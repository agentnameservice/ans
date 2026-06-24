// Command ans-ra runs the ANS Registration Authority HTTP server.
//
// Binaries:
//
//	ans-ra --config config/ra-local.yaml
//
// The RA exposes the V2 /v2/ans/* routes and pushes signed registration
// events to the Transparency Log (ans-tl) via a durable outbox.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/godaddy/ans/internal/adapter/auth"
	"github.com/godaddy/ans/internal/adapter/cert"
	"github.com/godaddy/ans/internal/adapter/challenge"
	"github.com/godaddy/ans/internal/adapter/didresolver"
	"github.com/godaddy/ans/internal/adapter/dns"
	"github.com/godaddy/ans/internal/adapter/docsui"
	"github.com/godaddy/ans/internal/adapter/eventbus"
	"github.com/godaddy/ans/internal/adapter/keymanager"
	"github.com/godaddy/ans/internal/adapter/store/sqlite"
	"github.com/godaddy/ans/internal/adapter/tlclient"
	"github.com/godaddy/ans/internal/config"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/handler"
	ramiddleware "github.com/godaddy/ans/internal/ra/middleware"
	raoutbox "github.com/godaddy/ans/internal/ra/outbox"
	"github.com/godaddy/ans/internal/ra/service"
)

// Build info injected at build time via -ldflags.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	cfgPath := flag.String("config", "config/ra-local.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ans-ra %s (%s) built %s\n", version, commit, date)
		return
	}

	if err := run(*cfgPath); err != nil {
		log.Error().Err(err).Msg("server exited with error")
		os.Exit(1)
	}
}

func run(cfgPath string) error {
	cfg, err := config.LoadRA(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger := buildLogger(cfg.Log)
	logger.Info().
		Str("version", version).Str("commit", commit).
		Str("config", cfgPath).
		Msg("starting ans-ra")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Storage.
	db, err := sqlite.Open(ctx, cfg.Store.SQLite.Path)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Warn().Err(err).Msg("db close")
		}
	}()

	agents := sqlite.NewAgentStore(db)
	endpoints := sqlite.NewEndpointStore(db)
	certsStore := sqlite.NewCertificateStore(db)
	byoc := sqlite.NewByocCertificateStore(db)
	renewals := sqlite.NewRenewalStore(db)
	outbox := sqlite.NewOutboxStore(db)
	identityStore := sqlite.NewIdentityStore(db)
	identityLinks := sqlite.NewIdentityLinkStore(db)

	// Crypto.
	km, err := keymanager.NewFileKeyManager(cfg.Keys.File.Path)
	if err != nil {
		return fmt.Errorf("open key manager: %w", err)
	}
	signerKeyID := cfg.Signer.KeyID
	if signerKeyID == "" {
		signerKeyID = "ans-ra-signer"
	}
	if _, err := km.EnsureKey(ctx, signerKeyID, port.AlgorithmECDSAP256); err != nil {
		return fmt.Errorf("ensure signer key: %w", err)
	}
	signerPub, err := km.GetPublicKey(ctx, signerKeyID)
	if err != nil {
		return fmt.Errorf("signer pubkey: %w", err)
	}
	logger.Info().
		Str("keyId", signerKeyID).
		Str("raId", cfg.Signer.RaID).
		Str("fingerprint", keymanager.KeyFingerprint(signerPub)).
		Msg("RA signer ready — register the public key in the TL producer-key store")

	// CA & validators.
	identityCA, err := cert.NewSelfCA(cfg.CA.Self.DataDir, cfg.CA.Self.Org, cfg.CA.Self.ValidityDays)
	if err != nil {
		return fmt.Errorf("init identity ca: %w", err)
	}
	// Optional server certificate issuer — enables the serverCsrPEM
	// path at registration and renewal. When the config block is
	// absent the RA accepts only BYOC (serverCertificatePEM).
	// `ca.server.type` selects the adapter: "self" (default) is the
	// in-process self-signed CA; "acme" is an external RFC 8555
	// provider such as Let's Encrypt. Both implement the same
	// port.ServerCertificateIssuer order lifecycle.
	var serverCA port.ServerCertificateIssuer
	if cfg.CA.Server != nil {
		serverCA, err = buildServerIssuer(cfg.CA.Server, logger)
		if err != nil {
			return err
		}
	} else {
		logger.Info().Msg("no server issuer configured — serverCsrPEM path disabled (BYOC-only)")
	}
	// In local-dev, accept self-signed BYOC certs. Production must
	// remove WithSkipChainVerify in its config factory.
	validator := cert.NewX509Validator(cert.WithSkipChainVerify())

	// DNS verifier.
	var dnsVerifier = selectDNSVerifier(cfg)

	// did:web resolver — noop (quickstart) or hardened web fetch,
	// the identity surface's analog of the DNS verifier selection.
	didResolver := selectDIDResolver(cfg, logger)
	logger.Info().
		Str("resolver", cfg.Identity.Resolver.Type).
		Dur("challengeTTL", cfg.Identity.ChallengeTTL).
		Msg("verified-identity surface configured")

	logger.Info().
		Str("tlPublicBaseURL", cfg.TLClient.PublicBaseURL).
		Str("tlBaseURL", cfg.TLClient.BaseURL).
		Msg("transparency log endpoints configured")

	// Auth.
	authProvider, err := buildAuth(ctx, cfg)
	if err != nil {
		return err
	}

	// Event bus.
	bus := eventbus.NewInMemoryBus(logger)

	// One TL client serves both seal-before-success lanes — agent
	// ACTIVATION (verify-dns) and identity ops. Both seal SYNCHRONOUSLY
	// (design §5.6.1; ANS-1 §12.3 for agents): the event is durable in the
	// log before the operation reports success, so neither rides the
	// outbox. A disabled TL client leaves the sealer nil and both lanes
	// fail closed with TL_UNAVAILABLE — there is no "seal later" mode for
	// an ACTIVE transition. (Revocation still rides the async outbox; the
	// worker below holds its own client.)
	//
	// The sealer is kept as a concrete *tlclient.Client and only assigned
	// into the interfaces when non-nil, so the services' `sealer == nil`
	// fail-closed checks aren't defeated by a typed-nil interface.
	var tlSealer *tlclient.Client
	if !cfg.TLClient.Disabled {
		tlSealer = tlclient.New(cfg.TLClient.BaseURL, cfg.TLClient.APIKey, cfg.TLClient.Timeout)
	} else {
		logger.Warn().Msg("TL client disabled — agent activation and identity verify/revoke/link operations will fail with TL_UNAVAILABLE (seal-before-success)")
	}

	// Services.
	regSvc := service.NewRegistrationService(
		agents, endpoints, certsStore, byoc, renewals, validator, identityCA, bus, outbox, db,
	).WithSigner(service.EventSigner{
		KeyManager: km,
		KeyID:      signerKeyID,
		RaID:       cfg.Signer.RaID,
	}).WithDNSVerifier(dnsVerifier).
		WithHTTPChallengeVerifier(challenge.NewHTTPVerifier()).
		WithServerCertificateIssuer(serverCA).
		WithTLPublicBaseURL(cfg.TLClient.PublicBaseURL)
	if tlSealer != nil {
		regSvc = regSvc.WithAgentSealer(tlSealer)
	}

	// Verified identities — the "who" behind the agents. Shares the
	// producer signer and the TL sealer with the registration service:
	// one RA, one producer identity on every TL lane.
	var identitySealer service.IdentityEventSealer
	if tlSealer != nil {
		identitySealer = tlSealer
	}
	identitySvc := service.NewIdentityService(
		identityStore, identityLinks, agents, didResolver, identitySealer, db,
	).WithSigner(service.EventSigner{
		KeyManager: km,
		KeyID:      signerKeyID,
		RaID:       cfg.Signer.RaID,
	}).WithChallengeTTL(cfg.Identity.ChallengeTTL).
		WithRegisterRateLimit(cfg.Identity.RegisterRateLimit).
		WithLinkRateLimit(cfg.Identity.LinkRateLimit).
		WithSealTimeout(cfg.Identity.SealTimeout).
		WithLogger(logger)

	// HTTP.
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(middleware.AllowContentType("application/json"))
	r.Use(authProvider.Middleware())

	// Admin routes (no auth).
	r.Get("/v2/admin/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	r.Get("/v2/admin/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})

	// Registration (no ownership middleware — POST creates a new agent
	// and the caller must be able to register their own).
	regH := handler.NewRegistrationHandler(regSvc)
	r.Post("/v2/ans/agents", regH.Register)

	// Agent-scoped routes — ownership middleware gates every one. The
	// middleware loads the agent, checks OwnerID == Identity.Subject,
	// and attaches the loaded agent to the request context. Read
	// routes (GET) 404 on not-owned to hide existence; write routes
	// (POST) 403 so authenticated operators understand it's an
	// authorization failure (spec §26, §370).
	lifeH := handler.NewLifecycleHandler(regSvc).WithIdentityViews(identitySvc)
	r.Get("/v2/ans/agents", lifeH.List)

	readOwnership := ramiddleware.ReadOwnership(agents)
	writeOwnership := ramiddleware.WriteOwnership(agents)

	r.With(readOwnership).Get("/v2/ans/agents/{agentId}", lifeH.Detail)

	// AI Catalog (owner-scoped, read-only). The bare CatalogEntry is the
	// registrant's own view of how their agent appears in a catalog; it
	// is NOT public — the crawlable surface is the population export
	// (later slice) and the AHP-published well-known document.
	catH := handler.NewCatalogHandler(regSvc)
	r.With(readOwnership).Get("/v2/ans/agents/{agentId}/catalog-entry", catH.CatalogEntry)
	// Host-complete AI Catalog document (the file the AHP publishes at
	// /.well-known/ai-catalog.json). Owner-scoped, served as
	// application/ai-catalog+json with ETag/304.
	r.With(readOwnership).Get("/v2/ans/agents/{agentId}/ai-catalog", catH.HostCatalog)

	r.With(readOwnership).Get("/v2/ans/agents/{agentId}/certificates/identity", lifeH.GetIdentityCerts)
	r.With(readOwnership).Get("/v2/ans/agents/{agentId}/certificates/server", lifeH.GetServerCerts)
	r.With(readOwnership).Get("/v2/ans/agents/{agentId}/csrs/{csrId}/status", lifeH.GetCSRStatus)

	r.With(writeOwnership).Post("/v2/ans/agents/{agentId}/verify-acme", lifeH.VerifyACME)
	r.With(writeOwnership).Post("/v2/ans/agents/{agentId}/verify-dns", lifeH.VerifyDNS)
	r.With(writeOwnership).Post("/v2/ans/agents/{agentId}/revoke", lifeH.Revoke)
	r.With(writeOwnership).Post("/v2/ans/agents/{agentId}/certificates/identity", lifeH.SubmitIdentityCSR)
	r.With(writeOwnership).Post("/v2/ans/agents/{agentId}/certificates/server", lifeH.SubmitServerCSR)

	// Server certificate renewal routes.
	r.With(readOwnership).Get("/v2/ans/agents/{agentId}/certificates/server/renewal", lifeH.GetServerCertRenewal)
	r.With(writeOwnership).Post("/v2/ans/agents/{agentId}/certificates/server/renewal", lifeH.SubmitServerCertRenewal)
	r.With(writeOwnership).Delete("/v2/ans/agents/{agentId}/certificates/server/renewal", lifeH.CancelServerCertRenewal)
	r.With(writeOwnership).Post("/v2/ans/agents/{agentId}/certificates/server/renewal/verify-acme", lifeH.VerifyRenewalACME)

	// Verified-identity routes (V2 only — the V1 lane is frozen).
	// Ownership is enforced inside the IdentityService (reads hide
	// existence with 404, writes split 404/403) because the owner
	// gate is the link mechanism's security boundary and the service
	// loads the aggregate anyway.
	idH := handler.NewIdentityHandler(identitySvc)
	r.Post("/v2/ans/identities", idH.Register)
	r.Get("/v2/ans/identities", idH.List)
	r.Get("/v2/ans/identities/{identityId}", idH.Detail)
	r.Put("/v2/ans/identities/{identityId}", idH.Rotate)
	r.Post("/v2/ans/identities/{identityId}/verify-control", idH.VerifyControl)
	r.Post("/v2/ans/identities/{identityId}/revoke", idH.Revoke)
	r.Post("/v2/ans/identities/{identityId}/links", idH.Link)
	r.Delete("/v2/ans/identities/{identityId}/links/{agentId}", idH.Unlink)

	// V1 RA surface — byte-for-byte parity with the reference V1 API
	// spec. Shares the same RegistrationService as the V2 routes;
	// only the DTO marshalling + TL-emit schema version differ. See
	// `internal/ra/handler/v1registration.go` and siblings.
	v1regH := handler.NewV1RegistrationHandler(regSvc)
	r.Post("/v1/agents/register", v1regH.Register)
	r.With(readOwnership).Get("/v1/agents/{agentId}", v1regH.Detail)

	// V1 lifecycle (verify-acme, verify-dns, revoke). V1 TL emits
	// AGENT_REGISTERED on successful verify-dns and AGENT_REVOKED on
	// revoke — the two terminal leaves V1 agents ever receive.
	v1lifeH := handler.NewV1LifecycleHandler(regSvc)
	r.With(writeOwnership).Post("/v1/agents/{agentId}/verify-acme", v1lifeH.VerifyACME)
	r.With(writeOwnership).Post("/v1/agents/{agentId}/verify-dns", v1lifeH.VerifyDNS)
	r.With(writeOwnership).Post("/v1/agents/{agentId}/revoke", v1lifeH.Revoke)

	// V1 certificate operations. DTOs reuse V2 types (reference spec
	// shares the schemas); only the URL prefix differs.
	v1certH := handler.NewV1CertificatesHandler(regSvc)
	r.With(readOwnership).Get("/v1/agents/{agentId}/certificates/identity", v1certH.GetIdentityCerts)
	r.With(readOwnership).Get("/v1/agents/{agentId}/certificates/server", v1certH.GetServerCerts)
	r.With(readOwnership).Get("/v1/agents/{agentId}/csrs/{csrId}/status", v1certH.GetCSRStatus)
	r.With(writeOwnership).Post("/v1/agents/{agentId}/certificates/identity", v1certH.SubmitIdentityCSR)
	r.With(writeOwnership).Post("/v1/agents/{agentId}/certificates/server", v1certH.SubmitServerCSR)

	// V1 server-cert renewal routes.
	v1renH := handler.NewV1RenewalHandler(regSvc)
	r.With(writeOwnership).Post("/v1/agents/{agentId}/certificates/server/renewal", v1renH.SubmitServerCertRenewal)
	r.With(readOwnership).Get("/v1/agents/{agentId}/certificates/server/renewal", v1renH.GetServerCertRenewal)
	r.With(writeOwnership).Delete("/v1/agents/{agentId}/certificates/server/renewal", v1renH.CancelServerCertRenewal)
	r.With(writeOwnership).Post("/v1/agents/{agentId}/certificates/server/renewal/verify-acme", v1renH.VerifyRenewalACME)

	// /docs — Swagger UI + embedded OpenAPI spec. Anonymous (see
	// buildAuth above). Operators who don't want docs exposed in
	// prod can drop this Mount call.
	docsui.Mount(r, docsui.SpecRA)

	// Outbox worker: drains outbox_events to the TL in the background.
	// Disabled-by-config skips starting it (e.g., when operators run
	// the worker as a separate process).
	var workerCancel context.CancelFunc
	if !cfg.TLClient.Disabled {
		tlc := tlclient.New(cfg.TLClient.BaseURL, cfg.TLClient.APIKey, cfg.TLClient.Timeout)
		worker := raoutbox.NewWorker(outbox, tlc, logger, raoutbox.Options{
			BatchSize:    cfg.TLClient.BatchSize,
			PollInterval: cfg.TLClient.PollInterval,
			MaxBackoff:   cfg.TLClient.MaxBackoff,
		})
		var wctx context.Context
		wctx, workerCancel = context.WithCancel(ctx)
		go func() { _ = worker.Run(wctx) }()
		logger.Info().
			Str("tlBaseURL", cfg.TLClient.BaseURL).
			Dur("pollInterval", cfg.TLClient.PollInterval).
			Msg("outbox worker started")
	} else {
		logger.Warn().Msg("outbox worker disabled — events will accumulate in the outbox_events table")
	}

	// Renewal expiry checker: sweeps pending renewals whose validation
	// window has elapsed and flips them to FAILED. Mirrors the
	// reference RA's `RenewalExpiryCheckJob`. Cadence is hard-coded
	// to 5 min — short enough that a failed renewal isn't listed as
	// PENDING for more than a few minutes, long enough that the DB
	// activity is negligible.
	expctx, expCancel := context.WithCancel(ctx)
	go service.RunExpiryChecker(expctx, renewals, certsStore, logger, service.ExpiryCheckerOptions{
		Interval: 5 * time.Minute,
	})
	// Registration-side twin: PENDING_VALIDATION registrations whose
	// challenge window lapsed flip to EXPIRED, per the spec's
	// "not cancellable and will auto-expire" contract.
	go service.RunAgentExpiryChecker(expctx, agents, logger, service.ExpiryCheckerOptions{
		Interval: 5 * time.Minute,
	})
	defer expCancel()

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logger.Info().Str("addr", addr).Msg("listening")
	// Hardened timeouts:
	//   - ReadHeaderTimeout caps slowloris-style header dribbling.
	//   - WriteTimeout > the 30s chi handler timeout (line 176) so
	//     chi gets the chance to write a clean 503 before the server
	//     drops the connection on a slow handler/client.
	//   - IdleTimeout caps how long an idle keep-alive connection
	//     can sit on the runner; pairs with HTTP/1.1 connection reuse
	//     for SDK clients while keeping a hard ceiling.
	//   - MaxHeaderBytes is set explicitly (Go's default is 1MiB) so
	//     it shows up in audits.
	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		logger.Info().Msg("shutting down")
		if workerCancel != nil {
			workerCancel()
		}
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if workerCancel != nil {
			workerCancel()
		}
		return err
	}
}

// buildLogger configures zerolog per cfg.
func buildLogger(cfg config.Log) zerolog.Logger {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	if cfg.Format == "text" {
		// zerolog encourages mutating its package-level Logger so
		// libraries that import `log` see the configured one.
		log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}). //nolint:reassign // zerolog package-Logger pattern
														With().Timestamp().Logger()
	} else {
		log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger() //nolint:reassign // zerolog package-Logger pattern
	}
	return log.Logger
}

// buildAuth selects and configures the AuthProvider.
func buildAuth(ctx context.Context, cfg *config.RAConfig) (providerWithAnonymous, error) {
	switch strings.ToLower(cfg.Auth.Type) {
	case "static":
		return auth.NewStaticProvider(
			cfg.Auth.Static.APIKey,
			auth.WithAPISecret(cfg.Auth.Static.APISecret),
			auth.WithAnonymousPath("/v2/admin/health"),
			auth.WithAnonymousPath("/v2/admin/ready"),
			auth.WithAnonymousPath("/docs"),
		), nil
	case "oidc":
		return auth.NewOIDCProvider(
			ctx,
			cfg.Auth.OIDC.IssuerURL,
			cfg.Auth.OIDC.Audience,
			cfg.Auth.OIDC.ClientID,
			auth.WithOIDCAnonymousPath("/v2/admin/health"),
			auth.WithOIDCAnonymousPath("/v2/admin/ready"),
			auth.WithOIDCAnonymousPath("/docs"),
			// Empty AdminGroups means no OIDC user is admin —
			// preserves prior behaviour for operators who haven't
			// opted in. Spreading nil/empty into a variadic is the
			// same as not calling the option at all.
			auth.WithAdminGroups(cfg.Auth.OIDC.AdminGroups...),
		)
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", cfg.Auth.Type)
	}
}

// providerWithAnonymous is satisfied by both auth.StaticProvider and
// auth.OIDCProvider since they share Middleware().
type providerWithAnonymous interface {
	Middleware() func(http.Handler) http.Handler
}

// buildServerIssuer builds the configured server certificate issuer.
// Config validation has already checked the per-type required fields.
func buildServerIssuer(s *config.CAServer, logger zerolog.Logger) (port.ServerCertificateIssuer, error) {
	if s.IsACME() {
		issuer, err := cert.NewACMEIssuer(s.ACME.DirectoryURL, s.ACME.Email, s.ACME.DataDir, cert.WithLogger(logger))
		if err != nil {
			return nil, fmt.Errorf("init acme issuer: %w", err)
		}
		logger.Info().
			Str("directoryURL", s.ACME.DirectoryURL).
			Str("dataDir", s.ACME.DataDir).
			Msg("ACME issuer ready — serverCsrPEM path enabled (provider-issued certs)")
		return issuer, nil
	}
	sca, err := cert.NewServerSelfCA(s.DataDir, s.Org, s.ValidityDays)
	if err != nil {
		return nil, fmt.Errorf("init server ca: %w", err)
	}
	logger.Info().
		Str("dataDir", s.DataDir).
		Str("org", s.Org).
		Int("validityDays", s.ValidityDays).
		Msg("server CA ready — serverCsrPEM path enabled")
	return sca, nil
}

// selectDNSVerifier returns the configured DNS adapter. Returns a
// port.DNSVerifier so the service layer can wire it directly.
//
// For "lookup" the optional `dns.server` config points the verifier
// at a specific nameserver — used by the demo's bundled `ans-dns`
// dev server and by operators who front ANS with their own
// authoritative nameserver. An empty string falls back to the OS
// resolver.
func selectDNSVerifier(cfg *config.RAConfig) port.DNSVerifier {
	switch cfg.DNS.Type {
	case "lookup":
		opts := []dns.LookupOption{}
		if cfg.DNS.Server != "" {
			opts = append(opts, dns.WithServer(cfg.DNS.Server))
		}
		return dns.NewLookupVerifier(opts...)
	default:
		return dns.NewNoopVerifier()
	}
}

// selectDIDResolver returns the configured did:web resolver adapter —
// the identity surface's analog of selectDNSVerifier. "web" performs
// the hardened HTTPS fetch (WebPKI + SSRF dialer guards); the default
// "noop" synthesizes documents from the submitted proofs' embedded
// keys for self-contained local development.
func selectDIDResolver(cfg *config.RAConfig, logger zerolog.Logger) port.DIDResolver {
	switch cfg.Identity.Resolver.Type {
	case "web":
		return didresolver.NewWebResolver(didresolver.WithLogger(logger))
	default:
		return didresolver.NewNoopResolver()
	}
}
