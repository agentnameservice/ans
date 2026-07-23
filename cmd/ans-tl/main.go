// Command ans-tl runs the ANS Transparency Log HTTP server.
//
//	ans-tl --config config/tl-local.yaml
//
// The TL:
//   - accepts signed events from the RA at POST /v1/internal/agents/event
//   - persists them via the Tessera library onto POSIX-layout storage
//   - serves badges, audit history, and receipts for verifiers
//   - publishes signed checkpoints (sumdb note format) on an interval
package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
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

	"github.com/agentnameservice/ans/internal/adapter/auth"
	"github.com/agentnameservice/ans/internal/adapter/docsui"
	"github.com/agentnameservice/ans/internal/adapter/keymanager"
	sqlitetl "github.com/agentnameservice/ans/internal/adapter/store/sqlitetl"
	"github.com/agentnameservice/ans/internal/config"
	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/port"
	"github.com/agentnameservice/ans/internal/tl/handler"
	"github.com/agentnameservice/ans/internal/tl/logstore"
	producerkeypkg "github.com/agentnameservice/ans/internal/tl/producerkey"
	"github.com/agentnameservice/ans/internal/tl/receipt"
	"github.com/agentnameservice/ans/internal/tl/service"
)

// Build info injected at build time via -ldflags.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	cfgPath := flag.String("config", "config/tl-local.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("ans-tl %s (%s) built %s\n", version, commit, date)
		return
	}
	if err := run(*cfgPath); err != nil {
		log.Error().Err(err).Msg("server exited with error")
		os.Exit(1)
	}
}

func run(cfgPath string) error {
	cfg, err := config.LoadTL(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger := buildLogger(cfg.Log)
	logger.Info().
		Str("version", version).Str("commit", commit).
		Str("config", cfgPath).Msg("starting ans-tl")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// SQLite index (events, checkpoints, receipts).
	db, err := sqlitetl.Open(ctx, cfg.Store.SQLite.Path)
	if err != nil {
		return fmt.Errorf("open tl db: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Warn().Err(err).Msg("db close")
		}
	}()

	// Single-key TL signing — one ECDSA P-256 key drives every
	// outbound signature: primary C2SP checkpoint line, JWS additional
	// signer, outer envelope attestation JWS, SCITT receipts, and
	// status tokens. Matches the reference TL's deployed topology
	// (production `/root-keys` advertises exactly one key).
	km, err := keymanager.NewFileKeyManager(cfg.Keys.File.Path)
	if err != nil {
		return fmt.Errorf("key manager: %w", err)
	}
	signingKeyID := cfg.Attestation.KeyID
	if signingKeyID == "" {
		signingKeyID = "ans-tl-attestation"
	}
	if _, err := km.EnsureKey(ctx, signingKeyID, port.AlgorithmECDSAP256); err != nil {
		return fmt.Errorf("ensure signing key: %w", err)
	}
	signingPub, err := km.GetPublicKey(ctx, signingKeyID)
	if err != nil {
		return fmt.Errorf("signing pubkey: %w", err)
	}
	signingPubECDSA, ok := signingPub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("signing key is not ECDSA (type %T)", signingPub)
	}
	logger.Info().
		Str("keyId", signingKeyID).
		Str("fingerprint", keymanager.KeyFingerprint(signingPub)).
		Msg("TL signing key ready")

	// Primary C2SP checkpoint signer — produces the `— <origin> <base64>`
	// line every checkpoint carries. Raw ECDSA signature over the note
	// body; Tessera prepends the 4-byte keyhash and base64-encodes.
	c2spSigner, err := logstore.NewC2SPECDSASigner(ctx, km, signingKeyID, cfg.Merkle.Origin)
	if err != nil {
		return fmt.Errorf("c2sp signer: %w", err)
	}

	// JWS additional signer — same key, different envelope shape
	// (standard compact JWS). Tessera appends a second signature line
	// per checkpoint so JWS-aware verifiers can validate without
	// speaking the raw C2SP protocol.
	jwsCPSigner, err := logstore.NewJWSCheckpointSigner(ctx, km, signingKeyID, cfg.Merkle.Origin)
	if err != nil {
		return fmt.Errorf("jws checkpoint signer: %w", err)
	}
	jwsCPSigner.WithClock(func() int64 { return time.Now().Unix() })

	// Tessera-backed log over POSIX storage.
	lg, err := logstore.Open(ctx, logstore.Config{
		DataDir:            cfg.Merkle.TileStorage.Filesystem.Path,
		Origin:             cfg.Merkle.Origin,
		CheckpointInterval: cfg.Merkle.CheckpointInterval,
	}, c2spSigner, logstore.WithAdditionalSigner(jwsCPSigner))
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}
	defer func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		if err := lg.Close(cctx); err != nil {
			logger.Warn().Err(err).Msg("log close")
		}
	}()

	eventStore := sqlitetl.NewEventStore(db)
	cpStore := sqlitetl.NewCheckpointStore(db)
	receiptStore := sqlitetl.NewReceiptStore(db)

	// Producer-key trust store — Stage 4 switched the authoritative
	// storage from in-memory YAML to SQLite with admin-routed CRUD.
	// The `tl.producerKeys[]` config is kept as a **bootstrap** path:
	// keys listed there are upserted into `tl_producer_keys` on
	// startup with a 10-year default validity window. This keeps the
	// quickstart demo working — operators still edit YAML — while
	// letting production deployments rotate keys at runtime via the
	// admin API without restarting the TL.
	pkStore := sqlitetl.NewProducerKeyStore(db)
	if err := bootstrapProducerKeys(ctx, pkStore, cfg.ProducerKeys, logger); err != nil {
		return fmt.Errorf("producer key bootstrap: %w", err)
	}
	producerSig := service.NewProducerSigVerifier(pkStore)

	logSvc := service.NewLogService(
		lg, eventStore, cpStore,
		producerSig, km, signingKeyID, cfg.Merkle.Origin,
	)
	// Drain in-flight checkpoint-persist goroutines before the
	// underlying Tessera reader gets torn down.
	defer logSvc.Close()
	badgeSvc := service.NewBadgeService(logSvc)
	identityBadgeSvc := service.NewIdentityBadgeService(logSvc, badgeSvc)

	// Receipt + status-token generators reuse the single signing
	// key. Matches the reference TL's deployed topology: one KMS key
	// drives every outbound signature produced by the log.
	receiptGen, err := receipt.NewKeyManagerGenerator(ctx, km, signingKeyID, cfg.Merkle.Origin)
	if err != nil {
		return fmt.Errorf("receipt generator: %w", err)
	}
	receiptSvc := service.NewReceiptService(logSvc, receiptStore, receiptGen)

	statusTokenGen, err := receipt.NewKeyManagerStatusTokenGenerator(
		ctx, km, signingKeyID, cfg.StatusToken.TTL,
	)
	if err != nil {
		return fmt.Errorf("status-token generator: %w", err)
	}
	statusTokenSvc := service.NewStatusTokenService(logSvc, statusTokenGen)
	logger.Info().
		Str("keyId", signingKeyID).
		Dur("ttl", cfg.StatusToken.TTL).
		Msg("TL status-token signer ready")

	// Auth.
	authProvider, err := buildAuth(ctx, cfg)
	if err != nil {
		return err
	}

	// HTTP.
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	// middleware.RealIP is deliberately NOT wired: chi 5.3 deprecates it
	// as IP-spoofable (it trusts X-Forwarded-For / X-Real-IP regardless
	// of whether a proxy set them), and nothing in this service reads
	// RemoteAddr — no request logger, no rate limiter, no IP audit.
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(authProvider.Middleware())

	r.Get("/v2/admin/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	r.Get("/v2/admin/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})

	// Pre-render the /root-keys body once at startup in the
	// sumdb-note-style verification-key format the reference TL emits:
	//
	//     <origin>+<keyhash-hex>+<base64(0x02 || SPKI-DER)>\n
	//
	// Single-key topology — exactly one line, matching production
	// `/root-keys`. Verifiers use the 4-byte keyhash as an O(1)
	// `kid`-to-key lookup on COSE receipts and checkpoint signature
	// lines.
	signingLine, err := anscrypto.PublicKeyToVerificationLine(cfg.Merkle.Origin, signingPubECDSA)
	if err != nil {
		return fmt.Errorf("encode signing key: %w", err)
	}
	rootKeysBody := []byte(signingLine + "\n")

	// Base64-encoded PEM of the signing key's SPKI for the checkpoint
	// response's `publicKeyPem` field. Production emits the PEM
	// wrapped in base64; match exactly.
	signingPEM, err := anscrypto.PublicKeyPEM(signingPubECDSA)
	if err != nil {
		return fmt.Errorf("encode signing pubkey PEM: %w", err)
	}
	signingPEMBase64 := base64.StdEncoding.EncodeToString([]byte(signingPEM))

	checkpointSvc := service.NewCheckpointService(cpStore).
		WithVerifiers(signingPubECDSA, signingPEMBase64)
	schemaSvc, err := service.NewSchemaService()
	if err != nil {
		return fmt.Errorf("schema service: %w", err)
	}

	h := handler.NewHandlers(
		logSvc, badgeSvc, identityBadgeSvc, receiptSvc, statusTokenSvc,
		checkpointSvc, schemaSvc, rootKeysBody,
	)
	h.Mount(r, lg.DataDir())

	// /docs — Swagger UI + embedded OpenAPI spec. Always anonymous
	// (see WithAnonymousPath("/docs") above); operators who don't
	// want docs exposed in prod can drop this Mount call.
	docsui.Mount(r, docsui.SpecTL)

	// Admin surface — gated by RequireAdmin. The chi.Group scopes the
	// middleware so it only applies to the admin routes; verifier and
	// ingest paths continue to run under their configured auth rules
	// (static key or OIDC). Mounting after the public handlers is
	// fine because chi dispatches on the most specific match.
	adminH := handler.NewAdminHandlers(pkStore)
	r.Group(func(ar chi.Router) {
		ar.Use(auth.RequireAdmin())
		adminH.Mount(ar)
	})

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logger.Info().Str("addr", addr).Msg("listening")
	// Hardened timeouts — see the matching block in cmd/ans-ra/main.go
	// for the full rationale. WriteTimeout sits above the 30s chi
	// middleware.Timeout wired on the router above so chi can write a
	// clean 503 first; IdleTimeout caps keep-alive idle time;
	// MaxHeaderBytes is the Go default written explicitly for audit
	// visibility.
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
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

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

// authMiddlewareProvider covers both StaticProvider and OIDCProvider.
type authMiddlewareProvider interface {
	Middleware() func(http.Handler) http.Handler
}

// bootstrapProducerKeys upserts YAML-declared producer keys into the
// SQLite trust store on startup. Idempotent: existing keyIDs are
// skipped so restarts don't churn.
//
// The YAML shape doesn't carry validity windows; we assign a decade
// starting "now" so dev/demo keys never expire unexpectedly. Admins
// that want tight rotation windows should create keys via the
// admin API instead of YAML. ValidFrom in the past is allowed by
// the store (no is-it-too-old check); we anchor at "now - 1h" so
// the key is valid immediately after the TL starts.
func bootstrapProducerKeys(
	ctx context.Context,
	store *sqlitetl.ProducerKeyStore,
	entries []config.ProducerKeyCfg,
	logger zerolog.Logger,
) error {
	if len(entries) == 0 {
		logger.Warn().Msg("no producer keys configured; use the admin API to register keys at runtime")
		return nil
	}
	now := time.Now()
	validFrom := now.Add(-1 * time.Hour)
	expiresAt := now.Add(10 * 365 * 24 * time.Hour) // ~10 years
	seeded := 0
	skipped := 0
	for _, pk := range entries {
		_, err := store.Register(ctx, producerkeypkg.Entry{
			RaID:         pk.RaID,
			KeyID:        pk.KeyID,
			Algorithm:    pk.Algorithm,
			PublicKeyPEM: pk.PublicKeyPEM,
			ValidFrom:    validFrom,
			ExpiresAt:    expiresAt,
		})
		switch {
		case err == nil:
			seeded++
		case errors.Is(err, producerkeypkg.ErrDuplicateKey):
			skipped++
		default:
			return fmt.Errorf("bootstrap %q: %w", pk.KeyID, err)
		}
	}
	logger.Info().
		Int("seeded", seeded).
		Int("skippedAlreadyPresent", skipped).
		Msg("producer-key bootstrap complete")
	return nil
}

func buildAuth(ctx context.Context, cfg *config.TLConfig) (authMiddlewareProvider, error) {
	switch strings.ToLower(cfg.Auth.Type) {
	case "static":
		opts := []auth.StaticOption{
			auth.WithAnonymousPath("/v2/admin/health"),
			auth.WithAnonymousPath("/v2/admin/ready"),
			// API docs are always anonymous — the whole point is
			// that any browser can hit /docs and explore.
			auth.WithAnonymousPath("/docs"),
		}
		if cfg.Auth.PublicRead {
			// Reference-parity verifier paths — badges, audit,
			// receipts, status tokens under /v1/agents/; JSON
			// checkpoint + schema under /v1/log/; raw tlog-tiles
			// artefacts at root (/checkpoint, /root-keys, /tile/...).
			// Producers still POST to /v1/internal/... which is NOT
			// covered here — that route requires the Bearer key.
			opts = append(opts,
				auth.WithAnonymousPath("/v1/agents/"),
				auth.WithAnonymousPath("/v1/identities/"),
				auth.WithAnonymousPath("/v1/log/"),
				auth.WithAnonymousPath("/checkpoint"),
				auth.WithAnonymousPath("/root-keys"),
				auth.WithAnonymousPath("/tile/"))
		}
		// The TL doesn't ship an SDK that sends sso-key — its own
		// producer-facing route (/v1/internal/agents/event) is called
		// by our outbox worker with the Bearer format, and the admin
		// routes are internal-only. We still wire APISecret through
		// for symmetry with the RA so operators that want to reuse
		// the same deployment convention can.
		opts = append(opts, auth.WithAPISecret(cfg.Auth.Static.APISecret))
		return auth.NewStaticProvider(cfg.Auth.Static.APIKey, opts...), nil
	case "oidc":
		return auth.NewOIDCProvider(ctx,
			cfg.Auth.OIDC.IssuerURL, cfg.Auth.OIDC.Audience, cfg.Auth.OIDC.ClientID,
			auth.WithOIDCAnonymousPath("/v2/admin/health"),
			auth.WithOIDCAnonymousPath("/v2/admin/ready"),
			auth.WithOIDCAnonymousPath("/docs"),
			auth.WithOIDCAnonymousPath("/v1/agents/"),
			auth.WithOIDCAnonymousPath("/v1/identities/"),
			auth.WithOIDCAnonymousPath("/v1/log/"),
			auth.WithOIDCAnonymousPath("/checkpoint"),
			auth.WithOIDCAnonymousPath("/root-keys"),
			auth.WithOIDCAnonymousPath("/tile/"),
			// Without this, /internal/v1/producer-keys (and any
			// future RequireAdmin-gated route) is unreachable on
			// OIDC. Empty AdminGroups preserves the prior behaviour.
			auth.WithAdminGroups(cfg.Auth.OIDC.AdminGroups...),
		)
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", cfg.Auth.Type)
	}
}
