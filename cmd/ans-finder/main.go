// Command ans-finder runs the ANS Finder — the Agentic Resource
// Discovery (ARD) service over the ANS reference implementation.
//
//	ans-finder --config config/finder-local.yaml
//
// The Finder:
//   - polls the RA's agent-events feed (GET /v1/agents/events)
//   - projects each event into an FTS5-indexed discovery catalog
//   - serves POST /v1/search and POST /v1/explore per the ARD contract
//     (spec/api-spec-finder-v1.yaml), every entry carrying a SCITT
//     receipt URI a client can verify against the Transparency Log
//
// All discovery routes are public and rate-limited; there is no auth
// provider.
//
// # Health vs readiness
//
// /v1/admin/health is LIVENESS: 200 whenever the process is up, including
// before the first poll. /v1/admin/ready is READINESS: 200 only after the
// poller has completed at least one successful feed round (so a
// freshly-started or never-bootstrapped replica is not routed discovery
// traffic while it would return only empty results); 503 until then. Wire
// health to a liveness probe and ready to a readiness/load-balancer
// probe.
//
// # Ingestion-wedge runbook
//
// Ingestion is feed-only and intentionally STOPS at the cursor on a
// structural feed error rather than skipping a malformed event (skipping
// would silently drop a registration or revocation). When a round fails
// repeatedly at the same cursor the poller logs:
//
//	finder poller: ingestion wedged at logId=<id>; manual intervention required
//
// To recover, in order of preference:
//
//  1. Fix the upstream cause (the feed event at that logId, or feed
//     availability) and let the next poll resume — no Finder action needed.
//  2. Skip the poison event: stop ans-finder, set finder_cursor.last_log_id
//     in the SQLite store to the logId AFTER the bad one, and restart. The
//     skipped event is permanently un-indexed until a later event for the
//     same agent supersedes it.
//  3. Rebuild from scratch: stop ans-finder, delete the finder SQLite file,
//     and restart to replay the feed from the beginning. NOTE the rebuild
//     only recovers events still within the feed's retention window;
//     anything aged out is not recoverable from the feed alone.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/agentnameservice/ans/internal/adapter/docsui"
	"github.com/agentnameservice/ans/internal/adapter/store/sqlitefinder"
	"github.com/agentnameservice/ans/internal/config"
	"github.com/agentnameservice/ans/internal/finder/handler"
	"github.com/agentnameservice/ans/internal/finder/poller"
	"github.com/agentnameservice/ans/internal/finder/project"
)

// Build info injected at build time via -ldflags.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	cfgPath := flag.String("config", "config/finder-local.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("ans-finder %s (%s) built %s\n", version, commit, date)
		return
	}
	if err := run(*cfgPath); err != nil {
		log.Error().Err(err).Msg("server exited with error")
		os.Exit(1)
	}
}

func run(cfgPath string) error {
	cfg, err := config.LoadFinder(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger := buildLogger(cfg.Log)
	logger.Info().
		Str("version", version).Str("commit", commit).
		Str("config", cfgPath).Msg("starting ans-finder")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// SQLite FTS5 catalog index.
	store, err := sqlitefinder.Open(ctx, cfg.Store.SQLite.Path)
	if err != nil {
		return fmt.Errorf("open finder index: %w", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Warn().Err(err).Msg("index close")
		}
	}()
	// Surface schema upgrades: a migration can rewrite the whole FTS
	// index between "starting" and "listening", so an operator must be
	// able to confirm from logs alone that it ran.
	if applied := store.AppliedMigrations(); len(applied) > 0 {
		logger.Info().Strs("migrations", applied).Msg("applied index migrations")
	}

	// Feed client + poller.
	feedClient, err := poller.NewHTTPFeedClient(cfg.Feed.BaseURL, cfg.Feed.AllowHTTP, cfg.Feed.Timeout)
	if err != nil {
		return fmt.Errorf("feed client: %w", err)
	}
	pl := poller.New(feedClient, store, poller.Config{
		Interval: cfg.Feed.PollInterval,
		PageSize: cfg.Feed.PageSize,
		ProjectOptions: project.Options{
			TLBaseURL: cfg.TL.PublicBaseURL,
			AllowHTTP: cfg.Feed.AllowHTTP,
		},
	}, logger, time.Now)

	// HTTP handler.
	rl := handler.NewRateLimiter(cfg.Search.Rate, cfg.Search.Burst)
	h := handler.New(store, handler.Config{
		SourceURL:       sourceURL(cfg),
		MaxPageSize:     cfg.Search.MaxPageSize,
		DefaultPageSize: cfg.Search.DefaultPageSize,
		StaleBound:      cfg.Feed.StaleBound,
		Referrals:       referrals(cfg),
	}, rl, logger, time.Now)

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.Timeout(30 * time.Second))
	h.Mount(r)

	// /docs — Swagger UI + embedded finder spec. Anonymous, like the RA
	// and TL docs surfaces.
	docsui.Mount(r, docsui.SpecFinder)

	addr := net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port))
	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Start the poller as a background goroutine. It runs until ctx is
	// cancelled (graceful shutdown) and never returns a fatal error — a
	// poll failure is logged and retried, so the discovery surface keeps
	// serving its last-known index.
	pollerDone := make(chan struct{})
	go func() {
		_ = pl.Run(ctx)
		close(pollerDone)
	}()

	// Echo the effective configuration at startup (the finder config holds
	// no secrets — feed/TL URLs, paths, and tunables only — so this is safe
	// to log and saves an operator from cross-referencing the YAML).
	logger.Info().
		Str("addr", addr).
		Str("feed", cfg.Feed.BaseURL).
		Bool("feedAllowHTTP", cfg.Feed.AllowHTTP).
		Dur("pollInterval", cfg.Feed.PollInterval).
		Dur("staleBound", cfg.Feed.StaleBound).
		Str("store", cfg.Store.SQLite.Path).
		Str("tlPublicBaseURL", cfg.TL.PublicBaseURL).
		Float64("rateLimitRate", cfg.Search.Rate).
		Float64("rateLimitBurst", cfg.Search.Burst).
		Msg("listening")

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
		err := srv.Shutdown(shutdownCtx)
		<-pollerDone // let the poll loop observe ctx cancellation and exit
		return err
	case err := <-errCh:
		// Listen failed. Cancel the context and drain the poller before
		// returning, so the deferred store.Close() does not run while the
		// poll loop is still reading/writing the store.
		cancel()
		<-pollerDone
		return err
	}
}

// sourceURL resolves the base URL echoed as a result's `source`. An
// explicit config value wins; otherwise it is derived from the listen
// address (http for local dev — operators behind TLS set source-url
// explicitly).
func sourceURL(cfg *config.FinderConfig) string {
	if cfg.Search.SourceURL != "" {
		return cfg.Search.SourceURL
	}
	hostPort := net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port))
	return "http://" + hostPort + "/v1/"
}

// referrals maps the config referral entries into wire catalog entries.
func referrals(cfg *config.FinderConfig) []project.Entry {
	if len(cfg.Referrals) == 0 {
		return nil
	}
	out := make([]project.Entry, 0, len(cfg.Referrals))
	for _, r := range cfg.Referrals {
		out = append(out, project.Entry{
			Identifier:  r.Identifier,
			DisplayName: r.DisplayName,
			Type:        r.Type,
			URL:         r.URL,
		})
	}
	return out
}

func buildLogger(cfg config.Log) zerolog.Logger {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	if cfg.Format == "text" {
		log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}). //nolint:reassign // zerolog package-Logger pattern
														With().Timestamp().Logger()
	} else {
		log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger() //nolint:reassign // zerolog package-Logger pattern
	}
	return log.Logger
}
