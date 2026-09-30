// Command hub runs the ZEIT26 Identity Hub: the dashboard and its API, the
// provisioning worker, and the regular sync with Asgardeo.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/zeit26/identity-hub/internal/asgardeo"
	"github.com/zeit26/identity-hub/internal/config"
	"github.com/zeit26/identity-hub/internal/db"
	"github.com/zeit26/identity-hub/internal/hub"
	"github.com/zeit26/identity-hub/internal/provisioning"
	"github.com/zeit26/identity-hub/internal/secrets"
	"github.com/zeit26/identity-hub/internal/store"
	"github.com/zeit26/identity-hub/internal/web"
	"github.com/zeit26/identity-hub/ui"
)

func main() {
	var handler slog.Handler = slog.NewTextHandler(os.Stderr, nil)
	if os.Getenv("HUB_LOG_FORMAT") == "json" {
		// One JSON object per line, for a log collector.
		handler = slog.NewJSONHandler(os.Stderr, nil)
	}
	log := slog.New(handler)
	if err := run(log); err != nil {
		log.Error("the Hub stopped", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	envFile := os.Getenv("HUB_ENV_FILE")
	if envFile == "" {
		envFile = ".env"
	}
	if err := config.LoadDotEnv(envFile); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}

	box, err := secrets.New(cfg.EncryptionKey)
	if err != nil {
		return err
	}
	st := store.New(pool)
	directory := asgardeo.New(cfg.AsgardeoBaseURL, cfg.M2MClientID, cfg.M2MClientSecret)
	worker := provisioning.NewWorker(st, box, log.With("component", "provisioning"))
	svc := hub.New(st, directory, box, log.With("component", "hub"), worker.Wake)

	server := &http.Server{
		Addr: cfg.Addr,
		Handler: web.New(web.Options{
			PublicURL:  cfg.PublicURL,
			SessionTTL: cfg.SessionTTL,
			OIDC: web.OIDCSettings{
				Issuer:       cfg.Issuer(),
				ClientID:     cfg.OIDCClientID,
				ClientSecret: cfg.OIDCClientSecret,
				RedirectURL:  cfg.RedirectURL(),
			},
			UI:           ui.Files(),
			Organization: cfg.Organization(),
		}, svc, st, box, log.With("component", "web")),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Onboarding waits for Asgardeo, which may take up to a minute.
		WriteTimeout:   2 * time.Minute,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 64 << 10,
	}

	var background sync.WaitGroup
	background.Go(func() { worker.Run(ctx) })
	background.Go(func() { svc.RunSync(ctx, cfg.SyncInterval) })

	serveErr := make(chan error, 1)
	go func() {
		log.Info("the Hub is listening", "config", cfg.String())
		serveErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		stop()
		background.Wait()
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = server.Shutdown(shutdownCtx)
	background.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
