package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-logger/internal/ch"
	"github.com/exemt/placitum-logger/internal/httpapi"
	"github.com/exemt/placitum-logger/internal/store"
	"github.com/exemt/placitum-shared/logkit"
	"github.com/exemt/placitum-shared/loglevel"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	level, err := loglevel.Env("WAF_SEARCH_LOG", "info")
	if err != nil {
		return err
	}

	journal := logkit.Open(logkit.Options{Service: "search", Level: level})
	defer journal.Close()

	log := journal.Log

	log.Info("build", "version", version, "revision", revision)
	slog.SetDefault(log)

	conn, err := ch.Open()
	if err != nil {
		return err
	}
	defer conn.Close()

	storeCfg, err := store.FromEnv()
	if err != nil {
		return err
	}

	addr := ":" + env("SEARCH_PORT", "8091")
	srv := &http.Server{
		Addr:              addr,
		Handler:           httpapi.Handler(conn, store.New(storeCfg), log),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if url := env("WAF_NATS_URL", ""); url != "" {
		nc, err := nats.Connect(url,
			nats.Name("waf-search"),
			nats.MaxReconnects(-1),
			nats.ReconnectWait(500*time.Millisecond),
			nats.RetryOnFailedConnect(true),
		)
		if err != nil {
			log.Warn("log bus", "url", url, "error", err.Error())
		} else {
			defer nc.Close()

			journal.Attach(ctx, nc)
			defer journal.Close()
		}
	}

	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()

	log.Info("listen", "addr", addr, "store_archive", storeCfg.ArchiveEnabled())

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http: %w", err)
	}

	return nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}
