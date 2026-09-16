package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-logger/internal/ch"
	"github.com/exemt/placitum-logger/internal/consume"
	"github.com/exemt/placitum-logger/internal/migrate"
	"github.com/exemt/placitum-logger/internal/pulse"
	"github.com/exemt/placitum-shared/flow"
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
	name := env("WAF_SERVICE_NAME", "logger")

	level, err := loglevel.Env("WAF_LOGGER_LOG", "info")
	if err != nil {
		return err
	}

	logIO := flow.New()
	journal := logkit.Open(logkit.Options{Service: name, Level: level, IO: logIO})
	defer journal.Close()

	log := journal.Log

	log.Info("build", "version", version, "revision", revision)
	slog.SetDefault(log)

	natsURL := env("WAF_NATS_URL", "nats://127.0.0.1:4222")
	schemaDir := env("WAF_SCHEMA_DIR", "schema")
	every := durationEnv("WAF_HEARTBEAT_EVERY", 4*time.Second)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	conn, err := ch.Open()
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := migrate.Apply(ctx, conn, schemaDir); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	log.Info("migrations applied", "dir", schemaDir)

	nc, err := nats.Connect(natsURL,
		nats.Name("waf-logger"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(500*time.Millisecond),
	)
	if err != nil {
		return fmt.Errorf("nats: %w", err)
	}
	defer nc.Close()

	journal.Attach(ctx, nc)
	defer journal.Close()

	stats := consume.NewStats()
	logStats := consume.NewStats()
	id := pulse.NewID()
	stopBeat := startHeartbeat(ctx, nc, conn, id, name, every, stats, logStats, logIO, log)
	defer stopBeat()

	go func() {
		if err := consume.RunLogs(ctx, nc, conn, logStats, journal.Quiet()); err != nil &&
			ctx.Err() == nil {
			log.Error("log consumer stopped", "error", err.Error())
		}
	}()

	return consume.Run(ctx, nc, conn, stats, log)
}

func startHeartbeat(
	ctx context.Context,
	nc *nats.Conn,
	conn interface{ Ping(context.Context) error },
	id, name string,
	every time.Duration,
	stats *consume.Stats,
	logStats *consume.Stats,
	logIO *flow.Counter,
	log *slog.Logger,
) func() {
	subject := pulse.Subject(name, id)
	log.Info("heartbeat on",
		"name", name,
		"id", id,
		"subject", subject,
		"every", every.String(),
	)

	beat := func() {
		work := pulse.Work{
			Inserted:  stats.Inserted() + logStats.Inserted(),
			LastBatch: stats.LastBatch(),
		}
		ping, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := conn.Ping(ping)
		cancel()
		work.ClickHouseOK = err == nil
		if err != nil {
			work.Error = err.Error()
		}
		io := map[string]flow.Flow{
			"consume":     stats.Consume.Snapshot(),
			"insert":      stats.Insert.Snapshot(),
			"log_consume": logStats.Consume.Snapshot(),
			"log_insert":  logStats.Insert.Snapshot(),
			"log":         logIO.Snapshot(),
		}
		msg := pulse.Build(id, name, work, io)
		msg.Version, msg.Revision = version, revision
		if err := pulse.Publish(nc, msg); err != nil {
			log.Warn("heartbeat failed", "error", err.Error())
			return
		}

		log.Debug("heartbeat",
			"hostname", msg.Hostname,
			"ready", msg.Ready,
			"inserted", work.Inserted,
			"log_inserted", logStats.Inserted(),
			"clickhouse_ok", work.ClickHouseOK,
		)
	}

	beat()
	tick := time.NewTicker(every)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-tick.C:
				beat()
			}
		}
	}()

	return func() {
		tick.Stop()
		close(done)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
