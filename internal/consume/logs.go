package consume

import (
	"context"
	"log/slog"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-logger/internal/model"
	"github.com/exemt/placitum-logger/internal/sink"
)

const (
	LogStream  = "WAF_LOG"
	LogDurable = "logger-log-v1"
	LogSubject = "waf.log.>"

	LogBatch = 100

	logWait = 2 * time.Second

	LogInsertEvery = 2 * time.Second
	LogInsertRows  = 20000
)

func RunLogs(ctx context.Context, nc *nats.Conn, conn driver.Conn, stats *Stats,
	log *slog.Logger) error {

	js, err := nc.JetStream()
	if err != nil {
		return err
	}

	sub, err := awaitStream(ctx, js, log)
	if err != nil {
		return err
	}

	log.Info("consuming logs",
		"stream", LogStream,
		"durable", LogDurable,
		"subject", LogSubject,
	)

	var (
		acc  logsBatch
		last = time.Now()
	)

	for {
		if ctx.Err() != nil {
			flushLogs(ctx, conn, acc, stats, log)

			return ctx.Err()
		}

		msgs, err := sub.Fetch(LogBatch, nats.MaxWait(MaxWait))
		if err != nil && err != nats.ErrTimeout {
			flushLogs(ctx, conn, acc, stats, log)

			return err
		}

		b := takeLogs(msgs, stats, log)
		acc.rows = append(acc.rows, b.rows...)
		acc.msgs = append(acc.msgs, b.msgs...)

		if len(acc.rows) >= LogInsertRows || time.Since(last) >= LogInsertEvery {
			flushLogs(ctx, conn, acc, stats, log)
			acc = logsBatch{}
			last = time.Now()
		}
	}
}

func awaitStream(ctx context.Context, js nats.JetStreamContext,
	log *slog.Logger) (*nats.Subscription, error) {

	said := false

	for {
		sub, err := js.PullSubscribe(LogSubject, LogDurable,
			nats.BindStream(LogStream),
			nats.ManualAck(),
			nats.AckWait(AckWait),
		)
		if err == nil {
			return sub, nil
		}

		if !said {
			log.Warn("log stream not ready", "stream", LogStream, "error", err.Error())
			said = true
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(logWait):
		}
	}
}

type logsBatch struct {
	rows []model.LogRow
	msgs []*nats.Msg
}

func takeLogs(msgs []*nats.Msg, stats *Stats, log *slog.Logger) logsBatch {
	b := logsBatch{msgs: make([]*nats.Msg, 0, len(msgs))}

	for _, m := range msgs {
		start := time.Now()
		rows, err := model.FromLog(m.Data)

		if stats != nil {
			stats.Consume.Add(uint64(len(m.Data)), 0, err != nil, time.Since(start))
		}

		if err != nil {
			log.Warn("skip bad log payload", "error", err.Error(), "subject", m.Subject)
		}

		if len(rows) == 0 {
			_ = m.Ack()

			continue
		}

		b.rows = append(b.rows, rows...)
		b.msgs = append(b.msgs, m)
	}

	return b
}

func flushLogs(ctx context.Context, conn driver.Conn, b logsBatch, stats *Stats,
	log *slog.Logger) {

	if len(b.msgs) == 0 {
		return
	}

	start := time.Now()
	err := sink.InsertLogs(ctx, conn, b.rows)
	elapsed := time.Since(start)

	if err != nil {
		log.Error("log flush failed", "error", err.Error(), "lines", len(b.rows))

		if stats != nil {
			stats.Insert.AddN(len(b.rows), 0, 0, true, elapsed)
		}

		for _, m := range b.msgs {
			_ = m.Nak()
		}

		return
	}

	if stats != nil {
		stats.Insert.AddN(len(b.rows), 0, 0, false, elapsed)
	}

	for _, m := range b.msgs {
		if err := m.Ack(); err != nil {
			log.Warn("log ack failed", "error", err.Error())
		}
	}

	stats.Add(len(b.rows))

	log.Debug("inserted logs", "lines", len(b.rows), "batches", len(b.msgs))
}
