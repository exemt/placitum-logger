package consume

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-logger/internal/model"
	"github.com/exemt/placitum-logger/internal/sink"
)

const (
	Stream  = "WAF_AUDIT"
	Durable = "logger-audit-v2"
	Subject = "waf.audit.>"
	Batch   = 500
	MaxWait = 200 * time.Millisecond
	AckWait = 30 * time.Second

	FetchBytes = 16 << 20

	InsertRows = 20000

	InsertEvery = 2 * time.Second

	pipeline = 2
)

func Run(ctx context.Context, nc *nats.Conn, conn driver.Conn, stats *Stats,
	log *slog.Logger) error {

	js, err := nc.JetStream()
	if err != nil {
		return fmt.Errorf("jetstream: %w", err)
	}

	sub, err := js.PullSubscribe(Subject, Durable,
		nats.BindStream(Stream),
		nats.ManualAck(),
		nats.AckWait(AckWait),
	)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	log.Info("consuming",
		"stream", Stream,
		"durable", Durable,
		"subject", Subject,
	)

	batches := make(chan batch, pipeline)
	done := make(chan error, 1)

	go func() { done <- insert(ctx, conn, batches, stats, log) }()

	ferr := fetch(ctx, sub, batches, stats, log)

	close(batches)

	if ierr := <-done; ferr == nil {
		return ierr
	}

	return ferr
}

func fetch(ctx context.Context, sub *nats.Subscription, out chan<- batch,
	stats *Stats, log *slog.Logger) error {

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		msgs, err := sub.Fetch(Batch,
			nats.MaxWait(MaxWait), nats.PullMaxBytes(FetchBytes))
		if err != nil && err != nats.ErrTimeout {
			return fmt.Errorf("fetch: %w", err)
		}

		b := take(msgs, stats, log)
		if len(b.msgs) == 0 {
			continue
		}

		select {
		case out <- b:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func insert(ctx context.Context, conn driver.Conn, in <-chan batch, stats *Stats,
	log *slog.Logger) error {

	tick := time.NewTicker(InsertEvery)
	defer tick.Stop()

	var acc batch

	for {
		select {
		case b, ok := <-in:
			if !ok {
				flush(ctx, conn, acc, stats, log)

				return nil
			}

			acc.rows = append(acc.rows, b.rows...)
			acc.findings = append(acc.findings, b.findings...)
			acc.msgs = append(acc.msgs, b.msgs...)

			if len(acc.rows)+len(acc.findings) >= InsertRows {
				flush(ctx, conn, acc, stats, log)
				acc = batch{}
			}

		case <-tick.C:
			flush(ctx, conn, acc, stats, log)
			acc = batch{}
		}
	}
}

type batch struct {
	rows     []model.Row
	findings []model.FindingRow
	msgs     []*nats.Msg
}

func take(msgs []*nats.Msg, stats *Stats, log *slog.Logger) batch {
	b := batch{msgs: make([]*nats.Msg, 0, len(msgs))}

	for _, m := range msgs {
		start := time.Now()
		rows, findings, err := parse(m.Data)

		if stats != nil {
			stats.Consume.Add(uint64(len(m.Data)), 0, err != nil, time.Since(start))
		}

		if err != nil {
			log.Warn("skip bad payload", "error", err.Error(), "subject", m.Subject)
		}

		if len(rows) == 0 && len(findings) == 0 {
			_ = m.Ack()

			continue
		}

		b.rows = append(b.rows, rows...)
		b.findings = append(b.findings, findings...)
		b.msgs = append(b.msgs, m)
	}

	return b
}

func parse(payload []byte) ([]model.Row, []model.FindingRow, error) {
	switch model.KindOf(payload) {
	case model.KindRequest, "":
		row, ok, err := model.FromRequest(payload)
		if err != nil || !ok {
			return nil, nil, err
		}

		return []model.Row{row}, nil, nil

	case model.KindInspector:
		ev, ok, err := model.FromInspector(payload)
		if err != nil || !ok {
			return nil, nil, err
		}

		return nil, ev.Findings, nil

	case model.KindBatch:
		items, ok := model.Batch(payload)
		if !ok {
			return nil, nil, nil
		}

		var (
			rows     []model.Row
			findings []model.FindingRow
			first    error
		)

		for _, item := range items {
			r, f, err := parse(item)
			if err != nil && first == nil {
				first = err
			}

			rows = append(rows, r...)
			findings = append(findings, f...)
		}

		return rows, findings, first
	}

	return nil, nil, nil
}

func flush(ctx context.Context, conn driver.Conn, b batch, stats *Stats,
	log *slog.Logger) {

	if len(b.msgs) == 0 {
		return
	}

	start := time.Now()
	err := write(ctx, conn, b.rows, b.findings)
	elapsed := time.Since(start)
	n := len(b.rows) + len(b.findings)

	if err != nil {
		log.Error("flush failed", "error", err.Error(),
			"anchors", len(b.rows), "findings", len(b.findings))

		if stats != nil {
			stats.Insert.AddN(n, 0, 0, true, elapsed)
		}

		for _, m := range b.msgs {
			_ = m.Nak()
		}

		return
	}

	if stats != nil {
		stats.Insert.AddN(n, 0, 0, false, elapsed)
	}

	for _, m := range b.msgs {
		if err := m.Ack(); err != nil {
			log.Warn("ack failed", "error", err.Error())
		}
	}

	stats.Add(n)

	log.Debug("inserted", "anchors", len(b.rows), "findings", len(b.findings))
}

func write(ctx context.Context, conn driver.Conn, rows []model.Row, findings []model.FindingRow) error {
	if err := sink.Insert(ctx, conn, rows); err != nil {
		return err
	}

	return sink.InsertFindings(ctx, conn, findings)
}
