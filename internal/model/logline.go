package model

import (
	"encoding/json"
	"strings"
	"time"
)

const KindLog = "log"

const maxText = 8 << 10

type LogRow struct {
	TS       time.Time
	Writer   string
	Service  string
	Severity string
	Text     string
}

type logLine struct {
	TS       string `json:"ts"`
	Service  string `json:"service"`
	Severity string `json:"severity"`
	Text     string `json:"text"`
}

type logBatch struct {
	Writer string    `json:"writer"`
	Lines  []logLine `json:"lines"`
}

const defaultService = "nginx"

func FromLog(payload []byte) ([]LogRow, error) {
	var b logBatch

	if err := json.Unmarshal(payload, &b); err != nil {
		return nil, err
	}

	writer := strings.TrimSpace(b.Writer)
	if writer == "" {
		writer = "unknown"
	}

	out := make([]LogRow, 0, len(b.Lines))

	for _, line := range b.Lines {
		text := line.Text
		if text == "" {
			continue
		}

		if len(text) > maxText {
			text = text[:maxText]
		}

		ts, err := time.Parse(time.RFC3339Nano, line.TS)
		if err != nil {
			ts = time.Now().UTC()
		}

		service := line.Service
		if service == "" {
			service = defaultService
		}

		out = append(out, LogRow{
			TS:       ts.UTC(),
			Writer:   writer,
			Service:  service,
			Severity: line.Severity,
			Text:     text,
		})
	}

	return out, nil
}
