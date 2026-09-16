package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/exemt/placitum-logger/internal/store"
)

type api struct {
	conn  driver.Conn
	store *store.Reader
	log   *slog.Logger
}

func Handler(conn driver.Conn, reader *store.Reader, log *slog.Logger) http.Handler {
	a := &api{conn: conn, store: reader, log: log}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("GET /api/audit", a.list)

	mux.HandleFunc("GET /api/audit/groups", a.groups)

	mux.HandleFunc("GET /api/audit/{node}/{ray}", a.one)

	mux.HandleFunc("GET /api/audit/{node}/{ray}/inspectors", a.inspectors)

	mux.HandleFunc("GET /api/audit/{node}/{ray}/findings", a.cardFindings)

	mux.HandleFunc("GET /api/audit/{node}/{ray}/headers", a.content("headers"))
	mux.HandleFunc("GET /api/audit/{node}/{ray}/args", a.content("args"))
	mux.HandleFunc("GET /api/audit/{node}/{ray}/body", a.content("body"))

	mux.HandleFunc("GET /api/findings", a.findings)

	mux.HandleFunc("GET /api/logs", a.logs)
	mux.HandleFunc("GET /api/logs/facets", a.logFacets)

	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	_ = enc.Encode(v)
}

func fail(w http.ResponseWriter, code int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
}

func (a *api) broken(w http.ResponseWriter, what string, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}

	a.log.Error(what, "error", err.Error())
	fail(w, http.StatusBadGateway, "query_failed")
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func parseStatus(s string) (uint16, bool) {
	if s == "" {
		return 0, false
	}

	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 999 {
		return 0, false
	}

	return uint16(n), true
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}

	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}

	return t.UTC()
}
