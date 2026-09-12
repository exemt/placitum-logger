/*
 * Сквозная проверка на живом ClickHouse: запись модуля -> строка -> вставка ->
 * поиск. Ловит то, чего не видит компилятор, -- расхождение порядка колонок в
 * INSERT и в SELECT. Без WAF_CH_ADDR пропускается.
 *
 *   docker run -d --name ch -p 9000:9000 clickhouse/clickhouse-server
 *   WAF_CH_ADDR=127.0.0.1:9000 go test ./internal/sink/
 */

package sink_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"github.com/exemt/placitum-logger/internal/model"
	"github.com/exemt/placitum-logger/internal/query"
	"github.com/exemt/placitum-logger/internal/sink"
)

const anchor = `{
  "v": 1, "kind": "request",
  "ray": "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10",
  "node": "nginx-1", "phase": "request",
  "ts": "2026-08-15T21:42:31.660Z",
  "client_ip": "203.0.113.77", "client_port": 54233,
  "server_ip": "10.0.0.8", "server_port": 443,
  "tls": {"version": "TLSv1.3", "sni": "shop.example.com"},
  "http": {"method":"POST","scheme":"https","host":"shop.example.com",
           "uri":"/api/orders","version":"HTTP/1.1","args_size":37,
           "headers_size":96,"headers_count":11,"body_size":812,
           "content_type":"application/x-www-form-urlencoded","status":403},
  "route": {"server_name":"shop.example.com","location":"/api/"},
  "verdict": "deny", "code": "score", "by": "module",
  "score": {"total": 80, "deny_at": 50, "shadow": 40},
  "inspectors": {
    "module": {"verdict":"deny"},
    "modsec": {"verdict":"score","score":50,"latency_ms":4.2,"profile":"strict"},
    "ml": {"state":"timeout","latency_ms":20,"role":"passive"}
  },
  "vars": {"ua": "curl/8.5.0"},
  "store": {"headers":{"store":"hot","key":"k"},"args":null,"body":{"size":812}},
  "waf_latency_us": 9100
}`

const detail = `{
  "v": 1, "kind": "inspector",
  "ts": "2026-08-15T21:42:31.658Z",
  "ray": "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10",
  "node": "nginx-1", "phase": "request",
  "inspector": "modsec", "profile": "strict",
  "verdict": "score", "score": 50, "engine_ms": 1.25,
  "findings": [
    {"code":"crs-942100","severity":"high","target":"args","rule":"942100",
     "offset":12,"length":8,"evidence":"' OR 1=1"},
    {"code":"crs-913100","severity":"critical","target":"header:user-agent",
     "rule":"913100","confidence":0.75}
  ],
  "engine": {"crs_anomaly_score": 15, "crs_threshold": 5}
}`

/*
 * Находки едут в свою таблицу и ищутся по правилу без обращения к
 * позвоночнику: профиль и вердикт инспектора повторены на строке находки
 * именно ради этого.
 */
func TestFindingsRoundTrip(t *testing.T) {
	addr := os.Getenv("WAF_CH_ADDR")
	if addr == "" {
		t.Skip("WAF_CH_ADDR is not set")
	}

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Username: envOr("CLICKHOUSE_USER", "waf"),
			Password: envOr("CLICKHOUSE_PASSWORD", "waf"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ev, ok, err := model.FromInspector([]byte(detail))
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := sink.InsertFindings(ctx, conn, ev.Findings); err != nil {
		t.Fatalf("insert: %v", err)
	}

	found, err := query.ListFindings(ctx, conn, query.FindingFilter{
		Rule:  "913100",
		Node:  "nginx-1",
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("by rule: %v", err)
	}

	if len(found) != 1 {
		t.Fatalf("rows: %d", len(found))
	}

	item := found[0]

	if item.Code != "crs-913100" || item.Severity != "critical" || item.Index != 1 {
		t.Fatalf("finding: %+v", item)
	}

	if item.Profile != "strict" || item.Verdict != "score" || item.Score != 50 {
		t.Fatalf("event fields: %+v", item)
	}

	if item.Confidence != 0.75 || len(item.Engine) == 0 {
		t.Fatalf("engine: %+v", item)
	}

	card, err := query.FindingsByRay(ctx, conn, "nginx-1",
		"11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10")
	if err != nil {
		t.Fatalf("card: %v", err)
	}

	if len(card) != 2 || card[0].Rule != "942100" || card[1].Rule != "913100" {
		t.Fatalf("card order: %+v", card)
	}

	if card[0].Offset != 12 || card[0].Length != 8 || card[0].Evidence == "" {
		t.Fatalf("match location: %+v", card[0])
	}
}

func TestRoundTrip(t *testing.T) {
	addr := os.Getenv("WAF_CH_ADDR")
	if addr == "" {
		t.Skip("WAF_CH_ADDR is not set")
	}

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Username: envOr("CLICKHOUSE_USER", "waf"),
			Password: envOr("CLICKHOUSE_PASSWORD", "waf"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	row, ok, err := model.FromRequest([]byte(anchor))
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := sink.Insert(ctx, conn, []model.Row{row}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	events, err := query.List(ctx, conn, query.Filter{
		Node:  "nginx-1",
		Ray:   "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10",
		Limit: 1,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("rows: %d", len(events))
	}

	ev := events[0]

	if ev.Verdict != "deny" || ev.Code != "score" || ev.By != "module" {
		t.Fatalf("decision: %+v", ev)
	}

	if ev.ClientIP != "203.0.113.77" || ev.ServerIP != "10.0.0.8" {
		t.Fatalf("addresses: %q %q", ev.ClientIP, ev.ServerIP)
	}

	if ev.TLSVersion != "TLSv1.3" || ev.HTTPVersion != "HTTP/1.1" || ev.ContentType == "" {
		t.Fatalf("http: %+v", ev)
	}

	if ev.HeadersCount != 11 || ev.BodySize != 812 || ev.ArgsSize != 37 {
		t.Fatalf("sizes: %+v", ev)
	}

	if ev.ServerName != "shop.example.com" || ev.Location != "/api/" {
		t.Fatalf("route: %+v", ev)
	}

	if ev.Score != 80 || ev.DenyAt != 50 || ev.Shadow != 40 {
		t.Fatalf("score: %+v", ev)
	}

	if ev.InspectorsState["ml"] != "timeout" || ev.InspectorsLatencyMs["ml"] != 20 {
		t.Fatalf("silent: %+v", ev.InspectorsState)
	}

	if ev.InspectorsScore["modsec"] != 50 || ev.InspectorsProfile["modsec"] != "strict" {
		t.Fatalf("modsec: %+v", ev)
	}

	if ev.InspectorsVerdict["module"] != "deny" {
		t.Fatalf("module entry: %+v", ev.InspectorsVerdict)
	}

	if ev.Store == nil || len(ev.Store.Headers) == 0 || len(ev.Store.Body) == 0 {
		t.Fatalf("store: %+v", ev.Store)
	}

	if ev.InspectorsView != "ml: timeout, modsec: score [50]" {
		t.Fatalf("view: %q", ev.InspectorsView)
	}

	t.Logf("ts=%s vars=%v", ev.TS.Format(time.RFC3339Nano), ev.Vars)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
