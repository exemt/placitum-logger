package model

import "testing"

// Полная запись по docs/messages/agent.schema.ts плюс конверт агента.
const anchor = `{
  "v": 1,
  "kind": "request",
  "ray": "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10",
  "node": "nginx-1",
  "phase": "request",
  "ts": "2026-08-15T21:42:31.660Z",
  "client_ip": "203.0.113.77",
  "client_port": 54233,
  "server_ip": "10.0.0.8",
  "server_port": 443,
  "tls": {"version": "TLSv1.3", "sni": "shop.example.com"},
  "http": {
    "method": "POST",
    "scheme": "https",
    "host": "shop.example.com",
    "uri": "/api/orders",
    "version": "HTTP/1.1",
    "args_size": 37,
    "headers_size": 96,
    "headers_count": 11,
    "body_size": 812,
    "content_type": "application/x-www-form-urlencoded",
    "status": 403
  },
  "route": {"server_name": "shop.example.com", "location": "/api/",
            "id": "6a0b6d6e-1c2d-4e3f-8a9b-0c1d2e3f4a5b"},
  "verdict": "deny",
  "code": "score",
  "by": "module",
  "score": {"total": 80, "deny_at": 50, "shadow": 40},
  "inspectors": {
    "module": {"verdict": "deny"},
    "modsec": {
      "verdict": "score",
      "score": 50,
      "latency_ms": 4.2,
      "profile": "strict"
    },
    "ml": {"verdict": "score", "score": 40, "latency_ms": 7.5, "role": "passive"}
  },
  "vars": {"ua": "curl/8.5.0", "country": "NL"},
  "store": {
    "headers": {"store": "hot", "driver": "redis", "key": "k:hdr", "size": 96},
    "args": null,
    "body": {"size": 812, "truncated": false, "store": "hot"}
  },
  "waf_latency_us": 9100
}`

func TestFromRequestRoute(t *testing.T) {
	row, ok, err := FromRequest([]byte(anchor))
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	// Имя блока и uuid пути едут рядом: по имени читают, по uuid схлопывают.
	if row.ServerName != "shop.example.com" || row.Location != "/api/" {
		t.Fatalf("route names: %s %s", row.ServerName, row.Location)
	}

	if row.LocationID != "6a0b6d6e-1c2d-4e3f-8a9b-0c1d2e3f4a5b" {
		t.Fatalf("route id: %q", row.LocationID)
	}
}

func TestFromRequestIdentity(t *testing.T) {
	row, ok, err := FromRequest([]byte(anchor))
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	if row.Node != "nginx-1" || row.Ray != "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10" {
		t.Fatalf("key: %s %s", row.Node, row.Ray)
	}

	if row.Phase != "request" {
		t.Fatalf("phase: %q", row.Phase)
	}

	// ts ставит модуль, не логгер: это момент поступления запроса.
	if got := row.TS.Format("2006-01-02T15:04:05.000Z"); got != "2026-08-15T21:42:31.660Z" {
		t.Fatalf("ts: %s", got)
	}
}

func TestFromRequestConnection(t *testing.T) {
	row, _, err := FromRequest([]byte(anchor))
	if err != nil {
		t.Fatal(err)
	}

	if row.ClientIP.String() != "203.0.113.77" || row.ClientPort != 54233 {
		t.Fatalf("client: %s %d", row.ClientIP, row.ClientPort)
	}

	if row.ServerIP.String() != "10.0.0.8" || row.ServerPort != 443 {
		t.Fatalf("server: %s %d", row.ServerIP, row.ServerPort)
	}

	if row.TLSVersion != "TLSv1.3" || row.TLSSNI != "shop.example.com" {
		t.Fatalf("tls: %q %q", row.TLSVersion, row.TLSSNI)
	}
}

func TestFromRequestHTTPAndRoute(t *testing.T) {
	row, _, err := FromRequest([]byte(anchor))
	if err != nil {
		t.Fatal(err)
	}

	if row.Method != "POST" || row.Scheme != "https" || row.HTTPVersion != "HTTP/1.1" {
		t.Fatalf("http: %+v", row)
	}

	if row.ArgsSize != 37 || row.HeadersSize != 96 || row.HeadersCount != 11 || row.BodySize != 812 {
		t.Fatalf("sizes: %+v", row)
	}

	if row.ContentType != "application/x-www-form-urlencoded" || row.Status != 403 {
		t.Fatalf("content: %q %d", row.ContentType, row.Status)
	}

	if row.ServerName != "shop.example.com" || row.Location != "/api/" {
		t.Fatalf("route: %q %q", row.ServerName, row.Location)
	}
}

// Три вопроса — три поля: что сделали, почему, кто.
func TestFromRequestDecision(t *testing.T) {
	row, _, err := FromRequest([]byte(anchor))
	if err != nil {
		t.Fatal(err)
	}

	if row.Verdict != "deny" || row.Code != "score" || row.VerdictBy != "module" {
		t.Fatalf("decision: %q %q %q", row.Verdict, row.Code, row.VerdictBy)
	}

	if row.Score != 80 || row.DenyAt != 50 || row.Shadow != 40 {
		t.Fatalf("score: %d %d %d", row.Score, row.DenyAt, row.Shadow)
	}

	if row.WAFLatencyUs != 9100 {
		t.Fatalf("latency: %d", row.WAFLatencyUs)
	}
}

func TestFromRequestInspectorsSpread(t *testing.T) {
	row, _, err := FromRequest([]byte(anchor))
	if err != nil {
		t.Fatal(err)
	}

	// Массив — только инспекторы: он отвечает на "кого звали".
	if len(row.Inspectors) != 2 || row.Inspectors[0] != "ml" || row.Inspectors[1] != "modsec" {
		t.Fatalf("inspectors: %v", row.Inspectors)
	}

	// Итог модуля из карты не выбрасывается: это такой же участник.
	if row.InspectorsVerdict[SelfKey] != "deny" {
		t.Fatalf("module entry lost: %v", row.InspectorsVerdict)
	}

	if row.InspectorsScore["modsec"] != 50 {
		t.Fatalf("score: %v", row.InspectorsScore)
	}

	if row.InspectorsLatencyMs["modsec"] != 4.2 {
		t.Fatalf("latency: %v", row.InspectorsLatencyMs)
	}

	if row.InspectorsProfile["modsec"] != "strict" || row.InspectorsRole["ml"] != "passive" {
		t.Fatalf("role/profile: %v %v", row.InspectorsRole, row.InspectorsProfile)
	}
}

func TestFromRequestStoreLocators(t *testing.T) {
	row, _, err := FromRequest([]byte(anchor))
	if err != nil {
		t.Fatal(err)
	}

	if row.StoreHeaders == "" || row.StoreBody == "" {
		t.Fatalf("locators: %q %q", row.StoreHeaders, row.StoreBody)
	}

	// null — объект не сохраняли; в колонке пусто, а не строка "null".
	if row.StoreArgs != "" {
		t.Fatalf("args must be empty: %q", row.StoreArgs)
	}
}

func TestFromRequestVars(t *testing.T) {
	row, _, err := FromRequest([]byte(anchor))
	if err != nil {
		t.Fatal(err)
	}

	if row.Vars["ua"] != "curl/8.5.0" || row.Vars["country"] != "NL" {
		t.Fatalf("vars: %#v", row.Vars)
	}
}

// Молчун обязан доехать: без него code=fail_timeout не объясняет, из-за кого.
func TestFromRequestSilentInspectors(t *testing.T) {
	raw := []byte(`{
	  "kind": "request",
	  "ray": "9a0b1c2d-3e4f-4567-89ab-cdef01234567",
	  "node": "nginx-1",
	  "phase": "request",
	  "ts": "2026-08-15T21:43:07.212Z",
	  "verdict": "deny",
	  "code": "fail_timeout",
	  "by": "module",
	  "inspectors": {
	    "module": {"verdict": "deny"},
	    "modsec": {"state": "timeout", "latency_ms": 20, "profile": "strict"},
	    "probe": {"state": "absent"},
	    "ml": {"state": "skipped"}
	  },
	  "waf_latency_us": 21000
	}`)

	row, ok, err := FromRequest(raw)
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	if row.Code != "fail_timeout" {
		t.Fatalf("code: %q", row.Code)
	}

	want := map[string]string{"modsec": "timeout", "probe": "absent", "ml": "skipped"}

	for name, state := range want {
		if row.InspectorsState[name] != state {
			t.Fatalf("%s: %v", name, row.InspectorsState)
		}
	}

	// У молчуна вердикта нет вовсе — ровно одно из verdict / state.
	if _, ok := row.InspectorsVerdict["probe"]; ok {
		t.Fatalf("silent inspector must not have a verdict: %v", row.InspectorsVerdict)
	}

	if row.InspectorsLatencyMs["modsec"] != 20 {
		t.Fatalf("timeout latency: %v", row.InspectorsLatencyMs)
	}
}

func TestFromRequestAllowHasNoCode(t *testing.T) {
	raw := []byte(`{
	  "kind": "request",
	  "ray": "7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
	  "node": "nginx-1",
	  "verdict": "allow",
	  "by": "module",
	  "inspectors": {"module": {"verdict": "allow"}}
	}`)

	row, ok, err := FromRequest(raw)
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	if row.Code != "" || row.Verdict != "allow" {
		t.Fatalf("allow: %q %q", row.Verdict, row.Code)
	}

	if row.Vars == nil || len(row.Vars) != 0 {
		t.Fatalf("vars must be empty map, not nil: %#v", row.Vars)
	}
}

// Превью приезжает парами, а в колонке нужна карта. Повторяющееся имя
// склеивается по правилу составных заголовков; регистр опускается только у
// заголовков — userId и userid для приложения разные.
func TestFromRequestPreviewFolds(t *testing.T) {
	raw := []byte(`{
	  "kind": "request",
	  "ray": "7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
	  "node": "nginx-1",
	  "verdict": "allow",
	  "headers_preview": [
	    ["X-Forwarded-For", "203.0.113.7"],
	    ["user-agent", "curl/8.5.0"],
	    ["x-forwarded-for", "198.51.100.4"]
	  ],
	  "args_preview": [["userId", "7"], ["userid", "9"]],
	  "body_preview": "id=7&next=/admin"
	}`)

	row, ok, err := FromRequest(raw)
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	if row.HeadersPreview["x-forwarded-for"] != "203.0.113.7, 198.51.100.4" {
		t.Fatalf("fold: %#v", row.HeadersPreview)
	}

	if row.ArgsPreview["userId"] != "7" || row.ArgsPreview["userid"] != "9" {
		t.Fatalf("args case: %#v", row.ArgsPreview)
	}

	if row.BodyPreview != "id=7&next=/admin" {
		t.Fatalf("body: %q", row.BodyPreview)
	}

	if len(row.HeadersPreviewTruncated) != 0 || row.HeadersPreviewDropped != 0 {
		t.Fatalf("nothing was cut: %v %d",
			row.HeadersPreviewTruncated, row.HeadersPreviewDropped)
	}
}

// Третий элемент пары говорит, что значение урезано потолком на пару. Без него
// показ выдал бы префикс за оригинал, а сравнение с headers_count на это уже не
// отвечает: длина карты та же.
func TestFromRequestPreviewTruncation(t *testing.T) {
	raw := []byte(`{
	  "kind": "request",
	  "ray": "7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
	  "node": "nginx-1",
	  "verdict": "allow",
	  "headers_preview": [
	    ["X-Trace", "abcd", 1],
	    ["user-agent", "curl/8.5.0"]
	  ],
	  "args_preview": [["q", "<scr", 1]],
	  "headers_preview_dropped": 2,
	  "args_preview_dropped": 1
	}`)

	row, ok, err := FromRequest(raw)
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	// Значение — то, что доехало: приписки в нём быть не должно, по нему ищут.
	if row.HeadersPreview["x-trace"] != "abcd" {
		t.Fatalf("value touched: %#v", row.HeadersPreview)
	}

	if len(row.HeadersPreviewTruncated) != 1 ||
		row.HeadersPreviewTruncated[0] != "x-trace" {
		t.Fatalf("headers truncated: %v", row.HeadersPreviewTruncated)
	}

	if len(row.ArgsPreviewTruncated) != 1 || row.ArgsPreviewTruncated[0] != "q" {
		t.Fatalf("args truncated: %v", row.ArgsPreviewTruncated)
	}

	if row.HeadersPreviewDropped != 2 || row.ArgsPreviewDropped != 1 {
		t.Fatalf("dropped: %d %d",
			row.HeadersPreviewDropped, row.ArgsPreviewDropped)
	}
}

// Без ray запись не склеивается ни с волной, ни с kind=inspector.
func TestFromRequestNeedsRayAndNode(t *testing.T) {
	for _, raw := range []string{
		`{"kind":"request","node":"edge-01","verdict":"allow"}`,
		`{"kind":"request","ray":"7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03","verdict":"allow"}`,
	} {
		if _, ok, err := FromRequest([]byte(raw)); ok || err != nil {
			t.Fatalf("%s: ok=%v err=%v", raw, ok, err)
		}
	}
}

func TestFromRequestSkipInspector(t *testing.T) {
	_, ok, err := FromRequest([]byte(
		`{"kind":"inspector","ray":"7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03","node":"edge-01"}`))
	if err != nil || ok {
		t.Fatalf("skip: ok=%v err=%v", ok, err)
	}
}

/*
 * Секции rewrite участников складываются в одну строку картой "инспектор ->
 * секция". Ключи отсортированы: та же запись, доставленная дважды, обязана дать
 * ту же строку, иначе ReplacingMergeTree оставит обе копии.
 */
func TestFromRequestRewrite(t *testing.T) {
	raw := `{"kind":"request","ray":"7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
	  "node":"edge-01","verdict":"allow",
	  "inspectors":{
	    "rewrite-obs":{"verdict":"allow","rewrite":{"applied":false,"groups":["mask"]}},
	    "rewrite":{"verdict":"allow","rewrite":{"applied":true,"size":128,"groups":["mask","hdrs"]}},
	    "modsec":{"verdict":"allow"}
	  }}`

	row, ok, err := FromRequest([]byte(raw))
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	want := `{"rewrite":{"applied":true,"size":128,"groups":["mask","hdrs"]},` +
		`"rewrite-obs":{"applied":false,"groups":["mask"]}}`

	if row.Rewrite != want {
		t.Fatalf("rewrite:\n got %s\nwant %s", row.Rewrite, want)
	}
}

// Правку никто не заказывал -- колонка пуста. Пустой объект "{}" читался бы
// как "правка была и потерялась".
func TestFromRequestWithoutRewrite(t *testing.T) {
	row, ok, err := FromRequest([]byte(anchor))
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	if row.Rewrite != "" {
		t.Fatalf("rewrite: %q, want empty", row.Rewrite)
	}
}

// Секция sessions раскладывается в параллельные массивы одной длины: i-й
// элемент каждого -- одна запись. Запись без source пропускается целиком,
// иначе дырка в одном массиве сдвинула бы остальные.
func TestFromRequestSessions(t *testing.T) {
	raw := `{"kind":"request","ray":"7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
	  "node":"edge-01","verdict":"allow",
	  "inspectors":{"auth":{"verdict":"allow"}},
	  "sessions":[
	    {"by":"auth","source":"corp","kind":"own","user":"alice","id":"k7f3",
	     "verified":true,"issued":1757232000,"expires":1757260800,"groups":"ops,dev"},
	    {"by":null,"source":"shop","kind":"app","user":"","id":"sha256:ab12",
	     "verified":false,"passive":true},
	    {"by":"auth","source":"","kind":"own","user":"ghost","id":"x"}
	  ]}`

	row, ok, err := FromRequest([]byte(raw))
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	if len(row.SessionsSource) != 2 || len(row.SessionsUser) != 2 ||
		len(row.SessionsPassive) != 2 || len(row.SessionsIssued) != 2 {
		t.Fatalf("lengths: source=%d user=%d passive=%d issued=%d",
			len(row.SessionsSource), len(row.SessionsUser),
			len(row.SessionsPassive), len(row.SessionsIssued))
	}

	if row.SessionsBy[0] != "auth" || row.SessionsSource[0] != "corp" ||
		row.SessionsKind[0] != "own" || row.SessionsUser[0] != "alice" ||
		row.SessionsID[0] != "k7f3" || row.SessionsVerified[0] != 1 ||
		row.SessionsIssued[0] != 1757232000 || row.SessionsExpires[0] != 1757260800 ||
		row.SessionsGroups[0] != "ops,dev" || row.SessionsPassive[0] != 0 {
		t.Fatalf("first: %#v", row)
	}

	if row.SessionsBy[1] != "" || row.SessionsUser[1] != "" ||
		row.SessionsVerified[1] != 0 || row.SessionsPassive[1] != 1 ||
		row.SessionsIssued[1] != 0 {
		t.Fatalf("second: by=%q user=%q verified=%d passive=%d",
			row.SessionsBy[1], row.SessionsUser[1],
			row.SessionsVerified[1], row.SessionsPassive[1])
	}
}

// Секции нет -- пустые массивы, не nil: карточка печатает [], а не null.
func TestFromRequestWithoutSessions(t *testing.T) {
	row, ok, err := FromRequest([]byte(anchor))
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	if row.SessionsSource == nil || len(row.SessionsSource) != 0 ||
		row.SessionsUser == nil || row.SessionsPassive == nil {
		t.Fatalf("sessions: %#v %#v %#v", row.SessionsSource, row.SessionsUser,
			row.SessionsPassive)
	}
}

/*
 * Маркеры: множество строк. Модуль повторов не печатает, но колонка пишется не
 * только им, а повтор в массиве сбил бы счёт группировки -- поэтому дубли и
 * пустые строки отбрасываются здесь, а порядок первого появления сохраняется.
 */
func TestFromRequestMarkers(t *testing.T) {
	raw := `{"kind":"request","ray":"7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
	  "node":"edge-01","verdict":"allow",
	  "inspectors":{"modsec":{"verdict":"allow"}},
	  "markers":["bot-farm","","checkout probe","bot-farm"]}`

	row, ok, err := FromRequest([]byte(raw))
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	if len(row.Markers) != 2 || row.Markers[0] != "bot-farm" ||
		row.Markers[1] != "checkout probe" {
		t.Fatalf("markers: %#v", row.Markers)
	}
}

// Секции нет -- пустой массив, не nil: колонка не nullable.
func TestFromRequestWithoutMarkers(t *testing.T) {
	row, ok, err := FromRequest([]byte(anchor))
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	if row.Markers == nil || len(row.Markers) != 0 {
		t.Fatalf("markers: %#v", row.Markers)
	}
}
