package query

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/exemt/placitum-logger/internal/model"
)

func TestNormalizeVerdictAndLimit(t *testing.T) {
	f := Normalize(Filter{Verdict: "drop", Limit: 5000})
	if f.Verdict != "" || f.Limit != 200 {
		t.Fatalf("got %+v", f)
	}

	f = Normalize(Filter{Verdict: "deny", Limit: 0, Offset: -3, Method: "get"})
	if f.Verdict != "deny" || f.Limit != 50 || f.Offset != 0 || f.Method != "GET" {
		t.Fatalf("got %+v", f)
	}

	f = Normalize(Filter{Method: "FOO"})
	if f.Method != "" {
		t.Fatalf("method: %q", f.Method)
	}
}

func TestBuildUsesPlaceholders(t *testing.T) {
	sql, args := build(Normalize(Filter{
		Verdict:   "deny",
		Method:    "get",
		Host:      "app",
		URI:       "modsec",
		Status:    403,
		HasStatus: true,
		Inspector: "modsec",
		From:      time.Unix(0, 0).UTC(),
		To:        time.Unix(1, 0).UTC(),
		Limit:     10,
		Offset:    20,
	}))

	if strings.Contains(sql, "app") || strings.Contains(sql, "/modsec") {
		t.Fatalf("value leaked into SQL: %s", sql)
	}

	if !strings.Contains(sql, "verdict = @verdict") ||
		!strings.Contains(sql, "method = @method") ||
		!strings.Contains(sql, "lower(uri) LIKE @uri") ||
		!strings.Contains(sql, "status = @status") ||
		!strings.Contains(sql, "has(inspectors, @inspector)") {
		t.Fatalf("clauses: %s", sql)
	}

	if !strings.Contains(sql, "LIMIT @limit OFFSET @offset") {
		t.Fatalf("page: %s", sql)
	}

	if len(args) < 6 {
		t.Fatalf("args: %d", len(args))
	}

	countSQL, countArgs := buildCount(Normalize(Filter{
		Verdict: "deny",
		From:    time.Unix(0, 0).UTC(),
		To:      time.Unix(1, 0).UTC(),
	}))
	if !strings.Contains(countSQL, "SELECT count()") || strings.Contains(countSQL, "LIMIT") {
		t.Fatalf("count: %s", countSQL)
	}
	if len(countArgs) < 3 {
		t.Fatalf("count args: %d", len(countArgs))
	}
}

/*
 * Список читается без FINAL и в порядке ключа таблицы задом наперёд -- так
 * ClickHouse идёт с хвоста и останавливается на LIMIT. Счёт -- с FINAL: он
 * читает окно целиком, и дубль до слияния там снимает только он.
 */
func TestBuildListReadsKeyOrderWithoutFinal(t *testing.T) {
	sql, _ := build(Normalize(Filter{
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
	}))

	if strings.Contains(sql, "FINAL") {
		t.Fatalf("list must not use FINAL: %s", sql)
	}

	if !strings.Contains(sql, "FROM waf.audit ") ||
		!strings.Contains(sql, "ORDER BY ts DESC, node DESC, ray DESC, phase DESC,"+
			" frame_direction DESC, frame_seq DESC LIMIT") {
		t.Fatalf("order: %s", sql)
	}

	countSQL, _ := buildCount(Normalize(Filter{
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
	}))

	if !strings.Contains(countSQL, "FROM waf.audit FINAL") {
		t.Fatalf("count must use FINAL: %s", countSQL)
	}
}

/*
 * Порядок с начала окна -- тот же ключ таблицы, целиком развёрнутый. Смешать
 * направления нельзя: ClickHouse читает по ключу, только пока порядок запроса
 * совпадает с ключом или обратен ему, а иначе сортирует всё окно.
 */
func TestBuildListAscendingReversesWholeKey(t *testing.T) {
	sql, _ := build(Normalize(Filter{
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
		Asc:  true,
	}))

	if !strings.Contains(sql, "ORDER BY ts ASC, node ASC, ray ASC, phase ASC,"+
		" frame_direction ASC, frame_seq ASC LIMIT") {
		t.Fatalf("order: %s", sql)
	}

	if strings.Contains(sql, "DESC") {
		t.Fatalf("mixed direction: %s", sql)
	}
}

// Подстрока пути уходит шаблоном LIKE в нижнем регистре, как у тела: иначе
// ngram-индекс не включится. Символы шаблона в игле экранируются.
func TestBuildURILike(t *testing.T) {
	_, args := build(Normalize(Filter{
		URI:  "/Admin_100%",
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
	}))

	var got string
	for _, a := range args {
		if named, ok := a.(driver.NamedValue); ok && named.Name == "uri" {
			got, _ = named.Value.(string)
		}
	}

	if got != `%/admin\_100\%%` {
		t.Fatalf("uri pattern: %q", got)
	}
}

// Дубль до слияния -- та же строка с тем же ключом склейки; страница
// оставляет первый экземпляр. Кадры одного соединения -- разные строки.
func TestDedup(t *testing.T) {
	req := Event{Node: "edge-01", Ray: "r1", Phase: "request"}
	resp := Event{Node: "edge-01", Ray: "r1", Phase: "response"}
	f1 := Event{Node: "edge-01", Ray: "r1", Phase: "frame", Frame: &FrameInfo{Direction: "c2s", Seq: 1}}
	f2 := Event{Node: "edge-01", Ray: "r1", Phase: "frame", Frame: &FrameInfo{Direction: "c2s", Seq: 2}}

	got := dedup([]Event{req, req, resp, f1, f2, f1})
	if len(got) != 4 ||
		got[0].Phase != "request" || got[1].Phase != "response" ||
		got[2].Frame.Seq != 1 || got[3].Frame.Seq != 2 {
		t.Fatalf("dedup: %+v", got)
	}

	if len(dedup(nil)) != 0 || len(dedup([]Event{req})) != 1 {
		t.Fatal("short input must pass through")
	}
}

func TestParseList(t *testing.T) {
	got := ParseList([]string{"aaaa", "bbbb, cccc", "", "aaaa"})
	if len(got) != 3 || got[0] != "aaaa" || got[1] != "bbbb" || got[2] != "cccc" {
		t.Fatalf("routes = %v", got)
	}
}

func TestParseCIDRs(t *testing.T) {
	got := ParseCIDRs([]string{"10.0.0.1", "10.0.0.0/8, 192.168.1.0/24", "nope", "10.0.0.0/8"})
	if len(got) != 3 || got[0] != "10.0.0.1/32" || got[1] != "10.0.0.0/8" || got[2] != "192.168.1.0/24" {
		t.Fatalf("got %#v", got)
	}
}

// Концы префикса в пространстве v6: v4 ложится mapped'ом, как в колонке.
func TestIPRange(t *testing.T) {
	cases := []struct{ prefix, lo, hi string }{
		{"10.0.0.1/32", "::ffff:10.0.0.1", "::ffff:10.0.0.1"},
		{"10.0.0.0/8", "::ffff:10.0.0.0", "::ffff:10.255.255.255"},
		{"192.168.1.0/24", "::ffff:192.168.1.0", "::ffff:192.168.1.255"},
		{"2a02:6b8::/32", "2a02:6b8::", "2a02:6b8:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"2a02:6b8::1/128", "2a02:6b8::1", "2a02:6b8::1"},
	}

	for _, c := range cases {
		lo, hi := ipRange(netip.MustParsePrefix(c.prefix))
		if lo.String() != c.lo || hi.String() != c.hi {
			t.Fatalf("%s: lo=%s hi=%s", c.prefix, lo, hi)
		}
	}
}

/*
 * Одиночные адреса -- равенством через IN, сети -- сравнением с концами;
 * значения только плейсхолдерами. Равенство здесь не ради красоты: только
 * его видит bloom-индекс по адресу.
 */
func TestBuildCIDRPlaceholder(t *testing.T) {
	sql, args := build(Normalize(Filter{
		CIDRs: []string{"10.0.0.1", "10.0.0.0/8", "2a02:6b8::5"},
		From:  time.Unix(0, 0).UTC(),
		To:    time.Unix(1, 0).UTC(),
	}))

	if strings.Contains(sql, "10.0.0") || strings.Contains(sql, "2a02") {
		t.Fatalf("address leaked: %s", sql)
	}

	if !strings.Contains(sql, "client_ip IN (toIPv6(@ip0), toIPv6(@ip2))") ||
		!strings.Contains(sql,
			"(client_ip >= toIPv6(@iplo1) AND client_ip <= toIPv6(@iphi1))") {
		t.Fatalf("cidr clause: %s", sql)
	}

	if strings.Contains(sql, "isIPAddressInRange") || strings.Contains(sql, "IPv6NumToString") {
		t.Fatalf("string conversion per row is back: %s", sql)
	}

	// От двух до трёх адресных аргументов плюс окно и страница.
	if len(args) < 8 {
		t.Fatalf("args: %d", len(args))
	}
}

func TestParseVars(t *testing.T) {
	got := ParseVars([]string{"ua=curl/8.5.0", "ja3=", "novalue", "bad name=x", "eq=a=b"})

	if len(got) != 3 {
		t.Fatalf("got %#v", got)
	}

	if got[0].Name != "ua" || got[0].Value != "curl/8.5.0" {
		t.Fatalf("pair: %#v", got[0])
	}

	// Пустое значение — законный фильтр: ищем записи, где поле пустое.
	if got[1].Name != "ja3" || got[1].Value != "" {
		t.Fatalf("empty value: %#v", got[1])
	}

	// Значение с равенством внутри режется по первому знаку, а не отбрасывается.
	if got[2].Name != "eq" || got[2].Value != "a=b" {
		t.Fatalf("cut: %#v", got[2])
	}
}

func TestBuildVarsPlaceholders(t *testing.T) {
	sql, args := build(Normalize(Filter{
		Vars: ParseVars([]string{"ua=curl/8.5.0", "ja3=cd08e3"}),
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
	}))

	if strings.Contains(sql, "curl") || strings.Contains(sql, "cd08e3") ||
		strings.Contains(sql, "'ua'") {
		t.Fatalf("var leaked into SQL: %s", sql)
	}

	if !strings.Contains(sql, "vars[@vk0] = @vv0") ||
		!strings.Contains(sql, "vars[@vk1] = @vv1") {
		t.Fatalf("var clauses: %s", sql)
	}

	if len(args) < 8 {
		t.Fatalf("args: %d", len(args))
	}
}

func TestNormalizeCode(t *testing.T) {
	if f := Normalize(Filter{Code: "fail_timeout"}); f.Code != "fail_timeout" {
		t.Fatalf("code: %q", f.Code)
	}

	// Код вне закрытого набора схемы фильтром быть не может.
	if f := Normalize(Filter{Code: "SCORE_THRESHOLD"}); f.Code != "" {
		t.Fatalf("unknown code kept: %q", f.Code)
	}
}

// Точечный поиск по ray не сужается окном: ссылка из тикета обязана открыть
// вчерашний инцидент.
func TestBuildRayIgnoresWindow(t *testing.T) {
	sql, _ := build(Normalize(Filter{
		Ray:  "7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
		Node: "edge-01",
	}))

	if !strings.Contains(sql, "ray = @ray") || !strings.Contains(sql, "node = @node") {
		t.Fatalf("ray lookup: %s", sql)
	}

	if strings.Contains(sql, "ts >= @from") {
		t.Fatalf("ray lookup must not be windowed: %s", sql)
	}
}

func TestView(t *testing.T) {
	got := view(
		[]string{"ip", "modsec"},
		map[string]string{"ip": "allow", "modsec": "score"},
		map[string]string{},
		map[string]int32{"modsec": 50},
	)
	if got != "ip: allow, modsec: score [50]" {
		t.Fatalf("view: %q", got)
	}
}

// Молчун виден состоянием: иначе из списка не понять, из-за кого сорвалась
// волна.
func TestViewShowsState(t *testing.T) {
	got := view(
		[]string{"ml", "modsec", "probe"},
		map[string]string{"modsec": "allow"},
		map[string]string{"ml": "skipped", "probe": "timeout"},
		map[string]int32{},
	)
	if got != "ml: skipped, modsec: allow, probe: timeout" {
		t.Fatalf("view: %q", got)
	}
}

// Логин и идентификатор сессии -- has() по массиву, значения только
// плейсхолдерами.
func TestBuildSessionPlaceholders(t *testing.T) {
	sql, args := build(Normalize(Filter{
		User:      " alice@example.com ",
		SessionID: "sha256:ab12",
		From:      time.Unix(0, 0).UTC(),
		To:        time.Unix(1, 0).UTC(),
	}))

	if strings.Contains(sql, "alice") || strings.Contains(sql, "ab12") {
		t.Fatalf("value leaked into SQL: %s", sql)
	}

	if !strings.Contains(sql, "has(sessions_user, @user)") ||
		!strings.Contains(sql, "has(sessions_id, @session)") {
		t.Fatalf("clauses: %s", sql)
	}

	if len(args) < 6 {
		t.Fatalf("args: %d", len(args))
	}
}

// Управляющий символ в логине -- не фильтр: опечатка либо попытка залезть в
// SQL, и в обоих случаях условие выбрасывается.
func TestNormalizeSessionText(t *testing.T) {
	f := Normalize(Filter{User: "ali\nce", SessionID: strings.Repeat("x", 300)})

	if f.User != "" || f.SessionID != "" {
		t.Fatalf("user=%q session=%q", f.User, f.SessionID)
	}

	if f := Normalize(Filter{User: "alice"}); f.User != "alice" {
		t.Fatalf("user: %q", f.User)
	}
}

// Параллельные массивы собираются обратно в записи; короткий массив читается
// пустым полем, а не паникой на индексе.
func TestSessionsFromArrays(t *testing.T) {
	row := model.Row{
		SessionsBy:       []string{"auth", ""},
		SessionsSource:   []string{"corp", "shop"},
		SessionsKind:     []string{"own", "app"},
		SessionsUser:     []string{"alice", ""},
		SessionsID:       []string{"k7f3", "sha256:ab12"},
		SessionsVerified: []uint8{1, 0},
		SessionsIssued:   []uint32{1757232000},
		SessionsExpires:  []uint32{},
		SessionsGroups:   []string{"ops"},
		SessionsPassive:  []uint8{0, 1},
	}

	got := sessions(&row)
	if len(got) != 2 {
		t.Fatalf("len: %d", len(got))
	}

	if got[0].By != "auth" || got[0].User != "alice" || !got[0].Verified ||
		got[0].Issued != 1757232000 || got[0].Groups != "ops" || got[0].Passive {
		t.Fatalf("first: %#v", got[0])
	}

	if got[1].By != "" || got[1].Kind != "app" || got[1].Verified ||
		got[1].Issued != 0 || got[1].Groups != "" || !got[1].Passive {
		t.Fatalf("second: %#v", got[1])
	}

	if sessions(&model.Row{}) != nil {
		t.Fatal("empty row must give nil sessions")
	}
}

/*
 * Пара «источник:логин» -- другое условие: не has() по одному массиву, а
 * совпадение по позиции в двух. Голый логин остаётся has(): «этот логин у кого
 * угодно» -- по-прежнему законный вопрос.
 */
func TestBuildIdentityPair(t *testing.T) {
	sql, _ := build(Normalize(Filter{
		User: "corp:alice",
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
	}))

	if strings.Contains(sql, "alice") || strings.Contains(sql, "corp") {
		t.Fatalf("value leaked into SQL: %s", sql)
	}

	if !strings.Contains(sql,
		"arrayExists((s, u) -> s = @user_source AND u = @user,"+
			" sessions_source, sessions_user)") {
		t.Fatalf("clause: %s", sql)
	}

	if strings.Contains(sql, "has(sessions_user") {
		t.Fatalf("pair fell back to bare login: %s", sql)
	}
}

// Двоеточие делит по первому: имя источника его не содержит, логин бывает
// урной. Строка, начатая двоеточием, -- логин с двоеточием у любого источника.
func TestSplitIdentity(t *testing.T) {
	cases := []struct{ raw, source, user string }{
		{"alice", "", "alice"},
		{"corp:alice", "corp", "alice"},
		{"corp:urn:user:1", "corp", "urn:user:1"},
		{":urn:user:1", "", "urn:user:1"},
	}

	for _, c := range cases {
		source, user := SplitIdentity(c.raw)
		if source != c.source || user != c.user {
			t.Fatalf("%q: source=%q user=%q", c.raw, source, user)
		}
	}

	// Экранированный логин доходит до has(), а не до пары.
	sql, _ := build(Normalize(Filter{
		User: ":urn:user:1",
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
	}))

	if !strings.Contains(sql, "has(sessions_user, @user)") {
		t.Fatalf("escaped login: %s", sql)
	}
}
