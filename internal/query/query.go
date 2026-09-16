package query

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/exemt/placitum-logger/internal/model"
)

const cols = `ts, node, ray, phase,
	client_ip, client_port, server_ip, server_port, tls_version, tls_sni,
	method, scheme, host, uri, http_version,
	args_size, headers_size, headers_count, body_size, content_type, status,
	upstream_status,
	server_name, location, location_id,
	verdict, code, verdict_by,
	score, deny_at, shadow, waf_latency_us,
	inspectors, inspectors_verdict, inspectors_state, inspectors_score,
	inspectors_latency_ms, inspectors_role,
	inspectors_profile,
	vars,
	store_headers, store_args, store_body,
	frame_seq, frame_direction, frame_opcode, frame_size, frame_fin,
	frame_rewritten,
	session_frames_c2s, session_frames_s2c, session_bytes_c2s, session_bytes_s2c,
	session_denied, session_rewritten, session_close_code, session_close_reason,
	session_duration_ms,
	sessions_by, sessions_source, sessions_kind, sessions_user, sessions_id,
	sessions_verified, sessions_issued, sessions_expires, sessions_groups,
	sessions_passive,
	markers`

const colsPreview = cols + `,
	headers_preview, args_preview, body_preview,
	headers_preview_truncated, args_preview_truncated,
	headers_preview_dropped, args_preview_dropped,
	actions, rewrite, frame_preview, frame_preview_truncated`

const (
	fromFinal = " FROM waf.audit FINAL"
	fromRaw   = " FROM waf.audit"
)

const (
	listOrderDesc = " ORDER BY ts DESC, node DESC, ray DESC, phase DESC," +
		" frame_direction DESC, frame_seq DESC"
	listOrderAsc = " ORDER BY ts ASC, node ASC, ray ASC, phase ASC," +
		" frame_direction ASC, frame_seq ASC"
)

func listOrder(asc bool) string {
	if asc {
		return listOrderAsc
	}

	return listOrderDesc
}

type Filter struct {
	From           time.Time
	To             time.Time
	Verdict        string
	Code           string
	Method         string
	Host           string
	URI            string
	Ray            string
	Phase          string
	FrameDirection string
	FrameSeq       uint64
	Status         uint16
	HasStatus      bool
	Node           string
	Inspector      string
	CIDRs          []string

	Country string
	ASN     uint32

	LocationIDs []string

	ServerNames []string

	Vars []VarFilter

	User      string
	SessionID string

	Marker string

	Headers []VarFilter
	Params  []VarFilter
	Body    string

	WithPreview bool

	Asc bool

	Limit  int
	Offset int
}

type VarFilter struct {
	Name  string
	Value string
}

type Event struct {
	TS    time.Time `json:"ts"`
	Node  string    `json:"node"`
	Ray   string    `json:"ray"`
	Phase string    `json:"phase"`

	ClientIP   string `json:"client_ip,omitempty"`
	ClientPort uint16 `json:"client_port,omitempty"`
	ServerIP   string `json:"server_ip,omitempty"`
	ServerPort uint16 `json:"server_port,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
	TLSSNI     string `json:"tls_sni,omitempty"`

	Method         string `json:"method"`
	Scheme         string `json:"scheme,omitempty"`
	Host           string `json:"host"`
	URI            string `json:"uri"`
	HTTPVersion    string `json:"http_version,omitempty"`
	ArgsSize       uint32 `json:"args_size"`
	HeadersSize    uint32 `json:"headers_size"`
	HeadersCount   uint16 `json:"headers_count"`
	BodySize       uint64 `json:"body_size"`
	ContentType    string `json:"content_type,omitempty"`
	Status         uint16 `json:"status"`
	UpstreamStatus uint16 `json:"upstream_status,omitempty"`

	ServerName string `json:"server_name,omitempty"`
	Location   string `json:"location,omitempty"`
	LocationID string `json:"location_id,omitempty"`

	Verdict string `json:"verdict"`
	Code    string `json:"code,omitempty"`
	By      string `json:"by"`

	Score  int32 `json:"score"`
	DenyAt int32 `json:"deny_at,omitempty"`
	Shadow int32 `json:"shadow,omitempty"`

	Actions string `json:"-"`

	Rewrite string `json:"-"`

	WAFLatencyUs uint32 `json:"waf_latency_us"`

	Inspectors          []string           `json:"inspectors"`
	InspectorsVerdict   map[string]string  `json:"inspectors_verdict"`
	InspectorsState     map[string]string  `json:"inspectors_state,omitempty"`
	InspectorsScore     map[string]int32   `json:"inspectors_score"`
	InspectorsLatencyMs map[string]float32 `json:"inspectors_latency_ms,omitempty"`
	InspectorsRole      map[string]string  `json:"inspectors_role,omitempty"`
	InspectorsProfile   map[string]string  `json:"inspectors_profile,omitempty"`
	InspectorsView      string             `json:"inspectors_view"`

	Vars map[string]string `json:"vars,omitempty"`

	Sessions []SessionEntry `json:"sessions,omitempty"`

	Markers []string `json:"markers,omitempty"`

	Store *Store `json:"store,omitempty"`

	HeadersPreview map[string]string `json:"headers_preview,omitempty"`
	ArgsPreview    map[string]string `json:"args_preview,omitempty"`
	BodyPreview    string            `json:"body_preview,omitempty"`

	HeadersPreviewTruncated []string `json:"headers_preview_truncated,omitempty"`
	ArgsPreviewTruncated    []string `json:"args_preview_truncated,omitempty"`
	HeadersPreviewDropped   uint16   `json:"headers_preview_dropped,omitempty"`
	ArgsPreviewDropped      uint16   `json:"args_preview_dropped,omitempty"`

	Frame   *FrameInfo   `json:"frame,omitempty"`
	Session *SessionInfo `json:"session,omitempty"`
}

type SessionEntry struct {
	By       string `json:"by,omitempty"`
	Source   string `json:"source"`
	Kind     string `json:"kind"`
	User     string `json:"user"`
	ID       string `json:"id"`
	Verified bool   `json:"verified"`
	Issued   uint32 `json:"issued,omitempty"`
	Expires  uint32 `json:"expires,omitempty"`
	Groups   string `json:"groups,omitempty"`
	Passive  bool   `json:"passive,omitempty"`
}

type FrameInfo struct {
	Seq              uint64 `json:"seq"`
	Direction        string `json:"direction"`
	Opcode           string `json:"opcode"`
	Fin              bool   `json:"fin"`
	Size             uint32 `json:"size"`
	Rewritten        bool   `json:"rewritten"`
	PayloadPreview   string `json:"payload_preview,omitempty"`
	PayloadTruncated bool   `json:"payload_truncated,omitempty"`
}

type SessionInfo struct {
	FramesC2S   uint64 `json:"frames_c2s"`
	FramesS2C   uint64 `json:"frames_s2c"`
	BytesC2S    uint64 `json:"bytes_c2s"`
	BytesS2C    uint64 `json:"bytes_s2c"`
	Denied      uint32 `json:"frames_denied"`
	Rewritten   uint32 `json:"frames_rewritten"`
	CloseCode   uint16 `json:"close_code"`
	CloseReason string `json:"close_reason"`
	DurationMs  uint32 `json:"duration_ms"`
}

type Store struct {
	Headers json.RawMessage `json:"headers,omitempty"`
	Args    json.RawMessage `json:"args,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
}

func Normalize(f Filter) Filter {
	if f.Limit <= 0 {
		f.Limit = 50
	}

	if f.Limit > 200 {
		f.Limit = 200
	}

	if f.Offset < 0 {
		f.Offset = 0
	}

	switch f.Verdict {
	case "allow", "deny", "redirect", "":
	default:
		f.Verdict = ""
	}

	f.Method = strings.ToUpper(strings.TrimSpace(f.Method))
	switch f.Method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE", "":
	default:
		f.Method = ""
	}

	switch f.Code {
	case "local_list", "local_rate", "inspector", "score",
		"fail_timeout", "fail_absent", "fail_bus", "fail_body", "":
	default:
		f.Code = ""
	}

	switch f.Phase {
	case "request", "response", "frame", "session", "":
	default:
		f.Phase = ""
	}

	f.Country = normalizeCountry(f.Country)
	f.CIDRs = ParseCIDRs(f.CIDRs)
	f.LocationIDs = ParseList(f.LocationIDs)
	f.ServerNames = ParseList(f.ServerNames)
	f.Vars = normalizeVars(f.Vars)
	f.Headers = normalizeNames(f.Headers, true)
	f.Params = normalizeNames(f.Params, false)
	f.User = sessionText(f.User)
	f.SessionID = sessionText(f.SessionID)

	if len(f.Body) > maxBodyQuery {
		f.Body = f.Body[:maxBodyQuery]
	}

	if f.Ray == "" {
		if f.To.IsZero() {
			f.To = time.Now().UTC()
		}

		if f.From.IsZero() {
			f.From = f.To.Add(-24 * time.Hour)
		}
	}

	return f
}

const maxVars = 16

func sessionText(raw string) string {
	raw = strings.TrimSpace(raw)

	if len(raw) > 256 || !printableName(raw) {
		return ""
	}

	return raw
}

func SplitIdentity(raw string) (source, user string) {
	if before, after, ok := strings.Cut(raw, ":"); ok {
		return before, after
	}

	return "", raw
}

func ParseVars(raw []string) []VarFilter {
	out := make([]VarFilter, 0, len(raw))

	for _, item := range raw {
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}

		name = strings.TrimSpace(name)
		if name == "" || !validVarName(name) {
			continue
		}

		out = append(out, VarFilter{Name: name, Value: value})

		if len(out) >= maxVars {
			break
		}
	}

	return out
}

func ParsePairs(raw []string) []VarFilter {
	out := make([]VarFilter, 0, len(raw))

	for _, item := range raw {
		name, value, _ := strings.Cut(item, "=")

		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		out = append(out, VarFilter{Name: name, Value: value})

		if len(out) >= maxVars {
			break
		}
	}

	return out
}

func normalizeVars(in []VarFilter) []VarFilter {
	if len(in) == 0 {
		return nil
	}

	out := make([]VarFilter, 0, len(in))

	for _, v := range in {
		if v.Name == "" || !validVarName(v.Name) {
			continue
		}

		out = append(out, v)

		if len(out) >= maxVars {
			break
		}
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

const maxBodyQuery = 256

func normalizeNames(in []VarFilter, header bool) []VarFilter {
	if len(in) == 0 {
		return nil
	}

	out := make([]VarFilter, 0, len(in))

	for _, v := range in {
		if v.Name == "" || len(v.Name) > 128 || !printableName(v.Name) {
			continue
		}

		if header {
			v.Name = strings.ToLower(v.Name)
		}

		out = append(out, v)

		if len(out) >= maxVars {
			break
		}
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

func printableName(name string) bool {
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}

	return true
}

func validVarName(name string) bool {
	if len(name) > 64 {
		return false
	}

	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_', r == '.', r == '-':
		default:
			return false
		}
	}

	return true
}

const maxCIDRs = 32

const maxList = 64

func ParseList(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))

	for _, item := range raw {
		for _, part := range strings.FieldsFunc(item, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
		}) {
			if _, dup := seen[part]; dup {
				continue
			}
			seen[part] = struct{}{}
			out = append(out, part)
			if len(out) >= maxList {
				return out
			}
		}
	}

	return out
}

func ParseCIDRs(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))

	for _, item := range raw {
		for _, part := range strings.FieldsFunc(item, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
		}) {
			p, ok := parseCIDR(part)
			if !ok {
				continue
			}
			s := p.String()
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
			if len(out) >= maxCIDRs {
				return out
			}
		}
	}

	return out
}

func ipRange(p netip.Prefix) (lo, hi netip.Addr) {
	p = p.Masked()

	addr, bits := p.Addr(), p.Bits()
	if addr.Is4() {
		addr, bits = netip.AddrFrom16(addr.As16()), bits+96
	}

	first := addr.As16()
	last := first

	for i := bits; i < 128; i++ {
		last[i/8] |= 1 << (7 - i%8)
	}

	return netip.AddrFrom16(first), netip.AddrFrom16(last)
}

func ipClause(cidrs []string) (string, []any) {
	var (
		singles []string
		ranges  []string
		args    []any
	)

	for i, raw := range cidrs {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}

		lo, hi := ipRange(p)

		if lo == hi {
			name := fmt.Sprintf("ip%d", i)
			singles = append(singles, "toIPv6(@"+name+")")
			args = append(args, clickhouse.Named(name, lo.String()))

			continue
		}

		loName, hiName := fmt.Sprintf("iplo%d", i), fmt.Sprintf("iphi%d", i)
		ranges = append(ranges,
			"(client_ip >= toIPv6(@"+loName+") AND client_ip <= toIPv6(@"+hiName+"))")
		args = append(args,
			clickhouse.Named(loName, lo.String()),
			clickhouse.Named(hiName, hi.String()))
	}

	parts := ranges
	if len(singles) > 0 {
		parts = append([]string{"client_ip IN (" + strings.Join(singles, ", ") + ")"}, parts...)
	}

	if len(parts) == 0 {
		return "", nil
	}

	return "(" + strings.Join(parts, " OR ") + ")", args
}

func parseCIDR(raw string) (netip.Prefix, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, false
	}

	if p, err := netip.ParsePrefix(raw); err == nil {
		return p.Masked(), true
	}

	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, false
	}

	ip = ip.Unmap()
	bits := 32
	if ip.Is6() {
		bits = 128
	}

	p, err := ip.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}

	return p, true
}

func List(ctx context.Context, conn driver.Conn, f Filter) ([]Event, error) {
	f = Normalize(f)
	sql, args := build(f)

	rows, err := conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	out := make([]Event, 0, f.Limit)

	for rows.Next() {
		ev, err := scan(rows, f.WithPreview)
		if err != nil {
			return nil, err
		}

		out = append(out, ev)
	}

	return dedup(out), rows.Err()
}

type rowKey struct {
	node, ray, phase, dir string
	seq                   uint64
}

func keyOf(ev Event) rowKey {
	k := rowKey{node: ev.Node, ray: ev.Ray, phase: ev.Phase}

	if ev.Frame != nil {
		k.dir, k.seq = ev.Frame.Direction, ev.Frame.Seq
	}

	return k
}

func dedup(in []Event) []Event {
	if len(in) < 2 {
		return in
	}

	seen := make(map[rowKey]struct{}, len(in))
	out := in[:0]

	for _, ev := range in {
		k := keyOf(ev)
		if _, dup := seen[k]; dup {
			continue
		}

		seen[k] = struct{}{}
		out = append(out, ev)
	}

	return out
}

func One(ctx context.Context, conn driver.Conn, node, ray, phase, frame string) (Event, bool, error) {
	if ray == "" {
		return Event{}, false, nil
	}

	dir, seq := ParseFrameAddr(frame)

	rows, err := List(ctx, conn, Filter{
		Node:           node,
		Ray:            ray,
		Phase:          phase,
		FrameDirection: dir,
		FrameSeq:       seq,
		WithPreview:    true,
		Limit:          2 * len(phases),
	})
	if err != nil {
		return Event{}, false, err
	}

	if len(rows) == 0 {
		return Event{}, false, nil
	}

	if phase == "" {
		for _, row := range rows {
			if row.Phase == "request" {
				return row, true, nil
			}
		}
	}

	return rows[0], true, nil
}

var phases = []string{"request", "response", "frame", "session"}

func ParseFrameAddr(raw string) (string, uint64) {
	dir, rest, ok := strings.Cut(raw, ":")
	if !ok || (dir != "c2s" && dir != "s2c") {
		return "", 0
	}

	seq, err := strconv.ParseUint(rest, 10, 64)
	if err != nil {
		return "", 0
	}

	return dir, seq
}

func Count(ctx context.Context, conn driver.Conn, f Filter) (uint64, error) {
	f = Normalize(f)
	sql, args := buildCount(f)

	var n uint64
	if err := conn.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("count: %w", err)
	}

	return n, nil
}

func where(f Filter) (clauses []string, args []any) {
	add := func(clause, name string, v any) {
		clauses = append(clauses, clause)
		args = append(args, clickhouse.Named(name, v))
	}

	if f.FrameDirection != "" {
		add("frame_direction = @frame_direction", "frame_direction", f.FrameDirection)
		add("frame_seq = @frame_seq", "frame_seq", f.FrameSeq)
	}

	if f.Phase != "" {
		add("phase = @phase", "phase", f.Phase)
	}

	if f.Ray != "" {
		add("ray = @ray", "ray", f.Ray)

		if f.Node != "" {
			add("node = @node", "node", f.Node)
		}

		return clauses, args
	}

	add("ts >= @from", "from", f.From)
	add("ts <= @to", "to", f.To)

	if f.Verdict != "" {
		add("verdict = @verdict", "verdict", f.Verdict)
	}

	if f.Code != "" {
		add("code = @code", "code", f.Code)
	}

	if f.Method != "" {
		add("method = @method", "method", f.Method)
	}

	if f.Host != "" {
		add("host = @host", "host", f.Host)
	}

	if f.URI != "" {
		add("lower(uri) LIKE @uri", "uri",
			"%"+escapeLike(strings.ToLower(f.URI))+"%")
	}

	if len(f.LocationIDs) > 0 {
		add("has(@routes, location_id)", "routes", f.LocationIDs)
	}

	if len(f.ServerNames) > 0 {
		add("has(@servers, server_name)", "servers", f.ServerNames)
	}

	if f.HasStatus {
		add("status = @status", "status", f.Status)
	}

	if f.Node != "" {
		add("node = @node", "node", f.Node)
	}

	if f.Inspector != "" {
		add("has(inspectors, @inspector)", "inspector", f.Inspector)
	}

	if f.Country != "" {
		add(CountryExpr+" = @country", "country", f.Country)
	}

	if f.ASN != 0 {
		add(ASNExpr+" = @asn", "asn", f.ASN)
	}

	if f.User != "" {
		if source, user := SplitIdentity(f.User); source != "" {
			clauses = append(clauses,
				"arrayExists((s, u) -> s = @user_source AND u = @user,"+
					" sessions_source, sessions_user)")
			args = append(args,
				clickhouse.Named("user_source", source),
				clickhouse.Named("user", user))
		} else {
			add("has(sessions_user, @user)", "user", user)
		}
	}

	if f.SessionID != "" {
		add("has(sessions_id, @session)", "session", f.SessionID)
	}

	if f.Marker != "" {
		add("has(markers, @marker)", "marker", f.Marker)
	}

	for i, v := range f.Vars {
		clauses = append(clauses, fmt.Sprintf("vars[@vk%d] = @vv%d", i, i))
		args = append(args,
			clickhouse.Named(fmt.Sprintf("vk%d", i), v.Name),
			clickhouse.Named(fmt.Sprintf("vv%d", i), v.Value),
		)
	}

	for i, h := range f.Headers {
		if h.Value == "" {
			clauses = append(clauses,
				fmt.Sprintf("has(mapKeys(headers_preview), @hk%d)", i))
			args = append(args, clickhouse.Named(fmt.Sprintf("hk%d", i), h.Name))
			continue
		}

		clauses = append(clauses,
			fmt.Sprintf("headers_preview[@hk%d] = @hv%d", i, i))
		args = append(args,
			clickhouse.Named(fmt.Sprintf("hk%d", i), h.Name),
			clickhouse.Named(fmt.Sprintf("hv%d", i), h.Value),
		)
	}

	for i, p := range f.Params {
		if p.Value == "" {
			clauses = append(clauses,
				fmt.Sprintf("has(mapKeys(args_preview), @pk%d)", i))
			args = append(args, clickhouse.Named(fmt.Sprintf("pk%d", i), p.Name))
			continue
		}

		clauses = append(clauses,
			fmt.Sprintf("args_preview[@pk%d] = @pv%d", i, i))
		args = append(args,
			clickhouse.Named(fmt.Sprintf("pk%d", i), p.Name),
			clickhouse.Named(fmt.Sprintf("pv%d", i), p.Value),
		)
	}

	if f.Body != "" {
		add("lower(body_preview) LIKE @body", "body",
			"%"+escapeLike(strings.ToLower(f.Body))+"%")
	}

	if len(f.CIDRs) > 0 {
		if clause, ipArgs := ipClause(f.CIDRs); clause != "" {
			clauses = append(clauses, clause)
			args = append(args, ipArgs...)
		}
	}

	return clauses, args
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func sessions(row *model.Row) []SessionEntry {
	n := len(row.SessionsSource)
	if n == 0 {
		return nil
	}

	str := func(items []string, i int) string {
		if i < len(items) {
			return items[i]
		}

		return ""
	}

	bit := func(items []uint8, i int) bool {
		return i < len(items) && items[i] != 0
	}

	num := func(items []uint32, i int) uint32 {
		if i < len(items) {
			return items[i]
		}

		return 0
	}

	out := make([]SessionEntry, 0, n)

	for i := 0; i < n; i++ {
		out = append(out, SessionEntry{
			By:       str(row.SessionsBy, i),
			Source:   row.SessionsSource[i],
			Kind:     str(row.SessionsKind, i),
			User:     str(row.SessionsUser, i),
			ID:       str(row.SessionsID, i),
			Verified: bit(row.SessionsVerified, i),
			Issued:   num(row.SessionsIssued, i),
			Expires:  num(row.SessionsExpires, i),
			Groups:   str(row.SessionsGroups, i),
			Passive:  bit(row.SessionsPassive, i),
		})
	}

	return out
}

func build(f Filter) (string, []any) {
	clauses, args := where(f)

	list := cols
	if f.WithPreview {
		list = colsPreview
	}

	sql := "SELECT " + list + fromRaw + whereClause(clauses)

	sql += listOrder(f.Asc) + " LIMIT @limit OFFSET @offset"
	args = append(args, clickhouse.Named("limit", f.Limit), clickhouse.Named("offset", f.Offset))

	return sql, args
}

func buildCount(f Filter) (string, []any) {
	clauses, args := where(f)

	return "SELECT count()" + fromFinal + whereClause(clauses), args
}

func scan(rows driver.Rows, withPreview bool) (Event, error) {
	var (
		row      model.Row
		clientIP netip.Addr
		serverIP netip.Addr
	)

	dst := []any{
		&row.TS,
		&row.Node,
		&row.Ray,
		&row.Phase,

		&clientIP,
		&row.ClientPort,
		&serverIP,
		&row.ServerPort,
		&row.TLSVersion,
		&row.TLSSNI,

		&row.Method,
		&row.Scheme,
		&row.Host,
		&row.URI,
		&row.HTTPVersion,

		&row.ArgsSize,
		&row.HeadersSize,
		&row.HeadersCount,
		&row.BodySize,
		&row.ContentType,
		&row.Status,
		&row.UpstreamStatus,

		&row.ServerName,
		&row.Location,
		&row.LocationID,

		&row.Verdict,
		&row.Code,
		&row.VerdictBy,

		&row.Score,
		&row.DenyAt,
		&row.Shadow,
		&row.WAFLatencyUs,

		&row.Inspectors,
		&row.InspectorsVerdict,
		&row.InspectorsState,
		&row.InspectorsScore,
		&row.InspectorsLatencyMs,
		&row.InspectorsRole,
		&row.InspectorsProfile,

		&row.Vars,

		&row.StoreHeaders,
		&row.StoreArgs,
		&row.StoreBody,

		&row.FrameSeq,
		&row.FrameDirection,
		&row.FrameOpcode,
		&row.FrameSize,
		&row.FrameFin,
		&row.FrameRewritten,
		&row.SessionFramesC2S,
		&row.SessionFramesS2C,
		&row.SessionBytesC2S,
		&row.SessionBytesS2C,
		&row.SessionDenied,
		&row.SessionRewritten,
		&row.SessionCloseCode,
		&row.SessionCloseReason,
		&row.SessionDurationMs,

		&row.SessionsBy,
		&row.SessionsSource,
		&row.SessionsKind,
		&row.SessionsUser,
		&row.SessionsID,
		&row.SessionsVerified,
		&row.SessionsIssued,
		&row.SessionsExpires,
		&row.SessionsGroups,
		&row.SessionsPassive,

		&row.Markers,
	}

	if withPreview {
		dst = append(dst,
			&row.HeadersPreview,
			&row.ArgsPreview,
			&row.BodyPreview,
			&row.HeadersPreviewTruncated,
			&row.ArgsPreviewTruncated,
			&row.HeadersPreviewDropped,
			&row.ArgsPreviewDropped,
			&row.Actions,
			&row.Rewrite,
			&row.FramePreview,
			&row.FramePreviewTruncated,
		)
	}

	if err := rows.Scan(dst...); err != nil {
		return Event{}, err
	}

	if row.Inspectors == nil {
		row.Inspectors = []string{}
	}

	if row.InspectorsVerdict == nil {
		row.InspectorsVerdict = map[string]string{}
	}

	if row.InspectorsScore == nil {
		row.InspectorsScore = map[string]int32{}
	}

	ev := Event{
		TS:    row.TS.UTC(),
		Node:  row.Node,
		Ray:   row.Ray,
		Phase: row.Phase,

		ClientPort: row.ClientPort,
		ServerPort: row.ServerPort,
		TLSVersion: row.TLSVersion,
		TLSSNI:     row.TLSSNI,

		Method:         row.Method,
		Scheme:         row.Scheme,
		Host:           row.Host,
		URI:            row.URI,
		HTTPVersion:    row.HTTPVersion,
		ArgsSize:       row.ArgsSize,
		HeadersSize:    row.HeadersSize,
		HeadersCount:   row.HeadersCount,
		BodySize:       row.BodySize,
		ContentType:    row.ContentType,
		Status:         row.Status,
		UpstreamStatus: row.UpstreamStatus,

		ServerName: row.ServerName,
		Location:   row.Location,
		LocationID: row.LocationID,

		Verdict: row.Verdict,
		Code:    row.Code,
		By:      row.VerdictBy,

		Score:  row.Score,
		DenyAt: row.DenyAt,
		Shadow: row.Shadow,

		WAFLatencyUs: row.WAFLatencyUs,

		Inspectors:          row.Inspectors,
		InspectorsVerdict:   row.InspectorsVerdict,
		InspectorsState:     row.InspectorsState,
		InspectorsScore:     row.InspectorsScore,
		InspectorsLatencyMs: row.InspectorsLatencyMs,
		InspectorsRole:      row.InspectorsRole,
		InspectorsProfile:   row.InspectorsProfile,
		InspectorsView: view(row.Inspectors, row.InspectorsVerdict,
			row.InspectorsState, row.InspectorsScore),

		Vars: row.Vars,
	}

	if clientIP.IsValid() && !clientIP.IsUnspecified() {
		ev.ClientIP = clientIP.Unmap().String()
	}

	if serverIP.IsValid() && !serverIP.IsUnspecified() {
		ev.ServerIP = serverIP.Unmap().String()
	}

	ev.Store = store(row.StoreHeaders, row.StoreArgs, row.StoreBody)
	ev.Sessions = sessions(&row)
	ev.Markers = row.Markers

	ev.Actions = row.Actions
	ev.Rewrite = row.Rewrite

	switch row.Phase {
	case "frame":
		ev.Frame = &FrameInfo{
			Seq:              row.FrameSeq,
			Direction:        row.FrameDirection,
			Opcode:           row.FrameOpcode,
			Fin:              row.FrameFin != 0,
			Size:             row.FrameSize,
			Rewritten:        row.FrameRewritten != 0,
			PayloadPreview:   row.FramePreview,
			PayloadTruncated: row.FramePreviewTruncated != 0,
		}

	case "session":
		ev.Session = &SessionInfo{
			FramesC2S:   row.SessionFramesC2S,
			FramesS2C:   row.SessionFramesS2C,
			BytesC2S:    row.SessionBytesC2S,
			BytesS2C:    row.SessionBytesS2C,
			Denied:      row.SessionDenied,
			Rewritten:   row.SessionRewritten,
			CloseCode:   row.SessionCloseCode,
			CloseReason: row.SessionCloseReason,
			DurationMs:  row.SessionDurationMs,
		}
	}
	ev.HeadersPreview = row.HeadersPreview
	ev.ArgsPreview = row.ArgsPreview
	ev.BodyPreview = row.BodyPreview

	ev.HeadersPreviewTruncated = row.HeadersPreviewTruncated
	ev.ArgsPreviewTruncated = row.ArgsPreviewTruncated
	ev.HeadersPreviewDropped = row.HeadersPreviewDropped
	ev.ArgsPreviewDropped = row.ArgsPreviewDropped

	return ev, nil
}

func store(headers, args, body string) *Store {
	if headers == "" && args == "" && body == "" {
		return nil
	}

	return &Store{
		Headers: json.RawMessage(headers),
		Args:    json.RawMessage(args),
		Body:    json.RawMessage(body),
	}
}

func view(names []string, verdicts, states map[string]string,
	scores map[string]int32) string {

	parts := make([]string, 0, len(names))

	for _, name := range names {
		if s := states[name]; s != "" {
			parts = append(parts, name+": "+s)
			continue
		}

		v := verdicts[name]
		if v == "" {
			parts = append(parts, name)
			continue
		}

		if s, ok := scores[name]; ok && s > 0 {
			parts = append(parts, fmt.Sprintf("%s: %s [%d]", name, v, s))
			continue
		}

		parts = append(parts, name+": "+v)
	}

	return strings.Join(parts, ", ")
}
