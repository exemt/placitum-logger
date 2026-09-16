package query

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

var groupDims = map[string]string{
	"ip":      "client_ip",
	"host":    "host",
	"uri":     "uri",
	"route":   "location_id",
	"server":  "server_name",
	"method":  "method",
	"status":  "status",
	"verdict": "verdict",
	"code":    "code",
	"by":      "verdict_by",
	"node":    "node",
	"phase":   "phase",
	"country": "country",
	"asn":     "asn",
	"marker":  "marker",
	"user":    "session_user",
}

var groupExprs = map[string]string{
	"marker":  "arrayJoin(markers)",
	"country": CountryExpr,
	"asn":     ASNExpr,
	"user": "arrayJoin(arrayDistinct(arrayFilter(x -> x != '', " +
		"arrayMap((s, u) -> if(u = '', '', concat(s, ':', u)), " +
		"sessions_source, sessions_user))))",
}

func groupExpr(dim string) string {
	if expr, ok := groupExprs[dim]; ok {
		return expr
	}

	return groupDims[dim]
}

const maxGroupBy = 4

func ParseGroupBy(raw string) []string {
	out := make([]string, 0, maxGroupBy)
	seen := make(map[string]struct{}, maxGroupBy)

	for _, part := range strings.Split(raw, ",") {
		dim := strings.TrimSpace(part)
		if _, ok := groupDims[dim]; !ok {
			continue
		}
		if _, dup := seen[dim]; dup {
			continue
		}
		seen[dim] = struct{}{}
		out = append(out, dim)
		if len(out) >= maxGroupBy {
			break
		}
	}

	return out
}

type Group struct {
	Keys       map[string]string `json:"keys"`
	Hits       uint64            `json:"hits"`
	Allowed    uint64            `json:"allowed"`
	Redirected uint64            `json:"redirected"`
	Denied     uint64            `json:"denied"`
	Last       time.Time         `json:"last"`
}

func Groups(ctx context.Context, conn driver.Conn, f Filter, by []string, sort GroupSort) ([]Group, uint64, error) {
	f = Normalize(f)
	sql, args := buildGroups(f, by, sort)

	rows, err := conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("groups: %w", err)
	}
	defer rows.Close()

	var (
		out   = make([]Group, 0, f.Limit)
		total uint64
	)

	for rows.Next() {
		g, n, err := scanGroup(rows, by)
		if err != nil {
			return nil, 0, err
		}

		out = append(out, g)
		total = n
	}

	return out, total, rows.Err()
}

func CountGroups(ctx context.Context, conn driver.Conn, f Filter, by []string) (uint64, error) {
	f = Normalize(f)
	sql, args := buildGroupCount(f, by)

	var n uint64
	if err := conn.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("group count: %w", err)
	}

	return n, nil
}

func groupCols(by []string) string {
	cols := make([]string, len(by))
	for i, dim := range by {
		cols[i] = groupDims[dim]
	}

	return strings.Join(cols, ", ")
}

func groupSelect(by []string) string {
	cols := make([]string, len(by))

	for i, dim := range by {
		if expr, ok := groupExprs[dim]; ok {
			cols[i] = expr + " AS " + groupDims[dim]
			continue
		}

		cols[i] = groupDims[dim]
	}

	return strings.Join(cols, ", ")
}

func groupExprCols(by []string) string {
	cols := make([]string, len(by))
	for i, dim := range by {
		cols[i] = groupExpr(dim)
	}

	return strings.Join(cols, ", ")
}

var groupMetrics = map[string]string{
	"hits":   "hits",
	"denied": "denied",
	"last":   "last",
}

type GroupSort struct {
	Key string
	Asc bool
}

func ParseGroupSort(by []string, key, dir string) GroupSort {
	metric := false
	if _, ok := groupMetrics[key]; ok {
		metric = true
	} else {
		found := false
		for _, dim := range by {
			if dim == key {
				found = true
				break
			}
		}
		if !found {
			key = "hits"
			metric = true
		}
	}

	asc := !metric
	switch dir {
	case "asc":
		asc = true
	case "desc":
		asc = false
	}

	return GroupSort{Key: key, Asc: asc}
}

func (s GroupSort) order() string {
	col := groupMetrics[s.Key]
	if col == "" {
		col = groupDims[s.Key]
	}

	dir := " DESC"
	if s.Asc {
		dir = " ASC"
	}

	tail := ", hits DESC"
	if s.Key == "hits" {
		tail = ", last DESC"
	}

	return " ORDER BY " + col + dir + tail
}

func buildGroups(f Filter, by []string, sort GroupSort) (string, []any) {
	clauses, args := where(f)
	cols := groupCols(by)

	sql := "SELECT " + groupSelect(by) +
		", count() AS hits" +
		", countIf(verdict = 'allow') AS allowed" +
		", countIf(verdict = 'redirect') AS redirected" +
		", countIf(verdict = 'deny') AS denied" +
		", max(ts) AS last" +
		", count() OVER () AS total" +
		fromFinal + whereClause(clauses) +
		" GROUP BY " + cols +
		sort.order() + " LIMIT @limit OFFSET @offset"
	args = append(args, clickhouse.Named("limit", f.Limit), clickhouse.Named("offset", f.Offset))

	return sql, args
}

func buildGroupCount(f Filter, by []string) (string, []any) {
	clauses, args := where(f)

	return "SELECT uniqExact(" + groupExprCols(by) + ")" + fromFinal + whereClause(clauses), args
}

func scanGroup(rows driver.Rows, by []string) (Group, uint64, error) {
	holders := make([]any, len(by))
	for i, dim := range by {
		switch dim {
		case "ip":
			holders[i] = new(netip.Addr)
		case "status":
			holders[i] = new(uint16)
		case "asn":
			holders[i] = new(uint32)
		default:
			holders[i] = new(string)
		}
	}

	var (
		g     Group
		total uint64
	)
	dst := append(
		append([]any{}, holders...),
		&g.Hits, &g.Allowed, &g.Redirected, &g.Denied, &g.Last, &total,
	)
	if err := rows.Scan(dst...); err != nil {
		return Group{}, 0, err
	}

	g.Last = g.Last.UTC()
	g.Keys = make(map[string]string, len(by))

	for i, dim := range by {
		switch h := holders[i].(type) {
		case *netip.Addr:
			if h.IsValid() && !h.IsUnspecified() {
				g.Keys[dim] = h.Unmap().String()
			} else {
				g.Keys[dim] = ""
			}
		case *uint16:
			g.Keys[dim] = strconv.FormatUint(uint64(*h), 10)
		case *uint32:
			if *h == 0 {
				g.Keys[dim] = ""
			} else {
				g.Keys[dim] = strconv.FormatUint(uint64(*h), 10)
			}
		case *string:
			g.Keys[dim] = *h
		}
	}

	return g, total, nil
}
