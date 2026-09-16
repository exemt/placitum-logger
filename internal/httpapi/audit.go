package httpapi

import (
	"context"
	"math"
	"net/http"

	"github.com/exemt/placitum-logger/internal/query"
)

func both(ctx context.Context, a, b func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- b(ctx) }()

	errA := a(ctx)
	if errA != nil {
		cancel()
	}

	errB := <-done

	if errA != nil {
		return errA
	}

	return errB
}

func parseFilter(r *http.Request) query.Filter {
	q := r.URL.Query()
	status, hasStatus := parseStatus(q.Get("status"))

	return query.Normalize(query.Filter{
		Verdict:     q.Get("verdict"),
		Code:        q.Get("code"),
		Method:      q.Get("method"),
		Host:        q.Get("host"),
		URI:         q.Get("uri"),
		LocationIDs: q["route"],
		ServerNames: q["server"],
		Status:      status,
		HasStatus:   hasStatus,
		Node:        q.Get("node"),
		Ray:         q.Get("ray"),
		Phase:       q.Get("phase"),
		Inspector:   q.Get("inspector"),
		CIDRs:       q["ip"],
		Country:     q.Get("country"),
		ASN:         parseASN(q.Get("asn")),
		Vars:        query.ParseVars(q["var"]),
		User:        q.Get("user"),
		SessionID:   q.Get("session"),
		Marker:      q.Get("marker"),
		Headers:     query.ParsePairs(q["header"]),
		Params:      query.ParsePairs(q["param"]),
		Body:        q.Get("body"),
		Limit:       atoi(q.Get("limit")),
		Offset:      atoi(q.Get("offset")),
		From:        parseTime(q.Get("from")),
		To:          parseTime(q.Get("to")),
		Asc:         q.Get("order") == "asc",
	})
}

func parseASN(raw string) uint32 {
	n := atoi(raw)
	if n <= 0 || n > math.MaxUint32 {
		return 0
	}

	return uint32(n)
}

func (a *api) list(w http.ResponseWriter, r *http.Request) {
	f := parseFilter(r)

	var (
		rows  []query.Event
		total uint64
	)

	err := both(r.Context(),
		func(ctx context.Context) (err error) {
			rows, err = query.List(ctx, a.conn, f)
			return
		},
		func(ctx context.Context) (err error) {
			total, err = query.Count(ctx, a.conn, f)
			return
		})
	if err != nil {
		a.broken(w, "list", err)
		return
	}

	writeJSON(w, map[string]any{
		"items":  rows,
		"count":  len(rows),
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
	})
}

func (a *api) groups(w http.ResponseWriter, r *http.Request) {
	by := query.ParseGroupBy(r.URL.Query().Get("by"))
	if len(by) == 0 {
		fail(w, http.StatusBadRequest, "bad_group_by")
		return
	}

	sort := query.ParseGroupSort(by, r.URL.Query().Get("sort"), r.URL.Query().Get("dir"))
	f := parseFilter(r)

	rows, total, err := query.Groups(r.Context(), a.conn, f, by, sort)
	if err != nil {
		a.broken(w, "groups", err)
		return
	}

	if len(rows) == 0 && f.Offset > 0 {
		if total, err = query.CountGroups(r.Context(), a.conn, f, by); err != nil {
			a.broken(w, "group count", err)
			return
		}
	}

	writeJSON(w, map[string]any{
		"items":  rows,
		"count":  len(rows),
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
	})
}

func (a *api) one(w http.ResponseWriter, r *http.Request) {
	ev, ok, err := a.record(w, r)
	if err != nil || !ok {
		return
	}

	writeJSON(w, ev)
}

func (a *api) inspectors(w http.ResponseWriter, r *http.Request) {
	ev, ok, err := a.record(w, r)
	if err != nil || !ok {
		return
	}

	findings, err := query.FindingsFor(r.Context(), a.conn, ev)
	if err != nil {
		a.broken(w, "card", err)
		return
	}

	writeJSON(w, query.CardOf(ev, findings))
}

func (a *api) cardFindings(w http.ResponseWriter, r *http.Request) {
	rows, err := query.FindingsByRay(r.Context(), a.conn,
		r.PathValue("node"), r.PathValue("ray"))
	if err != nil {
		a.broken(w, "findings by ray", err)
		return
	}

	writeJSON(w, map[string]any{"items": rows, "count": len(rows)})
}

func (a *api) findings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	f := query.NormalizeFinding(query.FindingFilter{
		Node:      q.Get("node"),
		Ray:       q.Get("ray"),
		Phase:     q.Get("phase"),
		Inspector: q.Get("inspector"),
		Profile:   q.Get("profile"),
		Verdict:   q.Get("verdict"),
		Rule:      q.Get("rule"),
		Code:      q.Get("code"),
		Severity:  q.Get("severity"),
		Tag:       q.Get("tag"),
		Limit:     atoi(q.Get("limit")),
		Offset:    atoi(q.Get("offset")),
		From:      parseTime(q.Get("from")),
		To:        parseTime(q.Get("to")),
	})

	rows, err := query.ListFindings(r.Context(), a.conn, f)
	if err != nil {
		a.broken(w, "findings", err)
		return
	}

	total, err := query.CountFindings(r.Context(), a.conn, f)
	if err != nil {
		a.broken(w, "findings count", err)
		return
	}

	writeJSON(w, map[string]any{
		"items":  rows,
		"count":  len(rows),
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
	})
}

func (a *api) record(w http.ResponseWriter, r *http.Request) (query.Event, bool, error) {
	ev, ok, err := query.One(r.Context(), a.conn,
		r.PathValue("node"), r.PathValue("ray"), r.URL.Query().Get("phase"),
		r.URL.Query().Get("frame"))

	if err != nil {
		a.broken(w, "get", err)
		return query.Event{}, false, err
	}

	if !ok {
		fail(w, http.StatusNotFound, "not_found")
		return query.Event{}, false, nil
	}

	return ev, true, nil
}
