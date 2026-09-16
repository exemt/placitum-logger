package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/exemt/placitum-logger/internal/query"
	"github.com/exemt/placitum-logger/internal/store"
)

type pair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type content struct {
	Node  string `json:"node"`
	Ray   string `json:"ray"`
	Phase string `json:"phase"`
	Kind  string `json:"kind"`

	Size         int64  `json:"size"`
	DeclaredSize int64  `json:"declared_size,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Complete     *bool  `json:"complete,omitempty"`
	Truncated    *bool  `json:"truncated,omitempty"`
	Encoding     string `json:"encoding,omitempty"`
	ContentType  string `json:"content_type,omitempty"`

	Store  string `json:"store,omitempty"`
	Driver string `json:"driver,omitempty"`
	Key    string `json:"key,omitempty"`

	ExpiresAt int64 `json:"expires_at,omitempty"`

	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`

	Offset   int64 `json:"offset"`
	Returned int   `json:"returned"`
	Clipped  bool  `json:"clipped,omitempty"`

	Continuation bool `json:"continuation,omitempty"`

	Headers []pair `json:"headers,omitempty"`
	Params  []pair `json:"params,omitempty"`
	Count   int    `json:"count,omitempty"`

	Raw string `json:"raw,omitempty"`

	Text   string `json:"text,omitempty"`
	Base64 string `json:"base64,omitempty"`
	Binary bool   `json:"binary,omitempty"`
}

func (a *api) content(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ev, ok, err := a.record(w, r)
		if err != nil || !ok {
			return
		}

		out := content{
			Node:  ev.Node,
			Ray:   ev.Ray,
			Phase: ev.Phase,
			Kind:  kind,
		}

		if kind == "body" {
			out.ContentType = ev.ContentType
		}

		loc, has := locatorOf(ev, kind)

		out.Size = loc.Size
		out.DeclaredSize = loc.DeclaredSize
		out.SHA256 = loc.SHA256
		out.Complete = loc.Complete
		out.Truncated = loc.Truncated
		out.Encoding = loc.Encoding
		out.Store = loc.Store
		out.Driver = loc.Driver
		out.Key = loc.Key
		out.ExpiresAt = loc.ExpiresAt

		offset, limit := windowOf(r, a.store.MaxBytes())
		out.Offset = offset

		got, err := a.store.FetchWindow(r.Context(), kind, loc, has, offset, limit)
		if err != nil {
			a.log.Error("store fetch",
				"kind", kind, "node", ev.Node, "ray", ev.Ray,
				"driver", loc.Driver, "key", loc.Key, "error", err.Error())
		}

		out.Reason = got.Reason
		out.Available = got.Available()
		out.Returned = len(got.Data)
		out.Clipped = got.Clipped

		if out.Available {
			decode(&out, kind, got.Data, offset)
		}

		writeJSON(w, out)
	}
}

func locatorOf(ev query.Event, kind string) (store.Locator, bool) {
	if ev.Store == nil {
		return store.Locator{}, false
	}

	switch kind {
	case "headers":
		return store.ParseLocator(string(ev.Store.Headers))
	case "args":
		return store.ParseLocator(string(ev.Store.Args))
	case "body":
		return store.ParseLocator(string(ev.Store.Body))
	}

	return store.Locator{}, false
}

const defaultViewChunk = 32 << 10

func windowOf(r *http.Request, max int64) (offset, limit int64) {
	q := r.URL.Query()
	offset = int64(atoi(q.Get("offset")))
	if offset < 0 {
		offset = 0
	}

	if q.Get("offset") == "" && q.Get("limit") == "" {
		return 0, max
	}

	limit = int64(atoi(q.Get("limit")))
	if limit <= 0 {
		limit = defaultViewChunk
	}
	if max > 0 && limit > max {
		limit = max
	}

	return offset, limit
}

func decode(out *content, kind string, data []byte, offset int64) {
	switch kind {

	case "headers":
		pairs, cont := parseHeadersFragment(data)
		out.Headers = pairs
		out.Count = len(pairs)
		if cont != "" {
			out.Continuation = true
			out.Text = cont
		}

	case "args":
		out.Raw = string(data)
		pairs, cont := parseArgsFragment(out.Raw, offset)
		out.Params = pairs
		out.Count = len(pairs)
		if cont != "" {
			out.Continuation = true
			out.Text = cont
		}

	case "body":
		if text, n, ok := utf8Window(data); ok {
			out.Text = text
			out.Returned = n
			return
		}

		out.Binary = true
		out.Base64 = base64.StdEncoding.EncodeToString(data)
	}
}

func parseHeaders(data []byte) []pair {
	var rows [][]string

	if err := json.Unmarshal(data, &rows); err != nil {
		return nil
	}

	out := make([]pair, 0, len(rows))

	for _, row := range rows {
		item := pair{}

		if len(row) > 0 {
			item.Name = row[0]
		}

		if len(row) > 1 {
			item.Value = row[1]
		}

		out = append(out, item)
	}

	return out
}

func parseArgs(raw string) []pair {
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, "&")
	out := make([]pair, 0, len(parts))

	for _, part := range parts {
		if part == "" {
			continue
		}

		name, value, _ := strings.Cut(part, "=")

		out = append(out, pair{Name: unescape(name), Value: unescape(value)})
	}

	return out
}

func unescape(s string) string {
	out, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}

	return out
}
