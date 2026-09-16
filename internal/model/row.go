package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

const SelfKey = "module"

type Row struct {
	TS    time.Time
	Node  string
	Ray   string
	Phase string
	Rev   uint32

	ClientIP   netip.Addr
	ClientPort uint16
	ServerIP   netip.Addr
	ServerPort uint16
	TLSVersion string
	TLSSNI     string

	Method         string
	Scheme         string
	Host           string
	URI            string
	HTTPVersion    string
	ArgsSize       uint32
	HeadersSize    uint32
	HeadersCount   uint16
	BodySize       uint64
	ContentType    string
	Status         uint16
	UpstreamStatus uint16

	ServerName string
	Location   string
	LocationID string

	Verdict   string
	Code      string
	VerdictBy string

	Score  int32
	DenyAt int32
	Shadow int32

	WAFLatencyUs uint32

	Inspectors          []string
	InspectorsVerdict   map[string]string
	InspectorsState     map[string]string
	InspectorsScore     map[string]int32
	InspectorsLatencyMs map[string]float32
	InspectorsRole      map[string]string
	InspectorsProfile   map[string]string

	Vars map[string]string

	StoreHeaders string
	StoreArgs    string
	StoreBody    string

	HeadersPreview map[string]string
	ArgsPreview    map[string]string
	BodyPreview    string

	HeadersPreviewTruncated []string
	ArgsPreviewTruncated    []string
	HeadersPreviewDropped   uint16
	ArgsPreviewDropped      uint16

	Actions string

	Rewrite string

	SessionsBy       []string
	SessionsSource   []string
	SessionsKind     []string
	SessionsUser     []string
	SessionsID       []string
	SessionsVerified []uint8
	SessionsIssued   []uint32
	SessionsExpires  []uint32
	SessionsGroups   []string
	SessionsPassive  []uint8

	Markers []string

	FrameSeq              uint64
	FrameDirection        string
	FrameOpcode           string
	FrameSize             uint32
	FrameFin              uint8
	FrameRewritten        uint8
	FramePreview          string
	FramePreviewTruncated uint8
	SessionFramesC2S      uint64
	SessionFramesS2C      uint64
	SessionBytesC2S       uint64
	SessionBytesS2C       uint64
	SessionDenied         uint32
	SessionRewritten      uint32
	SessionCloseCode      uint16
	SessionCloseReason    string
	SessionDurationMs     uint32
}

type sessionItem struct {
	By       *string `json:"by"`
	Source   string  `json:"source"`
	Kind     string  `json:"kind"`
	User     string  `json:"user"`
	ID       string  `json:"id"`
	Verified bool    `json:"verified"`
	Issued   uint32  `json:"issued"`
	Expires  uint32  `json:"expires"`
	Groups   string  `json:"groups"`
	Passive  bool    `json:"passive"`
}

type entry struct {
	Verdict   string   `json:"verdict"`
	State     string   `json:"state"`
	Score     *int32   `json:"score"`
	LatencyMs *float32 `json:"latency_ms"`
	Role      string   `json:"role"`
	Profile   string   `json:"profile"`

	Rewrite json.RawMessage `json:"rewrite"`
}

type requestEvent struct {
	Kind  string `json:"kind"`
	Ray   string `json:"ray"`
	Node  string `json:"node"`
	Phase string `json:"phase"`
	TS    string `json:"ts"`

	ClientIP   string `json:"client_ip"`
	ClientPort uint16 `json:"client_port"`
	ServerIP   string `json:"server_ip"`
	ServerPort uint16 `json:"server_port"`
	TLS        *struct {
		Version string `json:"version"`
		SNI     string `json:"sni"`
	} `json:"tls"`

	HTTP *struct {
		Method         string `json:"method"`
		Scheme         string `json:"scheme"`
		Host           string `json:"host"`
		URI            string `json:"uri"`
		Version        string `json:"version"`
		ArgsSize       uint32 `json:"args_size"`
		HeadersSize    uint32 `json:"headers_size"`
		HeadersCount   uint16 `json:"headers_count"`
		BodySize       uint64 `json:"body_size"`
		ContentType    string `json:"content_type"`
		Status         uint16 `json:"status"`
		UpstreamStatus uint16 `json:"upstream_status"`
	} `json:"http"`

	Route *struct {
		ServerName string `json:"server_name"`
		Location   string `json:"location"`
		ID         string `json:"id"`
	} `json:"route"`

	Verdict string `json:"verdict"`
	Code    string `json:"code"`
	By      string `json:"by"`

	Score *struct {
		Total  int32 `json:"total"`
		DenyAt int32 `json:"deny_at"`
		Shadow int32 `json:"shadow"`
	} `json:"score"`

	Inspectors map[string]entry `json:"inspectors"`

	Vars map[string]string `json:"vars"`

	Store *struct {
		Headers json.RawMessage `json:"headers"`
		Args    json.RawMessage `json:"args"`
		Body    json.RawMessage `json:"body"`
	} `json:"store"`

	HeadersPreview []previewPair `json:"headers_preview"`
	ArgsPreview    []previewPair `json:"args_preview"`
	BodyPreview    string        `json:"body_preview"`

	HeadersPreviewDropped uint16 `json:"headers_preview_dropped"`
	ArgsPreviewDropped    uint16 `json:"args_preview_dropped"`

	WAFLatencyUs uint32 `json:"waf_latency_us"`

	Actions json.RawMessage `json:"actions"`

	Sessions []sessionItem `json:"sessions"`

	Markers []string `json:"markers"`

	Frame *struct {
		ConnID           string `json:"conn_id"`
		Seq              uint64 `json:"seq"`
		Direction        string `json:"direction"`
		Opcode           string `json:"opcode"`
		Fin              bool   `json:"fin"`
		Size             uint32 `json:"size"`
		Rewritten        bool   `json:"rewritten"`
		PayloadPreview   string `json:"payload_preview"`
		PayloadTruncated bool   `json:"payload_truncated"`
	} `json:"frame"`

	Session *struct {
		ConnID      string `json:"conn_id"`
		Protocol    string `json:"protocol"`
		FramesC2S   uint64 `json:"frames_c2s"`
		FramesS2C   uint64 `json:"frames_s2c"`
		BytesC2S    uint64 `json:"bytes_c2s"`
		BytesS2C    uint64 `json:"bytes_s2c"`
		Denied      uint32 `json:"frames_denied"`
		Rewritten   uint32 `json:"frames_rewritten"`
		CloseCode   uint16 `json:"close_code"`
		CloseReason string `json:"close_reason"`
		DurationMs  uint32 `json:"duration_ms"`
	} `json:"session"`
}

func FromRequest(payload []byte) (Row, bool, error) {
	var ev requestEvent

	if err := json.Unmarshal(payload, &ev); err != nil {
		return Row{}, false, err
	}

	if ev.Kind != "" && ev.Kind != "request" {
		return Row{}, false, nil
	}

	if ev.Node == "" || ev.Ray == "" {
		return Row{}, false, nil
	}

	ts, err := time.Parse(time.RFC3339Nano, ev.TS)
	if err != nil {
		ts = time.Now().UTC()
	}

	row := Row{
		TS:         ts.UTC(),
		Node:       ev.Node,
		Ray:        ev.Ray,
		Phase:      ev.Phase,
		ClientIP:   parseIP(ev.ClientIP),
		ClientPort: ev.ClientPort,
		ServerIP:   parseIP(ev.ServerIP),
		ServerPort: ev.ServerPort,

		Verdict:   ev.Verdict,
		Code:      ev.Code,
		VerdictBy: ev.By,

		WAFLatencyUs: ev.WAFLatencyUs,

		Vars: ev.Vars,
	}

	if row.Phase == "" {
		row.Phase = "request"
	}

	if ev.TLS != nil {
		row.TLSVersion = ev.TLS.Version
		row.TLSSNI = ev.TLS.SNI
	}

	if ev.HTTP != nil {
		row.Method = ev.HTTP.Method
		row.Scheme = ev.HTTP.Scheme
		row.Host = ev.HTTP.Host
		row.URI = ev.HTTP.URI
		row.HTTPVersion = ev.HTTP.Version
		row.ArgsSize = ev.HTTP.ArgsSize
		row.HeadersSize = ev.HTTP.HeadersSize
		row.HeadersCount = ev.HTTP.HeadersCount
		row.BodySize = ev.HTTP.BodySize
		row.ContentType = ev.HTTP.ContentType
		row.Status = ev.HTTP.Status
		row.UpstreamStatus = ev.HTTP.UpstreamStatus
	}

	if ev.Route != nil {
		row.ServerName = ev.Route.ServerName
		row.Location = ev.Route.Location
		row.LocationID = ev.Route.ID
	}

	if ev.Score != nil {
		row.Score = ev.Score.Total
		row.DenyAt = ev.Score.DenyAt
		row.Shadow = ev.Score.Shadow
	}

	if ev.Store != nil {
		row.StoreHeaders = locator(ev.Store.Headers)
		row.StoreArgs = locator(ev.Store.Args)
		row.StoreBody = locator(ev.Store.Body)
	}

	row.HeadersPreview, row.HeadersPreviewTruncated =
		foldPairs(ev.HeadersPreview, true)
	row.ArgsPreview, row.ArgsPreviewTruncated =
		foldPairs(ev.ArgsPreview, false)
	row.BodyPreview = ev.BodyPreview
	row.HeadersPreviewDropped = ev.HeadersPreviewDropped
	row.ArgsPreviewDropped = ev.ArgsPreviewDropped

	if len(ev.Actions) != 0 && !bytes.Equal(ev.Actions, []byte("null")) {
		row.Actions = string(ev.Actions)
	}

	spreadInspectors(&row, ev.Inspectors)
	spreadSessions(&row, ev.Sessions)

	row.Markers = []string{}

	for _, marker := range ev.Markers {
		if marker == "" || slices.Contains(row.Markers, marker) {
			continue
		}

		row.Markers = append(row.Markers, marker)
	}

	if row.Vars == nil {
		row.Vars = map[string]string{}
	}

	if ev.Frame != nil {
		row.FrameSeq = ev.Frame.Seq
		row.FrameDirection = ev.Frame.Direction
		row.FrameOpcode = ev.Frame.Opcode
		row.FrameSize = ev.Frame.Size
		row.FramePreview = ev.Frame.PayloadPreview

		if ev.Frame.Fin {
			row.FrameFin = 1
		}

		if ev.Frame.Rewritten {
			row.FrameRewritten = 1
		}

		if ev.Frame.PayloadTruncated {
			row.FramePreviewTruncated = 1
		}
	}

	if ev.Session != nil {
		row.SessionFramesC2S = ev.Session.FramesC2S
		row.SessionFramesS2C = ev.Session.FramesS2C
		row.SessionBytesC2S = ev.Session.BytesC2S
		row.SessionBytesS2C = ev.Session.BytesS2C
		row.SessionDenied = ev.Session.Denied
		row.SessionRewritten = ev.Session.Rewritten
		row.SessionCloseCode = ev.Session.CloseCode
		row.SessionCloseReason = ev.Session.CloseReason
		row.SessionDurationMs = ev.Session.DurationMs
	}

	return row, true, nil
}

func spreadSessions(row *Row, items []sessionItem) {
	row.SessionsBy = []string{}
	row.SessionsSource = []string{}
	row.SessionsKind = []string{}
	row.SessionsUser = []string{}
	row.SessionsID = []string{}
	row.SessionsVerified = []uint8{}
	row.SessionsIssued = []uint32{}
	row.SessionsExpires = []uint32{}
	row.SessionsGroups = []string{}
	row.SessionsPassive = []uint8{}

	for _, item := range items {
		if item.Source == "" || item.Kind == "" {
			continue
		}

		by := ""
		if item.By != nil {
			by = *item.By
		}

		row.SessionsBy = append(row.SessionsBy, by)
		row.SessionsSource = append(row.SessionsSource, item.Source)
		row.SessionsKind = append(row.SessionsKind, item.Kind)
		row.SessionsUser = append(row.SessionsUser, item.User)
		row.SessionsID = append(row.SessionsID, item.ID)
		row.SessionsVerified = append(row.SessionsVerified, flag(item.Verified))
		row.SessionsIssued = append(row.SessionsIssued, item.Issued)
		row.SessionsExpires = append(row.SessionsExpires, item.Expires)
		row.SessionsGroups = append(row.SessionsGroups, item.Groups)
		row.SessionsPassive = append(row.SessionsPassive, flag(item.Passive))
	}
}

func flag(b bool) uint8 {
	if b {
		return 1
	}

	return 0
}

func spreadInspectors(row *Row, items map[string]entry) {
	row.Inspectors = make([]string, 0, len(items))
	row.InspectorsVerdict = make(map[string]string, len(items))
	row.InspectorsState = map[string]string{}
	row.InspectorsScore = map[string]int32{}
	row.InspectorsLatencyMs = map[string]float32{}
	row.InspectorsRole = map[string]string{}
	row.InspectorsProfile = map[string]string{}

	rewrites := map[string]json.RawMessage{}

	for name, item := range items {
		if name != SelfKey {
			row.Inspectors = append(row.Inspectors, name)
		}

		if item.Verdict != "" {
			row.InspectorsVerdict[name] = item.Verdict
		}

		if item.State != "" {
			row.InspectorsState[name] = item.State
		}

		if item.Score != nil {
			row.InspectorsScore[name] = *item.Score
		}

		if item.LatencyMs != nil {
			row.InspectorsLatencyMs[name] = *item.LatencyMs
		}

		if item.Role != "" {
			row.InspectorsRole[name] = item.Role
		}

		if item.Profile != "" {
			row.InspectorsProfile[name] = item.Profile
		}

		if len(item.Rewrite) != 0 && !bytes.Equal(item.Rewrite, []byte("null")) {
			rewrites[name] = item.Rewrite
		}
	}

	row.Rewrite = foldRewrites(rewrites)

	sortStrings(row.Inspectors)
}

func foldRewrites(items map[string]json.RawMessage) string {
	if len(items) == 0 {
		return ""
	}

	names := make([]string, 0, len(items))

	for name := range items {
		names = append(names, name)
	}

	sortStrings(names)

	var out []byte

	out = append(out, '{')

	for i, name := range names {
		if i != 0 {
			out = append(out, ',')
		}

		key, err := json.Marshal(name)
		if err != nil {
			continue
		}

		out = append(out, key...)
		out = append(out, ':')
		out = append(out, items[name]...)
	}

	out = append(out, '}')

	return string(out)
}

func sortStrings(in []string) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j] < in[j-1]; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

type previewPair struct {
	Name      string
	Value     string
	Truncated bool
}

func (p *previewPair) UnmarshalJSON(raw []byte) error {
	var parts []json.RawMessage

	if err := json.Unmarshal(raw, &parts); err != nil {
		return err
	}

	if len(parts) < 2 {
		return fmt.Errorf("preview pair of %d elements", len(parts))
	}

	if err := json.Unmarshal(parts[0], &p.Name); err != nil {
		return err
	}

	if err := json.Unmarshal(parts[1], &p.Value); err != nil {
		return err
	}

	p.Truncated = len(parts) > 2

	return nil
}

func foldPairs(pairs []previewPair, lower bool) (map[string]string, []string) {
	var (
		out  = make(map[string]string, len(pairs))
		cut  []string
		seen = map[string]bool{}
	)

	for _, kv := range pairs {
		name := kv.Name
		if lower {
			name = strings.ToLower(name)
		}

		if name == "" {
			continue
		}

		if kv.Truncated && !seen[name] {
			seen[name] = true
			cut = append(cut, name)
		}

		if prev, ok := out[name]; ok {
			out[name] = prev + ", " + kv.Value
			continue
		}

		out[name] = kv.Value
	}

	sortStrings(cut)

	return out, cut
}

func locator(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))

	if s == "" || s == "null" {
		return ""
	}

	return s
}

func parseIP(raw string) netip.Addr {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.IPv6Unspecified()
	}

	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.IPv6Unspecified()
	}

	return ip
}
