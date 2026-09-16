package query

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/exemt/placitum-logger/internal/model"
)

type Participant struct {
	Name string `json:"name"`

	Self bool `json:"self,omitempty"`

	Decisive bool `json:"decisive,omitempty"`

	Verdict string `json:"verdict,omitempty"`
	State   string `json:"state,omitempty"`

	Score int32 `json:"score,omitempty"`

	LatencyMs float32 `json:"latency_ms,omitempty"`
	EngineMs  float32 `json:"engine_ms,omitempty"`

	Role    string `json:"role,omitempty"`
	Profile string `json:"profile,omitempty"`

	Clean bool `json:"clean,omitempty"`

	Rewrite *Rewrite `json:"rewrite,omitempty"`

	Orphan bool `json:"orphan,omitempty"`

	Findings []Finding `json:"findings,omitempty"`
}

type Card struct {
	TS    time.Time `json:"ts"`
	Node  string    `json:"node"`
	Ray   string    `json:"ray"`
	Phase string    `json:"phase"`

	Verdict string `json:"verdict"`
	Code    string `json:"code,omitempty"`
	By      string `json:"by"`

	Score  int32 `json:"score"`
	DenyAt int32 `json:"deny_at,omitempty"`
	Shadow int32 `json:"shadow,omitempty"`

	Items []Participant `json:"items"`
	Count int           `json:"count"`

	Frame   *FrameInfo   `json:"frame,omitempty"`
	Session *SessionInfo `json:"session,omitempty"`

	Actions []Action `json:"actions,omitempty"`
}

type Rewrite struct {
	Applied bool     `json:"applied"`
	Size    *uint64  `json:"size,omitempty"`
	Groups  []string `json:"groups,omitempty"`
}

func samePhase(phase string, findings []Finding) []Finding {
	if phase == "" {
		return findings
	}

	out := make([]Finding, 0, len(findings))

	for _, item := range findings {
		if item.Phase == "" || item.Phase == phase {
			out = append(out, item)
		}
	}

	return out
}

func rewritesOf(raw string) map[string]Rewrite {
	if raw == "" {
		return nil
	}

	var items map[string]Rewrite

	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil
	}

	return items
}

type Action struct {
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Do     string `json:"do"`
	Apply  string `json:"apply,omitempty"`
	Code   string `json:"code,omitempty"`
	Delta  *int   `json:"delta,omitempty"`
	Value  *int   `json:"value,omitempty"`
	Marker string `json:"marker,omitempty"`
	Phase  string `json:"phase,omitempty"`

	Passive bool `json:"passive,omitempty"`

	Outcomes []ActionOutcome `json:"outcomes,omitempty"`
}

type ActionOutcome struct {
	Inspector string   `json:"inspector"`
	Outcome   string   `json:"outcome"`
	Took      *float64 `json:"took,omitempty"`
}

type wireAction struct {
	From    string   `json:"from"`
	To      string   `json:"to"`
	Do      string   `json:"do"`
	Apply   string   `json:"apply"`
	Code    string   `json:"code"`
	Delta   *int     `json:"delta"`
	Value   *int     `json:"value"`
	Marker  string   `json:"marker"`
	Phase   string   `json:"phase"`
	Passive bool     `json:"passive"`
	Outcome string   `json:"outcome"`
	Took    *float64 `json:"took"`
}

func actionKey(a wireAction) [5]string {
	return [5]string{a.From, a.Do, a.Apply, a.Code, a.Marker}
}

func actionsOf(raw string, findings []Finding) []Action {
	if raw == "" {
		return nil
	}

	var live []wireAction

	if err := json.Unmarshal([]byte(raw), &live); err != nil || len(live) == 0 {
		return nil
	}

	said := make(map[[5]string][]ActionOutcome, len(live))

	for _, item := range findings {
		if len(item.Engine) == 0 {
			continue
		}

		var eng struct {
			Actions []wireAction `json:"actions"`
		}

		if err := json.Unmarshal(item.Engine, &eng); err != nil {
			continue
		}

		for _, got := range eng.Actions {
			if got.Outcome == "" {
				continue
			}

			key := actionKey(got)
			said[key] = append(said[key], ActionOutcome{
				Inspector: item.Inspector,
				Outcome:   got.Outcome,
				Took:      got.Took,
			})
		}
	}

	out := make([]Action, 0, len(live))

	for _, a := range live {
		out = append(out, Action{
			From:     a.From,
			To:       a.To,
			Do:       a.Do,
			Apply:    a.Apply,
			Code:     a.Code,
			Delta:    a.Delta,
			Value:    a.Value,
			Marker:   a.Marker,
			Phase:    a.Phase,
			Passive:  a.Passive,
			Outcomes: said[actionKey(a)],
		})
	}

	return out
}

func CardOf(ev Event, findings []Finding) Card {
	card := Card{
		TS:    ev.TS,
		Node:  ev.Node,
		Ray:   ev.Ray,
		Phase: ev.Phase,
		Items: []Participant{},

		Verdict: ev.Verdict,
		Code:    ev.Code,
		By:      ev.By,

		Score:  ev.Score,
		DenyAt: ev.DenyAt,
		Shadow: ev.Shadow,

		Actions: actionsOf(ev.Actions, samePhase(ev.Phase, findings)),

		Frame:   ev.Frame,
		Session: ev.Session,
	}

	rewrites := rewritesOf(ev.Rewrite)

	byName := make(map[string][]Finding, len(findings))
	engine := make(map[string]float32, len(findings))
	clean := make(map[string]bool, len(findings))
	profiles := make(map[string]string, len(findings))

	for _, item := range findings {
		if item.Phase != "" && ev.Phase != "" && item.Phase != ev.Phase {
			continue
		}

		if item.EngineMs > engine[item.Inspector] {
			engine[item.Inspector] = item.EngineMs
		}

		if item.Profile != "" && profiles[item.Inspector] == "" {
			profiles[item.Inspector] = item.Profile
		}

		if item.Clean {
			clean[item.Inspector] = true
			continue
		}

		byName[item.Inspector] = append(byName[item.Inspector], item)
	}

	names := make([]string, 0, len(ev.Inspectors)+1)

	if _, ok := ev.InspectorsVerdict[model.SelfKey]; ok {
		names = append(names, model.SelfKey)
	}

	names = append(names, ev.Inspectors...)

	seen := make(map[string]bool, len(names))

	for _, name := range names {
		if seen[name] {
			continue
		}

		seen[name] = true

		card.Items = append(card.Items, Participant{
			Name:     name,
			Self:     name == model.SelfKey,
			Decisive: name == ev.By,

			Verdict: ev.InspectorsVerdict[name],
			State:   ev.InspectorsState[name],

			Score: ev.InspectorsScore[name],

			LatencyMs: ev.InspectorsLatencyMs[name],
			EngineMs:  engine[name],

			Role:    ev.InspectorsRole[name],
			Profile: firstProfile(ev.InspectorsProfile[name], profiles[name]),

			Clean:    clean[name] && len(byName[name]) == 0,
			Findings: byName[name],
			Rewrite:  rewriteOf(rewrites, name),
		})
	}

	for _, name := range sortedKeys(byName) {
		if seen[name] {
			continue
		}

		card.Items = append(card.Items, Participant{
			Name:     name,
			Orphan:   true,
			EngineMs: engine[name],
			Profile:  profiles[name],
			Findings: byName[name],
		})
	}

	card.Count = len(card.Items)

	return card
}

func FindingsFor(ctx context.Context, conn driver.Conn, ev Event) ([]Finding, error) {
	if ev.Frame != nil {
		return FindingsByFrame(ctx, conn, ev.Node, ev.Ray, ev.Frame.Direction, ev.Frame.Seq)
	}

	if ev.Session != nil {
		return nil, nil
	}

	return FindingsByRay(ctx, conn, ev.Node, ev.Ray)
}

func firstProfile(spine, finding string) string {
	if spine != "" {
		return spine
	}

	return finding
}

func sortedKeys(in map[string][]Finding) []string {
	out := make([]string, 0, len(in))

	for name := range in {
		out = append(out, name)
	}

	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}

	return out
}

func rewriteOf(items map[string]Rewrite, name string) *Rewrite {
	item, ok := items[name]

	if !ok {
		return nil
	}

	return &item
}
