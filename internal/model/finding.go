package model

import (
	"encoding/json"
	"time"
)

const maxFindings = 1024

type FindingRow struct {
	TS    time.Time
	Node  string
	Ray   string
	Phase string
	Rev   uint32

	Inspector string
	Profile   string
	Verdict   string
	Score     int32
	EngineMS  float32

	FrameDirection string
	FrameSeq       uint64

	FindingIdx uint16
	Code       string
	Severity   string
	Target     string
	Rule       string
	Offset     int64
	Length     int64
	Confidence float32
	Evidence   string
	Message    string
	Tags       []string

	Engine string
}

type InspectorEvent struct {
	Node      string
	Ray       string
	Phase     string
	Inspector string

	Findings []FindingRow
}

type finding struct {
	Code       string   `json:"code"`
	Severity   string   `json:"severity"`
	Target     string   `json:"target"`
	Offset     *int64   `json:"offset"`
	Length     *int64   `json:"length"`
	Rule       string   `json:"rule"`
	Confidence *float32 `json:"confidence"`
	Evidence   string   `json:"evidence"`
	Message    string   `json:"message"`
	Tags       []string `json:"tags"`
}

type inspectorEvent struct {
	TS        string `json:"ts"`
	Ray       string `json:"ray"`
	Node      string `json:"node"`
	Phase     string `json:"phase"`
	Inspector string `json:"inspector"`
	Profile   string `json:"profile"`

	Verdict  string  `json:"verdict"`
	Score    *int32  `json:"score"`
	EngineMS float32 `json:"engine_ms"`

	Findings []finding       `json:"findings"`
	Engine   json.RawMessage `json:"engine"`

	Frame *struct {
		Direction string `json:"direction"`
		Seq       uint64 `json:"seq"`
	} `json:"frame"`
}

func FromInspector(payload []byte) (InspectorEvent, bool, error) {
	if KindOf(payload) != KindInspector {
		return InspectorEvent{}, false, nil
	}

	var ev inspectorEvent

	if err := json.Unmarshal(payload, &ev); err != nil {
		return InspectorEvent{}, false, err
	}

	if ev.Node == "" || ev.Ray == "" || ev.Inspector == "" {
		return InspectorEvent{}, false, nil
	}

	phase := ev.Phase
	if phase == "" {
		phase = "request"
	}

	ts, err := time.Parse(time.RFC3339Nano, ev.TS)
	if err != nil {
		ts = time.Now().UTC()
	}

	out := InspectorEvent{
		Node:      ev.Node,
		Ray:       ev.Ray,
		Phase:     phase,
		Inspector: ev.Inspector,
	}

	head := FindingRow{
		TS:        ts.UTC(),
		Node:      ev.Node,
		Ray:       ev.Ray,
		Phase:     phase,
		Inspector: ev.Inspector,
		Profile:   ev.Profile,
		Verdict:   ev.Verdict,
		EngineMS:  ev.EngineMS,
		Engine:    locator(ev.Engine),
		Tags:      []string{},
	}

	if ev.Frame != nil {
		head.FrameDirection = ev.Frame.Direction
		head.FrameSeq = ev.Frame.Seq
	}

	if ev.Score != nil {
		head.Score = *ev.Score
	}

	if len(ev.Findings) == 0 {
		out.Findings = []FindingRow{head}

		return out, true, nil
	}

	items := ev.Findings
	if len(items) > maxFindings {
		items = items[:maxFindings]
	}

	out.Findings = make([]FindingRow, 0, len(items))

	for i, f := range items {
		row := head
		row.FindingIdx = uint16(i)
		row.Code = f.Code
		row.Severity = f.Severity
		row.Target = f.Target
		row.Rule = f.Rule
		row.Evidence = f.Evidence
		row.Message = f.Message

		if f.Tags != nil {
			row.Tags = f.Tags
		}

		if f.Offset != nil && f.Length != nil {
			row.Offset = *f.Offset
			row.Length = *f.Length
		}

		if f.Confidence != nil {
			row.Confidence = *f.Confidence
		}

		out.Findings = append(out.Findings, row)
	}

	return out, true, nil
}
