package model

import "encoding/json"

const (
	KindRequest   = "request"
	KindInspector = "inspector"
	KindBatch     = "batch"
)

type envelope struct {
	Kind string `json:"kind"`
}

type batch struct {
	Items []json.RawMessage `json:"items"`
}

func Batch(payload []byte) ([]json.RawMessage, bool) {
	if KindOf(payload) != KindBatch {
		return nil, false
	}

	var b batch

	if err := json.Unmarshal(payload, &b); err != nil {
		return nil, false
	}

	return b.Items, true
}

func KindOf(payload []byte) string {
	var env envelope

	if err := json.Unmarshal(payload, &env); err != nil {
		return ""
	}

	return env.Kind
}
