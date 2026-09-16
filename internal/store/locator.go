package store

import (
	"encoding/json"
	"strings"
	"time"
)

var Kinds = []string{"headers", "args", "body"}

type Locator struct {
	Unavailable string `json:"unavailable,omitempty"`

	Size         int64  `json:"size"`
	DeclaredSize int64  `json:"declared_size,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Complete     *bool  `json:"complete,omitempty"`
	Truncated    *bool  `json:"truncated,omitempty"`
	Encoding     string `json:"encoding,omitempty"`

	Store  string `json:"store,omitempty"`
	Driver string `json:"driver,omitempty"`
	Key    string `json:"key,omitempty"`

	ExpiresAt int64 `json:"expires_at,omitempty"`
}

func (l Locator) Addressable() bool {
	return l.Unavailable == "" && l.Driver != "" && l.Key != ""
}

func (l Locator) Expired(now time.Time) bool {
	return l.ExpiresAt > 0 && now.Unix() >= l.ExpiresAt
}

func ParseLocator(raw string) (Locator, bool) {
	raw = strings.TrimSpace(raw)

	if raw == "" || raw == "null" {
		return Locator{}, false
	}

	var loc Locator
	if err := json.Unmarshal([]byte(raw), &loc); err != nil {
		return Locator{}, false
	}

	return loc, true
}
