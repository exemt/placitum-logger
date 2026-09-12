/*
 * Присутствие на WAF_STATUS — та же шина, что у агента и Redis.
 * Не аудит и не healthcheck контейнера. Контроллер слушает WAF_STATUS.>
 * и ставит degraded по тишине.
 */

package pulse

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-logger/internal/flow"
	"github.com/exemt/placitum-logger/internal/host"
)

type Work struct {
	Inserted     int64  `json:"inserted,omitempty"`
	LastBatch    int    `json:"last_batch,omitempty"`
	ClickHouseOK bool   `json:"clickhouse_ok"`
	Error        string `json:"error,omitempty"`
}

type Message struct {
	V        int                  `json:"v"`
	Kind     string               `json:"kind"`
	ID       string               `json:"id"`
	Name     string               `json:"name"`
	Hostname string               `json:"hostname"`
	Ready    bool                 `json:"ready"`
	At       string               `json:"at"`
	Host     host.Snapshot        `json:"host"`
	Work     Work                 `json:"work"`
	WindowS  int                  `json:"window_s,omitempty"`
	IO       map[string]flow.Flow `json:"io,omitempty"`
}

func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func Subject(name, id string) string {
	return fmt.Sprintf("WAF_STATUS.service.%s.%s", token(name), token(id))
}

func Build(id, name string, work Work, io map[string]flow.Flow) Message {
	msg := Message{
		V:        1,
		Kind:     "service",
		ID:       id,
		Name:     name,
		Hostname: host.Hostname(),
		Ready:    work.ClickHouseOK,
		At:       time.Now().UTC().Format(time.RFC3339Nano),
		Host:     host.Collect(),
		Work:     work,
	}
	if len(io) > 0 {
		msg.WindowS = flow.Window
		msg.IO = io
	}
	return msg
}

func Publish(nc *nats.Conn, msg Message) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return nc.Publish(Subject(msg.Name, msg.ID), body)
}

func token(s string) string {
	r := strings.NewReplacer(".", "_", ">", "_", "*", "_", " ", "_")
	return r.Replace(s)
}
