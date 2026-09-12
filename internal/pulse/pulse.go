/*
 * Присутствие на WAF_STATUS — та же шина, что у агента и Redis.
 * Не аудит и не healthcheck контейнера. Контроллер слушает WAF_STATUS.>
 * и ставит degraded по тишине.
 *
 * Шапка кадра общая (pulse.Frame из placitum-shared); своё здесь — work:
 * вставки в ClickHouse и его доступность, она же ready.
 */

package pulse

import (
	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-shared/flow"
	shared "github.com/exemt/placitum-shared/pulse"
)

type Work struct {
	Inserted     int64  `json:"inserted,omitempty"`
	LastBatch    int    `json:"last_batch,omitempty"`
	ClickHouseOK bool   `json:"clickhouse_ok"`
	Error        string `json:"error,omitempty"`
}

type Message struct {
	shared.Frame
	Work Work `json:"work"`
}

func NewID() string {
	return shared.NewID()
}

func Subject(name, id string) string {
	return shared.ServiceSubject(name, id)
}

func Build(id, name string, work Work, io map[string]flow.Flow) Message {
	return Message{
		Frame: shared.NewFrame("service", id, name, work.ClickHouseOK, io),
		Work:  work,
	}
}

func Publish(nc *nats.Conn, msg Message) error {
	return shared.PublishFrame(nc, Subject(msg.Name, msg.ID), msg)
}
