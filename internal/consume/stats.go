package consume

import (
	"sync/atomic"

	"github.com/exemt/placitum-logger/internal/flow"
)

// Stats — счётчики для пульса флота. Не влияют на ack. Consume/Insert —
// темп каналов io: сколько снято с JetStream и сколько вставлено в
// ClickHouse, отдельно от накопительных Inserted/LastBatch.
type Stats struct {
	inserted  atomic.Int64
	lastBatch atomic.Int64
	Consume   *flow.Counter
	Insert    *flow.Counter
}

func NewStats() *Stats {
	return &Stats{Consume: flow.New(), Insert: flow.New()}
}

func (s *Stats) Add(n int) {
	if s == nil || n <= 0 {
		return
	}
	s.inserted.Add(int64(n))
	s.lastBatch.Store(int64(n))
}

func (s *Stats) Inserted() int64 {
	if s == nil {
		return 0
	}
	return s.inserted.Load()
}

func (s *Stats) LastBatch() int {
	if s == nil {
		return 0
	}
	return int(s.lastBatch.Load())
}
