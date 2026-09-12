package consume

import "testing"

func TestNewStatsHasCounters(t *testing.T) {
	s := NewStats()
	if s.Consume == nil || s.Insert == nil {
		t.Fatal("NewStats left a channel counter nil")
	}
	s.Consume.Add(4, 0, false, 0)
	s.Insert.AddN(2, 0, 0, false, 0)
}

func TestStatsAdd(t *testing.T) {
	var s Stats
	s.Add(3)
	s.Add(7)
	if s.Inserted() != 10 {
		t.Fatalf("inserted=%d", s.Inserted())
	}
	if s.LastBatch() != 7 {
		t.Fatalf("last=%d", s.LastBatch())
	}
}
