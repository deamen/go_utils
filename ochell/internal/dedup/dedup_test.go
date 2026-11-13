package dedup

import (
	"testing"
	"time"
)

func TestSet(t *testing.T) {
	now := time.Unix(0, 0)
	s := New(time.Minute)
	s.now = func() time.Time { return now }

	if !s.Add("a") || s.Add("a") {
		t.Fatal("expected first add new, second duplicate")
	}
	if !s.Add("") || !s.Add("") {
		t.Fatal("empty key must always be new")
	}
	now = now.Add(2 * time.Minute)
	if !s.Add("a") {
		t.Fatal("expected key to expire after TTL")
	}
	s.Remove("a")
	if !s.Add("a") {
		t.Fatal("expected key to be new after Remove")
	}
}
