// Package dedup remembers recently seen keys for a limited time.
package dedup

import (
	"sync"
	"time"
)

type Set struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]time.Time
	now  func() time.Time
}

func New(ttl time.Duration) *Set {
	return &Set{ttl: ttl, seen: map[string]time.Time{}, now: time.Now}
}

// Add records key and reports whether it was new (not seen within the TTL).
// Empty keys are always treated as new.
func (s *Set) Add(key string) bool {
	if key == "" {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, exp := range s.seen {
		if now.After(exp) {
			delete(s.seen, k)
		}
	}
	if exp, ok := s.seen[key]; ok && !now.After(exp) {
		return false
	}
	s.seen[key] = now.Add(s.ttl)
	return true
}

// Remove forgets key, e.g. when a task finishes and the ticket may be
// legitimately re-assigned.
func (s *Set) Remove(key string) {
	s.mu.Lock()
	delete(s.seen, key)
	s.mu.Unlock()
}
