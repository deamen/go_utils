package tracker

import (
	"context"
	"fmt"
	"sync"
)

// Fake is a Client that keeps everything in memory, for tests.
type Fake struct {
	mu sync.Mutex
	// Issues is what Assigned returns.
	Issues []Issue
	// Err, when set, is returned by every call.
	Err error

	comments []FakeComment
	statuses map[string]string
}

// FakeComment is one comment that was added through a Fake.
type FakeComment struct {
	Key, Body string
}

func (f *Fake) Assigned(context.Context) ([]Issue, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return nil, f.Err
	}
	return append([]Issue(nil), f.Issues...), nil
}

func (f *Fake) Comment(_ context.Context, key, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return f.Err
	}
	if key == "" {
		return fmt.Errorf("fake tracker: no ticket key")
	}
	f.comments = append(f.comments, FakeComment{key, body})
	return nil
}

func (f *Fake) SetStatus(_ context.Context, key, status string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return f.Err
	}
	if f.statuses == nil {
		f.statuses = map[string]string{}
	}
	f.statuses[key] = status
	return nil
}

// Comments returns the comments added to a ticket so far, in order.
func (f *Fake) Comments(key string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.comments {
		if c.Key == key {
			out = append(out, c.Body)
		}
	}
	return out
}

// Status returns the status a ticket was last moved to, or "".
func (f *Fake) Status(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statuses[key]
}
