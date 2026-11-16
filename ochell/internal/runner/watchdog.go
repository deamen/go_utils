package runner

import (
	"fmt"
	"strings"
	"sync"
)

// maxCycle is the longest circle of tool calls that the watchdog looks
// for: the same call again and again is a circle of one, A B A B one of
// two.
const maxCycle = 3

// toolCall is one tool call of a run, as far as the watchdog keeps it: what
// identifies it (agent.Event.Call), and the tool and the short part of its
// input that people are shown anyway.
type toolCall struct {
	id, tool, param string
}

// watchdog looks at the tool calls of one run as they are reported, and
// says when the run goes round in a circle: when its last calls are the
// same call, or the same two or three calls in the same order, repeats
// times in a row.
//
// That is all it looks at. It calls no model and does not judge what the
// agent writes, and it keeps nothing of a call's input. A run that makes
// the same call with another input each time, or that says nothing at all
// (agent.stall_timeout is for that), is not its business.
//
// A nil watchdog sees nothing and never fires.
type watchdog struct {
	repeats int
	// fired is closed when the run is found to go round in a circle.
	fired chan struct{}

	mu sync.Mutex
	// last holds the most recent calls, the newest first, and seen how
	// many of its places are filled.
	last [maxCycle]toolCall
	seen int
	// same[n-1] counts the calls in a row, up to the newest, that were
	// each the same as the call n calls before it. A circle of n calls
	// that went round k times makes that n*(k-1).
	same [maxCycle]int
	// found describes the circle, once there is one.
	found string
}

// newWatchdog returns the watchdog of one run, or nil when the check is
// turned off.
func newWatchdog(repeats int) *watchdog {
	if repeats < 2 {
		return nil
	}
	return &watchdog{repeats: repeats, fired: make(chan struct{})}
}

// stopped returns the channel that is closed when the run is to be
// stopped; nil, which never is, without a watchdog.
func (w *watchdog) stopped() <-chan struct{} {
	if w == nil {
		return nil
	}
	return w.fired
}

// reason says what the watchdog saw, or "" when it has not fired.
func (w *watchdog) reason() string {
	if w == nil {
		return ""
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.found
}

// observe takes the next tool call of the run. It is called while the
// agent's output is read, and does not block.
func (w *watchdog) observe(c toolCall) {
	if w == nil || c.id == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.found != "" {
		return
	}
	for n := 1; n <= maxCycle; n++ {
		if n <= w.seen && w.last[n-1].id == c.id {
			w.same[n-1]++
		} else {
			w.same[n-1] = 0
		}
	}
	copy(w.last[1:], w.last[:maxCycle-1])
	w.last[0] = c
	w.seen = min(w.seen+1, maxCycle)
	// The shortest circle first: A A A A is also A A twice.
	for n := 1; n <= maxCycle; n++ {
		if w.same[n-1] < n*(w.repeats-1) {
			continue
		}
		// The calls of the circle, the oldest first.
		names := make([]string, 0, n)
		for i := n - 1; i >= 0; i-- {
			names = append(names, strings.TrimSpace(w.last[i].tool+" "+w.last[i].param))
		}
		if n == 1 {
			w.found = fmt.Sprintf("it made the same tool call %d times in a row (%s)", w.repeats, names[0])
		} else {
			w.found = fmt.Sprintf("it made the same %d tool calls, in the same order, %d times in a row (%s)", n, w.repeats, strings.Join(names, ", "))
		}
		close(w.fired)
		return
	}
}
