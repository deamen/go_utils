package metrics

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ochell/internal/agent"
	"ochell/internal/runner"
	"ochell/internal/store"
	"ochell/internal/task"
	"ochell/internal/ticket"
)

type fakeStore struct{}

func (fakeStore) Metrics() (*store.Metrics, error) {
	return &store.Metrics{
		Tickets: map[ticket.State]int{ticket.Waiting: 2, ticket.Done: 5},
		Queued:  3, Running: 1,
		Started:       map[string]int{"assigned": 7, "retry": 2, "stalled": 1, "follow_up": 4},
		Ended:         map[task.Outcome]int{task.OutcomeFinished: 9, task.OutcomeFailed: 2, task.OutcomeTimedOut: 1, task.OutcomeCancelled: 1, task.OutcomeNoProgress: 2},
		DurationCount: 13, DurationSum: 4321.5, DurationBucket: []int{4, 8, 10, 11, 12, 13},
		CostUSD: 12.75, Usage: agent.Usage{InputTokens: 100, OutputTokens: 200, CacheReadTokens: 300, CacheWriteTokens: 400},
	}, nil
}

type fakeRunner struct{}

func (fakeRunner) Status() (runner.Status, error) { return runner.Status{Paused: true}, nil }

func TestMetrics(t *testing.T) {
	now := time.Date(2027, 11, 1, 12, 0, 0, 0, time.UTC)
	h := &Handler{Token: "0123456789abcdef", Version: "1.2.3", TokenExpiry: time.Date(2027, 11, 14, 0, 0, 0, 0, time.UTC),
		Store: fakeStore{}, Runner: fakeRunner{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }}
	scrape := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", Path, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, bad := range []string{"", "wrong-token-000000"} {
		if w := scrape(bad); w.Code != 401 || strings.Contains(w.Body.String(), "ochell_") {
			t.Errorf("a scrape with the token %q: %d %s", bad, w.Code, w.Body)
		}
	}
	w := scrape("0123456789abcdef")
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("scrape: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	body := w.Body.String()
	for _, want := range []string{
		`ochell_build_info{version="1.2.3"} 1`,
		`ochell_tickets{state="waiting"} 2`, `ochell_tickets{state="done"} 5`, `ochell_tickets{state="queued"} 0`,
		"ochell_queue_length 3", "ochell_runs_running 1", "ochell_paused 1",
		`ochell_runs_started_total{cause="assigned"} 7`, `ochell_runs_started_total{cause="follow_up"} 4`,
		`ochell_runs_ended_total{outcome="finished"} 9`, `ochell_runs_ended_total{outcome="timed_out"} 1`,
		`ochell_runs_ended_total{outcome="no_progress"} 2`, "ochell_run_failures_total 5", "ochell_run_retries_total 3",
		`ochell_run_duration_seconds_bucket{le="60"} 4`, `ochell_run_duration_seconds_bucket{le="7200"} 13`, `ochell_run_duration_seconds_bucket{le="+Inf"} 13`,
		"ochell_run_duration_seconds_sum 4321.5", "ochell_run_duration_seconds_count 13",
		"ochell_cost_usd_total 12.75", `ochell_tokens_total{kind="cache_read"} 300`, `ochell_tokens_total{kind="output"} 200`,
		"ochell_agent_token_expiry_timestamp_seconds 1826150400", "ochell_agent_token_days_left 12",
		"# TYPE ochell_runs_ended_total counter", "# TYPE ochell_queue_length gauge", "# TYPE ochell_run_duration_seconds histogram",
	} {
		if !strings.Contains(body, want+"\n") {
			t.Errorf("the metrics lack the line %q", want)
		}
	}
	// Every sample belongs to a metric that was announced.
	announced := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if name, ok := strings.CutPrefix(line, "# TYPE "); ok {
			announced[strings.Fields(name)[0]] = true
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		name := line[:strings.IndexAny(line, "{ ")]
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, "_bucket"), "_sum"), "_count")
		if !announced[name] && !announced[base] {
			t.Errorf("the sample %q has no TYPE line", line)
		}
	}
	// Without a date for the token there is no such metric.
	h.TokenExpiry = time.Time{}
	if body := scrape("0123456789abcdef").Body.String(); strings.Contains(body, "agent_token") {
		t.Error("a token metric without agent.token_expires")
	}
}
