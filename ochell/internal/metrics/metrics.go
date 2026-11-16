// Package metrics is the metrics endpoint: counters and gauges about
// ochell's runs, in the Prometheus text format.
//
// The numbers are counted from the store at each scrape, so they are the
// same after a restart, and a counter never goes back.
package metrics

import (
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"ochell/internal/runner"
	"ochell/internal/store"
)

// Path is where the endpoint is served.
const Path = "/metrics"

// Store is what the endpoint counts from. *store.Store implements it.
type Store interface {
	Metrics() (*store.Metrics, error)
}

// Runner tells whether ochell is paused. *runner.Runner implements it.
type Runner interface {
	Status() (runner.Status, error)
}

// Handler serves the metrics.
type Handler struct {
	// Token is what a scrape must send as a Bearer token.
	Token string
	// Version is ochell's version, for the build info.
	Version string
	// TokenExpiry is when the agent's credential stops working, as the
	// configuration notes it; zero: not noted.
	TokenExpiry time.Time
	Store       Store
	Runner      Runner
	Log         *slog.Logger
	// Now is the clock; nil: time.Now.
	Now func() time.Time
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || h.Token == "" || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), []byte(h.Token)) != 1 {
		h.Log.Warn("metrics: scrape without a valid token", "remote", r.RemoteAddr)
		w.Header().Set("WWW-Authenticate", `Bearer realm="ochell metrics"`)
		http.Error(w, "the metrics endpoint needs its token: Authorization: Bearer <metrics.token>", http.StatusUnauthorized)
		return
	}
	m, err := h.Store.Metrics()
	if err != nil {
		h.Log.Error("metrics: cannot read the store", "err", err)
		http.Error(w, "cannot read the store", http.StatusInternalServerError)
		return
	}
	st, err := h.Runner.Status()
	if err != nil {
		h.Log.Error("metrics: cannot read the status", "err", err)
		http.Error(w, "cannot read the status", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	h.write(w, m, st)
}

// num writes a number the way the text format wants it.
func num(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

// write prints every metric: a HELP and a TYPE line, then its samples.
func (h *Handler) write(w io.Writer, m *store.Metrics, st runner.Status) {
	metric := func(name, kind, help string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
	}
	labelled := func(name, label string, values map[string]float64) {
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "%s{%s=%q} %s\n", name, label, k, num(values[k]))
		}
	}

	metric("ochell_build_info", "gauge", "The version of ochell that answers; the value is always 1.")
	fmt.Fprintf(w, "ochell_build_info{version=%q} 1\n", h.Version)

	metric("ochell_tickets", "gauge", "Tickets that ochell knows, by state.")
	tickets := map[string]float64{}
	for _, s := range []string{"queued", "running", "checking", "waiting", "in_review", "done", "failed", "cancelled"} {
		tickets[s] = 0
	}
	for s, n := range m.Tickets {
		tickets[string(s)] = float64(n)
	}
	labelled("ochell_tickets", "state", tickets)

	metric("ochell_queue_length", "gauge", "Runs that wait in the queue.")
	fmt.Fprintf(w, "ochell_queue_length %d\n", m.Queued)
	metric("ochell_runs_running", "gauge", "Runs whose agent is working now.")
	fmt.Fprintf(w, "ochell_runs_running %d\n", m.Running)
	metric("ochell_paused", "gauge", "1 while no run starts because ochell is paused, 0 otherwise.")
	paused := 0
	if st.Paused {
		paused = 1
	}
	fmt.Fprintf(w, "ochell_paused %d\n", paused)

	metric("ochell_runs_started_total", "counter", "Runs that were started, by why they were queued: assigned, retry, stalled, recovery, follow_up, poll and others.")
	started := map[string]float64{"assigned": 0, "retry": 0}
	for c, n := range m.Started {
		started[c] = float64(n)
	}
	labelled("ochell_runs_started_total", "cause", started)

	metric("ochell_runs_ended_total", "counter", "Runs that have ended, by outcome.")
	ended := map[string]float64{"finished": 0, "failed": 0}
	failures := 0
	for o, n := range m.Ended {
		ended[string(o)] = float64(n)
		switch o {
		case "failed", "timed_out", "stalled", "not_started":
			failures += n
		}
	}
	labelled("ochell_runs_ended_total", "outcome", ended)
	metric("ochell_run_failures_total", "counter", "Runs that failed, timed out, stalled or could not be started.")
	fmt.Fprintf(w, "ochell_run_failures_total %d\n", failures)
	metric("ochell_run_retries_total", "counter", "Runs that ochell started by itself after a run that failed for a temporary reason or stalled.")
	fmt.Fprintf(w, "ochell_run_retries_total %d\n", m.Started["retry"]+m.Started["stalled"])

	metric("ochell_run_duration_seconds", "histogram", "How long the runs took that have ended.")
	for i, b := range store.DurationBuckets {
		fmt.Fprintf(w, "ochell_run_duration_seconds_bucket{le=%q} %d\n", num(b), m.DurationBucket[i])
	}
	fmt.Fprintf(w, "ochell_run_duration_seconds_bucket{le=\"+Inf\"} %d\n", m.DurationCount)
	fmt.Fprintf(w, "ochell_run_duration_seconds_sum %s\n", num(m.DurationSum))
	fmt.Fprintf(w, "ochell_run_duration_seconds_count %d\n", m.DurationCount)

	metric("ochell_cost_usd_total", "counter", "What all runs cost, in USD, as the agent reports it.")
	fmt.Fprintf(w, "ochell_cost_usd_total %s\n", num(m.CostUSD))
	metric("ochell_tokens_total", "counter", "Tokens of all runs, by kind.")
	labelled("ochell_tokens_total", "kind", map[string]float64{
		"input": float64(m.Usage.InputTokens), "output": float64(m.Usage.OutputTokens),
		"cache_read": float64(m.Usage.CacheReadTokens), "cache_write": float64(m.Usage.CacheWriteTokens),
	})

	if !h.TokenExpiry.IsZero() {
		now := time.Now
		if h.Now != nil {
			now = h.Now
		}
		metric("ochell_agent_token_expiry_timestamp_seconds", "gauge", "When the agent's own credential stops working, as agent.token_expires notes it.")
		fmt.Fprintf(w, "ochell_agent_token_expiry_timestamp_seconds %d\n", h.TokenExpiry.Unix())
		metric("ochell_agent_token_days_left", "gauge", "Days until the agent's own credential stops working; negative when it has.")
		fmt.Fprintf(w, "ochell_agent_token_days_left %s\n", num(float64(int(h.TokenExpiry.Sub(now()).Hours()/24))))
	}
}
