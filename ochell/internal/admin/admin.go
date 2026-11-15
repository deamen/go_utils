// Package admin is the local admin channel: a unix socket on which a
// running ochell takes commands from its operator (pause, resume, status,
// reset, stop).
//
// The socket is a file that only ochell's own OS user may open. That is the
// whole access control, and the reason it is not a loopback port: the agent
// runs on the same host and can reach any local port, but with the systemd
// launcher it runs as another user and cannot open this file.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"ochell/internal/agent"
	"ochell/internal/runner"
	"ochell/internal/store"
)

// Control is what the admin channel can do. *runner.Runner implements it.
type Control interface {
	// Pause and Resume hold and release the queue: all of it, or with a
	// tier the tickets of that tier.
	Pause(tier string) error
	Resume(tier string) error
	Status() (runner.Status, error)
	ResetAttempts(source, key string) error
	// Cost reports what one ticket, or with an empty key the last tickets,
	// have cost.
	Cost(source, key string) (*runner.CostReport, error)
	// Outcomes returns the outcome metrics per tier for a period.
	Outcomes(since, until time.Time) ([]store.Outcomes, error)
	// SetTier puts a ticket under another risk tier.
	SetTier(source, key, tier string) error
	// Stop ends the work on a ticket for the operator named in by.
	Stop(source, key, by string) (runner.Stopped, error)
}

// Server serves the admin commands on a unix socket.
type Server struct {
	path string
	ln   net.Listener
	srv  *http.Server
}

// Listen creates the socket at path, replacing one that a previous ochell
// left behind, and makes it accessible to the owner only.
func Listen(path string, c Control, log *slog.Logger) (*Server, error) {
	// A socket file that nothing listens on is left over from a crash. One
	// that answers belongs to another running ochell.
	if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
		conn.Close()
		return nil, fmt.Errorf("admin socket %s is in use: is another ochell running with it?", path)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("admin socket %s: the file exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("admin socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("admin socket: %w", err)
	}
	// Close removes the file itself. Left to the listener, the removal
	// could come late, from the serving goroutine, and hit a file that
	// someone else has put there since.
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	// Connecting needs write permission on the file. The mode it was
	// created with never gives that to other users; this takes the rest.
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("admin socket: %w", err)
	}
	s := &Server{path: path, ln: ln}
	s.srv = &http.Server{
		Handler:           routes(c, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("admin channel stopped", "err", err)
		}
	}()
	return s, nil
}

// Close stops the admin channel and removes the socket.
func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.srv.Shutdown(ctx)
	s.ln.Close()
	os.Remove(s.path)
}

func routes(c Control, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	answer := func(w http.ResponseWriter, code int, msg string) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(code)
		io.WriteString(w, msg+"\n")
	}
	status := func(w http.ResponseWriter, prefix string) {
		st, err := c.Status()
		if err != nil {
			answer(w, http.StatusInternalServerError, err.Error())
			return
		}
		answer(w, http.StatusOK, prefix+describe(st))
	}
	// tierError answers a pause or resume that failed.
	tierError := func(w http.ResponseWriter, tier string, err error) {
		if errors.Is(err, runner.ErrNoTier) {
			answer(w, http.StatusBadRequest, fmt.Sprintf("the policy has no tier %q", tier))
			return
		}
		answer(w, http.StatusInternalServerError, err.Error())
	}
	mux.HandleFunc("POST /pause", func(w http.ResponseWriter, r *http.Request) {
		tier := r.URL.Query().Get("tier")
		if err := c.Pause(tier); err != nil {
			tierError(w, tier, err)
			return
		}
		status(w, "")
	})
	mux.HandleFunc("POST /resume", func(w http.ResponseWriter, r *http.Request) {
		tier := r.URL.Query().Get("tier")
		if err := c.Resume(tier); err != nil {
			tierError(w, tier, err)
			return
		}
		status(w, "")
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("format") == "json" {
			st, err := c.Status()
			if err != nil {
				answer(w, http.StatusInternalServerError, err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(st)
			return
		}
		status(w, "")
	})
	mux.HandleFunc("GET /cost", func(w http.ResponseWriter, r *http.Request) {
		source, key := r.URL.Query().Get("source"), r.URL.Query().Get("key")
		switch rep, err := c.Cost(source, key); {
		case err == nil:
			answer(w, http.StatusOK, strings.TrimRight(costText(rep, key != ""), "\n"))
		case errors.Is(err, store.ErrUnknown):
			answer(w, http.StatusNotFound, fmt.Sprintf("ochell knows no %s ticket %s", source, key))
		default:
			log.Error("admin: cost failed", "err", err)
			answer(w, http.StatusInternalServerError, err.Error())
		}
	})
	mux.HandleFunc("GET /outcomes", func(w http.ResponseWriter, r *http.Request) {
		since, err1 := time.Parse(time.RFC3339, r.URL.Query().Get("since"))
		until, err2 := time.Parse(time.RFC3339, r.URL.Query().Get("until"))
		if err1 != nil || err2 != nil || !until.After(since) {
			answer(w, http.StatusBadRequest, "since and until must be times, with until after since")
			return
		}
		list, err := c.Outcomes(since, until)
		if err != nil {
			log.Error("admin: outcomes failed", "err", err)
			answer(w, http.StatusInternalServerError, err.Error())
			return
		}
		answer(w, http.StatusOK, strings.TrimRight(OutcomesText(list, since, until), "\n"))
	})
	mux.HandleFunc("POST /reset", func(w http.ResponseWriter, r *http.Request) {
		source, key, tier := r.URL.Query().Get("source"), r.URL.Query().Get("key"), r.URL.Query().Get("tier")
		note := ""
		if tier != "" {
			// First, so that a tier that does not exist resets nothing.
			switch err := c.SetTier(source, key, tier); {
			case err == nil:
				note = fmt.Sprintf(" and its tier is now %s", tier)
			case errors.Is(err, runner.ErrNoTier):
				answer(w, http.StatusBadRequest, fmt.Sprintf("the policy has no tier %q; nothing was reset", tier))
				return
			case errors.Is(err, store.ErrUnknown):
				answer(w, http.StatusNotFound, fmt.Sprintf("ochell knows no %s ticket %s", source, key))
				return
			default:
				log.Error("admin: setting the tier failed", "err", err)
				answer(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		switch err := c.ResetAttempts(source, key); {
		case err == nil:
			answer(w, http.StatusOK, fmt.Sprintf("the attempts and the budget of %s %s are reset%s; assign the ticket again, or reply on it, to start it", source, key, note))
		case errors.Is(err, store.ErrUnknown):
			answer(w, http.StatusNotFound, fmt.Sprintf("ochell knows no %s ticket %s", source, key))
		default:
			log.Error("admin: reset failed", "err", err)
			answer(w, http.StatusInternalServerError, err.Error())
		}
	})
	mux.HandleFunc("POST /stop", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		source, key := q.Get("source"), q.Get("key")
		// Who ran the command, as the client says: everyone who can open
		// the socket is ochell's own OS user, so this is a note for the
		// ticket, not a credential.
		by := "an operator"
		if user := strings.TrimSpace(q.Get("user")); user != "" {
			by = "the operator " + user
		}
		by += `, with "ochell stop" on the host`
		switch did, err := c.Stop(source, key, by); {
		case err == nil && did == runner.StoppedRun:
			answer(w, http.StatusOK, fmt.Sprintf("the agent of %s %s is being stopped; the ticket is released and is not started again until it is assigned again", source, key))
		case err == nil && did == runner.StoppedQueued:
			answer(w, http.StatusOK, fmt.Sprintf("the queued run of %s %s was removed; the ticket is released and is not started again until it is assigned again", source, key))
		case err == nil:
			answer(w, http.StatusOK, fmt.Sprintf("%s %s had no run; the ticket is released and is not started again until it is assigned again", source, key))
		case errors.Is(err, store.ErrUnknown):
			answer(w, http.StatusNotFound, fmt.Sprintf("ochell knows no %s ticket %s", source, key))
		case errors.Is(err, store.ErrReleased):
			answer(w, http.StatusConflict, fmt.Sprintf("nothing to stop: %s %s is done or was already released", source, key))
		default:
			log.Error("admin: stop failed", "err", err)
			answer(w, http.StatusInternalServerError, err.Error())
		}
	})
	return mux
}

// costText writes a cost report for the operator: one ticket with its
// runs, or the last tickets.
func costText(rep *runner.CostReport, one bool) string {
	var b strings.Builder
	tokens := func(u agent.Usage) string {
		return fmt.Sprintf("%d\t%d\t%d\t%d", u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheWriteTokens)
	}
	budget := func(t runner.TicketCost) string {
		if t.BudgetUSD <= 0 {
			return "-"
		}
		return fmt.Sprintf("%.4f of %.2f", t.SinceResetUSD, t.BudgetUSD)
	}
	tw := tabwriter.NewWriter(&b, 0, 8, 2, ' ', 0)
	if one && len(rep.Tickets) == 1 {
		t := rep.Tickets[0]
		fmt.Fprintf(&b, "%s %s: tier %s, %s, %d run(s), %.4f USD\n", t.Source, t.Key, t.Tier, t.State, t.Runs, t.CostUSD)
		if t.BudgetUSD > 0 {
			fmt.Fprintf(&b, "budget: %.4f USD of %.2f USD used since the last reset\n", t.SinceResetUSD, t.BudgetUSD)
		} else {
			fmt.Fprintf(&b, "budget: none in the tier %s\n", t.Tier)
		}
		fmt.Fprintln(tw, "RUN\tATTEMPT\tTIER\tOUTCOME\tCOST USD\tINPUT\tOUTPUT\tCACHE READ\tCACHE WRITE")
		for _, r := range rep.Runs {
			outcome := string(r.Outcome)
			if outcome == "" {
				outcome = "running"
			}
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%.4f\t%s\n", r.ID, r.Attempt, r.Tier, outcome, r.CostUSD, tokens(r.Usage))
		}
		fmt.Fprintf(tw, "total\t\t\t\t%.4f\t%s\n", t.CostUSD, tokens(t.Usage))
		tw.Flush()
		return b.String()
	}
	fmt.Fprintf(&b, "all runs: %d run(s), %.4f USD; today (UTC): %d run(s), %.4f USD\n", rep.Total.Runs, rep.Total.CostUSD, rep.Today.Runs, rep.Today.CostUSD)
	if len(rep.Tickets) == 0 {
		return b.String()
	}
	fmt.Fprintln(tw, "TICKET\tTIER\tSTATE\tRUNS\tCOST USD\tBUDGET USD\tINPUT\tOUTPUT\tCACHE READ\tCACHE WRITE")
	for _, t := range rep.Tickets {
		fmt.Fprintf(tw, "%s %s\t%s\t%s\t%d\t%.4f\t%s\t%s\n", t.Source, t.Key, t.Tier, t.State, t.Runs, t.CostUSD, budget(t), tokens(t.Usage))
	}
	tw.Flush()
	return b.String()
}

// Median returns the middle of some durations, 0 for none.
func Median(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	sorted := slices.Clone(d)
	slices.Sort(sorted)
	if n := len(sorted); n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[len(sorted)/2]
}

// share writes a part of a whole as "3 of 4 (75%)", and "-" for no whole.
func share(part, whole int) string {
	if whole == 0 {
		return "-"
	}
	return fmt.Sprintf("%d of %d (%d%%)", part, whole, (100*part+whole/2)/whole)
}

// OutcomesText writes the outcome metrics per tier for the operator.
func OutcomesText(list []store.Outcomes, since, until time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "outcomes per tier, %s to %s (UTC)\n", since.UTC().Format("2006-01-02 15:04"), until.UTC().Format("2006-01-02 15:04"))
	if len(list) == 0 {
		b.WriteString("no run started in this period\n")
		return b.String()
	}
	tw := tabwriter.NewWriter(&b, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "TIER\tTICKETS\tRUNS\tCOST USD\tCOST PER TICKET\tPULL REQUESTS\tTIME TO PR (MEDIAN)\tSENT BACK\tMERGED\tMERGED UNTOUCHED\tREOPENED")
	for _, o := range list {
		tier, per, ttp := o.Tier, "-", "-"
		if tier == "" {
			tier = "(none)"
		}
		if o.Tickets > 0 {
			per = fmt.Sprintf("%.4f", o.CostUSD/float64(o.Tickets))
		}
		if len(o.TimeToPR) > 0 {
			ttp = Median(o.TimeToPR).Round(time.Second).String()
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%.4f\t%s\t%d\t%s\t%s\t%d\t%s\t%d\n", tier, o.Tickets, o.Runs, o.CostUSD, per, o.PullRequests, ttp,
			share(o.Reworked, o.PullRequests), o.Merged, share(o.MergedUntouched, o.Merged), o.Reopened)
	}
	tw.Flush()
	return b.String()
}

// describe is what pause, resume and status answer with: one line
// that says whether runs start and how many are queued and running, and a
// line for everything that holds runs back.
func describe(st runner.Status) string {
	state := "running"
	if st.Paused {
		state = "paused: no new run starts"
	}
	out := fmt.Sprintf("%s; %d queued, %d running", state, st.Queued, st.Running)
	for _, h := range st.Holds {
		out += "\nheld: " + h
	}
	return out
}

// Call sends one command to the ochell that listens on the socket at path
// and returns its answer. A command that the server refuses is an error
// that holds its answer.
func Call(path, method, command string, query url.Values) (string, error) {
	if path == "" {
		return "", errors.New("no admin socket is configured (admin.socket)")
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}
	u := "http://ochell/" + command
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach ochell on %s: is it running, and are you its OS user? (%w)", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	answer := strings.TrimSpace(string(body))
	if resp.StatusCode != http.StatusOK {
		return "", errors.New(answer)
	}
	return answer, nil
}
