// Package admin is the local admin channel: a unix socket on which a
// running ochell takes commands from its operator (pause, resume, status,
// reset, stop).
//
// The socket is a file that only ochell's own OS user may open. That is the
// whole access control, and the reason it is not a loopback port, which
// every local user can reach.
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
	"strings"
	"text/tabwriter"
	"time"

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
	// Outcomes returns the outcome metrics per tier for a period.
	Outcomes(since, until time.Time) ([]store.Outcomes, error)
	// Backup writes a consistent copy of the store: to the file dest, or
	// with an empty dest to the configured backup directory. It returns
	// the path of the copy.
	Backup(dest string) (string, error)
	// SetTier puts a ticket under another risk tier.
	SetTier(source, key, tier string) error
	// Stop ends the work on a ticket for the operator named in by.
	Stop(source, key, by string) (runner.Stopped, error)
	// Autonomy returns the classes of work with their level of autonomy
	// and their numbers, and the last changes of levels.
	Autonomy() ([]runner.Class, []store.LevelChange, error)
	// Promote and Demote move the class of a tier one level up or down,
	// for the operator named in by.
	Promote(tier, by, reason string) (store.LevelChange, error)
	Demote(tier, by, reason string) (store.LevelChange, error)
	// Flag records that a guardrail outside ochell flagged the work on a
	// ticket, and lowers the class of the ticket by one level.
	Flag(source, key, by, reason string) (store.LevelChange, error)
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
	mux.HandleFunc("POST /backup", func(w http.ResponseWriter, r *http.Request) {
		switch path, err := c.Backup(r.URL.Query().Get("to")); {
		case err == nil:
			answer(w, http.StatusOK, "the store is backed up to "+path)
		case errors.Is(err, runner.ErrNoBackupDir):
			answer(w, http.StatusBadRequest, "no backup directory is configured (backup.dir); name a file with --to")
		default:
			log.Error("admin: backup failed", "err", err)
			answer(w, http.StatusInternalServerError, err.Error())
		}
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
			answer(w, http.StatusOK, fmt.Sprintf("the attempts of %s %s are reset%s; assign the ticket again, or reply on it, to start it", source, key, note))
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
	// operator names who ran a command, as the client says: everyone who
	// can open the socket is ochell's own OS user, so this is a note for
	// the record, not a credential.
	operator := func(r *http.Request) string {
		if user := strings.TrimSpace(r.URL.Query().Get("user")); user != "" {
			return "the operator " + user
		}
		return "an operator"
	}
	// levelError answers a change of a level that was refused.
	levelError := func(w http.ResponseWriter, what string, err error) {
		switch {
		case errors.Is(err, runner.ErrNoLevels):
			answer(w, http.StatusBadRequest, "the policy file has no autonomy section (autonomy.start_level): there are no levels")
		case errors.Is(err, runner.ErrNoTier), errors.Is(err, runner.ErrTopLevel), errors.Is(err, runner.ErrLowestLevel):
			answer(w, http.StatusBadRequest, "nothing was changed: "+err.Error())
		default:
			log.Error("admin: "+what+" failed", "err", err)
			answer(w, http.StatusInternalServerError, err.Error())
		}
	}
	mux.HandleFunc("GET /autonomy", func(w http.ResponseWriter, r *http.Request) {
		classes, changes, err := c.Autonomy()
		if err != nil {
			levelError(w, "autonomy", err)
			return
		}
		answer(w, http.StatusOK, strings.TrimRight(AutonomyText(classes, changes), "\n"))
	})
	for _, cmd := range []string{"promote", "demote"} {
		mux.HandleFunc("POST /"+cmd, func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			step := c.Promote
			if cmd == "demote" {
				step = c.Demote
			}
			ch, err := step(q.Get("tier"), operator(r), reason(q.Get("reason")))
			if err != nil {
				levelError(w, cmd, err)
				return
			}
			answer(w, http.StatusOK, fmt.Sprintf("the tier %s is now at the level %s (it was at %s); this holds for the runs that start from now on\nrecorded: by %s, with %s",
				ch.Class, ch.To, ch.From, ch.By, recordText(ch.Record)))
		})
	}
	mux.HandleFunc("POST /flag", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		source, key, why := q.Get("source"), q.Get("key"), reason(q.Get("reason"))
		if why == "" {
			answer(w, http.StatusBadRequest, "a flag needs a reason: what the guardrail found")
			return
		}
		switch ch, err := c.Flag(source, key, operator(r), why); {
		case err == nil && ch.From == ch.To:
			answer(w, http.StatusOK, fmt.Sprintf("the flag on %s %s is recorded; its tier %s is at the lowest level already (%s)", source, key, ch.Class, ch.To))
		case err == nil:
			answer(w, http.StatusOK, fmt.Sprintf("the flag on %s %s is recorded; its tier %s is now at the level %s (it was at %s), for the runs that start from now on", source, key, ch.Class, ch.To, ch.From))
		case errors.Is(err, store.ErrUnknown):
			answer(w, http.StatusNotFound, fmt.Sprintf("ochell knows no %s ticket %s", source, key))
		default:
			levelError(w, "flag", err)
		}
	})
	return mux
}

// maxReason is how much of the reason of a change of a level is kept.
const maxReason = 500

// reason is the reason of a change of a level as it is recorded: one line
// of a bounded length.
func reason(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxReason {
		s = strings.ToValidUTF8(s[:maxReason], "") + " […]"
	}
	return s
}

// recordText writes the numbers of a class for the operator.
func recordText(r store.Record) string {
	return fmt.Sprintf("%d ticket(s) with a pull request since %s, sent back: %s, merged untouched: %s",
		r.PullRequests, r.Since.UTC().Format("2006-01-02 15:04"), share(r.SentBack, r.PullRequests), share(r.MergedUntouched, r.Merged))
}

// AutonomyText writes the classes of work with their levels, and the last
// changes of levels, for the operator.
func AutonomyText(classes []runner.Class, changes []store.LevelChange) string {
	var b strings.Builder
	when := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") }
	b.WriteString("levels of autonomy per tier (times in UTC); the numbers are of the tickets under the present level\n")
	tw := tabwriter.NewWriter(&b, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "TIER\tLEVEL\tSINCE\tBY\tPULL REQUESTS\tSENT BACK\tMERGED\tMERGED UNTOUCHED")
	for _, c := range classes {
		since, by := "-", "the policy file (start_level)"
		if c.Since != nil {
			since, by = when(*c.Since), c.By
		}
		var r store.Record
		if c.Record != nil {
			r = *c.Record
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%d\t%s\n", c.Tier, c.Level, since, by, r.PullRequests, share(r.SentBack, r.PullRequests), r.Merged, share(r.MergedUntouched, r.Merged))
	}
	tw.Flush()
	if len(changes) == 0 {
		b.WriteString("no level was changed yet\n")
		return b.String()
	}
	b.WriteString("last changes, the newest first:\n")
	for _, ch := range changes {
		what := ch.From + " -> " + ch.To
		if ch.From == ch.To {
			what = "stays at " + ch.To
		}
		fmt.Fprintf(&b, "%s  %s: %s, by %s", when(ch.At), ch.Class, what, ch.By)
		if ch.Key != "" {
			fmt.Fprintf(&b, "; flagged: %s %s", ch.Source, ch.Key)
			if ch.Run != "" {
				fmt.Fprintf(&b, ", run %s", ch.Run)
			}
		}
		if ch.Reason != "" {
			fmt.Fprintf(&b, "; %s", ch.Reason)
		}
		fmt.Fprintf(&b, " [%s]\n", recordText(ch.Record))
	}
	return b.String()
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
	fmt.Fprintln(tw, "TIER\tTICKETS\tRUNS\tPULL REQUESTS\tTIME TO PR (MEDIAN)\tSENT BACK\tMERGED\tMERGED UNTOUCHED\tREOPENED")
	for _, o := range list {
		tier, ttp := o.Tier, "-"
		if tier == "" {
			tier = "(none)"
		}
		if len(o.TimeToPR) > 0 {
			ttp = store.Median(o.TimeToPR).Round(time.Second).String()
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\t%s\t%d\t%s\t%d\n", tier, o.Tickets, o.Runs, o.PullRequests, ttp,
			share(o.Reworked, o.PullRequests), o.Merged, share(o.MergedUntouched, o.Merged), o.Reopened)
	}
	tw.Flush()
	return b.String()
}

// describe is what pause, resume and status answer with: one line
// that says whether runs start and how many are queued and running, a
// line for everything that holds runs back, a line for the level of
// autonomy of each tier, and a line for everything in a repository's
// WORKFLOW.md that is not in force.
func describe(st runner.Status) string {
	state := "running"
	if st.Paused {
		state = "paused: no new run starts"
	}
	out := fmt.Sprintf("%s; %d queued, %d running", state, st.Queued, st.Running)
	for _, h := range st.Holds {
		out += "\nheld: " + h
	}
	for _, c := range st.Autonomy {
		line := fmt.Sprintf("\nautonomy: the tier %s is at the level %s", c.Tier, c.Level)
		if c.Since != nil {
			line += fmt.Sprintf(" since %s, by %s", c.Since.UTC().Format("2006-01-02 15:04 UTC"), c.By)
		}
		out += line
	}
	// What of a repository's WORKFLOW.md is not in force.
	for _, w := range st.Workflows {
		if w.Error != "" {
			out += "\nworkflow " + w.Repo + ": " + w.Error
		}
		for _, line := range w.Ignored {
			out += "\nworkflow " + w.Repo + ": " + line
		}
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
