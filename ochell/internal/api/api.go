// Package api is the status API: read-only pages about what ochell is
// doing, for the people who look after it and for the people on a ticket.
//
//	GET /api/v1/state         what is queued, running and waiting
//	GET /api/v1/tasks/<key>   one ticket with its runs
//	GET /api/v1/inbox         the tickets that wait for a person, and why
//
// A request gets JSON, or a plain HTML page when it asks for one (a
// browser). Every request needs the API token, as "Authorization: Bearer".
// The exception is the entry of one ticket, which can also be opened with
// a link that ochell signed for that ticket alone: that is the link in the
// ticket's Linear session, which a person opens in a browser.
package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ochell/internal/config"
	"ochell/internal/runner"
	"ochell/internal/store"
	"ochell/internal/ticket"
)

// Prefix is the path under which the API is served.
const Prefix = "/api/v1/"

// maxListed is how many tickets one list of a page holds.
const maxListed = 200

// maxText is how much of a message of an agent is shown.
const maxText = 4000

// Store is what the API reads. *store.Store implements it.
type Store interface {
	Tickets(limit int, states ...ticket.State) ([]store.Ticket, error)
	TicketsByKey(key string) ([]store.Ticket, error)
	Runs(source, key string) ([]store.RunInfo, error)
}

// Runner tells what ochell is doing right now. *runner.Runner implements
// it.
type Runner interface {
	Status() (runner.Status, error)
}

// API serves the status pages.
type API struct {
	cfg    config.API
	store  Store
	runner Runner
	log    *slog.Logger
	mux    *http.ServeMux
}

// New returns the API for the given settings. The caller mounts it under
// Prefix.
func New(cfg config.API, st Store, r Runner, log *slog.Logger) *API {
	a := &API{cfg: cfg, store: st, runner: r, log: log, mux: http.NewServeMux()}
	a.mux.HandleFunc("GET "+Prefix+"state", a.authed(a.state))
	a.mux.HandleFunc("GET "+Prefix+"tasks/{key}", a.task)
	a.mux.HandleFunc("GET "+Prefix+"inbox", a.authed(a.inbox))
	return a
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// What these pages show changes all the time and is not for a cache.
	w.Header().Set("Cache-Control", "no-store")
	a.mux.ServeHTTP(w, r)
}

// hasToken reports whether the request carries the API token.
func (a *API) hasToken(r *http.Request) bool {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && a.cfg.Token != "" && subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), []byte(a.cfg.Token)) == 1
}

func (a *API) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.hasToken(r) {
			a.refuse(w, r)
			return
		}
		h(w, r)
	}
}

func (a *API) refuse(w http.ResponseWriter, r *http.Request) {
	a.log.Warn("status API: request without a valid token", "path", r.URL.Path, "remote", r.RemoteAddr)
	w.Header().Set("WWW-Authenticate", `Bearer realm="ochell"`)
	http.Error(w, "the status API needs its token: Authorization: Bearer <api.token>", http.StatusUnauthorized)
}

// sign returns the signature of the link to one ticket's entry. It is
// made with the API token, and opens that entry and nothing else.
func (a *API) sign(source, key string) string {
	mac := hmac.New(sha256.New, []byte(a.cfg.Token))
	mac.Write([]byte("ochell ticket entry\n" + source + "\n" + key))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// Link returns the address of a ticket's entry for a person: with
// api.public_url, a link that opens in a browser without the token.
// Without it there is no such link, and the answer is "".
func (a *API) Link(source, key string) string {
	if a.cfg.PublicURL == "" {
		return ""
	}
	q := url.Values{"source": {source}, "sig": {a.sign(source, key)}}
	return strings.TrimRight(a.cfg.PublicURL, "/") + Prefix + "tasks/" + url.PathEscape(key) + "?" + q.Encode()
}

// Ticket is one ticket as the API shows it.
type Ticket struct {
	Source string `json:"source"`
	Key    string `json:"key"`
	Title  string `json:"title"`
	URL    string `json:"url,omitempty"`
	State  string `json:"state"`
	// Reason says what a waiting ticket waits for.
	Reason   string `json:"reason,omitempty"`
	Tier     string `json:"tier,omitempty"`
	Repo     string `json:"repo,omitempty"`
	Attempts int    `json:"attempts"`
	// PullRequest and Branch are the last ones that a run of the ticket
	// named.
	PullRequest string    `json:"pull_request,omitempty"`
	Branch      string    `json:"branch,omitempty"`
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
	// Runs are set in the entry of one ticket.
	Runs []Run `json:"runs,omitempty"`
}

// Run is one run of a ticket as the API shows it.
type Run struct {
	ID      string `json:"id"`
	Attempt int    `json:"attempt,omitempty"`
	// Status is queued, running or ended.
	Status string `json:"status"`
	// Cause says why the run was queued; empty for a plain assignment.
	Cause    string     `json:"cause,omitempty"`
	Phase    string     `json:"phase,omitempty"`
	Tier     string     `json:"tier,omitempty"`
	Received time.Time  `json:"received"`
	Started  *time.Time `json:"started,omitempty"`
	Ended    *time.Time `json:"ended,omitempty"`
	// Outcome, Result and what follows are set when the run has ended.
	Outcome    string `json:"outcome,omitempty"`
	Result     string `json:"result,omitempty"`
	Escalation string `json:"escalation,omitempty"`
	Error      string `json:"error,omitempty"`
	// Message is what the agent said for the people on the ticket.
	Message string  `json:"message,omitempty"`
	CostUSD float64 `json:"cost_usd,omitempty"`
}

func ticketOf(t store.Ticket) Ticket {
	return Ticket{
		Source: t.Source, Key: t.Key, Title: t.Title, URL: t.URL, State: string(t.State), Reason: string(t.Reason),
		Tier: t.Tier, Repo: t.Repo, Attempts: t.Attempts, PullRequest: t.PRURL, Branch: t.Branch, Created: t.Created, Updated: t.Updated,
	}
}

func cut(s string) string {
	if len(s) <= maxText {
		return s
	}
	return strings.ToValidUTF8(s[:maxText], "") + " […]"
}

func runOf(r store.RunInfo) Run {
	out := Run{
		ID: r.ID, Attempt: r.Attempt, Status: r.Status, Cause: string(r.Cause), Phase: string(r.Result.Phase), Tier: r.Tier,
		Received: r.Received, Outcome: string(r.Result.Outcome), Result: string(r.Result.Signal), Escalation: string(r.Result.Escalation),
		CostUSD: r.Result.CostUSD,
	}
	if !r.Started.IsZero() {
		out.Started = &r.Started
	}
	if !r.Ended.IsZero() {
		out.Ended = &r.Ended
	}
	if r.Result.Err != nil {
		out.Error = r.Result.Err.Error()
	}
	out.Message = cut(r.Result.SignalMessage)
	if out.Message == "" {
		out.Message = cut(r.Result.Message)
	}
	return out
}

// State is the answer of /api/v1/state.
type State struct {
	// Paused says that no run starts, and Holds what else keeps runs
	// back.
	Paused bool     `json:"paused"`
	Holds  []string `json:"holds,omitempty"`
	// Counts are the number of tickets in each state.
	Counts  map[string]int `json:"counts"`
	Running []Ticket       `json:"running"`
	Queued  []Ticket       `json:"queued"`
	// Waiting are the tickets that wait for a person, each with its
	// reason.
	Waiting []Ticket `json:"waiting"`
}

func (a *API) tickets(states ...ticket.State) ([]Ticket, error) {
	list, err := a.store.Tickets(maxListed, states...)
	if err != nil {
		return nil, err
	}
	out := make([]Ticket, 0, len(list))
	for _, t := range list {
		out = append(out, ticketOf(t))
	}
	return out, nil
}

func (a *API) state(w http.ResponseWriter, r *http.Request) {
	st, err := a.runner.Status()
	if err != nil {
		a.fail(w, err)
		return
	}
	out := State{Paused: st.Paused, Holds: st.Holds, Counts: map[string]int{}}
	all, err := a.store.Tickets(0)
	if err != nil {
		a.fail(w, err)
		return
	}
	for _, t := range all {
		out.Counts[string(t.State)]++
	}
	if out.Running, err = a.tickets(ticket.Running); err == nil {
		if out.Queued, err = a.tickets(ticket.Queued); err == nil {
			out.Waiting, err = a.tickets(ticket.Waiting)
		}
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	a.answer(w, r, statePage, out)
}

func (a *API) task(w http.ResponseWriter, r *http.Request) {
	key, source := r.PathValue("key"), r.URL.Query().Get("source")
	// The token, or the signature of the link to this one ticket.
	if !a.hasToken(r) {
		sig := r.URL.Query().Get("sig")
		if sig == "" || source == "" || subtle.ConstantTimeCompare([]byte(sig), []byte(a.sign(source, key))) != 1 {
			a.refuse(w, r)
			return
		}
	}
	list, err := a.store.TicketsByKey(key)
	if err != nil {
		a.fail(w, err)
		return
	}
	var out []Ticket
	for _, t := range list {
		if source != "" && t.Source != source {
			continue
		}
		runs, err := a.store.Runs(t.Source, t.Key)
		if err != nil {
			a.fail(w, err)
			return
		}
		tk := ticketOf(t)
		for _, run := range runs {
			tk.Runs = append(tk.Runs, runOf(run))
		}
		out = append(out, tk)
	}
	if len(out) == 0 {
		http.Error(w, "ochell knows no ticket "+key, http.StatusNotFound)
		return
	}
	// A key is one ticket, unless Jira and Linear both have it.
	a.answer(w, r, taskPage, struct {
		Tickets []Ticket `json:"tickets"`
	}{out})
}

// reasons says, for each reason a ticket can wait for, what a person is
// asked to do.
var reasons = map[ticket.Reason]string{
	ticket.ReasonInput:         "The agent asked a question. Answer it on the ticket.",
	ticket.ReasonPlanApproval:  "The agent's plan waits for an approval: /approve on the ticket, or say what to change.",
	ticket.ReasonBlocked:       "The agent is blocked by something outside the ticket. Remove the obstacle, then reply on the ticket.",
	ticket.ReasonStalled:       "The agent stopped producing output and was stopped, and the ticket has no attempt left. Look at the run log, then reply on the ticket.",
	ticket.ReasonNoResult:      "The run ended without saying how. Look at what it did, then reply on the ticket.",
	ticket.ReasonNoRepoMapping: "No repository is configured for the ticket. Add one to repos, then assign the ticket again.",
	ticket.ReasonEscalation:    "A limit or the agent itself stopped the work. Decide whether it goes on: reply on the ticket, change it, or stop it.",
	ticket.ReasonInterrupted:   "ochell stopped during the run and the ticket has no attempt left. Reply on the ticket to let it go on.",
}

// Item is one entry of the inbox: a ticket that waits for a person.
type Item struct {
	Ticket
	// Why says what the reason means and what a person is asked to do.
	Why string `json:"why"`
	// Since is when the ticket began to wait.
	Since time.Time `json:"since"`
	// Message is what the agent said last for the people on the ticket:
	// its question, its plan, or why it stopped.
	Message string `json:"message,omitempty"`
	// Entry is the address of the ticket's entry in this API.
	Entry string `json:"entry"`
}

// Inbox is the answer of /api/v1/inbox.
type Inbox struct {
	// Items are the tickets that wait for a person, the one that has
	// waited longest first.
	Items []Item `json:"items"`
}

// inbox lists exactly the tickets that wait for a person: the ones in the
// state "waiting", each with its reason. A ticket in any other state is
// not here: one in review is in the review queue of its pull request, and
// a failed one is in the state page.
func (a *API) inbox(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.Tickets(maxListed, ticket.Waiting)
	if err != nil {
		a.fail(w, err)
		return
	}
	out := Inbox{Items: []Item{}}
	// The store gives the ticket that changed last first; the inbox starts
	// with the one that has waited longest.
	for i := len(list) - 1; i >= 0; i-- {
		t := list[i]
		item := Item{Ticket: ticketOf(t), Why: reasons[t.Reason], Since: t.Updated,
			Entry: Prefix + "tasks/" + url.PathEscape(t.Key) + "?source=" + url.QueryEscape(t.Source)}
		runs, err := a.store.Runs(t.Source, t.Key)
		if err != nil {
			a.fail(w, err)
			return
		}
		for j := len(runs) - 1; j >= 0 && item.Message == ""; j-- {
			if runs[j].Status == "ended" {
				item.Message = runOf(runs[j]).Message
			}
		}
		out.Items = append(out.Items, item)
	}
	a.answer(w, r, inboxPage, out)
}

func (a *API) fail(w http.ResponseWriter, err error) {
	a.log.Error("status API: cannot read the store", "err", err)
	http.Error(w, "cannot read the state", http.StatusInternalServerError)
}

// answer writes v as an HTML page for a browser, and as JSON otherwise.
func (a *API) answer(w http.ResponseWriter, r *http.Request, page *template.Template, v any) {
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Nothing on the page comes from anywhere but ochell.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		if err := page.Execute(w, v); err != nil {
			a.log.Error("status API: cannot write the page", "err", err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		a.log.Error("status API: cannot write the answer", "err", err)
	}
}

var funcs = template.FuncMap{
	"when": func(t any) string {
		switch v := t.(type) {
		case time.Time:
			return v.UTC().Format("2006-01-02 15:04 UTC")
		case *time.Time:
			if v != nil {
				return v.UTC().Format("2006-01-02 15:04 UTC")
			}
		}
		return ""
	},
	"usd": func(v float64) string {
		if v == 0 {
			return ""
		}
		return fmt.Sprintf("%.4f", v)
	},
}

const style = `<style>
body { font: 15px/1.45 system-ui, sans-serif; margin: 2rem auto; max-width: 70rem; padding: 0 1rem; color: #1b1b1b; }
h1 { font-size: 1.4rem; } h2 { font-size: 1.1rem; margin-top: 2rem; }
table { border-collapse: collapse; width: 100%; } th, td { text-align: left; padding: .3rem .6rem; border-bottom: 1px solid #ddd; vertical-align: top; }
th { font-weight: 600; } .dim { color: #666; } pre { white-space: pre-wrap; margin: 0; font: inherit; }
</style>`

const ticketRows = `{{define "tickets"}}{{if .}}<table><tr><th>Ticket</th><th>Title</th><th>State</th><th>Tier</th><th>Attempts</th><th>Changed</th></tr>
{{range .}}<tr><td>{{.Source}} {{.Key}}</td><td>{{.Title}}</td><td>{{.State}}{{if .Reason}} ({{.Reason}}){{end}}</td><td>{{.Tier}}</td><td>{{.Attempts}}</td><td>{{when .Updated}}</td></tr>
{{end}}</table>{{else}}<p class="dim">None.</p>{{end}}{{end}}`

var statePage = template.Must(template.New("state").Funcs(funcs).Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ochell: state</title>` + style + `</head><body>
<h1>ochell</h1>
<p>{{if .Paused}}Paused: no new run starts.{{else}}Runs start.{{end}}{{range .Holds}}<br>Held: {{.}}{{end}}</p>
<p class="dim">{{range $state, $n := .Counts}}{{$state}}: {{$n}} &nbsp; {{end}}</p>
<h2>Waiting for a person</h2>{{template "tickets" .Waiting}}
<h2>Running</h2>{{template "tickets" .Running}}
<h2>Queued</h2>{{template "tickets" .Queued}}
</body></html>` + ticketRows))

var taskPage = template.Must(template.New("task").Funcs(funcs).Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ochell: ticket</title>` + style + `</head><body>
{{range .Tickets}}<h1>{{.Source}} {{.Key}}: {{.Title}}</h1>
<p>State: <b>{{.State}}</b>{{if .Reason}} ({{.Reason}}){{end}}{{if .Tier}} &nbsp; Tier: {{.Tier}}{{end}} &nbsp; Attempts: {{.Attempts}} &nbsp; Changed: {{when .Updated}}</p>
<p class="dim">{{if .Repo}}Repository: {{.Repo}}<br>{{end}}{{if .Branch}}Branch: {{.Branch}}<br>{{end}}{{if .PullRequest}}Pull request: {{.PullRequest}}<br>{{end}}{{if .URL}}Ticket: {{.URL}}{{end}}</p>
<h2>Runs</h2>
{{if .Runs}}<table><tr><th>#</th><th>Started</th><th>Ended</th><th>Status</th><th>Why</th><th>Outcome</th><th>Cost USD</th><th>What the agent said</th></tr>
{{range .Runs}}<tr><td>{{.Attempt}}</td><td>{{when .Started}}</td><td>{{when .Ended}}</td><td>{{.Status}}</td><td>{{.Cause}}{{if .Phase}} {{.Phase}}{{end}}</td>
<td>{{.Outcome}}{{if .Result}} / {{.Result}}{{end}}{{if .Escalation}} / escalation: {{.Escalation}}{{end}}{{if .Error}}<br><span class="dim">{{.Error}}</span>{{end}}</td><td>{{usd .CostUSD}}</td><td><pre>{{.Message}}</pre></td></tr>
{{end}}</table>{{else}}<p class="dim">No run yet.</p>{{end}}
{{end}}</body></html>`))

var inboxPage = template.Must(template.New("inbox").Funcs(funcs).Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ochell: inbox</title>` + style + `</head><body>
<h1>Waiting for a person</h1>
{{if .Items}}<table><tr><th>Ticket</th><th>Reason</th><th>Since</th><th>What the agent said</th></tr>
{{range .Items}}<tr><td>{{.Source}} {{.Key}}<br>{{.Title}}{{if .URL}}<br><span class="dim">{{.URL}}</span>{{end}}</td>
<td><b>{{.Reason}}</b><br>{{.Why}}</td><td>{{when .Since}}</td><td><pre>{{.Message}}</pre></td></tr>
{{end}}</table>{{else}}<p class="dim">Nothing waits for a person.</p>{{end}}
</body></html>`))
