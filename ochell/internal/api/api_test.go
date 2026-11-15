package api

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ochell/internal/config"
	"ochell/internal/runner"
	"ochell/internal/store"
	"ochell/internal/ticket"
)

type fakeStore struct{ tickets []store.Ticket }

func (f fakeStore) Tickets(limit int, states ...ticket.State) ([]store.Ticket, error) {
	var out []store.Ticket
	for _, t := range f.tickets {
		if len(states) == 0 || t.State == states[0] {
			out = append(out, t)
		}
	}
	return out, nil
}

func (f fakeStore) TicketsByKey(key string) ([]store.Ticket, error) {
	var out []store.Ticket
	for _, t := range f.tickets {
		if t.Key == key {
			out = append(out, t)
		}
	}
	return out, nil
}

func (fakeStore) Runs(source, key string) ([]store.RunInfo, error) {
	r := store.RunInfo{Received: time.Unix(1, 0)}
	r.ID, r.Status, r.Attempt = "run-1", "ended", 1
	r.Result.SignalMessage = "<script>alert(1)</script> " + strings.Repeat("x", maxText)
	return []store.RunInfo{r}, nil
}

type fakeRunner struct{}

func (fakeRunner) Status() (runner.Status, error) {
	return runner.Status{Holds: []string{"tier high is paused by a command"}}, nil
}

func newAPI(cfg config.API) *API {
	st := fakeStore{tickets: []store.Ticket{
		{Source: "jira", Key: "DEV-1", Title: "A <b>title</b>", State: ticket.Waiting, Reason: ticket.ReasonInput},
		{Source: "linear", Key: "DEV-1", Title: "Same key, other tracker", State: ticket.Running},
	}}
	return New(cfg, st, fakeRunner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func get(a *API, target, token, accept string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", target, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func TestTokenAndSignedLink(t *testing.T) {
	const token = "0123456789abcdef"
	a := newAPI(config.API{Enabled: true, Token: token, PublicURL: "https://ochell.example.com/"})
	if w := get(a, "/api/v1/state", token, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"tier high is paused by a command"`) || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("state with the token: %d %s", w.Code, w.Body)
	}
	for _, bad := range []string{"", "0123456789abcdeX", token + "x"} {
		if w := get(a, "/api/v1/state", bad, ""); w.Code != 401 {
			t.Errorf("state with the token %q: %d", bad, w.Code)
		}
	}
	// A key that both trackers have gives both tickets; a source narrows it.
	if w := get(a, "/api/v1/tasks/DEV-1", token, ""); w.Code != 200 || strings.Count(w.Body.String(), `"key": "DEV-1"`) != 2 {
		t.Errorf("a key of two trackers: %d %s", w.Code, w.Body)
	}

	link := a.Link("jira", "DEV-1")
	if !strings.HasPrefix(link, "https://ochell.example.com/api/v1/tasks/DEV-1?") || strings.Contains(link, token) {
		t.Fatalf("link = %q", link)
	}
	path := strings.TrimPrefix(link, "https://ochell.example.com")
	w := get(a, path, "", "text/html")
	if w.Code != 200 || strings.Contains(w.Body.String(), "Same key, other tracker") {
		t.Fatalf("the signed link: %d %s", w.Code, w.Body)
	}
	// What a ticket and an agent say is text on the page, never markup.
	if body := w.Body.String(); strings.Contains(body, "<script>") || strings.Contains(body, "<b>title</b>") || !strings.Contains(body, "&lt;script&gt;") || !strings.Contains(body, "[…]") {
		t.Errorf("the page does not escape or cut what it shows:\n%s", body)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("the page has no content security policy")
	}
	// The signature is for one ticket of one source.
	for _, other := range []string{strings.Replace(path, "source=jira", "source=linear", 1), strings.Replace(path, "DEV-1", "DEV-2", 1), strings.Replace(path, "sig=", "sig=0", 1), "/api/v1/tasks/DEV-1?source=jira"} {
		if w := get(a, other, "", ""); w.Code != 401 {
			t.Errorf("%s: %d, want 401", other, w.Code)
		}
	}
	// Another token signs another link.
	b := newAPI(config.API{Enabled: true, Token: "fedcba9876543210", PublicURL: "https://ochell.example.com"})
	if b.Link("jira", "DEV-1") == link {
		t.Error("the link does not depend on the token")
	}
	// Without a public address there is no link.
	if got := newAPI(config.API{Enabled: true, Token: token}).Link("jira", "DEV-1"); got != "" {
		t.Errorf("link without public_url = %q", got)
	}
}

// Every reason a ticket can wait for has a line that says what to do.
func TestEveryReasonIsExplained(t *testing.T) {
	for _, r := range []ticket.Reason{ticket.ReasonInput, ticket.ReasonPlanApproval, ticket.ReasonBlocked, ticket.ReasonStalled,
		ticket.ReasonNoResult, ticket.ReasonNoRepoMapping, ticket.ReasonEscalation, ticket.ReasonInterrupted} {
		if reasons[r] == "" {
			t.Errorf("the inbox has no text for the reason %s", r)
		}
		if err := ticket.Move(ticket.Running, ticket.Waiting, r); err != nil {
			t.Errorf("%s is not a reason of the state machine: %v", r, err)
		}
	}
}

func TestInbox(t *testing.T) {
	const token = "0123456789abcdef"
	a := newAPI(config.API{Enabled: true, Token: token})
	if w := get(a, "/api/v1/inbox", "", ""); w.Code != 401 {
		t.Errorf("the inbox without the token: %d", w.Code)
	}
	w := get(a, "/api/v1/inbox", token, "")
	// Only the waiting ticket, not the running one with the same key.
	if body := w.Body.String(); w.Code != 200 || strings.Count(body, `"key": "DEV-1"`) != 1 || !strings.Contains(body, `"reason": "input"`) ||
		!strings.Contains(body, `"why": "The agent asked a question. Answer it on the ticket."`) || !strings.Contains(body, `"entry": "/api/v1/tasks/DEV-1?source=jira"`) {
		t.Errorf("inbox: %d %s", w.Code, body)
	}
	if w := get(a, "/api/v1/inbox", token, "text/html"); w.Code != 200 || !strings.Contains(w.Body.String(), "<b>input</b>") || strings.Contains(w.Body.String(), "<script>") {
		t.Errorf("inbox page: %d %s", w.Code, w.Body)
	}
	empty := New(config.API{Enabled: true, Token: token}, fakeStore{}, fakeRunner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if w := get(empty, "/api/v1/inbox", token, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"items": []`) {
		t.Errorf("an empty inbox: %d %s", w.Code, w.Body)
	}
}
