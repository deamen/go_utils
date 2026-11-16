package jiraapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"ochell/internal/config"
	"ochell/internal/tracker"
	"ochell/internal/tracker/jiraapi/jiratest"
)

func client(site *jiratest.Server) *Client {
	return New(config.JiraAPI{BaseURL: site.URL + "/", Email: jiratest.Email, Token: jiratest.Token})
}

func TestAssigned(t *testing.T) {
	site := jiratest.New(t)
	for _, is := range []jiratest.Issue{
		{Key: "DEV-1", Summary: "First", Labels: []string{"frontend"}, Components: []string{"web"}},
		{Key: "DEV-2", Summary: "Second"},
		{Key: "DEV-3", Summary: "Third"},
		{Key: "OPS-7", Summary: "Fourth"},
		{Key: "OPS-8", Summary: "Fifth"},
	} {
		site.Add(is)
	}
	c := client(site)
	got, err := c.Assigned(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Five tickets in pages of two: every page was read.
	var keys []string
	for _, is := range got {
		keys = append(keys, is.Key)
	}
	if want := []string{"DEV-1", "DEV-2", "DEV-3", "OPS-7", "OPS-8"}; !slices.Equal(keys, want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
	first := got[0]
	if first.Title != "First" || first.URL != site.URL+"/browse/DEV-1" || !slices.Equal(first.Labels, []string{"frontend", "web"}) {
		t.Errorf("first ticket = %+v", first)
	}
	if jql := site.Searches(); len(jql) != 3 || jql[0] != DefaultJQL {
		t.Errorf("searches = %q, want three pages with the default JQL", jql)
	}

	// A configured JQL replaces the default.
	c = New(config.JiraAPI{BaseURL: site.URL, Email: jiratest.Email, Token: jiratest.Token, JQL: "project = DEV"})
	if _, err := c.Assigned(context.Background()); err != nil {
		t.Fatal(err)
	}
	if jql := site.Searches(); jql[len(jql)-1] != "project = DEV" {
		t.Errorf("last search = %q", jql[len(jql)-1])
	}
}

// A search that fails on a later page gives an error, never a part of the
// list: a ticket that is missing from the list counts as unassigned.
func TestAssignedIsAllOrNothing(t *testing.T) {
	site := jiratest.New(t)
	for _, k := range []string{"DEV-1", "DEV-2", "DEV-3"} {
		site.Add(jiratest.Issue{Key: k})
	}
	c := client(site)
	pages := 0
	c.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if pages++; pages == 2 {
			site.Fail(http.StatusServiceUnavailable)
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	got, err := c.Assigned(context.Background())
	if err == nil || got != nil {
		t.Fatalf("Assigned = %v, %v; want an error and no tickets", got, err)
	}
	if !strings.Contains(err.Error(), "HTTP 503") {
		t.Errorf("error = %v, want the HTTP status", err)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestComment(t *testing.T) {
	site := jiratest.New(t)
	site.Add(jiratest.Issue{Key: "DEV-1"})
	c := client(site)
	ctx := context.Background()
	if err := c.Comment(ctx, "DEV-1", "The digital employee started work."); err != nil {
		t.Fatal(err)
	}
	if got := site.Comments("DEV-1"); !slices.Equal(got, []string{"The digital employee started work."}) {
		t.Errorf("comments = %q", got)
	}
	if err := c.Comment(ctx, "DEV-404", "x"); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("comment on an unknown ticket: %v, want HTTP 404", err)
	}
	// A key that is not a key never reaches the URL.
	if err := c.Comment(ctx, "../../myself", "x"); err == nil || !strings.Contains(err.Error(), "not a ticket key") {
		t.Errorf("comment with a bad key: %v", err)
	}
}

func TestSetStatus(t *testing.T) {
	site := jiratest.New(t)
	site.Add(jiratest.Issue{Key: "DEV-1", Status: "In Progress", Statuses: []string{"To Do", "In Review"}})
	c := client(site)
	ctx := context.Background()
	if err := c.SetStatus(ctx, "DEV-1", "in review"); err != nil {
		t.Fatal(err)
	}
	if got := site.Status("DEV-1"); got != "In Review" {
		t.Errorf("status = %q, want In Review", got)
	}
	err := c.SetStatus(ctx, "DEV-1", "Deployed")
	if err == nil || !strings.Contains(err.Error(), "possible: To Do, In Review") {
		t.Errorf("a status the workflow does not offer: %v, want the possible ones", err)
	}
}

func TestWrongCredentials(t *testing.T) {
	site := jiratest.New(t)
	c := New(config.JiraAPI{BaseURL: site.URL, Email: jiratest.Email, Token: "wrong"})
	_, err := c.Assigned(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("error = %v, want HTTP 401", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Errorf("the error holds the token: %v", err)
	}
}

func TestAssigner(t *testing.T) {
	site := jiratest.New(t)
	site.Add(jiratest.Issue{Key: "DEV-1", Creator: "557058:creator", AssignedBy: "557058:anna"})
	site.Add(jiratest.Issue{Key: "DEV-2", Creator: "557058:creator"})
	site.Add(jiratest.Issue{Key: "DEV-3"})
	c := client(site)
	ctx := context.Background()
	for key, want := range map[string][]string{
		// The author of the last change of the assignee to the bot.
		"DEV-1": {"557058:anna"},
		// Created with the bot as assignee: the creator.
		"DEV-2": {"557058:creator"},
		// Jira does not say.
		"DEV-3": nil,
	} {
		got, err := c.Assigner(ctx, key)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("Assigner(%s) = %q, %v; want %q", key, got, err, want)
		}
	}
	if _, err := c.Assigner(ctx, "DEV-404"); err == nil {
		t.Error("Assigner of an unknown ticket gave no error")
	}
}

func TestLookup(t *testing.T) {
	site := jiratest.New(t)
	for _, k := range []string{"DEV-1", "DEV-2", "DEV-3", "DEV-4"} {
		site.Add(jiratest.Issue{Key: k})
	}
	site.Unassign("DEV-2")
	site.Close("DEV-3")
	site.Remove("DEV-4")
	c := client(site)
	ctx := context.Background()
	for key, want := range map[string]tracker.Status{
		"DEV-1": {},
		"DEV-2": {Unassigned: true},
		"DEV-3": {Closed: true},
		// Deleted, or no longer visible to the bot.
		"DEV-4": {Closed: true},
	} {
		got, err := c.Lookup(ctx, key)
		if err != nil || got != want {
			t.Errorf("Lookup(%s) = %+v, %v; want %+v", key, got, err, want)
		}
	}
	// What is unassigned or closed is not among the bot's open tickets.
	open, err := c.Assigned(ctx)
	if err != nil || len(open) != 1 || open[0].Key != "DEV-1" {
		t.Errorf("Assigned = %+v, %v; want DEV-1 only", open, err)
	}
	// A failing site is an error, not "closed".
	site.Fail(http.StatusServiceUnavailable)
	if got, err := c.Lookup(ctx, "DEV-1"); err == nil {
		t.Errorf("Lookup against a failing site = %+v, no error", got)
	}
}

func TestScheduling(t *testing.T) {
	site := jiratest.New(t)
	site.Add(jiratest.Issue{Key: "DEV-1", Creator: "557058:creator", Priority: "High",
		Labels: []string{"agent-ready", "old", "own"}, Components: []string{"web", "api"},
		LabelsBy:  map[string]string{"agent-ready": "557058:anna", "own": jiratest.AccountID, "api": jiratest.AccountID},
		BlockedBy: []string{"DEV-2", "DEV-3", "ELSE-9"}})
	site.Add(jiratest.Issue{Key: "DEV-2"})
	site.Add(jiratest.Issue{Key: "DEV-3"})
	site.Add(jiratest.Issue{Key: "DEV-4"})
	site.Close("DEV-3")
	c := client(site)
	ctx := context.Background()

	got, err := c.Scheduling(ctx, "DEV-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.PriorityName != "High" || got.Priority != 0 {
		t.Errorf("priority = %d %q, want the name High", got.Priority, got.PriorityName)
	}
	// Who added each label: the author of the last change that added it,
	// the creator for one that the ticket was created with. Components
	// count as labels.
	want := []tracker.Label{
		{Name: "agent-ready", By: []string{"557058:anna"}},
		{Name: "old", By: []string{"557058:creator"}},
		{Name: "own", By: []string{jiratest.AccountID}, Bot: true},
		{Name: "web", By: []string{"557058:creator"}},
		{Name: "api", By: []string{jiratest.AccountID}, Bot: true},
	}
	if len(got.Labels) != len(want) {
		t.Fatalf("labels = %+v, want %+v", got.Labels, want)
	}
	for i, l := range got.Labels {
		if l.Name != want[i].Name || !slices.Equal(l.By, want[i].By) || l.Bot != want[i].Bot {
			t.Errorf("label %d = %+v, want %+v", i, l, want[i])
		}
	}
	// The open tickets that this one "is blocked by": not the one that is
	// done, not a link of another kind or in the other direction. A
	// blocker that the site does not show counts as open.
	if want := []string{"DEV-2", "ELSE-9"}; !slices.Equal(got.BlockedBy, want) {
		t.Errorf("blocked by %v, want %v", got.BlockedBy, want)
	}

	// A ticket with nothing of all this, and one that Jira does not have.
	if got, err := c.Scheduling(ctx, "DEV-4"); err != nil || got.PriorityName != "" || len(got.Labels) != 0 || len(got.BlockedBy) != 0 {
		t.Errorf("Scheduling(DEV-4) = %+v, %v", got, err)
	}
	if _, err := c.Scheduling(ctx, "DEV-404"); !errors.Is(err, tracker.ErrNotFound) {
		t.Errorf("Scheduling of an unknown ticket: %v, want ErrNotFound", err)
	}
	site.Fail(http.StatusServiceUnavailable)
	if _, err := c.Scheduling(ctx, "DEV-1"); err == nil || errors.Is(err, tracker.ErrNotFound) {
		t.Errorf("Scheduling with a failing site: %v", err)
	}
	site.Fail(0)

	// The list of the bot's tickets has the priority of each.
	list, err := c.Assigned(ctx)
	if err != nil || len(list) != 3 || list[0].PriorityName != "High" || list[1].PriorityName != "" {
		t.Errorf("Assigned = %+v, %v", list, err)
	}
}

// What the ticket tools read: the ticket as a person sees it, with its
// newest comments, oldest first.
func TestTicket(t *testing.T) {
	site := jiratest.New(t)
	site.Add(jiratest.Issue{Key: "DEV-1", Summary: "Add a retry", Description: "Retry the payment call.", Status: "In Progress",
		Labels: []string{"backend"}, Components: []string{"payments"}})
	c := client(site)
	ctx := context.Background()
	got, err := c.Ticket(ctx, "DEV-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != "DEV-1" || got.Title != "Add a retry" || got.Description != "Retry the payment call." || got.Status != "In Progress" ||
		got.URL != site.URL+"/browse/DEV-1" || !slices.Equal(got.Labels, []string{"backend", "payments"}) || len(got.Comments) != 0 || got.MoreComments != 0 {
		t.Errorf("ticket = %+v", got)
	}

	// More comments than one page: the newest are returned, oldest first.
	site.Say("DEV-1", "557058:jane", "Jane", "the first")
	for i := range tracker.MaxComments - 1 {
		site.Say("DEV-1", "557058:jane", "Jane", "comment "+strings.Repeat("i", i))
	}
	if err := c.Comment(ctx, "DEV-1", "from the bot"); err != nil {
		t.Fatal(err)
	}
	got, err = c.Ticket(ctx, "DEV-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Comments) != tracker.MaxComments || got.MoreComments != 1 {
		t.Fatalf("%d comments and %d more, want %d and 1", len(got.Comments), got.MoreComments, tracker.MaxComments)
	}
	first, last := got.Comments[0], got.Comments[len(got.Comments)-1]
	if first.Body != "comment " || first.Author != "Jane" || first.Bot || first.At.IsZero() || !first.At.Before(last.At) {
		t.Errorf("the oldest comment of the page = %+v", first)
	}
	if last.Body != "from the bot" || !last.Bot {
		t.Errorf("the newest comment = %+v, want the bot's", last)
	}

	if _, err := c.Ticket(ctx, "DEV-404"); !errors.Is(err, tracker.ErrNotFound) {
		t.Errorf("a ticket that is not there: %v", err)
	}
	if _, err := c.Ticket(ctx, "../myself"); err == nil {
		t.Error("a key that is no key was accepted")
	}
	if id, err := c.Account(ctx); err != nil || id != jiratest.AccountID {
		t.Errorf("Account = %q, %v", id, err)
	}
}
