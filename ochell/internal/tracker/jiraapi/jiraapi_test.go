package jiraapi

import (
	"context"
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
