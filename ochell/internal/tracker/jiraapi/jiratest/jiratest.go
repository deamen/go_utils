// Package jiratest is a stand-in for the Jira Cloud REST API, as far as
// ochell uses it. Tests point the Jira client at it.
package jiratest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Credentials that the server accepts, and the account behind them.
const (
	Email     = "bot@example.com"
	Token     = "jira-api-token"
	AccountID = "712020:digital-employee"
)

// Issue is one ticket of the fake site.
type Issue struct {
	Key, Summary string
	Labels       []string
	Components   []string
	// Status is the current status; Statuses are the ones it can move to.
	Status   string
	Statuses []string
	// Creator is the accountId of who created the ticket, and AssignedBy
	// of who assigned it to the bot; empty: it was created that way.
	Creator    string
	AssignedBy string

	// unassigned and closed tickets are no longer among the bot's open
	// tickets, but can still be read.
	unassigned, closed bool
}

// Comment is one comment that was posted.
type Comment struct {
	Key, Body string
}

// Server is a fake Jira site.
type Server struct {
	URL string
	// PageSize is how many tickets one search page holds (default 2, so
	// that paging is always exercised).
	PageSize int

	mu       sync.Mutex
	issues   []*Issue
	comments []Comment
	jql      []string
	fail     int
}

// New starts a fake Jira site that is closed when the test ends.
func New(t *testing.T) *Server {
	s := &Server{PageSize: 2}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	s.URL = srv.URL
	return s
}

// Add puts a ticket on the site: it is assigned to the bot and open.
func (s *Server) Add(is Issue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issues = append(s.issues, &is)
}

// Remove takes a ticket off the list of the bot's open tickets, as an
// unassignment or a close does.
func (s *Server) Remove(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, is := range s.issues {
		if is.Key == key {
			s.issues = append(s.issues[:i], s.issues[i+1:]...)
			return
		}
	}
}

// Unassign takes a ticket away from the bot, and Close closes it. Both stay
// readable.
func (s *Server) Unassign(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is := s.find(key); is != nil {
		is.unassigned = true
	}
}

func (s *Server) Close(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is := s.find(key); is != nil {
		is.closed = true
	}
}

// Fail makes every request from now on fail with this HTTP status; 0 ends
// that.
func (s *Server) Fail(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = status
}

// Comments returns the bodies of the comments posted on a ticket, in order.
func (s *Server) Comments(key string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, c := range s.comments {
		if c.Key == key {
			out = append(out, c.Body)
		}
	}
	return out
}

// Status returns the current status of a ticket.
func (s *Server) Status(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is := s.find(key); is != nil {
		return is.Status
	}
	return ""
}

// Searches returns the JQL of every search so far.
func (s *Server) Searches() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.jql...)
}

func (s *Server) find(key string) *Issue {
	for _, is := range s.issues {
		if is.Key == key {
			return is
		}
	}
	return nil
}

func answer(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if email, token, ok := r.BasicAuth(); !ok || email != Email || token != Token {
		answer(w, http.StatusUnauthorized, map[string]any{"errorMessages": []string{"You are not authenticated."}})
		return
	}
	if s.fail != 0 {
		answer(w, s.fail, map[string]any{"errorMessages": []string{"the fake site was told to fail"}})
		return
	}
	body, _ := io.ReadAll(r.Body)
	if r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/search/jql" {
		s.search(w, body)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/rest/api/2/myself" {
		answer(w, http.StatusOK, map[string]string{"accountId": AccountID, "emailAddress": Email})
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/rest/api/2/issue/")
	key, what, _ := strings.Cut(rest, "/")
	is := s.find(key)
	if !ok || is == nil {
		answer(w, http.StatusNotFound, map[string]any{"errorMessages": []string{"Issue does not exist or you do not have permission to see it."}})
		return
	}
	switch {
	case what == "" && r.Method == http.MethodGet:
		s.issue(w, is, r.URL.Query().Get("expand") == "changelog")
	case what == "comment" && r.Method == http.MethodPost:
		var in struct {
			Body string `json:"body"`
		}
		if json.Unmarshal(body, &in) != nil || in.Body == "" {
			answer(w, http.StatusBadRequest, map[string]any{"errorMessages": []string{"Comment body can not be empty!"}})
			return
		}
		s.comments = append(s.comments, Comment{key, in.Body})
		answer(w, http.StatusCreated, map[string]string{"id": "10000"})
	case what == "transitions" && r.Method == http.MethodGet:
		type to struct {
			Name string `json:"name"`
		}
		type transition struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			To   to     `json:"to"`
		}
		list := []transition{}
		for _, st := range is.Statuses {
			list = append(list, transition{ID: "to:" + st, Name: "Move to " + st, To: to{st}})
		}
		answer(w, http.StatusOK, map[string]any{"transitions": list})
	case what == "transitions" && r.Method == http.MethodPost:
		var in struct {
			Transition struct {
				ID string `json:"id"`
			} `json:"transition"`
		}
		json.Unmarshal(body, &in)
		st, ok := strings.CutPrefix(in.Transition.ID, "to:")
		if !ok {
			answer(w, http.StatusBadRequest, map[string]any{"errorMessages": []string{"no such transition"}})
			return
		}
		is.Status = st
		answer(w, http.StatusNoContent, nil)
	default:
		answer(w, http.StatusNotFound, nil)
	}
}

// issue answers a GET of one ticket, with every field ochell asks for.
func (s *Server) issue(w http.ResponseWriter, is *Issue, changelog bool) {
	type account struct {
		AccountID string `json:"accountId"`
	}
	category := "indeterminate"
	if is.closed {
		category = "done"
	}
	fields := map[string]any{
		"status": map[string]any{"name": is.Status, "statusCategory": map[string]string{"key": category}},
	}
	if !is.unassigned {
		fields["assignee"] = account{AccountID}
	} else {
		fields["assignee"] = nil
	}
	if is.Creator != "" {
		fields["creator"] = account{is.Creator}
	}
	out := map[string]any{"key": is.Key, "fields": fields}
	if changelog {
		histories := []map[string]any{}
		if is.AssignedBy != "" {
			histories = append(histories,
				// An older assignment to someone else, and a change that is
				// no assignment, which must both be passed over.
				map[string]any{"created": "2026-11-01T09:00:00.000+0000", "author": account{"557058:earlier"},
					"items": []map[string]string{{"field": "assignee", "to": "557058:someone"}}},
				map[string]any{"created": "2026-11-14T09:00:00.000+0000", "author": account{is.AssignedBy},
					"items": []map[string]string{{"field": "assignee", "to": AccountID}}},
				map[string]any{"created": "2026-11-14T10:00:00.000+0000", "author": account{"557058:later"},
					"items": []map[string]string{{"field": "status", "to": "3"}}},
			)
		}
		out["changelog"] = map[string]any{"histories": histories}
	}
	answer(w, http.StatusOK, out)
}

func (s *Server) search(w http.ResponseWriter, body []byte) {
	var in struct {
		JQL           string `json:"jql"`
		NextPageToken string `json:"nextPageToken"`
	}
	if json.Unmarshal(body, &in) != nil || in.JQL == "" {
		answer(w, http.StatusBadRequest, map[string]any{"errorMessages": []string{"no jql"}})
		return
	}
	s.jql = append(s.jql, in.JQL)
	var open []*Issue
	for _, is := range s.issues {
		if !is.unassigned && !is.closed {
			open = append(open, is)
		}
	}
	start := 0
	if in.NextPageToken != "" {
		for i, is := range open {
			if is.Key == in.NextPageToken {
				start = i
			}
		}
	}
	type name struct {
		Name string `json:"name"`
	}
	type fields struct {
		Summary    string   `json:"summary"`
		Labels     []string `json:"labels"`
		Components []name   `json:"components"`
	}
	type issue struct {
		Key    string `json:"key"`
		Fields fields `json:"fields"`
	}
	out := map[string]any{}
	list := []issue{}
	for i := start; i < len(open); i++ {
		if len(list) == max(s.PageSize, 1) {
			// The token of the next page is the key of its first ticket.
			out["nextPageToken"] = open[i].Key
			break
		}
		is := open[i]
		f := fields{Summary: is.Summary, Labels: is.Labels}
		for _, c := range is.Components {
			f.Components = append(f.Components, name{c})
		}
		list = append(list, issue{Key: is.Key, Fields: f})
	}
	out["issues"] = list
	answer(w, http.StatusOK, out)
}
