// Package lineartest is a stand-in for the Linear GraphQL API, as far as
// ochell uses it. Tests point the Linear client at it.
package lineartest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// AppUserID is the user that the token belongs to: the agent.
const AppUserID = "app-user-0000"

// Activity is one agent activity that was posted.
type Activity struct {
	SessionID string
	Type      string
	Body      string
	// Action and Parameter are set for an activity of the type "action".
	Action    string
	Parameter string
	// Ephemeral activities are replaced by the next one in Linear.
	Ephemeral bool
	At        time.Time
}

// Issue is one issue of the fake workspace.
type Issue struct {
	Key, Title string
	// Description is the text of the issue, and State the name of its
	// workflow state.
	Description string
	State       string
	Labels      []string
	// DelegatedBy is the user id of who delegated the issue to the agent,
	// with the email address <id>@example.com. Empty: the issue was never
	// delegated; the agent was at most mentioned on it.
	DelegatedBy string
	// Creator is the user id of who created the issue.
	Creator string
	// Priority is the priority of the issue: 1 (urgent) to 4 (low); 0:
	// none.
	Priority int
	// LabelsBy says who added a label, by its name, as a user id. One
	// that is not in it was there when the issue was created.
	LabelsBy map[string]string
	// BlockedBy are the keys of the issues that block this one. A blocker
	// counts as done once it was closed in the workspace.
	BlockedBy []string

	closed, undelegated bool
}

// Comment is one comment on an issue: one that the agent app posted
// through the API, or one that a test put there for a person (Say).
type Comment struct {
	Key, Body string
	// Author is the user id of who wrote it.
	Author string
}

// Server is a fake Linear API. It accepts one access token.
type Server struct {
	URL string
	// PageSize is how many issues one page of a listing holds (default 2,
	// so that paging is always exercised).
	PageSize int

	token string

	mu         sync.Mutex
	activities []Activity
	comments   []Comment
	issues     []*Issue
	sessions   map[string][]string // sessions created by the agent, by issue
	links      map[string]string   // external URL of each session
	fail       bool
}

// New starts a fake Linear API that is closed when the test ends.
func New(t *testing.T, token string) *Server {
	s := &Server{PageSize: 2, token: token, sessions: map[string][]string{}}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	s.URL = srv.URL
	return s
}

// Add puts an issue into the workspace.
func (s *Server) Add(is Issue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issues = append(s.issues, &is)
}

// Change changes an issue of the workspace in place, as a person who edits
// it does: its labels, its priority, what blocks it.
func (s *Server) Change(key string, change func(*Issue)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is := s.find(key); is != nil {
		change(is)
	}
}

// Close completes an issue, and Undelegate takes it away from the agent.
func (s *Server) Close(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is := s.find(key); is != nil {
		is.closed = true
	}
}

func (s *Server) Undelegate(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is := s.find(key); is != nil {
		is.undelegated = true
	}
}

// Say puts a comment of a person on an issue.
func (s *Server) Say(key, author, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.comments = append(s.comments, Comment{Key: key, Body: body, Author: author})
}

// Comments returns the comments on an issue so far, oldest first.
func (s *Server) Comments(key string) []Comment {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Comment
	for _, c := range s.comments {
		if c.Key == key {
			out = append(out, c)
		}
	}
	return out
}

// Fail makes every request from now on fail, until it is called with false.
func (s *Server) Fail(fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = fail
}

// Activities returns the activities posted to a session so far.
func (s *Server) Activities(sessionID string) []Activity {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Activity
	for _, a := range s.activities {
		if a.SessionID == sessionID {
			out = append(out, a)
		}
	}
	return out
}

// ExternalURL returns the external URL that a session was given, or "".
func (s *Server) ExternalURL(sessionID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.links[sessionID]
}

// Sessions returns the ids of the sessions that the agent itself created
// on an issue.
func (s *Server) Sessions(key string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.sessions[key]...)
}

func (s *Server) find(key string) *Issue {
	for _, is := range s.issues {
		if is.Key == key {
			return is
		}
	}
	return nil
}

func person(id string) map[string]string {
	return map[string]string{"id": id, "email": id + "@example.com"}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"errors":[{"message":"authentication failed"}]}`)
		return
	}
	var req struct {
		Query     string `json:"query"`
		Variables struct {
			ID       string `json:"id"`
			After    string `json:"after"`
			Comments int    `json:"comments"`
			Input    struct {
				AgentSessionID string `json:"agentSessionId"`
				IssueID        string `json:"issueId"`
				Body           string `json:"body"`
				Ephemeral      bool   `json:"ephemeral"`
				ExternalURLs   []struct {
					URL string `json:"url"`
				} `json:"externalUrls"`
				Content struct {
					Type      string `json:"type"`
					Body      string `json:"body"`
					Action    string `json:"action"`
					Parameter string `json:"parameter"`
				} `json:"content"`
			} `json:"input"`
		} `json:"variables"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"errors":[{"message":"the fake API was told to fail"}]}`)
		return
	}
	data := map[string]any{"agentActivityCreate": map[string]bool{"success": true}, "agentSessionUpdate": map[string]bool{"success": true}}
	switch {
	case strings.Contains(req.Query, "OchellAssigned"):
		data = s.assigned(req.Variables.After)
	case strings.Contains(req.Query, "OchellScheduling"):
		data = s.scheduling(req.Variables.ID)
	case strings.Contains(req.Query, "OchellIssue"):
		data = s.issue(req.Variables.ID)
	case strings.Contains(req.Query, "OchellTicket"):
		data = s.ticket(req.Variables.ID, req.Variables.Comments)
	case strings.Contains(req.Query, "OchellComment"):
		// The mutation takes the id of the issue, not its key.
		key, ok := strings.CutPrefix(req.Variables.Input.IssueID, "issue-")
		if !ok || s.find(key) == nil || req.Variables.Input.Body == "" {
			io.WriteString(w, `{"errors":[{"message":"Entity not found: Issue"}]}`)
			return
		}
		s.comments = append(s.comments, Comment{Key: key, Body: req.Variables.Input.Body, Author: AppUserID})
		data = map[string]any{"commentCreate": map[string]bool{"success": true}}
	case strings.Contains(req.Query, "OchellSessionCreate"):
		key := req.Variables.Input.IssueID
		if s.find(key) == nil {
			io.WriteString(w, `{"errors":[{"message":"Entity not found: Issue"}]}`)
			return
		}
		id := fmt.Sprintf("own-session-%s-%d", key, len(s.sessions[key])+1)
		s.sessions[key] = append(s.sessions[key], id)
		data = map[string]any{"agentSessionCreateOnIssue": map[string]any{"success": true, "agentSession": map[string]string{"id": id}}}
	case len(req.Variables.Input.ExternalURLs) > 0:
		if s.links == nil {
			s.links = map[string]string{}
		}
		s.links[req.Variables.ID] = req.Variables.Input.ExternalURLs[0].URL
	default:
		if in := req.Variables.Input; in.Content.Type != "" {
			s.activities = append(s.activities, Activity{SessionID: in.AgentSessionID, Type: in.Content.Type, Body: in.Content.Body,
				Action: in.Content.Action, Parameter: in.Content.Parameter, Ephemeral: in.Ephemeral, At: time.Now()})
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"data": data})
}

// assigned answers the listing of the open issues delegated to the agent.
func (s *Server) assigned(after string) map[string]any {
	var open []*Issue
	for _, is := range s.issues {
		if is.DelegatedBy != "" && !is.closed && !is.undelegated {
			open = append(open, is)
		}
	}
	start, _ := strconv.Atoi(after)
	nodes := []map[string]any{}
	page := map[string]any{"hasNextPage": false, "endCursor": ""}
	for i := start; i < len(open); i++ {
		if len(nodes) == max(s.PageSize, 1) {
			page = map[string]any{"hasNextPage": true, "endCursor": strconv.Itoa(i)}
			break
		}
		is := open[i]
		labels := []map[string]string{}
		for _, l := range is.Labels {
			labels = append(labels, map[string]string{"name": l})
		}
		nodes = append(nodes, map[string]any{
			"identifier": is.Key, "title": is.Title, "url": "https://linear.app/example/issue/" + is.Key,
			"priority": is.Priority,
			"labels":   map[string]any{"nodes": labels},
		})
	}
	return map[string]any{"issues": map[string]any{"nodes": nodes, "pageInfo": page}}
}

// issue answers the query for one issue and its history.
func (s *Server) issue(key string) map[string]any {
	out := map[string]any{"viewer": map[string]string{"id": AppUserID}, "issue": nil}
	is := s.find(key)
	if is == nil {
		return out
	}
	state := "started"
	if is.closed {
		state = "completed"
	}
	issue := map[string]any{"state": map[string]string{"type": state}, "delegate": nil, "creator": nil}
	if is.Creator != "" {
		issue["creator"] = person(is.Creator)
	}
	history := []map[string]any{
		// A change that is no delegation, which must be passed over.
		{"createdAt": "2026-11-01T09:00:00.000Z", "actor": person("u-earlier"), "toDelegate": nil},
	}
	if is.DelegatedBy != "" {
		history = append(history, map[string]any{"createdAt": "2026-11-14T09:00:00.000Z", "actor": person(is.DelegatedBy), "toDelegate": map[string]string{"id": AppUserID}})
		if !is.undelegated {
			issue["delegate"] = map[string]string{"id": AppUserID}
		}
	}
	issue["history"] = map[string]any{"nodes": history}
	out["issue"] = issue
	return out
}

// ticket answers the query for one issue as a person sees it, with one
// page of its comments, the newest first.
func (s *Server) ticket(key string, limit int) map[string]any {
	out := map[string]any{"viewer": map[string]string{"id": AppUserID}, "issue": nil}
	is := s.find(key)
	if is == nil {
		return out
	}
	labels := []map[string]string{}
	for _, l := range is.Labels {
		labels = append(labels, map[string]string{"name": l})
	}
	nodes := []map[string]any{}
	more := false
	for i := len(s.comments) - 1; i >= 0; i-- {
		c := s.comments[i]
		if c.Key != key {
			continue
		}
		if len(nodes) == limit {
			more = true
			break
		}
		nodes = append(nodes, map[string]any{
			"body": c.Body, "createdAt": time.Date(2026, 11, 16, 9, 0, i, 0, time.UTC).Format("2006-01-02T15:04:05.000Z"),
			"user": map[string]string{"id": c.Author, "name": "Name of " + c.Author}, "botActor": nil,
		})
	}
	out["issue"] = map[string]any{
		"id": "issue-" + key, "identifier": key, "title": is.Title, "description": is.Description,
		"url":      "https://linear.app/example/issue/" + key,
		"state":    map[string]string{"name": is.State},
		"labels":   map[string]any{"nodes": labels},
		"comments": map[string]any{"nodes": nodes, "pageInfo": map[string]bool{"hasNextPage": more}},
	}
	return out
}

// scheduling answers the query for what decides when the work on an issue
// starts.
func (s *Server) scheduling(key string) map[string]any {
	out := map[string]any{"viewer": map[string]string{"id": AppUserID}, "issue": nil}
	is := s.find(key)
	if is == nil {
		return out
	}
	issue := map[string]any{"priority": is.Priority, "creator": nil}
	if is.Creator != "" {
		issue["creator"] = person(is.Creator)
	}
	labels := []map[string]string{}
	history := []map[string]any{
		// A change that adds no label, which must be passed over.
		{"createdAt": "2026-11-01T09:00:00.000Z", "actor": person("u-earlier"), "addedLabels": nil},
	}
	for _, l := range is.Labels {
		labels = append(labels, map[string]string{"name": l})
		if by := is.LabelsBy[l]; by != "" {
			history = append(history,
				// An earlier time at which someone else added the label.
				map[string]any{"createdAt": "2026-11-02T09:00:00.000Z", "actor": person("u-earlier"), "addedLabels": []map[string]string{{"name": l}}},
				map[string]any{"createdAt": "2026-11-15T09:00:00.000Z", "actor": person(by), "addedLabels": []map[string]string{{"name": l}}})
		}
	}
	issue["labels"] = map[string]any{"nodes": labels}
	issue["history"] = map[string]any{"nodes": history}
	relations := []map[string]any{
		// A relation of another kind, which must be passed over.
		{"type": "related", "issue": map[string]any{"identifier": "OTHER-1", "state": map[string]string{"type": "started"}}},
	}
	for _, b := range is.BlockedBy {
		state := "started"
		if blocker := s.find(b); blocker != nil && blocker.closed {
			state = "completed"
		}
		relations = append(relations, map[string]any{"type": "blocks", "issue": map[string]any{"identifier": b, "state": map[string]string{"type": state}}})
	}
	issue["inverseRelations"] = map[string]any{"nodes": relations}
	out["issue"] = issue
	return out
}
