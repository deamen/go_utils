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
	Labels     []string
	// DelegatedBy is the user id of who delegated the issue to the agent,
	// with the email address <id>@example.com. Empty: the issue was never
	// delegated; the agent was at most mentioned on it.
	DelegatedBy string
	// Creator is the user id of who created the issue.
	Creator string

	closed, undelegated bool
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
	issues     []*Issue
	sessions   map[string][]string // sessions created by the agent, by issue
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
			ID    string `json:"id"`
			After string `json:"after"`
			Input struct {
				AgentSessionID string `json:"agentSessionId"`
				IssueID        string `json:"issueId"`
				Ephemeral      bool   `json:"ephemeral"`
				Content        struct {
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
	case strings.Contains(req.Query, "OchellIssue"):
		data = s.issue(req.Variables.ID)
	case strings.Contains(req.Query, "OchellSessionCreate"):
		key := req.Variables.Input.IssueID
		if s.find(key) == nil {
			io.WriteString(w, `{"errors":[{"message":"Entity not found: Issue"}]}`)
			return
		}
		id := fmt.Sprintf("own-session-%s-%d", key, len(s.sessions[key])+1)
		s.sessions[key] = append(s.sessions[key], id)
		data = map[string]any{"agentSessionCreateOnIssue": map[string]any{"success": true, "agentSession": map[string]string{"id": id}}}
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
			"labels": map[string]any{"nodes": labels},
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
