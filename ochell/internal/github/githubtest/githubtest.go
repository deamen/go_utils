// Package githubtest is a fake GitHub API for tests: pull requests that a
// test opens, merges and closes, as far as ochell reads them.
package githubtest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Token is the token the fake API accepts.
const Token = "github-test-token"

// PullRequest is one pull request of the fake site.
type PullRequest struct {
	Owner, Repo string
	Number      int
	// HeadRef is the branch it comes from, and Author who opened it.
	HeadRef string
	Author  string
	HeadSHA string

	merged, closed bool
	mergedBy       string
}

// Server is a fake GitHub API.
type Server struct {
	URL string

	mu    sync.Mutex
	pulls []*PullRequest
	calls int
}

// New starts a fake GitHub API that is closed when the test ends.
func New(t *testing.T) *Server {
	s := &Server{}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	s.URL = srv.URL
	return s
}

// Host is the host of the fake site: what a pull request's address has to
// be on for ochell to follow it.
func (s *Server) Host() string { return strings.TrimPrefix(s.URL, "http://") }

// Open adds an open pull request and returns the address of its page.
func (s *Server) Open(pr PullRequest) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pr.HeadSHA == "" {
		pr.HeadSHA = "0000000000000000000000000000000000000001"
	}
	s.pulls = append(s.pulls, &pr)
	return s.URL + "/" + pr.Owner + "/" + pr.Repo + "/pull/" + strconv.Itoa(pr.Number)
}

func (s *Server) find(owner, repo string, number int) *PullRequest {
	for _, p := range s.pulls {
		if p.Owner == owner && p.Repo == repo && p.Number == number {
			return p
		}
	}
	return nil
}

// Merge marks a pull request as merged by a user.
func (s *Server) Merge(owner, repo string, number int, by string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.find(owner, repo, number); p != nil {
		p.merged, p.closed, p.mergedBy = true, true, by
	}
}

// Close marks a pull request as closed without a merge.
func (s *Server) Close(owner, repo string, number int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.find(owner, repo, number); p != nil {
		p.closed = true
	}
}

// Calls returns how many requests the API has answered.
func (s *Server) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

var pullPath = regexp.MustCompile(`^/repos/([^/]+)/([^/]+)/pulls/(\d+)$`)

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer "+Token {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "Bad credentials"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if r.Method != http.MethodGet {
		// ochell only reads.
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	m := pullPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
		return
	}
	n, _ := strconv.Atoi(m[3])
	p := s.find(m[1], m[2], n)
	if p == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
		return
	}
	state := "open"
	if p.closed {
		state = "closed"
	}
	out := map[string]any{
		"number": p.Number, "state": state, "merged": p.merged,
		"user": map[string]string{"login": p.Author},
		"head": map[string]string{"ref": p.HeadRef, "sha": p.HeadSHA},
	}
	if p.merged {
		out["merged_by"] = map[string]string{"login": p.mergedBy}
	} else {
		out["merged_by"] = nil
	}
	json.NewEncoder(w).Encode(out)
}
