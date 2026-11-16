// Package githubtest is a fake GitHub API for tests: pull requests that a
// test opens, merges and closes, as far as ochell reads them.
package githubtest

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
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
	comments       []Comment
}

// Check is a check run of a commit.
type Check struct {
	Name string
	// Status is queued, in_progress or completed; Conclusion is set when
	// it is completed.
	Status, Conclusion string
	Title, Summary     string
}

// Comment is something written on a pull request. Kind is "issue" (the
// conversation), "diff" (a line of the diff) or "review".
type Comment struct {
	Kind, Author, Association, Body, Path, Review string
	At                                            time.Time
}

// Server is a fake GitHub API.
type Server struct {
	URL string

	mu     sync.Mutex
	pulls  []*PullRequest
	checks map[string][]Check // by commit
	files  map[string]string  // by owner/repo/path, on the default branch
	repos  map[string]bool    // by owner/repo
	calls  int
}

// SetFile puts a file on the default branch of a repository, as a merge
// does. The repository exists from then on.
func (s *Server) SetFile(owner, repo, path, content string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.files == nil {
		s.files, s.repos = map[string]string{}, map[string]bool{}
	}
	s.files[owner+"/"+repo+"/"+path] = content
	s.repos[owner+"/"+repo] = true
}

// RemoveFile takes a file off the default branch; the repository stays.
func (s *Server) RemoveFile(owner, repo, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.files, owner+"/"+repo+"/"+path)
}

// SetChecks sets the check runs of a commit.
func (s *Server) SetChecks(sha string, checks ...Check) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.checks == nil {
		s.checks = map[string][]Check{}
	}
	s.checks[sha] = checks
}

// Push gives a pull request a new head commit, as a push to its branch
// does.
func (s *Server) Push(owner, repo string, number int, sha string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.find(owner, repo, number); p != nil {
		p.HeadSHA = sha
	}
}

// Comment adds a comment to a pull request, written now.
func (s *Server) Comment(owner, repo string, number int, c Comment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.find(owner, repo, number); p != nil {
		if c.At.IsZero() {
			c.At = time.Now()
		}
		p.comments = append(p.comments, c)
	}
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

var (
	pullPath    = regexp.MustCompile(`^/repos/([^/]+)/([^/]+)/pulls/(\d+)$`)
	commitPath  = regexp.MustCompile(`^/repos/[^/]+/[^/]+/commits/([^/]+)/(check-runs|status)$`)
	contentPath = regexp.MustCompile(`^/repos/([^/]+)/([^/]+)/contents/(.+)$`)
	repoPath    = regexp.MustCompile(`^/repos/([^/]+)/([^/]+)$`)
	commentPath = regexp.MustCompile(`^/repos/([^/]+)/([^/]+)/(issues|pulls)/(\d+)/(comments|reviews)$`)
)

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
	notFound := func() {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
	}
	if m := contentPath.FindStringSubmatch(r.URL.Path); m != nil {
		content, ok := s.files[m[1]+"/"+m[2]+"/"+m[3]]
		// A real GitHub answers from the default branch when no ref is
		// named. The fake has no other branch, so a ref is refused: ochell
		// must not name one.
		if !ok || r.URL.Query().Has("ref") {
			notFound()
			return
		}
		sum := sha1.Sum([]byte("blob " + strconv.Itoa(len(content)) + "\x00" + content))
		json.NewEncoder(w).Encode(map[string]any{"type": "file", "encoding": "base64", "size": len(content), "path": m[3],
			"sha": hex.EncodeToString(sum[:]), "content": base64.StdEncoding.EncodeToString([]byte(content)) + "\n"})
		return
	}
	if m := repoPath.FindStringSubmatch(r.URL.Path); m != nil {
		if !s.repos[m[1]+"/"+m[2]] {
			notFound()
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"full_name": m[1] + "/" + m[2], "default_branch": "main"})
		return
	}
	if m := commitPath.FindStringSubmatch(r.URL.Path); m != nil {
		if m[2] == "status" {
			json.NewEncoder(w).Encode(map[string]any{"state": "pending", "statuses": []any{}})
			return
		}
		runs := []map[string]any{}
		for _, c := range s.checks[m[1]] {
			run := map[string]any{"name": c.Name, "status": c.Status, "html_url": s.URL + "/checks/" + c.Name,
				"output": map[string]string{"title": c.Title, "summary": c.Summary}}
			if c.Status == "completed" {
				run["conclusion"] = c.Conclusion
			} else {
				run["conclusion"] = nil
			}
			runs = append(runs, run)
		}
		json.NewEncoder(w).Encode(map[string]any{"total_count": len(runs), "check_runs": runs})
		return
	}
	if m := commentPath.FindStringSubmatch(r.URL.Path); m != nil {
		n, _ := strconv.Atoi(m[4])
		kind := map[string]string{"issues/comments": "issue", "pulls/comments": "diff", "pulls/reviews": "review"}[m[3]+"/"+m[5]]
		list := []map[string]any{}
		if p := s.find(m[1], m[2], n); p != nil {
			for i, c := range p.comments {
				if c.Kind != kind {
					continue
				}
				item := map[string]any{"id": 1000*p.Number + i + 1, "body": c.Body, "user": map[string]string{"login": c.Author}, "author_association": c.Association}
				if kind == "review" {
					item["state"], item["submitted_at"] = c.Review, c.At.UTC().Format(time.RFC3339Nano)
				} else {
					item["created_at"] = c.At.UTC().Format(time.RFC3339Nano)
				}
				if kind == "diff" {
					item["path"] = c.Path
				}
				list = append(list, item)
			}
		}
		json.NewEncoder(w).Encode(list)
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
