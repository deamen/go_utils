// Package githubtest is a fake GitHub API for tests: pull requests that a
// test opens, merges and closes, as far as ochell reads them, and issues
// that a test assigns, labels and closes, with the comments that ochell
// writes on them.
package githubtest

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Token is the token the fake API accepts for reading, and IssuesToken
// the one that may also comment on issues: the token of the GitHub source.
const (
	Token       = "github-test-token"
	IssuesToken = "github-test-issues-token"
)

// Bot is the login of the account that IssuesToken belongs to, unless a
// test sets Server.Login.
const Bot = "digital-employee"

// Issue is one issue of the fake site; with PullRequest, a pull request
// as the issues API shows it.
type Issue struct {
	Owner, Repo string
	Number      int
	Title, Body string
	Author      string
	Labels      []string
	Assignees   []string
	// Type is the name of the issue type; empty: the issue has none.
	Type        string
	PullRequest bool
	Closed      bool

	comments []IssueComment
	events   []map[string]any
}

// IssueComment is a comment in the conversation of an issue.
type IssueComment struct {
	Author, Body string
	At           time.Time
}

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
	issues []*Issue
	// Login is the account of IssuesToken; empty: Bot.
	Login string
	// writes counts the requests that were not a GET, and refused those
	// of them that the fake did not allow.
	writes, refused int
}

// AddIssue adds an issue.
func (s *Server) AddIssue(is Issue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issues = append(s.issues, &is)
}

func (s *Server) issue(owner, repo string, number int) *Issue {
	for _, is := range s.issues {
		if is.Owner == owner && is.Repo == repo && is.Number == number {
			return is
		}
	}
	return nil
}

func user(login string) map[string]string { return map[string]string{"login": login} }

// Assign assigns an issue to a login, as the user by does.
func (s *Server) Assign(owner, repo string, number int, login, by string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is := s.issue(owner, repo, number); is != nil {
		is.Assignees = append(is.Assignees, login)
		is.events = append(is.events, map[string]any{"event": "assigned", "actor": user(login), "assignee": user(login), "assigner": user(by)})
	}
}

// Unassign takes an issue away from a login.
func (s *Server) Unassign(owner, repo string, number int, login string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is := s.issue(owner, repo, number); is != nil {
		var left []string
		for _, a := range is.Assignees {
			if a != login {
				left = append(left, a)
			}
		}
		is.Assignees = left
	}
}

// Label puts a label on an issue, as the user by does.
func (s *Server) Label(owner, repo string, number int, label, by string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is := s.issue(owner, repo, number); is != nil {
		is.Labels = append(is.Labels, label)
		is.events = append(is.events, map[string]any{"event": "labeled", "actor": user(by), "label": map[string]string{"name": label}})
	}
}

// CloseIssue closes an issue.
func (s *Server) CloseIssue(owner, repo string, number int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is := s.issue(owner, repo, number); is != nil {
		is.Closed = true
	}
}

// CommentIssue adds a comment to an issue, as a user does.
func (s *Server) CommentIssue(owner, repo string, number int, author, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is := s.issue(owner, repo, number); is != nil {
		is.comments = append(is.comments, IssueComment{Author: author, Body: body, At: time.Now()})
	}
}

// IssueComments returns the comments of an issue, oldest first.
func (s *Server) IssueComments(owner, repo string, number int) []IssueComment {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is := s.issue(owner, repo, number); is != nil {
		return append([]IssueComment(nil), is.comments...)
	}
	return nil
}

// Refused returns how many requests that would have written something
// the fake refused: every one but a comment with IssuesToken.
func (s *Server) Refused() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}

func (is *Issue) json(base string) map[string]any {
	state := "open"
	if is.Closed {
		state = "closed"
	}
	kind := "issues"
	if is.PullRequest {
		kind = "pull"
	}
	labels := []map[string]string{}
	for _, l := range is.Labels {
		labels = append(labels, map[string]string{"name": l})
	}
	assignees := []map[string]string{}
	for _, a := range is.Assignees {
		assignees = append(assignees, user(a))
	}
	out := map[string]any{"number": is.Number, "title": is.Title, "body": is.Body, "state": state, "user": user(is.Author),
		"html_url": base + "/" + is.Owner + "/" + is.Repo + "/" + kind + "/" + strconv.Itoa(is.Number),
		"labels":   labels, "assignees": assignees, "comments": len(is.comments)}
	if is.Type != "" {
		out["type"] = map[string]string{"name": is.Type}
	}
	if is.PullRequest {
		out["pull_request"] = map[string]string{"url": base + "/pulls/" + strconv.Itoa(is.Number)}
	}
	return out
}

// page cuts one page out of a list, as per_page and page ask for it.
func page[T any](list []T, r *http.Request) []T {
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if per <= 0 {
		per = 30
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if n <= 0 {
		n = 1
	}
	from := (n - 1) * per
	if from >= len(list) {
		return []T{}
	}
	return list[from:min(from+per, len(list))]
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

func (s *Server) login() string {
	if s.Login != "" {
		return s.Login
	}
	return Bot
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
	issuesPath  = regexp.MustCompile(`^/repos/([^/]+)/([^/]+)/issues$`)
	issuePath   = regexp.MustCompile(`^/repos/([^/]+)/([^/]+)/issues/(\d+)(/events)?$`)
)

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token != Token && token != IssuesToken {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "Bad credentials"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	notFound := func() {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
	}
	if r.Method != http.MethodGet {
		// ochell writes one thing: a comment on an issue, with the token
		// of the GitHub source. The token of the handoff only reads.
		s.writes++
		m := commentPath.FindStringSubmatch(r.URL.Path)
		if r.Method != http.MethodPost || m == nil || m[3] != "issues" || m[5] != "comments" || token != IssuesToken {
			s.refused++
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"message": "Resource not accessible by personal access token"})
			return
		}
		n, _ := strconv.Atoi(m[4])
		is := s.issue(m[1], m[2], n)
		var in struct {
			Body string `json:"body"`
		}
		if is == nil || json.NewDecoder(r.Body).Decode(&in) != nil || in.Body == "" {
			notFound()
			return
		}
		is.comments = append(is.comments, IssueComment{Author: s.login(), Body: in.Body, At: time.Now()})
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"id": 1000*is.Number + len(is.comments), "body": in.Body})
		return
	}
	if r.URL.Path == "/user" {
		if token != IssuesToken {
			notFound()
			return
		}
		json.NewEncoder(w).Encode(user(s.login()))
		return
	}
	if m := issuesPath.FindStringSubmatch(r.URL.Path); m != nil {
		q := r.URL.Query()
		list := []map[string]any{}
		for _, is := range s.issues {
			if is.Owner != m[1] || is.Repo != m[2] || (q.Get("state") == "open" && is.Closed) {
				continue
			}
			if a := q.Get("assignee"); a != "" && !slices.ContainsFunc(is.Assignees, func(l string) bool { return strings.EqualFold(l, a) }) {
				continue
			}
			list = append(list, is.json(s.URL))
		}
		json.NewEncoder(w).Encode(page(list, r))
		return
	}
	if m := issuePath.FindStringSubmatch(r.URL.Path); m != nil {
		n, _ := strconv.Atoi(m[3])
		is := s.issue(m[1], m[2], n)
		switch {
		case is == nil:
			notFound()
		case m[4] != "":
			json.NewEncoder(w).Encode(page(is.events, r))
		default:
			json.NewEncoder(w).Encode(is.json(s.URL))
		}
		return
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
		if is := s.issue(m[1], m[2], n); is != nil && kind == "issue" {
			for i, c := range is.comments {
				list = append(list, map[string]any{"id": 1000*is.Number + i + 1, "body": c.Body, "user": user(c.Author),
					"author_association": "MEMBER", "created_at": c.At.UTC().Format(time.RFC3339Nano)})
			}
			json.NewEncoder(w).Encode(page(list, r))
			return
		}
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
