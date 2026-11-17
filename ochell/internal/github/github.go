// Package github is ochell's access to GitHub. With the token of the
// handoff (github.token) it only reads: what became of the pull requests
// that its tickets opened, and a repository's WORKFLOW.md. With the token
// of the GitHub source (sources.github.token) it reads issues and writes
// comments on them (issues.go). It never merges, approves or pushes, and
// neither token needs a permission to.
//
// It is not how the agent reaches GitHub; the agent has its own account.
package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultAPIURL is the API of github.com.
const DefaultAPIURL = "https://api.github.com"

// Client reads from the GitHub REST API with one token.
type Client struct {
	// APIURL is the address of the API, without a trailing slash.
	APIURL string
	Token  string
	HTTP   *http.Client
}

// New returns a client. An empty apiURL means github.com.
func New(apiURL, token string) *Client {
	if apiURL == "" {
		apiURL = DefaultAPIURL
	}
	return &Client{APIURL: strings.TrimRight(apiURL, "/"), Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// WebHost returns the host of the pages that belong to this API: github.com
// for api.github.com, and the API's own host for GitHub Enterprise Server.
func (c *Client) WebHost() string {
	u, err := url.Parse(c.APIURL)
	if err != nil {
		return ""
	}
	if u.Host == "api.github.com" {
		return "github.com"
	}
	return u.Host
}

// Ref names one pull request.
type Ref struct {
	Owner, Repo string
	Number      int
}

func (r Ref) String() string { return fmt.Sprintf("%s/%s#%d", r.Owner, r.Repo, r.Number) }

var (
	pullPath = regexp.MustCompile(`^/([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9._-]+)/pull/([1-9][0-9]{0,8})(?:/.*)?$`)
)

// ParseURL reads the address of a pull request's page, as an agent reports
// it. The address comes from the agent, so nothing is taken from it but
// the owner, the repository and the number, and only when it is a page of
// host.
func ParseURL(raw, host string) (Ref, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return Ref{}, fmt.Errorf("%q is not the address of a pull request", raw)
	}
	if !strings.EqualFold(u.Host, host) {
		return Ref{}, fmt.Errorf("%q is not on %s", raw, host)
	}
	m := pullPath.FindStringSubmatch(u.Path)
	if m == nil {
		return Ref{}, fmt.Errorf("%q is not the address of a pull request", raw)
	}
	n, _ := strconv.Atoi(m[3])
	return Ref{Owner: m[1], Repo: strings.TrimSuffix(m[2], ".git"), Number: n}, nil
}

var (
	scpRepo  = regexp.MustCompile(`^(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+):([^/:]+)/([^/]+)$`)
	repoPath = regexp.MustCompile(`^/([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9._-]+)$`)
)

// ParseRepo reads the owner and the name of a repository out of its
// address, as git clone takes it: https://host/owner/repo.git,
// ssh://git@host/owner/repo.git or git@host:owner/repo.git. It is an error
// when the address is not a repository on host.
func ParseRepo(raw, host string) (owner, repo string, err error) {
	raw = strings.TrimSpace(raw)
	var at, path string
	if m := scpRepo.FindStringSubmatch(raw); m != nil && !strings.Contains(raw, "://") {
		at, path = m[1], "/"+m[2]+"/"+m[3]
	} else if u, perr := url.Parse(raw); perr == nil && u.Host != "" {
		at, path = u.Hostname(), u.Path
	} else {
		return "", "", fmt.Errorf("%q is not the address of a repository", raw)
	}
	want := host
	if u, perr := url.Parse("//" + host); perr == nil && u.Hostname() != "" {
		want = u.Hostname()
	}
	if !strings.EqualFold(at, want) {
		return "", "", fmt.Errorf("%q is not on %s", raw, host)
	}
	m := repoPath.FindStringSubmatch(strings.TrimSuffix(strings.TrimSuffix(path, "/"), ".git"))
	if m == nil {
		return "", "", fmt.Errorf("%q is not the address of a repository", raw)
	}
	return m[1], m[2], nil
}

// File is a file of a repository, as its default branch has it.
type File struct {
	Content []byte
	// SHA is the hash that git gives the content.
	SHA string
}

// File reads one file from the default branch of a repository: no branch
// is named, and GitHub then answers from the default one. A file of more
// than limit bytes, and anything that is not a file, is an error.
func (c *Client) File(ctx context.Context, owner, repo, path string, limit int) (*File, error) {
	var in struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Size     int    `json:"size"`
		Content  string `json:"content"`
		SHA      string `json:"sha"`
	}
	ref := Ref{Owner: owner, Repo: repo}
	if err := c.get(ctx, ref.path("/contents/"+url.PathEscape(path)), &in); err != nil {
		return nil, err
	}
	switch {
	case in.Type != "file":
		return nil, fmt.Errorf("github api: %s in %s/%s is not a file", path, owner, repo)
	case in.Size > limit:
		return nil, fmt.Errorf("github api: %s in %s/%s has %d bytes; at most %d are read", path, owner, repo, in.Size, limit)
	case in.Encoding != "base64":
		return nil, fmt.Errorf("github api: %s in %s/%s: unknown encoding %q", path, owner, repo, in.Encoding)
	}
	// GitHub breaks the encoded content into lines.
	content, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\n", "", "\r", "").Replace(in.Content))
	if err != nil {
		return nil, fmt.Errorf("github api: %s in %s/%s: %w", path, owner, repo, err)
	}
	if len(content) > limit {
		return nil, fmt.Errorf("github api: %s in %s/%s has %d bytes; at most %d are read", path, owner, repo, len(content), limit)
	}
	return &File{Content: content, SHA: in.SHA}, nil
}

// Repository asks whether the token can see a repository. NotFound tells
// the error for one that it cannot see, or that does not exist.
func (c *Client) Repository(ctx context.Context, owner, repo string) error {
	var in struct{}
	return c.get(ctx, Ref{Owner: owner, Repo: repo}.path(""), &in)
}

// PullRequest is what ochell wants to know about a pull request.
type PullRequest struct {
	// State is "open" or "closed"; Merged says that it was closed by a
	// merge.
	State  string
	Merged bool
	// ClosedBy is the login of who merged it; for a pull request that was
	// closed without a merge GitHub does not say here.
	ClosedBy string
	// Author is the login of who opened it, and HeadRef the branch it
	// comes from.
	Author  string
	HeadRef string
	// HeadSHA is the commit at the head of that branch.
	HeadSHA string
}

// Error is an answer of the API that is not a success.
type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("github api: HTTP %d: %s", e.Status, e.Body)
}

// NotFound reports whether err says that GitHub has no such thing, or does
// not show it to this token.
func NotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, http.StatusOK, out)
}

// do sends one request and reads the answer into out. in, when not nil, is
// sent as JSON. An answer with another status than want is an *Error.
func (c *Client) do(ctx context.Context, method, path string, in any, want int, out any) error {
	var send io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		send = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.APIURL+path, send)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("github api: %w", err)
	}
	if resp.StatusCode != want {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		return &Error{Status: resp.StatusCode, Body: msg}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("github api: %s: %w", path, err)
	}
	return nil
}

func (r Ref) path(rest string) string {
	return "/repos/" + url.PathEscape(r.Owner) + "/" + url.PathEscape(r.Repo) + rest
}

// PullRequest reads one pull request.
func (c *Client) PullRequest(ctx context.Context, ref Ref) (*PullRequest, error) {
	var in struct {
		State    string `json:"state"`
		Merged   bool   `json:"merged"`
		MergedBy *struct {
			Login string `json:"login"`
		} `json:"merged_by"`
		User *struct {
			Login string `json:"login"`
		} `json:"user"`
		Head struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"head"`
	}
	if err := c.get(ctx, ref.path("/pulls/"+strconv.Itoa(ref.Number)), &in); err != nil {
		return nil, err
	}
	pr := &PullRequest{State: in.State, Merged: in.Merged, HeadRef: in.Head.Ref, HeadSHA: in.Head.SHA}
	if in.MergedBy != nil {
		pr.ClosedBy = in.MergedBy.Login
	}
	if in.User != nil {
		pr.Author = in.User.Login
	}
	return pr, nil
}

// States of the checks of a commit.
const (
	// ChecksNone: nothing checks this commit, as far as GitHub knows.
	ChecksNone = "none"
	// ChecksRunning: at least one check has not finished.
	ChecksRunning = "pending"
	ChecksPassed  = "passed"
	ChecksFailed  = "failed"
)

// Checks is the state of the checks of one commit.
type Checks struct {
	// State is ChecksNone, ChecksRunning, ChecksPassed or ChecksFailed. It
	// is ChecksFailed only when every check has finished and at least one
	// did not succeed, so that Failed is the whole list.
	State  string
	Failed []FailedCheck
}

// FailedCheck is one check that did not succeed.
type FailedCheck struct {
	Name string
	// Conclusion is what GitHub calls the end: failure, timed_out, …
	Conclusion string
	// Summary is what the check says about itself: its title and summary,
	// or the description of a commit status.
	Summary string
	URL     string
}

// maxSummary is how much of what a check says about itself is kept.
const maxSummary = 4000

// Checks reads the checks of a commit: its check runs (GitHub Actions and
// other apps) and its commit statuses (older integrations).
func (c *Client) Checks(ctx context.Context, ref Ref, sha string) (*Checks, error) {
	var runs struct {
		CheckRuns []struct {
			Name       string `json:"name"`
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
			HTMLURL    string `json:"html_url"`
			Output     struct {
				Title   string `json:"title"`
				Summary string `json:"summary"`
			} `json:"output"`
		} `json:"check_runs"`
	}
	if err := c.get(ctx, ref.path("/commits/"+url.PathEscape(sha)+"/check-runs?per_page=100"), &runs); err != nil {
		return nil, err
	}
	var status struct {
		Statuses []struct {
			State       string `json:"state"`
			Context     string `json:"context"`
			Description string `json:"description"`
			TargetURL   string `json:"target_url"`
		} `json:"statuses"`
	}
	if err := c.get(ctx, ref.path("/commits/"+url.PathEscape(sha)+"/status?per_page=100"), &status); err != nil {
		return nil, err
	}
	out := &Checks{State: ChecksNone}
	pending, total := false, 0
	for _, r := range runs.CheckRuns {
		total++
		if r.Status != "completed" {
			pending = true
			continue
		}
		switch r.Conclusion {
		case "success", "neutral", "skipped":
		default:
			summary := strings.TrimSpace(r.Output.Title + "\n" + r.Output.Summary)
			out.Failed = append(out.Failed, FailedCheck{Name: r.Name, Conclusion: r.Conclusion, Summary: clip(summary), URL: r.HTMLURL})
		}
	}
	for _, s := range status.Statuses {
		total++
		switch s.State {
		case "success":
		case "pending":
			pending = true
		default:
			out.Failed = append(out.Failed, FailedCheck{Name: s.Context, Conclusion: s.State, Summary: clip(s.Description), URL: s.TargetURL})
		}
	}
	switch {
	case total == 0:
	case pending:
		out.State, out.Failed = ChecksRunning, nil
	case len(out.Failed) > 0:
		out.State = ChecksFailed
	default:
		out.State = ChecksPassed
	}
	return out, nil
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxSummary {
		return strings.ToValidUTF8(s[:maxSummary], "") + " […]"
	}
	return s
}

// Comment is something a person wrote on a pull request: a comment in the
// conversation, a comment on a line of the diff, or the text of a review.
type Comment struct {
	// ID identifies the comment among the comments of its Kind, which is
	// "issue" (the conversation), "diff" (a line of the diff) or "review".
	ID     int64
	Kind   string
	Author string
	// Association is how GitHub relates the author to the repository:
	// OWNER, MEMBER, COLLABORATOR, CONTRIBUTOR, NONE, …
	Association string
	Body        string
	// Path is the file that a comment on the diff is about.
	Path string
	// Review is the state of a review: APPROVED, CHANGES_REQUESTED,
	// COMMENTED.
	Review  string
	Created time.Time
}

// Comments reads what was written on a pull request at or after since,
// oldest first: at most a hundred of each kind. GitHub's times are whole
// seconds, so the caller tells comments it has seen apart by Kind and ID.
func (c *Client) Comments(ctx context.Context, ref Ref, since time.Time) ([]Comment, error) {
	type raw struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
		Path string `json:"path"`
		// State is set for a review.
		State string `json:"state"`
		User  *struct {
			Login string `json:"login"`
		} `json:"user"`
		Association string    `json:"author_association"`
		Created     time.Time `json:"created_at"`
		Submitted   time.Time `json:"submitted_at"`
	}
	n := strconv.Itoa(ref.Number)
	var out []Comment
	for kind, path := range map[string]string{
		"issue":  ref.path("/issues/" + n + "/comments?per_page=100"),
		"diff":   ref.path("/pulls/" + n + "/comments?per_page=100"),
		"review": ref.path("/pulls/" + n + "/reviews?per_page=100"),
	} {
		var list []raw
		if err := c.get(ctx, path, &list); err != nil {
			return nil, err
		}
		for _, r := range list {
			at := r.Created
			if at.IsZero() {
				at = r.Submitted
			}
			if strings.TrimSpace(r.Body) == "" || at.Before(since) {
				continue
			}
			cm := Comment{ID: r.ID, Kind: kind, Association: r.Association, Body: r.Body, Path: r.Path, Review: r.State, Created: at}
			if r.User != nil {
				cm.Author = r.User.Login
			}
			out = append(out, cm)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.Before(out[j].Created)
		}
		return out[i].Kind+strconv.FormatInt(out[i].ID, 10) < out[j].Kind+strconv.FormatInt(out[j].ID, 10)
	})
	return out, nil
}
