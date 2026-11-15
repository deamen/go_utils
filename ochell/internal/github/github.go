// Package github is ochell's read-only access to GitHub: what became of
// the pull requests that its tickets opened. ochell only reads. It never
// merges, approves or pushes, and its token needs no permission to.
//
// It is not how the agent reaches GitHub; the agent has its own account.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.APIURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
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
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		return &Error{Status: resp.StatusCode, Body: msg}
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
