package github

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// The issues of the GitHub source. A pull request is an issue here, as it
// is in GitHub's API. ochell reads issues and their history, and writes
// one thing: a comment. All of it is done with the token of the source,
// which needs read and write access to issues (and to pull requests, when
// pull requests are assigned to the bot) and nothing else.

// Issue is one issue or pull request, as far as ochell needs it.
type Issue struct {
	Number int
	Title  string
	Body   string
	// URL is the page of the issue for a person.
	URL string
	// State is "open" or "closed".
	State string
	// Author is the login of who opened it.
	Author    string
	Labels    []string
	Assignees []string
	// Type is the name of the issue type, where the organization has
	// issue types; "" otherwise.
	Type string
	// PullRequest: the issue is a pull request.
	PullRequest bool
	// Comments is how many comments the conversation has.
	Comments int
}

// rawIssue is an issue as the API sends it.
type rawIssue struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
	State   string `json:"state"`
	User    *struct {
		Login string `json:"login"`
	} `json:"user"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
	Assignees []struct {
		Login string `json:"login"`
	} `json:"assignees"`
	Type *struct {
		Name string `json:"name"`
	} `json:"type"`
	PullRequest *struct{} `json:"pull_request"`
	Comments    int       `json:"comments"`
}

func (r rawIssue) issue() Issue {
	is := Issue{Number: r.Number, Title: r.Title, Body: r.Body, URL: r.HTMLURL, State: r.State, PullRequest: r.PullRequest != nil, Comments: r.Comments}
	if r.User != nil {
		is.Author = r.User.Login
	}
	if r.Type != nil {
		is.Type = r.Type.Name
	}
	for _, l := range r.Labels {
		is.Labels = append(is.Labels, l.Name)
	}
	for _, a := range r.Assignees {
		is.Assignees = append(is.Assignees, a.Login)
	}
	return is
}

// perPage is how many entries of a list ochell asks for at once, and
// maxPages how many times it asks. A list that is longer is an error: a
// part of a list is never taken for the whole.
const (
	perPage  = 100
	maxPages = 10
)

// list reads every page of a list.
func list[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	var out []T
	for page := 1; page <= maxPages; page++ {
		var part []T
		if err := c.get(ctx, fmt.Sprintf("%s%sper_page=%d&page=%d", path, sep, perPage, page), &part); err != nil {
			return nil, err
		}
		out = append(out, part...)
		if len(part) < perPage {
			return out, nil
		}
	}
	return nil, fmt.Errorf("github api: %s has more than %d entries; ochell reads no more", path, perPage*maxPages)
}

// Issue reads one issue or pull request.
func (c *Client) Issue(ctx context.Context, ref Ref) (*Issue, error) {
	var in rawIssue
	if err := c.get(ctx, ref.path("/issues/"+strconv.Itoa(ref.Number)), &in); err != nil {
		return nil, err
	}
	is := in.issue()
	return &is, nil
}

// AssignedIssues returns every open issue and pull request of a
// repository that is assigned to login. It returns an error rather than a
// part of the list.
func (c *Client) AssignedIssues(ctx context.Context, owner, repo, login string) ([]Issue, error) {
	raw, err := list[rawIssue](ctx, c, Ref{Owner: owner, Repo: repo}.path("/issues?state=open&assignee="+url.QueryEscape(login)))
	if err != nil {
		return nil, err
	}
	out := make([]Issue, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.issue())
	}
	return out, nil
}

// IssueEvent is one entry of the history of an issue.
type IssueEvent struct {
	// Event is what happened: assigned, unassigned, labeled, unlabeled, …
	Event string
	// Actor is the login of who did it.
	Actor string
	// Assignee is who an issue was assigned to or taken from.
	Assignee string
	// Label is the label that was added or removed.
	Label string
}

// IssueEvents reads the history of an issue, oldest first. It returns an
// error rather than a part of it.
func (c *Client) IssueEvents(ctx context.Context, ref Ref) ([]IssueEvent, error) {
	type login struct {
		Login string `json:"login"`
	}
	raw, err := list[struct {
		Event    string `json:"event"`
		Actor    *login `json:"actor"`
		Assigner *login `json:"assigner"`
		Assignee *login `json:"assignee"`
		Label    *struct {
			Name string `json:"name"`
		} `json:"label"`
	}](ctx, c, ref.path("/issues/"+strconv.Itoa(ref.Number)+"/events"))
	if err != nil {
		return nil, err
	}
	out := make([]IssueEvent, 0, len(raw))
	for _, r := range raw {
		ev := IssueEvent{Event: r.Event}
		if r.Actor != nil {
			ev.Actor = r.Actor.Login
		}
		// For an assignment GitHub names who assigned apart from the actor.
		if r.Assigner != nil && r.Assigner.Login != "" {
			ev.Actor = r.Assigner.Login
		}
		if r.Assignee != nil {
			ev.Assignee = r.Assignee.Login
		}
		if r.Label != nil {
			ev.Label = r.Label.Name
		}
		out = append(out, ev)
	}
	return out, nil
}

// maxComment is how long a comment may be; GitHub takes 65536 characters.
const maxComment = 60000

// CommentOnIssue adds a comment to the conversation of an issue or pull
// request. It is the one thing that ochell writes on GitHub.
func (c *Client) CommentOnIssue(ctx context.Context, ref Ref, body string) error {
	if len(body) > maxComment {
		body = strings.ToValidUTF8(body[:maxComment], "") + " […]"
	}
	return c.do(ctx, http.MethodPost, ref.path("/issues/"+strconv.Itoa(ref.Number)+"/comments"), map[string]string{"body": body}, http.StatusCreated, nil)
}

// Login returns the login of the account that the token belongs to.
func (c *Client) Login(ctx context.Context) (string, error) {
	var in struct {
		Login string `json:"login"`
	}
	if err := c.get(ctx, "/user", &in); err != nil {
		return "", err
	}
	if in.Login == "" {
		return "", fmt.Errorf("github api: /user names no login")
	}
	return in.Login, nil
}
