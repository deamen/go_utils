// Package jiraapi is ochell's client for the Jira Cloud REST API, with the
// bot account's API token. It is the only place that calls the Jira API;
// everything else uses tracker.Client.
package jiraapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"ochell/internal/config"
	"ochell/internal/tracker"
)

// DefaultJQL finds the open tickets of the account that owns the token.
const DefaultJQL = `assignee = currentUser() AND statusCategory != Done`

const (
	pageSize = 100
	// maxPages bounds one search. More tickets than this is an error, not a
	// shortened list.
	maxPages = 50
	maxReply = 4 << 20
)

// Client implements tracker.Client for one Jira site.
type Client struct {
	HTTP *http.Client
	// BaseURL is the site, e.g. https://example.atlassian.net, without a
	// trailing slash.
	BaseURL string
	Email   string
	Token   string
	// JQL selects the tickets that Assigned returns.
	JQL string

	mu sync.Mutex
	// me is the accountId of the account that owns the token.
	me string
}

var (
	_ tracker.Client  = (*Client)(nil)
	_ tracker.Source  = (*Client)(nil)
	_ tracker.Tickets = (*Client)(nil)
)

// New returns the client for sources.jira_api.
func New(cfg config.JiraAPI) *Client {
	jql := cfg.JQL
	if jql == "" {
		jql = DefaultJQL
	}
	return &Client{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		BaseURL: strings.TrimRight(cfg.BaseURL, "/"),
		Email:   cfg.Email,
		Token:   cfg.Token,
		JQL:     jql,
	}
}

// Error is an answer of the Jira API that is not a success.
type Error struct {
	Status int
	// Body is the start of the response, which usually says what is wrong.
	Body string
}

func (e *Error) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("jira api: HTTP %d", e.Status)
	}
	return fmt.Sprintf("jira api: HTTP %d: %s", e.Status, e.Body)
}

// validKey is what a ticket key may look like before it goes into a path.
var validKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// do sends one request with a JSON body (nil: none) and decodes the JSON
// answer into out (nil: the answer is not read).
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.Email, c.Token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// The error of net/http holds the URL, never the credentials.
		return fmt.Errorf("jira api: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxReply))
	if err != nil {
		return fmt.Errorf("jira api: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		text := strings.Join(strings.Fields(string(raw)), " ")
		if len(text) > 300 {
			text = text[:300] + "…"
		}
		return &Error{Status: resp.StatusCode, Body: text}
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("jira api: %s %s: %w", method, path, err)
	}
	return nil
}

type searchReply struct {
	Issues []struct {
		Key    string `json:"key"`
		Fields struct {
			Summary    string   `json:"summary"`
			Labels     []string `json:"labels"`
			Components []struct {
				Name string `json:"name"`
			} `json:"components"`
			IssueType struct {
				Name string `json:"name"`
			} `json:"issuetype"`
			Priority *struct {
				Name string `json:"name"`
			} `json:"priority"`
		} `json:"fields"`
	} `json:"issues"`
	NextPageToken string `json:"nextPageToken"`
}

// Assigned returns the tickets that the JQL selects: by default the open
// tickets assigned to the account that owns the token.
func (c *Client) Assigned(ctx context.Context) ([]tracker.Issue, error) {
	var issues []tracker.Issue
	token := ""
	for range maxPages {
		in := map[string]any{
			"jql":        c.JQL,
			"fields":     []string{"summary", "labels", "components", "issuetype", "priority"},
			"maxResults": pageSize,
		}
		if token != "" {
			in["nextPageToken"] = token
		}
		var page searchReply
		if err := c.do(ctx, http.MethodPost, "/rest/api/3/search/jql", in, &page); err != nil {
			return nil, err
		}
		for _, is := range page.Issues {
			if !validKey.MatchString(is.Key) {
				continue
			}
			labels := append([]string{}, is.Fields.Labels...)
			for _, comp := range is.Fields.Components {
				if comp.Name != "" {
					labels = append(labels, comp.Name)
				}
			}
			out := tracker.Issue{
				Key:    is.Key,
				Title:  is.Fields.Summary,
				URL:    c.BaseURL + "/browse/" + is.Key,
				Labels: labels,
				Type:   is.Fields.IssueType.Name,
			}
			if p := is.Fields.Priority; p != nil {
				out.PriorityName = p.Name
			}
			issues = append(issues, out)
		}
		if token = page.NextPageToken; token == "" {
			return issues, nil
		}
	}
	return nil, fmt.Errorf("jira api: the search returns more than %d tickets; narrow sources.jira_api.jql", maxPages*pageSize)
}

// myself returns the accountId of the account that owns the token: the bot.
func (c *Client) myself(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.me != "" {
		return c.me, nil
	}
	var who struct {
		AccountID string `json:"accountId"`
	}
	if err := c.do(ctx, http.MethodGet, "/rest/api/2/myself", nil, &who); err != nil {
		return "", err
	}
	if who.AccountID == "" {
		return "", errors.New("jira api: the account of the token has no accountId")
	}
	c.me = who.AccountID
	return c.me, nil
}

// Account returns the accountId of the account that owns the token: the
// account that everything ochell writes to Jira comes from.
func (c *Client) Account(ctx context.Context) (string, error) { return c.myself(ctx) }

type account struct {
	AccountID string `json:"accountId"`
}

// Assigner returns the accountId of who assigned the ticket to the bot:
// the author of the last change of the assignee to the bot, or the creator
// of a ticket that never had such a change.
func (c *Client) Assigner(ctx context.Context, key string) ([]string, error) {
	me, err := c.myself(ctx)
	if err != nil {
		return nil, err
	}
	path, err := issuePath(key, "?fields=creator&expand=changelog")
	if err != nil {
		return nil, err
	}
	var is struct {
		Fields struct {
			Creator *account `json:"creator"`
		} `json:"fields"`
		Changelog struct {
			Histories []struct {
				Created string   `json:"created"`
				Author  *account `json:"author"`
				Items   []struct {
					Field string `json:"field"`
					To    string `json:"to"`
				} `json:"items"`
			} `json:"histories"`
		} `json:"changelog"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &is); err != nil {
		return nil, err
	}
	who, when := "", ""
	for _, h := range is.Changelog.Histories {
		for _, it := range h.Items {
			// The timestamps are in one format, so they compare as text.
			if it.Field == "assignee" && it.To == me && h.Author != nil && h.Created >= when {
				who, when = h.Author.AccountID, h.Created
			}
		}
	}
	if who == "" && is.Fields.Creator != nil {
		who = is.Fields.Creator.AccountID
	}
	if who == "" {
		return nil, nil
	}
	return []string{who}, nil
}

// Lookup asks about one ticket. A ticket that Jira does not show any more
// counts as closed.
func (c *Client) Lookup(ctx context.Context, key string) (tracker.Status, error) {
	me, err := c.myself(ctx)
	if err != nil {
		return tracker.Status{}, err
	}
	path, err := issuePath(key, "?fields=assignee,status")
	if err != nil {
		return tracker.Status{}, err
	}
	var is struct {
		Fields struct {
			Assignee *account `json:"assignee"`
			Status   struct {
				Category struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"status"`
		} `json:"fields"`
	}
	err = c.do(ctx, http.MethodGet, path, nil, &is)
	var apiErr *Error
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
		return tracker.Status{Closed: true}, nil
	}
	if err != nil {
		return tracker.Status{}, err
	}
	return tracker.Status{
		Closed:     is.Fields.Status.Category.Key == "done",
		Unassigned: is.Fields.Assignee == nil || is.Fields.Assignee.AccountID != me,
	}, nil
}

// blockedByLink is how Jira describes, from the side of the blocked ticket,
// the link that says one ticket blocks another.
const blockedByLink = "is blocked by"

// Scheduling asks what decides when the work on a ticket starts: its
// priority, its labels and components with who added each, and the open
// tickets that it "is blocked by".
//
// Who added a label is the author of the last change in the ticket's
// history that added it; a label without such a change was there when the
// ticket was created, and is its creator's.
func (c *Client) Scheduling(ctx context.Context, key string) (tracker.Scheduling, error) {
	var out tracker.Scheduling
	me, err := c.myself(ctx)
	if err != nil {
		return out, err
	}
	path, err := issuePath(key, "?fields=priority,labels,components,issuelinks,creator&expand=changelog")
	if err != nil {
		return out, err
	}
	var is struct {
		Fields struct {
			Priority *struct {
				Name string `json:"name"`
			} `json:"priority"`
			Labels     []string `json:"labels"`
			Components []struct {
				Name string `json:"name"`
			} `json:"components"`
			Creator    *account `json:"creator"`
			IssueLinks []struct {
				Type struct {
					Inward string `json:"inward"`
				} `json:"type"`
				InwardIssue *struct {
					Key    string `json:"key"`
					Fields struct {
						Status struct {
							Category struct {
								Key string `json:"key"`
							} `json:"statusCategory"`
						} `json:"status"`
					} `json:"fields"`
				} `json:"inwardIssue"`
			} `json:"issuelinks"`
		} `json:"fields"`
		Changelog struct {
			Histories []struct {
				Created string   `json:"created"`
				Author  *account `json:"author"`
				Items   []struct {
					Field      string `json:"field"`
					FromString string `json:"fromString"`
					ToString   string `json:"toString"`
				} `json:"items"`
			} `json:"histories"`
		} `json:"changelog"`
	}
	err = c.do(ctx, http.MethodGet, path, nil, &is)
	var apiErr *Error
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
		return out, tracker.ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if p := is.Fields.Priority; p != nil {
		out.PriorityName = p.Name
	}
	// by returns who added a label, or a component.
	by := func(name string, component bool) string {
		who, when := "", ""
		for _, h := range is.Changelog.Histories {
			for _, it := range h.Items {
				added := false
				switch {
				case component:
					added = it.Field == "Component" && it.ToString == name
				case it.Field == "labels":
					// Both sides are the labels of the ticket, with
					// spaces between them.
					added = slices.Contains(strings.Fields(it.ToString), name) && !slices.Contains(strings.Fields(it.FromString), name)
				}
				// The timestamps are in one format, so they compare as
				// text.
				if added && h.Author != nil && h.Created >= when {
					who, when = h.Author.AccountID, h.Created
				}
			}
		}
		if who == "" && is.Fields.Creator != nil {
			who = is.Fields.Creator.AccountID
		}
		return who
	}
	label := func(name string, component bool) tracker.Label {
		l := tracker.Label{Name: name}
		if who := by(name, component); who != "" {
			l.By, l.Bot = []string{who}, who == me
		}
		return l
	}
	for _, name := range is.Fields.Labels {
		out.Labels = append(out.Labels, label(name, false))
	}
	for _, comp := range is.Fields.Components {
		if comp.Name != "" {
			out.Labels = append(out.Labels, label(comp.Name, true))
		}
	}
	for _, l := range is.Fields.IssueLinks {
		if l.InwardIssue == nil || l.InwardIssue.Key == "" || !strings.EqualFold(strings.TrimSpace(l.Type.Inward), blockedByLink) {
			continue
		}
		if l.InwardIssue.Fields.Status.Category.Key != "done" {
			out.BlockedBy = append(out.BlockedBy, l.InwardIssue.Key)
		}
	}
	return out, nil
}

// jiraTime is how Jira writes a point in time.
const jiraTime = "2006-01-02T15:04:05.000-0700"

// Ticket returns one ticket as a person sees it: its summary, description,
// status, labels and components, and its newest comments. Version 2 of the
// API gives the description and the comments as text, where version 3
// gives a document tree.
func (c *Client) Ticket(ctx context.Context, key string) (tracker.Ticket, error) {
	var out tracker.Ticket
	me, err := c.myself(ctx)
	if err != nil {
		return out, err
	}
	path, err := issuePath(key, "?fields=summary,description,status,labels,components")
	if err != nil {
		return out, err
	}
	var is struct {
		Key    string `json:"key"`
		Fields struct {
			Summary     string   `json:"summary"`
			Description string   `json:"description"`
			Labels      []string `json:"labels"`
			Components  []struct {
				Name string `json:"name"`
			} `json:"components"`
			Status struct {
				Name string `json:"name"`
			} `json:"status"`
		} `json:"fields"`
	}
	notFound := func(err error) error {
		var apiErr *Error
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
			return tracker.ErrNotFound
		}
		return err
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &is); err != nil {
		return out, notFound(err)
	}
	out = tracker.Ticket{Key: key, Title: is.Fields.Summary, URL: c.BaseURL + "/browse/" + key,
		Description: is.Fields.Description, Status: is.Fields.Status.Name, Labels: append([]string{}, is.Fields.Labels...)}
	for _, comp := range is.Fields.Components {
		if comp.Name != "" {
			out.Labels = append(out.Labels, comp.Name)
		}
	}
	// The comments are a request of their own: the newest first, so that a
	// ticket with many comments costs one page.
	path, err = issuePath(key, fmt.Sprintf("/comment?orderBy=-created&maxResults=%d", tracker.MaxComments))
	if err != nil {
		return out, err
	}
	var page struct {
		Total    int `json:"total"`
		Comments []struct {
			Author *struct {
				AccountID   string `json:"accountId"`
				DisplayName string `json:"displayName"`
			} `json:"author"`
			Body    string `json:"body"`
			Created string `json:"created"`
		} `json:"comments"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &page); err != nil {
		return out, notFound(err)
	}
	for _, cm := range page.Comments {
		one := tracker.Comment{Body: cm.Body}
		if cm.Author != nil {
			one.Author, one.Bot = cm.Author.DisplayName, cm.Author.AccountID == me
		}
		one.At, _ = time.Parse(jiraTime, cm.Created)
		out.Comments = append(out.Comments, one)
	}
	if len(out.Comments) > tracker.MaxComments {
		out.Comments = out.Comments[:tracker.MaxComments]
	}
	slices.Reverse(out.Comments)
	out.MoreComments = max(page.Total-len(out.Comments), 0)
	return out, nil
}

func issuePath(key, rest string) (string, error) {
	if !validKey.MatchString(key) {
		return "", fmt.Errorf("jira api: %q is not a ticket key", key)
	}
	return "/rest/api/2/issue/" + url.PathEscape(key) + rest, nil
}

// Comment adds a comment to a ticket. The body is plain text; version 2 of
// the API takes it as it is, where version 3 wants a document tree.
func (c *Client) Comment(ctx context.Context, key, body string) error {
	path, err := issuePath(key, "/comment")
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, path, map[string]string{"body": body}, nil)
}

// SetStatus moves a ticket to the status with this name, by the transition
// of the ticket's workflow that leads there. The name of the transition
// itself is accepted too. Upper and lower case are not told apart.
func (c *Client) SetStatus(ctx context.Context, key, status string) error {
	path, err := issuePath(key, "/transitions")
	if err != nil {
		return err
	}
	var reply struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			To   struct {
				Name string `json:"name"`
			} `json:"to"`
		} `json:"transitions"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &reply); err != nil {
		return err
	}
	id := ""
	var possible []string
	for _, t := range reply.Transitions {
		possible = append(possible, t.To.Name)
		if id == "" && (strings.EqualFold(t.To.Name, status) || strings.EqualFold(t.Name, status)) {
			id = t.ID
		}
	}
	if id == "" {
		return fmt.Errorf("jira api: %s cannot move to %q from its current status; possible: %s", key, status, strings.Join(possible, ", "))
	}
	return c.do(ctx, http.MethodPost, path, map[string]any{"transition": map[string]string{"id": id}}, nil)
}
