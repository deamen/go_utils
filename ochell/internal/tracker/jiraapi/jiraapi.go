// Package jiraapi is ochell's client for the Jira Cloud REST API, with the
// bot account's API token. It is the only place that calls the Jira API;
// everything else uses tracker.Client.
package jiraapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
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
}

var _ tracker.Client = (*Client)(nil)

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
			"fields":     []string{"summary", "labels", "components"},
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
			issues = append(issues, tracker.Issue{
				Key:    is.Key,
				Title:  is.Fields.Summary,
				URL:    c.BaseURL + "/browse/" + is.Key,
				Labels: labels,
			})
		}
		if token = page.NextPageToken; token == "" {
			return issues, nil
		}
	}
	return nil, fmt.Errorf("jira api: the search returns more than %d tickets; narrow sources.jira_api.jql", maxPages*pageSize)
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
