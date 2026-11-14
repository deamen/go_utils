package linear

import (
	"context"
	"errors"
	"fmt"

	"ochell/internal/tracker"
)

// What the poller needs from Linear, as the agent app user. The queries
// have names, so that a log or a test can tell them apart.

var _ tracker.Source = (*Client)(nil)

const (
	issuePage = 50
	// maxIssuePages bounds one listing. More issues than this is an error,
	// not a shortened list.
	maxIssuePages = 40
)

const assignedQuery = `query OchellAssigned($first: Int!, $after: String) {
  issues(first: $first, after: $after, filter: {
    delegate: { isMe: { eq: true } },
    state: { type: { nin: ["completed", "canceled"] } }
  }) {
    nodes { identifier title url labels { nodes { name } } }
    pageInfo { hasNextPage endCursor }
  }
}`

// Assigned returns every open issue that is delegated to the agent.
func (c *Client) Assigned(ctx context.Context) ([]tracker.Issue, error) {
	var issues []tracker.Issue
	var after any
	for range maxIssuePages {
		var out struct {
			Issues struct {
				Nodes []struct {
					Identifier string `json:"identifier"`
					Title      string `json:"title"`
					URL        string `json:"url"`
					Labels     struct {
						Nodes []struct {
							Name string `json:"name"`
						} `json:"nodes"`
					} `json:"labels"`
				} `json:"nodes"`
				PageInfo struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
			} `json:"issues"`
		}
		if err := c.Do(ctx, assignedQuery, map[string]any{"first": issuePage, "after": after}, &out); err != nil {
			return nil, err
		}
		for _, n := range out.Issues.Nodes {
			if n.Identifier == "" {
				continue
			}
			is := tracker.Issue{Key: n.Identifier, Title: n.Title, URL: n.URL}
			for _, l := range n.Labels.Nodes {
				if l.Name != "" {
					is.Labels = append(is.Labels, l.Name)
				}
			}
			issues = append(issues, is)
		}
		if !out.Issues.PageInfo.HasNextPage || out.Issues.PageInfo.EndCursor == "" {
			return issues, nil
		}
		after = out.Issues.PageInfo.EndCursor
	}
	return nil, fmt.Errorf("linear api: more than %d issues are delegated to the agent", maxIssuePages*issuePage)
}

type person struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// issueHistory is what Assigner and Lookup read of one issue.
type issueHistory struct {
	Viewer struct {
		ID string `json:"id"`
	} `json:"viewer"`
	Issue *struct {
		Creator *person `json:"creator"`
		State   *struct {
			Type string `json:"type"`
		} `json:"state"`
		Delegate *person `json:"delegate"`
		History  struct {
			Nodes []struct {
				CreatedAt  string  `json:"createdAt"`
				Actor      *person `json:"actor"`
				ToDelegate *person `json:"toDelegate"`
			} `json:"nodes"`
		} `json:"history"`
	} `json:"issue"`
}

const historyQuery = `query OchellIssue($id: String!) {
  viewer { id }
  issue(id: $id) {
    creator { id email }
    state { type }
    delegate { id }
    history(first: 100) { nodes { createdAt actor { id email } toDelegate { id } } }
  }
}`

func (c *Client) history(ctx context.Context, key string) (*issueHistory, error) {
	var out issueHistory
	if err := c.Do(ctx, historyQuery, map[string]any{"id": key}, &out); err != nil {
		return nil, err
	}
	if out.Issue == nil {
		return nil, fmt.Errorf("linear api: no issue %s", key)
	}
	return &out, nil
}

// Assigner returns the id and the email address of who delegated the issue
// to the agent: the actor of the last change of the delegate to the agent,
// or the creator of an issue that has no such change.
func (c *Client) Assigner(ctx context.Context, key string) ([]string, error) {
	h, err := c.history(ctx, key)
	if err != nil {
		return nil, err
	}
	who, when := h.Issue.Creator, ""
	for _, n := range h.Issue.History.Nodes {
		// The timestamps are in one format, so they compare as text.
		if n.ToDelegate != nil && n.ToDelegate.ID == h.Viewer.ID && n.Actor != nil && n.CreatedAt >= when {
			who, when = n.Actor, n.CreatedAt
		}
	}
	if who == nil {
		return nil, nil
	}
	var ids []string
	for _, id := range []string{who.ID, who.Email} {
		if id != "" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// Lookup asks about one issue. Unassigned means that the issue was once
// delegated to the agent and no longer is; an issue that the agent was only
// mentioned on was never its own.
func (c *Client) Lookup(ctx context.Context, key string) (tracker.Status, error) {
	h, err := c.history(ctx, key)
	if err != nil {
		return tracker.Status{}, err
	}
	var st tracker.Status
	if s := h.Issue.State; s != nil {
		st.Closed = s.Type == "completed" || s.Type == "canceled"
	}
	mine := h.Issue.Delegate != nil && h.Issue.Delegate.ID == h.Viewer.ID
	was := false
	for _, n := range h.Issue.History.Nodes {
		if n.ToDelegate != nil && n.ToDelegate.ID == h.Viewer.ID {
			was = true
		}
	}
	st.Unassigned = was && !mine
	return st, nil
}

const sessionCreateMutation = `mutation OchellSessionCreate($input: AgentSessionCreateOnIssue!) {
  agentSessionCreateOnIssue(input: $input) { success agentSession { id } }
}`

// CreateSessionOnIssue starts an agent session on an issue and returns its
// id. Work that ochell finds itself, not through a webhook, has no session
// to report to until it creates one.
func (c *Client) CreateSessionOnIssue(ctx context.Context, key string) (string, error) {
	var out struct {
		Create struct {
			Success      bool `json:"success"`
			AgentSession *struct {
				ID string `json:"id"`
			} `json:"agentSession"`
		} `json:"agentSessionCreateOnIssue"`
	}
	if err := c.Do(ctx, sessionCreateMutation, map[string]any{"input": map[string]any{"issueId": key}}, &out); err != nil {
		return "", err
	}
	if out.Create.AgentSession == nil || out.Create.AgentSession.ID == "" {
		return "", errors.New("linear api: the session was not created")
	}
	return out.Create.AgentSession.ID, nil
}
