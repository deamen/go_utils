package linear

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"ochell/internal/tracker"
)

// What the poller needs from Linear, as the agent app user. The queries
// have names, so that a log or a test can tell them apart.

var (
	_ tracker.Source  = (*Client)(nil)
	_ tracker.Tickets = (*Client)(nil)
)

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
    nodes { identifier title url priority labels { nodes { name } } }
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
					Identifier string  `json:"identifier"`
					Title      string  `json:"title"`
					URL        string  `json:"url"`
					Priority   float64 `json:"priority"`
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
			is := tracker.Issue{Key: n.Identifier, Title: n.Title, URL: n.URL, Priority: Rank(n.Priority)}
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

// Rank turns the priority of a Linear issue into a rank. Linear counts
// from 1 (urgent) to 4 (low), which is a rank already; 0 is no priority,
// and so is anything else.
func Rank(priority float64) int {
	if priority >= 1 && priority <= 4 {
		return int(priority)
	}
	return 0
}

const schedulingQuery = `query OchellScheduling($id: String!) {
  viewer { id }
  issue(id: $id) {
    priority
    creator { id email }
    labels { nodes { name } }
    inverseRelations { nodes { type issue { identifier state { type } } } }
    history(first: 100) { nodes { createdAt actor { id email } addedLabels { name } } }
  }
}`

// Scheduling asks what decides when the work on an issue starts: its
// priority, its labels with who added each, and the open issues that
// block it (a relation of the type "blocks" that points at this issue).
//
// Who added a label is the actor of the last change in the issue's
// history that added it; a label without such a change was there when the
// issue was created, and is its creator's.
//
// It is a query of its own, so that a field that Linear does not have
// breaks neither Assigner nor Lookup.
func (c *Client) Scheduling(ctx context.Context, key string) (tracker.Scheduling, error) {
	var out tracker.Scheduling
	var reply struct {
		Viewer struct {
			ID string `json:"id"`
		} `json:"viewer"`
		Issue *struct {
			Priority float64 `json:"priority"`
			Creator  *person `json:"creator"`
			Labels   struct {
				Nodes []struct {
					Name string `json:"name"`
				} `json:"nodes"`
			} `json:"labels"`
			InverseRelations struct {
				Nodes []struct {
					Type  string `json:"type"`
					Issue *struct {
						Identifier string `json:"identifier"`
						State      *struct {
							Type string `json:"type"`
						} `json:"state"`
					} `json:"issue"`
				} `json:"nodes"`
			} `json:"inverseRelations"`
			History struct {
				Nodes []struct {
					CreatedAt   string  `json:"createdAt"`
					Actor       *person `json:"actor"`
					AddedLabels []struct {
						Name string `json:"name"`
					} `json:"addedLabels"`
				} `json:"nodes"`
			} `json:"history"`
		} `json:"issue"`
	}
	if err := c.Do(ctx, schedulingQuery, map[string]any{"id": key}, &reply); err != nil {
		if strings.Contains(err.Error(), "Entity not found") {
			return out, tracker.ErrNotFound
		}
		return out, err
	}
	is := reply.Issue
	if is == nil {
		return out, tracker.ErrNotFound
	}
	out.Priority = Rank(is.Priority)
	for _, l := range is.Labels.Nodes {
		if l.Name == "" {
			continue
		}
		who, when := is.Creator, ""
		for _, n := range is.History.Nodes {
			for _, added := range n.AddedLabels {
				// The timestamps are in one format, so they compare as
				// text.
				if added.Name == l.Name && n.Actor != nil && n.CreatedAt >= when {
					who, when = n.Actor, n.CreatedAt
				}
			}
		}
		label := tracker.Label{Name: l.Name}
		if who != nil {
			for _, id := range []string{who.ID, who.Email} {
				if id != "" {
					label.By = append(label.By, id)
				}
			}
			label.Bot = who.ID != "" && who.ID == reply.Viewer.ID
		}
		out.Labels = append(out.Labels, label)
	}
	for _, r := range is.InverseRelations.Nodes {
		if r.Type != "blocks" || r.Issue == nil || r.Issue.Identifier == "" {
			continue
		}
		if s := r.Issue.State; s != nil && (s.Type == "completed" || s.Type == "canceled") {
			continue
		}
		out.BlockedBy = append(out.BlockedBy, r.Issue.Identifier)
	}
	return out, nil
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

const ticketQuery = `query OchellTicket($id: String!, $comments: Int!) {
  viewer { id }
  issue(id: $id) {
    id identifier title description url
    state { name }
    labels { nodes { name } }
    comments(first: $comments, orderBy: createdAt) {
      nodes { body createdAt user { id name } botActor { name } }
      pageInfo { hasNextPage }
    }
  }
}`

// ticket is what Ticket and Comment read of one issue.
type ticket struct {
	Viewer struct {
		ID string `json:"id"`
	} `json:"viewer"`
	Issue *struct {
		ID          string `json:"id"`
		Identifier  string `json:"identifier"`
		Title       string `json:"title"`
		Description string `json:"description"`
		URL         string `json:"url"`
		State       *struct {
			Name string `json:"name"`
		} `json:"state"`
		Labels struct {
			Nodes []struct {
				Name string `json:"name"`
			} `json:"nodes"`
		} `json:"labels"`
		Comments struct {
			Nodes []struct {
				Body      string `json:"body"`
				CreatedAt string `json:"createdAt"`
				User      *struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"user"`
				BotActor *struct {
					Name string `json:"name"`
				} `json:"botActor"`
			} `json:"nodes"`
			PageInfo struct {
				HasNextPage bool `json:"hasNextPage"`
			} `json:"pageInfo"`
		} `json:"comments"`
	} `json:"issue"`
}

func (c *Client) ticket(ctx context.Context, key string, comments int) (*ticket, error) {
	var out ticket
	if err := c.Do(ctx, ticketQuery, map[string]any{"id": key, "comments": comments}, &out); err != nil {
		if strings.Contains(err.Error(), "Entity not found") {
			return nil, tracker.ErrNotFound
		}
		return nil, err
	}
	if out.Issue == nil {
		return nil, tracker.ErrNotFound
	}
	return &out, nil
}

// Ticket returns one issue as a person sees it: its title, description,
// state and labels, and its newest comments.
//
// The comments are the first page that Linear returns, which is taken to
// hold the newest; that was not checked against Linear. They are sorted
// here, so that their order does not depend on Linear's. Linear does not
// say how many comments an issue has; MoreComments is 1 when there are
// more.
func (c *Client) Ticket(ctx context.Context, key string) (tracker.Ticket, error) {
	t, err := c.ticket(ctx, key, tracker.MaxComments)
	if err != nil {
		return tracker.Ticket{}, err
	}
	is := t.Issue
	out := tracker.Ticket{Key: key, Title: is.Title, URL: is.URL, Description: is.Description}
	if is.State != nil {
		out.Status = is.State.Name
	}
	for _, l := range is.Labels.Nodes {
		if l.Name != "" {
			out.Labels = append(out.Labels, l.Name)
		}
	}
	for _, n := range is.Comments.Nodes {
		one := tracker.Comment{Body: n.Body}
		one.At, _ = time.Parse(time.RFC3339, n.CreatedAt)
		switch {
		case n.User != nil:
			one.Author, one.Bot = n.User.Name, n.User.ID != "" && n.User.ID == t.Viewer.ID
		case n.BotActor != nil:
			// An integration wrote it; the app's own comments are among
			// these when Linear does not name the app's user.
			one.Author = n.BotActor.Name
		}
		out.Comments = append(out.Comments, one)
	}
	slices.SortStableFunc(out.Comments, func(a, b tracker.Comment) int { return a.At.Compare(b.At) })
	if is.Comments.PageInfo.HasNextPage {
		out.MoreComments = 1
	}
	return out, nil
}

const commentMutation = `mutation OchellComment($input: CommentCreateInput!) {
  commentCreate(input: $input) { success }
}`

// Comment adds a comment to an issue, as the agent app. The mutation wants
// the id of the issue, not its key, so that is asked for first.
func (c *Client) Comment(ctx context.Context, key, body string) error {
	t, err := c.ticket(ctx, key, 1)
	if err != nil {
		return err
	}
	var out struct {
		Create struct {
			Success bool `json:"success"`
		} `json:"commentCreate"`
	}
	if err := c.Do(ctx, commentMutation, map[string]any{"input": map[string]any{"issueId": t.Issue.ID, "body": body}}, &out); err != nil {
		return err
	}
	if !out.Create.Success {
		return errors.New("linear api: the comment was not created")
	}
	return nil
}
