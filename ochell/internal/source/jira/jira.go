// Package jira parses Jira Cloud native webhooks and Automation
// "Send web request" payloads into tasks.
package jira

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrIgnored marks a valid payload that does not represent an assignment to
// the digital employee. Handlers answer 200 so Atlassian does not retry.
var ErrIgnored = errors.New("event ignored")

// ErrStale marks a payload whose timestamp is missing or too far from now.
var ErrStale = errors.New("webhook timestamp outside allowed skew")

// CheckTimestamp rejects a payload whose "timestamp" (milliseconds, set by
// Jira when the event happened) is more than maxSkew away from now. A
// captured request can then not be replayed later; within maxSkew the
// server's de-duplication of the signed body protects against replay.
func CheckTimestamp(body []byte, maxSkew time.Duration, now time.Time) error {
	var ts struct {
		Timestamp json.Number `json:"timestamp"`
	}
	if err := json.Unmarshal(body, &ts); err != nil {
		return fmt.Errorf("decode timestamp: %w", err)
	}
	ms, err := strconv.ParseInt(ts.Timestamp.String(), 10, 64)
	if err != nil {
		return fmt.Errorf("%w: missing timestamp", ErrStale)
	}
	if d := now.Sub(time.UnixMilli(ms)); d > maxSkew || d < -maxSkew {
		return fmt.Errorf("%w: %s", ErrStale, d.Round(time.Second))
	}
	return nil
}

type User struct {
	AccountID   string `json:"accountId"`
	DisplayName string `json:"displayName"`
}

type Fields struct {
	Summary    string   `json:"summary"`
	Assignee   *User    `json:"assignee"`
	Labels     []string `json:"labels"`
	Components []struct {
		Name string `json:"name"`
	} `json:"components"`
}

// labels returns the labels and component names of the issue.
func (f Fields) labels() []string {
	out := append([]string{}, f.Labels...)
	for _, c := range f.Components {
		if c.Name != "" {
			out = append(out, c.Name)
		}
	}
	return out
}

type Issue struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Self   string `json:"self"`
	Fields Fields `json:"fields"`
}

type ChangeItem struct {
	Field      string `json:"field"`
	FieldID    string `json:"fieldId"`
	From       string `json:"from"`
	FromString string `json:"fromString"`
	To         string `json:"to"`
	ToString   string `json:"toString"`
}

// WebhookEvent is the subset of a Jira native webhook payload we need.
type WebhookEvent struct {
	Timestamp          int64  `json:"timestamp"`
	WebhookEvent       string `json:"webhookEvent"`
	IssueEventTypeName string `json:"issue_event_type_name"`
	User               *User  `json:"user"`
	Issue              *Issue `json:"issue"`
	Changelog          *struct {
		Items []ChangeItem `json:"items"`
	} `json:"changelog"`
}

// Ticket is the normalized result of parsing a Jira payload.
type Ticket struct {
	Key     string
	Summary string
	URL     string
	// Labels holds the labels and component names of the issue, as far as
	// the payload has them.
	Labels []string
	// Actor is the accountId of the user who assigned the issue: the user
	// of the webhook event, or the initiator of the Automation rule. Empty
	// when the payload does not say.
	Actor string
}

// BrowseURL turns the REST "self" link into the user facing issue URL.
func BrowseURL(self, key string) string {
	u, err := url.Parse(self)
	if err != nil || u.Host == "" || key == "" {
		return ""
	}
	return fmt.Sprintf("%s://%s/browse/%s", u.Scheme, u.Host, key)
}

// ParseWebhook accepts jira:issue_created with the bot as assignee, or
// jira:issue_updated whose changelog shows the assignee changing to the bot.
func ParseWebhook(body []byte, botAccountID string) (*Ticket, error) {
	var ev WebhookEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return nil, fmt.Errorf("decode jira webhook: %w", err)
	}
	if ev.Issue == nil || ev.Issue.Key == "" {
		return nil, fmt.Errorf("%w: no issue in %q event", ErrIgnored, ev.WebhookEvent)
	}

	switch ev.WebhookEvent {
	case "jira:issue_created":
		if a := ev.Issue.Fields.Assignee; a == nil || a.AccountID != botAccountID {
			return nil, fmt.Errorf("%w: created issue not assigned to bot", ErrIgnored)
		}
	case "jira:issue_updated":
		if !assignedTo(ev, botAccountID) {
			return nil, fmt.Errorf("%w: no assignee change to bot", ErrIgnored)
		}
	default:
		return nil, fmt.Errorf("%w: event %q", ErrIgnored, ev.WebhookEvent)
	}
	return &Ticket{
		Key:     ev.Issue.Key,
		Summary: ev.Issue.Fields.Summary,
		URL:     BrowseURL(ev.Issue.Self, ev.Issue.Key),
		Labels:  ev.Issue.Fields.labels(),
		Actor:   actor(ev.User),
	}, nil
}

func actor(u *User) string {
	if u == nil {
		return ""
	}
	return u.AccountID
}

// ParseClosed reports whether a webhook payload says that an issue was
// closed, and returns its key: the issue was deleted, or it was resolved
// (its changelog sets the resolution). A workflow that closes issues
// without a resolution is not recognised.
func ParseClosed(body []byte) (key string, ok bool) {
	var ev WebhookEvent
	if json.Unmarshal(body, &ev) != nil || ev.Issue == nil || ev.Issue.Key == "" {
		return "", false
	}
	switch ev.WebhookEvent {
	case "jira:issue_deleted":
		return ev.Issue.Key, true
	case "jira:issue_updated":
		if ev.Changelog == nil {
			return "", false
		}
		for _, it := range ev.Changelog.Items {
			if (it.FieldID == "resolution" || it.Field == "resolution") && (it.To != "" || it.ToString != "") {
				return ev.Issue.Key, true
			}
		}
	}
	return "", false
}

// Comment is a comment that someone added to an issue.
type Comment struct {
	Key     string
	Summary string
	URL     string
	// Body is the text of the comment.
	Body string
	// Author is the accountId of who wrote it, and AuthorName their
	// display name.
	Author     string
	AuthorName string
	// Assignee is the accountId of the issue's assignee, as far as the
	// payload has it.
	Assignee string
}

// ParseComment returns the comment of a "comment_created" webhook, and
// ErrIgnored for every other event.
func ParseComment(body []byte) (*Comment, error) {
	var ev struct {
		WebhookEvent string `json:"webhookEvent"`
		Issue        *Issue `json:"issue"`
		Comment      *struct {
			Body   json.RawMessage `json:"body"`
			Author *User           `json:"author"`
		} `json:"comment"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		return nil, fmt.Errorf("decode jira webhook: %w", err)
	}
	if ev.WebhookEvent != "comment_created" {
		return nil, fmt.Errorf("%w: event %q", ErrIgnored, ev.WebhookEvent)
	}
	if ev.Issue == nil || ev.Issue.Key == "" || ev.Comment == nil {
		return nil, errors.New("comment_created without an issue or a comment")
	}
	c := &Comment{
		Key:     ev.Issue.Key,
		Summary: ev.Issue.Fields.Summary,
		URL:     BrowseURL(ev.Issue.Self, ev.Issue.Key),
	}
	// The webhook sends the text as it is. A body in another form (a
	// document tree) is not read: the comment then counts as empty.
	_ = json.Unmarshal(ev.Comment.Body, &c.Body)
	if a := ev.Comment.Author; a != nil {
		c.Author, c.AuthorName = a.AccountID, a.DisplayName
	}
	if a := ev.Issue.Fields.Assignee; a != nil {
		c.Assignee = a.AccountID
	}
	return c, nil
}

func assignedTo(ev WebhookEvent, bot string) bool {
	if ev.Changelog == nil {
		return false
	}
	for _, it := range ev.Changelog.Items {
		if (it.FieldID == "assignee" || it.Field == "assignee") && it.To == bot && it.From != bot {
			return true
		}
	}
	return false
}

// AutomationPayload is the custom JSON body recommended for the Jira
// Automation "Send web request" action (see examples/jira-automation-body.json).
type AutomationPayload struct {
	IssueKey  string `json:"issueKey"`
	Summary   string `json:"summary"`
	URL       string `json:"url"`
	Assignee  string `json:"assigneeAccountId"`
	EventName string `json:"event"`
	// Initiator is who triggered the rule: {{initiator.accountId}}. It is
	// needed when an allowlist of assigners is configured.
	Initiator string `json:"initiatorAccountId"`
	// Labels is optional: a list, or one text with commas, which is what
	// the smart value {{issue.labels}} gives.
	Labels labelList `json:"labels"`
	// Issue is set when the rule sends "Work item data (Jira format)".
	Issue *Issue `json:"issue"`
}

// labelList reads a JSON list of texts, or one text with commas.
type labelList []string

func (l *labelList) UnmarshalJSON(raw []byte) error {
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		*l = list
		return nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return errors.New("labels must be a list of texts or one text")
	}
	*l = nil
	for _, part := range strings.Split(text, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

// ErrNoAssignee marks an Automation payload that does not say who the ticket
// is assigned to, although the bot's account id is configured. It is refused
// rather than ignored: the rule's request body is most likely incomplete.
var ErrNoAssignee = errors.New("jira automation payload has no assignee")

// ParseAutomation accepts either the custom body or the built-in
// "Work item data (Jira format)" body. When botAccountID is set, the payload
// must name the bot as the assignee.
func ParseAutomation(body []byte, botAccountID string) (*Ticket, error) {
	var p AutomationPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decode jira automation payload: %w", err)
	}
	t := &Ticket{Key: p.IssueKey, Summary: p.Summary, URL: p.URL, Labels: p.Labels, Actor: strings.TrimSpace(p.Initiator)}
	assignee := p.Assignee
	if p.Issue != nil {
		if t.Key == "" {
			t.Key = p.Issue.Key
		}
		if t.Summary == "" {
			t.Summary = p.Issue.Fields.Summary
		}
		if t.URL == "" {
			t.URL = BrowseURL(p.Issue.Self, p.Issue.Key)
		}
		t.Labels = append(t.Labels, p.Issue.Fields.labels()...)
		if assignee == "" && p.Issue.Fields.Assignee != nil {
			assignee = p.Issue.Fields.Assignee.AccountID
		}
	}
	t.Key = strings.TrimSpace(t.Key)
	if t.Key == "" {
		return nil, errors.New("jira automation payload has no issue key")
	}
	if botAccountID != "" {
		if strings.TrimSpace(assignee) == "" {
			return nil, ErrNoAssignee
		}
		if assignee != botAccountID {
			return nil, fmt.Errorf("%w: assignee %s is not the bot", ErrIgnored, assignee)
		}
	}
	return t, nil
}
