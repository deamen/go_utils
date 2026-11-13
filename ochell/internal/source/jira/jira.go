// Package jira parses Jira Cloud native webhooks and Automation
// "Send web request" payloads into tasks.
package jira

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrIgnored marks a valid payload that does not represent an assignment to
// the digital employee. Handlers answer 200 so Atlassian does not retry.
var ErrIgnored = errors.New("event ignored")

type User struct {
	AccountID   string `json:"accountId"`
	DisplayName string `json:"displayName"`
}

type Fields struct {
	Summary  string `json:"summary"`
	Assignee *User  `json:"assignee"`
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
	}, nil
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
	// Issue is set when the rule sends "Work item data (Jira format)".
	Issue *Issue `json:"issue"`
}

// ParseAutomation accepts either the custom body or the built-in
// "Work item data (Jira format)" body. When botAccountID is set and an
// assignee is present in the payload, it must match.
func ParseAutomation(body []byte, botAccountID string) (*Ticket, error) {
	var p AutomationPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decode jira automation payload: %w", err)
	}
	t := &Ticket{Key: p.IssueKey, Summary: p.Summary, URL: p.URL}
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
		if assignee == "" && p.Issue.Fields.Assignee != nil {
			assignee = p.Issue.Fields.Assignee.AccountID
		}
	}
	t.Key = strings.TrimSpace(t.Key)
	if t.Key == "" {
		return nil, errors.New("jira automation payload has no issue key")
	}
	if botAccountID != "" && assignee != "" && assignee != botAccountID {
		return nil, fmt.Errorf("%w: assignee %s is not the bot", ErrIgnored, assignee)
	}
	return t, nil
}
