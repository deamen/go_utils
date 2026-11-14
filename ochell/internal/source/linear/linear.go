// Package linear handles Linear agent (OAuth app, actor=app) webhooks and
// reports progress back to the agent session through the GraphQL API.
//
// See https://linear.app/developers/agents and
// https://linear.app/developers/webhooks.
package linear

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"ochell/internal/auth"
)

// ErrIgnored marks a valid payload that does not start a task.
var ErrIgnored = errors.New("event ignored")

var (
	ErrStale     = errors.New("webhook timestamp outside allowed skew")
	ErrSignature = errors.New("invalid Linear-Signature")
)

// Verify checks the Linear-Signature header (hex HMAC-SHA256 of the raw
// body) and that webhookTimestamp is within maxSkew of now.
func Verify(secret string, body []byte, signature string, maxSkew time.Duration, now time.Time) error {
	if err := auth.VerifyHex(secret, body, signature); err != nil {
		return fmt.Errorf("%w: %v", ErrSignature, err)
	}
	var ts struct {
		WebhookTimestamp json.Number `json:"webhookTimestamp"`
	}
	if err := json.Unmarshal(body, &ts); err != nil {
		return fmt.Errorf("decode timestamp: %w", err)
	}
	ms, err := strconv.ParseInt(ts.WebhookTimestamp.String(), 10, 64)
	if err != nil {
		return fmt.Errorf("%w: missing webhookTimestamp", ErrStale)
	}
	if d := now.Sub(time.UnixMilli(ms)); d > maxSkew || d < -maxSkew {
		return fmt.Errorf("%w: %s", ErrStale, d.Round(time.Second))
	}
	return nil
}

type Issue struct {
	ID         string `json:"id"`
	Identifier string `json:"identifier"`
	Title      string `json:"title"`
	URL        string `json:"url"`
	// Labels is used when the payload has it.
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

type AgentSession struct {
	ID      string `json:"id"`
	IssueID string `json:"issueId"`
	Issue   *Issue `json:"issue"`
	Comment *struct {
		ID   string `json:"id"`
		Body string `json:"body"`
	} `json:"comment"`
}

type AgentActivity struct {
	ID      string `json:"id"`
	Body    string `json:"body"`
	Content *struct {
		Type string `json:"type"`
		Body string `json:"body"`
	} `json:"content"`
}

// Event is the subset of the webhook payload used by the orchestrator.
type Event struct {
	Type             string         `json:"type"`
	Action           string         `json:"action"`
	OrganizationID   string         `json:"organizationId"`
	AppUserID        string         `json:"appUserId"`
	OAuthClientID    string         `json:"oauthClientId"`
	WebhookID        string         `json:"webhookId"`
	CreatedAt        string         `json:"createdAt"`
	AgentSession     *AgentSession  `json:"agentSession"`
	AgentActivity    *AgentActivity `json:"agentActivity"`
	PromptContext    string         `json:"promptContext"`
	Guidance         any            `json:"guidance"`
	PreviousComments []any          `json:"previousComments"`
}

// Session is the normalized result of an AgentSessionEvent.
type Session struct {
	SessionID      string
	OrganizationID string
	Key            string
	Title          string
	URL            string
	Context        string
	// Comment is the comment the session was started from, when the agent
	// was mentioned in one.
	Comment string
	// Labels holds the labels of the issue, as far as the payload has them.
	Labels []string
}

// Parse returns a Session for AgentSessionEvent "created" events. "prompted"
// follow-ups and every other event type are returned as ErrIgnored for now.
func Parse(body []byte) (*Event, *Session, error) {
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		return nil, nil, fmt.Errorf("decode linear webhook: %w", err)
	}
	if ev.Type != "AgentSessionEvent" {
		return &ev, nil, fmt.Errorf("%w: type %q", ErrIgnored, ev.Type)
	}
	if ev.AgentSession == nil || ev.AgentSession.ID == "" {
		return &ev, nil, errors.New("AgentSessionEvent without agentSession.id")
	}
	if ev.Action != "created" {
		return &ev, nil, fmt.Errorf("%w: AgentSessionEvent action %q", ErrIgnored, ev.Action)
	}
	s := &Session{
		SessionID:      ev.AgentSession.ID,
		OrganizationID: ev.OrganizationID,
		Context:        ev.PromptContext,
	}
	if c := ev.AgentSession.Comment; c != nil {
		s.Comment = c.Body
	}
	if is := ev.AgentSession.Issue; is != nil {
		s.Key, s.Title, s.URL = is.Identifier, is.Title, is.URL
		for _, l := range is.Labels {
			if l.Name != "" {
				s.Labels = append(s.Labels, l.Name)
			}
		}
	}
	if s.Key == "" {
		// Sessions started outside an issue (e.g. a mention in a document)
		// still get a stable key.
		s.Key = "session-" + s.SessionID
	}
	return &ev, s, nil
}

// PromptText returns the user's follow-up message of a "prompted" event.
func (e *Event) PromptText() string {
	if e.AgentActivity == nil {
		return ""
	}
	if e.AgentActivity.Content != nil && e.AgentActivity.Content.Body != "" {
		return e.AgentActivity.Content.Body
	}
	return e.AgentActivity.Body
}
