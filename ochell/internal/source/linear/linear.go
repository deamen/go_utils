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
	// Creator is the user who delegated the issue or mentioned the agent.
	CreatorID string `json:"creatorId"`
	Creator   *struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"creator"`
}

type AgentActivity struct {
	ID      string `json:"id"`
	Body    string `json:"body"`
	Content *struct {
		Type string `json:"type"`
		Body string `json:"body"`
	} `json:"content"`
	// Signal is "stop" when the user asks the agent to stop.
	Signal string `json:"signal"`
	// User is who wrote the prompt.
	UserID string `json:"userId"`
	User   *struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}

// Event is the subset of the webhook payload used by the orchestrator.
type Event struct {
	Type           string         `json:"type"`
	Action         string         `json:"action"`
	OrganizationID string         `json:"organizationId"`
	AppUserID      string         `json:"appUserId"`
	OAuthClientID  string         `json:"oauthClientId"`
	WebhookID      string         `json:"webhookId"`
	CreatedAt      string         `json:"createdAt"`
	AgentSession   *AgentSession  `json:"agentSession"`
	AgentActivity  *AgentActivity `json:"agentActivity"`
	PromptContext  string         `json:"promptContext"`
	// Data is the issue of an "Issue" event.
	Data *struct {
		Identifier string `json:"identifier"`
		State      *struct {
			Type string `json:"type"`
		} `json:"state"`
		DelegateID string `json:"delegateId"`
	} `json:"data"`
	// UpdatedFrom holds the earlier values of what an "update" changed.
	UpdatedFrom      map[string]any `json:"updatedFrom"`
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
	// Actor and ActorEmail identify the user who started the session, or
	// who wrote the prompt, as far as the payload has them.
	Actor      string
	ActorEmail string
	// Prompted says that this is a "prompted" event: a person wrote to the
	// agent in a session that exists. Prompt is what they wrote, and Stop
	// says that they asked the agent to stop.
	Prompted bool
	Prompt   string
	Stop     bool
}

// Parse returns a Session for the AgentSessionEvent actions "created" (the
// issue was delegated to the agent, or the agent was mentioned) and
// "prompted" (a person wrote to the agent in a session that exists). Every
// other event is returned as ErrIgnored.
//
// A "prompted" payload may leave out the issue; Key is then empty, and the
// caller finds the ticket by the session.
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
	if ev.Action != "created" && ev.Action != "prompted" {
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
	s.Actor = ev.AgentSession.CreatorID
	if c := ev.AgentSession.Creator; c != nil {
		if c.ID != "" {
			s.Actor = c.ID
		}
		s.ActorEmail = c.Email
	}
	if ev.Action == "prompted" {
		s.Prompted, s.Prompt = true, ev.PromptText()
		if a := ev.AgentActivity; a != nil {
			s.Stop = a.Signal == "stop"
			// The author of the prompt, where the payload names one; the
			// creator of the session otherwise.
			if a.UserID != "" {
				s.Actor, s.ActorEmail = a.UserID, ""
			}
			if u := a.User; u != nil && (u.ID != "" || u.Email != "") {
				s.Actor, s.ActorEmail = u.ID, u.Email
			}
		}
	}
	if is := ev.AgentSession.Issue; is != nil {
		s.Key, s.Title, s.URL = is.Identifier, is.Title, is.URL
		for _, l := range is.Labels {
			if l.Name != "" {
				s.Labels = append(s.Labels, l.Name)
			}
		}
	}
	if s.Key == "" && !s.Prompted {
		// Sessions started outside an issue (e.g. a mention in a document)
		// still get a stable key.
		s.Key = "session-" + s.SessionID
	}
	return &ev, s, nil
}

// Closed reports whether the event says that an issue was closed, and
// returns its identifier: an "Issue" event whose issue was removed, or is
// in a completed or cancelled state. Linear sends these only when the
// app's webhook is subscribed to issue events.
func (e *Event) Closed() (key string, ok bool) {
	if e.Type != "Issue" || e.Data == nil || e.Data.Identifier == "" {
		return "", false
	}
	if e.Action == "remove" {
		return e.Data.Identifier, true
	}
	if s := e.Data.State; s != nil && (s.Type == "completed" || s.Type == "canceled") {
		return e.Data.Identifier, true
	}
	return "", false
}

// Undelegated reports whether the event says that an issue was taken away
// from this agent, and returns its identifier: an "Issue" update that
// changes the delegate, where the earlier delegate was this app's user.
//
// Without appUserId in the payload nobody can tell whose issue it was, and
// the answer is no. Linear sends these events only when the app's webhook
// is subscribed to issue events.
func (e *Event) Undelegated() (key string, ok bool) {
	if e.Type != "Issue" || e.Action != "update" || e.Data == nil || e.Data.Identifier == "" || e.AppUserID == "" {
		return "", false
	}
	before, changed := e.UpdatedFrom["delegateId"].(string)
	if !changed || before != e.AppUserID || e.Data.DelegateID == before {
		return "", false
	}
	return e.Data.Identifier, true
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
