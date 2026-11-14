// Package tracker is what ochell itself needs from the API of a ticket
// tracker: find the tickets assigned to the bot, comment on one, change its
// status. The poller and the back-channel use only this interface, so the
// way a tracker is reached (an API client today, perhaps twg later) can
// change without touching them.
//
// It is not how the agent reads a ticket; the agent has its own tool.
package tracker

import "context"

// Issue is one ticket, as far as ochell needs it.
type Issue struct {
	// Key is the human readable ticket key, e.g. "DEV-42".
	Key   string
	Title string
	// URL is the page of the ticket for a person.
	URL string
	// Labels holds the labels of the ticket; for Jira also its components.
	Labels []string
}

// Client is the access to one tracker, as the bot account.
type Client interface {
	// Assigned returns every open ticket that is assigned to the bot. It
	// returns an error rather than a part of the list: a caller may take
	// a ticket that is missing from it for one that was unassigned.
	Assigned(ctx context.Context) ([]Issue, error)
	// Comment adds a comment to a ticket.
	Comment(ctx context.Context, key, body string) error
	// SetStatus moves a ticket to the status with this name.
	SetStatus(ctx context.Context, key, status string) error
}
