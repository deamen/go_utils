// Package tracker is what ochell itself needs from the API of a ticket
// tracker: find the tickets assigned to the bot, comment on one, change its
// status. The poller and the back-channel use only this interface, so the
// way a tracker is reached (an API client today, perhaps twg later) can
// change without touching them.
//
// It is not how the agent reads a ticket; the agent has its own tool.
package tracker

import (
	"context"
	"errors"
)

// Issue is one ticket, as far as ochell needs it.
type Issue struct {
	// Key is the human readable ticket key, e.g. "DEV-42".
	Key   string
	Title string
	// URL is the page of the ticket for a person.
	URL string
	// Labels holds the labels of the ticket; for Jira also its components.
	Labels []string
	// Type is the Jira issue type, such as "Bug"; empty for Linear.
	Type string
	// Priority is the priority of the ticket: for Linear its rank, where 1
	// is the most urgent and 0 none; for Jira its name, such as "High",
	// which the policy turns into a rank.
	Priority     int
	PriorityName string
	// Repo is the repository that the tracker itself names for the ticket,
	// as git clone takes it: for a GitHub issue, the repository it is in.
	// Empty for Jira and Linear.
	Repo string
	// PullRequest is the page of the ticket when the ticket is itself a
	// pull request, and "" otherwise.
	PullRequest string
}

// Status is what a tracker says about one ticket that the bot had.
type Status struct {
	// Closed: the ticket is done, cancelled or gone.
	Closed bool
	// Unassigned: the ticket was the bot's, and no longer is.
	Unassigned bool
}

// ErrNotFound: the tracker has no ticket with this key, or does not show
// it to the bot account.
var ErrNotFound = errors.New("the tracker has no such ticket")

// Label is a label of a ticket, and who put it there.
type Label struct {
	Name string
	// By holds the ways the tracker names who added the label (an account
	// id, an email address); for a label that the ticket was created
	// with, its creator. Empty when the tracker does not say.
	By []string
	// Bot: the account that ochell asks the tracker as added it.
	Bot bool
}

// Scheduling is what a tracker says about one ticket that decides when
// its work starts.
type Scheduling struct {
	// Priority and PriorityName are those of Issue.
	Priority     int
	PriorityName string
	// Labels are the labels of the ticket; for Jira also its components.
	Labels []Label
	// BlockedBy are the keys of the tickets that the tracker says block
	// this one and that are still open.
	BlockedBy []string
}

// Source is what the poller needs to bring ochell in line with one
// tracker: which tickets are the bot's, who gave it one of them, and what
// became of a ticket that is no longer on the list.
type Source interface {
	// Assigned returns every open ticket that is assigned to the bot. It
	// returns an error rather than a part of the list.
	Assigned(ctx context.Context) ([]Issue, error)
	// Assigner returns the ways the tracker names the person who assigned
	// a ticket to the bot (an account id, an email address), or nothing
	// when it cannot tell.
	Assigner(ctx context.Context, key string) ([]string, error)
	// Lookup asks about one ticket.
	Lookup(ctx context.Context, key string) (Status, error)
	// Scheduling asks what decides when the work on one ticket starts. It
	// returns ErrNotFound for a ticket that the tracker does not have.
	Scheduling(ctx context.Context, key string) (Scheduling, error)
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
