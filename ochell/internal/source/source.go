// Package source is what the server needs from a source of tickets: a
// tracker that tells ochell by webhook that a ticket was given to the
// digital employee, and what happened to the ticket after that.
//
// A source authenticates a delivery and reads it into an Event. What the
// event then does (who may assign, what the bot account may not do, what a
// comment starts) is decided by the server, in one place for every source
// behind this interface, so that a new source cannot forget a gate.
//
// GitHub is behind it (package source/github). Jira and Linear are older
// than the interface and have handlers of their own in the server: Linear
// reports through agent sessions, and Jira comes in through two endpoints
// with their own rules, which this interface does not describe.
package source

import (
	"context"
	"errors"
	"net/http"

	"ochell/internal/tracker"
)

// Kind is what a delivery says happened.
type Kind int

const (
	// Ignored: nothing that ochell acts on. Event.Why says what it was.
	Ignored Kind = iota
	// Assigned: the ticket was given to the digital employee.
	Assigned
	// Unassigned: the ticket was taken away from the digital employee.
	Unassigned
	// Commented: someone wrote a comment on the ticket.
	Commented
	// Closed: the ticket was closed, or removed.
	Closed
	// Updated: something else about the ticket changed, such as a label.
	Updated
)

// Event is one delivery of a source, as far as ochell needs it. All of its
// text was written by people, or by the agent, and is untrusted.
type Event struct {
	Kind Kind
	// Why says, for an ignored delivery, what it was. Refused: it is one
	// that the host should hear about, such as a ticket from a place that
	// is not configured.
	Why     string
	Refused bool
	// Delivery is the id that the sender gave the delivery, or "".
	Delivery string

	// Key is the ticket key, Title and URL its title and its page.
	Key   string
	Title string
	URL   string
	// Repo is the repository that the source itself names for the ticket,
	// as git clone takes it; "" when the source knows none. The repos
	// setting of the host comes first.
	Repo string
	// Context is put in the agent's prompt as the context of the source.
	Context string
	// Labels and IssueType are what the policy looks at.
	Labels    []string
	IssueType string
	// Priority is the rank of the ticket's priority (0: none), and
	// HasPriority says that the source knows it: the tracker is then not
	// asked for it.
	Priority    int
	HasPriority bool
	// PullRequest is the page of the ticket when the ticket is itself a
	// pull request, and "" otherwise.
	PullRequest string

	// Actor is who did it, as the source names them in its allowlists,
	// and ActorName how a person would call them.
	Actor     string
	ActorName string
	// Reporter is who created the ticket, when the source says.
	Reporter string
	// Mine says, for a comment, that the ticket is assigned to the digital
	// employee now.
	Mine bool
	// Comment is the text of a comment.
	Comment string
}

var (
	// ErrUnauthorized: the delivery is not signed by the source.
	ErrUnauthorized = errors.New("the delivery is not signed by the source")
	// ErrBadPayload: the delivery is signed, and cannot be read.
	ErrBadPayload = errors.New("the delivery cannot be read")
	// ErrSilent: the source has no way to write on a ticket.
	ErrSilent = errors.New("the source cannot write on its tickets")
)

// Source is one source of tickets.
type Source interface {
	// Name is the name of the source in ticket ids, rules and commands,
	// such as "github".
	Name() string
	// Receive authenticates one delivery and reads it. It returns
	// ErrUnauthorized or ErrBadPayload, wrapped, for one that it does not
	// take.
	Receive(h http.Header, body []byte) (*Event, error)
	// Bot reports whether id names the account that the agent writes as.
	// What that account does on a ticket is never a person's word.
	Bot(id string) bool
	// Tell writes a text on a ticket, as the bot account. It returns
	// ErrSilent when the source has no access for that.
	Tell(ctx context.Context, key, text string) error
	// Tracker returns the API that the poller and the gates of scheduling
	// ask, or nil when the source cannot be asked.
	Tracker() tracker.Source
	// Tickets returns the access for the agent's ticket tools, or nil.
	Tickets() tracker.Tickets
	// CheckGates says whether the source can check the gates of
	// scheduling against its tracker: an error names what it cannot.
	CheckGates(requiredLabels, blockedBy bool) error
}
