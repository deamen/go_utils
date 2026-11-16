package server

import (
	"context"
	"strings"
	"testing"

	"ochell/internal/tracker"
)

// ticketsFake is a Jira that the ticket tools can use: it also reads a
// ticket, and says which account its token belongs to.
type ticketsFake struct {
	tracker.Fake
	account string
}

func (f *ticketsFake) Ticket(_ context.Context, key string) (tracker.Ticket, error) {
	return tracker.Ticket{Key: key, Title: "Title of " + key}, nil
}

func (f *ticketsFake) Account(context.Context) (string, error) { return f.account, nil }

// What the ticket tools write is written as the bot account. A comment
// from another account would reach ochell as a person's, so none is
// written when the account of the API token is not the bot's.
func TestTicketsWriteAsTheBotAccountOnly(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig()
	s := newServer(t, cfg, &fakeRunner{})
	if s.Tickets("jira") != nil || s.Tickets("linear") != nil || s.Tickets("github") != nil {
		t.Error("tickets without access to a tracker")
	}
	// A Jira access that cannot read a ticket is none for the tools.
	s.UseJira(&tracker.Fake{})
	if s.Tickets("jira") != nil {
		t.Error("tickets from an access that reads none")
	}

	jira := &ticketsFake{account: cfg.Sources.JiraWebhook.BotAccountID}
	s.UseJira(jira)
	tk := s.Tickets("jira")
	if got, err := tk.Ticket(ctx, "DEV-1"); err != nil || got.Title != "Title of DEV-1" {
		t.Errorf("Ticket = %+v, %v", got, err)
	}
	if err := tk.Comment(ctx, "DEV-1", "from the agent"); err != nil || len(jira.Comments("DEV-1")) != 1 {
		t.Errorf("a comment as the bot account: %v, %q", err, jira.Comments("DEV-1"))
	}

	// The API token of another account: reading works, writing does not.
	jira.account = "557058:someone-else"
	if _, err := tk.Ticket(ctx, "DEV-1"); err != nil {
		t.Errorf("Ticket as another account: %v", err)
	}
	if err := tk.Comment(ctx, "DEV-1", "from the agent"); err == nil || !strings.Contains(err.Error(), "is not its bot account") || len(jira.Comments("DEV-1")) != 1 {
		t.Errorf("a comment as another account: %v, %q", err, jira.Comments("DEV-1"))
	}
	// Without the webhook source no comment reaches ochell, so there is
	// nothing to mistake.
	cfg.Sources.JiraWebhook.Enabled = false
	if err := tk.Comment(ctx, "DEV-1", "from the agent"); err != nil || len(jira.Comments("DEV-1")) != 2 {
		t.Errorf("a comment without the webhook source: %v", err)
	}
}
