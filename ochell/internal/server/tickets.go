package server

import (
	"context"
	"fmt"

	"ochell/internal/tracker"
)

// Tickets returns ochell's access to the tickets of a source for the
// agent's ticket tools (package mcp), or nil when it has none.
//
// What the tools write is written as the bot account, with ochell's token.
// The gates rest on that account being known: a comment of the bot is
// never a person's follow-up, approval or stop.
func (s *Server) Tickets(source string) tracker.Tickets {
	switch source {
	case "jira":
		if t, ok := s.jira.(tracker.Tickets); ok {
			return jiraTickets{Tickets: t, s: s}
		}
	case "linear":
		// The app's own user, which every signed webhook names.
		if s.linear != nil {
			return s.linear
		}
	}
	return nil
}

// jiraTickets is the access to Jira for the ticket tools. It writes a
// comment only when the account of the API token is the bot account that
// the webhook source knows: a comment from any other account would reach
// ochell as a person's, and start a run.
type jiraTickets struct {
	tracker.Tickets
	s *Server
}

func (j jiraTickets) Comment(ctx context.Context, key, body string) error {
	who, ok := j.Tickets.(interface {
		Account(context.Context) (string, error)
	})
	if ok && j.s.cfg.Sources.JiraWebhook.Enabled {
		id, err := who.Account(ctx)
		if err != nil {
			return err
		}
		if !j.s.jiraBot(id) {
			j.s.log.Error("ticket tools: the account of sources.jira_api is not the bot account of the Jira sources (bot_account_id); a comment of the agent would be taken as a person's, so none is written", "key", key)
			return fmt.Errorf("the host is not set up for comments on Jira tickets: the account that ochell writes as is not its bot account")
		}
	}
	return j.Tickets.Comment(ctx, key, body)
}
