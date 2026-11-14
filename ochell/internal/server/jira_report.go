package server

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"ochell/internal/result"
	"ochell/internal/task"
	"ochell/internal/tracker"
)

// The Jira back-channel: what ochell itself writes on a Jira ticket. A
// Linear ticket has its agent session for this; a Jira ticket has only its
// comments. Everything here needs the Jira API (sources.jira_api).

const jiraCallBy = 30 * time.Second

// UseJira sets the access to the Jira API. New does this from the
// configuration; tests pass a fake.
func (s *Server) UseJira(c tracker.Client) { s.jira = c }

// reportsToJira says whether the run of t is reported in comments on a
// Jira ticket.
func (s *Server) reportsToJira(t *task.Task) bool {
	return s.jira != nil && t.Source == "jira"
}

// jiraComment adds a comment to a ticket without holding up the webhook
// response.
func (s *Server) jiraComment(key, body string, log *slog.Logger) {
	if s.jira == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), jiraCallBy)
		defer cancel()
		if err := s.jira.Comment(ctx, key, body); err != nil {
			log.Error("jira comment failed", "key", key, "err", err)
		}
	}()
}

// jiraStarted is the comment for the start of a run.
func jiraStarted(t *task.Task) string {
	if t.Attempt > 1 {
		return fmt.Sprintf("The digital employee is working on this ticket again (attempt %d).", t.Attempt)
	}
	return "The digital employee started work on this ticket."
}

// jiraFinished is the comment for the end of a run. It says the same as
// the activity that a Linear session gets.
func jiraFinished(res task.Result) string {
	if res.Next != "" {
		return queuedAgainText(res)
	}
	if res.Err != nil {
		return strings.TrimSpace(failureText(res) + "\n\n" + noFormat(lastN(res.Message, replyMax)))
	}
	_, msg := signalActivity(res)
	if res.Signal == result.Done {
		msg = "The digital employee finished its work on this ticket, which is now ready for review.\n\n" + msg
		if res.PRURL != "" {
			msg += "\n\nPull request: " + res.PRURL
		}
	}
	return msg
}

// noFormat shows agent output as it is: Jira would read it as wiki markup.
func noFormat(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return "{noformat}\n" + strings.ReplaceAll(s, "{noformat}", "{ noformat }") + "\n{noformat}"
}

// jiraRunStarted and jiraRunFinished are the Jira side of Started and
// Finished.
func (s *Server) jiraRunStarted(ctx context.Context, t *task.Task) error {
	ctx, cancel := context.WithTimeout(ctx, jiraCallBy)
	defer cancel()
	return s.jira.Comment(ctx, t.Key, jiraStarted(t))
}

func (s *Server) jiraRunFinished(ctx context.Context, t *task.Task, res task.Result) error {
	ctx, cancel := context.WithTimeout(ctx, 2*jiraCallBy)
	defer cancel()
	if err := s.jira.Comment(ctx, t.Key, jiraFinished(res)); err != nil {
		return err
	}
	// Only finished work is handed to the reviewers.
	status := s.cfg.Sources.JiraAPI.ReviewStatus
	if status == "" || res.Err != nil || res.Signal != result.Done {
		return nil
	}
	if err := s.jira.SetStatus(ctx, t.Key, status); err != nil {
		return fmt.Errorf("move %s to %q: %w", t.Key, status, err)
	}
	return nil
}
