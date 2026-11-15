package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"ochell/internal/github"
	"ochell/internal/runner"
	"ochell/internal/source/linear"
	"ochell/internal/store"
)

// The handoff: the agent opens a pull request and its ticket goes to
// review; a person reviews and merges it; then the ticket is done. ochell
// follows the pull requests that its tickets named, with read-only access
// to GitHub, and closes the ticket's work when a person has merged or
// closed them.
//
// The digital employee never merges. That is enforced on GitHub, by branch
// protection and an account without the right to merge, not here. ochell
// only refuses to take a merge by that account as an acceptance.

// pullRequestsBy is how long one round of questions to GitHub may take.
const pullRequestsBy = 2 * time.Minute

// UseGitHub sets the access to GitHub. New does this from the
// configuration; tests pass a client for a fake.
func (s *Server) UseGitHub(c *github.Client) { s.github = c }

// runPullRequestPoller asks about the open pull requests at once and then
// at every github.poll_interval, until ctx is done.
func (s *Server) runPullRequestPoller(ctx context.Context) {
	s.log.Info("following the pull requests of the tickets", "interval", s.cfg.GitHub.PollInterval, "host", s.github.WebHost())
	tick := time.NewTicker(s.cfg.GitHub.PollInterval)
	defer tick.Stop()
	for {
		pctx, cancel := context.WithTimeout(ctx, pullRequestsBy)
		s.PollPullRequests(pctx)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// branchOf returns the branch that a ticket is worked on (workspace.branch),
// or "" when it cannot be told.
func (s *Server) branchOf(source, key string) string {
	if s.branch == nil {
		return ""
	}
	var b strings.Builder
	if err := s.branch.Execute(&b, struct{ ID, Source, Key, Repo, Branch string }{Source: source, Key: key}); err != nil {
		return ""
	}
	return b.String()
}

// PollPullRequests asks GitHub once about every tracked pull request that
// is open, and acts on what became of it.
func (s *Server) PollPullRequests(ctx context.Context) {
	if s.github == nil {
		return
	}
	log := s.log.With("by", "pull requests")
	open, err := s.runner.OpenPullRequests()
	if err != nil {
		log.Error("cannot read the open pull requests", "err", err)
		return
	}
	type ticketKey struct{ source, key string }
	// What is still open after this round, and which tickets had a pull
	// request merged or closed by a person in it.
	left := map[ticketKey]int{}
	settled := map[ticketKey]store.PullRequest{}
	for _, pr := range open {
		if ctx.Err() != nil {
			return
		}
		k := ticketKey{pr.Source, pr.Key}
		prlog := log.With("source", pr.Source, "key", pr.Key, "pull_request", pr.URL)
		reject := func(why string) {
			prlog.Warn("the pull request is not followed: " + why)
			if err := s.runner.SetPullRequest(pr.Source, pr.Key, pr.URL, store.PRRejected, "", why); err != nil {
				prlog.Error("cannot record that", "err", err)
			}
		}
		// The address is what the agent reported. It counts only when it
		// is a pull request on the configured site, from the branch that
		// the ticket is worked on: otherwise the agent could point at
		// someone else's merged pull request and have its ticket done.
		ref, err := github.ParseURL(pr.URL, s.github.WebHost())
		if err != nil {
			reject(err.Error())
			continue
		}
		got, err := s.github.PullRequest(ctx, ref)
		if github.NotFound(err) {
			reject("GitHub has no such pull request, or does not show it to ochell's token")
			continue
		}
		if err != nil {
			// Nothing is concluded from an answer that did not come.
			prlog.Warn("cannot ask GitHub about the pull request", "err", err)
			left[k]++
			continue
		}
		if want := s.branchOf(pr.Source, pr.Key); want != "" && got.HeadRef != want {
			reject(fmt.Sprintf("it is from the branch %q, and the ticket is worked on %q", got.HeadRef, want))
			continue
		}
		if got.State == "open" {
			left[k]++
			continue
		}
		state := store.PRClosed
		if got.Merged {
			state = store.PRMerged
		}
		note := ""
		// A merge by the digital employee's own account is not a person's
		// acceptance.
		byBot := got.Merged && s.cfg.GitHub.BotLogin != "" && strings.EqualFold(got.ClosedBy, s.cfg.GitHub.BotLogin)
		if byBot {
			note = "merged by the bot account itself"
			prlog.Error("the pull request was merged by the digital employee's own account; that is not taken as an acceptance, and the ticket stays as it is. Check the branch protection of the repository", "merged_by", got.ClosedBy)
		}
		if err := s.runner.SetPullRequest(pr.Source, pr.Key, pr.URL, state, got.ClosedBy, note); err != nil {
			prlog.Error("cannot record what became of the pull request", "err", err)
			left[k]++
			continue
		}
		prlog.Info("pull request "+state, "by", got.ClosedBy)
		if !byBot {
			pr.State, pr.ClosedBy = state, got.ClosedBy
			settled[k] = pr
		}
	}
	// A ticket is done when a person has merged or closed a pull request
	// of it and none of its pull requests is open any more.
	for k, pr := range settled {
		if left[k] > 0 {
			continue
		}
		s.accepted(k.source, k.key, pr, log)
	}
}

// accepted closes the work on a ticket whose pull request a person merged
// or closed: the ticket becomes done, and is told.
func (s *Server) accepted(source, key string, pr store.PullRequest, log *slog.Logger) {
	text := fmt.Sprintf("The pull request %s was closed without a merge. The digital employee does no more work on %s; assign it again to start it again.", pr.URL, key)
	if pr.State == store.PRMerged {
		by := pr.ClosedBy
		if by == "" {
			by = "a reviewer"
		}
		text = fmt.Sprintf("The pull request %s was merged by %s. The work of the digital employee on %s is done.", pr.URL, by, key)
	}
	switch err := s.runner.Closed(source, key); {
	case err == nil:
		log.Info("ticket done: its pull request was "+pr.State, "source", source, "key", key, "pull_request", pr.URL, "by", pr.ClosedBy)
	case errors.Is(err, store.ErrUnknown), errors.Is(err, runner.ErrStopped):
		return
	default:
		log.Error("cannot record that the ticket is done", "source", source, "key", key, "err", err)
		return
	}
	switch source {
	case "jira":
		s.jiraComment(key, text, log)
	case "linear":
		if session, err := s.runner.Session(source, key); err == nil && session != "" {
			s.linearActivity(session, linear.ActivityResponse, text, log)
		}
	}
}
