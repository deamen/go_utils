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
	"ochell/internal/ticket"
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
			// A ticket that waited for the checks of this pull request has
			// nothing to wait for.
			s.toReview(pr, fmt.Sprintf("The pull request %s that the digital employee named is not followed: %s. %s goes to review as it is.", pr.URL, why, pr.Key), prlog)
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
			s.followOpen(ctx, pr, ref, got, prlog)
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
			s.toReview(pr, fmt.Sprintf("The pull request %s was merged by the digital employee's own account. That is not taken as an acceptance: %s stays in review for a person.", pr.URL, pr.Key), prlog)
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
	s.tell(source, key, text, log)
}

// followOpen looks at a pull request that is open: at what people wrote on
// it, and, while its ticket waits for them, at its checks.
func (s *Server) followOpen(ctx context.Context, pr store.PullRequest, ref github.Ref, got *github.PullRequest, log *slog.Logger) {
	s.passOnComments(ctx, pr, ref, log)
	st, err := s.runner.State(pr.Source, pr.Key)
	if err != nil || st != ticket.Checking {
		return
	}
	checks, err := s.github.Checks(ctx, ref, got.HeadSHA)
	if err != nil {
		log.Warn("cannot ask GitHub about the checks of the pull request", "err", err)
		return
	}
	switch checks.State {
	case github.ChecksPending:
	case github.ChecksNone:
		// Checks appear a moment after a push. A pull request that has
		// none after the grace period has none.
		if s.now().Sub(pr.Updated) < s.cfg.GitHub.ChecksGrace {
			return
		}
		s.toReview(pr, "The pull request "+pr.URL+" has no checks. "+pr.Key+" is ready for review.", log)
	case github.ChecksPassed:
		s.toReview(pr, "The checks of the pull request "+pr.URL+" passed. "+pr.Key+" is ready for review.", log)
	case github.ChecksFailed:
		s.checksFailed(pr, got.HeadSHA, checks, log)
	}
}

// toReview hands a ticket whose checks are through to the reviewers, and
// tells the ticket.
func (s *Server) toReview(pr store.PullRequest, text string, log *slog.Logger) {
	if err := s.runner.ToReview(pr.Source, pr.Key); err != nil {
		if !errors.Is(err, store.ErrNotChecking) {
			log.Error("cannot move the ticket to review", "err", err)
		}
		return
	}
	log.Info("ticket in review", "why", text)
	s.tell(pr.Source, pr.Key, text, log)
	if status := s.cfg.Sources.JiraAPI.ReviewStatus; status != "" && pr.Source == "jira" && s.jira != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), jiraCallBy)
			defer cancel()
			if err := s.jira.SetStatus(ctx, pr.Key, status); err != nil {
				log.Warn("cannot move the Jira ticket to its review status", "status", status, "err", err)
			}
		}()
	}
}

// tell posts a text on a ticket: a comment in Jira, a response in the
// Linear session of the ticket's last run.
func (s *Server) tell(source, key, text string, log *slog.Logger) {
	switch source {
	case "jira":
		s.jiraComment(key, text, log)
	case "linear":
		if session, err := s.runner.Session(source, key); err == nil && session != "" {
			s.linearActivity(session, linear.ActivityResponse, text, log)
		}
	}
}

// commentTTL is how long ochell remembers that it has passed a comment of
// a pull request on.
const commentTTL = 90 * 24 * time.Hour

// failureMax is how much of the failed checks is given to the agent.
const failureMax = 12000

// checksFailed wakes the ticket of a pull request whose checks failed, with
// the failure. A failure that the agent was already given, for the same
// commit, is one it did not fix: the ticket then goes to review as it is.
func (s *Server) checksFailed(pr store.PullRequest, sha string, checks *github.Checks, log *slog.Logger) {
	var b strings.Builder
	for _, f := range checks.Failed {
		fmt.Fprintf(&b, "Check %q: %s\n", f.Name, f.Conclusion)
		if f.Summary != "" {
			b.WriteString(f.Summary + "\n")
		}
		if f.URL != "" {
			b.WriteString(f.URL + "\n")
		}
		b.WriteString("\n")
	}
	failure := strings.TrimSpace(b.String())
	if len(failure) > failureMax {
		failure = strings.ToValidUTF8(failure[:failureMax], "") + " […]"
	}
	names := make([]string, 0, len(checks.Failed))
	for _, f := range checks.Failed {
		names = append(names, f.Name)
	}
	failed := strings.Join(names, ", ")
	if pr.CheckedSHA == sha {
		s.toReview(pr, fmt.Sprintf("The checks of the pull request %s still fail (%s), and the digital employee did not change the pull request after it was given the failure. %s goes to review as it is.", pr.URL, failed, pr.Key), log)
		return
	}
	t := s.newTask(pr.Source, pr.Key, "", "", "", "")
	t.Comment = failure
	if session, err := s.runner.Session(pr.Source, pr.Key); err == nil {
		t.TrackerSession = session
	}
	switch err := s.runner.WakeForChecks(t); {
	case err == nil:
		log.Info("the checks of the pull request failed; the ticket is queued again with the failure", "task", t.ID, "failed", failed, "commit", sha)
		if err := s.runner.NotePullRequest(pr.Source, pr.Key, pr.URL, sha, time.Time{}); err != nil {
			log.Error("cannot record which failure the agent was given", "err", err)
		}
		if t.TrackerSession != "" && pr.Source == "linear" {
			s.linearActivity(t.TrackerSession, linear.ActivityThought, fmt.Sprintf("The checks of the pull request failed (%s). The digital employee is looking at the failure.", failed), log)
		}
	case errors.Is(err, runner.ErrAttempts):
		s.toReview(pr, fmt.Sprintf("The checks of the pull request %s fail (%s), and %s has used its %d attempts. It goes to review as it is.", pr.URL, failed, pr.Key, s.cfg.Agent.MaxAttempts), log)
	case errors.Is(err, store.ErrNotChecking):
	default:
		log.Error("cannot queue the ticket for its failed checks; the next round tries again", "err", err)
	}
}

// reviewer reports whether what this person writes on a pull request is
// passed on to the agent: someone on github.allowed_reviewers, or without
// that list someone who belongs to the repository. Never the digital
// employee itself.
func (s *Server) reviewer(c github.Comment) bool {
	gh := s.cfg.GitHub
	if c.Author == "" || (gh.BotLogin != "" && strings.EqualFold(c.Author, gh.BotLogin)) {
		return false
	}
	if len(gh.AllowedReviewers) > 0 {
		for _, a := range gh.AllowedReviewers {
			if strings.EqualFold(strings.TrimSpace(a), c.Author) {
				return true
			}
		}
		return false
	}
	switch c.Association {
	case "OWNER", "MEMBER", "COLLABORATOR":
		return true
	}
	return false
}

// passOnComments gives the agent what reviewers wrote on a pull request
// since the last look, as a follow-up on the ticket.
func (s *Server) passOnComments(ctx context.Context, pr store.PullRequest, ref github.Ref, log *slog.Logger) {
	comments, err := s.github.Comments(ctx, ref, pr.SeenComment)
	if err != nil {
		log.Warn("cannot read the comments of the pull request", "err", err)
		return
	}
	if len(comments) == 0 {
		return
	}
	var parts, marked []string
	for _, c := range comments {
		// Each comment is passed on once. The time alone cannot tell:
		// GitHub's times are whole seconds.
		mark := fmt.Sprintf("github-comment:%s:%s:%d", pr.URL, c.Kind, c.ID)
		if isNew, err := s.seen.AddDelivery(mark, commentTTL); err != nil || !isNew {
			continue
		}
		marked = append(marked, mark)
		if !s.reviewer(c) {
			log.Debug("a comment on the pull request is not passed on: its author is not a reviewer", "author", c.Author, "association", c.Association)
			continue
		}
		where := "on the pull request"
		switch {
		case c.Path != "":
			where = "on " + c.Path + " in the pull request"
		case c.Review == "CHANGES_REQUESTED":
			where = "in a review that requests changes"
		case c.Review != "":
			where = "in a review"
		}
		body := strings.TrimSpace(c.Body)
		if len(body) > replyMax*2 {
			body = strings.ToValidUTF8(body[:replyMax*2], "") + " […]"
		}
		parts = append(parts, fmt.Sprintf("%s wrote %s (%s):\n%s", c.Author, where, pr.URL, body))
	}
	newest := comments[len(comments)-1].Created
	if len(parts) > 0 {
		t := s.newTask(pr.Source, pr.Key, "", "", "", "")
		t.Comment = strings.Join(parts, "\n\n")
		if session, err := s.runner.Session(pr.Source, pr.Key); err == nil {
			t.TrackerSession = session
		}
		// Not addressed to the agent itself: like a comment on the ticket,
		// it counts while ochell holds the ticket.
		switch later, err := s.runner.FollowUp(t, false); {
		case err == nil:
			log.Info("review comments passed on to the agent", "comments", len(parts), "task", t.ID, "kept_for_the_next_run", later)
		case errors.Is(err, store.ErrUnknown), errors.Is(err, store.ErrReleased):
		default:
			// Not noted as seen: the next round tries again.
			log.Error("cannot queue the review comments", "err", err)
			s.forgetDelivery(marked, log)
			return
		}
	}
	if err := s.runner.NotePullRequest(pr.Source, pr.Key, pr.URL, "", newest); err != nil {
		log.Error("cannot record which comments were passed on", "err", err)
	}
}
