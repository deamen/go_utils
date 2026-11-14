package server

import (
	"context"
	"log/slog"
	"time"

	"ochell/internal/source/linear"
	"ochell/internal/task"
	"ochell/internal/ticket"
	"ochell/internal/tracker"
)

// The poller is the safety net behind the webhooks. A webhook is fast, but
// it can be lost: ochell was down, the network failed, or the tracker does
// not send the event at all. So at start, and then at poller.interval,
// ochell asks each tracker for the bot's open tickets, and
//
//   - starts a ticket that it has never seen: its webhook was missed;
//   - stops the agent of a ticket that is no longer the bot's or was
//     closed.
//
// A ticket that ochell knows is never started by the poller, whatever its
// state: one that waits for a human or is in review has had its run, and one
// that a person stopped or released stays stopped until it is assigned
// again, which only a webhook can tell.

// pollBy is how long one round may take per tracker.
const pollBy = 5 * time.Minute

// polled is one tracker that the poller asks.
type polled struct {
	source string
	api    tracker.Source
	// assigners is the allowlist of who may assign work.
	assigners []string
	// stops says whether a ticket that is no longer the bot's is stopped.
	stops bool
}

// polledSources returns the trackers that can be asked.
func (s *Server) polledSources() []polled {
	var out []polled
	src := s.cfg.Sources
	if api, ok := s.jira.(tracker.Source); ok && (src.JiraWebhook.Enabled || src.JiraAutomation.Enabled) {
		p := polled{source: "jira", api: api, assigners: src.JiraWebhook.AllowedAssigners, stops: true}
		if !src.JiraWebhook.Enabled {
			p.assigners = src.JiraAutomation.AllowedAssigners
		}
		// A rule without bot_account_id may start a ticket that is not
		// assigned to the bot. Such a ticket must not be stopped for that.
		if src.JiraAutomation.Enabled && src.JiraAutomation.BotAccountID == "" {
			p.stops = false
		}
		out = append(out, p)
	}
	if s.linear != nil && src.Linear.Enabled {
		out = append(out, polled{source: "linear", api: s.linear, assigners: src.Linear.AllowedAssigners, stops: true})
	}
	return out
}

// runPoller polls at once and then at every interval, until ctx is done.
func (s *Server) runPoller(ctx context.Context) {
	sources := s.polledSources()
	if len(sources) == 0 {
		s.log.Info("poller: no tracker can be asked; it needs sources.jira_api, or the Linear app with its token")
		return
	}
	s.log.Info("poller started", "interval", s.cfg.Poller.Interval, "trackers", len(sources))
	tick := time.NewTicker(s.cfg.Poller.Interval)
	defer tick.Stop()
	for {
		s.Poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Poll asks every tracker once.
func (s *Server) Poll(ctx context.Context) {
	for _, p := range s.polledSources() {
		if ctx.Err() != nil {
			return
		}
		pctx, cancel := context.WithTimeout(ctx, pollBy)
		s.pollSource(pctx, p)
		cancel()
	}
}

func (s *Server) pollSource(ctx context.Context, p polled) {
	log := s.log.With("source", p.source, "by", "poller")
	issues, err := p.api.Assigned(ctx)
	if err != nil {
		// Nothing is concluded from a list that could not be read.
		log.Warn("poller: cannot list the bot's tickets", "err", err)
		return
	}
	listed := map[string]bool{}
	started := 0
	for _, is := range issues {
		listed[is.Key] = true
		if !validKey.MatchString(is.Key) {
			continue
		}
		st, err := s.runner.State(p.source, is.Key)
		if err != nil {
			log.Error("poller: cannot read the ticket", "key", is.Key, "err", err)
			continue
		}
		if st != ticket.None {
			continue
		}
		if s.pollStart(ctx, p, is, log) {
			started++
		}
	}
	stopped := 0
	if p.stops {
		stopped = s.pollStops(ctx, p, listed, log)
	}
	log.Debug("poller: round done", "listed", len(issues), "started", started, "stopped", stopped)
}

// pollStart starts a ticket that ochell has never seen, as its webhook
// would have. It reports whether a run was queued.
func (s *Server) pollStart(ctx context.Context, p polled, is tracker.Issue, log *slog.Logger) bool {
	// Who assigned it: the allowlist holds for a missed webhook as well.
	who, err := p.api.Assigner(ctx, is.Key)
	if err != nil {
		log.Warn("poller: cannot find out who assigned the ticket", "key", is.Key, "err", err)
		who = nil
	}
	if !mayAssign(p.assigners, who...) {
		if s.refusedOnce(p.source, is.Key) {
			log.Warn("poller: ticket not started: the assigner is not on the allowlist, or is not known", "key", is.Key, "assigner", who)
		}
		return false
	}
	t := s.newTask(p.source, is.Key, is.Title, is.URL, "", "")
	t.Cause = task.CausePoll
	if len(who) > 0 {
		t.Actor = who[0]
	}
	if p.source == "linear" {
		// Only a webhook brings a session. Without one there is nowhere
		// to report, so ochell opens its own.
		session, err := s.linear.CreateSessionOnIssue(ctx, is.Key)
		if err != nil {
			log.Warn("poller: cannot open an agent session on the issue; the next round tries again", "key", is.Key, "err", err)
			return false
		}
		t.TrackerSession = session
	}
	switch res, _, _ := s.admit(t, is.Labels, log); res {
	case submitQueued:
		log.Info("poller: started a ticket whose webhook was missed", "key", is.Key, "task", t.ID)
		if t.TrackerSession != "" {
			s.linearActivity(t.TrackerSession, linear.ActivityThought, pickedUpText(is.Key), log)
		}
		return true
	case submitHeld:
		if t.TrackerSession != "" {
			s.linearActivity(t.TrackerSession, linear.ActivityElicitation, noRepoText(is.Key), log)
		} else {
			s.jiraNotStarted(res, is.Key, log)
		}
	}
	return false
}

// pollStops stops the tickets that have a queued or running task and are
// not on the list of the bot's open tickets any more, after asking the
// tracker about each: the list alone is not believed. It returns how many
// were stopped.
func (s *Server) pollStops(ctx context.Context, p polled, listed map[string]bool, log *slog.Logger) int {
	active, err := s.runner.ActiveTickets(p.source)
	if err != nil {
		log.Error("poller: cannot read the tickets in progress", "err", err)
		return 0
	}
	stopped := 0
	for _, key := range active {
		if listed[key] {
			continue
		}
		st, err := p.api.Lookup(ctx, key)
		if err != nil {
			log.Warn("poller: cannot ask the tracker about a ticket in progress", "key", key, "err", err)
			continue
		}
		switch {
		case st.Closed:
			log.Warn("poller: a ticket in progress was closed", "key", key)
			if err := s.runner.Closed(p.source, key); err != nil {
				log.Error("poller: cannot record that the ticket was closed", "key", key, "err", err)
				continue
			}
			stopped++
		case st.Unassigned:
			log.Warn("poller: a ticket in progress is no longer assigned to the bot", "key", key)
			if _, err := s.runner.Stop(p.source, key, "the orchestrator: the ticket is no longer assigned to the digital employee"); err != nil {
				log.Error("poller: cannot stop the ticket", "key", key, "err", err)
				continue
			}
			stopped++
		}
	}
	return stopped
}

// refusedOnce reports whether this is the first time that the poller
// refuses a ticket, so that the log says it once and not at every round.
func (s *Server) refusedOnce(source, key string) bool {
	s.pollMu.Lock()
	defer s.pollMu.Unlock()
	if s.pollRefused == nil {
		s.pollRefused = map[string]bool{}
	}
	k := source + ":" + key
	first := !s.pollRefused[k]
	s.pollRefused[k] = true
	return first
}
