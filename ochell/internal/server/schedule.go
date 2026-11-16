package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"ochell/internal/policy"
	"ochell/internal/source/linear"
	"ochell/internal/store"
	"ochell/internal/tracker"
)

// Scheduling. The order of the queue and the places per repository and per
// tier are the store's matter (Claim). What needs the tracker is here: the
// priority of a ticket whose source did not name one, and the gates of the
// policy that hold the start of the work on a ticket,
//
//   - required_labels: the ticket carries every one of these labels, each
//     put there by someone other than the bot account;
//   - blocked_by: no open ticket blocks it.
//
// A ticket that has to be looked at is queued with a hold, and stays
// queued. This loop asks the tracker about each held ticket, outside any
// transaction of the store, and takes the hold off when nothing holds the
// ticket any more:
//
//   - at once for a new ticket;
//   - when a webhook says that the ticket changed (a label);
//   - for every held ticket when a webhook says that some ticket was closed
//     (it may have been a blocker), and at scheduling.check_interval, which
//     is what finds a blocker that was resolved without a webhook reaching
//     ochell.
//
// A gate that cannot be checked stays shut: while the tracker does not
// answer, a ticket that a gate could hold waits. Without a gate in the
// policy the tracker is only asked for the priority, and a ticket whose
// tracker does not answer starts without one.

// gateBy is how long the tracker may take to answer about one ticket.
const gateBy = 30 * time.Second

// holdNoAnswer is the hold of a ticket whose gates could not be checked.
const holdNoAnswer = "the tracker could not be asked whether a gate of scheduling holds the ticket; ochell asks again"

// trackerFor returns the API of the tracker of a source, or nil when it
// cannot be asked.
func (s *Server) trackerFor(source string) tracker.Source {
	for _, p := range s.polledSources() {
		if p.source == source {
			return p.api
		}
	}
	return nil
}

// CheckScheduling refuses a policy whose gates could not be checked: they
// are read from the tracker's API, so every source that is turned on needs
// one. A gate that silently held nothing would be worse than none.
func (s *Server) CheckScheduling() error {
	if !s.policy.Scheduling.Gated() {
		return nil
	}
	src := s.cfg.Sources
	var errs []error
	if (src.JiraWebhook.Enabled || src.JiraAutomation.Enabled) && s.trackerFor("jira") == nil {
		errs = append(errs, errors.New("the policy sets scheduling.required_labels or scheduling.blocked_by, which ochell checks against the tracker: the Jira sources need sources.jira_api"))
	}
	if src.Linear.Enabled && s.trackerFor("linear") == nil {
		errs = append(errs, errors.New("the policy sets scheduling.required_labels or scheduling.blocked_by, which ochell checks against the tracker: sources.linear needs the app (client_id) and its token"))
	}
	return errors.Join(errs...)
}

// look says which held tickets are looked at: every one, or else the ones
// that were not looked at yet and the ones named here, as "source:key".
type look struct {
	all     bool
	tickets map[string]bool
}

// kickGates makes the loop look now: with all at every held ticket;
// otherwise at the tickets that were not looked at yet, and at the ticket
// that is named.
func (s *Server) kickGates(all bool, source, key string) {
	s.gateMu.Lock()
	s.gateNext.all = s.gateNext.all || all
	if key != "" {
		if s.gateNext.tickets == nil {
			s.gateNext.tickets = map[string]bool{}
		}
		s.gateNext.tickets[source+":"+key] = true
	}
	s.gateMu.Unlock()
	select {
	case s.gateKick <- struct{}{}:
	default:
	}
}

// runGates looks at the held tickets at once, then whenever it is told to
// and at every scheduling.check_interval, until ctx is done.
func (s *Server) runGates(ctx context.Context) {
	tick := time.NewTicker(s.policy.Scheduling.CheckInterval)
	defer tick.Stop()
	next := look{all: true}
	for {
		s.checkHeld(ctx, next)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			next = look{all: true}
		case <-s.gateKick:
			s.gateMu.Lock()
			next, s.gateNext = s.gateNext, look{}
			s.gateMu.Unlock()
		}
	}
}

// CheckHeld asks the tracker once about the tickets that scheduling
// holds, and lets the ones go that nothing holds any more: with all about
// every one of them, otherwise only about the ones that were not looked at
// yet.
func (s *Server) CheckHeld(ctx context.Context, all bool) {
	s.checkHeld(ctx, look{all: all})
}

func (s *Server) checkHeld(ctx context.Context, at look) {
	held, err := s.runner.Held()
	if err != nil {
		s.log.Error("scheduling: cannot read the held tickets", "err", err)
		return
	}
	for _, h := range held {
		if ctx.Err() != nil {
			return
		}
		if at.all || h.Hold == store.HoldPending || at.tickets[h.Source+":"+h.Key] {
			s.checkTicket(ctx, h)
		}
	}
}

// checkTicket asks the tracker about one held ticket.
func (s *Server) checkTicket(ctx context.Context, h store.Held) {
	log := s.log.With("source", h.Source, "key", h.Key, "by", "scheduling")
	gated := s.policy.Scheduling.Gated()
	hold := ""
	if api := s.trackerFor(h.Source); api == nil {
		// CheckScheduling keeps ochell from starting like this; a ticket
		// that was held under another configuration ends up here.
		if gated {
			hold = holdNoAnswer
		}
	} else {
		cctx, cancel := context.WithTimeout(ctx, gateBy)
		sch, err := api.Scheduling(cctx, h.Key)
		cancel()
		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, tracker.ErrNotFound):
			// Work without a ticket in the tracker, such as a Linear
			// session outside an issue: it has no label and no blocker.
			hold = s.holdFor(h.Source, tracker.Scheduling{})
		case err != nil && gated:
			if h.Hold != holdNoAnswer {
				log.Warn("scheduling: cannot ask the tracker about the ticket; it waits, and is asked about again", "err", err)
			}
			hold = holdNoAnswer
		case err != nil:
			log.Warn("scheduling: cannot ask the tracker for the priority of the ticket; it starts without one", "err", err)
		default:
			rank := sch.Priority
			if rank == 0 && sch.PriorityName != "" {
				rank = s.policy.Scheduling.Rank(sch.PriorityName)
			}
			// Before the hold is taken off, so that the ticket gets its
			// place in the queue.
			if err := s.runner.SetPriority(h.Source, h.Key, rank); err != nil {
				log.Error("scheduling: cannot record the priority of the ticket", "err", err)
			}
			hold = s.holdFor(h.Source, sch)
		}
	}
	changed, err := s.runner.SetHold(h.Source, h.Key, hold)
	if err != nil {
		log.Error("scheduling: cannot record why the ticket waits", "err", err)
		return
	}
	if !changed || hold == "" || hold == holdNoAnswer {
		return
	}
	log.Info("scheduling: the ticket waits", "why", hold)
	// The ticket is told once, when it is first found held, and not at
	// every look or when the reason changes.
	if h.Hold == store.HoldPending || h.Hold == holdNoAnswer {
		s.tellHeld(h.Source, h.Key, hold, log)
	}
}

// holdFor returns why the gates of the policy hold a ticket, given what
// its tracker says about it; "" when they do not.
func (s *Server) holdFor(source string, sch tracker.Scheduling) string {
	pol := s.policy.Scheduling
	var why []string
	if len(pol.RequiredLabels) > 0 {
		// A label that the bot account put there opens no gate: the agent
		// can label tickets with its own tool.
		var counted, byBot []string
		for _, l := range sch.Labels {
			bot := l.Bot
			switch source {
			case "jira":
				for _, id := range l.By {
					bot = bot || s.jiraBot(id)
				}
			case "linear":
				bot = bot || s.linearBot("", l.By...)
			}
			if bot {
				byBot = append(byBot, l.Name)
			} else {
				counted = append(counted, l.Name)
			}
		}
		if missing := pol.Missing(counted); len(missing) > 0 {
			text := "it needs the label " + strings.Join(missing, ", ")
			if len(missing) > 1 {
				text = "it needs the labels " + strings.Join(missing, ", ")
			}
			if again := pol.Missing(append(counted, byBot...)); len(again) < len(missing) {
				text += " from a person (a label that the bot account added does not count)"
			}
			why = append(why, text)
		}
	}
	if pol.BlockedBy == policy.BlockedByWait && len(sch.BlockedBy) > 0 {
		blockers := append([]string{}, sch.BlockedBy...)
		sort.Strings(blockers)
		why = append(why, "it is blocked by "+strings.Join(blockers, ", ")+", which is not done")
	}
	return strings.Join(why, "; ")
}

// tellHeld says on a ticket that its work has not started, and why: a
// comment in Jira, a thought in the Linear session of its queued run.
func (s *Server) tellHeld(source, key, hold string, log *slog.Logger) {
	text := fmt.Sprintf("The digital employee has not started work on %s yet: %s. The work starts by itself once that has changed.", key, hold)
	switch source {
	case "jira":
		s.jiraComment(key, text, log)
	case "linear":
		if session, err := s.runner.Session(source, key); err == nil && session != "" {
			s.linearActivity(session, linear.ActivityThought, text, log)
		}
	}
}
