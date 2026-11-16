package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"ochell/internal/result"
	"ochell/internal/source"
	"ochell/internal/store"
	"ochell/internal/task"
)

// The sources behind the Source interface (package source). GitHub is one;
// Jira and Linear have handlers of their own in server.go.
//
// A source reads a delivery into an event, and everything that decides is
// here, the same for each of them: who may assign work, that the bot
// account gives itself none and passes no gate, what a comment starts, and
// how the ticket hears about its runs.

// tellBy is how long a source may take to write on a ticket.
const tellBy = 30 * time.Second

// bound is a source with the settings of the host for it.
type bound struct {
	src  source.Source
	path string
	// assigners and followUps are allowed_assigners and allowed_follow_ups.
	assigners, followUps []string
}

// bind adds a source. New does this from the configuration.
func (s *Server) bind(src source.Source, path string, assigners, followUps []string) {
	if s.sources == nil {
		s.sources = map[string]*bound{}
	}
	s.sources[src.Name()] = &bound{src: src, path: path, assigners: assigners, followUps: followUps}
}

// sourceBot reports whether one of ids is the bot account of a source
// behind the interface.
func (s *Server) sourceBot(name string, ids ...string) bool {
	b := s.sources[name]
	if b == nil {
		return false
	}
	for _, id := range ids {
		if b.src.Bot(id) {
			return true
		}
	}
	return false
}

// sourceTell writes a text on a ticket without holding the caller up. A
// source that cannot write stays silent, as a Jira ticket does without
// sources.jira_api.
func (s *Server) sourceTell(b *bound, key, text string, log *slog.Logger) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), tellBy)
		defer cancel()
		if err := b.src.Tell(ctx, key, text); err != nil && !errors.Is(err, source.ErrSilent) {
			log.Error("cannot write on the ticket", "source", b.src.Name(), "key", key, "err", err)
		}
	}()
}

// sourceStarted and sourceFinished are Started and Finished for a ticket
// of a source behind the interface: a comment on the ticket, as for Jira.
func (s *Server) sourceStarted(ctx context.Context, b *bound, t *task.Task) error {
	ctx, cancel := context.WithTimeout(ctx, tellBy)
	defer cancel()
	if err := b.src.Tell(ctx, t.Key, jiraStarted(t)); err != nil && !errors.Is(err, source.ErrSilent) {
		return err
	}
	return nil
}

func (s *Server) sourceFinished(ctx context.Context, b *bound, t *task.Task, res task.Result) error {
	ctx, cancel := context.WithTimeout(ctx, 2*tellBy)
	defer cancel()
	// A comment on the ticket always reaches ochell: the webhook that
	// brought the ticket brings its comments.
	if err := b.src.Tell(ctx, t.Key, finishedText(t, res, true, codeBlock, "")); err != nil && !errors.Is(err, source.ErrSilent) {
		return err
	}
	return nil
}

// pullPage matches the address of a pull request's page, whatever follows
// its number.
var pullPage = regexp.MustCompile(`^https?://([^/]+)/([^/]+)/([^/]+)/pull/([0-9]+)`)

// samePull reports whether two addresses name the same pull request.
func samePull(a, b string) bool {
	ma, mb := pullPage.FindStringSubmatch(strings.TrimSpace(a)), pullPage.FindStringSubmatch(strings.TrimSpace(b))
	if ma == nil || mb == nil {
		return false
	}
	for i := 1; i < len(ma); i++ {
		if !strings.EqualFold(strings.TrimSuffix(ma[i], ".git"), strings.TrimSuffix(mb[i], ".git")) {
			return false
		}
	}
	return true
}

// ownPullRequest reports whether a pull request is one that a ticket
// opened and ochell follows. Such a pull request is the work of that
// ticket; it does not become a ticket of its own.
func (s *Server) ownPullRequest(url string) bool {
	if url == "" {
		return false
	}
	open, err := s.runner.OpenPullRequests()
	if err != nil {
		s.log.Error("cannot read the open pull requests", "err", err)
		return false
	}
	for _, pr := range open {
		if samePull(pr.URL, url) {
			return true
		}
	}
	return false
}

// eventAttrs is what an event said about its ticket.
func eventAttrs(ev *source.Event) attrs {
	return attrs{labels: ev.Labels, issueType: ev.IssueType, priority: ev.Priority, hasPriority: ev.HasPriority, repo: ev.Repo}
}

// handleSource returns the handler of the webhook of one source.
func (s *Server) handleSource(b *bound) http.HandlerFunc {
	name := b.src.Name()
	return func(w http.ResponseWriter, r *http.Request) {
		log := s.log.With("source", name)
		body, ok := readBody(w, r)
		if !ok {
			return
		}
		ev, err := b.src.Receive(r.Header, body)
		switch {
		case errors.Is(err, source.ErrUnauthorized):
			log.Warn("signature verification failed", "err", err, "remote", r.RemoteAddr)
			reply(w, http.StatusUnauthorized, "invalid signature")
			return
		case err != nil:
			log.Warn("bad payload", "err", err)
			reply(w, http.StatusBadRequest, "bad payload")
			return
		}
		log = log.With("delivery", ev.Delivery)
		// What the bot account itself did to the ticket is no signal: it
		// gives itself no work, a close by it is not an acceptance of the
		// work, and its changes of labels move no tier. Taking the ticket
		// away from itself only stops work, and stays allowed.
		byBot := b.src.Bot(ev.Actor)
		switch ev.Kind {
		case source.Assigned:
			s.sourceAssigned(w, b, ev, byBot, deliveryKeys(name, ev.Delivery, body), log)
		case source.Unassigned:
			// Who may take a ticket away is the tracker's matter, like who
			// may close one.
			if !validKey.MatchString(ev.Key) {
				reply(w, http.StatusOK, "ignored")
				return
			}
			by := ev.ActorName
			if by == "" {
				by = "someone"
			}
			s.stop(w, name, ev.Key, by+", who took the ticket away from the digital employee", nil, log)
		case source.Closed:
			if byBot {
				log.Warn("ignored: the bot account closed its own ticket; that is not taken as an acceptance", "key", ev.Key)
				reply(w, http.StatusOK, "ignored: closed by the bot")
				return
			}
			s.closed(w, name, ev.Key, log)
		case source.Updated:
			if byBot {
				log.Debug("ignored: a change of the ticket by the bot account", "key", ev.Key)
				reply(w, http.StatusOK, "ignored: changed by the bot")
				return
			}
			s.updated(w, name, ev.Key, eventAttrs(ev), log)
		case source.Commented:
			s.sourceCommented(w, b, ev, byBot, deliveryKeys(name, ev.Delivery, body), log)
		default:
			if ev.Refused {
				log.Warn("ignored: "+ev.Why, "key", ev.Key)
				reply(w, http.StatusOK, "ignored: "+ev.Why)
				return
			}
			log.Debug("ignored", "reason", ev.Why)
			reply(w, http.StatusOK, "ignored")
		}
	}
}

// sourceAssigned handles the assignment of a ticket to the digital
// employee: a new run, when the person who assigned it may.
func (s *Server) sourceAssigned(w http.ResponseWriter, b *bound, ev *source.Event, byBot bool, keys []string, log *slog.Logger) {
	name := b.src.Name()
	if byBot {
		// The agent must not be able to give itself work, or to start a
		// ticket again that waits for a person.
		log.Warn("rejected: the bot account assigned the ticket to itself", "key", ev.Key)
		reply(w, http.StatusForbidden, "the bot account cannot assign work to itself")
		return
	}
	if !mayAssign(b.assigners, ev.Actor) {
		log.Warn("rejected: the assigner is not on the allowlist", "key", ev.Key, "assigner", ev.Actor)
		reply(w, http.StatusForbidden, "the assigner is not allowed to assign work")
		return
	}
	if s.ownPullRequest(ev.PullRequest) {
		log.Warn("rejected: the pull request is the work of a ticket, which ochell follows; it is not a ticket of its own", "key", ev.Key, "pull_request", ev.PullRequest)
		reply(w, http.StatusOK, "ignored: the pull request is the work of a ticket")
		return
	}
	if s.firstDelivery(w, keys, log) != deliveryNew {
		return
	}
	t := s.newTask(name, ev.Key, ev.Title, ev.URL, ev.Context, ev.Delivery)
	t.Actor = ev.Actor
	a := eventAttrs(ev)
	a.assigner = []string{ev.Actor}
	res := s.submit(w, t, a, log)
	if res == submitFailed {
		s.forgetDelivery(keys, log)
	}
	s.notStarted(res, t, log)
}

// sourceCommented handles a comment that someone added to a ticket. A
// comment of a person on a ticket that ochell holds starts a run of the
// ticket with the comment; the run continues the agent session of the
// ticket's earlier run. A first line that is a command stops the ticket,
// or approves its plan.
func (s *Server) sourceCommented(w http.ResponseWriter, b *bound, ev *source.Event, byBot bool, keys []string, log *slog.Logger) {
	name := b.src.Name()
	text := strings.TrimSpace(ev.Comment)
	first, rest := firstLine(text)
	switch {
	case byBot:
		// The loop guard: what the bot account writes (ochell's own
		// comments, and the agent's) must not wake the agent up, and is no
		// approval and no stop.
		log.Debug("ignored: a comment by the bot account", "key", ev.Key)
		reply(w, http.StatusOK, "ignored: comment by the bot")
		return
	case ev.Actor == "":
		log.Warn("ignored: a comment without an author", "key", ev.Key)
		reply(w, http.StatusOK, "ignored")
		return
	case !ev.Mine:
		log.Debug("ignored: a comment on a ticket that is not assigned to the bot", "key", ev.Key)
		reply(w, http.StatusOK, "ignored")
		return
	case text == "":
		log.Debug("ignored: a comment without text", "key", ev.Key)
		reply(w, http.StatusOK, "ignored")
		return
	case !validKey.MatchString(ev.Key):
		log.Warn("rejecting invalid ticket key", "key", ev.Key)
		reply(w, http.StatusBadRequest, "invalid ticket key")
		return
	}
	if s.firstDelivery(w, keys, log) != deliveryNew {
		return
	}
	who := ev.ActorName
	if who == "" {
		who = ev.Actor
	}
	if !s.mayFollowUp(name, ev.Key, b.followUps, b.assigners, ev.Reporter, ev.Actor) {
		// Comment text never widens who may direct the agent. The author
		// is told once, and only on a ticket that ochell knows.
		log.Warn("ignored: the author of the comment may not send follow-ups", "key", ev.Key, "author", ev.Actor)
		if _, known, _ := s.runner.Assigner(name, ev.Key); known && s.firstRefusal(name, ev.Key, ev.Actor) {
			s.sourceTell(b, ev.Key, "The last comment was not passed on to the digital employee: "+who+" is not on the list of people who may send it messages on this ticket.", log)
		}
		reply(w, http.StatusOK, "ignored: the author is not allowed")
		return
	}
	if first == stopCommand {
		s.stop(w, name, ev.Key, who+", with "+stopCommand+" in a comment", keys, log)
		return
	}
	t := s.newTask(name, ev.Key, ev.Title, ev.URL, "", ev.Delivery)
	if first == approveCommand {
		t.Comment = rest
		s.approve(w, t, who, []string{ev.Actor}, keys, func(text string, failed bool) {
			// The start of the run is commented anyway.
			if failed {
				s.sourceTell(b, ev.Key, text, log)
			}
		}, log)
		return
	}
	t.Comment = text
	switch later, err := s.runner.FollowUp(t, false); {
	case err == nil && later:
		log.Info("follow-up kept for the next run: the ticket is in progress", "key", t.Key, "author", ev.Actor, "chars", len(text))
		reply(w, http.StatusOK, "queued for the next run")
	case err == nil:
		log.Info("follow-up queued", "task", t.ID, "key", t.Key, "author", ev.Actor, "chars", len(text))
		reply(w, http.StatusOK, "queued "+t.ID)
	case errors.Is(err, store.ErrUnknown), errors.Is(err, store.ErrReleased):
		// Not a ticket that ochell holds: people talk to each other.
		log.Debug("ignored: a comment on a ticket that ochell does not hold", "key", t.Key, "reason", err)
		reply(w, http.StatusOK, "ignored")
	default:
		// 503 lets the sender deliver it again.
		log.Error("cannot queue the follow-up", "key", t.Key, "err", err)
		s.forgetDelivery(keys, log)
		reply(w, http.StatusServiceUnavailable, "cannot queue task")
	}
}

// notStartedText is what a ticket is told when it was accepted but is not
// started, and what has to happen first; "" when there is nothing to say.
func (s *Server) notStartedText(res submitResult, t *task.Task) string {
	switch res {
	case submitRefused:
		// Once a day: the same person may try again and again.
		if s.firstRefusal(t.Source, t.Key, "tier:"+t.Tier) {
			return "The digital employee did not start work on this ticket: " + tierRefusalText(t.Tier)
		}
	case submitCapped:
		return fmt.Sprintf("The digital employee did not start work on this ticket: it has used its %d attempts. Someone who looks after the orchestrator has to look at it and reset it (ochell reset %s %s); then assign the ticket again.", s.cfg.Agent.MaxAttempts, t.Source, t.Key)
	case submitHeld:
		return "The digital employee did not start work on this ticket: no repository is configured for it. Someone who looks after the orchestrator has to add one; then assign the ticket again."
	}
	return ""
}

// notStarted tells a ticket that it was accepted but is not started: in a
// comment, for Jira and for the sources behind the interface.
func (s *Server) notStarted(res submitResult, t *task.Task, log *slog.Logger) {
	text := s.notStartedText(res, t)
	if text == "" {
		return
	}
	if t.Source == "jira" {
		s.jiraComment(t.Key, text, log)
	} else if b := s.sources[t.Source]; b != nil {
		s.sourceTell(b, t.Key, text, log)
	}
}

// finishedText is the comment for the end of a run, on a ticket whose
// back-channel is its comments. It says the same as the activity that a
// Linear session gets. canReply: a comment on the ticket reaches ochell,
// so a run that waits for a person says how to answer; cannotReply is said
// about a plan otherwise. quote shows agent output as it is.
func finishedText(t *task.Task, res task.Result, canReply bool, quote func(string) string, cannotReply string) string {
	if res.Next != "" {
		return queuedAgainText(res)
	}
	if res.Outcome == task.OutcomeCancelled {
		return cancelledText(t, res)
	}
	if res.Escalation != "" {
		return escalationText(t, res)
	}
	if res.Outcome == task.OutcomeNoProgress {
		return noProgressText(t, res)
	}
	if res.Err != nil {
		return strings.TrimSpace(failureText(res) + "\n\n" + quote(lastN(res.Message, replyMax)))
	}
	if res.Signal == result.Plan {
		msg := planText(res, "comment")
		if !canReply {
			msg += "\n\n" + cannotReply
		}
		return msg
	}
	_, msg := signalActivity(res)
	if res.Signal == result.Done && res.AwaitChecks {
		msg = "The digital employee finished its work on this ticket.\n\n" + msg
		if res.PRURL != "" {
			msg += "\n\nPull request: " + res.PRURL
		}
		msg += "\n\n" + awaitChecksNote
	} else if res.Signal == result.Done {
		msg = "The digital employee finished its work on this ticket, which is now ready for review.\n\n" + msg
		if res.PRURL != "" {
			msg += "\n\nPull request: " + res.PRURL
		}
	} else if canReply {
		msg += "\n\n" + replyHint
	}
	return msg
}
