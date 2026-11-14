// Package server exposes the webhook endpoints and hands accepted tickets to
// the runner. Every endpoint authenticates the request, answers quickly (Jira
// and Linear both time out within seconds) and runs the agent asynchronously.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"text/template"
	"time"

	"ochell/internal/auth"
	"ochell/internal/config"
	"ochell/internal/ipsync"
	"ochell/internal/result"
	"ochell/internal/runner"
	"ochell/internal/source/jira"
	"ochell/internal/source/linear"
	"ochell/internal/store"
	"ochell/internal/task"
	"ochell/internal/ticket"
)

const (
	maxBody     = 1 << 20
	dedupTTL    = 24 * time.Hour
	linearAckBy = 8 * time.Second
	replyMax    = 2000
)

// Submitter is implemented by *runner.Runner.
type Submitter interface {
	// Submit queues a task.
	Submit(*task.Task) error
	// Hold records a ticket as waiting for a human, without a task.
	Hold(*task.Task, ticket.Reason) error
	// Closed is called when the tracker reports a ticket as closed.
	Closed(source, key string) error
}

// Deliveries remembers the webhook deliveries that were handled. It is
// implemented by *store.Store, so they are not forgotten by a restart.
type Deliveries interface {
	// AddDelivery records key for ttl and reports whether it is new.
	AddDelivery(key string, ttl time.Duration) (bool, error)
	RemoveDelivery(key string) error
}

type Server struct {
	cfg     *config.Config
	log     *slog.Logger
	runner  Submitter
	seen    Deliveries
	linear  *linear.Client
	extURL  *template.Template
	handler http.Handler
	now     func() time.Time

	// Allowlists, started by Run when ip_allowlist.enabled.
	atlassianIPs *ipsync.Allowlist
	linearIPs    *ipsync.Allowlist
}

func New(cfg *config.Config, log *slog.Logger, r Submitter, seen Deliveries) (*Server, error) {
	s := &Server{cfg: cfg, log: log, runner: r, seen: seen, now: time.Now}
	lc := cfg.Sources.Linear
	if lc.Enabled && lc.ClientID != "" {
		s.linear = linear.NewClient(lc.ClientID, lc.ClientSecret, lc.TokenFile)
		if lc.APIURL != "" {
			s.linear.APIURL = lc.APIURL
		}
		if lc.TokenURL != "" {
			s.linear.TokenURL = lc.TokenURL
		}
	}
	if lc.ExternalURL != "" {
		t, err := template.New("external_url").Parse(lc.ExternalURL)
		if err != nil {
			return nil, fmt.Errorf("sources.linear.external_url: %w", err)
		}
		s.extURL = t
	}
	if err := s.buildAllowlists(); err != nil {
		return nil, err
	}
	s.handler = s.routes()
	return s, nil
}

func (s *Server) buildAllowlists() error {
	ipc := s.cfg.IPAllowlist
	if !ipc.Enabled {
		return nil
	}
	extra, err := ipsync.ParsePrefixes(ipc.ExtraCIDRs)
	if err != nil {
		return fmt.Errorf("ip_allowlist.extra_cidrs: %w", err)
	}
	f := ipsync.NewFetcher()
	var atl, lin func(context.Context) ([]netip.Prefix, error)
	if ipc.AtlassianFeed {
		atl = f.Atlassian
	}
	if ipc.LinearFeed {
		lin = f.Linear
	}
	s.atlassianIPs = ipsync.NewAllowlist("atlassian", atl, extra)
	s.linearIPs = ipsync.NewAllowlist("linear", lin, extra)
	return nil
}

// Handler returns the HTTP handler (used by tests).
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok\n")
	})
	src := s.cfg.Sources
	guard := func(h http.HandlerFunc, l *ipsync.Allowlist) http.Handler {
		if l == nil {
			return h
		}
		return ipsync.Middleware(h, s.cfg.IPAllowlist.TrustProxyHeader, s.log, l)
	}
	if src.JiraWebhook.Enabled {
		mux.Handle("POST "+src.JiraWebhook.Path, guard(s.handleJiraWebhook, s.atlassianIPs))
	}
	if src.JiraAutomation.Enabled {
		mux.Handle("POST "+src.JiraAutomation.Path, guard(s.handleJiraAutomation, s.atlassianIPs))
	}
	if src.Linear.Enabled {
		mux.Handle("POST "+src.Linear.Path, guard(s.handleLinear, s.linearIPs))
		if s.linear != nil {
			// The OAuth callback is reached by the installing admin's browser,
			// so it is not IP restricted; the signed state protects it.
			mux.HandleFunc("GET "+src.Linear.CallbackPath, s.handleLinearCallback)
		}
	}
	return mux
}

// Run serves on the configured listeners until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if s.atlassianIPs != nil {
		go s.atlassianIPs.Run(ctx, s.cfg.IPAllowlist.Refresh, s.log)
		go s.linearIPs.Run(ctx, s.cfg.IPAllowlist.Refresh, s.log)
	}

	var servers []*http.Server
	errc := make(chan error, 2)
	start := func(l config.Listener, useTLS bool) {
		srv := &http.Server{
			Addr:              l.Addr(),
			Handler:           s.handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
			ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		}
		if useTLS {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		servers = append(servers, srv)
		go func() {
			var err error
			if useTLS {
				s.log.Info("listening", "proto", "https", "addr", srv.Addr)
				err = srv.ListenAndServeTLS(l.CertFile, l.KeyFile)
			} else {
				s.log.Info("listening", "proto", "http", "addr", srv.Addr)
				err = srv.ListenAndServe()
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	if s.cfg.HTTP.Enabled {
		start(s.cfg.HTTP, false)
	}
	if s.cfg.HTTPS.Enabled {
		start(s.cfg.HTTPS, true)
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = srv.Shutdown(shutdownCtx)
		}()
	}
	wg.Wait()
	return runErr
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	return body, true
}

func reply(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	io.WriteString(w, msg+"\n")
}

// validKey restricts ticket keys before they reach file names and templates.
var validKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

func (s *Server) newTask(source, key, title, url, ctxText, delivery string) *task.Task {
	now := s.now().UTC()
	return &task.Task{
		ID:         fmt.Sprintf("%s-%s-%s", now.Format("20060102T150405.000Z"), source, key),
		Source:     source,
		Key:        key,
		Title:      title,
		URL:        url,
		Context:    ctxText,
		DeliveryID: delivery,
		Received:   now,
	}
}

// deliveryKeys returns the de-duplication keys of a signed delivery: its
// body, and the delivery id when the sender provided one.
//
// The body comes first because it is what the signature covers. The delivery
// id is a header, which anyone who replays a captured request can change or
// leave out. It is still kept, in case a retry by the sender is signed again
// with a new timestamp.
func deliveryKeys(source, delivery string, body []byte) []string {
	sum := sha256.Sum256(body)
	keys := []string{source + ":body:" + hex.EncodeToString(sum[:])}
	if delivery != "" {
		keys = append(keys, source+":"+delivery)
	}
	return keys
}

// deliveryState is what firstDelivery found.
type deliveryState int

const (
	deliveryNew deliveryState = iota
	deliveryDuplicate
	// deliveryUnknown: the store could not be read or written.
	deliveryUnknown
)

// firstDelivery records keys and reports whether none of them was seen
// before. It writes the HTTP response unless the delivery is new.
func (s *Server) firstDelivery(w http.ResponseWriter, keys []string, log *slog.Logger) deliveryState {
	for _, k := range keys {
		isNew, err := s.seen.AddDelivery(k, dedupTTL)
		if err != nil {
			// 503 makes Jira and Linear retry later.
			log.Error("cannot record the delivery", "err", err)
			s.forgetDelivery(keys, log)
			reply(w, http.StatusServiceUnavailable, "cannot record the delivery")
			return deliveryUnknown
		}
		if !isNew {
			reply(w, http.StatusOK, "duplicate delivery")
			return deliveryDuplicate
		}
	}
	return deliveryNew
}

// forgetDelivery lets the sender retry a delivery that was not handled.
func (s *Server) forgetDelivery(keys []string, log *slog.Logger) {
	for _, k := range keys {
		if err := s.seen.RemoveDelivery(k); err != nil {
			log.Error("cannot forget the delivery", "err", err)
		}
	}
}

// submitResult is what happened to a task handed to the runner.
type submitResult int

const (
	// submitFailed: not queued; the sender may retry the delivery.
	submitFailed submitResult = iota
	submitQueued
	// submitBusy: the ticket is already queued or running. The delivery
	// was handled and must not be retried.
	submitBusy
	// submitHeld: the ticket cannot be started as it is, and now waits for
	// a human. The delivery was handled.
	submitHeld
	// submitCapped: the ticket has used up its attempts, and now waits for
	// a human. The delivery was handled.
	submitCapped
)

// mayAssign reports whether one of ids, the ways a payload names the person
// who assigned the work, is on the allowlist. An empty allowlist allows
// everyone.
func mayAssign(allowed []string, ids ...string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, id := range ids {
		if id != "" && slices.ContainsFunc(allowed, func(a string) bool { return strings.EqualFold(a, id) }) {
			return true
		}
	}
	return false
}

// submit queues t and writes the HTTP response. labels are the ticket's
// labels, for the repository mapping.
func (s *Server) submit(w http.ResponseWriter, t *task.Task, labels []string, log *slog.Logger) submitResult {
	if !validKey.MatchString(t.Key) {
		log.Warn("rejecting invalid ticket key", "key", t.Key)
		reply(w, http.StatusBadRequest, "invalid ticket key")
		return submitFailed
	}
	// With a repository mapping, a ticket that no entry matches is not
	// started: nobody said where its work belongs.
	held := false
	if len(s.cfg.Repos) > 0 {
		repo, ok := s.cfg.RepoFor(t.Source, t.Key, labels)
		t.Repo, held = repo, !ok
	}
	var err error
	if held {
		err = s.runner.Hold(t, ticket.ReasonNoRepoMapping)
	} else {
		err = s.runner.Submit(t)
	}
	// A ticket that has used up its attempts is not started again by
	// anything: it waits until a human looks at it and resets it.
	if errors.Is(err, runner.ErrAttempts) {
		if err = s.runner.Hold(t, ticket.ReasonEscalation); err == nil {
			log.Warn("ticket not started: it has used up its attempts", "key", t.Key, "max_attempts", s.cfg.Agent.MaxAttempts)
			reply(w, http.StatusOK, fmt.Sprintf("not started: %s has used its %d attempts", t.Key, s.cfg.Agent.MaxAttempts))
			return submitCapped
		}
	}
	switch {
	case err == nil && held:
		log.Warn("ticket not started: no repository is mapped to it", "key", t.Key, "project", config.ProjectOf(t.Key), "labels", labels)
		reply(w, http.StatusOK, "not started: no repository is mapped to "+t.Key)
		return submitHeld
	case err == nil:
		log.Info("task queued", "task", t.ID, "key", t.Key, "repo", t.Repo)
		reply(w, http.StatusOK, "queued "+t.ID)
		return submitQueued
	case errors.Is(err, runner.ErrBusy):
		log.Info("ticket already in progress", "key", t.Key)
		reply(w, http.StatusOK, "already in progress")
		return submitBusy
	default:
		// 503 makes Jira and Linear retry later.
		log.Error("cannot queue task", "key", t.Key, "err", err)
		reply(w, http.StatusServiceUnavailable, "cannot queue task")
		return submitFailed
	}
}

// closed handles the tracker's report that a ticket was closed, and writes
// the HTTP response. It is safe to receive the same report twice.
func (s *Server) closed(w http.ResponseWriter, source, key string, log *slog.Logger) {
	if !validKey.MatchString(key) {
		reply(w, http.StatusOK, "ignored")
		return
	}
	switch err := s.runner.Closed(source, key); {
	case err == nil:
		reply(w, http.StatusOK, "closed "+key)
	case errors.Is(err, store.ErrUnknown):
		log.Debug("ignored: a ticket that ochell never worked on was closed", "key", key)
		reply(w, http.StatusOK, "ignored")
	case errors.Is(err, runner.ErrBusy):
		// Stopping a run from the tracker is not supported yet.
		log.Warn("ticket was closed while its run is queued or running; the run goes on", "key", key)
		reply(w, http.StatusOK, "closed while in progress")
	default:
		log.Error("cannot record that the ticket was closed", "key", key, "err", err)
		reply(w, http.StatusServiceUnavailable, "cannot record the close")
	}
}

func (s *Server) handleJiraWebhook(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Sources.JiraWebhook
	delivery := r.Header.Get("X-Atlassian-Webhook-Identifier")
	log := s.log.With("source", "jira_webhook", "delivery", delivery)
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	if err := auth.VerifyHubSignature(cfg.Secret, body, r.Header.Get("X-Hub-Signature")); err != nil {
		log.Warn("signature verification failed", "err", err, "remote", r.RemoteAddr)
		reply(w, http.StatusUnauthorized, "invalid signature")
		return
	}
	// The signature proves who sent the payload, not when. Without this an
	// old request could be sent again after a restart, when the deliveries
	// kept in memory are gone.
	if err := jira.CheckTimestamp(body, cfg.MaxSkew, s.now()); err != nil {
		log.Warn("timestamp check failed", "err", err, "remote", r.RemoteAddr)
		reply(w, http.StatusUnauthorized, "stale or missing timestamp")
		return
	}
	t, err := jira.ParseWebhook(body, cfg.BotAccountID)
	if errors.Is(err, jira.ErrIgnored) {
		if key, ok := jira.ParseClosed(body); ok {
			s.closed(w, "jira", key, log)
			return
		}
		log.Debug("ignored", "reason", err)
		reply(w, http.StatusOK, "ignored")
		return
	}
	if err != nil {
		log.Warn("bad payload", "err", err)
		reply(w, http.StatusBadRequest, "bad payload")
		return
	}
	if !mayAssign(cfg.AllowedAssigners, t.Actor) {
		log.Warn("rejected: the assigner is not on the allowlist", "key", t.Key, "assigner", t.Actor)
		reply(w, http.StatusForbidden, "the assigner is not allowed to assign work")
		return
	}
	keys := deliveryKeys("jira", delivery, body)
	if s.firstDelivery(w, keys, log) != deliveryNew {
		return
	}
	if s.submit(w, s.newTask("jira", t.Key, t.Summary, t.URL, "", delivery), t.Labels, log) == submitFailed {
		s.forgetDelivery(keys, log)
	}
}

func (s *Server) handleJiraAutomation(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Sources.JiraAutomation
	log := s.log.With("source", "jira_automation")
	if err := auth.VerifyToken(r, cfg.Header, cfg.Token); err != nil {
		log.Warn("token verification failed", "err", err, "remote", r.RemoteAddr)
		reply(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	t, err := jira.ParseAutomation(body, cfg.BotAccountID)
	if errors.Is(err, jira.ErrIgnored) {
		log.Debug("ignored", "reason", err)
		reply(w, http.StatusOK, "ignored")
		return
	}
	if errors.Is(err, jira.ErrNoAssignee) {
		log.Warn("rejected: the payload names no assignee; check the rule's request body")
		reply(w, http.StatusBadRequest, "no assignee in the payload: send assigneeAccountId")
		return
	}
	if err != nil {
		log.Warn("bad payload", "err", err)
		reply(w, http.StatusBadRequest, "bad payload")
		return
	}
	if len(cfg.AllowedAssigners) > 0 && t.Actor == "" {
		log.Warn("rejected: the payload does not say who triggered the rule; check the rule's request body", "key", t.Key)
		reply(w, http.StatusBadRequest, "no initiator in the payload: send initiatorAccountId")
		return
	}
	if !mayAssign(cfg.AllowedAssigners, t.Actor) {
		log.Warn("rejected: the assigner is not on the allowlist", "key", t.Key, "assigner", t.Actor)
		reply(w, http.StatusForbidden, "the assigner is not allowed to assign work")
		return
	}
	// Automation has no delivery id; the runner's per-ticket in-flight guard
	// prevents duplicate concurrent runs.
	s.submit(w, s.newTask("jira", t.Key, t.Summary, t.URL, "", ""), t.Labels, log)
}

func (s *Server) handleLinear(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Sources.Linear
	delivery := r.Header.Get("Linear-Delivery")
	log := s.log.With("source", "linear", "delivery", delivery)
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	if err := linear.Verify(cfg.Secret, body, r.Header.Get("Linear-Signature"), cfg.MaxSkew, s.now()); err != nil {
		log.Warn("verification failed", "err", err, "remote", r.RemoteAddr)
		reply(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	ev, sess, err := linear.Parse(body)
	if errors.Is(err, linear.ErrIgnored) {
		if key, ok := ev.Closed(); ok {
			s.closed(w, "linear", key, log)
			return
		}
		if ev != nil && ev.Type == "AgentSessionEvent" && ev.Action == "prompted" {
			// Follow-up messages are not delivered to a running agent yet.
			log.Info("follow-up prompt received but not supported yet",
				"session", ev.AgentSession.ID, "chars", len(ev.PromptText()))
		} else {
			log.Debug("ignored", "reason", err)
		}
		reply(w, http.StatusOK, "ignored")
		return
	}
	if err != nil {
		log.Warn("bad payload", "err", err)
		reply(w, http.StatusBadRequest, "bad payload")
		return
	}
	keys := deliveryKeys("linear", delivery, body)
	if s.firstDelivery(w, keys, log) != deliveryNew {
		return
	}
	if !mayAssign(cfg.AllowedAssigners, sess.Actor, sess.ActorEmail) {
		// The delivery stays handled, and the session gets an answer: it
		// must not look unanswered, and a retry must not post twice.
		log.Warn("rejected: the assigner is not on the allowlist", "key", sess.Key, "assigner", sess.Actor, "email", sess.ActorEmail)
		s.linearActivity(sess.SessionID, linear.ActivityError,
			"The digital employee did not start work on "+sess.Key+": you are not on the list of people who may delegate work to it.", log)
		reply(w, http.StatusOK, "the assigner is not allowed to assign work")
		return
	}
	t := s.newTask("linear", sess.Key, sess.Title, sess.URL, sess.Context, delivery)
	t.TrackerSession = sess.SessionID
	t.Comment = sess.Comment
	// Linear marks a session unresponsive unless it sees an activity within
	// ~10s of "created", so answer now rather than when the agent starts.
	switch s.submit(w, t, sess.Labels, log) {
	case submitQueued:
		s.linearActivity(sess.SessionID, linear.ActivityThought,
			"Picked up "+sess.Key+", the digital employee is starting work.", log)
	case submitBusy:
		// A second session on a ticket that is already queued or running
		// starts no run, but it must not be left without an answer. A
		// response closes the session.
		s.linearActivity(sess.SessionID, linear.ActivityResponse,
			sess.Key+" is already being worked on by the digital employee in an earlier session, so this request did not start a new run. The result will be posted in that session. Messages to a running agent are not supported yet.", log)
	case submitCapped:
		s.linearActivity(sess.SessionID, linear.ActivityElicitation,
			fmt.Sprintf("The digital employee did not start work on %s: the issue has used its %d attempts. Someone who looks after the orchestrator has to look at it and reset it (ochell reset linear %s); then delegate the issue again.", sess.Key, s.cfg.Agent.MaxAttempts, sess.Key), log)
	case submitHeld:
		s.linearActivity(sess.SessionID, linear.ActivityElicitation,
			"The digital employee did not start work on "+sess.Key+": no repository is configured for it. Someone who looks after the orchestrator has to add one; then delegate the issue again.", log)
	default:
		s.forgetDelivery(keys, log)
	}
}

// linearActivity posts an activity to a session without holding up the
// webhook response.
func (s *Server) linearActivity(sessionID, kind, body string, log *slog.Logger) {
	if s.linear == nil {
		log.Warn("linear client not configured (client_id); session will not receive activities")
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), linearAckBy)
		defer cancel()
		if err := s.linear.CreateActivity(ctx, sessionID, kind, body); err != nil {
			log.Error("linear activity failed", "session", sessionID, "type", kind, "err", err)
		}
	}()
}

// reportsToLinear says whether the run of t is reported to a Linear agent
// session. The session id is stored with the task, so this also works for a
// task that was queued before a restart.
func (s *Server) reportsToLinear(t *task.Task) bool {
	return s.linear != nil && t.Source == "linear" && t.TrackerSession != ""
}

// Started tells the source of t that its run begins. It implements
// runner.Notifier.
func (s *Server) Started(ctx context.Context, t *task.Task) error {
	if !s.reportsToLinear(t) || s.extURL == nil {
		return nil
	}
	var b strings.Builder
	if err := s.extURL.Execute(&b, t); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.linear.SetExternalURL(ctx, t.TrackerSession, "Agent run", b.String())
}

// Finished tells the source of t how its run ended. It implements
// runner.Notifier.
func (s *Server) Finished(ctx context.Context, t *task.Task, res task.Result) error {
	if !s.reportsToLinear(t) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if res.Err != nil {
		return s.linear.CreateActivity(ctx, t.TrackerSession, linear.ActivityError,
			strings.TrimSpace(failureText(res)+"\n\n"+codeBlock(lastN(res.Message, replyMax))))
	}
	kind, msg := signalActivity(res)
	return s.linear.CreateActivity(ctx, t.TrackerSession, kind, msg)
}

// signalActivity turns the result of a run that ended by itself into what
// the Linear session is told. The agent's signal decides: a finished piece
// of work is a response, which closes the session; anything that needs a
// human is an elicitation, which leaves the session waiting for a reply.
func signalActivity(res task.Result) (kind, msg string) {
	said := strings.TrimSpace(lastN(res.SignalMessage, replyMax))
	if said == "" {
		// The agent's last words stand in for a message it did not write.
		said = strings.TrimSpace(lastN(res.Message, replyMax))
	}
	switch res.Signal {
	case result.Done:
		if said == "" {
			said = "The agent finished."
		}
		return linear.ActivityResponse, said
	case result.NeedsInput:
		return linear.ActivityElicitation, said
	case result.Blocked:
		return linear.ActivityElicitation, "The agent is blocked: " + said
	case result.LowConfidence:
		return linear.ActivityElicitation, "The agent finished, but is not sure of the result: " + said
	case result.OutOfScope:
		return linear.ActivityElicitation, "The agent did not do this, because it is out of its scope: " + said
	}
	note := "The agent stopped without reporting a result, so this ticket now waits for a human."
	if said == "" {
		return linear.ActivityElicitation, note
	}
	return linear.ActivityElicitation, said + "\n\n" + note
}

// failureText says why a run did not succeed. It goes by the outcome: the
// exit code of a run that ochell stopped means nothing.
func failureText(res task.Result) string {
	switch res.Outcome {
	case task.OutcomeTimedOut, task.OutcomeStopped, task.OutcomeInterrupted:
		return fmt.Sprintf("The run is incomplete: %v.", res.Err)
	case task.OutcomeNotStarted:
		return fmt.Sprintf("The run did not start: %v.", res.Err)
	}
	return fmt.Sprintf("The agent failed (exit %d): %v", res.ExitCode, res.Err)
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[len(s)-n:]
	// Do not start in the middle of a UTF-8 sequence.
	for i := 0; i < len(s) && i < 4; i++ {
		if s[i]&0xC0 != 0x80 {
			return "…" + s[i:]
		}
	}
	return "…" + s
}

func codeBlock(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return "```\n" + strings.ReplaceAll(s, "```", "'''") + "\n```"
}

func (s *Server) handleLinearCallback(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Sources.Linear
	log := s.log.With("source", "linear_oauth")
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		log.Warn("oauth install denied", "error", e)
		reply(w, http.StatusBadRequest, "authorization was not granted")
		return
	}
	if err := linear.VerifyState(cfg.ClientSecret, q.Get("state"), s.now()); err != nil {
		log.Warn("invalid oauth state", "err", err, "remote", r.RemoteAddr)
		reply(w, http.StatusBadRequest, "invalid or expired state; generate a new install link")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	tok, err := s.linear.Exchange(ctx, q.Get("code"), cfg.RedirectURL)
	if err != nil {
		log.Error("oauth code exchange failed", "err", err)
		reply(w, http.StatusBadGateway, "token exchange failed")
		return
	}
	v, err := s.linear.Viewer(ctx, tok.AccessToken)
	if err != nil {
		log.Error("cannot identify installed workspace", "err", err)
		reply(w, http.StatusBadGateway, "cannot verify installation")
		return
	}
	if cfg.OrganizationID != "" && v.Organization.ID != cfg.OrganizationID {
		log.Warn("install for unexpected workspace rejected", "organization", v.Organization.ID)
		reply(w, http.StatusForbidden, "workspace not allowed")
		return
	}
	if err := s.linear.SaveToken(tok); err != nil {
		log.Error("saving token failed", "err", err)
		reply(w, http.StatusInternalServerError, "cannot save token")
		return
	}
	log.Info("linear agent installed", "app_user", v.ID, "organization", v.Organization.Name, "organization_id", v.Organization.ID)
	reply(w, http.StatusOK, fmt.Sprintf("Installed as %s in workspace %s. You can close this page.", v.Name, v.Organization.Name))
}
