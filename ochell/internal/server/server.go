// Package server exposes the webhook endpoints and hands accepted tickets to
// the runner. Every endpoint authenticates the request, answers quickly (Jira
// and Linear both time out within seconds) and runs the agent asynchronously.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"

	"ochell/internal/auth"
	"ochell/internal/config"
	"ochell/internal/dedup"
	"ochell/internal/ipsync"
	"ochell/internal/runner"
	"ochell/internal/source/jira"
	"ochell/internal/source/linear"
	"ochell/internal/task"
)

const (
	maxBody     = 1 << 20
	dedupTTL    = 24 * time.Hour
	linearAckBy = 8 * time.Second
	replyMax    = 2000
)

// Submitter is implemented by *runner.Runner.
type Submitter interface {
	Submit(*task.Task) error
}

type Server struct {
	cfg     *config.Config
	log     *slog.Logger
	runner  Submitter
	seen    *dedup.Set
	linear  *linear.Client
	extURL  *template.Template
	handler http.Handler
	now     func() time.Time

	// Allowlists, started by Run when ip_allowlist.enabled.
	atlassianIPs *ipsync.Allowlist
	linearIPs    *ipsync.Allowlist
}

func New(cfg *config.Config, log *slog.Logger, r Submitter) (*Server, error) {
	s := &Server{cfg: cfg, log: log, runner: r, seen: dedup.New(dedupTTL), now: time.Now}
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

// deliveryKey returns the de-duplication key, or "" (never a duplicate) when
// the sender did not provide a delivery id.
func deliveryKey(source, delivery string) string {
	if delivery == "" {
		return ""
	}
	return source + ":" + delivery
}

// submit queues t and writes the HTTP response.
func (s *Server) submit(w http.ResponseWriter, t *task.Task, log *slog.Logger) bool {
	if !validKey.MatchString(t.Key) {
		log.Warn("rejecting invalid ticket key", "key", t.Key)
		reply(w, http.StatusBadRequest, "invalid ticket key")
		return false
	}
	switch err := s.runner.Submit(t); {
	case err == nil:
		log.Info("task queued", "task", t.ID, "key", t.Key)
		reply(w, http.StatusOK, "queued "+t.ID)
		return true
	case errors.Is(err, runner.ErrBusy):
		log.Info("ticket already in progress", "key", t.Key)
		reply(w, http.StatusOK, "already in progress")
	default:
		// 503 makes Jira and Linear retry later.
		log.Error("cannot queue task", "key", t.Key, "err", err)
		reply(w, http.StatusServiceUnavailable, "cannot queue task")
	}
	return false
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
	t, err := jira.ParseWebhook(body, cfg.BotAccountID)
	if errors.Is(err, jira.ErrIgnored) {
		log.Debug("ignored", "reason", err)
		reply(w, http.StatusOK, "ignored")
		return
	}
	if err != nil {
		log.Warn("bad payload", "err", err)
		reply(w, http.StatusBadRequest, "bad payload")
		return
	}
	key := deliveryKey("jira", delivery)
	if !s.seen.Add(key) {
		reply(w, http.StatusOK, "duplicate delivery")
		return
	}
	if !s.submit(w, s.newTask("jira", t.Key, t.Summary, t.URL, "", delivery), log) {
		s.seen.Remove(key)
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
	if err != nil {
		log.Warn("bad payload", "err", err)
		reply(w, http.StatusBadRequest, "bad payload")
		return
	}
	// Automation has no delivery id; the runner's per-ticket in-flight guard
	// prevents duplicate concurrent runs.
	s.submit(w, s.newTask("jira", t.Key, t.Summary, t.URL, "", ""), log)
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
	key := deliveryKey("linear", delivery)
	if !s.seen.Add(key) {
		reply(w, http.StatusOK, "duplicate delivery")
		return
	}
	t := s.newTask("linear", sess.Key, sess.Title, sess.URL, sess.Context, delivery)
	s.attachLinearCallbacks(t, sess.SessionID, log)
	if !s.submit(w, t, log) {
		s.seen.Remove(key)
		return
	}
	// Linear marks a session unresponsive unless it sees an activity within
	// ~10s of "created", so acknowledge now rather than when the agent starts.
	if s.linear != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), linearAckBy)
			defer cancel()
			if err := s.linear.CreateActivity(ctx, sess.SessionID, linear.ActivityThought,
				"Picked up "+sess.Key+", the digital employee is starting work."); err != nil {
				log.Error("linear acknowledgement failed", "err", err)
			}
		}()
	} else {
		log.Warn("linear client not configured (client_id); session will not receive activities")
	}
}

func (s *Server) attachLinearCallbacks(t *task.Task, sessionID string, log *slog.Logger) {
	if s.linear == nil {
		return
	}
	t.OnStart = func(ctx context.Context, t *task.Task) error {
		if s.extURL == nil {
			return nil
		}
		var b strings.Builder
		if err := s.extURL.Execute(&b, t); err != nil {
			return err
		}
		return s.linear.SetExternalURL(ctx, sessionID, "Agent run", b.String())
	}
	t.OnFinish = func(ctx context.Context, t *task.Task, res task.Result) error {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if res.Err != nil {
			return s.linear.CreateActivity(ctx, sessionID, linear.ActivityError,
				failureText(res)+"\n\n"+codeBlock(lastN(res.Tail, replyMax)))
		}
		msg := strings.TrimSpace(lastN(res.Tail, replyMax))
		if msg == "" {
			msg = "The agent finished."
		}
		return s.linear.CreateActivity(ctx, sessionID, linear.ActivityResponse, msg)
	}
}

// failureText says why a run did not succeed. It goes by the outcome: the
// exit code of a run that ochell stopped means nothing.
func failureText(res task.Result) string {
	switch res.Outcome {
	case task.OutcomeTimedOut, task.OutcomeStopped:
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
