/*
AI tasks orchestrator for the "digital employee" POC.

Receives Jira (native webhook or Automation "Send web request") and Linear
(agent app) webhooks, authenticates them, and launches the configured agent
CLI (e.g. Claude Code) with a prompt describing the assigned ticket.
*/
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"ochell/internal/admin"
	"ochell/internal/api"
	"ochell/internal/config"
	"ochell/internal/ipsync"
	"ochell/internal/policy"
	"ochell/internal/runner"
	"ochell/internal/server"
	"ochell/internal/source/linear"
	"ochell/internal/store"
	"ochell/internal/tracker"
	"ochell/internal/tracker/jiraapi"
)

var version = "dev"
var build string

var availCmds = [][2]string{
	{"serve", "run the webhook server (default)"},
	{"ngrok-sync", "sync Atlassian/Linear IP ranges into ngrok IP policies"},
	{"linear-install", "print the Linear agent app install URL"},
	{"jira-check", "check the Jira API access: list the bot's open tickets, and comment on one with --comment-on"},
	{"policy-check", "check the policy file and print its tiers"},
	{"pause", "hold the queue of the running ochell: no new run starts; --tier NAME holds one tier"},
	{"resume", "end a pause; --tier NAME ends the pause of one tier"},
	{"status", "say whether the running ochell is paused, and what is queued and running"},
	{"reset", "reset the attempts of a ticket, and with --tier set its risk tier: ochell reset <jira|linear> <KEY> [--tier NAME]"},
	{"outcomes", "show the outcome metrics per tier for a period: ochell outcomes [--since 2026-11-01] [--until 2026-11-15]"},
	{"cost", "show what the tickets have cost, or one ticket with its runs: ochell cost [<jira|linear> <KEY>]"},
	{"stop", "stop the run of a ticket and release the ticket: ochell stop <jira|linear> <KEY>"},
	{"version", "print the version"},
}

func prtCmds() {
	var b bytes.Buffer
	tw := tabwriter.NewWriter(&b, 0, 8, 4, ' ', 0)
	fmt.Fprintf(tw, "Usage: ochell [command] [flags]\n")
	fmt.Fprintf(tw, "Version: %s-%s\n\n", version, build)
	fmt.Fprintf(tw, "Available commands:\n")
	for _, c := range availCmds {
		fmt.Fprintf(tw, "\t%s\t%s\n", c[0], c[1])
	}
	fmt.Fprintf(tw, "\nRun 'ochell <command> -h' for the command flags.\n")
	tw.Flush()
	fmt.Print(b.String())
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func main() {
	cmd, args := "serve", os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "ngrok-sync":
		err = ngrokSync(args)
	case "linear-install":
		err = linearInstall(args)
	case "jira-check":
		err = jiraCheck(args)
	case "policy-check":
		err = policyCheck(args)
	case "pause", "resume", "status", "reset", "stop", "cost", "outcomes":
		err = adminCommand(cmd, args)
	case "version":
		fmt.Printf("%s-%s\n", version, build)
	case "help":
		prtCmds()
	default:
		prtCmds()
		os.Exit(2)
	}
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	cfg, err := config.Load("serve", args, nil)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	log := newLogger(cfg.LogLevel)
	log.Info("starting ochell", "version", version, "build", build, "agent", cfg.Agent.Command)

	// The first signal starts the shutdown; a second one ends the wait for
	// running agents.
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hurry := make(chan struct{})
	go func() {
		<-sigs
		cancel()
		<-sigs
		close(hurry)
	}()

	// The policy is read before anything is started: ochell does not run
	// with a policy that it cannot read, or that the agent could change.
	pol, err := loadPolicy(cfg)
	if err != nil {
		return err
	}
	log.Info("policy", "file", pol.File, "version", pol.Version, "tiers", len(pol.Tiers), "default_tier", pol.DefaultTier, "rules", len(pol.Rules))
	if pol.File != "" && cfg.Agent.Launcher != "systemd" {
		log.Warn("the agent runs as ochell's own OS user (agent.launcher direct) and can write whatever ochell can, the policy file included; use the systemd launcher where the policy has to hold against the agent")
	}

	st, err := store.Open(cfg.Store.Path)
	if err != nil {
		return err
	}
	defer st.Close()
	st.SetPolicyVersion(pol.Version)
	r, err := runner.New(cfg.Agent, log, st)
	if err != nil {
		return err
	}
	srv, err := server.New(cfg, log, r, st)
	if err != nil {
		return err
	}
	srv.UsePolicy(pol)
	if cfg.API.Enabled {
		status := api.New(cfg.API, st, r, log)
		srv.UseAPI(api.Prefix, status, status.Link)
		log.Info("status API", "path", api.Prefix, "public_url", cfg.API.PublicURL)
	}
	if err := r.UsePolicy(pol); err != nil {
		return fmt.Errorf("invalid policy:\n%w", err)
	}
	r.FollowChecks(cfg.GitHub.Enabled())
	r.SetNotifier(srv)
	if err := r.UseWorkspace(cfg.Workspace); err != nil {
		return err
	}
	if cfg.NgrokSync.Enabled {
		go ipsync.RunSync(ctx, cfg.NgrokSync, ipsync.NewFetcher(), log)
	}

	if cfg.Admin.Socket != "" {
		adm, err := admin.Listen(cfg.Admin.Socket, r, log)
		if err != nil {
			return err
		}
		defer adm.Close()
		log.Info("admin channel", "socket", cfg.Admin.Socket)
	}

	if err := r.Start(); err != nil {
		return err
	}
	err = srv.Run(ctx)
	cancel()

	// Give running agents time to finish; a restart must not kill them all
	// at once. After the wait, or on a second signal, they are stopped.
	drain, stopDrain := context.WithTimeout(context.Background(), cfg.Agent.DrainTimeout)
	defer stopDrain()
	go func() {
		select {
		case <-hurry:
			log.Warn("second signal: not waiting for running agents")
			stopDrain()
		case <-drain.Done():
		}
	}()
	if n := r.Running(); n > 0 {
		log.Info("shutting down: waiting for running agents", "tasks", n, "drain_timeout", cfg.Agent.DrainTimeout)
	}
	r.Shutdown(drain)
	log.Info("stopped")
	return err
}

// moment reads a point in time as an operator writes it: a date, a time,
// or how long before now. Empty gives def.
func moment(s string, now, def time.Time) (time.Time, error) {
	if s == "" {
		return def, nil
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return now.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("%q is not a date (2026-11-01), a time (2026-11-01T09:00:00Z) or how long ago (168h)", s)
}

// loadPolicy reads the policy file of the configuration, or returns the
// built-in policy when there is none.
func loadPolicy(cfg *config.Config) (*policy.Policy, error) {
	if cfg.Policy.File == "" {
		return policy.Builtin(), nil
	}
	pol, err := policy.Load(cfg.Policy.File)
	if err != nil {
		return nil, fmt.Errorf("invalid policy:\n%w", err)
	}
	return pol, nil
}

// policyCheck reads the policy as "serve" would, and prints what it says.
// It is what a review of a change to the policy file can run.
func policyCheck(args []string) error {
	cfg, err := config.Load("policy-check", args, nil)
	if err != nil {
		return err
	}
	pol, err := loadPolicy(cfg)
	if err != nil {
		return err
	}
	if pol.File == "" {
		fmt.Println("no policy file is configured (policy.file): the built-in policy holds")
	} else {
		fmt.Printf("%s is valid\n", pol.File)
	}
	fmt.Printf("version %s, %d rule(s); tiers from the lowest to the highest:\n", pol.Version, len(pol.Rules))
	for _, line := range pol.Describe() {
		fmt.Println("  " + line)
	}
	return nil
}

// adminCommand sends a command to the running ochell over its admin socket.
// The socket is found in the same configuration that the server uses.
func adminCommand(cmd string, args []string) error {
	var rest []string
	// The ticket of "reset" and "stop" comes before the flags:
	// ochell reset jira DEV-1 --config …
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		rest, args = append(rest, args[0]), args[1:]
	}
	var tier, since, until string
	cfg, err := config.Load(cmd, args, func(fs *flag.FlagSet) {
		switch cmd {
		case "reset":
			fs.StringVar(&tier, "tier", "", "also put the ticket under this risk tier; the one way to lower a tier")
		case "outcomes":
			fs.StringVar(&since, "since", "", "start of the period: a date (2026-11-01), a time (2026-11-01T09:00:00Z), or how long ago (168h); default: 7 days ago")
			fs.StringVar(&until, "until", "", "end of the period, in the same forms; default: now")
		case "pause", "resume":
			fs.StringVar(&tier, "tier", "", "only the tickets of this risk tier")
		}
	})
	if err != nil {
		return err
	}
	method, query := "POST", url.Values{}
	switch cmd {
	case "status":
		method = "GET"
	case "pause", "resume":
		if tier != "" {
			query.Set("tier", tier)
		}
	case "outcomes":
		method = "GET"
		now := time.Now()
		from, err := moment(since, now, now.Add(-7*24*time.Hour))
		if err != nil {
			return fmt.Errorf("--since: %w", err)
		}
		to, err := moment(until, now, now)
		if err != nil {
			return fmt.Errorf("--until: %w", err)
		}
		query.Set("since", from.UTC().Format(time.RFC3339Nano))
		query.Set("until", to.UTC().Format(time.RFC3339Nano))
	case "cost":
		method = "GET"
		if len(rest) != 0 && (len(rest) != 2 || (rest[0] != "jira" && rest[0] != "linear")) {
			return errors.New("usage: ochell cost [<jira|linear> <KEY>] [flags]")
		}
		if len(rest) == 2 {
			query.Set("source", rest[0])
			query.Set("key", rest[1])
		}
		rest = nil
	case "reset", "stop":
		if len(rest) != 2 || (rest[0] != "jira" && rest[0] != "linear") {
			return fmt.Errorf("usage: ochell %s <jira|linear> <KEY> [flags]", cmd)
		}
		query.Set("source", rest[0])
		query.Set("key", rest[1])
		if tier != "" {
			query.Set("tier", tier)
		}
		rest = nil
		if cmd == "stop" {
			// For the note on the ticket.
			if u, err := user.Current(); err == nil {
				query.Set("user", u.Username)
			}
		}
	}
	if len(rest) > 0 {
		return fmt.Errorf("unexpected arguments: %v", rest)
	}
	answer, err := admin.Call(cfg.Admin.Socket, method, cmd, query)
	if err != nil {
		return err
	}
	fmt.Println(answer)
	return nil
}

func ngrokSync(args []string) error {
	var dryRun, loop bool
	cfg, err := config.Load("ngrok-sync", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&dryRun, "dry-run", false, "only print the planned changes")
		fs.BoolVar(&loop, "loop", false, "keep running and sync every ngrok_sync.interval")
	})
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if loop && !dryRun {
		ipsync.RunSync(ctx, cfg.NgrokSync, ipsync.NewFetcher(), log)
		return nil
	}
	return ipsync.SyncPolicies(ctx, cfg.NgrokSync, ipsync.NewFetcher(), log, dryRun)
}

// jiraCheck shows that the Jira API access works: it lists the tickets
// that ochell takes for the bot's open tickets, and on request adds a
// comment to one of them.
func jiraCheck(args []string) error {
	var commentOn, text string
	cfg, err := config.Load("jira-check", args, func(fs *flag.FlagSet) {
		fs.StringVar(&commentOn, "comment-on", "", "also add a comment to this ticket")
		fs.StringVar(&text, "text", "Test comment from ochell: the Jira API access works.", "the comment for --comment-on")
	})
	if err != nil {
		return err
	}
	api := cfg.Sources.JiraAPI
	if !api.Enabled() {
		return errors.New("sources.jira_api is not configured")
	}
	if err := api.Validate(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var jira tracker.Client = jiraapi.New(api)
	issues, err := jira.Assigned(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("%d open ticket(s) assigned to the bot on %s\n", len(issues), api.BaseURL)
	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	for _, is := range issues {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", is.Key, is.Title, strings.Join(is.Labels, ","))
	}
	tw.Flush()
	if commentOn == "" {
		return nil
	}
	if err := jira.Comment(ctx, commentOn, text); err != nil {
		return err
	}
	fmt.Println("comment added to", commentOn)
	return nil
}

func linearInstall(args []string) error {
	var ttl time.Duration
	cfg, err := config.Load("linear-install", args, func(fs *flag.FlagSet) {
		fs.DurationVar(&ttl, "ttl", 30*time.Minute, "how long the install link stays valid")
	})
	if err != nil {
		return err
	}
	lc := cfg.Sources.Linear
	if lc.ClientID == "" || lc.ClientSecret == "" || lc.RedirectURL == "" {
		return errors.New("sources.linear client_id, client_secret and redirect_url are required")
	}
	fmt.Println("Open this URL as a Linear workspace admin to install the agent (valid for", ttl.String()+"):")
	fmt.Println(linear.AuthorizeURL(lc.ClientID, lc.RedirectURL, linear.NewState(lc.ClientSecret, ttl)))
	fmt.Println("\nThe orchestrator must be running and reachable at the redirect URL to store the token.")
	return nil
}
