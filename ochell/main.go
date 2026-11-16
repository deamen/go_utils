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
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"ochell/internal/admin"
	"ochell/internal/api"
	"ochell/internal/config"
	"ochell/internal/github"
	"ochell/internal/ipsync"
	"ochell/internal/mcp"
	"ochell/internal/metrics"
	"ochell/internal/policy"
	"ochell/internal/runner"
	"ochell/internal/server"
	"ochell/internal/source/linear"
	"ochell/internal/store"
	"ochell/internal/tracker"
	"ochell/internal/tracker/jiraapi"
	"ochell/internal/workflow"
)

var version = "dev"
var build string

var availCmds = [][2]string{
	{"serve", "run the webhook server (default)"},
	{"ngrok-sync", "sync Atlassian/Linear IP ranges into ngrok IP policies"},
	{"linear-install", "print the Linear agent app install URL"},
	{"jira-check", "check the Jira API access: list the bot's open tickets, and comment on one with --comment-on"},
	{"policy-check", "check the policy file and print its tiers, its scheduling and its autonomy settings"},
	{"workflow-check", "check a repository's WORKFLOW.md against the policy: ochell workflow-check --file WORKFLOW.md"},
	{"pause", "hold the queue of the running ochell: no new run starts; --tier NAME holds one tier"},
	{"resume", "end a pause; --tier NAME ends the pause of one tier"},
	{"status", "say whether the running ochell is paused, and what is queued and running"},
	{"reset", "reset the attempts of a ticket, and with --tier set its risk tier: ochell reset <jira|linear> <KEY> [--tier NAME]"},
	{"backup", "back the store of the running ochell up: to backup.dir, or to a file with --to"},
	{"restore", "put a backup in the place of the store, while ochell is stopped: ochell restore --from FILE"},
	{"outcomes", "show the outcome metrics per tier for a period: ochell outcomes [--since 2026-11-01] [--until 2026-11-15]"},
	{"cost", "show what the tickets have cost, or one ticket with its runs: ochell cost [<jira|linear> <KEY>]"},
	{"stop", "stop the run of a ticket and release the ticket: ochell stop <jira|linear> <KEY>"},
	{"autonomy", "show the level of autonomy of each tier, with its numbers and the last changes"},
	{"promote", "raise the level of autonomy of a tier by one step: ochell promote <TIER> [--reason TEXT]"},
	{"demote", "lower the level of autonomy of a tier by one step: ochell demote <TIER> [--reason TEXT]"},
	{"flag", "for a guardrail outside ochell: record a flag on a ticket's run and lower the level of its tier: ochell flag <jira|linear> <KEY> --reason TEXT"},
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
	case "workflow-check":
		err = workflowCheck(args)
	case "restore":
		err = restore(args)
	case "pause", "resume", "status", "reset", "stop", "cost", "outcomes", "backup", "autonomy", "promote", "demote", "flag":
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
	if err := srv.CheckScheduling(); err != nil {
		return fmt.Errorf("invalid policy:\n%w", err)
	}
	if sch := pol.DescribeScheduling(); len(sch) > 0 {
		log.Info("scheduling", "settings", strings.Join(sch, " "))
	}
	if a := pol.DescribeAutonomy(); a != "" {
		log.Info("autonomy: each tier has a level; an operator raises it (ochell promote), ochell lowers it by itself", "settings", a)
	}
	if cfg.API.Enabled {
		status := api.New(cfg.API, st, r, log)
		srv.UseAPI(api.Prefix, status, status.Link)
		log.Info("status API", "path", api.Prefix, "public_url", cfg.API.PublicURL)
	}
	if cfg.TicketTools.Enabled {
		// ochell's own MCP server, on the listeners of the webhooks. An
		// agent is another OS user and cannot open a socket of ochell's;
		// what keeps others out is the token of each run.
		tools := mcp.New(version, log)
		for _, source := range []string{"jira", "linear"} {
			if t := srv.Tickets(source); t != nil {
				tools.Use(source, t)
			}
		}
		lc, jc := cfg.Sources.Linear, cfg.Sources
		r.UseTicketTools(tools, cfg.TicketToolsURL(), []string{jc.JiraAPI.Token, jc.JiraWebhook.Secret, jc.JiraAutomation.Token, lc.Secret, lc.ClientSecret})
		srv.Mount(mcp.Path, tools)
		log.Info("ticket tools", "path", mcp.Path, "url", cfg.TicketToolsURL())
	}
	if err := r.UsePolicy(pol); err != nil {
		return fmt.Errorf("invalid policy:\n%w", err)
	}
	r.FollowChecks(cfg.GitHub.Enabled())
	r.UseRetention(cfg.Retention)
	r.UseBackup(cfg.Backup)
	r.SetNotifier(srv)
	if err := r.UseWorkspace(cfg.Workspace); err != nil {
		return err
	}
	if cfg.Workflow.Enabled {
		// The file comes from the default branch, through ochell's own
		// read access to GitHub; never from a working directory, which the
		// agent can write.
		r.UseWorkflow(cfg.Workflow, workflow.GitHub{Client: github.New(cfg.GitHub.APIURL, cfg.GitHub.Token)})
		log.Info("a repository's WORKFLOW.md is read from its default branch at the start of each run", "allow_hooks", cfg.Workflow.AllowHooks, "review_statuses", cfg.Workflow.ReviewStatuses)
	}
	expiry, _ := cfg.Agent.TokenExpiry()
	if cfg.Metrics.Enabled {
		srv.Mount("GET "+metrics.Path, &metrics.Handler{Token: cfg.Metrics.Token, Version: version, TokenExpiry: expiry, Store: st, Runner: r, Log: log})
		log.Info("metrics endpoint", "path", metrics.Path)
	}
	if !expiry.IsZero() {
		go watchTokenExpiry(ctx, expiry, cfg.Agent.TokenWarnDays, log)
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

// restore puts a backup in the place of the store. ochell must be stopped:
// a running ochell has the store open and would write over it.
func restore(args []string) error {
	var from string
	cfg, err := config.Load("restore", args, func(fs *flag.FlagSet) {
		fs.StringVar(&from, "from", "", "the backup file to restore")
	})
	if err != nil {
		return err
	}
	if from == "" {
		return errors.New("usage: ochell restore --from FILE [flags]")
	}
	if cfg.Admin.Socket != "" {
		if _, err := admin.Call(cfg.Admin.Socket, "GET", "status", nil); err == nil {
			return errors.New("ochell is running with this configuration; stop it before a restore")
		}
	}
	if err := store.Verify(from); err != nil {
		return fmt.Errorf("the backup cannot be used: %w", err)
	}
	dest := cfg.Store.Path
	// What is there now is kept under another name, not removed.
	kept := ""
	if _, err := os.Stat(dest); err == nil {
		kept = dest + ".before-restore-" + time.Now().UTC().Format("20060102T150405Z")
		if err := os.Rename(dest, kept); err != nil {
			return fmt.Errorf("cannot move the present store out of the way: %w", err)
		}
	}
	// The write-ahead files belong to the store that was moved away; with
	// the restored file they would be read as its newest changes.
	for _, ext := range []string{"-wal", "-shm"} {
		if err := os.Remove(dest + ext); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("cannot remove %s: %w", dest+ext, err)
		}
	}
	if err := copyFile(from, dest); err != nil {
		return fmt.Errorf("cannot put the backup in place: %w", err)
	}
	fmt.Printf("restored %s to %s\n", from, dest)
	if kept != "" {
		fmt.Printf("the store that was there is kept as %s\n", kept)
	}
	fmt.Println("start ochell; runs that were going on when the backup was made are queued again")
	return nil
}

// copyFile copies a file to a new file that only its owner can read.
func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	if dir := filepath.Dir(to); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	out, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(to)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
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
	for _, t := range pol.Tiers {
		if t.Grants.TicketTools && !cfg.TicketTools.Enabled {
			fmt.Printf("note: the tier %s is granted the ticket tools, but ticket_tools.enabled is not set in this configuration; ochell would not start\n", t.Name)
		}
	}
	if sch := pol.DescribeScheduling(); len(sch) > 0 {
		fmt.Println("scheduling: " + strings.Join(sch, " "))
	}
	if a := pol.DescribeAutonomy(); a != "" {
		fmt.Println("autonomy: " + a)
		for _, t := range pol.Tiers {
			fmt.Printf("  %s: starts at %s, can be promoted up to %s\n", t.Name, pol.Level(t.Name, ""), pol.MaxLevel(t.Name))
		}
	}
	return nil
}

// workflowCheck reads a WORKFLOW.md as "serve" would read it from a
// repository, and prints what it would mean under each tier of the policy.
// It is what a review of a change to the file can run before the merge.
func workflowCheck(args []string) error {
	var file string
	cfg, err := config.Load("workflow-check", args, func(fs *flag.FlagSet) {
		fs.StringVar(&file, "file", workflow.FileName, "the WORKFLOW.md to check")
	})
	if err != nil {
		return err
	}
	pol, err := loadPolicy(cfg)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	f, err := workflow.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is invalid; ochell would keep the last good version:\n%w", file, err)
	}
	fmt.Printf("%s is valid\n", file)
	if f.Prompt != "" {
		fmt.Println("prompt: the file's own")
	} else {
		fmt.Println("prompt: the host's (agent.prompt_template)")
	}
	if !cfg.Workflow.Enabled {
		fmt.Println("note: workflow.enabled is not set in this configuration; ochell would not read the file")
	}
	for _, t := range pol.Tiers {
		e := f.Apply(workflow.Host{Tier: t, AllowHooks: cfg.Workflow.AllowHooks, ReviewStatuses: cfg.Workflow.ReviewStatuses,
			LimitsTurns: cfg.Agent.Adapter == "claude", AbsoluteCommands: cfg.Agent.Launcher == "systemd"})
		line := fmt.Sprintf("tier %s: plan_gate=%s pr_review=%s auto_merge=%s", t.Name, e.Tier.PlanGate, e.Tier.PRReview, e.Tier.AutoMerge)
		if e.Tier.MaxTurns > 0 {
			line += fmt.Sprintf(" max_turns=%d", e.Tier.MaxTurns)
		}
		if e.ReviewStatus != "" {
			line += fmt.Sprintf(" review_status=%q", e.ReviewStatus)
		}
		for _, h := range e.Hooks.All() {
			if len(h.Command) > 0 {
				line += " hook=" + h.Name
			}
		}
		fmt.Println(line)
		for _, ig := range e.Ignored {
			fmt.Println("  " + ig)
		}
	}
	return nil
}

// tokenWarning says what the log should say about the end of the agent's
// credential on a given day, or "" when it is further away than warnDays.
func tokenWarning(expiry, now time.Time, warnDays int) (msg string, expired bool) {
	left := expiry.Sub(now)
	day := expiry.Add(-24 * time.Hour).Format("2006-01-02")
	switch {
	case left <= 0:
		return "the agent's token has expired (agent.token_expires " + day + "): runs fail until it is renewed; make a new one (claude setup-token), put it in the agent's environment file and set the new date", true
	case left <= time.Duration(warnDays)*24*time.Hour:
		return fmt.Sprintf("the agent's token expires in %d day(s), on %s (agent.token_expires): make a new one (claude setup-token) before then, put it in the agent's environment file and set the new date", int(left.Hours()/24)+1, day), false
	}
	return "", false
}

// watchTokenExpiry warns in the log, at start and then once a day, when
// the agent's credential is about to stop working or has.
func watchTokenExpiry(ctx context.Context, expiry time.Time, warnDays int, log *slog.Logger) {
	tick := time.NewTicker(24 * time.Hour)
	defer tick.Stop()
	for {
		if msg, expired := tokenWarning(expiry, time.Now(), warnDays); expired {
			log.Error(msg)
		} else if msg != "" {
			log.Warn(msg)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// adminCommand sends a command to the running ochell over its admin socket.
// The socket is found in the same configuration that the server uses.
func adminCommand(cmd string, args []string) error {
	var rest []string
	// The ticket of "reset", "stop" and "flag", and the tier of "promote"
	// and "demote", come before the flags: ochell reset jira DEV-1 --config …
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		rest, args = append(rest, args[0]), args[1:]
	}
	var tier, since, until, to, why string
	cfg, err := config.Load(cmd, args, func(fs *flag.FlagSet) {
		switch cmd {
		case "backup":
			fs.StringVar(&to, "to", "", "the file to write the backup to; it must not exist (default: a new file in backup.dir)")
		case "reset":
			fs.StringVar(&tier, "tier", "", "also put the ticket under this risk tier; the one way to lower a tier")
		case "outcomes":
			fs.StringVar(&since, "since", "", "start of the period: a date (2026-11-01), a time (2026-11-01T09:00:00Z), or how long ago (168h); default: 7 days ago")
			fs.StringVar(&until, "until", "", "end of the period, in the same forms; default: now")
		case "pause", "resume":
			fs.StringVar(&tier, "tier", "", "only the tickets of this risk tier")
		case "promote", "demote":
			fs.StringVar(&why, "reason", "", "why, for the record of the decision")
		case "flag":
			fs.StringVar(&why, "reason", "", "what the guardrail found; required")
		}
	})
	if err != nil {
		return err
	}
	method, query := "POST", url.Values{}
	// Who decided, for the record: the OS user that runs the command.
	me := func() {
		if u, err := user.Current(); err == nil {
			query.Set("user", u.Username)
		}
	}
	switch cmd {
	case "status", "autonomy":
		method = "GET"
	case "promote", "demote":
		if len(rest) != 1 {
			return fmt.Errorf("usage: ochell %s <TIER> [--reason TEXT] [flags]", cmd)
		}
		query.Set("tier", rest[0])
		query.Set("reason", why)
		rest = nil
		me()
	case "flag":
		if len(rest) != 2 || (rest[0] != "jira" && rest[0] != "linear") || strings.TrimSpace(why) == "" {
			return errors.New("usage: ochell flag <jira|linear> <KEY> --reason TEXT [flags]")
		}
		query.Set("source", rest[0])
		query.Set("key", rest[1])
		query.Set("reason", why)
		rest = nil
		me()
	case "pause", "resume":
		if tier != "" {
			query.Set("tier", tier)
		}
	case "backup":
		if to != "" {
			// The running ochell may have another working directory.
			abs, err := filepath.Abs(to)
			if err != nil {
				return err
			}
			query.Set("to", abs)
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
			me()
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
