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
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"ochell/internal/config"
	"ochell/internal/ipsync"
	"ochell/internal/runner"
	"ochell/internal/server"
	"ochell/internal/source/linear"
)

var version = "dev"
var build string

var availCmds = [][2]string{
	{"serve", "run the webhook server (default)"},
	{"ngrok-sync", "sync Atlassian/Linear IP ranges into ngrok IP policies"},
	{"linear-install", "print the Linear agent app install URL"},
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

	r, err := runner.New(cfg.Agent, log)
	if err != nil {
		return err
	}
	srv, err := server.New(cfg, log, r)
	if err != nil {
		return err
	}
	if cfg.NgrokSync.Enabled {
		go ipsync.RunSync(ctx, cfg.NgrokSync, ipsync.NewFetcher(), log)
	}

	r.Start()
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
