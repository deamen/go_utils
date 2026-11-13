package ipsync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"ochell/internal/config"
)

// SyncPolicies reconciles the configured ngrok IP policies with the Atlassian
// and Linear feeds. With dryRun only the plan is logged.
func SyncPolicies(ctx context.Context, cfg config.NgrokSync, f *Fetcher, log *slog.Logger, dryRun bool) error {
	if cfg.APIKey == "" {
		return errors.New("ngrok_sync.api_key is required")
	}
	targets := []struct {
		source, policy string
		load           func(context.Context) ([]netip.Prefix, error)
	}{
		{"atlassian", cfg.AtlassianPolicyID, f.Atlassian},
		{"linear", cfg.LinearPolicyID, f.Linear},
	}
	n := NewNgrok(cfg.APIURL, cfg.APIKey)
	var errs []error
	configured := 0
	for _, t := range targets {
		if t.policy == "" {
			continue
		}
		configured++
		desired, err := t.load(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s feed: %w", t.source, err))
			continue
		}
		rules, err := n.Rules(ctx, t.policy)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s policy %s: %w", t.source, t.policy, err))
			continue
		}
		plan := Diff(desired, rules)
		log.Info("ngrok ip policy plan", "source", t.source, "policy", t.policy,
			"desired", len(desired), "create", len(plan.Create), "delete", len(plan.Delete), "keep", plan.Keep, "dry_run", dryRun)
		for _, p := range plan.Create {
			log.Debug("create rule", "source", t.source, "cidr", p)
		}
		for _, r := range plan.Delete {
			log.Debug("delete rule", "source", t.source, "cidr", r.CIDR, "id", r.ID)
		}
		if dryRun {
			continue
		}
		if err := n.Apply(ctx, t.policy, t.source, plan); err != nil {
			errs = append(errs, fmt.Errorf("%s policy %s: %w", t.source, t.policy, err))
		}
	}
	if configured == 0 {
		return errors.New("no ngrok policy configured (ngrok_sync.atlassian_policy_id / linear_policy_id)")
	}
	return errors.Join(errs...)
}

// RunSync calls SyncPolicies now and then every interval until ctx is done.
func RunSync(ctx context.Context, cfg config.NgrokSync, f *Fetcher, log *slog.Logger) {
	for {
		if err := SyncPolicies(ctx, cfg, f, log, false); err != nil {
			log.Error("ngrok ip policy sync failed", "err", err)
		}
		if cfg.Interval <= 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.Interval):
		}
	}
}
