package ipsync

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Allowlist holds a refreshable set of prefixes. Until the first successful
// load it denies everything (fail closed).
type Allowlist struct {
	name  string
	load  func(context.Context) ([]netip.Prefix, error)
	extra []netip.Prefix

	mu       sync.RWMutex
	prefixes []netip.Prefix
}

func NewAllowlist(name string, load func(context.Context) ([]netip.Prefix, error), extra []netip.Prefix) *Allowlist {
	return &Allowlist{name: name, load: load, extra: extra, prefixes: extra}
}

func (a *Allowlist) Contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, p := range a.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Refresh reloads the feed; on failure the previous list is kept.
func (a *Allowlist) Refresh(ctx context.Context) error {
	if a.load == nil {
		return nil
	}
	ps, err := a.load(ctx)
	if err != nil {
		return err
	}
	ps = Normalize(append(ps, a.extra...))
	a.mu.Lock()
	a.prefixes = ps
	a.mu.Unlock()
	return nil
}

// Run refreshes immediately and then every interval until ctx is done.
func (a *Allowlist) Run(ctx context.Context, interval time.Duration, log *slog.Logger) {
	refresh := func() {
		if err := a.Refresh(ctx); err != nil {
			log.Error("ip allowlist refresh failed, keeping previous list", "list", a.name, "err", err)
			return
		}
		a.mu.RLock()
		n := len(a.prefixes)
		a.mu.RUnlock()
		log.Info("ip allowlist refreshed", "list", a.name, "prefixes", n)
	}
	refresh()
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refresh()
		}
	}
}

// ClientIP returns the peer address, or with trustProxy the right-most
// X-Forwarded-For entry (the address seen by the trusted proxy in front).
func ClientIP(r *http.Request, trustProxy bool) (netip.Addr, bool) {
	if trustProxy {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			parts := strings.Split(xff[len(xff)-1], ",")
			if a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return a.Unmap(), true
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// Middleware rejects requests whose client IP is not in any of the lists.
func Middleware(next http.Handler, trustProxy bool, log *slog.Logger, lists ...*Allowlist) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, ok := ClientIP(r, trustProxy)
		if ok {
			for _, l := range lists {
				if l.Contains(ip) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		log.Warn("request from non-allowlisted ip", "ip", ip, "path", r.URL.Path)
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}
