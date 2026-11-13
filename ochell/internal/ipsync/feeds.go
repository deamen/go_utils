// Package ipsync fetches the published source IP ranges of Atlassian and
// Linear, enforces them as an optional in-process allowlist, and syncs them
// into ngrok IP policies.
//
// IP filtering only reduces noise: Atlassian's egress ranges also carry
// customer-controlled traffic (e.g. Forge), so signatures and tokens remain
// the real authentication.
package ipsync

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"time"
)

const (
	AtlassianFeedURL = "https://ip-ranges.atlassian.com/"
	LinearFeedURL    = "https://linear.app/.well-known/appspecific/app.linear.ips.json"
)

type Fetcher struct {
	HTTP         *http.Client
	AtlassianURL string
	LinearURL    string
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		HTTP:         &http.Client{Timeout: 30 * time.Second},
		AtlassianURL: AtlassianFeedURL,
		LinearURL:    LinearFeedURL,
	}
}

func (f *Fetcher) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

type atlassianFeed struct {
	SyncToken json.Number `json:"syncToken"`
	Items     []struct {
		CIDR      string   `json:"cidr"`
		Product   []string `json:"product"`
		Direction []string `json:"direction"`
		Perimeter string   `json:"perimeter"`
	} `json:"items"`
}

// Atlassian returns the commercial Jira egress ranges.
func (f *Fetcher) Atlassian(ctx context.Context) ([]netip.Prefix, error) {
	var feed atlassianFeed
	if err := f.getJSON(ctx, f.AtlassianURL, &feed); err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, it := range feed.Items {
		if it.Perimeter != "commercial" || !slices.Contains(it.Direction, "egress") || !slices.Contains(it.Product, "jira") {
			continue
		}
		p, err := netip.ParsePrefix(it.CIDR)
		if err != nil {
			return nil, fmt.Errorf("atlassian feed: %w", err)
		}
		out = append(out, p.Masked())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("atlassian feed: no jira egress ranges found")
	}
	return Normalize(out), nil
}

// Linear returns Linear's webhook source addresses ("ips" in the feed).
func (f *Fetcher) Linear(ctx context.Context) ([]netip.Prefix, error) {
	var feed struct {
		IPs []string `json:"ips"`
	}
	if err := f.getJSON(ctx, f.LinearURL, &feed); err != nil {
		return nil, err
	}
	out, err := ParsePrefixes(feed.IPs)
	if err != nil {
		return nil, fmt.Errorf("linear feed: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("linear feed: no addresses found")
	}
	return out, nil
}

// ParsePrefixes accepts CIDRs or bare addresses.
func ParsePrefixes(ss []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, err
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p.Masked())
	}
	return Normalize(out), nil
}

// Normalize sorts and de-duplicates prefixes.
func Normalize(ps []netip.Prefix) []netip.Prefix {
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return slices.Compact(ps)
}
