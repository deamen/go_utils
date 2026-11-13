package ipsync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// ManagedTag marks ngrok IP policy rules owned by this tool. Rules without
// it are never modified or deleted.
const ManagedTag = "managed-by:ochell"

// Ngrok is a minimal client for the ngrok IP Policy Rules API
// (https://ngrok.com/docs/api-reference/ippolicyrules/list).
type Ngrok struct {
	HTTP   *http.Client
	APIURL string
	APIKey string
}

func NewNgrok(apiURL, apiKey string) *Ngrok {
	return &Ngrok{HTTP: &http.Client{Timeout: 30 * time.Second}, APIURL: strings.TrimRight(apiURL, "/"), APIKey: apiKey}
}

type Rule struct {
	ID          string `json:"id"`
	CIDR        string `json:"cidr"`
	Action      string `json:"action"`
	Description string `json:"description"`
	IPPolicy    struct {
		ID string `json:"id"`
	} `json:"ip_policy"`
}

func (n *Ngrok) do(ctx context.Context, method, url string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+n.APIKey)
	req.Header.Set("Ngrok-Version", "2")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := n.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		// ngrok echoes the credential in auth errors; keep it out of logs.
		msg := strings.TrimSpace(string(raw))
		if n.APIKey != "" {
			msg = strings.ReplaceAll(msg, n.APIKey, "[redacted]")
		}
		return fmt.Errorf("ngrok %s %s: HTTP %d: %s", method, url, resp.StatusCode, msg)
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Rules lists all rules of one IP policy.
func (n *Ngrok) Rules(ctx context.Context, policyID string) ([]Rule, error) {
	var all []Rule
	next := n.APIURL + "/ip_policy_rules?limit=100"
	for next != "" {
		var page struct {
			Rules       []Rule `json:"ip_policy_rules"`
			NextPageURI string `json:"next_page_uri"`
		}
		if err := n.do(ctx, http.MethodGet, next, nil, &page); err != nil {
			return nil, err
		}
		for _, r := range page.Rules {
			if r.IPPolicy.ID == policyID {
				all = append(all, r)
			}
		}
		next = page.NextPageURI
	}
	return all, nil
}

func (n *Ngrok) CreateRule(ctx context.Context, policyID string, p netip.Prefix, desc string) error {
	return n.do(ctx, http.MethodPost, n.APIURL+"/ip_policy_rules", map[string]string{
		"ip_policy_id": policyID,
		"cidr":         p.String(),
		"action":       "allow",
		"description":  desc,
	}, nil)
}

func (n *Ngrok) DeleteRule(ctx context.Context, id string) error {
	return n.do(ctx, http.MethodDelete, n.APIURL+"/ip_policy_rules/"+id, nil, nil)
}

// Plan is the difference between desired prefixes and managed rules.
type Plan struct {
	Create []netip.Prefix
	Delete []Rule
	Keep   int
}

// Diff compares desired prefixes with the managed rules of a policy.
// Unmanaged rules are left untouched; a desired prefix already covered by an
// unmanaged allow rule with the same CIDR is not duplicated.
func Diff(desired []netip.Prefix, rules []Rule) Plan {
	want := map[netip.Prefix]bool{}
	for _, p := range desired {
		want[p.Masked()] = true
	}
	var plan Plan
	have := map[netip.Prefix]bool{}
	for _, r := range rules {
		p, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			continue
		}
		p = p.Masked()
		if !strings.Contains(r.Description, ManagedTag) {
			if r.Action == "allow" {
				have[p] = true
			}
			continue
		}
		if !want[p] || have[p] || r.Action != "allow" {
			plan.Delete = append(plan.Delete, r)
			continue
		}
		have[p] = true
		plan.Keep++
	}
	for _, p := range Normalize(desired) {
		if !have[p] {
			plan.Create = append(plan.Create, p)
		}
	}
	return plan
}

// Apply executes a plan: creates first, then deletes, so the allow list never
// shrinks below the intersection of old and new ranges.
func (n *Ngrok) Apply(ctx context.Context, policyID, source string, plan Plan) error {
	for _, p := range plan.Create {
		if err := n.CreateRule(ctx, policyID, p, source+" "+ManagedTag); err != nil {
			return err
		}
	}
	for _, r := range plan.Delete {
		if err := n.DeleteRule(ctx, r.ID); err != nil {
			return err
		}
	}
	return nil
}
