package ipsync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestFeeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/atlassian":
			w.Write([]byte(`{"syncToken":1,"items":[
			  {"cidr":"104.192.136.0/21","product":["jira","confluence"],"direction":["egress"],"perimeter":"commercial"},
			  {"cidr":"2401:1d80::/32","product":["jira"],"direction":["egress","ingress"],"perimeter":"commercial"},
			  {"cidr":"10.0.0.0/8","product":["jira"],"direction":["ingress"],"perimeter":"commercial"},
			  {"cidr":"11.0.0.0/8","product":["email"],"direction":["egress"],"perimeter":"commercial"},
			  {"cidr":"12.0.0.0/8","product":["jira"],"direction":["egress"],"perimeter":"fedramp-moderate"}]}`))
		case "/linear":
			w.Write([]byte(`{"ips":["35.231.147.226/32","34.38.87.206"],"codingSessionIps":["1.2.3.4/32"]}`))
		}
	}))
	defer srv.Close()
	f := NewFetcher()
	f.AtlassianURL, f.LinearURL = srv.URL+"/atlassian", srv.URL+"/linear"

	atl, err := f.Atlassian(context.Background())
	if err != nil || len(atl) != 2 {
		t.Fatalf("atlassian: %v %v", atl, err)
	}
	lin, err := f.Linear(context.Background())
	if err != nil || len(lin) != 2 || lin[0].String() != "34.38.87.206/32" {
		t.Fatalf("linear: %v %v", lin, err)
	}
}

func TestDiff(t *testing.T) {
	desired, _ := ParsePrefixes([]string{"1.1.1.0/24", "2.2.2.0/24", "3.3.3.3"})
	rules := []Rule{
		{ID: "r1", CIDR: "1.1.1.0/24", Action: "allow", Description: "atlassian " + ManagedTag},
		{ID: "r2", CIDR: "9.9.9.0/24", Action: "allow", Description: "atlassian " + ManagedTag},
		{ID: "r3", CIDR: "2.2.2.0/24", Action: "allow", Description: "added by hand"},
		{ID: "r4", CIDR: "8.8.8.0/24", Action: "allow", Description: "added by hand"},
		{ID: "r5", CIDR: "1.1.1.0/24", Action: "allow", Description: "dup " + ManagedTag},
	}
	p := Diff(desired, rules)
	if len(p.Create) != 1 || p.Create[0].String() != "3.3.3.3/32" {
		t.Errorf("create = %v", p.Create)
	}
	var del []string
	for _, r := range p.Delete {
		del = append(del, r.ID)
	}
	if len(del) != 2 || del[0] != "r2" || del[1] != "r5" {
		t.Errorf("delete = %v (unmanaged rules must never be deleted)", del)
	}
	if p.Keep != 1 {
		t.Errorf("keep = %d", p.Keep)
	}
}

func TestMiddleware(t *testing.T) {
	extra, _ := ParsePrefixes([]string{"203.0.113.0/24"})
	l := NewAllowlist("t", nil, extra)
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}), true, discard(), l)

	cases := []struct {
		remote, xff string
		want        int
	}{
		{"203.0.113.5:1234", "", 200},
		{"198.51.100.1:1234", "", 403},
		{"127.0.0.1:1234", "198.51.100.1, 203.0.113.9", 200},
		{"127.0.0.1:1234", "203.0.113.9, 198.51.100.1", 403}, // spoofed left-most entry is ignored
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("remote=%s xff=%q: got %d want %d", c.remote, c.xff, w.Code, c.want)
		}
	}
	if !l.Contains(netip.MustParseAddr("::ffff:203.0.113.7")) {
		t.Error("IPv4-mapped address not matched")
	}
}

func TestNgrokErrorRedactsKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Ngrok-Version") != "2" {
			t.Errorf("missing Ngrok-Version header")
		}
		w.WriteHeader(403)
		w.Write([]byte(`{"msg":"Your credential: 'secret-key' is invalid"}`))
	}))
	defer srv.Close()
	_, err := NewNgrok(srv.URL, "secret-key").Rules(context.Background(), "ipp_x")
	if err == nil || strings.Contains(err.Error(), "secret-key") {
		t.Fatalf("api key leaked or no error: %v", err)
	}
}
