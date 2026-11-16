package main

import (
	"strings"
	"testing"
	"time"
)

func TestTokenWarning(t *testing.T) {
	// The token works through 13 November 2027.
	expiry := time.Date(2027, 11, 14, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		now     string
		want    string
		expired bool
	}{
		{"2027-10-01T12:00:00Z", "", false},
		{"2027-10-14T00:00:01Z", "", false},
		{"2027-10-15T12:00:00Z", "expires in 30 day(s), on 2027-11-13", false},
		{"2027-11-13T23:00:00Z", "expires in 1 day(s), on 2027-11-13", false},
		{"2027-11-14T00:00:00Z", "has expired (agent.token_expires 2027-11-13)", true},
		{"2028-01-01T00:00:00Z", "has expired", true},
	} {
		now, _ := time.Parse(time.RFC3339, c.now)
		msg, expired := tokenWarning(expiry, now, 30)
		if expired != c.expired || (c.want == "") != (msg == "") || !strings.Contains(msg, c.want) {
			t.Errorf("%s: %q, expired %v; want %q, expired %v", c.now, msg, expired, c.want, c.expired)
		}
	}
	if msg, _ := tokenWarning(expiry, expiry.Add(-48*time.Hour), 0); msg != "" {
		t.Errorf("with no warning period: %q", msg)
	}
}

func TestMoment(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{
		"":                     now.Add(-time.Hour),
		"2026-11-01":           time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		"2026-11-01T09:30:00Z": time.Date(2026, 11, 1, 9, 30, 0, 0, time.UTC),
		"48h":                  now.Add(-48 * time.Hour),
	} {
		if got, err := moment(in, now, now.Add(-time.Hour)); err != nil || !got.Equal(want) {
			t.Errorf("moment(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"last week", "-3h", "2026-13-01"} {
		if _, err := moment(bad, now, now); err == nil {
			t.Errorf("moment(%q) was accepted", bad)
		}
	}
}
