package github_test

import (
	"context"
	"strings"
	"testing"

	"ochell/internal/github"
	"ochell/internal/github/githubtest"
)

func TestParseURL(t *testing.T) {
	for _, ok := range []string{
		"https://github.com/example/web/pull/42",
		" https://GitHub.com/example/web/pull/42/files ",
		"https://github.com/example/web/pull/42#issuecomment-1",
	} {
		ref, err := github.ParseURL(ok, "github.com")
		if err != nil || ref != (github.Ref{Owner: "example", Repo: "web", Number: 42}) {
			t.Errorf("%q: %+v, %v", ok, ref, err)
		}
	}
	for _, bad := range []string{
		"", "example/web#42", "https://github.com/example/web/issues/42", "https://github.com/example/web/pull/0",
		"https://evil.example/example/web/pull/42", "https://github.com.evil.example/example/web/pull/42",
		"ftp://github.com/example/web/pull/42", "https://github.com/example/web/pull/abc", "https://github.com/../web/pull/1",
	} {
		if ref, err := github.ParseURL(bad, "github.com"); err == nil {
			t.Errorf("%q was taken for %v", bad, ref)
		}
	}
	if github.New("", "t").WebHost() != "github.com" || github.New("https://ghe.example.com/api/v3/", "t").WebHost() != "ghe.example.com" {
		t.Error("WebHost")
	}
}

func TestPullRequest(t *testing.T) {
	gh := githubtest.New(t)
	gh.Open(githubtest.PullRequest{Owner: "example", Repo: "web", Number: 7, HeadRef: "bot/DEV-1", Author: "digital-employee"})
	c := github.New(gh.URL, githubtest.Token)
	ref := github.Ref{Owner: "example", Repo: "web", Number: 7}
	ctx := context.Background()

	pr, err := c.PullRequest(ctx, ref)
	if err != nil || pr.State != "open" || pr.Merged || pr.HeadRef != "bot/DEV-1" || pr.Author != "digital-employee" || pr.ClosedBy != "" || pr.HeadSHA == "" {
		t.Fatalf("open pull request = %+v, %v", pr, err)
	}
	gh.Merge("example", "web", 7, "reviewer")
	if pr, err := c.PullRequest(ctx, ref); err != nil || pr.State != "closed" || !pr.Merged || pr.ClosedBy != "reviewer" {
		t.Errorf("merged pull request = %+v, %v", pr, err)
	}
	if _, err := c.PullRequest(ctx, github.Ref{Owner: "example", Repo: "web", Number: 8}); !github.NotFound(err) {
		t.Errorf("a missing pull request: %v", err)
	}
	if _, err := github.New(gh.URL, "wrong").PullRequest(ctx, ref); err == nil || github.NotFound(err) || !strings.Contains(err.Error(), "HTTP 401") {
		t.Errorf("a wrong token: %v", err)
	}
}
