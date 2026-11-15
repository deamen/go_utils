package github_test

import (
	"context"
	"strings"
	"testing"
	"time"

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

func TestChecks(t *testing.T) {
	gh := githubtest.New(t)
	c := github.New(gh.URL, githubtest.Token)
	ref := github.Ref{Owner: "example", Repo: "web", Number: 7}
	ctx := context.Background()
	state := func(sha string) *github.Checks {
		t.Helper()
		got, err := c.Checks(ctx, ref, sha)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := state("aaa"); got.State != github.ChecksNone {
		t.Errorf("a commit without checks: %+v", got)
	}
	gh.SetChecks("aaa", githubtest.Check{Name: "build", Status: "completed", Conclusion: "success"}, githubtest.Check{Name: "test", Status: "in_progress"})
	if got := state("aaa"); got.State != github.ChecksPending || len(got.Failed) != 0 {
		t.Errorf("a check that still runs: %+v", got)
	}
	// A failure counts only when everything has finished, so that the
	// list of failures is whole.
	gh.SetChecks("aaa", githubtest.Check{Name: "build", Status: "completed", Conclusion: "failure", Title: "1 error", Summary: "main.go:3: undefined: x"}, githubtest.Check{Name: "test", Status: "queued"})
	if got := state("aaa"); got.State != github.ChecksPending {
		t.Errorf("a failure while another check runs: %+v", got)
	}
	gh.SetChecks("aaa",
		githubtest.Check{Name: "build", Status: "completed", Conclusion: "failure", Title: "1 error", Summary: "main.go:3: undefined: x"},
		githubtest.Check{Name: "lint", Status: "completed", Conclusion: "skipped"},
		githubtest.Check{Name: "test", Status: "completed", Conclusion: "timed_out"})
	got := state("aaa")
	if got.State != github.ChecksFailed || len(got.Failed) != 2 || got.Failed[0].Name != "build" || got.Failed[0].Conclusion != "failure" ||
		got.Failed[0].Summary != "1 error\nmain.go:3: undefined: x" || !strings.HasSuffix(got.Failed[0].URL, "/checks/build") || got.Failed[1].Conclusion != "timed_out" {
		t.Errorf("failed checks: %+v", got)
	}
	gh.SetChecks("bbb", githubtest.Check{Name: "build", Status: "completed", Conclusion: "success"}, githubtest.Check{Name: "docs", Status: "completed", Conclusion: "neutral"})
	if got := state("bbb"); got.State != github.ChecksPassed {
		t.Errorf("passed checks: %+v", got)
	}
}

func TestComments(t *testing.T) {
	gh := githubtest.New(t)
	gh.Open(githubtest.PullRequest{Owner: "example", Repo: "web", Number: 7, HeadRef: "bot/DEV-1"})
	c := github.New(gh.URL, githubtest.Token)
	ref := github.Ref{Owner: "example", Repo: "web", Number: 7}
	t0 := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	gh.Comment("example", "web", 7, githubtest.Comment{Kind: "review", Author: "lead", Association: "MEMBER", Body: "Two things to change.", Review: "CHANGES_REQUESTED", At: t0.Add(3 * time.Minute)})
	gh.Comment("example", "web", 7, githubtest.Comment{Kind: "issue", Author: "dev", Association: "COLLABORATOR", Body: "Please rename it.", At: t0.Add(time.Minute)})
	gh.Comment("example", "web", 7, githubtest.Comment{Kind: "diff", Author: "lead", Association: "MEMBER", Body: "This can be nil.", Path: "main.go", At: t0.Add(2 * time.Minute)})
	gh.Comment("example", "web", 7, githubtest.Comment{Kind: "review", Author: "lead", Association: "MEMBER", Body: "", Review: "APPROVED", At: t0.Add(4 * time.Minute)})

	got, err := c.Comments(context.Background(), ref, time.Time{})
	if err != nil || len(got) != 3 {
		t.Fatalf("comments = %+v, %v", got, err)
	}
	if got[0].Body != "Please rename it." || got[0].Author != "dev" || got[0].Association != "COLLABORATOR" ||
		got[1].Path != "main.go" || got[2].Review != "CHANGES_REQUESTED" || !got[2].Created.Equal(t0.Add(3*time.Minute)) {
		t.Errorf("comments, oldest first = %+v", got)
	}
	// "since" includes its own moment: the caller knows what it has seen.
	if later, _ := c.Comments(context.Background(), ref, t0.Add(2*time.Minute)); len(later) != 2 || later[0].Kind != "diff" || later[0].ID == 0 || later[1].Review != "CHANGES_REQUESTED" {
		t.Errorf("comments from the second on = %+v", later)
	}
}
