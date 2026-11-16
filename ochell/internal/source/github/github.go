// Package github is the GitHub source: issues and pull requests that are
// assigned to the digital employee's GitHub account become tickets, told
// by a webhook of the repository or the organization.
//
// It is apart from the handoff (package server, handoff.go), which follows
// the pull requests that the tickets of any source open, and from package
// internal/github, the API client that both use.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"ochell/internal/auth"
	"ochell/internal/config"
	ghapi "ochell/internal/github"
	"ochell/internal/source"
	"ochell/internal/tracker"
)

// Name is the name of the source.
const Name = "github"

// Issue types that the policy sees for a ticket: GitHub's own type of the
// issue where the organization has issue types, and else these.
const (
	TypeIssue       = "Issue"
	TypePullRequest = "Pull Request"
)

// repo is one repository whose issues may become tickets.
type repo struct {
	owner, name string
	// project is the part of the ticket keys before the number.
	project string
	// clone is the address of the repository for git clone.
	clone string
}

func (r repo) full() string { return r.owner + "/" + r.name }

// Source is the GitHub source. It implements source.Source, and with a
// token also tracker.Source and tracker.Tickets.
type Source struct {
	secret string
	// bot is the login of the digital employee (github.bot_login).
	bot   string
	repos []repo
	// host is the host of GitHub's pages.
	host string
	// api reads issues and writes comments, with the token of the source;
	// nil without one.
	api *ghapi.Client

	// login is the account of the token, once GitHub has said it.
	mu    sync.Mutex
	login string
}

// New returns the source for a configuration that Validate has accepted.
func New(cfg config.GitHubSource, gh config.GitHub) *Source {
	host := ghapi.New(gh.APIURL, "").WebHost()
	s := &Source{secret: cfg.Secret, bot: gh.BotLogin, host: host}
	for _, r := range cfg.Repos {
		owner, name, _ := r.Split()
		s.repos = append(s.repos, repo{owner: owner, name: name, project: r.ProjectKey(), clone: "https://" + host + "/" + owner + "/" + name + ".git"})
	}
	if cfg.Token != "" {
		s.api = ghapi.New(gh.APIURL, cfg.Token)
	}
	return s
}

// UseAPI sets the client for the issues. Tests pass one for a fake.
func (s *Source) UseAPI(c *ghapi.Client) { s.api = c }

func (s *Source) Name() string { return Name }

// Bot reports whether a login is the digital employee's. GitHub does not
// tell logins apart by case.
func (s *Source) Bot(login string) bool {
	return login != "" && strings.EqualFold(login, s.bot)
}

type user struct {
	Login string `json:"login"`
}

func (u *user) login() string {
	if u == nil {
		return ""
	}
	return u.Login
}

// issue is an issue or a pull request in a webhook payload.
type issue struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	HTMLURL string `json:"html_url"`
	User    *user  `json:"user"`
	Labels  []struct {
		Name string `json:"name"`
	} `json:"labels"`
	Assignees []user `json:"assignees"`
	Assignee  *user  `json:"assignee"`
	Type      *struct {
		Name string `json:"name"`
	} `json:"type"`
	// PullRequest is set on an issue that is a pull request.
	PullRequest *struct{} `json:"pull_request"`
}

type payload struct {
	Action      string `json:"action"`
	Issue       *issue `json:"issue"`
	PullRequest *issue `json:"pull_request"`
	Comment     *struct {
		Body string `json:"body"`
		User *user  `json:"user"`
	} `json:"comment"`
	// Assignee is who an "assigned" or "unassigned" event is about.
	Assignee   *user `json:"assignee"`
	Repository *struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Sender *user `json:"sender"`
}

// Receive checks the signature of a delivery and reads it.
//
// GitHub signs the body with the secret of the webhook. The payload has no
// time in it that could be checked, so a captured delivery stays valid;
// what keeps it from being used twice is that ochell remembers the body
// of every delivery it handled.
func (s *Source) Receive(h http.Header, body []byte) (*source.Event, error) {
	if err := auth.VerifyHubSignature(s.secret, body, h.Get("X-Hub-Signature-256")); err != nil {
		return nil, fmt.Errorf("%w: %v", source.ErrUnauthorized, err)
	}
	ev := &source.Event{Delivery: h.Get("X-GitHub-Delivery")}
	kind := h.Get("X-GitHub-Event")
	switch kind {
	case "issues", "pull_request", "issue_comment":
	case "":
		return nil, fmt.Errorf("%w: no X-GitHub-Event header", source.ErrBadPayload)
	default:
		// Also "ping", which GitHub sends when the webhook is created.
		ev.Why = "an event of the kind " + kind
		return ev, nil
	}
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("%w: it is not JSON (the content type of the webhook must be application/json): %v", source.ErrBadPayload, err)
	}
	is, isPR := p.Issue, false
	if kind == "pull_request" {
		is, isPR = p.PullRequest, true
	} else if is != nil {
		isPR = is.PullRequest != nil
	}
	if is == nil || is.Number <= 0 || p.Repository == nil || p.Repository.FullName == "" {
		return nil, fmt.Errorf("%w: it names no issue or no repository", source.ErrBadPayload)
	}
	// Only the repositories that the host named. The secret may be that of
	// a webhook of a whole organization.
	r, ok := s.repoNamed(p.Repository.FullName)
	if !ok {
		ev.Why, ev.Refused = "the repository "+p.Repository.FullName+" is not one of sources.github.repos", true
		return ev, nil
	}
	what := "issue"
	if isPR {
		what = "pull request"
		ev.PullRequest = is.HTMLURL
	}
	ev.Key = r.project + "-" + strconv.Itoa(is.Number)
	ev.Title, ev.URL, ev.Repo = is.Title, is.HTMLURL, r.clone
	ev.Context = fmt.Sprintf("The ticket is the %s #%d of the GitHub repository %s.", what, is.Number, r.full())
	for _, l := range is.Labels {
		ev.Labels = append(ev.Labels, l.Name)
	}
	ev.IssueType = issueType(isPR, is.Type != nil, func() string { return is.Type.Name })
	// GitHub issues have no priority, so there is none to ask for.
	ev.HasPriority = true
	ev.Actor = p.Sender.login()
	ev.ActorName = ev.Actor
	ev.Reporter = is.User.login()
	ev.Mine = s.Bot(is.Assignee.login())
	for _, a := range is.Assignees {
		ev.Mine = ev.Mine || s.Bot(a.Login)
	}
	// A pull request that the digital employee opened is the work of a
	// ticket, which the handoff follows. It is never a ticket itself.
	own := isPR && s.Bot(is.User.login())

	if kind == "issue_comment" {
		switch {
		case p.Action != "created":
			ev.Why = "a comment that was " + p.Action
		case p.Comment == nil:
			return nil, fmt.Errorf("%w: a comment event without a comment", source.ErrBadPayload)
		case own:
			ev.Why = "a comment on a pull request of the digital employee; ochell reads those when it follows the pull request"
		default:
			ev.Kind = source.Commented
			ev.Comment = p.Comment.Body
			if who := p.Comment.User.login(); who != "" {
				ev.Actor, ev.ActorName = who, who
			}
		}
		return ev, nil
	}
	switch p.Action {
	case "assigned":
		switch {
		case !s.Bot(p.Assignee.login()):
			ev.Why = "an assignment to someone else"
		case own:
			ev.Why, ev.Refused = "a pull request that the digital employee opened was assigned to it; that is the work of a ticket, not a new ticket", true
		default:
			ev.Kind = source.Assigned
		}
	case "unassigned":
		if s.Bot(p.Assignee.login()) {
			ev.Kind = source.Unassigned
		} else {
			ev.Why = "someone else was unassigned"
		}
	case "closed", "deleted":
		ev.Kind = source.Closed
	case "labeled", "unlabeled", "edited", "typed", "untyped":
		ev.Kind = source.Updated
	default:
		ev.Why = "the " + what + " was " + p.Action
	}
	return ev, nil
}

// issueType is the issue type that the policy sees.
func issueType(isPR, typed bool, name func() string) string {
	switch {
	case isPR:
		return TypePullRequest
	case typed && name() != "":
		return name()
	}
	return TypeIssue
}

func (s *Source) repoNamed(full string) (repo, bool) {
	for _, r := range s.repos {
		if strings.EqualFold(r.full(), full) {
			return r, true
		}
	}
	return repo{}, false
}

// ref returns the issue that a ticket key names: the repository with the
// project of the key, and the number after it.
func (s *Source) ref(key string) (ghapi.Ref, repo, error) {
	i := strings.LastIndexByte(key, '-')
	if i <= 0 {
		return ghapi.Ref{}, repo{}, tracker.ErrNotFound
	}
	n, err := strconv.Atoi(key[i+1:])
	if err != nil || n <= 0 {
		return ghapi.Ref{}, repo{}, tracker.ErrNotFound
	}
	for _, r := range s.repos {
		if strings.EqualFold(r.project, key[:i]) {
			return ghapi.Ref{Owner: r.owner, Repo: r.name, Number: n}, r, nil
		}
	}
	return ghapi.Ref{}, repo{}, tracker.ErrNotFound
}

// PullRequestOf returns the page that a ticket has when it is a pull
// request, or "" for a key that is not of this source. The handoff asks,
// so that the conversation of such a pull request reaches the agent once.
func (s *Source) PullRequestOf(key string) string {
	ref, _, err := s.ref(key)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("https://%s/%s/%s/pull/%d", s.host, ref.Owner, ref.Repo, ref.Number)
}

// Tracker returns the API for the poller and the gates of scheduling: the
// source itself, when it has a token.
func (s *Source) Tracker() tracker.Source {
	if s.api == nil {
		return nil
	}
	return s
}

// Tickets returns the access for the agent's ticket tools: the source
// itself, when it has a token.
func (s *Source) Tickets() tracker.Tickets {
	if s.api == nil {
		return nil
	}
	return s
}

// CheckGates says which gates of scheduling can be checked for GitHub.
func (s *Source) CheckGates(requiredLabels, blockedBy bool) error {
	var errs []error
	if blockedBy {
		// GitHub has no one meaning of "blocked by" that every site and
		// every version of GitHub Enterprise Server has, and ochell reads
		// none. A gate that held nothing would be worse than none.
		errs = append(errs, errors.New("the policy sets scheduling.blocked_by: wait, which ochell cannot check for GitHub issues: it does not read dependencies between issues. Take the gate out of the policy, or turn sources.github off"))
	}
	if requiredLabels && s.api == nil {
		errs = append(errs, errors.New("the policy sets scheduling.required_labels, which ochell checks against the tracker: sources.github needs its token (sources.github.token)"))
	}
	return errors.Join(errs...)
}

// writesAsBot makes sure that the token of the source belongs to the
// digital employee's account. A comment from any other account would come
// back to ochell as a person's, and start a run.
func (s *Source) writesAsBot(ctx context.Context) error {
	s.mu.Lock()
	login := s.login
	s.mu.Unlock()
	if login == "" {
		var err error
		if login, err = s.api.Login(ctx); err != nil {
			return fmt.Errorf("cannot find out which account sources.github.token belongs to: %w", err)
		}
		s.mu.Lock()
		s.login = login
		s.mu.Unlock()
	}
	if !s.Bot(login) {
		return fmt.Errorf("the account of sources.github.token (%s) is not the digital employee's (github.bot_login); a comment by it would be taken as a person's, so none is written", login)
	}
	return nil
}

// Tell adds a comment to the issue of a ticket, as the bot account.
func (s *Source) Tell(ctx context.Context, key, text string) error {
	if s.api == nil {
		return source.ErrSilent
	}
	ref, _, err := s.ref(key)
	if err != nil {
		return err
	}
	if err := s.writesAsBot(ctx); err != nil {
		return err
	}
	return s.api.CommentOnIssue(ctx, ref, text)
}

// Comment implements tracker.Tickets.
func (s *Source) Comment(ctx context.Context, key, body string) error {
	return s.Tell(ctx, key, body)
}

// Assigned returns the open issues and pull requests of the configured
// repositories that are assigned to the bot. A pull request that the bot
// opened itself is not among them.
func (s *Source) Assigned(ctx context.Context) ([]tracker.Issue, error) {
	var out []tracker.Issue
	for _, r := range s.repos {
		issues, err := s.api.AssignedIssues(ctx, r.owner, r.name, s.bot)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.full(), err)
		}
		for _, is := range issues {
			if is.PullRequest && s.Bot(is.Author) {
				continue
			}
			t := tracker.Issue{Key: r.project + "-" + strconv.Itoa(is.Number), Title: is.Title, URL: is.URL, Labels: is.Labels, Repo: r.clone,
				Type: issueType(is.PullRequest, is.Type != "", func() string { return is.Type })}
			if is.PullRequest {
				t.PullRequest = is.URL
			}
			out = append(out, t)
		}
	}
	return out, nil
}

// Assigner returns who last assigned the issue to the bot, from the
// history of the issue.
func (s *Source) Assigner(ctx context.Context, key string) ([]string, error) {
	ref, _, err := s.ref(key)
	if err != nil {
		return nil, err
	}
	events, err := s.api.IssueEvents(ctx, ref)
	if err != nil {
		return nil, err
	}
	who := ""
	for _, ev := range events {
		if ev.Event == "assigned" && s.Bot(ev.Assignee) {
			who = ev.Actor
		}
	}
	if who == "" {
		return nil, nil
	}
	return []string{who}, nil
}

// Lookup asks about one issue.
func (s *Source) Lookup(ctx context.Context, key string) (tracker.Status, error) {
	ref, _, err := s.ref(key)
	if err != nil {
		// Its repository is not configured any more.
		return tracker.Status{}, err
	}
	is, err := s.api.Issue(ctx, ref)
	if ghapi.NotFound(err) {
		return tracker.Status{Closed: true}, nil
	}
	if err != nil {
		return tracker.Status{}, err
	}
	st := tracker.Status{Closed: is.State != "open", Unassigned: true}
	for _, a := range is.Assignees {
		if s.Bot(a) {
			st.Unassigned = false
		}
	}
	return st, nil
}

// Scheduling returns the labels of an issue, and who put each there. An
// issue has no priority, and ochell reads nothing that blocks it.
func (s *Source) Scheduling(ctx context.Context, key string) (tracker.Scheduling, error) {
	ref, _, err := s.ref(key)
	if err != nil {
		return tracker.Scheduling{}, err
	}
	is, err := s.api.Issue(ctx, ref)
	if ghapi.NotFound(err) {
		return tracker.Scheduling{}, tracker.ErrNotFound
	}
	if err != nil {
		return tracker.Scheduling{}, err
	}
	var sch tracker.Scheduling
	if len(is.Labels) == 0 {
		return sch, nil
	}
	events, err := s.api.IssueEvents(ctx, ref)
	if err != nil {
		return tracker.Scheduling{}, err
	}
	for _, name := range is.Labels {
		// Who added it last. Without an entry in the history, the label
		// came with the issue, from its author.
		by := is.Author
		for _, ev := range events {
			if ev.Event == "labeled" && strings.EqualFold(ev.Label, name) && ev.Actor != "" {
				by = ev.Actor
			}
		}
		l := tracker.Label{Name: name, Bot: s.Bot(by)}
		if by != "" {
			l.By = []string{by}
		}
		sch.Labels = append(sch.Labels, l)
	}
	return sch, nil
}

// Ticket returns an issue with its newest comments, for the ticket tools.
func (s *Source) Ticket(ctx context.Context, key string) (tracker.Ticket, error) {
	ref, _, err := s.ref(key)
	if err != nil {
		return tracker.Ticket{}, err
	}
	is, err := s.api.Issue(ctx, ref)
	if ghapi.NotFound(err) {
		return tracker.Ticket{}, tracker.ErrNotFound
	}
	if err != nil {
		return tracker.Ticket{}, err
	}
	t := tracker.Ticket{Key: key, Title: is.Title, URL: is.URL, Description: is.Body, Status: is.State, Labels: is.Labels}
	if is.Comments == 0 {
		return t, nil
	}
	comments, err := s.api.IssueComments(ctx, ref, is.Comments, tracker.MaxComments)
	if err != nil {
		return tracker.Ticket{}, err
	}
	for _, c := range comments {
		t.Comments = append(t.Comments, tracker.Comment{Author: c.Author, Bot: s.Bot(c.Author), At: c.Created, Body: c.Body})
	}
	if more := is.Comments - len(comments); more > 0 {
		t.MoreComments = more
	}
	return t, nil
}
