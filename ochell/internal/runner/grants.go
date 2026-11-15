package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"ochell/internal/policy"
	"ochell/internal/task"
)

// The grants of a tier are the tools and credentials that a run of the tier
// gets. ochell hands them to the run when it starts, keeps the secrets out
// of everything it writes down or passes on, and takes the ones that were
// made for the run back when it has ended.

// grantTimeout is the time limit of a mint or revoke command.
const grantTimeout = time.Minute

// minSecret is the shortest value that is redacted. A shorter one would
// blank out ordinary words.
const minSecret = 6

// granted is what one run got.
type granted struct {
	// env is set for the agent and the hooks: not secret.
	env []string
	// secrets are NAME=VALUE: the tier's credentials file and what the
	// mint command printed.
	secrets []string
	// minted is the part of secrets that the mint command made, and that
	// the revoke command takes back.
	minted []string
	// mcpConfig is the file with the MCP servers of the run, or "".
	mcpConfig string
	revoke    []string
}

// grant collects what the tier of t grants its runs. It reads the
// credentials file anew, so a changed secret needs no restart, and runs
// the mint command.
func (r *Runner) grant(ctx context.Context, t *task.Task) (*granted, error) {
	g := r.policy.Tier(t.Tier).Grants
	out := &granted{mcpConfig: g.MCPConfig, revoke: g.Revoke}
	for k, v := range g.Env {
		out.env = append(out.env, k+"="+v)
	}
	slices.Sort(out.env)
	if out.mcpConfig != "" {
		// For an agent whose adapter has no argument for it.
		out.env = append(out.env, "ORCH_MCP_CONFIG="+out.mcpConfig)
	}
	if g.CredentialsFile != "" {
		creds, err := policy.ReadCredentials(g.CredentialsFile)
		if err != nil {
			return nil, fmt.Errorf("the credentials of the tier %s: %w", t.Tier, err)
		}
		out.secrets = creds
	}
	if len(g.Mint) > 0 {
		printed, err := r.grantCommand(ctx, g.Mint, t, nil)
		if err != nil {
			return nil, fmt.Errorf("the mint command of the tier %s: %w", t.Tier, err)
		}
		minted, err := policy.ParseCredentials(printed, "its output")
		if err != nil {
			return nil, fmt.Errorf("the mint command of the tier %s: %w", t.Tier, err)
		}
		out.minted = minted
		out.secrets = append(out.secrets, minted...)
	}
	return out, nil
}

// describe names what was granted, for the audit record of the run: the
// tools file, and the names of the variables. Never a value.
func (g *granted) describe() string {
	var parts []string
	if g.mcpConfig != "" {
		parts = append(parts, "mcp_config="+g.mcpConfig)
	}
	names := func(list []string) string {
		var out []string
		for _, e := range list {
			name, _, _ := strings.Cut(e, "=")
			if name != "ORCH_MCP_CONFIG" {
				out = append(out, name)
			}
		}
		return strings.Join(out, ",")
	}
	if n := names(g.env); n != "" {
		parts = append(parts, "env="+n)
	}
	static := g.secrets[:len(g.secrets)-len(g.minted)]
	if n := names(static); n != "" {
		parts = append(parts, "credentials="+n)
	}
	if n := names(g.minted); n != "" {
		parts = append(parts, "minted="+n)
	}
	return strings.Join(parts, " ")
}

// setGrant notes what the run with this task id was granted, or with nil
// that the run has ended.
func (r *Runner) setGrant(id string, g *granted) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if g == nil {
		delete(r.grants, id)
		return
	}
	r.grants[id] = g
}

// grantOf returns what the run with this task id was granted, or an empty
// grant.
func (r *Runner) grantOf(id string) *granted {
	r.mu.Lock()
	defer r.mu.Unlock()
	if g := r.grants[id]; g != nil {
		return g
	}
	return &granted{}
}

// takeBack runs the revoke command for the credentials that were minted
// for a run. It is called when the run has ended, in whatever way.
func (r *Runner) takeBack(t *task.Task, g *granted) {
	if g == nil || len(g.revoke) == 0 || len(g.minted) == 0 {
		return
	}
	// Not the run's context: that may be cancelled, and the credentials
	// have to go all the same.
	if _, err := r.grantCommand(context.Background(), g.revoke, t, g.minted); err != nil {
		r.log.Error("the credentials of the run could not be revoked; they may still work", "task", t.ID, "tier", t.Tier, "err", err)
		return
	}
	r.log.Debug("the credentials of the run were revoked", "task", t.ID, "tier", t.Tier, "credentials", len(g.minted))
}

// grantCommand runs a mint or revoke command and returns what it printed.
// It runs as ochell itself, with ochell's own environment: it is part of
// the host's configuration, like ochell, and may need the host's identity
// to make a token. It also gets ORCH_TASK_* and extra.
func (r *Runner) grantCommand(ctx context.Context, argv []string, t *task.Task, extra []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, grantTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(append(os.Environ(), r.taskEnv(t)...), extra...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		// What the command printed may hold a secret: only its error
		// output is passed on, and that only in part.
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		if ctx.Err() != nil {
			return "", fmt.Errorf("%s did not end within %s", argv[0], grantTimeout)
		}
		return "", fmt.Errorf("%s: %w: %s", argv[0], err, msg)
	}
	return stdout.String(), nil
}

// redactor replaces the secrets of a run in text that ochell writes down or
// passes on: the run log, and what goes to the ticket.
type redactor struct {
	old, new [][]byte
	longest  int
}

func newRedactor(secrets []string) *redactor {
	var rd redactor
	for _, s := range secrets {
		name, value, _ := strings.Cut(s, "=")
		if len(value) < minSecret {
			continue
		}
		rd.old = append(rd.old, []byte(value))
		rd.new = append(rd.new, []byte("[redacted "+name+"]"))
		rd.longest = max(rd.longest, len(value))
	}
	return &rd
}

// bytes replaces every secret in p.
func (rd *redactor) bytes(p []byte) []byte {
	for i, old := range rd.old {
		p = bytes.ReplaceAll(p, old, rd.new[i])
	}
	return p
}

// text replaces every secret in s.
func (rd *redactor) text(s string) string {
	if rd == nil || len(rd.old) == 0 {
		return s
	}
	return string(rd.bytes([]byte(s)))
}

// redactingWriter passes what is written to it on with the secrets
// replaced. A secret can arrive in two pieces, so the end of what was
// written is held back until more arrives or Flush is called.
type redactingWriter struct {
	rd   *redactor
	w    io.Writer
	held []byte
}

// writer returns w itself when there is nothing to redact.
func (rd *redactor) writer(w io.Writer) flushWriter {
	if rd == nil || len(rd.old) == 0 {
		return plainWriter{w}
	}
	return &redactingWriter{rd: rd, w: w}
}

// flushWriter is a writer that may hold something back until Flush.
type flushWriter interface {
	io.Writer
	Flush() error
}

type plainWriter struct{ io.Writer }

func (plainWriter) Flush() error { return nil }

func (rw *redactingWriter) Write(p []byte) (int, error) {
	buf := rw.rd.bytes(append(rw.held, p...))
	// Keep what could be the beginning of a secret.
	keep := min(rw.rd.longest-1, len(buf))
	rw.held = append(rw.held[:0:0], buf[len(buf)-keep:]...)
	if _, err := rw.w.Write(buf[:len(buf)-keep]); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (rw *redactingWriter) Flush() error {
	if len(rw.held) == 0 {
		return nil
	}
	_, err := rw.w.Write(rw.rd.bytes(rw.held))
	rw.held = nil
	return err
}

// errGrant marks a run that was not started because its grants could not
// be put together.
var errGrant = errors.New("the run was not given its tools and credentials")
