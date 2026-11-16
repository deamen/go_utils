package launcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Exit codes 125 to 127 are podman's own: 125 when it could not create the
// container (no such image, a name that is taken, an option it refuses),
// 126 and 127 when the command could not be run in the image.
const (
	firstPodmanExitCode = 125
	lastPodmanExitCode  = 127
)

// ContainerHome is the home directory of the agent in a container: where
// the ticket's state directory is mounted.
const ContainerHome = "/home/agent"

// containerPrefix comes before the task id in the name of a container.
const containerPrefix = "ochell-run-"

// Podman runs each agent, and each workspace hook, in a container of its
// own. ochell's own OS user starts the containers (rootless podman): there
// is no root, no sudo and no script in between.
//
// A container sees its image and what is mounted in it: the working
// directory of its ticket, the directory of its run, the state directory of
// its ticket as its home, and read-only what its tier grants. Nothing of
// ochell's is mounted, and nothing of another ticket.
type Podman struct {
	// Command is the podman program.
	Command string
	Image   string
	// Pull is podman's pull policy for the image.
	Pull string
	// EnvFile holds the agent's own credential; podman reads it. Empty:
	// none.
	EnvFile string
	// Args are the host's own options for "podman run".
	Args []string
	// StopGrace is how long podman waits between SIGTERM and SIGKILL.
	StopGrace time.Duration
	// SecretsDir is a directory of ochell's own, for the file that carries
	// the secrets of a run to its container.
	SecretsDir string
	// Protected are directories of ochell's own. A directory that holds
	// one of them is never mounted.
	Protected []string
}

// mountable refuses a path that cannot be mounted as it is, or that would
// put files of ochell's own in the container.
func (p *Podman) mountable(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s is not an absolute path", path)
	}
	// --volume takes source, target and options with colons in between.
	if strings.ContainsAny(path, ":\n") {
		return fmt.Errorf("%s holds a character that a mount cannot have", path)
	}
	clean := filepath.Clean(path)
	for _, own := range p.Protected {
		if own == clean || strings.HasPrefix(own, strings.TrimSuffix(clean, "/")+"/") {
			return fmt.Errorf("%s holds %s, which is ochell's own and must not be in a container", path, own)
		}
	}
	return nil
}

// checkMounts refuses a run one of whose directories or files cannot be
// mounted.
func (p *Podman) checkMounts(spec Spec) error {
	paths := append([]string{spec.Dir}, spec.ReadOnly...)
	for _, d := range []string{spec.RunDir, spec.Home} {
		if d != "" {
			paths = append(paths, d)
		}
	}
	for _, path := range paths {
		if err := p.mountable(path); err != nil {
			return err
		}
	}
	return nil
}

// runArgs builds the arguments of "podman run" for one run. secretsFile is
// the file with the run's secrets, or "".
//
// No secret is among them: the process list shows them to every local
// user. The secrets are in files that podman reads.
func (p *Podman) runArgs(spec Spec, secretsFile string) ([]string, error) {
	if err := p.checkMounts(spec); err != nil {
		return nil, err
	}
	args := []string{
		"run", "--rm", "--name=" + containerPrefix + spec.TaskID,
		"--pull=" + p.Pull,
		// The output goes to ochell alone, which takes the secrets out of
		// it; podman's own log would be a second copy.
		"--log-driver=none",
		// The agent has the same uid in the container as ochell has on the
		// host, and it is not root there. So ochell owns every file that a
		// run leaves in the mounted directories.
		"--userns=keep-id",
		"--cap-drop=all",
		"--security-opt=no-new-privileges",
		// Nothing of ochell's own environment: it holds the webhook secrets.
		"--env-host=false",
		"--http-proxy=false",
	}
	if spec.Timeout > 0 {
		// ochell keeps the timer and stops the container; this limit only
		// applies if ochell is gone.
		args = append(args, "--timeout="+seconds(spec.Timeout+runtimeBackstop))
	}
	if spec.Stdin != nil {
		args = append(args, "--interactive")
	}
	// The directories have the same path in the container as on the host,
	// so that every path ochell names holds in both. Z: on a host with
	// SELinux, the directory is labelled for this container alone.
	mounts := []string{spec.Dir}
	if spec.RunDir != "" {
		mounts = append(mounts, spec.RunDir)
	}
	for _, m := range mounts {
		args = append(args, "--volume="+m+":"+m+":Z")
	}
	args = append(args, "--workdir="+spec.Dir)
	if spec.Home != "" {
		args = append(args, "--volume="+spec.Home+":"+ContainerHome+":Z", "--env=HOME="+ContainerHome)
	}
	for _, f := range spec.ReadOnly {
		// Not relabelled: runs of the same tier share the file.
		args = append(args, "--volume="+f+":"+f+":ro")
	}
	if p.EnvFile != "" {
		args = append(args, "--env-file="+p.EnvFile)
	}
	if secretsFile != "" {
		args = append(args, "--env-file="+secretsFile)
	}
	// As arguments and not in a file: a file has one variable per line, and
	// a value from a ticket (its URL) could bring a line of its own.
	for _, e := range spec.Env {
		args = append(args, "--env="+e)
	}
	args = append(args, p.Args...)
	args = append(args, p.Image, spec.Command)
	return append(args, spec.Args...), nil
}

// writeSecrets writes the secrets of a run to a file of its own that only
// ochell (and root) can read, and returns its path. podman reads it as an
// env file; it is not mounted in the container.
func (p *Podman) writeSecrets(taskID string, secrets []string) (string, error) {
	if p.SecretsDir == "" {
		return "", errors.New("podman launcher: agent.secrets_dir is required to pass credentials to a run")
	}
	for _, s := range secrets {
		// A line without "=" would make podman copy the variable of that
		// name from ochell's own environment.
		if name, _, ok := strings.Cut(s, "="); !ok || name == "" || strings.ContainsAny(s, "\r\n") || strings.ContainsAny(name, "* \t#") {
			return "", errors.New("podman launcher: a credential is not one line of the form NAME=VALUE")
		}
	}
	if err := os.MkdirAll(p.SecretsDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(p.SecretsDir, taskID+".env")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, werr := f.WriteString(strings.Join(secrets, "\n") + "\n")
	if err := errors.Join(werr, f.Close()); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func (p *Podman) Start(spec Spec) (Process, error) {
	if p.Command == "" || p.Image == "" {
		return nil, errors.New("podman launcher: command and image are required")
	}
	if err := p.checkMounts(spec); err != nil {
		return nil, fmt.Errorf("%w: podman launcher: %v", ErrNotStarted, err)
	}
	// ochell creates the directories itself, so they are its own before
	// podman could create them.
	for _, d := range []string{spec.Dir, spec.RunDir, spec.Home} {
		if d == "" {
			continue
		}
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, fmt.Errorf("create %s: %w", d, err)
		}
	}
	secretsFile := ""
	if len(spec.Secrets) > 0 {
		var err error
		if secretsFile, err = p.writeSecrets(spec.TaskID, spec.Secrets); err != nil {
			return nil, fmt.Errorf("%w: cannot hand the credentials to the run: %v", ErrNotStarted, err)
		}
	}
	args, err := p.runArgs(spec, secretsFile)
	if err != nil {
		if secretsFile != "" {
			os.Remove(secretsFile)
		}
		return nil, fmt.Errorf("%w: podman launcher: %v", ErrNotStarted, err)
	}
	// podman itself has ochell's environment, which it needs to find its
	// storage and its runtime directory. It passes none of it on.
	cmd := exec.Command(p.Command, args...)
	if spec.Stdin != nil {
		cmd.Stdin = spec.Stdin
	}
	cmd.Stdout, cmd.Stderr = spec.Output, spec.Output
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Start(); err != nil {
		if secretsFile != "" {
			os.Remove(secretsFile)
		}
		return nil, fmt.Errorf("%w: %s: %v", ErrNotStarted, p.Command, err)
	}
	return &podmanProcess{p: p, name: containerPrefix + spec.TaskID, cmd: cmd, secretsFile: secretsFile}, nil
}

type podmanProcess struct {
	p    *Podman
	name string
	cmd  *exec.Cmd
	// secretsFile is removed when the run has ended.
	secretsFile string
	stopped     atomic.Bool
}

func (c *podmanProcess) Wait() (int, error) {
	code, err := exitCode(c.cmd, c.cmd.Wait())
	if c.secretsFile != "" {
		os.Remove(c.secretsFile)
	}
	if err == nil && code >= firstPodmanExitCode && code <= lastPodmanExitCode && !c.stopped.Load() {
		return code, fmt.Errorf("%w: podman exit code %d", ErrNotStarted, code)
	}
	return code, err
}

// Stop stops the container: podman sends SIGTERM to the agent, and SIGKILL
// to every process of the container after the grace period. "podman run"
// ends by itself when the container has stopped, and removes it.
func (c *podmanProcess) Stop() error {
	c.stopped.Store(true)
	return c.p.podman("stop", "--ignore", "--time="+seconds(c.p.StopGrace), c.name)
}

// Reap stops and removes the container of a run that an earlier ochell
// process started. A container outlives the ochell that started it, and is
// found by its name. It is not an error when there is none.
func (p *Podman) Reap(taskID string) error {
	return p.podman("rm", "--force", "--ignore", "--time="+seconds(p.StopGrace), containerPrefix+taskID)
}

// podman runs one podman command that ends a container.
func (p *Podman) podman(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), p.StopGrace+stopMargin)
	defer cancel()
	out, err := exec.CommandContext(ctx, p.Command, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", p.Command, args[0], err, strings.TrimSpace(string(out)))
	}
	return nil
}
