// Package admin is the local admin channel: a unix socket on which a
// running ochell takes commands from its operator (pause, resume, status,
// reset).
//
// The socket is a file that only ochell's own OS user may open. That is the
// whole access control, and the reason it is not a loopback port: the agent
// runs on the same host and can reach any local port, but with the systemd
// launcher it runs as another user and cannot open this file.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"ochell/internal/runner"
	"ochell/internal/store"
)

// Control is what the admin channel can do. *runner.Runner implements it.
type Control interface {
	Pause() error
	Resume() error
	Status() (runner.Status, error)
	ResetAttempts(source, key string) error
}

// Server serves the admin commands on a unix socket.
type Server struct {
	path string
	ln   net.Listener
	srv  *http.Server
}

// Listen creates the socket at path, replacing one that a previous ochell
// left behind, and makes it accessible to the owner only.
func Listen(path string, c Control, log *slog.Logger) (*Server, error) {
	// A socket file that nothing listens on is left over from a crash. One
	// that answers belongs to another running ochell.
	if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
		conn.Close()
		return nil, fmt.Errorf("admin socket %s is in use: is another ochell running with it?", path)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("admin socket %s: the file exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("admin socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("admin socket: %w", err)
	}
	// Close removes the file itself. Left to the listener, the removal
	// could come late, from the serving goroutine, and hit a file that
	// someone else has put there since.
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	// Connecting needs write permission on the file. The mode it was
	// created with never gives that to other users; this takes the rest.
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("admin socket: %w", err)
	}
	s := &Server{path: path, ln: ln}
	s.srv = &http.Server{
		Handler:           routes(c, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("admin channel stopped", "err", err)
		}
	}()
	return s, nil
}

// Close stops the admin channel and removes the socket.
func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.srv.Shutdown(ctx)
	s.ln.Close()
	os.Remove(s.path)
}

func routes(c Control, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	answer := func(w http.ResponseWriter, code int, msg string) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(code)
		io.WriteString(w, msg+"\n")
	}
	status := func(w http.ResponseWriter, prefix string) {
		st, err := c.Status()
		if err != nil {
			answer(w, http.StatusInternalServerError, err.Error())
			return
		}
		answer(w, http.StatusOK, prefix+describe(st))
	}
	mux.HandleFunc("POST /pause", func(w http.ResponseWriter, _ *http.Request) {
		if err := c.Pause(); err != nil {
			answer(w, http.StatusInternalServerError, err.Error())
			return
		}
		status(w, "")
	})
	mux.HandleFunc("POST /resume", func(w http.ResponseWriter, _ *http.Request) {
		if err := c.Resume(); err != nil {
			answer(w, http.StatusInternalServerError, err.Error())
			return
		}
		status(w, "")
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("format") == "json" {
			st, err := c.Status()
			if err != nil {
				answer(w, http.StatusInternalServerError, err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(st)
			return
		}
		status(w, "")
	})
	mux.HandleFunc("POST /reset", func(w http.ResponseWriter, r *http.Request) {
		source, key := r.URL.Query().Get("source"), r.URL.Query().Get("key")
		switch err := c.ResetAttempts(source, key); {
		case err == nil:
			answer(w, http.StatusOK, fmt.Sprintf("the attempts of %s %s are reset; assign the ticket again to start it", source, key))
		case errors.Is(err, store.ErrUnknown):
			answer(w, http.StatusNotFound, fmt.Sprintf("ochell knows no %s ticket %s", source, key))
		default:
			log.Error("admin: reset failed", "err", err)
			answer(w, http.StatusInternalServerError, err.Error())
		}
	})
	return mux
}

// describe is the one line that pause, resume and status answer with.
func describe(st runner.Status) string {
	state := "running"
	if st.Paused {
		state = "paused: no new run starts"
	}
	return fmt.Sprintf("%s; %d queued, %d running", state, st.Queued, st.Running)
}

// Call sends one command to the ochell that listens on the socket at path
// and returns its answer. A command that the server refuses is an error
// that holds its answer.
func Call(path, method, command string, query url.Values) (string, error) {
	if path == "" {
		return "", errors.New("no admin socket is configured (admin.socket)")
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}
	u := "http://ochell/" + command
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach ochell on %s: is it running, and are you its OS user? (%w)", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	answer := strings.TrimSpace(string(body))
	if resp.StatusCode != http.StatusOK {
		return "", errors.New(answer)
	}
	return answer, nil
}
