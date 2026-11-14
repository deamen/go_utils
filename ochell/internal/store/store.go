// Package store keeps ochell's durable state in one SQLite file: the tickets
// it works on, the runs of each ticket, and the webhook deliveries it has
// already handled. The store is also the task queue, so queued work, and the
// record of what was running, survive a restart.
//
// A ticket is the work item (one Jira or Linear issue). A run is one attempt
// to work on it with an agent.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"ochell/internal/task"
	"ochell/internal/ticket"
)

var (
	ErrBusy      = errors.New("a task for this ticket is already queued or running")
	ErrQueueFull = errors.New("task queue is full")
)

// Run statuses.
const (
	runQueued  = "queued"
	runRunning = "running"
	runEnded   = "ended"
)

// migrations bring an older file up to date, one step per schema version.
// Never change a step that has been released; add a new one.
var migrations = []string{
	`CREATE TABLE tickets (
		source     TEXT NOT NULL,
		key        TEXT NOT NULL,
		title      TEXT NOT NULL DEFAULT '',
		url        TEXT NOT NULL DEFAULT '',
		state      TEXT NOT NULL,
		attempts   INTEGER NOT NULL DEFAULT 0,
		workspace  TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (source, key)
	);
	CREATE TABLE runs (
		id              TEXT PRIMARY KEY,
		source          TEXT NOT NULL,
		key             TEXT NOT NULL,
		status          TEXT NOT NULL,
		attempt         INTEGER NOT NULL DEFAULT 0,
		context         TEXT NOT NULL DEFAULT '',
		tracker_session TEXT NOT NULL DEFAULT '',
		delivery_id     TEXT NOT NULL DEFAULT '',
		received_at     INTEGER NOT NULL,
		started_at      INTEGER,
		ended_at        INTEGER,
		outcome         TEXT NOT NULL DEFAULT '',
		exit_code       INTEGER,
		error           TEXT NOT NULL DEFAULT '',
		log_file        TEXT NOT NULL DEFAULT '',
		FOREIGN KEY (source, key) REFERENCES tickets (source, key)
	);
	CREATE INDEX runs_by_status ON runs (status, received_at);
	CREATE INDEX runs_by_ticket ON runs (source, key);
	CREATE TABLE deliveries (
		key        TEXT PRIMARY KEY,
		expires_at INTEGER NOT NULL
	);`,

	// Version 2: the ticket states of package ticket replace the first,
	// provisional ones ("ended" and "interrupted").
	`ALTER TABLE tickets ADD COLUMN reason TEXT NOT NULL DEFAULT '';
	UPDATE tickets SET state = 'waiting', reason = 'interrupted' WHERE state = 'interrupted';
	UPDATE tickets SET state = CASE (
			SELECT r.outcome FROM runs r WHERE r.source = tickets.source AND r.key = tickets.key
			ORDER BY r.ended_at DESC, r.rowid DESC LIMIT 1
		) WHEN 'finished' THEN 'in_review' ELSE 'failed' END
		WHERE state = 'ended';`,

	// Version 3: what an agent adapter reads from a run, and the session
	// that the next run of the ticket resumes.
	`ALTER TABLE tickets ADD COLUMN agent_session TEXT NOT NULL DEFAULT '';
	ALTER TABLE runs ADD COLUMN workdir TEXT NOT NULL DEFAULT '';
	ALTER TABLE runs ADD COLUMN resumed INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE runs ADD COLUMN agent_session TEXT NOT NULL DEFAULT '';
	ALTER TABLE runs ADD COLUMN message TEXT NOT NULL DEFAULT '';
	ALTER TABLE runs ADD COLUMN cost_usd REAL NOT NULL DEFAULT 0;
	ALTER TABLE runs ADD COLUMN input_tokens INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE runs ADD COLUMN output_tokens INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE runs ADD COLUMN cache_read_tokens INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE runs ADD COLUMN cache_write_tokens INTEGER NOT NULL DEFAULT 0;`,
}

// Store is safe for concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens the store at path and creates or updates its tables. A new
// file is readable by its owner only: it holds ticket text.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: no path")
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
	}
	// SQLite would create the file with the process umask. Its journal
	// files take the mode of this one.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	f.Close()

	q := url.Values{}
	for _, p := range []string{"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(NORMAL)", "foreign_keys(1)"} {
		q.Add("_pragma", p)
	}
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	// One connection: every statement and transaction runs in turn, so a
	// read followed by a write inside a transaction cannot be interleaved.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("the file has schema version %d, this ochell knows up to %d: it was written by a newer ochell", version, len(migrations))
	}
	for v := version; v < len(migrations); v++ {
		err := s.tx(func(tx *sql.Tx) error {
			if _, err := tx.Exec(migrations[v]); err != nil {
				return err
			}
			// PRAGMA takes no parameters; v is an int.
			_, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v+1))
			return err
		})
		if err != nil {
			return fmt.Errorf("schema version %d: %w", v+1, err)
		}
	}
	return nil
}

// tx runs fn in a transaction, and rolls it back when fn fails.
func (s *Store) tx(fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func ms(t time.Time) int64 { return t.UnixMilli() }

// state returns the state of a ticket, ticket.None when there is none.
func state(tx *sql.Tx, source, key string) (ticket.State, error) {
	var s ticket.State
	err := tx.QueryRow(`SELECT state FROM tickets WHERE source = ? AND key = ?`, source, key).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return ticket.None, nil
	}
	return s, err
}

// move changes the state of an existing ticket. Every change of state goes
// through here, so that package ticket decides what is allowed.
func (s *Store) move(tx *sql.Tx, source, key string, to ticket.State, reason ticket.Reason) error {
	from, err := state(tx, source, key)
	if err != nil {
		return err
	}
	if err := ticket.Move(from, to, reason); err != nil {
		return fmt.Errorf("%s %s: %w", source, key, err)
	}
	_, err = tx.Exec(`UPDATE tickets SET state = ?, reason = ?, updated_at = ? WHERE source = ? AND key = ?`,
		to, reason, ms(s.now()), source, key)
	return err
}

// Enqueue records t as a queued run of its ticket. It returns ErrBusy when
// the ticket already has a queued or running run, and ErrQueueFull when
// maxQueued runs are waiting (0 means no limit).
func (s *Store) Enqueue(t *task.Task, maxQueued int) error {
	now := ms(s.now())
	return s.tx(func(tx *sql.Tx) error {
		from, err := state(tx, t.Source, t.Key)
		if err != nil {
			return err
		}
		if from.Active() {
			return ErrBusy
		}
		if maxQueued > 0 {
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM runs WHERE status = ?`, runQueued).Scan(&n); err != nil {
				return err
			}
			if n >= maxQueued {
				return ErrQueueFull
			}
		}
		// A new ticket is created in the state "none", then moved like any other.
		if _, err := tx.Exec(`INSERT INTO tickets (source, key, title, url, state, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (source, key) DO UPDATE SET title = excluded.title, url = excluded.url`,
			t.Source, t.Key, t.Title, t.URL, ticket.None, now, now); err != nil {
			return err
		}
		if err := s.move(tx, t.Source, t.Key, ticket.Queued, ""); err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO runs (id, source, key, status, context, tracker_session, delivery_id, received_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			t.ID, t.Source, t.Key, runQueued, t.Context, t.TrackerSession, t.DeliveryID, ms(t.Received))
		return err
	})
}

const taskColumns = `r.id, r.source, r.key, t.title, t.url, r.context, r.tracker_session, r.delivery_id, r.received_at, r.attempt,
	t.agent_session, t.workspace`

func scanTask(row interface{ Scan(...any) error }) (*task.Task, error) {
	var t task.Task
	var received int64
	if err := row.Scan(&t.ID, &t.Source, &t.Key, &t.Title, &t.URL, &t.Context, &t.TrackerSession, &t.DeliveryID, &received, &t.Attempt,
		&t.AgentSession, &t.Workspace); err != nil {
		return nil, err
	}
	t.Received = time.UnixMilli(received).UTC()
	return &t, nil
}

// Claim takes the oldest queued run and marks it, and its ticket, as
// running. It returns nil when nothing is queued. The task's Attempt says
// which run of the ticket this is, counting from 1; AgentSession and
// Workspace come from the ticket's earlier runs.
func (s *Store) Claim() (*task.Task, error) {
	now := ms(s.now())
	var t *task.Task
	err := s.tx(func(tx *sql.Tx) error {
		var id string
		err := tx.QueryRow(`SELECT id FROM runs WHERE status = ? ORDER BY received_at, rowid LIMIT 1`, runQueued).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var source, key string
		if err := tx.QueryRow(`SELECT source, key FROM runs WHERE id = ?`, id).Scan(&source, &key); err != nil {
			return err
		}
		if err := s.move(tx, source, key, ticket.Running, ""); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE tickets SET attempts = attempts + 1 WHERE source = ? AND key = ?`, source, key); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE runs SET status = ?, started_at = ?,
			attempt = (SELECT attempts FROM tickets t WHERE t.source = runs.source AND t.key = runs.key)
			WHERE id = ?`, runRunning, now, id); err != nil {
			return err
		}
		t, err = scanTask(tx.QueryRow(`SELECT `+taskColumns+` FROM runs r JOIN tickets t USING (source, key) WHERE r.id = ?`, id))
		return err
	})
	return t, err
}

// Finish records how a run ended, and moves the ticket to the state that
// follows from it (ticket.AfterRun). The ticket is then free for a new run.
func (s *Store) Finish(id string, res task.Result) error {
	return s.tx(func(tx *sql.Tx) error { return s.finish(tx, id, res) })
}

func (s *Store) finish(tx *sql.Tx, id string, res task.Result) error {
	now := ms(s.now())
	var exit any
	if res.ExitCode >= 0 {
		exit = res.ExitCode
	}
	msg := ""
	if res.Err != nil {
		msg = res.Err.Error()
	}
	r, err := tx.Exec(`UPDATE runs SET status = ?, ended_at = ?, outcome = ?, exit_code = ?, error = ?, log_file = ?,
			workdir = ?, resumed = ?, agent_session = ?, message = ?, cost_usd = ?,
			input_tokens = ?, output_tokens = ?, cache_read_tokens = ?, cache_write_tokens = ?
		WHERE id = ? AND status != ?`, runEnded, now, string(res.Outcome), exit, msg, res.LogFile,
		res.Workdir, res.Resumed, res.SessionID, res.Message, res.CostUSD,
		res.Usage.InputTokens, res.Usage.OutputTokens, res.Usage.CacheReadTokens, res.Usage.CacheWriteTokens,
		id, runEnded)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return fmt.Errorf("store: run %s is unknown or has already ended", id)
	}
	var source, key string
	if err := tx.QueryRow(`SELECT source, key FROM runs WHERE id = ?`, id).Scan(&source, &key); err != nil {
		return err
	}
	to, reason := ticket.AfterRun(res.Outcome)
	if err := s.move(tx, source, key, to, reason); err != nil {
		return err
	}
	if res.Workdir != "" {
		if _, err := tx.Exec(`UPDATE tickets SET workspace = ? WHERE source = ? AND key = ?`, res.Workdir, source, key); err != nil {
			return err
		}
	}
	switch {
	case res.SessionID != "":
		_, err = tx.Exec(`UPDATE tickets SET agent_session = ? WHERE source = ? AND key = ?`, res.SessionID, source, key)
	case res.Resumed && (res.Outcome == task.OutcomeFailed || res.Outcome == task.OutcomeNotStarted):
		// The agent did not even open the session it was asked to
		// resume: the session is gone. Forget it, or every later run of
		// the ticket would fail the same way.
		_, err = tx.Exec(`UPDATE tickets SET agent_session = '' WHERE source = ? AND key = ?`, source, key)
	}
	return err
}

// ErrInterrupted is the error recorded for a run that Recover closes.
var ErrInterrupted = errors.New("ochell stopped while the agent was running, and the run was not resumed")

// Recover is called once at start, before any run is claimed. Runs that
// were running when ochell stopped cannot be running any more as far as
// ochell knows: they are closed as interrupted and returned, so their
// tickets can be told. Queued runs stay queued.
func (s *Store) Recover() ([]*task.Task, error) {
	var tasks []*task.Task
	err := s.tx(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT `+taskColumns+` FROM runs r JOIN tickets t USING (source, key)
			WHERE r.status = ? ORDER BY r.started_at, r.rowid`, runRunning)
		if err != nil {
			return err
		}
		for rows.Next() {
			t, err := scanTask(rows)
			if err != nil {
				rows.Close()
				return err
			}
			tasks = append(tasks, t)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, t := range tasks {
			res := task.Result{Outcome: task.OutcomeInterrupted, ExitCode: -1, Err: ErrInterrupted}
			if err := s.finish(tx, t.ID, res); err != nil {
				return err
			}
		}
		return nil
	})
	return tasks, err
}

// Active returns the number of runs that are queued or running.
func (s *Store) Active() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM runs WHERE status IN (?, ?)`, runQueued, runRunning).Scan(&n)
	return n, err
}

// Ticket is the stored state of one work item.
type Ticket struct {
	Source, Key, Title, URL string
	State                   ticket.State
	// Reason is set when State is ticket.Waiting.
	Reason ticket.Reason
	// Attempts is the number of runs that were started.
	Attempts  int
	Workspace string
	// AgentSession is the agent's session id from the last run that
	// reported one.
	AgentSession string
	Created      time.Time
	Updated      time.Time
}

// Ticket returns the stored ticket, or nil when ochell has never seen it.
func (s *Store) Ticket(source, key string) (*Ticket, error) {
	t := Ticket{Source: source, Key: key}
	var created, updated int64
	err := s.db.QueryRow(`SELECT title, url, state, reason, attempts, workspace, agent_session, created_at, updated_at
		FROM tickets WHERE source = ? AND key = ?`, source, key).
		Scan(&t.Title, &t.URL, &t.State, &t.Reason, &t.Attempts, &t.Workspace, &t.AgentSession, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.Created, t.Updated = time.UnixMilli(created).UTC(), time.UnixMilli(updated).UTC()
	return &t, nil
}

// Run is the stored record of one run.
type Run struct {
	ID          string
	Source, Key string
	// Status is "queued", "running" or "ended".
	Status  string
	Attempt int
	// Result holds what is known once the run has ended. Its Err is an
	// error with the stored text, or nil.
	Result task.Result
}

// Run returns the stored run, or nil when there is none with this id.
func (s *Store) Run(id string) (*Run, error) {
	r := Run{ID: id}
	var exit sql.NullInt64
	var outcome, msg string
	res := &r.Result
	err := s.db.QueryRow(`SELECT source, key, status, attempt, outcome, exit_code, error, log_file,
			workdir, resumed, agent_session, message, cost_usd, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens
		FROM runs WHERE id = ?`, id).
		Scan(&r.Source, &r.Key, &r.Status, &r.Attempt, &outcome, &exit, &msg, &res.LogFile,
			&res.Workdir, &res.Resumed, &res.SessionID, &res.Message, &res.CostUSD,
			&res.Usage.InputTokens, &res.Usage.OutputTokens, &res.Usage.CacheReadTokens, &res.Usage.CacheWriteTokens)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	res.Outcome, res.ExitCode = task.Outcome(outcome), -1
	if exit.Valid {
		res.ExitCode = int(exit.Int64)
	}
	if msg != "" {
		res.Err = errors.New(msg)
	}
	return &r, nil
}

// AddDelivery records a webhook delivery for ttl and reports whether it is
// new. An empty key is always new.
func (s *Store) AddDelivery(key string, ttl time.Duration) (bool, error) {
	if key == "" {
		return true, nil
	}
	now := s.now()
	isNew := false
	err := s.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM deliveries WHERE expires_at < ?`, ms(now)); err != nil {
			return err
		}
		r, err := tx.Exec(`INSERT INTO deliveries (key, expires_at) VALUES (?, ?) ON CONFLICT (key) DO NOTHING`, key, ms(now.Add(ttl)))
		if err != nil {
			return err
		}
		n, err := r.RowsAffected()
		isNew = n == 1
		return err
	})
	return isNew, err
}

// RemoveDelivery forgets a delivery, so that the sender can retry it.
func (s *Store) RemoveDelivery(key string) error {
	_, err := s.db.Exec(`DELETE FROM deliveries WHERE key = ?`, key)
	return err
}
