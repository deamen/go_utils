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
	"sort"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"ochell/internal/agent"
	"ochell/internal/task"
	"ochell/internal/ticket"
)

var (
	ErrBusy      = errors.New("a task for this ticket is already queued or running")
	ErrQueueFull = errors.New("task queue is full")
	// ErrAttempts: the ticket has used up its attempts.
	ErrAttempts = errors.New("the ticket has reached its maximum number of attempts")
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

	// Version 4: the agent's own signal (its result file), and the pull
	// request and branch it names.
	`ALTER TABLE runs ADD COLUMN signal TEXT NOT NULL DEFAULT '';
	ALTER TABLE runs ADD COLUMN signal_message TEXT NOT NULL DEFAULT '';
	ALTER TABLE runs ADD COLUMN pr_url TEXT NOT NULL DEFAULT '';
	ALTER TABLE runs ADD COLUMN branch TEXT NOT NULL DEFAULT '';
	ALTER TABLE tickets ADD COLUMN pr_url TEXT NOT NULL DEFAULT '';
	ALTER TABLE tickets ADD COLUMN branch TEXT NOT NULL DEFAULT '';`,

	// Version 5: the comment that triggered a run.
	`ALTER TABLE runs ADD COLUMN comment TEXT NOT NULL DEFAULT '';`,

	// Version 6: the repository a ticket belongs to.
	`ALTER TABLE tickets ADD COLUMN repo TEXT NOT NULL DEFAULT '';`,

	// Version 7: the working directory that the after_create hook prepared.
	`ALTER TABLE tickets ADD COLUMN prepared_workspace TEXT NOT NULL DEFAULT '';`,

	// Version 8: settings that are changed while ochell runs (the pause flag).
	`CREATE TABLE settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);`,

	// Version 9: why a run was queued, when it was not a plain assignment.
	`ALTER TABLE runs ADD COLUMN cause TEXT NOT NULL DEFAULT '';`,

	// Version 10: a queued run that must wait, for the backoff of a retry.
	`ALTER TABLE runs ADD COLUMN not_before INTEGER NOT NULL DEFAULT 0;`,

	// Version 11: the attempt count at the last message from a person. The
	// attempt cap counts from there.
	`ALTER TABLE tickets ADD COLUMN attempts_base INTEGER NOT NULL DEFAULT 0;
	CREATE INDEX runs_by_session ON runs (source, tracker_session);`,

	// Version 12: messages from people that arrived while the ticket had a
	// run. They are delivered with the ticket's next run.
	`CREATE TABLE followups (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		source          TEXT NOT NULL,
		key             TEXT NOT NULL,
		body            TEXT NOT NULL,
		tracker_session TEXT NOT NULL DEFAULT '',
		received_at     INTEGER NOT NULL
	);
	CREATE INDEX followups_by_ticket ON followups (source, key, id);`,

	// Version 13: who assigned a ticket to the bot.
	`ALTER TABLE tickets ADD COLUMN assigner TEXT NOT NULL DEFAULT '';`,

	// Version 14: the risk tier of a ticket, and for each run the tier and
	// the version of the policy it ran under.
	`ALTER TABLE tickets ADD COLUMN tier TEXT NOT NULL DEFAULT '';
	ALTER TABLE runs ADD COLUMN tier TEXT NOT NULL DEFAULT '';
	ALTER TABLE runs ADD COLUMN policy_version TEXT NOT NULL DEFAULT '';`,

	// Version 15: what the agent's session had cost in total when a run
	// ended, and the cost of a ticket at its last reset. From here on
	// runs.cost_usd is the cost of the run alone. tickets.cost_base was
	// for the budget of a ticket, which ochell no longer has; nothing
	// reads or writes it.
	`ALTER TABLE runs ADD COLUMN session_cost_usd REAL NOT NULL DEFAULT 0;
	ALTER TABLE tickets ADD COLUMN cost_base REAL NOT NULL DEFAULT 0;`,

	// Version 16: the escalation that a run ended with, if any.
	// A message that an escalation kept back goes with the ticket's next
	// run, whenever that starts.
	`ALTER TABLE runs ADD COLUMN escalation TEXT NOT NULL DEFAULT '';
	ALTER TABLE followups ADD COLUMN held INTEGER NOT NULL DEFAULT 0;`,

	// Version 17: the plan gate. Whether a person approved the agent's plan
	// for a ticket and who, and the phase each run was for.
	`ALTER TABLE tickets ADD COLUMN plan_approved INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE tickets ADD COLUMN plan_approved_by TEXT NOT NULL DEFAULT '';
	ALTER TABLE runs ADD COLUMN phase TEXT NOT NULL DEFAULT '';`,

	// Version 18: the pull requests of each ticket, and what became of
	// them. Until now a ticket kept only the last one a run named.
	`CREATE TABLE pull_requests (
		source     TEXT NOT NULL,
		key        TEXT NOT NULL,
		url        TEXT NOT NULL,
		state      TEXT NOT NULL DEFAULT 'open',
		closed_by  TEXT NOT NULL DEFAULT '',
		note       TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (source, key, url)
	);
	INSERT INTO pull_requests (source, key, url, created_at, updated_at)
		SELECT source, key, pr_url, updated_at, updated_at FROM tickets WHERE pr_url != '';`,

	// Version 19: how far ochell has followed a pull request: the commit
	// whose failed checks the agent was given, and the newest comment that
	// was passed on.
	`ALTER TABLE pull_requests ADD COLUMN checked_sha TEXT NOT NULL DEFAULT '';
	ALTER TABLE pull_requests ADD COLUMN seen_comment INTEGER NOT NULL DEFAULT 0;`,

	// Version 20: the rest of the audit record of a run (the hash of its
	// prompt and what its tier granted it), and whether the run started
	// a ticket again that was done.
	`ALTER TABLE runs ADD COLUMN prompt_hash TEXT NOT NULL DEFAULT '';
	ALTER TABLE runs ADD COLUMN grants TEXT NOT NULL DEFAULT '';
	ALTER TABLE runs ADD COLUMN reopened INTEGER NOT NULL DEFAULT 0;`,

	// Version 21: the WORKFLOW.md of each repository: the last version
	// that was valid, which is the one in force, and what ochell found at
	// its last look. And for each run the version it ran under.
	`CREATE TABLE workflows (
		repo       TEXT PRIMARY KEY,
		version    TEXT NOT NULL DEFAULT '',
		content    TEXT NOT NULL DEFAULT '',
		loaded_at  INTEGER NOT NULL DEFAULT 0,
		checked_at INTEGER NOT NULL DEFAULT 0,
		error      TEXT NOT NULL DEFAULT '',
		ignored    TEXT NOT NULL DEFAULT ''
	);
	ALTER TABLE runs ADD COLUMN workflow TEXT NOT NULL DEFAULT '';`,

	// Version 22: scheduling. The priority that the tracker gives a
	// ticket, as a rank (0: none), and why scheduling keeps the ticket's
	// queued run from starting ('': it does not).
	`ALTER TABLE tickets ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE tickets ADD COLUMN hold TEXT NOT NULL DEFAULT '';`,

	// Version 23: graduated autonomy. Every change of the level of a class
	// of work: who decided it, why, and the numbers of the class at that
	// moment. The level of a class is where its last change left it. And
	// for each run the level it ran under.
	`CREATE TABLE autonomy (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		class      TEXT NOT NULL,
		from_level TEXT NOT NULL,
		to_level   TEXT NOT NULL,
		by         TEXT NOT NULL,
		reason     TEXT NOT NULL DEFAULT '',
		record     TEXT NOT NULL DEFAULT '',
		source     TEXT NOT NULL DEFAULT '',
		key        TEXT NOT NULL DEFAULT '',
		run        TEXT NOT NULL DEFAULT '',
		at         INTEGER NOT NULL
	);
	CREATE INDEX autonomy_by_class ON autonomy (class, id);
	ALTER TABLE runs ADD COLUMN autonomy TEXT NOT NULL DEFAULT '';`,

	// Version 24: a tier grants nothing any more, so the audit record of a
	// run no longer says what was granted.
	`ALTER TABLE runs DROP COLUMN grants;`,
}

// Store is safe for concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
	// policyVersion is recorded with every run that starts.
	policyVersion atomic.Value
	// holds are the pauses and throttles of the policy file.
	holds atomic.Value
}

// Holds are the settings of the policy file that keep runs from starting.
// A zero limit is no limit.
type Holds struct {
	// Paused holds everything, and PausedTiers the tickets of these tiers.
	Paused      bool
	PausedTiers []string
	// MaxRunsPerHour is how many runs may start within one hour.
	MaxRunsPerHour int
	// MaxOpenPRsPerRepo is how many pull requests of the bot may be open
	// in one repository.
	MaxOpenPRsPerRepo int
	// MaxConcurrentPerRepo is how many tickets of one repository may be
	// running at the same time.
	MaxConcurrentPerRepo int
	// MaxConcurrentPerTier is how many tickets of a tier may be running
	// at the same time, by the name of the tier.
	MaxConcurrentPerTier map[string]int
}

// SetHolds sets the pauses and throttles of the policy file. Claim keeps
// to them from now on.
func (s *Store) SetHolds(h Holds) { s.holds.Store(h) }

func (s *Store) policyHolds() Holds {
	h, _ := s.holds.Load().(Holds)
	return h
}

// SetPolicyVersion sets the version of the policy that is in force. It is
// recorded with every run that starts from now on.
func (s *Store) SetPolicyVersion(v string) { s.policyVersion.Store(v) }

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

// Limits bound what Enqueue accepts. A zero value means no limit.
type Limits struct {
	// MaxQueued is how many runs may wait in the queue.
	MaxQueued int
	// MaxAttempts is how many runs one ticket may have had since a person
	// last wrote to the agent (FollowUp) or the count was reset.
	MaxAttempts int
}

// attemptsLeft reports whether a ticket may have another run under the
// attempt cap max (0: no cap). The cap is there to stop what ochell starts
// by itself, so it counts the runs since the last message from a person.
func attemptsLeft(tx *sql.Tx, source, key string, max int) (bool, error) {
	if max <= 0 {
		return true, nil
	}
	var used int
	err := tx.QueryRow(`SELECT attempts - attempts_base FROM tickets WHERE source = ? AND key = ?`, source, key).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	return used < max, err
}

// AttemptsLeft reports whether a ticket may have another run under the
// attempt cap max (0: no cap).
func (s *Store) AttemptsLeft(source, key string, max int) (left bool, err error) {
	err = s.tx(func(tx *sql.Tx) error {
		left, err = attemptsLeft(tx, source, key, max)
		return err
	})
	return left, err
}

// queueFull reports whether max runs (0: no limit) are already waiting.
func queueFull(tx *sql.Tx, max int) (bool, error) {
	if max <= 0 {
		return false, nil
	}
	var n int
	err := tx.QueryRow(`SELECT COUNT(*) FROM runs WHERE status = ?`, runQueued).Scan(&n)
	return n >= max, err
}

// insertRun adds the queued run of t.
func insertRun(tx *sql.Tx, t *task.Task) error {
	_, err := tx.Exec(`INSERT INTO runs (id, source, key, status, context, comment, tracker_session, delivery_id, received_at, cause)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Source, t.Key, runQueued, t.Context, t.Comment, t.TrackerSession, t.DeliveryID, ms(t.Received), t.Cause)
	return err
}

// Enqueue records t as a queued run of its ticket. It returns ErrBusy when
// the ticket already has a queued or running run, ErrAttempts when the
// ticket has had lim.MaxAttempts runs, and ErrQueueFull when lim.MaxQueued
// runs are waiting.
func (s *Store) Enqueue(t *task.Task, lim Limits) error {
	now := ms(s.now())
	return s.tx(func(tx *sql.Tx) error {
		from, err := state(tx, t.Source, t.Key)
		if err != nil {
			return err
		}
		if from.Active() {
			return ErrBusy
		}
		if ok, err := attemptsLeft(tx, t.Source, t.Key, lim.MaxAttempts); err != nil {
			return err
		} else if !ok {
			return ErrAttempts
		}
		if full, err := queueFull(tx, lim.MaxQueued); err != nil {
			return err
		} else if full {
			return ErrQueueFull
		}
		if err := s.upsert(tx, t, now); err != nil {
			return err
		}
		if err := s.move(tx, t.Source, t.Key, ticket.Queued, ""); err != nil {
			return err
		}
		if err := insertRun(tx, t); err != nil {
			return err
		}
		if from == ticket.Done {
			// The ticket was done and is assigned again: reopened.
			_, err = tx.Exec(`UPDATE runs SET reopened = 1 WHERE id = ?`, t.ID)
		}
		return err
	})
}

// FollowUp queues a run of a ticket that ochell already knows, for a
// message that a person wrote to the agent (t.Comment). The ticket keeps
// its repository, and its title and URL where t has none.
//
// A person has looked at the ticket, so its attempts count from here again.
//
// addressed says that the person wrote to the agent itself, as in a Linear
// agent session. A message that is only a comment on the ticket counts
// while ochell holds the ticket open; for a ticket that is done or was
// released (cancelled), FollowUp then returns ErrReleased.
//
// A ticket that has a queued or running run takes no second one. The
// message is then kept, and delivered with the run that follows the current
// one (Finish queues it): later is true, and t itself is not queued.
//
// It returns ErrUnknown for a ticket that ochell has never seen, and
// ErrQueueFull when the queue, or the list of messages that wait for this
// ticket, is full.
func (s *Store) FollowUp(t *task.Task, addressed bool, lim Limits) (later bool, err error) {
	err = s.tx(func(tx *sql.Tx) error {
		from, err := state(tx, t.Source, t.Key)
		if err != nil {
			return err
		}
		switch {
		case from == ticket.None:
			return ErrUnknown
		case from.Active():
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM followups WHERE source = ? AND key = ?`, t.Source, t.Key).Scan(&n); err != nil {
				return err
			}
			if n >= maxWaitingMessages {
				return ErrQueueFull
			}
			later = true
			_, err := tx.Exec(`INSERT INTO followups (source, key, body, tracker_session, received_at) VALUES (?, ?, ?, ?, ?)`,
				t.Source, t.Key, t.Comment, t.TrackerSession, ms(t.Received))
			return err
		case !addressed && (from == ticket.Done || from == ticket.Cancelled):
			return ErrReleased
		}
		if full, err := queueFull(tx, lim.MaxQueued); err != nil {
			return err
		} else if full {
			return ErrQueueFull
		}
		if _, err := tx.Exec(`UPDATE tickets SET attempts_base = attempts,
				title = CASE WHEN ? != '' THEN ? ELSE title END,
				url = CASE WHEN ? != '' THEN ? ELSE url END
			WHERE source = ? AND key = ?`, t.Title, t.Title, t.URL, t.URL, t.Source, t.Key); err != nil {
			return err
		}
		if err := s.move(tx, t.Source, t.Key, ticket.Queued, ""); err != nil {
			return err
		}
		return insertRun(tx, t)
	})
	return later, err
}

// ErrNoPlan is returned for an approval of a ticket that does not wait for
// one.
var ErrNoPlan = errors.New("the ticket has no plan that waits for an approval")

// Approve records that a person, named in by, approved the agent's plan
// for the ticket of t, and queues the run that carries the plan out. What
// the person wrote besides the approval is t.Comment.
//
// It returns ErrNoPlan unless the ticket waits for a plan approval,
// ErrUnknown for a ticket that ochell has never seen, and ErrQueueFull.
func (s *Store) Approve(t *task.Task, by string, lim Limits) error {
	return s.tx(func(tx *sql.Tx) error {
		var st ticket.State
		var reason ticket.Reason
		err := tx.QueryRow(`SELECT state, reason FROM tickets WHERE source = ? AND key = ?`, t.Source, t.Key).Scan(&st, &reason)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ErrUnknown
		case err != nil:
			return err
		case st != ticket.Waiting || reason != ticket.ReasonPlanApproval:
			return ErrNoPlan
		}
		if full, err := queueFull(tx, lim.MaxQueued); err != nil {
			return err
		} else if full {
			return ErrQueueFull
		}
		// A person has looked at the ticket: its attempts count from here.
		if _, err := tx.Exec(`UPDATE tickets SET plan_approved = 1, plan_approved_by = ?, attempts_base = attempts WHERE source = ? AND key = ?`,
			by, t.Source, t.Key); err != nil {
			return err
		}
		if err := s.move(tx, t.Source, t.Key, ticket.Queued, ""); err != nil {
			return err
		}
		return insertRun(tx, t)
	})
}

// maxWaitingMessages is how many messages may wait for the next run of one
// ticket.
const maxWaitingMessages = 50

// takeFollowUps removes and returns the messages that wait for the next
// run of a ticket, oldest first, and the tracker session of the last one
// that names one. With held it takes only the messages that an escalation
// kept back.
func takeFollowUps(tx *sql.Tx, source, key string, held bool) (bodies []string, session string, err error) {
	only := ""
	if held {
		only = " AND held = 1"
	}
	rows, err := tx.Query(`SELECT body, tracker_session FROM followups WHERE source = ? AND key = ?`+only+` ORDER BY id`, source, key)
	if err != nil {
		return nil, "", err
	}
	for rows.Next() {
		var body, sess string
		if err := rows.Scan(&body, &sess); err != nil {
			rows.Close()
			return nil, "", err
		}
		bodies = append(bodies, body)
		if sess != "" {
			session = sess
		}
	}
	if err := rows.Close(); err != nil {
		return nil, "", err
	}
	_, err = tx.Exec(`DELETE FROM followups WHERE source = ? AND key = ?`+only, source, key)
	return bodies, session, err
}

// Waiting returns how many messages wait for the next run of a ticket.
func (s *Store) Waiting(source, key string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM followups WHERE source = ? AND key = ?`, source, key).Scan(&n)
	return n, err
}

// TicketOfSession returns the key of the ticket whose run reported to this
// tracker session (a Linear agent session), or "" when there is none.
func (s *Store) TicketOfSession(source, session string) (string, error) {
	if session == "" {
		return "", nil
	}
	var key string
	err := s.db.QueryRow(`SELECT key FROM runs WHERE source = ? AND tracker_session = ? ORDER BY received_at DESC, rowid DESC LIMIT 1`,
		source, session).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return key, err
}

// upsert records the ticket of t, or brings its title, URL and repository
// up to date, and its tier, its priority and who assigned it when t says
// so. A new ticket is created in the state "none", and then moved like any
// other. The ticket is held by scheduling when t.Hold says so, and not
// otherwise.
//
// It is called for a new assignment, which is new work: an approval that an
// earlier plan of the ticket got does not carry over.
func (s *Store) upsert(tx *sql.Tx, t *task.Task, now int64) error {
	_, err := tx.Exec(`INSERT INTO tickets (source, key, title, url, repo, assigner, tier, priority, hold, state, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (source, key) DO UPDATE SET title = excluded.title, url = excluded.url, repo = excluded.repo,
			assigner = CASE WHEN excluded.assigner != '' THEN excluded.assigner ELSE assigner END,
			tier = CASE WHEN excluded.tier != '' THEN excluded.tier ELSE tier END,
			priority = CASE WHEN excluded.priority > 0 THEN excluded.priority ELSE priority END,
			hold = excluded.hold,
			plan_approved = 0, plan_approved_by = ''`,
		t.Source, t.Key, t.Title, t.URL, t.Repo, t.Actor, t.Tier, t.Priority, t.Hold, ticket.None, now, now)
	return err
}

// Hold records the ticket of t as waiting for a human, without a run: the
// ticket cannot be started as it is. It returns ErrBusy when the ticket has
// a queued or running run.
func (s *Store) Hold(t *task.Task, reason ticket.Reason) error {
	return s.tx(func(tx *sql.Tx) error {
		from, err := state(tx, t.Source, t.Key)
		if err != nil {
			return err
		}
		if from.Active() {
			return ErrBusy
		}
		// Scheduling holds a queued run, and this ticket gets none.
		held := *t
		held.Hold = ""
		if err := s.upsert(tx, &held, ms(s.now())); err != nil {
			return err
		}
		return s.move(tx, t.Source, t.Key, ticket.Waiting, reason)
	})
}

const taskColumns = `r.id, r.source, r.key, t.title, t.url, r.context, r.tracker_session, r.delivery_id, r.received_at, r.attempt,
	t.agent_session, t.workspace, r.comment, t.pr_url, t.branch, t.repo, t.prepared_workspace, r.cause, t.tier, t.plan_approved, t.plan_approved_by,
	COALESCE((SELECT p.outcome FROM runs p WHERE p.source = r.source AND p.key = r.key AND p.status = 'ended' AND p.rowid != r.rowid
		ORDER BY p.ended_at DESC, p.rowid DESC LIMIT 1), '')`

func scanTask(row interface{ Scan(...any) error }) (*task.Task, error) {
	var t task.Task
	var received int64
	if err := row.Scan(&t.ID, &t.Source, &t.Key, &t.Title, &t.URL, &t.Context, &t.TrackerSession, &t.DeliveryID, &received, &t.Attempt,
		&t.AgentSession, &t.Workspace, &t.Comment, &t.PRURL, &t.Branch, &t.Repo, &t.PreparedWorkspace, &t.Cause, &t.Tier, &t.PlanApproved, &t.ApprovedBy, &t.LastOutcome); err != nil {
		return nil, err
	}
	t.Received = time.UnixMilli(received).UTC()
	return &t, nil
}

const settingPaused = "paused"

// settingPausedTier is the prefix of the setting that pauses one tier.
const settingPausedTier = "paused:tier:"

// SetTierPaused pauses the tickets of one tier, or ends that pause. While
// it is set, Claim hands out no run of a ticket in that tier. Like the
// pause of everything, it is kept across a restart.
func (s *Store) SetTierPaused(tier string, paused bool) error {
	if !paused {
		_, err := s.db.Exec(`DELETE FROM settings WHERE key = ?`, settingPausedTier+tier)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO settings (key, value) VALUES (?, '1') ON CONFLICT (key) DO NOTHING`, settingPausedTier+tier)
	return err
}

// pausedTiers returns the tiers that a command paused.
func pausedTiers(q interface {
	Query(string, ...any) (*sql.Rows, error)
}) ([]string, error) {
	rows, err := q.Query(`SELECT key FROM settings WHERE key LIKE ? ORDER BY key`, settingPausedTier+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tiers []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		tiers = append(tiers, strings.TrimPrefix(k, settingPausedTier))
	}
	return tiers, rows.Err()
}

// Holding is what keeps runs from starting right now.
type Holding struct {
	// Paused: a command paused everything. PolicyPaused: the policy file
	// does.
	Paused, PolicyPaused bool
	// Tiers are the tiers that a command paused, and PolicyTiers the ones
	// that the policy file pauses.
	Tiers, PolicyTiers []string
	// Throttles says, for each throttle that holds everything now, which
	// one and why.
	Throttles []string
}

// All reports whether no run at all can start.
func (h Holding) All() bool { return h.Paused || h.PolicyPaused || len(h.Throttles) > 0 }

// Holding reports what keeps runs from starting right now.
func (s *Store) Holding() (Holding, error) {
	var h Holding
	err := s.tx(func(tx *sql.Tx) error {
		var err error
		h, err = s.holding(tx)
		return err
	})
	return h, err
}

func (s *Store) holding(tx *sql.Tx) (Holding, error) {
	pol := s.policyHolds()
	h := Holding{PolicyPaused: pol.Paused, PolicyTiers: pol.PausedTiers}
	var err error
	if h.Paused, err = paused(tx); err != nil {
		return h, err
	}
	if h.Tiers, err = pausedTiers(tx); err != nil {
		return h, err
	}
	now := s.now()
	if pol.MaxRunsPerHour > 0 {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM runs WHERE started_at IS NOT NULL AND started_at > ?`, ms(now.Add(-time.Hour))).Scan(&n); err != nil {
			return h, err
		}
		if n >= pol.MaxRunsPerHour {
			h.Throttles = append(h.Throttles, fmt.Sprintf("max_runs_per_hour: %d runs started in the last hour, the limit is %d", n, pol.MaxRunsPerHour))
		}
	}
	return h, nil
}

// SetPaused sets the pause flag. While it is set, Claim hands out no run:
// queued runs stay queued, and running ones go on. The flag is kept across
// a restart.
func (s *Store) SetPaused(paused bool) error {
	if !paused {
		_, err := s.db.Exec(`DELETE FROM settings WHERE key = ?`, settingPaused)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO settings (key, value) VALUES (?, '1') ON CONFLICT (key) DO NOTHING`, settingPaused)
	return err
}

// Paused reports whether the pause flag is set.
func (s *Store) Paused() (bool, error) {
	return paused(s.db)
}

func paused(q interface {
	QueryRow(string, ...any) *sql.Row
}) (bool, error) {
	var n int
	err := q.QueryRow(`SELECT COUNT(*) FROM settings WHERE key = ?`, settingPaused).Scan(&n)
	return n > 0, err
}

// Counts returns the number of queued and of running runs.
func (s *Store) Counts() (queued, running int, err error) {
	err = s.db.QueryRow(`SELECT COUNT(*) FILTER (WHERE status = ?), COUNT(*) FILTER (WHERE status = ?) FROM runs`,
		runQueued, runRunning).Scan(&queued, &running)
	return queued, running, err
}

// ResetAttempts sets the attempt count of a ticket back to zero, so that a
// ticket that used up its attempts can be started again. It returns
// ErrUnknown for a ticket that ochell has never seen.
func (s *Store) ResetAttempts(source, key string) error {
	r, err := s.db.Exec(`UPDATE tickets SET attempts = 0, attempts_base = 0
		WHERE source = ? AND key = ?`, source, key)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrUnknown
	}
	return nil
}

// SessionCost returns what an agent session of a ticket had cost in total
// when ochell last heard of it: the highest total that a run in that
// session reported. 0 when none did.
func (s *Store) SessionCost(source, key, session string) (float64, error) {
	if session == "" {
		return 0, nil
	}
	var cost float64
	// A run from before version 15 has the session's total in cost_usd.
	err := s.db.QueryRow(`SELECT COALESCE(MAX(MAX(session_cost_usd, cost_usd)), 0) FROM runs
		WHERE source = ? AND key = ? AND agent_session = ?`, source, key, session).Scan(&cost)
	return cost, err
}

// Cost is what a ticket, or a run, has cost.
type Cost struct {
	// Runs is the number of runs that were started.
	Runs    int
	CostUSD float64
	Usage   agent.Usage
}

// TicketCost is what one ticket has cost.
type TicketCost struct {
	Source, Key, Tier string
	State             ticket.State
	Cost
}

const ticketCostQuery = `SELECT t.source, t.key, t.tier, t.state, COUNT(r.id), COALESCE(SUM(r.cost_usd), 0),
		COALESCE(SUM(r.input_tokens), 0), COALESCE(SUM(r.output_tokens), 0),
		COALESCE(SUM(r.cache_read_tokens), 0), COALESCE(SUM(r.cache_write_tokens), 0)
	FROM tickets t LEFT JOIN runs r ON r.source = t.source AND r.key = t.key AND r.started_at IS NOT NULL`

func scanTicketCost(row interface{ Scan(...any) error }) (*TicketCost, error) {
	var c TicketCost
	if err := row.Scan(&c.Source, &c.Key, &c.Tier, &c.State, &c.Runs, &c.CostUSD,
		&c.Usage.InputTokens, &c.Usage.OutputTokens, &c.Usage.CacheReadTokens, &c.Usage.CacheWriteTokens); err != nil {
		return nil, err
	}
	return &c, nil
}

// TicketCost returns what a ticket has cost over all its runs, or nil for
// a ticket that ochell has never seen.
func (s *Store) TicketCost(source, key string) (*TicketCost, error) {
	c, err := scanTicketCost(s.db.QueryRow(ticketCostQuery+` WHERE t.source = ? AND t.key = ? GROUP BY t.source, t.key`, source, key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// TicketCosts returns what the tickets have cost, the ones that ochell
// touched last first, at most limit of them.
func (s *Store) TicketCosts(limit int) ([]TicketCost, error) {
	rows, err := s.db.Query(ticketCostQuery+` GROUP BY t.source, t.key ORDER BY t.updated_at DESC, t.key LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TicketCost
	for rows.Next() {
		c, err := scanTicketCost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// TotalCost returns what all runs have cost that started at or after
// since; the zero time: all runs there are.
func (s *Store) TotalCost(since time.Time) (Cost, error) {
	var c Cost
	from := int64(0)
	if !since.IsZero() {
		from = ms(since)
	}
	err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(cost_usd), 0), COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0),
			COALESCE(SUM(cache_read_tokens), 0), COALESCE(SUM(cache_write_tokens), 0)
		FROM runs WHERE started_at IS NOT NULL AND started_at >= ?`, from).
		Scan(&c.Runs, &c.CostUSD, &c.Usage.InputTokens, &c.Usage.OutputTokens, &c.Usage.CacheReadTokens, &c.Usage.CacheWriteTokens)
	return c, err
}

// RunCost is what one run has cost.
type RunCost struct {
	ID      string
	Attempt int
	Tier    string
	// Outcome is empty for a run that is still going.
	Outcome task.Outcome
	Started time.Time
	Cost
}

// RunCosts returns what the runs of a ticket that were started have cost,
// oldest first.
func (s *Store) RunCosts(source, key string) ([]RunCost, error) {
	rows, err := s.db.Query(`SELECT id, attempt, tier, outcome, started_at, cost_usd, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens
		FROM runs WHERE source = ? AND key = ? AND started_at IS NOT NULL ORDER BY started_at, rowid`, source, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunCost
	for rows.Next() {
		c := RunCost{Cost: Cost{Runs: 1}}
		var started int64
		if err := rows.Scan(&c.ID, &c.Attempt, &c.Tier, &c.Outcome, &started, &c.CostUSD,
			&c.Usage.InputTokens, &c.Usage.OutputTokens, &c.Usage.CacheReadTokens, &c.Usage.CacheWriteTokens); err != nil {
			return nil, err
		}
		c.Started = time.UnixMilli(started).UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetTier sets the risk tier of a ticket. It returns ErrUnknown for a
// ticket that ochell has never seen.
func (s *Store) SetTier(source, key, tier string) error {
	r, err := s.db.Exec(`UPDATE tickets SET tier = ? WHERE source = ? AND key = ?`, tier, source, key)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrUnknown
	}
	return nil
}

// openPRs counts the pull requests of the bot that are open in the
// repository of the ticket t: the ones of tickets that are neither done
// nor cancelled. ochell does not ask the code host; a pull request counts
// as open until its ticket is closed.
const openPRs = `SELECT COUNT(DISTINCT o.pr_url) FROM tickets o
	WHERE o.repo = t.repo AND o.pr_url != '' AND o.state NOT IN ('done', 'cancelled')`

// runningInRepo and runningInTier count the tickets that have an agent
// running in the repository, or in the tier, of the ticket t.
const (
	runningInRepo = `SELECT COUNT(*) FROM tickets o WHERE o.repo = t.repo AND o.state = 'running'`
	runningInTier = `SELECT COUNT(*) FROM tickets o WHERE o.tier = t.tier AND o.state = 'running'`
)

// byPriority orders tickets by the rank of their priority: 1 first, and a
// ticket that has none after every ticket that has one.
const byPriority = `CASE WHEN t.priority > 0 THEN t.priority ELSE 1000 END`

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// HoldPending is the hold of a ticket that was queued and has not been
// looked at yet: whether a gate of scheduling holds it is not known, so it
// does not start.
const HoldPending = "not checked against the tracker yet"

// Held is a ticket whose queued run scheduling keeps from starting.
type Held struct {
	Source, Key string
	// Hold says why.
	Hold string
}

// Held returns the tickets whose queued run scheduling keeps from
// starting, the one that has waited longest first.
func (s *Store) Held() ([]Held, error) {
	rows, err := s.db.Query(`SELECT source, key, hold FROM tickets WHERE state = ? AND hold != '' ORDER BY updated_at, source, key`, ticket.Queued)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Held
	for rows.Next() {
		var h Held
		if err := rows.Scan(&h.Source, &h.Key, &h.Hold); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SetHold changes why scheduling holds the queued run of a ticket; with an
// empty hold the run may start. Only a ticket that is held is touched:
// one that was stopped or has started since is left as it is, and changed
// is then false.
func (s *Store) SetHold(source, key, hold string) (changed bool, err error) {
	r, err := s.db.Exec(`UPDATE tickets SET hold = ? WHERE source = ? AND key = ? AND state = ? AND hold != '' AND hold != ?`,
		hold, source, key, ticket.Queued, hold)
	if err != nil {
		return false, err
	}
	n, _ := r.RowsAffected()
	return n > 0, nil
}

// SetPriority records the priority that the tracker gives a ticket, as a
// rank (0: none). A ticket that ochell does not know is left alone.
func (s *Store) SetPriority(source, key string, priority int) error {
	_, err := s.db.Exec(`UPDATE tickets SET priority = ? WHERE source = ? AND key = ? AND priority != ?`, priority, source, key, priority)
	return err
}

// Full is a repository or a tier in which as many tickets are running as
// may, while a queued ticket waits for a place.
type Full struct {
	// Name is the repository or the tier.
	Name string
	// Running is how many tickets are running there, and Waiting how
	// many queued tickets wait for a place.
	Running, Waiting int
}

// FullRepos returns the repositories in which max tickets are running
// while a queued ticket of the repository waits.
func (s *Store) FullRepos(max int) ([]Full, error) {
	if max <= 0 {
		return nil, nil
	}
	return s.full(`SELECT t.repo, (`+runningInRepo+`), COUNT(*) FROM runs r JOIN tickets t USING (source, key)
		WHERE r.status = ? AND t.repo != '' AND (`+runningInRepo+`) >= ? GROUP BY t.repo ORDER BY t.repo`, runQueued, max)
}

// FullTiers returns the tiers of limits (the most tickets of a tier that
// may be running, by tier) in which that many are running while a queued
// ticket of the tier waits.
func (s *Store) FullTiers(limits map[string]int) ([]Full, error) {
	var out []Full
	for _, tier := range sortedKeys(limits) {
		if limits[tier] <= 0 {
			continue
		}
		full, err := s.full(`SELECT t.tier, (`+runningInTier+`), COUNT(*) FROM runs r JOIN tickets t USING (source, key)
			WHERE r.status = ? AND t.tier = ? AND (`+runningInTier+`) >= ? GROUP BY t.tier`, runQueued, tier, limits[tier])
		if err != nil {
			return nil, err
		}
		out = append(out, full...)
	}
	return out, nil
}

func (s *Store) full(query string, args ...any) ([]Full, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Full
	for rows.Next() {
		var f Full
		if err := rows.Scan(&f.Name, &f.Running, &f.Waiting); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// HeldByPRs returns the repositories in which a queued ticket waits
// because max pull requests of the bot are open there.
func (s *Store) HeldByPRs(max int) ([]string, error) {
	if max <= 0 {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT DISTINCT t.repo FROM runs r JOIN tickets t USING (source, key)
		WHERE r.status = ? AND t.repo != '' AND t.pr_url = '' AND (`+openPRs+`) >= ? ORDER BY t.repo`, runQueued, max)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var repos []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		repos = append(repos, r)
	}
	return repos, rows.Err()
}

// Claim takes the queued run that is next and marks it, and its ticket, as
// running: of the runs that may start, the one whose ticket has the most
// urgent priority, and the oldest of those. It returns nil when nothing is
// queued or every queued run still waits (for its time, as a retry with
// backoff; for a gate of scheduling; for a free place in its repository or
// its tier), and while the pause flag is set. The task's Attempt says
// which run of the ticket this is, counting from 1; AgentSession, Workspace,
// PRURL and Branch come from the ticket's earlier runs.
//
// The run records the tier that its ticket has now, and the version of the
// policy in force.
func (s *Store) Claim() (*task.Task, error) {
	now := ms(s.now())
	var t *task.Task
	err := s.tx(func(tx *sql.Tx) error {
		hold, err := s.holding(tx)
		if err != nil || hold.All() {
			return err
		}
		// A queued run whose time has come, of a ticket that scheduling
		// does not hold, that is not in a paused tier and would not open
		// one pull request too many in its repository. A ticket that has
		// a pull request already works on that one.
		query := `SELECT r.id FROM runs r JOIN tickets t USING (source, key) WHERE r.status = ? AND r.not_before <= ? AND t.hold = ''`
		args := []any{runQueued, now}
		for _, tier := range append(append([]string{}, hold.Tiers...), hold.PolicyTiers...) {
			query += ` AND t.tier != ?`
			args = append(args, tier)
		}
		if max := s.policyHolds().MaxOpenPRsPerRepo; max > 0 {
			query += ` AND (t.repo = '' OR t.pr_url != '' OR (` + openPRs + `) < ?)`
			args = append(args, max)
		}
		// And of a ticket whose repository and whose tier have a place
		// free. This is counted in the transaction that starts the run,
		// so two workers cannot both take the last place.
		pol := s.policyHolds()
		if max := pol.MaxConcurrentPerRepo; max > 0 {
			query += ` AND (t.repo = '' OR (` + runningInRepo + `) < ?)`
			args = append(args, max)
		}
		for _, tier := range sortedKeys(pol.MaxConcurrentPerTier) {
			query += ` AND (t.tier != ? OR (` + runningInTier + `) < ?)`
			args = append(args, tier, pol.MaxConcurrentPerTier[tier])
		}
		// The most urgent first, and a ticket without a priority last;
		// within one priority the oldest run.
		var id string
		err = tx.QueryRow(query+` ORDER BY `+byPriority+`, r.received_at, r.rowid LIMIT 1`, args...).Scan(&id)
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
		// Messages that an escalation left waiting go with this run, before
		// what the run itself was asked.
		if waiting, session, err := takeFollowUps(tx, source, key, true); err != nil {
			return err
		} else if len(waiting) > 0 {
			sep := task.CommentSeparator
			if _, err := tx.Exec(`UPDATE runs SET comment = CASE WHEN comment != '' THEN ? || ? || comment ELSE ? END,
					tracker_session = CASE WHEN tracker_session != '' THEN tracker_session ELSE ? END
				WHERE id = ?`, strings.Join(waiting, sep), sep, strings.Join(waiting, sep), session, id); err != nil {
				return err
			}
		}
		version, _ := s.policyVersion.Load().(string)
		if _, err := tx.Exec(`UPDATE runs SET status = ?, started_at = ?, policy_version = ?,
			attempt = (SELECT attempts FROM tickets t WHERE t.source = runs.source AND t.key = runs.key),
			tier = (SELECT tier FROM tickets t WHERE t.source = runs.source AND t.key = runs.key)
			WHERE id = ?`, runRunning, now, version, id); err != nil {
			return err
		}
		t, err = scanTask(tx.QueryRow(`SELECT `+taskColumns+` FROM runs r JOIN tickets t USING (source, key) WHERE r.id = ?`, id))
		return err
	})
	return t, err
}

// Finish records how a run ended, and moves the ticket to the state that
// follows from it (ticket.AfterRun). The ticket is then free for a new run.
//
// When messages from people arrived during the run (FollowUp), the ticket
// is queued again instead, with a run that delivers them.
func (s *Store) Finish(id string, res task.Result) error {
	_, err := s.FinishAndQueue(id, res, nil)
	return err
}

// Again describes the run that takes the place of one that has ended.
type Again struct {
	// ID is the id of the new run.
	ID    string
	Cause task.Cause
	// NotBefore, when set, is the earliest time the new run may start.
	NotBefore time.Time
	// MaxAttempts is how many runs the ticket may have had; 0: no limit.
	MaxAttempts int
}

// FinishAndQueue records how a run ended, like Finish. With again it also
// queues another run of the same ticket in its place: the ticket goes back
// to queued. The new run has the context, the comment and the tracker
// session of the one that ended.
//
// next says why the ticket was queued again, and is empty when it was not:
//   - again.Cause, when the run asked for with again was queued;
//   - task.CauseFollowUp, when again is nil or the ticket has used up its
//     attempts, and messages from people arrived during the run. The new
//     run delivers them, oldest first.
//
// Messages that arrived during the run are delivered with the new run in
// either case, and the ticket's attempts then count from there.
func (s *Store) FinishAndQueue(id string, res task.Result, again *Again) (next task.Cause, err error) {
	err = s.tx(func(tx *sql.Tx) error {
		next, err = s.finish(tx, id, res, again)
		return err
	})
	return next, err
}

func (s *Store) finish(tx *sql.Tx, id string, res task.Result, again *Again) (next task.Cause, err error) {
	if err := s.end(tx, id, res); err != nil {
		return "", err
	}
	var source, key, comment, session string
	if err := tx.QueryRow(`SELECT source, key, comment, tracker_session FROM runs WHERE id = ?`, id).Scan(&source, &key, &comment, &session); err != nil {
		return "", err
	}
	if again != nil {
		left, err := attemptsLeft(tx, source, key, again.MaxAttempts)
		if err != nil {
			return "", err
		}
		if !left {
			again = nil
		}
	}
	stopped := ticket.Reason("")
	switch {
	case res.Outcome == task.OutcomeCancelled:
	case res.Escalation != "":
		stopped = ticket.ReasonEscalation
	case res.Outcome == task.OutcomeNoProgress:
		// The watchdog stopped the run. Whoever wrote during it did not
		// know that yet.
		stopped = ticket.ReasonNoProgress
	}
	if stopped != "" {
		// An escalation or the watchdog stops the ticket: nothing follows
		// by itself, not another try and not a run for the messages that
		// arrived during this one. They stay, and go with the ticket's
		// next run (Claim).
		if _, err := tx.Exec(`UPDATE followups SET held = 1 WHERE source = ? AND key = ?`, source, key); err != nil {
			return "", err
		}
		return "", s.move(tx, source, key, ticket.Waiting, stopped)
	}
	waiting, waitingSession, err := takeFollowUps(tx, source, key, false)
	if err != nil {
		return "", err
	}
	if res.Outcome == task.OutcomeCancelled {
		// A person stopped the ticket: nothing follows, and what waited
		// for its next run is dropped.
		again, waiting, waitingSession = nil, nil, ""
	}
	fromPeople := len(waiting) > 0
	var newID string
	var notBefore int64
	switch {
	case again != nil:
		// The run that ended is done again, so what it was asked in a
		// comment still holds; the new messages come after it.
		next, newID = again.Cause, again.ID
		if !again.NotBefore.IsZero() {
			notBefore = ms(again.NotBefore)
		}
		if comment != "" {
			waiting = append([]string{comment}, waiting...)
		}
	case len(waiting) > 0:
		next = task.CauseFollowUp
		if newID, err = s.freeID(tx, source, key); err != nil {
			return "", err
		}
	default:
		to, reason := ticket.AfterRun(res.Outcome, res.Signal)
		if to == ticket.InReview && res.AwaitChecks {
			// Not for a reviewer yet: the checks of the pull request come
			// first, when the ticket has one that is followed.
			var open int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM pull_requests WHERE source = ? AND key = ? AND state = ?`, source, key, PROpen).Scan(&open); err != nil {
				return "", err
			}
			if open > 0 {
				to = ticket.Checking
			}
		}
		return "", s.move(tx, source, key, to, reason)
	}
	if err := s.move(tx, source, key, ticket.Queued, ""); err != nil {
		return "", err
	}
	if fromPeople {
		// A person wrote: the ticket's attempts count from here.
		if _, err := tx.Exec(`UPDATE tickets SET attempts_base = attempts WHERE source = ? AND key = ?`, source, key); err != nil {
			return "", err
		}
	}
	if waitingSession != "" {
		// The next run answers where the last message came in.
		session = waitingSession
	}
	_, err = tx.Exec(`INSERT INTO runs (id, source, key, status, context, comment, tracker_session, received_at, cause, not_before)
		SELECT ?, source, key, ?, context, ?, ?, ?, ?, ? FROM runs WHERE id = ?`,
		newID, runQueued, strings.Join(waiting, task.CommentSeparator), session, ms(s.now()), next, notBefore, id)
	return next, err
}

// freeID returns an id for a run of a ticket that the store queues by
// itself, which no other run has.
func (s *Store) freeID(tx *sql.Tx, source, key string) (string, error) {
	for at := s.now(); ; at = at.Add(time.Millisecond) {
		id := task.NewID(at, source, key)
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM runs WHERE id = ?`, id).Scan(&n); err != nil {
			return "", err
		}
		if n == 0 {
			return id, nil
		}
	}
}

// end records how a run ended, and what the ticket keeps from it. It does
// not move the ticket.
func (s *Store) end(tx *sql.Tx, id string, res task.Result) error {
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
			input_tokens = ?, output_tokens = ?, cache_read_tokens = ?, cache_write_tokens = ?,
			signal = ?, signal_message = ?, pr_url = ?, branch = ?, session_cost_usd = ?, escalation = ?, phase = ?,
			prompt_hash = ?, workflow = ?, autonomy = ?
		WHERE id = ? AND status != ?`, runEnded, now, string(res.Outcome), exit, msg, res.LogFile,
		res.Workdir, res.Resumed, res.SessionID, res.Message, res.CostUSD,
		res.Usage.InputTokens, res.Usage.OutputTokens, res.Usage.CacheReadTokens, res.Usage.CacheWriteTokens,
		res.Signal, res.SignalMessage, res.PRURL, res.Branch, res.SessionCostUSD, res.Escalation, res.Phase,
		res.PromptHash, res.Workflow, res.Autonomy,
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
	if res.Workdir != "" {
		if _, err := tx.Exec(`UPDATE tickets SET workspace = ? WHERE source = ? AND key = ?`, res.Workdir, source, key); err != nil {
			return err
		}
	}
	// Every pull request that a run names is tracked.
	if res.PRURL != "" {
		if _, err := tx.Exec(`INSERT INTO pull_requests (source, key, url, created_at, updated_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (source, key, url) DO NOTHING`, source, key, res.PRURL, now, now); err != nil {
			return err
		}
	}
	// The ticket keeps the last pull request and branch a run named.
	if res.PRURL != "" || res.Branch != "" {
		if _, err := tx.Exec(`UPDATE tickets SET
				pr_url = CASE WHEN ? != '' THEN ? ELSE pr_url END,
				branch = CASE WHEN ? != '' THEN ? ELSE branch END
			WHERE source = ? AND key = ?`, res.PRURL, res.PRURL, res.Branch, res.Branch, source, key); err != nil {
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

// Stop ends what ochell holds of a ticket without a running agent, for a
// person who stopped or released it:
//   - a ticket whose run is still queued: the run is closed as cancelled,
//     with why as its error, and returned;
//   - a ticket that waits for a human, is in review or failed: it is
//     released, and nothing is returned.
//
// In both cases the ticket becomes cancelled, the messages that waited for
// its next run are dropped, and it is not started again until it is
// assigned again.
//
// It returns ErrBusy for a ticket whose run is running (the caller stops
// the agent, and the run then ends as cancelled), ErrReleased for a ticket
// that is done or already cancelled, and ErrUnknown.
func (s *Store) Stop(source, key string, why error) (queued *task.Task, err error) {
	err = s.tx(func(tx *sql.Tx) error {
		from, err := state(tx, source, key)
		if err != nil {
			return err
		}
		switch from {
		case ticket.None:
			return ErrUnknown
		case ticket.Running:
			return ErrBusy
		case ticket.Done, ticket.Cancelled:
			return ErrReleased
		case ticket.Queued:
			queued, err = scanTask(tx.QueryRow(`SELECT `+taskColumns+` FROM runs r JOIN tickets t USING (source, key)
				WHERE r.source = ? AND r.key = ? AND r.status = ? ORDER BY r.rowid DESC LIMIT 1`, source, key, runQueued))
			if err != nil {
				return err
			}
			res := task.Result{Outcome: task.OutcomeCancelled, ExitCode: -1, Err: why}
			if err := s.end(tx, queued.ID, res); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`DELETE FROM followups WHERE source = ? AND key = ?`, source, key); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE tickets SET hold = '' WHERE source = ? AND key = ?`, source, key); err != nil {
			return err
		}
		return s.move(tx, source, key, ticket.Cancelled, "")
	})
	return queued, err
}

// ActiveTickets returns the keys of the tickets of a source that have a
// queued or running run.
func (s *Store) ActiveTickets(source string) ([]string, error) {
	rows, err := s.db.Query(`SELECT key FROM tickets WHERE source = ? AND state IN (?, ?) ORDER BY key`, source, ticket.Queued, ticket.Running)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// LastTask returns the task of the most recent run of a ticket, with what
// the ticket has now, or nil when the ticket never had a run. It says
// where a message about the ticket goes (the tracker session).
func (s *Store) LastTask(source, key string) (*task.Task, error) {
	t, err := scanTask(s.db.QueryRow(`SELECT `+taskColumns+` FROM runs r JOIN tickets t USING (source, key)
		WHERE r.source = ? AND r.key = ? ORDER BY r.received_at DESC, r.rowid DESC LIMIT 1`, source, key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// ErrInterrupted is the error recorded for a run that Recover closes.
var ErrInterrupted = errors.New("ochell stopped while the agent was running")

// Interrupted is a run that Recover closed.
type Interrupted struct {
	Task *task.Task
	// Next says why the ticket was queued again, as FinishAndQueue does;
	// empty when it was not.
	Next task.Cause
}

// Recover is called once at start, before any run is claimed. Runs that
// were running when ochell stopped cannot be running any more as far as
// ochell knows: they are closed as interrupted and returned, so their
// tickets can be told. Queued runs stay queued.
//
// again, when not nil, is asked for the run that takes the place of each
// interrupted one (FinishAndQueue). Without it the tickets wait for a human.
func (s *Store) Recover(again func(*task.Task) Again) ([]Interrupted, error) {
	var tasks []*task.Task
	var out []Interrupted
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
			var next *Again
			if again != nil {
				a := again(t)
				next = &a
			}
			queued, err := s.finish(tx, t.ID, res, next)
			if err != nil {
				return err
			}
			out = append(out, Interrupted{Task: t, Next: queued})
		}
		return nil
	})
	return out, err
}

// NoteSession records, while a run is still going, the agent session it
// opened and the working directory it runs in. A run that ochell does not
// see the end of can then be continued in the same session.
func (s *Store) NoteSession(source, key, session, workdir string) error {
	_, err := s.db.Exec(`UPDATE tickets SET agent_session = ?, workspace = ? WHERE source = ? AND key = ?`,
		session, workdir, source, key)
	return err
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
	// Repo is the repository the ticket belongs to, if one is mapped.
	Repo string
	// Tier is the risk tier the ticket runs under. It is empty for a
	// ticket that was recorded before there were tiers.
	Tier  string
	State ticket.State
	// Reason is set when State is ticket.Waiting.
	Reason ticket.Reason
	// Assigner is who last assigned the ticket to the bot, as the source
	// named them; empty when it did not.
	Assigner string
	// PlanApproved says that a person approved the agent's plan since the
	// ticket was last assigned, and PlanApprovedBy who.
	PlanApproved   bool
	PlanApprovedBy string
	// Attempts is the number of runs that were started.
	Attempts  int
	Workspace string
	// PreparedWorkspace is the working directory in which the after_create
	// hook has run.
	PreparedWorkspace string
	// AgentSession is the agent's session id from the last run that
	// reported one.
	AgentSession string
	// PRURL and Branch are the last pull request and branch that a run
	// of the ticket named in its result file.
	PRURL  string
	Branch string
	// Priority is the rank of the priority that the tracker gives the
	// ticket: 1 is the most urgent; 0: none.
	Priority int
	// Hold says why scheduling keeps the queued run of the ticket from
	// starting; empty when it does not.
	Hold    string
	Created time.Time
	Updated time.Time
}

const ticketColumns = `source, key, title, url, repo, tier, assigner, plan_approved, plan_approved_by, state, reason, attempts,
	workspace, prepared_workspace, agent_session, pr_url, branch, priority, hold, created_at, updated_at`

func scanTicket(row interface{ Scan(...any) error }) (*Ticket, error) {
	var t Ticket
	var created, updated int64
	if err := row.Scan(&t.Source, &t.Key, &t.Title, &t.URL, &t.Repo, &t.Tier, &t.Assigner, &t.PlanApproved, &t.PlanApprovedBy, &t.State, &t.Reason, &t.Attempts,
		&t.Workspace, &t.PreparedWorkspace, &t.AgentSession, &t.PRURL, &t.Branch, &t.Priority, &t.Hold, &created, &updated); err != nil {
		return nil, err
	}
	t.Created, t.Updated = time.UnixMilli(created).UTC(), time.UnixMilli(updated).UTC()
	return &t, nil
}

// Ticket returns the stored ticket, or nil when ochell has never seen it.
func (s *Store) Ticket(source, key string) (*Ticket, error) {
	t, err := scanTicket(s.db.QueryRow(`SELECT `+ticketColumns+` FROM tickets WHERE source = ? AND key = ?`, source, key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// Tickets returns the tickets that are in one of the given states, the
// ones that changed last first; with no state, every ticket. limit bounds
// how many; 0: all.
func (s *Store) Tickets(limit int, states ...ticket.State) ([]Ticket, error) {
	query, args := `SELECT `+ticketColumns+` FROM tickets`, []any{}
	if len(states) > 0 {
		query += ` WHERE state IN (?` + strings.Repeat(", ?", len(states)-1) + `)`
		for _, st := range states {
			args = append(args, st)
		}
	}
	query += ` ORDER BY updated_at DESC, source, key`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	return s.tickets(query, args...)
}

// TicketsByKey returns the tickets with this key, of any source.
func (s *Store) TicketsByKey(key string) ([]Ticket, error) {
	return s.tickets(`SELECT `+ticketColumns+` FROM tickets WHERE key = ? ORDER BY source`, key)
}

func (s *Store) tickets(query string, args ...any) ([]Ticket, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ticket
	for rows.Next() {
		t, err := scanTicket(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// RunInfo is one run of a ticket, as far as a person who looks at the
// ticket wants to see it.
type RunInfo struct {
	Run
	// Cause says why the run was queued; empty for a plain assignment.
	Cause task.Cause
	// Received is when the run was queued; Started and Ended are zero for
	// a run that has not got that far.
	Received, Started, Ended time.Time
}

// Runs returns the runs of a ticket, oldest first.
func (s *Store) Runs(source, key string) ([]RunInfo, error) {
	rows, err := s.db.Query(`SELECT id, status, attempt, tier, policy_version, cause, received_at, started_at, ended_at,
			outcome, exit_code, error, log_file, resumed, agent_session, cost_usd, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
			signal, signal_message, pr_url, branch, escalation, phase, prompt_hash, workflow, autonomy
		FROM runs WHERE source = ? AND key = ? ORDER BY received_at, rowid`, source, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunInfo
	for rows.Next() {
		r := RunInfo{Run: Run{Source: source, Key: key}}
		var received int64
		var started, ended, exit sql.NullInt64
		var outcome, msg string
		res := &r.Result
		if err := rows.Scan(&r.ID, &r.Status, &r.Attempt, &r.Tier, &r.PolicyVersion, &r.Cause, &received, &started, &ended,
			&outcome, &exit, &msg, &res.LogFile, &res.Resumed, &res.SessionID, &res.CostUSD,
			&res.Usage.InputTokens, &res.Usage.OutputTokens, &res.Usage.CacheReadTokens, &res.Usage.CacheWriteTokens,
			&res.Signal, &res.SignalMessage, &res.PRURL, &res.Branch, &res.Escalation, &res.Phase, &res.PromptHash, &res.Workflow, &res.Autonomy); err != nil {
			return nil, err
		}
		r.Received = time.UnixMilli(received).UTC()
		if started.Valid {
			r.Started = time.UnixMilli(started.Int64).UTC()
		}
		if ended.Valid {
			r.Ended = time.UnixMilli(ended.Int64).UTC()
		}
		res.Outcome, res.ExitCode = task.Outcome(outcome), -1
		if exit.Valid {
			res.ExitCode = int(exit.Int64)
		}
		if msg != "" {
			res.Err = errors.New(msg)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetPrepared records the working directory in which the after_create hook
// has run for a ticket.
func (s *Store) SetPrepared(source, key, dir string) error {
	_, err := s.db.Exec(`UPDATE tickets SET prepared_workspace = ? WHERE source = ? AND key = ?`, dir, source, key)
	return err
}

// States of a tracked pull request.
const (
	// PROpen: nobody has merged or closed it, as far as ochell knows.
	PROpen = "open"
	// PRMerged and PRClosed: the code host says so.
	PRMerged = "merged"
	PRClosed = "closed"
	// PRRejected: it is not a pull request of the ticket (it is not from
	// the ticket's branch), and ochell does not follow it.
	PRRejected = "rejected"
)

// PullRequest is a pull request that a run of a ticket named.
type PullRequest struct {
	Source, Key string
	URL         string
	// State is PROpen, PRMerged, PRClosed or PRRejected.
	State string
	// ClosedBy is who merged or closed it, as the code host names them.
	ClosedBy string
	// Note says why a pull request was rejected.
	Note string
	// CheckedSHA is the commit whose failed checks the agent was last
	// given, and SeenComment when the newest comment that was passed on to
	// the agent was written.
	CheckedSHA  string
	SeenComment time.Time
	Created     time.Time
	Updated     time.Time
}

func (s *Store) pullRequests(query string, args ...any) ([]PullRequest, error) {
	rows, err := s.db.Query(`SELECT source, key, url, state, closed_by, note, created_at, updated_at, checked_sha, seen_comment FROM pull_requests `+query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PullRequest
	for rows.Next() {
		var p PullRequest
		var created, updated, seen int64
		if err := rows.Scan(&p.Source, &p.Key, &p.URL, &p.State, &p.ClosedBy, &p.Note, &created, &updated, &p.CheckedSHA, &seen); err != nil {
			return nil, err
		}
		if seen > 0 {
			p.SeenComment = time.UnixMilli(seen).UTC()
		}
		p.Created, p.Updated = time.UnixMilli(created).UTC(), time.UnixMilli(updated).UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

// OpenPullRequests returns the tracked pull requests that are open, of
// tickets that are neither done nor cancelled, oldest first.
func (s *Store) OpenPullRequests() ([]PullRequest, error) {
	return s.pullRequests(`WHERE state = ? AND EXISTS (SELECT 1 FROM tickets t WHERE t.source = pull_requests.source AND t.key = pull_requests.key
		AND t.state NOT IN (?, ?)) ORDER BY created_at, url`, PROpen, ticket.Done, ticket.Cancelled)
}

// PullRequests returns the pull requests of a ticket, oldest first.
func (s *Store) PullRequests(source, key string) ([]PullRequest, error) {
	return s.pullRequests(`WHERE source = ? AND key = ? ORDER BY created_at, url`, source, key)
}

// SetPullRequest records what became of a tracked pull request.
func (s *Store) SetPullRequest(source, key, url, state, closedBy, note string) error {
	_, err := s.db.Exec(`UPDATE pull_requests SET state = ?, closed_by = ?, note = ?, updated_at = ? WHERE source = ? AND key = ? AND url = ?`,
		state, closedBy, note, ms(s.now()), source, key, url)
	return err
}

// NotePullRequest records how far ochell has followed a pull request: the
// commit whose failed checks the agent was given ("": unchanged) and when
// the newest comment that was passed on was written (zero: unchanged).
func (s *Store) NotePullRequest(source, key, url, checkedSHA string, seenComment time.Time) error {
	seen := int64(0)
	if !seenComment.IsZero() {
		seen = ms(seenComment)
	}
	_, err := s.db.Exec(`UPDATE pull_requests SET
			checked_sha = CASE WHEN ? != '' THEN ? ELSE checked_sha END,
			seen_comment = MAX(seen_comment, ?), updated_at = ?
		WHERE source = ? AND key = ? AND url = ?`, checkedSHA, checkedSHA, seen, ms(s.now()), source, key, url)
	return err
}

// ErrNotChecking is returned when a ticket does not wait for the checks
// of its pull request.
var ErrNotChecking = errors.New("the ticket does not wait for the checks of its pull request")

// ToReview moves a ticket that waited for the checks of its pull request
// to review: the checks passed, or the agent cannot fix them.
func (s *Store) ToReview(source, key string) error {
	return s.tx(func(tx *sql.Tx) error {
		from, err := state(tx, source, key)
		if err != nil {
			return err
		}
		if from != ticket.Checking {
			return ErrNotChecking
		}
		return s.move(tx, source, key, ticket.InReview, "")
	})
}

// WakeForChecks queues a run of a ticket whose pull request failed its
// checks. t.Comment says what failed. It returns ErrNotChecking unless the
// ticket waits for its checks, ErrAttempts when the ticket has used
// lim.MaxAttempts runs, and ErrQueueFull.
func (s *Store) WakeForChecks(t *task.Task, lim Limits) error {
	return s.tx(func(tx *sql.Tx) error {
		from, err := state(tx, t.Source, t.Key)
		if err != nil {
			return err
		}
		if from != ticket.Checking {
			return ErrNotChecking
		}
		if ok, err := attemptsLeft(tx, t.Source, t.Key, lim.MaxAttempts); err != nil {
			return err
		} else if !ok {
			return ErrAttempts
		}
		if full, err := queueFull(tx, lim.MaxQueued); err != nil {
			return err
		} else if full {
			return ErrQueueFull
		}
		if err := s.move(tx, t.Source, t.Key, ticket.Queued, ""); err != nil {
			return err
		}
		return insertRun(tx, t)
	})
}

// ErrUnknown is returned for a ticket that ochell has never seen.
var ErrUnknown = errors.New("unknown ticket")

// ErrReleased is returned for a ticket that ochell no longer holds: it is
// done, or it was stopped or released by a human.
var ErrReleased = errors.New("the ticket is done or was released")

// CloseTicket records that the tracker reports a ticket as closed, and
// returns the ticket. A ticket that waits or is in review, or whose last
// run failed, becomes done. It returns ErrBusy for a ticket with a queued
// or running run, which is left as it is, and ErrUnknown for a ticket that
// ochell has never seen.
func (s *Store) CloseTicket(source, key string) (*Ticket, error) {
	err := s.tx(func(tx *sql.Tx) error {
		from, err := state(tx, source, key)
		if err != nil {
			return err
		}
		switch {
		case from == ticket.None:
			return ErrUnknown
		case from.Active():
			return ErrBusy
		}
		if ticket.Move(from, ticket.Done, "") == nil {
			return s.move(tx, source, key, ticket.Done, "")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.Ticket(source, key)
}

// ClosedWithWorkspace returns the tickets that are done and still have a
// working directory recorded: its removal did not happen, or did not
// succeed.
func (s *Store) ClosedWithWorkspace() ([]Ticket, error) {
	return s.tickets(`SELECT `+ticketColumns+` FROM tickets WHERE state = ? AND (workspace != '' OR prepared_workspace != '') ORDER BY updated_at`, ticket.Done)
}

// ClearWorkspace forgets the working directory of a ticket, after it was
// removed. The agent session goes with it: its files were in there.
func (s *Store) ClearWorkspace(source, key string) error {
	_, err := s.db.Exec(`UPDATE tickets SET workspace = '', prepared_workspace = '', agent_session = ''
		WHERE source = ? AND key = ?`, source, key)
	return err
}

// Workflow is what ochell knows about the WORKFLOW.md of one repository.
type Workflow struct {
	// Repo is the repository, as the repos setting names it.
	Repo string
	// Version and Content are those of the last file that was valid: the
	// one in force. Both are empty when there is none.
	Version string
	Content string
	// Loaded is when the version in force was first read, and Checked when
	// ochell last looked at the default branch.
	Loaded, Checked time.Time
	// Error says why what the default branch has now is not in force: the
	// file is invalid, or could not be read. Empty: it is in force.
	Error string
	// Ignored are the settings of the file in force that the last run did
	// not use, each with the reason.
	Ignored []string
}

// Workflow returns what is stored about the WORKFLOW.md of a repository,
// or nil when ochell has never looked.
func (s *Store) Workflow(repo string) (*Workflow, error) {
	list, err := s.workflows(`WHERE repo = ?`, repo)
	if err != nil || len(list) == 0 {
		return nil, err
	}
	return &list[0], nil
}

// Workflows returns what is stored about every repository's WORKFLOW.md,
// by repository.
func (s *Store) Workflows() ([]Workflow, error) {
	return s.workflows(`ORDER BY repo`)
}

func (s *Store) workflows(where string, args ...any) ([]Workflow, error) {
	rows, err := s.db.Query(`SELECT repo, version, content, loaded_at, checked_at, error, ignored FROM workflows `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Workflow
	for rows.Next() {
		var w Workflow
		var loaded, checked int64
		var ignored string
		if err := rows.Scan(&w.Repo, &w.Version, &w.Content, &loaded, &checked, &w.Error, &ignored); err != nil {
			return nil, err
		}
		if loaded > 0 {
			w.Loaded = time.UnixMilli(loaded).UTC()
		}
		if checked > 0 {
			w.Checked = time.UnixMilli(checked).UTC()
		}
		if ignored != "" {
			w.Ignored = strings.Split(ignored, "\n")
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// SaveWorkflow stores what ochell knows about the WORKFLOW.md of a
// repository, in the place of what was stored.
func (s *Store) SaveWorkflow(w Workflow) error {
	var loaded, checked int64
	if !w.Loaded.IsZero() {
		loaded = ms(w.Loaded)
	}
	if !w.Checked.IsZero() {
		checked = ms(w.Checked)
	}
	// One line each: a reason never has a line break of its own.
	ignored := make([]string, len(w.Ignored))
	for i, line := range w.Ignored {
		ignored[i] = strings.Join(strings.Fields(line), " ")
	}
	_, err := s.db.Exec(`INSERT INTO workflows (repo, version, content, loaded_at, checked_at, error, ignored) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (repo) DO UPDATE SET version = excluded.version, content = excluded.content, loaded_at = excluded.loaded_at,
			checked_at = excluded.checked_at, error = excluded.error, ignored = excluded.ignored`,
		w.Repo, w.Version, w.Content, loaded, checked, w.Error, strings.Join(ignored, "\n"))
	return err
}

// Run is the stored record of one run.
type Run struct {
	ID          string
	Source, Key string
	// Status is "queued", "running" or "ended".
	Status  string
	Attempt int
	// Tier is the risk tier the run started under, and PolicyVersion the
	// version of the policy that was in force then. Both are empty for a
	// run that has not started.
	Tier          string
	PolicyVersion string
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
	err := s.db.QueryRow(`SELECT source, key, status, attempt, tier, policy_version, outcome, exit_code, error, log_file,
			workdir, resumed, agent_session, message, cost_usd, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
			signal, signal_message, pr_url, branch, session_cost_usd, escalation, phase, prompt_hash, workflow, autonomy
		FROM runs WHERE id = ?`, id).
		Scan(&r.Source, &r.Key, &r.Status, &r.Attempt, &r.Tier, &r.PolicyVersion, &outcome, &exit, &msg, &res.LogFile,
			&res.Workdir, &res.Resumed, &res.SessionID, &res.Message, &res.CostUSD,
			&res.Usage.InputTokens, &res.Usage.OutputTokens, &res.Usage.CacheReadTokens, &res.Usage.CacheWriteTokens,
			&res.Signal, &res.SignalMessage, &res.PRURL, &res.Branch, &res.SessionCostUSD, &res.Escalation, &res.Phase, &res.PromptHash, &res.Workflow, &res.Autonomy)
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

// Outcomes are the outcome metrics of the tickets of one tier, for a
// period. They are what a person looks at to judge how a class of work
// goes, and whether its policy should change.
type Outcomes struct {
	Tier string
	// Tickets had a run that started in the period, and Runs is how many.
	Tickets, Runs int
	// CostUSD is what those runs cost.
	CostUSD float64
	// PullRequests is how many tickets first handed over a pull request in
	// the period, and TimeToPR how long each of them took from the start
	// of its first run to that hand-over.
	PullRequests int
	TimeToPR     []time.Duration
	// Reworked is how many of those tickets a person then sent back: they
	// got a follow-up after the pull request.
	Reworked int
	// Merged is how many pull requests were merged in the period, and
	// MergedUntouched how many of them were of tickets that no person
	// sent back after the hand-over.
	Merged, MergedUntouched int
	// Reopened is how many tickets were done and were assigned again in
	// the period.
	Reopened int
}

// Outcomes returns the outcome metrics per tier for the period from since
// up to until, the tiers in alphabetical order. A ticket counts under the
// tier it has now.
func (s *Store) Outcomes(since, until time.Time) ([]Outcomes, error) {
	from, to := ms(since), ms(until)
	byTier := map[string]*Outcomes{}
	get := func(tier string) *Outcomes {
		if byTier[tier] == nil {
			byTier[tier] = &Outcomes{Tier: tier}
		}
		return byTier[tier]
	}
	rows, err := s.db.Query(`SELECT t.tier, COUNT(DISTINCT t.source || ' ' || t.key), COUNT(*), COALESCE(SUM(r.cost_usd), 0),
			COUNT(DISTINCT CASE WHEN r.reopened = 1 THEN t.source || ' ' || t.key END)
		FROM runs r JOIN tickets t USING (source, key)
		WHERE r.started_at >= ? AND r.started_at < ? GROUP BY t.tier`, from, to)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var tier string
		var o Outcomes
		if err := rows.Scan(&tier, &o.Tickets, &o.Runs, &o.CostUSD, &o.Reopened); err != nil {
			rows.Close()
			return nil, err
		}
		got := get(tier)
		got.Tickets, got.Runs, got.CostUSD, got.Reopened = o.Tickets, o.Runs, o.CostUSD, o.Reopened
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	// Per ticket: when its first run started, when it first handed over a
	// pull request, and whether a person sent it back after that.
	const handover = `(SELECT MIN(p.ended_at) FROM runs p WHERE p.source = t.source AND p.key = t.key AND p.pr_url != '')`
	const sentBack = `(SELECT COUNT(*) FROM runs f WHERE f.source = t.source AND f.key = t.key AND f.cause = 'follow_up' AND f.received_at > ` + handover + `)`
	rows, err = s.db.Query(`SELECT t.tier, (SELECT MIN(x.started_at) FROM runs x WHERE x.source = t.source AND x.key = t.key), `+handover+`, `+sentBack+`
		FROM tickets t WHERE `+handover+` >= ? AND `+handover+` < ?`, from, to)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var tier string
		var first, pr sql.NullInt64
		var back int
		if err := rows.Scan(&tier, &first, &pr, &back); err != nil {
			rows.Close()
			return nil, err
		}
		o := get(tier)
		o.PullRequests++
		if first.Valid && pr.Valid && pr.Int64 >= first.Int64 {
			o.TimeToPR = append(o.TimeToPR, time.Duration(pr.Int64-first.Int64)*time.Millisecond)
		}
		if back > 0 {
			o.Reworked++
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = s.db.Query(`SELECT t.tier, COUNT(*), COUNT(CASE WHEN `+sentBack+` = 0 THEN 1 END)
		FROM pull_requests pr JOIN tickets t USING (source, key)
		WHERE pr.state = ? AND pr.updated_at >= ? AND pr.updated_at < ? GROUP BY t.tier`, PRMerged, from, to)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var tier string
		var merged, untouched int
		if err := rows.Scan(&tier, &merged, &untouched); err != nil {
			rows.Close()
			return nil, err
		}
		o := get(tier)
		o.Merged, o.MergedUntouched = merged, untouched
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	out := make([]Outcomes, 0, len(byTier))
	for _, o := range byTier {
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tier < out[j].Tier })
	return out, nil
}

// Backup writes a consistent copy of the store to dest, which must not
// exist. It can run while ochell works: the copy is the state of one
// moment. The file is readable by its owner only, like the store.
func (s *Store) Backup(dest string) error {
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("store backup: %s exists", dest)
	}
	// VACUUM INTO writes a whole, compact database file in one read
	// transaction. It goes to a name of its own first, so that a backup
	// that broke off is never taken for a whole one.
	tmp := dest + ".partial"
	os.Remove(tmp)
	if _, err := s.db.Exec(`VACUUM INTO '` + strings.ReplaceAll(tmp, "'", "''") + `'`); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("store backup: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("store backup: %w", err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("store backup: %w", err)
	}
	return nil
}

// Verify checks that the file at path is a store that this ochell can
// use: a whole SQLite database, of a schema version that it knows. It
// does not change the file.
func Verify(path string) error {
	if info, err := os.Stat(path); err != nil {
		return err
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	q := url.Values{}
	q.Add("mode", "ro")
	q.Add("_pragma", "busy_timeout(5000)")
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: path}).EscapedPath()+"?"+q.Encode())
	if err != nil {
		return err
	}
	defer db.Close()
	var check string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil {
		return fmt.Errorf("%s is not a store: %w", path, err)
	}
	if check != "ok" {
		return fmt.Errorf("%s is damaged: %s", path, check)
	}
	var version, tables int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('tickets', 'runs')`).Scan(&tables); err != nil {
		return err
	}
	switch {
	case version == 0 || tables != 2:
		return fmt.Errorf("%s is not a store of ochell", path)
	case version > len(migrations):
		return fmt.Errorf("%s has schema version %d, this ochell knows up to %d: it was written by a newer ochell", path, version, len(migrations))
	}
	return nil
}

// DurationBuckets are the upper bounds, in seconds, of the buckets in
// which Metrics counts how long runs took.
var DurationBuckets = []float64{60, 300, 900, 1800, 3600, 7200}

// Metrics are counts over everything in the store, for the metrics
// endpoint. The counters only grow: a run is never removed.
type Metrics struct {
	// Tickets is the number of tickets in each state.
	Tickets map[ticket.State]int
	// Queued and Running are the runs that wait and that are going on.
	Queued, Running int
	// Started is the number of runs that were started, by why they were
	// queued ("assigned" for a plain assignment), and Ended the number
	// that have ended, by outcome.
	Started map[string]int
	Ended   map[task.Outcome]int
	// DurationCount and DurationSum are the number of ended runs that ran
	// and the seconds they took together; DurationBucket[i] is how many of
	// them took at most DurationBuckets[i] seconds.
	DurationCount  int
	DurationSum    float64
	DurationBucket []int
	// CostUSD and Usage are what all runs cost.
	CostUSD float64
	Usage   agent.Usage
}

// Metrics counts what is in the store.
func (s *Store) Metrics() (*Metrics, error) {
	m := &Metrics{Tickets: map[ticket.State]int{}, Started: map[string]int{}, Ended: map[task.Outcome]int{}, DurationBucket: make([]int, len(DurationBuckets))}
	err := s.tx(func(tx *sql.Tx) error {
		group := func(query string, add func(name string, n int)) error {
			rows, err := tx.Query(query)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var name string
				var n int
				if err := rows.Scan(&name, &n); err != nil {
					return err
				}
				add(name, n)
			}
			return rows.Err()
		}
		if err := group(`SELECT state, COUNT(*) FROM tickets GROUP BY state`, func(name string, n int) { m.Tickets[ticket.State(name)] = n }); err != nil {
			return err
		}
		if err := group(`SELECT CASE WHEN cause = '' THEN 'assigned' ELSE cause END, COUNT(*) FROM runs WHERE started_at IS NOT NULL GROUP BY 1`,
			func(name string, n int) { m.Started[name] = n }); err != nil {
			return err
		}
		if err := group(`SELECT outcome, COUNT(*) FROM runs WHERE status = 'ended' GROUP BY outcome`, func(name string, n int) { m.Ended[task.Outcome(name)] = n }); err != nil {
			return err
		}
		if err := tx.QueryRow(`SELECT COUNT(*) FILTER (WHERE status = ?), COUNT(*) FILTER (WHERE status = ?), COALESCE(SUM(cost_usd), 0),
				COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0), COALESCE(SUM(cache_read_tokens), 0), COALESCE(SUM(cache_write_tokens), 0)
			FROM runs`, runQueued, runRunning).Scan(&m.Queued, &m.Running, &m.CostUSD,
			&m.Usage.InputTokens, &m.Usage.OutputTokens, &m.Usage.CacheReadTokens, &m.Usage.CacheWriteTokens); err != nil {
			return err
		}
		// How long the runs took that ran and have ended.
		const took = `(ended_at - started_at) / 1000.0`
		query := `SELECT COUNT(*), COALESCE(SUM(` + took + `), 0)`
		for range DurationBuckets {
			query += `, COUNT(*) FILTER (WHERE ` + took + ` <= ?)`
		}
		args := make([]any, len(DurationBuckets))
		dest := []any{&m.DurationCount, &m.DurationSum}
		for i, b := range DurationBuckets {
			args[i] = b
			dest = append(dest, &m.DurationBucket[i])
		}
		return tx.QueryRow(query+` FROM runs WHERE status = 'ended' AND started_at IS NOT NULL AND ended_at IS NOT NULL`, args...).Scan(dest...)
	})
	return m, err
}
