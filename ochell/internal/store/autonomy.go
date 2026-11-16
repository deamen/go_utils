package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// Record is the outcome metrics of one class of work for a period, as they
// are kept with a change of the class's level: the numbers that a decision
// was made on.
type Record struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
	// Tickets had a run that started in the period, Runs is how many, and
	// CostUSD what they cost.
	Tickets int     `json:"tickets"`
	Runs    int     `json:"runs"`
	CostUSD float64 `json:"cost_usd"`
	// PullRequests is how many tickets first handed over a pull request in
	// the period, and SentBack how many of them a person then sent back
	// with a follow-up: the override rate of the class is SentBack of
	// PullRequests.
	PullRequests int `json:"pull_requests"`
	SentBack     int `json:"sent_back"`
	// TimeToPR is the median time from the start of a ticket's first run
	// to its pull request.
	TimeToPR        time.Duration `json:"time_to_pr_ns,omitempty"`
	Merged          int           `json:"merged"`
	MergedUntouched int           `json:"merged_untouched"`
	Reopened        int           `json:"reopened"`
}

// Rate is the share of the tickets with a pull request that were sent
// back; 0 for a class without one.
func (r Record) Rate() float64 {
	if r.PullRequests == 0 {
		return 0
	}
	return float64(r.SentBack) / float64(r.PullRequests)
}

// Median returns the middle of some durations, 0 for none.
func Median(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	sorted := slices.Clone(d)
	slices.Sort(sorted)
	if n := len(sorted); n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[len(sorted)/2]
}

// RecordOf returns the outcome metrics of one tier for the period from
// since up to until: the numbers of Outcomes, for that tier alone.
func (s *Store) RecordOf(tier string, since, until time.Time) (Record, error) {
	rec := Record{Since: since.UTC(), Until: until.UTC()}
	list, err := s.Outcomes(since, until)
	if err != nil {
		return rec, err
	}
	for _, o := range list {
		if o.Tier != tier {
			continue
		}
		rec.Tickets, rec.Runs, rec.CostUSD = o.Tickets, o.Runs, o.CostUSD
		rec.PullRequests, rec.SentBack, rec.TimeToPR = o.PullRequests, o.Reworked, Median(o.TimeToPR)
		rec.Merged, rec.MergedUntouched, rec.Reopened = o.Merged, o.MergedUntouched, o.Reopened
	}
	return rec, nil
}

// LevelChange is one change of the level of autonomy of a class of work,
// or a flag of a guardrail that found the class at the lowest level
// already (From and To are then the same).
type LevelChange struct {
	ID int64 `json:"id"`
	// Class names the class of work: the name of its tier.
	Class string `json:"class"`
	From  string `json:"from"`
	To    string `json:"to"`
	// By says who decided: an operator, by the name of their OS user, or
	// "ochell" for a demotion that nobody decided.
	By     string `json:"by"`
	Reason string `json:"reason,omitempty"`
	// Record is the numbers of the class when the level changed.
	Record Record `json:"record"`
	// Source, Key and Run name the ticket and the run that a guardrail
	// flagged; empty for any other change.
	Source string    `json:"source,omitempty"`
	Key    string    `json:"key,omitempty"`
	Run    string    `json:"run,omitempty"`
	At     time.Time `json:"at"`
}

const levelColumns = `id, class, from_level, to_level, by, reason, record, source, key, run, at`

func scanLevel(row interface{ Scan(...any) error }) (*LevelChange, error) {
	var c LevelChange
	var record string
	var at int64
	if err := row.Scan(&c.ID, &c.Class, &c.From, &c.To, &c.By, &c.Reason, &record, &c.Source, &c.Key, &c.Run, &at); err != nil {
		return nil, err
	}
	c.At = time.UnixMilli(at).UTC()
	if record != "" {
		// A record that cannot be read leaves the change itself readable.
		_ = json.Unmarshal([]byte(record), &c.Record)
	}
	return &c, nil
}

// ChangeLevel records a change of the level of a class of work. The class
// has the level c.To from now on. It returns the change as it is stored.
func (s *Store) ChangeLevel(c LevelChange) (LevelChange, error) {
	record, err := json.Marshal(c.Record)
	if err != nil {
		return c, err
	}
	c.At = s.now().UTC().Truncate(time.Millisecond)
	res, err := s.db.Exec(`INSERT INTO autonomy (class, from_level, to_level, by, reason, record, source, key, run, at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, c.Class, c.From, c.To, c.By, c.Reason, string(record), c.Source, c.Key, c.Run, ms(c.At))
	if err != nil {
		return c, err
	}
	c.ID, err = res.LastInsertId()
	return c, err
}

// Level returns the last change of the level of a class of work, which
// says what level it has and since when; nil when nobody has changed it.
func (s *Store) Level(class string) (*LevelChange, error) {
	c, err := scanLevel(s.db.QueryRow(`SELECT `+levelColumns+` FROM autonomy WHERE class = ? ORDER BY id DESC LIMIT 1`, class))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// LevelChanges returns the last changes of the levels of all classes, the
// newest first; limit 0: all of them.
func (s *Store) LevelChanges(limit int) ([]LevelChange, error) {
	if limit <= 0 {
		limit = -1
	}
	rows, err := s.db.Query(`SELECT `+levelColumns+` FROM autonomy ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LevelChange
	for rows.Next() {
		c, err := scanLevel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}
