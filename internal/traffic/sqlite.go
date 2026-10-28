package traffic

// The SQLite backend: the minute rows in /data/traffic.db, a file of their
// own so the app database keeps its one connection to itself, and so the
// whole history can be deleted without touching anything else.
//
// Three tables of the same shape, each a coarser copy of the one before:
// minutes for 48 hours, hours for 90 days, days for a year. Maintain rolls a
// finished hour (and day) up once its last minute has been written, which
// Aggregator guarantees by never writing to a minute it has already taken.

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

// Retention of each table.
const (
	MinuteKeep = 48 * time.Hour
	HourKeep   = 90 * 24 * time.Hour
	DayKeep    = 365 * 24 * time.Hour
)

// rollSettle is how long after an hour ends its minutes are taken as complete.
const rollSettle = 3 * time.Minute

const sqliteDDL = `
CREATE TABLE IF NOT EXISTS traffic_min (
  router_id TEXT NOT NULL, ts INTEGER NOT NULL, host TEXT NOT NULL, app TEXT NOT NULL,
  category TEXT NOT NULL, country TEXT NOT NULL,
  rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0, flows INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (router_id, ts, host, app, category, country)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS traffic_hour (
  router_id TEXT NOT NULL, ts INTEGER NOT NULL, host TEXT NOT NULL, app TEXT NOT NULL,
  category TEXT NOT NULL, country TEXT NOT NULL,
  rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0, flows INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (router_id, ts, host, app, category, country)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS traffic_day (
  router_id TEXT NOT NULL, ts INTEGER NOT NULL, host TEXT NOT NULL, app TEXT NOT NULL,
  category TEXT NOT NULL, country TEXT NOT NULL,
  rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0, flows INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (router_id, ts, host, app, category, country)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS traffic_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
`

// SQLite is the SQLite backend.
type SQLite struct {
	db *sql.DB
}

// OpenSQLite opens (creating if need be) the traffic database at path.
func OpenSQLite(path string) (*SQLite, error) {
	h, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	h.SetMaxOpenConns(1)
	if _, err := h.Exec(sqliteDDL); err != nil {
		h.Close()
		return nil, fmt.Errorf("traffic database %s: %w", path, err)
	}
	return &SQLite{db: h}, nil
}

// Backend names the backend.
func (s *SQLite) Backend() string { return "sqlite" }

// Close closes the file.
func (s *SQLite) Close() error { return s.db.Close() }

func upsert(table string) string {
	return `INSERT INTO ` + table + ` (router_id, ts, host, app, category, country, rx, tx, flows)
	        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	        ON CONFLICT (router_id, ts, host, app, category, country)
	        DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx, flows = flows + excluded.flows`
}

// Write stores the minutes in one transaction. Flows are not kept here.
func (s *SQLite) Write(ctx context.Context, routerID string, rows []Agg, _ []RouterFlow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	st, err := tx.PrepareContext(ctx, upsert("traffic_min"))
	if err != nil {
		return err
	}
	defer st.Close()
	for _, r := range rows {
		if _, err := st.ExecContext(ctx, routerID, r.TS.Unix(), r.Host, r.App, r.Category, r.Country,
			int64(r.Rx), int64(r.Tx), int64(r.Flows)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Maintain rolls finished hours and days up, then ages each table out.
func (s *SQLite) Maintain(ctx context.Context, now time.Time) error {
	settled := now.Add(-rollSettle)
	if err := s.roll(ctx, "traffic_min", "traffic_hour", 3600, settled.Truncate(time.Hour).Unix()); err != nil {
		return err
	}
	if err := s.roll(ctx, "traffic_hour", "traffic_day", 86400, settled.Truncate(24*time.Hour).Unix()); err != nil {
		return err
	}
	for table, keep := range map[string]time.Duration{"traffic_min": MinuteKeep, "traffic_hour": HourKeep, "traffic_day": DayKeep} {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE ts < ?`, now.Add(-keep).Unix()); err != nil {
			return err
		}
	}
	return nil
}

// roll adds every bucket of `from` in [done, upTo) to `to` at `size` seconds,
// and remembers upTo, so a bucket is rolled once.
func (s *SQLite) roll(ctx context.Context, from, to string, size, upTo int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	key := "rolled_" + to
	var done int64
	err = tx.QueryRowContext(ctx, `SELECT value FROM traffic_meta WHERE key = ?`, key).Scan(&done)
	if err == sql.ErrNoRows {
		// First roll: from the oldest row there is.
		var oldest sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT MIN(ts) FROM `+from).Scan(&oldest); err != nil {
			return err
		}
		done = upTo
		if oldest.Valid {
			done = oldest.Int64 / size * size
		}
	} else if err != nil {
		return err
	}
	if done >= upTo {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO `+to+` (router_id, ts, host, app, category, country, rx, tx, flows)
	        SELECT router_id, ts / `+strconv.FormatInt(size, 10)+` * `+strconv.FormatInt(size, 10)+` AS b, host, app,
	               category, country, SUM(rx), SUM(tx), SUM(flows)
	          FROM `+from+` WHERE ts >= ? AND ts < ?
	         GROUP BY router_id, b, host, app, category, country
	        ON CONFLICT (router_id, ts, host, app, category, country)
	        DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx, flows = flows + excluded.flows`,
		done, upTo); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO traffic_meta (key, value) VALUES (?, ?)
	        ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, upTo); err != nil {
		return err
	}
	return tx.Commit()
}

// tableFor is the finest table that still holds `from`, and its bucket size.
func tableFor(from, now time.Time) (string, time.Duration) {
	switch {
	case !from.Before(now.Add(-MinuteKeep)):
		return "traffic_min", time.Minute
	case !from.Before(now.Add(-HourKeep)):
		return "traffic_hour", time.Hour
	}
	return "traffic_day", 24 * time.Hour
}

// column is a dimension's column. Only these four reach the SQL.
func column(d Dim) (string, error) {
	switch d {
	case DimApp, DimCategory, DimHost, DimCountry:
		return string(d), nil
	}
	return "", fmt.Errorf("no such dimension %q", d)
}

// where is a query's filter, and its arguments after router_id.
func (q Query) where() (string, []any) {
	w := ` WHERE router_id = ? AND ts >= ? AND ts < ?`
	args := []any{q.RouterID, q.From.Unix(), q.To.Unix()}
	for col, v := range map[string]string{"host": q.Host, "app": q.App, "country": q.Country} {
		if v != "" {
			w += ` AND ` + col + ` = ?`
			args = append(args, v)
		}
	}
	return w, args
}

// Top answers a Query from the finest table that holds its range.
func (s *SQLite) Top(ctx context.Context, q Query) ([]Top, error) {
	col, err := column(q.Dim)
	if err != nil {
		return nil, err
	}
	table, _ := tableFor(q.From, time.Now())
	w, args := q.where()
	limit := q.Limit
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+col+`, SUM(rx), SUM(tx), SUM(flows) FROM `+table+w+
		` GROUP BY `+col+` ORDER BY SUM(rx) + SUM(tx) DESC, `+col+` LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Top{}
	for rows.Next() {
		var t Top
		var rx, tx, fl int64
		if err := rows.Scan(&t.Key, &rx, &tx, &fl); err != nil {
			return nil, err
		}
		t.Rx, t.Tx, t.Flows = uint64(rx), uint64(tx), uint64(fl)
		out = append(out, t)
	}
	return out, rows.Err()
}

// Series answers a series; a step finer than the table's bucket is the bucket.
func (s *SQLite) Series(ctx context.Context, q Query, step time.Duration, keys []string) ([]Point, error) {
	col, err := column(q.Dim)
	if err != nil {
		return nil, err
	}
	table, bucket := tableFor(q.From, time.Now())
	if step < bucket {
		step = bucket
	}
	w, args := q.where()
	sec := strconv.FormatInt(int64(step/time.Second), 10)
	rows, err := s.db.QueryContext(ctx, `SELECT ts / `+sec+` * `+sec+` AS b, `+col+`, SUM(rx), SUM(tx) FROM `+table+w+
		` GROUP BY b, `+col, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var raw []Point
	for rows.Next() {
		var ts, rx, tx int64
		var key string
		if err := rows.Scan(&ts, &key, &rx, &tx); err != nil {
			return nil, err
		}
		raw = append(raw, Point{TS: time.Unix(ts, 0), Key: key, Rx: uint64(rx), Tx: uint64(tx)})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return Fold(raw, keys), nil
}

// Flows: SQLite keeps none.
func (s *SQLite) Flows(context.Context, FlowQuery) ([]RouterFlow, error) {
	return nil, ErrNoFlowHistory
}
