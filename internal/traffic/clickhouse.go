package traffic

// The ClickHouse backend, over ClickHouse's HTTP interface with net/http: no
// driver, so no dependency (CLAUDE.md: a dependency needs a reason better than
// convenience, and this protocol is a POST).
//
// ── NOTHING THE USER TYPED IS SPLICED INTO SQL ──────────────────────────────
//
// Every value travels as a query parameter (`{name:Type}` in the SQL,
// `param_name` in the URL), which the server binds. The only identifiers built
// into the text are the database name, checked against [A-Za-z0-9_], and a
// dimension's column, one of four constants.
//
// ── TWO TABLES, EACH WITH ITS OWN TTL ───────────────────────────────────────
//
// traffic_agg holds the same minute rows as SQLite's traffic_min, kept a year;
// traffic_flows holds every attributed flow, kept FlowDays. ClickHouse ages
// both out itself. No rollup: grouping a year of minutes is what it is for.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ClickHouseConfig is how to reach the server.
type ClickHouseConfig struct {
	URL      string // http(s)://host:8123
	User     string
	Password string
	Database string
	// FlowDays is how long flows are kept; the minute rows are kept a year.
	FlowDays int
}

// DefaultFlowDays is the flows' retention when none is set.
const DefaultFlowDays = 90

var identRE = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// Validate checks the config and fills its defaults.
func (c *ClickHouseConfig) Validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("the ClickHouse URL is http(s)://host:port, its HTTP interface (8123 by default)")
	}
	if c.Database == "" {
		c.Database = "mikrodash"
	}
	if !identRE.MatchString(c.Database) {
		return errors.New("the database name is letters, digits and _")
	}
	if c.User == "" {
		c.User = "default"
	}
	if c.FlowDays <= 0 {
		c.FlowDays = DefaultFlowDays
	}
	if c.FlowDays > 3650 {
		return errors.New("flows are kept at most 3650 days")
	}
	return nil
}

// ClickHouse is the ClickHouse backend.
type ClickHouse struct {
	cfg    ClickHouseConfig
	client *http.Client
}

// OpenClickHouse checks the server answers, then creates the database and the
// two tables if they are missing and sets the flows' retention.
func OpenClickHouse(ctx context.Context, cfg ClickHouseConfig, client *http.Client) (*ClickHouse, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	c := &ClickHouse{cfg: cfg, client: client}
	db := cfg.Database
	for _, q := range []string{
		`CREATE DATABASE IF NOT EXISTS ` + db,
		`CREATE TABLE IF NOT EXISTS ` + db + `.traffic_agg (
		   router_id String, ts DateTime('UTC'), host String, app LowCardinality(String),
		   category LowCardinality(String), country LowCardinality(String), rx UInt64, tx UInt64, flows UInt64)
		 ENGINE = MergeTree PARTITION BY toYYYYMM(ts) ORDER BY (router_id, ts, host, app)
		 TTL ts + INTERVAL 1 YEAR`,
		`CREATE TABLE IF NOT EXISTS ` + db + `.traffic_flows (
		   router_id String, ts_end DateTime64(3, 'UTC'), ts_start DateTime64(3, 'UTC'), proto UInt8,
		   host String, host_port UInt16, remote String, remote_port UInt16, app LowCardinality(String),
		   category LowCardinality(String), country LowCardinality(String), org String,
		   rx UInt64, tx UInt64, packets UInt64)
		 ENGINE = MergeTree PARTITION BY toDate(ts_end) ORDER BY (router_id, ts_end, host)
		 TTL toDateTime(ts_end) + INTERVAL ` + strconv.Itoa(cfg.FlowDays) + ` DAY`,
		`ALTER TABLE ` + db + `.traffic_flows MODIFY TTL toDateTime(ts_end) + INTERVAL ` + strconv.Itoa(cfg.FlowDays) + ` DAY`,
	} {
		if _, err := c.do(ctx, q, nil, nil); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Backend names the backend.
func (c *ClickHouse) Backend() string { return "clickhouse" }

// Close has nothing to close: each call is its own request.
func (c *ClickHouse) Close() error { return nil }

// Maintain has nothing to do: the tables' TTLs age them out.
func (c *ClickHouse) Maintain(context.Context, time.Time) error { return nil }

// do runs one statement. `params` are bound to `{name:Type}`; `body`, when
// given, is the statement's data (an INSERT's rows).
func (c *ClickHouse) do(ctx context.Context, query string, params map[string]string, body []byte) ([]byte, error) {
	v := url.Values{}
	v.Set("output_format_json_quote_64bit_integers", "0")
	for k, p := range params {
		v.Set("param_"+k, p)
	}
	var rd io.Reader
	if body != nil {
		v.Set("query", query)
		rd = bytes.NewReader(body)
	} else {
		rd = strings.NewReader(query)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.URL, "/")+"/?"+v.Encode(), rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-ClickHouse-User", c.cfg.User)
	if c.cfg.Password != "" {
		req.Header.Set("X-ClickHouse-Key", c.cfg.Password)
	}
	res, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: %w", err)
	}
	defer res.Body.Close()
	out, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("clickhouse: %s: %s", res.Status, msg)
	}
	return out, nil
}

const chTime = "2006-01-02 15:04:05"
const chTime3 = "2006-01-02 15:04:05.000"

// Write inserts the minutes and the flows, each as one JSONEachRow body.
func (c *ClickHouse) Write(ctx context.Context, routerID string, rows []Agg, flows []RouterFlow) error {
	if len(rows) > 0 {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		for _, r := range rows {
			_ = enc.Encode(map[string]any{"router_id": routerID, "ts": r.TS.UTC().Format(chTime), "host": r.Host,
				"app": r.App, "category": r.Category, "country": r.Country, "rx": r.Rx, "tx": r.Tx, "flows": r.Flows})
		}
		if _, err := c.do(ctx, `INSERT INTO `+c.cfg.Database+`.traffic_agg FORMAT JSONEachRow`, nil, b.Bytes()); err != nil {
			return err
		}
	}
	if len(flows) > 0 {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		for _, f := range flows {
			_ = enc.Encode(map[string]any{"router_id": routerID, "ts_end": f.End.UTC().Format(chTime3),
				"ts_start": f.Start.UTC().Format(chTime3), "proto": f.Proto, "host": f.Host, "host_port": f.HostPort,
				"remote": f.Remote, "remote_port": f.RemotePort, "app": f.App, "category": f.Category,
				"country": f.Country, "org": f.Org, "rx": f.Rx, "tx": f.Tx, "packets": f.Packets})
		}
		if _, err := c.do(ctx, `INSERT INTO `+c.cfg.Database+`.traffic_flows FORMAT JSONEachRow`, nil, b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// where is a query's filter as bound parameters.
func (q Query) chWhere() (string, map[string]string) {
	w := ` WHERE router_id = {r:String} AND ts >= {from:DateTime('UTC')} AND ts < {to:DateTime('UTC')}`
	p := map[string]string{"r": q.RouterID, "from": q.From.UTC().Format(chTime), "to": q.To.UTC().Format(chTime)}
	for col, v := range map[string]string{"host": q.Host, "app": q.App, "country": q.Country} {
		if v != "" {
			w += ` AND ` + col + ` = {f_` + col + `:String}`
			p["f_"+col] = v
		}
	}
	return w, p
}

// Top answers a Query.
func (c *ClickHouse) Top(ctx context.Context, q Query) ([]Top, error) {
	col, err := column(q.Dim)
	if err != nil {
		return nil, err
	}
	w, p := q.chWhere()
	limit := q.Limit
	if limit <= 0 {
		limit = 1000
	}
	p["limit"] = strconv.Itoa(limit)
	out, err := c.do(ctx, `SELECT `+col+` AS key, sum(rx) AS s_rx, sum(tx) AS s_tx, sum(flows) AS s_flows FROM `+
		c.cfg.Database+`.traffic_agg`+w+` GROUP BY key ORDER BY s_rx + s_tx DESC, key LIMIT {limit:UInt32} FORMAT JSONEachRow`, p, nil)
	if err != nil {
		return nil, err
	}
	tops := []Top{}
	err = eachRow(out, func(line []byte) error {
		// Aliased apart from the columns: `sum(rx) AS rx` would make ClickHouse
		// read the rx inside the sum as the sum itself.
		var r struct {
			Key   string `json:"key"`
			Rx    uint64 `json:"s_rx"`
			Tx    uint64 `json:"s_tx"`
			Flows uint64 `json:"s_flows"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		tops = append(tops, Top{Key: r.Key, Rx: r.Rx, Tx: r.Tx, Flows: r.Flows})
		return nil
	})
	return tops, err
}

// Series answers a series.
func (c *ClickHouse) Series(ctx context.Context, q Query, step time.Duration, keys []string) ([]Point, error) {
	col, err := column(q.Dim)
	if err != nil {
		return nil, err
	}
	if step < time.Minute {
		step = time.Minute
	}
	w, p := q.chWhere()
	p["step"] = strconv.FormatInt(int64(step/time.Second), 10)
	out, err := c.do(ctx, `SELECT toUnixTimestamp(toStartOfInterval(ts, toIntervalSecond({step:UInt32}))) AS b, `+col+
		` AS key, sum(rx) AS s_rx, sum(tx) AS s_tx FROM `+c.cfg.Database+`.traffic_agg`+w+` GROUP BY b, key FORMAT JSONEachRow`, p, nil)
	if err != nil {
		return nil, err
	}
	var raw []Point
	err = eachRow(out, func(line []byte) error {
		var r struct {
			B   int64  `json:"b"`
			Key string `json:"key"`
			Rx  uint64 `json:"s_rx"`
			Tx  uint64 `json:"s_tx"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		raw = append(raw, Point{TS: time.Unix(r.B, 0), Key: r.Key, Rx: r.Rx, Tx: r.Tx})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return Fold(raw, keys), nil
}

// Flows searches the stored flows, newest first.
func (c *ClickHouse) Flows(ctx context.Context, q FlowQuery) ([]RouterFlow, error) {
	w := ` WHERE router_id = {r:String} AND ts_end >= {from:DateTime64(3, 'UTC')} AND ts_end < {to:DateTime64(3, 'UTC')}`
	p := map[string]string{"r": q.RouterID, "from": q.From.UTC().Format(chTime3), "to": q.To.UTC().Format(chTime3)}
	for col, v := range map[string]string{"host": q.Host, "remote": q.Remote, "app": q.App, "country": q.Country} {
		if v != "" {
			w += ` AND ` + col + ` = {f_` + col + `:String}`
			p["f_"+col] = v
		}
	}
	limit := q.Limit
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	p["limit"] = strconv.Itoa(limit)
	out, err := c.do(ctx, `SELECT toUnixTimestamp64Milli(ts_end) AS end_ms, toUnixTimestamp64Milli(ts_start) AS start_ms,
	        proto, host, host_port, remote, remote_port, app, category, country, org, rx, tx, packets
	        FROM `+c.cfg.Database+`.traffic_flows`+w+` ORDER BY ts_end DESC LIMIT {limit:UInt32} FORMAT JSONEachRow`, p, nil)
	if err != nil {
		return nil, err
	}
	flows := []RouterFlow{}
	err = eachRow(out, func(line []byte) error {
		var r struct {
			RouterFlow
			EndMs   int64  `json:"end_ms"`
			StartMs int64  `json:"start_ms"`
			HostP   uint16 `json:"host_port"`
			RemoteP uint16 `json:"remote_port"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		f := r.RouterFlow
		f.End, f.Start = time.UnixMilli(r.EndMs).UTC(), time.UnixMilli(r.StartMs).UTC()
		f.HostPort, f.RemotePort = r.HostP, r.RemoteP
		flows = append(flows, f)
		return nil
	})
	return flows, err
}

// eachRow calls f with each line of a JSONEachRow answer.
func eachRow(b []byte, f func([]byte) error) error {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		if line := bytes.TrimSpace(sc.Bytes()); len(line) > 0 {
			if err := f(line); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}
