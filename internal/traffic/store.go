package traffic

// What a backend stores and answers. Two backends, chosen in the Traffic
// page's settings, one contract:
//
//   - SQLite (sqlite.go): the minute rows in their own file beside the app's
//     database, rolled up to hours and days; flows are not kept, the server's
//     last fifteen minutes in memory answer the Flows tab.
//   - ClickHouse (clickhouse.go): the minute rows AND every flow, over HTTP,
//     each with its own retention. No rollup: a columnar store groups a year of
//     minutes faster than SQLite reads a day of them.
//
// Both answer every question below from the same rows, so the page does not
// know which one it is talking to, and a test can hold them to one answer.

import (
	"context"
	"errors"
	"sort"
	"time"
)

// Dim is what a question groups by.
type Dim string

// The dimensions.
const (
	DimApp      Dim = "app"
	DimCategory Dim = "category"
	DimHost     Dim = "host"
	DimCountry  Dim = "country"
)

// Valid is whether d is one of the dimensions.
func (d Dim) Valid() bool {
	return d == DimApp || d == DimCategory || d == DimHost || d == DimCountry
}

// Query is a question about the minute rows: grouped by Dim, optionally
// narrowed to one host, application or country, between From and To.
type Query struct {
	RouterID string
	Dim      Dim
	Host     string
	App      string
	Country  string
	From, To time.Time
	Limit    int
}

// Top is one group's totals.
type Top struct {
	Key   string `json:"key"`
	Rx    uint64 `json:"rx"`
	Tx    uint64 `json:"tx"`
	Flows uint64 `json:"flows"`
}

// Point is one group's bytes in one step of a series.
type Point struct {
	TS  time.Time `json:"ts"`
	Key string    `json:"key"`
	Rx  uint64    `json:"rx"`
	Tx  uint64    `json:"tx"`
}

// Other is the series key for every group outside the ones asked for.
const Other = "Other"

// FlowQuery is a search through stored flows.
type FlowQuery struct {
	RouterID string
	Host     string
	Remote   string
	App      string
	Country  string
	From, To time.Time
	Limit    int
}

// ErrNoFlowHistory is a backend that keeps no flows: SQLite.
var ErrNoFlowHistory = errors.New("this backend keeps no flows; the last fifteen minutes are in memory")

// Store is a backend.
type Store interface {
	// Backend is "sqlite" or "clickhouse".
	Backend() string
	// Write stores one router's completed minutes and the flows they came from.
	Write(ctx context.Context, routerID string, rows []Agg, flows []RouterFlow) error
	Top(ctx context.Context, q Query) ([]Top, error)
	// Series is each of `keys`' bytes per step, the rest under Other.
	Series(ctx context.Context, q Query, step time.Duration, keys []string) ([]Point, error)
	Flows(ctx context.Context, q FlowQuery) ([]RouterFlow, error)
	// Maintain rolls up and ages out; called once a minute.
	Maintain(ctx context.Context, now time.Time) error
	Close() error
}

// RouterFlow is a flow as stored and served: its fields as text, so both
// backends and the page read one shape.
type RouterFlow struct {
	End        time.Time `json:"end"`
	Start      time.Time `json:"start"`
	Proto      uint8     `json:"proto"`
	Host       string    `json:"host"`
	HostPort   uint16    `json:"hostPort"`
	Remote     string    `json:"remote"`
	RemotePort uint16    `json:"remotePort"`
	App        string    `json:"app"`
	Category   string    `json:"category"`
	Country    string    `json:"country"`
	Org        string    `json:"org"`
	Rx         uint64    `json:"rx"`
	Tx         uint64    `json:"tx"`
	Packets    uint64    `json:"packets"`
}

// Row is a flow as stored.
func (f Flow) Row() RouterFlow {
	return RouterFlow{End: f.End.UTC(), Start: f.Start.UTC(), Proto: f.Proto, Host: f.Host.String(), HostPort: f.HostPort,
		Remote: f.Remote.String(), RemotePort: f.RemotePort, App: f.App, Category: f.Category, Country: f.Country,
		Org: f.Org, Rx: f.Rx, Tx: f.Tx, Packets: f.Packets}
}

// Matches is whether a flow answers a search.
func (q FlowQuery) Matches(f RouterFlow) bool {
	return (q.Host == "" || f.Host == q.Host) && (q.Remote == "" || f.Remote == q.Remote) &&
		(q.App == "" || f.App == q.App) && (q.Country == "" || f.Country == q.Country) &&
		(q.From.IsZero() || !f.End.Before(q.From)) && (q.To.IsZero() || f.End.Before(q.To))
}

// keyOf is a row's value for a dimension.
func keyOf(r Agg, d Dim) string {
	switch d {
	case DimApp:
		return r.App
	case DimCategory:
		return r.Category
	case DimHost:
		return r.Host
	}
	return r.Country
}

// matches is whether a row is inside a query's filters and range.
func (q Query) matches(r Agg) bool {
	return (q.Host == "" || r.Host == q.Host) && (q.App == "" || r.App == q.App) &&
		(q.Country == "" || r.Country == q.Country) &&
		(q.From.IsZero() || !r.TS.Before(q.From)) && (q.To.IsZero() || r.TS.Before(q.To))
}

// TopOf answers a Query from rows in memory: the Live tab, and the reference
// the backends are tested against.
func TopOf(rows []Agg, q Query) []Top {
	by := map[string]*Top{}
	for _, r := range rows {
		if !q.matches(r) {
			continue
		}
		k := keyOf(r, q.Dim)
		t := by[k]
		if t == nil {
			t = &Top{Key: k}
			by[k] = t
		}
		t.Rx += r.Rx
		t.Tx += r.Tx
		t.Flows += r.Flows
	}
	out := make([]Top, 0, len(by))
	for _, t := range by {
		out = append(out, *t)
	}
	SortTop(out)
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out
}

// SortTop puts the most bytes first, then by key.
func SortTop(t []Top) {
	sort.Slice(t, func(i, j int) bool {
		a, b := t[i].Rx+t[i].Tx, t[j].Rx+t[j].Tx
		if a != b {
			return a > b
		}
		return t[i].Key < t[j].Key
	})
}

// SeriesOf answers a series from rows in memory, as TopOf does a Query.
func SeriesOf(rows []Agg, q Query, step time.Duration, keys []string) []Point {
	var raw []Point
	for _, r := range rows {
		if q.matches(r) {
			raw = append(raw, Point{TS: r.TS.Truncate(step), Key: keyOf(r, q.Dim), Rx: r.Rx, Tx: r.Tx})
		}
	}
	return Fold(raw, keys)
}

// Fold puts every point whose key is not one of `keys` under Other, adding up
// what then shares a time and key, in time order: a backend returns every
// group per step and this makes it the series asked for.
func Fold(points []Point, keys []string) []Point {
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	type pk struct {
		ts  int64
		key string
	}
	by := map[pk]*Point{}
	for _, p := range points {
		if !want[p.Key] {
			p.Key = Other
		}
		k := pk{p.TS.Unix(), p.Key}
		if q := by[k]; q != nil {
			q.Rx += p.Rx
			q.Tx += p.Tx
			continue
		}
		c := p
		c.TS = c.TS.UTC()
		by[k] = &c
	}
	out := make([]Point, 0, len(by))
	for _, p := range by {
		out = append(out, *p)
	}
	SortPoints(out)
	return out
}

// SortPoints orders a series by time, then key.
func SortPoints(p []Point) {
	sort.Slice(p, func(i, j int) bool {
		if !p[i].TS.Equal(p[j].TS) {
			return p[i].TS.Before(p[j].TS)
		}
		return p[i].Key < p[j].Key
	})
}

// StepFor is the step a range is drawn in: about 120 points, on a round step.
func StepFor(from, to time.Time) time.Duration {
	span := to.Sub(from)
	for _, s := range []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour, 24 * time.Hour} {
		if span/s <= 180 {
			return s
		}
	}
	return 7 * 24 * time.Hour
}
