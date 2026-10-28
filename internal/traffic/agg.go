package traffic

// Adding flows up by the minute: one row per (host, application, category,
// country) a minute, the unit both backends store.
//
// A record is counted in the minute it ENDED in: Traffic Flow exports a long
// connection once a minute (active-flow-timeout=1m), so each record covers at
// most the minute before it. A record arriving for a minute already taken is
// counted in the oldest minute still open rather than dropped.

import (
	"sort"
	"time"
)

// Agg is one row: what one host exchanged with one application, in one
// country, during one bucket.
type Agg struct {
	TS       time.Time `json:"ts"`
	Host     string    `json:"host"`
	App      string    `json:"app"`
	Category string    `json:"category"`
	Country  string    `json:"country"`
	Rx       uint64    `json:"rx"`
	Tx       uint64    `json:"tx"`
	// Flows is the connections that sent something in the bucket, counted on
	// the side that sent: a connection is two records a minute, one each way.
	Flows uint64 `json:"flows"`
}

type aggKey struct {
	minute                       int64
	host, app, category, country string
}

// Aggregator adds one router's flows up, a minute at a time.
type Aggregator struct {
	rows  map[aggKey]*Agg
	taken int64 // every minute before this one has been taken
	// Named and Total are the bytes that found an application, and all bytes,
	// since the aggregator started.
	Named, Total uint64
}

// NewAggregator is an empty aggregator.
func NewAggregator() *Aggregator { return &Aggregator{rows: map[aggKey]*Agg{}} }

// Add counts one flow.
func (a *Aggregator) Add(f Flow, now time.Time) {
	end := f.End
	if end.IsZero() || end.After(now) {
		end = now
	}
	m := end.Unix() / 60
	if m < a.taken {
		m = a.taken
	}
	k := aggKey{m, f.Host.String(), f.App, f.Category, f.Country}
	r := a.rows[k]
	if r == nil {
		r = &Agg{TS: time.Unix(m*60, 0).UTC(), Host: k.host, App: f.App, Category: f.Category, Country: f.Country}
		a.rows[k] = r
	}
	r.Rx += f.Rx
	r.Tx += f.Tx
	if f.Tx > 0 {
		r.Flows++
	}
	a.Total += f.Rx + f.Tx
	if f.Named {
		a.Named += f.Rx + f.Tx
	}
}

// Take removes and returns every minute that ended before `now`'s minute,
// oldest first.
func (a *Aggregator) Take(now time.Time) []Agg {
	cur := now.Unix() / 60
	out := []Agg{}
	for k, r := range a.rows {
		if k.minute < cur {
			out = append(out, *r)
			delete(a.rows, k)
		}
	}
	if cur > a.taken {
		a.taken = cur
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].TS.Equal(out[j].TS) {
			return out[i].TS.Before(out[j].TS)
		}
		return out[i].Rx+out[i].Tx > out[j].Rx+out[j].Tx
	})
	return out
}
