package traffic

// The Live tab's last seconds, when the sensor counts every packet: its
// counts arrive every few seconds, so Live can be a rate over the last
// WindowSpan rather than over the last finished minute.

import "time"

// WindowStep is a bucket; WindowSpan is how far back Live adds up.
const (
	WindowStep = 5 * time.Second
	WindowSpan = 30 * time.Second
)

type windowBucket struct {
	at   int64 // the bucket's start, unix seconds
	rows map[aggKey]*Agg
}

// Window keeps the last WindowSpan of flows in WindowStep buckets.
type Window struct {
	buckets []windowBucket
}

// Add counts one flow in the bucket of `now`.
func (w *Window) Add(f Flow, now time.Time) {
	at := now.Truncate(WindowStep).Unix()
	if n := len(w.buckets); n == 0 || w.buckets[n-1].at != at {
		w.buckets = append(w.buckets, windowBucket{at: at, rows: map[aggKey]*Agg{}})
		w.trim(now)
	}
	b := w.buckets[len(w.buckets)-1]
	k := aggKey{0, f.Host.String(), f.App, f.Category, f.Country}
	r := b.rows[k]
	if r == nil {
		r = &Agg{Host: k.host, App: f.App, Category: f.Category, Country: f.Country}
		b.rows[k] = r
	}
	r.Rx += f.Rx
	r.Tx += f.Tx
	if f.Tx > 0 || f.Rx > 0 {
		r.Flows++
	}
}

func (w *Window) trim(now time.Time) {
	cut := now.Add(-WindowSpan).Truncate(WindowStep).Unix()
	i := 0
	for i < len(w.buckets) && w.buckets[i].at < cut {
		i++
	}
	w.buckets = w.buckets[i:]
}

// Rows is the last WindowSpan, the bucket still filling left out, added up
// per (host, application, category, country), and the seconds it covers.
func (w *Window) Rows(now time.Time) ([]Agg, int) {
	w.trim(now)
	cur := now.Truncate(WindowStep).Unix()
	sum := map[aggKey]*Agg{}
	secs := 0
	for _, b := range w.buckets {
		if b.at >= cur {
			continue
		}
		secs += int(WindowStep / time.Second)
		for k, r := range b.rows {
			s := sum[k]
			if s == nil {
				c := *r
				c.TS = time.Unix(b.at, 0).UTC()
				sum[k] = &c
				continue
			}
			s.Rx += r.Rx
			s.Tx += r.Tx
			s.Flows += r.Flows
		}
	}
	out := make([]Agg, 0, len(sum))
	for _, r := range sum {
		out = append(out, *r)
	}
	return out, secs
}
