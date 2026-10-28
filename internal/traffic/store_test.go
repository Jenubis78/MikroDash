package traffic

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// sample is three minutes of two routers' rows, ending a few minutes ago.
func sample(now time.Time) map[string][]Agg {
	m := now.Truncate(time.Minute).Add(-5 * time.Minute)
	row := func(i int, host, app, cat, cc string, rx, tx, fl uint64) Agg {
		return Agg{TS: m.Add(time.Duration(i) * time.Minute).UTC(), Host: host, App: app, Category: cat, Country: cc, Rx: rx, Tx: tx, Flows: fl}
	}
	return map[string][]Agg{
		"r1": {
			row(0, "192.168.11.20", "YouTube", "Media", "US", 9000, 100, 2),
			row(0, "192.168.11.21", "Netflix", "Video", "NL", 5000, 50, 1),
			row(1, "192.168.11.20", "YouTube", "Media", "US", 7000, 70, 1),
			row(1, "192.168.11.20", "Steam", "Game", "DE", 20000, 300, 3),
			row(2, "192.168.11.22", "Unknown", "udp/53", "", 10, 10, 1),
		},
		"r2": {row(0, "10.0.0.5", "YouTube", "Media", "US", 1, 1, 1)},
	}
}

// checkBackend holds a backend to the answers TopOf and SeriesOf give from
// the same rows, for every dimension, with and without a filter.
func checkBackend(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now()
	data := sample(now)
	for rid, rows := range data {
		if err := s.Write(ctx, rid, rows, nil); err != nil {
			t.Fatalf("%s write: %v", s.Backend(), err)
		}
	}
	from, to := now.Add(-time.Hour), now.Add(time.Minute)
	for _, d := range []Dim{DimApp, DimCategory, DimHost, DimCountry} {
		for _, q := range []Query{
			{RouterID: "r1", Dim: d, From: from, To: to},
			{RouterID: "r1", Dim: d, Host: "192.168.11.20", From: from, To: to, Limit: 1},
		} {
			got, err := s.Top(ctx, q)
			if err != nil {
				t.Fatalf("%s top %s: %v", s.Backend(), d, err)
			}
			if want := TopOf(data["r1"], q); !reflect.DeepEqual(got, want) {
				t.Errorf("%s top %s host=%q:\n got %+v\nwant %+v", s.Backend(), d, q.Host, got, want)
			}
		}
	}
	q := Query{RouterID: "r1", Dim: DimApp, From: from, To: to}
	got, err := s.Series(ctx, q, time.Minute, []string{"YouTube"})
	if err != nil {
		t.Fatalf("%s series: %v", s.Backend(), err)
	}
	if want := SeriesOf(data["r1"], q, time.Minute, []string{"YouTube"}); !reflect.DeepEqual(got, want) {
		t.Errorf("%s series:\n got %+v\nwant %+v", s.Backend(), got, want)
	}
}

func TestSQLiteAnswersAsTheRowsInMemoryDo(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	checkBackend(t, s)
	if _, err := s.Flows(context.Background(), FlowQuery{}); err != ErrNoFlowHistory {
		t.Errorf("flows: %v", err)
	}
}

// Rolling up keeps every byte: an hour of minutes is one hour row with their
// sums, rolled once however often Maintain runs, and the minutes age out.
func TestSQLiteRollsFinishedHoursUpOnceAndAgesMinutesOut(t *testing.T) {
	ctx := context.Background()
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := time.Now().Add(-3 * 24 * time.Hour).Truncate(time.Hour)
	rows := []Agg{
		{TS: h, Host: "a", App: "YouTube", Country: "US", Rx: 10, Tx: 1, Flows: 1},
		{TS: h.Add(59 * time.Minute), Host: "a", App: "YouTube", Country: "US", Rx: 5, Tx: 2, Flows: 1},
		{TS: h.Add(time.Hour), Host: "a", App: "YouTube", Country: "US", Rx: 100, Tx: 0, Flows: 1},
	}
	if err := s.Write(ctx, "r1", rows, nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for range 3 {
		if err := s.Maintain(ctx, now); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM traffic_min`).Scan(&n)
	if n != 0 {
		t.Errorf("%d minute rows older than %v kept", n, MinuteKeep)
	}
	got, err := s.Top(ctx, Query{RouterID: "r1", Dim: DimApp, From: h.Add(-time.Hour), To: now})
	if err != nil || len(got) != 1 || got[0].Rx != 115 || got[0].Tx != 3 || got[0].Flows != 3 {
		t.Errorf("from the hour table: %v %+v", err, got)
	}
	var hours int
	s.db.QueryRow(`SELECT COUNT(*) FROM traffic_hour`).Scan(&hours)
	if hours != 2 {
		t.Errorf("%d hour rows, want 2", hours)
	}
}

// MIKRODASH_TEST_CLICKHOUSE=http://127.0.0.1:8123 runs the same checks
// against a real server; without it they are skipped, and say so.
func TestClickHouseAnswersAsTheRowsInMemoryDo(t *testing.T) {
	url := os.Getenv("MIKRODASH_TEST_CLICKHOUSE")
	if url == "" {
		t.Skip("MIKRODASH_TEST_CLICKHOUSE is not set")
	}
	ctx := context.Background()
	db := "mikrodash_test_" + time.Now().Format("150405")
	c, err := OpenClickHouse(ctx, ClickHouseConfig{URL: url, Database: db, FlowDays: 7}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.do(ctx, `DROP DATABASE IF EXISTS `+db, nil, nil)
	checkBackend(t, c)
	now := time.Now().UTC().Truncate(time.Millisecond)
	flows := []RouterFlow{
		{End: now, Start: now.Add(-time.Minute), Proto: 6, Host: "192.168.11.20", HostPort: 51544, Remote: "142.250.1.1",
			RemotePort: 443, App: "YouTube", Category: "Media", Country: "US", Org: "Google", Rx: 900, Tx: 100, Packets: 12},
		{End: now.Add(-time.Second), Start: now.Add(-time.Minute), Proto: 17, Host: "192.168.11.21", HostPort: 5353,
			Remote: "9.9.9.9", RemotePort: 53, App: "Unknown", Category: "udp/53", Rx: 80},
	}
	if err := c.Write(ctx, "r1", nil, flows); err != nil {
		t.Fatal(err)
	}
	got, err := c.Flows(ctx, FlowQuery{RouterID: "r1", Host: "192.168.11.20", From: now.Add(-time.Hour), To: now.Add(time.Hour)})
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], flows[0]) {
		t.Errorf("flows: %v\n got %+v\nwant %+v", err, got, flows[:1])
	}
}
