package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mikrodash/internal/db"
	"mikrodash/internal/store"
	"mikrodash/internal/traffic"
)

// The password is made once, random, readable by nobody else, and kept.
func TestTheStacksPasswordIsMadeOnceAndKept(t *testing.T) {
	c := clickHouseStack{URL: "http://clickhouse:8123", SecretFile: filepath.Join(t.TempDir(), "secret", "password")}
	if err := c.ensureSecret(); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(c.SecretFile)
	info, _ := os.Stat(c.SecretFile)
	if len(first) != 48 || info.Mode().Perm() != 0o600 {
		t.Fatalf("%q %v", first, info.Mode())
	}
	_ = c.ensureSecret()
	again, _ := os.ReadFile(c.SecretFile)
	if string(again) != string(first) {
		t.Error("the password changed: ClickHouse would no longer accept it")
	}
	cfg, err := c.config(30)
	if err != nil || cfg.Password != string(first) || cfg.User != stackCHUser || cfg.Database != stackCHDatabase {
		t.Errorf("%+v %v", cfg, err)
	}
	if _, err := (clickHouseStack{}).config(30); err == nil {
		t.Error("a stack without ClickHouse has no config")
	}
}

// stackServer is a server with a data directory and the stack's ClickHouse at url.
func stackServer(t *testing.T, url string) *Server {
	t.Helper()
	dir := t.TempDir()
	d, err := db.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{auditDB: d, store: st, chStack: clickHouseStack{URL: url, SecretFile: filepath.Join(dir, "chs", "password")}}
}

// An install that never chose a backend takes the stack's ClickHouse, and
// does not wait for it: one not up yet is tried again, the rows waiting.
func TestANewInstallTakesTheStacksClickHouseWithoutWaitingForIt(t *testing.T) {
	s := stackServer(t, "http://127.0.0.1:9") // nothing listens: not up yet
	start := time.Now()
	e := s.buildTraffic()
	defer e.Stop()
	if time.Since(start) > 2*time.Second {
		t.Errorf("start waited %v for the backend", time.Since(start))
	}
	if set, _ := s.auditDB.TrafficSettingsGet(); set.Backend != trafficBackendStack || !set.Saved {
		t.Fatalf("%+v", set)
	}
	if _, err := os.Stat(s.chStack.SecretFile); err != nil {
		t.Errorf("no password file: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, why := e.currentStore()
		if why != "opening" && why != "no backend is open" {
			if !strings.Contains(why, "clickhouse") {
				t.Errorf("why: %q", why)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("still opening")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A backend chosen on purpose is not taken over.
	s2 := stackServer(t, "http://127.0.0.1:9")
	_ = s2.auditDB.SaveTrafficSettings(db.TrafficSettings{Backend: "sqlite", Port: 2055, FlowDays: 90})
	e2 := s2.buildTraffic()
	defer e2.Stop()
	if set, _ := s2.auditDB.TrafficSettingsGet(); set.Backend != "sqlite" {
		t.Errorf("a chosen SQLite was replaced: %+v", set)
	}
}

// With a real ClickHouse (MIKRODASH_TEST_CLICKHOUSE): the stack's opens, the
// SQLite history goes into it once, and the file is set aside.
func TestTheSQLiteHistoryMovesIntoTheStacksClickHouseOnce(t *testing.T) {
	url := os.Getenv("MIKRODASH_TEST_CLICKHOUSE")
	if url == "" {
		t.Skip("MIKRODASH_TEST_CLICKHOUSE is not set")
	}
	s := stackServer(t, url)
	// The history SQLite holds before the switch.
	old, err := traffic.OpenSQLite(filepath.Join(s.store.Dir, "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	// The ClickHouse outlives the test: a router of this run's own.
	rid := fmt.Sprintf("r-stack-%d", time.Now().UnixNano())
	if err := old.Write(context.Background(), rid, []traffic.Agg{
		{TS: now.Add(-10 * time.Minute), Host: "192.168.11.20", App: "YouTube", Country: "US", Rx: 5000, Tx: 50, Flows: 1},
		{TS: now.Add(-5 * time.Minute), Host: "192.168.11.21", App: "NetFlix", Country: "NL", Rx: 7000, Tx: 70, Flows: 2},
	}, nil); err != nil {
		t.Fatal(err)
	}
	old.Close()

	e := s.buildTraffic()
	defer e.Stop()
	var st traffic.Store
	for deadline := time.Now().Add(20 * time.Second); st == nil; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			_, why := e.currentStore()
			t.Fatalf("the stack's ClickHouse did not open: %s", why)
		}
		st, _ = e.currentStore()
	}
	var got []traffic.Top
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		got, _ = st.Top(context.Background(), traffic.Query{RouterID: rid, Dim: traffic.DimApp,
			From: now.Add(-time.Hour), To: now.Add(time.Hour)})
		if len(got) == 2 {
			break
		}
	}
	if len(got) != 2 || got[0].Key != "NetFlix" || got[0].Rx != 7000 || got[1].Rx != 5000 {
		t.Fatalf("imported: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(s.store.Dir, "traffic.db")); !os.IsNotExist(err) {
		t.Error("traffic.db is still there: it would be imported again")
	}
	matches, _ := filepath.Glob(filepath.Join(s.store.Dir, "traffic.db.imported-*"))
	if len(matches) == 0 {
		t.Error("the imported file was not kept")
	}
}
