package session

// THE ROUTER'S OFFLINE THRESHOLD REACHES ITS CPU AND PING-LOSS RULES (2026-10-22).
//
// `connDownThresholdSec` is resolved as the offline debounce resolves it, carried
// on every alert.Router the session builds, and swapped in place on a save, so
// a change to it applies without a restart.

import "testing"

func TestTheAlertHoldIsTheRoutersOfflineThreshold(t *testing.T) {
	for _, c := range []struct {
		why, field string
		want       int64
	}{
		{"absent is the 30 s default", ``, 30_000},
		{"a value is used", `,"connDownThresholdSec":45`, 45_000},
		{"a deliberate 0 reacts at once", `,"connDownThresholdSec":0`, 0},
	} {
		m, _ := sessionWithRecord(t, `[{"id":"r1","label":"lab","host":"198.51.100.77",
		  "port":8728,"username":"u","password":"","alertsEnabled":true`+c.field+`}]`)
		r, _, ok := m.AlertRouter("r1")
		if !ok || r.HoldMs != c.want {
			t.Errorf("%s: HoldMs = %d, want %d", c.why, r.HoldMs, c.want)
		}
		m.ApplyAlertHold("r1", 60_000)
		if r, _, _ := m.AlertRouter("r1"); r.HoldMs != 60_000 {
			t.Errorf("%s: after ApplyAlertHold the live session holds %d, want 60000", c.why, r.HoldMs)
		}
		m.ApplyAlertHold("no-such-router", 1) // no session is not an error
		m.Release("r1")
		m.Shutdown()
	}
}
