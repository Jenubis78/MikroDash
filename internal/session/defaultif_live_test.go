package session

// A ROUTER EDIT'S WAN INTERFACE REACHES THE LIVE SESSION (issue #158).
//
// The traffic collector is given the record's `defaultIf` once, in Acquire,
// and both the WAN badge and every new viewer's default graph read it from
// there. Without ApplyDefaultIf a changed WAN stayed on the old interface
// until the session was rebuilt, which for a router held for alerting or
// recording meant a restart.

import "testing"

const wanRecord = `[{"id":"r1","label":"lab","host":"198.51.100.77","port":8728,
  "username":"u","password":"","defaultIf":"ether2","alertsEnabled":true}]`

func TestApplyDefaultIfReachesALiveSession(t *testing.T) {
	m, s := sessionWithRecord(t, wanRecord)
	defer m.Shutdown()
	defer m.Release("r1")
	if got := s.Traffic().DefaultIf(); got != "ether2" {
		t.Fatalf("the session starts on %q, want the record's ether2", got)
	}

	old, moved := m.ApplyDefaultIf("r1", "pppoe-out1")
	if !moved || old != "ether2" {
		t.Fatalf("ApplyDefaultIf = (%q, %v), want (ether2, true)", old, moved)
	}
	if got := s.Traffic().DefaultIf(); got != "pppoe-out1" {
		t.Errorf("after the edit the live session's WAN is %q, want pppoe-out1: the badge "+
			"and the default graph stay on the old interface until a restart", got)
	}

	if _, moved := m.ApplyDefaultIf("r1", "pppoe-out1"); moved {
		t.Error("re-applying the same WAN reported a move, which would shuffle every viewer on each save")
	}
	if _, moved := m.ApplyDefaultIf("r1", ""); moved {
		t.Error("an empty WAN was applied; the edit path resolves a fallback and never sends one")
	}
	if _, moved := m.ApplyDefaultIf("no-such-router", "ether3"); moved {
		t.Error("a router with no session reported a move")
	}
}

// CONTROL: a rebuilt session reads the edited record, so the record write was
// never the problem; only the live session was stale.
func TestARebuiltSessionReadsTheEditedWan(t *testing.T) {
	m, _ := sessionWithRecord(t, wanRecord)
	defer m.Shutdown()
	if err := m.store.UpdateRouter("r1", map[string]any{"defaultIf": "pppoe-out1"}); err != nil {
		t.Fatal(err)
	}
	m.CloseNow("r1")
	s2, err := m.Acquire("r1")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Release("r1")
	if got := s2.Traffic().DefaultIf(); got != "pppoe-out1" {
		t.Errorf("a rebuilt session reads %q, want pppoe-out1", got)
	}
}
