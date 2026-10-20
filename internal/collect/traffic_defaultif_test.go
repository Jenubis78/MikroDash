package collect

// A RUNNING TRAFFIC COLLECTOR FOLLOWS A NEW WAN INTERFACE (issue #158).

import (
	"testing"

	"mikrodash/internal/hub"
	"mikrodash/internal/routeros"
)

type offlineReader struct{}

func (offlineReader) Do(routeros.Cmd) ([]routeros.Reply, error) { return nil, nil }
func (offlineReader) Connected() bool                           { return false }

func trafficRow(name string) routeros.Reply {
	return routeros.Reply{"name": name, "rx-bits-per-second": "1000", "tx-bits-per-second": "2000"}
}

func TestSetDefaultIfMovesTheBadge(t *testing.T) {
	tr := NewTraffic(offlineReader{}, hub.Relay{}, "ether2", 1)
	tr.onPacket(trafficRow("ether2"))
	if w := tr.LastWan(); w == nil || w.IfName != "ether2" {
		t.Fatalf("the badge starts as %+v, want ether2", w)
	}

	if !tr.SetDefaultIf("pppoe-out1") {
		t.Fatal("SetDefaultIf reported no change")
	}
	if got := tr.DefaultIf(); got != "pppoe-out1" {
		t.Errorf("DefaultIf = %q, want pppoe-out1", got)
	}
	// The old reading describes the old interface; a page opening now would be
	// shown "ether2" until the new one's first sample.
	if w := tr.LastWan(); w != nil {
		t.Errorf("the badge still holds %+v after the WAN moved", *w)
	}
	// The old interface no longer feeds the badge, the new one does.
	tr.onPacket(trafficRow("ether2"))
	if w := tr.LastWan(); w != nil {
		t.Errorf("a sample for the old WAN set the badge: %+v", *w)
	}
	tr.onPacket(trafficRow("pppoe-out1"))
	if w := tr.LastWan(); w == nil || w.IfName != "pppoe-out1" {
		t.Errorf("the badge is %+v after a pppoe-out1 sample, want pppoe-out1", w)
	}
	// And the stream will carry it.
	tr.mu.Lock()
	names := tr.ifaceListLocked()
	tr.mu.Unlock()
	if len(names) != 1 || names[0] != "pppoe-out1" {
		t.Errorf("the stream covers %v, want [pppoe-out1]", names)
	}

	if tr.SetDefaultIf("pppoe-out1") || tr.SetDefaultIf("") {
		t.Error("the same WAN, or none, reported a change")
	}
}
