package traffic

import (
	"net/netip"
	"strings"
	"testing"

	"mikrodash/internal/routeros"
)

var params = PlanParams{Collector: netip.MustParseAddr("192.168.11.5"), Port: 2055}

func TestAFreshRouterGetsTrafficFlowATargetAndNothingElse(t *testing.T) {
	tf := routeros.Reply{"enabled": "false", "interfaces": "all", "active-flow-timeout": "30m", "inactive-flow-timeout": "15s"}
	ipfix := routeros.Reply{"bytes": "true", "nat-src-address": "false", "nat-dst-address": "true"}
	p := RouterPlan(params, tf, nil, ipfix, nil, false)
	if len(p.Steps) != 3 {
		t.Fatalf("%+v", p.Steps)
	}
	s := p.Steps[0]
	if s.Menu != "/ip/traffic-flow" || s.Args["enabled"] != "yes" || s.Args["active-flow-timeout"] != "1m" ||
		len(s.Args) != 2 {
		t.Errorf("only what differs: %+v", s.Args)
	}
	if cmd := s.Cmd(); cmd.Path != "/ip/traffic-flow/set" || strings.Contains(strings.Join(cmd.Args, " "), ".id") {
		t.Errorf("a one-row menu is set without an id: %+v", cmd)
	}
	if a := p.Steps[1].Args; p.Steps[1].Op != "add" || a["dst-address"] != "192.168.11.5" || a["port"] != "2055" || a["version"] != "ipfix" {
		t.Errorf("target: %+v", p.Steps[1])
	}
	if f := p.Steps[2].Args; len(f) != 1 || f["nat-src-address"] != "yes" {
		t.Errorf("fields: %+v", f)
	}
}

func TestARouterInStepNeedsNothingAndOthersAreWarnedAbout(t *testing.T) {
	tf := routeros.Reply{"enabled": "true", "interfaces": "all", "active-flow-timeout": "1m", "inactive-flow-timeout": "15s"}
	targets := []routeros.Reply{{".id": "*1", "dst-address": "192.168.11.5", "port": "2055", "version": "IPFIX"}}
	if p := RouterPlan(params, tf, targets, routeros.Reply{"bytes": "true"}, nil, false); len(p.Steps) != 0 || len(p.Warnings) != 0 {
		t.Errorf("in step: %+v", p)
	}
	tf["active-flow-timeout"] = "30m"
	targets = append(targets, routeros.Reply{".id": "*2", "dst-address": "10.0.0.9", "port": "9995", "version": "9"})
	filter := []routeros.Reply{{".id": "*F", "action": "fasttrack-connection"}}
	p := RouterPlan(params, tf, targets, nil, filter, false)
	if len(p.Steps) != 1 || len(p.Warnings) != 2 {
		t.Errorf("%+v", p)
	}
}

func TestRemoveTakesOnlyMikroDashsTargetAndLeavesTrafficFlowToOthers(t *testing.T) {
	tf := routeros.Reply{"enabled": "true"}
	mine := routeros.Reply{".id": "*1", "dst-address": "192.168.11.5", "port": "2055"}
	other := routeros.Reply{".id": "*2", "dst-address": "10.0.0.9", "port": "9995"}
	if p := RouterPlan(params, tf, []routeros.Reply{mine, other}, nil, nil, true); len(p.Steps) != 1 || p.Steps[0].ID != "*1" {
		t.Errorf("with another collector: %+v", p.Steps)
	}
	if p := RouterPlan(params, tf, []routeros.Reply{mine}, nil, nil, true); len(p.Steps) != 2 || p.Steps[1].Args["enabled"] != "no" {
		t.Errorf("alone: %+v", p.Steps)
	}
}

func TestRouterOSDurationsRead(t *testing.T) {
	for s, want := range map[string]int{"1m": 60, "30m": 1800, "15s": 15, "1h30m": 5400, "00:01:00": 60, "60": 60, "": -1, "x": -1} {
		if got := seconds(s); got != want {
			t.Errorf("%q: %d, want %d", s, got, want)
		}
	}
}
