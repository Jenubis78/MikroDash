package ips

import (
	"net/netip"
	"strings"
	"testing"

	"mikrodash/internal/routeros"
)

var sensor = netip.MustParseAddr("172.31.255.2")

func opsOf(p Plan) []string {
	var out []string
	for _, s := range p.Steps {
		out = append(out, s.Op+" "+s.Menu+" "+s.ID)
	}
	return out
}

func TestAnEmptyRouterGetsEveryRuleAboveTheOperators(t *testing.T) {
	rows := map[string][]routeros.Reply{
		"/ip/firewall/raw": {{".id": "*7", "chain": "prerouting", "action": "accept", "comment": "theirs"}},
	}
	p := PlanRouter(sensor, DefaultSniffBytes, rows, nil)
	if len(p.Steps) != 4 {
		t.Fatalf("steps: %v", opsOf(p))
	}
	for _, s := range p.Steps {
		if s.Op != "add" {
			t.Errorf("%+v: want an add", s)
		}
		if s.Menu == "/ip/firewall/raw" && s.Args["place-before"] != "*7" {
			t.Errorf("a raw rule must go above the operator's accept: %+v", s)
		}
		if s.Menu == "/ip/firewall/mangle" && s.Args["place-before"] != "" {
			t.Errorf("an empty mangle table has nothing to go above: %+v", s)
		}
	}
	m := p.Steps[0]
	if m.Args["sniff-target"] != "172.31.255.2" || m.Args["connection-bytes"] != "0-20000" ||
		m.Args["src-address"] != "!172.31.255.2" || !strings.HasPrefix(m.Args["comment"], Marker) {
		t.Errorf("the mangle rule: %+v", m.Args)
	}
	cmd := m.Cmd()
	if cmd.Path != "/ip/firewall/mangle/add" || cmd.Args[0] != "=action=sniff-tzsp" {
		t.Errorf("as a sentence: %+v", cmd)
	}
}

func TestARouterInStepNeedsNothingAndAStaleRowIsCorrected(t *testing.T) {
	rows := map[string][]routeros.Reply{}
	for i, w := range Want(sensor, DefaultSniffBytes) {
		r := routeros.Reply{".id": "*" + string(rune('a'+i))}
		for k, v := range w.Props {
			r[k] = v
		}
		rows[w.Menu] = append(rows[w.Menu], r)
	}
	if p := PlanRouter(sensor, DefaultSniffBytes, rows, nil); len(p.Steps) != 0 {
		t.Fatalf("a router in step: %v", opsOf(p))
	}
	rows["/ip/firewall/mangle"][0]["connection-bytes"] = "0-5000"
	rows["/ip/firewall/raw"][1]["disabled"] = "true"
	p := PlanRouter(sensor, DefaultSniffBytes, rows, nil)
	if len(p.Steps) != 2 || p.Steps[0].Op != "set" || p.Steps[0].Args["connection-bytes"] != "0-20000" ||
		p.Steps[1].Args["disabled"] != "no" {
		t.Fatalf("corrections: %+v", p.Steps)
	}
	if c := p.Steps[0].Cmd(); c.Path != "/ip/firewall/mangle/set" || c.Args[0] != "=.id=*a" {
		t.Errorf("a set names its row: %+v", c)
	}
}

func TestRemovalTouchesOnlyWhatTheIPSOwns(t *testing.T) {
	rows := map[string][]routeros.Reply{
		"/ip/firewall/mangle": {{".id": "*1", "comment": Marker + ": copy to the sensor"}, {".id": "*2", "comment": "theirs"}},
		"/ip/firewall/raw":    {{".id": "*3", "comment": Marker + ": blocked servers"}, {".id": "*4", "comment": "MikroDash list #1"}},
	}
	p := PlanRouter(netip.Addr{}, 0, rows, nil)
	got := strings.Join(opsOf(p), ", ")
	if got != "remove /ip/firewall/mangle *1, remove /ip/firewall/raw *3" {
		t.Fatalf("removal: %s", got)
	}
}

func TestAFasttrackRuleWithoutABytesLimitWarns(t *testing.T) {
	filter := []routeros.Reply{{".id": "*9", "action": "fasttrack-connection", "connection-state": "established,related"}}
	if p := PlanRouter(sensor, 30000, nil, filter); len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "connection-bytes=30000-0") {
		t.Errorf("warnings: %v", p.Warnings)
	}
	filter[0]["connection-bytes"] = "30000-0"
	if p := PlanRouter(sensor, 30000, nil, filter); len(p.Warnings) != 0 {
		t.Errorf("a limited fasttrack: %v", p.Warnings)
	}
}

func TestTheListEntryTimesOutAndSaysWhoMadeIt(t *testing.T) {
	args := ListEntryArgs(Decision{RuleID: 4, List: BlockList, Target: "203.0.113.7", TimeoutMin: 90}, "BitTorrent")
	want := []string{"=list=" + BlockList, "=address=203.0.113.7", "=timeout=90m", "=comment=" + Marker + " #4 BitTorrent"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Errorf("args: %v", args)
	}
}

func TestTheContainerScriptNamesTheTokenAndTheGateway(t *testing.T) {
	s := ContainerScript(ScriptParams{Token: "0123456789abcdef0123", Sensor: sensor, Disk: "/usb1/"})
	for _, want := range []string{
		"address=172.31.255.2/30 gateway=172.31.255.1",
		"/ip/address/add address=172.31.255.1/30",
		"registry-url=https://ghcr.io tmpdir=usb1/tmp",
		`cmd="--token 0123456789abcdef0123"`,
		"remote-image=" + DefaultImage,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the script lacks %q:\n%s", want, s)
		}
	}
}
