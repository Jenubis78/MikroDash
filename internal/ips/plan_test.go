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
		"root-dir=usb1/mikrodash-dpi",
		`cmd="--token 0123456789abcdef0123"`,
		"remote-image=" + DefaultImage,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the script lacks %q:\n%s", want, s)
		}
	}
}

func TestASensorOnARouterNetworkJoinsItsBridge(t *testing.T) {
	addrs := []routeros.Reply{
		{"address": "192.168.11.1/24", "interface": "bridge"},
		{"address": "192.168.20.1/24", "interface": "vlan20"},
		{"address": "192.168.30.1/24", "interface": "vlan30"},
		{"address": "203.0.113.2/30", "interface": "ether1"},
		{"address": "10.9.9.1/24", "interface": "bridge", "disabled": "true"},
	}
	bridges := []routeros.Reply{{"name": "bridge", "vlan-filtering": "true"}, {"name": "br-old", "vlan-filtering": "false"}}
	vlans := []routeros.Reply{{"name": "vlan20", "interface": "bridge", "vlan-id": "20"},
		{"name": "vlan30", "interface": "br-old", "vlan-id": "30"}}
	nets := Networks(addrs, bridges, vlans)
	if len(nets) != 4 {
		t.Fatalf("networks: %+v", nets)
	}
	if nets[1].VLAN != 20 || nets[1].Bridge != "bridge" || nets[1].Why != "" || nets[2].Why == "" || nets[3].Why == "" {
		t.Errorf("attachability: %+v", nets)
	}
	find := func(a, iface string) (*LANAttach, error) {
		var addr netip.Addr
		if a != "" {
			addr = netip.MustParseAddr(a)
		}
		return FindLAN(addr, iface, nets)
	}

	l, err := find("192.168.11.250", "")
	if err != nil || l == nil || l.Bridge != "bridge" || l.Gateway.String() != "192.168.11.1" || l.Bits != 24 || l.PVID != 0 {
		t.Fatalf("the bridge's own network: %+v %v", l, err)
	}
	s := ContainerScript(ScriptParams{Token: "0123456789abcdef0123", Sensor: netip.MustParseAddr("192.168.11.250"), LAN: l})
	for _, want := range []string{"address=192.168.11.250/24 gateway=192.168.11.1",
		"/interface/bridge/port/add bridge=bridge interface=veth-mikrodash-dpi comment="} {
		if !strings.Contains(s, want) {
			t.Errorf("the script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "\n/container/config/set") {
		t.Errorf("the script must not change the router-wide container settings:\n%s", s)
	}
	for _, not := range []string{"br-mikrodash-dpi", "/ip/address/add"} {
		if strings.Contains(s, not) {
			t.Errorf("a sensor on an existing network needs no %q:\n%s", not, s)
		}
	}

	// THE VLAN CHOSEN BY NAME, AND BY DHCP: no address, the VLAN as the pvid.
	l, err = find("", "vlan20")
	if err != nil || l.Bridge != "bridge" || l.PVID != 20 {
		t.Fatalf("VLAN 20 chosen, by DHCP: %+v %v", l, err)
	}
	s = ContainerScript(ScriptParams{LAN: l, DHCP: true})
	if !strings.Contains(s, "/interface/veth/add name=veth-mikrodash-dpi dhcp=yes ") ||
		!strings.Contains(s, "interface=veth-mikrodash-dpi pvid=20 ") || strings.Contains(s, "gateway=") {
		t.Errorf("a DHCP sensor in VLAN 20:\n%s", s)
	}
	if _, err := find("192.168.11.250", "vlan20"); err == nil || !strings.Contains(err.Error(), "not in 192.168.20.0/24") {
		t.Errorf("an address outside the chosen network: %v", err)
	}
	if _, err := find("", "ether9"); err == nil {
		t.Error("a network the router does not have must be refused")
	}
	for addr, why := range map[string]string{
		"192.168.30.9":   "does not filter VLANs",
		"203.0.113.1":    "not a bridge",
		"192.168.11.1":   "router's own address",
		"192.168.11.255": "not a host address",
		"192.168.11.0":   "not a host address",
	} {
		if _, err := find(addr, ""); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: %v, want %q", addr, err, why)
		}
	}
	if l, err := find("172.31.255.2", ""); l != nil || err != nil {
		t.Errorf("an address outside every network gets its own /30: %+v %v", l, err)
	}
}

func TestTheLeaseIsReadFromTheVeth(t *testing.T) {
	for in, want := range map[string]string{"192.168.11.57/24": "192.168.11.57", "192.168.11.57": "192.168.11.57", "": "invalid IP"} {
		if got := LeasedAddress(routeros.Reply{"dhcp-address": in}).String(); got != want {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
}
