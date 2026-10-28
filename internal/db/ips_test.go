package db

import (
	"testing"

	"mikrodash/internal/ips"
)

func TestIPSRulesKeepTheirOrderAndCriteria(t *testing.T) {
	d := openTestDB(t)
	a, err := d.SaveIPSRule(ips.Rule{Name: "p2p", Enabled: true, Apps: []string{"BitTorrent"}, Action: ips.ActionBlock, TimeoutMin: 60})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := d.SaveIPSRule(ips.Rule{Name: "risky", Enabled: true, Risks: []string{"*"}, Clients: []string{"192.168.88.0/24"},
		Countries: []string{"CN"}, Action: ips.ActionLog})
	if err := d.OrderIPSRules([]int64{b, a}); err != nil {
		t.Fatal(err)
	}
	rules, err := d.IPSRules()
	if err != nil || len(rules) != 2 || rules[0].ID != b || rules[1].ID != a {
		t.Fatalf("order: %v %+v", err, rules)
	}
	if rules[0].Clients[0] != "192.168.88.0/24" || rules[0].Countries[0] != "CN" || rules[1].Apps[0] != "BitTorrent" || rules[1].Categories == nil {
		t.Errorf("criteria: %+v", rules)
	}
	rules[1].Enabled = false
	if _, err := d.SaveIPSRule(rules[1]); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteIPSRule(b); err != nil {
		t.Fatal(err)
	}
	if rules, _ := d.IPSRules(); len(rules) != 1 || rules[0].Enabled {
		t.Errorf("after an edit and a delete: %+v", rules)
	}
	if _, err := d.SaveIPSRule(ips.Rule{ID: 999, Name: "gone", Action: ips.ActionLog}); err == nil {
		t.Error("saving a rule that does not exist must fail")
	}
}

func TestIPSSensorsAndEventsRoundTrip(t *testing.T) {
	d := openTestDB(t)
	s := IPSSensor{RouterID: "r1", Address: "172.31.255.2", Token: `{"sealed":"x"}`, Enforce: true,
		SniffBytes: 20000, Protected: []string{"192.168.88.50"}, Disk: "usb1", Network: "vlan11", DHCP: true, EveryPacket: true}
	if err := d.SaveIPSSensor(s); err != nil {
		t.Fatal(err)
	}
	s.Enforce = false
	if err := d.SaveIPSSensor(s); err != nil {
		t.Fatal(err)
	}
	got, err := d.IPSSensors()
	if err != nil || len(got) != 1 || got[0].Enforce || got[0].Token != s.Token || got[0].Protected[0] != "192.168.88.50" ||
		got[0].Network != "vlan11" || !got[0].DHCP || !got[0].EveryPacket {
		t.Fatalf("sensors: %v %+v", err, got)
	}
	for i, ts := range []int64{100, 300, 200} {
		if _, err := d.InsertIPSEvent(IPSEvent{TS: ts, RouterID: "r1", RuleID: int64(i), Action: "block", Result: "listed",
			Risks: []string{"x"}}); err != nil {
			t.Fatal(err)
		}
	}
	r2, _ := d.InsertIPSEvent(IPSEvent{TS: 400, RouterID: "r2", Action: "log", Result: "monitor"})
	ev, err := d.IPSEvents("r1", 2)
	if err != nil || len(ev) != 2 || ev[0].TS != 300 || ev[1].TS != 200 || ev[0].Risks[0] != "x" || ev[0].Hits != 1 {
		t.Fatalf("events: %v %+v", err, ev)
	}
	if err := d.AddIPSEventHits(map[int64]int64{r2: 41}); err != nil {
		t.Fatal(err)
	}
	if ev, _ := d.IPSEvents("r2", 1); ev[0].Hits != 42 {
		t.Errorf("hits: %+v", ev)
	}
	// Trimming keeps the newest rows of that router only.
	if n, err := d.TrimIPSEvents("r1", 1); err != nil || n != 2 {
		t.Errorf("trimmed %d: %v", n, err)
	}
	if ev, _ := d.IPSEvents("r1", 10); len(ev) != 1 || ev[0].RuleID != 2 {
		t.Errorf("after trim: %+v", ev)
	}
	if ev, _ := d.IPSEvents("r2", 10); len(ev) != 1 {
		t.Errorf("another router's rows were trimmed: %+v", ev)
	}
	if err := d.DeleteIPSSensor("r1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.IPSSensors(); len(got) != 0 {
		t.Errorf("after delete: %+v", got)
	}
}

func TestIPSGeoKeepsTheChoiceAndTheLastApplySeparately(t *testing.T) {
	d := openTestDB(t)
	if g, err := d.IPSGeoOf("r1"); err != nil || g.Saved || len(g.Countries) != 0 || g.Direction != ips.GeoBoth || g.Mode != ips.GeoModeBlock {
		t.Fatalf("none chosen: %v %+v", err, g)
	}
	if err := d.SaveIPSGeo("r1", ips.GeoChoice{Mode: ips.GeoModeBlock, Direction: ips.GeoIn, Block: []string{"CN", "RU"},
		Allow: []string{"FR"}}); err != nil {
		t.Fatal(err)
	}
	if err := d.RecordIPSGeo("r1", 42, "applied", 1234); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveIPSGeo("r1", ips.GeoChoice{Mode: ips.GeoModeAllow, Direction: ips.GeoOut, Block: []string{"KP"},
		Allow: []string{"FR", "BE"}}); err != nil {
		t.Fatal(err)
	}
	g, err := d.IPSGeoOf("r1")
	if err != nil || !g.Saved || g.Mode != ips.GeoModeAllow || g.Countries[0] != "KP" || len(g.Allow) != 2 ||
		g.Direction != ips.GeoOut || g.AppliedAt != 42 || g.Entries != 1234 {
		t.Errorf("%v %+v", err, g)
	}
}

func TestTrafficSettingsAndRoutersRoundTrip(t *testing.T) {
	d := openTestDB(t)
	if s, err := d.TrafficSettingsGet(); err != nil || s != DefaultTrafficSettings {
		t.Fatalf("defaults: %v %+v", err, s)
	}
	want := TrafficSettings{Backend: "clickhouse", CHURL: "http://ch:8123", CHUser: "md", CHPassword: `{"sealed":"x"}`,
		CHDatabase: "mikrodash", FlowDays: 30, Port: 2056, Collector: "192.168.11.5"}
	if err := d.SaveTrafficSettings(want); err != nil {
		t.Fatal(err)
	}
	if s, _ := d.TrafficSettingsGet(); s != want {
		t.Errorf("%+v", s)
	}
	r := TrafficRouter{RouterID: "r1", Enabled: true, Interfaces: "ether1", AppliedAt: 5, Result: "applied"}
	if err := d.SaveTrafficRouter(r); err != nil {
		t.Fatal(err)
	}
	r.Enabled = false
	_ = d.SaveTrafficRouter(r)
	if got, _ := d.TrafficRouters(); len(got) != 1 || got[0] != r {
		t.Errorf("%+v", got)
	}
}
