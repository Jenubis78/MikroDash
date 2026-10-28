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
		SniffBytes: 20000, Protected: []string{"192.168.88.50"}, Disk: "usb1", Network: "vlan11", DHCP: true}
	if err := d.SaveIPSSensor(s); err != nil {
		t.Fatal(err)
	}
	s.Enforce = false
	if err := d.SaveIPSSensor(s); err != nil {
		t.Fatal(err)
	}
	got, err := d.IPSSensors()
	if err != nil || len(got) != 1 || got[0].Enforce || got[0].Token != s.Token || got[0].Protected[0] != "192.168.88.50" ||
		got[0].Network != "vlan11" || !got[0].DHCP {
		t.Fatalf("sensors: %v %+v", err, got)
	}
	for i, ts := range []int64{100, 300, 200} {
		if err := d.InsertIPSEvent(IPSEvent{TS: ts, RouterID: "r1", RuleID: int64(i), Action: "block", Result: "listed",
			Risks: []string{"x"}}); err != nil {
			t.Fatal(err)
		}
	}
	_ = d.InsertIPSEvent(IPSEvent{TS: 400, RouterID: "r2", Action: "log", Result: "monitor"})
	ev, err := d.IPSEvents("r1", 2)
	if err != nil || len(ev) != 2 || ev[0].TS != 300 || ev[1].TS != 200 || ev[0].Risks[0] != "x" {
		t.Fatalf("events: %v %+v", err, ev)
	}
	if err := d.DeleteIPSSensor("r1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.IPSSensors(); len(got) != 0 {
		t.Errorf("after delete: %+v", got)
	}
}
