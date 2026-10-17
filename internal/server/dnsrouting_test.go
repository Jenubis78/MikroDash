package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"mikrodash/internal/alert"
	"mikrodash/internal/alertwire"
	"mikrodash/internal/collect"
	"mikrodash/internal/db"
	"mikrodash/internal/hub"
	"mikrodash/internal/routeros"
	"mikrodash/internal/session"
)

// routingRouter answers a router whose static entries feed `fed` entries to
// to_vpn, with a mangle rule marking for `vpn` and that table's one route
// active or not. It records what it was asked.
func routingRouter(fed int, active bool, asked *[]string) func(routeros.Cmd) ([]routeros.Reply, error) {
	return func(cmd routeros.Cmd) ([]routeros.Reply, error) {
		*asked = append(*asked, cmd.Path+" "+strings.Join(cmd.Args, " "))
		switch cmd.Path {
		case "/ip/dns/static/print":
			*cmd.Ret = map[bool]string{true: "1265", false: "0"}[fed > 0]
		case "/ip/firewall/address-list/print":
			*cmd.Ret = "312"
		case "/ip/firewall/mangle/print":
			return []routeros.Reply{{".id": "*9", "chain": "prerouting", "new-routing-mark": "vpn",
				"dst-address-list": "to_vpn", "packets": "42"}}, nil
		case "/ip/route/print":
			return []routeros.Reply{{"dst-address": "0.0.0.0/0", "gateway": "wg0", "routing-table": "vpn",
				"active": map[bool]string{true: "true", false: "false"}[active]}}, nil
		}
		return nil, nil
	}
}

func TestDomainRoutingNeedsARuleAndALiveRoute(t *testing.T) {
	if ok, _ := routingVerdict("to_vpn", []string{"vpn"}, []DomainRoutingRoute{{Table: "vpn", Active: true}}); !ok {
		t.Error("an active route in the marked table was not enough")
	}
	if ok, why := routingVerdict("to_vpn", nil, nil); ok || !strings.Contains(why, "mangle") {
		t.Errorf("no rule: %v %q", ok, why)
	}
	if ok, why := routingVerdict("to_vpn", []string{"vpn", "vpn2"},
		[]DomainRoutingRoute{{Table: "vpn", Active: true}, {Table: "vpn2"}}); ok || !strings.Contains(why, "vpn2") {
		t.Errorf("a dead second table: %v %q", ok, why)
	}
}

// TestARouterThatDoesNotRouteByDomainIsReadNoFurther. Only the count of
// static entries feeding the list is asked, and only every half hour.
func TestARouterThatDoesNotRouteByDomainIsReadNoFurther(t *testing.T) {
	var asked []string
	sn := session.NewForTestWithExec(hub.New(), "r1", routingRouter(0, true, &asked))
	s := &Server{features: &featureLoop{fed: map[string]routeFed{}, downStreak: map[string]int{}}}
	now := time.Now()
	st := s.readDomainRouting(context.Background(), "r1", sn, "to_vpn", now)
	if st.Feeding != 0 || st.Error != "" || len(asked) != 1 || !strings.Contains(asked[0], "=count-only= ?address-list=to_vpn") {
		t.Fatalf("status %+v after %v; want one count-only print and nothing else", st, asked)
	}
	s.readDomainRouting(context.Background(), "r1", sn, "to_vpn", now.Add(time.Minute))
	if len(asked) != 1 {
		t.Errorf("a minute later the router was asked again: %v", asked)
	}
	s.readDomainRouting(context.Background(), "r1", sn, "to_vpn", now.Add(domainRouteFedEvery))
	if len(asked) != 2 {
		t.Errorf("half an hour later it was not asked again: %v", asked)
	}

	asked = nil
	if st := s.readDomainRouting(context.Background(), "r1", sn, "", now); st.Error == "" || len(asked) != 0 {
		t.Errorf("with no list named: %+v after %v", st, asked)
	}
}

// TestARoutedRouterIsReadInFilteredPrints. Counts where a count is all the
// card needs, and every print filtered on the router.
func TestARoutedRouterIsReadInFilteredPrints(t *testing.T) {
	var asked []string
	sn := session.NewForTestWithExec(hub.New(), "r1", routingRouter(1265, false, &asked))
	s := &Server{features: &featureLoop{fed: map[string]routeFed{}, downStreak: map[string]int{}}}
	st := s.readDomainRouting(context.Background(), "r1", sn, "to_vpn", time.Now())
	if st.Feeding != 1265 || st.Entries != 312 || len(st.Rules) != 1 || len(st.Routes) != 1 || st.OK {
		t.Fatalf("status = %+v", st)
	}
	if !strings.Contains(st.Why, "vpn") {
		t.Errorf("why = %q", st.Why)
	}
	for _, a := range asked {
		if !strings.Contains(a, "?") {
			t.Errorf("an unfiltered print: %s", a)
		}
	}
}

// TestDomainRoutingWaitsOutAFlap. A bad reading is handed to the rule only as
// the third in a row; a good one always, and it starts the count again.
func TestDomainRoutingWaitsOutAFlap(t *testing.T) {
	f := &featureLoop{downStreak: map[string]int{}}
	got := []bool{f.routingDue("r1", false), f.routingDue("r1", false), f.routingDue("r1", true),
		f.routingDue("r1", false), f.routingDue("r1", false), f.routingDue("r1", false), f.routingDue("r1", false)}
	want := []bool{false, false, true, false, false, true, true}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("readings handed on = %v, want %v", got, want)
		}
	}
}

// TestTheCardShowsOnlyWhatItsViewerMayRead. The parts behind the Address
// Lists, Firewall and Routing pages reach only a viewer granted them, and the
// reason, which names tables, only one granted both Firewall and Routing.
func TestTheCardShowsOnlyWhatItsViewerMayRead(t *testing.T) {
	st := newDomainRoutingStatus("r1", "to_vpn")
	st.Feeding, st.Entries, st.Why = 1265, 312, "No active route in vpn for traffic to to_vpn"
	st.Rules = []DomainRoutingRule{{Mark: "vpn"}}
	st.Routes = []DomainRoutingRoute{{Table: "vpn"}}

	all := st.For(true, true, true)
	if all.Entries != 312 || len(all.Rules) != 1 || len(all.Routes) != 1 || all.Why == "" || len(all.Withheld) != 0 {
		t.Errorf("a viewer granted everything got %+v", all)
	}
	none := st.For(false, false, false)
	if none.Entries != 0 || len(none.Rules) != 0 || len(none.Routes) != 0 || none.Why != "" || len(none.Withheld) != 3 {
		t.Errorf("a DNS-only viewer got %+v", none)
	}
	if st.Entries != 312 || len(st.Rules) != 1 {
		t.Error("cutting a copy changed the stored reading")
	}
}

// TestPresenceReadsWifiAndLiveARPAndNotFixedARP. A device is here when it is a
// Wi-Fi client or has a live ARP entry; it is gone when both answered and
// neither has it; and a device only a static or DHCP-made entry names is
// neither here nor gone, which is what lets its open alert be closed.
func TestPresenceReadsWifiAndLiveARPAndNotFixedARP(t *testing.T) {
	const mac = "02:00:00:00:00:01"
	wifi := &collect.WirelessPayload{Clients: []collect.WirelessClient{{MAC: "02:00:00:00:00:02"}}}
	with := func(e collect.ARPEntry) *collect.ARPIndex {
		return &collect.ARPIndex{ByMAC: map[string]collect.ARPEntry{mac: e}}
	}
	for _, c := range []struct {
		name                  string
		wifi                  *collect.WirelessPayload
		arp                   *collect.ARPIndex
		present, known, fixed bool
	}{
		{"nothing has answered", nil, nil, false, false, false},
		{"in wifi", &collect.WirelessPayload{Clients: []collect.WirelessClient{{MAC: "02:00:00:00:00:01"}}}, nil, true, true, false},
		{"live in ARP", wifi, with(collect.ARPEntry{MAC: mac, Live: true}), true, true, false},
		{"in neither", wifi, with(collect.ARPEntry{MAC: "02:00:00:00:00:09"}), false, true, false},
		{"only a fixed entry", wifi, with(collect.ARPEntry{MAC: mac, Fixed: true}), false, false, true},
		{"fixed, but in wifi", &collect.WirelessPayload{Clients: []collect.WirelessClient{{MAC: "02:00:00:00:00:01"}}},
			with(collect.ARPEntry{MAC: mac, Fixed: true}), true, true, false},
		{"only wifi has answered", wifi, nil, false, true, false},
	} {
		present, known, fixed := presence(c.wifi, c.arp, mac)
		if present != c.present || known != c.known || fixed != c.fixed {
			t.Errorf("%s: present %v, known %v, fixed %v; want %v %v %v",
				c.name, present, known, fixed, c.present, c.known, c.fixed)
		}
	}
}

type fakeWatchReader struct {
	rows []routeros.Reply
}

func (f *fakeWatchReader) Do(routeros.Cmd) ([]routeros.Reply, error) { return f.rows, nil }
func (f *fakeWatchReader) Connected() bool                           { return true }

// TestCheckWatchListWithdrawsAnOpenAlertWhenADeviceTurnsFixed. An absence
// raised while a wired device was unplugged must be closed when it returns to
// the network through a static or DHCP-made ARP entry (status=permanent),
// which the router never probes. Leaving it open leaves an alert that cannot
// recover.
func TestCheckWatchListWithdrawsAnOpenAlertWhenADeviceTurnsFixed(t *testing.T) {
	d, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const mac = "02:00:00:00:00:01"
	if err := d.SaveWatchDevice(db.WatchDevice{RouterID: "r1", MAC: mac, Label: "Printer", GraceMinutes: 1}); err != nil {
		t.Fatal(err)
	}

	w := alertwire.New(nil)
	w.SetPersisting("r1", false)
	r := alert.Router{ID: "r1", AlertsEnabled: true}
	if fired := w.DeviceAbsent(r, mac, "Printer", false); len(fired) != 1 {
		t.Fatalf("opening the absence did not fire: %+v", fired)
	}

	arpReader := &fakeWatchReader{rows: []routeros.Reply{
		{"address": "10.0.0.1", "mac-address": mac, "status": "permanent", "complete": "true"},
	}}
	arp := collect.NewARP(arpReader, 30_000)
	arp.Tick()

	wifi := collect.NewWireless(&fakeWatchReader{}, hub.Relay{}, nil, 30_000)
	wifi.Tick()

	sn := session.NewForTest(hub.New(), "r1")
	sn.SetWatchForTest(true, wifi, arp)

	s := &Server{
		auditDB:  d,
		alerts:   w,
		features: &featureLoop{seen: map[string]int64{}},
	}
	s.checkWatchList(map[string]*session.Session{"r1": sn}, time.Now())

	// The alert must be withdrawn: a recovery must not fire because it was
	// closed silently, and a new absence must open afresh.
	if fired := w.DeviceAbsent(r, mac, "Printer", true); len(fired) != 0 {
		t.Fatalf("the alert was still open after checkWatchList saw a fixed entry: %+v", fired)
	}
	if fired := w.DeviceAbsent(r, mac, "Printer", false); len(fired) != 1 {
		t.Fatalf("opening a fresh absence after withdrawal did not fire: %+v", fired)
	}
}
