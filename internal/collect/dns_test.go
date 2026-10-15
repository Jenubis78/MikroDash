package collect

// The Go side of nodecheck/dns-fingerprint.test.js.
//
// The two suites assert the SAME behaviour against the two implementations, so
// they cannot drift apart silently. They were written asserting the OPPOSITE:
// a comment-only edit used to write the router and never reach the open page,
// because the fingerprint was a hand-listed tuple that omitted `comment`. The
// port found that, it was fixed in the live app, and these tests going red is
// how the port was told to follow. They now pin the fixed behaviour.

import (
	"errors"
	"mikrodash/internal/hub"
	"reflect"
	"strings"
	"testing"

	"mikrodash/internal/resource"
	"mikrodash/internal/routeros"
)

// scriptedReader answers from whatever rows it currently holds, so a test can
// change the router's answer between ticks.
type scriptedReader struct {
	settings   routeros.Reply
	static     []routeros.Reply
	forwarders []routeros.Reply
	adlists    []routeros.Reply
	// absent menus answer as a router without the package does.
	absent map[string]bool
	reads  int
	asked  map[string]int
}

func (s *scriptedReader) Connected() bool { return true }

func (s *scriptedReader) Do(cmd routeros.Cmd) ([]routeros.Reply, error) {
	s.reads++
	if s.asked == nil {
		s.asked = map[string]int{}
	}
	s.asked[cmd.Path]++
	if s.absent[cmd.Path] {
		return nil, errors.New("no such command prefix")
	}
	switch cmd.Path {
	case "/ip/dns/print":
		return []routeros.Reply{s.settings}, nil
	case "/ip/dns/static/print":
		return s.static, nil
	case "/ip/dns/forwarders/print":
		return s.forwarders, nil
	case "/ip/dns/adlist/print":
		return s.adlists, nil
	}
	return nil, nil
}

func baseRow() routeros.Reply {
	return routeros.Reply{".id": "*1", "name": "host.lan", "address": "198.51.100.7",
		"type": "A", "ttl": "1d", "disabled": "false", "comment": "before"}
}

// held still on purpose: cache-used is in the settings fingerprint, and letting
// it move would mask exactly what these tests measure.
func baseSettings() routeros.Reply {
	return routeros.Reply{"servers": "", "cache-size": "2048", "cache-used": "46"}
}

func TestDNSFingerprintCoversComment(t *testing.T) {
	r := &scriptedReader{settings: baseSettings(), static: []routeros.Reply{baseRow()}}
	var emits []string
	d := NewDNS(r, hub.NewRelay(func(room string, ev hub.Named, payload any) { event := ev.Name(); emits = append(emits, event) }), 10000)

	d.Tick()
	if len(emits) != 1 {
		t.Fatalf("the first tick emitted %d times, want 1", len(emits))
	}

	row := baseRow()
	row["comment"] = "after"
	r.static = []routeros.Reply{row}
	d.RefreshNow() // exactly what a res:save does

	if len(emits) != 2 {
		t.Errorf("a comment-only change emitted %d times, want 2 — `comment` is a "+
			"rendered column, so it must be in the fingerprint or the open page "+
			"keeps showing the old value after a save that really landed", len(emits))
	}
	// And the payload carries it, so the page shows what the router now holds.
	if got := d.Last().StaticEntries[0].Comment; got != "after" {
		t.Errorf("lastPayload comment = %q, want %q", got, "after")
	}
}

func TestDNSFingerprintCatchesAddress(t *testing.T) {
	r := &scriptedReader{settings: baseSettings(), static: []routeros.Reply{baseRow()}}
	var emits []string
	d := NewDNS(r, hub.NewRelay(func(room string, ev hub.Named, payload any) { event := ev.Name(); emits = append(emits, event) }), 10000)

	d.Tick()
	row := baseRow()
	row["address"] = "198.51.100.9"
	r.static = []routeros.Reply{row}
	d.RefreshNow()

	if len(emits) != 2 {
		t.Errorf("an address change emitted %d times, want 2", len(emits))
	}
}

// RefreshNow must re-read the static table even though it is normally read only
// every twelfth tick. Without the tick reset a save would leave the table
// showing the old row until the next config sweep — up to ten minutes on the
// default interval — which reads as a failed save.
func TestRefreshNowRereadsTheStaticTable(t *testing.T) {
	r := &scriptedReader{settings: baseSettings(), static: []routeros.Reply{baseRow()}}
	d := NewDNS(r, hub.Relay{}, 10000)
	d.Tick()

	row := baseRow()
	row["address"] = "198.51.100.9"
	r.static = []routeros.Reply{row}

	d.Tick() // an ordinary tick is NOT due a static read
	if got := d.Last().StaticEntries[0].Address; got != "198.51.100.7" {
		t.Errorf("an ordinary tick re-read the static table; address = %q", got)
	}
	d.RefreshNow()
	if got := d.Last().StaticEntries[0].Address; got != "198.51.100.9" {
		t.Errorf("RefreshNow did not re-read the static table; address = %q", got)
	}
}

// ── PHASE 4.1: THE DERIVATION, TESTED WITHOUT A COLLECTOR ──────────────────
//
// The point of extracting a builder is that the rows-to-payload step becomes
// testable without a collector, a session or a router. These cases could not have
// been written against `applyLocked`: it needs a `*DNS` with a lock, a poll
// interval, an emit function and carried static entries.

func TestBuildDNSIsPure(t *testing.T) {
	static := []DNSStaticEntry{{Name: "a.example", Address: "10.0.0.1"}}
	yes, no := true, false

	for _, tc := range []struct {
		name      string
		in        DNSInput
		available bool
	}{{
		// NIL MEANS NOT YET KNOWN, and it must read as available: a router is
		// presumed to have DNS until it says otherwise, and the alternative
		// blanks the page on the first tick before anything has answered.
		name:      "unknown availability reads as available",
		in:        DNSInput{Rows: []routeros.Reply{{"servers": "1.1.1.1"}}, Available: nil},
		available: true,
	}, {
		name:      "an explicit yes",
		in:        DNSInput{Rows: []routeros.Reply{{"servers": "1.1.1.1"}}, Available: &yes},
		available: true,
	}, {
		// A router whose DNS menu is missing. The page must be told, not left
		// looking at an empty table it cannot distinguish from "no servers set".
		name:      "an explicit no survives",
		in:        DNSInput{Rows: []routeros.Reply{{"servers": "1.1.1.1"}}, Available: &no},
		available: false,
	}, {
		// NO ROWS IS NOT AN ERROR. A scheduled read that has not answered yet
		// hands over an empty slice, and building from it must not panic on
		// rows[0] — which is the one thing a five-argument version of this
		// would have made easy to get wrong at a second call site.
		name:      "no rows at all",
		in:        DNSInput{Rows: nil, Available: &yes},
		available: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			in.Static, in.PollMs, in.Now = static, 10000, 1234
			got := BuildDNS(in)
			if got.Available != tc.available {
				t.Errorf("Available = %v, want %v", got.Available, tc.available)
			}
			if got.PollMs != 10000 || got.TS != 1234 {
				t.Errorf("pollMs=%d ts=%d; the builder invented a clock or an interval",
					got.PollMs, got.TS)
			}
			if len(got.StaticEntries) != 1 || got.StaticEntries[0].Name != "a.example" {
				t.Errorf("static entries = %v; they are carried between ticks and must "+
					"pass through untouched", got.StaticEntries)
			}
		})
	}
}

// TestBuildDNSTakesNoClockOfItsOwn. A derivation that reads the wall clock is not
// pure and cannot be replayed against a fixture: the same input would produce a
// different payload on every run, and the fingerprint that suppresses redundant
// emits would never match.
func TestBuildDNSTakesNoClockOfItsOwn(t *testing.T) {
	in := DNSInput{Rows: []routeros.Reply{{"servers": "9.9.9.9"}}, PollMs: 5000, Now: 42}
	a, b := BuildDNS(in), BuildDNS(in)
	if a.TS != 42 || b.TS != 42 {
		t.Fatalf("ts %d and %d; the builder is reading time.Now rather than its input", a.TS, b.TS)
	}
	// DeepEqual: DNSSettings holds a []string, so it is not comparable with ==.
	if !reflect.DeepEqual(a.Settings, b.Settings) {
		t.Error("the same rows produced two different settings")
	}
}

// TestDNSStaticReadCarriesEveryFormField. The table, the edit form and the fleet
// copy all start from this read, and a property it leaves out is one a copy
// drops: the fleet copy of a FWD entry lost its address list and its
// match-subdomain this way.
func TestDNSStaticReadCarriesEveryFormField(t *testing.T) {
	for _, c := range []struct {
		cmd routeros.Cmd
		res *resource.Resource
	}{{dnsStaticCmd, resource.DNSStatic}, {dnsForwardersCmd, resource.DNSForwarder},
		{dnsAdlistCmd, resource.DNSAdlist}} {
		props := map[string]bool{}
		for _, a := range c.cmd.Args {
			for _, p := range strings.Split(strings.TrimPrefix(a, "=.proplist="), ",") {
				props[p] = true
			}
		}
		if !props[".id"] {
			t.Errorf("%s does not ask for .id, so no row can be opened", c.cmd.Path)
		}
		for _, f := range c.res.Fields {
			if !f.Unread() && !props[f.ROS] {
				t.Errorf("%s does not ask for %s, which the %s form has", c.cmd.Path, f.ROS, c.res.Key)
			}
		}
	}
}

func TestStaticEntriesCarryTheAddressList(t *testing.T) {
	got := ParseStaticEntries([]routeros.Reply{
		{".id": "*1", "name": "example.com", "type": "FWD", "forward-to": "corp",
			"address-list": "to_vpn", "match-subdomain": "true"},
		{".id": "*2", "name": "pc.lan", "type": "A", "address": "198.51.100.5", "dynamic": "true"},
	})
	if len(got) != 2 {
		t.Fatalf("%d entries, want 2", len(got))
	}
	if e := got[0]; e.AddressList != "to_vpn" || !e.MatchSubdomain || e.Address != "corp" || e.Dynamic {
		t.Errorf("FWD entry = %+v", e)
	}
	if e := got[1]; !e.Dynamic || e.AddressList != "" || e.MatchSubdomain {
		t.Errorf("dynamic entry = %+v", e)
	}
}

func TestForwardersCountTheEntriesNamingThem(t *testing.T) {
	static := ParseStaticEntries([]routeros.Reply{
		{".id": "*1", "name": "a.example", "type": "FWD", "forward-to": "corp"},
		{".id": "*2", "name": "b.example", "type": "FWD", "forward-to": "corp"},
		{".id": "*3", "name": "c.example", "type": "FWD", "forward-to": "198.51.100.53"},
		{".id": "*4", "name": "corp", "type": "A", "address": "198.51.100.9"},
	})
	got := ParseForwarders([]routeros.Reply{
		{".id": "*A", "name": "corp", "dns-servers": "198.51.100.53,198.51.100.54", "comment": "office"},
		{".id": "*B", "name": "doh", "doh-servers": "https://dns.example/dns-query",
			"verify-doh-cert": "false", "disabled": "true"},
	}, static)
	if len(got) != 2 {
		t.Fatalf("%d forwarders, want 2", len(got))
	}
	corp, doh := got[0], got[1]
	if corp.UsedBy != 2 || len(corp.DNSServers) != 2 || !corp.VerifyDohCert || corp.Comment != "office" {
		t.Errorf("corp = %+v; an A record named like a forwarder is not a use of it", corp)
	}
	if doh.UsedBy != 0 || doh.VerifyDohCert || !doh.Disabled || len(doh.DoHServers) != 1 {
		t.Errorf("doh = %+v", doh)
	}
}

func TestAdlistsCarryTheirSourceAndCounts(t *testing.T) {
	got := ParseAdlists([]routeros.Reply{
		{".id": "*1", "url": "https://example.com/hosts.txt", "name-count": "1200", "match-count": "7"},
		{".id": "*2", "file": "hosts.txt", "ssl-verify": "false", "comment": "local"},
	})
	if len(got) != 2 {
		t.Fatalf("%d adlists, want 2", len(got))
	}
	if a := got[0]; a.NameCount == nil || *a.NameCount != 1200 || !a.SSLVerify {
		t.Errorf("url adlist = %+v", a)
	}
	if a := got[1]; a.File != "hosts.txt" || a.SSLVerify || a.MatchCount != nil || a.Comment != "local" {
		t.Errorf("file adlist = %+v", a)
	}
}

// TestARouterWithoutForwardersIsAskedOnce. Forwarders and adlists are newer than
// the rest of the resolver; a router that lacks them says so once, the page
// hides their cards, and the slow lane stops asking.
func TestARouterWithoutForwardersIsAskedOnce(t *testing.T) {
	r := &scriptedReader{settings: baseSettings(), static: []routeros.Reply{baseRow()},
		absent: map[string]bool{"/ip/dns/forwarders/print": true, "/ip/dns/adlist/print": true}}
	d := NewDNS(r, hub.Relay{}, 10000)
	d.Tick()
	d.RefreshNow()
	p := d.Last()
	if p.ForwardersAvailable || p.AdlistsAvailable {
		t.Errorf("forwardersAvailable=%v adlistsAvailable=%v on a router without either",
			p.ForwardersAvailable, p.AdlistsAvailable)
	}
	if p.Forwarders == nil || p.Adlists == nil {
		t.Error("an absent menu sent a null list")
	}
	if n := r.asked["/ip/dns/forwarders/print"]; n != 1 {
		t.Errorf("the absent forwarders menu was asked %d times", n)
	}
	if n := r.asked["/ip/dns/static/print"]; n != 2 {
		t.Errorf("the static table was read %d times, want 2", n)
	}

	r2 := &scriptedReader{settings: baseSettings(),
		forwarders: []routeros.Reply{{".id": "*A", "name": "corp", "dns-servers": "198.51.100.53"}}}
	d2 := NewDNS(r2, hub.Relay{}, 10000)
	d2.Tick()
	if p := d2.Last(); !p.ForwardersAvailable || len(p.Forwarders) != 1 || !p.AdlistsAvailable {
		t.Errorf("a router with forwarders: %+v", p)
	}
}
