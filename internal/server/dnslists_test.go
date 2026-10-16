package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"mikrodash/internal/db"
	"mikrodash/internal/routeros"
)

// TestADomainListReadsEveryShapeItIsPublishedIn: one a line, a hosts file,
// wildcards and adblock rules, with comments, in one paste.
func TestADomainListReadsEveryShapeItIsPublishedIn(t *testing.T) {
	got, skipped := ParseDomains(strings.Join([]string{
		"# a comment",
		"Example.COM",
		"0.0.0.0 ads.example.net  # trailing",
		"*.cdn.example.org",
		".leading.example.io",
		"||tracker.example.com^",
		"! adblock comment",
		"not a domain!",
		"localhost",
		"example.com",
		"-bad-.example.com",
	}, "\n"))
	want := []string{"ads.example.net", "cdn.example.org", "example.com", "leading.example.io",
		"tracker.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("domains = %v\nwant      %v", got, want)
	}
	if skipped != 3 {
		t.Errorf("skipped %d, want 3: the sentence, localhost and the label with a dash at its edge", skipped)
	}
	if got := WithoutCovered([]string{"a.example.com", "example.com", "b.c.example.com", "other.org"}); !reflect.DeepEqual(got, []string{"example.com", "other.org"}) {
		t.Errorf("WithoutCovered = %v", got)
	}
}

// TestAListSyncTouchesOnlyWhatItMade. The operator's own entry for a listed
// domain is left alone and the domain skipped; the list's entry for a domain
// that left the list goes; one whose address list moved is rewritten.
func TestAListSyncTouchesOnlyWhatItMade(t *testing.T) {
	l := db.DNSList{ID: 7, Name: "vpn", AddressList: "to_vpn", ForwardTo: "corp", MatchSubdomain: true}
	tag := listTag(l)
	rows := []routeros.Reply{
		{".id": "*1", "name": "kept.example", "type": "FWD", "forward-to": "corp", "address-list": "to_vpn",
			"match-subdomain": "true", "comment": tag},
		{".id": "*2", "name": "moved.example", "type": "FWD", "forward-to": "corp", "address-list": "old",
			"match-subdomain": "true", "comment": tag},
		{".id": "*3", "name": "gone.example", "type": "FWD", "comment": tag},
		{".id": "*4", "name": "mine.example", "type": "FWD", "address-list": "other", "comment": "by hand"},
	}
	in, skipped := PlanDNSList(l, []string{"kept.example", "moved.example", "mine.example", "new.example"}, rows)
	if skipped != 1 {
		t.Errorf("skipped %d, want the operator's own entry", skipped)
	}
	if len(in.Add) != 1 || in.Add[0]["name"] != "new.example" || in.Add[0]["comment"] != tag {
		t.Errorf("add = %v", in.Add)
	}
	if len(in.Set) != 1 || in.Set[0].ID != "*2" {
		t.Errorf("set = %+v", in.Set)
	}
	if !reflect.DeepEqual(in.Remove, []string{"*3"}) {
		t.Errorf("remove = %v; the hand-made *4 must survive", in.Remove)
	}
	// And the plan passes the same checks a job applies.
	if _, errs := planDNSBulk(in, rows); len(errs) > 0 {
		t.Errorf("the plan would be refused: %v", errs)
	}
}

// TestABadFetchRemovesNothing. An error page, an empty file or a captive
// portal parses to no domains or very few; synced, it would remove everything
// the list made. Nothing is refused that has not been accepted before.
func TestABadFetchRemovesNothing(t *testing.T) {
	for _, c := range []struct {
		count, last int
		refused     bool
	}{
		{0, 0, true}, {0, 500, true}, {200, 500, true},
		{250, 500, false}, {499, 500, false}, {1200, 500, false}, {3, 0, false},
	} {
		if got := ListShrank(c.count, c.last) != ""; got != c.refused {
			t.Errorf("%d domains after %d: refused=%v, want %v", c.count, c.last, got, c.refused)
		}
	}
}

// TestAListIsFetchedOnlyFromAPublicAddress. The check is on the address the
// dialer connects to, so a source on this machine is refused as a literal
// private address would be, and a redirect cannot get round it.
func TestAListIsFetchedOnlyFromAPublicAddress(t *testing.T) {
	for _, a := range []string{"127.0.0.1:80", "10.1.2.3:443", "192.168.88.1:80", "172.16.0.9:80",
		"169.254.1.1:80", "[::1]:80", "[fe80::1]:80", "[fd00::1]:443", "[::ffff:192.168.1.1]:80",
		"0.0.0.0:80", "224.0.0.1:80",
		// Carrier-grade NAT and Tailscale, this network, IETF assignments,
		// benchmarking, documentation, the reserved block and broadcast, and the
		// IPv6 forms that carry an IPv4 address somewhere else.
		"100.64.0.1:80", "100.127.255.254:443", "0.1.2.3:80", "192.0.0.8:80", "198.18.0.10:80",
		"198.19.255.1:80", "198.51.100.5:80", "203.0.113.9:80", "240.0.0.1:80", "255.255.255.255:80",
		"[64:ff9b::808:808]:443", "[64:ff9b:1::1]:443", "[2002:c000:204::1]:443", "[2001:db8::1]:443"} {
		if publicOnly("tcp", a, nil) == nil {
			t.Errorf("%s was allowed", a)
		}
	}
	for _, a := range []string{"93.184.215.14:443", "[2606:4700::6810:84e5]:443", "100.63.255.255:80", "198.20.0.1:80"} {
		if err := publicOnly("tcp", a, nil); err != nil {
			t.Errorf("%s was refused: %v", a, err)
		}
	}

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("example.com\n"))
	}))
	defer local.Close()
	_, err := listDomains(context.Background(), db.DNSList{SourceURL: local.URL})
	if err == nil || !strings.Contains(err.Error(), "not a public address") {
		t.Errorf("a source on loopback was fetched: %v", err)
	}
}

// TestARenamedListKeepsItsEntries. The entries belong to the list's id, not to
// its name: after a rename they are still the list's, they are not added a
// second time, their comment follows the new name, and one the list no longer
// holds still goes.
func TestARenamedListKeepsItsEntries(t *testing.T) {
	was := db.DNSList{ID: 7, Name: "vpn", AddressList: "to_vpn", ForwardTo: "corp", MatchSubdomain: true}
	now := was
	now.Name = "vpn-sites"
	rows := []routeros.Reply{
		{".id": "*1", "name": "kept.example", "type": "FWD", "forward-to": "corp", "address-list": "to_vpn",
			"match-subdomain": "true", "comment": listTag(was)},
		{".id": "*2", "name": "gone.example", "type": "FWD", "comment": listTag(was)},
		// Another list's entry, whose id merely starts with the same digit, is not ours.
		{".id": "*3", "name": "other.example", "type": "FWD", "comment": "MikroDash list #70 vpn"},
		{".id": "*4", "name": "mine.example", "type": "FWD", "comment": "by hand"},
	}
	in, _ := PlanDNSList(now, []string{"kept.example", "other.example"}, rows)
	if len(in.Add) != 0 {
		t.Errorf("add = %v; the renamed list's own entry was added a second time", in.Add)
	}
	if len(in.Set) != 1 || in.Set[0].ID != "*1" || in.Set[0].Values["comment"] != "MikroDash list #7 vpn-sites" {
		t.Errorf("set = %+v; want the kept entry's comment brought to the new name", in.Set)
	}
	if !reflect.DeepEqual(in.Remove, []string{"*2"}) {
		t.Errorf("remove = %v; want the entry the list dropped, and neither of the others", in.Remove)
	}
}

// TestAListRemovesASecondCopyOfAName. A name the list holds twice (an earlier
// failed run, or a hand copy of its comment) keeps one entry; the extra goes.
func TestAListRemovesASecondCopyOfAName(t *testing.T) {
	l := db.DNSList{ID: 3, Name: "vpn", AddressList: "to_vpn", MatchSubdomain: true}
	tag := listTag(l)
	rows := []routeros.Reply{
		{".id": "*1", "name": "dup.example", "type": "FWD", "address-list": "to_vpn", "match-subdomain": "true", "comment": tag},
		{".id": "*2", "name": "DUP.example", "type": "FWD", "address-list": "to_vpn", "match-subdomain": "true", "comment": tag},
	}
	in, _ := PlanDNSList(l, []string{"dup.example"}, rows)
	if len(in.Add) != 0 || len(in.Set) != 0 || !reflect.DeepEqual(in.Remove, []string{"*2"}) {
		t.Errorf("add %v set %+v remove %v; want only the second copy removed", in.Add, in.Set, in.Remove)
	}
}

// TestForgettingAListRemovesOnlyWhatItMade. A purge holds no domains, so the
// plan removes every entry of the list and nothing else.
func TestForgettingAListRemovesOnlyWhatItMade(t *testing.T) {
	l := db.DNSList{ID: 7, Name: "vpn", AddressList: "to_vpn", MatchSubdomain: true}
	rows := []routeros.Reply{
		{".id": "*1", "name": "a.example", "type": "FWD", "comment": listTag(l)},
		{".id": "*2", "name": "b.example", "type": "FWD", "comment": "MikroDash list #7 an old name"},
		{".id": "*3", "name": "c.example", "type": "FWD", "comment": "by hand"},
	}
	in, _ := PlanDNSList(l, nil, rows)
	if len(in.Add)+len(in.Set) != 0 || !reflect.DeepEqual(in.Remove, []string{"*1", "*2"}) {
		t.Errorf("add %v set %+v remove %v; want *1 and *2 removed and *3 left", in.Add, in.Set, in.Remove)
	}
}

// TestAPurgeReportsARouterItCannotReach. A sync leaves out a router that is
// disabled or gone, and visits it when it is back; a purge, which forgets or
// narrows a list, reports it as not clean, so nothing is dropped while its
// entries are still there.
func TestAPurgeReportsARouterItCannotReach(t *testing.T) {
	s := gateServer(t, `{}`, "")
	l := db.DNSList{ID: 4, Name: "vpn", AddressList: "to_vpn", RouterIDs: []string{"gone"}}
	if got := s.planDNSListFleet(context.Background(), l, []string{"a.example"}, false); len(got) != 0 {
		t.Errorf("a sync planned %+v for a router that is gone", got)
	}
	got := s.planDNSListFleet(context.Background(), l, nil, true)
	if len(got) != 1 || got[0].RouterID != "gone" || got[0].Error == "" {
		t.Errorf("a purge planned %+v; want the router reported with an error", got)
	}
}
