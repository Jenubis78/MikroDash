package resource

import (
	"sort"
	"strings"
	"testing"
)

// dnsManual is every property the RouterOS manual lists for the four DNS
// menus (manual.mikrotik.com/docs/cli-reference/ip/dns and its subpages,
// v7.26). `comment` is in none of the three tables' CLI reference pages, and it
// is in the command tree (`/console/inspect`) and every export for all three.
var dnsManual = map[*Resource][]string{
	DNSStatic: {"name", "regexp", "type", "address", "cname", "forward-to", "mx-exchange",
		"mx-preference", "ns", "srv-port", "srv-priority", "srv-target", "srv-weight", "text",
		"ttl", "match-subdomain", "address-list", "comment", "disabled", "dynamic"},
	DNSForwarder: {"name", "dns-servers", "doh-servers", "verify-doh-cert", "comment", "disabled"},
	DNSAdlist:    {"url", "file", "ssl-verify", "comment", "disabled", "name-count", "match-count"},
	DNSSettings: {"servers", "dynamic-servers", "use-doh-server", "verify-doh-cert",
		"doh-max-server-connections", "doh-max-concurrent-queries", "doh-timeout",
		"allow-remote-requests", "max-udp-packet-size", "query-server-timeout",
		"query-total-timeout", "max-concurrent-queries", "max-concurrent-tcp-sessions",
		"cache-size", "cache-max-ttl", "cache-used", "address-list-extra-time", "vrf",
		"mdns-repeat-ifaces"},
}

// TestDNSFormsCoverTheManual holds the four DNS resources to the manual in
// both directions: a documented property the form lacks is a value nobody can
// set from here, and a field the manual does not list is a word the router may
// refuse on every save. It replaced dnsStatic's place in the Node parity gate,
// whose declaration required forward-to and had no address-list.
func TestDNSFormsCoverTheManual(t *testing.T) {
	for res, props := range dnsManual {
		have := map[string]bool{}
		for _, f := range res.Fields {
			have[f.ROS] = true
		}
		want := map[string]bool{}
		for _, p := range props {
			want[p] = true
			if !have[p] {
				t.Errorf("%s has no field for the documented %s", res.Key, p)
			}
		}
		var extra []string
		for p := range have {
			if !want[p] {
				extra = append(extra, p)
			}
		}
		sort.Strings(extra)
		if len(extra) > 0 {
			t.Errorf("%s declares %v, which the manual does not list", res.Key, extra)
		}
	}
}

func dnsArgs(t *testing.T, values map[string]string, editing bool, stored map[string]string) string {
	t.Helper()
	v, errs := DNSStatic.Validate(values, editing)
	if len(errs) > 0 {
		t.Fatalf("%v refused: %v", values, errs)
	}
	v.Stored = stored
	return strings.Join(DNSStatic.BuildArgs(v), " ")
}

// TestAFWDEntryNeedsNoForwardTo. Without forward-to a FWD entry asks the
// resolver's own servers, which is how a name is put on an address list
// without changing where it resolves; the form required one, so no such entry
// could be saved from here.
func TestAFWDEntryNeedsNoForwardTo(t *testing.T) {
	got := dnsArgs(t, map[string]string{"name": "example.com", "type": "FWD",
		"addressList": "to_vpn", "matchSubdomain": "true"}, false, nil)
	want := "=name=example.com =type=FWD =address-list=to_vpn =match-subdomain=yes =disabled=no"
	if got != want {
		t.Errorf("a FWD create without forward-to:\n  got  %s\n  want %s", got, want)
	}
	// A FWD entry has no TTL of its own; one left in the form is not sent.
	got = dnsArgs(t, map[string]string{"name": "example.com", "type": "FWD",
		"forwardTo": "corp", "ttl": "1d"}, false, nil)
	if strings.Contains(got, "=ttl=") {
		t.Errorf("a FWD entry was sent a TTL: %s", got)
	}
}

// TestNameAndRegexpAreAlternatives. Exactly one of them is set, and editing an
// entry into the other kind empties the property it no longer has in the same
// set. Never with `!`: RouterOS refuses `!name` beside a regexp, and the other
// way round, with "only name or regexp allowed" (CHR and hAP ac2, 7.24.5).
func TestNameAndRegexpAreAlternatives(t *testing.T) {
	for _, vals := range []map[string]string{
		{"type": "A", "address": "198.51.100.1"},
		{"name": "a.lan", "regexp": `^a\.lan$`, "type": "A", "address": "198.51.100.1"},
	} {
		if _, errs := DNSStatic.Validate(vals, false); len(errs) == 0 {
			t.Errorf("%v was accepted", vals)
		}
	}

	nameRow := map[string]string{".id": "*1", "name": "a.lan", "type": "A", "address": "198.51.100.1"}
	got := dnsArgs(t, map[string]string{"regexp": `^a[0-9]\.lan$`, "type": "A",
		"address": "198.51.100.1"}, true, nameRow)
	if !strings.Contains(" "+got+" ", " =name= ") || !strings.Contains(got, `=regexp=^a[0-9]\.lan$`) ||
		strings.Contains(got, "=!") {
		t.Errorf("a name entry turned into a regexp one: %s", got)
	}

	reRow := map[string]string{".id": "*2", "regexp": `^a[0-9]\.lan$`, "type": "A", "address": "198.51.100.1"}
	got = dnsArgs(t, map[string]string{"name": "a.lan", "type": "A", "address": "198.51.100.1"}, true, reRow)
	if !strings.Contains(" "+got+" ", " =regexp= ") || !strings.Contains(got, "=name=a.lan") ||
		strings.Contains(got, "=!") {
		t.Errorf("a regexp entry turned into a name one: %s", got)
	}

	// An edit of a regexp entry that stays one removes nothing with `!`.
	got = dnsArgs(t, map[string]string{"regexp": `^a[0-9]\.lan$`, "type": "A",
		"address": "198.51.100.1", "comment": "lab"}, true, reRow)
	for _, word := range []string{"=!name=", "=!forward-to=", "=!address-list="} {
		if strings.Contains(got, word) {
			t.Errorf("a regexp entry's edit sent %s: %s", word, got)
		}
	}
}

func TestADynamicEntryIsReadOnly(t *testing.T) {
	if !DNSStatic.ReadOnlyWhen(map[string]string{"name": "pc.lan", "dynamic": "true"}) {
		t.Error("a DHCP-added entry opened editable")
	}
	if DNSStatic.ReadOnlyWhen(map[string]string{"regexp": `^ads\.`}) {
		t.Error("a regexp entry is still read-only")
	}
}

// TestTheResolverActionsAreSubMenuCommands. A singleton's verb is sent with no
// id, so the cache flush and the adlist reload address no row.
func TestTheResolverActionsAreSubMenuCommands(t *testing.T) {
	for key, path := range map[string]string{
		"flushCache": "/ip/dns/cache/flush", "reloadAdlists": "/ip/dns/adlist/reload"} {
		a := DNSSettings.ActionByKey(key)
		if a == nil {
			t.Errorf("DNS settings offer no %s", key)
			continue
		}
		if got := DNSSettings.Menu + "/" + a.Verb; got != path {
			t.Errorf("%s runs %s, want %s", key, got, path)
		}
	}
	if w := DNSSettings.IDWords(SingletonID); w != nil {
		t.Errorf("the resolver's actions would carry %v", w)
	}
}

// TestAnAdlistsSourceIsSetWhenItIsAdded. RouterOS takes `!url` and `!file`
// and changes nothing, and cannot clear `file` at all, so an edit that switched
// the source left both set. The source is set by the add, one of the two, and
// an edit never sends either.
func TestAnAdlistsSourceIsSetWhenItIsAdded(t *testing.T) {
	if _, errs := DNSAdlist.Validate(map[string]string{"url": "https://example.com/h.txt", "file": "h.txt"}, false); len(errs) == 0 {
		t.Error("an adlist with both a URL and a file was accepted")
	}
	if _, errs := DNSAdlist.Validate(map[string]string{"file": "hosts.txt"}, false); len(errs) > 0 {
		t.Errorf("a file adlist was refused: %v", errs)
	}
	v, errs := DNSAdlist.Validate(map[string]string{"url": "https://example.com/other.txt", "comment": "x"}, true)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	v.Stored = map[string]string{".id": "*1", "file": "hosts.txt"}
	if got := strings.Join(DNSAdlist.BuildArgs(v), " "); strings.Contains(got, "url") || strings.Contains(got, "file") {
		t.Errorf("an edit sent the source: %s", got)
	}
}

// TestASaveOnARouterWithoutMDNSRepeatNamesNoneOfIt. mdns-repeat-ifaces came in
// 7.16, and a router before it refuses a set naming it. An empty box clears it
// with `!` only when the row the router printed holds the property.
func TestASaveOnARouterWithoutMDNSRepeatNamesNoneOfIt(t *testing.T) {
	args := func(stored map[string]string) string {
		v, errs := DNSSettings.Validate(map[string]string{"servers": "198.51.100.53"}, true)
		if len(errs) > 0 {
			t.Fatal(errs)
		}
		v.Stored = stored
		return strings.Join(DNSSettings.BuildArgs(v), " ")
	}
	if got := args(map[string]string{"servers": "198.51.100.1"}); strings.Contains(got, "mdns-repeat-ifaces") {
		t.Errorf("a 7.15 save names mdns-repeat-ifaces: %s", got)
	}
	if got := args(map[string]string{"servers": "198.51.100.1", "mdns-repeat-ifaces": "bridge"}); !strings.Contains(got, "=!mdns-repeat-ifaces=") {
		t.Errorf("a cleared box left mdns-repeat-ifaces set: %s", got)
	}
}

// TestTheServerFieldsOfferThePublicResolvers. Each suggestion carries its
// provider's name, and the list is a suggestion rather than a select: a server
// that is not in it is still accepted.
func TestTheServerFieldsOfferThePublicResolvers(t *testing.T) {
	for _, c := range []struct {
		res   *Resource
		field string
	}{{DNSSettings, "servers"}, {DNSSettings, "useDohServer"}, {DNSForwarder, "dnsServers"}, {DNSForwarder, "dohServers"}} {
		f := c.res.FieldByName(c.field)
		if f == nil || f.OptionsFrom == nil || !f.OptionsFrom.Suggest || len(f.OptionsFrom.Values) == 0 {
			t.Errorf("%s.%s offers no public resolvers", c.res.Key, c.field)
			continue
		}
		for _, v := range f.OptionsFrom.Values {
			if f.OptionsFrom.Labels[v] == "" {
				t.Errorf("%s.%s offers %s without its provider's name", c.res.Key, c.field, v)
			}
		}
	}
	if _, errs := DNSSettings.Validate(map[string]string{"servers": "198.51.100.53,198.51.100.54"}, true); len(errs) > 0 {
		t.Errorf("a server not in the suggestions was refused: %v", errs)
	}
}
