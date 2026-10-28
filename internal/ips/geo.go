package ips

// Geofencing on the router: every IPv4 network of the chosen countries in one
// address list, and filter rules that drop NEW connections to or from it.
//
// ── FILTER, NOT RAW, AND THAT IS THE DIRECTION ──────────────────────────────
//
// Raw rules run before connection tracking, so a raw drop on the list's
// sources would also drop the replies to connections that went out: there "in"
// and "out" could not be told apart. The filter chain can: `connection-state=new`
// with the list as the source is a connection that came in from those
// countries, and with the list as the destination one that went out to them.
// Replies to a connection allowed before the list existed are left alone.
//
// Inbound covers both chains a connection from the internet reaches: forward
// (a dst-nat to a server at home) and input (the router itself).
//
// ── A BLACKLIST, OR A WHITELIST ─────────────────────────────────────────────
//
// Two modes. "block" drops the blacklist's countries, less any the whitelist
// names: the whitelist is what must never be cut, the router's own country by
// default. "allow" drops every country but the whitelist's: its list holds the
// whitelist and the ranges no country holds (private, loopback, CGNAT...), and
// the rules match what is NOT on it (`src-address-list=!list`), so the list
// stays the size of the countries kept rather than of the rest of the world.
//
// ── ONLY WHAT MIKRODASH WROTE, AND ONLY WHAT CHANGED ────────────────────────
//
// The list is MikroDash's alone, and a sync adds the prefixes it lacks and
// removes the ones it no longer needs: re-applying after a geo database update
// writes the difference, not the countries again.

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"mikrodash/internal/routeros"
)

// GeoList is the blacklist's address list: the rules drop what is on it.
const GeoList = "mikrodash-ips-geo"

// GeoAllowList is the whitelist's address list: the rules drop what is not on it.
const GeoAllowList = "mikrodash-ips-geo-allow"

// Geo modes.
const (
	GeoModeBlock = "block"
	GeoModeAllow = "allow"
)

// GeoLocal is the whitelist's entry for the ranges no country holds.
const GeoLocal = "local"

// LocalPrefixes are the IPv4 ranges no country holds: a whitelist always
// lets them through, or the LAN would be cut from the router.
var LocalPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/3"),
}

// GeoMaxEntries bounds one router's list: past it a router spends more memory
// and minutes of API writes than any country choice is worth.
const GeoMaxEntries = 100000

// Geo directions.
const (
	GeoIn   = "in"
	GeoOut  = "out"
	GeoBoth = "both"
)

const geoMarker = Marker + ": geo"

// GeoOwned is whether a filter rule is one of the geofencing rules.
func GeoOwned(r routeros.Reply) bool { return strings.HasPrefix(r["comment"], geoMarker) }

// GeoWant is the filter rules a mode and direction need; none for direction
// "" (removal).
func GeoWant(mode, direction string) []RouterRow {
	list, what := GeoList, ""
	if mode == GeoModeAllow {
		list, what = "!"+GeoAllowList, ", not whitelisted"
	}
	rule := func(chain, side, dir string) RouterRow {
		return RouterRow{Menu: "/ip/firewall/filter", Props: map[string]string{
			"chain": chain, "action": "drop", "connection-state": "new", side + "-address-list": list,
			"comment": geoMarker + ", " + dir + what}}
	}
	var out []RouterRow
	if direction == GeoIn || direction == GeoBoth {
		out = append(out, rule("forward", "src", "inbound"), rule("input", "src", "inbound to the router"))
	}
	if direction == GeoOut || direction == GeoBoth {
		out = append(out, rule("forward", "dst", "outbound"))
	}
	return out
}

// GeoRulesPlan is what /ip/firewall/filter needs for a mode and direction
// ("" removes).
func GeoRulesPlan(mode, direction string, filter []routeros.Reply) []Step {
	return planMenu("/ip/firewall/filter", GeoWant(mode, direction), filter, GeoOwned)
}

// GeoTarget is the list a mode fills and the countries that go on it: the
// blacklist less the whitelist, or the whitelist.
func GeoTarget(mode string, block, allow []string) (string, []string) {
	if mode == GeoModeAllow {
		return GeoAllowList, allow
	}
	keep := map[string]bool{}
	for _, c := range allow {
		keep[c] = true
	}
	out := []string{}
	for _, c := range block {
		if !keep[c] {
			out = append(out, c)
		}
	}
	return GeoList, out
}

// GeoEntry is one prefix and the country it is for.
type GeoEntry struct {
	Prefix  netip.Prefix
	Country string
}

// GeoEntriesPlan is the list's difference: the entries to add (sorted by
// prefix) and the ids to remove. `have` is the list as the router prints it.
func GeoEntriesPlan(want map[string][]netip.Prefix, have []routeros.Reply) (add []GeoEntry, remove []string) {
	wanted := map[netip.Prefix]string{}
	for c, ps := range want {
		for _, p := range ps {
			wanted[p.Masked()] = c
		}
	}
	held := map[netip.Prefix]bool{}
	for _, r := range have {
		p, ok := listPrefix(r["address"])
		if !ok || held[p] || wanted[p] == "" {
			// Not one of ours to keep: not a prefix, a duplicate, or no longer wanted.
			remove = append(remove, r[".id"])
			continue
		}
		held[p] = true
	}
	for p, c := range wanted {
		if !held[p] {
			add = append(add, GeoEntry{Prefix: p, Country: c})
		}
	}
	sort.Slice(add, func(i, j int) bool {
		if c := add[i].Prefix.Addr().Compare(add[j].Prefix.Addr()); c != 0 {
			return c < 0
		}
		return add[i].Prefix.Bits() < add[j].Prefix.Bits()
	})
	sort.Strings(remove)
	return add, remove
}

// listPrefix reads an address-list entry's address: RouterOS prints a /32 as
// the bare address.
func listPrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(s)
	return p.Masked(), err == nil
}

// GeoEntryArgs is the sentence that adds one entry to a list.
func GeoEntryArgs(list string, e GeoEntry) []string {
	addr := e.Prefix.String()
	if e.Prefix.IsSingleIP() {
		addr = e.Prefix.Addr().String()
	}
	return []string{"=list=" + list, "=address=" + addr, "=comment=" + Marker + " geo " + e.Country}
}

// GeoAllowConflicts is the addresses the router is reached from that a
// whitelist leaves out: dropping everything else would cut them off.
func GeoAllowConflicts(want map[string][]netip.Prefix, own []netip.Addr) []string {
	var out []string
	for _, a := range own {
		held := false
		for _, ps := range want {
			for _, p := range ps {
				held = held || p.Contains(a)
			}
		}
		if !held {
			out = append(out, a.String()+" (not whitelisted)")
		}
	}
	sort.Strings(out)
	return out
}

// GeoConflicts is the router's own public addresses that the countries hold:
// listing them would cut the router off from where it is, by its own rules.
func GeoConflicts(want map[string][]netip.Prefix, own []netip.Addr) []string {
	var out []string
	for c, ps := range want {
		for _, p := range ps {
			for _, a := range own {
				if p.Contains(a) {
					out = append(out, fmt.Sprintf("%s (%s)", a, c))
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// GeoChoice is a router's geofencing as chosen.
type GeoChoice struct {
	Mode      string
	Direction string
	Block     []string
	Allow     []string
}

// GeoValidate cleans a choice: each list upper case, once each, sorted; the
// mode and direction known; a whitelist mode with a whitelist.
func GeoValidate(c GeoChoice) (GeoChoice, error) {
	if c.Mode == "" {
		c.Mode = GeoModeBlock
	}
	if c.Mode != GeoModeBlock && c.Mode != GeoModeAllow {
		return c, fmt.Errorf("the mode is %q or %q", GeoModeBlock, GeoModeAllow)
	}
	if c.Direction != GeoIn && c.Direction != GeoOut && c.Direction != GeoBoth {
		return c, fmt.Errorf("the direction is %q, %q or %q", GeoIn, GeoOut, GeoBoth)
	}
	var err error
	if c.Block, err = cleanCountries(c.Block); err != nil {
		return c, err
	}
	if c.Allow, err = cleanCountries(c.Allow); err != nil {
		return c, err
	}
	if c.Mode == GeoModeAllow && len(c.Allow) == 0 {
		return c, errors.New("allowing only the whitelist needs a whitelist: it would drop every country")
	}
	return c, nil
}

func cleanCountries(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
		if !isoCode.MatchString(c) {
			return nil, fmt.Errorf("%q is not a two-letter country code", c)
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out, nil
}
