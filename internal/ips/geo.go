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
// ── ONLY WHAT MIKRODASH WROTE, AND ONLY WHAT CHANGED ────────────────────────
//
// The list is MikroDash's alone, and a sync adds the prefixes it lacks and
// removes the ones it no longer needs: re-applying after a geo database update
// writes the difference, not the countries again.

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"mikrodash/internal/routeros"
)

// GeoList is the address list the geofencing rules drop.
const GeoList = "mikrodash-ips-geo"

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

// GeoWant is the filter rules a direction needs; none for "" (removal).
func GeoWant(direction string) []RouterRow {
	rule := func(chain, side, what string) RouterRow {
		return RouterRow{Menu: "/ip/firewall/filter", Props: map[string]string{
			"chain": chain, "action": "drop", "connection-state": "new", side + "-address-list": GeoList,
			"comment": geoMarker + ", " + what}}
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

// GeoRulesPlan is what /ip/firewall/filter needs for a direction ("" removes).
func GeoRulesPlan(direction string, filter []routeros.Reply) []Step {
	return planMenu("/ip/firewall/filter", GeoWant(direction), filter, GeoOwned)
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

// GeoEntryArgs is the sentence that adds one entry.
func GeoEntryArgs(e GeoEntry) []string {
	addr := e.Prefix.String()
	if e.Prefix.IsSingleIP() {
		addr = e.Prefix.Addr().String()
	}
	return []string{"=list=" + GeoList, "=address=" + addr, "=comment=" + Marker + " geo " + e.Country}
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

// GeoValidate cleans a choice of countries (upper case, once each, sorted) and
// checks its direction.
func GeoValidate(countries []string, direction string) ([]string, error) {
	if direction != GeoIn && direction != GeoOut && direction != GeoBoth {
		return nil, fmt.Errorf("the direction is %q, %q or %q", GeoIn, GeoOut, GeoBoth)
	}
	seen := map[string]bool{}
	out := []string{}
	for _, c := range countries {
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
