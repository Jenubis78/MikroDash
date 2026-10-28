package geo

// Countries as sets of IPv4 networks, for the IPS's geofencing: the router
// drops what an address list holds, and the list is every network DB-IP places
// in the chosen countries.
//
// ── MERGED, OR THE ROUTER CARRIES THE CITY DATABASE ─────────────────────────
//
// City Lite cuts a country into many small networks, one per place it can
// tell apart. A router needs none of that: two adjacent networks of the same
// country are one range, and a range is the fewest prefixes that cover it.
// MergePrefixes does that, and it is what keeps a country's list in the
// thousands rather than the hundreds of thousands.
//
// ── ONE PASS OVER THE DATABASE, ON DEMAND ───────────────────────────────────
//
// Only the mmdb backend can be walked; the legacy geoip-lite files cannot, and
// geofencing says so rather than guessing. A walk decodes one field per network
// and takes seconds on City Lite, so the country names are kept once read and
// the networks are computed only when a router's lists are applied.

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

// ErrNoNetworks is a database that cannot be walked: the legacy backend.
var ErrNoNetworks = errors.New("country networks need the DB-IP database, which this install does not have")

var allIPv4 = netip.MustParsePrefix("0.0.0.0/0")

// Country is one country the database places addresses in.
type Country struct {
	ISO  string `json:"iso"`
	Name string `json:"name"`
}

var (
	countriesMu   sync.Mutex
	countriesDone []Country
)

// Countries is every country the database knows, by name. Read once.
func (d *DB) Countries() ([]Country, error) {
	if d == nil || d.mmdb == nil {
		return nil, ErrNoNetworks
	}
	countriesMu.Lock()
	defer countriesMu.Unlock()
	if countriesDone != nil {
		return countriesDone, nil
	}
	names := map[string]string{}
	for res := range d.mmdb.NetworksWithin(allIPv4) {
		var c struct {
			ISO   string            `maxminddb:"iso_code"`
			Names map[string]string `maxminddb:"names"`
		}
		if err := res.DecodePath(&c, "country"); err != nil {
			return nil, err
		}
		if c.ISO != "" && names[c.ISO] == "" {
			names[c.ISO] = firstNonEmpty(c.Names["en"], c.ISO)
		}
	}
	out := make([]Country, 0, len(names))
	for iso, name := range names {
		out = append(out, Country{ISO: iso, Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	countriesDone = out
	return out, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// CountryNetworks is every IPv4 network the database places in each of these
// countries (ISO codes), merged into the fewest prefixes.
func (d *DB) CountryNetworks(countries []string) (map[string][]netip.Prefix, error) {
	if d == nil || d.mmdb == nil {
		return nil, ErrNoNetworks
	}
	return countryNetworks(d.mmdb, countries)
}

func countryNetworks(r *maxminddb.Reader, countries []string) (map[string][]netip.Prefix, error) {
	want := map[string]bool{}
	for _, c := range countries {
		want[strings.ToUpper(c)] = true
	}
	found := map[string][]netip.Prefix{}
	for res := range r.NetworksWithin(allIPv4) {
		var iso string
		if err := res.DecodePath(&iso, "country", "iso_code"); err != nil {
			return nil, err
		}
		if !want[iso] {
			continue
		}
		p := res.Prefix()
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.Addr().Is4() {
			found[iso] = append(found[iso], p)
		}
	}
	for iso, ps := range found {
		found[iso] = MergePrefixes(ps)
	}
	return found, nil
}

// MergePrefixes is the fewest IPv4 prefixes that cover exactly what these do:
// overlaps folded, adjacent ranges joined, each range cut into the largest
// aligned blocks it holds.
func MergePrefixes(in []netip.Prefix) []netip.Prefix {
	type span struct{ lo, hi uint64 } // hi is one past the end
	spans := make([]span, 0, len(in))
	for _, p := range in {
		p = p.Masked()
		if !p.Addr().Is4() {
			continue
		}
		lo := uint64(u32(p.Addr()))
		spans = append(spans, span{lo, lo + 1<<(32-p.Bits())})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })
	var merged []span
	for _, s := range spans {
		if n := len(merged); n > 0 && s.lo <= merged[n-1].hi {
			merged[n-1].hi = max(merged[n-1].hi, s.hi)
			continue
		}
		merged = append(merged, s)
	}
	out := []netip.Prefix{}
	for _, s := range merged {
		for lo := s.lo; lo < s.hi; {
			// The largest block that starts at lo, is aligned there, and fits.
			size := uint64(1)
			for size < 1<<32 && lo%(size*2) == 0 && lo+size*2 <= s.hi {
				size *= 2
			}
			bits := 32
			for b := size; b > 1; b >>= 1 {
				bits--
			}
			v := uint32(lo)
			out = append(out, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), bits))
			lo += size
		}
	}
	return out
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
