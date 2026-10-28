package geo

import (
	"net/netip"
	"strings"
	"testing"
)

func prefixes(ss ...string) []netip.Prefix {
	out := []netip.Prefix{}
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func joined(ps []netip.Prefix) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.String())
	}
	return strings.Join(s, " ")
}

func TestMergePrefixesFoldsWhatACityDatabaseCuts(t *testing.T) {
	for in, want := range map[string]string{
		// Two halves are their whole.
		"10.0.0.0/25 10.0.0.128/25": "10.0.0.0/24",
		// Four quarters, out of order, are their whole.
		"10.0.0.192/26 10.0.0.0/26 10.0.0.128/26 10.0.0.64/26": "10.0.0.0/24",
		// A block inside another disappears.
		"10.0.0.0/16 10.0.5.0/24": "10.0.0.0/16",
		// Adjacent but not aligned: the fewest aligned blocks.
		"10.0.1.0/24 10.0.2.0/24":             "10.0.1.0/24 10.0.2.0/24",
		"10.0.1.0/24 10.0.2.0/23":             "10.0.1.0/24 10.0.2.0/23",
		"10.0.1.0/24 10.0.2.0/24 10.0.3.0/24": "10.0.1.0/24 10.0.2.0/23",
		// Apart stays apart; a single address stays a /32.
		"192.0.2.7/32 203.0.113.0/24": "192.0.2.7/32 203.0.113.0/24",
		// The whole space.
		"0.0.0.0/1 128.0.0.0/1": "0.0.0.0/0",
		// The last address of the space does not overflow.
		"255.255.255.254/31 255.255.255.0/25": "255.255.255.0/25 255.255.255.254/31",
	} {
		if got := joined(MergePrefixes(prefixes(strings.Fields(in)...))); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
	if got := MergePrefixes(nil); got == nil || len(got) != 0 {
		t.Errorf("nothing in, %v out", got)
	}
}

func TestALegacyDatabaseCannotBeWalked(t *testing.T) {
	if _, err := (&DB{}).CountryNetworks([]string{"FR"}); err != ErrNoNetworks {
		t.Errorf("the legacy backend: %v", err)
	}
	if _, err := (*DB)(nil).Countries(); err != ErrNoNetworks {
		t.Errorf("no database: %v", err)
	}
}
