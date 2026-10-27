package guard

import (
	"testing"

	"mikrodash/internal/routeros"
)

func ipsProtected() IPSProtected {
	rows := []routeros.Reply{{"address": "192.168.88.1/24"}, {"address": "198.51.100.2/30"}}
	return NewIPSProtected(rows, true, []string{"192.168.88.10"}, "172.31.255.2",
		[]string{"192.168.88.50", "10.20.0.0/16", "not-an-address"})
}

func TestTheIPSNeverListsWhatItDependsOn(t *testing.T) {
	p := ipsProtected()
	for target, code := range map[string]string{
		"192.168.88.1":    "ips-protected", // the router, on the LAN
		"198.51.100.2":    "ips-protected", // the router, on the WAN
		"192.168.88.10":   "ips-protected", // where the router sees MikroDash from
		"172.31.255.2":    "ips-protected", // the sensor
		"192.168.88.50":   "ips-protected", // the operator's own
		"10.20.3.4":       "ips-protected", // inside the operator's prefix
		"0.0.0.0":         "ips-special",
		"127.0.0.1":       "ips-special",
		"224.0.0.251":     "ips-special",
		"169.254.1.1":     "ips-special",
		"255.255.255.255": "ips-special",
		"2001:db8::1":     "ips-not-ipv4",
		"example.com":     "ips-not-ipv4",
	} {
		v := CheckIPSTarget(p, target)
		if !v.Refused() || v.Code != code {
			t.Errorf("%s: %+v, want a refusal %s", target, v, code)
		}
	}
}

func TestTheIPSListsAnOrdinaryAddress(t *testing.T) {
	p := ipsProtected()
	// The LAN behind the router's address is listable: protecting the router's
	// /24 would make quarantine useless.
	for _, target := range []string{"192.168.88.23", "203.0.113.7", "::ffff:203.0.113.7"} {
		if v := CheckIPSTarget(p, target); v.Level != "none" {
			t.Errorf("%s: %+v, want none", target, v)
		}
	}
}

func TestTheIPSListsNothingWhenTheRoutersAddressesAreUnknown(t *testing.T) {
	p := NewIPSProtected(nil, false, nil, "", nil)
	if v := CheckIPSTarget(p, "203.0.113.7"); !v.Refused() || v.Code != "ips-unresolved" {
		t.Fatalf("an unread router: %+v, want ips-unresolved", v)
	}
}
