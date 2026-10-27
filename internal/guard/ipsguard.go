package guard

// May the IPS put this address on one of its drop lists?
//
// The IPS writes on its own, from a flow, with nobody looking: a rule decides
// and the address is listed. Its raw rules drop in PREROUTING, before the input
// chain, so a listed address that MikroDash, the operator's workstation or the
// router itself depends on is cut off with no warning and no way back from
// inside MikroDash. A warning has nobody to read it, so this guard REFUSES.
//
// ── WHAT IS NEVER LISTED ────────────────────────────────────────────────────
//
//   - anything that is not one unicast IPv4 address: the lists are IPv4 lists,
//     and an unspecified, loopback, multicast, link-local or broadcast address
//     is never a party to a flow worth blocking;
//   - every address the router itself holds (`/ip/address`);
//   - the addresses the router sees MikroDash from (`/user/active`, as
//     SelfAddresses reads it), past any NAT or container bridge;
//   - the sensor, whose own traffic must reach MikroDash;
//   - the operator's protected prefixes: their own workstation, a server, a
//     resolver - whatever they named in the IPS setup.
//
// FAILS CLOSED, unlike the L2 guards: if the router's addresses could not be
// read, nothing is listed. Those guards fail open because a refusal there blocks
// an operator at the keyboard; here it only delays an automatic block until the
// next read succeeds, and an unguarded automatic block is the worse mistake.

import (
	"net/netip"
	"strings"

	"mikrodash/internal/routeros"
)

// IPSProtected is everything the IPS may never list on one router.
type IPSProtected struct {
	// Resolved is whether the router's own addresses were read.
	Resolved bool
	Prefixes []netip.Prefix
}

// NewIPSProtected builds the protected set from the router's /ip/address rows,
// the addresses it sees MikroDash from, the sensor's address and the operator's
// own list. A value that does not parse is skipped, never widened.
func NewIPSProtected(addressRows []routeros.Reply, resolved bool, self []string, sensor string,
	operator []string) IPSProtected {

	p := IPSProtected{Resolved: resolved}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if strings.Contains(s, "/") {
			if pf, err := netip.ParsePrefix(s); err == nil {
				p.Prefixes = append(p.Prefixes, pf.Masked())
			}
			return
		}
		if a, err := netip.ParseAddr(s); err == nil {
			p.Prefixes = append(p.Prefixes, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		}
	}
	for _, r := range addressRows {
		// The router's own address, not its subnet: "10.0.0.1/24" protects
		// 10.0.0.1, and the LAN behind it stays listable.
		if a, _, ok := strings.Cut(r["address"], "/"); ok {
			add(a)
		}
	}
	for _, s := range self {
		add(s)
	}
	add(sensor)
	for _, s := range operator {
		add(s)
	}
	return p
}

// CheckIPSTarget judges one address the IPS wants to list. A refusal's Code
// says why: ips-unresolved, ips-not-ipv4, ips-special or ips-protected.
func CheckIPSTarget(p IPSProtected, target string) Verdict {
	refuse := func(code string) Verdict {
		return Verdict{Level: "refuse", Code: code, Detail: map[string]any{"value": target}}
	}
	if !p.Resolved {
		return refuse("ips-unresolved")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(target))
	if err != nil || !a.Unmap().Is4() {
		return refuse("ips-not-ipv4")
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() ||
		a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return refuse("ips-special")
	}
	for _, pf := range p.Prefixes {
		if pf.Contains(a) {
			return Verdict{Level: "refuse", Code: "ips-protected",
				Detail: map[string]any{"value": target, "prefix": pf.String()}}
		}
	}
	return Verdict{Level: "none"}
}
