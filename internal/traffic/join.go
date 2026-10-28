// Package traffic is the Traffic page's core: it joins what the router's
// Traffic Flow exports (volumes, internal/ipfix) with what the IPS sensor's
// nDPI named (the application), and adds the result up a minute at a time.
// Pure: records and classifications in, rows out. Storage is store.go and its
// two backends; the server feeds it and serves it.
//
// ── ONE CONNECTION, SEEN TWICE, UNDER TWO NAMES ─────────────────────────────
//
// The sensor sees a connection in the forward chain, after dst-nat and before
// src-nat: the LAN client's own address, the server's real one. Traffic Flow
// exports each DIRECTION of it as its own record, and a record may carry the
// addresses either side of the NAT, with the translation in its NAT fields.
// So a record is tried under every pairing of its plain and translated
// addresses, both ways round, against the connections the sensor named; the
// way round it matched in says whether the client sent it (Tx) or received it
// (Rx). Which pairing RouterOS uses is for a live capture to settle, and this
// does not need to know.
//
// ── WHAT NOBODY NAMED IS STILL COUNTED ──────────────────────────────────────
//
// A connection the sensor never saw (it was down, or the connection predates
// it) keeps its bytes: the LAN side is its host, the other its remote, and its
// application is the remote's organisation and the port it served, or Router
// for the router's own traffic. The share of bytes that found an application is
// reported, because that is the number that says whether the join works.
package traffic

import (
	"net/netip"
	"strconv"
	"time"

	"mikrodash/internal/ipfix"
)

// Unknown is the application of bytes nDPI did not name.
const Unknown = "Unknown"

// RouterApp is the application of the router's own traffic.
const RouterApp = "Router"

// connTTL is how long a classification outlives its last record.
const connTTL = 2 * time.Minute

// Class is what the sensor said about one connection.
type Class struct {
	App      string
	Category string
	// Country is the party on the internet's country, when the geo database knew.
	Country string
}

type connKey struct {
	proto          uint8
	client, server netip.AddrPort
}

type conn struct {
	class Class
	seen  time.Time
}

// Lookups are what the joiner may ask about an address it has no
// classification for. Either may be nil.
type Lookups struct {
	Country func(netip.Addr) string
	Org     func(netip.Addr) string
}

// Joiner holds one router's classified connections.
type Joiner struct {
	conns map[connKey]*conn
	look  Lookups
	// own is the router's own addresses: traffic from or to them is the router's.
	own map[netip.Addr]bool
}

// NewJoiner is an empty joiner.
func NewJoiner(look Lookups) *Joiner {
	return &Joiner{conns: map[connKey]*conn{}, look: look, own: map[netip.Addr]bool{}}
}

// SetOwn replaces the router's own addresses.
func (j *Joiner) SetOwn(addrs []netip.Addr) {
	own := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		own[a.Unmap()] = true
	}
	j.own = own
}

// Proto is an L4 name's IP protocol number; 0 for one this does not know.
func Proto(l4 string) uint8 {
	switch l4 {
	case "tcp", "TCP":
		return 6
	case "udp", "UDP":
		return 17
	case "icmp", "ICMP":
		return 1
	}
	return 0
}

// Classify records what the sensor named one connection.
func (j *Joiner) Classify(proto uint8, client, server netip.AddrPort, c Class, now time.Time) {
	if !client.IsValid() || !server.IsValid() {
		return
	}
	k := connKey{proto, unmap(client), unmap(server)}
	j.conns[k] = &conn{class: c, seen: now}
}

// Expire forgets the connections no record has touched within connTTL.
func (j *Joiner) Expire(now time.Time) {
	for k, c := range j.conns {
		if now.Sub(c.seen) > connTTL {
			delete(j.conns, k)
		}
	}
}

// Conns is how many classified connections the joiner holds.
func (j *Joiner) Conns() int { return len(j.conns) }

// Flow is one record, attributed: whose it was, to where, and what.
type Flow struct {
	Start, End time.Time
	Proto      uint8
	Host       netip.Addr
	HostPort   uint16
	Remote     netip.Addr
	RemotePort uint16
	App        string
	Category   string
	Country    string
	Org        string
	// Rx is bytes the host received, Tx bytes it sent: one of them is the record's.
	Rx, Tx  uint64
	Packets uint64
	// Named is whether the sensor's classification was found.
	Named bool
}

// Attribute names one record.
func (j *Joiner) Attribute(r ipfix.Record, now time.Time) Flow {
	f := Flow{Start: r.Start, End: r.End, Proto: r.Proto, Packets: r.Packets}
	srcs := sides(r.Src, r.SrcPort, r.NATSrc, r.NATSrcPort)
	dsts := sides(r.Dst, r.DstPort, r.NATDst, r.NATDstPort)
	for _, s := range srcs {
		for _, d := range dsts {
			if c := j.conns[connKey{r.Proto, s, d}]; c != nil {
				c.seen = now
				f.Host, f.HostPort, f.Remote, f.RemotePort = s.Addr(), s.Port(), d.Addr(), d.Port()
				f.Tx, f.Named = r.Bytes, true
				f.App, f.Category, f.Country = c.class.App, c.class.Category, c.class.Country
				return j.fill(f)
			}
			if c := j.conns[connKey{r.Proto, d, s}]; c != nil {
				c.seen = now
				f.Host, f.HostPort, f.Remote, f.RemotePort = d.Addr(), d.Port(), s.Addr(), s.Port()
				f.Rx, f.Named = r.Bytes, true
				f.App, f.Category, f.Country = c.class.App, c.class.Category, c.class.Country
				return j.fill(f)
			}
		}
	}
	// Unnamed: the LAN side is the host. A private source sent it; else a
	// private destination received it; else the router's own address is the
	// host; else it is transit and the source is taken as the host.
	host, remote, sent := srcs[0], dsts[0], true
	switch {
	case anyLocal(srcs, j.own):
		host, remote = pick(srcs, j.own), pick(dsts, nil)
	case anyLocal(dsts, j.own):
		host, remote, sent = pick(dsts, j.own), pick(srcs, nil), false
	}
	f.Host, f.HostPort, f.Remote, f.RemotePort = host.Addr(), host.Port(), remote.Addr(), remote.Port()
	if sent {
		f.Tx = r.Bytes
	} else {
		f.Rx = r.Bytes
	}
	if j.own[f.Host] {
		f.App = RouterApp
	}
	return j.fill(f)
}

// fill completes what the lookups can: the remote's country and organisation,
// and for an unnamed flow an application that says what is known.
func (j *Joiner) fill(f Flow) Flow {
	if f.Country == "" && j.look.Country != nil && public(f.Remote) {
		f.Country = j.look.Country(f.Remote)
	}
	if j.look.Org != nil && public(f.Remote) {
		f.Org = j.look.Org(f.Remote)
	}
	if f.App == "" {
		f.App = Unknown
	}
	if !f.Named && f.Category == "" {
		// What is known of it: the port it served. The organisation rides beside.
		f.Category = portName(f.Proto, f.RemotePort)
	}
	return f
}

// portName is "tcp/443".
func portName(proto uint8, port uint16) string {
	name := strconv.Itoa(int(proto))
	switch proto {
	case 6:
		name = "tcp"
	case 17:
		name = "udp"
	case 1:
		return "icmp"
	}
	return name + "/" + strconv.Itoa(int(port))
}

// sides is an endpoint as the record gave it, then as translated, without
// repeats or invalid ones; never empty.
func sides(a netip.Addr, p uint16, na netip.Addr, np uint16) []netip.AddrPort {
	out := []netip.AddrPort{netip.AddrPortFrom(a.Unmap(), p)}
	if na.IsValid() && !na.IsUnspecified() {
		if np == 0 {
			np = p
		}
		if t := netip.AddrPortFrom(na.Unmap(), np); t != out[0] {
			out = append(out, t)
		}
	}
	return out
}

func anyLocal(eps []netip.AddrPort, own map[netip.Addr]bool) bool {
	for _, e := range eps {
		if local(e.Addr(), own) {
			return true
		}
	}
	return false
}

// pick is the LAN endpoint (a private address before the router's own, since
// a reply's translated destination is the client behind the router), or with
// no own set the first public one; else the first.
func pick(eps []netip.AddrPort, own map[netip.Addr]bool) netip.AddrPort {
	for _, e := range eps {
		if own != nil && e.Addr().IsPrivate() || own == nil && public(e.Addr()) {
			return e
		}
	}
	for _, e := range eps {
		if own[e.Addr()] {
			return e
		}
	}
	return eps[0]
}

func local(a netip.Addr, own map[netip.Addr]bool) bool {
	return a.IsValid() && (a.IsPrivate() || own[a])
}

func public(a netip.Addr) bool {
	return a.IsValid() && a.IsGlobalUnicast() && !a.IsPrivate()
}

func unmap(ap netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) }
