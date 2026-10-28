// Package ipfix decodes the IPFIX messages (RFC 7011) a RouterOS router sends
// from /ip/traffic-flow, into the few fields the traffic page reads.
//
// ── PURE, AND ONE DECODER PER EXPORTER ──────────────────────────────────────
//
// A data record means nothing without the template it was written against,
// and templates are per exporter and observation domain. A Decoder holds one
// exporter's templates; the receiver keeps one per router. Bytes in, records
// out, no I/O, so the tests replay messages byte for byte.
//
// ── STANDARD ELEMENTS ONLY ──────────────────────────────────────────────────
//
// Fields are read by their IANA Information Element ids. An element this
// package does not read is skipped by its length, an enterprise element too, so
// a template carrying more than the router was asked for still decodes.
//
// ── WHAT IS LOST IS COUNTED ─────────────────────────────────────────────────
//
// IPFIX over UDP has no retransmission. The header's sequence number counts
// the data records sent before the message; Decoder.Lost adds up every gap, so
// the page can say how much it did not see rather than under-report silently.
package ipfix

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Version is IPFIX's version number; NetFlow v9 is 9 and is not read here.
const Version = 10

// Set ids below 256 are templates; 256 and up name a data set's template.
const (
	setTemplate        = 2
	setOptionsTemplate = 3
	minDataSet         = 256
)

// Information Element ids (IANA "IPFIX Information Elements").
const (
	ieOctetDelta      = 1
	iePacketDelta     = 2
	ieProtocol        = 4
	ieSrcPort         = 7
	ieSrcIPv4         = 8
	ieIngress         = 10
	ieDstPort         = 11
	ieDstIPv4         = 12
	ieEgress          = 14
	ieFlowEndUptime   = 21
	ieFlowStartUptime = 22
	ieSrcIPv6         = 27
	ieDstIPv6         = 28
	ieFlowStartMillis = 152
	ieFlowEndMillis   = 153
	ieSysInitMillis   = 160
	ieNATSrcIPv4      = 225
	ieNATDstIPv4      = 226
	ieNATSrcPort      = 227
	ieNATDstPort      = 228
	ieNATSrcIPv6      = 281
	ieNATDstIPv6      = 282
)

// varLen is the length a template gives a variable-length field.
const varLen = 0xffff

// Header is a message's header.
type Header struct {
	Version    uint16
	Length     uint16
	ExportTime time.Time
	Seq        uint32
	Domain     uint32
}

// Record is one flow record: a direction of a connection over the router's
// export interval. A zero Addr or port is a field the template did not carry.
type Record struct {
	Proto            uint8
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	// The NAT fields: what the router translated the source or destination to.
	NATSrc, NATDst         netip.Addr
	NATSrcPort, NATDstPort uint16
	Bytes, Packets         uint64
	In, Out                uint32
	Start, End             time.Time
}

type field struct {
	id     uint16
	length uint16
	ent    bool
}

type template struct {
	fields []field
	// min is the shortest a record can be: fixed fields, one byte per variable one.
	min int
}

type tkey struct {
	domain uint32
	id     uint16
}

// Decoder holds one exporter's templates and what it has lost.
type Decoder struct {
	templates map[tkey]template
	// sysInit is each domain's boot time, from systemInitTimeMilliseconds:
	// the base that flowStartSysUpTime and flowEndSysUpTime count from.
	sysInit map[uint32]time.Time
	next    map[uint32]uint32 // the sequence number each domain's next message should carry
	// Lost is the data records the sequence numbers say never arrived.
	Lost uint64
	// Unknown is the data records skipped because their template has not been seen yet.
	Unknown uint64
}

// NewDecoder is a decoder with no templates yet.
func NewDecoder() *Decoder {
	return &Decoder{templates: map[tkey]template{}, sysInit: map[uint32]time.Time{}, next: map[uint32]uint32{}}
}

// ErrNotIPFIX is a message that is not IPFIX version 10.
var ErrNotIPFIX = errors.New("not an IPFIX message")

// Decode reads one message: it learns its templates and returns its flow
// records. A malformed set ends the message; the records before it are kept.
func (d *Decoder) Decode(msg []byte) (Header, []Record, error) {
	var h Header
	if len(msg) < 16 {
		return h, nil, ErrNotIPFIX
	}
	h.Version = binary.BigEndian.Uint16(msg)
	if h.Version != Version {
		return h, nil, ErrNotIPFIX
	}
	h.Length = binary.BigEndian.Uint16(msg[2:])
	h.ExportTime = time.Unix(int64(binary.BigEndian.Uint32(msg[4:])), 0)
	h.Seq = binary.BigEndian.Uint32(msg[8:])
	h.Domain = binary.BigEndian.Uint32(msg[12:])
	if int(h.Length) > len(msg) || h.Length < 16 {
		return h, nil, fmt.Errorf("ipfix: the header says %d bytes, %d arrived", h.Length, len(msg))
	}
	if want, ok := d.next[h.Domain]; ok && h.Seq != want {
		// Ahead is records lost; behind is a reordered or restarted exporter,
		// which is not counted as a loss.
		if gap := h.Seq - want; gap < 1<<31 {
			d.Lost += uint64(gap)
		}
	}
	var out []Record
	data := 0
	unknown := false
	body := msg[16:h.Length]
	for len(body) >= 4 {
		id := binary.BigEndian.Uint16(body)
		n := int(binary.BigEndian.Uint16(body[2:]))
		if n < 4 || n > len(body) {
			d.next[h.Domain] = h.Seq + uint32(data)
			return h, out, fmt.Errorf("ipfix: a set of %d bytes in %d", n, len(body))
		}
		set := body[4:n]
		body = body[n:]
		switch {
		case id == setTemplate:
			d.templatesFrom(h.Domain, set, false)
		case id == setOptionsTemplate:
			d.templatesFrom(h.Domain, set, true)
		case id >= minDataSet:
			t, ok := d.templates[tkey{h.Domain, id}]
			if !ok {
				// How many records it held is unknowable, so the next message's
				// sequence number cannot be checked against this one.
				d.Unknown++
				unknown = true
				continue
			}
			for len(set) >= t.min && t.min > 0 {
				r, used, ok := d.record(h, t, set)
				if !ok {
					break
				}
				set = set[used:]
				data++
				if r != nil {
					out = append(out, *r)
				}
			}
		}
	}
	if unknown {
		delete(d.next, h.Domain)
	} else {
		d.next[h.Domain] = h.Seq + uint32(data)
	}
	return h, out, nil
}

// templatesFrom learns (or withdraws) the templates in one template set.
func (d *Decoder) templatesFrom(domain uint32, set []byte, options bool) {
	head := 4
	if options {
		head = 6
	}
	for len(set) >= head {
		id := binary.BigEndian.Uint16(set)
		count := int(binary.BigEndian.Uint16(set[2:]))
		set = set[head:]
		if id < minDataSet {
			return // padding, or nonsense
		}
		if count == 0 {
			delete(d.templates, tkey{domain, id})
			continue
		}
		t := template{}
		for i := 0; i < count; i++ {
			if len(set) < 4 {
				return
			}
			f := field{id: binary.BigEndian.Uint16(set), length: binary.BigEndian.Uint16(set[2:])}
			set = set[4:]
			if f.id&0x8000 != 0 {
				f.id &^= 0x8000
				f.ent = true
				if len(set) < 4 {
					return
				}
				set = set[4:]
			}
			if f.length == varLen {
				t.min++
			} else {
				t.min += int(f.length)
			}
			t.fields = append(t.fields, f)
		}
		d.templates[tkey{domain, id}] = t
	}
}

// record reads one data record. It returns nil for a record that is not a
// flow (an options record, which may carry the exporter's boot time), how many
// bytes it used, and false when the rest of the set is too short to be one.
func (d *Decoder) record(h Header, t template, b []byte) (*Record, int, bool) {
	var r Record
	var startUp, endUp, startMs, endMs uint64
	var hasStartUp, hasEndUp, flow bool
	used := 0
	for _, f := range t.fields {
		n := int(f.length)
		if f.length == varLen {
			if used >= len(b) {
				return nil, 0, false
			}
			n = int(b[used])
			used++
			if n == 255 {
				if used+2 > len(b) {
					return nil, 0, false
				}
				n = int(binary.BigEndian.Uint16(b[used:]))
				used += 2
			}
		}
		if used+n > len(b) {
			return nil, 0, false
		}
		v := b[used : used+n]
		used += n
		if f.ent {
			continue
		}
		switch f.id {
		case ieOctetDelta:
			r.Bytes = uintOf(v)
		case iePacketDelta:
			r.Packets = uintOf(v)
		case ieProtocol:
			r.Proto = uint8(uintOf(v))
		case ieSrcPort:
			r.SrcPort = uint16(uintOf(v))
		case ieDstPort:
			r.DstPort = uint16(uintOf(v))
		case ieNATSrcPort:
			r.NATSrcPort = uint16(uintOf(v))
		case ieNATDstPort:
			r.NATDstPort = uint16(uintOf(v))
		case ieSrcIPv4, ieSrcIPv6:
			r.Src, flow = addrOf(v), true
		case ieDstIPv4, ieDstIPv6:
			r.Dst, flow = addrOf(v), true
		case ieNATSrcIPv4, ieNATSrcIPv6:
			r.NATSrc = addrOf(v)
		case ieNATDstIPv4, ieNATDstIPv6:
			r.NATDst = addrOf(v)
		case ieIngress:
			r.In = uint32(uintOf(v))
		case ieEgress:
			r.Out = uint32(uintOf(v))
		case ieFlowStartUptime:
			startUp, hasStartUp = uintOf(v), true
		case ieFlowEndUptime:
			endUp, hasEndUp = uintOf(v), true
		case ieFlowStartMillis:
			startMs = uintOf(v)
		case ieFlowEndMillis:
			endMs = uintOf(v)
		case ieSysInitMillis:
			d.sysInit[h.Domain] = time.UnixMilli(int64(uintOf(v)))
		}
	}
	if !flow {
		return nil, used, true
	}
	r.Start, r.End = h.ExportTime, h.ExportTime
	if init, ok := d.sysInit[h.Domain]; ok {
		if hasStartUp {
			r.Start = init.Add(time.Duration(startUp) * time.Millisecond)
		}
		if hasEndUp {
			r.End = init.Add(time.Duration(endUp) * time.Millisecond)
		}
	}
	if startMs != 0 {
		r.Start = time.UnixMilli(int64(startMs))
	}
	if endMs != 0 {
		r.End = time.UnixMilli(int64(endMs))
	}
	return &r, used, true
}

// uintOf reads an unsigned integer of any length up to eight bytes: IPFIX
// allows an exporter to send a counter in fewer bytes than its type
// (reduced-size encoding, RFC 7011 section 6.2).
func uintOf(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

func addrOf(b []byte) netip.Addr {
	a, _ := netip.AddrFromSlice(b)
	return a.Unmap()
}
