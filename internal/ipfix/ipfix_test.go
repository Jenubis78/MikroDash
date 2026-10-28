package ipfix

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// msg builds a message: the header, then each set as given (id, body).
func msg(seq, domain uint32, export int64, sets ...[]byte) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint16(b, Version)
	binary.BigEndian.PutUint32(b[4:], uint32(export))
	binary.BigEndian.PutUint32(b[8:], seq)
	binary.BigEndian.PutUint32(b[12:], domain)
	for _, s := range sets {
		b = append(b, s...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func set(id uint16, body ...[]byte) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b, id)
	for _, x := range body {
		b = append(b, x...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }
func ip(s string) []byte  { return netip.MustParseAddr(s).AsSlice() }

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// tmpl is a template record: id, then (element, length) pairs.
func tmpl(id uint16, fields ...uint16) []byte {
	b := cat(u16(id), u16(uint16(len(fields)/2)))
	for _, f := range fields {
		b = append(b, u16(f)...)
	}
	return b
}

// The router's flow template as MikroDash asks for it: addresses, ports, the
// NAT translation, counters, interfaces and the uptime timestamps.
var natTemplate = tmpl(256,
	ieSrcIPv4, 4, ieDstIPv4, 4, ieSrcPort, 2, ieDstPort, 2, ieProtocol, 1,
	ieNATSrcIPv4, 4, ieNATSrcPort, 2, ieNATDstIPv4, 4, ieNATDstPort, 2,
	ieOctetDelta, 8, iePacketDelta, 4, ieIngress, 4, ieEgress, 4, ieFlowStartUptime, 4, ieFlowEndUptime, 4)

func natRecord(bytes uint64, startUp, endUp uint32) []byte {
	return cat(ip("192.168.11.20"), ip("142.250.1.1"), u16(51544), u16(443), []byte{6},
		ip("198.51.100.2"), u16(40001), ip("142.250.1.1"), u16(443),
		u64(bytes), u32(12), u32(5), u32(1), u32(startUp), u32(endUp))
}

func TestATemplateThenItsRecordsDecodeEveryField(t *testing.T) {
	d := NewDecoder()
	boot := time.UnixMilli(1_790_000_000_000)
	// The exporter's boot time comes in an options record (scope: the domain).
	opts := set(setOptionsTemplate, cat(u16(300), u16(2), u16(1), u16(149), u16(4), u16(ieSysInitMillis), u16(8)))
	m := msg(0, 7, 1_790_000_100, opts, set(setTemplate, natTemplate),
		set(300, cat(u32(7), u64(uint64(boot.UnixMilli())))),
		set(256, natRecord(1500, 60_000, 90_000), natRecord(64, 61_000, 62_000)))
	h, recs, err := d.Decode(m)
	if err != nil || h.Domain != 7 || len(recs) != 2 {
		t.Fatalf("%v %+v %d records", err, h, len(recs))
	}
	r := recs[0]
	if r.Src.String() != "192.168.11.20" || r.Dst.String() != "142.250.1.1" || r.SrcPort != 51544 || r.DstPort != 443 ||
		r.Proto != 6 || r.NATSrc.String() != "198.51.100.2" || r.NATSrcPort != 40001 || r.NATDst.String() != "142.250.1.1" ||
		r.NATDstPort != 443 || r.Bytes != 1500 || r.Packets != 12 || r.In != 5 || r.Out != 1 {
		t.Errorf("%+v", r)
	}
	if !r.Start.Equal(boot.Add(time.Minute)) || !r.End.Equal(boot.Add(90*time.Second)) {
		t.Errorf("times from the boot time and the uptimes: %v %v", r.Start, r.End)
	}
	if d.Lost != 0 || d.Unknown != 0 {
		t.Errorf("lost %d unknown %d", d.Lost, d.Unknown)
	}
}

func TestRecordsBeforeTheirTemplateAreCountedNotGuessed(t *testing.T) {
	d := NewDecoder()
	_, recs, err := d.Decode(msg(0, 1, 1, set(256, natRecord(1, 0, 0))))
	if err != nil || len(recs) != 0 || d.Unknown != 1 {
		t.Fatalf("%v %d %d", err, len(recs), d.Unknown)
	}
	// The template arrives; the next message decodes, and the skipped set is
	// not mistaken for lost records.
	_, recs, _ = d.Decode(msg(5, 1, 1, set(setTemplate, natTemplate), set(256, natRecord(9, 0, 0))))
	if len(recs) != 1 || recs[0].Bytes != 9 || d.Lost != 0 {
		t.Errorf("%+v lost %d", recs, d.Lost)
	}
}

func TestAGapInTheSequenceIsCountedAsLost(t *testing.T) {
	d := NewDecoder()
	d.Decode(msg(0, 1, 1, set(setTemplate, natTemplate), set(256, natRecord(1, 0, 0), natRecord(1, 0, 0))))
	d.Decode(msg(2, 1, 1, set(256, natRecord(1, 0, 0))))  // in order
	d.Decode(msg(10, 1, 1, set(256, natRecord(1, 0, 0)))) // 7 records never arrived
	d.Decode(msg(4, 1, 1, set(256, natRecord(1, 0, 0))))  // late or restarted: not a loss
	if d.Lost != 7 {
		t.Errorf("lost %d, want 7", d.Lost)
	}
}

func TestReducedSizeVariableLengthAndEnterpriseFieldsAreRead(t *testing.T) {
	d := NewDecoder()
	// octetDeltaCount in 4 bytes instead of 8, a variable-length enterprise
	// element (id 0x8000|5, enterprise 14988) between, IPv6 addresses.
	tm := cat(u16(257), u16(4), u16(ieOctetDelta), u16(4), u16(0x8000|5), u16(varLen), u32(14988),
		u16(ieSrcIPv6), u16(16), u16(ieDstIPv6), u16(16))
	rec := cat(u32(70000), []byte{3}, []byte("abc"), ip("2001:db8::1"), ip("2001:db8::2"))
	_, recs, err := d.Decode(msg(0, 1, 1, set(setTemplate, tm), set(257, rec, []byte{0, 0})))
	if err != nil || len(recs) != 1 || recs[0].Bytes != 70000 || recs[0].Src.String() != "2001:db8::1" ||
		recs[0].Dst.String() != "2001:db8::2" {
		t.Fatalf("%v %+v", err, recs)
	}
}

func TestAWithdrawnTemplateStopsDecodingAndGarbageIsRefused(t *testing.T) {
	d := NewDecoder()
	d.Decode(msg(0, 1, 1, set(setTemplate, natTemplate)))
	d.Decode(msg(0, 1, 1, set(setTemplate, cat(u16(256), u16(0)))))
	if _, recs, _ := d.Decode(msg(0, 1, 1, set(256, natRecord(1, 0, 0)))); len(recs) != 0 {
		t.Error("a withdrawn template still decoded")
	}
	if _, _, err := d.Decode([]byte{0, 9, 0, 20}); err != ErrNotIPFIX {
		t.Errorf("short: %v", err)
	}
	bad := msg(0, 1, 1, set(setTemplate, natTemplate))
	binary.BigEndian.PutUint16(bad[18:], 9999) // a set longer than the message
	if _, _, err := d.Decode(bad); err == nil {
		t.Error("an overlong set must be an error")
	}
}
