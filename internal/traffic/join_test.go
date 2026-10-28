package traffic

import (
	"net/netip"
	"testing"
	"time"

	"mikrodash/internal/ipfix"
)

var t0 = time.Date(2026, 10, 28, 14, 0, 30, 0, time.UTC)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
func ad(s string) netip.Addr     { return netip.MustParseAddr(s) }

// The sensor named one outbound connection: the LAN client to YouTube.
func youtube() *Joiner {
	j := NewJoiner(Lookups{Country: func(netip.Addr) string { return "US" }, Org: func(netip.Addr) string { return "Google" }})
	j.SetOwn([]netip.Addr{ad("198.51.100.2")})
	j.Classify(6, ap("192.168.11.20:51544"), ap("142.250.1.1:443"), Class{App: "YouTube", Category: "Media", Country: "US"}, t0)
	return j
}

// Each way RouterOS may write the two directions of that connection: plain
// pre-NAT addresses, or the translated ones with the original in the NAT fields.
func TestBothDirectionsOfANATedConnectionFindTheirApplication(t *testing.T) {
	for name, tc := range map[string]struct {
		r      ipfix.Record
		rx, tx uint64
	}{
		"upload, pre-NAT source": {ipfix.Record{Proto: 6, Src: ad("192.168.11.20"), SrcPort: 51544, Dst: ad("142.250.1.1"), DstPort: 443,
			NATSrc: ad("198.51.100.2"), NATSrcPort: 40001, Bytes: 100}, 0, 100},
		"upload, post-NAT source": {ipfix.Record{Proto: 6, Src: ad("198.51.100.2"), SrcPort: 40001, Dst: ad("142.250.1.1"), DstPort: 443,
			NATSrc: ad("192.168.11.20"), NATSrcPort: 51544, Bytes: 100}, 0, 100},
		"download, to the router, NAT back to the client": {ipfix.Record{Proto: 6, Src: ad("142.250.1.1"), SrcPort: 443,
			Dst: ad("198.51.100.2"), DstPort: 40001, NATDst: ad("192.168.11.20"), NATDstPort: 51544, Bytes: 9000}, 9000, 0},
		"download, already to the client": {ipfix.Record{Proto: 6, Src: ad("142.250.1.1"), SrcPort: 443,
			Dst: ad("192.168.11.20"), DstPort: 51544, Bytes: 9000}, 9000, 0},
	} {
		f := youtube().Attribute(tc.r, t0)
		if !f.Named || f.App != "YouTube" || f.Host != ad("192.168.11.20") || f.Remote != ad("142.250.1.1") ||
			f.Rx != tc.rx || f.Tx != tc.tx || f.Country != "US" || f.Org != "Google" {
			t.Errorf("%s: %+v", name, f)
		}
	}
}

func TestAnUnnamedConnectionKeepsItsBytesUnderItsLANHost(t *testing.T) {
	j := youtube()
	// A download nobody classified, translated back to a LAN client.
	f := j.Attribute(ipfix.Record{Proto: 17, Src: ad("9.9.9.9"), SrcPort: 53, Dst: ad("198.51.100.2"), DstPort: 30000,
		NATDst: ad("192.168.11.30"), NATDstPort: 5353, Bytes: 80}, t0)
	if f.Named || f.App != Unknown || f.Host != ad("192.168.11.30") || f.Remote != ad("9.9.9.9") || f.Rx != 80 ||
		f.Category != "udp/53" || f.Org != "Google" {
		t.Errorf("unnamed download: %+v", f)
	}
	// The router's own query.
	f = j.Attribute(ipfix.Record{Proto: 17, Src: ad("198.51.100.2"), SrcPort: 41000, Dst: ad("1.1.1.1"), DstPort: 53, Bytes: 60}, t0)
	if f.App != RouterApp || f.Host != ad("198.51.100.2") || f.Tx != 60 {
		t.Errorf("router's own: %+v", f)
	}
}

func TestAClassificationOutlivesItsLastRecordByTheTTLOnly(t *testing.T) {
	j := youtube()
	up := ipfix.Record{Proto: 6, Src: ad("192.168.11.20"), SrcPort: 51544, Dst: ad("142.250.1.1"), DstPort: 443, Bytes: 1}
	j.Attribute(up, t0.Add(time.Minute)) // a record keeps it alive
	j.Expire(t0.Add(time.Minute + connTTL))
	if j.Conns() != 1 {
		t.Fatal("a connection with a recent record was forgotten")
	}
	j.Expire(t0.Add(2*time.Minute + connTTL))
	if j.Conns() != 0 || j.Attribute(up, t0).Named {
		t.Error("an idle classification outlived its TTL")
	}
}

func TestMinutesAreTakenOnceAndLateRecordsCountInTheOpenMinute(t *testing.T) {
	j := youtube()
	a := NewAggregator()
	up := ipfix.Record{Proto: 6, Src: ad("192.168.11.20"), SrcPort: 51544, Dst: ad("142.250.1.1"), DstPort: 443, Bytes: 100, End: t0}
	down := ipfix.Record{Proto: 6, Src: ad("142.250.1.1"), SrcPort: 443, Dst: ad("192.168.11.20"), DstPort: 51544, Bytes: 900, End: t0}
	a.Add(j.Attribute(up, t0), t0)
	a.Add(j.Attribute(down, t0), t0)
	if got := a.Take(t0); len(got) != 0 {
		t.Fatalf("the open minute was taken: %+v", got)
	}
	rows := a.Take(t0.Add(time.Minute))
	if len(rows) != 1 || rows[0].App != "YouTube" || rows[0].Rx != 900 || rows[0].Tx != 100 || rows[0].Flows != 1 ||
		!rows[0].TS.Equal(t0.Truncate(time.Minute)) {
		t.Fatalf("%+v", rows)
	}
	// A record for the minute already taken lands in the open one.
	a.Add(j.Attribute(up, t0), t0.Add(time.Minute))
	rows = a.Take(t0.Add(2 * time.Minute))
	if len(rows) != 1 || !rows[0].TS.Equal(t0.Truncate(time.Minute).Add(time.Minute)) {
		t.Errorf("late: %+v", rows)
	}
	if a.Named != 1100 || a.Total != 1100 {
		t.Errorf("coverage %d/%d", a.Named, a.Total)
	}
}
