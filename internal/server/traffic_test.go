package server

import (
	"context"
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"mikrodash/internal/ipfix"
	"mikrodash/internal/ips"
	"mikrodash/internal/traffic"
)

// ipfixMessage is one IPFIX message: a template for (src, dst, ports,
// protocol, bytes) and one record per `recs`.
func ipfixMessage(seq uint32, recs ...[5]any) []byte {
	be := binary.BigEndian
	tmpl := []uint16{256, 6, 8, 4, 12, 4, 7, 2, 11, 2, 4, 1, 1, 8}
	tset := make([]byte, 4)
	for _, v := range tmpl {
		tset = be.AppendUint16(tset, v)
	}
	be.PutUint16(tset, 2)
	be.PutUint16(tset[2:], uint16(len(tset)))
	dset := make([]byte, 4)
	for _, r := range recs {
		dset = append(dset, netip.MustParseAddr(r[0].(string)).AsSlice()...)
		dset = append(dset, netip.MustParseAddr(r[1].(string)).AsSlice()...)
		dset = be.AppendUint16(dset, r[2].(uint16))
		dset = be.AppendUint16(dset, r[3].(uint16))
		dset = append(dset, 6)
		dset = be.AppendUint64(dset, r[4].(uint64))
	}
	be.PutUint16(dset, 256)
	be.PutUint16(dset[2:], uint16(len(dset)))
	msg := make([]byte, 16)
	be.PutUint16(msg, ipfix.Version)
	be.PutUint32(msg[4:], uint32(time.Now().Unix()))
	be.PutUint32(msg[8:], seq)
	msg = append(append(msg, tset...), dset...)
	be.PutUint16(msg[2:], uint16(len(msg)))
	return msg
}

// What the IPS sensor named is what the IPFIX bytes of that connection are
// counted under, and the finished minute lands in the backend.
func TestTheSensorsNameReachesTheStoredMinute(t *testing.T) {
	st, err := traffic.OpenSQLite(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	e := &trafficEngine{s: &Server{}, store: st, routers: map[string]*trafficRouter{}, byAddr: map[netip.Addr]string{}}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	defer e.Stop()
	r := &trafficRouter{id: "r1", joiner: traffic.NewJoiner(traffic.Lookups{}), agg: traffic.NewAggregator(),
		decoders: map[netip.Addr]*ipfix.Decoder{}, drop: func() {}}
	e.routers["r1"] = r

	e.classify("r1", ips.Flow{L4: "tcp", Client: "192.168.11.20", ClientPort: 51544, Server: "142.250.1.1",
		ServerPort: 443, App: "YouTube", Category: "Media", ServerCountry: "US"})
	e.classify("r2", ips.Flow{L4: "tcp", Client: "192.168.11.20"}) // a router not set up: ignored
	now := time.Now()
	r.take(netip.MustParseAddr("192.168.11.1"), ipfixMessage(0,
		[5]any{"192.168.11.20", "142.250.1.1", uint16(51544), uint16(443), uint64(1000)},
		[5]any{"142.250.1.1", "192.168.11.20", uint16(443), uint16(51544), uint64(50000)},
		[5]any{"192.168.11.30", "9.9.9.9", uint16(5353), uint16(53), uint64(80)}), false, now)

	e.flush(now.Add(time.Minute))
	got, err := st.Top(context.Background(), traffic.Query{RouterID: "r1", Dim: traffic.DimApp,
		From: now.Add(-time.Hour), To: now.Add(time.Hour)})
	if err != nil || len(got) != 2 || got[0].Key != "YouTube" || got[0].Rx != 50000 || got[0].Tx != 1000 ||
		got[1].Key != traffic.Unknown || got[1].Tx != 80 {
		t.Fatalf("%v %+v", err, got)
	}
	status, live, at := e.status("r1")
	if status.Records != 3 || len(live) != 2 || at.IsZero() || status.Coverage < 0.99 {
		t.Errorf("status %+v live %+v", status, live)
	}
	if fl := e.recentFlows(traffic.FlowQuery{RouterID: "r1", App: "YouTube", Limit: 10}); len(fl) != 2 {
		t.Errorf("memory flows: %+v", fl)
	}
}

// A backend that is down keeps the rows for the next minute, and says why.
func TestRowsWaitWhileTheBackendIsDown(t *testing.T) {
	e := &trafficEngine{s: &Server{}, routers: map[string]*trafficRouter{}, byAddr: map[netip.Addr]string{}, storeErr: "down"}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	defer e.Stop()
	r := &trafficRouter{id: "r1", joiner: traffic.NewJoiner(traffic.Lookups{}), agg: traffic.NewAggregator(),
		decoders: map[netip.Addr]*ipfix.Decoder{}, drop: func() {}}
	e.routers["r1"] = r
	now := time.Now()
	r.take(netip.MustParseAddr("192.168.11.1"), ipfixMessage(0,
		[5]any{"192.168.11.20", "142.250.1.1", uint16(51544), uint16(443), uint64(1000)}), false, now)
	e.flush(now.Add(time.Minute))
	if len(r.backlog) != 1 {
		t.Fatalf("backlog %+v", r.backlog)
	}
	st, err := traffic.OpenSQLite(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	e.store = st
	e.flush(now.Add(2 * time.Minute))
	if len(r.backlog) != 0 || e.storeErr != "" {
		t.Errorf("after recovery: backlog %d, error %q", len(r.backlog), e.storeErr)
	}
	got, _ := st.Top(context.Background(), traffic.Query{RouterID: "r1", Dim: traffic.DimHost, From: now.Add(-time.Hour), To: now.Add(time.Hour)})
	if len(got) != 1 || got[0].Tx != 1000 {
		t.Errorf("%+v", got)
	}
}
