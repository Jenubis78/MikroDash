package server

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"mikrodash/internal/db"
	"mikrodash/internal/ips"
)

const ipsTestFlow = `{"type":"flow","ts":1,"l4":"tcp","client":"192.168.88.20","clientPort":50000,` +
	`"server":"203.0.113.7","serverPort":6881,"name":"BitTorrent","app":"BitTorrent","master":"Unknown",` +
	`"category":"Download","breed":"Acceptable","host":"","risks":[],"guessed":false,"packets":3,"bytes":400}`

func testReader(enforce bool, rules []ips.Rule) *ipsReader {
	e := &ipsEngine{s: &Server{}, rules: rules, readers: map[string]*ipsReader{}}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	return &ipsReader{e: e, routerID: "r1", cfg: db.IPSSensor{RouterID: "r1", Enforce: enforce, Token: "0123456789abcdef"},
		writes: make(chan ipsWrite, 2), apps: map[string]*IPSAppCount{}, listed: map[string]time.Time{}}
}

func flowFrom(t *testing.T, line string) ips.Flow {
	t.Helper()
	l, err := ips.ParseLine([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	return *l.Flow
}

var p2pBlock = []ips.Rule{{ID: 1, Name: "p2p", Enabled: true, Apps: []string{"BitTorrent"}, Action: ips.ActionBlock, TimeoutMin: 60}}

func TestAWatchingSensorListsNothingAndSaysWhatItWouldHaveDone(t *testing.T) {
	r := testReader(false, p2pBlock)
	f := flowFrom(t, ipsTestFlow)
	r.handle(f)
	r.handle(f)
	st, flows, apps := r.snapshot()
	if len(r.writes) != 0 {
		t.Fatal("a sensor that only watches must not queue a write")
	}
	if st.Seen != 2 || len(flows) != 2 || flows[0].Result != "monitor" || flows[0].Action != ips.ActionBlock {
		t.Errorf("status %+v, flows %+v", st, flows)
	}
	if len(apps) != 1 || apps[0].Name != "BitTorrent" || apps[0].Flows != 2 || apps[0].Bytes != 800 {
		t.Errorf("apps %+v", apps)
	}
}

func TestAnEnforcingSensorQueuesOneListingPerAddress(t *testing.T) {
	r := testReader(true, p2pBlock)
	f := flowFrom(t, ipsTestFlow)
	r.handle(f)
	r.handle(f) // the same server again: already on its way
	if len(r.writes) != 1 {
		t.Fatalf("queued %d writes, want 1", len(r.writes))
	}
	w := <-r.writes
	if w.d.Target != "203.0.113.7" || w.d.List != ips.BlockList {
		t.Errorf("write %+v", w.d)
	}
	_, flows, _ := r.snapshot()
	if flows[0].Result != "already" || flows[1].Result != "queued" {
		t.Errorf("results %q %q", flows[0].Result, flows[1].Result)
	}
}

func TestAFullQueueIsRecordedNotWaitedFor(t *testing.T) {
	r := testReader(true, p2pBlock)
	for i, server := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		f := flowFrom(t, strings.Replace(ipsTestFlow, "203.0.113.7", server, 1))
		r.handle(f)
		_, flows, _ := r.snapshot()
		want := "queued"
		if i == 2 {
			want = "limited" // the queue holds two
		}
		if flows[0].Result != want {
			t.Errorf("flow %d: %q, want %q", i, flows[0].Result, want)
		}
	}
	if st, _, _ := r.snapshot(); st.Limited != 1 {
		t.Errorf("limited = %d", st.Limited)
	}
}

func TestAFlowNoRuleMatchesIsOnlyCounted(t *testing.T) {
	r := testReader(true, nil)
	r.handle(flowFrom(t, ipsTestFlow))
	_, flows, _ := r.snapshot()
	if len(r.writes) != 0 || flows[0].Action != "" || flows[0].Result != "" {
		t.Errorf("an unmatched flow: %+v", flows[0])
	}
}

// fakeSensor answers one connection the way dpi-sensor/ does.
func fakeSensor(t *testing.T, token string, lines ...string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		hello, _ := bufio.NewReader(c).ReadString('\n')
		if strings.TrimSpace(hello) != "HELLO "+token {
			_, _ = c.Write([]byte(`{"type":"error","message":"bad token"}` + "\n"))
			return
		}
		for _, l := range lines {
			_, _ = c.Write([]byte(l + "\n"))
		}
	}()
	return ln.Addr().String()
}

func readFrom(t *testing.T, r *ipsReader, addr string) (bool, error) {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	r.cfg.Address = host
	old := ipsReaderPort
	ipsReaderPort = port
	defer func() { ipsReaderPort = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return r.readOnce(ctx)
}

func TestTheReaderSendsItsTokenAndReadsEveryLine(t *testing.T) {
	r := testReader(false, p2pBlock)
	addr := fakeSensor(t, r.cfg.Token, `{"type":"hello","version":"1","ndpi":"4.14"}`,
		`{"type":"stats","packets":10}`, "not json", ipsTestFlow)
	connected, err := readFrom(t, r, addr)
	if !connected || err != nil {
		t.Fatalf("connected=%v err=%v", connected, err)
	}
	st, flows, _ := r.snapshot()
	if st.State != "connected" || st.NDPI != "4.14" || st.Stats == nil || st.Stats.Packets != 10 || len(flows) != 1 {
		t.Errorf("status %+v flows %d", st, len(flows))
	}
}

func TestARefusedTokenIsTold(t *testing.T) {
	r := testReader(false, nil)
	addr := fakeSensor(t, "another-token-entirely")
	connected, err := readFrom(t, r, addr)
	var refused errRefused
	if connected || !errors.As(err, &refused) || !strings.Contains(err.Error(), "bad token") {
		t.Fatalf("connected=%v err=%v", connected, err)
	}
}
