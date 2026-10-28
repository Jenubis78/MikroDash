package server

// The Traffic page's engine: it takes the routers' IPFIX on one UDP port,
// names each record with what the IPS sensor classified (internal/traffic),
// and writes a minute of rows at a time to the backend chosen in the page's
// settings: /data/traffic.db, or ClickHouse.
//
// ── NOTHING LISTENS UNTIL A ROUTER IS SET UP ────────────────────────────────
//
// The UDP port is opened when the first router's Traffic Flow has been
// applied, and closed when the last is removed: an install that never uses the
// page has no port open for it.
//
// ── A PACKET IS A ROUTER'S ONLY IF IT COMES FROM ONE OF ITS ADDRESSES ───────
//
// IPFIX has no authentication. A datagram is read only when its source is an
// address of a router set up here (its /ip/address list, read every few
// minutes over its session, or the address MikroDash reaches it at); any
// other sender is counted and dropped.
//
// ── OR THE SENSOR, WHEN IT SEES EVERY PACKET ────────────────────────────────
//
// A router whose IPS sensor inspects every packet needs no Traffic Flow: the
// sensor counts each connection's bytes and sends them every few seconds
// (ips.LiveBytesEvery), already beside the application it named. Such a
// router is fed by the sensor alone - IPFIX from it is counted and ignored, so
// nothing is counted twice - and its Live tab is a rate over the last
// traffic.WindowSpan instead of the last finished minute. Its flows are kept a
// row per connection per minute.
//
// ── THE STORE NEVER HOLDS UP THE READ ───────────────────────────────────────
//
// The UDP loop only decodes and adds up. Once a minute another goroutine takes
// the finished minutes and writes them; a backend that is down keeps up to
// trafficBacklog minutes waiting and says so on the page, and Live goes on
// from memory.

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"mikrodash/internal/asn"
	"mikrodash/internal/db"
	"mikrodash/internal/geo"
	"mikrodash/internal/ipfix"
	"mikrodash/internal/ips"
	"mikrodash/internal/routeros"
	"mikrodash/internal/safe"
	"mikrodash/internal/traffic"
)

const (
	trafficHold       = "traffic"
	trafficRing       = 15 * time.Minute
	trafficRingMax    = 100000
	trafficBacklog    = 120 // minutes of rows kept while the backend is down
	trafficAddrsEvery = 5 * time.Minute
	trafficWriteWait  = 30 * time.Second
)

type trafficEngine struct {
	s      *Server
	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	settings db.TrafficSettings
	store    traffic.Store
	storeErr string
	routers  map[string]*trafficRouter
	byAddr   map[netip.Addr]string
	conn     *net.UDPConn
	port     int
	listen   string // why the port is not open, when it is not
	strays   uint64 // datagrams from no router's address
	opening  bool   // a reopen is under way
}

type trafficRouter struct {
	id   string
	drop func()

	mu       sync.Mutex
	joiner   *traffic.Joiner
	agg      *traffic.Aggregator
	decoders map[netip.Addr]*ipfix.Decoder
	pending  []traffic.RouterFlow // this minute's flows, for a backend that keeps them
	backlog  []traffic.Agg        // rows a failed write left
	ring     []traffic.RouterFlow // the last trafficRing, newest last
	live     []traffic.Agg        // the last finished minute
	liveAt   time.Time
	records  uint64
	lastAt   time.Time
	// sensorFed: the IPS sensor's counts are this router's volumes, not IPFIX.
	sensorFed bool
	ignored   uint64 // IPFIX records not counted, the sensor being the source
	window    traffic.Window
	connMin   map[string]*traffic.RouterFlow // this minute's flows, a row per connection
}

func (s *Server) buildTraffic() *trafficEngine {
	ctx, cancel := context.WithCancel(context.Background())
	e := &trafficEngine{s: s, ctx: ctx, cancel: cancel, routers: map[string]*trafficRouter{}, byAddr: map[netip.Addr]string{}}
	if s.auditDB == nil {
		return e
	}
	set, err := s.auditDB.TrafficSettingsGet()
	if err != nil {
		log.Printf("[traffic] reading the settings: %v", err)
		set = db.DefaultTrafficSettings
	}
	// THE STACK'S CLICKHOUSE, WHEN THERE IS ONE: its password is made here,
	// before ClickHouse starts (it waits for MikroDash to be healthy), and an
	// install that never chose a backend takes it.
	if s.chStack.URL != "" {
		if err := s.chStack.ensureSecret(); err != nil {
			log.Printf("[traffic] the stack's ClickHouse password: %v", err)
		} else if !set.Saved {
			set.Backend = trafficBackendStack
			if err := s.auditDB.SaveTrafficSettings(set); err == nil {
				log.Printf("[traffic] the stack has ClickHouse at %s: Traffic Analysis keeps its history there", s.chStack.URL)
			}
		}
	}
	e.applySettings(set)
	e.sync()
	go e.minutes()
	go e.addresses()
	return e
}

// Stop closes the port and the store and stops every loop.
func (e *trafficEngine) Stop() {
	e.cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn != nil {
		e.conn.Close()
		e.conn = nil
	}
	for id, r := range e.routers {
		r.drop()
		delete(e.routers, id)
	}
	if e.store != nil {
		e.store.Close()
		e.store = nil
	}
}

// openStore opens the backend the settings name.
func (e *trafficEngine) openStore(set db.TrafficSettings) (traffic.Store, error) {
	switch set.Backend {
	case "clickhouse", trafficBackendStack:
		cfg := traffic.ClickHouseConfig{URL: set.CHURL, User: set.CHUser, Password: e.s.openCredSecret(set.CHPassword),
			Database: set.CHDatabase, FlowDays: set.FlowDays}
		if set.Backend == trafficBackendStack {
			var err error
			if cfg, err = e.s.chStack.config(set.FlowDays); err != nil {
				return nil, err
			}
		}
		ctx, cancel := context.WithTimeout(e.ctx, trafficWriteWait)
		defer cancel()
		return traffic.OpenClickHouse(ctx, cfg, nil)
	}
	if e.s.store == nil {
		return nil, errors.New("no data directory")
	}
	return traffic.OpenSQLite(e.sqlitePath())
}

func (e *trafficEngine) sqlitePath() string { return filepath.Join(e.s.store.Dir, "traffic.db") }

// applySettings switches to new settings: the port moved at once, the
// backend reopened in the background, since a ClickHouse can take its time to
// answer, or not be up yet (the stack's starts after MikroDash). Until it
// opens the rows wait in the backlog, and a backend that does not open is
// tried again every minute (flush).
func (e *trafficEngine) applySettings(set db.TrafficSettings) {
	e.mu.Lock()
	if e.store != nil {
		e.store.Close()
	}
	e.settings, e.store, e.storeErr = set, nil, "opening"
	if e.conn != nil && e.port != set.Port {
		e.conn.Close()
		e.conn = nil
	}
	e.listenLocked()
	e.mu.Unlock()
	go e.reopen()
}

// reopen opens the backend the settings name, unless one is open or being
// opened; then, for ClickHouse, imports what SQLite still holds.
func (e *trafficEngine) reopen() {
	e.mu.Lock()
	if e.store != nil || e.opening {
		e.mu.Unlock()
		return
	}
	e.opening = true
	set := e.settings
	e.mu.Unlock()
	st, err := e.openStore(set)
	e.mu.Lock()
	e.opening = false
	if e.settings != set {
		// Changed while opening: the newer settings' own reopen wins.
		e.mu.Unlock()
		if st != nil {
			st.Close()
		}
		go e.reopen()
		return
	}
	if err != nil {
		e.storeErr = err.Error()
		e.mu.Unlock()
		log.Printf("[traffic] opening the %s backend: %v", set.Backend, err)
		return
	}
	e.store, e.storeErr = st, ""
	e.mu.Unlock()
	if st.Backend() == "clickhouse" {
		e.importSQLite(st)
	}
}

// importSQLite moves the SQLite history into ClickHouse once, when the
// backend becomes ClickHouse with traffic.db still there; the file is then
// renamed, so its rows are never imported twice and stay on disk.
func (e *trafficEngine) importSQLite(st traffic.Store) {
	if e.s.store == nil {
		return
	}
	path := e.sqlitePath()
	if _, err := os.Stat(path); err != nil {
		return
	}
	src, err := traffic.OpenSQLite(path)
	if err != nil {
		log.Printf("[traffic] importing the SQLite history: %v", err)
		return
	}
	n := 0
	err = src.Export(e.ctx, func(rid string, rows []traffic.Agg) error {
		ctx, cancel := context.WithTimeout(e.ctx, 2*trafficWriteWait)
		defer cancel()
		n += len(rows)
		return st.Write(ctx, rid, rows, nil)
	})
	src.Close()
	if err != nil {
		log.Printf("[traffic] importing the SQLite history (%d rows sent): %v; it is tried again at the next open", n, err)
		return
	}
	done := path + ".imported-" + time.Now().UTC().Format("20060102-150405")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); err == nil {
			if err := os.Rename(path+suffix, done+suffix); err != nil {
				log.Printf("[traffic] renaming %s: %v", path+suffix, err)
			}
		}
	}
	log.Printf("[traffic] imported %d rows of SQLite history into ClickHouse; the file is kept as %s", n, done)
}

// sync starts and stops routers to match the routers table.
func (e *trafficEngine) sync() {
	rows, err := e.s.auditDB.TrafficRouters()
	if err != nil {
		log.Printf("[traffic] reading the routers: %v", err)
		return
	}
	want := map[string]bool{}
	for _, r := range rows {
		if r.Enabled {
			want[r.RouterID] = true
		}
	}
	fed := map[string]bool{}
	if sensors, err := e.s.auditDB.IPSSensors(); err == nil {
		for _, sn := range sensors {
			if sn.EveryPacket {
				want[sn.RouterID], fed[sn.RouterID] = true, true
			}
		}
	}
	e.mu.Lock()
	for id, r := range e.routers {
		if !want[id] {
			r.drop()
			delete(e.routers, id)
		}
	}
	for id := range want {
		if e.routers[id] == nil {
			e.routers[id] = e.newRouter(id)
		}
		r := e.routers[id]
		r.mu.Lock()
		r.sensorFed = fed[id]
		r.mu.Unlock()
	}
	e.listenLocked()
	e.mu.Unlock()
	if e.s.sessions != nil {
		go e.refreshAddresses()
	}
}

func (e *trafficEngine) newRouter(id string) *trafficRouter {
	look := traffic.Lookups{}
	if gdb, ok := geo.Current(); ok {
		look.Country = func(a netip.Addr) string {
			if loc, found := gdb.Lookup(a.String()); found {
				return loc.Country
			}
			return ""
		}
	}
	if adb, ok := asn.Current(); ok {
		look.Org = func(a netip.Addr) string {
			org, _, _ := adb.Lookup(a.String())
			return org
		}
	}
	r := &trafficRouter{id: id, joiner: traffic.NewJoiner(look), agg: traffic.NewAggregator(),
		decoders: map[netip.Addr]*ipfix.Decoder{}, drop: func() {}}
	// A hold, as the IPS reader's: it keeps the session the address reads go
	// through, and starts no collector.
	if e.s.sessions == nil {
		return r // no session manager: a test, or a server without routers
	}
	if _, err := e.s.sessions.Retain(id, trafficHold); err == nil {
		r.drop = func() { e.s.sessions.Drop(id, trafficHold) }
	}
	return r
}

// listenLocked opens the port when a router needs it and closes it when none
// does. Called with mu held.
func (e *trafficEngine) listenLocked() {
	ipfixFed := 0
	for _, r := range e.routers {
		r.mu.Lock()
		if !r.sensorFed {
			ipfixFed++
		}
		r.mu.Unlock()
	}
	if ipfixFed == 0 {
		if e.conn != nil {
			e.conn.Close()
			e.conn = nil
		}
		e.listen = "no router takes its volumes from Traffic Flow"
		return
	}
	if e.conn != nil {
		return
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: e.settings.Port})
	if err != nil {
		e.listen = err.Error()
		log.Printf("[traffic] listening on udp/%d: %v", e.settings.Port, err)
		return
	}
	_ = conn.SetReadBuffer(4 << 20)
	e.conn, e.port, e.listen = conn, e.settings.Port, ""
	go e.read(conn)
}

// read is the UDP loop: one datagram is one IPFIX message.
func (e *trafficEngine) read(conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // closed
		}
		src := from.Addr().Unmap()
		e.mu.Lock()
		rid, ok := e.byAddr[src]
		r := e.routers[rid]
		keep := e.store != nil && e.store.Backend() == "clickhouse"
		if !ok || r == nil {
			e.strays++
		}
		e.mu.Unlock()
		if r != nil {
			r.take(src, buf[:n], keep, time.Now())
		}
	}
}

// take decodes one message and adds its records up.
func (r *trafficRouter) take(src netip.Addr, msg []byte, keep bool, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.decoders[src]
	if d == nil {
		d = ipfix.NewDecoder()
		r.decoders[src] = d
	}
	_, recs, err := d.Decode(msg)
	if err != nil && len(recs) == 0 {
		return
	}
	if r.sensorFed {
		r.ignored += uint64(len(recs))
		return
	}
	for _, rec := range recs {
		f := r.joiner.Attribute(rec, now)
		r.agg.Add(f, now)
		row := f.Row()
		if keep {
			r.pending = append(r.pending, row)
		}
		r.ring = append(r.ring, row)
	}
	r.records += uint64(len(recs))
	r.lastAt = now
	if len(r.ring) > trafficRingMax {
		r.ring = r.ring[len(r.ring)-trafficRingMax:]
	}
}

// takeCounts adds a sensor's counts up: the minute, the Live window, and a
// row per connection for the minute's flows.
func (r *trafficRouter) takeCounts(counts []ips.ConnBytes, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.sensorFed {
		return
	}
	if r.connMin == nil {
		r.connMin = map[string]*traffic.RouterFlow{}
	}
	for _, c := range counts {
		proto := traffic.Proto(c.L4)
		f := r.joiner.AttributeConn(proto, netip.AddrPortFrom(c.Client, c.ClientPort),
			netip.AddrPortFrom(c.Server, c.ServerPort), c.Tx, c.Rx, now)
		r.agg.Add(f, now)
		r.window.Add(f, now)
		k := c.L4 + " " + netip.AddrPortFrom(c.Client, c.ClientPort).String() + " " +
			netip.AddrPortFrom(c.Server, c.ServerPort).String()
		row := r.connMin[k]
		if row == nil {
			v := f.Row()
			r.connMin[k] = &v
			continue
		}
		row.Rx += f.Rx
		row.Tx += f.Tx
		row.End = f.End
		if row.App == traffic.Unknown && f.Named {
			row.App, row.Category, row.Country = f.App, f.Category, f.Country
		}
	}
	r.records += uint64(len(counts))
	r.lastAt = now
}

// classify is the IPS sensor naming a connection on a router.
func (e *trafficEngine) classify(routerID string, f ips.Flow) {
	if e == nil {
		return
	}
	e.mu.Lock()
	r := e.routers[routerID]
	e.mu.Unlock()
	if r == nil {
		return
	}
	client, err1 := netip.ParseAddr(f.Client)
	server, err2 := netip.ParseAddr(f.Server)
	if err1 != nil || err2 != nil {
		return
	}
	_, country, _ := f.Remote()
	c := traffic.Class{App: firstNonEmpty(f.App, f.Name), Category: f.Category, Country: country}
	r.mu.Lock()
	r.joiner.Classify(traffic.Proto(f.L4), netip.AddrPortFrom(client, uint16(f.ClientPort)),
		netip.AddrPortFrom(server, uint16(f.ServerPort)), c, time.Now())
	r.mu.Unlock()
}

// sensorBytes is the IPS sensor's counts for a router that it feeds.
func (e *trafficEngine) sensorBytes(routerID string, counts []ips.ConnBytes) {
	if e == nil {
		return
	}
	e.mu.Lock()
	r := e.routers[routerID]
	e.mu.Unlock()
	if r == nil {
		return
	}
	r.takeCounts(counts, time.Now())
}

// minutes writes each router's finished minutes, a few seconds after each
// minute turns, then lets the backend roll up and age out.
func (e *trafficEngine) minutes() {
	for {
		now := time.Now()
		next := now.Truncate(time.Minute).Add(time.Minute + 5*time.Second)
		select {
		case <-e.ctx.Done():
			return
		case <-time.After(next.Sub(now)):
		}
		e.flush(time.Now())
	}
}

func (e *trafficEngine) flush(now time.Time) {
	e.mu.Lock()
	if e.store == nil && !e.opening {
		go e.reopen() // a backend that did not open is tried again every minute
	}
	st := e.store
	routers := make([]*trafficRouter, 0, len(e.routers))
	for _, r := range e.routers {
		routers = append(routers, r)
	}
	e.mu.Unlock()
	var failed error
	keep := st != nil && st.Backend() == "clickhouse"
	for _, r := range routers {
		r.mu.Lock()
		for _, row := range r.connMin {
			if keep {
				r.pending = append(r.pending, *row)
			}
			r.ring = append(r.ring, *row)
		}
		r.connMin = nil
		if len(r.ring) > trafficRingMax {
			r.ring = r.ring[len(r.ring)-trafficRingMax:]
		}
		r.joiner.Expire(now)
		rows := r.agg.Take(now)
		if len(rows) > 0 {
			r.live, r.liveAt = rows, now.Truncate(time.Minute).Add(-time.Minute)
		}
		rows = append(r.backlog, rows...)
		flows := r.pending
		r.pending = nil
		cut := now.Add(-trafficRing)
		i := 0
		for i < len(r.ring) && r.ring[i].End.Before(cut) {
			i++
		}
		r.ring = r.ring[i:]
		r.mu.Unlock()
		if st == nil || len(rows) == 0 && len(flows) == 0 {
			r.keepBacklog(rows)
			continue
		}
		ctx, cancel := context.WithTimeout(e.ctx, trafficWriteWait)
		err := st.Write(ctx, r.id, rows, flows)
		cancel()
		if err != nil {
			failed = err
			r.keepBacklog(rows)
			continue
		}
		r.keepBacklog(nil)
	}
	if st == nil {
		return
	}
	ctx, cancel := context.WithTimeout(e.ctx, trafficWriteWait)
	if err := st.Maintain(ctx, now); err != nil && failed == nil {
		failed = err
	}
	cancel()
	e.mu.Lock()
	if e.store == st {
		e.storeErr = ""
		if failed != nil {
			e.storeErr = failed.Error()
			log.Printf("[traffic] writing to %s: %v", st.Backend(), failed)
		}
	}
	e.mu.Unlock()
}

// keepBacklog keeps the newest trafficBacklog minutes of rows a write left.
func (r *trafficRouter) keepBacklog(rows []traffic.Agg) {
	if len(rows) > 0 {
		cut := rows[len(rows)-1].TS.Add(-trafficBacklog * time.Minute)
		i := 0
		for i < len(rows) && rows[i].TS.Before(cut) {
			i++
		}
		rows = rows[i:]
	}
	r.mu.Lock()
	r.backlog = rows
	r.mu.Unlock()
}

// addresses re-reads the routers' own addresses every few minutes.
func (e *trafficEngine) addresses() {
	t := time.NewTicker(trafficAddrsEvery)
	defer t.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
			e.refreshAddresses()
		}
	}
}

// refreshAddresses maps each set-up router's addresses to it: what its
// /ip/address holds, and what its configured host resolves to.
func (e *trafficEngine) refreshAddresses() {
	e.mu.Lock()
	ids := make([]string, 0, len(e.routers))
	for id := range e.routers {
		ids = append(ids, id)
	}
	e.mu.Unlock()
	hosts := map[string]string{}
	if e.s.store != nil {
		all, _ := e.s.store.Routers()
		for _, r := range all {
			hosts[r.ID] = r.Host
		}
	}
	by := map[netip.Addr]string{}
	owns := map[string][]netip.Addr{}
	for _, id := range ids {
		var own []netip.Addr
		// Retain is idempotent by name: this is the router's own hold, fetched.
		sn, err := e.s.sessions.Retain(id, trafficHold)
		e.mu.Lock()
		gone := e.routers[id] == nil
		e.mu.Unlock()
		if gone && err == nil {
			// Removed since the list was taken: give its hold back.
			e.s.sessions.Drop(id, trafficHold)
			continue
		}
		if err == nil && sn != nil {
			rows, err := sn.Exec(routeros.Cmd{Path: "/ip/address/print", Args: []string{"=.proplist=address"},
				Timeout: ipsCmdTimeout})
			if err == nil {
				for _, row := range rows {
					if p, err := netip.ParsePrefix(row["address"]); err == nil {
						own = append(own, p.Addr().Unmap())
					}
				}
			}
		}
		if h := hosts[id]; h != "" {
			ctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
			addrs, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", h)
			cancel()
			for _, a := range addrs {
				own = append(own, a.Unmap())
			}
		}
		for _, a := range own {
			by[a] = id
		}
		owns[id] = own
	}
	e.mu.Lock()
	e.byAddr = by
	for id, own := range owns {
		if r := e.routers[id]; r != nil {
			r.mu.Lock()
			r.joiner.SetOwn(own)
			r.mu.Unlock()
		}
	}
	e.mu.Unlock()
}

// TrafficStatus is how the collection is going, for one router.
type TrafficStatus struct {
	Enabled    bool    `json:"enabled"`
	Listening  bool    `json:"listening"`
	Port       int     `json:"port"`
	Listen     string  `json:"listen"`
	Backend    string  `json:"backend"`
	StoreError string  `json:"storeError"`
	Records    uint64  `json:"records"`
	Lost       uint64  `json:"lost"`
	Unknown    uint64  `json:"unknown"`
	LastAt     int64   `json:"lastAt"`
	Coverage   float64 `json:"coverage"` // the share of bytes that found an application, 0..1
	Conns      int     `json:"conns"`
	Strays     uint64  `json:"strays"`
	Addresses  int     `json:"addresses"`
	// Source is where the volumes come from: "ipfix" (Traffic Flow) or
	// "sensor" (the IPS sensor, inspecting every packet).
	Source string `json:"source"`
	// Ignored is IPFIX records from a router the sensor feeds.
	Ignored uint64 `json:"ignored"`
}

// status is a router's collection status, what Live adds up, when that span
// started and how many seconds it covers: the last finished minute, or for a
// router the sensor feeds, the last traffic.WindowSpan.
func (e *trafficEngine) status(rid string) (TrafficStatus, []traffic.Agg, time.Time, int) {
	e.mu.Lock()
	st := TrafficStatus{Listening: e.conn != nil, Port: e.settings.Port, Listen: safe.Message(e.listen),
		Backend: e.settings.Backend, StoreError: safe.Message(e.storeErr), Strays: e.strays}
	r := e.routers[rid]
	for _, id := range e.byAddr {
		if id == rid {
			st.Addresses++
		}
	}
	e.mu.Unlock()
	if r == nil {
		return st, []traffic.Agg{}, time.Time{}, 60
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st.Enabled, st.Records, st.Conns, st.Ignored, st.Source = true, r.records, r.joiner.Conns(), r.ignored, "ipfix"
	for _, d := range r.decoders {
		st.Lost += d.Lost
		st.Unknown += d.Unknown
	}
	if !r.lastAt.IsZero() {
		st.LastAt = r.lastAt.UnixMilli()
	}
	if r.agg.Total > 0 {
		st.Coverage = float64(r.agg.Named) / float64(r.agg.Total)
	}
	if r.sensorFed {
		st.Source = "sensor"
		now := time.Now()
		rows, secs := r.window.Rows(now)
		if secs == 0 {
			return st, []traffic.Agg{}, time.Time{}, 0
		}
		return st, rows, now.Truncate(traffic.WindowStep).Add(-time.Duration(secs) * time.Second), secs
	}
	return st, append([]traffic.Agg{}, r.live...), r.liveAt, 60
}

// recentFlows is the memory's flows that answer a search, newest first.
func (e *trafficEngine) recentFlows(q traffic.FlowQuery) []traffic.RouterFlow {
	e.mu.Lock()
	r := e.routers[q.RouterID]
	e.mu.Unlock()
	out := []traffic.RouterFlow{}
	if r == nil {
		return out
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.ring) - 1; i >= 0 && len(out) < q.Limit; i-- {
		if q.Matches(r.ring[i]) {
			out = append(out, r.ring[i])
		}
	}
	return out
}

// currentStore is the backend, or nil with why.
func (e *trafficEngine) currentStore() (traffic.Store, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.store == nil {
		return nil, firstNonEmpty(e.storeErr, "no backend is open")
	}
	return e.store, ""
}

func (e *trafficEngine) currentSettings() db.TrafficSettings {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.settings
}
