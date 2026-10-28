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
	"path/filepath"
	"sync"
	"time"

	"mikrodash/internal/asn"
	"mikrodash/internal/db"
	"mikrodash/internal/geo"
	"mikrodash/internal/ipfix"
	"mikrodash/internal/ips"
	"mikrodash/internal/routeros"
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
	if set.Backend == "clickhouse" {
		ctx, cancel := context.WithTimeout(e.ctx, trafficWriteWait)
		defer cancel()
		return traffic.OpenClickHouse(ctx, traffic.ClickHouseConfig{URL: set.CHURL, User: set.CHUser,
			Password: e.s.openCredSecret(set.CHPassword), Database: set.CHDatabase, FlowDays: set.FlowDays}, nil)
	}
	if e.s.store == nil {
		return nil, errors.New("no data directory")
	}
	return traffic.OpenSQLite(filepath.Join(e.s.store.Dir, "traffic.db"))
}

// applySettings switches to new settings: the backend reopened, the port
// moved. A backend that does not open leaves the engine with none, which the
// page shows; the rows wait in the backlog.
func (e *trafficEngine) applySettings(set db.TrafficSettings) {
	st, err := e.openStore(set)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.store != nil {
		e.store.Close()
	}
	e.settings, e.store, e.storeErr = set, st, ""
	if err != nil {
		e.store, e.storeErr = nil, err.Error()
		log.Printf("[traffic] opening the %s backend: %v", set.Backend, err)
	}
	if e.conn != nil && e.port != set.Port {
		e.conn.Close()
		e.conn = nil
	}
	e.listenLocked()
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
	}
	e.listenLocked()
	e.mu.Unlock()
	go e.refreshAddresses()
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
	if _, err := e.s.sessions.Retain(id, trafficHold); err == nil {
		r.drop = func() { e.s.sessions.Drop(id, trafficHold) }
	}
	return r
}

// listenLocked opens the port when a router needs it and closes it when none
// does. Called with mu held.
func (e *trafficEngine) listenLocked() {
	if len(e.routers) == 0 {
		if e.conn != nil {
			e.conn.Close()
			e.conn = nil
		}
		e.listen = "no router is set up"
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
	st := e.store
	routers := make([]*trafficRouter, 0, len(e.routers))
	for _, r := range e.routers {
		routers = append(routers, r)
	}
	e.mu.Unlock()
	var failed error
	for _, r := range routers {
		r.mu.Lock()
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
}

// status is a router's collection status, its last finished minute, and
// when that minute started.
func (e *trafficEngine) status(rid string) (TrafficStatus, []traffic.Agg, time.Time) {
	e.mu.Lock()
	st := TrafficStatus{Listening: e.conn != nil, Port: e.settings.Port, Listen: e.listen, Backend: e.settings.Backend,
		StoreError: e.storeErr, Strays: e.strays}
	r := e.routers[rid]
	for _, id := range e.byAddr {
		if id == rid {
			st.Addresses++
		}
	}
	e.mu.Unlock()
	if r == nil {
		return st, []traffic.Agg{}, time.Time{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st.Enabled, st.Records, st.Conns = true, r.records, r.joiner.Conns()
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
	return st, append([]traffic.Agg{}, r.live...), r.liveAt
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
