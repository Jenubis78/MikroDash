package server

// The IPS page's engine: one reader per router that has a sensor, each reading
// classified flows from dpi-sensor/ and acting on what internal/ips decides.
//
// ── ONE READER PER SENSOR, FOR AS LONG AS THE SENSOR IS CONFIGURED ──────────
//
// A router with a row in ips_sensors has a reader whether or not anybody has
// the page open: an IPS that stops when the tab closes is not one. The reader
// holds the router's session (a `Retain` named "ips"), dials the sensor, sends
// the token, and reads one JSON line at a time. A sensor that cannot be reached
// is retried with a growing pause; one that refuses the token is retried slowly,
// because only a configuration change can fix that. `sync` starts and stops
// readers to match the table, and runs after every save.
//
// ── THE READ LOOP NEVER WAITS FOR THE ROUTER ────────────────────────────────
//
// A verdict that lists an address is a router write, and a router can take its
// whole timeout to answer. Writes go through a bounded queue to one writer
// goroutine; a flow that finds the queue full is recorded as `limited` rather
// than slowing the read of every flow behind it. So is a listing past
// ipsListPerMinute: a rule that matches everything must not turn into thousands
// of writes a minute.
//
// ── WHAT IS RECORDED ────────────────────────────────────────────────────────
//
// Every flow goes into the router's in-memory window (the page's Flows tab).
// A flow a rule matched with log, block or quarantine is also an ips_events row,
// up to ipsEventsPerMinute a router; past that it is counted, not written. A
// block of an address already listed is not recorded again until its entry has
// timed out: one row says the server was listed, not one per connection to it.
// The same decision again within ipsRepeatWindow (same rule, result, client,
// server and port) is a hit on its row, not a row: the hits are added once a
// minute in one transaction, and a router keeps its newest ipsEventsKeep rows.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mikrodash/internal/db"
	"mikrodash/internal/geo"
	"mikrodash/internal/guard"
	"mikrodash/internal/ips"
	"mikrodash/internal/routeros"
	"mikrodash/internal/safe"
	"mikrodash/internal/session"
)

const (
	ipsRiskClients     = 1000
	ipsRiskApps        = 8
	ipsFlowWindow      = 300
	ipsListPerMinute   = 60
	ipsEventsPerMinute = 240
	ipsRepeatWindow    = 10 * time.Minute
	ipsEventsKeep      = 500000
	ipsFlushEvery      = time.Minute
	ipsWriteQueue      = 256
	ipsProtectedEvery  = 5 * time.Minute
	ipsDialTimeout     = 5 * time.Second
	ipsIdleTimeout     = 30 * time.Second // the sensor sends stats every 5 s
	ipsRetryMin        = 5 * time.Second
	ipsRetryMax        = time.Minute
	ipsRetryRefused    = 5 * time.Minute
	ipsCmdTimeout      = 15 * time.Second
)

// ipsReaderPort is where the sensor is read: ips.ReaderPort, a variable so a
// test can point the reader at a listener of its own.
var ipsReaderPort = strconv.Itoa(ips.ReaderPort)

// IPSFlowView is one flow in the page's window, with what the rules made of it.
type IPSFlowView struct {
	ips.Flow
	Action string `json:"action"`
	Rule   string `json:"rule"`
	Result string `json:"result"`
	// Severity is the worst of the flow's risks, as nDPI ranks them; "" with none.
	Severity string `json:"severity"`
}

// IPSRiskCount is one risk's share of the flows since the reader started:
// the Risks tab.
type IPSRiskCount struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Flows    int    `json:"flows"`
	// Clients is how many distinct clients raised it, up to ipsRiskClients.
	Clients int `json:"clients"`
	// Apps are the applications it was seen on, the first ipsRiskApps.
	Apps   []string `json:"apps"`
	LastTS int64    `json:"lastTs"`
	// LastClient and LastServer are the flow that raised it last.
	LastClient string `json:"lastClient"`
	LastServer string `json:"lastServer"`

	clients map[string]bool
}

// IPSAppCount is one application's share of the flows since the reader started.
type IPSAppCount struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Flows    int    `json:"flows"`
	Bytes    int64  `json:"bytes"`
}

// IPSStatus is one router's reader, as the page shows it.
type IPSStatus struct {
	// State is off (no sensor), connecting, connected, unreachable or refused.
	State   string     `json:"state"`
	Message string     `json:"message"`
	Since   int64      `json:"since"`
	Sensor  string     `json:"sensor"`
	NDPI    string     `json:"ndpi"`
	Enforce bool       `json:"enforce"`
	Stats   *ips.Stats `json:"stats"`
	// Counters since the reader started.
	Seen    int64 `json:"seen"`
	Listed  int64 `json:"listed"`
	Refused int64 `json:"refused"`
	Limited int64 `json:"limited"`
	Failed  int64 `json:"failed"`
}

type ipsEngine struct {
	s      *Server
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	readers map[string]*ipsReader
	rules   []ips.Rule
	// geoJobs is each router's geofencing apply, running or last run; see
	// ips_geo.go.
	geoJobs map[string]*IPSGeoJob
}

type ipsReader struct {
	e        *ipsEngine
	routerID string
	cfg      db.IPSSensor // Token unsealed
	cancel   context.CancelFunc
	writes   chan ipsWrite
	// sn is the router's session, for a DHCP sensor's lease; nil in a test.
	sn *session.Session

	mu sync.Mutex
	// addr is where the sensor is read: the configured address, or a DHCP
	// sensor's lease as last read off its veth.
	addr      string
	status    IPSStatus
	flows     []IPSFlowView // newest last
	apps      map[string]*IPSAppCount
	risks     map[string]*IPSRiskCount
	listed    map[string]time.Time // list|address -> when the entry times out
	minute    int64
	listedMin int
	eventsMin int
	// recent is each decision's row while repeats still count on it.
	recent    map[string]*ipsRecent
	protected guard.IPSProtected
	protAt    time.Time
}

// ipsRecent is a decision's row and the repeats not yet added to it.
type ipsRecent struct {
	id    int64
	until time.Time
	hits  int64
}

type ipsWrite struct {
	d    ips.Decision
	flow ips.Flow
}

func (s *Server) buildIPS() *ipsEngine {
	ctx, cancel := context.WithCancel(context.Background())
	e := &ipsEngine{s: s, ctx: ctx, cancel: cancel, readers: map[string]*ipsReader{}}
	if s.auditDB != nil {
		e.reloadRules()
		e.sync()
	}
	return e
}

// Stop ends every reader.
func (e *ipsEngine) Stop() {
	e.cancel()
	e.mu.Lock()
	for _, r := range e.readers {
		r.cancel()
	}
	e.readers = map[string]*ipsReader{}
	e.mu.Unlock()
}

// reloadRules re-reads the rule table, after a save.
func (e *ipsEngine) reloadRules() {
	rules, err := e.s.auditDB.IPSRules()
	if err != nil {
		log.Printf("[ips] reading the rules: %v", err)
		return
	}
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
}

func (e *ipsEngine) currentRules() []ips.Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rules
}

// sync starts a reader for every configured sensor, restarts one whose
// configuration changed, and stops one whose sensor is gone.
func (e *ipsEngine) sync() {
	sensors, err := e.s.auditDB.IPSSensors()
	if err != nil {
		log.Printf("[ips] reading the sensors: %v", err)
		return
	}
	want := map[string]db.IPSSensor{}
	for _, sn := range sensors {
		sn.Token = e.s.openCredSecret(sn.Token)
		want[sn.RouterID] = sn
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ctx.Err() != nil {
		return
	}
	for id, r := range e.readers {
		cfg, ok := want[id]
		if !ok || !sameSensor(cfg, r.cfg) {
			r.cancel()
			delete(e.readers, id)
		}
	}
	for id, cfg := range want {
		if _, ok := e.readers[id]; ok || cfg.Token == "" {
			continue
		}
		e.readers[id] = e.startReader(cfg)
	}
}

func sameSensor(a, b db.IPSSensor) bool {
	return a.Address == b.Address && a.Token == b.Token && a.Enforce == b.Enforce && a.DHCP == b.DHCP &&
		a.Network == b.Network && strings.Join(a.Protected, ",") == strings.Join(b.Protected, ",")
}

func (e *ipsEngine) reader(routerID string) *ipsReader {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.readers[routerID]
}

func (e *ipsEngine) startReader(cfg db.IPSSensor) *ipsReader {
	ctx, cancel := context.WithCancel(e.ctx)
	r := &ipsReader{e: e, routerID: cfg.RouterID, cfg: cfg, cancel: cancel, addr: cfg.Address,
		writes: make(chan ipsWrite, ipsWriteQueue), apps: map[string]*IPSAppCount{}, risks: map[string]*IPSRiskCount{},
		listed: map[string]time.Time{}, recent: map[string]*ipsRecent{}, status: IPSStatus{State: "connecting", Since: nowMillis(), Enforce: cfg.Enforce}}
	if cfg.Address != "" {
		r.status.Sensor = net.JoinHostPort(cfg.Address, strconv.Itoa(ips.ReaderPort))
	}
	go r.run(ctx)
	go r.flusher(ctx)
	return r
}

func (r *ipsReader) setState(state, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status.State != state {
		r.status.Since = nowMillis()
	}
	r.status.State, r.status.Message = state, msg
}

// run holds the router's session and reads the sensor until cancelled.
func (r *ipsReader) run(ctx context.Context) {
	// A hold no collector reads: it keeps the connection the writer lists
	// through, and starts nothing (session.Reasons names the holds that do).
	const hold = "ips"
	for {
		sn, err := r.e.s.sessions.Retain(r.routerID, hold)
		if err == nil {
			defer r.e.s.sessions.Drop(r.routerID, hold)
			r.mu.Lock()
			r.sn = sn
			r.mu.Unlock()
			go r.writer(ctx, sn)
			break
		}
		r.setState("unreachable", "the router is not available to MikroDash")
		select {
		case <-ctx.Done():
			return
		case <-time.After(ipsRetryMax):
		}
	}
	wait := ipsRetryMin
	for ctx.Err() == nil {
		connected, err := r.readOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if connected {
			wait = ipsRetryMin // a sensor that was up is retried promptly
		}
		pause := wait
		var refused errRefused
		if errors.As(err, &refused) {
			r.setState("refused", refused.msg)
			pause = ipsRetryRefused
		} else {
			r.setState("unreachable", safe.Message(errMessage(err)))
			wait = min(wait*2, ipsRetryMax)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pause):
		}
	}
}

type errRefused struct{ msg string }

func (e errRefused) Error() string { return e.msg }

func errMessage(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return "the sensor closed the connection"
	case errors.As(err, &ne) && ne.Timeout():
		return "the sensor did not answer in time"
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		return "cannot reach the sensor: " + oe.Err.Error()
	}
	return err.Error()
}

// readOnce is one connection to the sensor, read to its end. `connected` is
// whether the sensor accepted the token on it.
func (r *ipsReader) readOnce(ctx context.Context) (connected bool, err error) {
	r.setState("connecting", "")
	addr, err := r.sensorAddress()
	if err != nil {
		return false, err
	}
	d := net.Dialer{Timeout: ipsDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, ipsReaderPort))
	if err != nil {
		return false, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(ipsDialTimeout))
	if _, err := fmt.Fprintf(conn, "HELLO %s\n", r.cfg.Token); err != nil {
		return false, err
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64<<10), 64<<10)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(ipsIdleTimeout))
		if !sc.Scan() {
			return connected, sc.Err()
		}
		line, err := ips.ParseLine(sc.Bytes())
		if err != nil {
			continue // one bad line is not a bad sensor
		}
		switch {
		case line.Error != "":
			return connected, errRefused{"the sensor refused MikroDash: " + line.Error}
		case line.Hello != nil:
			r.mu.Lock()
			r.status.NDPI = line.Hello.NDPI
			r.mu.Unlock()
			connected = true
			r.setState("connected", "")
		case line.Stats != nil:
			r.mu.Lock()
			r.status.Stats = line.Stats
			r.mu.Unlock()
		case line.Flow != nil:
			r.handle(*line.Flow)
		}
	}
}

// sensorAddress is where to dial: the configured address, or a DHCP sensor's
// lease, read off its veth before every connection. A lease that moved is
// followed at once, and said: the mangle rule still copies to the old address
// until Apply rewrites it.
func (r *ipsReader) sensorAddress() (string, error) {
	r.mu.Lock()
	sn, was := r.sn, r.addr
	r.mu.Unlock()
	if !r.cfg.DHCP {
		return was, nil
	}
	if sn == nil || !sn.Connected() {
		return "", errors.New("the router is not connected, so the sensor's DHCP lease cannot be read")
	}
	rows, err := sn.Exec(routeros.Cmd{Path: "/interface/veth/print",
		Args: []string{"=.proplist=dhcp-address", "?name=" + ips.Veth}, Timeout: ipsCmdTimeout})
	if err != nil || len(rows) == 0 {
		return "", errors.New("the router has no " + ips.Veth + ": run the container commands from Setup")
	}
	a := ips.LeasedAddress(rows[0])
	if !a.IsValid() {
		return "", errors.New("the sensor has no DHCP lease yet: is its container running?")
	}
	now := a.String()
	r.mu.Lock()
	r.addr = now
	r.status.Sensor = net.JoinHostPort(now, ipsReaderPort)
	if was != "" && was != now {
		r.protAt = time.Time{} // the guard protects the new address from now on
		log.Printf("[ips] %s: the sensor's lease moved from %s to %s; Apply rewrites the mangle rule", r.routerID, was, now)
	}
	r.mu.Unlock()
	return now, nil
}

// handle decides one flow and records what was decided.
func (r *ipsReader) handle(f ips.Flow) {
	// The countries are MikroDash's, from the same database the Connections
	// page reads; a private address has none.
	if gdb, ok := geo.Current(); ok {
		if loc, found := gdb.Lookup(f.Client); found {
			f.ClientCountry = loc.Country
		}
		if loc, found := gdb.Lookup(f.Server); found {
			f.ServerCountry = loc.Country
		}
	}
	// The Traffic page names the router's IPFIX records with what the sensor saw.
	r.e.s.traffic.classify(r.routerID, f)
	d := ips.Decide(r.e.currentRules(), f)
	view := IPSFlowView{Flow: f, Action: d.Action, Rule: d.RuleName, Severity: ips.WorstSeverity(f.Risks)}
	now := time.Now()
	record := false

	r.mu.Lock()
	r.status.Seen++
	r.rollMinute(now)
	name := firstNonEmpty(f.App, f.Name)
	a := r.apps[name]
	if a == nil {
		a = &IPSAppCount{Name: name, Category: f.Category}
		r.apps[name] = a
	}
	a.Flows++
	a.Bytes += f.Bytes
	for _, risk := range f.Risks {
		rc := r.risks[risk]
		if rc == nil {
			rc = &IPSRiskCount{Name: risk, Severity: ips.RiskSeverity(risk), Apps: []string{}, clients: map[string]bool{}}
			r.risks[risk] = rc
		}
		rc.Flows++
		if len(rc.clients) < ipsRiskClients {
			rc.clients[f.Client] = true
		}
		if len(rc.Apps) < ipsRiskApps && !slices.Contains(rc.Apps, name) {
			rc.Apps = append(rc.Apps, name)
		}
		rc.LastTS, rc.LastClient, rc.LastServer = f.TS, f.Client, f.Server
	}
	switch d.Action {
	case ips.ActionLog:
		view.Result, record = "logged", true
	case ips.ActionBlock, ips.ActionQuarantine:
		key := d.List + "|" + d.Target
		switch {
		case !r.cfg.Enforce:
			view.Result, record = "monitor", r.listed[key].Before(now)
			if record {
				// Recorded once per timeout, as a real listing would be.
				r.listed[key] = now.Add(time.Duration(d.TimeoutMin) * time.Minute)
			}
		case r.listed[key].After(now):
			view.Result = "already"
		case r.listedMin >= ipsListPerMinute:
			view.Result, record = "limited", true
			r.status.Limited++
		default:
			select {
			case r.writes <- ipsWrite{d: d, flow: f}:
				// The writer records the outcome; the window says it is on its way.
				view.Result = "queued"
				r.listedMin++
				r.listed[key] = now.Add(time.Duration(d.TimeoutMin) * time.Minute)
			default:
				view.Result, record = "limited", true
				r.status.Limited++
			}
		}
	}
	r.flows = append(r.flows, view)
	if len(r.flows) > ipsFlowWindow {
		r.flows = r.flows[len(r.flows)-ipsFlowWindow:]
	}
	r.mu.Unlock()

	if record {
		r.record(d, f, view.Result)
	}
}

// rollMinute starts a new minute's counts. Called with mu held.
func (r *ipsReader) rollMinute(now time.Time) {
	if m := now.Unix() / 60; m != r.minute {
		r.minute, r.listedMin, r.eventsMin = m, 0, 0
		for k, until := range r.listed {
			if until.Before(now) {
				delete(r.listed, k)
			}
		}
	}
}

// record writes one decision, within the per-minute allowance, or counts it
// as a hit on the same decision's recent row.
func (r *ipsReader) record(d ips.Decision, f ips.Flow, result string) {
	key := strconv.FormatInt(d.RuleID, 10) + "|" + result + "|" + f.Client + "|" + f.Server + "|" + strconv.Itoa(f.ServerPort)
	now := time.Now()
	r.mu.Lock()
	if rc := r.recent[key]; rc != nil && rc.until.After(now) {
		rc.hits++
		r.mu.Unlock()
		return
	}
	r.eventsMin++
	over := r.eventsMin > ipsEventsPerMinute
	r.mu.Unlock()
	if over || r.e.s.auditDB == nil {
		return
	}
	id, err := r.e.s.auditDB.InsertIPSEvent(db.IPSEvent{TS: nowMillis(), RouterID: r.routerID, RuleID: d.RuleID,
		RuleName: d.RuleName, Action: d.Action, Result: result, Target: d.Target, Client: f.Client,
		Server: f.Server, ServerPort: f.ServerPort, L4: f.L4, App: firstNonEmpty(f.Name, f.App),
		Category: f.Category, Host: f.Host, Risks: f.Risks})
	if err != nil {
		log.Printf("[ips] %s: recording a decision: %v", r.routerID, err)
		return
	}
	r.mu.Lock()
	r.recent[key] = &ipsRecent{id: id, until: now.Add(ipsRepeatWindow)}
	r.mu.Unlock()
}

// flusher adds the counted repeats to their rows once a minute, forgets rows
// past their window, and trims the router's decisions to ipsEventsKeep once
// an hour. A last flush on the way out keeps the hits of the final minute.
func (r *ipsReader) flusher(ctx context.Context) {
	t := time.NewTicker(ipsFlushEvery)
	defer t.Stop()
	for n := 1; ; n++ {
		select {
		case <-ctx.Done():
			r.flushHits(time.Now())
			return
		case now := <-t.C:
			r.flushHits(now)
			if n%60 == 0 && r.e.s.auditDB != nil {
				if _, err := r.e.s.auditDB.TrimIPSEvents(r.routerID, ipsEventsKeep); err != nil {
					log.Printf("[ips] %s: trimming the decisions: %v", r.routerID, err)
				}
			}
		}
	}
}

func (r *ipsReader) flushHits(now time.Time) {
	hits := map[int64]int64{}
	r.mu.Lock()
	for k, rc := range r.recent {
		if rc.hits > 0 {
			hits[rc.id] += rc.hits
			rc.hits = 0
		}
		if !rc.until.After(now) {
			delete(r.recent, k)
		}
	}
	r.mu.Unlock()
	if r.e.s.auditDB == nil {
		return
	}
	if err := r.e.s.auditDB.AddIPSEventHits(hits); err != nil {
		log.Printf("[ips] %s: adding repeats to the decisions: %v", r.routerID, err)
	}
}

// writer lists what the read loop queued, one write at a time, each judged by
// the guard against a fresh enough view of what must never be listed.
func (r *ipsReader) writer(ctx context.Context, sn *session.Session) {
	for {
		select {
		case <-ctx.Done():
			return
		case w := <-r.writes:
			result := r.list(sn, w.d, w.flow)
			r.mu.Lock()
			switch {
			case result == "listed":
				r.status.Listed++
			case strings.HasPrefix(result, "refused"):
				r.status.Refused++
			case result == "failed":
				r.status.Failed++
			}
			if result != "listed" {
				// Not listed, so not to be skipped as listed either.
				delete(r.listed, w.d.List+"|"+w.d.Target)
			}
			for i := len(r.flows) - 1; i >= 0; i-- {
				if r.flows[i].Result == "queued" && r.flows[i].Client == w.flow.Client &&
					r.flows[i].ClientPort == w.flow.ClientPort && r.flows[i].Server == w.flow.Server {
					r.flows[i].Result = result
					break
				}
			}
			r.mu.Unlock()
			r.record(w.d, w.flow, result)
		}
	}
}

// list puts one address on its list, unless the guard refuses it.
func (r *ipsReader) list(sn *session.Session, d ips.Decision, f ips.Flow) string {
	if !sn.Connected() {
		return "failed"
	}
	if v := guard.CheckIPSTarget(r.protectedSet(sn), d.Target); v.Refused() {
		return "refused: " + v.Code
	}
	_, err := sn.Exec(routeros.Cmd{Path: "/ip/firewall/address-list/add",
		Args: ips.ListEntryArgs(d, firstNonEmpty(f.Name, f.App)), Timeout: ipsCmdTimeout})
	if err != nil {
		var trap *routeros.Trap
		if errors.As(err, &trap) && strings.Contains(trap.Message, "already have") {
			return "listed"
		}
		log.Printf("[ips] %s: listing %s: %v", r.routerID, d.Target, err)
		return "failed"
	}
	return "listed"
}

// protectedSet is what the guard protects on this router, read again every
// ipsProtectedEvery. A read that fails leaves the set unresolved, and the guard
// then lists nothing.
func (r *ipsReader) protectedSet(sn *session.Session) guard.IPSProtected {
	r.mu.Lock()
	p, at := r.protected, r.protAt
	r.mu.Unlock()
	if p.Resolved && time.Since(at) < ipsProtectedEvery {
		return p
	}
	addrs, err := sn.Exec(routeros.Cmd{Path: "/ip/address/print", Args: []string{"=.proplist=address"},
		Timeout: ipsCmdTimeout})
	var self []string
	if active, aerr := sn.Exec(routeros.Cmd{Path: "/user/active/print", Args: []string{"=.proplist=name,address"},
		Timeout: ipsCmdTimeout}); aerr == nil {
		self, _ = guard.SelfAddresses(active, []string{sn.Username()})
	}
	r.mu.Lock()
	sensor := r.addr
	r.mu.Unlock()
	p = guard.NewIPSProtected(addrs, err == nil, self, sensor, r.cfg.Protected)
	r.mu.Lock()
	r.protected, r.protAt = p, time.Now()
	r.mu.Unlock()
	return p
}

// riskSnapshot is the Risks tab: worst severity first, then the most flows.
func (r *ipsReader) riskSnapshot() []IPSRiskCount {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]IPSRiskCount, 0, len(r.risks))
	for _, rc := range r.risks {
		c := *rc
		c.Clients = len(rc.clients)
		c.Apps = append([]string{}, rc.Apps...)
		c.clients = nil
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := ips.SeverityRank(out[i].Severity), ips.SeverityRank(out[j].Severity)
		if a != b {
			return a > b
		}
		if out[i].Flows != out[j].Flows {
			return out[i].Flows > out[j].Flows
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// snapshot is the reader's state for the page.
func (r *ipsReader) snapshot() (IPSStatus, []IPSFlowView, []IPSAppCount) {
	r.mu.Lock()
	defer r.mu.Unlock()
	flows := make([]IPSFlowView, 0, len(r.flows))
	for i := len(r.flows) - 1; i >= 0; i-- {
		f := r.flows[i]
		f.Risks = append([]string{}, f.Risks...)
		flows = append(flows, f)
	}
	apps := make([]IPSAppCount, 0, len(r.apps))
	for _, a := range r.apps {
		apps = append(apps, *a)
	}
	sort.Slice(apps, func(i, j int) bool {
		if apps[i].Flows != apps[j].Flows {
			return apps[i].Flows > apps[j].Flows
		}
		return apps[i].Name < apps[j].Name
	})
	if len(apps) > 25 {
		apps = apps[:25]
	}
	return r.status, flows, apps
}

// validSensorAddress is an IPv4 unicast address the router can send TZSP to.
func validSensorAddress(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !a.Is4() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
		return netip.Addr{}, false
	}
	return a, true
}
