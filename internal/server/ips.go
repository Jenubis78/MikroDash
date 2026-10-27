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

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mikrodash/internal/db"
	"mikrodash/internal/guard"
	"mikrodash/internal/ips"
	"mikrodash/internal/routeros"
	"mikrodash/internal/safe"
	"mikrodash/internal/session"
)

const (
	ipsFlowWindow      = 300
	ipsListPerMinute   = 60
	ipsEventsPerMinute = 240
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
}

type ipsReader struct {
	e        *ipsEngine
	routerID string
	cfg      db.IPSSensor // Token unsealed
	cancel   context.CancelFunc
	writes   chan ipsWrite

	mu        sync.Mutex
	status    IPSStatus
	flows     []IPSFlowView // newest last
	apps      map[string]*IPSAppCount
	listed    map[string]time.Time // list|address -> when the entry times out
	minute    int64
	listedMin int
	eventsMin int
	protected guard.IPSProtected
	protAt    time.Time
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
	return a.Address == b.Address && a.Token == b.Token && a.Enforce == b.Enforce &&
		strings.Join(a.Protected, ",") == strings.Join(b.Protected, ",")
}

func (e *ipsEngine) reader(routerID string) *ipsReader {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.readers[routerID]
}

func (e *ipsEngine) startReader(cfg db.IPSSensor) *ipsReader {
	ctx, cancel := context.WithCancel(e.ctx)
	r := &ipsReader{e: e, routerID: cfg.RouterID, cfg: cfg, cancel: cancel,
		writes: make(chan ipsWrite, ipsWriteQueue), apps: map[string]*IPSAppCount{}, listed: map[string]time.Time{},
		status: IPSStatus{State: "connecting", Since: nowMillis(), Sensor: net.JoinHostPort(cfg.Address,
			strconv.Itoa(ips.ReaderPort)), Enforce: cfg.Enforce}}
	go r.run(ctx)
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
	d := net.Dialer{Timeout: ipsDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(r.cfg.Address, ipsReaderPort))
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

// handle decides one flow and records what was decided.
func (r *ipsReader) handle(f ips.Flow) {
	d := ips.Decide(r.e.currentRules(), f)
	view := IPSFlowView{Flow: f, Action: d.Action, Rule: d.RuleName}
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

// record writes one decision, within the per-minute allowance.
func (r *ipsReader) record(d ips.Decision, f ips.Flow, result string) {
	r.mu.Lock()
	r.eventsMin++
	over := r.eventsMin > ipsEventsPerMinute
	r.mu.Unlock()
	if over || r.e.s.auditDB == nil {
		return
	}
	err := r.e.s.auditDB.InsertIPSEvent(db.IPSEvent{TS: nowMillis(), RouterID: r.routerID, RuleID: d.RuleID,
		RuleName: d.RuleName, Action: d.Action, Result: result, Target: d.Target, Client: f.Client,
		Server: f.Server, ServerPort: f.ServerPort, L4: f.L4, App: firstNonEmpty(f.Name, f.App),
		Category: f.Category, Host: f.Host, Risks: f.Risks})
	if err != nil {
		log.Printf("[ips] %s: recording a decision: %v", r.routerID, err)
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
	p = guard.NewIPSProtected(addrs, err == nil, self, r.cfg.Address, r.cfg.Protected)
	r.mu.Lock()
	r.protected, r.protAt = p, time.Now()
	r.mu.Unlock()
	return p
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
