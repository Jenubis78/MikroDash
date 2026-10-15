package collect

// The lifecycle every plain table collector shares.
//
// ── WHAT A TABLE COLLECTOR IS ───────────────────────────────────────────────
//
// One set A subscription whose cadence is simply "this table was read": the
// scheduler, or with no cache the poll loop, hands it rows; it derives a payload;
// and it sends that payload when it differs from the last one or a heartbeat is
// due. Sixteen collectors have that shape, and each wrote its own Start, Stop,
// Suspend, Resume, Reconnected, UseCache, SetPollMs, Last, RefreshNow and emit
// gate. The copies had drifted:
//
//   - `ppp`, `rosusers`, `dhcpNetworks` and `capsman` captured their construction-time
//     interval in the cadence, so a re-tune changed the `pollMs` the page
//     reported and not how often the router was read;
//   - seven checked the connection in Resume and nine did not;
//   - two kept the fingerprint across a reconnect, so the first identical
//     reading afterwards was suppressed;
//   - on the POLLED path six sent an empty payload after a failed read, while
//     the scheduled path of the same collector kept the last one.
//
// A collector now declares its menu, its interval bounds, its slow lane and its
// heartbeat, and supplies three methods: `derive`, `send` and `reset`. Everything
// else is here, once.
//
// ── WHAT IS DELIBERATELY NOT HERE ───────────────────────────────────────────
//
// The collectors that cannot be scheduled keep their own mechanism, for the four
// reasons docs/Collector-Architecture.md records: derived (vlans, bandwidth),
// streams (logs, ping, traffic), two cadences in one collector (vpn) and a menu
// chosen at runtime (firewall, wifi, wireless). So do the table collectors whose lifecycle
// genuinely differs: a residual loop beside its subscription (ifStatus), two
// payloads with separate emit gates (conns), and a second loop pinging each
// neighbour (topology). Forcing those in would mean a hook per difference, which
// is the second form this file exists to remove.
//
// Nor does it model "derive when several menus are fresh". A table collector
// subscribes to the menu that drives it and reads configuration inside
// `derive`, as scheduled.go says. That question belongs to views, not to a
// lifecycle helper.
//
// ── A SECOND LIVE MENU IS A SUBSCRIPTION OF ITS OWN ────────────────────────
//
// What a collector may NOT do is read a second LIVE menu inside `derive`. Its
// rows would arrive on the first menu's clock, and could not be streamed:
// `queues` read /queue/tree that way, one direct command per simple-queue round.
// A menu in `tableSpec.also` is subscribed beside `cmd`, at the same cadence,
// streamed when the router's settings allow, started and stopped with it, and
// delivered to the collector's `absorb` as it arrives. Each delivery derives
// from ITS OWN rows only: a byte counter is a rate against the time its rows
// arrived, and re-deriving the other menu's rows at a later time would measure
// a window nobody read.

import (
	"log"
	"sync"
	"time"

	"mikrodash/internal/roscache"
	"mikrodash/internal/routeros"
)

// tableRows is what a table collector supplies. The core calls all three with
// deriveMu held, so a collector's own derivation state needs no lock of its own
// unless something outside the derivation also reads it.
type tableRows[P any] interface {
	// derive turns one reading of the subscribed menu into a payload. `slow` is
	// true on the readings the collector's slow lane is due. A nil payload keeps
	// the last one, which is the answer to a failed read. An empty fingerprint
	// means the payload is sent on every reading.
	derive(rows []routeros.Reply, err error, slow bool) (payload *P, fingerprint string)
	// send emits a payload to the collector's rooms.
	send(payload P)
	// reset forgets what this connection taught the collector: availability
	// latches, counter samples, anything a new connection must learn again.
	reset()
}

// tableAlso is what a collector with `also` menus supplies besides tableRows.
type tableAlso[P any] interface {
	// absorb takes one reading of `also[i]` and answers as derive does: a payload
	// to send, or nil to send nothing. It must not touch the rows `derive` was
	// last given; see "A SECOND LIVE MENU" above. A menu the router does not
	// have, or refuses, is delivered once with its error and not read again on
	// this connection.
	absorb(i int, rows []routeros.Reply, err error) (payload *P, fingerprint string)
}

// tableSpec is a table collector's declaration.
type tableSpec struct {
	// cmd is the subscribed menu. Its proplist is the subscription's field list.
	cmd routeros.Cmd
	// poll is the default, floor and ceiling in milliseconds, in clampPoll's
	// order. A collector whose interval is not an operator setting pins all three.
	poll [3]int
	// slowEvery runs the slow lane on every Nth reading, the first included.
	// Zero means no slow lane.
	slowEvery int
	// heartbeat re-sends an unchanged payload once this much time has passed, so
	// a card with a stale threshold does not go stale on a quiet router. Zero
	// sends an unchanged payload never.
	heartbeat time.Duration
	// streamKey names a row when the menu is streamed. Nil is RouterOS `.id`.
	streamKey func(routeros.Reply) string
	// also are further live menus, each a subscription of its own beside cmd and
	// delivered to the collector's `absorb`. The collector must implement
	// tableAlso.
	also []routeros.Cmd
}

// tableCore is embedded by a table collector.
type tableCore[P any] struct {
	ros    Reader
	cache  *roscache.Cache
	pollMs *pollInterval
	poll   *pollLoop
	sched  scheduled
	// also are the `tableSpec.also` subscriptions, in its order. On the polled
	// path they have no loop: `fetch` reads them before the main menu.
	also     []*scheduled
	alsoCmds []routeros.Cmd
	// alsoGone marks an also-menu the router does not have or refuses, which is
	// not read again on this connection. Guarded by deriveMu.
	alsoGone []bool

	self      tableRows[P]
	cmd       routeros.Cmd
	bounds    [3]int
	slowEvery int
	heartbeat time.Duration

	// deriveMu serialises derivations: the scheduler, the poll loop and a
	// RefreshNow after a write can all arrive at once.
	deriveMu sync.Mutex
	ticks    int
	// retired stops reading until the connection is re-established. See retire.
	retired bool

	lastMu   sync.Mutex
	last     *P
	lastFP   string
	lastEmit time.Time
	now      func() time.Time
}

// setup wires the core. Called once, from the collector's constructor.
func (c *tableCore[P]) setup(self tableRows[P], ros Reader, pollMs int, spec tableSpec) {
	c.self, c.ros, c.cmd, c.bounds = self, ros, spec.cmd, spec.poll
	c.slowEvery, c.heartbeat, c.now = spec.slowEvery, spec.heartbeat, time.Now
	c.pollMs = newPollInterval(c.clamp(pollMs))
	c.poll = newPollLoop(c.Tick, c.pollMs.duration)
	// THE CADENCE IS THE INTERVAL, read on every schedule. Capturing the value
	// passed to the constructor instead is how three collectors ignored re-tunes.
	c.sched = scheduled{loop: c.poll, menu: spec.cmd.Path, fields: fieldsOf(spec.cmd),
		apply: c.apply, cadence: c.pollMs.duration, streamKey: spec.streamKey}
	if len(spec.also) > 0 {
		if _, ok := self.(tableAlso[P]); !ok {
			panic("collect: a tableSpec with `also` menus needs a collector that implements absorb")
		}
	}
	c.alsoCmds, c.alsoGone = spec.also, make([]bool, len(spec.also))
	for i, cmd := range spec.also {
		c.also = append(c.also, &scheduled{menu: cmd.Path, fields: fieldsOf(cmd),
			apply:   func(rows []routeros.Reply, err error) { c.applyAlso(i, rows, err, true) },
			cadence: c.pollMs.duration})
	}
}

func (c *tableCore[P]) clamp(ms int) int {
	return clampPoll(ms, c.bounds[0], c.bounds[1], c.bounds[2])
}

// UseCache moves the collector onto the router's scheduler, and routes its
// shared reads through the same cache. Set once, before Start; nil leaves it on
// its own poll loop.
func (c *tableCore[P]) UseCache(rc *roscache.Cache) {
	c.cache = rc
	c.sched.useCache(rc)
	for _, s := range c.also {
		s.useCache(rc)
	}
}

// readShared reads a menu other collectors may also read, through the cache when
// there is one, at this collector's interval.
func (c *tableCore[P]) readShared(cmd routeros.Cmd) ([]routeros.Reply, error) {
	return readVia(c.cache, c.ros, cmd, c.pollMs.duration())
}

// Tick reads the subscribed menu and derives from it. The poll loop calls it on
// the polled path.
func (c *tableCore[P]) Tick() { c.fetch(false) }

// fetch reads the subscribed menu, through the cache or, when `direct`, from the
// router itself.
func (c *tableCore[P]) fetch(direct bool) bool {
	c.deriveMu.Lock()
	retired := c.retired
	c.deriveMu.Unlock()
	if retired || !c.ros.Connected() {
		return false
	}
	// THE ALSO-MENUS FIRST, AND UNSENT: the main menu's payload carries them, so
	// a polled reading or a refresh sends once.
	for i, cmd := range c.alsoCmds {
		if c.gone(i) || (!direct && c.sched.scheduling()) {
			continue
		}
		var rows []routeros.Reply
		var err error
		if direct {
			rows, err = c.ros.Do(cmd)
		} else {
			rows, err = c.readShared(cmd)
		}
		c.applyAlso(i, rows, err, false)
	}
	if direct {
		c.apply(c.ros.Do(c.cmd))
	} else {
		c.apply(c.readShared(c.cmd))
	}
	return true
}

// apply is the one path from rows to a sent payload, whichever of the scheduler,
// the loop or a refresh delivered them. The connection is checked where a read is
// issued, in `fetch`; rows already delivered are derived whatever has happened to
// the connection since.
func (c *tableCore[P]) apply(rows []routeros.Reply, err error) {
	c.deriveMu.Lock()
	defer c.deriveMu.Unlock()
	if c.retired {
		return
	}
	slow := c.slowEvery > 0 && c.ticks%c.slowEvery == 0
	payload, fp := c.self.derive(rows, err, slow)
	if payload == nil {
		return
	}
	c.ticks++
	c.publish(payload, fp)
}

// applyAlso delivers one reading of an also-menu. `send` is false where the main
// menu's reading follows and sends for both.
func (c *tableCore[P]) applyAlso(i int, rows []routeros.Reply, err error, send bool) {
	c.deriveMu.Lock()
	defer c.deriveMu.Unlock()
	if c.retired || c.alsoGone[i] {
		return
	}
	if err != nil && menuGone(err) {
		// Not asked again on this connection, as readOptional's latch did when
		// the menu was read inside `derive`. Safe inside the callback: the
		// scheduler delivers outside its lock so a subscriber can release itself.
		c.alsoGone[i] = true
		c.also[i].end()
	}
	payload, fp := c.self.(tableAlso[P]).absorb(i, rows, err)
	if payload == nil || !send {
		return
	}
	c.publish(payload, fp)
}

func (c *tableCore[P]) gone(i int) bool {
	c.deriveMu.Lock()
	defer c.deriveMu.Unlock()
	return c.alsoGone[i]
}

// publish records a payload as the last one and sends it when it differs from
// the last sent or the heartbeat is due. Called with deriveMu held.
func (c *tableCore[P]) publish(payload *P, fp string) {
	now := c.now()
	c.lastMu.Lock()
	c.last = payload
	due := fp == "" || fp != c.lastFP || (c.heartbeat > 0 && now.Sub(c.lastEmit) >= c.heartbeat)
	if due {
		c.lastFP, c.lastEmit = fp, now
	}
	c.lastMu.Unlock()
	if due {
		c.self.send(*payload)
	}
}

// retire stops this collector reading for the rest of the connection. For a
// router that has said the menu does not exist, or that this user may not read
// it: neither answer changes until it reconnects, and asking every interval is
// load on the router and noise in the log. Called from derive only.
func (c *tableCore[P]) retire() { c.retired = true }

// Last is the most recent payload, or nil before the first reading.
func (c *tableCore[P]) Last() *P {
	c.lastMu.Lock()
	defer c.lastMu.Unlock()
	return c.last
}

// Start reads once at once on the polled path, then subscribes or starts the
// loop. Under the scheduler the first payload arrives with its first delivery.
func (c *tableCore[P]) Start() {
	c.readFirst()
	c.begin()
}

// begin wants every menu, end none: the main one and each `also`, together.
// An also-menu the router has said it does not have stays unwanted.
func (c *tableCore[P]) begin() {
	c.sched.begin()
	for i, s := range c.also {
		if !c.gone(i) {
			s.begin()
		}
	}
}

func (c *tableCore[P]) end() {
	c.sched.end()
	for _, s := range c.also {
		s.end()
	}
}

// readFirst is the immediate read on the polled path. Recorded as the loop's
// last run, or the loop starting next would read again straight away.
func (c *tableCore[P]) readFirst() {
	if !c.sched.scheduling() && c.fetch(false) {
		c.poll.ran()
	}
}

// Reconnected forgets the old connection and reads again, so the first reading
// on the new one always reaches the browser even if it is identical.
func (c *tableCore[P]) Reconnected() {
	c.end()
	c.forget()
	c.readFirst()
	c.begin()
}

// Suspend stops wanting the menu. Resume wants it again. Resume does not check
// the connection: a subscription on a disconnected router reads nothing, and a
// Resume dropped for that reason would leave the collector idle after it
// reconnects.
func (c *tableCore[P]) Suspend() { c.end() }
func (c *tableCore[P]) Resume()  { c.begin() }

// Stop ends the subscription and forgets the connection's state, so a later
// Start begins as a first reading.
func (c *tableCore[P]) Stop() {
	c.end()
	c.forget()
}

func (c *tableCore[P]) forget() {
	c.deriveMu.Lock()
	c.self.reset()
	c.ticks, c.retired = 0, false
	// A new connection may be a different build, so an absent menu is asked again.
	clear(c.alsoGone)
	c.deriveMu.Unlock()
	c.lastMu.Lock()
	c.lastFP = ""
	c.lastMu.Unlock()
}

// SetPollMs re-tunes a running collector, within its bounds.
func (c *tableCore[P]) SetPollMs(ms int) {
	c.pollMs.set(c.clamp(ms))
	c.poll.retime()
	// And the scheduler: a streamed menu reopens at the new interval.
	c.sched.retune()
	for _, s := range c.also {
		s.retune()
	}
}

func (c *tableCore[P]) PollMs() int { return c.pollMs.ms() }

// RefreshNow re-reads after a write: the subscribed menu and every also-menu,
// and the slow lane with them, because a write is exactly what a slow lane
// would miss.
//
// ── FROM THE ROUTER, NOT THROUGH THE CACHE ──────────────────────────────────
//
// A stream-filled entry answers `Get` from its rolling snapshot and ignores
// `Invalidate`, so a read through the cache after a write returns the rows from
// the last round, which predates the write: a saved user, DNS entry or NetWatch
// host would appear only when the next round arrived, up to a minute later. The
// polled entry is still invalidated, so another consumer of the menu is not served
// the rows from before the write either.
func (c *tableCore[P]) RefreshNow() {
	if !c.ros.Connected() {
		return
	}
	c.deriveMu.Lock()
	c.ticks = 0
	c.deriveMu.Unlock()
	if c.cache != nil {
		c.cache.Invalidate(c.cmd.Path)
		for _, cmd := range c.alsoCmds {
			c.cache.Invalidate(cmd.Path)
		}
	}
	c.fetch(true)
}

// latchMenu records what a read said about whether the router has a menu, in
// the three states the payloads' `available` flags read: nil not yet asked, true
// answered, false absent or refused. It reports a refusal, which a page words
// differently from an absent menu. A transient error leaves the latch alone.
func latchMenu(flag **bool, err error) (refused bool) {
	if err == nil {
		yes := true
		*flag = &yes
		return false
	}
	if menuGone(err) {
		no := false
		*flag = &no
	}
	return menuDenied(err)
}

// menuGone is an answer that will not change on this connection: the menu does
// not exist on this build, or this API user may not read it.
func menuGone(err error) bool { return menuMissing(err) || menuDenied(err) }

// readOptional reads a secondary menu a collector can do without. With a latch, a
// menu the router has refused or does not have is not asked again on this
// connection; a nil latch reads every time. Empty rows are dropped. It reports a
// refusal.
func readOptional(read func(routeros.Cmd) ([]routeros.Reply, error), cmd routeros.Cmd, flag **bool) ([]routeros.Reply, bool) {
	if flag != nil && *flag != nil && !**flag {
		return nil, false
	}
	rows, err := read(cmd)
	if err != nil {
		if !menuGone(err) {
			log.Printf("[collect] %s: %v", cmd.Path, err)
		}
		if flag == nil {
			return nil, menuDenied(err)
		}
		return nil, latchMenu(flag, err)
	}
	if flag != nil {
		latchMenu(flag, nil)
	}
	out := make([]routeros.Reply, 0, len(rows))
	for _, r := range rows {
		if len(r) > 0 {
			out = append(out, r)
		}
	}
	return out, false
}
