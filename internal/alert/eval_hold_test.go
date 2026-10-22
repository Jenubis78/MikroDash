package alert

// HIGH CPU AND PING LOSS MUST PERSIST FOR THE ROUTER'S HOLD BEFORE THEY ALERT.
//
// On 2026-10-22 the hAP AX3 filed three High CPU alerts that lasted 1.6 s, 4.2 s
// and 1.8 s, each rung on the bell and each followed by a recovery: the rule
// fired on the first reading past the floor. The hold is the router's own
// "Offline threshold" (`connDownThresholdSec`, 30 s on every router in that
// install), carried on Router.HoldMs and read on every evaluation.

import "testing"

const hold30 = 30_000

// clocked is an evaluator whose clock the test sets before each reading.
func clocked(t *testing.T) (*Evaluator, *int64) {
	t.Helper()
	now := int64(1_800_000_000_000)
	ev := NewEvaluator(&memStore{})
	ev.SetClock(func() int64 { return now })
	return ev, &now
}

func cpuAt(ev *Evaluator, now *int64, at int64, r Router, v float64) []Fired {
	*now = at
	return ev.SystemUpdate(r, &v, false, "", "")
}

func TestASpikeShorterThanTheHoldDoesNotFire(t *testing.T) {
	ev, now := clocked(t)
	r := Router{ID: "r1", AlertsEnabled: true, HoldMs: hold30}
	t0 := *now
	var all []Fired
	all = append(all, cpuAt(ev, now, t0, r, 95)...)
	all = append(all, cpuAt(ev, now, t0+2_000, r, 95)...)
	for i := int64(2); i < 40; i++ { // back to normal, and staying there
		all = append(all, cpuAt(ev, now, t0+i*2_000, r, 20)...)
	}
	if len(all) != 0 {
		t.Errorf("a 2 s spike to 95%% fired %s; it has to persist for the router's hold first",
			showFired(all))
	}
}

func TestABreachHeldPastTheHoldFires(t *testing.T) {
	ev, now := clocked(t)
	r := Router{ID: "r1", AlertsEnabled: true, HoldMs: hold30}
	t0 := *now
	for i := int64(0); i < 15; i++ { // 0 .. 28 s
		if f := cpuAt(ev, now, t0+i*2_000, r, 80+float64(i%3)); len(f) != 0 {
			t.Fatalf("fired at %d s, before the 30 s hold: %s", i*2, showFired(f))
		}
	}
	f := cpuAt(ev, now, t0+30_000, r, 85)
	if len(f) != 1 || f[0].Up || f[0].Escalation || f[0].AlertType != "High CPU" {
		t.Fatalf("CPU held past the hold fired %s, want one High CPU", showFired(f))
	}
	// THE LEVEL IS THE LOWEST OVER THE HOLD: 80, what a channel compares.
	if f[0].Value != 80 {
		t.Errorf("the alert's value is %v, want 80: the level held for the whole 30 s", f[0].Value)
	}
}

func TestAChangeToTheHoldTakesEffectOnTheNextReading(t *testing.T) {
	ev, now := clocked(t)
	r := Router{ID: "r1", AlertsEnabled: true, HoldMs: 60_000}
	t0 := *now
	for i := int64(0); i <= 20; i++ { // 40 s past the floor, under a 60 s hold
		if f := cpuAt(ev, now, t0+i*2_000, r, 90); len(f) != 0 {
			t.Fatalf("fired under a 60 s hold at %d s", i*2)
		}
	}
	r.HoldMs = hold30 // the operator lowers the Offline threshold to 30 s
	if f := cpuAt(ev, now, t0+42_000, r, 90); len(f) != 1 || f[0].Up {
		t.Errorf("after the hold was lowered to 30 s, a run 42 s long fired %s", showFired(f))
	}
}

func TestARecoveryMustAlsoPersist(t *testing.T) {
	ev, now := clocked(t)
	r := Router{ID: "r1", AlertsEnabled: true, HoldMs: hold30}
	t0 := *now
	for i := int64(0); i <= 15; i++ {
		cpuAt(ev, now, t0+i*2_000, r, 90)
	}
	// A 10 s dip, then high again: the same episode, not a recovery and a new alert.
	var during []Fired
	for i := int64(16); i < 21; i++ {
		during = append(during, cpuAt(ev, now, t0+i*2_000, r, 40)...)
	}
	for i := int64(21); i < 30; i++ {
		during = append(during, recordedOnly(cpuAt(ev, now, t0+i*2_000, r, 90))...)
	}
	if len(during) != 0 {
		t.Fatalf("a 10 s dip produced %s", showFired(during))
	}
	// Back under the floor for the hold: one recovery.
	var after []Fired
	for i := int64(30); i <= 46; i++ {
		after = append(after, cpuAt(ev, now, t0+i*2_000, r, 40)...)
	}
	if len(after) != 1 || !after[0].Up {
		t.Errorf("30 s back under the floor produced %s, want one recovery", showFired(after))
	}
}

// ELAPSED TIME, NOT READINGS: ping at one reading every 10 s and at one every
// second fires at the same moment.
func TestPingLossIsTimedNotCounted(t *testing.T) {
	for _, every := range []int64{1_000, 10_000} {
		ev, now := clocked(t)
		r := Router{ID: "r1", AlertsEnabled: true, HoldMs: hold30}
		target := "1.1.1.1"
		t0 := *now
		firedAt := int64(-1)
		for at := t0; at <= t0+60_000; at += every {
			*now = at
			loss := 100.0
			if f := ev.PingUpdate(r, &target, &loss, nil); len(f) == 1 && firedAt < 0 {
				firedAt = at - t0
			}
		}
		if firedAt != 30_000 {
			t.Errorf("readings every %d ms fired at %d ms, want 30000", every, firedAt)
		}
	}
}

// A CLIMB WITHIN AN OPEN EPISODE IS AN ESCALATION carrying the new held level,
// so a channel set to 90 hears about CPU held at 95 that started at 72.
func TestAClimbFrom72To95Escalates(t *testing.T) {
	ev, now := clocked(t)
	r := Router{ID: "r1", AlertsEnabled: true, HoldMs: hold30}
	t0 := *now
	var all []Fired
	for i := int64(0); i <= 15; i++ { // 72% for 30 s
		all = append(all, cpuAt(ev, now, t0+i*2_000, r, 72)...)
	}
	for i := int64(16); i <= 31; i++ { // then 95% for 30 s
		all = append(all, cpuAt(ev, now, t0+i*2_000, r, 95)...)
	}
	if len(all) != 2 || all[0].Escalation || all[0].Value != 72 ||
		!all[1].Escalation || all[1].Value != 95 {
		t.Fatalf("72%% then 95%% produced %s, want the breach at 72 then an escalation at 95",
			showFired(all))
	}
	if len(recordedOnly(all)) != 1 {
		t.Error("the escalation was recorded as a second alert")
	}
}

// TODAY'S REAL ROWS, replayed (2026-10-22, the hAP AX3): each spike's reading at
// the instant it fired, and a normal one at the instant it resolved, then normal
// readings every 2 s. With the router's 30 s hold nothing fires; with no hold
// it reproduces the three alerts and three recoveries that were filed.
func TestTodaysSpikesReplayed(t *testing.T) {
	spikes := []struct{ fired, resolved int64 }{
		{1792646249060, 1792646250634}, // 71%, 1.6 s
		{1792666166359, 1792666170520}, // 72%, 4.2 s
		{1792666170991, 1792666172790}, // 72%, 1.8 s
	}
	values := []float64{71, 72, 72}
	run := func(holdMs int64) []Fired {
		ev, now := clocked(t)
		r := Router{ID: "ax3", AlertsEnabled: true, HoldMs: holdMs}
		var all []Fired
		for i, s := range spikes {
			all = append(all, cpuAt(ev, now, s.fired, r, values[i])...)
			all = append(all, cpuAt(ev, now, s.resolved, r, 30)...)
			for k := int64(1); k <= 40; k++ {
				at := s.resolved + k*2_000
				if i+1 < len(spikes) && at >= spikes[i+1].fired {
					break
				}
				all = append(all, cpuAt(ev, now, at, r, 30)...)
			}
		}
		return all
	}
	if got := run(hold30); len(got) != 0 {
		t.Errorf("today's spikes under the router's 30 s hold fired %s", showFired(got))
	}
	// CONTROL: the same readings with no hold are what was filed today.
	if got := run(0); len(got) != 6 {
		t.Errorf("with no hold the replay fired %d alerts, want the 3 alerts and 3 recoveries "+
			"that were filed: %s", len(got), showFired(got))
	}
}

// STEADY LOSS IS REPORTED ONCE AND STILL FIRES. Ping is emitted only when it
// changes, so 100% loss held for a minute is one reading; found live on
// 2026-10-22, when 55 s of total loss filed nothing. The clock tick judges it.
func TestSteadyLossFiresOnTheClock(t *testing.T) {
	ev, now := clocked(t)
	r := Router{ID: "r1", AlertsEnabled: true, HoldMs: hold30}
	target := "198.51.100.1"
	t0 := *now
	loss := 100.0
	if f := ev.PingUpdate(r, &target, &loss, nil); len(f) != 0 { // the only reading
		t.Fatalf("the first reading fired %s", showFired(f))
	}
	firedAt := int64(-1)
	for at := t0 + 1_000; at <= t0+40_000; at += 1_000 {
		*now = at
		if f := ev.Tick(r, true); len(f) == 1 && firedAt < 0 {
			firedAt = at - t0
		}
	}
	if firedAt != 30_000 {
		t.Fatalf("100%% loss reported once fired at %d ms, want 30000", firedAt)
	}
	// And recovers the same way: one 0% reading, then silence.
	*now = t0 + 41_000
	clean := 0.0
	ev.PingUpdate(r, &target, &clean, nil)
	recoveredAt := int64(-1)
	for at := t0 + 42_000; at <= t0+80_000; at += 1_000 {
		*now = at
		if f := ev.Tick(r, true); len(f) == 1 && f[0].Up && recoveredAt < 0 {
			recoveredAt = at - (t0 + 41_000)
		}
	}
	if recoveredAt != 30_000 {
		t.Errorf("0%% loss reported once recovered %d ms later, want 30000", recoveredAt)
	}
}

// A REPLACED TARGET STARTS AGAIN, the live case of 2026-10-22: a 12 s spike on
// one target, the ping target switched back, then the same target 75 s later.
// The first build fired 5 s into the second run, timing the silence as held.
func TestAReplacedTargetStartsAgain(t *testing.T) {
	ev, now := clocked(t)
	r := Router{ID: "r1", AlertsEnabled: true, HoldMs: hold30}
	bad, good := "198.51.100.1", "1.1.1.1"
	lossy, clean := 100.0, 0.0
	t0 := *now
	*now = t0
	ev.PingUpdate(r, &bad, &lossy, nil)
	for at := t0 + 1_000; at < t0+12_000; at += 1_000 {
		*now = at
		ev.Tick(r, true)
	}
	*now = t0 + 12_000
	ev.PingUpdate(r, &good, &clean, nil) // switched back
	for at := t0 + 13_000; at < t0+87_000; at += 1_000 {
		*now = at
		if f := ev.Tick(r, true); len(f) != 0 {
			t.Fatalf("a target nobody pings any more fired %s", showFired(f))
		}
	}
	back := t0 + 87_000
	*now = back
	ev.PingUpdate(r, &bad, &lossy, nil) // the same target again
	firedAt := int64(-1)
	for at := back + 1_000; at <= back+40_000; at += 1_000 {
		*now = at
		if f := ev.Tick(r, true); len(f) == 1 && firedAt < 0 {
			firedAt = at - back
		}
	}
	if firedAt != 30_000 {
		t.Errorf("the target's second run fired %d ms in, want 30000", firedAt)
	}
}

// A DISCONNECT BREAKS A RUN: an offline router's last CPU reading is not
// evidence that it stayed there.
func TestADisconnectBreaksARun(t *testing.T) {
	ev, now := clocked(t)
	r := Router{ID: "r1", AlertsEnabled: true, HoldMs: hold30}
	t0 := *now
	for at := t0; at <= t0+20_000; at += 2_000 {
		cpuAt(ev, now, at, r, 90)
	}
	*now = t0 + 21_000
	if f := ev.Tick(r, false); len(f) != 0 {
		t.Fatalf("a disconnected tick fired %s", showFired(f))
	}
	for at := t0 + 60_000; at < t0+90_000; at += 2_000 { // back, still busy
		if f := cpuAt(ev, now, at, r, 90); len(f) != 0 {
			t.Fatalf("fired %d ms after reconnecting: the outage was timed as held", at-(t0+60_000))
		}
	}
	if f := cpuAt(ev, now, t0+90_000, r, 90); len(f) != 1 {
		t.Errorf("30 s after reconnecting fired %s, want the alert", showFired(f))
	}
}
