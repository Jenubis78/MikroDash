package server

// A CLIMB FROM 72% TO 95% REACHES A CHANNEL SET TO 90.
//
// The episode opens at the recording floor, at 72, which a channel set to 90
// skips. Before 2026-10-22 nothing fired again while it stayed open, so that
// channel never heard about CPU sitting at 95. The rise is an escalation now,
// delivered only to channels that had not yet been told about the episode.
// The real evaluator drives the real send path here.

import (
	"testing"

	"mikrodash/internal/alert"
	"mikrodash/internal/db"
)

// openRows is an alert.Store that keeps open alerts in memory.
type openRows struct{ open map[string]bool }

func (o *openRows) HasOpen(r, t, s string) bool { return o.open[r+"|"+t+"|"+s] }
func (o *openRows) Resolve(r, t, s string) []int64 {
	if !o.open[r+"|"+t+"|"+s] {
		return nil
	}
	delete(o.open, r+"|"+t+"|"+s)
	return []int64{1}
}
func (o *openRows) Record(r, t, s, _ string) int64 { o.open[r+"|"+t+"|"+s] = true; return 1 }

func TestAClimbFrom72To95ReachesAChannelSetTo90(t *testing.T) {
	d, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	// A ONE-SECOND COOLDOWN, so the cooldown cannot be what keeps the channel
	// already told about the episode from hearing the escalation: only the
	// rule under test may. With 60 s it hid exactly that mutation.
	for _, c := range []db.NotifyChannel{channelRow("at90", 90, 1), channelRow("at70", 70, 1)} {
		if err := d.UpsertNotifyChannel(c); err != nil {
			t.Fatal(err)
		}
	}
	clock := int64(1_800_000_000_000)
	s, tr := recoveryServer(d, &clock)

	ev := alert.NewEvaluator(&openRows{open: map[string]bool{}})
	ev.SetClock(func() int64 { return clock })
	r := alert.Router{ID: "r1", AlertsEnabled: true, HoldMs: 30_000}
	reading := func(v float64) {
		clock += 2_000
		s.dispatchFired("r1", "AX3", ev.SystemUpdate(r, &v, false, "", ""))
	}

	for i := 0; i < 16; i++ { // 72% held for 30 s: the episode opens
		reading(72)
	}
	if got := tr.waitFor(1); len(got) != 1 || got[0] != "at70.example" {
		t.Fatalf("the 72%% breach reached %v, want only at70.example", got)
	}
	for i := 0; i < 16; i++ { // then 95% held for 30 s
		reading(95)
	}
	if got := tr.waitFor(1); len(got) != 1 || got[0] != "at90.example" {
		t.Fatalf("CPU held at 95%% reached %v, want only at90.example: the channel set to 90 "+
			"must hear it, and the one already told about the episode must not be told twice", got)
	}
	for i := 0; i < 17; i++ { // back to normal for the hold
		reading(20)
	}
	if got := tr.waitFor(2); len(got) != 2 {
		t.Fatalf("the recovery reached %v, want both channels: both heard the episode", got)
	}
}
