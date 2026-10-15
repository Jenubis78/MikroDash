package collect

import (
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"mikrodash/internal/hub"
	"mikrodash/internal/roscache"
	"mikrodash/internal/routeros"
)

// queueReader answers the two queue menus with one row each, and counts reads.
type queueReader struct {
	mu    sync.Mutex
	reads map[string]int
}

func (r *queueReader) Connected() bool { return true }
func (r *queueReader) Do(c routeros.Cmd) ([]routeros.Reply, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.reads == nil {
		r.reads = map[string]int{}
	}
	r.reads[c.Path]++
	// The counters move with every read, as on a busy router, so each reading
	// carries a new rate and nothing is held back by the dirty check.
	n := strconv.Itoa(r.reads[c.Path] * 1_000_000)
	switch c.Path {
	case queueSimpleCmd:
		return []routeros.Reply{{".id": "*1", "name": "lan", "bytes": n + "/" + n, "rate": "0/0"}}, nil
	case queueTreeCmd:
		return []routeros.Reply{{".id": "*A", "name": "down", "parent": "global", "bytes": n, "rate": "0"}}, nil
	}
	return nil, nil
}

func demandOf(c *roscache.Cache) map[string]time.Duration {
	out := map[string]time.Duration{}
	for _, d := range c.Demand() {
		out[d.Menu] = d.Cadence
	}
	return out
}

// TestQueuesSubscribesItsTree: the tree was a direct read inside `derive`, one
// command per simple-queue round that no channel could back. It is a
// subscription of its own now, at the same cadence, and goes with the simple
// queues on Suspend and comes back on Resume.
func TestQueuesSubscribesItsTree(t *testing.T) {
	c := roscache.New(&queueReader{})
	q := NewQueues(&queueReader{}, hub.Relay{}, nil, 5000)
	q.UseCache(c)
	q.Start()
	defer q.Stop()

	got := demandOf(c)
	if got[queueSimpleCmd] != 5*time.Second || got[queueTreeCmd] != 5*time.Second {
		t.Fatalf("demand = %v; both queue menus must be subscribed at the poll interval", got)
	}
	q.Suspend()
	if d := c.Demand(); len(d) != 0 {
		t.Errorf("demand after Suspend = %v; the tree outlived the simple queues", d)
	}
	q.Resume()
	if got := demandOf(c); len(got) != 2 {
		t.Errorf("demand after Resume = %v, want both menus again", got)
	}
}

// TestAnAbsentTreeIsNotAskedAgainUntilAReconnect: what readOptional's latch did
// for the tree when `derive` read it, the core now does for an also-menu.
func TestAnAbsentTreeIsNotAskedAgainUntilAReconnect(t *testing.T) {
	c := roscache.New(&queueReader{})
	q := NewQueues(&queueReader{}, hub.Relay{}, nil, 5000)
	q.UseCache(c)
	q.Start()
	defer q.Stop()

	q.applyAlso(0, nil, errors.New("no such command prefix"), true)
	if _, held := demandOf(c)[queueTreeCmd]; held {
		t.Error("a router without /queue/tree is still asked for it every interval")
	}
	q.Resume() // a Resume must not bring it back either
	if _, held := demandOf(c)[queueTreeCmd]; held {
		t.Error("Resume re-subscribed a menu the router said it does not have")
	}
	// CONTROL: a reconnect may be a different build, so it is asked again.
	q.Reconnected()
	if _, held := demandOf(c)[queueTreeCmd]; !held {
		t.Error("the tree was not asked for again after a reconnect")
	}
}

// TestEachQueueKindMeasuresOnlyItsOwnRates: the two menus arrive separately, so
// building one must not prune the other's baselines. One shared prune dropped
// every simple-queue baseline on a tree-only build, and the next simple reading
// was a first sample again.
func TestEachQueueKindMeasuresOnlyItsOwnRates(t *testing.T) {
	prev := map[string]queueSample{}
	t0 := time.Unix(1000, 0)
	simple := []routeros.Reply{{".id": "*1", "name": "lan", "bytes": "1000/2000"}}
	tree := []routeros.Reply{{".id": "*A", "name": "down", "bytes": "5000"}}
	BuildSimpleRows(simple, prev, t0)
	BuildTreeRows(tree, prev, t0)

	BuildTreeRows(tree, prev, t0.Add(3*time.Second))
	if _, ok := prev[rateKey("s", simple[0])]; !ok {
		t.Fatal("a tree reading dropped the simple queue's baseline")
	}
	BuildSimpleRows(simple, prev, t0.Add(4*time.Second))
	if _, ok := prev[rateKey("t", tree[0])]; !ok {
		t.Fatal("a simple-queue reading dropped the tree's baseline")
	}
	// And the measurement is still a delta against the first reading.
	moved := []routeros.Reply{{".id": "*1", "name": "lan", "bytes": "2000/4000"}}
	rows := BuildSimpleRows(moved, prev, t0.Add(5*time.Second))
	if rows[0].RateSource == nil || *rows[0].RateSource != "delta" || rows[0].RateBps.Up == nil ||
		*rows[0].RateBps.Up != 1600 {
		t.Errorf("rate = %+v from %v; want a delta of 1000 bytes over 5 s = 1600 bit/s",
			rows[0].RateBps, rows[0].RateSource)
	}
}

// TestAPolledQueuesReadingSendsOnceWithBothTables: with no cache (the
// background pools), a reading reads the tree first and sends once, carrying it.
func TestAPolledQueuesReadingSendsOnceWithBothTables(t *testing.T) {
	var sent []QueuesPayload
	emit := hub.NewRelay(func(_ string, _ hub.Named, p any) { sent = append(sent, p.(QueuesPayload)) })
	r := &queueReader{}
	q := NewQueues(r, emit, nil, 5000)
	q.Tick()
	time.Sleep(20 * time.Millisecond) // a measurable window for the second rates
	q.Tick()

	// The SECOND reading is the one that tells: on the first, the tree has no
	// simple queues to ride with yet and could not send on its own anyway.
	if len(sent) != 2 {
		t.Fatalf("two polled readings sent %d payloads, want one each", len(sent))
	}
	if len(sent[1].Simple) != 1 || len(sent[1].Tree) != 1 {
		t.Errorf("payload has %d simple and %d tree rows, want 1 and 1",
			len(sent[1].Simple), len(sent[1].Tree))
	}
	if r.reads[queueTreeCmd] != 2 || r.reads[queueSimpleCmd] != 2 {
		t.Errorf("reads = %v, want each menu once per reading", r.reads)
	}
}

// TestATreeReadingWaitsForTheSimpleQueues: under the scheduler the tree may
// arrive first. It sends nothing until the simple queues have, then rides with
// them; a tree reading after that sends on its own.
func TestATreeReadingWaitsForTheSimpleQueues(t *testing.T) {
	var sent []QueuesPayload
	emit := hub.NewRelay(func(_ string, _ hub.Named, p any) { sent = append(sent, p.(QueuesPayload)) })
	r := &queueReader{}
	q := NewQueues(r, emit, nil, 5000)
	tree, _ := r.Do(routeros.Cmd{Path: queueTreeCmd})
	simple, _ := r.Do(routeros.Cmd{Path: queueSimpleCmd})

	q.applyAlso(0, tree, nil, true)
	if len(sent) != 0 {
		t.Fatalf("a tree reading before any simple one sent %d payloads", len(sent))
	}
	q.apply(simple, nil)
	if len(sent) != 1 || len(sent[0].Tree) != 1 {
		t.Fatalf("the first simple reading sent %d payloads; want one carrying the tree", len(sent))
	}
	// A changed tree sends at once, with the simple queues as last built.
	changed := []routeros.Reply{{".id": "*A", "name": "down", "parent": "global", "bytes": "300",
		"rate": "0", "max-limit": "1000000"}}
	q.applyAlso(0, changed, nil, true)
	if len(sent) != 2 || len(sent[1].Simple) != 1 || sent[1].Tree[0].MaxLimit.Bps != 1000000 {
		t.Errorf("a changed tree did not send with the simple queues alongside: %d sends", len(sent))
	}
}
