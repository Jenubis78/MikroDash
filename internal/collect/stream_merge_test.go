package collect

import (
	"testing"
	"time"

	"mikrodash/internal/hub"
	"mikrodash/internal/roscache"
	"mikrodash/internal/routeros"
)

// TestTwoReadersOfOneStreamedMenuShareOneChannel is the bug a review of the
// streaming coverage found on 2026-10-15: the first collector to join a
// streamed menu opened the channel with ITS proplist and cadence, and a second
// was refused and read whatever the first carried. `wireless` reads every
// field of the Wi-Fi registration table and `capsman` five, so which started
// first decided whether the Wi-Fi Clients page had its columns.
//
// Both orders, because the bug was an order: the merged command must be the
// same whoever joins first.
func TestTwoReadersOfOneStreamedMenuShareOneChannel(t *testing.T) {
	const menu = "/interface/wifi/registration-table/print"
	want := "=interval=10" // the finer of the two cadences, every field (no proplist)
	for _, order := range []string{"narrow first", "wide first"} {
		t.Run(order, func(t *testing.T) {
			r := &streamReader{}
			c := roscache.New(r)
			c.StreamWhen(func(string) bool { return true })
			narrow := &scheduled{cache: c, menu: menu, // capsman's shape
				cadence: func() time.Duration { return 10 * time.Second },
				fields:  []string{"interface", "mac-address", "ssid", "signal", "uptime"}}
			wide := &scheduled{cache: c, menu: menu, // wireless's: every field
				cadence: func() time.Duration { return 30 * time.Second }}
			first, second := narrow, wide
			if order == "wide first" {
				first, second = wide, narrow
			}
			first.begin()
			defer first.end()
			second.begin()
			defer second.end()

			if second.unfill == nil {
				t.Fatal("the second reader was refused the channel; it reads whatever " +
					"the first one asked for")
			}
			r.mu.Lock()
			last := r.args[len(r.args)-1]
			r.mu.Unlock()
			if last != want {
				t.Errorf("channel opened with %q, want %q: every field one reader needs, "+
					"at the finest cadence either asked for", last, want)
			}
			if got := c.StreamedMenus(); len(got) != 1 {
				t.Errorf("streamed menus = %v, want one channel for both readers", got)
			}
		})
	}
}

// TestMergeTableStream pins the rule itself.
func TestMergeTableStream(t *testing.T) {
	cmd := func(args ...string) routeros.Cmd { return routeros.Cmd{Path: "/ip/arp/print", Args: args} }
	cases := []struct {
		name string
		in   []routeros.Cmd
		want string
	}{
		{"one holder keeps its own words, with .id added",
			[]routeros.Cmd{cmd("=interval=30", "=.proplist=address,interface")},
			"=interval=30 =.proplist=.id,address,interface"},
		{"the union of the fields and the finest interval",
			[]routeros.Cmd{cmd("=interval=30", "=.proplist=address,mac-address"),
				cmd("=interval=5", "=.proplist=interface,address")},
			"=interval=5 =.proplist=.id,address,interface,mac-address"},
		{"a holder asking for every field means no proplist",
			[]routeros.Cmd{cmd("=interval=3", "=.proplist=address"), cmd("=interval=9")},
			"=interval=3"},
		{"CONTROL: no interval at all floors to one second",
			[]routeros.Cmd{cmd("=.proplist=.id")},
			"=interval=1 =.proplist=.id"},
	}
	for _, c := range cases {
		got := mergeTableStream(c.in)
		s := ""
		for i, a := range got.Args {
			if i > 0 {
				s += " "
			}
			s += a
		}
		if s != c.want || got.Path != "/ip/arp/print" {
			t.Errorf("%s: got %s %q, want %q", c.name, got.Path, s, c.want)
		}
	}
	// Order-independent, so a set of holders always opens the same command.
	a, b := cmd("=interval=8", "=.proplist=b,a"), cmd("=interval=4", "=.proplist=c")
	if x, y := mergeTableStream([]routeros.Cmd{a, b}), mergeTableStream([]routeros.Cmd{b, a}); !sameWords(x.Args, y.Args) {
		t.Errorf("the merge depends on holder order: %q vs %q", x.Args, y.Args)
	}
}

// TestAStreamProplistCarriesTheID: measured on CHR Test (7.24.5), a proplist
// without `.id` returns rows without one, which `keyByID` cannot name.
func TestAStreamProplistCarriesTheID(t *testing.T) {
	got := defaultStreamArgs(func() time.Duration { return 30 * time.Second },
		[]string{"mac-address", "on-interface"})
	if len(got) != 2 || got[1] != "=.proplist=.id,mac-address,on-interface" {
		t.Errorf("stream args = %q; without .id every row is unkeyed", got)
	}
	// CONTROL: a proplist that already has it is left alone.
	got = defaultStreamArgs(nil, []string{".id", "name"})
	if got[1] != "=.proplist=.id,name" {
		t.Errorf("stream args = %q; .id was added twice or moved", got)
	}
}

func sameWords(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestVPNSubscribesItsWireGuardPeers: the peers were read directly on a side
// loop, which a channel cannot back. They are a subscription of their own now,
// at the poll interval, beside /ppp/active on the slow lane.
func TestVPNSubscribesItsWireGuardPeers(t *testing.T) {
	c := roscache.New(&schedReader{})
	v := NewVPN(&schedReader{}, hub.Relay{}, 5000)
	v.UseCache(c)
	v.Start()
	defer v.Stop()

	got := map[string]time.Duration{}
	for _, d := range c.Demand() {
		got[d.Menu] = d.Cadence
	}
	if got[vpnPeersCmd.Path] != 5*time.Second {
		t.Errorf("demand = %v; the WireGuard peers must be subscribed at the poll interval", got)
	}
	if got[vpnPppCmd.Path] != vpnSlowTarget {
		t.Errorf("demand = %v; /ppp/active stays on the slow lane", got)
	}
	// AND THEY GO WITH IT. A subscription outliving Suspend keeps an
	// unwatched router's peers polled.
	v.Suspend()
	if d := c.Demand(); len(d) != 0 {
		t.Errorf("demand after Suspend = %v, want none", d)
	}
}
