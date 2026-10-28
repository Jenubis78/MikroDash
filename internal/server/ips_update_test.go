package server

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"mikrodash/internal/hub"
	"mikrodash/internal/ips"
	"mikrodash/internal/routeros"
	"mikrodash/internal/session"
)

// A 7.21 router: a pinned image is moved to the newest release, then the
// sensor is stopped, re-pulled and started, and the job ends when the sensor
// says hello with the new release.
func TestASensorUpdateOnA721RouterStopsRepullsAndStarts(t *testing.T) {
	was := ipsUpdateStep
	ipsUpdateStep = time.Millisecond
	defer func() { ipsUpdateStep = was }()

	e := &ipsEngine{s: &Server{}, readers: map[string]*ipsReader{}}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	defer e.cancel()
	rd := &ipsReader{status: IPSStatus{State: "connected", Build: "0.1.0"}}
	e.readers["r1"] = rd

	var mu sync.Mutex
	state, image, pulls := "running", "ghcr.io/jenubis78/mikrodash-dpi:0.1.0", 0
	var sent []string
	sn := session.NewForTestWithExec(hub.New(), "r1", func(cmd routeros.Cmd) ([]routeros.Reply, error) {
		mu.Lock()
		defer mu.Unlock()
		switch cmd.Path {
		case "/system/resource/print":
			return []routeros.Reply{{"version": "7.21.3 (stable)"}}, nil
		case "/container/print":
			if state == "extracting" {
				if pulls++; pulls > 2 {
					state = "stopped"
				}
			}
			return []routeros.Reply{{".id": "*9", "comment": ips.SensorComment, "remote-image": image, "status": state}}, nil
		}
		sent = append(sent, cmd.Path+" "+strings.Join(cmd.Args, " "))
		switch cmd.Path {
		case "/container/set":
			image = strings.TrimPrefix(cmd.Args[1], "=remote-image=")
		case "/container/stop":
			state = "stopped"
		case "/container/repull":
			state = "extracting"
		case "/container/start":
			state = "running"
			rd.mu.Lock()
			rd.status.Build = "0.2.0"
			rd.mu.Unlock()
		}
		return nil, nil
	})
	var phases []string
	if msg := e.updateOn(sn, "r1", "0.2.0", func(p string) { phases = append(phases, p) }); msg != "" {
		t.Fatalf("%s (phases %v)", msg, phases)
	}
	want := []string{"/container/set =.id=*9 =remote-image=ghcr.io/jenubis78/mikrodash-dpi:0.2.0", "/container/stop =.id=*9",
		"/container/repull =.id=*9", "/container/start =.id=*9"}
	if strings.Join(sent, "|") != strings.Join(want, "|") {
		t.Errorf("sent %v", sent)
	}
}

// Before 7.20 there is no repull: the job says what to do instead and writes nothing.
func TestASensorUpdateBefore720WritesNothing(t *testing.T) {
	e := &ipsEngine{s: &Server{}, readers: map[string]*ipsReader{}}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	defer e.cancel()
	writes := 0
	sn := session.NewForTestWithExec(hub.New(), "r1", func(cmd routeros.Cmd) ([]routeros.Reply, error) {
		if cmd.Path == "/system/resource/print" {
			return []routeros.Reply{{"version": "7.19.4 (stable)"}}, nil
		}
		writes++
		return nil, nil
	})
	if msg := e.updateOn(sn, "r1", "0.2.0", func(string) {}); !strings.Contains(msg, "7.20") || writes != 0 {
		t.Errorf("%q, %d other commands", msg, writes)
	}
}
