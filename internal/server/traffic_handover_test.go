package server

import (
	"context"
	"strings"
	"testing"

	"mikrodash/internal/db"
	"mikrodash/internal/hub"
	"mikrodash/internal/routeros"
	"mikrodash/internal/session"
)

// The round trip: a router with Traffic Flow on goes to every packet, and the
// IPS Apply takes Traffic Flow off and records it as handed to the sensor; back
// to the first bytes, the IPS Apply puts it back. A removal somebody asked for
// is not put back.
func TestTrafficFlowIsHandedToTheSensorAndBack(t *testing.T) {
	d, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	eng := &trafficEngine{settings: db.TrafficSettings{Backend: "sqlite", Port: 2055, Collector: "192.168.11.5"},
		routers: map[string]*trafficRouter{}}
	eng.ctx, eng.cancel = context.WithCancel(context.Background())
	defer eng.cancel()
	s := &Server{auditDB: d, traffic: eng}
	eng.s = s

	targets := []routeros.Reply{}
	sn := session.NewForTestWithExec(hub.New(), "r1", func(cmd routeros.Cmd) ([]routeros.Reply, error) {
		switch cmd.Path {
		case "/ip/traffic-flow/print":
			return []routeros.Reply{{"enabled": "true", "interfaces": "all", "active-flow-timeout": "1m", "inactive-flow-timeout": "15s"}}, nil
		case "/ip/traffic-flow/target/print":
			return targets, nil
		case "/ip/traffic-flow/ipfix/print":
			return []routeros.Reply{{"bytes": "true"}}, nil
		}
		return nil, nil
	})
	sensor := db.IPSSensor{RouterID: "r1", Address: "192.168.11.250", Token: "t", SniffBytes: 20000}
	set := func(every bool) {
		sensor.EveryPacket = every
		if err := d.SaveIPSSensor(sensor); err != nil {
			t.Fatal(err)
		}
	}
	ops := func(steps []string) string { return strings.Join(steps, ",") }
	stepsOf := func(after string) (string, []string) {
		p, a := s.trafficHandover(sn, "r1")
		var out []string
		for _, st := range p.Steps {
			out = append(out, st.Op+" "+st.Menu)
		}
		if a != after {
			t.Fatalf("after %q, want %q (warnings %v)", a, after, p.Warnings)
		}
		return a, out
	}

	// Traffic Flow on, its target on the router; the sensor goes to every packet.
	_ = d.SaveTrafficRouter(db.TrafficRouter{RouterID: "r1", Enabled: true, Result: "applied"})
	targets = []routeros.Reply{{".id": "*T", "dst-address": "192.168.11.5", "port": "2055", "version": "IPFIX"}}
	set(true)
	a, steps := stepsOf("sensor")
	if ops(steps) != "remove /ip/traffic-flow/target,set /ip/traffic-flow" {
		t.Errorf("handed to the sensor: %v", steps)
	}
	s.recordHandover("r1", a)
	if row := s.trafficRouterRow("r1"); row.Enabled || row.Result != trafficHandedToSensor {
		t.Fatalf("%+v", row)
	}
	// Nothing more to do while it stays on every packet.
	targets = nil
	stepsOf("")

	// Back to the first bytes: Traffic Flow is put back.
	set(false)
	a, steps = stepsOf("ipfix")
	if ops(steps) != "add /ip/traffic-flow/target" {
		t.Errorf("put back: %v", steps)
	}
	s.recordHandover("r1", a)
	if row := s.trafficRouterRow("r1"); !row.Enabled || row.Result != "applied" {
		t.Fatalf("%+v", row)
	}

	// A removal somebody asked for stays removed.
	_ = d.SaveTrafficRouter(db.TrafficRouter{RouterID: "r1", Enabled: false, Result: "removed"})
	stepsOf("")
}
