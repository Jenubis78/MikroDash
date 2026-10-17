package alert

import (
	"strings"
	"testing"
)

// A WATCHED DEVICE: gone once, not again while it stays gone, back once.
func TestAWatchedDeviceGoingAndComingBack(t *testing.T) {
	store := &memStore{}
	ev := NewEvaluator(store)
	r := Router{ID: "r1", AlertsEnabled: true}
	const mac = "02:00:00:00:00:01"

	fired := ev.DeviceAbsent(r, mac, "Kitchen tablet", false)
	if len(fired) != 1 || fired[0].Up || fired[0].Subject != mac ||
		!strings.Contains(fired[0].Detail, "Kitchen tablet") {
		t.Fatalf("absence fired %+v, want one alert naming the device", fired)
	}
	if !store.HasOpen("r1", "device_absent", mac) {
		t.Error("nothing was filed")
	}
	if n := len(ev.DeviceAbsent(r, mac, "Kitchen tablet", false)); n != 0 {
		t.Errorf("a device still gone fired %d more alerts", n)
	}
	fired = ev.DeviceAbsent(r, mac, "Kitchen tablet", true)
	if len(fired) != 1 || !fired[0].Up {
		t.Fatalf("the return fired %+v, want one resolution", fired)
	}
	if store.HasOpen("r1", "device_absent", mac) {
		t.Error("the return did not close the row")
	}
	// A device present all along has nothing to resolve, and says nothing.
	if n := len(ev.DeviceAbsent(r, "02:00:00:00:00:02", "", true)); n != 0 {
		t.Errorf("a device never absent fired %d alerts", n)
	}
	// Each device is its own subject: one gone does not hide another.
	ev.DeviceAbsent(r, mac, "", false)
	if n := len(ev.DeviceAbsent(r, "02:00:00:00:00:02", "", false)); n != 1 {
		t.Errorf("a second absent device fired %d alerts, want 1", n)
	}
}

// DOMAIN ROUTING: one row per router, whatever the list is called.
func TestDomainRoutingGoingDownAndComingBack(t *testing.T) {
	store := &memStore{}
	ev := NewEvaluator(store)
	r := Router{ID: "r1", AlertsEnabled: true}

	fired := ev.DomainRouting(r, false, "No active route in vpn for traffic to to_vpn")
	if len(fired) != 1 || fired[0].Up || fired[0].Subject != "" || !strings.Contains(fired[0].Detail, "vpn") {
		t.Fatalf("an outage fired %+v, want one alert carrying why", fired)
	}
	if n := len(ev.DomainRouting(r, false, "a different reason")); n != 0 {
		t.Errorf("a standing outage fired %d more alerts", n)
	}
	if fired = ev.DomainRouting(r, true, ""); len(fired) != 1 || !fired[0].Up {
		t.Fatalf("the recovery fired %+v, want one resolution", fired)
	}
	if store.HasOpen("r1", "domain_routing_down", "") {
		t.Error("the recovery did not close the row")
	}
}

func TestTheFeatureAlertsHonourTheRouterSwitch(t *testing.T) {
	ev := NewEvaluator(&memStore{})
	off := Router{ID: "r1"}
	if n := len(ev.DeviceAbsent(off, "02:00:00:00:00:01", "", false)) + len(ev.DomainRouting(off, false, "x")); n != 0 {
		t.Errorf("a router with alert monitoring off fired %d alerts", n)
	}
	if n := len(ev.DeviceAbsent(Router{ID: "r1", AlertsEnabled: true}, "", "", false)); n != 0 {
		t.Errorf("a device with no MAC fired %d alerts", n)
	}
}
