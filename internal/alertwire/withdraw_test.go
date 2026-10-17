package alertwire

import (
	"testing"

	"mikrodash/internal/alert"
)

// A WITHDRAWN ALERT IS CLOSED AND SAYS NOTHING. Switching a feature off, or no
// longer watching a device, must not leave its alert open for ever, and must
// not tell anyone the condition recovered: it did not.
func TestAWithdrawnAlertClosesSilently(t *testing.T) {
	w := New(nil)
	w.SetPersisting("r1", false)
	r := alert.Router{ID: "r1", AlertsEnabled: true}

	if fired := w.DomainRouting(r, false, "No active route in vpn"); len(fired) != 1 {
		t.Fatalf("the outage fired %+v", fired)
	}
	w.Withdraw("r1", "domain_routing_down", "")
	if fired := w.DomainRouting(r, true, ""); len(fired) != 0 {
		t.Errorf("a recovery after the withdrawal fired %+v; the row was still open", fired)
	}
	if fired := w.DomainRouting(r, false, "again"); len(fired) != 1 {
		t.Errorf("a new outage after the withdrawal fired %+v, want a fresh alert", fired)
	}

	if fired := w.DeviceAbsent(r, "02:00:00:00:00:01", "tablet", false); len(fired) != 1 {
		t.Fatalf("the absence fired %+v", fired)
	}
	w.Withdraw("r1", "device_absent", "02:00:00:00:00:01")
	if fired := w.DeviceAbsent(r, "02:00:00:00:00:01", "tablet", true); len(fired) != 0 {
		t.Errorf("the device's return after it was unwatched fired %+v", fired)
	}
}

// TestWithdrawingWhatIsNotOpenChangesNothing. The feature loop withdraws on every
// router once, whether or not it raised anything there.
func TestWithdrawingWhatIsNotOpenChangesNothing(t *testing.T) {
	w := New(nil)
	w.SetPersisting("r1", false)
	r := alert.Router{ID: "r1", AlertsEnabled: true}
	w.Withdraw("r1", "device_absent", "02:00:00:00:00:01")
	w.Withdraw("r1", "domain_routing_down", "")
	if fired := w.DeviceAbsent(r, "02:00:00:00:00:01", "tablet", false); len(fired) != 1 {
		t.Errorf("the absence after a withdrawal of nothing fired %+v, want one alert", fired)
	}
}
