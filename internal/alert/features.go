package alert

// The alerts of two optional features (Settings -> Features). Neither reads a
// collector payload: the server's feature loop decides once a minute and hands
// in a debounced verdict, as the connectivity tracker does for RouterStatus,
// and the store's de-duplication keeps a standing verdict from ringing twice.

// DeviceAbsent evaluates one watched device. `subject` is its MAC, which stays
// the same when somebody renames the device; `label` is what the message calls
// it.
func (e *Evaluator) DeviceAbsent(r Router, subject, label string, present bool) []Fired {
	if r.ID == "" || !r.AlertsEnabled || subject == "" {
		return nil
	}
	name := label
	if name == "" {
		name = subject
	}
	if present {
		return e.emit(r, Fired{
			Up:          true,
			AlertType:   "Device Back",
			ResolveType: "device_absent",
			Subject:     subject,
			Detail:      name + " is on the network again",
		})
	}
	return e.emit(r, Fired{
		AlertType: "Device Absent",
		Subject:   subject,
		Detail:    name + " is gone from Wi-Fi and ARP",
	})
}

// DomainRouting evaluates whether traffic to the router's domain-routed
// address list has a way out. THE SUBJECT IS EMPTY, for RouterStatus's reason:
// a router routes by one list, and a subject holding its name would leave the
// alert open for ever the day the list is renamed. `why` says what is broken.
func (e *Evaluator) DomainRouting(r Router, ok bool, why string) []Fired {
	if r.ID == "" || !r.AlertsEnabled {
		return nil
	}
	if ok {
		return e.emit(r, Fired{
			Up:          true,
			AlertType:   "Domain Routing Restored",
			ResolveType: "domain_routing_down",
			Detail:      "Domain-routed traffic has its route again",
		})
	}
	return e.emit(r, Fired{
		AlertType: "Domain Routing Down",
		Detail:    why,
	})
}
