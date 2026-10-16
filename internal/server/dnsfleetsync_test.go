package server

import (
	"reflect"
	"testing"

	"mikrodash/internal/routeros"
)

// TestAFleetSyncCopiesAndChangesButRemovesOnlyWhenAsked. The reference's
// records are added where missing and rewritten where they differ; a dynamic
// entry on either side is never copied, changed or removed; an extra record
// goes only with removeExtra. Round-robin A records line up by value.
func TestAFleetSyncCopiesAndChangesButRemovesOnlyWhenAsked(t *testing.T) {
	ref := []routeros.Reply{
		{".id": "*1", "name": "a.com", "type": "FWD", "forward-to": "zfwdentry", "address-list": "to_vpn"},
		{".id": "*2", "name": "b.com", "type": "FWD", "forward-to": "zfwdentry", "address-list": "to_vpn"},
		{".id": "*3", "name": "pc.lan", "type": "A", "address": "198.51.100.5", "dynamic": "true"},
		{".id": "*4", "name": "www.lan", "type": "A", "address": "198.51.100.1"},
		{".id": "*5", "name": "www.lan", "type": "A", "address": "198.51.100.2"},
	}
	target := []routeros.Reply{
		{".id": "*1", "name": "b.com", "type": "FWD", "forward-to": "zfwdentry", "address-list": "old"},
		{".id": "*2", "name": "extra.com", "type": "FWD", "forward-to": "zfwdentry"},
		{".id": "*3", "name": "pc2.lan", "type": "A", "address": "198.51.100.6", "dynamic": "true"},
		{".id": "*4", "name": "www.lan", "type": "A", "address": "198.51.100.1"},
	}
	in := PlanFleetSync(ref, target, false)
	var added []string
	for _, a := range in.Add {
		added = append(added, a["name"].(string)+" "+firstNonEmpty(asString(a["address"]), asString(a["forwardTo"])))
	}
	if !reflect.DeepEqual(added, []string{"a.com zfwdentry", "www.lan 198.51.100.2"}) {
		t.Errorf("added %v; want the missing record and the second round-robin address, not the dynamic one", added)
	}
	if len(in.Set) != 1 || in.Set[0].ID != "*1" || in.Set[0].Values["addressList"] != "to_vpn" {
		t.Errorf("set %+v; want b.com rewritten to the reference's address list", in.Set)
	}
	if len(in.Remove) != 0 {
		t.Errorf("removed %v without being asked", in.Remove)
	}
	if got := PlanFleetSync(ref, target, true).Remove; !reflect.DeepEqual(got, []string{"*2"}) {
		t.Errorf("asked, removed %v; want the extra static record and never the dynamic one", got)
	}
	if _, errs := planDNSBulk(in, target); len(errs) > 0 {
		t.Errorf("the plan would be refused: %v", errs)
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// TestAFleetSyncReadsNamesWithoutCaseAndLeavesADynamicTargetAlone. RouterOS keeps
// the case a name was written in and the resolver answers both, so a name in
// another case is neither added nor rewritten; and an entry a DHCP server made
// on the target, under a name the reference holds statically, is left as it is.
func TestAFleetSyncReadsNamesWithoutCaseAndLeavesADynamicTargetAlone(t *testing.T) {
	ref := []routeros.Reply{
		{".id": "*1", "name": "MDPROBE.test", "type": "A", "address": "198.51.100.1"},
		{".id": "*2", "name": "pc.lan", "type": "A", "address": "198.51.100.5"},
		{".id": "*3", "name": "rr.lan", "type": "A", "address": "198.51.100.7"},
		{".id": "*4", "name": "rr.lan", "type": "A", "address": "198.51.100.8"},
	}
	target := []routeros.Reply{
		{".id": "*1", "name": "mdprobe.test", "type": "A", "address": "198.51.100.1"},
		{".id": "*2", "name": "pc.lan", "type": "A", "address": "198.51.100.99", "dynamic": "true"},
		{".id": "*3", "name": "RR.lan", "type": "A", "address": "198.51.100.7"},
	}
	in := PlanFleetSync(ref, target, true)
	if len(in.Add) != 1 || in.Add[0]["address"] != "198.51.100.8" {
		t.Errorf("add = %v; want only the second round-robin address", in.Add)
	}
	if len(in.Set) != 0 {
		t.Errorf("set = %+v; a name in another case and a dynamic target need no change", in.Set)
	}
	if len(in.Remove) != 0 {
		t.Errorf("remove = %v; nothing on the target is extra", in.Remove)
	}
	if _, errs := planDNSBulk(in, target); len(errs) > 0 {
		t.Errorf("the plan would be refused: %v", errs)
	}
}
