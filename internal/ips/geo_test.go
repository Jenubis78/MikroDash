package ips

import (
	"net/netip"
	"reflect"
	"testing"

	"mikrodash/internal/routeros"
)

func TestEachGeoDirectionDropsOnlyNewConnectionsOnItsSide(t *testing.T) {
	sides := func(dir string) []string {
		var out []string
		for _, w := range GeoWant(dir) {
			if w.Props["connection-state"] != "new" || w.Props["action"] != "drop" || !GeoOwned(routeros.Reply(w.Props)) {
				t.Errorf("%s: %+v", dir, w.Props)
			}
			side := "dst"
			if w.Props["src-address-list"] == GeoList {
				side = "src"
			}
			out = append(out, w.Props["chain"]+" "+side)
		}
		return out
	}
	for dir, want := range map[string][]string{
		GeoIn:   {"forward src", "input src"},
		GeoOut:  {"forward dst"},
		GeoBoth: {"forward src", "input src", "forward dst"},
		"":      nil,
	} {
		if got := sides(dir); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v, want %v", dir, got, want)
		}
	}
}

func TestChangingDirectionRemovesTheOtherSideAndLeavesTheOperatorsRules(t *testing.T) {
	filter := []routeros.Reply{{".id": "*1", "chain": "forward", "action": "fasttrack-connection", "dynamic": "true"},
		{".id": "*2", "chain": "input", "action": "accept", "comment": "theirs"}}
	for i, w := range GeoWant(GeoBoth) {
		r := routeros.Reply{".id": "*a" + string(rune('0'+i))}
		for k, v := range w.Props {
			r[k] = v
		}
		filter = append(filter, r)
	}
	steps := GeoRulesPlan(GeoOut, filter)
	if len(steps) != 2 || steps[0].Op != "remove" || steps[1].Op != "remove" {
		t.Fatalf("%+v", steps)
	}
	for _, s := range GeoRulesPlan("", filter) {
		if s.ID == "*2" || s.ID == "*1" {
			t.Errorf("removed a rule the IPS does not own: %+v", s)
		}
	}
	adds := GeoRulesPlan(GeoIn, filter[:2])
	if len(adds) != 2 || adds[0].Args["place-before"] != "*2" {
		t.Errorf("a missing rule goes above the first static foreign one: %+v", adds)
	}
}

func TestTheListSyncWritesOnlyTheDifference(t *testing.T) {
	want := map[string][]netip.Prefix{
		"FR": {netip.MustParsePrefix("2.0.0.0/12"), netip.MustParsePrefix("5.135.0.0/16")},
		"CN": {netip.MustParsePrefix("1.0.1.0/24"), netip.MustParsePrefix("1.0.8.1/32")},
	}
	have := []routeros.Reply{
		{".id": "*5", "address": "2.0.0.0/12"},
		{".id": "*6", "address": "1.0.8.1"},     // a /32 prints bare
		{".id": "*7", "address": "2.0.0.0/12"},  // a duplicate
		{".id": "*8", "address": "9.9.9.0/24"},  // a country no longer chosen
		{".id": "*9", "address": "example.com"}, // not a prefix
	}
	add, remove := GeoEntriesPlan(want, have)
	if !reflect.DeepEqual(remove, []string{"*7", "*8", "*9"}) {
		t.Errorf("remove %v", remove)
	}
	if len(add) != 2 || add[0].Prefix.String() != "1.0.1.0/24" || add[0].Country != "CN" || add[1].Country != "FR" {
		t.Errorf("add %+v", add)
	}
	if args := GeoEntryArgs(GeoEntry{netip.MustParsePrefix("1.0.8.1/32"), "CN"}); args[1] != "=address=1.0.8.1" ||
		args[0] != "=list="+GeoList || args[2] != "=comment="+Marker+" geo CN" {
		t.Errorf("%v", args)
	}
}

func TestAGeoChoiceHoldingTheRoutersOwnAddressIsAConflict(t *testing.T) {
	want := map[string][]netip.Prefix{"FR": {netip.MustParsePrefix("198.51.100.0/24")}}
	own := []netip.Addr{netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.1")}
	if got := GeoConflicts(want, own); !reflect.DeepEqual(got, []string{"198.51.100.7 (FR)"}) {
		t.Errorf("%v", got)
	}
}

func TestAGeoChoiceIsCleanedAndItsDirectionChecked(t *testing.T) {
	got, err := GeoValidate([]string{"ru", " CN", "RU"}, GeoBoth)
	if err != nil || !reflect.DeepEqual(got, []string{"CN", "RU"}) {
		t.Errorf("%v %v", got, err)
	}
	if _, err := GeoValidate([]string{"CHN"}, GeoIn); err == nil {
		t.Error("a three-letter code")
	}
	if _, err := GeoValidate(nil, "sideways"); err == nil {
		t.Error("an unknown direction")
	}
}
