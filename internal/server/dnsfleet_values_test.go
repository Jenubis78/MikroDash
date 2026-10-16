package server

import (
	"encoding/json"
	"testing"

	"mikrodash/internal/collect"
	"mikrodash/internal/resource"
	"mikrodash/internal/routeros"
)

// A ROW THIS ENDPOINT READ MUST BE A ROW IT CAN WRITE BACK.
//
// `copy →` and `Sync all missing` take the `values` object the fleet read sent
// and post it straight back. That only works if the shape one half produces is
// the shape the other half accepts, and for a while it was not: `RowValues`
// emits a bool for a checkbox and the handler decoded into `map[string]string`,
// so the request became a 400 and both buttons did nothing at all — silently,
// with the table reloading unchanged. The Add dialog kept working, because a
// form only ever produces strings, which is why it went unnoticed.
//
// The round trip is the whole test: marshal as the browser would, decode as the
// handler does, and validate. It goes through `flattenValues`, which is also
// what `resSave` uses — one flattener, so a row copied across the fleet and a row
// saved from the dialog cannot reach a router differently.
func TestAFleetRowSurvivesTheRoundTripBackToTheRouter(t *testing.T) {
	row := map[string]string{
		".id": "*C9", "name": "example.test", "type": "FWD",
		"forward-to": "198.51.100.53", "ttl": "1d",
		"match-subdomain": "true", "disabled": "false", "comment": "note",
	}
	vals := resource.DNSStatic.RowValues(row)

	// WITHOUT A BOOL IN IT this test proves nothing, so it says so rather than
	// passing on a row that cannot reach the case it exists for.
	if _, ok := vals["matchSubdomain"].(bool); !ok {
		t.Fatalf("the projected row carries no boolean any more: %#v", vals)
	}

	wire, err := json.Marshal(map[string]any{"routerIds": []string{"a"}, "values": vals})
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		RouterIDs []string       `json:"routerIds"`
		Values    map[string]any `json:"values"`
	}
	if err := json.Unmarshal(wire, &body); err != nil {
		t.Fatalf("the handler cannot decode what the read sent: %v", err)
	}

	got := flattenValues(body.Values)
	if got["matchSubdomain"] != "true" || got["disabled"] != "false" {
		t.Errorf("matchSubdomain=%q disabled=%q, want true/false — the spelling a "+
			"checkbox sends and Validate reads", got["matchSubdomain"], got["disabled"])
	}
	validated, errs := resource.DNSStatic.Validate(got, false)
	if len(errs) > 0 {
		t.Fatalf("a row read from a router failed validation on the way back: %+v", errs)
	}
	// KEYED BY FIELD NAME, not by the RouterOS property — `BuildArgs` maps them
	// on the way out. And the toggle has become RouterOS's own spelling.
	if validated.Values["name"] != "example.test" || validated.Values["forwardTo"] != "198.51.100.53" {
		t.Errorf("the copy lost a value: %+v", validated.Values)
	}
	if validated.Values["matchSubdomain"] != "yes" {
		t.Errorf("matchSubdomain reached the router as %q, want yes",
			validated.Values["matchSubdomain"])
	}
}

// A ROUND-ROBIN RECORD IS PRESENT ONLY WITH ITS VALUE. Once a router holds two
// A records of a name, the comparison lines them up by value and shows the
// second as missing elsewhere; its copy must add it rather than answer that the
// name is already there. Without byValue, the Add dialog's "also add it to",
// any record of the name and type is the record, as before.
func TestARoundRobinRecordIsPresentOnlyWithItsValue(t *testing.T) {
	rows := []routeros.Reply{{".id": "*1", "name": "www.lan", "type": "A", "address": "198.51.100.1"}}
	record := func(v map[string]string) collect.DNSStaticEntry { return dnsRecordOf(resource.DNSStatic, v) }
	first := record(map[string]string{"name": "www.lan", "type": "A", "address": "198.51.100.1"})
	second := record(map[string]string{"name": "www.lan", "type": "A", "address": "198.51.100.2"})
	if !dnsAlreadyPresent(rows, second, false) {
		t.Error("by name and type, the router's A record of www.lan was not the record")
	}
	if dnsAlreadyPresent(rows, second, true) {
		t.Error("the second round-robin record was taken for the first, so its copy writes nothing")
	}
	if !dnsAlreadyPresent(rows, first, true) {
		t.Error("the record the router holds was not found by its value")
	}
	re := record(map[string]string{"regexp": `^ads\.`, "type": "A", "address": "198.51.100.1"})
	if dnsAlreadyPresent(rows, re, false) {
		t.Error("a regexp record was found in a router holding only a name record")
	}
	// RouterOS keeps a name's case; the resolver does not care about it.
	upper := record(map[string]string{"name": "WWW.lan", "type": "A", "address": "198.51.100.1"})
	if !dnsAlreadyPresent(rows, upper, true) {
		t.Error("the same name in another case was not found, so a copy would add a duplicate")
	}
}
