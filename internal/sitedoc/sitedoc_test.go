package sitedoc

import (
	"encoding/json"
	"testing"
)

// A floor-plan object's colour is drawn into a style, so anything but a hex
// colour is cleared when the plan is saved: a stored value carrying its own
// CSS declarations would run in every browser that opens the plan.
func TestWifiMapKeepsOnlyHexColours(t *testing.T) {
	for in, want := range map[string]string{
		"#38bdf8": "#38bdf8",
		"#abc":    "#abc",
		"":        "",
		"red":     "",
		"#38bdf8;background:url(https://x.test/)": "",
		"red;background:url(https://x.test/)":     "",
		"#12345":                                  "",
		"rgb(1,2,3)":                              "",
	} {
		raw, _ := json.Marshal(map[string]any{"objects": []map[string]any{{"id": "o1", "kind": "building", "colour": in}}})
		got := CleanWifiMap(raw)
		if len(got.Objects) != 1 || got.Objects[0].Colour != want {
			t.Errorf("colour %q was kept as %q, want %q", in, got.Objects[0].Colour, want)
		}
	}
}
