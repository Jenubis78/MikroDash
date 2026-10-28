package ips

import (
	"testing"

	"mikrodash/internal/routeros"
)

func TestTheNewestReleaseAndWhetherItIsAnUpdate(t *testing.T) {
	if got := NewestRelease([]string{"latest", "0.1.0", "0.10.0", "0.9.3", "v0.2.0", "sha-abc"}); got != "0.10.0" {
		t.Errorf("newest %q", got)
	}
	if NewestRelease([]string{"latest"}) != "" {
		t.Error("no release among the tags")
	}
	for _, c := range []struct {
		running, newest string
		want            bool
	}{{"0.2.0", "0.3.0", true}, {"0.3.0", "0.3.0", false}, {"0.10.0", "0.9.0", false}, {"", "0.2.0", true},
		{"dev", "0.2.0", true}, {"0.2.0", "", false}} {
		if got := UpdateAvailable(c.running, c.newest); got != c.want {
			t.Errorf("%q -> %q: %v", c.running, c.newest, got)
		}
	}
}

func TestHowARouterUpdatesItsSensor(t *testing.T) {
	for v, want := range map[string]string{"7.22.1 (stable)": UpdateRepull, "7.24": UpdateRepull, "7.20.4 (long-term)": UpdateStopRepullStart,
		"7.21rc2 (testing)": UpdateStopRepullStart, "8.0": UpdateRepull} {
		if got, err := UpdateMethod(v); err != nil || got != want {
			t.Errorf("%s: %q %v", v, got, err)
		}
	}
	if _, err := UpdateMethod("7.19.6 (stable)"); err == nil {
		t.Error("7.19 has no repull")
	}
	if UpdateImage("ghcr.io/a/dpi:latest", "0.3.0") != "ghcr.io/a/dpi:latest" ||
		UpdateImage("ghcr.io/a/dpi:0.2.0", "0.3.0") != "ghcr.io/a/dpi:0.3.0" {
		t.Error("a moving tag stays, a pinned one moves to the newest")
	}
	row, ok := SensorContainer([]routeros.Reply{{".id": "*1", "comment": "other"}, {".id": "*2", "comment": SensorComment, "tag": "x:1"}})
	if !ok || row[".id"] != "*2" || ContainerImage(row) != "x:1" {
		t.Errorf("%v", row)
	}
}

func TestAContainersStatusReadsFromEitherSpelling(t *testing.T) {
	for want, r := range map[string]routeros.Reply{"extracting": {"status": "extracting"}, "running": {"running": "true"},
		"stopped": {"stopped": "true"}, "": {}} {
		if got := ContainerStatus(r); got != want {
			t.Errorf("%v: %q", r, got)
		}
	}
}

func TestASensorBeforeReleasesWereReportedIs010(t *testing.T) {
	if ReleaseOf(Hello{Version: "1"}) != "0.1.0" || ReleaseOf(Hello{Version: "2", Build: "0.2.0"}) != "0.2.0" ||
		ReleaseOf(Hello{Version: "2", Build: "dev"}) != "dev" {
		t.Error("release")
	}
	if UpdateAvailable(ReleaseOf(Hello{Version: "1"}), "0.1.0") {
		t.Error("0.1.0 offered to itself")
	}
}
