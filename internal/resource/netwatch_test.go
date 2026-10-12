package resource

import (
	"strings"
	"testing"
)

// THE NETWATCH FORM NEVER CARRIES CODE, AND ONLY SENDS WHAT A PROBE USES (#97).

func TestNetwatchNeverOffersScripts(t *testing.T) {
	for _, f := range Netwatch.Fields {
		if strings.HasSuffix(f.ROS, "-script") {
			t.Errorf("%s is a field: a NetWatch script runs as RouterOS's system user", f.ROS)
		}
	}
}

// THE RECORD TYPE IS A SELECT, SO ITS LIST MUST BE THE ROUTER'S.
//
// This test refused `record-type` and `dns-server` as fields until 2026-10-12,
// when RouterOS documented no list of record types and a select missing one
// would have rewritten the probe on save. The CLI Reference now documents A,
// AAAA, MX and NS, and the CHR (7.24.5) refuses anything else, so the field is
// offered and the list is pinned instead. A RouterOS that adds a type must be
// added here, or a probe using it reads as A.
func TestNetwatchRecordTypesAreTheDocumentedFour(t *testing.T) {
	for _, f := range Netwatch.Fields {
		if f.ROS != "record-type" {
			continue
		}
		if f.Type != TypeSelect || strings.Join(f.Options, ",") != "A,AAAA,MX,NS" || f.Default != "A" {
			t.Errorf("record-type: type %s, options %v, default %q; want a select of A,AAAA,MX,NS defaulting to A",
				f.Type, f.Options, f.Default)
		}
		return
	}
	t.Fatal("the NetWatch resource has no record-type field")
}

// A BLANK TUNABLE IS THE DEFAULT, AND AN EDIT SAYS NOTHING ABOUT ONE IT NEVER SET.
//
// `print` omits a property at its default, so the form shows it blank, and a
// blank one must reset with `=!prop=` - an empty time is refused. Measured on
// the CHR, 7.24.5.
func TestNetwatchBlankTunablesResetToTheDefault(t *testing.T) {
	for _, f := range Netwatch.Fields {
		if f.Type != TypeText && f.Type != TypeInt {
			continue
		}
		switch f.ROS {
		case "name", "host", "comment":
			continue
		}
		if !f.Clearable || !f.ClearBang {
			t.Errorf("%s: a blank box must reset it to the RouterOS default with =!%s=", f.ROS, f.ROS)
		}
	}

	edit := func(form, stored map[string]string) string {
		v, errs := Netwatch.Validate(form, true)
		if len(errs) > 0 {
			t.Fatalf("%v failed validation: %+v", form, errs)
		}
		v.Stored = stored
		return strings.Join(Netwatch.BuildArgs(v), " ")
	}
	form := map[string]string{"host": "198.51.100.1", "type": "icmp", "thr-avg": "", "packet-count": "5"}
	args := edit(form, map[string]string{"host": "198.51.100.1", "type": "icmp", "thr-avg": "50ms"})
	if !strings.Contains(args, "=!thr-avg=") || !strings.Contains(args, "=packet-count=5") {
		t.Errorf("an ICMP edit blanking a held thr-avg sent %q, want =!thr-avg= and =packet-count=5", args)
	}
	if strings.Contains(args, "thr-max") {
		t.Errorf("an edit cleared thr-max, which the row never held: %q", args)
	}
	simple := edit(map[string]string{"host": "198.51.100.1", "type": "simple", "thr-avg": "50ms"},
		map[string]string{"host": "198.51.100.1", "type": "simple", "thr-avg": "50ms"})
	if strings.Contains(simple, "thr-") || strings.Contains(simple, "packet-") {
		t.Errorf("a simple probe's edit sent ICMP settings, which it does not use: %q", simple)
	}
}

func TestNetwatchProbeTypesAreTheDocumentedSix(t *testing.T) {
	want := []string{"simple", "icmp", "tcp-conn", "http-get", "https-get", "dns"}
	for _, f := range Netwatch.Fields {
		if f.Name != "type" {
			continue
		}
		if strings.Join(f.Options, ",") != strings.Join(want, ",") {
			t.Errorf("probe types %v, want %v", f.Options, want)
		}
		return
	}
	t.Fatal("the NetWatch resource has no type field")
}

func TestNetwatchSendsAPortOnlyForAProbeThatUsesOne(t *testing.T) {
	simple, errs := Netwatch.Validate(map[string]string{
		"host": "8.8.8.8", "type": "simple", "port": "53", "disabled": "false",
	}, false)
	if len(errs) > 0 {
		t.Fatalf("a simple probe failed validation: %+v", errs)
	}
	if _, has := simple.Values["port"]; has {
		t.Error("a port was sent for a simple probe, which has none")
	}
	tcp, errs := Netwatch.Validate(map[string]string{
		"host": "8.8.8.8", "type": "tcp-conn", "port": "53", "disabled": "false",
	}, false)
	if len(errs) > 0 || tcp.Values["port"] != "53" {
		t.Errorf("a tcp-conn probe's port = %q (errors %+v), want 53", tcp.Values["port"], errs)
	}
	if _, errs := Netwatch.Validate(map[string]string{"type": "simple", "disabled": "false"}, false); len(errs) == 0 {
		t.Error("a probe with no host passed validation")
	}
}
