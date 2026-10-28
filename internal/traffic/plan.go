package traffic

// What a router needs for MikroDash to read its traffic: Traffic Flow on,
// exporting IPFIX once a minute to MikroDash, with the fields the join reads.
// Pure, as the IPS's plan is: the router's rows in, steps out; the server runs
// them only when an administrator presses Apply.
//
// ── ONLY WHAT DIFFERS, AND ONLY MIKRODASH'S TARGET ──────────────────────────
//
// /ip/traffic-flow is one row shared with any other collector the operator
// has. The plan sets only the properties that differ, says so when another
// target will see the shorter timeout too, and Remove takes away MikroDash's
// own target, turning Traffic Flow off only when no other target is left.

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"mikrodash/internal/ips"
	"mikrodash/internal/routeros"
)

// ActiveTimeout is how often a long connection is exported: once a minute,
// the Live tab's resolution. RouterOS's default is 30m.
const ActiveTimeout = "1m"

// InactiveTimeout is RouterOS's default, kept: shorter overflows the cache.
const InactiveTimeout = "15s"

// TargetVersion is IPFIX as a target's `version` takes it. The documentation
// spells the enumeration `1 | 5 | 9 | IPFIX`, and a router refused that
// spelling live ("input does not match any value of version", 2026-10-28):
// the value is lower case, as /export prints it. A target already there is
// compared without regard to case.
const TargetVersion = "ipfix"

// IPFIXFields are the record fields the join reads; each must be "yes".
var IPFIXFields = []string{"bytes", "packets", "protocol", "src-address", "dst-address", "src-port", "dst-port",
	"nat-src-address", "nat-dst-address", "nat-src-port", "nat-dst-port", "in-interface", "out-interface",
	"first-forwarded", "last-forwarded", "sys-init-time"}

// PlanParams is where the router must send, and what it counts on.
type PlanParams struct {
	Collector netip.Addr
	Port      int
	// Interfaces is RouterOS's list, "all" when empty.
	Interfaces string
}

// ours is whether a target is the one sending to MikroDash.
func (p PlanParams) ours(t routeros.Reply) bool {
	a, err := netip.ParseAddr(t["dst-address"])
	return err == nil && a.Unmap() == p.Collector && t["port"] == strconv.Itoa(p.Port)
}

// RouterPlan is what the router must do. `tf` is /ip/traffic-flow, `targets`
// its targets, `ipfix` /ip/traffic-flow/ipfix, `filter` the firewall filter
// (read for FastTrack only). With remove, the plan takes MikroDash's target
// away.
func RouterPlan(p PlanParams, tf routeros.Reply, targets []routeros.Reply, ipfix routeros.Reply,
	filter []routeros.Reply, remove bool) ips.Plan {
	plan := ips.Plan{Steps: []ips.Step{}, Warnings: []string{}}
	var mine []routeros.Reply
	others := 0
	for _, t := range targets {
		if p.ours(t) {
			mine = append(mine, t)
		} else if t["disabled"] != "true" {
			others++
		}
	}
	if remove {
		for _, t := range mine {
			plan.Steps = append(plan.Steps, ips.Step{Op: "remove", Menu: "/ip/traffic-flow/target", ID: t[".id"],
				What: "remove the target " + t["dst-address"] + ":" + t["port"]})
		}
		if others == 0 && truthy(tf["enabled"]) {
			plan.Steps = append(plan.Steps, ips.Step{Op: "set", Menu: "/ip/traffic-flow",
				Args: map[string]string{"enabled": "no"}, What: "turn Traffic Flow off: no other target is left"})
		}
		return plan
	}
	iface := p.Interfaces
	if iface == "" {
		iface = "all"
	}
	set := map[string]string{}
	if !truthy(tf["enabled"]) {
		set["enabled"] = "yes"
	}
	if seconds(tf["active-flow-timeout"]) != 60 {
		set["active-flow-timeout"] = ActiveTimeout
	}
	if seconds(tf["inactive-flow-timeout"]) != 15 {
		set["inactive-flow-timeout"] = InactiveTimeout
	}
	if tf["interfaces"] != iface {
		set["interfaces"] = iface
	}
	if len(set) > 0 {
		plan.Steps = append(plan.Steps, ips.Step{Op: "set", Menu: "/ip/traffic-flow", Args: set,
			What: "Traffic Flow on, exporting every connection once a minute"})
		if others > 0 && set["active-flow-timeout"] != "" {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("Traffic Flow also sends to %d other target(s): "+
				"they will receive long connections every minute rather than every %s too.", others,
				firstNonEmpty(tf["active-flow-timeout"], "30m")))
		}
	}
	switch {
	case len(mine) == 0:
		plan.Steps = append(plan.Steps, ips.Step{Op: "add", Menu: "/ip/traffic-flow/target",
			Args: map[string]string{"dst-address": p.Collector.String(), "port": strconv.Itoa(p.Port), "version": TargetVersion},
			What: "send IPFIX to MikroDash at " + p.Collector.String() + ":" + strconv.Itoa(p.Port)})
	default:
		t := mine[0]
		fix := map[string]string{}
		if !strings.EqualFold(t["version"], TargetVersion) {
			fix["version"] = TargetVersion
		}
		if t["disabled"] == "true" {
			fix["disabled"] = "no"
		}
		if len(fix) > 0 {
			plan.Steps = append(plan.Steps, ips.Step{Op: "set", Menu: "/ip/traffic-flow/target", ID: t[".id"], Args: fix,
				What: "correct the target to MikroDash"})
		}
		for _, extra := range mine[1:] {
			plan.Steps = append(plan.Steps, ips.Step{Op: "remove", Menu: "/ip/traffic-flow/target", ID: extra[".id"],
				What: "remove a second target to MikroDash"})
		}
	}
	fields := map[string]string{}
	for _, f := range IPFIXFields {
		if v, ok := ipfix[f]; ok && !truthy(v) {
			fields[f] = "yes"
		}
	}
	if len(fields) > 0 {
		plan.Steps = append(plan.Steps, ips.Step{Op: "set", Menu: "/ip/traffic-flow/ipfix", Args: fields,
			What: "export the fields MikroDash reads"})
	}
	for _, r := range filter {
		if r["action"] == "fasttrack-connection" && r["disabled"] != "true" {
			plan.Warnings = append(plan.Warnings, "A fasttrack rule ("+r[".id"]+") is on: RouterOS documents that "+
				"FastTrack packets bypass Traffic Flow, so fasttracked connections will be counted only up to the "+
				"moment they are fasttracked.")
			break
		}
	}
	return plan
}

func truthy(v string) bool { return v == "true" || v == "yes" }

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// seconds reads a RouterOS duration ("1m", "30m", "15s", "1h30m", "00:01:00");
// -1 when it cannot.
func seconds(s string) int {
	if s == "" {
		return -1
	}
	if strings.Count(s, ":") == 2 {
		parts := strings.Split(s, ":")
		h, e1 := strconv.Atoi(parts[0])
		m, e2 := strconv.Atoi(parts[1])
		sec, e3 := strconv.Atoi(parts[2])
		if e1 != nil || e2 != nil || e3 != nil {
			return -1
		}
		return h*3600 + m*60 + sec
	}
	total, n := 0, 0
	digits := false
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			n, digits = n*10+int(c-'0'), true
		case digits && strings.ContainsRune("wdhms", c):
			total += n * map[rune]int{'w': 604800, 'd': 86400, 'h': 3600, 'm': 60, 's': 1}[c]
			n, digits = 0, false
		default:
			return -1
		}
	}
	if digits {
		total += n // a bare number is seconds
	}
	return total
}
