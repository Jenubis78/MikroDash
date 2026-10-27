package ips

// What the router must hold for the IPS to work, and the commands that put it
// there. Pure: the router's rows in, a plan out; internal/server/ips_api.go reads
// the rows and runs the plan.
//
// ── FOUR RULES, ALL MARKED ──────────────────────────────────────────────────
//
// One mangle rule copies the first SniffBytes of every forwarded connection to
// the sensor; three raw rules drop what the two address lists name. Every one
// carries a comment starting `MikroDash IPS`, and the plan adds, changes and
// removes only rows with that comment: an operator's own rules are never
// touched. The raw rules go above every other raw rule, because a raw `accept`
// above them would let a blocked address through.
//
// ── FASTTRACK HIDES TRAFFIC FROM THE SENSOR ─────────────────────────────────
//
// A fasttracked connection skips the mangle table after its first packets, and
// the default configuration fasttracks every established connection: the
// sensor then sees the handshake and not the TLS ClientHello that names the
// service. The plan does not edit the operator's fasttrack rule. It warns, and
// gives the one-word change (`connection-bytes`) that lets the first bytes
// through the slow path before fasttrack takes the connection.

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"mikrodash/internal/routeros"
)

// Marker starts the comment of every row the IPS owns on a router.
const Marker = "MikroDash IPS"

// Sensor defaults.
const (
	TZSPPort          = 37008
	ReaderPort        = 37009
	DefaultSniffBytes = 20000
	MinSniffBytes     = 2000
	MaxSniffBytes     = 1000000
	DefaultImage      = "ghcr.io/jenubis78/mikrodash-dpi:latest"
)

// Owned is whether a row's comment says the IPS made it.
func Owned(r routeros.Reply) bool { return strings.HasPrefix(r["comment"], Marker) }

// RouterRow is one rule the router must hold: its menu, and the properties that
// define it (the comment among them).
type RouterRow struct {
	Menu  string            `json:"menu"`
	Props map[string]string `json:"props"`
}

// Comment is the row's identity within its menu.
func (r RouterRow) Comment() string { return r.Props["comment"] }

// Want is the rows the router must hold for a sensor at this address.
func Want(sensor netip.Addr, sniffBytes int) []RouterRow {
	s := sensor.String()
	return []RouterRow{
		{Menu: "/ip/firewall/mangle", Props: map[string]string{
			"chain": "forward", "action": "sniff-tzsp", "sniff-target": s,
			"sniff-target-port": strconv.Itoa(TZSPPort), "connection-bytes": "0-" + strconv.Itoa(sniffBytes),
			"src-address": "!" + s, "dst-address": "!" + s, "comment": Marker + ": copy to the sensor"}},
		{Menu: "/ip/firewall/raw", Props: map[string]string{
			"chain": "prerouting", "action": "drop", "src-address-list": QuarantineList,
			"comment": Marker + ": quarantined clients"}},
		{Menu: "/ip/firewall/raw", Props: map[string]string{
			"chain": "prerouting", "action": "drop", "dst-address-list": BlockList,
			"comment": Marker + ": blocked servers"}},
		{Menu: "/ip/firewall/raw", Props: map[string]string{
			"chain": "prerouting", "action": "drop", "src-address-list": BlockList,
			"comment": Marker + ": blocked servers, replies"}},
	}
}

// Step is one write of a plan, as the page shows it and the server runs it.
type Step struct {
	Op   string            `json:"op"` // add, set, remove
	Menu string            `json:"menu"`
	ID   string            `json:"id,omitempty"`
	Args map[string]string `json:"args,omitempty"`
	What string            `json:"what"`
}

// Cmd is the step as a RouterOS API sentence.
func (s Step) Cmd() routeros.Cmd {
	var args []string
	switch s.Op {
	case "set", "remove":
		args = append(args, "=.id="+s.ID)
	}
	keys := make([]string, 0, len(s.Args))
	for k := range s.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "="+k+"="+s.Args[k])
	}
	return routeros.Cmd{Path: s.Menu + "/" + s.Op, Args: args}
}

// Plan is what a router must do to hold the IPS's rules.
type Plan struct {
	Steps []Step `json:"steps"`
	// Warnings are what the plan does not fix: today, a fasttrack rule.
	Warnings []string `json:"warnings"`
}

// PlanRouter compares what the router holds with what it must. `rows` is the
// current rows of each menu Want names; `filter` is /ip/firewall/filter, read
// only for the fasttrack warning. With no sensor (the zero Addr) it plans the
// removal of everything the IPS owns.
func PlanRouter(sensor netip.Addr, sniffBytes int, rows map[string][]routeros.Reply, filter []routeros.Reply) Plan {
	p := Plan{Steps: []Step{}, Warnings: []string{}}
	var want []RouterRow
	if sensor.IsValid() {
		want = Want(sensor, sniffBytes)
	}
	menus := []string{"/ip/firewall/mangle", "/ip/firewall/raw"}
	for _, menu := range menus {
		mine := map[string]routeros.Reply{}
		var extra []routeros.Reply
		firstForeign := ""
		for _, r := range rows[menu] {
			if !Owned(r) {
				if firstForeign == "" {
					firstForeign = r[".id"]
				}
				continue
			}
			if _, twice := mine[r["comment"]]; twice {
				extra = append(extra, r)
				continue
			}
			mine[r["comment"]] = r
		}
		wanted := map[string]bool{}
		for _, w := range want {
			if w.Menu != menu {
				continue
			}
			wanted[w.Comment()] = true
			have, ok := mine[w.Comment()]
			if !ok {
				args := map[string]string{}
				for k, v := range w.Props {
					args[k] = v
				}
				// Above every rule the operator has: a raw accept above a
				// drop would let a blocked address through, and a mangle rule
				// that stops processing above the copy would hide the flow.
				if firstForeign != "" {
					args["place-before"] = firstForeign
				}
				p.Steps = append(p.Steps, Step{Op: "add", Menu: menu, Args: args, What: "add " + w.Comment()})
				continue
			}
			if diff := differs(w.Props, have); len(diff) > 0 {
				p.Steps = append(p.Steps, Step{Op: "set", Menu: menu, ID: have[".id"], Args: diff,
					What: "correct " + w.Comment()})
			}
		}
		for comment, r := range mine {
			if !wanted[comment] {
				extra = append(extra, r)
			}
		}
		sort.Slice(extra, func(i, j int) bool { return extra[i][".id"] < extra[j][".id"] })
		for _, r := range extra {
			p.Steps = append(p.Steps, Step{Op: "remove", Menu: menu, ID: r[".id"], What: "remove " + r["comment"]})
		}
	}
	if sensor.IsValid() {
		for _, r := range filter {
			if r["action"] == "fasttrack-connection" && r["disabled"] != "true" && r["connection-bytes"] == "" {
				p.Warnings = append(p.Warnings, fmt.Sprintf(
					"A fasttrack rule (%s) takes connections off the slow path before the sensor has seen what names "+
						"the service. Let the first bytes through first: "+
						"/ip/firewall/filter/set [find where action=fasttrack-connection] connection-bytes=%d-0",
					r[".id"], sniffBytes))
				break
			}
		}
	}
	return p
}

// differs is the properties the router's row has wrong. A property the router
// leaves out is its default, which for every property Want sets is empty.
func differs(want map[string]string, have routeros.Reply) map[string]string {
	out := map[string]string{}
	for k, v := range want {
		if have[k] != v {
			out[k] = v
		}
	}
	if have["disabled"] == "true" {
		out["disabled"] = "no"
	}
	return out
}

// ListEntryArgs is the address-list entry one decision writes.
func ListEntryArgs(d Decision, app string) []string {
	comment := fmt.Sprintf("%s #%d %s", Marker, d.RuleID, strings.TrimSpace(app))
	if len(comment) > 120 {
		comment = comment[:120]
	}
	return []string{"=list=" + d.List, "=address=" + d.Target,
		"=timeout=" + strconv.Itoa(d.TimeoutMin) + "m", "=comment=" + comment}
}

// ScriptParams is what the container script is written for.
type ScriptParams struct {
	Token string
	// Sensor is the container's address; the router takes the one below it.
	Sensor netip.Addr
	// Disk is where the image is unpacked, e.g. "usb1".
	Disk  string
	Image string
}

// ContainerScript is the RouterOS commands that create the sensor's container.
// The operator runs them: installing a container needs container mode, which
// only somebody standing at the router can switch on, and a disk only they know.
func ContainerScript(p ScriptParams) string {
	gw := p.Sensor.Prev()
	disk := strings.Trim(p.Disk, "/ ")
	if disk == "" {
		disk = "usb1"
	}
	image := p.Image
	if image == "" {
		image = DefaultImage
	}
	registry := "https://" + strings.SplitN(image, "/", 2)[0]
	c := `comment="` + Marker + ` sensor"`
	var b strings.Builder
	fmt.Fprintf(&b, "# MikroDash IPS sensor. Once, with physical access, if containers are not enabled yet:\n")
	fmt.Fprintf(&b, "#   /system/device-mode/update container=yes   (then press the reset button or power-cycle)\n")
	fmt.Fprintf(&b, "/interface/veth/add name=veth-mikrodash-dpi address=%s/30 gateway=%s %s\n", p.Sensor, gw, c)
	fmt.Fprintf(&b, "/interface/bridge/add name=br-mikrodash-dpi %s\n", c)
	fmt.Fprintf(&b, "/interface/bridge/port/add bridge=br-mikrodash-dpi interface=veth-mikrodash-dpi %s\n", c)
	fmt.Fprintf(&b, "/ip/address/add address=%s/30 interface=br-mikrodash-dpi %s\n", gw, c)
	fmt.Fprintf(&b, "/container/config/set registry-url=%s tmpdir=%s/tmp\n", registry, disk)
	fmt.Fprintf(&b, "/container/add remote-image=%s interface=veth-mikrodash-dpi root-dir=%s/mikrodash-dpi \\\n", image, disk)
	fmt.Fprintf(&b, "  cmd=\"--token %s\" logging=yes start-on-boot=yes %s\n", p.Token, c)
	fmt.Fprintf(&b, "# Wait for status=stopped (the image is pulled), then:\n")
	fmt.Fprintf(&b, "/container/start [find where comment=\"%s sensor\"]\n", Marker)
	return b.String()
}
