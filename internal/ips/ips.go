// Package ips is the IPS page's decision: a classified flow and the rules in,
// what to do about it out. Pure, like internal/alert: no router, no database,
// no clock, so every rule is one table test.
//
// ── WHERE THE FLOWS COME FROM ───────────────────────────────────────────────
//
// dpi-sensor/ runs nDPI in a container on the router, which copies it the
// first bytes of every forwarded connection (a mangle `sniff-tzsp` rule). The
// sensor reports each flow once, when nDPI has named it or given up, as one
// JSON line; ParseLine reads that line. internal/server/ips.go dials the sensor
// and hands each flow to Decide.
//
// ── DETECT, THEN BLOCK ──────────────────────────────────────────────────────
//
// This is not an inline IPS and cannot be one: RouterOS forwards the packet
// whatever the sensor thinks of it. A verdict lands as an address-list entry
// with a timeout, which raw rules on the router drop, so the first packets of
// the flow that was judged have already passed. What is blocked is what comes
// after: the rest of that connection, and every later one to the same server.
//
// ── BLOCKING BY ADDRESS IS COARSE, AND SAID SO ──────────────────────────────
//
// `block` lists the party ON THE INTERNET, for everybody: the server of a
// connection that went out, the client of one that came in through a dst-nat.
// A rule naming clients chooses which flows trigger it, not who is cut off
// afterwards, and a service on a shared CDN takes its neighbours with it. That
// is why the default is to watch (a rule whose action is `log`), and why
// `quarantine` exists: it lists the party AT HOME, which is the precise answer
// to "this device is doing something it should not".
package ips

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// The address lists the router's raw rules drop. MikroDash owns every entry in
// them: it adds them, they time out, and nothing else should write there.
const (
	BlockList      = "mikrodash-ips-block"
	QuarantineList = "mikrodash-ips-quarantine"
)

// Actions a rule may take.
const (
	ActionAllow      = "allow"      // stop here: later rules do not see the flow
	ActionLog        = "log"        // record it, change nothing
	ActionBlock      = "block"      // list the server
	ActionQuarantine = "quarantine" // list the client
)

// Actions is every action, in the order the page offers them.
var Actions = []string{ActionLog, ActionBlock, ActionQuarantine, ActionAllow}

// Timeout bounds, in minutes: a listed address always comes off by itself.
const (
	MinTimeout     = 1
	MaxTimeout     = 7 * 24 * 60
	DefaultTimeout = 60
)

// Flow is one classified flow, as the sensor reports it.
type Flow struct {
	TS         int64    `json:"ts"`
	L4         string   `json:"l4"`
	Client     string   `json:"client"`
	ClientPort int      `json:"clientPort"`
	Server     string   `json:"server"`
	ServerPort int      `json:"serverPort"`
	Name       string   `json:"name"` // "TLS.YouTube": the master and the application
	App        string   `json:"app"`
	Master     string   `json:"master"`
	Category   string   `json:"category"`
	Breed      string   `json:"breed"`
	Host       string   `json:"host"` // the SNI, HTTP Host or DNS name, when there is one
	Risks      []string `json:"risks"`
	Guessed    bool     `json:"guessed"`
	Packets    int      `json:"packets"`
	Bytes      int64    `json:"bytes"`
	// ClientCountry and ServerCountry are ISO codes MikroDash adds from its
	// geo database; the sensor does not send them. Empty for a private or
	// unknown address.
	ClientCountry string `json:"clientCountry"`
	ServerCountry string `json:"serverCountry"`
}

// notPublic are the ranges no country holds, beyond what netip names.
var notPublic = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("240.0.0.0/4")}

// Public is whether an address is on the internet: not private, loopback,
// link-local, multicast, carrier-grade NAT or reserved.
func Public(addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	for _, p := range notPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// Remote is the flow's party on the internet: the server of a connection
// that went out, the client of one that came in (through a dst-nat). Empty
// for a flow between two private addresses.
func (f Flow) Remote() (addr, country string, inbound bool) {
	switch {
	case Public(f.Server):
		return f.Server, f.ServerCountry, false
	case Public(f.Client):
		return f.Client, f.ClientCountry, true
	}
	return "", "", false
}

// Stats is the sensor's own counters, every few seconds.
type Stats struct {
	Packets       int64 `json:"packets"`
	Bytes         int64 `json:"bytes"`
	Flows         int64 `json:"flows"`
	Active        int64 `json:"active"`
	Reported      int64 `json:"reported"`
	DroppedEvents int64 `json:"droppedEvents"`
	BadFrames     int64 `json:"badFrames"`
	Evicted       int64 `json:"evicted"`
}

// Line is one line from the sensor: exactly one of its fields is set.
type Line struct {
	Hello *Hello
	Flow  *Flow
	Stats *Stats
	// Bytes is what each connection moved since the last such line: the
	// sensor sends it, from version 2, to a reader that asked (LiveBytesRequest).
	Bytes []ConnBytes
	Error string
}

// ConnBytes is what one connection moved: tx is what its client sent, rx
// what it received.
type ConnBytes struct {
	L4         string
	Client     netip.Addr
	ClientPort uint16
	Server     netip.Addr
	ServerPort uint16
	Tx, Rx     uint64
}

// LiveBytesVersion is the first sensor version that sends live volumes.
const LiveBytesVersion = 2

// LiveBytesEvery is how often a reader asks for them.
const LiveBytesEvery = 5

// LiveBytesRequest is the line a reader sends to ask for them.
func LiveBytesRequest(seconds int) string { return fmt.Sprintf("BYTES %d\n", seconds) }

// Hello is the sensor's greeting once the token was accepted.
type Hello struct {
	Version string `json:"version"`
	NDPI    string `json:"ndpi"`
}

// connBytesOf reads one [l4, client, clientPort, server, serverPort, tx, rx].
func connBytesOf(r []json.RawMessage) (ConnBytes, error) {
	var c ConnBytes
	if len(r) != 7 {
		return c, fmt.Errorf("a bytes entry has %d fields, not 7", len(r))
	}
	var client, server string
	var cp, sp uint16
	for i, dst := range []any{&c.L4, &client, &cp, &server, &sp, &c.Tx, &c.Rx} {
		if err := json.Unmarshal(r[i], dst); err != nil {
			return c, fmt.Errorf("bytes entry field %d: %w", i, err)
		}
	}
	var err error
	if c.Client, err = netip.ParseAddr(client); err != nil {
		return c, fmt.Errorf("bytes client %q: %w", client, err)
	}
	if c.Server, err = netip.ParseAddr(server); err != nil {
		return c, fmt.Errorf("bytes server %q: %w", server, err)
	}
	c.ClientPort, c.ServerPort = cp, sp
	return c, nil
}

// ParseLine reads one line from the sensor. A flow whose addresses do not
// parse is an error, not a flow: nothing downstream may act on it.
func ParseLine(b []byte) (Line, error) {
	var head struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return Line{}, err
	}
	switch head.Type {
	case "hello":
		var h Hello
		if err := json.Unmarshal(b, &h); err != nil {
			return Line{}, err
		}
		return Line{Hello: &h}, nil
	case "stats":
		var s Stats
		if err := json.Unmarshal(b, &s); err != nil {
			return Line{}, err
		}
		return Line{Stats: &s}, nil
	case "error":
		return Line{Error: head.Message}, nil
	case "bytes":
		var raw struct {
			F [][]json.RawMessage `json:"f"`
		}
		if err := json.Unmarshal(b, &raw); err != nil {
			return Line{}, err
		}
		out := make([]ConnBytes, 0, len(raw.F))
		for _, r := range raw.F {
			c, err := connBytesOf(r)
			if err != nil {
				return Line{}, err
			}
			out = append(out, c)
		}
		return Line{Bytes: out}, nil
	case "flow":
		var f Flow
		if err := json.Unmarshal(b, &f); err != nil {
			return Line{}, err
		}
		if _, err := netip.ParseAddr(f.Client); err != nil {
			return Line{}, fmt.Errorf("flow client %q: %w", f.Client, err)
		}
		if _, err := netip.ParseAddr(f.Server); err != nil {
			return Line{}, fmt.Errorf("flow server %q: %w", f.Server, err)
		}
		if f.Risks == nil {
			f.Risks = []string{}
		}
		return Line{Flow: &f}, nil
	}
	return Line{}, fmt.Errorf("unknown line type %q", head.Type)
}

// Rule is one row of the ordered rule table. The first enabled rule that
// matches a flow decides it.
//
// A criterion that is empty matches everything; a criterion with values matches
// when any one of them does; a rule matches when every criterion does. So
// `Apps: [BitTorrent], Clients: [192.168.88.0/24]` is BitTorrent from that LAN.
type Rule struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Apps are nDPI protocol names: "YouTube" matches TLS.YouTube and
	// QUIC.YouTube, "TLS" matches every TLS flow.
	Apps       []string `json:"apps"`
	Categories []string `json:"categories"`
	// Breeds are nDPI's verdicts on a protocol: Safe, Acceptable, Fun, Unsafe,
	// Potentially Dangerous, Dangerous, Tracker/Ads, Unrated.
	Breeds []string `json:"breeds"`
	// Risks are nDPI risk names; "*" is any risk at all.
	Risks []string `json:"risks"`
	// Hosts match the flow's host name or any parent of it: "tiktok.com"
	// matches "www.tiktok.com".
	Hosts []string `json:"hosts"`
	// Clients are the addresses or prefixes the rule applies to.
	Clients []string `json:"clients"`
	// Countries are ISO codes matched against the flow's remote party (see
	// Flow.Remote): where a connection went, or where one came from.
	Countries  []string `json:"countries"`
	Action     string   `json:"action"`
	TimeoutMin int      `json:"timeoutMin"`
}

var isoCode = regexp.MustCompile(`^[A-Z]{2}$`)

var ruleName = regexp.MustCompile(`^[\pL\pN][\pL\pN ._/()&+-]{0,59}$`)

// Validate says what is wrong with a rule, or nil. It also normalises it:
// values trimmed, empty ones dropped, a block with no timeout given the
// default.
func (r *Rule) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	if !ruleName.MatchString(r.Name) {
		return errors.New("a name of letters, digits and simple punctuation, up to 60")
	}
	if !slices.Contains(Actions, r.Action) {
		return fmt.Errorf("the action must be one of %s", strings.Join(Actions, ", "))
	}
	for _, list := range []*[]string{&r.Apps, &r.Categories, &r.Breeds, &r.Risks, &r.Hosts, &r.Clients, &r.Countries} {
		*list = clean(*list)
		if len(*list) > 200 {
			return errors.New("a criterion takes up to 200 values")
		}
		for _, v := range *list {
			if len(v) > 100 {
				return errors.New("a value is longer than 100 characters")
			}
		}
	}
	for i, c := range r.Countries {
		c = strings.ToUpper(c)
		if !isoCode.MatchString(c) {
			return fmt.Errorf("%q is not a two-letter country code", r.Countries[i])
		}
		r.Countries[i] = c
	}
	if len(r.Apps)+len(r.Categories)+len(r.Breeds)+len(r.Risks)+len(r.Hosts)+len(r.Countries) == 0 {
		// Clients alone would match every flow those clients make, and a
		// rule that blocks every server a LAN talks to is a mistake.
		return errors.New("a rule needs an application, a category, a breed, a risk, a host or a country")
	}
	for i, h := range r.Hosts {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(h, "*"), "."), "."))
		if h == "" || strings.ContainsAny(h, " /:") {
			return fmt.Errorf("%q is not a host name", r.Hosts[i])
		}
		r.Hosts[i] = h
	}
	for _, c := range r.Clients {
		if _, err := parsePrefix(c); err != nil {
			return fmt.Errorf("%q is not an address or a prefix", c)
		}
	}
	switch r.Action {
	case ActionBlock, ActionQuarantine:
		if r.TimeoutMin == 0 {
			r.TimeoutMin = DefaultTimeout
		}
		if r.TimeoutMin < MinTimeout || r.TimeoutMin > MaxTimeout {
			return fmt.Errorf("a timeout of %d to %d minutes", MinTimeout, MaxTimeout)
		}
	default:
		r.TimeoutMin = 0
	}
	return nil
}

func clean(in []string) []string {
	out := []string{}
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// parsePrefix takes an address or a prefix.
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// Matches is whether the rule applies to the flow, ignoring Enabled.
func (r Rule) Matches(f Flow) bool {
	return anyOf(r.Apps, func(v string) bool { return appIs(f, v) }) &&
		anyOf(r.Categories, func(v string) bool { return strings.EqualFold(v, f.Category) }) &&
		anyOf(r.Breeds, func(v string) bool { return strings.EqualFold(v, f.Breed) }) &&
		anyOf(r.Risks, func(v string) bool { return hasRisk(f, v) }) &&
		anyOf(r.Hosts, func(v string) bool { return hostUnder(f.Host, v) }) &&
		anyOf(r.Clients, func(v string) bool { return clientIn(f.Client, v) }) &&
		anyOf(r.Countries, func(v string) bool { _, c, _ := f.Remote(); return c != "" && c == v })
}

func anyOf(values []string, match func(string) bool) bool {
	if len(values) == 0 {
		return true
	}
	return slices.ContainsFunc(values, match)
}

// appIs matches the application, its master, or any part of the dotted name.
func appIs(f Flow, v string) bool {
	if strings.EqualFold(v, f.App) || strings.EqualFold(v, f.Master) || strings.EqualFold(v, f.Name) {
		return true
	}
	for _, part := range strings.Split(f.Name, ".") {
		if strings.EqualFold(v, part) {
			return true
		}
	}
	return false
}

func hasRisk(f Flow, v string) bool {
	if v == "*" {
		return len(f.Risks) > 0
	}
	return slices.ContainsFunc(f.Risks, func(r string) bool { return strings.EqualFold(r, v) })
}

func hostUnder(host, suffix string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host != "" && (host == suffix || strings.HasSuffix(host, "."+suffix))
}

func clientIn(client, v string) bool {
	a, err := netip.ParseAddr(client)
	if err != nil {
		return false
	}
	p, err := parsePrefix(v)
	return err == nil && p.Contains(a.Unmap())
}

// Decision is what to do about one flow. RuleID 0 is no rule matched, and the
// action is then empty: nothing is recorded.
type Decision struct {
	RuleID   int64  `json:"ruleId"`
	RuleName string `json:"ruleName"`
	Action   string `json:"action"`
	// Target is the address to list, and List the list, for block and
	// quarantine; empty otherwise.
	Target     string `json:"target"`
	List       string `json:"list"`
	TimeoutMin int    `json:"timeoutMin"`
}

// Decide runs the rules over a flow in order.
func Decide(rules []Rule, f Flow) Decision {
	for _, r := range rules {
		if !r.Enabled || !r.Matches(f) {
			continue
		}
		d := Decision{RuleID: r.ID, RuleName: r.Name, Action: r.Action, TimeoutMin: r.TimeoutMin}
		// Block the party on the internet, quarantine the one at home: for a
		// connection that came in through a dst-nat they are the client and
		// the server, the other way round.
		remote, _, inbound := f.Remote()
		switch r.Action {
		case ActionBlock:
			d.Target, d.List = f.Server, BlockList
			if remote != "" {
				d.Target = remote
			}
		case ActionQuarantine:
			d.Target, d.List = f.Client, QuarantineList
			if inbound {
				d.Target = f.Server
			}
		}
		return d
	}
	return Decision{}
}
