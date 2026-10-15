package collect

// DNS collector — the port of src/collectors/dns.js.
//
//	/ip/dns             resolver settings - servers, DoH, cache size and usage
//	/ip/dns/static      static entries
//	/ip/dns/forwarders  named upstream sets a FWD entry forwards to
//	/ip/dns/adlist      blocklists
//
// The last three are configuration and share the slow lane. Each is read with
// the fields its resource declares, so a row the page opens in the edit form
// and a row the fleet comparison copies carry the same properties. A router
// without forwarders or adlists answers "no such command" once and is not
// asked again on that connection.
//
// THE CACHE CONTENTS ARE NOT READ, and that is a decision worth carrying over
// rather than an omission to fix. /ip/dns/cache holds every name the router has
// resolved — hundreds of rows on an idle home router — so enumerating it is a
// standing cost for a table nobody asked to browse. The cache-used and
// cache-size FIGURES still reach the page; they come from the one settings row.
// It is also a privacy line: the settings row says how full the cache is, while
// the cache itself is a log of everywhere the network has been.

import (
	"encoding/json"
	"sort"
	"time"

	"mikrodash/internal/resource"
	"mikrodash/internal/routeros"
)

var (
	dnsSettingsCmd   = routeros.Cmd{Path: "/ip/dns/print"}
	dnsStaticCmd     = areaReadCmd(resource.DNSStatic)
	dnsForwardersCmd = areaReadCmd(resource.DNSForwarder)
	dnsAdlistCmd     = areaReadCmd(resource.DNSAdlist)
)

// DNSStaticCmd is the static-entry read, for the ONE caller outside this
// collector.
//
// `internal/server`'s fleet comparison reads the same menu on several routers at
// once — a question no session can answer, because a session is one router. It
// takes the command from here rather than writing its own, so the proplist has
// one home: a second declaration would drift, and the divergence would show up
// as a column that is blank on the comparison and filled on the page.
func DNSStaticCmd() routeros.Cmd { return dnsStaticCmd }

// Static entries are configuration: they change when somebody edits the router,
// not every tick. The settings row is read every tick because cache-used is live.
const dnsConfigEvery = 12

// DNSSettings is the settings row as the page renders it. Field order matches
// the object literal in parseDnsSettings so the emitted JSON reads the same.
type DNSSettings struct {
	Servers        []string `json:"servers"`
	DynamicServers []string `json:"dynamicServers"`
	// A router with no DoH must render the panel as "off", not as blank fields,
	// so the flag is explicit rather than inferred from an empty string at the
	// other end of a socket.
	DohEnabled              bool     `json:"dohEnabled"`
	DohURL                  string   `json:"dohUrl"`
	DohVerifyCert           bool     `json:"dohVerifyCert"`
	DohMaxServerConnections *float64 `json:"dohMaxServerConnections"`
	DohMaxConcurrentQueries *float64 `json:"dohMaxConcurrentQueries"`
	DohTimeout              string   `json:"dohTimeout"`
	AllowRemoteRequests     bool     `json:"allowRemoteRequests"`
	CacheSize               *float64 `json:"cacheSize"`
	CacheUsed               *float64 `json:"cacheUsed"`
	CacheMaxTTL             string   `json:"cacheMaxTtl"`
	MaxUDPPacketSize        *float64 `json:"maxUdpPacketSize"`
	MaxConcurrentQueries    *float64 `json:"maxConcurrentQueries"`
	QueryServerTimeout      string   `json:"queryServerTimeout"`
	QueryTotalTimeout       string   `json:"queryTotalTimeout"`
	MdnsRepeatIfaces        []string `json:"mdnsRepeatIfaces"`
	VRF                     string   `json:"vrf"`
	// How long an address a static entry put on an address list outlives the
	// answer's TTL.
	AddressListExtraTime string `json:"addressListExtraTime"`
}

// DNSStaticEntry is one row of the static table.
type DNSStaticEntry struct {
	// The row id, so the page can open an entry in the edit form. It addresses
	// a row, it does not authorise one — every write re-reads and re-checks
	// before touching it.
	ID       string `json:"id"`
	Name     string `json:"name"`
	Regexp   string `json:"regexp"`
	Address  string `json:"address"`
	Type     string `json:"type"`
	TTL      string `json:"ttl"`
	Disabled bool   `json:"disabled"`
	Comment  string `json:"comment"`
	// The firewall list the answers are added to. It changes what the router
	// does with a match as much as the address does, so the fleet comparison
	// holds two routers to it.
	AddressList    string `json:"addressList"`
	MatchSubdomain bool   `json:"matchSubdomain"`
	// Added by another service, a DHCP server's add-dns-entries, and read-only.
	Dynamic bool `json:"dynamic"`
}

// DNSForwarderEntry is one row of /ip/dns/forwarders.
type DNSForwarderEntry struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	DNSServers    []string `json:"dnsServers"`
	DoHServers    []string `json:"dohServers"`
	VerifyDohCert bool     `json:"verifyDohCert"`
	Comment       string   `json:"comment"`
	Disabled      bool     `json:"disabled"`
	// How many static entries forward to it, counted from the static table so
	// the page can say a forwarder is in use before anyone removes it.
	UsedBy int `json:"usedBy"`
}

// DNSAdlistEntry is one row of /ip/dns/adlist.
type DNSAdlistEntry struct {
	ID         string   `json:"id"`
	URL        string   `json:"url"`
	File       string   `json:"file"`
	SSLVerify  bool     `json:"sslVerify"`
	Comment    string   `json:"comment"`
	Disabled   bool     `json:"disabled"`
	NameCount  *float64 `json:"nameCount"`
	MatchCount *float64 `json:"matchCount"`
}

// DNSPayload is the dns:update body.
type DNSPayload struct {
	TS            int64            `json:"ts"`
	PollMs        int              `json:"pollMs"`
	Settings      DNSSettings      `json:"settings"`
	StaticEntries []DNSStaticEntry `json:"staticEntries"`
	Available     bool             `json:"available"`
	// False when this router has no such menu: forwarders and adlists are
	// newer than the rest of the resolver.
	Forwarders          []DNSForwarderEntry `json:"forwarders"`
	ForwardersAvailable bool                `json:"forwardersAvailable"`
	Adlists             []DNSAdlistEntry    `json:"adlists"`
	AdlistsAvailable    bool                `json:"adlistsAvailable"`
}

// ParseDNSSettings normalises the settings row into the shape the page renders.
func ParseDNSSettings(row routeros.Reply) DNSSettings {
	if row == nil {
		row = routeros.Reply{}
	}
	doh := row["use-doh-server"]
	return DNSSettings{
		Servers:                 splitList(row["servers"]),
		DynamicServers:          splitList(row["dynamic-servers"]),
		DohEnabled:              doh != "",
		DohURL:                  doh,
		DohVerifyCert:           boolOf(row["verify-doh-cert"]),
		DohMaxServerConnections: numOf(row, "doh-max-server-connections"),
		DohMaxConcurrentQueries: numOf(row, "doh-max-concurrent-queries"),
		DohTimeout:              row["doh-timeout"],
		AllowRemoteRequests:     boolOf(row["allow-remote-requests"]),
		CacheSize:               numOf(row, "cache-size"),
		CacheUsed:               numOf(row, "cache-used"),
		CacheMaxTTL:             row["cache-max-ttl"],
		MaxUDPPacketSize:        numOf(row, "max-udp-packet-size"),
		MaxConcurrentQueries:    numOf(row, "max-concurrent-queries"),
		QueryServerTimeout:      row["query-server-timeout"],
		QueryTotalTimeout:       row["query-total-timeout"],
		MdnsRepeatIfaces:        splitList(row["mdns-repeat-ifaces"]),
		VRF:                     row["vrf"],
		AddressListExtraTime:    row["address-list-extra-time"],
	}
}

// ParseStaticEntries builds the static table. A regexp entry has no name, so it
// is keyed on its pattern.
func ParseStaticEntries(rows []routeros.Reply) []DNSStaticEntry {
	out := []DNSStaticEntry{}
	for _, r := range rows {
		if r["name"] == "" && r["regexp"] == "" {
			continue // also drops the {undefined:''} row RouterOS can send
		}
		// One column, nine types: whichever property this record's type puts its
		// value in. The types are mutually exclusive on the router, so the order
		// only decides what a malformed row shows.
		address := ""
		for _, k := range []string{"address", "cname", "forward-to", "mx-exchange",
			"ns", "srv-target", "text"} {
			if address = r[k]; address != "" {
				break
			}
		}
		typ := r["type"]
		if typ == "" {
			if r["cname"] != "" {
				typ = "CNAME"
			} else {
				typ = "A"
			}
		}
		out = append(out, DNSStaticEntry{
			ID: r[".id"], Name: r["name"], Regexp: r["regexp"],
			Address: address, Type: typ, TTL: r["ttl"],
			Disabled: boolOf(r["disabled"]), Comment: r["comment"],
			AddressList: r["address-list"], MatchSubdomain: boolOf(r["match-subdomain"]),
			Dynamic: boolOf(r["dynamic"]),
		})
	}
	// Collate, not a byte sort: this order is rendered verbatim and the Node
	// side sorts with localeCompare. SliceStable because Array.prototype.sort
	// is stable, so two entries with the same key keep the router's order.
	sort.SliceStable(out, func(i, j int) bool {
		ki, kj := out[i].Name, out[j].Name
		if ki == "" {
			ki = out[i].Regexp
		}
		if kj == "" {
			kj = out[j].Regexp
		}
		return Collate(ki, kj) < 0
	})
	return out
}

// ParseForwarders builds the forwarder table, counting the static entries that
// name each one in forward-to.
func ParseForwarders(rows []routeros.Reply, static []DNSStaticEntry) []DNSForwarderEntry {
	used := map[string]int{}
	for _, e := range static {
		if e.Type == "FWD" && e.Address != "" {
			used[e.Address]++
		}
	}
	out := []DNSForwarderEntry{}
	for _, r := range rows {
		if r["name"] == "" {
			continue
		}
		out = append(out, DNSForwarderEntry{
			ID: r[".id"], Name: r["name"],
			DNSServers: splitList(r["dns-servers"]), DoHServers: splitList(r["doh-servers"]),
			// The manual's default is yes, and a router may leave a property at
			// its default out of the print.
			VerifyDohCert: r["verify-doh-cert"] == "" || boolOf(r["verify-doh-cert"]),
			Comment:       r["comment"], Disabled: boolOf(r["disabled"]), UsedBy: used[r["name"]],
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return Collate(out[i].Name, out[j].Name) < 0 })
	return out
}

// ParseAdlists builds the adlist table, in the router's order.
func ParseAdlists(rows []routeros.Reply) []DNSAdlistEntry {
	out := []DNSAdlistEntry{}
	for _, r := range rows {
		if r["url"] == "" && r["file"] == "" {
			continue
		}
		out = append(out, DNSAdlistEntry{
			ID: r[".id"], URL: r["url"], File: r["file"],
			SSLVerify: r["ssl-verify"] == "" || boolOf(r["ssl-verify"]),
			Comment:   r["comment"], Disabled: boolOf(r["disabled"]),
			NameCount: numOf(r, "name-count"), MatchCount: numOf(r, "match-count"),
		})
	}
	return out
}

// DNS is the collector.
type DNS struct {
	tableCore[DNSPayload]
	emit Emit

	// The table core subscribes to the SETTINGS menu, which is the live one; the
	// static entries, forwarders and adlists are its slow lane and are carried
	// between readings.
	static     []DNSStaticEntry
	forwarders []DNSForwarderEntry
	adlists    []DNSAdlistEntry
	// nil = unprobed, false = this router has no such menu, stop asking.
	settingsAvailable   *bool
	staticAvailable     *bool
	forwardersAvailable *bool
	adlistsAvailable    *bool
}

// dnsHeartbeat is how long an unchanged `dns:update` may be suppressed. See
// packagesHeartbeat: a resolver whose settings and static entries are steady
// sent nothing, and the DNS card went stale on a working router.
const dnsHeartbeat = 10 * time.Second

// NewDNS builds the collector. pollMs of 0 takes the registry default.
func NewDNS(ros Reader, emit Emit, pollMs int) *DNS {
	d := &DNS{emit: emit, static: []DNSStaticEntry{},
		forwarders: []DNSForwarderEntry{}, adlists: []DNSAdlistEntry{}}
	// The settings row carries cache-used, which is live, so it is read every
	// reading; the static entries only every dnsConfigEvery.
	d.setup(d, ros, pollMs, tableSpec{
		cmd: dnsSettingsCmd, poll: [3]int{10000, 1000, 60000}, slowEvery: dnsConfigEvery, heartbeat: dnsHeartbeat,
	})
	return d
}

// DNSInput is one tick's worth of the outside world, for BuildDNS.
//
// A struct rather than five arguments, matching `ConnsInput`: the fields are
// named at the call site, and one added later does not re-order anything.
type DNSInput struct {
	// Rows is the settings menu's reply. Only the first row is read -- the menu
	// is a singleton -- and an empty slice is an ordinary state rather than an
	// error: a router asked before it has answered has no rows.
	Rows []routeros.Reply
	// Static is the static-entry table, carried between ticks by the collector
	// because it is read on a slow lane and the payload needs it on every tick.
	Static []DNSStaticEntry
	// Available is the menu-presence latch. NIL MEANS "NOT YET KNOWN", which
	// reads as available -- a router is presumed to have DNS until it says
	// otherwise, and the alternative would blank the page on the first tick.
	Available *bool
	// Forwarders and Adlists are carried like Static, each with its own latch.
	Forwarders          []DNSForwarderEntry
	ForwardersAvailable *bool
	Adlists             []DNSAdlistEntry
	AdlistsAvailable    *bool
	PollMs              int
	Now                 int64
}

// BuildDNS is the DNS payload, pure: input in, payload out, no receiver and no
// I/O.
//
// ── PHASE 4.1: WHY THIS IS A FUNCTION AND NOT A METHOD ──────────────────────
//
// The derivation layer's rule is that turning rows into a payload must be
// testable without a collector, a session or a router. `BuildBandwidth(prev, in)`
// and `BuildSimpleRows(rows, prev, now)` already have this shape; this follows
// them rather than inventing a second one.
//
// The SETTINGS are parsed here rather than by the caller, so the payload and the
// collector's own copy cannot come from two different parses of the same row --
// the caller takes `payload.Settings` back.
func BuildDNS(in DNSInput) *DNSPayload {
	var first routeros.Reply
	if len(in.Rows) > 0 {
		first = in.Rows[0]
	}
	forwarders, adlists := in.Forwarders, in.Adlists
	if forwarders == nil {
		forwarders = []DNSForwarderEntry{}
	}
	if adlists == nil {
		adlists = []DNSAdlistEntry{}
	}
	return &DNSPayload{
		TS: in.Now, PollMs: in.PollMs,
		Settings: ParseDNSSettings(first), StaticEntries: in.Static,
		Available:  MenuAvailable(in.Available),
		Forwarders: forwarders, ForwardersAvailable: MenuAvailable(in.ForwardersAvailable),
		Adlists: adlists, AdlistsAvailable: MenuAvailable(in.AdlistsAvailable),
	}
}

// derive is the settings row with the static entries. A settings menu this
// router does not have, or refuses, is sent once as unavailable and not asked
// again on this connection; a transient failure keeps the last payload.
func (d *DNS) derive(rows []routeros.Reply, err error, slow bool) (*DNSPayload, string) {
	if err != nil && !menuGone(err) {
		return nil, ""
	}
	latchMenu(&d.settingsAvailable, err)
	if err != nil {
		d.retire()
		rows = nil
	}
	if slow {
		static, _ := readOptional(d.ros.Do, dnsStaticCmd, &d.staticAvailable)
		d.static = ParseStaticEntries(static)
		forwarders, _ := readOptional(d.ros.Do, dnsForwardersCmd, &d.forwardersAvailable)
		d.forwarders = ParseForwarders(forwarders, d.static)
		adlists, _ := readOptional(d.ros.Do, dnsAdlistCmd, &d.adlistsAvailable)
		d.adlists = ParseAdlists(adlists)
	}
	payload := BuildDNS(DNSInput{
		Rows: rows, Static: d.static, Available: d.settingsAvailable,
		Forwarders: d.forwarders, ForwardersAvailable: d.forwardersAvailable,
		Adlists: d.adlists, AdlistsAvailable: d.adlistsAvailable,
		PollMs: d.PollMs(), Now: time.Now().UnixMilli(),
	})

	// The WHOLE entry, not a hand-picked tuple, matching the Node side.
	//
	// It used to be [name, regexp, address, type, disabled] on both sides, and
	// that omitted `comment` and `ttl` — both of which the page renders. A
	// comment-only edit wrote the router, RefreshNow re-read it, and the
	// fingerprint came back identical, so the open page kept the old value until
	// something unrelated moved. On a busy router `cache-used` moves within a
	// tick or two and it merely looked slow; on an idle one the update never
	// arrived at all. Fingerprinting the entry as a whole means a field the page
	// gains cannot fall out of this list again.
	//
	// `ts` is still excluded, and must be: it moves every tick and would make
	// every tick an emit, which is the thing the fingerprint exists to prevent.
	fp, _ := json.Marshal(struct {
		S DNSSettings         `json:"s"`
		T []DNSStaticEntry    `json:"t"`
		F []DNSForwarderEntry `json:"f"`
		A []DNSAdlistEntry    `json:"a"`
		B [2]bool             `json:"b"`
	}{payload.Settings, payload.StaticEntries, payload.Forwarders, payload.Adlists,
		[2]bool{payload.ForwardersAvailable, payload.AdlistsAvailable}})
	return payload, string(fp)
}

func (d *DNS) send(p DNSPayload) { EvDnsUpdate.Emit(d.emit, dnsRooms.Join(), p) }

// reset drops every latch. A router that has just come back may be a different
// build — an upgrade is the usual reason a connection dropped — so an "this menu
// is absent" decision taken against the old one must not persist.
func (d *DNS) reset() {
	d.settingsAvailable, d.staticAvailable = nil, nil
	d.forwardersAvailable, d.adlistsAvailable = nil, nil
}
