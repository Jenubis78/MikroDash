package server

// Two on-demand DNS reads for one router (Settings -> Features):
//
//	GET /api/dns/cache?routerId=&q=     the resolver's cache, searched
//	GET /api/dns/trace?routerId=&name=  why a domain does or does not take its route
//
// ── ASKED FOR, NEVER POLLED ─────────────────────────────────────────────────
//
// The DNS collector deliberately does not read /ip/dns/cache: it is thousands
// of rows and a record of everywhere the network has been (collect/dns.go).
// These read it only when somebody presses Read or asks about a name, and the
// trace asks the router for that one name, `?name=`, not for the cache.
//
// ── THE CACHE IS FOR ADMINISTRATORS ─────────────────────────────────────────
//
// The cache is a list of every name the network has looked up, whoever asked.
// DNS read access opens the static entries, not that, so the browser answers an
// administrator only. The trace asks the cache for the one name it was given.
//
// ── THE TRACE SHOWS ONLY WHAT ITS VIEWER MAY READ ───────────────────────────
//
// Past the static entry, the chain runs through three other pages' menus:
// address lists, mangle rules and routes. DNS read access is what opens the
// trace; each of those links is read only for a viewer the matching page is
// granted to on that router, and otherwise says it was withheld.
//
// ── WHAT IT CLAIMS ABOUT THE ROUTER'S CHOICE ────────────────────────────────
//
// The RouterOS DNS manual says that when several static entries match a name,
// the order of the list does not decide which one answers, and does not say what
// does. So the trace never picks: with one enabled FWD, A or AAAA entry that
// catches the name it follows that entry, and with more it lists them all and
// follows the chain only if they feed the same address list, which makes the
// rest of it hold whichever answers. Other types (MX, TXT, NS, SRV, CNAME) are
// shown as matching and are not followed: they answer other questions than a
// client opening a site asks.
//
// The chain is IPv4. Only /ip/firewall/mangle and /ip/route are read, so an
// AAAA answer is reported and not followed.

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"mikrodash/internal/collect"
	"mikrodash/internal/routeros"
	"mikrodash/internal/safe"
	"mikrodash/internal/session"
	"mikrodash/internal/store"
	"mikrodash/internal/topology"
)

const (
	dnsToolsHold = "dns-tools"
	// dnsCacheCap bounds one answer; the count says how many matched.
	dnsCacheCap = 2000
)

var (
	dnsCacheCmd   = routeros.Cmd{Path: "/ip/dns/cache/print", Args: []string{"=.proplist=name,type,data,ttl"}}
	addrListProps = "=.proplist=.id,list,address,timeout,dynamic,disabled,comment"
	mangleProps   = "=.proplist=.id,chain,action,dst-address-list,new-routing-mark,passthrough,packets,bytes,disabled,comment"
	routeProps    = "=.proplist=.id,dst-address,gateway,distance,active,disabled,routing-table"
)

func (s *Server) registerDNSTools(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/dns/cache", s.dnsCacheGet)
	mux.HandleFunc("GET /api/dns/trace", s.dnsTraceGet)
}

// dnsToolSession is the gate both reads share: the feature, a valid router, DNS
// read access to it, an administrator when the read asks for one, and a held
// session. The caller drops the hold. Everything that can refuse does so before
// the router is dialled.
func (s *Server) dnsToolSession(w http.ResponseWriter, r *http.Request, feature string,
	adminOnly bool) (*Session, *session.Session, func(), bool) {

	sess := s.layoutSession(w, r)
	if sess == nil || !s.featureGate(w, feature) {
		return nil, nil, nil, false
	}
	rid := r.URL.Query().Get("routerId")
	if !topology.IsValidRouterID(rid) {
		writeJSON400OK(w)
		return nil, nil, nil, false
	}
	if !permitted(s.rbac.CanPage(s.userIDFor(sess.Username), "dns", "read", rid)) {
		writeJSONErr(w, http.StatusForbidden, "Not permitted")
		return nil, nil, nil, false
	}
	if adminOnly && !s.isGlobalAdmin(sess) {
		writeJSONErr(w, http.StatusForbidden, "The DNS cache is for administrators")
		return nil, nil, nil, false
	}
	sn, drop, ok := s.fleetSession(r.Context(), rid, dnsToolsHold)
	if !ok {
		writeJSONErr(w, http.StatusServiceUnavailable, "the router is not connected")
		return nil, nil, nil, false
	}
	return sess, sn, drop, true
}

// DNSCacheRow is one cached answer.
type DNSCacheRow struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
	TTL  string `json:"ttl"`
}

func (s *Server) dnsCacheGet(w http.ResponseWriter, r *http.Request) {
	_, sn, drop, ok := s.dnsToolSession(w, r, store.FeatureDNSCache, true)
	if !ok {
		return
	}
	defer drop()
	rows, err := sn.Exec(dnsCacheCmd)
	if err != nil {
		writeJSONErr(w, http.StatusBadGateway, safe.Message(err.Error()))
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	out := []DNSCacheRow{}
	total := 0
	for _, row := range rows {
		c := DNSCacheRow{Name: row["name"], Type: row["type"], Data: row["data"], TTL: row["ttl"]}
		if q != "" && !strings.Contains(strings.ToLower(c.Name+" "+c.Data), q) {
			continue
		}
		total++
		if len(out) < dnsCacheCap {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, map[string]any{"total": total, "cached": len(rows), "rows": out})
}

// ── the trace ───────────────────────────────────────────────────────────────

// DNSTraceMatch is a static entry that catches the traced name.
type DNSTraceMatch struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Regexp      string `json:"regexp"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	AddressList string `json:"addressList"`
	Disabled    bool   `json:"disabled"`
	// How it matches: exact, subdomain or regexp.
	How string `json:"how"`
}

// answers is whether the entry decides what a client looking the name up is
// told: enabled, and a type a lookup of an address can be answered with.
func (m DNSTraceMatch) answers() bool {
	return !m.Disabled && (m.Type == "FWD" || m.Type == "A" || m.Type == "AAAA")
}

// DNSTraceStep is one line of the verdict.
type DNSTraceStep struct {
	Step  string `json:"step"`
	State string `json:"state"` // ok, warn, fail, skip
	Text  string `json:"text"`
}

// traceAccess is which links past the static entry the viewer may see.
type traceAccess struct {
	Lists, Mangle, Routes bool
}

// traceAccessFor is what a session may read of the chain on a router.
func (s *Server) traceAccessFor(sess *Session, routerID string) traceAccess {
	uid := s.userIDFor(sess.Username)
	may := func(page string) bool { return permitted(s.rbac.CanPage(uid, page, "read", routerID)) }
	return traceAccess{Lists: may("address-lists"), Mangle: may("firewall"), Routes: may("routing")}
}

// DNSTrace is the trace's answer.
type DNSTrace struct {
	Name    string          `json:"name"`
	Matches []DNSTraceMatch `json:"matches"`
	// Answering indexes Matches: the entries that decide the answer. More than
	// one means RouterOS's choice between them is not documented.
	Answering []int `json:"answering"`
	// Unevaluated are regexps this server could not compile, which may catch the
	// name for all it can tell.
	Unevaluated []string            `json:"unevaluated"`
	Cache       []DNSCacheRow       `json:"cache"`
	List        string              `json:"list"`
	Listed      []map[string]string `json:"listed"`
	Mangle      []map[string]string `json:"mangle"`
	Routes      []map[string]string `json:"routes"`
	Steps       []DNSTraceStep      `json:"steps"`
}

// TraceMatches finds the static entries that catch a name: every kind of entry,
// in no ranking, because the manual documents none. A regexp RouterOS accepts and
// Go does not is reported rather than skipped silently.
func TraceMatches(name string, rows []routeros.Reply) (matches []DNSTraceMatch, unevaluated []string) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	for _, e := range collect.ParseStaticEntries(rows) {
		m := DNSTraceMatch{ID: e.ID, Name: e.Name, Regexp: e.Regexp, Type: e.Type, Value: e.Address,
			AddressList: e.AddressList, Disabled: e.Disabled}
		own := strings.TrimSuffix(strings.ToLower(e.Name), ".")
		switch {
		case e.Regexp != "":
			rx, err := regexp.Compile(e.Regexp)
			if err != nil {
				unevaluated = append(unevaluated, e.Regexp)
				continue
			}
			if rx.MatchString(name) {
				m.How = "regexp"
				matches = append(matches, m)
			}
		case own == name:
			m.How = "exact"
			matches = append(matches, m)
		case e.MatchSubdomain && own != "" && strings.HasSuffix(name, "."+own):
			m.How = "subdomain"
			matches = append(matches, m)
		}
	}
	return matches, unevaluated
}

func (s *Server) dnsTraceGet(w http.ResponseWriter, r *http.Request) {
	sess, sn, drop, ok := s.dnsToolSession(w, r, store.FeatureDNSTrace, false)
	if !ok {
		return
	}
	defer drop()
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("name"))), ".")
	if name == "" || len(name) > 253 || strings.ContainsAny(name, " \t\"'?=") {
		writeJSONErr(w, http.StatusBadRequest, "a domain name, e.g. www.example.com")
		return
	}
	t, err := traceDomain(r.Context(), sn.Exec, name, s.traceAccessFor(sess, r.URL.Query().Get("routerId")))
	if err != nil {
		writeJSONErr(w, http.StatusBadGateway, safe.Message(err.Error()))
		return
	}
	writeJSON(w, t)
}

// answeringLists are the distinct address lists the answering entries feed, "" for
// an entry that feeds none.
func answeringLists(t DNSTrace) []string {
	seen := map[string]bool{}
	var out []string
	for _, i := range t.Answering {
		l := t.Matches[i].AddressList
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

// traceDomain reads what the verdict needs: the static table, the cached
// answers for the name, then only the list entries, mangle rules and routes
// the answering entries lead to, each filtered on the router and each only when
// `access` allows it.
func traceDomain(ctx context.Context, exec func(routeros.Cmd) ([]routeros.Reply, error), name string,
	access traceAccess) (DNSTrace, error) {
	t := DNSTrace{Name: name, Matches: []DNSTraceMatch{}, Answering: []int{}, Unevaluated: []string{},
		Cache: []DNSCacheRow{}, Listed: []map[string]string{}, Mangle: []map[string]string{},
		Routes: []map[string]string{}}
	rows, err := exec(collect.DNSStaticCmd())
	if err != nil {
		return t, err
	}
	t.Matches, t.Unevaluated = TraceMatches(name, rows)
	if t.Matches == nil {
		t.Matches = []DNSTraceMatch{}
	}
	if t.Unevaluated == nil {
		t.Unevaluated = []string{}
	}
	for i, m := range t.Matches {
		if m.answers() {
			t.Answering = append(t.Answering, i)
		}
	}

	// The cached answers, following a CNAME a few hops.
	seen := map[string]bool{}
	for q, hops := name, 0; q != "" && hops < 5 && !seen[q] && ctx.Err() == nil; hops++ {
		seen[q] = true
		cached, cerr := exec(routeros.Cmd{Path: dnsCacheCmd.Path, Args: append(append([]string{},
			dnsCacheCmd.Args...), "?name="+q)})
		if cerr != nil {
			break
		}
		next := ""
		for _, c := range cached {
			t.Cache = append(t.Cache, DNSCacheRow{Name: c["name"], Type: c["type"], Data: c["data"], TTL: c["ttl"]})
			if c["type"] == "CNAME" {
				next = strings.TrimSuffix(strings.ToLower(c["data"]), ".")
			}
		}
		q = next
	}

	// The chain is followed only when the answering entries agree on a list.
	if lists := answeringLists(t); len(lists) == 1 {
		t.List = lists[0]
	}
	if t.List != "" && access.Lists {
		for _, c := range t.Cache {
			if c.Type != "A" {
				continue
			}
			got, lerr := exec(routeros.Cmd{Path: "/ip/firewall/address-list/print",
				Args: []string{addrListProps, "?list=" + t.List, "?address=" + c.Data}})
			if lerr == nil {
				for _, g := range got {
					t.Listed = append(t.Listed, map[string]string(g))
				}
			}
		}
	}
	if t.List != "" && access.Mangle {
		if mangle, merr := exec(routeros.Cmd{Path: "/ip/firewall/mangle/print",
			Args: []string{mangleProps, "?dst-address-list=" + t.List}}); merr == nil {
			marks := map[string]bool{}
			for _, m := range mangle {
				t.Mangle = append(t.Mangle, map[string]string(m))
				if m["disabled"] != "true" && m["new-routing-mark"] != "" && access.Routes {
					marks[m["new-routing-mark"]] = true
				}
			}
			for mark := range marks {
				if routes, rerr := exec(routeros.Cmd{Path: "/ip/route/print",
					Args: []string{routeProps, "?routing-table=" + mark}}); rerr == nil {
					for _, rt := range routes {
						t.Routes = append(t.Routes, map[string]string(rt))
					}
				}
			}
		}
	}
	t.Steps = TraceSteps(t, access)
	return t, nil
}

// entryText describes one matching entry in a line.
func entryText(m DNSTraceMatch) string {
	desc := m.Type + " " + firstNonEmpty(m.Name, m.Regexp)
	switch m.How {
	case "subdomain":
		desc += " (matches subdomains)"
	case "regexp":
		desc = m.Type + " regexp " + m.Regexp
	}
	if m.Type == "FWD" {
		desc += ", forwarded to " + firstNonEmpty(m.Value, "the resolver's own servers")
	} else if m.Value != "" {
		desc += ", answers " + m.Value
	}
	return desc
}

// TraceSteps is the verdict, pure: what was read in, one line per link of the
// chain out. A link that cannot be judged because an earlier one is missing,
// or that the viewer may not read, says so as `skip`, rather than reporting a
// failure it did not measure.
func TraceSteps(t DNSTrace, access traceAccess) []DNSTraceStep {
	var out []DNSTraceStep
	add := func(step, state, text string) { out = append(out, DNSTraceStep{step, state, text}) }
	withheld := func(step, page string) {
		add(step, "skip", "Not shown: you may not read "+page+" on this router.")
	}
	unevaluated := func() {
		if n := len(t.Unevaluated); n > 0 {
			add("Regexp", "warn", strconv.Itoa(n)+" regexp "+map[bool]string{true: "entry", false: "entries"}[n == 1]+
				" could not be evaluated here ("+strings.Join(t.Unevaluated, ", ")+
				"), so "+map[bool]string{true: "it", false: "they"}[n == 1]+" may catch "+t.Name+".")
		}
	}

	switch len(t.Answering) {
	case 0:
		why := "No static entry catches " + t.Name + ": the router resolves it through its own servers and puts it on no list."
		if len(t.Matches) > 0 {
			why = "Only entries that do not answer a lookup of an address catch " + t.Name +
				" (disabled, or not FWD, A or AAAA): " + joinEntries(t.Matches) + "."
		}
		add("Static entry", "fail", why)
		unevaluated()
		return out
	case 1:
		add("Static entry", "ok", entryText(t.Matches[t.Answering[0]]))
	default:
		var picks []DNSTraceMatch
		for _, i := range t.Answering {
			picks = append(picks, t.Matches[i])
		}
		text := strconv.Itoa(len(picks)) + " entries catch " + t.Name + ": " + joinEntries(picks) +
			". RouterOS does not document which one answers."
		if lists := answeringLists(t); len(lists) == 1 {
			text += " They feed the same address list (" + listNames(lists)[0] + "), so the rest of the chain holds whichever does."
		}
		add("Static entry", "warn", text)
		if lists := answeringLists(t); len(lists) > 1 {
			unevaluated()
			add("Address list", "skip", "Not followed: they feed different lists ("+
				strings.Join(listNames(lists), ", ")+") and which entry answers is not documented.")
			return out
		}
	}
	unevaluated()

	var addrs []string
	aaaa := 0
	for _, c := range t.Cache {
		switch c.Type {
		case "A":
			addrs = append(addrs, c.Data)
		case "AAAA":
			aaaa++
		}
	}
	v6 := ""
	if aaaa > 0 {
		v6 = " IPv6 answers (AAAA) are not followed: this chain reads IPv4 only."
	}
	if len(addrs) == 0 {
		if aaaa > 0 {
			add("Resolved", "warn", "Only IPv6 answers are cached for it."+v6)
		} else {
			add("Resolved", "warn", "Not in the router's cache: nothing has asked for it lately, or the answer expired. "+
				"Open it from a client and trace again.")
		}
	} else {
		add("Resolved", "ok", strings.Join(addrs, ", ")+"."+v6)
	}

	if t.List == "" {
		add("Address list", "skip", "The entry feeds no address list.")
		return out
	}
	listed := map[string]bool{}
	for _, l := range t.Listed {
		listed[l["address"]] = true
	}
	n := 0
	for _, a := range addrs {
		if listed[a] {
			n++
		}
	}
	switch {
	case !access.Lists:
		withheld("Address list", "Address Lists")
	case len(addrs) == 0:
		add("Address list", "skip", "Nothing resolved to look for on "+t.List+".")
	case n == len(addrs):
		add("Address list", "ok", "Every address is on "+t.List+".")
	case n > 0:
		add("Address list", "warn", "Only "+strconv.Itoa(n)+" of "+strconv.Itoa(len(addrs))+" addresses are on "+t.List+".")
	default:
		add("Address list", "fail", "None of the addresses is on "+t.List+". Answers from the cache are not added; "+
			"a client's own query is.")
	}

	if !access.Mangle {
		withheld("Mangle", "Firewall")
		return out
	}
	marks := map[string]string{}
	for _, r := range t.Mangle {
		if r["disabled"] != "true" && r["new-routing-mark"] != "" {
			marks[r["new-routing-mark"]] = r["packets"]
		}
	}
	if len(marks) == 0 {
		add("Mangle", "fail", "No enabled mangle rule marks routing for dst-address-list="+t.List+
			", so being on the list changes nothing.")
		return out
	}
	names := make([]string, 0, len(marks))
	for k := range marks {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, mark := range names {
		add("Mangle", "ok", "Marks routing "+mark+" ("+firstNonEmpty(marks[mark], "0")+" packets so far).")
		if !access.Routes {
			withheld("Route", "Routing")
			continue
		}
		var active []string
		for _, rt := range t.Routes {
			if rt["routing-table"] == mark && rt["active"] == "true" && rt["disabled"] != "true" {
				active = append(active, rt["dst-address"]+" via "+firstNonEmpty(rt["gateway"], "?"))
			}
		}
		if len(active) == 0 {
			add("Route", "fail", "Table "+mark+" has no active route, so marked traffic does not leave by it.")
		} else {
			add("Route", "ok", "Table "+mark+": "+strings.Join(active, ", ")+".")
		}
	}
	return out
}

func joinEntries(ms []DNSTraceMatch) string {
	parts := make([]string, len(ms))
	for i, m := range ms {
		parts[i] = entryText(m)
		if m.Disabled {
			parts[i] += " [disabled]"
		}
	}
	return strings.Join(parts, "; ")
}

// listNames are address list names for a sentence, "no list" for an entry that
// feeds none.
func listNames(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = firstNonEmpty(s, "no list")
	}
	return out
}
