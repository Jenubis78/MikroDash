package server

// Domain routing (Settings -> Features): the address list the operator's static
// DNS entries feed, the mangle rules that mark routing for it, and whether the
// tables they mark for have an active route. The Dashboard card shows it and
// "Domain Routing Down" alerts on it.
//
// ── ONLY ROUTERS THAT ROUTE BY DOMAIN ───────────────────────────────────────
//
// The list is named in Settings; with none named nothing is read. A router is
// asked every half hour whether its static entries feed the list, one
// `count-only` print, and one where nothing does is read no further, raises
// nothing and shows "not used here". One that does is read once a minute by
// the feature loop: the list's size (count-only), the mangle rules that match
// it, and the routes of each table they mark for, every print filtered on the
// router and bounded by a timeout.
//
// ── DEBOUNCED ───────────────────────────────────────────────────────────────
//
// Down is raised once three readings in a row say so, about three minutes, as
// RouterStatus waits out the offline threshold: a route that drops while a
// tunnel reconnects is not an alert. Up is immediate. Switching the feature off
// withdraws every open Domain Routing Down without a message.
//
// ── EACH VIEWER SEES WHAT THEIR GRANTS ALLOW ────────────────────────────────
//
// The card opens with DNS read access. The list's size, the rules and the
// routes belong to the Address Lists, Firewall and Routing pages, and each is
// sent only to a viewer granted that page on the router, the way
// broadcastRouterList filters the fleet per socket. A viewer missing one gets
// the verdict without the reason, which names tables.

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"mikrodash/internal/routeros"
	"mikrodash/internal/safe"
	"mikrodash/internal/store"
)

const (
	// domainRouteDownAfter is how many failing readings in a row raise the alert.
	domainRouteDownAfter = 3
	// domainRouteFedEvery is how often a router is asked whether it feeds the list.
	domainRouteFedEvery = 30 * time.Minute
	// domainRouteRead bounds one print.
	domainRouteRead = 15 * time.Second
)

// DomainRoutingRule is one mangle rule that matches the list.
type DomainRoutingRule struct {
	ID       string `json:"id"`
	Chain    string `json:"chain"`
	Mark     string `json:"mark"`
	Packets  string `json:"packets"`
	Disabled bool   `json:"disabled"`
	Comment  string `json:"comment"`
}

// DomainRoutingRoute is one route in a table a rule marks for.
type DomainRoutingRoute struct {
	Table   string `json:"table"`
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Active  bool   `json:"active"`
}

// DomainRoutingStatus is one router's reading, as the card shows it.
type DomainRoutingStatus struct {
	RouterID string `json:"routerId"`
	// List is the address list watched; empty when Settings names none.
	List string `json:"list"`
	// Feeding is how many static entries feed it; 0 means the router does not
	// route by domain and nothing more was read.
	Feeding int `json:"feeding"`
	// Entries is how many addresses are on it now.
	Entries int                  `json:"entries"`
	Rules   []DomainRoutingRule  `json:"rules"`
	Routes  []DomainRoutingRoute `json:"routes"`
	OK      bool                 `json:"ok"`
	Why     string               `json:"why"`
	Error   string               `json:"error"`
	// Withheld names the pages whose part of the reading this viewer may not see.
	Withheld []string `json:"withheld"`
	TS       int64    `json:"ts"`
}

func newDomainRoutingStatus(routerID, list string) DomainRoutingStatus {
	return DomainRoutingStatus{RouterID: routerID, List: list, Rules: []DomainRoutingRule{},
		Routes: []DomainRoutingRoute{}, Withheld: []string{}, TS: time.Now().UnixMilli()}
}

// countOnly is how many rows a filtered print would answer, without the rows.
func countOnly(exec func(routeros.Cmd) ([]routeros.Reply, error), path string, query ...string) (int, error) {
	var ret string
	if _, err := exec(routeros.Cmd{Path: path, Args: append([]string{"=count-only="}, query...),
		Ret: &ret, Timeout: domainRouteRead}); err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(ret))
}

// domainRoutingFed is how many of the router's static entries feed the list.
func domainRoutingFed(exec func(routeros.Cmd) ([]routeros.Reply, error), list string) (int, error) {
	return countOnly(exec, "/ip/dns/static/print", "?address-list="+list)
}

// domainRoutingStatus reads the rest of the chain for a router that feeds the
// list.
func domainRoutingStatus(ctx context.Context, exec func(routeros.Cmd) ([]routeros.Reply, error),
	routerID, list string, feeding int) DomainRoutingStatus {

	st := newDomainRoutingStatus(routerID, list)
	st.Feeding = feeding
	fail := func(err error) DomainRoutingStatus {
		st.Error = safe.Message(err.Error())
		return st
	}
	n, err := countOnly(exec, "/ip/firewall/address-list/print", "?list="+list)
	if err != nil {
		return fail(err)
	}
	st.Entries = n
	rules, err := exec(routeros.Cmd{Path: "/ip/firewall/mangle/print",
		Args: []string{mangleProps, "?dst-address-list=" + list}, Timeout: domainRouteRead})
	if err != nil {
		return fail(err)
	}
	marks := map[string]bool{}
	for _, r := range rules {
		rule := DomainRoutingRule{ID: r[".id"], Chain: r["chain"], Mark: r["new-routing-mark"],
			Packets: r["packets"], Disabled: r["disabled"] == "true", Comment: r["comment"]}
		st.Rules = append(st.Rules, rule)
		if !rule.Disabled && rule.Mark != "" {
			marks[rule.Mark] = true
		}
	}
	tables := make([]string, 0, len(marks))
	for m := range marks {
		tables = append(tables, m)
	}
	sort.Strings(tables)
	for _, table := range tables {
		if ctx.Err() != nil {
			return fail(ctx.Err())
		}
		routes, rerr := exec(routeros.Cmd{Path: "/ip/route/print",
			Args: []string{routeProps, "?routing-table=" + table}, Timeout: domainRouteRead})
		if rerr != nil {
			return fail(rerr)
		}
		for _, r := range routes {
			if r["disabled"] == "true" {
				continue
			}
			st.Routes = append(st.Routes, DomainRoutingRoute{Table: table, Dst: r["dst-address"],
				Gateway: r["gateway"], Active: r["active"] == "true"})
		}
	}
	st.OK, st.Why = routingVerdict(list, tables, st.Routes)
	return st
}

// routingVerdict is the alert's question: does traffic to the list have a way
// out? Pure, so the reasons are tested without a router.
func routingVerdict(list string, tables []string, routes []DomainRoutingRoute) (bool, string) {
	if len(tables) == 0 {
		return false, "No enabled mangle rule marks routing for dst-address-list=" + list
	}
	var dead []string
	for _, t := range tables {
		up := false
		for _, r := range routes {
			if r.Table == t && r.Active {
				up = true
			}
		}
		if !up {
			dead = append(dead, t)
		}
	}
	if len(dead) > 0 {
		return false, "No active route in " + strings.Join(dead, ", ") + " for traffic to " + list
	}
	return true, ""
}

// For is the reading as a viewer with these grants may see it.
func (st DomainRoutingStatus) For(lists, firewall, routing bool) DomainRoutingStatus {
	out := st
	out.Rules = append([]DomainRoutingRule{}, st.Rules...)
	out.Routes = append([]DomainRoutingRoute{}, st.Routes...)
	out.Withheld = []string{}
	if !lists {
		out.Entries = 0
		out.Withheld = append(out.Withheld, "Address Lists")
	}
	if !firewall {
		out.Rules = []DomainRoutingRule{}
		out.Withheld = append(out.Withheld, "Firewall")
	}
	if !routing {
		out.Routes = []DomainRoutingRoute{}
		out.Withheld = append(out.Withheld, "Routing")
	}
	if !firewall || !routing {
		out.Why = ""
	}
	return out
}

// sendDomainRoute gives every socket showing the card for this router the
// reading, cut to what that viewer may read.
func (s *Server) sendDomainRoute(st DomainRoutingStatus) {
	for _, cn := range s.connections() {
		sc := cn.scope()
		cn.mu.Lock()
		showing := cn.cards["domainroute"]
		cn.mu.Unlock()
		if !showing || sc.routerID != st.RouterID {
			continue
		}
		// The grants the card was focused under may have gone since.
		if !cn.canPageIn(sc, "dashboard", "read") || !cn.canPageIn(sc, "dns", "read") {
			continue
		}
		cn.sendDomainRouteIn(sc, st)
	}
}

func (cn *conn) sendDomainRouteIn(sc connScope, st DomainRoutingStatus) {
	EvDNSRouting.Send(cn.srv.hub, cn.c, st.For(cn.canPageIn(sc, "address-lists", "read"),
		cn.canPageIn(sc, "firewall", "read"), cn.canPageIn(sc, "routing", "read")))
}

// domainRouteFocus answers the card being shown with the last reading, which
// the loop takes within a minute of the feature being switched on.
func (cn *conn) domainRouteFocus() {
	sc := cn.scope()
	if sc.routerID == "" {
		return
	}
	s := cn.srv
	if !s.featureOn(store.FeatureDomainRouting) || s.features == nil {
		st := newDomainRoutingStatus(sc.routerID, "")
		st.Error = "Switched off: Settings -> Features -> Domain routing card"
		cn.sendDomainRouteIn(sc, st)
		return
	}
	s.features.mu.Lock()
	st, ok := s.features.routing[sc.routerID]
	s.features.mu.Unlock()
	if !ok {
		st = newDomainRoutingStatus(sc.routerID, "")
		st.Error = "Waiting for the first reading, within a minute"
	}
	cn.sendDomainRouteIn(sc, st)
}
