package server

// The Traffic page's HTTP API. The engine is traffic.go; the core is
// internal/traffic.
//
//	GET  /api/traffic/state?router=     collection status and the last minute, by every dimension
//	GET  /api/traffic/history?router=   top groups and their series over a range (dim, range, host, app, country)
//	GET  /api/traffic/flows?router=     flows: ClickHouse, or the last fifteen minutes in memory
//	GET  /api/traffic/settings          the backend and its settings
//	POST /api/traffic/settings          change them (the backend is opened before it is kept)
//	POST /api/traffic/router?router=    the interfaces Traffic Flow counts on
//	GET  /api/traffic/plan?router=      what the router needs, read-only (`remove=1`: to take it off)
//	POST /api/traffic/apply?router=     do it
//
// Reading follows the page grant on the router; settings and router writes
// are for administrators, as the IPS's are, and audited.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"mikrodash/internal/audit"
	"mikrodash/internal/db"
	"mikrodash/internal/guard"
	"mikrodash/internal/ips"
	"mikrodash/internal/routeros"
	"mikrodash/internal/safe"
	"mikrodash/internal/session"
	"mikrodash/internal/topology"
	"mikrodash/internal/traffic"
)

const trafficPage = "traffic-analysis"

// trafficLiveTop is how many groups the Live tab lists per dimension.
const trafficLiveTop = 15

// trafficSeriesKeys is how many groups a History chart draws; the rest is Other.
const trafficSeriesKeys = 8

func (s *Server) registerTraffic(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/traffic/state", s.trafficState)
	mux.HandleFunc("GET /api/traffic/history", s.trafficHistory)
	mux.HandleFunc("GET /api/traffic/flows", s.trafficFlows)
	mux.HandleFunc("GET /api/traffic/settings", s.trafficSettingsGet)
	mux.HandleFunc("POST /api/traffic/settings", s.trafficSettingsSave)
	mux.HandleFunc("POST /api/traffic/router", s.trafficRouterSave)
	mux.HandleFunc("GET /api/traffic/plan", s.trafficPlan)
	mux.HandleFunc("POST /api/traffic/apply", s.trafficApply)
}

func (s *Server) trafficReadGate(w http.ResponseWriter, r *http.Request) (*Session, string) {
	sess := s.layoutSession(w, r)
	if sess == nil {
		return nil, ""
	}
	rid := r.URL.Query().Get("router")
	if !topology.IsValidRouterID(rid) || !permitted(s.rbac.CanPage(s.userIDFor(sess.Username), trafficPage, "read", rid)) {
		writeJSONErr(w, http.StatusForbidden, "no access to the traffic of this router")
		return nil, ""
	}
	if s.auditDB == nil || s.traffic == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "the database is not open")
		return nil, ""
	}
	return sess, rid
}

func (s *Server) trafficAdminGate(w http.ResponseWriter, r *http.Request) *Session {
	sess := s.layoutSession(w, r)
	if sess == nil {
		return nil
	}
	if !s.isGlobalAdmin(sess) {
		writeJSONErr(w, http.StatusForbidden, "the Traffic page is configured by administrators")
		return nil
	}
	if s.auditDB == nil || s.traffic == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "the database is not open")
		return nil
	}
	return sess
}

func (s *Server) trafficAdminRouterGate(w http.ResponseWriter, r *http.Request) (*Session, string) {
	sess := s.trafficAdminGate(w, r)
	if sess == nil {
		return nil, ""
	}
	rid := r.URL.Query().Get("router")
	if !topology.IsValidRouterID(rid) {
		writeJSONErr(w, http.StatusBadRequest, "no such router")
		return nil, ""
	}
	return sess, rid
}

func (s *Server) trafficRouterRow(rid string) db.TrafficRouter {
	rows, _ := s.auditDB.TrafficRouters()
	for _, r := range rows {
		if r.RouterID == rid {
			return r
		}
	}
	return db.TrafficRouter{RouterID: rid}
}

// TrafficStatePayload is the Live tab.
type TrafficStatePayload struct {
	Router TrafficRouterView        `json:"router"`
	Status TrafficStatus            `json:"status"`
	Live   map[string][]traffic.Top `json:"live"`
	// LiveAt is the start of the span Live adds up; 0 before the first.
	LiveAt int64 `json:"liveAt"`
	// LiveSeconds is how long that span is: 60 from Traffic Flow, the last
	// few seconds from the sensor.
	LiveSeconds int  `json:"liveSeconds"`
	Admin       bool `json:"admin"`
}

// TrafficRouterView is a router's row as the page reads it.
type TrafficRouterView struct {
	Enabled    bool   `json:"enabled"`
	Interfaces string `json:"interfaces"`
	AppliedAt  int64  `json:"appliedAt"`
	Result     string `json:"result"`
}

func (s *Server) trafficState(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.trafficReadGate(w, r)
	if sess == nil {
		return
	}
	row := s.trafficRouterRow(rid)
	st, live, at, secs := s.traffic.status(rid)
	p := TrafficStatePayload{Router: TrafficRouterView{Enabled: row.Enabled, Interfaces: row.Interfaces,
		AppliedAt: row.AppliedAt, Result: row.Result}, Status: st, Live: map[string][]traffic.Top{},
		Admin: s.isGlobalAdmin(sess), LiveSeconds: secs}
	if !at.IsZero() {
		p.LiveAt = at.UnixMilli()
	}
	for _, d := range []traffic.Dim{traffic.DimApp, traffic.DimCategory, traffic.DimHost, traffic.DimCountry} {
		p.Live[string(d)] = traffic.TopOf(live, traffic.Query{Dim: d, Limit: trafficLiveTop})
	}
	writeJSON(w, p)
}

// trafficRanges are the History tab's ranges.
var trafficRanges = map[string]time.Duration{"1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour,
	"7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour, "90d": 90 * 24 * time.Hour, "365d": 365 * 24 * time.Hour}

// TrafficHistoryPayload is a range's top groups and their series.
type TrafficHistoryPayload struct {
	From    int64           `json:"from"`
	To      int64           `json:"to"`
	Step    int64           `json:"step"` // seconds
	Backend string          `json:"backend"`
	Top     []traffic.Top   `json:"top"`
	Series  []traffic.Point `json:"series"`
}

func (s *Server) trafficHistory(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.trafficReadGate(w, r)
	if sess == nil {
		return
	}
	q := r.URL.Query()
	span, ok := trafficRanges[q.Get("range")]
	if !ok {
		span = 24 * time.Hour
	}
	dim := traffic.Dim(q.Get("dim"))
	if !dim.Valid() {
		writeJSONErr(w, http.StatusBadRequest, "dim is app, category, host or country")
		return
	}
	st, why := s.traffic.currentStore()
	if st == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, safe.Message("the backend is not open: "+why))
		return
	}
	to := time.Now().Truncate(time.Minute).Add(time.Minute)
	from := to.Add(-span)
	query := traffic.Query{RouterID: rid, Dim: dim, Host: q.Get("host"), App: q.Get("app"), Country: q.Get("country"),
		From: from, To: to, Limit: 50}
	top, err := st.Top(r.Context(), query)
	if err != nil {
		writeJSONErr(w, http.StatusBadGateway, safe.Message("the backend could not answer: "+err.Error()))
		return
	}
	keys := []string{}
	for i, t := range top {
		if i == trafficSeriesKeys {
			break
		}
		keys = append(keys, t.Key)
	}
	step := traffic.StepFor(from, to)
	series, err := st.Series(r.Context(), query, step, keys)
	if err != nil {
		writeJSONErr(w, http.StatusBadGateway, safe.Message("the backend could not answer: "+err.Error()))
		return
	}
	if series == nil {
		series = []traffic.Point{}
	}
	writeJSON(w, TrafficHistoryPayload{From: from.UnixMilli(), To: to.UnixMilli(), Step: int64(step / time.Second),
		Backend: st.Backend(), Top: top, Series: series})
}

func (s *Server) trafficFlows(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.trafficReadGate(w, r)
	if sess == nil {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	span, ok := trafficRanges[q.Get("range")]
	if !ok {
		span = time.Hour
	}
	to := time.Now().Add(time.Minute)
	fq := traffic.FlowQuery{RouterID: rid, Host: q.Get("host"), Remote: q.Get("remote"), App: q.Get("app"),
		Country: q.Get("country"), From: to.Add(-span), To: to, Limit: limit}
	if st, _ := s.traffic.currentStore(); st != nil {
		flows, err := st.Flows(r.Context(), fq)
		if err == nil {
			writeJSON(w, map[string]any{"source": st.Backend(), "flows": flows})
			return
		}
		if !errors.Is(err, traffic.ErrNoFlowHistory) {
			writeJSONErr(w, http.StatusBadGateway, safe.Message("the backend could not answer: "+err.Error()))
			return
		}
	}
	writeJSON(w, map[string]any{"source": "memory", "flows": s.traffic.recentFlows(fq)})
}

// TrafficSettingsView is the settings without the password, which only says
// whether one is set.
type TrafficSettingsView struct {
	db.TrafficSettings
	CHPasswordSet bool `json:"chPasswordSet"`
}

func (s *Server) trafficSettingsGet(w http.ResponseWriter, r *http.Request) {
	if s.trafficAdminGate(w, r) == nil {
		return
	}
	set := s.traffic.currentSettings()
	writeJSON(w, TrafficSettingsView{TrafficSettings: set, CHPasswordSet: set.CHPassword != ""})
}

func (s *Server) trafficSettingsSave(w http.ResponseWriter, r *http.Request) {
	sess := s.trafficAdminGate(w, r)
	if sess == nil {
		return
	}
	var body struct {
		Backend    string `json:"backend"`
		CHURL      string `json:"chUrl"`
		CHUser     string `json:"chUser"`
		CHPassword string `json:"chPassword"` // empty keeps the one set
		CHDatabase string `json:"chDatabase"`
		FlowDays   int    `json:"flowDays"`
		Port       int    `json:"port"`
		Collector  string `json:"collector"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeJSON400OK(w)
		return
	}
	was := s.traffic.currentSettings()
	set := db.TrafficSettings{Backend: body.Backend, CHURL: strings.TrimSpace(body.CHURL), CHUser: strings.TrimSpace(body.CHUser),
		CHPassword: was.CHPassword, CHDatabase: strings.TrimSpace(body.CHDatabase), FlowDays: body.FlowDays, Port: body.Port,
		Collector: strings.TrimSpace(body.Collector)}
	if set.Backend != "sqlite" && set.Backend != "clickhouse" {
		writeJSONErr(w, http.StatusBadRequest, "the backend is sqlite or clickhouse")
		return
	}
	if set.Port < 1024 || set.Port > 65535 {
		writeJSONErr(w, http.StatusBadRequest, "the IPFIX port is 1024 to 65535")
		return
	}
	if set.Collector != "" {
		if _, err := netip.ParseAddr(set.Collector); err != nil {
			writeJSONErr(w, http.StatusBadRequest, "the collector address is one IP address")
			return
		}
	}
	if body.CHPassword != "" {
		sealed, err := s.sealCredSecret(body.CHPassword)
		if err != nil {
			writeJSONErr(w, http.StatusInternalServerError, "the password could not be sealed")
			return
		}
		set.CHPassword = sealed
	}
	if set.Backend == "clickhouse" {
		cfg := traffic.ClickHouseConfig{URL: set.CHURL, User: set.CHUser, Database: set.CHDatabase, FlowDays: set.FlowDays}
		if err := cfg.Validate(); err != nil {
			writeJSONErr(w, http.StatusBadRequest, safe.Message(err.Error()))
			return
		}
		set.CHUser, set.CHDatabase, set.FlowDays = cfg.User, cfg.Database, cfg.FlowDays
		// Opened before it is kept: a backend that does not answer is refused
		// with ClickHouse's own reason, and the one in use stays.
		st, err := s.traffic.openStore(set)
		if err != nil {
			writeJSONErr(w, http.StatusBadGateway, safe.Message("ClickHouse did not accept the connection: "+err.Error()))
			return
		}
		st.Close()
	}
	if err := s.auditDB.SaveTrafficSettings(set); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "the settings could not be saved")
		return
	}
	s.traffic.applySettings(set)
	s.httpRecorder(r, sess).Record(audit.Event{Action: "traffic.settings", TargetType: "trafficSettings",
		TargetID: set.Backend, Note: "backend " + set.Backend + ", port " + strconv.Itoa(set.Port)})
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) trafficRouterSave(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.trafficAdminRouterGate(w, r)
	if sess == nil {
		return
	}
	var body struct {
		Interfaces string `json:"interfaces"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeJSON400OK(w)
		return
	}
	iface := strings.TrimSpace(body.Interfaces)
	if strings.ContainsAny(iface, "=\n\r\"") || len(iface) > 512 {
		writeJSONErr(w, http.StatusBadRequest, "interfaces are names separated by commas, or all")
		return
	}
	row := s.trafficRouterRow(rid)
	row.Interfaces = iface
	if err := s.auditDB.SaveTrafficRouter(row); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "the router could not be saved")
		return
	}
	s.httpRecorder(r, sess).Record(audit.Event{Action: "traffic.router", RouterID: rid, TargetType: "trafficRouter",
		TargetID: rid, Note: "interfaces " + firstNonEmpty(iface, "all")})
	writeJSON(w, map[string]any{"ok": true})
}

// errNoCollector is a router that does not show where it sees MikroDash from.
var errNoCollector = errors.New("the router does not show where it sees MikroDash from: set the collector address in the settings")

// sensorFeeds is whether a router's IPS sensor inspects every packet, and so
// counts its volumes itself.
func (s *Server) sensorFeeds(rid string) bool {
	sn, ok := s.ipsSensorOf(rid)
	return ok && sn.EveryPacket
}

// trafficRouterPlan reads what the plan needs and plans. A router the IPS
// sensor feeds needs no Traffic Flow: its plan is the removal, whatever was
// asked, and says why.
func (s *Server) trafficRouterPlan(sn *session.Session, rid string, remove bool) (ips.Plan, error) {
	fed := s.sensorFeeds(rid)
	remove = remove || fed
	set := s.traffic.currentSettings()
	collector, err := netip.ParseAddr(set.Collector)
	if err != nil {
		active, aerr := sn.Exec(routeros.Cmd{Path: "/user/active/print", Args: []string{"=.proplist=name,address"},
			Timeout: ipsCmdTimeout})
		if aerr != nil {
			return ips.Plan{}, aerr
		}
		self, _ := guard.SelfAddresses(active, []string{sn.Username()})
		for _, a := range self {
			if collector, err = netip.ParseAddr(a); err == nil {
				break
			}
		}
		if !collector.IsValid() {
			return ips.Plan{}, errNoCollector
		}
	}
	one := func(path string) (routeros.Reply, error) {
		rows, err := sn.Exec(routeros.Cmd{Path: path, Timeout: ipsCmdTimeout})
		if err != nil || len(rows) == 0 {
			return routeros.Reply{}, err
		}
		return rows[0], nil
	}
	tf, err := one("/ip/traffic-flow/print")
	if err != nil {
		return ips.Plan{}, err
	}
	targets, err := sn.Exec(routeros.Cmd{Path: "/ip/traffic-flow/target/print", Timeout: ipsCmdTimeout})
	if err != nil {
		return ips.Plan{}, err
	}
	ipfixRow, err := one("/ip/traffic-flow/ipfix/print")
	if err != nil {
		return ips.Plan{}, err
	}
	filter, _ := sn.Exec(routeros.Cmd{Path: "/ip/firewall/filter/print",
		Args: []string{"=.proplist=.id,action,disabled"}, Timeout: ipsCmdTimeout})
	row := s.trafficRouterRow(rid)
	plan := traffic.RouterPlan(traffic.PlanParams{Collector: collector, Port: set.Port, Interfaces: row.Interfaces},
		tf, targets, ipfixRow, filter, remove)
	if fed {
		plan.Warnings = append([]string{"This router's IPS sensor inspects every packet and counts its volumes " +
			"itself, every five seconds: Traffic Flow is not needed, so this takes MikroDash's target off the " +
			"router (and Traffic Flow with it, when no other collector uses it)."}, plan.Warnings...)
	}
	return plan, nil
}

func (s *Server) trafficPlanError(w http.ResponseWriter, err error) {
	if errors.Is(err, errNoCollector) {
		writeJSONErr(w, http.StatusConflict, safe.Message(errNoCollector.Error()))
		return
	}
	writeJSONErr(w, http.StatusBadGateway, "Traffic Flow could not be read")
}

func (s *Server) trafficPlan(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.trafficAdminRouterGate(w, r)
	if sess == nil {
		return
	}
	sn, drop, ok := s.ipsSession(r.Context(), rid)
	if !ok {
		writeJSONErr(w, http.StatusBadGateway, "the router is not reachable")
		return
	}
	defer drop()
	plan, err := s.trafficRouterPlan(sn, rid, r.URL.Query().Get("remove") == "1")
	if err != nil {
		s.trafficPlanError(w, err)
		return
	}
	writeJSON(w, plan)
}

func (s *Server) trafficApply(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.trafficAdminRouterGate(w, r)
	if sess == nil {
		return
	}
	remove := r.URL.Query().Get("remove") == "1" || s.sensorFeeds(rid)
	sn, drop, ok := s.ipsSession(r.Context(), rid)
	if !ok {
		writeJSONErr(w, http.StatusBadGateway, "the router is not reachable")
		return
	}
	defer drop()
	plan, err := s.trafficRouterPlan(sn, rid, remove)
	if err != nil {
		s.trafficPlanError(w, err)
		return
	}
	results := []IPSStepResult{}
	failed := 0
	for _, st := range plan.Steps {
		cmd := st.Cmd()
		cmd.Timeout = ipsCmdTimeout
		res := IPSStepResult{Step: st}
		if _, err := sn.Exec(cmd); err != nil {
			res.Error = safe.Message(errMessage(err))
			failed++
		}
		results = append(results, res)
		if failed > 0 {
			break
		}
	}
	row := s.trafficRouterRow(rid)
	row.AppliedAt = nowMillis()
	switch {
	case failed > 0:
		row.Result = "failed"
	case remove:
		row.Enabled, row.Result = false, "removed"
	default:
		row.Enabled, row.Result = true, "applied"
	}
	if err := s.auditDB.SaveTrafficRouter(row); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "the router could not be saved")
		return
	}
	s.traffic.sync()
	action := "traffic.apply"
	if remove {
		action = "traffic.remove"
	}
	ev := audit.Event{Action: action, RouterID: rid, TargetType: "trafficRouter", TargetID: rid,
		Note: strconv.Itoa(len(results)) + " steps, " + strconv.Itoa(failed) + " failed"}
	if failed > 0 {
		ev.Outcome = "failure"
	}
	s.httpRecorder(r, sess).Record(ev)
	writeJSON(w, map[string]any{"ok": failed == 0, "steps": results, "warnings": plan.Warnings})
}
