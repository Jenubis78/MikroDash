package server

// The IPS page's HTTP API. The engine is ips.go; the decisions are internal/ips.
//
//	GET    /api/ips/state?router=        the reader, its flows, the rules, the decisions
//	GET    /api/ips/listed?router=       what the two lists hold on the router now
//	POST   /api/ips/rules                create or change a rule
//	DELETE /api/ips/rules?id=            forget a rule
//	POST   /api/ips/rules/order          put the rules in this order
//	POST   /api/ips/sensor?router=       configure the router's sensor
//	DELETE /api/ips/sensor?router=       forget it
//	GET    /api/ips/script?router=       the RouterOS commands that create its container
//	GET    /api/ips/networks?router=     the router's networks the sensor can join
//	GET    /api/ips/plan?router=         what the router needs, read-only
//	POST   /api/ips/apply?router=        do it (`remove=1`: take everything off)
//	POST   /api/ips/unlist?router=       take one address off a list
//
// ── WHO MAY DO WHAT ─────────────────────────────────────────────────────────
//
// Reading follows the page grant on the router: `ips` read. Everything that
// changes what the IPS does is for administrators, as the domain lists are: a
// rule writes to every router that has a sensor, on its own, with nobody
// watching, so it is not a per-router grant to hand out. Every change and every
// router write is audited.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"mikrodash/internal/audit"
	"mikrodash/internal/db"
	"mikrodash/internal/ips"
	"mikrodash/internal/routeros"
	"mikrodash/internal/safe"
	"mikrodash/internal/session"
	"mikrodash/internal/topology"
)

const ipsPage = "ips"

func (s *Server) registerIPS(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/ips/state", s.ipsState)
	mux.HandleFunc("GET /api/ips/listed", s.ipsListed)
	mux.HandleFunc("POST /api/ips/rules", s.ipsRuleSave)
	mux.HandleFunc("DELETE /api/ips/rules", s.ipsRuleDelete)
	mux.HandleFunc("POST /api/ips/rules/order", s.ipsRuleOrder)
	mux.HandleFunc("POST /api/ips/sensor", s.ipsSensorSave)
	mux.HandleFunc("DELETE /api/ips/sensor", s.ipsSensorDelete)
	mux.HandleFunc("GET /api/ips/script", s.ipsScript)
	mux.HandleFunc("GET /api/ips/networks", s.ipsNetworksGet)
	mux.HandleFunc("GET /api/ips/plan", s.ipsPlan)
	mux.HandleFunc("POST /api/ips/apply", s.ipsApply)
	mux.HandleFunc("POST /api/ips/unlist", s.ipsUnlist)
}

// ipsReadGate: signed in, a valid router, the page's read grant on it.
func (s *Server) ipsReadGate(w http.ResponseWriter, r *http.Request) (*Session, string) {
	sess := s.layoutSession(w, r)
	if sess == nil {
		return nil, ""
	}
	rid := r.URL.Query().Get("router")
	if !topology.IsValidRouterID(rid) || !permitted(s.rbac.CanPage(s.userIDFor(sess.Username), ipsPage, "read", rid)) {
		writeJSONErr(w, http.StatusForbidden, "no access to the IPS on this router")
		return nil, ""
	}
	if s.auditDB == nil || s.ips == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "the database is not open")
		return nil, ""
	}
	return sess, rid
}

// ipsAdminGate: signed in, an administrator, the database.
func (s *Server) ipsAdminGate(w http.ResponseWriter, r *http.Request) *Session {
	sess := s.layoutSession(w, r)
	if sess == nil {
		return nil
	}
	if !s.isGlobalAdmin(sess) {
		writeJSONErr(w, http.StatusForbidden, "the IPS is configured by administrators")
		return nil
	}
	if s.auditDB == nil || s.ips == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "the database is not open")
		return nil
	}
	return sess
}

// ipsAdminRouterGate is ipsAdminGate for a request naming a router.
func (s *Server) ipsAdminRouterGate(w http.ResponseWriter, r *http.Request) (*Session, string) {
	sess := s.ipsAdminGate(w, r)
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

func (s *Server) ipsSensorOf(rid string) (db.IPSSensor, bool) {
	all, err := s.auditDB.IPSSensors()
	if err != nil {
		return db.IPSSensor{}, false
	}
	for _, sn := range all {
		if sn.RouterID == rid {
			return sn, true
		}
	}
	return db.IPSSensor{}, false
}

// IPSStatePayload is the page's whole view of one router.
type IPSStatePayload struct {
	Configured bool              `json:"configured"`
	Sensor     *db.IPSSensor     `json:"sensor"`
	Status     IPSStatus         `json:"status"`
	Flows      []IPSFlowView     `json:"flows"`
	Apps       []IPSAppCount     `json:"apps"`
	Events     []db.IPSEvent     `json:"events"`
	Rules      []ips.Rule        `json:"rules"`
	Admin      bool              `json:"admin"`
	Actions    []string          `json:"actions"`
	Lists      map[string]string `json:"lists"`
	Defaults   map[string]any    `json:"defaults"`
}

func (s *Server) ipsState(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.ipsReadGate(w, r)
	if sess == nil {
		return
	}
	p := IPSStatePayload{Status: IPSStatus{State: "off"}, Flows: []IPSFlowView{}, Apps: []IPSAppCount{},
		Rules: s.ips.currentRules(), Admin: s.isGlobalAdmin(sess), Actions: ips.Actions,
		Lists:    map[string]string{"block": ips.BlockList, "quarantine": ips.QuarantineList},
		Defaults: map[string]any{"sniffBytes": ips.DefaultSniffBytes, "image": ips.DefaultImage, "timeoutMin": ips.DefaultTimeout}}
	if p.Rules == nil {
		p.Rules = []ips.Rule{}
	}
	if sn, ok := s.ipsSensorOf(rid); ok {
		sn.Token = ""
		p.Configured, p.Sensor = true, &sn
	}
	if rd := s.ips.reader(rid); rd != nil {
		p.Status, p.Flows, p.Apps = rd.snapshot()
	}
	ev, err := s.auditDB.IPSEvents(rid, 200)
	if err != nil {
		ev = []db.IPSEvent{}
	}
	p.Events = ev
	writeJSON(w, p)
}

// ipsSession waits for the router's connection, for a request that reads or
// writes it now.
func (s *Server) ipsSession(ctx context.Context, rid string) (*session.Session, func(), bool) {
	ctx, cancel := context.WithTimeout(ctx, fleetDeadline)
	sn, drop, ok := s.fleetSession(ctx, rid, "ips")
	return sn, func() { drop(); cancel() }, ok
}

// IPSListed is one entry on one of the IPS's lists.
type IPSListed struct {
	ID      string `json:"id"`
	List    string `json:"list"`
	Address string `json:"address"`
	Timeout string `json:"timeout"`
	Comment string `json:"comment"`
}

func (s *Server) ipsListed(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.ipsReadGate(w, r)
	if sess == nil {
		return
	}
	sn, drop, ok := s.ipsSession(r.Context(), rid)
	if !ok {
		writeJSONErr(w, http.StatusBadGateway, "the router is not reachable")
		return
	}
	defer drop()
	out := []IPSListed{}
	for _, list := range []string{ips.BlockList, ips.QuarantineList} {
		rows, err := sn.Exec(routeros.Cmd{Path: "/ip/firewall/address-list/print",
			Args: []string{"=.proplist=.id,list,address,timeout,comment", "?list=" + list}, Timeout: ipsCmdTimeout})
		if err != nil {
			writeJSONErr(w, http.StatusBadGateway, "the address lists could not be read")
			return
		}
		for _, row := range rows {
			out = append(out, IPSListed{ID: row[".id"], List: row["list"], Address: row["address"],
				Timeout: row["timeout"], Comment: row["comment"]})
		}
	}
	writeJSON(w, map[string]any{"entries": out})
}

func (s *Server) ipsRuleSave(w http.ResponseWriter, r *http.Request) {
	sess := s.ipsAdminGate(w, r)
	if sess == nil {
		return
	}
	var rule ips.Rule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&rule); err != nil {
		writeJSON400OK(w)
		return
	}
	if err := rule.Validate(); err != nil {
		writeJSONErr(w, http.StatusBadRequest, safe.Message(err.Error()))
		return
	}
	id, err := s.auditDB.SaveIPSRule(rule)
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, "the rule could not be saved")
		return
	}
	s.ips.reloadRules()
	s.httpRecorder(r, sess).Record(audit.Event{Action: "ips.rule.save", TargetType: "ipsRule",
		TargetID: strconv.FormatInt(id, 10), TargetName: rule.Name, Note: rule.Action})
	writeJSON(w, map[string]any{"ok": true, "id": id})
}

func (s *Server) ipsRuleDelete(w http.ResponseWriter, r *http.Request) {
	sess := s.ipsAdminGate(w, r)
	if sess == nil {
		return
	}
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err := s.auditDB.DeleteIPSRule(id); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "the rule could not be removed")
		return
	}
	s.ips.reloadRules()
	s.httpRecorder(r, sess).Record(audit.Event{Action: "ips.rule.delete", TargetType: "ipsRule",
		TargetID: strconv.FormatInt(id, 10)})
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) ipsRuleOrder(w http.ResponseWriter, r *http.Request) {
	sess := s.ipsAdminGate(w, r)
	if sess == nil {
		return
	}
	var body struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON400OK(w)
		return
	}
	if err := s.auditDB.OrderIPSRules(body.IDs); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "the rules could not be reordered")
		return
	}
	s.ips.reloadRules()
	s.httpRecorder(r, sess).Record(audit.Event{Action: "ips.rule.order", TargetType: "ipsRule"})
	writeJSON(w, map[string]any{"ok": true})
}

// newIPSToken is 32 hex characters: what the sensor must be sent to be read.
func newIPSToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) ipsSensorSave(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.ipsAdminRouterGate(w, r)
	if sess == nil {
		return
	}
	var body struct {
		Address    string   `json:"address"`
		Enforce    bool     `json:"enforce"`
		SniffBytes int      `json:"sniffBytes"`
		Protected  []string `json:"protected"`
		Disk       string   `json:"disk"`
		Image      string   `json:"image"`
		Network    string   `json:"network"`
		DHCP       bool     `json:"dhcp"`
		NewToken   bool     `json:"newToken"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON400OK(w)
		return
	}
	known := false
	if all, _ := s.store.Routers(); all != nil {
		for _, rt := range all {
			known = known || rt.ID == rid
		}
	}
	if !known {
		writeJSONErr(w, http.StatusBadRequest, "no such router")
		return
	}
	// BY DHCP, OR AN ADDRESS. A DHCP sensor has no address to store: the
	// network it joins is what is chosen, and its lease is read off its veth.
	body.Network = strings.TrimSpace(body.Network)
	if len(body.Network) > 64 || strings.ContainsAny(body.Network, " \t\"'=\\;[]$") {
		writeJSONErr(w, http.StatusBadRequest, "a network is a router interface name")
		return
	}
	address := ""
	if body.DHCP {
		if body.Network == "" {
			writeJSONErr(w, http.StatusBadRequest, "a sensor by DHCP needs the network it joins")
			return
		}
	} else {
		addr, ok := validSensorAddress(body.Address)
		if !ok {
			writeJSONErr(w, http.StatusBadRequest, "the sensor's address must be one IPv4 address")
			return
		}
		address = addr.String()
	}
	if body.SniffBytes == 0 {
		body.SniffBytes = ips.DefaultSniffBytes
	}
	if body.SniffBytes < ips.MinSniffBytes || body.SniffBytes > ips.MaxSniffBytes {
		writeJSONErr(w, http.StatusBadRequest, "the bytes copied of each connection must be 2000 to 1000000")
		return
	}
	protected := []string{}
	for _, p := range body.Protected {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := netip.ParsePrefix(p); err != nil {
			if _, err := netip.ParseAddr(p); err != nil {
				writeJSONErr(w, http.StatusBadRequest, p+" is not an address or a prefix")
				return
			}
		}
		protected = append(protected, p)
	}
	body.Disk, body.Image = strings.TrimSpace(body.Disk), strings.TrimSpace(body.Image)
	for _, v := range []string{body.Disk, body.Image} {
		if len(v) > 200 || strings.ContainsAny(v, " \t\"'=\\;[]$") {
			writeJSONErr(w, http.StatusBadRequest, "a disk and an image are single words")
			return
		}
	}
	was, existed := s.ipsSensorOf(rid)
	sealed := was.Token
	if !existed || body.NewToken || sealed == "" {
		tok, err := newIPSToken()
		if err == nil {
			sealed, err = s.sealCredSecret(tok)
		}
		if err != nil {
			writeJSONErr(w, http.StatusInternalServerError, "a token could not be made")
			return
		}
	}
	sn := db.IPSSensor{RouterID: rid, Address: address, Token: sealed, Enforce: body.Enforce,
		SniffBytes: body.SniffBytes, Protected: protected, Disk: body.Disk, Image: body.Image,
		Network: body.Network, DHCP: body.DHCP}
	if err := s.auditDB.SaveIPSSensor(sn); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "the sensor could not be saved")
		return
	}
	s.ips.sync()
	note := "monitor"
	if body.Enforce {
		note = "enforce"
	}
	s.httpRecorder(r, sess).Record(audit.Event{Action: "ips.sensor.save", RouterID: rid, TargetType: "ipsSensor",
		TargetID: rid, TargetName: firstNonEmpty(address, "DHCP on "+body.Network), Note: note})
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) ipsSensorDelete(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.ipsAdminRouterGate(w, r)
	if sess == nil {
		return
	}
	if err := s.auditDB.DeleteIPSSensor(rid); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "the sensor could not be removed")
		return
	}
	s.ips.sync()
	s.httpRecorder(r, sess).Record(audit.Event{Action: "ips.sensor.delete", RouterID: rid, TargetType: "ipsSensor",
		TargetID: rid})
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) ipsScript(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.ipsAdminRouterGate(w, r)
	if sess == nil {
		return
	}
	sn, ok := s.ipsSensorOf(rid)
	if !ok {
		writeJSONErr(w, http.StatusNotFound, "configure the sensor first")
		return
	}
	addr, _ := validSensorAddress(sn.Address)
	// ON ONE OF THE ROUTER'S NETWORKS, OR ON A /30 OF ITS OWN. The router is
	// read to find out which: the network chosen, or the one that holds the
	// address, is joined as a port of its bridge; any other address is the
	// second of a new /30.
	rs, drop, ok := s.ipsSession(r.Context(), rid)
	if !ok {
		writeJSONErr(w, http.StatusBadGateway, "the router is not reachable")
		return
	}
	defer drop()
	lan, err := ips.FindLAN(addr, sn.Network, ipsNetworks(rs))
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, safe.Message(err.Error()))
		return
	}
	if b := addr.As4(); lan == nil && b[3]%4 != 2 {
		writeJSONErr(w, http.StatusBadRequest,
			"the sensor is in none of the router's networks, so it gets a /30 of its own as its second address "+
				"(x.x.x.2, .6, .10, ...); choose one, or a network in Setup")
		return
	}
	tok := s.openCredSecret(sn.Token)
	if tok == "" {
		writeJSONErr(w, http.StatusInternalServerError, "the token could not be read")
		return
	}
	s.httpRecorder(r, sess).Record(audit.Event{Action: "ips.script", RouterID: rid, TargetType: "ipsSensor",
		TargetID: rid, Note: "the container script, with its token, was shown"})
	writeJSON(w, map[string]any{"script": ips.ContainerScript(ips.ScriptParams{Token: tok, Sensor: addr,
		LAN: lan, DHCP: sn.DHCP, Disk: sn.Disk, Image: sn.Image})})
}

// ipsRouterPlan reads what the plan needs and plans. With remove, the plan
// takes everything off, whatever the sensor is.
func (s *Server) ipsRouterPlan(sn *session.Session, rid string, remove bool) (ips.Plan, error) {
	rows := map[string][]routeros.Reply{}
	for _, menu := range []string{"/ip/firewall/mangle", "/ip/firewall/raw"} {
		got, err := sn.Exec(routeros.Cmd{Path: menu + "/print", Timeout: ipsCmdTimeout})
		if err != nil {
			return ips.Plan{}, err
		}
		rows[menu] = got
	}
	filter, _ := sn.Exec(routeros.Cmd{Path: "/ip/firewall/filter/print",
		Args: []string{"=.proplist=.id,action,disabled,connection-bytes"}, Timeout: ipsCmdTimeout})
	var addr netip.Addr
	bytes := ips.DefaultSniffBytes
	if cfg, ok := s.ipsSensorOf(rid); ok && !remove {
		addr, _ = validSensorAddress(cfg.Address)
		bytes = cfg.SniffBytes
		if cfg.DHCP {
			// The mangle rule copies to the lease the sensor holds NOW.
			veth, _ := sn.Exec(routeros.Cmd{Path: "/interface/veth/print",
				Args: []string{"=.proplist=dhcp-address", "?name=" + ips.Veth}, Timeout: ipsCmdTimeout})
			if len(veth) > 0 {
				addr = ips.LeasedAddress(veth[0])
			}
			if !addr.IsValid() {
				return ips.Plan{}, errIPSNoLease
			}
		}
	}
	return ips.PlanRouter(addr, bytes, rows, filter), nil
}

// errIPSNoLease is a plan for a DHCP sensor that has no lease to copy to.
var errIPSNoLease = errors.New("the sensor has no DHCP lease yet: start its container, then preview again")

// ipsNetworks is the router's networks, as the Setup tab offers them.
func ipsNetworks(rs *session.Session) []ips.Network {
	read := func(path, props string) []routeros.Reply {
		rows, _ := rs.Exec(routeros.Cmd{Path: path, Args: []string{"=.proplist=" + props}, Timeout: ipsCmdTimeout})
		return rows
	}
	return ips.Networks(read("/ip/address/print", "address,interface,disabled"),
		read("/interface/bridge/print", "name,vlan-filtering"), read("/interface/vlan/print", "name,interface,vlan-id"))
}

func (s *Server) ipsNetworksGet(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.ipsAdminRouterGate(w, r)
	if sess == nil {
		return
	}
	rs, drop, ok := s.ipsSession(r.Context(), rid)
	if !ok {
		writeJSONErr(w, http.StatusBadGateway, "the router is not reachable")
		return
	}
	defer drop()
	writeJSON(w, map[string]any{"networks": ipsNetworks(rs)})
}

func (s *Server) ipsPlan(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.ipsAdminRouterGate(w, r)
	if sess == nil {
		return
	}
	sn, drop, ok := s.ipsSession(r.Context(), rid)
	if !ok {
		writeJSONErr(w, http.StatusBadGateway, "the router is not reachable")
		return
	}
	defer drop()
	plan, err := s.ipsRouterPlan(sn, rid, r.URL.Query().Get("remove") == "1")
	if err != nil {
		if errors.Is(err, errIPSNoLease) {
			writeJSONErr(w, http.StatusConflict, safe.Message(errIPSNoLease.Error()))
			return
		}
		writeJSONErr(w, http.StatusBadGateway, "the firewall could not be read")
		return
	}
	writeJSON(w, plan)
}

// IPSStepResult is one step of an apply, and how it went.
type IPSStepResult struct {
	ips.Step
	Error string `json:"error"`
}

func (s *Server) ipsApply(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.ipsAdminRouterGate(w, r)
	if sess == nil {
		return
	}
	remove := r.URL.Query().Get("remove") == "1"
	if _, ok := s.ipsSensorOf(rid); !ok && !remove {
		writeJSONErr(w, http.StatusBadRequest, "configure the sensor first")
		return
	}
	sn, drop, ok := s.ipsSession(r.Context(), rid)
	if !ok {
		writeJSONErr(w, http.StatusBadGateway, "the router is not reachable")
		return
	}
	defer drop()
	plan, err := s.ipsRouterPlan(sn, rid, remove)
	if err != nil {
		if errors.Is(err, errIPSNoLease) {
			writeJSONErr(w, http.StatusConflict, safe.Message(errIPSNoLease.Error()))
			return
		}
		writeJSONErr(w, http.StatusBadGateway, "the firewall could not be read")
		return
	}
	// Each step is its own write, in order, and the first failure stops the
	// rest: a half-applied plan is re-planned from what the router then holds.
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
	cleared := 0
	if remove && failed == 0 {
		cleared, failed = s.ipsClearLists(sn)
	}
	action := "ips.apply"
	if remove {
		action = "ips.remove"
	}
	ev := audit.Event{Action: action, RouterID: rid, TargetType: "ipsSensor", TargetID: rid,
		Note: strconv.Itoa(len(results)) + " steps, " + strconv.Itoa(failed) + " failed"}
	if failed > 0 {
		ev.Outcome = "failure"
	}
	s.httpRecorder(r, sess).Record(ev)
	writeJSON(w, map[string]any{"ok": failed == 0, "steps": results, "warnings": plan.Warnings, "cleared": cleared})
}

// ipsClearLists removes every entry on the IPS's two lists.
func (s *Server) ipsClearLists(sn *session.Session) (removed, failed int) {
	for _, list := range []string{ips.BlockList, ips.QuarantineList} {
		rows, err := sn.Exec(routeros.Cmd{Path: "/ip/firewall/address-list/print",
			Args: []string{"=.proplist=.id", "?list=" + list}, Timeout: ipsCmdTimeout})
		if err != nil {
			failed++
			continue
		}
		for _, row := range rows {
			if _, err := sn.Exec(routeros.Cmd{Path: "/ip/firewall/address-list/remove",
				Args: []string{"=.id=" + row[".id"]}, Timeout: ipsCmdTimeout}); err != nil {
				failed++
				continue
			}
			removed++
		}
	}
	return removed, failed
}

func (s *Server) ipsUnlist(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.ipsAdminRouterGate(w, r)
	if sess == nil {
		return
	}
	var body struct {
		List    string `json:"list"`
		Address string `json:"address"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeJSON400OK(w)
		return
	}
	if body.List != ips.BlockList && body.List != ips.QuarantineList {
		writeJSONErr(w, http.StatusBadRequest, "only the IPS's own lists")
		return
	}
	if _, err := netip.ParseAddr(body.Address); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "one address")
		return
	}
	sn, drop, ok := s.ipsSession(r.Context(), rid)
	if !ok {
		writeJSONErr(w, http.StatusBadGateway, "the router is not reachable")
		return
	}
	defer drop()
	rows, err := sn.Exec(routeros.Cmd{Path: "/ip/firewall/address-list/print",
		Args: []string{"=.proplist=.id", "?list=" + body.List, "?address=" + body.Address}, Timeout: ipsCmdTimeout})
	if err != nil {
		writeJSONErr(w, http.StatusBadGateway, "the address list could not be read")
		return
	}
	for _, row := range rows {
		if _, err := sn.Exec(routeros.Cmd{Path: "/ip/firewall/address-list/remove",
			Args: []string{"=.id=" + row[".id"]}, Timeout: ipsCmdTimeout}); err != nil {
			writeJSONErr(w, http.StatusBadGateway, "the entry could not be removed")
			return
		}
	}
	if rd := s.ips.reader(rid); rd != nil {
		// Forget it was listed, or the next flow to it would be skipped as
		// already listed until the old timeout.
		rd.mu.Lock()
		delete(rd.listed, body.List+"|"+body.Address)
		rd.mu.Unlock()
	}
	s.httpRecorder(r, sess).Record(audit.Event{Action: "ips.unlist", RouterID: rid, TargetType: "ipsList",
		TargetID: body.List, TargetName: body.Address})
	writeJSON(w, map[string]any{"ok": true, "removed": len(rows)})
}
