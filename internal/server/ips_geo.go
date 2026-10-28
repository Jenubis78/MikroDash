package server

// Geofencing on the router: the IPS page's Geo tab. The planning is pure
// (internal/ips/geo.go); this is the job that writes it.
//
// ── A JOB, NOT A REQUEST ────────────────────────────────────────────────────
//
// A country is hundreds to thousands of prefixes and each is one API write, so
// an apply takes from seconds to minutes. It runs on its own, one per router,
// and the page polls its progress. The engine's context stops it with the
// server; a job stopped half way leaves a list the next apply finishes, because
// every apply writes the difference between the list and the choice.
//
// ── THE LIST FIRST, THE RULES LAST; OFF IN THE OTHER ORDER ──────────────────
//
// The drop rules go in only once the list holds every country, and come out
// before the list is emptied, so no moment drops part of a choice.
//
// ── REFUSED, RATHER THAN CUTTING THE OPERATOR OFF ───────────────────────────
//
// An inbound drop of new connections from a country where the router's own
// public address is, or where someone is logged in to it from - MikroDash among
// them - would cut that access the moment the rules land. Such a choice is
// refused, naming the addresses, as the write guard refuses to list them.

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"mikrodash/internal/audit"
	"mikrodash/internal/db"
	"mikrodash/internal/geo"
	"mikrodash/internal/ips"
	"mikrodash/internal/routeros"
	"mikrodash/internal/safe"
	"mikrodash/internal/session"
)

// ipsGeoListTimeout is the read of a whole country list, which can be 100000 rows.
const ipsGeoListTimeout = 2 * time.Minute

// ipsGeoMaxFailures stops a job that keeps failing, rather than repeating one
// error for every prefix.
const ipsGeoMaxFailures = 10

// IPSGeoJob is a geofencing apply: running, or how the last one ended.
type IPSGeoJob struct {
	Running bool   `json:"running"`
	Remove  bool   `json:"remove"`
	Phase   string `json:"phase"`
	Done    int    `json:"done"`
	Total   int    `json:"total"`
	Error   string `json:"error"`
	// Conflicts is what a refused choice would have cut off.
	Conflicts []string `json:"conflicts"`
}

func (e *ipsEngine) geoJob(rid string) (IPSGeoJob, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	j, ok := e.geoJobs[rid]
	if !ok {
		return IPSGeoJob{Conflicts: []string{}}, false
	}
	c := *j
	c.Conflicts = append([]string{}, j.Conflicts...)
	return c, true
}

// startGeoJob claims the router's job; false while one is running.
func (e *ipsEngine) startGeoJob(rid string, remove bool) (*IPSGeoJob, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.geoJobs == nil {
		e.geoJobs = map[string]*IPSGeoJob{}
	}
	if j := e.geoJobs[rid]; j != nil && j.Running {
		return nil, false
	}
	j := &IPSGeoJob{Running: true, Remove: remove, Phase: "starting", Conflicts: []string{}}
	e.geoJobs[rid] = j
	return j, true
}

// geoUpdate changes a job under the engine's lock.
func (e *ipsEngine) geoUpdate(j *IPSGeoJob, f func(*IPSGeoJob)) {
	e.mu.Lock()
	f(j)
	e.mu.Unlock()
}

// IPSGeoPayload is the Geo tab.
type IPSGeoPayload struct {
	Geo db.IPSGeo `json:"geo"`
	Job IPSGeoJob `json:"job"`
	// Available is whether this install can turn countries into networks.
	Available  bool   `json:"available"`
	List       string `json:"list"`
	MaxEntries int    `json:"maxEntries"`
}

func (s *Server) ipsGeoGet(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.ipsReadGate(w, r)
	if sess == nil {
		return
	}
	g, err := s.auditDB.IPSGeoOf(rid)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "the geofencing could not be read")
		return
	}
	job, _ := s.ips.geoJob(rid)
	gdb, ok := geo.Current()
	_, werr := gdb.Countries()
	writeJSON(w, IPSGeoPayload{Geo: g, Job: job, Available: ok && werr == nil, List: ips.GeoList,
		MaxEntries: ips.GeoMaxEntries})
}

func (s *Server) ipsGeoSave(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.ipsAdminRouterGate(w, r)
	if sess == nil {
		return
	}
	var body struct {
		Countries []string `json:"countries"`
		Direction string   `json:"direction"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeJSON400OK(w)
		return
	}
	countries, err := ips.GeoValidate(body.Countries, body.Direction)
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, safe.Message(err.Error()))
		return
	}
	if err := s.auditDB.SaveIPSGeo(rid, countries, body.Direction); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "the geofencing could not be saved")
		return
	}
	s.httpRecorder(r, sess).Record(audit.Event{Action: "ips.geo.save", RouterID: rid, TargetType: "ipsGeo",
		TargetID: rid, Note: body.Direction + ": " + strings.Join(countries, ",")})
	writeJSON(w, map[string]any{"ok": true, "countries": countries})
}

func (s *Server) ipsGeoApply(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.ipsAdminRouterGate(w, r)
	if sess == nil {
		return
	}
	g, err := s.auditDB.IPSGeoOf(rid)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "the geofencing could not be read")
		return
	}
	// No countries is a removal whatever was asked: an empty list needs no rules.
	remove := r.URL.Query().Get("remove") == "1" || len(g.Countries) == 0
	var want map[string][]netip.Prefix
	if !remove {
		gdb, ok := geo.Current()
		if !ok {
			writeJSONErr(w, http.StatusConflict, safe.Message(geo.ErrNoNetworks.Error()))
			return
		}
		if want, err = gdb.CountryNetworks(g.Countries); err != nil {
			writeJSONErr(w, http.StatusConflict, safe.Message(geo.ErrNoNetworks.Error()))
			return
		}
		n := 0
		for _, ps := range want {
			n += len(ps)
		}
		if n > ips.GeoMaxEntries {
			writeJSONErr(w, http.StatusBadRequest, safe.Message("these countries are "+strconv.Itoa(n)+
				" networks, more than the "+strconv.Itoa(ips.GeoMaxEntries)+" one router's list may hold"))
			return
		}
	}
	job, ok := s.ips.startGeoJob(rid, remove)
	if !ok {
		writeJSONErr(w, http.StatusConflict, "an apply is already running on this router")
		return
	}
	rec := s.httpRecorder(r, sess)
	go s.ips.runGeo(rid, g, want, job, rec)
	writeJSON(w, map[string]any{"ok": true})
}

// runGeo is one apply (want != nil) or removal, start to finish.
func (e *ipsEngine) runGeo(rid string, g db.IPSGeo, want map[string][]netip.Prefix, j *IPSGeoJob, rec *audit.Recorder) {
	errText, entries := "", 0
	defer func() {
		e.geoUpdate(j, func(j *IPSGeoJob) { j.Running, j.Error = false, errText })
		result := "applied"
		action := "ips.geo.apply"
		if j.Remove {
			result, action = "removed", "ips.geo.remove"
		}
		ev := audit.Event{Action: action, RouterID: rid, TargetType: "ipsGeo", TargetID: rid,
			Note: g.Direction + ": " + strings.Join(g.Countries, ",") + ", " + strconv.Itoa(entries) + " entries"}
		if errText != "" {
			result, ev.Outcome = "failed: "+errText, "failure"
		}
		rec.Record(ev)
		if err := e.s.auditDB.RecordIPSGeo(rid, time.Now().UnixMilli(), result, entries); err != nil {
			log.Printf("[ips] %s: recording the geofencing: %v", rid, err)
		}
	}()
	wait, cancel := context.WithTimeout(e.ctx, fleetDeadline)
	sn, drop, ok := e.s.fleetSession(wait, rid, "ips-geo")
	cancel()
	if !ok {
		errText = "the router is not reachable"
		return
	}
	defer drop()
	errText, entries = e.geoWrite(sn, g, want, j)
}

// geoWrite brings the router in line: rules off, list, rules on.
func (e *ipsEngine) geoWrite(sn *session.Session, g db.IPSGeo, want map[string][]netip.Prefix, j *IPSGeoJob) (string, int) {
	phase := func(p string, total int) {
		e.geoUpdate(j, func(j *IPSGeoJob) { j.Phase, j.Done, j.Total = p, 0, total })
	}
	rules := func(direction string) string {
		filter, err := sn.Exec(routeros.Cmd{Path: "/ip/firewall/filter/print", Timeout: ipsCmdTimeout})
		if err != nil {
			return "the firewall could not be read"
		}
		for _, st := range ips.GeoRulesPlan(direction, filter) {
			cmd := st.Cmd()
			cmd.Timeout = ipsCmdTimeout
			if _, err := sn.Exec(cmd); err != nil {
				return st.What + ": " + errMessage(err)
			}
		}
		return ""
	}
	if want == nil {
		phase("removing the rules", 0)
		if msg := rules(""); msg != "" {
			return msg, 0
		}
	} else {
		phase("checking what the countries hold", 0)
		if conflicts := e.geoConflicts(sn, want, g.Direction); len(conflicts) > 0 {
			e.geoUpdate(j, func(j *IPSGeoJob) { j.Conflicts = conflicts })
			return "these countries hold addresses the router is reached from", 0
		}
	}
	phase("reading the list", 0)
	have, err := sn.Exec(routeros.Cmd{Path: "/ip/firewall/address-list/print",
		Args: []string{"=.proplist=.id,address", "?list=" + ips.GeoList}, Timeout: ipsGeoListTimeout})
	if err != nil {
		return "the address list could not be read", 0
	}
	add, remove := ips.GeoEntriesPlan(want, have)
	entries := len(have) - len(remove)
	failures := 0
	write := func(cmd routeros.Cmd) bool {
		cmd.Timeout = ipsCmdTimeout
		_, err := sn.Exec(cmd)
		if err != nil {
			failures++
		}
		e.geoUpdate(j, func(j *IPSGeoJob) { j.Done++ })
		return err == nil
	}
	phase("removing entries", len(remove))
	for _, id := range remove {
		if e.ctx.Err() != nil {
			return "stopped with the server", entries
		}
		if !write(routeros.Cmd{Path: "/ip/firewall/address-list/remove", Args: []string{"=.id=" + id}}) &&
			failures >= ipsGeoMaxFailures {
			return "the router refused " + strconv.Itoa(failures) + " writes", entries
		}
	}
	phase("adding entries", len(add))
	for _, en := range add {
		if e.ctx.Err() != nil {
			return "stopped with the server", entries
		}
		if write(routeros.Cmd{Path: "/ip/firewall/address-list/add", Args: ips.GeoEntryArgs(en)}) {
			entries++
		} else if failures >= ipsGeoMaxFailures {
			return "the router refused " + strconv.Itoa(failures) + " writes", entries
		}
	}
	if failures > 0 {
		// Rules over a partial list drop part of the choice: not put in.
		return strconv.Itoa(failures) + " entries could not be written; apply again", entries
	}
	if want != nil {
		phase("adding the rules", 0)
		if msg := rules(g.Direction); msg != "" {
			return msg, entries
		}
	}
	phase("done", 0)
	return "", entries
}

// geoConflicts is the addresses the router is reached from that an inbound
// drop of these countries would cut off: its own public addresses, and every
// public address someone is logged in from now, MikroDash included. Outbound
// alone cuts none of them, so it has none.
func (e *ipsEngine) geoConflicts(sn *session.Session, want map[string][]netip.Prefix, direction string) []string {
	if direction == ips.GeoOut {
		return nil
	}
	var own []netip.Addr
	for _, read := range []struct{ path, prop string }{{"/ip/address/print", "address"}, {"/user/active/print", "address"}} {
		rows, _ := sn.Exec(routeros.Cmd{Path: read.path, Args: []string{"=.proplist=" + read.prop}, Timeout: ipsCmdTimeout})
		for _, row := range rows {
			a, err := netip.ParseAddr(strings.Split(row[read.prop], "/")[0])
			if err == nil && ips.Public(a.String()) {
				own = append(own, a.Unmap())
			}
		}
	}
	return ips.GeoConflicts(want, own)
}
