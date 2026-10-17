package server

// CAP versions (Settings -> Features): the CAPsMAN page compares each CAP's
// RouterOS version with the manager's and offers Upgrade on the ones behind.
//
//	GET  /api/capsman/version?routerId=   the manager's own version
//	POST /api/capsman/upgrade             one CAP, by identity
//
// ── BY IDENTITY, ASKED AT THE CLICK ─────────────────────────────────────────
//
// A legacy `/caps-man` CAP reaches the page with no `.id`, and a modern one's
// id is whatever it was when the page last read. The router is asked for the id
// of the CAP with that identity when the button is pressed, in the tree the
// page says it is in, and `upgrade` is sent to that id. The manual names
// `upgrade` under both trees (cli-reference/interface/wifi/capsman/remote-cap
// and caps-man/remote-cap) and gives it no arguments beyond the row; the CAP
// fetches its packages from the manager, as WinBox's Upgrade button does.

import (
	"encoding/json"
	"net/http"
	"strings"

	"mikrodash/internal/audit"
	"mikrodash/internal/routeros"
	"mikrodash/internal/safe"
	"mikrodash/internal/store"
	"mikrodash/internal/topology"
)

func (s *Server) registerCapVersions(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/capsman/version", s.capManagerVersion)
	mux.HandleFunc("POST /api/capsman/upgrade", s.capUpgrade)
}

// capsGate: the feature, the router, the CAPsMAN page.
func (s *Server) capsGate(w http.ResponseWriter, r *http.Request, routerID, access string) *Session {
	sess := s.layoutSession(w, r)
	if sess == nil || !s.featureGate(w, store.FeatureCapVersions) {
		return nil
	}
	if !topology.IsValidRouterID(routerID) {
		writeJSON400OK(w)
		return nil
	}
	if !permitted(s.rbac.CanPage(s.userIDFor(sess.Username), "capsman", access, routerID)) {
		writeJSONErr(w, http.StatusForbidden, "Not permitted")
		return nil
	}
	return sess
}

// bareVersion is "7.24.2" out of "7.24.2 (stable)".
func bareVersion(v string) string {
	if i := strings.Index(v, " "); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

func (s *Server) capManagerVersion(w http.ResponseWriter, r *http.Request) {
	rid := r.URL.Query().Get("routerId")
	if s.capsGate(w, r, rid, "read") == nil {
		return
	}
	sn := s.sessions.Live()[rid]
	if sn == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "the router is not connected")
		return
	}
	v := ""
	if p := sn.SystemOrPrimed(); p != nil {
		v = bareVersion(p.Version)
	}
	writeJSON(w, map[string]any{"version": v})
}

func (s *Server) capUpgrade(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RouterID string `json:"routerId"`
		Identity string `json:"identity"`
		Legacy   bool   `json:"legacy"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeJSON400OK(w)
		return
	}
	sess := s.capsGate(w, r, in.RouterID, "write")
	if sess == nil {
		return
	}
	if in.Identity == "" || len(in.Identity) > 128 || strings.ContainsAny(in.Identity, "\x00\n") {
		writeJSONErr(w, http.StatusBadRequest, "a CAP's identity")
		return
	}
	if s.auditDB == nil {
		writeJSONErr(w, http.StatusForbidden, "Router changes are unavailable: the audit database is not open")
		return
	}
	sn, drop, ok := s.fleetSession(r.Context(), in.RouterID, "cap-upgrade")
	if !ok {
		writeJSONErr(w, http.StatusServiceUnavailable, "the router is not connected")
		return
	}
	defer drop()
	if s.writeLimit != nil {
		if ok, _, _ := s.writeLimit.take(writeLimitKey(sess.Username, in.RouterID)); !ok {
			writeJSONErr(w, http.StatusTooManyRequests, safe.Message(errWriteRateLimited.Error()))
			return
		}
	}
	menu := "/interface/wifi/capsman/remote-cap"
	if in.Legacy {
		menu = "/caps-man/remote-cap"
	}
	rec := s.httpRecorder(r, sess)
	ev := audit.Event{Action: "capsman.upgrade", TargetType: "cap", RouterID: in.RouterID, TargetName: in.Identity}
	var message string
	werr := sn.InWriteQueue(func() error {
		rows, err := sn.Exec(routeros.Cmd{Path: menu + "/print",
			Args: []string{"=.proplist=.id,identity", "?identity=" + in.Identity}})
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0][".id"] == "" {
			message = "the manager has no CAP called " + in.Identity + " now"
			return nil
		}
		ev.TargetID = rows[0][".id"]
		_, err = sn.Exec(routeros.Cmd{Path: menu + "/upgrade", Args: []string{"=.id=" + rows[0][".id"]}})
		return err
	})
	switch {
	case werr != nil:
		ev.Note = safe.Message(werr.Error())
		rec.Failed(ev)
		writeJSON(w, map[string]any{"ok": false, "message": safe.Message(werr.Error())})
	case message != "":
		writeJSON(w, map[string]any{"ok": false, "message": message})
	default:
		ev.Note = "asked the CAP to upgrade from the manager"
		rec.Record(ev)
		writeJSON(w, map[string]any{"ok": true})
	}
}
