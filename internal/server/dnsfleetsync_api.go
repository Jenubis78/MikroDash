package server

// `POST /api/dns/fleet-sync`: make other routers' static DNS tables hold what a
// reference router's holds (Settings -> Features -> Fleet sync).
//
// ── THE SERVER PLANS IT ─────────────────────────────────────────────────────
//
// The request names the reference, the routers and whether extras go, nothing
// else. The plan is computed here from tables read now, so the browser cannot
// submit a job of its own through this feature, and the two rules that matter
// hold whatever the page does: a dynamic entry is never copied, changed or
// removed, and nothing is removed unless `removeExtra` says so.
//
// `dryRun` answers the counts per router and writes nothing; the page shows
// them before it asks for the real thing. Each router's changes then run as a
// bulk job (dnsbulk_api.go), paced by the user's write limit on that router.

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"mikrodash/internal/collect"
	"mikrodash/internal/resource"
	"mikrodash/internal/routeros"
	"mikrodash/internal/store"
)

func (s *Server) registerDNSFleetSync(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/dns/fleet-sync", s.dnsFleetSync)
}

// FleetSyncRouter is one target's share of a sync.
type FleetSyncRouter struct {
	RouterID string `json:"routerId"`
	Label    string `json:"label"`
	Add      int    `json:"add"`
	Change   int    `json:"change"`
	Remove   int    `json:"remove"`
	// Code is why nothing was planned or started; empty when it was.
	Code  string `json:"code"`
	JobID string `json:"jobId"`
}

// fleetSyncKey lines a record up across tables: its name or regexp and type,
// and its value too when a table holds two of that name and type.
func fleetSyncKey(tables ...[]collect.DNSStaticEntry) func(collect.DNSStaticEntry) string {
	base := func(e collect.DNSStaticEntry) string {
		return strings.ToLower(e.Name) + "\x01" + e.Regexp + "\x01" + e.Type
	}
	multi := map[string]bool{}
	for _, t := range tables {
		seen := map[string]bool{}
		for _, e := range t {
			if seen[base(e)] {
				multi[base(e)] = true
			}
			seen[base(e)] = true
		}
	}
	return func(e collect.DNSStaticEntry) string {
		if multi[base(e)] {
			return base(e) + "\x01" + e.Address
		}
		return base(e)
	}
}

// PlanFleetSync is what one router must do to hold what the reference holds,
// pure: both tables in, a job out. A record that differs is rewritten whole
// from the reference's values, the way the Edit form would save it.
func PlanFleetSync(ref, target []routeros.Reply, removeExtra bool) dnsBulkIn {
	res := resource.DNSStatic
	refRows, tgtRows := collect.ParseStaticEntries(ref), collect.ParseStaticEntries(target)
	byID := func(rows []routeros.Reply) map[string]routeros.Reply {
		m := map[string]routeros.Reply{}
		for _, r := range rows {
			m[r[".id"]] = r
		}
		return m
	}
	refRaw, tgtRaw := byID(ref), byID(target)
	values := func(raw map[string]routeros.Reply, e collect.DNSStaticEntry) map[string]any {
		v := res.RowValues(raw[e.ID])
		delete(v, "dynamic")
		return v
	}
	keyOf := fleetSyncKey(refRows, tgtRows)

	want := map[string]collect.DNSStaticEntry{}
	for _, e := range refRows {
		if !e.Dynamic {
			want[keyOf(e)] = e
		}
	}
	have := map[string]collect.DNSStaticEntry{}
	for _, e := range tgtRows {
		have[keyOf(e)] = e
	}
	var in dnsBulkIn
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := want[k]
		t, ok := have[k]
		switch {
		case !ok:
			in.Add = append(in.Add, values(refRaw, e))
		case t.Dynamic:
		case !sameValues(values(refRaw, e), values(tgtRaw, t)):
			in.Set = append(in.Set, dnsBulkSet{ID: t.ID, Values: values(refRaw, e)})
		}
	}
	if removeExtra {
		for _, t := range tgtRows {
			if _, ok := want[keyOf(t)]; !ok && !t.Dynamic {
				in.Remove = append(in.Remove, t.ID)
			}
		}
	}
	return in
}

// sameValues is whether two records are the same to a resolver. A name compares
// without case: RouterOS keeps the case it was written in and answers both.
func sameValues(a, b map[string]any) bool {
	fa, fb := flattenValues(a), flattenValues(b)
	if len(fa) != len(fb) {
		return false
	}
	for k, v := range fa {
		if k == "name" && strings.EqualFold(fb[k], v) {
			continue
		}
		if fb[k] != v {
			return false
		}
	}
	return true
}

func (s *Server) dnsFleetSync(w http.ResponseWriter, r *http.Request) {
	sess := s.layoutSession(w, r)
	if sess == nil || !s.featureGate(w, store.FeatureDNSFleetSync) {
		return
	}
	var body struct {
		RefID       string   `json:"refId"`
		RouterIDs   []string `json:"routerIds"`
		RemoveExtra bool     `json:"removeExtra"`
		DryRun      bool     `json:"dryRun"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&body); err != nil {
		writeJSON400OK(w)
		return
	}
	if s.auditDB == nil {
		writeJSONErr(w, http.StatusForbidden, "Router changes are unavailable: the audit database is not open")
		return
	}
	ref, _ := s.fleetTargets(sess, []string{body.RefID}, "dns", "read")
	if len(ref) != 1 {
		writeJSONErr(w, http.StatusForbidden, "Not permitted")
		return
	}
	var ids []string
	for _, id := range body.RouterIDs {
		if id != body.RefID {
			ids = append(ids, id)
		}
	}
	targets, _ := s.fleetTargets(sess, ids, "dns", "write")
	if len(targets) == 0 {
		writeJSONErr(w, http.StatusForbidden, "Not permitted")
		return
	}

	sn, drop, ok := s.fleetSession(r.Context(), body.RefID, dnsBulkHold)
	if !ok {
		writeJSONErr(w, http.StatusServiceUnavailable, "the reference router is not connected")
		return
	}
	refRows, err := sn.Exec(collect.DNSStaticCmd())
	drop()
	if err != nil {
		writeJSONErr(w, http.StatusBadGateway, "the reference router's table could not be read")
		return
	}

	rec := s.httpRecorder(r, sess)
	out := fleetEach(r.Context(), targets, func(ctx context.Context, t fleetTarget) FleetSyncRouter {
		res := FleetSyncRouter{RouterID: t.ID, Label: t.Label}
		if !body.DryRun && s.dnsBulk.running(t.ID) {
			res.Code = "busy"
			return res
		}
		// The first write, before the read, as startDNSBulk takes it. A dry run
		// takes one too: it reads the router's whole table, and one that costs
		// nothing could be repeated for ever.
		if s.jobLimit != nil {
			if ok, _, _ := s.jobLimit.take(writeLimitKey(sess.Username, t.ID)); !ok {
				res.Code = "rate-limited"
				return res
			}
		}
		tsn, tdrop, ok := s.fleetSession(ctx, t.ID, dnsBulkHold)
		if !ok {
			res.Code = "unreachable"
			return res
		}
		rows, rerr := tsn.Exec(collect.DNSStaticCmd())
		if rerr != nil {
			tdrop()
			res.Code = "read-failed"
			return res
		}
		in := PlanFleetSync(refRows, rows, body.RemoveExtra)
		in.RouterID, in.Label = t.ID, "fleet sync from "+ref[0].Label
		res.Add, res.Change, res.Remove = len(in.Add), len(in.Set), len(in.Remove)
		if body.DryRun || res.Add+res.Change+res.Remove == 0 {
			tdrop()
			return res
		}
		if code, _ := bulkSize(in); code != "" {
			tdrop()
			res.Code = code
			return res
		}
		steps, errs := planDNSBulk(in, rows)
		if len(errs) > 0 {
			tdrop()
			res.Code = "invalid: " + strings.Join(errs, "; ")
			return res
		}
		job, code := s.beginDNSBulk(tsn, tdrop, sess.Username, in, steps, rec, true, nil)
		if job != nil {
			res.JobID = job.ID
		}
		res.Code = code
		return res
	})
	writeJSON(w, map[string]any{"ok": true, "routers": out})
}
