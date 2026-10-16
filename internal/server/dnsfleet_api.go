package server

// `/api/dns/fleet` — the same static entries, read across several routers.
//
// ── WHY THIS IS NOT THE DNS COLLECTOR ───────────────────────────────────────
//
// A collector belongs to a session and a session belongs to one router. The
// question this answers is about SEVERAL — "is that record on both of them, and
// does it say the same thing" — which no single session can answer. So it reads
// each router directly, on demand, from a hold it takes and gives back.
//
// ON DEMAND, NOT POLLED. The comparison is something an operator asks for while
// they are looking at it; polling every router's DNS table in the background
// would be a standing cost for a page nobody is on. A hold is taken per router
// for the length of the read and dropped after — `Retain` builds the session if
// there is not one already and the grace timer takes it down again.
//
// ── THE WRITE PATH IS THE SAME ONE, MINUS THE SOCKET ────────────────────────
//
// `resSave` in resource.go is bound to the connection's ACTIVE router: its
// permission check, its audit recorder and its error channel are all `cn`. It
// cannot be pointed at a second router without being rebuilt around one, so the
// add here re-uses the parts that carry the RULES — the resource descriptor's
// `Validate` and `BuildArgs` — and states the rest explicitly: an RBAC check per
// router, a read before the write, and an audit row per router.
//
// THAT IS ONLY SAFE BECAUSE `dnsStatic` DECLARES NO GUARD. A guarded resource
// would lose its guard down this path, which is why the endpoint refuses to
// write anything else: the resource is named here, not taken from the request.

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"mikrodash/internal/audit"
	"mikrodash/internal/collect"
	"mikrodash/internal/resource"
	"mikrodash/internal/routeros"
	"mikrodash/internal/safe"
)

// dnsFleetHold is the reason this endpoint's session holds carry, so a stuck
// one can be explained by name — see session.Manager.Retain.
const dnsFleetHold = "dns-fleet"

// dnsFleetEntry is one record, with everything needed to COPY it.
//
// ── THE DISPLAY SHAPE IS NOT ENOUGH TO RECREATE A RECORD ────────────────────
//
// `collect.DNSStaticEntry` collapses nine type-specific properties into one
// `address` column, which is right for a table and lossless for nothing: an MX
// record's preference and an SRV record's port, priority and weight are not in
// it at all. Copying from that would quietly drop them.
//
// `values` is the resource descriptor's own view of the row — the same map the
// edit form is filled from — so a copy carries every field the form has.
type dnsFleetEntry struct {
	collect.DNSStaticEntry
	Values map[string]any `json:"values"`
}

type dnsFleetRouter struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	OK    bool   `json:"ok"`
	// Error is why this router contributed nothing. Present rather than dropped:
	// a router silently missing from the comparison reads as a router with no
	// records, which is the opposite of the truth.
	Error   string          `json:"error"`
	Entries []dnsFleetEntry `json:"entries"`
}

func (s *Server) registerDNSFleet(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/dns/fleet", s.dnsFleetGet)
	mux.HandleFunc("POST /api/dns/fleet-add", s.dnsFleetAdd)
}

func (s *Server) dnsFleetGet(w http.ResponseWriter, r *http.Request) {
	sess := s.layoutSession(w, r)
	if sess == nil {
		return
	}
	ids := strings.Split(r.URL.Query().Get("routers"), ",")
	targets, over := s.fleetTargets(sess, ids, "dns", "read")
	out := fleetEach(r.Context(), targets, s.dnsFleetReadOne)
	for _, t := range over {
		out = append(out, dnsFleetRouter{ID: t.ID, Label: t.Label,
			Error: "not read: too many routers in one request", Entries: []dnsFleetEntry{}})
	}
	writeJSON(w, map[string]any{"routers": out})
}

func (s *Server) dnsFleetReadOne(ctx context.Context, t fleetTarget) dnsFleetRouter {
	row := dnsFleetRouter{ID: t.ID, Label: t.Label, Entries: []dnsFleetEntry{}}
	sn, drop, ok := s.fleetSession(ctx, t.ID, dnsFleetHold)
	if !ok {
		row.Error = "unreachable"
		return row
	}
	defer drop()
	rows, err := sn.Exec(collect.DNSStaticCmd())
	if err != nil {
		row.Error = safe.Message(err.Error())
		return row
	}
	row.OK = true
	row.Entries = dnsFleetEntries(rows)
	return row
}

type dnsFleetAddResult struct {
	ID   string `json:"id"`
	OK   bool   `json:"ok"`
	Code string `json:"code"`
}

func (s *Server) dnsFleetAdd(w http.ResponseWriter, r *http.Request) {
	sess := s.layoutSession(w, r)
	if sess == nil {
		return
	}
	var body struct {
		RouterIDs []string `json:"routerIds"`
		// NOT `map[string]string`. The read projects each row through
		// `resource.RowValues`, which emits a BOOL for a checkbox field, and the
		// copy button posts that object straight back. `flattenValues` is what
		// turns it into what the validator works in — the same function the
		// socket's write path uses, so the two cannot drift.
		Values map[string]any `json:"values"`
		// ByValue is set when the comparison lines this record up by its value
		// as well, because a router holds two of its name and type (round-robin
		// A records): another value under the name is then not this record.
		ByValue bool `json:"byValue"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&body); err != nil {
		writeJSON400OK(w)
		return
	}
	// THE RESOURCE IS NAMED HERE, NOT TAKEN FROM THE REQUEST. See the header:
	// this path has no guard chain, so it may only ever write the one resource
	// that declares no guard.
	res := resource.DNSStatic
	// A DHCP server's entry is that server's to add. Copied, it would become a
	// static record that outlives the lease it was made for.
	if body.Values["dynamic"] == true {
		writeJSON(w, map[string]any{"ok": false, "code": "dynamic-entry"})
		return
	}
	validated, errs := res.Validate(flattenValues(body.Values), false)
	if len(errs) > 0 {
		writeJSON(w, map[string]any{"ok": false, "code": "invalid", "errors": errs})
		return
	}
	name := validated.Values["name"]
	if name == "" {
		name = validated.Values[res.IdentityFallback]
	}

	// A write that cannot be recorded is refused (#97), as it is on the socket.
	if s.auditDB == nil {
		writeJSONErr(w, http.StatusForbidden, "Router changes are unavailable: the audit database is not open")
		return
	}
	targets, over := s.fleetTargets(sess, body.RouterIDs, "dns", "write")
	if len(targets) == 0 {
		writeJSONErr(w, http.StatusForbidden, "Not permitted")
		return
	}

	results := fleetEach(r.Context(), targets, func(ctx context.Context, t fleetTarget) dnsFleetAddResult {
		return s.dnsFleetAddOne(ctx, r, sess, res, validated, name, body.ByValue, t.ID)
	})
	for _, t := range over {
		results = append(results, dnsFleetAddResult{ID: t.ID, Code: "not-attempted"})
	}
	writeJSON(w, map[string]any{"ok": true, "results": results})
}

// dnsFleetAddOne writes one record to one router, and records what happened.
//
// EVERY ROUTER AT ONCE, from dnsFleetAdd: the writes are independent, each runs
// in its own session's write queue, and serially a fleet of sixteen would hold
// the request for the sum of their round trips.
func (s *Server) dnsFleetAddOne(ctx context.Context, r *http.Request, sess *Session,
	res *resource.Resource, validated resource.Validated, name string, byValue bool, routerID string) dnsFleetAddResult {

	sn, drop, ok := s.fleetSession(ctx, routerID, dnsFleetHold)
	if !ok {
		return dnsFleetAddResult{ID: routerID, Code: "unreachable"}
	}
	defer drop()

	out := dnsFleetAddResult{ID: routerID}
	// THE SAME LIMIT AS A WRITE FROM THE PAGE (#97): one allowance per user per
	// router, so copying a record across the fleet counts once against each.
	if s.writeLimit != nil {
		if ok, _, _ := s.writeLimit.take(writeLimitKey(sess.Username, routerID)); !ok {
			out.Code = "rate-limited"
			return out
		}
	}
	werr := sn.InWriteQueue(func() error {
		// A REGEXP IS FILTERED ON THE ROUTER; A NAME CANNOT BE. RouterOS keeps
		// a name's case and `?name=` matches it exactly, so `MDPROBE.test` and
		// `mdprobe.test` are two entries and a copy of one beside the other
		// was a duplicate. Names are read in the columns the comparison needs
		// and compared without case (dnsAlreadyPresent).
		read := routeros.Cmd{Path: "/ip/dns/static/print", Args: []string{dnsPresenceProps}}
		if q := validated.Values["regexp"]; q != "" {
			read.Args = append(read.Args, "?regexp="+q)
		}
		rows, rerr := sn.Exec(read)
		if rerr != nil {
			out.Code = "read-failed"
			return nil
		}
		// ALREADY THERE IS NOT AN ERROR, and saying so is the point of this
		// endpoint: "synchronise" pressed twice must not produce two records, and
		// a router that already agrees is the answer the operator wanted.
		if dnsAlreadyPresent(rows, dnsRecordOf(res, validated.Values), byValue) {
			out.OK = true
			out.Code = "already-present"
			return nil
		}
		if _, aerr := sn.Exec(routeros.Cmd{
			Path: res.Menu + "/add", Args: res.BuildArgs(validated)}); aerr != nil {
			out.Code = writeFailCode(aerr)
			return nil
		}
		out.OK = true
		out.Code = "added"
		s.httpRecorder(r, sess).Record(audit.Event{
			Action: res.Key + ".create", TargetType: res.Key, TargetName: name,
			RouterID: routerID, Note: "copied from another router",
		})
		return nil
	})
	if werr != nil {
		out.OK = false
		out.Code = writeFailCode(werr)
	}
	return out
}

// dnsRecordOf is the record a set of form values describes, in the projection
// the comparison shows, so a router's rows and the record being copied are
// read the same way.
func dnsRecordOf(res *resource.Resource, values map[string]string) collect.DNSStaticEntry {
	row := routeros.Reply{}
	for _, f := range res.Fields {
		if v, ok := values[f.Name]; ok {
			row[f.ROS] = v
		}
	}
	if e := collect.ParseStaticEntries([]routeros.Reply{row}); len(e) == 1 {
		return e[0]
	}
	return collect.DNSStaticEntry{}
}

// dnsPresenceProps is what dnsAlreadyPresent reads: the keys and the value
// column, not the whole row.
const dnsPresenceProps = "=.proplist=.id,name,regexp,type,address,cname,forward-to,mx-exchange,ns,srv-target,text"

// dnsAlreadyPresent is whether a router's rows hold the record. Name and regexp
// both, because a regexp entry has no name: comparing names alone found every
// regexp record already present on a router holding any. A name compares
// without case, as the resolver answers it.
func dnsAlreadyPresent(rows []routeros.Reply, want collect.DNSStaticEntry, byValue bool) bool {
	for _, e := range collect.ParseStaticEntries(rows) {
		if strings.EqualFold(e.Name, want.Name) && e.Regexp == want.Regexp && e.Type == want.Type &&
			(!byValue || e.Address == want.Address) {
			return true
		}
	}
	return false
}

// dnsFleetEntries projects one router's rows for the comparison.
//
// THE DISPLAY HALF AND THE COPY HALF COME FROM THE SAME ROW, joined by `.id`, so
// the two cannot describe different records. Sorted by name and then type, which
// is the key the page lines the columns up on — a record has to sit on the same
// line in every router's column or the comparison is unreadable.
func dnsFleetEntries(rows []routeros.Reply) []dnsFleetEntry {
	shown := collect.ParseStaticEntries(rows)
	raw := map[string]map[string]string{}
	for _, r := range rows {
		if id := r[".id"]; id != "" {
			raw[id] = r
		}
	}
	out := make([]dnsFleetEntry, 0, len(shown))
	for _, e := range shown {
		out = append(out, dnsFleetEntry{
			DNSStaticEntry: e,
			Values:         resource.DNSStatic.RowValues(raw[e.ID]),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Type < b.Type
	})
	return out
}
