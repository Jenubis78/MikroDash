package server

// `/api/dns/bulk`: many changes to one router's static DNS table, as one job
// (Settings -> Features -> Bulk edit).
//
// ── EVERY COMMAND IS A WRITE ────────────────────────────────────────────────
//
// Each command a job sends spends one of the user's job allowance on that
// router, twenty a minute, and the first is spent before the table is read. It
// is not the thirty a minute of the page (#97): drawn from that one, a long job
// would refuse every form save the same user makes on the router until it
// finished. A `set` or `remove` names up to a hundred ids, so moving two
// hundred entries to another address list is two writes; an add is one entry a
// command, so adding a thousand takes about fifty minutes. When the allowance
// is spent the job waits for the next window, outside the router's write queue,
// so a form save is never stuck behind it.
//
// ── THE SAME RULES AS A FORM ────────────────────────────────────────────────
//
// An add is validated as the Add form is; a full set as the Edit form is,
// against the row as the router holds it; a patch row by row, as the Edit form
// would validate that row with the patch applied, so `type=CNAME` on an entry
// with no target is refused before anything is sent. Everything is validated
// before the first command, so a job that would fail on row 900 changes
// nothing. dnsStatic declares no guard, which is what makes a path outside the
// socket's guard chain acceptable, the reasoning dnsfleet_api.go gives.
//
// Removes go first, then changes, then adds, so a job that replaces records
// never holds two copies. Each removed entry is audited by name, as a delete
// from the page is, and the job once more with its totals.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"mikrodash/internal/audit"
	"mikrodash/internal/collect"
	"mikrodash/internal/resource"
	"mikrodash/internal/routeros"
	"mikrodash/internal/safe"
	"mikrodash/internal/session"
	"mikrodash/internal/store"
)

const (
	dnsBulkHold = "dns-bulk"
	// dnsBulkMax bounds one job: four times the largest table measured.
	dnsBulkMax = 5000
	// dnsBulkIDs is how many ids one set or remove names; RouterOS takes a
	// comma list of ids in `.id`.
	dnsBulkIDs = 100
	// dnsBulkKeep is how long a finished job can still be asked about.
	dnsBulkKeep = 15 * time.Minute
)

type dnsBulkSet struct {
	// IDs with Patch: the same change to every row, through PartialArgs.
	IDs   []string       `json:"ids"`
	Patch map[string]any `json:"patch"`
	// ID with Values: one row rewritten in full, validated as the Edit form is.
	ID     string         `json:"id"`
	Values map[string]any `json:"values"`
}

type dnsBulkIn struct {
	RouterID string           `json:"routerId"`
	Label    string           `json:"label"`
	Add      []map[string]any `json:"add"`
	Set      []dnsBulkSet     `json:"set"`
	Remove   []string         `json:"remove"`
}

// DNSBulkJob is one job's state, as `GET /api/dns/bulk` answers it.
type DNSBulkJob struct {
	ID       string   `json:"id"`
	RouterID string   `json:"routerId"`
	Label    string   `json:"label"`
	State    string   `json:"state"` // running, done, failed, stopped
	Total    int      `json:"total"`
	Done     int      `json:"done"`
	Added    int      `json:"added"`
	Changed  int      `json:"changed"`
	Removed  int      `json:"removed"`
	Failed   int      `json:"failed"`
	Errors   []string `json:"errors"`
	// Unconfirmed counts writes the router accepted that the read after the
	// job could not find, the outcome #97 reports instead of guessing.
	Unconfirmed int `json:"unconfirmed"`
	// WaitingUntil is when the write limit lets the job go on, in ms; 0 while
	// it is not waiting.
	WaitingUntil int64 `json:"waitingUntil"`

	user     string
	finished time.Time
}

// dnsStep is one RouterOS command of a job and what it counts as.
type dnsStep struct {
	args []string
	verb string // add, set, remove
	rows int
	ids  []string
	// names are the removed entries' names or regexps, for their audit rows.
	names []string
	// key is "name\x01regexp\x01type" for an add, to find it afterwards.
	key string
}

type dnsBulkJobs struct {
	mu   sync.Mutex
	jobs map[string]*DNSBulkJob
	busy map[string]bool // router id -> a job is running
	seq  int
}

func (s *Server) registerDNSBulk(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/dns/bulk", s.dnsBulkStart)
	mux.HandleFunc("GET /api/dns/bulk", s.dnsBulkGet)
}

func (s *Server) dnsBulkStart(w http.ResponseWriter, r *http.Request) {
	sess := s.layoutSession(w, r)
	if sess == nil || !s.featureGate(w, store.FeatureDNSBulk) {
		return
	}
	var in dnsBulkIn
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&in); err != nil {
		writeJSON400OK(w)
		return
	}
	job, code, errs := s.startDNSBulk(r.Context(), sess, in, s.httpRecorder(r, sess))
	if code != "" {
		writeJSON(w, map[string]any{"ok": false, "code": code, "errors": errs})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "job": s.dnsBulk.snapshot(job)})
}

func (s *Server) dnsBulkGet(w http.ResponseWriter, r *http.Request) {
	sess := s.layoutSession(w, r)
	if sess == nil {
		return
	}
	// The page follows a job of its own bulk edit or its fleet sync; the lists run
	// theirs in this process and nobody asks after them.
	if !s.featureOn(store.FeatureDNSBulk) && !s.featureGate(w, store.FeatureDNSFleetSync) {
		return
	}
	s.dnsBulk.mu.Lock()
	j := s.dnsBulk.jobs[r.URL.Query().Get("id")]
	var snap DNSBulkJob
	if j != nil {
		snap = j.copy()
	}
	s.dnsBulk.mu.Unlock()
	if j == nil || snap.user != sess.Username {
		writeJSONErr(w, http.StatusNotFound, "no such job")
		return
	}
	writeJSON(w, snap)
}

// copy is a copy safe to marshal while the job runs. The caller holds the
// registry lock.
func (j *DNSBulkJob) copy() DNSBulkJob {
	c := *j
	c.Errors = append([]string{}, j.Errors...)
	return c
}

// snapshot is copy, taking the registry lock.
func (b *dnsBulkJobs) snapshot(j *DNSBulkJob) DNSBulkJob {
	b.mu.Lock()
	defer b.mu.Unlock()
	return j.copy()
}

// startDNSBulk checks, plans and starts a job a user asked for. A refusal
// changes nothing and comes back as a code and, for `invalid`, the field
// errors.
func (s *Server) startDNSBulk(ctx context.Context, sess *Session, in dnsBulkIn,
	rec *audit.Recorder) (*DNSBulkJob, string, []string) {

	if s.auditDB == nil {
		return nil, "audit-unavailable", nil
	}
	targets, _ := s.fleetTargets(sess, []string{in.RouterID}, "dns", "write")
	if len(targets) != 1 {
		return nil, "not-permitted", nil
	}
	if code, errs := bulkSize(in); code != "" {
		return nil, code, errs
	}
	if s.dnsBulk.running(in.RouterID) {
		return nil, "busy", nil
	}
	// THE FIRST WRITE IS SPENT BEFORE THE READ, so a job refused for its size
	// or its rows still cost the allowance it would have used, and a client
	// cannot read a router's whole table over and over through this endpoint.
	if s.jobLimit != nil {
		if ok, _, _ := s.jobLimit.take(writeLimitKey(sess.Username, in.RouterID)); !ok {
			return nil, "rate-limited", nil
		}
	}
	sn, drop, ok := s.fleetSession(ctx, in.RouterID, dnsBulkHold)
	if !ok {
		return nil, "unreachable", nil
	}
	rows, err := sn.Exec(collect.DNSStaticCmd())
	if err != nil {
		drop()
		return nil, "read-failed", []string{safe.Message(err.Error())}
	}
	steps, errs := planDNSBulk(in, rows)
	if len(errs) > 0 {
		drop()
		return nil, "invalid", errs
	}
	job, code := s.beginDNSBulk(sn, drop, sess.Username, in, steps, rec, true, nil)
	return job, code, nil
}

// bulkSize refuses a job with nothing in it or more than one job takes.
func bulkSize(in dnsBulkIn) (string, []string) {
	n := len(in.Add) + len(in.Remove)
	for _, st := range in.Set {
		n += max(len(st.IDs), 1)
	}
	if n == 0 {
		return "empty", nil
	}
	if n > dnsBulkMax {
		return "too-many", []string{fmt.Sprintf("%d changes; one job takes %d", n, dnsBulkMax)}
	}
	return "", nil
}

func (b *dnsBulkJobs) running(routerID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.busy[routerID]
}

// beginDNSBulk registers a planned job and runs it in the background, owning
// the session hold `drop` releases. `spent` says the first write was already
// taken. `done` sees the finished job.
func (s *Server) beginDNSBulk(sn *session.Session, drop func(), user string, in dnsBulkIn, steps []dnsStep,
	rec *audit.Recorder, spent bool, done func(DNSBulkJob)) (*DNSBulkJob, string) {

	s.dnsBulk.mu.Lock()
	if s.dnsBulk.busy[in.RouterID] {
		s.dnsBulk.mu.Unlock()
		drop()
		return nil, "busy"
	}
	s.dnsBulk.seq++
	job := &DNSBulkJob{
		ID:       strconv.FormatInt(time.Now().UnixMilli(), 36) + "-" + strconv.Itoa(s.dnsBulk.seq),
		RouterID: in.RouterID, Label: bulkLabel(in.Label), State: "running",
		Total: len(steps), Errors: []string{}, user: user,
	}
	s.dnsBulk.prune()
	s.dnsBulk.jobs[job.ID] = job
	s.dnsBulk.busy[in.RouterID] = true
	s.dnsBulk.mu.Unlock()

	go func() {
		defer drop()
		s.runDNSBulk(sn, job, steps, rec, writeLimitKey(user, in.RouterID), spent)
		if done != nil {
			done(s.dnsBulk.snapshot(job))
		}
	}()
	return job, ""
}

func bulkLabel(l string) string {
	l = strings.TrimSpace(l)
	if l == "" || len(l) > 80 {
		return "bulk change"
	}
	return l
}

// prune drops finished jobs nobody can still want. The caller holds the lock.
func (b *dnsBulkJobs) prune() {
	for id, j := range b.jobs {
		if j.State != "running" && time.Since(j.finished) > dnsBulkKeep {
			delete(b.jobs, id)
		}
	}
}

func bulkKey(row map[string]string) string {
	return row["name"] + "\x01" + row["regexp"] + "\x01" + row["type"]
}

// planDNSBulk turns a request into commands, checking every one first.
func planDNSBulk(in dnsBulkIn, rows []routeros.Reply) ([]dnsStep, []string) {
	res := resource.DNSStatic
	byID := map[string]routeros.Reply{}
	for _, r := range rows {
		byID[r[".id"]] = r
	}
	var steps []dnsStep
	var errs []string
	fail := func(where string, es []resource.Error) {
		for _, e := range es {
			errs = append(errs, where+": "+e.Message)
		}
	}
	known := func(id string) bool {
		if byID[id] == nil {
			errs = append(errs, id+": no such entry on the router")
			return false
		}
		if res.ReadOnlyWhen(byID[id]) {
			errs = append(errs, res.IdentityOf(byID[id])+": a dynamic entry belongs to the service that added it")
			return false
		}
		return true
	}

	var gone, goneNames []string
	for _, id := range in.Remove {
		if known(id) {
			gone = append(gone, id)
			goneNames = append(goneNames, res.IdentityOf(byID[id]))
		}
	}
	for i := 0; i < len(gone); i += dnsBulkIDs {
		ids := gone[i:min(i+dnsBulkIDs, len(gone))]
		steps = append(steps, dnsStep{verb: "remove", rows: len(ids), ids: ids,
			names: goneNames[i:min(i+dnsBulkIDs, len(gone))], args: []string{"=.id=" + strings.Join(ids, ",")}})
	}

	for i, st := range in.Set {
		where := "change " + strconv.Itoa(i+1)
		switch {
		case st.Values != nil:
			if !known(st.ID) {
				continue
			}
			v, es := res.Validate(flattenValues(st.Values), true)
			if len(es) > 0 {
				fail(where, es)
				continue
			}
			v.Stored = byID[st.ID]
			steps = append(steps, dnsStep{verb: "set", rows: 1, ids: []string{st.ID},
				args: append([]string{"=.id=" + st.ID}, res.BuildArgs(v)...)})
		case st.Patch != nil:
			patch := flattenValues(st.Patch)
			args, es := res.PartialArgs(patch)
			if len(es) > 0 {
				fail(where, es)
				continue
			}
			if len(args) == 0 {
				continue
			}
			// EACH ROW AS THE EDIT FORM WOULD SEE IT with the patch applied: a
			// change valid on its own can leave a row the router refuses.
			var ids []string
			for _, id := range st.IDs {
				if !known(id) {
					continue
				}
				row := flattenValues(res.RowValues(byID[id]))
				for k, v := range patch {
					row[k] = v
				}
				if _, es := res.Validate(row, true); len(es) > 0 {
					fail(res.IdentityOf(byID[id]), es)
					continue
				}
				ids = append(ids, id)
			}
			for c := 0; c < len(ids); c += dnsBulkIDs {
				part := ids[c:min(c+dnsBulkIDs, len(ids))]
				steps = append(steps, dnsStep{verb: "set", rows: len(part), ids: part,
					args: append([]string{"=.id=" + strings.Join(part, ",")}, args...)})
			}
		default:
			errs = append(errs, where+": names neither values nor a patch")
		}
	}

	for i, raw := range in.Add {
		v, es := res.Validate(flattenValues(raw), false)
		if len(es) > 0 {
			fail("add "+strconv.Itoa(i+1), es)
			continue
		}
		steps = append(steps, dnsStep{verb: "add", rows: 1, args: res.BuildArgs(v),
			key: bulkKey(map[string]string{"name": v.Values["name"], "regexp": v.Values["regexp"],
				"type": v.Values["type"]})})
	}
	if len(errs) > 20 {
		errs = append(errs[:20], fmt.Sprintf("and %d more", len(errs)-20))
	}
	return steps, errs
}

// writeToken waits for one of `key`'s writes. False when the server stopped
// first. `waiting` is told when the job will go on.
func (s *Server) writeToken(key string, waiting func(until time.Time)) bool {
	if s.jobLimit == nil {
		return true
	}
	for {
		ok, _, reset := s.jobLimit.take(key)
		if ok {
			waiting(time.Time{})
			return true
		}
		until := time.Now().Add(time.Duration(max(reset, 1)) * time.Second)
		waiting(until)
		select {
		case <-s.featuresDone():
			return false
		case <-time.After(time.Until(until)):
		}
	}
}

// runDNSBulk performs a planned job, then reads the table once to confirm it.
func (s *Server) runDNSBulk(sn *session.Session, job *DNSBulkJob, steps []dnsStep, rec *audit.Recorder,
	limitKey string, spent bool) {

	update := func(fn func()) {
		s.dnsBulk.mu.Lock()
		fn()
		s.dnsBulk.mu.Unlock()
	}
	waiting := func(until time.Time) {
		ms := int64(0)
		if !until.IsZero() {
			ms = until.UnixMilli()
		}
		update(func() { job.WaitingUntil = ms })
	}
	stopped := false
	var accepted []dnsStep
	for i, st := range steps {
		if (i > 0 || !spent) && !s.writeToken(limitKey, waiting) {
			stopped = true
			rest := 0
			for _, left := range steps[i:] {
				rest += left.rows
			}
			update(func() {
				job.Failed += rest
				job.Errors = append(job.Errors, "stopped: MikroDash shut down")
			})
			break
		}
		var err error
		werr := sn.InWriteQueue(func() error {
			_, err = sn.Exec(routeros.Cmd{Path: resource.DNSStatic.Menu + "/" + st.verb, Args: st.args})
			return nil
		})
		if werr != nil {
			err = werr
		}
		update(func() {
			job.Done++
			if err != nil {
				job.Failed += st.rows
				if len(job.Errors) < 20 {
					job.Errors = append(job.Errors, st.verb+": "+safe.Message(err.Error()))
				}
				return
			}
			accepted = append(accepted, st)
			switch st.verb {
			case "add":
				job.Added++
			case "set":
				job.Changed += st.rows
			case "remove":
				job.Removed += st.rows
			}
		})
	}

	// CONFIRMED BY READING IT BACK (#97): a removed row must be gone and an
	// added one present. A change is not re-compared field by field; the row
	// still being there is what the per-row path checks too.
	if rows, err := sn.Exec(collect.DNSStaticCmd()); err == nil {
		have, keys := map[string]bool{}, map[string]bool{}
		for _, r := range rows {
			have[r[".id"]] = true
			keys[bulkKey(r)] = true
		}
		missing := 0
		for _, st := range accepted {
			switch st.verb {
			case "add":
				if !keys[st.key] {
					missing++
				}
			case "remove":
				for _, id := range st.ids {
					if have[id] {
						missing++
					}
				}
			case "set":
				for _, id := range st.ids {
					if !have[id] {
						missing++
					}
				}
			}
		}
		update(func() { job.Unconfirmed = missing })
	} else {
		update(func() { job.Unconfirmed = job.Added + job.Changed + job.Removed })
	}

	if sn.CollectorEnabled("dns") {
		sn.DNS().RefreshNow()
	}
	for _, st := range accepted {
		if st.verb != "remove" {
			continue
		}
		for i, id := range st.ids {
			rec.Record(audit.Event{Action: "dnsStatic.delete", TargetType: "dnsStatic", RouterID: job.RouterID,
				TargetID: id, TargetName: st.names[i], Note: "in " + job.Label})
		}
	}
	var note string
	var nothing bool
	update(func() {
		note = fmt.Sprintf("added %d, changed %d, removed %d, failed %d", job.Added, job.Changed,
			job.Removed, job.Failed)
		if job.Unconfirmed > 0 {
			note += fmt.Sprintf(", %d not confirmed by the read-back", job.Unconfirmed)
		}
		nothing = job.Failed > 0 && job.Added+job.Changed+job.Removed == 0
	})
	ev := audit.Event{Action: "dnsStatic.bulk", TargetType: "dnsStatic", RouterID: job.RouterID,
		TargetName: job.Label, Note: note}
	if nothing {
		rec.Failed(ev)
	} else {
		rec.Record(ev)
	}
	update(func() {
		switch {
		case stopped:
			job.State = "stopped"
		case nothing:
			job.State = "failed"
		default:
			job.State = "done"
		}
		job.WaitingUntil = 0
		job.finished = time.Now()
		delete(s.dnsBulk.busy, job.RouterID)
	})
}
