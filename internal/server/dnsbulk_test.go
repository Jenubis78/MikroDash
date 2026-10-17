package server

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"mikrodash/internal/audit"
	"mikrodash/internal/db"
	"mikrodash/internal/hub"
	"mikrodash/internal/routeros"
	"mikrodash/internal/session"
)

func bulkRows() []routeros.Reply {
	return []routeros.Reply{
		{".id": "*1", "name": "a.example", "type": "FWD", "address-list": "old"},
		{".id": "*2", "name": "b.example", "type": "FWD", "address-list": "old"},
		{".id": "*3", "name": "pc.lan", "type": "A", "address": "198.51.100.5", "dynamic": "true"},
		{".id": "*4", "regexp": `^ads\.`, "type": "A", "address": "0.0.0.0"},
	}
}

// TestABulkPlanIsCheckedBeforeAnyCommand. A job that would fail on one row
// must change nothing, so a dynamic row, an unknown id and an invalid add are
// all refused at planning.
func TestABulkPlanIsCheckedBeforeAnyCommand(t *testing.T) {
	steps, errs := planDNSBulk(dnsBulkIn{
		Set:    []dnsBulkSet{{IDs: []string{"*1", "*2"}, Patch: map[string]any{"addressList": "to_vpn"}}},
		Remove: []string{"*2", "*4"},
		Add:    []map[string]any{{"name": "c.example", "type": "FWD", "addressList": "to_vpn", "matchSubdomain": true}},
	}, bulkRows())
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	var got []string
	for _, s := range steps {
		got = append(got, s.verb+" "+strings.Join(s.args, " "))
	}
	want := []string{
		"remove =.id=*2,*4",
		"set =.id=*1,*2 =address-list=to_vpn",
		"add =name=c.example =type=FWD =address-list=to_vpn =match-subdomain=yes =disabled=no",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("plan:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !reflect.DeepEqual(steps[0].names, []string{"b.example", `^ads\.`}) {
		t.Errorf("the removed entries are named %v, want their name or regexp", steps[0].names)
	}

	_, errs = planDNSBulk(dnsBulkIn{
		Remove: []string{"*3", "*404"},
		Add:    []map[string]any{{"type": "FWD"}},
	}, bulkRows())
	if len(errs) != 3 {
		t.Errorf("errors = %v; want the dynamic row, the unknown id and the nameless add", errs)
	}
}

// TestAPatchIsCheckedRowByRow. A change that is valid on its own can leave a
// row the router would refuse: CNAME on entries that have no target.
func TestAPatchIsCheckedRowByRow(t *testing.T) {
	steps, errs := planDNSBulk(dnsBulkIn{
		Set: []dnsBulkSet{{IDs: []string{"*1", "*4"}, Patch: map[string]any{"type": "CNAME"}}},
	}, bulkRows())
	if len(steps) != 0 || len(errs) != 2 {
		t.Fatalf("steps %d, errors %v; want both rows refused", len(steps), errs)
	}
	if !strings.HasPrefix(errs[0], "a.example: ") || !strings.HasPrefix(errs[1], `^ads\.: `) {
		t.Errorf("the refusals do not name their rows: %v", errs)
	}
}

func TestABulkSetNamesAHundredIDsAtMost(t *testing.T) {
	var rows []routeros.Reply
	var ids []string
	for i := range 250 {
		id := "*" + strconv.Itoa(i+1)
		rows = append(rows, routeros.Reply{".id": id, "name": id + ".example", "type": "FWD"})
		ids = append(ids, id)
	}
	steps, errs := planDNSBulk(dnsBulkIn{Remove: ids}, rows)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if len(steps) != 3 || steps[0].rows != 100 || steps[2].rows != 50 || len(steps[2].names) != 50 {
		t.Errorf("%d steps; want 100, 100, 50", len(steps))
	}
}

// bulkServer is a server whose job allowance is `n` writes a second and whose
// form allowance is two an hour, with a router that accepts every command and
// holds `rows`.
func bulkServer(t *testing.T, n int, rows []routeros.Reply) (*Server, *session.Session, *[]string, *db.DB) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	database := rbacTestDB(t)
	s := &Server{jobLimit: newRateLimiter(n, time.Second), writeLimit: newRateLimiter(2, time.Hour), auditDB: database,
		dnsBulk:  dnsBulkJobs{jobs: map[string]*DNSBulkJob{}, busy: map[string]bool{}},
		features: &featureLoop{ctx: ctx, cancel: cancel, listsRunning: map[int64]bool{}}}
	var sent []string
	sn := session.NewForTestWithExec(hub.New(), "r-A", func(cmd routeros.Cmd) ([]routeros.Reply, error) {
		if strings.HasSuffix(cmd.Path, "/print") {
			return rows, nil
		}
		sent = append(sent, cmd.Path+" "+strings.Join(cmd.Args, " "))
		return nil, nil
	})
	return s, sn, &sent, database
}

// TestABulkJobSpendsAWriteForEveryCommand. With an allowance of two writes a
// second, a job of four commands waits for the next window instead of
// sending them all, and says so while it waits.
func TestABulkJobSpendsAWriteForEveryCommand(t *testing.T) {
	var rows []routeros.Reply
	var adds []map[string]any
	for i := range 4 {
		adds = append(adds, map[string]any{"name": "n" + strconv.Itoa(i) + ".example", "type": "FWD",
			"addressList": "to_vpn"})
	}
	s, sn, sent, _ := bulkServer(t, 2, rows)
	steps, errs := planDNSBulk(dnsBulkIn{RouterID: "r-A", Add: adds}, rows)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	rec := audit.New(auditSinkOf(s), audit.System(), nowMillis)
	started := time.Now()
	finished := make(chan DNSBulkJob, 1)
	job, code := s.beginDNSBulk(sn, func() {}, "someone", dnsBulkIn{RouterID: "r-A", Label: "pace"}, steps, rec,
		false, func(j DNSBulkJob) { finished <- j })
	if code != "" {
		t.Fatal(code)
	}
	waited := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if s.dnsBulk.snapshot(job).WaitingUntil > 0 {
			waited = true
			break
		}
	}
	j := <-finished
	if !waited {
		t.Error("the job never said it was waiting for the write limit")
	}
	if len(*sent) != 4 || j.Added != 4 || j.State != "done" {
		t.Errorf("sent %d, added %d, state %s", len(*sent), j.Added, j.State)
	}
	if time.Since(started) < 500*time.Millisecond {
		t.Errorf("four writes on an allowance of two a second took %v", time.Since(started))
	}
}

// TestABulkRemoveIsAuditedByTheEntry. Removing entries in bulk records each
// one by name, as a delete from the page does, besides the job's totals.
func TestABulkRemoveIsAuditedByTheEntry(t *testing.T) {
	rows := bulkRows()
	s, sn, _, database := bulkServer(t, 30, nil)
	steps, errs := planDNSBulk(dnsBulkIn{RouterID: "r-A", Remove: []string{"*1", "*4"}}, rows)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	finished := make(chan DNSBulkJob, 1)
	rec := audit.New(auditSinkOf(s), audit.System(), nowMillis)
	if _, code := s.beginDNSBulk(sn, func() {}, "someone", dnsBulkIn{RouterID: "r-A", Label: "tidy"}, steps, rec,
		true, func(j DNSBulkJob) { finished <- j }); code != "" {
		t.Fatal(code)
	}
	<-finished
	page, err := database.QueryAuditEvents(db.Query{RouterIDs: []string{"r-A"}})
	if err != nil {
		t.Fatal(err)
	}
	deleted := map[string]bool{}
	bulk := 0
	for _, r := range page.Rows {
		switch r.Action {
		case "dnsStatic.delete":
			if r.TargetName != nil {
				deleted[*r.TargetName] = true
			}
		case "dnsStatic.bulk":
			bulk++
		}
	}
	if !deleted["a.example"] || !deleted[`^ads\.`] || bulk != 1 {
		t.Errorf("audited deletes %v and %d job rows; want both entries by name and one job row", deleted, bulk)
	}
}

// TestABulkJobStopsWithTheServer. A job waiting for the write limit ends when
// the features' lifetime does, rather than outliving the server.
func TestABulkJobStopsWithTheServer(t *testing.T) {
	var adds []map[string]any
	for i := range 3 {
		adds = append(adds, map[string]any{"name": "s" + strconv.Itoa(i) + ".example", "type": "FWD",
			"addressList": "to_vpn"})
	}
	s, sn, sent, _ := bulkServer(t, 1, nil)
	s.jobLimit = newRateLimiter(1, time.Hour)
	steps, _ := planDNSBulk(dnsBulkIn{Add: adds}, nil)
	finished := make(chan DNSBulkJob, 1)
	rec := audit.New(auditSinkOf(s), audit.System(), nowMillis)
	if _, code := s.beginDNSBulk(sn, func() {}, "someone", dnsBulkIn{RouterID: "r-A"}, steps, rec, false,
		func(j DNSBulkJob) { finished <- j }); code != "" {
		t.Fatal(code)
	}
	time.Sleep(100 * time.Millisecond)
	s.features.Stop()
	select {
	case j := <-finished:
		if j.State != "stopped" || len(*sent) != 1 {
			t.Errorf("state %s after %d commands; want stopped after the one the allowance covered", j.State, len(*sent))
		}
		if j.Failed != 2 {
			t.Errorf("%d failed; want the two entries that were never sent", j.Failed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the job outlived the server")
	}
}

// TestAStoppedJobCountsRowsNotCommands. A set or a remove names up to a hundred
// ids in one command, so what a job that never got to them failed to change is
// their rows.
func TestAStoppedJobCountsRowsNotCommands(t *testing.T) {
	var rows []routeros.Reply
	var ids []string
	for i := range 250 {
		id := "*" + strconv.Itoa(i+1)
		rows = append(rows, routeros.Reply{".id": id, "name": id + ".example", "type": "FWD"})
		ids = append(ids, id)
	}
	s, sn, _, _ := bulkServer(t, 1, rows)
	s.jobLimit = newRateLimiter(1, time.Hour)
	steps, errs := planDNSBulk(dnsBulkIn{Remove: ids}, rows)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	finished := make(chan DNSBulkJob, 1)
	rec := audit.New(auditSinkOf(s), audit.System(), nowMillis)
	if _, code := s.beginDNSBulk(sn, func() {}, "someone", dnsBulkIn{RouterID: "r-A"}, steps, rec, false,
		func(j DNSBulkJob) { finished <- j }); code != "" {
		t.Fatal(code)
	}
	time.Sleep(100 * time.Millisecond)
	s.features.Stop()
	select {
	case j := <-finished:
		if j.Failed != 150 || j.Removed != 100 {
			t.Errorf("removed %d, failed %d; want 100 removed and the other 150 rows failed", j.Removed, j.Failed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the job outlived the server")
	}
}

// TestAJobLeavesTheFormsAllowanceAlone. The writes of a job are drawn from its
// own allowance: a user whose list is syncing can still save a form on that
// router.
func TestAJobLeavesTheFormsAllowanceAlone(t *testing.T) {
	var adds []map[string]any
	for i := range 5 {
		adds = append(adds, map[string]any{"name": "j" + strconv.Itoa(i) + ".example", "type": "FWD",
			"addressList": "to_vpn"})
	}
	s, sn, sent, _ := bulkServer(t, 100, nil)
	steps, errs := planDNSBulk(dnsBulkIn{Add: adds}, nil)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	finished := make(chan DNSBulkJob, 1)
	rec := audit.New(auditSinkOf(s), audit.System(), nowMillis)
	if _, code := s.beginDNSBulk(sn, func() {}, "someone", dnsBulkIn{RouterID: "r-A"}, steps, rec, false,
		func(j DNSBulkJob) { finished <- j }); code != "" {
		t.Fatal(code)
	}
	<-finished
	if len(*sent) != 5 {
		t.Fatalf("the job sent %d commands, want 5", len(*sent))
	}
	key := writeLimitKey("someone", "r-A")
	for i := 1; i <= 2; i++ {
		if ok, _, _ := s.writeLimit.take(key); !ok {
			t.Errorf("form save %d was refused after a job, which should not have touched its allowance", i)
		}
	}
}

// TestTheJobEndpointFollowsItsSwitches. Asking after a job needs one of the two
// features that submit jobs from the page, and a signed-in user.
func TestTheJobEndpointFollowsItsSwitches(t *testing.T) {
	for _, c := range []struct {
		name, settings string
		signedIn       bool
		want           int
	}{
		{"signed out", `{"dnsBulkEnabled":true}`, false, 401},
		{"both off", `{}`, true, 403},
		{"lists only", `{"dnsListsEnabled":true}`, true, 403},
		{"bulk on", `{"dnsBulkEnabled":true}`, true, 404},
		{"fleet sync on", `{"dnsFleetSyncEnabled":true}`, true, 404},
	} {
		s := gateServer(t, c.settings, "")
		if w := gateCall(s, s.dnsBulkGet, "/api/dns/bulk?id=nope", c.signedIn); w.Code != c.want {
			t.Errorf("%s: answered %d, want %d", c.name, w.Code, c.want)
		}
	}
}
