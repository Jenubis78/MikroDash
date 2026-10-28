package server

// Updating the IPS sensor from the page: the registry says a newer release
// exists, an administrator presses Update, and the router re-pulls the image.
//
//	GET  /api/ips/sensor/update?router=   what runs, what is newest, the job
//	POST /api/ips/sensor/update?router=   update the sensor's container
//
// ── THE NEWEST RELEASE, ASKED SELDOM ────────────────────────────────────────
//
// The registry is asked for the image's tags at most every ipsReleaseEvery per
// image (or when the page asks to check now), never on the poll's path: the
// state endpoint reads the cache and starts a refresh it does not wait for.
//
// ── THE ROUTER DOES THE PULL ────────────────────────────────────────────────
//
// RouterOS 7.22 and later stop, re-pull and start a container on
// `/container/repull`; 7.20 and 7.21 have repull without the stop and start,
// so the job does them; before 7.20 there is no repull and the job says to
// recreate the container from the script. An image pinned to an older release
// is moved to the newest first. The job then waits for the sensor to say hello
// again with the new release.

import (
	"context"
	"net/http"
	"strings"
	"time"

	"mikrodash/internal/audit"
	"mikrodash/internal/ips"
	"mikrodash/internal/registry"
	"mikrodash/internal/routeros"
	"mikrodash/internal/safe"
	"mikrodash/internal/session"
)

const (
	ipsReleaseEvery    = 6 * time.Hour
	ipsUpdateStopWait  = 2 * time.Minute
	ipsUpdatePullWait  = 15 * time.Minute
	ipsUpdateHelloWait = 3 * time.Minute
)

// ipsUpdateStep is how often the job reads the container's state; a test
// shortens it.
var ipsUpdateStep = 3 * time.Second

// ipsRelease is what the registry said about one image.
type ipsRelease struct {
	newest  string
	err     string
	at      time.Time
	pending bool
}

// IPSUpdateJob is a sensor update: running, or how the last one ended.
type IPSUpdateJob struct {
	Running bool   `json:"running"`
	Phase   string `json:"phase"`
	Error   string `json:"error"`
	From    string `json:"from"`
	To      string `json:"to"`
	At      int64  `json:"at"`
}

// IPSUpdatePayload is what the page shows about the sensor's release.
type IPSUpdatePayload struct {
	Image     string       `json:"image"`
	Running   string       `json:"running"` // the sensor's release, "" when it does not say
	Newest    string       `json:"newest"`
	Available bool         `json:"available"`
	CheckedAt int64        `json:"checkedAt"`
	CheckErr  string       `json:"checkError"`
	Job       IPSUpdateJob `json:"job"`
}

// sensorImage is the image a router's sensor runs, as configured.
func (s *Server) sensorImage(rid string) string {
	if sn, ok := s.ipsSensorOf(rid); ok && sn.Image != "" {
		return sn.Image
	}
	return ips.DefaultImage
}

// release is the cached newest release of an image, refreshed in the
// background when stale (or when force).
func (e *ipsEngine) release(image string, force bool) ipsRelease {
	e.mu.Lock()
	if e.releases == nil {
		e.releases = map[string]*ipsRelease{}
	}
	r := e.releases[image]
	if r == nil {
		r = &ipsRelease{}
		e.releases[image] = r
	}
	stale := time.Since(r.at) > ipsReleaseEvery || force
	if stale && !r.pending {
		r.pending = true
		go e.checkRelease(image)
	}
	out := *r
	e.mu.Unlock()
	return out
}

func (e *ipsEngine) checkRelease(image string) {
	newest, msg := "", ""
	ref, err := registry.Parse(image)
	if err == nil {
		ctx, cancel := context.WithTimeout(e.ctx, 20*time.Second)
		var tags []string
		tags, err = registry.Tags(ctx, &http.Client{Timeout: 20 * time.Second}, ref)
		cancel()
		newest = ips.NewestRelease(tags)
	}
	if err != nil {
		msg = err.Error()
	}
	e.mu.Lock()
	r := e.releases[image]
	r.pending, r.at, r.err = false, time.Now(), msg
	if err == nil {
		r.newest = newest
	}
	e.mu.Unlock()
}

func (e *ipsEngine) updateJob(rid string) IPSUpdateJob {
	e.mu.Lock()
	defer e.mu.Unlock()
	if j := e.updates[rid]; j != nil {
		return *j
	}
	return IPSUpdateJob{}
}

func (e *ipsEngine) setUpdate(rid string, f func(j *IPSUpdateJob)) {
	e.mu.Lock()
	if e.updates == nil {
		e.updates = map[string]*IPSUpdateJob{}
	}
	j := e.updates[rid]
	if j == nil {
		j = &IPSUpdateJob{}
		e.updates[rid] = j
	}
	f(j)
	e.mu.Unlock()
}

// sensorUpdate is a router's release payload.
func (s *Server) sensorUpdate(rid string, force bool) IPSUpdatePayload {
	image := s.sensorImage(rid)
	rel := s.ips.release(image, force)
	p := IPSUpdatePayload{Image: image, Newest: rel.newest, CheckErr: safe.Message(rel.err), Job: s.ips.updateJob(rid)}
	if !rel.at.IsZero() {
		p.CheckedAt = rel.at.UnixMilli()
	}
	if rd := s.ips.reader(rid); rd != nil {
		rd.mu.Lock()
		p.Running = rd.status.Build
		connected := rd.status.State == "connected"
		rd.mu.Unlock()
		p.Available = connected && ips.UpdateAvailable(p.Running, p.Newest)
	}
	return p
}

func (s *Server) ipsUpdateGet(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.ipsReadGate(w, r)
	if sess == nil {
		return
	}
	writeJSON(w, s.sensorUpdate(rid, r.URL.Query().Get("check") == "1"))
}

func (s *Server) ipsUpdatePost(w http.ResponseWriter, r *http.Request) {
	sess, rid := s.ipsAdminRouterGate(w, r)
	if sess == nil {
		return
	}
	if _, ok := s.ipsSensorOf(rid); !ok {
		writeJSONErr(w, http.StatusBadRequest, "configure the sensor first")
		return
	}
	p := s.sensorUpdate(rid, false)
	if p.Job.Running {
		writeJSONErr(w, http.StatusConflict, "an update is already running on this router")
		return
	}
	if p.Newest == "" {
		writeJSONErr(w, http.StatusConflict, "the registry has not said which release is newest yet: check again")
		return
	}
	s.ips.setUpdate(rid, func(j *IPSUpdateJob) {
		*j = IPSUpdateJob{Running: true, Phase: "starting", From: p.Running, To: p.Newest, At: nowMillis()}
	})
	rec := s.httpRecorder(r, sess)
	go s.ips.runUpdate(rid, p.Newest, rec)
	writeJSON(w, map[string]any{"ok": true})
}

// runUpdate is one update, start to finish.
func (e *ipsEngine) runUpdate(rid, newest string, rec *audit.Recorder) {
	errText := ""
	defer func() {
		e.setUpdate(rid, func(j *IPSUpdateJob) {
			j.Running, j.Error = false, errText
			if errText == "" {
				j.Phase = "done"
			}
		})
		ev := audit.Event{Action: "ips.sensor.update", RouterID: rid, TargetType: "ipsSensor", TargetID: rid,
			Note: "to " + newest}
		if errText != "" {
			ev.Outcome, ev.Note = "failure", ev.Note+": "+errText
		}
		rec.Record(ev)
	}()
	phase := func(p string) { e.setUpdate(rid, func(j *IPSUpdateJob) { j.Phase = p }) }
	wait, cancel := context.WithTimeout(e.ctx, fleetDeadline)
	sn, drop, ok := e.s.fleetSession(wait, rid, "ips-update")
	cancel()
	if !ok {
		errText = "the router is not reachable"
		return
	}
	defer drop()
	errText = e.updateOn(sn, rid, newest, phase)
}

// updateOn runs the update on the router; "" when the sensor came back with
// the new release.
func (e *ipsEngine) updateOn(sn *session.Session, rid, newest string, phase func(string)) string {
	exec := func(path string, args ...string) ([]routeros.Reply, error) {
		return sn.Exec(routeros.Cmd{Path: path, Args: args, Timeout: ipsCmdTimeout})
	}
	phase("reading the router")
	res, err := exec("/system/resource/print", "=.proplist=version")
	if err != nil || len(res) == 0 {
		return "the router's version could not be read"
	}
	method, err := ips.UpdateMethod(res[0]["version"])
	if err != nil {
		return err.Error()
	}
	rows, err := exec("/container/print")
	if err != nil {
		return "the containers could not be read"
	}
	c, ok := ips.SensorContainer(rows)
	if !ok {
		return `no container is commented "` + ips.SensorComment + `": recreate it from Setup, Show the commands`
	}
	id := c[".id"]
	status := func() string {
		rows, err := exec("/container/print")
		if err != nil {
			return ""
		}
		for _, r := range rows {
			if r[".id"] == id {
				return ips.ContainerStatus(r)
			}
		}
		return "gone"
	}
	until := func(want func(string) bool, limit time.Duration) bool {
		for end := time.Now().Add(limit); time.Now().Before(end); {
			if e.ctx.Err() != nil {
				return false
			}
			if want(status()) {
				return true
			}
			time.Sleep(ipsUpdateStep)
		}
		return false
	}
	if img := ips.UpdateImage(ips.ContainerImage(c), newest); img != ips.ContainerImage(c) {
		phase("pointing the container at " + img)
		if _, err := exec("/container/set", "=.id="+id, "=remote-image="+img); err != nil {
			return "the container's image could not be changed: " + errMessage(err)
		}
	}
	switch method {
	case ips.UpdateRepull:
		phase("re-pulling the image")
		if _, err := exec("/container/repull", "=.id="+id); err != nil {
			return "the router refused the repull: " + errMessage(err)
		}
	case ips.UpdateStopRepullStart:
		phase("stopping the sensor")
		if _, err := exec("/container/stop", "=.id="+id); err != nil && !strings.Contains(errMessage(err), "not running") {
			return "the sensor could not be stopped: " + errMessage(err)
		}
		if !until(func(s string) bool { return s == "stopped" }, ipsUpdateStopWait) {
			return "the sensor did not stop"
		}
		phase("re-pulling the image")
		if _, err := exec("/container/repull", "=.id="+id); err != nil {
			return "the router refused the repull: " + errMessage(err)
		}
		time.Sleep(ipsUpdateStep)
		if !until(func(s string) bool { return s == "stopped" }, ipsUpdatePullWait) {
			return "the image did not finish pulling"
		}
		phase("starting the sensor")
		if _, err := exec("/container/start", "=.id="+id); err != nil {
			return "the sensor could not be started: " + errMessage(err)
		}
	}
	phase("waiting for the sensor to run")
	if !until(func(s string) bool { return s == "running" }, ipsUpdatePullWait) {
		return "the container did not come back to running: see /container/print and its log on the router"
	}
	phase("waiting for the sensor's hello")
	for end := time.Now().Add(ipsUpdateHelloWait); time.Now().Before(end); time.Sleep(ipsUpdateStep) {
		if e.ctx.Err() != nil {
			return "stopped with the server"
		}
		if rd := e.reader(rid); rd != nil {
			rd.mu.Lock()
			build, state := rd.status.Build, rd.status.State
			rd.mu.Unlock()
			if state == "connected" && !ips.UpdateAvailable(build, newest) {
				return ""
			}
		}
	}
	return "the container runs, but the sensor has not said hello with " + newest + " yet"
}
