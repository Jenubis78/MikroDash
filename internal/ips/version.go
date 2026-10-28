package ips

// The sensor's release, as its hello reports it (`build`), against the
// registry's tags: whether an update is there to offer.

import (
	"fmt"
	"strconv"
	"strings"

	"mikrodash/internal/routeros"
)

// semver reads "1.2.3" (a leading "v" allowed); ok false for anything else -
// "latest", "dev", a branch name.
func semver(s string) ([3]int, bool) {
	var v [3]int
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func less(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// NewestRelease is the highest x.y.z among a registry's tags; "" when none.
func NewestRelease(tags []string) string {
	best, found := [3]int{}, ""
	for _, t := range tags {
		if v, ok := semver(t); ok && (found == "" || less(best, v)) {
			best, found = v, t
		}
	}
	return found
}

// UpdateAvailable is whether `newest` is a release above the running one. A
// sensor that reports no release (before releases were reported, or a dev
// build) is offered the newest.
func UpdateAvailable(running, newest string) bool {
	n, ok := semver(newest)
	if !ok {
		return false
	}
	r, ok := semver(running)
	return !ok || less(r, n)
}

// SensorComment is the comment the container script gives the sensor's
// container, by which MikroDash finds it again.
const SensorComment = Marker + " sensor"

// SensorContainer is the sensor's row in /container/print.
func SensorContainer(rows []routeros.Reply) (routeros.Reply, bool) {
	for _, r := range rows {
		if r["comment"] == SensorComment {
			return r, true
		}
	}
	return nil, false
}

// ContainerImage is the image a container row runs: `remote-image`, or
// `tag` as RouterOS printed it before.
func ContainerImage(r routeros.Reply) string {
	if v := r["remote-image"]; v != "" {
		return v
	}
	return r["tag"]
}

// How a router updates a container, by its RouterOS version.
const (
	// UpdateRepull: 7.22 and later stop, re-pull and start on a repull.
	UpdateRepull = "repull"
	// UpdateStopRepullStart: 7.20 and 7.21 have repull, and need the stop
	// and the start around it.
	UpdateStopRepullStart = "stop-repull-start"
)

// UpdateMethod is how a router of this version updates a container, or why
// it cannot: repull arrived in 7.20.
func UpdateMethod(rosVersion string) (string, error) {
	v := strings.Fields(rosVersion)
	if len(v) == 0 {
		return "", fmt.Errorf("the router's version could not be read")
	}
	// "7.21rc2": the leading digits of each part.
	lead := func(s string) int {
		n := 0
		for _, c := range s {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		return n
	}
	parts := strings.SplitN(v[0], ".", 3)
	major, minor := lead(parts[0]), 0
	if len(parts) > 1 {
		minor = lead(parts[1])
	}
	switch {
	case major > 7 || major == 7 && minor >= 22:
		return UpdateRepull, nil
	case major == 7 && minor >= 20:
		return UpdateStopRepullStart, nil
	}
	return "", fmt.Errorf("RouterOS %s has no container repull (7.20 and later): recreate the container from Setup, "+
		"Show the commands", v[0])
}

// UpdateImage is what the container must run to update: the same name when
// it follows a moving tag (latest), the newest release when it is pinned to
// an older one.
func UpdateImage(current, newest string) string {
	i := strings.LastIndex(current, ":")
	if i < 0 || i < strings.LastIndex(current, "/") {
		return current
	}
	if _, pinned := semver(current[i+1:]); pinned && newest != "" {
		return current[:i+1] + newest
	}
	return current
}

// ContainerStatus is a container row's state: its `status` (stopped,
// running, extracting...), or what its running/stopped flags say when a
// version prints those instead.
func ContainerStatus(r routeros.Reply) string {
	switch {
	case r["status"] != "":
		return r["status"]
	case r["running"] == "true":
		return "running"
	case r["stopped"] == "true":
		return "stopped"
	}
	return ""
}

// ReleaseOf is the release a sensor's hello says it is. Releases are reported
// from 0.2.0; the one release before, 0.1.0, spoke protocol 1, so a hello of
// protocol 1 without one is 0.1.0 rather than unknown - which would offer it
// an "update" to itself while 0.1.0 is the newest.
func ReleaseOf(h Hello) string {
	if h.Build == "" && h.Version == "1" {
		return "0.1.0"
	}
	return h.Build
}
