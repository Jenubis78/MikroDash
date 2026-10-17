package db

// Reading and writing watched devices and Wi-Fi client samples; see
// clientwatch_schema.go.

import (
	"database/sql"
	"errors"
	"strings"
)

// WatchDevice is a device whose absence raises an alert.
type WatchDevice struct {
	ID           int64  `json:"id"`
	RouterID     string `json:"routerId"`
	MAC          string `json:"mac"`
	Label        string `json:"label"`
	GraceMinutes int    `json:"graceMinutes"`
}

// WatchDevices is every watched device, for one router or, with "", all.
func (d *DB) WatchDevices(routerID string) ([]WatchDevice, error) {
	q := `SELECT id, router_id, mac, label, grace_minutes FROM watch_devices`
	var args []any
	if routerID != "" {
		q += ` WHERE router_id = ?`
		args = append(args, routerID)
	}
	rows, err := d.sql.Query(q+` ORDER BY router_id, label, mac`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WatchDevice{}
	for rows.Next() {
		var w WatchDevice
		if err := rows.Scan(&w.ID, &w.RouterID, &w.MAC, &w.Label, &w.GraceMinutes); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// errBadMAC refuses an address the watcher could never match.
var errBadMAC = errors.New("a MAC address is AA:BB:CC:DD:EE:FF")

// SaveWatchDevice adds a device to the watch list, or updates its label and
// grace time when it is already on it. The MAC is stored upper-case, the way
// every RouterOS table reports it.
func (d *DB) SaveWatchDevice(w WatchDevice) error {
	mac := strings.ToUpper(strings.TrimSpace(w.MAC))
	if len(mac) != 17 || strings.Count(mac, ":") != 5 {
		return errBadMAC
	}
	if w.GraceMinutes < 1 {
		w.GraceMinutes = 10
	}
	_, err := d.sql.Exec(`INSERT INTO watch_devices (router_id, mac, label, grace_minutes) VALUES (?, ?, ?, ?)
	   ON CONFLICT(router_id, mac) DO UPDATE SET label = excluded.label, grace_minutes = excluded.grace_minutes`,
		w.RouterID, mac, strings.TrimSpace(w.Label), w.GraceMinutes)
	return err
}

// DeleteWatchDevice takes a device off the watch list.
func (d *DB) DeleteWatchDevice(routerID, mac string) error {
	_, err := d.sql.Exec(`DELETE FROM watch_devices WHERE router_id = ? AND mac = ?`,
		routerID, strings.ToUpper(mac))
	return err
}

// HasWatchDevice is whether a device is on the watch list.
func (d *DB) HasWatchDevice(routerID, mac string) bool {
	var n int
	err := d.sql.QueryRow(`SELECT COUNT(*) FROM watch_devices WHERE router_id = ? AND mac = ?`,
		routerID, strings.ToUpper(mac)).Scan(&n)
	return err == nil && n > 0
}

// WifiSample is one Wi-Fi client at one minute.
type WifiSample struct {
	TS     int64  `json:"ts"`
	MAC    string `json:"mac"`
	Iface  string `json:"iface"`
	AP     string `json:"ap"`
	SSID   string `json:"ssid"`
	Signal *int   `json:"signal"`
	TxRate string `json:"txRate"`
}

// InsertWifiSamples writes one router's minute, in one transaction.
func (d *DB) InsertWifiSamples(routerID string, rows []WifiSample) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`INSERT INTO wifi_samples (router_id, ts, mac, iface, ap, ssid, signal, tx_rate)
	   VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(routerID, r.TS, r.MAC, r.Iface, r.AP, r.SSID, r.Signal, r.TxRate); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// WifiSamples is one client's history in [from, to], oldest first.
func (d *DB) WifiSamples(routerID, mac string, from, to int64) ([]WifiSample, error) {
	rows, err := d.sql.Query(`SELECT ts, mac, iface, ap, ssid, signal, tx_rate FROM wifi_samples
	  WHERE router_id = ? AND mac = ? AND ts >= ? AND ts <= ? ORDER BY ts`,
		routerID, strings.ToUpper(mac), from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WifiSample{}
	for rows.Next() {
		var s WifiSample
		var sig sql.NullInt64
		if err := rows.Scan(&s.TS, &s.MAC, &s.Iface, &s.AP, &s.SSID, &sig, &s.TxRate); err != nil {
			return nil, err
		}
		if sig.Valid {
			v := int(sig.Int64)
			s.Signal = &v
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// WifiHistoryRouters is the routers whose clients are recorded, which are kept
// polling while nobody watches.
func (d *DB) WifiHistoryRouters() (map[string]bool, error) {
	rows, err := d.sql.Query(`SELECT router_id FROM wifi_history_routers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// SetWifiHistory switches the recording of a router's clients on or off.
func (d *DB) SetWifiHistory(routerID string, on bool) error {
	q := `DELETE FROM wifi_history_routers WHERE router_id = ?`
	if on {
		q = `INSERT OR IGNORE INTO wifi_history_routers (router_id) VALUES (?)`
	}
	_, err := d.sql.Exec(q, routerID)
	return err
}
