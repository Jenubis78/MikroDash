package db

// Reading and writing the Traffic page's settings; see traffic_schema.go.

import "database/sql"

// TrafficSettings is the one settings row. CHPassword is sealed.
type TrafficSettings struct {
	Backend    string `json:"backend"`
	CHURL      string `json:"chUrl"`
	CHUser     string `json:"chUser"`
	CHPassword string `json:"-"`
	CHDatabase string `json:"chDatabase"`
	FlowDays   int    `json:"flowDays"`
	Port       int    `json:"port"`
	Collector  string `json:"collector"`
	// Saved is whether a row exists: an install that never chose a backend
	// takes the stack's ClickHouse when there is one.
	Saved bool `json:"-"`
}

// DefaultTrafficSettings is what an install that never saved any uses.
var DefaultTrafficSettings = TrafficSettings{Backend: "sqlite", FlowDays: 90, Port: 2055}

// TrafficSettingsGet is the settings, or the defaults.
func (d *DB) TrafficSettingsGet() (TrafficSettings, error) {
	s := DefaultTrafficSettings
	err := d.sql.QueryRow(`SELECT backend, ch_url, ch_user, ch_password, ch_database, flow_days, port, collector
	   FROM traffic_settings WHERE id = 1`).Scan(&s.Backend, &s.CHURL, &s.CHUser, &s.CHPassword, &s.CHDatabase,
		&s.FlowDays, &s.Port, &s.Collector)
	if err == sql.ErrNoRows {
		return DefaultTrafficSettings, nil
	}
	s.Saved = err == nil
	return s, err
}

// SaveTrafficSettings replaces the settings.
func (d *DB) SaveTrafficSettings(s TrafficSettings) error {
	_, err := d.sql.Exec(`INSERT INTO traffic_settings (id, backend, ch_url, ch_user, ch_password, ch_database,
	        flow_days, port, collector) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
	        ON CONFLICT (id) DO UPDATE SET backend = excluded.backend, ch_url = excluded.ch_url,
	        ch_user = excluded.ch_user, ch_password = excluded.ch_password, ch_database = excluded.ch_database,
	        flow_days = excluded.flow_days, port = excluded.port, collector = excluded.collector`,
		s.Backend, s.CHURL, s.CHUser, s.CHPassword, s.CHDatabase, s.FlowDays, s.Port, s.Collector)
	return err
}

// TrafficRouter is one router's Traffic Flow, as MikroDash set it up.
type TrafficRouter struct {
	RouterID   string `json:"routerId"`
	Enabled    bool   `json:"enabled"`
	Interfaces string `json:"interfaces"`
	AppliedAt  int64  `json:"appliedAt"`
	Result     string `json:"result"`
}

// TrafficRouters is every router with a row.
func (d *DB) TrafficRouters() ([]TrafficRouter, error) {
	rows, err := d.sql.Query(`SELECT router_id, enabled, interfaces, applied_at, result FROM traffic_routers ORDER BY router_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrafficRouter{}
	for rows.Next() {
		var r TrafficRouter
		if err := rows.Scan(&r.RouterID, &r.Enabled, &r.Interfaces, &r.AppliedAt, &r.Result); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveTrafficRouter creates or replaces a router's row.
func (d *DB) SaveTrafficRouter(r TrafficRouter) error {
	_, err := d.sql.Exec(`INSERT INTO traffic_routers (router_id, enabled, interfaces, applied_at, result)
	        VALUES (?, ?, ?, ?, ?)
	        ON CONFLICT (router_id) DO UPDATE SET enabled = excluded.enabled, interfaces = excluded.interfaces,
	        applied_at = excluded.applied_at, result = excluded.result`,
		r.RouterID, r.Enabled, r.Interfaces, r.AppliedAt, r.Result)
	return err
}
