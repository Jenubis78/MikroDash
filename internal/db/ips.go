package db

// Reading and writing the IPS page's rules, sensors and events; see
// ips_schema.go.

import (
	"database/sql"
	"encoding/json"

	"mikrodash/internal/ips"
)

func jsonList(v []string) string {
	b, _ := json.Marshal(append([]string{}, v...))
	return string(b)
}

func listOf(s string) []string {
	var out []string
	if json.Unmarshal([]byte(s), &out) != nil || out == nil {
		return []string{}
	}
	return out
}

// IPSRules is every rule, in the order the first match is taken.
func (d *DB) IPSRules() ([]ips.Rule, error) {
	rows, err := d.sql.Query(`SELECT id, name, enabled, apps, categories, breeds, risks, hosts, clients,
	        countries, action, timeout_min FROM ips_rules ORDER BY position, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ips.Rule{}
	for rows.Next() {
		var r ips.Rule
		var apps, cats, breeds, risks, hosts, clients, countries string
		if err := rows.Scan(&r.ID, &r.Name, &r.Enabled, &apps, &cats, &breeds, &risks, &hosts, &clients,
			&countries, &r.Action, &r.TimeoutMin); err != nil {
			return nil, err
		}
		r.Apps, r.Categories, r.Breeds = listOf(apps), listOf(cats), listOf(breeds)
		r.Risks, r.Hosts, r.Clients = listOf(risks), listOf(hosts), listOf(clients)
		r.Countries = listOf(countries)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveIPSRule creates a rule at the end (ID 0) or replaces one in place, and
// returns its id. The rule is validated by the caller.
func (d *DB) SaveIPSRule(r ips.Rule) (int64, error) {
	if r.ID == 0 {
		res, err := d.sql.Exec(`INSERT INTO ips_rules (position, name, enabled, apps, categories, breeds, risks,
		        hosts, clients, countries, action, timeout_min)
		        VALUES ((SELECT COALESCE(MAX(position), 0) + 1 FROM ips_rules), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.Name, r.Enabled, jsonList(r.Apps), jsonList(r.Categories), jsonList(r.Breeds), jsonList(r.Risks),
			jsonList(r.Hosts), jsonList(r.Clients), jsonList(r.Countries), r.Action, r.TimeoutMin)
		if err != nil {
			return 0, err
		}
		return res.LastInsertId()
	}
	res, err := d.sql.Exec(`UPDATE ips_rules SET name = ?, enabled = ?, apps = ?, categories = ?, breeds = ?,
	        risks = ?, hosts = ?, clients = ?, countries = ?, action = ?, timeout_min = ? WHERE id = ?`,
		r.Name, r.Enabled, jsonList(r.Apps), jsonList(r.Categories), jsonList(r.Breeds), jsonList(r.Risks),
		jsonList(r.Hosts), jsonList(r.Clients), jsonList(r.Countries), r.Action, r.TimeoutMin, r.ID)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, sql.ErrNoRows
	}
	return r.ID, nil
}

// DeleteIPSRule forgets a rule. What it listed times out on the routers.
func (d *DB) DeleteIPSRule(id int64) error {
	_, err := d.sql.Exec(`DELETE FROM ips_rules WHERE id = ?`, id)
	return err
}

// OrderIPSRules puts the rules in this order; a rule the list does not name
// keeps its place after the named ones.
func (d *DB) OrderIPSRules(ids []int64) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`UPDATE ips_rules SET position = position + ?`, len(ids)+1); err != nil {
		return err
	}
	for i, id := range ids {
		if _, err := tx.Exec(`UPDATE ips_rules SET position = ? WHERE id = ?`, i+1, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// IPSSensor is one router's sensor. Token is sealed.
type IPSSensor struct {
	RouterID   string   `json:"routerId"`
	Address    string   `json:"address"`
	Token      string   `json:"-"`
	Enforce    bool     `json:"enforce"`
	SniffBytes int      `json:"sniffBytes"`
	Protected  []string `json:"protected"`
	Disk       string   `json:"disk"`
	Image      string   `json:"image"`
	// Network is the router interface the container joins; empty = by address.
	Network string `json:"network"`
	// DHCP leaves the address to the network's DHCP server; Address is then empty.
	DHCP bool `json:"dhcp"`
}

// IPSSensors is every router's sensor.
func (d *DB) IPSSensors() ([]IPSSensor, error) {
	rows, err := d.sql.Query(`SELECT router_id, address, token, enforce, sniff_bytes, protected, disk, image, network, dhcp
	   FROM ips_sensors ORDER BY router_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPSSensor{}
	for rows.Next() {
		var s IPSSensor
		var protected string
		if err := rows.Scan(&s.RouterID, &s.Address, &s.Token, &s.Enforce, &s.SniffBytes, &protected,
			&s.Disk, &s.Image, &s.Network, &s.DHCP); err != nil {
			return nil, err
		}
		s.Protected = listOf(protected)
		out = append(out, s)
	}
	return out, rows.Err()
}

// SaveIPSSensor creates or replaces a router's sensor.
func (d *DB) SaveIPSSensor(s IPSSensor) error {
	_, err := d.sql.Exec(`INSERT INTO ips_sensors (router_id, address, token, enforce, sniff_bytes, protected, disk, image,
	        network, dhcp)
	        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	        ON CONFLICT (router_id) DO UPDATE SET address = excluded.address, token = excluded.token,
	        enforce = excluded.enforce, sniff_bytes = excluded.sniff_bytes, protected = excluded.protected,
	        disk = excluded.disk, image = excluded.image, network = excluded.network, dhcp = excluded.dhcp`,
		s.RouterID, s.Address, s.Token, s.Enforce, s.SniffBytes, jsonList(s.Protected), s.Disk, s.Image,
		s.Network, s.DHCP)
	return err
}

// DeleteIPSSensor forgets a router's sensor.
func (d *DB) DeleteIPSSensor(routerID string) error {
	_, err := d.sql.Exec(`DELETE FROM ips_sensors WHERE router_id = ?`, routerID)
	return err
}

// IPSEvent is one decision a rule made.
type IPSEvent struct {
	ID         int64    `json:"id"`
	TS         int64    `json:"ts"`
	RouterID   string   `json:"routerId"`
	RuleID     int64    `json:"ruleId"`
	RuleName   string   `json:"ruleName"`
	Action     string   `json:"action"`
	Result     string   `json:"result"`
	Target     string   `json:"target"`
	Client     string   `json:"client"`
	Server     string   `json:"server"`
	ServerPort int      `json:"serverPort"`
	L4         string   `json:"l4"`
	App        string   `json:"app"`
	Category   string   `json:"category"`
	Host       string   `json:"host"`
	Risks      []string `json:"risks"`
}

// InsertIPSEvent records one decision.
func (d *DB) InsertIPSEvent(e IPSEvent) error {
	_, err := d.sql.Exec(`INSERT INTO ips_events (ts, router_id, rule_id, rule_name, action, result, target,
	        client, server, server_port, l4, app, category, host, risks)
	        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS, e.RouterID, e.RuleID, e.RuleName, e.Action, e.Result, e.Target, e.Client, e.Server, e.ServerPort,
		e.L4, e.App, e.Category, e.Host, jsonList(e.Risks))
	return err
}

// IPSEvents is a router's newest decisions, newest first.
func (d *DB) IPSEvents(routerID string, limit int) ([]IPSEvent, error) {
	rows, err := d.sql.Query(`SELECT id, ts, router_id, rule_id, rule_name, action, result, target, client, server,
	        server_port, l4, app, category, host, risks
	   FROM ips_events WHERE router_id = ? ORDER BY ts DESC, id DESC LIMIT ?`, routerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPSEvent{}
	for rows.Next() {
		var e IPSEvent
		var risks string
		if err := rows.Scan(&e.ID, &e.TS, &e.RouterID, &e.RuleID, &e.RuleName, &e.Action, &e.Result, &e.Target,
			&e.Client, &e.Server, &e.ServerPort, &e.L4, &e.App, &e.Category, &e.Host, &risks); err != nil {
			return nil, err
		}
		e.Risks = listOf(risks)
		out = append(out, e)
	}
	return out, rows.Err()
}

// IPSGeo is one router's geofencing: what it should hold, and what the last
// apply did.
type IPSGeo struct {
	RouterID  string   `json:"routerId"`
	Countries []string `json:"countries"`
	Direction string   `json:"direction"`
	AppliedAt int64    `json:"appliedAt"`
	Result    string   `json:"result"`
	Entries   int      `json:"entries"`
}

// IPSGeoOf is a router's geofencing; a router without a row has none chosen.
func (d *DB) IPSGeoOf(routerID string) (IPSGeo, error) {
	g := IPSGeo{RouterID: routerID, Countries: []string{}, Direction: ips.GeoBoth}
	var countries string
	err := d.sql.QueryRow(`SELECT countries, direction, applied_at, result, entries FROM ips_geo WHERE router_id = ?`,
		routerID).Scan(&countries, &g.Direction, &g.AppliedAt, &g.Result, &g.Entries)
	if err == sql.ErrNoRows {
		return g, nil
	}
	g.Countries = listOf(countries)
	return g, err
}

// SaveIPSGeo stores a router's choice of countries and direction, keeping what
// the last apply recorded.
func (d *DB) SaveIPSGeo(routerID string, countries []string, direction string) error {
	_, err := d.sql.Exec(`INSERT INTO ips_geo (router_id, countries, direction) VALUES (?, ?, ?)
	        ON CONFLICT (router_id) DO UPDATE SET countries = excluded.countries, direction = excluded.direction`,
		routerID, jsonList(countries), direction)
	return err
}

// RecordIPSGeo stores what an apply (or a removal) did.
func (d *DB) RecordIPSGeo(routerID string, at int64, result string, entries int) error {
	_, err := d.sql.Exec(`INSERT INTO ips_geo (router_id, applied_at, result, entries) VALUES (?, ?, ?, ?)
	        ON CONFLICT (router_id) DO UPDATE SET applied_at = excluded.applied_at, result = excluded.result,
	        entries = excluded.entries`, routerID, at, result, entries)
	return err
}
