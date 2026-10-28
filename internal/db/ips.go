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
	// EveryPacket copies whole connections, not their first SniffBytes.
	EveryPacket bool `json:"everyPacket"`
}

// IPSSensors is every router's sensor.
func (d *DB) IPSSensors() ([]IPSSensor, error) {
	rows, err := d.sql.Query(`SELECT router_id, address, token, enforce, sniff_bytes, protected, disk, image, network, dhcp,
	        every_packet FROM ips_sensors ORDER BY router_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPSSensor{}
	for rows.Next() {
		var s IPSSensor
		var protected string
		if err := rows.Scan(&s.RouterID, &s.Address, &s.Token, &s.Enforce, &s.SniffBytes, &protected,
			&s.Disk, &s.Image, &s.Network, &s.DHCP, &s.EveryPacket); err != nil {
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
	        network, dhcp, every_packet)
	        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	        ON CONFLICT (router_id) DO UPDATE SET address = excluded.address, token = excluded.token,
	        enforce = excluded.enforce, sniff_bytes = excluded.sniff_bytes, protected = excluded.protected,
	        disk = excluded.disk, image = excluded.image, network = excluded.network, dhcp = excluded.dhcp,
	        every_packet = excluded.every_packet`,
		s.RouterID, s.Address, s.Token, s.Enforce, s.SniffBytes, jsonList(s.Protected), s.Disk, s.Image,
		s.Network, s.DHCP, s.EveryPacket)
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
	// Hits is how many times this decision was taken while its row was recent.
	Hits int64 `json:"hits"`
}

// InsertIPSEvent records one decision and returns its row's id.
func (d *DB) InsertIPSEvent(e IPSEvent) (int64, error) {
	res, err := d.sql.Exec(`INSERT INTO ips_events (ts, router_id, rule_id, rule_name, action, result, target,
	        client, server, server_port, l4, app, category, host, risks)
	        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS, e.RouterID, e.RuleID, e.RuleName, e.Action, e.Result, e.Target, e.Client, e.Server, e.ServerPort,
		e.L4, e.App, e.Category, e.Host, jsonList(e.Risks))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// AddIPSEventHits adds repeats to decisions already recorded, in one
// transaction: id -> how many more.
func (d *DB) AddIPSEventHits(hits map[int64]int64) error {
	if len(hits) == 0 {
		return nil
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for id, n := range hits {
		if _, err := tx.Exec(`UPDATE ips_events SET hits = hits + ? WHERE id = ?`, n, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// TrimIPSEvents keeps a router's newest `keep` decisions and returns how many
// older ones it deleted.
func (d *DB) TrimIPSEvents(routerID string, keep int) (int64, error) {
	res, err := d.sql.Exec(`DELETE FROM ips_events WHERE router_id = ? AND id <= (
	        SELECT id FROM ips_events WHERE router_id = ? ORDER BY id DESC LIMIT 1 OFFSET ?)`, routerID, routerID, keep)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// IPSEvents is a router's newest decisions, newest first.
func (d *DB) IPSEvents(routerID string, limit int) ([]IPSEvent, error) {
	rows, err := d.sql.Query(`SELECT id, ts, router_id, rule_id, rule_name, action, result, target, client, server,
	        server_port, l4, app, category, host, risks, hits
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
			&e.Client, &e.Server, &e.ServerPort, &e.L4, &e.App, &e.Category, &e.Host, &risks, &e.Hits); err != nil {
			return nil, err
		}
		e.Risks = listOf(risks)
		out = append(out, e)
	}
	return out, rows.Err()
}

// IPSGeo is one router's geofencing: what it should hold, and what the last
// apply did. Countries is the blacklist, Allow the whitelist.
type IPSGeo struct {
	RouterID  string   `json:"routerId"`
	Mode      string   `json:"mode"`
	Countries []string `json:"countries"`
	Allow     []string `json:"allow"`
	Direction string   `json:"direction"`
	AppliedAt int64    `json:"appliedAt"`
	Result    string   `json:"result"`
	Entries   int      `json:"entries"`
	// Saved is whether anybody chose: a router never saved gets its defaults.
	Saved bool `json:"saved"`
}

// IPSGeoOf is a router's geofencing; a router without a row has none chosen.
func (d *DB) IPSGeoOf(routerID string) (IPSGeo, error) {
	g := IPSGeo{RouterID: routerID, Mode: ips.GeoModeBlock, Countries: []string{}, Allow: []string{}, Direction: ips.GeoBoth}
	var countries, allow string
	err := d.sql.QueryRow(`SELECT mode, countries, allow, direction, applied_at, result, entries FROM ips_geo
	   WHERE router_id = ?`, routerID).Scan(&g.Mode, &countries, &allow, &g.Direction, &g.AppliedAt, &g.Result, &g.Entries)
	if err == sql.ErrNoRows {
		return g, nil
	}
	g.Countries, g.Allow, g.Saved = listOf(countries), listOf(allow), true
	return g, err
}

// SaveIPSGeo stores a router's choice, keeping what the last apply recorded.
func (d *DB) SaveIPSGeo(routerID string, c ips.GeoChoice) error {
	_, err := d.sql.Exec(`INSERT INTO ips_geo (router_id, mode, countries, allow, direction) VALUES (?, ?, ?, ?, ?)
	        ON CONFLICT (router_id) DO UPDATE SET mode = excluded.mode, countries = excluded.countries,
	        allow = excluded.allow, direction = excluded.direction`,
		routerID, c.Mode, jsonList(c.Block), jsonList(c.Allow), c.Direction)
	return err
}

// RecordIPSGeo stores what an apply (or a removal) did.
func (d *DB) RecordIPSGeo(routerID string, at int64, result string, entries int) error {
	_, err := d.sql.Exec(`INSERT INTO ips_geo (router_id, applied_at, result, entries) VALUES (?, ?, ?, ?)
	        ON CONFLICT (router_id) DO UPDATE SET applied_at = excluded.applied_at, result = excluded.result,
	        entries = excluded.entries`, routerID, at, result, entries)
	return err
}
