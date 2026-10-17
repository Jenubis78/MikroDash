package db

// Reading and writing domain lists; see dnslists_schema.go.

import (
	"database/sql"
	"encoding/json"
)

// DNSList is a domain list kept in step with FWD entries.
type DNSList struct {
	ID             int64    `json:"id"`
	Name           string   `json:"name"`
	SourceURL      string   `json:"sourceUrl"`
	Domains        string   `json:"domains"`
	AddressList    string   `json:"addressList"`
	ForwardTo      string   `json:"forwardTo"`
	MatchSubdomain bool     `json:"matchSubdomain"`
	RouterIDs      []string `json:"routerIds"`
	IntervalHours  int      `json:"intervalHours"`
	LastSyncAt     int64    `json:"lastSyncAt"`
	LastResult     string   `json:"lastResult"`
	LastCount      int      `json:"lastCount"`
	Dropped        []string `json:"dropped"`
}

// DNSLists is every list, by name.
func (d *DB) DNSLists() ([]DNSList, error) {
	rows, err := d.sql.Query(`SELECT id, name, source_url, domains, address_list, forward_to,
	        match_subdomain, router_ids, interval_hours, last_sync_at, last_result, last_count, dropped_routers
	   FROM dns_lists ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DNSList{}
	for rows.Next() {
		var l DNSList
		var routers, dropped string
		if err := rows.Scan(&l.ID, &l.Name, &l.SourceURL, &l.Domains, &l.AddressList, &l.ForwardTo,
			&l.MatchSubdomain, &routers, &l.IntervalHours, &l.LastSyncAt, &l.LastResult, &l.LastCount,
			&dropped); err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(routers), &l.RouterIDs) != nil || l.RouterIDs == nil {
			l.RouterIDs = []string{}
		}
		if json.Unmarshal([]byte(dropped), &l.Dropped) != nil || l.Dropped == nil {
			l.Dropped = []string{}
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SaveDNSList creates a list (ID 0) or replaces one's definition, leaving its
// sync record alone, and returns the id.
func (d *DB) SaveDNSList(l DNSList) (int64, error) {
	routers, _ := json.Marshal(l.RouterIDs)
	dropped, _ := json.Marshal(append([]string{}, l.Dropped...))
	if l.ID == 0 {
		res, err := d.sql.Exec(`INSERT INTO dns_lists (name, source_url, domains, address_list, forward_to,
		        match_subdomain, router_ids, interval_hours, dropped_routers) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			l.Name, l.SourceURL, l.Domains, l.AddressList, l.ForwardTo, l.MatchSubdomain,
			string(routers), l.IntervalHours, string(dropped))
		if err != nil {
			return 0, err
		}
		return res.LastInsertId()
	}
	res, err := d.sql.Exec(`UPDATE dns_lists SET name = ?, source_url = ?, domains = ?, address_list = ?,
	        forward_to = ?, match_subdomain = ?, router_ids = ?, interval_hours = ?, dropped_routers = ?
	   WHERE id = ?`,
		l.Name, l.SourceURL, l.Domains, l.AddressList, l.ForwardTo, l.MatchSubdomain,
		string(routers), l.IntervalHours, string(dropped), l.ID)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, sql.ErrNoRows
	}
	return l.ID, nil
}

// SetDNSListDropped records the routers a list was taken off whose entries are
// still to be removed.
func (d *DB) SetDNSListDropped(id int64, routers []string) error {
	b, _ := json.Marshal(append([]string{}, routers...))
	_, err := d.sql.Exec(`UPDATE dns_lists SET dropped_routers = ? WHERE id = ?`, string(b), id)
	return err
}

// DeleteDNSList forgets a list. The entries it made stay on the routers.
func (d *DB) DeleteDNSList(id int64) error {
	_, err := d.sql.Exec(`DELETE FROM dns_lists WHERE id = ?`, id)
	return err
}

// MarkDNSListSynced records a sync's time and one-line outcome, and, for a sync
// whose fetch was accepted, how many domains it held (count < 0 keeps the last).
func (d *DB) MarkDNSListSynced(id, at int64, result string, count int) error {
	_, err := d.sql.Exec(`UPDATE dns_lists SET last_sync_at = ?, last_result = ?,
	        last_count = CASE WHEN ? < 0 THEN last_count ELSE ? END WHERE id = ?`, at, result, count, count, id)
	return err
}
