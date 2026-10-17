package db

// The tables of two optional features (Settings -> Features), migration 36.
//
//	watch_devices  a device whose absence raises an alert
//	wifi_samples   one Wi-Fi client's signal and access point, once a minute
//	wifi_history_routers  the routers whose clients are recorded
//
// Shared by `freshSchemaDDL` and `portMigrations[36]`, the rule
// monitorruns_schema.go gives: a new database and a migrated one must not be
// able to describe different tables, and `IF NOT EXISTS` makes it replayable.
//
// All three belong to a router and go with it (purge.go); `wifi_samples` ages out
// on its own retention (prune.go).
const clientWatchDDL = `
CREATE TABLE IF NOT EXISTS watch_devices (
          id            INTEGER PRIMARY KEY,
          router_id     TEXT    NOT NULL,
          mac           TEXT    NOT NULL,
          label         TEXT    NOT NULL DEFAULT '',
          grace_minutes INTEGER NOT NULL DEFAULT 10,
          UNIQUE(router_id, mac)
        );
CREATE TABLE IF NOT EXISTS wifi_samples (
          router_id TEXT    NOT NULL,
          ts        INTEGER NOT NULL,
          mac       TEXT    NOT NULL,
          iface     TEXT    NOT NULL DEFAULT '',
          ap        TEXT    NOT NULL DEFAULT '',
          ssid      TEXT    NOT NULL DEFAULT '',
          signal    INTEGER,
          tx_rate   TEXT    NOT NULL DEFAULT ''
        );
CREATE TABLE IF NOT EXISTS wifi_history_routers (
          router_id TEXT PRIMARY KEY
        );
CREATE INDEX IF NOT EXISTS idx_wifi_samples_client ON wifi_samples(router_id, mac, ts);
CREATE INDEX IF NOT EXISTS idx_wifi_samples_ts ON wifi_samples(ts);
`
