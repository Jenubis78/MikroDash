package db

// The IPS page's tables (internal/ips), migration 38.
//
// Shared by `freshSchemaDDL` and `portMigrations[38]`, the rule
// monitorruns_schema.go gives: a new database and a migrated one must not be
// able to describe different tables, and `IF NOT EXISTS` makes it replayable.
//
// ips_rules is ONE ordered table for every router: `position` is the order the
// first match is taken in. The criteria are JSON arrays of strings.
//
// ips_sensors is a router's sensor: where MikroDash reads it, the token it
// sends (sealed with the settings envelope before it gets here, never in the
// clear), whether its verdicts are written to the router (`enforce`) or only
// recorded, and the operator's protected addresses. A router without a row has
// no IPS. `network` is the router interface (a bridge, or a VLAN on one) the
// container joins, empty to go by the address; `dhcp` leaves the address to
// that network's DHCP server, and `address` is then empty (migration 39).
//
// ips_events is what the rules decided, one row per flow a rule matched with
// any action but allow. `result` is listed, monitor (not enforcing), refused
// (the guard said no; the code follows), already, limited (the per-minute cap)
// or failed. Pruned by age with the history, and to ipsEventsKeep rows a
// router. `hits` is how many times the same decision (rule, result, client,
// server, port) was taken again within ten minutes of its row: one row, not
// one per connection (migration 42).
//
// ips_geo is a router's geofencing (migration 41): the countries whose networks
// its address list holds, the direction its filter rules drop (in, out, both),
// and what the last apply did - when, its outcome, and how many entries the
// list held after it. The list itself lives on the router.
const ipsDDL = `
CREATE TABLE IF NOT EXISTS ips_rules (
          id          INTEGER PRIMARY KEY,
          position    INTEGER NOT NULL DEFAULT 0,
          name        TEXT    NOT NULL,
          enabled     INTEGER NOT NULL DEFAULT 1,
          apps        TEXT    NOT NULL DEFAULT '[]',
          categories  TEXT    NOT NULL DEFAULT '[]',
          breeds      TEXT    NOT NULL DEFAULT '[]',
          risks       TEXT    NOT NULL DEFAULT '[]',
          hosts       TEXT    NOT NULL DEFAULT '[]',
          clients     TEXT    NOT NULL DEFAULT '[]',
          countries   TEXT    NOT NULL DEFAULT '[]',
          action      TEXT    NOT NULL DEFAULT 'log',
          timeout_min INTEGER NOT NULL DEFAULT 0
        );
CREATE TABLE IF NOT EXISTS ips_sensors (
          router_id   TEXT    PRIMARY KEY,
          address     TEXT    NOT NULL,
          token       TEXT    NOT NULL DEFAULT '',
          enforce     INTEGER NOT NULL DEFAULT 0,
          sniff_bytes INTEGER NOT NULL DEFAULT 20000,
          protected   TEXT    NOT NULL DEFAULT '[]',
          disk        TEXT    NOT NULL DEFAULT '',
          image       TEXT    NOT NULL DEFAULT '',
          network     TEXT    NOT NULL DEFAULT '',
          dhcp        INTEGER NOT NULL DEFAULT 0
        );
CREATE TABLE IF NOT EXISTS ips_events (
          id          INTEGER PRIMARY KEY,
          ts          INTEGER NOT NULL,
          router_id   TEXT    NOT NULL,
          rule_id     INTEGER NOT NULL,
          rule_name   TEXT    NOT NULL DEFAULT '',
          action      TEXT    NOT NULL,
          result      TEXT    NOT NULL,
          target      TEXT    NOT NULL DEFAULT '',
          client      TEXT    NOT NULL DEFAULT '',
          server      TEXT    NOT NULL DEFAULT '',
          server_port INTEGER NOT NULL DEFAULT 0,
          l4          TEXT    NOT NULL DEFAULT '',
          app         TEXT    NOT NULL DEFAULT '',
          category    TEXT    NOT NULL DEFAULT '',
          host        TEXT    NOT NULL DEFAULT '',
          risks       TEXT    NOT NULL DEFAULT '[]',
          hits        INTEGER NOT NULL DEFAULT 1
        );
CREATE INDEX IF NOT EXISTS idx_ips_events_router_ts ON ips_events (router_id, ts);
CREATE TABLE IF NOT EXISTS ips_geo (
          router_id   TEXT    PRIMARY KEY,
          countries   TEXT    NOT NULL DEFAULT '[]',
          direction   TEXT    NOT NULL DEFAULT 'both',
          applied_at  INTEGER NOT NULL DEFAULT 0,
          result      TEXT    NOT NULL DEFAULT '',
          entries     INTEGER NOT NULL DEFAULT 0
        );
`
