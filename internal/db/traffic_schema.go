package db

// The Traffic page's settings (internal/traffic), migration 43. Its data is
// not here: the minute rows live in /data/traffic.db or in ClickHouse.
//
// Shared by `freshSchemaDDL` and `portMigrations[43]`, as ips_schema.go is.
//
// traffic_settings is one row: which backend stores the rows (`sqlite` or
// `clickhouse`), how to reach ClickHouse (its password sealed with the
// settings envelope before it gets here, never in the clear), how long it
// keeps flows, the UDP port MikroDash takes IPFIX on, and the address the
// routers are told to send it to (empty: the one the router sees MikroDash
// connect from).
//
// traffic_routers is each router whose Traffic Flow MikroDash set up: the
// interfaces it counts on, and what the last apply did.
const trafficDDL = `
CREATE TABLE IF NOT EXISTS traffic_settings (
          id          INTEGER PRIMARY KEY CHECK (id = 1),
          backend     TEXT    NOT NULL DEFAULT 'sqlite',
          ch_url      TEXT    NOT NULL DEFAULT '',
          ch_user     TEXT    NOT NULL DEFAULT '',
          ch_password TEXT    NOT NULL DEFAULT '',
          ch_database TEXT    NOT NULL DEFAULT '',
          flow_days   INTEGER NOT NULL DEFAULT 90,
          port        INTEGER NOT NULL DEFAULT 2055,
          collector   TEXT    NOT NULL DEFAULT ''
        );
CREATE TABLE IF NOT EXISTS traffic_routers (
          router_id   TEXT    PRIMARY KEY,
          enabled     INTEGER NOT NULL DEFAULT 1,
          interfaces  TEXT    NOT NULL DEFAULT '',
          applied_at  INTEGER NOT NULL DEFAULT 0,
          result      TEXT    NOT NULL DEFAULT ''
        );
`
