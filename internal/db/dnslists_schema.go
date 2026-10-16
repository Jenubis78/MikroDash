package db

// dns_lists: a domain list kept in step with FWD entries on chosen routers
// (Settings -> Features -> Domain list subscriptions), migration 35.
//
// Shared by `freshSchemaDDL` and `portMigrations[35]`, the rule
// monitorruns_schema.go gives: a new database and a migrated one must not be
// able to describe different tables, and `IF NOT EXISTS` makes it replayable.
//
// A list names routers in `router_ids` and outlives any one of them: removing a
// router drops it from the next sync, not the list. `last_count` is how many
// domains the last accepted sync held, the measure a later fetch is compared
// with before it may remove anything.
const dnsListsDDL = `
CREATE TABLE IF NOT EXISTS dns_lists (
          id              INTEGER PRIMARY KEY,
          name            TEXT    NOT NULL UNIQUE,
          source_url      TEXT    NOT NULL DEFAULT '',
          domains         TEXT    NOT NULL DEFAULT '',
          address_list    TEXT    NOT NULL DEFAULT '',
          forward_to      TEXT    NOT NULL DEFAULT '',
          match_subdomain INTEGER NOT NULL DEFAULT 1,
          router_ids      TEXT    NOT NULL DEFAULT '[]',
          interval_hours  INTEGER NOT NULL DEFAULT 0,
          last_sync_at    INTEGER NOT NULL DEFAULT 0,
          last_result     TEXT    NOT NULL DEFAULT '',
          last_count      INTEGER NOT NULL DEFAULT 0
        );
`
