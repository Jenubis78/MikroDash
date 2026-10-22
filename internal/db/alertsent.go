package db

// `alert_sent`: which notification channel was actually sent the breach of an
// alert episode, so its recovery goes only there (migration 37).
//
// A channel filters what it is told: its own CPU and ping-loss thresholds, its
// own cooldown. Its recovery has to follow the same decision, or a channel set
// to 90% is told "CPU back to normal" about a 71% spike it never heard about.
// That is what Telegram did on 2026-10-22.
//
// A ROW, NOT A MAP IN MEMORY, because an episode outlives a restart: an open
// alert stays open in `alert_events`, its recovery fires after the process comes
// back, and the channel that was told about the breach must still be told the
// all-clear. Keyed on what the recovery carries: router, the stored alert type
// (the breach's, which is also the recovery's `ResolveType`) and the subject.
//
// Cleared when the recovery is dispatched and when a new episode of the same
// alert starts, so a row never outlives its episode by more than one alert.

const alertSentDDL = `
CREATE TABLE IF NOT EXISTS alert_sent (
          router_id  TEXT    NOT NULL,
          alert_type TEXT    NOT NULL,
          subject    TEXT    NOT NULL DEFAULT '',
          channel_id TEXT    NOT NULL,
          sent_at    INTEGER NOT NULL,
          PRIMARY KEY (router_id, alert_type, subject, channel_id)
        );
`

// MarkAlertSent records that `channelID` was sent this alert's breach.
func (d *DB) MarkAlertSent(routerID, alertType, subject, channelID string, at int64) error {
	_, err := d.sql.Exec(
		`INSERT OR REPLACE INTO alert_sent (router_id, alert_type, subject, channel_id, sent_at)
		 VALUES (?, ?, ?, ?, ?)`, routerID, alertType, subject, channelID, at)
	return err
}

// AlertSentChannels is every channel that was sent this alert's breach.
func (d *DB) AlertSentChannels(routerID, alertType, subject string) (map[string]bool, error) {
	rows, err := d.sql.Query(
		`SELECT channel_id FROM alert_sent WHERE router_id = ? AND alert_type = ? AND subject = ?`,
		routerID, alertType, subject)
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

// ClearAlertSent forgets an episode's channels.
func (d *DB) ClearAlertSent(routerID, alertType, subject string) error {
	_, err := d.sql.Exec(
		`DELETE FROM alert_sent WHERE router_id = ? AND alert_type = ? AND subject = ?`,
		routerID, alertType, subject)
	return err
}
