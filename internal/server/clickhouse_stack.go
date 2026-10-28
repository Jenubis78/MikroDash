package server

// The stack's ClickHouse: a service beside MikroDash in its compose stack
// (docker-compose.yml, deploy/portainer), which Traffic Analysis uses with
// nothing typed in.
//
// ── A PASSWORD NOBODY CHOSE ─────────────────────────────────────────────────
//
// MikroDash writes a random password into a volume both containers mount
// (-clickhouse-secret), before ClickHouse starts: the stack starts ClickHouse
// once MikroDash is healthy, and the image reads its password from that file
// (CLICKHOUSE_PASSWORD_FILE). The file is made once and kept; MikroDash reads
// it again every time it connects. ClickHouse's port is not published, so it
// is reachable from the stack's network alone.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"mikrodash/internal/traffic"
)

// trafficBackendStack is the backend setting for the stack's ClickHouse.
const trafficBackendStack = "stack"

// The stack's user and database, as the compose files create them.
const (
	stackCHUser     = "mikrodash"
	stackCHDatabase = "mikrodash"
)

// clickHouseStack is where the stack's ClickHouse is, from -clickhouse-stack
// and -clickhouse-secret; a zero URL is a stack without one.
type clickHouseStack struct {
	URL        string
	SecretFile string
}

// ensureSecret makes the password file when it is missing.
func (c clickHouseStack) ensureSecret() error {
	if c.SecretFile == "" {
		return errors.New("no -clickhouse-secret file")
	}
	if b, err := os.ReadFile(c.SecretFile); err == nil && len(strings.TrimSpace(string(b))) >= 16 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.SecretFile), 0o700); err != nil {
		return err
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	return os.WriteFile(c.SecretFile, []byte(hex.EncodeToString(raw)), 0o600)
}

// config is how to reach it.
func (c clickHouseStack) config(flowDays int) (traffic.ClickHouseConfig, error) {
	if c.URL == "" {
		return traffic.ClickHouseConfig{}, errors.New("this stack has no ClickHouse (-clickhouse-stack is not set)")
	}
	b, err := os.ReadFile(c.SecretFile)
	if err != nil {
		return traffic.ClickHouseConfig{}, errors.New("the stack's ClickHouse password file cannot be read: " + err.Error())
	}
	return traffic.ClickHouseConfig{URL: c.URL, User: stackCHUser, Password: strings.TrimSpace(string(b)),
		Database: stackCHDatabase, FlowDays: flowDays}, nil
}
