package database

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

//go:embed schema.sql
var schemaSQL string

var columnMigrations = []string{
	`ALTER TABLE engagements ADD COLUMN IF NOT EXISTS started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP`,
	`ALTER TABLE engagements ADD COLUMN IF NOT EXISTS finished_at TIMESTAMP WITH TIME ZONE`,
	`ALTER TABLE targets ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb`,
	`ALTER TABLE targets ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP`,
	`ALTER TABLE asset_nodes ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP`,
	`ALTER TABLE asset_nodes ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS target_id UUID REFERENCES targets(id) ON DELETE CASCADE`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS confidence NUMERIC(4, 2) DEFAULT 0.0`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_score NUMERIC(4, 2) DEFAULT 0.0`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS endpoint TEXT DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence TEXT`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS poc_script TEXT`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS poc_details JSONB DEFAULT '{}'::jsonb`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS status VARCHAR(24) DEFAULT 'CANDIDATE'`,
	`ALTER TABLE findings ALTER COLUMN status SET DEFAULT 'CANDIDATE'`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP`,
}

// DB wraps a PostgreSQL *sql.DB connection pool.
type DB struct {
	*sql.DB
}

var validSSLModes = map[string]struct{}{
	"disable":     {},
	"allow":       {},
	"prefer":      {},
	"require":     {},
	"verify-ca":   {},
	"verify-full": {},
}

func isLoopbackDBHost(host string) bool {
	clean := strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(clean, "localhost") {
		return true
	}
	ip := net.ParseIP(clean)
	return ip != nil && ip.IsLoopback()
}

// ResolveSSLMode returns a validated PostgreSQL sslmode (defaulting to disable only for loopback, require for remote).
func ResolveSSLMode(host, explicitMode string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(explicitMode))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_DB_SSLMODE")))
	}
	if mode == "" {
		if isLoopbackDBHost(host) {
			return "disable", nil
		}
		return "require", nil
	}
	if _, ok := validSSLModes[mode]; !ok {
		return "", fmt.Errorf("invalid PostgreSQL sslmode %q", mode)
	}
	return mode, nil
}

// Connect opens a PostgreSQL connection pool using ARTEX_DB_SSLMODE (or secure defaults).
func Connect(host string, port int, user, password, dbname string) (*DB, error) {
	return ConnectWithSSLMode(host, port, user, password, dbname, "")
}

// ConnectWithSSLMode opens a PostgreSQL connection pool, verifies connectivity, and applies idempotent schema migrations.
func ConnectWithSSLMode(host string, port int, user, password, dbname, sslmode string) (*DB, error) {
	resolvedSSLMode, err := ResolveSSLMode(host, sslmode)
	if err != nil {
		return nil, err
	}
	if resolvedSSLMode == "disable" && !isLoopbackDBHost(host) {
		log.Printf("[DB] WARNING: sslmode=disable configured for non-loopback PostgreSQL host %q", host)
	}

	dsnURL := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
		Path:   "/" + dbname,
	}
	q := dsnURL.Query()
	q.Set("sslmode", resolvedSSLMode)
	dsnURL.RawQuery = q.Encode()

	sqlDB, err := sql.Open("postgres", dsnURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()

	if err := sqlDB.PingContext(pingCtx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	wrapped := &DB{sqlDB}
	migCtx, migCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer migCancel()

	if err := wrapped.Migrate(migCtx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("failed to migrate database schema: %w", err)
	}

	log.Printf("[DB] Connected successfully to PostgreSQL (%s:%d/%s sslmode=%s)", host, port, dbname, resolvedSSLMode)
	return wrapped, nil
}

// Migrate ensures all base tables, additive columns, and indexes exist without dropping existing data.
func (db *DB) Migrate(ctx context.Context) error {
	if db == nil || db.DB == nil {
		return fmt.Errorf("database connection is nil")
	}

	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("schema ddl execution failed: %w", err)
	}

	for _, stmt := range columnMigrations {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migration statement %q failed: %w", stmt, err)
		}
	}

	return nil
}
