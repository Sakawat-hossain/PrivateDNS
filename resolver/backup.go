package resolver

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Backup writes a consistent snapshot of the policy database to dest.
//
// This exists as a Go function rather than a shell one-liner because copying
// the file is wrong. The database runs in WAL mode, so at any moment the
// committed state is split between the main file and the write-ahead log —
// `cp policy.db backup.db` captures the first without the second and produces
// a backup that restores to a torn, sometimes unreadable, database.
//
// VACUUM INTO takes a read transaction and writes a complete, defragmented
// copy, safely while the service is still serving. Nothing has to be stopped.
func Backup(dbPath, dest string) error {
	if strings.TrimSpace(dest) == "" {
		return fmt.Errorf("destination is required")
	}

	// VACUUM INTO refuses to overwrite, which is the behaviour we want — a
	// backup that silently replaced an earlier one would be a poor place to
	// discover a typo in a path.
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("%s already exists", dest)
	}

	if dir := filepath.Dir(dest); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create backup directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(30000)")
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	// The path is interpolated because VACUUM INTO does not accept a bound
	// parameter. Quotes are doubled so a path containing one cannot terminate
	// the literal early.
	quoted := strings.ReplaceAll(dest, "'", "''")
	if _, err := db.Exec(fmt.Sprintf("VACUUM INTO '%s'", quoted)); err != nil {
		return fmt.Errorf("vacuum into %s: %w", dest, err)
	}

	// A backup carries every customer record and the whole audit log.
	if err := os.Chmod(dest, 0o600); err != nil {
		return fmt.Errorf("restrict backup permissions: %w", err)
	}

	info, err := os.Stat(dest)
	if err != nil {
		return err
	}
	if info.Size() == 0 {
		return fmt.Errorf("backup at %s is empty", dest)
	}

	return nil
}

// VerifyBackup checks that a file is a usable policy database rather than a
// truncated or corrupt one.
//
// Worth doing at the moment a backup is taken. A backup nobody has opened is
// an assumption, and the moment it matters is the worst time to find out.
func VerifyBackup(path string) (schemaVersion int, tenants int, err error) {
	if _, err := os.Stat(path); err != nil {
		return 0, 0, fmt.Errorf("backup not found: %w", err)
	}

	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(10000)&mode=ro")
	if err != nil {
		return 0, 0, fmt.Errorf("open backup: %w", err)
	}
	defer db.Close()

	var check string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil {
		return 0, 0, fmt.Errorf("integrity check failed to run: %w", err)
	}
	if check != "ok" {
		return 0, 0, fmt.Errorf("integrity check reported: %s", check)
	}

	if err := db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&schemaVersion); err != nil {
		return 0, 0, fmt.Errorf("backup has no migration history: %w", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM tenants`).Scan(&tenants); err != nil {
		return schemaVersion, 0, fmt.Errorf("backup has no tenants table: %w", err)
	}

	return schemaVersion, tenants, nil
}
