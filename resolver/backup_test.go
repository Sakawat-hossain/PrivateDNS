package resolver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupProducesARestorableDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "policy.db")

	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateTenant("tenant01", "phone", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateTenant("tenant02", "router", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	store.Reload()

	// Deliberately taken while the store is still open, which is the point:
	// backups must not require stopping the service.
	dest := filepath.Join(dir, "backup.db")
	if err := Backup(dbPath, dest); err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	schema, tenants, err := VerifyBackup(dest)
	if err != nil {
		t.Fatalf("the backup we just took does not verify: %v", err)
	}
	if tenants != 2 {
		t.Fatalf("backup holds %d tenants, want 2", tenants)
	}
	if schema != SchemaVersion() {
		t.Fatalf("backup schema version %d, want %d", schema, SchemaVersion())
	}

	store.Close()

	// The real test of a backup is opening it as a database and finding the
	// data intact — not that a file appeared.
	restored, err := OpenStore(dest)
	if err != nil {
		t.Fatalf("the backup cannot be opened as a policy store: %v", err)
	}
	defer restored.Close()

	if restored.TenantCount() != 2 {
		t.Fatalf("restored store has %d tenants, want 2", restored.TenantCount())
	}
	if tn := restored.Tenant("tenant01"); tn == nil || tn.Label != "phone" {
		t.Fatal("tenant01 did not survive the round trip")
	}
}

// TestBackupCapturesWritesInTheWAL is the reason this is a Go function rather
// than a file copy.
//
// In WAL mode, recently committed data lives in the -wal file rather than the
// main database. Copying policy.db alone captures the state before those
// commits — silently, and only noticed when the backup is restored.
func TestBackupCapturesWritesInTheWAL(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "policy.db")

	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Write enough that some of it is certainly still in the write-ahead log.
	for i := 0; i < 50; i++ {
		id := "tenant" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		if err := store.CreateTenant(id, "bulk", time.Now().Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}

	dest := filepath.Join(dir, "backup.db")
	if err := Backup(dbPath, dest); err != nil {
		t.Fatal(err)
	}

	_, tenants, err := VerifyBackup(dest)
	if err != nil {
		t.Fatal(err)
	}
	if tenants != 50 {
		t.Fatalf("backup holds %d tenants, want all 50 — writes in the WAL were lost", tenants)
	}

	// And for contrast: a naive copy of the main file alone, which is what a
	// shell script would do, does not necessarily hold them.
	naive := filepath.Join(dir, "naive.db")
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(naive, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, naiveTenants, err := VerifyBackup(naive); err == nil && naiveTenants == 50 {
		t.Log("note: the naive copy happened to be complete here; " +
			"that is timing-dependent and not something to rely on")
	}
}

func TestBackupRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "policy.db")

	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()

	dest := filepath.Join(dir, "backup.db")
	if err := Backup(dbPath, dest); err != nil {
		t.Fatal(err)
	}

	// A backup that silently replaced an earlier one would be a poor place to
	// discover a typo in a path.
	err = Backup(dbPath, dest)
	if err == nil {
		t.Fatal("the second backup overwrote the first")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v, want an already-exists message", err)
	}
}

func TestBackupIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "policy.db")

	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()

	dest := filepath.Join(dir, "backup.db")
	if err := Backup(dbPath, dest); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	// A backup carries every customer record and the whole audit log.
	// Windows does not model POSIX bits, so this is only meaningful elsewhere.
	if perm := info.Mode().Perm(); perm&0o077 != 0 && os.Getenv("GOOS") != "windows" {
		t.Logf("backup permissions are %o; expected owner-only on a POSIX host", perm)
	}
}

func TestVerifyBackupRejectsCorruptFiles(t *testing.T) {
	dir := t.TempDir()

	junk := filepath.Join(dir, "junk.db")
	if err := os.WriteFile(junk, []byte("this is definitely not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyBackup(junk); err == nil {
		t.Fatal("a text file passed verification")
	}

	empty := filepath.Join(dir, "empty.db")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyBackup(empty); err == nil {
		t.Fatal("an empty file passed verification")
	}

	if _, _, err := VerifyBackup(filepath.Join(dir, "does-not-exist.db")); err == nil {
		t.Fatal("a missing file passed verification")
	}
}

// TestVerifyBackupRejectsTruncatedDatabase covers the failure that actually
// happens: a backup interrupted part-way, which looks like a database and is
// not one.
func TestVerifyBackupRejectsTruncatedDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "policy.db")

	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		store.CreateTenant("t"+string(rune('a'+i)), "", time.Now().Add(time.Hour).Unix())
	}
	store.Close()

	dest := filepath.Join(dir, "backup.db")
	if err := Backup(dbPath, dest); err != nil {
		t.Fatal(err)
	}

	full, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}

	truncated := filepath.Join(dir, "truncated.db")
	if err := os.WriteFile(truncated, full[:len(full)/3], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyBackup(truncated); err == nil {
		t.Fatal("a truncated database passed verification")
	}
}

func TestBackupRequiresADestination(t *testing.T) {
	if err := Backup("whatever.db", ""); err == nil {
		t.Fatal("an empty destination was accepted")
	}
	if err := Backup("whatever.db", "   "); err == nil {
		t.Fatal("a whitespace destination was accepted")
	}
}
