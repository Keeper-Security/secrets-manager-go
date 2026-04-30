package test

import (
	"os"
	"path/filepath"
	"testing"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

// TestDownloadFileErrorReturn verifies that SaveFile, DownloadFileByTitle, and DownloadFile
// return meaningful errors for each distinct failure mode (KSM-918).
func TestDownloadFileErrorReturn(t *testing.T) {
	f := &ksm.KeeperFile{
		FileData: []byte("test file contents"),
		Title:    "test.txt",
		Name:     "test.txt",
	}

	t.Run("missing directory returns error", func(t *testing.T) {
		err := f.SaveFile("/tmp/does_not_exist_ksm_test/output.txt", false)
		if err == nil {
			t.Fatal("expected error for missing directory, got nil")
		}
		t.Logf("correctly returned: %v", err)
	})

	t.Run("write failure returns error (not silent success)", func(t *testing.T) {
		dir := t.TempDir()
		readOnlyDir := filepath.Join(dir, "readonly")
		if err := os.Mkdir(readOnlyDir, 0555); err != nil {
			t.Fatalf("setup: %v", err)
		}
		t.Cleanup(func() { os.Chmod(readOnlyDir, 0755) })

		err := f.SaveFile(filepath.Join(readOnlyDir, "output.txt"), false)
		if err == nil {
			t.Skip("permission model did not produce a write error on this platform")
		}
		t.Logf("correctly returned: %v", err)
	})

	t.Run("file title not found returns error", func(t *testing.T) {
		record := buildRecordWithFile(f)
		err := record.DownloadFileByTitle("no_such_file.txt", "/tmp/output.txt")
		if err == nil {
			t.Fatal("expected error for missing file title, got nil")
		}
		t.Logf("correctly returned: %v", err)
	})

	t.Run("file UID not found returns error", func(t *testing.T) {
		record := buildRecordWithFile(f)
		err := record.DownloadFile("no-such-uid", "/tmp/output.txt")
		if err == nil {
			t.Fatal("expected error for missing file UID, got nil")
		}
		t.Logf("correctly returned: %v", err)
	})

	t.Run("successful download returns nil error", func(t *testing.T) {
		record := buildRecordWithFile(f)
		dir := t.TempDir()
		err := record.DownloadFileByTitle("test.txt", filepath.Join(dir, "output.txt"))
		if err != nil {
			t.Fatalf("expected nil error for valid download, got: %v", err)
		}
	})
}

// buildRecordWithFile constructs a minimal Record with one KeeperFile attached.
func buildRecordWithFile(f *ksm.KeeperFile) *ksm.Record {
	return &ksm.Record{Files: []*ksm.KeeperFile{f}}
}
