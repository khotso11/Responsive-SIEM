package common

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenMessageSpoolRepairsCorruptTail(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	spoolPath := filepath.Join(tmpDir, "collector.spool.jsonl")
	good := queuedMessage{
		Seq:     7,
		EventID: "evt.good",
		DataB64: base64.StdEncoding.EncodeToString([]byte(`{"ok":true}`)),
	}
	goodLine, err := json.Marshal(good)
	if err != nil {
		t.Fatalf("json.Marshal(good): %v", err)
	}
	payload := append(append([]byte{}, goodLine...), '\n')
	payload = append(payload, 0x00, 0x00, '{', 'b', 'a', 'd', '\n')
	if err := os.WriteFile(spoolPath, payload, 0o600); err != nil {
		t.Fatalf("WriteFile(spoolPath): %v", err)
	}
	if err := os.WriteFile(spoolPath+".commit", []byte("7\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(commit): %v", err)
	}

	spool, err := openMessageSpool(spoolPath, false)
	if err != nil {
		t.Fatalf("openMessageSpool(): %v", err)
	}
	t.Cleanup(func() {
		_ = spool.Close()
	})

	if got, want := spool.nextSeq, uint64(8); got != want {
		t.Fatalf("nextSeq=%d want %d", got, want)
	}

	repaired, err := os.ReadFile(spoolPath)
	if err != nil {
		t.Fatalf("ReadFile(repaired): %v", err)
	}
	if strings.ContainsRune(string(repaired), '\x00') {
		t.Fatal("expected repaired spool to drop corrupt tail bytes")
	}
	if strings.TrimSpace(string(repaired)) != string(goodLine) {
		t.Fatalf("repaired spool=%q want %q", strings.TrimSpace(string(repaired)), string(goodLine))
	}

	backups, err := filepath.Glob(spoolPath + ".corrupt.*")
	if err != nil {
		t.Fatalf("Glob(backups): %v", err)
	}
	if len(backups) != 1 {
		t.Fatalf("backup files=%v want 1 backup", backups)
	}
	backupData, err := os.ReadFile(backups[0])
	if err != nil {
		t.Fatalf("ReadFile(backup): %v", err)
	}
	if !strings.ContainsRune(string(backupData), '\x00') {
		t.Fatal("expected backup to preserve corrupt content for audit")
	}
}
