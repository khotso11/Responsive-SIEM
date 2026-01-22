package tail

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type checkpointState struct {
	Offset uint64 `json:"offset"`
	Seq    uint64 `json:"seq"`
	FileID fileID `json:"file_id,omitempty"`
}

type fileID struct {
	Path          string `json:"path,omitempty"`
	Device        uint64 `json:"device,omitempty"`
	Inode         uint64 `json:"inode,omitempty"`
	SizeBytes     int64  `json:"file_size_bytes,omitempty"`
	ModTimeUnixMs int64  `json:"mod_time_unix_ms,omitempty"`
	Fingerprint   string `json:"fingerprint_sha256,omitempty"`
}

func loadCheckpoint(path string) (checkpointState, error) {
	if path == "" {
		return checkpointState{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return checkpointState{}, nil
		}
		return checkpointState{}, fmt.Errorf("read checkpoint: %w", err)
	}
	var state checkpointState
	if err := json.Unmarshal(data, &state); err != nil {
		return checkpointState{}, fmt.Errorf("parse checkpoint: %w", err)
	}
	return state, nil
}

func writeCheckpoint(path string, state checkpointState) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir checkpoint dir: %w", err)
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, payload, 0644); err != nil {
		return fmt.Errorf("write checkpoint tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename checkpoint: %w", err)
	}
	return nil
}

func computeFileID(path string, fingerprintBytes int) (fileID, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileID{}, err
	}
	id := fileID{
		Path:          path,
		SizeBytes:     info.Size(),
		ModTimeUnixMs: info.ModTime().UnixMilli(),
	}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		id.Device = uint64(sys.Dev)
		id.Inode = uint64(sys.Ino)
	}
	if fingerprintBytes > 0 {
		fingerprint, err := fingerprintFile(path, fingerprintBytes)
		if err != nil {
			return id, err
		}
		id.Fingerprint = fingerprint
	}
	return id, nil
}

func fingerprintFile(path string, fingerprintBytes int) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	reader := io.LimitReader(file, int64(fingerprintBytes))
	hasher := sha256.New()
	if _, err := io.Copy(hasher, reader); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func fileIDKnown(id fileID) bool {
	return id.Device != 0 || id.Inode != 0 || id.Fingerprint != "" || id.SizeBytes != 0 || id.ModTimeUnixMs != 0
}

func fileIDSummary(id fileID) map[string]any {
	return map[string]any{
		"path":             id.Path,
		"device":           id.Device,
		"inode":            id.Inode,
		"file_size_bytes":  id.SizeBytes,
		"mod_time_unix_ms": id.ModTimeUnixMs,
		"fingerprint":      id.Fingerprint,
	}
}
