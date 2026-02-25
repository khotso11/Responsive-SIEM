package sign

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func LoadOrInitKey(path string) ([]byte, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false, fmt.Errorf("key path is required")
	}
	if b, err := os.ReadFile(path); err == nil {
		k, err := parseKeyBytes(b)
		if err != nil {
			return nil, false, err
		}
		return k, false, nil
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	key, err := randomKey(32)
	if err != nil {
		return nil, false, err
	}
	if err := writeKey(path, key); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

func LoadKey(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("key path is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseKeyBytes(b)
}

func RotateKey(activePath, rotatedDir string) (string, string, error) {
	activePath = strings.TrimSpace(activePath)
	rotatedDir = strings.TrimSpace(rotatedDir)
	if activePath == "" || rotatedDir == "" {
		return "", "", fmt.Errorf("active path and rotated dir are required")
	}
	oldKey, err := LoadKey(activePath)
	if err != nil {
		return "", "", err
	}

	if err := os.MkdirAll(rotatedDir, 0o700); err != nil {
		return "", "", err
	}
	oldID := time.Now().UTC().Format("20060102T150405Z")
	rotatedPath := filepath.Join(rotatedDir, oldID+".key")
	if err := writeKeyExclusive(rotatedPath, oldKey); err != nil {
		return "", "", err
	}

	newKey, err := randomKey(32)
	if err != nil {
		return "", "", err
	}
	if err := writeKey(activePath, newKey); err != nil {
		return "", "", err
	}
	newID := time.Now().UTC().Format("20060102T150405.000000000Z")
	if newID == oldID {
		newID = newID + "-new"
	}
	return oldID, newID, nil
}

func randomKey(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func parseKeyBytes(raw []byte) ([]byte, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return nil, fmt.Errorf("key file is empty")
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("key file is not valid hex: %w", err)
	}
	if len(decoded) < 16 {
		return nil, fmt.Errorf("key length too short: %d", len(decoded))
	}
	return decoded, nil
}

func writeKey(path string, key []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	content := []byte(hex.EncodeToString(key) + "\n")
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeKeyExclusive(path string, key []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write([]byte(hex.EncodeToString(key) + "\n"))
	return err
}
