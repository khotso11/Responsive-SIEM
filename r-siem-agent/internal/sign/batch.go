package sign

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func SignFile(path string, key []byte, keyID string) (Signature, error) {
	if strings.TrimSpace(path) == "" {
		return Signature{}, fmt.Errorf("input path is required")
	}
	shaHex, err := fileSHA256(path)
	if err != nil {
		return Signature{}, err
	}
	count, firstTS, lastTS, err := jsonlStats(path)
	if err != nil {
		return Signature{}, err
	}
	if strings.TrimSpace(keyID) == "" {
		keyID = "active"
	}
	sig := Signature{
		Algo:          AlgoHMACSHA256,
		KeyID:         keyID,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		SubjectType:   "event_batch",
		SubjectPath:   filepath.ToSlash(filepath.Clean(path)),
		SHA256:        shaHex,
		Count:         count,
		FirstTSUnixMs: firstTS,
		LastTSUnixMs:  lastTS,
	}
	h, err := signPayload(sig, key)
	if err != nil {
		return Signature{}, err
	}
	sig.HMACSHA256 = h
	return sig, nil
}

func VerifyFile(path string, key []byte, sig Signature) error {
	if sig.SubjectType != "event_batch" {
		return fmt.Errorf("invalid_subject_type")
	}
	if sig.Algo != AlgoHMACSHA256 {
		return fmt.Errorf("invalid_algo")
	}
	if err := verifyPayload(sig, key); err != nil {
		return err
	}
	shaHex, err := fileSHA256(path)
	if err != nil {
		return err
	}
	if shaHex != sig.SHA256 {
		return fmt.Errorf("batch_digest_mismatch")
	}
	count, firstTS, lastTS, err := jsonlStats(path)
	if err != nil {
		return err
	}
	if sig.Count > 0 && sig.Count != count {
		return fmt.Errorf("batch_count_mismatch")
	}
	if sig.FirstTSUnixMs > 0 && sig.FirstTSUnixMs != firstTS {
		return fmt.Errorf("batch_first_ts_mismatch")
	}
	if sig.LastTSUnixMs > 0 && sig.LastTSUnixMs != lastTS {
		return fmt.Errorf("batch_last_ts_mismatch")
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func jsonlStats(path string) (int64, int64, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, 0, err
	}
	defer f.Close()

	var count int64
	var first int64
	var last int64
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		count++
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		ts := pickTS(m)
		if ts <= 0 {
			continue
		}
		if first == 0 || ts < first {
			first = ts
		}
		if ts > last {
			last = ts
		}
	}
	if err := s.Err(); err != nil {
		return 0, 0, 0, err
	}
	return count, first, last, nil
}

func pickTS(m map[string]any) int64 {
	keys := []string{
		"last_updated_at_unix_ms",
		"ts_unix_ms",
		"created_at_unix_ms",
		"finished_at_unix_ms",
		"started_at_unix_ms",
		"observed_at_unix_ms",
	}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			ts := parseInt64(v)
			if ts > 0 {
				return ts
			}
		}
	}
	return 0
}

func parseInt64(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case json.Number:
		n, _ := t.Int64()
		return n
	case string:
		var n int64
		_, _ = fmt.Sscanf(strings.TrimSpace(t), "%d", &n)
		return n
	default:
		return 0
	}
}
