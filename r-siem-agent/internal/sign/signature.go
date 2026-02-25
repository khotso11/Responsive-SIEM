package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const AlgoHMACSHA256 = "HMAC-SHA256"

func SaveSignature(path string, sig Signature) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("signature path is required")
	}
	data, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func LoadSignature(path string) (Signature, error) {
	var sig Signature
	if strings.TrimSpace(path) == "" {
		return sig, fmt.Errorf("signature path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return sig, err
	}
	if err := json.Unmarshal(data, &sig); err != nil {
		return sig, err
	}
	return sig, nil
}

func signPayload(sig Signature, key []byte) (string, error) {
	if len(key) == 0 {
		return "", fmt.Errorf("key is required")
	}
	copySig := sig
	copySig.HMACSHA256 = ""
	payload, err := json.Marshal(copySig)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func verifyPayload(sig Signature, key []byte) error {
	expected, err := signPayload(sig, key)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(strings.ToLower(strings.TrimSpace(sig.HMACSHA256)))) != 1 {
		return fmt.Errorf("hmac_mismatch")
	}
	return nil
}
