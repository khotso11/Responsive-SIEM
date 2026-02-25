package sign

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func SignBundle(bundleRoots, excludePrefixes []string, key []byte, keyID string) (Signature, error) {
	manifest, digest, err := buildBundle(bundleRoots, excludePrefixes)
	if err != nil {
		return Signature{}, err
	}
	if strings.TrimSpace(keyID) == "" {
		keyID = "active"
	}
	sig := Signature{
		Algo:        AlgoHMACSHA256,
		KeyID:       keyID,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		SubjectType: "bundle",
		SubjectPath: strings.Join(cleanRoots(bundleRoots), ","),
		Manifest:    manifest,
		SHA256:      digest,
	}
	h, err := signPayload(sig, key)
	if err != nil {
		return Signature{}, err
	}
	sig.HMACSHA256 = h
	return sig, nil
}

func VerifyBundle(bundleRoots, excludePrefixes []string, key []byte, sig Signature) error {
	if sig.SubjectType != "bundle" {
		return fmt.Errorf("invalid_subject_type")
	}
	if sig.Algo != AlgoHMACSHA256 {
		return fmt.Errorf("invalid_algo")
	}
	if err := verifyPayload(sig, key); err != nil {
		return err
	}
	manifest, digest, err := buildBundle(bundleRoots, excludePrefixes)
	if err != nil {
		return err
	}
	if digest != sig.SHA256 {
		return fmt.Errorf("bundle_digest_mismatch")
	}
	if len(manifest) != len(sig.Manifest) {
		return fmt.Errorf("bundle_manifest_length_mismatch")
	}
	for i := range manifest {
		a := manifest[i]
		b := sig.Manifest[i]
		if a.Path != b.Path || a.SHA256 != b.SHA256 || a.Size != b.Size {
			return fmt.Errorf("bundle_manifest_mismatch")
		}
	}
	return nil
}

func buildBundle(bundleRoots, excludePrefixes []string) ([]ManifestEntry, string, error) {
	roots := cleanRoots(bundleRoots)
	if len(roots) == 0 {
		return nil, "", fmt.Errorf("at least one bundle root is required")
	}
	files, err := collectBundleFiles(roots, excludePrefixes)
	if err != nil {
		return nil, "", err
	}
	manifest := make([]ManifestEntry, 0, len(files))
	h := sha256.New()
	for _, p := range files {
		shaHex, size, err := fileSHA256AndSize(p)
		if err != nil {
			return nil, "", err
		}
		entry := ManifestEntry{Path: p, SHA256: shaHex, Size: size}
		manifest = append(manifest, entry)
		_, _ = io.WriteString(h, fmt.Sprintf("%s\t%s\t%d\n", entry.Path, entry.SHA256, entry.Size))
	}
	return manifest, hex.EncodeToString(h.Sum(nil)), nil
}

func collectBundleFiles(bundleRoots, excludePrefixes []string) ([]string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	excludes := normalizePrefixes(excludePrefixes)
	filesSet := make(map[string]struct{})
	for _, root := range bundleRoots {
		root = filepath.Clean(strings.TrimSpace(root))
		if root == "" {
			continue
		}
		if err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			absPath, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(cwd, absPath)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if rel == "." {
				rel = filepath.ToSlash(filepath.Clean(path))
			}
			if hasExcludedPrefix(rel, excludes) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() {
				filesSet[rel] = struct{}{}
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	files := make([]string, 0, len(filesSet))
	for p := range filesSet {
		files = append(files, p)
	}
	sort.Strings(files)
	return files, nil
}

func fileSHA256AndSize(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	bw := bufio.NewReaderSize(f, 128*1024)
	n, err := io.Copy(h, bw)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func cleanRoots(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = filepath.ToSlash(filepath.Clean(strings.TrimSpace(v)))
		if v != "" && v != "." {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizePrefixes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		v = filepath.ToSlash(filepath.Clean(v))
		if v == "." {
			continue
		}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func hasExcludedPrefix(path string, excludes []string) bool {
	path = filepath.ToSlash(filepath.Clean(strings.TrimSpace(path)))
	for _, ex := range excludes {
		if path == ex || strings.HasPrefix(path, ex+"/") {
			return true
		}
	}
	return false
}
