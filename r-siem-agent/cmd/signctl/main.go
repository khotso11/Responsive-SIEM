package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"r-siem-agent/internal/sign"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	*m = append(*m, v)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "init-key":
		err = cmdInitKey(os.Args[2:])
	case "rotate-key":
		err = cmdRotateKey(os.Args[2:])
	case "sign-bundle":
		err = cmdSignBundle(os.Args[2:])
	case "verify-bundle":
		err = cmdVerifyBundle(os.Args[2:])
	case "sign-batch":
		err = cmdSignBatch(os.Args[2:])
	case "verify-batch":
		err = cmdVerifyBatch(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: signctl <command> [flags]
commands:
  init-key      --key pki/fr07/hmac/active.key
  rotate-key    --key pki/fr07/hmac/active.key --rotated_dir pki/fr07/hmac/rotated
  sign-bundle   --out <sig.json> [--bundle_root <path> ...] [--key <path>] [--key_id active]
  verify-bundle --sig <sig.json> [--bundle_root <path> ...] [--key <path>]
  sign-batch    --in <jsonl> --out <sig.json> [--key <path>] [--key_id active]
  verify-batch  --in <jsonl> --sig <sig.json> [--key <path>]
`)
}

func cmdInitKey(args []string) error {
	fs := flag.NewFlagSet("init-key", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	keyPath := fs.String("key", "pki/fr07/hmac/active.key", "Path to active key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, created, err := sign.LoadOrInitKey(*keyPath)
	if err != nil {
		return fmt.Errorf("init_key_failed: %w", err)
	}
	fmt.Printf("KEY_PATH=%s\n", filepath.ToSlash(filepath.Clean(*keyPath)))
	fmt.Printf("KEY_CREATED=%t\n", created)
	fmt.Println("PASS: signctl init-key")
	return nil
}

func cmdRotateKey(args []string) error {
	fs := flag.NewFlagSet("rotate-key", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	keyPath := fs.String("key", "pki/fr07/hmac/active.key", "Path to active key file")
	rotatedDir := fs.String("rotated_dir", "pki/fr07/hmac/rotated", "Directory to store rotated keys")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, _, err := sign.LoadOrInitKey(*keyPath); err != nil {
		return fmt.Errorf("rotate_key_init_failed: %w", err)
	}
	oldID, newID, err := sign.RotateKey(*keyPath, *rotatedDir)
	if err != nil {
		return fmt.Errorf("rotate_key_failed: %w", err)
	}
	fmt.Printf("KEY_PATH=%s\n", filepath.ToSlash(filepath.Clean(*keyPath)))
	fmt.Printf("ROTATED_OLD_KEY_ID=%s\n", oldID)
	fmt.Printf("NEW_KEY_ID=%s\n", newID)
	fmt.Println("PASS: signctl rotate-key")
	return nil
}

func cmdSignBundle(args []string) error {
	fs := flag.NewFlagSet("sign-bundle", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("out", "", "Output signature JSON path")
	keyPath := fs.String("key", "pki/fr07/hmac/active.key", "Path to active key file")
	keyID := fs.String("key_id", "active", "Key identifier to embed in signature")
	var roots multiFlag
	var excludes multiFlag
	fs.Var(&roots, "bundle_root", "Bundle root path (repeatable)")
	fs.Var(&excludes, "exclude_prefix", "Exclude prefix (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*out) == "" {
		return errors.New("sign_bundle_failed: --out is required")
	}
	if len(roots) == 0 {
		roots = defaultBundleRoots()
	}
	if len(excludes) == 0 {
		excludes = defaultExcludePrefixes()
	}
	key, _, err := sign.LoadOrInitKey(*keyPath)
	if err != nil {
		return fmt.Errorf("sign_bundle_key_failed: %w", err)
	}
	sig, err := sign.SignBundle(roots, excludes, key, *keyID)
	if err != nil {
		return fmt.Errorf("sign_bundle_failed: %w", err)
	}
	if err := sign.SaveSignature(*out, sig); err != nil {
		return fmt.Errorf("sign_bundle_write_failed: %w", err)
	}
	fmt.Printf("SIGNATURE_OUT=%s\n", filepath.ToSlash(filepath.Clean(*out)))
	fmt.Println("PASS: signctl sign-bundle")
	return nil
}

func cmdVerifyBundle(args []string) error {
	fs := flag.NewFlagSet("verify-bundle", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sigPath := fs.String("sig", "", "Signature JSON path")
	keyPath := fs.String("key", "pki/fr07/hmac/active.key", "Path to active key file")
	var roots multiFlag
	var excludes multiFlag
	fs.Var(&roots, "bundle_root", "Bundle root path (repeatable)")
	fs.Var(&excludes, "exclude_prefix", "Exclude prefix (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*sigPath) == "" {
		return errors.New("verify_bundle_failed: --sig is required")
	}
	if len(roots) == 0 {
		roots = defaultBundleRoots()
	}
	if len(excludes) == 0 {
		excludes = defaultExcludePrefixes()
	}
	key, err := sign.LoadKey(*keyPath)
	if err != nil {
		return fmt.Errorf("verify_bundle_failed: %w", err)
	}
	sig, err := sign.LoadSignature(*sigPath)
	if err != nil {
		return fmt.Errorf("verify_bundle_failed: %w", err)
	}
	if err := sign.VerifyBundle(roots, excludes, key, sig); err != nil {
		return fmt.Errorf("verify_bundle_failed: %s", err.Error())
	}
	fmt.Println("VERIFY_BUNDLE=PASS")
	return nil
}

func cmdSignBatch(args []string) error {
	fs := flag.NewFlagSet("sign-batch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("in", "", "Input JSONL file")
	out := fs.String("out", "", "Output signature JSON path")
	keyPath := fs.String("key", "pki/fr07/hmac/active.key", "Path to active key file")
	keyID := fs.String("key_id", "active", "Key identifier to embed in signature")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*in) == "" || strings.TrimSpace(*out) == "" {
		return errors.New("sign_batch_failed: --in and --out are required")
	}
	key, _, err := sign.LoadOrInitKey(*keyPath)
	if err != nil {
		return fmt.Errorf("sign_batch_key_failed: %w", err)
	}
	sig, err := sign.SignFile(*in, key, *keyID)
	if err != nil {
		return fmt.Errorf("sign_batch_failed: %w", err)
	}
	if err := sign.SaveSignature(*out, sig); err != nil {
		return fmt.Errorf("sign_batch_write_failed: %w", err)
	}
	fmt.Printf("SIGNATURE_OUT=%s\n", filepath.ToSlash(filepath.Clean(*out)))
	fmt.Println("PASS: signctl sign-batch")
	return nil
}

func cmdVerifyBatch(args []string) error {
	fs := flag.NewFlagSet("verify-batch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("in", "", "Input JSONL file")
	sigPath := fs.String("sig", "", "Signature JSON path")
	keyPath := fs.String("key", "pki/fr07/hmac/active.key", "Path to active key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*in) == "" || strings.TrimSpace(*sigPath) == "" {
		return errors.New("verify_batch_failed: --in and --sig are required")
	}
	key, err := sign.LoadKey(*keyPath)
	if err != nil {
		return fmt.Errorf("verify_batch_failed: %w", err)
	}
	sig, err := sign.LoadSignature(*sigPath)
	if err != nil {
		return fmt.Errorf("verify_batch_failed: %w", err)
	}
	if err := sign.VerifyFile(*in, key, sig); err != nil {
		return fmt.Errorf("verify_batch_failed: %s", err.Error())
	}
	fmt.Println("VERIFY_BATCH=PASS")
	return nil
}

func defaultExcludePrefixes() []string {
	return []string{
		"demo_artifacts",
		"retained",
		"logs",
		"exports",
		"tmp",
		"pki",
	}
}

func defaultBundleRoots() []string {
	playbooksRoot := discoverPlaybooksRoot()
	detectorRulesRoot := discoverDetectorRulesRoot(playbooksRoot)
	raw := []string{"configs", playbooksRoot, detectorRulesRoot}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		v = filepath.ToSlash(filepath.Clean(strings.TrimSpace(v)))
		if v == "" || v == "." {
			continue
		}
		if !pathExists(v) {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return []string{"configs"}
	}
	return out
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func discoverPlaybooksRoot() string {
	if pathExists("configs/playbooks") {
		return "configs/playbooks"
	}
	if p := findFirstConfigFile(func(body string) bool {
		return strings.Contains(body, "playbooks:") && strings.Contains(body, "PB-")
	}); p != "" {
		return p
	}
	return "configs"
}

func discoverDetectorRulesRoot(playbooksRoot string) string {
	if pathExists("configs/detector-rules") {
		return "configs/detector-rules"
	}
	if p := findFirstConfigFile(func(body string) bool {
		return strings.Contains(body, "rce:") && strings.Contains(body, "rules:")
	}); p != "" {
		p = filepath.ToSlash(filepath.Clean(p))
		if p == filepath.ToSlash(filepath.Clean(playbooksRoot)) && pathExists("cmd/detector-v0/main.go") {
			return "cmd/detector-v0/main.go"
		}
		return p
	}
	if pathExists("cmd/detector-v0/main.go") {
		return "cmd/detector-v0/main.go"
	}
	if pathExists("configs/detector.yaml") {
		return "configs/detector.yaml"
	}
	return "configs"
}

func findFirstConfigFile(match func(string) bool) string {
	files := make([]string, 0, 8)
	_ = filepath.WalkDir("configs", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			files = append(files, filepath.ToSlash(filepath.Clean(path)))
		}
		return nil
	})
	sort.Strings(files)
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if match(string(body)) {
			return file
		}
	}
	return ""
}
