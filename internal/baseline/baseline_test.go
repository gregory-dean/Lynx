package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/direo/lynx/internal/scanner"
)

func TestFingerprintStable(t *testing.T) {
	f := scanner.Finding{
		File:   "a.env",
		Line:   12,
		RuleID: "aws-access-key",
		Match:  "AKIAIOSFODNN7EXAMPLE",
	}
	a := Fingerprint(f)
	b := Fingerprint(f)
	if a != b || a == "" {
		t.Fatalf("unstable fingerprint: %q %q", a, b)
	}
}

func TestFingerprintIncludesCommit(t *testing.T) {
	base := scanner.Finding{
		File:   "a.env",
		Line:   12,
		RuleID: "aws-access-key",
		Match:  "AKIAIOSFODNN7EXAMPLE",
	}
	withCommit := base
	withCommit.Commit = "abc123def456"
	if Fingerprint(base) == Fingerprint(withCommit) {
		t.Fatal("history fingerprint should differ from working-tree fingerprint")
	}
}

func TestFilterAndSaveLoad(t *testing.T) {
	findings := []scanner.Finding{
		{File: "a.env", Line: 1, RuleID: "aws-access-key", Match: "AKIAIOSFODNN7EXAMPLE"},
		{File: "b.env", Line: 2, RuleID: "github-pat", Match: "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
	}
	b := FromFindings(findings[:1])
	dir := t.TempDir()
	path := filepath.Join(dir, ".lynx-baseline.json")
	if err := Save(path, b); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	remaining, suppressed := Filter(findings, loaded)
	if suppressed != 1 {
		t.Fatalf("suppressed=%d want 1", suppressed)
	}
	if len(remaining) != 1 || remaining[0].RuleID != "github-pat" {
		t.Fatalf("remaining=%+v", remaining)
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("expected error")
	}
	_ = os.ErrNotExist
}
