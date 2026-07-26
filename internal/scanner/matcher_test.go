package scanner

import (
	"path/filepath"
	"testing"

	"github.com/direo/lynx/internal/config"
	"github.com/direo/lynx/internal/rules"
)

func TestMatchLineAWS(t *testing.T) {
	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	line := `aws_access_key_id = AKIAIOSFODNN7EXAMPLE`
	findings := MatchLine("config.env", 1, line, rs, 4.5)
	found := false
	for _, f := range findings {
		if f.RuleID == "aws-access-key" {
			found = true
			if f.Match != "AKIAIOSFODNN7EXAMPLE" {
				t.Errorf("match=%q", f.Match)
			}
			if f.RedactedMatch != "AKIA****MPLE" {
				t.Errorf("redacted=%q", f.RedactedMatch)
			}
		}
	}
	if !found {
		t.Fatal("expected aws-access-key finding")
	}
}

func TestMatchLineNoFalsePositive(t *testing.T) {
	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	line := `const greeting = "hello world"`
	findings := MatchLine("main.go", 1, line, rs, 4.5)
	if len(findings) != 0 {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestMatchLineGitHubPAT(t *testing.T) {
	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	tok := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	line := "GITHUB_TOKEN=" + tok
	findings := MatchLine(".env", 3, line, rs, 4.5)
	found := false
	for _, f := range findings {
		if f.RuleID == "github-pat" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected github-pat, got %+v", findings)
	}
}

func TestMatchLineEntropyFilter(t *testing.T) {
	rs, err := rules.ParseRules([]byte(`
rules:
  - id: high-ent
    description: high entropy only
    regex: '[A-Za-z0-9]{16,}'
    entropy: 4.5
    severity: low
    keywords:
      - secret
`))
	if err != nil {
		t.Fatal(err)
	}
	low := MatchLine("f", 1, `secret=aaaaaaaaaaaaaaaa`, rs, 0)
	if len(low) != 0 {
		t.Fatalf("expected entropy filter to drop low-entropy match, got %+v", low)
	}
}

func TestMatchLineGlobalEntropyFloor(t *testing.T) {
	rs, err := rules.ParseRules([]byte(`
rules:
  - id: mid-ent
    description: mid entropy
    regex: '[A-Za-z0-9/+=]{20,}'
    entropy: 3.0
    severity: low
    keywords:
      - secret
`))
	if err != nil {
		t.Fatal(err)
	}
	// AKIAIOSFODNN7EXAMPLE entropy ~3.68 — passes rule 3.0, fails raised floor 4.5
	line := `secret=AKIAIOSFODNN7EXAMPLE`
	if got := MatchLine("f", 1, line, rs, 0); len(got) != 1 {
		t.Fatalf("expected match with rule entropy, got %+v", got)
	}
	if got := MatchLine("f", 1, line, rs, 4.5); len(got) != 0 {
		t.Fatalf("expected global floor to drop match, got %+v", got)
	}
}

func TestLoadRulesForOptions(t *testing.T) {
	builtin, err := LoadRulesForOptions(config.DefaultScanOptions())
	if err != nil || len(builtin) < 10 {
		t.Fatalf("builtin: %v len=%d", err, len(builtin))
	}
	custom := config.DefaultScanOptions()
	custom.RulesPath = filepath.Join("..", "..", "testdata", "rules", "custom.yaml")
	rs, err := LoadRulesForOptions(custom)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].ID != "custom-demo-secret" {
		t.Fatalf("custom=%+v", rs)
	}
}
