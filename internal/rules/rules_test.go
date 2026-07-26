package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBuiltin(t *testing.T) {
	rs, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	if len(rs) < 10 {
		t.Fatalf("expected at least 10 rules, got %d", len(rs))
	}
	for _, r := range rs {
		if r.Compiled() == nil {
			t.Errorf("rule %q has nil compiled regex", r.ID)
		}
	}
}

func TestParseRulesInvalidYAML(t *testing.T) {
	_, err := ParseRules([]byte("not: valid: yaml: [[["))
	if err == nil {
		t.Fatal("expected error for invalid yaml")
	}
}

func TestParseRulesMissingFields(t *testing.T) {
	_, err := ParseRules([]byte(`
rules:
  - id: bad
    description: missing regex
    severity: high
`))
	if err == nil {
		t.Fatal("expected error for missing regex")
	}
}

func TestParseRulesInvalidRegex(t *testing.T) {
	_, err := ParseRules([]byte(`
rules:
  - id: bad
    description: bad regex
    regex: "(unclosed"
    severity: high
`))
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestParseRulesDuplicateID(t *testing.T) {
	_, err := ParseRules([]byte(`
rules:
  - id: dup
    description: one
    regex: "abc"
    severity: low
  - id: dup
    description: two
    regex: "def"
    severity: low
`))
	if err == nil {
		t.Fatal("expected duplicate id error")
	}
}

func TestLoadRulesAndValidateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	content := []byte(`
rules:
  - id: test-rule
    description: Test
    regex: "SECRET_[A-Z0-9]+"
    severity: medium
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if len(rs) != 1 || rs[0].ID != "test-rule" {
		t.Fatalf("unexpected rules: %+v", rs)
	}
	if err := ValidateFile(path); err != nil {
		t.Fatalf("ValidateFile: %v", err)
	}
}

func TestEmbeddedDefaultYAML(t *testing.T) {
	path := filepath.Join("default.yaml")
	if err := ValidateFile(path); err != nil {
		t.Fatalf("embedded default.yaml invalid: %v", err)
	}
	data, err := BuiltinYAML()
	if err != nil || len(data) == 0 {
		t.Fatalf("BuiltinYAML: %v", err)
	}
}
