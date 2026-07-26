package scanner_test

import (
	"path/filepath"
	"testing"

	"github.com/direo/lynx/internal/config"
	"github.com/direo/lynx/internal/rules"
	"github.com/direo/lynx/internal/scanner"
)

func TestScanClean(t *testing.T) {
	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	opts := config.DefaultScanOptions()
	opts.Path = filepath.Join("..", "..", "testdata", "clean")
	opts.NoGitIgnore = true
	result, err := scanner.New(rs, opts).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(result.Findings), result.Findings)
	}
	if result.FilesScanned == 0 {
		t.Fatal("expected to scan files")
	}
}

func TestScanDirty(t *testing.T) {
	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	opts := config.DefaultScanOptions()
	opts.Path = filepath.Join("..", "..", "testdata", "dirty")
	opts.NoGitIgnore = true
	result, err := scanner.New(rs, opts).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings in dirty fixture")
	}

	wantRules := map[string]bool{
		"aws-access-key": false,
		"github-pat":     false,
		"slack-webhook":  false,
		"stripe-key":     false,
		"private-key":    false,
		"jwt-token":      false,
		"database-url":   false,
		"npm-token":      false,
	}
	for _, f := range result.Findings {
		if _, ok := wantRules[f.RuleID]; ok {
			wantRules[f.RuleID] = true
		}
	}
	for id, found := range wantRules {
		if !found {
			t.Errorf("missing expected rule finding: %s", id)
		}
	}
}
