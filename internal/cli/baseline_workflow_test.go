package cli

import (
	"path/filepath"
	"testing"

	"github.com/direo/lynx/internal/baseline"
	"github.com/direo/lynx/internal/config"
	"github.com/direo/lynx/internal/scanner"
)

func TestBaselineSuppressesFindings(t *testing.T) {
	opts := config.DefaultScanOptions()
	opts.Path = filepath.Join("..", "..", "testdata", "dirty")
	opts.Quiet = true
	opts.NoGitIgnore = true

	rs, err := scanner.LoadRulesForOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.New(rs, opts).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings")
	}

	dir := t.TempDir()
	basePath := filepath.Join(dir, ".lynx-baseline.json")
	if err := baseline.Save(basePath, baseline.FromFindings(result.Findings)); err != nil {
		t.Fatal(err)
	}

	opts.BaselinePath = basePath
	opts.FailOnFind = true
	code, err := runScan(opts)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("expected exit 0 after baseline, got %d", code)
	}
}
