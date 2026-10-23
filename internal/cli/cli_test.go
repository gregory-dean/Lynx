package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gregory-dean/lynx/internal/config"
)

func TestVersionCommand(t *testing.T) {
	rootCmd.SetArgs([]string{"version"})
	defer rootCmd.SetArgs(nil)
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := rootCmd.Execute()
	_ = w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(r)
	if !bytes.Contains(out, []byte("lynx")) {
		t.Fatalf("version output=%q", out)
	}
}

func TestRulesListAndValidate(t *testing.T) {
	rootCmd.SetArgs([]string{"rules", "list"})
	defer rootCmd.SetArgs(nil)
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rules list: %v", err)
	}

	path := filepath.Join("..", "..", "internal", "rules", "default.yaml")
	rootCmd.SetArgs([]string{"rules", "validate", path})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rules validate: %v", err)
	}
}

func TestBaselineCreateCommand(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "base.json")
	dirty := filepath.Join("..", "..", "testdata", "dirty")
	rootCmd.SetArgs([]string{"baseline", "create", dirty, "-o", out})
	defer rootCmd.SetArgs(nil)
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal(err)
	}
}

func TestRunScanNoFailOnFind(t *testing.T) {
	opts := config.DefaultScanOptions()
	opts.Path = filepath.Join("..", "..", "testdata", "dirty")
	opts.Quiet = true
	opts.NoGitIgnore = true
	opts.FailOnFind = false
	opts.Output = "table"
	code, err := runScan(opts)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
}

func TestScanCommandNoFail(t *testing.T) {
	dirty := filepath.Join("..", "..", "testdata", "dirty")
	rootCmd.SetArgs([]string{"scan", dirty, "--quiet", "--no-fail-on-find", "-o", "json"})
	defer rootCmd.SetArgs(nil)
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestRunScanUnknownOutput(t *testing.T) {
	opts := config.DefaultScanOptions()
	opts.Path = filepath.Join("..", "..", "testdata", "clean")
	opts.Quiet = true
	opts.Output = "xml"
	_, err := runScan(opts)
	if err == nil {
		t.Fatal("expected unknown output error")
	}
}
