package cli

import (
	"path/filepath"
	"testing"

	"github.com/direo/lynx/internal/config"
)

func TestParseSize(t *testing.T) {
	tests := []struct {
		in   string
		want int64
	}{
		{"1MB", 1 << 20},
		{"10KB", 10 * 1024},
		{"100", 100},
		{"2GB", 2 << 30},
	}
	for _, tt := range tests {
		got, err := parseSize(tt.in)
		if err != nil {
			t.Fatalf("parseSize(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("parseSize(%q)=%d want %d", tt.in, got, tt.want)
		}
	}
	if _, err := parseSize("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunScanCleanAndDirty(t *testing.T) {
	clean := config.DefaultScanOptions()
	clean.Path = filepath.Join("..", "..", "testdata", "clean")
	clean.Quiet = true
	clean.NoGitIgnore = true
	code, err := runScan(clean)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("clean exit=%d", code)
	}

	dirty := config.DefaultScanOptions()
	dirty.Path = filepath.Join("..", "..", "testdata", "dirty")
	dirty.Quiet = true
	dirty.NoGitIgnore = true
	dirty.Output = "json"
	code, err = runScan(dirty)
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 {
		t.Fatalf("dirty exit=%d want 1", code)
	}
}

func TestRunScanHistoryOutsideRepo(t *testing.T) {
	opts := config.DefaultScanOptions()
	opts.Path = t.TempDir()
	opts.History = true
	opts.Quiet = true
	code, err := runScan(opts)
	if err == nil {
		t.Fatal("expected error outside git repo")
	}
	if code != 2 {
		t.Fatalf("exit=%d want 2", code)
	}
}
