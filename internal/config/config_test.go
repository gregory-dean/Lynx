package config

import "testing"

func TestDefaultScanOptions(t *testing.T) {
	opts := DefaultScanOptions()
	if opts.Path != "." || opts.Output != DefaultOutput {
		t.Fatalf("unexpected defaults: %+v", opts)
	}
	if opts.MaxFileSize != DefaultMaxFileSize {
		t.Fatalf("max file size=%d", opts.MaxFileSize)
	}
	if !opts.FailOnFind {
		t.Fatal("FailOnFind should default true")
	}
	if len(DefaultExcludeDirs) < 4 {
		t.Fatal("expected default exclude dirs")
	}
}
