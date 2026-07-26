package config

import "time"

const (
	// DefaultEntropyThreshold is 0: use each rule's own entropy value when set.
	// Pass --entropy-threshold to raise the bar for entropy-gated rules.
	DefaultEntropyThreshold = 0
	DefaultMaxFileSize      = 1 << 20 // 1 MiB
	DefaultOutput           = "table"
	DefaultBaselineFile     = ".lynx-baseline.json"
	VerifyTimeout           = 5 * time.Second
)

// DefaultExcludeDirs are always skipped during traversal.
var DefaultExcludeDirs = []string{
	".git",
	"node_modules",
	"vendor",
	"__pycache__",
}

// ScanOptions holds runtime scan configuration.
type ScanOptions struct {
	Path             string
	RulesPath        string
	Exclude          []string
	Output           string
	BaselinePath     string
	EntropyThreshold float64
	Verify           bool
	MaxFileSize      int64
	NoGitIgnore      bool
	FailOnFind       bool
	Quiet            bool // suppress progress on stderr
	History          bool // scan git history instead of working tree
	MaxCommits       int  // 0 = all reachable commits from HEAD
}

// DefaultScanOptions returns sensible defaults for a scan.
func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		Path:             ".",
		Output:           DefaultOutput,
		EntropyThreshold: DefaultEntropyThreshold,
		MaxFileSize:      DefaultMaxFileSize,
		FailOnFind:       true,
	}
}
