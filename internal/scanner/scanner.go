package scanner

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/direo/lynx/internal/config"
	"github.com/direo/lynx/internal/rules"
)

// Result is the outcome of a scan.
type Result struct {
	Findings         []Finding
	FilesScanned     int
	FilesWithSecrets int
}

// ProgressFunc is called after each file is scanned.
type ProgressFunc func(filesScanned int, path string)

// Scanner orchestrates walking and matching.
type Scanner struct {
	Rules    []rules.Rule
	Opts     config.ScanOptions
	Progress ProgressFunc
}

// New creates a scanner with the given rules and options.
func New(rs []rules.Rule, opts config.ScanOptions) *Scanner {
	return &Scanner{Rules: rs, Opts: opts}
}

// Run executes the scan against opts.Path.
func (s *Scanner) Run() (*Result, error) {
	root := s.Opts.Path
	if root == "" {
		root = "."
	}

	entropy := s.Opts.EntropyThreshold
	if entropy <= 0 {
		entropy = config.DefaultEntropyThreshold
	}

	if s.Opts.History {
		return s.runHistory(root, entropy)
	}
	return s.runFilesystem(root, entropy)
}

func (s *Scanner) runFilesystem(root string, entropy float64) (*Result, error) {
	var all []Finding
	filesWith := map[string]struct{}{}
	count := 0

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	walkOpts := WalkOptions{
		Root:        root,
		Exclude:     s.Opts.Exclude,
		MaxFileSize: s.Opts.MaxFileSize,
		NoGitIgnore: s.Opts.NoGitIgnore,
		OnFile: func(path string) {
			count++
			if s.Progress != nil {
				s.Progress(count, path)
			}
		},
	}

	n, err := WalkFiles(walkOpts, func(path string, r io.Reader) error {
		rel := filepath.ToSlash(path)
		if rpath, relErr := filepath.Rel(absRoot, path); relErr == nil {
			rel = filepath.ToSlash(rpath)
		}

		findings, scanErr := ScanReader(rel, r, func(lineNum int, line string) []Finding {
			return MatchLine(rel, lineNum, line, s.Rules, entropy)
		})
		if scanErr != nil {
			return scanErr
		}
		if len(findings) > 0 {
			filesWith[rel] = struct{}{}
			all = append(all, findings...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}

	return &Result{
		Findings:         all,
		FilesScanned:     n,
		FilesWithSecrets: len(filesWith),
	}, nil
}

func (s *Scanner) runHistory(root string, entropy float64) (*Result, error) {
	var all []Finding
	filesWith := map[string]struct{}{}
	count := 0

	histOpts := HistoryOptions{
		Root:        root,
		Exclude:     s.Opts.Exclude,
		MaxFileSize: s.Opts.MaxFileSize,
		MaxCommits:  s.Opts.MaxCommits,
		OnBlob: func(path string) {
			count++
			if s.Progress != nil {
				s.Progress(count, path)
			}
		},
	}

	n, err := WalkGitHistory(histOpts, func(path, commit string, r io.Reader) error {
		findings, scanErr := ScanReader(path, r, func(lineNum int, line string) []Finding {
			fs := MatchLine(path, lineNum, line, s.Rules, entropy)
			for i := range fs {
				fs[i].Commit = commit
			}
			return fs
		})
		if scanErr != nil {
			return scanErr
		}
		if len(findings) > 0 {
			filesWith[path] = struct{}{}
			all = append(all, findings...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("history: %w", err)
	}

	return &Result{
		Findings:         all,
		FilesScanned:     n,
		FilesWithSecrets: len(filesWith),
	}, nil
}

// LoadRulesForOptions loads builtin or custom rules based on options.
func LoadRulesForOptions(opts config.ScanOptions) ([]rules.Rule, error) {
	if opts.RulesPath != "" {
		return rules.LoadRules(opts.RulesPath)
	}
	return rules.LoadBuiltin()
}
