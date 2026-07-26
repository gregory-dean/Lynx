package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/direo/lynx/internal/baseline"
	"github.com/direo/lynx/internal/config"
	"github.com/direo/lynx/internal/output"
	"github.com/direo/lynx/internal/scanner"
	"github.com/direo/lynx/internal/verify"
)

func newScanCmd() *cobra.Command {
	opts := config.DefaultScanOptions()
	var maxFileSizeStr string
	var noFailOnFind bool

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a directory or repository for secrets",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				opts.Path = args[0]
			}
			if noFailOnFind {
				opts.FailOnFind = false
			}
			size, err := parseSize(maxFileSizeStr)
			if err != nil {
				return err
			}
			opts.MaxFileSize = size

			code, runErr := runScan(opts)
			if runErr != nil {
				return runErr
			}
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&opts.RulesPath, "rules", "r", "", "Path to custom rules YAML")
	cmd.Flags().StringSliceVarP(&opts.Exclude, "exclude", "e", nil, "Additional exclude patterns")
	cmd.Flags().StringVarP(&opts.Output, "output", "o", config.DefaultOutput, "Output format: table, json, sarif")
	cmd.Flags().StringVarP(&opts.BaselinePath, "baseline", "b", "", "Baseline file to suppress known findings")
	cmd.Flags().Float64Var(&opts.EntropyThreshold, "entropy-threshold", config.DefaultEntropyThreshold, "Raise entropy floor for rules that set entropy (0 = use each rule's value)")
	cmd.Flags().BoolVar(&opts.Verify, "verify", false, "Attempt live verification of findings (sends secrets to third-party APIs)")
	cmd.Flags().StringVar(&maxFileSizeStr, "max-file-size", "1MB", "Skip files larger than this")
	cmd.Flags().BoolVar(&opts.NoGitIgnore, "no-git-ignore", false, "Do not respect .gitignore")
	cmd.Flags().BoolVar(&opts.FailOnFind, "fail-on-find", true, "Exit 1 when secrets found")
	cmd.Flags().BoolVar(&noFailOnFind, "no-fail-on-find", false, "Always exit 0 when scan succeeds")
	cmd.Flags().BoolVar(&opts.Quiet, "quiet", false, "Suppress progress output on stderr")
	cmd.Flags().BoolVar(&opts.History, "history", false, "Scan git history (unique blobs from HEAD) instead of the working tree")
	cmd.Flags().IntVar(&opts.MaxCommits, "max-commits", 0, "With --history, limit to N most recent commits (0 = all)")

	return cmd
}

func runScan(opts config.ScanOptions) (int, error) {
	rs, err := scanner.LoadRulesForOptions(opts)
	if err != nil {
		return 2, err
	}

	s := scanner.New(rs, opts)
	if !opts.Quiet && opts.Output == "table" {
		unit := "file(s)"
		if opts.History {
			unit = "blob(s)"
		}
		s.Progress = func(n int, path string) {
			fmt.Fprintf(os.Stderr, "\rScanned %d %s...", n, unit)
		}
	}

	result, err := s.Run()
	if err != nil {
		return 2, err
	}
	if s.Progress != nil {
		fmt.Fprintln(os.Stderr)
	}

	findings := result.Findings
	suppressed := 0
	if opts.BaselinePath != "" {
		b, bErr := baseline.Load(opts.BaselinePath)
		if bErr != nil {
			return 2, bErr
		}
		findings, suppressed = baseline.Filter(findings, b)
	}

	if opts.Verify {
		fmt.Fprintln(os.Stderr, "warning: --verify sends candidate secrets to third-party APIs")
		reg := verify.NewRegistry(nil)
		reg.Apply(context.Background(), findings)
	}

	// Recompute files-with-secrets after baseline filter.
	filesWith := map[string]struct{}{}
	for _, f := range findings {
		filesWith[f.File] = struct{}{}
	}

	summary := output.Summary{
		Total:            len(findings),
		FilesScanned:     result.FilesScanned,
		FilesWithSecrets: len(filesWith),
		Suppressed:       suppressed,
	}

	if err := output.Report(os.Stdout, opts.Output, findings, summary); err != nil {
		return 2, err
	}

	if len(findings) > 0 && opts.FailOnFind {
		return 1, nil
	}
	return 0, nil
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return config.DefaultMaxFileSize, nil
	}
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(s, "KB"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "MB"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "GB"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid max-file-size %q", s)
	}
	return n * multiplier, nil
}
