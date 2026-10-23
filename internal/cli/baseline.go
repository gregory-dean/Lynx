package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/gregory-dean/lynx/internal/baseline"
	"github.com/gregory-dean/lynx/internal/config"
	"github.com/gregory-dean/lynx/internal/scanner"
)

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage finding baselines",
	}
	cmd.AddCommand(newBaselineCreateCmd())
	return cmd
}

func newBaselineCreateCmd() *cobra.Command {
	var (
		rulesPath  string
		outPath    string
		history    bool
		maxCommits int
	)
	cmd := &cobra.Command{
		Use:   "create [path]",
		Short: "Generate a baseline from current scan findings",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			if outPath == "" {
				outPath = config.DefaultBaselineFile
			}

			opts := config.DefaultScanOptions()
			opts.Path = path
			opts.RulesPath = rulesPath
			opts.Quiet = true
			opts.History = history
			opts.MaxCommits = maxCommits

			rs, err := scanner.LoadRulesForOptions(opts)
			if err != nil {
				return err
			}
			result, err := scanner.New(rs, opts).Run()
			if err != nil {
				return err
			}

			b := baseline.FromFindings(result.Findings)
			if err := baseline.Save(outPath, b); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Wrote %d fingerprint(s) to %s\n", len(b.Fingerprints), outPath)
			return nil
		},
	}
	cmd.Flags().StringVarP(&rulesPath, "rules", "r", "", "Path to custom rules YAML")
	cmd.Flags().StringVarP(&outPath, "output", "o", config.DefaultBaselineFile, "Baseline output path")
	cmd.Flags().BoolVar(&history, "history", false, "Build baseline from git history instead of the working tree")
	cmd.Flags().IntVar(&maxCommits, "max-commits", 0, "With --history, limit to N most recent commits (0 = all)")
	return cmd
}
