package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/direo/lynx/internal/rules"
)

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Inspect and validate detection rules",
	}
	cmd.AddCommand(newRulesListCmd())
	cmd.AddCommand(newRulesValidateCmd())
	return cmd
}

func newRulesListCmd() *cobra.Command {
	var rulesPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List detection rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			var rs []rules.Rule
			var err error
			if rulesPath != "" {
				rs, err = rules.LoadRules(rulesPath)
			} else {
				rs, err = rules.LoadBuiltin()
			}
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSEVERITY\tDESCRIPTION")
			fmt.Fprintln(tw, "--\t--------\t-----------")
			for _, r := range rs {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", r.ID, r.Severity, r.Description)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVarP(&rulesPath, "rules", "r", "", "Path to custom rules YAML")
	return cmd
}

func newRulesValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [file]",
		Short: "Validate a rules YAML file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := rules.ValidateFile(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "OK: %s\n", args[0])
			return nil
		},
	}
}
