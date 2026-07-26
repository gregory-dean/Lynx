package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "lynx",
	Short: "Scan repositories for leaked secrets and credentials",
	Long: `Lynx is a local-first secrets scanner for repositories and filesystems.
It uses regex rules, Shannon entropy filtering, and optional live verification.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newRulesCmd())
	rootCmd.AddCommand(newBaselineCmd())
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(os.Stdout, "lynx %s\n", Version)
		},
	}
}
