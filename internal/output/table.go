package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/gregory-dean/lynx/internal/scanner"
)

// WriteTable writes a human-readable findings table.
func WriteTable(w io.Writer, findings []scanner.Finding, summary Summary) error {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No secrets found.")
		if summary.Suppressed > 0 {
			fmt.Fprintf(w, "%d finding(s) suppressed by baseline.\n", summary.Suppressed)
		}
		fmt.Fprintf(w, "Scanned %d file(s).\n", summary.FilesScanned)
		return nil
	}

	withCommit := false
	for _, f := range findings {
		if f.Commit != "" {
			withCommit = true
			break
		}
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if withCommit {
		fmt.Fprintln(tw, "COMMIT\tFILE\tLINE\tRULE\tMATCH (redacted)")
		fmt.Fprintln(tw, "------\t----\t----\t----\t---------------")
		for _, f := range findings {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", shortCommit(f.Commit), f.File, f.Line, f.RuleID, f.RedactedMatch)
		}
	} else {
		fmt.Fprintln(tw, "FILE\tLINE\tRULE\tMATCH (redacted)")
		fmt.Fprintln(tw, "----\t----\t----\t---------------")
		for _, f := range findings {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", f.File, f.Line, f.RuleID, f.RedactedMatch)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%d secret(s) found in %d file(s).\n", summary.Total, summary.FilesWithSecrets)
	if summary.Suppressed > 0 {
		fmt.Fprintf(w, "%d finding(s) suppressed by baseline.\n", summary.Suppressed)
	}
	return nil
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}
