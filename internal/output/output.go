package output

import (
	"fmt"
	"io"

	"github.com/direo/lynx/internal/scanner"
)

// Summary aggregates scan stats for reporters.
type Summary struct {
	Total            int `json:"total"`
	FilesScanned     int `json:"files_scanned"`
	FilesWithSecrets int `json:"files_with_findings"`
	Suppressed       int `json:"suppressed,omitempty"`
}

// Report writes findings in the requested format.
func Report(w io.Writer, format string, findings []scanner.Finding, summary Summary) error {
	switch format {
	case "", "table":
		return WriteTable(w, findings, summary)
	case "json":
		return WriteJSON(w, findings, summary)
	case "sarif":
		return WriteSARIF(w, findings, summary)
	default:
		return fmt.Errorf("unknown output format %q (want table, json, or sarif)", format)
	}
}
