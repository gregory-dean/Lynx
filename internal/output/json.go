package output

import (
	"encoding/json"
	"io"

	"github.com/direo/lynx/internal/scanner"
)

type jsonReport struct {
	Findings []scanner.Finding `json:"findings"`
	Summary  Summary           `json:"summary"`
}

// WriteJSON writes findings as JSON.
func WriteJSON(w io.Writer, findings []scanner.Finding, summary Summary) error {
	if findings == nil {
		findings = []scanner.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{
		Findings: findings,
		Summary:  summary,
	})
}
