package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/direo/lynx/internal/scanner"
)

// SARIF 2.1.0 minimal document for GitHub code scanning.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	ShortDescription *sarifMessage   `json:"shortDescription,omitempty"`
	DefaultConfig    *sarifRuleConf  `json:"defaultConfiguration,omitempty"`
}

type sarifRuleConf struct {
	Level string `json:"level,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level,omitempty"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]string `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

// WriteSARIF writes findings as SARIF 2.1.0.
func WriteSARIF(w io.Writer, findings []scanner.Finding, summary Summary) error {
	_ = summary
	ruleSet := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		if _, ok := ruleSet[f.RuleID]; !ok {
			ruleSet[f.RuleID] = sarifRule{
				ID: f.RuleID,
				ShortDescription: &sarifMessage{
					Text: firstNonEmpty(f.Description, f.RuleID),
				},
				DefaultConfig: &sarifRuleConf{Level: severityToLevel(f.Severity)},
			}
		}
		msg := fmt.Sprintf("Possible secret (%s): %s", f.RuleID, f.RedactedMatch)
		if f.Commit != "" {
			msg = fmt.Sprintf("Possible secret (%s) in commit %s: %s", f.RuleID, f.Commit, f.RedactedMatch)
		}
		res := sarifResult{
			RuleID: f.RuleID,
			Level:  severityToLevel(f.Severity),
			Message: sarifMessage{
				Text: msg,
			},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.File},
					Region: sarifRegion{
						StartLine:   f.Line,
						StartColumn: f.Column,
					},
				},
			}},
		}
		if f.Commit != "" {
			res.PartialFingerprints = map[string]string{"commitSha": f.Commit}
			res.Properties = map[string]string{"commit": f.Commit}
		}
		results = append(results, res)
	}

	ruleIDs := make([]string, 0, len(ruleSet))
	for id := range ruleSet {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	rules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, ruleSet[id])
	}

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "lynx",
					InformationURI: "https://github.com/direo/lynx",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func severityToLevel(sev string) string {
	switch sev {
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
