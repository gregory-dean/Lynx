package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/direo/lynx/internal/scanner"
)

// File is the on-disk baseline format.
type File struct {
	Fingerprints []string `json:"fingerprints"`
}

// Fingerprint returns SHA256 of a stable finding key as hex.
// Working-tree: file:line:rule_id:match
// History:      commit:file:line:rule_id:match
func Fingerprint(f scanner.Finding) string {
	var payload string
	if f.Commit != "" {
		payload = fmt.Sprintf("%s:%s:%d:%s:%s", f.Commit, f.File, f.Line, f.RuleID, f.Match)
	} else {
		payload = fmt.Sprintf("%s:%d:%s:%s", f.File, f.Line, f.RuleID, f.Match)
	}
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// Load reads a baseline file from disk.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var b File
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	if b.Fingerprints == nil {
		b.Fingerprints = []string{}
	}
	return &b, nil
}

// Save writes a baseline file to disk.
func Save(path string, b *File) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

// FromFindings builds a baseline from findings.
func FromFindings(findings []scanner.Finding) *File {
	fps := make([]string, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		fp := Fingerprint(f)
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		fps = append(fps, fp)
	}
	return &File{Fingerprints: fps}
}

// Filter removes findings present in the baseline.
// Returns remaining findings and the suppressed count.
func Filter(findings []scanner.Finding, b *File) ([]scanner.Finding, int) {
	if b == nil || len(b.Fingerprints) == 0 {
		return findings, 0
	}
	set := make(map[string]struct{}, len(b.Fingerprints))
	for _, fp := range b.Fingerprints {
		set[fp] = struct{}{}
	}
	out := make([]scanner.Finding, 0, len(findings))
	suppressed := 0
	for _, f := range findings {
		if _, ok := set[Fingerprint(f)]; ok {
			suppressed++
			continue
		}
		out = append(out, f)
	}
	return out, suppressed
}
