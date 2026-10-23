package scanner

import (
	"strings"

	"github.com/gregory-dean/lynx/internal/rules"
)

const keywordProximity = 50

// MatchLine runs all rules against a single line and returns findings.
func MatchLine(file string, lineNum int, line string, rs []rules.Rule, globalEntropy float64) []Finding {
	var findings []Finding
	for _, rule := range rs {
		if !keywordPresent(line, rule.Keywords) {
			continue
		}
		re := rule.Compiled()
		if re == nil {
			continue
		}
		allIdx := re.FindAllStringSubmatchIndex(line, -1)
		for _, loc := range allIdx {
			// Prefer first capture group when present; otherwise full match.
			start, end := loc[0], loc[1]
			if len(loc) >= 4 && loc[2] >= 0 && loc[3] >= 0 {
				start, end = loc[2], loc[3]
			}
			match := line[start:end]
			if !keywordNearMatch(line, start, end, rule.Keywords) {
				continue
			}
			ent := ShannonEntropy(match)
			if rule.Entropy > 0 {
				threshold := rule.Entropy
				// CLI may raise the minimum for entropy-gated rules.
				if globalEntropy > threshold {
					threshold = globalEntropy
				}
				if ent < threshold {
					continue
				}
			}

			findings = append(findings, Finding{
				File:          file,
				Line:          lineNum,
				Column:        start + 1,
				RuleID:        rule.ID,
				Description:   rule.Description,
				Severity:      rule.Severity,
				Match:         match,
				RedactedMatch: Redact(match),
				Entropy:       ent,
			})
		}
	}
	return findings
}

func keywordPresent(line string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	lower := strings.ToLower(line)
	for _, kw := range keywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

func keywordNearMatch(line string, start, end int, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	windowStart := start - keywordProximity
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := end + keywordProximity
	if windowEnd > len(line) {
		windowEnd = len(line)
	}
	window := strings.ToLower(line[windowStart:windowEnd])
	for _, kw := range keywords {
		if strings.Contains(window, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}
