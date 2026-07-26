package rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule defines a secret detection pattern.
type Rule struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Regex       string   `yaml:"regex"`
	Entropy     float64  `yaml:"entropy,omitempty"`
	Keywords    []string `yaml:"keywords,omitempty"`
	Severity    string   `yaml:"severity"` // high, medium, low

	compiled *regexp.Regexp `yaml:"-"`
}

// Compiled returns the compiled regex for the rule.
func (r *Rule) Compiled() *regexp.Regexp {
	return r.compiled
}

// fileFormat is the top-level YAML document shape.
type fileFormat struct {
	Rules []Rule `yaml:"rules"`
}

// LoadRules loads and validates rules from a YAML file.
func LoadRules(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	return ParseRules(data)
}

// ParseRules parses and validates rules from YAML bytes.
func ParseRules(data []byte) ([]Rule, error) {
	var doc fileFormat
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse rules yaml: %w", err)
	}
	if len(doc.Rules) == 0 {
		return nil, fmt.Errorf("no rules found in document")
	}

	out := make([]Rule, 0, len(doc.Rules))
	seen := make(map[string]struct{}, len(doc.Rules))
	for i, r := range doc.Rules {
		if err := validateRule(r); err != nil {
			return nil, fmt.Errorf("rule[%d] %q: %w", i, r.ID, err)
		}
		if _, ok := seen[r.ID]; ok {
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = struct{}{}

		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return nil, fmt.Errorf("rule %q: invalid regex: %w", r.ID, err)
		}
		r.compiled = re
		r.Severity = strings.ToLower(r.Severity)
		out = append(out, r)
	}
	return out, nil
}

func validateRule(r Rule) error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if strings.TrimSpace(r.Description) == "" {
		return fmt.Errorf("description is required")
	}
	if strings.TrimSpace(r.Regex) == "" {
		return fmt.Errorf("regex is required")
	}
	switch strings.ToLower(r.Severity) {
	case "high", "medium", "low":
	default:
		return fmt.Errorf("severity must be high, medium, or low")
	}
	return nil
}

// ValidateFile loads a rules file and returns an error if invalid.
func ValidateFile(path string) error {
	_, err := LoadRules(path)
	return err
}
