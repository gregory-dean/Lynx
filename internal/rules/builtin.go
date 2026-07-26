package rules

import (
	"embed"
	"fmt"
)

//go:embed default.yaml
var builtinFS embed.FS

const builtinName = "default.yaml"

// LoadBuiltin loads the embedded default ruleset.
func LoadBuiltin() ([]Rule, error) {
	data, err := builtinFS.ReadFile(builtinName)
	if err != nil {
		return nil, fmt.Errorf("read builtin rules: %w", err)
	}
	return ParseRules(data)
}

// BuiltinYAML returns the raw embedded default rules YAML.
func BuiltinYAML() ([]byte, error) {
	return builtinFS.ReadFile(builtinName)
}
