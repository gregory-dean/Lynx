package scanner

// Finding represents a detected secret.
type Finding struct {
	File          string  `json:"file"`
	Line          int     `json:"line"`
	Column        int     `json:"column"`
	RuleID        string  `json:"rule_id"`
	Description   string  `json:"description,omitempty"`
	Severity      string  `json:"severity"`
	Match         string  `json:"match"`
	RedactedMatch string  `json:"redacted"`
	Entropy       float64 `json:"entropy,omitempty"`
	Commit        string  `json:"commit,omitempty"` // set for git history scans
	Verified      *bool   `json:"verified,omitempty"`
}

// Redact returns a redacted view of secret: first 4 + **** + last 4.
func Redact(s string) string {
	r := []rune(s)
	n := len(r)
	if n <= 8 {
		if n <= 2 {
			return "****"
		}
		return string(r[:1]) + "****" + string(r[n-1:])
	}
	return string(r[:4]) + "****" + string(r[n-4:])
}
