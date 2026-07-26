package scanner

import "testing"

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		in      string
		min     float64
		max     float64
		exactly float64
		useExact bool
	}{
		{in: "", exactly: 0, useExact: true},
		{in: "aaaa", exactly: 0, useExact: true},
		{in: "abcd", min: 1.9, max: 2.1},
		{in: "AKIAIOSFODNN7EXAMPLE", min: 3.5, max: 5.0},
	}
	for _, tt := range tests {
		got := ShannonEntropy(tt.in)
		if tt.useExact {
			if got != tt.exactly {
				t.Errorf("ShannonEntropy(%q)=%v want %v", tt.in, got, tt.exactly)
			}
			continue
		}
		if got < tt.min || got > tt.max {
			t.Errorf("ShannonEntropy(%q)=%v want in [%v,%v]", tt.in, got, tt.min, tt.max)
		}
	}
}

func TestRedact(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"ab", "****"},
		{"abcdefghij", "abcd****ghij"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIA****MPLE"},
	}
	for _, tt := range tests {
		if got := Redact(tt.in); got != tt.want {
			t.Errorf("Redact(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}
