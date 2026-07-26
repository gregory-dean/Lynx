package scanner

import "math"

// ShannonEntropy returns the Shannon entropy of s in bits per character.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int, len(s))
	for _, c := range s {
		freq[c]++
	}
	var entropy float64
	length := float64(len([]rune(s)))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
