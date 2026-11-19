package tokens

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	for token, want := range map[string]bool{
		"github_pat_" + strings.Repeat("t", 40): true,
		"gho_abc.~+/=-":                         true,
		strings.Repeat("x", 1024):               true,
		"short":                                 false,
		strings.Repeat("x", 1025):               false,
		"has space":                             false,
		"bad token\r\nX-Injected: 1":            false,
		"tab\there":                             false,
		"nonascii-ü-token":                      false,
	} {
		if got := Valid(token); got != want {
			t.Errorf("Valid(%q) = %v, want %v", token, got, want)
		}
	}
}
