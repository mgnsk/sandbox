// Package tokens checks the tokens the token commands print, before they
// reach a guard. Tokens are never stored: the commands print them on the
// host at each start, and the guards keep them in memory only.
package tokens

import (
	"strings"
	"unicode"
)

// Valid says whether token can be one: 8 to 1024 printable ASCII
// characters, no spaces - so it can't smuggle a header into a request.
func Valid(token string) bool {
	return len(token) >= 8 && len(token) <= 1024 && !strings.ContainsFunc(token, func(r rune) bool {
		return r > unicode.MaxASCII || !unicode.IsGraphic(r) || unicode.IsSpace(r)
	})
}
