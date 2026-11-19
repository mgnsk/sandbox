// Package hostname checks the host names guards and the launcher take from
// the sandbox or the user, before they name a host to connect to.
package hostname

import (
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// Valid says whether name is a DNS host name (or IPv4 address) as it goes
// on the wire: ASCII, lowercase, no trailing dot.
func Valid(name string) bool {
	if name == "" || strings.HasSuffix(name, ".") {
		return false
	}
	ascii, err := idna.Lookup.ToASCII(name)
	return err == nil && ascii == name
}

// ValidPort says whether hostport is a Valid name with an optional port
// (1-65535).
func ValidPort(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return Valid(hostport)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n > 0 && Valid(host)
}

// Normalize is host[:port] from a host or an instance URL, lowercase, with
// the default HTTPS port left out; ok=false if it isn't one.
func Normalize(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(strings.TrimPrefix(value, "https://"), "http://")
	host, _, _ := strings.Cut(value, "/")
	host = strings.TrimSuffix(host, ":443")
	return host, ValidPort(host)
}
