package launcher

import (
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var hostPortRE = regexp.MustCompile(`^([0-9]{1,5})(-([0-9]{1,5}))?(/(tcp|udp))?$`)

// parseHostPorts gives the tcp and udp port lists for pasta's -T/-U from
// entries like 5037, 8080/udp or 9000-9010.
func parseHostPorts(specs []string) (tcp, udp []string, err error) {
	for _, spec := range specs {
		m := hostPortRE.FindStringSubmatch(spec)
		if m == nil {
			return nil, nil, errorf("bad SANDBOX_HOST_PORTS entry '%s' (want PORT[-PORT][/tcp|/udp])", spec)
		}
		first, _ := strconv.Atoi(m[1])
		last := first
		if m[3] != "" {
			last, _ = strconv.Atoi(m[3])
		}
		if first < 1 || last > 65535 || last < first {
			return nil, nil, errorf("bad SANDBOX_HOST_PORTS range '%s' (ports are 1-65535)", spec)
		}
		ports := strconv.Itoa(first)
		if first != last {
			ports += "-" + strconv.Itoa(last)
		}
		if m[5] == "udp" {
			udp = append(udp, ports)
		} else {
			tcp = append(tcp, ports)
		}
	}
	return tcp, udp, nil
}

// hostPortSpecs is the configured ports plus SANDBOX_HOST_PORTS from the
// host's environment - never from inside, since --clearenv keeps it out.
func hostPortSpecs(configured []string) []string {
	return append(append([]string{}, configured...),
		strings.Fields(strings.ReplaceAll(os.Getenv("SANDBOX_HOST_PORTS"), ",", " "))...)
}

func readResolvConf(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

// Where the sandbox sends DNS queries when the host's resolver is on
// loopback. Link-local, so it can't shadow a server the sandbox could
// otherwise reach.
const dnsForwardAddr = "169.254.1.53"

// dnsForward: a host resolver on loopback (systemd-resolved's 127.0.0.53, a
// local dnsmasq or unbound) is out of reach inside: the netns has its own
// loopback, and --map-host-loopback none removes the way to the host's.
//
// It returns the resolver and resolv.conf for inside when the first
// nameserver is an IPv4 loopback one: pasta forwards dnsForwardAddr, ports
// 53 and 853 only, to that resolver, and the text has it replaced by
// dnsForwardAddr. Other loopback nameservers are dropped, unreachable
// either way. Empty when the nameservers work inside as they are.
func dnsForward(resolvConf string) (resolver, text string) {
	seen := false
	var lines []string
	for _, line := range splitLines(resolvConf) {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			lines = append(lines, line)
			continue
		}
		first := !seen
		seen = true
		addr, err := netip.ParseAddr(fields[1])
		switch {
		case err != nil, !addr.IsLoopback():
			lines = append(lines, line)
		case first && addr.Is4():
			resolver = fields[1]
			lines = append(lines, "nameserver "+dnsForwardAddr)
		}
	}
	if resolver == "" {
		return "", ""
	}
	return resolver, strings.Join(lines, "\n") + "\n"
}

// splitLines splits as Python's str.splitlines does, for the line endings
// a text file has.
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	out := strings.Split(strings.NewReplacer("\r", "\n", "\v", "\n", "\f", "\n",
		"\x1c", "\n", "\x1d", "\n", "\x1e", "\n", "\x85", "\n", " ", "\n", " ", "\n").Replace(s), "\n")
	if len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

// hostAddresses are the host's global addresses, which get prohibit routes
// inside.
func hostAddresses(ip string) ([]string, error) {
	out, err := exec.Command(ip, "-o", "addr", "show", "scope", "global").Output()
	if err != nil {
		return nil, errorf("%s -o addr show scope global failed: %v", ip, err)
	}
	var addrs []string
	for _, line := range splitLines(string(out)) {
		if fields := strings.Fields(line); len(fields) > 3 {
			addr, _, _ := strings.Cut(fields[3], "/")
			addrs = append(addrs, addr)
		}
	}
	return addrs, nil
}

// Run by pasta, inside its netns, before bwrap: adds the prohibit routes
// while it still has pasta's CAP_NET_ADMIN (bwrap drops it, so the sandbox
// can't remove them), and opens the seccomp filter - here rather than in
// the launcher, since pasta closes inherited fds past stdio before running
// it.
const pastaInner = `
set -e
ip=$1 seccomp=$2 n=$3
shift 3
for addr in "${@:1:n}"; do
	"$ip" route replace prohibit "$addr"
done
shift "$n"
exec 10<"$seccomp"
exec "$@"
`

// pastaArgv: pasta creates a fresh net namespace with a userspace TAP and
// runs bwrap inside it; --config-net has pasta assign address/route/DNS.
//
// Ports bound inside are forwarded to the host's 127.0.0.1 (the explicit
// range because a bare `-t auto` skips the ephemeral range, where an OAuth
// login's callback listener binds); --host-lo-to-ns-lo delivers them to the
// namespace's loopback, so dev servers on 127.0.0.1 accept them. The host
// side binds 127.0.0.1 only: on *:port a browser opening localhost tries
// ::1 first, gets accepted, then reset.
//
// The other direction is closed except for the listed host ports: -T/-U
// mirror only those, --map-host-loopback/--map-guest-addr none remove the
// addresses pasta would translate to the host, and the host's own
// addresses get prohibit routes (a snapshot at start).
//
// The one exception is dnsResolver, a host resolver on loopback (see
// dnsForward), reachable at dnsForwardAddr on ports 53 and 853.
func pastaArgv(cfg *config, tcp, udp, addrs, bwrapArgs []string, dnsResolver string) []string {
	orNone := func(list []string) string {
		if len(list) == 0 {
			return "none"
		}
		return strings.Join(list, ",")
	}
	argv := []string{
		cfg.Tools.Pasta, "--config-net", "--host-lo-to-ns-lo",
		"-t", "127.0.0.1/1-65535,auto",
		"-T", orNone(tcp),
		"-U", orNone(udp),
		"--map-host-loopback", "none",
		"--map-guest-addr", "none",
	}
	if dnsResolver != "" {
		argv = append(argv, "--dns-forward", dnsForwardAddr, "--dns-host", dnsResolver)
	}
	argv = append(argv, "--", cfg.Tools.Bash, "-c", pastaInner, "bash",
		cfg.Tools.IP, cfg.Seccomp, strconv.Itoa(len(addrs)))
	argv = append(argv, addrs...)
	argv = append(argv, cfg.Tools.Bwrap, "--seccomp", "10")
	return append(argv, bwrapArgs...)
}
