package launcher

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// parseHostPorts gives the tcp and udp port lists for pasta's -T/-U from
// entries like 5037, 8080/udp or 9000-9010.
func parseHostPorts(specs []string) (tcp, udp []string, err error) {
	for _, spec := range specs {
		ports, proto, _ := strings.Cut(spec, "/")
		from, to, isRange := strings.Cut(ports, "-")
		first, err1 := strconv.ParseUint(from, 10, 16)
		last, err2 := first, error(nil)
		if isRange {
			last, err2 = strconv.ParseUint(to, 10, 16)
		}
		if err1 != nil || err2 != nil || first == 0 || last < first || proto != "" && proto != "tcp" && proto != "udp" {
			return nil, nil, fmt.Errorf("bad SANDBOX_HOST_PORTS entry %q (want PORT[-PORT][/tcp|/udp], ports 1-65535)", spec)
		}
		if first == last {
			ports = strconv.FormatUint(first, 10)
		}
		if proto == "udp" {
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
	return slices.Concat(configured, strings.FieldsFunc(os.Getenv("SANDBOX_HOST_PORTS"), func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	}))
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
	for line := range strings.Lines(resolvConf) {
		line = strings.TrimSuffix(line, "\n")
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

// nameservers are resolvConf's that aren't on loopback or forwarded: the
// ones the sandbox dials itself, which the network policy lets it reach for
// DNS wherever they are - a router's or tailscale's would be refused with
// the rest of their network otherwise.
func nameservers(resolvConf string) []netip.Addr {
	var out []netip.Addr
	for line := range strings.Lines(resolvConf) {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil || addr.IsLoopback() || fields[1] == dnsForwardAddr {
			continue
		}
		out = append(out, addr.WithZone("").Unmap())
	}
	return out
}

// Where a cloud host's metadata service answers, with the instance's
// credentials: reached from the host, as pasta's connections are.
var metadataAddr = netip.MustParseAddr("169.254.169.254")

// hostAddresses are the addresses the sandbox is refused whatever it is
// allowed (see nftRules): the host's own, and the metadata service's. A
// snapshot at start.
func hostAddresses() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := []netip.Addr{metadataAddr}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if addr, ok := netip.AddrFromSlice(ipnet.IP); ok && !addr.IsLoopback() {
			out = append(out, addr.Unmap())
		}
	}
	return out, nil
}

// Run by pasta, inside its netns, before bwrap: loads the network policy
// and adds the prohibit routes while it still has pasta's CAP_NET_ADMIN
// (bwrap drops it, so the sandbox can't remove them), and opens the seccomp
// filter and bwrap's arguments - here rather than in the launcher, since
// pasta closes inherited fds past stdio before running it. No policy, no
// sandbox.
const pastaInner = `
set -e
ip=$1 nft=$2 rules=$3 seccomp=$4 args=$5 n=$6
shift 6
if ! "$nft" -f "$rules"; then
	echo "sandbox: nft couldn't load the network policy (it needs the kernel's nf_tables)" >&2
	exit 1
fi
for addr in "${@:1:n}"; do
	"$ip" route replace prohibit "$addr"
done
shift "$n"
exec 10<"$seccomp" 11<"$args"
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
// addresses are refused by rules, the nft ruleset (see nftRules), which
// also keeps the sandbox off every network but the public internet and
// what allowNet names.
//
// The host's global addresses get prohibit routes besides, which a plain
// connect fails on at once; a socket bound to the interface gets past a
// route, hence the ruleset.
//
// The one exception is dnsResolver, a host resolver on loopback (see
// dnsForward), reachable at dnsForwardAddr on ports 53 and 853.
//
// bwrap reads its options from argsFile (see guards.argsFile) and runs
// command.
func pastaArgv(cfg *config, tcp, udp []string, addrs []netip.Addr, rules, argsFile string, command []string, dnsResolver string) []string {
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
	var routes []string
	for _, addr := range addrs {
		if addr.IsGlobalUnicast() || addr == metadataAddr {
			routes = append(routes, addr.String())
		}
	}
	argv = append(argv, "--", cfg.Tools.Bash, "-c", pastaInner, "bash",
		cfg.Tools.IP, cfg.Tools.Nft, rules, cfg.Seccomp, argsFile, strconv.Itoa(len(routes)))
	argv = append(argv, routes...)
	argv = append(argv, cfg.Tools.Bwrap, "--seccomp", "10", "--args", "11")
	return append(argv, command...)
}
