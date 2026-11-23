package launcher

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/mgnsk/sandbox/internal/hostname"
)

func prefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, p := range list {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// nonPublic is what the sandbox can't reach unless allowed: everything that
// isn't the public internet - private, CGNAT (tailscale's), link-local,
// multicast and reserved ranges. None overlap, as an nft set needs.
var nonPublic = prefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"224.0.0.0/4", "240.0.0.0/4",
	"fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b:1::/48",
)

// allowNetKeywords are the entries that stand for ranges. tailscale is its
// address ranges and not its interface: inside there's only pasta's
// interface, and which one a connection leaves the host on is the host's
// routing.
var allowNetKeywords = map[string][]netip.Prefix{
	"all": prefixes("0.0.0.0/0", "::/0"),
	"lan": prefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4",
		"fc00::/7", "fe80::/10", "ff00::/8"),
	"tailscale": prefixes("100.64.0.0/10", "fd7a:115c:a1e0::/48"),
}

// allowNetSpecs is the configured entries plus SANDBOX_ALLOW_NET from the
// host's environment - never from inside, since --clearenv keeps it out.
func allowNetSpecs(configured []string) []string {
	return slices.Concat(configured, strings.FieldsFunc(os.Getenv("SANDBOX_ALLOW_NET"), func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	}))
}

// lookupHost resolves an allowNet host name, on the host and once: what it
// gives at start is what's allowed.
func lookupHost(host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// allowed is a destination the sandbox reaches past nonPublic: on every
// port and protocol, or with ports (8080, 8000-8100) on proto (tcp, udp)
// only.
type allowed struct {
	prefix       netip.Prefix
	proto, ports string
}

func (a allowed) String() string {
	if a.ports == "" {
		return a.prefix.String()
	}
	return fmt.Sprintf("%s:%s/%s", a.prefix, a.ports, a.proto)
}

// everyPort allows list whole.
func everyPort(list []netip.Prefix) []allowed {
	out := make([]allowed, len(list))
	for i, p := range list {
		out[i] = allowed{prefix: p}
	}
	return out
}

// parseAllowNet gives what's allowed past nonPublic, from entries like
// 192.168.1.50, 10.0.0.0/8, 192.168.1.*, nas.lan, lan, tailscale or all,
// each on every port or with :PORT[-PORT][/tcp|/udp] on those only
// (192.168.1.50:8080, [fd00::5]:53/udp). A host name that doesn't resolve
// is a warning and left out: the sandbox still starts offline.
func parseAllowNet(specs []string, lookup func(string) ([]netip.Addr, error)) (allow []allowed, warnings []string, err error) {
	for _, spec := range specs {
		target, proto, ports, ok := splitPorts(strings.ToLower(spec))
		var list []netip.Prefix
		warning := ""
		if ok {
			list, warning, ok = allowTarget(target, lookup)
		}
		if !ok {
			return nil, nil, fmt.Errorf("bad SANDBOX_ALLOW_NET entry %q (want an address, a CIDR, 192.168.1.*, a host name, lan, tailscale or all, "+
				"with :PORT[-PORT][/tcp|/udp] for those ports only, an IPv6 address then in brackets)", spec)
		}
		if warning != "" {
			warnings = append(warnings, warning)
		}
		for _, p := range list {
			allow = append(allow, allowed{prefix: p, proto: proto, ports: ports})
		}
	}
	return allow, warnings, nil
}

// splitPorts takes the ports off an entry: 10.0.0.1:8080, nas.lan:53/udp,
// [fd00::5]:8000-8100. An IPv6 address has colons of its own, so it takes
// ports only in brackets; proto and ports are "" for an entry without.
func splitPorts(spec string) (target, proto, ports string, ok bool) {
	port := ""
	switch {
	case strings.HasPrefix(spec, "["):
		inside, rest, closed := strings.Cut(spec[1:], "]")
		if !closed || !strings.Contains(inside, ":") {
			return "", "", "", false
		}
		if rest == "" {
			return inside, "", "", true
		}
		if !strings.HasPrefix(rest, ":") {
			return "", "", "", false
		}
		target, port = inside, rest[1:]
	case strings.Count(spec, ":") == 1:
		target, port, _ = strings.Cut(spec, ":")
	default:
		return spec, "", "", true
	}
	ports, proto, ok = portRange(port)
	return target, proto, ports, ok
}

// allowTarget is what an entry without its ports names; a warning and
// nothing for a host name that doesn't resolve.
func allowTarget(name string, lookup func(string) ([]netip.Addr, error)) (list []netip.Prefix, warning string, ok bool) {
	if list, ok := allowNetKeywords[name]; ok {
		return list, "", true
	}
	if strings.Contains(name, "*") {
		p, ok := wildcard(name)
		return []netip.Prefix{p}, "", ok
	}
	if strings.Contains(name, "/") {
		p, err := netip.ParsePrefix(name)
		if err != nil {
			return nil, "", false
		}
		return []netip.Prefix{netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()}, "", true
	}
	if addr, err := netip.ParseAddr(name); err == nil {
		return []netip.Prefix{single(addr)}, "", addr.Zone() == ""
	}
	// An address cut short (192.168.1) is a mistake, not a name.
	last := name[strings.LastIndex(name, ".")+1:]
	if _, err := strconv.ParseUint(last, 10, 64); err == nil || !hostname.Valid(name) {
		return nil, "", false
	}
	addrs, err := lookup(name)
	if err != nil || len(addrs) == 0 {
		reason := "no addresses"
		if err != nil {
			reason = err.Error()
		}
		return nil, fmt.Sprintf("SANDBOX_ALLOW_NET: %s not resolved, so not allowed (%s)", name, reason), true
	}
	for _, addr := range addrs {
		list = append(list, single(addr.WithZone("")))
	}
	return list, "", true
}

func single(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen())
}

// wildcard is the IPv4 prefix for 10.*, 192.168.* or 192.168.1.* (the rest
// may be spelled out: 10.*.*.*): whole trailing octets only.
func wildcard(spec string) (netip.Prefix, bool) {
	parts := strings.Split(spec, ".")
	fixed := slices.Index(parts, "*")
	if fixed < 1 || len(parts) > 4 {
		return netip.Prefix{}, false
	}
	var octets [4]byte
	for i, part := range parts {
		if i >= fixed {
			if part != "*" {
				return netip.Prefix{}, false
			}
			continue
		}
		n, err := strconv.ParseUint(part, 10, 8)
		if err != nil || strconv.FormatUint(n, 10) != part {
			return netip.Prefix{}, false
		}
		octets[i] = byte(n)
	}
	return netip.PrefixFrom(netip.AddrFrom4(octets), 8*fixed), true
}

// distinct is list, in its order, without duplicates and without prefixes
// inside another of it: an nft set takes no overlapping elements.
func distinct(list []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for i, p := range list {
		inside := func(q netip.Prefix) bool { return q.Bits() < p.Bits() && q.Contains(p.Addr()) }
		if !slices.ContainsFunc(list, inside) && !slices.Contains(list[:i], p) {
			out = append(out, p)
		}
	}
	return out
}

// nftRules is the ruleset loaded in the sandbox's net namespace before bwrap
// drops the capability to change it: an output chain, since unlike a
// prohibit route it also holds for a socket bound to the interface.
//
// In order: loopback, which is the sandbox itself and the host ports pasta
// mirrors there; the forwarded resolver; IPv6's neighbour discovery, whose
// link-local and multicast destinations are refused further down; host,
// the host's own addresses and the metadata service's, refused whatever is
// allowed; nameservers, the sandbox's own, for DNS only; allow, a rule for
// each set of ports; and nonPublic, refused. The rest - the public
// internet - passes.
func nftRules(allow []allowed, host, nameservers []netip.Addr, dnsForward bool) string {
	const dns = "meta l4proto { tcp, udp } th dport { 53, 853 }"
	const reject = "reject with icmpx type admin-prohibited"
	rules := []string{
		"type filter hook output priority 0; policy accept;",
		`oifname "lo" accept`,
	}
	if dnsForward {
		rules = append(rules, fmt.Sprintf("ip daddr %s %s accept", dnsForwardAddr, dns))
	}
	rules = append(rules, "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, "+
		"mld-listener-report, mld-listener-done, mld2-listener-report } accept")

	singles := func(addrs []netip.Addr) []netip.Prefix {
		var out []netip.Prefix
		for _, addr := range addrs {
			out = append(out, single(addr.WithZone("")))
		}
		return out
	}
	// What's allowed by its ports, "" for every one, in the entries' order.
	var dports []string
	byPorts := map[string][]netip.Prefix{}
	for _, a := range allow {
		dport := ""
		if a.ports != "" {
			dport = fmt.Sprintf(" %s dport %s", a.proto, a.ports)
		}
		if _, seen := byPorts[dport]; !seen {
			dports = append(dports, dport)
		}
		byPorts[dport] = append(byPorts[dport], a.prefix)
	}
	for _, family := range []struct {
		name, nfproto string
		is4           bool
	}{{"ip", "ipv4", true}, {"ip6", "ipv6", false}} {
		// "" for nothing of this family, so no rule.
		daddr := func(list []netip.Prefix) string {
			var elems []string
			for _, p := range distinct(list) {
				switch {
				case p.Addr().Is4() != family.is4:
				case p.IsSingleIP():
					elems = append(elems, p.Addr().String())
				default:
					elems = append(elems, p.String())
				}
			}
			if len(elems) == 0 {
				return ""
			}
			return fmt.Sprintf("%s daddr { %s }", family.name, strings.Join(elems, ", "))
		}
		if match := daddr(singles(host)); match != "" {
			rules = append(rules, match+" "+reject)
		}
		if match := daddr(singles(nameservers)); match != "" {
			rules = append(rules, match+" "+dns+" accept")
		}
		for _, dport := range dports {
			list := byPorts[dport]
			// Every address isn't a set element nft takes.
			if slices.ContainsFunc(list, func(p netip.Prefix) bool { return p.Addr().Is4() == family.is4 && p.Bits() == 0 }) {
				rules = append(rules, fmt.Sprintf("meta nfproto %s%s accept", family.nfproto, dport))
			} else if match := daddr(list); match != "" {
				rules = append(rules, match+dport+" accept")
			}
		}
		rules = append(rules, daddr(nonPublic)+" "+reject)
	}
	return "table inet sandbox {\n\tchain out {\n\t\t" + strings.Join(rules, "\n\t\t") + "\n\t}\n}\n"
}

// nftFile writes rules where pasta's command reads them from: gone with the
// launcher, like bwrap's arguments.
func (g *guards) nftFile(rules string) (string, error) {
	dir, err := g.tempdir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "net.nft")
	return path, os.WriteFile(path, []byte(rules), 0o600)
}
