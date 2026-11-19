// Package seccomp builds the raw cBPF program the launcher hands to
// `bwrap --seccomp`, with libseccomp. It needs cgo, so only the build-time
// generator (cmd/seccomp-bpf) links it, not the sandbox binary.
//
// A denylist over a default-allow policy: kernel attack-surface reduction for
// code running in the sandbox, not data isolation - what the sandbox can
// read/write is still decided by its binds. Denied calls return an errno
// rather than killing, so anything that probes for them falls back instead
// of dying far from the cause.
package seccomp

import (
	"fmt"

	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

func errno(e unix.Errno) libseccomp.ScmpAction {
	return libseccomp.ActErrno.SetReturnCode(int16(e))
}

// rule denies a syscall when all of its conditions hold.
type rule struct {
	name  string
	act   libseccomp.ScmpAction
	conds []libseccomp.ScmpCondition
}

func cond(arg uint, op libseccomp.ScmpCompareOp, values ...uint64) libseccomp.ScmpCondition {
	c := libseccomp.ScmpCondition{Argument: arg, Op: op, Operand1: values[0]}
	if len(values) > 1 {
		c.Operand2 = values[1]
	}
	return c
}

func rules() []rule {
	var rs []rule
	deny := func(act libseccomp.ScmpAction, names ...string) {
		for _, name := range names {
			rs = append(rs, rule{name: name, act: act})
		}
	}

	// io_uring: the most prolific source of recent kernel LPEs, and ops
	// submitted through the ring never pass through seccomp at all. ENOSYS
	// so libuv/tokio/bun fall back to epoll as on a kernel without it.
	deny(errno(unix.ENOSYS), "io_uring_setup", "io_uring_enter", "io_uring_register")

	// Everything but AF_UNIX, AF_INET, AF_INET6 and AF_NETLINK: rarely
	// audited protocol code (AF_ALG, TIPC, RDS, VSOCK, ...) and the module
	// autoloading socket() triggers for it. The kernel takes the family as
	// an int but seccomp sees the full register, so anything with high bits
	// set lands in the final >= rule and is denied too.
	var low uint64
	for _, allowed := range []uint64{unix.AF_UNIX, unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK} {
		for family := low; family < allowed; family++ {
			rs = append(rs, rule{"socket", errno(unix.EAFNOSUPPORT),
				[]libseccomp.ScmpCondition{cond(0, libseccomp.CompareEqual, family)}})
		}
		low = allowed + 1
	}
	rs = append(rs, rule{"socket", errno(unix.EAFNOSUPPORT),
		[]libseccomp.ScmpCondition{cond(0, libseccomp.CompareGreaterEqual, low)}})

	// Kernel keyrings aren't fully namespaced; the inherited session keyring
	// can hold host credentials.
	deny(errno(unix.EPERM), "keyctl", "add_key", "request_key")

	// The sandbox shares the host's tty (no --new-session, to keep job
	// control), so these could type into the parent shell after it exits.
	// dev.tty.legacy_tiocsti=0 already blocks TIOCSTI; this doesn't depend
	// on it. Masked to 32 bits since the kernel ignores the upper half of the
	// command - CVE-2019-10063 was Flatpak comparing all 64.
	for _, cmd := range []uint64{unix.TIOCSTI, unix.TIOCLINUX} {
		rs = append(rs, rule{"ioctl", errno(unix.EPERM),
			[]libseccomp.ScmpCondition{cond(1, libseccomp.CompareMaskedEqual, 0xFFFFFFFF, cmd)}})
	}

	// Further LPE surface nothing in a dev sandbox needs; bpf is already off
	// for unprivileged users via sysctl, this doesn't depend on it.
	deny(errno(unix.EPERM), "perf_event_open", "userfaultfd", "bpf")

	// Only PER_LINUX and the 0xffffffff query: no ADDR_NO_RANDOMIZE,
	// READ_IMPLIES_EXEC, etc. libseccomp allows one comparison per argument
	// per rule, so "neither 0 nor all ones" is spelled as "some bit set whose
	// (cyclic) neighbour is clear", one rule per bit. Values with high bits
	// set are denied too rather than trusting the kernel's truncation to 32
	// bits.
	for bit := range 32 {
		set, clear := uint64(1)<<bit, uint64(1)<<((bit+1)%32)
		rs = append(rs, rule{"personality", errno(unix.EINVAL),
			[]libseccomp.ScmpCondition{cond(0, libseccomp.CompareMaskedEqual, set|clear, set)}})
	}
	rs = append(rs, rule{"personality", errno(unix.EINVAL),
		[]libseccomp.ScmpCondition{cond(0, libseccomp.CompareGreater, 0xFFFFFFFF)}})

	return rs
}

// Program returns the filter as bwrap reads it: an array of struct
// sock_filter in native byte order, for the native arch.
func Program() ([]byte, error) {
	f, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		return nil, fmt.Errorf("seccomp: %w", err)
	}
	defer f.Release()

	// Only the native ABI is in the filter; x32 and i386 (`int 0x80`)
	// syscalls would otherwise reach the same kernel code under numbers none
	// of the rules match.
	if err := f.SetBadArchAction(libseccomp.ActKillProcess); err != nil {
		return nil, fmt.Errorf("seccomp: %w", err)
	}
	for _, r := range rules() {
		nr, err := libseccomp.GetSyscallFromName(r.name)
		if err != nil {
			return nil, fmt.Errorf("seccomp: %s: %w", r.name, err)
		}
		if len(r.conds) == 0 {
			err = f.AddRule(nr, r.act)
		} else {
			err = f.AddRuleConditional(nr, r.act, r.conds)
		}
		if err != nil {
			return nil, fmt.Errorf("seccomp: %s: %w", r.name, err)
		}
	}
	prog, err := f.ExportBPFMem()
	if err != nil {
		return nil, fmt.Errorf("seccomp: %w", err)
	}
	return prog, nil
}
