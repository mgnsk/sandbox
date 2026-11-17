# Emits the raw cBPF program scripts/bin/sandbox hands to `bwrap --seccomp`.
#
# A denylist over a default-allow policy: kernel attack-surface reduction for
# code running in the sandbox, not data isolation - what the sandbox can
# read/write is still decided by its binds. Denied calls return an errno
# rather than killing, so anything that probes for them falls back instead
# of dying far from the cause.

import errno
import socket
import sys
import termios

from seccomp import (
    ALLOW,
    EQ,
    ERRNO,
    GE,
    GT,
    KILL_PROCESS,
    MASKED_EQ,
    Arg,
    Attr,
    SyscallFilter,
)

f = SyscallFilter(defaction=ALLOW)

# Only the native ABI is in the filter; x32 and i386 (`int 0x80`) syscalls
# would otherwise reach the same kernel code under numbers none of the rules
# below match.
f.set_attr(Attr.ACT_BADARCH, KILL_PROCESS)

# io_uring: the most prolific source of recent kernel LPEs, and ops submitted
# through the ring never pass through seccomp at all. ENOSYS so
# libuv/tokio/bun fall back to epoll as on a kernel without it.
for name in ("io_uring_setup", "io_uring_enter", "io_uring_register"):
    f.add_rule(ERRNO(errno.ENOSYS), name)

# Everything but AF_UNIX, AF_INET, AF_INET6 and AF_NETLINK: rarely audited
# protocol code (AF_ALG, TIPC, RDS, VSOCK, ...) and the module autoloading
# socket() triggers for it. The kernel takes the family as an int but seccomp
# sees the full register, so anything with high bits set lands in the final
# >= rule and is denied too.
low = 0
for allowed in (socket.AF_UNIX, socket.AF_INET, socket.AF_INET6, socket.AF_NETLINK):
    for family in range(low, allowed):
        f.add_rule(ERRNO(errno.EAFNOSUPPORT), "socket", Arg(0, EQ, family))
    low = allowed + 1
f.add_rule(ERRNO(errno.EAFNOSUPPORT), "socket", Arg(0, GE, low))

# Kernel keyrings aren't fully namespaced; the inherited session keyring can
# hold host credentials.
for name in ("keyctl", "add_key", "request_key"):
    f.add_rule(ERRNO(errno.EPERM), name)

# The sandbox shares the host's tty (no --new-session, to keep job control),
# so these could type into the parent shell after it exits.
# dev.tty.legacy_tiocsti=0 already blocks TIOCSTI; this doesn't depend on it.
# Masked to 32 bits since the kernel ignores the upper half of the command -
# CVE-2019-10063 was Flatpak comparing all 64.
for cmd in (termios.TIOCSTI, termios.TIOCLINUX):
    f.add_rule(ERRNO(errno.EPERM), "ioctl", Arg(1, MASKED_EQ, 0xFFFFFFFF, cmd))

# Further LPE surface nothing in a dev sandbox needs; bpf is already off for
# unprivileged users via sysctl, this doesn't depend on it.
for name in ("perf_event_open", "userfaultfd", "bpf"):
    f.add_rule(ERRNO(errno.EPERM), name)

# Only PER_LINUX and the 0xffffffff query: no ADDR_NO_RANDOMIZE,
# READ_IMPLIES_EXEC, etc. libseccomp allows one comparison per argument per
# rule, so "neither 0 nor all ones" is spelled as "some bit set whose (cyclic)
# neighbour is clear", one rule per bit. Values with high bits set are denied
# too rather than trusting the kernel's truncation to 32 bits.
for bit in range(32):
    set_bit, clear_bit = 1 << bit, 1 << ((bit + 1) % 32)
    f.add_rule(
        ERRNO(errno.EINVAL),
        "personality",
        Arg(0, MASKED_EQ, set_bit | clear_bit, set_bit),
    )
f.add_rule(ERRNO(errno.EINVAL), "personality", Arg(0, GT, 0xFFFFFFFF))

f.export_bpf(sys.stdout)
