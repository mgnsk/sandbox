package seccomp

import (
	"encoding/binary"
	"runtime"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Offsets into struct seccomp_data. The args are 64 bits each; the low half
// comes first on the (little-endian) archs the sandbox builds for.
const (
	offNr   = 0
	offArch = 4
	offArgs = 16
)

func argLo(i uint32) uint32 { return offArgs + 8*i }
func argHi(i uint32) uint32 { return offArgs + 8*i + 4 }

// The native arch's audit arch, and the bit that marks a syscall of the
// second ABI under it (x32 under x86_64).
var arches = map[string]struct{ audit, secondABI uint32 }{
	"amd64": {unix.AUDIT_ARCH_X86_64, 0x40000000},
	"arm64": {unix.AUDIT_ARCH_AARCH64, 0},
}

// load decodes the exported program for x/net/bpf's VM.
func load(t *testing.T) *bpf.VM {
	t.Helper()
	prog, err := Program()
	if err != nil {
		t.Fatal(err)
	}
	var ins []bpf.Instruction
	for b := prog; len(b) >= 8; b = b[8:] {
		ins = append(ins, bpf.RawInstruction{
			Op: binary.NativeEndian.Uint16(b),
			Jt: b[2],
			Jf: b[3],
			K:  binary.NativeEndian.Uint32(b[4:]),
		}.Disassemble())
	}
	vm, err := bpf.NewVM(ins)
	if err != nil {
		t.Fatal(err)
	}
	return vm
}

// call is a syscall as the filter sees it.
type call struct {
	arch       uint32
	nr         uint32
	arg0, arg1 uint64
}

// run evaluates the filter in x/net/bpf's VM, which loads big-endian: each
// 32-bit word is written that way, at the offset it has on the native arch.
func run(t *testing.T, vm *bpf.VM, c call) uint32 {
	t.Helper()
	d := make([]byte, 64)
	put := func(off, v uint32) { binary.BigEndian.PutUint32(d[off:], v) }
	put(offNr, c.nr)
	put(offArch, c.arch)
	put(argLo(0), uint32(c.arg0))
	put(argHi(0), uint32(c.arg0>>32))
	put(argLo(1), uint32(c.arg1))
	put(argHi(1), uint32(c.arg1>>32))
	ret, err := vm.Run(d)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(ret)
}

func TestFilter(t *testing.T) {
	arch, ok := arches[runtime.GOARCH]
	if !ok {
		t.Skipf("no audit arch for %s", runtime.GOARCH)
	}
	auditArch, x32SyscallBit := arch.audit, arch.secondABI
	vm := load(t)

	allow := uint32(unix.SECCOMP_RET_ALLOW)
	kill := uint32(unix.SECCOMP_RET_KILL_PROCESS)
	native := func(nr uint32, args ...uint64) call {
		c := call{arch: auditArch, nr: nr}
		if len(args) > 0 {
			c.arg0 = args[0]
		}
		if len(args) > 1 {
			c.arg1 = args[1]
		}
		return c
	}
	cases := []struct {
		name string
		call call
		want uint32
	}{
		{"read", native(unix.SYS_READ), allow},
		{"other arch", call{arch: 0x40000003, nr: unix.SYS_READ}, kill},
		{"io_uring_setup", native(unix.SYS_IO_URING_SETUP), retErrno(unix.ENOSYS)},
		{"io_uring_enter", native(unix.SYS_IO_URING_ENTER), retErrno(unix.ENOSYS)},
		{"io_uring_register", native(unix.SYS_IO_URING_REGISTER), retErrno(unix.ENOSYS)},
		{"keyctl", native(unix.SYS_KEYCTL), retErrno(unix.EPERM)},
		{"add_key", native(unix.SYS_ADD_KEY), retErrno(unix.EPERM)},
		{"request_key", native(unix.SYS_REQUEST_KEY), retErrno(unix.EPERM)},
		{"perf_event_open", native(unix.SYS_PERF_EVENT_OPEN), retErrno(unix.EPERM)},
		{"userfaultfd", native(unix.SYS_USERFAULTFD), retErrno(unix.EPERM)},
		{"bpf", native(unix.SYS_BPF), retErrno(unix.EPERM)},
		{"socket AF_UNIX", native(unix.SYS_SOCKET, unix.AF_UNIX), allow},
		{"socket AF_INET", native(unix.SYS_SOCKET, unix.AF_INET), allow},
		{"socket AF_INET6", native(unix.SYS_SOCKET, unix.AF_INET6), allow},
		{"socket AF_NETLINK", native(unix.SYS_SOCKET, unix.AF_NETLINK), allow},
		{"socket AF_UNSPEC", native(unix.SYS_SOCKET, unix.AF_UNSPEC), retErrno(unix.EAFNOSUPPORT)},
		{"socket AF_ALG", native(unix.SYS_SOCKET, unix.AF_ALG), retErrno(unix.EAFNOSUPPORT)},
		{"socket AF_VSOCK", native(unix.SYS_SOCKET, unix.AF_VSOCK), retErrno(unix.EAFNOSUPPORT)},
		{"socket AF_INET high bits", native(unix.SYS_SOCKET, 1<<32|unix.AF_INET), retErrno(unix.EAFNOSUPPORT)},
		{"ioctl TIOCSTI", native(unix.SYS_IOCTL, 0, unix.TIOCSTI), retErrno(unix.EPERM)},
		{"ioctl TIOCLINUX", native(unix.SYS_IOCTL, 0, unix.TIOCLINUX), retErrno(unix.EPERM)},
		{"ioctl TIOCSTI high bits", native(unix.SYS_IOCTL, 0, 1<<32|unix.TIOCSTI), retErrno(unix.EPERM)},
		{"ioctl TIOCGWINSZ", native(unix.SYS_IOCTL, 0, unix.TIOCGWINSZ), allow},
		{"personality PER_LINUX", native(unix.SYS_PERSONALITY, 0), allow},
		{"personality query", native(unix.SYS_PERSONALITY, 0xffffffff), allow},
		{"personality ADDR_NO_RANDOMIZE", native(unix.SYS_PERSONALITY, 0x0040000), retErrno(unix.EINVAL)},
		{"personality READ_IMPLIES_EXEC", native(unix.SYS_PERSONALITY, 0x0400000), retErrno(unix.EINVAL)},
		{"personality high bits", native(unix.SYS_PERSONALITY, 1<<32), retErrno(unix.EINVAL)},
		{"personality all ones", native(unix.SYS_PERSONALITY, ^uint64(0)), retErrno(unix.EINVAL)},
	}
	if x32SyscallBit != 0 {
		cases = append(cases, struct {
			name string
			call call
			want uint32
		}{"x32", native(x32SyscallBit | unix.SYS_READ), kill})
	}
	for _, c := range cases {
		if got := run(t, vm, c.call); got != c.want {
			t.Errorf("%s: got %#x, want %#x", c.name, got, c.want)
		}
	}
}

// retErrno is the filter's return value for an errno action.
func retErrno(e unix.Errno) uint32 {
	return unix.SECCOMP_RET_ERRNO | uint32(e)&unix.SECCOMP_RET_DATA
}
