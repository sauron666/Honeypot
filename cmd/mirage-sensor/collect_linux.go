//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/user"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// Linux collector: the kernel's process-events connector (netlink). It delivers
// a message on every fork/exec/exit system-wide, so no process an attacker runs
// is missed — the way auditd's execve rule works, but self-contained. It needs
// CAP_NET_ADMIN (run as root on the decoy).
//
// Cannot be exercised in CI (needs privileges and a Linux kernel), like the
// DRAKVUF and FUSE paths; the forwarder it feeds is unit-tested.

const (
	cnIdxProc         = 0x1
	cnValProc         = 0x1
	procCNMcastListen = 1
	procEventExec     = 0x00000002
	netlinkConnector  = 11
)

func collect(ctx context.Context, decoyID string, fwd *forwarder) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, netlinkConnector)
	if err != nil {
		return fmt.Errorf("open netlink socket (need root): %w", err)
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())}
	if err := unix.Bind(fd, addr); err != nil {
		return fmt.Errorf("bind netlink: %w", err)
	}
	if err := subscribe(fd); err != nil {
		return fmt.Errorf("subscribe to proc events: %w", err)
	}
	logf("subscribed to kernel process events")

	// Unblock the read loop when the context ends.
	go func() {
		<-ctx.Done()
		unix.Close(fd)
	}()

	buf := make([]byte, 8192)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("recv: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			continue
		}
		for _, m := range msgs {
			s, ok := parseExec(m.Data, decoyID)
			if ok {
				fwd.enqueue(s)
			}
		}
	}
}

// subscribe sends PROC_CN_MCAST_LISTEN so the kernel starts multicasting events.
func subscribe(fd int) error {
	// nlmsghdr(16) + cn_msg(20) + op(4)
	const dataLen = 4
	const cnLen = 20 + dataLen
	total := unix.NLMSG_HDRLEN + cnLen
	b := make([]byte, total)

	binary.LittleEndian.PutUint32(b[0:], uint32(total))        // nlmsg_len
	binary.LittleEndian.PutUint16(b[4:], unix.NLMSG_DONE)      // nlmsg_type
	binary.LittleEndian.PutUint16(b[6:], 0)                    // flags
	binary.LittleEndian.PutUint32(b[8:], 0)                    // seq
	binary.LittleEndian.PutUint32(b[12:], uint32(os.Getpid())) // pid

	off := unix.NLMSG_HDRLEN
	binary.LittleEndian.PutUint32(b[off+0:], cnIdxProc) // cb_id.idx
	binary.LittleEndian.PutUint32(b[off+4:], cnValProc) // cb_id.val
	binary.LittleEndian.PutUint32(b[off+8:], 0)         // seq
	binary.LittleEndian.PutUint32(b[off+12:], 0)        // ack
	binary.LittleEndian.PutUint16(b[off+16:], dataLen)  // len
	binary.LittleEndian.PutUint16(b[off+18:], 0)        // flags
	binary.LittleEndian.PutUint32(b[off+20:], procCNMcastListen)

	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	return unix.Sendto(fd, b, 0, addr)
}

// parseExec pulls an exec event out of a connector message and reads the new
// process's details from /proc. data is the netlink payload: cn_msg + proc_event.
func parseExec(data []byte, decoyID string) (drivers.Sighting, bool) {
	// cn_msg header is 20 bytes; proc_event follows.
	if len(data) < 20+16+8 {
		return drivers.Sighting{}, false
	}
	pe := data[20:]
	what := binary.LittleEndian.Uint32(pe[0:])
	if what != procEventExec {
		return drivers.Sighting{}, false
	}
	// proc_event: what(4) cpu(4) timestamp(8) then exec_proc_event{pid, tgid}.
	pid := int32(binary.LittleEndian.Uint32(pe[16:]))
	tgid := int32(binary.LittleEndian.Uint32(pe[20:]))

	comm := readProc(int(tgid), "comm")
	cmdline := readCmdline(int(tgid))
	if comm == "" && cmdline == "" {
		// The process already exited; nothing to report.
		return drivers.Sighting{}, false
	}
	s := drivers.Sighting{
		DecoyID: decoyID, Time: time.Now(), Kind: "process", Action: "exec",
		Process: strings.TrimSpace(comm), CommandLine: cmdline,
		PID: int(pid), User: procUser(int(tgid)),
	}
	if ppid := readPPID(int(tgid)); ppid > 0 {
		s.PPID = ppid
	}
	return s, true
}

func readProc(pid int, name string) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, name))
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(b), "\n\x00")
}

func readCmdline(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	// Arguments are NUL-separated.
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

func readPPID(pid int) int {
	status := readProc(pid, "status")
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "PPid:") {
			var ppid int
			fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")), "%d", &ppid)
			return ppid
		}
	}
	return 0
}

// procUser resolves the process's real UID to a username, falling back to the
// numeric uid.
func procUser(pid int) string {
	status := readProc(pid, "status")
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) > 0 {
				if u, err := user.LookupId(fields[0]); err == nil {
					return u.Username
				}
				return fields[0]
			}
		}
	}
	return ""
}
