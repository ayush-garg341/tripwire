package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// procNetFiles are the kernel tables listing every TCP socket on the box.
var procNetFiles = []string{"/proc/net/tcp", "/proc/net/tcp6"}

// lookupProcess names the process that opened a connection.
//
// in:  the local (source) and remote (destination) ports of an outbound SYN
// out: a description like "node(1421) /app/server.js", or "" if unattributable
//
// This is best-effort by nature: it maps port -> socket inode -> pid by reading
// /proc, and a connection that has already closed leaves nothing to find. It is
// only ever called when a *new* destination is seen, never per packet, so the
// /proc walk costs nothing in steady state.
func lookupProcess(localPort, remotePort uint16) string {
	inode, ok := socketInode(localPort, remotePort)
	if !ok {
		return ""
	}
	pid, ok := pidForInode(inode)
	if !ok {
		return ""
	}
	comm := strings.TrimSpace(readFile("/proc/" + pid + "/comm"))
	exe, _ := os.Readlink("/proc/" + pid + "/exe")
	if comm == "" && exe == "" {
		return ""
	}
	if exe == "" {
		return fmt.Sprintf("%s(%s)", comm, pid)
	}
	return fmt.Sprintf("%s(%s) %s", comm, pid, exe)
}

// socketInode finds the inode of the socket using a given port pair.
//
// in:  local and remote port, host byte order
// out: the inode string and true, or "" and false when no socket matches
//
// /proc/net/tcp columns are: sl, local_address, rem_address, st, ... , inode.
// Addresses are "HEXIP:HEXPORT"; only the ports are compared, which is enough
// to identify a single connection on one host.
func socketInode(localPort, remotePort uint16) (string, bool) {
	for _, f := range procNetFiles {
		for _, line := range strings.Split(readFile(f), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			if hexPort(fields[1]) != localPort || hexPort(fields[2]) != remotePort {
				continue
			}
			return fields[9], true
		}
	}
	return "", false
}

// pidForInode finds which process holds an open socket.
//
// in:  a socket inode as printed by /proc/net/tcp
// out: the pid as a string and true, or "" and false if no process holds it
//
// Every socket fd is a symlink reading "socket:[<inode>]", so this scans
// /proc/<pid>/fd for a matching link target.
func pidForInode(inode string) (string, bool) {
	target := "socket:[" + inode + "]"
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return "", false
	}
	for _, p := range procs {
		if !p.IsDir() || !isNumeric(p.Name()) {
			continue
		}
		fds, err := os.ReadDir("/proc/" + p.Name() + "/fd")
		if err != nil {
			continue // process exited, or not ours to inspect
		}
		for _, fd := range fds {
			link, err := os.Readlink("/proc/" + p.Name() + "/fd/" + fd.Name())
			if err == nil && link == target {
				return p.Name(), true
			}
		}
	}
	return "", false
}

// hexPort extracts the port from a "HEXIP:HEXPORT" field.
//
// in:  an address field from /proc/net/tcp
// out: the port, or 0 if the field is malformed
func hexPort(addr string) uint16 {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return 0
	}
	n, err := strconv.ParseUint(addr[i+1:], 16, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

// isNumeric reports whether a string is all digits, i.e. a pid directory.
//
// in:  a /proc entry name
// out: true if it names a process
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// readFile reads a file, returning "" on any error.
//
// in:  a path under /proc
// out: the contents, or "" if unreadable
//
// /proc reads fail routinely when a process exits mid-scan; that is expected,
// not exceptional, so errors collapse to an empty string.
func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}
