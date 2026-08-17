//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// readTimeout bounds how long a read blocks, so the capture loop wakes up
// regularly enough to run housekeeping (saving state, reloading rules) without
// needing a second goroutine and a lock around shared state.
const readTimeout = 1

// captureBuf caps kernel-side queueing. Only SYNs and DNS get this far, so a
// small buffer is plenty and keeps the socket's memory footprint fixed.
const captureBuf = 256 * 1024

// capture is a raw AF_PACKET socket with the tripwire's filter attached.
//
// libpcap is deliberately not used: talking to AF_PACKET directly removes the
// cgo dependency, which is what lets this build as a single static binary with
// nothing to install on the target box.
type capture struct {
	fd    int
	iface string
}

// openCapture binds a filtered capture socket to an interface.
//
// in:  interface name, e.g. "eth0" or "ens5"
// out: an open capture, or an error (EPERM means it needs root or CAP_NET_RAW)
//
// The filter is attached *before* the bind so that no unfiltered traffic can
// slip through in the window between the two.
func openCapture(iface string) (*capture, error) {
	link, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("opening packet socket (needs root or CAP_NET_RAW): %w", err)
	}
	c := &capture{fd: fd, iface: iface}

	prog, err := filterProgram()
	if err != nil {
		c.close()
		return nil, err
	}
	fprog := &unix.SockFprog{
		Len:    uint16(len(prog)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&prog[0])),
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, fprog); err != nil {
		c.close()
		return nil, fmt.Errorf("attaching filter: %w", err)
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, captureBuf); err != nil {
		c.close()
		return nil, fmt.Errorf("setting receive buffer: %w", err)
	}
	tv := unix.Timeval{Sec: readTimeout}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		c.close()
		return nil, fmt.Errorf("setting read timeout: %w", err)
	}

	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  link.Index,
	}
	if err := unix.Bind(fd, addr); err != nil {
		c.close()
		return nil, fmt.Errorf("binding to %s: %w", iface, err)
	}
	return c, nil
}

// read returns the next packet that passed the kernel filter.
//
// in:  a buffer to read into, reused across calls
// out: bytes read, whether the packet was sent *by* this host, and an error
//
// (0, false, nil) means the read timed out with no packet, which is the
// caller's cue to do housekeeping. The outgoing flag comes from AF_PACKET's
// own packet type, so direction costs nothing to determine and never has to be
// inferred from the addresses.
func (c *capture) read(buf []byte) (int, bool, error) {
	n, from, err := unix.Recvfrom(c.fd, buf, 0)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return 0, false, nil
		}
		return 0, false, err
	}
	ll, ok := from.(*unix.SockaddrLinklayer)
	return n, ok && ll.Pkttype == unix.PACKET_OUTGOING, nil
}

// close releases the capture socket.
//
// in:  nothing
// out: error from the underlying close
func (c *capture) close() error {
	if c.fd >= 0 {
		fd := c.fd
		c.fd = -1
		return unix.Close(fd)
	}
	return nil
}

// htons converts a port or protocol number to network byte order.
//
// in:  a host-order 16-bit value
// out: the same value in network order
//
// Assumes a little-endian host, which covers every architecture EC2 offers
// (x86-64 and Graviton are both little-endian under Linux).
func htons(v uint16) uint16 {
	return v<<8 | v>>8
}
