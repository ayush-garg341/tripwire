package main

import (
	"encoding/binary"
	"net/netip"
)

const (
	ethHeaderLen = 14
	ethTypeIPv4  = 0x0800

	protoTCP = 6
	protoUDP = 17

	tcpFlagSYN = 0x02
	tcpFlagACK = 0x10
)

// packet is the small slice of an Ethernet/IPv4 frame the tripwire acts on.
// It is a value type built from netip.Addr so that decoding a packet costs
// zero heap allocations.
type packet struct {
	proto    uint8
	src, dst netip.Addr
	srcPort  uint16
	dstPort  uint16
	tcpFlags uint8  // TCP only
	payload  []byte // UDP only; aliases the capture buffer, do not retain
}

// parseFrame decodes one Ethernet frame carrying IPv4 TCP or UDP.
//
// in:  raw bytes straight off the capture socket
// out: the decoded packet and true, or false if the frame is not IPv4 TCP/UDP
//
// It never allocates: payload aliases b, so callers must finish with it before
// the next read overwrites the buffer. Anything malformed or truncated is
// reported as false rather than guessed at.
func parseFrame(b []byte) (packet, bool) {
	if len(b) < ethHeaderLen+20 {
		return packet{}, false
	}
	if binary.BigEndian.Uint16(b[12:14]) != ethTypeIPv4 {
		return packet{}, false
	}

	ip := b[ethHeaderLen:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+8 {
		return packet{}, false
	}

	p := packet{
		proto: ip[9],
		src:   netip.AddrFrom4([4]byte(ip[12:16])),
		dst:   netip.AddrFrom4([4]byte(ip[16:20])),
	}

	t := ip[ihl:]
	p.srcPort = binary.BigEndian.Uint16(t[0:2])
	p.dstPort = binary.BigEndian.Uint16(t[2:4])

	switch p.proto {
	case protoTCP:
		if len(t) < 20 {
			return packet{}, false
		}
		p.tcpFlags = t[13]
	case protoUDP:
		// Trust the UDP length field only as far as the bytes we actually got.
		n := int(binary.BigEndian.Uint16(t[4:6]))
		if n < 8 || n > len(t) {
			n = len(t)
		}
		p.payload = t[8:n]
	default:
		return packet{}, false
	}
	return p, true
}

// isConnectionStart reports whether a TCP packet is a bare SYN, i.e. the first
// packet of a new outbound connection rather than a reply in an existing one.
//
// in:  a decoded packet
// out: true for SYN-set/ACK-clear TCP
func (p packet) isConnectionStart() bool {
	return p.proto == protoTCP && p.tcpFlags&(tcpFlagSYN|tcpFlagACK) == tcpFlagSYN
}
