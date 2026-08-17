package main

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
)

// The filter is hand-written BPF with manually counted jump offsets, so it is
// the one part of this program that cannot be eyeballed for correctness. These
// tests run real frames through a BPF VM and assert accept/drop, which catches
// any miscounted skip immediately.

// frame builds an Ethernet/IPv4 test packet.
//
// in:  ethertype, IP protocol, IP header length, fragment field, transport bytes
// out: a complete frame
func frame(ethType uint16, proto uint8, ihl int, fragField uint16, transport []byte) []byte {
	b := make([]byte, ethHeaderLen+ihl+len(transport))
	binary.BigEndian.PutUint16(b[12:14], ethType)

	ip := b[ethHeaderLen:]
	ip[0] = 0x40 | uint8(ihl/4) // version 4, header length in 32-bit words
	binary.BigEndian.PutUint16(ip[2:4], uint16(ihl+len(transport)))
	binary.BigEndian.PutUint16(ip[6:8], fragField)
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], []byte{10, 0, 0, 5})    // src
	copy(ip[16:20], []byte{93, 184, 16, 3}) // dst
	copy(ip[ihl:], transport)
	return b
}

// tcpHeader builds a minimal TCP header with the given flags.
//
// in:  source port, destination port, flags byte
// out: a 20-byte TCP header
func tcpHeader(sport, dport uint16, flags uint8) []byte {
	t := make([]byte, 20)
	binary.BigEndian.PutUint16(t[0:2], sport)
	binary.BigEndian.PutUint16(t[2:4], dport)
	t[12] = 5 << 4 // data offset
	t[13] = flags
	return t
}

// udpHeader builds a minimal UDP header.
//
// in:  source and destination port
// out: an 8-byte UDP header
func udpHeader(sport, dport uint16) []byte {
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u[0:2], sport)
	binary.BigEndian.PutUint16(u[2:4], dport)
	binary.BigEndian.PutUint16(u[4:6], 8)
	return u
}

func TestFilterAcceptsAndDrops(t *testing.T) {
	vm, err := bpf.NewVM(filterInstructions())
	if err != nil {
		t.Fatalf("assembling filter: %v", err)
	}

	tests := []struct {
		name string
		pkt  []byte
		want bool // true = should reach userspace
	}{
		{
			name: "bare SYN is a new connection",
			pkt:  frame(ethTypeIPv4, protoTCP, 20, 0, tcpHeader(51234, 443, tcpFlagSYN)),
			want: true,
		},
		{
			name: "SYN-ACK is a reply, not an initiation",
			pkt:  frame(ethTypeIPv4, protoTCP, 20, 0, tcpHeader(443, 51234, tcpFlagSYN|tcpFlagACK)),
			want: false,
		},
		{
			name: "established traffic is ignored",
			pkt:  frame(ethTypeIPv4, protoTCP, 20, 0, tcpHeader(51234, 443, tcpFlagACK)),
			want: false,
		},
		{
			name: "SYN survives IP options",
			// IHL of 6 means 4 bytes of options; this exercises LoadMemShift,
			// which is where a fixed-offset filter would silently break.
			pkt:  frame(ethTypeIPv4, protoTCP, 24, 0, tcpHeader(51234, 443, tcpFlagSYN)),
			want: true,
		},
		{
			name: "DNS query outbound",
			pkt:  frame(ethTypeIPv4, protoUDP, 20, 0, udpHeader(33333, 53)),
			want: true,
		},
		{
			name: "DNS answer inbound",
			pkt:  frame(ethTypeIPv4, protoUDP, 20, 0, udpHeader(53, 33333)),
			want: true,
		},
		{
			name: "other UDP is ignored",
			pkt:  frame(ethTypeIPv4, protoUDP, 20, 0, udpHeader(33333, 123)),
			want: false,
		},
		{
			name: "non-first fragment has no usable header",
			pkt:  frame(ethTypeIPv4, protoTCP, 20, 0x0025, tcpHeader(51234, 443, tcpFlagSYN)),
			want: false,
		},
		{
			name: "ICMP is ignored",
			pkt:  frame(ethTypeIPv4, 1, 20, 0, make([]byte, 20)),
			want: false,
		},
		{
			name: "IPv6 is out of scope",
			pkt:  frame(0x86dd, protoTCP, 20, 0, tcpHeader(51234, 443, tcpFlagSYN)),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := vm.Run(tc.pkt)
			if err != nil {
				t.Fatalf("running filter: %v", err)
			}
			if got := n > 0; got != tc.want {
				t.Errorf("accepted=%v, want %v (returned %d bytes)", got, tc.want, n)
			}
		})
	}
}

func TestFilterAssembles(t *testing.T) {
	prog, err := filterProgram()
	if err != nil {
		t.Fatalf("assembling filter: %v", err)
	}
	if len(prog) == 0 {
		t.Fatal("filter is empty")
	}
}
