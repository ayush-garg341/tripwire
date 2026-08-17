package main

import "golang.org/x/net/bpf"

// The kernel-side filter. Everything the tripwire cares about is decided here,
// inside the kernel, so userspace never wakes up for traffic it would discard.
//
// The equivalent tcpdump expression is:
//
//	(tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn) or (udp port 53)
//
// That is: TCP connection *initiations* (SYN set, ACK clear) plus DNS. On a
// small app server this is a few hundred 74-byte frames an hour instead of
// every packet on the wire.
//
// Direction is deliberately NOT filtered here. DNS answers arrive inbound and
// we need them to name destinations, so both directions are accepted and the
// capture loop drops inbound SYNs using the packet type AF_PACKET already
// hands us for free (see capture_linux.go). That keeps this program short
// enough to read and testable with bpf.NewVM.
//
// Layout assumption: Ethernet + IPv4. See docs/ARCHITECTURE.md for why IPv6
// and VLAN frames are out of scope for v1.
const (
	snapLen = 65535 // bytes to copy per accepted packet; SYNs and DNS are far smaller
	dropAll = 0     // a BPF return of 0 means "discard"
)

// filterProgram assembles the filter for attaching to the capture socket.
//
// in:  nothing
// out: assembled BPF instructions, or an error if the program is malformed
func filterProgram() ([]bpf.RawInstruction, error) {
	return bpf.Assemble(filterInstructions())
}

// filterInstructions returns the filter in source form.
//
// in:  nothing
// out: the BPF instruction list
//
// Jump targets are relative skip counts, so every jump below is annotated with
// the label it lands on. filter_test.go runs real packets through this program
// in a BPF VM to prove those counts are right; re-run it after any edit here.
func filterInstructions() []bpf.Instruction {
	return []bpf.Instruction{
		// 0: EtherType, and bail out on anything that is not IPv4.
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// 1:
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x0800, SkipTrue: 17}, // -> DROP

		// 2: Fragment offset. A non-first fragment has no transport header to
		//    read, so there is nothing here we can act on.
		bpf.LoadAbsolute{Off: 20, Size: 2},
		// 3:
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 15}, // -> DROP

		// 4: IP protocol number.
		bpf.LoadAbsolute{Off: 23, Size: 1},
		// 5:
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 6}, // -> UDP
		// 6:
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 6, SkipTrue: 12}, // -> DROP

		// --- TCP: keep bare SYNs only ---
		// 7: X = IP header length, so the transport header starts at 14+X.
		bpf.LoadMemShift{Off: 14},
		// 8: TCP flags byte (transport offset 13).
		bpf.LoadIndirect{Off: 14 + 13, Size: 1},
		// 9:
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x12}, // SYN|ACK
		// 10: SYN set and ACK clear == a new outbound connection.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x02, SkipTrue: 7}, // -> ACCEPT
		// 11:
		bpf.Jump{Skip: 7}, // -> DROP

		// --- UDP: keep port 53 in either direction ---
		// 12:
		bpf.LoadMemShift{Off: 14},
		// 13: source port
		bpf.LoadIndirect{Off: 14 + 0, Size: 2},
		// 14:
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 3}, // -> ACCEPT
		// 15: destination port
		bpf.LoadIndirect{Off: 14 + 2, Size: 2},
		// 16:
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 1}, // -> ACCEPT
		// 17:
		bpf.Jump{Skip: 1}, // -> DROP

		// 18: ACCEPT
		bpf.RetConstant{Val: snapLen},
		// 19: DROP
		bpf.RetConstant{Val: dropAll},
	}
}
