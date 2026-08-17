package main

import (
	"testing"
)

func TestParseFrameDecodesTCP(t *testing.T) {
	pkt, ok := parseFrame(frame(ethTypeIPv4, protoTCP, 20, 0, tcpHeader(51234, 443, tcpFlagSYN)))
	if !ok {
		t.Fatal("failed to parse a valid TCP frame")
	}
	if pkt.src.String() != "10.0.0.5" || pkt.dst.String() != "93.184.16.3" {
		t.Errorf("addresses = %s -> %s", pkt.src, pkt.dst)
	}
	if pkt.srcPort != 51234 || pkt.dstPort != 443 {
		t.Errorf("ports = %d -> %d", pkt.srcPort, pkt.dstPort)
	}
	if !pkt.isConnectionStart() {
		t.Error("bare SYN not recognised as a connection start")
	}
}

func TestParseFrameHandlesIPOptions(t *testing.T) {
	// With options present the transport header no longer sits at a fixed
	// offset; reading ports from byte 34 would silently produce garbage.
	pkt, ok := parseFrame(frame(ethTypeIPv4, protoTCP, 24, 0, tcpHeader(51234, 443, tcpFlagSYN)))
	if !ok {
		t.Fatal("failed to parse frame with IP options")
	}
	if pkt.dstPort != 443 {
		t.Errorf("dstPort = %d, want 443", pkt.dstPort)
	}
}

func TestParseFrameExtractsUDPPayload(t *testing.T) {
	payload := []byte("dns-bytes-here")
	udp := udpHeader(53, 33333)
	udp[4], udp[5] = 0, byte(8+len(payload)) // UDP length covers header + payload
	pkt, ok := parseFrame(frame(ethTypeIPv4, protoUDP, 20, 0, append(udp, payload...)))
	if !ok {
		t.Fatal("failed to parse a valid UDP frame")
	}
	if string(pkt.payload) != string(payload) {
		t.Errorf("payload = %q, want %q", pkt.payload, payload)
	}
}

func TestParseFrameRejectsMalformedInput(t *testing.T) {
	// Every one of these arrives from the network, so none may panic or be
	// trusted enough to read past the end of the buffer.
	tests := []struct {
		name string
		pkt  []byte
	}{
		{"empty", nil},
		{"runt", make([]byte, 10)},
		{"truncated IP header", make([]byte, 20)},
		{"IPv6", frame(0x86dd, protoTCP, 20, 0, tcpHeader(1, 2, tcpFlagSYN))},
		{"ICMP", frame(ethTypeIPv4, 1, 20, 0, make([]byte, 20))},
		{"truncated TCP header", frame(ethTypeIPv4, protoTCP, 20, 0, make([]byte, 10))},
		{"impossible header length", func() []byte {
			f := frame(ethTypeIPv4, protoTCP, 20, 0, tcpHeader(1, 2, tcpFlagSYN))
			f[ethHeaderLen] = 0x40 // IHL of 0
			return f
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := parseFrame(tc.pkt); ok {
				t.Error("accepted a frame it should have rejected")
			}
		})
	}
}

func TestParseFrameSurvivesArbitraryTruncation(t *testing.T) {
	// Fuzz-lite: every prefix of a valid frame must be rejected or parsed,
	// never panic.
	full := frame(ethTypeIPv4, protoUDP, 20, 0, append(udpHeader(53, 1), []byte("payload")...))
	for i := 0; i <= len(full); i++ {
		parseFrame(full[:i])
	}
}

func TestParseFrameAllocatesNothing(t *testing.T) {
	// Decoding runs on every captured packet. If it ever starts allocating,
	// steady-state memory becomes a function of traffic rate instead of a
	// fixed cost, which is the thing this daemon promises not to do.
	f := frame(ethTypeIPv4, protoTCP, 20, 0, tcpHeader(51234, 443, tcpFlagSYN))
	got := testing.AllocsPerRun(1000, func() {
		if _, ok := parseFrame(f); !ok {
			t.Fatal("parse failed")
		}
	})
	if got != 0 {
		t.Errorf("parseFrame allocated %v times per call, want 0", got)
	}
}

func TestIsConnectionStart(t *testing.T) {
	tests := []struct {
		name  string
		proto uint8
		flags uint8
		want  bool
	}{
		{"bare SYN", protoTCP, tcpFlagSYN, true},
		{"SYN-ACK", protoTCP, tcpFlagSYN | tcpFlagACK, false},
		{"ACK", protoTCP, tcpFlagACK, false},
		{"UDP is never a connection", protoUDP, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := packet{proto: tc.proto, tcpFlags: tc.flags}
			if got := p.isConnectionStart(); got != tc.want {
				t.Errorf("isConnectionStart = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHexPort(t *testing.T) {
	tests := []struct {
		in   string
		want uint16
	}{
		{"0100007F:1F90", 8080},
		{"00000000:0050", 80},
		{"garbage", 0},
		{"", 0},
	}
	for _, tc := range tests {
		if got := hexPort(tc.in); got != tc.want {
			t.Errorf("hexPort(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestIsNumeric(t *testing.T) {
	for _, s := range []string{"1", "1421"} {
		if !isNumeric(s) {
			t.Errorf("isNumeric(%q) = false", s)
		}
	}
	for _, s := range []string{"", "self", "net", "1a"} {
		if isNumeric(s) {
			t.Errorf("isNumeric(%q) = true", s)
		}
	}
}
