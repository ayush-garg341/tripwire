package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// These drive the real event loop with real frames, so they cover the wiring
// between capture, DNS naming, the baseline and alerting — the paths that unit
// tests of the individual pieces cannot reach.

// testLoop builds a loop whose alerts land in a channel instead of the log.
//
// in:  the mode to run in, "learn" or "watch"
// out: the loop and the notifier holding its alerts
func testLoop(mode string) (*loop, *notifier) {
	n := &notifier{ch: make(chan alert, 16)} // no delivery goroutine; tests read the channel
	l := &loop{
		cfg:    config{mode: mode},
		base:   newBaseline(0),
		dns:    newDNSCache(16),
		cool:   newCooldown(alertCooldown, maxSeenAlerts),
		notify: n,
	}
	return l, n
}

// synFrame builds an outbound bare SYN to a destination.
//
// in:  destination address, source port, destination port
// out: a complete Ethernet frame
func synFrame(dst string, sport, dport uint16) []byte {
	f := frame(ethTypeIPv4, protoTCP, 20, 0, tcpHeader(sport, dport, tcpFlagSYN))
	copy(f[ethHeaderLen+16:ethHeaderLen+20], netip.MustParseAddr(dst).AsSlice())
	return f
}

// dnsFrame wraps a DNS message in a UDP frame from port 53.
//
// in:  an encoded DNS message
// out: a complete Ethernet frame
func dnsFrame(msg []byte) []byte {
	udp := udpHeader(53, 33333)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(msg)))
	return frame(ethTypeIPv4, protoUDP, 20, 0, append(udp, msg...))
}

// drain collects everything queued on the notifier.
//
// in:  the notifier
// out: the alerts queued so far
func drain(n *notifier) []alert {
	var out []alert
	for {
		select {
		case a := <-n.ch:
			out = append(out, a)
		default:
			return out
		}
	}
}

func TestWatchAlertsOnNewDestinationWithItsName(t *testing.T) {
	l, n := testLoop("watch")
	now := time.Now()

	// The DNS answer arrives inbound first, then the app connects.
	l.handle(dnsFrame(dnsResponse(t, "evil.example.com.", "", 300, [4]byte{9, 9, 9, 9})), false, now)
	l.handle(synFrame("9.9.9.9", 51234, 443), true, now)

	alerts := drain(n)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if alerts[0].Host != "evil.example.com" {
		t.Errorf("Host = %q, want evil.example.com", alerts[0].Host)
	}
	if alerts[0].Key != "evil.example.com:443" {
		t.Errorf("Key = %q, want evil.example.com:443", alerts[0].Key)
	}
	if alerts[0].IP.String() != "9.9.9.9" {
		t.Errorf("IP = %s, want the exact address 9.9.9.9", alerts[0].IP)
	}
}

func TestWatchFlagsConnectionsThatSkippedDNS(t *testing.T) {
	// A destination reached without ever resolving it is characteristic of a
	// hardcoded address, so it gets its own reason string.
	l, n := testLoop("watch")
	l.handle(synFrame("203.0.113.7", 51234, 4444), true, time.Now())

	alerts := drain(n)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if alerts[0].Reason != "new destination, never resolved" {
		t.Errorf("Reason = %q", alerts[0].Reason)
	}
	if alerts[0].Host != "" {
		t.Errorf("Host = %q, want empty", alerts[0].Host)
	}
	if alerts[0].Key != "203.0.113.0/24:4444" {
		t.Errorf("Key = %q, want the /24 grouping", alerts[0].Key)
	}
}

func TestWatchStaysQuietForKnownAndAllowedDestinations(t *testing.T) {
	l, n := testLoop("watch")
	now := time.Now()
	l.base.record("api.stripe.com:443", "api.stripe.com", 443, "", now)
	l.base.allow = []string{"*.amazonaws.com:443"}

	l.handle(dnsFrame(dnsResponse(t, "api.stripe.com.", "", 300, [4]byte{1, 1, 1, 1})), false, now)
	l.handle(synFrame("1.1.1.1", 51234, 443), true, now)

	l.handle(dnsFrame(dnsResponse(t, "s3.eu-west-1.amazonaws.com.", "", 300, [4]byte{2, 2, 2, 2})), false, now)
	l.handle(synFrame("2.2.2.2", 51235, 443), true, now)

	if alerts := drain(n); len(alerts) != 0 {
		t.Errorf("got %d alerts, want none: %+v", len(alerts), alerts)
	}
}

func TestWatchIgnoresInboundConnections(t *testing.T) {
	// Someone connecting *to* the box is a different problem, and one that
	// fail2ban and the security group already handle.
	l, n := testLoop("watch")
	l.handle(synFrame("203.0.113.9", 40000, 22), false, time.Now())

	if alerts := drain(n); len(alerts) != 0 {
		t.Errorf("alerted on inbound traffic: %+v", alerts)
	}
}

func TestWatchAlertsOnceWhileTheCooldownHolds(t *testing.T) {
	l, n := testLoop("watch")
	now := time.Now()
	for i := 0; i < 50; i++ {
		l.handle(synFrame("203.0.113.7", uint16(50000+i), 4444), true, now.Add(time.Duration(i)*time.Second))
	}
	if alerts := drain(n); len(alerts) != 1 {
		t.Errorf("got %d alerts, want 1 - a reconnect loop must not flood", len(alerts))
	}
}

func TestWatchNeverWritesToTheBaseline(t *testing.T) {
	// A watcher that kept learning would quietly absorb an attacker's
	// destination as normal the first time it appeared.
	l, _ := testLoop("watch")
	l.handle(synFrame("203.0.113.7", 51234, 4444), true, time.Now())

	if len(l.base.entries) != 0 {
		t.Errorf("watch mode recorded %d entries, want 0", len(l.base.entries))
	}
}

func TestLearnRecordsInsteadOfAlerting(t *testing.T) {
	l, n := testLoop("learn")
	now := time.Now()

	l.handle(dnsFrame(dnsResponse(t, "api.stripe.com.", "", 300, [4]byte{1, 1, 1, 1})), false, now)
	l.handle(synFrame("1.1.1.1", 51234, 443), true, now)
	l.handle(synFrame("1.1.1.1", 51235, 443), true, now)

	if alerts := drain(n); len(alerts) != 0 {
		t.Errorf("learn mode alerted: %+v", alerts)
	}
	e, ok := l.base.entries["api.stripe.com:443"]
	if !ok {
		t.Fatalf("did not learn the destination; have %v", l.base.entries)
	}
	if e.Count != 2 {
		t.Errorf("Count = %d, want 2", e.Count)
	}
}

func TestExpiredDNSMakesADestinationAnonymousAgain(t *testing.T) {
	// Once the name expires the same address is no longer attributable to it,
	// and must fall back to the address-based key rather than a stale name.
	l, n := testLoop("watch")
	now := time.Now()
	l.handle(dnsFrame(dnsResponse(t, "api.example.com.", "", 60, [4]byte{9, 9, 9, 9})), false, now)
	l.handle(synFrame("9.9.9.9", 51234, 443), true, now.Add(2*time.Hour))

	alerts := drain(n)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if alerts[0].Key != "9.9.9.0/24:443" {
		t.Errorf("Key = %q, want the address-based key after expiry", alerts[0].Key)
	}
}

func TestHandleSurvivesGarbageFrames(t *testing.T) {
	// Everything here arrives from the network; none of it may panic.
	l, _ := testLoop("watch")
	now := time.Now()
	for _, f := range [][]byte{
		nil,
		{0x00},
		make([]byte, 14),
		frame(ethTypeIPv4, protoUDP, 20, 0, append(udpHeader(53, 1), 0xff, 0xfe, 0x00)),
		frame(0x86dd, protoTCP, 20, 0, tcpHeader(1, 2, tcpFlagSYN)),
	} {
		l.handle(f, true, now)
	}
}
