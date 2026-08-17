package main

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsResponse builds a DNS answer for a question name.
//
// in:  the queried name, an optional CNAME hop, the TTL, and the A records
// out: the encoded DNS message
func dnsResponse(t *testing.T, question string, cname string, ttl uint32, addrs ...[4]byte) []byte {
	t.Helper()
	qname := dnsmessage.MustNewName(question)

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: qname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}

	answerName := qname
	if cname != "" {
		target := dnsmessage.MustNewName(cname)
		hdr := dnsmessage.ResourceHeader{Name: qname, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: ttl}
		if err := b.CNAMEResource(hdr, dnsmessage.CNAMEResource{CNAME: target}); err != nil {
			t.Fatal(err)
		}
		answerName = target
	}
	for _, a := range addrs {
		hdr := dnsmessage.ResourceHeader{Name: answerName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl}
		if err := b.AResource(hdr, dnsmessage.AResource{A: a}); err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestObserveMapsAddressesToQueriedName(t *testing.T) {
	c := newDNSCache(16)
	now := time.Now()
	c.observe(dnsResponse(t, "api.stripe.com.", "", 300, [4]byte{1, 2, 3, 4}, [4]byte{1, 2, 3, 5}), now)

	for _, ip := range []string{"1.2.3.4", "1.2.3.5"} {
		got, ok := c.lookup(netip.MustParseAddr(ip), now)
		if !ok || got != "api.stripe.com" {
			t.Errorf("lookup(%s) = %q, %v; want api.stripe.com, true", ip, got, ok)
		}
	}
}

func TestObserveFollowsCNAMEToTheNameTheAppAskedFor(t *testing.T) {
	// The A record carries the CDN alias, but the useful name — the one that
	// stays stable and that a human recognises — is the question name.
	c := newDNSCache(16)
	now := time.Now()
	c.observe(dnsResponse(t, "api.myapp.com.", "d3x9.cloudfront.net.", 60, [4]byte{9, 9, 9, 9}), now)

	got, ok := c.lookup(netip.MustParseAddr("9.9.9.9"), now)
	if !ok || got != "api.myapp.com" {
		t.Errorf("lookup = %q, %v; want api.myapp.com, true", got, ok)
	}
}

func TestObserveIgnoresQueriesAndGarbage(t *testing.T) {
	c := newDNSCache(16)
	now := time.Now()

	// A query (not a response) must not populate the cache.
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	query, _ := b.Finish()

	c.observe(query, now)
	c.observe([]byte{0x00, 0x01, 0x02}, now)
	c.observe(nil, now)

	if len(c.entries) != 0 {
		t.Errorf("cache has %d entries, want 0", len(c.entries))
	}
}

func TestLookupExpiresEntries(t *testing.T) {
	c := newDNSCache(16)
	now := time.Now()
	c.observe(dnsResponse(t, "short.example.com.", "", 5, [4]byte{7, 7, 7, 7}), now)

	ip := netip.MustParseAddr("7.7.7.7")
	// A 5-second TTL is clamped up to minTTL, so it is still live just before it.
	if _, ok := c.lookup(ip, now.Add(minTTL-time.Second)); !ok {
		t.Error("entry expired before minTTL")
	}
	if _, ok := c.lookup(ip, now.Add(minTTL+time.Second)); ok {
		t.Error("entry outlived its TTL")
	}
}

func TestCacheNeverExceedsItsCap(t *testing.T) {
	// The memory bound that matters: a box doing heavy DNS must not be able to
	// grow this map without limit.
	const max = 8
	c := newDNSCache(max)
	now := time.Now()

	for i := 0; i < 500; i++ {
		addr := [4]byte{10, byte(i / 256), byte(i % 256), 1}
		c.observe(dnsResponse(t, "host.example.com.", "", 300, addr), now)
		if len(c.entries) > max {
			t.Fatalf("cache grew to %d entries, cap is %d", len(c.entries), max)
		}
	}
}
