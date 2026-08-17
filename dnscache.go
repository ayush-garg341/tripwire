package main

import (
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TTL clamps. Some CDNs hand out 5-second TTLs, which would evict a name
// before the connection that follows it; some hand out 24 hours, which would
// pin memory for a day. Both are clamped into a sane band.
const (
	minTTL = 60 * time.Second
	maxTTL = time.Hour
)

type dnsEntry struct {
	name    string
	expires time.Time
}

// dnsCache maps an IP back to the hostname that was looked up to reach it.
//
// Without this, alerts read "connection to 104.18.32.7" — meaningless for
// anything behind a CDN. With it they read "api.stripe.com", which is stable
// even as the CDN rotates addresses underneath.
//
// The cache is hard-capped. It is owned by the capture goroutine and is not
// safe for concurrent use; see docs/ARCHITECTURE.md on the threading model.
type dnsCache struct {
	entries map[netip.Addr]dnsEntry
	max     int
}

// newDNSCache creates a cache holding at most max entries.
//
// in:  max entry count (<= 0 selects a 4096-entry default)
// out: an empty cache
func newDNSCache(max int) *dnsCache {
	if max <= 0 {
		max = 4096
	}
	return &dnsCache{entries: make(map[netip.Addr]dnsEntry), max: max}
}

// observe records the answers in a DNS response.
//
// in:  a UDP payload that may be a DNS message, and the current time
// out: nothing; non-DNS or malformed input is ignored
//
// Every A/AAAA address in the answer is mapped to the name from the *question*
// section, not the name on the record itself. For a CNAME chain like
// api.foo.com -> d3x.cloudfront.net -> 1.2.3.4 that reports the name the app
// actually asked for rather than the CDN alias it landed on.
func (c *dnsCache) observe(payload []byte, now time.Time) {
	var p dnsmessage.Parser
	header, err := p.Start(payload)
	if err != nil || !header.Response {
		return
	}

	q, err := p.Question()
	if err != nil {
		return
	}
	name := trimDot(q.Name.String())
	if name == "" {
		return
	}
	if err := p.SkipAllQuestions(); err != nil {
		return
	}

	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return // includes ErrSectionDone
		}
		ttl := clampTTL(time.Duration(h.TTL) * time.Second)

		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return
			}
			c.put(netip.AddrFrom4(r.A), name, now.Add(ttl))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return
			}
			c.put(netip.AddrFrom16(r.AAAA), name, now.Add(ttl))
		default:
			if err := p.SkipAnswer(); err != nil {
				return
			}
		}
	}
}

// lookup returns the hostname last associated with an IP.
//
// in:  an address and the current time
// out: the hostname and true, or "" and false when unknown or expired
//
// A miss is itself a signal: a connection to an address that was never
// resolved means the destination was hardcoded rather than looked up.
func (c *dnsCache) lookup(ip netip.Addr, now time.Time) (string, bool) {
	e, ok := c.entries[ip]
	if !ok || now.After(e.expires) {
		return "", false
	}
	return e.name, true
}

// put inserts one IP -> name mapping, evicting first if the cache is full.
//
// in:  address, hostname, expiry time
// out: nothing
func (c *dnsCache) put(ip netip.Addr, name string, expires time.Time) {
	if _, exists := c.entries[ip]; !exists && len(c.entries) >= c.max {
		c.evict(expires)
	}
	c.entries[ip] = dnsEntry{name: name, expires: expires}
}

// evict makes room in a full cache.
//
// in:  the current time, as carried on the entry being inserted
// out: nothing; at least one slot is freed
//
// Expired entries go first. If none are expired the entry closest to expiry is
// dropped, which approximates an LRU without the bookkeeping of one. The scan
// is O(max) but only runs when the cache is full, and max is small.
func (c *dnsCache) evict(now time.Time) {
	for ip, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, ip)
		}
	}
	if len(c.entries) < c.max {
		return
	}
	var oldestIP netip.Addr
	var oldest time.Time
	for ip, e := range c.entries {
		if oldest.IsZero() || e.expires.Before(oldest) {
			oldestIP, oldest = ip, e.expires
		}
	}
	delete(c.entries, oldestIP)
}

// clampTTL keeps a record's TTL inside [minTTL, maxTTL].
//
// in:  the TTL from a DNS record
// out: the TTL to actually cache for
func clampTTL(d time.Duration) time.Duration {
	switch {
	case d < minTTL:
		return minTTL
	case d > maxTTL:
		return maxTTL
	}
	return d
}

// trimDot removes the trailing dot from a fully qualified DNS name.
//
// in:  a wire-format name such as "api.stripe.com."
// out: the same name without the root dot
func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
