package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// defaultMaxEntries caps how much the baseline can ever grow to. A normal app
// server talks to a few dozen destinations; anything approaching this cap means
// something is wrong, so the cap doubles as a memory bound and a smoke alarm.
const defaultMaxEntries = 4096

// entry is one destination the box is known to talk to.
type entry struct {
	Key       string    `json:"key"`
	Host      string    `json:"host,omitempty"` // empty when the IP was never resolved
	Port      uint16    `json:"port"`
	Procs     []string  `json:"procs,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     uint64    `json:"count"`
}

// baseline is the set of destinations considered normal for this host,
// plus the hand-written allow rules that supplement it.
//
// Owned by the capture goroutine; not safe for concurrent use.
type baseline struct {
	entries map[string]*entry
	allow   []string // glob patterns from the allow file
	max     int
	dirty   bool
	full    bool // set once max was hit, so the warning is logged only once
}

// newBaseline creates an empty baseline holding at most max entries.
//
// in:  max entry count (<= 0 selects defaultMaxEntries)
// out: an empty baseline
func newBaseline(max int) *baseline {
	if max <= 0 {
		max = defaultMaxEntries
	}
	return &baseline{entries: make(map[string]*entry), max: max}
}

// destKey builds the identity under which a destination is remembered.
//
// in:  the resolved hostname ("" if unknown), the destination IP, and the port
// out: a stable key such as "api.stripe.com:443" or "203.0.113.0/24:443"
//
// Keying on the hostname is what stops a CDN's rotating addresses from looking
// like hundreds of new destinations. When the name is unknown the address is
// widened to a /24 (or /64 for IPv6) for the same reason: it bounds how many
// entries a single service can create. Alerts still report the exact IP.
func destKey(host string, ip netip.Addr, port uint16) string {
	if host != "" {
		return fmt.Sprintf("%s:%d", host, port)
	}
	if ip.Is4() {
		p, err := ip.Prefix(24)
		if err == nil {
			return fmt.Sprintf("%s:%d", p, port)
		}
	} else if p, err := ip.Prefix(64); err == nil {
		return fmt.Sprintf("%s:%d", p, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// known reports whether a destination is already part of normal behaviour.
//
// in:  the destination key and resolved hostname ("" if unknown)
// out: true if the baseline or an allow rule covers it
func (b *baseline) known(key, host string) bool {
	if _, ok := b.entries[key]; ok {
		return true
	}
	return b.allowed(key, host)
}

// allowed reports whether a hand-written rule covers a destination.
//
// in:  the destination key and resolved hostname
// out: true if any allow pattern matches
//
// A pattern is matched against both "host:port" and the bare host, so both
// "*.amazonaws.com:443" and "*.amazonaws.com" behave as expected.
func (b *baseline) allowed(key, host string) bool {
	for _, pat := range b.allow {
		if ok, _ := path.Match(pat, key); ok {
			return true
		}
		if host != "" {
			if ok, _ := path.Match(pat, host); ok {
				return true
			}
		}
	}
	return false
}

// record adds or refreshes a destination.
//
// in:  key, hostname, port, and the owning process ("" if unattributed)
// out: true if this created a new entry
//
// Returns false without inserting once the entry cap is reached, so a
// misbehaving box can fill the alert log but never the heap.
func (b *baseline) record(key, host string, port uint16, proc string, now time.Time) bool {
	if e, ok := b.entries[key]; ok {
		e.LastSeen = now
		e.Count++
		e.addProc(proc)
		b.dirty = true
		return false
	}
	if len(b.entries) >= b.max {
		if !b.full {
			logf("baseline full at %d entries; not learning any more", b.max)
			b.full = true
		}
		return false
	}
	e := &entry{Key: key, Host: host, Port: port, FirstSeen: now, LastSeen: now, Count: 1}
	e.addProc(proc)
	b.entries[key] = e
	b.dirty = true
	return true
}

// addProc records which process used a destination, keeping at most four.
//
// in:  a process description ("" is ignored)
// out: nothing
func (e *entry) addProc(proc string) {
	if proc == "" || len(e.Procs) >= 4 {
		return
	}
	for _, p := range e.Procs {
		if p == proc {
			return
		}
	}
	e.Procs = append(e.Procs, proc)
}

// load reads a baseline from disk.
//
// in:  path to the JSON state file
// out: nil if the file is absent (a fresh box is not an error)
func (b *baseline) load(file string) error {
	data, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var entries []*entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("parsing %s: %w", file, err)
	}
	for _, e := range entries {
		b.entries[e.Key] = e
	}
	return nil
}

// save writes the baseline out, sorted, if anything changed.
//
// in:  path to the JSON state file
// out: error on write failure
//
// Writes to a temporary file and renames, so a crash mid-write cannot leave a
// truncated baseline behind — the old one survives intact.
func (b *baseline) save(file string) error {
	if !b.dirty {
		return nil
	}
	entries := make([]*entry, 0, len(b.entries))
	for _, e := range b.entries {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, file); err != nil {
		return err
	}
	b.dirty = false
	return nil
}

// loadAllow reads the hand-written allow rules.
//
// in:  path to a text file of one glob per line; # starts a comment
// out: nil if the file is absent
//
// This file is meant to be edited by hand, which is why it is not JSON:
// "*.amazonaws.com:443" is easier to write and review than an escaped object.
func (b *baseline) loadAllow(file string) error {
	data, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	b.allow = b.allow[:0]
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			b.allow = append(b.allow, line)
		}
	}
	return nil
}

// ensureDir creates the directory holding a state file.
//
// in:  path to a file
// out: error if the parent directory cannot be created
func ensureDir(file string) error {
	return os.MkdirAll(filepath.Dir(file), 0o700)
}
