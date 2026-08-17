package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDestKeyGroupsUnresolvedAddressesByPrefix(t *testing.T) {
	tests := []struct {
		name string
		host string
		ip   string
		port uint16
		want string
	}{
		{"named destination", "api.stripe.com", "104.18.32.7", 443, "api.stripe.com:443"},
		{"unresolved v4 widens to /24", "", "203.0.113.42", 443, "203.0.113.0/24:443"},
		{"unresolved v6 widens to /64", "", "2001:db8::1", 443, "2001:db8::/64:443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := destKey(tc.host, netip.MustParseAddr(tc.ip), tc.port)
			if got != tc.want {
				t.Errorf("destKey = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDestKeyCollapsesRotatingCDNAddresses(t *testing.T) {
	// The whole reason keys are built on the hostname: a CDN handing out a
	// different address every minute must stay one entry, not hundreds.
	a := destKey("cdn.example.com", netip.MustParseAddr("104.18.1.1"), 443)
	b := destKey("cdn.example.com", netip.MustParseAddr("151.101.9.9"), 443)
	if a != b {
		t.Errorf("same host produced different keys: %q vs %q", a, b)
	}
}

func TestAllowRules(t *testing.T) {
	b := newBaseline(0)
	b.allow = []string{"*.amazonaws.com:443", "registry.npmjs.org", "10.0.0.0/24:*"}

	tests := []struct {
		key, host string
		want      bool
	}{
		{"s3.eu-west-1.amazonaws.com:443", "s3.eu-west-1.amazonaws.com", true},
		{"s3.eu-west-1.amazonaws.com:22", "s3.eu-west-1.amazonaws.com", false},
		{"registry.npmjs.org:443", "registry.npmjs.org", true},
		{"evil.tk:443", "evil.tk", false},
		{"10.0.0.0/24:5432", "", true},
	}
	for _, tc := range tests {
		if got := b.allowed(tc.key, tc.host); got != tc.want {
			t.Errorf("allowed(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

func TestRecordTracksAndStopsAtCap(t *testing.T) {
	b := newBaseline(3)
	now := time.Now()

	if !b.record("a:443", "a", 443, "node(1)", now) {
		t.Error("first sighting should report a new destination")
	}
	if b.record("a:443", "a", 443, "node(1)", now) {
		t.Error("second sighting should not report a new destination")
	}
	if got := b.entries["a:443"].Count; got != 2 {
		t.Errorf("Count = %d, want 2", got)
	}

	b.record("b:443", "b", 443, "", now)
	b.record("c:443", "c", 443, "", now)
	if b.record("d:443", "d", 443, "", now) {
		t.Error("recorded past the cap")
	}
	if len(b.entries) != 3 {
		t.Errorf("baseline grew to %d entries, cap is 3", len(b.entries))
	}
}

func TestAddProcDeduplicatesAndCaps(t *testing.T) {
	e := &entry{}
	for i := 0; i < 10; i++ {
		e.addProc("node(1)")
	}
	e.addProc("")
	if len(e.Procs) != 1 {
		t.Errorf("Procs = %v, want one unique entry", e.Procs)
	}
	for _, p := range []string{"a", "b", "c", "d", "e"} {
		e.addProc(p)
	}
	if len(e.Procs) > 4 {
		t.Errorf("Procs grew to %d, cap is 4", len(e.Procs))
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "baseline.json")
	now := time.Now().UTC().Truncate(time.Second)

	b := newBaseline(0)
	b.record("api.stripe.com:443", "api.stripe.com", 443, "node(1421) /app/server.js", now)
	if err := b.save(state); err != nil {
		t.Fatal(err)
	}

	loaded := newBaseline(0)
	if err := loaded.load(state); err != nil {
		t.Fatal(err)
	}
	e, ok := loaded.entries["api.stripe.com:443"]
	if !ok {
		t.Fatal("entry did not survive the round trip")
	}
	if e.Host != "api.stripe.com" || e.Port != 443 || len(e.Procs) != 1 {
		t.Errorf("entry came back wrong: %+v", e)
	}
}

func TestLoadMissingFilesIsNotAnError(t *testing.T) {
	// A box that has never run learn mode has no state file; that is the
	// normal first-boot case, not a failure.
	b := newBaseline(0)
	missing := filepath.Join(t.TempDir(), "nope.json")
	if err := b.load(missing); err != nil {
		t.Errorf("load of missing file: %v", err)
	}
	if err := b.loadAllow(missing); err != nil {
		t.Errorf("loadAllow of missing file: %v", err)
	}
}

func TestLoadAllowParsesCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "allow.txt")
	content := "# managed by hand\n\n*.amazonaws.com:443\nregistry.npmjs.org:443  # package installs\n\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	b := newBaseline(0)
	if err := b.loadAllow(file); err != nil {
		t.Fatal(err)
	}
	want := []string{"*.amazonaws.com:443", "registry.npmjs.org:443"}
	if len(b.allow) != len(want) {
		t.Fatalf("allow = %v, want %v", b.allow, want)
	}
	for i := range want {
		if b.allow[i] != want[i] {
			t.Errorf("allow[%d] = %q, want %q", i, b.allow[i], want[i])
		}
	}
}

func TestSaveIsAtomic(t *testing.T) {
	// The state file is rewritten periodically while the daemon runs; a crash
	// mid-write must not be able to truncate the previous baseline.
	dir := t.TempDir()
	state := filepath.Join(dir, "baseline.json")

	b := newBaseline(0)
	b.record("a:443", "a", 443, "", time.Now())
	if err := b.save(state); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state + ".tmp"); !os.IsNotExist(err) {
		t.Error("temporary file was left behind")
	}
}

func TestSaveSkipsUnchangedState(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "baseline.json")

	b := newBaseline(0)
	if err := b.save(state); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Error("wrote a file despite having nothing to save")
	}
}

func TestCooldownSuppressesRepeats(t *testing.T) {
	c := newCooldown(time.Hour, 4)
	now := time.Now()

	if !c.fire("a:443", now) {
		t.Error("first sighting should fire")
	}
	if c.fire("a:443", now.Add(time.Minute)) {
		t.Error("repeat inside the window should be suppressed")
	}
	if !c.fire("a:443", now.Add(2*time.Hour)) {
		t.Error("repeat after the window should fire again")
	}
}

func TestCooldownNeverExceedsItsCap(t *testing.T) {
	const max = 4
	c := newCooldown(time.Hour, max)
	now := time.Now()

	for i := 0; i < 200; i++ {
		c.fire(destKey("", netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 1}), 443), now)
		if len(c.seen) > max {
			t.Fatalf("cooldown grew to %d entries, cap is %d", len(c.seen), max)
		}
	}
}
