package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestReportMarksUnblessedDestinations(t *testing.T) {
	b := newBaseline(0)
	b.allow = []string{"registry.npmjs.org:443"}
	old := time.Now().Add(-72 * time.Hour)

	b.record("registry.npmjs.org:443", "registry.npmjs.org", 443, "npm(2011)", old)
	b.record("paste.ee:443", "paste.ee", 443, "node(1421) /app/server.js", time.Now())

	var out bytes.Buffer
	if err := b.report(&out, "state.json", "allow.txt"); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	if !strings.Contains(got, "ok") || !strings.Contains(got, "??") {
		t.Errorf("report did not mark both blessed and unblessed rows:\n%s", got)
	}
	if !strings.Contains(got, "1 covered by an allow rule, 1 not") {
		t.Errorf("summary line wrong:\n%s", got)
	}
	// The unreviewed row must carry the process that opened it; that is what
	// makes it possible to act on.
	if !strings.Contains(got, "node(1421) /app/server.js") {
		t.Errorf("report dropped process attribution:\n%s", got)
	}
}

func TestReportPutsNewestFirst(t *testing.T) {
	// The destination that appeared last is the one most worth looking at, so
	// it must not be buried at the bottom of a long list.
	b := newBaseline(0)
	now := time.Now()
	b.record("old.example.com:443", "old.example.com", 443, "", now.Add(-72*time.Hour))
	b.record("new.example.com:443", "new.example.com", 443, "", now)

	var out bytes.Buffer
	if err := b.report(&out, "state.json", "allow.txt"); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	if strings.Index(got, "new.example.com") > strings.Index(got, "old.example.com") {
		t.Errorf("newest entry was not listed first:\n%s", got)
	}
}

func TestReportHandlesAnEmptyBaseline(t *testing.T) {
	b := newBaseline(0)
	var out bytes.Buffer
	if err := b.report(&out, "state.json", "allow.txt"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Run learn mode first") {
		t.Errorf("unhelpful output for a fresh install:\n%s", out.String())
	}
}

func TestReportSaysNothingToReviewWhenAllBlessed(t *testing.T) {
	b := newBaseline(0)
	b.allow = []string{"*.example.com:443"}
	b.record("api.example.com:443", "api.example.com", 443, "", time.Now())

	var out bytes.Buffer
	if err := b.report(&out, "state.json", "allow.txt"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Check the ?? rows") {
		t.Errorf("asked for review when everything was covered:\n%s", out.String())
	}
}
