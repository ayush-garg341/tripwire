package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"
)

// review prints the learned baseline for a human to check, marking which
// entries an allow rule already covers and which are still unblessed.
//
// in:  the parsed configuration; reads the state and allow files, captures nothing
// out: error if the state file cannot be read
//
// This is the step between learn and watch. Learn mode gathers evidence without
// judging it, so something recorded during a compromise looks exactly like a
// real dependency. The "??" rows are the ones a human still has to rule on.
func review(cfg config) error {
	base := newBaseline(cfg.maxEntry)
	if err := base.load(cfg.statePath); err != nil {
		return err
	}
	if err := base.loadAllow(cfg.allowPath); err != nil {
		return err
	}
	return base.report(os.Stdout, cfg.statePath, cfg.allowPath)
}

// report writes the review table and its summary.
//
// in:  where to write, and the two file paths, quoted in the closing advice
// out: error only if writing fails
//
// Newest first: a destination that first appeared once, at 3am on the last day
// of learning, is exactly the row worth looking at, and it should not be buried
// at the bottom of a long list.
func (b *baseline) report(w io.Writer, statePath, allowPath string) error {
	if len(b.entries) == 0 {
		_, err := fmt.Fprintf(w, "No destinations recorded yet in %s.\nRun learn mode first.\n", statePath)
		return err
	}

	entries := make([]*entry, 0, len(b.entries))
	for _, e := range b.entries {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].FirstSeen.After(entries[j].FirstSeen) })

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tDESTINATION\tFIRST SEEN\tCOUNT\tPROCESS")

	unblessed := 0
	for _, e := range entries {
		mark := "ok"
		if !b.allowed(e.Key, e.Host) {
			mark = "??"
			unblessed++
		}
		proc := "unknown"
		if len(e.Procs) > 0 {
			proc = e.Procs[0]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n",
			mark, e.Key, e.FirstSeen.Local().Format("Jan 02 15:04"), e.Count, proc)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintf(w, "\n%d destinations: %d covered by an allow rule, %d not.\n",
		len(entries), len(entries)-unblessed, unblessed)
	if unblessed > 0 {
		fmt.Fprintf(w, "\nCheck the ?? rows. For each one, either:\n"+
			"  - recognise it  -> add a line to %s\n"+
			"  - do not        -> delete its block from %s, and find out what made it\n",
			allowPath, statePath)
	}
	return nil
}

// procOrUnknown renders a process description for logging.
//
// in:  a process description, possibly empty
// out: the description, or "unknown process" when attribution failed
func procOrUnknown(proc string) string {
	if proc == "" {
		return "unknown process"
	}
	return proc
}
