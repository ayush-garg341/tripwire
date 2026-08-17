package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"time"
)

const (
	alertQueue    = 256             // buffered alerts; beyond this, alerts are dropped rather than blocking capture
	alertCooldown = time.Hour       // per-destination silence window
	webhookTime   = 5 * time.Second // webhook timeout
	maxSeenAlerts = 1024            // cap on the dedup table
)

// alert is one report of unexpected egress.
type alert struct {
	Time    time.Time  `json:"time"`
	Reason  string     `json:"reason"`
	Host    string     `json:"host,omitempty"`
	IP      netip.Addr `json:"ip"`
	Port    uint16     `json:"port"`
	Process string     `json:"process,omitempty"`
	Key     string     `json:"key"`
}

// text renders an alert as the single line written to the log.
//
// in:  nothing
// out: a human-readable one-liner
func (a alert) text() string {
	dest := a.Host
	if dest == "" {
		dest = "(no DNS lookup)"
	}
	proc := a.Process
	if proc == "" {
		proc = "unknown process"
	}
	return fmt.Sprintf("EGRESS %s: %s -> %s [%s:%d] (%s)", a.Reason, proc, dest, a.IP, a.Port, a.Key)
}

// notifier delivers alerts off the capture path.
//
// Capture must never block on a slow webhook, so alerts are handed to a
// buffered channel and delivered by a separate goroutine. If that channel
// fills, alerts are dropped and counted — losing an alert is strictly better
// than stalling packet capture on the box being protected.
type notifier struct {
	ch      chan alert
	webhook string
	client  *http.Client
	done    chan struct{}

	dropped uint64
}

// newNotifier starts the delivery goroutine.
//
// in:  webhook URL ("" disables HTTP delivery; the log always gets the alert)
// out: a running notifier; call close when finished
func newNotifier(webhook string) *notifier {
	n := &notifier{
		ch:      make(chan alert, alertQueue),
		webhook: webhook,
		client:  &http.Client{Timeout: webhookTime},
		done:    make(chan struct{}),
	}
	go n.run()
	return n
}

// send queues an alert without ever blocking.
//
// in:  the alert to deliver
// out: nothing; the alert is dropped and counted if the queue is full
func (n *notifier) send(a alert) {
	select {
	case n.ch <- a:
	default:
		n.dropped++
	}
}

// close stops the notifier and waits for queued alerts to drain.
//
// in:  nothing
// out: nothing
func (n *notifier) close() {
	close(n.ch)
	<-n.done
}

// run delivers queued alerts until the channel closes.
//
// in:  nothing
// out: nothing; closes done on exit
func (n *notifier) run() {
	defer close(n.done)
	for a := range n.ch {
		log.Print(a.text())
		if n.webhook != "" {
			if err := n.post(a); err != nil {
				log.Printf("webhook failed: %v", err)
			}
		}
	}
	if n.dropped > 0 {
		log.Printf("dropped %d alerts (queue full)", n.dropped)
	}
}

// cooldown remembers which destinations fired recently, so a process
// reconnecting in a loop cannot bury the first — and most useful — alert under
// thousands of copies.
//
// It also gates the /proc walk behind it: a suppressed destination costs a
// single map lookup rather than a scan of every process on the box.
//
// Owned by the capture goroutine; not safe for concurrent use.
type cooldown struct {
	seen   map[string]time.Time
	window time.Duration
	max    int
}

// newCooldown creates a bounded cooldown table.
//
// in:  the silence window per key, and the maximum number of keys tracked
// out: an empty cooldown
func newCooldown(window time.Duration, max int) *cooldown {
	return &cooldown{seen: make(map[string]time.Time), window: window, max: max}
}

// fire reports whether a key is allowed to alert now, and records that it did.
//
// in:  the destination key and the current time
// out: true to alert, false if the key fired within the window
func (c *cooldown) fire(key string, now time.Time) bool {
	if last, ok := c.seen[key]; ok && now.Sub(last) < c.window {
		return false
	}
	if len(c.seen) >= c.max {
		for k, t := range c.seen {
			if now.Sub(t) >= c.window {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= c.max {
			c.seen = make(map[string]time.Time) // pathological; start over rather than grow
		}
	}
	c.seen[key] = now
	return true
}

// post sends an alert to the configured webhook.
//
// in:  the alert
// out: error if the request fails or is rejected
//
// The body carries "text" and "content" alongside the structured fields so the
// same URL works for Slack and Discord without any per-service code.
func (n *notifier) post(a alert) error {
	body, err := json.Marshal(struct {
		Text    string `json:"text"`
		Content string `json:"content"`
		alert
	}{Text: a.text(), Content: a.text(), alert: a})
	if err != nil {
		return err
	}
	resp, err := n.client.Post(n.webhook, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

// logf writes an operational message to the log.
//
// in:  printf-style format and arguments
// out: nothing
func logf(format string, args ...any) {
	log.Printf(format, args...)
}
