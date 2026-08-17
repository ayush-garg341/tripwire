// Command tripwire watches what an application server connects *out* to and
// reports destinations it has never used before.
//
// See README.md for usage and docs/ARCHITECTURE.md for how it works.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const version = "0.1.0"

// config holds everything the daemon was asked to do.
type config struct {
	iface     string
	mode      string
	statePath string
	allowPath string
	webhook   string
	flush     time.Duration
	maxEntry  int
	maxDNS    int
	verbose   bool
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.iface, "i", "", "interface to capture on (required), e.g. eth0")
	flag.StringVar(&cfg.mode, "mode", "watch", "learn (record egress), watch (alert on new egress), or review (list what was learned)")
	flag.StringVar(&cfg.statePath, "state", "/var/lib/tripwire/baseline.json", "baseline state file")
	flag.StringVar(&cfg.allowPath, "allow", "/etc/tripwire/allow.txt", "hand-written allow rules, one glob per line")
	flag.StringVar(&cfg.webhook, "webhook", "", "optional webhook URL for alerts (Slack/Discord compatible)")
	flag.DurationVar(&cfg.flush, "flush", 30*time.Second, "how often to save state and reload allow rules")
	flag.IntVar(&cfg.maxEntry, "max-entries", defaultMaxEntries, "hard cap on baseline entries")
	flag.IntVar(&cfg.maxDNS, "dns-cache", 4096, "hard cap on cached DNS answers")
	flag.BoolVar(&cfg.verbose, "v", false, "log every learned destination")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("tripwire", version)
		return
	}
	switch cfg.mode {
	case "review":
		// Reads the files and prints; no capture, so no interface needed.
		if err := review(cfg); err != nil {
			log.Fatal(err)
		}
		return
	case "learn", "watch":
	default:
		log.Fatalf("mode must be learn, watch or review, got %q", cfg.mode)
	}
	if cfg.iface == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}

// run opens the capture socket and drives the event loop until interrupted.
//
// in:  the parsed configuration
// out: error on setup failure or an unrecoverable read error
func run(cfg config) error {
	base := newBaseline(cfg.maxEntry)
	if err := base.load(cfg.statePath); err != nil {
		return err
	}
	if err := base.loadAllow(cfg.allowPath); err != nil {
		return err
	}
	if cfg.mode == "learn" {
		if err := ensureDir(cfg.statePath); err != nil {
			return err
		}
	}

	sock, err := openCapture(cfg.iface)
	if err != nil {
		return err
	}
	defer sock.close()

	notify := newNotifier(cfg.webhook)
	defer notify.close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	logf("tripwire %s: %s mode on %s (%d known destinations, %d allow rules)",
		version, cfg.mode, cfg.iface, len(base.entries), len(base.allow))

	l := &loop{
		cfg:    cfg,
		base:   base,
		dns:    newDNSCache(cfg.maxDNS),
		cool:   newCooldown(alertCooldown, maxSeenAlerts),
		notify: notify,
		buf:    make([]byte, snapLen),
	}
	return l.serve(sock, stop)
}

// loop owns every piece of mutable state in the daemon.
//
// There is exactly one goroutine here. The DNS cache, the baseline and the
// cooldown table are never touched from anywhere else, so none of them need a
// mutex; the only hand-off across goroutines is the alert channel, which
// carries copies. See docs/ARCHITECTURE.md.
type loop struct {
	cfg    config
	base   *baseline
	dns    *dnsCache
	cool   *cooldown
	notify *notifier
	buf    []byte
}

// serve reads packets until a signal arrives.
//
// in:  an open capture and the signal channel
// out: error on an unrecoverable read failure
//
// Reads time out once a second, which is what gives the loop a chance to run
// housekeeping and notice signals without a second goroutine.
func (l *loop) serve(c *capture, stop <-chan os.Signal) error {
	lastFlush := time.Now()
	for {
		select {
		case <-stop:
			logf("shutting down")
			return l.housekeep(true)
		default:
		}

		n, outgoing, err := c.read(l.buf)
		if err != nil {
			return fmt.Errorf("reading from %s: %w", l.cfg.iface, err)
		}
		now := time.Now()
		if n > 0 {
			l.handle(l.buf[:n], outgoing, now)
		}
		if now.Sub(lastFlush) >= l.cfg.flush {
			if err := l.housekeep(false); err != nil {
				logf("housekeeping: %v", err)
			}
			lastFlush = now
		}
	}
}

// handle processes one captured frame.
//
// in:  the frame, whether this host sent it, and the current time
// out: nothing
func (l *loop) handle(frame []byte, outgoing bool, now time.Time) {
	pkt, ok := parseFrame(frame)
	if !ok {
		return
	}
	if pkt.proto == protoUDP {
		l.dns.observe(pkt.payload, now) // answers name the destinations below
		return
	}
	if outgoing && pkt.isConnectionStart() {
		l.connection(pkt, now)
	}
}

// connection handles one outbound connection attempt.
//
// in:  a bare-SYN packet and the current time
// out: nothing; learns the destination or alerts on it depending on mode
func (l *loop) connection(pkt packet, now time.Time) {
	host, _ := l.dns.lookup(pkt.dst, now)
	key := destKey(host, pkt.dst, pkt.dstPort)

	if l.base.known(key, host) {
		if l.cfg.mode == "learn" {
			// Already covered, by a previous sighting or an allow rule. Just
			// refresh the counters; the /proc walk below is not worth it.
			if l.base.record(key, host, pkt.dstPort, "", now) && l.cfg.verbose {
				logf("allowed by rule: %s", key)
			}
		}
		return
	}
	if !l.cool.fire(key, now) {
		return // already reported recently; skip the /proc walk entirely
	}

	proc := lookupProcess(pkt.srcPort, pkt.dstPort)

	if l.cfg.mode == "learn" {
		l.base.record(key, host, pkt.dstPort, proc, now)
		// Reaching here means no allow rule covered this destination, so say so
		// out loud rather than absorbing it silently. Recording it is still the
		// right call — learn mode's job is to gather evidence, not to judge —
		// but the operator should see what is accumulating. "tripwire -mode
		// review" lists these again at the end.
		logf("NEW (no allow rule): %s via %s", key, procOrUnknown(proc))
		return
	}

	reason := "new destination"
	if host == "" {
		reason = "new destination, never resolved"
	}
	l.notify.send(alert{
		Time: now, Reason: reason, Host: host, IP: pkt.dst,
		Port: pkt.dstPort, Process: proc, Key: key,
	})
}

// housekeep saves state and picks up edits to the allow file.
//
// in:  whether this is the final call before exit
// out: error if state could not be written
//
// Reloading the allow rules here means a new rule takes effect within one flush
// interval, with no restart and no dropped packets.
func (l *loop) housekeep(final bool) error {
	if err := l.base.loadAllow(l.cfg.allowPath); err != nil {
		logf("reloading allow rules: %v", err)
	}
	if l.cfg.mode != "learn" {
		return nil
	}
	if err := l.base.save(l.cfg.statePath); err != nil {
		return err
	}
	if final {
		logf("saved %d destinations to %s", len(l.base.entries), l.cfg.statePath)
	}
	return nil
}
