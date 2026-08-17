# Architecture

How tripwire works, and why each decision went the way it did. Read
[README.md](../README.md) first for what it does.

## The idea in one paragraph

Almost every compromise a solo operator actually faces — a poisoned dependency,
a crypto miner, a reverse shell, credentials being exfiltrated — has to reach
the network to be worth anything. All of them look identical at the moment they
do: an outbound connection to a destination this box has never used before.
Applications, by contrast, talk to a *small and boring* set of places, and that
set barely changes between deploys. So instead of matching known-bad signatures,
tripwire learns the known-good set and reports anything outside it. That inverts
the usual problem: it needs no threat feed, and it catches supply-chain attacks
that have no signature yet.

## The packet path

```
                  the wire
                     |
        +------------v------------+
        |   AF_PACKET raw socket  |
        |   + attached BPF filter |   <-- kernel; discards ~99.9% of traffic
        +------------+------------+
                     |  only bare SYNs and DNS
        +------------v------------+
        |       parseFrame        |   <-- zero-allocation header decode
        +------+-----------+------+
               |           |
          DNS answer   outbound SYN
               |           |
        +------v-----+ +---v----------------------+
        |  dnsCache  +>| destKey -> baseline?     |
        | ip -> name | +---+----------------------+
        +------------+     | not known
                           |
                    +------v------+     +----------+
                    | /proc walk  +---->| notifier |--> log + webhook
                    | (attribute) |     +----------+
                    +-------------+
```

### 1. The kernel filter does the work

The filter in [`filter.go`](../filter.go) is the whole efficiency story. It is
the BPF equivalent of:

```
(tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn) or (udp port 53)
```

A *bare* SYN — SYN set, ACK clear — is the first packet of a new connection.
Everything after it in the conversation, which is nearly all the bytes on the
wire, is irrelevant to us and never leaves the kernel. On a small app server
this turns "every packet" into a few hundred 74-byte frames an hour.

Two details in that program are worth knowing:

- **`LoadMemShift`** computes the IP header length at runtime so the TCP flags
  are read at `14 + IHL*4 + 13`, not a fixed offset. A packet with IP options
  would otherwise have its flags read out of the middle of the header. Both
  `filter_test.go` and `parse_test.go` cover this case.
- **Direction is not filtered here.** DNS answers arrive *inbound* and we need
  them, so both directions are accepted and inbound SYNs are dropped in
  userspace. AF_PACKET hands us `PACKET_OUTGOING` on every read for free, so
  this costs nothing and keeps the BPF program short enough to read — and short
  enough to run through a BPF VM in tests, which is how the hand-counted jump
  offsets are verified.

### 2. Why AF_PACKET directly, and not libpcap

Using libpcap would mean cgo, which means the binary stops being static and
starts depending on the target's libpcap version. Opening the socket by hand
with `x/sys/unix` is about forty lines, and in exchange the deployment story
becomes "copy one file". There are no runtime dependencies to install or patch
on the box.

The cost is no `TPACKET_V3` mmap ring buffer, so each packet costs a syscall.
At the filtered packet rate this is irrelevant, and the simplicity is worth
more than the syscalls saved.

### 3. Naming the destination

An alert that says `104.18.32.7` is useless — that is a Cloudflare address that
belongs to a different customer every week. So tripwire watches DNS answers and
builds an IP → hostname map.

The name it records is the one from the **question** section, not the name on
the answer record. For a chain like:

```
api.myapp.com  CNAME  d3x9.cloudfront.net  A  9.9.9.9
```

the useful name — the one a human recognises, and the one that stays stable —
is `api.myapp.com`. The A record only knows about the CDN alias.

**A lookup miss is itself a signal.** A connection to an address that was never
resolved means the destination was hardcoded rather than looked up, which is
much more characteristic of malware than of an application using a DNS name.
Those alerts are tagged `never resolved`.

### 4. Attributing the connection

`node(1421) /app/server.js` is an actionable alert; `something on this box` is
not. Attribution maps the connection's port pair to a socket inode via
`/proc/net/tcp`, then scans `/proc/<pid>/fd` for the process holding it.

That scan is not cheap, so it is gated twice: it runs **only** for destinations
that are not already known, and **only** for those that pass the cooldown. In
steady state it never runs at all.

It is best-effort by nature. A connection that closes before the lookup lands
leaves nothing to find, and the alert says `unknown process` instead. Reporting
that honestly is better than blocking the capture loop to win the race.

## Keeping memory flat

This is the constraint the whole design is arranged around: a monitoring daemon
that can starve the application it protects is worse than no daemon. Language
choice only sets the floor (~6 MB for Go). What actually decides whether RSS
stays flat is that **every structure that grows with traffic has a hard cap**:

| Structure | Bound | What stops it growing |
|---|---|---|
| Capture buffer | 64 KB | allocated once at startup, reused forever |
| Packet decode | 0 bytes | `parseFrame` allocates nothing; `netip.Addr` is a value, and the payload aliases the buffer. Guarded by `TestParseFrameAllocatesNothing` |
| DNS cache | 4096 entries | TTL eviction (clamped to 60s–1h), then oldest-expiry eviction when full |
| Baseline | 4096 entries | refuses to learn past the cap, and logs once when it hits it |
| Cooldown table | 1024 entries | expired-first sweep, then reset |
| Alert queue | 256 alerts | non-blocking send; drops and counts when full |
| Kernel socket buffer | 256 KB | `SO_RCVBUF` |

The cardinality of the baseline is the subtle one. Keying entries on the
*hostname* rather than the address is what stops a CDN handing out a new address
every minute from looking like hundreds of new destinations. When the name is
unknown the address is widened to a `/24` for the same reason. Alerts still
print the exact IP — the widening only affects how destinations are grouped and
counted.

The systemd unit adds `GOMEMLIMIT=48MiB` and `MemoryMax=64M` as backstops. Those
are belt-and-braces: if they ever trigger, something above is wrong.

## Threading

There is one goroutine that matters. It owns the DNS cache, the baseline and the
cooldown table, and nothing else ever touches them — so none of them carry a
mutex, and none of them can race.

The only hand-off is the alert channel, which carries copies to a delivery
goroutine. That split exists for one reason: a slow or hanging webhook must
never stall packet capture. If the queue fills, alerts are dropped and counted,
because losing an alert is strictly better than stalling the box's monitoring.

Housekeeping (saving state, reloading `allow.txt`) also runs on the capture
goroutine. That is why reads carry a one-second timeout: the timeout is what
gives the loop a chance to do periodic work and notice signals without a second
goroutine and the locking that would come with it.

## Learn, review and watch

`learn` records; `review` prints what was recorded; `watch` alerts and **never
writes to the baseline**.

The review step exists because learn mode is a stenographer, not a judge: it
records what happened, and a destination reached during a compromise is
indistinguishable from a real dependency at the moment it is recorded. So learn
mode announces every destination no allow rule covers as it appears, and
`review` lists them again afterwards, marking which ones a rule already blesses.
The unblessed rows are the review queue, sorted newest first. Nothing is ever
promoted automatically - crossing from "this happened" to "this is fine" is
always a human writing a line in `allow.txt`. That
asymmetry is deliberate: a baseline that keeps learning in production would
quietly absorb an attacker's destination as normal the moment it appeared. To
teach a running watcher about a new destination you add a line to `allow.txt` —
an explicit, reviewable, human action — and it takes effect within one flush
interval without a restart.

The baseline is written with a temp-file-and-rename, so a crash mid-write leaves
the previous baseline intact rather than a truncated one.

## Limits, stated plainly

- **IPv4 only.** The filter checks for EtherType `0x0800` and bails otherwise.
  IPv6 egress is invisible to this version. On a box with IPv6 connectivity that
  is a real gap, not a cosmetic one.
- **Untagged Ethernet only.** VLAN-tagged frames (EtherType `0x8100`) are
  skipped. Not a concern in a normal VPC.
- **One interface.** Container traffic is only seen on the interface you point
  it at — use `docker0` for Docker bridge networking, and note that
  container-to-container traffic on a user-defined network never reaches `eth0`.
- **UDP destinations are not baselined.** Only TCP connections are, because UDP
  has no connection to detect the start of. QUIC egress is therefore invisible,
  which matters more every year.
- **It is a detective control, not a preventive one.** It tells you something
  happened. It does not stop it.
- **Anything with root can turn it off.** It raises the cost of a quiet
  compromise; it does not survive one that gets root and knows to look.

## Where to take it next

In rough order of value per unit of work:

1. **TLS SNI parsing.** Read the `ClientHello` and take the server name straight
   off the wire. That covers DNS-over-HTTPS and hardcoded IPs, the two cases
   where DNS correlation gives you nothing today. Costs one more filter clause
   and a small parser.
2. **IPv6.** Mostly a second branch in the filter and in `parseFrame`.
3. **A digest instead of alerts.** A daily "here is everything new this week"
   summary is a better fit for a solo operator than per-event pings, and is far
   less likely to be muted.
4. **Optional blocking.** An `nftables` drop rule per confirmed-bad destination.
   Kept out of v1 on purpose: auto-blocking egress on a box you reach over SSH
   is how you lock yourself out of production at 3am.
