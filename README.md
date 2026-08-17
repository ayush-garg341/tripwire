# tripwire

Watches what your server connects **out** to, and tells you when it talks to
somewhere new.

Security groups allow all egress by default. Flow Logs cost money, arrive late,
and only know IP addresses. Meanwhile a poisoned npm dependency, a crypto miner
or a reverse shell all look the same on the wire: a connection to a destination
your box has never used before. That is the only thing this watches for.

One static binary, ~10 MB of RSS, no libpcap, no agent, no log pipeline.

## Install

Build on your laptop (any OS — the binary is static and self-contained):

```sh
make build     # produces dist/tripwire-linux-amd64 and dist/tripwire-linux-arm64
```

Copy the binary and the two config files up. Use `arm64` for Graviton
instances (t4g, c7g, m7g), `amd64` for everything else:

```sh
scp dist/tripwire-linux-arm64 ec2:/tmp/tripwire
scp deploy/allow.txt deploy/tripwire.service ec2:/tmp/
```

Then on the box, as root — no `make` or Go needed there:

```sh
install -m 0755 /tmp/tripwire /usr/local/bin/tripwire
install -d -m 0700 /var/lib/tripwire /etc/tripwire
install -m 0644 /tmp/allow.txt /etc/tripwire/allow.txt
install -m 0644 /tmp/tripwire.service /etc/systemd/system/tripwire.service
systemctl daemon-reload
```

(If you have the whole repo checked out on the box, `make install` does the
same thing.)

## Use

First, find your interface name — on EC2 it is often `ens5` or `enX0`, not
`eth0`:

```sh
ip route get 1.1.1.1 | grep -o 'dev [^ ]*'
```

Learn what normal looks like. Run this while your app does its usual work —
serving traffic, deploying, running cron. A few days is better than a few hours.

```sh
tripwire -i ens5 -mode learn
```

While it learns, every destination that no allow rule covers is announced as it
appears, so nothing accumulates silently:

```
NEW (no allow rule): api.stripe.com:443 via node(1421) /app/server.js
```

Then review what it collected. `??` marks the destinations you have not blessed
yet — those are the ones that still need a human decision. Newest first, because
something that showed up once at 3am on the last day is the row that matters:

```sh
tripwire -mode review
```

```
RULE  DESTINATION                     FIRST SEEN    COUNT  PROCESS
??    paste.ee:443                    Aug 17 03:14  1      node(1421) /app/server.js
??    api.stripe.com:443              Aug 14 11:20  1423   node(1421) /app/server.js
ok    registry.npmjs.org:443          Aug 14 10:05  892    npm(2011)
ok    s3.eu-west-1.amazonaws.com:443  Aug 14 10:02  15203  node(1421) /app/server.js

4 destinations: 2 covered by an allow rule, 2 not.
```

For each `??`: recognise it, and add a line to `allow.txt`; or don't, and delete
its block from `baseline.json` and go find out what made that connection.

Learn mode records everything it sees and judges none of it — so if the box was
already compromised while learning, the attacker's destination is in that list
too, looking perfectly ordinary. Reviewing is what catches that.

Then switch to watching. New destinations are logged and, optionally, posted to
a webhook:

```sh
tripwire -i ens5 -mode watch -webhook https://hooks.slack.com/services/...
```

To run it permanently, edit the `ExecStart` line in
`/etc/systemd/system/tripwire.service` to use your interface (and webhook),
then:

```sh
systemctl enable --now tripwire
journalctl -u tripwire -f
```

An alert looks like this:

```
EGRESS new destination: node(1421) /app/server.js -> paste.ee [104.21.4.7:443] (paste.ee:443)
```

## Configure

| Flag | Default | Meaning |
|---|---|---|
| `-i` | *(required)* | interface to capture on |
| `-mode` | `watch` | `learn` records egress, `review` lists it, `watch` alerts on new |
| `-state` | `/var/lib/tripwire/baseline.json` | learned baseline |
| `-allow` | `/etc/tripwire/allow.txt` | hand-written rules |
| `-webhook` | *(none)* | Slack/Discord-compatible URL |
| `-flush` | `30s` | how often state is saved and rules reloaded |
| `-v` | off | in learn mode, also log destinations an allow rule already covers |

`allow.txt` is one glob per line and is reloaded without a restart:

```
*.amazonaws.com:443
registry.npmjs.org:443     # noisy during deploys
```

Watch mode never writes to the baseline. To teach it something new, add a line
to `allow.txt` or re-run `learn`.

## What it will not do

- **It does not block anything.** It reports. Auto-blocking egress on a box you
  reach over SSH is how you lose the box.
- **It does not read your traffic.** It reads TCP SYNs and DNS answers; payloads
  are never captured, so TLS is irrelevant to it.
- **It will not see IPv6 or VLAN-tagged traffic** in this version, and it sees
  container traffic only on the interface you point it at (`docker0` for Docker
  bridge networking).
- **Process attribution is best-effort.** A connection that closes before the
  `/proc` lookup lands reports "unknown process".

## Development

```sh
go test ./...     # runs on macOS; capture itself is Linux-only
```

How it works, and why each piece is the way it is:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
