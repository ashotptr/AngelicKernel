# Angelic XMPP Server — Testing & Compliance Guide

## Overview

This guide covers three layers of automated testing for your bare-metal
unikernel XMPP server, plus instructions for using the official online
XMPP compliance testers.

---

## Project Structure

```
xmpp_testing/
├── raw_tests/
│   └── raw_xmpp_tester.py     # Low-level raw TCP/XML tests (RFC 6120/6121/XEP-0045)
├── slixmpp_tests/
│   └── slixmpp_suite.py       # Higher-level async tests via slixmpp library
├── compliance/
│   └── compliance_report.py   # Aggregate both suites → markdown report
└── docs/
    └── GAP_ANALYSIS.md        # Detailed gap analysis vs specs
```

---

## Layer 1 — Raw TCP/XML Test Harness

**Best for:** RFC 6120 stream-level tests, SASL, TLS, stream errors,
things a high-level library would abstract away and never let you
observe.

**Catches:** wrong stream closing, missing stream errors, SASL failure
handling, bad-namespace rejection, incorrect IQ error shapes.

### Install

```bash
pip install colorama pyopenssl
```

### Run

```bash
# Full suite
python3 raw_tests/raw_xmpp_tester.py --host angelic.local --port 5222

# Run only MUC tests
python3 raw_tests/raw_xmpp_tester.py --host angelic.local --port 5222 --filter 0045

# Run only RFC 6120 stream tests
python3 raw_tests/raw_xmpp_tester.py --host angelic.local --port 5222 --filter 6120
```

### What it tests (24 RFC-specific assertions)

**RFC 6120:**
- Stream opening response (stream:stream, features, from=, version=, id=)
- `host-unknown` on wrong `to=` attribute
- Graceful `</stream:stream>` on clean close
- SASL PLAIN: good/bad credentials, bad Base64, invalid mechanism
- Resource bind: features contain bind, result contains full JID
- Unknown IQ namespace → error response
- Invalid XML namespace → stream error

**RFC 6121:**
- Roster get/set/versioning
- Initial presence
- `<show>/<status>/<priority>` forwarded verbatim (vs current hardcoded)
- Direct message delivery
- Offline message with XEP-0203 `<delay/>`
- Subscription flow (subscribe/subscribed/unsubscribed + roster state update)

**XEP-0045:**
- Room create + join (status 110, 201, affiliation=owner)
- Room subject on join
- Nick conflict (409 + `<conflict/>`)
- Groupchat message broadcast + reflection
- **Private message** to room/nick (not broadcast)
- **Nick change** (status 303 + unavailable from old nick)
- **In-room presence update** relayed
- disco#info / disco#items

---

## Layer 2 — slixmpp Async Test Suite

**Best for:** RFC 6121 IM semantics, subscription state machine,
MUC interaction, service discovery — tested with a real, battle-hardened
XMPP client library that handles all the XML parsing and state correctly.

**Catches:** presence forwarding, roster subscription state transitions,
XEP-0045 MUC semantics at the client level, offline delivery.

### Install

```bash
pip install slixmpp colorama
```

### Run

```bash
python3 slixmpp_tests/slixmpp_suite.py --host angelic.local --port 5222

# Filter by name
python3 slixmpp_tests/slixmpp_suite.py --host angelic.local --port 5222 --filter muc
```

### What it tests (10 async test scenarios)

1. Connect + session establishment (TLS + SASL + bind)
2. Roster get
3. Roster update + full subscription flow (subscribe → subscribed → roster state)
4. Direct chat message delivery
5. MUC join + groupchat broadcast
6. MUC private message (delivered only to target, NOT to others)
7. Ping (XEP-0199)
8. Service Discovery (XEP-0030) — server + MUC service
9. Software Version (XEP-0092)
10. Offline message storage + delivery with `<delay/>`

---

## Layer 3 — Combined Compliance Report

Runs both suites and produces a Markdown compliance matrix.

```bash
cd compliance
python3 compliance_report.py --host angelic.local --port 5222 --output report.md
cat report.md
```

Output is a table per RFC/XEP with ✅/❌/⚠️ per requirement.

---

## Layer 4 — Tigase TTS-NG (Java Functional Test Suite)

**Best for:** The most comprehensive XMPP test suite that exists.
Over 200 functional tests covering Core XMPP, MUC, PubSub, MAM.
Used to validate production Tigase XMPP Server.

### Prerequisites

- Java 17+
- Maven 3.8+

### Setup

```bash
git clone https://github.com/tigase/tigase-tts-ng.git
cd tigase-tts-ng

# Copy and edit the settings file
cp scripts/tests-runner-settings.dist.sh scripts/tests-runner-settings.sh
```

Edit `scripts/tests-runner-settings.sh`:
```bash
# Point at your server
SERVER_IP="angelic.local"       # or the IP QEMU VM is reachable at
SERVER_DOMAIN="angelic.local"
MUC_COMPONENT_DOMAIN="conference.angelic.local"

# Admin credentials
ADMIN_JID="admin@angelic.local"
ADMIN_PASSWORD="admin"

# Test users
USER1_JID="user1@angelic.local"
USER1_PASSWORD="pass1"
USER2_JID="user2@angelic.local"
USER2_PASSWORD="pass2"

# Disable database setup (your server doesn't use a DB)
SKIP_DB_SETUP=true
SKIP_SERVER_STARTUP=true  # Your server is already running
```

Build and run:
```bash
mvn -Pdist clean install -DskipTests

# Run all XMPP Core tests
./scripts/tests-runner.sh --custom tigase.tests.xmpp.*

# Run MUC tests only
./scripts/tests-runner.sh --custom tigase.tests.muc.*

# Run everything
./scripts/tests-runner.sh --all-tests
```

**Note:** TTS-NG was designed for Tigase server, so some tests may
require specific extensions (PubSub, MAM) your server doesn't implement.
Focus on the core and MUC test groups.

---

## Layer 5 — Online XMPP Compliance Testers

These are the most authoritative, community-maintained compliance tests.
They require your server to be publicly reachable on port 5222.

### Option A — Tailscale (Easiest, LAN-private, no public internet)

Tailscale creates a private WireGuard mesh. Your VM gets a stable
100.x.y.z address reachable from any device in your Tailnet.

```bash
# On the host running your QEMU VM:
# (Tailscale runs on the host; forward port 5222 to the VM)
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# Forward XMPP port from host Tailscale IP → QEMU VM
socat TCP-LISTEN:5222,reuseaddr,fork TCP:192.168.122.X:5222 &
# where 192.168.122.X is your QEMU VM's internal IP

# Your Tailscale hostname is something like:
#   hostname.tail12345.ts.net
# Set DNS: add angelic.local → tailscale IP in /etc/hosts on test machines
```

Then run tests from any machine in your Tailnet:
```bash
python3 raw_tests/raw_xmpp_tester.py --host 100.x.y.z --port 5222
```

### Option B — ngrok (Quick public tunnel, temporary)

```bash
# Install ngrok: https://ngrok.com/download
# Note: ngrok TCP tunnels require a paid plan for port 5222 (non-HTTP)
ngrok tcp 5222
# You get a hostname like: tcp://0.tcp.ngrok.io:PORT
```

Your XMPP domain (`angelic.local`) must be resolvable as the tunnel host.
For compliance testers, they need to do a DNS SRV lookup:
```
_xmpp-client._tcp.yourdomain.com → 0.tcp.ngrok.io PORT
```
This requires real DNS control.

### Option C — Dedicated VPS with real domain (Best for compliance testing)

1. Get a VPS (Hetzner, DigitalOcean, Linode — ~$5/month)
2. Get a domain (e.g. `angelic-xmpp.net`)
3. Set DNS:
   ```
   A    angelic-xmpp.net    →   YOUR-VPS-IP
   A    conference.angelic-xmpp.net → YOUR-VPS-IP
   SRV  _xmpp-client._tcp.angelic-xmpp.net 5 0 5222 angelic-xmpp.net
   SRV  _xmpp-server._tcp.angelic-xmpp.net 5 0 5269 angelic-xmpp.net
   ```
4. Forward port 5222 from the VPS to your machine via an SSH tunnel:
   ```bash
   # On VPS (make it listen publicly):
   ssh -R 5222:localhost:5222 user@vps-ip
   # or use autossh for persistence:
   autossh -M 20000 -N -R 5222:localhost:5222 user@vps-ip
   ```
5. Update your server's XMPP_DOMAIN to `angelic-xmpp.net`
6. Generate a real Let's Encrypt cert or use your self-signed one

Then submit to:

#### XMPP Compliance Tester — https://compliance.conversations.im
- Tests your server against the XMPP Compliance Suite 2023
- Checks: Core (RFC 6120/6121), HTTP Upload, Message Delivery Receipts,
  Chat Markers, OMEMO, MUC, etc.
- Enter your domain and it tests from the internet

#### XMPP Observatory — https://xmpp.net/
- Tests TLS/SSL configuration specifically
- Gives A-F grades on TLS cipher suites, certificate validity, etc.

#### IM Observatory — https://www.jabber.at/online/
- Similar, checks if your server is reachable and responds correctly

### Setting XMPP_DOMAIN for public testing

In `xmpp_core.h`, change:
```c
#define XMPP_DOMAIN "angelic-xmpp.net"   // your real domain
```

And in the TLS cert generation (xmpp_tls.c), update the CN/SAN to match.

---

## Recommended Test Order

When fixing bugs from the GAP_ANALYSIS.md, run tests in this order:

1. **Start with raw harness, RFC 6120 filter:**
   ```bash
   python3 raw_xmpp_tester.py --filter 6120
   ```
   This validates the stream layer is correct before anything else.

2. **Then RFC 6121 basics:**
   ```bash
   python3 raw_xmpp_tester.py --filter 6121
   ```

3. **Then MUC:**
   ```bash
   python3 raw_xmpp_tester.py --filter 0045
   ```

4. **Run slixmpp suite for semantic validation:**
   ```bash
   python3 slixmpp_suite.py
   ```

5. **Generate compliance report:**
   ```bash
   cd compliance && python3 compliance_report.py
   ```

6. **Run Tigase TTS-NG for deep functional coverage.**

7. **Expose publicly + run compliance.conversations.im.**

---

## Quick Fix Priority Order (from GAP_ANALYSIS.md)

Fix these first for maximum compliance gain:

1. **`</stream:stream>` on all disconnect paths** (RFC 6120 §4.4)
   — One change, huge improvement in client compatibility.

2. **Client presence content forwarding** (RFC 6121 §4.6)
   — Store `<show>/<status>/<priority>` in ctx, forward them.

3. **MUC private messages** (XEP-0045 §7.13)
   — Check for `/` in `stanza->to` in the groupchat handler.

4. **MUC in-room presence updates** (XEP-0045 §7.16)
   — Check if sender already in room with same nick → relay update.

5. **MUC nick change** (XEP-0045 §7.6)
   — Check if sender already in room with different nick → nick change flow.

6. **Directed presence** (RFC 6121 §4.6)
   — Check `stanza->to` before broadcasting to everyone.

7. **Subscription state machine** (RFC 6121 §3)
   — Most complex; saves for after the simpler fixes.
