# XMPP Server Gap Analysis
## Angelic Unikernel — RFC 6120 / RFC 6121 / XEP-0045

This document is derived from a full read of the source code
(xmpp_handlers.c, xmpp_server.c, xmpp_router.c, xmpp_core.h,
xmpp_store.c, xmpp_persist.c) cross-referenced against the three
governing RFCs/XEPs.

---

## RFC 6120 — XMPP Core

### 🔴 CRITICAL / Protocol-breaking

#### 1. No `</stream:stream>` sent on any disconnect path
**Where:** `xmpp_server.c` — `xmpp_recv_callback()` p==NULL branch,
`handle_core_bind()` eviction path, rx_buffer overflow path.
**Symptom:** Every client sees a TCP RST instead of a graceful stream close.
Gajim logs "stream closed" as an error rather than a normal event.
**Fix:** Before every `tcp_close()` or `tcp_abort()`, send:
```xml
</stream:stream>
```
For error closes, send:
```xml
<stream:error><CONDITION xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></stream:error>
</stream:stream>
```
**RFC:** §4.4, §4.9.1

---

#### 2. JID validation is entirely absent
**Where:** `handle_sasl()` — `ctx->username` is accepted verbatim from
the decoded PLAIN payload. `handle_core_bind()` — resource is
server-generated (good) but username still unvalidated.
**Symptom:** A username containing `@`, `/`, `<`, `>`, or a space
will corrupt JID construction in `snprintf` calls throughout the
handlers, producing malformed XML.
**Minimum fix:** Reject SASL PLAIN auth if username contains
`@`, `/`, `<`, `>`, ` ` (space), `'`, `"` — send
`<failure><not-authorized/></failure>`.
**RFC:** §2.3 (Nodeprep profile of Stringprep)

---

#### 3. `to` attribute on `<stream:stream>` is not validated
**Where:** `xmpp_recv_callback()` / `handle_handshake_logic()` — the
`strstr(ctx->rx_buffer, "<stream:stream")` path calls
`handle_handshake_logic()` without checking `to=`.
**Symptom:** A client that sends `to='evil.example'` gets a stream
opened as if the domain was correct.
**Fix:** Extract the `to=` attribute; if absent or ≠ `XMPP_DOMAIN`,
send `<stream:error><host-unknown/></stream:error></stream:stream>`
then close.
**RFC:** §4.7.2, §4.9.3.9

---

#### 4. No `<conflict/>` stream error before eviction TCP close
**Where:** `handle_core_bind()` eviction loop — calls `tcp_close()`
directly after `memset()`.
**Current code:**
```c
xmpp_tls_client_free(&client_registry[i]);
tcp_close(client_registry[i].pcb);   // Bug 7 fix: close before zeroing
memset(&client_registry[i], 0, sizeof(xmpp_client_ctx_t));
```
**Missing:** Before `tcp_close()`, send to the evicted client:
```xml
<stream:error>
  <conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>
</stream:error>
</stream:stream>
```
**RFC:** §4.9.3.3

---

#### 5. `stanza->payload` silently truncates at 1023 bytes
**Where:** `xmpp_core.h` — `char payload[1024]`. Parser fills this;
no check exists for truncation.
**Symptom:** Large stanzas (roster with many contacts, OMEMO key
bundles, MUC config forms) are silently truncated. The XML mid-stream
corruption can desync the XML parser for subsequent stanzas.
**Fix:** Detect when the parsed inner content would exceed 1023 bytes
and send:
```xml
<stream:error>
  <policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>
</stream:error>
</stream:stream>
```
Also applies to `xmlns[128]`, `from[64]`, `to[64]`, `id[64]`.
**RFC:** §4.9.3.14

---

### 🟡 IMPORTANT / Interoperability-affecting

#### 6. No SASL failure retry limit
**Where:** `handle_sasl()` — returns without closing stream on
`<not-authorized/>`.
**Risk:** Brute-force password guessing is unlimited.
**Fix:** Add `int sasl_failures` to `xmpp_client_ctx_t`. On the Nth
failure (e.g. N=5), send `<stream:error><policy-violation/></stream:error>
</stream:stream>` and close.
**RFC:** §6.5

---

#### 7. Missing stream error conditions
**Present:** `<policy-violation/>`, `<resource-constraint/>`,
`<invalid-namespace/>`, `<unsupported-version/>`.
**Missing:** `<host-unknown/>` (needed for §3 above),
`<internal-server-error/>`, `<not-well-formed/>`, `<system-shutdown/>`.
The last is particularly useful: before a planned restart, iterate all
clients and send `<stream:error><system-shutdown/></stream:error>
</stream:stream>`.

---

#### 8. Required feature skipping not enforced
**Where:** `xmpp_server.c` / `xmpp_recv_callback()` — a client can
send `<auth>` before completing `<starttls>`.
**Symptom:** STARTTLS is marked `<required/>` in features but nothing
enforces it.
**Fix:** In `handle_sasl()`, check `ctx->tls_established == 0`; if so
send `<failure><encryption-required/></failure>`.
**RFC:** §5.3.2, §6.5

---

## RFC 6121 — XMPP IM

### 🔴 CRITICAL / Core IM functionality

#### 1. Subscription state machine is entirely absent
**Where:** `handle_broadcast_presence()` — subscription stanzas are
forwarded as-is to the target; `roster_store_upsert_item()` stores
whatever XML the client submitted verbatim, never updates
`subscription=` automatically.

**What is happening (correct):**
- Subscription stanzas are forwarded to the target if online, or
  queued in `pending_subs[]` if offline.

**What is NOT happening (missing):**
- When a `<presence type='subscribed'/>` is sent, the server does NOT
  update `subscription='to'` on the sender's roster item for that JID.
- When a `<presence type='subscribed'/>` is received, the server does NOT
  update `subscription='from'` (or `'both'`) on the recipient's item.
- The server does NOT enforce that `<presence>` is only delivered to
  contacts with `subscription='from'` or `'both'`; it broadcasts to all.
- No `ask='subscribe'` attribute is set on pending outbound
  subscription items.

**Practical consequence:** Gajim sends subscribe → gets subscribed back
→ roster still shows `subscription='none'`. Contact list never shows
"subscribed" state correctly.

**Fix outline:**
```c
// In handle_broadcast_presence, subscription branch:
// After forwarding the stanza, call a helper:
void update_subscription_state(const char *owner_user,
                                 const char *contact_jid,
                                 const char *stanza_type);
// This function looks up the roster item for owner_user/contact_jid
// and transitions the subscription field per the RFC 6121 §3 state
// machine table:
//   owner sends 'subscribe'    → set ask='subscribe' in owner's item
//   owner receives 'subscribed' → set subscription='to' (or 'both')
//   owner receives 'subscribe'  → set ask in contact's item
//   owner sends 'subscribed'   → set subscription='from' (or 'both')
//   owner sends 'unsubscribe'  → set subscription='none'/'from'
//   owner receives 'unsubscribed' → set subscription='none'/'from'
```
**RFC:** §3.1 through §3.6

---

#### 2. Initial presence broadcast ignores subscription state
**Where:** `handle_initial_presence()` — iterates ALL
`client_registry[]` slots with `state >= STATE_SESSION`.
**RFC 6121 §4.2.2 says:** "the server MUST broadcast
initial presence to each of the user's contacts that
has a subscription state of 'from' or 'both'".
**Current behaviour:** Broadcasts to every connected user.
**Fix:** Cross-reference each candidate against the roster; only send
if `subscription='from'` or `subscription='both'` on that user's item
for the sender.

---

#### 3. Client's actual presence content is discarded
**Where:** `handle_initial_presence()` — broadcasts a hardcoded
`<show>chat</show><priority>1</priority>`, ignoring the client's actual
`<show>`, `<status>`, and `<priority>` from the incoming stanza.
Also in `handle_broadcast_presence()` probe response:
```c
// hardcoded in probe reply:
"<show>chat</show><priority>1</priority>"
```
**Fix:** Store the client's actual presence XML (or decomposed fields)
in `xmpp_client_ctx_t`:
```c
char presence_show[16];    // away|chat|dnd|xa|""
char presence_status[256]; // arbitrary text
int  presence_priority;    // -128 to 127
char presence_payload[512]; // full inner XML for verbatim forwarding
```
Populate these in `handle_initial_presence()` from `stanza->payload`,
and use them when broadcasting/probing.

---

#### 4. Directed presence not handled
**Where:** `xmpp_router.c` — XMPP_PRESENCE falls through to
`handle_broadcast_presence()` regardless of whether `stanza->to` is
set.
**RFC 6121 §4.6 says:** if a client sends
`<presence to='user2@domain'/>`, that presence goes ONLY to that JID.
**Current behaviour:** Falls into the broadcast loop and is sent to
everyone.
**Fix:** In `handle_broadcast_presence()`, before the broadcast loop,
check if `stanza->to[0] != '\0'` and the target is not a MUC. If so,
do a direct delivery to that JID only.

---

### 🟡 IMPORTANT

#### 5. Roster versioning is static
**Where:** `handle_roster_request()` — always returns `ver='0'`.
**Fix:** Add a `roster_version` integer to persist metadata. Increment
it on every successful roster IQ-set. Return the current value as a
decimal string. This alone satisfies RFC 6121 §2.6.

---

#### 6. Offline message timestamp is always 1970-01-01T00:00:00Z
**Where:** `xmpp_store.c` — `offline_msg_drain()` formats the
XEP-0203 `<delay/>` stamp.
**Current:** No RTC, no PIT ticks → timestamp = 0.
**Fix (partial):** If your hardware has CMOS/RTC access (via port 0x70/
0x71), read wall time at boot and store it. If not, using a monotonic
counter from PIT since boot gives you relative ordering, which is better
than all messages showing the same timestamp. At minimum add the number
of seconds since boot as an offset from 2024-01-01T00:00:00Z.

---

## XEP-0045 — Multi-User Chat

### 🔴 CRITICAL / Core MUC functionality

#### 1. Nick change is treated as a new join
**Where:** `handle_muc_presence()` — the nick-conflict check fires
before detecting that the sender is already in the room with a
different nick.
**Current flow:** User "Alice" (nick="alice") sends
`<presence to='room@conf/newalice'>` → conflict check finds "alice"
is not the same as "newalice" but the user IS already in the room →
a new slot is created → two entries for the same JID.
Wait, actually re-reading: the conflict check is "is this nick already
taken by SOMEONE ELSE" — but the `jid` field is not checked. So
"alice" sends `<presence to='room/bob'>` → no conflict (bob is free)
→ a second slot is created for alice with nick "bob". Alice now has
two entries.
**XEP-0045 §7.6** requires:
1. Detect that sender is already in the room (match by JID).
2. If they request a different nick, treat as nick change:
   - Send `<presence type='unavailable' from='room/oldnick'>` to all
   - Send `<presence from='room/newnick'>` to all with status code 303

---

#### 2. Private messages between occupants are routed as groupchat
**Where:** `handle_chat_message()` — the condition is
`strstr(stanza->to, "conference.angelic.local")`. A message to
`room@conf/nick` (with resource = a nick) satisfies this and is
broadcast to ALL occupants.
**XEP-0045 §7.13** says: if `to` has a resource (occupant nick),
deliver ONLY to that occupant's real JID.
**Fix:**
```c
// In handle_chat_message(), groupchat branch:
char *slash = strchr(stanza->to, '/');
if (slash != NULL) {
    // private message — find recipient by nick, deliver only to them
} else {
    // normal groupchat — broadcast to all
}
```

---

#### 3. Room config form submit does not persist room settings
**Where:** `handle_muc_owner()` IQ-set branch — only clears
`rooms[i].locked = 0`. All the fields from the form
(`muc#roomconfig_persistentroom`, `muc#roomconfig_moderatedroom`,
`muc#roomconfig_membersonly`, `muc#roomconfig_whois`) are parsed but
never stored in `room_t`.
**Also:** `room_t` has no fields for these properties (only
`semi_anon` for `whois`, and `locked`).
**Fix:** Add fields to `room_t`:
```c
int persistent;    // survives empty room
int moderated;     // voice required
int members_only;  // member list enforced
```
Parse them from the submitted form in `handle_muc_owner()` and store.

---

#### 4. Persistent room flag is never checked on room deactivation
**Where:** `handle_muc_presence()` — when last occupant leaves, always
sets `r->active = 0`.
**Fix:** After adding the `persistent` field (item 3 above):
```c
if (!occupied) {
    if (!r->persistent) {
        r->active = 0;
        memset(r->name, 0, sizeof(r->name));
        ...
        xmpp_persist_save_rooms();
    }
    // if persistent, keep active=1, just no occupants
}
```

---

#### 5. Room destroy (`<destroy/>`) is not implemented
**Where:** `handle_muc_owner()` — only handles `type='submit'`.
A `<destroy/>` child in an IQ-set is ignored and returns a generic
result without closing the room.
**XEP-0045 §10.3 requires:**
1. Broadcast `<presence type='unavailable'>` with
   `<x><destroy jid='...'/></x>` to ALL occupants.
2. Set `r->active = 0`.
3. Send IQ result to the requestor.

---

#### 6. Occupant in-room presence updates not relayed
**Where:** `handle_muc_presence()` — only handles join (new entry) and
exit (type='unavailable'). An in-room availability update
(`<presence to='room/nick'><show>away</show></presence>`) falls into
the conflict check path (nick already taken by self) → conflict error
sent → the update is rejected.
**XEP-0045 §7.16 requires:** In-room presence updates must be relayed
to all other occupants.
**Fix:** Before the conflict check, detect if the sender is already in
the room AND the nick is the same as their current nick → treat as
in-room presence update, relay to all.

---

#### 7. Ban list is in-memory only
**Where:** `handle_muc_admin()` — sets `affiliation='outcast'` for
kick/ban but does NOT store a ban list; the user can rejoin immediately.
Comment in code acknowledges this.
**Fix:** Add a ban list to `room_t`:
```c
char banned_jids[8][64];  // up to 8 banned JIDs per room
int  banned_count;
```
Check this list in `handle_muc_presence()` before admitting a user.
Persist via `xmpp_persist_save_rooms()`.

---

### 🟡 IMPORTANT

#### 8. Subject change not implemented
**Where:** `handle_chat_message()` groupchat path — no check for
`<subject>` child element. A subject-change message is broadcast
as-is (which is actually fine for forwarding), but the room's stored
subject is never updated. The join path always sends:
```xml
<message><subject>Welcome to the Unikernel Lobby</subject></message>
```
**Fix:** Add `char subject[256]` to `room_t`. When a groupchat message
contains `<subject>`, update `r->subject`. Use `r->subject` in
the join path.

---

#### 9. `disco#items` on a room doesn't list occupants
**Where:** `handle_disco_items()` — only handles service-level queries
(`conference.angelic.local`) and server-level queries. A query to
`room@conference.angelic.local` falls into the service branch.
**XEP-0045 §6.5** says a query to the room itself should return
current occupants as `<item jid='room/nick'/>`.

---

#### 10. `disco#info` for rooms missing feature vars
**Where:** `handle_disco_info()` CASE 1 (room query) — only returns:
```xml
<feature var='http://jabber.org/protocol/muc'/>
<feature var='muc_semianonymous'/>   (or muc_nonanonymous)
```
Missing (based on actual room config):
- `muc_open` / `muc_membersonly`
- `muc_persistent` / `muc_temporary`
- `muc_moderated` / `muc_unmoderated`
These require the `room_t` fields from item 3 above.

---

## Summary Table

| # | Spec | Severity | Issue | Fixed? |
|---|------|----------|-------|--------|
| 1 | RFC6120 | 🔴 | No `</stream:stream>` on disconnect | ❌ |
| 2 | RFC6120 | 🔴 | JID validation absent | ❌ |
| 3 | RFC6120 | 🔴 | `to=` not validated on stream open | ❌ |
| 4 | RFC6120 | 🔴 | No `<conflict/>` before eviction close | ❌ |
| 5 | RFC6120 | 🔴 | payload truncates at 1023 silently | ❌ |
| 6 | RFC6120 | 🟡 | No SASL retry limit | ❌ |
| 7 | RFC6120 | 🟡 | Missing stream error conditions | ❌ |
| 8 | RFC6120 | 🟡 | Required feature skipping not enforced | ❌ |
| 9 | RFC6121 | 🔴 | Subscription state machine absent | ❌ |
| 10 | RFC6121 | 🔴 | Presence broadcast ignores roster | ❌ |
| 11 | RFC6121 | 🔴 | Client presence content discarded | ❌ |
| 12 | RFC6121 | 🔴 | Directed presence not handled | ❌ |
| 13 | RFC6121 | 🟡 | Roster versioning static | ❌ |
| 14 | RFC6121 | 🟡 | Offline message timestamp = epoch | ❌ |
| 15 | XEP-0045 | 🔴 | Nick change treated as new join | ❌ |
| 16 | XEP-0045 | 🔴 | Private MUC messages broadcast to all | ❌ |
| 17 | XEP-0045 | 🔴 | Room config form not stored | ❌ |
| 18 | XEP-0045 | 🔴 | Persistent room not checked on empty | ❌ |
| 19 | XEP-0045 | 🔴 | Room destroy not implemented | ❌ |
| 20 | XEP-0045 | 🔴 | In-room presence updates rejected | ❌ |
| 21 | XEP-0045 | 🟡 | Ban list in-memory only | ❌ |
| 22 | XEP-0045 | 🟡 | Room subject not updatable | ❌ |
| 23 | XEP-0045 | 🟡 | disco#items on room doesn't list occupants | ❌ |
| 24 | XEP-0045 | 🟡 | disco#info missing room feature vars | ❌ |
