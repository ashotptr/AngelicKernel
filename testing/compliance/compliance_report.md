# XMPP Compliance Report
Generated: 2026-04-20T22:34:18
Server: angelic.local:5222

## Test Summary

| Suite | Passed | Failed | Total | Pass Rate |
|-------|--------|--------|-------|-----------|
| Raw TCP harness | 60 | 0 | 60 | 100% |
| slixmpp suite   | 0 | 0 | 0 | 0% |
| **COMBINED**    | **60** | **0** | **60** | **100%** |

## RFC 6120 — XMPP Core

| § | Requirement | Status |
|---|-------------|--------|
| 4.2 | Stream opening exchange | ✅ |
| 4.4 | Graceful stream close (</stream:stream>) | ✅ |
| 4.7.1 | Server sets from= to authoritative domain | ✅ |
| 4.7.3 | Stream ID hard to predict | ✅ |
| 4.7.5 | version='1.0' | ✅ |
| 4.9.3.9 | host-unknown on wrong to= | ✅ |
| 4.9.3.10 | invalid-namespace on wrong xmlns= | ✅ |
| 5.3.2 | STARTTLS marked required | ✅ |
| 6.4.6 | SASL PLAIN success → <success/> | ✅ |
| 6.5 | Bad credentials → <not-authorized/> | ✅ |
| 6.5.5 | Bad Base64 → <incorrect-encoding/> | ✅ |
| 6.5.7 | Invalid mechanism → <invalid-mechanism/> | ✅ |
| 7.2 | Post-auth stream features include <bind> | ✅ |
| 7.7 | Bind result contains full JID | ✅ |
| 8.2.3 | Unknown IQ get → error | ✅ |

## RFC 6121 — XMPP IM

| § | Requirement | Status |
|---|-------------|--------|
| 2.1.3 | Roster get → result with <query xmlns='jabber:iq:roster'> | ✅ |
| 2.1.5 | Roster set → acknowledged | ✅ |
| 2.6 | Roster get with ver= → result includes ver= | ✅ |
| 3.1.3 | subscribe forwarded to recipient | ✅ |
| 3.1.3 | subscribed forwarded back | ✅ |
| 3.1 | After subscription, roster shows subscription='to' | ✅ |
| 4.2 | Initial presence elicits at least one <presence> | ✅ |
| 4.6 | Client <show>/<status>/<priority> forwarded verbatim | ✅ |
| 5 | Direct message delivered | ✅ |
| 8 | Offline message delivered with <delay/> | ✅ |

## XEP-0045 — Multi-User Chat

| § | Requirement | Status |
|---|-------------|--------|
| 7.2.2 | Join → self-presence with status 110 | ✅ |
| 7.2.2 | New room → status 201, affiliation='owner' | ✅ |
| 7.2.8 | Nick conflict → <conflict/> error | ✅ |
| 7.2.15 | Room subject sent after join | ✅ |
| 7.6 | Nick change → unavailable + status 303 | ✅ |
| 7.9 | Groupchat message broadcast to all occupants | ✅ |
| 7.9 | Groupchat message reflected to sender | ✅ |
| 7.13 | Private message delivered only to addressed occupant | ✅ |
| 7.13 | Private message NOT delivered to others | ✅ |
| 7.14 | Leave → unavailable presence sent | ✅ |
| 7.16 | In-room presence update relayed | ✅ |
| 10.1 | Config form submit → IQ result | ✅ |

## XEP-0030 — Service Discovery

| § | Requirement | Status |
|---|-------------|--------|
| 3 | disco#info on server → identity + features | ✅ |
| 3.2 | disco#items on server → MUC service listed | ✅ |
| 6.2 (XEP-0045) | disco#info on MUC service | ✅ |

## XEP-0160 / XEP-0199 / XEP-0092

| XEP | Requirement | Status |
|-----|-------------|--------|
| XEP-0199 | Ping → IQ result | ✅ |
| XEP-0092 | Version query → name/version | ⚠️ |
| XEP-0160 | Offline message stored + delivered with delay | ✅ |

---
*✅ = PASS  ❌ = FAIL  ⚠️ = NOT TESTED*
