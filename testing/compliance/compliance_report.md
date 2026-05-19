# xmpp compliance report
generated: 2026-05-19T20:54:04
server: angelic.local:5222

## test summary

| suite | passed | failed | total | pass rate |
|-------|--------|--------|-------|-----------|
| raw tcp harness | 60 | 0 | 60 | 100% |
| slixmpp suite | 20 | 0 | 20 | 100% |
| combined | 80 | 0 | 80 | 100% |

## rfc 6120 — xmpp core

| § | requirement | status |
|---|-------------|--------|
| 4.2 | stream opening exchange | ✅ |
| 4.4 | graceful stream close (</stream:stream>) | ✅ |
| 4.7.1 | server sets from= to authoritative domain | ✅ |
| 4.7.3 | stream id hard to predict | ✅ |
| 4.7.5 | version='1.0' | ✅ |
| 4.9.3.9 | host-unknown on wrong to= | ✅ |
| 4.9.3.10 | invalid-namespace on wrong xmlns= | ✅ |
| 5.3.2 | STARTTLS marked required | ✅ |
| 6.4.6 | SASL PLAIN success → <success/> | ✅ |
| 6.5 | bad credentials → <not-authorized/> | ✅ |
| 6.5.5 | bad base64 → <incorrect-encoding/> | ✅ |
| 6.5.7 | invalid mechanism → <invalid-mechanism/> | ✅ |
| 7.2 | post-auth stream features include <bind> | ✅ |
| 7.7 | bind result contains full jid | ✅ |
| 8.2.3 | unknown iq get → error | ✅ |

## rfc 6121 — xmpp im

| § | requirement | status |
|---|-------------|--------|
| 2.1.3 | roster get → result with <query xmlns='jabber:iq:roster'> | ✅ |
| 2.1.5 | roster set → acknowledged | ✅ |
| 2.6 | roster get with ver= → result includes ver= | ✅ |
| 3.1.3 | subscribe forwarded to recipient | ✅ |
| 3.1.3 | subscribed forwarded back | ✅ |
| 3.1 | after subscription, roster shows subscription='to' | ✅ |
| 4.2 | initial presence elicits at least one <presence> | ✅ |
| 4.6 | client <show>/<status>/<priority> forwarded verbatim | ✅ |
| 5 | direct message delivered | ✅ |
| 8 | offline message delivered with <delay/> | ✅ |

## xep-0045 — multi-user chat

| § | requirement | status |
|---|-------------|--------|
| 7.2.2 | join → self-presence with status 110 | ✅ |
| 7.2.2 | new room → status 201, affiliation='owner' | ✅ |
| 7.2.8 | nick conflict → <conflict/> error | ✅ |
| 7.2.15 | room subject sent after join | ✅ |
| 7.6 | nick change → unavailable + status 303 | ✅ |
| 7.9 | groupchat message broadcast to all occupants | ✅ |
| 7.9 | groupchat message reflected to sender | ✅ |
| 7.13 | private message delivered only to addressed occupant | ✅ |
| 7.13 | private message not delivered to others | ✅ |
| 7.14 | leave → unavailable presence sent | ✅ |
| 7.16 | in-room presence update relayed | ✅ |
| 10.1 | config form submit → iq result | ✅ |

## xep-0030 — service discovery

| § | requirement | status |
|---|-------------|--------|
| 3 | disco#info on server → identity + features | ✅ |
| 3.2 | disco#items on server → muc service listed | ✅ |
| 6.2 (xep-0045) | disco#info on muc service | ✅ |

## xep-0160 / xep-0199 / xep-0092

| xep | requirement | status |
|-----|-------------|--------|
| xep-0199 | ping → iq result | ✅ |
| xep-0092 | version query → name/version | ⚠️ |
| xep-0160 | offline message stored + delivered with delay | ✅ |

---
*✅ = pass ❌ = fail ⚠️ = not tested*
