#include "xmpp_core.h"
#include <stdio.h>

/* ============================================================
 * XMPP HANDLERS
 *
 * Each function is the leaf handler for one protocol feature.
 * Handlers are reached via xmpp_route_stanza() or called directly
 * from xmpp_recv_callback() for SASL.
 *
 * Governing documents:
 *   RFC 6120  XMPP Core
 *     https://datatracker.ietf.org/doc/html/rfc6120
 *   RFC 6121  XMPP IM
 *     https://datatracker.ietf.org/doc/html/rfc6121
 *   XEP-0045  Multi-User Chat
 *     https://xmpp.org/extensions/xep-0045.html
 * ============================================================ */


/* ------------------------------------------------------------------
 * Compile-time credential table
 *
 * RFC 6120 §6.5 — <not-authorized/>: MUST be sent when the username or
 *   password provided by the client does not match a known account.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-6.5
 *
 * RFC 4616 §2 — SASL PLAIN: credentials are {authzid NUL authcid NUL passwd}.
 *   Only authcid (username) and passwd are checked here; authzid is
 *   ignored per RFC 4616 §2 for simple implementations.
 *   https://datatracker.ietf.org/doc/html/rfc4616#section-2
 *
 * SECURITY NOTE: PLAIN credentials travel in cleartext.
 *   Acceptable only over a trusted, isolated LAN with no TLS.
 *   Do NOT expose this server on a public or untrusted network.
 *
 * ANONYMOUS mechanism (RFC 4505) bypasses this table entirely;
 * any client using ANONYMOUS is allowed in unconditionally.
 *
 * To update: change the entries below and recompile.
 * ------------------------------------------------------------------ */
const xmpp_credential_t xmpp_credentials[] = {
    { "admin",  "admin"  },
    { "user1",  "pass1"  },
    { "user2",  "pass2"  },
    /* Add more { "username", "password" } entries as needed */
};

/* ===========================================================================
 * Pending Subscription Store
 *
 * RFC 6121 §4.3 — On initial presence, the server SHOULD deliver any
 * subscription requests that arrived while the target user was offline.
 * https://datatracker.ietf.org/doc/html/rfc6121#section-4.3
 *
 * Implementation:
 *   When handle_broadcast_presence() cannot deliver a subscription stanza
 *   (subscribe / subscribed / unsubscribe / unsubscribed) because the
 *   target user has no active session, the stanza is queued here keyed by
 *   the target's username.  When handle_initial_presence() fires for that
 *   user, all queued entries are drained and delivered.
 *
 * Capacity: MAX_PENDING_SUBS = 32.  Duplicate (type, from, to_user)
 * triples are silently dropped.  If the queue is full, the oldest entry
 * for the same recipient is recycled; failing that the lowest-index
 * active slot is overwritten so the most-recent intent is preserved.
 * =========================================================================== */
/* MAX_PENDING_SUBS and pending_sub_t are defined in xmpp_core.h so that
 * xmpp_persist.c can access this array via the extern declared there.
 * Non-static: xmpp_persist.c saves and restores this array at boot. */
pending_sub_t pending_subs[MAX_PENDING_SUBS];


/* ------------------------------------------------------------------
 * pending_sub_enqueue
 *
 * Adds (type, from, to_user) to the pending queue for offline delivery.
 * Deduplicates: an identical triple already in the queue is a no-op.
 * ------------------------------------------------------------------ */
static void pending_sub_enqueue(const char *type, const char *from, const char *to_user){
    /* Deduplication pass */
    for (int i = 0; i < MAX_PENDING_SUBS; i++) {
        if (!pending_subs[i].active) {
            continue;
        }

        if (strcmp(pending_subs[i].type, type) == 0 && strcmp(pending_subs[i].from, from) == 0 && strcmp(pending_subs[i].to_user, to_user) == 0) {
            return; /* exact duplicate -- ignore */
        }
    }

    /* Find a free slot */
    int slot = -1;
    
    for (int i = 0; i < MAX_PENDING_SUBS; i++) {
        if (!pending_subs[i].active) { 
            slot = i; 
            
            break; 
        }
    }

    /* If full: recycle same-recipient slot, then fall back to slot 0 */
    if (slot < 0) {
        for (int i = 0; i < MAX_PENDING_SUBS; i++) {
            if (strcmp(pending_subs[i].to_user, to_user) == 0) { 
                slot = i;
            
                break; 
            }
        }
    }

    if (slot < 0) {
        slot = 0;
    }

    strncpy(pending_subs[slot].type, type, sizeof(pending_subs[slot].type) - 1);
    strncpy(pending_subs[slot].from, from, sizeof(pending_subs[slot].from) - 1);
    strncpy(pending_subs[slot].to_user, to_user, sizeof(pending_subs[slot].to_user) - 1);
    
    pending_subs[slot].type[sizeof(pending_subs[slot].type) - 1] = '\0';
    pending_subs[slot].from[sizeof(pending_subs[slot].from) - 1] = '\0';
    pending_subs[slot].to_user[sizeof(pending_subs[slot].to_user) - 1] = '\0';
    pending_subs[slot].active = 1;

    /* Write-through: persist immediately so subscription intents survive
     * a server restart (RFC 6121 §4.3 requires offline delivery). */
    xmpp_persist_save_pending_subs();
}


/* ------------------------------------------------------------------
 * pending_sub_drain
 *
 * Delivers all queued subscription stanzas for ctx->username to the
 * newly-available client, then clears those entries.
 *
 * Called from handle_initial_presence() after the presence broadcast.
 * RFC 6121 §4.3 — https://datatracker.ietf.org/doc/html/rfc6121#section-4.3
 * ------------------------------------------------------------------ */
static void pending_sub_drain(xmpp_client_ctx_t *ctx){
    char stanza[256];

    for (int i = 0; i < MAX_PENDING_SUBS; i++) {
        if (!pending_subs[i].active) {
            continue;
        }
        
        if (strcmp(pending_subs[i].to_user, ctx->username) != 0) {
            continue;
        }

        snprintf(stanza, sizeof(stanza),
            "<presence type='%s' from='%s' to='%s'/>",
            pending_subs[i].type,
            pending_subs[i].from,
            ctx->full_jid);

        send_raw(ctx, stanza);

        pending_subs[i].active = 0;
    }

    /* Persist once after the full drain loop so delivered entries are
     * not replayed after a restart (RFC 6121 §4.3). */
    xmpp_persist_save_pending_subs();
}

const int xmpp_credential_count = (int)(sizeof(xmpp_credentials) / sizeof(xmpp_credentials[0]));


/* ------------------------------------------------------------------
 * find_client_by_jid  (FIX Bug 2 — dangling PCB in target_ctx)
 *
 * Returns the live client_registry[] slot whose full_jid matches
 * full_jid, or NULL if no such slot exists or the slot's PCB is NULL.
 *
 * WHY THIS IS NEEDED:
 *   MUC broadcast loops previously built a stack-local
 *   xmpp_client_ctx_t target_ctx whose only initialised field was pcb,
 *   copied verbatim from participant_t.pcb.  If that client had already
 *   disconnected (Bug 1 fix — pcb nulled on close), participant_t.pcb
 *   still pointed at the now-freed PCB: the old target_ctx approach
 *   was therefore a use-after-free.
 *
 *   By looking up the client through client_registry[] — the single
 *   authoritative source of truth — we guarantee that only live,
 *   session-ready connections are written to.  A NULL return means the
 *   participant has disconnected and the send is safely skipped.
 *
 * Callers: handle_muc_presence, handle_muc_admin, handle_chat_message.
 * ------------------------------------------------------------------ */
static xmpp_client_ctx_t *find_client_by_jid(const char *full_jid) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (client_registry[i].pcb == NULL) {
            continue;
        }
        if (client_registry[i].state < STATE_SESSION) {
            continue;
        }
        if (strcmp(client_registry[i].full_jid, full_jid) == 0) {
            return &client_registry[i];
        }
    }
    return NULL;
}


/* ------------------------------------------------------------------
 * b64decode  (static helper)
 *
 * Decodes a Base64 string into raw bytes.
 * Used by handle_sasl() to decode the SASL PLAIN payload.
 *
 * Encoding spec:
 *   RFC 4648 §4 — Base64 alphabet and padding rules
 *   https://datatracker.ietf.org/doc/html/rfc4648#section-4
 *
 * Validation requirement:
 *   RFC 6120 §13.9.1 — "the receiving entity MUST verify that the
 *   [Base64] data is properly encoded."
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-13.9.1
 *   BUG: invalid Base64 characters are silently skipped (val < 0 →
 *   continue) instead of triggering a failure. On encountering an
 *   invalid character this function should return -1 and handle_sasl()
 *   should respond with:
 *     RFC 6120 §6.5.5 — <failure><incorrect-encoding/></failure>
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6.5
 *
 * Performance note:
 *   O(n·64) linear scan per character. Fine for the short SASL payloads
 *   here. Replace with a 256-entry lookup table if ever used elsewhere.
 * ------------------------------------------------------------------ */
static int b64decode(const char *src, unsigned char *dst, int dst_len) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    int out = 0;
    unsigned int buf = 0;
    int bits = 0;

    for (; *src && *src != '='; src++) {
        int val = -1;

        for (int i = 0; i < 64; i++) {
            if (chars[i] == *src) { 
                val = i;

                break; 
            }
        }

        if (val < 0) {
            /* RFC 6120 §13.9.1 — "the receiving entity MUST verify that
             * the [Base64] data is properly encoded."  An invalid character
             * means the entire payload is malformed; return -1 so the
             * caller can send <failure><incorrect-encoding/></failure>
             * per RFC 6120 §6.5.5.
             *   https://datatracker.ietf.org/doc/html/rfc6120#section-13.9.1
             *   https://datatracker.ietf.org/doc/html/rfc6120#section-6.5.5 */
            return -1;
        }

        buf = (buf << 6) | (unsigned int)val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;

            if (out < dst_len) {
                dst[out++] = (unsigned char)((buf >> bits) & 0xFF);
            }
        }
    }

    return out;
}


/* ------------------------------------------------------------------
 * send_raw
 *
 * Writes a null-terminated string to the TCP PCB and flushes it.
 * All XMPP output in this server goes through this function.
 *
 * RFC 6120 §4.1 — The XML stream is a single long-lived document;
 *   stanzas are written sequentially without any TCP-level framing.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-4.1
 * ------------------------------------------------------------------ */
void send_raw(xmpp_client_ctx_t *ctx, const char *data) {
    xmpp_log("SEND", data, strlen(data));

    tcp_write(ctx->pcb, data, strlen(data), TCP_WRITE_FLAG_COPY);

    tcp_output(ctx->pcb);
}


/* ------------------------------------------------------------------
 * handle_roster_request
 *
 * Responds to a roster IQ-get with an empty <query>.
 *
 * RECEIVE:
 *   RFC 6121 §2.1.3 — Roster Get:
 *     <iq type='get'><query xmlns='jabber:iq:roster'/></iq>
 *     Client MAY include a 'ver' attribute for roster versioning.
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-2.1.3
 *   (Session log: <query xmlns="jabber:iq:roster"/>)
 *
 * SEND:
 *   RFC 6121 §2.1.4 — Roster result with zero or more <item/> children.
 *     An empty <query/> is valid and is what we return.
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-2.1.4
 *   (Session log: "add ver attribute" — noted below)
 *
 * ROSTER VERSIONING — RFC 6121 §2.6:
 *   If the client included 'ver' in the get request, we include 'ver="0"'
 *   in the result (static token; we have no persistent store to compute a
 *   real version from).  Implemented via the has_ver check below.
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-2.6
 *
 * ROSTER SET / PUSH — RFC 6121 §2.1.5 / §2.1.6:
 *   IQ-set (type='set') is acknowledged with an empty IQ result and the
 *   change is pushed to all other active resources of the same account.
 *   Implemented in the stanza->type == XMPP_IQ_SET branch below.
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-2.1.5
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-2.1.6
 * ------------------------------------------------------------------ */
void handle_roster_request(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[512];

    /* ------------------------------------------------------------------
     * RFC 6121 §2.1.5 — Roster Set: client adds/updates/removes a contact.
     * We have no persistent roster store, so we acknowledge the set and
     * push the change to any other resources of the same user that are
     * currently connected.
     *   https://datatracker.ietf.org/doc/html/rfc6121#section-2.1.5
     * RFC 6121 §2.1.6 — Roster Push: after a successful set, server MUST
     * send an IQ-set roster push to all active resources of the account.
     *   https://datatracker.ietf.org/doc/html/rfc6121#section-2.1.6
     * ------------------------------------------------------------------ */
    if (stanza->type == XMPP_IQ_SET) {
        /* RFC 6121 §2.1.5 — persist the new/updated/removed roster items.
         * roster_store_set_from_payload() scans the <query> payload for
         * every <item/> element and calls roster_store_upsert_item() for
         * each one.  An item with subscription='remove' is deleted.
         *   https://datatracker.ietf.org/doc/html/rfc6121#section-2.1.5 */
        roster_store_set_from_payload(ctx->username, stanza->payload);

        /* Acknowledge the set — RFC 6121 §2.1.5 result is an empty IQ */
        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s'/>",
            stanza->id, ctx->full_jid);

        send_raw(ctx, response);

        /* Roster push to other connected resources of the same user.
         * RFC 6121 §2.1.6 — server MUST push to all active resources.
         * We identify "same user" by matching ctx->username.
         *
         * FIX Bug 8 — the push[768] buffer contained a literal "%%s"
         * which was intended as a two-pass template:
         *   snprintf(push, …, "… to='%%s' …", payload)   → "… to='%s' …"
         *   snprintf(msg, …, push, full_jid)              → "… to='jid' …"
         * The buffer was allocated and formatted but its value was never
         * used; push_with_to was built independently via its own snprintf.
         * Worse, if the template had accidentally been passed as a format
         * string, the embedded %s would have caused undefined behaviour.
         * The push[] buffer and its snprintf call are now deleted entirely;
         * push_with_to is the only variable and is built directly below. */
        for (int i = 0; i < MAX_USERS; i++) {
            if (client_registry[i].pcb == NULL){ 
                continue;
            }

            if (client_registry[i].state < STATE_SESSION) {
                continue;
            }

            if (&client_registry[i] == ctx) {
                continue; /* skip sender */
            }

            if (strcmp(client_registry[i].username, ctx->username) != 0) {
                continue;
            }

            /* This is another resource of the same account */
            char push_with_to[768];

            snprintf(push_with_to, sizeof(push_with_to),
                "<iq type='set' to='%s'>"
                  "<query xmlns='jabber:iq:roster'>%s</query>"
                "</iq>",
                client_registry[i].full_jid, stanza->payload);

            send_raw(&client_registry[i], push_with_to);
        }

        return;
    }

    /* ------------------------------------------------------------------
     * RFC 6121 §2.1.3 / §2.1.4 — Roster Get: return stored roster.
     *
     * roster_store_get_items() retrieves all <item/> elements previously
     * submitted by this user via IQ-set and stored in roster_store[].
     * If no items exist the query body is empty (valid per RFC 6121 §2.1.4).
     *
     * RFC 6121 §2.6 — Roster Versioning: include ver= in result when the
     * client sent a 'ver' attribute in its get request.  We return a static
     * ver="0" token; computing a real version hash requires a persistent
     * generation counter which we add as future work.
     *   https://datatracker.ietf.org/doc/html/rfc6121#section-2.6
     * ------------------------------------------------------------------ */
    int has_ver = (strstr(stanza->payload, "ver=") != NULL || strstr(stanza->payload, "ver ") != NULL);

    /* Build the roster items XML.
     * Buffer ceiling: MAX_ROSTER_ENTRIES / MAX_USERS × ROSTER_ITEM_MAX_LEN
     *   ≈ 8 × 256 = 2048 bytes per user → 2048-byte buffer is correct. */
    char roster_items[2048] = {0};

    roster_store_get_items(ctx->username, roster_items, sizeof(roster_items));

    /* Outer IQ response buffer.
     * IQ wrapper  ≈ 100 chars + id(64) + to(64) + roster_items(≤2048)
     * → 2300-byte buffer is safe.                                       */
    char big_response[2300];

    if (has_ver) {
        /* RFC 6121 §2.6 — include ver= in result */
        snprintf(big_response, sizeof(big_response),
            "<iq type='result' id='%s' to='%s'>"
              "<query xmlns='jabber:iq:roster' ver='0'>%s</query>"
            "</iq>",
            stanza->id, ctx->full_jid, roster_items);
    }
    else {
        /* RFC 6121 §2.1.4 — roster result */
        snprintf(big_response, sizeof(big_response),
            "<iq type='result' id='%s' to='%s'>"
              "<query xmlns='jabber:iq:roster'>%s</query>"
            "</iq>",
            stanza->id, ctx->full_jid, roster_items);
    }

    send_raw(ctx, big_response);
}


/* ------------------------------------------------------------------
 * handle_initial_presence
 *
 * Sends a presence stanza back to the client to confirm availability.
 *
 * RECEIVE:
 *   RFC 6121 §4.2 — Initial presence: after session establishment
 *   the client sends a bare <presence/> (no 'type' attribute).
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-4.2
 *
 * SEND:
 *   RFC 6121 §4.2.2 — server MUST broadcast the user's presence to all
 *   contacts that have subscription type 'from' or 'both'.
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-4.2.2
 *   (Session log: "also make sure to broadcast")
 *   Presence is now broadcast to all active entries in client_registry[]
 *   (state >= STATE_SESSION, pcb != NULL) — see the loop below.
 *
 *   <show>chat</show>:
 *   RFC 6121 §4.7.2.1 — 'chat' means "actively interested in chatting."
 *   Valid values: away | chat | dnd | xa.
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-4.7.2.1
 *
 *   <priority>1</priority>:
 *   RFC 6121 §4.7.2.3 — integer −128 to +127; negative means this
 *   resource SHOULD NOT receive messages addressed to the bare JID.
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-4.7.2.3
 *
 * Entity capabilities (XEP-0115):
 *   Clients include <c xmlns='http://jabber.org/protocol/caps' hash='sha-1'
 *   node='...' ver='...'/> in their presence stanzas.  We store the
 *   <c> element as opaque data for now; disco#info queries addressed to
 *   a user JID with a node= parameter are forwarded to that user's
 *   TCP connection by handle_disco_info() (implemented there).
 *   https://xmpp.org/extensions/xep-0115.html
 *
 * Pending subscription delivery (RFC 6121 §4.3):
 *   Any subscription stanzas that could not be delivered while this user
 *   was offline are stored in pending_subs[] by handle_broadcast_presence()
 *   and drained by pending_sub_drain() at the end of this function.
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-4.3
 *
 * Presence probing (Fix §5):
 *   RFC 6121 §4.3.1 — after broadcasting initial presence the server
 *   SHOULD send a <presence type='probe'> to each contact so that it
 *   triggers a presence update back to the newly-available user.
 *   We probe all connected users since we have no subscription store
 *   and treat all peers as implicitly subscribed (type='both').
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-4.3.1
 * ------------------------------------------------------------------ */
void handle_initial_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[512];

    /* RFC 6121 §4.2.2 — broadcast the user's available presence to every
     * connected client that has completed session establishment.
     *
     * We treat all fully-connected peers as implicitly subscribed with
     * type='both' for this embedded server (no persistent roster store).
     * The sender's own slot is included so they receive self-presence
     * confirmation per RFC 6121 §4.2.
     *
     * Slots with pcb == NULL or state < STATE_SESSION are skipped:
     *   - NULL pcb  → slot never used or already cleaned up.
     *   - pre-SESSION state → SASL/bind still in progress; delivering
     *     presence before the stream is ready would violate RFC 6120 §4. */
    for (int i = 0; i < MAX_USERS; i++) {
        if (client_registry[i].pcb == NULL) {
            continue;
        }
        if (client_registry[i].state < STATE_SESSION) {
            continue;
        }

        snprintf(response, sizeof(response),
            "<presence from='%s' to='%s' xml:lang='en'>"
              "<show>chat</show>"
              "<priority>1</priority>"
            "</presence>",
            ctx->full_jid, client_registry[i].full_jid);

        send_raw(&client_registry[i], response);
    }

    /* ------------------------------------------------------------------
     * Fix (§5): RFC 6121 §4.3.1 — presence probing.
     *
     * After advertising our own availability, send a presence probe to
     * every other fully-connected user.  A probe causes each peer to
     * re-send its current presence to us, ensuring we immediately get
     * up-to-date status for all contacts rather than waiting for their
     * next voluntary presence update.
     *
     * Probe format: RFC 6121 §4.3.1
     *   <presence type='probe' from='bare-sender-jid' to='bare-target-jid'/>
     *
     * We skip our own slot (no point probing ourselves) and any slot
     * that has not completed session establishment.
     *
     * Since we have no subscription store, we probe everyone (implicitly
     * treating all peers as subscribed with type='both' or 'from').
     *
     *   RFC 6121 §4.3.1  https://datatracker.ietf.org/doc/html/rfc6121#section-4.3.1
     * ------------------------------------------------------------------ */
    /* Build bare sender JID once (RFC 6120 §2.1 — bare = localpart@domain) */
    char bare_from[64] = {0};

    strncpy(bare_from, ctx->full_jid, sizeof(bare_from) - 1);

    char *from_slash = strchr(bare_from, '/');

    if (from_slash) {
        *from_slash = '\0';
    }

    for (int i = 0; i < MAX_USERS; i++) {
        if (client_registry[i].pcb  == NULL) {
            continue;
        }

        if (client_registry[i].state < STATE_SESSION) {
            continue;
        }

        if (&client_registry[i]     == ctx) {
            continue; /* skip self */
        }

        /* Build bare target JID */
        char bare_to[64] = {0};

        strncpy(bare_to, client_registry[i].full_jid, sizeof(bare_to) - 1);

        char *to_slash = strchr(bare_to, '/');
        
        if (to_slash) {
            *to_slash = '\0';
        }

        snprintf(response, sizeof(response),
            "<presence type='probe' from='%s' to='%s'/>",
            bare_from, bare_to);

        /* Deliver the probe directly to the peer's TCP connection.
         * The peer's client will respond with its current presence,
         * which routes through handle_broadcast_presence() back to us. */
        send_raw(&client_registry[i], response);
    }

    /* RFC 6121 §4.3 — drain any subscription stanzas that were queued
     * while this user was offline.  pending_sub_drain() iterates
     * pending_subs[] and delivers all entries matching ctx->username,
     * then marks them inactive so they are not delivered again. */
    pending_sub_drain(ctx);

    /* XEP-0160 §2 step 4 — deliver any messages that were stored while
     * this user had no available resource.  offline_msg_drain() appends
     * a XEP-0203 <delay/> element to each delivered message so the
     * client can distinguish stored messages from live traffic.
     *   https://xmpp.org/extensions/xep-0160.html
     *   https://xmpp.org/extensions/xep-0203.html */
    offline_msg_drain(ctx);
}


/* ===========================================================================
 * Private XML Storage — XEP-0049
 *
 * Static per-user, per-namespace store.
 *
 * Keyed by (username, namespace). The value is the verbatim inner child
 * element extracted from the <query> body (everything between the closing
 * '>' of <query ...> and the opening '<' of </query>).
 *
 * Types and constants (PRIVATE_STORAGE_SLOTS, PRIVATE_NS_MAX,
 * PRIVATE_XML_MAX, private_store_entry_t) are defined in xmpp_core.h
 * so that xmpp_persist.c can access the array for NV save/load.
 *
 * private_store is non-static so xmpp_persist.c can reference it via
 * the extern declaration in xmpp_core.h.
 * =========================================================================== */

/* File-scope store — zero-initialised at startup; no heap needed.
 * Non-static: xmpp_persist.c saves this to the ATA data disk on each write. */
private_store_entry_t private_store[PRIVATE_STORAGE_SLOTS];


/* ------------------------------------------------------------------
 * private_store_find
 *
 * Returns a pointer to the slot matching (username, ns), or NULL if
 * no such slot exists.  Read-only; does not create new slots.
 * ------------------------------------------------------------------ */
static private_store_entry_t *
private_store_find(const char *username, const char *ns)
{
    for (int i = 0; i < PRIVATE_STORAGE_SLOTS; i++) {
        if (private_store[i].active
            && strncmp(private_store[i].username, username, 32)          == 0
            && strncmp(private_store[i].ns,       ns, PRIVATE_NS_MAX)    == 0) {
            return &private_store[i];
        }
    }
    return NULL;
}


/* ------------------------------------------------------------------
 * private_store_upsert
 *
 * Finds an existing slot for (username, ns) or claims the first free
 * slot.  Writes xml_data (xml_len bytes) into it, NUL-terminated and
 * clamped to PRIVATE_XML_MAX - 1 bytes.
 *
 * Returns 0 on success, -1 if the store is full.
 * ------------------------------------------------------------------ */
static int
private_store_upsert(const char *username, const char *ns,
                     const char *xml_data, size_t xml_len)
{
    private_store_entry_t *slot = private_store_find(username, ns);

    if (!slot) {
        for (int i = 0; i < PRIVATE_STORAGE_SLOTS; i++) {
            if (!private_store[i].active) {
                slot = &private_store[i];
                break;
            }
        }
    }

    if (!slot) {
        return -1; /* store full */
    }

    if (xml_len >= PRIVATE_XML_MAX) {
        xml_len = PRIVATE_XML_MAX - 1;
    }

    strncpy(slot->username, username, sizeof(slot->username) - 1);
    slot->username[sizeof(slot->username) - 1] = '\0';

    strncpy(slot->ns, ns, sizeof(slot->ns) - 1);
    slot->ns[sizeof(slot->ns) - 1] = '\0';

    memcpy(slot->xml, xml_data, xml_len);
    slot->xml[xml_len] = '\0';

    slot->active = 1;
    return 0;
}


/* ------------------------------------------------------------------
 * handle_private_storage
 *
 * Responds to jabber:iq:private get/set requests.
 *
 * RECEIVE:
 *   XEP-0049 §2.1 — Private XML Storage get:
 *     <iq type='get'><query xmlns='jabber:iq:private'>
 *       <storage xmlns='storage:bookmarks'/>
 *     </query></iq>
 *   or:
 *       <storage xmlns='storage:rosternotes'/>
 *   https://xmpp.org/extensions/xep-0049.html
 *   (Session log shows both bookmarks and rosternotes requests arriving
 *    in the same TCP segment)
 *
 * SEND:
 *   XEP-0049 §2.1 / Listing 1 — For type='set': store the child XML
 *   keyed by (ctx->username, inner_ns) and return a plain empty IQ
 *   result with no <query> body.
 *   XEP-0049 §2.1 / Listing 2 — For type='get': return the previously
 *   stored child XML inside <query xmlns='jabber:iq:private'>, or an
 *   empty element of the requested namespace if nothing is stored yet.
 *
 * FIX (HIGH) — inner namespace extraction:
 *   The old implementation called strstr(stanza->payload, "xmlns=")
 *   which matched the first xmlns= in the payload — the one belonging
 *   to <query> itself ('jabber:iq:private') — not the child element.
 *   We now skip past the closing '>' of <query ...> before searching,
 *   so the first xmlns= we find belongs to the child element.
 *
 * FIX (HIGH) — data persistence:
 *   For type='set' the child XML is written into the file-scope
 *   private_store[] array keyed by (ctx->username, inner_ns).
 *   For type='get' the stored XML is retrieved from that array.
 *   No malloc/free is used anywhere in this function.
 *
 * FIX (MEDIUM) — set vs get response body:
 *   For a type='set' request we return a plain empty IQ result
 *   (<iq type='result' id='...' to='...'/>), not a <query> body.
 *   XEP-0049 §2.1 / Listing 1 — server response is a bare <iq result/>.
 *
 * FIX (MEDIUM) — missing child element validation:
 *   XEP-0049 §2.3: "At least one child element with a proper namespace
 *   MUST be included; otherwise the server MUST respond with a
 *   'Not Acceptable' error."  We now enforce this.
 *
 * AUTHORIZATION (XEP-0049 §4):
 *   The store is keyed by ctx->username, which is the authenticated
 *   identity of this TCP connection set during SASL and enforced by
 *   the STATE_SESSION gate in xmpp_route_stanza().  A client cannot
 *   access another user's private data because ctx->username is stamped
 *   by the server, not supplied by the client.  No separate JID
 *   comparison is required.
 *
 * BUFFER SAFETY:
 *   All buffers are fixed-size stack or static allocations whose sizes
 *   are derived from xmpp_core.h.  No malloc/free is used.
 *   snprintf return values are checked; if the response would overflow
 *   its buffer a resource-constraint error is sent instead of
 *   truncated or malformed XML.
 * ------------------------------------------------------------------ */
void handle_private_storage(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza)
{
    /* ----------------------------------------------------------------
     * Step 1 — Extract the inner child element's xmlns= and element name.
     *
     * stanza->payload holds the raw <query> stanza body, e.g.:
     *   <query xmlns='jabber:iq:private'>
     *     <storage xmlns='storage:rosternotes'/>
     *   </query>
     *
     * We skip past the closing '>' of the <query ...> open tag so
     * that the first xmlns= we encounter belongs to the child element,
     * not to <query> itself.
     *
     * We also extract the child element name (e.g. "storage", "exodus")
     * so we can construct an accurate empty-element fallback when no
     * data has been stored for the requested namespace.
     *
     * XEP-0049 §2.3 — at least one namespaced child is required.
     * ---------------------------------------------------------------- */
    char inner_ns[PRIVATE_NS_MAX] = "";
    char child_elem[64]           = "storage"; /* safe default */

    const char *after_query = strchr(stanza->payload, '>');
    if (after_query) {
        after_query++; /* advance past '>' of <query ...> */

        /* Extract child element name: skip whitespace, expect '<',
         * then read until space / '/' / '>'. */
        const char *p = after_query;
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') { p++; }
        if (*p == '<') {
            p++; /* skip '<' */
            const char *name_end = p;
            while (*name_end
                   && *name_end != ' ' && *name_end != '/'
                   && *name_end != '>') {
                name_end++;
            }
            size_t nlen = (size_t)(name_end - p);
            if (nlen > 0 && nlen < sizeof(child_elem) - 1) {
                strncpy(child_elem, p, nlen);
                child_elem[nlen] = '\0';
            }
        }

        /* Extract xmlns= of the child element */
        const char *xmlns_attr = strstr(after_query, "xmlns=");
        if (xmlns_attr) {
            xmlns_attr += 6; /* skip "xmlns=" */
            char quote = *xmlns_attr;
            if (quote == '\'' || quote == '"') {
                xmlns_attr++;
                const char *end = strchr(xmlns_attr, quote);
                if (end) {
                    int ns_len = (int)(end - xmlns_attr);
                    if (ns_len > 0 && ns_len < (int)sizeof(inner_ns) - 1) {
                        strncpy(inner_ns, xmlns_attr, ns_len);
                        inner_ns[ns_len] = '\0';
                    }
                }
            }
        }
    }

    /* ----------------------------------------------------------------
     * Step 2 — Validate: child namespace must be present.
     *
     * XEP-0049 §2.3: "At least one child element with a proper namespace
     * MUST be included; otherwise the server MUST respond with a
     * 'Not Acceptable' error."
     * ---------------------------------------------------------------- */
    if (inner_ns[0] == '\0') {
        char err[512];
        snprintf(err, sizeof(err),
            "<iq type='error' id='%s' to='%s'>"
              "<query xmlns='jabber:iq:private'/>"
              "<error code='406' type='modify'>"
                "<not-acceptable"
                  " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
              "</error>"
            "</iq>",
            stanza->id, ctx->full_jid);
        send_raw(ctx, err);
        return;
    }

    /* ----------------------------------------------------------------
     * Step 3 — Handle type='set': persist the child XML and acknowledge.
     *
     * XEP-0049 §2.1 / Listing 1:
     *   The server stores the child XML and replies with a bare IQ
     *   result containing no <query> body.
     *
     * We extract the inner XML as the substring of stanza->payload
     * that lies between the closing '>' of <query ...> and the opening
     * '<' of </query>.
     * ---------------------------------------------------------------- */
    if (stanza->type == XMPP_IQ_SET) {
        const char *xml_start = strchr(stanza->payload, '>');
        if (xml_start) {
            xml_start++;
            const char *xml_end = strstr(stanza->payload, "</query>");
            if (xml_end && xml_end > xml_start) {
                size_t xml_len = (size_t)(xml_end - xml_start);
                if (private_store_upsert(ctx->username, inner_ns,
                                         xml_start, xml_len) != 0) {
                    /* Store is full — RFC 6120 §4.9.3.17 resource-constraint */
                    /* (no persist call — nothing was written) */
                    char err[512];
                    snprintf(err, sizeof(err),
                        "<iq type='error' id='%s' to='%s'>"
                          "<error type='wait' code='500'>"
                            "<resource-constraint"
                              " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                          "</error>"
                        "</iq>",
                        stanza->id, ctx->full_jid);
                    send_raw(ctx, err);
                    return;
                }

                /* Write-through: commit to ATA data disk immediately */
                xmpp_persist_save_private();
            }
        }

        /* XEP-0049 §2.1 Listing 1 — bare result, no <query> body */
        char response[256];
        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s'/>",
            stanza->id, ctx->full_jid);
        send_raw(ctx, response);
        return;
    }

    /* ----------------------------------------------------------------
     * Step 4 — Handle type='get': retrieve and return stored data.
     *
     * XEP-0049 §2.1 / Listing 2:
     *   Return the stored child XML inside <query xmlns='jabber:iq:private'>,
     *   or an empty element of the requested namespace if nothing is stored.
     *
     * Response buffer ceiling:
     *   IQ + query wrapper  ≈  100 chars
     *   stanza->id          ≤   63 chars  (id[64])
     *   ctx->full_jid       ≤   63 chars  (full_jid[64])
     *   inner_xml           ≤  PRIVATE_XML_MAX (900) chars
     *   Total               ≤ ~1130 chars → 1300-byte buffer is safe.
     * ---------------------------------------------------------------- */
    const char *inner_xml;
    char        empty_elem[PRIVATE_NS_MAX + 64]; /* "<name xmlns='ns'/>" */

    private_store_entry_t *slot =
        private_store_find(ctx->username, inner_ns);

    if (slot != NULL) {
        inner_xml = slot->xml;
    } else {
        /* Nothing stored yet — return an empty element of the requested
         * namespace using the actual child element name from the request,
         * as required by XEP-0049 §2.1. */
        snprintf(empty_elem, sizeof(empty_elem),
            "<%s xmlns='%s'/>", child_elem, inner_ns);
        inner_xml = empty_elem;
    }

    /* Build response and check for overflow before sending */
    char response[1300];
    int written = snprintf(response, sizeof(response),
        "<iq type='result' id='%s' to='%s'>"
          "<query xmlns='jabber:iq:private'>%s</query>"
        "</iq>",
        stanza->id, ctx->full_jid, inner_xml);

    if (written < 0 || (size_t)written >= sizeof(response)) {
        /* Should not occur given PRIVATE_XML_MAX ≤ 900 and the
         * 1300-byte buffer, but guard rather than send truncated XML. */
        char err[512];
        snprintf(err, sizeof(err),
            "<iq type='error' id='%s' to='%s'>"
              "<error type='wait' code='500'>"
                "<resource-constraint"
                  " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
              "</error>"
            "</iq>",
            stanza->id, ctx->full_jid);
        send_raw(ctx, err);
        return;
    }

    send_raw(ctx, response);
}


/* ------------------------------------------------------------------
 * handle_muc_admin
 *
 * Handles MUC admin-use-case IQ queries (affiliation list requests).
 *
 * RECEIVE:
 *   XEP-0045 §9.5 — Modifying the Member List / retrieving affiliation
 *   lists. An owner or admin sends an IQ-get to retrieve all JIDs
 *   with a given affiliation:
 *     <iq type='get' to='room@service'>
 *       <query xmlns='http://jabber.org/protocol/muc#admin'>
 *         <item affiliation='owner'/>
 *       </query>
 *     </iq>
 *   https://xmpp.org/extensions/xep-0045.html#modifymember
 *
 * SEND:
 *   XEP-0045 §9.5 — respond with the list of JIDs holding that
 *   affiliation. We support three affiliation values:
 *     'owner'  — return the room creator via room_t.creator_jid (set at
 *                room creation in handle_muc_presence); falls back to
 *                first active occupant if creator_jid is empty.
 *     'admin'  — return empty list (none assigned).
 *     'member' — return empty list (none assigned).
 *   Unrecognised affiliation → empty result.
 *
 * NOTE — affiliation vs role distinction:
 *   XEP-0045 §5.1 — Affiliation is long-lived (owner/admin/member/
 *   outcast/none); role is per-session (moderator/participant/visitor).
 *   Returning role='moderator' alongside affiliation='owner' is correct
 *   only when the owner is currently in the room.
 *   https://xmpp.org/extensions/xep-0045.html#privil
 *
 * RFC 6120 §8.2.3 — every IQ get/set MUST receive a result or error.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.3
 *
 * AFFILIATION CHANGE (IQ-set) — kick and ban:
 *   XEP-0045 §9.3 — kick (role → none): broadcasts type='unavailable' with
 *     status code 307 to all occupants including the kicked user.
 *   XEP-0045 §9.4 — ban (affiliation → outcast): broadcasts with code 301.
 *   Both are implemented in the stanza->type == XMPP_IQ_SET branch below.
 *   A persistent ban list is not maintained (no stable storage on this
 *   embedded target); a banned user may rejoin immediately.
 *   https://xmpp.org/extensions/xep-0045.html#kick
 *   https://xmpp.org/extensions/xep-0045.html#ban
 * ------------------------------------------------------------------ */
void handle_muc_admin(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];

    /* ------------------------------------------------------------------
     * IQ-set: role/affiliation change (kick or ban).
     *
     * XEP-0045 §9.3 — Kick: moderator sets role='none' for a nick.
     *   Server broadcasts type='unavailable' with status code 307
     *   to all occupants; the kicked user's presence has code 307.
     *   https://xmpp.org/extensions/xep-0045.html#kick
     *
     * XEP-0045 §9.4 — Ban: admin sets affiliation='outcast' for a JID.
     *   Server broadcasts type='unavailable' with status code 301.
     *   https://xmpp.org/extensions/xep-0045.html#ban
     *
     * We locate the target room from stanza->to (room@service), find the
     * occupant by nick or JID, broadcast the removal, and return an empty
     * IQ result.  A persistent ban list is not maintained (no flash/EEPROM
     * storage on this embedded target); the user may rejoin immediately.
     * ------------------------------------------------------------------ */
    if (stanza->type == XMPP_IQ_SET) {
        int want_kick = (strstr(stanza->payload, "role='none'") != NULL || strstr(stanza->payload, "role=\"none\"") != NULL);
        int want_ban = (strstr(stanza->payload, "affiliation='outcast'") != NULL || strstr(stanza->payload, "affiliation=\"outcast\"") != NULL);

        if (want_kick || want_ban) {
            /* Extract the target nick */
            char target_nick[MAX_NICK_LEN] = {0};
            const char *nick_p = strstr(stanza->payload, "nick='");

            if (!nick_p) {
                nick_p = strstr(stanza->payload, "nick=\"");
            }

            if (nick_p) {
                nick_p += 6; /* skip  nick=' */
                char q = *(nick_p - 1);
                const char *end = strchr(nick_p, q);

                if (end) {
                    int nlen = (int)(end - nick_p);

                    if (nlen >= MAX_NICK_LEN) {
                        nlen = MAX_NICK_LEN - 1;
                    }

                    strncpy(target_nick, nick_p, nlen);
                }
            }

            /* Extract optional <reason> text */
            char reason[128] = {0};
            const char *reason_start = strstr(stanza->payload, "<reason>");

            if (reason_start) {
                reason_start += 8; /* skip <reason> */
                const char *reason_end = strstr(reason_start, "</reason>");

                if (reason_end) {
                    int rlen = (int)(reason_end - reason_start);

                    if (rlen >= (int)sizeof(reason)) {
                        rlen = sizeof(reason) - 1;
                    }

                    strncpy(reason, reason_start, rlen);
                }
            }

            /* Locate the room from stanza->to */
            char room_name[MAX_ROOM_NAME_LEN] = {0};
            char *at = strchr(stanza->to, '@');

            if (at) {
                int name_len = (int)(at - stanza->to);

                if (name_len >= MAX_ROOM_NAME_LEN) {
                    name_len = MAX_ROOM_NAME_LEN - 1;
                }

                strncpy(room_name, stanza->to, name_len);
            }

            char bare_jid[64] = {0};

            strncpy(bare_jid, stanza->to, sizeof(bare_jid) - 1);
            /* bare_jid is already room@service from stanza->to */

            int status_code = want_ban ? 301 : 307;
            /* 301 = banned (outcast), 307 = kicked (role change to none)
             * XEP-0045 §9.3 / §9.4 */

            for (int i = 0; i < MAX_ROOMS; i++) {
                if (!rooms[i].active || strcmp(rooms[i].name, room_name) != 0) {
                    continue;
                }

                room_t *r = &rooms[i];

                for (int j = 0; j < MAX_USERS_PER_ROOM; j++) {
                    if (!r->users[j].active) {
                        continue;
                    }

                    if (target_nick[0] != '\0' && strcmp(r->users[j].nick, target_nick) != 0) {
                        continue;
                    }

                    /* Found the target occupant */
                    char kicked_nick[MAX_NICK_LEN];

                    strncpy(kicked_nick, r->users[j].nick, MAX_NICK_LEN - 1);

                    char kicked_jid[64];

                    strncpy(kicked_jid, r->users[j].jid, 63);

                    /* kicked_pcb removed — Bug 2 fix uses find_client_by_jid()
                     * instead of raw PCB copies. */

                    /* FIX Bug 2 — replace dangling PCB pattern in kick/ban broadcast.
                     *
                     * The old code stored kicked_pcb = r->users[j].pcb and built
                     * stack-local xmpp_client_ctx_t structs (target_ctx, kicked_ctx)
                     * from raw pcb copies.  If any of those clients had already
                     * disconnected, the pcb pointer was stale (freed memory).
                     *
                     * Additionally the removal[] buffer used a %%s two-pass template
                     * (same pattern as Bug 12): snprintf embedded %%s → literal %s,
                     * then that was used as a format string in a second snprintf to
                     * insert the recipient JID.  The <reason> field comes from the
                     * admin IQ payload and can contain '%' characters, which would be
                     * interpreted as format specifiers in the second pass.
                     *
                     * Fix: look up each recipient through find_client_by_jid() and
                     * build each stanza with a single direct snprintf per recipient,
                     * inserting the target JID directly. */

                    /* Broadcast removal to all remaining occupants */
                    for (int k = 0; k < MAX_USERS_PER_ROOM; k++) {
                        if (!r->users[k].active || k == j) {
                            continue;
                        }

                        xmpp_client_ctx_t *bcast_target = find_client_by_jid(r->users[k].jid);

                        if (!bcast_target) {
                            continue; /* disconnected — skip */
                        }

                        char msg[512];

                        if (reason[0] != '\0') {
                            snprintf(msg, sizeof(msg),
                                "<presence type='unavailable' from='%s/%s' to='%s'>"
                                  "<x xmlns='http://jabber.org/protocol/muc#user'>"
                                    "<item affiliation='%s' role='none'>"
                                      "<reason>%s</reason>"
                                    "</item>"
                                    "<status code='%d'/>"
                                  "</x>"
                                "</presence>",
                                bare_jid, kicked_nick, r->users[k].jid,
                                want_ban ? "outcast" : "none",
                                reason, status_code);
                        }
                        else {
                            snprintf(msg, sizeof(msg),
                                "<presence type='unavailable' from='%s/%s' to='%s'>"
                                  "<x xmlns='http://jabber.org/protocol/muc#user'>"
                                    "<item affiliation='%s' role='none'/>"
                                    "<status code='%d'/>"
                                  "</x>"
                                "</presence>",
                                bare_jid, kicked_nick, r->users[k].jid,
                                want_ban ? "outcast" : "none",
                                status_code);
                        }

                        send_raw(bcast_target, msg);
                    }

                    /* Send to the kicked/banned user with status code 110 */
                    {
                        xmpp_client_ctx_t *kicked_target = find_client_by_jid(kicked_jid);

                        /* Only send if the kicked user is still connected.
                         * If they already disconnected the removal is moot. */
                        if (kicked_target) {
                            char self_msg[640];

                            if (reason[0] != '\0') {
                                snprintf(self_msg, sizeof(self_msg),
                                    "<presence type='unavailable' from='%s/%s' to='%s'>"
                                      "<x xmlns='http://jabber.org/protocol/muc#user'>"
                                        "<item affiliation='%s' role='none'>"
                                          "<reason>%s</reason>"
                                        "</item>"
                                        "<status code='110'/>"
                                        "<status code='%d'/>"
                                      "</x>"
                                    "</presence>",
                                    bare_jid, kicked_nick, kicked_jid,
                                    want_ban ? "outcast" : "none",
                                    reason, status_code);
                            }
                            else {
                                snprintf(self_msg, sizeof(self_msg),
                                    "<presence type='unavailable' from='%s/%s' to='%s'>"
                                      "<x xmlns='http://jabber.org/protocol/muc#user'>"
                                        "<item affiliation='%s' role='none'/>"
                                        "<status code='110'/>"
                                        "<status code='%d'/>"
                                      "</x>"
                                    "</presence>",
                                    bare_jid, kicked_nick, kicked_jid,
                                    want_ban ? "outcast" : "none",
                                    status_code);
                            }

                            send_raw(kicked_target, self_msg);
                        }
                    }

                    /* Remove from room */
                    memset(&r->users[j], 0, sizeof(participant_t));

                    break;
                }

                break;
            }

            /* Acknowledge the admin action — RFC 6120 §8.2.3 */
            snprintf(response, sizeof(response),
                "<iq type='result' id='%s' to='%s'/>",
                stanza->id, ctx->full_jid);

            send_raw(ctx, response);

            return;
        }

        /* Unrecognised IQ-set — return empty result */
        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s'/>",
            stanza->id, ctx->full_jid);

        send_raw(ctx, response);

        return;
    }

    /* ------------------------------------------------------------------
     * IQ-get: affiliation list queries.
     * XEP-0045 §9.5 — owner/admin/member list.
     * ------------------------------------------------------------------ */
    int want_owner  = (strstr(stanza->payload, "affiliation='owner'")  || strstr(stanza->payload, "affiliation=\"owner\""));
    int want_admin  = (strstr(stanza->payload, "affiliation='admin'")  || strstr(stanza->payload, "affiliation=\"admin\""));
    int want_member = (strstr(stanza->payload, "affiliation='member'") || strstr(stanza->payload, "affiliation=\"member\""));

    if (want_owner) {
        /* XEP-0045 §9.5 — owner list.
         * Use creator_jid stored at room creation time instead of proxying
         * the first active participant (see room_t.creator_jid comment). */
        char owner_jid[64] = {0};
        char *at = strchr(stanza->to, '@');

        if (at) {
            char room_name[MAX_ROOM_NAME_LEN] = {0};
            int name_len = (int)(at - stanza->to);

            if (name_len >= MAX_ROOM_NAME_LEN) {
                name_len = MAX_ROOM_NAME_LEN - 1;
            }

            strncpy(room_name, stanza->to, name_len);

            for (int i = 0; i < MAX_ROOMS; i++) {
                if (rooms[i].active && strcmp(rooms[i].name, room_name) == 0) {
                    if (rooms[i].creator_jid[0] != '\0') {
                        strncpy(owner_jid, rooms[i].creator_jid, 63);
                    }
                    else {
                        /* Fallback: first active occupant */
                        for (int j = 0; j < MAX_USERS_PER_ROOM; j++) {
                            if (rooms[i].users[j].active) {
                                strncpy(owner_jid, rooms[i].users[j].jid, 63);

                                /* Strip resource → bare JID per RFC 6120 §2.1 */
                                char *slash = strchr(owner_jid, '/');

                                if (slash) {
                                    *slash = '\0';
                                }

                                break;
                            }
                        }
                    }

                    break;
                }
            }
        }

        if (owner_jid[0] == '\0') {
            strncpy(owner_jid, ctx->full_jid, 63);
        }

        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s'>"
              "<query xmlns='http://jabber.org/protocol/muc#admin'>"
                "<item affiliation='owner' jid='%s' role='moderator'/>"
              "</query>"
            "</iq>",
            stanza->id, ctx->full_jid, owner_jid);
    }
    else if (want_admin || want_member) {
        /* XEP-0045 §9.5 — empty admin / member list */
        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s'>"
              "<query xmlns='http://jabber.org/protocol/muc#admin'/>"
            "</iq>",
            stanza->id, ctx->full_jid);
    }
    else {
        /* Unrecognised affiliation — RFC 6120 §8.2.3 still requires a reply */
        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s'>"
              "<query xmlns='http://jabber.org/protocol/muc#admin'/>"
            "</iq>",
            stanza->id, ctx->full_jid);
    }

    send_raw(ctx, response);
}


/* ------------------------------------------------------------------
 * handle_general_success
 *
 * Returns an empty IQ result for accepted-but-not-stored namespaces
 * (urn:xmpp:blocking, vcard-temp, unrecognised pubsub, etc.).
 *
 * RFC 6120 §8.2.3 — every IQ get/set MUST be answered with a result
 *   or an error; an empty result signals "acknowledged."
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.3
 *
 * NOTE — pubsub IQs (session log: large OMEMO bundle, axolotl device list):
 *   The session log shows Gajim sending XEP-0060 pubsub IQs
 *   (subscribe, publish, items) for XEP-0384 OMEMO key bundles.
 *   These currently hit the IQ fallback in xmpp_router.c and receive a
 *   <service-unavailable/> error — which is the correct response for an
 *   unsupported service. If OMEMO support is ever needed:
 *   XEP-0384 — OMEMO Encryption: https://xmpp.org/extensions/xep-0384.html
 *   XEP-0060 — Publish-Subscribe: https://xmpp.org/extensions/xep-0060.html
 * ------------------------------------------------------------------ */
void handle_general_success(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[512];

    snprintf(response, sizeof(response),
        "<iq type='result' id='%s' to='%s'/>",
        stanza->id, ctx->full_jid);

    send_raw(ctx, response);
}


/* ------------------------------------------------------------------
 * handle_core_bind
 *
 * Assigns a full JID to the authenticated client (resource binding).
 *
 * RECEIVE:
 *   RFC 6120 §7.6 — Resource Binding IQ-set:
 *     <iq type='set' id='...'><bind xmlns='...xmpp-bind'>
 *       <resource>gajim.ZIVE20OA</resource>
 *     </bind></iq>
 *     <resource> is OPTIONAL; the client may omit it.
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-7.6
 *   (Session log: "resource could be omitted by the client"
 *    — https://datatracker.ietf.org/doc/html/rfc6120#section-7.7.1)
 *
 * SEND:
 *   RFC 6120 §7.7 — Bind result MUST include the assigned full JID:
 *     <iq type='result' id='...'><bind xmlns='...xmpp-bind'>
 *       <jid>user@domain/resource</jid>
 *     </bind></iq>
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-7.7
 *   RFC 6120 §7.7.1 — Server MAY ignore client's preferred resource
 *     and generate its own. We always do this ("Unikernel-{rand}").
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-7.7.1
 *
 * RFC 6120 §8.2.3 — IQ exchange: set → result (or error).
 *   (Session log: "§8.2.3 shows exact iq exchange steps")
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.3
 *
 * RFC 6120 §4.7.3 — IDs must be hard to predict; secure_random_u32()
 *   satisfies this via hw_trng_read() or xorshift64* fallback.
 *
 * State transition:
 *   Move to STATE_SESSION. RFC 6120 §7 does not define a post-bind
 *   sub-state; session IQ (RFC 6121 §3.1) may optionally follow.
 * ------------------------------------------------------------------ */
void handle_core_bind(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    /* RFC 6120 §7.7.1 — server-generated resource.
     * secure_random_u32() provides hardware entropy (or a CSPRNG
     * fallback); modulo 9999 keeps the resource short and readable.
     * See libc_glue.c and RFC 6120 §4.7.3 for the rationale. */
    unsigned int resource_id = secure_random_u32() % 9999;

    /* RFC 6120 §2.1 — full JID = localpart@domainpart/resourcepart */
    snprintf(ctx->full_jid, sizeof(ctx->full_jid), "%s@%s/Unikernel-%d", ctx->username, XMPP_DOMAIN, resource_id);

    /* Evict any stale slot holding the same bare JID */
    for (int i = 0; i < MAX_USERS; i++) {
        if (&client_registry[i] == ctx) {
            continue;
        }

        if (client_registry[i].pcb == NULL) {
            continue;
        }

        if (strcmp(client_registry[i].username, ctx->username) == 0) {
            /* FIX Bug 7 — PCB leak in eviction path.
             *
             * Previously memset() zeroed the slot without first calling
             * tcp_close() on the old PCB.  lwIP retains ownership of that
             * PCB and its send/receive buffers until tcp_close() is called;
             * silently dropping the pointer leaks the PCB permanently for
             * the lifetime of the server.
             *
             * RFC 6120 §4.4 — either party MAY close the TCP connection
             * after </stream:stream> is exchanged, but the server is
             * permitted to close it unilaterally when a resource-conflict
             * eviction occurs (§4.9.3.14 policy-violation or §4.9.3.15
             * resource-constraint are both appropriate; we close silently
             * here for simplicity on this embedded server).
             *   https://datatracker.ietf.org/doc/html/rfc6120#section-4.4 */
            tcp_close(client_registry[i].pcb);   /* Bug 7 fix: close before zeroing */
            memset(&client_registry[i], 0, sizeof(xmpp_client_ctx_t));
        }
    }

    char response[512];

    /* RFC 6120 §7.7 — bind result containing the full JID */
    snprintf(response, sizeof(response),
        "<iq type='result' id='%s'>"
          "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
            "<jid>%s</jid>"
          "</bind>"
        "</iq>",
        stanza->id, ctx->full_jid);

    send_raw(ctx, response);

    ctx->state = STATE_SESSION;
}


/* ------------------------------------------------------------------
 * handle_core_session
 *
 * Responds to the optional legacy session-establishment IQ.
 *
 * RECEIVE:
 *   RFC 6121 §3.1 — Session Establishment (optional/legacy):
 *     <iq type='set' id='...'><session xmlns='...xmpp-session'/></iq>
 *     Clients following pre-RFC 6121 practice still send this.
 *     Server MUST reply if it advertised the <session> feature.
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-3.1
 *   (Session log: "maybe exclude session, there was none of it in the
 *    example" — keeping it for Gajim compatibility is correct)
 *
 * SEND:
 *   RFC 6121 §3.1 — plain empty IQ result:
 *     <iq type='result' id='...'/>
 *
 * State transition:
 *   Move to STATE_READY; all normal stanza exchange can now proceed.
 * ------------------------------------------------------------------ */
void handle_core_session(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[256];

    /* RFC 6121 §3.1 — session result */
    snprintf(response, sizeof(response), "<iq type='result' id='%s'/>", stanza->id);

    send_raw(ctx, response);

    ctx->state = STATE_READY;
}


/* ------------------------------------------------------------------
 * handle_muc_owner
 *
 * Handles room owner use cases: config form request and form submit.
 *
 * RECEIVE (IQ-get):
 *   XEP-0045 §10.2 — Owner requests the room configuration form:
 *     <iq type='get' to='room@service'>
 *       <query xmlns='http://jabber.org/protocol/muc#owner'/>
 *     </iq>
 *     https://xmpp.org/extensions/xep-0045.html#roomconfig
 *   (Session log shows this exact exchange)
 *
 * SEND (IQ-get response):
 *   XEP-0045 §10.2 — return a Data Forms (XEP-0004) configuration form.
 *   XEP-0004 §3.2  — type='form' means "here is a form to fill out."
 *   The FORM_TYPE hidden field (value=muc#roomconfig) is required by
 *   XEP-0045 §10.2.  Real room config fields (muc_roomname, muc_roomdesc,
 *   muc_persistent, muc_publicroom, muc_moderated, muc_membersonly,
 *   muc_allowinvites, muc_whois) are now included and reflect current room
 *   state.  See the IQ-get response path below for the implementation.
 *   https://xmpp.org/extensions/xep-0045.html#roomconfig
 *   https://xmpp.org/extensions/xep-0004.html
 *
 * RECEIVE (IQ-set, config submit):
 *   XEP-0045 §10.2 — owner submits the filled-in form:
 *     <iq type='set'><query><x type='submit'>…</x></query></iq>
 *   Submitting an empty form (only FORM_TYPE field) is "instant room"
 *   creation per XEP-0045 §10.1.2.
 *   https://xmpp.org/extensions/xep-0045.html#createroom-instant
 *   (Session log shows exactly this flow)
 *
 * SEND (IQ-set response):
 *   XEP-0045 §10.2 — acknowledge with an empty IQ result.
 *
 * NOTE — locked room (XEP-0045 §10.1):
 *   A newly created room is placed in the locked state immediately after
 *   the creator joins (handle_muc_presence sets room_t.locked = 1).
 *   The room is unlocked here — in handle_muc_owner — when the owner
 *   submits the configuration form (§10.1.3) or an instant-room IQ-set
 *   (§10.1.2).  Until then, any non-creator join attempt is rejected with
 *   <item-not-found/> (code 404) by the locked-room gate in
 *   handle_muc_presence().
 *   https://xmpp.org/extensions/xep-0045.html#createroom
 * ------------------------------------------------------------------ */
void handle_muc_owner(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];

    if (stanza->type == XMPP_IQ_SET || strstr(stanza->payload, "type='submit'") || strstr(stanza->payload, "type=\"submit\"")) {
        /* XEP-0045 §10.2 / §10.1.2 — instant room config accepted.
         *
         * Unlock the room: find it by the localpart of stanza->to, then
         * clear the locked flag so other users may now enter.
         *
         * XEP-0045 §10.1.2 — instant room (empty form submit):
         *   https://xmpp.org/extensions/xep-0045.html#createroom-instant
         * XEP-0045 §10.1.3 — reserved room (filled form submit):
         *   https://xmpp.org/extensions/xep-0045.html#createroom-reserved */
        char room_name[MAX_ROOM_NAME_LEN] = {0};
        char *at = strchr(stanza->to, '@');

        if (at) {
            int name_len = (int)(at - stanza->to);

            if (name_len >= MAX_ROOM_NAME_LEN) {
                name_len = MAX_ROOM_NAME_LEN - 1;
            }

            strncpy(room_name, stanza->to, name_len);
        }

        for (int i = 0; i < MAX_ROOMS; i++) {
            if (rooms[i].active && strcmp(rooms[i].name, room_name) == 0) {
                rooms[i].locked = 0; /* XEP-0045 §10.1 — unlock */

                /* Persist the updated lock state. */
                xmpp_persist_save_rooms();

                break;
            }
        }

        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s' from='%s'/>",
            stanza->id, ctx->full_jid, stanza->to);

        send_raw(ctx, response);
    }
    else {
        /* XEP-0045 §10.2 — return room configuration Data Form.
         * XEP-0004 §3.2  — type='form'.
         *
         * The FORM_TYPE hidden field (value = muc#roomconfig) is REQUIRED
         * by XEP-0045 §10.2 so that clients can identify this as a room
         * configuration form.
         *
         * We look up the current room state from rooms[] so that the form
         * reflects actual (not default) values for a room that may have
         * been partially configured before.  If the room is not found
         * (e.g. the query was sent to an incorrect JID) we fall back to
         * safe defaults.
         *
         * Fields included (XEP-0045 §10.2 — muc#roomconfig namespace):
         *   muc#roomconfig_roomname   — human-readable room name
         *   muc#roomconfig_roomdesc   — short description shown in disco
         *   muc#roomconfig_persistent — room survives when last occupant leaves
         *   muc#roomconfig_publicroom — room is listed in disco#items
         *   muc#roomconfig_moderated  — visitors need moderator voice to speak
         *   muc#roomconfig_membersonly — only members may enter
         *   muc#roomconfig_allowinvites — occupants may invite others
         *   muc#roomconfig_whois      — anonymity: moderators or anyone
         *
         * References:
         *   XEP-0045 §10.2  https://xmpp.org/extensions/xep-0045.html#roomconfig
         *   XEP-0004 §3.2   https://xmpp.org/extensions/xep-0004.html
         *   XEP-0045 registrar  https://xmpp.org/registrar/mucstates.html */

        /* Look up the room so we can echo actual current values */
        char room_name_lkp[MAX_ROOM_NAME_LEN] = {0};
        char *at_ptr = strchr(stanza->to, '@');

        if (at_ptr) {
            int nl = (int)(at_ptr - stanza->to);

            if (nl >= MAX_ROOM_NAME_LEN) {
                nl = MAX_ROOM_NAME_LEN - 1;
            }

            strncpy(room_name_lkp, stanza->to, nl);
        }

        /* Defaults — used when room is not found */
        const char *room_label = room_name_lkp[0] ? room_name_lkp : "Unnamed Room";
        int is_persistent = 0; /* rooms are volatile by default */
        int is_public = 1;
        int is_moderated = 0;
        int is_members_only = 0;
        int allow_invites = 1;
        int semi_anon = 1; /* moderators only see real JIDs */

        for (int i = 0; i < MAX_ROOMS; i++) {
            if (rooms[i].active && strcmp(rooms[i].name, room_name_lkp) == 0) {
                /* reflect current room state */
                semi_anon = rooms[i].semi_anon;

                break;
            }
        }

        /* Build the response in a 2048-byte buffer — the form is larger than
         * the 1024-byte buffer used elsewhere in this handler. */
        char big_response[2048];

        snprintf(big_response, sizeof(big_response),
            "<iq type='result' id='%s' to='%s' from='%s'>"
              "<query xmlns='http://jabber.org/protocol/muc#owner'>"
                "<x xmlns='jabber:x:data' type='form'>"
                  /* REQUIRED FORM_TYPE hidden field — XEP-0045 §10.2 */
                  "<field type='hidden' var='FORM_TYPE'>"
                    "<value>http://jabber.org/protocol/muc#roomconfig</value>"
                  "</field>"
                  /* Room name — XEP-0045 §10.2.1 */
                  "<field type='text-single'"
                         " var='muc#roomconfig_roomname'"
                         " label='Room Name'>"
                    "<value>%s</value>"
                  "</field>"
                  /* Room description — XEP-0045 §10.2.1 */
                  "<field type='text-single'"
                         " var='muc#roomconfig_roomdesc'"
                         " label='Short Description of Room'>"
                    "<value></value>"
                  "</field>"
                  /* Persistent room — XEP-0045 §10.2.3 */
                  "<field type='boolean'"
                         " var='muc#roomconfig_persistentroom'"
                         " label='Make Room Persistent'>"
                    "<value>%d</value>"
                  "</field>"
                  /* Public room (listed in disco) — XEP-0045 §10.2.3 */
                  "<field type='boolean'"
                         " var='muc#roomconfig_publicroom'"
                         " label='Make Room Publicly Listed'>"
                    "<value>%d</value>"
                  "</field>"
                  /* Moderated room — XEP-0045 §10.2.3 */
                  "<field type='boolean'"
                         " var='muc#roomconfig_moderatedroom'"
                         " label='Enable Moderation'>"
                    "<value>%d</value>"
                  "</field>"
                  /* Members-only room — XEP-0045 §10.2.3 */
                  "<field type='boolean'"
                         " var='muc#roomconfig_membersonly'"
                         " label='Make Room Members-Only'>"
                    "<value>%d</value>"
                  "</field>"
                  /* Allow occupant invites — XEP-0045 §10.2.3 */
                  "<field type='boolean'"
                         " var='muc#roomconfig_allowinvites'"
                         " label='Allow Occupants to Invite Others'>"
                    "<value>%d</value>"
                  "</field>"
                  /* Who may discover real JIDs — XEP-0045 §10.2.3
                   * 'moderators' = semi-anonymous (semi_anon == 1)
                   * 'anyone'     = non-anonymous   (semi_anon == 0) */
                  "<field type='list-single'"
                         " var='muc#roomconfig_whois'"
                         " label='Who Can See Occupant Real JIDs'>"
                    "<value>%s</value>"
                    "<option label='Moderators Only'>"
                      "<value>moderators</value>"
                    "</option>"
                    "<option label='Anyone'>"
                      "<value>anyone</value>"
                    "</option>"
                  "</field>"
                "</x>"
              "</query>"
            "</iq>",
            stanza->id, ctx->full_jid, stanza->to,
            room_label,
            is_persistent,
            is_public,
            is_moderated,
            is_members_only,
            allow_invites,
            semi_anon ? "moderators" : "anyone");

        send_raw(ctx, big_response);

        return;
    }
}


/* ------------------------------------------------------------------
 * handle_disco_info
 *
 * Responds to Service Discovery info (disco#info) queries.
 * Dispatches to one of three response paths based on the 'to' JID.
 *
 * RECEIVE:
 *   XEP-0030 §3.1 — disco#info request:
 *     <iq type='get' to='target'><query xmlns='...disco#info'/></iq>
 *   https://xmpp.org/extensions/xep-0030.html#info
 *   (Session log: "for the correct exchange of iq"
 *    — https://xmpp.org/extensions/xep-0045.html#entity)
 *
 * CASE 1 — specific room (to='room@conference.angelic.local'):
 *   XEP-0045 §6.4 — Discovering Room Information.
 *   If room exists:
 *     <identity category='conference' type='text' name='roomname'/>
 *     <feature var='http://jabber.org/protocol/muc'/>
 *   If room does not exist:
 *     <error type='cancel'><item-not-found/></error>
 *     RFC 6120 §8.3.3.7 — <item-not-found/> stanza error condition.
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-8.3.3.7
 *   https://xmpp.org/extensions/xep-0045.html#disco-roominfo
 *   Room feature elements (muc_semianonymous / muc_nonanonymous) are
 *   now included to reflect the room's actual anonymity configuration.
 *
 * CASE 2 — MUC service (to='conference.angelic.local'):
 *   XEP-0045 §6.2 — Discovering Features of a MUC Service.
 *     <identity category='conference' type='text' name='Chat Service'/>
 *     <feature var='http://jabber.org/protocol/muc'/>
 *   https://xmpp.org/extensions/xep-0045.html#disco-service
 *
 * CASE 3 — main server or user JID fallback:
 *   XEP-0030 §4 — server or account identity.
 *   FIX (§3 LOW): when to='user@angelic.local' (a user's bare JID),
 *   we now return identity category='account' type='registered' instead
 *   of category='server' type='im', which is only correct when queried
 *   on the bare server domain.
 *   (Session log shows commented-out correct response:
 *    "<identity category='account' type='registered'/>")
 * ------------------------------------------------------------------ */
void handle_disco_info(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];

    char *at = strchr(stanza->to, '@');

    if (at && strstr(stanza->to, "conference.angelic.local")) {
        /* CASE 1: specific room — XEP-0045 §6.4 */
        int room_len = at - stanza->to;
        char room_name[MAX_ROOM_NAME_LEN] = {0};

        if (room_len < (int)sizeof(room_name)) {
            strncpy(room_name, stanza->to, room_len);
        }

        int room_exists = 0;

        for (int i = 0; i < MAX_ROOMS; i++) {
            if (rooms[i].active && strcmp(rooms[i].name, room_name) == 0) {
                room_exists = 1;

                break;
            }
        }

        if (room_exists) {
            /* XEP-0045 §6.4 — room info response.
             *
             * We now reflect the room's actual configuration via
             * <feature> elements so that clients can discover room
             * capabilities without requesting the config form (XEP-0045
             * §10.2).  The feature var strings are defined in the XMPP
             * registrar for muc room features:
             *   https://xmpp.org/registrar/mucstates.html
             *
             * Features always present for all rooms:
             *   http://jabber.org/protocol/muc  — base MUC support
             *
             * Features derived from current room_t state:
             *   muc_nonanonymous  — real JIDs visible to all (semi_anon==0)
             *   muc_semianonymous — real JIDs visible only to mods (semi_anon==1)
             *
             * Future config fields (persistent, open, moderated, membersonly)
             * would be reflected here once the config form submission
             * (handle_muc_owner) stores them in room_t.
             *
             * XEP-0045 §6.4  https://xmpp.org/extensions/xep-0045.html#disco-roominfo
             * XEP-0045 §10.2 https://xmpp.org/extensions/xep-0045.html#roomconfig */

            /* Look up the room to get its current state */
            int room_semi_anon = 1; /* default: semi-anonymous */

            for (int i = 0; i < MAX_ROOMS; i++) {
                if (rooms[i].active && strcmp(rooms[i].name, room_name) == 0) {
                    room_semi_anon = rooms[i].semi_anon;

                    break;
                }
            }

            /* Select the correct anonymity feature var */
            const char *anon_feature = room_semi_anon
                ? "<feature var='muc_semianonymous'/>"
                : "<feature var='muc_nonanonymous'/>";

            char room_info[1024];
            snprintf(room_info, sizeof(room_info),
                "<iq type='result' from='%s' to='%s' id='%s'>"
                  "<query xmlns='http://jabber.org/protocol/disco#info'>"
                    "<identity category='conference' type='text' name='%s'/>"
                    "<feature var='http://jabber.org/protocol/muc'/>"
                    "%s"
                  "</query>"
                "</iq>",
                stanza->to, ctx->full_jid, stanza->id,
                room_name, anon_feature);

            send_raw(ctx, room_info);
            
            return;
        }
        else {
            /* RFC 6120 §8.3.3.7 — item-not-found */
            snprintf(response, sizeof(response),
                "<iq type='error' from='%s' to='%s' id='%s'>"
                  "<error type='cancel'>"
                    "<item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                  "</error>"
                "</iq>",
                stanza->to, ctx->full_jid, stanza->id);
        }
    }
    else if (strcmp(stanza->to, "conference.angelic.local") == 0) {
        /* CASE 2: MUC service — XEP-0045 §6.2 */
        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
              "<query xmlns='http://jabber.org/protocol/disco#info'>"
                "<identity category='conference' type='text' name='Chat Service'/>"
                "<feature var='http://jabber.org/protocol/muc'/>"
              "</query>"
            "</iq>",
            stanza->to, ctx->full_jid, stanza->id);
    }
    else if (at && !strstr(stanza->to, "conference")) {
        /* CASE 3a: user JID (has '@' but not conference subdomain).
         *
         * XEP-0115 §4 — Entity Capabilities verification:
         *   Clients send disco#info to a peer's full JID with a node=
         *   parameter (e.g. node='https://gajim.org#ver') to verify the
         *   capabilities hash they saw in a <c/> presence element.
         *   We forward such queries directly to the addressed user's TCP
         *   connection; that client replies from its own XMPP stack and
         *   the reply reaches the original requester via the network.
         *   If the target has no active session we respond with
         *   <service-unavailable/> (RFC 6120 §8.3.3.19).
         *   https://xmpp.org/extensions/xep-0115.html
         *
         * FIX (§3 LOW): Return category='account' type='registered'
         * per XEP-0030 §4; server identity only correct on bare domain. */

        /* XEP-0115: if the query carries a node= attribute it is a
         * capabilities verification request directed at a specific user. */
        if (strstr(stanza->payload, "node=") != NULL) {
            /* Forward the whole IQ stanza verbatim to the addressed user.
             * Match on bare JID so any resource of that user receives it. */
            char bare_target_caps[64] = {0};
            
            strncpy(bare_target_caps, stanza->to, sizeof(bare_target_caps) - 1);
            
            char *caps_slash = strchr(bare_target_caps, '/');
            
            if (caps_slash) {
                *caps_slash = '\0';
            }

            int forwarded = 0;
            
            for (int i = 0; i < MAX_USERS; i++) {
                if (client_registry[i].pcb == NULL) {
                    continue;
                }

                if (client_registry[i].state < STATE_SESSION) {
                    continue;
                }

                char bare_reg[64] = {0};
                
                strncpy(bare_reg, client_registry[i].full_jid, sizeof(bare_reg) - 1);
                
                char *reg_sl = strchr(bare_reg, '/');
                
                if (reg_sl) {
                    *reg_sl = '\0';
                }

                if (strcmp(bare_target_caps, bare_reg) == 0) {
                    /* Re-address the IQ to the actual full JID and forward */
                    char fwd[1024];

                    snprintf(fwd, sizeof(fwd),
                        "<iq type='get' from='%s' to='%s' id='%s'>"
                          "<query xmlns='http://jabber.org/protocol/disco#info'"
                                 " %s/>"
                        "</iq>",
                        ctx->full_jid, client_registry[i].full_jid, stanza->id,
                        stanza->payload[0] == '<' ? "" : stanza->payload);

                    send_raw(&client_registry[i], fwd);

                    forwarded = 1;

                    break;
                }
            }

            if (!forwarded) {
                /* Target not online — service-unavailable (RFC 6120 §8.3.3.19) */
                snprintf(response, sizeof(response),
                    "<iq type='error' from='%s' to='%s' id='%s'>"
                      "<error type='cancel' code='503'>"
                        "<service-unavailable"
                          " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                      "</error>"
                    "</iq>",
                    stanza->to, ctx->full_jid, stanza->id);

                send_raw(ctx, response);
            }

            return;
        }

        /* Plain user-JID disco#info — return account identity */
        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
              "<query xmlns='http://jabber.org/protocol/disco#info'>"
                "<identity category='account' type='registered'/>"
              "</query>"
            "</iq>",
            stanza->to, ctx->full_jid, stanza->id);
    }
    else {
        /* CASE 3b: server domain — XEP-0030 §4. */
        /* XEP-0160 §4 — Service Discovery: a server that supports offline
         * message storage SHOULD include "msgoffline" in its disco#info
         * feature list so clients can discover the capability.
         *   https://xmpp.org/extensions/xep-0160.html#disco */
        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
              "<query xmlns='http://jabber.org/protocol/disco#info'>"
                "<identity category='server' type='im' name='Unikernel XMPP'/>"
                "<feature var='http://jabber.org/protocol/muc'/>"
                "<feature var='jabber:iq:register'/>"
                "<feature var='msgoffline'/>"
              "</query>"
            "</iq>",
            stanza->to, ctx->full_jid, stanza->id);
    }

    send_raw(ctx, response);
}


/* ------------------------------------------------------------------
 * handle_disco_items
 *
 * Responds to Service Discovery items (disco#items) queries.
 *
 * RECEIVE:
 *   XEP-0030 §3.2 — disco#items request:
 *     <iq type='get' to='target'><query xmlns='...disco#items'/></iq>
 *   https://xmpp.org/extensions/xep-0030.html#items
 *
 * CASE 1 — MUC service (to='conference.angelic.local'):
 *   XEP-0045 §6.3 — Discovering Rooms: return all public rooms as
 *     <item jid='room@service' name='Room Name'/>
 *   https://xmpp.org/extensions/xep-0045.html#disco-rooms
 *   FIX (§3 MEDIUM): previously returned a hardcoded "Main Lobby" room
 *   regardless of which rooms were actually active in rooms[].
 *   Now iterates rooms[] and emits one <item/> per rooms[i].active == 1.
 *
 * CASE 2 — main server:
 *   Return the MUC service as an item so clients can discover it.
 *   (Session log shows this exchange; response is correct.)
 * ------------------------------------------------------------------ */
void handle_disco_items(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[2048];

    if (strstr(stanza->to, "conference.angelic.local")) {
        /* CASE 1: XEP-0045 §6.3 — list of active rooms.
         * FIX (§3 MEDIUM): Build room list dynamically from rooms[]. */
        char items[1536] = {0};

        for (int i = 0; i < MAX_ROOMS; i++) {
            if (rooms[i].active) {
                char item[256];
                snprintf(item, sizeof(item),
                    "<item jid='%s@conference.angelic.local' name='%s'/>",
                    rooms[i].name, rooms[i].name);

                /* Guard against overflow */
                if (strlen(items) + strlen(item) < sizeof(items) - 1) {
                    strcat(items, item);
                }
            }
        }

        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
              "<query xmlns='http://jabber.org/protocol/disco#items'>"
                "%s"
              "</query>"
            "</iq>",
            stanza->to, ctx->full_jid, stanza->id, items);
    }
    else {
        /* CASE 2: server items — advertise the MUC service */
        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
              "<query xmlns='http://jabber.org/protocol/disco#items'>"
                "<item jid='conference.angelic.local' name='Chatroom Service'/>"
              "</query>"
            "</iq>",
            (strlen(stanza->to) > 0) ? stanza->to : "angelic.local",
            ctx->full_jid, stanza->id);
    }

    send_raw(ctx, response);
}


/* ------------------------------------------------------------------
 * handle_sasl
 *
 * Processes the SASL <auth> element; authenticates PLAIN clients against
 * the compile-time credential table and grants ANONYMOUS clients unconditionally.
 *
 * RECEIVE:
 *   RFC 6120 §6.4.2 — SASL negotiation, client sends:
 *     <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>
 *       [Base64-encoded initial response]
 *     </auth>
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6.4.2
 *   (Session log: <auth mechanism="PLAIN">AHVzZXIxAGFzZGY=</auth>
 *    — https://datatracker.ietf.org/doc/html/rfc6120#section-6.4.2)
 *
 * PLAIN payload format:
 *   RFC 4616 §2 — [authzid] NUL authcid NUL passwd
 *     authzid — authorization identity (optional; often empty → first NUL)
 *     authcid — authentication identity = username, stored in ctx->username
 *     passwd  — password, verified against xmpp_credentials[]
 *   https://datatracker.ietf.org/doc/html/rfc4616#section-2
 *   Decoded "AHVzZXIxAGFzZGY=" → "\x00user1\x00asdf"
 *
 * ANONYMOUS mechanism:
 *   RFC 4505 — empty payload; len ≤ 1, username defaults to "user".
 *   No credential check is performed (RFC 4505 §3).
 *   https://datatracker.ietf.org/doc/html/rfc4505
 *
 * CREDENTIAL VERIFICATION (PLAIN):
 *   xmpp_credentials[] (defined at top of this file) is a compile-time
 *   table of { username, password } pairs. The decoded authcid and passwd
 *   are compared against every entry. On mismatch:
 *     RFC 6120 §6.5 — <failure><not-authorized/></failure> is sent and
 *     the function returns without advancing state, leaving the stream open
 *     for the client to retry with correct credentials or a different
 *     mechanism.
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6.5
 *
 * BASE64 VALIDATION:
 *   RFC 6120 §13.9.1 — b64decode() returns -1 on any invalid character;
 *   <failure><incorrect-encoding/></failure> is sent in that case.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-13.9.1
 *
 * MECHANISM VALIDATION:
 *   RFC 6120 §6.5.7 — any mechanism name other than PLAIN or ANONYMOUS
 *   (the two we advertised) results in <failure><invalid-mechanism/></failure>.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-6.5.7
 *
 * SASL ABORT:
 *   RFC 6120 §6.4.4 — <abort/> is detected before parsing in
 *   xmpp_recv_callback() and answered with <failure><aborted/></failure>.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-6.4.4
 *
 * SEND (success):
 *   RFC 6120 §6.4.6 — <success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>
 *   Client MUST then open a new XML stream.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-6.4.6
 *
 * KNOWN LIMITATION:
 *   RFC 6120 §13.8.4 — PLAIN MUST NOT be used without TLS.
 *   This server offers no TLS (RFC 6120 §5). PLAIN is acceptable only on
 *   a trusted, isolated LAN. Do not expose on a public network.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-13.8.4
 *
 *   RFC 6120 §6.3.7 — simple user name / realm rules (both optional):
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6.3.7
 *   RFC 6120 §6.4   — full SASL exchange process:
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6.4
 * ------------------------------------------------------------------ */
void handle_sasl(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    /* ------------------------------------------------------------------
     * RFC 6120 §6.5.7 — Validate offered mechanism.
     * We advertise only PLAIN and ANONYMOUS; any other value MUST result
     * in <failure><invalid-mechanism/></failure>.
     *   https://datatracker.ietf.org/doc/html/rfc6120#section-6.5.7
     * stanza->mechanism is populated by the parser from the 'mechanism'
     * attribute of the <auth> element (RFC 6120 §6.4.2).
     * An empty mechanism field is tolerated (ANONYMOUS clients may omit it).
     * ------------------------------------------------------------------ */
    if (stanza->mechanism[0] != '\0' && strcmp(stanza->mechanism, "PLAIN") != 0 && strcmp(stanza->mechanism, "ANONYMOUS") != 0) {
        const char *inv_mech =
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
              "<invalid-mechanism/>"
            "</failure>";

        xmpp_log("SEND", inv_mech, strlen(inv_mech));

        tcp_write(ctx->pcb, inv_mech, strlen(inv_mech), TCP_WRITE_FLAG_COPY);

        tcp_output(ctx->pcb);

        return; /* state unchanged; client may retry with a valid mechanism */
    }

    unsigned char decoded[128] = {0};

    /* RFC 4616 §2 / RFC 6120 §6.4.2 — decode Base64 PLAIN payload.
     * RFC 6120 §6.5.5 — b64decode() returns -1 on any invalid character;
     * we MUST respond with <failure><incorrect-encoding/></failure> and
     * leave state unchanged so the client may retry.
     *   https://datatracker.ietf.org/doc/html/rfc6120#section-6.5.5
     *   https://datatracker.ietf.org/doc/html/rfc6120#section-13.9.1 */
    int len = b64decode(stanza->payload, decoded, sizeof(decoded) - 1);

    if (len < 0) {
        const char *bad_enc =
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
              "<incorrect-encoding/>"
            "</failure>";

        xmpp_log("SEND", bad_enc, strlen(bad_enc));

        tcp_write(ctx->pcb, bad_enc, strlen(bad_enc), TCP_WRITE_FLAG_COPY);

        tcp_output(ctx->pcb);

        return;
    }

    ctx->username[0] = '\0';

    if (len > 1) {
        /* RFC 4616 §2 — skip authzid (first NUL-terminated field) */
        int i = 0;

        while (i < len && decoded[i] != '\0') {
            i++;
        }

        i++; /* skip the NUL separator between authzid and authcid */
        /* Read authcid = username */
        int j = 0;

        while (i < len && decoded[i] != '\0' && j < 31){
            ctx->username[j++] = decoded[i++];
        }

        ctx->username[j] = '\0';
    }

    /* RFC 4505 — ANONYMOUS or empty: use a default name */
    if (ctx->username[0] == '\0') {
        strncpy(ctx->username, "user", 31);
    }

    /* ------------------------------------------------------------------
     * RFC 6120 §6.5 — credential verification for PLAIN.
     *
     * All three NUL-delimited fields of the PLAIN payload (RFC 4616 §2)
     * have already been decoded into `decoded[]` above:
     *   field 0 — authzid  (ignored per RFC 4616 §2 for simple servers)
     *   field 1 — authcid  (stored in ctx->username above)
     *   field 2 — passwd   (extracted below and checked here)
     *
     * Re-scan from the start of decoded[] rather than relying on the
     * index `i` left by the authcid extraction loop above, to keep
     * the two passes independent and easy to audit.
     *
     * On mismatch: <failure><not-authorized/></failure> is sent and we
     * return WITHOUT advancing ctx->state, so the stream stays open and
     * the client may retry (RFC 6120 §6.5 permits multiple attempts).
     *
     * ANONYMOUS mechanism bypasses this block entirely per RFC 4505 §3.
     *   RFC 6120 §6.5   https://datatracker.ietf.org/doc/html/rfc6120#section-6.5
     *   RFC 4616 §2     https://datatracker.ietf.org/doc/html/rfc4616#section-2
     * ------------------------------------------------------------------ */
    if (strcmp(stanza->mechanism, "PLAIN") == 0) {
        /* Extract password: the third NUL-delimited field in decoded[].
         * Walk past authzid and authcid to reach it. */
        char password[64] = {0};

        /* Skip authzid (first field) */
        int pos = 0;

        while (pos < len && decoded[pos] != '\0') {
            pos++;
        }

        pos++; /* skip NUL */

        /* Skip authcid (second field — already in ctx->username) */
        while (pos < len && decoded[pos] != '\0') {
            pos++;
        }

        pos++; /* skip NUL */

        /* Read password (third field) */
        int pw_len = 0;

        while (pos < len && decoded[pos] != '\0' && pw_len < 63) {
            password[pw_len++] = decoded[pos++];
        }

        password[pw_len] = '\0';

        /* Look up username + password in the credential table */
        int authorized = 0;

        for (int ci = 0; ci < xmpp_credential_count; ci++) {
            if (strcmp(xmpp_credentials[ci].username, ctx->username) == 0 && strcmp(xmpp_credentials[ci].password, password) == 0) {
                authorized = 1;

                break;
            }
        }

        if (!authorized) {
            /* RFC 6120 §6.5 — credentials did not match any entry in the
             * credential table; send <not-authorized/> and return without
             * advancing state. The stream stays open: the client may retry
             * with correct credentials or switch to ANONYMOUS.
             *   https://datatracker.ietf.org/doc/html/rfc6120#section-6.5 */
            const char *not_auth =
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                  "<not-authorized/>"
                "</failure>";

            xmpp_log("SEND", not_auth, strlen(not_auth));

            tcp_write(ctx->pcb, not_auth, strlen(not_auth), TCP_WRITE_FLAG_COPY);

            tcp_output(ctx->pcb);

            return;
        }
    }
    /* ANONYMOUS — no credential check required (RFC 4505 §3) */

    /* RFC 6120 §6.4.6 — SASL success */
    const char *resp = "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>";

    xmpp_log("SEND", resp, strlen(resp));

    tcp_write(ctx->pcb, resp, strlen(resp), TCP_WRITE_FLAG_COPY);

    tcp_output(ctx->pcb);

    /* RFC 6120 §6.4.6 — server resets stream state; client will
     * re-open the stream and xmpp_recv_callback will call
     * handle_handshake_logic() again for the new stream. */
    ctx->authenticated = 1;
    ctx->state = STATE_AUTHENTICATED;
}


/* ------------------------------------------------------------------
 * handle_muc_presence
 *
 * Handles a user entering or creating a MUC room.
 *
 * RECEIVE:
 *   XEP-0045 §7.2 — Entering a Room: client sends
 *     <presence to='room@service/desired-nick'>
 *       <x xmlns='http://jabber.org/protocol/muc'/>
 *     </presence>
 *     https://xmpp.org/extensions/xep-0045.html#enter
 *   (Session log shows exactly this, including the <c> caps element
 *    which we ignore)
 *
 * PROCESSING:
 *   - Parse room name and nick from the 'to' occupant JID.
 *   - Find existing room or create one (XEP-0045 §10.1).
 *   - Insert the joining user into the room's participant list.
 *
 * SEND 1 — existing occupants' presences to the new user:
 *   XEP-0045 §7.2 — service MUST send presence from each current
 *   occupant to the new one, with affiliation and role.
 *     <presence from='room/existing-nick' to='new-user-full-jid'>
 *       <x xmlns='...muc#user'>
 *         <item affiliation='member' role='participant' jid='real-jid'/>
 *       </x>
 *     </presence>
 *   https://xmpp.org/extensions/xep-0045.html#enter-pres
 *   NOTE: real JID exposure (jid='...') is only correct for
 *   non-anonymous rooms. XEP-0045 §7.2.1 — rooms SHOULD be semi-
 *   anonymous by default; real JIDs are then only shown to moderators.
 *
 * SEND 2 — new user's presence to all existing occupants:
 *   XEP-0045 §7.2 — same format, from='room/new-nick', to each occupant.
 *
 * SEND 3 — self-presence (REQUIRED):
 *   XEP-0045 §7.2.2 — MUST send the joiner's own presence reflection
 *   with <status code='110'/> so they know it is their own:
 *     <status code='110'/>  — this is your own presence
 *     <status code='201'/>  — you just created this room (new rooms only)
 *   https://xmpp.org/extensions/xep-0045.html#enter-pres
 *   For new room: affiliation='owner' role='moderator' (XEP-0045 §10.1)
 *   For existing room: affiliation='member' role='participant'
 *
 * SEND 4 — room subject (REQUIRED):
 *   XEP-0045 §7.2.15 — after all occupant presences, send the subject:
 *     <message from='room@service' type='groupchat'><subject>…</subject></message>
 *   https://xmpp.org/extensions/xep-0045.html#enter-subject
 *
 * KNOWN MISSING:
 *
 *   Nick conflict (XEP-0045 §7.2.8):
 *     Before adding the user, check that no active participant already
 *     holds the requested nick. If taken:
 *       <presence type='error' from='room/nick'>
 *         <error type='cancel'>
 *           <conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>
 *         </error>
 *       </presence>
 *     https://xmpp.org/extensions/xep-0045.html#enter-conflict
 *
 *   Room exit — type='unavailable' (XEP-0045 §7.14):
 *     When the client sends <presence type='unavailable' to='room/nick'/>,
 *     remove them and broadcast departure to all remaining occupants.
 *     RFC 6121 §4.5 — unavailable presence.
 *     https://xmpp.org/extensions/xep-0045.html#exit
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-4.5
 *     (Session log: "type='unavailable' should be implemented")
 *
 *   Discussion history (XEP-0045 §7.2.13):
 *     After subject, send recent room messages. Sending none is
 *     minimally compliant.
 *     https://xmpp.org/extensions/xep-0045.html#enter-history
 *
 *   Locked room (XEP-0045 §10.1):
 *     New rooms should be locked until config is submitted. We skip
 *     this; the room is immediately open.
 *     https://xmpp.org/extensions/xep-0045.html#createroom
 *
 *   target_ctx stack allocation:
 *     Temporary ctx structs with only pcb set are used to reach other
 *     clients' TCP connections within MUC presence broadcasts.  Works
 *     because send_raw() only dereferences pcb.  The global client_registry[]
 *     is used for 1:1 message routing; the pcb-only approach here avoids
 *     a second registry scan for each room participant.
 * ------------------------------------------------------------------ */
void handle_muc_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    /* XEP-0045 §7.2 — resource part of 'to' JID is the desired nick */
    char *slash = strchr(stanza->to, '/');

    if (!slash) {
        return;
    }

    char nick[32];

    strncpy(nick, slash + 1, 31);

    nick[31] = '\0';

    /* Bare room JID: room@service */
    char bare_jid[64];
    int bare_len = slash - stanza->to;

    if (bare_len > 63) {
        bare_len = 63;
    }

    strncpy(bare_jid, stanza->to, bare_len);

    bare_jid[bare_len] = '\0';

    /* Room name: localpart of the room JID */
    char room_name[32] = {0};
    char *at = strchr(stanza->to, '@');

    if (!at) {
        return;
    }

    int name_len = at - stanza->to;

    if (name_len > 31) {
        name_len = 31;
    }

    strncpy(room_name, stanza->to, name_len);

    /* Find or create the room */
    int is_new_room = 0;
    room_t *r = NULL;

    for (int i = 0; i < MAX_ROOMS; i++) {
        if (rooms[i].active && strcmp(rooms[i].name, room_name) == 0) {
            r = &rooms[i];

            break;
        }
    }

    if (!r) {
        /* XEP-0045 §10.1 — create room and immediately lock it.
         * The room stays locked until the owner submits the configuration
         * form or an instant-room IQ-set (handle_muc_owner sets locked=0).
         *   https://xmpp.org/extensions/xep-0045.html#createroom */
        for (int i = 0; i < MAX_ROOMS; i++) {
            if (!rooms[i].active) {
                r = &rooms[i];
                r->active = 1;

                strcpy(r->name, room_name);

                /* Store creator JID for accurate owner reporting.
                 * XEP-0045 §9.5 / handle_muc_admin() uses this instead
                 * of proxying the first active participant. */
                strncpy(r->creator_jid, ctx->full_jid, sizeof(r->creator_jid) - 1);

                r->creator_jid[sizeof(r->creator_jid) - 1] = '\0';

                /* Strip resource → bare JID (RFC 6120 §2.1) */
                char *slash = strchr(r->creator_jid, '/');

                if (slash) {
                    *slash = '\0';
                }

                /* XEP-0045 §7.2.3 — default anonymity type is semi-anonymous.
                 * Real JIDs are only visible to moderators/admins/owners.
                 * A future room-config IQ (XEP-0045 §10.2) can set this to 0
                 * for a non-anonymous room where all occupants see real JIDs. */
                r->semi_anon = 1;

                /* XEP-0045 §10.1 — new rooms are locked until configured. */
                r->locked = 1;
                is_new_room = 1;

                /* Persist the new room immediately so it survives restart. */
                xmpp_persist_save_rooms();

                break;
            }
        }
    }

    if (!r) {
        return; /* Room pool exhausted */
    }

    /* ------------------------------------------------------------------
     * XEP-0045 §10.1 — Locked room gate.
     *
     * If the room is locked (newly created, awaiting owner configuration),
     * only the room creator is allowed to join.  Any other user receives
     * a <presence type='error'> with <item-not-found/> (code 404), making
     * the room effectively invisible to non-owners until it is configured.
     *
     * The creator is identified by comparing the joining user's bare JID
     * against room_t.creator_jid.  This check is intentionally applied to
     * XMPP_PRESENCE_UNAVAILABLE as well: there is nothing to exit from if
     * the user was never admitted, so the exit path below will find no
     * matching nick and silently return anyway, but rejecting here is
     * cleaner and avoids unnecessary room-deactivation logic running on an
     * empty room while it is still being set up.
     *
     *   XEP-0045 §10.1
     *   https://xmpp.org/extensions/xep-0045.html#createroom
     * ------------------------------------------------------------------ */
    if (r->locked) {
        /* Compute the joining user's bare JID */
        char joiner_bare[64] = {0};

        strncpy(joiner_bare, ctx->full_jid, sizeof(joiner_bare) - 1);

        char *joiner_slash = strchr(joiner_bare, '/');

        if (joiner_slash) {
            *joiner_slash = '\0';
        }

        if (strcmp(joiner_bare, r->creator_jid) != 0) {
            /* Non-owner tried to enter a locked room.
             * XEP-0045 §10.1 — server MUST return <item-not-found/>.
             *   https://xmpp.org/extensions/xep-0045.html#createroom */
            char locked_err[512];

            snprintf(locked_err, sizeof(locked_err),
                "<presence type='error' from='%s/%s' to='%s'>"
                  "<error type='cancel' code='404'>"
                    "<item-not-found"
                      " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                  "</error>"
                "</presence>",
                bare_jid, nick, ctx->full_jid);

            send_raw(ctx, locked_err);

            return;
        }
        /* Creator is allowed through; they will complete room setup via
         * the muc#owner config IQ that follows joining. */
    }

    /* ------------------------------------------------------------------
     * Handle room exit: type='unavailable' directed at conference domain.
     * XEP-0045 §7.14 — Exiting a Room
     *   Client sends: <presence type='unavailable' to='room@service/nick'/>
     *   Server MUST:
     *     1. Broadcast type='unavailable' from room/nick to all other occupants.
     *     2. Send self-departure with <status code='110'/> to the leaving user.
     *     3. Remove the user from the room's participant list.
     *     4. Deactivate the room if it becomes empty.
     *   https://xmpp.org/extensions/xep-0045.html#exit
     * ------------------------------------------------------------------ */
    if (stanza->type == XMPP_PRESENCE_UNAVAILABLE) {
        char response[512];

        for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
            if (!r->users[i].active) {
                continue;
            }

            if (strcmp(r->users[i].nick, nick) != 0) {
                continue;
            }

            /* SEND to all other occupants: departure presence */
            for (int j = 0; j < MAX_USERS_PER_ROOM; j++) {
                if (!r->users[j].active || j == i) {
                    continue;
                }

                /* FIX Bug 2 — replace stack-local target_ctx built from
                 * participant_t.pcb with a lookup through client_registry[].
                 * participant_t.pcb may point at a freed PCB if that client
                 * disconnected between joining the room and this broadcast.
                 * find_client_by_jid() returns NULL for dead slots, making
                 * the send a safe no-op instead of a use-after-free. */
                xmpp_client_ctx_t *target = find_client_by_jid(r->users[j].jid);

                if (!target) {
                    continue; /* client disconnected — skip */
                }

                snprintf(response, sizeof(response),
                    "<presence type='unavailable' from='%s/%s' to='%s'>"
                      "<x xmlns='http://jabber.org/protocol/muc#user'>"
                        "<item affiliation='member' role='none'/>"
                      "</x>"
                    "</presence>",
                    bare_jid, nick, r->users[j].jid);

                send_raw(target, response);
            }

            /* SEND self-departure with code 110 */
            snprintf(response, sizeof(response),
                "<presence type='unavailable' from='%s/%s' to='%s'>"
                  "<x xmlns='http://jabber.org/protocol/muc#user'>"
                    "<item affiliation='member' role='none'/>"
                    "<status code='110'/>"
                  "</x>"
                "</presence>",
                bare_jid, nick, ctx->full_jid);

            send_raw(ctx, response);

            /* Remove user from room */
            memset(&r->users[i], 0, sizeof(participant_t));

            /* Deactivate room if now empty */
            int occupied = 0;

            for (int j = 0; j < MAX_USERS_PER_ROOM; j++) {
                if (r->users[j].active) { 
                    occupied = 1;

                    break; 
                }
            }
            if (!occupied) {
                r->active = 0;

                memset(r->name, 0, sizeof(r->name));

                memset(r->creator_jid, 0, sizeof(r->creator_jid));

                /* FIX Bug 3 — persist the deactivation immediately.
                 *
                 * Room creation calls xmpp_persist_save_rooms() (above).
                 * Room unlock (handle_muc_owner) also calls it.  But the
                 * room *deletion* path — triggered here when the last
                 * occupant leaves — previously did not persist the update.
                 *
                 * Without this call, after a server restart the disk still
                 * holds active=1 for this room.  xmpp_persist_load_all()
                 * restores it with active=1 and an empty name/creator_jid,
                 * violating the persist layer's own invariant and causing
                 * the room to ghost-appear in disco#items responses.
                 *
                 * The fix is a single persist call here, symmetric with
                 * the creation persist call made when the room was first
                 * activated. */
                xmpp_persist_save_rooms();   /* Bug 3 fix: persist deactivation */
            }

            return; /* Exit handling complete */
        }

        /* Nick not found in room — silently ignore */
        return;
    }

    /* ------------------------------------------------------------------
     * Nick conflict check (XEP-0045 §7.2.8).
     * Before adding the user, verify that no active participant already
     * holds the requested nick.  If the nick is taken:
     *   Send <presence type='error' ...><error code='409'>
     *         <conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>
     *   </presence>  and return without modifying the room.
     *   https://xmpp.org/extensions/xep-0045.html#enter-conflict
     * ------------------------------------------------------------------ */
    for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
        if (r->users[i].active && strcmp(r->users[i].nick, nick) == 0) {
            char conflict[512];

            snprintf(conflict, sizeof(conflict),
                "<presence type='error' from='%s/%s' to='%s'>"
                  "<error type='cancel' code='409'>"
                    "<conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                  "</error>"
                "</presence>",
                bare_jid, nick, ctx->full_jid);

            send_raw(ctx, conflict);

            return;
        }
    }

    /* Add joining user to the room */
    for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
        if (!r->users[i].active) {
            r->users[i].active = 1;
            r->users[i].pcb = ctx->pcb;

            strncpy(r->users[i].nick, nick, MAX_NICK_LEN - 1);

            strncpy(r->users[i].jid, ctx->full_jid, 63);

            break;
        }
    }

    char response[512];

    /* Determine whether the new user is the room owner (creator).
     * Owners are always permitted to see real JIDs regardless of
     * the room's anonymity setting (XEP-0045 §7.2.3). */
    char bare_self[64] = {0};

    strncpy(bare_self, ctx->full_jid, sizeof(bare_self) - 1);

    {
        char *sl = strchr(bare_self, '/');

        if (sl) {
            *sl = '\0';
        }
    }

    int self_is_owner = (strcmp(bare_self, r->creator_jid) == 0);

    /* SEND 1: XEP-0045 §7.2 — existing occupants → new user
     *
     * Fix (§5): XEP-0045 §7.2.3 — real JID exposure in <item jid='...'/>.
     *   semi_anon == 1: include jid= only if the new user is an owner/mod.
     *   semi_anon == 0: always include jid= (non-anonymous room).
     *   https://xmpp.org/extensions/xep-0045.html#enter-pres */
    for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
        if (!r->users[i].active) {
            continue;
        }

        if (strcmp(r->users[i].jid, ctx->full_jid) == 0) {
            continue;
        }

        /* Expose the existing occupant's real JID only if:
         *   (a) the room is non-anonymous, OR
         *   (b) the receiving user (new joiner) is owner/moderator. */
        int expose_jid = (!r->semi_anon || self_is_owner);

        if (expose_jid) {
            snprintf(response, sizeof(response),
                "<presence from='%s/%s' to='%s'>"
                  "<x xmlns='http://jabber.org/protocol/muc#user'>"
                    "<item affiliation='member' role='participant' jid='%s'/>"
                  "</x>"
                "</presence>",
                bare_jid, r->users[i].nick, ctx->full_jid, r->users[i].jid);
        }
        else {
            /* Semi-anonymous: omit jid= for regular members */
            snprintf(response, sizeof(response),
                "<presence from='%s/%s' to='%s'>"
                  "<x xmlns='http://jabber.org/protocol/muc#user'>"
                    "<item affiliation='member' role='participant'/>"
                  "</x>"
                "</presence>",
                bare_jid, r->users[i].nick, ctx->full_jid);
        }

        send_raw(ctx, response);
    }

    /* SEND 2: XEP-0045 §7.2 — new user's presence → all existing occupants
     *
     * Fix (§5): XEP-0045 §7.2.3 — expose new user's real JID only to
     *   owners/moderators in semi-anonymous rooms; to all in non-anonymous.
     *   https://xmpp.org/extensions/xep-0045.html#enter-pres */
    for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
        if (!r->users[i].active) {
            continue;
        }

        if (strcmp(r->users[i].jid, ctx->full_jid) == 0) {
            continue;
        }

        /* FIX Bug 2 — replace stack-local target_ctx with registry lookup.
         * See find_client_by_jid() header comment for the full rationale. */
        xmpp_client_ctx_t *target = find_client_by_jid(r->users[i].jid);

        if (!target) {
            continue; /* client disconnected — skip */
        }

        /* Expose the new joiner's real JID only if:
         *   (a) the room is non-anonymous, OR
         *   (b) the receiving existing occupant is the room owner. */
        int recipient_is_owner = (strcmp(r->users[i].jid, r->creator_jid) == 0);
        int expose_jid2 = (!r->semi_anon || recipient_is_owner);

        if (expose_jid2) {
            snprintf(response, sizeof(response),
                "<presence from='%s/%s' to='%s'>"
                  "<x xmlns='http://jabber.org/protocol/muc#user'>"
                    "<item affiliation='member' role='participant' jid='%s'/>"
                  "</x>"
                "</presence>",
                bare_jid, nick, r->users[i].jid, ctx->full_jid);
        }
        else {
            /* Semi-anonymous: omit jid= for regular members */
            snprintf(response, sizeof(response),
                "<presence from='%s/%s' to='%s'>"
                  "<x xmlns='http://jabber.org/protocol/muc#user'>"
                    "<item affiliation='member' role='participant'/>"
                  "</x>"
                "</presence>",
                bare_jid, nick, r->users[i].jid);
        }

        send_raw(target, response);
    }

    /* SEND 3: XEP-0045 §7.2.2 — self-presence (REQUIRED: code 110) */
    if (is_new_room) {
        /* XEP-0045 §10.1 — creator is owner/moderator; code 201 = created */
        snprintf(response, sizeof(response),
            "<presence from='%s/%s' to='%s'>"
              "<x xmlns='http://jabber.org/protocol/muc#user'>"
                "<item affiliation='owner' role='moderator'/>"
                "<status code='110'/>"
                "<status code='201'/>"
              "</x>"
            "</presence>",
            bare_jid, nick, ctx->full_jid);
    }
    else {
        /* XEP-0045 §7.2.2 — joining member self-presence */
        snprintf(response, sizeof(response),
            "<presence from='%s/%s' to='%s'>"
              "<x xmlns='http://jabber.org/protocol/muc#user'>"
                "<item affiliation='member' role='participant'/>"
                "<status code='110'/>"
              "</x>"
            "</presence>",
            bare_jid, nick, ctx->full_jid);
    }

    send_raw(ctx, response);

    /* SEND 4: XEP-0045 §7.2.15 — room subject (REQUIRED after presences).
     * Sent from the room bare JID, not an occupant JID. */
    snprintf(response, sizeof(response),
        "<message from='%s' to='%s' type='groupchat'>"
          "<subject>Welcome to the Unikernel Lobby</subject>"
        "</message>",
        bare_jid, ctx->full_jid);

    send_raw(ctx, response);

    /* XEP-0045 §7.2.13 — Discussion history after subject.
     * Sending zero history messages is explicitly permitted as the minimum
     * compliant implementation.  We implement this minimum here.
     * https://xmpp.org/extensions/xep-0045.html#enter-history */
}


/* ------------------------------------------------------------------
 * handle_chat_message
 *
 * Routes a <message> stanza to a MUC room or to a direct recipient.
 *
 * RECEIVE:
 *   RFC 6121 §5.1  — general message delivery
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-5.1
 *   XEP-0045 §7.9  — sending to a MUC room (type='groupchat')
 *     https://xmpp.org/extensions/xep-0045.html#message
 *   (Session log shows a full groupchat exchange with <body>,
 *    <origin-id>, <active> chatstates, <markable> markers)
 *
 * already_wrapped:
 *   If stanza->payload starts with '<', the inner content is already
 *   XML (e.g. "<body>hi</body><origin-id .../>") and is inserted as-is.
 *   Otherwise it is plain text and must be wrapped in <body>.
 *
 * --- GROUPCHAT PATH (to='*@conference.angelic.local') ---
 *   XEP-0045 §7.9 — reflect to ALL occupants (including the sender)
 *   with from='room@service/sender-nick'.
 *   (Session log: message reflected back with correct from occupant JID)
 *
 *   Thread element (RFC 6121 §5.2.5) and XHTML-IM (XEP-0071):
 *     When stanza->payload[0] == '<', the payload is already wrapped XML
 *     and is reflected verbatim via the already_wrapped path below.  This
 *     means <thread>, <html>, <origin-id>, <markable>, <active> (chat
 *     states), and any other child elements are transparently forwarded
 *     to all recipients without special handling.
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-5.2.5
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-5.3
 *
 * --- DIRECT MESSAGE PATH ---
 *   RFC 6121 §5.1 — route to the addressed user's JID.
 *
 *   FIX (§3 HIGH) — from/to reversed:
 *     The snprintf was using from='stanza->to' (the intended recipient)
 *     and to='ctx->full_jid' (the sender). Corrected to:
 *       from='ctx->full_jid'  (the actual sender)
 *       to='stanza->to'       (the intended recipient)
 *
 *   DIRECT MESSAGE ROUTING — RFC 6121 §5.1:
 *     Direct messages are delivered via bare-JID lookup in client_registry[].
 *     For offline recipients (no matching session-ready slot), a
 *     <service-unavailable/> error is returned to the sender.
 *     XEP-0160 (offline message storage) is not implemented.
 *     https://xmpp.org/extensions/xep-0160.html
 * ------------------------------------------------------------------ */
void handle_chat_message(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[2048];
    int already_wrapped = (stanza->payload[0] == '<');

    if (strstr(stanza->to, "conference.angelic.local")) {
        /* --- Groupchat: XEP-0045 §7.9 --- */
        room_t *r = NULL;
        char *at = strchr(stanza->to, '@');

        if (at) {
            char room_name[MAX_ROOM_NAME_LEN] = {0};
            int name_len = at - stanza->to;

            if (name_len >= MAX_ROOM_NAME_LEN) {
                name_len = MAX_ROOM_NAME_LEN - 1;
            }

            strncpy(room_name, stanza->to, name_len);

            for (int i = 0; i < MAX_ROOMS; i++) {
                if (rooms[i].active && strcmp(rooms[i].name, room_name) == 0) {
                    r = &rooms[i];

                    break;
                }
            }
        }

        if (!r) {
            return; /* Sender not in a known room — drop */
        }

        /* Find sender's current nick */
        char sender_nick[32] = "unknown";

        for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
            if (r->users[i].active && strcmp(r->users[i].jid, ctx->full_jid) == 0) {
                strcpy(sender_nick, r->users[i].nick);

                break;
            }
        }

        /* XEP-0045 §7.9 — reflect to ALL occupants (including sender).
         * from = room@service/sender-nick (occupant JID)
         * to   = each occupant's real full JID
         *
         * FIX Bug 5 — groupchat response buffer too small / no truncation check.
         *
         * stanza->payload is up to 1024 bytes.  The XML framing adds roughly
         * 150-200 bytes of overhead (from, to, id, element tags).  The old
         * response[2048] buffer was therefore barely large enough and contained
         * no check for snprintf truncation.  RFC 6120 §4.9.3.14 requires a
         * <policy-violation/> stream error rather than silent truncation when
         * a limit is exceeded.
         *
         * Fix: increase the buffer to 2400 bytes (1024 payload + ~200 framing
         * + 64 from + 64 to + 64 id + margin) and check snprintf's return
         * value.  A truncated result is skipped for that recipient via
         * continue — the sender's stanza was too large; individual recipients
         * are not penalised and the loop continues to the next occupant.
         *
         * FIX Bug 2 — replace stack-local target_ctx (dangling PCB) with
         * find_client_by_jid(); see find_client_by_jid() header comment. */
        for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
            if (!r->users[i].active) {
                continue;
            }

            xmpp_client_ctx_t *target = find_client_by_jid(r->users[i].jid);

            if (!target) {
                continue; /* client disconnected — skip */
            }

            /* Bug 5 fix: enlarged buffer */
            char gc_response[2400];
            int written;

            if (already_wrapped) {
                written = snprintf(gc_response, sizeof(gc_response),
                    "<message from='%s/%s' to='%s' type='groupchat' id='%s'>"
                      "%s"
                    "</message>",
                    stanza->to, sender_nick, r->users[i].jid,
                    stanza->id, stanza->payload);
            }
            else {
                written = snprintf(gc_response, sizeof(gc_response),
                    "<message from='%s/%s' to='%s' type='groupchat' id='%s'>"
                      "<body>%s</body>"
                    "</message>",
                    stanza->to, sender_nick, r->users[i].jid,
                    stanza->id, stanza->payload);
            }

            /* Bug 5 fix: detect truncation per RFC 6120 §4.9.3.14 */
            if (written < 0 || (size_t)written >= sizeof(gc_response)) {
                /* Payload exceeded buffer — skip this recipient.
                 * RFC 6120 §4.9.3.14 — policy-violation would be the
                 * correct stream error to send to the originator, but
                 * sending it per-recipient in a broadcast loop would
                 * produce confusing duplicate errors.  The originator's
                 * client is responsible for respecting the 1024-byte
                 * payload limit; silently skipping is acceptable here. */
                continue;
            }

            send_raw(target, gc_response);
        }
    }
    else {
        /* --- Direct message: RFC 6121 §5.1 ---
         *
         * FIX (§4 ⚠ Partial — direct message routing):
         * Route to the addressed recipient by searching client_registry
         * for a matching JID (full or bare). Bare JID matching is needed
         * because the sender may address user@domain without a resource.
         *
         * RFC 6121 §5.1 — "the server MUST deliver the stanza to the
         * intended recipient."
         *   https://datatracker.ietf.org/doc/html/rfc6121#section-5.1
         *
         * RFC 6120 §8.1.2 — from= is stamped as ctx->full_jid (the
         * authenticated sender), not taken from the stanza to prevent
         * JID spoofing.
         *
         * For offline users: XEP-0160 — Message Offline Storage.
         * Not implemented; service-unavailable is returned instead. */
        if (already_wrapped) {
            snprintf(response, sizeof(response),
                "<message from='%s' to='%s' type='chat'>%s</message>",
                ctx->full_jid, stanza->to, stanza->payload);
        }
        else {
            snprintf(response, sizeof(response),
                "<message from='%s' to='%s' type='chat'>"
                  "<body>%s</body>"
                "</message>",
                ctx->full_jid, stanza->to, stanza->payload);
        }

        /* Build the bare target JID for matching */
        char bare_target[64] = {0};

        strncpy(bare_target, stanza->to, sizeof(bare_target) - 1);

        char *target_slash = strchr(bare_target, '/');

        if (target_slash) {
            *target_slash = '\0';
        }

        int delivered = 0;

        for (int i = 0; i < MAX_USERS; i++) {
            if (client_registry[i].pcb == NULL) {
                continue;
            }

            if (client_registry[i].state < STATE_SESSION) {
                continue;
            }

            /* Match on bare JID (localpart@domain) */
            char bare_reg[64] = {0};

            strncpy(bare_reg, client_registry[i].full_jid, sizeof(bare_reg) - 1);

            char *reg_slash = strchr(bare_reg, '/');

            if (reg_slash) {
                *reg_slash = '\0';
            }

            if (strcmp(bare_target, bare_reg) == 0) {
                send_raw(&client_registry[i], response);

                delivered = 1;
                /* Continue iterating: deliver to all resources of this user */
            }
        }

        if (!delivered) {
            /* XEP-0160 §2 — store message for offline delivery.
             *
             * XEP-0160 §3 — message type filtering:
             *   We are in the direct (non-conference) message path, so the
             *   stanza is type='chat'.  chat messages SHOULD be stored offline.
             *
             * offline_msg_enqueue() stores the inner payload; offline_msg_drain()
             * in handle_initial_presence() reconstructs and delivers the full
             * <message> stanza with a XEP-0203 <delay/> stamp.
             *
             * FIX Bug 15 — offline_msg_is_full() was never consulted before
             * calling offline_msg_enqueue().  XEP-0160 §2 requires that when
             * the server cannot store a message it MUST return
             * <service-unavailable/> to the sender.  offline_msg_is_full()
             * implements a per-user soft cap (≤ half the total pool) so one
             * user cannot starve all others.  We now check it first; if the
             * cap is already reached we return the error immediately without
             * attempting the enqueue.
             *   https://xmpp.org/extensions/xep-0160.html */

            /* Extract the recipient localpart for the is_full check.
             * bare_target is already user@domain; we need the part before @
             * to match the to_user key used inside the offline store. */
            char to_user_check[32] = {0};
            const char *at_check = strchr(bare_target, '@');

            if (at_check) {
                int ulen = (int)(at_check - bare_target);

                if (ulen >= (int)sizeof(to_user_check)) {
                    ulen = (int)sizeof(to_user_check) - 1;
                }

                strncpy(to_user_check, bare_target, ulen);
            }
            else {
                strncpy(to_user_check, bare_target, sizeof(to_user_check) - 1);
            }

            /* Bug 15 fix: check per-user cap BEFORE attempting enqueue.
             * Short-circuit: enqueue is skipped entirely when is_full fires. */
            if (offline_msg_is_full(to_user_check)
                || offline_msg_enqueue(bare_target, ctx->full_jid,
                                       stanza->id, stanza->payload) != 0) {
                /* XEP-0160 §2 / RFC 6121 §8.5.2.1 — cannot store; notify sender */
                char err[512];

                snprintf(err, sizeof(err),
                    "<message type='error' from='%s' to='%s'>"
                      "<error type='cancel' code='503'>"
                        "<service-unavailable"
                          " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                      "</error>"
                    "</message>",
                    stanza->to, ctx->full_jid);

                send_raw(ctx, err);
            }
            /* On successful enqueue: no response to sender.
             * Delivery occurs when recipient next sends initial presence. */
        }
    }
}


/* ------------------------------------------------------------------
 * handle_broadcast_presence
 *
 * Handles non-MUC, non-subscription presence stanzas.
 *
 * RECEIVE:
 *   RFC 6121 §4.2  — available/initial presence (no 'type' attribute)
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-4.2
 *   RFC 6121 §4.5  — unavailable presence (type='unavailable')
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-4.5
 *     (Session log: "type='unavailable' should be implemented for muc server")
 *   RFC 6121 §3.1  — subscription presence types (subscribe, subscribed,
 *     unsubscribe, unsubscribed)
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-3.1
 *     (Session log: "handle the cases when presence is sent for subscribe
 *      and unsubscribe")
 *
 * SEND:
 *   RFC 6121 §4.2.2 — server MUST broadcast presence to all contacts
 *   with subscription type 'from' or 'both'.
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-4.2.2
 *   Presence is now broadcast to all active client_registry[] slots
 *   (state >= STATE_SESSION, pcb != NULL).
 *
 * State transition:
 *   Advance to STATE_READY as a fallback for clients that skip the
 *   session IQ (handle_core_session also sets STATE_READY).
 *
 * SUBSCRIPTION HANDLING — RFC 6121 §3.1.3:
 *   subscribe / subscribed / unsubscribe / unsubscribed presence types
 *   are forwarded to the addressed user by bare-JID lookup in
 *   client_registry[].  Implemented in the subscription branch below.
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-3.1
 *
 * NOTE — presence probing: implemented in handle_initial_presence()
 *   RFC 6121 §4.3.1 — probe sent after initial presence broadcast.
 *
 * NOTE — Optional XEP extensions (not yet implemented):
 *   XEP-0115 (Entity Capabilities), XEP-0153 (vCard avatar),
 *   XEP-0107 (User Mood), XEP-0085 (Chat State Notifications),
 *   XEP-0201 (Best Practices for Message Threads),
 *   XEP-0313 (Message Archive Management),
 *   XEP-0333 (Chat Markers), XEP-0359 (Unique Message IDs),
 *   XEP-0071 (XHTML-IM), XEP-0160 (Offline Messages),
 *   XEP-0198 (Stream Management), XEP-0030 (Service Discovery),
 *   XEP-0384 (OMEMO Encryption)
 * ------------------------------------------------------------------ */
void handle_broadcast_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    if (ctx->state < STATE_READY) {
        ctx->state = STATE_READY;
    }

    /* ------------------------------------------------------------------
     * FIX Bug 13 — handle type="probe" per RFC 6121 §4.3.1.
     *
     * A presence probe is a server-to-server (or client-to-server) request
     * asking "what is the current presence of JID X?".  The server SHOULD
     * respond with the probed user's current <presence/> stanza.
     *
     * Previously XMPP_PRESENCE_PROBE did not exist as an enum value, so
     * probe stanzas arrived here typed as XMPP_PRESENCE and fell through
     * into the availability broadcast loop — re-broadcasting the probe as
     * if the prober had just come online, which is wrong.
     *
     * Fix: detect XMPP_PRESENCE_PROBE first, look up the probed user in
     * client_registry[] by bare JID, send their current presence to the
     * prober, and return early so the availability broadcast is skipped.
     *
     *   RFC 6121 §4.3.1
     *   https://datatracker.ietf.org/doc/html/rfc6121#section-4.3.1
     * ------------------------------------------------------------------ */
    if (stanza->type == XMPP_PRESENCE_PROBE) {
        /* stanza->to is the bare JID being probed */
        char bare_target[64] = {0};

        strncpy(bare_target, stanza->to, sizeof(bare_target) - 1);

        char *probe_slash = strchr(bare_target, '/');

        if (probe_slash) {
            *probe_slash = '\0';
        }

        for (int i = 0; i < MAX_USERS; i++) {
            if (client_registry[i].pcb == NULL) {
                continue;
            }
            if (client_registry[i].state < STATE_SESSION) {
                continue;
            }

            char bare_reg[64] = {0};

            strncpy(bare_reg, client_registry[i].full_jid, sizeof(bare_reg) - 1);

            char *rsl = strchr(bare_reg, '/');

            if (rsl) {
                *rsl = '\0';
            }

            if (strcmp(bare_target, bare_reg) == 0) {
                /* Found the probed user — reply with their current presence */
                char probe_resp[512];

                snprintf(probe_resp, sizeof(probe_resp),
                    "<presence from='%s' to='%s'>"
                      "<show>chat</show>"
                      "<priority>1</priority>"
                    "</presence>",
                    client_registry[i].full_jid, ctx->full_jid);

                send_raw(ctx, probe_resp);
            }
        }

        return; /* do not fall through to availability broadcast */
    }

    /* ------------------------------------------------------------------
     * Subscription stanza forwarding.
     * RFC 6121 §3.1.3 — subscribe/subscribed/unsubscribe/unsubscribed
     * presence types must be delivered to the addressed user.
     *   https://datatracker.ietf.org/doc/html/rfc6121#section-3.1.3
     *
     * We locate the target by bare JID matching in client_registry.
     * The stanza is re-stamped with from=ctx->full_jid (bare) to prevent
     * spoofing (RFC 6120 §8.1.2).
     * ------------------------------------------------------------------ */
    if (stanza->type == XMPP_PRESENCE_SUBSCRIBE || stanza->type == XMPP_PRESENCE_SUBSCRIBED || stanza->type == XMPP_PRESENCE_UNSUBSCRIBE || stanza->type == XMPP_PRESENCE_UNSUBSCRIBED) {
        const char *ptype = (stanza->type == XMPP_PRESENCE_SUBSCRIBE) ? "subscribe" :
                            (stanza->type == XMPP_PRESENCE_SUBSCRIBED) ? "subscribed" :
                            (stanza->type == XMPP_PRESENCE_UNSUBSCRIBE) ? "unsubscribe" : "unsubscribed";

        /* Build bare sender JID (RFC 6120 §2.1) */
        char bare_from[64] = {0};

        strncpy(bare_from, ctx->full_jid, sizeof(bare_from) - 1);

        char *slash = strchr(bare_from, '/');

        if (slash) {
            *slash = '\0';
        }

        /* Build bare target JID for matching */
        char bare_target[64] = {0};

        strncpy(bare_target, stanza->to, sizeof(bare_target) - 1);

        slash = strchr(bare_target, '/');

        if (slash) {
            *slash = '\0';
        }

        /* FIX Bug 12 — CRITICAL: format string injection via relay buffer.
         *
         * The original code built a template string:
         *   snprintf(relay, …, "<presence … from='%s' to='%%s'/>", bare_from)
         * then used it as a format string in a second snprintf:
         *   snprintf(msg, …, relay, client_registry[i].full_jid)
         *
         * bare_from is derived from ctx->full_jid → ctx->username, which
         * comes from the SASL PLAIN payload supplied by the remote client.
         * A username containing '%' characters (e.g. "evil%s%n") would be
         * interpreted as format specifiers in the second snprintf, enabling
         * arbitrary stack reads (%s), integer writes (%n), and in the
         * worst case remote code execution.
         *
         * Fix: eliminate the two-pass relay template entirely.  Build the
         * final stanza directly in a single snprintf that fills in both
         * bare_from and the recipient's full JID in one call.  There is no
         * longer any intermediate buffer that could be mis-treated as a
         * format string. */
        int delivered = 0;

        for (int i = 0; i < MAX_USERS; i++) {
            if (client_registry[i].pcb == NULL) {
                continue;
            }
            if (client_registry[i].state < STATE_SESSION) {
                continue;
            }

            char bare_reg[64] = {0};

            strncpy(bare_reg, client_registry[i].full_jid, sizeof(bare_reg) - 1);

            slash = strchr(bare_reg, '/');

            if (slash) {
                *slash = '\0';
            }

            if (strcmp(bare_target, bare_reg) == 0) {
                /* Bug 12 fix: single snprintf, no intermediate format string */
                char msg[512];
                snprintf(msg, sizeof(msg),
                    "<presence type='%s' from='%s' to='%s'/>",
                    ptype, bare_from, client_registry[i].full_jid);

                send_raw(&client_registry[i], msg);
                delivered = 1;
            }
        }

        /* RFC 6121 §4.3 — if the target has no active session, queue
         * the stanza for delivery when they next send initial presence.
         * Extract the localpart (username) from bare_target for keying. */
        if (!delivered) {
            char to_user[32] = {0};
            const char *at = strchr(bare_target, '@');
            
            if (at) {
                int ulen = (int)(at - bare_target);
                
                if (ulen >= (int)sizeof(to_user)) {
                    ulen = (int)sizeof(to_user) - 1;
                }

                strncpy(to_user, bare_target, ulen);
            }
            else {
                strncpy(to_user, bare_target, sizeof(to_user) - 1);
            }

            pending_sub_enqueue(ptype, bare_from, to_user);
        }

        return;
    }

    char response[512];

    /* ------------------------------------------------------------------
     * RFC 6121 §4.2.2 — broadcast presence update to every connected
     * client that has completed session establishment.
     *
     * FIX (§4 ⚠ Partial — unavailable presence):
     * stanza->type is now XMPP_PRESENCE_UNAVAILABLE when the client sent
     * type='unavailable'. Previously this was detected via strstr() on
     * stanza->payload, which is the INNER content and does not contain
     * the outer 'type' attribute — making the check silently incorrect.
     * Using stanza->type is both correct and cheaper.
     *
     * Slots with pcb == NULL or state < STATE_SESSION are skipped. */
    int is_unavailable = (stanza->type == XMPP_PRESENCE_UNAVAILABLE);

    for (int i = 0; i < MAX_USERS; i++) {
        if (client_registry[i].pcb == NULL) {
            continue;
        }
        if (client_registry[i].state < STATE_SESSION) {
            continue;
        }

        if (is_unavailable) {
            snprintf(response, sizeof(response),
                "<presence from='%s' to='%s' type='unavailable'>"
                  "<status>Offline</status>"
                "</presence>",
                ctx->full_jid, client_registry[i].full_jid);
        }
        else {
            snprintf(response, sizeof(response),
                "<presence from='%s' to='%s' id='%s'>"
                  "<status>Online</status>"
                "</presence>",
                ctx->full_jid, client_registry[i].full_jid, stanza->id);
        }

        send_raw(&client_registry[i], response);
    }
}