#include "xmpp_core.h"
#include <stdio.h>
#include <string.h>

/* ============================================================
 * xmpp_store.c — Persistent in-memory stores
 *
 * Implements two stores that survive across client reconnections
 * within the lifetime of the running server:
 *
 *   1. XEP-0160 Offline Message Queue
 *      https://xmpp.org/extensions/xep-0160.html
 *      Messages addressed to users with no active session are held
 *      here and delivered (with XEP-0203 delay notation) the next
 *      time that user sends initial presence.
 *
 *   2. RFC 6121 §2 Per-User Roster Store
 *      https://datatracker.ietf.org/doc/html/rfc6121#section-2
 *      Roster <item/> elements submitted via IQ-set are persisted
 *      per (username, contact-jid) and returned on roster IQ-get.
 *
 * Design constraints (bare-metal unikernel):
 *   - No heap / no malloc; all storage is statically allocated BSS.
 *   - No filesystem; persistence ends when the kernel is reset.
 *   - All buffer sizes derived from limits in xmpp_core.h so that
 *     the two layers stay in sync automatically.
 * ============================================================ */


/* ============================================================
 * §1  OFFLINE MESSAGE STORE — XEP-0160
 * ============================================================
 *
 * Capacity: MAX_OFFLINE_MSGS slots shared across all users.
 * Per-slot memory:
 *   from[64] + to_bare[64] + to_user[32] + id[64] + payload[1024]
 *   + active[4]  ≈  1252 bytes
 * Total BSS for this store: 32 × 1252 ≈ 40 KB.
 *
 * XEP-0160 §3 — Message type handling (caller is responsible for
 * calling offline_msg_enqueue only for storable types):
 *   normal    — SHOULD be stored   (type='normal' or absent)
 *   chat      — SHOULD be stored
 *   groupchat — MUST NOT be stored (user cannot be in a MUC room
 *               if they have no available resource)
 *   headline  — SHOULD NOT be stored (time-sensitive)
 *   error     — SHOULD NOT be stored
 *
 * XEP-0160 §2 — Offline Storage Process:
 *   1. Sender generates message stanza for unavailable recipient.
 *   2. Server determines recipient has no available resource.
 *   3. Server stores the stanza for later delivery.
 *   4. On next initial presence from recipient, server delivers all
 *      queued messages (each with XEP-0203 <delay/> stamp).
 * ============================================================ */

/* MAX_OFFLINE_MSGS and offline_msg_t are defined in xmpp_core.h so that
 * xmpp_persist.c can access this array via the extern declared there.
 * Non-static: xmpp_persist.c saves and restores this array at boot. */
offline_msg_t offline_store[MAX_OFFLINE_MSGS];


/* ------------------------------------------------------------------
 * offline_msg_enqueue
 *
 * XEP-0160 §2 step 3 — store a message for an offline recipient.
 *
 * Parameters:
 *   to_bare  — recipient's bare JID (user@domain)
 *   from_jid — sender's full JID (already stamped by the router per
 *              RFC 6120 §8.1.2 — server MUST overwrite 'from')
 *   msg_id   — stanza 'id' attribute (may be empty string)
 *   payload  — verbatim inner XML from xmpp_stanza_t.payload
 *
 * Queue-full policy:
 *   XEP-0160 §2 — if the server cannot store the message it MUST
 *   return <service-unavailable/> to the sender.  We return -1 so
 *   the caller (handle_chat_message) can send that error.
 *
 * Returns 0 on success, -1 if the queue is full.
 * ------------------------------------------------------------------ */
int offline_msg_enqueue(const char *to_bare, const char *from_jid, const char *msg_id,  const char *payload) {
    /* Extract localpart (username) from to_bare for drain lookup */
    char to_user[32] = {0};
    const char *at = strchr(to_bare, '@');

    if (at) {
        int ulen = (int)(at - to_bare);
        
        if (ulen >= (int)sizeof(to_user)) {
            ulen = (int)sizeof(to_user) - 1;
        }

        strncpy(to_user, to_bare, ulen);
    }
    else {
        strncpy(to_user, to_bare, sizeof(to_user) - 1);
    }

    /* Claim a free slot */
    for (int i = 0; i < MAX_OFFLINE_MSGS; i++) {
        if (offline_store[i].active) continue;

        strncpy(offline_store[i].from, from_jid, sizeof(offline_store[i].from) - 1);
        strncpy(offline_store[i].to_bare, to_bare, sizeof(offline_store[i].to_bare) - 1);
        strncpy(offline_store[i].to_user, to_user, sizeof(offline_store[i].to_user) - 1);
        strncpy(offline_store[i].id, msg_id, sizeof(offline_store[i].id) - 1);
        strncpy(offline_store[i].payload, payload, sizeof(offline_store[i].payload) - 1);

        offline_store[i].from[sizeof(offline_store[i].from) - 1] = '\0';
        offline_store[i].to_bare[sizeof(offline_store[i].to_bare) - 1] = '\0';
        offline_store[i].to_user[sizeof(offline_store[i].to_user) - 1] = '\0';
        offline_store[i].id[sizeof(offline_store[i].id) - 1] = '\0';
        offline_store[i].payload[sizeof(offline_store[i].payload) - 1] = '\0';

        offline_store[i].active = 1;

        /* Write-through: persist immediately so queued messages survive
         * a server restart (XEP-0160 §2 — storage is server-side). */
        xmpp_persist_save_offline();

        return 0;
    }

    return -1; /* queue full — caller must send <service-unavailable/> */
}


/* ------------------------------------------------------------------
 * offline_msg_drain
 *
 * XEP-0160 §2 step 4 — deliver all queued messages to a newly
 * available user and remove them from the store.
 *
 * Called from handle_initial_presence() after the presence broadcast
 * and pending subscription drain (RFC 6121 §4.3).
 *
 * XEP-0203 — Delayed Delivery:
 *   Each delivered message is annotated with a <delay> element so
 *   the client can distinguish live messages from stored ones.
 *   https://xmpp.org/extensions/xep-0203.html
 *
 *   The 'stamp' attribute SHOULD hold the original storage time.
 *   This server has no wall-clock RTC; we emit a fixed epoch marker
 *   "1970-01-01T00:00:00Z" which clients will render as "stored" and
 *   sort before any live messages, which is the correct UX intent.
 *   Replace with a real timestamp if RTC support is added.
 *
 * XEP-0160 §2 Listing 3 — delivered message example:
 *   <message from='romeo@montague.net/orchard' to='juliet@capulet.com'>
 *     <body>...</body>
 *     <delay xmlns='urn:xmpp:delay' from='capulet.com'
 *            stamp='2002-09-10T23:08:25Z'>Offline Storage</delay>
 *   </message>
 * ------------------------------------------------------------------ */
void offline_msg_drain(xmpp_client_ctx_t *ctx) {
    /* Buffer for the reconstructed delivered stanza.
     * Ceiling:
     *   <message from=...> wrapper  ≈  120 chars
     *   payload (inner XML)         ≤ 1024 chars
     *   <delay .../>                ≈   80 chars
     *   </message>                  =   10 chars
     *   Total                       ≤ ~1240 chars → 1400-byte buffer is safe */
    char out[1400];

    for (int i = 0; i < MAX_OFFLINE_MSGS; i++) {
        if (!offline_store[i].active) {
            continue;
        }

        if (strcmp(offline_store[i].to_user, ctx->username) != 0) {
            continue;
        }

        int written;

        if (offline_store[i].id[0] != '\0') {
            written = snprintf(out, sizeof(out),
                "<message from='%s' to='%s' type='chat' id='%s'>"
                  "%s"
                  "<delay xmlns='urn:xmpp:delay'"
                         " from='" XMPP_DOMAIN "'"
                         " stamp='1970-01-01T00:00:00Z'>"
                    "Offline Storage"
                  "</delay>"
                "</message>",
                offline_store[i].from,
                ctx->full_jid,
                offline_store[i].id,
                offline_store[i].payload);
        }
        else {
            written = snprintf(out, sizeof(out),
                "<message from='%s' to='%s' type='chat'>"
                  "%s"
                  "<delay xmlns='urn:xmpp:delay'"
                         " from='" XMPP_DOMAIN "'"
                         " stamp='1970-01-01T00:00:00Z'>"
                    "Offline Storage"
                  "</delay>"
                "</message>",
                offline_store[i].from,
                ctx->full_jid,
                offline_store[i].payload);
        }

        if (written > 0 && (size_t)written < sizeof(out)) {
            send_raw(ctx, out);
        }

        offline_store[i].active = 0;
    }

    /* Persist the updated store once after the entire drain loop.
     * Calling save per-message would be wasteful; the entire array
     * state is written atomically here instead. */
    xmpp_persist_save_offline();
}


/* ------------------------------------------------------------------
 * offline_msg_is_full
 *
 * Returns 1 if the per-user offline queue is at or above the per-user
 * soft cap, 0 otherwise.
 *
 * XEP-0160 §2 — the spec does not mandate per-user limits but
 * reserving at most half the total pool for a single user prevents
 * one user from starving all others.
 * ------------------------------------------------------------------ */
int offline_msg_is_full(const char *to_user) {
    int count = 0;
    
    for (int i = 0; i < MAX_OFFLINE_MSGS; i++) {
        if (offline_store[i].active && strcmp(offline_store[i].to_user, to_user) == 0) {
            count++;
        }
    }

    return (count >= MAX_OFFLINE_MSGS / 2);
}


/* ============================================================
 * §2  ROSTER STORE — RFC 6121 §2
 * ============================================================
 *
 * Stores per-user contact lists as individual <item/> elements,
 * keyed by (username, contact-jid).
 *
 * Capacity: MAX_ROSTER_ENTRIES slots shared across all users.
 * With MAX_USERS=10 this gives ~8 contacts per user on average.
 * Per-slot memory:
 *   username[32] + jid[64] + item_xml[256] + active[4] = 356 bytes
 * Total BSS: 80 × 356 ≈ 28 KB.
 *
 * RFC 6121 §2.1.5 — Roster Set:
 *   A roster IQ-set with subscription='remove' MUST delete the entry;
 *   any other set upserts it.
 *
 * RFC 6121 §2.1.3 / §2.1.4 — Roster Get / Result:
 *   roster_store_get_items() builds the sequence of <item/> elements
 *   that the server embeds in the <query> result body.
 * ============================================================ */

/* MAX_ROSTER_ENTRIES, ROSTER_ITEM_MAX_LEN, and roster_entry_t are
 * defined in xmpp_core.h so that xmpp_persist.c can also use them.
 * Do NOT redefine them here. */

/* Non-static: xmpp_persist.c accesses this array via the extern
 * declaration in xmpp_core.h to save/load it to the ATA data disk. */
roster_entry_t roster_store[MAX_ROSTER_ENTRIES];


/* ------------------------------------------------------------------
 * roster_extract_jid  (internal helper)
 *
 * Extracts the value of the jid= attribute from an <item ...> element.
 * Returns 1 on success, 0 if no jid= attribute is found.
 * ------------------------------------------------------------------ */
static int roster_extract_jid(const char *item_xml, char *jid_out, int jid_max) {
    const char *p = strstr(item_xml, "jid=");
    if (!p) {
        return 0;
    }

    p += 4; /* skip "jid=" */
    char q = *p;
    
    if (q != '\'' && q != '"') {
        return 0;
    }

    p++;

    const char *end = strchr(p, q);
    
    if (!end) {
        return 0;
    }

    int len = (int)(end - p);
    
    if (len >= jid_max) {
        len = jid_max - 1;
    }
    
    strncpy(jid_out, p, len);
    
    jid_out[len] = '\0';
    
    return 1;
}


/* ------------------------------------------------------------------
 * roster_store_upsert_item
 *
 * RFC 6121 §2.1.5 — stores or updates a single roster <item/> for
 * the given username.  An item with subscription='remove' causes
 * deletion of the existing entry.
 *
 * item_xml must be a complete self-closing element, e.g.:
 *   <item jid='friend@example.com' name='Friend' subscription='both'/>
 *
 * Returns 0 on success, -1 on failure (no jid= attribute, or store full).
 * ------------------------------------------------------------------ */
int roster_store_upsert_item(const char *username, const char *item_xml) {
    char contact_jid[64] = {0};

    if (!roster_extract_jid(item_xml, contact_jid, sizeof(contact_jid))) {
        return -1; /* malformed <item> — no jid= attribute */
    }

    /* RFC 6121 §2.1.5 — subscription='remove' → delete the entry */
    int is_remove = (strstr(item_xml, "subscription='remove'") != NULL ||
                     strstr(item_xml, "subscription=\"remove\"") != NULL);

    /* Locate existing (username, jid) slot */
    roster_entry_t *slot = NULL;
    for (int i = 0; i < MAX_ROSTER_ENTRIES; i++) {
        if (!roster_store[i].active) {
            continue;
        }

        if (strncmp(roster_store[i].username, username, 32) != 0) {
            continue;
        }

        if (strncmp(roster_store[i].jid, contact_jid, 64) != 0) {
            continue;
        }

        slot = &roster_store[i];
        
        break;
    }

    if (is_remove) {
        if (slot) {
            slot->active = 0;
        }

        xmpp_persist_save_roster(); /* persist the deletion */
        
        return 0;
    }

    /* Upsert: if no existing slot, claim a free one */
    if (!slot) {
        for (int i = 0; i < MAX_ROSTER_ENTRIES; i++) {
            if (!roster_store[i].active) {
                slot = &roster_store[i];

                break;
            }
        }
    }

    if (!slot) {
        return -1; /* store full */
    }

    strncpy(slot->username, username, sizeof(slot->username) - 1);
    strncpy(slot->jid, contact_jid, sizeof(slot->jid) - 1);

    int xml_len = (int)strlen(item_xml);
    
    if (xml_len >= ROSTER_ITEM_MAX_LEN) {
        xml_len = ROSTER_ITEM_MAX_LEN - 1;
    }

    strncpy(slot->item_xml, item_xml, xml_len);

    slot->username[sizeof(slot->username) - 1] = '\0';
    slot->jid[sizeof(slot->jid) - 1] = '\0';
    slot->item_xml[xml_len] = '\0';

    slot->active = 1;

    /* Write-through: commit roster change to disk (ATA data drive)
     * immediately so it survives a reboot. Also called for remove
     * (active=0) above via the early-return path. */
    xmpp_persist_save_roster();

    return 0;
}


/* ------------------------------------------------------------------
 * roster_store_set_from_payload
 *
 * RFC 6121 §2.1.5 — parses the <query ...> payload from a roster
 * IQ-set and calls roster_store_upsert_item() for each <item/>.
 *
 * stanza->payload for a roster set looks like:
 *   <query xmlns='jabber:iq:roster'>
 *     <item jid='friend@example.com' name='Friend' subscription='both'/>
 *   </query>
 *
 * We scan for every occurrence of "<item " and extract up to the
 * first matching ">" (self-closing or with children).  Each extracted
 * element string is passed to roster_store_upsert_item().
 *
 * Handles both self-closing (<item .../>) and element-with-children
 * (<item ...>...</item>) forms; only the opening tag (up to the first
 * '>') is stored since child elements are not used by our roster store.
 * ------------------------------------------------------------------ */
void roster_store_set_from_payload(const char *username, const char *payload) {
    const char *p = payload;
    char item_buf[ROSTER_ITEM_MAX_LEN];

    while ((p = strstr(p, "<item ")) != NULL) {
        /* Find end of opening tag */
        const char *end = strchr(p, '>');
        
        if (!end) {
            break;
        }

        /* Include the closing '>' to form a valid self-closing element.
         * If the tag is not self-closing (doesn't end with '/>')
         * we add '/>' to make it so; we only care about attributes. */
        int len = (int)(end - p) + 1; /* include '>' */
        
        if (len >= ROSTER_ITEM_MAX_LEN) {
            len = ROSTER_ITEM_MAX_LEN - 1;
        }

        strncpy(item_buf, p, len);
        item_buf[len] = '\0';

        /* Ensure element is self-closing */
        if (len >= 2 && item_buf[len - 2] != '/') {
            /* Replace trailing '>' with '/>' */
            if (len < ROSTER_ITEM_MAX_LEN - 1) {
                item_buf[len - 1] = '/';
                item_buf[len] = '>';
                item_buf[len + 1] = '\0';
            }
        }

        roster_store_upsert_item(username, item_buf);

        p = end + 1; /* advance past this <item> */
    }
}


/* ------------------------------------------------------------------
 * roster_store_get_items
 *
 * RFC 6121 §2.1.4 — builds the concatenated <item/> XML that the
 * server embeds inside <query xmlns='jabber:iq:roster'> in a result.
 *
 * Writes at most buf_len - 1 bytes into buf, NUL-terminated.
 * Returns the number of roster entries found for the user.
 * ------------------------------------------------------------------ */
int roster_store_get_items(const char *username, char *buf, int buf_len) {
    int count = 0;
    int pos = 0;

    buf[0] = '\0';

    for (int i = 0; i < MAX_ROSTER_ENTRIES; i++) {
        if (!roster_store[i].active) {
            continue;
        }
        if (strncmp(roster_store[i].username, username, 32) != 0) {
            continue;
        }

        int item_len = (int)strlen(roster_store[i].item_xml);

        if (pos + item_len >= buf_len - 1) {
            break; /* guard overflow */
        }

        memcpy(buf + pos, roster_store[i].item_xml, item_len);
        
        pos += item_len;
        buf[pos] = '\0';

        count++;
    }

    return count;
}