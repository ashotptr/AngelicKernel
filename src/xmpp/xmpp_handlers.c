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
            /* TODO: RFC 6120 §13.9.1 — return -1 here and send
             * <failure><incorrect-encoding/></failure> in handle_sasl(). */
            continue;
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
 * TODO — roster versioning (session log: "add ver attribute"):
 *   RFC 6121 §2.6 — if the client includes 'ver' in the get request,
 *   the server SHOULD include 'ver' in the result and MAY send only
 *   the delta since that version.
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-2.6
 *
 * TODO — roster set / push (session log: "handle this set, get cases"):
 *   RFC 6121 §2.1.5 — Roster Set: client adds/updates a contact.
 *   RFC 6121 §2.1.6 — Roster Push: server distributes the change to
 *     all of the user's active resources.
 *   RFC 6121 §2.2   — Removing a roster item (subscription='remove').
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-2.1.5
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-2.1.6
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-2.2
 * ------------------------------------------------------------------ */
void handle_roster_request(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[512];

    /* RFC 6121 §2.1.4 — empty roster result */
    snprintf(response, sizeof(response),
        "<iq type='result' id='%s' to='%s'>"
          "<query xmlns='jabber:iq:roster'/>"
        "</iq>",
        stanza->id, ctx->full_jid);

    send_raw(ctx, response);
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
 *   BUG: we only reflect presence back to the sender. We should
 *   iterate all active client contexts and broadcast to each.
 *   TODO: maintain a global ctx array and iterate it here.
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
 * TODO — entity capabilities (session log: "deal with <c tag"):
 *   The client's presence includes
 *     <c xmlns='http://jabber.org/protocol/caps' hash='sha-1'
 *        node='https://gajim.org' ver='...'/>
 *   XEP-0115 — Entity Capabilities. Handling it lets us reply correctly
 *   to disco#info queries addressed to the client JID.
 *   https://xmpp.org/extensions/xep-0115.html
 *
 * TODO — pending subscription delivery:
 *   RFC 6121 §4.3 — on initial presence, server SHOULD deliver any
 *   pending subscription requests that arrived while offline.
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-4.3
 *
 * TODO — presence probing (session log: "use only when I get 4.3.1 done"):
 *   RFC 6121 §4.3.1 — probe each subscribed contact for their status.
 *   RFC 6121 §4.3.2 / §4.3.2.1 — handle probe responses.
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
 * Sizing rationale (all bounds derived from xmpp_core.h / xmpp_stanza_t):
 *
 *   username  — xmpp_client_ctx_t.username[32]  → 32 bytes
 *   namespace — xmpp_stanza_t.xmlns[128]         → 128 bytes (PRIVATE_NS_MAX)
 *   inner xml — stanza->payload[1024] minus the
 *               <query xmlns='jabber:iq:private'> wrapper (~38 chars)
 *               and </query> (8 chars) ≈ 978 chars usable;
 *               capped at 900 to leave headroom.   → PRIVATE_XML_MAX
 *
 *   PRIVATE_STORAGE_SLOTS — MAX_USERS(10) × ~2 namespaces per user.
 *   Increase if more namespaces per user are needed.
 * =========================================================================== */
#define PRIVATE_STORAGE_SLOTS  20
#define PRIVATE_NS_MAX        128   /* must match xmpp_stanza_t.xmlns[128]  */
#define PRIVATE_XML_MAX       900   /* conservative inner-xml ceiling        */

typedef struct {
    char username[32];              /* matches xmpp_client_ctx_t.username   */
    char ns[PRIVATE_NS_MAX];
    char xml[PRIVATE_XML_MAX];
    int  active;
} private_store_entry_t;

/* File-scope store — zero-initialised at startup; no heap needed. */
static private_store_entry_t private_store[PRIVATE_STORAGE_SLOTS];


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
 *     'owner'  — return first active participant as a proxy owner.
 *                TODO: store the real creator JID in room_t.
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
 * TODO — affiliation change (IQ-set):
 *   XEP-0045 §9.3 — kick (role → none): send type='unavailable' presence
 *     with status code 307 to all occupants.
 *   XEP-0045 §9.4 — ban (affiliation → outcast): send type='unavailable'
 *     presence with status code 301 to all occupants.
 *   https://xmpp.org/extensions/xep-0045.html#kick
 *   https://xmpp.org/extensions/xep-0045.html#ban
 * ------------------------------------------------------------------ */
void handle_muc_admin(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];

    int want_owner  = strstr(stanza->payload, "affiliation='owner'")  || strstr(stanza->payload, "affiliation=\"owner\"");
    int want_admin  = strstr(stanza->payload, "affiliation='admin'")  || strstr(stanza->payload, "affiliation=\"admin\"");
    int want_member = strstr(stanza->payload, "affiliation='member'") || strstr(stanza->payload, "affiliation=\"member\"");

    if (want_owner) {
        /* XEP-0045 §9.5 — owner list.
         * Find first active occupant as a proxy for the owner.
         * TODO: add a creator_jid field to room_t set in handle_muc_presence(). */
        char owner_jid[64] = {0};
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
 *   XEP-0045 §10.2.
 *   https://xmpp.org/extensions/xep-0045.html#roomconfig
 *   https://xmpp.org/extensions/xep-0004.html
 *   TODO: add real room config fields: muc_persistent, muc_open,
 *   muc_moderated, muc_membersonly, roomname, roomdesc, etc.
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
 *   A newly created room MUST be in a "locked" state until the owner
 *   submits this config form. We create the room immediately active
 *   inside handle_muc_presence(), so the locked state is skipped.
 *   Acceptable for embedded single-room use; document as a known
 *   deviation.
 *   https://xmpp.org/extensions/xep-0045.html#createroom
 * ------------------------------------------------------------------ */
void handle_muc_owner(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];

    if (stanza->type == XMPP_IQ_SET || strstr(stanza->payload, "type='submit'") || strstr(stanza->payload, "type=\"submit\"")) {
        /* XEP-0045 §10.2 / §10.1.2 — instant room config accepted */
        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s' from='%s'/>",
            stanza->id, ctx->full_jid, stanza->to);
    }
    else {
        /* XEP-0045 §10.2 — return room configuration Data Form.
         * XEP-0004 §3.2  — type='form'.
         * TODO: populate full room config fields per XEP-0045 §10.2. */
        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s' from='%s'>"
              "<query xmlns='http://jabber.org/protocol/muc#owner'>"
                "<x xmlns='jabber:x:data' type='form'>"
                  "<field type='hidden' var='FORM_TYPE'>"
                    "<value>http://jabber.org/protocol/muc#roomconfig</value>"
                  "</field>"
                "</x>"
              "</query>"
            "</iq>",
            stanza->id, ctx->full_jid, stanza->to);
    }

    send_raw(ctx, response);
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
 *   TODO: add room feature elements (muc_open, muc_persistent, etc.)
 *   to reflect the room's actual configuration.
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
             * TODO: add feature elements for room configuration flags. */
            snprintf(response, sizeof(response),
                "<iq type='result' from='%s' to='%s' id='%s'>"
                  "<query xmlns='http://jabber.org/protocol/disco#info'>"
                    "<identity category='conference' type='text' name='%s'/>"
                    "<feature var='http://jabber.org/protocol/muc'/>"
                  "</query>"
                "</iq>",
                stanza->to, ctx->full_jid, stanza->id, room_name);
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
         * FIX (§3 LOW): Return category='account' type='registered'
         * per XEP-0030 §4; server identity only correct on bare domain. */
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
        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
              "<query xmlns='http://jabber.org/protocol/disco#info'>"
                "<identity category='server' type='im' name='Unikernel XMPP'/>"
                "<feature var='http://jabber.org/protocol/muc'/>"
                "<feature var='jabber:iq:register'/>"
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
 * Processes the SASL <auth> element and grants access.
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
 *     authcid — authentication identity = username
 *     passwd  — password (read but not verified)
 *   https://datatracker.ietf.org/doc/html/rfc4616#section-2
 *   Decoded "AHVzZXIxAGFzZGY=" → "\x00user1\x00asdf"
 *   The code correctly skips authzid and reads authcid.
 *
 * ANONYMOUS mechanism:
 *   RFC 4505 — empty payload; len ≤ 1, username defaults to "user".
 *   https://datatracker.ietf.org/doc/html/rfc4505
 *
 * SEND:
 *   RFC 6120 §6.4.6 — on success:
 *     <success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>
 *   Client MUST then open a new XML stream.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-6.4.6
 *
 * NOTE — code duplication:
 *   The tcp_write / state-update block here duplicates handle_sasl_success()
 *   in xmpp_server.c. TODO: refactor to call handle_sasl_success(ctx).
 *
 * SECURITY ISSUES:
 *
 *   1. No credential verification:
 *      We always succeed. For PLAIN, password is decoded but ignored.
 *      RFC 6120 §6.5 — on bad credentials MUST send:
 *        <failure><not-authorized/></failure>
 *        https://datatracker.ietf.org/doc/html/rfc6120#section-6.5
 *
 *   2. No Base64 validation:
 *      RFC 6120 §13.9.1 — MUST verify encoding; see b64decode() note.
 *      (Session log: "on importance of checking base64 format in the request"
 *       — https://datatracker.ietf.org/doc/html/rfc6120#section-13.9.1)
 *
 *   3. PLAIN over cleartext:
 *      RFC 6120 §13.8.4 — PLAIN MUST NOT be used without TLS.
 *      Acceptable for closed LAN only.
 *      https://datatracker.ietf.org/doc/html/rfc6120#section-13.8.4
 *      (Session log: "https://datatracker.ietf.org/doc/html/rfc6120#section-13.8")
 *
 *   4. No <abort/> handling:
 *      RFC 6120 §6.5 — client may send <abort/>; server MUST reply
 *        <failure><aborted/></failure>.
 *
 *   5. No invalid-mechanism handling:
 *      RFC 6120 §6.5.5 — mechanism not in offered list MUST reply
 *        <failure><invalid-mechanism/></failure>.
 *      (Noted in xmpp_server.c receive callback comment)
 *      https://datatracker.ietf.org/doc/html/rfc6120#section-6.5
 *
 *   RFC 6120 §6.3.7 — simple user name / realm rules (both optional):
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6.3.7
 *   RFC 6120 §6.4   — full SASL exchange process:
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6.4
 * ------------------------------------------------------------------ */
void handle_sasl(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    unsigned char decoded[128] = {0};

    /* RFC 4616 §2 / RFC 6120 §6.4.2 — decode Base64 PLAIN payload.
     * TODO: treat b64decode() returning an error indicator as a signal
     * to send <failure><incorrect-encoding/></failure>. */
    int len = b64decode(stanza->payload, decoded, sizeof(decoded) - 1);

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

    /* TODO: verify password against expected credentials.
     * On failure: send <failure><not-authorized/></failure>
     * (RFC 6120 §6.5) and return without setting authenticated = 1. */

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
 *   XEP-0045 §7.1 — Entering a Room: client sends
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
 *     clients' TCP connections. Works because send_raw() only reads pcb,
 *     but is fragile. TODO: a global (jid → ctx*) or (pcb → ctx*) map
 *     would be cleaner and safer.
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
        /* XEP-0045 §10.1 — create room; ideally mark as locked here */
        for (int i = 0; i < MAX_ROOMS; i++) {
            if (!rooms[i].active) {
                r = &rooms[i];
                r->active = 1;

                strcpy(r->name, room_name);

                is_new_room = 1;

                break;
            }
        }
    }

    if (!r) {
        return; /* Room pool exhausted */
    }

    /* TODO: XEP-0045 §7.2.8 — nick conflict check before adding user.
     * Iterate r->users[], compare nick; if taken send presence error. */

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

    /* SEND 1: XEP-0045 §7.2 — existing occupants → new user */
    for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
        if (!r->users[i].active) {
            continue;
        }

        if (strcmp(r->users[i].jid, ctx->full_jid) == 0) {
            continue;
        }

        snprintf(response, sizeof(response),
            "<presence from='%s/%s' to='%s'>"
              "<x xmlns='http://jabber.org/protocol/muc#user'>"
                "<item affiliation='member' role='participant' jid='%s'/>"
              "</x>"
            "</presence>",
            bare_jid, r->users[i].nick, ctx->full_jid, r->users[i].jid);

        send_raw(ctx, response);
    }

    /* SEND 2: XEP-0045 §7.2 — new user's presence → all existing occupants */
    for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
        if (!r->users[i].active) {
            continue;
        }

        if (strcmp(r->users[i].jid, ctx->full_jid) == 0) {
            continue;
        }

        xmpp_client_ctx_t target_ctx; /* only pcb is used by send_raw() */
        target_ctx.pcb = r->users[i].pcb;

        snprintf(response, sizeof(response),
            "<presence from='%s/%s' to='%s'>"
              "<x xmlns='http://jabber.org/protocol/muc#user'>"
                "<item affiliation='member' role='participant' jid='%s'/>"
              "</x>"
            "</presence>",
            bare_jid, nick, r->users[i].jid, ctx->full_jid);

        send_raw(&target_ctx, response);
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

    /* TODO: XEP-0045 §7.2.13 — send discussion history after subject.
     * Minimum valid implementation: send nothing (zero messages).
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
 *   TODO — RFC 6121 §5.2.5: <thread> element for conversation threading.
 *     (Session log: "for thread stanza, but I do not handle it for now")
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-5.2.5
 *
 *   TODO — RFC 6121 §5.3 / XEP-0071: XHTML-IM body formatting.
 *     (Session log: "for xhtml")
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
 *   BUG — message not delivered to recipient:
 *     We call send_raw(ctx, ...) which writes back to the sender, not
 *     the intended recipient. To route properly we need a global
 *     (full_jid → xmpp_client_ctx_t*) map.
 *     TODO: implement a global client registry and look up stanza->to.
 *     For offline users: XEP-0160 — Message Offline Storage.
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
         * to   = each occupant's real full JID */
        for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
            if (!r->users[i].active) {
                continue;
            }

            xmpp_client_ctx_t target_ctx;
            target_ctx.pcb = r->users[i].pcb;

            if (already_wrapped) {
                snprintf(response, sizeof(response),
                    "<message from='%s/%s' to='%s' type='groupchat' id='%s'>"
                      "%s"
                    "</message>",
                    stanza->to, sender_nick, r->users[i].jid,
                    stanza->id, stanza->payload);
            }
            else {
                snprintf(response, sizeof(response),
                    "<message from='%s/%s' to='%s' type='groupchat' id='%s'>"
                      "<body>%s</body>"
                    "</message>",
                    stanza->to, sender_nick, r->users[i].jid,
                    stanza->id, stanza->payload);
            }

            send_raw(&target_ctx, response);
        }
    }
    else {
        /* --- Direct message: RFC 6121 §5.1 ---
         * FIX (§3 HIGH): from/to corrected; was stanza->to / ctx->full_jid.
         * TODO: look up stanza->to in a global ctx registry and route there.
         * For offline users: XEP-0160 — Message Offline Storage. */
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

        send_raw(ctx, response);
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
 *   (Session log: "also make sure to broadcast")
 *   BUG: we only reflect presence back to the sender itself.
 *   TODO: iterate all active client contexts and deliver the presence
 *   update to each connected user.
 *
 * State transition:
 *   Advance to STATE_READY as a fallback for clients that skip the
 *   session IQ (handle_core_session also sets STATE_READY).
 *
 * TODO — subscription handling:
 *   RFC 6121 §3.1.3 — 'subscribe': deliver or store the request.
 *   RFC 6121 §3.1.4 — 'subscribed'/'unsubscribed': update the roster.
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-3.1
 *
 * TODO — presence probing (session log: "use only when I get 4.3.1 done"):
 *   RFC 6121 §4.3.1 — on initial presence, probe each subscribed contact.
 *   RFC 6121 §4.3.2 / §4.4 — handle probe responses.
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-4.3.1
 *
 * TODO — XEP reviews noted in session log:
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

    char response[512];

    /* RFC 6121 §4.2.2 — broadcast presence update to every connected
     * client that has completed session establishment.
     *
     * 'type' is forwarded verbatim so that 'unavailable', 'away', etc.
     * are correctly reflected to all peers.  An empty type means the
     * user is available (RFC 6121 §4.2 — initial/available presence).
     *
     * Slots with pcb == NULL or state < STATE_SESSION are skipped for
     * the same reasons as in handle_initial_presence(). */
    const char *ptype = stanza->type == XMPP_PRESENCE ? "" : "unavailable";
    /* Determine whether the sender is going unavailable so we can
     * carry the correct type attribute in the broadcast. */
    int is_unavailable = (strstr(stanza->payload, "type='unavailable'") != NULL ||
                          strstr(stanza->payload, "type=\"unavailable\"") != NULL);

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
        } else {
            snprintf(response, sizeof(response),
                "<presence from='%s' to='%s' id='%s'>"
                  "<status>Online</status>"
                "</presence>",
                ctx->full_jid, client_registry[i].full_jid, stanza->id);
        }

        send_raw(&client_registry[i], response);
    }
}