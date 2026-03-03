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
 *     RFC 6120 §6.5 — <failure><incorrect-encoding/></failure>
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

    /* RFC 6121 §4.2.2 — reflect presence back to sender.
     * TODO: also broadcast to all other connected clients. */
    snprintf(response, sizeof(response),
        "<presence from='%s' to='%s' xml:lang='en'>"
          "<show>chat</show>"
          "<priority>1</priority>"
        "</presence>",
        ctx->full_jid, ctx->full_jid);

    send_raw(ctx, response);
}


/* ------------------------------------------------------------------
 * handle_private_storage
 *
 * Responds to jabber:iq:private get/set requests.
 *
 * RECEIVE:
 *   XEP-0049 §3 — Private XML Storage get:
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
 *   XEP-0049 §3 — return stored private XML, or an empty element of
 *   the same namespace if nothing is stored.
 *
 * BUG — namespace mismatch:
 *   We always return <storage xmlns='storage:bookmarks'/> regardless
 *   of what was requested. When the client asks for storage:rosternotes
 *   we send the wrong namespace back.
 *   TODO: extract the inner namespace from stanza->payload (look for
 *   the xmlns= attribute inside <storage>) and echo it back, returning
 *   an empty element of that same namespace.
 *
 * BUG — set vs get:
 *   For a type='set' request we should return a plain empty IQ result
 *   (<iq type='result' id='...' to='...'/>), not a <query> body.
 *   TODO: check stanza->type == XMPP_IQ_SET and use handle_general_success()
 *   or an equivalent plain result.
 * ------------------------------------------------------------------ */
void handle_private_storage(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];

    /* XEP-0049 §3 — return empty storage element.
     * TODO: echo the correct inner namespace from stanza->payload.
     * TODO: for XMPP_IQ_SET, return a bare <iq type='result'> instead. */
    snprintf(response, sizeof(response),
        "<iq type='result' id='%s' to='%s'>"
          "<query xmlns='jabber:iq:private'>"
            "<storage xmlns='storage:bookmarks'/>"
          "</query>"
        "</iq>",
        stanza->id, ctx->full_jid);

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
 * FIXME: rand() is not a CSPRNG. See handle_handshake_logic() note in
 *   xmpp_server.c — RFC 6120 §4.7.1 requires unpredictable IDs.
 *
 * State transition:
 *   Move to STATE_SESSION. RFC 6120 §7 does not define a post-bind
 *   sub-state; session IQ (RFC 6121 §3.1) may optionally follow.
 * ------------------------------------------------------------------ */
void handle_core_bind(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    /* RFC 6120 §7.7.1 — server-generated resource */
    int resource_id = rand() % 9999;

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
 *   BUG: when to='user@angelic.local' (a user's bare JID) the correct
 *   identity is category='account' type='registered', NOT
 *   category='server' type='im'.
 *   (Session log shows commented-out correct response:
 *    "<identity category='account' type='registered'/>")
 *   TODO: if stanza->to contains '@' and does NOT contain 'conference',
 *   return the account identity instead of the server identity.
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
    else {
        /* CASE 3: server / user JID — XEP-0030 §4.
         * TODO: if '@' in stanza->to → category='account' type='registered'. */
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
 *   BUG: returns a hardcoded "Main Lobby" room regardless of which
 *   rooms are actually active in rooms[].
 *   TODO: iterate rooms[] and emit one <item/> per rooms[i].active == 1.
 *
 * CASE 2 — main server:
 *   Return the MUC service as an item so clients can discover it.
 *   (Session log shows this exchange; response is correct.)
 * ------------------------------------------------------------------ */
void handle_disco_items(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];

    if (strstr(stanza->to, "conference.angelic.local")) {
        /* CASE 1: XEP-0045 §6.3 — list of rooms.
         * TODO: build dynamically from rooms[] instead of hardcoding. */
        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
              "<query xmlns='http://jabber.org/protocol/disco#items'>"
                "<item jid='lobby@conference.angelic.local' name='Main Lobby'/>"
              "</query>"
            "</iq>",
            stanza->to, ctx->full_jid, stanza->id);
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
 *   BUG 1 — from/to reversed:
 *     The snprintf uses from='stanza->to' (the intended recipient's JID)
 *     and to='ctx->full_jid' (the sender). It should be:
 *       from='ctx->full_jid'  (the actual sender)
 *       to='stanza->to'       (the intended recipient)
 *
 *   BUG 2 — message not delivered to recipient:
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
         * BUG: from/to are swapped; message echoes to sender, not recipient.
         * TODO: look up stanza->to in a global ctx registry and route there. */
        if (already_wrapped) {
            snprintf(response, sizeof(response),
                /* BUG: should be from='%s' ctx->full_jid, to='%s' stanza->to */
                "<message from='%s' to='%s' type='chat'>%s</message>",
                stanza->to, ctx->full_jid, stanza->payload);
        }
        else {
            snprintf(response, sizeof(response),
                /* BUG: should be from='%s' ctx->full_jid, to='%s' stanza->to */
                "<message from='%s' to='%s' type='chat'>"
                  "<body>%s</body>"
                "</message>",
                stanza->to, ctx->full_jid, stanza->payload);
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

    /* RFC 6121 §4.2.2 — reflect presence to sender.
     * TODO: broadcast to all other connected clients as well. */
    snprintf(response, sizeof(response),
        "<presence from='%s' to='%s' id='%s'>"
          "<status>Online</status>"
        "</presence>",
        ctx->full_jid, ctx->full_jid, stanza->id);

    send_raw(ctx, response);
}