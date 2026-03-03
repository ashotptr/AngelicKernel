#include "xmpp_core.h"
#include <stdio.h>

typedef void (*handler_fn)(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

struct route_entry {
    const char *xmlns;
    handler_fn handler;
    client_state_t min_state;
};

/* ------------------------------------------------------------------
 * Routing table
 *
 * Each entry maps a namespace URI (as detected by the parser) to the
 * handler function responsible for that protocol feature, along with
 * the minimum connection state required before the handler may be called.
 *
 * The state ordering enforces RFC 6120's mandatory negotiation sequence
 * (§4): SASL before bind, bind before normal stanza exchange.
 *
 * RFC / XEP reference for each namespace:
 *
 *   urn:ietf:params:xml:ns:xmpp-sasl
 *     RFC 6120 §6.3  — SASL Negotiation
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6.3
 *
 *   urn:ietf:params:xml:ns:xmpp-bind
 *     RFC 6120 §7    — Resource Binding
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-7
 *
 *   urn:ietf:params:xml:ns:xmpp-session
 *     RFC 6121 §3.1  — Session Establishment (optional/legacy)
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-3.1
 *
 *   jabber:iq:roster
 *     RFC 6121 §2    — Roster Management
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-2
 *
 *   http://jabber.org/protocol/disco#info
 *     XEP-0045 §6.2  — Discovering Features of a Room or Service
 *     https://xmpp.org/extensions/xep-0045.html#disco-service
 *
 *   http://jabber.org/protocol/disco#items
 *     XEP-0045 §6.3  — Discovering Rooms
 *     https://xmpp.org/extensions/xep-0045.html#disco-rooms
 *
 *   http://jabber.org/protocol/muc
 *     XEP-0045 §7.1  — Entering a Room (presence with <x> child)
 *     https://xmpp.org/extensions/xep-0045.html#enter
 *
 *   http://jabber.org/protocol/muc#owner
 *     XEP-0045 §10   — Owner Use Cases (create, configure, destroy)
 *     https://xmpp.org/extensions/xep-0045.html#createroom
 *
 *   jabber:iq:private
 *     XEP-0049        — Private XML Storage (client config data)
 *     https://xmpp.org/extensions/xep-0049.html
 *
 *   http://jabber.org/protocol/muc#admin
 *     XEP-0045 §9    — Admin Use Cases (kick/ban/role changes)
 *     https://xmpp.org/extensions/xep-0045.html#admin
 *
 *   urn:xmpp:blocking
 *     XEP-0191        — Blocking Command (we accept but ignore)
 *     https://xmpp.org/extensions/xep-0191.html
 *
 *   vcard-temp
 *     XEP-0054        — vcard-temp (we accept but ignore)
 *     https://xmpp.org/extensions/xep-0054.html
 *
 * NOTE: "jabber:client" (for plain chat messages) is intentionally
 * NOT in this table. Chat messages are routed via the type-based
 * fallback at the bottom of xmpp_route_stanza() because a <message>
 * stanza's xmlns is set to "jabber:client" regardless of whether it
 * is a direct chat or a groupchat, and we need the stanza type to
 * distinguish them. RFC 6121 §5 — Message delivery.
 * ------------------------------------------------------------------ */
static struct route_entry router[] = {
    { "urn:ietf:params:xml:ns:xmpp-sasl", handle_sasl, STATE_CONNECTED },
    { "urn:ietf:params:xml:ns:xmpp-bind", handle_core_bind, STATE_AUTHENTICATED },
    { "urn:ietf:params:xml:ns:xmpp-session", handle_core_session, STATE_AUTHENTICATED },
    { "jabber:iq:roster", handle_roster_request, STATE_SESSION },
    { "http://jabber.org/protocol/disco#info", handle_disco_info, STATE_SESSION },
    { "http://jabber.org/protocol/disco#items", handle_disco_items, STATE_SESSION },
    { "http://jabber.org/protocol/muc", handle_muc_presence, STATE_SESSION },
    { "http://jabber.org/protocol/muc#owner", handle_muc_owner, STATE_SESSION },
    { "jabber:iq:private", handle_private_storage, STATE_SESSION },
    { "http://jabber.org/protocol/muc#admin", handle_muc_admin, STATE_SESSION },
    { "urn:xmpp:blocking", handle_general_success, STATE_SESSION },
    { "vcard-temp", handle_general_success, STATE_SESSION },
    { NULL, NULL, 0 }
};

/* ------------------------------------------------------------------
 * xmpp_route_stanza
 *
 * Dispatches a parsed stanza to the appropriate handler based on its
 * xmlns and/or type, enforcing the minimum required connection state.
 *
 * RFC 6120 §8     — General stanza processing rules
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8
 * RFC 6120 §8.2.3 — IQ rules: server MUST reply to every IQ get or
 *   set with either a result or an error.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.3
 * RFC 6120 §8.3.3.19 — <service-unavailable/>: used when the server
 *   does not support the requested service/namespace.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.3.3.19
 *
 * STREAM OPEN DETECTION:
 *   If xmlns contains "stream", this is a stream-level element, not a
 *   stanza — delegate to handle_handshake_logic().
 *   RFC 6120 §4.2  — stream:stream opening
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-4.2
 *
 * MUC#OWNER PRE-CHECK:
 *   BUG: The muc#owner check at the top will invoke handle_muc_owner
 *   a second time for stanzas that also match the table entry. This is
 *   harmless only because handle_muc_owner is idempotent for the same
 *   stanza, but it should be removed — the table entry is sufficient.
 *
 * PRESENCE ROUTING:
 *   RFC 6121 §4.2  — initial/subsequent presence broadcast
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-4.2
 *   XEP-0045 §7.1  — MUC presence to conference.* subdomain
 *     https://xmpp.org/extensions/xep-0045.html#enter
 *
 * IQ FALLBACK ERROR:
 *   RFC 6120 §8.2.3 — unrecognised IQ get/set MUST receive an error.
 *   We send <service-unavailable/> (RFC 6120 §8.3.3.19) which is
 *   correct for an unsupported namespace/feature.
 *   NOTE: We only send this if stanza->id is non-empty. RFC 6120
 *   §8.1.3 says the 'id' attribute is RECOMMENDED on IQ stanzas;
 *   technically a server MUST still reply even without an id.
 *   TODO: send the error even when id is empty (omit the 'id' attr
 *   from the response in that case).
 * ------------------------------------------------------------------ */
void xmpp_route_stanza(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    /* Stream-level element detection (should not reach here normally,
     * but guard against edge cases in stream restart).
     * RFC 6120 §4.2 — stream:stream element
     * https://datatracker.ietf.org/doc/html/rfc6120#section-4.2 */
    if (stanza->xmlns[0] != '\0' && strstr(stanza->xmlns, "stream") != NULL) {
        extern void handle_handshake_logic(xmpp_client_ctx_t *ctx);

        handle_handshake_logic(ctx);

        return;
    }

    /* FIXME: This block is redundant with the table entry for muc#owner
     * and causes double-dispatch. Remove it — the table handles it. */
    if (strstr(stanza->payload, "http://jabber.org/protocol/muc#owner") || strcmp(stanza->xmlns, "http://jabber.org/protocol/muc#owner") == 0) {
        handle_muc_owner(ctx, stanza);

        return;
    }

    /* Primary dispatch: xmlns-based routing table */
    for (int i = 0; router[i].xmlns != NULL; i++) {
        if (strcmp(stanza->xmlns, router[i].xmlns) == 0) {
            if (ctx->state < router[i].min_state) {
                /* RFC 6120 §8.2.3 — for IQ stanzas we SHOULD reply with
                 * an error rather than silently dropping.
                 * TODO: send <not-allowed/> or <unexpected-request/> here. */
                return;
            }

            router[i].handler(ctx, stanza);

            return;
        }
    }

    /* Fallback dispatch by stanza type for xmlns-less or jabber:client stanzas */
    if (ctx->state >= STATE_SESSION) {
        if (stanza->type == XMPP_MESSAGE) {
            /* RFC 6121 §5   — Message delivery
             * XEP-0045 §7.9 — groupchat message (type='groupchat')
             * The handler itself must check stanza->to to determine
             * whether this is a direct message or a room message. */
            handle_chat_message(ctx, stanza);

            return;
        }
        else if (stanza->type == XMPP_PRESENCE) {
            if (strstr(stanza->to, "conference.angelic.local")) {
                /* Presence directed at the MUC service subdomain.
                 * XEP-0045 §7.1 — entering a room
                 * XEP-0045 §7.14 — exiting a room (type='unavailable')
                 * https://xmpp.org/extensions/xep-0045.html#enter */
                handle_muc_presence(ctx, stanza);
            }
            else {
                /* Presence to/from regular contacts.
                 * RFC 6121 §4.2 — broadcasting initial/updated presence
                 * https://datatracker.ietf.org/doc/html/rfc6121#section-4.2 */
                handle_broadcast_presence(ctx, stanza);
            }
        }
        else if (stanza->type == XMPP_IQ_GET || stanza->type == XMPP_IQ_SET) {
            /* Second attempt at muc#owner inside unrecognised IQ payload */
            if (strstr(stanza->payload, "http://jabber.org/protocol/muc#owner")) {
                handle_muc_owner(ctx, stanza);

                return;
            }

            /* RFC 6120 §8.2.3 — MUST send error for unrecognised IQ.
             * RFC 6120 §8.3.3.19 — <service-unavailable/> is the correct
             * condition when the server does not offer the feature.
             * https://datatracker.ietf.org/doc/html/rfc6120#section-8.3.3.19
             * TODO: also send when stanza->id is empty (omit id attr). */
            if (strlen(stanza->id) > 0) {
                char response[512];

                snprintf(response, sizeof(response),
                    "<iq type='error' from='%s' to='%s' id='%s'>"
                      "<error type='cancel' code='503'>"
                        "<service-unavailable "
                          "xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                      "</error>"
                    "</iq>",
                    stanza->to, ctx->full_jid, stanza->id);

                send_raw(ctx, response);
            }
        }
    }
}