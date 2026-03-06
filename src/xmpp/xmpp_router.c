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
 *     RFC 6120 §6    — SASL Negotiation (top-level)
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6
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
 *     XEP-0045 §7.2  — Entering a Room (presence with <x> child)
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
 * PRESENCE ROUTING:
 *   RFC 6121 §4.2  — initial/subsequent presence broadcast
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-4.2
 *   XEP-0045 §7.2  — MUC presence to conference.* subdomain
 *     https://xmpp.org/extensions/xep-0045.html#enter
 *
 * IQ FALLBACK ERROR:
 *   RFC 6120 §8.2.3 — unrecognised IQ get/set MUST receive an error.
 *   We send <service-unavailable/> (RFC 6120 §8.3.3.19) which is
 *   correct for an unsupported namespace/feature.
 *   NOTE: We reply even when stanza->id is absent — in that case the
 *   'id' attribute is omitted from the response (not echoed as an empty
 *   string) so the client can still correlate by stream position.
 *   Both branches are implemented in the IQ fallback block below.
 * ------------------------------------------------------------------ */
void xmpp_route_stanza(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    /* ------------------------------------------------------------------
     * Fix (§5): RFC 6120 §8.1.2 — server MUST overwrite the 'from'
     * attribute on every inbound stanza with the authenticated sender JID.
     *
     * Clients can put any value (including another user's JID) in their
     * outgoing 'from=' attribute.  If we relay stanza->from without
     * replacement, a client can trivially impersonate any other user.
     * Overwriting here — before any handler sees the stanza — is the
     * single chokepoint that prevents all JID spoofing across every
     * protocol path (IQ, message, presence, subscription).
     *
     * After SASL+bind, ctx->full_jid is the server-assigned full JID
     * (localpart@domain/resource) and is authoritative.
     * Handlers that need a bare JID derive it from this value.
     *
     *   RFC 6120 §8.1.2 — "from" attribute MUST be stamped by server
     *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.1.2
     * ------------------------------------------------------------------ */
    if (ctx->full_jid[0] != '\0') {
        strncpy(stanza->from, ctx->full_jid, sizeof(stanza->from) - 1);

        stanza->from[sizeof(stanza->from) - 1] = '\0';
    }

    /* Stream-level element detection (should not reach here normally,
     * but guard against edge cases in stream restart).
     * RFC 6120 §4.2 — stream:stream element
     * https://datatracker.ietf.org/doc/html/rfc6120#section-4.2 */
    if (stanza->xmlns[0] != '\0' && strstr(stanza->xmlns, "stream") != NULL) {
        extern void handle_handshake_logic(xmpp_client_ctx_t *ctx);

        handle_handshake_logic(ctx);

        return;
    }

    /* FIX (§3 HIGH): Removed the muc#owner strstr() pre-check block that
     * was here. It caused handle_muc_owner() to be called twice for every
     * muc#owner stanza — once by this block and again by the routing table
     * entry below. The table entry is sufficient and correct; the pre-check
     * was entirely redundant. */

    /* Primary dispatch: xmlns-based routing table */
    for (int i = 0; router[i].xmlns != NULL; i++) {
        if (strcmp(stanza->xmlns, router[i].xmlns) == 0) {
            if (ctx->state < router[i].min_state) {
                /* RFC 6120 §8.2.3 — MUST reply to every IQ get/set with a result
                 * or error; silently dropping is a protocol violation.
                 * RFC 6120 §8.3.3.20 — <unexpected-request/>: used when the server
                 * receives a request that cannot be processed at this stage of the
                 * negotiation (e.g. bind IQ arriving before SASL completes).
                 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.3.3.20
                 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.3
                 *
                 * For non-IQ stanzas (message, presence) silently dropping is
                 * acceptable since the stream is not yet ready for stanza exchange.
                 * We include the id= attribute only when it is present on the
                 * inbound stanza, as required by RFC 6120 §8.1.3. */
                if (stanza->type == XMPP_IQ_GET || stanza->type == XMPP_IQ_SET) {
                    char err[512];
                    const char *from_jid = (stanza->to[0] != '\0') ? stanza->to : XMPP_DOMAIN;
                    const char *to_jid = (ctx->full_jid[0] != '\0') ? ctx->full_jid : "unknown";

                    if (stanza->id[0] != '\0') {
                        snprintf(err, sizeof(err),
                            "<iq type='error' from='%s' to='%s' id='%s'>"
                              "<error type='wait'>"
                                "<unexpected-request "
                                  "xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                              "</error>"
                            "</iq>",
                            from_jid, to_jid, stanza->id);
                    }
                    else {
                        /* id absent — omit id= attribute per RFC 6120 §8.1.3 */
                        snprintf(err, sizeof(err),
                            "<iq type='error' from='%s' to='%s'>"
                              "<error type='wait'>"
                                "<unexpected-request "
                                  "xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                              "</error>"
                            "</iq>",
                            from_jid, to_jid);
                    }

                    send_raw(ctx, err);
                }

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
        else if (stanza->type == XMPP_PRESENCE || stanza->type == XMPP_PRESENCE_UNAVAILABLE || stanza->type == XMPP_PRESENCE_SUBSCRIBE || stanza->type == XMPP_PRESENCE_SUBSCRIBED || stanza->type == XMPP_PRESENCE_UNSUBSCRIBE || stanza->type == XMPP_PRESENCE_UNSUBSCRIBED) {
            if (strstr(stanza->to, "conference.angelic.local")) {
                /* Presence directed at the MUC service subdomain.
                 * XEP-0045 §7.2  — entering a room
                 * XEP-0045 §7.14 — exiting a room (type='unavailable')
                 * https://xmpp.org/extensions/xep-0045.html#enter
                 * NOTE: handle_muc_presence() checks stanza->type to
                 * distinguish enter vs exit vs subscription. */
                handle_muc_presence(ctx, stanza);
            }
            else {
                /* Presence to/from regular contacts.
                 * RFC 6121 §4.2   — broadcasting initial/updated presence
                 * RFC 6121 §3.1.3 — subscription stanzas forwarded to target
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
             *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.3.3.19
             *
             * FIX (§4 ⚠ Partial): Reply even when stanza->id is empty.
             * RFC 6120 §8.2.3 — MUST reply to every IQ get/set regardless
             * of whether 'id' was present. When id is absent, the response
             * omits the id= attribute entirely (rather than echoing an empty
             * string) so the client can still correlate by stream position.
             *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.3 */
            {
                char response[512];

                /* RFC 6120 §8.1.1.1 — 'from' on an error reply must be the
                 * JID to which the original IQ was addressed.  IQs with no
                 * 'to' attribute are implicitly sent to the server domain.
                 * Use XMPP_DOMAIN as the fallback (same pattern as the
                 * xmlns-routing block above). */
                const char *from_jid = (stanza->to[0] != '\0') ? stanza->to : XMPP_DOMAIN;

                if (strlen(stanza->id) > 0) {
                    snprintf(response, sizeof(response),
                        "<iq type='error' from='%s' to='%s' id='%s'>"
                          "<error type='cancel' code='503'>"
                            "<service-unavailable "
                              "xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                          "</error>"
                        "</iq>",
                        from_jid, ctx->full_jid, stanza->id);
                }
                else {
                    /* id absent — omit id= attribute per RFC 6120 §8.2.3 */
                    snprintf(response, sizeof(response),
                        "<iq type='error' from='%s' to='%s'>"
                          "<error type='cancel' code='503'>"
                            "<service-unavailable "
                              "xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                          "</error>"
                        "</iq>",
                        from_jid, ctx->full_jid);
                }

                send_raw(ctx, response);
            }
        }
    }

    /* ------------------------------------------------------------------
     * RFC 6120 §8.2.3 / §8.3.3.2 — <bad-request/>: detect <iq> stanzas
     * whose type= attribute is absent or not one of get|set|result|error.
     *
     * The parser (xmpp_parser.c) initialises s->type to XMPP_UNKNOWN for
     * an <iq> element and only overrides it to XMPP_IQ_{GET,SET,RESULT,ERROR}
     * when it finds a recognised type= value.  If type= is missing or holds
     * an unrecognised value, s->type remains XMPP_UNKNOWN after parsing.
     *
     * We distinguish this from other XMPP_UNKNOWN stanzas (e.g. a stream-level
     * element that slipped through) by requiring stanza->id to be non-empty:
     * RFC 6120 §8.1.3 RECOMMENDS that <iq> stanzas carry an id= attribute, and
     * in practice every XMPP client sends one.  An XMPP_UNKNOWN stanza without
     * an id is unlikely to be a malformed IQ and is silently dropped.
     *
     * The check is gated on STATE_AUTHENTICATED rather than STATE_SESSION so
     * that a bind IQ arriving with a bad type attribute (in STATE_AUTHENTICATED)
     * still receives an error reply rather than being dropped silently.
     *
     *   RFC 6120 §8.2.3   https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.3
     *   RFC 6120 §8.3.3.2  https://datatracker.ietf.org/doc/html/rfc6120#section-8.3.3.2
     * ------------------------------------------------------------------ */
    if (stanza->type == XMPP_UNKNOWN && stanza->id[0] != '\0' && ctx->state >= STATE_AUTHENTICATED) {
        char response[512];
        const char *from_jid = (stanza->to[0]      != '\0') ? stanza->to      : XMPP_DOMAIN;
        const char *to_jid   = (ctx->full_jid[0]   != '\0') ? ctx->full_jid   : "unknown";

        snprintf(response, sizeof(response),
            "<iq type='error' from='%s' to='%s' id='%s'>"
              "<error type='modify'>"
                "<bad-request "
                  "xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
              "</e>"
            "</iq>",
            from_jid, to_jid, stanza->id);

        send_raw(ctx, response);
    }
}