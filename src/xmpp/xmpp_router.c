#include "xmpp_core.h"
#include <stdio.h>

typedef void (*handler_fn)(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

struct route_entry {
    const char *xmlns;
    handler_fn handler;
    client_state_t min_state;
};

static struct route_entry router[] = {
    { "urn:ietf:params:xml:ns:xmpp-bind", handle_core_bind, STATE_BIND },
    { "urn:ietf:params:xml:ns:xmpp-session", handle_core_session, STATE_AUTHENTICATED },
    { "jabber:iq:roster", handle_roster_request, STATE_SESSION },
    { "http://jabber.org/protocol/disco#info", handle_disco_info, STATE_SESSION },
    { "http://jabber.org/protocol/disco#items", handle_disco_items, STATE_SESSION },
    { "http://jabber.org/protocol/muc", handle_muc_presence, STATE_SESSION },
    { "http://jabber.org/protocol/muc#owner", handle_muc_owner, STATE_SESSION },
    { "jabber:iq:private", handle_private_storage, STATE_SESSION },
    { "http://jabber.org/protocol/muc#admin", handle_muc_admin, STATE_SESSION },
    { "urn:xmpp:blocking", handle_blocklist, STATE_SESSION },
    { "vcard-temp", handle_general_success, STATE_SESSION },
    { "jabber:iq:version", handle_version, STATE_SESSION },
    { "jabber:iq:last", handle_last, STATE_SESSION },
    { "urn:ietf:params:xml:ns:xmpp-ping", handle_ping, STATE_SESSION },
    { NULL, NULL, 0 }
};

void xmpp_route_stanza(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    if (ctx->full_jid[0] != '\0') {
        strncpy(stanza->from, ctx->full_jid, sizeof(stanza->from) - 1);

        stanza->from[sizeof(stanza->from) - 1] = '\0';
    }

    if (stanza->xmlns[0] != '\0' && strstr(stanza->xmlns, "stream") != NULL) {
        extern void handle_handshake_logic(xmpp_client_ctx_t *ctx);

        handle_handshake_logic(ctx);

        return;
    }

    for (int i = 0; router[i].xmlns != NULL; i++) {
        if (strcmp(stanza->xmlns, router[i].xmlns) == 0) {
            if (ctx->state < router[i].min_state) {
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

    if (ctx->state >= STATE_SESSION) {
        if (stanza->type == XMPP_MESSAGE) {
            handle_chat_message(ctx, stanza);

            return;
        }

        else if (stanza->type == XMPP_PRESENCE || stanza->type == XMPP_PRESENCE_UNAVAILABLE || stanza->type == XMPP_PRESENCE_SUBSCRIBE || stanza->type == XMPP_PRESENCE_SUBSCRIBED || stanza->type == XMPP_PRESENCE_UNSUBSCRIBE || stanza->type == XMPP_PRESENCE_UNSUBSCRIBED || stanza->type == XMPP_PRESENCE_PROBE) {
            if (strstr(stanza->to, "conference.angelic.local")) {
                handle_muc_presence(ctx, stanza);
            }
            else if (stanza->type == XMPP_PRESENCE) {
                if (!ctx->initial_presence_sent) {
                    ctx->initial_presence_sent = 1;

                    handle_initial_presence(ctx, stanza);
                }
                else {
                    handle_broadcast_presence(ctx, stanza);
                }
            }
            else {
                handle_broadcast_presence(ctx, stanza);
            }

            return;
        }
        else if (stanza->type == XMPP_IQ_GET || stanza->type == XMPP_IQ_SET) {
            if (strstr(stanza->payload, "http://jabber.org/protocol/muc#owner")) {
                handle_muc_owner(ctx, stanza);

                return;
            }

            {
                char response[512];

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

    if (stanza->type == XMPP_UNKNOWN && stanza->id[0] != '\0' &&
        ctx->state >= STATE_AUTHENTICATED) {
        char response[512];
        const char *from_jid = (stanza->to[0] != '\0') ? stanza->to : XMPP_DOMAIN;
        const char *to_jid = (ctx->full_jid[0] != '\0') ? ctx->full_jid : "unknown";

        snprintf(response, sizeof(response),
            "<iq type='error' from='%s' to='%s' id='%s'>"
              "<error type='modify'>"
                "<bad-request "
                  "xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
              "</error>"
            "</iq>",
            from_jid, to_jid, stanza->id);

        send_raw(ctx, response);
    }
}