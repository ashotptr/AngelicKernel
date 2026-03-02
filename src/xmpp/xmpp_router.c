#include "xmpp_core.h"
#include <stdio.h>

typedef void (*handler_fn)(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

struct route_entry {
    const char *xmlns;
    handler_fn handler;
    client_state_t min_state;
};

static struct route_entry router[] = {
    { "urn:ietf:params:xml:ns:xmpp-sasl", handle_sasl, STATE_CONNECTED },
    { "urn:ietf:params:xml:ns:xmpp-bind",  handle_core_bind, STATE_AUTHENTICATED },
    { "urn:ietf:params:xml:ns:xmpp-session", handle_core_session, STATE_AUTHENTICATED },
    { "jabber:iq:roster", handle_roster_request, STATE_SESSION },
    { "http://jabber.org/protocol/disco#info", handle_disco_info, STATE_SESSION },
    { "http://jabber.org/protocol/disco#items", handle_disco_items, STATE_SESSION },
    { "http://jabber.org/protocol/muc", handle_muc_presence, STATE_SESSION },
    { "http://jabber.org/protocol/muc#owner", handle_muc_owner, STATE_SESSION },
    // { "jabber:client", handle_chat_message, STATE_SESSION },
    
    { "jabber:iq:private", handle_private_storage, STATE_SESSION },
    { "http://jabber.org/protocol/muc#admin", handle_muc_admin, STATE_SESSION },
    { "urn:xmpp:blocking", handle_general_success, STATE_SESSION },
    { "vcard-temp", handle_general_success, STATE_SESSION },
    
    { NULL, NULL, 0 }
};

void xmpp_route_stanza(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    if (stanza->xmlns[0] != '\0' && strstr(stanza->xmlns, "stream") != NULL) {
        extern void handle_handshake_logic(xmpp_client_ctx_t *ctx);

        handle_handshake_logic(ctx);
        
        return;
    }
    
    if (strstr(stanza->payload, "http://jabber.org/protocol/muc#owner") || strcmp(stanza->xmlns, "http://jabber.org/protocol/muc#owner") == 0) {
        handle_muc_owner(ctx, stanza);

        return;
    }
    
    for (int i = 0; router[i].xmlns != NULL; i++) {
        if (strcmp(stanza->xmlns, router[i].xmlns) == 0) {
            if (ctx->state < router[i].min_state) {
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
        else if (stanza->type == XMPP_PRESENCE) {
            if (strstr(stanza->to, "conference.angelic.local")) {
                handle_muc_presence(ctx, stanza);
            } 
            else {
                handle_broadcast_presence(ctx, stanza);
            }
        }
        else if (stanza->type == XMPP_IQ_GET || stanza->type == XMPP_IQ_SET) {
             if (strstr(stanza->payload, "http://jabber.org/protocol/muc#owner")) {
                 handle_muc_owner(ctx, stanza);

                 return;
             }

             if (strlen(stanza->id) > 0) {
                 char response[512];

                 snprintf(response, sizeof(response), 
                    "<iq type='error' from='%s' to='%s' id='%s'>"
                    "<error type='cancel' code='503'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
                    "</iq>",
                    stanza->to, ctx->full_jid, stanza->id);
                 
                 send_raw(ctx, response);
             }
        }
    }
}