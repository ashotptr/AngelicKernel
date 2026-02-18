#include "xmpp_core.h"

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
    // NEW: Explicitly handle client messages
    // { "jabber:client", handle_chat_message, STATE_SESSION },
    
    { NULL, NULL, 0 }
};

void xmpp_route_stanza(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    // 1. Handshake Restart
    if (stanza->xmlns[0] != '\0' && strstr(stanza->xmlns, "stream") != NULL) {
        extern void handle_handshake_logic(xmpp_client_ctx_t *ctx);
        handle_handshake_logic(ctx);
        return;
    }

    // 2. Exact Namespace Match
    for (int i = 0; router[i].xmlns != NULL; i++) {
        if (strcmp(stanza->xmlns, router[i].xmlns) == 0) {
            if (ctx->state < router[i].min_state) return;
            router[i].handler(ctx, stanza);
            return;
        }
    }
    
    // 3. Fallback Logic
    if (ctx->state >= STATE_SESSION) {
        if (stanza->type == XMPP_MESSAGE) {
            handle_chat_message(ctx, stanza);
            return; // <--- CRITICAL: Return here to stop error spam
        }
        else if (stanza->type == XMPP_PRESENCE) {
            // --- CRITICAL FIX START ---
            // If the destination contains "conference", it IS a MUC join.
            // This catches cases where the parser missed the xmlns or client used a variation.
            if (strstr(stanza->to, "conference.server")) {
                handle_muc_presence(ctx, stanza);
            } 
            else {
                // Otherwise, it's just the user going "Online"
                handle_broadcast_presence(ctx, stanza);
            }
            // --- CRITICAL FIX END ---
        }
        else if ((stanza->type == XMPP_IQ_GET || stanza->type == XMPP_IQ_SET) && strlen(stanza->id) > 0) {
             // Send 503 Service Unavailable for unknown IQs (OMEMO/PubSub)
             // This keeps Gajim snappy.
            char response[512];
            snprintf(response, sizeof(response), 
                "<iq type='error' from='server' to='%s' id='%s'>"
                "<error type='cancel' code='503'>"
                "<service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                "</error>"
                "</iq>",
                ctx->full_jid, stanza->id);
            send_raw(ctx, response);
        }
    }
}