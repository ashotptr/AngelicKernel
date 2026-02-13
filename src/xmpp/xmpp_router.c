#include "xmpp_core.h"
// No other changes needed if xmpp_core.h has the prototypes at the bottom.
// Function pointer definition for all handlers
typedef void (*handler_fn)(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

// The Routing Table
struct route_entry {
    const char *xmlns;
    handler_fn handler;
    client_state_t min_state; // <-- NEW: The Automata Guard
};

static struct route_entry router[] = {
    // Auth & Bind
    { "urn:ietf:params:xml:ns:xmpp-sasl", handle_sasl, STATE_CONNECTED },
    { "urn:ietf:params:xml:ns:xmpp-bind",  handle_core_bind, STATE_AUTHENTICATED },
    { "urn:ietf:params:xml:ns:xmpp-session", handle_core_session, STATE_AUTHENTICATED },
    
    // Discovery (Allow this immediately after Bind/Session)
    { "http://jabber.org/protocol/disco#info", handle_disco_info, STATE_SESSION },
    { "http://jabber.org/protocol/disco#items", handle_disco_items, STATE_SESSION },
    
    // MUC (Allow joining rooms immediately after Bind/Session)
    { "http://jabber.org/protocol/muc", handle_muc_presence, STATE_SESSION },
    
    { NULL, NULL, 0 }
};

void xmpp_route_stanza(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    // 1. Handle Stream Restart (Special Case)
    if (stanza->xmlns[0] != '\0' && strstr(stanza->xmlns, "stream") != NULL) {
        extern void handle_handshake_logic(xmpp_client_ctx_t *ctx);
        handle_handshake_logic(ctx);
        return;
    }

    // 2. Try Specific Namespace Match
    for (int i = 0; router[i].xmlns != NULL; i++) {
        if (strcmp(stanza->xmlns, router[i].xmlns) == 0) {
            if (ctx->state < router[i].min_state) {
                 // printf("Blocked %s: State %d < %d\n", stanza->xmlns, ctx->state, router[i].min_state);
                 return;
            }
            router[i].handler(ctx, stanza);
            return;
        }
    }
    
    // 3. Fallback: Generic Stanzas (Message/Presence)
    // Only allow if user has at least reached Session state (is Bound)
    if (ctx->state >= STATE_SESSION) {
        if (stanza->type == XMPP_MESSAGE) {
            handle_chat_message(ctx, stanza);
        }
        else if (stanza->type == XMPP_PRESENCE) {
            // New: Handle Broadcast Presence (I am online)
            handle_broadcast_presence(ctx, stanza);
        }
    }
}