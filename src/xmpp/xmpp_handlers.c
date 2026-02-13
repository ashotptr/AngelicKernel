#include "xmpp_core.h"
#include <stdio.h>

void send_raw(xmpp_client_ctx_t *ctx, const char *data) {
    xmpp_log("SEND", data, strlen(data));
    
    tcp_write(ctx->pcb, data, strlen(data), TCP_WRITE_FLAG_COPY);
    tcp_output(ctx->pcb);
}

void handle_core_bind(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    // Dynamically build the JID: admin@angelic.local/Unikernel
    snprintf(ctx->full_jid, 64, "admin@%s/Unikernel", XMPP_DOMAIN);
    
    char response[512];
    snprintf(response, 512, 
        "<iq type='result' id='%s'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>%s</jid></bind></iq>", 
        stanza->id, ctx->full_jid);
        
    send_raw(ctx, response);
    ctx->state = STATE_SESSION;
}

void handle_core_session(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[256];
    snprintf(response, 256, "<iq type='result' id='%s'/>", stanza->id);
    send_raw(ctx, response);
    ctx->state = STATE_READY;
}

void handle_disco_info(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];
    snprintf(response, sizeof(response),
        "<iq type='result' from='server' to='%s' id='%s'>"
        "  <query xmlns='http://jabber.org/protocol/disco#info'>"
        "    <identity category='server' type='im' name='Unikernel XMPP'/>"
        "    <feature var='http://jabber.org/protocol/muc'/>"  // <-- CRITICAL: "I support MUC"
        "    <feature var='jabber:iq:register'/>"
        "  </query>"
        "</iq>",
        ctx->full_jid, stanza->id);
    send_raw(ctx, response);
}

// 2. Handle "What rooms do you have?" (Disco Items)
void handle_disco_items(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    // In a real server, you loop through your 'rooms' array here
    char response[1024];
    snprintf(response, sizeof(response),
        "<iq type='result' from='server' to='%s' id='%s'>"
        "  <query xmlns='http://jabber.org/protocol/disco#items'>"
        "    <item jid='lobby@conference.server' name='Main Lobby'/>"
        "  </query>"
        "</iq>",
        ctx->full_jid, stanza->id);
    send_raw(ctx, response);
}

void handle_sasl(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    // In a real server, we would check the base64 payload in stanza->payload.
    // For this Unikernel, we trust the client and assume ANONYMOUS/PLAIN success.

    const char *resp = "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>";
    tcp_write(ctx->pcb, resp, strlen(resp), TCP_WRITE_FLAG_COPY);
    tcp_output(ctx->pcb);

    ctx->authenticated = 1;
    ctx->state = STATE_AUTHENTICATED;
    
    // Note: Most clients reset the XML stream after SASL success. 
    // We remain open for simplicity.
}

// --- MUC HANDLERS ---
void handle_muc_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    // 1. Parse JID: "room@service/nick"
    char room_name[32] = {0};
    char nick[32] = {0};
    
    char *at_sign = strchr(stanza->to, '@');
    char *slash = strchr(stanza->to, '/');
    
    if (!at_sign || !slash) return; 

    // Extract Room Name
    int room_len = at_sign - stanza->to;
    if (room_len > 31) room_len = 31;
    strncpy(room_name, stanza->to, room_len);
    
    // Extract Nickname
    strncpy(nick, slash + 1, 31);

    // 2. Find or Create Room
    room_t *r = NULL;
    for (int i=0; i<MAX_ROOMS; i++) {
        if (rooms[i].active && strcmp(rooms[i].name, room_name) == 0) {
            r = &rooms[i]; break;
        }
    }
    
    if (!r) {
        // Create new room
        for (int i=0; i<MAX_ROOMS; i++) {
            if (!rooms[i].active) {
                r = &rooms[i];
                r->active = 1;
                strcpy(r->name, room_name);
                break;
            }
        }
    }
    
    if (!r) return; // Server Full

    // 3. Add User to Room (Simple overwrite strategy)
    participant_t *p = NULL;
    for(int i=0; i<MAX_USERS_PER_ROOM; i++) {
        if (!r->users[i].active) {
            p = &r->users[i];
            p->active = 1;
            p->pcb = ctx->pcb;
            strcpy(p->nick, nick);
            strcpy(p->jid, ctx->full_jid);
            break;
        }
    }

    // 4. Send Success Presence (Self-Presence)
    char response[512];
    snprintf(response, 512, 
        "<presence from='%s' to='%s'>"
        "<x xmlns='http://jabber.org/protocol/muc#user'>"
        "<item affiliation='member' role='participant'/>"
        "<status code='110'/>"
        "</x></presence>", 
        stanza->to, ctx->full_jid);
    
    send_raw(ctx, response);
}

void handle_chat_message(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    // Echo back (Loopback test)
    char response[512];
    snprintf(response, 512, 
        "<message from='%s' to='%s' type='chat'><body>Echo: %s</body></message>",
        stanza->to, ctx->full_jid, stanza->payload);
    send_raw(ctx, response);
}

void handle_broadcast_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    // 1. Update State: If they send presence, they are fully Ready.
    if (ctx->state < STATE_READY) {
        ctx->state = STATE_READY;
    }

    // 2. Echo presence back to self (Self-Presence)
    char response[512];
    snprintf(response, sizeof(response), 
        "<presence from='%s' to='%s' id='%s'>"
        "<status>Online</status>"
        "</presence>",
        ctx->full_jid, ctx->full_jid, stanza->id);
        
    send_raw(ctx, response);
}