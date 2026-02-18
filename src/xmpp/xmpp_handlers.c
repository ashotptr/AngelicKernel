#include "xmpp_core.h"
#include <stdio.h>

void send_raw(xmpp_client_ctx_t *ctx, const char *data) {
    xmpp_log("SEND", data, strlen(data));
    
    tcp_write(ctx->pcb, data, strlen(data), TCP_WRITE_FLAG_COPY);
    tcp_output(ctx->pcb);
}

void handle_roster_request(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[512];
    snprintf(response, sizeof(response), 
        "<iq type='result' id='%s' to='%s'>"
        "<query xmlns='jabber:iq:roster'/>" 
        "</iq>", 
        stanza->id, ctx->full_jid);
    send_raw(ctx, response);
}

void handle_initial_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    // Echo presence back to self so the client knows it is connected
    char response[512];
    snprintf(response, sizeof(response), 
        "<presence from='%s' to='%s' xml:lang='en'>"
        "<show>chat</show>"
        "<priority>1</priority>"
        "</presence>", 
        ctx->full_jid, ctx->full_jid);
    send_raw(ctx, response);
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
    
    // Check if the request is for the ROOM (contains @conference)
    if (strstr(stanza->to, "conference.server")) {
        // Must return FROM the room JID, and ID as 'conference'
        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
            "<query xmlns='http://jabber.org/protocol/disco#info'>"
            "<identity category='conference' type='text' name='Chat Room'/>"
            "<feature var='http://jabber.org/protocol/muc'/>"
            "</query></iq>",
            stanza->to, ctx->full_jid, stanza->id);
    } else {
        // Server Identity
        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
            "<query xmlns='http://jabber.org/protocol/disco#info'>"
            "<identity category='server' type='im' name='Unikernel XMPP'/>"
            "<feature var='http://jabber.org/protocol/muc'/>"
            "<feature var='jabber:iq:register'/>"
            "</query></iq>",
            stanza->to, ctx->full_jid, stanza->id);
    }
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
    // 1. Basic Parsing
    char *slash = strchr(stanza->to, '/');
    if (!slash) return;

    // Extract Nickname (e.g., "admin")
    char nick[32];
    strncpy(nick, slash + 1, 31);
    nick[31] = '\0';

    // Extract Bare JID (e.g., "lobby@conference.server") for the Subject Message
    char bare_jid[64];
    int bare_len = slash - stanza->to;
    if (bare_len > 63) bare_len = 63;
    strncpy(bare_jid, stanza->to, bare_len);
    bare_jid[bare_len] = '\0';

    // Extract Room Name (e.g., "lobby") for internal logic
    char room_name[32] = {0};
    char *at = strchr(stanza->to, '@');
    int name_len = at - stanza->to;
    if (name_len > 31) name_len = 31;
    strncpy(room_name, stanza->to, name_len);

    // 2. Find or Create Room (Same logic as before)
    room_t *r = NULL;
    for (int i=0; i<MAX_ROOMS; i++) {
        if (rooms[i].active && strcmp(rooms[i].name, room_name) == 0) {
            r = &rooms[i]; break;
        }
    }

    if (!r) {
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

    // 3. Add User to Room
    for(int i=0; i<MAX_USERS_PER_ROOM; i++) {
        if (!r->users[i].active) {
            r->users[i].active = 1;
            r->users[i].pcb = ctx->pcb;
            strcpy(r->users[i].nick, nick);
            strcpy(r->users[i].jid, ctx->full_jid);
            break;
        }
    }

    char response[512];

    // 4. Send Success Presence (Self-Presence)
    // This makes Gajim say "Admin joined"
    snprintf(response, sizeof(response), 
        "<presence from='%s' to='%s'>"
        "<x xmlns='http://jabber.org/protocol/muc#user'>"
        "<item affiliation='member' role='participant'/>"
        "<status code='110'/>"
        "</x></presence>", 
        stanza->to, ctx->full_jid);
    send_raw(ctx, response);

    // 5. Send Room Subject (THE FIX)
    // This stops the spinner! The message must come from the Bare JID (lobby@conference.server).
    snprintf(response, sizeof(response),
        "<message from='%s' to='%s' type='groupchat'>"
        "<subject>Welcome to the Unikernel Lobby</subject>"
        "</message>",
        bare_jid, ctx->full_jid);
    send_raw(ctx, response);
}

void handle_chat_message(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    // 1. Detect Groupchat (MUC)
    // If sending to the conference server, we must broadcast to the room.
    if (strstr(stanza->to, "conference.server")) {
        room_t *r = &rooms[0]; // Hardcoded to our single 'lobby'
        
        // Find sender's nickname
        char sender_nick[32] = "unknown";
        for(int i=0; i<MAX_USERS_PER_ROOM; i++) {
            if(r->users[i].active && strcmp(r->users[i].jid, ctx->full_jid) == 0) {
                strcpy(sender_nick, r->users[i].nick);
                break;
            }
        }

        // Broadcast to ALL participants (Fan-out)
        for(int i=0; i<MAX_USERS_PER_ROOM; i++) {
            if(r->users[i].active) {
                char response[2048];
                // MUC Standard: type='groupchat', from='room/nick', payload is copied AS-IS
                snprintf(response, sizeof(response),
                    "<message from='%s/%s' to='%s' type='groupchat' id='%s'>%s</message>",
                    r->name, sender_nick, r->users[i].jid, stanza->id, stanza->payload);
                
                // For this single-user test, we echo to self. 
                // (In a multi-user setup, you would check r->users[i].pcb)
                if (r->users[i].pcb == ctx->pcb) {
                    send_raw(ctx, response);
                }
            }
        }
    } 
    else {
        // 2. Private Chat Echo (Fixing the Nested Body Bug)
        char response[1024];
        
        // Check if payload already contains XML tags (like <body... or <active...)
        // If so, do NOT wrap it in another <body> tag.
        if (strstr(stanza->payload, "<") && strstr(stanza->payload, ">")) {
             snprintf(response, sizeof(response), 
                "<message from='%s' to='%s' type='chat'>%s</message>",
                stanza->to, ctx->full_jid, stanza->payload);
        } else {
             // It's just plain text, so we wrap it
             snprintf(response, sizeof(response), 
                "<message from='%s' to='%s' type='chat'><body>%s</body></message>",
                stanza->to, ctx->full_jid, stanza->payload);
        }
        send_raw(ctx, response);
    }
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