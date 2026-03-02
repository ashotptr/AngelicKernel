#include "xmpp_core.h"
#include <stdio.h>

// review
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
    char response[512];

    snprintf(response, sizeof(response), 
        "<presence from='%s' to='%s' xml:lang='en'>"
        "<show>chat</show>"
        "<priority>1</priority>"
        "</presence>", 
        ctx->full_jid, ctx->full_jid);
    
    send_raw(ctx, response);
}

void handle_private_storage(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];
    
    snprintf(response, sizeof(response), 
        "<iq type='result' id='%s' to='%s'>"
        "<query xmlns='jabber:iq:private'>"
        "<storage xmlns='storage:bookmarks'/>" 
        "</query></iq>", 
        stanza->id, ctx->full_jid);

    send_raw(ctx, response);
}

void handle_muc_admin(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];

    int want_owner  = strstr(stanza->payload, "affiliation='owner'")  || strstr(stanza->payload, "affiliation=\"owner\"");
    int want_admin  = strstr(stanza->payload, "affiliation='admin'")  || strstr(stanza->payload, "affiliation=\"admin\"");
    int want_member = strstr(stanza->payload, "affiliation='member'") || strstr(stanza->payload, "affiliation=\"member\"");

    if (want_owner) {
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
            "</query></iq>",
            stanza->id, ctx->full_jid, owner_jid);
    }
    else if (want_admin || want_member) {
        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s'>"
            "<query xmlns='http://jabber.org/protocol/muc#admin'/>"
            "</iq>",
            stanza->id, ctx->full_jid);
    }
    else {
        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s'>"
            "<query xmlns='http://jabber.org/protocol/muc#admin'/>"
            "</iq>",
            stanza->id, ctx->full_jid);
    }

    send_raw(ctx, response);
}

void handle_general_success(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[512];
    
    snprintf(response, sizeof(response), 
        "<iq type='result' id='%s' to='%s'/>", 
        stanza->id, ctx->full_jid);

    send_raw(ctx, response);
}

void handle_core_bind(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    int resource_id = rand() % 9999;

    snprintf(ctx->full_jid, 64, "%s@%s/Unikernel-%d", ctx->username, XMPP_DOMAIN, resource_id);
    
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

void handle_muc_owner(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];

    if (stanza->type == XMPP_IQ_SET || strstr(stanza->payload, "type='submit'") || strstr(stanza->payload, "type=\"submit\"")) {
        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s' from='%s'/>",
            stanza->id, ctx->full_jid, stanza->to);
    }
    else {
        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s' from='%s'>"
            "  <query xmlns='http://jabber.org/protocol/muc#owner'>"
            "    <x xmlns='jabber:x:data' type='form'>"
            "      <field type='hidden' var='FORM_TYPE'>"
            "        <value>http://jabber.org/protocol/muc#roomconfig</value>"
            "      </field>"
            "    </x>"
            "  </query>"
            "</iq>",
            stanza->id, ctx->full_jid, stanza->to);
    }
    
    send_raw(ctx, response);
}

void handle_disco_info(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];
    
    char *at = strchr(stanza->to, '@');

    if (at && strstr(stanza->to, "conference.angelic.local")) {
        int room_len = at - stanza->to;
        char room_name[MAX_ROOM_NAME_LEN] = {0};
        
        if (room_len < sizeof(room_name)) {
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
            snprintf(response, sizeof(response),
                "<iq type='result' from='%s' to='%s' id='%s'>"
                "<query xmlns='http://jabber.org/protocol/disco#info'>"
                "<identity category='conference' type='text' name='%s'/>"
                "<feature var='http://jabber.org/protocol/muc'/>"
                "</query></iq>",
                stanza->to, ctx->full_jid, stanza->id, room_name);
        }
        else {
            snprintf(response, sizeof(response),
                "<iq type='error' from='%s' to='%s' id='%s'>"
                "<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
                "</iq>",
                stanza->to, ctx->full_jid, stanza->id);
        }
    }
    else if (strcmp(stanza->to, "conference.angelic.local") == 0) {
        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
            "<query xmlns='http://jabber.org/protocol/disco#info'>"
            "<identity category='conference' type='text' name='Chat Service'/>"
            "<feature var='http://jabber.org/protocol/muc'/>"
            "</query></iq>",
            stanza->to, ctx->full_jid, stanza->id);
    }
    else {
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

void handle_disco_items(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];
    
    if (strstr(stanza->to, "conference.angelic.local")) {
        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
            "  <query xmlns='http://jabber.org/protocol/disco#items'>"
            "    <item jid='lobby@conference.angelic.local' name='Main Lobby'/>"
            "  </query>"
            "</iq>",
            stanza->to, ctx->full_jid, stanza->id);
    }
    else {
        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
            "  <query xmlns='http://jabber.org/protocol/disco#items'>"
            "    <item jid='conference.angelic.local' name='Chatroom Service'/>"
            "  </query>"
            "</iq>",
            (strlen(stanza->to) > 0) ? stanza->to : "angelic.local", 
            ctx->full_jid, stanza->id);
    }

    send_raw(ctx, response);
}

void handle_sasl(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    unsigned char decoded[128] = {0};
    int len = b64decode(stanza->payload, decoded, sizeof(decoded) - 1);

    ctx->username[0] = '\0';

    if (len > 1) {
        int i = 0;

        while (i < len && decoded[i] != '\0') {
            i++;
        }

        i++;
        int j = 0;
        
        while (i < len && decoded[i] != '\0' && j < 31) {
            ctx->username[j++] = decoded[i++];
        }

        ctx->username[j] = '\0';
    }

    if (ctx->username[0] == '\0') {
        strncpy(ctx->username, "user", 31);
    }

    const char *resp = "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>";
    
    xmpp_log("SEND", resp, strlen(resp));

    tcp_write(ctx->pcb, resp, strlen(resp), TCP_WRITE_FLAG_COPY);

    tcp_output(ctx->pcb);

    ctx->authenticated = 1;
    ctx->state = STATE_AUTHENTICATED;
}

void handle_muc_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char *slash = strchr(stanza->to, '/');

    if (!slash) {
        return;
    }

    char nick[32];

    strncpy(nick, slash + 1, 31);
    
    nick[31] = '\0';

    char bare_jid[64];
    int bare_len = slash - stanza->to;

    if (bare_len > 63) {
        bare_len = 63;
    }
    
    strncpy(bare_jid, stanza->to, bare_len);
    
    bare_jid[bare_len] = '\0';

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

    int is_new_room = 0;
    room_t *r = NULL;

    for (int i = 0; i < MAX_ROOMS; i++) {
        if (rooms[i].active && strcmp(rooms[i].name, room_name) == 0) {
            r = &rooms[i];
            
            break;
        }
    }

    if (!r) {
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
        return;
    }

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
            "</x></presence>",
            bare_jid, r->users[i].nick, ctx->full_jid, r->users[i].jid);

        send_raw(ctx, response);
    }

    for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
        if (!r->users[i].active) {
            continue;
        }

        if (strcmp(r->users[i].jid, ctx->full_jid) == 0) {
            continue;
        }

        xmpp_client_ctx_t target_ctx;
        target_ctx.pcb = r->users[i].pcb;

        snprintf(response, sizeof(response),
            "<presence from='%s/%s' to='%s'>"
            "<x xmlns='http://jabber.org/protocol/muc#user'>"
            "<item affiliation='member' role='participant' jid='%s'/>"
            "</x></presence>",
            bare_jid, nick, r->users[i].jid, ctx->full_jid);
        
        send_raw(&target_ctx, response);
    }

    if (is_new_room) {
        snprintf(response, sizeof(response),
            "<presence from='%s/%s' to='%s'>"
            "<x xmlns='http://jabber.org/protocol/muc#user'>"
            "<item affiliation='owner' role='moderator'/>"
            "<status code='110'/>"
            "<status code='201'/>"
            "</x></presence>",
            bare_jid, nick, ctx->full_jid);
    }
    else {
        snprintf(response, sizeof(response),
            "<presence from='%s/%s' to='%s'>"
            "<x xmlns='http://jabber.org/protocol/muc#user'>"
            "<item affiliation='member' role='participant'/>"
            "<status code='110'/>"
            "</x></presence>",
            bare_jid, nick, ctx->full_jid);
    }

    send_raw(ctx, response);

    snprintf(response, sizeof(response),
        "<message from='%s' to='%s' type='groupchat'>"
        "<subject>Welcome to the Unikernel Lobby</subject>"
        "</message>",
        bare_jid, ctx->full_jid);

    send_raw(ctx, response);
}

void handle_chat_message(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[2048];    
    int already_wrapped = (stanza->payload[0] == '<');

   if (strstr(stanza->to, "conference.angelic.local")) {
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
            return;
        }

        char sender_nick[32] = "unknown";

        for(int i = 0; i < MAX_USERS_PER_ROOM; i++) {
            if(r->users[i].active && strcmp(r->users[i].jid, ctx->full_jid) == 0) {
                strcpy(sender_nick, r->users[i].nick);

                break;
            }
        }

        for(int i = 0; i < MAX_USERS_PER_ROOM; i++) {
            if(r->users[i].active) {
                char response[2048];
                int already_wrapped = (stanza->payload[0] == '<');

                if (already_wrapped) {
                    snprintf(response, sizeof(response),
                        "<message from='%s/%s' to='%s' type='groupchat' id='%s'>%s</message>",
                        stanza->to, sender_nick, r->users[i].jid, stanza->id, stanza->payload);
                }
                else {
                    snprintf(response, sizeof(response),
                        "<message from='%s/%s' to='%s' type='groupchat' id='%s'><body>%s</body></message>",
                        stanza->to, sender_nick, r->users[i].jid, stanza->id, stanza->payload);
                }
                
                xmpp_client_ctx_t target_ctx; 
                target_ctx.pcb = r->users[i].pcb;

                send_raw(&target_ctx, response);
            }
        }
    } 
    else {
        if (already_wrapped) {
             snprintf(response, sizeof(response), 
                "<message from='%s' to='%s' type='chat'>%s</message>",
                stanza->to, ctx->full_jid, stanza->payload);
        }
        else {
             snprintf(response, sizeof(response), 
                "<message from='%s' to='%s' type='chat'><body>%s</body></message>",
                stanza->to, ctx->full_jid, stanza->payload);
        }

        send_raw(ctx, response);
    }
}

void handle_broadcast_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    if (ctx->state < STATE_READY) {
        ctx->state = STATE_READY;
    }

    char response[512];
    
    snprintf(response, sizeof(response), 
        "<presence from='%s' to='%s' id='%s'>"
        "<status>Online</status>"
        "</presence>",
        ctx->full_jid, ctx->full_jid, stanza->id);
        
    send_raw(ctx, response);
}