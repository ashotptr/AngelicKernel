#include "xmpp_core.h"
#include <stdio.h>

const xmpp_credential_t xmpp_credentials[] = {
    { "admin", "admin" },
    { "user1", "pass1" },
    { "user2", "pass2" },
};

pending_sub_t pending_subs[MAX_PENDING_SUBS];

static void pending_sub_enqueue(const char *type, const char *from, const char *to_user){
    for (int i = 0; i < MAX_PENDING_SUBS; i++) {
        if (!pending_subs[i].active) {
            continue;
        }

        if (strcmp(pending_subs[i].type, type) == 0 && strcmp(pending_subs[i].from, from) == 0 && strcmp(pending_subs[i].to_user, to_user) == 0) {
            return;
        }
    }
    
    int slot = -1;
    
    for (int i = 0; i < MAX_PENDING_SUBS; i++) {
        if (!pending_subs[i].active) { 
            slot = i; 
            
            break; 
        }
    }

    if (slot < 0) {
        for (int i = 0; i < MAX_PENDING_SUBS; i++) {
            if (strcmp(pending_subs[i].to_user, to_user) == 0) { 
                slot = i;
            
                break; 
            }
        }
    }

    if (slot < 0) {
        slot = 0;
    }

    strncpy(pending_subs[slot].type, type, sizeof(pending_subs[slot].type) - 1);
    strncpy(pending_subs[slot].from, from, sizeof(pending_subs[slot].from) - 1);
    strncpy(pending_subs[slot].to_user, to_user, sizeof(pending_subs[slot].to_user) - 1);
    
    pending_subs[slot].type[sizeof(pending_subs[slot].type) - 1] = '\0';
    pending_subs[slot].from[sizeof(pending_subs[slot].from) - 1] = '\0';
    pending_subs[slot].to_user[sizeof(pending_subs[slot].to_user) - 1] = '\0';
    pending_subs[slot].active = 1;

    xmpp_persist_save_pending_subs();
}

static void pending_sub_drain(xmpp_client_ctx_t *ctx){
    char stanza[256];

    for (int i = 0; i < MAX_PENDING_SUBS; i++) {
        if (!pending_subs[i].active) {
            continue;
        }
        
        if (strcmp(pending_subs[i].to_user, ctx->username) != 0) {
            continue;
        }

        snprintf(stanza, sizeof(stanza),
            "<presence type='%s' from='%s' to='%s'/>",
            pending_subs[i].type,
            pending_subs[i].from,
            ctx->full_jid);

        send_raw(ctx, stanza);

        pending_subs[i].active = 0;
    }

    xmpp_persist_save_pending_subs();
}

const int xmpp_credential_count = (int)(sizeof(xmpp_credentials) / sizeof(xmpp_credentials[0]));

static xmpp_client_ctx_t *find_client_by_jid(const char *bare_jid) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (client_registry[i].pcb == NULL) {
            continue;
        }

        if (client_registry[i].state < STATE_SESSION) {
            continue;
        }

        const char *full = client_registry[i].full_jid;
        size_t bare_len = strlen(bare_jid);

        if (strncmp(full, bare_jid, bare_len) == 0 && (full[bare_len] == '/' || full[bare_len] == '\0')) {
            return &client_registry[i];
        }
    }

    return NULL;
}

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
            return -1;
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
    xmpp_log("send", data, strlen(data));

    if (ctx->tls_established) {
        size_t total = strlen(data);
        const unsigned char *p = (const unsigned char *)data;

        while (total > 0) {
            int written = mbedtls_ssl_write(&ctx->tls_ssl, p, total);

            if (written == MBEDTLS_ERR_SSL_WANT_WRITE || written == MBEDTLS_ERR_SSL_WANT_READ) {
                if (ctx->pcb) {
                    tcp_output(ctx->pcb);
                }

                written = mbedtls_ssl_write(&ctx->tls_ssl, p, total);
                
                if (written <= 0) {
                    break;
                }
            }
            else if (written <= 0) {
                break;
            }

            p += written;
            total -= (size_t)written;
        }

        if (ctx->pcb) {
            tcp_output(ctx->pcb);
        }
    }
    else {
        tcp_write(ctx->pcb, data, strlen(data), TCP_WRITE_FLAG_COPY);

        tcp_output(ctx->pcb);
    }

    xmpp_sm_on_stanza_sent(ctx);
}

void handle_roster_request(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];
    
    if (stanza->type == XMPP_IQ_SET) {
        roster_store_set_from_payload(ctx->username, stanza->payload);

        xmpp_persist_save_roster();

        roster_version++;

        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s'/>",
            stanza->id, ctx->full_jid);

        send_raw(ctx, response);
        
        for (int i = 0; i < MAX_USERS; i++) {
            if (client_registry[i].pcb == NULL){ 
                continue;
            }

            if (client_registry[i].state < STATE_SESSION) {
                continue;
            }

            if (&client_registry[i] == ctx) {
                continue;
            }

            if (strcmp(client_registry[i].username, ctx->username) != 0) {
                continue;
            }

            char push_with_to[1200];

            snprintf(push_with_to, sizeof(push_with_to),
                "<iq type='set' to='%s'>"
                  "<query xmlns='jabber:iq:roster'>%s</query>"
                "</iq>",
                client_registry[i].full_jid, stanza->payload);

            send_raw(&client_registry[i], push_with_to);
        }

        return;
    }
    
    int has_ver = (strstr(stanza->payload, "ver=") != NULL || strstr(stanza->payload, "ver ") != NULL);

    char roster_items[2048] = {0};

    roster_store_get_items(ctx->username, roster_items, sizeof(roster_items));

    char big_response[2300];

    if (has_ver) {
        snprintf(big_response, sizeof(big_response),
            "<iq type='result' id='%s' to='%s'>"
              "<query xmlns='jabber:iq:roster' ver='%d'>%s</query>"
            "</iq>",
            stanza->id, ctx->full_jid, roster_version, roster_items);
    }
    else {
        snprintf(big_response, sizeof(big_response),
            "<iq type='result' id='%s' to='%s'>"
              "<query xmlns='jabber:iq:roster'>%s</query>"
            "</iq>",
            stanza->id, ctx->full_jid, roster_items);
    }

    send_raw(ctx, big_response);
}

void handle_initial_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];

    if (stanza->payload[0] != '\0') {
        strncpy(ctx->presence_payload, stanza->payload, sizeof(ctx->presence_payload) - 1);

        ctx->presence_payload[sizeof(ctx->presence_payload) - 1] = '\0';
    }
    else {
        ctx->presence_payload[0] = '\0';
    }
    
    for (int i = 0; i < MAX_USERS; i++) {
        if (client_registry[i].pcb == NULL) {
            continue;
        }

        if (client_registry[i].state < STATE_SESSION) {
            continue;
        }
        
        if (ctx->presence_payload[0] != '\0') {
            snprintf(response, sizeof(response),
                "<presence from='%s' to='%s' xml:lang='en'>%s</presence>",
                ctx->full_jid, client_registry[i].full_jid,
                ctx->presence_payload);
        }
        else {
            snprintf(response, sizeof(response),
                "<presence from='%s' to='%s' xml:lang='en'/>",
                ctx->full_jid, client_registry[i].full_jid);
        }

        send_raw(&client_registry[i], response);
    }
    
    char bare_from[64] = {0};

    strncpy(bare_from, ctx->full_jid, sizeof(bare_from) - 1);

    char *from_slash = strchr(bare_from, '/');

    if (from_slash) {
        *from_slash = '\0';
    }

    for (int i = 0; i < MAX_USERS; i++) {
        if (client_registry[i].pcb  == NULL) {
            continue;
        }

        if (client_registry[i].state < STATE_SESSION) {
            continue;
        }

        if (&client_registry[i] == ctx) {
            continue;
        }

        char bare_to[64] = {0};

        strncpy(bare_to, client_registry[i].full_jid, sizeof(bare_to) - 1);

        char *to_slash = strchr(bare_to, '/');
        
        if (to_slash) {
            *to_slash = '\0';
        }
        
        {
            char peer_bare[64] = {0};

            strncpy(peer_bare, client_registry[i].full_jid, sizeof(peer_bare) - 1);
            
            char *peer_sl = strchr(peer_bare, '/');
            
            if (peer_sl) {
                *peer_sl = '\0';
            }

            char probe_resp[1024];

            if (client_registry[i].presence_payload[0] != '\0') {
                snprintf(probe_resp, sizeof(probe_resp),
                    "<presence from='%s' to='%s'>%s</presence>",
                    client_registry[i].full_jid, ctx->full_jid,
                    client_registry[i].presence_payload);
            }
            else {
                snprintf(probe_resp, sizeof(probe_resp),
                    "<presence from='%s' to='%s'/>",
                    client_registry[i].full_jid, ctx->full_jid);
            }

            send_raw(ctx, probe_resp);
        }
    }

    pending_sub_drain(ctx);

    offline_msg_drain(ctx);
}

private_store_entry_t private_store[PRIVATE_STORAGE_SLOTS];

static private_store_entry_t *private_store_find(const char *username, const char *ns) {
    for (int i = 0; i < PRIVATE_STORAGE_SLOTS; i++) {
        if (private_store[i].active && strncmp(private_store[i].username, username, 32) == 0 && strncmp(private_store[i].ns, ns, PRIVATE_NS_MAX) == 0) {
            return &private_store[i];
        }
    }

    return NULL;
}

static int private_store_upsert(const char *username, const char *ns, const char *xml_data, size_t xml_len) {
    private_store_entry_t *slot = private_store_find(username, ns);

    if (!slot) {
        for (int i = 0; i < PRIVATE_STORAGE_SLOTS; i++) {
            if (!private_store[i].active) {
                slot = &private_store[i];

                break;
            }
        }
    }

    if (!slot) {
        return -1;
    }

    if (xml_len >= PRIVATE_XML_MAX) {
        xml_len = PRIVATE_XML_MAX - 1;
    }

    strncpy(slot->username, username, sizeof(slot->username) - 1);

    slot->username[sizeof(slot->username) - 1] = '\0';

    strncpy(slot->ns, ns, sizeof(slot->ns) - 1);

    slot->ns[sizeof(slot->ns) - 1] = '\0';

    memcpy(slot->xml, xml_data, xml_len);

    slot->xml[xml_len] = '\0';
    slot->active = 1;

    return 0;
}

void handle_private_storage(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char inner_ns[PRIVATE_NS_MAX] = "";
    char child_elem[64] = "storage";

    const char *after_query = strchr(stanza->payload, '>');

    if (after_query) {
        after_query++;
        const char *p = after_query;

        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') { 
            p++;
        }

        if (*p == '<') {
            p++;
            const char *name_end = p;

            while (*name_end && *name_end != ' ' && *name_end != '/' && *name_end != '>') {
                name_end++;
            }
            
            size_t nlen = (size_t)(name_end - p);
            
            if (nlen > 0 && nlen < sizeof(child_elem) - 1) {
                strncpy(child_elem, p, nlen);

                child_elem[nlen] = '\0';
            }
        }

        const char *xmlns_attr = strstr(after_query, "xmlns=");

        if (xmlns_attr) {
            xmlns_attr += 6;
            char quote = *xmlns_attr;

            if (quote == '\'' || quote == '"') {
                xmlns_attr++;
                const char *end = strchr(xmlns_attr, quote);

                if (end) {
                    int ns_len = (int)(end - xmlns_attr);
                    
                    if (ns_len > 0 && ns_len < (int)sizeof(inner_ns) - 1) {
                        strncpy(inner_ns, xmlns_attr, ns_len);

                        inner_ns[ns_len] = '\0';
                    }
                }
            }
        }
    }

    if (inner_ns[0] == '\0') {
        char err[512];

        snprintf(err, sizeof(err),
            "<iq type='error' id='%s' to='%s'>"
              "<query xmlns='jabber:iq:private'/>"
              "<error code='406' type='modify'>"
                "<not-acceptable"
                  " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
              "</error>"
            "</iq>",
            stanza->id, ctx->full_jid);

        send_raw(ctx, err);

        return;
    }

    if (stanza->type == XMPP_IQ_SET) {
        const char *xml_start = strchr(stanza->payload, '>');

        if (xml_start) {
            xml_start++;
            const char *xml_end = strstr(stanza->payload, "</query>");

            if (xml_end && xml_end > xml_start) {
                size_t xml_len = (size_t)(xml_end - xml_start);

                if (private_store_upsert(ctx->username, inner_ns, xml_start, xml_len) != 0) {
                    char err[512];

                    snprintf(err, sizeof(err),
                        "<iq type='error' id='%s' to='%s'>"
                          "<error type='wait' code='500'>"
                            "<resource-constraint"
                              " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                          "</error>"
                        "</iq>",
                        stanza->id, ctx->full_jid);
                    
                    send_raw(ctx, err);
                    
                    return;
                }

                xmpp_persist_save_private();
            }
        }

        char response[256];

        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s'/>",
            stanza->id, ctx->full_jid);
        
        send_raw(ctx, response);
    
        return;
    }
    
    const char *inner_xml;
    char empty_elem[PRIVATE_NS_MAX + 64];

    private_store_entry_t *slot = private_store_find(ctx->username, inner_ns);

    if (slot != NULL) {
        inner_xml = slot->xml;
    }
    else {
        snprintf(empty_elem, sizeof(empty_elem), "<%s xmlns='%s'/>", child_elem, inner_ns);

        inner_xml = empty_elem;
    }

    char response[1300];
    int written = snprintf(response, sizeof(response),
        "<iq type='result' id='%s' to='%s'>"
          "<query xmlns='jabber:iq:private'>%s</query>"
        "</iq>",
        stanza->id, ctx->full_jid, inner_xml);

    if (written < 0 || (size_t)written >= sizeof(response)) {
        char err[512];

        snprintf(err, sizeof(err),
            "<iq type='error' id='%s' to='%s'>"
              "<error type='wait' code='500'>"
                "<resource-constraint"
                  " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
              "</error>"
            "</iq>",
            stanza->id, ctx->full_jid);
        
        send_raw(ctx, err);
        
        return;
    }

    send_raw(ctx, response);
}

void handle_muc_admin(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];
    
    if (stanza->type == XMPP_IQ_SET) {
        int want_kick = (strstr(stanza->payload, "role='none'") != NULL || strstr(stanza->payload, "role=\"none\"") != NULL);
        int want_ban = (strstr(stanza->payload, "affiliation='outcast'") != NULL || strstr(stanza->payload, "affiliation=\"outcast\"") != NULL);

        if (want_kick || want_ban) {
            char target_nick[MAX_NICK_LEN] = {0};
            const char *nick_p = strstr(stanza->payload, "nick='");

            if (!nick_p) {
                nick_p = strstr(stanza->payload, "nick=\"");
            }

            if (nick_p) {
                nick_p += 6;
                char q = *(nick_p - 1);
                const char *end = strchr(nick_p, q);

                if (end) {
                    int nlen = (int)(end - nick_p);

                    if (nlen >= MAX_NICK_LEN) {
                        nlen = MAX_NICK_LEN - 1;
                    }

                    strncpy(target_nick, nick_p, nlen);
                }
            }

            char reason[128] = {0};
            const char *reason_start = strstr(stanza->payload, "<reason>");

            if (reason_start) {
                reason_start += 8;
                const char *reason_end = strstr(reason_start, "</reason>");

                if (reason_end) {
                    int rlen = (int)(reason_end - reason_start);

                    if (rlen >= (int)sizeof(reason)) {
                        rlen = sizeof(reason) - 1;
                    }

                    strncpy(reason, reason_start, rlen);
                }
            }

            char room_name[MAX_ROOM_NAME_LEN] = {0};
            char *at = strchr(stanza->to, '@');

            if (at) {
                int name_len = (int)(at - stanza->to);

                if (name_len >= MAX_ROOM_NAME_LEN) {
                    name_len = MAX_ROOM_NAME_LEN - 1;
                }

                strncpy(room_name, stanza->to, name_len);
            }

            char bare_jid[64] = {0};

            strncpy(bare_jid, stanza->to, sizeof(bare_jid) - 1);

            int status_code = want_ban ? 301 : 307;

            for (int i = 0; i < MAX_ROOMS; i++) {
                if (!rooms[i].active || strcmp(rooms[i].name, room_name) != 0) {
                    continue;
                }

                room_t *r = &rooms[i];

                for (int j = 0; j < MAX_USERS_PER_ROOM; j++) {
                    if (!r->users[j].active) {
                        continue;
                    }

                    if (target_nick[0] != '\0' && strcmp(r->users[j].nick, target_nick) != 0) {
                        continue;
                    }

                    char kicked_nick[MAX_NICK_LEN];

                    strncpy(kicked_nick, r->users[j].nick, MAX_NICK_LEN - 1);

                    char kicked_jid[64];

                    strncpy(kicked_jid, r->users[j].jid, 63);

                    for (int k = 0; k < MAX_USERS_PER_ROOM; k++) {
                        if (!r->users[k].active || k == j) {
                            continue;
                        }

                        xmpp_client_ctx_t *bcast_target = find_client_by_jid(r->users[k].jid);

                        if (!bcast_target) {
                            continue;
                        }

                        char msg[512];

                        if (reason[0] != '\0') {
                            snprintf(msg, sizeof(msg),
                                "<presence type='unavailable' from='%s/%s' to='%s'>"
                                  "<x xmlns='http://jabber.org/protocol/muc#user'>"
                                    "<item affiliation='%s' role='none'>"
                                      "<reason>%s</reason>"
                                    "</item>"
                                    "<status code='%d'/>"
                                  "</x>"
                                "</presence>",
                                bare_jid, kicked_nick, r->users[k].jid,
                                want_ban ? "outcast" : "none",
                                reason, status_code);
                        }
                        else {
                            snprintf(msg, sizeof(msg),
                                "<presence type='unavailable' from='%s/%s' to='%s'>"
                                  "<x xmlns='http://jabber.org/protocol/muc#user'>"
                                    "<item affiliation='%s' role='none'/>"
                                    "<status code='%d'/>"
                                  "</x>"
                                "</presence>",
                                bare_jid, kicked_nick, r->users[k].jid,
                                want_ban ? "outcast" : "none",
                                status_code);
                        }

                        send_raw(bcast_target, msg);
                    }

                    {
                        xmpp_client_ctx_t *kicked_target = find_client_by_jid(kicked_jid);
                        
                        if (kicked_target) {
                            char self_msg[640];

                            if (reason[0] != '\0') {
                                snprintf(self_msg, sizeof(self_msg),
                                    "<presence type='unavailable' from='%s/%s' to='%s'>"
                                      "<x xmlns='http://jabber.org/protocol/muc#user'>"
                                        "<item affiliation='%s' role='none'>"
                                          "<reason>%s</reason>"
                                        "</item>"
                                        "<status code='110'/>"
                                        "<status code='%d'/>"
                                      "</x>"
                                    "</presence>",
                                    bare_jid, kicked_nick, kicked_jid,
                                    want_ban ? "outcast" : "none",
                                    reason, status_code);
                            }
                            else {
                                snprintf(self_msg, sizeof(self_msg),
                                    "<presence type='unavailable' from='%s/%s' to='%s'>"
                                      "<x xmlns='http://jabber.org/protocol/muc#user'>"
                                        "<item affiliation='%s' role='none'/>"
                                        "<status code='110'/>"
                                        "<status code='%d'/>"
                                      "</x>"
                                    "</presence>",
                                    bare_jid, kicked_nick, kicked_jid,
                                    want_ban ? "outcast" : "none",
                                    status_code);
                            }

                            send_raw(kicked_target, self_msg);
                        }
                    }

                    if (want_ban) {
                        char kicked_bare[64] = {0};

                        strncpy(kicked_bare, kicked_jid, sizeof(kicked_bare) - 1);

                        char *kb_sl = strchr(kicked_bare, '/');

                        if (kb_sl) {
                            *kb_sl = '\0';
                        }

                        if (r->banned_count < MAX_BANNED_PER_ROOM) {
                            strncpy(r->banned_jids[r->banned_count], kicked_bare, 63);

                            r->banned_jids[r->banned_count][63] = '\0';
                            r->banned_count++;

                            xmpp_persist_save_rooms();
                        }
                    }

                    memset(&r->users[j], 0, sizeof(participant_t));

                    break;
                }

                break;
            }

            snprintf(response, sizeof(response),
                "<iq type='result' id='%s' to='%s'/>",
                stanza->id, ctx->full_jid);

            send_raw(ctx, response);

            return;
        }

        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s'/>",
            stanza->id, ctx->full_jid);

        send_raw(ctx, response);

        return;
    }

    int want_owner = (strstr(stanza->payload, "affiliation='owner'") || strstr(stanza->payload, "affiliation=\"owner\""));
    int want_admin = (strstr(stanza->payload, "affiliation='admin'") || strstr(stanza->payload, "affiliation=\"admin\""));
    int want_member = (strstr(stanza->payload, "affiliation='member'") || strstr(stanza->payload, "affiliation=\"member\""));

    if (want_owner) {
        char owner_jid[64] = {0};
        char *at = strchr(stanza->to, '@');

        if (at) {
            char room_name[MAX_ROOM_NAME_LEN] = {0};
            int name_len = (int)(at - stanza->to);

            if (name_len >= MAX_ROOM_NAME_LEN) {
                name_len = MAX_ROOM_NAME_LEN - 1;
            }

            strncpy(room_name, stanza->to, name_len);

            for (int i = 0; i < MAX_ROOMS; i++) {
                if (rooms[i].active && strcmp(rooms[i].name, room_name) == 0) {
                    if (rooms[i].creator_jid[0] != '\0') {
                        strncpy(owner_jid, rooms[i].creator_jid, 63);
                    }
                    else {
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

void handle_blocklist(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[256];

    if (stanza->type == XMPP_IQ_GET) {
        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s'>"
              "<blocklist xmlns='urn:xmpp:blocking'/>"
            "</iq>",
            stanza->id, ctx->full_jid);
    }
    else {
        snprintf(response, sizeof(response),
            "<iq type='result' id='%s' to='%s'/>",
            stanza->id, ctx->full_jid);
    }

    send_raw(ctx, response);
}

void handle_version(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];

    snprintf(response, sizeof(response),
        "<iq type='result' id='%s' from='angelic.local' to='%s'>"
          "<query xmlns='jabber:iq:version'>"
            "<name>AngelicKernel XMPP</name>"
            "<version>1.0</version>"
            "<os>Bare Metal UEFI</os>"
          "</query>"
        "</iq>",
        stanza->id, ctx->full_jid);

    send_raw(ctx, response);
}

void handle_last(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[256];

    snprintf(response, sizeof(response),
        "<iq type='result' id='%s' from='angelic.local' to='%s'>"
          "<query xmlns='jabber:iq:last' seconds='0'/>"
        "</iq>",
        stanza->id, ctx->full_jid);

    send_raw(ctx, response);
}

void handle_ping(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[256];

    snprintf(response, sizeof(response),
        "<iq type='result' id='%s' to='%s'/>",
        stanza->id, ctx->full_jid);

    send_raw(ctx, response);
}

void handle_general_success(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];

    snprintf(response, sizeof(response),
        "<iq type='result' id='%s' to='%s'/>",
        stanza->id, ctx->full_jid);

    send_raw(ctx, response);
}

void handle_core_bind(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    if (ctx->state != STATE_BIND) {
        char err[512];
        const char *from_jid = (stanza->to[0] != '\0') ? stanza->to : XMPP_DOMAIN;
        const char *to_jid = (ctx->full_jid[0] != '\0') ? ctx->full_jid : "unknown";

        if (stanza->id[0] != '\0') {
            snprintf(err, sizeof(err),
                "<iq type='error' from='%s' to='%s' id='%s'>"
                  "<error type='cancel'>"
                    "<unexpected-request"
                      " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                  "</error>"
                "</iq>",
                from_jid, to_jid, stanza->id);
        }
        else {
            snprintf(err, sizeof(err),
                "<iq type='error' from='%s' to='%s'>"
                  "<error type='cancel'>"
                    "<unexpected-request"
                      " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                  "</error>"
                "</iq>",
                from_jid, to_jid);
        }

        send_raw(ctx, err);

        return;
    }
    
    unsigned int resource_id = secure_random_u32() % 9999;
    
    snprintf(ctx->full_jid, sizeof(ctx->full_jid), "%s@%s/unikernel-%d", ctx->username, XMPP_DOMAIN, resource_id);

    for (int i = 0; i < MAX_USERS; i++) {
        if (&client_registry[i] == ctx) {
            continue;
        }

        if (client_registry[i].pcb == NULL) {
            continue;
        }

        if (strcmp(client_registry[i].username, ctx->username) == 0) {
            {
                const char *conflict_err =
                    "<stream:error>"
                      "<conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                    "</stream:error>"
                    "</stream:stream>";

                if (client_registry[i].tls_established) {
                    mbedtls_ssl_write(&client_registry[i].tls_ssl, (const unsigned char *)conflict_err, strlen(conflict_err));

                    if (client_registry[i].pcb) {
                        tcp_output(client_registry[i].pcb);
                    }
                }
                else if (client_registry[i].pcb) {
                    tcp_write(client_registry[i].pcb, conflict_err, strlen(conflict_err), TCP_WRITE_FLAG_COPY);

                    tcp_output(client_registry[i].pcb);
                }
            }

            xmpp_tls_client_free(&client_registry[i]);
            
            tcp_close(client_registry[i].pcb);
            
            memset(&client_registry[i], 0, sizeof(xmpp_client_ctx_t));
        }
    }

    char response[1024];
    
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

void handle_core_session(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[256];

    snprintf(response, sizeof(response), "<iq type='result' id='%s'/>", stanza->id);

    send_raw(ctx, response);

    ctx->state = STATE_READY;
}

void handle_muc_owner(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];
    
    if (stanza->type == XMPP_IQ_SET && strstr(stanza->payload, "<destroy")) {
        char room_name_d[MAX_ROOM_NAME_LEN] = {0};
        char *at_d = strchr(stanza->to, '@');

        if (at_d) {
            int nl = (int)(at_d - stanza->to);
            
            if (nl >= MAX_ROOM_NAME_LEN) {
                nl = MAX_ROOM_NAME_LEN - 1;
            }

            strncpy(room_name_d, stanza->to, nl);
        }

        char alt_jid[64] = {0};
        const char *djid = strstr(stanza->payload, "<destroy");

        if (djid) {
            const char *ajp = strstr(djid, "jid=");

            if (ajp) {
                ajp += 4;
                char aq = *ajp++;
                const char *aje = strchr(ajp, aq);

                if (aje) {
                    int al = (int)(aje - ajp);

                    if (al >= 64) {
                        al = 63;
                    }

                    strncpy(alt_jid, ajp, al);
                }
            }
        }

        char destroy_reason[128] = {0};
        const char *drs = strstr(stanza->payload, "<reason>");

        if (drs) {
            drs += 8;
            const char *dre = strstr(drs, "</reason>");

            if (dre) {
                int drl = (int)(dre - drs);

                if (drl >= 128) {
                    drl = 127;
                }
                
                strncpy(destroy_reason, drs, drl);
            }
        }

        for (int ri = 0; ri < MAX_ROOMS; ri++) {
            if (!rooms[ri].active || strcmp(rooms[ri].name, room_name_d) != 0) {
                continue;
            }

            room_t *rd = &rooms[ri];

            char bare_jid_d[64] = {0};
            int bl = (int)(strchr(stanza->to, '/') ? strchr(stanza->to, '/') - stanza->to : (int)strlen(stanza->to));

            if (bl >= 64) {
                bl = 63;
            }
            
            strncpy(bare_jid_d, stanza->to, bl);
            strncpy(bare_jid_d, stanza->to, 63);

            for (int ui = 0; ui < MAX_USERS_PER_ROOM; ui++) {
                if (!rd->users[ui].active) {
                    continue;
                }

                xmpp_client_ctx_t *du = find_client_by_jid(rd->users[ui].jid);

                if (!du) {
                    continue;
                }

                char dmsg[640];

                if (alt_jid[0] != '\0' && destroy_reason[0] != '\0') {
                    snprintf(dmsg, sizeof(dmsg),
                        "<presence type='unavailable' from='%s/%s' to='%s'>"
                          "<x xmlns='http://jabber.org/protocol/muc#user'>"
                            "<item affiliation='none' role='none'/>"
                            "<destroy jid='%s'>"
                              "<reason>%s</reason>"
                            "</destroy>"
                          "</x>"
                        "</presence>",
                        bare_jid_d, rd->users[ui].nick, rd->users[ui].jid,
                        alt_jid, destroy_reason);
                }
                else if (alt_jid[0] != '\0') {
                    snprintf(dmsg, sizeof(dmsg),
                        "<presence type='unavailable' from='%s/%s' to='%s'>"
                          "<x xmlns='http://jabber.org/protocol/muc#user'>"
                            "<item affiliation='none' role='none'/>"
                            "<destroy jid='%s'/>"
                          "</x>"
                        "</presence>",
                        bare_jid_d, rd->users[ui].nick, rd->users[ui].jid, alt_jid);
                }
                else {
                    snprintf(dmsg, sizeof(dmsg),
                        "<presence type='unavailable' from='%s/%s' to='%s'>"
                          "<x xmlns='http://jabber.org/protocol/muc#user'>"
                            "<item affiliation='none' role='none'/>"
                            "<destroy/>"
                          "</x>"
                        "</presence>",
                        bare_jid_d, rd->users[ui].nick, rd->users[ui].jid);
                }

                send_raw(du, dmsg);
            }

            memset(rd, 0, sizeof(room_t));

            xmpp_persist_save_rooms();
            
            break;
        }

        char dest_resp[256];

        snprintf(dest_resp, sizeof(dest_resp), "<iq type='result' id='%s' to='%s'/>", stanza->id, ctx->full_jid);

        send_raw(ctx, dest_resp);

        return;
    }

    if (stanza->type == XMPP_IQ_SET || strstr(stanza->payload, "type='submit'") || strstr(stanza->payload, "type=\"submit\"")) {
        char room_name[MAX_ROOM_NAME_LEN] = {0};
        char *at = strchr(stanza->to, '@');

        if (at) {
            int name_len = (int)(at - stanza->to);

            if (name_len >= MAX_ROOM_NAME_LEN) {
                name_len = MAX_ROOM_NAME_LEN - 1;
            }

            strncpy(room_name, stanza->to, name_len);
        }

        for (int i = 0; i < MAX_ROOMS; i++) {
            if (rooms[i].active && strcmp(rooms[i].name, room_name) == 0) {
                rooms[i].locked = 0;
                
                #define PARSE_BOOL_FIELD(var_str, field) do { const char *_vp = strstr(stanza->payload, (var_str)); if (_vp) { const char *_val = strstr(_vp, "<value>"); if (_val) { _val += 7; rooms[i].field = (_val[0] == '1' || strncmp(_val, "true", 4) == 0) ? 1 : 0; } } } while (0)

                PARSE_BOOL_FIELD("muc#roomconfig_persistentroom", persistent);
                PARSE_BOOL_FIELD("muc#roomconfig_moderatedroom", moderated);
                PARSE_BOOL_FIELD("muc#roomconfig_membersonly", members_only);

                {
                    const char *_wp = strstr(stanza->payload, "muc#roomconfig_whois");

                    if (_wp) {
                        const char *_wv = strstr(_wp, "<value>");

                        if (_wv) {
                            _wv += 7;
                            rooms[i].semi_anon = (strncmp(_wv, "moderators", 10) == 0) ? 1 : 0;
                        }
                    }
                }

                #undef PARSE_BOOL_FIELD

                xmpp_persist_save_rooms();

                break;
            }
        }

        snprintf(response, sizeof(response), "<iq type='result' id='%s' to='%s' from='%s'/>", stanza->id, ctx->full_jid, stanza->to);

        send_raw(ctx, response);
    }
    else {
        char room_name_lkp[MAX_ROOM_NAME_LEN] = {0};
        char *at_ptr = strchr(stanza->to, '@');

        if (at_ptr) {
            int nl = (int)(at_ptr - stanza->to);

            if (nl >= MAX_ROOM_NAME_LEN) {
                nl = MAX_ROOM_NAME_LEN - 1;
            }

            strncpy(room_name_lkp, stanza->to, nl);
        }

        const char *room_label = room_name_lkp[0] ? room_name_lkp : "unnamed room";
        int is_persistent = 0;
        int is_public = 1;
        int is_moderated = 0;
        int is_members_only = 0;
        int allow_invites = 1;
        int semi_anon = 1;

        for (int i = 0; i < MAX_ROOMS; i++) {
            if (rooms[i].active && strcmp(rooms[i].name, room_name_lkp) == 0) {
                semi_anon = rooms[i].semi_anon;
                is_persistent = rooms[i].persistent;
                is_moderated = rooms[i].moderated;
                is_members_only = rooms[i].members_only;

                break;
            }
        }

        char big_response[2048];

        snprintf(big_response, sizeof(big_response),
            "<iq type='result' id='%s' to='%s' from='%s'>"
              "<query xmlns='http://jabber.org/protocol/muc#owner'>"
                "<x xmlns='jabber:x:data' type='form'>"
                  "<field type='hidden' var='FORM_TYPE'>"
                    "<value>http://jabber.org/protocol/muc#roomconfig</value>"
                  "</field>"
                  "<field type='text-single'"
                         " var='muc#roomconfig_roomname'"
                         " label='Room Name'>"
                    "<value>%s</value>"
                  "</field>"
                  "<field type='text-single'"
                         " var='muc#roomconfig_roomdesc'"
                         " label='Short Description of Room'>"
                    "<value></value>"
                  "</field>"
                  "<field type='boolean'"
                         " var='muc#roomconfig_persistentroom'"
                         " label='Make Room Persistent'>"
                    "<value>%d</value>"
                  "</field>"
                  "<field type='boolean'"
                         " var='muc#roomconfig_publicroom'"
                         " label='Make Room Publicly Listed'>"
                    "<value>%d</value>"
                  "</field>"
                  "<field type='boolean'"
                         " var='muc#roomconfig_moderatedroom'"
                         " label='Enable Moderation'>"
                    "<value>%d</value>"
                  "</field>"
                  "<field type='boolean'"
                         " var='muc#roomconfig_membersonly'"
                         " label='Make Room Members-Only'>"
                    "<value>%d</value>"
                  "</field>"
                  "<field type='boolean'"
                         " var='muc#roomconfig_allowinvites'"
                         " label='Allow Occupants to Invite Others'>"
                    "<value>%d</value>"
                  "</field>"
                  "<field type='list-single'"
                         " var='muc#roomconfig_whois'"
                         " label='Who Can See Occupant Real JIDs'>"
                    "<value>%s</value>"
                    "<option label='Moderators Only'>"
                      "<value>moderators</value>"
                    "</option>"
                    "<option label='Anyone'>"
                      "<value>anyone</value>"
                    "</option>"
                  "</field>"
                "</x>"
              "</query>"
            "</iq>",
            stanza->id, ctx->full_jid, stanza->to,
            room_label,
            is_persistent,
            is_public,
            is_moderated,
            is_members_only,
            allow_invites,
            semi_anon ? "moderators" : "anyone");

        send_raw(ctx, big_response);

        return;
    }
}

void handle_disco_info(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[1024];

    char *at = strchr(stanza->to, '@');

    if (at && strstr(stanza->to, "conference.angelic.local")) {
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
            int room_semi_anon = 1;

            for (int i = 0; i < MAX_ROOMS; i++) {
                if (rooms[i].active && strcmp(rooms[i].name, room_name) == 0) {
                    room_semi_anon = rooms[i].semi_anon;

                    break;
                }
            }
            
            const char *anon_feature = room_semi_anon
                ? "<feature var='muc_semianonymous'/>"
                : "<feature var='muc_nonanonymous'/>";

            int room_persistent = 0;
            int room_moderated = 0;
            int room_members_only = 0;

            for (int ri = 0; ri < MAX_ROOMS; ri++) {
                if (rooms[ri].active && strcmp(rooms[ri].name, room_name) == 0) {
                    room_persistent = rooms[ri].persistent;
                    room_moderated = rooms[ri].moderated;
                    room_members_only = rooms[ri].members_only;

                    break;
                }
            }

            const char *persist_feat = room_persistent
                ? "<feature var='muc_persistent'/>"
                : "<feature var='muc_temporary'/>";
            const char *mod_feat = room_moderated
                ? "<feature var='muc_moderated'/>"
                : "<feature var='muc_unmoderated'/>";
            const char *open_feat = room_members_only
                ? "<feature var='muc_membersonly'/>"
                : "<feature var='muc_open'/>";

            char room_info[1280];
            snprintf(room_info, sizeof(room_info),
                "<iq type='result' from='%s' to='%s' id='%s'>"
                  "<query xmlns='http://jabber.org/protocol/disco#info'>"
                    "<identity category='conference' type='text' name='%s'/>"
                    "<feature var='http://jabber.org/protocol/muc'/>"
                    "%s%s%s%s"
                  "</query>"
                "</iq>",
                stanza->to, ctx->full_jid, stanza->id,
                room_name,
                anon_feature, persist_feat, mod_feat, open_feat);

            send_raw(ctx, room_info);

            return;
        }
        else {
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
        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
              "<query xmlns='http://jabber.org/protocol/disco#info'>"
                "<identity category='conference' type='text' name='Chat Service'/>"
                "<feature var='http://jabber.org/protocol/muc'/>"
              "</query>"
            "</iq>",
            stanza->to, ctx->full_jid, stanza->id);
    }
    else if (at && !strstr(stanza->to, "conference")) {
        if (strstr(stanza->payload, "node=") != NULL) {
            char bare_target_caps[64] = {0};
            
            strncpy(bare_target_caps, stanza->to, sizeof(bare_target_caps) - 1);
            
            char *caps_slash = strchr(bare_target_caps, '/');
            
            if (caps_slash) {
                *caps_slash = '\0';
            }

            int forwarded = 0;
            
            for (int i = 0; i < MAX_USERS; i++) {
                if (client_registry[i].pcb == NULL) {
                    continue;
                }

                if (client_registry[i].state < STATE_SESSION) {
                    continue;
                }

                char bare_reg[64] = {0};
                
                strncpy(bare_reg, client_registry[i].full_jid, sizeof(bare_reg) - 1);
                
                char *reg_sl = strchr(bare_reg, '/');
                
                if (reg_sl) {
                    *reg_sl = '\0';
                }

                if (strcmp(bare_target_caps, bare_reg) == 0) {
                    char fwd[1024];

                    snprintf(fwd, sizeof(fwd),
                        "<iq type='get' from='%s' to='%s' id='%s'>"
                          "<query xmlns='http://jabber.org/protocol/disco#info'"
                                 " %s/>"
                        "</iq>",
                        ctx->full_jid, client_registry[i].full_jid, stanza->id,
                        stanza->payload[0] == '<' ? "" : stanza->payload);

                    send_raw(&client_registry[i], fwd);

                    forwarded = 1;

                    break;
                }
            }

            if (!forwarded) {
                snprintf(response, sizeof(response),
                    "<iq type='error' from='%s' to='%s' id='%s'>"
                      "<error type='cancel' code='503'>"
                        "<service-unavailable"
                          " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                      "</error>"
                    "</iq>",
                    stanza->to, ctx->full_jid, stanza->id);

                send_raw(ctx, response);
            }

            return;
        }

        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
              "<query xmlns='http://jabber.org/protocol/disco#info'>"
                "<identity category='account' type='registered'/>"
              "</query>"
            "</iq>",
            stanza->to, ctx->full_jid, stanza->id);
    }
    else {
        snprintf(response, sizeof(response),
            "<iq type='result' from='%s' to='%s' id='%s'>"
              "<query xmlns='http://jabber.org/protocol/disco#info'>"
                "<identity category='server' type='im' name='Unikernel XMPP'/>"
                "<feature var='http://jabber.org/protocol/muc'/>"
                "<feature var='jabber:iq:register'/>"
                "<feature var='msgoffline'/>"
              "</query>"
            "</iq>",
            stanza->to, ctx->full_jid, stanza->id);
    }

    send_raw(ctx, response);
}

void handle_disco_items(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    char response[2048];

    if (strstr(stanza->to, "conference.angelic.local")) {
        char *at_di = strchr(stanza->to, '@');

        if (at_di && at_di > stanza->to) {
            char room_name_di[MAX_ROOM_NAME_LEN] = {0};
            int rlen_di = (int)(at_di - stanza->to);

            if (rlen_di >= MAX_ROOM_NAME_LEN) {
                rlen_di = MAX_ROOM_NAME_LEN - 1;
            }
            
            strncpy(room_name_di, stanza->to, rlen_di);

            char occ_items[1536] = {0};
            int room_found_di = 0;

            for (int ri = 0; ri < MAX_ROOMS; ri++) {
                if (!rooms[ri].active || strcmp(rooms[ri].name, room_name_di) != 0) {
                    continue;
                }

                room_found_di = 1;

                for (int ui = 0; ui < MAX_USERS_PER_ROOM; ui++) {
                    if (!rooms[ri].users[ui].active) {
                        continue;
                    }

                    char oi[256];
                    
                    snprintf(oi, sizeof(oi),
                        "<item jid='%s/%s' name='%s'/>",
                        stanza->to, rooms[ri].users[ui].nick,
                        rooms[ri].users[ui].nick);
                    
                    if (strlen(occ_items) + strlen(oi) < sizeof(occ_items) - 1) {
                        strcat(occ_items, oi);
                    }
                }

                break;
            }

            if (!room_found_di) {
                snprintf(response, sizeof(response),
                    "<iq type='error' from='%s' to='%s' id='%s'>"
                      "<error type='cancel'>"
                        "<item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                      "</error>"
                    "</iq>",
                    stanza->to, ctx->full_jid, stanza->id);
            }
            else {
                snprintf(response, sizeof(response),
                    "<iq type='result' from='%s' to='%s' id='%s'>"
                      "<query xmlns='http://jabber.org/protocol/disco#items'>"
                        "%s"
                      "</query>"
                    "</iq>",
                    stanza->to, ctx->full_jid, stanza->id, occ_items);
            }
        }
        else {
            char items[1536] = {0};

            for (int i = 0; i < MAX_ROOMS; i++) {
                if (rooms[i].active) {
                    char item[256];

                    snprintf(item, sizeof(item),
                        "<item jid='%s@conference.angelic.local' name='%s'/>",
                        rooms[i].name, rooms[i].name);

                    if (strlen(items) + strlen(item) < sizeof(items) - 1) {
                        strcat(items, item);
                    }
                }
            }

            snprintf(response, sizeof(response),
                "<iq type='result' from='%s' to='%s' id='%s'>"
                  "<query xmlns='http://jabber.org/protocol/disco#items'>"
                    "%s"
                  "</query>"
                "</iq>",
                stanza->to, ctx->full_jid, stanza->id, items);
        }
    }
    else {
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

void handle_sasl(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    if (!ctx->tls_established) {
        const char *enc_req =
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
              "<encryption-required/>"
            "</failure>";
            
        send_raw(ctx, enc_req);

        return;
    }

    if (stanza->mechanism[0] != '\0' && strcmp(stanza->mechanism, "PLAIN") != 0 && strcmp(stanza->mechanism, "ANONYMOUS") != 0) {
        const char *inv_mech =
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
              "<invalid-mechanism/>"
            "</failure>";

        send_raw(ctx, inv_mech);

        return;
    }

    unsigned char decoded[128] = {0};

    int len = b64decode(stanza->payload, decoded, sizeof(decoded) - 1);

    if (len < 0) {
        const char *bad_enc =
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
              "<incorrect-encoding/>"
            "</failure>";

        send_raw(ctx, bad_enc);

        return;
    }

    ctx->username[0] = '\0';

    if (len > 1) {
        int i = 0;

        while (i < len && decoded[i] != '\0') {
            i++;
        }

        i++;
        
        int j = 0;

        while (i < len && decoded[i] != '\0' && j < 31){
            ctx->username[j++] = decoded[i++];
        }

        ctx->username[j] = '\0';
    }
    
    for (int _ci = 0; ctx->username[_ci] != '\0'; _ci++) {
        char _c = ctx->username[_ci];

        if (_c == '@' || _c == '/' || _c == '<' || _c == '>' || _c == ' ' || _c == '\'' || _c == '"') {
            const char *inv_usr =
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                  "<not-authorized/>"
                "</failure>";

            send_raw(ctx, inv_usr);

            ctx->sasl_failures++;
            
            if (ctx->sasl_failures >= SASL_MAX_FAILURES) {
                const char *pol_vio =
                    "<stream:error>"
                      "<policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                    "</stream:error>"
                    "</stream:stream>";

                send_raw(ctx, pol_vio);

                tcp_close(ctx->pcb);

                ctx->pcb = NULL;
                ctx->state = STATE_CONNECTED;
            }

            return;
        }
    }

    if (ctx->username[0] == '\0') {
        strncpy(ctx->username, "user", 31);
    }
    
    if (strcmp(stanza->mechanism, "PLAIN") == 0) {
        char password[64] = {0};
        
        int pos = 0;

        while (pos < len && decoded[pos] != '\0') {
            pos++;
        }

        pos++;

        while (pos < len && decoded[pos] != '\0') {
            pos++;
        }

        pos++;
        
        int pw_len = 0;

        while (pos < len && decoded[pos] != '\0' && pw_len < 63) {
            password[pw_len++] = decoded[pos++];
        }

        password[pw_len] = '\0';

        int authorized = 0;

        for (int ci = 0; ci < xmpp_credential_count; ci++) {
            if (strcmp(xmpp_credentials[ci].username, ctx->username) == 0 && strcmp(xmpp_credentials[ci].password, password) == 0) {
                authorized = 1;

                break;
            }
        }

        if (!authorized) {
            const char *not_auth =
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                  "<not-authorized/>"
                "</failure>";

            send_raw(ctx, not_auth);

            ctx->sasl_failures++;
            
            if (ctx->sasl_failures >= SASL_MAX_FAILURES) {
                const char *pol_vio =
                    "<stream:error>"
                      "<policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                    "</stream:error>"
                    "</stream:stream>";

                send_raw(ctx, pol_vio);
                
                tcp_close(ctx->pcb);

                ctx->pcb = NULL;
                ctx->state = STATE_CONNECTED;
            }

            return;
        }
    }
    
    const char *resp = "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>";

    send_raw(ctx, resp);
    
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

                strncpy(r->creator_jid, ctx->full_jid, sizeof(r->creator_jid) - 1);

                r->creator_jid[sizeof(r->creator_jid) - 1] = '\0';
                char *slash = strchr(r->creator_jid, '/');

                if (slash) {
                    *slash = '\0';
                }

                r->semi_anon = 1;
                r->locked = 0;
                is_new_room = 1;

                xmpp_persist_save_rooms();

                break;
            }
        }
    }

    if (!r) {
        return;
    }
    
    if (r->locked) {
        char joiner_bare[64] = {0};

        strncpy(joiner_bare, ctx->full_jid, sizeof(joiner_bare) - 1);

        char *joiner_slash = strchr(joiner_bare, '/');

        if (joiner_slash) {
            *joiner_slash = '\0';
        }

        if (strcmp(joiner_bare, r->creator_jid) != 0) {
            char locked_err[512];

            snprintf(locked_err, sizeof(locked_err),
                "<presence type='error' from='%s/%s' to='%s'>"
                  "<error type='cancel' code='404'>"
                    "<item-not-found"
                      " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                  "</error>"
                "</presence>",
                bare_jid, nick, ctx->full_jid);

            send_raw(ctx, locked_err);

            return;
        }
    }

    if (stanza->type == XMPP_PRESENCE_UNAVAILABLE) {
        char response[1024];

        for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
            if (!r->users[i].active) {
                continue;
            }

            if (strcmp(r->users[i].nick, nick) != 0) {
                continue;
            }

            for (int j = 0; j < MAX_USERS_PER_ROOM; j++) {
                if (!r->users[j].active || j == i) {
                    continue;
                }

                xmpp_client_ctx_t *target = find_client_by_jid(r->users[j].jid);

                if (!target) {
                    continue;
                }

                snprintf(response, sizeof(response),
                    "<presence type='unavailable' from='%s/%s' to='%s'>"
                      "<x xmlns='http://jabber.org/protocol/muc#user'>"
                        "<item affiliation='member' role='none'/>"
                      "</x>"
                    "</presence>",
                    bare_jid, nick, r->users[j].jid);

                send_raw(target, response);
            }
            
            snprintf(response, sizeof(response),
                "<presence type='unavailable' from='%s/%s' to='%s'>"
                  "<x xmlns='http://jabber.org/protocol/muc#user'>"
                    "<item affiliation='member' role='none'/>"
                    "<status code='110'/>"
                  "</x>"
                "</presence>",
                bare_jid, nick, ctx->full_jid);

            send_raw(ctx, response);

            memset(&r->users[i], 0, sizeof(participant_t));

            int occupied = 0;

            for (int j = 0; j < MAX_USERS_PER_ROOM; j++) {
                if (r->users[j].active) { 
                    occupied = 1;

                    break; 
                }
            }

            if (!occupied) {
                if (!r->persistent) {
                    r->active = 0;

                    memset(r->name, 0, sizeof(r->name));
                    memset(r->creator_jid, 0, sizeof(r->creator_jid));
                    
                    r->subject[0] = '\0';
                    r->banned_count = 0;
                    r->persistent = 0;
                    r->moderated = 0;
                    r->members_only = 0;
                }
                
                xmpp_persist_save_rooms();
            }

            return;
        }
        
        return;
    }
    
    {
        int occupant_idx = -1;
        char sender_bare_jid[64] = {0};

        strncpy(sender_bare_jid, ctx->full_jid, sizeof(sender_bare_jid) - 1);

        {
            char *_sl = strchr(sender_bare_jid, '/');
            
            if (_sl) {
                *_sl = '\0';
            }
        }

        for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
            if (r->users[i].active && strcmp(r->users[i].jid, sender_bare_jid) == 0) {
                occupant_idx = i;

                break;
            }
        }

        if (occupant_idx >= 0) {
            if (strcmp(r->users[occupant_idx].nick, nick) == 0) {
                char avail_resp[2400];

                for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
                    if (!r->users[i].active) {
                        continue;
                    }

                    xmpp_client_ctx_t *target = find_client_by_jid(r->users[i].jid);

                    if (!target) {
                        continue;
                    }

                    int is_self = (strcmp(r->users[i].jid, ctx->full_jid) == 0);

                    const char *aff = (strcmp(r->users[occupant_idx].jid, r->creator_jid) == 0) ? "owner" : "member";
                    const char *role = (strcmp(aff, "owner") == 0) ? "moderator" : "participant";

                    const char *inner = (stanza->payload[0] != '\0') ? stanza->payload : "";

                    if (is_self) {
                        snprintf(avail_resp, sizeof(avail_resp),
                            "<presence from='%s/%s' to='%s'>"
                              "%s"
                              "<x xmlns='http://jabber.org/protocol/muc#user'>"
                                "<item affiliation='%s' role='%s'/>"
                                "<status code='110'/>"
                              "</x>"
                            "</presence>",
                            bare_jid, nick, r->users[i].jid,
                            inner, aff, role);
                    }
                    else {
                        snprintf(avail_resp, sizeof(avail_resp),
                            "<presence from='%s/%s' to='%s'>"
                              "%s"
                              "<x xmlns='http://jabber.org/protocol/muc#user'>"
                                "<item affiliation='%s' role='%s'/>"
                              "</x>"
                            "</presence>",
                            bare_jid, nick, r->users[i].jid,
                            inner, aff, role);
                    }

                    send_raw(target, avail_resp);
                }

                return;
            }

            const char *old_nick = r->users[occupant_idx].nick;

            int nick_taken_by_other = 0;

            for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
                if (!r->users[i].active) {
                    continue;
                }

                if (i == occupant_idx) {
                    continue;
                }

                if (strcmp(r->users[i].nick, nick) == 0) {
                    nick_taken_by_other = 1;

                    break;
                }
            }

            if (nick_taken_by_other) {
                char conflict[512];
                
                snprintf(conflict, sizeof(conflict),
                    "<presence type='error' from='%s/%s' to='%s'>"
                      "<x xmlns='http://jabber.org/protocol/muc'/>"
                      "<error type='cancel'"
                        " by='%s'>"
                        "<conflict"
                          " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                      "</error>"
                    "</presence>",
                    bare_jid, nick, ctx->full_jid, bare_jid);

                send_raw(ctx, conflict);
                
                return;
            }
            
            char unav_resp[512];

            for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
                if (!r->users[i].active) {
                    continue;
                }

                xmpp_client_ctx_t *target = find_client_by_jid(r->users[i].jid);

                if (!target) {
                    continue;
                }

                int is_self = (strcmp(r->users[i].jid, ctx->full_jid) == 0);

                if (is_self) {
                    snprintf(unav_resp, sizeof(unav_resp),
                        "<presence type='unavailable' from='%s/%s' to='%s'>"
                          "<x xmlns='http://jabber.org/protocol/muc#user'>"
                            "<item affiliation='member' role='participant'"
                              " nick='%s'/>"
                            "<status code='303'/>"
                            "<status code='110'/>"
                          "</x>"
                        "</presence>",
                        bare_jid, old_nick, r->users[i].jid, nick);
                }
                else {
                    snprintf(unav_resp, sizeof(unav_resp),
                        "<presence type='unavailable' from='%s/%s' to='%s'>"
                          "<x xmlns='http://jabber.org/protocol/muc#user'>"
                            "<item affiliation='member' role='participant'"
                              " nick='%s'/>"
                            "<status code='303'/>"
                          "</x>"
                        "</presence>",
                        bare_jid, old_nick, r->users[i].jid, nick);
                }

                send_raw(target, unav_resp);
            }

            strncpy(r->users[occupant_idx].nick, nick, MAX_NICK_LEN - 1);

            r->users[occupant_idx].nick[MAX_NICK_LEN - 1] = '\0';

            char new_pres[512];

            for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
                if (!r->users[i].active) {
                    continue;
                }

                xmpp_client_ctx_t *target = find_client_by_jid(r->users[i].jid);

                if (!target) {
                    continue;
                }

                int is_self = (strcmp(r->users[i].jid, ctx->full_jid) == 0);

                if (is_self) {
                    snprintf(new_pres, sizeof(new_pres),
                        "<presence from='%s/%s' to='%s'>"
                          "<x xmlns='http://jabber.org/protocol/muc#user'>"
                            "<item affiliation='member' role='participant'/>"
                            "<status code='110'/>"
                          "</x>"
                        "</presence>",
                        bare_jid, nick, r->users[i].jid);
                }
                else {
                    snprintf(new_pres, sizeof(new_pres),
                        "<presence from='%s/%s' to='%s'>"
                          "<x xmlns='http://jabber.org/protocol/muc#user'>"
                            "<item affiliation='member' role='participant'/>"
                          "</x>"
                        "</presence>",
                        bare_jid, nick, r->users[i].jid);
                }

                send_raw(target, new_pres);
            }

            return;
        }
    }

    {
        char joiner_bare_ban[64] = {0};

        strncpy(joiner_bare_ban, ctx->full_jid, sizeof(joiner_bare_ban) - 1);

        char *jb_sl = strchr(joiner_bare_ban, '/');

        if (jb_sl) {
            *jb_sl = '\0';
        }

        for (int bi = 0; bi < r->banned_count; bi++) {
            if (strcmp(r->banned_jids[bi], joiner_bare_ban) == 0) {
                char ban_err[512];

                snprintf(ban_err, sizeof(ban_err),
                    "<presence type='error' from='%s/%s' to='%s'>"
                      "<error type='auth' code='403'>"
                        "<forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                      "</error>"
                    "</presence>",
                    bare_jid, nick, ctx->full_jid);

                send_raw(ctx, ban_err);
                
                return;
            }
        }
    }

    for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
        if (r->users[i].active && strcmp(r->users[i].nick, nick) == 0) {
            char conflict[512];

            snprintf(conflict, sizeof(conflict),
                "<presence type='error' from='%s/%s' to='%s'>"
                  "<error type='cancel' code='409'>"
                    "<conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                  "</error>"
                "</presence>",
                bare_jid, nick, ctx->full_jid);

            send_raw(ctx, conflict);

            return;
        }
    }

    for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
        if (!r->users[i].active) {
            r->users[i].active = 1;
            r->users[i].pcb = ctx->pcb;

            strncpy(r->users[i].nick, nick, MAX_NICK_LEN - 1);
            strncpy(r->users[i].jid, ctx->full_jid, 63);

            r->users[i].jid[63] = '\0';

            {
                char *jid_slash = strchr(r->users[i].jid, '/');

                if (jid_slash) {
                    *jid_slash = '\0';
                }
            }

            break;
        }
    }

    char response[1024];
    char bare_self[64] = {0};

    strncpy(bare_self, ctx->full_jid, sizeof(bare_self) - 1);

    {
        char *sl = strchr(bare_self, '/');

        if (sl) {
            *sl = '\0';
        }
    }

    int self_is_owner = (strcmp(bare_self, r->creator_jid) == 0);
    
    for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
        if (!r->users[i].active) {
            continue;
        }

        char ctx_bare[64] = {0};
        
        strncpy(ctx_bare, ctx->full_jid, sizeof(ctx_bare) - 1);

        char *ctx_sl = strchr(ctx_bare, '/');
        
        if (ctx_sl) {
            *ctx_sl = '\0';
        }

        if (strcmp(r->users[i].jid, ctx_bare) == 0) {
            continue;
        }

        int expose_jid = (!r->semi_anon || self_is_owner);

        if (expose_jid) {
            snprintf(response, sizeof(response),
                "<presence from='%s/%s' to='%s'>"
                  "<x xmlns='http://jabber.org/protocol/muc#user'>"
                    "<item affiliation='member' role='participant' jid='%s'/>"
                  "</x>"
                "</presence>",
                bare_jid, r->users[i].nick, ctx->full_jid, r->users[i].jid);
        }
        else {
            snprintf(response, sizeof(response),
                "<presence from='%s/%s' to='%s'>"
                  "<x xmlns='http://jabber.org/protocol/muc#user'>"
                    "<item affiliation='member' role='participant'/>"
                  "</x>"
                "</presence>",
                bare_jid, r->users[i].nick, ctx->full_jid);
        }

        send_raw(ctx, response);
    }
    
    for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
        if (!r->users[i].active) {
            continue;
        }

        char ctx_bare[64] = {0};

        strncpy(ctx_bare, ctx->full_jid, sizeof(ctx_bare) - 1);
        
        char *ctx_sl = strchr(ctx_bare, '/');
        
        if (ctx_sl) {
            *ctx_sl = '\0';
        }

        if (strcmp(r->users[i].jid, ctx_bare) == 0) {
            continue;
        }

        xmpp_client_ctx_t *target = find_client_by_jid(r->users[i].jid);

        if (!target) {
            continue;
        }
        
        int recipient_is_owner = (strcmp(r->users[i].jid, r->creator_jid) == 0);
        int expose_jid2 = (!r->semi_anon || recipient_is_owner);

        if (expose_jid2) {
            snprintf(response, sizeof(response),
                "<presence from='%s/%s' to='%s'>"
                  "<x xmlns='http://jabber.org/protocol/muc#user'>"
                    "<item affiliation='member' role='participant' jid='%s'/>"
                  "</x>"
                "</presence>",
                bare_jid, nick, r->users[i].jid, ctx->full_jid);
        }
        else {
            snprintf(response, sizeof(response),
                "<presence from='%s/%s' to='%s'>"
                  "<x xmlns='http://jabber.org/protocol/muc#user'>"
                    "<item affiliation='member' role='participant'/>"
                  "</x>"
                "</presence>",
                bare_jid, nick, r->users[i].jid);
        }

        send_raw(target, response);
    }

    if (is_new_room) {
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
    
    {
        const char *room_subject = (r->subject[0] != '\0') ? r->subject : "Welcome to the Unikernel Lobby";
        snprintf(response, sizeof(response),
            "<message from='%s' to='%s' type='groupchat'>"
              "<subject>%s</subject>"
            "</message>",
            bare_jid, ctx->full_jid, room_subject);
    }

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
        
        char *to_slash = NULL;
        {
            char *to_at = strchr(stanza->to, '@');

            if (to_at) {
                to_slash = strchr(to_at, '/');
            }
        }

        if (to_slash != NULL) {
            const char *target_nick = to_slash + 1;
            
            if (strstr(ctx->rx_buffer, "type='groupchat'") || strstr(ctx->rx_buffer, "type=\"groupchat\"")) {
                char bad_req[512];

                snprintf(bad_req, sizeof(bad_req),
                    "<message from='%s' to='%s' type='error' id='%s'>"
                      "<error type='modify' by='%s@conference.angelic.local'>"
                        "<bad-request"
                          " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                      "</error>"
                    "</message>",
                    stanza->to, ctx->full_jid, stanza->id, r->name);

                send_raw(ctx, bad_req);

                return;
            }

            char sender_nick[32] = "unknown";

            for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
                if (r->users[i].active && strcmp(r->users[i].jid, ctx->full_jid) == 0) {
                    strncpy(sender_nick, r->users[i].nick, 31);

                    break;
                }
            }

            xmpp_client_ctx_t *recipient = NULL;

            for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
                if (!r->users[i].active) {
                    continue;
                }

                if (strcmp(r->users[i].nick, target_nick) != 0) {
                    continue;
                }

                recipient = find_client_by_jid(r->users[i].jid);
                
                break;
            }

            if (!recipient) {
                char not_found[512];
                char bare_jid[64];
                int bare_len = (int)(to_slash - stanza->to);

                if (bare_len > 63) {
                    bare_len = 63;
                }

                strncpy(bare_jid, stanza->to, bare_len);
                
                bare_jid[bare_len] = '\0';

                snprintf(not_found, sizeof(not_found),
                    "<message from='%s' to='%s' type='error' id='%s'>"
                      "<error type='cancel'>"
                        "<item-not-found"
                          " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                      "</error>"
                    "</message>",
                    stanza->to, ctx->full_jid, stanza->id);

                send_raw(ctx, not_found);

                return;
            }

            char bare_room[64];
            int broom_len = (int)(to_slash - stanza->to);

            if (broom_len > 63) {
                broom_len = 63;
            }
            
            strncpy(bare_room, stanza->to, broom_len);
            
            bare_room[broom_len] = '\0';

            char pm_out[2400];
            int written;
            
            if (already_wrapped) {
                written = snprintf(pm_out, sizeof(pm_out),
                    "<message from='%s/%s' to='%s' type='chat' id='%s'>"
                      "<x xmlns='http://jabber.org/protocol/muc#user'/>"
                      "%s"
                    "</message>",
                    bare_room, sender_nick, recipient->full_jid,
                    stanza->id, stanza->payload);
            }
            else {
                written = snprintf(pm_out, sizeof(pm_out),
                    "<message from='%s/%s' to='%s' type='chat' id='%s'>"
                      "<x xmlns='http://jabber.org/protocol/muc#user'/>"
                      "<body>%s</body>"
                    "</message>",
                    bare_room, sender_nick, recipient->full_jid,
                    stanza->id, stanza->payload);
            }

            if (written > 0 && (size_t)written < sizeof(pm_out)) {
                send_raw(recipient, pm_out);
            }
            
            return;
        }
        
        {
            const char *subj_s = strstr(stanza->payload, "<subject>");

            if (subj_s) {
                subj_s += 9;
                const char *subj_e = strstr(subj_s, "</subject>");

                if (subj_e) {
                    int slen = (int)(subj_e - subj_s);
                    
                    if (slen >= (int)sizeof(r->subject)) {
                        slen = (int)sizeof(r->subject) - 1;
                    }
                    
                    strncpy(r->subject, subj_s, slen);
                    
                    r->subject[slen] = '\0';
                    
                    xmpp_persist_save_rooms();
                }
            }
        }

        char sender_nick[32] = "unknown";

        for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
            char ctx_bare[64] = {0};

            strncpy(ctx_bare, ctx->full_jid, sizeof(ctx_bare) - 1);
            
            char *ctx_sl = strchr(ctx_bare, '/');
            
            if (ctx_sl) {
                *ctx_sl = '\0';
            }

            if (r->users[i].active && strcmp(r->users[i].jid, ctx_bare) == 0) {
                strcpy(sender_nick, r->users[i].nick);

                break;
            }
        }
        
        for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
            if (!r->users[i].active) {
                continue;
            }

            xmpp_client_ctx_t *target = find_client_by_jid(r->users[i].jid);

            if (!target) {
                continue;
            }

            char gc_response[2400];
            int written;

            if (already_wrapped) {
                written = snprintf(gc_response, sizeof(gc_response),
                    "<message from='%s/%s' to='%s' type='groupchat' id='%s'>"
                      "%s"
                    "</message>",
                    stanza->to, sender_nick, r->users[i].jid,
                    stanza->id, stanza->payload);
            }
            else {
                written = snprintf(gc_response, sizeof(gc_response),
                    "<message from='%s/%s' to='%s' type='groupchat' id='%s'>"
                      "<body>%s</body>"
                    "</message>",
                    stanza->to, sender_nick, r->users[i].jid,
                    stanza->id, stanza->payload);
            }

            if (written < 0 || (size_t)written >= sizeof(gc_response)) {
                continue;
            }

            send_raw(target, gc_response);
        }
    }
    else {
        if (already_wrapped) {
            snprintf(response, sizeof(response),
                "<message from='%s' to='%s' type='chat'>%s</message>",
                ctx->full_jid, stanza->to, stanza->payload);
        }
        else {
            snprintf(response, sizeof(response),
                "<message from='%s' to='%s' type='chat'>"
                  "<body>%s</body>"
                "</message>",
                ctx->full_jid, stanza->to, stanza->payload);
        }

        char bare_target[64] = {0};

        strncpy(bare_target, stanza->to, sizeof(bare_target) - 1);

        char *target_slash = strchr(bare_target, '/');

        if (target_slash) {
            *target_slash = '\0';
        }

        int delivered = 0;

        for (int i = 0; i < MAX_USERS; i++) {
            if (client_registry[i].pcb == NULL) {
                continue;
            }

            if (client_registry[i].state < STATE_SESSION) {
                continue;
            }

            char bare_reg[64] = {0};

            strncpy(bare_reg, client_registry[i].full_jid, sizeof(bare_reg) - 1);

            char *reg_slash = strchr(bare_reg, '/');

            if (reg_slash) {
                *reg_slash = '\0';
            }

            if (strcmp(bare_target, bare_reg) == 0) {
                send_raw(&client_registry[i], response);

                delivered = 1;
            }
        }

        if (!delivered) {
            char to_user_check[32] = {0};
            const char *at_check = strchr(bare_target, '@');

            if (at_check) {
                int ulen = (int)(at_check - bare_target);

                if (ulen >= (int)sizeof(to_user_check)) {
                    ulen = (int)sizeof(to_user_check) - 1;
                }

                strncpy(to_user_check, bare_target, ulen);
            }
            else {
                strncpy(to_user_check, bare_target, sizeof(to_user_check) - 1);
            }

            if (offline_msg_is_full(to_user_check) || offline_msg_enqueue(bare_target, ctx->full_jid, stanza->id, stanza->payload) != 0) {
                char err[512];

                snprintf(err, sizeof(err),
                    "<message type='error' from='%s' to='%s'>"
                      "<error type='cancel' code='503'>"
                        "<service-unavailable"
                          " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                      "</error>"
                    "</message>",
                    stanza->to, ctx->full_jid);

                send_raw(ctx, err);
            }
        }
    }
}

static void subscription_update_roster(const char *owner_user, const char *contact_jid, const char *direction, const char *ptype) {
    roster_entry_t *slot = NULL;

    for (int i = 0; i < MAX_ROSTER_ENTRIES; i++) {
        if (!roster_store[i].active) {
            continue;
        }

        if (strncmp(roster_store[i].username, owner_user, 32) != 0) {
            continue;
        }

        if (strncmp(roster_store[i].jid, contact_jid, 64)  != 0) {
            continue;
        }

        slot = &roster_store[i];
        
        break;
    }
 
    const char *cur_sub = "none";

    if (slot) {
        if (strstr(slot->item_xml, "subscription='both'") || strstr(slot->item_xml, "subscription=\"both\"")) {
            cur_sub = "both";
        }
        else if (strstr(slot->item_xml, "subscription='to'") || strstr(slot->item_xml, "subscription=\"to\"")) {
            cur_sub = "to";
        }
        else if (strstr(slot->item_xml, "subscription='from'") || strstr(slot->item_xml, "subscription=\"from\"")) {
            cur_sub = "from";
        }
    }
 
    const char *new_sub = cur_sub;
 
    if (strcmp(ptype, "subscribed") == 0) {
        if (strcmp(direction, "inbound") == 0) {
            if (strcmp(cur_sub, "none") == 0) {
                new_sub = "to";
            }
            else if (strcmp(cur_sub, "from") == 0) {
                new_sub = "both";
            }
        } 
        else {
            if (strcmp(cur_sub, "none") == 0) {
                new_sub = "from";
            }
            else if (strcmp(cur_sub, "to") == 0) {
                new_sub = "both";
            }
        }
    }
    else if (strcmp(ptype, "unsubscribed") == 0) {
        if (strcmp(direction, "inbound") == 0) {
            if (strcmp(cur_sub, "both") == 0) {
                new_sub = "from";
            }
            else if (strcmp(cur_sub, "to") == 0) {
                new_sub = "none";
            }
        }
        else {
            if (strcmp(cur_sub, "both") == 0) {
                new_sub = "to";
            }
            else if (strcmp(cur_sub, "from") == 0) {
                new_sub = "none";
            }
        }
    }

    if (strcmp(new_sub, cur_sub) == 0 && slot != NULL) {
        return;
    }
    
    if (!slot) {
        if (strcmp(new_sub, "none") == 0) {
            return;
        }

        for (int i = 0; i < MAX_ROSTER_ENTRIES; i++) {
            if (!roster_store[i].active) {
                slot = &roster_store[i];

                break;
            }
        }
 
        if (!slot) {
            return;
        }

        strncpy(slot->username, owner_user, sizeof(slot->username) - 1);

        slot->username[sizeof(slot->username) - 1] = '\0';
        
        strncpy(slot->jid, contact_jid, sizeof(slot->jid) - 1);
        
        slot->jid[sizeof(slot->jid) - 1] = '\0';
        slot->item_xml[0] = '\0';
        slot->active = 1;
 
        cur_sub = "none";
    }

    char jid_val[64] = {0};
    const char *jp = strstr(slot->item_xml, "jid=");

    if (jp) {
        jp += 4;
        char qc = *jp++;
        const char *je = strchr(jp, qc);

        if (je) {
            int jlen = (int)(je - jp);

            if (jlen >= 64) {
                jlen = 63;
            }

            strncpy(jid_val, jp, jlen);
        }
    }

    if (jid_val[0] == '\0') {
        strncpy(jid_val, contact_jid, 63);
    }

    char name_attr[128] = {0};
    const char *np = strstr(slot->item_xml, "name=");

    if (np) {
        np += 5;
        char qc = *np++;
        const char *ne = strchr(np, qc);

        if (ne) {
            int nlen = (int)(ne - np);

            if (nlen >= 64) {
                nlen = 63;
            }

            char name_val[64] = {0};

            strncpy(name_val, np, nlen);
            snprintf(name_attr, sizeof(name_attr), " name='%s'", name_val);
        }
    }

    char new_xml[ROSTER_ITEM_MAX_LEN];

    snprintf(new_xml, sizeof(new_xml), "<item jid='%s'%s subscription='%s'/>", jid_val, name_attr, new_sub);
 
    strncpy(slot->item_xml, new_xml, ROSTER_ITEM_MAX_LEN - 1);

    slot->item_xml[ROSTER_ITEM_MAX_LEN - 1] = '\0';

    xmpp_persist_save_roster();

    for (int i = 0; i < MAX_USERS; i++) {
        if (client_registry[i].pcb == NULL) {
            continue;
        }

        if (client_registry[i].state < STATE_SESSION) {
            continue;
        }

        if (strcmp(client_registry[i].username, owner_user) != 0) {
            continue;
        }
 
        char push[512];

        snprintf(push, sizeof(push),
            "<iq type='set' to='%s'>"
              "<query xmlns='jabber:iq:roster'>"
                "%s"
              "</query>"
            "</iq>",
            client_registry[i].full_jid, new_xml);
        
        send_raw(&client_registry[i], push);
    }
}

void handle_broadcast_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza) {
    if (ctx->state >= STATE_SESSION && ctx->state < STATE_READY) {
        ctx->state = STATE_READY;
    }
    
    if (stanza->type == XMPP_PRESENCE_PROBE) {
        char bare_target[64] = {0};

        strncpy(bare_target, stanza->to, sizeof(bare_target) - 1);

        char *probe_slash = strchr(bare_target, '/');

        if (probe_slash) {
            *probe_slash = '\0';
        }

        for (int i = 0; i < MAX_USERS; i++) {
            if (client_registry[i].pcb == NULL) {
                continue;
            }

            if (client_registry[i].state < STATE_SESSION) {
                continue;
            }

            char bare_reg[64] = {0};

            strncpy(bare_reg, client_registry[i].full_jid, sizeof(bare_reg) - 1);

            char *rsl = strchr(bare_reg, '/');

            if (rsl) {
                *rsl = '\0';
            }

            if (strcmp(bare_target, bare_reg) == 0) {
                char probe_resp[512];
                
                if (client_registry[i].presence_payload[0] != '\0') {
                    snprintf(probe_resp, sizeof(probe_resp),
                        "<presence from='%s' to='%s'>%s</presence>",
                        client_registry[i].full_jid, ctx->full_jid,
                        client_registry[i].presence_payload);
                }
                else {
                    snprintf(probe_resp, sizeof(probe_resp),
                        "<presence from='%s' to='%s'/>",
                        client_registry[i].full_jid, ctx->full_jid);
                }

                send_raw(ctx, probe_resp);
            }
        }

        return;
    }

    if (stanza->type == XMPP_PRESENCE_SUBSCRIBE || stanza->type == XMPP_PRESENCE_SUBSCRIBED || stanza->type == XMPP_PRESENCE_UNSUBSCRIBE || stanza->type == XMPP_PRESENCE_UNSUBSCRIBED) {
        const char *ptype = (stanza->type == XMPP_PRESENCE_SUBSCRIBE) ? "subscribe" :
                            (stanza->type == XMPP_PRESENCE_SUBSCRIBED) ? "subscribed" :
                            (stanza->type == XMPP_PRESENCE_UNSUBSCRIBE) ? "unsubscribe" : "unsubscribed";
        char bare_from[64] = {0};

        strncpy(bare_from, ctx->full_jid, sizeof(bare_from) - 1);

        char *slash = strchr(bare_from, '/');

        if (slash) {
            *slash = '\0';
        }

        char bare_target[64] = {0};

        strncpy(bare_target, stanza->to, sizeof(bare_target) - 1);

        slash = strchr(bare_target, '/');

        if (slash) {
            *slash = '\0';
        }
        
        int delivered = 0;

        for (int i = 0; i < MAX_USERS; i++) {
            if (client_registry[i].pcb == NULL) {
                continue;
            }

            if (client_registry[i].state < STATE_SESSION) {
                continue;
            }

            char bare_reg[64] = {0};

            strncpy(bare_reg, client_registry[i].full_jid, sizeof(bare_reg) - 1);

            slash = strchr(bare_reg, '/');

            if (slash) {
                *slash = '\0';
            }

            if (strcmp(bare_target, bare_reg) == 0) {
                char msg[512];

                snprintf(msg, sizeof(msg), "<presence type='%s' from='%s' to='%s'/>", ptype, bare_from, client_registry[i].full_jid);

                send_raw(&client_registry[i], msg);

                delivered = 1;
            }
        }

        if (!delivered) {
            char to_user[32] = {0};
            const char *at = strchr(bare_target, '@');
            
            if (at) {
                int ulen = (int)(at - bare_target);
                
                if (ulen >= (int)sizeof(to_user)) {
                    ulen = (int)sizeof(to_user) - 1;
                }

                strncpy(to_user, bare_target, ulen);
            }
            else {
                strncpy(to_user, bare_target, sizeof(to_user) - 1);
            }

            pending_sub_enqueue(ptype, bare_from, to_user);
        }

        if (strcmp(ptype, "subscribed") == 0 || strcmp(ptype, "unsubscribed") == 0) {
            char sender_user[32] = {0};
            const char *fat = strchr(bare_from, '@');

            if (fat) {
                int ul = (int)(fat - bare_from);

                if (ul >= 32) {
                    ul = 31;
                }

                strncpy(sender_user, bare_from, ul);
            }
            else {
                strncpy(sender_user, bare_from, 31);
            }

            char recip_user[32] = {0};
            const char *rat = strchr(bare_target, '@');

            if (rat) {
                int ul = (int)(rat - bare_target);

                if (ul >= 32) {
                    ul = 31;
                }

                strncpy(recip_user, bare_target, ul);
            }
            else {
                strncpy(recip_user, bare_target, 31);
            }

            subscription_update_roster(sender_user, bare_target, "outbound", ptype);

            subscription_update_roster(recip_user, bare_from, "inbound", ptype);
        }

        return;
    }

    char response[1024];
    int is_unavailable = (stanza->type == XMPP_PRESENCE_UNAVAILABLE);
    
    if (!is_unavailable && stanza->to[0] != '\0' && !strstr(stanza->to, "conference.angelic.local")) {
        char bare_dp[64] = {0};

        strncpy(bare_dp, stanza->to, sizeof(bare_dp) - 1);
        
        char *dp_sl = strchr(bare_dp, '/');
        
        if (dp_sl) {
            *dp_sl = '\0';
        }

        for (int i = 0; i < MAX_USERS; i++) {
            if (client_registry[i].pcb == NULL) {
                continue;
            }

            if (client_registry[i].state < STATE_SESSION) {
                continue;
            }

            char bare_reg_dp[64] = {0};

            strncpy(bare_reg_dp, client_registry[i].full_jid, sizeof(bare_reg_dp) - 1);

            char *rsl_dp = strchr(bare_reg_dp, '/');
            
            if (rsl_dp) {
                *rsl_dp = '\0';
            }

            if (strcmp(bare_dp, bare_reg_dp) != 0) {
                continue;
            }

            char dp_resp[512];

            if (ctx->presence_payload[0] != '\0') {
                snprintf(dp_resp, sizeof(dp_resp),
                    "<presence from='%s' to='%s'>%s</presence>",
                    ctx->full_jid, client_registry[i].full_jid,
                    ctx->presence_payload);
            }
            else {
                snprintf(dp_resp, sizeof(dp_resp),
                    "<presence from='%s' to='%s'/>",
                    ctx->full_jid, client_registry[i].full_jid);
            }

            send_raw(&client_registry[i], dp_resp);
        }

        return;
    }

    for (int i = 0; i < MAX_USERS; i++) {
        if (client_registry[i].pcb == NULL) {
            continue;
        }

        if (client_registry[i].state < STATE_SESSION) {
            continue;
        }

        if (is_unavailable) {
            snprintf(response, sizeof(response),
                "<presence from='%s' to='%s' type='unavailable'>"
                  "<status>Offline</status>"
                "</presence>",
                ctx->full_jid, client_registry[i].full_jid);
        }
        else {
            if (stanza->payload[0] != '\0') {
                strncpy(ctx->presence_payload, stanza->payload, sizeof(ctx->presence_payload) - 1);

                ctx->presence_payload[sizeof(ctx->presence_payload) - 1] = '\0';
            }

            if (ctx->presence_payload[0] != '\0') {
                snprintf(response, sizeof(response),
                    "<presence from='%s' to='%s' id='%s'>%s</presence>",
                    ctx->full_jid, client_registry[i].full_jid,
                    stanza->id, ctx->presence_payload);
            }
            else {
                snprintf(response, sizeof(response),
                    "<presence from='%s' to='%s' id='%s'/>",
                    ctx->full_jid, client_registry[i].full_jid,
                    stanza->id);
            }
        }

        send_raw(&client_registry[i], response);
    }
}