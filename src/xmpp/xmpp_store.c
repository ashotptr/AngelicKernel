#include "xmpp_core.h"
#include <stdio.h>
#include <string.h>

offline_msg_t offline_store[MAX_OFFLINE_MSGS];

int offline_msg_enqueue(const char *to_bare, const char *from_jid, const char *msg_id, const char *payload) {
    char to_user[32] = {0};
    const char *at = strchr(to_bare, '@');

    if (at) {
        int ulen = (int)(at - to_bare);
        
        if (ulen >= (int)sizeof(to_user)) {
            ulen = (int)sizeof(to_user) - 1;
        }

        strncpy(to_user, to_bare, ulen);
    }
    else {
        strncpy(to_user, to_bare, sizeof(to_user) - 1);
    }

    for (int i = 0; i < MAX_OFFLINE_MSGS; i++) {
        if (offline_store[i].active){
            continue;
        }

        strncpy(offline_store[i].from, from_jid, sizeof(offline_store[i].from) - 1);
        strncpy(offline_store[i].to_bare, to_bare, sizeof(offline_store[i].to_bare) - 1);
        strncpy(offline_store[i].to_user, to_user, sizeof(offline_store[i].to_user) - 1);
        strncpy(offline_store[i].id, msg_id, sizeof(offline_store[i].id) - 1);
        strncpy(offline_store[i].payload, payload, sizeof(offline_store[i].payload) - 1);

        offline_store[i].from[sizeof(offline_store[i].from) - 1] = '\0';
        offline_store[i].to_bare[sizeof(offline_store[i].to_bare) - 1] = '\0';
        offline_store[i].to_user[sizeof(offline_store[i].to_user) - 1] = '\0';
        offline_store[i].id[sizeof(offline_store[i].id) - 1] = '\0';
        offline_store[i].payload[sizeof(offline_store[i].payload) - 1] = '\0';
        offline_store[i].active = 1;

        xmpp_persist_save_offline();

        return 0;
    }

    return -1;
}

void offline_msg_drain(xmpp_client_ctx_t *ctx) {
    char out[1400];

    for (int i = 0; i < MAX_OFFLINE_MSGS; i++) {
        if (!offline_store[i].active) {
            continue;
        }

        if (strcmp(offline_store[i].to_user, ctx->username) != 0) {
            continue;
        }

        int written;

        if (offline_store[i].id[0] != '\0') {
            written = snprintf(out, sizeof(out),
                "<message from='%s' to='%s' type='chat' id='%s'>"
                  "%s"
                  "<delay xmlns='urn:xmpp:delay'"
                         " from='" XMPP_DOMAIN "'"
                         " stamp='2024-01-01T00:00:00Z'>"
                    "Offline Storage"
                  "</delay>"
                "</message>",
                offline_store[i].from,
                ctx->full_jid,
                offline_store[i].id,
                offline_store[i].payload);
        }
        else {
            written = snprintf(out, sizeof(out),
                "<message from='%s' to='%s' type='chat'>"
                  "%s"
                  "<delay xmlns='urn:xmpp:delay'"
                         " from='" XMPP_DOMAIN "'"
                         " stamp='2024-01-01T00:00:00Z'>"
                    "Offline Storage"
                  "</delay>"
                "</message>",
                offline_store[i].from,
                ctx->full_jid,
                offline_store[i].payload);
        }

        if (written > 0 && (size_t)written < sizeof(out)) {
            send_raw(ctx, out);
        }

        offline_store[i].active = 0;
    }

    xmpp_persist_save_offline();
}

int offline_msg_is_full(const char *to_user) {
    int count = 0;
    
    for (int i = 0; i < MAX_OFFLINE_MSGS; i++) {
        if (offline_store[i].active && strcmp(offline_store[i].to_user, to_user) == 0) {
            count++;
        }
    }

    return (count >= MAX_OFFLINE_MSGS / 2);
}

int roster_version = 0;
roster_entry_t roster_store[MAX_ROSTER_ENTRIES];

static int roster_extract_jid(const char *item_xml, char *jid_out, int jid_max) {
    const char *p = strstr(item_xml, "jid=");

    if (!p) {
        return 0;
    }

    p += 4;
    char q = *p;
    
    if (q != '\'' && q != '"') {
        return 0;
    }

    p++;

    const char *end = strchr(p, q);

    if (!end) {
        return 0;
    }

    int len = (int)(end - p);

    if (len >= jid_max) {
        len = jid_max - 1;
    }

    strncpy(jid_out, p, len);

    jid_out[len] = '\0';

    return 1;
}

int roster_store_upsert_item(const char *username, const char *item_xml) {
    char contact_jid[64] = {0};

    if (!roster_extract_jid(item_xml, contact_jid, sizeof(contact_jid))) {
        return -1;
    }

    int is_remove = (strstr(item_xml, "subscription='remove'") != NULL || strstr(item_xml, "subscription=\"remove\"") != NULL);
    roster_entry_t *slot = NULL;

    for (int i = 0; i < MAX_ROSTER_ENTRIES; i++) {
        if (!roster_store[i].active) {
            continue;
        }

        if (strncmp(roster_store[i].username, username, 32) != 0) {
            continue;
        }

        if (strncmp(roster_store[i].jid, contact_jid, 64) != 0) {
            continue;
        }

        slot = &roster_store[i];
        
        break;
    }

    if (is_remove) {
        if (slot) {
            slot->active = 0;
        }

        return 0;
    }

    if (!slot) {
        for (int i = 0; i < MAX_ROSTER_ENTRIES; i++) {
            if (!roster_store[i].active) {
                slot = &roster_store[i];

                break;
            }
        }
    }

    if (!slot) {
        return -1;
    }

    strncpy(slot->username, username, sizeof(slot->username) - 1);
    strncpy(slot->jid, contact_jid, sizeof(slot->jid) - 1);

    int xml_len = (int)strlen(item_xml);
    
    if (xml_len >= ROSTER_ITEM_MAX_LEN) {
        xml_len = ROSTER_ITEM_MAX_LEN - 1;
    }

    strncpy(slot->item_xml, item_xml, xml_len);

    slot->username[sizeof(slot->username) - 1] = '\0';
    slot->jid[sizeof(slot->jid) - 1] = '\0';
    slot->item_xml[xml_len] = '\0';
    slot->active = 1;

    return 0;
}

void roster_store_set_from_payload(const char *username, const char *payload) {
    const char *p = payload;
    char item_buf[ROSTER_ITEM_MAX_LEN];

    while ((p = strstr(p, "<item ")) != NULL) {
        const char *end = strchr(p, '>');
        
        if (!end) {
            break;
        }

        int len = (int)(end - p) + 1;

        if (len >= ROSTER_ITEM_MAX_LEN) {
            len = ROSTER_ITEM_MAX_LEN - 1;
        }

        strncpy(item_buf, p, len);
        item_buf[len] = '\0';

        if (len >= 2 && item_buf[len - 2] != '/') {
            if (len < ROSTER_ITEM_MAX_LEN - 1) {
                item_buf[len - 1] = '/';
                item_buf[len] = '>';
                item_buf[len + 1] = '\0';
            }
        }

        roster_store_upsert_item(username, item_buf);

        p = end + 1;
    }
}

int roster_store_get_items(const char *username, char *buf, int buf_len) {
    int count = 0;
    int pos = 0;

    buf[0] = '\0';

    for (int i = 0; i < MAX_ROSTER_ENTRIES; i++) {
        if (!roster_store[i].active) {
            continue;
        }

        if (strncmp(roster_store[i].username, username, 32) != 0) {
            continue;
        }

        int item_len = (int)strlen(roster_store[i].item_xml);

        if (pos + item_len >= buf_len - 1) {
            break;
        }

        memcpy(buf + pos, roster_store[i].item_xml, item_len);
        
        pos += item_len;
        buf[pos] = '\0';
        count++;
    }

    return count;
}