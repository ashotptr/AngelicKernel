#include "xmpp_core.h"
#include <string.h>
#include <stdio.h>

// Helper to extract attributes safely
static void extract_attribute(const char *tag, const char *key, char *dest, int max_len) {
    const char *p = tag;
    int key_len = strlen(key);

    while (*p) {
        // 1. Find the key (e.g., "to")
        if (strncmp(p, key, key_len) == 0) {
            // Ensure it's the whole word (not "topic" matching "to")
            char after = p[key_len];
            if (after == '=' || after == ' ' || after == '\t') {
                // 2. Skip garbage until '='
                p += key_len;
                while (*p == ' ' || *p == '\t' || *p == '=') p++;

                // 3. Detect Quote Type (' or ")
                char quote = *p;
                if (quote == '"' || quote == '\'') {
                    p++; // Skip opening quote
                    // 4. Copy Value until closing quote
                    int i = 0;
                    while (*p && *p != quote && i < max_len - 1) {
                        dest[i++] = *p++;
                    }
                    dest[i] = '\0';
                    return;
                }
            }
        }
        p++;
    }
}

xmpp_stanza_t* parse_xml_stream(char *payload, int len, int *bytes_consumed) {
    *bytes_consumed = 0;
    
    int offset = 0;
    
    while (offset < len && (payload[offset] == ' ' || payload[offset] == '\r' || payload[offset] == '\n' || payload[offset] == '\t')) {
        offset++;
    }

    if (offset >= len) {
        *bytes_consumed = offset;

        return NULL;
    }

    char *xml_start = payload + offset;
    int remaining_len = len - offset;

    if (remaining_len < 4) {
        *bytes_consumed = offset;

        return NULL;
    }

    char *end_tag = NULL;

    char *self_close = strstr(xml_start, "/>");
    char *close_tag_ptr = strstr(xml_start, "</"); // e.g. </message>

    // Prioritize whichever comes first
    if (self_close && (!close_tag_ptr || self_close < close_tag_ptr)) {
        end_tag = self_close + 2;
    } else if (close_tag_ptr) {
        end_tag = strchr(close_tag_ptr, '>');
        if (end_tag) end_tag += 1;
    }

    if (!end_tag) {
        // Incomplete stanza, but we might have consumed whitespace
        *bytes_consumed = offset;
        return NULL;
    }

    // Calculate total stanza length (whitespace + xml)
    int stanza_len = (end_tag - xml_start);
    
    // Safety: ensure we didn't go out of bounds (shouldn't happen with strstr/strchr on null-term buffer, 
    // but useful if buffer isn't null-term)
    if (stanza_len > remaining_len) return NULL;

    // IMPORTANT: Consume the whitespace + the stanza
    *bytes_consumed = offset + stanza_len;

    // 3. Alloc and Parse
    xmpp_stanza_t *s = xmpp_alloc_stanza();
    if (!s) return NULL;

    // Copy only this stanza to a temp buffer for string manipulation safely
    char temp_buf[1024];
    int copy_len = (stanza_len < 1023) ? stanza_len : 1023;
    memcpy(temp_buf, xml_start, copy_len);
    temp_buf[copy_len] = '\0';

    // --- LOGIC FROM YOUR ORIGINAL PARSER ---
    if (strncmp(temp_buf, "<message", 8) == 0) {
        s->type = XMPP_MESSAGE;
        strcpy(s->xmlns, "jabber:client"); // Default for chat
    } 
    else if (strncmp(temp_buf, "<iq", 3) == 0) {
        if (strstr(temp_buf, "type='get'") || strstr(temp_buf, "type=\"get\"")) 
            s->type = XMPP_IQ_GET;
        else if (strstr(temp_buf, "type='set'") || strstr(temp_buf, "type=\"set\"")) 
            s->type = XMPP_IQ_SET;
        else 
            s->type = XMPP_IQ_RESULT;

        // Extract inner xmlns for router
        char *query = strstr(temp_buf, "<query");
        if (query) extract_attribute(query, "xmlns", s->xmlns, 128);
        else if (strstr(temp_buf, "jabber:iq:roster")) {
            strcpy(s->xmlns, "jabber:iq:roster");
        }
        else if (strstr(temp_buf, "<bind")) strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-bind");
        else if (strstr(temp_buf, "<session")) strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-session");
    }
    else if (strncmp(temp_buf, "<presence", 9) == 0) {
        s->type = XMPP_PRESENCE;
        if(strstr(temp_buf, "http://jabber.org/protocol/muc"))
            strcpy(s->xmlns, "http://jabber.org/protocol/muc");
        else
            strcpy(s->xmlns, "jabber:client");
    }
    else if (strncmp(temp_buf, "<auth", 5) == 0) {
        strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-sasl");
    }

    extract_attribute(temp_buf, "to", s->to, 64);
    extract_attribute(temp_buf, "from", s->from, 64);
    extract_attribute(temp_buf, "id", s->id, 64);

    // Extract Payload (Body/Inner XML)
    // Simple heuristic: content between first '>' and last '<'
    char *inner_start = strchr(temp_buf, '>');
    if (inner_start && inner_start < (temp_buf + copy_len)) {
        // Copy everything after the first >
        strncpy(s->payload, inner_start + 1, sizeof(s->payload) - 1);
        s->payload[sizeof(s->payload) - 1] = '\0'; // Ensure null termination
        
        // Find the LAST < to strip the closing tag
        char *last_close = strrchr(s->payload, '<');
        if(last_close) *last_close = '\0';
    }

    return s;
}