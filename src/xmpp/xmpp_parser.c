#include "xmpp_core.h"
#include <string.h>
#include <stdio.h>

// Helper to extract attributes safely
// REPLACE your old extract_attribute with this Lexer-based function
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

//Replace your parse_xml_stream function with this:
xmpp_stanza_t* parse_xml_stream(char *payload, int len, int *bytes_consumed) {
    *bytes_consumed = 0;
    
    // 1. Safety check
    if (len < 4) return NULL; 

    // 2. Determine end of stanza
    // This is a simplified check. In production, count depth of < > tags.
    char *end_tag = NULL;
    
    // Check for self-closing tags first (e.g. <auth .../>)
    char *self_close = strstr(payload, "/>");
    char *close_tag = strstr(payload, "</"); // e.g. </message>

    if (self_close && (!close_tag || self_close < close_tag)) {
        end_tag = self_close + 2;
    } else if (close_tag) {
        end_tag = strchr(close_tag, '>');
        if (end_tag) end_tag += 1;
    }

    if (!end_tag) return NULL; // Stanza is incomplete, wait for more TCP data

    // Calculate total stanza length
    int stanza_len = end_tag - payload;
    if (stanza_len > len) return NULL; // Should not happen but safety first

    *bytes_consumed = stanza_len;

    // 3. Alloc and Parse
    xmpp_stanza_t *s = xmpp_alloc_stanza();
    if (!s) return NULL;

    // Copy only this stanza to a temp buffer for string manipulation safely
    char temp_buf[1024];
    int copy_len = (stanza_len < 1023) ? stanza_len : 1023;
    memcpy(temp_buf, payload, copy_len);
    temp_buf[copy_len] = '\0';

    // --- LOGIC FROM YOUR ORIGINAL PARSER ---
    if (strncmp(temp_buf, "<message", 8) == 0) {
        s->type = XMPP_MESSAGE;
        strcpy(s->xmlns, "jabber:client"); // Default for chat
    } 
    else if (strncmp(temp_buf, "<iq", 3) == 0) {
        if (strstr(temp_buf, "type='get'")) s->type = XMPP_IQ_GET;
        else if (strstr(temp_buf, "type='set'")) s->type = XMPP_IQ_SET;
        else s->type = XMPP_IQ_RESULT;
        
        char *query = strstr(temp_buf, "<query");
        if (query) extract_attribute(query, "xmlns", s->xmlns, 128);
        else if (strstr(temp_buf, "<bind")) strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-bind");
        else if (strstr(temp_buf, "<session")) strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-session");
    }
    else if (strncmp(temp_buf, "<presence", 9) == 0) {
        s->type = XMPP_PRESENCE;
        // Don't force MUC namespace here, let it be generic if needed
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
    char *inner_start = strchr(temp_buf, '>');
    if (inner_start && inner_start < (temp_buf + copy_len)) {
        // Calculate inner content length excluding outer tags if desirable
        // For simplicity, we just copy everything after the first >
        strcpy(s->payload, inner_start + 1); 
        // Remove closing tag from payload for cleaner processing
        char *last_close = strrchr(s->payload, '<');
        if(last_close) *last_close = '\0';
    }

    return s;
}