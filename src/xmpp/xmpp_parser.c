#include "xmpp_core.h"
#include "yxml.h"
#include <string.h>
#include <stdio.h>

static void extract_attribute(const char *tag, const char *key, char *dest, int max_len) {
    const char *p = tag;
    int key_len = strlen(key);

    while (*p) {
        if (strncmp(p, key, key_len) == 0) {
            char after = p[key_len];
            if (after == '=' || after == ' ' || after == '\t') {
                p += key_len;
                while (*p == ' ' || *p == '\t' || *p == '=') p++;

                char quote = *p;
                if (quote == '"' || quote == '\'') {
                    p++;
                    
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

static int find_stanza_end(const char *xml, int len) {
    const char *p   = xml;
    const char *end = xml + len;
    int depth = 0;

    while (p < end) {
        if (*p != '<') { 
            p++;
        
            continue;
        }

        if (p + 1 < end && (*(p + 1) == '?' || *(p + 1) == '!')) {
            const char *gt = memchr(p, '>', end - p);

            if (!gt) {
                return -1;
            }

            p = gt + 1;

            continue;
        }

        if (p + 1 < end && *(p + 1) == '/') {
            const char *gt = memchr(p, '>', end - p);
            
            if (!gt) {
                return -1;
            }
            
            depth--;
            
            if (depth == 0) {
                return (int)((gt + 1) - xml);
            }
            
            p = gt + 1;
            
            continue;
        }

        const char *gt = memchr(p, '>', end - p);

        if (!gt) {
            return -1;
        }

        if (*(gt - 1) == '/') {
            if (depth == 0) {
                return (int)((gt + 1) - xml);
            }
        }
        else {
            depth++;
        }
        
        p = gt + 1;
    }

    return -1;
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

    int stanza_len = find_stanza_end(xml_start, remaining_len);

    if (stanza_len < 0) {
        *bytes_consumed = offset;

        return NULL;
    }

    *bytes_consumed = offset + stanza_len;

    xmpp_stanza_t *s = xmpp_alloc_stanza();

    if (!s) {
        return NULL;
    }

    yxml_t x;
    char stack[1024]; 

    yxml_init(&x, stack, sizeof(stack));

    int depth = 0;
    char current_attr[64] = {0};

    for (int i = 0; i < stanza_len; i++) {
        yxml_ret_t r = yxml_parse(&x, xml_start[i]);

        if (r == YXML_ELEMSTART) {
            depth++;

            if (depth == 1) {
                if (strcmp(x.elem, "message") == 0) {
                    s->type = XMPP_MESSAGE;

                    strcpy(s->xmlns, "jabber:client");
                } 
                else if (strcmp(x.elem, "iq") == 0) {
                    s->type = XMPP_IQ_RESULT; 
                } 
                else if (strcmp(x.elem, "presence") == 0) {
                    s->type = XMPP_PRESENCE;

                    strcpy(s->xmlns, "jabber:client");
                } 
                else if (strcmp(x.elem, "auth") == 0) {
                    strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-sasl");
                }
            }
            else if (depth == 2) {
                if (strcmp(x.elem, "bind") == 0) {
                    strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-bind");
                }
                else if (strcmp(x.elem, "session") == 0) {
                    strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-session");
                }
            }
        }
        else if (r == YXML_ATTRSTART) {
            strncpy(current_attr, x.attr, sizeof(current_attr) - 1);

            current_attr[sizeof(current_attr) - 1] = '\0';
        }
        else if (r == YXML_ATTRVAL) {
            if (depth == 1) {
                if (strcmp(current_attr, "to") == 0) {
                    strncat(s->to, x.data, sizeof(s->to) - strlen(s->to) - 1);
                }
                else if (strcmp(current_attr, "from") == 0) {
                    strncat(s->from, x.data, sizeof(s->from) - strlen(s->from) - 1);
                }
                else if (strcmp(current_attr, "id") == 0) {
                    strncat(s->id, x.data, sizeof(s->id) - strlen(s->id) - 1);
                }
                else if (strcmp(current_attr, "type") == 0 && strcmp(x.elem, "iq") == 0) {
                    if (strcmp(x.data, "get") == 0) {
                        s->type = XMPP_IQ_GET;
                    }
                    else if (strcmp(x.data, "set") == 0) {
                        s->type = XMPP_IQ_SET;
                    }
                }
            }
            else if (depth == 2) {
                if (strcmp(x.elem, "query") == 0 && strcmp(current_attr, "xmlns") == 0) {
                    strncat(s->xmlns, x.data, sizeof(s->xmlns) - strlen(s->xmlns) - 1);
                }
            }
        }
    }

    char temp_buf[1024];
    int copy_len = (stanza_len < 1023) ? stanza_len : 1023;

    memcpy(temp_buf, xml_start, copy_len);
    
    temp_buf[copy_len] = '\0';

    if (strstr(temp_buf, "jabber:iq:roster")) {
        strcpy(s->xmlns, "jabber:iq:roster");
    }
    else if (strstr(temp_buf, "muc#owner")) {
        strcpy(s->xmlns, "http://jabber.org/protocol/muc#owner");
    }
    else if (strstr(temp_buf, "muc#admin")) {
        strcpy(s->xmlns, "http://jabber.org/protocol/muc#admin");
    }
    else if (strstr(temp_buf, "disco#info")) {
        strcpy(s->xmlns, "http://jabber.org/protocol/disco#info");
    }
    else if (strstr(temp_buf, "disco#items")) {
        strcpy(s->xmlns, "http://jabber.org/protocol/disco#items");
    }
    else if (strstr(temp_buf, "http://jabber.org/protocol/muc")) {
        strcpy(s->xmlns, "http://jabber.org/protocol/muc");
    }
    
    char *header_end = strchr(temp_buf, '>');
    int is_self_closing = (header_end && header_end > temp_buf && *(header_end - 1) == '/');

    if (is_self_closing) {
        s->payload[0] = '\0';
    }
    else {
        char *inner_start = header_end;

        if (inner_start && inner_start < (temp_buf + copy_len)) {
            inner_start++;
            
            char closer[64];

            snprintf(closer, sizeof(closer), "</%s>", s->type == XMPP_MESSAGE ? "message" : 
                                                      s->type == XMPP_IQ_GET ? "iq" :
                                                      s->type == XMPP_IQ_SET ? "iq" :
                                                      s->type == XMPP_IQ_RESULT ? "iq" :
                                                      s->type == XMPP_PRESENCE ? "presence" : "unknown");

            char tag_name[32] = {0};
            int t = 0;
            const char *p_tag = temp_buf + 1;

            while (*p_tag && *p_tag != ' ' && *p_tag != '>' && t < 31) {
                tag_name[t++] = *p_tag++;
            }
            
            tag_name[t] = '\0';            
            char specific_closer[40];

            snprintf(specific_closer, sizeof(specific_closer), "</%s>", tag_name);

            char *inner_end = strstr(inner_start, specific_closer);
            
            if (inner_end) {
                int payload_len = inner_end - inner_start;

                if (payload_len >= (int)sizeof(s->payload)) {
                    payload_len = sizeof(s->payload) - 1;
                }

                strncpy(s->payload, inner_start, payload_len);
                
                s->payload[payload_len] = '\0';
            }
            else {
                s->payload[0] = '\0';
            }
        }
    }

    return s;
}