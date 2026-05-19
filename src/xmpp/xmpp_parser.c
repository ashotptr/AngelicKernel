#include "xmpp_core.h"
#include "yxml.h"
#include <string.h>
#include <stdio.h>


extern int find_stanza_end_dispatch(const char *xml, int len);

#define find_stanza_end(xml, len) find_stanza_end_dispatch(xml, len)

xmpp_stanza_t* parse_xml_stream(char *payload, int len, int *bytes_consumed, parse_null_reason_t *reason) {
    *bytes_consumed = 0;
    int offset = 0;

    while (offset < len && (payload[offset] == ' ' || payload[offset] == '\r' || payload[offset] == '\n' || payload[offset] == '\t')) {
        offset++;
    }

    if (offset >= len) {
        *bytes_consumed = offset;
        *reason = PARSE_INCOMPLETE;

        return NULL;
    }

    char *xml_start = payload + offset;
    int remaining_len = len - offset;

    if (remaining_len < 4) {
        *bytes_consumed = offset;
        *reason = PARSE_INCOMPLETE;

        return NULL;
    }

    int stanza_len = find_stanza_end(xml_start, remaining_len);

    if (stanza_len < 0) {
        *bytes_consumed = offset;
        *reason = PARSE_INCOMPLETE;

        return NULL;
    }

    *bytes_consumed = offset + stanza_len;

    xmpp_stanza_t *s = xmpp_alloc_stanza();

    if (!s) {
        *reason = PARSE_NO_MEMORY;
        
        return NULL;
    }

    yxml_t x;
    char stack[1024];

    yxml_init(&x, stack, sizeof(stack));

    int depth = 0;
    char current_attr[64] = {0};
    char iq_type_buf[16] = {0};
    char pres_type_buf[16] = {0};
    int is_iq = 0;
    int is_pres = 0;
    int xmlns_locked = 0;

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
                    s->type = XMPP_UNKNOWN;
                    
                    is_iq = 1;
                }
                else if (strcmp(x.elem, "presence") == 0) {
                    s->type = XMPP_PRESENCE;
                    
                    is_pres = 1;

                    strcpy(s->xmlns, "jabber:client");
                }
                else if (strcmp(x.elem, "auth") == 0) {
                    strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-sasl");
                }
            }
            else if (depth == 2) {
                if (strcmp(x.elem, "bind") == 0) {
                    strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-bind");
                    
                    xmlns_locked = 1;
                }
                else if (strcmp(x.elem, "session") == 0) {
                    strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-session");
                    
                    xmlns_locked = 1;
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
                else if (strcmp(current_attr, "type") == 0 && is_iq) {
                    strncat(iq_type_buf, x.data, sizeof(iq_type_buf) - strlen(iq_type_buf) - 1);
                }
                else if (strcmp(current_attr, "type") == 0 && is_pres) {
                    strncat(pres_type_buf, x.data, sizeof(pres_type_buf) - strlen(pres_type_buf) - 1);
                }
                else if (strcmp(current_attr, "mechanism") == 0 && strcmp(x.elem, "auth") == 0) {
                    strncat(s->mechanism, x.data, sizeof(s->mechanism) - strlen(s->mechanism) - 1);
                }
            }
            else if (depth == 2) {
                if (strcmp(current_attr, "xmlns") == 0 && !xmlns_locked) {
                    strncat(s->xmlns, x.data, sizeof(s->xmlns) - strlen(s->xmlns) - 1);
                }
            }
        }
    }

    if (is_iq) {
        if (strcmp(iq_type_buf, "get") == 0) {
            s->type = XMPP_IQ_GET;
        }
        else if (strcmp(iq_type_buf, "set") == 0) {
            s->type = XMPP_IQ_SET;
        }
        else if (strcmp(iq_type_buf, "result") == 0) {
            s->type = XMPP_IQ_RESULT;
        }
        else if (strcmp(iq_type_buf, "error") == 0) {
            s->type = XMPP_IQ_ERROR;
        }
    }

    if (is_pres && pres_type_buf[0] != '\0') {
        if (strcmp(pres_type_buf, "unavailable") == 0) {
            s->type = XMPP_PRESENCE_UNAVAILABLE;
        }
        else if (strcmp(pres_type_buf, "subscribe") == 0) {
            s->type = XMPP_PRESENCE_SUBSCRIBE;
        }
        else if (strcmp(pres_type_buf, "subscribed") == 0) {
            s->type = XMPP_PRESENCE_SUBSCRIBED;
        }
        else if (strcmp(pres_type_buf, "unsubscribe") == 0) {
            s->type = XMPP_PRESENCE_UNSUBSCRIBE;
        }
        else if (strcmp(pres_type_buf, "unsubscribed") == 0) {
            s->type = XMPP_PRESENCE_UNSUBSCRIBED;
        }
        else if (strcmp(pres_type_buf, "probe") == 0) {
            s->type = XMPP_PRESENCE_PROBE;
        }
    }

    char temp_buf[1024];
    int copy_len = (stanza_len < 1023) ? stanza_len : 1023;

    memcpy(temp_buf, xml_start, copy_len);

    temp_buf[copy_len] = '\0';

    if (s->xmlns[0] == '\0') {
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
        else if (strstr(temp_buf, "urn:xmpp:blocking")) {
            strcpy(s->xmlns, "urn:xmpp:blocking");
        }
        else if (strstr(temp_buf, "http://jabber.org/protocol/pubsub")) {
            strcpy(s->xmlns, "http://jabber.org/protocol/pubsub");
        }
        else if (strstr(temp_buf, "http://jabber.org/protocol/muc")) {
            strcpy(s->xmlns, "http://jabber.org/protocol/muc");
        }
    }
    else if (s->type == XMPP_PRESENCE || s->type == XMPP_PRESENCE_UNAVAILABLE) {
        if (strstr(temp_buf, "muc#owner")) {
            strcpy(s->xmlns, "http://jabber.org/protocol/muc#owner");
        }
        else if (strstr(temp_buf, "muc#admin")) {
            strcpy(s->xmlns, "http://jabber.org/protocol/muc#admin");
        }
        else if (strstr(temp_buf, "http://jabber.org/protocol/muc")) {
            strcpy(s->xmlns, "http://jabber.org/protocol/muc");
        }
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