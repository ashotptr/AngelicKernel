#include "xmpp_core.h"
#include "yxml.h"
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------
 * extract_attribute  (static helper)
 *
 * Extracts a named attribute value from a raw XML tag string.
 * Used as a fallback when yxml's streaming callback model is
 * inconvenient for one-shot attribute reads.
 *
 * NOTE: This is not used in the current parse_xml_stream() —
 * attribute extraction there is done via yxml callbacks.
 * ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------
 * find_stanza_end  (static helper)
 *
 * Returns the byte offset just past the end of the first complete
 * XML element starting at xml[0], or -1 if the element is not yet
 * complete in the buffer.
 *
 * RFC 6120 §4.1 — Because an XMPP stream is a single open XML
 *   document, stanza boundaries must be determined by element depth,
 *   not by TCP segment boundaries.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-4.1
 *
 * KNOWN LIMITATIONS (acceptable for embedded use):
 *   - Does not handle XML comments (<!-- ... -->) spanning a '<'
 *   - Does not handle CDATA sections (<![CDATA[...]]>)
 *   - Does not validate element nesting matches tag names
 *   - Processing instructions (<?...?>) are skipped correctly.
 * ------------------------------------------------------------------ */
static int find_stanza_end(const char *xml, int len) {
    const char *p   = xml;
    const char *end = xml + len;
    int depth = 0;

    while (p < end) {
        if (*p != '<') { 
            p++;

            continue;
        }

        /* Processing instruction or declaration: <?...?> or <!...>
         * RFC 6120 §11.3 — Processing instructions are allowed in streams. */
        if (p + 1 < end && (*(p + 1) == '?' || *(p + 1) == '!')) {
            const char *gt = memchr(p, '>', end - p);

            if (!gt) {
                return -1;
            }

            p = gt + 1;

            continue;
        }

        /* Closing tag </foo> — decrements depth */
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

        /* Opening or self-closing tag */
        const char *gt = memchr(p, '>', end - p);

        if (!gt) {
            return -1;
        }

        if (*(gt - 1) == '/') {
            /* Self-closing <foo/> — depth unchanged; complete if depth==0 */
            if (depth == 0) {
                return (int)((gt + 1) - xml);
            }
        }
        else {
            depth++;
        }

        p = gt + 1;
    }

    return -1; /* Incomplete stanza */
}

/* ------------------------------------------------------------------
 * parse_xml_stream
 *
 * Parses the next complete XMPP stanza from [payload, len) and fills
 * an xmpp_stanza_t. Sets *bytes_consumed to the number of bytes to
 * remove from the caller's buffer regardless of success/failure.
 *
 * Returns a filled stanza on success; NULL if the buffer holds only
 * an incomplete stanza (caller should wait for more data).
 *
 * --- RFC/XEP references by section ---
 *
 * Stanza kinds and their top-level element names:
 *   RFC 6120 §8.2  — <iq>
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-8.2
 *   RFC 6120 §8.4  — <message>
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-8.4
 *   RFC 6120 §8.5  — <presence>
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-8.5
 *
 * IQ type attribute (MUST be exactly one of get|set|result|error):
 *   RFC 6120 §8.2.1 — IQ Semantics
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.1
 *   BUG: s->type is pre-set to XMPP_IQ_RESULT before the type
 *   attribute is read. If yxml never fires YXML_ATTRVAL for "type"
 *   (e.g. malformed or very long element), the stanza silently becomes
 *   a RESULT. Fix: initialise to XMPP_UNKNOWN and set XMPP_IQ_ERROR
 *   if type="error" is encountered.
 *
 * SASL <auth> element:
 *   RFC 6120 §6.3.3 — namespace urn:ietf:params:xml:ns:xmpp-sasl
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6.3.3
 *
 * Resource bind child element:
 *   RFC 6120 §7.6 — namespace urn:ietf:params:xml:ns:xmpp-bind
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-7.6
 *
 * Session child element:
 *   RFC 6121 §3.1 — namespace urn:ietf:params:xml:ns:xmpp-session
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-3.1
 *
 * Roster query:
 *   RFC 6121 §2.1.3 — namespace jabber:iq:roster
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-2.1.3
 *
 * Disco queries:
 *   XEP-0045 §6.2 — http://jabber.org/protocol/disco#info
 *   XEP-0045 §6.3 — http://jabber.org/protocol/disco#items
 *     https://xmpp.org/extensions/xep-0045.html#disco
 *
 * MUC namespaces:
 *   XEP-0045 §7.1 — http://jabber.org/protocol/muc  (entering a room)
 *     https://xmpp.org/extensions/xep-0045.html#enter
 *   XEP-0045 §10  — http://jabber.org/protocol/muc#owner
 *     https://xmpp.org/extensions/xep-0045.html#createroom
 *   XEP-0045 §9   — http://jabber.org/protocol/muc#admin
 *     https://xmpp.org/extensions/xep-0045.html#admin
 *
 * SIZE WARNINGS:
 *   yxml stack[1024]: yxml documents the stack must be large enough
 *   to hold the longest element name + attribute name + value that
 *   appears during parsing. Complex stanzas (XEP-0004 data forms
 *   used in XEP-0045 §10.2 room config) may exceed this.
 *   temp_buf[1024]: payload truncated to 1023 bytes — see note in
 *   xmpp_core.h about stanza size limits.
 *
 * XMLNS DETECTION ORDER WARNING:
 *   The strstr fallback block checks for "muc#owner" before "muc".
 *   This is correct because "muc#owner" contains the substring "muc"
 *   — if the order were reversed, muc#owner stanzas would be misclassified
 *   as plain MUC. Do not reorder these checks.
 * ------------------------------------------------------------------ */
xmpp_stanza_t* parse_xml_stream(char *payload, int len, int *bytes_consumed) {
    *bytes_consumed = 0;
    int offset = 0;

    /* Skip leading whitespace (RFC 6120 §11.7 — whitespace pings) */
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

    /* Locate end of this stanza (by XML element depth) */
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
    char stack[1024]; /* See size warning above */

    yxml_init(&x, stack, sizeof(stack));

    int depth = 0;
    char current_attr[64] = {0};

    /* --- Phase 1: yxml streaming parse for element names, types, attrs --- */
    for (int i = 0; i < stanza_len; i++) {
        yxml_ret_t r = yxml_parse(&x, xml_start[i]);

        if (r == YXML_ELEMSTART) {
            depth++;

            if (depth == 1) {
                /* Top-level stanza element name determines the stanza kind.
                 * RFC 6120 §8 — the three stanza types are <message>, <iq>,
                 * <presence>; anything else at depth 1 is invalid mid-stream.
                 *
                 * BUG: IQ type is set to XMPP_IQ_RESULT here before we have
                 * read the type attribute. Should be XMPP_UNKNOWN. */
                if (strcmp(x.elem, "message") == 0) {
                    s->type = XMPP_MESSAGE;

                    strcpy(s->xmlns, "jabber:client"); /* RFC 6120 §8.4 */
                }
                else if (strcmp(x.elem, "iq") == 0) {
                    s->type = XMPP_IQ_RESULT; /* FIXME: should be XMPP_UNKNOWN */
                }
                else if (strcmp(x.elem, "presence") == 0) {
                    s->type = XMPP_PRESENCE;

                    strcpy(s->xmlns, "jabber:client"); /* RFC 6120 §8.5 */
                }
                else if (strcmp(x.elem, "auth") == 0) {
                    /* RFC 6120 §6.3.3 — SASL <auth> element */
                    strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-sasl");
                }
            }
            else if (depth == 2) {
                /* Child element namespace shortcuts for common negotiation
                 * elements that don't use a <query xmlns=...> pattern: */
                if (strcmp(x.elem, "bind") == 0) {
                    /* RFC 6120 §7.6 — resource bind child */
                    strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-bind");
                }
                else if (strcmp(x.elem, "session") == 0) {
                    /* RFC 6121 §3.1 — session establishment child */
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
                /* RFC 6120 §8.1 — common stanza attributes */
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
                    /* RFC 6120 §8.2.1 — IQ type values */
                    if (strcmp(x.data, "get") == 0) {
                        s->type = XMPP_IQ_GET;
                    }
                    else if (strcmp(x.data, "set") == 0) {
                        s->type = XMPP_IQ_SET;
                    }
                    else if (strcmp(x.data, "error") == 0) {
                        s->type = XMPP_IQ_ERROR;
                    }
                    else if (strcmp(x.data, "result") == 0) {
                        s->type = XMPP_IQ_RESULT;
                    }
                    /* TODO: RFC 6120 §8.2.1 — if type is none of the above,
                     * respond with <bad-request/> stanza error. */
                }
            }
            else if (depth == 2) {
                /* <query xmlns='...'> pattern used by roster and disco.
                 * RFC 6121 §2.1.3  — jabber:iq:roster
                 * XEP-0045 §6.2/6.3 — disco#info / disco#items */
                if (strcmp(x.elem, "query") == 0 && strcmp(current_attr, "xmlns") == 0) {
                    strncat(s->xmlns, x.data, sizeof(s->xmlns) - strlen(s->xmlns) - 1);
                }
            }
        }
    }

    /* --- Phase 2: strstr fallback for namespace detection --------------- */
    /* This block is needed because some child namespaces appear in
     * attributes of deeply-nested elements (e.g. <x xmlns='...muc'/> at
     * depth > 2) that yxml above only processes at depth 1-2.
     *
     * ORDER IS CRITICAL — more specific strings must come before substrings:
     *   "muc#owner" before "muc"
     *   "muc#admin" before "muc"
     * Swapping these would cause muc#owner/admin to be misclassified. */
    char temp_buf[1024];
    int copy_len = (stanza_len < 1023) ? stanza_len : 1023;

    memcpy(temp_buf, xml_start, copy_len);

    temp_buf[copy_len] = '\0';

    if (strstr(temp_buf, "jabber:iq:roster")) {
        /* RFC 6121 §2.1.3 */
        strcpy(s->xmlns, "jabber:iq:roster");
    }
    else if (strstr(temp_buf, "muc#owner")) {
        /* XEP-0045 §10 — owner use cases */
        strcpy(s->xmlns, "http://jabber.org/protocol/muc#owner");
    }
    else if (strstr(temp_buf, "muc#admin")) {
        /* XEP-0045 §9 — admin use cases */
        strcpy(s->xmlns, "http://jabber.org/protocol/muc#admin");
    }
    else if (strstr(temp_buf, "disco#info")) {
        /* XEP-0045 §6.2 — service/room feature discovery */
        strcpy(s->xmlns, "http://jabber.org/protocol/disco#info");
    }
    else if (strstr(temp_buf, "disco#items")) {
        /* XEP-0045 §6.3 — listing rooms / room items */
        strcpy(s->xmlns, "http://jabber.org/protocol/disco#items");
    }
    else if (strstr(temp_buf, "http://jabber.org/protocol/muc")) {
        /* XEP-0045 §7.1 — <x xmlns='http://jabber.org/protocol/muc'/>
         * embedded in a <presence> stanza to enter a room */
        strcpy(s->xmlns, "http://jabber.org/protocol/muc");
    }

    /* --- Phase 3: payload extraction ----------------------------------- */
    /* Extract inner XML (child elements / text) from the stanza.
     * The payload is used by handlers to read child element content
     * (e.g. <resource> in bind, <query> in roster).
     *
     * We use a simple string scan rather than yxml here to avoid the
     * complexity of reassembling the inner document from streaming
     * yxml events — acceptable for the fixed small payloads this
     * server is designed to handle. */
    char *header_end = strchr(temp_buf, '>');
    int is_self_closing = (header_end && header_end > temp_buf && *(header_end - 1) == '/');

    if (is_self_closing) {
        /* e.g. <presence/> — no inner content
         * RFC 6121 §4.1 — an empty <presence/> signals availability */
        s->payload[0] = '\0';
    }
    else {
        char *inner_start = header_end;

        if (inner_start && inner_start < (temp_buf + copy_len)) {
            inner_start++;

            /* Build the closing tag from the element name */
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
                /* NOTE: payload is silently truncated at 1023 bytes.
                 * XEP-0045 §10.2 room config (Data Forms/XEP-0004)
                 * can produce larger payloads. */
            }
            else {
                s->payload[0] = '\0';
            }
        }
    }

    return s;
}