#include "xmpp_core.h"
#include "yxml.h"
#include <string.h>
#include <stdio.h>


extern int find_stanza_end_dispatch(const char *xml, int len);

#define find_stanza_end(xml, len) find_stanza_end_dispatch(xml, len)
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
// static int find_stanza_end(const char *xml, int len) {
//     const char *p   = xml;
//     const char *end = xml + len;
//     int depth = 0;

//     while (p < end) {
//         if (*p != '<') { 
//             p++;

//             continue;
//         }

//         /* Processing instruction or declaration: <?...?> or <!...>
//          * RFC 6120 §11.3 — Processing instructions are allowed in streams. */
//         if (p + 1 < end && (*(p + 1) == '?' || *(p + 1) == '!')) {
//             const char *gt = memchr(p, '>', end - p);

//             if (!gt) {
//                 return -1;
//             }

//             p = gt + 1;

//             continue;
//         }

//         /* Closing tag </foo> — decrements depth */
//         if (p + 1 < end && *(p + 1) == '/') {
//             const char *gt = memchr(p, '>', end - p);

//             if (!gt) {
//                 return -1;
//             }

//             depth--;

//             if (depth == 0) {
//                 return (int)((gt + 1) - xml);
//             }

//             p = gt + 1;

//             continue;
//         }

//         /* Opening or self-closing tag */
//         const char *gt = memchr(p, '>', end - p);

//         if (!gt) {
//             return -1;
//         }

//         if (*(gt - 1) == '/') {
//             /* Self-closing <foo/> — depth unchanged; complete if depth==0 */
//             if (depth == 0) {
//                 return (int)((gt + 1) - xml);
//             }
//         }
//         else {
//             depth++;
//         }

//         p = gt + 1;
//     }

//     return -1; /* Incomplete stanza */
// }

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
 *   RFC 6120 §8.2   — Basic Semantics (parent section)
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-8.2
 *   RFC 6120 §8.2.1 — <message> semantics
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.1
 *   RFC 6120 §8.2.2 — <presence> semantics
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.2
 *   RFC 6120 §8.2.3 — <iq> semantics
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.3
 *
 * IQ type attribute (MUST be exactly one of get|set|result|error):
 *   RFC 6120 §8.2.3 — IQ Semantics
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.3
 *   s->type is now initialised to XMPP_UNKNOWN at the
 *   depth-1 ELEMSTART for <iq> rather than being pre-set to XMPP_IQ_RESULT.
 *   The actual type value is resolved after the yxml loop by comparing
 *   the accumulated iq_type_buf against "get"/"set"/"result"/"error".
 *   This is necessary because yxml delivers ATTRVAL one byte at a time;
 *   comparing x.data (a 1-char string) against "get" inside the loop
 *   always fails.  If no recognised type= value is found, s->type
 *   remains XMPP_UNKNOWN and the router sends <bad-request/>.
 *
 * SASL <auth> element:
 *   RFC 6120 §6.4.2 — Initiation: <auth> element sent by the client
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6.4.2
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
 *   XEP-0045 §7.2  — http://jabber.org/protocol/muc  (entering a room)
 *     https://xmpp.org/extensions/xep-0045.html#enter
 *   XEP-0045 §10   — http://jabber.org/protocol/muc#owner
 *     https://xmpp.org/extensions/xep-0045.html#createroom
 *   XEP-0045 §9    — http://jabber.org/protocol/muc#admin
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
xmpp_stanza_t* parse_xml_stream(char *payload, int len, int *bytes_consumed, parse_null_reason_t *reason) {
    *bytes_consumed = 0;
    int offset = 0;

    /* Skip leading whitespace (RFC 6120 §11.7 — whitespace pings) */
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

    /* Locate end of this stanza (by XML element depth) */
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
    char stack[1024]; /* See size warning above */

    yxml_init(&x, stack, sizeof(stack));

    int depth = 0;
    char current_attr[64] = {0};

    /* Accumulators for IQ and presence type= attribute values.
     *
     * yxml delivers YXML_ATTRVAL events one byte at a time (x.data is always
     * a 1-character NUL-terminated string for ASCII input).  Comparing
     * x.data against a multi-character literal like "get" therefore always
     * fails.  We must accumulate the full value and compare only after the
     * yxml loop completes.
     *
     * RFC 6120 §8.2.3 — IQ type MUST be get|set|result|error.
     * RFC 6121 §4.5 — presence type for unavailable/subscription states. */
    char iq_type_buf[16] = {0}; /* accumulates the value of type= on <iq> */
    char pres_type_buf[16] = {0}; /* accumulates the value of type= on <presence>  */
    int is_iq = 0; /* set when depth-1 element is <iq> */
    int is_pres = 0; /* set when depth-1 element is <presence> */
    int xmlns_locked = 0; /* set when depth-2 ELEMSTART already wrote xmlns */

    /* --- Phase 1: yxml streaming parse for element names, types, attrs --- */
    for (int i = 0; i < stanza_len; i++) {
        yxml_ret_t r = yxml_parse(&x, xml_start[i]);

        if (r == YXML_ELEMSTART) {
            depth++;

            if (depth == 1) {
                /* Top-level stanza element name determines the stanza kind.
                 * RFC 6120 §8.2 — the three stanza types are <message>,
                 * <iq>, <presence>; anything else at depth 1 is invalid
                 * mid-stream.
                 *
                 * IQ type is now initialised to XMPP_UNKNOWN
                 * here, not XMPP_IQ_RESULT. XMPP_IQ_RESULT is only set
                 * when the type="result" attribute is explicitly parsed in
                 * the ATTRVAL branch below. This prevents a malformed or
                 * attribute-less <iq> from silently becoming an IQ-result. */
                if (strcmp(x.elem, "message") == 0) {
                    s->type = XMPP_MESSAGE;

                    strcpy(s->xmlns, "jabber:client"); /* RFC 6120 §8.2.1 */
                }
                else if (strcmp(x.elem, "iq") == 0) {
                    s->type = XMPP_UNKNOWN; /* final value resolved after yxml loop from iq_type_buf */
                    
                    is_iq = 1;
                }
                else if (strcmp(x.elem, "presence") == 0) {
                    s->type = XMPP_PRESENCE; /* overridden after loop if pres_type_buf is non-empty */
                    
                    is_pres = 1;

                    strcpy(s->xmlns, "jabber:client"); /* RFC 6120 §8.2.2 */
                }
                else if (strcmp(x.elem, "auth") == 0) {
                    /* RFC 6120 §6.4.2 — SASL Initiation: <auth> element
                     * sent by the client to begin SASL negotiation */
                    strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-sasl");
                }
            }
            else if (depth == 2) {
                /* Child element namespace shortcuts for <bind> and <session>,
                 * which declare their namespace as part of the element name
                 * itself (RFC 6120 §7.6, RFC 6121 §3.1) rather than via an
                 * xmlns= attribute that follows.  We write s->xmlns here and
                 * set xmlns_locked so the depth-2 ATTRVAL accumulator below
                 * does not later overwrite it. */
                if (strcmp(x.elem, "bind") == 0) {
                    /* RFC 6120 §7.6 — resource bind child */
                    strcpy(s->xmlns, "urn:ietf:params:xml:ns:xmpp-bind");
                    
                    xmlns_locked = 1;
                }
                else if (strcmp(x.elem, "session") == 0) {
                    /* RFC 6121 §3.1 — session establishment child */
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
                else if (strcmp(current_attr, "type") == 0 && is_iq) {
                    /* Accumulate type= value one byte at a time.
                     * yxml delivers YXML_ATTRVAL one character per call, so
                     * we cannot compare x.data to "get"/"set" here directly —
                     * the comparison is deferred to after the yxml loop.
                     * RFC 6120 §8.2.3 — IQ type MUST be get|set|result|error. */
                    strncat(iq_type_buf, x.data, sizeof(iq_type_buf) - strlen(iq_type_buf) - 1);
                }
                else if (strcmp(current_attr, "type") == 0 && is_pres) {
                    /* RFC 6121 §4.5   — unavailable presence
                     * RFC 6121 §3.1.3 — subscription presence types
                     *   https://datatracker.ietf.org/doc/html/rfc6121#section-4.5
                     *   https://datatracker.ietf.org/doc/html/rfc6121#section-3.1.3
                     *
                     * NOTE: an available <presence/> has no 'type' attribute; the
                     * type remains XMPP_PRESENCE (set at ELEMSTART above).
                     * Comparison deferred to after the yxml loop. */
                    strncat(pres_type_buf, x.data, sizeof(pres_type_buf) - strlen(pres_type_buf) - 1);
                }
                else if (strcmp(current_attr, "mechanism") == 0 && strcmp(x.elem, "auth") == 0) {
                    /* RFC 6120 §6.4.2 — capture the SASL mechanism name.
                     * Used by handle_sasl() to validate that the client
                     * requested a mechanism that was actually offered.
                     *   https://datatracker.ietf.org/doc/html/rfc6120#section-6.4.2 */
                    strncat(s->mechanism, x.data, sizeof(s->mechanism) - strlen(s->mechanism) - 1);
                }
            }
            else if (depth == 2) {
                /* Generic depth-2 xmlns capture.
                 *
                 * Any child element can carry its namespace in an xmlns=
                 * attribute.  We previously only handled <query xmlns=...>
                 * here, which caused <blocklist xmlns='urn:xmpp:blocking'/>,
                 * <pubsub xmlns='http://jabber.org/protocol/pubsub'>, and
                 * similar elements to leave s->xmlns empty.  Empty xmlns means
                 * the routing table never matches, the stanza falls through to
                 * the type-based catch-all.
                 *
                 * Guard: only accumulate when xmlns_locked is clear.
                 * xmlns_locked is set by the depth-2 ELEMSTART block above
                 * for <bind> and <session>, which write their namespace
                 * directly without an xmlns= attribute.  For all other
                 * elements we accumulate here, one YXML_ATTRVAL byte at a time.
                 *
                 * IMPORTANT: The old guard was `s->xmlns[0] == '\0'`, which
                 * fired correctly for the first byte but then prevented all
                 * subsequent bytes from being appended — leaving only the
                 * first character in s->xmlns.  xmlns_locked is set once at
                 * ELEMSTART and never changes during ATTRVAL, so it is safe
                 * across the full multi-byte accumulation.
                 *
                 * RFC 6121 §2.1.3  — jabber:iq:roster  (<query>)
                 * XEP-0045 §6.2/6.3 — disco#info / disco#items  (<query>)
                 * XEP-0191          — urn:xmpp:blocking          (<blocklist>)
                 * XEP-0060          — pubsub                     (<pubsub>)
                 * XEP-0049          — jabber:iq:private           (<query>)
                 * XEP-0054          — vcard-temp                  (<vCard>)  */
                if (strcmp(current_attr, "xmlns") == 0 && !xmlns_locked) {
                    strncat(s->xmlns, x.data, sizeof(s->xmlns) - strlen(s->xmlns) - 1);
                }
            }
        }
    }

    /* --- Post-loop: resolve IQ and presence type from accumulated buffers - */
    /* IQ type (RFC 6120 §8.2.3) */
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
        /* Otherwise iq_type_buf is empty (no type= attr) or holds an
         * unrecognised value — s->type stays XMPP_UNKNOWN, which the
         * router will reject with <bad-request/> per RFC 6120 §8.2.3. */
    }

    /* Presence type (RFC 6121 §4.5, §3.1.3) */
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
        /* RFC 6121 §4.3.1 — the server SHOULD respond with the probed
         * user's current presence, not re-broadcast the probe.
         * handle_broadcast_presence() has a dedicated probe branch that
         * handles this correctly and returns early.
         *   https://datatracker.ietf.org/doc/html/rfc6121#section-4.3.1 */
        else if (strcmp(pres_type_buf, "probe") == 0) {
            s->type = XMPP_PRESENCE_PROBE;
        }
        /* Unknown presence type — stays XMPP_PRESENCE; silently tolerated. */
    }

    /* --- Phase 2: strstr fallback for namespace detection --------------- */
    /* The correct approach:
     *   A) If yxml found a xmlns (s->xmlns is non-empty), trust it —
     *      EXCEPT for MUC presence stanzas (see B below).
     *   B) MUC join/exit presence stanzas carry
     *        <x xmlns='http://jabber.org/protocol/muc'/>
     *      at depth > 2, which the yxml depth-2 accumulator never visits.
     *      For XMPP_PRESENCE stanzas only, we apply the strstr checks
     *      even when yxml already wrote something, so the MUC namespace
     *      is not missed.  The more-specific "muc#owner"/"muc#admin"
     *      strings are checked before "muc" to avoid misclassification.
     *   C) When yxml found nothing (s->xmlns is empty), the full strstr
     *      fallback is applied unconditionally — this catches namespaces
     *      on elements that sit deeper than depth 2 in non-presence stanzas
     *      (e.g. XEP-0191 blocklist, XEP-0060 pubsub).
     *
     * ORDER IS CRITICAL — more-specific strings must precede substrings:
     *   "muc#owner" before "muc", "muc#admin" before "muc".
     *
     * Primary purpose: catch namespaces that appear on deeply-nested elements
     * (depth > 2, e.g. <x xmlns='...muc'/> inside a <presence>) which the
     * yxml phase above only visits at depth 1-2. */
    char temp_buf[1024];
    int copy_len = (stanza_len < 1023) ? stanza_len : 1023;

    memcpy(temp_buf, xml_start, copy_len);

    temp_buf[copy_len] = '\0';

    if (s->xmlns[0] == '\0') {
        /* Case C — yxml found nothing: apply full strstr fallback. */
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
        else if (strstr(temp_buf, "urn:xmpp:blocking")) {
            /* XEP-0191 — Blocking Command */
            strcpy(s->xmlns, "urn:xmpp:blocking");
        }
        else if (strstr(temp_buf, "http://jabber.org/protocol/pubsub")) {
            /* XEP-0060 — Publish-Subscribe */
            strcpy(s->xmlns, "http://jabber.org/protocol/pubsub");
        }
        else if (strstr(temp_buf, "http://jabber.org/protocol/muc")) {
            /* XEP-0045 §7.2 — <x xmlns='http://jabber.org/protocol/muc'/>
             * embedded in a <presence> stanza to enter a room */
            strcpy(s->xmlns, "http://jabber.org/protocol/muc");
        }
    }
    else if (s->type == XMPP_PRESENCE || s->type == XMPP_PRESENCE_UNAVAILABLE) {
        /* Case B — MUC presence xmlns is at depth > 2 so yxml misses it.
         * Override only for presence stanzas where a MUC join/exit is
         * signalled via <x xmlns='http://jabber.org/protocol/muc[#owner|#admin]'/>
         * Check more-specific strings first to avoid misclassification. */
        if (strstr(temp_buf, "muc#owner")) {
            strcpy(s->xmlns, "http://jabber.org/protocol/muc#owner");
        }
        else if (strstr(temp_buf, "muc#admin")) {
            strcpy(s->xmlns, "http://jabber.org/protocol/muc#admin");
        }
        else if (strstr(temp_buf, "http://jabber.org/protocol/muc")) {
            strcpy(s->xmlns, "http://jabber.org/protocol/muc");
        }
        /* else: leave whatever yxml found (e.g. jabber:client) intact */
    }
    /* Case A — yxml found a xmlns and this is not a presence stanza:
     * trust yxml completely; do not apply strstr checks. */

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