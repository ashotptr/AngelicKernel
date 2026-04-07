/* ===========================================================================
 * xmpp_sm.c — XEP-0198 Stream Management (Stanza Acknowledgement)
 *
 * XEP-0198 §1 (Introduction):
 *   Stream Management allows either party to verify receipt of stanzas
 *   by acknowledging them incrementally with <a> elements.  If the
 *   connection drops unexpectedly, a resumed session can replay any
 *   unacknowledged stanzas from an in-memory queue without losing data.
 *
 * WHAT WE IMPLEMENT (the minimum viable subset for the Capstone):
 *
 *   ── Enable/Ack exchange (§4) ──────────────────────────────────────────
 *   Client sends:  <enable xmlns='urn:xmpp:sm:3'/>
 *   Server sends:  <enabled xmlns='urn:xmpp:sm:3' id='...' resume='false'/>
 *     NOTE: resume='false' — we implement ack-only, no session resumption.
 *     Full resumption requires persistent stanza queuing across reconnects
 *     which is not feasible in a stateless unikernel without stable storage.
 *
 *   ── Stanza counting (§4.1) ────────────────────────────────────────────
 *   We increment h (handled count) for every stanza received from the client
 *   after SM is enabled.  The value is returned in <a h='N'/> responses.
 *
 *   ── Ack requests (§4.2) ───────────────────────────────────────────────
 *   Client sends:  <r xmlns='urn:xmpp:sm:3'/>
 *   Server replies: <a xmlns='urn:xmpp:sm:3' h='N'/>
 *   where N is the count of stanzas handled so far.
 *
 *   ── Server-side ack requests ──────────────────────────────────────────
 *   When the server sends a stanza to the client, it MAY periodically
 *   send <r/> to request confirmation.  We do this every 10 stanzas.
 *
 * WHAT WE DO NOT IMPLEMENT:
 *   - Session resumption (resume='true', <resume/>, <resumed/>).
 *     Requires persisting the unacknowledged stanza queue to disk and
 *     assigning stable stream IDs across reconnects.
 *   - Outbound stanza queue for resumption.
 *     We set resume='false' so clients know not to expect resumption.
 *
 * INTEGRATION WITH xmpp_server.c:
 *   1. Add `sm_enabled`, `sm_inbound_h`, `sm_outbound_count` to xmpp_client_ctx_t
 *      (see xmpp_core.h additions below).
 *   2. In xmpp_recv_callback(), after the existing stream-open and SASL
 *      detection blocks, add a call to xmpp_sm_handle_element().
 *   3. In send_raw() (xmpp_handlers.c), increment ctx->sm_outbound_count
 *      and periodically call xmpp_sm_request_ack().
 *   4. In xmpp_init_server(), add <sm xmlns='urn:xmpp:sm:3'/> to the
 *      post-auth stream features.
 *
 * FIELDS TO ADD TO xmpp_client_ctx_t (xmpp_core.h):
 *
 *   // XEP-0198 Stream Management state
 *   int      sm_enabled;        // 1 after <enable/> is processed
 *   uint32_t sm_inbound_h;      // count of stanzas received (acked to client)
 *   uint32_t sm_outbound_count; // count of stanzas sent (for periodic <r/>)
 *
 * STREAM FEATURES TO ADVERTISE (in handle_handshake_logic, post-auth only):
 *   "<sm xmlns='urn:xmpp:sm:3'/>"
 *
 * XEP-0198: https://xmpp.org/extensions/xep-0198.html
 * =========================================================================== */

#include "xmpp_core.h"
#include <string.h>
#include <stdio.h>

/* How often (in sent stanzas) to proactively ask the client for an ack.
 * XEP-0198 §4.2 — the server MAY send <r/> at any time; we do it every
 * SM_ACK_INTERVAL outbound stanzas to detect dead connections quickly. */
#define SM_ACK_INTERVAL 10u

/* XEP-0198 namespace */
#define SM_NS "urn:xmpp:sm:3"

/* Forward declarations from xmpp_handlers.c */
extern void send_raw(xmpp_client_ctx_t *ctx, const char *data);


/* ── xmpp_sm_send_enabled ────────────────────────────────────────────────────
 *
 * XEP-0198 §4.1 — responds to <enable/> with <enabled/>.
 *
 * We set resume='false' because full session resumption is not implemented.
 * A future version could set resume='true' and store the stanza queue on
 * the ATA data disk, but that would require significant additional work.
 *
 * The 'id' attribute is a server-generated token that would identify the
 * resumable session. Since we don't implement resumption, we use a random
 * value for spec compliance.
 * ─────────────────────────────────────────────────────────────────────────── */
void xmpp_sm_send_enabled(xmpp_client_ctx_t *ctx) {
    /* Generate a short random ID for the SM session token.
     * Not cryptographically important since resume='false'. */
    extern unsigned int secure_random_u32(void);
    unsigned int token = secure_random_u32() % 0xFFFFFF;

    char response[256];
    snprintf(response, sizeof(response),
        "<enabled xmlns='" SM_NS "'"
        " id='angelic%06x'"
        " resume='false'/>",
        token);

    ctx->sm_enabled       = 1;
    ctx->sm_inbound_h     = 0;
    ctx->sm_outbound_count = 0;

    send_raw(ctx, response);
}


/* ── xmpp_sm_send_ack ────────────────────────────────────────────────────────
 *
 * XEP-0198 §4.2 — responds to <r/> with <a h='N'/>.
 * N = the number of stanzas received from this client since SM was enabled.
 * ─────────────────────────────────────────────────────────────────────────── */
void xmpp_sm_send_ack(xmpp_client_ctx_t *ctx) {
    char response[128];
    snprintf(response, sizeof(response),
        "<a xmlns='" SM_NS "' h='%u'/>",
        ctx->sm_inbound_h);
    send_raw(ctx, response);
}


/* ── xmpp_sm_request_ack ─────────────────────────────────────────────────────
 *
 * XEP-0198 §4.2 — proactively send <r/> to the client to request an ack.
 * Called from the send path every SM_ACK_INTERVAL stanzas.
 *
 * This lets the server detect dead connections without waiting for the
 * next inbound stanza from the client.
 * ─────────────────────────────────────────────────────────────────────────── */
void xmpp_sm_request_ack(xmpp_client_ctx_t *ctx) {
    if (!ctx->sm_enabled) return;
    send_raw(ctx, "<r xmlns='" SM_NS "'/>");
}


/* ── xmpp_sm_on_stanza_received ──────────────────────────────────────────────
 *
 * Call this whenever a complete stanza is received from the client and
 * SM is enabled. Increments the inbound handled count.
 *
 * XEP-0198 §4.1:
 *   "the server MUST keep a count of stanzas received from the client"
 * ─────────────────────────────────────────────────────────────────────────── */
void xmpp_sm_on_stanza_received(xmpp_client_ctx_t *ctx) {
    if (ctx->sm_enabled) {
        ctx->sm_inbound_h++;
    }
}


/* ── xmpp_sm_on_stanza_sent ──────────────────────────────────────────────────
 *
 * Call this after every stanza is sent to the client when SM is enabled.
 * Periodically triggers a proactive <r/> request to the client.
 *
 * XEP-0198 §4.2:
 *   "At any time, either party MAY ask the other party to acknowledge
 *    stanzas that have been received."
 * ─────────────────────────────────────────────────────────────────────────── */
void xmpp_sm_on_stanza_sent(xmpp_client_ctx_t *ctx) {
    if (!ctx->sm_enabled) return;

    ctx->sm_outbound_count++;

    if (ctx->sm_outbound_count % SM_ACK_INTERVAL == 0) {
        xmpp_sm_request_ack(ctx);
    }
}


/* ── xmpp_sm_handle_element ──────────────────────────────────────────────────
 *
 * Pre-parse dispatcher for SM elements in the receive buffer.
 * Call this from xmpp_recv_callback() BEFORE the normal stanza parser,
 * at any connection state after STATE_AUTHENTICATED.
 *
 * Returns 1 if the element was an SM element (consumed), 0 otherwise.
 *
 * SM elements we handle:
 *   <enable .../>      — client requests SM
 *   <r .../>           — client requests ack of its inbound count
 *   <a h='N'/>         — client acks N of our outbound stanzas
 *
 * NOTE: SM elements are NOT XML stanzas (not <message>/<iq>/<presence>),
 * so they should be consumed before stanza parsing to avoid confusing yxml.
 * ─────────────────────────────────────────────────────────────────────────── */
int xmpp_sm_handle_element(xmpp_client_ctx_t *ctx) {
    const char *buf = ctx->rx_buffer;

    if (ctx->state < STATE_AUTHENTICATED) return 0;

    /* ── <enable ...> ─────────────────────────────────────────────────── */
    if (strncmp(buf, "<enable", 7) == 0 &&
        strstr(buf, SM_NS) != NULL) {

        /* Consume through the closing '>' */
        char *gt = strchr(buf, '>');
        if (!gt) return 0;

        int consumed = (int)(gt - buf) + 1;

        xmpp_sm_send_enabled(ctx);

        /* Slide consumed bytes out of the receive buffer */
        memmove(ctx->rx_buffer, ctx->rx_buffer + consumed,
                ctx->rx_pos - consumed);
        ctx->rx_pos -= consumed;
        ctx->rx_buffer[ctx->rx_pos] = '\0';

        return 1;
    }

    /* ── <r .../> ─────────────────────────────────────────────────────── */
    if (strncmp(buf, "<r", 2) == 0 && buf[2] == ' ' || strncmp(buf, "<r/>", 4) == 0) {
        if (strstr(buf, SM_NS) != NULL) {
            char *gt = strchr(buf, '>');
            if (!gt) return 0;

            int consumed = (int)(gt - buf) + 1;
            xmpp_sm_send_ack(ctx);

            memmove(ctx->rx_buffer, ctx->rx_buffer + consumed,
                    ctx->rx_pos - consumed);
            ctx->rx_pos -= consumed;
            ctx->rx_buffer[ctx->rx_pos] = '\0';
            return 1;
        }
    }

    /* ── <a h='N'/> ───────────────────────────────────────────────────── */
    if (strncmp(buf, "<a", 2) == 0 && buf[2] == ' ') {
        if (strstr(buf, SM_NS) != NULL && strstr(buf, "h=") != NULL) {
            char *gt = strchr(buf, '>');
            if (!gt) return 0;

            /* Parse h= value — client is acking this many of our stanzas.
             * We don't maintain an outbound queue for resumption, so we
             * note the ack but take no further action. */
            const char *h_attr = strstr(buf, "h='");
            if (!h_attr) h_attr = strstr(buf, "h=\"");

            if (h_attr) {
                h_attr += 3;
                /* parse decimal integer */
                uint32_t acked = 0;
                while (*h_attr >= '0' && *h_attr <= '9') {
                    acked = acked * 10 + (*h_attr - '0');
                    h_attr++;
                }
                /* Nothing to do with acked since we don't queue for resumption.
                 * On a real implementation: dequeue stanzas ≤ acked from the
                 * unacknowledged outbound queue. */
                (void)acked;
            }

            int consumed = (int)(gt - buf) + 1;
            memmove(ctx->rx_buffer, ctx->rx_buffer + consumed,
                    ctx->rx_pos - consumed);
            ctx->rx_pos -= consumed;
            ctx->rx_buffer[ctx->rx_pos] = '\0';
            return 1;
        }
    }

    return 0;
}
