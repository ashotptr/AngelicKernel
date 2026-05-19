#include "xmpp_core.h"
#include <string.h>
#include <stdio.h>

#define SM_ACK_INTERVAL 10u

#define SM_NS "urn:xmpp:sm:3"

extern void send_raw(xmpp_client_ctx_t *ctx, const char *data);

void xmpp_sm_send_enabled(xmpp_client_ctx_t *ctx) {
    extern unsigned int secure_random_u32(void);
    unsigned int token = secure_random_u32() % 0xFFFFFF;

    char response[256];

    snprintf(response, sizeof(response),
        "<enabled xmlns='" SM_NS "'"
        " id='angelic%06x'"
        " resume='false'/>",
        token);

    ctx->sm_enabled = 1;
    ctx->sm_inbound_h = 0;
    ctx->sm_outbound_count = 0;

    send_raw(ctx, response);
}

void xmpp_sm_send_ack(xmpp_client_ctx_t *ctx) {
    char response[128];

    snprintf(response, sizeof(response),
        "<a xmlns='" SM_NS "' h='%u'/>",
        ctx->sm_inbound_h);

    send_raw(ctx, response);
}

void xmpp_sm_request_ack(xmpp_client_ctx_t *ctx) {
    if (!ctx->sm_enabled) {
        return;
    }

    send_raw(ctx, "<r xmlns='" SM_NS "'/>");
}

void xmpp_sm_on_stanza_received(xmpp_client_ctx_t *ctx) {
    if (ctx->sm_enabled) {
        ctx->sm_inbound_h++;
    }
}

void xmpp_sm_on_stanza_sent(xmpp_client_ctx_t *ctx) {
    if (!ctx->sm_enabled) {
        return;
    }

    ctx->sm_outbound_count++;

    if (ctx->sm_outbound_count % SM_ACK_INTERVAL == 0) {
        ctx->sm_want_ack = 1;
    }
}

int xmpp_sm_handle_element(xmpp_client_ctx_t *ctx) {
    const char *buf = ctx->rx_buffer;

    if (ctx->state < STATE_SESSION) {
        return 0;
    }

    if (strncmp(buf, "<enable", 7) == 0 && strstr(buf, SM_NS) != NULL) {
        char *gt = strchr(buf, '>');

        if (!gt) {
            return 0;
        }

        int consumed = (int)(gt - buf) + 1;

        xmpp_sm_send_enabled(ctx);

        memmove(ctx->rx_buffer, ctx->rx_buffer + consumed, ctx->rx_pos - consumed);
        
        ctx->rx_pos -= consumed;
        ctx->rx_buffer[ctx->rx_pos] = '\0';

        return 1;
    }

    if ((strncmp(buf, "<r", 2) == 0 && buf[2] == ' ') || strncmp(buf, "<r/>", 4) == 0) {
        if (strstr(buf, SM_NS) != NULL) {
            char *gt = strchr(buf, '>');

            if (!gt) {
                return 0;
            }

            int consumed = (int)(gt - buf) + 1;

            xmpp_sm_send_ack(ctx);

            memmove(ctx->rx_buffer, ctx->rx_buffer + consumed, ctx->rx_pos - consumed);

            ctx->rx_pos -= consumed;
            ctx->rx_buffer[ctx->rx_pos] = '\0';

            return 1;
        }
    }

    if (strncmp(buf, "<a", 2) == 0 && buf[2] == ' ') {
        if (strstr(buf, SM_NS) != NULL && strstr(buf, "h=") != NULL) {
            char *gt = strchr(buf, '>');

            if (!gt) {
                return 0;
            }

            const char *h_attr = strstr(buf, "h='");

            if (!h_attr) {
                h_attr = strstr(buf, "h=\"");
            }

            if (h_attr) {
                h_attr += 3;
                uint32_t acked = 0;

                while (*h_attr >= '0' && *h_attr <= '9') {
                    acked = acked * 10 + (*h_attr - '0');
                    h_attr++;
                }

                (void)acked;
            }

            int consumed = (int)(gt - buf) + 1;

            memmove(ctx->rx_buffer, ctx->rx_buffer + consumed, ctx->rx_pos - consumed);

            ctx->rx_pos -= consumed;
            ctx->rx_buffer[ctx->rx_pos] = '\0';

            return 1;
        }
    }

    return 0;
}