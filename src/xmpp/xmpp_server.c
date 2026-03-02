#include "xmpp_core.h"
#include <string.h>

room_t rooms[MAX_ROOMS];

void handle_handshake_logic(xmpp_client_ctx_t *ctx) {
    char response[512];
    int stream_id = rand(); // make not repeating

    if (ctx->authenticated) {
        snprintf(response, sizeof(response),
            "<?xml version='1.0'?>"
            "<stream:stream from='%s' id='%u' version='1.0' "
            "xml:lang='en' "
            "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"
            "<stream:features>"
            "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>"
            "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>" // maybe comment out
            "</stream:features>",
            XMPP_DOMAIN, stream_id);
    } 
    else {
        snprintf(response, sizeof(response),
            "<?xml version='1.0'?>"
            "<stream:stream from='%s' id='%u' version='1.0' "
            "xml:lang='en' "
            "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"
            "<stream:features>"
            "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
            "<mechanism>ANONYMOUS</mechanism>"
            "<mechanism>PLAIN</mechanism>" //tls for future
            "</mechanisms>"
            "</stream:features>",
            XMPP_DOMAIN, stream_id);
    }
// add error cases for invalid stream, etc.
// https://datatracker.ietf.org/doc/html/rfc6120#section-4.9.1.1
    send_raw(ctx, response);
}

void handle_sasl_success(xmpp_client_ctx_t *ctx) {
    const char *resp = "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>";
    
    xmpp_log("SEND", resp, strlen(resp));

    tcp_write(ctx->pcb, resp, strlen(resp), TCP_WRITE_FLAG_COPY);
    
    tcp_output(ctx->pcb);

    ctx->authenticated = 1;
    ctx->state = STATE_AUTHENTICATED;
}

err_t xmpp_recv_callback(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    xmpp_client_ctx_t *ctx = (xmpp_client_ctx_t*)arg;
    
    if (!p) { 
        tcp_close(pcb);

        return ERR_OK; 
    }

    xmpp_log("RECV", (char*)p->payload, p->len);

    if (ctx->rx_pos + (int)p->len < (int)(sizeof(ctx->rx_buffer) - 1)) {
        memcpy(ctx->rx_buffer + ctx->rx_pos, p->payload, p->len);

        ctx->rx_pos += p->len;
        ctx->rx_buffer[ctx->rx_pos] = '\0';
    }
    else {
        printf("[XMPP] Buffer Overflow! Dropping %d bytes. rx_pos=%d\n", p->len, ctx->rx_pos);

        ctx->rx_pos = 0;
    }
    
    tcp_recved(pcb, p->len);

    pbuf_free(p);

    while (ctx->rx_pos > 0) {
        int shift = 0;

        while (shift < ctx->rx_pos) {
            char c = ctx->rx_buffer[shift];

            if (c != ' ' && c != '\n' && c != '\r' && c != '\t'){
                break;
            }
            
            shift++;
        }
        
        if (shift > 0) {
            memmove(ctx->rx_buffer, ctx->rx_buffer + shift, ctx->rx_pos - shift);

            ctx->rx_pos -= shift;
            
            ctx->rx_buffer[ctx->rx_pos] = '\0';
        }

        if (ctx->rx_pos == 0) {
            break;
        }

        if (strncmp(ctx->rx_buffer, "<?xml", 5) == 0 || strstr(ctx->rx_buffer, "<stream:stream")) {
            handle_handshake_logic(ctx);

            ctx->rx_pos = 0;

            return ERR_OK;
        }

        int bytes_consumed = 0;

        xmpp_stanza_t *stanza = parse_xml_stream(ctx->rx_buffer, ctx->rx_pos, &bytes_consumed);
        
        if (stanza) {
            if (ctx->state == STATE_CONNECTED) {
                if (strcmp(stanza->xmlns, "urn:ietf:params:xml:ns:xmpp-sasl") == 0) { 
                    // check for error cases such as invalid mechanism, etc.
                    // https://datatracker.ietf.org/doc/html/rfc6120#section-13.9.1
                    // https://datatracker.ietf.org/doc/html/rfc6120#section-6.5.5
                    handle_sasl(ctx, stanza);
                }
            }
            else {
                xmpp_route_stanza(ctx, stanza);
            }
            
            xmpp_free_stanza(stanza);

            if (bytes_consumed > 0) {
                memmove(ctx->rx_buffer, ctx->rx_buffer + bytes_consumed, ctx->rx_pos - bytes_consumed);

                ctx->rx_pos -= bytes_consumed;
                ctx->rx_buffer[ctx->rx_pos] = '\0';
            }
        }
        else {
            break; 
        }
    }

    return ERR_OK;
}

err_t xmpp_accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err) {
    static xmpp_client_ctx_t client_pool[MAX_USERS];
    static int client_idx = 0;
    
    xmpp_client_ctx_t *ctx = &client_pool[client_idx]; 
    client_idx = (client_idx + 1) % MAX_USERS;

    ctx->pcb = newpcb;
    ctx->state = STATE_CONNECTED;
    ctx->authenticated = 0;

    tcp_arg(newpcb, ctx);
    
    tcp_recv(newpcb, xmpp_recv_callback);

    return ERR_OK;
}

void xmpp_init_server() {
    struct tcp_pcb *pcb = tcp_new();

    tcp_bind(pcb, IP_ADDR_ANY, 5222);

    pcb = tcp_listen(pcb);

    tcp_accept(pcb, xmpp_accept_callback);
}