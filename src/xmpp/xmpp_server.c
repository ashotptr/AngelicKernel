#include "xmpp_core.h"
#include <string.h>

room_t rooms[MAX_ROOMS];

static int extract_stream_attr(const char *buf, const char *attr_name, char *out, int out_max) {
    char key[64];

    snprintf(key, sizeof(key), " %s=", attr_name);

    const char *p = strstr(buf, key);

    if (!p) {
        return 0;
    }

    p += strlen(key);
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

    if (len >= out_max) {
        len = out_max - 1;
    }

    strncpy(out, p, len);
    
    out[len] = '\0';
    
    return 1;
}

static void send_stream_close_and_free(xmpp_client_ctx_t *ctx) {
    const char *close_tag = "</stream:stream>";

    if (ctx->tls_established) {
        mbedtls_ssl_write(&ctx->tls_ssl, (const unsigned char *)close_tag, strlen(close_tag));

        if (ctx->pcb) {
            tcp_output(ctx->pcb);
        }

        mbedtls_ssl_close_notify(&ctx->tls_ssl);
    }
    else if (ctx->pcb && ctx->state >= STATE_SASL) {
        tcp_write(ctx->pcb, close_tag, strlen(close_tag), TCP_WRITE_FLAG_COPY);

        tcp_output(ctx->pcb);
    }

    xmpp_tls_client_free(ctx);

    if (ctx->pcb) {
        tcp_close(ctx->pcb);
    }

    ctx->pcb = NULL;
    ctx->state = STATE_CONNECTED;
}

void handle_handshake_logic(xmpp_client_ctx_t *ctx) {
    char response[512];

    unsigned int stream_id = secure_random_u32();

    char to_attr[96] = "";

    if (ctx->client_from[0] != '\0') {
        snprintf(to_attr, sizeof(to_attr), " to='%s'", ctx->client_from);
    }

    if (ctx->authenticated) {
        ctx->state = STATE_BIND;

        snprintf(response, sizeof(response),
            "<?xml version='1.0'?>"
            "<stream:stream from='%s'%s id='%u' version='1.0' "
            "xml:lang='en' "
            "xmlns='jabber:client' "
            "xmlns:stream='http://etherx.jabber.org/streams'>"
            "<stream:features>"
              "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>"
              "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>"
              "<sm xmlns='urn:xmpp:sm:3'/>"
            "</stream:features>",
            XMPP_DOMAIN, to_attr, stream_id);
    }
    else if (ctx->tls_established) {
        snprintf(response, sizeof(response),
            "<?xml version='1.0'?>"
            "<stream:stream from='%s'%s id='%u' version='1.0' "
            "xml:lang='en' "
            "xmlns='jabber:client' "
            "xmlns:stream='http://etherx.jabber.org/streams'>"
            "<stream:features>"
              "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                "<mechanism>PLAIN</mechanism>"
              "</mechanisms>"
            "</stream:features>",
            XMPP_DOMAIN, to_attr, stream_id);
    }
    else {
        snprintf(response, sizeof(response),
             "<?xml version='1.0'?>"
            "<stream:stream from='%s'%s id='%u' version='1.0' "
             "xml:lang='en' "
             "xmlns='jabber:client' "
             "xmlns:stream='http://etherx.jabber.org/streams'>"
             "<stream:features>"
               "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>"
                 "<required/>"
               "</starttls>"
             "</stream:features>",
            XMPP_DOMAIN, to_attr, stream_id);
    }

    send_raw(ctx, response);

    if (!ctx->authenticated && ctx->tls_established) {
        ctx->state = STATE_SASL;
    }
}

err_t xmpp_recv_callback(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    xmpp_client_ctx_t *ctx = (xmpp_client_ctx_t*)arg;

    if (!p) {
        if (ctx->pcb == NULL) {
            ctx->pcb = pcb;
        }

        send_stream_close_and_free(ctx);
        
        ctx->pcb = NULL;
        ctx->state = STATE_CONNECTED;

        return ERR_OK;
    }

    if (ctx->state == STATE_STARTTLS) {
        tcp_recved(pcb, p->tot_len);

        for (struct pbuf *q = p; q != NULL && ctx->pcb != NULL; q = q->next) {
            xmpp_tls_handshake_step(ctx, (const uint8_t *)q->payload, (int)q->len);
        }

        pbuf_free(p);

        return ERR_OK;
    }

    if (!ctx->tls_established) {
        xmpp_log("recv", (char*)p->payload, p->len);
    }

    int skip_plaintext_copy = 0;

    if (ctx->tls_established) {
        tcp_recved(pcb, p->tot_len);
        
        for (struct pbuf *q = p; q != NULL && ctx->pcb != NULL; q = q->next) {
            xmpp_tls_decrypt(ctx, (const uint8_t *)q->payload, (int)q->len);
        }
        
        pbuf_free(p);
        
        skip_plaintext_copy = 1;
    }

    if (!skip_plaintext_copy) {
        int overflow = 0;

        for (struct pbuf *q = p; q != NULL && !overflow; q = q->next) {
            if (ctx->rx_pos + (int)q->len < (int)(sizeof(ctx->rx_buffer) - 1)) {
                memcpy(ctx->rx_buffer + ctx->rx_pos, q->payload, q->len);

                ctx->rx_pos += q->len;
                ctx->rx_buffer[ctx->rx_pos] = '\0';
            }
            else {
                overflow = 1;
            }
        }

        if (overflow) {
            printf("[xmpp] buffer ovverflow, rx_pos=%d, incoming=%d\n", ctx->rx_pos, (int)p->tot_len);
            
            tcp_recved(pcb, p->tot_len);
            
            pbuf_free(p);

            const char *stream_err =
                "<stream:error>"
                  "<policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                "</stream:error>"
                "</stream:stream>";

            tcp_write(pcb, stream_err, strlen(stream_err), TCP_WRITE_FLAG_COPY);

            tcp_output(pcb);
            
            tcp_close(pcb);

            ctx->pcb = NULL;
            ctx->state = STATE_CONNECTED;

            return ERR_OK;
        }

        tcp_recved(pcb, p->tot_len);

        pbuf_free(p);
    }

    while (ctx->rx_pos > 0) {
        int shift = 0;

        while (shift < ctx->rx_pos) {
            char c = ctx->rx_buffer[shift];

            if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
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

        if (ctx->state == STATE_CONNECTED && !ctx->tls_established && strncmp(ctx->rx_buffer, "<starttls", 9) == 0) {
            char *starttls_gt = strchr(ctx->rx_buffer, '>');

            if (!starttls_gt) {
                break;
            }

            const char *proceed = "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";

            tcp_write(ctx->pcb, proceed, strlen(proceed), TCP_WRITE_FLAG_COPY);
            
            tcp_output(ctx->pcb);

            if (xmpp_tls_client_init(ctx) != 0) {
                const char *fail = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
                
                tcp_write(ctx->pcb, fail, strlen(fail), TCP_WRITE_FLAG_COPY);
                
                tcp_output(ctx->pcb);
                
                tcp_close(ctx->pcb);
                
                ctx->pcb = NULL;
                ctx->state = STATE_CONNECTED;
                ctx->rx_pos = 0;
                
                return ERR_OK;
            }

            ctx->state  = STATE_STARTTLS;
            ctx->rx_pos = 0;
            
            return ERR_OK;
        }

        if (strncmp(ctx->rx_buffer, "</stream:stream", 15) == 0 || strncmp(ctx->rx_buffer, "</stream>", 9) == 0) {
            const char *close_tag = "</stream:stream>";

            if (ctx->tls_established) {
                mbedtls_ssl_write(&ctx->tls_ssl, (const unsigned char *)close_tag, strlen(close_tag));

                if (ctx->pcb) {
                    tcp_output(ctx->pcb);
                }

                mbedtls_ssl_close_notify(&ctx->tls_ssl);
            }
            else {
                tcp_write(ctx->pcb, close_tag, strlen(close_tag), TCP_WRITE_FLAG_COPY);
                
                tcp_output(ctx->pcb);
            }

            xmpp_tls_client_free(ctx);
            
            tcp_close(ctx->pcb);
            
            ctx->pcb = NULL;
            ctx->state = STATE_CONNECTED;
            ctx->rx_pos = 0;

            return ERR_OK;
        }

        if ((ctx->state == STATE_CONNECTED || ctx->state == STATE_AUTHENTICATED) && (strncmp(ctx->rx_buffer, "<?xml", 5) == 0 || strstr(ctx->rx_buffer, "<stream:stream"))) {
            if (strstr(ctx->rx_buffer, "<stream:stream")) {
                ctx->client_from[0] = '\0';

                extract_stream_attr(ctx->rx_buffer, "from", ctx->client_from, sizeof(ctx->client_from));

                if (!ctx->tls_established && !ctx->authenticated) {
                    char stream_to[64] = "";
                    
                    extract_stream_attr(ctx->rx_buffer, "to", stream_to, sizeof(stream_to));
                    
                    if (stream_to[0] != '\0' && strcmp(stream_to, XMPP_DOMAIN) != 0) {
                        char err[512];

                        snprintf(err, sizeof(err),
                            "<?xml version='1.0'?>"
                            "<stream:stream from='" XMPP_DOMAIN "' id='0'"
                              " version='1.0' xml:lang='en'"
                              " xmlns='jabber:client'"
                              " xmlns:stream='http://etherx.jabber.org/streams'>"
                            "<stream:error>"
                              "<host-unknown"
                                " xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
                            "</stream:error>"
                            "</stream:stream>");
                        
                        tcp_write(ctx->pcb, err, strlen(err), TCP_WRITE_FLAG_COPY);
                        
                        tcp_output(ctx->pcb);
                        
                        tcp_close(ctx->pcb);
                        
                        ctx->pcb = NULL;
                        ctx->rx_pos = 0;
                        
                        return ERR_OK;
                    }
                }

                int bad_ns = (strstr(ctx->rx_buffer, "xmlns='jabber:client'") == NULL && strstr(ctx->rx_buffer, "xmlns=\"jabber:client\"") == NULL);
                int bad_stream_ns = (strstr(ctx->rx_buffer, "xmlns:stream='http://etherx.jabber.org/streams'") == NULL && strstr(ctx->rx_buffer, "xmlns:stream=\"http://etherx.jabber.org/streams\"") == NULL);
                int bad_ver = (strstr(ctx->rx_buffer, "version='1.0'") == NULL && strstr(ctx->rx_buffer, "version=\"1.0\"") == NULL);

                if (bad_ns || bad_stream_ns) {
                    const char *err =
                        "<?xml version='1.0'?>"
                        "<stream:stream from='" XMPP_DOMAIN "' id='0' version='1.0' "
                          "xmlns='jabber:client' "
                          "xmlns:stream='http://etherx.jabber.org/streams'>"
                        "<stream:error>"
                          "<invalid-namespace "
                            "xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                        "</stream:error>"
                        "</stream:stream>";
                    
                    tcp_write(ctx->pcb, err, strlen(err), TCP_WRITE_FLAG_COPY);
                    
                    tcp_output(ctx->pcb);
                    
                    tcp_close(ctx->pcb);
                    
                    ctx->rx_pos = 0;
                    
                    return ERR_OK;
                }

                if (bad_ver) {
                    const char *err =
                        "<?xml version='1.0'?>"
                        "<stream:stream from='" XMPP_DOMAIN "' id='0' version='1.0' "
                          "xmlns='jabber:client' "
                          "xmlns:stream='http://etherx.jabber.org/streams'>"
                        "<stream:error>"
                          "<unsupported-version "
                            "xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                        "</stream:error>"
                        "</stream:stream>";
                    
                    tcp_write(ctx->pcb, err, strlen(err), TCP_WRITE_FLAG_COPY);
                    
                    tcp_output(ctx->pcb);
                    
                    tcp_close(ctx->pcb);
                    
                    ctx->rx_pos = 0;
                    
                    return ERR_OK;
                }
            }
            else {
                break;
            }

            handle_handshake_logic(ctx);

            ctx->rx_pos = 0;
            
            return ERR_OK;
        }
        
        if ((ctx->state == STATE_CONNECTED || ctx->state == STATE_SASL) && strncmp(ctx->rx_buffer, "<abort", 6) == 0) {
            char *gt = strchr(ctx->rx_buffer, '>');

            if (gt) {
                int abort_consumed = (int)((gt - ctx->rx_buffer) + 1);
                const char *abort_resp =
                    "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                      "<aborted/>"
                    "</failure>";

                send_raw(ctx, abort_resp);
                
                memmove(ctx->rx_buffer, ctx->rx_buffer + abort_consumed, ctx->rx_pos - abort_consumed);
                
                ctx->rx_pos -= abort_consumed;
                ctx->rx_buffer[ctx->rx_pos] = '\0';
                
                continue;
            }

            break;
        }

        if (ctx->state >= STATE_SESSION) {
            if (xmpp_sm_handle_element(ctx)) {
                continue;
            }
        }

        int bytes_consumed = 0;
        parse_null_reason_t reason;
        xmpp_stanza_t *stanza = parse_xml_stream(ctx->rx_buffer, ctx->rx_pos, &bytes_consumed, &reason);

        if (stanza) {
            if (ctx->state == STATE_CONNECTED || ctx->state == STATE_SASL) {
                if (strcmp(stanza->xmlns, "urn:ietf:params:xml:ns:xmpp-sasl") == 0) {
                    handle_sasl(ctx, stanza);
                }
            }
            else {
                xmpp_route_stanza(ctx, stanza);

                xmpp_sm_on_stanza_received(ctx);
            }

            xmpp_free_stanza(stanza);

            if (bytes_consumed > 0) {
                memmove(ctx->rx_buffer, ctx->rx_buffer + bytes_consumed, ctx->rx_pos - bytes_consumed);

                ctx->rx_pos -= bytes_consumed;
                ctx->rx_buffer[ctx->rx_pos] = '\0';
            }
        }
        else {
            if (reason == PARSE_NO_MEMORY) {
                printf("[xmpp] stanza pool exhausted, resource-constraint\n");
                
                const char *stream_err =
                    "<stream:error>"
                      "<resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                    "</stream:error>"
                    "</stream:stream>";
                
                tcp_write(pcb, stream_err, strlen(stream_err), TCP_WRITE_FLAG_COPY);
                
                tcp_output(pcb);
                
                tcp_close(pcb);
                
                ctx->pcb = NULL;
                ctx->state = STATE_CONNECTED;
                
                return ERR_OK;
            }

            break;
        }
    }

    return ERR_OK;
}

static void xmpp_err_callback(void *arg, err_t err) {
    xmpp_client_ctx_t *ctx = (xmpp_client_ctx_t *)arg;

    if (!ctx) {
        return;
    }

    {
        char tmp[64];
        
        snprintf(tmp, sizeof(tmp), "[xmpp] tcp error %d on connection, cleaning up\n", (int)err);

        serial_print(tmp);
    }
    
    ctx->pcb = NULL;

    xmpp_tls_client_free(ctx);

    memset(ctx, 0, sizeof(xmpp_client_ctx_t));
}

xmpp_client_ctx_t client_registry[MAX_USERS];

err_t xmpp_accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err) {
    (void)arg;
    (void)err;
    static int client_idx = 0;

    xmpp_client_ctx_t *ctx = &client_registry[client_idx];
    client_idx = (client_idx + 1) % MAX_USERS;

    if (ctx->pcb != NULL) {
        xmpp_tls_client_free(ctx);

        tcp_close(ctx->pcb);
    }

    memset(ctx, 0, sizeof(*ctx));

    ctx->pcb = newpcb;
    ctx->state = STATE_CONNECTED;
    ctx->authenticated = 0;

    tcp_arg(newpcb, ctx);

    tcp_recv(newpcb, xmpp_recv_callback);
    
    tcp_err(newpcb, xmpp_err_callback);

    return ERR_OK;
}

void xmpp_init_server() {
    xmpp_persist_load_all();
    
    if (xmpp_tls_server_init() != 0) {
        printf("[xmpp] tls server init failed, halting\n");
        
        for (;;) {}
    }

    struct tcp_pcb *pcb = tcp_new();

    tcp_bind(pcb, IP_ADDR_ANY, 5222);

    pcb = tcp_listen(pcb);

    tcp_accept(pcb, xmpp_accept_callback);
}