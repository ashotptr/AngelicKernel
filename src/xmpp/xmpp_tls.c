#include "xmpp_core.h"
#include "lwip/tcp.h"
#include "mbedtls/ssl.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/version.h"
#include <string.h>
#include <stdint.h>

extern void serial_print(const char *s);
extern unsigned int secure_random_u32(void);

#define TLS_POOL_SIZE (288u * 1024u)

static uint8_t tls_pool[TLS_POOL_SIZE] __attribute__((aligned(8)));

static int tls_entropy_func(void *data, unsigned char *output, size_t len) {
    (void)data;
    size_t i = 0;

    while (i + sizeof(uint32_t) <= len) {
        uint32_t r = secure_random_u32();

        memcpy(output + i, &r, sizeof(r));

        i += sizeof(r);
    }

    if (i < len) {
        uint32_t r = secure_random_u32();

        memcpy(output + i, &r, len - i);
    }

    return 0;
}

static mbedtls_ssl_config g_tls_conf;
static mbedtls_x509_crt g_tls_cert;
static mbedtls_pk_context g_tls_pkey;
static mbedtls_ctr_drbg_context g_tls_drbg;

static uint8_t g_cert_der[2048];

static int tls_net_send(void *bio_ctx, const unsigned char *buf, size_t len) {
    xmpp_client_ctx_t *ctx = (xmpp_client_ctx_t *)bio_ctx;

    if (!ctx->pcb) {
        return -1;
    }

    {
        char tmp[64];

        snprintf(tmp, sizeof(tmp), "[tls-bio] send %d bytes\n", (int)len);

        serial_print(tmp);
    }

    err_t e = tcp_write(ctx->pcb, buf, (u16_t)len, TCP_WRITE_FLAG_COPY);

    if (e == ERR_MEM) {
        serial_print("[tls-bio] tcp_write err_mem -> want_write\n");

        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    if (e != ERR_OK) {
        serial_print("[tls-bio] tcp_write error\n");

        return -1;
    }

    return (int)len;
}

static int tls_net_recv(void *bio_ctx, unsigned char *buf, size_t len) {
    xmpp_client_ctx_t *ctx = (xmpp_client_ctx_t *)bio_ctx;
    int avail = ctx->tls_rx_len - ctx->tls_rx_pos;

    if (avail <= 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    int n = ((int)len < avail) ? (int)len : avail;

    memcpy(buf, ctx->tls_rx_buf + ctx->tls_rx_pos, (size_t)n);

    ctx->tls_rx_pos += n;
    
    return n;
}

static void tls_staging_compact(xmpp_client_ctx_t *ctx) {
    if (ctx->tls_rx_pos >= ctx->tls_rx_len) {
        ctx->tls_rx_pos = 0;
        ctx->tls_rx_len = 0;
    }
    else if (ctx->tls_rx_pos > 0) {
        memmove(ctx->tls_rx_buf, ctx->tls_rx_buf + ctx->tls_rx_pos, (size_t)(ctx->tls_rx_len - ctx->tls_rx_pos));

        ctx->tls_rx_len -= ctx->tls_rx_pos;
        ctx->tls_rx_pos = 0;
    }
}

int xmpp_tls_server_init(void) {
    int ret;

    mbedtls_memory_buffer_alloc_init(tls_pool, sizeof(tls_pool));

    serial_print("[tls] initialising server tls context\n");
    
    mbedtls_ctr_drbg_init(&g_tls_drbg);

    const char *pers = "xmpp_server_" XMPP_DOMAIN;
    
    ret = mbedtls_ctr_drbg_seed(&g_tls_drbg, tls_entropy_func, NULL, (const unsigned char *)pers, strlen(pers));

    if (ret != 0) {
        serial_print("[rls] ctr-drbg seed failed\n");
        
        return ret;
    }

    mbedtls_pk_init(&g_tls_pkey);

    ret = mbedtls_pk_setup(&g_tls_pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    
    if (ret != 0) {
        serial_print("[tls] pk_setup failed\n");
        
        return ret;
    }

    serial_print("[tls] generating ecdsa p-256 key\n");

    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(g_tls_pkey), mbedtls_ctr_drbg_random, &g_tls_drbg);
    
    if (ret != 0) {
        serial_print("[tls] key generation failed\n");
        
        return ret;
    }

    serial_print("[tls] key generation complete.\n");

    mbedtls_x509write_cert crt_ctx;
    
    mbedtls_x509write_crt_init(&crt_ctx);
    
    mbedtls_x509write_crt_set_version(&crt_ctx, MBEDTLS_X509_CRT_VERSION_3);
    
    mbedtls_x509write_crt_set_md_alg(&crt_ctx, MBEDTLS_MD_SHA256);
    
    mbedtls_x509write_crt_set_subject_key(&crt_ctx, &g_tls_pkey);
    
    mbedtls_x509write_crt_set_issuer_key(&crt_ctx, &g_tls_pkey);

    char dn[64];
    
    snprintf(dn, sizeof(dn), "CN=%s,O=unikernel xmpp", XMPP_DOMAIN);
    
    mbedtls_x509write_crt_set_subject_name(&crt_ctx, dn);
    
    mbedtls_x509write_crt_set_issuer_name(&crt_ctx, dn);

#if MBEDTLS_VERSION_NUMBER >= 0x03020000
    {
        unsigned char serial_bytes[1] = { 0x01 };
        ret = mbedtls_x509write_crt_set_serial_raw(&crt_ctx, serial_bytes, sizeof(serial_bytes));
    }
#else
    {
        mbedtls_mpi serial;

        mbedtls_mpi_init(&serial);

        mbedtls_mpi_lset(&serial, 1);

        ret = mbedtls_x509write_crt_set_serial(&crt_ctx, &serial);

        mbedtls_mpi_free(&serial);
    }
#endif
    if (ret != 0) {
        serial_print("[tls] set_serial failed\n");

        mbedtls_x509write_crt_free(&crt_ctx);

        return ret;
    }

    mbedtls_x509write_crt_set_validity(&crt_ctx, "20250101000000", "20350101000000");

    mbedtls_x509write_crt_set_basic_constraints(&crt_ctx, 0, -1);

    mbedtls_x509write_crt_set_subject_key_identifier(&crt_ctx);
    
    mbedtls_x509write_crt_set_authority_key_identifier(&crt_ctx);

    serial_print("[tls] writing self-signed certificate\n");
    
    int cert_len = mbedtls_x509write_crt_der(&crt_ctx, g_cert_der, sizeof(g_cert_der), mbedtls_ctr_drbg_random, &g_tls_drbg);

    mbedtls_x509write_crt_free(&crt_ctx);
    
    if (cert_len <= 0) {
        serial_print("[tls] certificate write failed\n");
        
        return cert_len;
    }

    mbedtls_x509_crt_init(&g_tls_cert);

    ret = mbedtls_x509_crt_parse_der(&g_tls_cert, g_cert_der + sizeof(g_cert_der) - cert_len, (size_t)cert_len);

    if (ret != 0) {
        serial_print("[tls] certificate parse failed\n");

        return ret;
    }

    serial_print("[tls] certificate ready\n");

    mbedtls_ssl_config_init(&g_tls_conf);

    ret = mbedtls_ssl_config_defaults(&g_tls_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    
    if (ret != 0) {
        serial_print("[tls] ssl_config_defaults failed\n");
        
        return ret;
    }

    mbedtls_ssl_conf_authmode(&g_tls_conf, MBEDTLS_SSL_VERIFY_NONE);

    mbedtls_ssl_conf_rng(&g_tls_conf, mbedtls_ctr_drbg_random, &g_tls_drbg);

    ret = mbedtls_ssl_conf_own_cert(&g_tls_conf, &g_tls_cert, &g_tls_pkey);
    
    if (ret != 0) {
        serial_print("[tls] ssl_conf_own_cert failed\n");
        
        return ret;
    }

    serial_print("[tls] server tls context ready\n");
    
    return 0;
}

int xmpp_tls_client_init(xmpp_client_ctx_t *ctx) {
    ctx->tls_want_write = 0;

    mbedtls_ssl_init(&ctx->tls_ssl);

    int ret = mbedtls_ssl_setup(&ctx->tls_ssl, &g_tls_conf);

    if (ret != 0) {
        char errbuf[80];

        mbedtls_strerror(ret, errbuf, sizeof(errbuf));

        serial_print("[tls] ssl_setup: ");
        serial_print(errbuf);
        serial_print("\n");

        mbedtls_ssl_free(&ctx->tls_ssl);

        return ret;
    }

    mbedtls_ssl_set_bio(&ctx->tls_ssl, ctx, tls_net_send, tls_net_recv, NULL);

    ctx->tls_rx_len = 0;
    ctx->tls_rx_pos = 0;
    ctx->tls_established = 0;
    ctx->tls_initialised = 1;

    return 0;
}

void xmpp_tls_client_free(xmpp_client_ctx_t *ctx) {
    if (ctx->tls_initialised) {
        mbedtls_ssl_free(&ctx->tls_ssl);

        ctx->tls_established = 0;
        ctx->tls_initialised = 0;
        ctx->tls_rx_len = 0;
        ctx->tls_rx_pos = 0;
    }
}

void xmpp_tls_handshake_step(xmpp_client_ctx_t *ctx, const uint8_t *data, int len) {
    tls_staging_compact(ctx);

    int space = (int)sizeof(ctx->tls_rx_buf) - ctx->tls_rx_len;

    if (len > space) {
        serial_print("[tls] handshake staging buffer overflow\n");

        if (ctx->pcb) { 
            tcp_close(ctx->pcb); 

            ctx->pcb = NULL; 
        }
        
        ctx->state = STATE_CONNECTED;
        ctx->tls_established = 0;

        return;
    }

    if (len > 0) {
        memcpy(ctx->tls_rx_buf + ctx->tls_rx_len, data, (size_t)len);

        ctx->tls_rx_len += len;
    }

    int ret = mbedtls_ssl_handshake(&ctx->tls_ssl);

    {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "[tls] handshake ret=0x%x\n", (unsigned)-ret);

        serial_print(tmp);
    }

    if (ctx->pcb) {
        tcp_output(ctx->pcb);
    }

    tls_staging_compact(ctx);

    if (ret == 0) {
        ctx->tls_established = 1;
        ctx->tls_want_write = 0;
        ctx->state = STATE_CONNECTED;
        ctx->rx_pos = 0;

        serial_print("[tls] handshake complete, stream reset pending\n");

        return;
    }

    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        ctx->tls_want_write = 0;

        return;
    }

    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        ctx->tls_want_write = 1;

        return;
    }

    ctx->tls_want_write = 0;

    {
        char errbuf[80];

        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        
        serial_print("[tls] handshake failed: ");
        serial_print(errbuf);
        serial_print("\n");
    }

    if (ctx->pcb) { 
        tcp_close(ctx->pcb);

        ctx->pcb = NULL; 
    }

    ctx->state = STATE_CONNECTED;
    ctx->tls_established = 0;
}

void xmpp_tls_decrypt(xmpp_client_ctx_t *ctx, const uint8_t *data, int len) {
    tls_staging_compact(ctx);

    int space = (int)sizeof(ctx->tls_rx_buf) - ctx->tls_rx_len;

    if (len > space) {
        serial_print("[tls] decrypt staging buffer overflow\n");

        if (ctx->pcb) { 
            tcp_close(ctx->pcb); 
            
            ctx->pcb = NULL;
        }
        
        return;
    }

    if (len > 0) {
        memcpy(ctx->tls_rx_buf + ctx->tls_rx_len, data, (size_t)len);

        ctx->tls_rx_len += len;
    }

    unsigned char dec[MBEDTLS_SSL_IN_CONTENT_LEN];
    int ret;

    do {
        ret = mbedtls_ssl_read(&ctx->tls_ssl, dec, sizeof(dec));

        if (ret > 0) {
            if (ctx->rx_pos + ret < (int)(sizeof(ctx->rx_buffer) - 1)) {
                memcpy(ctx->rx_buffer + ctx->rx_pos, dec, (size_t)ret);

                ctx->rx_pos += ret;
                ctx->rx_buffer[ctx->rx_pos] = '\0';
            }
            else {
                serial_print("[tls] rx_buffer overflow after decryption\n");

                if (ctx->pcb) {
                    const char *err =
                        "<stream:error>"
                          "<policy-violation"
                            " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
                        "</stream:error>"
                        "</stream:stream>";

                    mbedtls_ssl_write(&ctx->tls_ssl, (const unsigned char *)err, strlen(err));

                    tcp_output(ctx->pcb);

                    tcp_close(ctx->pcb);

                    ctx->pcb = NULL;
                }

                return;
            }
        }
        else if (ret == 0) {
            if (ctx->pcb) { 
                tcp_close(ctx->pcb); 

                ctx->pcb = NULL; 
            }

            return;
        }
        else if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            char errbuf[80];

            mbedtls_strerror(ret, errbuf, sizeof(errbuf));

            serial_print("[tls] decrypt error: ");
            serial_print(errbuf);
            serial_print("\n");

            if (ctx->pcb) { 
                tcp_close(ctx->pcb); 

                ctx->pcb = NULL; 
            }

            ctx->tls_established = 0;

            return;
        }
    } while (ret > 0);

    tls_staging_compact(ctx);
}