/* ===========================================================================
 * xmpp_tls.c — STARTTLS / mbedTLS integration
 *
 * Implements RFC 6120 §5 (STARTTLS negotiation) using mbedTLS 3.2+.
 *
 * STARTTLS PROTOCOL FLOW (RFC 6120 §5.2):
 *
 *   1. Server sends <stream:features> with <starttls required/> (first feature,
 *      before any SASL offer — RFC 6120 §5.3.1).
 *
 *   2. Client sends:
 *        <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>
 *
 *   3. Server sends:
 *        <proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>
 *      and immediately enters TLS mode (STATE_STARTTLS).
 *
 *   4. TLS handshake across however many recv_callback round-trips are needed,
 *      each driving xmpp_tls_handshake_step().
 *
 *   5. Both sides MUST reset the XML stream (RFC 6120 §5.2 step 5c).
 *      On completion the server sets tls_established=1 and returns state to
 *      STATE_CONNECTED.  The client then opens a new <stream:stream>.
 *      handle_handshake_logic() sees tls_established=1 and offers SASL —
 *      NOT STARTTLS again.
 *
 *   6. SASL, bind, session proceed normally over the encrypted channel.
 *
 * MEMORY MODEL:
 *   mbedTLS requires a dynamic allocator.  We use mbedTLS's own production
 *   buffer allocator (MBEDTLS_MEMORY_BUFFER_ALLOC_C) backed by a static array.
 *   mbedtls_memory_buffer_alloc_init() is called first in xmpp_tls_server_init()
 *   and internally registers the allocator via mbedtls_platform_set_calloc_free().
 *   No custom allocator code is needed.
 *
 *   Buffer sizing (MBEDTLS_SSL_IN/OUT_CONTENT_LEN = 4096):
 *     Per-session I/O buffers : 2 × ~4300 B  =  8.6 KB
 *     Handshake ephemeral     : ~2 KB
 *     10 sessions             : 10 × 10.6 KB = 106 KB
 *     Shared cert / key / cfg : ~4 KB
 *     TLS_POOL_SIZE           : 160 KB  (comfortable margin)
 *
 * CERTIFICATE:
 *   Self-signed ECDSA P-256 for CN=XMPP_DOMAIN generated at startup.
 *   Valid 2025-01-01 → 2035-01-01.  Certificate expiry is NOT checked at
 *   runtime (MBEDTLS_HAVE_TIME_DATE is undefined — no wall clock available
 *   post-ExitBootServices).
 *
 * ENTROPY:
 *   secure_random_u32() (hw_trng_read() + xorshift64* fallback) is wrapped
 *   in tls_entropy_func() and passed directly to mbedtls_ctr_drbg_seed().
 *
 * MBEDTLS VERSION COMPATIBILITY:
 *   Serial-number API changed in mbedTLS 3.2:
 *     < 3.2: mbedtls_x509write_crt_set_serial(ctx, mpi*)
 *    >= 3.2: mbedtls_x509write_crt_set_serial_new(ctx, buf, len)
 *   A MBEDTLS_VERSION_NUMBER guard selects the right call.
 * =========================================================================== */

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

/* ===========================================================================
 * Static backing buffer for the mbedTLS buffer allocator
 *
 * mbedtls_memory_buffer_alloc_init() uses this as the heap from which all
 * mbedTLS allocations are served.  It coalesces freed blocks internally.
 * Alignment to 8 bytes satisfies the allocator's requirements on x86-64.
 *
 * Sizing derivation: see file header above.
 * =========================================================================== */
#define TLS_POOL_SIZE (288u * 1024u)  /* increased: IN_CONTENT_LEN=16384 needs ~25KB/session */

static uint8_t tls_pool[TLS_POOL_SIZE] __attribute__((aligned(8)));

/* ===========================================================================
 * Entropy source
 *
 * Passed as f_entropy to mbedtls_ctr_drbg_seed().  Wraps secure_random_u32()
 * which uses hw_trng_read() with an xorshift64* CSPRNG fallback.
 * =========================================================================== */
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

/* ===========================================================================
 * Global server-side TLS state
 *
 * Shared across all client connections.  Only mbedtls_ssl_context is per-client.
 * =========================================================================== */
static mbedtls_ssl_config g_tls_conf;
static mbedtls_x509_crt g_tls_cert;
static mbedtls_pk_context g_tls_pkey;
static mbedtls_ctr_drbg_context g_tls_drbg;

/* DER buffer for the self-signed certificate (used only during init).
 * mbedtls_x509write_crt_der() writes right-justified into this buffer. */
static uint8_t g_cert_der[2048];

/* ===========================================================================
 * lwIP I/O callbacks registered with mbedtls_ssl_set_bio()
 *
 * bio_ctx == xmpp_client_ctx_t* for the connection.
 * =========================================================================== */

static int tls_net_send(void *bio_ctx, const unsigned char *buf, size_t len) {
    serial_print("[TLS-BIO] send called\n");
    xmpp_client_ctx_t *ctx = (xmpp_client_ctx_t *)bio_ctx;

    if (!ctx->pcb) {
        return -1; /* fatal: no PCB, cannot send */
    }

    /* tcp_write() buffers; tcp_output() in the callers flushes. */
    err_t e = tcp_write(ctx->pcb, buf, (u16_t)len, TCP_WRITE_FLAG_COPY);

    if (e == ERR_MEM) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    if (e != ERR_OK) {
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

/* Slide consumed bytes to the front of the staging buffer. */
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

/* ===========================================================================
 * xmpp_tls_server_init
 *
 * Must be called once from xmpp_init_server() before accepting any connection.
 * Steps:
 *   0. Install the mbedTLS buffer allocator (MUST be first).
 *   1. Seed CTR-DRBG from secure_random_u32().
 *   2. Generate ECDSA P-256 private key.
 *   3. Build and parse a self-signed X.509v3 certificate.
 *   4. Configure the shared server SSL context.
 *
 * Returns 0 on success, non-zero mbedTLS error code on failure.
 * =========================================================================== */
int xmpp_tls_server_init(void) {
    int ret;

    /* ── 0. Install mbedTLS buffer allocator ─────────────────────────────────
     * Must be the absolute first mbedTLS call.  mbedtls_memory_buffer_alloc_init()
     * internally calls mbedtls_platform_set_calloc_free() to install its hooks.
     * After this point all mbedTLS allocations draw from tls_pool[].
     *
     * MBEDTLS_PLATFORM_NO_STD_FUNCTIONS ensures the gnu-efi calloc/free
     * (which are invalid post-ExitBootServices) are never used as defaults. */
    mbedtls_memory_buffer_alloc_init(tls_pool, sizeof(tls_pool));

    serial_print("[TLS] Initialising server TLS context...\n");

    /* ── 1. Seed CTR-DRBG ────────────────────────────────────────────────────
     * tls_entropy_func wraps secure_random_u32() (hw_trng + xorshift64*).
     * MBEDTLS_ENTROPY_C is disabled — we bypass it and pass f_entropy directly. */
    mbedtls_ctr_drbg_init(&g_tls_drbg);

    const char *pers = "xmpp_server_" XMPP_DOMAIN;
    
    ret = mbedtls_ctr_drbg_seed(&g_tls_drbg, tls_entropy_func, NULL, (const unsigned char *)pers, strlen(pers));

    if (ret != 0) {
        serial_print("[TLS] ERROR: CTR-DRBG seed failed\n");
        
        return ret;
    }

    /* ── 2. Generate ECDSA P-256 private key ─────────────────────────────────
     * mbedtls_ecp_gen_key() is a blocking call (~50-100 ms on a typical core).
     * This is acceptable: the server has not started accepting connections yet.
     * MBEDTLS_ECP_RESTARTABLE is intentionally absent — it only helps TLS
     * clients, not servers. */
    mbedtls_pk_init(&g_tls_pkey);

    ret = mbedtls_pk_setup(&g_tls_pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    
    if (ret != 0) {
        serial_print("[TLS] ERROR: pk_setup failed\n");
        
        return ret;
    }

    serial_print("[TLS] Generating ECDSA P-256 key...\n");

    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(g_tls_pkey), mbedtls_ctr_drbg_random, &g_tls_drbg);
    
    if (ret != 0) {
        serial_print("[TLS] ERROR: key generation failed\n");
        
        return ret;
    }

    serial_print("[TLS] Key generation complete.\n");

    /* ── 3. Build self-signed X.509v3 certificate ────────────────────────────
     * MBEDTLS_HAVE_TIME_DATE is disabled so mbedtls_x509write_crt_der() does
     * not attempt to call time()/gmtime() for timestamp validation. */
    mbedtls_x509write_cert crt_ctx;
    
    mbedtls_x509write_crt_init(&crt_ctx);
    
    mbedtls_x509write_crt_set_version(&crt_ctx, MBEDTLS_X509_CRT_VERSION_3);
    
    mbedtls_x509write_crt_set_md_alg(&crt_ctx, MBEDTLS_MD_SHA256);
    
    mbedtls_x509write_crt_set_subject_key(&crt_ctx, &g_tls_pkey);
    
    mbedtls_x509write_crt_set_issuer_key(&crt_ctx, &g_tls_pkey);

    char dn[64];
    
    snprintf(dn, sizeof(dn), "CN=%s,O=Unikernel XMPP", XMPP_DOMAIN);
    
    mbedtls_x509write_crt_set_subject_name(&crt_ctx, dn);
    
    mbedtls_x509write_crt_set_issuer_name(&crt_ctx, dn);

    /* ------------------------------------------------------------------
     * Serial number: 1
     * API changed in mbedTLS 3.2 (MPI-based form deprecated):
     *   < 3.2: mbedtls_x509write_crt_set_serial(ctx, mpi*)
     *  >= 3.2: mbedtls_x509write_crt_set_serial_raw(ctx, raw_bytes, len)
     * ------------------------------------------------------------------ */
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
        serial_print("[TLS] ERROR: set_serial failed\n");

        mbedtls_x509write_crt_free(&crt_ctx);
        
        return ret;
    }

    /* 10-year validity window.
     * Certificate expiry is NOT enforced at runtime because MBEDTLS_HAVE_TIME_DATE
     * is disabled — no gmtime() available post-ExitBootServices. */
    mbedtls_x509write_crt_set_validity(&crt_ctx, "20250101000000", "20350101000000");

    mbedtls_x509write_crt_set_basic_constraints(&crt_ctx, 0 /* not CA */, -1);

    mbedtls_x509write_crt_set_subject_key_identifier(&crt_ctx);
    
    mbedtls_x509write_crt_set_authority_key_identifier(&crt_ctx);

    /* ------------------------------------------------------------------
     * Subject Alternative Name (SAN) — required by RFC 6125 and every
     * modern TLS client (OpenSSL 1.1+, GnuTLS 3.x, Python 3.7+).
     *
     * Without a dNSName SAN that matches the server hostname, clients
     * reject the certificate even if CN matches.  The CN field alone
     * has been deprecated for hostname matching since RFC 2818 (2000)
     * and is no longer checked by any modern TLS implementation.
     *
     * Structure (DER, right-justified in san_buf[]):
     *   SEQUENCE {               30 <len>
     *     [2] IMPLICIT IA5String    82 <len> <dns_bytes>
     *   }
     *
     * mbedtls_x509write_crt_set_extension() takes the raw DER of the
     * extension VALUE (the SEQUENCE), not the outer OID wrapper — that
     * is added by the library.
     *
     * mbedtls_asn1_write_* functions write RIGHT-TO-LEFT into the buffer,
     * so we start from the END and work backwards.  'p' is the current
     * write cursor; san_len is the number of bytes written so far.
     *
     *   RFC 5280 §4.2.1.6 — Subject Alternative Name
     *   RFC 6125 §6.4      — Matching against the SAN DNS-ID
     * ------------------------------------------------------------------ */
    {
        unsigned char san_buf[128];
        unsigned char *p_san = san_buf + sizeof(san_buf);
        size_t san_len = 0;

        const char *dns_name = XMPP_DOMAIN;
        size_t      dns_len  = strlen(dns_name);

        /* 1. Write the raw DNS name bytes */
        if (dns_len > (size_t)(p_san - san_buf)) {
            serial_print("[TLS] ERROR: XMPP_DOMAIN too long for SAN buffer\n");
            mbedtls_x509write_crt_free(&crt_ctx);
            return -1;
        }
        p_san   -= dns_len;
        san_len += dns_len;
        memcpy(p_san, dns_name, dns_len);

        /* 2. Tag: context-specific primitive [2] = dNSName (0x82) */
        ret = mbedtls_asn1_write_len(&p_san, san_buf, dns_len);
        if (ret < 0) { mbedtls_x509write_crt_free(&crt_ctx); return ret; }
        san_len += (size_t)ret;

        ret = mbedtls_asn1_write_tag(&p_san, san_buf,
                  MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2);
        if (ret < 0) { mbedtls_x509write_crt_free(&crt_ctx); return ret; }
        san_len += (size_t)ret;

        /* 3. Wrap in SEQUENCE { ... } */
        ret = mbedtls_asn1_write_len(&p_san, san_buf, san_len);
        if (ret < 0) { mbedtls_x509write_crt_free(&crt_ctx); return ret; }
        san_len += (size_t)ret;

        ret = mbedtls_asn1_write_tag(&p_san, san_buf,
                  MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret < 0) { mbedtls_x509write_crt_free(&crt_ctx); return ret; }
        san_len += (size_t)ret;

        /* 4. Register the extension (OID 2.5.29.17, not critical) */
        ret = mbedtls_x509write_crt_set_extension(
                  &crt_ctx,
                  MBEDTLS_OID_SUBJECT_ALT_NAME,
                  MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
                  0,        /* critical = false */
                  p_san,    /* DER value (right-justified in san_buf) */
                  san_len);
        if (ret != 0) {
            char errbuf[80];
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            serial_print("[TLS] ERROR: SAN extension failed: ");
            serial_print(errbuf);
            serial_print("\n");
            mbedtls_x509write_crt_free(&crt_ctx);
            return ret;
        }
        serial_print("[TLS] SAN extension added (dNSName=" XMPP_DOMAIN ")\n");
    }

    /* Write to DER — right-justified within g_cert_der[]. */
    serial_print("[TLS] Writing self-signed certificate...\n");
    
    int cert_len = mbedtls_x509write_crt_der(&crt_ctx, g_cert_der, sizeof(g_cert_der), mbedtls_ctr_drbg_random, &g_tls_drbg);

    mbedtls_x509write_crt_free(&crt_ctx);
    
    if (cert_len <= 0) {
        serial_print("[TLS] ERROR: certificate write failed\n");
        
        return cert_len;
    }

    /* Parse DER into g_tls_cert for use by the SSL config. */
    mbedtls_x509_crt_init(&g_tls_cert);

    ret = mbedtls_x509_crt_parse_der(&g_tls_cert, g_cert_der + sizeof(g_cert_der) - cert_len, (size_t)cert_len);

    if (ret != 0) {
        serial_print("[TLS] ERROR: certificate parse failed\n");

        return ret;
    }

    serial_print("[TLS] Certificate ready.\n");

    /* ── 4. Configure shared SSL server context ───────────────────────────── */
    mbedtls_ssl_config_init(&g_tls_conf);

    ret = mbedtls_ssl_config_defaults(&g_tls_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    
    if (ret != 0) {
        serial_print("[TLS] ERROR: ssl_config_defaults failed\n");
        
        return ret;
    }

    /* No client certificate required — XMPP clients authenticate via SASL. */
    mbedtls_ssl_conf_authmode(&g_tls_conf, MBEDTLS_SSL_VERIFY_NONE);

    mbedtls_ssl_conf_rng(&g_tls_conf, mbedtls_ctr_drbg_random, &g_tls_drbg);

    ret = mbedtls_ssl_conf_own_cert(&g_tls_conf, &g_tls_cert, &g_tls_pkey);
    
    if (ret != 0) {
        serial_print("[TLS] ERROR: ssl_conf_own_cert failed\n");
        
        return ret;
    }

    serial_print("[TLS] Server TLS context ready.\n");
    
    return 0;
}

/* ===========================================================================
 * xmpp_tls_client_init
 *
 * Sets up the per-client mbedtls_ssl_context and registers lwIP I/O callbacks.
 * Called immediately after the server sends <proceed/>.
 *
 * Returns 0 on success, non-zero on failure (server must then send
 * <failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/> and close).
 * =========================================================================== */
int xmpp_tls_client_init(xmpp_client_ctx_t *ctx) {
    mbedtls_ssl_init(&ctx->tls_ssl);

    int ret = mbedtls_ssl_setup(&ctx->tls_ssl, &g_tls_conf);

    if (ret != 0) {
        char errbuf[80];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        serial_print("[TLS] ERROR: ssl_setup: ");
        serial_print(errbuf);
        serial_print("\n");
        mbedtls_ssl_free(&ctx->tls_ssl);
        return ret;
    }

    mbedtls_ssl_set_bio(&ctx->tls_ssl, ctx, tls_net_send, tls_net_recv, NULL);

    ctx->tls_rx_len      = 0;
    ctx->tls_rx_pos      = 0;
    ctx->tls_established = 0;
    ctx->tls_initialised = 1;

    return 0;
}

/* ===========================================================================
 * xmpp_tls_client_free
 *
 * Releases per-client mbedTLS resources.  Safe to call on a context where
 * TLS was never initialised.
 *
 * MUST be called before memset() on the context, and before tcp_close(),
 * so the pool allocator can reclaim the session's I/O buffers cleanly.
 * =========================================================================== */
void xmpp_tls_client_free(xmpp_client_ctx_t *ctx) {
    /* Guard on tls_initialised, NOT on tls_established or state.
     *
     * The old guard (tls_established || state==STATE_STARTTLS) missed
     * the case where the handshake failed partway through:
     *   - tls_initialised=1 (ssl_setup was called)
     *   - tls_established=0 (handshake never completed)
     *   - state was reset to STATE_CONNECTED on the error path
     * That combination leaked the entire per-session allocation (~10 KB)
     * from the static mbedTLS pool every time a client rejected the cert.
     * With 288 KB pool, 29 such failures exhaust it permanently.
     */
    if (ctx->tls_initialised) {
        mbedtls_ssl_free(&ctx->tls_ssl);
        ctx->tls_established = 0;
        ctx->tls_initialised = 0;
        ctx->tls_rx_len      = 0;
        ctx->tls_rx_pos      = 0;
    }
}

/* ===========================================================================
 * xmpp_tls_handshake_step
 *
 * Feeds raw TLS bytes into the staging buffer and drives mbedTLS's handshake
 * state machine.  Called from xmpp_recv_callback() while state == STATE_STARTTLS.
 *
 * Outcome:
 *   Handshake complete → tls_established=1, state=STATE_CONNECTED.
 *                        Client then opens a new XML stream (RFC 6120 §5.2.5c).
 *   Need more data     → state stays STATE_STARTTLS; returns normally.
 *   Fatal error        → TCP connection closed; ctx->pcb = NULL.
 * =========================================================================== */
void xmpp_tls_handshake_step(xmpp_client_ctx_t *ctx, const uint8_t *data, int len) {
    tls_staging_compact(ctx);

    int space = (int)sizeof(ctx->tls_rx_buf) - ctx->tls_rx_len;

    if (len > space) {
        serial_print("[TLS] ERROR: handshake staging buffer overflow\n");
        if (ctx->pcb) { tcp_close(ctx->pcb); ctx->pcb = NULL; }
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
        snprintf(tmp, sizeof(tmp), "[TLS] handshake ret=0x%x\n", (unsigned)-ret);
        serial_print(tmp);
    }

    if (ctx->pcb) {
        tcp_output(ctx->pcb);
    }

    tls_staging_compact(ctx);

    if (ret == 0) {
        ctx->tls_established = 1;
        ctx->tls_want_write  = 0;
        ctx->state  = STATE_CONNECTED;  /* RFC 6120 §5.2 step 5c — stream reset */
        ctx->rx_pos = 0;
        serial_print("[TLS] Handshake complete — stream reset pending\n");
        return;
    }

    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        ctx->tls_want_write = 0;
        return;   /* wait for more data from client */
    }

    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        /* tcp_write ran out of send-buffer space.  Mark the flag so
         * the main loop can call us again (with len=0) after the
         * next tcp_output drains the window. */
        ctx->tls_want_write = 1;
        return;
    }

    /* Fatal error */
    ctx->tls_want_write = 0;
    {
        char errbuf[80];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        serial_print("[TLS] Handshake failed: ");
        serial_print(errbuf);
        serial_print("\n");
    }

    if (ctx->pcb) { tcp_close(ctx->pcb); ctx->pcb = NULL; }
    ctx->state = STATE_CONNECTED;
    ctx->tls_established = 0;
}

/* ===========================================================================
 * xmpp_tls_decrypt
 *
 * Feeds raw encrypted bytes into the staging buffer and decrypts them into
 * ctx->rx_buffer for normal XMPP parsing.  Called from xmpp_recv_callback()
 * when ctx->tls_established == 1.
 *
 * Loops until all complete TLS records in the staging buffer are consumed.
 * =========================================================================== */
void xmpp_tls_decrypt(xmpp_client_ctx_t *ctx, const uint8_t *data, int len) {
    tls_staging_compact(ctx);

    int space = (int)sizeof(ctx->tls_rx_buf) - ctx->tls_rx_len;

    if (len > space) {
        serial_print("[TLS] ERROR: decrypt staging buffer overflow\n");

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

    /* Buffer must hold a full TLS record; sized to MBEDTLS_SSL_IN_CONTENT_LEN.
     * With IN_CONTENT_LEN=16384 this covers OMEMO bundles (~10 KB). */
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
                /* Decrypted data overflows rx_buffer — RFC 6120 §4.9.3.14 */
                serial_print("[TLS] rx_buffer overflow after decryption\n");

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
            /* TLS close_notify — clean shutdown */
            if (ctx->pcb) { 
                tcp_close(ctx->pcb); 
                
                ctx->pcb = NULL; 
            }
            
            return;
        }
        else if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            /* Fatal TLS error (e.g. record too large, bad MAC).
             * Close the connection so the client can reconnect cleanly.
             * Previously this path fell through silently, leaving the SSL
             * context broken and the TCP connection in a zombie state. */
            char errbuf[80];

            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            
            serial_print("[TLS] Fatal decrypt error: ");
            serial_print(errbuf);
            serial_print("\n");
            
            if (ctx->pcb) { 
                tcp_close(ctx->pcb); 
                
                ctx->pcb = NULL; 
            }

            ctx->tls_established = 0;
            
            return;
        }
        /* MBEDTLS_ERR_SSL_WANT_READ: no more complete records — exit loop */
    } while (ret > 0);

    tls_staging_compact(ctx);
}