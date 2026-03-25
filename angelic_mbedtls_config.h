/* ===========================================================================
 * angelic_mbedtls_config.h — AngelicKernel XMPP STARTTLS configuration
 *
 * WHY THIS NAME:
 *   build_info.h lives in mbedtls/include/mbedtls/.  GCC resolves
 *   #include "file" by searching the including file's directory first.
 *   A file named mbedtls_config.h would collide with the DEFAULT config at
 *   mbedtls/include/mbedtls/mbedtls_config.h, causing the full default
 *   config to be silently used instead of ours.  The unique name prevents
 *   this: GCC finds nothing in that directory, then searches -I. and finds
 *   our file at the project root.
 *
 * Injected into every mbedTLS translation unit via:
 *   -DMBEDTLS_CONFIG_FILE='"angelic_mbedtls_config.h"'
 *
 * TARGET CONSTRAINTS (all firm, post-ExitBootServices):
 *   • No POSIX/libc heap  — calloc/free replaced by mbedTLS buffer allocator
 *   • No time() / gmtime() — wall clock unavailable; cert expiry not checked
 *   • No filesystem       — all key/cert material generated in memory
 *   • No sockets (POSIX)  — networking via lwIP callbacks (tls_net_send/recv)
 *   • No SSE/AVX          — Makefile passes -mno-sse -mno-avx (EFI constraint)
 *   • No threading        — cooperative lwIP scheduler; one TCP callback at a time
 *   • No PSA crypto       — TLS 1.2 classic API only; PSA adds ~100 KB overhead
 *
 * TARGETS mbedTLS 3.2+.  check_config.h is included automatically (since 3.0).
 * =========================================================================== */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* ===========================================================================
 * PLATFORM LAYER
 * =========================================================================== */

/* Enable platform abstraction so we can hook calloc/free/printf/snprintf. */
#define MBEDTLS_PLATFORM_C

/* Allow overriding calloc/free.  Required by MBEDTLS_MEMORY_BUFFER_ALLOC_C. */
#define MBEDTLS_PLATFORM_MEMORY

/* Do NOT fall back to libc calloc/free even as defaults.
 *
 * Critical reason: gnu-efi provides calloc/free backed by EFI AllocatePool,
 * which is invalid after ExitBootServices.  Without this flag, platform.c
 * would initialise mbedtls_calloc/mbedtls_free to the gnu-efi versions before
 * our mbedtls_memory_buffer_alloc_init() call has a chance to override them.
 * Any allocation that happens in static initialisers would corrupt memory.
 * With this flag the defaults are null; mbedtls_memory_buffer_alloc_init()
 * installs the real function pointers before any allocation occurs. */
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS

/* Redirect mbedTLS-internal printf/snprintf to the gnu-efi implementations.
 *
 * Without MBEDTLS_DEBUG_C or MBEDTLS_SELF_TEST (both disabled below), the
 * only mbedTLS internal caller of snprintf is error.c (mbedtls_strerror),
 * which we use for serial diagnostics in xmpp_tls.c.  Mapping directly to
 * the gnu-efi symbols satisfies the linker at zero cost. */
#define MBEDTLS_PLATFORM_PRINTF_MACRO   printf
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO snprintf

/* ===========================================================================
 * STATIC BUFFER ALLOCATOR
 *
 * mbedTLS ships its own production-grade static-buffer allocator in
 * memory_buffer_alloc.c.  Enabling this and calling:
 *   mbedtls_memory_buffer_alloc_init(buf, size)
 * at startup automatically registers its own calloc/free hooks — no separate
 * mbedtls_platform_set_calloc_free() call is needed.  The allocator handles
 * free-block coalescing and is well-tested across embedded targets.
 *
 * The backing buffer is declared in xmpp_tls.c as:
 *   static uint8_t tls_pool[TLS_POOL_SIZE] __attribute__((aligned(8)));
 * and passed to mbedtls_memory_buffer_alloc_init() as the very first call
 * inside xmpp_tls_server_init(), before any other mbedTLS function runs.
 *
 * Sizing (MBEDTLS_SSL_IN/OUT_CONTENT_LEN = 4096):
 *   Per-session I/O buffers : 2 x ~4300 B  = 8.6 KB
 *   Handshake ephemeral     : ~2 KB
 *   10 sessions             : 10 x 10.6 KB = 106 KB
 *   Shared cert / key / cfg : ~4 KB
 *   TLS_POOL_SIZE           : 160 KB  (comfortable margin)
 * =========================================================================== */
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C

/* ===========================================================================
 * EXPLICITLY DISABLED — with reasons
 * =========================================================================== */

/* time() is used by SSL session cache, session tickets, DTLS hello cookies.
 * None of these features are enabled.  time() does not exist post-ExitBootServices.
 * Explicitly undef'd so platform.c does not emit a reference to the symbol. */
#undef MBEDTLS_HAVE_TIME

/* gmtime() is used by x509.c to validate NotBefore/NotAfter against the wall
 * clock.  No wall clock exists post-ExitBootServices.  Without this undef,
 * loading our self-signed cert would call gmtime(NULL) and either crash or
 * mark the cert as expired — a real runtime bug. */
#undef MBEDTLS_HAVE_TIME_DATE

/* fopen/fread/fwrite used across x509 parse, pkparse, entropy, bignum, dhm.
 * No filesystem exists post-ExitBootServices; all material is in-memory. */
#undef MBEDTLS_FS_IO

/* POSIX socket layer — not used.  lwIP I/O callbacks replace it entirely.
 * net_sockets.c must not be compiled (already absent from Makefile SRCS). */
#undef MBEDTLS_NET_C

/* Timing module — uses gettimeofday(), alarm(), signal().
 * None exist post-ExitBootServices.  timing.c must not be compiled. */
#undef MBEDTLS_TIMING_C

/* Self-tests — pull in rand() (via rsa.c self-test).  rand() does not exist.
 * Self-tests are never executed in the unikernel runtime. */
#undef MBEDTLS_SELF_TEST

/* Debug module — uses fprintf(FILE*, ...).  FILE* does not exist
 * post-ExitBootServices.  debug.c must not be compiled or linked. */
#undef MBEDTLS_DEBUG_C

/* Session tickets / session cache — require time() for key rotation and expiry.
 * XMPP clients do full handshakes; resumption is not needed.
 * Disabling reduces code size and eliminates the time() dependency. */
#undef MBEDTLS_SSL_SESSION_TICKETS
#undef MBEDTLS_SSL_CACHE_C

/* ===========================================================================
 * ENTROPY / DRBG
 *
 * tls_entropy_func() in xmpp_tls.c wraps secure_random_u32() and is passed
 * directly to mbedtls_ctr_drbg_seed() as f_entropy.  The standard entropy
 * module reads /dev/urandom or platform-specific HW — neither is available.
 * =========================================================================== */
#define MBEDTLS_CTR_DRBG_C
/* MBEDTLS_ENTROPY_C intentionally left undefined */

/* ===========================================================================
 * BIG-NUMBER ARITHMETIC
 * =========================================================================== */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_HAVE_INT64   /* 64-bit platform; avoids double-word emulation */

/* ===========================================================================
 * ELLIPTIC-CURVE CRYPTOGRAPHY
 * =========================================================================== */
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED   /* P-256 for key and certificate   */
#define MBEDTLS_ECDH_C                     /* ECDHE key exchange               */
#define MBEDTLS_ECDSA_C                    /* ECDSA signatures                 */

/* MBEDTLS_ECP_RESTARTABLE intentionally NOT defined.
 *
 * The mbedTLS documentation states: "The restartable SSL feature is supported
 * for TLS client only."  This is a TLS server.  Defining the flag would add
 * code and state to every ECP operation with zero benefit on the server
 * handshake path.  The one-time mbedtls_ecp_gen_key() at startup blocks for
 * <100 ms, which is acceptable since connections are not yet being accepted. */

/* No hardware acceleration.
 * The EFI environment has the vector unit disabled until the kernel enables it.
 * Makefile already passes -mno-sse -mno-avx; these undef's prevent mbedTLS
 * from emitting AES-NI intrinsics that would fault on first execution. */
#undef MBEDTLS_AESNI_C
#undef MBEDTLS_HAVE_SSE2

/* ===========================================================================
 * SYMMETRIC CRYPTO
 * =========================================================================== */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_GCM

/* ===========================================================================
 * MESSAGE DIGEST
 * =========================================================================== */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA1_C     /* OID mapping in x509 / oid modules              */
#define MBEDTLS_SHA256_C   /* PRF + certificate signature                    */
#define MBEDTLS_SHA512_C   /* AES-256-GCM-SHA384 ciphersuite                 */

/* ===========================================================================
 * ASN.1 / OID
 * =========================================================================== */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C

/* ===========================================================================
 * PUBLIC KEY LAYER
 * =========================================================================== */
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C   /* required by MBEDTLS_X509_USE_C (check_config.h) */
#define MBEDTLS_PK_WRITE_C

/* ===========================================================================
 * X.509 CERTIFICATE HANDLING
 * =========================================================================== */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CRT_WRITE_C
#define MBEDTLS_BASE64_C       /* needed by pkparse.c even when using DER    */
#define MBEDTLS_PEM_PARSE_C

/* ===========================================================================
 * SSL / TLS
 * =========================================================================== */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_SRV_C              /* server-side handshake only          */
#define MBEDTLS_SSL_PROTO_TLS1_2       /* TLS 1.3 requires PSA — not used     */
/* MBEDTLS_SSL_CLI_C intentionally undefined — server only                    */
/* MBEDTLS_SSL_PROTO_TLS1_3 intentionally undefined — requires PSA crypto     */

#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/* Two AEAD suites — covers every modern XMPP client.
 * Explicit list shrinks ssl_ciphersuites.c considerably. */
#define MBEDTLS_SSL_CIPHERSUITES \
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, \
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

/* ===========================================================================
 * RECORD / BUFFER SIZING  (mbedTLS 3.x split-direction form)
 * =========================================================================== */
#define MBEDTLS_SSL_IN_CONTENT_LEN   16384   /* TLS max; required for OMEMO bundles */
#define MBEDTLS_SSL_OUT_CONTENT_LEN   4096   /* server stanzas always < 4 KB        */

/* ===========================================================================
 * MISCELLANEOUS
 * =========================================================================== */
#define MBEDTLS_ERROR_C         /* mbedtls_strerror() used in xmpp_tls.c     */
#define MBEDTLS_CONSTANT_TIME_C /* required internally by ssl_msg.c in 3.x   */

/* ===========================================================================
 * EXPLICIT DISABLES — prevent config_adjust_ssl.h from auto-enabling these
 *
 * mbedTLS 3.6 ships config_adjust_*.h files that are included AFTER the
 * custom config.  They add dependencies based on what is enabled.  We
 * pre-emptively undef the things we never want so even if the adjustments
 * try to enable them, they remain off at the point that matters.
 *
 * Note: #undef here runs before config_adjust, so the adjustments CAN
 * re-enable things.  For truly unwanted modules we rely on the fact that
 * none of our enabled features pull them in as a hard dependency.
 * =========================================================================== */

/* TLS 1.3 — requires PSA crypto which we don't use */
#undef MBEDTLS_SSL_PROTO_TLS1_3
#undef MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE

/* Client-side handshake — we are a server only */
#undef MBEDTLS_SSL_CLI_C

/* PSA crypto — not used; TLS 1.2 classic API is sufficient */
#undef MBEDTLS_USE_PSA_CRYPTO
#undef MBEDTLS_PSA_CRYPTO_C
#undef MBEDTLS_PSA_CRYPTO_CONFIG

/* ===========================================================================
 * INTERNAL FLAGS
 *
 * These are normally set by config_adjust_legacy_crypto.h based on the
 * user-visible defines above.  We set them explicitly here because
 * pk_ecc.c in mbedTLS 3.6.4 guards mbedtls_eckey_info / mbedtls_eckeydh_info
 * under MBEDTLS_ECP_LIGHT, and mbedtls_pk_info_from_type in pk.c references
 * them under the same guard.  Without an explicit define they can end up
 * undefined at link time if the config_adjust include chain resolves them
 * differently across translation units.
 * =========================================================================== */
#define MBEDTLS_ECP_LIGHT        /* set by ECP_C — required by pk_ecc.c      */
#define MBEDTLS_PK_HAVE_ECC_KEYS /* set by ECP_LIGHT — required by pk_ecc.c  */

#endif /* MBEDTLS_CONFIG_H */