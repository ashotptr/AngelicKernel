/* ===========================================================================
 * INTEGRATION GUIDE: How to wire the new files into the build
 *
 * This file is NOT compiled directly. It is a reference for the developer
 * showing exactly which lines to change in the existing source files to
 * complete the Capstone missing pieces.
 * ===========================================================================
 *
 * ── 1. Makefile ─────────────────────────────────────────────────────────────
 *
 * Add to OBJS list (after src/xmpp/xmpp_tls.o):
 *
 *   src/xmpp/mpk_benchmark.o \
 *   src/xmpp/xmpp_sm.o \
 *
 *
 * ── 2. xmpp_core.h ──────────────────────────────────────────────────────────
 *
 * Add to xmpp_client_ctx_t struct (after tls_established):
 *
 *   // XEP-0198 Stream Management state (xmpp_sm.c)
 *   int      sm_enabled;         // 1 after <enable/> processed
 *   uint32_t sm_inbound_h;       // stanzas received from client (acked count)
 *   uint32_t sm_outbound_count;  // stanzas sent to client (triggers <r/>)
 *
 *
 * Add declarations after existing "xmpp_persist.c" block:
 *
 *   // xmpp_sm.c — XEP-0198 Stream Management
 *   void xmpp_sm_send_enabled(xmpp_client_ctx_t *ctx);
 *   void xmpp_sm_send_ack(xmpp_client_ctx_t *ctx);
 *   void xmpp_sm_request_ack(xmpp_client_ctx_t *ctx);
 *   void xmpp_sm_on_stanza_received(xmpp_client_ctx_t *ctx);
 *   void xmpp_sm_on_stanza_sent(xmpp_client_ctx_t *ctx);
 *   int  xmpp_sm_handle_element(xmpp_client_ctx_t *ctx);
 *
 *   // mpk_benchmark.c — WRPKRU cycle-count micro-benchmark
 *   void mpk_benchmark(void);
 *
 *
 * ── 3. kernel.c ─────────────────────────────────────────────────────────────
 *
 * Add declaration near top:
 *   extern void mpk_benchmark(void);
 *
 * Add call after mpk_diagnostic():
 *   mpk_benchmark();   // Capstone §9.2 — WRPKRU cycle count
 *
 *
 * ── 4. xmpp_server.c: handle_handshake_logic() ──────────────────────────────
 *
 * In the "post-auth" branch (ctx->authenticated), add <sm> to stream features:
 *
 *   snprintf(response, sizeof(response),
 *     "<?xml version='1.0'?>"
 *     "<stream:stream ...>"
 *     "<stream:features>"
 *       "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>"
 *       "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>"
 *       // ADD THIS LINE:
 *       "<sm xmlns='urn:xmpp:sm:3'/>"
 *     "</stream:features>",
 *     ...);
 *
 *
 * ── 5. xmpp_server.c: xmpp_recv_callback() ──────────────────────────────────
 *
 * In the main while(ctx->rx_pos > 0) loop, BEFORE the stanza parse call,
 * add the SM element handler:
 *
 *   // Handle XEP-0198 SM elements before stanza parsing
 *   if (ctx->state >= STATE_AUTHENTICATED) {
 *       if (xmpp_sm_handle_element(ctx)) {
 *           continue;  // SM element consumed; restart loop
 *       }
 *   }
 *
 * After the stanza is successfully dispatched (after xmpp_route_stanza),
 * increment the SM inbound counter:
 *
 *   xmpp_sm_on_stanza_received(ctx);
 *
 *
 * ── 6. xmpp_handlers.c: send_raw() ──────────────────────────────────────────
 *
 * At the END of send_raw() (after all tcp_write/mbedtls_ssl_write calls):
 *
 *   // XEP-0198: track outbound stanzas and periodically request ack
 *   xmpp_sm_on_stanza_sent(ctx);
 *
 *
 * ── 7. Makefile (OBJS already shown above) + run.sh ─────────────────────────
 *
 * No changes to run.sh needed. The new .c files compile with the same flags.
 *
 *
 * ── 8. testing/benchmarks/ ─────────────────────────────────────────────────
 *
 * New files (no changes to existing files needed):
 *   testing/benchmarks/boot_time_measure.py   — boot time metric
 *   testing/benchmarks/tsung_angelic.xml      — Tsung load scenario
 *   testing/benchmarks/prosody_baseline.sh    — Prosody Docker baseline
 *
 *
 * ── 9. testing/slixmpp_tests/slixmpp_suite.py ──────────────────────────────
 *
 * Replace entirely with the fixed version (removes disable_starttls kwarg,
 * handles modern slixmpp API, uses permissive SSL context for self-signed cert).
 *
 * ===========================================================================
 */
