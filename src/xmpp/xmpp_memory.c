#include "xmpp_core.h"
#include <string.h>
#include <stddef.h>

/* ------------------------------------------------------------------
 * Static stanza pool
 *
 * RFC 6120 does not mandate any particular memory model; this pool
 * replaces dynamic allocation (malloc/free) which is typically
 * unavailable or undesirable on embedded targets.
 *
 * Pool size (MAX_POOL_STANZAS = 16):
 *   In the worst case, one stanza per connected client can be in
 *   flight at once. With MAX_USERS = 10, a pool of 16 provides
 *   some headroom. If xmpp_alloc_stanza() returns NULL (pool
 *   exhausted), the caller (xmpp_recv_callback) should send:
 *     RFC 6120 §4.9.3.17 — <resource-constraint/> stream error
 *     and close the offending connection with tcp_close().
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-4.9.3.17
 * ------------------------------------------------------------------ */
#define MAX_POOL_STANZAS 16
static xmpp_stanza_t stanza_pool[MAX_POOL_STANZAS];

/* ------------------------------------------------------------------
 * xmpp_alloc_stanza
 *
 * Returns a zeroed, marked-in-use stanza from the pool, or NULL if
 * the pool is exhausted.
 *
 * Thread safety: not thread-safe. Acceptable on a single-core MCU
 * running lwIP in a cooperative (no-preemption) mode.
 *
 * On NULL return: the caller MUST send
 *   RFC 6120 §4.9.3.17 — <resource-constraint/> stream error
 *   and close the connection. See xmpp_recv_callback() in
 *   xmpp_server.c for the implemented handler.
 * ------------------------------------------------------------------ */
xmpp_stanza_t* xmpp_alloc_stanza() {
    for (int i = 0; i < MAX_POOL_STANZAS; i++) {
        if (stanza_pool[i].is_used == 0) {
            memset(&stanza_pool[i], 0, sizeof(xmpp_stanza_t));

            stanza_pool[i].is_used = 1;

            return &stanza_pool[i];
        }
    }
    /* Pool exhausted.
     * RFC 6120 §4.9.3.17 — caller must send <resource-constraint/>
     * stream error and close the offending connection. */
    return NULL;
}

/* ------------------------------------------------------------------
 * xmpp_free_stanza
 *
 * Returns a stanza to the pool by clearing is_used.
 * The caller (xmpp_recv_callback) is responsible for calling this
 * after every successful parse-and-dispatch cycle.
 * ------------------------------------------------------------------ */
void xmpp_free_stanza(xmpp_stanza_t *s) {
    if (s) {
        s->is_used = 0;
    }
}