#ifndef XMPP_CORE_H
#define XMPP_CORE_H

#include "lwip/tcp.h"
#include <stdio.h>
#include <string.h>

/* ============================================================
 * XMPP CORE — shared types, constants, and declarations
 *
 * Governing documents:
 *   RFC 6120  XMPP Core
 *     https://datatracker.ietf.org/doc/html/rfc6120
 *   RFC 6121  XMPP Instant Messaging
 *     https://datatracker.ietf.org/doc/html/rfc6121
 *   XEP-0045  Multi-User Chat
 *     https://xmpp.org/extensions/xep-0045.html
 * ============================================================ */

/* MUC limits — implementation-defined.
 * XEP-0045 §6 (Service Requirements) sets no numeric caps;
 * these values are ours. */
#define MAX_ROOMS 4
#define MAX_USERS_PER_ROOM 8
#define MAX_NICK_LEN 32
#define MAX_ROOM_NAME_LEN 32
#define MAX_USERS 10

/* Domain used as the server's authoritative domain in JIDs and the
 * stream 'from' attribute.
 *
 * RFC 6120 §2.1   — JID syntax: [localpart "@"] domainpart ["/" resourcepart]
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-2.1
 * RFC 6120 §4.7.2 — Server's <stream:stream> MUST set 'from' to its
 *   authoritative domain.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-4.7.2 */
#define XMPP_DOMAIN "angelic.local"
#define SERVER_JID(user) user "@" XMPP_DOMAIN

/* ------------------------------------------------------------------
 * Stanza types
 *
 * RFC 6120 §8   — XML Stanzas
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8
 * RFC 6120 §8.2 — <iq>: type MUST be exactly one of get|set|result|error
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.2
 * RFC 6120 §8.4 — <message>
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.4
 * RFC 6120 §8.5 — <presence>
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.5
 * ------------------------------------------------------------------ */
typedef enum {
    XMPP_UNKNOWN = 0,  /* type attribute absent or unrecognised      */
    XMPP_IQ_GET,        /* RFC 6120 §8.2.1 — type="get"    */
    XMPP_IQ_SET,        /* RFC 6120 §8.2.1 — type="set"    */
    XMPP_IQ_RESULT,     /* RFC 6120 §8.2.1 — type="result" */
    XMPP_IQ_ERROR,      /* RFC 6120 §8.2.1 — type="error"  */
    XMPP_MESSAGE,       /* RFC 6120 §8.4                    */
    XMPP_PRESENCE       /* RFC 6120 §8.5                    */
} stanza_type_t;

/* ------------------------------------------------------------------
 * Client connection state machine
 *
 * RFC 6120 §4 defines the mandatory stream negotiation order.
 * No stanza exchange is valid until all preceding stages complete.
 *
 *   STATE_CONNECTED
 *     TCP accepted; no XML exchanged yet.
 *     RFC 6120 §4.2 step 1 — client opens stream
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-4.2
 *
 *   STATE_SASL
 *     Server sent <stream:features> with SASL mechanisms.
 *     RFC 6120 §6.3.4 — advertising mechanisms
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6.3
 *     NOTE: currently set in handle_sasl() but not used as a
 *     min_state gate — consider enforcing it so SASL <auth> is only
 *     accepted before authentication, not after.
 *
 *   STATE_AUTHENTICATED
 *     <success/> sent; old stream is now dead.
 *     RFC 6120 §6.3.6 step 4 — "the initiating entity MUST initiate
 *     a new stream to the receiving entity."
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6.3.6
 *
 *   STATE_BIND
 *     Client opened new stream; server offered <bind> feature.
 *     RFC 6120 §7 — Resource Binding
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-7
 *     NOTE: not currently a distinct gate in the router (unused).
 *
 *   STATE_SESSION
 *     Bind complete. Client may send the optional <session> IQ.
 *     RFC 6121 §3.1 — Session Establishment (now optional per RFC 6121
 *     §3.1 and its errata; many clients still send it).
 *     https://datatracker.ietf.org/doc/html/rfc6121#section-3.1
 *     All normal stanza exchange is gated behind this state.
 *
 *   STATE_READY
 *     Full session established. Currently unused; STATE_SESSION
 *     serves as the final gate.
 * ------------------------------------------------------------------ */
typedef enum {
    STATE_CONNECTED,
    STATE_SASL,
    STATE_AUTHENTICATED,
    STATE_BIND,
    STATE_SESSION,
    STATE_READY
} client_state_t;

/* ------------------------------------------------------------------
 * Parsed XMPP stanza (one unit of protocol exchange)
 *
 * RFC 6120 §8.1  — Common attributes present on all stanza kinds:
 *   'to'       §8.1.1 — destination JID (bare or full)
 *   'from'     §8.1.2 — sender JID; server SHOULD stamp this on
 *                       outbound stanzas to prevent spoofing
 *   'id'       §8.1.3 — opaque token; MUST be echoed in result/error
 *   'type'     §8.1.4 — stanza-specific (see stanza_type_t above)
 *   'xml:lang' §8.1.5 — BCP47 language tag (not stored; extend if needed)
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.1
 *
 * 'xmlns' is stored here as the namespace URI of the primary child
 * element; it is not a stanza-level attribute in the RFC but drives
 * our routing table in xmpp_router.c.
 *
 * SIZING NOTE — payload[1024] and xmlns[128]:
 *   RFC 6120 defines no maximum stanza size. A full roster response
 *   (RFC 6121 §2.1.4) or a Data Forms payload (XEP-0004) used during
 *   room configuration (XEP-0045 §10.2) can easily exceed 1 KB and
 *   will be silently truncated.
 *   To enforce a server-side limit, send a stream error:
 *     RFC 6120 §4.9.3.20 — <policy-violation/>
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-4.9.3.20
 * ------------------------------------------------------------------ */
typedef struct {
    stanza_type_t type;
    char from[64];
    char to[64];
    char id[64];
    char xmlns[128];
    char payload[1024];
    int is_used;
} xmpp_stanza_t;

/* ------------------------------------------------------------------
 * Per-client connection context
 *
 * full_jid  — populated by handle_core_bind().
 *             RFC 6120 §7.7 — After successful bind, the server MUST
 *             return the full JID in the <bind> result; the client
 *             MUST use that exact JID for subsequent stanzas.
 *             Format per RFC 6120 §2.1: localpart@domainpart/resourcepart
 *             https://datatracker.ietf.org/doc/html/rfc6120#section-7.7
 *
 * rx_buffer — byte-level accumulation buffer.
 *             RFC 6120 §4.1 — An XML stream is a single long-lived XML
 *             document at the TCP level; there is no per-stanza framing.
 *             https://datatracker.ietf.org/doc/html/rfc6120#section-4.1
 * ------------------------------------------------------------------ */
typedef struct {
    struct tcp_pcb *pcb;
    client_state_t state;
    char full_jid[64];
    char username[32];
    int authenticated;
    char rx_buffer[16384];
    int rx_pos;
} xmpp_client_ctx_t;

/* ------------------------------------------------------------------
 * MUC participant and room structures
 *
 * XEP-0045 §4   — Architecture: a MUC service hosts rooms; each room
 *   has occupants identified by occupant JID = room@service/nick
 *   https://xmpp.org/extensions/xep-0045.html#arch
 * XEP-0045 §7.2 — Entering a room: server sends presence from each
 *   current occupant to the new one, including a <x> with status.
 *   https://xmpp.org/extensions/xep-0045.html#enter-pres
 * XEP-0045 §7.2.3 — Nick/JID association: real JID exposed to
 *   moderators/admins; hidden from regular members by default.
 *   https://xmpp.org/extensions/xep-0045.html#enter-pres
 * ------------------------------------------------------------------ */
typedef struct {
    struct tcp_pcb *pcb;
    char nick[MAX_NICK_LEN];
    char jid[64];   /* real (bare) JID of the occupant */
    int active;
} participant_t;

typedef struct {
    char name[MAX_ROOM_NAME_LEN];
    participant_t users[MAX_USERS_PER_ROOM];
    int active;
} room_t;

extern room_t rooms[MAX_ROOMS];

/* ------------------------------------------------------------------
 * Function declarations
 * (See each .c file for per-function RFC annotations)
 * ------------------------------------------------------------------ */

/* xmpp_memory.c */
xmpp_stanza_t* xmpp_alloc_stanza();
void xmpp_free_stanza(xmpp_stanza_t *s);

/* xmpp_parser.c */
xmpp_stanza_t* parse_xml_stream(char *payload, int len, int *bytes_consumed);

/* xmpp_router.c */
void xmpp_route_stanza(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

/* xmpp_handlers.c ------------------------------------------------- */
void handle_core_bind(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* RFC 6120 §7.6 — Bind IQ exchange
     * https://datatracker.ietf.org/doc/html/rfc6120#section-7.6 */

void handle_core_session(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* RFC 6121 §3.1 — Session Establishment (optional/legacy)
     * https://datatracker.ietf.org/doc/html/rfc6121#section-3.1 */

void handle_muc_owner(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* XEP-0045 §10  — Owner Use Cases
     * https://xmpp.org/extensions/xep-0045.html#createroom */

void handle_disco_info(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* XEP-0045 §6.2 — Discovering Features (disco#info)
     * https://xmpp.org/extensions/xep-0045.html#disco-service */

void handle_disco_items(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* XEP-0045 §6.3 — Discovering Rooms (disco#items)
     * https://xmpp.org/extensions/xep-0045.html#disco-rooms */

void handle_muc_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* XEP-0045 §7.1 / §7.14 — Entering and leaving a room
     * https://xmpp.org/extensions/xep-0045.html#enter
     * https://xmpp.org/extensions/xep-0045.html#exit */

void handle_chat_message(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* RFC 6121 §5   — Exchanging Messages
     * XEP-0045 §7.9 — Sending a message to a room (type='groupchat')
     * https://datatracker.ietf.org/doc/html/rfc6121#section-5
     * https://xmpp.org/extensions/xep-0045.html#message */

void handle_sasl(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* RFC 6120 §6.3 — SASL negotiation
     * https://datatracker.ietf.org/doc/html/rfc6120#section-6.3 */

void handle_broadcast_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* RFC 6121 §4.2 — Broadcasting presence to contacts
     * https://datatracker.ietf.org/doc/html/rfc6121#section-4.2 */

void handle_roster_request(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* RFC 6121 §2.1 — Roster Get / §2.3 — Roster Set
     * https://datatracker.ietf.org/doc/html/rfc6121#section-2 */

void handle_initial_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* RFC 6121 §4.2 — Initial presence broadcast
     * https://datatracker.ietf.org/doc/html/rfc6121#section-4.2 */

void handle_private_storage(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* XEP-0049 — Private XML Storage
     * https://xmpp.org/extensions/xep-0049.html */

void handle_muc_admin(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* XEP-0045 §9 — Admin Use Cases (kick, ban, role/affiliation changes)
     * https://xmpp.org/extensions/xep-0045.html#admin */

void handle_general_success(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* Catch-all: returns empty <iq type='result'/> for benign unknown IQs.
     * RFC 6120 §8.2.3 — server MUST reply to every IQ get/set. */

void xmpp_log(const char *direction, const char *data, int len);
void send_raw(xmpp_client_ctx_t *ctx, const char *data);

extern int rand(void);

#endif