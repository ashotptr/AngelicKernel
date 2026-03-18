#ifndef XMPP_CORE_H
#define XMPP_CORE_H

#include "lwip/tcp.h"
#include <stdio.h>
#include <string.h>

typedef enum {
    PARSE_INCOMPLETE,   // wait for more data — do nothing
    PARSE_NO_MEMORY,    // pool exhausted — send resource-constraint + close
} parse_null_reason_t;

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
 * RFC 6120 §4.7.1 — Server's <stream:stream> MUST set 'from' to its
 *   authoritative domain.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-4.7.1 */
#define XMPP_DOMAIN "angelic.local"
#define SERVER_JID(user) user "@" XMPP_DOMAIN

/* ------------------------------------------------------------------
 * Stanza types
 *
 * RFC 6120 §8    — XML Stanzas (parent section)
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8
 * RFC 6120 §8.2.3 — <iq>: type MUST be exactly one of get|set|result|error
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.3
 * RFC 6120 §8.2.1 — <message> semantics
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.1
 * RFC 6120 §8.2.2 — <presence> semantics
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-8.2.2
 * ------------------------------------------------------------------ */
typedef enum {
    XMPP_UNKNOWN = 0,              /* type attribute absent or unrecognised           */
    XMPP_IQ_GET,                   /* RFC 6120 §8.2.3 — type="get"                    */
    XMPP_IQ_SET,                   /* RFC 6120 §8.2.3 — type="set"                    */
    XMPP_IQ_RESULT,                /* RFC 6120 §8.2.3 — type="result"                 */
    XMPP_IQ_ERROR,                 /* RFC 6120 §8.2.3 — type="error"                  */
    XMPP_MESSAGE,                  /* RFC 6120 §8.2.1 — Message Semantics             */
    XMPP_PRESENCE,                 /* RFC 6120 §8.2.2 — available (no type attribute) */

    /* Presence subtypes — RFC 6121 §4.5, §3.1.3
     * These are separate enum values so routing code can use a single
     * stanza->type check rather than calling strstr() on raw XML.
     * The parser sets these from the 'type' attribute on <presence>.
     *   https://datatracker.ietf.org/doc/html/rfc6121#section-4.5
     *   https://datatracker.ietf.org/doc/html/rfc6121#section-3.1.3 */
    XMPP_PRESENCE_UNAVAILABLE,    /* RFC 6121 §4.5  — type="unavailable"              */
    XMPP_PRESENCE_SUBSCRIBE,      /* RFC 6121 §3.1.3 — type="subscribe"               */
    XMPP_PRESENCE_SUBSCRIBED,     /* RFC 6121 §3.1.3 — type="subscribed"              */
    XMPP_PRESENCE_UNSUBSCRIBE,    /* RFC 6121 §3.1.3 — type="unsubscribe"             */
    XMPP_PRESENCE_UNSUBSCRIBED    /* RFC 6121 §3.1.3 — type="unsubscribed"            */
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
 *     RFC 6120 §6.3.4 Mechanism Offers / §6.4.1 Exchange of Stream
 *     Headers and Features — advertising mechanisms in stream:features.
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6.4.1
 *     NOTE: currently set in handle_sasl() but not used as a
 *     min_state gate — consider enforcing it so SASL <auth> is only
 *     accepted before authentication, not after.
 *
 *   STATE_AUTHENTICATED
 *     <success/> sent; old stream is now dead.
 *     RFC 6120 §6.4.6 — SASL Success: "the initiating entity MUST
 *     initiate a new stream to the receiving entity."
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-6.4.6
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
 *     RFC 6120 §4.9.3.14 — <policy-violation/>
 *     https://datatracker.ietf.org/doc/html/rfc6120#section-4.9.3.14
 * ------------------------------------------------------------------ */
typedef struct {
    stanza_type_t type;
    char from[64];
    char to[64];
    char id[64];
    char xmlns[128];
    char payload[1024];
    /* mechanism — populated for <auth mechanism='...'> elements.
     * RFC 6120 §6.4.2 — client specifies the mechanism name in this
     * attribute. Used by handle_sasl() to validate that the requested
     * mechanism (PLAIN or ANONYMOUS) was actually offered.
     * RFC 6120 §6.5.7 — if the mechanism is not in the offered list,
     * server MUST respond with <failure><invalid-mechanism/></failure>.
     *   https://datatracker.ietf.org/doc/html/rfc6120#section-6.4.2 */
    char mechanism[32];
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
    /* creator_jid — the bare JID of the user who first created this room.
     * Set in handle_muc_presence() when is_new_room == 1.
     * Used by handle_muc_admin() to return an accurate owner in
     * affiliation list queries (XEP-0045 §9.5) instead of falling
     * back to the first active participant as a proxy.
     *   https://xmpp.org/extensions/xep-0045.html#modifymember */
    char creator_jid[64];
    /* semi_anon — room anonymity type.
     * XEP-0045 §7.2.3 — controls whether real JIDs are exposed in
     * <item jid='...'/> within MUC presence stanzas.
     *   1 (default) = semi-anonymous: real JIDs visible only to
     *     moderators and the room owner.  Regular participants see
     *     occupant JIDs only (room@service/nick).
     *   0 = non-anonymous: real JID visible to all occupants.
     * Rooms start as semi-anonymous.  A future room-config IQ
     * (XEP-0045 §10.2) can set this to 0.
     *   https://xmpp.org/extensions/xep-0045.html#enter-pres */
    int semi_anon;
    /* locked — XEP-0045 §10.1 locked-room state.
     *
     * A newly created room MUST be placed in the locked state immediately
     * after creation and MUST remain locked until the owner either:
     *   (a) submits a configuration form  (XEP-0045 §10.1.3), or
     *   (b) submits an instant-room request (XEP-0045 §10.1.2).
     *
     * While locked == 1, any user other than the room creator who sends
     * a join presence MUST receive:
     *   <presence type='error' from='room@service/nick' to='user'>
     *     <error type='cancel' code='404'>
     *       <item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>
     *     </error>
     *   </presence>
     *
     * The creator is identified by comparing the joining user's bare JID
     * against room_t.creator_jid (set at room creation time in
     * handle_muc_presence()).  The creator may re-enter the locked room
     * freely (e.g. after a reconnect) while the room is being configured.
     *
     * Unlocked (set to 0) by handle_muc_owner() when the owner submits
     * a config-form IQ-set or an instant-room IQ-set.
     *
     *   XEP-0045 §10.1   https://xmpp.org/extensions/xep-0045.html#createroom
     *   XEP-0045 §10.1.2 https://xmpp.org/extensions/xep-0045.html#createroom-instant
     *   XEP-0045 §10.1.3 https://xmpp.org/extensions/xep-0045.html#createroom-reserved */
    int locked;
    int active;
} room_t;

extern room_t rooms[MAX_ROOMS];

/* ------------------------------------------------------------------
 * Global client registry
 *
 * Exposes the flat pool of all connection contexts so that handlers
 * can iterate every connected client — required for RFC 6121 §4.2.2
 * presence broadcasting.
 *
 * client_registry[i].pcb == NULL  → slot is free / never used.
 * client_registry[i].state < STATE_SESSION → negotiation not complete;
 *   skip for presence delivery.
 *
 * Defined in xmpp_server.c; declared here for use in xmpp_handlers.c.
 * ------------------------------------------------------------------ */
extern xmpp_client_ctx_t client_registry[MAX_USERS];

/* ------------------------------------------------------------------
 * Function declarations
 * (See each .c file for per-function RFC annotations)
 * ------------------------------------------------------------------ */

/* xmpp_memory.c */
xmpp_stanza_t* xmpp_alloc_stanza();
void xmpp_free_stanza(xmpp_stanza_t *s);

/* xmpp_parser.c */
xmpp_stanza_t* parse_xml_stream(char *payload, int len, int *bytes_consumed, parse_null_reason_t *reason);

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
    /* XEP-0045 §7.2  — Entering a Room (presence protocol)
     * XEP-0045 §7.14 — Exiting a Room (type='unavailable')
     * https://xmpp.org/extensions/xep-0045.html#enter
     * https://xmpp.org/extensions/xep-0045.html#exit */

void handle_chat_message(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* RFC 6121 §5   — Exchanging Messages
     * XEP-0045 §7.9 — Sending a message to a room (type='groupchat')
     * https://datatracker.ietf.org/doc/html/rfc6121#section-5
     * https://xmpp.org/extensions/xep-0045.html#message */

void handle_sasl(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* RFC 6120 §6   — SASL negotiation (top-level)
     * RFC 6120 §6.4 — SASL Process
     * https://datatracker.ietf.org/doc/html/rfc6120#section-6 */

void handle_broadcast_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* RFC 6121 §4.2 — Broadcasting presence to contacts
     * https://datatracker.ietf.org/doc/html/rfc6121#section-4.2 */

void handle_roster_request(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
    /* RFC 6121 §2.1   — Roster Management
     * RFC 6121 §2.1.5 — Roster Set
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

/* xmpp_server.c — TCP network layer */
err_t xmpp_recv_callback(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
err_t xmpp_accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err);
void xmpp_init_server();

/* libc_glue.c — cryptographically unpredictable random word.
 * Use this (never rand()) for stream IDs and resource IDs.
 * RFC 6120 §4.7.3 — stream 'id' MUST be hard to predict.
 * RFC 6120 §7.7.1 — server-generated resource IDs (same requirement). */
extern unsigned int secure_random_u32(void);

/* ------------------------------------------------------------------
 * Compile-time credential table
 *
 * RFC 6120 §6.5 — SASL <not-authorized/>: server MUST send this failure
 *   condition when provided credentials do not match any known account.
 *   https://datatracker.ietf.org/doc/html/rfc6120#section-6.5
 *
 * RFC 4616 §2 — PLAIN mechanism: credentials travel in cleartext.
 *   MUST only be used over a TLS-protected stream in production.
 *   Acceptable here for a trusted, closed LAN.
 *   https://datatracker.ietf.org/doc/html/rfc4616#section-2
 *
 * ANONYMOUS mechanism bypasses credential verification entirely per
 * RFC 4505; entries here only apply to SASL PLAIN logins.
 *
 * Usage: change entries and recompile to update the user list.
 * ------------------------------------------------------------------ */
typedef struct {
    char username[32];
    char password[64];
} xmpp_credential_t;

/* Defined in xmpp_handlers.c; declared here for shared visibility. */
extern const xmpp_credential_t xmpp_credentials[];
extern const int xmpp_credential_count;

/* ------------------------------------------------------------------
 * xmpp_store.c / xmpp_persist.c — shared store types & declarations
 *
 * Keeping types here avoids circular includes between xmpp_store.c,
 * xmpp_handlers.c, and xmpp_persist.c.
 * ------------------------------------------------------------------ */

/* ---- XEP-0049 Private XML Storage (defined in xmpp_handlers.c) -- */
#define PRIVATE_STORAGE_SLOTS 20
#define PRIVATE_NS_MAX 128   /* must match xmpp_stanza_t.xmlns  */
#define PRIVATE_XML_MAX 900   /* conservative inner-xml ceiling   */

typedef struct {
    char username[32];
    char ns[PRIVATE_NS_MAX];
    char xml[PRIVATE_XML_MAX];
    int active;
} private_store_entry_t;

/* Defined in xmpp_handlers.c; non-static so xmpp_persist.c can save it. */
extern private_store_entry_t private_store[PRIVATE_STORAGE_SLOTS];

/* ---- RFC 6121 Roster Store (defined in xmpp_store.c) ------------ */
#define MAX_ROSTER_ENTRIES 80
#define ROSTER_ITEM_MAX_LEN 256

typedef struct {
    char username[32];
    char jid[64];
    char item_xml[ROSTER_ITEM_MAX_LEN];
    int active;
} roster_entry_t;

/* Defined in xmpp_store.c; non-static so xmpp_persist.c can save it. */
extern roster_entry_t roster_store[MAX_ROSTER_ENTRIES];

/* ------------------------------------------------------------------
 * xmpp_persist.c — ATA disk persistence for XMPP stores
 *
 * Replaces EFI NVRAM with direct ATA PIO sector I/O to a dedicated
 * raw data disk (data.img, IDE slave, primary channel 0x1F0).
 * Works after ExitBootServices — no UEFI protocols required.
 *
 * Disk layout on data.img (1 MB, ATA_DATA_DRIVE = slave):
 *   LBA  0       : persist_header_t (magic 0xA6E71C3D + CRC32)
 *   LBA  1..42   : private_store[]  (XEP-0049)
 *   LBA 43..98   : roster_store[]   (RFC 6121)
 *   LBA 99..2047 : reserved
 *
 * xmpp_persist_load_all     — called once from xmpp_init_server().
 * xmpp_persist_save_private — write-through after every XEP-0049 set.
 * xmpp_persist_save_roster  — write-through after every roster change.
 * xmpp_persist_save_rooms   — called after room created or configured.
 * ------------------------------------------------------------------ */
void xmpp_persist_load_all();
void xmpp_persist_save_private();
void xmpp_persist_save_roster();
void xmpp_persist_save_rooms();

/* ------------------------------------------------------------------
 * xmpp_store.c — in-memory stores (offline queue + roster)
 * ------------------------------------------------------------------ */

/* XEP-0160 Offline Message Queue */
int offline_msg_enqueue(const char *to_bare, const char *from_jid, const char *msg_id,  const char *payload);
void offline_msg_drain(xmpp_client_ctx_t *ctx);
int offline_msg_is_full(const char *to_user);

/* RFC 6121 §2 Roster Store */
int roster_store_upsert_item (const char *username, const char *item_xml);
void roster_store_set_from_payload(const char *username, const char *payload);
int roster_store_get_items (const char *username, char *buf, int buf_len);

#endif