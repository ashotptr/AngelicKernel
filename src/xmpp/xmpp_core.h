#ifndef XMPP_CORE_H
#define XMPP_CORE_H

#include "lwip/tcp.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "mbedtls/ssl.h"

typedef enum {
    PARSE_INCOMPLETE,
    PARSE_NO_MEMORY,
} parse_null_reason_t;

#define MAX_ROOMS 4
#define MAX_USERS_PER_ROOM 8
#define MAX_NICK_LEN 32
#define MAX_ROOM_NAME_LEN 32
#define MAX_USERS 20

#define MAX_BANNED_PER_ROOM 8

#define TLS_RX_BUF_SIZE 32768

#define XMPP_DOMAIN "angelic.local"
#define SERVER_JID(user) user "@" XMPP_DOMAIN

#define SASL_MAX_FAILURES 5

typedef enum {
    XMPP_UNKNOWN = 0,
    XMPP_IQ_GET,
    XMPP_IQ_SET,
    XMPP_IQ_RESULT,
    XMPP_IQ_ERROR,
    XMPP_MESSAGE,
    XMPP_PRESENCE,
    XMPP_PRESENCE_UNAVAILABLE,
    XMPP_PRESENCE_SUBSCRIBE,
    XMPP_PRESENCE_SUBSCRIBED,
    XMPP_PRESENCE_UNSUBSCRIBE,
    XMPP_PRESENCE_UNSUBSCRIBED,
    XMPP_PRESENCE_PROBE
} stanza_type_t;

typedef enum {
    STATE_CONNECTED,
    STATE_STARTTLS,
    STATE_SASL,
    STATE_AUTHENTICATED,
    STATE_BIND,
    STATE_SESSION,
    STATE_READY
} client_state_t;

typedef struct {
    stanza_type_t type;
    char from[64];
    char to[64];
    char id[64];
    char xmlns[128];
    char payload[4096];
    char mechanism[32];
    int is_used;
} xmpp_stanza_t;

typedef struct {
    struct tcp_pcb *pcb;
    client_state_t state;
    char full_jid[64];
    char username[32];
    int authenticated;
    char rx_buffer[32768];
    int rx_pos;

    char client_from[64];
    char presence_payload[1024];
    int sasl_failures;
    mbedtls_ssl_context tls_ssl;
    uint8_t tls_rx_buf[TLS_RX_BUF_SIZE];
    int tls_rx_len;
    int tls_rx_pos;
    int tls_established;
    int tls_initialised;
    int tls_want_write;
    
    int initial_presence_sent;
    int sm_enabled;
    int sm_want_ack;
    uint32_t sm_inbound_h;
    uint32_t sm_outbound_count;
} xmpp_client_ctx_t;

typedef struct {
    struct tcp_pcb *pcb;
    char nick[MAX_NICK_LEN];
    char jid[64];
    int active;
} participant_t;

typedef struct {
    char name[MAX_ROOM_NAME_LEN];
    participant_t users[MAX_USERS_PER_ROOM];
    char creator_jid[64];
    int semi_anon;
    int locked;

    int active;
    int persistent;
    
    int moderated;

    int members_only;

    char banned_jids[MAX_BANNED_PER_ROOM][64];
    int banned_count;

    char subject[256];
} room_t;

extern room_t rooms[MAX_ROOMS];

extern xmpp_client_ctx_t client_registry[MAX_USERS];

xmpp_stanza_t* xmpp_alloc_stanza();
void xmpp_free_stanza(xmpp_stanza_t *s);

xmpp_stanza_t* parse_xml_stream(char *payload, int len, int *bytes_consumed, parse_null_reason_t *reason);

void xmpp_route_stanza(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_core_bind(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_core_session(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_muc_owner(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_disco_info(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_disco_items(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_muc_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_chat_message(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_sasl(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_broadcast_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_roster_request(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_initial_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_private_storage(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_muc_admin(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_general_success(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_blocklist(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_version(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_last(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void handle_ping(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

void xmpp_log(const char *direction, const char *data, int len);
void send_raw(xmpp_client_ctx_t *ctx, const char *data);

int xmpp_tls_server_init(void);

int xmpp_tls_client_init(xmpp_client_ctx_t *ctx);

void xmpp_tls_client_free(xmpp_client_ctx_t *ctx);

void xmpp_tls_handshake_step(xmpp_client_ctx_t *ctx, const uint8_t *data, int len);

void xmpp_tls_decrypt(xmpp_client_ctx_t *ctx, const uint8_t *data, int len);

err_t xmpp_recv_callback(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
err_t xmpp_accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err);
void xmpp_init_server();

extern unsigned int secure_random_u32(void);

typedef struct {
    char username[32];
    char password[64];
} xmpp_credential_t;

extern const xmpp_credential_t xmpp_credentials[];
extern const int xmpp_credential_count;

#define MAX_OFFLINE_MSGS 32

typedef struct {
    char from[64];
    char to_bare[64];
    char to_user[32];
    char id[64];
    char payload[1024];
    int32_t active;
} offline_msg_t;

extern offline_msg_t offline_store[MAX_OFFLINE_MSGS];

#define MAX_PENDING_SUBS 32

typedef struct {
    char type[16];
    char from[64];
    char to_user[32];
    int32_t active;
} pending_sub_t;

extern pending_sub_t pending_subs[MAX_PENDING_SUBS];

#define PRIVATE_STORAGE_SLOTS 20
#define PRIVATE_NS_MAX 128
#define PRIVATE_XML_MAX 900

typedef struct {
    char username[32];
    char ns[PRIVATE_NS_MAX];
    char xml[PRIVATE_XML_MAX];
    int active;
} private_store_entry_t;

extern private_store_entry_t private_store[PRIVATE_STORAGE_SLOTS];

#define MAX_ROSTER_ENTRIES 80
#define ROSTER_ITEM_MAX_LEN 256

typedef struct {
    char username[32];
    char jid[64];
    char item_xml[ROSTER_ITEM_MAX_LEN];
    int active;
} roster_entry_t;

extern roster_entry_t roster_store[MAX_ROSTER_ENTRIES];

extern int roster_version;

void xmpp_persist_load_all();
void xmpp_persist_save_private();
void xmpp_persist_save_roster();
void xmpp_persist_save_rooms();
void xmpp_persist_save_offline();
void xmpp_persist_save_pending_subs();

void xmpp_sm_send_enabled(xmpp_client_ctx_t *ctx);
void xmpp_sm_send_ack(xmpp_client_ctx_t *ctx);
void xmpp_sm_request_ack(xmpp_client_ctx_t *ctx);
void xmpp_sm_on_stanza_received(xmpp_client_ctx_t *ctx);
void xmpp_sm_on_stanza_sent(xmpp_client_ctx_t *ctx);
int xmpp_sm_handle_element(xmpp_client_ctx_t *ctx);

void mpk_benchmark(void); 

int offline_msg_enqueue(const char *to_bare, const char *from_jid, const char *msg_id, const char *payload);
void offline_msg_drain(xmpp_client_ctx_t *ctx);
int offline_msg_is_full(const char *to_user);

int roster_store_upsert_item(const char *username, const char *item_xml);
void roster_store_set_from_payload(const char *username, const char *payload);
int roster_store_get_items(const char *username, char *buf, int buf_len);

#endif
