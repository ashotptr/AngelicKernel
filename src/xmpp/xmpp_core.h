#ifndef XMPP_CORE_H
#define XMPP_CORE_H

#include "lwip/tcp.h" 
#include <stdio.h>
#include <string.h>

#define MAX_ROOMS 4
#define MAX_USERS_PER_ROOM 8
#define MAX_NICK_LEN 32
#define MAX_ROOM_NAME_LEN 32
#define MAX_USERS 10

#define XMPP_DOMAIN "angelic.local"
#define SERVER_JID(user) user "@" XMPP_DOMAIN

typedef enum {
    XMPP_UNKNOWN = 0,
    XMPP_IQ_GET, 
    XMPP_IQ_SET, 
    XMPP_IQ_RESULT, 
    XMPP_IQ_ERROR,
    XMPP_MESSAGE, 
    XMPP_PRESENCE
} stanza_type_t;

typedef enum {
    STATE_CONNECTED,
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
    char payload[1024];
    int is_used;
} xmpp_stanza_t;

typedef struct {
    struct tcp_pcb *pcb;
    client_state_t state;
    char full_jid[64];
    char username[32];
    int authenticated;
    char rx_buffer[16384];
    int rx_pos;
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
    int active;
} room_t;

extern room_t rooms[MAX_ROOMS];

xmpp_stanza_t* xmpp_alloc_stanza();
void xmpp_free_stanza(xmpp_stanza_t *s);
xmpp_stanza_t* parse_xml_stream(char *payload, int len, int *bytes_consumed);

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
void xmpp_log(const char *direction, const char *data, int len);
void send_raw(xmpp_client_ctx_t *ctx, const char *data);
extern int rand(void);
void handle_roster_request(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
void handle_initial_presence(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
void handle_private_storage(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
void handle_muc_admin(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);
void handle_general_success(xmpp_client_ctx_t *ctx, xmpp_stanza_t *stanza);

#endif