#ifndef XMPP_STRUCTS_H
#define XMPP_STRUCTS_H

#include "lwip/tcp.h"

// Unikernel Limits
#define MAX_ROOMS 4
#define MAX_USERS_PER_ROOM 8
#define MAX_NICK_LEN 32
#define MAX_ROOM_NAME_LEN 32
#define BUFFER_SIZE 1024

typedef struct {
    struct tcp_pcb *pcb;        // LwIP Connection Handle
    char nick[MAX_NICK_LEN];
    char jid[64];               // Full JID: user@ip
    int active;                 // 1 = connected
} participant_t;

typedef struct {
    char name[MAX_ROOM_NAME_LEN];
    participant_t users[MAX_USERS_PER_ROOM];
    int active;
} room_t;

// Global State
static room_t rooms[MAX_ROOMS];

#endif