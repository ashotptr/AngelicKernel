#include "xmpp_structs.h"
#include <string.h>
#include <stdio.h>

void serial_print(const char* str);

int str_contains(const char *haystack, const char *needle) {
    return (strstr(haystack, needle) != NULL);
}

// xmpp protocol handlers
// 1. Initial Handshake & SASL Bypass
// Cited from XEP-0045 & RFC 6120: We spoof SASL to force ANONYMOUS login.
void handle_handshake(struct tcp_pcb *pcb) {
    const char *response = 
        "<?xml version='1.0'?>"
        "<stream:stream from='angelic.local' id='12345' version='1.0' "
        "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"
        "<stream:features>"
        "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
        "<mechanism>ANONYMOUS</mechanism>"
        "</mechanisms>"
        "</stream:features>";
    
    tcp_write(pcb, response, strlen(response), TCP_WRITE_FLAG_COPY);
    tcp_output(pcb);
}

// 2. Service Discovery (Disco)
// Gajim asks "What are you?". We must reply "I am a MUC service".
void handle_disco_info(struct tcp_pcb *pcb, const char *id, const char *from) {
    char response[512];
    // Construct the IQ Result packet
    // Note: We use sprintf carefully. In kernel, ensure snprintf is available or safe.
    snprintf(response, sizeof(response),
        "<iq type='result' id='%s' to='%s' from='muc.angelic.local'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'>"
        "<identity category='conference' type='text' name='AngelicKernel MUC'/>"
        "<feature var='http://jabber.org/protocol/muc'/>"
        "</query></iq>", 
        id, from);

    tcp_write(pcb, response, strlen(response), TCP_WRITE_FLAG_COPY);
}

// 3. Joining a Room
// User sends <presence to='room@muc/nick'>
void handle_join_room(struct tcp_pcb *pcb, char *room_name, char *nick, char *full_from_jid) {
    // A. Find or Create Room
    room_t *r = NULL;
    for (int i = 0; i < MAX_ROOMS; i++) {
        if (rooms[i].active && strcmp(rooms[i].name, room_name) == 0) {
            r = &rooms[i];
            break;
        }
    }
    // If not found, create new (simplification for Unikernel)
    if (!r) {
        for (int i = 0; i < MAX_ROOMS; i++) {
            if (!rooms[i].active) {
                rooms[i].active = 1;
                strncpy(rooms[i].name, room_name, MAX_ROOM_NAME_LEN);
                r = &rooms[i];
                break;
            }
        }
    }
    if (!r) return; // No space for rooms

    // B. Add User to Room
    participant_t *me = NULL;
    for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
        if (!r->users[i].active) {
            r->users[i].active = 1;
            r->users[i].pcb = pcb;
            strncpy(r->users[i].nick, nick, MAX_NICK_LEN);
            strncpy(r->users[i].jid, full_from_jid, 64);
            me = &r->users[i];
            break;
        }
    }

    // C. Broadast Presence to ALL (including self)
    char presence[512];
    snprintf(presence, sizeof(presence),
        "<presence from='%s@muc.angelic.local/%s' to='%s'>"
        "<x xmlns='http://jabber.org/protocol/muc#user'>"
        "<item affiliation='member' role='participant'/>"
        "</x></presence>",
        room_name, nick, full_from_jid); // Send to self

    // Send to everyone in the room
    for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
        if (r->users[i].active) {
            // Notify them about ME
            tcp_write(r->users[i].pcb, presence, strlen(presence), TCP_WRITE_FLAG_COPY);
            tcp_output(r->users[i].pcb);

            // Notify ME about THEM (if it's not me)
            if (r->users[i].pcb != pcb) {
                 char other_pres[512];
                 snprintf(other_pres, sizeof(other_pres),
                    "<presence from='%s@muc.angelic.local/%s' to='%s'/>",
                    room_name, r->users[i].nick, full_from_jid);
                 tcp_write(pcb, other_pres, strlen(other_pres), TCP_WRITE_FLAG_COPY);
                 tcp_output(pcb);
            }
        }
    }
}

// 4. Message Broadcast
// Input: <message type='groupchat' to='room@muc' ...><body>Text</body></message>
void handle_message(struct tcp_pcb *pcb, char *room_name, char *body) {
    // Find room
    room_t *r = NULL;
    for (int i = 0; i < MAX_ROOMS; i++) {
        if (rooms[i].active && strcmp(rooms[i].name, room_name) == 0) {
            r = &rooms[i];
            break;
        }
    }
    if (!r) return;

    // Find Sender's Nickname
    char *sender_nick = "Unknown";
    for(int i=0; i<MAX_USERS_PER_ROOM; i++) {
        if(r->users[i].active && r->users[i].pcb == pcb) {
            sender_nick = r->users[i].nick;
            break;
        }
    }

    // Broadcast
    char msg_out[1024];
    snprintf(msg_out, sizeof(msg_out),
        "<message type='groupchat' from='%s@muc.angelic.local/%s' to='ROOM'>"
        "<body>%s</body></message>",
        room_name, sender_nick, body);

for (int i = 0; i < MAX_USERS_PER_ROOM; i++) {
        if (r->users[i].active) {
            // Fix the 'to' address for each recipient
            // Note: In a real implementation, you'd replace 'ROOM' dynamically or loop better.
            // Simplified here: we assume client ignores 'to' mismatch or we hack it.
            // Proper way: Re-snprintf with correct 'to' JID for each user.
             char personal_msg[1024];
             snprintf(personal_msg, sizeof(personal_msg),
                "<message type='groupchat' from='%s@muc.angelic.local/%s' to='%s'>"
                "<body>%s</body></message>",
                room_name, sender_nick, r->users[i].jid, body);

            tcp_write(r->users[i].pcb, personal_msg, strlen(personal_msg), TCP_WRITE_FLAG_COPY);
            tcp_output(r->users[i].pcb);
        }
    }
}

// lwIP callbacks
err_t xmpp_recv_callback(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)arg;
    (void)err;
    if (p == NULL) {
        // Disconnect
        tcp_close(pcb);
        return ERR_OK;
    }

    char *data = (char *)p->payload;
    // IMPORTANT: Null-terminate the buffer for string functions!
    // We assume p->len < BUFFER_SIZE for this simple version.
    char buffer[BUFFER_SIZE];
    int len = (p->len < BUFFER_SIZE-1) ? p->len : BUFFER_SIZE-1;
    memcpy(buffer, data, len);
    buffer[len] = '\0';

    serial_print("[XMPP RECV] > ");
    serial_print(buffer);
    serial_print("\n");

    // parser (Very Basic State Machine) ---
    
    if (str_contains(buffer, "<stream:stream")) {
        handle_handshake(pcb);
    }
    else if (str_contains(buffer, "disco#info")) {
        // Extract ID (Hack: assume id='...' format)
        char *id_start = strstr(buffer, "id='");
        if (id_start) {
            char id[16] = {0};
            int i=0; 
            id_start += 4;
            while(id_start[i] != '\'' && i<15) { id[i] = id_start[i]; i++; }
            handle_disco_info(pcb, id, "client@ip"); // Simplify JID
        }
    }
    else if (str_contains(buffer, "<presence") && str_contains(buffer, "muc")) {
        // Assume format: to='room@muc/nick'
        // Parsing logic would go here to extract room and nick
        // Hardcoded Test for "lobby"
        handle_join_room(pcb, "lobby", "Guest", "client@ip"); 
    }
    else if (str_contains(buffer, "<message") && str_contains(buffer, "<body>")) {
        // Extract Body
        char *body_start = strstr(buffer, "<body>");
        char body[256] = {0};
        if(body_start) {
            body_start += 6;
            int i=0;
            while(body_start[i] != '<' && i<255) { body[i] = body_start[i]; i++; }
            handle_message(pcb, "lobby", body);
        }
    }

    tcp_recved(pcb, p->len);
    pbuf_free(p);
    return ERR_OK;
}

err_t xmpp_accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err) {
    (void)arg; // Add this
    (void)err; // Add this
    tcp_recv(newpcb, xmpp_recv_callback);
    return ERR_OK;
}

// Public Function to Start Server
void xmpp_init_server() {
    struct tcp_pcb *pcb = tcp_new();
    tcp_bind(pcb, IP_ADDR_ANY, 5222);
    pcb = tcp_listen(pcb);
    tcp_accept(pcb, xmpp_accept_callback);
}