#include "xmpp_core.h"
#include "drivers/disk.h"
#include <string.h>
#include <stdint.h>

extern void serial_print(const char *s);
extern void serial_print_hex(uint64_t n);

#define PERSIST_MAGIC 0xA6E71C3Du
#define PERSIST_VERSION 5u

#define LBA_HEADER 0u
#define LBA_PRIVATE_START 1u
#define LBA_PRIVATE_SECTORS 42u
#define LBA_ROSTER_START 43u
#define LBA_ROSTER_SECTORS 56u
#define LBA_ROOMS_START 99u
#define LBA_ROOMS_SECTORS 8u
#define LBA_OFFLINE_START 107u
#define LBA_OFFLINE_SECTORS 79u
#define LBA_PENDING_SUBS_START 186u
#define LBA_PENDING_SUBS_SECTORS 8u

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t crc32;
    uint32_t flags;
    uint8_t _pad[496];
} __attribute__((packed)) persist_header_t;

_Static_assert(sizeof(persist_header_t) == 512, "persist_header_t must be exactly 512 bytes");

typedef struct {
    char name[MAX_ROOM_NAME_LEN];
    char creator_jid[64];
    int32_t semi_anon;
    int32_t locked;
    int32_t active;
    int32_t persistent;
    int32_t moderated;
    int32_t members_only;
    int32_t banned_count;
    char banned_jids[MAX_BANNED_PER_ROOM][64];
    char subject[256];
    uint8_t _pad[0];
} __attribute__((packed)) persist_room_entry_t;

_Static_assert(sizeof(persist_room_entry_t) <= 1024, "persist_room_entry_t must fit in 1024 bytes");
_Static_assert(sizeof(persist_room_entry_t) * MAX_ROOMS <= LBA_ROOMS_SECTORS * 512, "rooms do not fit in allocated sectors");


typedef struct {
    char from[64];
    char to_bare[64];
    char to_user[32];
    char id[64];
    char payload[1024];
    int32_t active;
} __attribute__((packed)) persist_offline_entry_t;

_Static_assert(sizeof(persist_offline_entry_t) == 1252, "persist_offline_entry_t size mismatch");
_Static_assert(sizeof(persist_offline_entry_t) * MAX_OFFLINE_MSGS <= LBA_OFFLINE_SECTORS * 512, "offline_store does not fit in allocated sectors");

typedef struct {
    char type[16];
    char from[64];
    char to_user[32];
    int32_t active;
} __attribute__((packed)) persist_pending_sub_entry_t;

_Static_assert(sizeof(persist_pending_sub_entry_t) == 116, "persist_pending_sub_entry_t size mismatch");
_Static_assert(sizeof(persist_pending_sub_entry_t) * MAX_PENDING_SUBS <= LBA_PENDING_SUBS_SECTORS * 512, "pending_subs does not fit in allocated sectors");

static uint8_t private_buf[LBA_PRIVATE_SECTORS * 512];
static uint8_t roster_buf [LBA_ROSTER_SECTORS * 512];
static uint8_t rooms_buf [LBA_ROOMS_SECTORS * 512];
static uint8_t offline_buf [LBA_OFFLINE_SECTORS * 512];
static uint8_t pending_subs_buf [LBA_PENDING_SUBS_SECTORS * 512];

static uint32_t compute_full_crc(void) {
    uint32_t crc = 0xFFFFFFFFu;
    const uint8_t *p;
    uint32_t len;

    p = (const uint8_t *)private_store;
    len = (uint32_t)(sizeof(private_store_entry_t) * PRIVATE_STORAGE_SLOTS);

    while (len--) {
        crc ^= *p++;
        
        for (int i = 0; i < 8; i++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }

    p = (const uint8_t *)roster_store;
    len = (uint32_t)(sizeof(roster_entry_t) * MAX_ROSTER_ENTRIES);

    while (len--) {
        crc ^= *p++;

        for (int i = 0; i < 8; i++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }

    for (int i = 0; i < MAX_ROOMS; i++) {
        persist_room_entry_t e;

        memset(&e, 0, sizeof(e));

        strncpy(e.name, rooms[i].name, sizeof(e.name) - 1);
        strncpy(e.creator_jid, rooms[i].creator_jid, sizeof(e.creator_jid) - 1);
        strncpy(e.subject, rooms[i].subject, sizeof(e.subject) - 1);

        e.semi_anon = (int32_t)rooms[i].semi_anon;
        e.locked = (int32_t)rooms[i].locked;
        e.active = (int32_t)rooms[i].active;
        e.persistent = (int32_t)rooms[i].persistent;
        e.moderated = (int32_t)rooms[i].moderated;
        e.members_only = (int32_t)rooms[i].members_only;
        e.banned_count = (int32_t)rooms[i].banned_count;

        for (int bi = 0; bi < rooms[i].banned_count && bi < MAX_BANNED_PER_ROOM; bi++) {
            strncpy(e.banned_jids[bi], rooms[i].banned_jids[bi], sizeof(e.banned_jids[bi]) - 1);
        }

        p = (const uint8_t *)&e;
        len = (uint32_t)sizeof(e);

        while (len--) {
            crc ^= *p++;

            for (int j = 0; j < 8; j++) {
                uint32_t mask = -(crc & 1u);
                crc = (crc >> 1) ^ (0xEDB88320u & mask);
            }
        }
    }

    p = (const uint8_t *)offline_store;
    len = (uint32_t)(sizeof(persist_offline_entry_t) * MAX_OFFLINE_MSGS);

    while (len--) {
        crc ^= *p++;

        for (int i = 0; i < 8; i++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }

    p = (const uint8_t *)pending_subs;
    len = (uint32_t)(sizeof(persist_pending_sub_entry_t) * MAX_PENDING_SUBS);

    while (len--) {
        crc ^= *p++;

        for (int i = 0; i < 8; i++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }

    return ~crc;
}

static void write_header(void) {
    persist_header_t hdr;

    memset(&hdr, 0, sizeof(hdr));
    
    hdr.magic = PERSIST_MAGIC;
    hdr.version = PERSIST_VERSION;
    hdr.crc32 = compute_full_crc();
    hdr.flags = 0;

    if (disk_write_sectors(LBA_HEADER, 1, &hdr) != 0){
        serial_print("[persist] failed to write header\n");
    }
}

void xmpp_persist_save_private(void) {
    memset(private_buf, 0, sizeof(private_buf));
    
    memcpy(private_buf, private_store, sizeof(private_store_entry_t) * PRIVATE_STORAGE_SLOTS);

    if (disk_write_sectors(LBA_PRIVATE_START, LBA_PRIVATE_SECTORS, private_buf) != 0) {
        serial_print("[persist] private_store write failed\n");

        return;
    }

    write_header();
    
    serial_print("[persist] private_store saved to disk\n");
}

void xmpp_persist_save_roster(void) {
    memset(roster_buf, 0, sizeof(roster_buf));
    
    memcpy(roster_buf, roster_store, sizeof(roster_entry_t) * MAX_ROSTER_ENTRIES);

    if (disk_write_sectors(LBA_ROSTER_START, LBA_ROSTER_SECTORS, roster_buf) != 0) {
        serial_print("[persist] roster_store write failed\n");
        
        return;
    }

    write_header();
    
    serial_print("[persist] roster_store saved to disk\n");
}

void xmpp_persist_save_rooms(void) {
    memset(rooms_buf, 0, sizeof(rooms_buf));

    persist_room_entry_t *entries = (persist_room_entry_t *)rooms_buf;
    
    for (int i = 0; i < MAX_ROOMS; i++) {
        memset(&entries[i], 0, sizeof(entries[i]));

        strncpy(entries[i].name, rooms[i].name, sizeof(entries[i].name) - 1);
        strncpy(entries[i].creator_jid, rooms[i].creator_jid, sizeof(entries[i].creator_jid) - 1);
        strncpy(entries[i].subject, rooms[i].subject, sizeof(entries[i].subject) - 1);

        entries[i].semi_anon = (int32_t)rooms[i].semi_anon;
        entries[i].locked = (int32_t)rooms[i].locked;
        entries[i].active = (int32_t)rooms[i].active;
        entries[i].persistent = (int32_t)rooms[i].persistent;
        entries[i].moderated = (int32_t)rooms[i].moderated;
        entries[i].members_only = (int32_t)rooms[i].members_only;
        entries[i].banned_count = (int32_t)rooms[i].banned_count;

        for (int bi = 0; bi < rooms[i].banned_count && bi < MAX_BANNED_PER_ROOM; bi++) {
            strncpy(entries[i].banned_jids[bi], rooms[i].banned_jids[bi], sizeof(entries[i].banned_jids[bi]) - 1);
        }
    }

    if (disk_write_sectors(LBA_ROOMS_START, LBA_ROOMS_SECTORS, rooms_buf) != 0) {
        serial_print("[persist] rooms write failed\n");

        return;
    }

    write_header();

    serial_print("[persist] rooms saved to disk\n");
}

void xmpp_persist_save_offline(void) {
    memset(offline_buf, 0, sizeof(offline_buf));
    
    memcpy(offline_buf, offline_store, sizeof(persist_offline_entry_t) * MAX_OFFLINE_MSGS);

    if (disk_write_sectors(LBA_OFFLINE_START, LBA_OFFLINE_SECTORS, offline_buf) != 0) {
        serial_print("[persist] offline_store write failed\n");

        return;
    }

    write_header();

    serial_print("[persist] offline_store saved to disk\n");
}

void xmpp_persist_save_pending_subs(void) {
    memset(pending_subs_buf, 0, sizeof(pending_subs_buf));

    memcpy(pending_subs_buf, pending_subs, sizeof(persist_pending_sub_entry_t) * MAX_PENDING_SUBS);

    if (disk_write_sectors(LBA_PENDING_SUBS_START, LBA_PENDING_SUBS_SECTORS, pending_subs_buf) != 0) {
        serial_print("[persist] pending_subs write failed\n");

        return;
    }

    write_header();

    serial_print("[persist] pending_subs saved to disk\n");
}

static void fresh_start(void) {
    memset(private_store, 0, sizeof(private_store_entry_t) * PRIVATE_STORAGE_SLOTS);
    memset(roster_store, 0, sizeof(roster_entry_t) * MAX_ROSTER_ENTRIES);
    memset(rooms, 0, sizeof(room_t) * MAX_ROOMS);
    memset(offline_store, 0, sizeof(offline_msg_t) * MAX_OFFLINE_MSGS);
    memset(pending_subs, 0, sizeof(pending_sub_t) * MAX_PENDING_SUBS);
    memset(private_buf, 0, sizeof(private_buf));
    memset(roster_buf, 0, sizeof(roster_buf));
    memset(rooms_buf, 0, sizeof(rooms_buf));
    memset(offline_buf, 0, sizeof(offline_buf));
    memset(pending_subs_buf, 0, sizeof(pending_subs_buf));

    disk_write_sectors(LBA_PRIVATE_START, LBA_PRIVATE_SECTORS, private_buf);
    disk_write_sectors(LBA_ROSTER_START, LBA_ROSTER_SECTORS, roster_buf);
    disk_write_sectors(LBA_ROOMS_START, LBA_ROOMS_SECTORS, rooms_buf);
    disk_write_sectors(LBA_OFFLINE_START, LBA_OFFLINE_SECTORS, offline_buf);
    disk_write_sectors(LBA_PENDING_SUBS_START, LBA_PENDING_SUBS_SECTORS, pending_subs_buf);

    write_header();

    serial_print("[persist] clean disk initialised\n");
}

static int try_load(void) {
    persist_header_t hdr;

    if (disk_read_sectors(LBA_HEADER, 1, &hdr) != 0) {
        serial_print("[persist] cannot read header\n");

        return 0;
    }
    if (hdr.magic != PERSIST_MAGIC) {
        serial_print("[persist] first boot, initialising fresh disk\n");

        return 0;
    }
    if (hdr.version != PERSIST_VERSION) {
        serial_print("[persist] schema version mismatch, discarding\n");

        return 0;
    }
    if (disk_read_sectors(LBA_PRIVATE_START, LBA_PRIVATE_SECTORS, private_buf) != 0) {
        serial_print("[persist] cannot read private sectors\n");

        return 0;
    }
    if (disk_read_sectors(LBA_ROSTER_START, LBA_ROSTER_SECTORS, roster_buf) != 0) {
        serial_print("[persist] cannot read roster sectors\n");

        return 0;
    }
    if (disk_read_sectors(LBA_ROOMS_START, LBA_ROOMS_SECTORS, rooms_buf) != 0) {
        serial_print("[persist] cannot read rooms sectors\n");

        return 0;
    }
    if (disk_read_sectors(LBA_OFFLINE_START, LBA_OFFLINE_SECTORS, offline_buf) != 0) {
        serial_print("[persist] cannot read offline sectors\n");

        return 0;
    }
    if (disk_read_sectors(LBA_PENDING_SUBS_START, LBA_PENDING_SUBS_SECTORS, pending_subs_buf) != 0) {
        serial_print("[persist] cannot read pending_subs sectors\n");

        return 0;
    }

    memcpy(private_store, private_buf, sizeof(private_store_entry_t) * PRIVATE_STORAGE_SLOTS);
    memcpy(roster_store, roster_buf, sizeof(roster_entry_t) * MAX_ROSTER_ENTRIES);

    const persist_room_entry_t *entries = (const persist_room_entry_t *)rooms_buf;

    for (int i = 0; i < MAX_ROOMS; i++) {
        memset(&rooms[i], 0, sizeof(room_t));

        strncpy(rooms[i].name, entries[i].name, sizeof(rooms[i].name) - 1);
        strncpy(rooms[i].creator_jid, entries[i].creator_jid, sizeof(rooms[i].creator_jid) - 1);
        strncpy(rooms[i].subject, entries[i].subject, sizeof(rooms[i].subject) - 1);

        rooms[i].semi_anon = (int)entries[i].semi_anon;
        rooms[i].locked = (int)entries[i].locked;
        rooms[i].active = (int)entries[i].active;
        rooms[i].persistent = (int)entries[i].persistent;
        rooms[i].moderated = (int)entries[i].moderated;
        rooms[i].members_only = (int)entries[i].members_only;
        rooms[i].banned_count = (int)entries[i].banned_count;

        if (rooms[i].banned_count > MAX_BANNED_PER_ROOM) {
            rooms[i].banned_count = MAX_BANNED_PER_ROOM;
        }

        for (int bi = 0; bi < rooms[i].banned_count; bi++) {
            strncpy(rooms[i].banned_jids[bi], entries[i].banned_jids[bi], sizeof(rooms[i].banned_jids[bi]) - 1);
        }
    }

    memcpy(offline_store, offline_buf, sizeof(persist_offline_entry_t) * MAX_OFFLINE_MSGS);
    memcpy(pending_subs, pending_subs_buf, sizeof(persist_pending_sub_entry_t) * MAX_PENDING_SUBS);

    uint32_t expected = hdr.crc32;
    uint32_t actual = compute_full_crc();

    if (expected != actual) {
        serial_print("[persist] crc mismatch, power loss recovery\n");
        serial_print("expected=0x");
        serial_print_hex(expected);
        serial_print("actual=0x");
        serial_print_hex(actual);
        serial_print("\n");

        return 0;
    }

    return 1;
}

void xmpp_persist_load_all(void) {
    serial_print("[persist] loading stores from disk\n");

    if (try_load()) {
        serial_print("[persist] stores restored from disk\n");
    }
    else {
        fresh_start();
    }
}