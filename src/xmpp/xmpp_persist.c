/* ===========================================================================
 * xmpp_persist.c — Disk-based persistence for XMPP stores
 *
 * I/O is routed through the disk abstraction layer (drivers/disk.h),
 * which automatically selects between AHCI (DMA) and ATA PIO (polling).
 *
 * DATA DISK LAYOUT (data.img, 1 MB = 2048 sectors of 512 bytes each):
 *
 *   LBA  0        (1 sector  =  512 B)  persist_header_t
 *                                         magic:   0xA6E71C3D
 *                                         version: 3
 *                                         crc32:   covers all payload sectors
 *
 *   LBA  1..42   (42 sectors = 21504 B)  private_store[PRIVATE_STORAGE_SLOTS]
 *                                         actual payload: 20 x 1064 = 21280 B
 *
 *   LBA 43..98   (56 sectors = 28672 B)  roster_store[MAX_ROSTER_ENTRIES]
 *                                         actual payload: 80 x 356  = 28480 B
 *
 *   LBA 99       (1 sector  =   512 B)  rooms[MAX_ROOMS]
 *                                         4 x persist_room_entry_t (128 B each)
 *                                         stores: name, creator_jid, semi_anon,
 *                                                 locked, active
 *                                         NOTE: live participants (pcb pointers)
 *                                         are NOT persisted — users rejoin after
 *                                         restart, but the room itself survives.
 *
 *   LBA 100..178 (79 sectors = 40448 B)  offline_store[MAX_OFFLINE_MSGS]
 *                                         actual payload: 32 x 1252 = 40064 B
 *                                         stores: from, to_bare, to_user, id,
 *                                                 payload, active
 *                                         XEP-0160 §2 — messages queued for
 *                                         users with no active session survive
 *                                         a server restart and are delivered
 *                                         on next initial presence.
 *
 *   LBA 179..186  (8 sectors =  4096 B)  pending_subs[MAX_PENDING_SUBS]
 *                                         actual payload: 32 x 116  =  3712 B
 *                                         stores: type, from, to_user, active
 *                                         RFC 6121 §4.3 — subscription stanzas
 *                                         queued for offline users survive a
 *                                         restart and are drained on next login.
 *
 *   LBA 187..2047  reserved for future use
 *
 * INTEGRITY:
 *   CRC32 (IEEE 802.3) over all five payload regions.
 *   Mismatch on load = power-loss recovery: zero all stores, write clean header.
 *
 * VERSION HISTORY:
 *   1 — private_store + roster_store
 *   2 — added rooms[] persistence (LBA 99)
 *   3 — added offline_store (LBA 100..178) + pending_subs (LBA 179..186)
 * =========================================================================== */

#include "xmpp_core.h"
#include "drivers/disk.h"
#include <string.h>
#include <stdint.h>

extern void serial_print(const char *s);
extern void serial_print_hex(uint64_t n);

/* ------------------------------------------------------------------
 * Disk layout constants
 * ------------------------------------------------------------------ */
#define PERSIST_MAGIC 0xA6E71C3Du
#define PERSIST_VERSION 5u  // Bumped: forces fresh_start on images with corrupt layout

#define LBA_HEADER 0u
#define LBA_PRIVATE_START 1u
#define LBA_PRIVATE_SECTORS 42u
#define LBA_ROSTER_START 43u
#define LBA_ROSTER_SECTORS 56u
#define LBA_ROOMS_START 99u
#define LBA_ROOMS_SECTORS 8u
#define LBA_OFFLINE_START 107u   // Fixed: was 100, overlapped rooms (99+8=107)
#define LBA_OFFLINE_SECTORS 79u   /* 32 x 1252 B = 40064 B, ceil to 79 sectors */
#define LBA_PENDING_SUBS_START 186u  // Fixed: was 179, moved past offline (107+79=186)
#define LBA_PENDING_SUBS_SECTORS 8u    /* 32 x 116 B  =  3712 B, ceil to  8 sectors */

/* ------------------------------------------------------------------
 * On-disk header — exactly 512 bytes (one sector)
 * ------------------------------------------------------------------ */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t crc32;
    uint32_t flags;
    uint8_t _pad[496];
} __attribute__((packed)) persist_header_t;

_Static_assert(sizeof(persist_header_t) == 512, "persist_header_t must be exactly 512 bytes");

/* ------------------------------------------------------------------
 * persist_room_entry_t — on-disk representation of one MUC room.
 *
 * We only persist the configuration fields.  The live participants
 * array (participant_t users[]) is intentionally excluded because it
 * contains TCP PCB pointers which are only valid in the current
 * process lifetime.  Users simply rejoin after a server restart.
 *
 * Padded to 128 bytes so 4 entries fit exactly in one 512-byte sector.
 * ------------------------------------------------------------------ */
typedef struct {
    char    name[MAX_ROOM_NAME_LEN];              /* room local name           */
    char    creator_jid[64];                       /* bare JID of room owner    */
    int32_t semi_anon;                             /* 1=semi-anon, 0=non-anon   */
    int32_t locked;                                /* 1=locked (unconfigured)   */
    int32_t active;                                /* 1=room exists             */
    int32_t persistent;                            /* 1=survives empty room     */
    int32_t moderated;                             /* 1=voice required to speak */
    int32_t members_only;                          /* 1=member gate enforced    */
    int32_t banned_count;                          /* # entries in banned_jids  */
    char    banned_jids[MAX_BANNED_PER_ROOM][64];  /* bare JIDs: 8 × 64 = 512B */
    char    subject[256];                          /* current room subject      */
    uint8_t _pad[0];                               /* struct now exactly 960 B  */
} __attribute__((packed)) persist_room_entry_t;

/* 32+64+4+4+4+4+4+4+4+512+256 = 892 bytes. Pad to 1024 so future fields fit
 * within one sector boundary and we can store MAX_ROOMS=4 in ≤ 8 sectors.
 * Total: 4 × 1024 = 4096 bytes = 8 sectors                                 */
_Static_assert(sizeof(persist_room_entry_t) <= 1024,
    "persist_room_entry_t must fit in 1024 bytes");
_Static_assert(sizeof(persist_room_entry_t) * MAX_ROOMS <= LBA_ROOMS_SECTORS * 512, "rooms do not fit in allocated sectors");

/* ------------------------------------------------------------------
 * persist_offline_entry_t — on-disk representation of one offline message.
 *
 * Mirrors offline_msg_t (xmpp_core.h) exactly, but uses int32_t for
 * the active flag to guarantee the same wire size on all platforms.
 *
 * XEP-0160 §2 — queued messages must survive a server restart.
 * ------------------------------------------------------------------ */
typedef struct {
    char    from[64];
    char    to_bare[64];
    char    to_user[32];
    char    id[64];
    char    payload[1024];
    int32_t active;
} __attribute__((packed)) persist_offline_entry_t;

_Static_assert(sizeof(persist_offline_entry_t) == 1252,
    "persist_offline_entry_t size mismatch");
_Static_assert(sizeof(persist_offline_entry_t) * MAX_OFFLINE_MSGS
               <= LBA_OFFLINE_SECTORS * 512,
    "offline_store does not fit in allocated sectors");

/* ------------------------------------------------------------------
 * persist_pending_sub_entry_t — on-disk representation of one pending
 * subscription stanza.
 *
 * Mirrors pending_sub_t (xmpp_core.h) with int32_t active.
 *
 * RFC 6121 §4.3 — queued subscription stanzas must survive a restart.
 * ------------------------------------------------------------------ */
typedef struct {
    char    type[16];
    char    from[64];
    char    to_user[32];
    int32_t active;
} __attribute__((packed)) persist_pending_sub_entry_t;

_Static_assert(sizeof(persist_pending_sub_entry_t) == 116,
    "persist_pending_sub_entry_t size mismatch");
_Static_assert(sizeof(persist_pending_sub_entry_t) * MAX_PENDING_SUBS
               <= LBA_PENDING_SUBS_SECTORS * 512,
    "pending_subs does not fit in allocated sectors");

/* ------------------------------------------------------------------
 * Sector-aligned staging buffers (static = no heap needed)
 * ------------------------------------------------------------------ */
static uint8_t private_buf[LBA_PRIVATE_SECTORS * 512];
static uint8_t roster_buf [LBA_ROSTER_SECTORS * 512];
static uint8_t rooms_buf        [LBA_ROOMS_SECTORS * 512];  /* 8 * 512 = 4096 bytes */
static uint8_t offline_buf      [LBA_OFFLINE_SECTORS * 512];
static uint8_t pending_subs_buf [LBA_PENDING_SUBS_SECTORS * 512];

/* ------------------------------------------------------------------
 * compute_full_crc — CRC32 (IEEE 802.3) over all three live stores
 * ------------------------------------------------------------------ */
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

    /* CRC covers only the persistent fields we actually save.
     * We re-pack into persist_room_entry_t to exclude the live
     * participant array which is never written to disk. */
    for (int i = 0; i < MAX_ROOMS; i++) {
        persist_room_entry_t e;
        memset(&e, 0, sizeof(e));

        strncpy(e.name, rooms[i].name, sizeof(e.name) - 1);
        strncpy(e.creator_jid, rooms[i].creator_jid, sizeof(e.creator_jid) - 1);
        strncpy(e.subject, rooms[i].subject, sizeof(e.subject) - 1);

        e.semi_anon    = (int32_t)rooms[i].semi_anon;
        e.locked       = (int32_t)rooms[i].locked;
        e.active       = (int32_t)rooms[i].active;
        e.persistent   = (int32_t)rooms[i].persistent;
        e.moderated    = (int32_t)rooms[i].moderated;
        e.members_only = (int32_t)rooms[i].members_only;
        e.banned_count = (int32_t)rooms[i].banned_count;
        for (int bi = 0; bi < rooms[i].banned_count && bi < MAX_BANNED_PER_ROOM; bi++) {
            strncpy(e.banned_jids[bi], rooms[i].banned_jids[bi],
                    sizeof(e.banned_jids[bi]) - 1);
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

    /* CRC over offline_store — written verbatim (no pointer fields). */
    p = (const uint8_t *)offline_store;
    len = (uint32_t)(sizeof(persist_offline_entry_t) * MAX_OFFLINE_MSGS);

    while (len--) {
        crc ^= *p++;

        for (int i = 0; i < 8; i++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }

    /* CRC over pending_subs — written verbatim (no pointer fields). */
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

/* ------------------------------------------------------------------
 * write_header — update on-disk header with current CRC
 * ------------------------------------------------------------------ */
static void write_header(void) {
    persist_header_t hdr;

    memset(&hdr, 0, sizeof(hdr));
    
    hdr.magic = PERSIST_MAGIC;
    hdr.version = PERSIST_VERSION;
    hdr.crc32 = compute_full_crc();
    hdr.flags = 0;

    if (disk_write_sectors(LBA_HEADER, 1, &hdr) != 0){
        serial_print("[PERSIST] ERROR: failed to write header\n");
    }
}

/* ===========================================================================
 * xmpp_persist_save_private
 * =========================================================================== */
void xmpp_persist_save_private(void) {
    memset(private_buf, 0, sizeof(private_buf));
    
    memcpy(private_buf, private_store, sizeof(private_store_entry_t) * PRIVATE_STORAGE_SLOTS);

    if (disk_write_sectors(LBA_PRIVATE_START, LBA_PRIVATE_SECTORS, private_buf) != 0) {
        serial_print("[PERSIST] ERROR: private_store write failed\n");

        return;
    }

    write_header();
    
    serial_print("[PERSIST] private_store saved to disk\n");
}

/* ===========================================================================
 * xmpp_persist_save_roster
 * =========================================================================== */
void xmpp_persist_save_roster(void) {
    memset(roster_buf, 0, sizeof(roster_buf));
    
    memcpy(roster_buf, roster_store, sizeof(roster_entry_t) * MAX_ROSTER_ENTRIES);

    if (disk_write_sectors(LBA_ROSTER_START, LBA_ROSTER_SECTORS, roster_buf) != 0) {
        serial_print("[PERSIST] ERROR: roster_store write failed\n");
        
        return;
    }

    write_header();
    
    serial_print("[PERSIST] roster_store saved to disk\n");
}

/* ===========================================================================
 * xmpp_persist_save_rooms
 *
 * Serialises rooms[] into persist_room_entry_t records (no PCB pointers,
 * no participant list) and writes them to LBA 99.
 * Called from handle_muc_presence (room created) and handle_muc_owner
 * (room configured / unlocked).
 * =========================================================================== */
void xmpp_persist_save_rooms(void) {
    memset(rooms_buf, 0, sizeof(rooms_buf));

    persist_room_entry_t *entries = (persist_room_entry_t *)rooms_buf;
    
    for (int i = 0; i < MAX_ROOMS; i++) {
        memset(&entries[i], 0, sizeof(entries[i]));
        strncpy(entries[i].name, rooms[i].name, sizeof(entries[i].name) - 1);
        strncpy(entries[i].creator_jid, rooms[i].creator_jid, sizeof(entries[i].creator_jid) - 1);
        strncpy(entries[i].subject, rooms[i].subject, sizeof(entries[i].subject) - 1);

        entries[i].semi_anon     = (int32_t)rooms[i].semi_anon;
        entries[i].locked        = (int32_t)rooms[i].locked;
        entries[i].active        = (int32_t)rooms[i].active;
        entries[i].persistent    = (int32_t)rooms[i].persistent;
        entries[i].moderated     = (int32_t)rooms[i].moderated;
        entries[i].members_only  = (int32_t)rooms[i].members_only;
        entries[i].banned_count  = (int32_t)rooms[i].banned_count;

        for (int bi = 0; bi < rooms[i].banned_count && bi < MAX_BANNED_PER_ROOM; bi++) {
            strncpy(entries[i].banned_jids[bi], rooms[i].banned_jids[bi],
                    sizeof(entries[i].banned_jids[bi]) - 1);
        }
    }

    if (disk_write_sectors(LBA_ROOMS_START, LBA_ROOMS_SECTORS, rooms_buf) != 0) {
        serial_print("[PERSIST] ERROR: rooms write failed\n");

        return;
    }

    write_header();

    serial_print("[PERSIST] rooms saved to disk\n");
}

/* ===========================================================================
 * xmpp_persist_save_offline
 *
 * Serialises offline_store[] to LBA 100..178.
 * Called by offline_msg_enqueue() (write-through on each new message) and
 * by offline_msg_drain() once after delivering all queued messages.
 *
 * XEP-0160 §2 — the server MUST store messages for offline recipients;
 * persisting to disk ensures they survive a server restart.
 *   https://xmpp.org/extensions/xep-0160.html
 * =========================================================================== */
void xmpp_persist_save_offline(void) {
    memset(offline_buf, 0, sizeof(offline_buf));

    /* offline_msg_t and persist_offline_entry_t are layout-compatible
     * (same field order, same sizes, packed) so a direct memcpy is safe. */
    memcpy(offline_buf, offline_store,
           sizeof(persist_offline_entry_t) * MAX_OFFLINE_MSGS);

    if (disk_write_sectors(LBA_OFFLINE_START, LBA_OFFLINE_SECTORS,
                           offline_buf) != 0) {
        serial_print("[PERSIST] ERROR: offline_store write failed\n");

        return;
    }

    write_header();

    serial_print("[PERSIST] offline_store saved to disk\n");
}

/* ===========================================================================
 * xmpp_persist_save_pending_subs
 *
 * Serialises pending_subs[] to LBA 179..186.
 * Called by pending_sub_enqueue() (write-through on each new entry) and
 * by pending_sub_drain() once after all entries for a user are cleared.
 *
 * RFC 6121 §4.3 — the server SHOULD deliver queued subscription stanzas
 * when the target user next sends initial presence; persisting to disk
 * ensures those intents survive a server restart.
 *   https://datatracker.ietf.org/doc/html/rfc6121#section-4.3
 * =========================================================================== */
void xmpp_persist_save_pending_subs(void) {
    memset(pending_subs_buf, 0, sizeof(pending_subs_buf));

    memcpy(pending_subs_buf, pending_subs,
           sizeof(persist_pending_sub_entry_t) * MAX_PENDING_SUBS);

    if (disk_write_sectors(LBA_PENDING_SUBS_START, LBA_PENDING_SUBS_SECTORS,
                           pending_subs_buf) != 0) {
        serial_print("[PERSIST] ERROR: pending_subs write failed\n");

        return;
    }

    write_header();

    serial_print("[PERSIST] pending_subs saved to disk\n");
}

/* ------------------------------------------------------------------
 * fresh_start — zero all stores and write a clean disk image
 *
 * IMPORTANT: this function is only safe to call at boot time, before
 * any network connections are accepted.  It zeroes rooms[] in place,
 * which includes the participant_t.pcb (TCP PCB pointer) fields inside
 * each room_t.  Those pointers are only valid during an active session;
 * zeroing them while live connections exist would corrupt lwIP state.
 * ------------------------------------------------------------------ */
static void fresh_start(void) {
    memset(private_store, 0, sizeof(private_store_entry_t) * PRIVATE_STORAGE_SLOTS);
    memset(roster_store,  0, sizeof(roster_entry_t) * MAX_ROSTER_ENTRIES);
    memset(rooms,         0, sizeof(room_t) * MAX_ROOMS);
    memset(offline_store, 0, sizeof(offline_msg_t) * MAX_OFFLINE_MSGS);
    memset(pending_subs,  0, sizeof(pending_sub_t) * MAX_PENDING_SUBS);

    memset(private_buf,      0, sizeof(private_buf));
    memset(roster_buf,       0, sizeof(roster_buf));
    memset(rooms_buf,        0, sizeof(rooms_buf));
    memset(offline_buf,      0, sizeof(offline_buf));
    memset(pending_subs_buf, 0, sizeof(pending_subs_buf));

    disk_write_sectors(LBA_PRIVATE_START,      LBA_PRIVATE_SECTORS,      private_buf);
    disk_write_sectors(LBA_ROSTER_START,       LBA_ROSTER_SECTORS,       roster_buf);
    disk_write_sectors(LBA_ROOMS_START,        LBA_ROOMS_SECTORS,        rooms_buf);
    disk_write_sectors(LBA_OFFLINE_START,      LBA_OFFLINE_SECTORS,      offline_buf);
    disk_write_sectors(LBA_PENDING_SUBS_START, LBA_PENDING_SUBS_SECTORS, pending_subs_buf);

    write_header();

    serial_print("[PERSIST] Clean disk initialised\n");
}

/* ------------------------------------------------------------------
 * try_load — attempt to restore all stores from disk.
 * Returns 1 on success, 0 if the disk should be re-initialised.
 * ------------------------------------------------------------------ */
static int try_load(void) {
    persist_header_t hdr;

    if (disk_read_sectors(LBA_HEADER, 1, &hdr) != 0) {
        serial_print("[PERSIST] ERROR: cannot read header\n");

        return 0;
    }
    if (hdr.magic != PERSIST_MAGIC) {
        serial_print("[PERSIST] First boot — initialising fresh disk\n");

        return 0;
    }
    if (hdr.version != PERSIST_VERSION) {
        serial_print("[PERSIST] WARNING: schema version mismatch — discarding\n");

        return 0;
    }
    if (disk_read_sectors(LBA_PRIVATE_START, LBA_PRIVATE_SECTORS, private_buf) != 0) {
        serial_print("[PERSIST] ERROR: cannot read private sectors\n");

        return 0;
    }
    if (disk_read_sectors(LBA_ROSTER_START, LBA_ROSTER_SECTORS, roster_buf) != 0) {
        serial_print("[PERSIST] ERROR: cannot read roster sectors\n");

        return 0;
    }
    if (disk_read_sectors(LBA_ROOMS_START, LBA_ROOMS_SECTORS, rooms_buf) != 0) {
        serial_print("[PERSIST] ERROR: cannot read rooms sectors\n");

        return 0;
    }
    if (disk_read_sectors(LBA_OFFLINE_START, LBA_OFFLINE_SECTORS,
                          offline_buf) != 0) {
        serial_print("[PERSIST] ERROR: cannot read offline sectors\n");

        return 0;
    }
    if (disk_read_sectors(LBA_PENDING_SUBS_START, LBA_PENDING_SUBS_SECTORS,
                          pending_subs_buf) != 0) {
        serial_print("[PERSIST] ERROR: cannot read pending_subs sectors\n");

        return 0;
    }

    /* Copy into live stores before CRC check */
    memcpy(private_store, private_buf,
           sizeof(private_store_entry_t) * PRIVATE_STORAGE_SLOTS);
    memcpy(roster_store, roster_buf,
           sizeof(roster_entry_t) * MAX_ROSTER_ENTRIES);

    /* Restore rooms — configuration only, participants start empty */
    const persist_room_entry_t *entries = (const persist_room_entry_t *)rooms_buf;

    for (int i = 0; i < MAX_ROOMS; i++) {
        memset(&rooms[i], 0, sizeof(room_t));

        strncpy(rooms[i].name, entries[i].name, sizeof(rooms[i].name) - 1);
        strncpy(rooms[i].creator_jid, entries[i].creator_jid,
                sizeof(rooms[i].creator_jid) - 1);
        strncpy(rooms[i].subject, entries[i].subject,
                sizeof(rooms[i].subject) - 1);

        rooms[i].semi_anon    = (int)entries[i].semi_anon;
        rooms[i].locked       = (int)entries[i].locked;
        rooms[i].active       = (int)entries[i].active;
        rooms[i].persistent   = (int)entries[i].persistent;
        rooms[i].moderated    = (int)entries[i].moderated;
        rooms[i].members_only = (int)entries[i].members_only;
        rooms[i].banned_count = (int)entries[i].banned_count;

        if (rooms[i].banned_count > MAX_BANNED_PER_ROOM)
            rooms[i].banned_count = MAX_BANNED_PER_ROOM;

        for (int bi = 0; bi < rooms[i].banned_count; bi++) {
            strncpy(rooms[i].banned_jids[bi], entries[i].banned_jids[bi],
                    sizeof(rooms[i].banned_jids[bi]) - 1);
        }
    }

    /* Restore offline_store — layout-compatible direct copy. */
    memcpy(offline_store, offline_buf,
           sizeof(persist_offline_entry_t) * MAX_OFFLINE_MSGS);

    /* Restore pending_subs — layout-compatible direct copy. */
    memcpy(pending_subs, pending_subs_buf,
           sizeof(persist_pending_sub_entry_t) * MAX_PENDING_SUBS);

    uint32_t expected = hdr.crc32;
    uint32_t actual = compute_full_crc();

    if (expected != actual) {
        serial_print("[PERSIST] WARNING: CRC mismatch — power loss recovery\n");
        serial_print("  expected=0x"); serial_print_hex(expected);
        serial_print("  actual=0x"); serial_print_hex(actual);
        serial_print("\n");

        return 0;
    }

    return 1;
}

/* ===========================================================================
 * xmpp_persist_load_all
 * =========================================================================== */
void xmpp_persist_load_all(void) {
    serial_print("[PERSIST] Loading stores from disk...\n");

    if (try_load()) {
        serial_print("[PERSIST] Stores restored from disk (CRC OK)\n");
    }
    else {
        fresh_start();
    }
}