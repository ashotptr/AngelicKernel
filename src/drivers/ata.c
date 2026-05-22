#include "drivers/ata.h"
#include <stdint.h>
#include <string.h>

extern void serial_print(const char *s);
extern void serial_print_hex(uint64_t n);

static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    __asm__ volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline uint16_t inw(uint16_t port) {
    uint16_t ret;
    __asm__ volatile("inw %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline void outw(uint16_t port, uint16_t val) {
    __asm__ volatile("outw %0, %1" : : "a"(val), "Nd"(port));
}

#define ATA_DATA 0x1F0u
#define ATA_ERR_FEAT 0x1F1u
#define ATA_SECTOR_CNT 0x1F2u
#define ATA_LBA_LO 0x1F3u
#define ATA_LBA_MID 0x1F4u
#define ATA_LBA_HI 0x1F5u

#define ATA_DRIVE_HEAD 0x1F6u
#define ATA_STATUS_CMD 0x1F7u

#define ATA_ALT_STATUS 0x3F6u

#define ATA_SR_BSY 0x80u
#define ATA_SR_DRDY 0x40u
#define ATA_SR_DRQ 0x08u
#define ATA_SR_ERR 0x01u

#define ATA_CMD_READ_SECTORS 0x20u
#define ATA_CMD_WRITE_SECTORS 0x30u
#define ATA_CMD_FLUSH_CACHE 0xE7u
#define ATA_CMD_IDENTIFY 0xECu

static void ata_400ns_delay(void) {
    inb(ATA_ALT_STATUS);
    inb(ATA_ALT_STATUS);
    inb(ATA_ALT_STATUS);
    inb(ATA_ALT_STATUS);
}

static int ata_wait_not_busy(void) {
    for (uint32_t i = 0; i < 0x10000000u; i++) {
        if (!(inb(ATA_STATUS_CMD) & ATA_SR_BSY)) {
            return 0;
        }
    }

    serial_print("[ata] bsy timeout\n");
    
    return -1;
}

static int ata_wait_drq(void) {
    for (uint32_t i = 0; i < 0x10000000u; i++) {
        uint8_t status = inb(ATA_STATUS_CMD);

        if (status & ATA_SR_ERR) {
            serial_print("[ata] drive reported err bit\n");
            
            return -1;
        }
        
        if (status & ATA_SR_DRQ) {
            return 0;
        }
    }
    
    serial_print("[ata] drq timeout\n");
    
    return -1;
}

static void ata_select_drive(int drive, uint32_t lba) {
    uint8_t val = (uint8_t)(0xE0u | ((uint32_t)(drive & 1) << 4) | ((lba >> 24) & 0x0Fu));

    outb(ATA_DRIVE_HEAD, val);
}

int ata_init(void) {
    serial_print("[ata] probing primary channel\n");

    int found = 0;

    for (int drive = 0; drive <= 1; drive++) {
        ata_select_drive(drive, 0);

        ata_400ns_delay();

        outb(ATA_SECTOR_CNT, 0);
        outb(ATA_LBA_LO, 0);
        outb(ATA_LBA_MID, 0);
        outb(ATA_LBA_HI, 0);

        outb(ATA_STATUS_CMD, ATA_CMD_IDENTIFY);

        ata_400ns_delay();

        uint8_t status = inb(ATA_STATUS_CMD);

        if (status == 0x00u) {
            serial_print(drive == 0 ? "[ata] master: not present\n" : "[ata] slave: not present\n");

            continue;
        }

        if (ata_wait_not_busy() != 0) {
            continue;
        }

        uint8_t mid = inb(ATA_LBA_MID);
        uint8_t hi = inb(ATA_LBA_HI);

        if (mid != 0 || hi != 0) {
            serial_print(drive == 0 ? "[ata] master: atapi (ignored)\n" : "[ata] slave: atapi (ignored)\n");

            continue;
        }

        if (ata_wait_drq() != 0) {
            continue;
        }

        uint16_t id[256];

        for (int i = 0; i < 256; i++) {
            id[i] = inw(ATA_DATA);
        }

        char model[41];

        for (int i = 0; i < 20; i++) {
            model[i * 2] = (char)(id[27 + i] >> 8);
            model[i * 2 + 1] = (char)(id[27 + i] & 0xFFu);
        }

        model[40] = '\0';

        for (int i = 39; i >= 0 && model[i] == ' '; i--) {
            model[i] = '\0';
        }

        uint32_t sectors = ((uint32_t)id[61] << 16) | id[60];

        serial_print(drive == 0 ? "[ata] master: \"" : "[ata] slave: \"");
        serial_print(model);
        serial_print("\"sectors=0x");
        serial_print_hex(sectors);
        serial_print("\n");

        found |= (1 << drive);
    }

    if (!found) {
        serial_print("[ata] No ata drives detected on primary channel\n");
    }

    return found;
}

int ata_read_sectors(int drive, uint32_t lba, uint8_t count, void *buf) {
    if (ata_wait_not_busy() != 0) {
        return -1;
    }

    ata_select_drive(drive, lba);

    ata_400ns_delay();

    outb(ATA_SECTOR_CNT, count);
    outb(ATA_LBA_LO, (uint8_t)( lba & 0xFFu));
    outb(ATA_LBA_MID, (uint8_t)((lba >> 8) & 0xFFu));
    outb(ATA_LBA_HI, (uint8_t)((lba >> 16) & 0xFFu));

    outb(ATA_STATUS_CMD, ATA_CMD_READ_SECTORS);

    ata_400ns_delay();

    uint16_t *p = (uint16_t *)buf;

    for (int s = 0; s < count; s++) {
        if (ata_wait_not_busy() != 0) {
            return -1;
        }
    
        if (ata_wait_drq() != 0) {
            return -1;
        }

        for (int w = 0; w < 256; w++) {
            *p++ = inw(ATA_DATA);
        }

        ata_400ns_delay();
    }

    return 0;
}

int ata_write_sectors(int drive, uint32_t lba, uint8_t count, const void *buf) {
    if (ata_wait_not_busy() != 0) {
        return -1;
    }

    ata_select_drive(drive, lba);
    ata_400ns_delay();

    outb(ATA_SECTOR_CNT, count);
    outb(ATA_LBA_LO, (uint8_t)(lba & 0xFFu));
    outb(ATA_LBA_MID, (uint8_t)((lba >> 8) & 0xFFu));
    outb(ATA_LBA_HI, (uint8_t)((lba >> 16) & 0xFFu));

    outb(ATA_STATUS_CMD, ATA_CMD_WRITE_SECTORS);

    ata_400ns_delay();

    const uint16_t *p = (const uint16_t *)buf;

    for (int s = 0; s < count; s++) {
        if (ata_wait_not_busy() != 0) {
            return -1;
        }

        if (ata_wait_drq() != 0) {
            return -1;
        }

        for (int w = 0; w < 256; w++) {
            outw(ATA_DATA, *p++);
        }

        ata_400ns_delay();
    }
    
    if (ata_wait_not_busy() != 0) {
        return -1;
    }

    ata_select_drive(drive, 0);
    ata_400ns_delay();

    outb(ATA_STATUS_CMD, ATA_CMD_FLUSH_CACHE);
    ata_400ns_delay();

    if (ata_wait_not_busy() != 0) {
        serial_print("[ata] warning: flush cache timeout, data may not be durable\n");

        return -1;
    }

    return 0;
}
