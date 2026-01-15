#include <efi.h>
#include <efilib.h>

// ---------------------------------------------------------
// 1. Data Structures (Headers)
// ---------------------------------------------------------
typedef struct {
    uint8_t dest[6]; uint8_t src[6]; uint16_t type;      
} __attribute__((packed)) ethernet_frame_t;

typedef struct {
    uint16_t hw_type; uint16_t proto_type;
    uint8_t  hw_len; uint8_t  proto_len;
    uint16_t opcode;
    uint8_t  sender_mac[6]; uint32_t sender_ip;
    uint8_t  target_mac[6]; uint32_t target_ip;
} __attribute__((packed)) arp_packet_t;

typedef struct {
    uint8_t  version_ihl; // Version(4) + IHL(5) = 0x45
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;    // 1 = ICMP, 17 = UDP
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
} __attribute__((packed)) ipv4_header_t;

typedef struct {
    uint8_t  type;        // 8 = Request, 0 = Reply
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} __attribute__((packed)) icmp_header_t;

// Hardware Descriptors
struct e1000_tx_desc {
    uint64_t addr; uint16_t length; uint8_t cso; uint8_t cmd;
    uint8_t status; uint8_t css; uint16_t special;
} __attribute__((packed));

struct e1000_rx_desc {
    uint64_t addr; uint16_t length; uint16_t checksum;
    uint8_t status; uint8_t errors; uint16_t special;
} __attribute__((packed));

typedef struct {
    uint16_t VendorID; uint16_t DeviceID; uint16_t Command;
    uint16_t Status; uint8_t RevisionID; uint8_t ProgIF;
    uint8_t SubClass; uint8_t ClassCode; uint8_t CacheLineSize;
    uint8_t LatencyTimer; uint8_t HeaderType; uint8_t BIST;
    uint32_t BAR0;      
} __attribute__((packed)) PCI_HEADER;

// ---------------------------------------------------------
// 2. Globals
// ---------------------------------------------------------
uint64_t mmio_base_global = 0; 
struct e1000_tx_desc *tx_ring_base;
struct e1000_rx_desc *rx_ring_base;
uint8_t *rx_buffer_pool; 
uint32_t tx_tail_index = 0;
uint32_t rx_tail_index = 0;

uint8_t my_mac[6]; 
uint8_t gateway_mac[6] = {0}; // Starts Empty
int gateway_found = 0;        // Flag

// ---------------------------------------------------------
// 3. Helpers (Checksum & Utils)
// ---------------------------------------------------------
uint16_t swap16(uint16_t val) { return (val << 8) | (val >> 8); }

// Standard Internet Checksum Algorithm
uint16_t calculate_checksum(void *data, int len) {
    uint32_t sum = 0;
    uint16_t *p = (uint16_t *)data;
    
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len) sum += *(uint8_t *)p;
    
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

void print_byte(EFI_SYSTEM_TABLE *SystemTable, uint8_t n) {
    CHAR16 hex[] = L"0123456789ABCDEF";
    CHAR16 buf[3];
    buf[0] = hex[(n >> 4) & 0xF];
    buf[1] = hex[n & 0xF];
    buf[2] = L'\0';
    SystemTable->ConOut->OutputString(SystemTable->ConOut, buf);
}

void * allocate_aligned_pages(EFI_SYSTEM_TABLE *ST, UINTN pages) {
    EFI_PHYSICAL_ADDRESS phys;
    ST->BootServices->AllocatePages(AllocateAnyPages, EfiLoaderData, pages, &phys);
    return (void *)(uintptr_t)phys;
}

// ---------------------------------------------------------
// 4. Driver Logic
// ---------------------------------------------------------
void init_tx(EFI_SYSTEM_TABLE *SystemTable) {
    tx_ring_base = allocate_aligned_pages(SystemTable, 1);
    SystemTable->BootServices->SetMem(tx_ring_base, 4096, 0);

    volatile uint32_t *tdbal = (volatile uint32_t *)(mmio_base_global + 0x3800); 
    volatile uint32_t *tdbah = (volatile uint32_t *)(mmio_base_global + 0x3804); 
    volatile uint32_t *tdlen = (volatile uint32_t *)(mmio_base_global + 0x3808); 
    volatile uint32_t *tdh   = (volatile uint32_t *)(mmio_base_global + 0x3810); 
    volatile uint32_t *tdt   = (volatile uint32_t *)(mmio_base_global + 0x3818); 
    volatile uint32_t *tctl  = (volatile uint32_t *)(mmio_base_global + 0x0400); 

    *tdbal = (uint32_t)(uint64_t)tx_ring_base;
    *tdbah = (uint32_t)((uint64_t)tx_ring_base >> 32);
    *tdlen = 512; *tdh = 0; *tdt = 0; 
    *tctl = (1 << 1) | (1 << 3) | (15 << 4) | (64 << 12);
}

void init_rx(EFI_SYSTEM_TABLE *SystemTable) {
    rx_ring_base = allocate_aligned_pages(SystemTable, 1);
    SystemTable->BootServices->SetMem(rx_ring_base, 4096, 0);
    rx_buffer_pool = allocate_aligned_pages(SystemTable, 16);

    for(int i=0; i<32; i++) {
        rx_ring_base[i].addr = (uint64_t)(rx_buffer_pool + (i * 2048));
        rx_ring_base[i].status = 0; 
    }

    volatile uint32_t *rdbal = (volatile uint32_t *)(mmio_base_global + 0x2800);
    volatile uint32_t *rdbah = (volatile uint32_t *)(mmio_base_global + 0x2804);
    volatile uint32_t *rdlen = (volatile uint32_t *)(mmio_base_global + 0x2808);
    volatile uint32_t *rdh   = (volatile uint32_t *)(mmio_base_global + 0x2810);
    volatile uint32_t *rdt   = (volatile uint32_t *)(mmio_base_global + 0x2818);
    volatile uint32_t *rctl  = (volatile uint32_t *)(mmio_base_global + 0x0100);

    *rdbal = (uint32_t)(uint64_t)rx_ring_base;
    *rdbah = (uint32_t)((uint64_t)rx_ring_base >> 32);
    *rdlen = 512; *rdh = 0; *rdt = 0; 
    *rctl = (1 << 1) | (1 << 3) | (1 << 4) | (1 << 15) | (1 << 26);
    
    for(volatile int k=0; k<10000; k++) {}
    *rdt = 31; 
}

void send_packet(EFI_SYSTEM_TABLE *SystemTable, void *data, uint16_t len) {
    (void)SystemTable;
    struct e1000_tx_desc *desc = &tx_ring_base[tx_tail_index];
    desc->addr = (uint64_t)data;
    desc->length = len;
    desc->cmd = 0x0B; desc->status = 0;
    tx_tail_index = (tx_tail_index + 1) % 32;
    volatile uint32_t *tdt = (volatile uint32_t *)(mmio_base_global + 0x3818);
    *tdt = tx_tail_index;
}

// ---------------------------------------------------------
// 5. Network Functions (ARP & Ping)
// ---------------------------------------------------------

void send_arp_request(EFI_SYSTEM_TABLE *SystemTable) {
    static uint8_t buffer[128];
    SystemTable->BootServices->SetMem(buffer, 128, 0);

    ethernet_frame_t *eth = (ethernet_frame_t *)buffer;
    arp_packet_t *arp = (arp_packet_t *)(buffer + sizeof(ethernet_frame_t));

    for(int i=0; i<6; i++) eth->dest[i] = 0xFF; // Broadcast
    for(int i=0; i<6; i++) eth->src[i] = my_mac[i];
    eth->type = swap16(0x0806);

    arp->hw_type = swap16(1);
    arp->proto_type = swap16(0x0800);
    arp->hw_len = 6; arp->proto_len = 4;
    arp->opcode = swap16(1);

    for(int i=0; i<6; i++) arp->sender_mac[i] = my_mac[i];
    arp->sender_ip = 0x0F02000A; // 10.0.2.15
    for(int i=0; i<6; i++) arp->target_mac[i] = 0x00;
    arp->target_ip = 0x0202000A; // 10.0.2.2

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L".");
    send_packet(SystemTable, buffer, 60);
}

void send_ping(EFI_SYSTEM_TABLE *SystemTable) {
    static uint8_t buffer[128];
    SystemTable->BootServices->SetMem(buffer, 128, 0);

    ethernet_frame_t *eth = (ethernet_frame_t *)buffer;
    ipv4_header_t *ip = (ipv4_header_t *)(buffer + sizeof(ethernet_frame_t));
    icmp_header_t *icmp = (icmp_header_t *)(buffer + sizeof(ethernet_frame_t) + sizeof(ipv4_header_t));

    // 1. Ethernet Header (Use the discovered Gateway MAC)
    for(int i=0; i<6; i++) eth->dest[i] = gateway_mac[i];
    for(int i=0; i<6; i++) eth->src[i] = my_mac[i];
    eth->type = swap16(0x0800); // IPv4

    // 2. IP Header
    ip->version_ihl = 0x45; // Ver 4, Header Len 5 words (20 bytes)
    ip->total_length = swap16(sizeof(ipv4_header_t) + sizeof(icmp_header_t));
    ip->id = swap16(0x1234);
    ip->flags_frag = 0;
    ip->ttl = 64;
    ip->protocol = 1; // ICMP
    ip->src_ip = 0x0F02000A; // 10.0.2.15
    ip->dest_ip = 0x0202000A; // 10.0.2.2
    ip->checksum = 0; // Calc later
    ip->checksum = calculate_checksum(ip, sizeof(ipv4_header_t));

    // 3. ICMP Header
    icmp->type = 8; // Echo Request
    icmp->code = 0;
    icmp->id = swap16(1);
    icmp->sequence = swap16(1);
    icmp->checksum = 0;
    icmp->checksum = calculate_checksum(icmp, sizeof(icmp_header_t));

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L" [PING] ");
    send_packet(SystemTable, buffer, sizeof(ethernet_frame_t) + sizeof(ipv4_header_t) + sizeof(icmp_header_t));
}

void check_for_packets(EFI_SYSTEM_TABLE *SystemTable) {
    volatile struct e1000_rx_desc *desc = &rx_ring_base[rx_tail_index];
    
    if ((desc->status & 0x1)) {
        uint8_t *pkt = (uint8_t *)(rx_buffer_pool + (rx_tail_index * 2048));
        ethernet_frame_t *eth = (ethernet_frame_t *)pkt;
        uint16_t type = swap16(eth->type);

        // --- HANDLE ARP ---
        if (type == 0x0806) {
            arp_packet_t *arp = (arp_packet_t *)(pkt + sizeof(ethernet_frame_t));
            if (swap16(arp->opcode) == 2) {
                // If we haven't found gateway yet, save it!
                if (!gateway_found) {
                    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n  [ARP]     Gateway MAC Found: ");
                    for(int i=0; i<6; i++) {
                        gateway_mac[i] = arp->sender_mac[i];
                        print_byte(SystemTable, gateway_mac[i]);
                        if(i<5) SystemTable->ConOut->OutputString(SystemTable->ConOut, L":");
                    }
                    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n");
                    gateway_found = 1; // ENABLE PING MODE
                }
            }
        }
        
        // --- HANDLE IPv4 ---
        if (type == 0x0800) {
            ipv4_header_t *ip = (ipv4_header_t *)(pkt + sizeof(ethernet_frame_t));
            // Protocol 1 = ICMP
            if (ip->protocol == 1) {
                icmp_header_t *icmp = (icmp_header_t *)(pkt + sizeof(ethernet_frame_t) + sizeof(ipv4_header_t));
                // Type 0 = Echo Reply
                if (icmp->type == 0) {
                    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n  [SUCCESS] PONG! Gateway replied to Ping!\r\n");
                }
            }
        }

        desc->status = 0;
        rx_tail_index = (rx_tail_index + 1) % 32;
        volatile uint32_t *rdt = (volatile uint32_t *)(mmio_base_global + 0x2818);
        *rdt = (rx_tail_index + 31) % 32; 
    }
}

EFI_STATUS efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    (void)ImageHandle;
    SystemTable->ConOut->Reset(SystemTable->ConOut, 1);
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n  [KERNEL]  XMPP Unikernel Booting... \r\n");

    EFI_GUID PciIoProtocolGuid = EFI_PCI_IO_PROTOCOL_GUID;
    EFI_PCI_IO_PROTOCOL *PciIo;
    UINTN HandleCount;
    EFI_HANDLE *HandleBuffer;
    PCI_HEADER PciHeader;

    SystemTable->BootServices->LocateHandleBuffer(ByProtocol, &PciIoProtocolGuid, NULL, &HandleCount, &HandleBuffer);

    for (UINTN i = 0; i < HandleCount; i++) {
        SystemTable->BootServices->HandleProtocol(HandleBuffer[i], &PciIoProtocolGuid, (void **)&PciIo);
        PciIo->Pci.Read(PciIo, EfiPciIoWidthUint32, 0, sizeof(PCI_HEADER)/4, &PciHeader);

        if (PciHeader.VendorID == 0x8086 && PciHeader.DeviceID == 0x100E) {
            SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [FOUND]   Intel e1000 Network Card!\r\n");
            uint16_t cmd;
            PciIo->Pci.Read(PciIo, EfiPciIoWidthUint16, 0x04, 1, &cmd);
            cmd |= 0x4; PciIo->Pci.Write(PciIo, EfiPciIoWidthUint16, 0x04, 1, &cmd);
            mmio_base_global = (uint64_t)(PciHeader.BAR0 & 0xFFFFFFF0);
            
            volatile uint32_t *imc = (volatile uint32_t *)(mmio_base_global + 0x00D8);
            *imc = 0xFFFFFFFF;
            volatile uint32_t *ral = (volatile uint32_t *)(mmio_base_global + 0x5400);
            volatile uint32_t *rah = (volatile uint32_t *)(mmio_base_global + 0x5404);
            uint32_t low = *ral; uint32_t high = *rah;
            my_mac[0] = low & 0xFF; my_mac[1] = (low >> 8) & 0xFF;
            my_mac[2] = (low >> 16) & 0xFF; my_mac[3] = (low >> 24) & 0xFF;
            my_mac[4] = high & 0xFF; my_mac[5] = (high >> 8) & 0xFF;
            *rah |= 0x80000000;
            init_tx(SystemTable);
            init_rx(SystemTable);
        }
    }

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [KERNEL]  Resolving Gateway... \r\n");

    uint64_t timer = 0;
    while(1) { 
        check_for_packets(SystemTable);
        timer++;
        
        if (timer % 5000000 == 0) {
            if (gateway_found == 0) {
                // Phase 1: Keep asking "Who is Gateway?"
                send_arp_request(SystemTable);
            } else {
                // Phase 2: Gateway Found! Spam Pings!
                send_ping(SystemTable);
            }
        }
        __asm__ __volatile__("pause");
    }
    return EFI_SUCCESS;
}