#ifndef LWIP_CUSTOM_LWIPOPTS_H
#define LWIP_CUSTOM_LWIPOPTS_H

#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define MEM_ALIGNMENT 4

#define MEM_SIZE (128 * 1024)
#define MEMP_NUM_PBUF 16
#define MEMP_NUM_TCP_PCB 16
#define PBUF_POOL_SIZE 64

#define MEMP_NUM_TCP_SEG 64

#define TCP_MSS 1460
#define TCP_WND (8 * TCP_MSS)
#define TCP_SND_BUF (8 * TCP_MSS)

#define LWIP_ARP 1
#define LWIP_ETHERNET 1
#define LWIP_IPV4 1
#define LWIP_TCP 1
#define LWIP_UDP 1
#define LWIP_ICMP 1
#define LWIP_DHCP 0

#define CHECKSUM_GEN_IP 1
#define CHECKSUM_GEN_UDP 1
#define CHECKSUM_GEN_TCP 1
#define CHECKSUM_CHECK_IP 1
#define CHECKSUM_CHECK_UDP 1
#define CHECKSUM_CHECK_TCP 1

#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_DNS 0

#endif