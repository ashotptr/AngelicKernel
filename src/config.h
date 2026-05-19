#ifndef ANGELIC_CONFIG_H
#define ANGELIC_CONFIG_H

#define ANGELIC_IP_0 10
#define ANGELIC_IP_1 0
#define ANGELIC_IP_2 2
#define ANGELIC_IP_3 15

#define ANGELIC_NM_0 255
#define ANGELIC_NM_1 255
#define ANGELIC_NM_2 255
#define ANGELIC_NM_3 0

#define ANGELIC_GW_0 10
#define ANGELIC_GW_1 0
#define ANGELIC_GW_2 2
#define ANGELIC_GW_3 2

#define ANGELIC_XMPP_PORT 5222
#define ANGELIC_XMPP_DOMAIN "angelic.local"

#define ANGELIC_NIC_VENDOR 0x8086u

#define ANGELIC_NIC_IDS { \
    0x100Eu, \
    0x1076u, \
    0x100Fu, \
    0x1079u, \
    0x107Cu, \
    0x1010u, \
    0x1011u, \
    0x1026u, \
    0x0000u \
}

#define ANGELIC_RAM_MB 512

#define ANGELIC_SERIAL_PORT 0x3F8u
#define ANGELIC_SERIAL_BAUD 115200u

_Static_assert(ANGELIC_XMPP_PORT > 0 && ANGELIC_XMPP_PORT < 65536,
               "ANGELIC_XMPP_PORT out of range");

#endif
