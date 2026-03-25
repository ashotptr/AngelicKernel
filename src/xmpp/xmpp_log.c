#include "xmpp_core.h"
#include <stdio.h>

void xmpp_log(const char *direction, const char *data, int len) {
    printf("[%s] %d bytes:\n", direction, len);
    
    for (int i = 0; i < len; i++) {
        putchar(data[i]);
    }
    
    printf("\n--------------------------------------------------\n");
}