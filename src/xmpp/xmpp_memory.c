#include "xmpp_core.h"
#include <string.h>
#include <stddef.h>

#define MAX_POOL_STANZAS 16
static xmpp_stanza_t stanza_pool[MAX_POOL_STANZAS];

xmpp_stanza_t* xmpp_alloc_stanza() {
    for(int i=0; i<MAX_POOL_STANZAS; i++) {
        if(stanza_pool[i].is_used == 0) {            
            memset(&stanza_pool[i], 0, sizeof(xmpp_stanza_t));

            stanza_pool[i].is_used = 1;
            
            return &stanza_pool[i];
        }
    }
    return NULL;
}

void xmpp_free_stanza(xmpp_stanza_t *s) {
    if (s) {
        s->is_used = 0;
    }
}