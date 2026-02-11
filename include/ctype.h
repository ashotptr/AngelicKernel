#ifndef _CTYPE_H
#define _CTYPE_H

// A minimal ctype.h for bare metal LwIP

static inline int isdigit(int c) { 
    return (c >= '0' && c <= '9'); 
}

static inline int isxdigit(int c) { 
    return (c >= '0' && c <= '9') || 
           (c >= 'a' && c <= 'f') || 
           (c >= 'A' && c <= 'F'); 
}

static inline int isspace(int c) { 
    return (c == ' ' || c == '\f' || c == '\n' || 
            c == '\r' || c == '\t' || c == '\v'); 
}

static inline int islower(int c) { 
    return (c >= 'a' && c <= 'z'); 
}

static inline int isupper(int c) { 
    return (c >= 'A' && c <= 'Z'); 
}

static inline int tolower(int c) { 
    return isupper(c) ? (c + 32) : c; 
}

static inline int toupper(int c) { 
    return islower(c) ? (c - 32) : c; 
}

#endif