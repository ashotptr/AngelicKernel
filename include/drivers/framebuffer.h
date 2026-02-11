#ifndef FRAMEBUFFER_H
#define FRAMEBUFFER_H

#include <efi.h>

typedef struct {
    UINT32* BaseAddress;
    UINT64 BufferSize;
    UINT32 Width;
    UINT32 Height;
    UINT32 PixelsPerScanLine;
} Framebuffer;

// Global instance to use after exit
static Framebuffer gFb;

// Simple function to paint a pixel
static void put_pixel(UINT32 x, UINT32 y, UINT32 color) {
    if (x >= gFb.Width || y >= gFb.Height) return;
    UINT32 index = x + (y * gFb.PixelsPerScanLine);
    gFb.BaseAddress[index] = color;
}

// Draw a box (visual heartbeat)
static inline void draw_rect(UINT32 x, UINT32 y, UINT32 w, UINT32 h, UINT32 color) {
    for (UINT32 i = 0; i < w; i++) {
        for (UINT32 j = 0; j < h; j++) {
            put_pixel(x + i, y + j, color);
        }
    }
}

#endif