// include/sys/mpk_sections.h
#ifndef MPK_SECTIONS_H
#define MPK_SECTIONS_H

// In Phase 1: These define nothing.
// In Phase 2: You will change this to __attribute__((section(".secure_driver")))
// This forces the linker to group these functions on their own 4KB pages.

#define SECURE_DRIVER_CODE 
#define SECURE_DRIVER_DATA 

#endif