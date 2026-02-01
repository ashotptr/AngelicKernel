#ifndef MPK_SECTIONS_H
#define MPK_SECTIONS_H

// code in a section we will mark as 'Execute Only' or 'Read Only' for the rest of the kernel
#define SECURE_DRIVER_CODE __attribute__((section(".secure_driver_code")))

// rings and buffers in a section protected by MPK Key 1
#define SECURE_DRIVER_DATA __attribute__((section(".secure_driver_data")))

#endif