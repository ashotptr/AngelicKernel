#ifndef MPK_SECTIONS_H
#define MPK_SECTIONS_H

#define SECURE_DRIVER_CODE __attribute__((section(".secure_driver_code")))

#define SECURE_DRIVER_DATA __attribute__((section(".secure_driver_data")))

#endif