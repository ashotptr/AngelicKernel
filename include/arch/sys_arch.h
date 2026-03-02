#ifndef LWIP_ARCH_SYS_ARCH_H
#define LWIP_ARCH_SYS_ARCH_H

// NO_SYS=1 mode means we don't need real OS primitives.
// These defines satisfy the compiler.

#define SYS_MBOX_NULL   NULL
#define SYS_SEM_NULL    NULL

// We don't need protection because we aren't using threads.
// When calling lwIP from interrupts, must implement this.
typedef u32_t sys_prot_t;

// typedef void * sys_sem_t;

// typedef void * sys_mbox_t;

// typedef void * sys_thread_t;

#define sys_arch_protect()      0
#define sys_arch_unprotect(x)   do { (void)(x); } while(0)

#endif