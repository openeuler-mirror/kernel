/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _UAPI_ASM_SW64_UNISTD_H
#define _UAPI_ASM_SW64_UNISTD_H

/*
 * These are traditionally the names uses for generic system calls
 */
#define __NR_umount     __NR_umount2

#include <asm/unistd_64.h>

/* sw64 doesn't have protection keys. */
#define __IGNORE_pkey_mprotect
#define __IGNORE_pkey_alloc
#define __IGNORE_pkey_free

#endif /* _UAPI_ASM_SW64_UNISTD_H */
