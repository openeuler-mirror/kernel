/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_SW64_TYPES_H
#define _UAPI_ASM_SW64_TYPES_H

/*
 * This file is never included by application software unless
 * explicitly requested (e.g., via linux/types.h) in which case the
 * application is Linux specific so (user-) name space pollution is
 * not a major issue.  However, for interoperability, libraries still
 * need to be careful to avoid a name clashes.
 */

/*
 * This is here because we used to use l64 for sw64 and we don't want
 * to impact user mode with our change to ll64 in the kernel.
 *
 * However, some user programs are fine with this.  They can
 * flag __SANE_USERSPACE_TYPES__ to get int-ll64.h here.
 */
#ifndef __KERNEL__
#ifndef __SANE_USERSPACE_TYPES__
#include <asm-generic/int-l64.h>
#else
#include <asm-generic/int-ll64.h>
#endif /* __SANE_USERSPACE_TYPES__ */
#endif /* __KERNEL__ */

#endif /* _UAPI_ASM_SW64_TYPES_H */
