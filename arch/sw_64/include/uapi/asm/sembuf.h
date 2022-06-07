/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_SW64_SEMBUF_H
#define _UAPI_ASM_SW64_SEMBUF_H

/*
 * The semid64_ds structure for sw64 architecture.
 * Note extra padding because this structure is passed back and forth
 * between kernel and user space.
 *
 * Pad space is left for:
 * - 2 miscellaneous 64-bit values
 */

struct semid64_ds {
	struct ipc64_perm sem_perm;		/* permissions .. see ipc.h */
	long		sem_otime;		/* last semop time */
	long		sem_ctime;		/* last change time */
	unsigned long	sem_nsems;		/* no. of semaphores in array */
	unsigned long	__unused1;
	unsigned long	__unused2;
};

#endif /* _UAPI_ASM_SW64_SEMBUF_H */
