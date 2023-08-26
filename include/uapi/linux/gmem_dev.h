/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_GMEM_DEV_H
#define _UAPI_LINUX_GMEM_DEV_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define GMEM_MAGIC 0x55

#define _GMEM_GET_HNUMA_ID	1
#define _GMEM_MADVISE		2

struct gmem_hnid_arg {
	int *hnuma_id;
};

struct hmadvise_arg {
	int hnid;
	unsigned long start;
	__kernel_size_t len_in;
	int behavior;
};

#define GMEM_GET_HNUMA_ID _IOW(GMEM_MAGIC, _GMEM_GET_HNUMA_ID, struct gmem_hnid_arg)
#define GMEM_MADVISE _IOW(GMEM_MAGIC, _GMEM_MADVISE, struct hmadvise_arg)

#endif
