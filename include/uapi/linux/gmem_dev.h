/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_GMEM_DEV_H
#define _UAPI_LINUX_GMEM_DEV_H

#include <linux/ioctl.h>

#define GMEM_MAGIC 0x55

#define _GMEM_GET_HNUMA_ID	1

struct gmem_hnid_arg {
	int *hnuma_id;
};

#define GMEM_GET_HNUMA_ID _IOW(GMEM_MAGIC, _GMEM_GET_HNUMA_ID, struct gmem_hnid_arg)

#endif
