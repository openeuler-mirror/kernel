/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * Copyright(c) 2026 HiSilicon Technologies CO., All rights reserved.
 * Description: HiSilicon implementation of the ummu data structure definition.
 */

#ifndef _HISI_UMMU_H_
#define _HISI_UMMU_H_

#include <linux/types.h>

struct hisi_ummu_tdev_info {
	__u32 version;
	union {
		struct {
			__u64 ummu_idx_mask;
			__u8 on_chip;
		} v1;
		struct {
			__u64 reserved;
			__u8 on_chip;
			__u32 tid;
		} v2;
	};
};

#endif /* _HISI_UMMU_H_ */
