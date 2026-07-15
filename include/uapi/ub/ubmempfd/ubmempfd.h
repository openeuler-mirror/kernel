/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ubmempfd defines and function prototypes
 */

#ifndef _UAPI_UB_UBMEMPFD_UBMEMPFD_H_
#define _UAPI_UB_UBMEMPFD_UBMEMPFD_H_

#include <linux/kernel.h>
#include <linux/types.h>

enum ubmempfd_opcode {
	UBMEMPFD_OPCODE_MAP = 0,
	UBMEMPFD_OPCODE_UNMAP = 1,
	UBMEMPFD_OPCODE_DEFAULT = 2
};

struct ubm_request {
	__u32 opcode;
	__u32 tid;
	__u64 uba;
	__u64 size;
	__u64 areas_num;
	struct {
		__u64 hva;
		__u64 size;
	} areas[];
};

#endif /*_UAPI_UB_UBMEMPFD_UBMEMPFD_H_*/

