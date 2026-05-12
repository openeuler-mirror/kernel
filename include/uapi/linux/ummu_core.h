/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU-CORE defines and function prototypes.
 */

#ifndef _UAPI_UMMU_CORE_H_
#define _UAPI_UMMU_CORE_H_

#include <linux/types.h>

enum ummu_mapt_perm {
	MAPT_PERM_W = 1,
	MAPT_PERM_R = 2,
	MAPT_PERM_RW = 3,
	MAPT_PERM_ATOMIC_W = 5,
	MAPT_PERM_ATOMIC_R = 6,
	MAPT_PERM_ATOMIC_RW = 7
};

enum ummu_mapt_mode {
	MAPT_MODE_TABLE = 0,
	MAPT_MODE_ENTRY = 1,
	MAPT_MODE_END
};

enum ummu_ebit_state {
	UMMU_EBIT_OFF = 0,
	UMMU_EBIT_ON = 1,
	UMMU_EBIT_END
};

struct ummu_token_info {
	/* 0:input, 1:output */
	unsigned int input;
	unsigned int tokenVal;

	struct {
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
	} kabi_reserve;
};

struct ummu_tid_attr {
	enum ummu_mapt_mode mode;

	struct {
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
	} kabi_reserve;
};

struct ummu_seg_attr {
	struct ummu_token_info *token;
	enum ummu_ebit_state e_bit;

	struct {
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
	} kabi_reserve;
};

struct ummu_tid_info {
	unsigned char pcmdq_order;
	unsigned char pcplq_order;
	int expan;
	unsigned long blk_exp_size;
	unsigned long dev;
	unsigned int tid;
	unsigned int ummu_cnt;
	enum ummu_mapt_mode mode;
	__u64 hw_cap;
	__u64 va;
	__u64 size;

	struct {
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
		__u64:64;
	} kabi_reserve;
};

#define HW_CAP_EXPAN (1UL << 0)
#define HW_CAP_DOUBLE_PLBI (1UL << 1)
#define HW_CAP_KCMD_PLBI (1UL << 2)
#define HW_CAP_IOPF (1UL << 3)
#define HW_CAP_FREE_BIT (1UL << 4)
#define HW_CAP_PPLBI (1UL << 5)

#define TID_MISC_NAME "ummu/tid"
#define TID_DEVICE_NAME "/dev/" TID_MISC_NAME

#define UMMU_IOC_MAGIC ((unsigned int)'k')

#define UMMU_IOCALLOC_TID _IOW(UMMU_IOC_MAGIC, 4U, struct ummu_tid_info)
#define UMMU_IOCFREE_TID _IOW(UMMU_IOC_MAGIC, 5U, struct ummu_tid_info)
#define UMMU_IOCPLBI_VA _IOW(UMMU_IOC_MAGIC, 6U, struct ummu_tid_info)
#define UMMU_IOCPLBI_ALL _IOW(UMMU_IOC_MAGIC, 7U, struct ummu_tid_info)

#define BLOCK_SIZE_4K		0x00001000
#define BLOCK_SIZE_16K		0x00004000
#define BLOCK_SIZE_32K		0x00008000
#define BLOCK_SIZE_64K		0x00010000
#define BLOCK_SIZE_128K		0x00020000
#define BLOCK_SIZE_2M		0x00200000

#define MMAP_TYPE_BLOCK (1UL)
#define MMAP_TYPE_MUTIQ (2UL)

#define BLOCK_MAX_INDEX 512
#define COMPRESSED_SHIFT 12
#define UMMU_OFFSET_OP_SHIFT PAGE_SHIFT
#define UMMU_OFFSET_INDEX_SHIFT (UMMU_OFFSET_OP_SHIFT + 2U)
#define UMMU_OFFSET_SIZE_SHIFT (UMMU_OFFSET_INDEX_SHIFT + 10U)

/*
 *|20bit|10bit|2bit|page_shift|
 *| tid |index|op  | rsv      |
 */

#define UMMU_OFFSET_BLK(index, tid) (((MMAP_TYPE_BLOCK) << (UMMU_OFFSET_OP_SHIFT)) \
					| (((__u64)(index)) << (UMMU_OFFSET_INDEX_SHIFT)) \
					| (((__u64)(tid)) << (UMMU_OFFSET_SIZE_SHIFT)))

#define UMMU_OFFSET_QUE(tid) ((MMAP_TYPE_MUTIQ) << (UMMU_OFFSET_OP_SHIFT) \
				| (((__u64)(tid)) << (UMMU_OFFSET_INDEX_SHIFT)))

#endif /* UMMU_CORE_H */
