/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ub-dtu physical device and command-queue structures.
 */

#ifndef __UMMU_DTU_COMM_H__
#define __UMMU_DTU_COMM_H__

#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/ummu_core.h>

#define UMMU_DESC_DATA_LEN	6

/* 128 descriptors, 128 * 32 = 4096 = one page, depth = 128 >> 3 = 16 */
#define UMMU_CMDQ_DESC_NUM	128

/* IMP Buffer Descriptor: 32-byte hardware format */
struct dtu_cmdq_desc {
	__le16	opcode;
	u8	flag;
	u8	bd_num;
	__le16	ret;
	__le16	rsv;
	__le32	data[UMMU_DESC_DATA_LEN];
};

/* Circular CMDQ ring buffer (producer-consumer) */
struct dtu_cmdq_ring {
	u32			head;
	u32			tail;
	u32			depth;
	u32			desc_num;
	u32			tx_timeout;
	phys_addr_t		desc_pa;
	struct dtu_cmdq_desc	*desc;
	struct mutex		lock;
};

/* Per-die command queue wrapper */
struct ub_dtu_cmdq {
	struct dtu_cmdq_ring	csq;
	unsigned long		state_bitmap; /* DTU_STATE_CMD_DISABLE etc. */
};

/* Per-die DTU hardware instance — one per ub-dtu@N DTS node */
struct ub_dtu_device {
	struct device		*dev;
	struct platform_device	*pdev;
	struct ub_dtu_cmdq	cmdq;
	void __iomem		*cmdq_base;
	struct resource		cmdq_res;
	void __iomem		*dtu_base;
	u32			index;
	bool			use_imp_cmdq;
	struct list_head	list;
};

#endif /* __UMMU_DTU_COMM_H__ */
