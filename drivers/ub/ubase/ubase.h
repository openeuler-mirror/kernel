/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_H__
#define __UBASE_H__

#include <linux/bitmap.h>
#include <linux/io.h>

#define UBASE_CAP_LEN			3
#define UBASE_MAX_TCG_NUM		(4)
#define UBASE_PMEM_PAGE_SIZE		(2 * 1024 * 1024UL) /* 2MB */

#define UBASE_FAULT_MODULE_ID		(0)
#define UBASE_FAULT_EVENT_PROBE		(0)
#define UBASE_FAULT_EVENT_REMOVE	(1)

#define UBASE_FAULT_EVENT_ID_PROBE	(UBASE_FAULT_MODULE_ID << 24 | \
					 UBASE_FAULT_EVENT_PROBE)
#define UBASE_FAULT_EVENT_ID_REMOVE	(UBASE_FAULT_MODULE_ID << 24 | \
					 UBASE_FAULT_EVENT_REMOVE)

enum ubase_service_state {
	UBASE_STATE_CRQ_SERVICE_SCHED,
	UBASE_STATE_CRQ_HANDLING,
	UBASE_SERVICE_STATE_ERR_SCHED,
	UBASE_SERVICE_STATE_RESET_SCHED,
	UBASE_STATE_CTRLQ_SERVICE_SCHED,
	UBASE_STATE_CTRLQ_HANDLING,
	UBASE_STATE_ARQ_SERVICE_SCHED,
	UBASE_STATE_ARQ_HANDLING,
};

struct ubase_delay_work {
	struct delayed_work	service_task;
	unsigned long		state;
};

enum {
	UBASE_SUPPORT_UBL_B		= 0,
	UBASE_SUPPORT_TA_EXTDB_BUF_B	= 2,
	UBASE_SUPPORT_TA_TIMER_BUF_B	= 3,
	UBASE_SUPPORT_ERR_HANDLE_B	= 4,
	UBASE_SUPPORT_CTRLQ_B		= 5,
	UBASE_SUPPORT_ETH_MAC_B		= 6,
	UBASE_SUPPORT_MAC_STATS_B	= 10,
	UBASE_SUPPORT_PRE_ALLOC_B		= 13,
	UBASE_SUPPORT_UDMA_DISABLE_B		= 14,
	UBASE_SUPPORT_UNIC_DISABLE_B		= 15,
	UBASE_SUPPORT_UVB_B			= 16,
	UBASE_SUPPORT_IP_OVER_URMA_B		= 17,
	UBASE_SUPPORT_IP_OVER_URMA_UTP_B	= 18,
	UBASE_SUPPORT_ACTIVATE_PROXY_B		= 19,
	UBASE_SUPPORT_UTP_B			= 20,
	UBASE_SUPPORT_DTU_B			= 21,
	UBASE_SUPPORT_USC_B			= 22,
	UBASE_SUPPORT_UCP_B			= 23,
	UBASE_SUPPORT_PMU_IRQ_B			= 24,

	/* must be last entry and it should <= UBASE_CAP_LEN * 32 */
	UBASE_SUPPORT_MASK_NBITS
};

#define ubase_get_cap_bit(udev, nr) \
	test_bit(nr, (unsigned long *)((udev)->cap_bits))

static inline void ubase_write_reg(void __iomem *base, u32 reg, u32 value)
{
	writel(value, base + reg);
}

static inline u32 ubase_read_reg(u8 __iomem *base, u32 reg)
{
	u8 __iomem *reg_addr = READ_ONCE(base);

	return readl(reg_addr + reg);
}

#define ubase_write_dev(a, reg, value) \
	ubase_write_reg((a)->io_base.addr, reg, value)
#define ubase_read_dev(a, reg) \
	ubase_read_reg((a)->io_base.addr, reg)

#define ubase_addr_gen(addr_h, addr_l) ((u64)(addr_h) << 32 | (addr_l))
#define ubase_size_gen(size_h, size_l) ((u64)(size_h) << 32 | (size_l))

#endif /* __UBASE_H__ */
