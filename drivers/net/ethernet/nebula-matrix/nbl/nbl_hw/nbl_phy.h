/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_PHY_H_
#define _NBL_PHY_H_

#include "nbl_core.h"

#define NBL_PHY_MGT_TO_COMMON(phy_mgt)		((phy_mgt)->common)
#define NBL_PHY_MGT_TO_DEV(phy_mgt)		NBL_COMMON_TO_DEV(NBL_PHY_MGT_TO_COMMON(phy_mgt))
#define NBL_MEMORY_BAR				(0)
#define NBL_MAILBOX_BAR				(2)
#define NBL_RDMA_NOTIFY_OFF			(8192)

struct nbl_phy_mgt {
	struct nbl_common_info *common;
	u8 __iomem *hw_addr;
	u8 __iomem *mailbox_bar_hw_addr;
	u64 notify_offset;
	u32 version;
	u32 hw_size;
	spinlock_t reg_lock;  /* Protect reg access */
	bool should_lock;
};

static inline __maybe_unused u32 rd32(u8 __iomem *addr, u64 reg)
{
	return readl(addr + (reg));
}

static inline __maybe_unused void wr32_barrier(u8 __iomem *addr, u64 reg, u32 value)
{
	writel((value), (addr + (reg)));
}

static inline __maybe_unused void nbl_hw_read_regs(struct nbl_phy_mgt *phy_mgt, u64 reg,
						   u8 *data, u32 len)
{
	u32 size = len / 4;
	u32 i = 0;

	if (len % 4)
		return;

	if (size > 1 && phy_mgt->should_lock)
		spin_lock(&phy_mgt->reg_lock);

	for (i = 0; i < size; i++)
		*(u32 *)(data + i * sizeof(u32)) = rd32(phy_mgt->hw_addr, reg + i * sizeof(u32));

	if (size > 1 && phy_mgt->should_lock)
		spin_unlock(&phy_mgt->reg_lock);
}

static inline __maybe_unused void nbl_hw_write_regs(struct nbl_phy_mgt *phy_mgt,
						    u64 reg, const u8 *data, u32 len)
{
	u32 size = len / 4;
	u32 i = 0;

	if (len % 4)
		return;

	if (size > 1 && phy_mgt->should_lock)
		spin_lock(&phy_mgt->reg_lock);

	for (i = 0; i < size; i++)
		/* Used for emu, make sure that we won't write too frequently */
		wr32_barrier(phy_mgt->hw_addr, reg + i * sizeof(u32),
			     *(u32 *)(data + i * sizeof(u32)));

	if (size > 1 && phy_mgt->should_lock)
		spin_unlock(&phy_mgt->reg_lock);
}

static __maybe_unused void nbl_hw_wr32(struct nbl_phy_mgt *phy_mgt, u64 reg, u32 value)
{
	/* Used for emu, make sure that we won't write too frequently */
	wr32_barrier(phy_mgt->hw_addr, reg, value);
}

static __maybe_unused u32 nbl_hw_rd32(struct nbl_phy_mgt *phy_mgt, u64 reg)
{
	return rd32(phy_mgt->hw_addr, reg);
}

static __maybe_unused void nbl_mbx_wr32(void *priv, u64 reg, u32 value)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	writel((value), ((phy_mgt)->mailbox_bar_hw_addr + (reg)));
}

static __maybe_unused u32 nbl_mbx_rd32(void *priv, u64 reg)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	return readl((phy_mgt)->mailbox_bar_hw_addr + (reg));
}

static __maybe_unused void nbl_hw_read_mbx_regs(struct nbl_phy_mgt *phy_mgt,
						u64 reg, u8 *data, u32 len)
{
	u32 i = 0;

	if (len % 4)
		return;

	for (i = 0; i < len / 4; i++)
		*(u32 *)(data + i * sizeof(u32)) = nbl_mbx_rd32(phy_mgt, reg + i * sizeof(u32));
}

static __maybe_unused void nbl_hw_write_mbx_regs(struct nbl_phy_mgt *phy_mgt,
						 u64 reg, const u8 *data, u32 len)
{
	u32 i = 0;

	if (len % 4)
		return;

	for (i = 0; i < len / 4; i++)
		/* Used for emu, make sure that we won't write too frequently */
		nbl_mbx_wr32(phy_mgt, reg + i * sizeof(u32),
			     *(u32 *)(data + i * sizeof(u32)));
}

/* Mgt structure for each product.
 * Every indivisual mgt must have the common mgt as its first member, and contains its unique
 * data structure in the reset of it.
 */
struct nbl_phy_mgt_leonis {
	struct nbl_phy_mgt phy_mgt;
	bool ro_enable;
};

struct nbl_phy_mgt_bootis {
	struct nbl_phy_mgt phy_mgt;
};

#endif
