// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include <linux/pci.h>
#include <linux/device.h>
#include <linux/log2.h>

#include "../mce.h"
#include "../mce_fdir.h"
#include "../mce_vf_lib.h"
#include "../mce_lib.h"
#include "../mce_mbx.h"
#include "../mce_base.h"
#include "mce_hw_n20.h"
#include "mce_hw_debugfs.h"
#include "mce_hw_dcb.h"
#include "mce_hw_npu.h"
#include "mce_hw_fdir.h"
#include "mce_hw_ptp.h"
#include "../mce_fwchnl.h"

/* pf_vf_num[8]: 0:pf 1:vf
 * pf_vf_num[7:0]: vfnum
 */

static void n20_init_vport_bitmap_clear_ram(struct mce_hw *hw)
{
	int i;

	for (i = 0; i < 1024; i++) {
		wr32(hw, N20_ETH_VPORT_BITMAP_MEM0(i), 0);
		wr32(hw, N20_ETH_VPORT_BITMAP_MEM1(i), 0);
		wr32(hw, N20_ETH_VPORT_BITMAP_MEM2(i), 0);
		wr32(hw, N20_ETH_VPORT_BITMAP_MEM3(i), 0);
	}
}

static void n20_init_etype_clear_ram(struct mce_hw *hw)
{
	int i, j;

	for (i = 0; i < MCE_LIMIT_VFS; i++) {
		for (j = 0; j < 16; j++) {
			wr32(hw, N20_ETH_RQA_ETQF_OFF(i, j), 0);
			wr32(hw, N20_ETH_RQA_ETQS_OFF(i, j), 0);
		}
	}
}

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
static void n20_init_fd_clear_ram(struct mce_hw *hw)
{
	hw->ops->fd_clear_hw(hw);
}
#endif

static void n20_init_vport_mc_vlan_clear_ram(struct mce_hw *hw)
{
	/* clear vf multicast filter table */
	hw->vf.ops->set_vf_clear_mc_filter(hw, false);
	/* clear vf vlan filter table */
	hw->vf.ops->set_vf_clear_all_flr_vlan(hw);
}

static void n20_init_rss_clear_ram(struct mce_hw *hw)
{
	int i, j;

#define __N20_RSS_HASH_ENTRY(i, j) ((0x0000 + ((j) << 2)) + (i) * 0x40)
	for (i = 0; i < MCE_LIMIT_VFS; i++) {
		for (j = 0; j < 14; j++)
			wr32(hw, N20_RSS_OFF(__N20_RSS_HASH_ENTRY(i, j)), 0);
	}
}

static void n20_update_pf_stat(struct mce_hw *hw)
{
	int speed = speed_unzip(hw->fw_stat.stat0.s_speed);
	u64 tmp = 0;
	u32 val = 0;

	/* update link speed to tc control */
	if (hw->fw_stat.stat0.linkup) {
		if (hw->speed_limit)
			speed = min_t(int, speed, hw->speed_limit);

		val = rd32(hw, N20_DMA_TC_TAL_BW);

		/* update for dcb use */
		hw->qos.link_speed = speed;

		val |= F_PF_BW_EN;
		tmp = ((speed  * 1000) >> 9) * 500 / hw->axi_mhz;

		tmp = tmp * hw->qos.interal;
		val |= (tmp & (0x3fffffff));
	}
	wr32(hw, N20_DMA_TC_TAL_BW, val);
	/* update mac status here */
	mce_mbx_set_pf_stat_reg(hw);
}

static void n20_update_fw_stat(struct mce_hw *hw)
{
	int ret;

	hw->fw_stat.stat0.v = raw_rd32(hw->dm_stat);
	hw->fw_stat.stat1.v = raw_rd32(hw->nic_stat);
	hw->fw_stat.stat2.v = raw_rd32(hw->ext2_stat);

	ret = mce_mbx_get_fw_stat(&hw->fw_mbx, FW_NIC_RESET_DONE_STAT);
	if (ret >= 0)
		hw->fw_stat.fw_nic_reset_done = ret;

	ret = mce_mbx_get_fw_stat(&hw->fw_mbx, FW_NR_PF);
	if (ret >= 0) {
		hw->pfvfnum.pf = ret & 1;
	} else {
		hw->pfvfnum.pf = 0;
		dev_err(hw->dev, "get pf id from firmware failed, default 0\n");
	}
	hw->nr_pf = hw->pfvfnum.pf;
}

static void n20_wait_nic_reset_done(struct mce_hw *hw, int timeout_ms)
{
	while (timeout_ms > 0) {
		n20_update_fw_stat(hw);
		if (hw->fw_stat.fw_nic_reset_done)
			break;
		usleep_range(1000, 1100);
		timeout_ms--;
	}
	if (!timeout_ms)
		dev_err(hw->dev, "wait for fw nic reset done timeout\n");
}

static void n20_reset_hw(struct mce_hw *hw)
{
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	int time = 0;
	u32 val;

	/* reset nic */
	wr32(hw, N20_NIC_RESET, 0 | F_NIC_RESET_MASK);
	usleep_range(1000, 1100);
	wr32(hw, N20_NIC_RESET, F_NIC_RESET_EN | F_NIC_RESET_MASK);
	usleep_range(1000, 1100);

	if (hw->rdma_bar_base) {
		/* reset rdma */
		rdma_wr32(hw, N20_RDMA_BTH(0x1c), 1);

		do {
			val = rdma_rd32(hw, N20_RDMA_BTH(0x20));
			usleep_range(1000, 1100);
			time++;
			if (time > 10) {
				dev_err(hw->dev, "reset rdma timeout\n");
				break;
			}
		} while (val != 1);

		if (time < 10) {
			rdma_wr32(hw, N20_RDMA_BTH(0x18), 0);
			usleep_range(1000, 1100);
			rdma_wr32(hw, N20_RDMA_BTH(0x18), 1);
			usleep_range(1000, 1100);
			rdma_wr32(hw, N20_RDMA_BTH(0x1c), 0);
			dev_info(hw->dev, "reset rdma ok\n");
		}
	}

	/* mask all misc interrupt when nic reset */
	hw->ops->set_misc_irq_mask(hw, MCE_MAC_MISC_IRQ_ALL, true);
	wr32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_CLR), 0x0);
	/* clear nic ram */
	n20_init_vport_bitmap_clear_ram(hw);
	n20_init_etype_clear_ram(hw);
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	n20_init_fd_clear_ram(hw);
#endif
	n20_init_vport_mc_vlan_clear_ram(hw);
	n20_init_rss_clear_ram(hw);
	mce_mbx_reset(hw);

	mce_mbx_send_nic_reset_event_to_fw(hw);
	n20_wait_nic_reset_done(hw, 10);
	if (hw->saved_force_speed != NO_FORCE_SPEED)
		mce_mbx_set_force_speed(hw, hw->saved_force_speed);
	/* set ififo to 16k */
	wr32(hw, N20_IFIFO_DATA_PROG_FULL, 0x100);
	wr32(hw, PAUSE_TIMER_ALDONE_THRES, DEFAULT_THRES);

	/* if in capture rdma packets, open it */
	if (test_bit(MCE_FLAG_CAPTURE_RDMA_ENA, pf->flags))
		hw->ops->set_capture_rdma(hw, true);
}

/**
 * n20_set_mac_station_addr - Set MAC station address for PFC/pause frames
 * @hw: pointer to the hw structure
 * @addr: 6-byte MAC address
 *
 * The MAC hardware uses this station address as the source MAC when
 * autonomously generating PFC and pause control frames. If not set,
 * the source MAC defaults to 00:00:00:00:00:00.
 */
static void n20_set_mac_station_addr(struct mce_hw *hw, const u8 *addr)
{
	u32 sa_lo, sa_hi;

	/* Hardware reads SA registers in this order to form the on-wire MAC:
	 *   SA_HI[15:8]  -> wire byte 0
	 *   SA_HI[7:0]   -> wire byte 1
	 *   SA_LO[31:24] -> wire byte 2
	 *   SA_LO[23:16] -> wire byte 3
	 *   SA_LO[15:8]  -> wire byte 4
	 *   SA_LO[7:0]   -> wire byte 5
	 */
	sa_hi = ((u32)addr[0] << 8) |
		(u32)addr[1];

	sa_lo = ((u32)addr[2] << 24) |
		((u32)addr[3] << 16) |
		((u32)addr[4] << 8)  |
		(u32)addr[5];

	wr32(hw, N20_MAC_SA_LO, sa_lo);
	wr32(hw, N20_MAC_SA_HI, sa_hi);
}

static void mac_default_init(struct mce_hw *hw)
{
	u32 val;

	val = F_M_CFG_JUMBO_EN | F_M_DIC_EN | F_M_STCRC_EN | F_M_IF_MODE_EN |
	      F_M_PAU_DISCARD | F_M_PAU_TIMER_PIN | F_M_BYPASS_PTP_TIMER_EN |
	      F_M_TX_EN | F_M_RX_EN | F_M_QTAG_EN | F_M_DB_QTAG_EN;

	if (hw->hw_flags & NETIF_F_RXFCS)
		val &= ~F_M_STCRC_EN;

	wr32(hw, N20_M_CFG, val);

	/* setup default max-length */
	val = MCE_ETH_DFT_FRAME_MAX_LEN;
	wr32(hw, N20_M_JUMBO_LENGTH, val << 16 | val);

	/* Set the MAC station address used for PFC/pause frame source MAC */
	n20_set_mac_station_addr(hw, hw->port_info->perm_addr);
}

static void ddp_default_init(struct mce_hw *hw)
{
	int g_id, r_id;
	u32 val;

	/* reset all rules */
	for (g_id = 0; g_id < 16; g_id++) {
		for (r_id = 0; r_id < 4; r_id++) {
			val = 0;
			MODIFY_BITFIELD(val, g_id * 4 + r_id, 6, 24);
			wr32(hw, N20_ETH_PROG_REG_LO(r_id, g_id), 0x00);
			wr32(hw, N20_ETH_PROG_REG_HI(r_id, g_id), val);
		}
	}
	/* 88a8+88a8/8100+88a8 two vlan bypass  */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 0), 0x00031927);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 0), 0x8083010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 0), 0x0030e218);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 0), 0xc183010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 0), 0x00036a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 0), 0x8283010c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 0), 0x0030e218);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 0), 0xc383010c);
	/* arp */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 1), 0x0003984c);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 1), 0x8403000c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 1), 0x000c96d1);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 1), 0xc503000c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 1), 0x0030da38);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 1), 0xc603000c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 1), 0x00c01463);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 1), 0xc703000c);
	/* 1vlan + arp */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 2), 0x000cd26e);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 2), 0x8803000e);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 2), 0x0030c018);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 2), 0xc903000e);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 2), 0x00c0030f);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 2), 0xca03000e);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 2), 0x03004fdf);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 2), 0xcb03000e);
	/* 2vlan + arp */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 3), 0x00304a32);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 3), 0x8c030010);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 3), 0x00c07906);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 3), 0xcd030010);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 3), 0x030020c6);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 3), 0xce030010);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 3), 0x0c008e1c);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 3), 0xcf030010);
	/* 8100 + ip4inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 4), 0x80305a07);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 4), 0x9083010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 4), 0x8000803f);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 4), 0xd183010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 4), 0x0030da38);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 4), 0xd283010c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 4), 0x00036a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 4), 0xd383010c);
	/* 8100 + io6inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 5), 0x8030aadd);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 5), 0x9483010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 5), 0x0030da38);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 5), 0xd583010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 5), 0x800070e5);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 5), 0xd683010c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 5), 0x00036a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 5), 0xd783010c);
	/* 8100 + gre */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 6), 0x80302a9c);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 6), 0x9883010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 6), 0x0030da38);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 6), 0xd983010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 6), 0x8000f0a4);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 6), 0xda83010c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 6), 0x00036a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 6), 0xdb83010c);
	/* 8100 + 8100 + ip4inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 7), 0x80305a07);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 7), 0x9c830110);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 7), 0x0033b0b7);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 7), 0xdd830110);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 7), 0x8003eab0);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 7), 0xde830110);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 7), 0x00036a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 7), 0xdf83010c);
	/* 8100 + 8100 + ip6inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 8), 0x8030aadd);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 8), 0xa0830110);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 8), 0x0033b0b7);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 8), 0xe1830110);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 8), 0x80031a6a);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 8), 0xe2830110);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 8), 0x00036a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 8), 0xe383010c);
	/* 8100 + 8100 + gre */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 9), 0x80302a9c);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 9), 0xa4830110);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 9), 0x0033b0b7);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 9), 0xe5830110);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 9), 0x80039a2b);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 9), 0xe6830110);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 9), 0x00036a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 9), 0xe783010c);
	/* 88a8 + ip4inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 10), 0x80305a07);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 10), 0xa883010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 10), 0x8000803f);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 10), 0xe983010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 10), 0x0030da38);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 10), 0xea83010c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 10), 0x00031927);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 10), 0xeb83010c);
	/* 88a8 + ip6inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 11), 0x8030aadd);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 11), 0xac83010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 11), 0x0030da38);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 11), 0xed83010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 11), 0x800070e5);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 11), 0xee83010c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 11), 0x00031927);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 11), 0xef83010c);
	/* 88a8 + gre */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 12), 0x80302a9c);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 12), 0xb083010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 12), 0x0033c31f);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 12), 0xf183010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 12), 0x8003e983);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 12), 0xf283010c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 12), 0x00031927);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 12), 0xf383010c);
	/* 1: ip4inip 2: 88a8 + 8100 + ip4inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 13), 0x080056e7);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 13), 0xb483010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 13), 0x00030b47);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 13), 0xf583010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 13), 0x80333088);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 13), 0xb6830110);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 13), 0x00031927);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 13), 0xf783010c);
	/* 1: ip6inip 2: 88a8 + 8100 + ip6inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 14), 0x08007a32);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 14), 0xb883010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 14), 0x00030b47);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 14), 0xf983010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 14), 0x80336a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 14), 0xba830110);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 14), 0x00031927);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 14), 0xfb83010c);
	/* 1: gre 2: 88a8 + 8100 + gre */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 15), 0x0800811b);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 15), 0xbc83010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 15), 0x00030b47);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 15), 0xfd83010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 15), 0x80334013);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 15), 0xbe830110);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 15), 0x00031927);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 15), 0xff83010c);
}

static void n20_init_hw(struct mce_hw *hw)
{
	u32 val = 0;
	int i = 0;

	/* clean DMA AXI */
	wr32(hw, N20_DMA_AXI_EN, 0);
	mce_wait_status(hw, N20_DMA_AXI_STATUS, _v == 0xf, 2000,
			"wait dma axi status failed");

#ifdef MCE_TX_WB_COAL
	val = rd32(hw, N20_DMA_CONFIG);
	val |= F_TX_WB_EN;
	MODIFY_BITFIELD(val, 2, 2, 2);
	wr32(hw, N20_DMA_CONFIG, val);
#endif

#ifdef MCE_RX_WB_COAL
	val = rd32(hw, N20_DMA_CONFIG);
	val |= F_RX_WB_EN;
	MODIFY_BITFIELD(val, 1, 2, 0);
	wr32(hw, N20_DMA_CONFIG, val);
#endif

	/* 2 write back is ok, it is 64bytes */
	/* we default setup rx */

	/* enable hw rx dim (just enable not start) */
	/* setup dim sample_inval 1ms */

	/* get MAC addr */

	val = hw->fw_stat.fix_mac_addr[1];
	hw->port_info->perm_addr[5] = (val >> 8) & 0xff;
	hw->port_info->perm_addr[4] = val & 0xff;
	val = hw->fw_stat.fix_mac_addr[0];
	hw->port_info->perm_addr[3] = (val >> 24) & 0xff;
	hw->port_info->perm_addr[2] = (val >> 16) & 0xff;
	hw->port_info->perm_addr[1] = (val >> 8) & 0xff;
	hw->port_info->perm_addr[0] = val & 0xff;

	/* clean VLAN type in nic */
	for (i = 0; i < 8; i++) {
		wr32(hw, N20_ETH_VLAN_TPID(i), 0);
		wr32(hw, N20_ETH_O_VLAN_TYPE(i), 0xffffffff);
		wr32(hw, N20_ETH_I_VLAN_TYPE(i), 0xffffffff);
	}
	/* set VLAN type that we can support */
	wr32(hw, N20_ETH_VLAN_TPID(0), ETH_P_8021Q);
	wr32(hw, N20_ETH_VLAN_TPID(1), ETH_P_8021AD);
	wr32(hw, N20_ETH_O_VLAN_TYPE(0), ETH_P_8021Q);
	wr32(hw, N20_ETH_O_VLAN_TYPE(1), ETH_P_8021AD);
	wr32(hw, N20_ETH_I_VLAN_TYPE(0), ETH_P_8021Q);
	wr32(hw, N20_ETH_I_VLAN_TYPE(1), ETH_P_8021AD);

	/* enable redirection (rss rx_csum) */
	wr32(hw, N20_ETH_RQA_CTRL,
	     (F_REDIR_EN | F_RSS_EN | F_MULTI_FILTER_TABLE_EN |
	      F_VF_VLAN_FLR_EN | F_ARP_RSS_EN | F_ETYPE_EN | F_TUPLE5_EN |
	      0x3f));

	/* enable L2 filter */
	set_bit(DMAC_FILTER_EN, hw->l2_fltr_flags);
	val = rd32(hw, N20_ETH_L2_CTRL0);
	val |= (F_L2_FILTER_EN | F_DMAC_FILTER_EN);
	val |= (F_BC_BYPASS_EN | F_UC_SEL | F_MC_SEL);
	/* close rdma in default */
	val &= (~BIT(8));
	wr32(hw, N20_ETH_L2_CTRL0, val);

	/* default turn on vport attr vlan promisc */
	hw->vf.ops->set_vf_set_vlan_promisc(hw, PFINFO_IDX, true);
	/* default turn off vport vtag filter. */
	hw->vf.ops->set_vf_set_vtag_vport_en(hw, 0, false);
	wr32(hw, N20_ETH_EMAC_POST_CTRL, F_PORT_CTRL_MUL_ANTI_SPOOF_EN);
	/* setup default to rdma */
	rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_US_VALUE), hw->axi_mhz);

	val = rd32(hw, N20_MSIX_OFF(N20_IRQ_MB_ST_CLR));
	val |= F_IRQ_AVOID_DROP_INTR_EN;
	wr32(hw, N20_MSIX_OFF(N20_IRQ_MB_ST_CLR), val);
	/* setup esp udp port */
	for (i = 0; i < 8; i++)
		wr32(hw, N20_ETH_IPSEC_PORT + i * 4,
		     MCE_TC_FLWR_IPSEC_NAT_T_PORT0);
	wr32(hw, N20_ETH_IPSEC_PORT, MCE_TC_FLWR_IPSEC_NAT_T_PORT1);
	hw->ops->set_ucmc_hash_type_fltr(hw);
	/* clear hw ring stats */
	hw->ops->clear_hw_ring_stats(hw);
#if MCE_MAC_STATS_EN
	hw->ops->clr_mac_stats(hw);
#endif

	wr32(hw, N20_ETH_DFT_RXTRANS_MIN_LEN, MCE_ETH_DFT_RXTRANS_MIN_LEN);
	wr32(hw, N20_ETH_DFT_RXTRANS_MAX_LEN, MCE_ETH_DFT_RXTRANS_MAX_LEN);

	mac_default_init(hw);
	ddp_default_init(hw);
	/* set for rx-all */
	hw->ops->set_err_mode(hw);
	/* get pf id */
	hw->ops->update_fw_stat(hw);
	val = 0;
	MODIFY_BITFIELD(val, hw->pfvfnum.pf, 2, 2);
	MODIFY_BITFIELD(val, hw->pfvfnum.pf, 1, 15);
	wr32(hw, N20_NIC_CONFIG, val);
	wr32(hw, N20_ETH_PORT_RX_PROGFULL(0), N20_ETH_PORT_RX_PROGFULL_DFT);
	val = rd32(hw, N20_ETH_CFG_ADAPTER_CTRL0);
	MODIFY_BITFIELD(val, 0x20, 8, F_RX_CDC);
	val |= F_RX_CTRL;
	wr32(hw, N20_ETH_CFG_ADAPTER_CTRL0, val);

	val = rd32(hw, N20_ETH_TSO_MAX_LEN);
	MODIFY_BITFIELD(val, MCE_ETH_DFT_FRAME_MAX_LEN, 16, 0);
	wr32(hw, N20_ETH_TSO_MAX_LEN, val);

	/* clear all vf flr mask */
	wr32(hw, N20_NIC_DMA_FLR_MASK(0), 0);
	wr32(hw, N20_NIC_DMA_FLR_MASK(1), 0);
	wr32(hw, N20_NIC_DMA_FLR_MASK(2), 0);
	wr32(hw, N20_NIC_DMA_FLR_MASK(3), 0);

	/* open tx flow control */
	val = rd32(hw, N20_DMA_TC_CTRL);
	val |= F_TC_INTERAL_EN;
	MODIFY_BITFIELD(val, hw->qos.interal, 10, F_TC_INTERAL_OFFSET);
	wr32(hw, N20_DMA_TC_CTRL, val);

	hw->ops->enable_axi_tx(hw);
	hw->ops->enable_axi_rx(hw);
}

/**
 * n20_enable_proc - turn on tx and rx except handle
 * @hw:  ptr to the hw
 */
void n20_enable_proc(struct mce_hw *hw)
{
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_vsi *vsi;
	int time = 0;
	u32 val = 0;
	u32 target;

	vsi = mce_get_main_vsi(pf);
	/* first stop rdma tx */
	rdma_wr32(hw, N20_RDMA_BTH(N20_RDMA_TX_RX_ENABLE), 0);

	/* stop rx */
	val = rd32(hw, N20_ETH_EXCEPT_RX_PROC);
	val |= 1;
	wr32(hw, N20_ETH_EXCEPT_RX_PROC, val);

	/* stop tx */
	val = rd32(hw, N20_ETH_EXCEPT_TX_PROC);
	val |= 1;
	wr32(hw, N20_ETH_EXCEPT_TX_PROC, val);

	val = rd32(hw, N20_ETH_FWD_CTRL);
	val |= F_CONGEST_DROP;
	wr32(hw, N20_ETH_FWD_CTRL, val);

	set_bit(MCE_VSI_DROP_TX, vsi->state);
	usleep_range(1000, 2000);
	/* check tx fifo empty */
	target = 0xffffffff;
	do {
		val = rd32(hw, N20_ETH_RX_DEBUG0);
		usleep_range(100, 200);
		time++;

	} while ((val != target) && (time < 100));

	if (time == 100)
		dev_err(hw->dev, "wait tx fifo timeout %x\n", val);
	time = 0;
	do {
		val = rd32(hw, N20_ETH_RX_DEBUG4);
		usleep_range(100, 200);
		time++;

	} while ((val != 0xffffffff) && (time < 100));

	if (time == 100)
		dev_err(hw->dev, "wait rx fifo timeout %x\n", val);
	time = 0;
	target = 0x3fff;
	do {
		val = rd32(hw, N20_ETH_RX_DEBUG5);
		usleep_range(100, 200);
		time++;

	} while ((val != target) && (time < 100));

	if (time == 100)
		dev_err(hw->dev, "wait rx fifo timeout debug5 %x\n", val);
}

/**
 * n20_disable_proc - turn off tx and rx except handle
 * @hw:  ptr to the hw
 */
void n20_disable_proc(struct mce_hw *hw)
{
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_vsi *vsi;
	u32 val = 0;

	vsi = mce_get_main_vsi(pf);

	val = rd32(hw, N20_ETH_FWD_CTRL);
	val &= ~F_CONGEST_DROP;
	wr32(hw, N20_ETH_FWD_CTRL, val);

	val = rd32(hw, N20_ETH_EXCEPT_RX_PROC);
	val &= ~1;
	wr32(hw, N20_ETH_EXCEPT_RX_PROC, val);

	val = rd32(hw, N20_ETH_EXCEPT_TX_PROC);
	val &= ~1;
	wr32(hw, N20_ETH_EXCEPT_TX_PROC, val);

	rdma_wr32(hw, N20_RDMA_BTH(N20_RDMA_TX_RX_ENABLE), 3);

	clear_bit(MCE_VSI_DROP_TX, vsi->state);
}

static void n20_enable_axi_tx(struct mce_hw *hw)
{
	u32 dma_axi_ctl;

	dma_axi_ctl = rd32(hw, N20_DMA_AXI_EN);
	dma_axi_ctl |= F_TX_AXI_RW_EN;
	dma_axi_ctl |= F_TX_AXI_RW_MS;
	wr32(hw, N20_DMA_AXI_EN, dma_axi_ctl);
}

static void n20_disable_axi_tx(struct mce_hw *hw)
{
	u32 dma_axi_ctl;

	dma_axi_ctl = rd32(hw, N20_DMA_AXI_EN);
	dma_axi_ctl &= ~(F_TX_AXI_RW_EN);
	dma_axi_ctl |= F_TX_AXI_RW_MS;
	wr32(hw, N20_DMA_AXI_EN, dma_axi_ctl);
}

static void n20_enable_axi_rx(struct mce_hw *hw)
{
	u32 dma_axi_ctl;

	dma_axi_ctl = rd32(hw, N20_DMA_AXI_EN);
	dma_axi_ctl |= F_RX_AXI_RW_EN;
	dma_axi_ctl |= F_RX_AXI_RW_MS;
	wr32(hw, N20_DMA_AXI_EN, dma_axi_ctl);
}

static void n20_disable_axi_rx(struct mce_hw *hw)
{
	u32 dma_axi_ctl;

	dma_axi_ctl = rd32(hw, N20_DMA_AXI_EN);
	dma_axi_ctl &= ~(F_RX_AXI_RW_EN);
	dma_axi_ctl |= F_RX_AXI_RW_MS;
	wr32(hw, N20_DMA_AXI_EN, dma_axi_ctl);
}

static void n20_cfg_vec2tqirq(struct mce_hw *hw, u16 vec, u16 tirq)
{
	u32 val = 0;

	val = rd32(hw, N20_MSIX_OFF((N20_MSIX_RING_VEC(vec))));
	CLR_BIT(31, val);
	MODIFY_BITFIELD(val, hw->pfvfnum.pf, 7, 24);
	MODIFY_BITFIELD(val, tirq, 11, 11);
	wr32(hw, N20_MSIX_OFF((N20_MSIX_RING_VEC(vec))), val);
}

static void n20_cfg_vec2rqirq(struct mce_hw *hw, u16 vec, u16 rirq)
{
	u32 val = 0;

	val = rd32(hw, N20_MSIX_OFF((N20_MSIX_RING_VEC(vec))));
	CLR_BIT(31, val);
	MODIFY_BITFIELD(val, hw->pfvfnum.pf, 7, 24);
	MODIFY_BITFIELD(val, rirq, 11, 0);
	wr32(hw, N20_MSIX_OFF((N20_MSIX_RING_VEC(vec))), val);
}

static int n20_set_vf_update_vm_macaddr(struct mce_hw *hw, u8 *mac_addr,
					u32 index, bool active)
{
	u32 rar_lo = 0, rar_hi = 0;
	u32 val = 0;
	int err = 0;

	rar_lo = ((u32)(mac_addr[5]) | (((u32)(mac_addr[4])) << 8) |
		  (((u32)(mac_addr[3])) << 16) | (((u32)(mac_addr[2])) << 24));

	rar_hi = (u32)mac_addr[1] | ((u32)(mac_addr[0])) << 8;
	if (!active) {
		rar_lo = 0;
		rar_hi = 0;
	}
	wr32(hw, N20_ETH_VM_DMAC_RAH(index), rar_hi);
	wr32(hw, N20_ETH_VM_DMAC_RAL(index), rar_lo);
	val = rd32(hw, N20_ETH_VM_IPORT_PVF(index));
	val = active ? val | F_MAC_FILTER_PVF_EN : val & ~F_MAC_FILTER_PVF_EN;
	wr32(hw, N20_ETH_VM_IPORT_PVF(index), val);

	return err;
}

static int n20_set_vf_update_vm_default_vlan(struct mce_hw *hw, int index)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);

	vf->t_info.vlanid = 0xfff;
	mce_vf_set_veb_misc_rule(hw, index, VEB_POLICY_TYPE_UC_ADD_VLAN);
	return 0;
}

#define __MCE_MC_FILTER_PER_BANK (8)
static bool __is_mc_filter_bank1(int avail_id)
{
	return !!(avail_id >= __MCE_MC_FILTER_PER_BANK);
}

static void __config_vf_mc_mac_to_bank(struct mce_hw *hw, int num, int avail_id,
				       bool en, const u8 *mac_addr)
{
	u32 t_mac = 0, val = 0, idx = 0;

	if (num)
		avail_id -= __MCE_MC_FILTER_PER_BANK;

	if (avail_id % 2) {
		idx = (avail_id / 2) * 3 + 1;
		t_mac = (u32)(mac_addr[5]) | (((u32)(mac_addr[4])) << 8);
		if (!en)
			t_mac = 0;
		val = rd32(hw,
			   N20_ETH_VF_MC_OFF(num, _vfnum(hw, PFINFO_IDX), idx));
		MODIFY_BITFIELD(val, t_mac, 16, 16);
		wr32(hw, N20_ETH_VF_MC_OFF(num, _vfnum(hw, PFINFO_IDX), idx),
		     val);
		t_mac = (u32)(mac_addr[0]) << 24 | (u32)(mac_addr[1]) << 16 |
			(u32)(mac_addr[2]) << 8 | (u32)(mac_addr[3]) << 0;
		if (!en)
			t_mac = 0;
		wr32(hw,
		     N20_ETH_VF_MC_OFF(num, _vfnum(hw, PFINFO_IDX), idx + 1),
		     t_mac);
	} else {
		idx = (avail_id / 2) * 3;
		t_mac = ((u32)(mac_addr[5]) | (((u32)(mac_addr[4])) << 8) |
			 (((u32)(mac_addr[3])) << 16) |
			 (((u32)(mac_addr[2])) << 24));
		if (!en)
			t_mac = 0;
		wr32(hw, N20_ETH_VF_MC_OFF(num, _vfnum(hw, PFINFO_IDX), idx),
		     t_mac);
		val = rd32(hw, N20_ETH_VF_MC_OFF(num, _vfnum(hw, PFINFO_IDX),
						 idx + 1));
		t_mac = ((u32)mac_addr[1] | ((u32)(mac_addr[0])) << 8);
		if (!en)
			t_mac = 0;
		MODIFY_BITFIELD(val, t_mac, 16, 0);
		wr32(hw,
		     N20_ETH_VF_MC_OFF(num, _vfnum(hw, PFINFO_IDX), idx + 1),
		     val);
	}
}

static void n20_set_vf_clear_mc_filter(struct mce_hw *hw, bool only_pf)
{
	int i, vfnum = 0, vfs_cnt = 0;

	vfs_cnt = only_pf ? 1 : MCE_LIMIT_VFS;
	for (vfnum = 0; vfnum < vfs_cnt; vfnum++) {
		for (i = 0; i < 0x40; i += 4) {
			wr32(hw, N20_ETH_VF_MC_OFF(0, vfnum, i / 4), 0);
			wr32(hw, N20_ETH_VF_MC_OFF(1, vfnum, i / 4), 0);
		}
	}
}

static void n20_set_vf_true_promisc(struct mce_hw *hw, int vfid, bool on)
{
	u32 val, idx;

	idx = _vfnum(hw, vfid);
	val = rd32(hw, N20_ETH_TRUE_PROMISC_VPORT_ADDR(idx));

	on ? F_SET_TRUE_PROMISC_VPORT_CTRL(idx, val) :
	     F_CLR_TRUE_PROMISC_VPORT_CTRL(idx, val);
	wr32(hw, N20_ETH_TRUE_PROMISC_VPORT_ADDR(idx), val);
}

static void n20_set_vf_rqa_tcp_sync_en(struct mce_hw *hw, bool on)
{
	u32 val;

	val = rd32(hw, N20_ETH_RQA_CTRL);
	val = on ? val | F_TCP_SYNC_EN : val & ~F_TCP_SYNC_EN;
	wr32(hw, N20_ETH_RQA_CTRL, val);
}

static void n20_set_vf_rqa_tcp_sync_remapping(struct mce_hw *hw, int vfnum,
					      struct mce_tcpsync *tcpsync)
{
	u32 val, idx;

	idx = _vfnum(hw, vfnum);
	val = tcpsync->acl.data;
	wr32(hw, N20_RQA_TCP_SYNC_OFF(N20_RQA_TCP_SYNC_ACL(idx)), val);
	val = tcpsync->pri.data;
	wr32(hw, N20_RQA_TCP_SYNC_OFF(N20_RQA_TCP_SYNC_PRI(idx)), val);
}

static int n20_set_vf_bw_limit_init(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	u32 val = 0, qg_cnt;

	qg_cnt = hw->vf_max_ring / 4;
	val |= F_VF_LIMIT_EN;
	F_SET_VF_QG_NUM(val, ilog2(qg_cnt));
	wr32(hw, N20_DMA_VF_QG_CTRL, val);

	val |= F_TC_EN | F_TC_BP_MOD;
	val |= F_TC_CRC | F_TC_INTERAL_EN;
	if (hw->vf_rate_qos.interal)
		val |= hw->vf_rate_qos.interal << F_TC_INTERAL_OFFSET;
	else
		val |= hw->qos.interal << F_TC_INTERAL_OFFSET;
	/* tc0~7 mode setup ETS mode*/
	val |= 0xffff;
	wr32(hw, N20_DMA_TC_CTRL, val);

	return 0;
}

static int n20_set_vf_bw_qg_ctrl(struct mce_pf *pf, int vf_id, u16 ring_cnt)
{
	struct mce_hw *hw = &pf->hw;
	int idx, qg_offset, qg_cnt;
	u32 val, data;
	int i, j;

	if (ring_cnt > hw->vf_max_ring)
		return 0;

	idx = _vfnum(hw, vf_id);
	qg_cnt = hw->vf_max_ring / 4;
	qg_offset = qg_cnt * idx;

	for (i = qg_offset; i < qg_offset + qg_cnt; i++) {
		val = 0;
		/* one qg include 4 rings */
		for (j = 0; j < 4; j++) {
			if (!ring_cnt)
				break;
			val |= BIT(j);
			ring_cnt--;
		}
		data = rd32(hw, N20_DMA_TC_QG_CTRL(i));
		MODIFY_BITFIELD(data, val, 4, 8);
		wr32(hw, N20_DMA_TC_QG_CTRL(i), data);
	}

	return 0;
}

static int n20_set_vf_bw_limit_rate(struct mce_pf *pf, int vf_id,
				    u64 max_tx_rate, u16 ring_cnt)
{
#define __MCE_TM_RATE_UNIT 512
#define __MCE_TC_VF_QG_BYTE_BASE_CLK_MHZ 500 /* limit rate base clk 500M */
	struct mce_hw *hw = &pf->hw;
	u64 interal_rate;
	u32 hw_rate;
	int idx;

	idx = _vfnum(hw, vf_id);
	if (hw->vf_rate_qos.interal)
		interal_rate = 1000 / hw->vf_rate_qos.interal;
	else
		interal_rate = hw->qos.rate;
	/* calc real rate */
	hw_rate = (max_tx_rate / interal_rate) / __MCE_TM_RATE_UNIT *
		  __MCE_TC_VF_QG_BYTE_BASE_CLK_MHZ / hw->axi_mhz;
	wr32(hw, N20_DMA_TC_VF_QG_BYTE_LIMIT(idx), hw_rate);
	hw->vf.ops->set_vf_bw_qg_ctrl(pf, vf_id, ring_cnt);
	return 0;
}

static void n20_set_vf_rebase_ring_base(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 val;

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		hw->ring_max_cnt = hw->vf_max_ring;
		hw->ring_base_addr = N20_MAX_Q_CNT - hw->ring_max_cnt;
		wr32(hw, N20_MSIX_OFF(N20_MSIX_CFG_VF_NUM),
		     N20_MAX_RING_CNT / hw->ring_max_cnt);
	} else {
		hw->ring_max_cnt = N20_MAX_Q_CNT;
		hw->ring_base_addr = 0;
		/* default 128 vfs */
		wr32(hw, N20_MSIX_OFF(N20_MSIX_CFG_VF_NUM), 128);
	}

	/* setup vf default ring */
	val = rd32(hw, N20_ETH_VPORT_ATTR_TABLE(_vfnum(hw, PFINFO_IDX)));
	F_SET_VPORT_DEFAULT_RING(val, hw->ring_base_addr);
	wr32(hw, N20_ETH_VPORT_ATTR_TABLE(_vfnum(hw, PFINFO_IDX)), val);
}

static void n20_vf_cfg_txring_bw_lmt(struct mce_hw *hw, int vf_id,
				     int max_tx_rate)
{
	u32 th = (max_tx_rate * 1000) >> 3;
	u32 tm = 1000 * hw->axi_mhz;
	int i, offset;

	/* if 0, clear all */
	if (!max_tx_rate) {
		th = 0;
		tm = 0;
	}
	vf_id = _vfnum(hw, vf_id);
	offset = hw->vf_max_ring * vf_id;
	for (i = offset; i < offset + hw->vf_max_ring; i++) {
		wr32(hw, N20_DMA_REG_TX_FLOW_CTRL_TH + 0x100 * i, th);
		wr32(hw, N20_DMA_REG_TX_FLOW_CTRL_TM + 0x100 * i, tm);
	}
}

static void n20_set_vf_clear_all_flr_vlan(struct mce_hw *hw)
{
	int i, vfnum = 0;

	for (vfnum = 0; vfnum < MCE_LIMIT_VFS; vfnum++) {
		for (i = 0; i < MCE_MAX_VF_VLAN_WHITE_LISTS; i++)
			wr32(hw, N20_ETH_VF_VLAN_OFF(vfnum, i), 0);
	}
}

static void n20_set_vf_set_vlan_promisc(struct mce_hw *hw, int vfid, bool on)
{
	u32 val;

	val = rd32(hw, N20_ETH_VPORT_ATTR_TABLE(_vfnum(hw, vfid)));
	if (on)
		val |= F_VPORT_VLAN_PROMISC_EN;
	else
		val &= (~F_VPORT_VLAN_PROMISC_EN);

	wr32(hw, N20_ETH_VPORT_ATTR_TABLE(_vfnum(hw, vfid)), val);
}

static void n20_set_vf_set_vtag_vport_en(struct mce_hw *hw, int vfid, bool on)
{
	u32 val, idx;

	idx = _vfnum(hw, vfid);
	val = rd32(hw, N20_ETH_VTAG_VPORT_FILTER_ADDR(idx));

	on ? F_SET_VTAG_VPORT_FILTER_CTRL(idx, val) :
	     F_CLR_VTAG_VPORT_FILTER_CTRL(idx, val);
	wr32(hw, N20_ETH_VTAG_VPORT_FILTER_ADDR(idx), val);
}

static void n20_set_vf_add_mc_fliter(struct mce_hw *hw, const u8 *mac_addr)
{
	u32 num = 0, id;
	int avail_id;

	for (id = 0; id < MCE_MAX_MC_WHITE_LISTS; id++) {
		if (hw->mc_info[id].en) {
			if (ether_addr_equal(hw->mc_info[id].addr, mac_addr))
				break;
		}
	}

	/* mac addr exists, do nothing */
	if (id < MCE_MAX_MC_WHITE_LISTS)
		return;

	avail_id = find_first_zero_bit(hw->avail_mc, MCE_MAX_MC_WHITE_LISTS);
	if (avail_id >= MCE_MAX_MC_WHITE_LISTS) {
		dev_err(mce_hw_to_dev(hw),
			"vf:%d the multicast nums exceeds maximum allowed:%d\n",
			_vfnum(hw, PFINFO_IDX), MCE_MAX_MC_WHITE_LISTS);
		return;
	}

	if (__is_mc_filter_bank1(avail_id))
		num = 1;
	set_bit(avail_id, hw->avail_mc);
	hw->mc_info[avail_id].en = true;
	ether_addr_copy(hw->mc_info[avail_id].addr, mac_addr);
	__config_vf_mc_mac_to_bank(hw, num, avail_id, true, mac_addr);
}

static void n20_set_vf_del_mc_filter(struct mce_hw *hw, const u8 *mac_addr)
{
	u8 addr[ETH_ALEN];
	int id, num = 0;

	for (id = 0; id < MCE_MAX_MC_WHITE_LISTS; id++) {
		if (hw->mc_info[id].en) {
			if (ether_addr_equal(hw->mc_info[id].addr, mac_addr))
				break;
		}
	}
	if (id >= MCE_MAX_MC_WHITE_LISTS) {
		dev_err(mce_hw_to_dev(hw),
			"vf:%d not found mc addr:%02x:%02x:%02x:%02x:%02x:%02x, cannot delete it\n",
			_vfnum(hw, PFINFO_IDX), mac_addr[0], mac_addr[1],
			mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
		return;
	}
	if (__is_mc_filter_bank1(id))
		num = 1;
	__config_vf_mc_mac_to_bank(hw, num, id, false, mac_addr);
	clear_bit(id, hw->avail_mc);
	hw->mc_info[id].en = false;
	memset(addr, 0, ETH_ALEN);
	ether_addr_copy(hw->mc_info[id].addr, addr);
}

static void n20_set_vf_add_flr_vlan(struct mce_hw *hw, int vfid, int entry)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	u32 val = 0;

	val = rd32(hw, N20_ETH_VF_VLAN_OFF(_vfnum(hw, vfid), entry));
	if (entry % 2)
		MODIFY_BITFIELD(val, vf->t_info.vlanid, 16, 16);
	else
		MODIFY_BITFIELD(val, vf->t_info.vlanid, 16, 0);
	wr32(hw, N20_ETH_VF_VLAN_OFF(_vfnum(hw, vfid), entry), val);
}

static void n20_set_vf_del_flr_vlan(struct mce_hw *hw, int vfid, int entry)
{
	u32 val = 0;

	val = rd32(hw, N20_ETH_VF_VLAN_OFF(_vfnum(hw, vfid), entry));
	if (entry % 2)
		MODIFY_BITFIELD(val, 0, 16, 16);
	else
		MODIFY_BITFIELD(val, 0, 16, 0);
	wr32(hw, N20_ETH_VF_VLAN_OFF(_vfnum(hw, vfid), entry), val);
}

static void n20_set_vf_add_veb_vlan(struct mce_hw *hw, int vfid, int entry)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int vid = vf->t_info.vlanid;
	u32 val = 0;

	wr32(hw, N20_ETH_VEB_VLAN_PVF(entry), vid);
	val = rd32(hw, N20_ETH_VM_IPORT_PVF(entry));
	val |= F_VLAN_FILTER_PVF_EN;
	wr32(hw, N20_ETH_VM_IPORT_PVF(entry), val);
}

static void n20_set_vf_del_veb_vlan(struct mce_hw *hw, int vfid, int entry)
{
	u32 val = 0;

	val = rd32(hw, N20_ETH_VM_IPORT_PVF(entry));
	val &= ~F_VLAN_FILTER_PVF_EN;
	wr32(hw, N20_ETH_VM_IPORT_PVF(entry), val);
	wr32(hw, N20_ETH_VEB_VLAN_PVF(entry), 0);
}

static int n20_get_evb_vf_uc_index(struct mce_hw *hw, int entry)
{
	int idx;

	/* pf must use hw->max_vfs bitmap for rdma */
	if (entry == N20_VEB_PF_ADDR_ENTRY_OFF)
		idx = hw->max_vfs;
	else if (entry > N20_VEB_PF_ADDR_ENTRY_OFF)
		idx = entry - N20_VEB_VF_ADDR_ENTRY_OFF;
	else
		idx = N20_VEB_PF_ADDR_ENTRY_OFF - entry + N20_VF_CNT;
	return idx;
}

static void n20_set_vf_set_veb_act(struct mce_hw *hw, int vfid, int entry,
				   bool set, enum mce_flag_type set_bcmc_bitmap)
{
	int uc_idx = n20_get_evb_vf_uc_index(hw, entry);
	int idx = _vfnum(hw, vfid);
	u32 val = 0;

	/* uc/bcmc action */
	val = rd32(hw, N20_ETH_VEB_ACT_PVF(entry));
	if (set) {
		if (vfid != PFINFO_BCMC)
			F_SET_VM_MATCH_INDEX(val, uc_idx);
		else
			F_SET_VM_MATCH_INDEX(val, entry);
	} else {
		F_SET_VM_MATCH_INDEX(val, 0);
	}
	wr32(hw, N20_ETH_VEB_ACT_PVF(entry), val);

	if (vfid != PFINFO_BCMC) {
		/* uc bitmap */
		val = rd32(hw, N20_ETH_VPORT_SET_BITMAP(idx, uc_idx));
		if (set)
			val |= BIT(idx % 32);
		else
			val &= ~BIT(idx % 32);

		wr32(hw, N20_ETH_VPORT_SET_BITMAP(idx, uc_idx), val);

		if (set_bcmc_bitmap == MCE_F_HOLD)
			goto out;

		entry = hw->vf_bcmc_addr_offset;
		val = rd32(hw, N20_ETH_VPORT_SET_BITMAP(idx, entry));
		if (set_bcmc_bitmap == MCE_F_SET)
			val |= BIT(idx % 32);
		if (set_bcmc_bitmap == MCE_F_CLEAR)
			val &= ~BIT(idx % 32);
		wr32(hw, N20_ETH_VPORT_SET_BITMAP(idx, entry), val);
	} else {
		/* bcmc bitmap */
		entry = hw->vf_bcmc_addr_offset;
		idx = _vfnum(hw, PFINFO_IDX);
		wr32(hw, N20_ETH_VPORT_SET_BITMAP(idx, entry), BIT(idx % 32));
	}
out:
	return;
}

static int n20_update_fltr_macaddr(struct mce_hw *hw, u8 *mac_addr, u32 index,
				   bool active)
{
	u32 rar_lo = 0;
	u32 rar_hi = 0;
	int err = 0;

	if (!active)
		memset(mac_addr, 0x0, ETH_ALEN);
	rar_lo = ((u32)(mac_addr[5]) | (((u32)(mac_addr[4])) << 8) |
		  (((u32)(mac_addr[3])) << 16) | (((u32)(mac_addr[2])) << 24));

	rar_hi = ((u32)mac_addr[1] | ((u32)(mac_addr[0])) << 8);

	rar_hi = active ? rar_hi | F_MAC_FLTR_EN : rar_hi & ~F_MAC_FLTR_EN;
	wr32(hw, N20_ETH_FLTR_DMAC_RAH(index), rar_hi);
	wr32(hw, N20_ETH_FLTR_DMAC_RAL(index), rar_lo);

	return err;
}

static void n20_set_max_pktlen(struct mce_hw *hw, u32 mtu)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct net_device *netdev = vsi->netdev;
	u32 value = 0, max_len;
	u32 vfid = 0;

	/* if in rx-all mode, receive all packets */
	if (hw->hw_flags & MCE_F_RX_ALL_EN)
		max_len = MCE_ETH_DFT_FRAME_MAX_LEN;
	else
		max_len = mtu + 14 + 2 * 4 + 4;
	/* mtu + mac_hdr + 2 vlan_hdr + fcs */

	if (pf->priv_h.en)
		max_len += pf->priv_h.len;
	vfid = _vfnum(hw, PFINFO_IDX);
	value = rd32(hw, N20_ETH_VPORT_ATTR_TABLE(vfid));
	value &= ~(F_VPORT_DROP);
	value |= F_VPORT_LIMIT_LEN_EN;
	F_SET_VPORT_MAX_LEN(value, max_len); /* clean max len */
	wr32(hw, N20_ETH_VPORT_ATTR_TABLE(vfid), value);

	if (netdev->mtu > NORMAL_MTU)
		wr32(hw, N20_ETH_TSO_OFIFO_THRESH, 0x110);
	else
		wr32(hw, N20_ETH_TSO_OFIFO_THRESH, 0x100);
}

static void n20_set_rx_csum_chk_err_mask(struct mce_hw *hw, bool on)
{
	u32 val = 0;

	val = rd32(hw, N20_ETH_RQA_CTRL);
	if (on)
		val &= ~F_RX_CHK_ERR_MASK;
	else
		val |= F_RX_CHK_ERR_MASK;
	wr32(hw, N20_ETH_RQA_CTRL, val);
}

static void n20_set_vf_vlan_strip(struct mce_hw *hw, int vf_id, bool en)
{
	u16 txq_cnt = hw->func_caps.common_cap.vf_num_txq;
	u32 strip_cnt, offset;
	u32 value = 0;
	u32 strip_en;
	int i = 0;

	if (en) {
		strip_en = 1;
		strip_cnt = 1;
	} else {
		strip_en = 0;
		strip_cnt = 0;
	}
	/* TODO: for FPGA, vf id offset need plus 4 */
	vf_id = _vfnum(hw, vf_id);
	offset = vf_id * txq_cnt;
	for (i = offset; txq_cnt + offset; i++) {
		value = rd32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)));
		F_SET_VLAN_STRIP_EN(value, strip_en);
		F_SET_VLAN_STRIP_CNT(value, strip_cnt);
		F_SET_RETA_HASH_QUEUE_ID(value, 0);
		wr32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)), value);
	}
}

static int n20_set_vf_rss_table(struct mce_hw *hw, int vf_id, u16 q_cnt)
{
	struct mce_pf *pf = (struct mce_pf *)hw->back;
	u16 i = 0, offset, vfnum = _vfnum(hw, vf_id);
	u32 act_reta = 0, vft_reta = 0, val;
	u32 table_size = pf->rss_tb_size;

	if (!q_cnt)
		q_cnt = table_size;

	offset = vfnum * table_size;
	for (i = offset; i < table_size + offset; i++) {
		if (!(hw->hw_flags & MCE_F_RSS_TABLE_INITED)) {
			val = (i - offset) % q_cnt;
			hw->rss_table[i - offset] = val;
		} else {
			val = hw->rss_table[i - offset];
		}

		if (i % 2 == 0) {
			vft_reta = val & 0xffff;
		} else {
			vft_reta |= val << 16;
			wr32(hw, N20_RSS_OFF(N20_RSS_VFT_CONFIG_MEM(i / 2)),
			     vft_reta);
		}
		act_reta = rd32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)));
		act_reta |= F_RSS_RETA_QUEUE_EN;
		wr32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)), act_reta);
	}

	hw->hw_flags |= MCE_F_RSS_TABLE_INITED;
	return 0;
}

static void n20_clear_vf_all_rss_table(struct mce_hw *hw)
{
	u32 i;

	for (i = 0; i < 256; i++)
		wr32(hw, N20_RSS_OFF(N20_RSS_VFT_CONFIG_MEM_BASE(i)), 0);
}

static int __set_vf_spoofchk_mac(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	u8 *mac_addr = vf->vfinfo[vfid].vf_mac_addr;
	u32 rar_lo, rar_hi, val, idx;

	idx = _vfnum(hw, vfid);
	rar_lo = ((u32)(mac_addr[5]) | (((u32)(mac_addr[4])) << 8) |
		  (((u32)(mac_addr[3])) << 16) | (((u32)(mac_addr[2])) << 24));

	wr32(hw, N20_ETH_VM_ANTI_SMAC_RAL(idx), rar_lo);

	val = rd32(hw, N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx));
	val &= 0xffff0000;
	rar_hi = ((u32)mac_addr[1] | ((u32)(mac_addr[0])) << 8);
	val |= rar_hi;
	wr32(hw, N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx), val);
	return 0;
}

static int n20_set_vf_spoofchk_mac(struct mce_hw *hw, int vfid, bool en,
				   bool setmac)
{
	u32 val, idx;

	idx = _vfnum(hw, vfid);
	val = rd32(hw, N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx));

	val = en ? val | F_ANTI_SPOOF_MAC_VALID :
		   val & ~(F_ANTI_SPOOF_MAC_VALID);
	wr32(hw, N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx), val);

	if (setmac)
		__set_vf_spoofchk_mac(hw, vfid);

	return 0;
}

static int __set_vf_spoofchk_vlan(struct mce_hw *hw, int vfid,
				  enum mce_vf_antivlan_ctrl vlanctrl)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	u32 val, idx;

	if (vlanctrl == MCE_VF_ANTI_VLAN_HOLD)
		return 0;

	idx = _vfnum(hw, vfid);
	val = rd32(hw, N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx));
	if (vlanctrl == MCE_VF_ANTI_VLAN_CLEAR)
		F_SET_ANTI_SPOOF_VLAN_ID(val, 0);
	else
		F_SET_ANTI_SPOOF_VLAN_ID(val, vf->vfinfo[vfid].pf_vlan);
	wr32(hw, N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx), val);
	return 0;
}

static int n20_set_vf_spoofchk_vlan(struct mce_hw *hw, int vfid, bool en,
				    enum mce_vf_antivlan_ctrl vlanctrl)
{
	u32 val, idx;

	idx = _vfnum(hw, vfid);
	val = rd32(hw, N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx));

	val = en ? val | F_ANTI_SPOOF_VLAN_VALID :
		   val & ~(F_ANTI_SPOOF_VLAN_VALID);
	wr32(hw, N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx), val);
	__set_vf_spoofchk_vlan(hw, vfid, vlanctrl);
	return 0;
}

static int n20_set_vf_trusted(struct mce_hw *hw, int vfid, bool on)
{
	u32 val, idx;

	idx = _vfnum(hw, vfid);
	val = rd32(hw, N20_ETH_TRUSTED_VPORT_ADDR(idx));

	on ? F_SET_TRUSTED_VPORT_CTRL(idx, val) :
	     F_CLR_TRUSTED_VPORT_CTRL(idx, val);
	wr32(hw, N20_ETH_TRUSTED_VPORT_ADDR(idx), val);

	return 0;
}

static int n20_set_vf_default_vport(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 val = 0, idx;

	idx = _vfnum(hw, vfid);

	wr32(hw, N20_ETH_DEFAULT_VPORT_ADDR(0), 0);
	wr32(hw, N20_ETH_DEFAULT_VPORT_ADDR(1), 0);
	wr32(hw, N20_ETH_DEFAULT_VPORT_ADDR(2), 0);
	wr32(hw, N20_ETH_DEFAULT_VPORT_ADDR(3), 0);

	F_SET_DEFAULT_VPORT_CTRL(idx, val);
	wr32(hw, N20_ETH_DEFAULT_VPORT_ADDR(idx), val);

	val = rd32(hw, N20_ETH_FWD_CTRL);
	MODIFY_BITFIELD(val, idx, 7, F_DFT_PPORT_OFFSET);
	wr32(hw, N20_ETH_FWD_CTRL, val);
	pf->default_vport = idx;
	return 0;
}

static int n20_set_vf_recv_ximit_by_self(struct mce_hw *hw, bool on)
{
	struct mce_pf *pf = hw->back;
	u32 val;
	int i;

	val = rd32(hw, N20_ETH_FWD_CTRL);
	val = on ? val | F_RX_SELF_EN : val & ~F_RX_SELF_EN;
	wr32(hw, N20_ETH_FWD_CTRL, val);

	mce_for_each_pf_vf_id(pf, i) {
		val = rd32(hw, N20_ETH_VM_ANTI_VTAG_SMAC_RAH(_vfnum(hw, i)));
		val = on ? val & ~F_ANTI_SPOOF_DST_MAC_VALID :
			   val | F_ANTI_SPOOF_DST_MAC_VALID;
		wr32(hw, N20_ETH_VM_ANTI_VTAG_SMAC_RAH(_vfnum(hw, i)), val);
	}

	return 0;
}

static int n20_set_vf_trust_vport_en(struct mce_hw *hw, bool on)
{
	struct mce_pf *pf = hw->back;
	u32 val;

	val = rd32(hw, N20_ETH_FWD_CTRL);
	val = on ? val | F_TRUST_VPORT_EN : val & ~F_TRUST_VPORT_EN;
	wr32(hw, N20_ETH_FWD_CTRL, val);

	/* Cannot modify post mode in vepa mode */
	if (test_bit(MCE_FLAG_EVB_VEPA_ENA, pf->flags))
		return 0;

	if (on)
		hw->vf.ops->set_vf_emac_post_ctrl(hw, MCE_VF_VEB_VLAN_OUTER1, false,
			MCE_VF_POST_CTRL_ALLIN_TO_TXTRANS_AND_RX, true);
	else
		hw->vf.ops->set_vf_emac_post_ctrl(hw, MCE_VF_VEB_VLAN_OUTER1, false,
			MCE_VF_POST_CTRL_FILTER_TX_TO_RX, true);
	return 0;
}

static void n20_stat_update64_lh(struct mce_hw *hw, u32 reg_l, u32 reg_h,
				 bool is_rdma,
				 u64 *prev_stat, u64 *cur_stat)
{
	u64 new_data = 0;

	if (is_rdma) {
		new_data = rdma_rd32(hw, reg_h) & (BIT_ULL(32) - 1);
		new_data = (new_data << 32) + (rdma_rd32(hw, reg_l) & (BIT_ULL(32) - 1));
	} else {
		new_data = rd32(hw, reg_h) & (BIT_ULL(32) - 1);
		new_data = (new_data << 32) + (rd32(hw, reg_l) & (BIT_ULL(32) - 1));
	}

	/* Calculate the difference between the new and old values, and then
	 * add it to the software stat value.
	 */
	if (new_data >= *prev_stat)
		*cur_stat += new_data - *prev_stat;
	else
		/* to manage the potential roll-over */
		*cur_stat += (new_data + BIT_ULL(32)) - *prev_stat;

	/* Update the previously stored value to prepare for next read */
	*prev_stat = new_data;
}

static void n20_stat_update32(struct mce_hw *hw, u32 reg, bool is_rdma,
			      bool flag_64, u64 *prev_stat, u64 *cur_stat)
{
	u64 new_data = 0;

	if (is_rdma) {
		if (flag_64)
			new_data = rdma_rd64(hw, reg);
		else
			new_data = rdma_rd32(hw, reg) & (BIT_ULL(32) - 1);
	} else {
		if (flag_64)
			new_data = rd64(hw, reg);
		else
			new_data = rd32(hw, reg) & (BIT_ULL(32) - 1);
	}

	/* Calculate the difference between the new and old values, and then
	 * add it to the software stat value.
	 */
	if (new_data >= *prev_stat)
		*cur_stat += new_data - *prev_stat;
	else
		/* to manage the potential roll-over */
		*cur_stat += (new_data + BIT_ULL(32)) - *prev_stat;

	/* Update the previously stored value to prepare for next read */
	*prev_stat = new_data;
}

static void n20_get_hw_stats(struct mce_hw *hw, struct mce_hw_stats *prev_stats,
			     struct mce_hw_stats *cur_stats)
{
	u32 val;
	/* consider vsi count */
	/* update nic value todo */
	n20_stat_update64_lh(hw, N20_DMAC_FILTER_COUNT_L,
			     N20_DMAC_FILTER_COUNT_H, false,
			     &prev_stats->dmac_filter_drop,
			     &cur_stats->dmac_filter_drop);

	/* should trig reg first */
	rdma_wr32(hw, N20_RDMA_TRIG, 0xffffffff);

	n20_stat_update32(hw, N20_RDMA_TX_VPORT_UNICAST_PKTS, true, false,
			  &prev_stats->tx_vport_rdma_unicast_packets,
			  &cur_stats->tx_vport_rdma_unicast_packets);

	n20_stat_update32(hw, N20_RDMA_TX_VPORT_UNICAST_BYTS, true, true,
			  &prev_stats->tx_vport_rdma_unicast_bytes,
			  &cur_stats->tx_vport_rdma_unicast_bytes);

	n20_stat_update32(hw, N20_RDMA_RX_VPORT_UNICAST_PKTS, true, false,
			  &prev_stats->rx_vport_rdma_unicast_packets,
			  &cur_stats->rx_vport_rdma_unicast_packets);

	n20_stat_update32(hw, N20_RDMA_RX_VPORT_UNICAST_BYTS, true, true,
			  &prev_stats->rx_vport_rdma_unicast_bytes,
			  &cur_stats->rx_vport_rdma_unicast_bytes);

	n20_stat_update32(hw, N20_RDMA_NP_CNP_SENT, true, false,
			  &prev_stats->np_cnp_sent,
			  &cur_stats->np_cnp_sent);

	n20_stat_update32(hw, N20_RDMA_RP_CNP_HANDLED, true, false,
			  &prev_stats->rn_cnp_handled,
			  &cur_stats->rn_cnp_handled);

	n20_stat_update32(hw, N20_RDMA_NP_ECN_MARKED_ROCE_PACKETS, true, false,
			  &prev_stats->np_ecn_marked_roce_packets,
			  &cur_stats->np_ecn_marked_roce_packets);

	n20_stat_update32(hw, N20_RDMA_RP_CNP_IGNORED, true, false,
			  &prev_stats->rp_cnp_ignored,
			  &cur_stats->rp_cnp_ignored);

	n20_stat_update32(hw, N20_RDMA_OUT_OF_SEQUENCE, true, false,
			  &prev_stats->out_of_sequence,
			  &cur_stats->out_of_sequence);

	n20_stat_update32(hw, N20_RDMA_PACKET_SEQ_ERR, true, false,
			  &prev_stats->packet_seq_err,
			  &cur_stats->packet_seq_err);

	n20_stat_update32(hw, N20_RDMA_ACK_TIMEOUT_ERR, true, false,
			  &prev_stats->ack_timeout_err,
			  &cur_stats->ack_timeout_err);
	/* get rx crc cnts */
	val = rd32(hw, N20_ETH_EXCEPT_RX_PROC);
	MODIFY_BITFIELD(val, 4, 8, F_DGB_RXTRANS_BUS_OFF);
	wr32(hw, N20_ETH_EXCEPT_RX_PROC, val);
	n20_stat_update32(hw, N20_RXTRANS_BUS_STATIC, false, false,
			  &prev_stats->rx_crc_err, &cur_stats->rx_crc_err);
}

static void n20_get_mac_stat32(struct mce_hw *hw, u64 *val, u32 addr)
{
	*val = rd32(hw, addr);
}

static void n20_get_mac_stat64(struct mce_hw *hw, u64 *val, u32 hi, u32 lo)
{
	u64 t = 0;

	t = rd32(hw, hi);

	t <<= 32;
	t |= rd32(hw, lo);
	*val = t;
}

#define MAC_STAT32(val, addr) n20_get_mac_stat32(hw, &stats->val, addr)
#define MAC_STAT64(val, hi, lo) n20_get_mac_stat64(hw, &stats->val, hi, lo)

static void n20_get_mac_stats(struct mce_hw *hw, struct mce_mac_stats *stats)
{
	MAC_STAT32(rx_fcs_err, MCE_M_RX_FCS_ERR);
	MAC_STAT64(rx_good_pkts, MCE_M_RX_GFRAMSB_HI, MCE_M_RX_GFRAMSB);
	MAC_STAT64(rx_good_bytes, MCE_M_RX_GOCTGB_HI, MCE_M_RX_GOCTGB);
	MAC_STAT64(rx_bad_pkts, MCE_M_RX_BFRMB_HI, MCE_M_RX_BFRMB);
	MAC_STAT64(rx_good_bad_bytes, MCE_M_RX_GBOCTGB_HI, MCE_M_RX_GBOCTGB);
	MAC_STAT64(rx_good_bad_pkts, MCE_M_RX_GBFRMB_HI, MCE_M_RX_GBFRMB);
	MAC_STAT32(rx_undersize_err, MCE_M_RX_USIZECB);
	MAC_STAT32(rx_oversize_err, MCE_M_RX_OSIZE_FRMB);
	MAC_STAT32(rx_jabber_err, MCE_M_RX_JABBER_FRMB);
	MAC_STAT32(rx_runt_err, MCE_M_RX_RUNTERB);
	MAC_STAT32(rx_discard_pkts, MCE_M_RX_DISCARD);
	MAC_STAT32(rx_pause_pkts, MCE_M_RX_PAUSE_FRAMS);
	MAC_STAT32(rx_vlan_pkts, MCE_M_RX_VLAN_FRAMB);

	MAC_STAT32(rx_pfc_pri0_pkts, MCE_M_RX_PFC_PRI0_NUM);
	MAC_STAT32(rx_pfc_pri1_pkts, MCE_M_RX_PFC_PRI1_NUM);
	MAC_STAT32(rx_pfc_pri2_pkts, MCE_M_RX_PFC_PRI2_NUM);
	MAC_STAT32(rx_pfc_pri3_pkts, MCE_M_RX_PFC_PRI3_NUM);
	MAC_STAT32(rx_pfc_pri4_pkts, MCE_M_RX_PFC_PRI4_NUM);
	MAC_STAT32(rx_pfc_pri5_pkts, MCE_M_RX_PFC_PRI5_NUM);
	MAC_STAT32(rx_pfc_pri6_pkts, MCE_M_RX_PFC_PRI6_NUM);
	MAC_STAT32(rx_pfc_pri7_pkts, MCE_M_RX_PFC_PRI7_NUM);

	MAC_STAT64(rx_unicast_pkts, MCE_M_RX_GUCASTB_HI, MCE_M_RX_GUCASTB);
	MAC_STAT64(rx_multicast_pkts, MCE_M_RX_GMCASTB_HI, MCE_M_RX_GMCASTB);
	MAC_STAT64(rx_broadcast_pkts, MCE_M_RX_GBCASTB_HI, MCE_M_RX_GBCASTB);

	MAC_STAT64(rx_64octes_pkts, MCE_M_RX_64_BYTESB_HI, MCE_M_RX_64_BYTESB);
	MAC_STAT64(rx_65to127_octes_pkts, MCE_M_RX_65TO127_BYTESB_HI,
		   MCE_M_RX_65TO127_BYTESB);
	MAC_STAT64(rx_128to255_octes_pkts, MCE_M_RX_128TO255_BYTESB_HI,
		   MCE_M_RX_128TO255_BYTESB);
	MAC_STAT64(rx_256to511_octes_pkts, MCE_M_RX_256TO511_BYTESB_HI,
		   MCE_M_RX_256TO511_BYTESB);
	MAC_STAT64(rx_512to1023_octes_pkts, MCE_M_RX_512TO1023_BYTESB_HI,
		   MCE_M_RX_512TO1023_BYTESB);
	MAC_STAT64(rx_1024to1518_octes_pkts, MCE_M_RX_1024TO1518_BYTESB_HI,
		   MCE_M_RX_1024TO1518_BYTESB);
	MAC_STAT64(rx_1519tomax_octes_pkts, MCE_M_RX_1519TOMAX_BYTESB_HI,
		   MCE_M_RX_1519TOMAX_BYTESB);

	MAC_STAT64(tx_good_pkts, MCE_M_TX_GFRAMSB_HI, MCE_M_TX_GFRAMSB);
	MAC_STAT64(tx_good_bytes, MCE_M_TX_GOCTGB_HI, MCE_M_TX_GOCTGB);
	MAC_STAT64(tx_bad_pkts, MCE_M_TX_BFRMB_HI, MCE_M_TX_BFRMB);

	MAC_STAT64(tx_good_bad_bytes, MCE_M_TX_GBOCTGB_HI, MCE_M_TX_GBOCTGB);
	MAC_STAT64(tx_good_bad_pkts, MCE_M_TX_GBFRMB_HI, MCE_M_TX_GBFRMB);
	MAC_STAT32(tx_oversize_err, MCE_M_TX_OSIZE_FRMB);
	MAC_STAT32(tx_jabber_err, MCE_M_TX_JABBER_FRMB);
	MAC_STAT32(tx_pause_pkts, MCE_M_TX_PAUSE_FRAMS);
	MAC_STAT32(tx_vlan_pkts, MCE_M_TX_VLAN_FRAMB);

	MAC_STAT32(tx_pfc_pri0_pkts, MCE_M_TX_PFC_PRI0_NUM);
	MAC_STAT32(tx_pfc_pri1_pkts, MCE_M_TX_PFC_PRI1_NUM);
	MAC_STAT32(tx_pfc_pri2_pkts, MCE_M_TX_PFC_PRI2_NUM);
	MAC_STAT32(tx_pfc_pri3_pkts, MCE_M_TX_PFC_PRI3_NUM);
	MAC_STAT32(tx_pfc_pri4_pkts, MCE_M_TX_PFC_PRI4_NUM);
	MAC_STAT32(tx_pfc_pri5_pkts, MCE_M_TX_PFC_PRI5_NUM);
	MAC_STAT32(tx_pfc_pri6_pkts, MCE_M_TX_PFC_PRI6_NUM);
	MAC_STAT32(tx_pfc_pri7_pkts, MCE_M_TX_PFC_PRI7_NUM);

	MAC_STAT64(tx_unicast_pkts, MCE_M_TX_GUCASTB_HI, MCE_M_TX_GUCASTB);
	MAC_STAT64(tx_multicast_pkts, MCE_M_TX_GMCASTB_HI, MCE_M_TX_GMCASTB);
	MAC_STAT64(tx_broadcast_pkts, MCE_M_TX_GBCASTB_HI, MCE_M_TX_GBCASTB);

	MAC_STAT64(tx_64octes_pkts, MCE_M_TX_64_BYTESB_HI, MCE_M_TX_64_BYTESB);
	MAC_STAT64(tx_65to127_octes_pkts, MCE_M_TX_65TO127_BYTESB_HI,
		   MCE_M_TX_65TO127_BYTESB);
	MAC_STAT64(tx_128to255_octes_pkts, MCE_M_TX_128TO255_BYTESB_HI,
		   MCE_M_TX_128TO255_BYTESB);
	MAC_STAT64(tx_256to511_octes_pkts, MCE_M_TX_256TO511_BYTESB_HI,
		   MCE_M_TX_256TO511_BYTESB);
	MAC_STAT64(tx_512to1023_octes_pkts, MCE_M_TX_512TO1023_BYTESB_HI,
		   MCE_M_TX_512TO1023_BYTESB);
	MAC_STAT64(tx_1024to1518_octes_pkts, MCE_M_TX_1024TO1518_BYTESB_HI,
		   MCE_M_TX_1024TO1518_BYTESB);
	MAC_STAT64(tx_1519tomax_octes_pkts, MCE_M_TX_1519TOMAX_BYTESB_HI,
		   MCE_M_TX_1519TOMAX_BYTESB);
}

static void n20_clr_mac_stats(struct mce_hw *hw)
{
	struct mce_mac_stats stats;
	u32 val;

	val = rd32(hw, N20_M_CFG);
	val |= F_M_CFG_RCLRC;
	wr32(hw, N20_M_CFG, val);
	hw->ops->get_mac_stats(hw, &stats);
	val = rd32(hw, N20_M_CFG);
	val &= ~F_M_CFG_RCLRC;
	wr32(hw, N20_M_CFG, val);
}

static void n20_set_fcs_mode(struct mce_hw *hw, bool en)
{
	u32 val;

	val = rd32(hw, N20_M_CFG);
	if (en)
		val &= ~F_M_STCRC_EN;
	else
		val |= F_M_STCRC_EN;

	wr32(hw, N20_M_CFG, val);
}

static void n20_set_err_mode(struct mce_hw *hw)
{
	u32 val_mac;
	u32 val;

	val = rd32(hw, N20_ETH_EXCEPT_RX_PROC);
	val_mac = rd32(hw, N20_M_CFG);

	if (hw->hw_flags & MCE_F_RX_ALL_EN) {
		MODIFY_BITFIELD(val, 0, 9, F_DEFAULT_ACTION_OFF);
		val_mac |= F_M_STPAD_EN;
	} else {
		/**
		 * 0: pass 1: drop. drop crc error，under-size, over-size and
		 * 802.3 len error when turn off rx-all.
		 */
#define ETH_ERR_MASK                                            \
	(F_CRC_ERROR | F_UNDER_SIZE_ERROR | F_OVER_SIZE_ERROR | \
	 F_8023_LEN_ERROR)

		MODIFY_BITFIELD(val, ETH_ERR_MASK, 9, F_DEFAULT_ACTION_OFF);
		val_mac &= ~F_M_STPAD_EN;
	}

	wr32(hw, N20_ETH_EXCEPT_RX_PROC, val);
	wr32(hw, N20_M_CFG, val_mac);
}

static void n20_enable_txring_irq(struct mce_ring *ring)
{
	u32 status = 0;

	if (!ring)
		return;

	CLR_BIT(F_TX_INT_MASK_EN_BIT, status);
	SET_BIT(F_TX_INT_MASK_MS_BIT, status);
	ring_wr32(ring, N20_DMA_REG_INT_MASK, status);
}

static void n20_disable_txring_irq(struct mce_ring *ring)
{
	u32 status = 0;

	if (!ring)
		return;

	status = 0;
	SET_BIT(F_TX_INT_MASK_EN_BIT, status);
	SET_BIT(F_TX_INT_MASK_MS_BIT, status);
	ring_wr32(ring, N20_DMA_REG_INT_MASK, status);
}

static void n20_enable_txrxring_irq(struct mce_ring *ring)
{
	u32 status = 0;

	if (!ring)
		return;

	CLR_BIT(F_TX_INT_MASK_EN_BIT, status);
	CLR_BIT(F_RX_INT_MASK_EN_BIT, status);
	SET_BIT(F_TX_INT_MASK_MS_BIT, status);
	SET_BIT(F_RX_INT_MASK_MS_BIT, status);
	ring_wr32(ring, N20_DMA_REG_INT_MASK, status);
}

static void n20_disable_txrxring_irq(struct mce_ring *ring)
{
	u32 status = 0;

	if (!ring)
		return;

	status = 0;
	SET_BIT(F_TX_INT_MASK_EN_BIT, status);
	SET_BIT(F_RX_INT_MASK_EN_BIT, status);
	SET_BIT(F_TX_INT_MASK_MS_BIT, status);
	SET_BIT(F_RX_INT_MASK_MS_BIT, status);
	ring_wr32(ring, N20_DMA_REG_INT_MASK, status);
}

static void n20_start_txring(struct mce_ring *tx_ring)
{
	if (!tx_ring)
		return;

	/* enable queue */
	ring_wr32(tx_ring, N20_DMA_REG_TX_START,
		  F_TX_START_FLR_EN | F_TX_START_EN);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_LEN, tx_ring->count);
	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_TAIL, tx_ring->next_to_use);
}

static void n20_stop_txring(struct mce_ring *tx_ring)
{
	u32 timeout = 0;
	u32 head = 0;
	u32 tail = 0;

	if (!tx_ring)
		return;

	do {
		head = ring_rd32(tx_ring, N20_DMA_REG_TX_DESC_HEAD);
		tail = ring_rd32(tx_ring, N20_DMA_REG_TX_DESC_TAIL);
		if (head == tail)
			break;

		if ((++timeout) > 200) {
			dev_err(tx_ring->dev,
				"200 wait tx-%u done timeout, head-%u tail-%u\n",
				tx_ring->q_index, head, tail);
			break;
		}
		usleep_range(30000, 50000);
	} while (head != tail);

	/* disable queue */
	ring_wr32(tx_ring, N20_DMA_REG_TX_START, F_TX_START_FLR_EN);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_LEN, tx_ring->count);
	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_TAIL, 0);
}

static void n20_set_rxring_hw_dim(struct mce_ring *rx_ring, bool enable)
{
	struct mce_dim_cq_moder mce_rx_dim[2][MCE_HW_PROFILE] = {
		{
#ifdef MCE_RX_WB_COAL
			/* soc can remove this */
			{ 16, 256 },
			{ 16, 128 },
#else
			{ 2, 256 },
			{ 8, 128 },
#endif
			{ 16, 64 },
			{ 32, 64 },
			{ 64, 64 } },
		{ /* 2 is 1 since hw is 1 << x */
		  /* 1 << (fls(2) - 1) == 1 us */
		  { 2, 256 },
		  { 8, 256 },
		  { 64, 256 },
		  { 128, 256 },
		  { 256, 256 }
		}
	};
	u32 reg = 0;
	int i;
#define MCE_RX_DIM_MODE (0)

	if (!enable) {
		reg = ring_rd32(rx_ring, DMA_REG_RX_INT_FRAMES);
		MODIFY_BITFIELD(reg, 0, 1, 31);
		ring_wr32(rx_ring, DMA_REG_RX_INT_FRAMES, reg);
		return;
	}

	ring_wr32(rx_ring, DMA_REG_RX_PKT_RATE_LOW, IRQ_MIN_200K_RX);
	ring_wr32(rx_ring, DMA_REG_RX_PKT_RATE_HIGH, IRQ_MAX_200K_RX);
#ifdef STEP_DIM
	reg = ring_rd32(rx_ring, DMA_REG_RX_INT_FRAMES);
	MODIFY_BITFIELD(reg, 1, 1, 31);
	MODIFY_BITFIELD(reg, 1, 1, 30);
	MODIFY_BITFIELD(reg, 5, 8, 20);
	ring_wr32(rx_ring, DMA_REG_RX_INT_FRAMES, reg);
#else
	reg = ring_rd32(rx_ring, DMA_REG_RX_INT_FRAMES);
	MODIFY_BITFIELD(reg, 1, 1, 31);
	MODIFY_BITFIELD(reg, 1, 8, 20);

	MODIFY_BITFIELD(reg, 1, 2, 28);

	for (i = 0; i < MCE_HW_PROFILE; i++) {
		MODIFY_BITFIELD(reg,
				fls(mce_rx_dim[MCE_RX_DIM_MODE][i].pkts) - 1, 4,
				(MCE_HW_PROFILE - i - 1) * 4);
	}
	ring_wr32(rx_ring, DMA_REG_RX_INT_FRAMES, reg);
	reg = ring_rd32(rx_ring, DMA_REG_RX_INT_USECS);
	for (i = 0; i < MCE_HW_PROFILE; i++) {
		MODIFY_BITFIELD(reg,
				fls(mce_rx_dim[MCE_RX_DIM_MODE][i].usec) - 1, 4,
				(MCE_HW_PROFILE - i - 1) * 4);
	}
	ring_wr32(rx_ring, DMA_REG_RX_INT_USECS, reg);
#endif
}

static void n20_set_txring_hw_dim(struct mce_ring *tx_ring, bool enable)
{
	struct mce_dim_cq_moder mce_tx_dim[2][MCE_HW_PROFILE] = {
		{ { 5, 128 }, { 8, 64 }, { 16, 32 }, { 32, 32 }, { 64, 32 } },
		{ /* 2 is 1 since hw is 1 << x */
		  /* 1 << (fls(2) - 1) == 1 us */
		  { 2, 128 },
		  { 8, 128 },
		  { 32, 128 },
		  { 64, 128 },
		  { 128, 128 }
		}
	};
	u32 reg = 0;
	int i;
#define MCE_TX_DIM_MODE (1)

	if (!enable) {
		reg = ring_rd32(tx_ring, DMA_REG_TX_INT_FRAMES);
		MODIFY_BITFIELD(reg, 0, 1, 31);
		ring_wr32(tx_ring, DMA_REG_TX_INT_FRAMES, reg);
		return;
	}

	ring_wr32(tx_ring, DMA_REG_TX_PKT_RATE_LOW, IRQ_MIN_200K);
	ring_wr32(tx_ring, DMA_REG_TX_PKT_RATE_HIGH, IRQ_MAX_200K);
#ifdef STEP_DIM
	reg = ring_rd32(tx_ring, DMA_REG_TX_INT_FRAMES);
	MODIFY_BITFIELD(reg, 1, 1, 31);
	MODIFY_BITFIELD(reg, 1, 1, 30);
	MODIFY_BITFIELD(reg, 5, 8, 20);
	ring_wr32(tx_ring, DMA_REG_TX_INT_FRAMES, reg);
#else
	reg = ring_rd32(tx_ring, DMA_REG_TX_INT_FRAMES);
	MODIFY_BITFIELD(reg, 1, 1, 31);
	/* 1 << xx */
	MODIFY_BITFIELD(reg, 1, 8, 20);

	MODIFY_BITFIELD(reg, 1, 2, 28);

	for (i = 0; i < MCE_HW_PROFILE; i++) {
		MODIFY_BITFIELD(reg,
				fls(mce_tx_dim[MCE_TX_DIM_MODE][i].pkts) - 1, 4,
				(MCE_HW_PROFILE - i - 1) * 4);
	}
	ring_wr32(tx_ring, DMA_REG_TX_INT_FRAMES, reg);

	reg = ring_rd32(tx_ring, DMA_REG_TX_INT_USECS);

	for (i = 0; i < MCE_HW_PROFILE; i++) {
		MODIFY_BITFIELD(reg,
				fls(mce_tx_dim[MCE_TX_DIM_MODE][i].usec) - 1, 4,
				(MCE_HW_PROFILE - i - 1) * 4);
	}
	ring_wr32(tx_ring, DMA_REG_TX_INT_USECS, reg);
#endif
}

static void n20_set_txring_ctx(struct mce_ring *tx_ring, struct mce_hw *hw)
{
	struct mce_vsi *vsi = tx_ring->vsi;

	if (!tx_ring || !vsi)
		return;

	tx_ring->ring_addr =
		hw->eth_bar_base +
		N20_RING_OFF(tx_ring->q_index + hw->ring_base_addr);
	tx_ring->tail = tx_ring->ring_addr + N20_DMA_REG_TX_DESC_TAIL;
	tx_ring->next_to_use = ring_rd32(tx_ring, N20_DMA_REG_TX_DESC_HEAD);
	tx_ring->next_to_clean = tx_ring->next_to_use;

	if (tx_ring->next_to_use > tx_ring->count)
		return;

	/* disable queue */
	ring_wr32(tx_ring, N20_DMA_REG_TX_START, F_TX_START_FLR_EN);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_BASE_ADDR_LO, (u32)tx_ring->dma);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_BASE_ADDR_HI,
		  (u32)((tx_ring->dma) >> 32));

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_LEN, tx_ring->count);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_FETCH_CTRL,
		  (56 << 0) | (4 << 16));

	ring_wr32(tx_ring, N20_DMA_REG_TX_INT_DELAY_TIMER,
		  tx_ring->q_vector->tx.dim_params.usecs * hw->axi_mhz);

	ring_wr32(tx_ring, N20_DMA_REG_TX_INT_DELAY_PKTCNT,
		  tx_ring->q_vector->tx.dim_params.frames);

	ring_wr32(tx_ring, N20_DMA_REG_TX_FLOW_CTRL_TH, 0);

	ring_wr32(tx_ring, N20_DMA_REG_TX_FLOW_CTRL_TM, 0);
}

static void n20_set_txring_intr_coal(struct mce_ring *tx_ring)
{
	struct mce_hw *hw = &tx_ring->vsi->back->hw;
	struct mce_ring_container *tx = NULL;

	if (!tx_ring)
		return;

	tx = &tx_ring->q_vector->tx;
	if (!tx)
		return;

	/* maybe not setup always? */
	if (tx->dim_params.usecs != tx->dim_params.last_usecs)
		ring_wr32(tx_ring, N20_DMA_REG_TX_INT_DELAY_TIMER,
			  tx->dim_params.usecs * hw->axi_mhz);
	if (tx->dim_params.frames != tx->dim_params.last_frames)
		ring_wr32(tx_ring, N20_DMA_REG_TX_INT_DELAY_PKTCNT,
			  tx->dim_params.frames);
	tx->dim_params.last_frames = tx->dim_params.frames;
	tx->dim_params.last_usecs = tx->dim_params.usecs;
}

static int n20_cfg_txring_bw_lmt(struct mce_ring *tx_ring, u32 maxrate)
{
	struct mce_hw *hw = &tx_ring->vsi->back->hw;
	u32 th = (maxrate * 1000) >> 3;
	u32 tm = 1000 * hw->axi_mhz;

	ring_wr32(tx_ring, N20_DMA_REG_TX_FLOW_CTRL_TH, th);
	ring_wr32(tx_ring, N20_DMA_REG_TX_FLOW_CTRL_TM, tm);

	return 0;
}

static void n20_enable_rxring_irq(struct mce_ring *ring)
{
	u32 status = 0;

	if (!ring)
		return;

	CLR_BIT(F_RX_INT_MASK_EN_BIT, status);
	SET_BIT(F_RX_INT_MASK_MS_BIT, status);
	ring_wr32(ring, N20_DMA_REG_INT_MASK, status);
}

static void n20_disable_rxring_irq(struct mce_ring *ring)
{
	u32 status = 0;

	if (!ring)
		return;

	status = 0;
	SET_BIT(F_RX_INT_MASK_EN_BIT, status);
	SET_BIT(F_RX_INT_MASK_MS_BIT, status);
	ring_wr32(ring, N20_DMA_REG_INT_MASK, status);
}

static void n20_start_rxring(struct mce_ring *rx_ring)
{
	if (!rx_ring)
		return;

	/* enable queue */
	ring_wr32(rx_ring, N20_DMA_REG_RX_START,
		  F_RX_START_FLR_EN | F_RX_START_EN);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_LEN, rx_ring->count);
	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_TAIL, rx_ring->next_to_use);
}

static void n20_stop_rxring(struct mce_ring *rx_ring)
{
	if (!rx_ring)
		return;

	/* disable rxring */
	ring_wr32(rx_ring, N20_DMA_REG_RX_START, F_RX_START_FLR_EN);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_LEN, 0);
	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_TAIL, 0);
}

static void n20_set_rxring_ctx(struct mce_ring *rx_ring, struct mce_hw *hw)
{
	struct mce_vsi *vsi = rx_ring->vsi;

	if (!rx_ring || !vsi)
		return;

	rx_ring->ring_addr =
		hw->eth_bar_base +
		N20_RING_OFF(rx_ring->q_index + hw->ring_base_addr);
	rx_ring->tail = rx_ring->ring_addr + N20_DMA_REG_RX_DESC_TAIL;
	rx_ring->next_to_use = ring_rd32(rx_ring, N20_DMA_REG_RX_DESC_HEAD);
	rx_ring->next_to_clean = rx_ring->next_to_use;

	if (rx_ring->next_to_use > rx_ring->count)
		return;

	/* disable queue */
	ring_wr32(rx_ring, N20_DMA_REG_RX_START, F_RX_START_FLR_EN);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_BASE_ADDR_LO, (u32)rx_ring->dma);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_BASE_ADDR_HI,
		  (u32)((rx_ring->dma) >> 32));

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_LEN, rx_ring->count);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_FETCH_CTRL,
		  (48 << 0) | (16 << 16));

	ring_wr32(rx_ring, N20_DMA_REG_RX_INT_DELAY_TIMER,
		  rx_ring->q_vector->rx.dim_params.usecs * hw->axi_mhz);

	ring_wr32(rx_ring, N20_DMA_REG_RX_INT_DELAY_PKTCNT,
		  rx_ring->q_vector->rx.dim_params.frames);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_TIMEOUT_TH, 0);

	ring_wr32(rx_ring, N20_DMA_REG_RX_SCATTER_LENGTH,
		  DIV_ROUND_UP(rx_ring->rx_buf_len, 64));
}

static void n20_set_rxring_intr_coal(struct mce_ring *rx_ring)
{
	struct mce_hw *hw = &rx_ring->vsi->back->hw;
	struct mce_ring_container *rx = NULL;

	if (!rx_ring)
		return;

	rx = &rx_ring->q_vector->rx;
	if (!rx)
		return;

	/* maybe not setup always */
	/* todo */
	if (rx->dim_params.usecs != rx->dim_params.last_usecs)
		ring_wr32(rx_ring, N20_DMA_REG_RX_INT_DELAY_TIMER,
			  rx->dim_params.usecs * hw->axi_mhz);
	if (rx->dim_params.frames != rx->dim_params.last_frames)
		ring_wr32(rx_ring, N20_DMA_REG_RX_INT_DELAY_PKTCNT,
			  rx->dim_params.frames);
	rx->dim_params.last_frames = rx->dim_params.frames;
	rx->dim_params.last_usecs = rx->dim_params.usecs;
}

/**
 * n20_set_vlan_strip - Enable or disable the function of the rx vlan offload at the hw level
 * @hw:  ptr to the hw
 * @features: the feature set that the stack is suggesting
 */
static void n20_set_vlan_strip(struct mce_hw *hw, netdev_features_t features)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 strip_cnt = pf->vlan_strip_cnt;
	u32 i = 0, value = 0, strip_en = 0;

	if (strip_cnt > N20_VLAN_MAX_STRIP_CNT) {
		dev_warn(mce_hw_to_dev(hw),
			 "pf vlan strip count:%d exceed!"
			 "(which range is >= 0 and <= %d), force setup to 1.\n",
			 strip_cnt, N20_VLAN_MAX_STRIP_CNT);
		pf->vlan_strip_cnt = 1;
		strip_cnt = pf->vlan_strip_cnt;
	}

	if ((features & NETIF_F_HW_VLAN_CTAG_RX) ||
	    (features & NETIF_F_HW_VLAN_STAG_RX))
		strip_en = 1;
	else if (test_bit(MCE_FLAG_VF_INSERT_VLAN, pf->flags))
		strip_en = 1;

	pf->vlan_strip_cnt = 0;
	if (test_bit(MCE_FLAG_VF_INSERT_VLAN, pf->flags))
		pf->vlan_strip_cnt++;
	if (features & NETIF_F_HW_VLAN_CTAG_RX ||
	    features & NETIF_F_HW_VLAN_STAG_RX)
		pf->vlan_strip_cnt++;
	strip_cnt = pf->vlan_strip_cnt;

	for (i = hw->ring_base_addr; i < hw->ring_max_cnt + hw->ring_base_addr;
	     i++) {
		value = rd32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)));
		F_SET_VLAN_STRIP_EN(value, strip_en);
		F_SET_VLAN_STRIP_CNT(value, strip_cnt);
		F_SET_RETA_HASH_QUEUE_ID(value, 0);
		wr32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)), value);
	}
}

/**
 * n20_set_rss_hash - Enable or disable the function of RSS at the hw level
 * @hw:  ptr to the hw
 * @features: the feature set that the stack is suggesting
 */
static void n20_set_rss_hash(struct mce_hw *hw, netdev_features_t features)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 mrqc_id = hw->func_caps.common_cap.rss_key_size / 4;
	u16 vfnum = _vfnum(hw, PFINFO_IDX);
	u32 val;

	val = rd32(hw, N20_RSS_OFF(N20_RSS_HASH_ENTRY(mrqc_id, vfnum)));

	if (features & NETIF_F_RXHASH) {
		val |= F_RSS_HASH_EN;
		if (hw->rss_hfunc == ETH_RSS_HASH_TOP)
			val &= ~F_RSS_HASH_XOR_OR_TOP_EN;
		if (hw->rss_hfunc == ETH_RSS_HASH_XOR)
			val |= F_RSS_HASH_XOR_OR_TOP_EN;
		if (test_bit(MCE_FLAG_PF_RSS_MODE_ORDER, pf->flags)) {
			val &= ~F_RSS_HASH_XOR_OR_TOP_EN;
			val |= F_RSS_HASH_ORDER_EN;
		}
	} else {
		val &= ~F_RSS_HASH_EN;
	}
	wr32(hw, N20_RSS_OFF(N20_RSS_HASH_ENTRY(mrqc_id, vfnum)), val);
}

/**
 * n20_set_rss_key - Set RSS key to hw
 * @hw:  ptr to the hw
 */
static void n20_set_rss_key(struct mce_hw *hw)
{
	u32 entry_size = ((hw->func_caps.common_cap.rss_key_size) / 4);
	u16 vfnum = _vfnum(hw, PFINFO_IDX);
	u32 tmp_rss_key = 0;
	u32 i = 0;

	for (i = 0; i < entry_size; i++) {
		tmp_rss_key = (hw->rss_key[(i * 4)]);
		tmp_rss_key |= (hw->rss_key[(i * 4) + 1] << 8);
		tmp_rss_key |= (hw->rss_key[(i * 4) + 2] << 16);
		tmp_rss_key |= (hw->rss_key[(i * 4) + 3] << 24);
		tmp_rss_key = (__force u32)htonl(tmp_rss_key);
		wr32(hw,
		     N20_RSS_OFF(N20_RSS_HASH_ENTRY(entry_size - i - 1, vfnum)),
		     tmp_rss_key);
	}
}

/**
 * n20_set_rss_hash_type - Set the hash type that triggers RSS
 * @hw:  ptr to the hw
 */
static void n20_set_rss_hash_type(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 mrqc_id = hw->func_caps.common_cap.rss_key_size / 4;
	u16 vfnum = _vfnum(hw, PFINFO_IDX);
	u32 val;

	val = rd32(hw, N20_RSS_OFF(N20_RSS_HASH_ENTRY(mrqc_id, vfnum)));
	MODIFY_BITFIELD(val, hw->rss_hash_type, 6, 0);

	val &= ~(F_IPV4_HASH_TEID_EN | F_IPV6_HASH_TEID_EN |
		 F_IPV6_HASH_SPI_EN | F_IPV4_HASH_SPI_EN | F_RSS_HASH_PTP_EN);

	/* rss force setup ipv4 and ipv6 */
	val |= F_IPV6_HASH_EN | F_IPV4_HASH_EN;
	if (test_bit(MCE_FLAG_RSS_MISC_TYPE_PTP, pf->flags))
		val |= F_RSS_HASH_PTP_EN;
	if (test_bit(MCE_FLAG_RSS_MISC_TYPE_IPV4_SPI, pf->flags))
		val |= F_IPV4_HASH_SPI_EN;
	if (test_bit(MCE_FLAG_RSS_MISC_TYPE_IPV6_SPI, pf->flags))
		val |= F_IPV6_HASH_SPI_EN;
	if (test_bit(MCE_FLAG_RSS_MISC_TYPE_IPV4_TEID, pf->flags))
		val |= F_IPV4_HASH_TEID_EN;
	if (test_bit(MCE_FLAG_RSS_MISC_TYPE_IPV6_TEID, pf->flags))
		val |= F_IPV6_HASH_TEID_EN;
	wr32(hw, N20_RSS_OFF(N20_RSS_HASH_ENTRY(mrqc_id, vfnum)), val);
}

/**
 * n20_set_rss_table - Set the hash indirect table at hw level
 * @hw:  ptr to the hw
 * @q_cnt: queue count
 * Returns: The result of the operation.
 */
static int n20_set_rss_table(struct mce_hw *hw, u16 q_cnt)
{
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	u32 table_size = pf->rss_tb_size;
	u32 act_reta = 0;
	u32 pft_reta = 0;
	u16 i = 0;

	if (!q_cnt)
		q_cnt = table_size;
	for (i = 0; i < table_size; i++) {
		/* if should reset rss table */
		if (!(hw->hw_flags & MCE_F_RSS_TABLE_INITED))
			hw->rss_table[i] = i % q_cnt;
		if (i % 2 == 0) {
			pft_reta = (hw->rss_table[i] + hw->ring_base_addr) &
				   0xffff;
		} else {
			pft_reta |= (((hw->rss_table[i] + hw->ring_base_addr) &
				      0xffff)
				     << 16);
			wr32(hw, N20_RSS_OFF(N20_RSS_PFT_CONFIG_MEM(i / 2)),
			     pft_reta);
		}
		act_reta = rd32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)));
		act_reta |= F_RSS_RETA_QUEUE_EN;
		wr32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)), act_reta);
	}

	hw->hw_flags |= MCE_F_RSS_TABLE_INITED;
	return 0;
}

static void n20_set_ucmc_hash_type_fltr(struct mce_hw *hw)
{
	u32 val, type = hw->uc_mc_hash_ctl.type;

	if (type >= MCE_UC_MC_HASH_TYPE_MAX) {
		type = MCE_UC_MC_HASH_TYPE_BIT_11_0_OR_47_36;
		hw->uc_mc_hash_ctl.uc_s_low = true;
		hw->uc_mc_hash_ctl.mc_s_low = true;
	}

	val = rd32(hw, N20_ETH_L2_CTRL0);
	val &= ~GENMASK(3, 0);
	val |= type;
	if (hw->uc_mc_hash_ctl.uc_s_low)
		val |= BIT(2);
	if (hw->uc_mc_hash_ctl.mc_s_low)
		val |= BIT(3);
	wr32(hw, N20_ETH_L2_CTRL0, val);
}

/**
 * n20_set_uc_filter - Enable or disable the uc filter at the hw level
 * @hw:  ptr to the hw
 * @enable: true or false
 */
static void n20_set_uc_filter(struct mce_hw *hw, bool enable)
{
	u32 value;

	/* when turn on sriov, no support setup L2 filter */
	if (hw->promisc_no_permit)
		return;

	value = rd32(hw, N20_ETH_L2_CTRL0);
	if (enable)
		value |= F_UC_HASH_EN;
	else
		value &= (~F_UC_HASH_EN);

	wr32(hw, N20_ETH_L2_CTRL0, value);
}

static void __n20_calc_uc_mc_hash_cfg(u16 hash_v, u32 *idx, u32 *bit)
{
	*idx = (hash_v >> 5) & 0x7f;
	*bit = 1 << (hash_v & 0x1f);
}

/**
 * n20_add_uc_filter - Add addr for uc filter at the hw level
 * @hw:  ptr to the hw
 * @hash_v: hash vector value
 */
static void n20_add_uc_filter(struct mce_hw *hw, u16 hash_v)
{
	u32 val, idx, bit;

	__n20_calc_uc_mc_hash_cfg(hash_v, &idx, &bit);
	val = rd32(hw, N20_ETH_UC_HASH_TABLE(idx));
	val |= bit;
	wr32(hw, N20_ETH_UC_HASH_TABLE(idx), val);
}

/**
 * n20_del_uc_filter - Del addr for uc filter at the hw level
 * @hw:  ptr to the hw
 * @hash_v: hash vector value
 */
static void n20_del_uc_filter(struct mce_hw *hw, u16 hash_v)
{
	u32 val, idx, bit;

	__n20_calc_uc_mc_hash_cfg(hash_v, &idx, &bit);
	val = rd32(hw, N20_ETH_UC_HASH_TABLE(idx));
	val &= ~bit;
	wr32(hw, N20_ETH_UC_HASH_TABLE(idx), val);
}

/**
 * n20_set_mc_filter - Enable or disable the mc filter at the hw level
 * @hw:  ptr to the hw
 * @enable: true or false
 */
static void n20_set_mc_filter(struct mce_hw *hw, bool enable)
{
	u32 value;

	if (hw->promisc_no_permit)
		return;

	value = rd32(hw, N20_ETH_L2_CTRL0);
	if (enable)
		value |= F_MC_HASH_EN;
	else
		value &= (~F_MC_HASH_EN);

	wr32(hw, N20_ETH_L2_CTRL0, value);
}

/**
 * n20_add_mc_filter - Add addr for mc filter at the hw level
 * @hw:  ptr to the hw
 * @hash_v: hash vector value
 */
static void n20_add_mc_filter(struct mce_hw *hw, u16 hash_v)
{
	u32 val, idx, bit;

	__n20_calc_uc_mc_hash_cfg(hash_v, &idx, &bit);
	val = rd32(hw, N20_ETH_MC_HASH_TABLE(idx));
	val |= bit;
	wr32(hw, N20_ETH_MC_HASH_TABLE(idx), val);
}

/**
 * n20_del_mc_filter - Add addr for mc filter at the hw level
 * @hw:  ptr to the hw
 * @hash_v: hash vector value
 */
static void n20_del_mc_filter(struct mce_hw *hw, u16 hash_v)
{
	u32 val, idx, bit;

	__n20_calc_uc_mc_hash_cfg(hash_v, &idx, &bit);
	val = rd32(hw, N20_ETH_MC_HASH_TABLE(idx));
	val &= ~bit;
	wr32(hw, N20_ETH_MC_HASH_TABLE(idx), val);
}

static void n20_clr_mc_filter(struct mce_hw *hw)
{
	int i;

	for (i = 0; i < 128; i++)
		wr32(hw, N20_ETH_MC_HASH_TABLE(i), 0);
}

/**
 * n20_set_mc_promisc - Enable or disable the mc promisc at the hw level
 * @hw:  ptr to the hw
 * @enable: true or false
 */
static void n20_set_mc_promisc(struct mce_hw *hw, bool enable)
{
	int vfid = _vfnum(hw, PFINFO_IDX);

	u32 value = rd32(hw, N20_ETH_VPORT_ATTR_TABLE(vfid));

	if (enable)
		value |= F_VPORT_MC_PROMISC_EN;
	else
		value &= (~F_VPORT_MC_PROMISC_EN);

	wr32(hw, N20_ETH_VPORT_ATTR_TABLE(vfid), value);
}

/**
 * n20_set_rx_promisc - Enable or disable the rx promisc at the hw level
 * @hw:  ptr to the hw
 * @enable: true or false
 */
static void n20_set_rx_promisc(struct mce_hw *hw, bool enable)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 value = rd32(hw, N20_ETH_L2_CTRL0);
	int vfid = _vfnum(hw, PFINFO_IDX);

	if (enable) {
		value &= (~F_DMAC_FILTER_EN);
		value &= (~F_VLAN_FILTER_EN);
	} else {
		if (test_bit(DMAC_FILTER_EN, hw->l2_fltr_flags))
			value |= F_DMAC_FILTER_EN;
		if (test_bit(VLAN_FILTER_EN, hw->l2_fltr_flags))
			value |= F_VLAN_FILTER_EN;
	}

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		value |= F_DMAC_FILTER_EN;

	wr32(hw, N20_ETH_L2_CTRL0, value);

	value = rd32(hw, N20_ETH_VPORT_ATTR_TABLE(vfid));
	if (enable)
		value |= F_VPORT_UC_PROMISC_EN | F_VPORT_TRUE_PROMISC_EN;
	else
		value &= ~(F_VPORT_UC_PROMISC_EN | F_VPORT_TRUE_PROMISC_EN);
	wr32(hw, N20_ETH_VPORT_ATTR_TABLE(vfid), value);
}

/**
 * n20_set_vlan_filter - Enable or disable vlan filter at the hw level
 * @hw:  ptr to the hw
 * @features: the feature set that the stack is suggesting
 */
static void n20_set_vlan_filter(struct mce_hw *hw, netdev_features_t features)
{
	u32 value;

	/* when turn on sriov, no support setup L2 filter */
	if (hw->promisc_no_permit)
		return;
	value = rd32(hw, N20_ETH_L2_CTRL0);
	if ((features & NETIF_F_HW_VLAN_CTAG_FILTER) ||
	    (features & NETIF_F_HW_VLAN_STAG_FILTER)) {
		value |= F_VLAN_FILTER_EN;
		set_bit(VLAN_FILTER_EN, hw->l2_fltr_flags);
	} else {
		value &= (~F_VLAN_FILTER_EN);
		clear_bit(VLAN_FILTER_EN, hw->l2_fltr_flags);
	}

	wr32(hw, N20_ETH_L2_CTRL0, value);
}

/**
 * n20_add_vlan_filter - Add vlan id  for vlan filter at the hw level
 * @hw:  ptr to the hw
 * @vid: vlan id for filter
 */
static void n20_add_vlan_filter(struct mce_hw *hw, u16 vid)
{
	u32 vid_idx = 0;
	u32 vid_bit = 0;
	u32 value = 0;

	vid_idx = (u32)((vid >> 5) & (0x7f));
	vid_bit = (u32)(1 << (vid & 0x1f));
	value = rd32(hw, N20_ETH_VLAN_HASH_TABLE(vid_idx));
	value |= vid_bit;
	wr32(hw, N20_ETH_VLAN_HASH_TABLE(vid_idx), value);
}

/**
 * n20_del_vlan_filter - Del vlan id  for vlan filter at the hw level
 * @hw:  ptr to the hw
 * @vid: vlan id for filter
 */
static void n20_del_vlan_filter(struct mce_hw *hw, u16 vid)
{
	u32 vid_idx = 0;
	u32 vid_bit = 0;
	u32 value = 0;

	vid_idx = (u32)((vid >> 5) & (0x7f));
	vid_bit = (u32)(1 << (vid & 0x1f));
	value = rd32(hw, N20_ETH_VLAN_HASH_TABLE(vid_idx));
	value &= ~vid_bit;
	wr32(hw, N20_ETH_VLAN_HASH_TABLE(vid_idx), value);
}

/**
 * __n20_add_ntuple_filter - add ntuple rule to hw
 * @hw:  ptr to the hw
 * @rule: ntuple-t rule
 */
static void __n20_add_ntuple_filter(struct mce_hw *hw,
				    struct mce_fdir_fltr *rule)
{
	u32 filter = 0, policy = 0, src_ip = 0, dst_ip = 0, port = 0;
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	enum mce_fltr_ptype flow_type = rule->flow_type;
	int vfid;
	u32 loc;

	if (!rule)
		return;

	vfid = rule->vfid ? rule->vfid - 1 : pf->default_vport;

	loc = MCE_ACL_MAX_TUPLE5_CNT - 1 - rule->tuple5_loc;
	filter |= F_T5_L4_TYPE_MASK;
	switch (flow_type) {
	case MCE_FLTR_PTYPE_IPV4_TCP:
		F_T5_SET_L4_TYPE(filter, IPPROTO_TCP);
		filter &= ~F_T5_L4_TYPE_MASK;
		break;
	case MCE_FLTR_PTYPE_IPV4_UDP:
		F_T5_SET_L4_TYPE(filter, IPPROTO_UDP);
		filter &= ~F_T5_L4_TYPE_MASK;
		break;
	case MCE_FLTR_PTYPE_IPV4_SCTP:
		F_T5_SET_L4_TYPE(filter, IPPROTO_SCTP);
		filter &= ~F_T5_L4_TYPE_MASK;
		break;
	case MCE_FLTR_PTYPE_IPV6_TCP:
		F_T5_SET_L4_TYPE(filter, IPPROTO_TCP);
		filter &= ~F_T5_L4_TYPE_MASK;
		break;
	case MCE_FLTR_PTYPE_IPV6_UDP:
		F_T5_SET_L4_TYPE(filter, IPPROTO_UDP);
		filter &= ~F_T5_L4_TYPE_MASK;
		break;
	case MCE_FLTR_PTYPE_IPV6_SCTP:
		F_T5_SET_L4_TYPE(filter, IPPROTO_SCTP);
		filter &= ~F_T5_L4_TYPE_MASK;
		break;
	case MCE_FLTR_PTYPE_IPV4_OTHER:
		F_T5_SET_L4_TYPE(filter, rule->ip.v4.proto);
		filter &= ~F_T5_L4_TYPE_MASK;
		break;
	case MCE_FLTR_PTYPE_IPV6_OTHER:
		F_T5_SET_L4_TYPE(filter, rule->ip.v6.proto);
		filter &= ~F_T5_L4_TYPE_MASK;
		break;
	default:
		return;
	}

	if (flow_type == MCE_FLTR_PTYPE_IPV4_OTHER ||
	    flow_type == MCE_FLTR_PTYPE_IPV4_TCP ||
	    flow_type == MCE_FLTR_PTYPE_IPV4_UDP ||
	    flow_type == MCE_FLTR_PTYPE_IPV4_SCTP) {
		src_ip = (__force u32)htonl((__force u32)rule->ip.v4.src_ip);
		if (src_ip == 0)
			filter |= F_T5_SIP_MASK;
		else
			filter &= ~F_T5_SIP_MASK;

		dst_ip = (__force u32)htonl((__force u32)rule->ip.v4.dst_ip);
		if (dst_ip == 0)
			filter |= F_T5_DIP_MASK;
		else
			filter &= ~F_T5_DIP_MASK;

		F_T5_SET_IP4_TYPE(filter);
	}

	if (flow_type == MCE_FLTR_PTYPE_IPV4_TCP ||
	    flow_type == MCE_FLTR_PTYPE_IPV4_UDP ||
	    flow_type == MCE_FLTR_PTYPE_IPV4_SCTP) {
		if (rule->ip.v4.src_port == 0)
			filter |= F_T5_SPORT_MASK;
		else
			filter &= ~F_T5_SPORT_MASK;
		F_T5_SET_SPORT(port, (__force u16)htons((__force u16)
							 rule->ip.v4.src_port));

		if (rule->ip.v4.dst_port == 0)
			filter |= F_T5_DPORT_MASK;
		else
			filter &= ~F_T5_DPORT_MASK;
		F_T5_SET_DPORT(port, (__force u16)htons((__force u16)
							 rule->ip.v4.dst_port));
	}

	if (flow_type == MCE_FLTR_PTYPE_IPV4_OTHER) {
		/*  other type should mask sport dport */
		filter |= F_T5_SPORT_MASK;
		filter |= F_T5_DPORT_MASK;
	}

	if (flow_type == MCE_FLTR_PTYPE_IPV6_OTHER ||
	    flow_type == MCE_FLTR_PTYPE_IPV6_TCP ||
	    flow_type == MCE_FLTR_PTYPE_IPV6_UDP ||
	    flow_type == MCE_FLTR_PTYPE_IPV6_SCTP) {
		F_T5_SET_IP6_TYPE(filter);
		filter |= F_T5_DIP_MASK;
		filter |= F_T5_SIP_MASK;
	}

	if (flow_type == MCE_FLTR_PTYPE_IPV6_TCP ||
	    flow_type == MCE_FLTR_PTYPE_IPV6_UDP ||
	    flow_type == MCE_FLTR_PTYPE_IPV6_SCTP) {
		if (rule->ip.v6.src_port == 0)
			filter |= F_T5_SPORT_MASK;
		else
			filter &= ~F_T5_SPORT_MASK;
		F_T5_SET_SPORT(port, (__force u16)htons((__force u16)
							 rule->ip.v6.src_port));

		if (rule->ip.v6.dst_port == 0)
			filter |= F_T5_DPORT_MASK;
		else
			filter &= ~F_T5_DPORT_MASK;
		F_T5_SET_DPORT(port, (__force u16)htons((__force u16)
							 rule->ip.v6.dst_port));
	}

	if (flow_type == MCE_FLTR_PTYPE_IPV6_OTHER) {
		/*  other type should mask sport dport */
		filter |= F_T5_SPORT_MASK;
		filter |= F_T5_DPORT_MASK;
	}

	filter |= F_T5_FILTER_EN;

	if (rule->fltr_action & F_FLTR_ACTION_DROP)
		policy |= F_ACL_ACTION_DROP;
	else
		policy &= ~F_ACL_ACTION_DROP;
	policy |= F_ACL_ACTION_RING_EN;
	F_ACL_ACTION_SET_RING_ID(policy, rule->q_id);
	F_T5_SET_VPORT_ID(filter, vfid);
	filter |= F_T5_VPORT_EN;
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_SIP(loc)), src_ip);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_DIP(loc)), dst_ip);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_PORT(loc)), port);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_FILTER(loc)), filter);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_POLICY(loc)), policy);

	hw->fdir_ntuple5_active_fltr++;

	logd(LOG_NTUPLE_INFO,
	     "add ntuple loc is : %u, ntuple cnt : %u action q_id is %u\n",
	     loc, hw->fdir_ntuple5_active_fltr, rule->q_id);
}

static void __n20_add_l2_filter(struct mce_hw *hw, struct mce_fdir_fltr *rule)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 etqs = 0, etqf = 0;
	int vfid;
	u32 loc;

	if (!rule)
		return;

	vfid = rule->vfid ? rule->vfid - 1 : pf->default_vport;

	loc = MCE_MAX_ETYPE_CNT - 1 - rule->etype_loc;
	rule->eth.type = rule->eth.type;
	etqf |= BIT(31);
	MODIFY_BITFIELD(etqf, rule->eth.type, 16, 0);
	wr32(hw, N20_ETH_RQA_ETQF_OFF(vfid, loc), etqf);
	logd(LOG_NTUPLE_INFO, "setup etqf %d loc %d %x --> %x\n", vfid, loc,
	     etqf, N20_ETH_RQA_ETQF_OFF(vfid, loc));
	etqs |= F_ACL_ACTION_RING_EN;
	if (rule->fltr_action & F_FLTR_ACTION_DROP)
		etqs |= F_ACL_ACTION_DROP;
	else
		etqs &= ~F_ACL_ACTION_DROP;
	F_ACL_ACTION_SET_RING_ID(etqs, rule->q_id);
	wr32(hw, N20_ETH_RQA_ETQS_OFF(vfid, loc), etqs);
	logd(LOG_NTUPLE_INFO, "setup etqs %d loc %d %x --> %x\n", vfid, loc,
	     etqs, N20_ETH_RQA_ETQS_OFF(vfid, loc));
	hw->fdir_etype_active_fltr++;
}

static void n20_add_filter(struct mce_hw *hw, struct mce_fdir_fltr *rule)
{
	if (rule->flow_type == MCE_FLTR_PTYPE_NONF_ETH)
		__n20_add_l2_filter(hw, rule);
	else
		__n20_add_ntuple_filter(hw, rule);
}

static void n20_del_ntuple_filter(struct mce_hw *hw, struct mce_fdir_fltr *rule)
{
	u32 loc;

	loc = MCE_ACL_MAX_TUPLE5_CNT - 1 - rule->tuple5_loc;
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_SIP(loc)), 0);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_DIP(loc)), 0);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_PORT(loc)), 0);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_FILTER(loc)), 0);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_POLICY(loc)), 0);

	hw->fdir_ntuple5_active_fltr--;
	dev_dbg(hw->dev, "[debug] del ntuple loc is : %u, ntuple cnt : %u\n",
		loc, hw->fdir_ntuple5_active_fltr);
}

static void __n20_del_l2_filter(struct mce_hw *hw, struct mce_fdir_fltr *rule)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 etqs = 0, etqf = 0;
	int vfid;
	u32 loc;

	if (!rule)
		return;

	vfid = rule->vfid ? rule->vfid - 1 : pf->default_vport;

	loc = MCE_MAX_ETYPE_CNT - 1 - rule->etype_loc;
	logd(LOG_NTUPLE_INFO, "clean etqf %d loc %d %x --> %x\n", vfid, loc,
	     etqf, N20_ETH_RQA_ETQF_OFF(vfid, loc));
	logd(LOG_NTUPLE_INFO, "clean etqs %d loc %d %x --> %x\n", vfid, loc,
	     etqs, N20_ETH_RQA_ETQS_OFF(vfid, loc));
	wr32(hw, N20_ETH_RQA_ETQF_OFF(vfid, loc), etqf);
	wr32(hw, N20_ETH_RQA_ETQS_OFF(vfid, loc), etqs);
	hw->fdir_etype_active_fltr--;
}

static void n20_del_filter(struct mce_hw *hw, struct mce_fdir_fltr *rule)
{
	if (rule->flow_type == MCE_FLTR_PTYPE_NONF_ETH)
		__n20_del_l2_filter(hw, rule);
	else
		n20_del_ntuple_filter(hw, rule);
}

static int __n20_get_udp_tnl_reg_base(enum mce_tunnel_type tnl_type)
{
	u32 reg_base = 0;

	if (tnl_type >= TNL_ALL)
		return 0;

	switch (tnl_type) {
	case TNL_VXLAN:
		reg_base = N20_ETH_VXLAN_PORT;
		break;
	case TNL_GENEVE:
		reg_base = N20_ETH_GENEVE_PORT;
		break;
	case TNL_VXLAN_GPE:
		reg_base = N20_ETH_VXLAN_GPE_PORT;
		break;
	default:
		return 0;
	}

	return reg_base;
}

static void n20_add_udp_tnl(struct mce_hw *hw, enum mce_tunnel_type tnl_type,
			    u16 port)
{
	struct mce_tunnel_entry *tnl_entry;
	u32 reg_base = 0;
	int i = 0;

	reg_base = __n20_get_udp_tnl_reg_base(tnl_type);
	if (reg_base == 0)
		return;

	for (i = 0; i < MCE_TUNNEL_MAX_ENTRIES; i++) {
		tnl_entry = &hw->tnl[tnl_type].tbl[i];
		if (tnl_entry->in_use)
			continue;
		wr32(hw, reg_base + 0x4 * i, port);
		tnl_entry->port = port;
		tnl_entry->in_use = true;
		tnl_entry->ref_cnt = 1;
		++hw->tnl[tnl_type].tnl_cnt;
		break;
	}
}

static void n20_del_udp_tnl(struct mce_hw *hw, enum mce_tunnel_type tnl_type,
			    u16 port)
{
	struct mce_tunnel_entry *tnl_entry;
	u32 reg_base = 0;
	int i = 0;

	reg_base = __n20_get_udp_tnl_reg_base(tnl_type);
	if (reg_base == 0)
		return;

	for (i = 0; i < MCE_TUNNEL_MAX_ENTRIES; i++) {
		tnl_entry = &hw->tnl[tnl_type].tbl[i];
		if (!tnl_entry->in_use)
			continue;

		if (tnl_entry->port != port)
			continue;

		if (tnl_entry->ref_cnt > 0) {
			tnl_entry->ref_cnt--;
		} else {
			WARN_ON(tnl_entry->default_port == 0);
			wr32(hw, reg_base + 0x4 * i, tnl_entry->default_port);
			tnl_entry->in_use = false;
			tnl_entry->port = 0;
			tnl_entry->ref_cnt = 0;
			hw->tnl[tnl_type].tnl_cnt--;
		}
	}
}

static void n20_restore_udp_tnl(struct mce_hw *hw,
				enum mce_tunnel_type tnl_type)
{
	struct mce_tunnel_entry *tnl_entry;
	u32 reg_base = 0;
	u16 port, i;

	reg_base = __n20_get_udp_tnl_reg_base(tnl_type);
	if (reg_base == 0)
		return;

	for (i = 0; i < MCE_TUNNEL_MAX_ENTRIES; i++) {
		tnl_entry = &hw->tnl[tnl_type].tbl[i];
		port = tnl_entry->in_use ? tnl_entry->port :
					   tnl_entry->default_port;
		wr32(hw, reg_base + 0x4 * i, port);
	}
}

static void n20_set_tun_select_inner(struct mce_hw *hw, bool inner)
{
	int vfid = _vfnum(hw, PFINFO_IDX);
	u32 val = 0;

	val = rd32(hw, N20_ETH_VPORT_ATTR_TABLE(vfid));
	if (inner)
		val |= F_VPORT_TUN_SELECT_INNER;
	else
		val &= (~F_VPORT_TUN_SELECT_INNER);
	val |= F_VPORT_TUN_SELECT_INNER_OUTER_EN;
	wr32(hw, N20_ETH_VPORT_ATTR_TABLE(vfid), val);
}

static void n20_set_pause(struct mce_hw *hw, int mtu)
{
	u32 tx_fifo_thresh[N20_FIFO_PROG_CNT] = { 0x100, 0x8, 0x8, 0x8,
						  0x8,	 0x8, 0x8, 0x8 };
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_flow_control *fc = &pf->fc;
	int set_fifo_l = 0;
	u32 val = 0;
	u32 val_mac;
	/* should relative with mtu */
	u32 rx_fifo_thresh[N20_FIFO_PROG_CNT] = { 0x100, 0x8, 0x8, 0x8,
						 0x8, 0x8, 0x8, 0x8 };
	u32 dflt_thresh[N20_FIFO_PROG_CNT] = { 0x100, 0x8, 0x8, 0x8,
					       0x8,   0x8, 0x8, 0x8 };
	u32 dflt_tx_cdc_fifo_thresh = 0x100;
	u32 paus_tx_cdc_fifo_thresh = 0x100;
	u32 cfg_adap = 0;
	u8 i = 0;

	if (mtu > NORMAL_MTU) {
		tx_fifo_thresh[0] = 0x110;
		set_fifo_l = 1;
	}
	/* if current_mode equal req_mode, nothing todo */
	if (fc->current_mode == fc->req_mode) {
		wr32(hw, N20_ETH_PORT_TX_PROGFULL(0), tx_fifo_thresh[0]);
		return;
	}
	/* Stop transmitting and receiving packets. */
	n20_enable_proc(hw);
	n20_set_dft_fifo_space(hw);

	val = rd32(hw, N20_ETH_PAUSE_CTRL);
	val_mac = rd32(hw, N20_M_CFG);

	val_mac &= ~(F_M_PAUSE_EN | F_M_PAUSE_STOP_EN);
	switch (fc->req_mode) {
	case MCE_FC_TX_PAUSE:
		val |= F_TX_PAUSE_EN;
		val &= ~F_RX_PAUSE_EN;
		val_mac |= F_M_PAUSE_EN;

		for (i = 0; i < N20_FIFO_PROG_CNT; i++) {
			wr32(hw, N20_ETH_PORT_TX_PROGFULL(i),
			     tx_fifo_thresh[i]);
			wr32(hw, N20_ETH_PORT_RX_PROGFULL(i), dflt_thresh[i]);
		}

		cfg_adap = rd32(hw, N20_ETH_CFG_ADAPTER_CTRL0);
		MODIFY_BITFIELD(cfg_adap, paus_tx_cdc_fifo_thresh, 9, F_TX_CDC);
		wr32(hw, N20_ETH_CFG_ADAPTER_CTRL0, cfg_adap);
		break;
	case MCE_FC_RX_PAUSE:
		val |= F_RX_PAUSE_EN;
		val &= ~F_TX_PAUSE_EN;
		val_mac |= F_M_PAUSE_EN | F_M_PAUSE_STOP_EN;

		for (i = 0; i < N20_FIFO_PROG_CNT; i++) {
			wr32(hw, N20_ETH_PORT_TX_PROGFULL(i), dflt_thresh[i]);
			wr32(hw, N20_ETH_PORT_RX_PROGFULL(i),
			     rx_fifo_thresh[i]);
		}

		if (set_fifo_l)
			wr32(hw, N20_ETH_PORT_TX_PROGFULL(0), tx_fifo_thresh[0]);

		cfg_adap = rd32(hw, N20_ETH_CFG_ADAPTER_CTRL0);
		MODIFY_BITFIELD(cfg_adap, dflt_tx_cdc_fifo_thresh, 9, F_TX_CDC);
		wr32(hw, N20_ETH_CFG_ADAPTER_CTRL0, cfg_adap);
		break;
	case MCE_FC_FULL:
		val |= F_RX_PAUSE_EN;
		val |= F_TX_PAUSE_EN;

		val_mac |= F_M_PAUSE_EN | F_M_PAUSE_STOP_EN;
		for (i = 0; i < N20_FIFO_PROG_CNT; i++) {
			wr32(hw, N20_ETH_PORT_TX_PROGFULL(i),
			     tx_fifo_thresh[i]);
			wr32(hw, N20_ETH_PORT_RX_PROGFULL(i),
			     rx_fifo_thresh[i]);
		}

		cfg_adap = rd32(hw, N20_ETH_CFG_ADAPTER_CTRL0);
		MODIFY_BITFIELD(cfg_adap, paus_tx_cdc_fifo_thresh, 9, F_TX_CDC);
		wr32(hw, N20_ETH_CFG_ADAPTER_CTRL0, cfg_adap);
		break;
	case MCE_FC_NONE:
		val &= ~F_RX_PAUSE_EN;
		val &= ~F_TX_PAUSE_EN;

		for (i = 0; i < N20_FIFO_PROG_CNT; i++) {
			wr32(hw, N20_ETH_PORT_TX_PROGFULL(i), dflt_thresh[i]);
			wr32(hw, N20_ETH_PORT_RX_PROGFULL(i), dflt_thresh[i]);
		}

		if (set_fifo_l)
			wr32(hw, N20_ETH_PORT_TX_PROGFULL(0), tx_fifo_thresh[0]);
		cfg_adap = rd32(hw, N20_ETH_CFG_ADAPTER_CTRL0);
		MODIFY_BITFIELD(cfg_adap, dflt_tx_cdc_fifo_thresh, 9, F_TX_CDC);
		wr32(hw, N20_ETH_CFG_ADAPTER_CTRL0, cfg_adap);
		break;
	default:
		break;
	}

	wr32(hw, N20_ETH_PAUSE_CTRL, val);
	wr32(hw, N20_M_CFG, val_mac);
	wr32(hw, N20_M_PAUSE_TIMER, 0xffff);

	/* Start transmitting and receiving packets. */
	n20_disable_proc(hw);

	fc->current_mode = fc->req_mode;
}

static void n20_set_pause_en_only(struct mce_hw *hw)
{
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_flow_control *fc = &pf->fc;
	u32 val_mac = 0;
	u32 val = 0;

	val = rd32(hw, N20_ETH_PAUSE_CTRL);
	val_mac = rd32(hw, N20_M_CFG);

	val_mac &= ~(F_M_PAUSE_EN | F_M_PAUSE_STOP_EN);

	switch (fc->req_mode) {
	case MCE_FC_TX_PAUSE:
		val |= F_TX_PAUSE_EN;
		val &= ~F_RX_PAUSE_EN;
		val_mac |= F_M_PAUSE_EN;

		break;
	case MCE_FC_RX_PAUSE:
		val |= F_RX_PAUSE_EN;
		val &= ~F_TX_PAUSE_EN;
		val_mac |= F_M_PAUSE_EN | F_M_PAUSE_STOP_EN;

		break;
	case MCE_FC_FULL:
		val |= F_RX_PAUSE_EN;
		val |= F_TX_PAUSE_EN;
		val_mac |= F_M_PAUSE_EN | F_M_PAUSE_STOP_EN;

		break;
	case MCE_FC_NONE:
		val &= ~F_RX_PAUSE_EN;
		val &= ~F_TX_PAUSE_EN;

		break;
	default:
		break;
	}

	/* set pause will close pf? */
	wr32(hw, N20_ETH_PAUSE_CTRL, val);
	wr32(hw, N20_M_CFG, val_mac);

	fc->current_mode = fc->req_mode;
}

static int n20_set_lldp_tx_en(struct mce_hw *hw, bool enable)
{
	int v = 0x01270000 | (hw->nr_pf << 8);

	if (enable)
		v |= 1;
	return mce_mbx_set_dump(hw, v);
}

static void n20_set_ddp_extra_en(struct mce_hw *hw, bool enable)
{
	u32 val;

	val = rd32(hw, N20_ETH_PARSER_CTRL);
	if (enable)
		val &= (~F_DDP_EXTRA_EN);
	else
		val |= F_DDP_EXTRA_EN;

	wr32(hw, N20_ETH_PARSER_CTRL, val);
}

static void n20_set_evb_mode(struct mce_hw *hw, int mode)
{
	struct mce_pf *pf = hw->back;
	u32 val;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return;

	val = rd32(hw, N20_ETH_L2_CTRL0);
	if (mode == BRIDGE_MODE_VEPA)
		val |= F_VEPA_SW_EN;
	else
		val &= ~F_VEPA_SW_EN;
	wr32(hw, N20_ETH_L2_CTRL0, val);
	if (mode == BRIDGE_MODE_VEPA)
		hw->vf.ops->set_vf_emac_post_ctrl(hw, 0, false, MCE_VF_POST_CTRL_NORMAL, true);
	else
		hw->vf.ops->set_vf_emac_post_ctrl(hw, 0, false,
							MCE_VF_POST_CTRL_FILTER_TX_TO_RX, true);
}

static void n20_set_dma_tso_cnts_en(struct mce_hw *hw, bool en)
{
	u32 val;

	val = rd32(hw, N20_DMA_CONFIG);
	val = en ? val | F_DMA_TSO_CNTS_EN : val & ~F_DMA_TSO_CNTS_EN;
	wr32(hw, N20_DMA_CONFIG, val);
}

static void n20_set_fd_fltr_guar(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);

	hw->func_caps.fd_fltr_guar = N20_LOC_FDIR_CNT;
}

static void n20_set_irq_legacy_en(struct mce_hw *hw, bool en, u32 tick_timer)
{
	u32 reg_val = 0;

	if (en) {
		F_NIC_MSI_CONFIG_MSIX_TICK_TIMER(reg_val, tick_timer);
		reg_val |= F_NIC_MSI_CONFIG_LEGACY_EN;
	}
	wr32(hw, N20_NIC_MSI_CONFIG, reg_val);
}

static bool n20_get_misc_irq_evt(struct mce_hw *hw, enum mce_misc_irq_type type)
{
	u32 s_val, c_val = 0;
	bool ret = false;

	s_val = rd32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_ST));
	switch (type) {
	case MCE_MAC_MISC_IRQ_PCS_LINK:
		ret = !!(s_val & BIT(0));
		if (ret)
			c_val = BIT(0);
		break;
	case MCE_MAC_MISC_IRQ_PTP:
		ret = !!(s_val & BIT(4));
		if (ret)
			c_val = BIT(4);
		break;
	case MCE_MAC_MISC_IRQ_FLR:
		ret = !!(s_val & BIT(8));
		if (ret)
			c_val = BIT(8);
		break;
	default:
		ret = false;
		break;
	}
	/* clear misc link event */
	if (ret) {
		wr32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_CLR), c_val);
		/* Read back to flush the clear write. */
		(void)rd32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_CLR));
		wr32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_CLR), 0);
		(void)rd32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_CLR));
	}

	return !!ret;
}

static int n20_set_misc_irq(struct mce_hw *hw, bool en, int nr_vec)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 irq_en_val = 0;
	u32 val = 0;

	nr_vec = en ? nr_vec : 0;

	if (pf->mac_misc_irq & BIT(MCE_MAC_MISC_IRQ_PCS_LINK)) {
		val = rd32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_VEC(0)));
		MODIFY_BITFIELD(val, nr_vec, 11, 0);
		wr32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_VEC(0)), val);
		hw->ops->set_misc_irq_mask(hw, MCE_MAC_MISC_IRQ_PCS_LINK, !en);

		irq_en_val |= BIT(16 + 0);
	}

	if (pf->mac_misc_irq & BIT(MCE_MAC_MISC_IRQ_PTP)) {
		val = rd32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_VEC(2)));
		MODIFY_BITFIELD(val, nr_vec, 11, 0);
		wr32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_VEC(2)), val);
		hw->ops->set_misc_irq_mask(hw, MCE_MAC_MISC_IRQ_PTP, !en);
		irq_en_val |= BIT(16 + 4);
	}

	if (pf->mac_misc_irq & BIT(MCE_MAC_MISC_IRQ_FLR)) {
		val = rd32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_VEC(4)));
		MODIFY_BITFIELD(val, nr_vec, 11, 0);
		wr32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_VEC(4)), val);
		hw->ops->set_misc_irq_mask(hw, MCE_MAC_MISC_IRQ_FLR, !en);
		irq_en_val |= BIT(16 + 8);
	}

	if (!en)
		irq_en_val = 0;

	md32(hw, N20_NIC_INTR_EN_REG, GENMASK(31, 16), irq_en_val);

/* T = 1s / system f * tick_timer */
#define N20_MISC_IRQ_RETRY_TIMES 0x1212d0 /* 50ms */
	val = pf->mac_misc_irq_retry && en ?
		      N20_MISC_IRQ_RETRY_TIMES | BIT(31) :
		      0;
	wr32(hw, N20_NIC_MSIX_CONFIG, val);
	return 0;
}

static int n20_get_misc_irq_st(struct mce_hw *hw, enum mce_misc_irq_type type,
			       u32 *val)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 t_val = 0;
	int ret = 0;

	if (!(pf->mac_misc_irq & BIT(type)))
		return -EINVAL;

	switch (type) {
	case MCE_MAC_MISC_IRQ_PCS_LINK:
		*val = rd32(hw, N20_MAC_INT_STAT(0));
		break;
	case MCE_MAC_MISC_IRQ_PTP:
		*val = rd32(hw, N20_MAC_INT_STAT(4));
		break;
	case MCE_MAC_MISC_IRQ_FLR:
		if (*val == MCE_MISC_IRQ_FLR_0_31)
			t_val = rd32(hw, N20_NIC_DMA_FLR_STATUS(0));
		if (*val == MCE_MISC_IRQ_FLR_32_63)
			t_val = rd32(hw, N20_NIC_DMA_FLR_STATUS(1));
		if (*val == MCE_MISC_IRQ_FLR_64_95)
			t_val = rd32(hw, N20_NIC_DMA_FLR_STATUS(2));
		if (*val == MCE_MISC_IRQ_FLR_96_127)
			t_val = rd32(hw, N20_NIC_DMA_FLR_STATUS(3));
		*val = t_val;
		break;
	default:
		*val = 0;
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int n20_set_misc_irq_mask(struct mce_hw *hw, enum mce_misc_irq_type type,
				 bool en)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 val = 0;
	int ret = 0;

	if (!(pf->mac_misc_irq & BIT(type)) && type != MCE_MAC_MISC_IRQ_ALL)
		return -EINVAL;

	val = en ? 0xffffffff : 0x0;
	switch (type) {
	case MCE_MAC_MISC_IRQ_PCS_LINK:
		wr32(hw, N20_MAC_INT_MASK(0), val);
		break;
	case MCE_MAC_MISC_IRQ_PTP:
		wr32(hw, N20_MAC_INT_MASK(4), val);
		break;
	case MCE_MAC_MISC_IRQ_FLR:
		wr32(hw, N20_MAC_INT_MASK(4), val);
		wr32(hw, N20_NIC_DMA_FLR_MASK(0), val);
		wr32(hw, N20_NIC_DMA_FLR_MASK(1), val);
		wr32(hw, N20_NIC_DMA_FLR_MASK(2), val);
		wr32(hw, N20_NIC_DMA_FLR_MASK(3), val);
		break;
	case MCE_MAC_MISC_IRQ_ALL:
		/* mac interrupt */
		wr32(hw, N20_MAC_INT_MASK(0), val);
		wr32(hw, N20_MAC_INT_MASK(1), val);
		wr32(hw, N20_MAC_INT_MASK(2), val);
		wr32(hw, N20_MAC_INT_MASK(3), val);
		wr32(hw, N20_MAC_INT_MASK(4), val);
		wr32(hw, N20_MAC_INT_MASK(5), val);
		wr32(hw, N20_MAC_INT_MASK(6), val);
		/* nic dma flr interrupt */
		wr32(hw, N20_NIC_DMA_FLR_MASK(0), val);
		wr32(hw, N20_NIC_DMA_FLR_MASK(1), val);
		wr32(hw, N20_NIC_DMA_FLR_MASK(2), val);
		wr32(hw, N20_NIC_DMA_FLR_MASK(3), val);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int n20_clear_misc_irq_evt(struct mce_hw *hw,
				  enum mce_misc_irq_type type, int idx, u32 val)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	int ret = 0;
	u32 reg;

	if (!(pf->mac_misc_irq & BIT(type)) && type != MCE_MAC_MISC_IRQ_ALL)
		return -EINVAL;

	if (type == MCE_MAC_MISC_IRQ_ALL)
		val = MCE_MISC_IRQ_CLEAR_ALL;

	switch (type) {
	case MCE_MAC_MISC_IRQ_PCS_LINK:
		wr32(hw, N20_MAC_INT_CLR(0), val);
		break;
	case MCE_MAC_MISC_IRQ_PTP:
		wr32(hw, N20_MAC_INT_CLR(4), val);
		break;
	case MCE_MAC_MISC_IRQ_FLR:
		reg = rd32(hw, N20_NIC_DMA_FLR_CLR(idx));
		reg |= val;
		wr32(hw, N20_NIC_DMA_FLR_CLR(idx), reg);
		reg &= ~val;
		wr32(hw, N20_NIC_DMA_FLR_CLR(idx), reg);
		break;
	case MCE_MAC_MISC_IRQ_ALL:
		/* mac interrupt clear */
		wr32(hw, N20_MAC_INT_CLR(0), val);
		wr32(hw, N20_MAC_INT_CLR(1), val);
		wr32(hw, N20_MAC_INT_CLR(2), val);
		wr32(hw, N20_MAC_INT_CLR(3), val);
		wr32(hw, N20_MAC_INT_CLR(4), val);
		wr32(hw, N20_MAC_INT_CLR(5), val);
		wr32(hw, N20_MAC_INT_CLR(6), val);
		/* nic dma flr interrupt */
		wr32(hw, N20_NIC_DMA_FLR_CLR(0), val);
		wr32(hw, N20_NIC_DMA_FLR_CLR(1), val);
		wr32(hw, N20_NIC_DMA_FLR_CLR(2), val);
		wr32(hw, N20_NIC_DMA_FLR_CLR(3), val);
		wr32(hw, N20_NIC_DMA_FLR_CLR(0), 0);
		wr32(hw, N20_NIC_DMA_FLR_CLR(1), 0);
		wr32(hw, N20_NIC_DMA_FLR_CLR(2), 0);
		wr32(hw, N20_NIC_DMA_FLR_CLR(3), 0);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

/* Initialize PTP hardware when PTP misc IRQ support is present. */
static int n20_set_init_ptp(struct mce_hw *hw)
{
	/* reset ptp */
	wr32(hw, N20_CE_REG_BASE + 0x683c, 0x43);
	wr32(hw, N20_CE_REG_BASE + 0x683c, 0x40);
	/* parse ptp */
	wr32(hw, N20_CE_REG_BASE + 0x4000, 0xc418444);
	wr32(hw, N20_CE_REG_BASE + 0x4390, 0x6c0000);
	wr32(hw, N20_CE_REG_BASE + 0x4060, 0x107);
	wr32(hw, N20_CE_REG_BASE + 0x430C, 0x0);
	wr32(hw, N20_CE_REG_BASE + 0x4300, 0x1);
	wr32(hw, N20_CE_REG_BASE + 0x4304, 0x500);
	wr32(hw, N20_CE_REG_BASE + 0x430C, 0x1);
	return 0;
}

static void n20_update_rdma_status(struct mce_hw *hw, bool en)
{
	u32 val = rd32(hw, N20_ETH_L2_CTRL0);

	if (en)
		val |= BIT(8);
	else
		val &= ~BIT(8);

	wr32(hw, N20_ETH_L2_CTRL0, val);
}

static int n20_set_txring_trig_intr(struct mce_ring *tx_ring)
{
	ring_wr32(tx_ring, N20_DMA_REG_INT_TRIG, _F_N20_DMA_INT_CLR_TRIG_TX);
	ring_wr32(tx_ring, N20_DMA_REG_INT_TRIG, _F_N20_DMA_INT_SET_TRIG_TX);
	return 0;
}

static u64 n20_get_hw_ring_stats(struct mce_ring *ring,
				 enum mce_hw_ring_stats_type type)
{
	u64 val_hi = 0, val_lo = 0;

	if (!ring || !ring->ring_addr)
		return 0;

	switch (type) {
	case MCE_HW_R_STATS_RX_BYTES:
		val_lo = ring_rd32(ring, N20_DMA_REG_RX_BYTES_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_RX_BYTES_HI);
		break;
	case MCE_HW_R_STATS_RX_UNICAST:
		val_lo = ring_rd32(ring, N20_DMA_REG_RX_UNICAST_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_RX_UNICAST_HI);
		break;
	case MCE_HW_R_STATS_RX_MULTICAST:
		val_lo = ring_rd32(ring, N20_DMA_REG_RX_MULTICAST_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_RX_MULTICAST_HI);
		break;
	case MCE_HW_R_STATS_RX_BROADCAST:
		val_lo = ring_rd32(ring, N20_DMA_REG_RX_BROADCAST_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_RX_BROADCAST_HI);
		break;
	case MCE_HW_R_STATS_RX_MISS_DROP:
		val_lo = ring_rd32(ring, N20_DMA_REG_RX_MISS_DROP);
		val_hi = 0;
		break;
	case MCE_HW_R_STATS_TX_BYTES:
		val_lo = ring_rd32(ring, N20_DMA_REG_TX_BYTES_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_TX_BYTES_HI);
		break;
	case MCE_HW_R_STATS_TX_UNICAST:
		val_lo = ring_rd32(ring, N20_DMA_REG_TX_UNICAST_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_TX_UNICAST_HI);
		break;
	case MCE_HW_R_STATS_TX_MULTICAST:
		val_lo = ring_rd32(ring, N20_DMA_REG_TX_MULTICAST_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_TX_MULTICAST_HI);
		break;
	case MCE_HW_R_STATS_TX_BROADCAST:
		val_lo = ring_rd32(ring, N20_DMA_REG_TX_BROADCAST_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_TX_BROADCAST_HI);
		break;
	default:
		break;
	}

	return (val_lo + (val_hi << 32));
}

static int n20_clear_hw_ring_stats(struct mce_hw *hw)
{
	int i = 0, q_id;

	for (i = 0; i < hw->ring_max_cnt; i++) {
		q_id = hw->ring_base_addr + i;
		/* turn on read clean switch */
		wr32(hw, N20_DMA_REG_READ_CLEAD + q_id * 0x100, 1);
		/* Read all counters to clear the read-to-clear registers. */
		(void)rd32(hw, N20_DMA_REG_RX_MISS_DROP + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_RX_BYTES_LO + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_RX_BYTES_HI + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_RX_UNICAST_LO + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_RX_UNICAST_HI + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_RX_MULTICAST_LO + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_RX_MULTICAST_HI + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_RX_BROADCAST_LO + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_RX_BROADCAST_HI + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_TX_BYTES_LO + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_TX_BYTES_HI + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_TX_UNICAST_LO + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_TX_UNICAST_HI + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_TX_MULTICAST_LO + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_TX_MULTICAST_HI + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_TX_BROADCAST_LO + q_id * 0x100);
		(void)rd32(hw, N20_DMA_REG_TX_BROADCAST_HI + q_id * 0x100);
		/* turn off read clean switch */
		wr32(hw, N20_DMA_REG_READ_CLEAD + q_id * 0x100, 0);
	}

	return 0;
}

static void n20_update_pfc_rr_mode(struct mce_hw *hw, bool on)
{
	u32 val;

	val = rd32(hw, N20_ETH_EXCEPT_TX_PROC);
	if (on)
		MODIFY_BITFIELD(val, 1, 1, 9);
	else
		MODIFY_BITFIELD(val, 0, 1, 9);

	wr32(hw, N20_ETH_EXCEPT_TX_PROC, val);
}

static void n20_set_capture_rdma(struct mce_hw *hw, bool on)
{
	u32 port = 0, filter = 0, policy = 0;
	u32 val;

	if (on) {
		val = rd32(hw, N20_ETH_EMAC_POST_CTRL);
		val |= F_COPY_EN | F_VIRTUAL_INNER_EN;
		wr32(hw, N20_ETH_EMAC_POST_CTRL, val);

		/* todo maybe confict with eswitch */
		val = rd32(hw, N20_ETH_L2_CTRL1);
		val |= F_T10_MATCH_EN;
		wr32(hw, N20_ETH_L2_CTRL1, val);

		/* use t10 idx 0 */
		wr32(hw, N20_ETH_T10_VM_PORT(0), 0x12b7);
		wr32(hw, N20_ETH_T10_VM_TYPE(0), 0x20000000);
		wr32(hw, N20_ETH_VM_T4_ACT_PVF(0), 0x90);

		/* setup udp dport 4791 to ring 0 */
		F_T5_SET_L4_TYPE(filter, IPPROTO_UDP);
		filter &= ~F_T5_L4_TYPE_MASK;
		F_T5_SET_DPORT(port, 0x12b7);
		filter |= F_T5_SIP_MASK | F_T5_DIP_MASK;
		F_T5_SET_IP4_TYPE(filter);
		filter |= F_T5_SPORT_MASK;
		filter |= F_T5_FILTER_EN;

		policy &= ~F_ACL_ACTION_DROP;
		policy |= F_ACL_ACTION_RING_EN;
		F_ACL_ACTION_SET_RING_ID(policy, 0);
		/* use tuple5 idx 511 */
		wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_SIP(511)), 0);
		wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_DIP(511)), 0);
		wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_PORT(511)), port);
		wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_FILTER(511)), filter);
		wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_POLICY(511)), policy);
	} else {
		val = rd32(hw, N20_ETH_EMAC_POST_CTRL);
		val &= ~(F_COPY_EN | F_VIRTUAL_INNER_EN);
		wr32(hw, N20_ETH_EMAC_POST_CTRL, val);

		val = rd32(hw, N20_ETH_L2_CTRL1);
		val &= ~F_T10_MATCH_EN;
		wr32(hw, N20_ETH_L2_CTRL1, val);

		/* use t10 idx 0 */
		wr32(hw, N20_ETH_T10_VM_PORT(0), 0);
		wr32(hw, N20_ETH_T10_VM_TYPE(0), 0);
		wr32(hw, N20_ETH_VM_T4_ACT_PVF(0), 0x0);

		/* use tuple5 idx 511 */
		wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_SIP(511)), 0);
		wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_DIP(511)), 0);
		wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_PORT(511)), 0);
		wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_FILTER(511)), 0);
		wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_POLICY(511)), 0);
	}
}

static void mce_setup_mbx_info_vf(struct mce_hw *hw, int nr_vf,
				  struct mce_mbx_info *mbx)
{
	mbx->hw = hw;

	mutex_init(&mbx->req_lock);
	spin_lock_init(&mbx->req_shm_lock);
	spin_lock_init(&mbx->peer_shm_lock);

	mbx->irq_enabled = 0;
	mbx->is_vf_mbx = true;
	mbx->nr_vf = nr_vf;
	mbx->nr_pf = hw->pfvfnum.pf;
	snprintf(mbx->name, sizeof(mbx->name), "%s-mbx-pf%dvf%d",
		 pci_name(hw->pdev), mbx->nr_pf, mbx->nr_vf);

	mbx->req_shm_size = PF2VF_SHM_SIZE;
	mbx->peer_shm_size = VF2PF_SHM_SIZE;

	mbx->pf2peer_shm = hw->eth_bar_base + N20_MBX_BASE + PF2VF_SHM(nr_vf);
	mbx->pf2peer_shm_lock =
		hw->eth_bar_base + N20_MBX_BASE + PF2VF_SHM_LOCK(nr_vf);
	mbx->pf2peer_ctrl =
		hw->eth_bar_base + N20_MBX_BASE + PF2VF_REQ_CTRL(nr_vf);
	mbx->pf2peer_shm_lock_msk = BIT(3); /* CFU */

	mbx->peer2pf_shm = hw->eth_bar_base + N20_MBX_BASE + VF2PF_SHM(nr_vf);
	mbx->peer2pf_shm_lock =
		hw->eth_bar_base + N20_MBX_BASE + VF2PF_SHM_LOCK(nr_vf);
	mbx->peer2pf_ctrl =
		hw->eth_bar_base + N20_MBX_BASE + VF2PF_REQ_CTRL(nr_vf);
	mbx->peer2pf_shm_lock_msk = BIT(3); /* PFU */

	mbx->vf2pf_irq_stat = hw->eth_bar_base + N20_MBX_BASE + VF2PF_REQ_ST0;
	mbx->mbx_vec_base =
		hw->eth_bar_base + N20_MBX_BASE + VF2PF_MB_VEC(nr_vf);

	mbx->setup_done = true;
}

static void n20_mbx_init_vf(struct mce_hw *hw, struct mce_mbx_info *mbx,
			    int nr_vf)
{
	mce_setup_mbx_info_vf(hw, nr_vf, mbx);
	mce_mbx_init_configure(mbx);

	/* update pf2vf_mbx_ctrl[9] : nr_pf bit */
	mce_mbx_set_pf_stat_vf(mbx);
}

static struct mce_hw_operations n20_ops = {
	.mbx_init_vf = n20_mbx_init_vf,
	.update_fw_stat = n20_update_fw_stat,
	.update_pf_stat = n20_update_pf_stat,
	.reset_hw = n20_reset_hw,
	.init_hw = n20_init_hw,
	.enable_proc = n20_enable_proc,
	.disable_proc = n20_disable_proc,
	.enable_axi_tx = n20_enable_axi_tx,
	.disable_axi_tx = n20_disable_axi_tx,
	.enable_axi_rx = n20_enable_axi_rx,
	.disable_axi_rx = n20_disable_axi_rx,
	.cfg_vec2tqirq = n20_cfg_vec2tqirq,
	.cfg_vec2rqirq = n20_cfg_vec2rqirq,
	.set_max_pktlen = n20_set_max_pktlen,
	.get_hw_stats = n20_get_hw_stats,
	.get_mac_stats = n20_get_mac_stats,
	.clr_mac_stats = n20_clr_mac_stats,
	.set_fcs_mode = n20_set_fcs_mode,
	.set_err_mode = n20_set_err_mode,
	.dump_debug_regs = n20_dump_debug_regs,
	.update_fltr_macaddr = n20_update_fltr_macaddr,

	.set_rxring_ctx = n20_set_rxring_ctx,
	.set_txring_ctx = n20_set_txring_ctx,
	.enable_rxring_irq = n20_enable_rxring_irq,
	.enable_txring_irq = n20_enable_txring_irq,
	.disable_rxring_irq = n20_disable_rxring_irq,
	.disable_txring_irq = n20_disable_txring_irq,
	.enable_txrxring_irq = n20_enable_txrxring_irq,
	.disable_txrxring_irq = n20_disable_txrxring_irq,
	.start_rxring = n20_start_rxring,
	.start_txring = n20_start_txring,
	.stop_rxring = n20_stop_rxring,
	.stop_txring = n20_stop_txring,
	.set_rxring_intr_coal = n20_set_rxring_intr_coal,
	.set_txring_intr_coal = n20_set_txring_intr_coal,
	.set_txring_hw_dim = n20_set_txring_hw_dim,
	.set_rxring_hw_dim = n20_set_rxring_hw_dim,
	.cfg_txring_bw_lmt = n20_cfg_txring_bw_lmt,

	.set_rss_hash = n20_set_rss_hash,
	.set_rss_key = n20_set_rss_key,
	.set_rss_table = n20_set_rss_table,
	.set_rss_hash_type = n20_set_rss_hash_type,

	.set_rx_csum_chk_err_mask = n20_set_rx_csum_chk_err_mask,
	.set_vlan_strip = n20_set_vlan_strip,

	.set_ucmc_hash_type_fltr = n20_set_ucmc_hash_type_fltr,
	.set_uc_filter = n20_set_uc_filter,
	.add_uc_filter = n20_add_uc_filter,
	.del_uc_filter = n20_del_uc_filter,
	.set_mc_filter = n20_set_mc_filter,
	.add_mc_filter = n20_add_mc_filter,
	.del_mc_filter = n20_del_mc_filter,
	.clr_mc_filter = n20_clr_mc_filter,

	.set_mc_promisc = n20_set_mc_promisc,
	.set_rx_promisc = n20_set_rx_promisc,

	.set_vlan_filter = n20_set_vlan_filter,
	.add_vlan_filter = n20_add_vlan_filter,
	.del_vlan_filter = n20_del_vlan_filter,

	.add_ntuple_filter = n20_add_filter,
	.del_ntuple_filter = n20_del_filter,

	.add_udp_tnl = n20_add_udp_tnl,
	.del_udp_tnl = n20_del_udp_tnl,
	.restore_udp_tnl = n20_restore_udp_tnl,

	.set_pause = n20_set_pause,
	.set_pause_en_only = n20_set_pause_en_only,

	.enable_tc = n20_enable_tc,
	.disable_tc = n20_disable_tc,
	.enable_rdma_tc = n20_enable_rdma_tc,
	.disable_rdma_tc = n20_disable_rdma_tc,
	.set_tc_bw = n20_set_tc_bw,
	.set_tc_bw_rdma = n20_set_tc_bw_rdma,
	.set_qg_ctrl = n20_set_qg_ctrl,
	.set_qg_rate = n20_set_qg_rate,
	.set_q_to_tc = n20_set_q_to_tc,
	.clr_q_to_tc = n20_clr_q_to_tc,
	.enable_pfc = n20_enable_pfc,
	.disable_pfc = n20_disable_pfc,
	.setup_rx_buffer = n20_setup_rx_buffer,
	.set_q_to_pfc = n20_set_q_to_pfc,
	.clr_q_to_pfc = n20_clr_q_to_pfc,
	.set_mac_station_addr = n20_set_mac_station_addr,
	.set_dscp = n20_set_dscp,
	.set_tun_select_inner = n20_set_tun_select_inner,
	.set_ddp_extra_en = n20_set_ddp_extra_en,
	.set_lldp_tx_en = n20_set_lldp_tx_en,
	.set_evb_mode = n20_set_evb_mode,
	.set_dma_tso_cnts_en = n20_set_dma_tso_cnts_en,
	.set_fd_fltr_guar = n20_set_fd_fltr_guar,

	.set_irq_legacy_en = n20_set_irq_legacy_en,
	.get_misc_irq_evt = n20_get_misc_irq_evt,
	.set_misc_irq = n20_set_misc_irq,
	.get_misc_irq_st = n20_get_misc_irq_st,
	.set_misc_irq_mask = n20_set_misc_irq_mask,
	.clear_misc_irq_evt = n20_clear_misc_irq_evt,
	.set_init_ptp = n20_set_init_ptp,
	/* npu callback */
	.npu_download_firmware = n20_npu_download_firmware,
	.update_rdma_status = n20_update_rdma_status,

	/* PTP control */
#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
	.ptp_get_systime = n20_get_systime,
	.ptp_init_counter = n20_ptp_init_counter,
	.ptp_init_systime = n20_init_systime,
	.ptp_adjust_systime = n20_adjust_systime,
	.ptp_adjfine = n20_adjfine,
	.ptp_set_ts_config = n20_ptp_set_ts_config,
	.ptp_tx_state = n20_ptp_tx_status,
	.ptp_tx_stamp = n20_ptp_tx_stamp,
#endif
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	/* Flow Director flow-engine callbacks. */
	.fd_update_entry_table = n20_fd_update_entry_table,
	.fd_query_entry_table = n20_fd_query_entry_table,
	.fd_update_hash_table = n20_fd_update_hash_table,
	.fd_query_hash_table = n20_fd_query_hash_table,
	.fd_update_ex_hash_table = n20_fd_update_ex_hash_table,
	.fd_query_ex_hash_table = n20_fd_query_ex_hash_table,
	.fd_verificate_sign_rule = n20_fd_verificate_sign_rule,
	.fd_clear_sign_rule = n20_fd_clear_sign_rule,
	.fd_field_bitmask_setup = n20_fd_field_bitmask_setup,
	.fd_profile_field_bitmask_update = n20_fd_profile_field_bitmask_update,
	.fd_profile_update = n20_fd_profile_update,
	.fd_init_hw = n20_fd_init_hw,
	.fd_deinit_hw = n20_fd_deinit_hw,
	.fd_clear_hw = n20_fd_clear_hw,
#endif
	.set_txring_trig_intr = n20_set_txring_trig_intr,
	.get_hw_ring_stats = n20_get_hw_ring_stats,
	.clear_hw_ring_stats = n20_clear_hw_ring_stats,
	.update_pfc_rr_mode = n20_update_pfc_rr_mode,
	.set_capture_rdma = n20_set_capture_rdma,
};

static void n20_set_vf_init_config(struct mce_hw *hw, bool en)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	u32 val = 0;

	if (en) {
		hw->eswitch.ops->eswitch_en(hw, true);
		val = rd32(hw, N20_ETH_L2_CTRL0);
		val |= N20_ETH_L2_CTRL0_DEFAULT_CFG;
		wr32(hw, N20_ETH_L2_CTRL0, val);

		/* turn on true promisc switch for vf*/
		val = rd32(hw, N20_ETH_FWD_CTRL);
		val |= F_PROMISC_VPORT_UPLINK_EN | F_PROMISC_VPORT_VEB_EN;
		wr32(hw, N20_ETH_FWD_CTRL, val);

		/* set pf action and bitmap, pf take as vf0 */
		if (pf->switchdev.is_running)
			memset(vf->t_info.macaddr, 0x0, ETH_ALEN);
		else
			ether_addr_copy(vf->t_info.macaddr,
					vsi->port_info->addr);
		vf->t_info.bcmc_bitmap = MCE_F_HOLD;
		mce_vf_set_veb_misc_rule(hw, PFINFO_IDX,
					 VEB_POLICY_TYPE_UC_ADD_MACADDR_WITH_ACT);

		/* config default bc/mc mac or vlan, mc take as bc */
		vf->t_info.bcmc_bitmap = MCE_F_HOLD;
		mce_vf_set_veb_misc_rule(hw, PFINFO_BCMC,
					 VEB_POLICY_TYPE_BCMC_ADD_MACADDR_WITH_ACT);
	} else {
		hw->eswitch.ops->eswitch_en(hw, false);
		/* turn off true promisc switch for vf*/
		val = rd32(hw, N20_ETH_FWD_CTRL);
		val &= ~(F_PROMISC_VPORT_UPLINK_EN | F_PROMISC_VPORT_VEB_EN);
		wr32(hw, N20_ETH_FWD_CTRL, val);

		val = rd32(hw, N20_ETH_L2_CTRL0);
		val &= ~N20_ETH_L2_CTRL0_DEFAULT_CFG;
		wr32(hw, N20_ETH_L2_CTRL0, val);
		vf->t_info.bcmc_bitmap = MCE_F_HOLD;
		mce_vf_set_veb_misc_rule(hw, PFINFO_BCMC,
					 VEB_POLICY_TYPE_BCMC_ADD_MACADDR_WITH_ACT);
	}
}

static void n20_init_vf_params(struct mce_hw *hw, int max_ring)
{
	hw->vf_max_ring = max_ring;
	hw->vf_min_ring_cnt = N20_VF_DEFAULT_QUEUE_CNT;
	hw->vf_max_ring_cnt = N20_VF_MAX_QUEUE_CNT;
	hw->func_caps.common_cap.vf_num_txq = max_ring;
	hw->func_caps.common_cap.vf_num_rxq = max_ring;
	hw->func_caps.common_cap.max_vfs = N20_MAX_Q_CNT / max_ring - 1;
	hw->vf_uc_addr_offset = N20_VEB_VF_ADDR_ENTRY_OFF;
	hw->vf_macvlan_addr_offset = N20_VEB_MACVLAN_ADDR_ENTRY_OFF;
	hw->vf_bcmc_addr_offset = N20_VEB_BCMC_ADDR_ENTRY_OFF;
	/* 1 pf + 0 uplink(pf take as uplink ) + vfs */
	hw->func_caps.guar_num_vsi = 1 + 0 + MCE_MAX_VF_NUM;
#if IS_ENABLED(CONFIG_PCI_IOV)
	hw->func_caps.common_cap.sr_iov = 1;
#endif
}

static void n20_init_vf_pcie_totalvfs(struct mce_hw *hw, int max_ring)
{
	/* set pcie max vfs drv limit */
}

static void n20_set_vf_virtual_config(struct mce_hw *hw, bool en)
{
	u32 val;

	val = rd32(hw, N20_NIC_CONFIG);
	en ? SET_BIT(F_VIRTUAAL_SW_OFFSET, val) :
	     CLR_BIT(F_VIRTUAAL_SW_OFFSET, val);
	wr32(hw, N20_NIC_CONFIG, val);

	/* active vf */
	val = rd32(hw, N20_DMA_CONFIG);
	en ? SET_BIT(F_VF_ACTIVE_OFFSET, val) :
	     CLR_BIT(F_VF_ACTIVE_OFFSET, val);
	en ? MODIFY_BITFIELD(val, _vfnum(hw, PFINFO_IDX), 9, 16) :
	     MODIFY_BITFIELD(val, 0, 9, 16);
	wr32(hw, N20_DMA_CONFIG, val);
	n20_set_vf_init_config(hw, en);
}

/* data path reg will be cleared after nic-reset, manager patch reg will not */
static void n20_unset_vf_virtual_config(struct mce_hw *hw)
{
	u8 mac_addr[ETH_ALEN];
	u32 i, val, idx;

	memset(mac_addr, 0x00, ETH_ALEN);
	/* not clear pf setup */
	for (i = N20_VEB_PF_ADDR_ENTRY_OFF; i <= N20_VEB_BCMC_ADDR_ENTRY_OFF;
	     i++) {
		/* clear l2 dmac */
		hw->ops->update_fltr_macaddr(hw, mac_addr, i, false);
		wr32(hw, N20_ETH_VM_DMAC_RAL(i), 0);
		wr32(hw, N20_ETH_VM_DMAC_RAH(i), 0);
		wr32(hw, N20_ETH_VM_IPORT_PVF(i), 0);
		wr32(hw, N20_ETH_VEB_VLAN_PVF(i), 0);
		val = rd32(hw, N20_ETH_VEB_ACT_PVF(i));
		F_SET_VM_MATCH_INDEX(val, 0);
		wr32(hw, N20_ETH_VEB_ACT_PVF(i), 0);
		/* clear bitmap */
		idx = n20_get_evb_vf_uc_index(hw, i);
		wr32(hw, N20_ETH_VPORT_BITMAP_MEM0(idx), 0);
		wr32(hw, N20_ETH_VPORT_BITMAP_MEM1(idx), 0);
		wr32(hw, N20_ETH_VPORT_BITMAP_MEM2(idx), 0);
		wr32(hw, N20_ETH_VPORT_BITMAP_MEM3(idx), 0);
	}
	/* clear vf attr table except pf*/
	for (i = 0; i < N20_VF_CNT; i++)
		wr32(hw, N20_ETH_VPORT_ATTR_TABLE(_vfnum(hw, i)), 0);
	hw->vf.ops->set_vf_clear_all_rss_table(hw);
}

static int __vf_max_queue_unzip(int v_3bit)
{
	int real_v[] = {
		[0] = 4, [1] = 8, [2] = 16, [3] = 32, [4] = 64,
	};
	if (v_3bit >= ARRAY_SIZE(real_v))
		return 4;
	return real_v[v_3bit];
}

/* @ret: 0 pf0/pf1 all VF isolated.
 * [0]: 1:pf0 VF isolate-disabled
 * [1]: 1:pf1 VF isolate-disabled
 */
static int n20_get_vf_max_supported_queue(struct mce_hw *hw,
					  int *pf0_max_vf_queues,
					  int *pf1_max_vf_queues)
{
	int ret = 0;

	if (!pf0_max_vf_queues || !pf1_max_vf_queues)
		return -EINVAL;

	n20_update_fw_stat(hw);

	if (hw->fw_stat.stat1.pf0_vf_isolate)
		ret |= BIT(0);
	if (hw->fw_stat.stat1.pf1_vf_isolate)
		ret |= BIT(1);

	*pf0_max_vf_queues = __vf_max_queue_unzip(hw->fw_stat.stat1.pf0_vf_max_queue_cnt_3bit);
	*pf1_max_vf_queues = __vf_max_queue_unzip(hw->fw_stat.stat1.pf0_vf_max_queue_cnt_3bit);
	return ret;
}

static void n20_set_vf_dma_max_queue_size(struct mce_hw *hw,
					  int vf_max_queue_num)
{
	unsigned int order;
	u32 val;

	if (vf_max_queue_num < 4)
		vf_max_queue_num = 4;

	if (vf_max_queue_num > hw->vf_max_ring_cnt) {
		dev_err(hw->dev,
			"%s: invalid input: vf_max_queue_num:%d > %d\n",
			__func__, vf_max_queue_num, hw->vf_max_ring_cnt);
		return;
	}

	vf_max_queue_num = roundup_pow_of_two(vf_max_queue_num);

	order = order_base_2(vf_max_queue_num);

	/* N20_DMA_CONFIG[9:11] 0: 1ring/vf 1:2ring/vf 2:4ring/vf ...pow_of_2(order)ring/vf */
	val = rd32(hw, N20_DMA_CONFIG);
	MODIFY_BITFIELD(val, order, 3, 9);
	wr32(hw, N20_DMA_CONFIG, val);

	/* N20_ETH_RQA_CTRL[16:18] 0: 4ring/vf 1:8ring/vf 2:16ring/vf ... */
	val = rd32(hw, N20_ETH_RQA_CTRL);
	MODIFY_BITFIELD(val, order - 2, 3, 16);
	wr32(hw, N20_ETH_RQA_CTRL, val);
}

static void n20_set_vf_emac_post_ctrl(struct mce_hw *hw,
				      enum mce_vf_veb_vlan_type vlan_type,
				      bool vlan_on,
				      enum mce_vf_post_ctrl post_ctrl,
				      bool ctrl_on)
{
	u32 val = 0;

	val = rd32(hw, N20_ETH_EMAC_POST_CTRL);
	if (vlan_on)
		MODIFY_BITFIELD(val, vlan_type, 2, 2);

	if (ctrl_on)
		MODIFY_BITFIELD(val, post_ctrl, 2, 0);
	wr32(hw, N20_ETH_EMAC_POST_CTRL, val);
}

static void n20_setup_mbx_info_fw(struct mce_hw *hw, struct mce_mbx_info *mbx)
{
	mbx->hw = hw;

	mutex_init(&mbx->req_lock);
	spin_lock_init(&mbx->req_shm_lock);
	spin_lock_init(&mbx->peer_shm_lock);

	mbx->irq_enabled = 0;
	mbx->is_vf_mbx = false;
	mbx->nr_vf = 0;
	mbx->nr_pf = hw->pfvfnum.pf;

	mbx->req_shm_size = PF2FW_SHM_SZ;
	mbx->peer_shm_size = FW2PF_SHM_SZ;

	/* pf2fw */
	mbx->pf2peer_shm = hw->eth_bar_base + N20_MBX_BASE + PF2FW_SHM;
	mbx->pf2peer_ctrl = hw->eth_bar_base + N20_MBX_BASE + PF2FW_MBX_CTRL;
	mbx->pf2peer_shm_lock = mbx->pf2peer_ctrl;
	mbx->pf2peer_shm_lock_msk = BIT(3); /* PFU */

	/* fw2pf */
	mbx->peer2pf_shm = hw->eth_bar_base + N20_MBX_BASE + FW2PF_SHM;
	mbx->peer2pf_ctrl = hw->eth_bar_base + N20_MBX_BASE + FW2PF_MBX_CTRL;
	mbx->peer2pf_shm_lock = mbx->pf2peer_shm_lock;
	mbx->peer2pf_shm_lock_msk = BIT(3); /* PFU */

	mbx->vf2pf_irq_stat = hw->eth_bar_base + N20_MBX_BASE + VF2PF_REQ_ST0;

	mbx->mbx_vec_base = hw->eth_bar_base + N20_MBX_BASE + FW2PF_MB_VEC;

	mbx->setup_done = true;
}

static struct mce_vf_operations n20_vf_ops = {
	.init_vf_params = n20_init_vf_params,
	.init_vf_pcie_totalvfs = n20_init_vf_pcie_totalvfs,
	.set_vf_virtual_config = n20_set_vf_virtual_config,
	.unset_vf_virtual_config = n20_unset_vf_virtual_config,
	.set_vf_dma_max_queue_size = n20_set_vf_dma_max_queue_size,
	.set_vf_emac_post_ctrl = n20_set_vf_emac_post_ctrl,
	.set_vf_vlan_strip = n20_set_vf_vlan_strip,
	.set_vf_rss_table = n20_set_vf_rss_table,
	.set_vf_clear_all_rss_table = n20_clear_vf_all_rss_table,
	.set_vf_spoofchk_mac = n20_set_vf_spoofchk_mac,
	.set_vf_spoofchk_vlan = n20_set_vf_spoofchk_vlan,
	.set_vf_trusted = n20_set_vf_trusted,
	.set_vf_default_vport = n20_set_vf_default_vport,
	.set_vf_recv_ximit_by_self = n20_set_vf_recv_ximit_by_self,
	.set_vf_trust_vport_en = n20_set_vf_trust_vport_en,
	.set_vf_update_vm_macaddr = n20_set_vf_update_vm_macaddr,
	.set_vf_update_vm_default_vlan = n20_set_vf_update_vm_default_vlan,
	.set_vf_add_flr_vlan = n20_set_vf_add_flr_vlan,
	.set_vf_del_flr_vlan = n20_set_vf_del_flr_vlan,
	.set_vf_add_veb_vlan = n20_set_vf_add_veb_vlan,
	.set_vf_del_veb_vlan = n20_set_vf_del_veb_vlan,
	.set_vf_clear_all_flr_vlan = n20_set_vf_clear_all_flr_vlan,
	.set_vf_set_veb_act = n20_set_vf_set_veb_act,
	.set_vf_set_vlan_promisc = n20_set_vf_set_vlan_promisc,
	.set_vf_set_vtag_vport_en = n20_set_vf_set_vtag_vport_en,
	.set_vf_add_mc_fliter = n20_set_vf_add_mc_fliter,
	.set_vf_del_mc_filter = n20_set_vf_del_mc_filter,
	.set_vf_clear_mc_filter = n20_set_vf_clear_mc_filter,
	.set_vf_true_promisc = n20_set_vf_true_promisc,
	.set_vf_rqa_tcp_sync_en = n20_set_vf_rqa_tcp_sync_en,
	.set_vf_rqa_tcp_sync_remapping = n20_set_vf_rqa_tcp_sync_remapping,
	.set_vf_bw_limit_init = n20_set_vf_bw_limit_init,
	.set_vf_bw_limit_rate = n20_set_vf_bw_limit_rate,
	.set_vf_bw_qg_ctrl = n20_set_vf_bw_qg_ctrl,
	.set_vf_rebase_ring_base = n20_set_vf_rebase_ring_base,
	.set_vf_cfg_txring_bw_lmt = n20_vf_cfg_txring_bw_lmt,
	.get_vf_max_supported_queue = n20_get_vf_max_supported_queue,
};

static void n20_eswitch_en(struct mce_hw *hw, bool en)
{
	u32 val = rd32(hw, N20_ETH_L2_CTRL1);

	if (en) {
		val |= F_T4_T10_CONFIG_MASK | F_MC_CONVERT_TO_BC_EN;
		wr32(hw, N20_ETH_L2_CTRL1, val);
	} else {
		val &= ~(F_T4_T10_CONFIG_MASK | F_MC_CONVERT_TO_BC_EN);
		wr32(hw, N20_ETH_L2_CTRL1, val);
	}
}

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
static void n20_eswitch_update_legacy(struct mce_hw *hw,
				      struct mce_eswitch_filter *filter,
					      bool add)
{
	struct mce_eswitch_pattern *pattern = &filter->lkup_pattern;
	const u8 *mac = pattern->formatted.dst_mac;
	int loc = filter->rule_loc;
	u32 mac_lo, mac_hi;
	u32 rule_ctrl = 0;

	if (add) {
		if (filter->options & MCE_OPT_DMAC) {
			mac_lo = (mac[2] << 24) | (mac[3] << 16) |
				 mac[4] << 8 | mac[5];
			mac_hi = (mac[0] << 8) | mac[1];
			wr32(hw, N20_ETH_VM_DMAC_RAH(loc), mac_hi);
			wr32(hw, N20_ETH_VM_DMAC_RAL(loc), mac_lo);
			rule_ctrl |= F_MAC_FILTER_PVF_EN;

			mac_hi |= F_MAC_FLTR_EN;
			wr32(hw, N20_ETH_FLTR_DMAC_RAH(loc), mac_hi);
			wr32(hw, N20_ETH_FLTR_DMAC_RAL(loc), mac_lo);
		}

		if (pattern->formatted.svport_id == PFINFO_IDX) {
			/* peer packets do not need a source port setup */
		} else if (pattern->formatted.svport_id < MCE_MAX_VF_NUM) {
			rule_ctrl |= F_IPORT_FILTER_PVF_EN;
			rule_ctrl |= pattern->formatted.svport_id;
		}

		wr32(hw, N20_ETH_VM_IPORT_PVF(loc), rule_ctrl);

		if (filter->drop_en) {
			/* no redirect bitmap means that the packet is dropped */
			wr32(hw, N20_ETH_VEB_ACT_PVF(loc), loc << 8);
			return;
		}

		if (pattern->dvport_id == PFINFO_IDX) {
			/* downlink to uplink packets are sent to the NPU switch */
			wr32(hw, N20_ETH_VEB_ACT_PVF(loc), 0x20);
		} else {
			wr32(hw, N20_ETH_VEB_ACT_PVF(loc), loc << 8);
			if (pattern->dvport_id < MCE_MAX_VF_NUM) {
				int idx = _vfnum(hw, pattern->dvport_id);
				u32 v_bit = BIT(pattern->dvport_id % 32);

				wr32(hw, N20_ETH_VPORT_SET_BITMAP(idx, loc), v_bit);
			}
		}
	} else {
		int idx = _vfnum(hw, pattern->dvport_id);

		wr32(hw, N20_ETH_VM_DMAC_RAH(loc), 0);
		wr32(hw, N20_ETH_VM_DMAC_RAL(loc), 0);
		wr32(hw, N20_ETH_FLTR_DMAC_RAH(loc), 0);
		wr32(hw, N20_ETH_FLTR_DMAC_RAL(loc), 0);
		wr32(hw, N20_ETH_VM_IPORT_PVF(loc), 0);
		wr32(hw, N20_ETH_VEB_ACT_PVF(loc), 0);
		wr32(hw, N20_ETH_VPORT_SET_BITMAP(idx, loc), 0);
	}
}

static void n20_eswitch_update_switchdev(struct mce_hw *hw,
					 struct mce_eswitch_filter *filter,
						 bool add)
{
}

static void n20_eswitch_update_bcmc_redir(struct mce_hw *hw, int vfid,
					  bool add)
{
	u32 entry;
	u32 val;
	int idx;

	idx = _vfnum(hw, vfid);
	entry = hw->vf_bcmc_addr_offset;
	val = rd32(hw, N20_ETH_VPORT_SET_BITMAP(idx, entry));

	if (add)
		val |= BIT(idx % 32);
	else
		val &= ~BIT(idx % 32);

	wr32(hw, N20_ETH_VPORT_SET_BITMAP(idx, entry), val);
}
#endif

static struct mce_eswitch_operations n20_eswitch_ops = {
	.eswitch_en = n20_eswitch_en,
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	.eswitch_update_legacy = n20_eswitch_update_legacy,
	.eswitch_update_switchdev = n20_eswitch_update_switchdev,
	.eswitch_update_bcmc_redir = n20_eswitch_update_bcmc_redir,
#endif
};

#ifdef N20_RSS_DEBUG
static u8 rss_default_key[N20_RSS_HASH_KEY_SIZE] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25,
	0x3d, 0x43, 0xa3, 0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b,
	0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c, 0x6a,
	0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
#endif

static void n20_init_feature(struct mce_hw *hw)
{
	hw->func_caps.common_cap.mac_misc_irq_retry = true;
	hw->func_caps.common_cap.mac_misc_irq = BIT(MCE_MAC_MISC_IRQ_FLR);
	hw->func_caps.common_cap.xmit_check_intr_drop = false;
	hw->func_caps.common_cap.poll_check_intr_drop = false;

	hw->uc_mc_hash_ctl.type = MCE_UC_MC_HASH_TYPE_BIT_11_0_OR_47_36;
	hw->uc_mc_hash_ctl.uc_s_low = true;
	hw->uc_mc_hash_ctl.mc_s_low = true;

#ifdef N20_RSS_DEBUG
	memcpy(hw->rss_key, rss_default_key, sizeof(rss_default_key));
#else
	netdev_rss_key_fill(hw->rss_key, N20_RSS_HASH_KEY_SIZE);
#endif
	hw->rss_hash_type = N20_RSS_HASH_TYPE_CFG;
	hw->rss_hfunc = ETH_RSS_HASH_TOP;
	hw->func_caps.common_cap.drop_intr_timer_en = true;
}

static void n20_set_axi_mhz(struct mce_hw *hw, enum mce_axi_clk axi_mode)
{
	int axi_map[] = {
		[AXI_250_MHZ] = 250,
		[AXI_333_MHZ] = 333,
		[AXI_500_MHZ] = 500,
	};
	int force_axi;

	if (axi_mode >= AXI_500_MHZ || axi_mode == AXI_NO_FORCE)
		return;
	force_axi = axi_map[axi_mode];
	mce_mbx_axi_mhz_set(hw, force_axi);
}

int mce_get_n20_caps(struct mce_hw *hw)
{
	struct mce_pf *pf = (struct mce_pf *)hw->back;
	struct mce_mbx_info *mbx = &hw->fw_mbx;
	struct port_abilities ability = {};
	int ret = 0;

	hw->nic_version = rd32(hw, N20_NIC_VERSION);
	hw->dma_version = rd32(hw, N20_DMA_VERSION);
	if ((hw->nic_version & 0xfff00000) != 0x20200000 ||
	    (hw->dma_version & 0xfff00000) != 0x20200000) {
		dev_err(&hw->pdev->dev, "Failed to get hw version\n");
		return -EIO;
	}
	dev_info(hw->dev, "dma-version:0x%x nic-version:0x%x\n",
		 hw->dma_version, hw->nic_version);

	hw->ops = &n20_ops;
	hw->vf.ops = &n20_vf_ops;
	hw->eswitch.ops = &n20_eswitch_ops;

	hw->dm_stat = hw->eth_bar_base + 0x4000c;
	hw->nic_stat = hw->eth_bar_base + 0x7000c;
	hw->ext_stat = hw->eth_bar_base + 0x33000;
	hw->ext2_stat = hw->eth_bar_base + 0x33000 + 0x10;

	hw->fw_stat.fix_mac_addr[0] = raw_rd32(hw->ext_stat);
	hw->fw_stat.fix_mac_addr[1] = raw_rd32(hw->ext_stat + 0x4);
	hw->fw_stat.fw_version = raw_rd32(hw->ext_stat + 0x8);
	hw->fw_stat.pxe_version = raw_rd32(hw->ext_stat + 0xc);

	dev_info(hw->dev,
		 "perm-macaddr:%pM  fw_version:%u.%u.%u.%u pxe_version:0x%08x ccode:0x%x\n",
		(char *)hw->fw_stat.fix_mac_addr,
		(hw->fw_stat.fw_version >> 24) & 0xff,
		(hw->fw_stat.fw_version >> 16) & 0xff,
		(hw->fw_stat.fw_version >> 8) & 0xff,
		(hw->fw_stat.fw_version >> 0) & 0xff, hw->fw_stat.pxe_version,
		raw_rd32(hw->eth_bar_base + 0x3302c));

	n20_setup_mbx_info_fw(hw, mbx);
	mce_mbx_init_configure(mbx);

	mce_mbx_set_force_speed(hw, NO_FORCE_SPEED);
	if (hw->axi_mode != AXI_NO_FORCE)
		n20_set_axi_mhz(hw, hw->axi_mode);
	/* get capability from fw */
	ret = mce_fw_get_capability(hw, &ability);
	if (ret < 0)
		return ret;

	/* pfvfnum */
	hw->pfvfnum.vfnum = 0;
	pf->nr_pf = hw->pfvfnum.pf;
	mbx->nr_pf = pf->nr_pf;
	snprintf(mbx->name, sizeof(mbx->name), "%s-mbx-pf%d",
		 pci_name(hw->pdev), mbx->nr_pf);
	hw->max_speed = speed_unzip(ability.max_speed);
	hw->vf_isolation_disabled = ability.vf_isolation_disabled;
	hw->is_sgmii = ability.is_sgmii;
	hw->axi_mhz = ability.axi_mhz;
	hw->npu_avail = ability.rpu_available;

	/* later should get this from phy */
	hw->qos.link_speed = hw->max_speed / 1000; /* unit Mbit */
	hw->qos.interal = 100; /* unit ms */

	hw->qos.rate = (1000 / hw->qos.interal); /* interal*rate=1s */
	hw->func_caps.common_cap.num_txq = N20_MAX_Q_CNT;
	hw->func_caps.common_cap.num_rxq = N20_MAX_Q_CNT;
	hw->func_caps.common_cap.max_tc = MCE_MAX_TC_CNT;
	hw->func_caps.common_cap.queue_for_tc = MCE_QUEUE_FOR_TC;
	/* init vf params */
	hw->vf.ops->init_vf_params(hw, ability.vf_max_ring);
	hw->vf.ops->init_vf_pcie_totalvfs(hw, ability.vf_max_ring);
	hw->func_caps.common_cap.pcie_irq_capable =
		BIT(MCE_PCIE_IRQ_MODE_MSIX) | BIT(MCE_PCIE_IRQ_MODE_MSI) |
		BIT(MCE_PCIE_IRQ_MODE_LEGACY);

	hw->func_caps.common_cap.vlan_strip_cnt = N20_VLAN_DEFAULT_STRIP_CNT;

	hw->func_caps.common_cap.mbox_irq_base = N20_MBOX_IRQ_BASE;
	hw->func_caps.common_cap.num_mbox_irqs = N20_NUM_MBOX_IRQS;
	hw->func_caps.common_cap.rdma_irq_base = N20_RDMA_IRQ_BASE;
	hw->func_caps.common_cap.num_rdma_irqs = N20_NUM_RDMA_IRQS;
	hw->func_caps.common_cap.qvec_irq_base = N20_QVEC_IRQ_BASE;
	hw->func_caps.common_cap.max_irq_cnts = N20_MAX_IRQS;

	n20_init_feature(hw);
	hw->npu_avail = ability.rpu_available;
	hw->func_caps.common_cap.npu_capable = hw->npu_avail;

	hw->func_caps.common_cap.pf_rss_tb_size = N20_RSS_PF_TABLE_SIZE;
	hw->func_caps.common_cap.vf_rss_tb_size = N20_RSS_VF_TABLE_SIZE;
	hw->func_caps.common_cap.rss_key_size = N20_RSS_HASH_KEY_SIZE;

	hw->cur_tc_time_for_rdma = 1024;
	/* only for test 25Gbps in tc_time */
	hw->cur_link_speed = 25 * 1024 / hw->cur_tc_time_for_rdma;
	return 0;
}
