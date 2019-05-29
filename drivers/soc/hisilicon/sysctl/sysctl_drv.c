// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Hisilicon Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http:
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/io.h>
#include <linux/cpu.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include "sysctl_drv.h"
#include "hllc_ras_c_union_define.h"
#include "hllc_ras_reg_offset.h"
#include "hllc_regs_c_union_define.h"
#include "hllc_regs_reg_offset.h"
#include "hllc_pcs_c_union_define.h"
#include "hllc_pcs_reg_offset.h"
#include "dmc_c_union_define.h"
#include "dmc_reg_offset.h"
#include "rasc_c_union_define.h"
#include "rasc_reg_offset.h"
#include "pa_c_union_define.h"

#include "pa_reg_offset.h"
#include "sysctl_local_ras.h"

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#define DEBUG

#define	SYSCTL_DRIVER_VERSION "1.7.8.0"
/* debug?a1? */
unsigned int g_sysctrl_debug;

/* sysctrl reg base address */
struct his_hllc_priv {
	void __iomem *hllc_base[CHIP_ID_NUM_MAX][HLLC_NUM_MAX];
	void __iomem *pcs_base[CHIP_ID_NUM_MAX][HLLC_NUM_MAX];
	void __iomem *pa_base[CHIP_ID_NUM_MAX];
	void __iomem *ddrc_tb_base[CHIP_ID_NUM_MAX][DDRC_CH_NUM_MAX];
	void __iomem *ddrc_ta_base[CHIP_ID_NUM_MAX][DDRC_CH_NUM_MAX];
	void __iomem *pm_base[CHIP_ID_NUM_MAX];
};

struct his_hllc_priv hip_hllc_priv;

static void his_sysctrl_reg_rd(const void __iomem *addr, u32 reg, unsigned int *val)
{
	*val = readl(addr + reg);
}

static void his_sysctrl_reg_wr(void __iomem *addr, u32 reg, unsigned int val)
{
	writel(val, addr + reg);
}

int hisi_sysctl_print_debug(u32 print_debug_en)
{
	if (print_debug_en)
		g_sysctrl_debug = 0x1;
	else
		g_sysctrl_debug = 0x0;

	return 0;
}

int his_hllc_init(void)
{
	u32 hllc_num;
	u32 chip_id;
	u32 ddrc_num;
	u64 addr;
	u32 chip_ver;
	u64 chip_module_base;
	void __iomem *chip_ver_addr;

	pr_info("[INFO] %s start.\n", __func__);

	chip_ver_addr = ioremap(0x20107E238, (u64)4);
	if (!chip_ver_addr) {
		pr_err("[ERROR] %s chip_ver_base is error.\n", __func__);
		return ERR_FAILED;
	}

	chip_ver = readl(chip_ver_addr);
	chip_ver = chip_ver>>28;
	if (chip_ver == CHIP_VERSION_ES) {
		pr_info("[sysctl hllc] chip is es\n");
		chip_module_base = HLLC_CHIP_MODULE_ES;
	} else {
		chip_module_base = HLLC_CHIP_MODULE_CS;
		pr_info("[sysctl hllc] chip is cs\n");
	}

	pr_info("[sysctl hllc] chip ver=%x\n", chip_ver);
	for (chip_id = 0; chip_id < CHIP_ID_NUM_MAX; chip_id++) {
		for (hllc_num = 0; hllc_num < HLLC_NUM_MAX; hllc_num++) {
			addr = (u64)chip_id * chip_module_base + HLLC0_REG_BASE + (u64)hllc_num * 0x10000;
			hip_hllc_priv.hllc_base[chip_id][hllc_num] = ioremap(addr, (u64)0x10000);

			debug_sysctrl_print("[DBG] hllc_base: %p.\n",
				hip_hllc_priv.hllc_base[chip_id][hllc_num]);

			addr = (u64)chip_id * chip_module_base + PCS0_REG_BASE + (u64)hllc_num * 0x10000;
			hip_hllc_priv.pcs_base[chip_id][hllc_num] = ioremap(addr, (u64)0x10000);

			debug_sysctrl_print("[DBG] pcs_base: %p.\n",
				hip_hllc_priv.pcs_base[chip_id][hllc_num]);
		}

		addr = (u64)chip_id * chip_module_base + PA_REG_BASE;
		hip_hllc_priv.pa_base[chip_id] = ioremap(addr, (u64)0x10000);

		debug_sysctrl_print("[DBG] pa_base: %p.\n",
			hip_hllc_priv.pa_base[chip_id]);

		addr = (u64)chip_id * chip_module_base + PM_REG_BASE;
		hip_hllc_priv.pm_base[chip_id] = ioremap(addr, (u64)0x10000);

		debug_sysctrl_print("[DBG] pm_base: %p.\n",
			hip_hllc_priv.pm_base[chip_id]);

		for (ddrc_num = 0; ddrc_num < DDRC_CH_NUM_MAX; ddrc_num++) {
			addr = (u64)chip_id * chip_module_base + DDRC0_TB_REG_BASE + (u64)ddrc_num * 0x10000;
			hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_num] = ioremap(addr, (u64)0x10000);
			addr = (u64)chip_id * chip_module_base + DDRC0_TA_REG_BASE + (u64)ddrc_num * 0x10000;
			hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_num] = ioremap(addr, (u64)0x10000);

			debug_sysctrl_print("[DBG] ddrc_tb_base: %p.\n",
				hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_num]);
			debug_sysctrl_print("[DBG] ddrc_ta_base: %p.\n",
				hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_num]);
		}

	}

	iounmap((void *)chip_ver_addr);

	return ERR_OK;
}

int his_hllc_deinit(void)
{
	u8 chip_id;
	u8 hllc_num;
	u8 ddrc_num;

	for (chip_id = 0; chip_id < CHIP_ID_NUM_MAX; chip_id++) {
		for (hllc_num = 0; hllc_num < HLLC_NUM_MAX; hllc_num++) {
			if (hip_hllc_priv.hllc_base[chip_id][hllc_num])
				iounmap((void *)hip_hllc_priv.hllc_base[chip_id][hllc_num]);

			if (hip_hllc_priv.pcs_base[chip_id][hllc_num])
				iounmap((void *)hip_hllc_priv.pcs_base[chip_id][hllc_num]);
		}

		if (hip_hllc_priv.pa_base[chip_id])
			iounmap((void *)hip_hllc_priv.pa_base[chip_id]);

		if (hip_hllc_priv.pm_base[chip_id])
			iounmap((void *)hip_hllc_priv.pm_base[chip_id]);

		for (ddrc_num = 0; ddrc_num < DDRC_CH_NUM_MAX; ddrc_num++) {
			if (hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_num])
				iounmap((void *)hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_num]);

			if (hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_num])
				iounmap((void *)hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_num]);
		}
	}

	return ERR_OK;
}

int hisi_sysctl_get_intlv_mode_cfg(u8 chip_id, u8 *intlv_mode_cfg)
{
	pa_u_global_cfg pa_global_cfg;
	void __iomem *addr;
	int ret = 0;

	debug_sysctrl_print("%s: begin\n", __func__);

	if (intlv_mode_cfg == NULL)
		return ERR_PARAM;

	if (chip_id >= CHIP_ID_NUM_MAX)
		return ERR_PARAM;

	/* set the PLL0 slow */
	if (hip_hllc_priv.pa_base[chip_id] == NULL) {
		pr_err("%s: hip_hllc_priv.pa_base[%u] is NULL.\n", __func__, chip_id);
		return ERR_FAULT;
	}

	addr = hip_hllc_priv.pa_base[chip_id] + PA_PA_GLOBAL_CFG_REG;
	pa_global_cfg.u32 = readl(addr);

	debug_sysctrl_print("addr:%p, val:0x%x.\n",
		addr, pa_global_cfg.u32);

	*intlv_mode_cfg = (u8)pa_global_cfg.bits.intlv_mode_cfg;

	debug_sysctrl_print("%s: end\n", __func__);
	return ret;
}

int hisi_sysctl_get_hllc_enable_cfg(u8 chip_id, u8 intlv_mode_cfg, u8 *hllc_eanble_cfg)
{
	pa_u_global_cfg pa_global_cfg;
	void __iomem *addr;
	int ret = 0;

	debug_sysctrl_print("%s: begin\n", __func__);

	if (hllc_eanble_cfg == NULL)
		return ERR_PARAM;

	switch (intlv_mode_cfg & 0x7) {
	case HLLC_INTLV_MODE_2PX8:
		if (hip_hllc_priv.pa_base[chip_id] == NULL) {
			pr_err("%s: hip_hllc_priv.pa_base[%u] is NULL.\n", __func__, chip_id);
			return ERR_FAULT;
		}

		addr = hip_hllc_priv.pa_base[chip_id] + PA_PA_GLOBAL_CFG_REG;
		pa_global_cfg.u32 = readl(addr);

		debug_sysctrl_print("addr:%p, val:0x%x.\n",
			addr, pa_global_cfg.u32);

		*hllc_eanble_cfg = (u8)pa_global_cfg.bits.hydra_port_en_cfg;
		break;

	case HLLC_INTLV_MODE_2PX16:
		/* 2p x16, port0-port1 */
		*hllc_eanble_cfg = 0x3;
		break;

	case HLLC_INTLV_MODE_2PX24:
		debug_sysctrl_print("2PX24 is no use. pls check\n");
		break;

	case HLLC_INTLV_MODE_4PX8:
		/* 4P */
		*hllc_eanble_cfg = 0x7;
		break;

	case HLLC_INTLV_MODE_3P1:
		/* 3P */
		*hllc_eanble_cfg = 0x7;
		break;
	case HLLC_INTLV_MODE_3P2:
		/* 3P */
		*hllc_eanble_cfg = 0x7;
		break;
	default:
		debug_sysctrl_print("intlv_mode_cfg[0x%x] is err\n",
			intlv_mode_cfg);
		ret = ERR_FAILED;
		break;
	}

	debug_sysctrl_print("hllc_eanble_cfg is 0x%x.\n.",
		*hllc_eanble_cfg);

	debug_sysctrl_print("%s: end\n",
		__func__);
	return ret;
}

int hisi_sysctl_clr_hllc_ecc(u8 chip_id, u8 hllc_id, u32 ecc_clr)
{
	void __iomem *addr;

	debug_sysctrl_print("%s: begin\n", __func__);

	if (CHIP_ID_NUM_MAX <= chip_id || HLLC_NUM_MAX <= hllc_id)
		return ERR_PARAM;

	debug_sysctrl_print("clr_hllc_ecc:chip_id[0x%x], hllc_id[0x%x].\n",
		chip_id, hllc_id);

	if (hip_hllc_priv.hllc_base[chip_id][hllc_id] == NULL) {
		pr_err("%s: hip_hllc_priv.hllc_base[%u][%u] is NULL.\n",
			__func__, chip_id, hllc_id);
		return ERR_FAULT;
	}

	/* hllc clr ecc */
	addr = hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_REGS_HLLC_CNT_CLR_REG;

	writel(ecc_clr & 0x1, addr);

	return ERR_OK;
}

int hisi_sysctl_set_hllc_crc_ecc(u8 chip_id, u8 hllc_id, u32 crc_err_times)
{
	void __iomem *addr;
	u32 loop = 0x10000;
	u32 inject_crc_err_done = 0;

	debug_sysctrl_print("%s: begin\n", __func__);

	if (CHIP_ID_NUM_MAX <= chip_id
		|| HLLC_NUM_MAX <= hllc_id
		|| 0 == crc_err_times)
		return ERR_PARAM;

	debug_sysctrl_print("set_hllc_crc_ecc:chip_id[0x%x], hllc_id[0x%x], crc_err_times[0x%x].\n", chip_id, hllc_id, crc_err_times);

	if (hip_hllc_priv.hllc_base[chip_id][hllc_id] == NULL) {
		pr_err("%s: hip_hllc_priv.hllc_base[%u][%u] is NULL.\n", __func__, chip_id, hllc_id);
		return ERR_FAULT;
	}

	/* enable crc ecc*/
	addr = hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_REGS_HLLC_PHY_TX_INJECT_1BIT_CRC_ERR_EN_REG;
	writel(0x1, addr);
	writel(0x0, addr);

	/* config ecc count */
	addr = hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_REGS_HLLC_PHY_TX_INJECT_1BIT_CRC_ERR_TIMES_REG;
	writel(crc_err_times, addr);

	/* check done */
	addr = hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_REGS_HLLC_PHY_TX_INJECT_1BIT_CRC_ERR_DONE_REG;
	while (loop) {
		udelay((unsigned long)100);

		inject_crc_err_done = readl(addr);
		if (inject_crc_err_done & 0x1)
			break;

		loop--;
	}

	if (!loop) {
		pr_err("%s:set hllc crc ecc time out, hip_hllc_priv.hllc_base[%u][%u] is NULL.\n", __func__, chip_id, hllc_id);
		return ERR_TIMEOUT;
	}

	debug_sysctrl_print("%s: set_hllc_mem_ecc success\n", __func__);

	return ERR_OK;
}

int hisi_sysctl_get_hllc_crc_ecc(u8 chip_id, hllc_crc_ecc_info *hllc_crc_ecc)
{
	u32 phy_rx_flit_crc_err_cnt;
	void __iomem *addr;
	int ret;
	u8 intlv_mode_cfg;
	u8 hllc_eanble_cfg = 0;
	u8 hllc_num;

	debug_sysctrl_print("%s: begin\n", __func__);

	if (chip_id >= CHIP_ID_NUM_MAX)
		return ERR_PARAM;

	if (hllc_crc_ecc == NULL)
		return ERR_PARAM;

	ret = hisi_sysctl_get_intlv_mode_cfg(chip_id, &intlv_mode_cfg);
	if (ret)
		return ret;

	ret = hisi_sysctl_get_hllc_enable_cfg(chip_id, intlv_mode_cfg, &hllc_eanble_cfg);
	if (ret)
		return ret;

	hllc_crc_ecc->hllc_enable = hllc_eanble_cfg;

	for (hllc_num = 0; hllc_num < HLLC_NUM_MAX; hllc_num++) {
		if (hip_hllc_priv.hllc_base[chip_id][hllc_num] == NULL) {
			pr_err("%s: hip_hllc_priv.hllc_base[%u][%u] is NULL.\n", __func__, chip_id, hllc_num);
			return ERR_FAULT;
		}

		addr = hip_hllc_priv.hllc_base[chip_id][hllc_num] + HLLC_HLLC_REGS_HLLC_PHY_RX_FLIT_CRC_ERR_CNT_REG;
		phy_rx_flit_crc_err_cnt = readl(addr);

		debug_sysctrl_print("addr:%p, crc_err_cnt:0x%x.\n",
			addr, phy_rx_flit_crc_err_cnt);

		hllc_crc_ecc->hllc_crc_ecc[hllc_num] = phy_rx_flit_crc_err_cnt;
	}

	debug_sysctrl_print("hllc_crc_ecc.hllc_enable:0x%x.\n",
		hllc_crc_ecc->hllc_enable);

	debug_sysctrl_print("%s: get_hllc_crc_ecc success\n",
		__func__);

	return ret;
}

int hisi_sysctl_get_hllc_link_status(u8 chip_id, hllc_link_sta_info *hllc_link_sta)
{
	pcs_u_tx_training_sts pcs_tx_training_sts;
	void __iomem *addr;
	int ret;
	u8 intlv_mode_cfg;
	u8 hllc_eanble_cfg = 0;
	u8 hllc_num;
	u8 lane_num;
	u8 hllc_link_status;

	debug_sysctrl_print("%s: begin\n", __func__);

	if (chip_id >= CHIP_ID_NUM_MAX)
		return ERR_PARAM;

	if (hllc_link_sta == NULL)
		return ERR_PARAM;

	ret = hisi_sysctl_get_intlv_mode_cfg(chip_id, &intlv_mode_cfg);
	if (ret)
		return ret;

	ret = hisi_sysctl_get_hllc_enable_cfg(chip_id, intlv_mode_cfg, &hllc_eanble_cfg);
	if (ret)
		return ret;

	hllc_link_sta->bits.hllc_enable = hllc_eanble_cfg;
	hllc_link_sta->bits.hllc_link_status = 0;

	for (hllc_num = 0; hllc_num < HLLC_NUM_MAX; hllc_num++) {
		hllc_link_status = 1;

		if (hip_hllc_priv.pcs_base[chip_id][hllc_num] == NULL) {
			pr_err("%s: hip_hllc_priv.pcs_base[%u][%u] is NULL.\n",
				__func__, chip_id, hllc_num);
			return ERR_FAULT;
		}

		for (lane_num = 0; lane_num < HLLC_LANE_NUM_MAX; lane_num++) {
			addr = hip_hllc_priv.pcs_base[chip_id][hllc_num] + HLLC_HLLC_PCS_PCS_TX_TRAINING_STS_0_REG + lane_num * 4;
			pcs_tx_training_sts.u32 = readl(addr);

			debug_sysctrl_print("addr:%p, val:0x%x.\n",
				addr, pcs_tx_training_sts.u32);

			hllc_link_status &= pcs_tx_training_sts.bits.tx_training_succeed;
		}

		hllc_link_sta->bits.hllc_link_status |= hllc_link_status << hllc_num;
	}

	debug_sysctrl_print("hllc_crc_ecc:0x%x.\n",
		hllc_link_sta->u32);

	debug_sysctrl_print("%s: get_hllc_link_status success\n",
		__func__);

	return ret;
}

int hisi_sysctl_set_hllc_mem_ecc(u8 chip_id, u8 hllc_id, u8 hllc_ch_bitmap, u8 ecc_err_type)
{
	hllc_regs_u_inject_ecc_type hllc_inject_ecc_type;
	hllc_regs_u_inject_ecc_en hllc_inject_ecc_en;
	void __iomem *addr;
	int ret = 0;

	debug_sysctrl_print("%s: begin\n", __func__);

	if (CHIP_ID_NUM_MAX <= chip_id || HLLC_NUM_MAX <= hllc_id)
		return ERR_PARAM;

	debug_sysctrl_print("set_hllc_mem_ecc:chip_id[0x%x], hllc_id[0x%x], hllc_ch_bitmap[0x%x], ecc_err_type[0x%x] .\n",
		chip_id, hllc_id, hllc_ch_bitmap, ecc_err_type);

	if (hip_hllc_priv.hllc_base[chip_id][hllc_id] == NULL) {
		pr_err("%s: hip_hllc_priv.hllc_base[%u][%u] is NULL.\n", __func__, chip_id, hllc_id);
		return ERR_FAULT;
	}

	addr = hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_REGS_HLLC_INJECT_ECC_TYPE_REG;
	hllc_inject_ecc_type.u32 = readl(addr);
	hllc_inject_ecc_type.bits.inject_ecc_err_type = ecc_err_type & 0x3;
	writel(hllc_inject_ecc_type.u32, addr);

	debug_sysctrl_print("addr:%p, val:0x%x.\n",
		addr, hllc_inject_ecc_type.u32);

	addr = hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_REGS_HLLC_INJECT_ECC_EN_REG;
	hllc_inject_ecc_en.u32 = readl(addr);
	hllc_inject_ecc_en.bits.hydra_tx_inject_ecc_err_en = hllc_ch_bitmap & 0x7;
	writel(hllc_inject_ecc_en.u32, addr);

	debug_sysctrl_print("addr:%p, val:0x%x.\n",
		addr, hllc_inject_ecc_en.u32);

	debug_sysctrl_print("%s: set_hllc_mem_ecc success\n", __func__);

	return ret;
}

int hisi_sysctl_get_hllc_mem_ecc(u8 chip_id, u8 hllc_id, hllc_mem_ecc_info *hllc_mem_ecc)
{
	hllc_ras_u_err_misc1h hllc_ras_err_misc1h;
	hllc_ras_u_err_misc1l hllc_ras_err_misc1l;
	void __iomem *addr;
	int ret = 0;

	debug_sysctrl_print("%s: begin\n", __func__);

	if (CHIP_ID_NUM_MAX <= chip_id
		|| HLLC_NUM_MAX <= hllc_id
		|| hllc_mem_ecc == NULL)
		return ERR_PARAM;

	debug_sysctrl_print("get_hllc_mem_ecc:chip_id[0x%x], hllc_id[0x%x].\n",
		chip_id, hllc_id);

	if (hip_hllc_priv.hllc_base[chip_id][hllc_id] == NULL) {
		pr_err("%s: hip_hllc_priv.hllc_base[%u][%u] is NULL.\n",
			__func__, chip_id, hllc_id);
		return ERR_FAULT;
	}

	addr = hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_RAS_HLLC_ERR_MISC1H_REG;
	hllc_ras_err_misc1h.u32 = readl(addr);
	hllc_mem_ecc->u32 = hllc_ras_err_misc1h.u32 & 0x7f;
	debug_sysctrl_print("addr:%p, val:0x%x.\n",
		addr, hllc_ras_err_misc1h.u32);

	addr = hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_RAS_HLLC_ERR_MISC1L_REG;
	hllc_ras_err_misc1l.u32 = readl(addr);
	hllc_mem_ecc->u32 |= (hllc_ras_err_misc1l.u32 & 0x7f) << 0x7;
	debug_sysctrl_print("addr:%p, val:0x%x.\n",
		addr, hllc_ras_err_misc1l.u32);

	debug_sysctrl_print("hllc_mem_ecc:0x%x.\n",
		hllc_mem_ecc->u32);

	debug_sysctrl_print("%s: get_hllc_mem_ecc success\n",
		__func__);

	return ret;
}

int hisi_sysctl_clr_ddrc_mem_ecc(u8 chip_id, u8 totem, u8 ddrc_ch_id, u32 rasc_cfg_clr)
{
	ddrc_rasc_u_cfg_clr ddrc_rasc_cfg_clr;
	void __iomem *addr_ecc_clr;
	int ret = 0;

	debug_sysctrl_print("%s: begin\n",
		__func__);

	if (CHIP_ID_NUM_MAX <= chip_id
		|| TOTEM_NUM_MAX <= totem
		|| DDRC_CH_NUM_MAX <= ddrc_ch_id)
		return ERR_PARAM;

	debug_sysctrl_print("clr_ddrc_mem_ecc:chip_id[0x%x], totem[0x%x], ddrc_ch_id[0x%x].\n",
		chip_id, totem, ddrc_ch_id);

	if (totem == TOTEM_TA_NUM) {
		if (hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_ch_id] == NULL) {
			pr_err("%s: hip_hllc_priv.ddrc_ta_base[%u][%u] is NULL.\n",
				__func__, chip_id, ddrc_ch_id);
			return ERR_FAULT;
		}

		addr_ecc_clr = hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_ch_id] + DDRC_RASC_RASC_CFG_CLR_REG;
	} else {
		if (hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_ch_id] == NULL) {
			pr_err("%s: hip_hllc_priv.ddrc_tb_base[%u][%u] is NULL.\n",
				__func__, chip_id, ddrc_ch_id);
			return ERR_FAULT;
		}

		addr_ecc_clr = hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_ch_id] + DDRC_RASC_RASC_CFG_CLR_REG;
	}

	ddrc_rasc_cfg_clr.u32 = rasc_cfg_clr;
	writel(ddrc_rasc_cfg_clr.u32, addr_ecc_clr);

	debug_sysctrl_print("addr:%p, val:0x%x.\n",
		addr_ecc_clr, ddrc_rasc_cfg_clr.u32);

	return ret;
}

int hisi_sysctl_get_ddrc_mem_ecc(u8 chip_id, u8 totem, u8 ddrc_ch_id, u8 rank_id, ddrc_mem_ecc_info *ddrc_mem_ecc)
{
	dmc_ddrc_u_cfg_ecc dmc_ddrc_cfg_ecc;
	ddrc_rasc_u_cfg_info_rnk ddrc_rasc_cfg_info_rnk;
	ddrc_rasc_u_his_ha_rankcnt_inf ddrc_rasc_his_ha_rankcnt_inf;
	void __iomem *addr_ecc_cnt;
	void __iomem *addr_ecc_cfg_info_rnk;
	void __iomem *addr_ecc_cfg_ecc;
	int ret = 0;

	debug_sysctrl_print("%s: begin\n", __func__);

	if (CHIP_ID_NUM_MAX <= chip_id
		|| TOTEM_NUM_MAX <= totem
		|| DDRC_CH_NUM_MAX <= ddrc_ch_id
		|| ddrc_mem_ecc == NULL
		|| DDRC_RANK_NUM_MAX <= rank_id)
		return ERR_PARAM;

	debug_sysctrl_print("get_ddrc_mem_ecc:chip_id[0x%x], totem[0x%x], ddrc_ch_id[0x%x], rank_id[0x%x].\n",
		chip_id, totem, ddrc_ch_id, rank_id);

	if (totem == TOTEM_TA_NUM) {
		if (hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_ch_id] == NULL) {
			pr_err("%s: hip_hllc_priv.ddrc_ta_base[%u][%u] is NULL.\n",
				__func__, chip_id, ddrc_ch_id);
			return ERR_FAULT;
		}

		addr_ecc_cfg_info_rnk = hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_ch_id] + DDRC_RASC_RASC_CFG_INFO_RNK_REG;
		addr_ecc_cnt = hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_ch_id] + DDRC_RASC_RASC_HIS_HA_RANKCNT_INF_REG;
		addr_ecc_cfg_ecc = hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_ch_id] + DMC_DMC_DDRC_CFG_ECC_REG;
	} else {
		if (hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_ch_id] == NULL) {
			pr_err("%s: hip_hllc_priv.ddrc_tb_base[%u][%u] is NULL.\n",
				__func__, chip_id, ddrc_ch_id);
			return ERR_FAULT;
		}

		addr_ecc_cfg_info_rnk = hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_ch_id] + DDRC_RASC_RASC_CFG_INFO_RNK_REG;
		addr_ecc_cnt = hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_ch_id] + DDRC_RASC_RASC_HIS_HA_RANKCNT_INF_REG;
		addr_ecc_cfg_ecc = hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_ch_id] + DMC_DMC_DDRC_CFG_ECC_REG;
	}

	debug_sysctrl_print("addr_ecc_cfg_info_rnk:%p.\n",
		addr_ecc_cfg_info_rnk);

	memset(&ddrc_rasc_cfg_info_rnk, 0, sizeof(ddrc_rasc_u_cfg_info_rnk));
	ddrc_rasc_cfg_info_rnk.bits.idx_rnk = rank_id & 0xf;
	(void)writel(ddrc_rasc_cfg_info_rnk.u32, addr_ecc_cfg_info_rnk);

	ddrc_rasc_his_ha_rankcnt_inf.u32 = readl(addr_ecc_cnt);
	ddrc_mem_ecc->ddrc_mem_secc = ddrc_rasc_his_ha_rankcnt_inf.u32;
	debug_sysctrl_print("addr:%p, ddrc_serr_cnt.funnel_corr_cnt:0x%x.\n",
		addr_ecc_cnt, ddrc_rasc_his_ha_rankcnt_inf.bits.ha_rnk_funnel_corr_cnt);
	debug_sysctrl_print("addr:%p, ddrc_serr_cnt.corr_cnt:0x%x.\n",
		addr_ecc_cnt, ddrc_rasc_his_ha_rankcnt_inf.bits.ha_rnk_corr_cnt);

	dmc_ddrc_cfg_ecc.u32 = readl(addr_ecc_cfg_ecc);
	if ((dmc_ddrc_cfg_ecc.u32 & DDRC_ECC_EN) == DDRC_ECC_EN) {
		ddrc_mem_ecc->ddrc_mem_secc_en = 0x1;
	} else {
		ddrc_mem_ecc->ddrc_mem_secc_en = 0x0;
	}

	debug_sysctrl_print("addr:%p, dmc_ddrc_cfg_ecc:0x%x.\n",
		addr_ecc_cfg_ecc, dmc_ddrc_cfg_ecc.u32);

	debug_sysctrl_print("%s: get_ddrc_mem_ecc success\n",
		__func__);

	return ret;
}

/* check: hisi_sysctl_get_hllc_crc_ecc */
unsigned long ut_hisi_sysctl_get_hllc_crc_ecc_enable(u8 chip_id)
{
	unsigned int ret = ERR_OK;
	hllc_crc_ecc_info hllc_crc_ecc;

	memset(&hllc_crc_ecc, 0, sizeof(hllc_crc_ecc_info));
	ret = hisi_sysctl_get_hllc_crc_ecc(chip_id, &hllc_crc_ecc);
	pr_info("hllc_crc_ecc.hllc_enable:0x%x.\n",
		hllc_crc_ecc.hllc_enable);

	return ((unsigned long)hllc_crc_ecc.hllc_enable << 32) | ret;
}

unsigned long ut_hisi_sysctl_get_hllc_crc_ecc(u8 chip_id, u32 hllc_id)
{
	unsigned int ret = ERR_OK;
	hllc_crc_ecc_info hllc_crc_ecc;

	memset(&hllc_crc_ecc, 0, sizeof(hllc_crc_ecc_info));
	ret = hisi_sysctl_get_hllc_crc_ecc(chip_id, &hllc_crc_ecc);
	pr_info("hllc_crc_ecc.hllc_crc_ecc[%d]:0x%x.\n",
		hllc_id, hllc_crc_ecc.hllc_crc_ecc[hllc_id]);

	return ((unsigned long)hllc_crc_ecc.hllc_crc_ecc[hllc_id] << 32) | ret;
}

/* check: hisi_sysctl_get_hllc_link_status */
unsigned long ut_hisi_sysctl_get_hllc_link_enable(u8 chip_id)
{
	unsigned int ret = ERR_OK;
	hllc_link_sta_info hllc_link_sta;

	memset(&hllc_link_sta, 0, sizeof(hllc_link_sta_info));
	ret = hisi_sysctl_get_hllc_link_status(chip_id, &hllc_link_sta);
	pr_info("hllc_link_sta.bits.hllc_enable:0x%x.\n",
		hllc_link_sta.bits.hllc_enable);

	return ((unsigned long)hllc_link_sta.bits.hllc_enable << 32) | ret;
}

unsigned long ut_hisi_sysctl_get_hllc_link_status(u8 chip_id)
{
	unsigned int ret = ERR_OK;
	hllc_link_sta_info hllc_link_sta;

	memset(&hllc_link_sta, 0, sizeof(hllc_link_sta_info));
	ret = hisi_sysctl_get_hllc_link_status(chip_id, &hllc_link_sta);
	pr_info("hllc_link_sta.bits.hllc_link_status:0x%x.\n",
		hllc_link_sta.bits.hllc_link_status);

	return ((unsigned long)hllc_link_sta.bits.hllc_link_status << 32) | ret;
}

/* check: hisi_sysctl_get_hllc_mem_ecc */
unsigned long ut_hisi_sysctl_get_hllc_mem_ecc(u8 chip_id, u8 hllc_id)
{
	unsigned int ret = ERR_OK;
	hllc_mem_ecc_info hllc_mem_ecc;

	memset(&hllc_mem_ecc, 0, sizeof(hllc_mem_ecc_info));
	ret = hisi_sysctl_get_hllc_mem_ecc(chip_id, hllc_id, &hllc_mem_ecc);
	pr_info("hllc_mem_ecc.u32:0x%x.\n",
		hllc_mem_ecc.u32);

	return ((unsigned long)hllc_mem_ecc.u32 << 32) | ret;
}

/* check: hisi_sysctl_get_ddrc_mem_ecc */
unsigned long ut_hisi_sysctl_get_ddrc_mem_secc_en(u8 chip_id, u8 totem, u8 ddrc_ch_id, u8 rank_id)
{
	unsigned int ret = ERR_OK;
	ddrc_mem_ecc_info ddrc_mem_ecc;

	memset(&ddrc_mem_ecc, 0, sizeof(ddrc_mem_ecc_info));
	ret = hisi_sysctl_get_ddrc_mem_ecc(chip_id, totem, ddrc_ch_id, rank_id, &ddrc_mem_ecc);
	pr_info("ddrc_mem_ecc.ddrc_mem_secc_en:0x%x.\n",
		ddrc_mem_ecc.ddrc_mem_secc_en);

	return ((unsigned long)ddrc_mem_ecc.ddrc_mem_secc_en << 32) | ret;
}

unsigned long ut_hisi_sysctl_get_ddrc_mem_secc(u8 chip_id, u8 totem, u8 ddrc_ch_id, u8 rank_id)
{
	unsigned int ret = ERR_OK;
	ddrc_mem_ecc_info ddrc_mem_ecc;

	memset(&ddrc_mem_ecc, 0, sizeof(ddrc_mem_ecc_info));
	ret = hisi_sysctl_get_ddrc_mem_ecc(chip_id, totem, ddrc_ch_id, rank_id, &ddrc_mem_ecc);
	pr_info("ddrc_mem_ecc.ddrc_mem_secc:0x%x.\n",
		ddrc_mem_ecc.ddrc_mem_secc);

	return ((unsigned long)ddrc_mem_ecc.ddrc_mem_secc << 32) | ret;
}

unsigned long ut_hisi_sysctl_get_ddrc_mem_mecc(u8 chip_id, u8 totem, u8 ddrc_ch_id, u8 rank_id)
{
	unsigned int ret = ERR_OK;
	ddrc_mem_ecc_info ddrc_mem_ecc;

	memset(&ddrc_mem_ecc, 0, sizeof(ddrc_mem_ecc_info));
	ret = hisi_sysctl_get_ddrc_mem_ecc(chip_id, totem, ddrc_ch_id, rank_id, &ddrc_mem_ecc);
	pr_info("ddrc_mem_ecc.ddrc_mem_mecc:0x%x.\n",
		ddrc_mem_ecc.ddrc_mem_mecc);

	return ((unsigned long)ddrc_mem_ecc.ddrc_mem_mecc << 32) | ret;
}

int sysctl_reg_read8(u64 addr, u32 data_len)
{
	u32 loop;
	u8  data;
	void __iomem *reg_addr;
	void __iomem *reg_base;

	if (0x10000 <= data_len || data_len == 0)
		pr_err("%s: data_len[%u] is ERR, be range[0x0--0x10000].\n",
			__func__, data_len);

	reg_base = ioremap(addr, (u64)0x10000);

	for (loop = 0; loop < data_len; loop++) {
		reg_addr = reg_base + loop;
		data = readb(reg_addr);

		pr_info("0x%llx: 0x%2.2x\n", addr + loop, data);
	}

	if (reg_base)
		iounmap((void *)reg_base);

	return 0;
}

int sysctl_reg_write8(u64 addr, u8 data)
{
	void __iomem *reg_base;

	reg_base = ioremap(addr, (u64)0x100);

	writeb(data, reg_base);

	if (reg_base)
		iounmap((void *)reg_base);

	return 0;
}

int sysctl_reg_read32(u64 addr, u32 data_len)
{
	u32 loop;
	u32 data;
	void __iomem *reg_addr;
	void __iomem *reg_base;

	if (0x10000 <= data_len
		|| data_len == 0
		|| addr % 4 != 0) {
		pr_err("%s: data_len[%u] is ERR, be range[0x0--0x10000].\n",
			__func__, data_len);
	}

	reg_base = ioremap(addr, (u64)0x10000);

	for (loop = 0; loop < data_len; loop++) {
		reg_addr = reg_base + loop*4;
		data = readl(reg_addr);

		pr_info("0x%llx: 0x%8.8x\n", addr + (u64)loop*4, data);
	}

	if (reg_base)
		iounmap((void *)reg_base);

	return 0;
}

int sysctl_reg_write32(u64 addr, u32 data)
{
	void __iomem *reg_base;

	if (addr % 4 != 0)
		pr_err("%s: reg_addr is err.\n", __func__);

	reg_base = ioremap(addr, (u64)0x100);

	writel(data, reg_base);

	if (reg_base)
		iounmap((void *)reg_base);

	return 0;
}

int InitPmbus(u8 chip_id)
{
	static void __iomem *base;

	if (chip_id >= CHIP_ID_NUM_MAX) {
		pr_err("[sysctl pmbus]read chip_id range[0x0-0x3]is err!\n");
		return ERR_PARAM;
	}

	base = hip_hllc_priv.pm_base[chip_id];

	debug_sysctrl_print("Initialize Pmbus\n");

	his_sysctrl_reg_wr(base, PMBUS_WR_OPEN_OFFSET, 0x1ACCE551);
	his_sysctrl_reg_wr(base, AVS_WR_OPEN_OFFSET, 0x1ACCE551);
	his_sysctrl_reg_wr(base, I2C_LOCK_OFFSET, 0x36313832);

	his_sysctrl_reg_wr(base, I2C_ENABLE_OFFSET, 0);
	his_sysctrl_reg_wr(base, I2C_CON_OFFSET, 0x63);
	/*ulSclHigh > 1us*/
	his_sysctrl_reg_wr(base, I2C_SS_SCL_HCNT_OFFSET, I2C_SS_SCLHCNT);
	/*ulSclLow > 1.5us*/
	his_sysctrl_reg_wr(base, I2C_SS_SCL_LCNT_OFFSET, I2C_SS_SCLLCNT);
	his_sysctrl_reg_wr(base, I2C_ENABLE_OFFSET, 0x1);

	debug_sysctrl_print("Initialize Pmbus end\n");
	return 0;
}

int DeInitPmbus(u8 chip_id)
{
	static void __iomem *base;

	if (chip_id >= CHIP_ID_NUM_MAX) {
		pr_err("[sysctl pmbus]read chip_id range[0x0-0x3]is err!\n");
		return ERR_PARAM;
	}

	base = hip_hllc_priv.pm_base[chip_id];

	his_sysctrl_reg_wr(base, PMBUS_WR_OPEN_OFFSET, 0);
	his_sysctrl_reg_wr(base, AVS_WR_OPEN_OFFSET, 0);
	return 0;
}

int sysctl_pmbus_cfg (u8 chip_id, u8 addr, u8 page, u32 slave_addr)
{
	static void __iomem *base;
	if (chip_id >= CHIP_ID_NUM_MAX) {
		pr_err("[sysctl pmbus]read chip_id range[0x0-0x3]is err!\n");
		return ERR_PARAM;
	}

	base = hip_hllc_priv.pm_base[chip_id];

	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (2 << 8) | slave_addr);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, addr);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (4 << 8) | page);

	return 0;
}

int sysctl_pmbus_write(u8 chip_id, u8 addr, u32 slave_addr, u32 data_len, u32 buf)
{
	u32 i = 0;
	u32 temp = 0;
	u32 loop = 0x1000;
	static void __iomem *base;

	if (CHIP_ID_NUM_MAX <= chip_id
		|| 0x4 < data_len) {
		pr_err("[sysctl pmbus]write chip_id range[0x0-0x3] or data_len range[0x0-0x4] is err!\n");
		return ERR_PARAM;
	}

	base = hip_hllc_priv.pm_base[chip_id];

	his_sysctrl_reg_wr(base, I2C_INTR_RAW_OFFSET, 0x3ffff);

	his_sysctrl_reg_wr(base, 0x0810, (2 << 8) | slave_addr);
	if (data_len != 0) {
		his_sysctrl_reg_wr(base, 0x0810, addr);

		for (i = 0; i < data_len - 1; i++)
			his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, 0xff & (buf >> (i*8)));

		his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (4 << 8) | (0xff & (buf >> (i*8))));
	} else {
		his_sysctrl_reg_wr(base, 0x0810, (4 << 8) | addr);
	}

	/*poll untill send done*/
	for (;;) {
		udelay((unsigned long)100);

		his_sysctrl_reg_rd(base, I2C_INTR_RAW_OFFSET, &temp);

		/*send data failed*/
		if (temp & I2C_TX_ABRT) {
			his_sysctrl_reg_rd(base, I2C_TX_ABRT_SRC_REG, &temp);
			pr_err("[sysctl pmbus]write data fail, chip_id:0x%x,slave_addr:0x%x, addr:0x%x!\r\n",
				chip_id, slave_addr, addr);

			his_sysctrl_reg_rd(base, I2C_CLR_TX_ABRT_REG, &temp);
			return ERR_FAILED;
		}

		his_sysctrl_reg_rd(base, I2C_STATUS_REG, &temp);
		if (temp & I2C_TX_FIFO_EMPTY) {
			his_sysctrl_reg_rd(base, I2C_TX_FIFO_DATA_NUM_REG, &temp);
			if (temp == 0)
				break;
		}

		loop--;
		if (0 == loop) {
			pr_err("[sysctl pmbus]write data retry fail, chip_id:0x%x,slave_addr:0x%x, addr:0x%x!\r\n", chip_id, slave_addr, addr);
			return ERR_FAILED;
		}
	}

	return ERR_OK;
}

int sysctl_pmbus_read(u8 chip_id, u8 addr, u32 slave_addr, u32 data_len, u32 *buf)
{
	u32 i = 0;
	u32 fifo_num = 0;
	u32 temp_byte = 0;
	u32 temp = 0;
	u32 loop = 0x100;
	static void __iomem *base;

	if (CHIP_ID_NUM_MAX <= chip_id
		|| DATA_NUM_MAX < data_len
		|| 0x0 == data_len) {
		pr_err("[sysctl pmbus]read chip_id range[0x0-0x3] or data_len range[0x1-0x4] is err!\n");
		return ERR_PARAM;
	}

	base = hip_hllc_priv.pm_base[chip_id];

	his_sysctrl_reg_wr(base, I2C_INTR_RAW_OFFSET, 0x3ffff);

	his_sysctrl_reg_rd(base, I2C_RXFLR_OFFSET, &fifo_num);
	debug_sysctrl_print("[sysctl_pmbus_read_byte]read pmbus , read empty rx fifo num:%d\r\n", fifo_num);
	for (i = 0; i < fifo_num; i++) {
		his_sysctrl_reg_rd(base, I2C_DATA_CMD_OFFSET, &temp_byte);
	}

	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (2 << 8) | slave_addr);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, addr);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (3 << 8) | slave_addr);

	i = data_len;
	while (i - 1 > 0) {
		his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, 0x100);
		i--;
	}

	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, 0x500);

	while (--loop) {
		udelay((unsigned long)100);
		his_sysctrl_reg_rd(base, I2C_RXFLR_OFFSET, &fifo_num);
		debug_sysctrl_print("[sysctl_pmbus_read_byte]read pmbus, read rx fifo num:%d\r\n", fifo_num);
		if (data_len == fifo_num) {
			debug_sysctrl_print("[sysctl_pmbus_read_byte]read pmbus, Loop:%d\r\n", 0xffff - loop);
			break;
		}
	}

	if (0 == loop) {
		pr_err("[sysctl pmbus]read pmbus error, I2C_RXFLR = %d\n", fifo_num);
		for (i = 0; i < fifo_num; i++) {
			his_sysctrl_reg_rd(base, I2C_DATA_CMD_OFFSET, &temp_byte);
		}

		if (temp_byte) {

		}

		his_sysctrl_reg_wr(base, I2C_INTR_RAW_OFFSET, 0x3FFFF);
		return ERR_TIMEOUT;
	}

	for (i = 0; i < data_len; i++) {
		his_sysctrl_reg_rd(base, I2C_DATA_CMD_OFFSET, &temp_byte);

		temp |= temp_byte << (i*8);
	}

	pr_info("[sysctl pmbus]read pmbus temp = 0x%x\n", temp);

	if (!buf) {
		pr_err("[sysctl pmbus]read pmbus error, buf is NULL\n");
		return ERR_PARAM;
	}

	*buf = temp;

	return 0;
}

int sysctl_cpu_voltage_password_cfg (u8 chip_id, u32 slave_addr)
{
	static void __iomem *base;

	if (CHIP_ID_NUM_MAX <= chip_id) {
		pr_err("[sysctl pmbus]read chip_id range[0x0-0x3]is err!\n");
		return ERR_PARAM;
	}

	base = hip_hllc_priv.pm_base[chip_id];

	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (2 << 8) | slave_addr);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, 0x27);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, 0x7c);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (4 << 8) | 0xb3);

	return 0;
}

int hi_vrd_info_get (u8 chip_id, u8 addr, u8 page, u32 slave_addr, u32 data_len, u32 *buf)
{
	u32 retry_time = 0x10;
	u32 ret = 0;

	if (chip_id >= CHIP_ID_NUM_MAX) {
		pr_err("[sysctl pmbus] read chip_id range[0x0-0x3]is err!\n");
		return ERR_PARAM;
	}

	if (page >= PAGE_NUM_MAX) {
		pr_err("[sysctl pmbus] read page range[0x0-0x6f]is err!\n");
		return ERR_PARAM;
	}

	if (DATA_NUM_MAX < data_len
		|| 0 == data_len) {
		pr_err("[sysctl pmbus] read data len range[0x1-0x4]is err!\n");
		return ERR_PARAM;
	}

	(void)InitPmbus(chip_id);

	/* read val */
	(void)sysctl_pmbus_cfg(chip_id, 0x0, page, slave_addr);
	while (retry_time) {
		ret = sysctl_pmbus_read(chip_id, addr, slave_addr, data_len, buf);
		if (ERR_TIMEOUT != ret)
			break;

		retry_time--;

		udelay((unsigned long)100);
	}

	if (!retry_time) {
		pr_err("[sysctl pmbus] read voltage mode time out!\n");
		(void)DeInitPmbus(chip_id);
		return ERR_TIMEOUT;
	}

	if (!buf) {
		pr_err("[sysctl pmbus]read vrd info error, buf is NULL\n");
		return ERR_PARAM;
	}

	pr_info("read val:0x%x !\n", *buf);

	(void)DeInitPmbus(chip_id);
	return 0;
}

int sysctl_cpu_voltage_read (u8 chip_id, u8 loop, u32 slave_addr)
{
	pmbus_vout_mode vout_mode;
	u32 val = 0;
	u32 ret = 0;

	if (chip_id >= CHIP_ID_NUM_MAX) {
		pr_err("[sysctl pmbus] read chip_id range[0x0-0x3]is err!\n");
		return ERR_PARAM;
	}

	if (loop >= VOL_LOOP_NUM_MAX) {
		pr_err("[sysctl pmbus] read voltage loop range[0x0-0x2]is err!\n");
		return ERR_PARAM;
	}

	/* read voltage mode */
	ret = hi_vrd_info_get (chip_id, 0x20, loop, slave_addr, 0x1, (u32 *)&vout_mode);
	if (ret)
		return ret;

	if (vout_mode.bits.vout_mode_surport != 0x1) {
		pr_err("[sysctl pmbus]Warning: voltage mode is not supported!\n");
	}

	/* read voltage vlave */
	ret = hi_vrd_info_get (chip_id, 0x8b, loop, slave_addr, 0x2, (u32 *)&val);
	if (ret)
		return ret;

	if (vout_mode.bits.vid_table == CPU_VOUT_MODE_VR125) {
		val = 2*((val - 1) * 5 + 250);
	} else if (vout_mode.bits.vid_table == CPU_VOUT_MODE_VR120) {
		val = (val - 1) * 5 + 250;
	} else {
		pr_err("vout mode[0x%x] is err, voltage is invalid!\n", vout_mode.bits.vid_table);
	}

	pr_info("voltage :%dmV!\n", val);

	return 0;
}

int sysctl_cpu_voltage_adjust (u8 chip_id, u8 loop, u32 slave_addr, u32 value)
{
	u32 ret = 0;
	u32 vid;
	pmbus_vout_mode vout_mode;
	void __iomem *base = hip_hllc_priv.pm_base[chip_id];

	if (chip_id >= CHIP_ID_NUM_MAX) {
		pr_err("[sysctl pmbus]read chip_id range[0x0-0x3]is err!\n");
		return ERR_PARAM;
	}

	/* read voltage mode */
	ret = hi_vrd_info_get (chip_id, 0x20, loop, slave_addr, 0x1, (u32 *)&vout_mode);
	if (ret)
		return ret;

	if (vout_mode.bits.vout_mode_surport != 0x1) {
		pr_err("[sysctl pmbus]Warning: voltage mode is not supported!\n");
	}

	if (vout_mode.bits.vid_table == CPU_VOUT_MODE_VR125) {
		vid = (value/2 - 250) / 5 + 1;
	} else if (vout_mode.bits.vid_table == CPU_VOUT_MODE_VR120) {
		vid = (value - 250) / 5 + 1;
	} else {
		pr_err("voltage adjust vout mode[0x%x] is err!\n", vout_mode.bits.vid_table);
		return ERR_FAILED;
	}

	(void)InitPmbus(chip_id);

	(void)sysctl_pmbus_cfg(chip_id, 0x0, 0x3f, slave_addr);
	(void)sysctl_cpu_voltage_password_cfg (chip_id, slave_addr);

	(void)sysctl_pmbus_cfg(chip_id, 0x0, loop, slave_addr);

	his_sysctrl_reg_wr(base, I2C_INTR_RAW_OFFSET, 0x3ffff);

	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (2 << 8) | slave_addr);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, 0x21);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, 0xff & vid);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (4 << 8) | (0xff & (vid >> 8)));

	udelay((unsigned long)100);

	his_sysctrl_reg_wr(base, PMBUS_WR_OPEN_OFFSET, 0x0);
	his_sysctrl_reg_wr(base, AVS_WR_OPEN_OFFSET, 0x0);

	return ERR_OK;

}

int hip_sysctrl_probe(void)
{
	int ret;

	ret = his_hllc_init();

	if (ret != ERR_OK) {
		pr_err("[ERROR] his_hllc_init fail, ret:[0x%x].\n", ret);
		return ret;
	}

	return ERR_OK;
}

int hip_sysctrl_remove(void)
{
	int ret;

	ret = his_hllc_deinit();

	if (ret != ERR_OK) {
		pr_err("[ERROR] his hllc deinit fail, ret:[0x%x].\n", ret);
		return ret;
	}

	return ERR_OK;
}

static int __init his_sysctrl_init(void)
{
	int ret = ERR_OK;

	(void)hip_sysctrl_probe();

	(void)hip_sysctl_local_ras_init();

	pr_info("[INFO] insmod sysctrl success.\n");

	return ret;
}

static void __exit his_sysctrl_exit(void)
{
	(void)hip_sysctrl_remove();

	(void)hip_sysctl_local_ras_exit();

	pr_info("[INFO] rmmod sysctrl success.\n");

	return;
}

EXPORT_SYMBOL(hisi_sysctl_get_hllc_crc_ecc);
EXPORT_SYMBOL(hisi_sysctl_get_hllc_link_status);
EXPORT_SYMBOL(hisi_sysctl_set_hllc_mem_ecc);
EXPORT_SYMBOL(hisi_sysctl_get_hllc_mem_ecc);
EXPORT_SYMBOL(hisi_sysctl_get_ddrc_mem_ecc);
EXPORT_SYMBOL(hisi_sysctl_clr_ddrc_mem_ecc);
EXPORT_SYMBOL(his_hllc_init);
EXPORT_SYMBOL(his_hllc_deinit);
EXPORT_SYMBOL(hip_sysctrl_probe);
EXPORT_SYMBOL(hip_sysctrl_remove);
EXPORT_SYMBOL(sysctl_cpu_voltage_read);
EXPORT_SYMBOL(hi_vrd_info_get);
EXPORT_SYMBOL(sysctl_cpu_voltage_adjust);
EXPORT_SYMBOL(sysctl_pmbus_write);
EXPORT_SYMBOL(sysctl_pmbus_read);
EXPORT_SYMBOL(InitPmbus);
EXPORT_SYMBOL(DeInitPmbus);

module_init(his_sysctrl_init);
module_exit(his_sysctrl_exit);

MODULE_DESCRIPTION("sysctrl for hisillicon platform");
MODULE_VERSION(SYSCTL_DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:hip-sysctl");
