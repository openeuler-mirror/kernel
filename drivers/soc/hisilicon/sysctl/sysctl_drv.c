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
#include "sysctl_pmbus.h"

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#define DEBUG

#define SYSCTL_DRIVER_VERSION "1.9.31.0"

unsigned int g_sysctrl_debug;

/* sysctrl reg base address */
struct his_hllc_priv {
	void __iomem *hllc_base[CHIP_ID_NUM_MAX][HLLC_NUM_MAX];
	void __iomem *pcs_base[CHIP_ID_NUM_MAX][HLLC_NUM_MAX];
	void __iomem *pa_base[CHIP_ID_NUM_MAX];
	void __iomem *ddrc_tb_base[CHIP_ID_NUM_MAX][DDRC_CH_NUM_MAX];
	void __iomem *ddrc_ta_base[CHIP_ID_NUM_MAX][DDRC_CH_NUM_MAX];
};

struct his_hllc_priv g_hip_hllc_priv;

int hisi_sysctl_print_debug(u32 print_debug_en)
{
	if (print_debug_en)
		g_sysctrl_debug = 0x1;
	else
		g_sysctrl_debug = 0x0;

	return 0;
}

u64 get_chip_base(void)
{
	u32 chip_ver;
	void __iomem *chip_ver_addr;
	u64 chip_module_base;

	chip_ver_addr = ioremap(CHIP_VER_BASE, (u64)0x4);
	if (!chip_ver_addr) {
		pr_err("sysctl [ERROR] %s chip_ver_base is error.\n", __func__);
		return SYSCTL_ERR_FAILED;
	}

	chip_ver = readl(chip_ver_addr);
	chip_ver = chip_ver>>28; /* bit28 indicates the board type. */
	if (chip_ver == CHIP_VERSION_ES) {
		pr_info("sysctl  [INFO] chip is es\n");
		chip_module_base = HLLC_CHIP_MODULE_ES;
	} else {
		chip_module_base = HLLC_CHIP_MODULE_CS;
		pr_info("sysctl [INFO] chip is cs\n");
	}

	iounmap((void *)chip_ver_addr);

	pr_info("sysctl [INFO] chip ver=%x\n", chip_ver);

	return chip_module_base;
}

int his_hllc_init(void)
{
	u32 hllc_num;
	u32 chip_id;
	u32 ddrc_num;
	u64 addr;
	u64 chip_module_base;

	pr_info("[INFO] %s start.\n", __func__);

	chip_module_base = get_chip_base();

	for (chip_id = 0; chip_id < CHIP_ID_NUM_MAX; chip_id++) {
		for (hllc_num = 0; hllc_num < HLLC_NUM_MAX; hllc_num++) {
			addr = (u64)chip_id * chip_module_base + HLLC0_REG_BASE + (u64)hllc_num * 0x10000;
			g_hip_hllc_priv.hllc_base[chip_id][hllc_num] = ioremap(addr, (u64)0x10000);
			if (!g_hip_hllc_priv.hllc_base[chip_id][hllc_num])
				pr_err("chip=%u, hllc=%u, hllc ioremap failed\n", chip_id, hllc_num);

			addr = (u64)chip_id * chip_module_base + PCS0_REG_BASE + (u64)hllc_num * 0x10000;
			g_hip_hllc_priv.pcs_base[chip_id][hllc_num] = ioremap(addr, (u64)0x10000);
			if (!g_hip_hllc_priv.pcs_base[chip_id][hllc_num])
				pr_err("chip=%u, hllc=%u, pcs ioremap failed\n", chip_id, hllc_num);
		}

		addr = (u64)chip_id * chip_module_base + PA_REG_BASE;
		g_hip_hllc_priv.pa_base[chip_id] = ioremap(addr, (u64)0x10000);
		if (!g_hip_hllc_priv.pa_base[chip_id])
			pr_err("chip=%u, pa ioremap failed\n", chip_id);

		for (ddrc_num = 0; ddrc_num < DDRC_CH_NUM_MAX; ddrc_num++) {
			addr = (u64)chip_id * chip_module_base + DDRC0_TB_REG_BASE + (u64)ddrc_num * 0x10000;
			g_hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_num] = ioremap(addr, (u64)0x10000);
			if (!g_hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_num])
				pr_err("chip=%u,ddr_ch=%u ddrc tb ioremap failed\n", chip_id, ddrc_num);

			addr = (u64)chip_id * chip_module_base + DDRC0_TA_REG_BASE + (u64)ddrc_num * 0x10000;
			g_hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_num] = ioremap(addr, (u64)0x10000);
			if (!g_hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_num])
				pr_err("chip=%u,ddr_ch=%u ddrc ta ioremap failed\n", chip_id, ddrc_num);
		}

	}

	return SYSCTL_ERR_OK;
}

int his_hllc_deinit(void)
{
	u8 chip_id;
	u8 hllc_num;
	u8 ddrc_num;

	for (chip_id = 0; chip_id < CHIP_ID_NUM_MAX; chip_id++) {
		for (hllc_num = 0; hllc_num < HLLC_NUM_MAX; hllc_num++) {
			if (g_hip_hllc_priv.hllc_base[chip_id][hllc_num])
				iounmap((void *)g_hip_hllc_priv.hllc_base[chip_id][hllc_num]);

			if (g_hip_hllc_priv.pcs_base[chip_id][hllc_num])
				iounmap((void *)g_hip_hllc_priv.pcs_base[chip_id][hllc_num]);
		}

		if (g_hip_hllc_priv.pa_base[chip_id])
			iounmap((void *)g_hip_hllc_priv.pa_base[chip_id]);

		for (ddrc_num = 0; ddrc_num < DDRC_CH_NUM_MAX; ddrc_num++) {
			if (g_hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_num])
				iounmap((void *)g_hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_num]);

			if (g_hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_num])
				iounmap((void *)g_hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_num]);
		}
	}

	return SYSCTL_ERR_OK;
}

int hisi_sysctl_get_intlv_mode_cfg(u8 chip_id, u8 *intlv_mode_cfg)
{
	pa_u_global_cfg pa_global_cfg;
	void __iomem *addr;
	int ret = 0;

	debug_sysctrl_print("%s: begin\n", __func__);

	if (intlv_mode_cfg == NULL)
		return SYSCTL_ERR_PARAM;

	if (chip_id >= CHIP_ID_NUM_MAX)
		return SYSCTL_ERR_PARAM;

	/* set the PLL0 slow */
	if (g_hip_hllc_priv.pa_base[chip_id] == NULL) {
		pr_err("%s: g_hip_hllc_priv.pa_base[%u] is NULL.\n", __func__, chip_id);
		return SYSCTL_ERR_FAULT;
	}

	addr = g_hip_hllc_priv.pa_base[chip_id] + PA_PA_GLOBAL_CFG_REG;
	pa_global_cfg.u32 = readl(addr);

	debug_sysctrl_print("addr:%pK, val:0x%x.\n", addr, pa_global_cfg.u32);

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
		return SYSCTL_ERR_PARAM;

	switch (intlv_mode_cfg & 0x7) {
	case HLLC_INTLV_MODE_2PX8:
		if (g_hip_hllc_priv.pa_base[chip_id] == NULL) {
			pr_err("%s: g_hip_hllc_priv.pa_base[%u] is NULL.\n", __func__, chip_id);
			return SYSCTL_ERR_FAULT;
		}

		addr = g_hip_hllc_priv.pa_base[chip_id] + PA_PA_GLOBAL_CFG_REG;
		pa_global_cfg.u32 = readl(addr);

		debug_sysctrl_print("addr:%pK, val:0x%x.\n", addr, pa_global_cfg.u32);

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
		debug_sysctrl_print("intlv_mode_cfg[0x%x] is err\n", intlv_mode_cfg);
		ret = SYSCTL_ERR_FAILED;
		break;
	}

	debug_sysctrl_print("hllc_eanble_cfg is 0x%x.\n.", *hllc_eanble_cfg);

	debug_sysctrl_print("%s: end\n", __func__);
	return ret;
}

int hisi_sysctl_clr_hllc_ecc(u8 chip_id, u8 hllc_id, u32 ecc_clr)
{
	void __iomem *addr;

	debug_sysctrl_print("%s: begin\n", __func__);

	if ((chip_id >= CHIP_ID_NUM_MAX) || (hllc_id >= HLLC_NUM_MAX))
		return SYSCTL_ERR_PARAM;

	debug_sysctrl_print("clr_hllc_ecc:chip_id[0x%x], hllc_id[0x%x].\n", chip_id, hllc_id);

	if (g_hip_hllc_priv.hllc_base[chip_id][hllc_id] == NULL) {
		pr_err("%s: g_hip_hllc_priv.hllc_base[%u][%u] is NULL.\n", __func__, chip_id, hllc_id);
		return SYSCTL_ERR_FAULT;
	}

	/* hllc clr ecc */
	addr = g_hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_REGS_HLLC_CNT_CLR_REG;

	writel(ecc_clr & 0x1, addr);

	return SYSCTL_ERR_OK;
}

int hisi_sysctl_set_hllc_crc_ecc(u8 chip_id, u8 hllc_id, u32 crc_err_times)
{
	void __iomem *addr;
	u32 loop = 0x10000;
	u32 inject_crc_err_done = 0;

	debug_sysctrl_print("%s: begin\n", __func__);

	if ((chip_id >= CHIP_ID_NUM_MAX) ||
		(hllc_id >= HLLC_NUM_MAX) ||
		(crc_err_times == 0))
		return SYSCTL_ERR_PARAM;

	debug_sysctrl_print("set_hllc_crc_ecc:chip_id[0x%x], hllc_id[0x%x], crc_err_times[0x%x].\n",
		chip_id, hllc_id, crc_err_times);

	if (g_hip_hllc_priv.hllc_base[chip_id][hllc_id] == NULL) {
		pr_err("%s: g_hip_hllc_priv.hllc_base[%u][%u] is NULL.\n", __func__, chip_id, hllc_id);
		return SYSCTL_ERR_FAULT;
	}

	/* enable crc ecc */
	addr = g_hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_REGS_HLLC_PHY_TX_INJECT_1BIT_CRC_ERR_EN_REG;
	writel(0x1, addr);
	writel(0x0, addr);

	/* config ecc count */
	addr = g_hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_REGS_HLLC_PHY_TX_INJECT_1BIT_CRC_ERR_TIMES_REG;
	writel(crc_err_times, addr);

	/* check done */
	addr = g_hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_REGS_HLLC_PHY_TX_INJECT_1BIT_CRC_ERR_DONE_REG;
	while (loop) {
		udelay((unsigned long)100); /* Delay 100 subtleties */

		inject_crc_err_done = readl(addr);
		if (inject_crc_err_done & 0x1)
			break;

		loop--;
	}

	if (!loop) {
		pr_err("%s:set hllc crc ecc time out, hllc_base[%u][%u]: %pK.\n",
			__func__, chip_id, hllc_id, g_hip_hllc_priv.hllc_base[chip_id][hllc_id]);
		return SYSCTL_ERR_TIMEOUT;
	}

	debug_sysctrl_print("%s: set_hllc_mem_ecc success\n", __func__);

	return SYSCTL_ERR_OK;
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
		return SYSCTL_ERR_PARAM;

	if (hllc_crc_ecc == NULL)
		return SYSCTL_ERR_PARAM;

	ret = hisi_sysctl_get_intlv_mode_cfg(chip_id, &intlv_mode_cfg);
	if (ret)
		return ret;

	ret = hisi_sysctl_get_hllc_enable_cfg(chip_id, intlv_mode_cfg, &hllc_eanble_cfg);
	if (ret)
		return ret;

	hllc_crc_ecc->hllc_enable = hllc_eanble_cfg;

	for (hllc_num = 0; hllc_num < HLLC_NUM_MAX; hllc_num++) {
		if (g_hip_hllc_priv.hllc_base[chip_id][hllc_num] == NULL) {
			pr_err("%s: g_hip_hllc_priv.hllc_base[%u][%u] is NULL.\n",
				__func__, chip_id, hllc_num);
			return SYSCTL_ERR_FAULT;
		}

		addr = g_hip_hllc_priv.hllc_base[chip_id][hllc_num] + HLLC_HLLC_REGS_HLLC_PHY_RX_FLIT_CRC_ERR_CNT_REG;
		phy_rx_flit_crc_err_cnt = readl(addr);

		debug_sysctrl_print("addr:%pK, crc_err_cnt:0x%x.\n", addr, phy_rx_flit_crc_err_cnt);

		hllc_crc_ecc->hllc_crc_ecc[hllc_num] = phy_rx_flit_crc_err_cnt;
	}

	debug_sysctrl_print("hllc_crc_ecc.hllc_enable:0x%x.\n", hllc_crc_ecc->hllc_enable);

	debug_sysctrl_print("%s: get_hllc_crc_ecc success\n", __func__);

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
		return SYSCTL_ERR_PARAM;

	if (hllc_link_sta == NULL)
		return SYSCTL_ERR_PARAM;

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

		if (g_hip_hllc_priv.pcs_base[chip_id][hllc_num] == NULL) {
			pr_err("%s: g_hip_hllc_priv.pcs_base[%u][%u] is NULL.\n", __func__, chip_id, hllc_num);
			return SYSCTL_ERR_FAULT;
		}

		for (lane_num = 0; lane_num < HLLC_LANE_NUM_MAX; lane_num++) {
			addr = g_hip_hllc_priv.pcs_base[chip_id][hllc_num] \
				+ HLLC_HLLC_PCS_PCS_TX_TRAINING_STS_0_REG + lane_num * 0x4;
			pcs_tx_training_sts.u32 = readl(addr);

			debug_sysctrl_print("addr:%pK, val:0x%x.\n", addr, pcs_tx_training_sts.u32);

			hllc_link_status &= pcs_tx_training_sts.bits.tx_training_succeed;
		}

		hllc_link_sta->bits.hllc_link_status |= hllc_link_status << hllc_num;
	}

	debug_sysctrl_print("hllc_crc_ecc:0x%x.\n", hllc_link_sta->u32);

	debug_sysctrl_print("%s: get_hllc_link_status success\n", __func__);

	return ret;
}

int hisi_sysctl_set_hllc_mem_ecc(u8 chip_id, u8 hllc_id, u8 hllc_ch_bitmap, u8 ecc_err_type)
{
	hllc_regs_u_inject_ecc_type hllc_inject_ecc_type;
	hllc_regs_u_inject_ecc_en hllc_inject_ecc_en;
	void __iomem *addr;

	debug_sysctrl_print("%s: begin\n", __func__);

	if ((chip_id >= CHIP_ID_NUM_MAX) || (hllc_id >= HLLC_NUM_MAX))
		return SYSCTL_ERR_PARAM;

	debug_sysctrl_print("set_hllc_mem_ecc:chip_id[0x%x], hllc_id[0x%x], hllc_ch_bitmap[0x%x], ecc_err_type[0x%x].\n",
		chip_id, hllc_id, hllc_ch_bitmap, ecc_err_type);

	if (g_hip_hllc_priv.hllc_base[chip_id][hllc_id] == NULL) {
		pr_err("%s: g_hip_hllc_priv.hllc_base[%u][%u] is NULL.\n", __func__, chip_id, hllc_id);
		return SYSCTL_ERR_FAULT;
	}

	addr = g_hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_REGS_HLLC_INJECT_ECC_TYPE_REG;
	hllc_inject_ecc_type.u32 = readl(addr);
	hllc_inject_ecc_type.bits.inject_ecc_err_type = ecc_err_type & 0x3;
	writel(hllc_inject_ecc_type.u32, addr);

	debug_sysctrl_print("addr:%pK, val:0x%x.\n", addr, hllc_inject_ecc_type.u32);

	addr = g_hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_REGS_HLLC_INJECT_ECC_EN_REG;
	hllc_inject_ecc_en.u32 = readl(addr);
	hllc_inject_ecc_en.bits.hydra_tx_inject_ecc_err_en = hllc_ch_bitmap & 0x7;
	writel(hllc_inject_ecc_en.u32, addr);

	debug_sysctrl_print("addr:%pK, val:0x%x.\n", addr, hllc_inject_ecc_en.u32);

	debug_sysctrl_print("%s: set_hllc_mem_ecc success\n", __func__);

	return 0;
}

int hisi_sysctl_get_hllc_mem_ecc(u8 chip_id, u8 hllc_id, hllc_mem_ecc_info *hllc_mem_ecc)
{
	hllc_ras_u_err_misc1h hllc_ras_err_misc1h;
	hllc_ras_u_err_misc1l hllc_ras_err_misc1l;
	void __iomem *addr;
	int ret = 0;

	debug_sysctrl_print("%s: begin\n", __func__);

	if ((chip_id >= CHIP_ID_NUM_MAX) ||
		(hllc_id >= HLLC_NUM_MAX) ||
		(hllc_mem_ecc == NULL))
		return SYSCTL_ERR_PARAM;

	debug_sysctrl_print("get_hllc_mem_ecc:chip_id[0x%x], hllc_id[0x%x].\n", chip_id, hllc_id);

	if (g_hip_hllc_priv.hllc_base[chip_id][hllc_id] == NULL) {
		pr_err("%s: g_hip_hllc_priv.hllc_base[%u][%u] is NULL.\n", __func__, chip_id, hllc_id);
		return SYSCTL_ERR_FAULT;
	}

	addr = g_hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_RAS_HLLC_ERR_MISC1H_REG;
	hllc_ras_err_misc1h.u32 = readl(addr);
	hllc_mem_ecc->u32 = hllc_ras_err_misc1h.u32 & 0x7f;
	debug_sysctrl_print("addr:%pK, val:0x%x.\n", addr, hllc_ras_err_misc1h.u32);

	addr = g_hip_hllc_priv.hllc_base[chip_id][hllc_id] + HLLC_HLLC_RAS_HLLC_ERR_MISC1L_REG;
	hllc_ras_err_misc1l.u32 = readl(addr);
	hllc_mem_ecc->u32 |= (hllc_ras_err_misc1l.u32 & 0x7f) << 0x7;
	debug_sysctrl_print("addr:%pK, val:0x%x.\n", addr, hllc_ras_err_misc1l.u32);

	debug_sysctrl_print("hllc_mem_ecc:0x%x.\n", hllc_mem_ecc->u32);

	debug_sysctrl_print("%s: get_hllc_mem_ecc success\n", __func__);

	return ret;
}

int hisi_sysctl_clr_ddrc_mem_ecc(u8 chip_id, u8 totem, u8 ddrc_ch_id, u32 rasc_cfg_clr)
{
	ddrc_rasc_u_cfg_clr ddrc_rasc_cfg_clr;
	void __iomem *addr_ecc_clr;
	int ret = 0;

	debug_sysctrl_print("%s: begin\n", __func__);

	if ((chip_id >= CHIP_ID_NUM_MAX) ||
		(totem >= TOTEM_NUM_MAX) ||
		(ddrc_ch_id >= DDRC_CH_NUM_MAX))
		return SYSCTL_ERR_PARAM;

	debug_sysctrl_print("clr_ddrc_mem_ecc:chip_id[0x%x], totem[0x%x], ddrc_ch_id[0x%x].\n",
		chip_id, totem, ddrc_ch_id);

	if (totem == TOTEM_TA_NUM) {
		if (g_hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_ch_id] == NULL) {
			pr_err("%s: g_hip_hllc_priv.ddrc_ta_base[%u][%u] is NULL.\n",
				__func__, chip_id, ddrc_ch_id);
			return SYSCTL_ERR_FAULT;
		}

		addr_ecc_clr = g_hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_ch_id] + DDRC_RASC_RASC_CFG_CLR_REG;
	} else {
		if (g_hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_ch_id] == NULL) {
			pr_err("%s: g_hip_hllc_priv.ddrc_tb_base[%u][%u] is NULL.\n",
				__func__, chip_id, ddrc_ch_id);
			return SYSCTL_ERR_FAULT;
		}

		addr_ecc_clr = g_hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_ch_id] + DDRC_RASC_RASC_CFG_CLR_REG;
	}

	ddrc_rasc_cfg_clr.u32 = rasc_cfg_clr;
	writel(ddrc_rasc_cfg_clr.u32, addr_ecc_clr);

	debug_sysctrl_print("addr:%pK, val:0x%x.\n", addr_ecc_clr, ddrc_rasc_cfg_clr.u32);

	return ret;
}

static int calc_ddrc_mem_reg_addr(u8 chip_id, u8 totem, u8 ddrc_ch_id,
	void __iomem **addr_ecc_cnt, void __iomem **addr_ecc_cfg_info_rnk, void __iomem **addr_ecc_cfg_ecc)
{
	if (totem == TOTEM_TA_NUM) {
		if (g_hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_ch_id] == NULL) {
			pr_err("%s: g_hip_hllc_priv.ddrc_ta_base[%u][%u] is NULL.\n",
				__func__, chip_id, ddrc_ch_id);
			return SYSCTL_ERR_FAULT;
		}

		*addr_ecc_cfg_info_rnk = g_hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_ch_id] + DDRC_RASC_RASC_CFG_INFO_RNK_REG;
		*addr_ecc_cnt = g_hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_ch_id] + DDRC_RASC_RASC_HIS_HA_RANKCNT_INF_REG;
		*addr_ecc_cfg_ecc = g_hip_hllc_priv.ddrc_ta_base[chip_id][ddrc_ch_id] + DMC_DMC_DDRC_CFG_ECC_REG;
	} else {
		if (g_hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_ch_id] == NULL) {
			pr_err("%s: g_hip_hllc_priv.ddrc_tb_base[%u][%u] is NULL.\n",
				__func__, chip_id, ddrc_ch_id);
			return SYSCTL_ERR_FAULT;
		}

		*addr_ecc_cfg_info_rnk = g_hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_ch_id] + DDRC_RASC_RASC_CFG_INFO_RNK_REG;
		*addr_ecc_cnt = g_hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_ch_id] + DDRC_RASC_RASC_HIS_HA_RANKCNT_INF_REG;
		*addr_ecc_cfg_ecc = g_hip_hllc_priv.ddrc_tb_base[chip_id][ddrc_ch_id] + DMC_DMC_DDRC_CFG_ECC_REG;
	}
	debug_sysctrl_print("addr_ecc_cfg_info_rnk:%pK.\n", addr_ecc_cfg_info_rnk);

	return SYSCTL_ERR_OK;
}

int hisi_sysctl_get_ddrc_mem_ecc(u8 chip_id, u8 totem, u8 ddrc_ch_id, u8 rank_id, ddrc_mem_ecc_info *ddrc_mem_ecc)
{
	dmc_ddrc_u_cfg_ecc dmc_ddrc_cfg_ecc;
	ddrc_rasc_u_cfg_info_rnk ddrc_rasc_cfg_info_rnk;
	ddrc_rasc_u_his_ha_rankcnt_inf ddrc_rasc_his_ha_rankcnt_inf;
	void __iomem *addr_ecc_cnt;
	void __iomem *addr_ecc_cfg_info_rnk;
	void __iomem *addr_ecc_cfg_ecc;
	int ret;

	debug_sysctrl_print("%s: begin\n", __func__);

	if ((chip_id >= CHIP_ID_NUM_MAX) ||
		(totem >= TOTEM_NUM_MAX) ||
		(ddrc_ch_id >= DDRC_CH_NUM_MAX) ||
		(ddrc_mem_ecc == NULL) ||
		(rank_id >= DDRC_RANK_NUM_MAX))
		return SYSCTL_ERR_PARAM;

	debug_sysctrl_print("get_ddrc_mem_ecc:chip_id[0x%x], totem[0x%x], ddrc_ch_id[0x%x], rank_id[0x%x].\n",
		chip_id, totem, ddrc_ch_id, rank_id);

	ret = calc_ddrc_mem_reg_addr(chip_id, totem, ddrc_ch_id,
		&addr_ecc_cnt, &addr_ecc_cfg_info_rnk, &addr_ecc_cfg_ecc);
	if (ret)
		return ret;

	memset(&ddrc_rasc_cfg_info_rnk, 0, sizeof(ddrc_rasc_u_cfg_info_rnk));
	ddrc_rasc_cfg_info_rnk.bits.idx_rnk = rank_id & 0xf;
	writel(ddrc_rasc_cfg_info_rnk.u32, addr_ecc_cfg_info_rnk);

	ddrc_rasc_his_ha_rankcnt_inf.u32 = readl(addr_ecc_cnt);
	ddrc_mem_ecc->ddrc_mem_secc = ddrc_rasc_his_ha_rankcnt_inf.u32;
	debug_sysctrl_print("addr:%pK, ddrc_serr_cnt.funnel_corr_cnt:0x%x.\n",
		addr_ecc_cnt, ddrc_rasc_his_ha_rankcnt_inf.bits.ha_rnk_funnel_corr_cnt);
	debug_sysctrl_print("addr:%pK, ddrc_serr_cnt.corr_cnt:0x%x.\n",
		addr_ecc_cnt, ddrc_rasc_his_ha_rankcnt_inf.bits.ha_rnk_corr_cnt);

	dmc_ddrc_cfg_ecc.u32 = readl(addr_ecc_cfg_ecc);
	if ((dmc_ddrc_cfg_ecc.u32 & DDRC_ECC_EN) == DDRC_ECC_EN)
		ddrc_mem_ecc->ddrc_mem_secc_en = 0x1;
	else
		ddrc_mem_ecc->ddrc_mem_secc_en = 0x0;

	debug_sysctrl_print("addr:%pK, dmc_ddrc_cfg_ecc:0x%x.\n",
		addr_ecc_cfg_ecc, dmc_ddrc_cfg_ecc.u32);

	debug_sysctrl_print("%s: get_ddrc_mem_ecc success\n", __func__);

	return ret;
}

/* check: hisi_sysctl_get_hllc_crc_ecc */
unsigned long ut_hisi_sysctl_get_hllc_crc_ecc_enable(u8 chip_id)
{
	unsigned int ret;
	hllc_crc_ecc_info hllc_crc_ecc;

	memset(&hllc_crc_ecc, 0, sizeof(hllc_crc_ecc_info));
	ret = hisi_sysctl_get_hllc_crc_ecc(chip_id, &hllc_crc_ecc);
	pr_info("hllc_crc_ecc.hllc_enable:0x%x.\n", hllc_crc_ecc.hllc_enable);

	return ((unsigned long)hllc_crc_ecc.hllc_enable << 32) | ret; /* the upper 32 bits. */
}

unsigned long ut_hisi_sysctl_get_hllc_crc_ecc(u8 chip_id, u32 hllc_id)
{
	unsigned int ret;
	hllc_crc_ecc_info hllc_crc_ecc;

	if (hllc_id >= HLLC_NUM_MAX)
		return SYSCTL_ERR_PARAM; /* the upper 32 bits. */

	memset(&hllc_crc_ecc, 0, sizeof(hllc_crc_ecc_info));
	ret = hisi_sysctl_get_hllc_crc_ecc(chip_id, &hllc_crc_ecc);
	pr_info("hllc_crc_ecc.hllc_crc_ecc[%d]:0x%x.\n", hllc_id, hllc_crc_ecc.hllc_crc_ecc[hllc_id]);

	return ((unsigned long)hllc_crc_ecc.hllc_crc_ecc[hllc_id] << 32) | ret; /* the upper 32 bits. */
}

/* check: hisi_sysctl_get_hllc_link_status */
unsigned long ut_hisi_sysctl_get_hllc_link_enable(u8 chip_id)
{
	unsigned int ret;
	hllc_link_sta_info hllc_link_sta;

	memset(&hllc_link_sta, 0, sizeof(hllc_link_sta_info));
	ret = hisi_sysctl_get_hllc_link_status(chip_id, &hllc_link_sta);
	pr_info("hllc_link_sta.bits.hllc_enable:0x%x.\n", hllc_link_sta.bits.hllc_enable);

	return ((unsigned long)hllc_link_sta.bits.hllc_enable << 32) | ret; /* the upper 32 bits. */
}

unsigned long ut_hisi_sysctl_get_hllc_link_status(u8 chip_id)
{
	unsigned int ret;
	hllc_link_sta_info hllc_link_sta;

	memset(&hllc_link_sta, 0, sizeof(hllc_link_sta_info));
	ret = hisi_sysctl_get_hllc_link_status(chip_id, &hllc_link_sta);
	pr_info("hllc_link_sta.bits.hllc_link_status:0x%x.\n", hllc_link_sta.bits.hllc_link_status);

	return ((unsigned long)hllc_link_sta.bits.hllc_link_status << 32) | ret; /* the upper 32 bits. */
}

/* check: hisi_sysctl_get_hllc_mem_ecc */
unsigned long ut_hisi_sysctl_get_hllc_mem_ecc(u8 chip_id, u8 hllc_id)
{
	unsigned int ret;
	hllc_mem_ecc_info hllc_mem_ecc;

	memset(&hllc_mem_ecc, 0, sizeof(hllc_mem_ecc_info));
	ret = hisi_sysctl_get_hllc_mem_ecc(chip_id, hllc_id, &hllc_mem_ecc);
	pr_info("hllc_mem_ecc.u32:0x%x.\n", hllc_mem_ecc.u32);

	return ((unsigned long)hllc_mem_ecc.u32 << 32) | ret; /* the upper 32 bits. */
}

/* check: hisi_sysctl_get_ddrc_mem_ecc */
unsigned long ut_hisi_sysctl_get_ddrc_mem_secc_en(u8 chip_id, u8 totem, u8 ddrc_ch_id, u8 rank_id)
{
	unsigned int ret;
	ddrc_mem_ecc_info ddrc_mem_ecc;

	memset(&ddrc_mem_ecc, 0, sizeof(ddrc_mem_ecc_info));
	ret = hisi_sysctl_get_ddrc_mem_ecc(chip_id, totem, ddrc_ch_id, rank_id, &ddrc_mem_ecc);
	pr_info("ddrc_mem_ecc.ddrc_mem_secc_en:0x%x.\n", ddrc_mem_ecc.ddrc_mem_secc_en);

	return ((unsigned long)ddrc_mem_ecc.ddrc_mem_secc_en << 32) | ret; /* the upper 32 bits. */
}

unsigned long ut_hisi_sysctl_get_ddrc_mem_secc(u8 chip_id, u8 totem, u8 ddrc_ch_id, u8 rank_id)
{
	unsigned int ret;
	ddrc_mem_ecc_info ddrc_mem_ecc;

	memset(&ddrc_mem_ecc, 0, sizeof(ddrc_mem_ecc_info));
	ret = hisi_sysctl_get_ddrc_mem_ecc(chip_id, totem, ddrc_ch_id, rank_id, &ddrc_mem_ecc);
	pr_info("ddrc_mem_ecc.ddrc_mem_secc:0x%x.\n", ddrc_mem_ecc.ddrc_mem_secc);

	return ((unsigned long)ddrc_mem_ecc.ddrc_mem_secc << 32) | ret; /* the upper 32 bits. */
}

unsigned long ut_hisi_sysctl_get_ddrc_mem_mecc(u8 chip_id, u8 totem, u8 ddrc_ch_id, u8 rank_id)
{
	unsigned int ret;
	ddrc_mem_ecc_info ddrc_mem_ecc;

	memset(&ddrc_mem_ecc, 0, sizeof(ddrc_mem_ecc_info));
	ret = hisi_sysctl_get_ddrc_mem_ecc(chip_id, totem, ddrc_ch_id, rank_id, &ddrc_mem_ecc);
	pr_info("ddrc_mem_ecc.ddrc_mem_mecc:0x%x.\n", ddrc_mem_ecc.ddrc_mem_mecc);

	return ((unsigned long)ddrc_mem_ecc.ddrc_mem_mecc << 32) | ret; /* the upper 32 bits. */
}

int hip_sysctrl_probe(void)
{
	int ret;

	ret = his_hllc_init();

	if (ret != SYSCTL_ERR_OK) {
		pr_err("[ERROR] his_hllc_init fail, ret:[0x%x].\n", ret);
		return ret;
	}

	return SYSCTL_ERR_OK;
}

int hip_sysctrl_remove(void)
{
	int ret;

	ret = his_hllc_deinit();

	if (ret != SYSCTL_ERR_OK) {
		pr_err("[ERROR] his hllc deinit fail, ret:[0x%x].\n", ret);
		return ret;
	}

	return SYSCTL_ERR_OK;
}

static int __init his_sysctrl_init(void)
{
	int ret = SYSCTL_ERR_OK;

	(void)hip_sysctl_pmbus_init();
	(void)hip_sysctrl_probe();
	(void)hip_sysctl_local_ras_init();

	pr_info("[INFO] insmod sysctrl success.\n");

	return ret;
}

static void __exit his_sysctrl_exit(void)
{
	(void)hip_sysctl_pmbus_exit();
	(void)hip_sysctrl_remove();
	(void)hip_sysctl_local_ras_exit();

	pr_info("[INFO] rmmod sysctrl success.\n");
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

module_init(his_sysctrl_init);
module_exit(his_sysctrl_exit);

MODULE_DESCRIPTION("sysctrl for hisilicon platform");
MODULE_VERSION(SYSCTL_DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:hip-sysctl");
