// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2013 Linaro Ltd.
 * Copyright (c) 2013 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
#include "dw_mmc_hisi.h"

#ifdef CONFIG_HISI_BOOTDEVICE
#include <linux/bootdevice.h>
#endif
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/sd.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/host.h>

#include <linux/slab.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/pinctrl/consumer.h>
#include <linux/regulator/consumer.h>
#include <linux/of_address.h>
#include <linux/pm_runtime.h>
#include <linux/clk-provider.h>
#include <linux/hwspinlock.h>

#include "dw_mmc.h"
#include "dw_mmc-pltfm.h"
#include "hisi_mmc_pmic.h"
#include "dw_mmc_extern.h"

/* Common flag combinations */
#define DW_MCI_DATA_ERROR_FLAGS (SDMMC_INT_DRTO | SDMMC_INT_DCRC | \
				SDMMC_INT_HTO | SDMMC_INT_SBE  | \
				SDMMC_INT_EBE)
#define DW_MCI_CMD_ERROR_FLAGS  (SDMMC_INT_RTO | SDMMC_INT_RCRC | \
				SDMMC_INT_RESP_ERR)
#define DW_MCI_ERROR_FLAGS      (DW_MCI_DATA_ERROR_FLAGS | \
				DW_MCI_CMD_ERROR_FLAGS  | SDMMC_INT_HLE)


void __iomem *peri_subctrl_base;
void __iomem *sys_base;

static unsigned long hs_dwmmc_reg[CHIP_TYPE_MAX_NUM][REG_MAX_NUM] = {
	{
		HIXX10_PERI_SC_EMMC_RST_REQ,
		HIXX10_PERI_SC_EMMC_RST_DREQ,
		HIXX10_PERI_SC_EMMC_ICG_EN,
		HIXX10_PERI_SC_EMMC_ICG_DIS,
		HIXX10_PERI_SC_EMMC_CLK_SEL,
		HIXX10_SC_BIAS_CTRL,
		HIXX10_SC_PLL_PROF_CFG0,
	}, {
		HIXX51_PERI_SC_EMMC_RST_REQ,
		HIXX51_PERI_SC_EMMC_RST_DREQ,
		HIXX51_PERI_SC_EMMC_ICG_EN,
		HIXX51_PERI_SC_EMMC_ICG_DIS,
		HIXX51_PERI_SC_EMMC_CLK_SEL,
		HIXX51_SC_BIAS_CTRL,
		HIXX51_SC_PLL_PROF_CFG0,
		HIXX51_SC_USER1_EMMC,
		HIXX51_SC_AXI_EMMC,
	}
};

static unsigned long hs_dwmmc_caps[];

static const u8 tuning_blk_pattern_4bit[] = {
	0xff, 0x0f, 0xff, 0x00, 0xff, 0xcc, 0xc3, 0xcc,
	0xc3, 0x3c, 0xcc, 0xff, 0xfe, 0xff, 0xfe, 0xef,
	0xff, 0xdf, 0xff, 0xdd, 0xff, 0xfb, 0xff, 0xfb,
	0xbf, 0xff, 0x7f, 0xff, 0x77, 0xf7, 0xbd, 0xef,
	0xff, 0xf0, 0xff, 0xf0, 0x0f, 0xfc, 0xcc, 0x3c,
	0xcc, 0x33, 0xcc, 0xcf, 0xff, 0xef, 0xff, 0xee,
	0xff, 0xfd, 0xff, 0xfd, 0xdf, 0xff, 0xbf, 0xff,
	0xbb, 0xff, 0xf7, 0xff, 0xf7, 0x7f, 0x7b, 0xde,
};

static const u8 tuning_blk_pattern_8bit[] = {
	0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00,
	0xff, 0xff, 0xcc, 0xcc, 0xcc, 0x33, 0xcc, 0xcc,
	0xcc, 0x33, 0x33, 0xcc, 0xcc, 0xcc, 0xff, 0xff,
	0xff, 0xee, 0xff, 0xff, 0xff, 0xee, 0xee, 0xff,
	0xff, 0xff, 0xdd, 0xff, 0xff, 0xff, 0xdd, 0xdd,
	0xff, 0xff, 0xff, 0xbb, 0xff, 0xff, 0xff, 0xbb,
	0xbb, 0xff, 0xff, 0xff, 0x77, 0xff, 0xff, 0xff,
	0x77, 0x77, 0xff, 0x77, 0xbb, 0xdd, 0xee, 0xff,
	0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00,
	0x00, 0xff, 0xff, 0xcc, 0xcc, 0xcc, 0x33, 0xcc,
	0xcc, 0xcc, 0x33, 0x33, 0xcc, 0xcc, 0xcc, 0xff,
	0xff, 0xff, 0xee, 0xff, 0xff, 0xff, 0xee, 0xee,
	0xff, 0xff, 0xff, 0xdd, 0xff, 0xff, 0xff, 0xdd,
	0xdd, 0xff, 0xff, 0xff, 0xbb, 0xff, 0xff, 0xff,
	0xbb, 0xbb, 0xff, 0xff, 0xff, 0x77, 0xff, 0xff,
	0xff, 0x77, 0x77, 0xff, 0x77, 0xbb, 0xdd, 0xee,
};

static int hs_timing_config[][TUNING_INIT_TIMING_MODE][TUNING_INIT_CONFIG_NUM] = {
	/* bus_clk,    div, drv_phase, sam_dly, */
	/* sam_phase_max, sam_phase_min, input_clk */
	{ /*MMC*/
		{3200000, 7, 7, 0, 15, 15, 400000},	/* 0: LEGACY 400k */
		{400000000, 7, 6, 0, 15, 15, 50000000},	/* 1: MMC_HS */
		{200000000, 7, 6, 0, 15, 15, 25000000},	/* 2: SD_HS */
		{200000000, 7, 6, 0, 15, 15, 25000000},	/* 3: SDR12 */
		{400000000, 7, 6, 0, 15, 15, 50000000},	/* 4: SDR25 */
		{800000000, 7, 4, 0, 12, 0, 100000000},	/* 5: SDR50 */
		{1600000000, 7, 5, 4, 15, 0, 200000000},/* 6: SDR104 */
		{800000000, 7, 6, 0, 7, 0, 100000000},	/* 7: DDR50 */
		{800000000, 7, 6, 0, 7, 0, 100000000},	/* 8: DDR52 */
		{1600000000, 7, 5, 4, 15, 0, 200000000},/* 9: HS200 */
	},
	{ /*SD*/
		{3200000, 7, 7, 0, 15, 15, 400000},	/* 0: LEGACY 400k */
		{0},					/* 1: MMC_HS */
		{400000000, 7, 6, 0, 1, 1, 50000000},	/* 2: SD_HS */
		{200000000, 7, 6, 0, 15, 15, 25000000},	/* 3: SDR12 */
		{400000000, 7, 6, 0, 1, 1, 50000000},	/* 4: SDR25 */
		{800000000, 7, 3, 0, 12, 0, 100000000},	/* 5: SDR50 */
		{1600000000, 7, 5, 4, 15, 0, 200000000},/* 6: SDR104 */
		{0},					/* 7: DDR50 */
		{0},					/* 8: DDR52 */
		{0},					/* 9: HS200 */
	},
	{ /*SDIO*/
		{3200000, 7, 7, 0, 15, 15, 400000},	/* 0: LEGACY 400k */
		{0},					/* 1: MMC_HS */
		{400000000, 7, 6, 0, 15, 15, 50000000},	/* 2: SD_HS */
		{200000000, 7, 6, 0, 15, 15, 25000000},	/* 3: SDR12 */
		{400000000, 7, 6, 0, 15, 15, 50000000},	/* 4: SDR25 */
		{800000000, 7, 5, 0, 12, 0, 100000000},	/* 5: SDR50 */
		{1600000000, 7, 5, 4, 15, 0, 200000000},/* 6: SDR104 */
		{0},					/* 7: DDR50 */
		{0},					/* 8: DDR52 */
		{0},					/* 9: HS200 */
	}
};

static int hs_timing_config_kirin970[][TUNING_INIT_TIMING_MODE][TUNING_INIT_CONFIG_NUM] = {
	/* bus_clk, div, drv_phase, sam_dly, */
	/* sam_phase_max, sam_phase_min, input_clk */
	{ /*MMC*/
		{3200000, 7, 7, 0, 15, 15, 400000},	/* 0: LEGACY 400k */
		/* 1: MMC_HS */ /* ES 400M, 8div 50M */
		{480000000, 9, 6, 0, 1, 1, 48000000},
		{200000000, 7, 6, 0, 15, 15, 25000000},	/* 2: SD_HS */
		{200000000, 7, 6, 0, 15, 15, 25000000},	/* 3: SDR12 */
		{400000000, 7, 6, 0, 15, 15, 50000000},	/* 4: SDR25 */
		{800000000, 7, 4, 0, 12, 0, 100000000},	/* 5: SDR50 */
		{1600000000, 7, 5, 4, 15, 0, 200000000},/* 6: SDR104 */
		{800000000, 7, 6, 0, 7, 0, 100000000},	/* 7: DDR50 */
		{800000000, 7, 6, 0, 7, 0, 100000000},	/* 8: DDR52 */
		{800000000, 7, 5, 0, 15, 0, 100000000},	/* 9: HS200 */

	},
	{ /*SD*/
		{3200000, 7, 7, 0, 15, 15, 400000},	/* 0: LEGACY 400k */
		{200000000, 7, 6, 0, 1, 1, 25000000},	/* 1: MMC_HS */
		{400000000, 7, 6, 0, 4, 4, 50000000},	/* 2: SD_HS */
		{200000000, 7, 6, 0, 15, 15, 25000000},	/* 3: SDR12 */
		{400000000, 7, 6, 0, 2, 2, 50000000},	/* 4: SDR25 */
		{800000000, 7, 5, 0, 12, 0, 100000000},	/* 5: SDR50 */
		{1600000000, 7, 5, 4, 15, 0, 200000000},/* 6: SDR104 */
		{0},					/* 7: DDR50 */
		{0},					/* 8: DDR52 */
		{0},					/* 9: HS200 */
	},
	{ /*SDIO*/
		{3200000, 7, 7, 0, 15, 15, 400000},	/* 0: LEGACY 400k */
		{0},					/* 1: MMC_HS */
		{400000000, 7, 6, 0, 15, 15, 50000000},	/* 2: SD_HS */
		{200000000, 7, 6, 0, 15, 15, 25000000},	/* 3: SDR12 */
		{400000000, 7, 6, 0, 1, 1, 50000000},	/* 4: SDR25 */
		{800000000, 7, 2, 0, 12, 0, 100000000},	/* 5: SDR50 */
		{1600000000, 7, 5, 4, 15, 0, 200000000},/* 6: SDR104 */
		{0},					/* 7: DDR50 */
		{0},					/* 8: DDR52 */
		{0},					/* 9: HS200 */
	}
};

static int hs_timing_config_kirin970_cs[][TUNING_INIT_TIMING_MODE][TUNING_INIT_CONFIG_NUM] = {
	/* bus_clk, div, drv_phase, sam_dly, */
	/* sam_phase_max, sam_phase_min, input_clk */
	{ /*MMC*/
		{3200000, 7, 7, 0, 15, 15, 400000},	/* 0: LEGACY 400k */
		/* 1: MMC_HS */ /* ES 400M, 8div 50M */
		{480000000, 9, 6, 0, 1, 1, 48000000},
		{200000000, 7, 6, 0, 15, 15, 25000000},	/* 2: SD_HS */
		{200000000, 7, 6, 0, 15, 15, 25000000},	/* 3: SDR12 */
		{400000000, 7, 6, 0, 15, 15, 50000000},	/* 4: SDR25 */
		{800000000, 7, 4, 0, 12, 0, 100000000},	/* 5: SDR50 */
		{1600000000, 7, 5, 4, 15, 0, 200000000},/* 6: SDR104 */
		{800000000, 7, 6, 0, 7, 0, 100000000},  /* 7: DDR50 */
		{800000000, 7, 6, 0, 7, 0, 100000000},  /* 8: DDR52 */
		/* 9: HS200 */ /* ES 960M, 8div 120M */
		{1920000000, 9, 5, 4, 15, 0, 192000000},
	},
	{ /*SD*/
		{3200000, 7, 7, 0, 19, 19, 400000},	/* 0: LEGACY 400k */
		{240000000, 9, 8, 0, 3, 3, 24000000},	/* 1: MMC_HS */
		{480000000, 9, 7, 0, 4, 4, 48000000},	/* 2: SD_HS */
		{240000000, 9, 8, 0, 19, 19, 24000000},	/* 3: SDR12 */
		{480000000, 9, 7, 0, 3, 3, 48000000},	/* 4: SDR25 */
		{960000000, 9, 4, 0, 16, 0, 96000000},	/* 5: SDR50 */
		{1920000000, 9, 6, 4, 19, 0, 192000000},/* 6: SDR104 */
		{0},					/* 7: DDR50 */
		{0},					/* 8: DDR52 */
		{0},					/* 9: HS200 */
	},
	{ /*SDIO*/
		{3200000, 7, 7, 0, 19, 19, 400000},	/* 0: LEGACY 400k */
		{0},					/* 1: MMC_HS */
		{480000000, 9, 7, 0, 19, 19, 48000000},	/* 2: SD_HS */
		{240000000, 9, 8, 0, 19, 19, 24000000},	/* 3: SDR12 */
		{480000000, 9, 7, 0, 19, 19, 48000000},	/* 4: SDR25 */
		{960000000, 9, 4, 0, 16, 0,  96000000},	/* 5: SDR50 */
		{1920000000, 9, 5, 4, 19, 0, 192000000},/* 6: SDR104 */
		{0},					/* 7: DDR50 */
		{0},					/* 8: DDR52 */
		{0},					/* 9: HS200 */
	}
};

static int check_himntn(int feature)
{
	return 0;
}


static void dw_mci_hs_set_timing(struct dw_mci *host,
	int id, int timing, int sam_phase, int clk_div)
{
	int cclk_div;
	int drv_phase;
	int sam_dly;
	int sam_phase_max, sam_phase_min;
	int sam_phase_val;
	int reg_value;
	int enable_shift = 0;
	int use_sam_dly = 0;
	int d_value = 0;
	struct dw_mci_slot *slot = host->cur_slot;

	if ((host->hw_mmc_id == DWMMC_SD_ID) && (timing == MMC_TIMING_LEGACY))
		cclk_div = hs_timing_config[id][timing][1];
	else
		cclk_div = clk_div;
	if (host->hw_mmc_id == DWMMC_SD_ID)
		d_value = cclk_div - hs_timing_config[id][timing][1];
	drv_phase = hs_timing_config[id][timing][2];
	sam_dly = hs_timing_config[id][timing][3] + d_value;
	sam_phase_max = hs_timing_config[id][timing][4] + 2 * d_value;
	sam_phase_min = hs_timing_config[id][timing][5];

	if (sam_phase == -1)
		sam_phase_val = (sam_phase_max + sam_phase_min) / 2;
	else
		sam_phase_val = sam_phase;

	/* enable_shift and use_sam_dly setting code */
	/* warning! different with K3V3 */
	switch (id) {
	case DW_MCI_EMMC_ID:
		switch (timing) {
		case MMC_TIMING_UHS_DDR50:
			if (sam_phase_val >= 4 && sam_phase_val <= 12)
				enable_shift = 1;
			break;
		case MMC_TIMING_MMC_HS200:
			if (sam_phase_val >= 4 && sam_phase_val <= 12)
				enable_shift = 1;
			if (sam_phase_val >= 11 && sam_phase_val <= 14)
				use_sam_dly = 1;
			break;
		}
		break;
	case DW_MCI_SD_ID:
		switch (timing) {
		case MMC_TIMING_UHS_SDR50:
			if (4 + d_value <= sam_phase_val &&
				sam_phase_val <= 12 + d_value)
				enable_shift = 1;
			break;
		case MMC_TIMING_UHS_SDR104:
			if (11 + 2 * d_value <= sam_phase_val &&
				sam_phase_val <= 14 + 2 * d_value)
				use_sam_dly = 1;
			if (4 + d_value <= sam_phase_val &&
				sam_phase_val <= 12 + d_value)
				enable_shift = 1;
			break;
		}
		break;
	case DW_MCI_SDIO_ID:
		switch (timing) {
		case MMC_TIMING_UHS_SDR12:
			break;
		case MMC_TIMING_UHS_DDR50:
			if (sam_phase_val >= 4 && sam_phase_val <= 12)
				enable_shift = 1;
			break;
		case MMC_TIMING_UHS_SDR50:
			if (sam_phase_val >= 4 && sam_phase_val <= 12)
				enable_shift = 1;
			break;
		case MMC_TIMING_UHS_SDR104:
			if (host->wifi_sdio_sdr104_160M == 0xaaaa) {
				if (sam_phase_val >= 15 && sam_phase_val <= 18)
					use_sam_dly = 1;
			} else if (host->wifi_sdio_sdr104_177M == 0xaaaa) {
				if (sam_phase_val >= 13 && sam_phase_val <= 16)
					use_sam_dly = 1;
			} else {
				if (sam_phase_val >= 11 && sam_phase_val <= 14)
					use_sam_dly = 1;
			}
			if (sam_phase_val >= 4 && sam_phase_val <= 12)
				enable_shift = 1;
			break;
		}
		break;
	}

	/* first disabl clk */
	mci_writel(host, GPIO, 0x0);
	udelay(5);

	reg_value = SDMMC_UHS_REG_EXT_VALUE(sam_phase_val, sam_dly, drv_phase);
	mci_writel(host, UHS_REG_EXT, reg_value);

	mci_writel(host, ENABLE_SHIFT, enable_shift);

	reg_value = SDMMC_GPIO_VALUE(cclk_div, use_sam_dly);
	mci_writel(host, GPIO, (unsigned int)reg_value | GPIO_CLK_ENABLE);

	if (!(slot && slot->sdio_wakelog_switch))
		dev_info(host->dev, "id=%d,timing=%d,\n", id, timing);
		dev_info(host->dev,
			"UHS_REG_EXT=0x%x, ENABLE_SHIFT=0x%x,GPIO=0x%x\n",
			mci_readl(host, UHS_REG_EXT),
			mci_readl(host, ENABLE_SHIFT),
			mci_readl(host, GPIO));
}

#define	SD_HWLOCK_ID	11
#define	SD_LOCK_TIMEOUT	1000
static struct hwspinlock	*sd_hwlock;
static int dw_mci_set_sel18(int chip_type, bool set)
{
	u32 reg;
	unsigned long flag = 0;

	/* hixx51 not support voltage selection */
	if (chip_type == CHIP_HIXX51)
		return 0;

	if ((chip_type >= CHIP_TYPE_MAX_NUM) || (chip_type < 0)) {
		pr_err("chip type error %d!\n", chip_type);
		return -1;
	}

	if (sd_hwlock == NULL)
		return 0;

	if (sys_base == NULL) {
		pr_err("sys_base is null, can't switch 1.8V or 3.0V !\n");
		return -1;
	}

	/*
	 * 1s timeout, if we can't get sd_hwlock,
	 * sd card module will init failed
	 */
	if (hwspin_lock_timeout_irqsave(sd_hwlock, SD_LOCK_TIMEOUT, &flag)) {
		pr_warn("%s: hwspinlock timeout!\n", __func__);
		return 0;
	}

	/*sysctrl offset: 0x3780 bit[1:0], 0x3--1.8v, 0x0--3.3v*/
	reg = readl(sys_base + hs_dwmmc_reg[chip_type][SC_BIAS_CTRL]);
	if (set)
		reg |= 0x3;
	else
		reg &= (~0x3);

	writel(reg, sys_base + hs_dwmmc_reg[chip_type][SC_BIAS_CTRL]);

	hwspin_unlock_irqrestore(sd_hwlock, &flag);
	pr_info(" reg = 0x%x\n", reg);
	return 0;
}

int dw_mci_clk_set_rate(struct dw_mci *host, u32 clk)
{
	u32 reg = 0;
	u32 freq_div_flag = 0;
	u32 pll5_div = 0;
	u32 chip_type;
	struct dw_mci_hs_priv_data *priv = NULL;

	if ((peri_subctrl_base == NULL) ||
		(sys_base == NULL) ||
		(host == NULL)) {
		dev_err(host->dev,
			"peri_subctrl_base or sys_base is null, can't rst!\n"
			);
		return -1;
	}
	priv = host->priv;
	chip_type = priv->chip_type;

	/* peri_subctrl offset: 0x3500 bit[0], 0x1--PLL5(1.6G)   0x0--3.2M */
	reg = readl(peri_subctrl_base +
		hs_dwmmc_reg[chip_type][PERI_SC_EMMC_CLK_SEL]);
	if (clk > PLL5_CLK_DEFAULT_FREQ) {
		reg |= 0x1;
		freq_div_flag = 1;
	} else {
		reg &= ~0x1;
		freq_div_flag = 0;
	}
	writel(reg, peri_subctrl_base +
		hs_dwmmc_reg[chip_type][PERI_SC_EMMC_CLK_SEL]);

	if (freq_div_flag) {
		/* set eMMC level-1 freq divider to 1.6G/div=xxxM, */
		/* sysctrl offset: 0x3688 bit[27:24] = div */
		pll5_div = PLL5_CLK_FREQ_MAX/clk;
		if (pll5_div > PLL5_EMMC_DIV_MAX) {
			dev_warn(host->dev,
				"pll5_div(%d) invalid, max(16)\n", pll5_div);
			pll5_div = PLL5_EMMC_DIV_MAX;
		}

		if (pll5_div > 0)
			pll5_div--;

		/* Hixx51 FPGA B500 not support pll configure */
		if (priv->chip_type == CHIP_HIXX10) {
			reg = readl(sys_base +
				hs_dwmmc_reg[chip_type][SC_PLL_PROF_CFG0]);
			reg &= 0xf0ffffff;
			reg |= (pll5_div << 24);
			writel(reg, sys_base +
				hs_dwmmc_reg[chip_type][SC_PLL_PROF_CFG0]);
		} else if ((priv->chip_type == CHIP_HIXX51) &&
			(priv->chip_platform == SDMMC_ASIC_PLATFORM)) {
			reg = readl(peri_subctrl_base +
				hs_dwmmc_reg[chip_type][PERI_SC_EMMC_CLK_SEL]);
			reg &= HIXX51_EMMC_CLK_SEL_PLL_OFF;
			reg |= (pll5_div << HIXX51_EMMC_CLK_SEL_PLL_L_S);
			writel(reg, peri_subctrl_base +
				hs_dwmmc_reg[chip_type][PERI_SC_EMMC_CLK_SEL]);
		}
	}

	return 0;
}


static void dw_mci_hs_set_ios_power_off(struct dw_mci *host)
{
	struct dw_mci_hs_priv_data *priv = host->priv;
	int ret;

	dev_info(host->dev, "set io to lowpower\n");
	/* set pin to idle, skip emmc for vccq keeping power always on */
	if ((host->hw_mmc_id == DWMMC_SD_ID) &&
		!(check_himntn(HIMNTN_SD2JTAG) ||
		check_himntn(HIMNTN_SD2DJTAG))) {
		if ((host->pinctrl) && (host->pins_idle)) {
			ret = pinctrl_select_state(host->pinctrl,
				host->pins_idle);
			if (ret)
				dev_warn(host->dev,
					"could not set idle pins\n");
		}
	} else if ((host->hw_mmc_id != DWMMC_EMMC_ID) &&
		(host->hw_mmc_id != DWMMC_SD_ID)) {
		if ((host->pinctrl) && (host->pins_idle)) {
			ret = pinctrl_select_state(host->pinctrl,
				host->pins_idle);
			if (ret)
				dev_warn(host->dev,
					"could not set idle pins\n");
		}
	}

	if (host->vqmmc) {
		ret = regulator_disable(host->vqmmc);
		if (ret)
			dev_warn(host->dev,
				"regulator_disable vqmmc failed\n");
	} else {
		if ((host->hw_mmc_id == DWMMC_SD_ID) &&
			(priv->chip_platform == SDMMC_ASIC_PLATFORM)) {
			ret = pmu_ldo9_disable();
			if (ret)
				dev_warn(host->dev,
					"pmu_ldo9_disable failed\n");
		}
	}

	if (host->vmmc) {
		ret = regulator_disable(host->vmmc);
		if (ret)
			dev_warn(host->dev, "regulator_disable vmmc failed\n");
	} else {
		if ((host->hw_mmc_id == DWMMC_SD_ID) &&
			(priv->chip_platform == SDMMC_ASIC_PLATFORM)) {
			ret = pmu_ldo16_disable();
			if (ret)
				dev_warn(host->dev,
					"pmu_ldo16_disable vmmc failed\n");
		}
	}

}

static void dw_mci_hs_set_ios_power_up(struct dw_mci *host)
{
	struct dw_mci_hs_priv_data *priv = host->priv;
	int ret;

	dev_info(host->dev, "set io to normal\n");
	if (priv->hi3660_fpga_sd_ioset == HI3660_FPGA) {
		/* set GPIO15[0] and GPIO15[1] to outpot */
		/* set GPIO15[0] to High */
		/* set GPIO15[1] to Low */
		(void)gpio_request(
			priv->hi3660_sd_ioset_jtag_sd_sel, "jtag_sd_sel");
		(void)gpio_request(priv->hi3660_sd_ioset_sd_sel, "sd_sel");
		gpio_direction_output(priv->hi3660_sd_ioset_jtag_sd_sel, 0);
		gpio_direction_output(priv->hi3660_sd_ioset_sd_sel, 1);
		dev_info(host->dev, "set Hi3660 FPGA sd io\n");
		gpio_free(priv->hi3660_sd_ioset_jtag_sd_sel);
		gpio_free(priv->hi3660_sd_ioset_sd_sel);
	}
	if (host->hw_mmc_id == DWMMC_SD_ID) {
		ret = dw_mci_set_sel18(priv->chip_type, 0);
		if (ret)
			dev_err(host->dev, " ios dw_mci_set_sel18 error!\n");
		/* Wait for 5ms */
		usleep_range(5000, 5500);
		if (host->vqmmc)
			host->vqmmc = NULL;
		if (host->vmmc)
			host->vmmc = NULL;
		if (host->vqmmc) {
			ret = regulator_set_voltage(
				host->vqmmc, 2950000, 2950000);
			if (ret)
				dev_err(host->dev,
					"regulator_set_voltage failed !\n");
			ret = regulator_enable(host->vqmmc);
			if (ret)
				dev_err(host->dev,
					"regulator_enable failed !\n");
			usleep_range(1000, 1500);
		} else {
			if ((host->hw_mmc_id == DWMMC_SD_ID) &&
				(priv->chip_platform == SDMMC_ASIC_PLATFORM)) {
				ret = pmu_ldo9_set_voltage(2950);
				if (ret)
					dev_err(host->dev,
					"pmu_ldo9_set_voltage failed !\n");

				ret = pmu_ldo9_enable();
				if (ret)
					dev_err(host->dev,
						"pmu_ldo9_enable failed !\n");
				usleep_range(1000, 1500);
			}
		}
		if (host->vmmc) {
			ret = regulator_set_voltage(
				host->vmmc, 2950000, 2950000);
			if (ret)
				dev_err(host->dev,
					"regulator_set_voltage failed !\n");
			ret = regulator_enable(host->vmmc);
			if (ret)
				dev_err(host->dev,
					"regulator_enable failed !\n");
			usleep_range(1000, 1500);
		} else {
			if ((host->hw_mmc_id == DWMMC_SD_ID) &&
				(priv->chip_platform == SDMMC_ASIC_PLATFORM)) {
				ret = pmu_ldo16_set_voltage(2950);
				if (ret)
					dev_err(host->dev,
					"pmu_ldo16_set_voltage failed !\n");
				ret = pmu_ldo16_enable();
				if (ret)
					dev_err(host->dev,
					"pmu_ldo16_enable failed !\n");
				usleep_range(1000, 1500);
			}
		}

		if (!(check_himntn(HIMNTN_SD2JTAG) ||
			check_himntn(HIMNTN_SD2DJTAG))) {
			if ((host->pinctrl) && (host->pins_default)) {
				ret = pinctrl_select_state(host->pinctrl,
					host->pins_default);
				if (ret)
					dev_warn(host->dev,
					"could not set default pins\n");
			}
		}
		return;
	}
	if ((host->pinctrl) && (host->pins_default)) {
		ret = pinctrl_select_state(host->pinctrl, host->pins_default);
		if (ret)
			dev_warn(host->dev, "could not set default pins\n");
	}
	if (host->vmmc) {
		ret = regulator_set_voltage(host->vmmc, 2950000, 2950000);
		if (ret)
			dev_err(host->dev, "regulator_set_voltage failed !\n");

		ret = regulator_enable(host->vmmc);
		if (ret)
			dev_err(host->dev, "regulator_enable failed !\n");
	} else {
		if ((host->hw_mmc_id == DWMMC_SD_ID) &&
			(priv->chip_platform == SDMMC_ASIC_PLATFORM)) {
			ret = pmu_ldo16_set_voltage(2950);
			if (ret)
				dev_err(host->dev,
					"pmu_ldo16_set_voltage failed !\n");

			ret = pmu_ldo16_enable();
			if (ret)
				dev_err(host->dev,
					"pmu_ldo16_enable failed !\n");
		}
	}

	if (host->vqmmc) {
		ret = regulator_set_voltage(host->vqmmc, 2950000, 2950000);
		if (ret)
			dev_err(host->dev, "regulator_set_voltage failed !\n");

		ret = regulator_enable(host->vqmmc);
		if (ret)
			dev_err(host->dev, "regulator_enable failed !\n");
	} else {
		if ((host->hw_mmc_id == DWMMC_SD_ID) &&
			(priv->chip_platform == SDMMC_ASIC_PLATFORM)) {
			ret = pmu_ldo9_set_voltage(2950);
			if (ret)
				dev_err(host->dev,
					"pmu_ldo9_set_voltage failed !\n");

			ret = pmu_ldo9_enable();
			if (ret)
				dev_err(host->dev,
					"pmu_ldo9_enable failed !\n");
		}
	}

}

static void dw_mci_hs_set_ios(struct dw_mci *host, struct mmc_ios *ios)
{
	struct dw_mci_hs_priv_data *priv = host->priv;
	int id = priv->id;
	int ret;


	if (priv->old_power_mode != ios->power_mode) {
		switch (ios->power_mode) {
		case MMC_POWER_OFF:
			dw_mci_hs_set_ios_power_off(host);
			break;
		case MMC_POWER_UP:
			dw_mci_hs_set_ios_power_up(host);
			break;
		case MMC_POWER_ON:
			break;
		default:
			dev_info(host->dev, "unknown power supply mode\n");
			break;
		}
		priv->old_power_mode = ios->power_mode;
	}

	if (priv->old_timing != ios->timing) {
		if (peri_subctrl_base == NULL) {
			dev_err(host->dev, "peri_subctrl_base is null,\n");
			dev_err(host->dev,
				"can't disable and enable clock!\n");
			return;
		}

		/* disable clock for fpga */
		writel(0x1, peri_subctrl_base +
			hs_dwmmc_reg[priv->chip_type][PERI_SC_EMMC_ICG_DIS]);

		ret = dw_mci_clk_set_rate(host,
			hs_timing_config[id][ios->timing][0]);
		if (ret)
			dev_err(host->dev, "dw_mci_clk_set_rate failed\n");

		/* enable clock for fpga */
		writel(0x1, peri_subctrl_base +
			hs_dwmmc_reg[priv->chip_type][PERI_SC_EMMC_ICG_EN]);

		if (priv->in_resume != STATE_KEEP_PWR)
			host->tuning_init_sample =
				(hs_timing_config[id][ios->timing][4] +
				hs_timing_config[id][ios->timing][5]) / 2;

		if (host->sd_reinit == 0)
			host->current_div =
				hs_timing_config[id][ios->timing][1];

		dw_mci_hs_set_timing(host, id, ios->timing,
			host->tuning_init_sample, host->current_div);

		if (priv->priv_bus_hz == 0)
			host->bus_hz = hs_timing_config[id][ios->timing][6];
		else
			host->bus_hz =
				2 * hs_timing_config[id][ios->timing][6];

		if (priv->dw_mmc_bus_clk) {
			/*if FPGA, the clk for SD should be 20M */
			host->bus_hz = priv->dw_mmc_bus_clk;
		}

		priv->old_timing = ios->timing;
	}
}

static void dw_mci_hs_prepare_command(struct dw_mci *host, u32 *cmdr)
{
	*cmdr |= SDMMC_CMD_USE_HOLD_REG;
}

int dw_mci_hs_get_dt_pltfm_resource(struct device_node  *of_node)
{
	if (of_device_is_compatible(of_node, "hisilicon,davinci-dw-mshc")) {
		if (of_find_property(of_node,
			"cs_sd_timing_config", (int *)NULL)) {
			memcpy(hs_timing_config, hs_timing_config_kirin970_cs,
				sizeof(hs_timing_config));
			pr_info("%s: boston_cs_sd_timing_config_cs\n",
				__func__);
			pr_info("%s: is used for timing_config!\n", __func__);
		} else {
			memcpy(hs_timing_config, hs_timing_config_kirin970,
				sizeof(hs_timing_config));
			pr_info("%s: boston_cs_sd_timing_config\n", __func__);
			pr_info("%s: is used for timing_config!\n", __func__);
		}
	} else {
		pr_err("%s: no compatible platform resource found!\n",
			__func__);
		return -1;
	}

	return 0;
}

int dw_mci_hs_get_resource(void)
{
	struct device_node *np = NULL;

	np = of_find_compatible_node(NULL, NULL, "hisilicon,davinci-dw-mshc");
	if (np == NULL) {
		pr_err("can't find davinci-dw-mshc!\n");
		return -EFAULT;
	}

	if (!peri_subctrl_base) {
		peri_subctrl_base = of_iomap(np, MEM_PERI_SUBCTRL_IOBASE);
		if (!peri_subctrl_base) {
			pr_err("peri_subctrl_base iomap error!\n");
			return -ENOMEM;
		}
	}

	if (!sys_base) {
		sys_base = of_iomap(np, MEM_SYSCTRL_IOBASE);
		if (!sys_base) {
			pr_err("sysctrl iomap error!\n");
			iounmap(peri_subctrl_base);
			return -ENOMEM;
		}
	}

	return 0;
}


/*
 * Do private setting specified for controller.
 * dw_mci_hs_priv_init execute before controller unreset,
 * this will cause NOC error.
 * put this function after unreset and clock set.
 */
static void dw_mci_hs_priv_setting(struct dw_mci *host)
{
	/* set threshold to 512 bytes */
	mci_writel(host, CDTHRCTL, 0x02000001);
}

void dw_mci_hs_set_rst_m(struct dw_mci *host, bool set)
{
	struct dw_mci_hs_priv_data *priv = host->priv;
	u32 chip_type = priv->chip_type;
	int id = priv->id;

	if (peri_subctrl_base == NULL) {
		dev_err(host->dev, "peri_subctrl_base is null, can't rst!\n");
		return;
	}

	if (set) {
		if (id == DW_MCI_EMMC_ID) {
			writel(BIT_RST_EMMC, peri_subctrl_base +
				hs_dwmmc_reg[chip_type][PERI_SC_EMMC_RST_REQ]);
			dev_info(host->dev, "reset_m for emmc\n");
		} else if (id == DW_MCI_SD_ID) {
			writel(BIT_RST_SD, peri_subctrl_base +
				hs_dwmmc_reg[chip_type][PERI_SC_EMMC_RST_REQ]);
			dev_info(host->dev, "reset_m for sd\n");
		} else {
			dev_info(host->dev,
				"other reset_m need to add, id : %d\n", id);
		}
	} else {
		if (id == DW_MCI_EMMC_ID) {
			writel(BIT_RST_EMMC, peri_subctrl_base +
				hs_dwmmc_reg[chip_type][PERI_SC_EMMC_RST_DREQ]
				);
			dev_info(host->dev, "unreset_m for emmc\n");
		} else if (id == DW_MCI_SD_ID) {
			writel(BIT_RST_SD, peri_subctrl_base +
				hs_dwmmc_reg[chip_type][PERI_SC_EMMC_RST_DREQ]
				);
			dev_info(host->dev, "unreset_m for sd\n");
		} else {
			dev_info(host->dev,
				"other unreset_m need to add, id : %d\n", id);
		}
	}
}

int dw_mci_hs_set_controller(struct dw_mci *host, bool set)
{
	struct dw_mci_hs_priv_data *priv = host->priv;
	u32 chip_type = priv->chip_type;
	int id = priv->id;

	if (peri_subctrl_base == NULL) {
		dev_err(host->dev,
			"peri_subctrl_base is null, can't reset mmc!\n");
		return -1;
	}

	if (set) {
		/* disable clock for fpga */
		writel(0x1, peri_subctrl_base +
			hs_dwmmc_reg[chip_type][PERI_SC_EMMC_ICG_DIS]);

		if (id == DW_MCI_EMMC_ID) {
			writel(BIT_RST_EMMC, peri_subctrl_base +
				hs_dwmmc_reg[chip_type][PERI_SC_EMMC_RST_REQ]);
			goto out;
		} else if (id == DW_MCI_SD_ID) {
			writel(BIT_RST_SD, peri_subctrl_base +
				hs_dwmmc_reg[chip_type][PERI_SC_EMMC_RST_REQ]);
			goto out;
		} else {
			goto out;
		}
	} else {
		/* enable clock for fpga */
		writel(0x1, peri_subctrl_base +
				hs_dwmmc_reg[chip_type][PERI_SC_EMMC_ICG_EN]);
		dev_info(host->dev, "eMMC/SD clock gate enable\n");

		if (id == DW_MCI_EMMC_ID) {
			writel(BIT_RST_EMMC, peri_subctrl_base +
				hs_dwmmc_reg[chip_type][PERI_SC_EMMC_RST_DREQ]
				);
			goto out;
		} else if (id == DW_MCI_SD_ID) {
			writel(BIT_RST_SD, peri_subctrl_base +
				hs_dwmmc_reg[chip_type][PERI_SC_EMMC_RST_DREQ]
				);
			goto out;
		} else {
			goto out;
		}

	}
out:
	return 0;
}

struct dw_mci *sdio_host;

void dw_mci_sdio_card_detect(struct dw_mci *host)
{
	if (host == NULL) {
		dev_info(host->dev, "sdio detect, host is null,\n");
		dev_info(host->dev, "can not used to detect sdio\n");
		return;
	}

	dw_mci_set_cd(host);

	queue_work(host->card_workqueue, &host->card_work);
	return;
};

void dw_mci_sdio_card_detect_change(void)
{
	dw_mci_sdio_card_detect(sdio_host);
}
EXPORT_SYMBOL(dw_mci_sdio_card_detect_change);

static int dw_mci_hs_priv_device_info(struct dw_mci *host)
{
	struct dw_mci_hs_priv_data *priv = host->priv;

	priv->chip_platform = SDMMC_ASIC_PLATFORM;

	if (of_property_read_u32(host->dev->of_node, "device-type",
		&priv->chip_type)) {
		dev_info(host->dev, "can't find device_type!\n");
		priv->chip_type = CHIP_HIXX10;
	} else {
		if (priv->chip_type >= CHIP_TYPE_MAX_NUM) {
			dev_err(host->dev, "device type %d error!\n",
				priv->chip_type);
			return -EFAULT;
		}
	}

	if (of_find_property(host->dev->of_node, "board_fpga", NULL))
		priv->chip_platform = SDMMC_FPGA_PLATFORM;

	dev_info(host->dev, "chip type %d chip platform %d!\n", priv->chip_type,
		priv->chip_platform);

	return 0;
}

static int dw_mci_hs_init_specific(struct dw_mci *host)
{
	struct platform_device *pdev = NULL;
#ifdef CONFIG_MMC_DW_EMMC_USED_AS_MODEM
	static const char *const hi_mci0 = "hi_mci.3";
#else
	static const char *const hi_mci0 = "hi_mci.0";
#endif
	static const char *const hi_mci1 = "hi_mci.1";
	static const char *const hi_mci2 = "hi_mci.2";
	int error;
	int ret;

	struct dw_mci_hs_priv_data *priv = host->priv;

	/* BUG: device rename krees old name, which would be realloced for */
	/*  other device, pdev->name points to freed space, */
	/*  driver match may cause a panic for wrong device */
	pdev = container_of(host->dev, struct platform_device, dev);

	switch (priv->id) {
	case MMC_EMMC:
		pdev->name = hi_mci0;
		error = device_rename(host->dev, hi_mci0);
		if (error < 0) {
			dev_err(host->dev, "dev set name %s fail\n", hi_mci0);
			goto fail;
		}

		/* Sd hardware lock,avoid to access the SCPERCTRL5 */
		/*  register in USIM card module in the same time */
		sd_hwlock = hwspin_lock_request_specific(SD_HWLOCK_ID);
		if (sd_hwlock == NULL) {
			dev_err(host->dev, "Request hwspin lock failed !\n");
			goto fail;
		}

		ret = dw_mci_set_sel18(priv->chip_type, 1);
		if (ret)
			dev_err(host->dev, " ios dw_mci_set_sel18 error!\n");

#ifndef CONFIG_MMC_DW_EMMC_USED_AS_MODEM
#ifdef CONFIG_HISI_BOOTDEVICE
		if (get_bootdevice_type() == BOOT_DEVICE_EMMC)
			set_bootdevice_name(&pdev->dev);
#endif
#endif
		break;
	case MMC_SD:
		pdev->name = hi_mci1;
		error = device_rename(host->dev, hi_mci1);
		if (error < 0) {
			dev_err(host->dev, "dev set name hi_mci.1 fail\n");
			goto fail;
		}

		/* Sd hardware lock,avoid to access the SCPERCTRL5 */
		/*  register in USIM card module in the same time */
		sd_hwlock = hwspin_lock_request_specific(SD_HWLOCK_ID);
		if (sd_hwlock == NULL) {
			dev_err(host->dev, "Request hwspin lock failed !\n");
			goto fail;
		}

		ret = dw_mci_set_sel18(priv->chip_type, 0);
		if (ret)
			dev_err(host->dev, " ios dw_mci_set_sel18 error!\n");
		break;
	case MMC_SDIO:
		pdev->name = hi_mci2;
		error = device_rename(host->dev, hi_mci2);
		if (error < 0) {
			dev_err(host->dev, "dev set name hi_mci.2 fail\n");
			goto fail;
		}

		break;

	default:
		dev_err(host->dev, "mpriv->id is out of range!!!\n");
		goto fail;
	}
	/* still keep pdev->name same with dev->kobj.name */
	pdev->name = host->dev->kobj.name;
	return 0;

fail:
	/* if rename failed, restore old value, keep pdev->name same to */
	/*  dev->kobj.name */
	pdev->name = host->dev->kobj.name;
	return -1;
}


static int dw_mci_hs_priv_init(struct dw_mci *host)
{
	struct dw_mci_hs_priv_data *priv = NULL;
	u32 reg;
	int ret;

	priv = devm_kzalloc(host->dev, sizeof(*priv), GFP_KERNEL);
	if (priv == NULL)
		return -ENOMEM;
	priv->id = of_alias_get_id(host->dev->of_node, "mshc");
	/* BEGIN masked for davinci, 2018/01/08 */

	/* BEGIN masked for davinci, 2018/01/08 */
	priv->old_timing = -1;
	priv->in_resume = STATE_LEGACY;
	host->priv = priv;
	host->hw_mmc_id = priv->id;
	host->flags &= ~DWMMC_IN_TUNING;
	host->flags &= ~DWMMC_TUNING_DONE;

	/*
	 *  Here for SD, the default value of voltage-switch gpio,
	 *  which is only used in hi3650 FPGA, is set to (-1) for ASIC
	 */
	priv->dw_voltage_switch_gpio = SDMMC_ASIC_PLATFORM;

	ret = dw_mci_hs_priv_device_info(host);
	if (ret) {
		dev_err(host->dev, "device info error!\n");
		return -1;
	}

	/* Hixx51 FPGA B500 not support sysctrl pll configure */
	if ((sys_base != NULL) && (priv->chip_type == CHIP_HIXX10)) {
		/* Set the level-1 frequency divider of the eMMC
		 * to divide by 2. 1.6G/2=800M,
		 * sysctrl offset: 0x3688 bit[27:24] = 1
		 */
		reg = readl(sys_base +
			hs_dwmmc_reg[priv->chip_type][SC_PLL_PROF_CFG0]);
		reg &= 0xf0ffffff;
		reg |= 0x01000000;
		writel(reg, sys_base +
			hs_dwmmc_reg[priv->chip_type][SC_PLL_PROF_CFG0]);
	} else if ((peri_subctrl_base != NULL) &&
		(priv->chip_type == CHIP_HIXX51) &&
		(priv->chip_platform == SDMMC_ASIC_PLATFORM)) {
		/* Set the level-1 frequency divider of the eMMC
		 * to divide by 2. 1.6G/2=800M,
		 * peri_subctrl_base offset: 0x104 bit[7:4] = 1
		 */
		reg = readl(peri_subctrl_base +
			hs_dwmmc_reg[priv->chip_type][PERI_SC_EMMC_CLK_SEL]);
		reg &= HIXX51_EMMC_CLK_SEL_PLL_OFF;
		reg |= HIXX51_EMMC_CLK_SEL_PLL_VAL;
		writel(reg, peri_subctrl_base +
			hs_dwmmc_reg[priv->chip_type][PERI_SC_EMMC_CLK_SEL]);
	}

	if (priv->id == DW_MCI_SDIO_ID)
		sdio_host = host;

	ret = dw_mci_hs_init_specific(host);
	if (ret) {
		devm_kfree(host->dev, priv);
		dev_err(host->dev, "device init specific error!\n");
		return -1;
	}

	return 0;
}

int dw_mci_hs_setup_clock(struct dw_mci *host)
{
	struct dw_mci_hs_priv_data *priv = host->priv;
	int timing = MMC_TIMING_LEGACY;
	int id = priv->id;
	int ret;

	ret = dw_mci_clk_set_rate(host, hs_timing_config[id][timing][0]);
	if (ret)
		dev_err(host->dev, "dw_mci_clk_set_rate failed\n");

	dw_mci_hs_set_controller(host, 0);
	dw_mci_hs_priv_setting(host);

	host->tuning_current_sample = -1;
	host->current_div = hs_timing_config[id][timing][1];

	host->tuning_init_sample =
		(hs_timing_config[id][timing][4] +
		hs_timing_config[id][timing][5]) / 2;

	dw_mci_hs_set_timing(host, id, timing, host->tuning_init_sample,
		host->current_div);

	if (priv->priv_bus_hz == 0)
		host->bus_hz = hs_timing_config[id][timing][6];
	else
		host->bus_hz = priv->priv_bus_hz;

	if (priv->dw_mmc_bus_clk) {
		/* if FPGA, the clk for SD should be 20M */
		host->bus_hz = priv->dw_mmc_bus_clk;
	}

	priv->old_timing = timing;

	return 0;
}

static int dw_mci_dt_get_bus_width(struct dw_mci *host)
{
	struct device_node *cnp = NULL;
	struct device_node *np = NULL;
	u32 bus_width = 0;

	np = host->dev->of_node;
	for_each_child_of_node(np, cnp) {
		if (!of_property_read_u32(cnp, "bus-width", &bus_width))
			break;

		dev_info(host->dev, "\"bus-width\" property is missing,\n");
		dev_info(host->dev, " assuming 1 bit.\n");
		bus_width = EMMC_BUS_WIDTH_1_BIT;
	}
	dev_info(host->dev, "\"bus-width\" value %u\n", bus_width);
	switch (bus_width) {
	case EMMC_BUS_WIDTH_8_BIT:
		hs_dwmmc_caps[DW_MCI_EMMC_ID] |= MMC_CAP_8_BIT_DATA;
		break;
	case EMMC_BUS_WIDTH_4_BIT:
		hs_dwmmc_caps[DW_MCI_EMMC_ID] |= MMC_CAP_4_BIT_DATA;
		break;
	case EMMC_BUS_WIDTH_1_BIT:
		break;
	default:
		dev_err(host->dev,
			"Invalid \"bus-width\" value %u!\n", bus_width);
		return -EINVAL;
	}
	return 0;
}

static int dw_mci_hs_parse_dt(struct dw_mci *host)
{
	struct dw_mci_hs_priv_data *priv = host->priv;
	struct device_node *np = host->dev->of_node;
	u32 value = 0;
	int error = 0;

	error = dw_mci_hs_get_dt_pltfm_resource(np);
	if (error)
		return error;

	if (of_find_property(np, "hi3660_fpga_sd_ioset", NULL)) {
		priv->hi3660_fpga_sd_ioset = HI3660_FPGA;
		dev_info(host->dev, "fpga_sd_ioset is %d",
			priv->hi3660_fpga_sd_ioset);
	}

	priv->hi3660_sd_ioset_sd_sel =
		of_get_named_gpio(np, "hi3660_sd_ioset_sd_sel", 0);
	if (!gpio_is_valid(priv->hi3660_sd_ioset_sd_sel)) {
		dev_info(host->dev, "sd_ioset_sd_sel not available\n");
		priv->hi3660_sd_ioset_sd_sel = -1;
	}

	priv->hi3660_sd_ioset_jtag_sd_sel =
		of_get_named_gpio(np, "hi3660_sd_ioset_jtag_sd_sel", 0);
	if (!gpio_is_valid(priv->hi3660_sd_ioset_jtag_sd_sel)) {
		dev_info(host->dev, "sd_ioset_jtag_sd_sel not available\n");
		priv->hi3660_sd_ioset_jtag_sd_sel = -1;
	}

	if (of_find_property(np, "hi6250-timing-65M", NULL)) {
		hs_dwmmc_caps[DW_MCI_SDIO_ID] |=
			(MMC_CAP_UHS_SDR12 |
			MMC_CAP_UHS_SDR25 | MMC_CAP_UHS_SDR50);
		hs_timing_config[2][5][0] = 535000000;
		dev_info(host->dev, "exit setup timing clock 65M.\n");
	}

	if (of_find_property(np, "wifi_sdio_sdr104_156M", (int *)NULL)) {
		hs_dwmmc_caps[DW_MCI_SDIO_ID] |=
			(MMC_CAP_UHS_SDR12 |
			MMC_CAP_UHS_SDR25 |
			MMC_CAP_UHS_SDR50 | MMC_CAP_UHS_SDR104);
		hs_timing_config[2][6][1] = 9;
		hs_timing_config[2][6][4] = 19;
		hs_timing_config[2][6][6] = 160000000;
		host->wifi_sdio_sdr104_160M = 0xaaaa;
		dev_info(host->dev, "set berlin sdio sdr104 156M.\n");
	}

	if (of_find_property(np, "wifi_sdio_sdr104_177M", (int *)NULL)) {
		hs_dwmmc_caps[DW_MCI_SDIO_ID] |=
			(MMC_CAP_UHS_SDR12 |
			MMC_CAP_UHS_SDR25 |
			MMC_CAP_UHS_SDR50 | MMC_CAP_UHS_SDR104);
		hs_timing_config[2][6][1] = 8;
		hs_timing_config[2][6][4] = 17;
		hs_timing_config[2][6][6] = 177777777;
		host->wifi_sdio_sdr104_177M = 0xaaaa;
		dev_info(host->dev, "set berlin sdio sdr104 177M.\n");
	}

	if (of_property_read_u32(np, "hisi,bus_hz", &value)) {
		dev_info(host->dev, "bus_hz property not found, using\n");
		dev_info(host->dev, "value of 0 as default\n");
		value = 0;
	}
	priv->priv_bus_hz = value;
	dev_info(host->dev, "dts bus_hz = %d\n", priv->priv_bus_hz);

	value = 0;
	if (of_property_read_u32(np, "cd-vol", &value)) {
		dev_info(host->dev, "cd-vol property not found, using\n");
		dev_info(host->dev, "value of 0 as default\n");
		value = 0;
	}
	priv->cd_vol = value;
	dev_info(host->dev, "dts cd-vol = %d\n", priv->cd_vol);

	if (of_find_property(np, "sdio_support_uhs", NULL))
		hs_dwmmc_caps[DW_MCI_SDIO_ID] |=
			(MMC_CAP_UHS_SDR12 | MMC_CAP_UHS_SDR25 |
			MMC_CAP_UHS_SDR50 | MMC_CAP_UHS_SDR104);

	if (of_find_property(np, "sd_support_uhs", (int *)NULL)) {
		hs_dwmmc_caps[DW_MCI_SD_ID] |=
			(MMC_CAP_UHS_SDR12 |
			MMC_CAP_UHS_SDR25 |
			MMC_CAP_UHS_SDR50);
		dev_info(host->dev, "set sd_support_uhs.\n");
	}

	/* find out mmc_bus_clk supported for hi3650 FPGA */
	if (of_property_read_u32(np, "board-mmc-bus-clk",
		&(priv->dw_mmc_bus_clk))) {
		dev_info(host->dev, "board mmc_bus_clk property not found,\n");
		dev_info(host->dev, "assuming asic board is available\n");

		priv->dw_mmc_bus_clk = 0;
	}
	dev_info(host->dev, "######board-mmc-bus-clk is %x\n",
		priv->dw_mmc_bus_clk);

	/* find out voltage switch supported by gpio for hi3650 FPGA */
	priv->dw_voltage_switch_gpio = of_get_named_gpio(np,
		"board-sd-voltage-switch-gpio", 0);
	if (!gpio_is_valid(priv->dw_voltage_switch_gpio)) {
		dev_info(host->dev,
			"board-sd-voltage-switch-gpio not available\n");
		priv->dw_voltage_switch_gpio = SDMMC_ASIC_PLATFORM;
	}
	dev_info(host->dev, "######dw_voltage_switch_gpio is %d\n",
		priv->dw_voltage_switch_gpio);

	if (dw_mci_dt_get_bus_width(host))
		dev_info(host->dev, "Invalid emmc \"bus-width\" value !\n");

	return 0;
}

static irqreturn_t dw_mci_hs_card_detect(int irq, void *data)
{
	struct dw_mci *host = (struct dw_mci *)data;

	host->sd_reinit = 0;
	host->sd_hw_timeout = 0;
	host->flags &= ~DWMMC_IN_TUNING;
	host->flags &= ~DWMMC_TUNING_DONE;

	queue_work(host->card_workqueue, &host->card_work);
	return IRQ_HANDLED;
};

static int dw_mci_hs_get_cd(struct dw_mci *host, u32 slot_id)
{
	unsigned int status;
	struct dw_mci_hs_priv_data *priv = host->priv;

	/* cd_vol = 1 means sdcard gpio detect pin active-high */
	if (priv->cd_vol)
		status = !gpio_get_value(priv->gpio_cd);
	else	/* cd_vol = 0 means sdcard gpio detect pin active-low */
		status = gpio_get_value(priv->gpio_cd);

	/* If sd to jtag func enabled, make the SD always not present */
	if ((host->hw_mmc_id == DWMMC_SD_ID) &&
		(check_himntn(HIMNTN_SD2JTAG)
		|| check_himntn(HIMNTN_SD2DJTAG)))
		status = 1;


	dev_info(host->dev, " sd status = %d\n", status);

	return status;
}

static int dw_mci_hs_cd_detect_init(struct dw_mci *host)
{
	struct dw_mci_hs_priv_data *priv = host->priv;
	struct device_node *np = host->dev->of_node;
	u32 shared_irq = 0;
	int gpio;
	int err;

	if (host->pdata->quirks & DW_MCI_QUIRK_BROKEN_CARD_DETECTION)
		return 0;

	gpio = of_get_named_gpio(np, "cd-gpio", 0);
	if (gpio_is_valid(gpio)) {
		if (devm_gpio_request_one(
			host->dev, gpio, GPIOF_IN, "dw-mci-cd")) {
			dev_warn(host->dev,
				"gpio [%d] request failed\n", gpio);
		} else {
			dev_info(host->dev, "gpio [%d] request\n", gpio);

			priv->gpio_cd = gpio;
			host->pdata->get_cd = dw_mci_hs_get_cd;

			if (of_property_read_u32(
				np, "shared-irq", &shared_irq)) {
				dev_info(host->dev,
					"shared-irq property not found,\n");
				dev_info(host->dev,
					"using shared_irq of 0 as default\n");
				shared_irq = 0;
			}

			if (shared_irq) {
				err = devm_request_irq(host->dev,
					gpio_to_irq(gpio),
					dw_mci_hs_card_detect,
					IRQF_TRIGGER_FALLING |
					IRQF_TRIGGER_RISING |
					IRQF_NO_SUSPEND
					| IRQF_SHARED,
					DRIVER_NAME, host);
			} else {
				err = devm_request_irq(host->dev,
					gpio_to_irq(gpio),
					dw_mci_hs_card_detect,
					IRQF_TRIGGER_FALLING |
					IRQF_TRIGGER_RISING,
					DRIVER_NAME, host);
			}

			if (err)
				dev_warn(mmc_dev(host->dev),
					"request gpio irq error\n");
		}

	} else {
		dev_info(host->dev, "cd gpio not available");
	}
	return 0;
}

static int hs_dwmmc_card_busy(struct dw_mci *host)
{
	if ((mci_readl(host, STATUS) & SDMMC_STATUS_BUSY) || host->cmd
		|| host->data || host->mrq || (host->state != STATE_IDLE)) {
		dev_vdbg(host->dev, " card is busy!");
		return 1;
	}

	return 0;
}

static int dw_mci_3_3v_signal_voltage_switch(struct dw_mci_slot *slot)
{
	struct dw_mci *host = slot->host;
	struct dw_mci_hs_priv_data *priv = host->priv;
	u32 reg;
	int ret = 0;

	ret = dw_mci_set_sel18(priv->chip_type, 0);
	if (ret) {
		dev_err(host->dev, " dw_mci_set_sel18 error!\n");
		return ret;
	}

	/* hixx51 not support voltage 3.3v */
	if (priv->chip_type == CHIP_HIXX51) {
		dev_info(host->dev, "hixx51 not support voltage 3.3v\n");
		return -EPERM;
	}

	/* Wait for 5ms */
	usleep_range(5000, 5500);

	/* only for SD voltage switch on hi3650 FPGA */
	if (priv->dw_voltage_switch_gpio != SDMMC_ASIC_PLATFORM) {
		(void)gpio_request(priv->dw_voltage_switch_gpio,
			"board-sd-voltage-switch-gpio");
		/* set the voltage to 3V for SD IO */
		gpio_direction_output(priv->dw_voltage_switch_gpio, 1);
		gpio_free(priv->dw_voltage_switch_gpio);
	} else {
		if (host->vqmmc) {
			ret = regulator_set_voltage(host->vqmmc,
				2950000, 2950000);
			if (ret) {
				dev_warn(host->dev,
					"Switching to 3.3V signalling\n");
				dev_warn(host->dev, "voltage failed\n");
				return -EIO;
			}
		} else if ((host->hw_mmc_id == DWMMC_SD_ID) &&
			(priv->chip_platform == SDMMC_ASIC_PLATFORM)) {
			ret = pmu_ldo9_set_voltage(2950);
			if (ret) {
				dev_warn(host->dev,
					"Switching to 3.3V signalling\n");
				dev_warn(host->dev, "voltage failed\n");
				return -EIO;
			}
		} else {
			reg = mci_readl(slot->host, UHS_REG);
			reg &= ~(0x1 << slot->id);
			mci_writel(slot->host, UHS_REG, reg);
		}
	}

	/* Wait for 5ms */
	usleep_range(5000, 5500);

	return ret;
}

static int dw_mci_1_8v_signal_voltage_switch(struct dw_mci_slot *slot)
{
	unsigned long loop_count = 0x100000;
	struct dw_mci *host = slot->host;
	struct dw_mci_hs_priv_data *priv = host->priv;
	int ret;
	int intrs;

	/* disable interrupt upon voltage switch. handle interrupt here */
	/*  and DO NOT triggle irq */
	mci_writel(host, CTRL,
		(mci_readl(host, CTRL) & ~SDMMC_CTRL_INT_ENABLE));

	/* stop clock */
	mci_writel(host, CLKENA, (0x0 << 0));
	mci_writel(host, CMD, SDMMC_CMD_ONLY_CLK | SDMMC_CMD_VOLT_SWITCH);
	do {
		if (!(mci_readl(host, CMD) & SDMMC_CMD_START))
			break;
		loop_count--;
	} while (loop_count);

	if (!loop_count)
		dev_warn(host->dev,
			" disable clock failed in voltage_switch\n");

	mmiowb();

	if (priv->dw_voltage_switch_gpio != SDMMC_ASIC_PLATFORM) {
		(void)gpio_request(priv->dw_voltage_switch_gpio,
				"board-sd-voltage-switch-gpio");
		/* set the voltage to 3V for SD IO */
		(void)gpio_direction_output(priv->dw_voltage_switch_gpio, 0);
		gpio_free(priv->dw_voltage_switch_gpio);
	} else {
		if (host->vqmmc) {
			ret = regulator_set_voltage(host->vqmmc,
				1800000, 1800000);
			if (ret) {
				dev_warn(host->dev,
					"Switching to 1.8V signalling\n");
				dev_warn(host->dev, "voltage failed\n");
				return -EIO;
			}
		} else {
			if ((host->hw_mmc_id == DWMMC_SD_ID) &&
				(priv->chip_platform == SDMMC_ASIC_PLATFORM)) {
				ret = pmu_ldo9_set_voltage(1800);
				if (ret) {
					dev_warn(host->dev,
						"Switching to 1.8V\n");
					dev_warn(host->dev,
						"signalling voltage failed\n");
					return -EIO;
				}
			}
		}
	}

	/* Wait 55ms for pmu voltage drop*/
	usleep_range(55000, 55500);

	ret = dw_mci_set_sel18(priv->chip_type, 1);
	if (ret) {
		dev_err(host->dev, " dw_mci_set_sel18 error!\n");
		return ret;
	}

	/* Wait for 5ms */
	usleep_range(5000, 5500);

	/* start clock */
	mci_writel(host, CLKENA, (0x1 << 0));
	mci_writel(host, CMD, SDMMC_CMD_ONLY_CLK | SDMMC_CMD_VOLT_SWITCH);
	loop_count = 0x100000;
	do {
		if (!(mci_readl(host, CMD) & SDMMC_CMD_START))
			break;
		loop_count--;
	} while (loop_count);

	if (!loop_count)
		dev_warn(host->dev, " enable clock failed in voltage_switch\n");

	/* poll cd interrupt */
	loop_count = 0x100000;
	do {
		intrs = mci_readl(host, RINTSTS);
		if (intrs & SDMMC_INT_CMD_DONE) {
			dev_info(host->dev, " cd 0x%x in voltage_switch\n",
				intrs);
			mci_writel(host, RINTSTS, intrs);
			break;
		}
		loop_count--;
	} while (loop_count);

	if (!loop_count)
		dev_warn(host->dev, " poll cd failed in voltage_switch\n");

	/* enable interrupt */
	mci_writel(host, CTRL, (mci_readl(host, CTRL) | SDMMC_CTRL_INT_ENABLE));

	mmiowb();

	return ret;
}

static int dw_mci_priv_voltage_switch(struct mmc_host *mmc, struct mmc_ios *ios)
{
	struct dw_mci_slot *slot = mmc_priv(mmc);
	int ret = 0;
/* BEGIN FPGA not support voltage switch, 2018/02/08 */
	/* only sd need to switch voltage */
	if (slot->host->hw_mmc_id != DWMMC_SD_ID)
		return ret;

	pm_runtime_get_sync(mmc_dev(mmc));

	if (ios->signal_voltage == MMC_SIGNAL_VOLTAGE_330)
		ret = dw_mci_3_3v_signal_voltage_switch(slot);
	else if (ios->signal_voltage == MMC_SIGNAL_VOLTAGE_180)
		ret = dw_mci_1_8v_signal_voltage_switch(slot);

	pm_runtime_mark_last_busy(mmc_dev(mmc));
	pm_runtime_put_autosuspend(mmc_dev(mmc));
/* END FPGA not support voltage switch, 2018/02/08 */
	return ret;
}

void dw_mci_set_timeout(struct dw_mci *host)
{
	/* timeout (maximum) */
	mci_writel(host, TMOUT, 0xffffffff);
}

static void dw_mci_hs_tuning_clear_flags(struct dw_mci *host)
{
	host->tuning_sample_flag = 0;
}

static bool dw_mci_hi3xxx_wait_reset(struct device *dev,
	struct dw_mci *host, unsigned int reset_val)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(50);
	unsigned int ctrl;

	ctrl = mci_readl(host, CTRL);
	ctrl |= reset_val;
	mci_writel(host, CTRL, ctrl);

	/* wait till resets clear */
	do {
		if (!(mci_readl(host, CTRL) & reset_val))
			return true;
	} while (time_before(jiffies, timeout));

	dev_warn(dev, "Timeout resetting block (ctrl %#x)\n", ctrl);

	return false;
}

static bool mci_hi3xxx_wait_reset(struct dw_mci *host)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(50);
	unsigned int ctrl;

	mci_writel(host, CTRL, (SDMMC_CTRL_RESET | SDMMC_CTRL_FIFO_RESET |
		SDMMC_CTRL_DMA_RESET));

	/* wait till resets clear */
	do {
		ctrl = mci_readl(host, CTRL);
		if (!(ctrl & (SDMMC_CTRL_RESET | SDMMC_CTRL_FIFO_RESET |
			SDMMC_CTRL_DMA_RESET)))
			return true;
	} while (time_before(jiffies, timeout));

	dev_warn(host->dev, "Timeout resetting block (ctrl %#x)\n", ctrl);

	return false;
}

static void dw_mci_hi3xxx_mci_send_cmd(struct dw_mci *host, u32 cmd, u32 arg)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(100);
	unsigned int cmd_status = 0;
	int try = 3;

	mci_writel(host, CMDARG, arg);
	/* Synchronous execution */
	wmb();
	mci_writel(host, CMD, SDMMC_CMD_START | cmd);

	do {
		while (time_before(jiffies, timeout)) {
			cmd_status = mci_readl(host, CMD);
			if (!(cmd_status & SDMMC_CMD_START))
				return;
		}

		dw_mci_hi3xxx_wait_reset(host->dev, host, SDMMC_CTRL_RESET);
		mci_writel(host, CMD, SDMMC_CMD_START | cmd);
		timeout = jiffies + msecs_to_jiffies(100);
	} while (--try);

	dev_warn(host->dev, "hi3xxx_dw_mmc\n");
	dev_warn(host->dev,
		"Timeout sending command (cmd %#x arg %#x status %#x)\n",
		cmd, arg, cmd_status);
}

static void dw_mci_hi3xxx_work_fail_reset(struct dw_mci *host)
{
	struct dw_mci_hs_priv_data *priv = host->priv;

	unsigned int retval = 0;
	unsigned int ctype;
	unsigned int clkena;
	unsigned int clkdiv;
	unsigned int uhs_reg;
	unsigned int uhs_reg_ext;
	unsigned int enable_shift;
	unsigned int gpio;
	unsigned int fifoth;
	unsigned int timeout;
	unsigned int cardthrctrl;
	unsigned int _rintsts;
	unsigned int _tcbcnt;
	unsigned int _tbbcnt;
	unsigned int _fifoth;

	if ((priv->id != DW_MCI_SD_ID) && (priv->id != DW_MCI_SDIO_ID)) {
		dev_err(host->dev, "Not support now, return\n");
		return;
	}

	dev_warn(host->dev, "Start to reset SDIO IP\n");
	mci_writel(host, CTRL, (mci_readl(host, CTRL) & (~INT_ENABLE)));
	mci_writel(host, INTMASK, 0);

	mci_writel(host, RINTSTS, INTMSK_ALL);

#ifdef CONFIG_MMC_DW_IDMAC
	if (host->dma_64bit_address == SDMMC_32_BIT_DMA)
		mci_writel(host, IDSTS, IDMAC_INT_CLR);
	else
		mci_writel(host, IDSTS64, IDMAC_INT_CLR);
#endif

	ctype = mci_readl(host, CTYPE);
	clkena = mci_readl(host, CLKENA);
	clkdiv = mci_readl(host, CLKDIV);
	fifoth = mci_readl(host, FIFOTH);
	timeout = mci_readl(host, TMOUT);
	cardthrctrl = mci_readl(host, CDTHRCTL);
	uhs_reg = mci_readl(host, UHS_REG);
	uhs_reg_ext = mci_readl(host, UHS_REG_EXT);
	enable_shift = mci_readl(host, ENABLE_SHIFT);
	gpio = mci_readl(host, GPIO);

	_rintsts = mci_readl(host, RINTSTS);
	_tcbcnt = mci_readl(host, TCBCNT);
	_tbbcnt = mci_readl(host, TBBCNT);
	retval = mci_readl(host, CTRL);

	dev_info(host->dev,
		"before ip reset: CTRL=%x, UHS_REG_EXT=%x, ENABLE_SHIFT=%x,\n",
		retval, uhs_reg_ext, enable_shift);
	dev_info(host->dev,
		" GPIO=%x, CLKEN=%d, CLKDIV=%d, TMOUT=%x, RINTSTS=%x,\n",
		gpio, clkena, clkdiv, timeout, _rintsts);
	dev_info(host->dev, " TCBCNT=%x, TBBCNT=%x,FIFOTH=%x\n",
		_tcbcnt, _tbbcnt, fifoth);

	udelay(20);

	dw_mci_hs_set_rst_m(host, 1);
	dw_mci_hs_set_controller(host, 1);

	if (!IS_ERR(host->ciu_clk))
		clk_disable_unprepare(host->ciu_clk);

	dw_mci_hs_set_rst_m(host, 0);

	if (!IS_ERR(host->ciu_clk)) {
		if (clk_prepare_enable(host->ciu_clk))
			dev_err(host->dev, "ciu_clk clk_prepare_enable failed\n");
	}

	dw_mci_hs_set_controller(host, 0);

	udelay(20);
	mci_hi3xxx_wait_reset(host);

	mci_writel(host, CTYPE, ctype);
	mci_writel(host, FIFOTH, fifoth);
	mci_writel(host, TMOUT, timeout);
	mci_writel(host, CDTHRCTL, cardthrctrl);
	mci_writel(host, UHS_REG, uhs_reg);
	mci_writel(host, GPIO, 0x0);
	udelay(10);
	mci_writel(host, UHS_REG_EXT, uhs_reg_ext);
	mci_writel(host, ENABLE_SHIFT, enable_shift);
	mci_writel(host, GPIO, gpio | GPIO_CLK_ENABLE);

	mci_writel(host, BMOD, SDMMC_IDMAC_SWRESET);
#ifdef CONFIG_MMC_DW_IDMAC
	if (host->dma_64bit_address == SDMMC_32_BIT_DMA) {
		mci_writel(host, IDSTS, IDMAC_INT_CLR);
		mci_writel(host, IDINTEN, SDMMC_IDMAC_INT_NI |
			SDMMC_IDMAC_INT_RI | SDMMC_IDMAC_INT_TI);
		mci_writel(host, DBADDR, host->sg_dma);
	} else {
		mci_writel(host, IDSTS64, IDMAC_INT_CLR);
		mci_writel(host, IDINTEN64, SDMMC_IDMAC_INT_NI |
			SDMMC_IDMAC_INT_RI | SDMMC_IDMAC_INT_TI);
		mci_writel(host, DBADDRL, host->sg_dma & 0xffffffff);
		mci_writel(host, DBADDRU, (u64)host->sg_dma >> 32);
	}
#endif


	mci_writel(host, RINTSTS, INTMSK_ALL);
	mci_writel(host, INTMASK, 0);
	mci_writel(host, RINTSTS, INTMSK_ALL);
#ifdef CONFIG_MMC_DW_IDMAC
	if (host->dma_64bit_address == SDMMC_32_BIT_DMA)
		mci_writel(host, IDSTS, IDMAC_INT_CLR);
	else
		mci_writel(host, IDSTS64, IDMAC_INT_CLR);
#endif
	mci_writel(host, INTMASK, SDMMC_INT_CMD_DONE | SDMMC_INT_DATA_OVER |
		SDMMC_INT_TXDR | SDMMC_INT_RXDR | DW_MCI_ERROR_FLAGS |
		SDMMC_INT_CD);
	/* Enable mci interrupt */
	mci_writel(host, CTRL, SDMMC_CTRL_INT_ENABLE);

	/* disable clock */
	mci_writel(host, CLKENA, 0);
	mci_writel(host, CLKSRC, 0);

	/* inform CIU */
	dw_mci_hi3xxx_mci_send_cmd(host,
		SDMMC_CMD_UPD_CLK | SDMMC_CMD_PRV_DAT_WAIT, 0);

	/* set clock to desired speed */
	mci_writel(host, CLKDIV, clkdiv);

	/* inform CIU */
	dw_mci_hi3xxx_mci_send_cmd(host,
		SDMMC_CMD_UPD_CLK | SDMMC_CMD_PRV_DAT_WAIT, 0);

	mci_writel(host, CLKENA, clkena);

	/* inform CIU */
	dw_mci_hi3xxx_mci_send_cmd(host,
		SDMMC_CMD_UPD_CLK | SDMMC_CMD_PRV_DAT_WAIT, 0);

	retval = mci_readl(host, CTRL);
	_rintsts = mci_readl(host, RINTSTS);
	_tcbcnt = mci_readl(host, TCBCNT);
	_tbbcnt = mci_readl(host, TBBCNT);
	_fifoth = mci_readl(host, FIFOTH);
	uhs_reg_ext = mci_readl(host, UHS_REG_EXT);
	enable_shift = mci_readl(host, ENABLE_SHIFT);
	gpio = mci_readl(host, GPIO);

	dev_info(host->dev, "after  ip reset: CTRL=%x, UHS_REG_EXT=%x,\n",
		retval, uhs_reg_ext);
	dev_info(host->dev,
		"ENABLE_SHIFT=%x, GPIO=%x, CLKEN=%d, CLKDIV=%d, TMOUT=%x,\n",
		enable_shift, gpio, clkena, clkdiv, timeout);
	dev_info(host->dev, "RINTSTS=%x, TCBCNT=%x, TBBCNT=%x,FIFOTH=%x\n",
		 _rintsts, _tcbcnt, _tbbcnt, _fifoth);
}

static void dw_mci_hs_tuning_set_flags(struct dw_mci *host, int sample, int ok)
{
	if (ok)
		host->tuning_sample_flag |= (1 << sample);
	else
		host->tuning_sample_flag &= ~(1 << sample);
}

/* By tuning, find the best timing condition
 *  1 -- tuning is not finished. And this function should be called again
 *  0 -- Tuning successfully.
 *    If this function be called again, another round of tuning would be start
 *  -1 -- Tuning failed. Maybe slow down the clock and call this function again
 */
static int dw_mci_hs_tuning_find_condition(struct dw_mci *host, int timing)
{
	struct dw_mci_hs_priv_data *priv = host->priv;
	const struct dw_mci_drv_data *drv_data = host->drv_data;
	int id = priv->id;
	int sample_min, sample_max;
	int i, j;
	int ret = 0;
	int mask, mask_length;
	int d_value = 0;

	if (host->hw_mmc_id == DWMMC_SD_ID) {
		d_value = host->current_div - hs_timing_config[id][timing][1];
		if (timing == MMC_TIMING_SD_HS) {
			sample_max = hs_timing_config[id][timing][4] + d_value;
			sample_min = hs_timing_config[id][timing][5] + d_value;
		} else if ((timing == MMC_TIMING_UHS_SDR50) ||
			(timing == MMC_TIMING_UHS_SDR104)) {
			sample_max =
				hs_timing_config[id][timing][4] + 2 * d_value;
			sample_min = hs_timing_config[id][timing][5];
		} else {
			sample_max = hs_timing_config[id][timing][4];
			sample_min = hs_timing_config[id][timing][5];
		}
	} else {
		sample_max = hs_timing_config[id][timing][4];
		sample_min = hs_timing_config[id][timing][5];
	}

	if (sample_max == sample_min) {
		host->tuning_init_sample = (sample_max + sample_min) / 2;
		dw_mci_hs_set_timing(host, id,
			timing, host->tuning_init_sample, host->current_div);
		dev_info(host->dev,
			"no need tuning: timing is %d, tuning sample = %d",
			timing, host->tuning_init_sample);
		return 0;
	}

	if (-1 == host->tuning_current_sample) {

		dw_mci_hs_tuning_clear_flags(host);

		/* set the first sam del as the min_sam_del */
		host->tuning_current_sample = sample_min;
		/* a trick for next "++" */
		host->tuning_current_sample--;
	}

	if (host->tuning_current_sample >= sample_max) {
		/* tuning finish, select the best sam_del */

		/* set sam del to -1, for next tuning */
		host->tuning_current_sample = -1;

		host->tuning_init_sample = -1;
		for (mask_length =
			(((sample_max - sample_min) >> 1) << 1) + 1;
			mask_length >= 1; mask_length -= 2) {

			mask = (1 << mask_length) - 1;
			for (i = (sample_min +
				sample_max - mask_length + 1) / 2, j = 1;
				(i <= sample_max - mask_length + 1) &&
					(i >= sample_min);
				i = ((sample_min +
					sample_max - mask_length + 1) / 2) +
					((j % 2) ? -1 : 1) * (j / 2)) {
				if ((host->tuning_sample_flag &
					((unsigned int)mask << (unsigned int)i)
					) == (
					(unsigned int)mask << (unsigned int)i)
					) {
					host->tuning_init_sample =
						i + mask_length / 2;
					break;
				}

				j++;
			}

			if (host->tuning_init_sample != -1) {
				if ((host->hw_mmc_id == DWMMC_SD_ID)
					&& (mask_length < 3) &&
					(drv_data->slowdown_clk)) {
					dev_info(host->dev,
						"sd card tuning need slow\n");
					dev_info(host->dev,
						"down clk, timing is %d,\n",
						timing);
					dev_info(host->dev,
						"tuning_flag = 0x%x\n",
						host->tuning_sample_flag);
					return -1;
				}
				dev_info(host->dev,
					"tuning OK: timing is %d,\n",
					timing);
				dev_info(host->dev, "tuning sample = %d,\n",
					host->tuning_init_sample);
				dev_info(host->dev, "tuning_flag = 0x%x\n",
					host->tuning_sample_flag);
				ret = 0;
				break;
			}
		}

		if (-1 == host->tuning_init_sample) {
			host->tuning_init_sample =
				(sample_min + sample_max) / 2;
			dev_info(host->dev,
				"tuning err: no good sam_del,\n");
			dev_info(host->dev,
				" timing is %d, tuning_flag = 0x%x\n",
				timing, host->tuning_sample_flag);
			ret = -1;
		}

		dw_mci_hs_set_timing(host, id, timing,
			host->tuning_init_sample, host->current_div);
		return ret;
	}
	host->tuning_current_sample++;
	dw_mci_hs_set_timing(host, id, timing,
		host->tuning_current_sample, host->current_div);
	return 1;


}

static void dw_mci_hs_tuning_set_current_state(struct dw_mci *host, int ok)
{
	dw_mci_hs_tuning_set_flags(host, host->tuning_current_sample, ok);
}

#ifdef CONFIG_MMC_DW_SD_CLK_SLOWDOWN
static int dw_mci_hs_slowdown_clk(struct dw_mci *host, int timing)
{
	struct dw_mci_hs_priv_data *priv = host->priv;
	int id = priv->id;

	host->current_div += 2;

	/* slow down up to half of original freq */
	if (host->current_div > 2 * hs_timing_config[id][timing][1]) {
		host->current_div = 2 * hs_timing_config[id][timing][1];
		return -1;
	}
	dev_info(host->dev,
		"begin slowdown clk, current_div=%d\n",
		host->current_div);

	dw_mci_hs_set_timing(host, id, timing,
		host->tuning_init_sample, host->current_div);

	return 0;
}
#endif

int dw_mci_sdio_wakelog_switch(struct mmc_host *mmc, bool enable)
{
	struct dw_mci_slot *slot = NULL;

	if (!mmc)
		return -1;

	slot = mmc_priv(mmc);
	if (!slot)
		return -1;

	if (enable)
		slot->sdio_wakelog_switch = 1;
	else
		slot->sdio_wakelog_switch = 0;

	slot->sdio_wakelog_switch = slot->sdio_wakelog_switch &&
		(MMC_CAP2_SUPPORT_WIFI & (mmc->caps2));
	return slot->sdio_wakelog_switch;
}
EXPORT_SYMBOL(dw_mci_sdio_wakelog_switch);

static int dw_mci_hs_tuning_move(struct dw_mci *host, int timing, int start)
{
	struct dw_mci_hs_priv_data *priv = host->priv;
	int id = priv->id;
	int sample_min, sample_max;
	int loop;
	struct dw_mci_slot *slot = host->cur_slot;

	sample_max = hs_timing_config[id][timing][4];
	sample_min = hs_timing_config[id][timing][5];

	if (sample_max == sample_min) {
		dev_info(host->dev, "id = %d, tuning move return\n", id);
		return 0;
	}

	if (start)
		host->tuning_move_count = 0;

	for (loop = 0; loop < 2; loop++) {
		host->tuning_move_count++;
		host->tuning_move_sample =
			host->tuning_init_sample +
			((host->tuning_move_count % 2) ? 1 : -1) *
			(host->tuning_move_count / 2);

		if ((host->tuning_move_sample > sample_max) ||
			(host->tuning_move_sample < sample_min)) {
			continue;
		} else {
			break;
		}
	}

	if ((host->tuning_move_sample > sample_max) ||
		(host->tuning_move_sample < sample_min)) {
		dw_mci_hs_set_timing(host, id, timing,
			host->tuning_init_sample, host->current_div);
		dev_info(host->dev,
			"id = %d, tuning move end to init del_sel %d\n",
			id, host->tuning_init_sample);
		return 0;
	}
	dw_mci_hs_set_timing(host, id, timing,
		host->tuning_move_sample, host->current_div);

	if (!(slot && slot->sdio_wakelog_switch))
		dev_info(host->dev,
		"id = %d, tuning move to current del_sel %d\n",
		id, host->tuning_move_sample);
	return 1;

}

#define EMMC_PATTERN_ADDRESS (384*2)
int dw_mci_priv_execute_tuning(struct dw_mci_slot *slot,
	u32 opcode, struct dw_mci_tuning_data *tuning_data)
{
	struct mmc_host *mmc = slot->mmc;
	struct dw_mci *host = slot->host;
	const struct dw_mci_drv_data *drv_data = host->drv_data;
	unsigned int tuning_loop = MAX_TUNING_LOOP;
	const u8 *tuning_blk_pattern;
	int ret = 0;
	u8 *tuning_blk;
	int blksz;

	int id = host->hw_mmc_id;
	u32 arg = 0;
	unsigned int flags = MMC_RSP_R1 | MMC_CMD_ADTC;

	if (opcode == MMC_SEND_TUNING_BLOCK_HS200) {
		if (mmc->ios.bus_width == MMC_BUS_WIDTH_8) {
			tuning_blk_pattern = tuning_blk_pattern_8bit;
			blksz = 128;
		} else if (mmc->ios.bus_width == MMC_BUS_WIDTH_4) {
			tuning_blk_pattern = tuning_blk_pattern_4bit;
			blksz = 64;
		} else
			return -EINVAL;
	} else if (opcode == MMC_SEND_TUNING_BLOCK) {
		tuning_blk_pattern = tuning_blk_pattern_4bit;
		blksz = 64;
	} else if (opcode == MMC_READ_SINGLE_BLOCK) {
		if (id == 0)			/* emmc ddr50 */
			arg = EMMC_PATTERN_ADDRESS;

		blksz = 512;
	} else if (opcode == SD_IO_RW_EXTENDED) {
		arg = 0x200004;
		flags = MMC_RSP_SPI_R5 | MMC_RSP_R5 | MMC_CMD_ADTC;

		blksz = 4;
	} else {
		dev_err(&mmc->class_dev,
			"Undefined command(%d) for tuning\n", opcode);
		return -EINVAL;
	}

	tuning_blk = kmalloc(blksz, GFP_KERNEL);
	if (!tuning_blk)
		return -ENOMEM;

	if ((!drv_data->tuning_find_condition) ||
		(!drv_data->tuning_set_current_state)) {
		dev_err(&mmc->class_dev, "no tuning find condition method\n");
		goto out;
	}

	pm_runtime_get_sync(mmc_dev(mmc));

	host->flags |= DWMMC_IN_TUNING;
	host->flags &= ~DWMMC_TUNING_DONE;

	do {
		struct mmc_request mrq = { NULL };
		struct mmc_command cmd = { 0 };
		struct mmc_data data = { 0 };
		struct scatterlist sg;

		cmd.opcode = opcode;
		cmd.arg = arg;
		cmd.flags = flags;

		data.blksz = blksz;
		data.blocks = 1;
		data.flags = MMC_DATA_READ;
		data.sg = &sg;
		data.sg_len = 1;

		sg_init_one(&sg, tuning_blk, blksz);
		dw_mci_set_timeout(host);

		mrq.cmd = &cmd;
		mrq.stop = NULL;
		mrq.data = &data;

		ret = drv_data->tuning_find_condition(host, mmc->ios.timing);
		if (ret == -1) {
			if ((host->hw_mmc_id == DWMMC_SD_ID) &&
				(drv_data->slowdown_clk)) {
				ret = drv_data->slowdown_clk(host,
					mmc->ios.timing);
				if (ret)
					break;
			} else {
				break;
			}
		} else if (ret == 0)
			break;

		mmc_wait_for_req(mmc, &mrq);

		if (!cmd.error && !data.error) {
			drv_data->tuning_set_current_state(host, 1);
		} else {
			drv_data->tuning_set_current_state(host, 0);
			dev_dbg(&mmc->class_dev,
				"Tuning error: cmd.error:%d, data.error:%d\n",
				cmd.error, data.error);
		}

	} while (tuning_loop--);

	host->flags &= ~DWMMC_IN_TUNING;
	if (!ret)
		host->flags |= DWMMC_TUNING_DONE;

	host->tuning_move_start = 1;
out:
	kfree(tuning_blk);

	pm_runtime_mark_last_busy(mmc_dev(mmc));
	pm_runtime_put_autosuspend(mmc_dev(mmc));

	return ret;
}

/* Common capabilities of hi3650 SoC */
static unsigned long hs_dwmmc_caps[3] = {
#ifdef CONFIG_MMC_DW_EMMC_USED_AS_MODEM
	/* sdio1  - via modem */
	MMC_CAP_4_BIT_DATA | MMC_CAP_SD_HIGHSPEED | MMC_CAP_SDIO_IRQ,
#else
	MMC_CAP_CMD23,
#endif
	/* sd */
	MMC_CAP_DRIVER_TYPE_A | MMC_CAP_4_BIT_DATA | MMC_CAP_SD_HIGHSPEED
		| MMC_CAP_MMC_HIGHSPEED,
	/* sdio */
	MMC_CAP_4_BIT_DATA | MMC_CAP_SD_HIGHSPEED | MMC_CAP_NONREMOVABLE,
};

static const struct dw_mci_drv_data hs_drv_data = {
	.caps = hs_dwmmc_caps,
	.init = dw_mci_hs_priv_init,
	.set_ios = dw_mci_hs_set_ios,
	.setup_clock = dw_mci_hs_setup_clock,
	.prepare_command = dw_mci_hs_prepare_command,
	.parse_dt = dw_mci_hs_parse_dt,
	.cd_detect_init = dw_mci_hs_cd_detect_init,
	.tuning_find_condition = dw_mci_hs_tuning_find_condition,
	.tuning_set_current_state = dw_mci_hs_tuning_set_current_state,
	.tuning_move = dw_mci_hs_tuning_move,
#ifdef CONFIG_MMC_DW_SD_CLK_SLOWDOWN
	.slowdown_clk = dw_mci_hs_slowdown_clk,
#endif
	.execute_tuning_hisi = dw_mci_priv_execute_tuning,
	.start_signal_voltage_switch = dw_mci_priv_voltage_switch,
	.work_fail_reset = dw_mci_hi3xxx_work_fail_reset,
};

static const struct of_device_id dw_mci_hs_match[] = {
	{
	 .compatible = "hisilicon,davinci-dw-mshc",
	 .data = &hs_drv_data,
	},
	{},
};

MODULE_DEVICE_TABLE(of, dw_mci_hs_match);

int dw_mci_hs_probe(struct platform_device *pdev)
{
	const struct dw_mci_drv_data *drv_data = NULL;
	const struct of_device_id *match = NULL;
	int err;

	match = of_match_node(dw_mci_hs_match, pdev->dev.of_node);
	if (!match)
		return -1;
	drv_data = match->data;

	err = dw_mci_hs_get_resource();
	if (err)
		return err;

	err = dw_mci_pltfm_register(pdev, drv_data);
	if (err)
		return err;

	/* when sdio1 used for via modem, disable pm runtime */
	if (!of_property_read_bool(pdev->dev.of_node, "modem_sdio_enable")) {

		pm_runtime_set_active(&pdev->dev);
		pm_runtime_enable(&pdev->dev);
		pm_runtime_set_autosuspend_delay(&pdev->dev, 50);
		pm_runtime_use_autosuspend(&pdev->dev);
		pm_suspend_ignore_children(&pdev->dev, 1);
	} else {
		pr_info("%s mmc/sdio device support via modem,\n", __func__);
		pr_info(" disable pm_runtime on this device\n");
	}

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int dw_mci_hs_suspend(struct device *dev)
{
	int ret;
	struct dw_mci *host = dev_get_drvdata(dev);
	struct dw_mci_hs_priv_data *priv = host->priv;

	dev_info(host->dev, " %s ++\n", __func__);
	pm_runtime_get_sync(dev);

	if (priv->gpio_cd) {
		disable_irq(gpio_to_irq(priv->gpio_cd));
		cancel_work_sync(&host->card_work);
		dev_info(host->dev, " disable gpio detect\n");
	}

	ret = dw_mci_suspend(host);
	if (ret)
		return ret;

	priv->old_timing = -1;
	priv->old_power_mode = MMC_POWER_OFF;
	if (!IS_ERR(host->biu_clk))
		clk_disable_unprepare(host->biu_clk);

	if (!IS_ERR(host->ciu_clk))
		clk_disable_unprepare(host->ciu_clk);

	dw_mci_hs_set_controller(host, 1);

	host->current_speed = 0;

	pm_runtime_mark_last_busy(dev);
	pm_runtime_put_autosuspend(dev);
	dev_info(host->dev, " %s --\n", __func__);
	return 0;
}

static int dw_mci_hs_resume(struct device *dev)
{
	int ret, i;
	struct dw_mci *host = dev_get_drvdata(dev);
	struct dw_mci_hs_priv_data *priv = host->priv;

	pm_runtime_get_sync(dev);

	if (!IS_ERR(host->biu_clk)) {
		if (clk_prepare_enable(host->biu_clk))
			dev_err(host->dev, "biu_clk clk_prepare_enable failed\n");
	}

	if (!IS_ERR(host->ciu_clk)) {
		if (clk_prepare_enable(host->ciu_clk))
			dev_err(host->dev, "ciu_clk clk_prepare_enable failed\n");
	}

	dw_mci_hs_set_controller(host, 0);

	for (i = 0; i < host->num_slots; i++) {
		struct dw_mci_slot *slot = host->slot;

		if (!slot)
			continue;

		if (slot->mmc->pm_flags & MMC_PM_KEEP_POWER) {
			priv->in_resume = STATE_KEEP_PWR;
		} else {
			host->flags &= ~DWMMC_IN_TUNING;
			host->flags &= ~DWMMC_TUNING_DONE;
		}
	}

	/* restore controller specified setting */
	dw_mci_hs_priv_setting(host);
	ret = dw_mci_resume(host);
	if (ret)
		return ret;

	priv->in_resume = STATE_LEGACY;

	if (priv->gpio_cd)
		enable_irq(gpio_to_irq(priv->gpio_cd));

	pm_runtime_mark_last_busy(dev);
	pm_runtime_put_autosuspend(dev);

	return 0;
}
#endif

#ifdef CONFIG_PM
static int dw_mci_hs_runtime_suspend(struct device *dev)
{
	struct dw_mci *host = dev_get_drvdata(dev);

	dev_vdbg(host->dev, " %s ++\n", __func__);
	if (hs_dwmmc_card_busy(host)) {
		dev_warn(host->dev, " %s: card is busy\n", __func__);
		return -EBUSY;
	}

	if (!IS_ERR(host->biu_clk))
		clk_disable_unprepare(host->biu_clk);

	if (!IS_ERR(host->ciu_clk))
		clk_disable_unprepare(host->ciu_clk);
	dev_vdbg(host->dev, " %s --\n", __func__);

	return 0;
}

static int dw_mci_hs_runtime_resume(struct device *dev)
{
	struct dw_mci *host = dev_get_drvdata(dev);

	dev_vdbg(host->dev, " %s ++\n", __func__);
	if (!IS_ERR(host->biu_clk)) {
		if (clk_prepare_enable(host->biu_clk))
			dev_err(host->dev, "biu_clk clk_prepare_enable failed\n");
	}

	if (!IS_ERR(host->ciu_clk)) {
		if (clk_prepare_enable(host->ciu_clk))
			dev_err(host->dev, "ciu_clk clk_prepare_enable failed\n");
	}

	dev_vdbg(host->dev, " %s --\n", __func__);
	return 0;
}
#endif

void dw_mci_reg_dump(struct dw_mci *host)
{
	u32 status, mintsts;

	dev_info(host->dev, ": ============== REGISTER DUMP ==============\n");
	dev_info(host->dev, ": CTRL:	0x%08x\n", mci_readl(host, CTRL));
	dev_info(host->dev, ": PWREN:	0x%08x\n", mci_readl(host, PWREN));
	dev_info(host->dev, ": CLKDIV:	0x%08x\n", mci_readl(host, CLKDIV));
	dev_info(host->dev, ": CLKSRC:	0x%08x\n", mci_readl(host, CLKSRC));
	dev_info(host->dev, ": CLKENA:	0x%08x\n", mci_readl(host, CLKENA));
	dev_info(host->dev, ": TMOUT:	0x%08x\n", mci_readl(host, TMOUT));
	dev_info(host->dev, ": CTYPE:	0x%08x\n", mci_readl(host, CTYPE));
	dev_info(host->dev, ": BLKSIZ:	0x%08x\n", mci_readl(host, BLKSIZ));
	dev_info(host->dev, ": BYTCNT:	0x%08x\n", mci_readl(host, BYTCNT));
	dev_info(host->dev, ": INTMSK:	0x%08x\n", mci_readl(host, INTMASK));
	dev_info(host->dev, ": CMDARG:	0x%08x\n", mci_readl(host, CMDARG));
	dev_info(host->dev, ": CMD:	0x%08x\n", mci_readl(host, CMD));
	dev_info(host->dev, ": MINTSTS:	0x%08x\n", mci_readl(host, MINTSTS));
	dev_info(host->dev, ": RINTSTS:	0x%08x\n", mci_readl(host, RINTSTS));
	dev_info(host->dev, ": STATUS:	0x%08x\n", mci_readl(host, STATUS));
	dev_info(host->dev, ": FIFOTH:	0x%08x\n", mci_readl(host, FIFOTH));
	dev_info(host->dev, ": CDETECT:	0x%08x\n", mci_readl(host, CDETECT));
	dev_info(host->dev, ": WRTPRT:	0x%08x\n", mci_readl(host, WRTPRT));
	dev_info(host->dev, ": GPIO:	0x%08x\n", mci_readl(host, GPIO));
	dev_info(host->dev, ": TCBCNT:	0x%08x\n", mci_readl(host, TCBCNT));
	dev_info(host->dev, ": TBBCNT:	0x%08x\n", mci_readl(host, TBBCNT));
	dev_info(host->dev, ": DEBNCE:	0x%08x\n", mci_readl(host, DEBNCE));
	dev_info(host->dev, ": USRID:	0x%08x\n", mci_readl(host, USRID));
	dev_info(host->dev, ": VERID:	0x%08x\n", mci_readl(host, VERID));
	dev_info(host->dev, ": HCON:	0x%08x\n", mci_readl(host, HCON));
	dev_info(host->dev, ": UHS_REG:	0x%08x\n", mci_readl(host, UHS_REG));
	dev_info(host->dev, ": BMOD:	0x%08x\n", mci_readl(host, BMOD));
	dev_info(host->dev, ": PLDMND:	0x%08x\n", mci_readl(host, PLDMND));
	if (host->dma_64bit_address == SDMMC_32_BIT_DMA) {
		dev_info(host->dev, ": DBADDR:	0x%08x\n",
			mci_readl(host, DBADDR));
		dev_info(host->dev, ": IDSTS:    0x%08x\n",
			mci_readl(host, IDSTS));
		dev_info(host->dev, ": IDINTEN:	0x%08x\n",
			mci_readl(host, IDINTEN));
		dev_info(host->dev, ": DSCADDR:	0x%08x\n",
			mci_readl(host, DSCADDR));
		dev_info(host->dev, ": BUFADDR:	0x%08x\n",
			mci_readl(host, BUFADDR));
	} else {
		dev_info(host->dev, ": DBADDRL:	0x%08x\n",
			mci_readl(host, DBADDRL));
		dev_info(host->dev, ": DBADDRU:	0x%08x\n",
			mci_readl(host, DBADDRU));
		dev_info(host->dev, ": IDSTS:    0x%08x\n",
			mci_readl(host, IDSTS64));
		dev_info(host->dev, ": IDINTEN:	0x%08x\n",
			mci_readl(host, IDINTEN64));
	}
	dev_info(host->dev, ": CDTHRCTL:	0x%08x\n",
			mci_readl(host, CDTHRCTL));
	dev_info(host->dev, ": UHS_REG_EXT:	0x%08x\n",
			mci_readl(host, UHS_REG_EXT));
	dev_info(host->dev, ": ============== STATUS DUMP ================\n");
	dev_info(host->dev, ": cmd_status:      0x%08x\n", host->cmd_status);
	dev_info(host->dev, ": data_status:     0x%08x\n", host->data_status);
	dev_info(host->dev, ": pending_events:  0x%08lx\n",
			host->pending_events);
	dev_info(host->dev, ": completed_events:0x%08lx\n",
			host->completed_events);
	dev_info(host->dev, ": state:           %d\n", host->state);
	dev_info(host->dev, ": ===========================================\n");

	/* summary */
	mintsts = mci_readl(host, MINTSTS);
	status = mci_readl(host, STATUS);
	dev_info(host->dev, "CMD%d, ARG=0x%08x, intsts : %s, status : %s.\n",
			mci_readl(host, CMD) & 0x3F,
			mci_readl(host, CMDARG),
			mintsts & 0x8 ? "Data transfer done" :
			mintsts & 0x4 ? "Command Done" : "refer to dump",
			status & (0x1 << 9) ? "dat0 busy" : "refer to dump");
	dev_info(host->dev, ": RESP0:	0x%08x\n", mci_readl(host, RESP0));
	dev_info(host->dev, ": RESP1:	0x%08x\n", mci_readl(host, RESP1));
	dev_info(host->dev, ": RESP2:	0x%08x\n", mci_readl(host, RESP2));
	dev_info(host->dev, ": RESP3:	0x%08x\n", mci_readl(host, RESP3));
	dev_info(host->dev, ": host : cmd_status=0x%08x, data_status=0x%08x.\n",
			host->cmd_status, host->data_status);
	dev_info(host->dev,
		": host : pending_events=0x%08lx,\n", host->pending_events);
	dev_info(host->dev,
		"completed_events=0x%08lx.\n", host->completed_events);
	dev_info(host->dev, ": ===========================================\n");
}
EXPORT_SYMBOL(dw_mci_reg_dump);

#ifdef CONFIG_MMC_HISI_TRACE
void dw_mci_reg_dump_fortrace(struct mmc_host *mmc)
{
	u32 status, mintsts;
	struct dw_mci_slot *slot = mmc_priv(mmc);
	struct dw_mci *host = slot->host;

	pm_runtime_get_sync(mmc_dev(mmc));

	mmc_trace_comm_record(mmc,
			": =========== REGISTER DUMP (%s)===========\n",
			mmc_hostname(mmc));

	mmc_trace_comm_record(mmc,
			": ============== REGISTER DUMP ==============\n");
	mmc_trace_comm_record(mmc, ": CTRL:	0x%x\n",
			mci_readl(host, CTRL));
	mmc_trace_comm_record(mmc, ": PWREN:	0x%x\n",
			mci_readl(host, PWREN));
	mmc_trace_comm_record(mmc, ": CLKDIV:	0x%x\n",
			mci_readl(host, CLKDIV));
	mmc_trace_comm_record(mmc, ": CLKSRC:	0x%x\n",
			mci_readl(host, CLKSRC));
	mmc_trace_comm_record(mmc, ": CLKENA:	0x%x\n",
			mci_readl(host, CLKENA));
	mmc_trace_comm_record(mmc, ": TMOUT:	0x%x\n",
			mci_readl(host, TMOUT));
	mmc_trace_comm_record(mmc, ": CTYPE:	0x%x\n",
			mci_readl(host, CTYPE));
	mmc_trace_comm_record(mmc, ": BLKSIZ:	0x%x\n",
			mci_readl(host, BLKSIZ));
	mmc_trace_comm_record(mmc, ": BYTCNT:	0x%x\n",
			mci_readl(host, BYTCNT));
	mmc_trace_comm_record(mmc, ": INTMSK:	0x%x\n",
			mci_readl(host, INTMASK));
	mmc_trace_comm_record(mmc, ": CMDARG:	0x%x\n",
			mci_readl(host, CMDARG));
	mmc_trace_comm_record(mmc, ": CMD:	0x%x\n",
			mci_readl(host, CMD));
	mmc_trace_comm_record(mmc, ": MINTSTS:	0x%x\n",
			mci_readl(host, MINTSTS));
	mmc_trace_comm_record(mmc, ": RINTSTS:	0x%x\n",
			mci_readl(host, RINTSTS));
	mmc_trace_comm_record(mmc, ": STATUS:	0x%x\n",
			mci_readl(host, STATUS));
	mmc_trace_comm_record(mmc, ": FIFOTH:	0x%x\n",
			mci_readl(host, FIFOTH));
	mmc_trace_comm_record(mmc, ": CDETECT:	0x%x\n",
			mci_readl(host, CDETECT));
	mmc_trace_comm_record(mmc, ": WRTPRT:	0x%x\n",
			mci_readl(host, WRTPRT));
	mmc_trace_comm_record(mmc, ": GPIO:	0x%x\n",
			mci_readl(host, GPIO));
	mmc_trace_comm_record(mmc, ": TCBCNT:	0x%x\n",
			mci_readl(host, TCBCNT));
	mmc_trace_comm_record(mmc, ": TBBCNT:	0x%x\n",
			mci_readl(host, TBBCNT));
	mmc_trace_comm_record(mmc, ": DEBNCE:	0x%x\n",
			mci_readl(host, DEBNCE));
	mmc_trace_comm_record(mmc, ": USRID:	0x%x\n",
			mci_readl(host, USRID));
	mmc_trace_comm_record(mmc, ": VERID:	0x%x\n",
			mci_readl(host, VERID));
	mmc_trace_comm_record(mmc, ": HCON:	0x%x\n",
			mci_readl(host, HCON));
	mmc_trace_comm_record(mmc, ": UHS_REG:	0x%x\n",
			mci_readl(host, UHS_REG));
	mmc_trace_comm_record(mmc, ": BMOD:	0x%08x\n",
			mci_readl(host, BMOD));
	mmc_trace_comm_record(mmc, ": PLDMND:	0x%x\n",
			mci_readl(host, PLDMND));
	mmc_trace_comm_record(mmc, ": DBADDR:	0x%x\n",
			mci_readl(host, DBADDR));
	mmc_trace_comm_record(mmc, ": IDSTS:	0x%x\n",
			mci_readl(host, IDSTS));
	mmc_trace_comm_record(mmc, ": IDINTEN:	0x%x\n",
			mci_readl(host, IDINTEN));
	mmc_trace_comm_record(mmc, ": DSCADDR:	0x%x\n",
			mci_readl(host, DSCADDR));
	mmc_trace_comm_record(mmc, ": BUFADDR:	0x%x\n",
			mci_readl(host, BUFADDR));
	mmc_trace_comm_record(mmc, ": CDTHRCTL:	0x%x\n",
			mci_readl(host, CDTHRCTL));
	mmc_trace_comm_record(mmc, ": UHS_REG_EXT:	0x%x\n",
			mci_readl(host, UHS_REG_EXT));
	mmc_trace_comm_record(mmc,
			": ============== STATUS DUMP ================\n");
	mmc_trace_comm_record(mmc, ": cmd_status:      0x%x\n",
			host->cmd_status);
	mmc_trace_comm_record(mmc, ": data_status:     0x%x\n",
			host->data_status);
	mmc_trace_comm_record(mmc, ": pending_events:  0x%x\n",
			host->pending_events);
	mmc_trace_comm_record(mmc, ": completed_events:0x%x\n",
			host->completed_events);
	mmc_trace_comm_record(mmc, ": state:           %d\n",
			host->state);
	mmc_trace_comm_record(mmc,
			": ===========================================\n");

	/* summary */
	mintsts = mci_readl(host, MINTSTS);
	status = mci_readl(host, STATUS);
	mmc_trace_comm_record(mmc,
			"CMD%d, ARG=0x%x, intsts : %s, status : %s.\n",
			mci_readl(host, CMD) & 0x3F,
			mci_readl(host, CMDARG),
			mintsts & 0x8 ? "Data transfer done" :
			mintsts & 0x4 ? "Command Done" : "refer to dump",
			status & (0x1 << 9) ? "dat0 busy" : "refer to dump");
	mmc_trace_comm_record(mmc,
			": RESP0:	0x%x\n", mci_readl(host, RESP0));
	mmc_trace_comm_record(mmc,
			": RESP1:	0x%x\n", mci_readl(host, RESP1));
	mmc_trace_comm_record(mmc,
			": RESP2:	0x%x\n", mci_readl(host, RESP2));
	mmc_trace_comm_record(mmc,
			": RESP3:	0x%x\n", mci_readl(host, RESP3));
	mmc_trace_comm_record(mmc,
			": host : cmd_status=0x%x, data_status=0x%x.\n",
			host->cmd_status, host->data_status);
	mmc_trace_comm_record(mmc,
			": host : pending_events=0x%x,completed_events=0x%x.\n",
			host->pending_events, host->completed_events);

	pm_runtime_mark_last_busy(mmc_dev(mmc));
	pm_runtime_put_autosuspend(mmc_dev(mmc));

	mmc_trace_comm_record(mmc,
		": ===========================================\n");
}
#endif

bool dw_mci_stop_abort_cmd(struct mmc_command *cmd)
{
	u32 op = cmd->opcode;

	if ((op == MMC_STOP_TRANSMISSION) ||
	    (op == MMC_GO_IDLE_STATE) ||
	    (op == MMC_GO_INACTIVE_STATE) ||
	    ((op == SD_IO_RW_DIRECT) && (cmd->arg & 0x80000000) &&
	     ((cmd->arg >> 9) & 0x1FFFF) == SDIO_CCCR_ABORT))
		return true;
	return false;
}

bool dw_mci_wait_reset(struct device *dev, struct dw_mci *host,
		unsigned int reset_val)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(50);
	unsigned int ctrl;

	ctrl = mci_readl(host, CTRL);
	ctrl |= reset_val;
	mci_writel(host, CTRL, ctrl);

	/* wait till resets clear */
	do {
		if (!(mci_readl(host, CTRL) & reset_val))
			return true;
	} while (time_before(jiffies, timeout));

	dev_warn(dev, "Timeout resetting block (ctrl %#x)\n", ctrl);

	return false;
}
EXPORT_SYMBOL(dw_mci_wait_reset);

static int mci_send_cmd(struct dw_mci_slot *slot, u32 cmd, u32 arg)
{
	struct dw_mci *host = slot->host;
	unsigned long timeout = jiffies + msecs_to_jiffies(100);
	unsigned int cmd_status = 0;

	mci_writel(host, CMDARG, arg);
	/* synchronous execution */
	wmb();
	mci_writel(host, CMD, SDMMC_CMD_START | cmd);
	while (time_before(jiffies, timeout)) {
		cmd_status = mci_readl(host, CMD);
		if (!(cmd_status & SDMMC_CMD_START))
			return 0;
	}

	if (!dw_mci_wait_reset(host->dev, host, SDMMC_CTRL_RESET))
		return 1;

	timeout = jiffies + msecs_to_jiffies(100);
	mci_writel(host, CMD, SDMMC_CMD_START | cmd);
	while (time_before(jiffies, timeout)) {
		cmd_status = mci_readl(host, CMD);
		if (!(cmd_status & SDMMC_CMD_START))
			return 0;
	}

	dev_info(&slot->mmc->class_dev,
		"Timeout sending command (cmd %#x arg %#x status %#x)\n",
		cmd, arg, cmd_status);
	return 1;
}

void dw_mci_ciu_reset(struct device *dev, struct dw_mci *host)
{
	struct dw_mci_slot *slot = host->cur_slot;

	if (slot) {
		if (!dw_mci_wait_reset(dev, host, SDMMC_CTRL_RESET))
			dev_info(dev, "dw_mci_wait_reset failed\n");

		mci_send_cmd(slot, SDMMC_CMD_UPD_CLK |
			SDMMC_CMD_PRV_DAT_WAIT, 0);
	}
}
EXPORT_SYMBOL(dw_mci_ciu_reset);

bool dw_mci_fifo_reset(struct device *dev, struct dw_mci *host)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(1000);
	unsigned int ctrl;
	bool result;

	do {
		result = dw_mci_wait_reset(host->dev,
			host, SDMMC_CTRL_FIFO_RESET);

		if (!result)
			break;

		ctrl = mci_readl(host, STATUS);
		if (!(ctrl & SDMMC_STATUS_DMA_REQ)) {
			result = dw_mci_wait_reset(host->dev, host,
					SDMMC_CTRL_FIFO_RESET);
			if (result) {
				/* clear exception raw interrupts */
				/* can not be handled */
				/* ex fifo full => RXDR interrupt rising */
				ctrl = mci_readl(host, RINTSTS);
				ctrl = ctrl & ~(mci_readl(host, MINTSTS));
				if (ctrl)
					mci_writel(host, RINTSTS, ctrl);

				return true;
			}
		}
	} while (time_before(jiffies, timeout));

	dev_warn(dev, "%s: Timeout while resetting host controller after err\n",
		__func__);

	return false;
}
EXPORT_SYMBOL(dw_mci_fifo_reset);

u32 dw_mci_prep_stop(struct dw_mci *host, struct mmc_command *cmd)
{
	struct mmc_command *stop = &host->stop;
	const struct dw_mci_drv_data *drv_data = host->drv_data;
	u32 cmdr = cmd->opcode;

	memset(stop, 0, sizeof(struct mmc_command));

	if (cmdr == SD_IO_RW_EXTENDED) {
		stop->opcode = SD_IO_RW_DIRECT;
		stop->arg = 0x80000000;
		stop->arg |= (cmd->arg >> 28) & 0x7;
		stop->arg |= SDIO_CCCR_ABORT << 9;
		stop->flags = MMC_RSP_SPI_R5 | MMC_RSP_R5 | MMC_CMD_AC;
	} else {
		stop->opcode = MMC_STOP_TRANSMISSION;
		stop->arg = 0;
		stop->flags = MMC_RSP_R1B | MMC_CMD_AC;
	}

	cmdr = stop->opcode | SDMMC_CMD_STOP |
		SDMMC_CMD_RESP_CRC | SDMMC_CMD_RESP_EXP;

	/* Use hold bit register */
	if (drv_data && drv_data->prepare_command)
		drv_data->prepare_command(host, &cmdr);

	return cmdr;
}
EXPORT_SYMBOL(dw_mci_prep_stop);

bool dw_mci_wait_data_busy(struct dw_mci *host, struct mmc_request *mrq)
{
	u32 status;
	unsigned long timeout = jiffies + msecs_to_jiffies(500);

	do {
		status = mci_readl(host, STATUS);
		if (!(status & SDMMC_STATUS_BUSY))
			return true;

		usleep_range(10, 20);
	} while (time_before(jiffies, timeout));

	/* card is checked every 1s by CMD13 at least */
	if (mrq->cmd->opcode == MMC_SEND_STATUS)
		return true;

	dev_info(host->dev, "status is busy, reset ctrl\n");

	if (!dw_mci_wait_reset(host->dev, host, SDMMC_CTRL_RESET))
		return false;

	/* After CTRL Reset, Should be needed clk val to CIU */
	if (host->cur_slot)
		mci_send_cmd(host->cur_slot,
			SDMMC_CMD_UPD_CLK | SDMMC_CMD_PRV_DAT_WAIT, 0);

	timeout = jiffies + msecs_to_jiffies(500);
	do {
		status = mci_readl(host, STATUS);
		if (!(status & SDMMC_STATUS_BUSY))
			return true;

		usleep_range(10, 20);
	} while (time_before(jiffies, timeout));


	dev_warn(host->dev, "Data[0]: data is busy\n");

	return false;
}

void dw_mci_set_cd(struct dw_mci *host)
{

	if (host == NULL)
		return;
	if (host->slot && host->slot->mmc) {
		dev_dbg(&host->slot->mmc->class_dev, "sdio_present = %d\n",
			host->slot->mmc->sdio_present);
		host->slot->mmc->sdio_present = 1;
	}
}

int dw_mci_start_signal_voltage_switch(struct mmc_host *mmc,
		struct mmc_ios *ios)
{
	struct dw_mci_slot *slot = mmc_priv(mmc);
	struct dw_mci *host = slot->host;
	const struct dw_mci_drv_data *drv_data = host->drv_data;
	int err = -ENOSYS;

	if (drv_data && drv_data->start_signal_voltage_switch)
		err = drv_data->start_signal_voltage_switch(mmc, ios);

	return err;
}
EXPORT_SYMBOL(dw_mci_start_signal_voltage_switch);

void dw_mci_slowdown_clk(struct mmc_host *mmc, int timing)
{
	struct dw_mci_slot *slot = mmc_priv(mmc);
	struct dw_mci *host = slot->host;
	const struct dw_mci_drv_data *drv_data = host->drv_data;

	if (host->flags & DWMMC_TUNING_DONE)
		host->flags &= ~DWMMC_TUNING_DONE;

	if (drv_data->slowdown_clk) {
		if (host->sd_reinit)
			return;

		host->sd_reinit = 1;
		pm_runtime_get_sync(mmc_dev(mmc));
		drv_data->slowdown_clk(host, timing);
		pm_runtime_mark_last_busy(mmc_dev(mmc));
		pm_runtime_put_autosuspend(mmc_dev(mmc));

	}

}
EXPORT_SYMBOL(dw_mci_slowdown_clk);

void dw_mci_timeout_timer(struct timer_list *t)
{
	struct dw_mci *host = from_timer(host, t, timer);
	struct mmc_request *mrq;


	if (host) {
		spin_lock(&host->lock);
		if (host->mrq) {
			mrq = host->mrq;
			dev_vdbg(host->dev, "time out host->mrq = %pK\n",
				host->mrq);

			dev_warn(host->dev,
				"Timeout waiting for hardware interrupt.");
			dev_warn(host->dev, " state = %d\n", host->state);
			dw_mci_reg_dump(host);

			host->sg = NULL;
			host->data = NULL;
			host->cmd = NULL;

			switch (host->state) {
			case STATE_IDLE:
				break;
			case STATE_SENDING_CMD:
				mrq->cmd->error = -ENOMEDIUM;
				if (!mrq->data)
					break;
			/* fall through */
			case STATE_SENDING_DATA:
				mrq->data->error = -ENOMEDIUM;
				dw_mci_stop_dma(host);
				break;
			case STATE_DATA_BUSY:
			case STATE_DATA_ERROR:
				if (mrq->data->error == -EINPROGRESS)
					mrq->data->error = -ENOMEDIUM;
				/* fall through */
			case STATE_SENDING_STOP:
				if (mrq->stop)
					mrq->stop->error = -ENOMEDIUM;
				break;
			}

			host->sd_hw_timeout = 1;

			dw_mci_fifo_reset(host->dev, host);
			dw_mci_ciu_reset(host->dev, host);

			dw_mci_request_end(host, mrq);
		}
		spin_unlock(&host->lock);
	}
}
EXPORT_SYMBOL(dw_mci_timeout_timer);

void dw_mci_work_routine_queue_clean(struct dw_mci *host)
{
	struct dw_mci_slot *slot = host->slot;
	struct mmc_request *mrq;

	mrq = slot->mrq;
	if (mrq) {
		if (mrq == host->mrq) {
			host->data = NULL;
			host->cmd = NULL;

			switch (host->state) {
			case STATE_IDLE:
				break;
			case STATE_SENDING_CMD:
				mrq->cmd->error = -ENOMEDIUM;
				if (!mrq->data)
					break;
				/* fall through */
			case STATE_SENDING_DATA:
				mrq->data->error = -ENOMEDIUM;
				dw_mci_stop_dma(host);
				break;
			case STATE_DATA_BUSY:
			case STATE_DATA_ERROR:
				if (mrq->data->error == -EINPROGRESS)
					mrq->data->error = -ENOMEDIUM;
				if (!mrq->stop)
					break;
				/* fall through */
			case STATE_SENDING_STOP:
				if (mrq->stop)
					mrq->stop->error = -ENOMEDIUM;
				break;
			}

			dw_mci_request_end(host, mrq);
		} else {
			list_del(&slot->queue_node);
			mrq->cmd->error = -ENOMEDIUM;
			if (mrq->data)
				mrq->data->error = -ENOMEDIUM;
			if (mrq->stop)
				mrq->stop->error = -ENOMEDIUM;

			if (del_timer(&host->timer) != 0)
				dev_info(host->dev, "del_timer failed\n");
			spin_unlock(&host->lock);
			mmc_request_done(slot->mmc, mrq);
			spin_lock(&host->lock);
		}
	}

}

void dw_mci_work_routine_card(struct work_struct *work)
{
	struct dw_mci *host = container_of(work, struct dw_mci, card_work);
	int i;

	for (i = 0; i < host->num_slots; i++) {
		struct dw_mci_slot *slot = host->slot;
		struct mmc_host *mmc = slot->mmc;
		int present;

		present = hisi_dw_mci_get_cd(mmc);
		while (present != slot->last_detect_state) {
			dev_dbg(&slot->mmc->class_dev, "card %s\n",
				present ? "inserted" : "removed");

			spin_lock_bh(&host->lock);

			/* Card change detected */
			slot->last_detect_state = present;

			/* Mark card as present if applicable */
			if (present != 0)
				set_bit(DW_MMC_CARD_PRESENT, &slot->flags);

			/* Clean up queue if present */
			dw_mci_work_routine_queue_clean(host);
			/* Power down slot */
			if (present == 0) {
				clear_bit(DW_MMC_CARD_PRESENT, &slot->flags);

				/*
				 * Clear down the FIFO - doing so generates a
				 * block interrupt, hence setting the
				 * scatter-gather pointer to NULL.
				 */
				sg_miter_stop(&host->sg_miter);
				host->sg = NULL;

				dw_mci_fifo_reset(host->dev, host);
				dw_mci_ciu_reset(host->dev, host);
#ifdef CONFIG_MMC_DW_IDMAC
				dw_mci_idmac_reset(host);
#endif
			}

			spin_unlock_bh(&host->lock);

			present = hisi_dw_mci_get_cd(mmc);
		}

		mmc_detect_change(slot->mmc,
			msecs_to_jiffies(host->pdata->detect_delay_ms));
	}
}
EXPORT_SYMBOL(dw_mci_work_routine_card);

bool mci_wait_reset(struct device *dev, struct dw_mci *host)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(50);
	unsigned int ctrl;

	mci_writel(host, CTRL, (SDMMC_CTRL_RESET | SDMMC_CTRL_FIFO_RESET |
				SDMMC_CTRL_DMA_RESET));

	/* wait till resets clear */
	do {
		ctrl = mci_readl(host, CTRL);
		if (!(ctrl & (SDMMC_CTRL_RESET | SDMMC_CTRL_FIFO_RESET |
			      SDMMC_CTRL_DMA_RESET)))
			return true;
	} while (time_before(jiffies, timeout));

	dev_warn(dev, "Timeout resetting block (ctrl %#x)\n", ctrl);

	return false;
}
EXPORT_SYMBOL(mci_wait_reset);

static const struct dev_pm_ops dw_mci_hs_pmops = {
	SET_SYSTEM_SLEEP_PM_OPS(dw_mci_hs_suspend, dw_mci_hs_resume)
	SET_RUNTIME_PM_OPS(dw_mci_hs_runtime_suspend,
			   dw_mci_hs_runtime_resume, NULL)
};

static struct platform_driver dw_mci_hs_pltfm_driver = {
	.probe = dw_mci_hs_probe,
	.remove = dw_mci_pltfm_remove,
	.driver = {
			   .name = DRIVER_NAME,
			   .of_match_table = of_match_ptr(dw_mci_hs_match),
			   .pm = &dw_mci_hs_pmops,
			   },
};

module_platform_driver(dw_mci_hs_pltfm_driver);

MODULE_DESCRIPTION("Hisilicon Specific DW-MSHC Driver Extension");
MODULE_LICENSE("GPL v2");
#pragma GCC diagnostic pop
