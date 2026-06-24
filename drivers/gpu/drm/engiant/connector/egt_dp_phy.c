// SPDX-License-Identifier: GPL-2.0
/*
 * DisplayPort PHY Driver functions
 *
 * Copyright (c) 2019-2026, New H3C Semiconductor Technologies Co., Ltd.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include "egt_dp.h"
#include "egt_dp_phy.h"

static inline void egt_dc_clock_write(struct egt_displayport *dp, u32 reg, u32 value)
{
	writel(value, dp->mem_base.pixel_pll_base + reg);
}

static inline u32 egt_dc_clock_read(struct egt_displayport *dp, u32 reg)
{
	u32 value = readl(dp->mem_base.pixel_pll_base + reg);

	return value;
}

static inline void egt_dp_pcie_write(struct egt_displayport *dp, u32 reg, u32 value)
{
	writel(value, dp->mem_base.crg_base + reg);
}

static inline void egt_dp_phy_write(struct egt_displayport *dp, u32 reg, u32 value)
{
	writel(value, dp->mem_base.dp_phy1_base + reg);
}

static inline u32 egt_dp_phy_read(struct egt_displayport *dp, u32 reg)
{
	u32 value = readl(dp->mem_base.dp_phy1_base + reg);

	return value;
}

static void egt_dp_after_phy_locked(struct egt_displayport *dp, u8 bw_code)
{
	int i = 0;

	pr_debug("egt phy config\n");
	if (bw_code == EGT_TX_LINK_BW_5_4)
		egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG3, 0x0003a00);

	egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG13, 0x10000000);
	egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG15, 0x00000000);

	if (bw_code == EGT_TX_LINK_BW_5_4)
		egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG3, 0x0003a00);

	egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG8, 0x00000318);
	udelay(1);
	egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG8, 0x00000b18);

	egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG4, 0x7d555000);
	egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG5, 0x00ffffff);

	for (i = 0; i < 2; i++)
		egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG49, 0x00c18006);

	egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG49, 0x00c00006);
}

void egt_dp_set_phy(struct egt_displayport *dp, u8 bw_code)
{
	u32 reg_val = 0;
	unsigned int timeout_us = 3000000;
	s64 elapsed_us = 0;
	ktime_t start_time = 0;

	pr_debug("egt phy start pll config, training rate is 0x%x\n", bw_code);
	egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG49, 0x0c4bc06);

	if (bw_code == EGT_TX_LINK_BW_1_62) {
		egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG3, 0x00a3a00);
		egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG50, 0x01e3009);
	} else if (bw_code == EGT_TX_LINK_BW_2_7) {
		egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG3, 0x0083a00);
		egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG50, 0x0191009);
	} else if (bw_code == EGT_TX_LINK_BW_5_4) {
		egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG50, 0x0191009);
	} else {
		pr_err("training rate error\n");
	}
	egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG51, 0x000001c);
	egt_dp_phy_write(dp, EGT_DP_PHY_CONFIG49, 0x0c08006);

	/* check phy pll locked status */
	reg_val = egt_dp_phy_read(dp, EGT_DP_PHY_CONFIG57);
	if (reg_val & (1 << 0)) {
		pr_debug("egt phy pll lock quickly! lock = 0x%x\n", reg_val);
	} else {
		udelay(50);
		start_time = ktime_get();

		do {
			reg_val = egt_dp_phy_read(dp, EGT_DP_PHY_CONFIG57);
			if (reg_val & (1 << 0)) {
				pr_debug("egt phy pll lock ok! lock = 0x%x\n", reg_val);
				break;
			}

			elapsed_us = ktime_to_us(ktime_sub(ktime_get(), start_time));
			if (elapsed_us > timeout_us) {
				pr_err("phy lock: timeout=%u us, elapsed=%lld us\n",
					timeout_us, (long long)elapsed_us);
				return;
			}

			usleep_range(100, 200);
		} while (1);
	}

	egt_dp_after_phy_locked(dp, bw_code);
}

static void egt_dp_pixel_pll_cfg(struct egt_displayport *dp,
					struct egt_dc_pll_config *config)
{
	u32 pll_cfg1 = 0;
	u32 pll_cfg2 = 0;
	u32 pll_cfg3 = 0;
	u32 reg_val = 0;
	u32 N0 = 0;
	u32 F = 0;
	u16 M = 0;
	u8 N1 = 0;
	u8 N2 = 0;
	u8 div_clk = 0;
	unsigned int timeout_us = 3000000;
	s64 elapsed_us = 0;
	ktime_t start_time = 0;

	N0 = (uint32_t)config->N0_cfg << 16;
	N1 = config->N1_cfg;
	N2 = config->N2_cfg << 4;
	M =  config->M_cfg;
	F =  config->F_cfg;

	div_clk = config->div_clk;

	pll_cfg1 = egt_dc_clock_read(dp, EGT_DCDP_PLL_CFG1) & (~0x3F0FFF);
	pll_cfg2 = egt_dc_clock_read(dp, EGT_DCDP_PLL_CFG2) & (~0xFF);
	pll_cfg3 = egt_dc_clock_read(dp, EGT_DCDP_PLL_CFG3) & (~0xFFFFFF);

	egt_dc_clock_write(dp, EGT_DCDP_PLL_CFG1, pll_cfg1 | N0 | M);
	egt_dc_clock_write(dp, EGT_DCDP_PLL_CFG2, pll_cfg2 | N1 | N2);
	egt_dc_clock_write(dp, EGT_DCDP_PLL_CFG3, pll_cfg3 | F);
	egt_dp_pcie_write(dp, EGT_DCDP_SEL, (div_clk - 1));

	reg_val = egt_dc_clock_read(dp, EGT_DCDP_PLL_CFG2);
	if (reg_val & (1 << 31)) {
		pr_debug("pixel pll lock quickly! lock = 0x%x\n", reg_val);
	} else {
		udelay(50);
		start_time = ktime_get();

		do {
			reg_val = egt_dc_clock_read(dp, EGT_DCDP_PLL_CFG2);
			if (reg_val & (1 << 31)) {
				pr_debug("pixel pll lock ok! lock = 0x%x\n", reg_val);
				break;
			}

			elapsed_us = ktime_to_us(ktime_sub(ktime_get(), start_time));
			if (elapsed_us > timeout_us) {
				pr_err("pll lock: timeout=%u us, elapsed=%lld us\n",
					timeout_us, (long long)elapsed_us);
				break;
			}

			usleep_range(100, 200);
		} while (1);
	}
}

static u32 egt_dp_try_pll_config(struct egt_dc_pll_config *config,
				struct egt_displayport *dp, uint8_t div_clk,
				uint8_t N0, u64 expect_pll_out2)
{
	const s32 REF_KHZ = 25000;
	const u64 F_SCALE = 16777216;
	u8 N1 = 0;
	u8 N2 = 0;
	u64 F = 0;
	u64 M = 0;
	u32 M_rem = 0;
	u64 vco_component = 0;
	u64 vco_khz = 0;
	u64 pll_out1_khz = 0;
	u64 auto_pll_out2 = 0;

	for (N2 = 0; N2 <= 15; N2++) {
		for (N1 = 0; N1 <= 15; N1++) {
			M = div_u64_rem((expect_pll_out2 * N0 * (N1+1) * (N2+1)),
					REF_KHZ, &M_rem);
			if (M < 40 || M > 4095)
				continue;

			F = div_u64(M_rem * F_SCALE, REF_KHZ);
			vco_component = (M * F_SCALE + F);
			vco_khz = div_u64(div_u64((REF_KHZ * vco_component), N0), F_SCALE);
			if (vco_khz < 950000 || vco_khz > 3800000)
				continue;

			pll_out1_khz = div_u64(vco_khz, (N1 + 1));
			auto_pll_out2 = div_u64(pll_out1_khz, (N2 + 1));

			if (abs_diff(auto_pll_out2, expect_pll_out2) > 100)
				continue;

			config->N0_cfg = N0;
			config->M_cfg = M;
			config->F_cfg = F;
			config->N1_cfg = N1;
			config->N2_cfg = N2;
			config->div_clk = div_clk;

			egt_dp_pixel_pll_cfg(dp, config);

			pr_debug("PLL Configuration:\n");
			pr_debug("  expect_pll_out2 is %llu\n",
					(unsigned long long)expect_pll_out2);
			pr_debug("  auto_pll_out2 is %llu\n",
					(unsigned long long)auto_pll_out2);
			pr_debug("  vco_khz: %llu (0x%llx)\n",
					(unsigned long long)vco_khz,
					(unsigned long long)vco_khz);
			pr_debug("  N0_cfg: %u (0x%02x)\n", config->N0_cfg, config->N0_cfg);
			pr_debug("  M_cfg: %u (0x%03x)\n", config->M_cfg, config->M_cfg);
			pr_debug("  F_cfg: %u (0x%06x)\n", config->F_cfg, config->F_cfg);
			pr_debug("  N1_cfg: %u (0x%x)\n", config->N1_cfg, config->N1_cfg);
			pr_debug("  N2_cfg: %u (0x%x)\n", config->N2_cfg, config->N2_cfg);
			pr_debug("  div_clk: %u (0x%x)\n", config->div_clk, config->div_clk);

			return 1;
		}
	}
	return 0;
}

static void egt_dp_calculate_pll_config(int freq_khz,
			struct egt_dc_pll_config *config, struct egt_displayport *dp)
{
	u8 div_clk = 0;
	u8 N0 = 0;
	u32 ret = 0;
	u64 expect_pll_out2 = 0;

	for (div_clk = 1; div_clk <= 127; div_clk++) {
		expect_pll_out2 = (u64)(freq_khz / 4) * div_clk;
		for (N0 = 1; N0 <= 127; N0++) {
			ret = egt_dp_try_pll_config(config, dp,
					div_clk, N0, expect_pll_out2);
			if (ret)
				return;
		}
	}
	pr_err("the best pll configuration was not found\n");
}

void egt_dp_pixel_pll_calculate(struct egt_displayport *dp, int pclk)
{
	struct egt_dc_pll_config config = {0};

	egt_dp_calculate_pll_config(pclk, &config, dp);
}

MODULE_DESCRIPTION("Engiant DP PHY Driver");
MODULE_LICENSE("GPL");
