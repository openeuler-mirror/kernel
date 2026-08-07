/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DisplayPort PHY Driver Header
 *
 * Copyright (c) 2019-2026, New H3C Semiconductor Technologies Co., Ltd.
 */

#ifndef __EGT_DP_PHY_H__
#define __EGT_DP_PHY_H__

#define EGT_DP_PHY_CONFIG3		0xc
#define EGT_DP_PHY_CONFIG4		0x10
#define EGT_DP_PHY_CONFIG5		0x14
#define EGT_DP_PHY_CONFIG8		0x20
#define EGT_DP_PHY_CONFIG13		0x34
#define EGT_DP_PHY_CONFIG15		0x3c
#define EGT_DP_PHY_CONFIG49		0xc4
#define EGT_DP_PHY_CONFIG50		0xc8
#define EGT_DP_PHY_CONFIG51		0xcc
#define EGT_DP_PHY_CONFIG52		0xd0
#define EGT_DP_PHY_CONFIG57		0xe4

#define EGT_DCDP_PLL_CFG1		(0x34)
#define EGT_DCDP_PLL_CFG2		(0x38)
#define EGT_DCDP_PLL_CFG3		(0x3c)
#define EGT_DCDP_SEL			(0x828)

struct egt_dc_pll_config {
	u8 N0_cfg;
	u16 M_cfg;
	u8 N1_cfg;
	u8 N2_cfg;
	u32 F_cfg;
	u8 div_clk;
};

void egt_dp_set_phy(struct egt_displayport *dp, u8 bw_code);
void egt_dp_pixel_pll_calculate(struct egt_displayport *dp, int pclk);

#endif /* __EGT_DP_PHY_H__ */

