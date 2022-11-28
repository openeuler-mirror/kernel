// SPDX-License-Identifier: GPL-2.0
/*
 * Hi3519A Clock Driver
 *
 * Copyright (c) 2016-2017 HiSilicon Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <linux/of_address.h>
#include <dt-bindings/clock/hi3519av100-clock.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include "clk.h"
#include "reset.h"

struct hi3519av100_pll_clock {
	u32             id;
	const char      *name;
	const char      *parent_name;
	u32             ctrl_reg1;
	u8              frac_shift;
	u8              frac_width;
	u8              postdiv1_shift;
	u8              postdiv1_width;
	u8              postdiv2_shift;
	u8              postdiv2_width;
	u32             ctrl_reg2;
	u8              fbdiv_shift;
	u8              fbdiv_width;
	u8              refdiv_shift;
	u8              refdiv_width;
};

struct hi3519av100_clk_pll {
	struct clk_hw   hw;
	u32             id;
	void __iomem    *ctrl_reg1;
	u8              frac_shift;
	u8              frac_width;
	u8              postdiv1_shift;
	u8              postdiv1_width;
	u8              postdiv2_shift;
	u8              postdiv2_width;
	void __iomem    *ctrl_reg2;
	u8              fbdiv_shift;
	u8              fbdiv_width;
	u8              refdiv_shift;
	u8              refdiv_width;
};

static struct hi3519av100_pll_clock hi3519av100_pll_clks[] __initdata = {
	{
		HI3519AV100_APLL_CLK, "apll", NULL, 0x0, 0, 24, 24, 3, 28, 3,
		0x4, 0, 12, 12, 6
	},
};

#define to_pll_clk(_hw) container_of(_hw, struct hi3519av100_clk_pll, hw)

/* soc clk config */
static struct hisi_fixed_rate_clock hi3519av100_fixed_rate_clks[] __initdata = {
	{ HI3519AV100_FIXED_2376M, "2376m", NULL, 0, 2376000000UL, },
	{ HI3519AV100_FIXED_1188M, "1188m", NULL, 0, 1188000000, },
	{ HI3519AV100_FIXED_594M, "594m", NULL, 0, 594000000, },
	{ HI3519AV100_FIXED_297M, "297m", NULL, 0, 297000000, },
	{ HI3519AV100_FIXED_148P5M, "148p5m", NULL, 0, 148500000, },
	{ HI3519AV100_FIXED_74P25M, "74p25m", NULL, 0, 74250000, },
	{ HI3519AV100_FIXED_792M, "792m", NULL, 0, 792000000, },
	{ HI3519AV100_FIXED_475M, "475m", NULL, 0, 475000000, },
	{ HI3519AV100_FIXED_340M, "340m", NULL, 0, 340000000, },
	{ HI3519AV100_FIXED_72M, "72m", NULL, 0, 72000000, },
	{ HI3519AV100_FIXED_400M, "400m", NULL, 0, 400000000, },
	{ HI3519AV100_FIXED_200M, "200m", NULL, 0, 200000000, },
	{ HI3519AV100_FIXED_54M, "54m", NULL, 0, 54000000, },
	{ HI3519AV100_FIXED_27M, "27m", NULL, 0, 1188000000, },
	{ HI3519AV100_FIXED_37P125M, "37p125m", NULL, 0, 37125000, },
	{ HI3519AV100_FIXED_3000M, "3000m", NULL, 0, 3000000000UL, },
	{ HI3519AV100_FIXED_1500M, "1500m", NULL, 0, 1500000000, },
	{ HI3519AV100_FIXED_500M, "500m", NULL, 0, 500000000, },
	{ HI3519AV100_FIXED_250M, "250m", NULL, 0, 250000000, },
	{ HI3519AV100_FIXED_125M, "125m", NULL, 0, 125000000, },
	{ HI3519AV100_FIXED_1000M, "1000m", NULL, 0, 1000000000, },
	{ HI3519AV100_FIXED_600M, "600m", NULL, 0, 600000000, },
	{ HI3519AV100_FIXED_750M, "750m", NULL, 0, 750000000, },
	{ HI3519AV100_FIXED_150M, "150m", NULL, 0, 150000000, },
	{ HI3519AV100_FIXED_75M, "75m", NULL, 0, 75000000, },
	{ HI3519AV100_FIXED_300M, "300m", NULL, 0, 300000000, },
	{ HI3519AV100_FIXED_60M, "60m", NULL, 0, 60000000, },
	{ HI3519AV100_FIXED_214M, "214m", NULL, 0, 214000000, },
	{ HI3519AV100_FIXED_107M, "107m", NULL, 0, 107000000, },
	{ HI3519AV100_FIXED_100M, "100m", NULL, 0, 100000000, },
	{ HI3519AV100_FIXED_50M, "50m", NULL, 0, 50000000, },
	{ HI3519AV100_FIXED_25M, "25m", NULL, 0, 25000000, },
	{ HI3519AV100_FIXED_24M, "24m", NULL, 0, 24000000, },
	{ HI3519AV100_FIXED_3M, "3m", NULL, 0, 3000000, },
	{ HI3519AV100_FIXED_100K, "100k", NULL, 0, 100000, },
	{ HI3519AV100_FIXED_400K, "400k", NULL, 0, 400000, },
	{ HI3519AV100_FIXED_49P5M, "49p5m", NULL, 0, 49500000, },
	{ HI3519AV100_FIXED_99M, "99m", NULL, 0, 99000000, },
	{ HI3519AV100_FIXED_187P5M, "187p5m", NULL, 0, 187500000, },
	{ HI3519AV100_FIXED_198M, "198m", NULL, 0, 198000000, },
};


static const char *fmc_mux_p[] __initconst = {
	"24m", "100m", "150m", "198m", "250m", "300m", "396m"
};
static u32 fmc_mux_table[] = {0, 1, 2, 3, 4, 5, 6};

static const char *mmc_mux_p[] __initconst = {
	"100k", "25m", "49p5m", "99m", "187p5m", "150m", "198m", "400k"
};
static u32 mmc_mux_table[] = {0, 1, 2, 3, 4, 5, 6, 7};

static const char *sysapb_mux_p[] __initconst = {
	"24m", "50m",
};
static u32 sysapb_mux_table[] = {0, 1};

static const char *sysbus_mux_p[] __initconst = {
	"24m", "300m"
};
static u32 sysbus_mux_table[] = {0, 1};

static const char *uart_mux_p[] __initconst = {"50m", "24m", "3m"};
static u32 uart_mux_table[] = {0, 1, 2};

static const char *a53_1_clksel_mux_p[] __initconst = {
	"24m", "apll", "vpll", "792m"
};
static u32 a53_1_clksel_mux_table[] = {0, 1, 2, 3};

static struct hisi_mux_clock hi3519av100_mux_clks[] __initdata = {
	{
		HI3519AV100_FMC_MUX, "fmc_mux", fmc_mux_p, ARRAY_SIZE(fmc_mux_p),
		CLK_SET_RATE_PARENT, 0x170, 2, 3, 0, fmc_mux_table,
	},

	{
		HI3519AV100_MMC0_MUX, "mmc0_mux", mmc_mux_p, ARRAY_SIZE(mmc_mux_p),
		CLK_SET_RATE_PARENT, 0x1a8, 24, 3, 0, mmc_mux_table,
	},

	{
		HI3519AV100_MMC1_MUX, "mmc1_mux", mmc_mux_p, ARRAY_SIZE(mmc_mux_p),
		CLK_SET_RATE_PARENT, 0x1ec, 24, 3, 0, mmc_mux_table,
	},

	{
		HI3519AV100_MMC2_MUX, "mmc2_mux", mmc_mux_p, ARRAY_SIZE(mmc_mux_p),
		CLK_SET_RATE_PARENT, 0x214, 24, 3, 0, mmc_mux_table,
	},

	{
		HI3519AV100_SYSAPB_MUX, "sysapb_mux", sysapb_mux_p, ARRAY_SIZE(sysapb_mux_p),
		CLK_SET_RATE_PARENT, 0xe8, 3, 1, 0, sysapb_mux_table
	},

	{
		HI3519AV100_SYSBUS_MUX, "sysbus_mux", sysbus_mux_p, ARRAY_SIZE(sysbus_mux_p),
		CLK_SET_RATE_PARENT, 0xe8, 0, 1, 1, sysbus_mux_table
	},

	{
		HI3519AV100_UART0_MUX, "uart0_mux", uart_mux_p, ARRAY_SIZE(uart_mux_p),
		CLK_SET_RATE_PARENT, 0x1a4, 0, 2, 1, uart_mux_table
	},

	{
		HI3519AV100_UART1_MUX, "uart1_mux", uart_mux_p, ARRAY_SIZE(uart_mux_p),
		CLK_SET_RATE_PARENT, 0x1a4, 2, 2, 1, uart_mux_table
	},

	{
		HI3519AV100_UART2_MUX, "uart2_mux", uart_mux_p, ARRAY_SIZE(uart_mux_p),
		CLK_SET_RATE_PARENT, 0x1a4, 4, 2, 1, uart_mux_table
	},

	{
		HI3519AV100_UART3_MUX, "uart3_mux", uart_mux_p, ARRAY_SIZE(uart_mux_p),
		CLK_SET_RATE_PARENT, 0x1a4, 6, 2, 1, uart_mux_table
	},

	{
		HI3519AV100_UART4_MUX, "uart4_mux", uart_mux_p, ARRAY_SIZE(uart_mux_p),
		CLK_SET_RATE_PARENT, 0x1a4, 8, 2, 1, uart_mux_table
	},

	{
		HI3519AV100_UART5_MUX, "uart5_mux", uart_mux_p, ARRAY_SIZE(uart_mux_p),
		CLK_SET_RATE_PARENT, 0x1a4, 10, 2, 1, uart_mux_table
	},

	{
		HI3519AV100_UART6_MUX, "uart6_mux", uart_mux_p, ARRAY_SIZE(uart_mux_p),
		CLK_SET_RATE_PARENT, 0x1a4, 12, 2, 1, uart_mux_table
	},

	{
		HI3519AV100_UART7_MUX, "uart7_mux", uart_mux_p, ARRAY_SIZE(uart_mux_p),
		CLK_SET_RATE_PARENT, 0x1a4, 14, 2, 1, uart_mux_table
	},

	{
		HI3519AV100_UART8_MUX, "uart8_mux", uart_mux_p, ARRAY_SIZE(uart_mux_p),
		CLK_SET_RATE_PARENT, 0x1a4, 28, 2, 1, uart_mux_table
	},

	{
		HI3519AV100_A53_1_MUX, "a53_1_mux", a53_1_clksel_mux_p,
		ARRAY_SIZE(a53_1_clksel_mux_p), CLK_SET_RATE_PARENT,
		0xe4, 10, 2, 3, a53_1_clksel_mux_table
	},

};

static struct hisi_fixed_factor_clock hi3519av100_fixed_factor_clks[] __initdata
	= {

};

static struct hisi_gate_clock hi3519av100_gate_clks[] __initdata = {
	{
		HI3519AV100_FMC_CLK, "clk_fmc", "fmc_mux",
		CLK_SET_RATE_PARENT, 0x170, 1, 0,
	},
	{
		HI3519AV100_MMC0_CLK, "clk_mmc0", "mmc0_mux",
		CLK_SET_RATE_PARENT, 0x1a8, 28, 0,
	},
	{
		HI3519AV100_MMC1_CLK, "clk_mmc1", "mmc1_mux",
		CLK_SET_RATE_PARENT, 0x1ec, 28, 0,
	},
	{
		HI3519AV100_MMC2_CLK, "clk_mmc2", "mmc2_mux",
		CLK_SET_RATE_PARENT, 0x214, 28, 0,
	},
	{
		HI3519AV100_UART0_CLK, "clk_uart0", "uart0_mux",
		CLK_SET_RATE_PARENT, 0x198, 16, 0,
	},
	{
		HI3519AV100_UART1_CLK, "clk_uart1", "uart1_mux",
		CLK_SET_RATE_PARENT, 0x198, 17, 0,
	},
	{
		HI3519AV100_UART2_CLK, "clk_uart2", "uart2_mux",
		CLK_SET_RATE_PARENT, 0x198, 18, 0,
	},
	{
		HI3519AV100_UART3_CLK, "clk_uart3", "uart3_mux",
		CLK_SET_RATE_PARENT, 0x198, 19, 0,
	},
	{
		HI3519AV100_UART4_CLK, "clk_uart4", "uart4_mux",
		CLK_SET_RATE_PARENT, 0x198, 20, 0,
	},
	{
		HI3519AV100_UART5_CLK, "clk_uart5", "uart5_mux",
		CLK_SET_RATE_PARENT, 0x198, 21, 0,
	},
	{
		HI3519AV100_UART6_CLK, "clk_uart6", "uart6_mux",
		CLK_SET_RATE_PARENT, 0x198, 22, 0,
	},
	{
		HI3519AV100_UART7_CLK, "clk_uart7", "uart7_mux",
		CLK_SET_RATE_PARENT, 0x198, 23, 0,
	},
	{
		HI3519AV100_UART8_CLK, "clk_uart8", "uart8_mux",
		CLK_SET_RATE_PARENT, 0x198, 29, 0,
	},
	{
		HI3519AV100_ETH_CLK, "clk_eth", NULL,
		CLK_SET_RATE_PARENT, 0x0174, 1, 0,
	},
	{
		HI3519AV100_ETH_MACIF_CLK, "clk_eth_macif", NULL,
		CLK_SET_RATE_PARENT, 0x0174, 5, 0,
	},
	/* i2c */
	{
		HI3519AV100_I2C0_CLK, "clk_i2c0", "50m",
		CLK_SET_RATE_PARENT, 0x01a0, 16, 0,
	},
	{
		HI3519AV100_I2C1_CLK, "clk_i2c1", "50m",
		CLK_SET_RATE_PARENT, 0x01a0, 17, 0,
	},
	{
		HI3519AV100_I2C2_CLK, "clk_i2c2", "50m",
		CLK_SET_RATE_PARENT, 0x01a0, 18, 0,
	},
	{
		HI3519AV100_I2C3_CLK, "clk_i2c3", "50m",
		CLK_SET_RATE_PARENT, 0x01a0, 19, 0,
	},
	{
		HI3519AV100_I2C4_CLK, "clk_i2c4", "50m",
		CLK_SET_RATE_PARENT, 0x01a0, 20, 0,
	},
	{
		HI3519AV100_I2C5_CLK, "clk_i2c5", "50m",
		CLK_SET_RATE_PARENT, 0x01a0, 21, 0,
	},
	{
		HI3519AV100_I2C6_CLK, "clk_i2c6", "50m",
		CLK_SET_RATE_PARENT, 0x01a0, 22, 0,
	},
	{
		HI3519AV100_I2C7_CLK, "clk_i2c7", "50m",
		CLK_SET_RATE_PARENT, 0x01a0, 23, 0,
	},
	{
		HI3519AV100_I2C8_CLK, "clk_i2c8", "50m",
		CLK_SET_RATE_PARENT, 0x01a0, 24, 0,
	},
	{
		HI3519AV100_I2C9_CLK, "clk_i2c9", "50m",
		CLK_SET_RATE_PARENT, 0x01a0, 25, 0,
	},
	{
		HI3519AV100_SPI0_CLK, "clk_spi0", "100m",
		CLK_SET_RATE_PARENT, 0x0198, 24, 0,
	},
	{
		HI3519AV100_SPI1_CLK, "clk_spi1", "100m",
		CLK_SET_RATE_PARENT, 0x0198, 25, 0,
	},
	{
		HI3519AV100_SPI2_CLK, "clk_spi2", "100m",
		CLK_SET_RATE_PARENT, 0x0198, 26, 0,
	},
	{
		HI3519AV100_SPI3_CLK, "clk_spi3", "100m",
		CLK_SET_RATE_PARENT, 0x0198, 27, 0,
	},
	{
		HI3519AV100_SPI4_CLK, "clk_spi4", "100m",
		CLK_SET_RATE_PARENT, 0x0198, 28, 0,
	},
	{
		HI3519AV100_EDMAC_AXICLK, "axi_clk_edmac", NULL,
		CLK_SET_RATE_PARENT, 0x16c, 6, 0,
	},
	{
		HI3519AV100_EDMAC_CLK, "clk_edmac", NULL,
		CLK_SET_RATE_PARENT, 0x16c, 5, 0,
	},
	{
		HI3519AV100_EDMAC1_AXICLK, "axi_clk_edmac1", NULL,
		CLK_SET_RATE_PARENT, 0x16c, 9, 0,
	},
	{
		HI3519AV100_EDMAC1_CLK, "clk_edmac1", NULL,
		CLK_SET_RATE_PARENT, 0x16c, 8, 0,
	},
	{
		HI3519AV100_VDMAC_CLK, "clk_vdmac", NULL,
		CLK_SET_RATE_PARENT, 0x14c, 5, 0,
	},
};

static void hi3519av100_calc_pll(u32 *frac_val,
				 u32 *postdiv1_val,
				 u32 *postdiv2_val,
				 u32 *fbdiv_val,
				 u32 *refdiv_val,
				 u64 rate)
{
	u64 rem;
	*frac_val = 0;
	rem = do_div(rate, 1000000);
	*fbdiv_val = rate;
	*refdiv_val = 24;
	if ((rem * (1 << 24)) > ULLONG_MAX) {
		pr_err("Data over limits!\n");
		return;
	}
	rem = rem * (1 << 24);
	do_div(rem, 1000000);
	*frac_val = rem;
}

static int clk_pll_set_rate(struct clk_hw *hw,
			    unsigned long rate,
			    unsigned long parent_rate)
{
	struct hi3519av100_clk_pll *clk = to_pll_clk(hw);
	u32 frac_val, postdiv1_val, postdiv2_val, fbdiv_val, refdiv_val;
	u32 val;

	postdiv1_val = postdiv2_val = 0;

	hi3519av100_calc_pll(&frac_val, &postdiv1_val, &postdiv2_val,
			     &fbdiv_val, &refdiv_val, rate);

	val = readl_relaxed(clk->ctrl_reg1);
	val &= ~(((1 << clk->frac_width) - 1) << clk->frac_shift);
	val &= ~(((1 << clk->postdiv1_width) - 1) << clk->postdiv1_shift);
	val &= ~(((1 << clk->postdiv2_width) - 1) << clk->postdiv2_shift);

	val |= frac_val << clk->frac_shift;
	val |= postdiv1_val << clk->postdiv1_shift;
	val |= postdiv2_val << clk->postdiv2_shift;
	writel_relaxed(val, clk->ctrl_reg1);

	val = readl_relaxed(clk->ctrl_reg2);
	val &= ~(((1 << clk->fbdiv_width) - 1) << clk->fbdiv_shift);
	val &= ~(((1 << clk->refdiv_width) - 1) << clk->refdiv_shift);

	val |= fbdiv_val << clk->fbdiv_shift;
	val |= refdiv_val << clk->refdiv_shift;
	writel_relaxed(val, clk->ctrl_reg2);

	return 0;
}

static unsigned long clk_pll_recalc_rate(struct clk_hw *hw,
		unsigned long parent_rate)
{
	struct hi3519av100_clk_pll *clk = to_pll_clk(hw);
	u64 frac_val, fbdiv_val;
	u32 val;
	u64 tmp, rate;
	u32 refdiv_val;

	val = readl_relaxed(clk->ctrl_reg1);
	val = val >> clk->frac_shift;
	val &= ((1 << clk->frac_width) - 1);
	frac_val = val;

	val = readl_relaxed(clk->ctrl_reg2);
	val = val >> clk->fbdiv_shift;
	val &= ((1 << clk->fbdiv_width) - 1);
	fbdiv_val = val;

	val = readl_relaxed(clk->ctrl_reg2);
	val = val >> clk->refdiv_shift;
	val &= ((1 << clk->refdiv_width) - 1);
	refdiv_val = val;

	/* rate = 24000000 * (fbdiv + frac / (1<<24) ) / refdiv  */
	rate = 0;
	if ((24000000 * fbdiv_val) > ULLONG_MAX) {
		pr_err("Data over limits!\n");
		return 0;
	}
	tmp = 24000000 * fbdiv_val;
	rate += tmp;
	do_div(rate, refdiv_val);

	return rate;
}

static int clk_pll_determine_rate(struct clk_hw *hw,
				  struct clk_rate_request *req)
{
	return req->rate;
}

static const struct clk_ops clk_pll_ops = {
	.set_rate = clk_pll_set_rate,
	.determine_rate = clk_pll_determine_rate,
	.recalc_rate = clk_pll_recalc_rate,
};

void __init hi3519av100_clk_register_pll(struct hi3519av100_pll_clock *clks,
		int nums, struct hisi_clock_data *data)
{
	int i;
	void __iomem *base = NULL;

	if (clks == NULL || data == NULL)
		return;

	base = data->base;
	for (i = 0; i < nums; i++) {
		struct hi3519av100_clk_pll *p_clk = NULL;
		struct clk *clk = NULL;
		struct clk_init_data init;

		p_clk = kzalloc(sizeof(*p_clk), GFP_KERNEL);
		if (!p_clk)
			return;

		init.name = clks[i].name;
		init.flags = CLK_IS_BASIC | CLK_SET_RATE_PARENT;
		init.parent_names =
			(clks[i].parent_name ? &clks[i].parent_name : NULL);
		init.num_parents = (clks[i].parent_name ? 1 : 0);
		init.ops = &clk_pll_ops;

		p_clk->ctrl_reg1 = base + clks[i].ctrl_reg1;
		p_clk->frac_shift = clks[i].frac_shift;
		p_clk->frac_width = clks[i].frac_width;
		p_clk->postdiv1_shift = clks[i].postdiv1_shift;
		p_clk->postdiv1_width = clks[i].postdiv1_width;
		p_clk->postdiv2_shift = clks[i].postdiv2_shift;
		p_clk->postdiv2_width = clks[i].postdiv2_width;

		p_clk->ctrl_reg2 = base + clks[i].ctrl_reg2;
		p_clk->fbdiv_shift = clks[i].fbdiv_shift;
		p_clk->fbdiv_width = clks[i].fbdiv_width;
		p_clk->refdiv_shift = clks[i].refdiv_shift;
		p_clk->refdiv_width = clks[i].refdiv_width;
		p_clk->hw.init = &init;

		clk = clk_register(NULL, &p_clk->hw);
		if (IS_ERR(clk)) {
			kfree(p_clk);
			pr_err("%s: failed to register clock %s\n",
			       __func__, clks[i].name);
			continue;
		}

		data->clk_data.clks[clks[i].id] = clk;
	}
}

static void __init hi3519av100_clk_init(struct device_node *np)
{
	struct hisi_clock_data *clk_data;

	clk_data = hisi_clk_init(np, HI3519AV100_NR_CLKS);
	if (!clk_data)
		return;
	if (IS_ENABLED(CONFIG_RESET_CONTROLLER))
		hibvt_reset_init(np, HI3519AV100_NR_RSTS);

	hisi_clk_register_fixed_rate(hi3519av100_fixed_rate_clks,
				     ARRAY_SIZE(hi3519av100_fixed_rate_clks),
				     clk_data);
	hisi_clk_register_mux(hi3519av100_mux_clks, ARRAY_SIZE(hi3519av100_mux_clks),
			      clk_data);
	hisi_clk_register_fixed_factor(hi3519av100_fixed_factor_clks,
				       ARRAY_SIZE(hi3519av100_fixed_factor_clks), clk_data);
	hisi_clk_register_gate(hi3519av100_gate_clks,
			       ARRAY_SIZE(hi3519av100_gate_clks), clk_data);

	hi3519av100_clk_register_pll(hi3519av100_pll_clks,
				     ARRAY_SIZE(hi3519av100_pll_clks), clk_data);
}

CLK_OF_DECLARE(hi3519av100_clk, "hisilicon,hi3519av100-clock",
	       hi3519av100_clk_init);
