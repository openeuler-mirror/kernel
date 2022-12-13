// SPDX-License-Identifier: GPL-2.0
/*
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

#include <dt-bindings/clock/hi3516dv300-clock.h>
#include <linux/clk-provider.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include "clk.h"
#include "crg.h"
#include "reset.h"

static struct hisi_fixed_rate_clock hi3516dv300_fixed_rate_clks[] __initdata = {
	{ HI3516DV300_FIXED_3M, "3m", NULL, 0, 3000000, },
	{ HI3516DV300_FIXED_6M, "6m", NULL, 0, 6000000, },
	{ HI3516DV300_FIXED_12M, "12m", NULL, 0, 12000000, },
	{ HI3516DV300_FIXED_24M, "24m", NULL, 0, 24000000, },
	{ HI3516DV300_FIXED_25M, "25m", NULL, 0, 25000000, },
	{ HI3516DV300_FIXED_50M, "50m", NULL, 0, 50000000, },
	{ HI3516DV300_FIXED_54M, "54m", NULL, 0, 54000000, },
	{ HI3516DV300_FIXED_83P3M, "83.3m", NULL, 0, 83300000, },
	{ HI3516DV300_FIXED_100M, "100m", NULL, 0, 100000000, },
	{ HI3516DV300_FIXED_125M, "125m", NULL, 0, 125000000, },
	{ HI3516DV300_FIXED_150M, "150m", NULL, 0, 150000000, },
	{ HI3516DV300_FIXED_163M, "163m", NULL, 0, 163000000, },
	{ HI3516DV300_FIXED_200M, "200m", NULL, 0, 200000000, },
	{ HI3516DV300_FIXED_250M, "250m", NULL, 0, 250000000, },
	{ HI3516DV300_FIXED_257M, "257m", NULL, 0, 257000000, },
	{ HI3516DV300_FIXED_300M, "300m", NULL, 0, 300000000, },
	{ HI3516DV300_FIXED_324M, "324m", NULL, 0, 324000000, },
	{ HI3516DV300_FIXED_342M, "342m", NULL, 0, 342000000, },
	{ HI3516DV300_FIXED_342M, "375m", NULL, 0, 375000000, },
	{ HI3516DV300_FIXED_396M, "396m", NULL, 0, 396000000, },
	{ HI3516DV300_FIXED_400M, "400m", NULL, 0, 400000000, },
	{ HI3516DV300_FIXED_448M, "448m", NULL, 0, 448000000, },
	{ HI3516DV300_FIXED_500M, "500m", NULL, 0, 500000000, },
	{ HI3516DV300_FIXED_540M, "540m", NULL, 0, 540000000, },
	{ HI3516DV300_FIXED_600M, "600m", NULL, 0, 600000000, },
	{ HI3516DV300_FIXED_750M, "750m", NULL, 0, 750000000, },
	{ HI3516DV300_FIXED_1000M, "1000m", NULL, 0, 1000000000, },
	{ HI3516DV300_FIXED_1500M, "1500m", NULL, 0, 1500000000UL, },
};

static const char *sysaxi_mux_p[] __initconst = {
	"24m", "200m", "300m"
};
static const char *sysapb_mux_p[] __initconst = {"24m", "50m"};
static const char *uart_mux_p[] __initconst = {"24m", "6m"};
static const char *fmc_mux_p[] __initconst = {"24m", "100m", "150m",
	"163m", "200m", "257m", "300m", "396m"};
static const char *eth_mux_p[] __initconst = {"100m", "54m"};
static const char *mmc_mux_p[] __initconst = {"100m", "50m", "25m"};
static const char *pwm_mux_p[] __initconst = {"3m", "50m", "24m", "24m"};

static u32 sysaxi_mux_table[] = {0, 1, 2};
static u32 sysapb_mux_table[] = {0, 1};
static u32 uart_mux_table[] = {0, 1};
static u32 fmc_mux_table[] = {0, 1, 2, 3, 4, 5, 6, 7};
static u32 eth_mux_table[] = {0, 1};
static u32 mmc_mux_table[] = {1, 2, 3};
static u32 pwm_mux_table[] = {0, 1, 2, 3};

static struct hisi_mux_clock hi3516dv300_mux_clks[] __initdata = {
	{
		HI3516DV300_SYSAXI_CLK, "sysaxi_mux", sysaxi_mux_p,
		ARRAY_SIZE(sysaxi_mux_p),
		CLK_SET_RATE_PARENT, 0x80, 6, 2, 0, sysaxi_mux_table,
	},
	{
		HI3516DV300_SYSAPB_CLK, "sysapb_mux", sysapb_mux_p,
		ARRAY_SIZE(sysapb_mux_p),
		CLK_SET_RATE_PARENT, 0x80, 10, 1, 0, sysapb_mux_table,
	},
	{
		HI3516DV300_FMC_MUX, "fmc_mux", fmc_mux_p, ARRAY_SIZE(fmc_mux_p),
		CLK_SET_RATE_PARENT, 0x144, 2, 3, 0, fmc_mux_table,
	},
	{
		HI3516DV300_MMC0_MUX, "mmc0_mux", mmc_mux_p, ARRAY_SIZE(mmc_mux_p),
		CLK_SET_RATE_PARENT, 0x148, 2, 2, 0, mmc_mux_table,
	},
	{
		HI3516DV300_MMC1_MUX, "mmc1_mux", mmc_mux_p, ARRAY_SIZE(mmc_mux_p),
		CLK_SET_RATE_PARENT, 0x160, 2, 2, 0, mmc_mux_table,
	},
	{
		HI3516DV300_MMC2_MUX, "mmc2_mux", mmc_mux_p, ARRAY_SIZE(mmc_mux_p),
		CLK_SET_RATE_PARENT, 0x154, 2, 2, 0, mmc_mux_table,
	},
	{
		HI3516DV300_UART_MUX, "uart_mux0", uart_mux_p,
		ARRAY_SIZE(uart_mux_p),
		CLK_SET_RATE_PARENT, 0x1bc, 18, 1, 0, uart_mux_table,
	},
	{
		HI3516DV300_UART1_MUX, "uart_mux1", uart_mux_p,
		ARRAY_SIZE(uart_mux_p),
		CLK_SET_RATE_PARENT, 0x1bc, 19, 1, 0, uart_mux_table,
	},
	{
		HI3516DV300_UART2_MUX, "uart_mux2", uart_mux_p,
		ARRAY_SIZE(uart_mux_p),
		CLK_SET_RATE_PARENT, 0x1bc, 20, 1, 0, uart_mux_table,
	},
	{
		HI3516DV300_UART3_MUX, "uart_mux3", uart_mux_p,
		ARRAY_SIZE(uart_mux_p),
		CLK_SET_RATE_PARENT, 0x1bc, 21, 1, 0, uart_mux_table,
	},
	{
		HI3516DV300_UART4_MUX, "uart_mux4", uart_mux_p,
		ARRAY_SIZE(uart_mux_p),
		CLK_SET_RATE_PARENT, 0x1bc, 22, 1, 0, uart_mux_table,
	},
	{
		HI3516DV300_PWM_MUX, "pwm_mux", pwm_mux_p,
		ARRAY_SIZE(pwm_mux_p),
		CLK_SET_RATE_PARENT, 0x1bc, 8, 2, 0, pwm_mux_table,
	},
	/* ethernet clock select */
	{
		HI3516DV300_ETH_MUX, "eth_mux", eth_mux_p, ARRAY_SIZE(eth_mux_p),
		CLK_SET_RATE_PARENT, 0x16c, 7, 1, 0, eth_mux_table,
	},
};

static struct hisi_fixed_factor_clock hi3516dv300_fixed_factor_clks[] __initdata
	= {
	{
		HI3516DV300_SYSAXI_CLK, "clk_sysaxi", "sysaxi_mux", 1, 4,
		CLK_SET_RATE_PARENT
	},
};

static struct hisi_gate_clock hi3516dv300_gate_clks[] __initdata = {
	{
		HI3516DV300_FMC_CLK, "clk_fmc", "fmc_mux",
		CLK_SET_RATE_PARENT, 0x144, 1, 0,
	},
	{
		HI3516DV300_MMC0_CLK, "clk_mmc0", "mmc0_mux",
		CLK_SET_RATE_PARENT, 0x148, 1, 0,
	},
	{
		HI3516DV300_MMC1_CLK, "clk_mmc1", "mmc1_mux",
		CLK_SET_RATE_PARENT, 0x160, 1, 0,
	},
	{
		HI3516DV300_MMC2_CLK, "clk_mmc2", "mmc2_mux",
		CLK_SET_RATE_PARENT, 0x154, 1, 0,
	},
	{
		HI3516DV300_UART0_CLK, "clk_uart0", "uart_mux0",
		CLK_SET_RATE_PARENT, 0x1b8, 0, 0,
	},
	{
		HI3516DV300_UART1_CLK, "clk_uart1", "uart_mux1",
		CLK_SET_RATE_PARENT, 0x1b8, 1, 0,
	},
	{
		HI3516DV300_UART2_CLK, "clk_uart2", "uart_mux2",
		CLK_SET_RATE_PARENT, 0x1b8, 2, 0,
	},
	{
		HI3516DV300_UART3_CLK, "clk_uart3", "uart_mux3",
		CLK_SET_RATE_PARENT, 0x1b8, 3, 0,
	},
	{
		HI3516DV300_UART4_CLK, "clk_uart4", "uart_mux4",
		CLK_SET_RATE_PARENT, 0x1b8, 4, 0,
	},
	{
		HI3516DV300_I2C0_CLK, "clk_i2c0", "50m",
		CLK_SET_RATE_PARENT, 0x1b8, 11, 0,
	},
	{
		HI3516DV300_I2C1_CLK, "clk_i2c1", "50m",
		CLK_SET_RATE_PARENT, 0x1b8, 12, 0,
	},
	{
		HI3516DV300_I2C2_CLK, "clk_i2c2", "50m",
		CLK_SET_RATE_PARENT, 0x1b8, 13, 0,
	},
	{
		HI3516DV300_I2C3_CLK, "clk_i2c3", "50m",
		CLK_SET_RATE_PARENT, 0x1b8, 14, 0,
	},
	{
		HI3516DV300_I2C4_CLK, "clk_i2c4", "50m",
		CLK_SET_RATE_PARENT, 0x1b8, 15, 0,
	},
	{
		HI3516DV300_I2C5_CLK, "clk_i2c5", "50m",
		CLK_SET_RATE_PARENT, 0x1b8, 16, 0,
	},
	{
		HI3516DV300_I2C6_CLK, "clk_i2c6", "50m",
		CLK_SET_RATE_PARENT, 0x1b8, 17, 0,
	},
	{
		HI3516DV300_I2C7_CLK, "clk_i2c7", "50m",
		CLK_SET_RATE_PARENT, 0x1b8, 18, 0,
	},
	{
		HI3516DV300_SPI0_CLK, "clk_spi0", "100m",
		CLK_SET_RATE_PARENT, 0x1bc, 12, 0,
	},
	{
		HI3516DV300_SPI1_CLK, "clk_spi1", "100m",
		CLK_SET_RATE_PARENT, 0x1bc, 13, 0,
	},
	{
		HI3516DV300_SPI2_CLK, "clk_spi2", "100m",
		CLK_SET_RATE_PARENT, 0x1bc, 14, 0,
	},
	{
		HI3516DV300_ETH0_CLK, "clk_eth0", "eth_mux",
		CLK_SET_RATE_PARENT, 0x16c, 1, 0,
	},
	{
		HI3516DV300_DMAC_CLK, "clk_dmac", NULL,
		CLK_SET_RATE_PARENT, 0x194, 1, 0,
	},
	{
		HI3516DV300_DMAC_AXICLK, "axiclk_dmac", NULL,
		CLK_SET_RATE_PARENT, 0x194, 2, 0,
	},
	{
		HI3516DV300_PWM_CLK, "clk_pwm", "pwm_mux",
		CLK_SET_RATE_PARENT, 0x1bc, 7, 0,
	},
};

static void __init hi3516dv300_clk_init(struct device_node *np)
{
	struct hisi_clock_data *clk_data;

	clk_data = hisi_clk_init(np, HI3516DV300_NR_CLKS);
	if (!clk_data)
		return;

	hisi_clk_register_fixed_rate(hi3516dv300_fixed_rate_clks,
				     ARRAY_SIZE(hi3516dv300_fixed_rate_clks),
				     clk_data);
	hisi_clk_register_mux(hi3516dv300_mux_clks, ARRAY_SIZE(hi3516dv300_mux_clks),
			      clk_data);
	hisi_clk_register_fixed_factor(hi3516dv300_fixed_factor_clks,
				       ARRAY_SIZE(hi3516dv300_fixed_factor_clks), clk_data);
	hisi_clk_register_gate(hi3516dv300_gate_clks,
			       ARRAY_SIZE(hi3516dv300_gate_clks), clk_data);
}

MODULE_LICENSE("GPL");
CLK_OF_DECLARE(hi3516dv300_clk, "hisilicon,hi3516dv300-clock",
	       hi3516dv300_clk_init);

