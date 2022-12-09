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

#ifndef __DTS_HI3516DV300_CLOCK_H
#define __DTS_HI3516DV300_CLOCK_H

/* clk in Hi3516CV500 CRG */
/* fixed rate clocks */
#define HI3516DV300_FIXED_3M        1
#define HI3516DV300_FIXED_6M        2
#define HI3516DV300_FIXED_12M       3
#define HI3516DV300_FIXED_24M       4
#define HI3516DV300_FIXED_50M       5
#define HI3516DV300_FIXED_83P3M     6
#define HI3516DV300_FIXED_100M      7
#define HI3516DV300_FIXED_125M      8
#define HI3516DV300_FIXED_148P5M    9
#define HI3516DV300_FIXED_150M      10
#define HI3516DV300_FIXED_200M      11
#define HI3516DV300_FIXED_250M      12
#define HI3516DV300_FIXED_300M      13
#define HI3516DV300_FIXED_324M      14
#define HI3516DV300_FIXED_342M      15
#define HI3516DV300_FIXED_375M      16
#define HI3516DV300_FIXED_400M      17
#define HI3516DV300_FIXED_448M      18
#define HI3516DV300_FIXED_500M      19
#define HI3516DV300_FIXED_540M      20
#define HI3516DV300_FIXED_600M      21
#define HI3516DV300_FIXED_750M      22
#define HI3516DV300_FIXED_1000M     23
#define HI3516DV300_FIXED_1500M     24
#define HI3516DV300_FIXED_54M       25
#define HI3516DV300_FIXED_25M       26
#define HI3516DV300_FIXED_163M      27
#define HI3516DV300_FIXED_257M      28
#define HI3516DV300_FIXED_396M      29

/* mux clocks */
#define HI3516DV300_SYSAXI_CLK      30
#define HI3516DV300_SYSAPB_CLK      31
#define HI3516DV300_FMC_MUX         32
#define HI3516DV300_UART_MUX        33
#define HI3516DV300_MMC0_MUX        34
#define HI3516DV300_MMC1_MUX        35
#define HI3516DV300_MMC2_MUX        36
#define HI3516DV300_UART1_MUX       33
#define HI3516DV300_UART2_MUX       37
#define HI3516DV300_UART4_MUX       38
#define HI3516DV300_ETH_MUX     39

/* gate clocks */
#define HI3516DV300_UART0_CLK       40
#define HI3516DV300_UART1_CLK       41
#define HI3516DV300_UART2_CLK       42
#define HI3516DV300_FMC_CLK         43
#define HI3516DV300_ETH0_CLK        44
#define HI3516DV300_USB2_BUS_CLK    45
#define HI3516DV300_USB2_CLK        46
#define HI3516DV300_DMAC_CLK        47
#define HI3516DV300_SPI0_CLK        48
#define HI3516DV300_SPI1_CLK        49
#define HI3516DV300_MMC0_CLK        50
#define HI3516DV300_MMC1_CLK        51
#define HI3516DV300_MMC2_CLK        52
#define HI3516DV300_UART4_CLK       53
#define HI3516DV300_SPI2_CLK        54
#define HI3516DV300_I2C0_CLK        55
#define HI3516DV300_I2C1_CLK        56
#define HI3516DV300_I2C2_CLK        57
#define HI3516DV300_I2C3_CLK        58
#define HI3516DV300_I2C4_CLK        59
#define HI3516DV300_I2C5_CLK        60
#define HI3516DV300_I2C6_CLK        61
#define HI3516DV300_I2C7_CLK        62
#define HI3516DV300_UART3_MUX       63
#define HI3516DV300_UART3_CLK       64
#define HI3516DV300_DMAC_AXICLK     70
#define HI3516DV300_PWM_CLK         71
#define HI3516DV300_PWM_MUX         72

#define HI3516DV300_NR_CLKS     256
#define HI3516DV300_NR_RSTS     256

#endif  /* __DTS_HI3516DV300_CLOCK_H */
