// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/arch/sw/kernel/setup.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 */

#include <linux/clk.h>
#include <linux/cpufreq.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/delay.h>

#include <asm/sw64io.h>
#include <asm/hw_init.h>
#include <asm/debug.h>
#include <asm/clock.h>

#define CLK_PRT         0x1UL
#define CORE_CLK0_V     (0x1UL << 1)
#define CORE_CLK0_R     (0x1UL << 2)
#define CORE_CLK2_V     (0x1UL << 15)
#define CORE_CLK2_R     (0x1UL << 16)

#define CLK_LV1_SEL_PRT         0x1UL
#define CLK_LV1_SEL_MUXA        (0x1UL << 2)
#define CLK_LV1_SEL_MUXB        (0x1UL << 3)

#define CORE_PLL0_CFG_SHIFT     4
#define CORE_PLL2_CFG_SHIFT     18

char   curruent_policy[CPUFREQ_NAME_LEN];

/* Minimum CLK support */
enum {
	DC_0, DC_1, DC_2, DC_3, DC_4, DC_5, DC_6, DC_7, DC_8,
	DC_9, DC_10, DC_11, DC_12, DC_13, DC_14, DC_15, DC_16, DC_RESV
};

static int cpu_freq[14] = {
	0,	1200,	1800,	1900,
	1950,	2000,	2050,	2100,
	2150,	2200,	2250,	2300,
	2350,	2400	};

struct cpufreq_frequency_table sw64_clockmod_table[] = {
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{0, DC_1, 0},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{0, DC_2, 0},
	{-1, DC_RESV, CPUFREQ_ENTRY_INVALID},
	{0, DC_3, 0},
	{0, DC_4, 0},
	{0, DC_5, 0},
	{0, DC_6, 0},
	{0, DC_7, 0},
	{0, DC_8, 0},
	{0, DC_9, 0},
	{0, DC_10, 0},
	{0, DC_11, 0},
	{0, DC_12, 0},
	{0, DC_13, 0},
{-1, DC_RESV, CPUFREQ_TABLE_END},
};
EXPORT_SYMBOL_GPL(sw64_clockmod_table);

static struct clk cpu_clk = {
	.name = "cpu_clk",
	.flags = CLK_ALWAYS_ENABLED | CLK_RATE_PROPAGATES,
	.rate = 2400000000,
};

struct clk *sw64_clk_get(struct device *dev, const char *id)
{
	return &cpu_clk;
}
EXPORT_SYMBOL(sw64_clk_get);

unsigned int __sw64_cpufreq_get(struct cpufreq_policy *policy)
{
	int i;
	u64 val;

	val = sw64_io_read(0, CLK_CTL);
	val = val >> CORE_PLL2_CFG_SHIFT;

	for (i = 0; i < sizeof(cpu_freq)/sizeof(int); i++) {
		if (cpu_freq[val] == cpu_freq[i])
			return cpu_freq[i];
	}
	return 0;
}
EXPORT_SYMBOL(__sw64_cpufreq_get);

void sw64_store_policy(struct cpufreq_policy *policy)
{
	memcpy(curruent_policy, policy->governor->name, CPUFREQ_NAME_LEN);
}
EXPORT_SYMBOL_GPL(sw64_store_policy);

void sw64_set_rate(unsigned long rate)
{
	unsigned int i, val;
	int index = -1;

	rate /= 1000000;

	for (i = 0; i < sizeof(cpu_freq)/sizeof(int); i++) {
		if (rate == cpu_freq[i]) {
			index = i;
			update_cpu_freq(cpu_freq[i]);
			break;
		}
	}

	if (index < 0)
		return -EINVAL;

	sw64_io_write(0, CLK_CTL, CORE_CLK2_R | CORE_CLK2_V | CLK_PRT);
	sw64_io_write(1, CLK_CTL, CORE_CLK2_R | CORE_CLK2_V | CLK_PRT);
	val = sw64_io_read(0, CLK_CTL);

	sw64_io_write(0, CLK_CTL, val | index << CORE_PLL2_CFG_SHIFT);
	sw64_io_write(1, CLK_CTL, val | index << CORE_PLL2_CFG_SHIFT);

	udelay(1);

	sw64_io_write(0, CLK_CTL, CORE_CLK2_V | CLK_PRT
			| index << CORE_PLL2_CFG_SHIFT);
	sw64_io_write(1, CLK_CTL, CORE_CLK2_V | CLK_PRT
			| index << CORE_PLL2_CFG_SHIFT);
	val = sw64_io_read(0, CLK_CTL);

	/* LV1 select PLL1/PLL2 */
	sw64_io_write(0, CLU_LV1_SEL, CLK_LV1_SEL_MUXA | CLK_LV1_SEL_PRT);
	sw64_io_write(1, CLU_LV1_SEL, CLK_LV1_SEL_MUXA | CLK_LV1_SEL_PRT);

	/* Set CLK_CTL PLL0 */
	sw64_io_write(0, CLK_CTL, val | CORE_CLK0_R | CORE_CLK0_V);
	sw64_io_write(1, CLK_CTL, val | CORE_CLK0_R | CORE_CLK0_V);

	sw64_io_write(0, CLK_CTL, val | CORE_CLK0_R | CORE_CLK0_V
			| index << CORE_PLL0_CFG_SHIFT);
	sw64_io_write(1, CLK_CTL, val | CORE_CLK0_R | CORE_CLK0_V
			| index << CORE_PLL0_CFG_SHIFT);

	udelay(1);

	sw64_io_write(0, CLK_CTL, val | CORE_CLK0_V
			| index << CORE_PLL0_CFG_SHIFT);
	sw64_io_write(1, CLK_CTL, val | CORE_CLK0_V
			| index << CORE_PLL0_CFG_SHIFT);

	/* LV1 select PLL0/PLL1 */
	sw64_io_write(0, CLU_LV1_SEL, CLK_LV1_SEL_MUXB | CLK_LV1_SEL_PRT);
	sw64_io_write(1, CLU_LV1_SEL, CLK_LV1_SEL_MUXB | CLK_LV1_SEL_PRT);
}
EXPORT_SYMBOL_GPL(sw64_set_rate);
