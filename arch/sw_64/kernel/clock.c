// SPDX-License-Identifier: GPL-2.0

#include <linux/clk.h>
#include <linux/cpufreq.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/delay.h>

#include <asm/sw64_init.h>
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

char curruent_policy[CPUFREQ_NAME_LEN];

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
	struct cpufreq_frequency_table *ft = policy->freq_table;

	val = sw64_io_read(0, CLK_CTL) >> CORE_PLL2_CFG_SHIFT;

	for (i = 0; ft[i].frequency != CPUFREQ_TABLE_END; i++) {
		if (val == ft[i].driver_data)
			return ft[i].frequency;
	}
	return 0;
}
EXPORT_SYMBOL(__sw64_cpufreq_get);

void sw64_store_policy(struct cpufreq_policy *policy)
{
	memcpy(curruent_policy, policy->governor->name, CPUFREQ_NAME_LEN);
}
EXPORT_SYMBOL_GPL(sw64_store_policy);

void sw64_set_rate(unsigned int index)
{
	unsigned int i, val;
	int cpu_num;

	cpu_num = sw64_chip->get_cpu_num();

	for (i = 0; i < cpu_num; i++) {
		sw64_io_write(i, CLK_CTL, CORE_CLK2_R | CORE_CLK2_V | CLK_PRT);
		val = sw64_io_read(i, CLK_CTL);

		sw64_io_write(i, CLK_CTL, val | index << CORE_PLL2_CFG_SHIFT);

		udelay(1);

		sw64_io_write(i, CLK_CTL, CORE_CLK2_V | CLK_PRT
				| index << CORE_PLL2_CFG_SHIFT);
		val = sw64_io_read(i, CLK_CTL);

		/* LV1 select PLL1/PLL2 */
		sw64_io_write(i, CLU_LV1_SEL, CLK_LV1_SEL_MUXA | CLK_LV1_SEL_PRT);

		/* Set CLK_CTL PLL0 */
		sw64_io_write(i, CLK_CTL, val | CORE_CLK0_R | CORE_CLK0_V);

		sw64_io_write(i, CLK_CTL, val | CORE_CLK0_R | CORE_CLK0_V
				| index << CORE_PLL0_CFG_SHIFT);

		udelay(1);

		sw64_io_write(i, CLK_CTL, val | CORE_CLK0_V
				| index << CORE_PLL0_CFG_SHIFT);

		/* LV1 select PLL0/PLL1 */
		sw64_io_write(i, CLU_LV1_SEL, CLK_LV1_SEL_MUXB | CLK_LV1_SEL_PRT);
	}
}
EXPORT_SYMBOL_GPL(sw64_set_rate);
