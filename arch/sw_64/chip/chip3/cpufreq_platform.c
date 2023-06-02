// SPDX-License-Identifier: GPL-2.0

#include <linux/platform_device.h>
#include <asm/hw_init.h>
#include <asm/cpufreq.h>
#include <asm/sw64io.h>

#define CRYSTAL_BIT	(1UL << 34)

/* Minimum CLK support */
enum {
	DC_0, DC_1, DC_2, DC_3, DC_4, DC_5, DC_6, DC_7, DC_8,
	DC_9, DC_10, DC_11, DC_12, DC_13, DC_14, DC_15, DC_RESV
};

struct cpufreq_frequency_table freq_table[] = {
	{0, 200, CPUFREQ_ENTRY_INVALID},
	{0, DC_1, CPUFREQ_ENTRY_INVALID},
	{0, DC_2, 0},
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
	{0, DC_14, 0},
	{0, DC_15, 0},
	{-1, DC_RESV, CPUFREQ_TABLE_END},
};


static struct platform_device sw64_cpufreq_device = {
	.name = "sw64_cpufreq",
	.id = -1,
};

static int __init sw64_cpufreq_init(void)
{
	int i;
	unsigned long max_rate, freq_off;
	max_rate = get_cpu_freq() / 1000000;

	if (sw64_io_read(0, INIT_CTL) & CRYSTAL_BIT)
		freq_off = 50;
	else
		freq_off = 60;

	/* clock table init */
	for (i = 0; freq_table[i].frequency != CPUFREQ_TABLE_END; i++) {
		if (i == 1)
			freq_table[i].driver_data = freq_off * 24;
		if (i == 2)
			freq_table[i].frequency = freq_off * 36;
		if (i > 2)
			freq_table[i].frequency = freq_off * 38 + ((i - 3) * freq_off);

		if (freq_table[i].frequency == max_rate)
			freq_table[i + 1].frequency = CPUFREQ_TABLE_END;
	}

	return platform_device_register(&sw64_cpufreq_device);
}
arch_initcall(sw64_cpufreq_init);
