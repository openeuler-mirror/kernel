// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/arch/sw/kernel/setup.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 */

/*
 * Cpufreq driver for the sw64 processors
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cpufreq.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/sched.h>	/* set_cpus_allowed() */
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/mod_devicetable.h>

#include <asm/hw_init.h>
#include <asm/clock.h>
#include <asm/sw64io.h>

#define CRYSTAL_BIT	(1UL << 34)

static uint nowait;

static struct clk *cpuclk;

/* Minimum CLK support */
enum {
	DC_0, DC_1, DC_2, DC_3, DC_4, DC_5, DC_6, DC_7, DC_8,
	DC_9, DC_10, DC_11, DC_12, DC_13, DC_14, DC_15, DC_RESV
};

static struct cpufreq_frequency_table freq_table[] = {
	{0, DC_0, CPUFREQ_ENTRY_INVALID},
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

static int sw64_cpu_freq_notifier(struct notifier_block *nb,
					unsigned long val, void *data);

static struct notifier_block sw64_cpufreq_notifier_block = {
	.notifier_call = sw64_cpu_freq_notifier
};

static int sw64_cpu_freq_notifier(struct notifier_block *nb,
					unsigned long val, void *data)
{
	struct cpufreq_freqs *freqs = (struct cpufreq_freqs *)data;
	unsigned long cpu = freqs->policy->cpu;

	if (val == CPUFREQ_POSTCHANGE)
		sw64_update_clockevents(cpu, freqs->new * 1000000);

	return 0;
}

static unsigned int sw64_cpufreq_get(unsigned int cpu)
{
	struct cpufreq_policy *policy = cpufreq_cpu_get_raw(cpu);

	if (!policy || IS_ERR(policy->clk)) {
		pr_err("%s: No %s associated to cpu: %d\n",
			__func__, policy ? "clk" : "policy", cpu);
		return 0;
	}

	return __sw64_cpufreq_get(policy);
}

/*
 * Here we notify other drivers of the proposed change and the final change.
 */
static int sw64_cpufreq_target(struct cpufreq_policy *policy,
				     unsigned int index)
{
	unsigned int cpu = policy->cpu;

	if (!cpu_online(cpu))
		return -ENODEV;

	sw64_store_policy(policy);

	/* setting the cpu frequency */
	sw64_set_rate(index);

	return 0;
}

static int sw64_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
	int i;
	unsigned long max_rate, freq_off;

	cpuclk = sw64_clk_get(NULL, "cpu_clk");
	if (IS_ERR(cpuclk)) {
		pr_err("couldn't get CPU clk\n");
		return PTR_ERR(cpuclk);
	}

	max_rate = get_cpu_freq() / 1000000;

	if (sw64_io_read(0, INIT_CTL) & CRYSTAL_BIT)
		freq_off = 50;
	else
		freq_off = 60;

	/* clock table init */
	for (i = 0; freq_table[i].frequency != CPUFREQ_TABLE_END; i++) {
		if (i == 2)
			freq_table[i].frequency = freq_off * 36;
		if (i > 2)
			freq_table[i].frequency = freq_off * 38 + ((i - 3) * freq_off);

		if (freq_table[i].frequency == max_rate)
			freq_table[i + 1].frequency = CPUFREQ_TABLE_END;
	}

	policy->clk = cpuclk;

	cpufreq_generic_init(policy, freq_table, 0);

	return 0;
}

static int sw64_cpufreq_verify(struct cpufreq_policy_data *policy)
{
	return cpufreq_frequency_table_verify(policy, freq_table);
}

static int sw64_cpufreq_exit(struct cpufreq_policy *policy)
{
	return 0;
}

static struct freq_attr *sw64_table_attr[] = {
	&cpufreq_freq_attr_scaling_available_freqs, NULL,
};

static struct cpufreq_driver sw64_cpufreq_driver = {
	.name = "sw64",
	.init = sw64_cpufreq_cpu_init,
	.verify = sw64_cpufreq_verify,
	.target_index = sw64_cpufreq_target,
	.get = sw64_cpufreq_get,
	.exit = sw64_cpufreq_exit,
	.attr = sw64_table_attr,
};

static const struct platform_device_id platform_device_ids[] = {
	{
		.name = "sw64_cpufreq",
	},
	{}
};

MODULE_DEVICE_TABLE(platform, platform_device_ids);

static struct platform_driver platform_driver = {
	.driver = {
		.name = "sw64_cpufreq",
	},
	.id_table = platform_device_ids,
};


static int __init cpufreq_init(void)
{
	int ret;

	/* Register platform stuff */
	ret = platform_driver_register(&platform_driver);
	if (ret)
		return ret;

	pr_info("SW-64 CPU frequency driver\n");

	cpufreq_register_notifier(&sw64_cpufreq_notifier_block,
				  CPUFREQ_TRANSITION_NOTIFIER);

	return cpufreq_register_driver(&sw64_cpufreq_driver);
}

static void __exit cpufreq_exit(void)
{
	cpufreq_unregister_driver(&sw64_cpufreq_driver);
	cpufreq_unregister_notifier(&sw64_cpufreq_notifier_block,
				    CPUFREQ_TRANSITION_NOTIFIER);

	platform_driver_unregister(&platform_driver);
}

module_init(cpufreq_init);
module_exit(cpufreq_exit);

module_param(nowait, uint, 0644);
MODULE_PARM_DESC(nowait, "Disable SW-64 specific wait");

MODULE_DESCRIPTION("cpufreq driver for sw64");
MODULE_LICENSE("GPL");
