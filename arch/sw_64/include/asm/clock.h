/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_SW64_CLOCK_H
#define _ASM_SW64_CLOCK_H

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/clk.h>
#include <linux/cpufreq.h>

struct clk;

extern struct cpufreq_frequency_table sw64_clockmod_table[];

extern char curruent_policy[CPUFREQ_NAME_LEN];

struct clk_ops {
	void (*init)(struct clk *clk);
	void (*enable)(struct clk *clk);
	void (*disable)(struct clk *clk);
	void (*recalc)(struct clk *clk);
	int (*set_rate)(struct clk *clk, unsigned long rate, int algo_id);
	long (*round_rate)(struct clk *clk, unsigned long rate);
};

struct clk {
	struct list_head node;
	const char *name;
	int id;
	struct module *owner;

	struct clk *parent;
	const struct clk_ops *ops;

	struct kref kref;

	unsigned long rate;
	unsigned long flags;
};

#define CLK_ALWAYS_ENABLED	(1 << 0)
#define CLK_RATE_PROPAGATES	(1 << 1)

int clk_init(void);

void sw64_set_rate(unsigned long rate);

struct clk *sw64_clk_get(struct device *dev, const char *id);

void sw64_update_clockevents(unsigned long cpu, u32 freq);

void sw64_store_policy(struct cpufreq_policy *policy);

unsigned int __sw64_cpufreq_get(struct cpufreq_policy *policy);
#endif				/* _ASM_SW64_CLOCK_H */
