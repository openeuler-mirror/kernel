/* SPDX-License-Identifier: GPL-2.0 */
/**
 * @file arch/sw_64/oprofile/op_impl.h
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Richard Henderson <rth@twiddle.net>
 */

#ifndef _SW64_OPROFILE_OP_IMPL_H
#define _SW64_OPROFILE_OP_IMPL_H

/* Per-counter configuration as set via oprofilefs.  */
struct op_counter_config {
	unsigned long enabled;
	unsigned long event;
	unsigned long count;
	/* Dummies because I am too lazy to hack the userspace tools.  */
	unsigned long kernel;
	unsigned long user;
	unsigned long unit_mask;
};

/* System-wide configuration as set via oprofilefs.  */
struct op_system_config {
	unsigned long enable_pal;
	unsigned long enable_kernel;
	unsigned long enable_user;
};

/* Cached values for the various performance monitoring registers.  */
struct op_register_config {
	unsigned long enable;
	unsigned long mux_select;
	unsigned long proc_mode;
	unsigned long freq;
	unsigned long reset_values;
	unsigned long need_reset;
};

/* Per-architecture configuration and hooks.  */
struct op_axp_model {
	void (*reg_setup)(struct op_register_config *reg,
			  struct op_counter_config *ctr,
			  struct op_system_config *sys);
	void (*cpu_setup)(void *x);
	void (*reset_ctr)(struct op_register_config *reg, unsigned long ctr);
	void (*handle_interrupt)(unsigned long which, struct pt_regs *regs,
				 struct op_counter_config *ctr);
	char *cpu_type;
	unsigned char num_counters;
	unsigned char can_set_proc_mode;
};

#endif /* _SW64_OPROFILE_OP_IMPL_H */
