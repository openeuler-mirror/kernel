// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt)	"smt_qos: " fmt

#include <linux/module.h>

#include <asm/arch_gicv3.h>
#include <asm/cpuidle.h>
#include <asm/daifflags.h>
#include <asm/timex.h>
#include <asm/xint.h>

#include <vdso/time64.h>

static unsigned int sysctl_sched_wfi_timeout = 50;
static DEFINE_STATIC_KEY_TRUE(split_mode);
static u32 arch_timer_freq;

static void irq_complete(u32 irqnr)
{
	if (static_branch_likely(&split_mode))
		write_gicreg(irqnr, ICC_EOIR1_EL1);
	isb();
}

static void irq_deactive(u32 irqnr)
{
	if (static_branch_likely(&split_mode)) {
		gic_write_dir(irqnr);
	} else {
		write_gicreg(irqnr, ICC_EOIR1_EL1);
		isb();
	}
}

static __always_inline void throttle_offline(void)
{
	cycles_t start, end;
	u64 delta_us = 0;

	local_daif_restore(DAIF_PROCCTX);

	start = get_cycles();
	while (delta_us < sysctl_sched_wfi_timeout && should_restrict()) {
		cpu_do_idle();
		end = get_cycles();
		delta_us = (end - start) * USEC_PER_SEC / arch_timer_freq;
	}

	local_daif_mask();
}

asmlinkage void el0_xint_ipi_handler(struct pt_regs *regs)
{
	irq_complete(NR_IPI_USER);
	irq_deactive(NR_IPI_USER);
	throttle_offline();
}

static struct ctl_table sched_wfi_timeout_sysctl_table[] = {
	{
		.procname	= "sched_wfi_timeout_us",
		.data		= &sysctl_sched_wfi_timeout,
		.maxlen		= sizeof(sysctl_sched_wfi_timeout),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_THOUSAND,
	},
	{}
};

static int __init xint_init(void)
{
	if (!system_uses_xint())
		return 0;

	arch_timer_freq = arch_timer_get_cntfrq();
	register_sysctl_init("kernel", sched_wfi_timeout_sysctl_table);

	if (!is_hyp_mode_available())
		static_branch_disable(&split_mode);

	pr_info("GIC split mode enabled: %d, arch timer freq: %u Hz\n",
		static_key_enabled(&split_mode), arch_timer_freq);
	return 0;
}
module_init(xint_init);
