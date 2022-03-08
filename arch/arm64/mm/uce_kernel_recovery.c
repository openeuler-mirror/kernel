// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "ARM64 UCE: " fmt

#include <linux/acpi.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/sysctl.h>

#include <asm/acpi.h>
#include <asm/exception.h>
#include <asm/system_misc.h>
#include <asm/traps.h>
#include <asm/esr.h>

struct uce_kernel_recovery_info {
	int (*fn)(void);
	const char *name;
	unsigned long addr;
	unsigned long size;
};

int copy_from_user_sea_fallback(void);

static int kernel_access_sea_recovery;
static int kernel_uce_recovery_sysctl_max = 7;

#define UCE_KER_REC_NUM   ARRAY_SIZE(reco_info)
static struct uce_kernel_recovery_info reco_info[] = {
	{NULL, NULL, 0, 0},  /* reserved */
	{NULL, NULL, 0, 0},  /* reserved */
	{copy_from_user_sea_fallback, "__arch_copy_from_user", (unsigned long)__arch_copy_from_user, 0},
};

static struct ctl_table uce_kernel_recovery_ctl_table[] = {
	{
		.procname	= "uce_kernel_recovery",
		.data		= &kernel_access_sea_recovery,
		.maxlen		= sizeof(kernel_access_sea_recovery),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &kernel_uce_recovery_sysctl_max,
	},
	{ }
};

static int __init kernel_access_sea_recovery_init(void)
{
	unsigned long addr, size, offset;
	unsigned int i;

	for (i = 0; i < UCE_KER_REC_NUM; i++) {
		addr = reco_info[i].addr;

		if (!addr)
			continue;

		if (!kallsyms_lookup_size_offset(addr, &size, &offset)) {
			pr_info("symbol %s lookup addr fail.\n",
				reco_info[i].name);
			size = 0;
		}

		reco_info[i].size = size;
	}

	if (!register_sysctl("kernel", uce_kernel_recovery_ctl_table))
		pr_err("register sysctl table fail.\n");

	return 1;
}
fs_initcall(kernel_access_sea_recovery_init);

static int __init enable_kernel_access_sea_recovery(char *str)
{
	int max = (1 << UCE_KER_REC_NUM) - 1;
	int val;

	if (kstrtoint(str, 0, &val))
		return -EINVAL;

	if (val < 0 || val > max) {
		pr_info("invalid uce_kernel_recovery value %d", val);
		return -EINVAL;
	}

	kernel_access_sea_recovery = val;

	return 1;
}
__setup("uce_kernel_recovery=", enable_kernel_access_sea_recovery);

/*
 * what is kernel recovery?
 * If the process's private data is accessed in the kernel mode to trigger
 * special sea fault, it can controlled by killing the process and isolating
 * the failure pages instead of die.
 */
static int is_in_kernel_recovery(unsigned int esr, struct pt_regs *regs)
{
	/*
	 * target insn: ldp-pre, ldp-post, ldp-offset,
	 * ldr-64bit-pre/pose, ldr-32bit-pre/post, ldrb-pre/post, ldrh-pre/post
	 */
	u32 target_insn[] = {0xa8c, 0xa9c, 0xa94, 0xf84, 0x784, 0x384, 0xb84};
	void  *pc = (void  *)instruction_pointer(regs);
	struct uce_kernel_recovery_info *info;
	bool insn_match = false;
	u32 insn;
	int i;

	pr_emerg("%s-%d, kernel recovery: 0x%x, esr: 0x%08x -- %s, %pS\n",
		 current->comm, current->pid, kernel_access_sea_recovery, esr,
		 esr_get_class_string(esr), pc);

	if (aarch64_insn_read((void *)pc, &insn)) {
		pr_emerg("insn read fail.\n");
		return -EFAULT;
	}

	/*
	 * We process special ESR:
	 * EC : 0b100101   Data Abort taken without a change in Exception level.
	 * DFSC : 0b010000 Synchronous External abort, not on translation table
	 * walk or hardware update of translation table.
	 * eg: 0x96000610
	 */
	if (ESR_ELx_EC(esr) != ESR_ELx_EC_DABT_CUR ||
		(esr & ESR_ELx_FSC) != ESR_ELx_FSC_EXTABT) {
		pr_emerg("esr not match.\n");
		return -EINVAL;
	}

	insn = (insn >> 20) & 0xffc;
	for (i = 0; i < ARRAY_SIZE(target_insn); i++) {
		if (insn == target_insn[i]) {
			insn_match = true;
			break;
		}
	}

	if (!insn_match) {
		pr_emerg("insn 0x%x is not match.\n", insn);
		return -EINVAL;
	}

	for (i = 0; i < UCE_KER_REC_NUM; i++) {
		if (!((kernel_access_sea_recovery >> i) & 0x1))
			continue;

		info = &reco_info[i];
		if (info->fn && regs->pc >= info->addr &&
		    regs->pc < (info->addr + info->size)) {
			pr_emerg("total match %s success.\n", info->name);
			return i;
		}
	}

	pr_emerg("scene is not match, kernel recovery %d.\n",
		 kernel_access_sea_recovery);
	return -EINVAL;
}

bool arm64_process_kernel_sea(unsigned long addr, unsigned int esr,
			      struct pt_regs *regs, int sig,
			      int code, void __user *siaddr)
{
	int idx;

	if (user_mode(regs) || apei_claim_sea(regs) < 0)
		return false;

	if (!current->mm || !kernel_access_sea_recovery) {
		pr_emerg("kernel recovery %d, %s-%d is %s-thread.\n",
			 kernel_access_sea_recovery,
			 current->comm, current->pid,
			 (current->mm) ? "user" : "kernel");

		return false;
	}

	idx = is_in_kernel_recovery(esr, regs);
	if (idx < 0 || idx >= UCE_KER_REC_NUM) {
		pr_emerg("Uncorrected hardware memory error (sence not match or sence switch is off) in kernel-access\n");
		return false;
	}

	current->thread.fault_address = 0;
	current->thread.fault_code = esr;
	regs->pc = (unsigned long)reco_info[idx].fn;

	arm64_force_sig_fault(sig, code, siaddr,
		"Uncorrected hardware memory use with kernel recovery in kernel-access\n");

	return true;
}
