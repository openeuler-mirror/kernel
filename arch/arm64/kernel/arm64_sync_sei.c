// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <asm/alternative.h>
#include <asm/cpufeature.h>
#include <asm/insn.h>
#include <asm/patching.h>
#include <asm/setup.h>

static bool arm64_sync_sei __read_mostly;

/*
 * alternative_cb callback for sei_restore_sp_el0 in entry.S.
 *
 * The SP_EL0 restoration is needed on firmware-first RAS platforms where
 * the trusted firmware clobbers SP_EL0 before delegating SEI back to the
 * kernel. This is a correctness requirement in the el1h_64_error handler
 * path, not a performance decision, so it depends solely on the CPU having
 * the RAS extension (ARM64_HAS_RAS_EXTN). It is independent of the
 * dynamic arm64_sync_sei sysctl which only controls ESB at exception
 * boundaries for performance reasons.
 */
void noinstr arm64_sync_sei_cb(struct alt_instr *alt, __le32 *origptr,
			__le32 *updptr, int nr_inst)
{
	int i;

	if (cpus_have_cap(ARM64_HAS_RAS_EXTN))
		return;

	/* Keep as NOP */
	for (i = 0; i < nr_inst; i++)
		updptr[i] = cpu_to_le32(aarch64_insn_gen_nop());
}

bool arm64_sync_sei_enabled(void)
{
	return arm64_sync_sei;
}

static int arm64_sync_sei_toggle(bool enable)
{
	unsigned long *table = __start_esb_patch_table;
	int count = __stop_esb_patch_table - __start_esb_patch_table;
	void **addrs;
	u32 *insns;
	u32 target_insn;
	int i, ret;

	if (!count)
		return -ENODEV;

	if (!cpus_have_cap(ARM64_HAS_RAS_EXTN))
		return -ENODEV;

	target_insn = enable
		? aarch64_insn_gen_hint(AARCH64_INSN_HINT_ESB)
		: aarch64_insn_gen_nop();

	addrs = kmalloc_array(count, sizeof(void *), GFP_KERNEL);
	insns = kmalloc_array(count, sizeof(u32), GFP_KERNEL);
	if (!addrs || !insns) {
		kfree(addrs);
		kfree(insns);
		return -ENOMEM;
	}

	for (i = 0; i < count; i++) {
		addrs[i] = (void *)table[i];
		insns[i] = target_insn;
	}

	cpus_read_lock();
	ret = aarch64_insn_patch_text(addrs, insns, count);
	cpus_read_unlock();

	kfree(addrs);
	kfree(insns);

	return ret;
}

static int arm64_sync_sei_sysctl(struct ctl_table *table, int write,
			       void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	bool old_val = arm64_sync_sei;

	ret = proc_dobool(table, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	if (write && arm64_sync_sei != old_val) {
		ret = arm64_sync_sei_toggle(arm64_sync_sei);
		if (ret)
			arm64_sync_sei = old_val;
	}

	return ret;
}

static struct ctl_table arm64_sync_sei_sysctl_table[] = {
	{
		.procname	= "arm64_sync_sei",
		.data		= &arm64_sync_sei,
		.maxlen		= sizeof(bool),
		.mode		= 0644,
		.proc_handler	= arm64_sync_sei_sysctl,
	},
};

static int __init arm64_sync_sei_late_init(void)
{
	if (read_cpuid_id() != MIDR_HISI_HIP12)
		return 0;

	register_sysctl("kernel", arm64_sync_sei_sysctl_table);
	return 0;
}
late_initcall(arm64_sync_sei_late_init);
