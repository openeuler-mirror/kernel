// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Huawei Technologies Co., Ltd */
#include <asm/cpufeature.h>
#include <asm/cpu.h>
#include <asm/cputype.h>

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/cpuset.h>
#include <linux/pid_namespace.h>

#include "hwcap_str.h"

bool bpf_arm64_cpu_have_feature(unsigned int num)
{
	return cpu_have_feature(num);
}

enum arch_flags_type {
	ARM64_HWCAP,
	ARM64_HWCAP_SIZE,
	ARM64_COMPAT_HWCAP,
	ARM64_COMPAT_HWCAP_SIZE,
	ARM64_COMPAT_HWCAP2,
	ARM64_COMPAT_HWCAP2_SIZE,
};

__bpf_kfunc const char *bpf_arch_flags(enum arch_flags_type t, int i)
{
	switch (t) {
	case ARM64_HWCAP:
		return hwcap_str[i];
	case ARM64_HWCAP_SIZE:
		return (void *)ARRAY_SIZE(hwcap_str);
	case ARM64_COMPAT_HWCAP:
		return compat_hwcap_str[i];
	case ARM64_COMPAT_HWCAP_SIZE:
		return (void *)ARRAY_SIZE(compat_hwcap_str);
	case ARM64_COMPAT_HWCAP2:
		return compat_hwcap2_str[i];
	case ARM64_COMPAT_HWCAP2_SIZE:
		return (void *)ARRAY_SIZE(compat_hwcap2_str);
	default:
		return NULL;
	}
}

BTF_KFUNCS_START(bpf_arm64_kfunc_ids)
BTF_ID_FLAGS(func, bpf_arm64_cpu_have_feature, KF_RCU)
BTF_ID_FLAGS(func, bpf_arch_flags)
BTF_KFUNCS_END(bpf_arm64_kfunc_ids)

static const struct btf_kfunc_id_set bpf_arm64_kfunc_set = {
	.owner		= THIS_MODULE,
	.set		= &bpf_arm64_kfunc_ids,
};

static int __init bpf_arm64_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
					 &bpf_arm64_kfunc_set);
}
late_initcall(bpf_arm64_kfunc_init);

/*
 * ARM64 cpuinfo iterator target
 */

static int native_c_show(struct seq_file *m, void *v)
{
	int j;
	int cpu = m->index;
	bool aarch32 = personality(current->personality) == PER_LINUX32;
	struct cpuinfo_arm64 *cpuinfo = v;
	u32 midr = cpuinfo->reg_midr;

	/*
	 * glibc reads /proc/cpuinfo to determine the number of
	 * online processors, looking for lines beginning with
	 * "processor".  Give glibc what it expects.
	 */
	seq_printf(m, "processor\t: %d\n", cpu);
	if (aarch32)
		seq_printf(m, "model name\t: ARMv8 Processor rev %d (%s)\n",
			   MIDR_REVISION(midr), COMPAT_ELF_PLATFORM);

	seq_printf(m, "BogoMIPS\t: %lu.%02lu\n",
		   loops_per_jiffy / (500000UL/HZ),
		   loops_per_jiffy / (5000UL/HZ) % 100);

	/*
	 * Dump out the common processor features in a single line.
	 * Userspace should read the hwcaps with getauxval(AT_HWCAP)
	 * rather than attempting to parse this, but there's a body of
	 * software which does already (at least for 32-bit).
	 */
	seq_puts(m, "Features\t:");
	if (aarch32) {
#ifdef CONFIG_AARCH32_EL0
		for (j = 0; j < ARRAY_SIZE(compat_hwcap_str); j++) {
			if (a32_elf_hwcap & (1 << j)) {
				/*
				 * Warn once if any feature should not
				 * have been present on arm64 platform.
				 */
				if (WARN_ON_ONCE(!compat_hwcap_str[j]))
					continue;

				seq_printf(m, " %s", compat_hwcap_str[j]);
			}
		}

		for (j = 0; j < ARRAY_SIZE(compat_hwcap2_str); j++)
			if (a32_elf_hwcap2 & (1 << j))
				seq_printf(m, " %s", compat_hwcap2_str[j]);
#endif /* CONFIG_AARCH32_EL0 */
	} else {
		for (j = 0; j < ARRAY_SIZE(hwcap_str); j++)
			if (cpu_have_feature(j))
				seq_printf(m, " %s", hwcap_str[j]);
	}
	seq_puts(m, "\n");

	seq_printf(m, "CPU implementer\t: 0x%02x\n", MIDR_IMPLEMENTOR(midr));
	seq_printf(m, "CPU architecture: 8\n");
	seq_printf(m, "CPU variant\t: 0x%x\n", MIDR_VARIANT(midr));
	seq_printf(m, "CPU part\t: 0x%03x\n", MIDR_PARTNUM(midr));
	seq_printf(m, "CPU revision\t: %d\n\n", MIDR_REVISION(midr));

	return 0;
}

static void bpf_c_stop(struct seq_file *m, void *v)
{
}

struct cpuinfo_arm64_seq_priv {
	cpumask_t allowed_mask;
};

static void *bpf_c_start(struct seq_file *m, loff_t *pos)
{
	struct cpuinfo_arm64_seq_priv *priv = m->private;
	struct task_struct *reaper = get_current_level1_reaper();

	task_effective_cpumask(reaper ?: current, &priv->allowed_mask);
	if (reaper)
		put_task_struct(reaper);

	/*
	 * DO NOT use cpumask_first() here: sys_read may start from somewhere in
	 * the middle of the file, and *pos may contain a value from the last
	 * read.
	 */
	*pos = cpumask_next(*pos - 1, &priv->allowed_mask);
	return *pos < nr_cpu_ids ? &per_cpu(cpu_data, *pos) : NULL;
}

static void *bpf_c_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct cpuinfo_arm64_seq_priv *priv = m->private;

	*pos = cpumask_next(*pos, &priv->allowed_mask);
	return *pos < nr_cpu_ids ? &per_cpu(cpu_data, *pos) : NULL;
}

struct bpf_iter__cpuinfo_arm64 {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct cpuinfo_arm64 *, cpuinfo);
};

static int bpf_c_show(struct seq_file *m, void *v)
{
	struct bpf_iter__cpuinfo_arm64 ctx;
	struct bpf_iter_meta meta;
	struct bpf_prog *prog;

	meta.seq = m;
	prog = bpf_iter_get_info(&meta, false);
	if (!prog)
		return native_c_show(m, v);

	ctx.meta = &meta;
	ctx.cpuinfo = (struct cpuinfo_arm64 *)v;
	return bpf_iter_run_prog(prog, &ctx);
}

static const struct seq_operations bpf_cpuinfo_op = {
	.start	= bpf_c_start,
	.next	= bpf_c_next,
	.stop	= bpf_c_stop,
	.show	= bpf_c_show
};

DEFINE_BPF_ITER_FUNC(cpuinfo_arm64, struct bpf_iter_meta *meta,
		     struct cpuinfo_arm64 *cpuinfo)

BTF_ID_LIST(btf_cpuinfo_arm64_id)
BTF_ID(struct, cpuinfo_arm64)

static const struct bpf_iter_seq_info cpuinfo_arm64_seq_info = {
	.seq_ops		= &bpf_cpuinfo_op,
	.init_seq_private	= NULL,
	.fini_seq_private	= NULL,
	.seq_priv_size		= sizeof(struct cpuinfo_arm64_seq_priv),
};

static struct bpf_iter_reg cpuinfo_arm64_reg_info = {
	.target			= "cpuinfo_arm64",
	.ctx_arg_info_size	= 1,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__cpuinfo_arm64, cpuinfo),
		  PTR_TO_BTF_ID },
	},
	.seq_info		= &cpuinfo_arm64_seq_info,
};

static int __init cpuinfo_iter_init(void)
{
	cpuinfo_arm64_reg_info.ctx_arg_info[0].btf_id = *btf_cpuinfo_arm64_id;
	return bpf_iter_reg_target(&cpuinfo_arm64_reg_info);
}
late_initcall(cpuinfo_iter_init);
