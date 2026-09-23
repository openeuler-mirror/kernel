// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Huawei Technologies Co., Ltd */
#include <linux/cpumask.h>
#include <linux/bpf.h>
#include <linux/cpuset.h>
#include <linux/pid_namespace.h>

struct cpuinfo_x86_bpf {
	unsigned int cpu_khz;
	unsigned int siblings;
};

struct bpf_iter__cpuinfo_x86 {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct cpuinfo_x86 *, cpuinfo);
	__bpf_md_ptr(struct cpuinfo_x86_bpf *, cpuinfo_bpf);
};

struct cpuinfo_x86_seq_priv {
	cpumask_t allowed_mask;
};

static void *bpf_c_start(struct seq_file *m, loff_t *pos)
{
	struct cpuinfo_x86_seq_priv *priv = m->private;
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
	if ((*pos) < nr_cpu_ids)
		return &cpu_data(*pos);
	return NULL;
}

static void *bpf_c_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct cpuinfo_x86_seq_priv *priv = m->private;

	*pos = cpumask_next(*pos, &priv->allowed_mask);
	if ((*pos) < nr_cpu_ids)
		return &cpu_data(*pos);
	return NULL;
}

int show_cpuinfo(struct seq_file *m, void *v);

static int bpf_show_cpuinfo(struct seq_file *m, void *v)
{
	struct bpf_iter__cpuinfo_x86 ctx;
	struct bpf_iter_meta meta;
	struct cpuinfo_x86_bpf cpuinfo_bpf;
	struct bpf_prog *prog;

	meta.seq = m;
	prog = bpf_iter_get_info(&meta, false);
	if (!prog)
		return show_cpuinfo(m, v);

	ctx.meta = &meta;
	ctx.cpuinfo = (struct cpuinfo_x86 *)v;

	cpuinfo_bpf.cpu_khz = cpu_khz;
	cpuinfo_bpf.siblings = cpumask_weight(topology_core_cpumask(ctx.cpuinfo->cpu_index));
	ctx.cpuinfo_bpf = &cpuinfo_bpf;

	return bpf_iter_run_prog(prog, &ctx);
}

static void bpf_c_stop(struct seq_file *m, void *v)
{
}

const struct seq_operations bpf_cpuinfo_op = {
	.start	= bpf_c_start,
	.next	= bpf_c_next,
	.stop	= bpf_c_stop,
	.show	= bpf_show_cpuinfo,
};

DEFINE_BPF_ITER_FUNC(cpuinfo_x86, struct bpf_iter_meta *meta, struct cpuinfo_x86 *cpuinfo,
		struct cpuinfo_x86_bpf *cpuinfo_bpf)

BTF_ID_LIST(btf_cpuinfo_x86_id)
BTF_ID(struct, cpuinfo_x86)
BTF_ID(struct, cpuinfo_x86_bpf)

static const struct bpf_iter_seq_info cpuinfo_x86_seq_info = {
	.seq_ops		= &bpf_cpuinfo_op,
	.init_seq_private	= NULL,
	.fini_seq_private	= NULL,
	.seq_priv_size		= sizeof(struct cpuinfo_x86_seq_priv),
};

static struct bpf_iter_reg cpuinfo_x86_reg_info = {
	.target			= "cpuinfo_x86",
	.ctx_arg_info_size	= 2,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__cpuinfo_x86, cpuinfo),
		  PTR_TO_BTF_ID, },
		{ offsetof(struct bpf_iter__cpuinfo_x86, cpuinfo_bpf),
		  PTR_TO_BTF_ID, },
	},
	.seq_info		= &cpuinfo_x86_seq_info,
};

static int __init cpuinfo_iter_init(void)
{
	cpuinfo_x86_reg_info.ctx_arg_info[0].btf_id = btf_cpuinfo_x86_id[0];
	cpuinfo_x86_reg_info.ctx_arg_info[1].btf_id = btf_cpuinfo_x86_id[1];
	return bpf_iter_reg_target(&cpuinfo_x86_reg_info);
}
late_initcall(cpuinfo_iter_init);

enum arch_flags_type {
	X86_CAP,
	X86_BUG,
	X86_POWER,
	X86_POWER_SIZE,
};

__bpf_kfunc const char *bpf_arch_flags(enum arch_flags_type t, int i)
{
	switch (t) {
	case X86_CAP:
		return x86_cap_flags[i];
	case X86_BUG:
		return x86_bug_flags[i];
	case X86_POWER:
		return x86_power_flags[i];
	case X86_POWER_SIZE:
		return (void *)ARRAY_SIZE(x86_power_flags);
	default:
		return NULL;
	}
}

BTF_KFUNCS_START(bpf_arch_flags_kfunc_ids)
BTF_ID_FLAGS(func, bpf_arch_flags)
BTF_KFUNCS_END(bpf_arch_flags_kfunc_ids)

static const struct btf_kfunc_id_set bpf_arch_flags_kfunc_set = {
	.owner		= THIS_MODULE,
	.set		= &bpf_arch_flags_kfunc_ids,
};

static int __init bpf_arch_flags_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
					 &bpf_arch_flags_kfunc_set);
}
late_initcall(bpf_arch_flags_kfunc_init);
