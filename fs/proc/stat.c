// SPDX-License-Identifier: GPL-2.0
#include <linux/cpumask.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/stat.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/time_namespace.h>
#include <linux/irqnr.h>
#include <linux/sched/cputime.h>
#include <linux/tick.h>
#ifdef CONFIG_BPF_RVI
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/pid_namespace.h>
#include <linux/cgroup.h>
#include <linux/cpuset.h>
#endif

#ifndef arch_irq_stat_cpu
#define arch_irq_stat_cpu(cpu) 0
#endif
#ifndef arch_irq_stat
#define arch_irq_stat() 0
#endif

u64 get_idle_time(struct kernel_cpustat *kcs, int cpu)
{
	u64 idle, idle_usecs = -1ULL;

	if (cpu_online(cpu))
		idle_usecs = get_cpu_idle_time_us(cpu, NULL);

	if (idle_usecs == -1ULL)
		/* !NO_HZ or cpu offline so we can rely on cpustat.idle */
		idle = kcs->cpustat[CPUTIME_IDLE];
	else
		idle = idle_usecs * NSEC_PER_USEC;

	return idle;
}

static u64 get_iowait_time(struct kernel_cpustat *kcs, int cpu)
{
	u64 iowait, iowait_usecs = -1ULL;

	if (cpu_online(cpu))
		iowait_usecs = get_cpu_iowait_time_us(cpu, NULL);

	if (iowait_usecs == -1ULL)
		/* !NO_HZ or cpu offline so we can rely on cpustat.iowait */
		iowait = kcs->cpustat[CPUTIME_IOWAIT];
	else
		iowait = iowait_usecs * NSEC_PER_USEC;

	return iowait;
}

static void show_irq_gap(struct seq_file *p, unsigned int gap)
{
	static const char zeros[] = " 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";

	while (gap > 0) {
		unsigned int inc;

		inc = min_t(unsigned int, gap, ARRAY_SIZE(zeros) / 2);
		seq_write(p, zeros, 2 * inc);
		gap -= inc;
	}
}

static void show_all_irqs(struct seq_file *p)
{
	unsigned int i, next = 0;

	for_each_active_irq(i) {
		show_irq_gap(p, i - next);
		seq_put_decimal_ull(p, " ", kstat_irqs_usr(i));
		next = i + 1;
	}
	show_irq_gap(p, nr_irqs - next);
}

static int show_stat(struct seq_file *p, void *v)
{
	int i, j;
	u64 user, nice, system, idle, iowait, irq, softirq, steal;
	u64 guest, guest_nice;
	u64 sum = 0;
	u64 sum_softirq = 0;
	unsigned int per_softirq_sums[NR_SOFTIRQS] = {0};
	struct timespec64 boottime;

	user = nice = system = idle = iowait =
		irq = softirq = steal = 0;
	guest = guest_nice = 0;
	getboottime64(&boottime);
	/* shift boot timestamp according to the timens offset */
	timens_sub_boottime(&boottime);

	for_each_possible_cpu(i) {
		struct kernel_cpustat kcpustat;
		u64 *cpustat = kcpustat.cpustat;

		kcpustat_cpu_fetch(&kcpustat, i);

		user		+= cpustat[CPUTIME_USER];
		nice		+= cpustat[CPUTIME_NICE];
		system		+= cpustat[CPUTIME_SYSTEM];
		idle		+= get_idle_time(&kcpustat, i);
		iowait		+= get_iowait_time(&kcpustat, i);
		irq		+= cpustat[CPUTIME_IRQ];
		softirq		+= cpustat[CPUTIME_SOFTIRQ];
		steal		+= cpustat[CPUTIME_STEAL];
		guest		+= cpustat[CPUTIME_GUEST];
		guest_nice	+= cpustat[CPUTIME_GUEST_NICE];
		sum		+= kstat_cpu_irqs_sum(i);
		sum		+= arch_irq_stat_cpu(i);

		for (j = 0; j < NR_SOFTIRQS; j++) {
			unsigned int softirq_stat = kstat_softirqs_cpu(j, i);

			per_softirq_sums[j] += softirq_stat;
			sum_softirq += softirq_stat;
		}
	}
	sum += arch_irq_stat();

	seq_put_decimal_ull(p, "cpu  ", nsec_to_clock_t(user));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(nice));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(system));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(idle));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(iowait));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(irq));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(softirq));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(steal));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(guest));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(guest_nice));
	seq_putc(p, '\n');

	for_each_online_cpu(i) {
		struct kernel_cpustat kcpustat;
		u64 *cpustat = kcpustat.cpustat;

		kcpustat_cpu_fetch(&kcpustat, i);

		/* Copy values here to work around gcc-2.95.3, gcc-2.96 */
		user		= cpustat[CPUTIME_USER];
		nice		= cpustat[CPUTIME_NICE];
		system		= cpustat[CPUTIME_SYSTEM];
		idle		= get_idle_time(&kcpustat, i);
		iowait		= get_iowait_time(&kcpustat, i);
		irq		= cpustat[CPUTIME_IRQ];
		softirq		= cpustat[CPUTIME_SOFTIRQ];
		steal		= cpustat[CPUTIME_STEAL];
		guest		= cpustat[CPUTIME_GUEST];
		guest_nice	= cpustat[CPUTIME_GUEST_NICE];
		seq_printf(p, "cpu%d", i);
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(user));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(nice));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(system));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(idle));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(iowait));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(irq));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(softirq));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(steal));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(guest));
		seq_put_decimal_ull(p, " ", nsec_to_clock_t(guest_nice));
		seq_putc(p, '\n');
	}
	seq_put_decimal_ull(p, "intr ", (unsigned long long)sum);

	show_all_irqs(p);

	seq_printf(p,
		"\nctxt %llu\n"
		"btime %llu\n"
		"processes %lu\n"
		"procs_running %u\n"
		"procs_blocked %u\n",
		nr_context_switches(),
		(unsigned long long)boottime.tv_sec,
		total_forks,
		nr_running(),
		nr_iowait());

	seq_put_decimal_ull(p, "softirq ", (unsigned long long)sum_softirq);

	for (i = 0; i < NR_SOFTIRQS; i++)
		seq_put_decimal_ull(p, " ", per_softirq_sums[i]);
	seq_putc(p, '\n');

	return 0;
}

static int stat_open(struct inode *inode, struct file *file)
{
	unsigned int size = 1024 + 128 * num_online_cpus();

	/* minimum size to display an interrupt count : 2 bytes */
	size += 2 * nr_irqs;
	return single_open_size(file, show_stat, NULL, size);
}

static const struct proc_ops stat_proc_ops = {
	.proc_flags	= PROC_ENTRY_PERMANENT,
	.proc_open	= stat_open,
	.proc_read_iter	= seq_read_iter,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int __init proc_stat_init(void)
{
	proc_create("stat", 0, NULL, &stat_proc_ops);
	return 0;
}
fs_initcall(proc_stat_init);

#ifdef CONFIG_BPF_RVI
__bpf_kfunc u64 bpf_get_idle_time(struct kernel_cpustat *kcs, int cpu)
{
	return get_idle_time(kcs, cpu);
}

__bpf_kfunc u64 bpf_get_iowait_time(struct kernel_cpustat *kcs, int cpu)
{
	return get_iowait_time(kcs, cpu);
}

__bpf_kfunc void bpf_show_all_irqs(struct seq_file *p)
{
	show_all_irqs(p);
}

BTF_KFUNCS_START(bpf_proc_stat_kfunc_ids)
BTF_ID_FLAGS(func, bpf_get_idle_time)
BTF_ID_FLAGS(func, bpf_get_iowait_time)
BTF_ID_FLAGS(func, bpf_show_all_irqs)
BTF_KFUNCS_END(bpf_proc_stat_kfunc_ids)

static const struct btf_kfunc_id_set bpf_proc_stat_kfunc_set = {
	.owner		= THIS_MODULE,
	.set		= &bpf_proc_stat_kfunc_ids,
};

static int __init bpf_proc_stat_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
					 &bpf_proc_stat_kfunc_set);
}
late_initcall(bpf_proc_stat_kfunc_init);

struct stat_sum_data {
	u64 user, nice, system, idle, iowait, irq, softirq, steal;
	u64 guest, guest_nice;
	u64 sum;
	u64 sum_softirq;
	unsigned int per_softirq_sums[NR_SOFTIRQS];
};

struct stat_seq_priv {
	cpumask_t allowed_mask;
	struct cpuacct *cpuacct;
	bool sum_printed;
	struct task_struct *task;
	struct seq_file seqf_pcpu;
};

static int seq_file_setup(struct seq_file *seq)
{
	seq->size = PAGE_SIZE << 3;
	seq->buf = kvzalloc(seq->size, GFP_KERNEL);
	if (!seq->buf)
		return -ENOMEM;
	return 0;
}

static void seq_file_destroy(struct seq_file *seq)
{
	if (seq->buf)
		kvfree(seq->buf);
}

static void *bpf_c_start(struct seq_file *m, loff_t *pos)
{
	struct stat_seq_priv *priv = m->private;
	struct task_struct *reaper = get_current_level1_reaper();

	priv->task = reaper ?: current;
	task_effective_cpumask(priv->task, &priv->allowed_mask);
	priv->cpuacct = task_cpuacct(priv->task);
	if (seq_file_setup(&priv->seqf_pcpu))
		return NULL;

	/*
	 * DO NOT use cpumask_first() here: sys_read may start from somewhere in
	 * the middle of the file, and *pos may contain a value from the last
	 * read.
	 */
	*pos = cpumask_next(*pos - 1, &priv->allowed_mask);
	if ((*pos) < nr_cpu_ids)
		// avoid 0, which will be treated as NULL
		return (void *)(unsigned long)((*pos) + 1);
	return NULL;
}

static void *bpf_c_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct stat_seq_priv *priv = m->private;

	*pos = cpumask_next(*pos, &priv->allowed_mask);

	if ((*pos) == nr_cpu_ids) {
		if (!priv->sum_printed)
			priv->sum_printed = true;
		else {
			++*pos; // just to silence "did not updated position index" msg
			return NULL;
		}
	}

	// avoid 0, which will be treated as NULL
	return (void *)(unsigned long)((*pos) + 1);
}

struct bpf_iter__stat {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	u64 cpuid __aligned(8);
	__bpf_md_ptr(struct cpuacct *, cpuacct);
	u64 arch_irq_stat_cpu __aligned(8);
	u64 arch_irq_stat __aligned(8);
	bool print_all __aligned(8);
	__bpf_md_ptr(struct seq_file *, seqf_pcpu);
};

static int bpf_show_stat(struct seq_file *m, void *v)
{
	struct stat_seq_priv *priv = m->private;
	struct bpf_iter__stat ctx;
	struct bpf_iter_meta meta;
	struct bpf_prog *prog;
	u64 cpuid = (unsigned long)v - 1; // decode '+ 1'

	meta.seq = m;
	prog = bpf_iter_get_info(&meta, false);
	if (!prog)
		return show_stat(m, v);

	ctx.meta = &meta;

	ctx.cpuid = cpuid;
	ctx.cpuacct = priv->cpuacct;
	if (cpuid != nr_cpu_ids)
		ctx.arch_irq_stat_cpu = arch_irq_stat_cpu(cpuid);
	else
		ctx.arch_irq_stat = arch_irq_stat();
	ctx.print_all = (cpuid == nr_cpu_ids);
	ctx.seqf_pcpu = &priv->seqf_pcpu;

	return bpf_iter_run_prog(prog, &ctx);
}

static void bpf_c_stop(struct seq_file *m, void *v)
{
	struct stat_seq_priv *priv = m->private;

	if (priv->task != current)
		put_task_struct(priv->task);
	seq_file_destroy(&priv->seqf_pcpu);
}

const struct seq_operations bpf_stat_ops = {
	.start	= bpf_c_start,
	.next	= bpf_c_next,
	.stop	= bpf_c_stop,
	.show	= bpf_show_stat,
};

DEFINE_BPF_ITER_FUNC(stat, struct bpf_iter_meta *meta,
			   u64 cpuid,
			   struct cpuacct *cpuacct,
			   u64 arch_irq_stat_cpu,
			   u64 arch_irq_stat,
			   bool print_all,
			   struct seq_file *seqf_pcpu)

BTF_ID_LIST(btf_stat_id)
BTF_ID(struct, cpuacct)

static const struct bpf_iter_seq_info stat_seq_info = {
	.seq_ops		= &bpf_stat_ops,
	.init_seq_private	= NULL,
	.fini_seq_private	= NULL,
	.seq_priv_size		= sizeof(struct stat_seq_priv),
};

static struct bpf_iter_reg stat_reg_info = {
	.target			= "stat",
	.ctx_arg_info_size	= 1,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__stat, cpuacct),
			PTR_TO_BTF_ID, },
	},
	.seq_info		= &stat_seq_info,
};

static int __init stat_iter_init(void)
{
	stat_reg_info.ctx_arg_info[0].btf_id = btf_stat_id[0];
	return bpf_iter_reg_target(&stat_reg_info);
}
late_initcall(stat_iter_init);
#endif /* CONFIG_BPF_RVI */
