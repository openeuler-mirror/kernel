// SPDX-License-Identifier: GPL-2.0
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <asm/local.h>

#include "debugfs.h"

/*
 * Per-CPU I/O counters, same pattern as block layer disk_stats / part_stat:
 * update under preempt_disable with __this_cpu_* (io_inflight via local_t);
 * readers sum across CPUs.
 */
struct p2p_io_stats {
	u64 io_issued;
	u64 io_bytes;
	local_t io_inflight;
	u64 io_failed;
	u64 io_issue_failed;
};

struct p2p_io_stats_snapshot {
	u64 io_issued;
	u64 io_bytes;
	s64 io_inflight;
	u64 io_failed;
	u64 io_issue_failed;
};

static DEFINE_PER_CPU(struct p2p_io_stats, p2p_io_stats);
static struct dentry *p2p_debugfs_root;

void p2p_stats_io_issued(u64 bytes)
{
	preempt_disable();
	__this_cpu_inc(p2p_io_stats.io_issued);
	__this_cpu_add(p2p_io_stats.io_bytes, bytes);
	local_inc(&this_cpu_ptr(&p2p_io_stats)->io_inflight);
	preempt_enable();
}

void p2p_stats_io_issue_failed(void)
{
	preempt_disable();
	__this_cpu_inc(p2p_io_stats.io_issue_failed);
	preempt_enable();
}

void p2p_stats_io_complete(blk_status_t status)
{
	preempt_disable();
	if (status)
		__this_cpu_inc(p2p_io_stats.io_failed);
	local_dec(&this_cpu_ptr(&p2p_io_stats)->io_inflight);
	preempt_enable();
}

static void p2p_io_stats_snapshot(struct p2p_io_stats_snapshot *out)
{
	unsigned int cpu;

	memset(out, 0, sizeof(*out));
	for_each_possible_cpu(cpu) {
		struct p2p_io_stats *s = per_cpu_ptr(&p2p_io_stats, cpu);

		out->io_issued += s->io_issued;
		out->io_bytes += s->io_bytes;
		out->io_inflight += local_read(&s->io_inflight);
		out->io_failed += s->io_failed;
		out->io_issue_failed += s->io_issue_failed;
	}
}

static int p2p_summary_show(struct seq_file *seq, void *unused)
{
	struct p2p_io_stats_snapshot snapshot;

	p2p_io_stats_snapshot(&snapshot);

	seq_printf(seq, "io_issued: %llu\n", snapshot.io_issued);
	seq_printf(seq, "io_bytes: %llu\n", snapshot.io_bytes);
	seq_printf(seq, "io_inflight: %lld\n", snapshot.io_inflight);
	seq_printf(seq, "io_failed: %llu\n", snapshot.io_failed);
	seq_printf(seq, "io_issue_failed: %llu\n", snapshot.io_issue_failed);
	return 0;
}

static int p2p_summary_open(struct inode *inode, struct file *file)
{
	return single_open(file, p2p_summary_show, NULL);
}

static ssize_t p2p_summary_write(struct file *file,
				 const char __user *buf, size_t count,
				 loff_t *ppos)
{
	unsigned int cpu;

	if (!count)
		return 0;

	/* Reset cumulative counters only; leave io_inflight alone. */
	for_each_possible_cpu(cpu) {
		struct p2p_io_stats *s = per_cpu_ptr(&p2p_io_stats, cpu);

		s->io_issued = 0;
		s->io_bytes = 0;
		s->io_failed = 0;
		s->io_issue_failed = 0;
	}
	return count;
}

static const struct file_operations p2p_summary_fops = {
	.owner = THIS_MODULE,
	.open = p2p_summary_open,
	.read = seq_read,
	.write = p2p_summary_write,
	.llseek = seq_lseek,
	.release = single_release,
};

void p2p_debugfs_init(void)
{
	struct dentry *root;
	struct dentry *summary;

	root = debugfs_create_dir("p2p_device", NULL);
	if (IS_ERR(root)) {
		pr_warn("p2p: create debugfs directory err %ld\n",
			PTR_ERR(root));
		return;
	}

	summary = debugfs_create_file("summary", 0600, root, NULL,
				      &p2p_summary_fops);
	if (IS_ERR(summary)) {
		pr_warn("p2p: create debugfs summary err %ld\n",
			PTR_ERR(summary));
		debugfs_remove_recursive(root);
		return;
	}

	p2p_debugfs_root = root;
}

void p2p_debugfs_exit(void)
{
	debugfs_remove_recursive(p2p_debugfs_root);
	p2p_debugfs_root = NULL;
}
