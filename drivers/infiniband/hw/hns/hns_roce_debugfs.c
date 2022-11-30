// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2022 Hisilicon Limited.
 */

#include <linux/debugfs.h>
#include <linux/device.h>

#include "hns_roce_common.h"
#include "hns_roce_device.h"
#include "hns_roce_dca.h"
#include "hns_roce_debugfs.h"

static struct dentry *hns_roce_dbgfs_root;

#define KB 1024

/* debugfs seqfile */
struct hns_debugfs_seqfile {
	struct dentry *entry;
	int (*read)(struct seq_file *seq, void *data);
	void *data;
};

static int hns_debugfs_seqfile_open(struct inode *inode, struct file *f)
{
	struct hns_debugfs_seqfile *seqfile = inode->i_private;

	return single_open(f, seqfile->read, seqfile->data);
}

static const struct file_operations hns_debugfs_seqfile_fops = {
	.owner = THIS_MODULE,
	.open = hns_debugfs_seqfile_open,
	.release = single_release,
	.read = seq_read,
	.llseek = seq_lseek
};

static void init_debugfs_seqfile(struct hns_debugfs_seqfile *seq,
				 const char *name, struct dentry *parent,
				 int (*read_fn)(struct seq_file *, void *),
				 void *data)
{
	struct dentry *entry;

	entry = debugfs_create_file(name, 0400, parent, seq,
				    &hns_debugfs_seqfile_fops);
	if (IS_ERR(entry))
		return;

	seq->read = read_fn;
	seq->data = data;
	seq->entry = entry;
}

static void cleanup_debugfs_seqfile(struct hns_debugfs_seqfile *seq)
{
	debugfs_remove(seq->entry);
	seq->entry = NULL;
}

/* DCA debugfs */
struct hns_dca_ctx_debugfs {
	struct dentry *root; /* pool debugfs entry */
	struct hns_debugfs_seqfile mem; /* mems in pool */
	struct hns_debugfs_seqfile qp; /* QPs stats in pool */
};

struct hns_dca_debugfs {
	struct dentry *root; /* dev debugfs entry */
	struct hns_debugfs_seqfile pool; /* pools stats on device */
	struct hns_debugfs_seqfile qp; /* QPs stats on device */
	struct hns_dca_ctx_debugfs kctx; /* kDCA context */
};

/* Debugfs for device */
struct hns_roce_dev_debugfs {
	struct dentry *root;
	struct hns_dca_debugfs *dca_root;
};

struct dca_mem_stats {
	unsigned int total_mems;
	unsigned int clean_mems;
	size_t free_size;
	size_t total_size;
	size_t active_size;
	size_t locked_size;
};

#define DCA_CTX_PID_LEN	10
#define DCA_CTX_STATE_LEN 22

#define LOADING_PERCENT_SCALE 100
#define LOADING_PERCENT_SHIFT 2

static int stats_dca_pool_proc(struct hns_dca_page_state *states, u32 count,
			       void *param)
{
	struct dca_mem_stats *stats = param;
	struct hns_dca_page_state *s;
	int i, free_pages;

	free_pages = 0;
	for (i = 0; i < count; i++) {
		s = &states[i];
		if (s->buf_id == HNS_DCA_INVALID_BUF_ID) {
			free_pages++;
			stats->free_size += HNS_HW_PAGE_SIZE;
		} else {
			if (s->lock)
				stats->locked_size += HNS_HW_PAGE_SIZE;

			if (s->active)
				stats->active_size += HNS_HW_PAGE_SIZE;
		}
	}

	stats->total_size += (count * HNS_HW_PAGE_SIZE);
	stats->total_mems++;
	if (free_pages == count)
		stats->clean_mems++;

	return 0;
}

/* stats QPs in DCA pool */
struct dca_stats_qp_attr {
	unsigned long *qpn_bitmap;
	unsigned int qpn_max;
};

static int stats_dca_qp_proc(struct hns_dca_page_state *states, u32 count,
			     void *param)
{
	struct dca_stats_qp_attr *attr = param;
	struct hns_dca_page_state *s;
	u32 qpn;
	int i;

	for (i = 0; i < count; i++) {
		s = &states[i];
		if (s->buf_id == HNS_DCA_INVALID_BUF_ID || s->lock ||
		    !s->active)
			continue;

		qpn = HNS_DCA_BUF_ID_TO_QPN(s->buf_id);
		if (qpn < attr->qpn_max)
			set_bit(qpn, attr->qpn_bitmap);
	}

	return 0;
}

static void dca_ctx_stats_qp(struct hns_roce_dca_ctx *ctx,
			     unsigned long *qpn_bitmap, unsigned int qpn_max)
{
	struct dca_stats_qp_attr attr;

	attr.qpn_bitmap = qpn_bitmap;
	attr.qpn_max = qpn_max;
	hns_roce_enum_dca_pool(ctx, &attr, stats_dca_qp_proc);
}

static void dca_ctx_stats_mem(struct hns_roce_dca_ctx *ctx,
			      struct dca_mem_stats *stats)
{
	hns_roce_enum_dca_pool(ctx, stats, stats_dca_pool_proc);
}

static void dca_setup_pool_name(pid_t pid, bool is_kdca, char *name, int size)
{
	if (is_kdca)
		snprintf(name, size, "kernel");
	else
		snprintf(name, size, "%d", pid);
}

static u64 calc_loading_percent(size_t total, size_t free, u32 *out_rem)
{
	u32 all_pages, used_pages, free_pages, scale;
	u64 percent = 0;
	u32 rem = 0;

	all_pages = total >> HNS_HW_PAGE_SHIFT;
	free_pages = free >> HNS_HW_PAGE_SHIFT;
	if (all_pages >= free_pages) {
		used_pages = all_pages - free_pages;
		scale = LOADING_PERCENT_SCALE * LOADING_PERCENT_SCALE;
		percent = (used_pages * scale) / all_pages;
		percent = div_u64_rem(percent, LOADING_PERCENT_SCALE, &rem);
	}

	if (out_rem)
		*out_rem = rem;

	return percent;
}

static void dca_print_pool_stats(struct hns_roce_dca_ctx *ctx, pid_t pid,
				 bool is_kdca, struct seq_file *file)
{
	char name[DCA_CTX_PID_LEN];
	u64 percent;
	u32 rem = 0;

	percent = calc_loading_percent(ctx->total_size, ctx->free_size, &rem);
	dca_setup_pool_name(pid, is_kdca, name, sizeof(name));
	seq_printf(file, "%-10s %-16ld %-16ld %-16u %llu.%0*u\n", name,
		   ctx->total_size / KB, ctx->free_size / KB, ctx->free_mems,
		   percent, LOADING_PERCENT_SHIFT, rem);
}

static void dca_stats_dev_pool_in_seqfile(struct hns_roce_dev *hr_dev,
					  struct seq_file *file)
{
	struct hns_roce_ucontext *uctx, *tmp;

	seq_printf(file, "%-10s %-16s %-16s %-16s %-s\n", "PID", "Total(kB)",
		   "Free(kB)", "Clean(BLK)", "Loading");

	/* Write kernel DCA pool stats */
	dca_print_pool_stats(&hr_dev->dca_ctx, 0, true, file);
	/* Write user DCA pool stats */
	spin_lock(&hr_dev->uctx_list_lock);
	list_for_each_entry_safe(uctx, tmp, &hr_dev->uctx_list, list) {
		spin_unlock(&hr_dev->uctx_list_lock);
		dca_print_pool_stats(&uctx->dca_ctx, uctx->pid, false, file);
		spin_lock(&hr_dev->uctx_list_lock);
	}
	spin_unlock(&hr_dev->uctx_list_lock);
}

struct dca_qp_stats {
	char name[DCA_CTX_PID_LEN];
	char state[DCA_CTX_STATE_LEN];
	u32 qpn;
	u32 total_size;
	u32 sq_size;
	u32 rq_size;
	u32 sge_size;
};

static void dca_setup_qp_state(struct hns_roce_qp *hr_qp, char *buf, int size)
{
	struct hns_roce_dca_cfg *cfg = &hr_qp->dca_cfg;

	if (cfg->buf_id == HNS_DCA_INVALID_BUF_ID)
		snprintf(buf, size, "detached");
	else if (hr_qp->rq.wqe_cnt > 0)
		snprintf(buf, size, "stable");
	else
		snprintf(buf, size, "attached-%-u", cfg->attach_count);
}

static void dca_setup_qp_stats(struct hns_roce_qp *hr_qp,
			       struct dca_qp_stats *stats)
{
	struct hns_roce_ucontext *uctx = NULL;

	if (!(hr_qp->en_flags & HNS_ROCE_QP_CAP_DYNAMIC_CTX_ATTACH) ||
	    !hr_qp->ibqp.pd)
		return;

	if (hr_qp->ibqp.pd->uobject)
		uctx = to_hr_ucontext(hr_qp->ibqp.pd->uobject->context);

	dca_setup_pool_name(uctx ? uctx->pid : 0, !uctx, stats->name,
			    sizeof(stats->name));
	stats->qpn = (u32)hr_qp->qpn;
	stats->total_size = hr_qp->buff_size;

	stats->sq_size = to_hr_hem_entries_size(hr_qp->sq.wqe_cnt,
						hr_qp->sq.wqe_shift);
	stats->sge_size = to_hr_hem_entries_size(hr_qp->sge.sge_cnt,
						 hr_qp->sge.sge_shift);
	stats->rq_size = to_hr_hem_entries_size(hr_qp->rq.wqe_cnt,
						hr_qp->rq.wqe_shift);

	dca_setup_qp_state(hr_qp, stats->state, sizeof(stats->state));
}

static void dca_stats_dev_qp_in_seqfile(struct hns_roce_dev *hr_dev,
					struct seq_file *file)
{
	struct dca_qp_stats stats;
	struct hns_roce_qp *hr_qp;
	unsigned long id;

	seq_printf(file, "%-10s %-10s %-10s %s\n", "QPN", "Size(kB)", "PID",
		   "State");

	xa_lock(&hr_dev->qp_table_xa);
	xa_for_each(&hr_dev->qp_table_xa, id, hr_qp) {
		stats.total_size = 0;
		dca_setup_qp_stats(hr_qp, &stats);
		if (!stats.total_size)
			continue;

		xa_unlock(&hr_dev->qp_table_xa);
		seq_printf(file, "%-10u %-10u %-10s %-s\n", stats.qpn,
			   stats.total_size / KB, stats.name, stats.state);
		xa_lock(&hr_dev->qp_table_xa);
	}
	xa_unlock(&hr_dev->qp_table_xa);
}

static void dca_stats_ctx_qp_in_seqfile(struct hns_roce_dev *hr_dev,
					struct hns_roce_dca_ctx *ctx,
					struct seq_file *file)
{
	struct dca_qp_stats stats;
	struct hns_roce_qp *hr_qp;
	unsigned int qpn, nbits;
	unsigned long *bitmap;

	nbits = hr_dev->caps.num_qps;
	if (nbits < 1)
		return;

	bitmap = bitmap_zalloc(nbits, GFP_ATOMIC);
	if (!bitmap)
		return;

	seq_printf(file, "%-10s %-10s %-10s %-10s %-10s\n", "QPN", "Total(kB)",
		   "SQ(kB)", "SGE(kB)", "RQ(kB)");

	dca_ctx_stats_qp(ctx, bitmap, nbits);
	for_each_set_bit(qpn, bitmap, nbits) {
		stats.total_size = 0;
		xa_lock(&hr_dev->qp_table_xa);
		hr_qp = __hns_roce_qp_lookup(hr_dev, qpn);
		if (hr_qp)
			dca_setup_qp_stats(hr_qp, &stats);
		xa_unlock(&hr_dev->qp_table_xa);
		if (!stats.total_size)
			continue;

		seq_printf(file, "%-10u %-10u %-10u %-10u %-10u\n",
			   stats.qpn, stats.total_size / KB, stats.sq_size / KB,
			   stats.sge_size / KB, stats.rq_size / KB);
	}
	bitmap_free(bitmap);
}

static void dca_stats_ctx_mem_in_seqfile(struct hns_roce_dca_ctx *ctx,
					 bool is_kdca, struct seq_file *file)
{
	struct dca_mem_stats stats = {};
	u64 percent;
	u32 rem = 0;

#define DCA_STAT_NAME_FMT "%-22s "
#define dca_ctx_print_mem_size(f, n, fmt, v) \
		seq_printf(f, DCA_STAT_NAME_FMT fmt "\n", n, v)

#define dca_ctx_print_mem_kb(f, n, v) \
	dca_ctx_print_mem_size(f, n, "%-u kB", (u32)((v) / KB))

	dca_ctx_stats_mem(ctx, &stats);
	percent = calc_loading_percent(stats.total_size, stats.free_size, &rem);
	seq_printf(file, DCA_STAT_NAME_FMT "%llu.%0*u\n", "Loading:", percent,
		   LOADING_PERCENT_SHIFT, rem);
	dca_ctx_print_mem_kb(file, "Total:", stats.total_size);
	dca_ctx_print_mem_kb(file, "Free:", stats.free_size);
	dca_ctx_print_mem_kb(file, "Active:", stats.active_size);
	dca_ctx_print_mem_kb(file, "Locked:", stats.locked_size);
	dca_ctx_print_mem_size(file, "Dirty:", "%-u Blocks",
			       stats.total_mems - stats.clean_mems);
	dca_ctx_print_mem_size(file, "Clean:", "%-u Blocks", stats.clean_mems);
	if (is_kdca) {
		dca_ctx_print_mem_size(file, "Unit:", "%-u", ctx->unit_size);
		dca_ctx_print_mem_size(file, "Max:", "%-zu", ctx->max_size);
		dca_ctx_print_mem_size(file, "Min:", "%-zu", ctx->min_size);
	}
}

static int dca_debugfs_pool_show(struct seq_file *file, void *offset)
{
	struct hns_roce_dev *hr_dev = file->private;

	dca_stats_dev_pool_in_seqfile(hr_dev, file);
	return 0;
}

static int dca_debugfs_qp_show(struct seq_file *file, void *offset)
{
	struct hns_roce_dev *hr_dev = file->private;

	dca_stats_dev_qp_in_seqfile(hr_dev, file);
	return 0;
}

static int dca_debugfs_kctx_qp_stats_show(struct seq_file *file, void *offset)
{
	struct hns_roce_dev *hr_dev = file->private;

	dca_stats_ctx_qp_in_seqfile(hr_dev, &hr_dev->dca_ctx, file);
	return 0;
}

static int dca_debugfs_uctx_qp_stats_show(struct seq_file *file, void *offset)
{
	struct hns_roce_ucontext *uctx = file->private;

	dca_stats_ctx_qp_in_seqfile(to_hr_dev(uctx->ibucontext.device),
				    &uctx->dca_ctx, file);
	return 0;
}

static int dca_debugfs_kctx_mem_stats_show(struct seq_file *file, void *offset)
{
	struct hns_roce_dev *hr_dev = file->private;

	dca_stats_ctx_mem_in_seqfile(&hr_dev->dca_ctx, true, file);
	return 0;
}

static int dca_debugfs_uctx_mem_stats_show(struct seq_file *file, void *offset)
{
	struct hns_roce_ucontext *uctx = file->private;

	dca_stats_ctx_mem_in_seqfile(&uctx->dca_ctx, false, file);
	return 0;
}

static void init_dca_ctx_debugfs(struct hns_dca_ctx_debugfs *dbgfs,
				 struct dentry *parent,
				 struct hns_roce_dev *hr_dev,
				 struct hns_roce_ucontext *uctx)
{
	char name[DCA_CTX_PID_LEN];

	if (IS_ERR_OR_NULL(parent))
		return;

	dca_setup_pool_name(uctx ? uctx->pid : 0, !uctx, name, sizeof(name));
	dbgfs->root = debugfs_create_dir(name, parent);
	if (IS_ERR_OR_NULL(dbgfs->root))
		return;

	if (uctx) {
		init_debugfs_seqfile(&dbgfs->mem, "mstats", dbgfs->root,
				     dca_debugfs_uctx_mem_stats_show, uctx);
		init_debugfs_seqfile(&dbgfs->qp, "qp", dbgfs->root,
				     dca_debugfs_uctx_qp_stats_show, uctx);
	} else {
		init_debugfs_seqfile(&dbgfs->mem, "mstats", dbgfs->root,
				     dca_debugfs_kctx_mem_stats_show, hr_dev);
		init_debugfs_seqfile(&dbgfs->qp, "qp", dbgfs->root,
				     dca_debugfs_kctx_qp_stats_show, hr_dev);
	}
}

static void cleanup_dca_ctx_debugfs(struct hns_dca_ctx_debugfs *ctx_dbgfs)
{
	cleanup_debugfs_seqfile(&ctx_dbgfs->qp);
	cleanup_debugfs_seqfile(&ctx_dbgfs->mem);
	debugfs_remove_recursive(ctx_dbgfs->root);
}

static struct hns_dca_debugfs *
create_dca_debugfs(struct hns_roce_dev *hr_dev, struct dentry *parent)
{
	struct hns_dca_debugfs *dbgfs;

	if (IS_ERR(parent))
		return NULL;

	dbgfs = kzalloc(sizeof(*dbgfs), GFP_KERNEL);
	if (!dbgfs)
		return NULL;

	dbgfs->root = debugfs_create_dir("dca", parent);
	if (IS_ERR_OR_NULL(dbgfs->root)) {
		kfree(dbgfs);
		return NULL;
	}

	init_debugfs_seqfile(&dbgfs->pool, "pool", dbgfs->root,
			     dca_debugfs_pool_show, hr_dev);
	init_debugfs_seqfile(&dbgfs->qp, "qp", dbgfs->root,
			     dca_debugfs_qp_show, hr_dev);

	init_dca_ctx_debugfs(&dbgfs->kctx, dbgfs->root, hr_dev, NULL);

	return dbgfs;
}

static void destroy_dca_debugfs(struct hns_dca_debugfs *dca_dbgfs)
{
	cleanup_dca_ctx_debugfs(&dca_dbgfs->kctx);
	cleanup_debugfs_seqfile(&dca_dbgfs->pool);
	cleanup_debugfs_seqfile(&dca_dbgfs->qp);
	debugfs_remove_recursive(dca_dbgfs->root);
	kfree(dca_dbgfs);
}

/* debugfs for ucontext */
void hns_roce_register_uctx_debugfs(struct hns_roce_dev *hr_dev,
				    struct hns_roce_ucontext *uctx)
{
	struct hns_roce_dev_debugfs *dev_dbgfs = hr_dev->dbgfs;
	struct hns_dca_debugfs *dca_dbgfs;

	if (!dev_dbgfs)
		return;

	dca_dbgfs = dev_dbgfs->dca_root;
	if (dca_dbgfs) {
		uctx->dca_dbgfs = kzalloc(sizeof(struct hns_dca_ctx_debugfs),
					  GFP_KERNEL);
		if (!uctx->dca_dbgfs)
			return;

		init_dca_ctx_debugfs(uctx->dca_dbgfs, dca_dbgfs->root,
				     hr_dev, uctx);
	}
}

void hns_roce_unregister_uctx_debugfs(struct hns_roce_dev *hr_dev,
				      struct hns_roce_ucontext *uctx)
{
	struct hns_dca_ctx_debugfs *dbgfs = uctx->dca_dbgfs;

	if (dbgfs) {
		uctx->dca_dbgfs = NULL;
		cleanup_dca_ctx_debugfs(dbgfs);
		kfree(dbgfs);
	}
}

/* debugfs for device */
void hns_roce_register_debugfs(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_dev_debugfs *dbgfs;

	if (IS_ERR_OR_NULL(hns_roce_dbgfs_root))
		return;

	dbgfs = kzalloc(sizeof(*dbgfs), GFP_KERNEL);
	if (!dbgfs)
		return;

	dbgfs->root = debugfs_create_dir(dev_name(&hr_dev->ib_dev.dev),
					 hns_roce_dbgfs_root);
	if (IS_ERR(dbgfs->root)) {
		kfree(dbgfs);
		return;
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_DCA_MODE)
		dbgfs->dca_root = create_dca_debugfs(hr_dev, dbgfs->root);

	hr_dev->dbgfs = dbgfs;
}

void hns_roce_unregister_debugfs(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_dev_debugfs *dbgfs;

	if (IS_ERR_OR_NULL(hns_roce_dbgfs_root))
		return;

	dbgfs = hr_dev->dbgfs;
	if (!dbgfs)
		return;

	hr_dev->dbgfs = NULL;

	if (dbgfs->dca_root) {
		destroy_dca_debugfs(dbgfs->dca_root);
		dbgfs->dca_root = NULL;
	}

	debugfs_remove_recursive(dbgfs->root);
	kfree(dbgfs);
}

/* debugfs for hns module */
void hns_roce_init_debugfs(void)
{
	hns_roce_dbgfs_root = debugfs_create_dir("hns_roce", NULL);
}

void hns_roce_cleanup_debugfs(void)
{
	debugfs_remove_recursive(hns_roce_dbgfs_root);
	hns_roce_dbgfs_root = NULL;
}
