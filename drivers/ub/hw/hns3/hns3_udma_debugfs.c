// SPDX-License-Identifier: GPL-2.0
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include <linux/debugfs.h>
#include <linux/device.h>
#include "hns3_udma_common.h"
#include "hns3_udma_device.h"
#include "hns3_udma_dca.h"
#include "hns3_udma_debugfs.h"

static struct dentry *udma_dbgfs_root;

static int udma_debugfs_seqfile_open(struct inode *inode, struct file *f)
{
	struct udma_debugfs_seqfile *seqfile = inode->i_private;

	return single_open(f, seqfile->read, seqfile->data);
}

static const struct file_operations udma_debugfs_seqfile_fops = {
	.owner = THIS_MODULE,
	.open = udma_debugfs_seqfile_open,
	.release = single_release,
	.read = seq_read,
	.llseek = seq_lseek
};

static void init_debugfs_seqfile(struct udma_debugfs_seqfile *seq,
				 const char *name, struct dentry *parent,
				 int (*read_fn)(struct seq_file *, void *),
				 void *data)
{
	struct dentry *entry;

	entry = debugfs_create_file(name, FILE_PERMISSION, parent, seq,
				    &udma_debugfs_seqfile_fops);
	if (IS_ERR(entry))
		return;

	seq->read = read_fn;
	seq->data = data;
	seq->entry = entry;
}

static void cleanup_debugfs_seqfile(struct udma_debugfs_seqfile *seq)
{
	debugfs_remove(seq->entry);
	seq->entry = NULL;
}

static int stats_dca_pool_proc(struct dca_page_state *states, uint32_t count,
			       void *param)
{
	struct dca_mem_stats *stats = param;
	struct dca_page_state *s;
	int i, free_pages;

	free_pages = 0;
	for (i = 0; i < count; i++) {
		s = &states[i];
		if (s->buf_id == UDMA_DCA_INVALID_BUF_ID) {
			free_pages++;
			stats->free_size += UDMA_PAGE_SIZE;
		} else {
			if (s->lock)
				stats->locked_size += UDMA_PAGE_SIZE;

			if (s->active)
				stats->active_size += UDMA_PAGE_SIZE;
		}
	}

	stats->total_size += (count * UDMA_PAGE_SIZE);
	stats->total_mems++;
	if (free_pages == count)
		stats->clean_mems++;

	return 0;
}

static int stats_dca_qp_proc(struct dca_page_state *states, uint32_t count,
			     void *param)
{
	struct dca_stats_qp_attr *attr = param;
	struct dca_page_state *s;
	uint32_t qpn;
	int i;

	for (i = 0; i < count; i++) {
		s = &states[i];
		if (s->buf_id == UDMA_DCA_INVALID_BUF_ID || s->lock ||
		    !s->active)
			continue;

		qpn = UDMA_DCA_BUF_ID_TO_QPN(s->buf_id);
		if (qpn < attr->qpn_max)
			set_bit(qpn, attr->qpn_bitmap);
	}

	return 0;
}

static void dca_ctx_stats_qp(struct udma_dca_ctx *ctx,
			     uintptr_t *qpn_bitmap, uint32_t qpn_max)
{
	struct dca_stats_qp_attr attr;

	attr.qpn_bitmap = qpn_bitmap;
	attr.qpn_max = qpn_max;
	udma_enum_dca_pool(ctx, &attr, stats_dca_qp_proc);
}

static uint64_t calc_loading_percent(size_t total, size_t free,
				     uint32_t *out_rem)
{
	uint32_t all_pages, used_pages, free_pages, scale;
	uint64_t percent = 0;
	uint32_t rem = 0;

	all_pages = total >> UDMA_HW_PAGE_SHIFT;
	free_pages = free >> UDMA_HW_PAGE_SHIFT;
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

static void dca_setup_qp_stats(struct udma_qp *qp,
			       struct dca_qp_stats *stats)
{
	struct udma_ucontext *uctx = NULL;

	if (!(qp->en_flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH))
		return;

	if (qp->dca_ctx)
		uctx = container_of(qp->dca_ctx, struct udma_ucontext, dca_ctx);

	stats->qpn = (uint32_t)qp->qpn;
	stats->total_size = qp->buff_size;

	stats->sq_size = to_udma_hem_entries_size(qp->sq.wqe_cnt,
						  qp->sq.wqe_shift);
	stats->sge_size = to_udma_hem_entries_size(qp->sge.sge_cnt,
						   qp->sge.sge_shift);
	stats->rq_size = to_udma_hem_entries_size(qp->rq.wqe_cnt,
						  qp->rq.wqe_shift);
}

static void dca_stats_ctx_qp_in_seqfile(struct udma_dev *udma_dev,
					struct udma_dca_ctx *ctx,
					struct seq_file *file)
{
	struct dca_qp_stats stats;
	uint32_t qpn, nbits;
	struct udma_qp *qp;
	uintptr_t *bitmap;

	nbits = udma_dev->caps.num_qps;
	if (nbits < 1)
		return;

	bitmap = bitmap_zalloc(nbits, GFP_ATOMIC);
	if (!bitmap)
		return;

	seq_printf(file, "%-10s %-10s %-10s %-10s %-10s\n", "TPN", "Total(kB)",
		   "SQ(kB)", "SGE(kB)", "RQ(kB)");

	dca_ctx_stats_qp(ctx, bitmap, nbits);
	for_each_set_bit(qpn, bitmap, nbits) {
		stats.total_size = 0;
		xa_lock(&udma_dev->qp_table.xa);
		qp = get_qp(udma_dev, qpn);
		if (qp)
			dca_setup_qp_stats(qp, &stats);
		xa_unlock(&udma_dev->qp_table.xa);
		if (!stats.total_size)
			continue;

		seq_printf(file, "%-10u %-10u %-10u %-10u %-10u\n",
			   stats.qpn, stats.total_size / KB, stats.sq_size / KB,
			   stats.sge_size / KB, stats.rq_size / KB);
	}
	bitmap_free(bitmap);
}

static void dca_stats_ctx_mem_in_seqfile(struct udma_dca_ctx *ctx,
					 bool is_kdca, struct seq_file *file)
{
	struct dca_mem_stats stats = {};
	uint64_t percent;
	uint32_t rem = 0;

	udma_enum_dca_pool(ctx, &stats, stats_dca_pool_proc);
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
}

static int dca_debugfs_uctx_qp_stats_show(struct seq_file *file, void *offset)
{
	struct udma_ucontext *ucontext = file->private;
	struct udma_dev *udma_dev;

	udma_dev = container_of(ucontext->uctx.ub_dev, struct udma_dev, ub_dev);
	dca_stats_ctx_qp_in_seqfile(udma_dev, &ucontext->dca_ctx, file);

	return 0;
}

static int dca_debugfs_uctx_mem_stats_show(struct seq_file *file, void *offset)
{
	struct udma_ucontext *uctx = file->private;

	dca_stats_ctx_mem_in_seqfile(&uctx->dca_ctx, false, file);

	return 0;
}

static void init_dca_ctx_debugfs(struct udma_dca_ctx_debugfs *dbgfs,
				 struct dentry *parent,
				 struct udma_dev *udma_dev,
				 struct udma_ucontext *uctx)
{
	char name[DCA_CTX_PID_LEN];

	if (IS_ERR_OR_NULL(parent))
		return;

	snprintf(name, DCA_CTX_PID_LEN, "%u", current->pid);
	dbgfs->root = debugfs_create_dir(name, parent);
	if (IS_ERR_OR_NULL(dbgfs->root))
		return;

	init_debugfs_seqfile(&dbgfs->mem, "mstats", dbgfs->root,
			     dca_debugfs_uctx_mem_stats_show, uctx);
	init_debugfs_seqfile(&dbgfs->qp, "tp", dbgfs->root,
			     dca_debugfs_uctx_qp_stats_show, uctx);
}

static void cleanup_dca_ctx_debugfs(struct udma_dca_ctx_debugfs *ctx_dbgfs)
{
	cleanup_debugfs_seqfile(&ctx_dbgfs->qp);
	cleanup_debugfs_seqfile(&ctx_dbgfs->mem);
	debugfs_remove_recursive(ctx_dbgfs->root);
}

static struct udma_dca_debugfs *create_dca_debugfs(struct udma_dev *udma_dev,
						   struct dentry *parent)
{
	struct udma_dca_debugfs *dbgfs;

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

	return dbgfs;
}

static void destroy_dca_debugfs(struct udma_dca_debugfs *dca_dbgfs)
{
	debugfs_remove_recursive(dca_dbgfs->root);
	kfree(dca_dbgfs);
}

/* debugfs for ucontext */
void udma_register_uctx_debugfs(struct udma_dev *udma_dev,
				struct udma_ucontext *uctx)
{
	struct udma_dev_debugfs *dev_dbgfs = udma_dev->dbgfs;
	struct udma_dca_debugfs *dca_dbgfs;

	if (!dev_dbgfs)
		return;

	dca_dbgfs = dev_dbgfs->dca_root;
	if (dca_dbgfs) {
		uctx->dca_dbgfs = kzalloc(sizeof(struct udma_dca_ctx_debugfs),
					  GFP_KERNEL);
		if (!uctx->dca_dbgfs)
			return;

		init_dca_ctx_debugfs(uctx->dca_dbgfs, dca_dbgfs->root, udma_dev, uctx);
	}
}

void udma_unregister_uctx_debugfs(struct udma_ucontext *uctx)
{
	struct udma_dca_ctx_debugfs *dbgfs = uctx->dca_dbgfs;

	if (dbgfs) {
		uctx->dca_dbgfs = NULL;
		cleanup_dca_ctx_debugfs(dbgfs);
		kfree(dbgfs);
	}
}

/* debugfs for device */
void udma_register_debugfs(struct udma_dev *udma_dev)
{
	struct udma_dev_debugfs *dbgfs;

	if (IS_ERR_OR_NULL(udma_dbgfs_root))
		return;

	dbgfs = kzalloc(sizeof(*dbgfs), GFP_KERNEL);
	if (!dbgfs)
		return;

	dbgfs->root = debugfs_create_dir(dev_name(&udma_dev->ub_dev.dev),
					 udma_dbgfs_root);
	if (IS_ERR(dbgfs->root)) {
		kfree(dbgfs);
		return;
	}

	if (udma_dev->caps.flags & UDMA_CAP_FLAG_DCA_MODE)
		dbgfs->dca_root = create_dca_debugfs(udma_dev, dbgfs->root);

	udma_dev->dbgfs = dbgfs;
}

void udma_unregister_debugfs(struct udma_dev *udma_dev)
{
	struct udma_dev_debugfs *dbgfs;

	if (IS_ERR_OR_NULL(udma_dbgfs_root))
		return;

	dbgfs = udma_dev->dbgfs;
	if (!dbgfs)
		return;

	udma_dev->dbgfs = NULL;

	if (dbgfs->dca_root) {
		destroy_dca_debugfs(dbgfs->dca_root);
		dbgfs->dca_root = NULL;
	}

	debugfs_remove_recursive(dbgfs->root);
	kfree(dbgfs);
}

/* debugfs for udma module */
void udma_init_debugfs(void)
{
	udma_dbgfs_root = debugfs_create_dir("udma", NULL);
}

void udma_cleanup_debugfs(void)
{
	debugfs_remove_recursive(udma_dbgfs_root);
	udma_dbgfs_root = NULL;
}
