/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef __UDMA_DEBUGFS_H
#define __UDMA_DEBUGFS_H

#define KB 1024
#define KB_SHIFT 10
#define DCA_CTX_PID_LEN 10
#define DCA_CTX_STATE_LEN 22

#define LOADING_PERCENT_SCALE 100
#define LOADING_PERCENT_SHIFT 2

#define UDMA_DCA_BUF_ID_TO_QPN(buf_id) ((buf_id) & UDMA_DCA_OWN_MASK)

#define DCA_STAT_NAME_FMT "%-22s "
#define dca_ctx_print_mem_size(f, n, fmt, v) \
	seq_printf(f, DCA_STAT_NAME_FMT fmt "\n", n, v)
#define dca_ctx_print_mem_kb(f, n, v) \
	dca_ctx_print_mem_size(f, n, "%-u kB", (uint32_t)((v) / KB))

#define FILE_PERMISSION 0400
/* stats QPs in DCA pool */
struct dca_stats_qp_attr {
	uintptr_t	*qpn_bitmap;
	uint32_t	qpn_max;
};

/* debugfs seqfile */
struct udma_debugfs_seqfile {
	struct dentry	*entry;
	int		(*read)(struct seq_file *seq, void *data);
	void		*data;
};

/* DCA debugfs */
struct udma_dca_ctx_debugfs {
	struct dentry			*root; /* pool debugfs entry */
	struct udma_debugfs_seqfile	mem; /* mems in pool */
	struct udma_debugfs_seqfile	qp; /* QPs stats in pool */
};

struct udma_dca_debugfs {
	struct dentry *root; /* dev debugfs entry */
};

/* Debugfs for device */
struct udma_dev_debugfs {
	struct dentry		*root;
	struct udma_dca_debugfs	*dca_root;
};

struct dca_mem_stats {
	uint32_t	total_mems;
	uint32_t	clean_mems;
	size_t		free_size;
	size_t		total_size;
	size_t		active_size;
	size_t		locked_size;
};

struct dca_qp_stats {
	uint32_t qpn;
	uint32_t total_size;
	uint32_t sq_size;
	uint32_t rq_size;
	uint32_t sge_size;
};

void udma_init_debugfs(void);
void udma_cleanup_debugfs(void);
void udma_register_debugfs(struct udma_dev *udma_dev);
void udma_unregister_debugfs(struct udma_dev *udma_dev);
void udma_unregister_uctx_debugfs(struct udma_ucontext *uctx);
void udma_register_uctx_debugfs(struct udma_dev *udma_dev,
				struct udma_ucontext *uctx);
#endif
