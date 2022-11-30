/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2023 Hisilicon Limited.
 */

#ifndef __HNS_ROCE_DEBUGFS_H
#define __HNS_ROCE_DEBUGFS_H

/* debugfs seqfile */
struct hns_debugfs_seqfile {
	int (*read)(struct seq_file *seq, void *data);
	void *data;
};

struct hns_sw_stat_debugfs {
	struct dentry *root;
	struct hns_debugfs_seqfile sw_stat;
};

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
	struct hns_sw_stat_debugfs sw_stat_root;
	struct hns_dca_debugfs dca_root;
};

struct hns_roce_dev;
struct hns_roce_ucontext;

void hns_roce_init_debugfs(void);
void hns_roce_cleanup_debugfs(void);
void hns_roce_register_debugfs(struct hns_roce_dev *hr_dev);
void hns_roce_unregister_debugfs(struct hns_roce_dev *hr_dev);
void hns_roce_register_uctx_debugfs(struct hns_roce_dev *hr_dev,
				    struct hns_roce_ucontext *uctx);
void hns_roce_unregister_uctx_debugfs(struct hns_roce_ucontext *uctx);

#endif
