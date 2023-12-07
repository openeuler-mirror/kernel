/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2016-2017 Hisilicon Limited.

#ifndef __HNS_ROCE_DEBUGFS_H
#define __HNS_ROCE_DEBUGFS_H

/* debugfs seqfile */
struct hns_debugfs_seqfile {
	int (*read)(struct seq_file *seq, void *data);
	void *data;
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

struct hns_poe_ch_debugfs {
	struct dentry *root; /* dev debugfs entry */
	struct hns_debugfs_seqfile en; /* enable stats fir this ch */
	struct hns_debugfs_seqfile addr; /* addr of this ch */
	struct hns_debugfs_seqfile ref_cnt; /* ref_cnt for this ch */
};

struct hns_poe_debugfs {
	struct dentry *root; /* dev debugfs entry */
	struct hns_poe_ch_debugfs *poe_ch;
};

struct hns_sw_stat_debugfs {
	struct dentry *root;
	struct hns_debugfs_seqfile sw_stat;
};

struct hns_srq_debugfs {
	struct dentry *root;
	struct hns_debugfs_seqfile srqc;
	struct hns_debugfs_seqfile srqn;
	atomic_t atomic_srqn;
};

/* Debugfs for device */
struct hns_roce_dev_debugfs {
	struct dentry *root;
	struct hns_dca_debugfs dca_root;
	struct hns_poe_debugfs poe_root;
	struct hns_sw_stat_debugfs sw_stat_root;
	struct hns_srq_debugfs srq_root;
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
