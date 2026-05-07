/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_DBGFS_H
#define NBL_IB_DBGFS_H

#define NBL_QPN_STR_LEN_MAX 10
#define NBL_DUMP_BUF_SIZE 1048576

#define NBL_RDMA_DENTRY_LEN 256

bool nbl_dentry_is_exist(char *dentry);
int nbl_ib_get_debugfs_absolute_path(struct nbl_device *dev,
				     struct dentry *dentry_path,
				     char *absolute_path);
int nbl_ib_copy_dentry(char *src_dir, char *dst_dir);

void nbl_debugfs_function_init(struct nbl_device *nbl_dev);
void nbl_debugfs_function_exit(struct nbl_device *nbl_dev);
void nbl_debugfs_init(void);
void nbl_debugfs_exit(void);

/* CC debugfs */
void nbl_debugfs_cc_init(struct nbl_device *dev);
void nbl_debugfs_cc_deinit(struct nbl_device *dev);
void add_statid_of_qp_cmd(struct nbl_device *nbl_dev, u32 qp_id);

void nbl_debug_function_init(struct nbl_device *dev);
void nbl_debug_function_deinit(struct nbl_device *dev);

void nbl_debugfs_qos_dev_init(struct nbl_device *dev);
void nbl_debugfs_qos_dev_deinit(struct nbl_device *dev);

#define CHECK_STAT_NAME_IS_PACKET(i) \
	(((i) >= 64 && (i) <= 89) || \
	((i) == 35) || ((i) == 99) || \
	((i) >= 0 && (i) <= 25))

#define CHECK_NORMAL_ERRCODE_STAT(i) \
	((i) == 0x4a || \
	(i) == 0x4b || \
	(i) == 0x5d || \
	(i) == 0x5e)
#endif /* NBL_IB_DBGFS_H */
