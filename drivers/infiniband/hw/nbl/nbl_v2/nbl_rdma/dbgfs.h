/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */
#include <linux/string.h>

#ifndef NBL_IB_DBGFS_H
#define NBL_IB_DBGFS_H

#define NBL_DUMP_BUF_SIZE 1048576

#define NBL_RDMA_DENTRY_LEN 256

bool nbl_dentry_is_exist(char *dentry);
int nbl_ib_get_debugfs_absolute_path(struct nbl_device *dev,
				     struct dentry *dentry_path,
				     char *absolute_path);
int nbl_ib_copy_dentry(char *src_dir, char *dst_dir);
int nbl_debugfs_function_pre_init(struct nbl_device *nbl_dev);
void nbl_debugfs_function_init(struct nbl_device *nbl_dev);
void nbl_debugfs_function_pre_exit(struct nbl_device *nbl_dev);
void nbl_debugfs_function_exit(struct nbl_device *nbl_dev);

/* CC debugfs */
void nbl_dbgfs_cc_init(struct nbl_device *dev);
void nbl_dbgfs_cc_deinit(struct nbl_device *dev);
void add_statid_of_qp_cmd(struct nbl_device *nbl_dev, u32 qp_id);

void nbl_dbgfs_func_init(struct nbl_device *dev);
void nbl_dbgfs_func_deinit(struct nbl_device *dev);

void nbl_dbgfs_qos_init(struct nbl_device *dev);
void nbl_dbgfs_qos_deinit(struct nbl_device *dev);

void nbl_dbgfs_cache_hit_init(struct nbl_device *dev);
void nbl_dbgfs_cache_hit_deinit(struct nbl_device *dev);

int nbl_handle_fun_dbg_set(struct nbl_device *nbl_dev, int offset, u32 var);
void nbl_init_qpn_info_record(struct nbl_device *nbl_dev);
void nbl_print_grc_src_addr_tbl(struct nbl_pci_f *rf, u32 var);

/* Classify and select packet statistics idx and parse output */
#define CHECK_STAT_NAME_IS_PACKET_V4(i) \
	((((i) >= 192 && (i) <= 225) || \
	((i) >= 128 && (i) <= 177) || \
	((i) >= 0 && (i) <= 54)) || \
	((i) >= 62 && (i) <= 97) || \
	((i) == 57))
#define CHECK_STAT_NAME_IS_PACKET_V2(i) \
	(((i) >= 0 && (i) <= 57) || \
	((i) >= 62 && (i) <= 113))
#define CHECK_NORMAL_ERRCODE_STAT(i) \
	((i) == 0x4a || \
	(i) == 0x4b || \
	(i) == 0x5d || \
	(i) == 0x5e)
#endif /* NBL_IB_DBGFS_H */
