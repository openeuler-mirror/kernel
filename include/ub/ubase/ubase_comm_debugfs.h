/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef _UB_UBASE_COMM_DEBUGFS_H_
#define _UB_UBASE_COMM_DEBUGFS_H_

#include <linux/auxiliary_bus.h>

struct ubase_dbgfs;

/**
 * struct ubase_dbg_dentry_info - ubase debugfs dentry information
 * @name: dentry name
 * @dentry: the dentry for this file
 * @property: property supported by this dentry
 * @support: function to determine whether to create this dentry. dev: struct device,
 * property: the struct number variable 'property'.
 */
struct ubase_dbg_dentry_info {
	const char *name;
	struct dentry *dentry;
	u32 property;
	bool (*support)(struct device *dev, u32 property);
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ubase_dbg_cmd_info - ubase debugfs cmd information
 * @name: file name
 * @dentry_index: dentry index
 * @property: property supported by this file.
 * @support: function to determine whether to create this file. dev: struct device,
 * property: the struct number variable 'property.
 * @init: init debugfs cmd file function. dev: struct device, dirs: struct
 * ubase_dbg_dentry_info, dbgfs: struct ubase_dbgfs, idx: idxth file.
 * @read_func: reading debugfs detailed implementation function. s: struct seq_file,
 * data: data buffer
 */
struct ubase_dbg_cmd_info {
	const char *name;
	int dentry_index;
	u32 property;
	bool (*support)(struct device *dev, u32 property);
	int (*init)(struct device *dev, struct ubase_dbg_dentry_info *dirs,
		    struct ubase_dbgfs *dbgfs, u32 idx);
	int (*read_func)(struct seq_file *s, void *data);
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ubase_dbgfs - ubase debugfs data structure
 * @dentry: debugfs root path
 * @cmd_info: ubase debugfs cmd information
 * @cmd_info_size: the size of cmd_info
 */
struct ubase_dbgfs {
	struct dentry			*dentry;
	struct ubase_dbg_cmd_info	*cmd_info;
	int				cmd_info_size;
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

int ubase_dbg_seq_file_init(struct device *dev,
			    struct ubase_dbg_dentry_info *dirs,
			    struct ubase_dbgfs *dbgfs, u32 idx);
int ubase_dbg_create_dentry(struct device *dev, struct ubase_dbgfs *dbgfs,
			    struct ubase_dbg_dentry_info *dirs, u32 root_idx);
struct dentry *ubase_diag_debugfs_root(struct auxiliary_device *adev);
void ubase_print_context_hw(struct seq_file *s, void *ctx_addr, u32 ctx_len);
bool ubase_dbg_dentry_support(struct auxiliary_device *adev, u32 property);
int ubase_dbg_format_time(time64_t time, struct seq_file *s);

#endif /* _UB_UBASE_COMM_DEBUGFS_H_ */
