// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/debugfs.h>
#include "common/xsc_core.h"
#include "common/xsc_lag.h"
#include "../net/xsc_eth.h"

#define XSC_DEFINE_SHOW_ATTRIBUTE(__name)					\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __name ## _show, inode->i_private);	\
}

#define XSC_DEFINE_DEBUGFS_FOPS(__name) \
static const struct file_operations __name ## _fops = {   \
	.owner = THIS_MODULE,                                 \
	.open = __name ## _open,                              \
	.read = seq_read,                                     \
	.llseek = seq_lseek,                                  \
	.release = single_release,                            \
}

static char *get_str_mode_type(struct xsc_lag *lag)
{
	switch (lag->lag_type) {
	case XSC_LAG_FLAG_ROCE:
		return "roce";
	case XSC_LAG_FLAG_SRIOV:
		return "switchdev";
	case XSC_LAG_FLAG_KERNEL:
		return "kernel";
	case (XSC_LAG_FLAG_MPESW | XSC_LAG_FLAG_SRIOV):
		return "mp_eswitch";
	default:
		return "invalid";
	}
}

static int type_show(struct seq_file *file, void *priv)
{
	struct xsc_core_device *dev = file->private;
	struct xsc_lag *lag;
	char *mode = NULL;

	if (xsc_lag_is_active(dev)) {
		xsc_board_lag_lock(dev);
		lag = xsc_get_lag(dev);
		mode = get_str_mode_type(lag);
		xsc_board_lag_unlock(dev);
	}

	seq_printf(file, "%s\n", mode);

	return 0;
}

static int port_sel_mode_show(struct seq_file *file, void *priv)
{
	struct xsc_core_device *dev = file->private;
	int ret = -EINVAL;
	char *mode;

	if (xsc_lag_is_active(dev))
		mode = "hash";
	else
		return ret;

	seq_printf(file, "%s\n", mode);

	return 0;
}

static int state_show(struct seq_file *file, void *priv)
{
	struct xsc_core_device *dev = file->private;
	bool active;

	active = xsc_lag_is_active(dev);
	seq_printf(file, "%s\n", active ? "active" : "disabled");

	return 0;
}

static int flags_show(struct seq_file *file, void *priv)
{
	struct xsc_core_device *dev = file->private;
	bool fdb_sel_mode_native;
	struct xsc_lag *lag;
	bool shared_fdb;
	bool lag_active;

	lag_active = xsc_lag_is_active(dev);
	if (!lag_active)
		return -EINVAL;

	xsc_board_lag_lock(dev);
	lag = xsc_get_lag(dev);
	shared_fdb = lag->lag_type == XSC_LAG_FLAG_MPESW;
	fdb_sel_mode_native = false;
	xsc_board_lag_unlock(dev);

	seq_printf(file, "%s:%s\n", "shared_fdb", shared_fdb ? "on" : "off");
	seq_printf(file, "%s:%s\n", "fdb_selection_mode",
		   fdb_sel_mode_native ? "native" : "affinity");

	return 0;
}

static int mapping_show(struct seq_file *file, void *priv)
{
	struct xsc_core_device *dev = file->private, *xdev_tmp;
	struct xsc_lag *lag;
	bool lag_active;
	int i = 0, err = 0;

	lag_active = xsc_lag_is_active(dev);
	if (!lag_active)
		return -EINVAL;

	xsc_board_lag_lock(dev);
	lag = xsc_get_lag(dev);
	list_for_each_entry(xdev_tmp, &lag->slave_list, slave_node)
		seq_printf(file, "%d:%s\n", i++, dev_name(xdev_tmp->device));
	xsc_board_lag_unlock(dev);

	return err;
}

static int members_show(struct seq_file *file, void *priv)
{
	struct xsc_core_device *dev = file->private, *xdev_tmp;
	struct xsc_adapter *adapter;
	int i;
	struct xsc_board_lag *board_lag = xsc_board_lag_get(dev);

	if (!board_lag)
		return -EINVAL;

	xsc_board_lag_lock(dev);
	for (i = 0; i < XSC_BOARD_NETDEV_MAX; i++)  {
		if (board_lag->netdev[i]) {
			adapter = netdev_priv(board_lag->netdev[i]);
			xdev_tmp = adapter->xdev;
			seq_printf(file, "%s\n", dev_name(xdev_tmp->device));
		}
	}
	xsc_board_lag_unlock(dev);

	return 0;
}

XSC_DEFINE_SHOW_ATTRIBUTE(type);
XSC_DEFINE_SHOW_ATTRIBUTE(port_sel_mode);
XSC_DEFINE_SHOW_ATTRIBUTE(state);
XSC_DEFINE_SHOW_ATTRIBUTE(flags);
XSC_DEFINE_SHOW_ATTRIBUTE(mapping);
XSC_DEFINE_SHOW_ATTRIBUTE(members);

XSC_DEFINE_DEBUGFS_FOPS(type);
XSC_DEFINE_DEBUGFS_FOPS(port_sel_mode);
XSC_DEFINE_DEBUGFS_FOPS(state);
XSC_DEFINE_DEBUGFS_FOPS(flags);
XSC_DEFINE_DEBUGFS_FOPS(mapping);
XSC_DEFINE_DEBUGFS_FOPS(members);

void xsc_ldev_add_debugfs(struct xsc_core_device *dev)
{
	struct dentry *dbg;

	if (!xsc_debugfs_root)
		return;

	dbg = debugfs_create_dir("lag", dev->dev_res->dbg_root);
	dev->dev_res->lag_debugfs = dbg;

	debugfs_create_file("type", 0444, dbg, dev, &type_fops);
	debugfs_create_file("port_sel_mode", 0444, dbg, dev, &port_sel_mode_fops);
	debugfs_create_file("state", 0444, dbg, dev, &state_fops);
	debugfs_create_file("flags", 0444, dbg, dev, &flags_fops);
	debugfs_create_file("mapping", 0444, dbg, dev, &mapping_fops);
	debugfs_create_file("members", 0444, dbg, dev, &members_fops);
}

void xsc_ldev_remove_debugfs(struct xsc_core_device *dev)
{
	if (!xsc_debugfs_root)
		return;

	debugfs_remove_recursive(dev->dev_res->lag_debugfs);
}

