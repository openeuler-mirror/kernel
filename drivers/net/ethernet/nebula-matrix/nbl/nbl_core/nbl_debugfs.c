// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_debugfs.h"

#define SINGLE_FOPS_RO(_fops_, _open_)				\
	static const struct file_operations _fops_ = {		\
		.open = _open_,					\
		.read = seq_read,				\
		.llseek = seq_lseek,				\
		.release = seq_release,				\
	}

#define SINGLE_FOPS_WO(_fops_, _open_, _write_)		\
	static const struct file_operations _fops_ = {		\
		.open = _open_,					\
		.write = _write_,				\
		.llseek = seq_lseek,				\
		.release = seq_release,				\
	}

#define COMPLETE_FOPS_RW(_fops_, _open_, _write_)	\
	static const struct file_operations _fops_ = {		\
		.open = _open_,					\
		.write = _write_,				\
		.read = seq_read,				\
		.llseek = seq_lseek,				\
		.release = seq_release,				\
	}

static int nbl_flow_info_dump(struct seq_file *m, void *v)
{
	struct nbl_debugfs_mgt *debugfs_mgt = (struct nbl_debugfs_mgt *)m->private;
	struct nbl_dispatch_ops *disp_ops = NBL_DEBUGFS_MGT_TO_DISP_OPS(debugfs_mgt);

	disp_ops->dump_flow(NBL_DEBUGFS_MGT_TO_DISP_PRIV(debugfs_mgt), m);

	return 0;
}

static int nbl_mbx_txq_dma_dump(struct seq_file *m, void *v)
{
	struct nbl_debugfs_mgt *debugfs_mgt = (struct nbl_debugfs_mgt *)m->private;
	struct nbl_channel_ops *chan_ops = NBL_DEBUGFS_MGT_TO_CHAN_OPS(debugfs_mgt);

	chan_ops->dump_txq(NBL_DEBUGFS_MGT_TO_CHAN_PRIV(debugfs_mgt), m, NBL_CHAN_TYPE_MAILBOX);

	return 0;
}

static int nbl_mbx_rxq_dma_dump(struct seq_file *m, void *v)
{
	struct nbl_debugfs_mgt *debugfs_mgt = (struct nbl_debugfs_mgt *)m->private;
	struct nbl_channel_ops *chan_ops = NBL_DEBUGFS_MGT_TO_CHAN_OPS(debugfs_mgt);

	chan_ops->dump_rxq(NBL_DEBUGFS_MGT_TO_CHAN_PRIV(debugfs_mgt), m, NBL_CHAN_TYPE_MAILBOX);

	return 0;
}

static int nbl_adminq_txq_dma_dump(struct seq_file *m, void *v)
{
	struct nbl_debugfs_mgt *debugfs_mgt = (struct nbl_debugfs_mgt *)m->private;
	struct nbl_channel_ops *chan_ops = NBL_DEBUGFS_MGT_TO_CHAN_OPS(debugfs_mgt);

	chan_ops->dump_txq(NBL_DEBUGFS_MGT_TO_CHAN_PRIV(debugfs_mgt), m, NBL_CHAN_TYPE_ADMINQ);

	return 0;
}

static int nbl_adminq_rxq_dma_dump(struct seq_file *m, void *v)
{
	struct nbl_debugfs_mgt *debugfs_mgt = (struct nbl_debugfs_mgt *)m->private;
	struct nbl_channel_ops *chan_ops = NBL_DEBUGFS_MGT_TO_CHAN_OPS(debugfs_mgt);

	chan_ops->dump_rxq(NBL_DEBUGFS_MGT_TO_CHAN_PRIV(debugfs_mgt), m, NBL_CHAN_TYPE_ADMINQ);

	return 0;
}

static int nbl_debugfs_flow_info_dump(struct inode *inode, struct file *file)
{
	return single_open(file, nbl_flow_info_dump, inode->i_private);
}

static int nbl_debugfs_mbx_txq_dma_dump(struct inode *inode, struct file *file)
{
	return single_open(file, nbl_mbx_txq_dma_dump, inode->i_private);
}

static int nbl_debugfs_mbx_rxq_dma_dump(struct inode *inode, struct file *file)
{
	return single_open(file, nbl_mbx_rxq_dma_dump, inode->i_private);
}

static int nbl_debugfs_adminq_txq_dma_dump(struct inode *inode, struct file *file)
{
	return single_open(file, nbl_adminq_txq_dma_dump, inode->i_private);
}

static int nbl_debugfs_adminq_rxq_dma_dump(struct inode *inode, struct file *file)
{
	return single_open(file, nbl_adminq_rxq_dma_dump, inode->i_private);
}

SINGLE_FOPS_RO(flow_info_fops, nbl_debugfs_flow_info_dump);
SINGLE_FOPS_RO(mbx_txq_fops, nbl_debugfs_mbx_txq_dma_dump);
SINGLE_FOPS_RO(mbx_rxq_fops, nbl_debugfs_mbx_rxq_dma_dump);
SINGLE_FOPS_RO(adminq_txq_fops, nbl_debugfs_adminq_txq_dma_dump);
SINGLE_FOPS_RO(adminq_rxq_fops, nbl_debugfs_adminq_rxq_dma_dump);

static int nbl_ring_index_dump(struct seq_file *m, void *v)
{
	struct nbl_debugfs_mgt *debugfs_mgt = (struct nbl_debugfs_mgt *)m->private;

	seq_printf(m, "Index = %d", debugfs_mgt->ring_index);

	return 0;
}

static int nbl_ring_index_open(struct inode *inode, struct file *file)
{
	return single_open(file, nbl_ring_index_dump, inode->i_private);
}

static ssize_t nbl_ring_index_write(struct file *file, const char __user *buf,
				    size_t count, loff_t *offp)
{
	struct nbl_debugfs_mgt *debugfs_mgt = file_inode(file)->i_private;
	char buffer[4] = {0};
	size_t size = min(count, sizeof(buffer));

	if (copy_from_user(buffer, buf, size))
		return -EFAULT;
	if (kstrtou16(buffer, 10, &debugfs_mgt->ring_index))
		return -EFAULT;

	return size;
}

SINGLE_FOPS_WO(ring_index_fops, nbl_ring_index_open, nbl_ring_index_write);

static int nbl_ring_dump(struct seq_file *m, void *v)
{
	struct nbl_debugfs_mgt *debugfs_mgt = (struct nbl_debugfs_mgt *)m->private;
	struct nbl_dispatch_ops *disp_ops = NBL_DEBUGFS_MGT_TO_DISP_OPS(debugfs_mgt);
	bool is_tx = debugfs_mgt->ring_index % 2;
	u16 ring_index = debugfs_mgt->ring_index / 2;

	seq_printf(m, "Dump %s_ring_%d :\n", is_tx ? "tx" : "rx", ring_index);
	disp_ops->dump_ring(NBL_DEBUGFS_MGT_TO_DISP_PRIV(debugfs_mgt), m, is_tx, ring_index);

	return 0;
}

static int nbl_debugfs_ring_dump(struct inode *inode, struct file *file)
{
	return single_open(file, nbl_ring_dump, inode->i_private);
}

SINGLE_FOPS_RO(ring_fops, nbl_debugfs_ring_dump);

static void nbl_serv_debugfs_setup_netops(struct nbl_debugfs_mgt *debugfs_mgt)
{
	debugfs_create_file("txrx_ring_index", 0644, debugfs_mgt->nbl_debugfs_root,
			    debugfs_mgt, &ring_index_fops);
	debugfs_create_file("txrx_ring", 0444, debugfs_mgt->nbl_debugfs_root,
			    debugfs_mgt, &ring_fops);
}

static int nbl_ring_stats_dump(struct seq_file *m, void *v)
{
	struct nbl_debugfs_mgt *debugfs_mgt = (struct nbl_debugfs_mgt *)m->private;
	struct nbl_dispatch_ops *disp_ops = NBL_DEBUGFS_MGT_TO_DISP_OPS(debugfs_mgt);
	struct nbl_queue_err_stats queue_err_stats = {0};
	bool is_tx = debugfs_mgt->ring_index % 2;
	u16 ring_index = debugfs_mgt->ring_index / 2;
	int ret;

	seq_printf(m, "Dump %s_ring_%d_stats\n", is_tx ? "tx" : "rx", ring_index);
	disp_ops->dump_ring_stats(NBL_DEBUGFS_MGT_TO_DISP_PRIV(debugfs_mgt), m, is_tx, ring_index);
	if (is_tx) {
		ret = disp_ops->get_queue_err_stats(NBL_DEBUGFS_MGT_TO_DISP_PRIV(debugfs_mgt),
						    ring_index,
						    &queue_err_stats, true);
		if (!ret)
			seq_printf(m, "dvn_pkt_drop_cnt: %d\n", queue_err_stats.dvn_pkt_drop_cnt);
	} else {
		ret = disp_ops->get_queue_err_stats(NBL_DEBUGFS_MGT_TO_DISP_PRIV(debugfs_mgt),
						    ring_index,
						    &queue_err_stats, false);
		if (!ret)
			seq_printf(m, "uvn_pkt_drop_cnt: %d\n", queue_err_stats.uvn_stat_pkt_drop);
	}

	return 0;
}

static int nbl_debugfs_ring_stats_dump(struct inode *inode, struct file *file)
{
	return single_open(file, nbl_ring_stats_dump, inode->i_private);
}

SINGLE_FOPS_RO(ring_stats_fops, nbl_debugfs_ring_stats_dump);

static void nbl_serv_debugfs_setup_pfops(struct nbl_debugfs_mgt *debugfs_mgt)
{
	debugfs_create_file("txrx_ring_stats", 0444, debugfs_mgt->nbl_debugfs_root,
			    debugfs_mgt, &ring_stats_fops);
}

static void nbl_serv_debugfs_setup_ctrlops(struct nbl_debugfs_mgt *debugfs_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DEBUGFS_MGT_TO_CHAN_OPS(debugfs_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_DEBUGFS_MGT_TO_DISP_OPS(debugfs_mgt);

	if (chan_ops->check_queue_exist(NBL_DEBUGFS_MGT_TO_CHAN_PRIV(debugfs_mgt),
					NBL_CHAN_TYPE_ADMINQ)) {
		debugfs_create_file("adminq_txq", 0444, debugfs_mgt->nbl_debugfs_root,
				    debugfs_mgt, &adminq_txq_fops);
		debugfs_create_file("adminq_rxq", 0444, debugfs_mgt->nbl_debugfs_root,
				    debugfs_mgt, &adminq_rxq_fops);
	}

	if (disp_ops->get_product_fix_cap(NBL_DEBUGFS_MGT_TO_DISP_PRIV(debugfs_mgt),
					  NBL_DUMP_FLOW_CAP))
		debugfs_create_file("flow_info", 0444, debugfs_mgt->nbl_debugfs_root,
				    debugfs_mgt, &flow_info_fops);
}

static void nbl_serv_debugfs_setup_commonops(struct nbl_debugfs_mgt *debugfs_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DEBUGFS_MGT_TO_CHAN_OPS(debugfs_mgt);

	if (!chan_ops->check_queue_exist(NBL_DEBUGFS_MGT_TO_CHAN_PRIV(debugfs_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	debugfs_create_file("mbx_txq", 0444, debugfs_mgt->nbl_debugfs_root,
			    debugfs_mgt, &mbx_txq_fops);
	debugfs_create_file("mbx_rxq", 0444, debugfs_mgt->nbl_debugfs_root,
			    debugfs_mgt, &mbx_rxq_fops);
}

void nbl_debugfs_func_init(void *p, struct nbl_init_param *param)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_debugfs_mgt **debugfs_mgt =
		(struct nbl_debugfs_mgt **)&NBL_ADAPTER_TO_DEBUGFS_MGT(adapter);
	struct nbl_common_info *common;
	struct device *dev;
	const char *name;

	common = NBL_ADAPTER_TO_COMMON(adapter);
	dev = NBL_ADAPTER_TO_DEV(adapter);

	*debugfs_mgt = devm_kzalloc(dev, sizeof(struct nbl_debugfs_mgt), GFP_KERNEL);
	if (!*debugfs_mgt)
		return;

	NBL_DEBUGFS_MGT_TO_DISP_OPS_TBL(*debugfs_mgt) = NBL_ADAPTER_TO_DISP_OPS_TBL(adapter);
	NBL_DEBUGFS_MGT_TO_CHAN_OPS_TBL(*debugfs_mgt) = NBL_ADAPTER_TO_CHAN_OPS_TBL(adapter);
	NBL_DEBUGFS_MGT_TO_COMMON(*debugfs_mgt) = common;

	name = pci_name(NBL_COMMON_TO_PDEV(common));
	(*debugfs_mgt)->nbl_debugfs_root = debugfs_create_dir(name, nbl_get_debugfs_root());
	if (!(*debugfs_mgt)->nbl_debugfs_root) {
		nbl_err(common, NBL_DEBUG_DEBUGFS, "nbl init debugfs failed\n");
		return;
	}

	nbl_serv_debugfs_setup_commonops(*debugfs_mgt);

	if (param->caps.has_ctrl)
		nbl_serv_debugfs_setup_ctrlops(*debugfs_mgt);

	if (param->caps.has_net) {
		nbl_serv_debugfs_setup_netops(*debugfs_mgt);
		if (!param->caps.is_vf)
			nbl_serv_debugfs_setup_pfops(*debugfs_mgt);
	}
}

void nbl_debugfs_func_remove(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_debugfs_mgt **debugfs_mgt =
		(struct nbl_debugfs_mgt **)&NBL_ADAPTER_TO_DEBUGFS_MGT(adapter);
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);

	debugfs_remove_recursive((*debugfs_mgt)->nbl_debugfs_root);
	(*debugfs_mgt)->nbl_debugfs_root = NULL;

	devm_kfree(dev, *debugfs_mgt);
}
