// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_dev.h"

static int debug = -1;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "netif debug level (0=none,...,16=all), adapter debug_mask (<-1)");

static struct nbl_dev_board_id_table board_id_table;

struct nbl_dev_ops dev_ops;

static const struct net_device_ops netdev_ops_leonis_pf;
static const struct ethtool_ops ethtool_ops_leonis_pf;

static int nbl_dev_clean_mailbox_schedule(struct nbl_dev_mgt *dev_mgt);
static void nbl_dev_clean_adminq_schedule(struct nbl_task_info *task_info);

/* ----------  Basic functions  ---------- */
static int nbl_dev_get_port_attributes(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_port_attributes(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}

static int nbl_dev_enable_port(struct nbl_dev_mgt *dev_mgt, bool enable)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->enable_port(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), enable);
}

static int nbl_dev_alloc_board_id(struct nbl_dev_board_id_table *index_table, u16 bus)
{
	int i = 0;

	for (i = 0; i < NBL_DEV_BOARD_ID_MAX; i++) {
		if (index_table->entry[i].bus == bus) {
			index_table->entry[i].refcount++;
			return i;
		}
	}

	for (i = 0; i < NBL_DEV_BOARD_ID_MAX; i++) {
		if (!index_table->entry[i].valid) {
			index_table->entry[i].bus = bus;
			index_table->entry[i].refcount++;
			index_table->entry[i].valid = true;
			return i;
		}
	}

	return -ENOSPC;
}

static void nbl_dev_free_board_id(struct nbl_dev_board_id_table *index_table, u16 bus)
{
	int i = 0;

	for (i = 0; i < NBL_DEV_BOARD_ID_MAX; i++) {
		if (index_table->entry[i].bus == bus && index_table->entry[i].valid) {
			index_table->entry[i].refcount--;
			break;
		}
	}

	if (i != NBL_DEV_BOARD_ID_MAX && !index_table->entry[i].refcount)
		memset(&index_table->entry[i], 0, sizeof(index_table->entry[i]));
}

static void nbl_dev_set_netdev_priv(struct net_device *netdev, struct nbl_dev_vsi *vsi)
{
	struct nbl_netdev_priv *net_priv = netdev_priv(netdev);

	net_priv->tx_queue_num = vsi->queue_num;
	net_priv->rx_queue_num = vsi->queue_num;
	net_priv->queue_size = vsi->queue_size;
	net_priv->netdev = netdev;
	net_priv->default_vsi_index = vsi->index;
	net_priv->default_vsi_id = vsi->vsi_id;
}

/* ----------  Interrupt config  ---------- */
static irqreturn_t nbl_dev_clean_mailbox(int __always_unused irq, void *data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)data;

	nbl_dev_clean_mailbox_schedule(dev_mgt);

	return IRQ_HANDLED;
}

static irqreturn_t nbl_dev_clean_adminq(int __always_unused irq, void *data)
{
	struct nbl_task_info *task_info = (struct nbl_task_info *)data;

	nbl_dev_clean_adminq_schedule(task_info);

	return IRQ_HANDLED;
}

static void nbl_dev_handle_abnormal_event(struct work_struct *work)
{
	struct nbl_task_info *task_info = container_of(work, struct nbl_task_info,
						       clean_abnormal_irq_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->process_abnormal_event(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}

static void nbl_dev_clean_abnormal_status(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_task_info *task_info = NBL_DEV_CTRL_TO_TASK_INFO(ctrl_dev);

	nbl_common_queue_work(&task_info->clean_abnormal_irq_task, true, false);
}

static irqreturn_t nbl_dev_clean_abnormal_event(int __always_unused irq, void *data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)data;

	nbl_dev_clean_abnormal_status(dev_mgt);

	return IRQ_HANDLED;
}

static void nbl_dev_register_common_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_irq_num irq_num = {0};

	serv_ops->get_common_irq_num(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &irq_num);
	msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num = irq_num.mbx_irq_num;
}

static void nbl_dev_register_net_irq(struct nbl_dev_mgt *dev_mgt, u16 queue_num)
{
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);

	msix_info->serv_info[NBL_MSIX_NET_TYPE].num = queue_num;
	msix_info->serv_info[NBL_MSIX_NET_TYPE].hw_self_mask_en = 1;
}

static void nbl_dev_register_ctrl_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_ctrl_irq_num irq_num = {0};

	serv_ops->get_ctrl_irq_num(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &irq_num);

	msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].num = irq_num.abnormal_irq_num;
	msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].num = irq_num.adminq_irq_num;
}

static int nbl_dev_request_net_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	struct nbl_msix_info_param param = {0};
	int msix_num = msix_info->serv_info[NBL_MSIX_NET_TYPE].num;
	int ret = 0;

	param.msix_entries = kcalloc(msix_num, sizeof(*param.msix_entries), GFP_KERNEL);
	if (!param.msix_entries)
		return -ENOMEM;

	param.msix_num = msix_num;
	memcpy(param.msix_entries, msix_info->msix_entries +
		msix_info->serv_info[NBL_MSIX_NET_TYPE].base_vector_id,
		sizeof(param.msix_entries[0]) * msix_num);

	ret = serv_ops->request_net_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &param);

	kfree(param.msix_entries);
	return ret;
}

static void nbl_dev_free_net_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	struct nbl_msix_info_param param = {0};
	int msix_num = msix_info->serv_info[NBL_MSIX_NET_TYPE].num;

	param.msix_entries = kcalloc(msix_num, sizeof(*param.msix_entries), GFP_KERNEL);
	if (!param.msix_entries)
		return;

	param.msix_num = msix_num;
	memcpy(param.msix_entries, msix_info->msix_entries +
		msix_info->serv_info[NBL_MSIX_NET_TYPE].base_vector_id,
	       sizeof(param.msix_entries[0]) * msix_num);

	serv_ops->free_net_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &param);

	kfree(param.msix_entries);
}

static int nbl_dev_request_mailbox_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;
	u32 irq_num;
	int err;

	if (!msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].base_vector_id;
	irq_num = msix_info->msix_entries[local_vector_id].vector;

	snprintf(dev_common->mailbox_name, sizeof(dev_common->mailbox_name) - 1, "%s-%s",
		 dev_name(dev), "mailbox");
	err = devm_request_irq(dev, irq_num, nbl_dev_clean_mailbox,
			       0, dev_common->mailbox_name, dev_mgt);
	if (err) {
		dev_err(dev, "Request mailbox irq handler failed err: %d\n", err);
		return err;
	}

	return 0;
}

static void nbl_dev_free_mailbox_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;
	u32 irq_num;

	if (!msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num)
		return;

	local_vector_id = msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].base_vector_id;
	irq_num = msix_info->msix_entries[local_vector_id].vector;

	devm_free_irq(dev, irq_num, dev_mgt);
}

static int nbl_dev_enable_mailbox_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;

	if (!msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].base_vector_id;
	chan_ops->set_queue_interrupt_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
					    NBL_CHAN_TYPE_MAILBOX, true);

	return serv_ops->enable_mailbox_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    local_vector_id, true);
}

static int nbl_dev_disable_mailbox_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;

	if (!msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num)
		return 0;

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_CLEAN_MAILBOX_CAP))
		nbl_common_flush_task(&dev_common->clean_mbx_task);

	local_vector_id = msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].base_vector_id;
	chan_ops->set_queue_interrupt_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
					    NBL_CHAN_TYPE_MAILBOX, false);

	return serv_ops->enable_mailbox_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    local_vector_id, false);
}

static int nbl_dev_request_adminq_irq(struct nbl_dev_mgt *dev_mgt, struct nbl_task_info *task_info)
{
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;
	u32 irq_num;
	int err;

	if (!msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].base_vector_id;
	irq_num = msix_info->msix_entries[local_vector_id].vector;

	err = devm_request_irq(dev, irq_num, nbl_dev_clean_adminq,
			       0, "adminq_irq", task_info);
	if (err) {
		dev_err(dev, "Request adminq irq handler failed err: %d\n", err);
		return err;
	}

	return 0;
}

static void nbl_dev_free_adminq_irq(struct nbl_dev_mgt *dev_mgt, struct nbl_task_info *task_info)
{
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;
	u32 irq_num;

	if (!msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].num)
		return;

	local_vector_id = msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].base_vector_id;
	irq_num = msix_info->msix_entries[local_vector_id].vector;

	devm_free_irq(dev, irq_num, task_info);
}

static int nbl_dev_enable_adminq_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;

	if (!msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].base_vector_id;
	chan_ops->set_queue_interrupt_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_TYPE_ADMINQ,
					    true);

	return serv_ops->enable_adminq_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    local_vector_id, true);
}

static int nbl_dev_disable_adminq_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;

	if (!msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].base_vector_id;
	chan_ops->set_queue_interrupt_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_TYPE_ADMINQ,
					    false);

	return serv_ops->enable_adminq_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    local_vector_id, false);
}

static int nbl_dev_request_abnormal_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;
	u32 irq_num;
	int err;

	if (!msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].base_vector_id;
	irq_num = msix_info->msix_entries[local_vector_id].vector;

	err = devm_request_irq(dev, irq_num, nbl_dev_clean_abnormal_event,
			       0, "abnormal_irq", dev_mgt);
	if (err) {
		dev_err(dev, "Request abnormal_irq irq handler failed err: %d\n", err);
		return err;
	}

	return 0;
}

void nbl_dev_free_abnormal_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;
	u32 irq_num;

	if (!msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].num)
		return;

	local_vector_id = msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].base_vector_id;
	irq_num = msix_info->msix_entries[local_vector_id].vector;

	devm_free_irq(dev, irq_num, dev_mgt);
}

static int nbl_dev_enable_abnormal_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;
	int err = 0;

	if (!msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].base_vector_id;
	err = serv_ops->enable_abnormal_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    local_vector_id, true);

	return err;
}

static int nbl_dev_disable_abnormal_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;
	int err = 0;

	if (!msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].base_vector_id;
	err = serv_ops->enable_abnormal_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    local_vector_id, false);

	return err;
}

static int nbl_dev_configure_msix_map(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	int err = 0;
	int i;
	u16 msix_not_net_num = 0;

	for (i = NBL_MSIX_NET_TYPE; i < NBL_MSIX_TYPE_MAX; i++)
		msix_info->serv_info[i].base_vector_id = msix_info->serv_info[i - 1].base_vector_id
							 + msix_info->serv_info[i - 1].num;

	for (i = NBL_MSIX_MAILBOX_TYPE; i < NBL_MSIX_TYPE_MAX; i++) {
		if (i == NBL_MSIX_NET_TYPE)
			continue;

		msix_not_net_num += msix_info->serv_info[i].num;
	}

	err = serv_ops->configure_msix_map(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					   msix_info->serv_info[NBL_MSIX_NET_TYPE].num,
					   msix_not_net_num,
					   msix_info->serv_info[NBL_MSIX_NET_TYPE].hw_self_mask_en);

	return err;
}

static int nbl_dev_destroy_msix_map(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	int err = 0;

	err = serv_ops->destroy_msix_map(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	return err;
}

static int nbl_dev_alloc_msix_entries(struct nbl_dev_mgt *dev_mgt, u16 num_entries)
{
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	u16 i;

	msix_info->msix_entries = devm_kcalloc(NBL_DEV_MGT_TO_DEV(dev_mgt), num_entries,
					       sizeof(msix_info->msix_entries),
					       GFP_KERNEL);
	if (!msix_info->msix_entries)
		return -ENOMEM;

	for (i = 0; i < num_entries; i++)
		msix_info->msix_entries[i].entry =
				serv_ops->get_msix_entry_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), i);

	dev_info(NBL_DEV_MGT_TO_DEV(dev_mgt), "alloc msix entry: %u-%u.\n",
		 msix_info->msix_entries[0].entry, msix_info->msix_entries[num_entries - 1].entry);

	return 0;
}

static void nbl_dev_free_msix_entries(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);

	devm_kfree(NBL_DEV_MGT_TO_DEV(dev_mgt), msix_info->msix_entries);
	msix_info->msix_entries = NULL;
}

static int nbl_dev_alloc_msix_intr(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	int needed = 0;
	int err;
	int i;

	for (i = 0; i < NBL_MSIX_TYPE_MAX; i++)
		needed += msix_info->serv_info[i].num;

	err = nbl_dev_alloc_msix_entries(dev_mgt, (u16)needed);
	if (err) {
		pr_err("Allocate msix entries failed\n");
		return err;
	}

	err = pci_enable_msix_range(NBL_COMMON_TO_PDEV(common), msix_info->msix_entries,
				    needed, needed);
	if (err < 0) {
		pr_err("pci_enable_msix_range failed, err = %d.\n", err);
		goto enable_msix_failed;
	}

	return needed;

enable_msix_failed:
	nbl_dev_free_msix_entries(dev_mgt);
	return err;
}

static void nbl_dev_free_msix_intr(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);

	pci_disable_msix(NBL_COMMON_TO_PDEV(common));
	nbl_dev_free_msix_entries(dev_mgt);
}

static int nbl_dev_init_interrupt_scheme(struct nbl_dev_mgt *dev_mgt)
{
	int err = 0;

	err = nbl_dev_alloc_msix_intr(dev_mgt);
	if (err < 0) {
		dev_err(NBL_DEV_MGT_TO_DEV(dev_mgt), "Failed to enable MSI-X vectors\n");
		return err;
	}

	return 0;
}

static void nbl_dev_clear_interrupt_scheme(struct nbl_dev_mgt *dev_mgt)
{
	nbl_dev_free_msix_intr(dev_mgt);
}

/* ----------  Channel config  ---------- */
static int nbl_dev_setup_chan_qinfo(struct nbl_dev_mgt *dev_mgt, u8 chan_type)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	int ret = 0;

	if (!chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), chan_type))
		return 0;

	ret = chan_ops->cfg_chan_qinfo_map_table(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
						 chan_type);
	if (ret)
		dev_err(dev, "setup chan:%d, qinfo map table failed\n", chan_type);

	return ret;
}

static int nbl_dev_setup_chan_queue(struct nbl_dev_mgt *dev_mgt, u8 chan_type)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	int ret = 0;

	if (chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), chan_type))
		ret = chan_ops->setup_queue(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), chan_type);

	return ret;
}

static int nbl_dev_remove_chan_queue(struct nbl_dev_mgt *dev_mgt, u8 chan_type)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	int ret = 0;

	if (chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), chan_type))
		ret = chan_ops->teardown_queue(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), chan_type);

	return ret;
}

static int nbl_dev_setup_chan_keepalive(struct nbl_dev_mgt *dev_mgt, u8 chan_type)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	u16 dest_func_id = NBL_COMMON_TO_MGT_PF(common);

	if (chan_type != NBL_CHAN_TYPE_MAILBOX)
		return -EOPNOTSUPP;

	dest_func_id = serv_ops->get_function_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
						 NBL_COMMON_TO_VSI_ID(common));

	if (chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), chan_type))
		return chan_ops->setup_keepalive(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
						 dest_func_id, chan_type);

	return -ENOENT;
}

static void nbl_dev_remove_chan_keepalive(struct nbl_dev_mgt *dev_mgt, u8 chan_type)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	if (chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), chan_type))
		chan_ops->remove_keepalive(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), chan_type);
}

static bool nbl_dev_should_chan_keepalive(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	bool ret = true;

	ret &= serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					     NBL_TASK_KEEP_ALIVE);

	return ret;
}

static void nbl_dev_register_chan_task(struct nbl_dev_mgt *dev_mgt,
				       u8 chan_type, struct work_struct *task)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	if (chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), chan_type))
		chan_ops->register_chan_task(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), chan_type, task);
}

/* ----------  Tasks config  ---------- */
static void nbl_dev_clean_mailbox_task(struct work_struct *work)
{
	struct nbl_dev_common *common_dev = container_of(work, struct nbl_dev_common,
							 clean_mbx_task);
	struct nbl_dev_mgt *dev_mgt = common_dev->dev_mgt;
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	chan_ops->clean_queue_subtask(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_TYPE_MAILBOX);
}

static int nbl_dev_clean_mailbox_schedule(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_common *common_dev = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	bool is_ctrl = !!(NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt));

	nbl_common_queue_work(&common_dev->clean_mbx_task, is_ctrl, true);

	return 0;
}

static void nbl_dev_clean_adminq_task(struct work_struct *work)
{
	struct nbl_task_info *task_info = container_of(work, struct nbl_task_info,
						       clean_adminq_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	chan_ops->clean_queue_subtask(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_TYPE_ADMINQ);
}

static void nbl_dev_clean_adminq_schedule(struct nbl_task_info *task_info)
{
	nbl_common_queue_work(&task_info->clean_adminq_task, true, false);
}

static void nbl_dev_fw_heartbeat_task(struct work_struct *work)
{
	struct nbl_task_info *task_info = container_of(work, struct nbl_task_info,
						       fw_hb_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);

	if (task_info->fw_resetting)
		return;

	if (!serv_ops->check_fw_heartbeat(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt))) {
		dev_notice(NBL_COMMON_TO_DEV(common), "FW reset detected");
		task_info->fw_resetting = true;

		nbl_common_queue_delayed_work(&task_info->fw_reset_task, MSEC_PER_SEC, true, false);
	}
}

static void nbl_dev_fw_reset_task(struct work_struct *work)
{
	struct delayed_work *delayed_work = to_delayed_work(work);
	struct nbl_task_info *task_info = container_of(delayed_work, struct nbl_task_info,
						       fw_reset_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);

	if (serv_ops->check_fw_reset(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt))) {
		dev_notice(NBL_COMMON_TO_DEV(common), "FW recovered");

		nbl_dev_disable_adminq_irq(dev_mgt);
		nbl_dev_free_adminq_irq(dev_mgt, task_info);

		nbl_dev_remove_chan_queue(dev_mgt, NBL_CHAN_TYPE_ADMINQ);
		nbl_dev_setup_chan_qinfo(dev_mgt, NBL_CHAN_TYPE_ADMINQ);
		nbl_dev_setup_chan_queue(dev_mgt, NBL_CHAN_TYPE_ADMINQ);
		nbl_dev_request_adminq_irq(dev_mgt, task_info);
		nbl_dev_enable_adminq_irq(dev_mgt);

		if (NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt)) {
			nbl_dev_get_port_attributes(dev_mgt);
			nbl_dev_enable_port(dev_mgt, true);
		}
		task_info->fw_resetting = false;
		return;
	}

	nbl_common_queue_delayed_work(delayed_work, MSEC_PER_SEC, true, false);
}

static void nbl_dev_adapt_desc_gother_task(struct work_struct *work)
{
	struct nbl_task_info *task_info = container_of(work, struct nbl_task_info,
						       adapt_desc_gother_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->adapt_desc_gother(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}

static void nbl_dev_recovery_abnormal_task(struct work_struct *work)
{
	struct nbl_task_info *task_info = container_of(work, struct nbl_task_info,
						       recovery_abnormal_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->recovery_abnormal(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}

static void nbl_dev_ctrl_task_schedule(struct nbl_task_info *task_info)
{
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_FW_HB_CAP))
		nbl_common_queue_work(&task_info->fw_hb_task, true, false);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_ADAPT_DESC_GOTHER))
		nbl_common_queue_work(&task_info->adapt_desc_gother_task, true, false);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_RECOVERY_ABNORMAL_STATUS))
		nbl_common_queue_work(&task_info->recovery_abnormal_task, true, false);
}

static void nbl_dev_ctrl_task_timer(struct timer_list *t)
{
	struct nbl_task_info *task_info = from_timer(task_info, t, serv_timer);

	mod_timer(&task_info->serv_timer, round_jiffies(task_info->serv_timer_period + jiffies));
	nbl_dev_ctrl_task_schedule(task_info);
}

static void nbl_dev_ctrl_task_start(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_task_info *task_info = NBL_DEV_CTRL_TO_TASK_INFO(ctrl_dev);

	if (!task_info->timer_setup)
		return;

	mod_timer(&task_info->serv_timer, round_jiffies(jiffies + task_info->serv_timer_period));
}

static void nbl_dev_ctrl_task_stop(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_task_info *task_info = NBL_DEV_CTRL_TO_TASK_INFO(ctrl_dev);

	if (!task_info->timer_setup)
		return;

	del_timer_sync(&task_info->serv_timer);
}

static void nbl_dev_chan_notify_flr_resp(void *priv, u16 src_id, u16 msg_id,
					 void *data, u32 data_len)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	u16 vfid;

	vfid = *(u16 *)data;
	serv_ops->process_flr(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vfid);
}

static void nbl_dev_ctrl_register_flr_chan_msg(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	if (!serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					   NBL_PROCESS_FLR_CAP))
		return;

	chan_ops->register_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
			       NBL_CHAN_MSG_ADMINQ_FLR_NOTIFY,
			       nbl_dev_chan_notify_flr_resp, dev_mgt);
}

static int nbl_dev_setup_ctrl_dev_task(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_task_info *task_info = NBL_DEV_CTRL_TO_TASK_INFO(ctrl_dev);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	task_info->dev_mgt = dev_mgt;

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_FW_HB_CAP)) {
		nbl_common_alloc_task(&task_info->fw_hb_task, nbl_dev_fw_heartbeat_task);
		task_info->timer_setup = true;
	}

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_FW_RESET_CAP)) {
		nbl_common_alloc_delayed_task(&task_info->fw_reset_task, nbl_dev_fw_reset_task);
		task_info->timer_setup = true;
	}

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_CLEAN_ADMINDQ_CAP)) {
		nbl_common_alloc_task(&task_info->clean_adminq_task, nbl_dev_clean_adminq_task);
		task_info->timer_setup = true;
	}

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_ADAPT_DESC_GOTHER)) {
		nbl_common_alloc_task(&task_info->adapt_desc_gother_task,
				      nbl_dev_adapt_desc_gother_task);
		task_info->timer_setup = true;
	}

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_RECOVERY_ABNORMAL_STATUS)) {
		nbl_common_alloc_task(&task_info->recovery_abnormal_task,
				      nbl_dev_recovery_abnormal_task);
		task_info->timer_setup = true;
	}

	nbl_common_alloc_task(&task_info->clean_abnormal_irq_task,
			      nbl_dev_handle_abnormal_event);

	if (task_info->timer_setup) {
		timer_setup(&task_info->serv_timer, nbl_dev_ctrl_task_timer, 0);
		task_info->serv_timer_period = HZ;
	}

	nbl_dev_register_chan_task(dev_mgt, NBL_CHAN_TYPE_ADMINQ, &task_info->clean_adminq_task);

	return 0;
}

static void nbl_dev_remove_ctrl_dev_task(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_task_info *task_info = NBL_DEV_CTRL_TO_TASK_INFO(ctrl_dev);

	nbl_dev_register_chan_task(dev_mgt, NBL_CHAN_TYPE_ADMINQ, NULL);

	nbl_common_release_task(&task_info->clean_abnormal_irq_task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_FW_RESET_CAP))
		nbl_common_release_delayed_task(&task_info->fw_reset_task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_FW_HB_CAP))
		nbl_common_release_task(&task_info->fw_hb_task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_CLEAN_ADMINDQ_CAP))
		nbl_common_release_task(&task_info->clean_adminq_task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_ADAPT_DESC_GOTHER))
		nbl_common_release_task(&task_info->adapt_desc_gother_task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_RECOVERY_ABNORMAL_STATUS))
		nbl_common_release_task(&task_info->recovery_abnormal_task);
}

static int nbl_dev_setup_customized_p4(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	if (!serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_P4_CAP))
		return 0;

	return serv_ops->init_p4(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}

static int nbl_dev_update_ring_num(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->update_ring_num(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}

/* ----------  Dev init process  ---------- */
static int nbl_dev_setup_common_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_common *common_dev;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	int board_id;

	common_dev = devm_kzalloc(NBL_ADAPTER_TO_DEV(adapter),
				  sizeof(struct nbl_dev_common), GFP_KERNEL);
	if (!common_dev)
		return -ENOMEM;
	common_dev->dev_mgt = dev_mgt;

	if (nbl_dev_setup_chan_queue(dev_mgt, NBL_CHAN_TYPE_MAILBOX))
		goto setup_chan_fail;

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_CLEAN_MAILBOX_CAP))
		nbl_common_alloc_task(&common_dev->clean_mbx_task, nbl_dev_clean_mailbox_task);

	if (param->caps.is_nic) {
		board_id = serv_ops->get_board_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
		if (board_id < 0)
			goto get_board_id_fail;
		NBL_COMMON_TO_BOARD_ID(common) = board_id;
	}

	NBL_COMMON_TO_VSI_ID(common) = serv_ops->get_vsi_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), 0,
							    NBL_VSI_DATA);

	serv_ops->get_eth_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_COMMON_TO_VSI_ID(common),
			     &NBL_COMMON_TO_ETH_MODE(common), &NBL_COMMON_TO_ETH_ID(common));

	nbl_dev_register_chan_task(dev_mgt, NBL_CHAN_TYPE_MAILBOX, &common_dev->clean_mbx_task);

	NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt) = common_dev;

	nbl_dev_register_common_irq(dev_mgt);

	return 0;

get_board_id_fail:
	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_CLEAN_MAILBOX_CAP))
		nbl_common_release_task(&common_dev->clean_mbx_task);
setup_chan_fail:
	devm_kfree(NBL_ADAPTER_TO_DEV(adapter), common_dev);
	return -EFAULT;
}

static void nbl_dev_remove_common_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_common *common_dev = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);

	if (!common_dev)
		return;

	nbl_dev_register_chan_task(dev_mgt, NBL_CHAN_TYPE_MAILBOX, NULL);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_CLEAN_MAILBOX_CAP))
		nbl_common_release_task(&common_dev->clean_mbx_task);

	nbl_dev_remove_chan_queue(dev_mgt, NBL_CHAN_TYPE_MAILBOX);

	devm_kfree(NBL_ADAPTER_TO_DEV(adapter), common_dev);
	NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt) = NULL;
}

static int nbl_dev_setup_ctrl_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_ctrl *ctrl_dev;
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	int i, ret = 0;

	if (param->caps.is_nic)
		NBL_COMMON_TO_BOARD_ID(common) =
			nbl_dev_alloc_board_id(&board_id_table, common->bus);

	ctrl_dev = devm_kzalloc(dev, sizeof(struct nbl_dev_ctrl), GFP_KERNEL);
	if (!ctrl_dev)
		goto alloc_fail;
	NBL_DEV_CTRL_TO_TASK_INFO(ctrl_dev)->adapter = adapter;
	NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt) = ctrl_dev;

	nbl_dev_register_ctrl_irq(dev_mgt);

	ret = serv_ops->init_chip(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	if (ret) {
		dev_err(dev, "ctrl dev chip_init failed\n");
		goto chip_init_fail;
	}

	ret = serv_ops->start_mgt_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	if (ret) {
		dev_err(dev, "ctrl dev start_mgt_flow failed\n");
		goto mgt_flow_fail;
	}

	for (i = 0; i < NBL_CHAN_TYPE_MAX; i++) {
		ret = nbl_dev_setup_chan_qinfo(dev_mgt, i);
		if (ret) {
			dev_err(dev, "ctrl dev setup chan qinfo failed\n");
				goto setup_chan_q_fail;
		}
	}

	ret = nbl_dev_setup_chan_queue(dev_mgt, NBL_CHAN_TYPE_ADMINQ);
	if (ret) {
		dev_err(dev, "ctrl dev setup chan queue failed\n");
			goto setup_chan_q_fail;
	}

	ret = nbl_dev_setup_ctrl_dev_task(dev_mgt);
	if (ret) {
		dev_err(dev, "ctrl dev task failed\n");
		goto setup_ctrl_dev_task_fail;
	}

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_RESTOOL_CAP)) {
		ret = serv_ops->setup_st(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), nbl_get_st_table());
		if (ret) {
			dev_err(dev, "ctrl dev st failed\n");
			goto setup_ctrl_dev_st_fail;
		}
	}

	ret = nbl_dev_setup_customized_p4(dev_mgt);
	if (ret)
		goto customize_p4_fail;

	nbl_dev_update_ring_num(dev_mgt);

	return 0;

customize_p4_fail:
	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_RESTOOL_CAP))
		serv_ops->remove_st(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), nbl_get_st_table());
setup_ctrl_dev_st_fail:
	nbl_dev_remove_ctrl_dev_task(dev_mgt);
setup_ctrl_dev_task_fail:
	nbl_dev_remove_chan_queue(dev_mgt, NBL_CHAN_TYPE_ADMINQ);
setup_chan_q_fail:
	serv_ops->stop_mgt_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
mgt_flow_fail:
	serv_ops->destroy_chip(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
chip_init_fail:
	devm_kfree(dev, ctrl_dev);
	NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt) = NULL;
alloc_fail:
	nbl_dev_free_board_id(&board_id_table, common->bus);
	return ret;
}

static void nbl_dev_remove_ctrl_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_ctrl **ctrl_dev = &NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);

	if (!*ctrl_dev)
		return;

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_RESTOOL_CAP))
		serv_ops->remove_st(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), nbl_get_st_table());

	nbl_dev_remove_chan_queue(dev_mgt, NBL_CHAN_TYPE_ADMINQ);
	nbl_dev_remove_ctrl_dev_task(dev_mgt);

	serv_ops->stop_mgt_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	serv_ops->destroy_chip(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));

	devm_kfree(NBL_ADAPTER_TO_DEV(adapter), *ctrl_dev);
	*ctrl_dev = NULL;

	/* If it is not nic, this free function will do nothing, so no need check */
	nbl_dev_free_board_id(&board_id_table, common->bus);
}

static int nbl_dev_netdev_open(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->netdev_open(netdev);
}

static int nbl_dev_netdev_stop(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->netdev_stop(netdev);
}

static netdev_tx_t nbl_dev_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_resource_pt_ops *pt_ops = NBL_DEV_MGT_TO_RES_PT_OPS(dev_mgt);

	return pt_ops->start_xmit(skb, netdev);
}

static void nbl_dev_netdev_get_stats64(struct net_device *netdev, struct rtnl_link_stats64 *stats)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_stats64(netdev, stats);
}

static void nbl_dev_netdev_set_rx_mode(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->set_rx_mode(netdev);
}

static void nbl_dev_netdev_change_rx_flags(struct net_device *netdev, int flag)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->change_rx_flags(netdev, flag);
}

static int nbl_dev_netdev_set_mac(struct net_device *netdev, void *p)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_mac(netdev, p);
}

static int nbl_dev_netdev_rx_add_vid(struct net_device *netdev, __be16 proto, u16 vid)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->rx_add_vid(netdev, proto, vid);
}

static int nbl_dev_netdev_rx_kill_vid(struct net_device *netdev, __be16 proto, u16 vid)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->rx_kill_vid(netdev, proto, vid);
}

static netdev_features_t
nbl_dev_netdev_features_check(struct sk_buff *skb, struct net_device *netdev,
			      netdev_features_t features)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->features_check(skb, netdev, features);
}

static void nbl_dev_netdev_tx_timeout(struct net_device *netdev, u32 txqueue)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->tx_timeout(netdev, txqueue);
}

static int nbl_dev_netdev_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->change_mtu(netdev, new_mtu);
}

static int nbl_dev_ndo_get_phys_port_name(struct net_device *netdev, char *name, size_t len)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_phys_port_name(netdev, name, len);
}

static int
nbl_dev_ndo_get_port_parent_id(struct net_device *netdev, struct netdev_phys_item_id *ppid)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_port_parent_id(netdev, ppid);
}

static const struct net_device_ops netdev_ops_leonis_pf = {
	.ndo_open = nbl_dev_netdev_open,
	.ndo_stop = nbl_dev_netdev_stop,
	.ndo_start_xmit = nbl_dev_start_xmit,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_get_stats64 = nbl_dev_netdev_get_stats64,
	.ndo_set_rx_mode = nbl_dev_netdev_set_rx_mode,
	.ndo_change_rx_flags = nbl_dev_netdev_change_rx_flags,
	.ndo_set_mac_address = nbl_dev_netdev_set_mac,
	.ndo_vlan_rx_add_vid = nbl_dev_netdev_rx_add_vid,
	.ndo_vlan_rx_kill_vid = nbl_dev_netdev_rx_kill_vid,
	.ndo_features_check = nbl_dev_netdev_features_check,
	.ndo_tx_timeout = nbl_dev_netdev_tx_timeout,
	.ndo_change_mtu = nbl_dev_netdev_change_mtu,
	.ndo_get_phys_port_name = nbl_dev_ndo_get_phys_port_name,
	.ndo_get_port_parent_id = nbl_dev_ndo_get_port_parent_id,
};

static int nbl_dev_setup_netops_leonis(void *priv, struct net_device *netdev,
				       struct nbl_init_param *param)
{
	netdev->netdev_ops = &netdev_ops_leonis_pf;

	return 0;
}

static void nbl_dev_remove_netops(struct net_device *netdev)
{
	netdev->netdev_ops = NULL;
}

static void nbl_dev_get_drvinfo(struct net_device *netdev, struct ethtool_drvinfo *drvinfo)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_drvinfo(netdev, drvinfo);
}

static int nbl_dev_get_module_eeprom(struct net_device *netdev,
				     struct ethtool_eeprom *eeprom, u8 *data)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_module_eeprom(netdev, eeprom, data);
}

static int nbl_dev_get_module_info(struct net_device *netdev, struct ethtool_modinfo *info)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_module_info(netdev, info);
}

static int nbl_dev_get_eeprom_len(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_eeprom_length(netdev);
}

static int nbl_dev_get_eeprom(struct net_device *netdev, struct ethtool_eeprom *eeprom, u8 *bytes)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_eeprom(netdev, eeprom, bytes);
}

static void nbl_dev_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_strings(netdev, stringset, data);
}

static int nbl_dev_get_sset_count(struct net_device *netdev, int sset)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_sset_count(netdev, sset);
}

static void nbl_dev_get_ethtool_stats(struct net_device *netdev,
				      struct ethtool_stats *stats, u64 *data)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_ethtool_stats(netdev, stats, data);
}

static void nbl_dev_get_channels(struct net_device *netdev, struct ethtool_channels *channels)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_channels(netdev, channels);
}

static int nbl_dev_set_channels(struct net_device *netdev, struct ethtool_channels *channels)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_channels(netdev, channels);
}

static u32 nbl_dev_get_link(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_link(netdev);
}

static int
nbl_dev_get_link_ksettings(struct net_device *netdev, struct ethtool_link_ksettings *cmd)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_ksettings(netdev, cmd);
}

static int
nbl_dev_set_link_ksettings(struct net_device *netdev, const struct ethtool_link_ksettings *cmd)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_ksettings(netdev, cmd);
}

static void nbl_dev_get_ringparam(struct net_device *netdev, struct ethtool_ringparam *ringparam,
				  struct kernel_ethtool_ringparam *k_ringparam,
				  struct netlink_ext_ack *extack)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_ringparam(netdev, ringparam, k_ringparam, extack);
}

static int nbl_dev_set_ringparam(struct net_device *netdev, struct ethtool_ringparam *ringparam,
				 struct kernel_ethtool_ringparam *k_ringparam,
				 struct netlink_ext_ack *extack)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_ringparam(netdev, ringparam, k_ringparam, extack);
}

static int nbl_dev_get_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
				struct kernel_ethtool_coalesce *kernel_ec,
				struct netlink_ext_ack *extack)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_coalesce(netdev, ec, kernel_ec, extack);
}

static int nbl_dev_set_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
				struct kernel_ethtool_coalesce *kernel_ec,
				struct netlink_ext_ack *extack)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_coalesce(netdev, ec, kernel_ec, extack);
}

static int nbl_dev_get_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd, u32 *rule_locs)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_rxnfc(netdev, cmd, rule_locs);
}

static u32 nbl_dev_get_rxfh_indir_size(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_rxfh_indir_size(netdev);
}

static u32 nbl_dev_get_rxfh_key_size(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_rxfh_key_size(netdev);
}

static int nbl_dev_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key, u8 *hfunc)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_rxfh(netdev, indir, key, hfunc);
}

static u32 nbl_dev_get_msglevel(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_msglevel(netdev);
}

static void nbl_dev_set_msglevel(struct net_device *netdev, u32 msglevel)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->set_msglevel(netdev, msglevel);
}

static int nbl_dev_get_regs_len(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_regs_len(netdev);
}

static void nbl_dev_get_regs(struct net_device *netdev,
			     struct ethtool_regs *regs, void *p)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_ethtool_dump_regs(netdev, regs, p);
}

static int nbl_dev_get_per_queue_coalesce(struct net_device *netdev,
					  u32 q_num, struct ethtool_coalesce *ec)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_per_queue_coalesce(netdev, q_num, ec);
}

static int nbl_dev_set_per_queue_coalesce(struct net_device *netdev,
					  u32 q_num, struct ethtool_coalesce *ec)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_per_queue_coalesce(netdev, q_num, ec);
}

static void nbl_dev_self_test(struct net_device *netdev, struct ethtool_test *eth_test, u64 *data)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->self_test(netdev, eth_test, data);
}

static u32 nbl_dev_get_priv_flags(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_priv_flags(netdev);
}

static int nbl_dev_set_priv_flags(struct net_device *netdev, u32 priv_flags)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_priv_flags(netdev, priv_flags);
}

static int nbl_dev_set_pauseparam(struct net_device *netdev, struct ethtool_pauseparam *param)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_pause_param(netdev, param);
}

static void nbl_dev_get_pauseparam(struct net_device *netdev, struct ethtool_pauseparam *param)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_pause_param(netdev, param);
}

static int nbl_dev_set_fecparam(struct net_device *netdev, struct ethtool_fecparam *fec)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_fec_param(netdev, fec);
}

static int nbl_dev_get_fecparam(struct net_device *netdev, struct ethtool_fecparam *fec)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_fec_param(netdev, fec);
}

static int nbl_dev_get_ts_info(struct net_device *netdev, struct ethtool_ts_info *ts_info)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_ts_info(netdev, ts_info);
}

static int nbl_dev_set_phys_id(struct net_device *netdev, enum ethtool_phys_id_state state)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_phys_id(netdev, state);
}

static int nbl_dev_nway_reset(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->nway_reset(netdev);
}

static const struct ethtool_ops ethtool_ops_leonis_pf = {
	.supported_coalesce_params = ETHTOOL_COALESCE_RX_USECS |
				     ETHTOOL_COALESCE_RX_MAX_FRAMES |
				     ETHTOOL_COALESCE_TX_USECS |
				     ETHTOOL_COALESCE_TX_MAX_FRAMES |
				     ETHTOOL_COALESCE_USE_ADAPTIVE,
	.get_drvinfo = nbl_dev_get_drvinfo,
	.get_module_eeprom = nbl_dev_get_module_eeprom,
	.get_module_info = nbl_dev_get_module_info,
	.get_eeprom_len = nbl_dev_get_eeprom_len,
	.get_eeprom = nbl_dev_get_eeprom,
	.get_strings = nbl_dev_get_strings,
	.get_sset_count = nbl_dev_get_sset_count,
	.get_ethtool_stats = nbl_dev_get_ethtool_stats,
	.get_channels = nbl_dev_get_channels,
	.set_channels = nbl_dev_set_channels,
	.get_link = nbl_dev_get_link,
	.get_link_ksettings = nbl_dev_get_link_ksettings,
	.set_link_ksettings = nbl_dev_set_link_ksettings,
	.get_ringparam = nbl_dev_get_ringparam,
	.set_ringparam = nbl_dev_set_ringparam,
	.get_coalesce = nbl_dev_get_coalesce,
	.set_coalesce = nbl_dev_set_coalesce,
	.get_rxnfc = nbl_dev_get_rxnfc,
	.get_rxfh_indir_size = nbl_dev_get_rxfh_indir_size,
	.get_rxfh_key_size = nbl_dev_get_rxfh_key_size,
	.get_rxfh = nbl_dev_get_rxfh,
	.get_msglevel = nbl_dev_get_msglevel,
	.set_msglevel = nbl_dev_set_msglevel,
	.get_regs_len = nbl_dev_get_regs_len,
	.get_regs = nbl_dev_get_regs,
	.get_per_queue_coalesce = nbl_dev_get_per_queue_coalesce,
	.set_per_queue_coalesce = nbl_dev_set_per_queue_coalesce,
	.self_test = nbl_dev_self_test,
	.get_priv_flags = nbl_dev_get_priv_flags,
	.set_priv_flags = nbl_dev_set_priv_flags,
	.set_pauseparam = nbl_dev_set_pauseparam,
	.get_pauseparam = nbl_dev_get_pauseparam,
	.set_fecparam = nbl_dev_set_fecparam,
	.get_fecparam = nbl_dev_get_fecparam,
	.get_ts_info = nbl_dev_get_ts_info,
	.set_phys_id = nbl_dev_set_phys_id,
	.nway_reset = nbl_dev_nway_reset,
};

static int nbl_dev_setup_ethtool_ops_leonis(void *priv, struct net_device *netdev,
					    struct nbl_init_param *param)
{
	netdev->ethtool_ops = &ethtool_ops_leonis_pf;

	return 0;
}

static void nbl_dev_remove_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = NULL;
}

void nbl_dev_set_eth_mac_addr(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	u8 mac[ETH_ALEN];

	ether_addr_copy(mac, netdev->dev_addr);
	serv_ops->set_eth_mac_addr(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
				   mac, NBL_COMMON_TO_ETH_ID(common));
}

static int nbl_dev_cfg_netdev(struct net_device *netdev, struct nbl_dev_mgt *dev_mgt,
			      struct nbl_init_param *param,
			      struct nbl_register_net_result *register_result)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_net_ops *net_dev_ops = NBL_DEV_MGT_TO_NETDEV_OPS(dev_mgt);
	int ret = 0;

	if (param->pci_using_dac)
		netdev->features |= NETIF_F_HIGHDMA;

	netdev->hw_features |= nbl_features_to_netdev_features(register_result->hw_features);
	netdev->features |= nbl_features_to_netdev_features(register_result->features);
	netdev->vlan_features |= netdev->features;

	SET_DEV_MIN_MTU(netdev, ETH_MIN_MTU);
	SET_DEV_MAX_MTU(netdev, register_result->max_mtu);
	netdev->mtu = min_t(u16, register_result->max_mtu, NBL_DEFAULT_MTU);

	if (is_valid_ether_addr(register_result->mac))
		eth_hw_addr_set(netdev, register_result->mac);
	else
		eth_hw_addr_random(netdev);

	ether_addr_copy(netdev->perm_addr, netdev->dev_addr);

	serv_ops->set_spoof_check_addr(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), netdev->perm_addr);

	netdev->needed_headroom = serv_ops->get_tx_headroom(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));

	ret = net_dev_ops->setup_netdev_ops(dev_mgt, netdev, param);
	if (ret)
		goto set_ops_fail;

	ret = net_dev_ops->setup_ethtool_ops(dev_mgt, netdev, param);
	if (ret)
		goto set_ethtool_fail;

	nbl_dev_set_eth_mac_addr(dev_mgt, netdev);

	return 0;

set_ethtool_fail:
	nbl_dev_remove_netops(netdev);
set_ops_fail:
	return ret;
}

static void nbl_dev_reset_netdev(struct net_device *netdev)
{
	nbl_dev_remove_ethtool_ops(netdev);
	nbl_dev_remove_netops(netdev);
}

static int nbl_dev_register_net(struct nbl_dev_mgt *dev_mgt,
				struct nbl_register_net_result *register_result)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct pci_dev *pdev = NBL_COMMON_TO_PDEV(NBL_DEV_MGT_TO_COMMON(dev_mgt));
	struct resource *res;
	u16 pf_bdf;
	u64 pf_bar_start;
	u64 vf_bar_start, vf_bar_size;
	u16 total_vfs, offset, stride;
	int pos;
	u32 val;
	struct nbl_register_net_param register_param = {0};
	int ret = 0;

	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_0, &val);
	pf_bar_start = (u64)(val & PCI_BASE_ADDRESS_MEM_MASK);
	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_0 + 4, &val);
	pf_bar_start |= ((u64)val << 32);

	register_param.pf_bar_start = pf_bar_start;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (pos) {
		pf_bdf = PCI_DEVID(pdev->bus->number, pdev->devfn);

		pci_read_config_word(pdev, pos + PCI_SRIOV_VF_OFFSET, &offset);
		pci_read_config_word(pdev, pos + PCI_SRIOV_VF_STRIDE, &stride);
		pci_read_config_word(pdev, pos + PCI_SRIOV_TOTAL_VF, &total_vfs);

		pci_read_config_dword(pdev, pos + PCI_SRIOV_BAR, &val);
		vf_bar_start = (u64)(val & PCI_BASE_ADDRESS_MEM_MASK);
		pci_read_config_dword(pdev, pos + PCI_SRIOV_BAR + 4, &val);
		vf_bar_start |= ((u64)val << 32);

		res = &pdev->resource[PCI_IOV_RESOURCES];
		vf_bar_size = resource_size(res);

		if (total_vfs) {
			register_param.pf_bdf = pf_bdf;
			register_param.vf_bar_start = vf_bar_start;
			register_param.vf_bar_size = vf_bar_size;
			register_param.total_vfs = total_vfs;
			register_param.offset = offset;
			register_param.stride = stride;
		}
	}

	ret = serv_ops->register_net(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
				     &register_param, register_result);

	if (!register_result->tx_queue_num || !register_result->rx_queue_num)
		return -EIO;

	return ret;
}

void nbl_dev_unregister_net(struct nbl_adapter *adapter)
{
	struct nbl_service_ops_tbl *serv_ops_tbl = NBL_ADAPTER_TO_SERV_OPS_TBL(adapter);
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	int ret;

	ret = serv_ops_tbl->ops->unregister_net(serv_ops_tbl->priv);
	if (ret)
		dev_err(dev, "unregister net failed\n");
}

static u16 nbl_dev_vsi_alloc_queue(struct nbl_dev_net *net_dev, u16 queue_num)
{
	struct nbl_dev_vsi_controller *vsi_ctrl = &net_dev->vsi_ctrl;
	u16 queue_offset = 0;

	if (vsi_ctrl->queue_free_offset + queue_num > net_dev->total_queue_num)
		return -ENOSPC;

	queue_offset = vsi_ctrl->queue_free_offset;
	vsi_ctrl->queue_free_offset += queue_num;

	return queue_offset;
}

static int nbl_dev_vsi_common_setup(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
				    struct nbl_dev_vsi *vsi)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	int ret = 0;

	vsi->queue_offset = nbl_dev_vsi_alloc_queue(NBL_DEV_MGT_TO_NET_DEV(dev_mgt),
						    vsi->queue_num);

	/* Tell serv & res layer the mapping from vsi to queue_id */
	ret = serv_ops->register_vsi_info(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->index,
					  vsi->vsi_id, vsi->queue_offset, vsi->queue_num);
	return ret;
}

static void nbl_dev_vsi_common_remove(struct nbl_dev_mgt *dev_mgt, struct nbl_dev_vsi *vsi)
{
}

static int nbl_dev_vsi_common_start(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev,
				    struct nbl_dev_vsi *vsi)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	int ret;

	vsi->napi_netdev = netdev;

	ret = serv_ops->setup_q2vsi(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
	if (ret) {
		dev_err(dev, "Setup q2vsi failed\n");
		goto set_q2vsi_fail;
	}

	ret = serv_ops->setup_rss(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
	if (ret) {
		dev_err(dev, "Setup q2vsi failed\n");
		goto set_rss_fail;
	}

	ret = serv_ops->enable_napis(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->index);
	if (ret) {
		dev_err(dev, "Enable napis failed\n");
		goto enable_napi_fail;
	}

	return 0;

enable_napi_fail:
	serv_ops->remove_rss(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
set_rss_fail:
	serv_ops->remove_q2vsi(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
set_q2vsi_fail:
	return ret;
}

static void nbl_dev_vsi_common_stop(struct nbl_dev_mgt *dev_mgt, struct nbl_dev_vsi *vsi)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->disable_napis(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->index);
	serv_ops->remove_rss(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
	serv_ops->remove_q2vsi(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
}

static int nbl_dev_vsi_data_register(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
				     void *vsi_data)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;
	int ret = 0;

	ret = nbl_dev_register_net(dev_mgt, &vsi->register_result);
	if (ret)
		return ret;

	vsi->queue_num = vsi->register_result.tx_queue_num;
	vsi->queue_size = vsi->register_result.queue_size;

	nbl_debug(common, NBL_DEBUG_VSI, "Data vsi register, queue_num %d, queue_size %d",
		  vsi->queue_num, vsi->queue_size);

	return 0;
}

static int nbl_dev_vsi_data_setup(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
				  void *vsi_data)
{
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;

	return nbl_dev_vsi_common_setup(dev_mgt, param, vsi);
}

static void nbl_dev_vsi_data_remove(struct nbl_dev_mgt *dev_mgt, void *vsi_data)
{
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;

	nbl_dev_vsi_common_remove(dev_mgt, vsi);
}

static int nbl_dev_vsi_data_start(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev,
				  void *vsi_data)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;
	int ret;

	ret = serv_ops->start_net_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), netdev, vsi->vsi_id);
	if (ret) {
		dev_err(dev, "Set netdev flow table failed\n");
		goto set_flow_fail;
	}

	if (!NBL_COMMON_TO_VF_CAP(common)) {
		ret = serv_ops->set_lldp_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
		if (ret) {
			dev_err(dev, "Set netdev lldp flow failed\n");
			goto set_lldp_fail;
		}

		vsi->feature.has_lldp = true;

		ret = serv_ops->enable_lag_protocol(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
						    vsi->vsi_id, true);
		if (ret) {
			dev_err(dev, "Set netdev lacp flow failed\n");
			goto set_lacp_fail;
		}

		vsi->feature.has_lacp = true;
	}

	ret = nbl_dev_vsi_common_start(dev_mgt, netdev, vsi);
	if (ret) {
		dev_err(dev, "Vsi common start failed\n");
		goto common_start_fail;
	}

	return 0;

common_start_fail:
	if (!NBL_COMMON_TO_VF_CAP(common))
		serv_ops->enable_lag_protocol(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id,
					      false);
set_lacp_fail:
	if (!NBL_COMMON_TO_VF_CAP(common))
		serv_ops->remove_lldp_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
set_lldp_fail:
	serv_ops->stop_net_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
set_flow_fail:
	return ret;
}

static void nbl_dev_vsi_data_stop(struct nbl_dev_mgt *dev_mgt, void *vsi_data)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;

	nbl_dev_vsi_common_stop(dev_mgt, vsi);

	if (!NBL_COMMON_TO_VF_CAP(common)) {
		serv_ops->remove_lldp_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
		vsi->feature.has_lldp = false;
		serv_ops->enable_lag_protocol(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id,
					      false);
		vsi->feature.has_lacp = false;
	}

	serv_ops->stop_net_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
}

static int nbl_dev_vsi_data_netdev_build(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
					 struct net_device *netdev, void *vsi_data)
{
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;

	vsi->netdev = netdev;
	return nbl_dev_cfg_netdev(netdev, dev_mgt, param, &vsi->register_result);
}

static void nbl_dev_vsi_data_netdev_destroy(struct nbl_dev_mgt *dev_mgt, void *vsi_data)
{
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;

	nbl_dev_reset_netdev(vsi->netdev);
}

static int nbl_dev_vsi_ctrl_register(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
				     void *vsi_data)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;

	nbl_debug(common, NBL_DEBUG_VSI, "Ctrl vsi register, queue_num %d, queue_size %d",
		  vsi->queue_num, vsi->queue_size);
	return 0;
}

static int nbl_dev_vsi_ctrl_setup(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
				  void *vsi_data)
{
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;

	return nbl_dev_vsi_common_setup(dev_mgt, param, vsi);
}

static void nbl_dev_vsi_ctrl_remove(struct nbl_dev_mgt *dev_mgt, void *vsi_data)
{
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;

	nbl_dev_vsi_common_remove(dev_mgt, vsi);
}

static int nbl_dev_vsi_ctrl_start(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev,
				  void *vsi_data)
{
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	int ret = 0;

	ret = nbl_dev_vsi_common_start(dev_mgt, netdev, vsi);
	if (ret)
		goto start_fail;

	/* For ctrl vsi, open it after create, for that we don't have ndo_open ops. */
	ret = serv_ops->vsi_open(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), netdev,
				 vsi->index, vsi->queue_num, 1);
	if (ret)
		goto open_fail;

	return ret;

open_fail:
	nbl_dev_vsi_common_stop(dev_mgt, vsi);
start_fail:
	return ret;
}

static void nbl_dev_vsi_ctrl_stop(struct nbl_dev_mgt *dev_mgt, void *vsi_data)
{
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->vsi_stop(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->index);
	nbl_dev_vsi_common_stop(dev_mgt, vsi);
}

static int nbl_dev_vsi_ctrl_netdev_build(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
					 struct net_device *netdev, void *vsi_data)
{
	return 0;
}

static void nbl_dev_vsi_ctrl_netdev_destroy(struct nbl_dev_mgt *dev_mgt, void *vsi_data)
{
}

static int nbl_dev_vsi_user_register(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
				     void *vsi_data)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_user_queue_info(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &vsi->queue_num,
				      &vsi->queue_size, NBL_COMMON_TO_VSI_ID(common));

	nbl_debug(common, NBL_DEBUG_VSI, "User vsi register, queue_num %d, queue_size %d",
		  vsi->queue_num, vsi->queue_size);
	return 0;
}

static int nbl_dev_vsi_user_setup(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
				  void *vsi_data)
{
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;

	return nbl_dev_vsi_common_setup(dev_mgt, param, vsi);
}

static void nbl_dev_vsi_user_remove(struct nbl_dev_mgt *dev_mgt, void *vsi_data)
{
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;

	nbl_dev_vsi_common_remove(dev_mgt, vsi);
}

static int nbl_dev_vsi_user_start(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev,
				  void *vsi_data)
{
	return 0;
}

static void nbl_dev_vsi_user_stop(struct nbl_dev_mgt *dev_mgt, void *vsi_data)
{
}

static int nbl_dev_vsi_user_netdev_build(struct nbl_dev_mgt *dev_mgt,
					 struct nbl_init_param *param,
					 struct net_device *netdev, void *vsi_data)
{
	return 0;
}

static void nbl_dev_vsi_user_netdev_destroy(struct nbl_dev_mgt *dev_mgt, void *vsi_data)
{
}

static struct nbl_dev_vsi_tbl vsi_tbl[NBL_VSI_MAX] = {
	[NBL_VSI_DATA] = {
		.vsi_ops = {
			.register_vsi = nbl_dev_vsi_data_register,
			.setup = nbl_dev_vsi_data_setup,
			.remove = nbl_dev_vsi_data_remove,
			.start = nbl_dev_vsi_data_start,
			.stop = nbl_dev_vsi_data_stop,
			.netdev_build = nbl_dev_vsi_data_netdev_build,
			.netdev_destroy = nbl_dev_vsi_data_netdev_destroy,
		},
		.vf_support = true,
		.only_nic_support = false,
		.in_kernel = true,
	},
	[NBL_VSI_CTRL] = {
		.vsi_ops = {
			.register_vsi = nbl_dev_vsi_ctrl_register,
			.setup = nbl_dev_vsi_ctrl_setup,
			.remove = nbl_dev_vsi_ctrl_remove,
			.start = nbl_dev_vsi_ctrl_start,
			.stop = nbl_dev_vsi_ctrl_stop,
			.netdev_build = nbl_dev_vsi_ctrl_netdev_build,
			.netdev_destroy = nbl_dev_vsi_ctrl_netdev_destroy,
		},
		.vf_support = false,
		.only_nic_support = true,
		.in_kernel = true,
	},
	[NBL_VSI_USER] = {
		.vsi_ops = {
			.register_vsi = nbl_dev_vsi_user_register,
			.setup = nbl_dev_vsi_user_setup,
			.remove = nbl_dev_vsi_user_remove,
			.start = nbl_dev_vsi_user_start,
			.stop = nbl_dev_vsi_user_stop,
			.netdev_build = nbl_dev_vsi_user_netdev_build,
			.netdev_destroy = nbl_dev_vsi_user_netdev_destroy,
		},
		.vf_support = false,
		.only_nic_support = true,
		.in_kernel = false,
	},
};

static int nbl_dev_vsi_build(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param)
{
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_vsi *vsi = NULL;
	int i;

	net_dev->vsi_ctrl.queue_num = 0;
	net_dev->vsi_ctrl.queue_free_offset = 0;

	/* Build all vsi, and alloc vsi_id for each of them */
	for (i = 0; i < NBL_VSI_MAX; i++) {
		if ((param->caps.is_vf && !vsi_tbl[i].vf_support) ||
		    (!param->caps.is_nic && vsi_tbl[i].only_nic_support))
			continue;

		vsi = devm_kzalloc(NBL_DEV_MGT_TO_DEV(dev_mgt), sizeof(*vsi), GFP_KERNEL);
		if (!vsi)
			goto malloc_vsi_fail;

		vsi->ops = &vsi_tbl[i].vsi_ops;
		vsi->vsi_id = serv_ops->get_vsi_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), 0, i);
		vsi->index = i;
		vsi->in_kernel = vsi_tbl[i].in_kernel;

		net_dev->vsi_ctrl.vsi_list[i] = vsi;
	}

	return 0;

malloc_vsi_fail:
	while (--i + 1) {
		devm_kfree(NBL_DEV_MGT_TO_DEV(dev_mgt), net_dev->vsi_ctrl.vsi_list[i]);
		net_dev->vsi_ctrl.vsi_list[i] = NULL;
	}

	return -ENOMEM;
}

static void nbl_dev_vsi_destroy(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	int i;

	for (i = 0; i < NBL_VSI_MAX; i++)
		if (net_dev->vsi_ctrl.vsi_list[i]) {
			devm_kfree(NBL_DEV_MGT_TO_DEV(dev_mgt), net_dev->vsi_ctrl.vsi_list[i]);
			net_dev->vsi_ctrl.vsi_list[i] = NULL;
		}
}

static struct nbl_dev_vsi *nbl_dev_vsi_select(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_dev_vsi *vsi = NULL;
	int i = 0;

	for (i = 0; i < NBL_VSI_MAX; i++) {
		vsi = net_dev->vsi_ctrl.vsi_list[i];
		if (vsi && vsi->index == NBL_VSI_DATA)
			return vsi;
	}

	return NULL;
}

static int nbl_dev_vsi_handle_switch_event(u16 type, void *event_data, void *callback_data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)callback_data;
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct net_device *netdev = net_dev->netdev;
	struct nbl_netdev_priv *net_priv = netdev_priv(netdev);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_event_dev_mode_switch_data *data =
		(struct nbl_event_dev_mode_switch_data *)event_data;
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_vsi *from_vsi = NULL, *to_vsi = NULL;
	int op = data->op;

	switch (op) {
	case NBL_DEV_KERNEL_TO_USER:
		from_vsi = net_dev->vsi_ctrl.vsi_list[NBL_VSI_DATA];
		to_vsi = net_dev->vsi_ctrl.vsi_list[NBL_VSI_USER];
		break;
	case NBL_DEV_USER_TO_KERNEL:
		from_vsi = net_dev->vsi_ctrl.vsi_list[NBL_VSI_USER];
		to_vsi = net_dev->vsi_ctrl.vsi_list[NBL_VSI_DATA];
		break;
	default:
		nbl_err(common, NBL_DEBUG_VSI, "Unknown switch op %d", op);
		return -ENOENT;
	}

	net_priv->default_vsi_index = to_vsi->index;
	net_priv->default_vsi_id = to_vsi->vsi_id;

	data->ret = serv_ops->switch_traffic_default_dest(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
							  from_vsi->vsi_id,
							  to_vsi->vsi_id);
	if (data->ret) {
		net_priv->default_vsi_index = from_vsi->index;
		net_priv->default_vsi_id = from_vsi->vsi_id;
	}

	return 0;
}

static struct nbl_dev_net_ops netdev_ops[NBL_PRODUCT_MAX] = {
	{
		.setup_netdev_ops	= nbl_dev_setup_netops_leonis,
		.setup_ethtool_ops	= nbl_dev_setup_ethtool_ops_leonis,
	},
};

static void nbl_det_setup_net_dev_ops(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param)
{
	NBL_DEV_MGT_TO_NETDEV_OPS(dev_mgt) = &netdev_ops[param->product_type];
}

static int nbl_dev_setup_net_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_net **net_dev = &NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct nbl_dev_vsi *vsi;
	u16 total_queue_num = 0, kernel_queue_num = 0, user_queue_num = 0;
	int i, ret = 0;

	*net_dev = devm_kzalloc(dev, sizeof(struct nbl_dev_net), GFP_KERNEL);
	if (!*net_dev)
		return -ENOMEM;

	ret = nbl_dev_vsi_build(dev_mgt, param);
	if (ret)
		goto vsi_build_fail;

	for (i = 0; i < NBL_VSI_MAX; i++) {
		vsi = (*net_dev)->vsi_ctrl.vsi_list[i];

		if (!vsi)
			continue;

		ret = vsi->ops->register_vsi(dev_mgt, param, vsi);
		if (ret) {
			dev_err(NBL_DEV_MGT_TO_DEV(dev_mgt), "Vsi %d register failed", vsi->index);
			goto vsi_register_fail;
		}

		total_queue_num += vsi->queue_num;
		if (vsi->in_kernel)
			kernel_queue_num += vsi->queue_num;
		else
			user_queue_num += vsi->queue_num;
	}

	/* This must before vsi_setup, or else no queue can be alloced */
	(*net_dev)->total_queue_num = total_queue_num;
	(*net_dev)->kernel_queue_num = kernel_queue_num;
	(*net_dev)->user_queue_num = user_queue_num;

	for (i = 0; i < NBL_VSI_MAX; i++) {
		vsi = (*net_dev)->vsi_ctrl.vsi_list[i];

		if (!vsi)
			continue;

		ret = vsi->ops->setup(dev_mgt, param, vsi);
		if (ret) {
			dev_err(NBL_DEV_MGT_TO_DEV(dev_mgt), "Vsi %d setup failed", vsi->index);
			goto vsi_setup_fail;
		}
	}

	nbl_dev_register_net_irq(dev_mgt, kernel_queue_num);

	nbl_det_setup_net_dev_ops(dev_mgt, param);

	return 0;

vsi_setup_fail:
	while (--i + 1) {
		vsi = (*net_dev)->vsi_ctrl.vsi_list[i];

		if (!vsi)
			continue;

		vsi->ops->remove(dev_mgt, vsi);
	}
vsi_register_fail:
	nbl_dev_vsi_destroy(dev_mgt);
vsi_build_fail:
	devm_kfree(dev, *net_dev);
	return ret;
}

static void nbl_dev_remove_net_dev(struct nbl_adapter *adapter)
{
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_net **net_dev = &NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct net_device *netdev;
	struct nbl_dev_vsi *vsi;
	int i = 0;

	if (!*net_dev)
		return;

	netdev = (*net_dev)->netdev;

	for (i = 0; i < NBL_VSI_MAX; i++) {
		vsi = (*net_dev)->vsi_ctrl.vsi_list[i];

		if (!vsi)
			continue;

		vsi->ops->remove(dev_mgt, vsi);
	}
	nbl_dev_vsi_destroy(dev_mgt);

	nbl_dev_unregister_net(adapter);

	devm_kfree(dev, *net_dev);
	*net_dev = NULL;
}

static int nbl_dev_setup_dev_mgt(struct nbl_common_info *common, struct nbl_dev_mgt **dev_mgt)
{
	*dev_mgt = devm_kzalloc(NBL_COMMON_TO_DEV(common), sizeof(struct nbl_dev_mgt), GFP_KERNEL);
	if (!*dev_mgt)
		return -ENOMEM;

	NBL_DEV_MGT_TO_COMMON(*dev_mgt) = common;
	return 0;
}

static void nbl_dev_remove_dev_mgt(struct nbl_common_info *common, struct nbl_dev_mgt **dev_mgt)
{
	devm_kfree(NBL_COMMON_TO_DEV(common), *dev_mgt);
	*dev_mgt = NULL;
}

static void nbl_dev_remove_ops(struct device *dev, struct nbl_dev_ops_tbl **dev_ops_tbl)
{
	devm_kfree(dev, *dev_ops_tbl);
	*dev_ops_tbl = NULL;
}

static int nbl_dev_setup_ops(struct device *dev, struct nbl_dev_ops_tbl **dev_ops_tbl,
			     struct nbl_adapter *adapter)
{
	*dev_ops_tbl = devm_kzalloc(dev, sizeof(struct nbl_dev_ops_tbl), GFP_KERNEL);
	if (!*dev_ops_tbl)
		return -ENOMEM;

	NBL_DEV_OPS_TBL_TO_OPS(*dev_ops_tbl) = &dev_ops;
	NBL_DEV_OPS_TBL_TO_PRIV(*dev_ops_tbl) = adapter;

	return 0;
}

int nbl_dev_init(void *p, struct nbl_init_param *param)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_dev_mgt **dev_mgt = (struct nbl_dev_mgt **)&NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_ops_tbl **dev_ops_tbl = &NBL_ADAPTER_TO_DEV_OPS_TBL(adapter);
	struct nbl_service_ops_tbl *serv_ops_tbl = NBL_ADAPTER_TO_SERV_OPS_TBL(adapter);
	struct nbl_channel_ops_tbl *chan_ops_tbl = NBL_ADAPTER_TO_CHAN_OPS_TBL(adapter);
	int ret = 0;

	ret = nbl_dev_setup_dev_mgt(common, dev_mgt);
	if (ret)
		goto setup_mgt_fail;

	NBL_DEV_MGT_TO_SERV_OPS_TBL(*dev_mgt) = serv_ops_tbl;
	NBL_DEV_MGT_TO_CHAN_OPS_TBL(*dev_mgt) = chan_ops_tbl;

	ret = nbl_dev_setup_common_dev(adapter, param);
	if (ret)
		goto setup_common_dev_fail;

	if (param->caps.has_ctrl) {
		ret = nbl_dev_setup_ctrl_dev(adapter, param);
		if (ret)
			goto setup_ctrl_dev_fail;
	}

	ret = nbl_dev_setup_net_dev(adapter, param);
	if (ret)
		goto setup_net_dev_fail;

	ret = nbl_dev_setup_ops(dev, dev_ops_tbl, adapter);
	if (ret)
		goto setup_ops_fail;

	return 0;

setup_ops_fail:
	nbl_dev_remove_net_dev(adapter);
setup_net_dev_fail:
	nbl_dev_remove_ctrl_dev(adapter);
setup_ctrl_dev_fail:
	nbl_dev_remove_common_dev(adapter);
setup_common_dev_fail:
	nbl_dev_remove_dev_mgt(common, dev_mgt);
setup_mgt_fail:
	return ret;
}

void nbl_dev_remove(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_dev_mgt **dev_mgt = (struct nbl_dev_mgt **)&NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_ops_tbl **dev_ops_tbl = &NBL_ADAPTER_TO_DEV_OPS_TBL(adapter);

	nbl_dev_remove_ops(dev, dev_ops_tbl);

	nbl_dev_remove_net_dev(adapter);
	nbl_dev_remove_ctrl_dev(adapter);
	nbl_dev_remove_common_dev(adapter);

	nbl_dev_remove_dev_mgt(common, dev_mgt);
}

/* ----------  Dev start process  ---------- */
static int nbl_dev_start_ctrl_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	int err = 0;

	err = nbl_dev_request_abnormal_irq(dev_mgt);
	if (err)
		goto abnormal_request_irq_err;

	err = nbl_dev_enable_abnormal_irq(dev_mgt);
	if (err)
		goto enable_abnormal_irq_err;

	err = nbl_dev_request_adminq_irq(dev_mgt, &NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt)->task_info);
	if (err)
		goto request_adminq_irq_err;

	err = nbl_dev_enable_adminq_irq(dev_mgt);
	if (err)
		goto enable_adminq_irq_err;

	nbl_dev_ctrl_register_flr_chan_msg(dev_mgt);

	nbl_dev_get_port_attributes(dev_mgt);
	nbl_dev_enable_port(dev_mgt, true);
	nbl_dev_ctrl_task_start(dev_mgt);

	return 0;

enable_adminq_irq_err:
	nbl_dev_free_adminq_irq(dev_mgt, &NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt)->task_info);
request_adminq_irq_err:
	nbl_dev_disable_abnormal_irq(dev_mgt);
enable_abnormal_irq_err:
	nbl_dev_free_abnormal_irq(dev_mgt);
abnormal_request_irq_err:
	return err;
}

static void nbl_dev_stop_ctrl_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);

	if (!NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt))
		return;

	nbl_dev_ctrl_task_stop(dev_mgt);
	nbl_dev_enable_port(dev_mgt, false);
	nbl_dev_disable_adminq_irq(dev_mgt);
	nbl_dev_free_adminq_irq(dev_mgt, &NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt)->task_info);
	nbl_dev_disable_abnormal_irq(dev_mgt);
	nbl_dev_free_abnormal_irq(dev_mgt);
}

static void nbl_dev_chan_notify_link_state_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct net_device *netdev = (struct net_device *)priv;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_chan_param_notify_link_state *link_info;

	link_info = (struct nbl_chan_param_notify_link_state *)data;

	serv_ops->set_netdev_carrier_state(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					   netdev, link_info->link_state);
}

static void nbl_dev_register_link_state_chan_msg(struct nbl_dev_mgt *dev_mgt,
						 struct net_device *netdev)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	if (!chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	chan_ops->register_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
			       NBL_CHAN_MSG_NOTIFY_LINK_STATE,
			       nbl_dev_chan_notify_link_state_resp, netdev);
}

static int nbl_dev_start_net_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct net_device *netdev = net_dev->netdev;
	struct nbl_netdev_priv *net_priv;
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_dev_vsi *vsi;
	struct nbl_event_callback callback = {0};
	u16 net_vector_id;
	int ret;

	vsi = nbl_dev_vsi_select(dev_mgt);
	if (!vsi)
		return -EFAULT;

	netdev = alloc_etherdev_mqs(sizeof(struct nbl_netdev_priv), vsi->queue_num, vsi->queue_num);
	if (!netdev) {
		dev_err(dev, "Alloc net device failed\n");
		ret = -ENOMEM;
		goto alloc_netdev_fail;
	}

	SET_NETDEV_DEV(netdev, dev);
	net_priv = netdev_priv(netdev);
	net_priv->adapter = adapter;
	nbl_dev_set_netdev_priv(netdev, vsi);

	net_dev->netdev = netdev;
	common->msg_enable = netif_msg_init(debug, DEFAULT_MSG_ENABLE);
	serv_ops->set_mask_en(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), 1);

	/* Alloc all queues.
	 * One problem is we now must use the queue_size of data_vsi for all queues.
	 */
	ret = serv_ops->alloc_rings(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), netdev,
				    net_dev->kernel_queue_num, net_dev->kernel_queue_num,
				    net_priv->queue_size);
	if (ret) {
		dev_err(dev, "Alloc rings failed\n");
		goto alloc_rings_fail;
	}

	net_vector_id = msix_info->serv_info[NBL_MSIX_NET_TYPE].base_vector_id;
	ret = serv_ops->setup_txrx_queues(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  vsi->vsi_id, net_dev->total_queue_num, net_vector_id);
	if (ret) {
		dev_err(dev, "Set queue map failed\n");
		goto set_queue_fail;
	}

	ret = serv_ops->setup_net_resource_mgt(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), netdev);
	if (ret) {
		dev_err(dev, "setup net mgt failed\n");
		goto setup_net_mgt_fail;
	}

	nbl_dev_register_link_state_chan_msg(dev_mgt, netdev);

	ret = vsi->ops->netdev_build(dev_mgt, param, netdev, vsi);
	if (ret) {
		dev_err(dev, "Build netdev failed, selected vsi %d\n", vsi->index);
		goto build_netdev_fail;
	}

	ret = vsi->ops->start(dev_mgt, netdev, vsi);
	if (ret) {
		dev_err(dev, "Start vsi failed, selected vsi %d\n", vsi->index);
		goto start_vsi_fail;
	}

	ret = nbl_dev_request_net_irq(dev_mgt);
	if (ret) {
		dev_err(dev, "request irq failed\n");
		goto request_irq_fail;
	}

	netif_carrier_off(netdev);
	ret = register_netdev(netdev);
	if (ret) {
		dev_err(dev, "Register netdev failed\n");
		goto register_netdev_fail;
	}

	if (!param->caps.is_vf) {
		callback.callback = nbl_dev_vsi_handle_switch_event;
		callback.callback_data = dev_mgt;
		nbl_event_register(NBL_EVENT_DEV_MODE_SWITCH, &callback,
				   NBL_COMMON_TO_ETH_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	}

	set_bit(NBL_DOWN, adapter->state);

	return 0;

register_netdev_fail:
	nbl_dev_free_net_irq(dev_mgt);
request_irq_fail:
	vsi->ops->stop(dev_mgt, vsi);
start_vsi_fail:
	vsi->ops->netdev_destroy(dev_mgt, vsi);
build_netdev_fail:
	serv_ops->remove_net_resource_mgt(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
setup_net_mgt_fail:
	serv_ops->remove_txrx_queues(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
set_queue_fail:
	serv_ops->free_rings(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
alloc_rings_fail:
	free_netdev(netdev);
alloc_netdev_fail:
	return ret;
}

static void nbl_dev_stop_net_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_event_callback callback = {0};
	struct nbl_dev_vsi *vsi;
	struct net_device *netdev;
	struct nbl_netdev_priv *net_priv;

	if (!net_dev)
		return;

	netdev = net_dev->netdev;
	net_priv = netdev_priv(netdev);

	vsi = net_dev->vsi_ctrl.vsi_list[NBL_VSI_DATA];
	if (!vsi)
		return;

	if (!common->is_vf) {
		callback.callback = nbl_dev_vsi_handle_switch_event;
		callback.callback_data = dev_mgt;
		nbl_event_unregister(NBL_EVENT_DEV_MODE_SWITCH, &callback,
				     NBL_COMMON_TO_ETH_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	}

	unregister_netdev(netdev);

	vsi->ops->netdev_destroy(dev_mgt, vsi);
	vsi->ops->stop(dev_mgt, vsi);

	nbl_dev_free_net_irq(dev_mgt);

	serv_ops->remove_net_resource_mgt(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	serv_ops->remove_txrx_queues(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
	serv_ops->free_rings(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));

	free_netdev(netdev);
}

static int nbl_dev_resume_net_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct net_device *netdev;
	int ret = 0;

	if (!net_dev)
		return 0;

	netdev = net_dev->netdev;

	ret = nbl_dev_request_net_irq(dev_mgt);
	if (ret)
		dev_err(dev, "request irq failed\n");

	netif_device_attach(netdev);
	return ret;
}

static void nbl_dev_suspend_net_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct net_device *netdev;

	if (!net_dev)
		return;

	netdev = net_dev->netdev;
	netif_device_detach(netdev);
	nbl_dev_free_net_irq(dev_mgt);
}

/* ----------  Devlink config  ---------- */
static void nbl_dev_devlink_free(void *devlink_ptr)
{
	devlink_free((struct devlink *)devlink_ptr);
}

static int nbl_dev_setup_devlink(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param)
{
	struct nbl_dev_common *common_dev = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct devlink *devlink;
	struct devlink_ops *devlink_ops;
	struct nbl_devlink_priv *priv;
	int ret = 0;

	if (param->caps.is_vf)
		return 0;

	devlink_ops = devm_kzalloc(dev, sizeof(*devlink_ops), GFP_KERNEL);
	if (!devlink_ops)
		return -ENOMEM;

	devlink_ops->info_get = serv_ops->get_devlink_info;

	if (param->caps.has_ctrl)
		devlink_ops->flash_update = serv_ops->update_devlink_flash;

	devlink = devlink_alloc(devlink_ops, sizeof(*priv), dev);

	if (!devlink)
		return -ENOMEM;

	common_dev->devlink_ops = devlink_ops;

	if (devm_add_action(dev, nbl_dev_devlink_free, devlink)) {
		devlink_free(devlink);
		return -EFAULT;
	}
	priv = devlink_priv(devlink);
	priv->priv = NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt);
	priv->dev_mgt = dev_mgt;

	devlink_register(devlink);

	common_dev->devlink = devlink;
	return ret;
}

static void nbl_dev_remove_devlink(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_common *common_dev = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);

	if (common_dev->devlink) {
		devlink_unregister(common_dev->devlink);
		devm_kfree(NBL_DEV_MGT_TO_DEV(dev_mgt), common_dev->devlink_ops);
	}
}

static int nbl_dev_start_common_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	int ret = 0;

	ret = nbl_dev_configure_msix_map(dev_mgt);
	if (ret)
		goto config_msix_map_err;

	ret = nbl_dev_init_interrupt_scheme(dev_mgt);
	if (ret)
		goto init_interrupt_scheme_err;

	ret = nbl_dev_request_mailbox_irq(dev_mgt);
	if (ret)
		goto mailbox_request_irq_err;

	ret = nbl_dev_enable_mailbox_irq(dev_mgt);
	if (ret)
		goto enable_mailbox_irq_err;

	ret = nbl_dev_setup_devlink(dev_mgt, param);
	if (ret)
		goto setup_devlink_err;

	if (!param->caps.is_vf &&
	    serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
	    NBL_HWMON_TEMP_CAP)) {
		ret = nbl_dev_setup_hwmon(adapter);
		if (ret)
			goto setup_hwmon_err;
	}

	if (nbl_dev_should_chan_keepalive(dev_mgt))
		nbl_dev_setup_chan_keepalive(dev_mgt, NBL_CHAN_TYPE_MAILBOX);

	return 0;

setup_hwmon_err:
	nbl_dev_remove_devlink(dev_mgt);
setup_devlink_err:
	nbl_dev_disable_mailbox_irq(dev_mgt);
enable_mailbox_irq_err:
	nbl_dev_free_mailbox_irq(dev_mgt);
mailbox_request_irq_err:
	nbl_dev_clear_interrupt_scheme(dev_mgt);
init_interrupt_scheme_err:
	nbl_dev_destroy_msix_map(dev_mgt);
config_msix_map_err:
	return ret;
}

void nbl_dev_stop_common_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);

	if (nbl_dev_should_chan_keepalive(dev_mgt))
		nbl_dev_remove_chan_keepalive(dev_mgt, NBL_CHAN_TYPE_MAILBOX);

	nbl_dev_remove_hwmon(adapter);
	nbl_dev_remove_devlink(dev_mgt);
	nbl_dev_free_mailbox_irq(dev_mgt);
	nbl_dev_disable_mailbox_irq(dev_mgt);
	nbl_dev_clear_interrupt_scheme(dev_mgt);
	nbl_dev_destroy_msix_map(dev_mgt);
}

static int nbl_dev_resume_common_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	int ret = 0;

	ret = nbl_dev_request_mailbox_irq(dev_mgt);
	if (ret)
		return ret;

	if (nbl_dev_should_chan_keepalive(dev_mgt))
		nbl_dev_setup_chan_keepalive(dev_mgt, NBL_CHAN_TYPE_MAILBOX);

	return 0;
}

void nbl_dev_suspend_common_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);

	if (nbl_dev_should_chan_keepalive(dev_mgt))
		nbl_dev_remove_chan_keepalive(dev_mgt, NBL_CHAN_TYPE_MAILBOX);

	nbl_dev_free_mailbox_irq(dev_mgt);
}

int nbl_dev_start(void *p, struct nbl_init_param *param)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	int ret = 0;

	ret = nbl_dev_start_common_dev(adapter, param);
	if (ret)
		goto start_common_dev_fail;

	if (param->caps.has_ctrl) {
		ret = nbl_dev_start_ctrl_dev(adapter, param);
		if (ret)
			goto start_ctrl_dev_fail;
	}

	ret = nbl_dev_start_net_dev(adapter, param);
	if (ret)
		goto start_net_dev_fail;

	if (param->caps.has_user)
		nbl_dev_start_user_dev(adapter);

	return 0;

start_net_dev_fail:
	nbl_dev_stop_ctrl_dev(adapter);
start_ctrl_dev_fail:
	nbl_dev_stop_common_dev(adapter);
start_common_dev_fail:
	return ret;
}

void nbl_dev_stop(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;

	nbl_dev_stop_user_dev(adapter);
	nbl_dev_stop_ctrl_dev(adapter);
	nbl_dev_stop_net_dev(adapter);
	nbl_dev_stop_common_dev(adapter);
}

int nbl_dev_resume(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_init_param *param = &adapter->init_param;
	int ret = 0;

	ret = nbl_dev_resume_common_dev(adapter, param);
	if (ret)
		goto start_common_dev_fail;

	if (param->caps.has_ctrl) {
		ret = nbl_dev_start_ctrl_dev(adapter, param);
		if (ret)
			goto start_ctrl_dev_fail;
	}

	ret = nbl_dev_resume_net_dev(adapter, param);
	if (ret)
		goto start_net_dev_fail;

	return 0;

start_net_dev_fail:
	nbl_dev_stop_ctrl_dev(adapter);
start_ctrl_dev_fail:
	nbl_dev_stop_common_dev(adapter);
start_common_dev_fail:
	return ret;
}

int nbl_dev_suspend(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;

	nbl_dev_stop_ctrl_dev(adapter);
	nbl_dev_suspend_net_dev(adapter);
	nbl_dev_suspend_common_dev(adapter);

	return 0;
}
