// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include <net/xfrm.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include "nbl_dev.h"

static int debug = -1;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "netif debug level (0=none,...,16=all), adapter debug_mask (<-1)");

static int net_msix_mask_en = 1;
module_param(net_msix_mask_en, int, 0);
MODULE_PARM_DESC(net_msix_mask_en, "net msix interrupt mask enable");

int performance_mode = 3;
module_param(performance_mode, int, 0);
MODULE_PARM_DESC(performance_mode, "performance_mode");

int restore_eth;
module_param(restore_eth, int, 0);
MODULE_PARM_DESC(restore_eth, "restore_eth");

static struct nbl_dev_board_id_table board_id_table;

struct nbl_dev_ops dev_ops;

static int nbl_dev_clean_mailbox_schedule(struct nbl_dev_mgt *dev_mgt);
static void nbl_dev_clean_adminq_schedule(struct nbl_task_info *task_info);
static void nbl_dev_remove_rep_res(struct nbl_dev_mgt *dev_mgt);
static void nbl_dev_handle_fatal_err(struct nbl_dev_mgt *dev_mgt);
static int nbl_dev_setup_st_dev(struct nbl_adapter *adapter, struct nbl_init_param *param);
static void nbl_dev_remove_st_dev(struct nbl_adapter *adapter);
static void nbl_dev_chan_notify_link_state_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len);
static void nbl_dev_chan_notify_reset_event_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len);
static void nbl_dev_chan_ack_reset_event_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len);
static int nbl_dev_setup_devlink_port(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev,
				      struct nbl_init_param *param);
static void nbl_dev_remove_devlink_port(struct nbl_dev_mgt *dev_mgt);
static int nbl_dev_setup_devlink(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param);
static void nbl_dev_remove_devlink(struct nbl_dev_mgt *dev_mgt);
static int nbl_dev_start_adminq(struct nbl_dev_mgt *dev_mgt);
static void nbl_dev_stop_adminq(struct nbl_dev_mgt *dev_mgt);
static void nbl_dev_stop_mailbox(struct nbl_dev_mgt *dev_mgt);
static void nbl_dev_resume_task(struct delayed_work *work);

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

static void nbl_dev_init_port(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	if (restore_eth)
		serv_ops->init_port(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}

static int nbl_dev_alloc_board_id(struct nbl_dev_board_id_table *index_table, u32 board_key)
{
	int i = 0;

	for (i = 0; i < NBL_DEV_BOARD_ID_MAX; i++) {
		if (index_table->entry[i].board_key == board_key) {
			index_table->entry[i].refcount++;
			return i;
		}
	}

	for (i = 0; i < NBL_DEV_BOARD_ID_MAX; i++) {
		if (!index_table->entry[i].valid) {
			index_table->entry[i].board_key = board_key;
			index_table->entry[i].refcount++;
			index_table->entry[i].valid = true;
			return i;
		}
	}

	return -ENOSPC;
}

static void nbl_dev_free_board_id(struct nbl_dev_board_id_table *index_table, u32 board_key)
{
	int i = 0;

	for (i = 0; i < NBL_DEV_BOARD_ID_MAX; i++) {
		if (index_table->entry[i].board_key == board_key && index_table->entry[i].valid) {
			index_table->entry[i].refcount--;
			break;
		}
	}

	if (i != NBL_DEV_BOARD_ID_MAX && !index_table->entry[i].refcount)
		memset(&index_table->entry[i], 0, sizeof(index_table->entry[i]));
}

static void nbl_dev_set_netdev_priv(struct net_device *netdev, struct nbl_dev_vsi *vsi,
				    struct nbl_dev_vsi *user_vsi)
{
	struct nbl_netdev_priv *net_priv = netdev_priv(netdev);

	net_priv->tx_queue_num = vsi->queue_num;
	net_priv->rx_queue_num = vsi->queue_num;
	net_priv->rep = NULL;
	net_priv->netdev = netdev;
	net_priv->data_vsi = vsi->vsi_id;
	if (user_vsi)
		net_priv->user_vsi = user_vsi->vsi_id;
	else
		net_priv->user_vsi = vsi->vsi_id;
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

static __maybe_unused void nbl_dev_notify_ipsec_hard_expire(void *priv, u16 src_id, u16 msg_id,
							    void *data, u32 data_len)
{
#if IS_ENABLED(CONFIG_XFRM_OFFLOAD)
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv;
	struct net *net = dev_net(NBL_DEV_MGT_TO_NET_DEV(dev_mgt)->netdev);
	struct nbl_sa_search_key *param;
	struct xfrm_state *x;

	param = (struct nbl_sa_search_key *)data;
	x = xfrm_state_lookup(net, param->mark, &param->daddr, param->spi,
			      IPPROTO_ESP, param->family);
	if (x) {
		x->km.state = XFRM_STATE_EXPIRED;
		hrtimer_start(&x->mtimer, 0, HRTIMER_MODE_REL_SOFT);
		xfrm_state_put(x);
	}
#endif
}

static void nbl_dev_handle_ipsec_event(struct work_struct *work)
{
#if IS_ENABLED(CONFIG_XFRM_OFFLOAD)
	struct nbl_task_info *task_info = container_of(work, struct nbl_task_info,
						       ipsec_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct nbl_service_ops *serv_ops;

	serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	serv_ops->handle_ipsec_event(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
#endif
}

static void nbl_dev_clean_ipsec_status(struct nbl_dev_mgt *dev_mgt)
{
#if IS_ENABLED(CONFIG_XFRM_OFFLOAD)
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_task_info *task_info = NBL_DEV_CTRL_TO_TASK_INFO(ctrl_dev);

	if (serv_ops->check_ipsec_status(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt)))
		nbl_common_queue_work(&task_info->ipsec_task, true);
#endif
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

	nbl_common_queue_work(&task_info->clean_abnormal_irq_task, true);
}

static irqreturn_t nbl_dev_clean_abnormal_event(int __always_unused irq, void *data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)data;
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	nbl_dev_rdma_process_abnormal_event(rdma_dev);

	if (serv_ops->get_product_flex_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					   NBL_SECURITY_IPSEC_CAP))
		nbl_dev_clean_ipsec_status(dev_mgt);

	nbl_dev_clean_abnormal_status(dev_mgt);

	return IRQ_HANDLED;
}

static irqreturn_t nbl_dev_process_sfp_plug_event(int __always_unused irq, void *data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)data;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_task_info *task_info = NBL_DEV_CTRL_TO_TASK_INFO(ctrl_dev);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_SFP_PLUG_CAP))
		nbl_common_queue_work(&task_info->sfp_plug_task, true);

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
	bool hw_support_auto_mask;
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	hw_support_auto_mask =
		serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					      NBL_MSIX_AUTO_MASK_CAP);
	hw_support_auto_mask &= net_msix_mask_en;

	msix_info->serv_info[NBL_MSIX_NET_TYPE].num = queue_num;
	msix_info->serv_info[NBL_MSIX_NET_TYPE].hw_self_mask_en = hw_support_auto_mask;
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
	msix_info->serv_info[NBL_MSIX_SFP_PLUG_TYPE].num = irq_num.sfp_plug_irq_num;
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
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;
	u32 irq_num;
	int err;

	if (!msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num)
		return 0;

	if (msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].enable)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].base_vector_id;
	irq_num = msix_info->msix_entries[local_vector_id].vector;

	snprintf(dev_common->mailbox_name, sizeof(dev_common->mailbox_name),
		 "nbl_mailbox@pci:%s", pci_name(NBL_COMMON_TO_PDEV(common)));
	err = devm_request_irq(dev, irq_num, nbl_dev_clean_mailbox,
			       0, dev_common->mailbox_name, dev_mgt);
	if (err) {
		dev_err(dev, "Request mailbox irq handler failed err: %d\n", err);
		return err;
	}

	msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].enable = true;

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

	if (!msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].enable)
		return;

	local_vector_id = msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].base_vector_id;
	irq_num = msix_info->msix_entries[local_vector_id].vector;

	devm_free_irq(dev, irq_num, dev_mgt);
	msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].enable = false;
}

static int nbl_dev_enable_mailbox_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	u16 local_vector_id;

	if (!msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].base_vector_id;
	chan_ops->set_queue_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_INTERRUPT_READY,
				  NBL_CHAN_TYPE_MAILBOX, true);

	return serv_ops->enable_mailbox_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    NBL_COMMON_TO_MGT_PF(common),
					    local_vector_id, true);
}

static int nbl_dev_disable_mailbox_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	u16 local_vector_id;

	if (!msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num)
		return 0;

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_CLEAN_MAILBOX_CAP))
		nbl_common_flush_task(&dev_common->clean_mbx_task);

	local_vector_id = msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].base_vector_id;
	chan_ops->set_queue_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_INTERRUPT_READY,
				  NBL_CHAN_TYPE_MAILBOX, false);

	return serv_ops->enable_mailbox_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    NBL_COMMON_TO_MGT_PF(common),
					    local_vector_id, false);
}

static int nbl_dev_request_adminq_irq(struct nbl_dev_mgt *dev_mgt, struct nbl_task_info *task_info)
{
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;
	u32 irq_num;
	char *irq_name;
	int err;

	if (!msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].num)
		return 0;

	if (msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].enable)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].base_vector_id;
	irq_num = msix_info->msix_entries[local_vector_id].vector;
	irq_name = msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].irq_name;

	snprintf(irq_name, NBL_STRING_NAME_LEN, "nbl_adminq@pci:%s",
		 pci_name(NBL_COMMON_TO_PDEV(common)));
	err = devm_request_irq(dev, irq_num, nbl_dev_clean_adminq,
			       0, irq_name, task_info);
	if (err) {
		dev_err(dev, "Request adminq irq handler failed err: %d\n", err);
		return err;
	}

	msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].enable = true;

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

	if (!msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].enable)
		return;

	local_vector_id = msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].base_vector_id;
	irq_num = msix_info->msix_entries[local_vector_id].vector;

	devm_free_irq(dev, irq_num, task_info);
	msix_info->serv_info[NBL_MSIX_ADMINDQ_TYPE].enable = false;
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
	chan_ops->set_queue_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_INTERRUPT_READY,
				  NBL_CHAN_TYPE_ADMINQ, true);

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
	chan_ops->set_queue_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_INTERRUPT_READY,
				  NBL_CHAN_TYPE_ADMINQ, false);

	return serv_ops->enable_adminq_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    local_vector_id, false);
}

static int nbl_dev_request_abnormal_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	char *irq_name;
	u32 irq_num;
	int err;
	u16 local_vector_id;

	if (!msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].base_vector_id;
	irq_num = msix_info->msix_entries[local_vector_id].vector;
	irq_name = msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].irq_name;

	snprintf(irq_name, NBL_STRING_NAME_LEN, "nbl_abnormal@pci:%s",
		 pci_name(NBL_COMMON_TO_PDEV(common)));
	err = devm_request_irq(dev, irq_num, nbl_dev_clean_abnormal_event,
			       0, irq_name, dev_mgt);
	if (err) {
		dev_err(dev, "Request abnormal_irq irq handler failed err: %d\n", err);
		return err;
	}

	return 0;
}

static void nbl_dev_free_abnormal_irq(struct nbl_dev_mgt *dev_mgt)
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
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	u16 local_vector_id;
	int err = 0;

	if (!msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].base_vector_id;
	err = serv_ops->enable_abnormal_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    NBL_COMMON_TO_MGT_PF(common),
					    local_vector_id, true);

	return err;
}

static int nbl_dev_disable_abnormal_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	u16 local_vector_id;
	int err = 0;

	if (!msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_ABNORMAL_TYPE].base_vector_id;
	err = serv_ops->enable_abnormal_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    NBL_COMMON_TO_MGT_PF(common),
					    local_vector_id, false);

	return err;
}

static int nbl_dev_request_sfp_plug_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	char *irq_name;
	u32 irq_num;
	int err;
	u16 local_vector_id;

	if (!msix_info->serv_info[NBL_MSIX_SFP_PLUG_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_SFP_PLUG_TYPE].base_vector_id;
	irq_num = msix_info->msix_entries[local_vector_id].vector;
	irq_name = msix_info->serv_info[NBL_MSIX_SFP_PLUG_TYPE].irq_name;

	snprintf(irq_name, NBL_STRING_NAME_LEN, "sfp_event_irq@pci:%s",
		 pci_name(NBL_COMMON_TO_PDEV(common)));
	err = devm_request_irq(dev, irq_num, nbl_dev_process_sfp_plug_event,
			       0, irq_name, dev_mgt);
	if (err) {
		dev_err(dev, "Request sfp plug event irq handler failed err: %d\n", err);
		return err;
	}

	return 0;
}

static void nbl_dev_free_sfp_plug_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;
	u32 irq_num;

	if (!msix_info->serv_info[NBL_MSIX_SFP_PLUG_TYPE].num)
		return;

	local_vector_id = msix_info->serv_info[NBL_MSIX_SFP_PLUG_TYPE].base_vector_id;
	irq_num = msix_info->msix_entries[local_vector_id].vector;

	devm_free_irq(dev, irq_num, dev_mgt);
}

static int nbl_dev_enable_sfp_plug_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;
	int err = 0;

	if (!msix_info->serv_info[NBL_MSIX_SFP_PLUG_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_SFP_PLUG_TYPE].base_vector_id;
	err = serv_ops->enable_sfp_plug_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    local_vector_id, true);

	return err;
}

static int nbl_dev_disable_sfp_plug_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 local_vector_id;
	int err = 0;

	if (!msix_info->serv_info[NBL_MSIX_SFP_PLUG_TYPE].num)
		return 0;

	local_vector_id = msix_info->serv_info[NBL_MSIX_SFP_PLUG_TYPE].base_vector_id;
	err = serv_ops->enable_sfp_plug_irq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    local_vector_id, false);

	return err;
}

static int nbl_dev_configure_msix_map(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
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
					   NBL_COMMON_TO_MGT_PF(common),
					   msix_info->serv_info[NBL_MSIX_NET_TYPE].num,
					   msix_not_net_num,
					   msix_info->serv_info[NBL_MSIX_NET_TYPE].hw_self_mask_en);

	return err;
}

static int nbl_dev_destroy_msix_map(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	int err = 0;

	err = serv_ops->destroy_msix_map(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					 NBL_COMMON_TO_MGT_PF(common));
	return err;
}

static int nbl_dev_alloc_msix_entries(struct nbl_dev_mgt *dev_mgt, u16 num_entries)
{
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	u16 i;

	msix_info->msix_entries = devm_kcalloc(NBL_DEV_MGT_TO_DEV(dev_mgt), num_entries,
					       sizeof(msix_info->msix_entries),
					       GFP_KERNEL);
	if (!msix_info->msix_entries)
		return -ENOMEM;

	for (i = 0; i < num_entries; i++)
		msix_info->msix_entries[i].entry = i;

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

static void nbl_fw_tracer_clean_saved_traces_array(struct nbl_health_reporters *reps)
{
	mutex_destroy(&reps->temp_st_arr.lock);
	mutex_destroy(&reps->reboot_st_arr.lock);
}

static void nbl_dev_destroy_health(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);

	if (!ctrl_dev)
		return;

	if (!IS_ERR_OR_NULL(ctrl_dev->health_reporters.fw_temp_reporter))
		devl_health_reporter_destroy(ctrl_dev->health_reporters.fw_temp_reporter);

	if (!IS_ERR_OR_NULL(ctrl_dev->health_reporters.fw_reboot_reporter))
		devl_health_reporter_destroy(ctrl_dev->health_reporters.fw_reboot_reporter);
	nbl_fw_tracer_clean_saved_traces_array(&ctrl_dev->health_reporters);
}

static void nbl_fw_temp_save_trace(struct nbl_health_reporters *reps, u8 temp,
				   u64 uptime)
{
	struct nbl_fw_temp_trace_data *trace_data;

	mutex_lock(&reps->temp_st_arr.lock);
	trace_data = &reps->temp_st_arr.trace_data[reps->temp_st_arr.saved_traces_index];
	trace_data->timestamp = uptime;
	trace_data->temp_num = temp;

	reps->temp_st_arr.saved_traces_index =
		(reps->temp_st_arr.saved_traces_index + 1) & (NBL_SAVED_TRACES_NUM - 1);
	mutex_unlock(&reps->temp_st_arr.lock);
}

static void nbl_fw_reboot_save_trace(struct nbl_health_reporters *reps)
{
	struct nbl_fw_reboot_trace_data *trace_data;
	struct timespec64 ts;
	struct tm tm;

	ktime_get_real_ts64(&ts);
	time64_to_tm(ts.tv_sec, 0, &tm);
	mutex_lock(&reps->reboot_st_arr.lock);
	trace_data = &reps->reboot_st_arr.trace_data[reps->reboot_st_arr.saved_traces_index];
	snprintf(trace_data->local_time, NBL_TIME_LEN, "%04ld-%02d-%02d  %02d:%02d:%02d UTC",
		 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
		 tm.tm_sec);
	snprintf(reps->reporter_ctx.reboot_report_time, NBL_TIME_LEN,
		 "%04ld-%02d-%02d  %02d:%02d:%02d",
		 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
		 tm.tm_sec);

	reps->reboot_st_arr.saved_traces_index =
		(reps->reboot_st_arr.saved_traces_index + 1) & (NBL_SAVED_TRACES_NUM - 1);
	mutex_unlock(&reps->reboot_st_arr.lock);
}

static void nbl_dev_health_report_temp_task(struct work_struct *work)
{
	struct nbl_fw_reporter_ctx fw_reporter_cxt;
	struct nbl_task_info *task_info = container_of(work, struct nbl_task_info,
						       report_temp_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_health_reporters *reps = &ctrl_dev->health_reporters;
	int err;

	fw_reporter_cxt.temp_num = reps->reporter_ctx.temp_num;
	if (!reps->fw_temp_reporter)
		return;

	err = devlink_health_report(reps->fw_temp_reporter, "nbl_fw_temp", &fw_reporter_cxt);
	if (err)
		dev_err(dev, "failed to report nbl_fw_temp health\n");
}

static void nbl_dev_health_report_reboot_task(struct work_struct *work)
{
	struct nbl_task_info *task_info = container_of(work, struct nbl_task_info,
						       report_reboot_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_health_reporters *reps = &ctrl_dev->health_reporters;
	int err;

	if (!reps->fw_reboot_reporter)
		return;
	err = devlink_health_report(reps->fw_reboot_reporter, "nbl_fw_reboot", &reps->reporter_ctx);
	if (err)
		dev_err(dev, "failed to report nbl_fw_reboot health\n");
}

/* ----------  Channel config  ---------- */
static int nbl_dev_setup_chan_qinfo(struct nbl_dev_mgt *dev_mgt, u8 chan_type)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	unsigned long *owned_pf_bitmap;
	u8 max_pf;
	u16 bdf = 0;
	int ret = 0;

	if (!chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), chan_type))
		return 0;

	ret = serv_ops->get_owned_pf_bitmap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    &owned_pf_bitmap, &max_pf, &bdf);
	if (ret) {
		dev_err(dev, "setup chan:%d, get_owned_pf_bitmap failed\n", chan_type);
		return ret;
	}

	ret = chan_ops->cfg_chan_qinfo_map_table(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
						 chan_type, owned_pf_bitmap, max_pf, bdf);
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
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);

	if (ctrl_dev)
		queue_work(ctrl_dev->ctrl_dev_wq1, &common_dev->clean_mbx_task);
	else
		nbl_common_queue_work(&common_dev->clean_mbx_task, false);

	return 0;
}

static void nbl_dev_prepare_eswitch_reset(struct nbl_dev_mgt *dev_mgt)
{
	nbl_dev_remove_rep_res(dev_mgt);
}

static void nbl_dev_prepare_reset_task(struct work_struct *work)
{
	int ret;
	enum nbl_core_reset_event event = NBL_CORE_FATAL_ERR_EVENT;
	struct nbl_reset_task_info *task_info = container_of(work, struct nbl_reset_task_info,
							     task);
	struct nbl_dev_common *common_dev = container_of(task_info, struct nbl_dev_common,
							 reset_task);
	struct nbl_dev_mgt *dev_mgt = common_dev->dev_mgt;
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_chan_send_info chan_send;

	nbl_event_notify(NBL_EVENT_RESET_EVENT, &event,
			 NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	serv_ops->netdev_stop(dev_mgt->net_dev->netdev);
	nbl_dev_prepare_eswitch_reset(dev_mgt);
	netif_device_detach(dev_mgt->net_dev->netdev); /* to avoid ethtool operation */

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_ACK_RESET_EVENT, NULL,
		      0, NULL, 0, 0);
	/* notify ctrl dev, finish reset event process */
	ret = chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
	chan_ops->set_queue_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_ABNORMAL,
				  NBL_CHAN_TYPE_MAILBOX, true);

	/* sleep to avoid send_msg is running */
	usleep_range(10, 20);

	/* ctrl dev must shutdown phy reg read/write after ctrl dev has notify emp shutdown dev */
	if (!NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt))
		serv_ops->set_hw_status(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_HW_FATAL_ERR);
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
	nbl_common_queue_work(&task_info->clean_adminq_task, true);
}

static void nbl_dev_fw_heartbeat_task(struct work_struct *work)
{
	struct nbl_task_info *task_info = container_of(work, struct nbl_task_info,
						       fw_hb_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_adapter *adapter = dev_mgt->adapter;

	if (task_info->fw_resetting)
		return;

	if (test_bit(NBL_PCI_ERR_RECOVERING, adapter->state))
		return;

	if (!serv_ops->check_fw_heartbeat(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt))) {
		dev_notice(NBL_COMMON_TO_DEV(common), "FW reset detected");
		task_info->fw_resetting = true;
		nbl_dev_stop_adminq(dev_mgt);
		nbl_common_queue_delayed_work(&task_info->fw_reset_task, MSEC_PER_SEC, true);
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
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);

	if (serv_ops->check_fw_reset(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt))) {
		dev_notice(NBL_COMMON_TO_DEV(common), "FW recovered");
		nbl_dev_start_adminq(dev_mgt);
		serv_ops->enable_driver(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
		if (NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt)) {
			nbl_dev_get_port_attributes(dev_mgt);
			nbl_dev_enable_port(dev_mgt, true);
		}

		task_info->fw_resetting = false;
		nbl_fw_reboot_save_trace(&ctrl_dev->health_reporters);
		nbl_common_queue_work(&task_info->report_reboot_task, true);
		return;
	}

	nbl_common_queue_delayed_work(delayed_work, MSEC_PER_SEC, true);
}

static void nbl_dev_offload_network_task(struct work_struct *work)
{
	struct nbl_task_info *task_info = container_of(work, struct nbl_task_info,
						       offload_network_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->check_offload_status(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}

static void nbl_dev_check_link_state(struct work_struct *work)
{
	struct nbl_task_info *task_info = container_of(work, struct nbl_task_info,
						       port_link_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct net_device *netdev = dev_mgt->net_dev->netdev;

	serv_ops->set_link_state(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), netdev);
}

static void nbl_dev_sfp_plug_task(struct work_struct *work)
{
	struct nbl_task_info *task_info = container_of(work, struct nbl_task_info,
						       sfp_plug_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->process_sfp_plug_event(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}

static void nbl_dev_adapt_desc_gother_task(struct work_struct *work)
{
	struct nbl_task_info *task_info = container_of(work, struct nbl_task_info,
						       adapt_desc_gother_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->adapt_desc_gother(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}

static void nbl_dev_ctrl_reset_task(struct work_struct *work)
{
	struct nbl_task_info *task_info = container_of(work, struct nbl_task_info,
						       reset_task);
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;

	nbl_dev_handle_fatal_err(dev_mgt);
}

static void nbl_dev_ctrl_task_schedule(struct nbl_task_info *task_info)
{
	struct nbl_dev_mgt *dev_mgt = task_info->dev_mgt;
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_OFFLOAD_NETWORK_CAP) && ctrl_dev)
		queue_work(ctrl_dev->ctrl_dev_wq1, &task_info->offload_network_task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_FW_HB_CAP))
		nbl_common_queue_work(&task_info->fw_hb_task, true);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_CHECK_PORT_LINK_CAP))
		nbl_common_queue_work(&task_info->port_link_task, true);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_ADAPT_DESC_GOTHER))
		nbl_common_queue_work(&task_info->adapt_desc_gother_task, true);
}

static void nbl_dev_ctrl_task_timer(struct timer_list *t)
{
	struct nbl_task_info *task_info = container_of(t, struct nbl_task_info, serv_timer);

	mod_timer(&task_info->serv_timer, round_jiffies(task_info->serv_timer_period + jiffies));
	nbl_dev_ctrl_task_schedule(task_info);
}

static void nbl_dev_ctrl_task_start(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_task_info *task_info = NBL_DEV_CTRL_TO_TASK_INFO(ctrl_dev);

	if (!task_info->timer_setup)
		return;

	if (task_info->timer_working)
		return;

	mod_timer(&task_info->serv_timer, round_jiffies(jiffies + task_info->serv_timer_period));
	task_info->timer_working = true;
}

static void nbl_dev_ctrl_task_stop(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_task_info *task_info = NBL_DEV_CTRL_TO_TASK_INFO(ctrl_dev);

	if (!task_info->timer_setup)
		return;

	if (!task_info->timer_working)
		return;

	timer_delete_sync(&task_info->serv_timer);
	task_info->timer_working = false;
}

static void nbl_dev_chan_notify_flr_resp(void *priv, u16 src_id, u16 msg_id,
					 void *data, u32 data_len)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	u16 func_id;
	u16 vfid;
	u16 vsi_id;

	vfid = *(u16 *)data;
	dev_dbg(dev, "recv flr, vfid: %d\n", vfid);
	func_id = vfid + NBL_MAX_PF;
	if (serv_ops->check_vf_is_active(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), func_id))
		serv_ops->process_flr(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vfid);
	vsi_id = serv_ops->covert_vfid_to_vsi_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vfid);
	if (vsi_id != U16_MAX)
		nbl_dev_rdma_process_flr_event(rdma_dev, vsi_id);
	if (serv_ops->check_vf_is_active(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), func_id + 1))
		serv_ops->process_qinfo_cfg(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vfid + 1);
}

static void nbl_dev_chan_keep_alive_resp(void *priv, u16 src_id, u16 msg_id,
					 void *data, u32 data_len)
{
	int status;
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv;
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_adapter *adapter = dev_mgt->adapter;
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_chan_send_info chan_send;

	if (src_id == NBL_COMMON_TO_MGT_PF(common))
		return;

	status = !test_bit(NBL_PCI_ERR_RECOVERING, adapter->state);
	NBL_CHAN_SEND(chan_send, src_id, NBL_CHAN_MSG_NOTIFY_RSM_STAT, &status,
		      sizeof(status), NULL, 0, 0);
	chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);

	dev_info(dev, "receive func: %d alive, my_resume_status: %d\n", src_id, status);
}

static void nbl_dev_chan_notify_rsm_stat_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv;
	struct nbl_dev_common *common_dev = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);

	common_dev->resume_task.my_ctrl_rsm_done = *(int *)data;
	dev_info(dev, "receive my ctrl func: %d status:%d\n", src_id,
		 common_dev->resume_task.my_ctrl_rsm_done);
	common_dev->resume_task.ctrl_ack_rsm_tmp = true;
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

static void nbl_dev_register_reset_event_chan_msg(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	if (!chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	chan_ops->register_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
			       NBL_CHAN_MSG_NOTIFY_RESET_EVENT,
			       nbl_dev_chan_notify_reset_event_resp, dev_mgt);
	chan_ops->register_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
			       NBL_CHAN_MSG_ACK_RESET_EVENT,
			       nbl_dev_chan_ack_reset_event_resp, dev_mgt);
}

static void nbl_dev_register_keep_alive_chan_msg(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	if (!chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	chan_ops->register_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
			       NBL_CHAN_MSG_KEEP_ALIVE,
			       nbl_dev_chan_keep_alive_resp, dev_mgt);
}

static void nbl_dev_register_notify_resume_status_chan_msg(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	if (!chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	chan_ops->register_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
			       NBL_CHAN_MSG_NOTIFY_RSM_STAT,
			       nbl_dev_chan_notify_rsm_stat_resp, dev_mgt);
}

static struct nbl_dev_temp_alarm_info temp_alarm_info[NBL_TEMP_STATUS_MAX] = {
	{LOGLEVEL_WARNING, "High temperature on sensors0 resumed.\n"},
	{LOGLEVEL_WARNING, "High temperature on sensors0 observed, security(WARNING).\n"},
	{LOGLEVEL_CRIT, "High temperature on sensors0 observed, security(CRITICAL).\n"},
	{LOGLEVEL_EMERG, "High temperature on sensors0 observed, security(EMERGENCY).\n"},
};

static void nbl_dev_handle_temp_ext(struct nbl_dev_mgt *dev_mgt, u8 *data, u16 data_len)
{
	u16 temp = (u16)*data;
	u64 uptime = 0;
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	enum nbl_dev_temp_status old_temp_status = ctrl_dev->temp_status;
	enum nbl_dev_temp_status new_temp_status = NBL_TEMP_STATUS_NORMAL;

	/* no resume if temp exceed NBL_TEMP_EMERG_THRESHOLD, even if the temp resume nomal.
	 * Because the hw has shutdown.
	 */
	if (old_temp_status == NBL_TEMP_STATUS_EMERG)
		return;

	/* if temp in (85-105) and not in normal_status, no resume to avoid alarm oscillate */
	if (temp > NBL_TEMP_NOMAL_THRESHOLD &&
	    temp < NBL_TEMP_WARNING_THRESHOLD &&
	    old_temp_status > NBL_TEMP_STATUS_NORMAL)
		return;

	if (temp >= NBL_TEMP_WARNING_THRESHOLD &&
	    temp < NBL_TEMP_CRIT_THRESHOLD)
		new_temp_status = NBL_TEMP_STATUS_WARNING;
	else if (temp >= NBL_TEMP_CRIT_THRESHOLD &&
		 temp < NBL_TEMP_EMERG_THRESHOLD)
		new_temp_status = NBL_TEMP_STATUS_CRIT;
	else if (temp >= NBL_TEMP_EMERG_THRESHOLD)
		new_temp_status = NBL_TEMP_STATUS_EMERG;

	if (new_temp_status == old_temp_status)
		return;

	ctrl_dev->temp_status = new_temp_status;

	/* temp fall only alarm when the alarm need to resume */
	if (new_temp_status < old_temp_status && new_temp_status != NBL_TEMP_STATUS_NORMAL)
		return;

	if (data_len > sizeof(u16))
		uptime = *(u64 *)(data + sizeof(u16));

	if (new_temp_status != NBL_TEMP_STATUS_NORMAL) {
		ctrl_dev->health_reporters.reporter_ctx.temp_num = temp;
		nbl_fw_temp_save_trace(&ctrl_dev->health_reporters, temp, uptime);
		nbl_common_queue_work(&ctrl_dev->task_info.report_temp_task, false);
	}
	nbl_log(common, temp_alarm_info[new_temp_status].logvel,
		"[%llu] %s", uptime, temp_alarm_info[new_temp_status].alarm_info);

	if (new_temp_status == NBL_TEMP_STATUS_EMERG) {
		ctrl_dev->task_info.reset_event = NBL_HW_FATAL_ERR_EVENT;
		nbl_common_queue_work(&ctrl_dev->task_info.reset_task, false);
	}
}

static int nbl_dev_chan_log_module_alarm_req(struct nbl_dev_mgt *dev_mgt,
					     struct nbl_chan_param_log_module_alarm *para)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_chan_send_info chan_send = {0};

	/* logic_eth_id = pf func id */
	NBL_CHAN_SEND(chan_send, para->logic_eth_id, NBL_CHAN_MSG_LOG_MODULE_ALARM,
		      para, sizeof(*para),
		      NULL, 0, 0);
	return chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
}

static struct nbl_dev_temp_alarm_info module_temp_alarm_info[NBL_TEMP_STATUS_MAX] = {
	{LOGLEVEL_WARNING, "High module temperature resumed."},
	{LOGLEVEL_WARNING, "High module temperature observed, security(WARNING)."},
};

static void nbl_dev_handle_module_temp_ext(struct nbl_dev_mgt *dev_mgt, u8 *data, u16 data_len)
{
	struct nbl_chan_param_log_module_alarm para = {0};
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	int copy_len;

	copy_len = data_len < sizeof(struct nbl_chan_param_log_module_alarm) ?
			data_len : sizeof(struct nbl_chan_param_log_module_alarm);
	memcpy(&para, data, copy_len);

	/* net port will send msg to corresponding pf to print */
	if (NBL_COMMON_TO_LOGIC_ETH_ID(common) == para.logic_eth_id)
		nbl_log(common, module_temp_alarm_info[para.status].logvel,
			"[%llu] %s temp %u threshold %u\n", para.up_time,
			module_temp_alarm_info[para.status].alarm_info,
			para.temp, para.temp_th);
	else
		nbl_dev_chan_log_module_alarm_req(dev_mgt, &para);
}

static const char *nbl_log_level_name(int level)
{
	switch (level) {
	case NBL_EMP_ALERT_LOG_FATAL:
		return "FATAL";
	case NBL_EMP_ALERT_LOG_ERROR:
		return "ERROR";
	case NBL_EMP_ALERT_LOG_WARNING:
		return "WARNING";
	case NBL_EMP_ALERT_LOG_INFO:
		return "INFO";
	default:
		return "UNKNOWN";
	}
}

static void nbl_dev_handle_emp_log_ext(struct nbl_dev_mgt *dev_mgt, u8 *data, u16 data_len)
{
	struct nbl_emp_alert_log_event *log_event = (struct nbl_emp_alert_log_event *)data;
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);

	nbl_log(common, LOGLEVEL_INFO, "[FW][%llu] <%s> %.*s", log_event->uptime,
		nbl_log_level_name(log_event->level), data_len - sizeof(u64) - sizeof(u8),
		log_event->data);
}

static void nbl_dev_chan_notify_evt_alert_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv;
	struct nbl_chan_param_emp_alert_event *alert_param =
						(struct nbl_chan_param_emp_alert_event *)data;

	switch (alert_param->type) {
	case NBL_EMP_EVENT_TEMP_ALERT:
		nbl_dev_handle_temp_ext(dev_mgt, alert_param->data, alert_param->len);
		return;
	case NBL_EMP_EVENT_MODULE_TEMP_ALERT:
		nbl_dev_handle_module_temp_ext(dev_mgt, alert_param->data, alert_param->len);
		return;
	case NBL_EMP_EVENT_LOG_ALERT:
		nbl_dev_handle_emp_log_ext(dev_mgt, alert_param->data, alert_param->len);
		return;
	default:
		return;
	}
}

static void nbl_dev_ctrl_register_emp_ext_alert_chan_msg(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	/* draco use mailbox communication with emp */
	if (!chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	chan_ops->register_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
			       NBL_CHAN_MSG_ADMINQ_EXT_ALERT,
			       nbl_dev_chan_notify_evt_alert_resp, dev_mgt);
}

static int nbl_dev_setup_ctrl_dev_task(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_task_info *task_info = NBL_DEV_CTRL_TO_TASK_INFO(ctrl_dev);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	task_info->dev_mgt = dev_mgt;

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_OFFLOAD_NETWORK_CAP)) {
		nbl_common_alloc_task(&task_info->offload_network_task,
				      nbl_dev_offload_network_task);
		task_info->timer_setup = true;
	}

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
					  NBL_TASK_IPSEC_AGE_CAP)) {
		nbl_common_alloc_task(&task_info->ipsec_task, nbl_dev_handle_ipsec_event);
		task_info->timer_setup = true;
	}

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_CHECK_PORT_LINK_CAP)) {
		nbl_common_alloc_task(&task_info->port_link_task, nbl_dev_check_link_state);
		task_info->timer_setup = true;
	}

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_SFP_PLUG_CAP)) {
		nbl_common_alloc_task(&task_info->sfp_plug_task, nbl_dev_sfp_plug_task);
		task_info->timer_setup = true;
	}

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_ADAPT_DESC_GOTHER)) {
		nbl_common_alloc_task(&task_info->adapt_desc_gother_task,
				      nbl_dev_adapt_desc_gother_task);
		task_info->timer_setup = true;
	}

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_HEALTH_REPORT_TEMP_CAP))
		nbl_common_alloc_task(&task_info->report_temp_task,
				      &nbl_dev_health_report_temp_task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_HEALTH_REPORT_REBOOT_CAP))
		nbl_common_alloc_task(&task_info->report_reboot_task,
				      &nbl_dev_health_report_reboot_task);
	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_RESET_CTRL_CAP))
		nbl_common_alloc_task(&task_info->reset_task, &nbl_dev_ctrl_reset_task);

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
					  NBL_TASK_OFFLOAD_NETWORK_CAP))
		nbl_common_release_task(&task_info->offload_network_task);

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
					  NBL_TASK_IPSEC_AGE_CAP))
		nbl_common_release_task(&task_info->ipsec_task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_CHECK_PORT_LINK_CAP))
		nbl_common_release_task(&task_info->port_link_task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_SFP_PLUG_CAP))
		nbl_common_release_task(&task_info->sfp_plug_task);
	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_ADAPT_DESC_GOTHER))
		nbl_common_release_task(&task_info->adapt_desc_gother_task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_RESET_CTRL_CAP))
		nbl_common_release_task(&task_info->reset_task);
	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_HEALTH_REPORT_TEMP_CAP))
		nbl_common_release_task(&task_info->report_temp_task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_HEALTH_REPORT_REBOOT_CAP))
		nbl_common_release_task(&task_info->report_reboot_task);
}

static int nbl_dev_update_template_config(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->update_template_config(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}

/* warn if firmware build date differs from driver release date by over 6 months */
static void nbl_dev_check_fw_build_date(struct device *dev, const char *fw_version)
{
	int fw_year, fw_mon, drv_year, drv_mon;

	/* fw_version format: "x.y.z build YYYYMMDD hash", skip check if not match */
	if (sscanf(fw_version, "%*d.%*d.%*d build %4d%2d", &fw_year, &fw_mon) != 2 ||
	    fw_year < 2020)
		return;

	/* driver release date, update it with each release */
	drv_year = 2026;
	drv_mon = 9;

	if (abs((fw_year * 12 + fw_mon) - (drv_year * 12 + drv_mon)) > 6)
		dev_info(dev, "There is a significant discrepancy between the firmware and driver versions; it is recommended to upgrade to the latest drivers and firmware.\n");
}

static int nbl_dev_get_firmware_version(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_ch_prm_get_firmware_version fw;
	int ret = 0;

	memset(&fw, 0, sizeof(fw));
	fw.sfid = NBL_COMMON_TO_MGT_PF(common);
	ret = serv_ops->get_firmware_version(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &fw);
	memcpy(common->firmware_version, fw.version, NBL_FRIMWARE_VERSION_LEN);
	if (!common->is_vf) {
		dev_info(dev, "get firmware version: %s\n", common->firmware_version);
		nbl_dev_check_fw_build_date(dev, common->firmware_version);
	}

	return ret;
}

/* ----------  Dev init process  ---------- */
static int nbl_dev_setup_common_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_common *common_dev;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_board_port_info board_info = { 0 };
	struct nbl_ch_prm_get_eth_id eth_id_param = {0};
	struct nbl_ch_prm_get_eth_id eth_id_resp = {0};
	u16 sfid;
	u8 my_pf = 0;
	int board_id;
	int ret;

	common_dev = devm_kzalloc(NBL_ADAPTER_TO_DEV(adapter),
				  sizeof(struct nbl_dev_common), GFP_KERNEL);
	if (!common_dev)
		return -ENOMEM;
	common_dev->dev_mgt = dev_mgt;

	common->msg_enable = netif_msg_init(debug, DEFAULT_MSG_ENABLE);
	if (nbl_dev_setup_chan_queue(dev_mgt, NBL_CHAN_TYPE_MAILBOX))
		goto setup_chan_fail;

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_CLEAN_MAILBOX_CAP))
		nbl_common_alloc_task(&common_dev->clean_mbx_task, nbl_dev_clean_mailbox_task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_RESET_CAP))
		nbl_common_alloc_task(&common_dev->reset_task.task, &nbl_dev_prepare_reset_task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_RESUME_CAP))
		nbl_common_alloc_delayed_task(&common_dev->resume_task.task, &nbl_dev_resume_task);

	if (param->caps.is_nic) {
		board_id = serv_ops->get_board_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
		if (board_id < 0)
			goto get_board_id_fail;
		NBL_COMMON_TO_BOARD_ID(common) = board_id;

		sfid = NBL_COMMON_TO_MGT_PF(common);
		serv_ops->get_my_pf(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &sfid, &my_pf);
		NBL_COMMON_TO_MY_PF(common) = my_pf;
	}

	NBL_COMMON_TO_VSI_ID(common) = serv_ops->get_vsi_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
							    NBL_COMMON_TO_MGT_PF(common),
							    NBL_VSI_DATA);

	eth_id_param.vsi_id = NBL_COMMON_TO_VSI_ID(common);
	serv_ops->get_eth_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &eth_id_param, &eth_id_resp);
	NBL_COMMON_TO_ETH_MODE(common) = eth_id_resp.eth_mode;
	NBL_COMMON_TO_ETH_ID(common) = eth_id_resp.eth_id;
	NBL_COMMON_TO_LOGIC_ETH_ID(common) = eth_id_resp.logic_eth_id;

	serv_ops->get_board_info(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &board_info);

	NBL_COMMON_TO_ETH_MAX_SPEED(common) = nbl_port_speed_to_speed(board_info.eth_speed);
	common->port_type = board_info.port_type;
	nbl_dev_register_chan_task(dev_mgt, NBL_CHAN_TYPE_MAILBOX, &common_dev->clean_mbx_task);
	NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt) = common_dev;
	nbl_dev_register_common_irq(dev_mgt);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_HWMON_TEMP_CAP)) {
		ret = nbl_dev_setup_hwmon(adapter);
		if (ret)
			goto setup_hwmon_err;
	}

	return 0;

setup_hwmon_err:
get_board_id_fail:
	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_RESUME_CAP))
		nbl_common_release_delayed_task(&common_dev->resume_task.task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_RESET_CAP))
		nbl_common_release_task(&common_dev->reset_task.task);

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

	nbl_dev_remove_hwmon(adapter);
	nbl_dev_register_chan_task(dev_mgt, NBL_CHAN_TYPE_MAILBOX, NULL);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_RESUME_CAP))
		nbl_common_release_delayed_task(&common_dev->resume_task.task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_RESET_CAP))
		nbl_common_release_task(&common_dev->reset_task.task);

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_CLEAN_MAILBOX_CAP))
		nbl_common_release_task(&common_dev->clean_mbx_task);

	nbl_dev_remove_chan_queue(dev_mgt, NBL_CHAN_TYPE_MAILBOX);

	devm_kfree(NBL_ADAPTER_TO_DEV(adapter), common_dev);
	NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt) = NULL;
}

static void nbl_devlink_fmsg_fill_temp_trace(struct devlink_fmsg *fmsg,
					     struct nbl_fw_temp_trace_data *trace_data)
{
	devlink_fmsg_obj_nest_start(fmsg);
	devlink_fmsg_u64_pair_put(fmsg, "timestamp", trace_data->timestamp);
	devlink_fmsg_u8_pair_put(fmsg, "high temperature", trace_data->temp_num);
	devlink_fmsg_obj_nest_end(fmsg);
}

static int nbl_fw_temp_trace_get_entry(struct nbl_dev_ctrl *ctrl_dev, struct devlink_fmsg *fmsg)
{
	struct nbl_health_reporters *reps = &ctrl_dev->health_reporters;
	struct nbl_fw_temp_trace_data *trace_data = reps->temp_st_arr.trace_data;
	u8 index, start_index, end_index;
	u8 saved_traces_index;

	if (!trace_data[0].timestamp)
		return -ENOMSG;

	mutex_lock(&reps->temp_st_arr.lock);
	saved_traces_index = reps->temp_st_arr.saved_traces_index;
	if (trace_data[saved_traces_index].timestamp)
		start_index = saved_traces_index;
	else
		start_index = 0;
	devlink_fmsg_arr_pair_nest_start(fmsg, "dump nbl fw traces");
	end_index = (saved_traces_index - 1) & (NBL_SAVED_TRACES_NUM - 1);
	index = start_index;
	for (; index != end_index; ) {
		nbl_devlink_fmsg_fill_temp_trace(fmsg, &trace_data[index]);
		index = (index + 1) & (NBL_SAVED_TRACES_NUM - 1);
	}
	nbl_devlink_fmsg_fill_temp_trace(fmsg, &trace_data[index]);
	devlink_fmsg_arr_pair_nest_end(fmsg);
	mutex_unlock(&reps->temp_st_arr.lock);

	return 0;
}

static int nbl_fw_temp_reporter_diagnose(struct devlink_health_reporter *reporter,
					 struct devlink_fmsg *fmsg,
					 struct netlink_ext_ack *extack)
{
	struct nbl_dev_mgt *dev_mgt = devlink_health_reporter_priv(reporter);
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);

	return nbl_fw_temp_trace_get_entry(ctrl_dev, fmsg);
}

static int nbl_fw_temp_reporter_dump(struct devlink_health_reporter *reporter,
				     struct devlink_fmsg *fmsg, void *priv_ctx,
				     struct netlink_ext_ack *extack)
{
	if (priv_ctx) {
		struct nbl_fw_reporter_ctx *fw_reporter_ctx =
			(struct nbl_fw_reporter_ctx *)priv_ctx;
		devlink_fmsg_obj_nest_start(fmsg);
		devlink_fmsg_u32_pair_put(fmsg, "high temperature", fw_reporter_ctx->temp_num);
		devlink_fmsg_obj_nest_end(fmsg);
	}
	return 0;
}

static void nbl_fw_tracer_init_saved_traces_array(struct nbl_health_reporters *reps)
{
	reps->temp_st_arr.saved_traces_index = 0;
	reps->reboot_st_arr.saved_traces_index = 0;
	mutex_init(&reps->temp_st_arr.lock);
	mutex_init(&reps->reboot_st_arr.lock);
}

static struct devlink_health_reporter_ops nbl_fw_temp_reporter_ops = {
	.name = "nbl_fw_temp",
	.diagnose = nbl_fw_temp_reporter_diagnose,
	.dump = nbl_fw_temp_reporter_dump,
};

static void nbl_devlink_fmsg_fill_reboot_trace(struct devlink_fmsg *fmsg,
					       struct nbl_fw_reboot_trace_data *trace_data)
{
	devlink_fmsg_obj_nest_start(fmsg);
	devlink_fmsg_string_pair_put(fmsg, "reboot time", trace_data->local_time);
	devlink_fmsg_obj_nest_end(fmsg);
}

static int nbl_fw_reboot_trace_get_entry(struct nbl_dev_ctrl *ctrl_dev, struct devlink_fmsg *fmsg)
{
	struct nbl_health_reporters *reps = &ctrl_dev->health_reporters;
	struct nbl_fw_reboot_trace_data *trace_data = reps->reboot_st_arr.trace_data;
	u8 index, start_index, end_index;
	u8 saved_traces_index;

	if (!trace_data[0].local_time[0])
		return -ENOMSG;

	mutex_lock(&reps->reboot_st_arr.lock);
	saved_traces_index = reps->reboot_st_arr.saved_traces_index;
	if (trace_data[saved_traces_index].local_time[0])
		start_index = saved_traces_index;
	else
		start_index = 0;
	devlink_fmsg_arr_pair_nest_start(fmsg, "dump nbl fw traces");
	end_index = (saved_traces_index - 1) & (NBL_SAVED_TRACES_NUM - 1);
	index = start_index;
	for (; index != end_index; ) {
		nbl_devlink_fmsg_fill_reboot_trace(fmsg, &trace_data[index]);
		index = (index + 1) & (NBL_SAVED_TRACES_NUM - 1);
	}
	nbl_devlink_fmsg_fill_reboot_trace(fmsg, &trace_data[index]);
	devlink_fmsg_arr_pair_nest_end(fmsg);
	mutex_unlock(&reps->reboot_st_arr.lock);

	return 0;
}

static int nbl_fw_reboot_reporter_diagnose(struct devlink_health_reporter *reporter,
					   struct devlink_fmsg *fmsg,
					   struct netlink_ext_ack *extack)
{
	struct nbl_dev_mgt *dev_mgt = devlink_health_reporter_priv(reporter);
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);

	return nbl_fw_reboot_trace_get_entry(ctrl_dev, fmsg);
}

static int nbl_fw_reboot_reporter_dump(struct devlink_health_reporter *reporter,
				       struct devlink_fmsg *fmsg, void *priv_ctx,
				       struct netlink_ext_ack *extack)
{
	if (priv_ctx) {
		struct nbl_fw_reporter_ctx *fw_reporter_ctx =
			(struct nbl_fw_reporter_ctx *)priv_ctx;
		devlink_fmsg_obj_nest_start(fmsg);
		devlink_fmsg_string_pair_put(fmsg, "reboot time",
					     fw_reporter_ctx->reboot_report_time);
		devlink_fmsg_obj_nest_end(fmsg);
	}
	return 0;
}

static struct devlink_health_reporter_ops nbl_fw_reboot_reporter_ops = {
	.name = "nbl_fw_reboot",
	.diagnose = nbl_fw_reboot_reporter_diagnose,
	.dump = nbl_fw_reboot_reporter_dump,
};

static void nbl_setup_devlink_reporter(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_health_reporters *reps = &ctrl_dev->health_reporters;
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct devlink *devlink = dev_common->devlink;
	struct devlink_health_reporter_ops *fw_reboot_ops;
	struct devlink_health_reporter_ops *fw_temp_ops;
	const u64 graceful_period = 0;

	if (!devlink)
		return;

	fw_temp_ops = &nbl_fw_temp_reporter_ops;
	fw_reboot_ops = &nbl_fw_reboot_reporter_ops;

	nbl_fw_tracer_init_saved_traces_array(&ctrl_dev->health_reporters);

	reps->fw_temp_reporter =
		devl_health_reporter_create(devlink, fw_temp_ops, graceful_period, dev_mgt);
	if (IS_ERR(reps->fw_temp_reporter)) {
		dev_err(dev, "failed to create fw temp reporter err = %ld\n",
			PTR_ERR(reps->fw_temp_reporter));
		return;
	}

	reps->fw_reboot_reporter =
		devl_health_reporter_create(devlink, fw_reboot_ops, graceful_period, dev_mgt);
	if (IS_ERR(reps->fw_reboot_reporter)) {
		dev_err(dev, "failed to create fw reboot reporter err = %ld\n",
			PTR_ERR(reps->fw_reboot_reporter));
		if (reps->fw_temp_reporter)
			devl_health_reporter_destroy(reps->fw_temp_reporter);
		return;
	}
}

static int nbl_dev_init_health(struct nbl_dev_mgt *dev_mgt)
{
	if (!NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt))
		return 0;

	nbl_setup_devlink_reporter(dev_mgt);
	return 0;
}

static int nbl_dev_setup_ctrl_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_ctrl *ctrl_dev;
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	int i, ret = 0;
	u32 board_key;
	char part_number[50] = "";
	char serial_number[128] = "";

	board_key = pci_domain_nr(dev_mgt->common->pdev->bus) << 16 |
				  dev_mgt->common->pdev->bus->number;
	if (param->caps.is_nic) {
		NBL_COMMON_TO_BOARD_ID(common) =
			nbl_dev_alloc_board_id(&board_id_table, board_key);
		if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
						  NBL_DEVSHR_IDX_CAP)) {
			ret = nbl_devshr_register_idx_pool(NBL_COMMON_TO_BOARD_ID(common));
			if (ret)
				goto register_idx_pool_failed;
		}
	}

	ctrl_dev = devm_kzalloc(dev, sizeof(struct nbl_dev_ctrl), GFP_KERNEL);
	if (!ctrl_dev)
		goto alloc_fail;
	NBL_DEV_CTRL_TO_TASK_INFO(ctrl_dev)->adapter = adapter;
	NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt) = ctrl_dev;

	nbl_dev_register_ctrl_irq(dev_mgt);

	ctrl_dev->ctrl_dev_wq1 = create_singlethread_workqueue("nbl_ctrldev_wq1");
	if (!ctrl_dev->ctrl_dev_wq1) {
		dev_err(dev, "Failed to create workqueue nbl_ctrldev_wq1\n");
		goto alloc_wq_fail;
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

	if (param->caps.is_nic) {
		serv_ops->get_part_number(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), part_number);
		serv_ops->get_serial_number(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), serial_number);
		dev_info(dev, "part number: %s, serial number: %s\n", part_number, serial_number);
	}

	nbl_dev_update_template_config(dev_mgt);

	serv_ops->cfg_eth_bond_event(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), true);
	serv_ops->cfg_fd_update_event(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), true);
	serv_ops->cfg_mirror_outputport_event(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), true);

	/* register emp ext message handle last, to avoid health null and task no alloc */
	nbl_dev_ctrl_register_emp_ext_alert_chan_msg(dev_mgt);
	nbl_dev_ctrl_register_flr_chan_msg(dev_mgt);

	return 0;

setup_ctrl_dev_task_fail:
	nbl_dev_remove_chan_queue(dev_mgt, NBL_CHAN_TYPE_ADMINQ);
setup_chan_q_fail:
	destroy_workqueue(ctrl_dev->ctrl_dev_wq1);
alloc_wq_fail:
	devm_kfree(dev, ctrl_dev);
	NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt) = NULL;
alloc_fail:
	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_DEVSHR_IDX_CAP))
		nbl_devshr_unregister_idx_pool(NBL_COMMON_TO_BOARD_ID(common));
register_idx_pool_failed:
	nbl_dev_free_board_id(&board_id_table, board_key);
	return ret;
}

static void nbl_dev_remove_ctrl_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_ctrl **ctrl_dev = &NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	u32 board_key;

	if (!*ctrl_dev)
		return;

	serv_ops->cfg_fd_update_event(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), false);
	serv_ops->cfg_eth_bond_event(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), false);
	serv_ops->cfg_mirror_outputport_event(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), false);

	nbl_dev_remove_chan_queue(dev_mgt, NBL_CHAN_TYPE_ADMINQ);
	nbl_dev_remove_ctrl_dev_task(dev_mgt);
	destroy_workqueue((*ctrl_dev)->ctrl_dev_wq1);
	devm_kfree(NBL_ADAPTER_TO_DEV(adapter), *ctrl_dev);
	*ctrl_dev = NULL;

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_DEVSHR_IDX_CAP))
		nbl_devshr_unregister_idx_pool(NBL_COMMON_TO_BOARD_ID(common));

	/* If it is not nic, this free function will do nothing, so no need check */
	board_key = pci_domain_nr(dev_mgt->common->pdev->bus) << 16 |
				  dev_mgt->common->pdev->bus->number;
	nbl_dev_free_board_id(&board_id_table, board_key);
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

static void nbl_dev_netdev_get_stats64(struct net_device *netdev,
				       struct rtnl_link_stats64 *stats)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_stats64(netdev, stats);
}

static void nbl_dev_netdev_set_rx_mode(struct net_device *dev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->set_rx_mode(dev);
}

static void nbl_dev_netdev_change_rx_flags(struct net_device *dev, int flag)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->change_rx_flags(dev, flag);
}

static int nbl_dev_netdev_set_mac(struct net_device *dev, void *p)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_mac(dev, p);
}

static int nbl_dev_netdev_rx_add_vid(struct net_device *dev, __be16 proto,
				     u16 vid)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->rx_add_vid(dev, proto, vid);
}

static int nbl_dev_netdev_rx_kill_vid(struct net_device *dev, __be16 proto,
				      u16 vid)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->rx_kill_vid(dev, proto, vid);
}

static int nbl_dev_netdev_set_features(struct net_device *dev,
				       netdev_features_t features)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_features(dev, features);
}

static void nbl_dev_netdev_tx_timeout(struct net_device *netdev, u32 txqueue)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->tx_timeout(netdev, txqueue);
}

static int nbl_dev_netdev_bridge_getlink(struct sk_buff *skb, u32 pid, u32 seq,
					 struct net_device *dev,
					 u32 filter_mask, int nlflags)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->bridge_getlink(skb, pid, seq, dev, filter_mask,
					nlflags);
}

static int nbl_dev_netdev_bridge_setlink(struct net_device *netdev,
					 struct nlmsghdr *nlh, u16 flags,
					 struct netlink_ext_ack *extack)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->bridge_setlink(netdev, nlh, flags, extack);
}

static int nbl_dev_netdev_set_vf_spoofchk(struct net_device *netdev, int vf_id,
					  bool ena)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_vf_spoofchk(netdev, vf_id, ena);
}

static int nbl_dev_netdev_set_vf_link_state(struct net_device *dev, int vf_id,
					    int link_state)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_vf_link_state(dev, vf_id, link_state);
}

static int nbl_dev_netdev_set_vf_mac(struct net_device *netdev, int vf_id,
				     u8 *mac)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_vf_mac(netdev, vf_id, mac);
}

static int nbl_dev_netdev_set_vf_rate(struct net_device *netdev, int vf_id,
				      int min_rate, int max_rate)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_vf_rate(netdev, vf_id, min_rate, max_rate);
}

static int nbl_dev_netdev_get_vf_config(struct net_device *dev, int vf_id,
					struct ifla_vf_info *ivi)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_vf_config(dev, vf_id, ivi);
}

static int nbl_dev_netdev_get_vf_stats(struct net_device *dev, int vf_id,
				       struct ifla_vf_stats *vf_stats)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_vf_stats(dev, vf_id, vf_stats);
}

static u16 nbl_dev_netdev_select_queue(struct net_device *netdev,
				       struct sk_buff *skb,
				       struct net_device *sb_dev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->select_queue(netdev, skb, sb_dev);
}

static int nbl_dev_netdev_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->change_mtu(netdev, new_mtu);
}

static int nbl_dev_netdev_setup_tc(struct net_device *dev,
				   enum tc_setup_type type, void *type_data)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->setup_tc(dev, type, type_data);
}

static int nbl_dev_netdev_set_vf_vlan(struct net_device *dev, int vf_id,
				      u16 vlan, u8 pri, __be16 proto)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_vf_vlan(dev, vf_id, vlan, pri, proto);
}

static int nbl_dev_netdev_set_vf_trust(struct net_device *netdev, int vf_id,
				       bool trusted)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_vf_trust(netdev, vf_id, trusted);
}

static int nbl_dev_set_xdp(struct net_device *netdev, struct netdev_bpf *xdp)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_xdp(netdev, xdp);
}

static int nbl_dev_ndo_get_phys_port_name(struct net_device *dev, char *name,
					  size_t len)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_phys_port_name(dev, name, len);
}

static int nbl_dev_ndo_get_port_parent_id(struct net_device *dev,
					  struct netdev_phys_item_id *ppid)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_port_parent_id(dev, ppid);
}

static int nbl_dev_rep_netdev_open(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->rep_netdev_open(netdev);
}

static int nbl_dev_rep_netdev_stop(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->rep_netdev_stop(netdev);
}

static netdev_tx_t nbl_dev_rep_start_xmit(struct sk_buff *skb,
					  struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->rep_start_xmit(skb, netdev);
}

static void nbl_dev_netdev_rep_get_stats64(struct net_device *netdev,
					   struct rtnl_link_stats64 *stats)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->rep_get_stats64(netdev, stats);
}

static void nbl_dev_netdev_rep_set_rx_mode(struct net_device *dev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->rep_set_rx_mode(dev);
}

static int nbl_dev_netdev_rep_set_mac(struct net_device *dev, void *p)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->rep_set_mac(dev, p);
}

static int nbl_dev_netdev_rep_rx_add_vid(struct net_device *dev, __be16 proto,
					 u16 vid)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->rep_rx_add_vid(dev, proto, vid);
}

static int nbl_dev_netdev_rep_rx_kill_vid(struct net_device *dev, __be16 proto,
					  u16 vid)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->rep_rx_kill_vid(dev, proto, vid);
}

static int nbl_dev_netdev_rep_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->change_rep_mtu(netdev, new_mtu);
}

static int nbl_dev_netdev_rep_setup_tc(struct net_device *dev,
				       enum tc_setup_type type, void *type_data)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->rep_setup_tc(dev, type, type_data);
}

static int nbl_dev_rep_get_phys_port_name(struct net_device *dev, char *name,
					  size_t len)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->rep_get_phys_port_name(dev, name, len);
}

static int nbl_dev_rep_get_port_parent_id(struct net_device *dev,
					  struct netdev_phys_item_id *ppid)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->rep_get_port_parent_id(dev, ppid);
}

static netdev_tx_t nbl_dev_start_xmit(struct sk_buff *skb,
				      struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_resource_pt_ops *pt_ops = NBL_DEV_MGT_TO_RES_PT_OPS(dev_mgt);

	return pt_ops->start_xmit(skb, netdev);
}

static netdev_tx_t nbl_dev_start_xmit_draco(struct sk_buff *skb,
					    struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_resource_pt_ops *pt_ops = NBL_DEV_MGT_TO_RES_PT_OPS(dev_mgt);

	return pt_ops->start_xmit_draco(skb, netdev);
}

static netdev_features_t nbl_dev_features_check(struct sk_buff *skb,
						struct net_device *dev,
						netdev_features_t features)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_resource_pt_ops *pt_ops = NBL_DEV_MGT_TO_RES_PT_OPS(dev_mgt);

	return pt_ops->features_check(skb, dev, features);
}

static int nbl_dev_xdp_xmit(struct net_device *netdev, int n,
			    struct xdp_frame **frame, u32 flags)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_resource_pt_ops *pt_ops = NBL_DEV_MGT_TO_RES_PT_OPS(dev_mgt);

	return pt_ops->xdp_xmit(netdev, n, frame, flags);
}

static const struct net_device_ops netdev_ops_leonis_rep = {
	.ndo_open = nbl_dev_rep_netdev_open,
	.ndo_stop = nbl_dev_rep_netdev_stop,
	.ndo_start_xmit = nbl_dev_rep_start_xmit,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_get_stats64 = nbl_dev_netdev_rep_get_stats64,
	.ndo_set_rx_mode = nbl_dev_netdev_rep_set_rx_mode,
	.ndo_set_mac_address = nbl_dev_netdev_rep_set_mac,
	.ndo_vlan_rx_add_vid = nbl_dev_netdev_rep_rx_add_vid,
	.ndo_vlan_rx_kill_vid = nbl_dev_netdev_rep_rx_kill_vid,
	.ndo_features_check = nbl_dev_features_check,
	.ndo_setup_tc = nbl_dev_netdev_rep_setup_tc,
	.ndo_change_mtu = nbl_dev_netdev_rep_change_mtu,
	.ndo_get_phys_port_name = nbl_dev_rep_get_phys_port_name,
	.ndo_get_port_parent_id = nbl_dev_rep_get_port_parent_id,
};

static const struct net_device_ops netdev_ops_leonis_pf = {
	.ndo_open = nbl_dev_netdev_open,
	.ndo_stop = nbl_dev_netdev_stop,
	.ndo_start_xmit = nbl_dev_start_xmit,
	.ndo_xdp_xmit = nbl_dev_xdp_xmit,
	.ndo_bpf = nbl_dev_set_xdp,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_get_stats64 = nbl_dev_netdev_get_stats64,
	.ndo_set_rx_mode = nbl_dev_netdev_set_rx_mode,
	.ndo_change_rx_flags = nbl_dev_netdev_change_rx_flags,
	.ndo_set_mac_address = nbl_dev_netdev_set_mac,
	.ndo_vlan_rx_add_vid = nbl_dev_netdev_rx_add_vid,
	.ndo_vlan_rx_kill_vid = nbl_dev_netdev_rx_kill_vid,
	.ndo_set_features = nbl_dev_netdev_set_features,
	.ndo_features_check = nbl_dev_features_check,
	.ndo_set_vf_spoofchk = nbl_dev_netdev_set_vf_spoofchk,
	.ndo_tx_timeout = nbl_dev_netdev_tx_timeout,
	.ndo_bridge_getlink = nbl_dev_netdev_bridge_getlink,
	.ndo_bridge_setlink = nbl_dev_netdev_bridge_setlink,
	.ndo_set_vf_link_state = nbl_dev_netdev_set_vf_link_state,
	.ndo_set_vf_mac = nbl_dev_netdev_set_vf_mac,
	.ndo_set_vf_rate = nbl_dev_netdev_set_vf_rate,
	.ndo_get_vf_config = nbl_dev_netdev_get_vf_config,
	.ndo_get_vf_stats = nbl_dev_netdev_get_vf_stats,
	.ndo_select_queue = nbl_dev_netdev_select_queue,
	.ndo_set_vf_vlan = nbl_dev_netdev_set_vf_vlan,
	.ndo_set_vf_trust = nbl_dev_netdev_set_vf_trust,
	.ndo_setup_tc = nbl_dev_netdev_setup_tc,
	.ndo_change_mtu = nbl_dev_netdev_change_mtu,
	.ndo_get_phys_port_name = nbl_dev_ndo_get_phys_port_name,
	.ndo_get_port_parent_id = nbl_dev_ndo_get_port_parent_id,
};

static const struct net_device_ops netdev_ops_leonis_vf = {
	.ndo_open = nbl_dev_netdev_open,
	.ndo_stop = nbl_dev_netdev_stop,
	.ndo_start_xmit = nbl_dev_start_xmit,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_get_stats64 = nbl_dev_netdev_get_stats64,
	.ndo_set_rx_mode = nbl_dev_netdev_set_rx_mode,
	.ndo_set_mac_address = nbl_dev_netdev_set_mac,
	.ndo_vlan_rx_add_vid = nbl_dev_netdev_rx_add_vid,
	.ndo_vlan_rx_kill_vid = nbl_dev_netdev_rx_kill_vid,
	.ndo_set_features = nbl_dev_netdev_set_features,
	.ndo_features_check = nbl_dev_features_check,
	.ndo_tx_timeout = nbl_dev_netdev_tx_timeout,
	.ndo_setup_tc = nbl_dev_netdev_setup_tc,
	.ndo_change_mtu = nbl_dev_netdev_change_mtu,
	.ndo_get_phys_port_name = nbl_dev_ndo_get_phys_port_name,
};

static const struct net_device_ops netdev_ops_draco_rep = {
	.ndo_open = nbl_dev_rep_netdev_open,
	.ndo_stop = nbl_dev_rep_netdev_stop,
	.ndo_start_xmit = nbl_dev_rep_start_xmit,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_get_stats64 = nbl_dev_netdev_rep_get_stats64,
	.ndo_set_rx_mode = nbl_dev_netdev_rep_set_rx_mode,
	.ndo_set_mac_address = nbl_dev_netdev_rep_set_mac,
	.ndo_vlan_rx_add_vid = nbl_dev_netdev_rep_rx_add_vid,
	.ndo_vlan_rx_kill_vid = nbl_dev_netdev_rep_rx_kill_vid,
	.ndo_features_check = nbl_dev_features_check,
	.ndo_setup_tc = nbl_dev_netdev_rep_setup_tc,
	.ndo_change_mtu = nbl_dev_netdev_rep_change_mtu,
	.ndo_get_phys_port_name = nbl_dev_rep_get_phys_port_name,
	.ndo_get_port_parent_id = nbl_dev_rep_get_port_parent_id,
};

static const struct net_device_ops netdev_ops_draco_pf = {
	.ndo_open = nbl_dev_netdev_open,
	.ndo_stop = nbl_dev_netdev_stop,
	.ndo_start_xmit = nbl_dev_start_xmit_draco,
	.ndo_xdp_xmit = nbl_dev_xdp_xmit,
	.ndo_bpf = nbl_dev_set_xdp,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_get_stats64 = nbl_dev_netdev_get_stats64,
	.ndo_set_rx_mode = nbl_dev_netdev_set_rx_mode,
	.ndo_change_rx_flags = nbl_dev_netdev_change_rx_flags,
	.ndo_set_mac_address = nbl_dev_netdev_set_mac,
	.ndo_vlan_rx_add_vid = nbl_dev_netdev_rx_add_vid,
	.ndo_vlan_rx_kill_vid = nbl_dev_netdev_rx_kill_vid,
	.ndo_set_features = nbl_dev_netdev_set_features,
	.ndo_features_check = nbl_dev_features_check,
	.ndo_set_vf_spoofchk = nbl_dev_netdev_set_vf_spoofchk,
	.ndo_bridge_getlink = nbl_dev_netdev_bridge_getlink,
	.ndo_bridge_setlink = nbl_dev_netdev_bridge_setlink,
	.ndo_set_vf_link_state = nbl_dev_netdev_set_vf_link_state,
	.ndo_set_vf_mac = nbl_dev_netdev_set_vf_mac,
	.ndo_set_vf_rate = nbl_dev_netdev_set_vf_rate,
	.ndo_get_vf_config = nbl_dev_netdev_get_vf_config,
	.ndo_get_vf_stats = nbl_dev_netdev_get_vf_stats,
	.ndo_select_queue = nbl_dev_netdev_select_queue,
	.ndo_set_vf_vlan = nbl_dev_netdev_set_vf_vlan,
	.ndo_set_vf_trust = nbl_dev_netdev_set_vf_trust,
	.ndo_setup_tc = nbl_dev_netdev_setup_tc,
	.ndo_change_mtu = nbl_dev_netdev_change_mtu,
	.ndo_get_phys_port_name = nbl_dev_ndo_get_phys_port_name,
	.ndo_get_port_parent_id = nbl_dev_ndo_get_port_parent_id,
};

static const struct net_device_ops netdev_ops_draco_vf = {
	.ndo_open = nbl_dev_netdev_open,
	.ndo_stop = nbl_dev_netdev_stop,
	.ndo_start_xmit = nbl_dev_start_xmit_draco,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_get_stats64 = nbl_dev_netdev_get_stats64,
	.ndo_set_rx_mode = nbl_dev_netdev_set_rx_mode,
	.ndo_set_mac_address = nbl_dev_netdev_set_mac,
	.ndo_vlan_rx_add_vid = nbl_dev_netdev_rx_add_vid,
	.ndo_vlan_rx_kill_vid = nbl_dev_netdev_rx_kill_vid,
	.ndo_set_features = nbl_dev_netdev_set_features,
	.ndo_features_check = nbl_dev_features_check,
	.ndo_setup_tc = nbl_dev_netdev_setup_tc,
	.ndo_change_mtu = nbl_dev_netdev_change_mtu,
	.ndo_get_phys_port_name = nbl_dev_ndo_get_phys_port_name,
};

static int nbl_dev_setup_netops_leonis(void *priv, struct net_device *netdev,
				       struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	bool is_vf = param->caps.is_vf;
	bool is_rep = param->is_rep;

	if (is_rep) {
		netdev->netdev_ops = &netdev_ops_leonis_rep;
		serv_ops->set_netdev_ops(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					 &netdev_ops_leonis_rep, false);
	} else if (is_vf) {
		netdev->netdev_ops = &netdev_ops_leonis_vf;
	} else {
		netdev->netdev_ops = &netdev_ops_leonis_pf;
		serv_ops->set_netdev_ops(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					 &netdev_ops_leonis_pf, true);
		/* set rep_ops first, cuz pf may turn on switch_dev without sriov enabled */
		serv_ops->set_netdev_ops(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					 &netdev_ops_leonis_rep, false);
	}

	return 0;
}

static int nbl_dev_setup_netops_draco(void *priv, struct net_device *netdev,
				      struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	bool is_vf = param->caps.is_vf;
	bool is_rep = param->is_rep;

	if (is_rep) {
		netdev->netdev_ops = &netdev_ops_draco_rep;
		serv_ops->set_netdev_ops(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					 &netdev_ops_draco_rep, false);
	} else if (is_vf) {
		netdev->netdev_ops = &netdev_ops_draco_vf;
	} else {
		netdev->netdev_ops = &netdev_ops_draco_pf;
		serv_ops->set_netdev_ops(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					 &netdev_ops_draco_pf, true);
		/* set rep_ops first, cuz pf may turn on switch_dev without sriov enabled */
		serv_ops->set_netdev_ops(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					 &netdev_ops_draco_rep, false);
	}

	return 0;
}

static void nbl_dev_remove_netops(struct net_device *netdev)
{
	netdev->netdev_ops = NULL;
}

static void nbl_dev_get_drvinfo(struct net_device *netdev,
				struct ethtool_drvinfo *drvinfo)
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

static int nbl_dev_get_module_info(struct net_device *netdev,
				   struct ethtool_modinfo *info)
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

static int nbl_dev_get_eeprom(struct net_device *netdev,
			      struct ethtool_eeprom *eeprom, u8 *bytes)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_eeprom(netdev, eeprom, bytes);
}

static void nbl_dev_get_strings(struct net_device *netdev, u32 stringset,
				u8 *data)
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

static void nbl_dev_get_channels(struct net_device *netdev,
				 struct ethtool_channels *channels)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_channels(netdev, channels);
}

static int nbl_dev_set_channels(struct net_device *netdev,
				struct ethtool_channels *channels)
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

static int nbl_dev_get_link_ksettings(struct net_device *netdev,
				      struct ethtool_link_ksettings *cmd)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_ksettings(netdev, cmd);
}

static int nbl_dev_set_link_ksettings(struct net_device *netdev,
				      const struct ethtool_link_ksettings *cmd)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_ksettings(netdev, cmd);
}

static void nbl_dev_get_ringparam(struct net_device *netdev,
				  struct ethtool_ringparam *ringparam,
				  struct kernel_ethtool_ringparam *k_ringparam,
				  struct netlink_ext_ack *extack)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_ringparam(netdev, ringparam, k_ringparam, extack);
}

static int nbl_dev_set_ringparam(struct net_device *netdev,
				 struct ethtool_ringparam *ringparam,
				 struct kernel_ethtool_ringparam *k_ringparam,
				 struct netlink_ext_ack *extack)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_ringparam(netdev, ringparam, k_ringparam, extack);
}

static int nbl_dev_get_coalesce(struct net_device *netdev,
				struct ethtool_coalesce *ec,
				struct kernel_ethtool_coalesce *kernel_ec,
				struct netlink_ext_ack *extack)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_coalesce(netdev, ec, kernel_ec, extack);
}

static int nbl_dev_set_coalesce(struct net_device *netdev,
				struct ethtool_coalesce *ec,
				struct kernel_ethtool_coalesce *kernel_ec,
				struct netlink_ext_ack *extack)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_coalesce(netdev, ec, kernel_ec, extack);
}

static int nbl_dev_get_rxnfc(struct net_device *netdev,
			     struct ethtool_rxnfc *cmd, u32 *rule_locs)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_rxnfc(netdev, cmd, rule_locs);
}

static int nbl_dev_set_rxnfc(struct net_device *netdev,
			     struct ethtool_rxnfc *cmd)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_rxnfc(netdev, cmd);
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

static int nbl_dev_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key,
			    u8 *hfunc)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_rxfh(netdev, indir, key, hfunc);
}

static int nbl_dev_set_rxfh(struct net_device *netdev, const u32 *indir,
			    const u8 *key, const u8 hfunc)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_rxfh(netdev, indir, key, hfunc);
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

static int nbl_dev_get_per_queue_coalesce(struct net_device *netdev, u32 q_num,
					  struct ethtool_coalesce *ec)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_per_queue_coalesce(netdev, q_num, ec);
}

static int nbl_dev_set_per_queue_coalesce(struct net_device *netdev, u32 q_num,
					  struct ethtool_coalesce *ec)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_per_queue_coalesce(netdev, q_num, ec);
}

static void nbl_dev_self_test(struct net_device *netdev,
			      struct ethtool_test *eth_test, u64 *data)
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

static int nbl_dev_set_pauseparam(struct net_device *netdev,
				  struct ethtool_pauseparam *param)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_pause_param(netdev, param);
}

static void nbl_dev_get_pauseparam(struct net_device *netdev,
				   struct ethtool_pauseparam *param)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_pause_param(netdev, param);
}

static int nbl_dev_set_fecparam(struct net_device *netdev,
				struct ethtool_fecparam *fec)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_fec_param(netdev, fec);
}

static int nbl_dev_get_fecparam(struct net_device *netdev,
				struct ethtool_fecparam *fec)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_fec_param(netdev, fec);
}

static int nbl_dev_get_ts_info(struct net_device *netdev,
			       struct ethtool_ts_info *ts_info)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_ts_info(netdev, ts_info);
}

static int nbl_dev_set_phys_id(struct net_device *netdev,
			       enum ethtool_phys_id_state state)
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

static int nbl_dev_flash_device(struct net_device *netdev,
				struct ethtool_flash *flash)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->flash_device(netdev, flash);
}

static int nbl_dev_get_dump_flag(struct net_device *netdev,
				 struct ethtool_dump *dump)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_dump_flag(netdev, dump);
}

static int nbl_dev_get_dump_data(struct net_device *netdev,
				 struct ethtool_dump *dump, void *buffer)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_dump_data(netdev, dump, buffer);
}

static int nbl_dev_set_dump(struct net_device *netdev,
			    struct ethtool_dump *dump)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_dump(netdev, dump);
}

static int nbl_dev_set_wol(struct net_device *netdev,
			   struct ethtool_wolinfo *wol)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->set_wol(netdev, wol);
}

static void nbl_dev_get_wol(struct net_device *netdev,
			    struct ethtool_wolinfo *wol)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_wol(netdev, wol);
}

static void nbl_dev_get_eth_ctrl_stats(struct net_device *netdev,
				       struct ethtool_eth_ctrl_stats *stats)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_eth_ctrl_stats(netdev, stats);
}

static void nbl_dev_get_pause_stats(struct net_device *netdev,
				    struct ethtool_pause_stats *pause_stats)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_pause_stats(netdev, pause_stats);
}

static void nbl_dev_get_eth_mac_stats(struct net_device *netdev,
				      struct ethtool_eth_mac_stats *mac_stats)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_eth_mac_stats(netdev, mac_stats);
}

static void nbl_dev_get_fec_stats(struct net_device *netdev,
				  struct ethtool_fec_stats *fec_stats)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_fec_stats(netdev, fec_stats);
}

static int nbl_dev_get_link_ext_state(struct net_device *netdev,
				      struct ethtool_link_ext_state_info *info)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_link_ext_state(netdev, info);
}

static void nbl_dev_get_link_ext_stats(struct net_device *netdev,
				       struct ethtool_link_ext_stats *stats)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_link_ext_stats(netdev, stats);
}

static void nbl_dev_get_rmon_stats(struct net_device *netdev,
				   struct ethtool_rmon_stats *rmon_stats,
				   const struct ethtool_rmon_hist_range **range)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_rmon_stats(netdev, rmon_stats, range);
}

static void nbl_dev_get_rep_strings(struct net_device *netdev, u32 stringset,
				    u8 *data)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_rep_strings(netdev, stringset, data);
}

static int nbl_dev_get_rep_sset_count(struct net_device *netdev, int sset)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->get_rep_sset_count(netdev, sset);
}

static void nbl_dev_get_rep_ethtool_stats(struct net_device *netdev,
					  struct ethtool_stats *stats,
					  u64 *data)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_rep_ethtool_stats(netdev, stats, data);
}

static const struct ethtool_ops ethtool_ops_leonis_rep = {
	.get_drvinfo = nbl_dev_get_drvinfo,
	.get_strings = nbl_dev_get_rep_strings,
	.get_sset_count = nbl_dev_get_rep_sset_count,
	.get_ethtool_stats = nbl_dev_get_rep_ethtool_stats,
	.get_link = nbl_dev_get_link,
	.get_link_ksettings = nbl_dev_get_link_ksettings,
	.get_ringparam = nbl_dev_get_ringparam,
};

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
	.set_rxnfc = nbl_dev_set_rxnfc,
	.get_rxfh_indir_size = nbl_dev_get_rxfh_indir_size,
	.get_rxfh_key_size = nbl_dev_get_rxfh_key_size,
	.get_rxfh = nbl_dev_get_rxfh,
	.set_rxfh = nbl_dev_set_rxfh,
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
	.flash_device = nbl_dev_flash_device,
	.get_dump_flag = nbl_dev_get_dump_flag,
	.get_dump_data = nbl_dev_get_dump_data,
	.set_dump = nbl_dev_set_dump,
	.set_wol = nbl_dev_set_wol,
	.get_wol = nbl_dev_get_wol,
	.get_eth_ctrl_stats = nbl_dev_get_eth_ctrl_stats,
	.get_pause_stats = nbl_dev_get_pause_stats,
	.get_eth_mac_stats = nbl_dev_get_eth_mac_stats,
	.get_fec_stats = nbl_dev_get_fec_stats,
	.get_link_ext_state = nbl_dev_get_link_ext_state,
	.get_link_ext_stats = nbl_dev_get_link_ext_stats,
	.get_rmon_stats = nbl_dev_get_rmon_stats,
};

static const struct ethtool_ops ethtool_ops_leonis_vf = {
	.supported_coalesce_params = ETHTOOL_COALESCE_RX_USECS |
			     ETHTOOL_COALESCE_RX_MAX_FRAMES |
			     ETHTOOL_COALESCE_TX_USECS |
			     ETHTOOL_COALESCE_TX_MAX_FRAMES |
			     ETHTOOL_COALESCE_USE_ADAPTIVE,
	.get_drvinfo = nbl_dev_get_drvinfo,
	.get_strings = nbl_dev_get_strings,
	.get_sset_count = nbl_dev_get_sset_count,
	.get_ethtool_stats = nbl_dev_get_ethtool_stats,
	.get_channels = nbl_dev_get_channels,
	.set_channels = nbl_dev_set_channels,
	.get_link = nbl_dev_get_link,
	.get_link_ksettings = nbl_dev_get_link_ksettings,
	.get_ringparam = nbl_dev_get_ringparam,
	.set_ringparam = nbl_dev_set_ringparam,
	.get_coalesce = nbl_dev_get_coalesce,
	.set_coalesce = nbl_dev_set_coalesce,
	.get_rxnfc = nbl_dev_get_rxnfc,
	.set_rxnfc = nbl_dev_set_rxnfc,
	.get_rxfh_indir_size = nbl_dev_get_rxfh_indir_size,
	.get_rxfh_key_size = nbl_dev_get_rxfh_key_size,
	.get_rxfh = nbl_dev_get_rxfh,
	.set_rxfh = nbl_dev_set_rxfh,
	.get_msglevel = nbl_dev_get_msglevel,
	.set_msglevel = nbl_dev_set_msglevel,
	.get_regs_len = nbl_dev_get_regs_len,
	.get_regs = nbl_dev_get_regs,
	.get_per_queue_coalesce = nbl_dev_get_per_queue_coalesce,
	.set_per_queue_coalesce = nbl_dev_set_per_queue_coalesce,
	.get_priv_flags = nbl_dev_get_priv_flags,
	.set_priv_flags = nbl_dev_set_priv_flags,
	.get_ts_info = nbl_dev_get_ts_info,
};

static const struct ethtool_ops ethtool_ops_draco_rep = {
	.get_drvinfo = nbl_dev_get_drvinfo,
	.get_strings = nbl_dev_get_rep_strings,
	.get_sset_count = nbl_dev_get_rep_sset_count,
	.get_ethtool_stats = nbl_dev_get_rep_ethtool_stats,
	.get_link = nbl_dev_get_link,
	.get_link_ksettings = nbl_dev_get_link_ksettings,
	.get_ringparam = nbl_dev_get_ringparam,
};

static const struct ethtool_ops ethtool_ops_draco_pf = {
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
	.set_rxnfc = nbl_dev_set_rxnfc,
	.get_rxfh_indir_size = nbl_dev_get_rxfh_indir_size,
	.get_rxfh_key_size = nbl_dev_get_rxfh_key_size,
	.get_rxfh = nbl_dev_get_rxfh,
	.set_rxfh = nbl_dev_set_rxfh,
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
	.flash_device = nbl_dev_flash_device,
	.get_dump_flag = nbl_dev_get_dump_flag,
	.get_dump_data = nbl_dev_get_dump_data,
	.set_dump = nbl_dev_set_dump,
	.set_wol = nbl_dev_set_wol,
	.get_wol = nbl_dev_get_wol,
	.get_pause_stats = nbl_dev_get_pause_stats,
	.get_eth_mac_stats = nbl_dev_get_eth_mac_stats,
	.get_fec_stats = nbl_dev_get_fec_stats,
	.get_link_ext_state = nbl_dev_get_link_ext_state,
	.get_link_ext_stats = nbl_dev_get_link_ext_stats,
	.get_rmon_stats = nbl_dev_get_rmon_stats,
};

static const struct ethtool_ops ethtool_ops_draco_vf = {
	.supported_coalesce_params = ETHTOOL_COALESCE_RX_USECS |
			     ETHTOOL_COALESCE_RX_MAX_FRAMES |
			     ETHTOOL_COALESCE_TX_USECS |
			     ETHTOOL_COALESCE_TX_MAX_FRAMES |
			     ETHTOOL_COALESCE_USE_ADAPTIVE,
	.get_drvinfo = nbl_dev_get_drvinfo,
	.get_strings = nbl_dev_get_strings,
	.get_sset_count = nbl_dev_get_sset_count,
	.get_ethtool_stats = nbl_dev_get_ethtool_stats,
	.get_channels = nbl_dev_get_channels,
	.set_channels = nbl_dev_set_channels,
	.get_link = nbl_dev_get_link,
	.get_link_ksettings = nbl_dev_get_link_ksettings,
	.get_ringparam = nbl_dev_get_ringparam,
	.set_ringparam = nbl_dev_set_ringparam,
	.get_coalesce = nbl_dev_get_coalesce,
	.set_coalesce = nbl_dev_set_coalesce,
	.get_rxnfc = nbl_dev_get_rxnfc,
	.set_rxnfc = nbl_dev_set_rxnfc,
	.get_rxfh_indir_size = nbl_dev_get_rxfh_indir_size,
	.get_rxfh_key_size = nbl_dev_get_rxfh_key_size,
	.get_rxfh = nbl_dev_get_rxfh,
	.set_rxfh = nbl_dev_set_rxfh,
	.get_msglevel = nbl_dev_get_msglevel,
	.set_msglevel = nbl_dev_set_msglevel,
	.get_regs_len = nbl_dev_get_regs_len,
	.get_regs = nbl_dev_get_regs,
	.get_per_queue_coalesce = nbl_dev_get_per_queue_coalesce,
	.set_per_queue_coalesce = nbl_dev_set_per_queue_coalesce,
	.get_priv_flags = nbl_dev_get_priv_flags,
	.set_priv_flags = nbl_dev_set_priv_flags,
	.get_ts_info = nbl_dev_get_ts_info,
};

static int nbl_dev_setup_ethtool_ops_leonis(void *priv, struct net_device *netdev,
					    struct nbl_init_param *param)
{
	bool is_vf = param->caps.is_vf;
	bool is_rep = param->is_rep;

	if (is_rep)
		netdev->ethtool_ops = &ethtool_ops_leonis_rep;
	else if (is_vf)
		netdev->ethtool_ops = &ethtool_ops_leonis_vf;
	else
		netdev->ethtool_ops = &ethtool_ops_leonis_pf;

	return 0;
}

static int nbl_dev_setup_ethtool_ops_draco(void *priv, struct net_device *netdev,
					   struct nbl_init_param *param)
{
	bool is_vf = param->caps.is_vf;
	bool is_rep = param->is_rep;

	if (is_rep)
		netdev->ethtool_ops = &ethtool_ops_draco_rep;
	else if (is_vf)
		netdev->ethtool_ops = &ethtool_ops_draco_vf;
	else
		netdev->ethtool_ops = &ethtool_ops_draco_pf;

	return 0;
}

static void nbl_dev_remove_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = NULL;
}

#if IS_ENABLED(CONFIG_TLS_DEVICE)
static int nbl_dev_tls_dev_add(struct net_device *netdev, struct sock *sk,
			       enum tls_offload_ctx_dir direction,
			       struct tls_crypto_info *crypto_info,
			       u32 start_offload_tcp_sn)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->add_tls_dev(netdev, sk, direction, crypto_info,
				     start_offload_tcp_sn);
}

static void nbl_dev_tls_dev_del(struct net_device *netdev,
				struct tls_context *tls_ctx,
				enum tls_offload_ctx_dir direction)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->del_tls_dev(netdev, tls_ctx, direction);
}

static int nbl_dev_tls_dev_resync(struct net_device *netdev, struct sock *sk,
				  u32 tcp_seq, u8 *rec_num,
				  enum tls_offload_ctx_dir direction)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->resync_tls_dev(netdev, sk, tcp_seq, rec_num,
					direction);
}

static const struct tlsdev_ops ktls_ops = {
	.tls_dev_add = nbl_dev_tls_dev_add,
	.tls_dev_del = nbl_dev_tls_dev_del,
	.tls_dev_resync = nbl_dev_tls_dev_resync,
};

static int nbl_dev_setup_ktls_ops(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	if (!serv_ops->get_product_flex_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    NBL_SECURITY_TLS_CAP))
		return 0;

	netdev->features     |= NETIF_F_HW_TLS_RX;
	netdev->hw_features  |= NETIF_F_HW_TLS_RX;
	netdev->features     |= NETIF_F_HW_TLS_TX;
	netdev->hw_features  |= NETIF_F_HW_TLS_TX;
	netdev->tlsdev_ops = &ktls_ops;
	return 0;
}

static void nbl_dev_remove_ktls_ops(struct net_device *netdev)
{
	netdev->features     &= ~NETIF_F_HW_TLS_RX;
	netdev->hw_features  &= ~NETIF_F_HW_TLS_RX;
	netdev->features     &= ~NETIF_F_HW_TLS_TX;
	netdev->hw_features  &= ~NETIF_F_HW_TLS_TX;

	netdev->tlsdev_ops = NULL;
}

#else
static int nbl_dev_setup_ktls_ops(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev)
{
	return 0;
}

static void nbl_dev_remove_ktls_ops(struct net_device *netdev)
{
}
#endif

#if IS_ENABLED(CONFIG_XFRM_OFFLOAD)
static int nbl_dev_xdo_state_add(struct xfrm_state *x,
				 struct netlink_ext_ack *extack)
{
	struct net_device *netdev = x->xso.dev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->add_xdo_dev_state(x, extack);
}

static void nbl_dev_xdo_state_delete(struct xfrm_state *x)
{
	struct net_device *netdev = x->xso.dev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->delete_xdo_dev_state(x);
}

static void nbl_dev_xdo_state_free(struct xfrm_state *x)
{
	struct net_device *netdev = x->xso.dev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->free_xdo_dev_state(x);
}

static bool nbl_dev_xdo_offload_ok(struct sk_buff *skb, struct xfrm_state *x)
{
	struct net_device *netdev = x->xso.dev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->xdo_dev_offload_ok(skb, x);
}

static void nbl_dev_xdo_dev_state_advance_esn(struct xfrm_state *x)
{
	struct net_device *netdev = x->xso.dev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->xdo_dev_state_advance_esn(x);
}

static const struct xfrmdev_ops xfrm_ops = {
	.xdo_dev_state_add = nbl_dev_xdo_state_add,
	.xdo_dev_state_delete = nbl_dev_xdo_state_delete,
	.xdo_dev_state_free = nbl_dev_xdo_state_free,
	.xdo_dev_offload_ok = nbl_dev_xdo_offload_ok,
	.xdo_dev_state_advance_esn = nbl_dev_xdo_dev_state_advance_esn,
};

static int nbl_dev_setup_xfrm_ops(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	enum nbl_flex_cap_type cap_type = NBL_SECURITY_IPSEC_CAP;

	if (!serv_ops->get_product_flex_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), cap_type))
		return 0;
	chan_ops->register_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
			       NBL_CHAN_MSG_NOTIFY_IPSEC_HARD_EXPIRE,
			       nbl_dev_notify_ipsec_hard_expire, dev_mgt);

	netdev->features     |= NETIF_F_HW_ESP;
	netdev->hw_enc_features  |= NETIF_F_HW_ESP;
	netdev->features     |= NETIF_F_HW_ESP_TX_CSUM;
	netdev->hw_enc_features  |= NETIF_F_HW_ESP_TX_CSUM;

	/* gso_partial_features */
	netdev->gso_partial_features |= NETIF_F_GSO_ESP;
	netdev->features |= NETIF_F_GSO_ESP;
	netdev->hw_features |= NETIF_F_GSO_ESP;
	netdev->hw_enc_features  |= NETIF_F_GSO_ESP;

	netdev->xfrmdev_ops = &xfrm_ops;
	return 0;
}

static void nbl_dev_remove_xfrm_ops(struct net_device *netdev)
{
	netdev->features     &= ~NETIF_F_HW_ESP;
	netdev->hw_enc_features  &= ~NETIF_F_HW_ESP;
	netdev->features     &= ~NETIF_F_HW_ESP_TX_CSUM;
	netdev->hw_enc_features  &= ~NETIF_F_HW_ESP_TX_CSUM;

	/* gso_partial_features */
	netdev->gso_partial_features &= ~NETIF_F_GSO_ESP;
	netdev->features &= ~NETIF_F_GSO_ESP;
	netdev->hw_features &= ~NETIF_F_GSO_ESP;
	netdev->hw_enc_features  &= ~NETIF_F_GSO_ESP;

	netdev->xfrmdev_ops = NULL;
}
#else
static int nbl_dev_setup_xfrm_ops(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev)
{
	return 0;
}

static void nbl_dev_remove_xfrm_ops(struct net_device *netdev)
{
}
#endif

#if IS_ENABLED(CONFIG_MACSEC)
static int nbl_dev_mdo_add_txsa(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->add_macsec_txsa(ctx);
}

static int nbl_dev_mdo_upd_txsa(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->upd_macsec_txsa(ctx);
}

static int nbl_dev_mdo_del_txsa(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->del_macsec_txsa(ctx);
}

static int nbl_dev_mdo_add_rxsc(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->add_macsec_rxsc(ctx);
}

static int nbl_dev_mdo_upd_rxsc(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->upd_macsec_rxsc(ctx);
}

static int nbl_dev_mdo_del_rxsc(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->del_macsec_rxsc(ctx);
}

static int nbl_dev_mdo_add_rxsa(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->add_macsec_rxsa(ctx);
}

static int nbl_dev_mdo_upd_rxsa(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->upd_macsec_rxsa(ctx);
}

static int nbl_dev_mdo_del_rxsa(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->del_macsec_rxsa(ctx);
}

static int nbl_dev_mdo_add_secy(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->add_macsec_secy(ctx);
}

static int nbl_dev_mdo_upd_secy(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->upd_macsec_secy(ctx);
}

static int nbl_dev_mdo_del_secy(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->del_macsec_secy(ctx);
}

static const struct macsec_ops macsec_ops = {
	.mdo_add_txsa = nbl_dev_mdo_add_txsa,
	.mdo_upd_txsa = nbl_dev_mdo_upd_txsa,
	.mdo_del_txsa = nbl_dev_mdo_del_txsa,
	.mdo_add_rxsc = nbl_dev_mdo_add_rxsc,
	.mdo_upd_rxsc = nbl_dev_mdo_upd_rxsc,
	.mdo_del_rxsc = nbl_dev_mdo_del_rxsc,
	.mdo_add_rxsa = nbl_dev_mdo_add_rxsa,
	.mdo_upd_rxsa = nbl_dev_mdo_upd_rxsa,
	.mdo_del_rxsa = nbl_dev_mdo_del_rxsa,
	.mdo_add_secy = nbl_dev_mdo_add_secy,
	.mdo_upd_secy = nbl_dev_mdo_upd_secy,
	.mdo_del_secy = nbl_dev_mdo_del_secy,
};

static int nbl_dev_setup_macsec_ops(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	if (!serv_ops->get_product_flex_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					    NBL_SECURITY_MACSEC_CAP))
		return 0;

	netdev->features |= NETIF_F_HW_MACSEC;

	netdev->macsec_ops = &macsec_ops;
	return 0;
}

static void nbl_dev_remove_macsec_ops(struct net_device *netdev)
{
	netdev->features &= ~NETIF_F_HW_MACSEC;

	netdev->macsec_ops = NULL;
}
#else
static int nbl_dev_setup_macsec_ops(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev)
{
	return 0;
}

static void nbl_dev_remove_macsec_ops(struct net_device *netdev)
{
}
#endif

#ifdef CONFIG_DCB
static int nbl_dev_ieee_setets(struct net_device *netdev, struct ieee_ets *ets)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->ieee_setets(netdev, ets);
}

static int nbl_dev_ieee_getets(struct net_device *netdev, struct ieee_ets *ets)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->ieee_getets(netdev, ets);
}

static int nbl_dev_ieee_setpfc(struct net_device *netdev, struct ieee_pfc *pfc)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->ieee_setpfc(netdev, pfc);
}

static int nbl_dev_ieee_getpfc(struct net_device *netdev, struct ieee_pfc *pfc)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->ieee_getpfc(netdev, pfc);
}

static int nbl_dev_ieee_setapp(struct net_device *netdev, struct dcb_app *app)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->ieee_setapp(netdev, app);
}

static int nbl_dev_ieee_delapp(struct net_device *netdev, struct dcb_app *app)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->ieee_delapp(netdev, app);
}

static u8 nbl_dev_getdcbx(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->ieee_getdcbx(netdev);
}

static u8 nbl_dev_setdcbx(struct net_device *netdev, u8 mode)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->ieee_setdcbx(netdev, mode);
}

static int nbl_dev_getnumtcs(struct net_device *netdev, int tcid, u8 *num)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->dcbnl_getnumtcs(netdev, tcid, num);
}

static void nbl_dev_setpfccfg(struct net_device *netdev, int prio, u8 set)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->dcbnl_setpfccfg(netdev, prio, set);
}

static void nbl_dev_getpfccfg(struct net_device *netdev, int prio, u8 *setting)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->dcbnl_getpfccfg(netdev, prio, setting);
}

static u8 nbl_dev_getstate(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->dcbnl_getstate(netdev);
}

static u8 nbl_dev_setstate(struct net_device *netdev, u8 state)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->dcbnl_setstate(netdev, state);
}

static u8 nbl_dev_getpfcstate(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->dcbnl_getpfcstate(netdev);
}

static u8 nbl_dev_getcap(struct net_device *netdev, int capid, u8 *cap)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->dcbnl_getcap(netdev, capid, cap);
}

static const struct dcbnl_rtnl_ops dcbnl_ops_leonis_pf = {
	.ieee_setets = nbl_dev_ieee_setets,
	.ieee_getets = nbl_dev_ieee_getets,
	.ieee_setpfc = nbl_dev_ieee_setpfc,
	.ieee_getpfc = nbl_dev_ieee_getpfc,
	.ieee_setapp = nbl_dev_ieee_setapp,
	.ieee_delapp = nbl_dev_ieee_delapp,
	.getdcbx = nbl_dev_getdcbx,
	.setdcbx = nbl_dev_setdcbx,
	.getnumtcs = nbl_dev_getnumtcs,
	.setpfccfg = nbl_dev_setpfccfg,
	.getpfccfg = nbl_dev_getpfccfg,
	.getstate = nbl_dev_getstate,
	.setstate = nbl_dev_setstate,
	.getpfcstate = nbl_dev_getpfcstate,
	.getcap = nbl_dev_getcap,
};

static int nbl_dev_setup_dcbnl_ops_leonis(void *priv, struct net_device *netdev,
					  struct nbl_init_param *param)
{
	bool is_vf = param->caps.is_vf;

	if (!is_vf)
		netdev->dcbnl_ops = &dcbnl_ops_leonis_pf;

	return 0;
}

static int nbl_dev_setup_dcbnl_ops_draco(void *priv, struct net_device *netdev,
					 struct nbl_init_param *param)
{
	return 0;
}

static void nbl_dev_remove_dcbnl_ops(struct net_device *netdev)
{
	netdev->dcbnl_ops = NULL;
}
#endif

static void nbl_dev_set_eth_mac_addr(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev)
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
	u64 hw_features = 0;
	u64 features = 0;
	u64 vlan_features = 0;
	u64 hw_enc_features = 0;
	int ret = 0;

	if (param->pci_using_dac)
		netdev->features |= NETIF_F_HIGHDMA;
	if (!param->is_rep)
		netdev->watchdog_timeo = 5 * HZ;

	hw_features = register_result->hw_features;
	features = register_result->features;
	/* to support request use develop branch, response use v3r1 branch. v3r1 branch
	 * the value of vlan_features member is zero
	 */
	vlan_features = register_result->vlan_features ? register_result->vlan_features
							: register_result->features;
	hw_enc_features = register_result->hw_enc_features;

	netdev->hw_features |= nbl_features_to_netdev_features(hw_features);
	netdev->features |= nbl_features_to_netdev_features(features);
	netdev->vlan_features |= nbl_features_to_netdev_features(vlan_features);
	netdev->hw_enc_features |= nbl_features_to_netdev_features(hw_enc_features);
	netdev->xdp_features = NETDEV_XDP_ACT_BASIC | NETDEV_XDP_ACT_REDIRECT |
			       NETDEV_XDP_ACT_NDO_XMIT;

	netdev->priv_flags |= IFF_UNICAST_FLT;

	SET_DEV_MIN_MTU(netdev, ETH_MIN_MTU);
	SET_DEV_MAX_MTU(netdev, register_result->max_mtu);
	netdev->mtu = min_t(u16, register_result->max_mtu, NBL_DEFAULT_MTU);

	if (is_valid_ether_addr(register_result->mac))
		eth_hw_addr_set(netdev, register_result->mac);
	else
		eth_hw_addr_random(netdev);

	ether_addr_copy(netdev->perm_addr, netdev->dev_addr);

	netdev->needed_headroom = serv_ops->get_tx_headroom(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));

	ret = net_dev_ops->setup_netdev_ops(dev_mgt, netdev, param);
	if (ret)
		goto set_ops_fail;

	ret = net_dev_ops->setup_ethtool_ops(dev_mgt, netdev, param);
	if (ret)
		goto set_ethtool_fail;
#ifdef CONFIG_DCB
	ret = net_dev_ops->setup_dcbnl_ops(dev_mgt, netdev, param);
	if (ret)
		goto set_dcbnl_fail;
#endif
	if (!param->is_rep) {
		ret = nbl_dev_setup_ktls_ops(dev_mgt, netdev);
		if (ret)
			goto set_ktls_fail;

		ret = nbl_dev_setup_xfrm_ops(dev_mgt, netdev);
		if (ret)
			goto set_xfrm_fail;
		ret = nbl_dev_setup_macsec_ops(dev_mgt, netdev);
		if (ret)
			goto set_macsec_fail;
	}

	return 0;

set_macsec_fail:
	nbl_dev_remove_xfrm_ops(netdev);
set_xfrm_fail:
	nbl_dev_remove_ktls_ops(netdev);
set_ktls_fail:
#ifdef CONFIG_DCB
	nbl_dev_remove_dcbnl_ops(netdev);
set_dcbnl_fail:
#endif
	nbl_dev_remove_ethtool_ops(netdev);
set_ethtool_fail:
	nbl_dev_remove_netops(netdev);
set_ops_fail:
	return ret;
}

static void nbl_dev_reset_netdev(struct net_device *netdev)
{
	nbl_dev_remove_ktls_ops(netdev);
	nbl_dev_remove_xfrm_ops(netdev);
	nbl_dev_remove_macsec_ops(netdev);
#ifdef CONFIG_DCB
	nbl_dev_remove_dcbnl_ops(netdev);
#endif
	nbl_dev_remove_ethtool_ops(netdev);
	nbl_dev_remove_netops(netdev);
}

static int nbl_dev_register_net(struct nbl_dev_mgt *dev_mgt,
				struct nbl_register_net_result *register_result)
{
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct pci_dev *pdev = NBL_COMMON_TO_PDEV(NBL_DEV_MGT_TO_COMMON(dev_mgt));
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
#ifdef CONFIG_PCI_IOV
	struct resource *res;
#endif
	u16 pf_bdf;
	u64 pf_bar_start;
	u64 vf_bar_start, vf_bar_size;
	u16 total_vfs = 0, offset, stride;
	int pos;
	u32 val;
	struct nbl_ch_prm_register_net_info register_param = {0};
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

#ifdef CONFIG_PCI_IOV
		res = &pdev->resource[PCI_IOV_RESOURCES];
		vf_bar_size = resource_size(res);
#else
		vf_bar_size = 0;
#endif
		if (total_vfs) {
			register_param.pf_bdf = pf_bdf;
			register_param.vf_bar_start = vf_bar_start;
			register_param.vf_bar_size = vf_bar_size;
			register_param.total_vfs = total_vfs;
			register_param.offset = offset;
			register_param.stride = stride;
		}
	}

	net_dev->total_vfs = total_vfs;
	register_param.sfid =  NBL_COMMON_TO_MGT_PF(common);
	ret = serv_ops->register_net(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
				     &register_param, register_result);

	if (!register_result->tx_queue_num || !register_result->rx_queue_num)
		return -EIO;

	return ret;
}

static void nbl_dev_get_rep_feature(struct nbl_adapter *adapter,
				    struct nbl_register_net_result *register_result)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_rep_feature(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), register_result);
}

static void nbl_dev_get_rep_queue_num(struct nbl_adapter *adapter,
				      u8 *base_queue_id,
				      u8 *rep_queue_num)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_rep_queue_num(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
				    base_queue_id, rep_queue_num);
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
	int ret = 0;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_vsi_param vsi_param = {0};

	vsi->queue_offset = nbl_dev_vsi_alloc_queue(NBL_DEV_MGT_TO_NET_DEV(dev_mgt),
						    vsi->queue_num);
	vsi_param.index = vsi->index;
	vsi_param.vsi_id = vsi->vsi_id;
	vsi_param.queue_offset = vsi->queue_offset;
	vsi_param.queue_num = vsi->queue_num;

	/* Tell serv & res layer the mapping from vsi to queue_id */
	ret = serv_ops->register_vsi_info(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &vsi_param);
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
		dev_err(dev, "Setup rss failed\n");
		goto set_rss_fail;
	}

	ret = serv_ops->setup_rss_indir(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->index);
	if (ret) {
		dev_err(dev, "Setup rss indir failed\n");
		goto setup_rss_indir_fail;
	}

	ret = serv_ops->init_tx_rate(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
	if (ret) {
		dev_err(dev, "init tx_rate failed\n");
		goto init_tx_rate_fail;
	}

	return 0;

init_tx_rate_fail:
setup_rss_indir_fail:
	serv_ops->remove_rss(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
set_rss_fail:
	serv_ops->remove_q2vsi(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
set_q2vsi_fail:
	return ret;
}

static void nbl_dev_vsi_common_stop(struct nbl_dev_mgt *dev_mgt, struct nbl_dev_vsi *vsi)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

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

static int nbl_dev_vsi_data_start(void *dev_priv, struct net_device *netdev,
				  void *vsi_data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)dev_priv;
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;
	int ret;
	u16 vid;

	vid = vsi->register_result.vlan_tci & VLAN_VID_MASK;
	ret = serv_ops->start_net_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), netdev, vsi->vsi_id, vid,
				       vsi->register_result.trusted);
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
	}

	ret = nbl_dev_vsi_common_start(dev_mgt, netdev, vsi);
	if (ret) {
		dev_err(dev, "Vsi common start failed\n");
		goto common_start_fail;
	}

	return 0;

common_start_fail:
	if (!NBL_COMMON_TO_VF_CAP(common))
		serv_ops->remove_lldp_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
set_lldp_fail:
	serv_ops->stop_net_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
set_flow_fail:
	return ret;
}

static void nbl_dev_vsi_data_stop(void *dev_priv, void *vsi_data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)dev_priv;
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;

	nbl_dev_vsi_common_stop(dev_mgt, vsi);

	if (!NBL_COMMON_TO_VF_CAP(common))
		serv_ops->remove_lldp_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);

	serv_ops->stop_net_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
}

static int nbl_dev_build_net_dev(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
				 struct net_device *netdev, struct nbl_dev_vsi *vsi)
{
	vsi->netdev = netdev;
	return nbl_dev_cfg_netdev(netdev, dev_mgt, param, &vsi->register_result);
}

static int nbl_dev_vsi_ctrl_register(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
				     void *vsi_data)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_rep_queue_info(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
				     &vsi->queue_num, &vsi->queue_size);

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

static int nbl_dev_vsi_ctrl_start(void *dev_priv, struct net_device *netdev,
				  void *vsi_data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)dev_priv;
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

static void nbl_dev_vsi_ctrl_stop(void *dev_priv, void *vsi_data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)dev_priv;
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->vsi_stop(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->index);
	nbl_dev_vsi_common_stop(dev_mgt, vsi);
}

static int nbl_dev_vsi_user_register(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
				     void *vsi_data)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->get_user_queue_info(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
				      &vsi->queue_num, &vsi->queue_size,
				      NBL_COMMON_TO_VSI_ID(common));

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

static int nbl_dev_vsi_user_start(void *dev_priv, struct net_device *netdev,
				  void *vsi_data)
{
	return 0;
}

static void nbl_dev_vsi_user_stop(void *dev_priv, void *vsi_data)
{
}

static int nbl_dev_vsi_xdp_register(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
				    void *vsi_data)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	if (!serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_XDP_CAP))
		return 0;

	serv_ops->get_xdp_queue_info(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
				     &vsi->queue_num, &vsi->queue_size,
				     NBL_COMMON_TO_VSI_ID(common));

	nbl_debug(common, NBL_DEBUG_VSI, "Xdp vsi register, queue_num %d, queue_size %d",
		  vsi->queue_num, vsi->queue_size);
	return 0;
}

static int nbl_dev_vsi_xdp_setup(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
				 void *vsi_data)
{
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;

	return nbl_dev_vsi_common_setup(dev_mgt, param, vsi);
}

static void nbl_dev_vsi_xdp_remove(struct nbl_dev_mgt *dev_mgt, void *vsi_data)
{
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;

	nbl_dev_vsi_common_remove(dev_mgt, vsi);
}

static int nbl_dev_vsi_xdp_start(void *dev_priv, struct net_device *netdev,
				 void *vsi_data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)dev_priv;
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	int ret = 0;

	ret = nbl_dev_vsi_common_start(dev_mgt, netdev, vsi);
	if (ret)
		goto start_fail;

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

static void nbl_dev_vsi_xdp_stop(void *dev_priv, void *vsi_data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)dev_priv;
	struct nbl_dev_vsi *vsi = (struct nbl_dev_vsi *)vsi_data;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->vsi_stop(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->index);
	nbl_dev_vsi_common_stop(dev_mgt, vsi);
}

static struct nbl_dev_vsi_tbl vsi_tbl[NBL_VSI_MAX] = {
	[NBL_VSI_DATA] = {
		.vsi_ops = {
			.register_vsi = nbl_dev_vsi_data_register,
			.setup = nbl_dev_vsi_data_setup,
			.remove = nbl_dev_vsi_data_remove,
			.start = nbl_dev_vsi_data_start,
			.stop = nbl_dev_vsi_data_stop,
		},
		.vf_support = true,
		.only_nic_support = false,
		.userdev_support = false,
		.in_kernel = true,
		.use_independ_irq = true,
		.static_queue = true,
	},
	[NBL_VSI_CTRL] = {
		.vsi_ops = {
			.register_vsi = nbl_dev_vsi_ctrl_register,
			.setup = nbl_dev_vsi_ctrl_setup,
			.remove = nbl_dev_vsi_ctrl_remove,
			.start = nbl_dev_vsi_ctrl_start,
			.stop = nbl_dev_vsi_ctrl_stop,
		},
		.vf_support = false,
		.only_nic_support = true,
		.userdev_support = false,
		.in_kernel = true,
		.use_independ_irq = true,
		.static_queue = true,
	},
	[NBL_VSI_USER] = {
		.vsi_ops = {
			.register_vsi = nbl_dev_vsi_user_register,
			.setup = nbl_dev_vsi_user_setup,
			.remove = nbl_dev_vsi_user_remove,
			.start = nbl_dev_vsi_user_start,
			.stop = nbl_dev_vsi_user_stop,
		},
		.vf_support = false,
		.only_nic_support = false,
		.userdev_support = true,
		.in_kernel = false,
		.use_independ_irq = false,
		.static_queue = false,
	},
	[NBL_VSI_XDP] = {
		.vsi_ops = {
			.register_vsi = nbl_dev_vsi_xdp_register,
			.setup = nbl_dev_vsi_xdp_setup,
			.remove = nbl_dev_vsi_xdp_remove,
			.start = nbl_dev_vsi_xdp_start,
			.stop = nbl_dev_vsi_xdp_stop,
		},
		.vf_support = false,
		.only_nic_support = true,
		.userdev_support = false,
		.in_kernel = true,
		.use_independ_irq = false,
		.static_queue = false,
	},
};

static int nbl_dev_vsi_build(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param)
{
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_vsi *vsi = NULL;
	u16 vsi_id = 0;
	int i;

	net_dev->vsi_ctrl.queue_num = 0;
	net_dev->vsi_ctrl.queue_free_offset = 0;

	/* Build all vsi, and alloc vsi_id for each of them */
	for (i = 0; i < NBL_VSI_MAX; i++) {
		if ((param->caps.is_vf && !vsi_tbl[i].vf_support) ||
		    (!param->caps.is_nic && vsi_tbl[i].only_nic_support) ||
		    (!param->caps.has_user && vsi_tbl[i].userdev_support))
			continue;

		vsi_id = serv_ops->get_vsi_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
						   NBL_COMMON_TO_MGT_PF(common), i);
		if (vsi_id == U16_MAX)
			continue;

		vsi = devm_kzalloc(NBL_DEV_MGT_TO_DEV(dev_mgt), sizeof(*vsi), GFP_KERNEL);
		if (!vsi)
			goto malloc_vsi_fail;

		vsi->ops = &vsi_tbl[i].vsi_ops;
		vsi->vsi_id = vsi_id;
		vsi->index = i;
		vsi->in_kernel = vsi_tbl[i].in_kernel;
		vsi->use_independ_irq = vsi_tbl[i].use_independ_irq;
		vsi->static_queue = vsi_tbl[i].static_queue;
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

struct nbl_dev_vsi *nbl_dev_vsi_select(struct nbl_dev_mgt *dev_mgt, u8 vsi_index)
{
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_dev_vsi *vsi = NULL;
	int i = 0;

	for (i = 0; i < NBL_VSI_MAX; i++) {
		vsi = net_dev->vsi_ctrl.vsi_list[i];
		if (vsi && vsi->index == vsi_index)
			return vsi;
	}

	return NULL;
}

static int nbl_dev_vsi_handle_netdev_event(u16 type, void *event_data, void *callback_data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)callback_data;
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct net_device *netdev = net_dev->netdev;
	bool *netdev_state = (bool *)event_data;
	struct nbl_dev_vsi *vsi;
	int ret;

	vsi = nbl_dev_vsi_select(dev_mgt, NBL_VSI_XDP);
	if (!vsi)
		return 0;

	if (*netdev_state) {
		ret = vsi->ops->start(dev_mgt, netdev, vsi);
		if (ret)
			nbl_err(common, NBL_DEBUG_VSI, "xdp-vsi start failed\n");
	} else {
		vsi->ops->stop(dev_mgt, vsi);
	}

	return 0;
}

static void nbl_dev_chan_log_module_alarm_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv;
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_chan_param_log_module_alarm para;
	int copy_len;

	copy_len = data_len < sizeof(para) ? data_len : sizeof(para);
	memcpy(&para, data, copy_len);

	nbl_log(common, module_temp_alarm_info[para.status].logvel,
		"[%llu] %s temp %u threshold %u\n", para.up_time,
		module_temp_alarm_info[para.status].alarm_info,
		para.temp, para.temp_th);
}

static void nbl_dev_register_log_module_alarm_chan_msg(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	if (!chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	chan_ops->register_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
			       NBL_CHAN_MSG_LOG_MODULE_ALARM,
			       nbl_dev_chan_log_module_alarm_resp, dev_mgt);
}

static int nbl_dev_chan_get_st_name_req(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_dev_st_dev *st_dev = NBL_DEV_MGT_TO_ST_DEV(dev_mgt);
	struct nbl_chan_send_info chan_send = {0};

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_ST_NAME, NULL, 0,
		      st_dev->real_st_name, sizeof(st_dev->real_st_name), 1);
	return chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
}

static void nbl_dev_chan_get_st_name_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv;
	struct nbl_dev_st_dev *st_dev = NBL_DEV_MGT_TO_ST_DEV(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(dev_mgt->common);
	struct nbl_chan_ack_info chan_ack;
	int ret;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_ST_NAME, msg_id,
		     0, st_dev->st_name, sizeof(st_dev->st_name));
	ret = chan_ops->send_ack(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_GET_ST_NAME);
}

static void nbl_dev_register_get_st_name_chan_msg(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	if (!chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	chan_ops->register_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
			       NBL_CHAN_MSG_GET_ST_NAME,
			       nbl_dev_chan_get_st_name_resp, dev_mgt);
}

static struct nbl_dev_net_ops netdev_ops[NBL_PRODUCT_MAX] = {
	{
		.setup_netdev_ops	= nbl_dev_setup_netops_leonis,
		.setup_ethtool_ops	= nbl_dev_setup_ethtool_ops_leonis,
#ifdef CONFIG_DCB
		.setup_dcbnl_ops	= nbl_dev_setup_dcbnl_ops_leonis,
#endif
	},
	{
		.setup_netdev_ops	= nbl_dev_setup_netops_draco,
		.setup_ethtool_ops	= nbl_dev_setup_ethtool_ops_draco,
#ifdef CONFIG_DCB
		.setup_dcbnl_ops	= nbl_dev_setup_dcbnl_ops_draco,
#endif
	},
};

static void nbl_dev_setup_net_dev_ops(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param)
{
	NBL_DEV_MGT_TO_NETDEV_OPS(dev_mgt) = &netdev_ops[param->product_type];
}

static int nbl_dev_setup_net_dev_vsi(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
				     struct nbl_dev_net *net_dev)
{
	struct nbl_event_callback callback = {0};
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_vsi *vsi;
	int i, ret = 0;
	u16 total_queue_num = 0, kernel_queue_num = 0, user_queue_num = 0;
	u16 dynamic_queue_max = 0, irq_queue_num = 0;

	ret = nbl_dev_vsi_build(dev_mgt, param);
	if (ret)
		goto vsi_build_fail;

	for (i = 0; i < NBL_VSI_MAX; i++) {
		vsi = net_dev->vsi_ctrl.vsi_list[i];

		if (!vsi)
			continue;

		ret = vsi->ops->register_vsi(dev_mgt, param, vsi);
		if (ret) {
			dev_err(NBL_DEV_MGT_TO_DEV(dev_mgt), "Vsi %d register failed", vsi->index);
			goto vsi_register_fail;
		}

		if (vsi->static_queue) {
			total_queue_num += vsi->queue_num;
		} else {
			if (dynamic_queue_max < vsi->queue_num)
				dynamic_queue_max = vsi->queue_num;
		}

		if (vsi->use_independ_irq)
			irq_queue_num += vsi->queue_num;

		if (vsi->in_kernel)
			kernel_queue_num += vsi->queue_num;
		else
			user_queue_num += vsi->queue_num;
	}

	/* all vsi's dynamic only support enable use one at the same time. */
	total_queue_num += dynamic_queue_max;

	/* the total queue set must before vsi stepup */
	net_dev->total_queue_num = total_queue_num;
	net_dev->kernel_queue_num = kernel_queue_num;
	net_dev->user_queue_num = user_queue_num;

	for (i = 0; i < NBL_VSI_MAX; i++) {
		vsi = net_dev->vsi_ctrl.vsi_list[i];

		if (!vsi)
			continue;

		if (!vsi->in_kernel)
			continue;

		ret = vsi->ops->setup(dev_mgt, param, vsi);
		if (ret) {
			dev_err(NBL_DEV_MGT_TO_DEV(dev_mgt), "Vsi %d setup failed", vsi->index);
			goto vsi_setup_fail;
		}
	}

	nbl_dev_register_net_irq(dev_mgt, irq_queue_num);

	callback.callback = nbl_dev_vsi_handle_netdev_event;
	callback.callback_data = dev_mgt;
	nbl_event_register(NBL_EVENT_NETDEV_STATE_CHANGE, &callback, NBL_COMMON_TO_VSI_ID(common),
			   NBL_COMMON_TO_BOARD_ID(common));

	return 0;

vsi_setup_fail:
vsi_register_fail:
	nbl_dev_vsi_destroy(dev_mgt);
vsi_build_fail:
	return ret;
}

static int nbl_dev_setup_net_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_resource_pt_tbl *pt_tbl = NBL_ADAPTER_TO_RES_PT_TBL(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_net **net_dev = &NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct net_device *netdev;
	struct nbl_netdev_priv *net_priv;
	struct nbl_dev_vsi *vsi;
	struct nbl_dev_vsi *user_vsi;
	struct nbl_dev_vsi *xdp_vsi;
	struct nbl_ring_param ring_param = {0};
	int ret = 0;
	u16 queue_num, xdp_queue_num = 0;
	bool hw_support_auto_mask;

	*net_dev = devm_kzalloc(dev, sizeof(struct nbl_dev_net), GFP_KERNEL);
	if (!*net_dev)
		return -ENOMEM;

	ret = nbl_dev_setup_net_dev_vsi(dev_mgt, param, *net_dev);
	if (ret) {
		dev_err(dev, "Setup vsi failed %d", ret);
		goto setup_vsi_failed;
	}

	nbl_dev_setup_net_dev_ops(dev_mgt, param);

	vsi = nbl_dev_vsi_select(dev_mgt, NBL_VSI_DATA);
	user_vsi = nbl_dev_vsi_select(dev_mgt, NBL_VSI_USER);
	xdp_vsi = nbl_dev_vsi_select(dev_mgt, NBL_VSI_XDP);
	if (xdp_vsi)
		xdp_queue_num = xdp_vsi->queue_num;
#if IS_ENABLED(CONFIG_MACSEC)
	ret = serv_ops->init_macsec(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	if (ret) {
		dev_err(dev, "init macsec failed\n");
		goto init_macsec_fail;
	}
#endif

	queue_num = vsi->queue_num;
	netdev = alloc_etherdev_mqs(sizeof(struct nbl_netdev_priv), queue_num, queue_num);
	if (!netdev) {
		dev_err(dev, "Alloc net device failed\n");
		ret = -ENOMEM;
		goto alloc_netdev_fail;
	}

	SET_NETDEV_DEV(netdev, dev);
	net_priv = netdev_priv(netdev);
	net_priv->adapter = adapter;
	net_priv->txrx_mgt = pt_tbl->txrx_mgt;
	nbl_dev_set_netdev_priv(netdev, vsi, user_vsi);
	(*net_dev)->netdev = netdev;

	ring_param.tx_ring_num = (*net_dev)->kernel_queue_num;
	ring_param.rx_ring_num = (*net_dev)->kernel_queue_num;
	ring_param.xdp_ring_offset =  (*net_dev)->kernel_queue_num - xdp_queue_num;
	ring_param.queue_size = vsi->queue_size;
	ring_param.netdev = netdev;
	ret = serv_ops->alloc_rings(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &ring_param);
	if (ret) {
		dev_err(dev, "Alloc rings failed\n");
		goto alloc_rings_fail;
	}

	hw_support_auto_mask =
		serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					      NBL_MSIX_AUTO_MASK_CAP);
	hw_support_auto_mask &= net_msix_mask_en;
	serv_ops->set_mask_en(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), hw_support_auto_mask);

	ret = serv_ops->setup_net_resource_mgt(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), netdev,
					       vsi->register_result.vlan_proto,
					       vsi->register_result.vlan_tci,
					       vsi->register_result.rate);
	if (ret) {
		dev_err(dev, "setup net mgt failed\n");
		goto setup_net_mgt_fail;
	}

	/* netdev build must before setup_txrx_queues. Because snoop check mac trust the mac
	 * if pf use ip link cfg the mac for vf. We judge the case will not permit accord queue
	 * has alloced when vf modify mac.
	 */
	ret = nbl_dev_build_net_dev(dev_mgt, param, netdev, vsi);
	if (ret) {
		dev_err(dev, "Build netdev failed, selected vsi %d\n", vsi->index);
		goto build_netdev_fail;
	}

	netif_carrier_off(netdev);

	nbl_dev_register_link_state_chan_msg(dev_mgt, netdev);
	nbl_dev_register_reset_event_chan_msg(dev_mgt);
	nbl_dev_register_keep_alive_chan_msg(dev_mgt);
	nbl_dev_register_notify_resume_status_chan_msg(dev_mgt);
	nbl_dev_register_log_module_alarm_chan_msg(dev_mgt);
	ret = nbl_dev_setup_devlink(dev_mgt, param);
	if (ret)
		goto setup_devlink_err;

	ret = nbl_dev_setup_devlink_port(dev_mgt, netdev, param);
	if (ret) {
		dev_err(dev, "Setup devlink_port failed\n");
		goto setup_devlink_port_fail;
	}

	nbl_dev_init_health(dev_mgt);

	if ((*net_dev)->total_vfs) {
		ret = serv_ops->setup_vf_resource(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
						(*net_dev)->total_vfs);
		if (ret)
			goto setup_vf_res_fail;
	}

	set_bit(NBL_DOWN, adapter->state);

	return 0;

setup_vf_res_fail:
	nbl_dev_destroy_health(dev_mgt);
	nbl_dev_remove_devlink_port(dev_mgt);
setup_devlink_port_fail:
	nbl_dev_remove_devlink(dev_mgt);
setup_devlink_err:
	nbl_dev_reset_netdev(netdev);
build_netdev_fail:
	serv_ops->remove_net_resource_mgt(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
setup_net_mgt_fail:
	serv_ops->free_rings(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
alloc_rings_fail:
	free_netdev(netdev);
alloc_netdev_fail:
#if IS_ENABLED(CONFIG_MACSEC)
	serv_ops->uninit_macsec(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
init_macsec_fail:
#endif
	nbl_dev_vsi_destroy(dev_mgt);
setup_vsi_failed:
	devm_kfree(dev, *net_dev);
	return ret;
}

static void nbl_dev_remove_net_dev(struct nbl_adapter *adapter)
{
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_net **net_dev = &NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct net_device *netdev;
	struct nbl_dev_vsi *vsi;
	int i = 0;

	if (!*net_dev)
		return;

	netdev = (*net_dev)->netdev;
	if (!common->is_vf)
		serv_ops->remove_vf_resource(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));

	serv_ops->free_rings(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));

	nbl_dev_destroy_health(dev_mgt);
	nbl_dev_remove_devlink_port(dev_mgt);
	nbl_dev_remove_devlink(dev_mgt);
	nbl_dev_reset_netdev(netdev);
	serv_ops->remove_net_resource_mgt(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	free_netdev(netdev);

#if IS_ENABLED(CONFIG_MACSEC)
	serv_ops->uninit_macsec(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
#endif

	for (i = 0; i < NBL_VSI_MAX; i++) {
		vsi = (*net_dev)->vsi_ctrl.vsi_list[i];

		if (!vsi)
			continue;

		vsi->ops->remove(dev_mgt, vsi);
	}

	nbl_dev_vsi_destroy(dev_mgt);
	devm_kfree(dev, *net_dev);
	*net_dev = NULL;
}

static int nbl_dev_setup_st_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	int ret;
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_st_dev *st_dev;

	/* unify restool's chardev for leonis/draco/rnic400. all pf create chardev */
	if (!serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_RESTOOL_CAP))
		return 0;

	st_dev = devm_kzalloc(dev, sizeof(struct nbl_dev_st_dev), GFP_KERNEL);
	if (!st_dev)
		return -ENOMEM;

	NBL_DEV_MGT_TO_ST_DEV(dev_mgt) = st_dev;
	ret = serv_ops->setup_st(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					 nbl_get_st_table(), st_dev->st_name);
	if (ret) {
		dev_err(dev, "create resource char dev failed\n");
		goto alloc_chardev_failed;
	}

	if (param->caps.has_ctrl) {
		nbl_dev_register_get_st_name_chan_msg(dev_mgt);
	} else {
		ret = nbl_dev_chan_get_st_name_req(dev_mgt);
		if (!ret)
			serv_ops->register_real_st_name(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
							st_dev->real_st_name);
		else
			dev_err(dev, "get real resource char dev failed\n");
	}

	return 0;
alloc_chardev_failed:
	devm_kfree(NBL_ADAPTER_TO_DEV(adapter), st_dev);
	NBL_DEV_MGT_TO_ST_DEV(dev_mgt) = NULL;
	return -1;
}

static void nbl_dev_remove_st_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_st_dev *st_dev = NBL_DEV_MGT_TO_ST_DEV(dev_mgt);

	if (!serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_RESTOOL_CAP))
		return;

	serv_ops->remove_st(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), nbl_get_st_table());

	devm_kfree(NBL_ADAPTER_TO_DEV(adapter), st_dev);
	NBL_DEV_MGT_TO_ST_DEV(dev_mgt) = NULL;
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
	struct nbl_dispatch_ops_tbl *disp_ops_tbl = NBL_ADAPTER_TO_DISP_OPS_TBL(adapter);
	int ret = 0;

	ret = nbl_dev_setup_dev_mgt(common, dev_mgt);
	if (ret)
		goto setup_mgt_fail;

	NBL_DEV_MGT_TO_SERV_OPS_TBL(*dev_mgt) = serv_ops_tbl;
	NBL_DEV_MGT_TO_CHAN_OPS_TBL(*dev_mgt) = chan_ops_tbl;
	NBL_DEV_MGT_TO_DISP_OPS_TBL(*dev_mgt) = disp_ops_tbl;
	(*dev_mgt)->adapter = adapter;

	ret = nbl_dev_setup_common_dev(adapter, param);
	if (ret)
		goto setup_common_dev_fail;

	if (param->caps.has_ctrl) {
		ret = nbl_dev_setup_ctrl_dev(adapter, param);
		if (ret)
			goto setup_ctrl_dev_fail;
	}

	ret = nbl_dev_setup_lag_dev(adapter, param);
	if (ret)
		goto setup_lag_dev_fail;

	ret = nbl_dev_setup_net_dev(adapter, param);
	if (ret)
		goto setup_net_dev_fail;

	ret = nbl_dev_setup_rdma_dev(adapter, param);
	if (ret)
		goto setup_rdma_dev_fail;

	ret = nbl_dev_setup_st_dev(adapter, param);
	if (ret)
		goto setup_st_dev_fail;

	ret = nbl_dev_setup_ops(dev, dev_ops_tbl, adapter);
	if (ret)
		goto setup_ops_fail;

	if (param->caps.has_user)
		nbl_dev_setup_user_dev(adapter);

	return 0;

setup_ops_fail:
	nbl_dev_remove_st_dev(adapter);
setup_st_dev_fail:
	nbl_dev_remove_rdma_dev(adapter);
setup_rdma_dev_fail:
	nbl_dev_remove_net_dev(adapter);
setup_net_dev_fail:
	nbl_dev_remove_lag_dev(adapter);
setup_lag_dev_fail:
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

	nbl_dev_remove_user_dev(adapter);

	nbl_dev_remove_ops(dev, dev_ops_tbl);

	nbl_dev_remove_st_dev(adapter);
	nbl_dev_remove_rdma_dev(adapter);
	nbl_dev_remove_net_dev(adapter);
	nbl_dev_remove_lag_dev(adapter);
	nbl_dev_remove_ctrl_dev(adapter);
	nbl_dev_remove_common_dev(adapter);

	nbl_dev_remove_dev_mgt(common, dev_mgt);
}

static void nbl_dev_notify_dev_prepare_reset(struct nbl_dev_mgt *dev_mgt,
					     enum nbl_reset_event event)
{
	int func_num = 0;
	unsigned long cur_func = 0;
	unsigned long next_func = 0;
	unsigned long *func_bitmap;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_chan_send_info chan_send;

	func_bitmap = devm_kcalloc(NBL_COMMON_TO_DEV(common), BITS_TO_LONGS(NBL_MAX_FUNC),
				   sizeof(long), GFP_KERNEL);
	if (!func_bitmap)
		return;

	serv_ops->get_active_func_bitmaps(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), func_bitmap,
					  NBL_MAX_FUNC);
	memset(dev_mgt->ctrl_dev->task_info.reset_status, 0,
	       sizeof(dev_mgt->ctrl_dev->task_info.reset_status));
	/* clear ctrl_dev func_id, and do it last */
	clear_bit(NBL_COMMON_TO_MGT_PF(common), func_bitmap);

	cur_func = NBL_COMMON_TO_MGT_PF(common);
	while (1) {
		next_func = find_next_bit(func_bitmap, NBL_MAX_FUNC, cur_func + 1);
		if (next_func >= NBL_MAX_FUNC)
			break;

		cur_func = next_func;
		dev_mgt->ctrl_dev->task_info.reset_status[cur_func] = NBL_RESET_SEND;
		NBL_CHAN_SEND(chan_send, cur_func, NBL_CHAN_MSG_NOTIFY_RESET_EVENT, &event,
			      sizeof(event), NULL, 0, 0);
		chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
		func_num++;
		if (func_num >= NBL_DEV_BATCH_RESET_FUNC_NUM) {
			usleep_range(NBL_DEV_BATCH_RESET_USEC, NBL_DEV_BATCH_RESET_USEC * 2);
			func_num = 0;
		}
	}

	if (func_num)
		usleep_range(NBL_DEV_BATCH_RESET_USEC, NBL_DEV_BATCH_RESET_USEC * 2);

	/* ctrl dev need proc last, basecase reset task will close mailbox */
	dev_mgt->ctrl_dev->task_info.reset_status[NBL_COMMON_TO_MGT_PF(common)] = NBL_RESET_SEND;
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_NOTIFY_RESET_EVENT,
		      NULL, 0, NULL, 0, 0);
	chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
	usleep_range(NBL_DEV_BATCH_RESET_USEC, NBL_DEV_BATCH_RESET_USEC * 2);

	cur_func = NBL_COMMON_TO_MGT_PF(common);
	while (1) {
		if (dev_mgt->ctrl_dev->task_info.reset_status[cur_func] == NBL_RESET_SEND)
			nbl_info(common, NBL_DEBUG_MAIN, "func %lu reset failed", cur_func);

		next_func = find_next_bit(func_bitmap, NBL_MAX_FUNC, cur_func + 1);
		if (next_func >= NBL_MAX_FUNC)
			break;

		cur_func = next_func;
	}

	devm_kfree(NBL_COMMON_TO_DEV(common), func_bitmap);
}

static void nbl_dev_handle_fatal_err(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_chan_param_notify_fw_reset_info fw_reset = {0};
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev_mgt->net_dev->netdev);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_chan_send_info chan_send;

	if (test_and_set_bit(NBL_FATAL_ERR, adapter->state)) {
		nbl_info(common, NBL_DEBUG_MAIN, "dev in fatal_err status already.");
		return;
	}

	nbl_dev_disable_abnormal_irq(dev_mgt);
	nbl_dev_ctrl_task_stop(dev_mgt);
	nbl_dev_notify_dev_prepare_reset(dev_mgt, NBL_HW_FATAL_ERR_EVENT);

	/* notify emp shutdown dev */
	fw_reset.type = NBL_FW_HIGH_TEMP_RESET;
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_NOTITY_FW_RESET, &fw_reset, sizeof(fw_reset), NULL, 0, 0);
	chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);

	chan_ops->set_queue_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_ABNORMAL,
				  NBL_CHAN_TYPE_ADMINQ, true);
	serv_ops->set_hw_status(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_HW_FATAL_ERR);
	nbl_info(common, NBL_DEBUG_MAIN, "dev in fatal_err status.");
}

/* ----------  Dev start process  ---------- */
static int nbl_dev_start_ctrl_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	int err = 0;

	err = serv_ops->init_chip(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	if (err) {
		dev_err(dev, "ctrl dev chip_init failed\n");
		goto init_chip_fail;
	}

	err = serv_ops->start_mgt_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	if (err)
		goto start_mgt_flow_fail;

	err = nbl_dev_request_sfp_plug_irq(dev_mgt);
	if (err)
		goto request_sfp_plug_irq_err;

	err = nbl_dev_enable_sfp_plug_irq(dev_mgt);
	if (err)
		goto enable_sfp_plug_irq_err;

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

	/* Notify emp driver ready */
	serv_ops->enable_driver(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	nbl_dev_get_port_attributes(dev_mgt);
	nbl_dev_init_port(dev_mgt);
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
	nbl_dev_disable_sfp_plug_irq(dev_mgt);
enable_sfp_plug_irq_err:
	nbl_dev_free_sfp_plug_irq(dev_mgt);
request_sfp_plug_irq_err:
	serv_ops->stop_mgt_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
start_mgt_flow_fail:
	serv_ops->destroy_chip(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
init_chip_fail:
	return err;
}

static void nbl_dev_stop_ctrl_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	if (!NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt))
		return;

	nbl_dev_ctrl_task_stop(dev_mgt);
	nbl_dev_enable_port(dev_mgt, false);
	nbl_dev_disable_adminq_irq(dev_mgt);
	nbl_dev_free_adminq_irq(dev_mgt, &NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt)->task_info);
	nbl_dev_disable_abnormal_irq(dev_mgt);
	nbl_dev_free_abnormal_irq(dev_mgt);
	nbl_dev_disable_sfp_plug_irq(dev_mgt);
	nbl_dev_free_sfp_plug_irq(dev_mgt);
	serv_ops->stop_mgt_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	serv_ops->destroy_chip(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
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
	serv_ops->set_port_state_update(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), true);
}

static void nbl_dev_chan_notify_reset_event_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv;
	enum nbl_reset_event event = *(enum nbl_reset_event *)data;

	dev_mgt->common_dev->reset_task.event = event;
	nbl_common_queue_work(&dev_mgt->common_dev->reset_task.task, false);
}

static void nbl_dev_chan_ack_reset_event_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv;

	WRITE_ONCE(dev_mgt->ctrl_dev->task_info.reset_status[src_id], NBL_RESET_DONE);
}

static int nbl_dev_setup_rep_netdev(struct nbl_adapter *adapter, struct nbl_init_param *param,
				    struct nbl_rep_data *rep)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_resource_pt_tbl *pt_tbl = NBL_ADAPTER_TO_RES_PT_TBL(adapter);
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct net_device *netdev;
	struct nbl_netdev_priv *net_priv;
	struct nbl_register_net_result register_result = { 0 };
	u16 tx_queue_num = 1, rx_queue_num = 1;
	int ret = 0;

	nbl_dev_get_rep_feature(adapter, &register_result);

	netdev = alloc_etherdev_mqs(sizeof(struct nbl_netdev_priv), tx_queue_num, rx_queue_num);
	if (!netdev) {
		dev_err(dev, "Alloc net device failed\n");
		ret = -ENOMEM;
		goto alloc_fail;
	}

	net_priv = netdev_priv(netdev);
	net_priv->adapter = adapter;
	rep->netdev = netdev;
	net_priv->rep = rep;
	net_priv->netdev = netdev;
	net_priv->txrx_mgt = pt_tbl->txrx_mgt;

	SET_NETDEV_DEV(netdev, dev);
	ret = nbl_dev_cfg_netdev(netdev, dev_mgt, param, &register_result);
	if (ret) {
		dev_err(dev, "Cfg net device failed, ret=%d\n", ret);
		goto cfg_netdev_fail;
	}

	netif_carrier_off(netdev);
	ret = register_netdev(netdev);
	if (ret) {
		dev_err(dev, "Register netdev failed, ret=%d\n", ret);
		goto register_netdev_fail;
	}
	return 0;

register_netdev_fail:
cfg_netdev_fail:
	free_netdev(netdev);
	rep->netdev = NULL;
alloc_fail:
	return ret;
}

static int nbl_dev_eswitch_load_rep(struct nbl_adapter *adapter, int num_vfs)
{
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_init_param param;
	struct nbl_dev_rep *rep_dev;
	struct nbl_alloc_rep_data_param rep_prm = {0};
	int i, ret = 0;
	u16 vf_base_vsi_id;
	char net_dev_name[IFNAMSIZ];

	rep_dev = devm_kzalloc(dev, sizeof(struct nbl_dev_rep), GFP_KERNEL);
	if (!rep_dev)
		return -ENOMEM;

	memset(&param, 0, sizeof(param));

	NBL_DEV_MGT_TO_REP_DEV(dev_mgt) = rep_dev;
	rep_dev->num_vfs = num_vfs;
	param.is_rep = true;
	param.pci_using_dac = NBL_COMMON_TO_PCI_USING_DAC(common);
	rep_dev->rep = devm_kzalloc(dev, num_vfs * sizeof(struct nbl_rep_data), GFP_KERNEL);
	if (!rep_dev->rep)
		return -ENOMEM;

	vf_base_vsi_id = serv_ops->get_vf_base_vsi_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
						      NBL_COMMON_TO_MGT_PF(common));
	rep_prm.num_vfs = num_vfs;
	rep_prm.vf_base_vsi_id = vf_base_vsi_id;
	ret = serv_ops->alloc_rep_data(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &rep_prm);

	for (i = 0; i < num_vfs; i++) {
		rep_dev->rep[i].rep_vsi_id = vf_base_vsi_id + i;
		ret = nbl_dev_setup_rep_netdev(adapter, &param, &rep_dev->rep[i]);
		if (ret)
			return ret;
		nbl_dev_get_rep_queue_num(adapter, &rep_dev->rep[i].base_queue_id,
					  &rep_dev->rep[i].rep_queue_num);

		/* add dev_name sysfs here */
		snprintf(net_dev_name, IFNAMSIZ, "%s_%d", net_dev->netdev->name, i);
		nbl_net_init_netname_attr(&rep_dev->rep[i].dev_name_attr, net_dev_name);
		ret = sysfs_create_file(&rep_dev->rep[i].netdev->dev.kobj,
					&rep_dev->rep[i].dev_name_attr.attr);
		if (ret) {
			dev_err(dev, "nbl rep add rep_id net-fs failed");
			return ret;
		}
		serv_ops->set_rep_netdev_info(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					      &rep_dev->rep[i]);
	}

	dev_info(dev, "nbl dev switch load rep success\n");
	return 0;
}

static int nbl_dev_eswitch_unload_rep(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_rep *rep_dev = NBL_DEV_MGT_TO_REP_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_rep_data *rep_data = NULL;
	struct device *dev;
	struct net_device *netdev;
	int i;

	if (!rep_dev)
		return -ENODEV;

	dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	rep_data = rep_dev->rep;
	if (!rep_data) {
		devm_kfree(dev, rep_dev);
		NBL_DEV_MGT_TO_REP_DEV(dev_mgt) = NULL;
		return -ENODEV;
	}

	serv_ops->unset_rep_netdev_info(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	for (i = 0; i < rep_dev->num_vfs; i++) {
		netdev = rep_data[i].netdev;
		if (!netdev)
			continue;
		sysfs_remove_file(&netdev->dev.kobj, &rep_data[i].dev_name_attr.attr);
		unregister_netdev(netdev);
		nbl_dev_reset_netdev(netdev);
		free_netdev(netdev);
	}
	serv_ops->free_rep_data(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	devm_kfree(dev, rep_data);
	devm_kfree(dev, rep_dev);
	NBL_DEV_MGT_TO_REP_DEV(dev_mgt) = NULL;

	return 0;
}

static int nbl_dev_eswitch_mode_to_devlink(u16 cur_eswitch_mode, u16 *devlink_eswitch_mode)
{
	switch (cur_eswitch_mode) {
	case NBL_ESWITCH_LEGACY:
		*devlink_eswitch_mode = DEVLINK_ESWITCH_MODE_LEGACY;
		break;
	case NBL_ESWITCH_OFFLOADS:
		*devlink_eswitch_mode = DEVLINK_ESWITCH_MODE_SWITCHDEV;
		break;
	default:
		*devlink_eswitch_mode = DEVLINK_ESWITCH_MODE_LEGACY;
	}
	return 0;
}

static int nbl_dev_eswitch_mode_from_devlink(u16 devlink_eswitch_mode, u16 *cfg_eswitch_mode)
{
	switch (devlink_eswitch_mode) {
	case DEVLINK_ESWITCH_MODE_LEGACY:
		*cfg_eswitch_mode = NBL_ESWITCH_LEGACY;
		break;
	case DEVLINK_ESWITCH_MODE_SWITCHDEV:
		*cfg_eswitch_mode = NBL_ESWITCH_OFFLOADS;
		break;
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

int nbl_dev_destroy_rep(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct net_device *netdev = net_dev->netdev;
	u16 eswitch_mode = 0;
	int ret = 0;

	eswitch_mode = serv_ops->get_eswitch_mode(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	if (eswitch_mode == NBL_ESWITCH_OFFLOADS) {
		ret = nbl_dev_eswitch_unload_rep(dev_mgt);
		if (ret)
			return ret;
		ret = serv_ops->free_rep_queue_mgt(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
		if (ret)
			return ret;
		serv_ops->unregister_indr_dev_tc_offload(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), netdev);
	}

	return ret;
}

int nbl_dev_create_rep(void *p, int num_vfs)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct net_device *netdev = net_dev->netdev;
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	u16 eswitch_mode = 0;
	int ret = 0;

	eswitch_mode = serv_ops->get_eswitch_mode(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	dev_info(dev, "dev create rep num_vfs:%d, eswitch_mode:%d\n", num_vfs, eswitch_mode);
	if (eswitch_mode == NBL_ESWITCH_OFFLOADS) {
		ret = nbl_dev_eswitch_load_rep(adapter, num_vfs);
		if (ret) {
			nbl_dev_eswitch_unload_rep(dev_mgt);
			return ret;
		}
		ret = serv_ops->alloc_rep_queue_mgt(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), netdev);
		if (ret)
			return ret;
		ret = serv_ops->register_indr_dev_tc_offload(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
							     netdev);
	}

	return ret;
}

int nbl_dev_setup_vf_config(void *p, int num_vfs)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->setup_vf_config(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), num_vfs, false);
}

void nbl_dev_register_dev_name(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);

	/* get pf_name then register it to AF */
	serv_ops->register_dev_name(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
				    common->vsi_id, net_dev->netdev->name);
}

void nbl_dev_get_dev_name(void *p, char *dev_name)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);

	serv_ops->get_dev_name(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), common->vsi_id, dev_name);
}

void nbl_dev_remove_vf_config(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	return serv_ops->remove_vf_config(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}

static int nbl_dev_init_offload_mode(struct nbl_dev_mgt *dev_mgt, u16 vsi_id)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	int ret = 0;

	ret = serv_ops->disable_phy_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), common->eth_id);
	if (ret)
		return ret;
	serv_ops->init_acl(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	ret = serv_ops->set_upcall_rule(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), common->eth_id, vsi_id);
	if (ret)
		goto fail_set_upcall_rule;

	/* eswitch mode set, start CMDQ or add reference */
	ret = serv_ops->switchdev_init_cmdq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	if (ret < 0 || ret >= NBL_TC_FLOW_INST_COUNT)
		goto fail_init_cmdq;
	common->tc_inst_id = ret;

	ret = serv_ops->set_tc_flow_info(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	if (ret)
		goto fail_set_tc_flow_info;

	ret = serv_ops->get_tc_flow_info(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	if (ret)
		goto fail_get_tc_flow_info;

	return 0;

fail_get_tc_flow_info:
	serv_ops->unset_tc_flow_info(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
fail_set_tc_flow_info:
	serv_ops->switchdev_deinit_cmdq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
fail_init_cmdq:
	serv_ops->unset_upcall_rule(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), common->eth_id);
fail_set_upcall_rule:
	serv_ops->uninit_acl(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	serv_ops->enable_phy_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), common->eth_id);
	return ret;
}

static int nbl_dev_uninit_offload_mode(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	int ret = 0;

	ret = serv_ops->enable_phy_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), common->eth_id);
	if (ret)
		return ret;
	ret = serv_ops->unset_upcall_rule(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), common->eth_id);
	if (ret)
		goto fail_unset_upcall_rule;
	serv_ops->uninit_acl(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));

	return 0;

fail_unset_upcall_rule:
	serv_ops->disable_phy_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), common->eth_id);
	return ret;
}

static void nbl_dev_destroy_flow_res(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	/* unset tc flow info */
	serv_ops->unset_tc_flow_info(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	serv_ops->get_tc_flow_info(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));

	/* stop CMDQ or reduce its reference */
	serv_ops->switchdev_deinit_cmdq(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}

static void nbl_dev_remove_rep_res(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_vsi *vsi = dev_mgt->net_dev->vsi_ctrl.vsi_list[NBL_VSI_CTRL];
	u16 cur_eswitch_mode = NBL_ESWITCH_NONE;

	cur_eswitch_mode = serv_ops->get_eswitch_mode(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	if (cur_eswitch_mode == NBL_ESWITCH_OFFLOADS) {
		nbl_dev_eswitch_unload_rep(dev_mgt);
		serv_ops->free_rep_queue_mgt(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
		serv_ops->set_eswitch_mode(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_ESWITCH_NONE);
		vsi->ops->stop(dev_mgt, vsi);
		nbl_dev_destroy_flow_res(dev_mgt);
		nbl_dev_uninit_offload_mode(dev_mgt);
	}
}

static int nbl_dev_setup_devlink_port(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev,
				      struct nbl_init_param *param)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct devlink_port *devlink_port;
	struct devlink_port_attrs attrs = {0};
	int flavour = 0;
	int ret = 0;

	devlink_port = devm_kzalloc(dev, sizeof(*devlink_port), GFP_KERNEL);
	if (!devlink_port)
		return -ENOMEM;

	if (param->caps.is_vf) {
		flavour = DEVLINK_PORT_FLAVOUR_VIRTUAL;

		attrs.flavour = flavour;
		devlink_port_attrs_set(devlink_port, &attrs);
	} else {
		attrs.flavour = DEVLINK_PORT_FLAVOUR_PHYSICAL;
		attrs.phys.port_number = NBL_COMMON_TO_LOGIC_ETH_ID(common);
		devlink_port_attrs_set(devlink_port, &attrs);
	}

	ret = devlink_port_register(dev_common->devlink, devlink_port,
				    dev_mgt->common->vsi_id);
	if (ret) {
		dev_err(dev, "devlink_port_register failed %d\n", ret);
		devm_kfree(dev, devlink_port);
		return ret;
	}
	common->devlink_port = devlink_port;
	SET_NETDEV_DEVLINK_PORT(netdev, devlink_port);

	return ret;
}

static void nbl_dev_remove_devlink_port(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);

	if (common->devlink_port) {
		devlink_port_unregister(common->devlink_port);
		devm_kfree(dev, common->devlink_port);
	}
}

static int nbl_dev_start_net_dev(struct nbl_adapter *adapter, struct nbl_init_param *param,
				 bool probe_stage)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(dev_common);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct net_device *netdev = net_dev->netdev;
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_dev_vsi *vsi;
	u16 net_vector_id = 0;
	int ret;

	vsi = nbl_dev_vsi_select(dev_mgt, NBL_VSI_DATA);
	if (!vsi)
		return -EFAULT;

	serv_ops->set_spoof_check_addr(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), netdev->perm_addr);
	nbl_dev_set_eth_mac_addr(dev_mgt, netdev);

	serv_ops->cpu_affinity_init(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->queue_num);
	net_vector_id = msix_info->serv_info[NBL_MSIX_NET_TYPE].base_vector_id;
	ret = serv_ops->setup_txrx_queues(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  vsi->vsi_id, net_dev->total_queue_num, net_vector_id);
	if (ret) {
		dev_err(dev, "Set queue map failed\n");
		goto set_queue_fail;
	}

	ret = serv_ops->init_hw_stats(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), param);
	if (ret) {
		dev_err(dev, "init hw stats failed\n");
		goto init_hw_stats_fail;
	}

	serv_ops->start_net_resource_mgt(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));

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

	rtnl_lock();
	serv_ops->change_mtu(netdev, netdev->mtu);
	rtnl_unlock();

	nbl_ldev_add_netdev(dev_mgt, netdev);

	if (probe_stage) {
		ret = register_netdev(netdev);
		if (ret) {
			dev_err(dev, "Register netdev failed\n");
			goto register_netdev_fail;
		}

		ret = nbl_netdev_add_sysfs(net_dev);
		if (ret) {
			dev_err(dev, "add netdev sysfs failed\n");
			if (ret)
				goto add_sysfs_fail;
		}
	} else {
		rtnl_lock();
		if (netif_running(netdev))
			serv_ops->netdev_open(netdev);
		netif_device_attach(dev_mgt->net_dev->netdev); /* to avoid ethtool operation */
		rtnl_unlock();
	}

	return 0;

add_sysfs_fail:
	unregister_netdev(netdev);
register_netdev_fail:
	nbl_ldev_remove_netdev(dev_mgt, netdev);
	nbl_dev_free_net_irq(dev_mgt);
request_irq_fail:
	vsi->ops->stop(dev_mgt, vsi);
start_vsi_fail:
	serv_ops->stop_net_resource_mgt(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	serv_ops->remove_hw_stats(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
init_hw_stats_fail:
	serv_ops->remove_txrx_queues(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
set_queue_fail:
	return ret;
}

static void nbl_dev_stop_net_dev(struct nbl_adapter *adapter, bool remove_stage)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_vsi *vsi;
	struct net_device *netdev;

	if (!net_dev)
		return;

	netdev = net_dev->netdev;
	nbl_dev_remove_rep_res(dev_mgt);
	rtnl_lock();
	serv_ops->change_mtu(netdev, 0);
	serv_ops->reset_tc_mqprio(netdev);
	rtnl_unlock();

	rtnl_lock();
	if (netif_running(netdev))
		serv_ops->netdev_stop(dev_mgt->net_dev->netdev);
	/* unregister_netdev's netdev must be present  */
	if (!remove_stage) {
		netif_device_detach(dev_mgt->net_dev->netdev); /* to avoid ethtool operation */
	} else {
		rtnl_unlock();
		nbl_netdev_remove_sysfs(dev_mgt->net_dev);
		unregister_netdev(netdev);
		rtnl_lock();
		netif_device_detach(netdev);
	}
	rtnl_unlock();

	nbl_ldev_remove_netdev(dev_mgt, netdev);
	nbl_dev_free_net_irq(dev_mgt);

	vsi = nbl_dev_vsi_select(dev_mgt, NBL_VSI_DATA);
	if (!vsi)
		return;

	vsi->ops->stop(dev_mgt, vsi);
	serv_ops->stop_net_resource_mgt(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	serv_ops->remove_hw_stats(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	serv_ops->remove_txrx_queues(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), vsi->vsi_id);
}

static int nbl_dev_resume_net_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
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
	serv_ops->start_net_dev_timer(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	return ret;
}

static void nbl_dev_suspend_net_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct net_device *netdev;

	if (!net_dev)
		return;

	netdev = net_dev->netdev;
	serv_ops->stop_net_dev_timer(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	netif_device_detach(netdev);
	nbl_dev_free_net_irq(dev_mgt);
}

static int nbl_dev_get_devlink_eswitch_mode(struct devlink *devlink, u16 *mode)
{
	struct nbl_devlink_priv *priv = devlink_priv(devlink);
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv->dev_mgt;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct pci_dev *pdev = NBL_COMMON_TO_PDEV(common);
	struct nbl_adapter *adapter = NULL;
	u16 cur_eswitch_mode = NBL_ESWITCH_NONE;

	adapter = pci_get_drvdata(pdev);
	if (!adapter)
		return -EINVAL;

	cur_eswitch_mode = serv_ops->get_eswitch_mode(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	return nbl_dev_eswitch_mode_to_devlink(cur_eswitch_mode, mode);
}

static int nbl_dev_set_devlink_eswitch_mode(struct devlink *devlink, u16 mode,
					    struct netlink_ext_ack *extack)
{
	struct nbl_devlink_priv *priv = devlink_priv(devlink);
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv->dev_mgt;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct pci_dev *pdev = NBL_COMMON_TO_PDEV(common);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_adapter *adapter = NULL;
	struct nbl_dev_vsi *vsi = dev_mgt->net_dev->vsi_ctrl.vsi_list[NBL_VSI_CTRL];
	struct nbl_event_offload_status_data event_data = {0};
	int num_vfs = 0;
	u16 cfg_eswitch_mode = NBL_ESWITCH_NONE;
	u16 cur_eswitch_mode = NBL_ESWITCH_NONE;
	int ret = 0;

	num_vfs = pci_num_vf(pdev);
	adapter = pci_get_drvdata(pdev);
	if (!adapter)
		return -EINVAL;
	ret = nbl_dev_eswitch_mode_from_devlink(mode, &cfg_eswitch_mode);
	if (ret)
		return ret;
	cur_eswitch_mode = serv_ops->get_eswitch_mode(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	if (cur_eswitch_mode == cfg_eswitch_mode)
		return 0;

	if (!vsi)
		return -ENOENT;

	if (cfg_eswitch_mode == NBL_ESWITCH_OFFLOADS) {
		ret = vsi->ops->start(dev_mgt, dev_mgt->net_dev->netdev, vsi);
		if (ret)
			return ret;

		ret = nbl_dev_init_offload_mode(dev_mgt, vsi->vsi_id);
		if (ret) {
			dev_err(dev, "dev fail init offload mode\n");
			return -EBUSY;
		}
		serv_ops->set_eswitch_mode(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), cfg_eswitch_mode);
		if (num_vfs) {
			ret = nbl_dev_create_rep(adapter, num_vfs);
			if (ret)
				goto fail_cfg_rep;
		}

		event_data.pf_vsi_id = NBL_COMMON_TO_VSI_ID(common);
		event_data.status = true;
		nbl_event_notify(NBL_EVENT_OFFLOAD_STATUS_CHANGED, &event_data,
				 NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	} else if (cur_eswitch_mode == NBL_ESWITCH_OFFLOADS) {
		if (num_vfs) {
			ret = nbl_dev_destroy_rep(adapter);
			if (ret)
				goto fail_cfg_rep;
		}
		serv_ops->set_eswitch_mode(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_ESWITCH_NONE);
		nbl_dev_destroy_flow_res(dev_mgt);
		ret = nbl_dev_uninit_offload_mode(dev_mgt);
		if (ret) {
			dev_err(dev, "dev fail uninit offload mode\n");
			return -EBUSY;
		}
		vsi->ops->stop(dev_mgt, vsi);

		serv_ops->set_eswitch_mode(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), cfg_eswitch_mode);

		event_data.pf_vsi_id = NBL_COMMON_TO_VSI_ID(common);
		event_data.status = false;
		nbl_event_notify(NBL_EVENT_OFFLOAD_STATUS_CHANGED, &event_data,
				 NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	}
	return 0;

fail_cfg_rep:
	if (cfg_eswitch_mode == NBL_ESWITCH_OFFLOADS) {
		serv_ops->set_eswitch_mode(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), cur_eswitch_mode);
		vsi->ops->stop(dev_mgt, vsi);
		ret = nbl_dev_uninit_offload_mode(dev_mgt);
		if (ret)
			dev_err(dev, "dev fail uninit offload mode when rep create fail\n");
	} else if (cur_eswitch_mode == NBL_ESWITCH_OFFLOADS) {
		ret = nbl_dev_init_offload_mode(dev_mgt, vsi->vsi_id);
		if (ret)
			dev_err(dev, "dev fail init offload mode when rep destroy fail\n");
	}
	return -EBUSY;
}

/* ----------  Devlink config  ---------- */
static void nbl_dev_devlink_free(void *devlink_ptr)
{
	devlink_free((struct devlink *)devlink_ptr);
}

static int nbl_dev_setup_devlink(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param)
{
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct devlink *devlink;
	struct devlink_ops *devlink_ops;
	struct nbl_devlink_priv *priv;
	int ret = 0;

	devlink_ops = devm_kzalloc(dev, sizeof(*devlink_ops), GFP_KERNEL);
	if (!devlink_ops)
		return -ENOMEM;

	if (!param->caps.is_vf) {
		devlink_ops->eswitch_mode_set = nbl_dev_set_devlink_eswitch_mode;
		devlink_ops->eswitch_mode_get = nbl_dev_get_devlink_eswitch_mode;
	devlink_ops->info_get = serv_ops->get_devlink_info;
		if (param->caps.has_ctrl)
			devlink_ops->flash_update = serv_ops->update_devlink_flash;
	}

	devlink = devlink_alloc(devlink_ops, sizeof(*priv), dev);

	if (!devlink)
		return -ENOMEM;

	dev_common->devlink_ops = devlink_ops;

	if (devm_add_action(dev, nbl_dev_devlink_free, devlink)) {
		devlink_free(devlink);
		return -EFAULT;
	}
	priv = devlink_priv(devlink);
	priv->priv = NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt);
	priv->dev_mgt = dev_mgt;

	devlink_register(devlink);

	dev_common->devlink = devlink;
	return ret;
}

static void nbl_dev_remove_devlink(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);

	if (dev_common->devlink) {
		devlink_unregister(dev_common->devlink);
		devm_kfree(NBL_DEV_MGT_TO_DEV(dev_mgt), dev_common->devlink_ops);
	}
}

static int nbl_dev_start_common_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	int ret = 0;

	nbl_dev_get_firmware_version(dev_mgt);
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

	ret = nbl_dev_wait_my_ctrl_initdone(adapter);
	if (ret)
		goto wait_ctrl_init_err;

	return 0;

wait_ctrl_init_err:
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

static void nbl_dev_stop_common_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);

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

	return 0;
}

static void nbl_dev_suspend_common_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);

	nbl_dev_free_mailbox_irq(dev_mgt);
}

int nbl_dev_start(void *p, struct nbl_init_param *param, bool probe_stage)
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

	ret = nbl_dev_start_net_dev(adapter, param, probe_stage);
	if (ret)
		goto start_net_dev_fail;

	ret = nbl_dev_start_rdma_dev(adapter);
	if (ret)
		goto start_rdma_dev_fail;

	return 0;

start_rdma_dev_fail:
	nbl_dev_stop_net_dev(adapter, probe_stage);
start_net_dev_fail:
	nbl_dev_stop_ctrl_dev(adapter);
start_ctrl_dev_fail:
	nbl_dev_stop_common_dev(adapter);
start_common_dev_fail:
	return ret;
}

void nbl_dev_stop(void *p, bool remove_stage)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;

	nbl_dev_stop_rdma_dev(adapter);
	nbl_dev_stop_net_dev(adapter, remove_stage);
	nbl_dev_stop_ctrl_dev(adapter);
	nbl_dev_stop_common_dev(adapter);
}

int nbl_dev_resume(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct nbl_init_param *param = &adapter->init_param;
	int ret = 0;

	dev_info(dev, "nbl resume\n");

	pci_set_power_state(adapter->pdev, PCI_D0);
	pci_restore_state(adapter->pdev);
	pci_save_state(adapter->pdev);

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

	ret = nbl_dev_resume_rdma_dev(adapter);
	if (ret)
		goto start_rdma_dev_fail;

	dev_info(dev, "nbl resume ok\n");

	return 0;

start_rdma_dev_fail:
	nbl_dev_stop_net_dev(adapter, false);
start_net_dev_fail:
	nbl_dev_stop_ctrl_dev(adapter);
start_ctrl_dev_fail:
	nbl_dev_stop_common_dev(adapter);
start_common_dev_fail:
	dev_info(dev, "nbl resume failed %d\n", ret);
	return ret;
}

int nbl_dev_suspend(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);

	dev_info(dev, "nbl suspend\n");

	nbl_dev_suspend_rdma_dev(adapter);
	nbl_dev_suspend_net_dev(adapter);
	nbl_dev_stop_ctrl_dev(adapter);
	nbl_dev_suspend_common_dev(adapter);

	pci_save_state(adapter->pdev);
	pci_wake_from_d3(adapter->pdev, common->wol_ena);
	pci_set_power_state(adapter->pdev, PCI_D3hot);

	dev_info(dev, "nbl suspend ok\n");

	return 0;
}

void nbl_dev_stop_adminq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	int i = 5;
	int ret;

	if (!NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt))
		return;

	chan_ops->set_queue_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_ABNORMAL,
				  NBL_CHAN_TYPE_ADMINQ, true);

	nbl_dev_disable_adminq_irq(dev_mgt);
	nbl_dev_free_adminq_irq(dev_mgt, &NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt)->task_info);

	while (i--) {
		ret = nbl_dev_remove_chan_queue(dev_mgt, NBL_CHAN_TYPE_ADMINQ);
		if (!ret)
			break;

		msleep(NBL_DEV_FW_RESET_WAIT_TIME); // wait adminq timeout
	}

	if (ret)
		nbl_err(common, NBL_DEBUG_MAIN, "stop adminq failed\n");
}

int nbl_dev_start_adminq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	int ret;

	if (!NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt))
		return 0;

	ret = nbl_dev_setup_chan_qinfo(dev_mgt, NBL_CHAN_TYPE_ADMINQ);
	if (ret)
		goto setup_chan_info_failed;

	ret = nbl_dev_setup_chan_queue(dev_mgt, NBL_CHAN_TYPE_ADMINQ);
	if (ret)
		goto setup_chan_queue_failed;

	ret = nbl_dev_request_adminq_irq(dev_mgt, &NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt)->task_info);
	if (ret)
		goto req_adminq_irq_failed;

	ret = nbl_dev_enable_adminq_irq(dev_mgt);
	if (ret)
		goto enable_adminq_irq_failed;

	chan_ops->set_queue_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_ABNORMAL,
					NBL_CHAN_TYPE_ADMINQ, false);

	return 0;

enable_adminq_irq_failed:
	nbl_dev_free_adminq_irq(dev_mgt, &NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt)->task_info);
req_adminq_irq_failed:
	nbl_dev_remove_chan_queue(dev_mgt, NBL_CHAN_TYPE_ADMINQ);
setup_chan_queue_failed:
setup_chan_info_failed:
	nbl_err(common, NBL_DEBUG_MAIN, "start adminq failed\n");

	return ret;
}

static void nbl_dev_stop_mailbox(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	int i = 5;
	int ret;

	chan_ops->set_queue_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_ABNORMAL,
				  NBL_CHAN_TYPE_MAILBOX, true);

	nbl_dev_disable_mailbox_irq(dev_mgt);
	nbl_dev_free_mailbox_irq(dev_mgt);

	while (i--) {
		ret = nbl_dev_remove_chan_queue(dev_mgt, NBL_CHAN_TYPE_MAILBOX);
		if (!ret)
			break;

		msleep(NBL_DEV_FW_RESET_WAIT_TIME); // wait adminq timeout
	}

	if (ret)
		nbl_err(common, NBL_DEBUG_MAIN, "stop mailbox failed\n");
}

void nbl_dev_pci_err_stop(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	if (!serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					   NBL_RESUME_CAP))
		return;

	if (test_and_set_bit(NBL_PCI_ERR_RECOVERING, adapter->state))
		return;

	serv_ops->set_hw_status(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_HW_PCIE_RESET_ERR);
	if (NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt))
		chan_ops->set_queue_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_ABNORMAL,
					  NBL_CHAN_TYPE_ADMINQ, true);

	chan_ops->set_queue_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_ABNORMAL,
				  NBL_CHAN_TYPE_MAILBOX, true);
}

static int nbl_dev_resume_start_chan(struct nbl_dev_mgt *dev_mgt)
{
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	int i;
	int ret;

	/* stop chan queue in resume func, because pcie is after pci slot reset call */
	nbl_dev_stop_mailbox(dev_mgt);
	nbl_dev_stop_adminq(dev_mgt);

	if (NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt)) {
		for (i = 0; i < NBL_CHAN_TYPE_MAX; i++) {
			ret = nbl_dev_setup_chan_qinfo(dev_mgt, i);
			if (ret) {
				dev_err(dev, "dev setup chan qinfo failed when resume\n");
				goto setup_chan_qinfo_fail;
			}
		}

		ret = nbl_dev_setup_chan_queue(dev_mgt, NBL_CHAN_TYPE_ADMINQ);
		if (ret) {
			dev_err(dev, "dev setup adminq failed when resume\n");
			goto setup_adminq_fail;
		}

		chan_ops->set_queue_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_ABNORMAL,
					  NBL_CHAN_TYPE_ADMINQ, false);
	}

	ret = nbl_dev_setup_chan_queue(dev_mgt, NBL_CHAN_TYPE_MAILBOX);
	if (ret) {
		dev_err(dev, "dev setup adminq failed when resume\n");
		goto setup_mailbox_fail;
	}

	chan_ops->set_queue_state(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_ABNORMAL,
				  NBL_CHAN_TYPE_MAILBOX, false);

	return 0;

setup_mailbox_fail:
	nbl_dev_remove_chan_queue(dev_mgt, NBL_CHAN_TYPE_ADMINQ);
setup_adminq_fail:
setup_chan_qinfo_fail:
	return ret;
}

static int nbl_dev_resume_wait_chan_rdy(struct nbl_dev_mgt *dev_mgt)
{
	int ret;
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_chan_send_info chan_send;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MY_PF(common), NBL_CHAN_MSG_KEEP_ALIVE, NULL,
		      0, NULL, 0, 0);
	ret = chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
	if (ret)
		goto out;

	return 0;
out:
	nbl_err(common, NBL_DEBUG_MAIN, "chan ready failed");
	return -1;
}

static int nbl_dev_resume_recovering(struct nbl_dev_mgt *dev_mgt)
{
	int ret;
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_adapter *adapter = dev_mgt->adapter;

	nbl_dev_stop(adapter, false);
	ret = nbl_dev_start(adapter, &adapter->init_param, false);
	nbl_info(common, NBL_DEBUG_MAIN, "resume recovered: %d", ret);

	return ret;
}

static int nbl_dev_resume_success(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_ctrl *ctrl_dev = NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_task_info *task_info;

	if (serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_TASK_FW_RESET_CAP)) {
		/* init ping pong, to avoid fw reset detect */
		task_info = NBL_DEV_CTRL_TO_TASK_INFO(ctrl_dev);
		nbl_common_queue_delayed_work(&task_info->fw_reset_task, 0, true);
		nbl_common_flush_delay_task(&task_info->fw_reset_task);
	}

	nbl_info(common, NBL_DEBUG_MAIN, "resume success");

	return 0;
}

static struct nbl_dev_resume_fsm_info nbl_resume_fsm[NBL_RESUME_MAX_FSM] = {
	[NBL_RESUME_INIT_FSM] = {NBL_RESUME_WAIT_CHAN_RDY_FSM, nbl_dev_resume_start_chan},
	[NBL_RESUME_WAIT_CHAN_RDY_FSM] = {NBL_RESUME_RECOVERING_FSM, nbl_dev_resume_wait_chan_rdy},
	[NBL_RESUME_RECOVERING_FSM] = {NBL_RESUME_SUCCESS_FSM, nbl_dev_resume_recovering},
	[NBL_RESUME_SUCCESS_FSM] = {NBL_RESUME_FINISH_FSM, nbl_dev_resume_success},
};

static void nbl_dev_resume_task(struct delayed_work *work)
{
	int ret;
	struct nbl_resume_task_info *task_info = container_of(work, struct nbl_resume_task_info,
							     task);
	struct nbl_dev_common *common_dev = container_of(task_info, struct nbl_dev_common,
							 resume_task);
	struct nbl_dev_mgt *dev_mgt = common_dev->dev_mgt;
	struct nbl_adapter *adapter = dev_mgt->adapter;
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	enum nbl_resume_fsm cur_fsm = NBL_RESUME_INIT_FSM;
	enum nbl_resume_fsm next_fsm;

	nbl_info(common, NBL_DEBUG_MAIN, "resume begin");

	while (1) {
		if (nbl_resume_fsm[cur_fsm].act_cb) {
			ret = nbl_resume_fsm[cur_fsm].act_cb(dev_mgt);
			if (ret)
				goto out;

			next_fsm = nbl_resume_fsm[cur_fsm].success_next_fsm;
			if (next_fsm == NBL_RESUME_FINISH_FSM)
				break;

			cur_fsm = next_fsm;
			task_info->fsm = next_fsm;
		} else {
			goto out;
		}
	}

	task_info->fsm = NBL_RESUME_INIT_FSM;
	task_info->my_ctrl_rsm_done = 0;
	clear_bit(NBL_PCI_ERR_RECOVERING, adapter->state);
	nbl_info(common, NBL_DEBUG_MAIN, "resume finish");

	return;
out:
	task_info->fsm = NBL_RESUME_ERR_FSM;
	nbl_err(common, NBL_DEBUG_MAIN, "resume error");
}

int nbl_dev_wait_my_ctrl_initdone(struct nbl_adapter *adapter)
{
	u8 dest_func;
	int ret;
	int try_num = 0;
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_chan_send_info chan_send;

	/* only not ctrldev's resume processs need to check status*/
	if (NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt))
		return 0;

	if  (!test_bit(NBL_PCI_ERR_RECOVERING, adapter->state))
		return 0;

	dest_func = !NBL_COMMON_TO_VF_CAP(common) ? NBL_COMMON_TO_MGT_PF(common) :
			NBL_COMMON_TO_MY_PF(common);
again:
	if (try_num >= NBL_DEV_WAIT_CTRL_TRY_NUM)
		goto out;

	dev_common->resume_task.ctrl_ack_rsm_tmp = 0;
	NBL_CHAN_SEND(chan_send, dest_func, NBL_CHAN_MSG_KEEP_ALIVE, NULL, 0, NULL, 0, 0);
	ret = chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
	if (ret) {
		nbl_err(common, NBL_DEBUG_MAIN, "failed to send msg when wait ctrl init done");
		goto out;
	} else {
		try_num++;
		usleep_range(NBL_DEV_WAIT_CTRL_SLEEP_MIN_TIME1,
			     NBL_DEV_WAIT_CTRL_SLEEP_MAX_TIME1);

		/**
		 * my pf maybe overwrite chanqinfo's msix(nbl_res_prepare_vf_chan). so reenable
		 * mailbox_irq.
		 */
		if (!dev_common->resume_task.ctrl_ack_rsm_tmp) {
			nbl_dev_enable_mailbox_irq(dev_mgt);
			usleep_range(NBL_DEV_WAIT_CTRL_SLEEP_MIN_TIME2,
				     NBL_DEV_WAIT_CTRL_SLEEP_MAX_TIME2);
		}

		if (!dev_common->resume_task.my_ctrl_rsm_done)
			goto again;
	}

	nbl_info(common, NBL_DEBUG_MAIN, "my ctrl init done");

	return 0;

out:
	nbl_err(common, NBL_DEBUG_MAIN, "my ctrl not init done, try_num: %d", try_num);
	return -EBUSY;
}

void nbl_dev_pci_err_start(struct nbl_adapter *adapter)
{
	int delay_time = NBL_DEV_RESUME_DELAY_CTRL_TIME;
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_dev_common *dev_common = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	if (!serv_ops->get_product_fix_cap(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					   NBL_RESUME_CAP))
		return;

	if (dev_common->resume_task.fsm)
		return;

	serv_ops->set_hw_status(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_HW_NOMAL);

	if (!NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt))
		delay_time = !NBL_COMMON_TO_VF_CAP(common) ? NBL_DEV_RESUME_DELAY_PF_TIME :
				NBL_DEV_RESUME_DELAY_VF_TIME;

	nbl_common_queue_delayed_work(&dev_mgt->common_dev->resume_task.task, delay_time, false);
}

void nbl_dev_check_fast_remove(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->check_hw_status(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}
