// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_dispatch.h"

static int nbl_disp_chan_add_macvlan_req(void *priv, u8 *mac, u16 vlan, u16 vsi)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_add_macvlan param;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	if (!disp_mgt || !mac)
		return -EINVAL;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	memcpy(param.mac, mac, sizeof(param.mac));
	param.vlan = vlan;
	param.vsi = vsi;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_ADD_MACVLAN, &param, sizeof(param),
		      NULL, 0, 1);

	if (chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send))
		return -EFAULT;

	return 0;
}

static void nbl_disp_chan_add_macvlan_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_add_macvlan *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_add_macvlan *)data;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_macvlan,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->mac,
				param->vlan, param->vsi);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_ADD_MACVLAN, msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_ADD_MACVLAN);
}

static void nbl_disp_chan_del_macvlan_req(void *priv, u8 *mac, u16 vlan, u16 vsi)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_del_macvlan param;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	if (!disp_mgt || !mac)
		return;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	memcpy(param.mac, mac, sizeof(param.mac));
	param.vlan = vlan;
	param.vsi = vsi;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_DEL_MACVLAN, &param, sizeof(param),
		      NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_del_macvlan_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_del_macvlan *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_del_macvlan *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_macvlan,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  param->mac, param->vlan, param->vsi);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_DEL_MACVLAN, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_add_multi_rule_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	if (!disp_mgt)
		return -EINVAL;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_ADD_MULTI_RULE,
		      &vsi_id, sizeof(vsi_id), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_add_multi_rule_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;
	u16 vsi_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	vsi_id = *(u16 *)data;
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_multi_rule,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_ADD_MULTI_RULE, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_del_multi_rule_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	if (!disp_mgt)
		return;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_DEL_MULTI_RULE,
		      &vsi_id, sizeof(vsi_id), NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_del_multi_rule_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	vsi_id = *(u16 *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_multi_rule,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_DEL_MULTI_RULE, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_setup_multi_group_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_SETUP_MULTI_GROUP,
		      NULL, 0, NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_setup_multi_group_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_multi_group,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SETUP_MULTI_GROUP, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_remove_multi_group_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_REMOVE_MULTI_GROUP,
		      NULL, 0, NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_remove_multi_group_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_multi_group,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REMOVE_MULTI_GROUP, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_register_net_req(void *priv,
					  struct nbl_register_net_param *register_param,
					  struct nbl_register_net_result *register_result)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_register_net_info param = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;
	int ret = 0;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.pf_bar_start = register_param->pf_bar_start;
	param.pf_bdf = register_param->pf_bdf;
	param.vf_bar_start = register_param->vf_bar_start;
	param.vf_bar_size = register_param->vf_bar_size;
	param.total_vfs = register_param->total_vfs;
	param.offset = register_param->offset;
	param.stride = register_param->stride;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_REGISTER_NET, &param, sizeof(param),
		      (void *)register_result, sizeof(*register_result), 1);

	ret = chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
	return ret;
}

static void nbl_disp_chan_register_net_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_register_net_info *param;
	struct nbl_register_net_result result = {0};
	struct nbl_register_net_param register_param = {0};
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_register_net_info *)data;

	register_param.pf_bar_start = param->pf_bar_start;
	register_param.pf_bdf = param->pf_bdf;
	register_param.vf_bar_start = param->vf_bar_start;
	register_param.vf_bar_size = param->vf_bar_size;
	register_param.total_vfs = param->total_vfs;
	register_param.offset = param->offset;
	register_param.stride = param->stride;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->register_net,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id, &register_param, &result);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REGISTER_NET,
		     msg_id, err, &result, sizeof(result));
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d, src_id:%d\n",
			ret, NBL_CHAN_MSG_REGISTER_NET, src_id);
}

static int nbl_disp_unregister_net(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->unregister_net,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), 0);
}

static int nbl_disp_chan_unregister_net_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_UNREGISTER_NET, NULL, 0, NULL, 0, 1);

	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_unregister_net_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->unregister_net,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_UNREGISTER_NET,
		     msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d, src_id:%d\n",
			ret, NBL_CHAN_MSG_UNREGISTER_NET, src_id);
}

static int nbl_disp_chan_alloc_txrx_queues_req(void *priv, u16 vsi_id, u16 queue_num)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_alloc_txrx_queues param = {0};
	struct nbl_chan_param_alloc_txrx_queues result = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;
	param.queue_num = queue_num;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_ALLOC_TXRX_QUEUES, &param,
		      sizeof(param), &result, sizeof(result), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return 0;
}

static void nbl_disp_chan_alloc_txrx_queues_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_alloc_txrx_queues *param;
	struct nbl_chan_param_alloc_txrx_queues result = {0};
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_alloc_txrx_queues *)data;
	result.queue_num = param->queue_num;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->alloc_txrx_queues,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id, param->queue_num);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_ALLOC_TXRX_QUEUES,
		     msg_id, err, &result, sizeof(result));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_free_txrx_queues_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_FREE_TXRX_QUEUES,
		      &vsi_id, sizeof(vsi_id), NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_free_txrx_queues_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	vsi_id = *(u16 *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->free_txrx_queues,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_FREE_TXRX_QUEUES, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_register_vsi2q_req(void *priv, u16 vsi_index, u16 vsi_id,
					    u16 queue_offset, u16 queue_num)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_register_vsi2q param = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_index = vsi_index;
	param.vsi_id = vsi_id;
	param.queue_offset = queue_offset;
	param.queue_num = queue_num;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_REGISTER_VSI2Q, &param,
		      sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_register_vsi2q_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_register_vsi2q *param = NULL;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_register_vsi2q *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->register_vsi2q, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  param->vsi_index, param->vsi_id, param->queue_offset, param->queue_num);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REGISTER_VSI2Q, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_setup_q2vsi_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_SETUP_Q2VSI, &vsi_id,
		      sizeof(vsi_id), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_setup_q2vsi_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	vsi_id = *(u16 *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_q2vsi, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SETUP_Q2VSI, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_remove_q2vsi_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_REMOVE_Q2VSI, &vsi_id,
		      sizeof(vsi_id), NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_remove_q2vsi_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	vsi_id = *(u16 *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_q2vsi, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REMOVE_Q2VSI, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_setup_rss_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_SETUP_RSS, &vsi_id,
		      sizeof(vsi_id), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_setup_rss_resp(void *priv, u16 src_id, u16 msg_id,
					 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	vsi_id = *(u16 *)data;
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_rss, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SETUP_RSS, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_remove_rss_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_REMOVE_RSS, &vsi_id,
		      sizeof(vsi_id), NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_remove_rss_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	vsi_id = *(u16 *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_rss, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REMOVE_RSS, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_setup_queue_req(void *priv, struct nbl_txrx_queue_param *queue_param,
					 bool is_tx)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_setup_queue param;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	memcpy(&param.queue_param, queue_param, sizeof(param.queue_param));
	param.is_tx = is_tx;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_SETUP_QUEUE, &param, sizeof(param),
		      NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_setup_queue_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_setup_queue *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_setup_queue *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_queue,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), &param->queue_param, param->is_tx);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SETUP_QUEUE, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_remove_all_queues_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_REMOVE_ALL_QUEUES,
		      &vsi_id, sizeof(vsi_id), NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_remove_all_queues_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	vsi_id = *(u16 *)data;
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_all_queues,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REMOVE_ALL_QUEUES, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_cfg_dsch_req(void *priv, u16 vsi_id, bool vld)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_cfg_dsch param = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;
	param.vld = vld;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_CFG_DSCH, &param, sizeof(param),
		      NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_cfg_dsch_resp(void *priv, u16 src_id, u16 msg_id,
					void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_cfg_dsch *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_cfg_dsch *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_dsch,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id, param->vld);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CFG_DSCH, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_setup_cqs_req(void *priv, u16 vsi_id, u16 real_qps)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_setup_cqs param = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;
	param.real_qps = real_qps;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_SETUP_CQS, &param, sizeof(param),
		      NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_setup_cqs_resp(void *priv, u16 src_id, u16 msg_id,
					 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_setup_cqs *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_setup_cqs *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_cqs,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id, param->real_qps);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SETUP_CQS, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_remove_cqs_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf,
		      NBL_CHAN_MSG_REMOVE_CQS, &vsi_id, sizeof(vsi_id),
		      NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_remove_cqs_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	vsi_id = *(u16 *)data;
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_cqs,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REMOVE_CQS, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_set_promisc_mode(void *priv, u16 vsi_id, u16 mode)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!disp_mgt)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_promisc_mode,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, mode);
	return ret;
}

static int nbl_disp_chan_set_promisc_mode_req(void *priv, u16 vsi_id, u16 mode)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_set_promisc_mode param = {0};
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;
	param.mode = mode;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_SET_PROSISC_MODE,
		      &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_promisc_mode_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	struct nbl_chan_param_set_promisc_mode *param = NULL;
	int err = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_set_promisc_mode *)data;
	err = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_promisc_mode,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id, param->mode);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_PROSISC_MODE, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_set_spoof_check_addr_req(void *priv, u16 vsi_id, u8 *mac)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_spoof_check_addr param = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;
	ether_addr_copy(param.mac, mac);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_SET_SPOOF_CHECK_ADDR,
		      &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_spoof_check_addr_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_spoof_check_addr *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_set_spoof_check_addr *)data;
	err = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_spoof_check_addr,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id, param->mac);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_SPOOF_CHECK_ADDR, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_set_vf_spoof_check_req(void *priv, u16 vsi_id, int vf_id, u8 enable)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_vf_spoof_check param = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;
	param.vf_id = vf_id;
	param.enable = enable;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_SET_VF_SPOOF_CHECK,
		      &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_vf_spoof_check_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_vf_spoof_check *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_set_vf_spoof_check *)data;
	err = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_vf_spoof_check,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id,
				param->vf_id, param->enable);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_VF_SPOOF_CHECK, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_get_base_mac_addr_req(void *priv, u8 *mac)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_GET_BASE_MAC_ADDR,
		      NULL, 0, mac, ETH_ALEN, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_base_mac_addr_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u8 mac[ETH_ALEN];

	NBL_OPS_CALL(res_ops->get_base_mac_addr,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mac));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_BASE_MAC_ADDR, msg_id, err,
		     mac, ETH_ALEN);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_get_firmware_version_req(void *priv, char *firmware_verion, u8 max_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_FIRMWARE_VERSION, NULL, 0,
		      firmware_verion, max_len, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_firmware_version_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	char firmware_verion[ETHTOOL_FWVERS_LEN] = "";
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	ret = NBL_OPS_CALL(res_ops->get_firmware_version,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), firmware_verion));
	if (ret) {
		err = NBL_CHAN_RESP_ERR;
		dev_err(dev, "get emp version failed with ret: %d\n", ret);
	}

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_FIRMWARE_VERSION, msg_id, err,
		     firmware_verion, ETHTOOL_FWVERS_LEN);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d, src_id: %d\n",
			ret, NBL_CHAN_MSG_GET_FIRMWARE_VERSION, src_id);
}

static int nbl_disp_get_queue_err_stats(void *priv, u8 queue_id,
					struct nbl_queue_err_stats *queue_err_stats, bool is_tx)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	return NBL_OPS_CALL(res_ops->get_queue_err_stats,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			    0, queue_id, queue_err_stats, is_tx));
}

static int nbl_disp_chan_get_queue_err_stats_req(void *priv, u8 queue_id,
						 struct nbl_queue_err_stats *queue_err_stats,
						 bool is_tx)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_queue_err_stats param = {0};
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.queue_id = queue_id;
	param.is_tx = is_tx;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_QUEUE_ERR_STATS, &param,
		      sizeof(param), queue_err_stats, sizeof(*queue_err_stats), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_queue_err_stats_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_queue_err_stats *param;
	struct nbl_chan_ack_info chan_ack;
	struct nbl_queue_err_stats queue_err_stats = { 0 };
	int err = NBL_CHAN_RESP_OK;
	int ret;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_get_queue_err_stats *)data;

	ret = NBL_OPS_CALL(res_ops->get_queue_err_stats,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id, param->queue_id,
			   &queue_err_stats, param->is_tx));
	if (ret) {
		err = NBL_CHAN_RESP_ERR;
		dev_err(dev, "disp get queue err stats_resp failed with ret: %d\n", ret);
	}
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_QUEUE_ERR_STATS, msg_id, err,
		     &queue_err_stats, sizeof(queue_err_stats));
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "disp chan send ack failed with ret: %d, msg_type: %d, src_id: %d\n",
			ret, NBL_CHAN_MSG_GET_QUEUE_ERR_STATS, src_id);
}

static void nbl_disp_chan_get_coalesce_req(void *priv, u16 vector_id,
					   struct ethtool_coalesce *ec)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf,
		      NBL_CHAN_MSG_GET_COALESCE, &vector_id, sizeof(vector_id),
		      ec, sizeof(*ec), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_coalesce_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	struct ethtool_coalesce ec = { 0 };
	u16 vector_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	vector_id = *(u16 *)data;

	NBL_OPS_CALL(res_ops->get_coalesce,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id,
		      vector_id, &ec));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_COALESCE, msg_id, ret,
		     &ec, sizeof(ec));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_set_coalesce_req(void *priv, u16 vector_id,
					   u16 vector_num, u16 pnum, u16 rate)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_coalesce param = {0};
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.local_vector_id = vector_id;
	param.vector_num = vector_num;
	param.rx_max_coalesced_frames = pnum;
	param.rx_coalesce_usecs = rate;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_SET_COALESCE, &param, sizeof(param),
		      NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_coalesce_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_coalesce *param;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_set_coalesce *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_coalesce,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id, param->local_vector_id,
			  param->vector_num, param->rx_max_coalesced_frames,
			  param->rx_coalesce_usecs);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_COALESCE, msg_id, ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_get_rxfh_indir_size_req(void *priv, u16 vsi_id, u32 *rxfh_indir_size)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_RXFH_INDIR_SIZE,
		      &vsi_id, sizeof(vsi_id), rxfh_indir_size, sizeof(u32), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_rxfh_indir_size_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	u32 rxfh_indir_size = 0;
	int ret = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	vsi_id = *(u16 *)data;
	NBL_OPS_CALL(res_ops->get_rxfh_indir_size,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, &rxfh_indir_size));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_RXFH_INDIR_SIZE, msg_id,
		     ret, &rxfh_indir_size, sizeof(u32));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_get_rxfh_indir_req(void *priv, u16 vsi_id, u32 *indir, u32 indir_size)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_rxfh_indir param = {0};
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;
	param.rxfh_indir_size = indir_size;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_RXFH_INDIR, &param,
		      sizeof(param), indir, indir_size * sizeof(u32), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_rxfh_indir_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_rxfh_indir *param;
	struct nbl_chan_ack_info chan_ack;
	u32 *indir;
	int ret = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_get_rxfh_indir *)data;

	indir = kcalloc(param->rxfh_indir_size, sizeof(u32), GFP_KERNEL);
	NBL_OPS_CALL(res_ops->get_rxfh_indir,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id, indir));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_RXFH_INDIR, msg_id, ret,
		     indir, param->rxfh_indir_size * sizeof(u32));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);

	kfree(indir);
}

static void nbl_disp_chan_get_rxfh_rss_key_req(void *priv, u8 *rss_key, u32 rss_key_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf,
		      NBL_CHAN_MSG_GET_RXFH_RSS_KEY, &rss_key_len,
		      sizeof(rss_key_len), rss_key, rss_key_len, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_rxfh_rss_key_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	u8 *rss_key;
	int ret = NBL_CHAN_RESP_OK;
	u32 rss_key_len;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	rss_key_len = *(u32 *)data;

	rss_key = kzalloc(rss_key_len, GFP_KERNEL);
	NBL_OPS_CALL(res_ops->get_rxfh_rss_key, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), rss_key));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_RXFH_RSS_KEY, msg_id, ret,
		     rss_key, rss_key_len);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);

	kfree(rss_key);
}

static void nbl_disp_chan_get_rxfh_rss_alg_sel_req(void *priv, u8 *rss_alg_sel, u8 eth_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf,
		      NBL_CHAN_MSG_GET_RXFH_RSS_ALG_SEL, &eth_id,
		      sizeof(eth_id), rss_alg_sel, sizeof(u8), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_rxfh_rss_alg_sel_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	u8 rss_alg_sel, eth_id;
	int ret = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	eth_id = *(u8 *)data;

	NBL_OPS_CALL(res_ops->get_rss_alg_sel,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), &rss_alg_sel, eth_id));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_RXFH_RSS_ALG_SEL, msg_id, ret,
		     &rss_alg_sel, sizeof(rss_alg_sel));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_get_phy_caps_req(void *priv, u8 eth_id, struct nbl_phy_caps *phy_caps)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_PHY_CAPS, &eth_id,
		      sizeof(eth_id), phy_caps, sizeof(*phy_caps), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_phy_caps_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	struct nbl_phy_caps phy_caps = { 0 };
	u8 eth_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	eth_id = *(u8 *)data;

	NBL_OPS_CALL(res_ops->get_phy_caps,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, &phy_caps));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_PHY_CAPS, msg_id, ret,
		     &phy_caps, sizeof(phy_caps));

	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_get_phy_state_req(void *priv, u8 eth_id, struct nbl_phy_state *phy_state)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_PHY_STATE, &eth_id,
		      sizeof(eth_id), phy_state, sizeof(*phy_state), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_phy_state_resp(void *priv, u16 src_id, u16 msg_id,
					     void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	struct nbl_phy_state phy_state = { 0 };
	u8 eth_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	eth_id = *(u8 *)data;

	NBL_OPS_CALL(res_ops->get_phy_state,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, &phy_state));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_PHY_STATE, msg_id, ret,
		     &phy_state, sizeof(phy_state));

	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_set_sfp_state_req(void *priv, u8 eth_id, u8 state)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_sfp_state param = {0};
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.eth_id = eth_id;
	param.state = state;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_SET_SFP_STATE, &param,
		      sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_sfp_state_resp(void *priv, u16 src_id, u16 msg_id,
					     void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	struct nbl_chan_param_set_sfp_state *param;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_set_sfp_state *)data;

	ret = NBL_OPS_CALL(res_ops->set_sfp_state,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->eth_id, param->state));
	if (ret) {
		err = NBL_CHAN_RESP_ERR;
		dev_err(dev, "set sfp state failed with ret: %d\n", ret);
	}

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_SFP_STATE, msg_id, err, NULL, 0);

	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d, src_id: %d\n",
			ret, NBL_CHAN_MSG_SET_SFP_STATE, src_id);
}

static u64 nbl_disp_chan_get_real_hw_addr_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;
	u64 addr = 0;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	NBL_CHAN_SEND(chan_send, common->mgt_pf,
		      NBL_CHAN_MSG_GET_REAL_HW_ADDR, &vsi_id,
		      sizeof(vsi_id), &addr, sizeof(addr), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return addr;
}

static void nbl_disp_chan_get_real_hw_addr_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	u16 vsi_id;
	u64 addr;

	vsi_id = *(u16 *)data;
	addr = NBL_OPS_CALL(res_ops->get_real_hw_addr,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_REAL_HW_ADDR, msg_id,
		     ret, &addr, sizeof(addr));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static u16 nbl_disp_chan_get_function_id_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;
	u16 func_id = 0;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf,
		      NBL_CHAN_MSG_GET_FUNCTION_ID, &vsi_id,
		      sizeof(vsi_id), &func_id, sizeof(func_id), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return func_id;
}

static void nbl_disp_chan_get_function_id_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	u16 vsi_id, func_id;

	vsi_id = *(u16 *)data;

	func_id = NBL_OPS_CALL(res_ops->get_function_id,
			       (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_FUNCTION_ID, msg_id,
		     ret, &func_id, sizeof(func_id));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_get_real_bdf_req(void *priv, u16 vsi_id, u8 *bus, u8 *dev, u8 *function)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_result_get_real_bdf result = {0};
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_REAL_BDF, &vsi_id,
		      sizeof(vsi_id), &result, sizeof(result), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	*bus = result.bus;
	*dev = result.dev;
	*function = result.function;
}

static void nbl_disp_chan_get_real_bdf_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_result_get_real_bdf result = {0};
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	vsi_id = *(u16 *)data;
	NBL_OPS_CALL(res_ops->get_real_bdf,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id,
		      &result.bus, &result.dev, &result.function));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_REAL_BDF, msg_id,
		     ret, &result, sizeof(result));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_get_mbx_irq_num_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;
	int result = 0;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_MBX_IRQ_NUM, NULL, 0,
		      &result, sizeof(result), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return result;
}

static void nbl_disp_chan_get_mbx_irq_num_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int result, ret = NBL_CHAN_RESP_OK;

	result = NBL_OPS_CALL(res_ops->get_mbx_irq_num, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_MBX_IRQ_NUM, msg_id,
		     ret, &result, sizeof(result));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_clear_flow_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_CLEAR_FLOW, &vsi_id, sizeof(vsi_id),
		      NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_clear_flow_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	u16 *vsi_id = (u16 *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->clear_flow,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), *vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CLEAR_FLOW, msg_id,
		     NBL_CHAN_RESP_OK, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_clear_queues_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_CLEAR_QUEUE, &vsi_id,
		      sizeof(vsi_id), NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_clear_queues_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	u16 *vsi_id = (u16 *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->clear_queues,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), *vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CLEAR_QUEUE, msg_id,
		     NBL_CHAN_RESP_OK, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static u16 nbl_disp_chan_get_vsi_id_req(void *priv, u16 func_id, u16 type)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_get_vsi_id param = {0};
	struct nbl_chan_param_get_vsi_id result = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.type = type;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_VSI_ID, &param,
		      sizeof(param), &result, sizeof(result), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return result.vsi_id;
}

static void nbl_disp_chan_get_vsi_id_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_get_vsi_id *param;
	struct nbl_chan_param_get_vsi_id result;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	param = (struct nbl_chan_param_get_vsi_id *)data;

	result.vsi_id = NBL_OPS_CALL(res_ops->get_vsi_id,
				     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id, param->type));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_VSI_ID,
		     msg_id, err, &result, sizeof(result));
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_GET_VSI_ID);
}

static void nbl_disp_chan_get_eth_id_req(void *priv, u16 vsi_id, u8 *eth_mode, u8 *eth_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_get_eth_id param = {0};
	struct nbl_chan_param_get_eth_id result = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_ETH_ID,  &param,
		      sizeof(param), &result, sizeof(result), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	*eth_mode = result.eth_mode;
	*eth_id = result.eth_id;
}

static void nbl_disp_chan_get_eth_id_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_get_eth_id *param;
	struct nbl_chan_param_get_eth_id result = {0};
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	param = (struct nbl_chan_param_get_eth_id *)data;

	NBL_OPS_CALL(res_ops->get_eth_id, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id,
					   &result.eth_mode, &result.eth_id));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_ETH_ID,
		     msg_id, err, &result, sizeof(result));
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_GET_ETH_ID);
}

static int nbl_disp_alloc_rings(void *priv, struct net_device *netdev, u16 tx_num,
				u16 rx_num, u16 tx_desc_num, u16 rx_desc_num)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->alloc_rings,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), netdev, tx_num,
			   rx_num, tx_desc_num, rx_desc_num));
	return ret;
}

static void nbl_disp_remove_rings(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	if (!disp_mgt)
		return;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->remove_rings, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static dma_addr_t nbl_disp_start_tx_ring(void *priv, u8 ring_index)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	dma_addr_t addr = 0;

	if (!disp_mgt)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	addr = NBL_OPS_CALL(res_ops->start_tx_ring,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), ring_index));
	return addr;
}

static void nbl_disp_stop_tx_ring(void *priv, u8 ring_index)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	if (!disp_mgt)
		return;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->stop_tx_ring, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), ring_index));
}

static dma_addr_t nbl_disp_start_rx_ring(void *priv, u8 ring_index, bool use_napi)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	dma_addr_t addr = 0;

	if (!disp_mgt)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	addr = NBL_OPS_CALL(res_ops->start_rx_ring,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), ring_index, use_napi));

	return addr;
}

static void nbl_disp_stop_rx_ring(void *priv, u8 ring_index)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	if (!disp_mgt)
		return;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->stop_rx_ring, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), ring_index));
}

static void nbl_disp_kick_rx_ring(void *priv, u16 index)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->kick_rx_ring, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), index));
}

static int nbl_disp_dump_ring(void *priv, struct seq_file *m, bool is_tx, int index)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->dump_ring,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), m, is_tx, index));
	return ret;
}

static int nbl_disp_dump_ring_stats(void *priv, struct seq_file *m, bool is_tx, int index)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->dump_ring_stats,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), m, is_tx, index));
	return ret;
}

static struct napi_struct *nbl_disp_get_vector_napi(void *priv, u16 index)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	return NBL_OPS_CALL(res_ops->get_vector_napi,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), index));
}

static void nbl_disp_set_vector_info(void *priv, u8 *irq_enable_base,
				     u32 irq_data, u16 index, bool mask_en)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->set_vector_info,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
		      irq_enable_base, irq_data, index, mask_en));
}

static void nbl_disp_register_vsi_ring(void *priv, u16 vsi_index, u16 ring_offset, u16 ring_num)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->register_vsi_ring,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_index, ring_offset, ring_num));
}

static void nbl_disp_get_res_pt_ops(void *priv, struct nbl_resource_pt_ops *pt_ops)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_resource_pt_ops,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), pt_ops));
}

static int nbl_disp_register_net(void *priv, struct nbl_register_net_param *register_param,
				 struct nbl_register_net_result *register_result)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->register_net,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), 0,
				register_param, register_result);
	return ret;
}

static int nbl_disp_alloc_txrx_queues(void *priv, u16 vsi_id, u16 queue_num)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->alloc_txrx_queues,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, queue_num);
	return ret;
}

static void nbl_disp_free_txrx_queues(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->free_txrx_queues,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static int nbl_disp_register_vsi2q(void *priv, u16 vsi_index, u16 vsi_id,
				   u16 queue_offset, u16 queue_num)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->register_vsi2q,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_index, vsi_id,
				 queue_offset, queue_num);
}

static int nbl_disp_setup_q2vsi(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_q2vsi,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static void nbl_disp_remove_q2vsi(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_q2vsi,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static int nbl_disp_setup_rss(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_rss,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static void nbl_disp_remove_rss(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_rss,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static int nbl_disp_setup_queue(void *priv, struct nbl_txrx_queue_param *param, bool is_tx)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_queue,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param, is_tx);
	return ret;
}

static void nbl_disp_remove_all_queues(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_all_queues,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static int nbl_disp_cfg_dsch(void *priv, u16 vsi_id, bool vld)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_dsch,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, vld);
	return ret;
}

static int nbl_disp_setup_cqs(void *priv, u16 vsi_id, u16 real_qps)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_cqs,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, real_qps);
	return ret;
}

static void nbl_disp_remove_cqs(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_cqs,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static int nbl_disp_enable_msix_irq(void *priv, u16 global_vector_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!disp_mgt)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->enable_msix_irq,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), global_vector_id));
	return ret;
}

static u8 *nbl_disp_get_msix_irq_enable_info(void *priv, u16 global_vector_id, u32 *irq_data)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	if (!disp_mgt)
		return NULL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	return NBL_OPS_CALL(res_ops->get_msix_irq_enable_info,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), global_vector_id, irq_data));
}

static int nbl_disp_add_macvlan(void *priv, u8 *mac, u16 vlan, u16 vsi)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!disp_mgt || !mac)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_macvlan,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mac, vlan, vsi);
	return ret;
}

static void nbl_disp_del_macvlan(void *priv, u8 *mac, u16 vlan, u16 vsi)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	if (!disp_mgt || !mac)
		return;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_macvlan,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mac, vlan, vsi);
}

static int nbl_disp_add_multi_rule(void *priv, u16 vsi)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!disp_mgt)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_multi_rule,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi);
	return ret;
}

static void nbl_disp_del_multi_rule(void *priv, u16 vsi)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	if (!disp_mgt)
		return;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_multi_rule,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi);
}

static int nbl_disp_setup_multi_group(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_multi_group,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static void nbl_disp_remove_multi_group(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_multi_group,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static void nbl_disp_get_net_stats(void *priv, struct nbl_stats *net_stats)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_net_stats, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), net_stats));
}

static void nbl_disp_get_private_stat_len(void *priv, u32 *len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_private_stat_len,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), len);
}

static void nbl_disp_get_private_stat_data(void *priv, u32 eth_id, u64 *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_private_stat_data,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, data);
}

static void nbl_disp_get_private_stat_data_req(void *priv, u32 eth_id, u64 *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_get_private_stat_data param = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.eth_id = eth_id;
	param.data_len = data_len;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_ETH_STATS, &param,
		      sizeof(param), data, data_len, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_private_stat_data_resp(void *priv, u16 src_id, u16 msg_id,
						     void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_get_private_stat_data *param;
	struct nbl_chan_ack_info chan_ack;
	u64 *recv_data;
	int ret = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_get_private_stat_data *)data;
	recv_data = kmalloc(param->data_len, GFP_ATOMIC);
	if (!recv_data) {
		dev_err(dev, "Allocate memory to private_stat_data failed\n");
		return;
	}

	NBL_OPS_CALL(res_ops->get_private_stat_data,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->eth_id, recv_data));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_ETH_STATS, msg_id,
		     ret, recv_data, param->data_len);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);

	kfree(recv_data);
}

static void nbl_disp_fill_private_stat_strings(void *priv, u8 *strings)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->fill_private_stat_strings,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), strings);
}

static u16 nbl_disp_get_max_desc_num(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	u16 ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_max_desc_num, ());
	return ret;
}

static u16 nbl_disp_get_min_desc_num(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	u16 ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_min_desc_num, ());
	return ret;
}

static int nbl_disp_set_spoof_check_addr(void *priv, u16 vsi_id, u8 *mac)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_spoof_check_addr,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, mac);
	return ret;
}

static int nbl_disp_set_vf_spoof_check(void *priv, u16 vsi_id, int vf_id, u8 enable)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_vf_spoof_check,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, vf_id, enable);
	return ret;
}

static void nbl_disp_get_base_mac_addr(void *priv, u8 *mac)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_base_mac_addr,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mac);
}

static u16 nbl_disp_get_tx_desc_num(void *priv, u32 ring_index)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	u16 ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_tx_desc_num,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), ring_index));
	return ret;
}

static u16 nbl_disp_get_rx_desc_num(void *priv, u32 ring_index)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	u16 ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_rx_desc_num,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), ring_index));
	return ret;
}

static void nbl_disp_set_tx_desc_num(void *priv, u32 ring_index, u16 desc_num)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->set_tx_desc_num,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), ring_index, desc_num));
}

static void nbl_disp_set_rx_desc_num(void *priv, u32 ring_index, u16 desc_num)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->set_rx_desc_num,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), ring_index, desc_num));
}

static void nbl_disp_get_queue_stats(void *priv, u8 queue_id,
				     struct nbl_queue_stats *queue_stats, bool is_tx)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_queue_stats,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), queue_id, queue_stats, is_tx));
}

static void nbl_disp_get_firmware_version(void *priv, char *firmware_verion, u8 max_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_firmware_version,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), firmware_verion));
	if (ret)
		dev_err(dev, "get emp version failed with ret: %d\n", ret);
}

static int nbl_disp_get_driver_info(void *priv, struct nbl_driver_info *driver_info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_driver_info,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), driver_info));
}

static void nbl_disp_get_coalesce(void *priv, u16 vector_id,
				  struct ethtool_coalesce *ec)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_coalesce,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), 0, vector_id, ec));
}

static void nbl_disp_set_coalesce(void *priv, u16 vector_id, u16 vector_num, u16 pnum, u16 rate)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_coalesce,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), 0, vector_id,
			  vector_num, pnum, rate);
}

static void nbl_disp_get_rxfh_indir_size(void *priv, u16 vsi_id, u32 *rxfh_indir_size)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_rxfh_indir_size,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, rxfh_indir_size));
}

static void nbl_disp_get_rxfh_rss_key_size(void *priv, u32 *rxfh_rss_key_size)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_rxfh_rss_key_size,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), rxfh_rss_key_size));
}

static void nbl_disp_get_rxfh_indir(void *priv, u16 vsi_id, u32 *indir, u32 indir_size)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_rxfh_indir, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, indir));
}

static void nbl_disp_get_rxfh_rss_key(void *priv, u8 *rss_key, u32 key_size)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_rxfh_rss_key, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), rss_key));
}

static void nbl_disp_get_rxfh_rss_alg_sel(void *priv, u8 *alg_sel, u8 eth_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_rss_alg_sel,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), alg_sel, eth_id));
}

static void nbl_disp_get_phy_caps(void *priv, u8 eth_id, struct nbl_phy_caps *phy_caps)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_phy_caps, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, phy_caps));
}

static void nbl_disp_get_phy_state(void *priv, u8 eth_id, struct nbl_phy_state *phy_state)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_phy_state,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, phy_state));
}

static int nbl_disp_set_sfp_state(void *priv, u8 eth_id, u8 state)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->set_sfp_state,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, state));
	return ret;
}

static int nbl_disp_init_chip_module(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!disp_mgt)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->init_chip_module, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	return ret;
}

static int nbl_disp_queue_init(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!disp_mgt)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->queue_init, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	return ret;
}

static int nbl_disp_vsi_init(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!disp_mgt)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->vsi_init, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	return ret;
}

static int nbl_disp_configure_msix_map(void *priv, u16 num_net_msix, u16 num_others_msix,
				       bool net_msix_mask_en)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!disp_mgt)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->configure_msix_map,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), 0, num_net_msix,
				num_others_msix, net_msix_mask_en);
	return ret;
}

static int nbl_disp_chan_configure_msix_map_req(void *priv, u16 num_net_msix, u16 num_others_msix,
						bool net_msix_mask_en)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_cfg_msix_map param = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	if (!disp_mgt)
		return -EINVAL;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.num_net_msix = num_net_msix;
	param.num_others_msix = num_others_msix;
	param.msix_mask_en = net_msix_mask_en;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_CONFIGURE_MSIX_MAP,
		      &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_configure_msix_map_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_cfg_msix_map *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_cfg_msix_map *)data;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->configure_msix_map,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id,
				param->num_net_msix, param->num_others_msix, param->msix_mask_en);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CONFIGURE_MSIX_MAP, msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_CONFIGURE_MSIX_MAP);
}

static int nbl_disp_chan_destroy_msix_map_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	if (!disp_mgt)
		return -EINVAL;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_DESTROY_MSIX_MAP,
		      NULL, 0, NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_destroy_msix_map_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_cfg_msix_map *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_cfg_msix_map *)data;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->destroy_msix_map,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_DESTROY_MSIX_MAP, msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_DESTROY_MSIX_MAP);
}

static int nbl_disp_chan_enable_mailbox_irq_req(void *priv, u16 vector_id, bool enable_msix)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_enable_mailbox_irq param = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	if (!disp_mgt)
		return -EINVAL;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vector_id = vector_id;
	param.enable_msix = enable_msix;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_MAILBOX_ENABLE_IRQ,
		      &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_enable_mailbox_irq_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_enable_mailbox_irq *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_enable_mailbox_irq *)data;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->enable_mailbox_irq,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id,
				param->vector_id, param->enable_msix);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_MAILBOX_ENABLE_IRQ, msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_MAILBOX_ENABLE_IRQ);
}

static u16 nbl_disp_chan_get_global_vector_req(void *priv, u16 vsi_id, u16 local_vector_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_global_vector param = {0};
	struct nbl_chan_param_get_global_vector result = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	if (!disp_mgt)
		return -EINVAL;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;
	param.vector_id = local_vector_id;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_GLOBAL_VECTOR,  &param,
		      sizeof(param), &result, sizeof(result), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return result.vector_id;
}

static void nbl_disp_chan_get_global_vector_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_global_vector *param;
	struct nbl_chan_param_get_global_vector result;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_get_global_vector *)data;

	result.vector_id = NBL_OPS_CALL(res_ops->get_global_vector,
					(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
					 param->vsi_id, param->vector_id));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_GLOBAL_VECTOR,
		     msg_id, err, &result, sizeof(result));
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_GET_GLOBAL_VECTOR);
}

static int nbl_disp_destroy_msix_map(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!disp_mgt)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->destroy_msix_map,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), 0);
	return ret;
}

static int nbl_disp_enable_mailbox_irq(void *priv, u16 vector_id, bool enable_msix)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!disp_mgt)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->enable_mailbox_irq,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), 0, vector_id, enable_msix);
	return ret;
}

static int nbl_disp_enable_abnormal_irq(void *priv, u16 vector_id, bool enable_msix)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!disp_mgt)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->enable_abnormal_irq,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vector_id, enable_msix));
	return ret;
}

static int nbl_disp_enable_adminq_irq(void *priv, u16 vector_id, bool enable_msix)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!disp_mgt)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->enable_adminq_irq,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vector_id, enable_msix));
	return ret;
}

static u16 nbl_disp_get_global_vector(void *priv, u16 vsi_id, u16 local_vector_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	u16 ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->get_global_vector,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, local_vector_id));
	return ret;
}

static u16 nbl_disp_get_msix_entry_id(void *priv, u16 vsi_id, u16 local_vector_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	u16 ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->get_msix_entry_id,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, local_vector_id));
	return ret;
}

static void nbl_disp_dump_flow(void *priv, struct seq_file *m)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->dump_flow, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), m);
}

static u16 nbl_disp_get_vsi_id(void *priv, u16 func_id, u16 type)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	if (!disp_mgt)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	return NBL_OPS_CALL(res_ops->get_vsi_id, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			    func_id, type));
}

static void nbl_disp_get_eth_id(void *priv, u16 vsi_id, u8 *eth_mode, u8 *eth_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->get_eth_id, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
					   vsi_id, eth_mode, eth_id));
}

static int nbl_disp_chan_add_lag_flow_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;

	NBL_CHAN_SEND(chan_send, 0, NBL_CHAN_MSG_ADD_LAG_FLOW, &vsi_id, sizeof(vsi_id),
		      NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_add_lag_flow_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_lag_flow,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), *(u16 *)data);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_ADD_LAG_FLOW, msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_ADD_LAG_FLOW);
}

static int nbl_disp_add_lag_flow(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_lag_flow,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static void nbl_disp_chan_del_lag_flow_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;

	NBL_CHAN_SEND(chan_send, 0, NBL_CHAN_MSG_DEL_LAG_FLOW, &vsi_id, sizeof(vsi_id),
		      NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_del_lag_flow_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_lag_flow, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  *(u16 *)data);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_DEL_LAG_FLOW, msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_DEL_LAG_FLOW);
}

static void nbl_disp_del_lag_flow(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_lag_flow,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static int nbl_disp_chan_add_lldp_flow_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;

	NBL_CHAN_SEND(chan_send, 0, NBL_CHAN_MSG_ADD_LLDP_FLOW, &vsi_id, sizeof(vsi_id),
		      NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_add_lldp_flow_resp(void *priv, u16 src_id, u16 msg_id,
					     void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_lldp_flow,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), *(u16 *)data);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_ADD_LLDP_FLOW, msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_ADD_LLDP_FLOW);
}

static int nbl_disp_add_lldp_flow(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_lldp_flow,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static void nbl_disp_chan_del_lldp_flow_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;

	NBL_CHAN_SEND(chan_send, 0, NBL_CHAN_MSG_DEL_LLDP_FLOW, &vsi_id, sizeof(vsi_id),
		      NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_del_lldp_flow_resp(void *priv, u16 src_id, u16 msg_id,
					     void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_lldp_flow, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  *(u16 *)data);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_DEL_LLDP_FLOW, msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_DEL_LLDP_FLOW);
}

static void nbl_disp_del_lldp_flow(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_lldp_flow,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static u32 nbl_disp_get_tx_headroom(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	u32 ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_tx_headroom, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	return ret;
}

static u8 __iomem *nbl_disp_get_hw_addr(void *priv, size_t *size)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	u8 __iomem *addr = NULL;

	addr = NBL_OPS_CALL(res_ops->get_hw_addr, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), size));
	return addr;
}

static u64 nbl_disp_get_real_hw_addr(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	u64 ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_real_hw_addr,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id));
	return ret;
}

static u16 nbl_disp_get_function_id(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	u16 ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_function_id, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id));
	return ret;
}

static void nbl_disp_get_real_bdf(void *priv, u16 vsi_id, u8 *bus, u8 *dev, u8 *function)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->get_real_bdf,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, bus, dev, function));
}

static bool nbl_disp_check_fw_heartbeat(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = false;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->check_fw_heartbeat, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	return ret;
}

static bool nbl_disp_check_fw_reset(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	return NBL_OPS_CALL(res_ops->check_fw_reset, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_flash_lock(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->flash_lock, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_flash_unlock(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->flash_unlock, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_flash_prepare(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->flash_prepare, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_flash_image(void *priv, u32 module, const u8 *data, size_t len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->flash_image,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), module, data, len));
}

static int nbl_disp_flash_activate(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->flash_activate, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_set_eth_loopback(void *priv, u8 enable)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	u8 eth_id = NBL_DISP_MGT_TO_COMMON(disp_mgt)->eth_id;

	return NBL_OPS_CALL(res_ops->setup_loopback,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, enable));
}

static int nbl_disp_chan_set_eth_loopback_req(void *priv, u8 enable)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_set_eth_loopback param = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.eth_port_id = NBL_DISP_MGT_TO_COMMON(disp_mgt)->eth_id;
	param.enable = enable;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_SET_ETH_LOOPBACK,  &param,
		      sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_eth_loopback_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	struct nbl_chan_param_set_eth_loopback *param;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_set_eth_loopback *)data;
	ret = NBL_OPS_CALL(res_ops->setup_loopback,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->eth_port_id, param->enable));
	if (ret)
		dev_err(dev, "setup loopback adminq failed with ret: %d\n", ret);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_ETH_LOOPBACK,
		     msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_SET_ETH_LOOPBACK);
}

static struct sk_buff *nbl_disp_clean_rx_lb_test(void *priv, u32 ring_index)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->clean_rx_lb_test,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), ring_index));
}

static u32 nbl_disp_check_active_vf(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->check_active_vf,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), 0));
}

static u32 nbl_disp_chan_check_active_vf_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct device *dev = NBL_DISP_MGT_TO_DEV(disp_mgt);
	u32 active_vf_num = 0;
	int ret;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_CHECK_ACTIVE_VF,  NULL, 0,
		      &active_vf_num, sizeof(active_vf_num), 1);
	ret = chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
	if (ret)
		dev_err(dev, "channel check active vf send msg failed with ret: %d\n", ret);

	return active_vf_num;
}

static void nbl_disp_chan_check_active_vf_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	u32 active_vf_num;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	active_vf_num = NBL_OPS_CALL(res_ops->check_active_vf,
				     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CHECK_ACTIVE_VF,
		     msg_id, err, &active_vf_num, sizeof(active_vf_num));
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_SET_ETH_LOOPBACK);
}

static u32 nbl_disp_get_adminq_tx_buf_size(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	return chan_ops->get_adminq_tx_buf_size(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt));
}

static bool nbl_disp_get_product_flex_cap(void *priv, enum nbl_flex_cap_type cap_type)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	bool has_cap = false;

	has_cap = NBL_OPS_CALL(res_ops->get_product_flex_cap, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
							       cap_type));
	return has_cap;
}

static bool nbl_disp_chan_get_product_flex_cap_req(void *priv, enum nbl_flex_cap_type cap_type)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;
	bool has_cap = false;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_PRODUCT_FLEX_CAP, &cap_type,
		      sizeof(cap_type), &has_cap, sizeof(has_cap), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return has_cap;
}

static void nbl_disp_chan_get_product_flex_cap_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	enum nbl_flex_cap_type *cap_type = (enum nbl_flex_cap_type *)data;
	struct nbl_chan_ack_info chan_ack = {0};
	bool has_cap = false;

	has_cap = NBL_OPS_CALL(res_ops->get_product_flex_cap,
			       (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), *cap_type));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_PRODUCT_FLEX_CAP, msg_id,
		     NBL_CHAN_RESP_OK, &has_cap, sizeof(has_cap));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static bool nbl_disp_get_product_fix_cap(void *priv, enum nbl_fix_cap_type cap_type)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	bool has_cap = false;

	has_cap = NBL_OPS_CALL(res_ops->get_product_fix_cap, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
							      cap_type));
	return has_cap;
}

static int nbl_disp_get_mbx_irq_num(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_mbx_irq_num, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_get_adminq_irq_num(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_adminq_irq_num, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_get_abnormal_irq_num(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_abnormal_irq_num, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static void nbl_disp_clear_flow(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->clear_flow,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static void nbl_disp_clear_queues(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->clear_queues,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static u16 nbl_disp_get_vsi_global_qid(void *priv, u16 vsi_id, u16 local_qid)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_vsi_global_queue_id,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, local_qid));
}

static u16
nbl_disp_chan_get_vsi_global_qid_req(void *priv, u16 vsi_id, u16 local_qid)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_vsi_qid_info param = {0};
	struct nbl_chan_send_info chan_send;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param.vsi_id = vsi_id;
	param.local_qid = local_qid;

	NBL_CHAN_SEND(chan_send, 0, NBL_CHAN_MSG_GET_VSI_GLOBAL_QUEUE_ID,
		      &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void
nbl_disp_chan_get_vsi_global_qid_resp(void *priv, u16 src_id, u16 msg_id,
				      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_vsi_qid_info *param;
	struct nbl_chan_ack_info chan_ack;
	u16 global_qid;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_vsi_qid_info *)data;
	global_qid = NBL_OPS_CALL(res_ops->get_vsi_global_queue_id,
				  (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
				  param->vsi_id, param->local_qid));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_VSI_GLOBAL_QUEUE_ID,
		     msg_id, global_qid, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_get_board_info_resp(void *priv, u16 src_id, u16 msg_id,
				  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	struct nbl_board_port_info board_info = {0};

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_board_info,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), &board_info));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_BOARD_INFO,
		     msg_id, 0, &board_info, sizeof(board_info));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_port_attributes(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_port_attributes, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	if (ret)
		dev_err(dev, "get port attributes failed with ret: %d\n", ret);

	return ret;
}

static int nbl_disp_update_ring_num(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->update_ring_num, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_set_ring_num(void *priv, struct nbl_fw_cmd_ring_num_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->set_ring_num, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param));
}

static int nbl_disp_enable_port(void *priv, bool enable)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int ret = 0;

	ret = NBL_OPS_CALL(res_ops->enable_port, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), enable));
	if (ret)
		dev_err(dev, "enable port failed with ret: %d\n", ret);

	return ret;
}

static void nbl_disp_chan_recv_port_notify_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	res_ops->recv_port_notify(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), data);
}

static int nbl_disp_get_port_state(void *priv, u8 eth_id,
				   struct nbl_port_state *port_state)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_port_state,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, port_state));
	return ret;
}

static int nbl_disp_chan_get_port_state_req(void *priv, u8 eth_id,
					    struct nbl_port_state *port_state)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf,
		      NBL_CHAN_MSG_GET_PORT_STATE, &eth_id, sizeof(eth_id),
		      port_state, sizeof(*port_state), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_port_state_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	struct nbl_port_state info = {0};
	int ret = 0;
	u8 eth_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	eth_id = *(u8 *)data;
	ret = NBL_OPS_CALL(res_ops->get_port_state,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, &info));
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_PORT_STATE, msg_id, err,
		     &info, sizeof(info));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_set_port_advertising(void *priv,
					 struct nbl_port_advertising *port_advertising)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int ret = 0;

	ret = NBL_OPS_CALL(res_ops->set_port_advertising,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), port_advertising));
	return ret;
}

static int nbl_disp_chan_set_port_advertising_req(void *priv,
						  struct nbl_port_advertising *port_advertising)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_SET_PORT_ADVERTISING,
		      port_advertising, sizeof(*port_advertising),
		      NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_port_advertising_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_port_advertising *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_port_advertising *)data;

	ret = res_ops->set_port_advertising(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_PORT_ADVERTISING, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_module_info(void *priv, u8 eth_id, struct ethtool_modinfo *info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return res_ops->get_module_info(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, info);
}

static int nbl_disp_chan_get_module_info_req(void *priv, u8 eth_id, struct ethtool_modinfo *info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf,
		      NBL_CHAN_MSG_GET_MODULE_INFO, &eth_id,
		      sizeof(eth_id), info, sizeof(*info), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_module_info_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	struct ethtool_modinfo info;
	int ret = 0;
	u8 eth_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	eth_id = *(u8 *)data;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_module_info,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, &info);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_MODULE_INFO, msg_id, err,
		     &info, sizeof(info));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_module_eeprom(void *priv, u8 eth_id,
				      struct ethtool_eeprom *eeprom, u8 *data)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return res_ops->get_module_eeprom(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, eeprom, data);
}

static int nbl_disp_chan_get_module_eeprom_req(void *priv, u8 eth_id,
					       struct ethtool_eeprom *eeprom, u8 *data)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_module_eeprom param = {0};
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.eth_id = eth_id;
	memcpy(&param.eeprom, eeprom, sizeof(struct ethtool_eeprom));

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_MODULE_EEPROM, &param,
		      sizeof(param), data, eeprom->len, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_module_eeprom_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_module_eeprom *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u8 eth_id;
	struct ethtool_eeprom *eeprom;
	u8 *recv_data;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_get_module_eeprom *)data;
	eth_id = param->eth_id;
	eeprom = &param->eeprom;
	recv_data = kmalloc(eeprom->len, GFP_ATOMIC);
	if (!recv_data) {
		dev_err(dev, "Allocate memory to store module eeprom failed\n");
		return;
	}

	ret = res_ops->get_module_eeprom(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
					 eth_id, eeprom, recv_data);
	if (ret) {
		err = NBL_CHAN_RESP_ERR;
		dev_err(dev, "Get module eeprom failed with ret: %d\n", ret);
	}

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_MODULE_EEPROM, msg_id, err,
		     recv_data, eeprom->len);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d, src_id: %d\n",
			ret, NBL_CHAN_MSG_GET_MODULE_EEPROM, src_id);
	kfree(recv_data);
}

static int nbl_disp_get_link_state(void *priv, u8 eth_id, struct nbl_eth_link_info *eth_link_info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	/* if donot have res_ops->get_link_state(), default eth is up */
	if (res_ops->get_link_state)
		ret = res_ops->get_link_state(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
					      eth_id, eth_link_info);
	else
		eth_link_info->link_status = 1;

	return ret;
}

static int nbl_disp_chan_get_link_state_req(void *priv, u8 eth_id,
					    struct nbl_eth_link_info *eth_link_info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf,
		      NBL_CHAN_MSG_GET_LINK_STATE, &eth_id,
		      sizeof(eth_id), eth_link_info, sizeof(*eth_link_info), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_link_state_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u8 eth_id;
	struct nbl_eth_link_info eth_link_info = {0};
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	eth_id = *(u8 *)data;
	ret = res_ops->get_link_state(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
					 eth_id, &eth_link_info);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_LINK_STATE, msg_id, err,
		     &eth_link_info, sizeof(eth_link_info));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_get_reg_dump(void *priv, u32 *data, u32 len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->get_reg_dump, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), data, len));
}

static void nbl_disp_chan_get_reg_dump_req(void *priv, u32 *data, u32 len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;
	u32 *result = NULL;

	result = kmalloc(len, GFP_KERNEL);
	if (!result)
		return;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_REG_DUMP, &len, sizeof(len),
		      result, len, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	memcpy(data, result, len);
	kfree(result);
}

static void nbl_disp_chan_get_reg_dump_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u32 *result = NULL;
	u32 len = 0;

	len = *(u32 *)data;
	result = kmalloc(len, GFP_KERNEL);
	if (!result)
		return;

	NBL_OPS_CALL(res_ops->get_reg_dump, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), result, len));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_REG_DUMP, msg_id, err, result, len);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	kfree(result);
}

static int nbl_disp_get_reg_dump_len(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_reg_dump_len, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_chan_get_reg_dump_len_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;
	int result = 0;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_REG_DUMP_LEN, NULL, 0,
		      &result, sizeof(result), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return result;
}

static void nbl_disp_chan_get_reg_dump_len_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int result = 0;

	result = NBL_OPS_CALL(res_ops->get_reg_dump_len, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_REG_DUMP_LEN, msg_id, err,
		     &result, sizeof(result));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_set_eth_mac_addr(void *priv, u8 *mac, u8 eth_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->set_eth_mac_addr,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mac, eth_id));
}

static int nbl_disp_chan_set_eth_mac_addr_req(void *priv, u8 *mac, u8 eth_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_eth_mac_addr param;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	memcpy(param.mac, mac, sizeof(param.mac));
	param.eth_id = eth_id;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_SET_ETH_MAC_ADDR,
		      &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_eth_mac_addr_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_eth_mac_addr *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_set_eth_mac_addr *)data;

	ret = NBL_OPS_CALL(res_ops->set_eth_mac_addr,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->mac, param->eth_id));
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_ETH_MAC_ADDR, msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_SET_ETH_MAC_ADDR);
}

static u32 nbl_disp_get_chip_temperature(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return res_ops->get_chip_temperature(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static u32 nbl_disp_chan_get_chip_temperature_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;
	u32 chip_tempetature = 0;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf,
		      NBL_CHAN_MSG_GET_CHIP_TEMPERATURE, NULL, 0,
		      &chip_tempetature, sizeof(chip_tempetature), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return chip_tempetature;
}

static void nbl_disp_chan_get_chip_temperature_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	u32 chip_tempetature = 0;

	chip_tempetature = NBL_OPS_CALL(res_ops->get_chip_temperature,
					(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_CHIP_TEMPERATURE, msg_id,
		     ret, &chip_tempetature, sizeof(chip_tempetature));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static u32 nbl_disp_get_chip_temperature_max(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return res_ops->get_chip_temperature_max(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static u32 nbl_disp_get_chip_temperature_crit(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return res_ops->get_chip_temperature_crit(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static int nbl_disp_get_module_temperature(void *priv, u8 eth_id,
					   enum nbl_module_temp_type type)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_module_temperature,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, type));
}

static int nbl_disp_chan_get_module_temperature_req(void *priv, u8 eth_id,
						    enum nbl_module_temp_type type)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	int module_temp;
	struct nbl_chan_param_get_module_tempetature param = {0};
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	param.eth_id = eth_id;
	param.type = type;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_MODULE_TEMPERATURE,
		      &param, sizeof(param), &module_temp, sizeof(module_temp), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return module_temp;
}

static void nbl_disp_chan_get_module_temperature_resp(void *priv, u16 src_id, u16 msg_id,
						      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	int module_temp;
	struct nbl_chan_param_get_module_tempetature *param;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_get_module_tempetature *)data;
	module_temp = NBL_OPS_CALL(res_ops->get_module_temperature,
				   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
				    param->eth_id, param->type));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_MODULE_TEMPERATURE, msg_id,
		     ret, &module_temp, sizeof(module_temp));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_process_abnormal_event(void *priv, struct nbl_abnormal_event_info *abnomal_info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return res_ops->process_abnormal_event(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), abnomal_info);
}

static void nbl_disp_adapt_desc_gother(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->adapt_desc_gother, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static void nbl_disp_flr_clear_net(void *priv, u16 vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->flr_clear_net,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vf_id);
}

static void nbl_disp_flr_clear_queues(void *priv, u16 vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->flr_clear_queues,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vf_id);
}

static void nbl_disp_flr_clear_flows(void *priv, u16 vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->flr_clear_flows,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vf_id);
}

static void nbl_disp_flr_clear_interrupt(void *priv, u16 vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->flr_clear_interrupt,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vf_id);
}

static void nbl_disp_unmask_all_interrupts(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->unmask_all_interrupts,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static void nbl_disp_keep_alive_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_KEEP_ALIVE,
		      NULL, 0, NULL, 0, 1);

	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_keep_alive_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_KEEP_ALIVE, msg_id,
		     0, NULL, 0);

	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_get_user_queue_info_req(void *priv, u16 *queue_num, u16 *queue_size,
						  u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_get_queue_info result = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_GET_USER_QUEUE_INFO,
		      &vsi_id, sizeof(vsi_id), &result, sizeof(result), 1);

	if (!chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send)) {
		*queue_num = result.queue_num;
		*queue_size = result.queue_size;
	}
}

static void nbl_disp_chan_get_user_queue_info_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	struct nbl_chan_param_get_queue_info result = {0};
	int ret = NBL_CHAN_RESP_OK;

	NBL_OPS_CALL(res_ops->get_user_queue_info,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), &result.queue_num,
		      &result.queue_size, *(u16 *)data));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_USER_QUEUE_INFO, msg_id,
		     ret, &result, sizeof(result));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_get_user_queue_info(void *priv, u16 *queue_num, u16 *queue_size, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->get_user_queue_info,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), queue_num, queue_size, vsi_id));
}

static int nbl_disp_ctrl_port_led(void *priv, u8 eth_id,
				  enum nbl_led_reg_ctrl led_ctrl, u32 *led_reg)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->ctrl_port_led,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, led_ctrl, led_reg));
}

static int nbl_disp_chan_ctrl_port_led_req(void *priv, u8 eth_id,
					   enum nbl_led_reg_ctrl led_ctrl,
					   u32 *led_reg)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_ctrl_port_led param = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.eth_id = eth_id;
	param.led_status = led_ctrl;
	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_CTRL_PORT_LED,
		      &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_ctrl_port_led_resp(void *priv, u16 src_id, u16 msg_id,
					     void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	struct nbl_chan_param_ctrl_port_led *param = {0};
	int ret = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_ctrl_port_led *)data;
	ret = NBL_OPS_CALL(res_ops->ctrl_port_led,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			   param->eth_id, param->led_status, NULL));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CTRL_PORT_LED, msg_id,
		     ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_passthrough_fw_cmd(void *priv, struct nbl_passthrough_fw_cmd_param *param,
				       struct nbl_passthrough_fw_cmd_param *result)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->passthrough_fw_cmd,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param, result));
}

static int nbl_disp_nway_reset(void *priv, u8 eth_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->nway_reset, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id));
}

static int nbl_disp_chan_nway_reset_req(void *priv, u8 eth_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_NWAY_RESET,
		      &eth_id, sizeof(eth_id), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_nway_reset_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	u8 *eth_id;
	int ret = NBL_CHAN_RESP_OK;

	eth_id = (u8 *)data;
	ret = NBL_OPS_CALL(res_ops->nway_reset,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), *eth_id));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_NWAY_RESET, msg_id,
		     ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static u16 nbl_disp_get_vf_base_vsi_id(void *priv, u16 func_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_vf_base_vsi_id,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), func_id));
}

static u16 nbl_disp_chan_get_vf_base_vsi_id_req(void *priv, u16 func_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	u16 vf_base_vsi_id = 0;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_VF_BASE_VSI_ID,
		      NULL, 0, &vf_base_vsi_id, sizeof(vf_base_vsi_id), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return vf_base_vsi_id;
}

static void nbl_disp_chan_get_vf_base_vsi_id_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	u16 vf_base_vsi_id;

	vf_base_vsi_id = NBL_OPS_CALL(res_ops->get_vf_base_vsi_id,
				      (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_VF_BASE_VSI_ID, msg_id,
		     ret, &vf_base_vsi_id, sizeof(vf_base_vsi_id));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static u16 nbl_disp_get_intr_suppress_level(void *priv, u64 pkt_rates, u16 last_level)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	return NBL_OPS_CALL(res_ops->get_intr_suppress_level,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), pkt_rates, last_level));
}

static void nbl_disp_set_intr_suppress_level(void *priv, u16 vector_id, u16 vector_num, u16 level)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_intr_suppress_level,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), common->mgt_pf,
			  vector_id, vector_num, level);
}

static void nbl_disp_chan_set_intr_suppress_level_req(void *priv, u16 vector_id,
						      u16 vector_num, u16 level)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_intr_suppress_level param = {0};
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.local_vector_id = vector_id;
	param.vector_num = vector_num;
	param.level = level;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_SET_INTL_SUPPRESS_LEVEL,
		      &param, sizeof(param), NULL, 0, 0);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_intr_suppress_level_resp(void *priv, u16 src_id, u16 msg_id,
						       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_intr_suppress_level *param;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_set_intr_suppress_level *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_intr_suppress_level,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id, param->local_vector_id,
			  param->vector_num, param->level);
}

static int nbl_disp_get_p4_info(void *priv, char *verify_code)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_p4_info,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), verify_code));
}

static int nbl_disp_load_p4(void *priv, struct nbl_load_p4_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->load_p4, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param));
}

static int nbl_disp_load_p4_default(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->load_p4_default, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_chan_get_p4_used_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	int p4_type;

	NBL_CHAN_SEND(chan_send, common->mgt_pf, NBL_CHAN_MSG_GET_P4_USED,
		      NULL, 0, &p4_type, sizeof(p4_type), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return p4_type;
}

static void nbl_disp_chan_get_p4_used_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	int p4_type;

	p4_type = NBL_OPS_CALL(res_ops->get_p4_used, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_P4_USED, msg_id,
		     ret, &p4_type, sizeof(p4_type));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_p4_used(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_p4_used, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_set_p4_used(void *priv, int p4_type)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->set_p4_used, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), p4_type));
}

static int nbl_disp_chan_get_board_id_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	int result = -1;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_GET_BOARD_ID,
		      NULL, 0, &result, sizeof(result), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return result;
}

static void nbl_disp_chan_get_board_id_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK, result = -1;

	result = NBL_OPS_CALL(res_ops->get_board_id, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_BOARD_ID,
		     msg_id, ret, &result, sizeof(result));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_board_id(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_board_id, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static dma_addr_t nbl_disp_restore_abnormal_ring(void *priv, int ring_index, int type)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->restore_abnormal_ring,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), ring_index, type));
}

static int nbl_disp_restart_abnormal_ring(void *priv, int ring_index, int type)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->restart_abnormal_ring,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), ring_index, type));
}

static int nbl_disp_chan_restore_hw_queue_req(void *priv, u16 vsi_id, u16 local_queue_id,
					      dma_addr_t dma, int type)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_param_restore_hw_queue param = {0};
	struct nbl_chan_send_info chan_send = {0};

	param.vsi_id = vsi_id;
	param.local_queue_id = local_queue_id;
	param.dma = dma;
	param.type = type;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_RESTORE_HW_QUEUE, &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_restore_hw_queue_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_restore_hw_queue *param = NULL;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_restore_hw_queue *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->restore_hw_queue, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  param->vsi_id, param->local_queue_id, param->dma, param->type);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_RESTORE_HW_QUEUE, msg_id, ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_restore_hw_queue(void *priv, u16 vsi_id, u16 local_queue_id,
				     dma_addr_t dma, int type)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->restore_hw_queue,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
				 vsi_id, local_queue_id, dma, type);
}

static u16 nbl_disp_get_local_queue_id(void *priv, u16 vsi_id, u16 global_queue_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_local_queue_id, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			    vsi_id, global_queue_id));
}

static int nbl_disp_set_bridge_mode(void *priv, u16 bmode)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_bridge_mode,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
				 NBL_COMMON_TO_MGT_PF(common), bmode);
}

static int nbl_disp_chan_set_bridge_mode_req(void *priv, u16 bmode)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_SET_BRIDGE_MODE, &bmode, sizeof(bmode), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_bridge_mode_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	u16 *bmode;

	bmode = (u16 *)data;
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_bridge_mode,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id, *bmode);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_BRIDGE_MODE,
		     msg_id, ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static u16 nbl_disp_get_vf_function_id(void *priv, u16 vsi_id, int vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_vf_function_id,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, vf_id));
}

static u16 nbl_disp_chan_get_vf_function_id_req(void *priv, u16 vsi_id, int vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_get_vf_func_id param;
	struct nbl_common_info *common;
	u16 func_id = 0;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	param.vsi_id = vsi_id;
	param.vf_id = vf_id;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_VF_FUNCTION_ID, &param,
		      sizeof(param), &func_id, sizeof(func_id), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return func_id;
}

static void nbl_disp_chan_get_vf_function_id_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_get_vf_func_id *param;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	u16 func_id;

	param = (struct nbl_chan_param_get_vf_func_id *)data;
	func_id = NBL_OPS_CALL(res_ops->get_vf_function_id,
			       (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id, param->vf_id));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_VF_FUNCTION_ID, msg_id,
		     ret, &func_id, sizeof(func_id));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

/* NBL_DISP_SET_OPS(disp_op_name, res_func, ctrl_lvl, msg_type, msg_req, msg_resp)
 * ctrl_lvl is to define when this disp_op should go directly to res_op, not sending a channel msg.
 *
 * Use X Macros to reduce codes in channel_op and disp_op setup/remove
 */
#define NBL_DISP_OPS_TBL									\
do {												\
	NBL_DISP_SET_OPS(init_chip_module, nbl_disp_init_chip_module,				\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_resource_pt_ops, nbl_disp_get_res_pt_ops,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(queue_init, nbl_disp_queue_init,					\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(vsi_init, nbl_disp_vsi_init,						\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(configure_msix_map, nbl_disp_configure_msix_map,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CONFIGURE_MSIX_MAP,		\
			 nbl_disp_chan_configure_msix_map_req,					\
			 nbl_disp_chan_configure_msix_map_resp);				\
	NBL_DISP_SET_OPS(destroy_msix_map, nbl_disp_destroy_msix_map,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_DESTROY_MSIX_MAP,			\
			 nbl_disp_chan_destroy_msix_map_req,					\
			 nbl_disp_chan_destroy_msix_map_resp);					\
	NBL_DISP_SET_OPS(enable_mailbox_irq, nbl_disp_enable_mailbox_irq,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_MAILBOX_ENABLE_IRQ,		\
			 nbl_disp_chan_enable_mailbox_irq_req,					\
			 nbl_disp_chan_enable_mailbox_irq_resp);				\
	NBL_DISP_SET_OPS(enable_abnormal_irq, nbl_disp_enable_abnormal_irq,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(enable_adminq_irq, nbl_disp_enable_adminq_irq,				\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_global_vector, nbl_disp_get_global_vector,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_GLOBAL_VECTOR,			\
			 nbl_disp_chan_get_global_vector_req,					\
			 nbl_disp_chan_get_global_vector_resp);					\
	NBL_DISP_SET_OPS(get_msix_entry_id, nbl_disp_get_msix_entry_id,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(alloc_rings, nbl_disp_alloc_rings,					\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(remove_rings, nbl_disp_remove_rings,					\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(start_tx_ring, nbl_disp_start_tx_ring,					\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(stop_tx_ring, nbl_disp_stop_tx_ring,					\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(start_rx_ring, nbl_disp_start_rx_ring,					\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(stop_rx_ring, nbl_disp_stop_rx_ring,					\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(kick_rx_ring, nbl_disp_kick_rx_ring,					\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(dump_ring, nbl_disp_dump_ring,						\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(dump_ring_stats, nbl_disp_dump_ring_stats,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_vector_napi, nbl_disp_get_vector_napi,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(set_vector_info, nbl_disp_set_vector_info,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(register_vsi_ring, nbl_disp_register_vsi_ring,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(register_net, nbl_disp_register_net,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REGISTER_NET,			\
			 nbl_disp_chan_register_net_req, nbl_disp_chan_register_net_resp);	\
	NBL_DISP_SET_OPS(unregister_net, nbl_disp_unregister_net,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_UNREGISTER_NET,			\
			 nbl_disp_chan_unregister_net_req, nbl_disp_chan_unregister_net_resp);	\
	NBL_DISP_SET_OPS(alloc_txrx_queues, nbl_disp_alloc_txrx_queues,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ALLOC_TXRX_QUEUES,			\
			 nbl_disp_chan_alloc_txrx_queues_req,					\
			 nbl_disp_chan_alloc_txrx_queues_resp);					\
	NBL_DISP_SET_OPS(free_txrx_queues, nbl_disp_free_txrx_queues,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_FREE_TXRX_QUEUES,			\
			 nbl_disp_chan_free_txrx_queues_req,					\
			 nbl_disp_chan_free_txrx_queues_resp);					\
	NBL_DISP_SET_OPS(register_vsi2q, nbl_disp_register_vsi2q,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REGISTER_VSI2Q,			\
			 nbl_disp_chan_register_vsi2q_req,					\
			 nbl_disp_chan_register_vsi2q_resp);					\
	NBL_DISP_SET_OPS(setup_q2vsi, nbl_disp_setup_q2vsi,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SETUP_Q2VSI,			\
			 nbl_disp_chan_setup_q2vsi_req,						\
			 nbl_disp_chan_setup_q2vsi_resp);					\
	NBL_DISP_SET_OPS(remove_q2vsi, nbl_disp_remove_q2vsi,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REMOVE_Q2VSI,			\
			 nbl_disp_chan_remove_q2vsi_req,					\
			 nbl_disp_chan_remove_q2vsi_resp);					\
	NBL_DISP_SET_OPS(setup_rss, nbl_disp_setup_rss,						\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SETUP_RSS,				\
			 nbl_disp_chan_setup_rss_req,						\
			 nbl_disp_chan_setup_rss_resp);						\
	NBL_DISP_SET_OPS(remove_rss, nbl_disp_remove_rss,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REMOVE_RSS,			\
			 nbl_disp_chan_remove_rss_req,						\
			 nbl_disp_chan_remove_rss_resp);					\
	NBL_DISP_SET_OPS(setup_queue, nbl_disp_setup_queue,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SETUP_QUEUE,			\
			 nbl_disp_chan_setup_queue_req, nbl_disp_chan_setup_queue_resp);	\
	NBL_DISP_SET_OPS(remove_all_queues, nbl_disp_remove_all_queues,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REMOVE_ALL_QUEUES,			\
			 nbl_disp_chan_remove_all_queues_req,					\
			 nbl_disp_chan_remove_all_queues_resp);					\
	NBL_DISP_SET_OPS(cfg_dsch, nbl_disp_cfg_dsch,						\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_DSCH,				\
			 nbl_disp_chan_cfg_dsch_req, nbl_disp_chan_cfg_dsch_resp);		\
	NBL_DISP_SET_OPS(setup_cqs, nbl_disp_setup_cqs,						\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SETUP_CQS,				\
			 nbl_disp_chan_setup_cqs_req, nbl_disp_chan_setup_cqs_resp);		\
	NBL_DISP_SET_OPS(remove_cqs, nbl_disp_remove_cqs,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REMOVE_CQS,			\
			 nbl_disp_chan_remove_cqs_req, nbl_disp_chan_remove_cqs_resp);		\
	NBL_DISP_SET_OPS(enable_msix_irq, nbl_disp_enable_msix_irq,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_msix_irq_enable_info, nbl_disp_get_msix_irq_enable_info,		\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(add_macvlan, nbl_disp_add_macvlan,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ADD_MACVLAN,			\
			 nbl_disp_chan_add_macvlan_req, nbl_disp_chan_add_macvlan_resp);	\
	NBL_DISP_SET_OPS(del_macvlan, nbl_disp_del_macvlan,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_DEL_MACVLAN,			\
			 nbl_disp_chan_del_macvlan_req, nbl_disp_chan_del_macvlan_resp);	\
	NBL_DISP_SET_OPS(add_multi_rule, nbl_disp_add_multi_rule,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ADD_MULTI_RULE,			\
			 nbl_disp_chan_add_multi_rule_req, nbl_disp_chan_add_multi_rule_resp);	\
	NBL_DISP_SET_OPS(del_multi_rule, nbl_disp_del_multi_rule,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_DEL_MULTI_RULE,			\
			 nbl_disp_chan_del_multi_rule_req, nbl_disp_chan_del_multi_rule_resp);	\
	NBL_DISP_SET_OPS(setup_multi_group, nbl_disp_setup_multi_group,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SETUP_MULTI_GROUP,			\
			 nbl_disp_chan_setup_multi_group_req,					\
			 nbl_disp_chan_setup_multi_group_resp);					\
	NBL_DISP_SET_OPS(remove_multi_group, nbl_disp_remove_multi_group,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REMOVE_MULTI_GROUP,		\
			 nbl_disp_chan_remove_multi_group_req,					\
			 nbl_disp_chan_remove_multi_group_resp);				\
	NBL_DISP_SET_OPS(dump_flow, nbl_disp_dump_flow,						\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_vsi_id, nbl_disp_get_vsi_id,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_VSI_ID,			\
			 nbl_disp_chan_get_vsi_id_req, nbl_disp_chan_get_vsi_id_resp);		\
	NBL_DISP_SET_OPS(get_eth_id, nbl_disp_get_eth_id,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_ETH_ID,			\
			 nbl_disp_chan_get_eth_id_req, nbl_disp_chan_get_eth_id_resp);		\
	NBL_DISP_SET_OPS(add_lldp_flow, nbl_disp_add_lldp_flow,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ADD_LLDP_FLOW,			\
			 nbl_disp_chan_add_lldp_flow_req, nbl_disp_chan_add_lldp_flow_resp);	\
	NBL_DISP_SET_OPS(del_lldp_flow, nbl_disp_del_lldp_flow,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_DEL_LLDP_FLOW,			\
			 nbl_disp_chan_del_lldp_flow_req, nbl_disp_chan_del_lldp_flow_resp);	\
	NBL_DISP_SET_OPS(add_lag_flow, nbl_disp_add_lag_flow,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ADD_LAG_FLOW,			\
			 nbl_disp_chan_add_lag_flow_req, nbl_disp_chan_add_lag_flow_resp);	\
	NBL_DISP_SET_OPS(del_lag_flow, nbl_disp_del_lag_flow,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_DEL_LAG_FLOW,			\
			 nbl_disp_chan_del_lag_flow_req, nbl_disp_chan_del_lag_flow_resp);	\
	NBL_DISP_SET_OPS(set_promisc_mode, nbl_disp_set_promisc_mode,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_PROSISC_MODE,			\
			 nbl_disp_chan_set_promisc_mode_req,					\
			 nbl_disp_chan_set_promisc_mode_resp);					\
	NBL_DISP_SET_OPS(set_spoof_check_addr, nbl_disp_set_spoof_check_addr,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_SPOOF_CHECK_ADDR,		\
			 nbl_disp_chan_set_spoof_check_addr_req,				\
			 nbl_disp_chan_set_spoof_check_addr_resp);				\
	NBL_DISP_SET_OPS(set_vf_spoof_check, nbl_disp_set_vf_spoof_check,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_VF_SPOOF_CHECK,		\
			 nbl_disp_chan_set_vf_spoof_check_req,					\
			 nbl_disp_chan_set_vf_spoof_check_resp);				\
	NBL_DISP_SET_OPS(get_base_mac_addr, nbl_disp_get_base_mac_addr,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_BASE_MAC_ADDR,			\
			 nbl_disp_chan_get_base_mac_addr_req,					\
			 nbl_disp_chan_get_base_mac_addr_resp);					\
	NBL_DISP_SET_OPS(get_tx_headroom, nbl_disp_get_tx_headroom,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_firmware_version, nbl_disp_get_firmware_version,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_FIRMWARE_VERSION,		\
			 nbl_disp_chan_get_firmware_version_req,				\
			 nbl_disp_chan_get_firmware_version_resp);				\
	NBL_DISP_SET_OPS(get_driver_info, nbl_disp_get_driver_info,				\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_queue_stats, nbl_disp_get_queue_stats,				\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_queue_err_stats, nbl_disp_get_queue_err_stats,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_QUEUE_ERR_STATS,		\
			 nbl_disp_chan_get_queue_err_stats_req,					\
			 nbl_disp_chan_get_queue_err_stats_resp);				\
	NBL_DISP_SET_OPS(get_net_stats, nbl_disp_get_net_stats,					\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_private_stat_len, nbl_disp_get_private_stat_len,			\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_private_stat_data, nbl_disp_get_private_stat_data,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_ETH_STATS,			\
			 nbl_disp_get_private_stat_data_req,					\
			 nbl_disp_chan_get_private_stat_data_resp);				\
	NBL_DISP_SET_OPS(fill_private_stat_strings, nbl_disp_fill_private_stat_strings,		\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_max_desc_num, nbl_disp_get_max_desc_num,				\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_min_desc_num, nbl_disp_get_min_desc_num,				\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_tx_desc_num, nbl_disp_get_tx_desc_num,				\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_rx_desc_num, nbl_disp_get_rx_desc_num,				\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(set_tx_desc_num, nbl_disp_set_tx_desc_num,				\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(set_rx_desc_num, nbl_disp_set_rx_desc_num,				\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(set_eth_loopback, nbl_disp_set_eth_loopback,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_ETH_LOOPBACK,			\
			 nbl_disp_chan_set_eth_loopback_req,					\
			 nbl_disp_chan_set_eth_loopback_resp);					\
	NBL_DISP_SET_OPS(clean_rx_lb_test, nbl_disp_clean_rx_lb_test,				\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_coalesce, nbl_disp_get_coalesce,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_COALESCE,			\
			 nbl_disp_chan_get_coalesce_req,					\
			 nbl_disp_chan_get_coalesce_resp);					\
	NBL_DISP_SET_OPS(set_coalesce, nbl_disp_set_coalesce,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_COALESCE,			\
			 nbl_disp_chan_set_coalesce_req,					\
			 nbl_disp_chan_set_coalesce_resp);					\
	NBL_DISP_SET_OPS(get_intr_suppress_level, nbl_disp_get_intr_suppress_level,		\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(set_intr_suppress_level, nbl_disp_set_intr_suppress_level,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_INTL_SUPPRESS_LEVEL,		\
			 nbl_disp_chan_set_intr_suppress_level_req,				\
			 nbl_disp_chan_set_intr_suppress_level_resp);				\
	NBL_DISP_SET_OPS(get_rxfh_indir_size, nbl_disp_get_rxfh_indir_size,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_RXFH_INDIR_SIZE,		\
			 nbl_disp_chan_get_rxfh_indir_size_req,					\
			 nbl_disp_chan_get_rxfh_indir_size_resp);				\
	NBL_DISP_SET_OPS(get_rxfh_rss_key_size, nbl_disp_get_rxfh_rss_key_size,			\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_rxfh_indir, nbl_disp_get_rxfh_indir,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_RXFH_INDIR,			\
			 nbl_disp_chan_get_rxfh_indir_req, nbl_disp_chan_get_rxfh_indir_resp);	\
	NBL_DISP_SET_OPS(get_rxfh_rss_key, nbl_disp_get_rxfh_rss_key,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_RXFH_RSS_KEY,			\
			 nbl_disp_chan_get_rxfh_rss_key_req,					\
			 nbl_disp_chan_get_rxfh_rss_key_resp);					\
	NBL_DISP_SET_OPS(get_rxfh_rss_alg_sel, nbl_disp_get_rxfh_rss_alg_sel,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_RXFH_RSS_ALG_SEL,		\
			 nbl_disp_chan_get_rxfh_rss_alg_sel_req,				\
			 nbl_disp_chan_get_rxfh_rss_alg_sel_resp);				\
	NBL_DISP_SET_OPS(get_hw_addr, nbl_disp_get_hw_addr,					\
			 NBL_DISP_CTRL_LVL_ALWAYS, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_real_hw_addr, nbl_disp_get_real_hw_addr,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_REAL_HW_ADDR,			\
			 nbl_disp_chan_get_real_hw_addr_req,					\
			 nbl_disp_chan_get_real_hw_addr_resp);					\
	NBL_DISP_SET_OPS(get_function_id, nbl_disp_get_function_id,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_FUNCTION_ID,			\
			 nbl_disp_chan_get_function_id_req, nbl_disp_chan_get_function_id_resp);\
	NBL_DISP_SET_OPS(get_real_bdf, nbl_disp_get_real_bdf,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_REAL_BDF,			\
			 nbl_disp_chan_get_real_bdf_req, nbl_disp_chan_get_real_bdf_resp);	\
	NBL_DISP_SET_OPS(check_fw_heartbeat, nbl_disp_check_fw_heartbeat,			\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(check_fw_reset, nbl_disp_check_fw_reset,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(flash_lock, nbl_disp_flash_lock,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(flash_unlock, nbl_disp_flash_unlock,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(flash_prepare, nbl_disp_flash_prepare,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(flash_image, nbl_disp_flash_image,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(flash_activate, nbl_disp_flash_activate,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_phy_caps, nbl_disp_get_phy_caps,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_PHY_CAPS,			\
			 nbl_disp_chan_get_phy_caps_req,					\
			 nbl_disp_chan_get_phy_caps_resp);					\
	NBL_DISP_SET_OPS(get_phy_state, nbl_disp_get_phy_state,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_PHY_STATE,			\
			 nbl_disp_chan_get_phy_state_req,					\
			 nbl_disp_chan_get_phy_state_resp);					\
	NBL_DISP_SET_OPS(set_sfp_state, nbl_disp_set_sfp_state,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_SFP_STATE,			\
			 nbl_disp_chan_set_sfp_state_req,					\
			 nbl_disp_chan_set_sfp_state_resp);					\
	NBL_DISP_SET_OPS(passthrough_fw_cmd, nbl_disp_passthrough_fw_cmd,			\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(check_active_vf, nbl_disp_check_active_vf,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CHECK_ACTIVE_VF,			\
			 nbl_disp_chan_check_active_vf_req,					\
			 nbl_disp_chan_check_active_vf_resp);					\
	NBL_DISP_SET_OPS(get_adminq_tx_buf_size, nbl_disp_get_adminq_tx_buf_size,		\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_product_flex_cap, nbl_disp_get_product_flex_cap,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_PRODUCT_FLEX_CAP,		\
			 nbl_disp_chan_get_product_flex_cap_req,				\
			 nbl_disp_chan_get_product_flex_cap_resp);				\
	NBL_DISP_SET_OPS(get_product_fix_cap, nbl_disp_get_product_fix_cap,			\
			 NBL_DISP_CTRL_LVL_ALWAYS, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_mbx_irq_num, nbl_disp_get_mbx_irq_num,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_MBX_IRQ_NUM,			\
			 nbl_disp_chan_get_mbx_irq_num_req,					\
			 nbl_disp_chan_get_mbx_irq_num_resp);					\
	NBL_DISP_SET_OPS(get_adminq_irq_num, nbl_disp_get_adminq_irq_num,			\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_abnormal_irq_num, nbl_disp_get_abnormal_irq_num,			\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(clear_flow, nbl_disp_clear_flow,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CLEAR_FLOW,			\
			 nbl_disp_chan_clear_flow_req, nbl_disp_chan_clear_flow_resp);		\
	NBL_DISP_SET_OPS(clear_queues, nbl_disp_clear_queues,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CLEAR_QUEUE,			\
			 nbl_disp_chan_clear_queues_req, nbl_disp_chan_clear_queues_resp);	\
	NBL_DISP_SET_OPS(get_reg_dump, nbl_disp_get_reg_dump,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_REG_DUMP,			\
			 nbl_disp_chan_get_reg_dump_req,					\
			 nbl_disp_chan_get_reg_dump_resp);					\
	NBL_DISP_SET_OPS(get_reg_dump_len, nbl_disp_get_reg_dump_len,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_REG_DUMP_LEN,			\
			 nbl_disp_chan_get_reg_dump_len_req,					\
			 nbl_disp_chan_get_reg_dump_len_resp);					\
	NBL_DISP_SET_OPS(get_p4_info, nbl_disp_get_p4_info,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(load_p4, nbl_disp_load_p4,						\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(load_p4_default, nbl_disp_load_p4_default,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_p4_used, nbl_disp_get_p4_used,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_P4_USED,			\
			 nbl_disp_chan_get_p4_used_req,	nbl_disp_chan_get_p4_used_resp);	\
	NBL_DISP_SET_OPS(set_p4_used, nbl_disp_set_p4_used,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_board_id, nbl_disp_get_board_id,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_BOARD_ID,			\
			 nbl_disp_chan_get_board_id_req, nbl_disp_chan_get_board_id_resp);	\
	NBL_DISP_SET_OPS(restore_abnormal_ring, nbl_disp_restore_abnormal_ring,			\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(restart_abnormal_ring, nbl_disp_restart_abnormal_ring,			\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(restore_hw_queue, nbl_disp_restore_hw_queue,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_RESTORE_HW_QUEUE,			\
			 nbl_disp_chan_restore_hw_queue_req,					\
			 nbl_disp_chan_restore_hw_queue_resp);					\
	NBL_DISP_SET_OPS(get_local_queue_id, nbl_disp_get_local_queue_id,			\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_vsi_global_queue_id, nbl_disp_get_vsi_global_qid,			\
			 NBL_DISP_CTRL_LVL_MGT,							\
			 NBL_CHAN_MSG_GET_VSI_GLOBAL_QUEUE_ID,					\
			 nbl_disp_chan_get_vsi_global_qid_req,					\
			 nbl_disp_chan_get_vsi_global_qid_resp);				\
	NBL_DISP_SET_OPS(get_port_attributes, nbl_disp_get_port_attributes,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(update_ring_num, nbl_disp_update_ring_num,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(set_ring_num, nbl_disp_set_ring_num,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(enable_port, nbl_disp_enable_port,					\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(dummy_func, NULL,							\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ADMINQ_PORT_NOTIFY,		\
			 NULL,									\
			 nbl_disp_chan_recv_port_notify_resp);					\
	NBL_DISP_SET_OPS(get_port_state, nbl_disp_get_port_state,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_PORT_STATE,			\
			 nbl_disp_chan_get_port_state_req,					\
			 nbl_disp_chan_get_port_state_resp);					\
	NBL_DISP_SET_OPS(set_port_advertising, nbl_disp_set_port_advertising,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_PORT_ADVERTISING,		\
			 nbl_disp_chan_set_port_advertising_req,				\
			 nbl_disp_chan_set_port_advertising_resp);				\
	NBL_DISP_SET_OPS(get_module_info, nbl_disp_get_module_info,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_MODULE_INFO,			\
			 nbl_disp_chan_get_module_info_req,					\
			 nbl_disp_chan_get_module_info_resp);					\
	NBL_DISP_SET_OPS(get_module_eeprom, nbl_disp_get_module_eeprom,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_MODULE_EEPROM,			\
			 nbl_disp_chan_get_module_eeprom_req,					\
			 nbl_disp_chan_get_module_eeprom_resp);					\
	NBL_DISP_SET_OPS(get_link_state, nbl_disp_get_link_state,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_LINK_STATE,			\
			 nbl_disp_chan_get_link_state_req,					\
			 nbl_disp_chan_get_link_state_resp);					\
	NBL_DISP_SET_OPS(set_eth_mac_addr, nbl_disp_set_eth_mac_addr,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_ETH_MAC_ADDR,			\
			 nbl_disp_chan_set_eth_mac_addr_req,					\
			 nbl_disp_chan_set_eth_mac_addr_resp);					\
	NBL_DISP_SET_OPS(get_chip_temperature, nbl_disp_get_chip_temperature,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_CHIP_TEMPERATURE,		\
			 nbl_disp_chan_get_chip_temperature_req,				\
			 nbl_disp_chan_get_chip_temperature_resp);				\
	NBL_DISP_SET_OPS(get_chip_temperature_max, nbl_disp_get_chip_temperature_max,		\
			 NBL_DISP_CTRL_LVL_ALWAYS, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_chip_temperature_crit, nbl_disp_get_chip_temperature_crit,		\
			 NBL_DISP_CTRL_LVL_ALWAYS, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_module_temperature, nbl_disp_get_module_temperature,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_MODULE_TEMPERATURE,		\
			 nbl_disp_chan_get_module_temperature_req,				\
			 nbl_disp_chan_get_module_temperature_resp);				\
	NBL_DISP_SET_OPS(process_abnormal_event, nbl_disp_process_abnormal_event,		\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(adapt_desc_gother, nbl_disp_adapt_desc_gother,				\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(flr_clear_net, nbl_disp_flr_clear_net,					\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(flr_clear_queues, nbl_disp_flr_clear_queues,				\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(flr_clear_flows, nbl_disp_flr_clear_flows,				\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(flr_clear_interrupt, nbl_disp_flr_clear_interrupt,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(unmask_all_interrupts, nbl_disp_unmask_all_interrupts,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(keep_alive, nbl_disp_keep_alive_req,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_KEEP_ALIVE,			\
			 nbl_disp_keep_alive_req,						\
			 nbl_disp_chan_keep_alive_resp);					\
	NBL_DISP_SET_OPS(ctrl_port_led, nbl_disp_ctrl_port_led,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CTRL_PORT_LED,			\
			 nbl_disp_chan_ctrl_port_led_req, nbl_disp_chan_ctrl_port_led_resp);	\
	NBL_DISP_SET_OPS(nway_reset, nbl_disp_nway_reset,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_NWAY_RESET,			\
			 nbl_disp_chan_nway_reset_req, nbl_disp_chan_nway_reset_resp);		\
	NBL_DISP_SET_OPS(get_user_queue_info, nbl_disp_get_user_queue_info,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_USER_QUEUE_INFO,		\
			 nbl_disp_chan_get_user_queue_info_req,					\
			 nbl_disp_chan_get_user_queue_info_resp);				\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_GET_BOARD_INFO, NULL,					\
			 nbl_disp_chan_get_board_info_resp);					\
	NBL_DISP_SET_OPS(get_vf_base_vsi_id, nbl_disp_get_vf_base_vsi_id,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_VF_BASE_VSI_ID,		\
			 nbl_disp_chan_get_vf_base_vsi_id_req,					\
			 nbl_disp_chan_get_vf_base_vsi_id_resp);				\
	NBL_DISP_SET_OPS(set_bridge_mode, nbl_disp_set_bridge_mode,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_BRIDGE_MODE,			\
			 nbl_disp_chan_set_bridge_mode_req,					\
			 nbl_disp_chan_set_bridge_mode_resp);					\
	NBL_DISP_SET_OPS(get_vf_function_id, nbl_disp_get_vf_function_id,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_VF_FUNCTION_ID,		\
			 nbl_disp_chan_get_vf_function_id_req,					\
			 nbl_disp_chan_get_vf_function_id_resp);				\
} while (0)

/* Structure starts here, adding an op should not modify anything below */
static int nbl_disp_setup_msg(struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	int ret = 0;

	if (!chan_ops->check_queue_exist(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return 0;

	mutex_init(&disp_mgt->ops_mutex_lock);
	spin_lock_init(&disp_mgt->ops_spin_lock);
	disp_mgt->ops_lock_required = true;

#define NBL_DISP_SET_OPS(disp_op, res_func, ctrl_lvl, msg_type, msg_req, msg_resp)		\
do {												\
	typeof(msg_type) _msg_type = (msg_type);						\
	if (_msg_type >= 0)									\
		ret += chan_ops->register_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt),		\
					      _msg_type, msg_resp, disp_mgt);			\
} while (0)
	NBL_DISP_OPS_TBL;
#undef  NBL_DISP_SET_OPS

	return ret;
}

/* Ctrl lvl means that if a certain level is set, then all disp_ops that decleared this lvl
 * will go directly to res_ops, rather than send a channel msg, and vice versa.
 */
static int nbl_disp_setup_ctrl_lvl(struct nbl_dispatch_mgt *disp_mgt, u32 lvl)
{
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_DISP_MGT_TO_DISP_OPS(disp_mgt);

	set_bit(lvl, disp_mgt->ctrl_lvl);

#define NBL_DISP_SET_OPS(disp_op, res_func, ctrl, msg_type, msg_req, msg_resp)			\
do {												\
	disp_ops->NBL_NAME(disp_op) = test_bit(ctrl, disp_mgt->ctrl_lvl) ? res_func : msg_req; ;\
} while (0)
	NBL_DISP_OPS_TBL;
#undef  NBL_DISP_SET_OPS

	return 0;
}

static int nbl_disp_setup_disp_mgt(struct nbl_common_info *common,
				   struct nbl_dispatch_mgt **disp_mgt)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	*disp_mgt = devm_kzalloc(dev, sizeof(struct nbl_dispatch_mgt), GFP_KERNEL);
	if (!*disp_mgt)
		return -ENOMEM;

	NBL_DISP_MGT_TO_COMMON(*disp_mgt) = common;
	return 0;
}

static void nbl_disp_remove_disp_mgt(struct nbl_common_info *common,
				     struct nbl_dispatch_mgt **disp_mgt)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	devm_kfree(dev, *disp_mgt);
	*disp_mgt = NULL;
}

static void nbl_disp_remove_ops(struct device *dev, struct nbl_dispatch_ops_tbl **disp_ops_tbl)
{
	devm_kfree(dev, NBL_DISP_OPS_TBL_TO_OPS(*disp_ops_tbl));
	devm_kfree(dev, *disp_ops_tbl);
	*disp_ops_tbl = NULL;
}

static int nbl_disp_setup_ops(struct device *dev, struct nbl_dispatch_ops_tbl **disp_ops_tbl,
			      struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_dispatch_ops *disp_ops;

	*disp_ops_tbl = devm_kzalloc(dev, sizeof(struct nbl_dispatch_ops_tbl), GFP_KERNEL);
	if (!*disp_ops_tbl)
		return -ENOMEM;

	disp_ops = devm_kzalloc(dev, sizeof(struct nbl_dispatch_ops), GFP_KERNEL);
	if (!disp_ops)
		return -ENOMEM;

	NBL_DISP_OPS_TBL_TO_OPS(*disp_ops_tbl) = disp_ops;
	NBL_DISP_OPS_TBL_TO_PRIV(*disp_ops_tbl) = disp_mgt;

	return 0;
}

int nbl_disp_init(void *p, struct nbl_init_param *param)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_dispatch_mgt **disp_mgt =
		(struct nbl_dispatch_mgt **)&NBL_ADAPTER_TO_DISP_MGT(adapter);
	struct nbl_dispatch_ops_tbl **disp_ops_tbl = &NBL_ADAPTER_TO_DISP_OPS_TBL(adapter);
	struct nbl_resource_ops_tbl *res_ops_tbl = NBL_ADAPTER_TO_RES_OPS_TBL(adapter);
	struct nbl_channel_ops_tbl *chan_ops_tbl = NBL_ADAPTER_TO_CHAN_OPS_TBL(adapter);
	int ret = 0;

	ret = nbl_disp_setup_disp_mgt(common, disp_mgt);
	if (ret)
		goto setup_mgt_fail;

	ret = nbl_disp_setup_ops(dev, disp_ops_tbl, *disp_mgt);
	if (ret)
		goto setup_ops_fail;

	NBL_DISP_MGT_TO_RES_OPS_TBL(*disp_mgt) = res_ops_tbl;
	NBL_DISP_MGT_TO_CHAN_OPS_TBL(*disp_mgt) = chan_ops_tbl;
	NBL_DISP_MGT_TO_DISP_OPS_TBL(*disp_mgt) = *disp_ops_tbl;

	ret = nbl_disp_setup_msg(*disp_mgt);
	if (ret)
		goto setup_msg_fail;

	if (param->caps.has_ctrl || param->caps.has_factory_ctrl) {
		ret = nbl_disp_setup_ctrl_lvl(*disp_mgt, NBL_DISP_CTRL_LVL_MGT);
		if (ret)
			goto setup_msg_fail;
	}

	if (param->caps.has_net || param->caps.has_factory_ctrl) {
		ret = nbl_disp_setup_ctrl_lvl(*disp_mgt, NBL_DISP_CTRL_LVL_NET);
		if (ret)
			goto setup_msg_fail;
	}

	ret = nbl_disp_setup_ctrl_lvl(*disp_mgt, NBL_DISP_CTRL_LVL_ALWAYS);
	if (ret)
		goto setup_msg_fail;

	return 0;

setup_msg_fail:
	nbl_disp_remove_ops(dev, disp_ops_tbl);
setup_ops_fail:
	nbl_disp_remove_disp_mgt(common, disp_mgt);
setup_mgt_fail:
	return ret;
}

void nbl_disp_remove(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_dispatch_mgt **disp_mgt;
	struct nbl_dispatch_ops_tbl **disp_ops_tbl;

	if (!adapter)
		return;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	disp_mgt = (struct nbl_dispatch_mgt **)&NBL_ADAPTER_TO_DISP_MGT(adapter);
	disp_ops_tbl = &NBL_ADAPTER_TO_DISP_OPS_TBL(adapter);

	nbl_disp_remove_ops(dev, disp_ops_tbl);

	nbl_disp_remove_disp_mgt(common, disp_mgt);
}
