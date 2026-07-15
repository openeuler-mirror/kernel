// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_aux_driver.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/idr.h>

#include "sxe2.h"
#include "sxe2_common.h"
#include "sxe2_aux_driver.h"
#include "sxe2_log.h"
#include "sxe2_mbx_msg.h"
#include "sxe2_netdev.h"
#include "sxe2_lag.h"
#include "sxe2_tc.h"
#include "sxe2_version.h"

#define MAX_RDMA_MSG_SIZE (4096)
#define PRIMARY_PF_INDEX 0
#define REDUNDANT_PF_INDEX 1
static DEFINE_IDA(sxe2_aux_ida);

u8 sxe2_rdma_aux_get_qset_tc(struct sxe2_adapter *adapter,
			     struct aux_rdma_qset_params *qset)
{
	if (sxe2_lag_is_bonded(adapter))
		return qset->tc[adapter->pf_idx];

	return qset->tc[PRIMARY_PF_INDEX];
}

static bool sxe2_rdma_aux_is_in_vf(struct sxe2_adapter *adapter,
				   struct aux_rdma_qset_params *qset)
{
	bool is_vf = false;

	is_vf = (qset->vport_id == adapter->vsi_ctxt.main_vsi->idx_in_dev) ? false
									   : true;

	return is_vf;
}

static int sxe2_alloc_res(struct aux_core_dev_info *cdev_info,
			  struct aux_rdma_qset_params *qset)
{
	int ret;
	u8 tc;
	struct sxe2_lag_context *lag;
	struct sxe2_adapter *adapter = NULL;
	struct sxe2_vsi *vsi = NULL;
	bool is_primary = false;
	bool is_vf = false;

	if (!cdev_info || !qset)
		return -EINVAL;

	adapter = cdev_info->adapter;
	if (!sxe2_txsched_support_chk(adapter))
		return 0;

	if (qset->vport_id == adapter->vsi_ctxt.main_vsi->idx_in_dev) {
		ret = sxe2_txsched_rdma_vsi_cfg(adapter->vsi_ctxt.main_vsi, 0);
		if (ret) {
			LOG_ERROR("rdma vsi cfg failed, ret=%d\n", ret);
			return ret;
		}
		vsi = adapter->vsi_ctxt.main_vsi;
	} else {
		vsi = sxe2_vsi_get_by_idx(adapter, qset->vport_id);
		if (!vsi) {
			LOG_ERROR("rdma vsi cfg failed, find vf vsi by vsi_id %d  failed.\n",
				  qset->vport_id);
			return -EINVAL;
		}
	}

	tc = qset->tc[PRIMARY_PF_INDEX];
	ret = sxe2_txsched_qset_node_add(adapter, vsi, qset, tc);
	if (ret) {
		LOG_ERROR("rdma qset node add failed, ret=%d\n", ret);
		goto l_end;
	}

	lag = adapter->lag_ctxt;
	is_primary = (adapter->pf_idx == PRIMARY_PF_INDEX) ? true : false;
	is_vf = sxe2_rdma_aux_is_in_vf(adapter, qset);
	if (sxe2_lag_support(adapter) && lag && is_primary && !is_vf) {
		mutex_lock(&lag->lock);
		qset->qset_port = SXE2_RDMA_PF0;
		lag->rdma_qset[qset->user_pri] = *qset;
		if (sxe2_lag_is_bonded(adapter)) {
			sxe2_lag_alloced_node_move(cdev_info, qset->user_pri, false);
			qset->teid = lag->rdma_qset[qset->user_pri].teid;
			qset->qset_port = lag->rdma_qset[qset->user_pri].qset_port;
		}
		mutex_unlock(&lag->lock);
	}
	LOG_INFO("rdma add sched teid %#x.\n", qset->teid);
l_end:
	return ret;
}

static s32 sxe2_rdma_aux_free_qset(struct aux_core_dev_info *cdev_info,
				   struct aux_rdma_qset_params *dqset, u8 tc,
				   bool is_primary)
{
	s32 ret;
	struct sxe2_lag_context *lag;
	bool is_vf = false;

	is_vf = sxe2_rdma_aux_is_in_vf(cdev_info->adapter, dqset);

	lag = cdev_info->adapter->lag_ctxt;
	if (sxe2_lag_support(cdev_info->adapter) && lag && is_primary && !is_vf) {
		mutex_lock(&lag->lock);
		ret = sxe2_txsched_qset_node_del(cdev_info->adapter, dqset, tc);
		if (!ret)
			lag->rdma_qset[dqset->user_pri].teid = 0;
		mutex_unlock(&lag->lock);
	} else {
		ret = sxe2_txsched_qset_node_del(cdev_info->adapter, dqset, tc);
	}

	return ret;
}

static int sxe2_free_res(struct aux_core_dev_info *cdev_info,
			 struct aux_rdma_qset_params *qset)
{
	int ret;
	u8 tc;
	struct sxe2_adapter *adapter = NULL;
	struct sxe2_lag_context *lag = NULL;
	bool is_primary = false;
	bool is_vf = false;

	if (!cdev_info || !qset)
		return -EINVAL;

	if (!sxe2_txsched_support_chk(cdev_info->adapter))
		return 0;

	adapter = cdev_info->adapter;
	lag = cdev_info->adapter->lag_ctxt;
	is_primary = (adapter->pf_idx == PRIMARY_PF_INDEX) ? true : false;
	is_vf = sxe2_rdma_aux_is_in_vf(adapter, qset);

	LOG_INFO("rdma del sched teid %#x.\n", qset->teid);

	if (sxe2_lag_support(cdev_info->adapter) && lag && is_primary && !is_vf) {
		mutex_lock(&lag->lock);
		qset->teid = lag->rdma_qset[qset->user_pri].teid;
		if (sxe2_lag_is_bonded(cdev_info->adapter) &&
		    cdev_info->bond_mode == SXE2_LAG_MODE_ACTIVE_BACKUP) {
			sxe2_lag_ab_reclaim_node(lag, cdev_info, qset->user_pri);
			qset->teid = lag->rdma_qset[qset->user_pri].teid;
			qset->qset_port = lag->rdma_qset[qset->user_pri].qset_port;
		}
		mutex_unlock(&lag->lock);
	}

	tc = qset->tc[PRIMARY_PF_INDEX];
	ret = sxe2_rdma_aux_free_qset(cdev_info, qset, tc, is_primary);
	if (ret)
		LOG_ERROR("rdma qset node del failed, ret=%d\n", ret);

	if (qset->vport_id == adapter->vsi_ctxt.main_vsi->idx_in_dev &&
	    sxe2_txsched_qset_left(adapter, qset->vport_id) == false) {
		ret = sxe2_txsched_rdma_vsi_rm(cdev_info->adapter->vsi_ctxt.main_vsi);
		if (ret)
			LOG_ERROR("rdma vsi rm failed, ret=%d\n", ret);
	}
	return ret;
}

static int sxe2_request_reset(struct aux_core_dev_info *cdev_info,
			      enum aux_reset_type reset_type)
{
	struct sxe2_adapter *adapter;

	if (reset_type != AUX_PFR)
		return -EINVAL;

	adapter = pci_get_drvdata(cdev_info->pdev);
	if (!adapter)
		return -EINVAL;

	return sxe2_reset_async(adapter, SXE2_RESET_PFR);
}

STATIC void sxe2_rdma_aux_qsets_info_update(struct aux_rdma_multi_qset_params *qset,
					    struct sxe2_lag_context *lag)
{
	qset->teid[PRIMARY_PF_INDEX] =
			lag->rdma_qsets[qset->user_pri].teid[PRIMARY_PF_INDEX];
	qset->teid[REDUNDANT_PF_INDEX] =
			lag->rdma_qsets[qset->user_pri].teid[REDUNDANT_PF_INDEX];
	qset->qset_port[PRIMARY_PF_INDEX] =
			lag->rdma_qsets[qset->user_pri].qset_port[PRIMARY_PF_INDEX];
	qset->qset_port[REDUNDANT_PF_INDEX] =
			lag->rdma_qsets[qset->user_pri]
					.qset_port[REDUNDANT_PF_INDEX];
}

static int sxe2_alloc_rdma_multi_qsets(struct aux_core_dev_info *cdev_info,
				       struct aux_rdma_multi_qset_params *qset)
{
	int ret;
	int i;
	struct sxe2_lag_context *lag;
	struct aux_rdma_qset_params aqset;

	if (!cdev_info || !qset)
		return -EINVAL;

	if (!sxe2_txsched_support_chk(cdev_info->adapter))
		return 0;

	ret = sxe2_txsched_rdma_vsi_cfg(cdev_info->adapter->vsi_ctxt.main_vsi, 1);
	if (ret) {
		LOG_ERROR("rdma vsi cfg failed, ret=%d\n", ret);
		goto l_end;
	}

	for (i = 0; i < qset->num; i++) {
		aqset.teid = qset->teid[i];
		aqset.tc[PRIMARY_PF_INDEX] = qset->tc[PRIMARY_PF_INDEX];

		aqset.qset_id = qset->qset_id[i];
		aqset.user_pri = qset->user_pri;
		ret = sxe2_txsched_qset_node_add(cdev_info->adapter,
						 cdev_info->adapter->vsi_ctxt.main_vsi, &aqset,
						 qset->tc[PRIMARY_PF_INDEX]);
		if (ret) {
			LOG_ERROR("rdma qset node add qg %d failed, ret=%d\n", i,
				  ret);
			goto l_end;
		}
		qset->teid[i] = aqset.teid;
		LOG_INFO("rdma add sched i %d teid %#x.\n", i, qset->teid[i]);
	}

	for (i = 0; i < qset->num; i++)
		qset->qset_port[i] = SXE2_RDMA_PF0;

	lag = cdev_info->adapter->lag_ctxt;
	if (sxe2_lag_support(cdev_info->adapter) && lag) {
		mutex_lock(&lag->lock);
		lag->rdma_qsets[qset->user_pri] = *qset;
		if (sxe2_lag_is_bonded(cdev_info->adapter) &&
		    cdev_info->bond_mode == SXE2_LAG_MODE_ACTIVE_ACTIVE) {
			sxe2_lag_alloced_node_move(cdev_info, qset->user_pri, true);
			sxe2_rdma_aux_qsets_info_update(qset, lag);
		}
		mutex_unlock(&lag->lock);
	}

l_end:
	return ret;
}

static s32 sxe2_rdma_aux_bond_aa_free_qset(struct aux_core_dev_info *cdev_info,
					   struct aux_rdma_qset_params *dqset, u8 tc,
					   int i)
{
	s32 ret;
	struct sxe2_lag_context *lag;

	lag = cdev_info->adapter->lag_ctxt;
	if (sxe2_lag_support(cdev_info->adapter) && lag) {
		mutex_lock(&lag->lock);
		ret = sxe2_txsched_qset_node_del(cdev_info->adapter, dqset, tc);
		if (!ret)
			lag->rdma_qsets[dqset->user_pri].teid[i] = 0;

		mutex_unlock(&lag->lock);
	} else {
		ret = sxe2_txsched_qset_node_del(cdev_info->adapter, dqset, tc);
	}

	return ret;
}

static int sxe2_free_rdma_multi_qsets(struct aux_core_dev_info *cdev_info,
				      struct aux_rdma_multi_qset_params *qset)
{
	struct aux_rdma_qset_params dqset;
	struct sxe2_lag_context *lag;
	int i;
	int ret;

	if (!cdev_info || !qset)
		return -EINVAL;
	if (!sxe2_txsched_support_chk(cdev_info->adapter))
		return 0;

	lag = cdev_info->adapter->lag_ctxt;
	if (sxe2_lag_support(cdev_info->adapter) && lag) {
		mutex_lock(&lag->lock);
		sxe2_rdma_aux_qsets_info_update(qset, lag);
		if (sxe2_lag_is_bonded(cdev_info->adapter) &&
		    cdev_info->bond_mode == SXE2_LAG_MODE_ACTIVE_ACTIVE) {
			sxe2_lag_aa_reclaim_node(lag, cdev_info, qset->user_pri);
			sxe2_rdma_aux_qsets_info_update(qset, lag);
		}
		mutex_unlock(&lag->lock);
	}

	for (i = 0; i < qset->num; i++) {
		dqset.teid = qset->teid[i];
		dqset.user_pri = qset->user_pri;
		dqset.tc[PRIMARY_PF_INDEX] = qset->tc[PRIMARY_PF_INDEX];
		dqset.qset_id = qset->qset_id[i];
		ret = sxe2_rdma_aux_bond_aa_free_qset(cdev_info, &dqset,
						      qset->tc[PRIMARY_PF_INDEX], i);
		if (ret) {
			LOG_ERROR("rdma qset node del failed, ret=%d\n", ret);
			goto l_end;
		}
	}
l_end:
	return ret;
}

STATIC s32 sxe2_get_vf_info(struct aux_core_dev_info *cdev_info, u16 vf_id,
			    struct aux_vf_port_info *vf_port_info)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter;
	struct sxe2_vf_node *vf;
	struct sxe2_vsi *vsi;

	if (!cdev_info || !vf_port_info) {
		LOG_INFO("params err dev(%p) vf port(%p).\n", (void *)cdev_info,
			 (void *)vf_port_info);
		ret = -EINVAL;
		goto l_end;
	}

	adapter = pci_get_drvdata(cdev_info->pdev);
	if (!adapter) {
		LOG_INFO("invalid vf_id:%u adapter err.\n", vf_id);
		ret = -EINVAL;
		goto l_end;
	}

	if (sxe2_vf_id_check(adapter, vf_id)) {
		ret = -EINVAL;
		goto l_end;
	}

	mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_id));
	vf = sxe2_vf_node_get(adapter, vf_id);
	if (!vf) {
		ret = -EAGAIN;
		LOG_INFO_BDF("invalid vf_id:%u vf nullptr.\n", vf_id);
		goto l_unlock;
	}

	ret = sxe2_check_vf_ready_for_cfg(vf);
	if (ret) {
		LOG_ERROR_BDF("vf:%u pf flags:0x%lx vf states:0x%lx not ready.\n",
			      vf_id, *adapter->flags, *vf->states);
		goto l_unlock;
	}

	vsi = vf->vsi;
	if (!vsi) {
		LOG_INFO_BDF("invalid vf_id:%u vsi nullptr.\n", vf_id);
		ret = -EAGAIN;
		goto l_unlock;
	}

	vf_port_info->vf_id = vf->vf_idx;
	vf_port_info->vport_id = vsi->idx_in_dev;

	if (sxe2_port_vlan_is_exist(vf)) {
		vf_port_info->port_vlan_id = sxe2_vf_port_vid_get(vf);
		vf_port_info->port_vlan_tpid = sxe2_vf_port_tpid_get(vf);
	}

l_unlock:
	mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_id));

l_end:
	return ret;
}

static int sxe2_vc_send(struct aux_core_dev_info *cdev_info, u16 vf_id, u8 *msg,
			u16 len, u64 session_id)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter;

	if (!cdev_info || !msg || !len || len > MAX_RDMA_MSG_SIZE)
		return -EINVAL;

	adapter = pci_get_drvdata(cdev_info->pdev);

	ret = sxe2_aux_reply_rdma_msg_to_vf(adapter, vf_id, msg, len, session_id);
	return ret;
}

int sxe2_rdma_msg_send(struct sxe2_adapter *adapter, enum sxe2_drv_cmd_opcode opcode,
		       u8 *msg, u16 len, u8 *recv_msg, u16 recv_len)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, opcode, msg, len, recv_msg, recv_len);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to exec rdma op=%u ,ret=%d\n", opcode, ret);
		ret = -EIO;
	}
	return ret;
}

static s32 sxe2_rdma_mac_rule_cmd(struct sxe2_adapter *adapter, u8 *mac, bool is_add)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;

	if (!is_multicast_ether_addr(mac))
		return -EADDRNOTAVAIL;

	mutex_lock(&adapter->vsi_ctxt.lock);

	if (is_add)
		ret = sxe2_mac_addr_add(vsi, mac, SXE2_MAC_OWNER_ROCE);
	else
		ret = sxe2_mac_addr_del(vsi, mac, SXE2_MAC_OWNER_ROCE);

	if (ret) {
		LOG_ERROR_BDF("roce %s mac addr %pM failed, ret %d\n",
			      is_add ? "add" : "del", mac, ret);
	}

	mutex_unlock(&adapter->vsi_ctxt.lock);

	return ret;
}

static s32 sxe2_rdma_send_cmd(struct aux_core_dev_info *cdev_info,
			      enum sxe2_drv_cmd_opcode op, u8 *msg, u16 len,
			      u8 *recv_msg, u16 recv_len)
{
	s32 ret = -EINVAL;
	struct sxe2_adapter *adapter;

	if (!cdev_info || !msg || !len || len > MAX_RDMA_MSG_SIZE)
		return -EINVAL;

	adapter = pci_get_drvdata(cdev_info->pdev);
	ret = sxe2_rdma_msg_send(adapter, op, msg, len, recv_msg, recv_len);

	return ret;
}

static s32 sxe2_rdma_drv_config(struct aux_core_dev_info *cdev_info, u8 op, u8 *msg)
{
	s32 ret = -EINVAL;
	struct sxe2_adapter *adapter;
	enum aux_rdma_opcode opcode = op;

	if (!cdev_info || !msg)
		return -EINVAL;

	adapter = pci_get_drvdata(cdev_info->pdev);
	switch (opcode) {
	case RDMA_MAC_RULE_ADD:
		ret = sxe2_rdma_mac_rule_cmd(adapter, msg, true);
		break;
	case RDMA_MAC_RULE_DELETE:
		ret = sxe2_rdma_mac_rule_cmd(adapter, msg, false);
		break;
	default:
		break;
	}
	return ret;
}

static void sxe2_rdma_loaded(struct aux_core_dev_info *cdev_info, bool loaded)
{
	struct sxe2_adapter *adapter;

	adapter = pci_get_drvdata(cdev_info->pdev);

	if (loaded)
		set_bit(SXE2_FLAG_RDMA_LOADED, adapter->flags);
	else
		clear_bit(SXE2_FLAG_RDMA_LOADED, adapter->flags);

	LOG_INFO_BDF("roce loaded %d.\n", loaded);
}

static int sxe2_rdma_dump_pcap_cmd(struct aux_core_dev_info *cdev_info, u8 *mac,
				   bool is_add)
{
	struct sxe2_adapter *adapter;

	adapter = pci_get_drvdata(cdev_info->pdev);

	return sxe2_rdma_dump_pcap_setup(adapter->vsi_ctxt.main_vsi, mac, is_add);
}

static u32 sxe2_rdma_get_link_speed(struct aux_core_dev_info *cdev_info)
{
	struct sxe2_adapter *adapter;

	adapter = pci_get_drvdata(cdev_info->pdev);

	return sxe2_get_link_speed(adapter);
}

static struct sxe2_core_ops core_ops = {
		.alloc_res = sxe2_alloc_res,
		.free_res = sxe2_free_res,
		.request_reset = sxe2_request_reset,
		.get_vf_info = sxe2_get_vf_info,
		.vc_send = sxe2_vc_send,
		.rdma_send_cmd = sxe2_rdma_send_cmd,
		.alloc_multi_res = sxe2_alloc_rdma_multi_qsets,
		.free_multi_res = sxe2_free_rdma_multi_qsets,
		.dump_pcap_cmd = sxe2_rdma_dump_pcap_cmd,
		.rdma_drv_config = sxe2_rdma_drv_config,
		.notify_rdma_load = sxe2_rdma_loaded,
		.rdma_get_link_speed = sxe2_rdma_get_link_speed,
};

struct sxe2_auxiliary_drv *sxe2_rdma_aux_drv_get(struct aux_core_dev_info *cdev_info)
{
	struct auxiliary_device *adev = cdev_info->adev;

	if (!adev || !adev->dev.driver) {
		LOG_WARN("adev null.\n");
		return NULL;
	}
	return container_of(adev->dev.driver, struct sxe2_auxiliary_drv,
			    adrv.driver);
}

static int sxe2_rdma_aux_send_event(struct sxe2_adapter *adapter,
				    struct sxe2_rdma_event_info *event)
{
	struct sxe2_auxiliary_drv *iadrv;
	struct aux_core_dev_info *cdev_info;

	if (!adapter || !event)
		return -EINVAL;

	if (sxe2_is_safe_mode(adapter))
		return -EPERM;

	cdev_info = &adapter->aux_ctxt.cdev_info;

	mutex_lock(&adapter->aux_ctxt.adev_mutex);
	if (!cdev_info->adev) {
		mutex_unlock(&adapter->aux_ctxt.adev_mutex);
		LOG_WARN_BDF("adev null, event:0x%lx no need send.\n", *event->type);
		return 0;
	}

	device_lock(&cdev_info->adev->dev);
	iadrv = sxe2_rdma_aux_drv_get(cdev_info);
	if (iadrv && iadrv->aux_ops.event_handler)
		iadrv->aux_ops.event_handler(cdev_info, event);
	device_unlock(&cdev_info->adev->dev);
	mutex_unlock(&adapter->aux_ctxt.adev_mutex);

	return 0;
}

void sxe2_rdma_aux_adev_release(struct device *dev)
{
	struct sxe2_auxiliary_device *iadev;

	iadev = container_of(dev, struct sxe2_auxiliary_device, adev.dev);
	kfree(iadev);
}

STATIC s32 sxe2_rdma_aux_msix_get(struct sxe2_adapter *adapter)
{
	u16 irq_num = adapter->irq_ctxt.irq_layout.rdma;
	s32 index = sxe2_irq_offset_get(adapter, irq_num, SXE2_VSI_T_RDMA);

	if (index < 0) {
		LOG_DEV_ERR("failed to get rdma irqs. err:%d\n", index);
		return index;
	}

	adapter->irq_ctxt.rdma_base_idx = (u16)index;
	return 0;
}

STATIC void sxe2_rdma_aux_add_qos_set(struct sxe2_adapter *adapter)
{
	struct sxe2_adapter *redundant_adapter;
	struct sxe2_lag_context *lag = adapter->lag_ctxt;
	struct aux_core_dev_info *aux_info = &adapter->aux_ctxt.cdev_info;

	(void)memset(aux_info->qos_info, 0x0, sizeof(aux_info->qos_info));
	sxe2_setup_dcb_qos_info(adapter, &aux_info->qos_info[PRIMARY_PF_INDEX]);

	if (lag && sxe2_lag_is_bonded(adapter)) {
		redundant_adapter = sxe2_lag_role_find(lag, REDUNDANT_PF_INDEX);
		if (!redundant_adapter) {
			LOG_ERROR("qos info set, find redundant failed.\n");
			return;
		}
		sxe2_setup_dcb_qos_info(redundant_adapter,
					&aux_info->qos_info[REDUNDANT_PF_INDEX]);
	}
}

int sxe2_rdma_aux_add(struct sxe2_adapter *adapter)
{
	int ret = 0;
	struct auxiliary_device *adev;
	struct sxe2_auxiliary_device *sadev;
	struct aux_core_dev_info *cdev_info = &adapter->aux_ctxt.cdev_info;

	if (cdev_info->adev) {
		LOG_DEV_WARN("rdma adev exists, duplicate create.\n");
		goto out;
	}

	sadev = kzalloc(sizeof(*sadev), GFP_KERNEL);
	if (!sadev) {
		ret = -ENOMEM;
		goto out;
	}

	adev = &sadev->adev;

	mutex_lock(&adapter->aux_ctxt.adev_mutex);
	cdev_info->adev = adev;
	sadev->cdev_info = cdev_info;
	mutex_unlock(&adapter->aux_ctxt.adev_mutex);

	cdev_info->adapter = adapter;
	cdev_info->pdev = adapter->pdev;
	cdev_info->netdev = adapter->vsi_ctxt.main_vsi->netdev;
	cdev_info->pf_id = adapter->pf_idx;
	cdev_info->ops = &core_ops;
	cdev_info->ftype = AUX_FUNCTION_TYPE_PF;
	cdev_info->ver.major = AUX_MAJOR_VER;
	cdev_info->ver.minor = AUX_MINOR_VER;
	cdev_info->rdma_caps.gen = AUX_RDMA_GEN_1;
	cdev_info->vfid_base = adapter->vf_ctxt.vfid_base;
	cdev_info->hw_addr = sxe2_reg_addr_get(&adapter->hw, 0);
	cdev_info->cdev_info_id = SXE2_RDMA_INDEX;
	cdev_info->vport_id = adapter->vsi_ctxt.main_vsi->idx_in_dev;
	cdev_info->msix_count = adapter->irq_ctxt.irq_layout.rdma;
	cdev_info->rdma_pf_bitmap = SXE2_RDMA_INVALID_PF;
	(void)strscpy(cdev_info->drv_ver, SXE2_VERSION, SXE2_DRV_VER_STR_LEN);
	sxe2_rdma_aux_add_qos_set(adapter);

	cdev_info->msix_entries = &adapter->irq_ctxt.msix_entries
						   [adapter->irq_ctxt.rdma_base_idx];

	adev->id = (u32)adapter->aux_ctxt.aux_idx;
	adev->dev.release = sxe2_rdma_aux_adev_release;
	adev->dev.parent = &cdev_info->pdev->dev;
	adev->name = SXE2_RDMA_NAME;

	ret = auxiliary_device_init(adev);
	if (ret)
		goto err_out;

	ret = auxiliary_device_add(adev);
	if (ret) {
		auxiliary_device_uninit(adev);
		goto err_out;
	}

	goto out;

err_out:
	kfree(sadev);
	cdev_info->adev = NULL;
out:
	return ret;
}

void sxe2_rdma_aux_delete(struct aux_core_dev_info *cdev_info)
{
	struct sxe2_adapter *adapter;
	struct auxiliary_device *adev;

	if (cdev_info->pdev)
		adapter = pci_get_drvdata(cdev_info->pdev);
	else
		return;

	LOG_DEBUG_BDF("release aux device!adev is :0x%pK\n", cdev_info->adev);

	mutex_lock(&adapter->aux_ctxt.adev_mutex);
	if (!cdev_info->adev) {
		mutex_unlock(&adapter->aux_ctxt.adev_mutex);
		return;
	}
	adev = cdev_info->adev;
	cdev_info->adev = NULL;
	mutex_unlock(&adapter->aux_ctxt.adev_mutex);

	if (adev) {
		auxiliary_device_delete(adev);
		auxiliary_device_uninit(adev);
	}
}

int sxe2_rdma_aux_init(struct sxe2_adapter *adapter)
{
	int ret;

	ret = sxe2_rdma_aux_msix_get(adapter);
	if (ret < 0) {
		LOG_DEV_ERR("failed to initial aux driver,no irq to use.\n");
		goto l_end;
	}

	adapter->aux_ctxt.aux_idx = ida_alloc(&sxe2_aux_ida, GFP_KERNEL);
	if (adapter->aux_ctxt.aux_idx < 0) {
		LOG_DEV_ERR("failed to allocate device ID for aux drvs\n");
		ret = -ENOMEM;
		goto l_end;
	}

	adapter->aux_ctxt.init = true;

l_end:
	return ret;
}

void sxe2_rdma_aux_deinit(struct sxe2_adapter *adapter)
{
	struct aux_core_dev_info *cdev_info = &adapter->aux_ctxt.cdev_info;

	if (adapter->aux_ctxt.init) {
		if (cdev_info->adev)
			sxe2_rdma_aux_delete(cdev_info);

		ida_simple_remove(&sxe2_aux_ida, adapter->aux_ctxt.aux_idx);

		adapter->aux_ctxt.init = false;
	}
}

s32 sxe2_rdma_aux_rebuild(struct sxe2_adapter *adapter)
{
	LOG_DEBUG_BDF("aux driver rebuild:index=%d\n", adapter->aux_ctxt.aux_idx);

	if (sxe2_lag_support(adapter)) {
		mutex_lock(&adapter->lag_ctxt->lock);
		if (sxe2_lag_is_bonded(adapter)) {
			mutex_unlock(&adapter->lag_ctxt->lock);
			LOG_WARN_BDF("running in bond mode, rdma does not need\t"
				     "rebuild.\n");
			goto end;
		}
		mutex_unlock(&adapter->lag_ctxt->lock);
	}

	if (!sxe2_is_safe_mode(adapter))
		return sxe2_rdma_aux_add(adapter);
	LOG_WARN_BDF("running in safe mode, rdma does not need rebuild.\n");

end:
	return 0;
}

void sxe2_rdma_aux_send_reset_event(struct sxe2_adapter *adapter)
{
	struct sxe2_rdma_event_info event;

	(void)memset(&event, 0, sizeof(event));
	set_bit(SXE2_EVENT_NOTIFY_RESET, event.type);
	(void)sxe2_rdma_aux_send_event(adapter, &event);
}

int sxe2_rdma_aux_send_mtu_changed_event(struct sxe2_adapter *adapter)
{
	struct sxe2_rdma_event_info event;

	(void)memset(&event, 0x0, sizeof(event));
	set_bit(SXE2_EVENT_MTU_CHANGED, event.type);
	return sxe2_rdma_aux_send_event(adapter, &event);
}

int sxe2_rdma_aux_send_vf_reset_event(struct sxe2_adapter *adapter, u16 vf_id)
{
	struct sxe2_rdma_event_info event;

	(void)memset(&event, 0x0, sizeof(event));
	event.vf_id = vf_id;
	set_bit(SXE2_EVENT_VF_RESET, event.type);
	return sxe2_rdma_aux_send_event(adapter, &event);
}

int sxe2_rdma_aux_send_aeq_overflow_event(struct sxe2_adapter *adapter)
{
	struct sxe2_rdma_event_info event;
	int ret = 0;

	(void)memset(&event, 0x0, sizeof(event));
	set_bit(SXE2_EVENT_AEQ_OVERFLOW, event.type);
	ret = sxe2_rdma_aux_send_event(adapter, &event);
	LOG_DEBUG_BDF("aux send--aeq overflow err:ret %d\n", ret);
	return ret;
}

void sxe2_aux_aeq_overflow_handler(struct sxe2_adapter *adapter)
{
	if (test_and_clear_bit(SXE2_FLAG_RDMA_AEQ_OVERFLOW, adapter->flags))
		(void)sxe2_rdma_aux_send_aeq_overflow_event(adapter);
}

int sxe2_rdma_aux_send_failover_event(struct sxe2_adapter *adapter)
{
	struct sxe2_rdma_event_info event;

	(void)memset(&event, 0x0, sizeof(event));
	set_bit(SXE2_EVENT_FAILOVER, event.type);
	LOG_INFO_BDF("lag send failover event.\n");
	return sxe2_rdma_aux_send_event(adapter, &event);
}

STATIC struct sxe2_adapter *sxe2_rdma_aux_qos_set(struct sxe2_adapter *adapter)
{
	struct aux_core_dev_info *aux_info = &adapter->aux_ctxt.cdev_info;

	(void)memset(aux_info->qos_info, 0x0, sizeof(aux_info->qos_info));

	sxe2_setup_dcb_qos_info(adapter, &aux_info->qos_info[PRIMARY_PF_INDEX]);

	return adapter;
}

STATIC struct sxe2_adapter *sxe2_rdma_aux_bond_qos_set(struct sxe2_adapter *adapter,
						       struct sxe2_lag_context *lag)
{
	struct sxe2_adapter *primary_adapter;
	struct aux_core_dev_info *send_aux_info;
	struct sxe2_adapter *send_adapter = NULL;

	primary_adapter = sxe2_lag_role_find(lag, PRIMARY_PF_INDEX);
	if (!primary_adapter) {
		LOG_ERROR("qos info set, find primary failed.\n");
		goto l_end;
	}

	send_adapter = primary_adapter;
	send_aux_info = &primary_adapter->aux_ctxt.cdev_info;

	if (primary_adapter->pf_idx == adapter->pf_idx) {
		sxe2_setup_dcb_qos_info(send_adapter,
					&send_aux_info->qos_info[PRIMARY_PF_INDEX]);
	} else {
		sxe2_setup_dcb_qos_info(adapter,
					&send_aux_info->qos_info[REDUNDANT_PF_INDEX]);
	}

l_end:
	return send_adapter;
}

STATIC struct sxe2_adapter *
sxe2_rdma_aux_support_lag_qos_set(struct sxe2_adapter *adapter)
{
	struct sxe2_lag_context *lag = adapter->lag_ctxt;
	struct sxe2_adapter *send_adapter = adapter;
	struct aux_core_dev_info *aux_info = &adapter->aux_ctxt.cdev_info;

	if (lag && sxe2_lag_is_bonded(adapter)) {
		send_adapter = sxe2_rdma_aux_bond_qos_set(adapter, lag);
	} else {
		(void)memset(aux_info->qos_info, 0x0, sizeof(aux_info->qos_info));
		sxe2_setup_dcb_qos_info(send_adapter,
					&aux_info->qos_info[PRIMARY_PF_INDEX]);
	}

	return send_adapter;
}

STATIC struct sxe2_adapter *
sxe2_rdma_aux_change_qos_update(struct sxe2_adapter *adapter)
{
	struct sxe2_adapter *send_adapter = NULL;

	if (sxe2_lag_support(adapter) && adapter->lag_ctxt) {
		mutex_lock(&adapter->lag_ctxt->lock);
		send_adapter = sxe2_rdma_aux_support_lag_qos_set(adapter);
		mutex_unlock(&adapter->lag_ctxt->lock);
	} else {
		send_adapter = sxe2_rdma_aux_qos_set(adapter);
	}

	return send_adapter;
}

int sxe2_rdma_aux_send_tc_change_event(struct sxe2_adapter *adapter)
{
	int ret = -1;
	struct sxe2_rdma_event_info event;
	struct sxe2_adapter *send_adapter = NULL;

	(void)memset(&event, 0x0, sizeof(event));

	send_adapter = sxe2_rdma_aux_change_qos_update(adapter);
	if (!send_adapter) {
		LOG_ERROR("rdma aux send tc change event failed, pf id = %d\n",
			  adapter->pf_idx);
		return ret;
	}

	set_bit(SXE2_EVENT_TC_CHANGE, event.type);
	return sxe2_rdma_aux_send_event(send_adapter, &event);
}
