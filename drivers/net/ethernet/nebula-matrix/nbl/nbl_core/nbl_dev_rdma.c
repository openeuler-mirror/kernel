// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_dev.h"
#include "nbl_dev_lag.h"

static DEFINE_IDA(nbl_adev_ida);
static DEFINE_IDA(nbl_grc_adev_ida);
static DEFINE_MUTEX(nbl_adev_lock);

static int nbl_dev_rdma_bond_active_num(struct nbl_core_export *core_info)
{
	int i, count = 0;

	if (!core_info->is_lag)
		return 0;

	for (i = 0; i < NBL_RDMA_LAG_MBRS_MAX; i++)
		if (core_info->lag_info.mbr[i].active)
			count++;

	return count;
}

static void nbl_dev_rdma_cfg_bond(struct nbl_dev_mgt *dev_mgt, struct nbl_core_export *core_info,
				  bool enable)
{
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_ch_prm_cfg_bond_shaping shaping_prm = {0};
	struct nbl_ch_prm_cfg_bgid_back_pressure bgid_prm = {0};
	int other_eth_id = -1, i;

	/* TODO: if we need to support bond with more than two ports, need to modify here */
	for (i = 0; i < 2; i++)
		if (core_info->lag_info.mbr[i].eth_id != NBL_COMMON_TO_ETH_ID(common))
			other_eth_id = core_info->lag_info.mbr[i].eth_id;

	if (other_eth_id == -1) {
		nbl_warn(common, NBL_DEBUG_MAIN, "Fail to find bond other eth id, rdma cfg abort");
		return;
	}

	shaping_prm.eth_id = NBL_COMMON_TO_ETH_ID(common);
	shaping_prm.enable = enable;
	serv_ops->cfg_bond_shaping(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &shaping_prm);
	bgid_prm.main_eth_id = NBL_COMMON_TO_ETH_ID(common);
	bgid_prm.other_eth_id = other_eth_id;
	bgid_prm.enable = enable;
	serv_ops->cfg_bgid_back_pressure(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &bgid_prm);

	rdma_dev->bond_shaping_configed = enable;
}

static void nbl_dev_chan_grc_process_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv;
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_chan_rdma_req *req;
	struct nbl_chan_rdma_resp result;
	struct nbl_chan_rdma_prm chan_rpm;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	struct nbl_adev *nadev = NULL;
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);

	if (rdma_dev && rdma_dev->grc_adev) {
		nadev = container_of(rdma_dev->grc_adev, struct nbl_adev,
				     adev);
	} else {
		dev_err(dev, "rdma not grc adev can't process channel msg\n");
		return;
	}

	if (!nadev)
		return;

	memset(&result, 0, sizeof(result));
	req = (struct nbl_chan_rdma_req *)data;
	chan_rpm.req = req;
	chan_rpm.resp = &result;
	blocking_notifier_call_chain(&nadev->core_info->grc_ch_rcv_nh,
				     NBL_CORE_EVT_GRC_CHAN_RCV, &chan_rpm);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GRC_PROCESS,
		     msg_id, err, &result, sizeof(result));
	chan_ops->send_ack(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_ack);
}

int nbl_core_send_chan_msg_to_grc(struct pci_dev *pdev, u8 *req_args,
				  u8 req_len, void *resp, u16 resp_len)
{
	struct nbl_adapter *adapter;
	struct nbl_dev_mgt *dev_mgt;
	struct nbl_common_info *common;
	struct nbl_channel_ops *chan_ops;
	int ret;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_rdma_req param;
	struct nbl_chan_rdma_resp result;

	if (!pdev || !req_args || !resp || req_len > RDMA_MSG_MAX_SIZE ||
	    resp_len > RDMA_MSG_MAX_SIZE)
		return -EINVAL;

	adapter = pci_get_drvdata(pdev);
	dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	memset(&param, 0, sizeof(param));
	memset(&result, 0, sizeof(result));
	memcpy(param.req_data, req_args, req_len);
	param.data_len = req_len;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GRC_PROCESS, &param, sizeof(param),
		      &result, sizeof(result), 1);
	ret = chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
	if (ret)
		return ret;

	resp_len = min(resp_len, result.data_len);
	memcpy(resp, result.resp_data, resp_len);

	return 0;
}
EXPORT_SYMBOL(nbl_core_send_chan_msg_to_grc);

static void nbl_dev_rdma_handle_abnormal_event_task(struct work_struct *work)
{
	struct nbl_dev_rdma *rdma_dev = container_of(work, struct nbl_dev_rdma,
						     abnormal_event_task);
	struct nbl_adev *nadev = NULL;

	if (rdma_dev && rdma_dev->grc_adev)
		nadev = container_of(rdma_dev->grc_adev, struct nbl_adev, adev);
	else
		return;

	if (!nadev)
		return;

	blocking_notifier_call_chain(&nadev->core_info->grc_abn_nh,
				     NBL_CORE_EVT_ABN, NULL);
}

void nbl_dev_rdma_process_abnormal_event(struct nbl_dev_rdma *rdma_dev)
{
	if (rdma_dev && rdma_dev->has_abnormal_event_task)
		nbl_common_queue_work_rdma(&rdma_dev->abnormal_event_task, false);
}

int nbl_core_rcv_rdma_up_rdma_bypass(struct auxiliary_device *grc_adev,
				     u16 vsi_id, bool enable)
{
	struct nbl_adev *nadev;
	struct nbl_core_export *core_info;
	struct nbl_dev_mgt *dev_mgt;
	struct nbl_service_ops *serv_ops;
	int ret = 0;

	if (!grc_adev)
		return -1;

	nadev = container_of(grc_adev, struct nbl_adev, adev);
	core_info = nadev->core_info;
	dev_mgt = NBL_NETDEV_TO_DEV_MGT(core_info->netdev);
	serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	if (serv_ops->enable_up_rdma_bypass)
		ret = serv_ops->enable_up_rdma_bypass(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
						      vsi_id, enable);
	return ret;
}
EXPORT_SYMBOL(nbl_core_rcv_rdma_up_rdma_bypass);

int nbl_core_rcv_rdma_mirror_cfg(struct auxiliary_device *adev, u8 mirror_id)
{
	struct nbl_adev *nadev = container_of(adev, struct nbl_adev, adev);
	struct nbl_dev_mgt *dev_mgt;
	struct nbl_service_ops *serv_ops;
	void *serv_p;
	struct nbl_ch_prm_tx_mirror_to_rdma param = {.mt_id = mirror_id, .enable = true};

	dev_mgt = NBL_NETDEV_TO_DEV_MGT(nadev->core_info->netdev);
	serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	serv_p = NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt);

	if (serv_ops->configure_tx_mirror_to_rdma)
		return serv_ops->configure_tx_mirror_to_rdma(serv_p, &param);

	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nbl_core_rcv_rdma_mirror_cfg);

void nbl_dev_rdma_process_flr_event(struct nbl_dev_rdma *rdma_dev, u16 vsi_id)
{
	struct nbl_adev *nadev = NULL;

	if (!rdma_dev || !rdma_dev->grc_adev)
		return;

	nadev = container_of(rdma_dev->grc_adev, struct nbl_adev, adev);

	if (nadev)
		blocking_notifier_call_chain(&nadev->core_info->grc_flr_nh,
					     NBL_CORE_EVT_FLR, &vsi_id);
}

/* nbl_rdma notify nbl_core, rdma has probe */
int nbl_core_rcv_rdma_driver_probed(struct pci_dev *pdev, bool enable)
{
	struct nbl_adapter *adapter;
	struct nbl_dev_mgt *dev_mgt;
	struct nbl_dev_rdma *rdma_dev;
	struct nbl_adev *nadev;
	struct nbl_common_info *common;
	struct nbl_service_ops *serv_ops;
	bool status;

	if (!pdev)
		return -EINVAL;

	adapter = pci_get_drvdata(pdev);
	dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	common = NBL_DEV_MGT_TO_COMMON(dev_mgt);

	if (!rdma_dev || !rdma_dev->bond_adev)
		return -EINVAL;

	nadev = container_of(rdma_dev->bond_adev, struct nbl_adev, adev);
	rdma_dev->bond_registered = enable;
	status = !rdma_dev->bond_shp_dis &&
		 rdma_dev->bond_registered &&
		 (nbl_dev_rdma_bond_active_num(nadev->core_info) > 1);

	if (status && !rdma_dev->bond_shaping_configed)
		nbl_dev_rdma_cfg_bond(dev_mgt, nadev->core_info, true);
	else if (!status && rdma_dev->bond_shaping_configed)
		nbl_dev_rdma_cfg_bond(dev_mgt, nadev->core_info, false);

	return 0;
}
EXPORT_SYMBOL(nbl_core_rcv_rdma_driver_probed);

static void nbl_dev_rdma_form_lag_info(struct nbl_dev_mgt *dev_mgt,
				       struct nbl_core_lag_info *lag_info)
{
	struct nbl_lag_dev *ldev = NBL_DEV_MGT_TO_LAG_DEV(dev_mgt);
	struct nbl_dev_mgt *dev_tmp;
	struct nbl_common_info *common;
	struct nbl_lag_func *pf;
	int i, _tmp;
	int num = 0;

	lag_info->mbr_num = ldev->ports;
	nbl_ldev_for_each(i, 0, ldev) {
		pf = nbl_lag_pf(ldev, i);
		dev_tmp = pf->pdev;
		common = NBL_DEV_MGT_TO_COMMON(dev_tmp);
		lag_info->mbr[num].vsi_id = NBL_COMMON_TO_VSI_ID(common);
		lag_info->mbr[num].eth_id = NBL_COMMON_TO_ETH_ID(common);
		lag_info->mbr[num].active =
				nbl_lag_mbr_is_active(&ldev->new_tracker, i);
		num++;
	}
}

void nbl_dev_rdma_notify_bond_member(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	struct nbl_adev *nadev;
	bool status;

	if (!rdma_dev || !rdma_dev->bond_adev)
		return;

	nadev = container_of(rdma_dev->bond_adev, struct nbl_adev, adev);
	nbl_dev_rdma_form_lag_info(dev_mgt, &nadev->core_info->lag_info);

	blocking_notifier_call_chain(&nadev->core_info->lag_mbr_nh,
				     NBL_CORE_EVT_LAG_MBR, NULL);

	status = !rdma_dev->bond_shp_dis &&
		 rdma_dev->bond_registered &&
		 (nbl_dev_rdma_bond_active_num(nadev->core_info) > 1);

	if (status && !rdma_dev->bond_shaping_configed)
		nbl_dev_rdma_cfg_bond(dev_mgt, nadev->core_info, true);
	else if (!status && rdma_dev->bond_shaping_configed)
		nbl_dev_rdma_cfg_bond(dev_mgt, nadev->core_info, false);
}

static int __nbl_dev_rdma_bond_shaping_async_func(struct nbl_dev_rdma *rdma_dev,
						  bool bond_shp_dis)
{
	struct nbl_adev *nadev;
	struct nbl_dev_mgt *dev_mgt = rdma_dev->dev_mgt;
	bool status;

	if (!rdma_dev->bond_adev)
		goto out;

	nadev = container_of(rdma_dev->bond_adev, struct nbl_adev, adev);
	status = !bond_shp_dis &&
		 rdma_dev->bond_registered &&
		 (nbl_dev_rdma_bond_active_num(nadev->core_info) > 1);

	if (status && !rdma_dev->bond_shaping_configed)
		nbl_dev_rdma_cfg_bond(dev_mgt, nadev->core_info, true);
	else if (!status && rdma_dev->bond_shaping_configed)
		nbl_dev_rdma_cfg_bond(dev_mgt, nadev->core_info, false);

out:
	return 0;
}

static int nbl_dev_rdma_update_bond_shaping(struct nbl_dev_mgt *dev_mgt,
					    bool bond_shp_dis)
{
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);

	if (!rdma_dev)
		return 0;

	rdma_dev->bond_shp_dis = bond_shp_dis;
	rdma_dev->aync_evt_data[NBL_RDMA_BOND_CFG].bond_shp_dis =
							bond_shp_dis;
	spin_lock(&rdma_dev->async_evt_lock);
	rdma_dev->aync_evt_change[NBL_RDMA_BOND_CFG] = true;
	spin_unlock(&rdma_dev->async_evt_lock);

	nbl_common_queue_work_rdma(&rdma_dev->asyn_evt_task, false);
	return 0;
}

static int nbl_dev_rdma_handle_bond_event(u16 type, void *event_data, void *callback_data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)callback_data;
	struct nbl_event_param *event_prm = (struct nbl_event_param *)event_data;

	switch (event_prm->subevent) {
	case NBL_SUBEVENT_BOND_SHAPING:
		nbl_dev_rdma_update_bond_shaping(dev_mgt, event_prm->bond_shaping_dis);
		break;
	default:
		break;
	}

	return 0;
}

static int
nbl_dev_rdma_handle_mirror_outputport_event(u16 type, void *event_data, void *callback_data)
{
	bool mirror_enable = *(bool *)event_data;
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)callback_data;
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);

	if (!rdma_dev)
		return 0;

	/**
	 * the adev add/del condition as follows:
	 * 1 nbl_dev_start_rdma_dev and nbl_dev_stop_rdma_dev
	 * 2 bond add/del
	 * not all pf has devcomm device, so nbl_lag_devcomm_lock only can
	 * protect bond/del conflict;
	 * all rdma_dev has rdma_dev->adev_lock;
	 * bond add/del only has nbl_lag_devcomm_lock;
	 *
	 * the ops call only vf, so only need rdma_dev->adev_lock
	 */
	mutex_lock(&rdma_dev->adev_lock);
	if (mirror_enable) {
		if (rdma_dev->adev)
			nbl_dev_destroy_rdma_aux_dev(rdma_dev, &rdma_dev->adev);
	} else if (!rdma_dev->adev && rdma_dev->has_rdma) {
		nbl_dev_create_rdma_aux_dev(dev_mgt, NBL_AUX_DEV_ROCE);
	}
	mutex_unlock(&rdma_dev->adev_lock);

	return 0;
}

static int
nbl_dev_rdma_handle_mirror_selectport_event(u16 type, void *event_data, void *callback_data)
{
	bool mirror_enable = *(bool *)event_data;
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)callback_data;
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	struct nbl_adev *nadev;
	struct auxiliary_device *adev;

	if (!rdma_dev)
		return 0;

	/**
	 * the adev add/del condition as follows:
	 * 1 nbl_dev_start_rdma_dev and nbl_dev_stop_rdma_dev
	 * 2 bond add/del
	 * not all pf has devcomm device, so nbl_lag_devcomm_lock only can
	 * protect bond/del conflict;
	 * all rdma_dev has rdma_dev->adev_lock;
	 * bond add/del only has nbl_lag_devcomm_lock;
	 *
	 * the ops call not only bond pf, so need nbl_lag_devcomm_lock
	 * and rdma_dev->adev_lock
	 */
	mutex_lock(&rdma_dev->adev_lock);
	nbl_lag_devcomm_lock(dev_mgt);
	adev = rdma_dev->adev ? rdma_dev->adev : rdma_dev->bond_adev;
	if (!adev)
		goto out;

	if (rdma_dev->mirror_enable == mirror_enable)
		goto out;

	rdma_dev->mirror_enable = mirror_enable;
	nadev = container_of(adev, struct nbl_adev, adev);
	nadev->core_info->mirror_enable = mirror_enable;
	blocking_notifier_call_chain(&nadev->core_info->mirror_cfg_nh,
				     NBL_CORE_EVT_MIRROR_CFG, &mirror_enable);
out:
	nbl_lag_devcomm_unlock(dev_mgt);
	mutex_unlock(&rdma_dev->adev_lock);
	return 0;
}

static int __nbl_dev_rdma_ovs_offload_async_func(struct nbl_dev_rdma *rdma_dev,
						 bool status)
{
	struct nbl_adev *nadev;

	if (!rdma_dev->bond_adev)
		goto out;

	nadev = container_of(rdma_dev->bond_adev, struct nbl_adev, adev);
	blocking_notifier_call_chain(&nadev->core_info->ovs_offld_nh,
				     NBL_CORE_EVT_OVS_OFFLD, &status);
out:
	return 0;
}

static int nbl_dev_rdma_handle_offload_status(u16 type, void *event_data, void *callback_data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)callback_data;
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	struct nbl_event_offload_status_data *data =
		(struct nbl_event_offload_status_data *)event_data;

	if (!rdma_dev)
		return 0;

	if (data->pf_vsi_id !=
	    NBL_COMMON_TO_VSI_ID(NBL_DEV_MGT_TO_COMMON(dev_mgt)))
		goto out;

	rdma_dev->aync_evt_data[NBL_RDMA_OVS_OFFLOAD].ovs_offld =
								data->status;
	spin_lock(&rdma_dev->async_evt_lock);
	rdma_dev->aync_evt_change[NBL_RDMA_OVS_OFFLOAD] = true;
	spin_unlock(&rdma_dev->async_evt_lock);

	nbl_common_queue_work_rdma(&rdma_dev->asyn_evt_task, false);

out:
	return 0;
}

static int nbl_dev_rdma_handle_reset_event(u16 type, void *event_data, void *callback_data)
{
	struct nbl_dev_rdma *rdma_dev = (struct nbl_dev_rdma *)callback_data;
	enum nbl_core_reset_event event = *(enum nbl_core_reset_event *)event_data;
	struct nbl_adev *nadev;
	struct auxiliary_device *adev;
	struct nbl_dev_mgt *dev_mgt = rdma_dev->dev_mgt;

	 /**
	  * the adev add/del condition as follows:
	  * 1 nbl_dev_start_rdma_dev and nbl_dev_stop_rdma_dev
	  * 2 bond add/del
	  * not all pf has devcomm device, so nbl_lag_devcomm_lock only can
	  * protect bond/del conflict;
	  * all rdma_dev has rdma_dev->adev_lock;
	  * bond add/del only has nbl_lag_devcomm_lock;
	  *
	  * the ops call not only bond pf, so need nbl_lag_devcomm_lock
	  * and rdma_dev->adev_lock
	  */
	mutex_lock(&rdma_dev->adev_lock);
	nbl_lag_devcomm_lock(dev_mgt);
	adev = rdma_dev->adev ? rdma_dev->adev : rdma_dev->bond_adev;
	if (!adev)
		goto out;

	nadev = container_of(adev, struct nbl_adev, adev);
	blocking_notifier_call_chain(&nadev->core_info->reset_nh,
				     NBL_CORE_EVT_RESET, &event);
	if (rdma_dev->has_grc && rdma_dev->grc_adev) {
		adev = rdma_dev->grc_adev;
		nadev = container_of(adev, struct nbl_adev, adev);
		blocking_notifier_call_chain(&nadev->core_info->reset_nh,
					     NBL_CORE_EVT_RESET, &event);
	}

out:
	nbl_lag_devcomm_unlock(dev_mgt);
	mutex_unlock(&rdma_dev->adev_lock);
	return 0;
}

static int __nbl_dev_rdma_mtu_change_async_func(struct nbl_dev_rdma *rdma_dev,
						int mtu)
{
	struct nbl_adev *nadev;

	if (rdma_dev && rdma_dev->adev)
		nadev = container_of(rdma_dev->adev, struct nbl_adev, adev);
	else if (rdma_dev && rdma_dev->bond_adev)
		nadev = container_of(rdma_dev->bond_adev,
				     struct nbl_adev, adev);
	else
		goto out;

	if (nadev)
		blocking_notifier_call_chain(&nadev->core_info->mtu_nh,
					     NBL_CORE_EVT_MTU_CHANGE, &mtu);

out:
	return 0;
}

static int nbl_dev_rdma_handle_change_mtu_event(u16 type, void *event_data, void *callback_data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)callback_data;
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	int new_mtu = *(int *)event_data;

	rdma_dev->aync_evt_data[NBL_RDMA_MTU_CFG].mtu = new_mtu;
	spin_lock(&rdma_dev->async_evt_lock);
	rdma_dev->aync_evt_change[NBL_RDMA_MTU_CFG] = true;
	spin_unlock(&rdma_dev->async_evt_lock);

	nbl_common_queue_work_rdma(&rdma_dev->asyn_evt_task, false);

	return 0;
}

size_t nbl_dev_rdma_qos_cfg_store(struct nbl_dev_mgt *dev_mgt, int offset,
				  const char *buf, size_t count)
{
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	struct nbl_adev *nadev;
	struct auxiliary_device *adev;
	struct nbl_qos_cfg qos_cfg;

	 /**
	  * the adev add/del condition as follows:
	  * 1 nbl_dev_start_rdma_dev and nbl_dev_stop_rdma_dev
	  * 2 bond add/del
	  * not all pf has devcomm device, so nbl_lag_devcomm_lock only can
	  * protect bond/del conflict;
	  * all rdma_dev has rdma_dev->adev_lock;
	  * bond add/del only has nbl_lag_devcomm_lock;
	  *
	  * the ops call not only bond pf, so need nbl_lag_devcomm_lock
	  * and rdma_dev->adev_lock
	  */
	mutex_lock(&rdma_dev->adev_lock);
	nbl_lag_devcomm_lock(dev_mgt);
	if (rdma_dev && rdma_dev->bond_adev) {
		adev = rdma_dev->bond_adev;
		nadev = container_of(rdma_dev->bond_adev, struct nbl_adev,
				     adev);
	} else if (rdma_dev && rdma_dev->adev) {
		adev = rdma_dev->adev;
		nadev = container_of(adev, struct nbl_adev, adev);
	} else {
		goto out;
	}

	qos_cfg.offset = offset;
	qos_cfg.buf = buf;
	qos_cfg.count = count;
	qos_cfg.return_size = -EINVAL;
	blocking_notifier_call_chain(&nadev->core_info->qos_cfg_nh,
				     NBL_CORE_EVT_QOS_CFG, &qos_cfg);
	nbl_lag_devcomm_unlock(dev_mgt);
	mutex_unlock(&rdma_dev->adev_lock);
	return qos_cfg.return_size;
out:
	nbl_lag_devcomm_unlock(dev_mgt);
	mutex_unlock(&rdma_dev->adev_lock);
	return -EINVAL;
}

size_t nbl_dev_rdma_qos_cfg_show(struct nbl_dev_mgt *dev_mgt, int offset, char *buf)
{
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	struct nbl_adev *nadev;
	struct auxiliary_device *adev;
	struct nbl_qos_show qos_show;

	/**
	 * the adev add/del condition as follows:
	 * 1 nbl_dev_start_rdma_dev and nbl_dev_stop_rdma_dev
	 * 2 bond add/del
	 * not all pf has devcomm device, so nbl_lag_devcomm_lock only can
	 * protect bond/del conflict;
	 * all rdma_dev has rdma_dev->adev_lock;
	 * bond add/del only has nbl_lag_devcomm_lock;
	 *
	 * the ops call not only bond pf, so need nbl_lag_devcomm_lock
	 * and rdma_dev->adev_lock
	 */
	mutex_lock(&rdma_dev->adev_lock);
	nbl_lag_devcomm_lock(dev_mgt);
	if (rdma_dev && rdma_dev->bond_adev) {
		adev = rdma_dev->bond_adev;
		nadev = container_of(rdma_dev->bond_adev, struct nbl_adev,
				     adev);
	} else if (rdma_dev && rdma_dev->adev) {
		adev = rdma_dev->adev;
		nadev = container_of(adev, struct nbl_adev, adev);
	} else {
		goto out;
	}

	qos_show.offset = offset;
	qos_show.buf = buf;
	qos_show.return_size = -EINVAL;
	blocking_notifier_call_chain(&nadev->core_info->qos_show_nh,
				     NBL_CORE_EVT_QOS_SHOW, &qos_show);
	nbl_lag_devcomm_unlock(dev_mgt);
	mutex_unlock(&rdma_dev->adev_lock);
	return qos_show.return_size;
out:
	nbl_lag_devcomm_unlock(dev_mgt);
	mutex_unlock(&rdma_dev->adev_lock);
	return -EINVAL;
}

static struct nbl_core_export *
nbl_dev_rdma_setup_core_info(struct nbl_dev_mgt *dev_mgt, u8 type)
{
	struct nbl_dev_common *common_dev = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(common_dev);
	void *serv_p = NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt);
	struct nbl_core_export *core_info = NULL;
	int irq_num, i;
	u16 base_vector_id = msix_info->serv_info[NBL_MSIX_RDMA_TYPE].base_vector_id;
	u16 vsi_tmp;

	core_info = kzalloc(sizeof(*core_info), GFP_KERNEL);
	if (!core_info)
		goto malloc_cinfo_fail;

	core_info->dma_dev = NBL_COMMON_TO_DMA_DEV(common);
	core_info->pdev = NBL_COMMON_TO_PDEV(common);
	core_info->hw_addr = serv_ops->get_hw_addr(serv_p, NULL);
	core_info->rdma_hw_addr = serv_ops->get_rdma_hw_addr(serv_p);
	vsi_tmp = NBL_COMMON_TO_VSI_ID(common);
	core_info->real_hw_addr = serv_ops->get_real_hw_addr(serv_p, vsi_tmp);
	core_info->function_id = serv_ops->get_function_id(serv_p, vsi_tmp);
	core_info->netdev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt)->netdev;
	core_info->vsi_id = NBL_COMMON_TO_VSI_ID(common);

	if (type == NBL_AUX_DEV_BOND) {
		nbl_dev_rdma_form_lag_info(dev_mgt, &core_info->lag_info);
		core_info->is_lag = true;
	}

	if (serv_ops->get_product_fix_cap(serv_p, NBL_UDF_EXTRACT_CAP) && !common->is_vf) {
		if (type == NBL_AUX_DEV_BOND) {
			for (i = 0; i < core_info->lag_info.mbr_num && i < 4; i++) {
				vsi_tmp = core_info->lag_info.mbr[i].vsi_id;
				core_info->rx_vlan_vsi_id[i] =
					RDMA_RX_VLAN_VSI_ID(vsi_tmp);
			}
		} else {
			core_info->rx_vlan_vsi_id[0] =
				RDMA_RX_VLAN_VSI_ID(core_info->vsi_id);
		}
	}

	core_info->eth_mode = NBL_COMMON_TO_ETH_MODE(common);
	core_info->eth_id = NBL_COMMON_TO_ETH_ID(common);
	core_info->rdma_mem_type = rdma_dev->mem_type;
	core_info->internal_cfg = rdma_dev->internal_cfg;

	if (type == NBL_AUX_DEV_GRC) {
		for (i = 0; i < NBL_RDMA_MAX_FLOW_ID_NUM; i++)
			core_info->ecn_fs_id[i] = NBL_RDMA_MAX_FLOW_ID_IN - i;

		serv_ops->get_rdma_cap_num(serv_p,
					   &core_info->rdma_cap_num,
					   &core_info->rdma_cap_my_num);
	}

	serv_ops->get_real_bdf(serv_p,
			       NBL_COMMON_TO_VSI_ID(common),
			       &core_info->real_bus, &core_info->real_dev,
			       &core_info->real_function);

	if (type == NBL_AUX_DEV_GRC)
		goto out;

	irq_num = msix_info->serv_info[NBL_MSIX_RDMA_TYPE].num;
	core_info->msix_entries = kcalloc(irq_num, sizeof(struct msix_entry),
					  GFP_KERNEL);
	if (!core_info->msix_entries)
		goto malloc_msix_fail;

	core_info->global_vector_id = kcalloc(irq_num, sizeof(u16), GFP_KERNEL);
	if (!core_info->global_vector_id)
		goto malloc_gbl_vec_fail;

	for (i = 0; i < irq_num; i++) {
		memcpy(&core_info->msix_entries[i],
		       &msix_info->msix_entries[i + base_vector_id],
		       sizeof(core_info->msix_entries[i]));
		core_info->global_vector_id[i] =
			serv_ops->get_global_vector(serv_p,
						    i + base_vector_id);
	}
	core_info->msix_count = irq_num;
out:
	return core_info;

malloc_gbl_vec_fail:
	kfree(core_info->msix_entries);
malloc_msix_fail:
	kfree(core_info);
malloc_cinfo_fail:
	return NULL;
}

static void nbl_dev_rdma_free_core_info(struct nbl_core_export *core_info)
{
	kfree(core_info->msix_entries);
	kfree(core_info->global_vector_id);
	kfree(core_info);
}

static void nbl_dev_rdma_handle_async_event_task(struct work_struct *work)
{
	struct nbl_dev_rdma *rdma_dev = container_of(work, struct nbl_dev_rdma,
						     asyn_evt_task);
	bool aync_evt[NBL_RDMA_ASYNC_EVT_MAX];
	bool bond_shp_dis;
	bool ovs_offld;
	int mtu;

	spin_lock(&rdma_dev->async_evt_lock);
	memcpy(aync_evt, rdma_dev->aync_evt_change, sizeof(aync_evt));
	memset(rdma_dev->aync_evt_change, 0, sizeof(aync_evt));
	spin_unlock(&rdma_dev->async_evt_lock);

	mutex_lock(&rdma_dev->adev_lock);
	nbl_lag_devcomm_lock(rdma_dev->dev_mgt);

	if (aync_evt[NBL_RDMA_BOND_CFG]) {
		bond_shp_dis =
			rdma_dev->aync_evt_data[NBL_RDMA_BOND_CFG].bond_shp_dis;
		__nbl_dev_rdma_bond_shaping_async_func(rdma_dev, bond_shp_dis);
	}

	if (aync_evt[NBL_RDMA_MTU_CFG]) {
		mtu = rdma_dev->aync_evt_data[NBL_RDMA_MTU_CFG].mtu;
		__nbl_dev_rdma_mtu_change_async_func(rdma_dev, mtu);
	}

	if (aync_evt[NBL_RDMA_OVS_OFFLOAD]) {
		ovs_offld =
			rdma_dev->aync_evt_data[NBL_RDMA_OVS_OFFLOAD].ovs_offld;
		__nbl_dev_rdma_ovs_offload_async_func(rdma_dev, ovs_offld);
	}

	nbl_lag_devcomm_unlock(rdma_dev->dev_mgt);
	mutex_unlock(&rdma_dev->adev_lock);
}

static void nbl_dev_adev_release(struct device *dev)
{
	struct nbl_adev *nadev;

	nadev = container_of(dev, struct nbl_adev, adev.dev);
	nbl_dev_rdma_free_core_info(nadev->core_info);
	kfree(nadev);
}

int nbl_dev_create_rdma_aux_dev(struct nbl_dev_mgt *dev_mgt, u8 type)
{
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);
	struct nbl_adev *nadev;
	struct auxiliary_device *adev, **temp_adev = NULL;
	bool is_grc = false;
	int ret = 0;

	if (!rdma_dev)
		return -ENODEV;

	nadev = kzalloc(sizeof(*nadev), GFP_KERNEL);
	if (!nadev)
		return -ENOMEM;

	nadev->adev_idx = type == NBL_AUX_DEV_GRC ? rdma_dev->grc_adev_index :
				rdma_dev->adev_index;
	nadev->adev_type = type;
	adev = &nadev->adev;
	adev->id = nadev->adev_idx;
	adev->dev.parent = dev;
	adev->dev.release = nbl_dev_adev_release;

	switch (type) {
	case NBL_AUX_DEV_GRC:
		rdma_dev->grc_adev = adev;
		adev->name = "nbl.roce_grc2";
		temp_adev = &rdma_dev->grc_adev;
		is_grc = true;
		break;
	case NBL_AUX_DEV_ROCE:
		rdma_dev->adev = adev;
		adev->name = "nbl.roce2";
		temp_adev = &rdma_dev->adev;
		break;
	case NBL_AUX_DEV_BOND:
		rdma_dev->bond_adev = adev;
		adev->name = "nbl.roce_bond2";
		temp_adev = &rdma_dev->bond_adev;
		break;
	default:
		goto unknown_type_err;
	}

	nadev->core_info = nbl_dev_rdma_setup_core_info(dev_mgt, type);
	if (!nadev->core_info) {
		ret = -ENOMEM;
		goto malloc_core_info_fail;
	}

	nadev->core_info->mirror_enable = rdma_dev->mirror_enable;
	BLOCKING_INIT_NOTIFIER_HEAD(&nadev->core_info->lag_mbr_nh);
	BLOCKING_INIT_NOTIFIER_HEAD(&nadev->core_info->ovs_offld_nh);
	BLOCKING_INIT_NOTIFIER_HEAD(&nadev->core_info->mtu_nh);
	BLOCKING_INIT_NOTIFIER_HEAD(&nadev->core_info->grc_ch_rcv_nh);
	BLOCKING_INIT_NOTIFIER_HEAD(&nadev->core_info->grc_abn_nh);
	BLOCKING_INIT_NOTIFIER_HEAD(&nadev->core_info->grc_flr_nh);
	BLOCKING_INIT_NOTIFIER_HEAD(&nadev->core_info->reset_nh);
	BLOCKING_INIT_NOTIFIER_HEAD(&nadev->core_info->qos_cfg_nh);
	BLOCKING_INIT_NOTIFIER_HEAD(&nadev->core_info->qos_show_nh);
	BLOCKING_INIT_NOTIFIER_HEAD(&nadev->core_info->mirror_cfg_nh);
	BLOCKING_INIT_NOTIFIER_HEAD(&nadev->core_info->ecpu_bond_nh);

	ret = auxiliary_device_init(adev);
	if (ret) {
		dev_err(dev, "auxiliary_device_init fail ret= %d", ret);
		goto aux_dev_init_err;
	}

	ret = __auxiliary_device_add(adev, "nbl");
	if (ret) {
		dev_err(dev, "__auxiliary_device_add fail ret= %d", ret);
		goto aux_dev_add_err;
	}

	dev_info(dev, "nbl plug type: %d, idx: %d auxiliary device OK",
		 type, rdma_dev->adev_index);
	return 0;

aux_dev_add_err:
	/* When uninit, it will call nbl_dev_adev_release, which will free dev_link.
	 * So just return.
	 */
	auxiliary_device_uninit(adev);
	if (temp_adev)
		*temp_adev = NULL;
	return ret;
aux_dev_init_err:
	nbl_dev_rdma_free_core_info(nadev->core_info);
malloc_core_info_fail:
unknown_type_err:
	if (temp_adev)
		*temp_adev = NULL;
	kfree(nadev);
	return ret;
}

void nbl_dev_destroy_rdma_aux_dev(struct nbl_dev_rdma *rdma_dev,
				  struct auxiliary_device **adev)
{
	if (!rdma_dev || !adev || !*adev)
		return;

	if (rdma_dev->has_abnormal_event_task)
		nbl_common_flush_task(&rdma_dev->abnormal_event_task);

	auxiliary_device_delete(*adev);
	auxiliary_device_uninit(*adev);

	*adev = NULL;
}

int nbl_dev_setup_rdma_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_rdma *rdma_dev;
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_dev_common *common_dev = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct nbl_msix_info *msix_info = NBL_DEV_COMMON_TO_MSIX_INFO(common_dev);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_rdma_register_param register_param = {0};
	struct nbl_event_callback event_callback = {0};
	int grc_id = 0;
	int ret;
	bool has_grc = false;

	if (param->caps.has_grc)
		has_grc = true;

	/* This must be performed after ctrl dev setup */
	if (param->caps.has_ctrl) {
		serv_ops->setup_rdma_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					&nbl_adev_ida, &nbl_grc_adev_ida, &nbl_adev_lock);
		if (has_grc) {
			ret = serv_ops->register_rdma_grc_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
							     NBL_COMMON_TO_VSI_ID(common), &grc_id);
			if (ret)
				return ret;
		}
	}

	ret = serv_ops->register_rdma(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
				      NBL_COMMON_TO_VSI_ID(common), &register_param);
	if (ret)
		goto register_rdma_fail;

	if (!register_param.has_rdma && !has_grc)
		return 0;

	rdma_dev = devm_kzalloc(NBL_ADAPTER_TO_DEV(adapter),
				sizeof(struct nbl_dev_rdma), GFP_KERNEL);
	if (!rdma_dev)
		return -ENOMEM;

	NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt) = rdma_dev;
	rdma_dev->dev_mgt = dev_mgt;
	mutex_init(&rdma_dev->adev_lock);
	rdma_dev->has_rdma = register_param.has_rdma;
	rdma_dev->has_grc = has_grc;
	rdma_dev->mem_type = register_param.mem_type;
	rdma_dev->adev_index = register_param.id;
	rdma_dev->grc_adev_index = grc_id;
	rdma_dev->internal_cfg = register_param.internal_cfg;
	msix_info->serv_info[NBL_MSIX_RDMA_TYPE].num += register_param.intr_num;

	if (chan_ops->check_queue_exist(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt),
					NBL_CHAN_TYPE_MAILBOX))
		chan_ops->register_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), NBL_CHAN_MSG_GRC_PROCESS,
				       nbl_dev_chan_grc_process_resp, dev_mgt);

	if (rdma_dev->has_grc) {
		ret = nbl_dev_create_rdma_aux_dev(dev_mgt, NBL_AUX_DEV_GRC);
		if (ret)
			goto create_grc_aux_err;

		nbl_common_alloc_task(&rdma_dev->abnormal_event_task,
				      nbl_dev_rdma_handle_abnormal_event_task);
		rdma_dev->has_abnormal_event_task = true;
	}

	nbl_common_alloc_task(&rdma_dev->asyn_evt_task,
			      nbl_dev_rdma_handle_async_event_task);
	spin_lock_init(&rdma_dev->async_evt_lock);

	if (!NBL_COMMON_TO_VF_CAP(common)) {
		event_callback.callback_data = dev_mgt;
		event_callback.callback = nbl_dev_rdma_handle_bond_event;
		nbl_event_register(NBL_EVENT_RDMA_BOND_UPDATE, &event_callback,
				   NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
		event_callback.callback_data = dev_mgt;
		event_callback.callback = nbl_dev_rdma_handle_mirror_selectport_event;
		nbl_event_register(NBL_EVENT_MIRROR_SELECTPORT, &event_callback,
				   NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
		event_callback.callback_data = dev_mgt;
		event_callback.callback = nbl_dev_rdma_handle_offload_status;
		nbl_event_register(NBL_EVENT_OFFLOAD_STATUS_CHANGED, &event_callback,
				   NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	} else {
		event_callback.callback_data = dev_mgt;
		event_callback.callback = nbl_dev_rdma_handle_mirror_outputport_event;
		nbl_event_register(NBL_EVENT_MIRROR_OUTPUTPORT_DEVLAYER, &event_callback,
				   NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	}

	event_callback.callback_data = rdma_dev;
	event_callback.callback = nbl_dev_rdma_handle_reset_event;
	nbl_event_register(NBL_EVENT_RESET_EVENT, &event_callback,
			   NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));

	event_callback.callback_data = dev_mgt;
	event_callback.callback = nbl_dev_rdma_handle_change_mtu_event;
	nbl_event_register(NBL_EVENT_CHANGE_MTU, &event_callback,
			   NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));

	return 0;

create_grc_aux_err:
	devm_kfree(NBL_ADAPTER_TO_DEV(adapter), rdma_dev);
	NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt) = NULL;
	serv_ops->unregister_rdma(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), NBL_COMMON_TO_VSI_ID(common));
	if (param->caps.has_ctrl)
		serv_ops->remove_rdma_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					 &nbl_adev_ida, &nbl_grc_adev_ida, &nbl_adev_lock);
	return ret;

register_rdma_fail:
	if (param->caps.has_ctrl)
		serv_ops->remove_rdma_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					 &nbl_adev_ida, &nbl_grc_adev_ida, &nbl_adev_lock);
	return ret;
}

void nbl_dev_remove_rdma_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_adev *nadev;
	struct nbl_event_callback event_callback = {0};
	enum nbl_hw_status hw_status;
	enum nbl_core_reset_event event = NBL_CORE_FATAL_ERR_EVENT;

	if (!rdma_dev)
		return;

	event_callback.callback_data = rdma_dev;
	event_callback.callback = nbl_dev_rdma_handle_reset_event;
	nbl_event_unregister(NBL_EVENT_RESET_EVENT, &event_callback,
			     NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));

	event_callback.callback_data = dev_mgt;
	event_callback.callback = nbl_dev_rdma_handle_change_mtu_event;
	nbl_event_unregister(NBL_EVENT_CHANGE_MTU, &event_callback,
			     NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));

	if (!NBL_COMMON_TO_VF_CAP(common)) {
		event_callback.callback_data = dev_mgt;
		event_callback.callback = nbl_dev_rdma_handle_bond_event;
		nbl_event_unregister(NBL_EVENT_RDMA_BOND_UPDATE, &event_callback,
				     NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
		event_callback.callback_data = dev_mgt;
		event_callback.callback = nbl_dev_rdma_handle_mirror_selectport_event;
		nbl_event_unregister(NBL_EVENT_MIRROR_SELECTPORT, &event_callback,
				     NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
		event_callback.callback_data = dev_mgt;
		event_callback.callback = nbl_dev_rdma_handle_offload_status;
		nbl_event_unregister(NBL_EVENT_OFFLOAD_STATUS_CHANGED, &event_callback,
				     NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	} else {
		event_callback.callback_data = dev_mgt;
		event_callback.callback = nbl_dev_rdma_handle_mirror_outputport_event;
		nbl_event_unregister(NBL_EVENT_MIRROR_OUTPUTPORT_DEVLAYER, &event_callback,
				     NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	}

	nbl_common_release_task(&rdma_dev->asyn_evt_task);

	if (rdma_dev->has_abnormal_event_task) {
		rdma_dev->has_abnormal_event_task = false;
		nbl_common_release_task(&rdma_dev->abnormal_event_task);
	}

	if (rdma_dev->grc_adev) {
		nadev = container_of(rdma_dev->grc_adev, struct nbl_adev, adev);
		hw_status = serv_ops->get_hw_status(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
		if (hw_status)
			blocking_notifier_call_chain(&nadev->core_info->reset_nh,
						     NBL_CORE_EVT_RESET, &event);
		nbl_dev_destroy_rdma_aux_dev(rdma_dev, &rdma_dev->grc_adev);
	}

	if (rdma_dev->has_rdma)
		serv_ops->unregister_rdma(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					  NBL_COMMON_TO_VSI_ID(common));

	if (NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt)) {
		if (rdma_dev->has_grc)
			serv_ops->unregister_rdma_grc_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
							 NBL_COMMON_TO_VSI_ID(common));
		serv_ops->remove_rdma_id(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
					 &nbl_adev_ida, &nbl_grc_adev_ida, &nbl_adev_lock);
	}

	devm_kfree(NBL_ADAPTER_TO_DEV(adapter), rdma_dev);
	NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt) = NULL;
}

int nbl_dev_start_rdma_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	int ret;

	if (!rdma_dev)
		return 0;

	if (rdma_dev->has_rdma) {
		/**
		 * the adev add/del condition as follows:
		 * 1 nbl_dev_start_rdma_dev and nbl_dev_stop_rdma_dev
		 * 2 bond add/del
		 * not all pf has devcomm device, so nbl_lag_devcomm_lock only can
		 * protect bond/del conflict;
		 * all rdma_dev has rdma_dev->adev_lock;
		 * bond add/del only has nbl_lag_devcomm_lock;
		 *
		 * the ops call not only bond pf, so need nbl_lag_devcomm_lock
		 * and rdma_dev->adev_lock
		 */
		mutex_lock(&rdma_dev->adev_lock);
		nbl_lag_devcomm_lock(dev_mgt);
		dev_mgt->adev_flag &= ~NBL_DISABLE_ADEV;
		if (!rdma_dev->adev) {
			ret = nbl_dev_create_rdma_aux_dev(dev_mgt, NBL_AUX_DEV_ROCE);
			if (ret)
				goto create_rdma_aux_err_unlock;
		}
		nbl_lag_devcomm_unlock(dev_mgt);
		mutex_unlock(&rdma_dev->adev_lock);
	}

	return 0;

create_rdma_aux_err_unlock:
	nbl_lag_devcomm_unlock(dev_mgt);
	mutex_unlock(&rdma_dev->adev_lock);
	return ret;
}

void nbl_dev_stop_rdma_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_adev *nadev;
	enum nbl_hw_status hw_status;
	enum nbl_core_reset_event event = NBL_CORE_FATAL_ERR_EVENT;

	if (!rdma_dev)
		return;

	hw_status = serv_ops->get_hw_status(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
	/**
	 * the adev add/del condition as follows:
	 * 1 nbl_dev_start_rdma_dev and nbl_dev_stop_rdma_dev
	 * 2 bond add/del
	 * not all pf has devcomm device, so nbl_lag_devcomm_lock only can
	 * protect bond/del conflict;
	 * all rdma_dev has rdma_dev->adev_lock;
	 * bond add/del only has nbl_lag_devcomm_lock;
	 *
	 * the ops call not only bond pf, so need nbl_lag_devcomm_lock
	 * and rdma_dev->adev_lock
	 */
	mutex_lock(&rdma_dev->adev_lock);
	nbl_lag_devcomm_lock(dev_mgt);
	dev_mgt->adev_flag |= NBL_DISABLE_ADEV;
	if (rdma_dev->bond_adev) {
		nadev = container_of(rdma_dev->bond_adev, struct nbl_adev, adev);
		if (hw_status)
			blocking_notifier_call_chain(&nadev->core_info->reset_nh,
						     NBL_CORE_EVT_RESET, &event);
		nbl_dev_destroy_rdma_aux_dev(rdma_dev, &rdma_dev->bond_adev);
	}

	if (rdma_dev->adev) {
		nadev = container_of(rdma_dev->adev, struct nbl_adev, adev);
		if (hw_status)
			blocking_notifier_call_chain(&nadev->core_info->reset_nh,
						     NBL_CORE_EVT_RESET, &event);
		nbl_dev_destroy_rdma_aux_dev(rdma_dev, &rdma_dev->adev);
	}

	nbl_lag_devcomm_unlock(dev_mgt);
	mutex_unlock(&rdma_dev->adev_lock);
}

int nbl_dev_resume_rdma_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);

	if (!rdma_dev || (!rdma_dev->has_rdma && !rdma_dev->has_grc))
		return 0;

	if (rdma_dev->has_abnormal_event_task)
		nbl_common_alloc_task(&rdma_dev->abnormal_event_task,
				      nbl_dev_rdma_handle_abnormal_event_task);
	return 0;
}

int nbl_dev_suspend_rdma_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);

	if (!rdma_dev)
		return 0;

	if (rdma_dev->has_abnormal_event_task)
		nbl_common_release_task(&rdma_dev->abnormal_event_task);

	return 0;
}

