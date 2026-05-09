// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_aux_drv.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/idr.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include "sxe2vf.h"
#include "sxe2vf_netdev.h"
#include "sxe2_log.h"
#include "sxe2vf_irq.h"
#include "sxe2vf_aux_drv.h"
#include "sxe2_version.h"
static DEFINE_IDA(sxe2vf_aux_ida);

static int sxe2vf_aux_vc_send(struct aux_core_dev_info *cdev_info, u16 vf_id,
			      u8 *msg, u16 len, u64 session_id)
{
	struct sxe2vf_adapter *adapter;

	if (!cdev_info)
		return -EINVAL;

	adapter = SXE2VF_DEV_TO_ADAPTER(cdev_info->pdev);
	if (!adapter)
		return -EINVAL;
	return 0;
}

static int sxe2vf_aux_vc_send_sync(struct aux_core_dev_info *cdev_info, u8 *msg,
				   u16 len, u8 *recv_msg, u16 recv_len)
{
	int ret;
	struct sxe2vf_adapter *adapter;

	if (!cdev_info || !recv_len || recv_len > MAX_RDMA_MSG_SIZE)
		return -EINVAL;

	adapter = SXE2VF_DEV_TO_ADAPTER(cdev_info->pdev);
	if (!adapter)
		return -EINVAL;
	ret = sxe2vf_rdma_msg_send(adapter, msg, len, recv_msg, recv_len);
	if (ret)
		LOG_ERROR_BDF("failed to send rdma msg to pf,err:%d.\n", ret);
	return ret;
}

static int sxe2vf_aux_request_reset(struct aux_core_dev_info *cdev_info,
				    enum aux_reset_type reset_type)
{
	struct sxe2vf_adapter *adapter;

	if (!cdev_info)
		return -EINVAL;

	adapter = SXE2VF_DEV_TO_ADAPTER(cdev_info->pdev);

	sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_VFR_REQUEST,
			     SXE2VF_RESET_NONE);
	sxe2vf_wkq_schedule(adapter, SXE2VF_WK_MONITOR_IM, 0);

	LOG_INFO_BDF("Trigger reset from rdma.\n");
	return 0;
}

static int sxe2vf_aux_vc_rdma_qv_map(struct sxe2vf_adapter *adapter,
				     struct aux_qvlist_info *qvl_info, bool map)
{
	s32 ret;

	ret = sxe2vf_qv_map_msg_send(adapter, qvl_info, map);
	if (ret) {
		LOG_DEBUG_BDF("rdma qv map err:%d.\n", ret);
		ret = -EINVAL;
	}
	return ret;
}

static bool sxe2vf_aux_is_adapter_ready(struct sxe2vf_adapter *adapter)
{
	if (test_bit(SXE2VF_FLAG_RESET_NOTIFY, adapter->flags)) {
		LOG_DEBUG_BDF("dev reset pending!\n");
		return false;
	}
	return true;
}

static int sxe2vf_aux_vc_queue_map_unmap(struct aux_core_dev_info *cdev_info,
					 struct aux_qvlist_info *qvl_info, bool map)
{
	int err;
	struct sxe2vf_adapter *adapter = SXE2VF_DEV_TO_ADAPTER(cdev_info->pdev);

	if (!sxe2vf_aux_is_adapter_ready(adapter)) {
		LOG_DEBUG_BDF("Adapter is not ready to map/unmap RDMA queue vector \t"
			      "over virtchnl\n");
		return -ENODEV;
	}

	err = sxe2vf_aux_vc_rdma_qv_map(adapter, qvl_info, map);
	if (err)
		LOG_INFO_BDF("Failed to send RDMA queue vector map/unmap message, \t"
			     "err %d\n",
			     err);

	return err;
}

static s32 sxe2vf_rdma_mac_rule_add(struct sxe2vf_adapter *adapter, u8 *mac)
{
	s32 ret = 0;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	if (!is_multicast_ether_addr(mac))
		return -EADDRNOTAVAIL;

	mutex_lock(&switch_ctxt->mac_addr_lock);
	ret = sxe2vf_mac_addr_add(adapter, mac, SXE2VF_MAC_OWNER_ROCE);
	if (ret && ret != -EEXIST)
		LOG_DEV_ERR("add mac filter failed, addr %pM, ret %d\n", mac, ret);
	else if (ret == -EEXIST)
		ret = 0;

	mutex_unlock(&switch_ctxt->mac_addr_lock);

	return ret;
}

static s32 sxe2vf_rdma_mac_rule_del(struct sxe2vf_adapter *adapter, u8 *mac)
{
	s32 ret = 0;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	if (!is_multicast_ether_addr(mac))
		return -EADDRNOTAVAIL;

	mutex_lock(&switch_ctxt->mac_addr_lock);
	ret = sxe2vf_mac_addr_del(adapter, mac, SXE2VF_MAC_OWNER_ROCE);
	if (ret && ret != -ENOENT)
		LOG_DEV_ERR("del mac filter failed, addr %pM, ret %d\n", mac, ret);
	else if (ret == -ENOENT)
		ret = 0;

	mutex_unlock(&switch_ctxt->mac_addr_lock);

	return ret;
}

static s32 sxe2vf_rdma_send_cmd(struct aux_core_dev_info *cdev_info,
				enum sxe2_drv_cmd_opcode opcode, u8 *msg, u16 len,
				u8 *recv_msg, u16 recv_len)
{
	s32 ret = -EINVAL;
	struct sxe2vf_adapter *adapter;

	if (!cdev_info || !msg || !len || len > MAX_RDMA_MSG_SIZE)
		return -EINVAL;

	adapter = SXE2VF_DEV_TO_ADAPTER(cdev_info->pdev);

	ret = sxe2vf_aux_mgr_msg_send(adapter, opcode, msg, len, recv_msg, recv_len);

	return ret;
}

static s32 sxe2vf_rdma_drv_config(struct aux_core_dev_info *cdev_info, u8 op,
				  u8 *msg)
{
	s32 ret = -EINVAL;
	struct sxe2vf_adapter *adapter;
	enum aux_rdma_opcode opcode = op;

	if (!cdev_info || !msg)
		return -EINVAL;

	adapter = SXE2VF_DEV_TO_ADAPTER(cdev_info->pdev);
	switch (opcode) {
	case RDMA_MAC_RULE_ADD:
		ret = sxe2vf_rdma_mac_rule_add(adapter, msg);
		break;
	case RDMA_MAC_RULE_DELETE:
		ret = sxe2vf_rdma_mac_rule_del(adapter, msg);
		break;
	default:
		LOG_INFO_BDF("opcode(%d) not support.\n", opcode);
		break;
	}

	return ret;
}

static int sxe2vf_rdma_dump_pcap_cmd(struct aux_core_dev_info *cdev_info, u8 *mac,
				     bool is_add)
{
	struct sxe2vf_adapter *adapter;

	adapter = SXE2VF_DEV_TO_ADAPTER(cdev_info->pdev);

	return sxe2vf_rdma_dump_pcap_msg_send(adapter, mac, is_add);
}

static struct sxe2_core_ops core_ops = {
		.request_reset = sxe2vf_aux_request_reset,
		.vc_send = sxe2vf_aux_vc_send,
		.vc_send_sync = sxe2vf_aux_vc_send_sync,
		.vc_queue_vec_map_unmap = sxe2vf_aux_vc_queue_map_unmap,
		.rdma_send_cmd = sxe2vf_rdma_send_cmd,
		.dump_pcap_cmd = sxe2vf_rdma_dump_pcap_cmd,
		.rdma_drv_config = sxe2vf_rdma_drv_config,
};

static struct sxe2_auxiliary_drv *
sxe2vf_rdma_aux_drv_get(struct aux_core_dev_info *cdev_info)
{
	struct auxiliary_device *adev;

	adev = cdev_info->adev;
	if (!adev || !adev->dev.driver)
		return NULL;
	return container_of(adev->dev.driver, struct sxe2_auxiliary_drv,
			    adrv.driver);
}

static void sxe2vf_adev_release(struct device *dev)
{
	struct sxe2_auxiliary_device *sxe2_adev;

	sxe2_adev = container_of(dev, struct sxe2_auxiliary_device, adev.dev);
	kfree(sxe2_adev);
}

static s32 sxe2vf_aux_dev_add(struct aux_core_dev_info *cdev_info)
{
	struct sxe2_auxiliary_device *sxe2vf_adev;
	struct auxiliary_device *adev;
	struct sxe2vf_adapter *adapter;
	s32 ret;

	adapter = SXE2VF_DEV_TO_ADAPTER(cdev_info->pdev);
	if (!adapter)
		return -EINVAL;

	sxe2vf_adev = kzalloc(sizeof(*sxe2vf_adev), GFP_KERNEL);
	if (!sxe2vf_adev)
		return -ENOMEM;

	mutex_lock(&adapter->aux_ctxt.adev_mutex);
	adev = &sxe2vf_adev->adev;
	cdev_info->adev = adev;
	mutex_unlock(&adapter->aux_ctxt.adev_mutex);

	sxe2vf_adev->cdev_info = cdev_info;
	adev->name = SXE2VF_RDMA_NAME;
	adev->id = (u32)adapter->aux_ctxt.aux_idx;
	adev->dev.release = sxe2vf_adev_release;
	adev->dev.parent = &cdev_info->pdev->dev;

	ret = auxiliary_device_init(adev);
	if (ret)
		goto err_vfadev_alloc;

	ret = auxiliary_device_add(adev);
	if (ret) {
		auxiliary_device_uninit(adev);
		goto err_vfadev_alloc;
	}

	goto out;

err_vfadev_alloc:
	kfree(sxe2vf_adev);
	cdev_info->adev = NULL;
out:
	return ret;
}

static void sxe2vf_aux_dev_delete(struct aux_core_dev_info *cdev_info)
{
	struct sxe2vf_adapter *adapter;
	struct auxiliary_device *adev;

	if (cdev_info->pdev)
		adapter = SXE2VF_DEV_TO_ADAPTER(cdev_info->pdev);
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

	LOG_DEBUG_BDF("release aux device end\n");
}

STATIC s32 sxe2vf_aux_device_init(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	u32 aux_irq_start = adapter->irq_ctxt.rdma_offset;
	struct sxe2vf_aux_context *aux = &adapter->aux_ctxt;
	struct aux_core_dev_info *cdev_info = &aux->cdev_info;
	struct pci_dev *pdev = adapter->pdev;

	if (adapter->aux_ctxt.init) {
		LOG_INFO_BDF("aux device is already initialized.\n");
		return 0;
	}

	adapter->aux_ctxt.aux_idx = ida_alloc(&sxe2vf_aux_ida, GFP_KERNEL);
	if (adapter->aux_ctxt.aux_idx < 0) {
		LOG_ERROR_BDF("failed to allocate device ID for aux drvs\n");
		return -ENOMEM;
	}

	cdev_info->hw_addr = adapter->hw.reg_base_addr;
	cdev_info->cdev_info_id = SXE2_RDMA_INDEX;

	cdev_info->pdev = pdev;
	cdev_info->netdev = adapter->netdev;
	cdev_info->vport_id =
			adapter->vsi_ctxt.vsi_ids[SXE2VF_VSI_TYPE_ETH];
	cdev_info->pf_id = 0;
	cdev_info->ops = &core_ops;
	cdev_info->ftype = AUX_FUNCTION_TYPE_VF;
	cdev_info->ver.major = AUX_MAJOR_VER;
	cdev_info->ver.minor = AUX_MINOR_VER;
	cdev_info->rdma_caps.gen = AUX_RDMA_GEN_1;
	(void)strscpy(cdev_info->drv_ver, SXE2_VERSION, SXE2_DRV_VER_STR_LEN);

	cdev_info->msix_count = adapter->aux_ctxt.num_msix;
	if (cdev_info->msix_count) {
		cdev_info->msix_entries =
				&adapter->irq_ctxt.msix_entries[aux_irq_start];
	}

	adapter->aux_ctxt.init = true;
	return ret;
}

void sxe2vf_aux_init_task(struct work_struct *work)
{
	struct sxe2vf_aux_context *aux =
		container_of(work, struct sxe2vf_aux_context, init_task.work);
	struct sxe2vf_adapter *adapter = aux->vfadapter;
	s32 err;

	err = sxe2vf_aux_device_init(adapter);
	if (err) {
		LOG_ERROR_BDF("failed to initialize rdma aux driver.\n");
		return;
	}
	err = sxe2vf_aux_dev_add(&aux->cdev_info);
	if (err) {
		LOG_ERROR_BDF("failed to add rdma aux driver.\n");
		return;
	}

	LOG_INFO_BDF("aux init task done.\n");
}

void sxe2vf_auxdrv_init(struct sxe2vf_adapter *adapter)
{
	(void)schedule_delayed_work(&adapter->aux_ctxt.init_task,
				    msecs_to_jiffies(5));
}

static int sxe2vf_rdma_aux_send_event(struct sxe2vf_adapter *adapter,
				      struct sxe2_rdma_event_info *event)
{
	struct sxe2_auxiliary_drv *iadrv;
	struct aux_core_dev_info *cdev_info;

	LOG_DEBUG_BDF("Start send event!\n");
	if (!adapter || !event)
		return -EINVAL;

	cdev_info = &adapter->aux_ctxt.cdev_info;

	mutex_lock(&adapter->aux_ctxt.adev_mutex);
	if (!cdev_info->adev || !event) {
		mutex_unlock(&adapter->aux_ctxt.adev_mutex);
		return 0;
	}

	device_lock(&cdev_info->adev->dev);
	iadrv = sxe2vf_rdma_aux_drv_get(cdev_info);
	if (iadrv && iadrv->aux_ops.event_handler)
		iadrv->aux_ops.event_handler(cdev_info, event);

	device_unlock(&cdev_info->adev->dev);
	mutex_unlock(&adapter->aux_ctxt.adev_mutex);

	LOG_DEBUG_BDF("End send event!\n");
	return 0;
}

void sxe2vf_auxdrv_send_reset_event(struct sxe2vf_adapter *adapter)
{
	struct sxe2_rdma_event_info event;

	(void)memset(&event, 0x0, sizeof(event));
	set_bit(SXE2_EVENT_NOTIFY_RESET, event.type);
	(void)sxe2vf_rdma_aux_send_event(adapter, &event);
}

int sxe2vf_rdma_aux_send_mtu_changed_event(struct sxe2vf_adapter *adapter)
{
	struct sxe2_rdma_event_info event;

	memset(&event, 0x0, sizeof(event));
	set_bit(SXE2_EVENT_MTU_CHANGED, event.type);
	return sxe2vf_rdma_aux_send_event(adapter, &event);
}

void sxe2vf_auxdrv_deinit(struct sxe2vf_adapter *adapter)
{
	struct aux_core_dev_info *cdev_info = &adapter->aux_ctxt.cdev_info;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return;

	if (adapter->aux_ctxt.init_task.work.func)
		(void)cancel_delayed_work_sync(&adapter->aux_ctxt.init_task);

	if (!adapter->aux_ctxt.init) {
		LOG_INFO_BDF(" auxdrv already deinit.\n");
		return;
	}

	if (cdev_info->adev) {
		LOG_INFO_BDF("adev is 0x%p remove:%u.\n", cdev_info->adev,
			     adapter->dev_ctxt.remove);
		if (!adapter->dev_ctxt.remove)
			sxe2vf_auxdrv_send_reset_event(adapter);
		(void)sxe2vf_aux_dev_delete(cdev_info);
	}

	ida_simple_remove(&sxe2vf_aux_ida, adapter->aux_ctxt.aux_idx);

	adapter->aux_ctxt.init = false;
	LOG_DEBUG_BDF("End deinit auxdrv!\n");
}
