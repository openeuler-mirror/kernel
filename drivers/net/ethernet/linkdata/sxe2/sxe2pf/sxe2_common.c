// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_common.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_common.h"
#include "sxe2_cmd_channel.h"
#include "sxe2_log.h"
#include "sxe2_spec.h"

STATIC void sxe2_dev_caps_set(struct sxe2_adapter *adapter,
			      struct sxe2_fwc_dev_caps *dev_caps)
{
	adapter->aux_ctxt.cdev_info.pf_cnt = dev_caps->pf_cnt;
	adapter->pf_cnt = dev_caps->pf_cnt;

	if (dev_caps->dev_common_caps.acl_support)
		set_bit(SXE2_FLAG_ACL_CAPABLE, adapter->flags);
	if (dev_caps->dev_common_caps.acl_ext_support)
		set_bit(SXE2_FLAG_ACL_EXT_CAPABLE, adapter->flags);

	set_bit(SXE2_FLAG_DCB_CAPABLE, adapter->flags);

	LOG_INFO_BDF("pf_cnt:%u\n", dev_caps->pf_cnt);
}

STATIC s32 sxe2_fwc_dev_caps_get(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_fwc_dev_caps dev_caps = {};
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_DEV_CAPS, NULL, 0, &dev_caps,
				  sizeof(dev_caps));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("get func caps failed, ret=%d\n", ret);
		ret = -EIO;
		goto l_end;
	}

	sxe2_dev_caps_set(adapter, &dev_caps);

l_end:
	return ret;
}

static u16 __sxe2_min_msix_num_calc(struct sxe2_adapter *adapter)
{
	u16 cnt;
	u32 mode = (u32)sxe2_com_mode_get(adapter);

	if (mode == SXE2_COM_MODULE_KERNEL)
		cnt = SXE2_MSIX_MIN_CNT + SXE2_RDMA_MSIX_MIN_CNT +
		      SXE2_FNAV_MSIX_CNT + SXE2_ESWITCH_MSIX_CNT;
	else if (mode == SXE2_COM_MODULE_DPDK)
		cnt = SXE2_DPDK_MSIX_MIN_CNT + SXE2_EVENT_MSIX_CNT +
		      SXE2_ESWITCH_MSIX_CNT + SXE2_DPDK_ESWITCH_MSIX_CNT;
	else
		cnt = SXE2_MSIX_MIN_CNT + SXE2_RDMA_MSIX_MIN_CNT +
		      SXE2_FNAV_MSIX_CNT + SXE2_ESWITCH_MSIX_CNT +
		      SXE2_DPDK_ESWITCH_MSIX_CNT + SXE2_DPDK_MSIX_MIN_CNT;

	LOG_INFO_BDF("mode:%d min irq cnt:%u\n", mode, cnt);

	return cnt;
}

u16 sxe2_min_msix_num_calc(struct sxe2_adapter *adapter)
{
	u16 min_msix;

	if (sxe2_is_safe_mode(adapter))
		min_msix = SXE2_MSIX_MIN_CNT;
	else
		min_msix = __sxe2_min_msix_num_calc(adapter);
	return min_msix;
}

u16 sxe2_min_queue_num_calc(struct sxe2_adapter *adapter)
{
	u16 min_msix;

	if (sxe2_is_safe_mode(adapter))
		min_msix = SXE2_SAFE_MODE_TXQ_CNT;
	else
		min_msix = SXE2_NON_SAFEMODE_MIN_TXQ_CNT;
	return min_msix;
}

STATIC s32 sxe2_func_caps_check(struct sxe2_adapter *adapter,
				struct sxe2_fwc_func_caps *func_caps)
{
	s32 ret = 0;
	u16 min_msix = sxe2_min_msix_num_calc(adapter);
	u16 min_queue = sxe2_min_queue_num_calc(adapter);

	if (le16_to_cpu(func_caps->msix_caps.cnt) < min_msix)
		ret = -ENOSPC;
	if (le16_to_cpu(func_caps->tx_caps.cnt) < min_queue)
		ret = -ENOSPC;
	if (le16_to_cpu(func_caps->rx_caps.cnt) < min_queue)
		ret = -ENOSPC;
	return ret;
}

STATIC s32 sxe2_sw_caps_set(struct sxe2_adapter *adapter,
			    struct sxe2_fwc_func_caps *func_caps)
{
	if (sxe2_func_caps_check(adapter, func_caps))
		return -ENOSPC;

	adapter->irq_ctxt.max_cnt = le16_to_cpu(func_caps->msix_caps.cnt);
	adapter->irq_ctxt.base_idx_in_dev =
			le16_to_cpu(func_caps->msix_caps.base_idx);

	adapter->q_ctxt.max_txq_cnt = le16_to_cpu(func_caps->tx_caps.cnt);
	adapter->q_ctxt.txq_base_idx_in_dev =
			le16_to_cpu(func_caps->tx_caps.base_idx);
	adapter->q_ctxt.max_rxq_cnt = le16_to_cpu(func_caps->rx_caps.cnt);
	adapter->q_ctxt.rxq_base_idx_in_dev =
			le16_to_cpu(func_caps->rx_caps.base_idx);

	adapter->vsi_ctxt.max_cnt = le16_to_cpu(func_caps->vsi_caps.cnt);
	adapter->vsi_ctxt.base_idx_in_dev =
			le16_to_cpu(func_caps->vsi_caps.base_idx);
	adapter->pf_idx = func_caps->pf_idx;
	adapter->port_idx = func_caps->port_idx;

	adapter->caps_ctxt.max_rss_lut_size =
			le16_to_cpu(func_caps->ppe_caps.rss_lut_size);
	adapter->caps_ctxt.fnav_space_bsize =
			le16_to_cpu(func_caps->ppe_caps.fnav_space_bsize);
	adapter->caps_ctxt.fnav_space_gsize =
			le16_to_cpu(func_caps->ppe_caps.fnav_space_gsize);
	adapter->caps_ctxt.fnav_stat_base =
			le16_to_cpu(func_caps->ppe_caps.fnav_counter_base);
	adapter->caps_ctxt.fnav_stat_num =
			le16_to_cpu(func_caps->ppe_caps.fnav_counter_num);
	adapter->caps_ctxt.acl_stat_base =
			le16_to_cpu(func_caps->ppe_caps.acl_counter_base);
	adapter->caps_ctxt.acl_stat_num =
			le16_to_cpu(func_caps->ppe_caps.acl_counter_num);
	adapter->caps_ctxt.global_lut_base =
			le16_to_cpu(func_caps->ppe_caps.rss_global_lut_base);
	adapter->caps_ctxt.global_lut_num =
			le16_to_cpu(func_caps->ppe_caps.rss_global_lut_num);
	adapter->vsi_ctxt.dpdk_lut_type = SXE2_RSS_VSI_LUT;
	adapter->vsi_ctxt.dpdk_global_lut_id = SXE2_VF_GLOBAL_LUT_INVALID_ID;
	adapter->caps_ctxt.acl_stat_base =
			le16_to_cpu(func_caps->ppe_caps.acl_counter_base);
	adapter->caps_ctxt.acl_stat_num =
			le16_to_cpu(func_caps->ppe_caps.acl_counter_num);

	if (func_caps->vf_caps.sriov_cap) {
		set_bit(SXE2_FLAG_SRIOV_CAPABLE, adapter->flags);
		adapter->vf_ctxt.max_vfs = (u16)min_t(u16,
				(le16_to_cpu(func_caps->vf_caps.cnt)),
				SXE2_VF_NUM);
		adapter->vf_ctxt.vfid_base =
				le16_to_cpu(func_caps->vf_caps.base_idx);
	}

	clear_bit(SXE2_FLAG_VMDQ_CAPABLE, adapter->flags);
	if (func_caps->common_caps.vmdq_support)
		set_bit(SXE2_FLAG_VMDQ_CAPABLE, adapter->flags);

	adapter->ptp_ctxt.ptp_owned =
			(func_caps->pf_idx == func_caps->common_caps.ptp_owner);

	if (sxe2_is_safe_mode(adapter))
		sxe2_safe_mode_caps_set(adapter);

	LOG_INFO_BDF("pf_idx:%u port_idx:%u irq max:%u base:%u txq max:%u\n"
		     "txq_base_idx_in_dev:%u rxq max:%u rxq_base_idx_in_dev:%u\n"
		     "sriov_cap:%u max_vfs:%u vfid_base:%u rss_lut_size:%u.\n"
		     "fnav_bsize: %u, fnav_gsize: %u vsi_max_cnt:%u vsi_base_id:%u\n"
			 "acl_stat_base:%u, acl_stat_num:%u.\n",
		     adapter->pf_idx, adapter->port_idx, adapter->irq_ctxt.max_cnt,
		     adapter->irq_ctxt.base_idx_in_dev, adapter->q_ctxt.max_txq_cnt,
		     adapter->q_ctxt.txq_base_idx_in_dev,
		     adapter->q_ctxt.max_rxq_cnt,
		     adapter->q_ctxt.rxq_base_idx_in_dev,
		     func_caps->vf_caps.sriov_cap, adapter->vf_ctxt.max_vfs,
		     adapter->vf_ctxt.vfid_base, adapter->caps_ctxt.max_rss_lut_size,
		     adapter->caps_ctxt.fnav_space_bsize,
		     adapter->caps_ctxt.fnav_space_gsize, adapter->vsi_ctxt.max_cnt,
		     adapter->vsi_ctxt.base_idx_in_dev, adapter->caps_ctxt.acl_stat_base,
		     adapter->caps_ctxt.acl_stat_num);
	return 0;
}

s32 sxe2_fwc_func_caps_get(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_fwc_func_caps func_caps = {};
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FUNC_CAPS, NULL, 0, &func_caps,
				  sizeof(func_caps));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_DEV_ERR("get func caps failed, ret=%d\n", ret);
		ret = -EIO;
		goto l_end;
	}

	ret = sxe2_sw_caps_set(adapter, &func_caps);
	if (ret)
		LOG_DEV_ERR("set func caps failed, ret=%d\n", ret);

l_end:
	return ret;
}

s32 __sxe2_drv_mode_get(struct sxe2_adapter *adapter,
			struct sxe2_fwc_drv_mode_resp *resp, u32 resp_len)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};

	memset(&cmd, 0, sizeof(cmd));

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_DRV_MODE_GET, NULL, 0, resp,
				  resp_len);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_DEV_INFO("get drv mode failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

void sxe2_drv_mode_get(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	enum sxe2_com_module drv_mode = sxe2_g_drv_mode_get();
	struct sxe2_fwc_drv_mode_resp resp = {};

	adapter->drv_mode = drv_mode;

	ret = __sxe2_drv_mode_get(adapter, &resp, sizeof(resp));
	if (!ret) {
		if (resp.drv_mode != SXE2_COM_MODULE_UNDEFINED) {
			adapter->drv_mode = resp.drv_mode;
			return;
		}
	} else {
		LOG_ERROR_BDF("__sxe2_drv_mode_get failed: %d\n", ret);
	}
}

s32 sxe2_drv_mode_set(struct sxe2_adapter *adapter, enum sxe2_com_module type)
{
	s32 ret = 0;
	struct sxe2_fwc_drv_mode_req req = {};
	struct sxe2_cmd_params cmd = {};

	req.drv_mode = type;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_DRV_MODE_SET, &req, sizeof(req),
				  NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_DEV_ERR("set drv mode failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_hw_mtu_init(struct sxe2_adapter *adapter, u32 init_mtu, u8 is_set_hw)
{
	s32 ret;
	struct sxe2_fw_mtu_info mtu = {};
	struct sxe2_cmd_params cmd = {};

	mtu.mtu = init_mtu;
	mtu.is_set_hw = is_set_hw;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_MAC_MTU_SET, &mtu, sizeof(mtu),
				  NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_DEV_ERR("init mac 9k failed, ret=%d\n", ret);

	return ret;
}

s32 sxe2_caps_get(struct sxe2_adapter *adapter)
{
	s32 ret;

	ret = sxe2_fwc_dev_caps_get(adapter);
	if (ret)
		goto l_end;

	ret = sxe2_fwc_func_caps_get(adapter);

l_end:
	return ret;
}

u32 sxe2_local_cpus_cnt_get(struct device *device)
{
	unsigned int cnt;
	int node;

	node = dev_to_node(device);

	if (node == NUMA_NO_NODE)
		cnt = cpumask_weight(cpu_online_mask);
	else
		cnt = cpumask_weight(cpumask_of_node(node));

	return cnt;
}

u32 sxe2_standardize_cpu_cnt(u32 cpu_cnt)
{
	if (cpu_cnt > SXE2_DFLT_IRQS_MAX_CNT)
		cpu_cnt = SXE2_DFLT_IRQS_MAX_CNT;
	else if (cpu_cnt < SXE2_DFLT_IRQS_MIN_CNT)
		cpu_cnt = SXE2_DFLT_IRQS_MIN_CNT;

	return cpu_cnt;
}

bool sxe2_is_safe_mode(struct sxe2_adapter *adapter)
{
	return !test_bit(SXE2_FLAG_ADVANCE_MODE, adapter->flags);
}

void sxe2_safe_mode_caps_set(struct sxe2_adapter *adapter)
{
	adapter->irq_ctxt.max_cnt = SXE2_SAFE_MODE_IRQ_CNT;
	adapter->q_ctxt.max_txq_cnt = SXE2_SAFE_MODE_TXQ_CNT;
	adapter->q_ctxt.max_rxq_cnt = SXE2_SAFE_MODE_RXQ_CNT;
	adapter->vsi_ctxt.max_cnt = SXE2_SAFE_MODE_VSI_CNT;

	clear_bit(SXE2_FLAG_VMDQ_CAPABLE, adapter->flags);

	clear_bit(SXE2_FLAG_MACVLAN_ENABLE, adapter->flags);

	clear_bit(SXE2_FLAG_DCB_CAPABLE, adapter->flags);

	clear_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags);
}

bool sxe2_is_vf_vlan_enabled(struct sxe2_vsi *vsi)
{
	return false;
}

s32 sxe2_err_code_trans_hw(s32 err)
{
	s32 ret;

	switch (err) {
	case SXE2_HW_ERR_SUCCESS:
		ret = 0;
		break;
	case -SXE2_HW_ERR_FAULT:
		ret = -EFAULT;
		break;
	case -SXE2_HW_ERR_TIMEDOUT:
		ret = -ETIMEDOUT;
		break;
	case -SXE2_HW_ERR_INVAL:
		ret = -EINVAL;
		break;
	case -SXE2_HW_ERR_IO:
	default:
		ret = -EIO;
		break;
	}

	return ret;
}

s32 sxe2_fwc_pxe_disable(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_fwc_pxe_req req = {};
	struct sxe2_cmd_params cmd = {};

	req.ena = 0;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_PXE_CTRL, &req, sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("pxe disable failed, ret=%d\n", ret);
		ret = -EIO;
	}
	return ret;
}

void sxe2_queue_work(struct sxe2_adapter *adapter, struct workqueue_struct *wq,
		     struct work_struct *dwork)
{
	if (!queue_work(wq, dwork))
		LOG_WARN_BDF("work was already on a queue.\n");
}

s32 __sxe2_global_lut_get(struct sxe2_adapter *adapter)
{
	struct sxe2_caps_context *caps_ctxt = &adapter->caps_ctxt;
	s32 lut_id;

	lut_id = bitmap_find_free_region(caps_ctxt->global_lut_id,
					 caps_ctxt->global_lut_num, 0);
	if (lut_id < 0)
		return lut_id;

	return lut_id + (s32)caps_ctxt->global_lut_base;
}

s32 sxe2_global_lut_get(struct sxe2_adapter *adapter)
{
	s32 lut_id;

	mutex_lock(&adapter->caps_ctxt.global_lut_lock);
	lut_id = __sxe2_global_lut_get(adapter);
	mutex_unlock(&adapter->caps_ctxt.global_lut_lock);

	return lut_id;
}

void sxe2_global_lut_put(struct sxe2_adapter *adapter, u8 lut_id)
{
	struct sxe2_caps_context *caps_ctxt = &adapter->caps_ctxt;

	if (lut_id == SXE2_VF_GLOBAL_LUT_INVALID_ID)
		return;

	mutex_lock(&caps_ctxt->global_lut_lock);
	clear_bit(lut_id - caps_ctxt->global_lut_base,
		  caps_ctxt->global_lut_id);
	mutex_unlock(&caps_ctxt->global_lut_lock);
}

u16 __sxe2_global_lut_remaining(struct sxe2_adapter *adapter)
{
	struct sxe2_caps_context *caps_ctxt = &adapter->caps_ctxt;

	return caps_ctxt->global_lut_num -
	       (u16)bitmap_weight(caps_ctxt->global_lut_id,
				  caps_ctxt->global_lut_num);
}

bool sxe2_global_lut_get_bulk(struct sxe2_adapter *adapter, u16 cnt, u8 *lut_ids)
{
	struct sxe2_caps_context *caps_ctxt = &adapter->caps_ctxt;
	bool sufficient = true;
	u16 i;

	mutex_lock(&caps_ctxt->global_lut_lock);
	if (cnt > __sxe2_global_lut_remaining(adapter)) {
		sufficient = false;
		goto l_end;
	}

	for (i = 0; i < cnt; i++) {
		s32 lut_id = __sxe2_global_lut_get(adapter);

		if (lut_id < 0) {
			while (i > 0)
				clear_bit(lut_ids[--i] -
					  caps_ctxt->global_lut_base,
					  caps_ctxt->global_lut_id);
			sufficient = false;
			goto l_end;
		}
		lut_ids[i] = (u8)lut_id;
	}

l_end:
	mutex_unlock(&caps_ctxt->global_lut_lock);
	return sufficient;
}

s32 sxe2_dpdk_pf_caps_get(struct sxe2_adapter *adapter,
			  struct sxe2_fwc_func_caps *caps)
{
	s32 ret = 0;
	u16 q_max;

	if (!adapter || !caps) {
		ret = -EINVAL;
		LOG_ERROR_BDF("param invalid.\n");
		goto l_end;
	}

	if (adapter->vsi_ctxt.dpdk_lut_type != SXE2_RSS_GLOBAL_LUT) {
		s32 lut_id = sxe2_global_lut_get(adapter);

		if (lut_id >= 0) {
			adapter->vsi_ctxt.dpdk_lut_type = SXE2_RSS_GLOBAL_LUT;
			adapter->vsi_ctxt.dpdk_global_lut_id = (u8)lut_id;
		} else {
			adapter->vsi_ctxt.dpdk_lut_type = SXE2_RSS_VSI_LUT;
			adapter->vsi_ctxt.dpdk_global_lut_id =
				SXE2_VF_GLOBAL_LUT_INVALID_ID;
		}
	}

	q_max = (adapter->vsi_ctxt.dpdk_lut_type == SXE2_RSS_GLOBAL_LUT) ?
		SXE2_GLOBAL_LUT_MAX_QUEUE : SXE2_VSI_LUT_MAX_QUEUE;

	caps->tx_caps.base_idx = adapter->q_ctxt.txq_layout.dpdk_offset;
	caps->tx_caps.cnt = min_t(u16, q_max, adapter->q_ctxt.txq_layout.dpdk);

	caps->rx_caps.base_idx = adapter->q_ctxt.rxq_layout.dpdk_offset;
	caps->rx_caps.cnt = min_t(u16, q_max, adapter->q_ctxt.rxq_layout.dpdk);

	caps->msix_caps.base_idx = adapter->irq_ctxt.irq_layout.dpdk_offset;
	caps->msix_caps.cnt = adapter->irq_ctxt.irq_layout.dpdk;

	caps->vsi_caps.dpdk_lut_type = adapter->vsi_ctxt.dpdk_lut_type;
	caps->vsi_caps.dpdk_global_lut_id = adapter->vsi_ctxt.dpdk_global_lut_id;

	LOG_INFO_BDF("dpdk pf txq base:%d cnt:%d rxq base:%d cnt:%d irq base:%d cnt:%d "
		     "lut_type:%u lut_id:%u.\n",
		     caps->tx_caps.base_idx, caps->tx_caps.cnt,
		     caps->rx_caps.base_idx, caps->rx_caps.cnt,
		     caps->msix_caps.base_idx, caps->msix_caps.cnt,
		     caps->vsi_caps.dpdk_lut_type, caps->vsi_caps.dpdk_global_lut_id);

l_end:
	return ret;
}
