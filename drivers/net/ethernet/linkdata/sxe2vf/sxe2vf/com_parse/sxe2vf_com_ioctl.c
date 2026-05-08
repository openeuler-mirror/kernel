// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_com_ioctl.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2vf_com_ioctl.h"
#include "sxe2_ioctl_chnl.h"
#include "sxe2vf_queue.h"
#include "sxe2vf_tx.h"
#include "sxe2vf_rx.h"
#include "sxe2_cmd.h"
#include "sxe2vf_vsi.h"
#include "sxe2_log.h"
#include "sxe2_drv_cmd.h"
#include "sxe2_com_cdev.h"
#include "sxe2vf_mbx_msg.h"
#include "sxe2vf_ethtool.h"
#include "sxe2vf_com_l2_filter.h"
#include "sxe2vf.h"
#include "sxe2_mbx_public.h"
#include "sxe2vf_com_stats.h"

static s32 sxe2vf_com_handshake_disable(struct sxe2vf_adapter *adapter,
					struct sxe2_obj *obj,
					struct sxe2_drv_cmd_params *cmd_buf)
{
	return 0;
}

static s32
sxe2vf_com_user_vf_passthrough_to_kernel_pf(struct sxe2vf_adapter *adapter,
					    struct sxe2_obj *obj,
					    struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_com_user_data_passthrough_req *req = NULL;
	struct sxe2_com_user_data_passthrough_resp *resp = NULL;
	struct sxe2vf_msg_params params = { 0 };
	s32 ret;
	u32 req_len;
	u32 resp_len;

	if (!cmd_buf)
		return -EINVAL;

	req_len = sizeof(struct sxe2_com_user_data_passthrough_req) +
		  cmd_buf->req_len * sizeof(u8);
	req = kzalloc(req_len, GFP_KERNEL);
	if (!req) {
		LOG_ERROR_BDF("kzalloc req failed.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	if (cmd_buf->req_len > 0 && cmd_buf->req_data) {
		if (copy_from_user(req->cmd_buff, cmd_buf->req_data, cmd_buf->req_len)) {
			ret = -EFAULT;
			goto l_end;
		}
		req->req_len = cmd_buf->req_len;
	}

	resp_len = sizeof(struct sxe2_com_user_data_passthrough_resp) +
		   cmd_buf->resp_len * sizeof(u8);
	resp = kzalloc(resp_len, GFP_KERNEL);
	if (!resp) {
		LOG_ERROR_BDF("kzalloc resp failed.\n");
		ret = -ENOMEM;
		goto l_end;
	}
	req->resp_len = cmd_buf->resp_len;
	memcpy(&req->obj, obj, sizeof(struct sxe2_obj));
	req->opcode = cmd_buf->opcode;
	req->vsi_id = cmd_buf->vsi_id;

	LOG_INFO_BDF("opcode:%d, req_len=%d, resp_len=%d\n", req->opcode, req->req_len,
		     req->resp_len);
	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_PASSTHROUGH_USER_VF_DATA, req, req_len,
					resp, resp_len);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("mbx msg send failed.(err:%d)\n", ret);
		goto l_end;
	}

	if (cmd_buf->resp_len > 0 && cmd_buf->resp_data) {
		if (copy_to_user(cmd_buf->resp_data, resp->cmd_buff, cmd_buf->resp_len)) {
			ret = -EFAULT;
			goto l_end;
		}
	}

l_end:
	kfree(req);
	kfree(resp);
	return ret;
}

STATIC s32 sxe2vf_user_vsi_hw_cfg(struct sxe2vf_adapter *adapter,
				  struct sxe2_drv_vsi_create_req_resp *vsi_info,
				  bool is_clear)
{
	struct sxe2_vf_vsi_cfg vsi_cfg = {};
	struct sxe2vf_msg_params params = { 0 };
	s32 ret = 0;
	u16 vsi_type = 8;

	memset(&vsi_cfg, 0, sizeof(vsi_cfg));
	vsi_cfg.txq_base_idx = cpu_to_le16(vsi_info->used_queues.base_idx_in_pf);
	vsi_cfg.txq_cnt = cpu_to_le16(vsi_info->used_queues.queues_cnt);
	vsi_cfg.rxq_base_idx = cpu_to_le16(vsi_info->used_queues.base_idx_in_pf);
	vsi_cfg.rxq_cnt = cpu_to_le16(vsi_info->used_queues.queues_cnt);
	vsi_cfg.irq_base_idx = cpu_to_le16(vsi_info->used_msix.base_idx_in_func);
	vsi_cfg.irq_cnt = cpu_to_le16(vsi_info->used_msix.msix_vectors_cnt);

	vsi_cfg.is_clear = is_clear;
	vsi_cfg.vsi_id = cpu_to_le16(adapter->vsi_ctxt.vsi_ids[SXE2VF_VSI_TYPE_DPDK]);

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_VSI_CFG, &vsi_cfg, sizeof(vsi_cfg), NULL,
					0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("mbx msg send failed.(err:%d)\n", ret);
		ret = -EINVAL;
		goto l_end;
	}

	vsi_info->vsi_id = vsi_cfg.vsi_id;
	vsi_info->vsi_type = vsi_type;

l_end:
	return ret;
}

static s32 sxe2vf_com_cap_get(struct sxe2vf_adapter *adapter, struct sxe2_obj *obj,
			      struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_dev_caps_resp *resp;
	struct sxe2vf_res_caps caps;
	s32 ret = 0;

	resp = kmalloc(sizeof(*resp), GFP_KERNEL);
	if (!resp)
		return -ENOMEM;

	memset(resp, 0, sizeof(*resp));

	ret = sxe2vf_dpdk_caps_get(adapter, &caps);
	if (ret) {
		LOG_ERROR_BDF("sxe2vf_dpdk_caps_get failed\n");
		ret = -EINVAL;
		goto l_end;
	}

	resp->dev_type = SXE2_DEV_T_VF;

	resp->queue_caps.base_idx_in_pf = caps.txq_base;
	resp->queue_caps.queues_cnt = caps.txq_cnt;

	resp->msix_caps.msix_vectors_cnt = caps.irq_cnt;
	resp->msix_caps.base_idx_in_func = caps.irq_base;

	resp->rss_hash_caps.hash_key_size = caps.rss_key_size;
	resp->rss_hash_caps.lut_key_size = caps.rss_lut_size;

	resp->vsi_caps.dpdk_vsi_id = 0xFFFF;
	resp->vsi_caps.vsi_type = 0xFF;

	if (adapter->vsi_ctxt.vf_vsi)
		resp->vsi_caps.kernel_vsi_id = adapter->vsi_ctxt.vf_vsi->vsi_id;

	resp->txsch_caps.layer_cap = adapter->txsch_cap.layer_cap;
	resp->txsch_caps.prio_num = adapter->txsch_cap.prio_num;
	resp->txsch_caps.tm_mid_node_num = adapter->txsch_cap.tm_mid_node_num;
	resp->cap_flags = SXE2_DEV_CAPS_OFFLOAD_L2 | SXE2_DEV_CAPS_OFFLOAD_VLAN |
			  SXE2_DEV_CAPS_OFFLOAD_RSS | SXE2_DEV_CAPS_OFFLOAD_FNAV |
			  SXE2_DEV_CAPS_OFFLOAD_TM;
	if (adapter->ipsec_ctxt.max_tx_sa_cnt && adapter->ipsec_ctxt.max_rx_sa_cnt)
		resp->cap_flags |= SXE2_DEV_CAPS_OFFLOAD_IPSEC;

	if (copy_to_user(cmd_buf->resp_data, resp, sizeof(*resp))) {
		ret = -EFAULT;
		goto l_end;
	}
	cmd_buf->resp_len = sizeof(*resp);

l_end:
	kfree(resp);
	return ret;
}

static s32 sxe2vf_com_link_info_get(struct sxe2vf_adapter *adapter, struct sxe2_obj *obj,
				    struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_link_info_resp resp;
	s32 ret = 0;

	memset(&resp, 0, sizeof(resp));
	ret = sxe2vf_com_link_info_request(adapter, &resp.status, &resp.speed);
	if (ret) {
		LOG_ERROR_BDF("get vf link info failed ret:%d\n", ret);
		resp.status = 0;
		resp.speed = SXE2_LINK_SPEED_VF_UNKNOWN;
	}

	if (copy_to_user(cmd_buf->resp_data, &resp, sizeof(resp))) {
		ret = -EFAULT;
		goto l_end;
	}
	cmd_buf->resp_len = sizeof(resp);

l_end:
	return ret;
}

static s32 sxe2vf_com_main_vsi_create(struct sxe2vf_adapter *adapter,
				      struct sxe2_obj *obj,
				      struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;
	struct sxe2_drv_vsi_create_req_resp *req_resp;

	req_resp = (struct sxe2_drv_vsi_create_req_resp *)
		   sxe2vf_com_req_data_copy_to_kernel(cmd_buf);

	ret = sxe2vf_user_vsi_hw_cfg(adapter, req_resp, false);
	if (ret) {
		LOG_ERROR_BDF("user vsi create failed ret:%d\n", ret);
		ret = -EINVAL;
		goto l_end;
	}

	if (copy_to_user(cmd_buf->resp_data, req_resp, sizeof(*req_resp))) {
		ret = -EFAULT;
		goto l_free_vsi;
	}

	cmd_buf->resp_len = sizeof(*req_resp);
	goto l_end;

l_free_vsi:
	(void)sxe2vf_user_vsi_hw_cfg(adapter, req_resp, true);

l_end:
	kfree(req_resp);
	return ret;
}

static s32 sxe2vf_com_vsi_destroy(struct sxe2vf_adapter *adapter, struct sxe2_obj *obj,
				  struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;
	struct sxe2_drv_vsi_free_req *free_req;
	struct sxe2_drv_vsi_create_req_resp req_resp = {0};

	free_req = (struct sxe2_drv_vsi_free_req *)
			   sxe2vf_com_req_data_copy_to_kernel(cmd_buf);
	if (!free_req) {
		ret = -EINVAL;
		goto l_end;
	}
	req_resp.vsi_id = free_req->vsi_id;
	ret = sxe2vf_user_vsi_hw_cfg(adapter, &req_resp, true);
	if (ret) {
		LOG_ERROR_BDF("user vsi destroy failed ret:%d\n", ret);
		ret = -EINVAL;
		goto l_end;
	}

l_end:
	kfree(free_req);
	return ret;
}

static s32 sxe2vf_com_q_map(struct sxe2vf_adapter *adapter, struct sxe2_obj *obj,
			    struct sxe2_drv_cmd_params *cmd_buf)
{
	LOG_ERROR_BDF("VF does not support queue mapping\n");
	return -EINVAL;
}

static struct sxe2vf_ioctl_cmd_table driver_cmd_table[] = {
		{SXE2_DRV_CMD_HANDSHAKE_DISABLE, sxe2vf_com_handshake_disable},
		{SXE2_DRV_CMD_DEV_GET_CAPS, sxe2vf_com_cap_get},
		{SXE2_DRV_CMD_DEV_GET_SWITCHDEV_INFO,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},

		{SXE2_DRV_CMD_DEV_GET_INFO, sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_DEV_GET_FW_INFO,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_LINK_STATUS_GET, sxe2vf_com_link_info_get},

		{SXE2_DRV_CMD_VSI_CREATE, sxe2vf_com_main_vsi_create},
		{SXE2_DRV_CMD_VSI_FREE, sxe2vf_com_vsi_destroy},

		{SXE2_DRV_CMD_VSI_STATS_GET, sxe2vf_com_vsi_stat_get},
		{SXE2_DRV_CMD_VSI_STATS_CLEAR, sxe2vf_com_vsi_stat_clear},

		{SXE2_DRV_CMD_MAC_ADDR_UC, sxe2vf_com_switch_filter_uc},
		{SXE2_DRV_CMD_MAC_ADDR_MC, sxe2vf_com_switch_filter_mc},
		{SXE2_DRV_CMD_VLAN_FILTER_SWITCH, sxe2vf_com_switch_filter_vlan_control},
		{SXE2_DRV_CMD_VLAN_FILTER_ADD_DEL, sxe2vf_com_switch_filter_vlan_rule},
		{SXE2_DRV_CMD_PROMISC_CFG, sxe2vf_com_switch_filter_promisc},
		{SXE2_DRV_CMD_ALLMULTI_CFG, sxe2vf_com_switch_filter_allmulti},

		{SXE2_DRV_CMD_TXQ_CFG_ENABLE,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_RXQ_CFG_ENABLE,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},

		{SXE2_DRV_CMD_EVT_IRQ_BAND_RXQ,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},

		{SXE2_DRV_CMD_RXQ_DISABLE, sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_TXQ_DISABLE, sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_FLOW_FILTER_ADD,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_FLOW_FILTER_DEL,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_FLOW_FNAV_STAT_ALLOC,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_FLOW_FNAV_STAT_FREE,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_FLOW_FNAV_STAT_QUERY,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},

		{SXE2_DRV_CMD_VLAN_OFFLOAD_CFG,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},

		{SXE2_DRV_CMD_IPSEC_CAP_GET, sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_IPSEC_TXSA_ADD,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_IPSEC_RXSA_ADD,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_IPSEC_TXSA_DEL,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_IPSEC_RXSA_DEL,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_IPSEC_RESOURCE_CLEAR,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},

		{SXE2_DRV_CMD_SCHED_ROOT_TREE_ALLOC,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_SCHED_ROOT_TREE_RELEASE,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_SCHED_ROOT_CHILDREN_DELETE,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_SCHED_TM_ADD_MID_NODE,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_SCHED_TM_ADD_QUEUE_NODE,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},

		{SXE2_DRV_CMD_RX_MAP_SET, sxe2vf_com_q_map},
		{SXE2_DRV_CMD_TX_MAP_SET, sxe2vf_com_q_map},
		{SXE2_DRV_CMD_TX_RX_MAP_GET, sxe2vf_com_q_map},
		{SXE2_DRV_CMD_TX_RX_MAP_RESET, sxe2vf_com_q_map},
		{SXE2_DRV_CMD_TX_RX_MAP_INFO_CLEAR, sxe2vf_com_q_map},

		{SXE2_DRV_CMD_RSS_KEY_SET, sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_RSS_LUT_SET, sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_RSS_FUNC_SET, sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_RSS_HF_ADD, sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_RSS_HF_DEL, sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_RSS_HF_CLEAR, sxe2vf_com_user_vf_passthrough_to_kernel_pf},

		{SXE2_DRV_CMD_VLAN_CFG_QUERY,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_UDPTUNNEL_GET, sxe2vf_com_user_vf_passthrough_to_kernel_pf},
		{SXE2_DRV_CMD_VSI_SRCVSI_PRUNE,
		 sxe2vf_com_user_vf_passthrough_to_kernel_pf},

		{SXE2_DRV_CMD_OPT_EEP_GET, sxe2vf_com_user_vf_passthrough_to_kernel_pf},
};

static s32 sxe2vf_drv_cmd_len_check(struct sxe2_drv_cmd_params *cmd_buf)
{
	return 0;
}

static s32 sxe2_vf_status_check(struct sxe2vf_adapter *adapter,
				struct sxe2_drv_cmd_params *cmd_buf)
{
	return 0;
}

static s32 sxe2vf_drv_msg_check(struct sxe2vf_adapter *adapter,
				struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;

	ret = sxe2vf_drv_cmd_len_check(cmd_buf);
	if (ret)
		return ret;

	ret = sxe2_vf_status_check(adapter, cmd_buf);
	if (ret)
		return ret;

	return ret;
}

static struct sxe2vf_ioctl_cmd_table *sxe2vf_drv_cmd_handle_get(u32 opcode)
{
	u32 i;
	struct sxe2vf_ioctl_cmd_table *cmd_func = NULL;

	for (i = 0; i < ARRAY_SIZE(driver_cmd_table); i++) {
		if (driver_cmd_table[i].opcode == opcode) {
			cmd_func = &driver_cmd_table[i];
			break;
		}
	}

	return cmd_func;
}

s32 sxe2vf_com_cmd_send(void *ad, struct sxe2_obj *obj, struct sxe2_drv_cmd_params *param)
{
	s32 ret;
	struct sxe2vf_ioctl_cmd_table *cmd_table = NULL;
	struct sxe2vf_adapter *adapter = ad;

	if (sxe2vf_drv_msg_check(adapter, param)) {
		ret = -EINVAL;
		goto l_end;
	}

	cmd_table = sxe2vf_drv_cmd_handle_get(param->opcode);
	if (cmd_table && cmd_table->func) {
		ret = cmd_table->func(adapter, obj, param);
	} else {
		LOG_ERROR_BDF("Can't find cmd opcode:0x%x vsi_id:%u trace_id:0x%llx\n.",
			      param->opcode, param->vsi_id, param->trace_id);
		ret = -EINVAL;
	}

l_end:
	return ret;
}
