// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_ioctl.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_com_ioctl.h"
#include "sxe2_ioctl_chnl.h"
#include "sxe2_queue.h"
#include "sxe2_tx.h"
#include "sxe2_rx.h"
#include "sxe2_cmd.h"
#include "sxe2_vsi.h"
#include "sxe2_log.h"
#include "sxe2_drv_cmd.h"
#include "sxe2_com_cdev.h"
#include "sxe2_linkchg.h"
#include "sxe2_com_l2_filter.h"
#include "sxe2_com_rss.h"
#include "sxe2_com_switchdev.h"
#include "sxe2_com_flow.h"
#include "sxe2_common.h"
#include "sxe2_sriov.h"
#include "sxe2_vsi.h"
#include "sxe2_eswitch.h"
#include "sxe2_rx.h"
#include "sxe2_tx.h"
#include "sxe2_com_stats.h"
#include "sxe2_acl.h"
#include "sxe2_com_ipsec.h"
#include "sxe2_com_vlan.h"
#include "sxe2_netdev.h"
#include "sxe2_ethtool.h"

STATIC s32 sxe2_com_handshake_disable(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				      struct sxe2_drv_cmd_params *cmd_buf)
{
	return 0;
}

STATIC void sxe2_txsch_cap_get(struct sxe2_adapter *adapter,
			       struct sxe2_drv_dev_caps_resp *resp)
{
	resp->txsch_caps.layer_cap = 4;
	resp->txsch_caps.prio_num = 8;
	resp->txsch_caps.tm_mid_node_num = 8;
}

STATIC s32 sxe2_com_cap_get(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			    struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_fwc_func_caps caps = {};
	struct sxe2_drv_dev_caps_resp *resp;
	s32 ret = 0;

	(void)memset(&caps, 0, sizeof(caps));

	resp = kmalloc(sizeof(*resp), GFP_KERNEL);
	if (!resp) {
		ret = -ENOMEM;
		goto l_end;
	}

	memset(resp, 0, sizeof(*resp));
	ret = sxe2_dpdk_pf_caps_get(adapter, &caps);
	if (ret) {
		LOG_ERROR_BDF("sxe2_dpdk_pf_caps_get failed\n");
		ret = -EINVAL;
		goto l_end;
	}

	resp->dev_type = SXE2_DEV_T_PF;

	resp->queue_caps.base_idx_in_pf = caps.tx_caps.base_idx;
	resp->queue_caps.queues_cnt = caps.tx_caps.cnt;

	resp->msix_caps.msix_vectors_cnt = caps.msix_caps.cnt;
	resp->msix_caps.base_idx_in_func = caps.msix_caps.base_idx;

	resp->vsi_caps.vsi_type = SXE2_VSI_T_DPDK_PF;
	resp->vsi_caps.kernel_vsi_id = adapter->vsi_ctxt.main_vsi->idx_in_dev;
	resp->vsi_caps.dpdk_vsi_id = 0xFFFF;
	resp->vsi_caps.func_id = adapter->pf_idx;

	resp->rss_hash_caps.hash_key_size = SXE2_RSS_HASH_KEY_SIZE;
	if (adapter->q_ctxt.rxq_layout.dpdk == SXE2_DPDK_QUEUE_DFLT_CNT)
		resp->rss_hash_caps.lut_key_size = SXE2_RSS_LUT_SIZE_512;
	else
		resp->rss_hash_caps.lut_key_size = adapter->caps_ctxt.max_rss_lut_size;

	resp->pf_idx = adapter->pf_idx;
	resp->port_idx = adapter->port_idx;

	resp->repr_caps.cnt_repr_vf = sxe2_vf_num_get(adapter);
	memset(resp->repr_caps.repr_vf_id, 0, sizeof(resp->repr_caps.repr_vf_id));
	sxe2_vfs_vsi_id_get(adapter, resp->repr_caps.repr_vf_id);

	sxe2_txsch_cap_get(adapter, resp);

	resp->cap_flags = SXE2_DEV_CAPS_OFFLOAD_L2 | SXE2_DEV_CAPS_OFFLOAD_VLAN |
			  SXE2_DEV_CAPS_OFFLOAD_RSS | SXE2_DEV_CAPS_OFFLOAD_FNAV |
			  SXE2_DEV_CAPS_OFFLOAD_TM | SXE2_DEV_CAPS_OFFLOAD_Q_MAP |
			  SXE2_DEV_CAPS_OFFLOAD_FC_STATE;
	if (adapter->ipsec_ctxt.max_tx_sa_cnt && adapter->ipsec_ctxt.max_rx_sa_cnt)
		resp->cap_flags |= SXE2_DEV_CAPS_OFFLOAD_IPSEC;

	if (sxe2_com_resp_copy_to_user(cmd_buf, resp, sizeof(*resp), obj) != 0) {
		ret = -EFAULT;
		goto l_end;
	}
	cmd_buf->resp_len = sizeof(*resp);

l_end:
	kfree(resp);
	return ret;
}

STATIC s32 sxe2_com_switchdev_info_get(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				       struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_switchdev_info *resp;
	s32 ret = 0;

	resp = kmalloc(sizeof(*resp), GFP_KERNEL);
	if (!resp) {
		ret = -ENOMEM;
		goto l_end;
	}
	memset(resp, 0, sizeof(*resp));
	if (sxe2_eswitch_is_offload(adapter) && sxe2_vf_is_exist(adapter)) {
		resp->is_switchdev = true;
		resp->port_name_type = SXE2_PHYS_PORT_NAME_TYPE_PFVF;
		resp->representor = 1;
		resp->master = 0;
	} else {
		resp->is_switchdev = false;
		resp->port_name_type = SXE2_PHYS_PORT_NAME_TYPE_LEGACY;
		resp->representor = 0;
		resp->master = 1;
	}

	LOG_DEBUG_BDF("adapter->eswitch_ctxt.mode = %d\n", adapter->eswitch_ctxt.mode);
	if (sxe2_com_resp_copy_to_user(cmd_buf, resp, sizeof(*resp), obj) != 0) {
		ret = -EFAULT;
		goto l_end;
	}
	cmd_buf->resp_len = sizeof(*resp);

l_end:
	kfree(resp);
	return ret;
}

STATIC s32 sxe2_com_main_vsi_create(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				    struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;
	struct sxe2_drv_vsi_create_req_resp *req_resp;
	struct sxe2_fwc_vsi_crud_resp fwc_resp;
	struct sxe2_vsi_cfg_params params = {0};

	req_resp = (struct sxe2_drv_vsi_create_req_resp *)
		    sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req_resp) {
		LOG_ERROR_BDF("vsi create req is NULL\n");
		ret = -EINVAL;
		goto l_end;
	}

	params.type = SXE2_VSI_T_DPDK_PF;
	ret = sxe2_dpdk_vsi_create(adapter, &params, &fwc_resp);
	if (ret) {
		LOG_ERROR_BDF("sxe2_dpdk_vsi_create failed, ret: %d\n", ret);
		ret = -EINVAL;
		goto l_end;
	}

	req_resp->vsi_id = fwc_resp.vsi_id;
	req_resp->vsi_type = SXE2_VSI_T_DPDK_PF;
	if (sxe2_com_resp_copy_to_user(cmd_buf, req_resp, sizeof(*req_resp), obj) != 0) {
		LOG_ERROR_BDF("resp_copy_to_user failed, len=%lu\n", sizeof(*req_resp));
		ret = -EFAULT;
		goto l_free_vsi;
	}

	cmd_buf->resp_len = sizeof(*req_resp);
	goto l_end;

l_free_vsi:
	params.vsi_id = req_resp->vsi_id;
	(void)sxe2_dpdk_vsi_destroy(adapter, &params);

l_end:
	kfree(req_resp);
	return ret;
}

static s32 sxe2_com_free_vsi(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			     struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_vsi_cfg_params params;
	struct sxe2_drv_vsi_free_req *req;
	s32 ret;

	req = (struct sxe2_drv_vsi_free_req *)sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("vsi free req is NULL\n");
		ret = -EINVAL;
		goto l_end;
	}
	params.vsi_id = req->vsi_id;
	ret = sxe2_dpdk_vsi_destroy(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("sxe2_dpdk_vsi_destroy failed, ret: %d\n", ret);
		ret = -EINVAL;
		goto l_end;
	}

l_end:
	kfree(req);
	return ret;
}

static s32 sxe2_com_vsi_fc_get(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			       struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_vsi_fc_get_req *req =
		(struct sxe2_drv_vsi_fc_get_req *)sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	struct sxe2_drv_vsi_fc_get_resp resp;
	s32 ret;

	req = (struct sxe2_drv_vsi_fc_get_req *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("vsi fc get req is NULL\n");
		ret = -EINVAL;
		goto l_end;
	}
	ret = sxe2_fc_get(adapter, req->vsi_id, &resp.fc_enable);
	if (ret) {
		LOG_ERROR_BDF("sxe2_fc_get failed, ret: %d\n", ret);
		ret = -EINVAL;
		goto l_end;
	}

	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%zu\n", sizeof(resp));
		ret = -EFAULT;
		goto l_end;
	}

	cmd_buf->resp_len = sizeof(resp);

l_end:
	kfree(req);
	return ret;
}

static s32 sxe2_com_vsi_info_get(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				 struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_vsi_info_get_req *req;
	struct sxe2_drv_vsi_info_get_resp resp;
	struct sxe2_fwc_func_caps caps;
	s32 ret;

	req = (struct sxe2_drv_vsi_info_get_req *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("vsi info get null\n");
		ret = -EINVAL;
		goto l_end;
	}
	ret = sxe2_user_vsi_info_get(adapter, req->vsi_id, &caps);
	if (ret) {
		LOG_ERROR_BDF("vsi info get failed, ret: %d\n", ret);
		ret = -EINVAL;
		goto l_end;
	}

	resp.used_queues.base_idx_in_pf = caps.tx_caps.base_idx;
	resp.used_queues.queues_cnt = caps.tx_caps.cnt;
	resp.used_msix.msix_vectors_cnt = caps.msix_caps.cnt;
	resp.used_msix.base_idx_in_func = caps.msix_caps.base_idx;

	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%zu\n", sizeof(resp));
		ret = -EFAULT;
		goto l_end;
	}

	cmd_buf->resp_len = sizeof(resp);
l_end:
	kfree(req);
	return ret;
}

static s32 sxe2_com_rxq_cfg_enable(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				   struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_rxq_cfg_req *req;
	struct sxe2_rxq_cfg_params *rxq_params = NULL;
	s32 ret;
	u32 len;
	u16 q_idx;

	req = (struct sxe2_drv_rxq_cfg_req *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("rxq cfg req is NULL\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (req->q_cnt == 0) {
		LOG_ERROR_BDF("dpdk rxq q_cnt is 0\n");
		ret = -EINVAL;
		goto l_end;
	}

	len = sizeof(*rxq_params) + sizeof(struct sxe2_ctxt_elem) * req->q_cnt;
	rxq_params = kzalloc(len, GFP_KERNEL);
	if (!rxq_params) {
		ret = -SXE2_VF_ERR_NO_MEMORY;
		LOG_ERROR_BDF("rxq msg mem %uB alloc failed.\n", len);
		goto l_end;
	}
	rxq_params->q_cnt = req->q_cnt;
	rxq_params->vsi_id = req->vsi_id;
	rxq_params->max_frame_size = req->max_frame_size;
	for (q_idx = 0; q_idx < req->q_cnt; q_idx++) {
		rxq_params->cfg[q_idx].dma_addr = req->cfg[q_idx].dma_addr;
		rxq_params->cfg[q_idx].max_lro_size = req->cfg[q_idx].max_lro_size;
		rxq_params->cfg[q_idx].split_type_mask = req->cfg[q_idx].split_type_mask;
		rxq_params->cfg[q_idx].hdr_len = req->cfg[q_idx].hdr_len;
		rxq_params->cfg[q_idx].queue_id = req->cfg[q_idx].queue_id;
		rxq_params->cfg[q_idx].depth = req->cfg[q_idx].depth;
		rxq_params->cfg[q_idx].buf_len = req->cfg[q_idx].buf_len;
		rxq_params->cfg[q_idx].lro_en = req->cfg[q_idx].lro_en;
		rxq_params->cfg[q_idx].keep_crc_en = req->cfg[q_idx].keep_crc_en;
		rxq_params->cfg[q_idx].split_en = req->cfg[q_idx].split_en;
		rxq_params->cfg[q_idx].desc_size = req->cfg[q_idx].desc_size;
	}

	ret = sxe2_rxq_cfg_ena_common_handle(adapter, rxq_params);
	if (ret) {
		LOG_ERROR_BDF("sxe2_rxq_cfg_ena_common_handle failed, ret: %d\n", ret);
		ret = -EINVAL;
		goto l_end;
	}

l_end:
	kfree(rxq_params);
	kfree(req);
	return ret;
}

static s32 sxe2_com_rxq_cfg_disable(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				    struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_q_switch_req *req;
	struct sxe2_rxq_dis_params params;
	s32 ret;

	req = (struct sxe2_drv_q_switch_req *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("rxq switch req is NULL\n");
		ret = -EINVAL;
		goto l_end;
	}

	params.q_idx = req->q_idx;
	params.vsi_id = req->vsi_id;
	ret = sxe2_rxq_disable_common_handle(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("sxe2_rxq_disable_common_handle failed, ret: %d\n", ret);
		ret = -EINVAL;
		goto l_end;
	}

l_end:
	kfree(req);
	return ret;
}

static s32 sxe2_com_txq_cfg_disable(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				    struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_q_switch_req *req;
	struct sxe2_txq_ucmd_dis_params txq_params;
	s32 ret;

	req = (struct sxe2_drv_q_switch_req *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("usr txq cfg req=NULL\n");
		ret = -EINVAL;
		goto l_end;
	}

	txq_params.q_idx = req->q_idx;
	txq_params.vsi_id = req->vsi_id;
	txq_params.sched_mode = req->sched_mode;
	ret = sxe2_txq_dis_common_handle(adapter, &txq_params);
	if (ret) {
		LOG_ERROR_BDF("usr vsi[%d] txq[%d] dis failed\n", txq_params.vsi_id,
			      txq_params.q_idx);
	} else {
		LOG_INFO_BDF("usr vsi[%d] txq[%d] dis success\n", txq_params.vsi_id,
			     txq_params.q_idx);
	}

l_end:
	kfree(req);
	return ret;
}

static s32 sxe2_com_txq_cfg_enable(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				   struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret;
	u32 i, len;
	struct sxe2_drv_txq_ctxt *ctxt;
	struct sxe2_drv_txq_cfg_req *req;
	struct sxe2_txq_ucmd_en_params *txq_params;

	req = (struct sxe2_drv_txq_cfg_req *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("usr txq cfg req is NULL\n");
		ret = -EINVAL;
		goto l_end;
	}

	len = sizeof(*txq_params) + sizeof(*ctxt) * req->q_cnt;
	txq_params = kzalloc(len, GFP_KERNEL);
	if (!txq_params) {
		LOG_ERROR_BDF("txq msg mem %u alloc failed.\n", len);
		ret = -ENOMEM;
		goto l_end;
	}

	txq_params->q_cnt = req->q_cnt;
	txq_params->vsi_idx = req->vsi_id;
	for (i = 0; i < txq_params->q_cnt; i++) {
		ctxt = &req->cfg[i];
		txq_params->ctxts[i].depth = ctxt->depth;
		txq_params->ctxts[i].dma_addr = ctxt->dma_addr;
		txq_params->ctxts[i].queue_id = ctxt->queue_id;
		txq_params->ctxts[i].sched_mode = ctxt->sched_mode;
	}
	ret = sxe2_txq_cfg_ena_common_handle(adapter, txq_params);
	if (ret) {
		LOG_ERROR_BDF("usr vsi[%d] txq[%d] num[%u] cfg failed\n",
			      txq_params->vsi_idx, txq_params->ctxts[0].queue_id,
			      txq_params->q_cnt);
	} else {
		LOG_INFO_BDF("usr vsi[%d] txq[%d] num[%u] cfg success\n",
			     txq_params->vsi_idx, txq_params->ctxts[0].queue_id,
			     txq_params->q_cnt);
	}

	kfree(txq_params);
l_end:
	kfree(req);
	return ret;
}

STATIC bool sxe2_com_txq_mapping_check(struct sxe2_adapter *adapter, u16 hw_queue_id,
				       u8 *map_pool_idx, u8 *queues_idx)
{
	struct sxe2_stats_map *stats_map = (struct sxe2_stats_map *)&adapter->stats_map;
	struct sxe2_stats_txq_map *stats_txq_map = &stats_map->txq_map;
	struct sxe2_stats_txq_map_pool *map_pool;
	bool is_config = false;
	u8 i;
	u8 j;

	for (i = 0; i < SXE2_TXQ_STATS_MAP_MAX_NUM; i++) {
		map_pool = &stats_txq_map->txq_map_pool[i];
		for (j = 0; j < SXE2_TXQ_STATS_MAP_MAX_NUM; j++) {
			if (map_pool->queue_id_pool[j] == hw_queue_id) {
				is_config = true;
				goto l_end;
			}
		}
	}

l_end:
	if (is_config) {
		if (map_pool_idx)
			*map_pool_idx = i;

		if (queues_idx)
			*queues_idx = j;
	}

	return is_config;
}

STATIC s32 sxe2_com_cmd_txq_stat_map_set(struct sxe2_adapter *adapter, u16 hw_queue_id)
{
	struct sxe2_stats_map *stats_map = &adapter->stats_map;
	struct sxe2_stats_txq_map *stats_txq_map = &stats_map->txq_map;
	struct sxe2_cmd_params cmd   = { 0 };
	struct sxe2_fwc_txq_stats_map_pool_get_resp get_resp = { 0 };
	struct sxe2_fwc_txq_stats_map_pool_set_req set_req = { 0 };
	s32 ret = 0;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TXQUEUE_STATS_MAP_POOL_GET, NULL, 0,
				  &get_resp, sizeof(get_resp));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("fail to get txqueue stats mapping, ret=%d\n", ret);
		goto l_end;
	}

	stats_txq_map->hw_txq_map.hw_txq_map_pool[get_resp.hw_index].txq_id = hw_queue_id;

	stats_txq_map->hw_txq_map.curr_map_idx++;

	set_req.cfg_info = cpu_to_le16(hw_queue_id);
	set_req.hw_index = get_resp.hw_index;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TXQUEUE_STATS_MAP_POOL_SET, &set_req,
				  sizeof(set_req), NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("fail to set txqueue stats mapping, ret=%d\n", ret);
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_com_rx_map_info_get(struct sxe2_adapter *adapter, u8 pool_idx,
				    struct sxe2_rxq_map_info *rxq_stats_map_info)
{
	struct sxe2_stats_map *stats_map = &adapter->stats_map;
	struct sxe2_stats_rxq_map *stats_rxq_map = &stats_map->rxq_map;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_fwc_rxq_stats_map_get_info_resp resp = {0};
	struct sxe2_fwc_rxq_stats_map_get_info_req req = {0};
	u8 curr_map_idx;
	s32 ret = 0;

	if (pool_idx >= SXE2_RXQ_STATS_MAP_MAX_NUM) {
		LOG_ERROR_BDF("RX Invalid pool ID[%u]:exceeds supported range.\n", pool_idx);
		ret = -EFAULT;
		goto l_end;
	}

	curr_map_idx = stats_rxq_map->rxq_map_pool[pool_idx].curr_map_idx;
	if (curr_map_idx == 0) {
		LOG_ERROR_BDF("The current mapping pool has not been configured.\n");
		ret = -EFAULT;
		goto l_end;
	}

	req.hw_pool_idx = stats_rxq_map->rxq_map_pool[pool_idx].pool_id;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RXQUEUE_STATS_MAP_INFO_GET, &req,
				  sizeof(req), &resp, sizeof(resp));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("fail to get rxqueue stats mapping, ret=%d\n", ret);
		goto l_end;
	}

	rxq_stats_map_info->rxq_fd_in_pkt_cnt = cpu_to_le64(resp.rxq_fd_in_pkt_cnt);
	rxq_stats_map_info->rxq_lan_in_byte_cnt = cpu_to_le64(resp.rxq_lan_in_byte_cnt);
	rxq_stats_map_info->rxq_lan_in_pkt_cnt = cpu_to_le64(resp.rxq_lan_in_pkt_cnt);
	rxq_stats_map_info->rxq_mng_in_byte_cnt = cpu_to_le64(resp.rxq_mng_in_byte_cnt);
	rxq_stats_map_info->rxq_mng_in_pkt_cnt = cpu_to_le64(resp.rxq_mng_in_pkt_cnt);
	rxq_stats_map_info->rxq_mng_out_pkt_cnt = cpu_to_le64(resp.rxq_mng_out_pkt_cnt);

l_end:
	return ret;
}

STATIC s32 sxe2_com_tx_map_info_get(struct sxe2_adapter *adapter, u8 index,
				    struct sxe2_txq_map_info *txq_stats_map_info)
{
	struct sxe2_stats_map *stats_map = &adapter->stats_map;
	struct sxe2_stats_txq_map *stats_txq_map = &stats_map->txq_map;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_fwc_txq_stats_map_get_info_resp resp = {0};
	struct sxe2_fwc_txq_stats_map_get_info_req req = {0};
	struct sxe2_txq_map_info stats_map_info = {0};
	u8 curr_map_idx;
	u8 i;
	u8 j;
	u16 hw_queue_id;
	s32 ret = 0;

	if (index >= SXE2_TXQ_STATS_MAP_MAX_NUM) {
		LOG_ERROR_BDF("TX Invalid pool ID[%u]:exceeds supported range.\n", index);
		ret = -EFAULT;
		goto l_end;
	}

	curr_map_idx = stats_txq_map->txq_map_pool[index].curr_map_idx;
	if (curr_map_idx == 0) {
		LOG_ERROR_BDF("The current mapping pool has not been configured.\n");
		ret = -EFAULT;
		goto l_end;
	}

	for (i = 0; i < curr_map_idx; i++) {
		hw_queue_id = stats_txq_map->txq_map_pool[index].queue_id_pool[i];

		for (j = 0; j < SXE2_TXQ_STATS_MAP_MAX_NUM; j++) {
			if (stats_txq_map->hw_txq_map.hw_txq_map_pool[j].txq_id ==
			    hw_queue_id) {
				break;
			}
		}

		if (j >= SXE2_TXQ_STATS_MAP_MAX_NUM) {
			LOG_ERROR_BDF("get tx map stats info fail!\n");
			ret = -EFAULT;
			goto l_end;
		}

		req.hw_index = j;
		sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TXQUEUE_STATS_MAP_INFO_GET, &req,
					  sizeof(req), &resp, sizeof(resp));
		ret = sxe2_cmd_fw_exec(adapter, &cmd);
		if (ret) {
			LOG_ERROR_BDF("fail to get txqueue stats mapping, ret=%d\n", ret);
			goto l_end;
		}

		stats_map_info.txq_lan_byte_cnt += cpu_to_le64(resp.txq_lan_byte_cnt);
		stats_map_info.txq_lan_pkt_cnt += cpu_to_le64(resp.txq_lan_pkt_cnt);
	}

	txq_stats_map_info->txq_lan_byte_cnt = stats_map_info.txq_lan_byte_cnt;
	txq_stats_map_info->txq_lan_pkt_cnt = stats_map_info.txq_lan_pkt_cnt;

l_end:
	return ret;
}

STATIC s32 sxe2_com_tx_rx_queue_info_get(struct sxe2_adapter *adapter,
					 struct sxe2_obj *obj,
					 struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_stats_map *stats_map = &adapter->stats_map;
	struct sxe2_stats_rxq_map *stats_rxq_map = &stats_map->rxq_map;
	struct sxe2_stats_txq_map *stats_txq_map = &stats_map->txq_map;
	struct sxe2_rxq_map_info *rxq_info = stats_map->q_info.rxq_stats_map_info;
	struct sxe2_txq_map_info *txq_info = stats_map->q_info.txq_stats_map_info;
	u8 pool_idx;
	u8 index;
	u8 curr_map_idx;
	s32 ret = 0;

	for (pool_idx = 0; pool_idx < SXE2_RXQ_STATS_MAP_MAX_NUM; pool_idx++) {
		curr_map_idx = stats_rxq_map->rxq_map_pool[pool_idx].curr_map_idx;
		if (curr_map_idx == 0)
			continue;

		ret = sxe2_com_rx_map_info_get(adapter, pool_idx, &rxq_info[pool_idx]);
		if (ret)
			goto l_end;
	}

	for (index = 0; index < SXE2_TXQ_STATS_MAP_MAX_NUM; index++) {
		curr_map_idx = stats_txq_map->txq_map_pool[index].curr_map_idx;
		if (curr_map_idx == 0)
			continue;

		ret = sxe2_com_tx_map_info_get(adapter, index, &txq_info[index]);
		if (ret)
			goto l_end;
	}

	if (sxe2_com_resp_copy_to_user(cmd_buf, &stats_map->q_info,
				       sizeof(stats_map->q_info), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%lu, resp_len=%d\n",
			      sizeof(stats_map->q_info), cmd_buf->resp_len);
		ret = -EFAULT;
		goto l_end;
	}
	cmd_buf->resp_len = sizeof(stats_map->q_info);
l_end:
	return ret;
}

s32 sxe2_dpdk_q_map_resource_release(struct sxe2_adapter *adapter, struct sxe2_obj *obj)
{
	struct sxe2_cmd_params cmd = { 0 };
	s32 ret = 0;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RXQUEUE_STATS_MAP_RES_REL, NULL, 0, NULL,
				  0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("RxQueue stats mapping config release fail.");
		goto l_end;
	}

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TXQUEUE_STATS_MAP_RES_REL, NULL, 0, NULL,
				  0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("TxQueue stats mapping config release fail. ");
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_com_tx_rx_map_reset(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				    struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_stats_map *stats_map = &adapter->stats_map;
	struct sxe2_stats_txq_map *stats_txq_map = &stats_map->txq_map;
	struct sxe2_stats_rxq_map *stats_rxq_map = &stats_map->rxq_map;
	struct sxe2_stats_hw_txq_map *hw_txq_map;
	struct sxe2_stats_txq_map_pool *tx_map_pool;
	struct sxe2_stats_rxq_map_pool *rx_map_pool;
	struct sxe2_cmd_params cmd = { 0 };
	u32 i;
	u32 j;
	s32 ret = 0;

	memset(stats_map, 0, sizeof(*stats_map));

	for (i = 0; i < SXE2_TXQ_STATS_MAP_MAX_NUM; i++) {
		tx_map_pool = &stats_txq_map->txq_map_pool[i];
		for (j = 0; j < SXE2_TXQ_STATS_MAP_MAX_NUM; j++)
			tx_map_pool->queue_id_pool[j] = SXE2_STAT_MAP_INVALID_QID;
	}

	hw_txq_map = &stats_txq_map->hw_txq_map;
	for (i = 0; i < SXE2_TXQ_STATS_MAP_MAX_NUM; i++)
		hw_txq_map->hw_txq_map_pool[i].txq_id = SXE2_STAT_MAP_INVALID_QID;

	for (i = 0; i < SXE2_RXQ_STATS_MAP_MAX_NUM; i++) {
		rx_map_pool = &stats_rxq_map->rxq_map_pool[i];
		for (j = 0; j < SXE2_RXQ_MAP_Q_MAX_NUM; j++)
			rx_map_pool->queue_id_pool[j] = SXE2_STAT_MAP_INVALID_QID;
	}

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RXQUEUE_STATS_MAP_RES_REL, NULL, 0, NULL,
				  0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("Queue stats mapping config release fail. ");
		goto l_end;
	}

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TXQUEUE_STATS_MAP_RES_REL, NULL, 0, NULL,
				  0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("Queue stats mapping config release fail. ");
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_com_queue_map_info_clear(struct sxe2_adapter *adapter,
					 struct sxe2_obj *obj,
					 struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_stats_map *stats_map = &adapter->stats_map;
	struct sxe2_stats_txq_map *stats_txq_map = &stats_map->txq_map;
	struct sxe2_stats_rxq_map *stats_rxq_map = &stats_map->rxq_map;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_fwc_rxq_stats_map_info_clear_req rx_req = { 0 };
	struct sxe2_fwc_txq_stats_map_info_clear_req tx_req = { 0 };
	struct sxe2_rxq_map_info *rxq_info = stats_map->q_info.rxq_stats_map_info;
	struct sxe2_txq_map_info *txq_info = stats_map->q_info.txq_stats_map_info;
	u8 curr_map_idx;
	u8 i;
	s32 ret = 0;

	rxq_info->rxq_lan_in_byte_cnt = 0;
	rxq_info->rxq_lan_in_pkt_cnt = 0;
	txq_info->txq_lan_byte_cnt = 0;
	txq_info->txq_lan_pkt_cnt = 0;

	for (i = 0; i < SXE2_TXQ_STATS_MAP_MAX_NUM; i++) {
		if (stats_txq_map->hw_txq_map.hw_txq_map_pool[i].txq_id
				== SXE2_STAT_MAP_INVALID_QID)
			continue;

		tx_req.hw_index = i;
		sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TXQUEUE_STATS_MAP_INFO_CLEAR,
					  &tx_req, sizeof(tx_req), NULL, 0);
		ret = sxe2_cmd_fw_exec(adapter, &cmd);
		if (ret) {
			LOG_ERROR_BDF("fail to clr txqueue stats mapping, ret=%d\n", ret);
			goto l_end;
		}
	}

	for (i = 0; i < SXE2_RXQ_STATS_MAP_MAX_NUM; i++) {
		curr_map_idx = stats_rxq_map->rxq_map_pool[i].curr_map_idx;
		if (curr_map_idx == 0)
			continue;

		rx_req.hw_pool_idx = stats_rxq_map->rxq_map_pool[i].pool_id;
		sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RXQUEUE_STATS_MAP_INFO_CLEAR,
					  &rx_req, sizeof(rx_req), NULL, 0);
		ret = sxe2_cmd_fw_exec(adapter, &cmd);
		if (ret) {
			LOG_ERROR_BDF("fail to clr rxqueue stats mapping, ret=%d\n", ret);
			goto l_end;
		}
	}

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RXLAN_QUEUE_STATS_MAP_INFO_CLEAR, NULL,
				  0, NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("fail to clr rxlan stats mapping, ret=%d\n", ret);
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_com_txq_mapping_set(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				    struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_tx_map_req *req;
	struct sxe2_stats_map *stats_map = (struct sxe2_stats_map *)&adapter->stats_map;
	struct sxe2_stats_txq_map *stats_txq_map = &stats_map->txq_map;
	struct sxe2_stats_txq_map_pool *map_pool;
	bool is_config;
	u8 map_pool_idx;
	u8 queues_idx;
	s32 ret = 0;
	struct sxe2_q_id_transe params = {0};

	req = (struct sxe2_drv_tx_map_req *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req));
		ret = -EFAULT;
		goto l_end;
	}

	params.q_id = req->queue_id;
	params.is_tx = true;
	params.vsi_id = cmd_buf->vsi_id;
	ret = sxe2_dpdk_abs_qid_get(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("get hw_queue_id failed.\n");
		goto l_end;
	}

	LOG_DEBUG_BDF("dpdk q_id:%u params.q_id_in_dev:%u\n", req->queue_id,
		      params.q_id_in_dev);
	if (req->pool_idx >= SXE2_TXQ_STATS_MAP_MAX_NUM) {
		LOG_ERROR_BDF("Txq mapping: pool_idx supports up to %u, but %u was provided.\n",
			      SXE2_TXQ_STATS_MAP_MAX_NUM - 1, req->pool_idx);
		ret = -EFAULT;
		goto l_end;
	}

	is_config = sxe2_com_txq_mapping_check(adapter, params.q_id_in_dev, &map_pool_idx,
					       &queues_idx);
	if (is_config) {
		if (map_pool_idx == req->pool_idx) {
			LOG_ERROR_BDF("pool_idx%u: queue_id = %u already exist.\n",
				      req->pool_idx, params.q_id_in_dev);
			ret = -EFAULT;
			goto l_end;
		}
	} else {
		if (stats_txq_map->hw_txq_map.curr_map_idx >= SXE2_TXQ_STATS_MAP_MAX_NUM) {
			LOG_ERROR_BDF("Mapping failed:exceeds the limit of %u.\n",
				      SXE2_TXQ_STATS_MAP_MAX_NUM);
			ret = -EFAULT;
			goto l_end;
		}

		ret = sxe2_com_cmd_txq_stat_map_set(adapter, params.q_id_in_dev);
		if (ret)
			goto l_end;
	}

	map_pool = &stats_txq_map->txq_map_pool[req->pool_idx];
	map_pool->queue_id_pool[map_pool->curr_map_idx++] = params.q_id_in_dev;

	LOG_DEBUG_BDF("CREATE:TX pool [%u] cfg: %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n",
		      req->pool_idx,
		      map_pool->queue_id_pool[0], map_pool->queue_id_pool[1],
		      map_pool->queue_id_pool[2], map_pool->queue_id_pool[3],
		      map_pool->queue_id_pool[4], map_pool->queue_id_pool[5],
		      map_pool->queue_id_pool[6], map_pool->queue_id_pool[7],
		      map_pool->queue_id_pool[8], map_pool->queue_id_pool[9],
		      map_pool->queue_id_pool[10], map_pool->queue_id_pool[11],
		      map_pool->queue_id_pool[12], map_pool->queue_id_pool[13],
		      map_pool->queue_id_pool[14], map_pool->queue_id_pool[15]);

l_end:
	kfree(req);
	return ret;
}

STATIC s32 sxe2_com_rxq_mapping_set(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				    struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_rx_map_req *req;
	struct sxe2_stats_map *stats_map = &adapter->stats_map;
	struct sxe2_stats_rxq_map *stats_rxq_map = &stats_map->rxq_map;
	struct sxe2_stats_rxq_map_pool *map_pool;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_fwc_rxq_stats_map_pool_get_resp get_resp = { 0 };
	struct sxe2_fwc_rxq_stats_map_pool_set_req set_req = { 0 };
	u16 last_q_id;
	s32 ret = 0;
	u32 qid_cfg;
	struct sxe2_q_id_transe params = {0};

	req = (struct sxe2_drv_rx_map_req *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("copy_to_user failed, len=%lu\n", sizeof(*req));
		ret = -EFAULT;
		goto l_end;
	}

	params.q_id = req->queue_id;
	params.is_tx = false;
	params.vsi_id = cmd_buf->vsi_id;
	ret = sxe2_dpdk_abs_qid_get(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("get hw_queue_id failed.\n");
		goto l_end;
	}

	LOG_DEBUG_BDF("dpdk q_id:%u params.q_id_in_dev:%u\n", req->queue_id, params.q_id_in_dev);
	if (req->pool_idx >= SXE2_RXQ_STATS_MAP_MAX_NUM) {
		LOG_ERROR_BDF("Rxq mapping: supports up to %u, but %u was provided.\n",
			      SXE2_RXQ_STATS_MAP_MAX_NUM - 1, req->pool_idx);
		ret = -EFAULT;
		goto l_end;
	}

	map_pool = &stats_rxq_map->rxq_map_pool[req->pool_idx];
	if (map_pool->curr_map_idx == 0) {
		sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RXQUEUE_STATS_MAP_POOL_GET, NULL,
					  0, &get_resp, sizeof(get_resp));
		ret = sxe2_cmd_fw_exec(adapter, &cmd);
		if (ret) {
			LOG_ERROR_BDF("failed to get rxq stats map pool, ret=%d\n", ret);
			goto l_end;
		}

		map_pool->pool_id = get_resp.hw_pool_idx;

	} else {
		last_q_id = map_pool->queue_id_pool[map_pool->curr_map_idx - 1];
		if (last_q_id + 1 != params.q_id_in_dev) {
			LOG_ERROR_BDF("Mapping failed: the rxq:%u qmapping[%u] contiguous.\n",
				      params.q_id_in_dev, req->pool_idx);
			ret = -EFAULT;
			goto l_end;
		}

		if (map_pool->curr_map_idx >= SXE2_RXQ_MAP_Q_MAX_NUM) {
			LOG_ERROR_BDF("mapping config limit reached, max:%d\n",
				      SXE2_RXQ_MAP_Q_MAX_NUM);
			ret = -EFAULT;
			goto l_end;
		}
	}

	map_pool->queue_id_pool[map_pool->curr_map_idx++] = params.q_id_in_dev;

	qid_cfg = ((map_pool->queue_id_pool[map_pool->curr_map_idx - 1] & 0x7FF) << 11) |
		  (map_pool->queue_id_pool[0] & 0x7FF);

	set_req.cfg_info = cpu_to_le32(qid_cfg);
	set_req.hw_pool_idx = map_pool->pool_id;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RXQUEUE_STATS_MAP_POOL_SET, &set_req,
				  sizeof(set_req), NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to set rxq stats map pool, ret=%d\n", ret);
		goto l_end;
	}

	LOG_DEBUG_BDF("CREATE:RX mapping pool [%u] configured qrange: %u ~ %u\n",
		      req->pool_idx,
		      map_pool->queue_id_pool[0],
		      map_pool->queue_id_pool[map_pool->curr_map_idx - 1]);
l_end:
	kfree(req);
	return ret;
}

static s32 sxe2_user_mac_addr_get(struct sxe2_vsi *vsi, u16 vf_idx,
				  struct sxe2_drv_dev_info_resp *resp)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_vf_node *vf = NULL;
	enum sxe2_vsi_type type;
	s32 ret = 0;

	if (!vsi || !resp)
		return -EINVAL;

	type = vsi->type;
	switch (type) {
	case SXE2_VSI_T_DPDK_PF:
		memcpy(resp->mac_addr, adapter->hw.mac_info.perm_addr, ETH_ALEN);
		break;
	case SXE2_VSI_T_DPDK_VF:
		vf = vsi->vf_node;
		if (!vf) {
			LOG_ERROR_BDF("vf not found, vsi_id=%u\n", vsi->idx_in_dev);
			ret = -EINVAL;
			goto l_end;
		}

		ret = sxe2_check_vf_ready_for_cfg(vf);
		if (ret)
			LOG_ERROR_BDF("VF %u not ready for mac cfg.\n", vf->vf_idx);
		else
			memcpy(resp->mac_addr, vf->mac_addr.addr, ETH_ALEN);
		break;
	default:
		LOG_ERROR_BDF("vsi type %u not supported\n", type);
		ret = -EINVAL;
		break;
	}

l_end:
	return ret;
}

static s32 sxe2_user_repr_mac_addr_get(struct sxe2_adapter *adapter, u16 vf_idx,
				       struct sxe2_drv_dev_info_resp *resp)
{
	struct sxe2_vf_node *vf = NULL;
	s32 ret = 0;

	if (!resp)
		return -EINVAL;

	mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));

	vf = sxe2_vf_node_get(adapter, vf_idx);
	if (!vf) {
		LOG_ERROR_BDF("vf not found, vf_idx=%u\n", vf_idx);
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2_check_vf_ready_for_cfg(vf);
	if (ret)
		LOG_ERROR_BDF("VF %u not ready for mac cfg.\n", vf_idx);
	else
		memcpy(resp->mac_addr, vf->mac_addr.addr, ETH_ALEN);

	mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));

l_end:
	return ret;
}

STATIC s32 sxe2_com_info_get(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			     struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_dev_info_resp resp;
	struct pci_dev *pdev = adapter->pdev;
	struct sxe2_vsi *vsi = NULL;
	u64 dsn = 0;
	s32 ret = 0;
	u32 dsn_low, dsn_high;
	u16 pos;

	memset(&resp, 0, sizeof(resp));
	if (obj->func_type == SXE2_PF && cmd_buf->repr_id < SXE2_VF_NUM) {
		ret = sxe2_user_repr_mac_addr_get(adapter, cmd_buf->repr_id, &resp);
		if (ret) {
			LOG_ERROR_BDF("get user mac addr failed, ret=%d\n", ret);
			goto l_end;
		}
	} else {
		mutex_lock(&adapter->vsi_ctxt.lock);
		vsi = sxe2_vsi_get_by_idx(adapter, cmd_buf->vsi_id);
		if (!vsi) {
			mutex_unlock(&adapter->vsi_ctxt.lock);
			LOG_ERROR_BDF("get vsi:%d failed.\n", cmd_buf->vsi_id);
			ret = -EIO;
			goto l_end;
		}
		ret = sxe2_user_mac_addr_get(vsi, cmd_buf->repr_id, &resp);
		mutex_unlock(&adapter->vsi_ctxt.lock);
		if (ret) {
			LOG_ERROR_BDF("get user mac addr failed, ret=%d\n", ret);
			goto l_end;
		}
	}
	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_DSN);
	if (!pos) {
		LOG_WARN_BDF("Failed to find device serial number capability\n");
	} else {
		pci_read_config_dword(pdev, pos + 4, &dsn_low);
		pci_read_config_dword(pdev, pos + 8, &dsn_high);
		dsn = ((u64)dsn_high << 22) | dsn_low;
	}
	resp.dsn = dsn;

	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%zu\n", sizeof(resp));
		ret = -EFAULT;
		goto l_end;
	}
	cmd_buf->resp_len = sizeof(resp);

l_end:
	return ret;
}

STATIC s32 sxe2_com_fw_info_get(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_fw_ver_msg *fw_ver = &adapter->hw.fw_ver;
	struct sxe2_drv_dev_fw_info_resp resp;
	s32 ret = 0;

	memset(&resp, 0, sizeof(resp));

	resp.main_version_id = fw_ver->main_version_id;
	resp.sub_version_id = fw_ver->sub_version_id;
	resp.fix_version_id = fw_ver->fix_version_id;
	resp.build_id = fw_ver->build_id;

	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%lu\n",
			      sizeof(struct sxe2_drv_dev_info_resp));
		ret = -EFAULT;
	}
	cmd_buf->resp_len = sizeof(resp);

	return ret;
}

STATIC s32 sxe2_com_link_info_get(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				  struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_link_info_resp resp;
	s32 ret = 0;

	memset(&resp, 0, sizeof(resp));
	sxe2_link_get_info_config(adapter, &resp.status, &resp.speed);

	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%lu\n",
			      sizeof(struct sxe2_drv_dev_info_resp));
		ret = -EFAULT;
	}
	cmd_buf->resp_len = sizeof(resp);

	return ret;
}

STATIC s32 sxe2_com_sched_root_tree_alloc(struct sxe2_adapter *adapter,
					  struct sxe2_obj *obj,
					  struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret;
	struct sxe2_vsi *usr_vsi;
	struct sxe2_tm_res tm_res = {0};

	mutex_lock(&adapter->vsi_ctxt.lock);
	usr_vsi = sxe2_vsi_get_by_idx(adapter, cmd_buf->vsi_id);
	if (!usr_vsi) {
		mutex_unlock(&adapter->vsi_ctxt.lock);
		LOG_ERROR_BDF("sxe2_vsi_get_with_id failed.\n");
		ret = -EIO;
		goto l_end;
	}

	ret = sxe2_txsch_ucmd_root_vsi_cfg(usr_vsi, &tm_res.teid);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	if (ret) {
		LOG_ERROR_BDF("sxe2_txsch_ucmd_dflt_vsi_topo_cfg failed.\n");
		goto l_end;
	}

	if (sxe2_com_resp_copy_to_user(cmd_buf, &tm_res, sizeof(tm_res), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%lu\n", sizeof(tm_res));
		ret = -EFAULT;
		goto l_end;
	}

	cmd_buf->resp_len = sizeof(tm_res);

l_end:
	return ret;
}

STATIC s32 sxe2_com_sched_root_tree_release(struct sxe2_adapter *adapter,
					    struct sxe2_obj *obj,
					    struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret;
	struct sxe2_tm_res *tm_res;

	tm_res = (struct sxe2_tm_res *)
		  sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!tm_res) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(tm_res));
		ret = -EFAULT;
		goto l_end;
	}
	mutex_lock(&adapter->vsi_ctxt.lock);
	ret = sxe2_txsch_ucmd_subtree_del(adapter, cmd_buf->vsi_id, tm_res->teid, true);
	mutex_unlock(&adapter->vsi_ctxt.lock);

	if (ret) {
		LOG_ERROR_BDF("sxe2_txsch_ucmd_subtree_del failed.\n");
		ret = -EIO;
		goto l_end;
	}

l_end:
	kfree(tm_res);
	return ret;
}

STATIC s32 sxe2_com_sched_root_children_del(struct sxe2_adapter *adapter,
					    struct sxe2_obj *obj,
					    struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret;
	struct sxe2_tm_res *tm_res;

	tm_res = (struct sxe2_tm_res *)sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!tm_res) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(tm_res));
		ret = -EFAULT;
		goto l_end;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	ret = sxe2_txsch_ucmd_subtree_del(adapter, cmd_buf->vsi_id, tm_res->teid, false);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	if (ret) {
		LOG_ERROR_BDF("sxe2_txsch_ucmd_subtree_del failed.\n");
		goto l_end;
	}

l_end:
	kfree(tm_res);
	return ret;
}

STATIC s32 sxe2_com_sched_tm_mid_add(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				     struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret;
	struct sxe2_tm_res tm_res;
	struct sxe2_vsi *usr_vsi;
	struct sxe2_txsched_ucmd_node_params ucmd_node_param;
	struct sxe2_tm_add_mid_msg  *msg;

	msg = (struct sxe2_tm_add_mid_msg *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!msg) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*msg));
		ret = -EFAULT;
		goto l_end;
	}

	ucmd_node_param.parent_teid = msg->parent_teid;
	ucmd_node_param.adj_lvl = msg->adj_lvl;
	ucmd_node_param.peak = msg->info.peak;
	ucmd_node_param.committed = msg->info.committed;
	ucmd_node_param.priority = msg->info.priority;
	ucmd_node_param.weight = msg->info.weight;

	mutex_lock(&adapter->vsi_ctxt.lock);
	usr_vsi = sxe2_vsi_get_by_idx(adapter, cmd_buf->vsi_id);
	if (!usr_vsi) {
		mutex_unlock(&adapter->vsi_ctxt.lock);
		LOG_ERROR_BDF("sxe2_vsi_get_by_idx failed.\n");
		ret = -EIO;
		goto l_end;
	}

	ret = sxe2_txsched_ucmd_node_add(usr_vsi, &ucmd_node_param);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	if (ret) {
		LOG_ERROR_BDF("sxe2_txsched_ucmd_node_add failed.\n");
		ret = -EIO;
		return ret;
	}

	tm_res.teid = ucmd_node_param.node_teid;

	if (sxe2_com_resp_copy_to_user(cmd_buf, &tm_res, sizeof(tm_res), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%lu\n", sizeof(tm_res));
		ret = -EFAULT;
		goto l_end;
	}
	cmd_buf->resp_len = sizeof(tm_res);

l_end:
	kfree(msg);
	return ret;
}

STATIC s32 sxe2_com_sched_tm_queue_add(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				       struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_vsi *usr_vsi;
	struct sxe2_txsch_ucmd_qnode_params ucmd_node_param;
	struct sxe2_tm_add_queue_msg *msg;
	struct sxe2_tm_res tm_res;
	s32 ret;

	msg = (struct sxe2_tm_add_queue_msg *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!msg) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*msg));
		ret = -EFAULT;
		goto l_end;
	}

	ucmd_node_param.parent_teid = msg->parent_teid;
	ucmd_node_param.queue_id = msg->queue_id;
	ucmd_node_param.adj_lvl = msg->adj_lvl;
	ucmd_node_param.committed = msg->info.committed;
	ucmd_node_param.peak = msg->info.peak;
	ucmd_node_param.priority = msg->info.priority;
	ucmd_node_param.weight = msg->info.weight;

	mutex_lock(&adapter->vsi_ctxt.lock);
	usr_vsi = sxe2_vsi_get_by_idx(adapter, cmd_buf->vsi_id);
	if (!usr_vsi) {
		mutex_unlock(&adapter->vsi_ctxt.lock);
		LOG_ERROR_BDF("sxe2_vsi_get_by_idx failed.\n");
		ret = -EIO;
		goto l_end;
	}

	ret = sxe2_txsched_ucmd_qnode_add(usr_vsi, &ucmd_node_param);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	if (ret) {
		LOG_ERROR_BDF("sxe2_txsched_ucmd_qnode_add failed.\n");
		ret = -EIO;
		goto l_end;
	}

	tm_res.teid = ucmd_node_param.node_teid;

	if (sxe2_com_resp_copy_to_user(cmd_buf, &tm_res, sizeof(tm_res), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%lu\n", sizeof(tm_res));
		ret = -EFAULT;
		goto l_end;
	}
	cmd_buf->resp_len = sizeof(tm_res);

l_end:
	kfree(msg);
	return ret;
}

STATIC s32 sxe2_com_irq_band_rxq(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				 struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_queue *rxq;
	struct sxe2_vsi *vsi;
	struct sxe2_drv_queue_irq_bind_req *req = NULL;
	s32 ret = 0;

	if (sizeof(*req) != cmd_buf->req_len) {
		LOG_ERROR_BDF("cmd len err %zu != %u\n", sizeof(*req), cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	req = (struct sxe2_drv_queue_irq_bind_req *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req));
		ret = -EFAULT;
		goto l_end;
	}

	vsi = sxe2_vsi_get_by_idx(adapter, cmd_buf->vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("failed to get vsi[%u]\n", cmd_buf->vsi_id);
		ret = -EFAULT;
		goto l_end;
	}

	rxq = vsi->rxqs.q[req->q_idx];
	if (!rxq) {
		LOG_ERROR_BDF("failed to get vsi[%u] rxq[%u].\n", cmd_buf->vsi_id,
			      req->q_idx);
		ret = -EFAULT;
		goto l_end;
	}

	LOG_DEBUG("irq band rxq, vsi[%d] rxq[%u/%u] bind irq[%u->%u] itr[%u].\n",
		  cmd_buf->vsi_id, rxq->idx_in_vsi, rxq->idx_in_pf, req->msix_idx,
		  req->msix_idx + vsi->irqs.base_idx_in_pf, req->itr_idx);

	if (req->bind) {
		sxe2_hw_rxq_irq_cause_setup(&adapter->hw, rxq->idx_in_pf, req->itr_idx,
					    req->msix_idx + vsi->irqs.base_idx_in_pf);
		LOG_DEBUG("vsi[%d] rxq[%u/%u] bind irq[%u] itr[%u] setup.\n",
			  cmd_buf->vsi_id, rxq->idx_in_vsi, rxq->idx_in_pf, req->msix_idx,
			  req->itr_idx);
	} else {
		sxe2_hw_rxq_irq_cause_clear(&adapter->hw, rxq->idx_in_pf);
		LOG_DEBUG("vsi[%d] rxq[%u/%u] bind irq[%u] clear.\n", cmd_buf->vsi_id,
			  rxq->idx_in_vsi, rxq->idx_in_pf, req->msix_idx);
	}

l_end:
	kfree(req);
	return ret;
}

STATIC s32 sxe2_com_switch_srcvsi_ext_prune(struct sxe2_adapter *adapter,
					    struct sxe2_obj *obj,
					    struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_srcvsi_ext_cfg_req *srcvsi_ext_cfg_req;
	s32 ret = 0;
	u16 vsi_id;
	u16 idx;
	u16 srcvsi_list[SXE2_SRCVSI_PRUNE_MAX_NUM];
	u16 srcvsi_cnt;
	u8 is_add;

	srcvsi_ext_cfg_req = (struct sxe2_srcvsi_ext_cfg_req *)
			      sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!srcvsi_ext_cfg_req) {
		LOG_ERROR_BDF("srcvsi list cfg req is NULL\n");
		ret = -EFAULT;
		goto l_end;
	}

	is_add = srcvsi_ext_cfg_req->is_add;
	srcvsi_cnt = srcvsi_ext_cfg_req->srcvsi_cnt;
	vsi_id = le16_to_cpu(srcvsi_ext_cfg_req->vsi_id);
	for (idx = 0; idx < srcvsi_cnt; idx++)
		srcvsi_list[idx] = le16_to_cpu(srcvsi_ext_cfg_req->srcvsi_list[idx]);

	if (is_add)
		ret = sxe2_ucmd_srcvsi_ext_add(adapter, vsi_id, srcvsi_list, srcvsi_cnt);
	else
		ret = sxe2_ucmd_srcvsi_ext_del(adapter, vsi_id);

	if (ret) {
		LOG_ERROR_BDF("user driver(vsi=%u) %s srcvsi ext fail, ret=%d\n", vsi_id,
			      is_add ? "set" : "clear", ret);
	} else {
		LOG_DEBUG_BDF("user driver(vsi=%u) %s srcvsi ext\n", vsi_id,
			      is_add ? "set" : "clear");
	}

l_end:
	kfree(srcvsi_ext_cfg_req);
	return ret;
}

STATIC s32 sxe2_com_sfp_eeprom_read(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				    struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;
	struct sxe2_drv_sfp_req *req =
		(struct sxe2_drv_sfp_req *)sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	u32 resp_len = sizeof(struct sxe2_drv_sfp_resp) + req->data_len;
	struct sxe2_drv_sfp_resp *resp = NULL;
	struct sxe2_sfp_resp *sff_value = NULL;

	resp = kzalloc(resp_len, GFP_KERNEL);
	if (!resp) {
		ret = -ENOMEM;
		goto l_end;
	}

	sff_value = kzalloc(sizeof(*sff_value) + req->data_len, GFP_KERNEL);
	if (!sff_value) {
		ret = -ENOMEM;
		goto l_end;
	}

	memset(resp, 0, resp_len);
	memset(sff_value, 0, sizeof(*sff_value) + req->data_len);

	ret = sxe2_fwc_sff_eeprom_get(adapter, req->is_qsfp, req->bus_addr, req->page_cnt,
				      req->offset, req->data_len, sff_value);
	if (ret) {
		LOG_ERROR_BDF("get eeprom failed, ret=%d.\n", ret);
		goto l_end;
	}

	memcpy(resp->data, sff_value->data, req->data_len);
	if (sxe2_com_resp_copy_to_user(cmd_buf, resp, resp_len, obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed.\n");
		ret = -EFAULT;
		goto l_end;
	}
	cmd_buf->resp_len = resp_len;

l_end:
	kfree(req);
	kfree(resp);
	kfree(sff_value);
	return ret;
}

struct sxe2_ioctl_cmd_table driver_cmd_table[] = {
	{SXE2_DRV_CMD_HANDSHAKE_DISABLE, sxe2_com_handshake_disable},

	{SXE2_DRV_CMD_DEV_GET_CAPS, sxe2_com_cap_get},
	{SXE2_DRV_CMD_DEV_GET_SWITCHDEV_INFO, sxe2_com_switchdev_info_get},

	{SXE2_DRV_CMD_DEV_GET_INFO, sxe2_com_info_get},
	{SXE2_DRV_CMD_DEV_GET_FW_INFO, sxe2_com_fw_info_get},

	{SXE2_DRV_CMD_RX_MAP_SET, sxe2_com_rxq_mapping_set},
	{SXE2_DRV_CMD_TX_MAP_SET, sxe2_com_txq_mapping_set},
	{SXE2_DRV_CMD_TX_RX_MAP_GET, sxe2_com_tx_rx_queue_info_get},
	{SXE2_DRV_CMD_TX_RX_MAP_RESET, sxe2_com_tx_rx_map_reset},
	{SXE2_DRV_CMD_TX_RX_MAP_INFO_CLEAR, sxe2_com_queue_map_info_clear},

	{SXE2_DRV_CMD_SCHED_ROOT_TREE_ALLOC, sxe2_com_sched_root_tree_alloc},
	{SXE2_DRV_CMD_SCHED_ROOT_TREE_RELEASE, sxe2_com_sched_root_tree_release},
	{SXE2_DRV_CMD_SCHED_ROOT_CHILDREN_DELETE, sxe2_com_sched_root_children_del},
	{SXE2_DRV_CMD_SCHED_TM_ADD_MID_NODE, sxe2_com_sched_tm_mid_add},
	{SXE2_DRV_CMD_SCHED_TM_ADD_QUEUE_NODE, sxe2_com_sched_tm_queue_add},

	{SXE2_DRV_CMD_RSS_KEY_SET, sxe2_com_rss_key_set},
	{SXE2_DRV_CMD_RSS_LUT_SET, sxe2_com_rss_lut_set},
	{SXE2_DRV_CMD_RSS_FUNC_SET, sxe2_com_rss_func_set},
	{SXE2_DRV_CMD_RSS_HF_ADD, sxe2_com_rss_hf_add},
	{SXE2_DRV_CMD_RSS_HF_DEL, sxe2_com_rss_hf_del},
	{SXE2_DRV_CMD_RSS_HF_CLEAR, sxe2_com_rss_hf_clear},

	{SXE2_DRV_CMD_VSI_CREATE, sxe2_com_main_vsi_create},
	{SXE2_DRV_CMD_VSI_FREE, sxe2_com_free_vsi},
	{SXE2_DRV_CMD_VSI_FC_GET, sxe2_com_vsi_fc_get},
	{SXE2_DRV_CMD_VSI_INFO_GET, sxe2_com_vsi_info_get},
	{SXE2_DRV_CMD_RXQ_CFG_ENABLE, sxe2_com_rxq_cfg_enable},
	{SXE2_DRV_CMD_RXQ_DISABLE, sxe2_com_rxq_cfg_disable},
	{SXE2_DRV_CMD_TXQ_CFG_ENABLE, sxe2_com_txq_cfg_enable},
	{SXE2_DRV_CMD_TXQ_DISABLE, sxe2_com_txq_cfg_disable},

	{SXE2_DRV_CMD_MAC_ADDR_UC, sxe2_com_switch_filter_uc},
	{SXE2_DRV_CMD_MAC_ADDR_MC, sxe2_com_switch_filter_mc},
	{SXE2_DRV_CMD_VLAN_FILTER_SWITCH, sxe2_com_switch_filter_vlan_control},
	{SXE2_DRV_CMD_VLAN_FILTER_ADD_DEL, sxe2_com_switch_filter_vlan_rule},
	{SXE2_DRV_CMD_PROMISC_CFG, sxe2_com_switch_filter_promisc},
	{SXE2_DRV_CMD_ALLMULTI_CFG, sxe2_com_switch_filter_allmulti},

	{SXE2_DRV_CMD_VSI_STATS_GET, sxe2_com_vsi_stat_get},
	{SXE2_DRV_CMD_VSI_STATS_CLEAR, sxe2_com_vsi_stat_clear},
	{SXE2_DRV_CMD_MAC_STATS_GET, sxe2_com_mac_stat_get},
	{SXE2_DRV_CMD_MAC_STATS_CLEAR, sxe2_com_mac_stat_clear},

	{SXE2_DRV_CMD_EVT_IRQ_BAND_RXQ, sxe2_com_irq_band_rxq},

	{SXE2_DRV_CMD_SWITCH_UPLINK, sxe2_com_switch_uplink},
	{SXE2_DRV_CMD_SWITCH_REPR, sxe2_com_switch_repr},
	{SXE2_DRV_CMD_SWITCH_MODE, sxe2_com_switch_mode},
	{SXE2_DRV_CMD_SWITCH_CPVSI, sxe2_com_switch_cp_vsi},

	{SXE2_DRV_CMD_UDPTUNNEL_ADD, sxe2_com_udptunnel_handler},
	{SXE2_DRV_CMD_UDPTUNNEL_DEL, sxe2_com_udptunnel_handler},
	{SXE2_DRV_CMD_UDPTUNNEL_GET, sxe2_com_udptunnel_handler},

	{SXE2_DRV_CMD_IPSEC_CAP_GET, sxe2_ipsec_cap_get},
	{SXE2_DRV_CMD_IPSEC_TXSA_ADD, sxe2_ipsec_txsa_add},
	{SXE2_DRV_CMD_IPSEC_RXSA_ADD, sxe2_ipsec_rxsa_add},
	{SXE2_DRV_CMD_IPSEC_TXSA_DEL, sxe2_ipsec_txsa_del},
	{SXE2_DRV_CMD_IPSEC_RXSA_DEL, sxe2_ipsec_rxsa_del},
	{SXE2_DRV_CMD_IPSEC_RESOURCE_CLEAR, sxe2_ipsec_resource_clear},

	{SXE2_DRV_CMD_FLOW_FILTER_ADD, sxe2_com_flow_filter_add},
	{SXE2_DRV_CMD_FLOW_FILTER_DEL, sxe2_com_flow_filter_del},
	{SXE2_DRV_CMD_FLOW_FNAV_STAT_ALLOC, sxe2_com_flow_fnav_stat_alloc},
	{SXE2_DRV_CMD_FLOW_FNAV_STAT_FREE, sxe2_com_flow_fnav_stat_free},
	{SXE2_DRV_CMD_FLOW_FNAV_STAT_QUERY, sxe2_com_flow_fnav_stat_query},

	{SXE2_DRV_CMD_LINK_STATUS_GET, sxe2_com_link_info_get},

	{SXE2_DRV_CMD_VLAN_OFFLOAD_CFG, sxe2_com_vlan_offload_cfg},
	{SXE2_DRV_CMD_VLAN_CFG_QUERY, sxe2_com_vlan_cfg_query},

	{SXE2_DRV_CMD_VSI_SRCVSI_PRUNE, sxe2_com_switch_srcvsi_ext_prune},

	{SXE2_DRV_CMD_OPT_EEP_GET, sxe2_com_sfp_eeprom_read},
};

STATIC s32 sxe2_drv_cmd_len_check(struct sxe2_drv_cmd_params *cmd_buf)
{
	return 0;
}

static s32 sxe2_pf_status_check(struct sxe2_adapter *adapter,
				struct sxe2_drv_cmd_params *cmd_buf)
{
	return 0;
}

STATIC s32 sxe2_drv_msg_check(struct sxe2_adapter *adapter,
			      struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;

	ret = sxe2_drv_cmd_len_check(cmd_buf);
	if (ret)
		return ret;

	ret = sxe2_pf_status_check(adapter, cmd_buf);
	if (ret)
		return ret;

	return ret;
}

STATIC struct sxe2_ioctl_cmd_table *sxe2_drv_cmd_handle_get(u32 opcode)
{
	u32 i;
	struct sxe2_ioctl_cmd_table *cmd_func = NULL;

	for (i = 0; i < ARRAY_SIZE(driver_cmd_table); i++) {
		if (driver_cmd_table[i].opcode == opcode) {
			cmd_func = &driver_cmd_table[i];
			break;
		}
	}

	return cmd_func;
}

s32 sxe2_com_cmd_send(void *ad, struct sxe2_obj *obj, struct sxe2_drv_cmd_params *param)
{
	s32 ret;
	struct sxe2_ioctl_cmd_table *cmd_table;
	struct sxe2_adapter *adapter = ad;

	if (sxe2_drv_msg_check(adapter, param)) {
		ret = -EINVAL;
		goto l_end;
	}

	LOG_DEBUG_BDF("com cmd opcode:0x%x vsi_id:%u trace_id:0x%llx\n.", param->opcode,
		      param->vsi_id, param->trace_id);
	cmd_table = sxe2_drv_cmd_handle_get(param->opcode);
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
