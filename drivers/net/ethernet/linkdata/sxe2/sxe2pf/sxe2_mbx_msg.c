// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_mbx_msg.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/bitmap.h>
#include "sxe2_mbx_msg.h"
#include "sxe2_cmd_channel.h"
#include "sxe2_mbx_channel.h"
#include "sxe2_mbx_public.h"
#include "sxe2_log.h"
#include "sxe2_rx.h"
#include "sxe2_vsi.h"
#include "sxe2_sriov.h"
#include "sxe2_switch.h"
#include "sxe2_tx.h"
#include "sxe2_hw.h"
#include "sxe2_dev_ctrl.h"
#include "sxe2_ethtool.h"
#include "sxe2_rss.h"
#include "sxe2_ptp.h"
#include "sxe2_monitor.h"
#include "sxe2_txsched.h"
#include "sxe2_tc.h"
#include "sxe2_com_ioctl.h"

#define SXE2_CALC_RESP_LEN(data_obj, max_tran_len)                                  \
	min_t(u32, sizeof(data_obj), (max_tran_len))

static bool sxe2_mbx_msg_vsi_id_is_valid(struct sxe2_vf_node *vf, u16 vsi_id)
{
	return (vf->vsi_id[SXE2_VF_TYPE_ETH] == vsi_id) ||
	       (vf->vsi_id[SXE2_VF_TYPE_DPDK] == vsi_id);
}

void sxe2_mbx_msg_params_fill(struct sxe2_cmd_params *cmd, u32 opc, void *req_data,
			      u32 req_len, u16 vf_idx, bool no_resp)
{
	cmd->opcode = opc;
	cmd->req_data = req_data;
	cmd->req_len = (u16)req_len;
	cmd->vf_idx = vf_idx;
	cmd->no_resp = no_resp;

	sxe2_trace_id_alloc(&cmd->trace_id);
}

STATIC void sxe2_mbx_msg_reply_params_fill(struct sxe2_cmd_params *cmd, u32 opc,
					   void *req_data, u32 req_len, u16 vf_idx,
					   u64 session_id, s32 err_code)
{
	cmd->opcode = opc;
	cmd->req_data = req_data;
	cmd->req_len = (u16)req_len;
	cmd->vf_idx = vf_idx;
	cmd->session_id = session_id;
	cmd->err_code = err_code;
	cmd->no_resp = true;

	sxe2_trace_id_alloc(&cmd->trace_id);

	LOG_DEBUG("vf_id:%d opcode:0x%x req_len:%u session_id:0x%llx err_code:%d.\n",
		  vf_idx, opc, req_len, session_id, err_code);
}

STATIC s32 sxe2_ver_msg_func(struct sxe2_vf_node *vf,
			     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_vf_ver_msg pf_ver = {0};
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	struct sxe2_vf_ver_msg *ver_msg =
		(struct sxe2_vf_ver_msg *)(msg_info->buf +
					   SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	s32 ret;

	vf->vf_ver.major = le16_to_cpu(ver_msg->major);
	vf->vf_ver.minor = le16_to_cpu(ver_msg->minor);

	pf_ver.major = cpu_to_le16(SXE2_VF_VERSION_MAJOR);
	pf_ver.minor = cpu_to_le16(SXE2_VF_VERSION_MINOR);

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, &pf_ver,
				       SXE2_CALC_RESP_LEN(pf_ver, cmd_hdr->tran_out_len),
				       vf->vf_idx, session_id, 0);
	ret = sxe2_mbx_msg_reply(adapter, &params);

	LOG_INFO_BDF("rcv vf:%u drv version:%d.%d reply pf version:%d.%d.(ret:%d)\n",
		     vf->vf_idx, le16_to_cpu(ver_msg->major),
		     le16_to_cpu(ver_msg->minor), SXE2_VF_VERSION_MAJOR,
		     SXE2_VF_VERSION_MINOR, ret);

	return ret;
}

static s32 sxe2_reset_msg_func(struct sxe2_vf_node *vf,
			       struct sxe2_mbx_msg_info *msg_info)
{
	s32 ret;
	struct sxe2_adapter *adapter = vf->adapter;

	ret = sxe2_reset_vf(adapter, vf->vf_idx, 0);

	LOG_INFO_BDF("vf:%u reset request handle ret:%d\n", vf->vf_idx, ret);

	return ret;
}

static u32 sxe2_speed_get(struct sxe2_vf_node *vf)
{
#if defined(SXE2_HARDWARE_ASIC)
	return sxe2_get_link_speed(vf->adapter);
#endif
}

static bool sxe2_vf_is_link_up(struct sxe2_vf_node *vf)
{
	if (vf->prop.link_forced)
		return vf->prop.link_up;
	else
		return sxe2_get_pf_link_status(vf->adapter);
}

void sxe2_notify_vf_link_state(struct sxe2_vf_node *vf)
{
	struct sxe2_cmd_params params = {0};
	struct sxe2_vf_link_msg link_msg = {0};
	struct sxe2_adapter *adapter = vf->adapter;
	u32 len = sizeof(struct sxe2_vf_link_msg);

	if (sxe2_vf_is_link_up(vf)) {
		LOG_INFO("change link up.\n");
		link_msg.status = 1;
		link_msg.speed = sxe2_speed_get(vf);
	} else {
		LOG_INFO("change link down.\n");
		link_msg.status = 0;
		link_msg.speed = SXE2_LINK_SPEED_UNKNOWN;
	}

	sxe2_mbx_msg_params_fill(&params, SXE2_VF_LINK_UPDATE_NOTIFY, &link_msg, len,
				 vf->vf_idx, true);
	(void)sxe2_mbx_msg_send(adapter, &params);
}

static s32 sxe2_rxq_cfg_ena_msg_func(struct sxe2_vf_node *vf,
				     struct sxe2_mbx_msg_info *msg_info)
{
	s32 ret;
	u16 i = 0;
	struct sxe2_vsi *vsi;
	struct sxe2_vf_rxq_msg *rxq_msg =
		(struct sxe2_vf_rxq_msg *)
		 (msg_info->buf + SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vf_rxq_ctxt *ctxt;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_rxq_cfg_params *rxq_params;
	u32 len;

	vsi = sxe2_vf_vsi_get(vf, le16_to_cpu(rxq_msg->vsi_id));
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", le16_to_cpu(rxq_msg->vsi_id));
		ret = -SXE2_VF_ERR_PARAM;
		goto l_reply;
	}

	len = sizeof(*rxq_params) +
	      sizeof(struct sxe2_ctxt_elem) * le16_to_cpu(rxq_msg->q_cnt);

	rxq_params = kzalloc(len, GFP_KERNEL);
	if (!rxq_params) {
		ret = -SXE2_VF_ERR_NO_MEMORY;
		LOG_ERROR_BDF("rxq msg mem %uB alloc failed.\n", len);
		goto l_reply;
	}

	rxq_params->vsi_id = le16_to_cpu(rxq_msg->vsi_id);
	rxq_params->q_cnt = le16_to_cpu(rxq_msg->q_cnt);
	rxq_params->max_frame_size = le16_to_cpu(rxq_msg->max_frame_size);
	for (i = 0; i < rxq_params->q_cnt; i++) {
		ctxt = &rxq_msg->ctxt[i];
		rxq_params->cfg[i].queue_id = le16_to_cpu(ctxt->queue_id);
		rxq_params->cfg[i].depth = le16_to_cpu(ctxt->depth);
		rxq_params->cfg[i].buf_len = le16_to_cpu(ctxt->buf_len);
		rxq_params->cfg[i].dma_addr = le64_to_cpu(ctxt->dma_addr);
		rxq_params->cfg[i].keep_crc_en = ctxt->keep_crc_en;
		rxq_params->cfg[i].lro_en = ctxt->lro_status;
	}

	ret = sxe2_rxq_cfg_ena_common_handle(adapter, rxq_params);

	kfree(rxq_params);

l_reply:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);

	return sxe2_mbx_msg_reply(adapter, &params);
}

static s32 sxe2_mbx_txq_cfg_reply(struct sxe2_vf_node *vf,
				  struct sxe2_mbx_msg_info *msg_info)
{
	s32 ret = 0;
	u32 i, len;
	struct sxe2_vsi *vsi;
	struct sxe2_vf_txq_ctxt *ctxt;
	struct sxe2_cmd_params params = {0};
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	struct sxe2_txq_ucmd_en_params *txq_params;
	struct sxe2_vf_txq_ctxt_msg *req =
			(struct sxe2_vf_txq_ctxt_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));

	vsi = sxe2_vf_vsi_get(vf, le16_to_cpu(req->vsi_id));
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", le16_to_cpu(req->vsi_id));
		ret = -SXE2_VF_ERR_PARAM;
		goto l_reply;
	}

	len = sizeof(*txq_params) +
	      sizeof(struct sxe2_vf_txq_ctxt) * le16_to_cpu(req->q_cnt);

	txq_params = kzalloc(len, GFP_KERNEL);
	if (!txq_params) {
		LOG_ERROR_BDF("txq msg mem %uB alloc failed.\n", len);
		ret = -SXE2_VF_ERR_NO_MEMORY;
		goto l_reply;
	}

	txq_params->q_cnt = le16_to_cpu(req->q_cnt);
	txq_params->vsi_idx = le16_to_cpu(req->vsi_id);
	for (i = 0; i < txq_params->q_cnt; i++) {
		ctxt = &req->ctxs[i];
		txq_params->ctxts[i].depth = le16_to_cpu(ctxt->depth);
		txq_params->ctxts[i].dma_addr = le64_to_cpu(ctxt->dma_addr);
		txq_params->ctxts[i].queue_id = le16_to_cpu(ctxt->queue_id);
		txq_params->ctxts[i].sched_mode = le32_to_cpu(ctxt->sched_mode);
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

l_reply:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, le64_to_cpu(cmd_hdr->session_id),
				       ret);
	(void)sxe2_mbx_msg_reply(adapter, &params);
	return 0;
}

STATIC s32 sxe2_res_get_msg_func(struct sxe2_vf_node *vf,
				 struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_fw_ver_msg *fw_ver = &adapter->hw.fw_ver;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_vf_vfres_msg *vfres = NULL;
	struct sxe2_vf_vsi_res *vsi_res = NULL;
	struct sxe2_vf_vfres_msg_req *vfreq =
			(struct sxe2_vf_vfres_msg_req
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	u8 i;

	vfres = kzalloc(sizeof(*vfres), GFP_KERNEL);
	if (!vfres) {
		ret = -SXE2_VF_ERR_NO_MEMORY;
		goto err;
	}

	vsi_res = vfres->vsi_res;

	if (vfreq->support_sw_stats)
		set_bit(SXE2_FLAG_VFSWSTATS_ENABLE, adapter->flags);
	else
		clear_bit(SXE2_FLAG_VFSWSTATS_ENABLE, adapter->flags);

	vfres->num_vsis = cpu_to_le16(SXE2_VF_VSI_CNT_USED);

	for (i = 0; i < vfres->num_vsis; i++)
		vsi_res[i].vsi_id = cpu_to_le16(vf->vsi_id[i]);

	vfres->rxft_cap.fnav_space_bsize =
			cpu_to_le16(adapter->caps_ctxt.fnav_space_bsize);
	vfres->rxft_cap.fnav_space_gsize = 0;
	vfres->rxft_cap.rss_key_size = cpu_to_le16(SXE2_RSS_HASH_KEY_SIZE);
	vfres->rxft_cap.rss_lut_size = cpu_to_le16(SXE2_RSS_LUT_SIZE_64);
	vfres->rxft_cap.rss_lut_type = cpu_to_le16(SXE2_RSS_VSI_LUT);

	vfres->q_cnt = cpu_to_le16(adapter->vf_ctxt.q_cnt);
	vfres->max_vectors = cpu_to_le16(adapter->vf_ctxt.irq_cnt);
	vfres->itr_gran = cpu_to_le16(adapter->hw.hw_cfg.itr_gran);
	ether_addr_copy(vfres->addr, vf->mac_addr.addr);
	vfres->port_vlan_exsit = (u8)sxe2_port_vlan_is_exist(vf);
	vfres->is_switchdev =
			(u8)test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags);
	vfres->max_vlan_cnt = cpu_to_le16(vf->prop.trusted ? VLAN_N_VID
							   : SXE2_VF_VLAN_CNT_MAX);

	vfres->pf_cnt = adapter->aux_ctxt.cdev_info.pf_cnt;
	vfres->fw_ver.main_version_id = fw_ver->main_version_id;
	vfres->fw_ver.sub_version_id = fw_ver->sub_version_id;
	vfres->fw_ver.fix_version_id = fw_ver->fix_version_id;
	vfres->fw_ver.build_id = fw_ver->build_id;
	vfres->tm_layers = 3;
	vfres->cap_flags = SXE2_VF_OFFLOAD_L2 | SXE2_VF_OFFLOAD_VLAN |
			   SXE2_VF_OFFLOAD_IPSEC | SXE2_VF_OFFLOAD_PTP |
			   SXE2_VF_OFFLOAD_TM;

	vfres->cap_flags |= SXE2_VF_OFFLOAD_RSS;

	vfres->cap_flags |= SXE2_VF_OFFLOAD_FNAV;
	vfres->parent_pfid = adapter->pf_idx;
	vfres->parent_portid = adapter->port_idx;
	vfres->vf_id_in_dev = cpu_to_le16(vf->vf_idx + adapter->vf_ctxt.vfid_base);

	if (sxe2_txsch_is_vf_vsi_agg_mode(adapter)) {
		vfres->vf_txsch_cap.layer_cap = 3;
		vfres->vf_txsch_cap.prio_num = 8;
		vfres->vf_txsch_cap.tm_mid_node_num = 8;
	} else {
		vfres->vf_txsch_cap.layer_cap = 3;
		vfres->vf_txsch_cap.prio_num = 4;
		vfres->vf_txsch_cap.tm_mid_node_num = 4;
	}

	set_bit(SXE2_VF_STATE_ACTIVE, vf->states);

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, (void *)vfres,
				       SXE2_CALC_RESP_LEN(*vfres, cmd_hdr->tran_out_len),
				       vf->vf_idx, session_id, 0);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	kfree(vfres);
	goto l_end;

err:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);

l_end:
	return ret;
}

STATIC void sxe2_vsi_stats_to_le(struct sxe2_vsi *vsi,
				 struct sxe2_vf_vsi_hw_stats *stats)
{
	struct sxe2_vsi_hw_stats *new_stats = &vsi->vsi_stats.vsi_hw_stats;

	stats->rx_vsi_unicast_packets =
			cpu_to_le64(new_stats->rx_vsi_unicast_packets);
	stats->rx_vsi_bytes = cpu_to_le64(new_stats->rx_vsi_bytes);
	stats->tx_vsi_unicast_packets =
			cpu_to_le64(new_stats->tx_vsi_unicast_packets);
	stats->tx_vsi_bytes = cpu_to_le64(new_stats->tx_vsi_bytes);
	stats->rx_vsi_multicast_packets =
			cpu_to_le64(new_stats->rx_vsi_multicast_packets);
	stats->tx_vsi_multicast_packets =
			cpu_to_le64(new_stats->tx_vsi_multicast_packets);
	stats->rx_vsi_broadcast_packets =
			cpu_to_le64(new_stats->rx_vsi_broadcast_packets);
	stats->tx_vsi_broadcast_packets =
			cpu_to_le64(new_stats->tx_vsi_broadcast_packets);
}

STATIC void sxe2_hw_vsi_stats_clear(struct sxe2_vsi *vsi)
{
	struct sxe2_vsi_hw_stats *stats = &vsi->vsi_stats.vsi_hw_stats;

	stats->rx_vsi_unicast_packets = 0;
	stats->rx_vsi_bytes = 0;
	stats->tx_vsi_unicast_packets = 0;
	stats->tx_vsi_bytes = 0;
	stats->rx_vsi_multicast_packets = 0;
	stats->tx_vsi_multicast_packets = 0;
	stats->rx_vsi_broadcast_packets = 0;
	stats->tx_vsi_broadcast_packets = 0;
}

STATIC s32 sxe2_stats_clear_msg_func(struct sxe2_vf_node *vf,
				     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_vsi *vsi;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_vsi_res *res_msg =
		(struct sxe2_vf_vsi_res *)(msg_info->buf +
					   SXE2VF_MBX_DATA_OFFSET(msg_info->buf));

	if (!sxe2_mbx_msg_vsi_id_is_valid(vf, le16_to_cpu(res_msg->vsi_id))) {
		ret = -SXE2_VF_ERR_PARAM;
		LOG_DEV_ERR("vsi id:%d is invalid.\n", le16_to_cpu(res_msg->vsi_id));
		goto err;
	}

	vsi = sxe2_vf_vsi_get(vf, le16_to_cpu(res_msg->vsi_id));
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", le16_to_cpu(res_msg->vsi_id));
		ret = -SXE2_VF_ERR_PARAM;
		goto err;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	sxe2_hw_vsi_stats_clear(vsi);
	mutex_unlock(&adapter->vsi_ctxt.lock);
err:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);

	ret = sxe2_mbx_msg_reply(adapter, &params);
	LOG_DEV_INFO("vf stats clear. vsi id:%d ret:%d\n",
		     le16_to_cpu(res_msg->vsi_id), ret);
	return ret;
}

STATIC s32 sxe2_stats_get_msg_func(struct sxe2_vf_node *vf,
				   struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_vsi *vsi;
	struct sxe2_vf_vsi_sw_stats *vf_sw_stats;
	struct sxe2_vsi_sw_stats *vsi_sw_stats;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vf_hw_stats_rsp vf_stats_rsp = {{0}, 0};
	struct sxe2_vf_vsi_hw_stats *vf_hw_stats = &vf_stats_rsp.hw_stats;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_sw_stats *res_msg =
		(struct sxe2_vf_sw_stats *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));

	if (!sxe2_mbx_msg_vsi_id_is_valid(vf, le16_to_cpu(res_msg->vsi_id))) {
		ret = -SXE2_VF_ERR_PARAM;
		LOG_DEV_ERR("vsi id:%d is invalid.\n", le16_to_cpu(res_msg->vsi_id));
		goto err;
	}

	vsi = sxe2_vf_vsi_get(vf, le16_to_cpu(res_msg->vsi_id));
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", le16_to_cpu(res_msg->vsi_id));
		ret = -SXE2_VF_ERR_PARAM;
		goto err;
	}

	vf_sw_stats = &res_msg->sw_stats;
	vsi_sw_stats = &vsi->vsi_stats.vsi_sw_stats;

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi_sw_stats->rx_bytes = le64_to_cpu(vf_sw_stats->rx_bytes);
	vsi_sw_stats->rx_packets = le64_to_cpu(vf_sw_stats->rx_packets);
	vsi_sw_stats->tx_bytes = le64_to_cpu(vf_sw_stats->tx_bytes);
	vsi_sw_stats->tx_packets = le64_to_cpu(vf_sw_stats->tx_packets);

	sxe2_hw_vsi_stats_update(vsi);

	sxe2_vsi_stats_to_le(vsi, vf_hw_stats);

	mutex_unlock(&adapter->vsi_ctxt.lock);

	sxe2_fnav_match_stats_get(adapter, le16_to_cpu(res_msg->fnav_stats_idx),
				  vsi->id_in_pf);
	vf_stats_rsp.fnav_match =
			cpu_to_le64(adapter->fnav_ctxt.fnav_stat_ctxt
						    .vsi_fnav_match[vsi->id_in_pf]);

err:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, &vf_stats_rsp,
				       SXE2_CALC_RESP_LEN(vf_stats_rsp, cmd_hdr->tran_out_len),
				       vf->vf_idx, session_id, ret);

	ret = sxe2_mbx_msg_reply(adapter, &params);
	return ret;
}

STATIC s32 sxe2_stats_push_msg_func(struct sxe2_vf_node *vf,
				    struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_vsi *vsi;
	struct sxe2_vf_vsi_sw_stats *vf_sw_stats;
	struct sxe2_vsi_sw_stats *vsi_sw_stats;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vf_hw_stats_rsp vf_stats_rsp = {{0}, 0};
	struct sxe2_vf_vsi_hw_stats *vf_hw_stats = &vf_stats_rsp.hw_stats;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_sw_stats *res_msg =
			(struct sxe2_vf_sw_stats *)(msg_info->buf +
						    SXE2VF_MBX_FULL_HDR_SIZE);

	if (!sxe2_mbx_msg_vsi_id_is_valid(vf, le16_to_cpu(res_msg->vsi_id))) {
		ret = -SXE2_VF_ERR_PARAM;
		LOG_DEV_ERR("vsi id:%d is invalid.\n", le16_to_cpu(res_msg->vsi_id));
		goto err;
	}

	vsi = sxe2_vf_vsi_get(vf, le16_to_cpu(res_msg->vsi_id));
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", le16_to_cpu(res_msg->vsi_id));
		ret = -SXE2_VF_ERR_PARAM;
		goto err;
	}

	vf_sw_stats = &res_msg->sw_stats;
	vsi_sw_stats = &vsi->vsi_stats.vsi_sw_stats;

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi_sw_stats->rx_bytes = le64_to_cpu(vf_sw_stats->rx_bytes);
	vsi_sw_stats->rx_packets = le64_to_cpu(vf_sw_stats->rx_packets);
	vsi_sw_stats->tx_bytes = le64_to_cpu(vf_sw_stats->tx_bytes);
	vsi_sw_stats->tx_packets = le64_to_cpu(vf_sw_stats->tx_packets);

	sxe2_vsi_stats_to_le(vsi, vf_hw_stats);

	mutex_unlock(&adapter->vsi_ctxt.lock);

err:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, &vf_stats_rsp,
				       sizeof(vf_stats_rsp), vf->vf_idx, session_id,
				       ret);

	ret = sxe2_mbx_msg_reply(adapter, &params);
	return ret;
}

STATIC bool sxe2_vsi_txq_idx_is_valid(struct sxe2_vsi *vsi, u16 queue_idx)
{
	return (queue_idx < vsi->txqs.q_cnt);
}

STATIC bool sxe2_vsi_rxq_idx_is_valid(struct sxe2_vsi *vsi, u16 queue_idx)
{
	return (queue_idx < vsi->rxqs.q_cnt);
}

STATIC s32 sxe2_vsi_queue_idx_is_valid(struct sxe2_vsi *vsi,
				       struct sxe2_irq_data *irq_data,
				       struct sxe2_vf_irq_map *irq_map)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	u64 vsi_q_id, vsi_q_id_idx;
	unsigned long qmap;
	u16 queue_cnt = 0;
	s32 ret = SXE2_VF_ERR_SUCCESS;

	qmap = le16_to_cpu(irq_map->txq_map);
	queue_cnt = vsi->txqs.q_cnt;
	for_each_set_bit(vsi_q_id_idx, &qmap, queue_cnt) {
		vsi_q_id = vsi_q_id_idx;

		if (!sxe2_vsi_txq_idx_is_valid(vsi, (u16)vsi_q_id)) {
			LOG_DEV_ERR("irq map tx queue:%llu failed.\n", vsi_q_id);
			ret = -SXE2_VF_ERR_PARAM;
			goto l_out;
		}
	}

	qmap = le16_to_cpu(irq_map->rxq_map);
	queue_cnt = vsi->rxqs.q_cnt;
	for_each_set_bit(vsi_q_id_idx, &qmap, queue_cnt) {
		vsi_q_id = vsi_q_id_idx;

		if (!sxe2_vsi_rxq_idx_is_valid(vsi, (u16)vsi_q_id)) {
			LOG_DEV_ERR("irq map rx queue:%llu failed.\n", vsi_q_id);
			ret = -SXE2_VF_ERR_PARAM;
			goto l_out;
		}
	}

l_out:
	return ret;
}

STATIC void sxe2_irq_queue_cfg(struct sxe2_irq_data *irq_data,
			       struct sxe2_q_container *q_container,
			       struct sxe2_queue *queue, __le16 itr_idx)
{
	SXE2_BUG_ON((q_container->list.cnt == 0) &&
		    (q_container->list.next));
	SXE2_BUG_ON((q_container->list.cnt != 0) &&
		    (!q_container->list.next));

	q_container->itr_idx = le16_to_cpu(itr_idx);
	queue->irq_data = irq_data;
	sxe2_queue_add(queue, &q_container->list);
}

STATIC s32 sxe2_irq_map(struct sxe2_vsi *vsi, struct sxe2_irq_data *irq_data,
			struct sxe2_vf_irq_map *irq_map)
{
	u64 vsi_q_id, vsi_q_id_idx;
	unsigned long qmap;
	u16 queue_cnt = 0;
	s32 ret = SXE2_VF_ERR_SUCCESS;

	ret = sxe2_vsi_queue_idx_is_valid(vsi, irq_data, irq_map);
	if (ret)
		goto l_out;

	qmap = le16_to_cpu(irq_map->txq_map);
	queue_cnt = vsi->txqs.q_cnt;
	for_each_set_bit(vsi_q_id_idx, &qmap, queue_cnt) {
		vsi_q_id = vsi_q_id_idx;
		sxe2_irq_queue_cfg(irq_data, &irq_data->tx, vsi->txqs.q[vsi_q_id],
				   irq_map->txitr_idx);
	}

	qmap = le16_to_cpu(irq_map->rxq_map);
	queue_cnt = vsi->rxqs.q_cnt;
	for_each_set_bit(vsi_q_id_idx, &qmap, queue_cnt) {
		vsi_q_id = vsi_q_id_idx;
		sxe2_irq_queue_cfg(irq_data, &irq_data->rx, vsi->rxqs.q[vsi_q_id],
				   irq_map->rxitr_idx);
	}

l_out:
	return ret;
}

STATIC s32 sxe2_irq_map_msg_func(struct sxe2_vf_node *vf,
				 struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = NULL;
	struct sxe2_vf_irq_map *irq_map;
	u16 i, num_irqs, irq_id;
	struct sxe2_vf_irq_map_msg *irq_map_msg =
			(struct sxe2_vf_irq_map_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	u16 vsi_id = le16_to_cpu(irq_map_msg->vsi_id);

	num_irqs = le16_to_cpu(irq_map_msg->num_irqs);

	if (adapter->vf_ctxt.irq_cnt < num_irqs || !num_irqs) {
		ret = -SXE2_VF_ERR_PARAM;
		LOG_INFO_BDF("num_irqs:%d invalid.\n", num_irqs);
		goto err;
	}

	vsi = sxe2_vf_vsi_get(vf, vsi_id);
	if (!vsi) {
		ret = -SXE2_VF_ERR_PARAM;
		LOG_INFO_BDF("vsi_id:%d vsi null.\n", vsi_id);
		goto err;
	}

	sxe2_vsi_queues_irqs_unmap(vsi);

	for (i = 0; i < num_irqs; i++) {
		struct sxe2_irq_data *irq_data;

		irq_map = &irq_map_msg->irq_maps[i];

		irq_id = le16_to_cpu(irq_map->irq_id);
		if (irq_id >= vsi->irqs.cnt) {
			ret = -SXE2_VF_ERR_PARAM;
			LOG_INFO_BDF("irq_id:%d exceed vsi:%d irq cnt:%d.\n", irq_id,
				     vsi_id, vsi->irqs.cnt);
			goto err;
		}

		irq_data = vsi->irqs.irq_data[i];
		if (!irq_data) {
			ret = -SXE2_VF_ERR_PARAM;
			goto err;
		}

		ret = sxe2_irq_map(vsi, irq_data, irq_map);
		if (ret) {
			LOG_DEV_ERR("vsi irq map failed.ret:%u\n", ret);
			goto err;
		}
		sxe2_vsi_irqs_setup(vsi);
	}
err:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	return ret;
}

STATIC s32 sxe2_irq_unmap_msg_func(struct sxe2_vf_node *vf,
				   struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi;
	struct sxe2_vf_irq_unmap_msg *irq_unmap_msg =
			(struct sxe2_vf_irq_unmap_msg *)(msg_info->buf +
							 SXE2VF_MBX_FULL_HDR_SIZE);
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	u16 vsi_id = le16_to_cpu(irq_unmap_msg->vsi_id);

	vsi = sxe2_vf_vsi_get(vf, vsi_id);
	if (!vsi) {
		ret = -SXE2_VF_ERR_PARAM;
		LOG_INFO_BDF("vsi_id:%d vsi null.\n", vsi_id);
		goto err;
	}

	if (!sxe2_mbx_msg_vsi_id_is_valid(vf, vsi_id)) {
		ret = -SXE2_VF_ERR_PARAM;
		LOG_DEV_ERR("vsi id:%d is invalid.\n", vsi_id);
		goto err;
	}

	sxe2_vsi_queues_irqs_unmap(vsi);

	sxe2_vsi_irqs_release(vsi);

err:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	return ret;
}

static bool sxe2_addr_msg_is_valid(struct sxe2_vf_node *vf,
				   struct sxe2_vf_addr_msg *addr_msg, bool add)
{
	int addr_msg_has_pf_mac = 0;
	u32 i = 0;
	struct sxe2_adapter *adapter = vf->adapter;

	if (!sxe2_mbx_msg_vsi_id_is_valid(vf, le16_to_cpu(addr_msg->vsi_id))) {
		LOG_ERROR("addr msg invalid vsi_id:%u correct vsi_id_eth:%u\t"
			  "vsi_id_dpdk:%u.\n",
			  le16_to_cpu(addr_msg->vsi_id),
			  vf->vsi_id[SXE2_VF_TYPE_ETH],
			  vf->vsi_id[SXE2_VF_TYPE_DPDK]);
		return false;
	}

	if (add) {
		if (!is_zero_ether_addr(vf->mac_addr.addr)) {
			for (i = 0; i < addr_msg->addr_cnt; i++) {
				if (ether_addr_equal(addr_msg->elem[i].addr,
						     vf->mac_addr.addr))
					addr_msg_has_pf_mac++;
			}
		}

		if (!sxe2_vf_is_trusted(vf) &&
		    ((addr_msg->addr_cnt + vf->mac_cnt - addr_msg_has_pf_mac) >
		     SXE2_VF_MACADDR_CNT_MAX)) {
			LOG_DEV_ERR("vf:%u mac addr most add:%u, set vf to trusted\t"
				    "mode to add more\n",
				    vf->vf_idx,
				    (SXE2_VF_MACADDR_CNT_MAX - vf->mac_cnt));
			return false;
		}
	}

	return true;
}

static s32 sxe2_vf_addr_add(struct sxe2_vf_node *vf, struct sxe2_vsi *vsi,
			    struct sxe2_vf_addr *addr)
{
	struct sxe2_adapter *adapter = vf->adapter;
	u8 *mac_addr = addr->addr;
	s32 ret;

	if (is_unicast_ether_addr(mac_addr) &&
	    !ether_addr_equal(mac_addr, vf->mac_addr.addr) &&
	    !sxe2_vf_set_mac_is_allow(vf)) {
		LOG_DEV_ERR("untrusted vf modify mac addr from pf not permed\n");
		return -EPERM;
	}
	if (!vsi) {
		LOG_DEV_ERR("vsi is NULL\n");
		return -EINVAL;
	}

	ret = sxe2_mac_rule_add(vsi, mac_addr);
	if (ret == -EEXIST) {
		LOG_WARN_BDF("MAC %pM already exists for VF %d\n", mac_addr,
			     vf->vf_idx);
		ret = SXE2_VF_ERR_SUCCESS;
	} else if (ret) {
		LOG_DEV_ERR("Failed to add MAC %pM for VF %d\n, error %d\n",
			    mac_addr, vf->vf_idx, ret);
		goto l_out;
	} else {
		if (is_unicast_ether_addr(mac_addr)) {
			ret = sxe2_mac_spoofchk_ext_rule_add(adapter,
							     vsi->idx_in_dev,
							     mac_addr);
			if (ret) {
				LOG_DEV_ERR("Failed to add mac spoof ext rule %pM \t"
					    "for VF %d vsi %u\n, error %d\n",
					    mac_addr, vf->vf_idx, vsi->idx_in_dev,
					    ret);
				(void)sxe2_mac_rule_del(adapter, vsi->idx_in_dev,
							mac_addr);
				return ret;
			}
		}
		vf->mac_cnt++;
	}

	LOG_INFO_BDF("vf:%u mac:%pM added mac_cnt:%u\n", vf->vf_idx, mac_addr,
		     vf->mac_cnt);

	if (vsi->type == SXE2_VSI_T_VF && addr->type == SXE2_VF_MAC_TYPE_P)
		ether_addr_copy(vf->mac_addr.addr, mac_addr);
l_out:
	return ret;
}

static s32 sxe2_vf_addr_del(struct sxe2_vf_node *vf, struct sxe2_vsi *vsi,
			    struct sxe2_vf_addr *addr)
{
	struct sxe2_adapter *adapter = vf->adapter;
	u8 *mac_addr = addr->addr;
	s32 ret;

	if (!sxe2_vf_set_mac_is_allow(vf) &&
	    ether_addr_equal(mac_addr, vf->mac_addr.addr))
		return 0;

	if (!vsi) {
		LOG_DEV_INFO("Ingnore invalid vsi, vsi is NULL\n");
		return 0;
	}

	ret = sxe2_mac_rule_del(adapter, vsi->idx_in_dev, mac_addr);
	if (ret == -ENOENT) {
		LOG_WARN_BDF("MAC %pM does not exist for VF %d\n", mac_addr,
			     vf->vf_idx);
		return -ENOENT;
	} else if (ret) {
		LOG_DEV_ERR("Failed to delete MAC %pM for VF %d, error %d\n",
			    mac_addr, vf->vf_idx, ret);
		return -EIO;
	}

	if (is_unicast_ether_addr(mac_addr)) {
		ret = sxe2_mac_spoofchk_ext_rule_del(adapter, vsi->idx_in_dev,
						     mac_addr);
		if (ret) {
			LOG_DEV_ERR("Failed to del MAC spoof rule %pM for VF %d,\t"
				    "error %d\n",
				    mac_addr, vf->vf_idx, ret);
			ret = sxe2_mac_rule_add(vsi, mac_addr);
			if (ret)
				LOG_DEV_ERR("Failed to add MAC %pM for VF %d, error\t"
					    "%d\n",
					    mac_addr, vf->vf_idx, ret);
		}
	}

	vf->mac_cnt--;
	LOG_INFO_BDF("vf:%u mac:%pM del mac_cnt:%u\n", vf->vf_idx, mac_addr,
		     vf->mac_cnt);

	return ret;
}

static s32 sxe2_addr_msg_handle(struct sxe2_vf_node *vf,
				struct sxe2_mbx_msg_info *msg_info, bool add)
{
	s32 (*sxe2_vf_addr_action)(struct sxe2_vf_node *vf, struct sxe2_vsi *vsi,
				   struct sxe2_vf_addr *addr);
	s32 h_ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_vf_addr_msg *msg =
			(struct sxe2_vf_addr_msg *)(msg_info->buf +
						    SXE2VF_MBX_FULL_HDR_SIZE);
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vsi *vsi;
	u32 i = 0;
	s32 ret;

	if (add)
		sxe2_vf_addr_action = sxe2_vf_addr_add;
	else
		sxe2_vf_addr_action = sxe2_vf_addr_del;

	if (!sxe2_addr_msg_is_valid(vf, msg, add)) {
		h_ret = -EPERM;
		goto l_msg_reply;
	}

	if (msg->is_user) {
		for (i = 0; i < msg->addr_cnt; i++) {
			u8 *mac_addr = msg->elem[i].addr;

			if (is_zero_ether_addr(mac_addr))
				continue;

			ret = sxe2_vf_addr_action(vf, vf->dpdk_vf_vsi,
						  &msg->elem[i]);
			if (ret == -EEXIST || ret == -ENOENT) {
				continue;
			} else if (ret) {
				h_ret = ret;
				break;
			}
		}
	} else {
		vsi = sxe2_vf_vsi_get(vf, vf->vsi_id[SXE2_VF_TYPE_ETH]);
		if (!vsi) {
			LOG_ERROR_BDF("invalid vsi id:%d.\n",
				      vf->vsi_id[SXE2_VF_TYPE_ETH]);
			h_ret = -SXE2_VF_ERR_PARAM;
			goto l_msg_reply;
		}
		for (i = 0; i < msg->addr_cnt; i++) {
			u8 *mac_addr = msg->elem[i].addr;

			if (is_broadcast_ether_addr(mac_addr) ||
			    is_zero_ether_addr(mac_addr))
				continue;

			ret = sxe2_vf_addr_action(vf, vsi, &msg->elem[i]);
			if (ret == -EEXIST || ret == -ENOENT) {
				continue;
			} else if (ret) {
				h_ret = ret;
				break;
			}
		}
	}

l_msg_reply:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, h_ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("add:%u mac addr cnt:%u complete cnt:%u ret:%d.\n",
			      add, msg->addr_cnt, i, ret);
	return ret;
}

static s32 sxe2_addr_add_msg_func(struct sxe2_vf_node *vf,
				  struct sxe2_mbx_msg_info *msg_info)
{
	return sxe2_addr_msg_handle(vf, msg_info, true);
}

static s32 sxe2_addr_del_msg_func(struct sxe2_vf_node *vf,
				  struct sxe2_mbx_msg_info *msg_info)
{
	return sxe2_addr_msg_handle(vf, msg_info, false);
}

static s32 sxe2_addr_update_msg_func(struct sxe2_vf_node *vf,
				     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_addr_update_msg *update_msg;
	s32 ret;
	u16 old_vsi, new_vsi;
	u8 *mac_addr;
	struct sxe2_vsi *vsi;

	update_msg = (struct sxe2_vf_addr_update_msg *)(msg_info->buf +
							SXE2VF_MBX_FULL_HDR_SIZE);

	if (!sxe2_mbx_msg_vsi_id_is_valid(vf, le16_to_cpu(update_msg->vsi_id))) {
		LOG_ERROR("addr msg invalid vsi_id:%u correct vsi_id:%u.\n",
			  le16_to_cpu(update_msg->vsi_id),
			  vf->vsi_id[SXE2_VF_TYPE_ETH]);
		ret = -EPERM;
		goto l_msg_reply;
	}

	if (update_msg->to_user) {
		old_vsi = vf->vsi_id[SXE2_VF_TYPE_ETH];
		new_vsi = vf->vsi_id[SXE2_VF_TYPE_DPDK];
	} else {
		old_vsi = vf->vsi_id[SXE2_VF_TYPE_DPDK];
		new_vsi = vf->vsi_id[SXE2_VF_TYPE_ETH];
	}

	mac_addr = update_msg->addr;
	ret = sxe2_mac_rule_update(adapter, mac_addr, old_vsi, new_vsi);
	if (ret) {
		LOG_ERROR_BDF("update mac rule %pM, failed, to_user:%u, \t"
			      "old_vsi:%u,\t"
			      "new_vsi:%u, ret:%d.\n",
			      mac_addr, update_msg->to_user, old_vsi, new_vsi, ret);
		goto l_msg_reply;
	}

	if (is_unicast_ether_addr(mac_addr)) {
		vsi = sxe2_vf_vsi_get(vf, vf->vsi_id[SXE2_VF_TYPE_ETH]);
		if (!vsi) {
			LOG_ERROR_BDF("invalid vsi id:%d.\n",
				      vf->vsi_id[SXE2_VF_TYPE_ETH]);
			ret = -SXE2_VF_ERR_PARAM;
			goto l_msg_reply;
		}

		ret = sxe2_mac_spoof_rule_update(vsi, vf->dpdk_vf_vsi, mac_addr,
						 update_msg->to_user);
		if (ret) {
			LOG_ERROR_BDF("update spoofchk rule %pM, failed, \t"
				      "to_user:%u, old_vsi:%u,\t"
				      "new_vsi:%u, ret:%d.\n",
				      mac_addr, update_msg->to_user, old_vsi,
				      new_vsi, ret);
			(void)sxe2_mac_rule_update(adapter, mac_addr, new_vsi,
						   old_vsi);
		}
	}

l_msg_reply:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("update mac rule mbx msg reply failed ret:%d.\n", ret);
	return ret;
}

static s32 sxe2_promisc_update_msg_func(struct sxe2_vf_node *vf,
					struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_promisc_update_msg *update_msg;
	s32 ret;
	u16 old_vsi, new_vsi;

	update_msg = (struct sxe2_vf_promisc_update_msg *)(msg_info->buf +
							   SXE2VF_MBX_FULL_HDR_SIZE);

	if (!sxe2_mbx_msg_vsi_id_is_valid(vf, le16_to_cpu(update_msg->vsi_id))) {
		LOG_ERROR("addr msg invalid vsi_id:%u correct vsi_id:%u.\n",
			  le16_to_cpu(update_msg->vsi_id),
			  vf->vsi_id[SXE2_VF_TYPE_ETH]);
		ret = -EPERM;
		goto l_msg_reply;
	}

	if (update_msg->to_user) {
		old_vsi = vf->vsi_id[SXE2_VF_TYPE_ETH];
		new_vsi = vf->vsi_id[SXE2_VF_TYPE_DPDK];
	} else {
		old_vsi = vf->vsi_id[SXE2_VF_TYPE_DPDK];
		new_vsi = vf->vsi_id[SXE2_VF_TYPE_ETH];
	}

	if (update_msg->is_promisc) {
		ret = sxe2_promisc_rule_update(adapter, old_vsi, new_vsi);
		if (ret) {
			LOG_ERROR_BDF("update promisc rule failed, to_user:%u, \t"
				      "old_vsi:%u, \t"
				      "new_vsi:%u, ret:%d.\n",
				      update_msg->to_user, old_vsi, new_vsi, ret);
		}
	} else {
		ret = sxe2_allmulti_rule_update(adapter, old_vsi, new_vsi);
		if (ret) {
			LOG_ERROR_BDF("update allmulti rule failed, to_user:%u, \t"
				      "old_vsi:%u, \t"
				      "new_vsi:%u, ret:%d.\n",
				      update_msg->to_user, old_vsi, new_vsi, ret);
		}
	}

l_msg_reply:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("update promisc or aullmulti rule mbx msg reply \t"
			      "failed ret:%d.\n",
			      ret);
	return ret;
}

static s32 sxe2_vf_vlan_add(struct sxe2_vf_node *vf, struct sxe2_vsi *vsi,
			    struct sxe2_vf_vlan *vlan_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret;
	struct sxe2_vlan vlan = {0};

	vlan.tpid = le16_to_cpu(vlan_info->tpid);
	vlan.vid = le16_to_cpu(vlan_info->vid);

	if (vf->vlan_info.vlan_cnt >=
	    (vf->prop.trusted ? VLAN_N_VID : SXE2_VF_VLAN_CNT_MAX))
		return -EIO;
	ret = sxe2_vlan_rule_add(vsi, &vlan);
	if (ret == -EEXIST) {
		ret = 0;
	} else if (ret) {
		LOG_DEV_ERR("Failed to add vlan tpid:0x%x vid:%u for VF %d, error \t"
			    "%d\n",
			    vlan.tpid, vlan.vid, vf->vf_idx, ret);
		goto l_out;
	} else {
		if (vsi->type != SXE2_VSI_T_DPDK_VF || vlan.vid != 0)
			vf->vlan_info.vlan_cnt++;
	}

	LOG_INFO_BDF("vf:%u vlan tpid:0x%x vid:0x%x added vlan_cnt:%u.\n",
		     vf->vf_idx, vlan.tpid, vlan.vid, vf->vlan_info.vlan_cnt);
l_out:
	return ret;
}

static s32 sxe2_vf_vlan_del(struct sxe2_vf_node *vf, struct sxe2_vsi *vsi,
			    struct sxe2_vf_vlan *vlan_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret;
	struct sxe2_vlan vlan = {0};

	vlan.tpid = le16_to_cpu(vlan_info->tpid);
	vlan.vid = le16_to_cpu(vlan_info->vid);

	ret = sxe2_vlan_rule_del(adapter, vsi->idx_in_dev, &vlan);
	if (ret == -ENOENT) {
		ret = 0;
	} else if (ret) {
		LOG_DEV_ERR("Failed to del vlan tpid:0x%x vid:%u for VF %d, error \t"
			    "%d\n",
			    vlan.tpid, vlan.vid, vf->vf_idx, ret);
		goto l_out;
	} else {
		if (vsi->type != SXE2_VSI_T_DPDK_VF || vlan.vid != 0)
			vf->vlan_info.vlan_cnt--;
	}

	LOG_INFO_BDF("vf:%u vlan tpid:0x%x vid:0x%x deleted vlan_cnt:%u.\n",
		     vf->vf_idx, vlan.tpid, vlan.vid, vf->vlan_info.vlan_cnt);

l_out:
	return ret;
}

static s32 sxe2_user_vlan_msg_func(struct sxe2_vf_node *vf,
				   struct sxe2_mbx_msg_info *msg_info)
{
	s32 (*sxe2_vf_vlan_action)(struct sxe2_vf_node *vf, struct sxe2_vsi *vsi,
				   struct sxe2_vf_vlan *vlan);
	s32 h_ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	struct sxe2_vf_user_vlan_msg *msg =
		(struct sxe2_vf_user_vlan_msg *)(msg_info->buf +
						 SXE2VF_MBX_FULL_HDR_SIZE);
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	u64 sesstion_id = le64_to_cpu(cmd_hdr->session_id);
	s32 ret;

	if (msg->is_add && sxe2_port_vlan_is_exist(vf)) {
		LOG_WARN_BDF("vf %u has set port vlan, not support add vlan rule.\n",
			     vf->vf_idx);
		h_ret = SXE2_VF_ERR_SUCCESS;
		goto l_msg_reply;
	}

	if (msg->is_add)
		sxe2_vf_vlan_action = sxe2_vf_vlan_add;
	else
		sxe2_vf_vlan_action = sxe2_vf_vlan_del;

	ret = sxe2_vf_vlan_action(vf, vf->dpdk_vf_vsi, &msg->vlan);
	if (ret != -EEXIST && ret != -ENOENT)
		h_ret = ret;

l_msg_reply:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, sesstion_id, h_ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("add:%u, vid:%u, tpid:%u, ret:%d.\n", msg->is_add,
			      msg->vlan.vid, msg->vlan.tpid, ret);
	return ret;
}

static s32 sxe2_repr_addr_update_msg_func(struct sxe2_vf_node *vf,
					  struct sxe2_mbx_msg_info *msg_info)
{
	s32 h_ret = -EPERM;
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	s32 ret;

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, h_ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("repr update mac rule mbx msg \t"
			      "reply failed ret:%d.\n",
			      ret);
	return ret;
}

static s32 sxe2_repr_promisc_update_msg_func(struct sxe2_vf_node *vf,
					     struct sxe2_mbx_msg_info *msg_info)
{
	s32 h_ret = -EPERM;
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	s32 ret;

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, h_ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("repr update peomisc rule mbx msg \t"
			      "reply failed ret:%d.\n",
			      ret);
	return ret;
}

static bool sxe2_qps_dis_msg_is_valid(struct sxe2_vf_node *vf,
				      struct sxe2_vf_qps_dis_msg *dis_msg)
{
	struct sxe2_vsi *vsi;
	struct sxe2_adapter *adapter = vf->adapter;

	vsi = sxe2_vf_vsi_get(vf, le16_to_cpu(dis_msg->vsi_id));
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", le16_to_cpu(dis_msg->vsi_id));
		return false;
	}

	if ((le16_to_cpu(dis_msg->qps_cnt) > vsi->rxqs.q_cnt) || !dis_msg->qps_cnt) {
		LOG_ERROR_BDF("msg qps cnt:%u invalid max:%u.\n", dis_msg->qps_cnt,
			      vsi->rxqs.q_cnt);
		return false;
	}

	if (!sxe2_mbx_msg_vsi_id_is_valid(vf, le16_to_cpu(dis_msg->vsi_id))) {
		LOG_ERROR_BDF("msg vsi_id:%u invalid vf[%u] extract vsi_id:%u.\n",
			      le16_to_cpu(dis_msg->vsi_id), vf->vf_idx,
			      vsi->idx_in_dev);
		return false;
	}

	return true;
}

STATIC s32 sxe2_queues_dis_msg_func(struct sxe2_vf_node *vf,
				    struct sxe2_mbx_msg_info *msg_info)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi = NULL;
	struct sxe2_vf_qps_dis_msg *dis_msg =
			(struct sxe2_vf_qps_dis_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);

	if (!sxe2_qps_dis_msg_is_valid(vf, dis_msg)) {
		ret = -SXE2_VF_ERR_PARAM;
		goto l_err_reply;
	}

	vsi = sxe2_vf_vsi_get(vf, le16_to_cpu(dis_msg->vsi_id));
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", le16_to_cpu(dis_msg->vsi_id));
		ret = -SXE2_VF_ERR_PARAM;
		goto l_err_reply;
	}

	if (sxe2_txqs_stop(vsi)) {
		ret = -SXE2_VF_ERR_PARAM;
		LOG_ERROR_BDF("vsi:%u txqs disable failed.\n", vsi->idx_in_dev);
	}

	if (sxe2_rxqs_stop(vsi)) {
		ret = -SXE2_VF_ERR_PARAM;
		LOG_ERROR_BDF("vsi:%u rxqs disable failed.\n", vsi->idx_in_dev);
	}

l_err_reply:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	(void)sxe2_mbx_msg_reply(adapter, &params);
	return ret;
}

STATIC s32 sxe2_txq_dis_msg_func(struct sxe2_vf_node *vf,
				 struct sxe2_mbx_msg_info *msg_info)
{
	s32 ret = 0;
	struct sxe2_vf_q_stop_msg *req =
			(struct sxe2_vf_q_stop_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_txq_ucmd_dis_params txq_params;

	txq_params.q_idx = le16_to_cpu(req->q_idx);
	txq_params.vsi_id = le16_to_cpu(req->vsi_id);
	txq_params.sched_mode = SXE2_UCMD_TXQ_MODE_DEFAULT;
	ret = sxe2_txq_dis_common_handle(adapter, &txq_params);
	if (ret)
		LOG_ERROR_BDF("usr vsi[%d] txq[%d] dis failed\n", txq_params.vsi_id,
			      txq_params.q_idx);
	else
		LOG_INFO_BDF("usr vsi[%d] txq[%d] dis success\n", txq_params.vsi_id,
			     txq_params.q_idx);

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	(void)sxe2_mbx_msg_reply(adapter, &params);
	return ret;
}

STATIC s32 sxe2_rxq_dis_msg_func(struct sxe2_vf_node *vf,
				 struct sxe2_mbx_msg_info *msg_info)
{
	s32 ret = 0;
	struct sxe2_vf_q_stop_msg *dis_msg =
			(struct sxe2_vf_q_stop_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_rxq_dis_params dis_params = {};

	dis_params.q_idx = le16_to_cpu(dis_msg->q_idx);
	dis_params.vsi_id = le16_to_cpu(dis_msg->vsi_id);

	ret = sxe2_rxq_disable_common_handle(adapter, &dis_params);

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);

	return ret;
}

STATIC s32 sxe2_ptp_get_time_msg_func(struct sxe2_vf_node *vf,
				      struct sxe2_mbx_msg_info *msg_info)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_ptp_clock_res res = {0};
	struct timespec64 hwts;

	if (!sxe2_ptp_primary_timer_read(adapter, &hwts)) {
		LOG_ERROR_BDF("failed to read 1588 timer.\n");
		ret = -EIO;
		goto l_end;
	}
	res.clock_ns = cpu_to_le32((u32)hwts.tv_nsec);
	res.clock_s = cpu_to_le64((u64)hwts.tv_sec);
l_end:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, &res,
				       SXE2_CALC_RESP_LEN(res, cmd_hdr->tran_out_len), vf->vf_idx,
				       session_id, ret);
	(void)sxe2_mbx_msg_reply(adapter, &params);
	return 0;
}

static s32 sxe2_aux_rdma_msg_handler(struct sxe2_adapter *adapter, u16 vf_id,
				     u8 *msg, u16 len, u64 session_id)
{
	struct aux_core_dev_info *cdev_info = &adapter->aux_ctxt.cdev_info;
	struct sxe2_auxiliary_drv *iadrv;
	s32 ret = -ENODEV;
	struct sxe2_cmd_params params = {0};

	mutex_lock(&adapter->aux_ctxt.adev_mutex);
	if (!cdev_info->adev) {
		mutex_unlock(&adapter->aux_ctxt.adev_mutex);
		LOG_WARN_BDF("adev null, vf:%u sid:0x%llx no need handler.\n", vf_id,
			     session_id);
		return 0;
	}
	device_lock(&cdev_info->adev->dev);
	iadrv = sxe2_rdma_aux_drv_get(cdev_info);
	if (iadrv && iadrv->aux_ops.vc_receive)
		ret = iadrv->aux_ops.vc_receive(cdev_info, vf_id, msg, len,
						session_id);
	device_unlock(&cdev_info->adev->dev);

	mutex_unlock(&adapter->aux_ctxt.adev_mutex);
	if (ret) {
		LOG_ERROR_BDF("failed to send message to rdma pf.\n");
		sxe2_mbx_msg_reply_params_fill(&params, SXE2_VF_RDMA, NULL, 0, vf_id,
					       session_id, ret);
		return sxe2_mbx_msg_reply(adapter, &params);
	}
	return ret;
}

static s32 sxe2_rdma_msg_func(struct sxe2_vf_node *vf,
			      struct sxe2_mbx_msg_info *msg_info)
{
	s32 ret;
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);

	ret = sxe2_aux_rdma_msg_handler(adapter, vf->vf_idx, msg_info->buf,
					msg_info->msg_len, session_id);

	return ret;
}

s32 sxe2_aux_reply_rdma_msg_to_vf(struct sxe2_adapter *adapter, u16 vf_id, u8 *msg,
				  u16 len, u64 session_id)
{
	struct sxe2_cmd_params params = {0};

	sxe2_mbx_msg_reply_params_fill(&params, SXE2_VF_RDMA, msg, len, vf_id,
				       session_id, 0);
	return sxe2_mbx_msg_reply(adapter, &params);
}

static s32 sxe2_qv_map_unmap_params_chk(const struct sxe2_vf_node *vf,
					const struct aux_qvlist_info *qvlist)
{
	u32 i;
	s32 ret = 0;
	struct sxe2_adapter *adapter = vf->adapter;
	u32 num_msix_per_vf = adapter->vf_ctxt.irq_cnt;
	const struct aux_qv_info *qv_info;

	for (i = 0; i < qvlist->num_vectors; i++) {
		qv_info = &qvlist->qv_info[i];
		if (qv_info->v_idx >= num_msix_per_vf)
			goto err;

		if (qv_info->ceq_idx == SXE2_RDMA_VCHNL_Q_INVALID_IDX &&
		    qv_info->aeq_idx == SXE2_RDMA_VCHNL_Q_INVALID_IDX)
			goto err;
		if (qv_info->aeq_idx != SXE2_RDMA_VCHNL_Q_INVALID_IDX &&
		    qv_info->aeq_idx >= num_msix_per_vf)
			goto err;
	}
	goto end;
err:
	LOG_INFO_BDF("rdma map params invalid.(vf:%d num_vectors:%d irq cnt:%d \t"
		     "v_idx:%d aeq_idx:%d ceq_idx:%d)\n",
		     vf->vf_idx, qvlist->num_vectors, num_msix_per_vf,
		     qv_info->v_idx, qv_info->aeq_idx, qv_info->ceq_idx);
	ret = -SXE2_VF_ERR_PARAM;
end:

	return ret;
}

STATIC s32 sxe2_qv_map_unmap_msg_func(struct sxe2_vf_node *vf,
				      struct sxe2_mbx_msg_info *msg_info)
{
	const struct sxe2_vf_ops *ops = vf->vf_ops;
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	u32 i;
	s32 ret = SXE2_VF_ERR_SUCCESS;

	struct aux_qvlist_info *qv_map_msg =
		(struct aux_qvlist_info *)(msg_info->buf +
					   SXE2VF_MBX_DATA_OFFSET(msg_info->buf));

	ret = sxe2_qv_map_unmap_params_chk(vf, qv_map_msg);
	if (ret)
		goto reply;

	for (i = 0; i < qv_map_msg->num_vectors; i++) {
		struct aux_qv_info *qv_info = &qv_map_msg->qv_info[i];

		if (msg_info->opcode == SXE2_VF_QV_MAP)
			ops->cfg_rdma_irq_map(vf, qv_info);
		else
			ops->clear_rdma_irq_map(vf, qv_info);
	}

reply:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);

	return sxe2_mbx_msg_reply(adapter, &params);
}

static s32 sxe2_vf_rdma_mgr_msg_func(struct sxe2_vf_node *vf,
				     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_vf_rdma_mgr_cmd_msg *auxmgr_msg =
			(struct sxe2_vf_rdma_mgr_cmd_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_FULL_HDR_SIZE);
	u8 *recv_msg;
	u16 recv_len = (u16)auxmgr_msg->resv_len;
	u32 opcode;

	recv_msg = kzalloc(recv_len, GFP_KERNEL);
	if (!recv_msg) {
		LOG_INFO_BDF("memory not enough! buffer is nullptr.\n");
		return -ENOMEM;
	}

	opcode = auxmgr_msg->opcode;

	ret = sxe2_rdma_msg_send(adapter, opcode, auxmgr_msg->msg,
				 (u16)auxmgr_msg->msg_len, recv_msg, recv_len);

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, (void *)recv_msg,
				       recv_len, vf->vf_idx, session_id, ret);

	ret = sxe2_mbx_msg_reply(adapter, &params);
	kfree(recv_msg);
	return ret;
}

STATIC s32 sxe2_promisc_cfg_msg_func(struct sxe2_vf_node *vf,
				     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_vsi *vsi;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_vf_promisc_msg *promisc_msg =
			(struct sxe2_vf_promisc_msg *)(msg_info->buf +
						       SXE2VF_MBX_FULL_HDR_SIZE);
	u32 promisc_flags = le32_to_cpu(promisc_msg->flags);
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);

	if (promisc_msg->is_user)
		vsi = vf->dpdk_vf_vsi;
	else
		vsi = vf->vsi;

	if (!vsi) {
		ret = -SXE2_VF_ERR_PARAM;
		goto l_end;
	}

	if (!sxe2_vf_is_trusted(vf)) {
		LOG_INFO_BDF("Untrusted vf %d is attempting to configure \t"
			     "promiscuous mode\n",
			     vf->vf_idx);
		goto l_end;
	}

	if (promisc_flags & SXE2_VF_PROMISC_MULTICAST) {
		ret = sxe2_allmulti_rule_add(vsi);
		if (ret && ret != -EEXIST)
			LOG_ERROR_BDF("add allmulti filter failed, ret %d\n", ret);
	} else {
		ret = sxe2_allmulti_rule_del(adapter, vsi->idx_in_dev);
		if (ret && ret != -ENOENT)
			LOG_ERROR_BDF("delete allmulti filter failed, ret %d\n",
				      ret);
	}

	if (promisc_flags & SXE2_VF_PROMISC) {
		ret = sxe2_promisc_rule_add(vsi);
		if (ret && ret != -EEXIST) {
			LOG_ERROR_BDF("add promisc filter failed, ret %d\n", ret);
			goto l_end;
		}
		if (!sxe2_port_vlan_is_exist(vf))
			(void)sxe2_vlan_filter_control(adapter, vsi->idx_in_dev,
						       false);

	} else {
		ret = sxe2_promisc_rule_del(adapter, vsi->idx_in_dev);
		if (ret && ret != -ENOENT) {
			LOG_ERROR_BDF("delete promisc filter failed, ret %d\n", ret);
			goto l_end;
		}
		if (!sxe2_port_vlan_is_exist(vf) &&
		    (promisc_flags & SXE2_VF_VLAN_FILTER))
			(void)sxe2_vlan_filter_control(adapter, vsi->idx_in_dev,
						       true);
	}
l_end:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, 0);

	return sxe2_mbx_msg_reply(adapter, &params);
}

STATIC s32 sxe2_vlan_offload_cfg_msg_func(struct sxe2_vf_node *vf,
					  struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_vf_vlan_offload_cfg *vlan_cfg =
			(struct sxe2_vf_vlan_offload_cfg
					 *)(msg_info->buf +
					    SXE2VF_MBX_FULL_HDR_SIZE);
	struct sxe2_hw *hw = &vf->adapter->hw;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	s32 ret = 0;
	bool port_vlan_exist = sxe2_port_vlan_is_exist(vf);

	if ((vlan_cfg->ctag_strip_enable != SXE2_VF_VLAN_STATUS_INVALID &&
	     sxe2_hw_desc_vlan_param_check(port_vlan_exist, true, ETH_P_8021Q)) ||
	    (vlan_cfg->stag_strip_enable != SXE2_VF_VLAN_STATUS_INVALID &&
	     sxe2_hw_desc_vlan_param_check(port_vlan_exist, true, ETH_P_8021AD)) ||
	    (vlan_cfg->ctag_insert_enable != SXE2_VF_VLAN_STATUS_INVALID &&
	     sxe2_hw_desc_vlan_param_check(port_vlan_exist, false, ETH_P_8021Q)) ||
	    (vlan_cfg->stag_insert_enable != SXE2_VF_VLAN_STATUS_INVALID &&
	     sxe2_hw_desc_vlan_param_check(port_vlan_exist, false, ETH_P_8021AD))) {
		ret = -SXE2_VF_ERR_HANDLE_ERROR;
		goto l_reply;
	}

	if (vlan_cfg->ctag_strip_enable != SXE2_VF_VLAN_STATUS_INVALID) {
		(void)sxe2_hw_desc_vlan_strip_switch(hw,
						     vf->vsi_id[SXE2_VF_TYPE_ETH],
						     ETH_P_8021Q,
						     port_vlan_exist,
						     vlan_cfg->ctag_strip_enable);
	}

	if (vlan_cfg->stag_strip_enable != SXE2_VF_VLAN_STATUS_INVALID) {
		(void)sxe2_hw_desc_vlan_strip_switch(hw,
						     vf->vsi_id[SXE2_VF_TYPE_ETH],
						     ETH_P_8021AD,
						     port_vlan_exist,
						     vlan_cfg->stag_strip_enable);
	}

	if (vlan_cfg->ctag_insert_enable != SXE2_VF_VLAN_STATUS_INVALID ||
	    vlan_cfg->stag_insert_enable != SXE2_VF_VLAN_STATUS_INVALID) {
		if (!vlan_cfg->ctag_insert_enable) {
			(void)sxe2_hw_desc_vlan_insert_switch(hw,
							      vf->vsi_id[SXE2_VF_TYPE_ETH],
							      ETH_P_8021Q, port_vlan_exist,
							      vlan_cfg->ctag_insert_enable);
		} else if (!vlan_cfg->stag_insert_enable) {
			(void)sxe2_hw_desc_vlan_insert_switch(hw,
							      vf->vsi_id[SXE2_VF_TYPE_ETH],
							      ETH_P_8021AD, port_vlan_exist,
							      vlan_cfg->stag_insert_enable);
		}

		if (vlan_cfg->ctag_insert_enable) {
			(void)sxe2_hw_desc_vlan_insert_switch(hw,
							      vf->vsi_id[SXE2_VF_TYPE_ETH],
							      ETH_P_8021Q, port_vlan_exist,
							      vlan_cfg->ctag_insert_enable);
		} else if (vlan_cfg->stag_insert_enable) {
			(void)sxe2_hw_desc_vlan_insert_switch(hw,
							      vf->vsi_id[SXE2_VF_TYPE_ETH],
							      ETH_P_8021AD, port_vlan_exist,
							      vlan_cfg->stag_insert_enable);
		}
	}
l_reply:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, 0);

	ret = sxe2_mbx_msg_reply(vf->adapter, &params);

	return ret;
}

STATIC s32 sxe2_vlan_filter_cfg_msg_func(struct sxe2_vf_node *vf,
					 struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_vf_vlan_filter_cfg *filter_cfg =
			(struct sxe2_vf_vlan_filter_cfg *)(msg_info->buf +
							   SXE2VF_MBX_FULL_HDR_SIZE);
	struct sxe2_cmd_params params = {0};
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	s32 ret = 0;
	u16 vsi_id_indev;

	if (filter_cfg->is_user)
		vsi_id_indev = vf->vsi_id[SXE2_VF_TYPE_DPDK];
	else
		vsi_id_indev = vf->vsi_id[SXE2_VF_TYPE_ETH];

	ret = sxe2_vlan_filter_control(adapter, vsi_id_indev,
				       filter_cfg->ctag_filter_enable);
	if (ret)
		LOG_ERROR_BDF("vf:%u vlan filter cfg to %u fail.\n", vf->vf_idx,
			      filter_cfg->ctag_filter_enable);

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, 0);

	ret = sxe2_mbx_msg_reply(adapter, &params);

	return ret;
}

static bool sxe2_vlan_msg_is_valid(struct sxe2_vf_node *vf,
				   struct sxe2_vf_vlan_filter_msg *msg, bool add)
{
	return true;
}

static s32 sxe2_vlan_msg_handle(struct sxe2_vf_node *vf,
				struct sxe2_mbx_msg_info *msg_info, bool add)
{
	s32 (*sxe2_vf_vlan_action)(struct sxe2_vf_node *vf, struct sxe2_vsi *vsi,
				   struct sxe2_vf_vlan *vlan);
	s32 h_ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	struct sxe2_vf_vlan_filter_msg *msg =
			(struct sxe2_vf_vlan_filter_msg *)(msg_info->buf +
							   SXE2VF_MBX_FULL_HDR_SIZE);
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vlan vlan = {0};
	u64 sesstion_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vsi *vsi;
	u32 i = 0;
	s32 ret;

	if (add && sxe2_port_vlan_is_exist(vf)) {
		LOG_WARN_BDF("vf %u has set port vlan, not support add vlan rule.\n",
			     vf->vf_idx);
		h_ret = SXE2_VF_ERR_SUCCESS;
		goto l_msg_reply;
	}

	if (add)
		sxe2_vf_vlan_action = sxe2_vf_vlan_add;
	else
		sxe2_vf_vlan_action = sxe2_vf_vlan_del;

	if (!sxe2_vlan_msg_is_valid(vf, msg, add)) {
		h_ret = -EINVAL;
		goto l_msg_reply;
	}

	vsi = sxe2_vf_vsi_get(vf, vf->vsi_id[SXE2_VF_TYPE_ETH]);
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", vf->vsi_id[SXE2_VF_TYPE_ETH]);
		h_ret = -SXE2_VF_ERR_PARAM;
		goto l_msg_reply;
	}

	for (i = 0; i < le16_to_cpu(msg->vlan_cnt); i++) {
		vlan.tpid = le16_to_cpu(msg->elem[i].tpid);
		vlan.vid = le16_to_cpu(msg->elem[i].vid);
		if (vlan.vid == 0 && vlan.tpid == ETH_P_8021Q)
			continue;
		ret = sxe2_vf_vlan_action(vf, vsi, &msg->elem[i]);
		if (ret == -EEXIST || ret == -ENOENT) {
			continue;
		} else if (ret) {
			h_ret = ret;
			break;
		}
	}

l_msg_reply:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, sesstion_id, h_ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("add:%u vlan addr cnt:%u complete cnt:%u ret:%d.\n",
			      add, msg->vlan_cnt, i, ret);
	return ret;
}

STATIC s32 sxe2_vlan_add_msg_func(struct sxe2_vf_node *vf,
				  struct sxe2_mbx_msg_info *msg_info)
{
	return sxe2_vlan_msg_handle(vf, msg_info, true);
}

STATIC s32 sxe2_vlan_del_msg_func(struct sxe2_vf_node *vf,
				  struct sxe2_mbx_msg_info *msg_info)
{
	return sxe2_vlan_msg_handle(vf, msg_info, false);
}

static s32 sxe2_link_msg_func(struct sxe2_vf_node *vf,
			      struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_link_msg link_msg;
	s32 ret;

	link_msg.status = (u8)sxe2_vf_is_link_up(vf);
	if (link_msg.status)
		link_msg.speed = sxe2_speed_get(vf);
	else
		link_msg.speed = SXE2_LINK_SPEED_UNKNOWN;

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, &link_msg,
				       SXE2_CALC_RESP_LEN(link_msg, cmd_hdr->tran_out_len),
				       vf->vf_idx, session_id, 0);
	ret = sxe2_mbx_msg_reply(adapter, &params);

	LOG_INFO_BDF("vf:%u link speed:%u link_up:%u.(ret:%d).\n", vf->vf_idx,
		     link_msg.speed, link_msg.status, ret);

	return ret;
}

static s32 sxe2_vf_ethtool_info_get_msg_func(struct sxe2_vf_node *vf,
					     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_msg_ethtool_info ethtool_info;
	s32 ret;
	struct flm_link_info_pasist pasist_info;

	(void)memset(&ethtool_info, 0, sizeof(struct sxe2_msg_ethtool_info));

	ret = sxe2_get_link_configure(adapter, &ethtool_info.cfg);
	if (ret) {
		ethtool_info.cfg.optical_module.current_connection =
				SXE2_FW_CONNECT_MDDE_UNKNOWN;
		LOG_ERROR_BDF("failed to link cfg, ret=%d\n", ret);
	}

	ret = sxe2_get_support_speed_ability(adapter, &ethtool_info.ability);
	if (ret)
		LOG_ERROR_BDF("failed to get  speed_ability, ret=%d\n", ret);

	pasist_info.speed = FLM_FW_SPEED_AUTO;
	ret = sxe2_link_get_pasist_info(adapter, &pasist_info);
	if (ret)
		LOG_ERROR_BDF("failed to get  speed_ability, ret=%d\n", ret);
	ethtool_info.usr_link_speed = pasist_info.speed;

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, &ethtool_info,
				       sizeof(struct sxe2_msg_ethtool_info),
				       vf->vf_idx, session_id, 0);
	ret = sxe2_mbx_msg_reply(adapter, &params);

	LOG_INFO_BDF("vf:%u get ethtool info.(ret:%d).\n", vf->vf_idx, ret);

	return ret;
}

static s32 sxe2_vf_vsi_cfg_msg_check(struct sxe2_vf_node *vf_node,
				     struct sxe2_vsi_cfg_params *params)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vf_node->adapter;

	if (params->irq_base_idx >= adapter->irq_ctxt.irq_layout.sriov ||
	    params->irq_cnt > adapter->irq_ctxt.irq_layout.sriov ||
	    params->txq_base_idx >= adapter->q_ctxt.txq_layout.sriov ||
	    params->txq_cnt > adapter->q_ctxt.txq_layout.sriov ||
	    params->rxq_base_idx >= adapter->q_ctxt.txq_layout.sriov ||
	    params->rxq_cnt > adapter->q_ctxt.rxq_layout.sriov ||
	    params->vsi_id >=
	     (adapter->vsi_ctxt.max_cnt + adapter->vsi_ctxt.base_idx_in_dev) ||
	    params->vsi_id < adapter->vsi_ctxt.base_idx_in_dev) {
		ret = -EINVAL;
		LOG_ERROR_BDF("irq_base:%u irq_cnt:%u txq_base:%u txq_cnt:%u\t"
			      "rxq_base:%u rxq_cnt:%u vsi id:%u max:%u base:%u\t"
			      "sriov irq cnt:%u txq cnt:%u rxq cnt:%u ret:%d.\n",
			      params->irq_base_idx, params->irq_cnt,
			      params->txq_base_idx, params->txq_cnt,
			      params->rxq_base_idx, params->rxq_cnt, params->vsi_id,
			      adapter->vsi_ctxt.max_cnt,
			      adapter->vsi_ctxt.base_idx_in_dev,
			      adapter->irq_ctxt.irq_layout.sriov,
			      adapter->q_ctxt.txq_layout.sriov,
			      adapter->q_ctxt.rxq_layout.sriov, ret);
	}

	return ret;
}

STATIC s32 sxe2_vf_vsi_rule_cfg(struct sxe2_adapter *adapter,
				struct sxe2_vf_node *vf_node, struct sxe2_vsi *vsi)
{
	s32 ret = 0;

	sxe2_vf_trust_cfg_restore(vf_node);

	if (!sxe2_eswitch_is_offload(adapter) && vsi->type == SXE2_VSI_T_VF) {
		ret = sxe2_vf_base_l2_filter_setup(vf_node, vsi);
		if (ret) {
			LOG_ERROR("vf:%u vsi %u base l2 filter setup fail %d.\n",
				  vf_node->vf_idx, vsi->idx_in_dev, ret);
			return ret;
		}
	} else if (!sxe2_eswitch_is_offload(adapter) &&
		   vsi->type == SXE2_VSI_T_DPDK_VF &&
		   sxe2_port_vlan_is_exist(vf_node)) {
		ret = sxe2_vf_vsi_port_vlan_cfg(vf_node, vsi);
		if (ret) {
			LOG_ERROR("vf:%u vsi %u port vlan cfg fail %d.\n",
				  vf_node->vf_idx, vsi->idx_in_dev, ret);
			return ret;
		}
	} else if (sxe2_eswitch_is_offload(adapter) &&
		   vsi->type == SXE2_VSI_T_DPDK_VF) {
		ret = sxe2_vf_sp_rule_add(vf_node, true);
		if (ret) {
			LOG_ERROR("vf:%u vsi %u sp rule add fail %d.\n",
				  vf_node->vf_idx, vsi->idx_in_dev, ret);
			return ret;
		}
	}
	return ret;
}

STATIC s32 __sxe2_vf_vsi_cfg(struct sxe2_vf_node *vf_node,
			     struct sxe2_vf_vsi_cfg *cfg_info)
{
	struct sxe2_vsi_cfg_params params = {};
	struct sxe2_adapter *adapter = vf_node->adapter;
	struct sxe2_vsi *vsi;
	s32 ret;

	params.vsi_id = le16_to_cpu(cfg_info->vsi_id);
	params.irq_base_idx = le16_to_cpu(cfg_info->irq_base_idx);
	params.irq_cnt = le16_to_cpu(cfg_info->irq_cnt);
	params.txq_base_idx = le16_to_cpu(cfg_info->txq_base_idx);
	params.txq_cnt = le16_to_cpu(cfg_info->txq_cnt);
	params.rxq_base_idx = le16_to_cpu(cfg_info->rxq_base_idx);
	params.rxq_cnt = le16_to_cpu(cfg_info->rxq_cnt);

	ret = sxe2_vf_vsi_cfg_msg_check(vf_node, &params);
	if (ret) {
		LOG_ERROR_BDF("vf_idx:%u vsi create param check fail.\n",
			      vf_node->vf_idx);
		return ret;
	}

	ret = sxe2_vf_vsi_type_get(vf_node, params.vsi_id, &params.type);
	if (ret) {
		LOG_ERROR_BDF("vf_idx:%u vsi type get fail.\n", vf_node->vf_idx);
		return ret;
	}

	sxe2_vf_vsi_destroy_by_id(vf_node, params.vsi_id);

	params.vf = vf_node;
	vsi = sxe2_vsi_create(adapter, &params);
	if (!vsi) {
		LOG_ERROR_BDF("vf_idx:%u vsi create fail.\n", vf_node->vf_idx);
		return -ENOMEM;
	}

	LOG_INFO_BDF("vf[%u] hw vsi_id:%u type:%d vsi irq cnt:%u vsi queue \t"
		     "cnt:%u.\n",
		     vf_node->vf_idx, vsi->idx_in_dev, vsi->type, vsi->irqs.cnt,
		     vsi->rxqs.q_cnt);

	if (params.type == SXE2_VSI_T_VF) {
		vf_node->vsi = vsi;
		if (vf_node->repr) {
			vf_node->repr->src_vsi = vsi;
			vf_node->repr->vf_idx = vf_node->vf_idx;
		}

	} else if (params.type == SXE2_VSI_T_DPDK_VF) {
		vf_node->dpdk_vf_vsi = vsi;
		if (vf_node->repr) {
			vf_node->repr->dpdk_vf_vsi = vsi;
			vf_node->repr->vf_idx = vf_node->vf_idx;
			LOG_ERROR_BDF("dpdk_vf_vsi vsi id:%u.\n", vsi->idx_in_dev);
		}
	}
	ret = sxe2_vf_vsi_rule_cfg(adapter, vf_node, vsi);
	if (ret) {
		LOG_ERROR_BDF("vf[%u] hw vsi_id:%u type:%d rule cfg failed.\n",
			      vf_node->vf_idx, vsi->idx_in_dev, vsi->type);
		sxe2_vf_vsi_destroy_by_id(vf_node, params.vsi_id);
		goto l_end;
	}

l_end:

	return ret;
}

STATIC s32 __sxe2_vf_vsi_decfg(struct sxe2_vf_node *vf_node,
			       struct sxe2_vf_vsi_cfg *cfg_info)
{
	struct sxe2_adapter *adapter = vf_node->adapter;
	u16 vsi_id = le16_to_cpu(cfg_info->vsi_id);
	s32 ret = 0;

	sxe2_vf_vsi_destroy_by_id(vf_node, vsi_id);

	LOG_INFO_BDF("vf:%d vsi_id:%d vsi destroyed.\n", vf_node->vf_idx, vsi_id);

	return ret;
}

static s32 sxe2_vf_vsi_cfg_msg_func(struct sxe2_vf_node *vf,
				    struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_vsi_cfg *vsi_cfg =
		(struct sxe2_vf_vsi_cfg *)(msg_info->buf +
					   SXE2VF_MBX_DATA_OFFSET(msg_info->buf));

	s32 ret;

	if (vsi_cfg->is_clear)
		ret = __sxe2_vf_vsi_decfg(vf, vsi_cfg);
	else
		ret = __sxe2_vf_vsi_cfg(vf, vsi_cfg);

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	return sxe2_mbx_msg_reply(adapter, &params);
}

static s32 sxe2_vf_user_driver_vsi_release(struct sxe2_vf_node *vf)
{
	struct sxe2_vsi *vsi = NULL;
	s32 ret = 0;
	struct sxe2_adapter *adapter = vf->adapter;

	vsi = sxe2_vf_vsi_get(vf, vf->vsi_id[SXE2_VF_TYPE_DPDK]);
	if (!vsi) {
		ret = -SXE2_VF_ERR_PARAM;
		LOG_ERROR_BDF("invalid vsi id:%d.\n", vf->vsi_id[SXE2_VF_TYPE_DPDK]);
		return ret;
	}

	LOG_INFO_BDF("dpdk release vsi:%u txqs disable start.\n", vsi->idx_in_dev);

	if (sxe2_txqs_stop(vsi))
		LOG_DEV_ERR("vsi:%u txqs disable failed.\n", vsi->idx_in_dev);

	if (sxe2_rxqs_stop(vsi))
		LOG_DEV_ERR("vsi:%u rxqs disable failed.\n", vsi->idx_in_dev);

	sxe2_vf_dpdk_cfg_clear(vf, true);

	return ret;
}

static s32 sxe2_vf_user_driver_release_msg_func(struct sxe2_vf_node *vf,
						struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_user_driver_release *release =
			(struct sxe2_vf_user_driver_release
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	s32 ret = 0;
	struct sxe2_obj obj = {0};

	(void)sxe2_vf_user_driver_vsi_release(vf);

	obj.func_type = SXE2_VF;
	obj.vf_id = release->func_id;
	obj.drv_type = SXE2_DPDK_DRV;
	obj.drv_id = release->drv_id;
	if (sxe2_dpdk_ipsec_resource_release(adapter, &obj))
		LOG_DEV_ERR("func[%u] drv[%u] ipsec clear failed.\n", obj.vf_id,
			    (obj.drv_type << 6 | obj.drv_id));

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	return sxe2_mbx_msg_reply(adapter, &params);
}

STATIC s32 sxe2_rss_key_get_msg_func(struct sxe2_vf_node *vf,
				     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	u8 *key_msg = NULL;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);

	if (!vsi) {
		LOG_ERROR_BDF("vsi is null!\n");
		ret = -SXE2_VF_ERR_PARAM;
		goto l_err;
	}

	key_msg = kzalloc(SXE2_RSS_HASH_KEY_SIZE, GFP_KERNEL);
	if (!key_msg) {
		LOG_ERROR_BDF("sxe2 vf rss get key no memory.\n");
		ret = -SXE2_VF_ERR_NO_MEMORY;
		goto l_err;
	}

	ret = sxe2_fwc_rss_hkey_get(vsi, key_msg);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf rss get key failed, ret: %d, vsi id: %u.\n",
			      ret, vsi->id_in_pf);
		goto l_err;
	}

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, key_msg,
				       SXE2_CALC_RESP_LEN(*key_msg, cmd_hdr->tran_out_len),
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	goto l_end;

l_err:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);

l_end:
	kfree(key_msg);
	return ret;
}

STATIC s32 sxe2_rss_lut_get_msg_func(struct sxe2_vf_node *vf,
				     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	u8 *lut_msg = NULL;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);

	if (!vsi) {
		LOG_ERROR_BDF("vsi is null!\n");
		ret = -SXE2_VF_ERR_PARAM;
		goto l_err;
	}

	lut_msg = kzalloc(vsi->rss_ctxt.lut_size, GFP_KERNEL);
	if (!lut_msg) {
		LOG_ERROR_BDF("sxe2 vf rss get lut no memory.\n");
		ret = -SXE2_VF_ERR_NO_MEMORY;
		goto l_err;
	}

	ret = sxe2_fwc_rss_lut_get(vsi, lut_msg, vsi->rss_ctxt.lut_size);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf rss get lut failed, ret: %d, vsi id: %u.\n",
			      ret, vsi->id_in_pf);
		goto l_err;
	}

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, lut_msg,
				       SXE2_CALC_RESP_LEN(*lut_msg, cmd_hdr->tran_out_len),
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	goto l_end;

l_err:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
l_end:
	kfree(lut_msg);
	return ret;
}

STATIC s32 sxe2_rss_key_set_msg_func(struct sxe2_vf_node *vf,
				     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	u8 *key = (u8 *)(msg_info->buf + SXE2VF_MBX_DATA_OFFSET(msg_info->buf));

	if (!vsi) {
		LOG_ERROR_BDF("vsi is null!\n");
		ret = -SXE2_VF_ERR_PARAM;
		goto l_end;
	}

	ret = sxe2_fwc_rss_hkey_set(vsi, key);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss set key fwc failed, ret: %d, vsi id: \t"
			      "%u.\n",
			      ret, vsi->id_in_pf);

l_end:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss set key reply failed, ret: %d, vf id: \t"
			      "%u.\n",
			      ret, vf->vf_idx);

	return ret;
}

STATIC s32 sxe2_rss_lut_set_msg_func(struct sxe2_vf_node *vf,
				     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	u8 *lut = (u8 *)(msg_info->buf + SXE2VF_MBX_DATA_OFFSET(msg_info->buf));

	if (!vsi) {
		LOG_ERROR_BDF("vsi is null!\n");
		ret = -SXE2_VF_ERR_PARAM;
		goto l_end;
	}

	ret = sxe2_fwc_rss_lut_set(vsi, lut, vsi->rss_ctxt.lut_size);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss set lut fwc failed, ret: %d, vsi id: \t"
			      "%u.\n",
			      ret, vsi->id_in_pf);

l_end:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss set key reply failed, ret: %d, vf id: \t"
			      "%u.\n",
			      ret, vf->vf_idx);

	return ret;
}

STATIC void
sxe2_rss_hash_msg_convert_hash_cfg(struct sxe2_rss_hash_cfg *hash_cfg,
				   struct sxe2_vf_rss_hash_msg *rss_hash_msg)
{
	u32 tmp_headers[BITS_TO_U32(SXE2_FLOW_HDR_MAX)];
	u32 tmp_flds[BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX)];
	u32 i = 0;

	(void)memset(hash_cfg, 0, sizeof(struct sxe2_rss_hash_cfg));
	for (i = 0; i < BITS_TO_U32(SXE2_FLOW_HDR_MAX); i++)
		tmp_headers[i] = le32_to_cpu(rss_hash_msg->headers[i]);

	bitmap_from_arr32(hash_cfg->headers, tmp_headers, SXE2_FLOW_HDR_MAX);

	for (i = 0; i < BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX); i++)
		tmp_flds[i] = le32_to_cpu(rss_hash_msg->hash_flds[i]);

	bitmap_from_arr32(hash_cfg->hash_flds, tmp_flds, SXE2_FLOW_FLD_ID_MAX);

	hash_cfg->hdr_type = le32_to_cpu(rss_hash_msg->hdr_type);
	hash_cfg->symm = rss_hash_msg->symm == 1 ? true : false;
}

STATIC s32 sxe2_rss_cfg_add_msg_func(struct sxe2_vf_node *vf,
				     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_rss_hash_msg *cfg_msg =
			(struct sxe2_vf_rss_hash_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	struct sxe2_rss_hash_cfg cfg;

	if (sxe2_is_safe_mode(adapter) || !vsi) {
		LOG_ERROR_BDF("sxe2 vf rss is in safe mode, not support.\n");
		ret = -EINVAL;
		goto l_out;
	}

	sxe2_rss_hash_msg_convert_hash_cfg(&cfg, cfg_msg);

	if (bitmap_empty(cfg.headers, SXE2_FLOW_HDR_MAX)) {
		LOG_ERROR_BDF("invalid header type! vsi type: %u, idx: %u\n",
			      vsi->type, vsi->id_in_pf);
		ret = -EINVAL;
		goto l_out;
	}

	if (bitmap_empty(cfg.hash_flds, SXE2_FLOW_FLD_ID_MAX)) {
		LOG_ERROR_BDF("invalid header type! vsi type: %u, idx: %u\n",
			      vsi->type, vsi->id_in_pf);
		ret = -EINVAL;
		goto l_out;
	}

	ret = sxe2_add_rss_flow(&adapter->rss_flow_ctxt, vsi->id_in_pf, &cfg);
	if (ret != 0)
		LOG_ERROR_BDF("invalid field type! vsi type: %u, idx: %u\n",
			      vsi->type, vsi->id_in_pf);

l_out:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss reply vf failed! vf_id: %u\n",
			      vf->vf_idx);

	return ret;
}

STATIC s32 sxe2_rss_cfg_del_msg_func(struct sxe2_vf_node *vf,
				     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_rss_hash_msg *cfg_msg =
			(struct sxe2_vf_rss_hash_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	struct sxe2_rss_hash_cfg cfg;

	if (sxe2_is_safe_mode(adapter) || !vsi) {
		LOG_ERROR_BDF("sxe2 vf rss is in safe mode, not support.\n");
		ret = -EINVAL;
		goto l_out;
	}

	sxe2_rss_hash_msg_convert_hash_cfg(&cfg, cfg_msg);

	if (bitmap_empty(cfg.headers, SXE2_FLOW_HDR_MAX)) {
		LOG_ERROR_BDF("invalid header type! vsi type: %u, idx: %u\n",
			      vsi->type, vsi->id_in_pf);
		ret = -EINVAL;
		goto l_out;
	}

	if (bitmap_empty(cfg.hash_flds, SXE2_FLOW_FLD_ID_MAX)) {
		LOG_ERROR_BDF("invalid header type! vsi type: %u, idx: %u\n",
			      vsi->type, vsi->id_in_pf);
		ret = -EINVAL;
		goto l_out;
	}

	ret = sxe2_rss_rem_cfg(&adapter->rss_flow_ctxt, vsi->id_in_pf, &cfg);
	if (ret != 0)
		LOG_ERROR_BDF("invalid field type! vsi type: %u, idx: %u\n",
			      vsi->type, vsi->id_in_pf);

l_out:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss reply vf failed! vf_id: %u\n",
			      vf->vf_idx);

	return ret;
}

STATIC s32 sxe2_rss_cfg_replay_func(struct sxe2_vf_node *vf,
				    struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);

	if (sxe2_is_safe_mode(adapter) || !vsi) {
		LOG_ERROR_BDF("sxe2 vf rss is in safe mode, not support.\n");
		ret = -EINVAL;
		goto l_out;
	}

	ret = sxe2_rss_replay_hash_cfg(&adapter->rss_flow_ctxt, vsi->id_in_pf);
	if (ret) {
		sxe2_rss_vsi_flow_clean(vsi);
		LOG_ERROR_BDF("sxe2 vf rss default flow set failed, ret=%d.\n", ret);
	}

l_out:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf add default rss cfg failed! vf_id: %u\n",
			      vf->vf_idx);

	return ret;
}

STATIC s32 sxe2_rss_add_default_cfg_func(struct sxe2_vf_node *vf,
					 struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);

	if (sxe2_is_safe_mode(adapter) || !vsi) {
		LOG_ERROR_BDF("sxe2 vf rss is in safe mode, not support.\n");
		ret = -EINVAL;
		goto l_out;
	}

	sxe2_rss_delete_vsi_cfg_list(&adapter->rss_flow_ctxt, vsi->id_in_pf);

	ret = sxe2_rss_default_flow_set(vsi);
	if (ret) {
		sxe2_rss_vsi_flow_clean(vsi);
		LOG_ERROR_BDF("sxe2 vf rss default flow set failed, ret=%d.\n", ret);
	}

l_out:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss reply vf failed! vf_id: %u\n",
			      vf->vf_idx);

	return ret;
}

STATIC s32 sxe2_rss_cfg_clear_msg_func(struct sxe2_vf_node *vf,
				       struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);

	if (!vsi) {
		LOG_ERROR_BDF("vsi is null!\n");
		ret = -SXE2_VF_ERR_PARAM;
		goto l_end;
	}

	sxe2_rss_vsi_flow_clean(vsi);

l_end:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss reply vf failed! vf_id %u\n", vf->vf_idx);

	return ret;
}

STATIC s32 sxe2_rss_hash_ctrl_set_msg_func(struct sxe2_vf_node *vf,
					   struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_rss_hash_ctrl *hash_ctrl =
			(struct sxe2_vf_rss_hash_ctrl
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	struct sxe2_cmd_params cmd = {0};
	struct sxe2_rss_vsi_hctrl hctrl = {0};

	if (!vsi) {
		LOG_ERROR_BDF("vsi is null!\n");
		ret = -SXE2_VF_ERR_PARAM;
		goto l_end;
	}

	hctrl.vsi_hw_id = cpu_to_le16(vsi->idx_in_dev);
	hctrl.hash_type = hash_ctrl->hash_func;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RSS_VSI_HCTRL_SET, &hctrl,
				  sizeof(hctrl), NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf rss set hash ctrl fw failed! idx: %u\n",
			      vsi->id_in_pf);
		ret = -EIO;
	}

l_end:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss set hash ctrl replay failed!  vf_id: \t"
			      "%u\n",
			      vf->vf_idx);

	return ret;
}

STATIC s32 sxe2_fnav_filter_add_msg_func(struct sxe2_vf_node *vf,
					 struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_fnav_add_filter_resp filter_resp;
	struct sxe2_fnav_comm_full_msg *filter_msg =
			(struct sxe2_fnav_comm_full_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	u32 flow_id = 0;

	if (!vsi) {
		LOG_ERROR_BDF("vsi is null!\n");
		ret = -SXE2_VF_ERR_PARAM;
		goto l_end;
	}

	ret = sxe2_comm_add_fnav_filter(adapter, vsi->id_in_pf, vsi->id_in_pf,
					vsi->id_in_pf, filter_msg, &flow_id);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf fnav parse pattern fail ret: %d ! idx: %u\n",
			      ret, vsi->id_in_pf);

	filter_resp.flow_id = cpu_to_le32(flow_id);

l_end:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, &filter_resp,
				       SXE2_CALC_RESP_LEN(filter_resp, cmd_hdr->tran_out_len),
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf fnav reply vf failed! vf_id: %u\n",
			      vf->vf_idx);

	return ret;
}

STATIC s32 sxe2_fnav_filter_del_msg_func(struct sxe2_vf_node *vf,
					 struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_fnav_filter_del_msg *del_msg =
			(struct sxe2_vf_fnav_filter_del_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	u32 flow_id;

	if (!vsi) {
		LOG_ERROR_BDF("vsi is null!\n");
		ret = -SXE2_VF_ERR_PARAM;
		goto l_end;
	}

	flow_id = le32_to_cpu(del_msg->flow_id);
	ret = sxe2_fnav_del_filter_by_flow_id(adapter, vsi->id_in_pf, flow_id);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf fnav param check fail ret: %d ! vsi type: \t"
			      "%u, idx: %u\n",
			      ret, vsi->type, vsi->id_in_pf);

l_end:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf fnav reply vf failed! vf_id %u\n",
			      vf->vf_idx);

	return ret;
}

STATIC s32 sxe2_fnav_filter_clear_msg_func(struct sxe2_vf_node *vf,
					   struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);

	if (!vsi) {
		LOG_ERROR_BDF("vsi is null!\n");
		ret = -SXE2_VF_ERR_PARAM;
		goto l_end;
	}

	ret = sxe2_fnav_del_filter_by_vsi(vsi);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf fnav param check fail ret: %d ! vsi type: \t"
			      "%u, idx: %u\n",
			      ret, vsi->type, vsi->id_in_pf);
	}

l_end:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf fnav reply vf failed! vf_id: %u\n",
			      vf->vf_idx);

	return ret;
}

STATIC s32 sxe2_fnav_stat_alloc_msg_func(struct sxe2_vf_node *vf,
					 struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	struct sxe2_vf_fnav_stat_alloc_req_msg *stat_req =
			(struct sxe2_vf_fnav_stat_alloc_req_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_fnav_stat_msg stat_msg = {0};
	u16 stat_index = 0;
	bool need_update = false;

	if (!vsi) {
		LOG_ERROR_BDF("vsi is null!\n");
		ret = -SXE2_VF_ERR_PARAM;
		goto l_end;
	}

	need_update = stat_req->need_update;
	ret = sxe2_fnav_stat_idx_alloc_with_lock(adapter, vsi->id_in_pf, &stat_index,
						 need_update);
	if (ret)
		LOG_ERROR_BDF("sxe2 fnav now has valid stat index! vsi type: %u, \t"
			      "idx: %u\n",
			      vsi->type, vsi->id_in_pf);
	else
		stat_msg.stat_index = cpu_to_le16(stat_index);

l_end:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, &stat_msg,
				       SXE2_CALC_RESP_LEN(stat_msg, cmd_hdr->tran_out_len),
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf fnav reply vf failed! vf_id: %u\n",
			      vf->vf_idx);

	return ret;
}

STATIC s32 sxe2_fnav_stat_free_msg_func(struct sxe2_vf_node *vf,
					struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_fnav_stat_msg *stat_msg =
			(struct sxe2_vf_fnav_stat_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	u16 stat_index = 0;

	stat_index = le16_to_cpu(stat_msg->stat_index);
	ret = sxe2_fnav_stat_idx_free_with_lock(adapter, stat_index);
	if (ret)
		LOG_ERROR_BDF("sxe2 fnav now has valid stat index! vf_id: %u, idx: \t"
			      "%u\n",
			      vf->vf_idx, stat_index);

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf fnav reply vf failed! vf_id: %u, idx: %u\n",
			      vf->vf_idx, stat_index);

	return ret;
}

STATIC s32 sxe2_fnav_stat_query_msg_func(struct sxe2_vf_node *vf,
					 struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_fnav_stat_query_req_msg *stat_msg =
			(struct sxe2_vf_fnav_stat_query_req_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	struct sxe2_vf_fnav_stat_query_resp_msg stat_resp;
	u16 stat_index = 0;
	u32 is_clear = 0;
	enum sxe2_fnav_stat_ctrl_type stat_type;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_fnav_stats_req req = {};
	struct sxe2_fwc_fnav_stats_resp resp = {};
	u64 hits = 0;
	u64 bytes = 0;

	stat_index = le16_to_cpu(stat_msg->stat_index);
	is_clear = le32_to_cpu(stat_msg->is_clear);
	stat_type = le32_to_cpu(stat_msg->stat_ctrl);

	req.is_clear = is_clear ? true : false;
	req.counter_idx = cpu_to_le16(stat_index);
	req.bank_type = SXE2_FNAV_COUNTER_BANK_ALL;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FNAV_STATS_GET, &req, sizeof(req),
				  &resp, sizeof(resp));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf fnav get state failed, stat_index=%u, ret=%d",
			      stat_index, ret);
	} else {
		switch (stat_type) {
		case SXE2_FNAV_STAT_ENA_PKTS:
			hits += le64_to_cpu(resp.stats[0]);
			break;
		case SXE2_FNAV_STAT_ENA_BYTES:
			bytes += le64_to_cpu(resp.stats[0]);
			break;
		case SXE2_FNAV_STAT_ENA_ALL:
			hits += le64_to_cpu(resp.stats[0]);
			bytes += le64_to_cpu(resp.stats[1]);
			break;
		default:
			break;
		}
	}

	stat_resp.stat_index = stat_msg->stat_index;
	stat_resp.stat_hits = cpu_to_le64(hits);
	stat_resp.stat_bytes = cpu_to_le64(bytes);

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, &stat_resp,
				       SXE2_CALC_RESP_LEN(stat_resp, cmd_hdr->tran_out_len),
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf fnav reply vf failed! vf_id: %u, idx: %u\n",
			      vf->vf_idx, stat_index);
	}

	return ret;
}

STATIC s32 sxe2_fnav_match_clear_msg_func(struct sxe2_vf_node *vf,
					  struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);

	if (!vsi) {
		LOG_ERROR_BDF("vsi is null!\n");
		ret = -SXE2_VF_ERR_PARAM;
		goto l_end;
	}

	adapter->fnav_ctxt.fnav_stat_ctxt.vsi_fnav_match[vsi->id_in_pf] = 0;

l_end:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	return ret;
}

#ifdef SXE2_SUPPORT_ACL
STATIC s32 sxe2_vf_acl_filter_add_msg_func(struct sxe2_vf_node *vf,
					   struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_vsi *vsi = vf->vsi;
	struct ethtool_rx_flow_spec *fsp =
			(struct ethtool_rx_flow_spec *)(msg_info->buf +
							SXE2VF_MBX_FULL_HDR_SIZE);
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_cmd_params params = {0};
	s32 ret = 0;

	ret = sxe2_acl_add_rule_ethtool(vsi, fsp);
	if (ret)
		LOG_ERROR_BDF("add vf filter failed, ret:%d\n", ret);

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf acl reply vf failed! vsi type: %u, idx: %u\n",
			      vsi->type, vsi->id_in_pf);
	}

	return ret;
}

STATIC s32 sxe2_vf_acl_filter_del_msg_func(struct sxe2_vf_node *vf,
					   struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2vf_acl_filter_del_req *req =
			(struct sxe2vf_acl_filter_del_req
					 *)(msg_info->buf +
					    SXE2VF_MBX_FULL_HDR_SIZE);
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_cmd_params params = {0};
	s32 ret = 0;

	ret = sxe2_acl_del_filter_by_id(vsi,
					SXE2_GEN_FILTER_ID(vsi->idx_in_dev, req->filter_id));
	if (ret)
		LOG_ERROR_BDF("delete filter failed, ret:%d\n", ret);

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf acl reply vf failed! vsi type: %u, idx: %u\n",
			      vsi->type, vsi->id_in_pf);

	return ret;
}

STATIC s32 sxe2_vf_acl_filter_clear_msg_func(struct sxe2_vf_node *vf,
					     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_vsi *vsi = vf->vsi;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_cmd_params params = {0};
	s32 ret = 0;

	ret = sxe2_acl_del_filter_by_vsi(vsi);
	if (ret)
		LOG_ERROR_BDF("delete filter failed, ret:%d\n", ret);

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf acl reply vf failed! vsi type: %u, idx: %u\n",
			      vsi->type, vsi->id_in_pf);
	}

	return ret;
}
#endif

static s32 sxe2_vf_ipsec_sa_add_msg_func(struct sxe2_vf_node *vf,
					 struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_ipsec_sa_add_msg *req =
			(struct sxe2_vf_ipsec_sa_add_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	struct sxe2_vf_ipsec_sa_add_resp resp;
	u32 hw_sa_index = SXE2_IPSEC_HW_INDEX_INVALID;

	if (!sxe2_vf_is_trusted(vf)) {
		ret = -SXE2_VF_ERR_PARAM;
		goto out;
	}

	ret = sxe2_ipsec_vf_sa_add(adapter, vf->vf_idx, req, &hw_sa_index, false);
	if (ret) {
		LOG_ERROR_BDF("failed to add vf sa， ret: %d ! vf idx: %u\n", ret,
			      vf->vf_idx);
		goto out;
	}

	resp.sa_idx = hw_sa_index;

out:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, &resp,
				       SXE2_CALC_RESP_LEN(resp, cmd_hdr->tran_out_len),
				       vf->vf_idx,
				       session_id, ret);

	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("failed to add vf sa! vf idx: %u\n", vf->vf_idx);

	return ret;
}

static s32 sxe2_vf_ipsec_sa_clear_msg_func(struct sxe2_vf_node *vf,
					   struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_ipsec_sa_del_msg *req =
			(struct sxe2_vf_ipsec_sa_del_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));

	ret = sxe2_ipsec_vf_sa_free(adapter, vf->vf_idx, req);
	if (ret) {
		LOG_ERROR_BDF("failed to free vf sa， ret: %d ! vf idx: %u\n", ret,
			      vf->vf_idx);
	}

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("failed to add vf sa! vf idx: %u\n", vf->vf_idx);

	return ret;
}

static s32 sxe2_vf_ipsec_get_capa_msg_func(struct sxe2_vf_node *vf,
					   struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2vf_get_capa_response resp;

	if (adapter->ipsec_ctxt.status != SXE2_IPSEC_READY &&
	    adapter->ipsec_ctxt.status != SXE2_IPSEC_RESETTING) {
		ret = 0;
		resp.rx_sa_cnt = 0;
		resp.tx_sa_cnt = 0;
	} else {
		resp.rx_sa_cnt = (u16)adapter->ipsec_ctxt.max_rx_sa_cnt;
		resp.tx_sa_cnt = (u16)adapter->ipsec_ctxt.max_tx_sa_cnt;
	}

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, &resp,
				       SXE2_CALC_RESP_LEN(resp, cmd_hdr->tran_out_len),
				       vf->vf_idx,
				       session_id, ret);

	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("failed to get capa! vf idx: %u\n", vf->vf_idx);

	return ret;
}

static s32 sxe2_vf_rdma_dump_pcap_msg_func(struct sxe2_vf_node *vf,
					   struct sxe2_mbx_msg_info *msg_info)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi;
	struct sxe2vf_rdma_dump_pcap_msg *msg =
			(struct sxe2vf_rdma_dump_pcap_msg
					 *)(msg_info->buf +
					    SXE2VF_MBX_FULL_HDR_SIZE);
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);

	vsi = sxe2_vf_vsi_get(vf, vf->vsi_id[SXE2_VF_TYPE_ETH]);
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", vf->vsi_id[SXE2_VF_TYPE_ETH]);
		ret = -SXE2_VF_ERR_PARAM;
		goto l_msg_reply;
	}

	ret = sxe2_rdma_dump_pcap_setup(vsi, msg->mac, msg->is_add);
	if (ret) {
		LOG_ERROR_BDF("failed to setup vf rdma dump pcap! vf idx: %u\n",
			      vf->vf_idx);
	}

l_msg_reply:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);

	return sxe2_mbx_msg_reply(adapter, &params);
}

static s32
sxe2_vf_passthrough_user_driver_data_func(struct sxe2_vf_node *vf,
					  struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	s32 ret = 0;
	struct sxe2_com_user_data_passthrough_req *req =
			(struct sxe2_com_user_data_passthrough_req
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	struct sxe2_com_user_data_passthrough_resp *resp = NULL;
	struct sxe2_drv_cmd_params *cmd_param = NULL;
	struct sxe2_obj obj = {0};
	u32 total_resp_len = 0;

	cmd_param = kzalloc(sizeof(*cmd_param), GFP_KERNEL);
	if (!cmd_param) {
		LOG_ERROR_BDF("Mem alloc failed ret:%d", ret);
		ret = -SXE2_VF_ERR_NO_MEMORY;
		goto l_end;
	}

	memcpy(&obj, &req->obj, sizeof(struct sxe2_mbx_obj));
	cmd_param->opcode = req->opcode;
	cmd_param->vsi_id = req->vsi_id;
	cmd_param->req_len = req->req_len;
	cmd_param->resp_len = req->resp_len;

	if (cmd_param->req_len > 0) {
		cmd_param->req_data = kzalloc(cmd_param->req_len, GFP_KERNEL);
		if (!cmd_param->req_data) {
			LOG_ERROR_BDF("Mem alloc failed ret:%d", ret);
			ret = -SXE2_VF_ERR_NO_MEMORY;
			goto l_end;
		}
		(void)memcpy(cmd_param->req_data, req->cmd_buff, cmd_param->req_len);
	}

	if (cmd_param->resp_len > 0) {
		total_resp_len = sizeof(*resp) + cmd_param->resp_len;
		resp = kzalloc(total_resp_len, GFP_KERNEL);
		if (!resp) {
			LOG_ERROR_BDF("Mem alloc failed ret:%d", ret);
			ret = -SXE2_VF_ERR_NO_MEMORY;
			total_resp_len = 0;
			goto l_end;
		}
		cmd_param->resp_data = resp->cmd_buff;
	}

	ret = sxe2_com_cmd_send(adapter, &obj, cmd_param);
	if (ret) {
		LOG_ERROR_BDF("dpdk_passthrough_vf_data failed ret:%d\n", ret);
		goto l_end;
	}

l_end:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, resp,
				       total_resp_len, vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);

	if (cmd_param) {
		kfree(cmd_param->req_data);
		kfree(cmd_param);
	}

	kfree(resp);

	return ret;
}

static s32 sxe2_vf_drv_mode_set_func(struct sxe2_vf_node *vf,
				     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	struct sxe2_vf_drv_mode_req *vf_msg =
			(struct sxe2_vf_drv_mode_req
					 *)(msg_info->buf +
					    SXE2VF_MBX_DATA_OFFSET(msg_info->buf));
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	s32 ret = 0;

	vf->mode = vf_msg->drv_mode;

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("failed to set drv mode ret:%d vf idx: %u\n", ret,
			      vf->vf_idx);

	return ret;
}

static s32 sxe2_vf_drv_mode_get_func(struct sxe2_vf_node *vf,
				     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	struct sxe2_vf_drv_mode_resp resp;
	s32 ret = 0;

	resp.drv_mode = vf->mode;

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, &resp,
				       sizeof(resp), vf->vf_idx, session_id, ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("failed to set drv mode ret:%d vf idx: %u\n", ret,
			      vf->vf_idx);

	return ret;
}

struct sxe2_mbx_msg_table vf_msg_table[SXE2_VF_OPCODE_NR] = {
		[SXE2_VF_VERSION_MATCH] = {SXE2_VF_VERSION_MATCH, sxe2_ver_msg_func},
		[SXE2_VF_RESET_REQUEST] = {SXE2_VF_RESET_REQUEST,
					   sxe2_reset_msg_func},
		[SXE2_VF_HW_RES_GET] = {SXE2_VF_HW_RES_GET, sxe2_res_get_msg_func},
		[SXE2_VF_STATS_GET] = {SXE2_VF_STATS_GET, sxe2_stats_get_msg_func},
		[SXE2_VF_STATS_PUSH] = {SXE2_VF_STATS_PUSH,
					sxe2_stats_push_msg_func},
		[SXE2_VF_RXQ_CFG_AND_ENABLE] = {SXE2_VF_RXQ_CFG_AND_ENABLE,
						sxe2_rxq_cfg_ena_msg_func},

		[SXE2_VF_MAC_ADDR_ADD] = {SXE2_VF_MAC_ADDR_ADD,
					  sxe2_addr_add_msg_func},
		[SXE2_VF_MAC_ADDR_DEL] = {SXE2_VF_MAC_ADDR_DEL,
					  sxe2_addr_del_msg_func},
		[SXE2_VF_MAC_ADDR_UPDATE] = {SXE2_VF_MAC_ADDR_UPDATE,
					     sxe2_addr_update_msg_func},
		[SXE2_VF_PROMISC_UPDATE] = {SXE2_VF_PROMISC_UPDATE,
					    sxe2_promisc_update_msg_func},
		[SXE2_VF_USER_VLAN_PROCESS] = {SXE2_VF_USER_VLAN_PROCESS,
					       sxe2_user_vlan_msg_func},

		[SXE2_VF_TXQ_CFG_AND_ENABLE] = {SXE2_VF_TXQ_CFG_AND_ENABLE,
						sxe2_mbx_txq_cfg_reply},
		[SXE2_VF_IRQ_MAP] = {SXE2_VF_IRQ_MAP, sxe2_irq_map_msg_func},
		[SXE2_VF_IRQ_UNMAP] = {SXE2_VF_IRQ_UNMAP, sxe2_irq_unmap_msg_func},
		[SXE2_VF_QUEUES_DISABLE] = {SXE2_VF_QUEUES_DISABLE,
					    sxe2_queues_dis_msg_func},
		[SXE2_VF_PROMISC_CFG] = {SXE2_VF_PROMISC_CFG,
					 sxe2_promisc_cfg_msg_func},
		[SXE2_VF_VLAN_OFFLOAD_CFG] = {SXE2_VF_VLAN_OFFLOAD_CFG,
					      sxe2_vlan_offload_cfg_msg_func},
		[SXE2_VF_VLAN_FILTER_CFG] = {SXE2_VF_VLAN_FILTER_CFG,
					     sxe2_vlan_filter_cfg_msg_func},
		[SXE2_VF_VLAN_ADD] = {SXE2_VF_VLAN_ADD, sxe2_vlan_add_msg_func},
		[SXE2_VF_VLAN_DEL] = {SXE2_VF_VLAN_DEL, sxe2_vlan_del_msg_func},

		[SXE2_VF_LINK_STATUS_GET] = {SXE2_VF_LINK_STATUS_GET,
					     sxe2_link_msg_func},

		[SXE2_VF_RDMA] = {SXE2_VF_RDMA, sxe2_rdma_msg_func},
		[SXE2_VF_QV_MAP] = {SXE2_VF_QV_MAP, sxe2_qv_map_unmap_msg_func},
		[SXE2_VF_QV_UNMAP] = {SXE2_VF_QV_UNMAP, sxe2_qv_map_unmap_msg_func},
		[SXE2_VF_RDMA_MGR_CMD] = {SXE2_VF_RDMA_MGR_CMD,
					  sxe2_vf_rdma_mgr_msg_func},

		[SXE2_VF_GET_RSS_KEY] = {SXE2_VF_GET_RSS_KEY,
					 sxe2_rss_key_get_msg_func},
		[SXE2_VF_GET_RSS_LUT] = {SXE2_VF_GET_RSS_LUT,
					 sxe2_rss_lut_get_msg_func},
		[SXE2_VF_SET_RSS_KEY] = {SXE2_VF_SET_RSS_KEY,
					 sxe2_rss_key_set_msg_func},
		[SXE2_VF_SET_RSS_LUT] = {SXE2_VF_SET_RSS_LUT,
					 sxe2_rss_lut_set_msg_func},
		[SXE2_VF_ADD_RSS_CFG] = {SXE2_VF_ADD_RSS_CFG,
					 sxe2_rss_cfg_add_msg_func},
		[SXE2_VF_CLEAR_RSS_CFG] = {SXE2_VF_CLEAR_RSS_CFG,
					   sxe2_rss_cfg_clear_msg_func},
		[SXE2_VF_SET_RSS_HASH_CTRL] = {SXE2_VF_SET_RSS_HASH_CTRL,
					       sxe2_rss_hash_ctrl_set_msg_func},
		[SXE2_VF_DEL_RSS_CFG] = {SXE2_VF_DEL_RSS_CFG,
					 sxe2_rss_cfg_del_msg_func},
		[SXE2_VF_ADD_DEFAULT_RSS_CFG] = {SXE2_VF_ADD_DEFAULT_RSS_CFG,
						 sxe2_rss_add_default_cfg_func},
		[SXE2_VF_REPLAY_RSS_CFG] = {SXE2_VF_REPLAY_RSS_CFG,
					    sxe2_rss_cfg_replay_func},
		[SXE2_VF_FNAV_FILTER_ADD] = {SXE2_VF_FNAV_FILTER_ADD,
					     sxe2_fnav_filter_add_msg_func},
		[SXE2_VF_FNAV_FILTER_DEL] = {SXE2_VF_FNAV_FILTER_DEL,
					     sxe2_fnav_filter_del_msg_func},
		[SXE2_VF_FNAV_FILTER_CLEAR] = {SXE2_VF_FNAV_FILTER_CLEAR,
					       sxe2_fnav_filter_clear_msg_func},
		[SXE2_VF_FNAV_ALLOC_STAT] = {SXE2_VF_FNAV_ALLOC_STAT,
					     sxe2_fnav_stat_alloc_msg_func},
		[SXE2_VF_FNAV_FREE_STAT] = {SXE2_VF_FNAV_FREE_STAT,
					    sxe2_fnav_stat_free_msg_func},
		[SXE2_VF_FNAV_QUERY_STAT] = {SXE2_VF_FNAV_QUERY_STAT,
					     sxe2_fnav_stat_query_msg_func},
		[SXE2_VF_FNAV_MATCH_CLEAR] = {SXE2_VF_FNAV_MATCH_CLEAR,
					      sxe2_fnav_match_clear_msg_func},
		[SXE2_VF_STATS_CLEAR] = {SXE2_VF_STATS_CLEAR,
					 sxe2_stats_clear_msg_func},
		[SXE2_VF_RXQ_DISABLE] = {SXE2_VF_RXQ_DISABLE, sxe2_rxq_dis_msg_func},
		[SXE2_VF_TXQ_DISABLE] = {SXE2_VF_TXQ_DISABLE, sxe2_txq_dis_msg_func},

		[SXE2_VF_GET_PTP_CLOCK] = {SXE2_VF_GET_PTP_CLOCK,
					   sxe2_ptp_get_time_msg_func},

		[SXE2_VF_IPSEC_SA_ADD] = {SXE2_VF_IPSEC_SA_ADD,
					  sxe2_vf_ipsec_sa_add_msg_func},
		[SXE2_VF_IPSEC_SA_CLEAR] = {SXE2_VF_IPSEC_SA_CLEAR,
					    sxe2_vf_ipsec_sa_clear_msg_func},
		[SXE2_VF_IPSEC_GET_CAPA] = {SXE2_VF_IPSEC_GET_CAPA,
					    sxe2_vf_ipsec_get_capa_msg_func},

		[SXE2_VF_RDMA_DUMP_PCAP] = {SXE2_VF_RDMA_DUMP_PCAP,
					    sxe2_vf_rdma_dump_pcap_msg_func},
		[SXE2_VF_GET_ETHTOOL_INFO] = {SXE2_VF_GET_ETHTOOL_INFO,
					      sxe2_vf_ethtool_info_get_msg_func},
		[SXE2_VF_VSI_CFG] = {SXE2_VF_VSI_CFG, sxe2_vf_vsi_cfg_msg_func},
#ifdef SXE2_SUPPORT_ACL
		[SXE2_VF_ACL_FILTER_ADD] = {SXE2_VF_ACL_FILTER_ADD,
					    sxe2_vf_acl_filter_add_msg_func},
		[SXE2_VF_ACL_FILTER_DEL] = {SXE2_VF_ACL_FILTER_DEL,
					    sxe2_vf_acl_filter_del_msg_func},
		[SXE2_VF_ACL_FILTER_CLEAR] = {SXE2_VF_ACL_FILTER_CLEAR,
					      sxe2_vf_acl_filter_clear_msg_func},
#endif
		[SXE2_VF_USER_DRIVER_RELEASE] = {SXE2_VF_USER_DRIVER_RELEASE,
				 sxe2_vf_user_driver_release_msg_func},
		[SXE2_VF_PASSTHROUGH_USER_VF_DATA] = {SXE2_VF_PASSTHROUGH_USER_VF_DATA,
				 sxe2_vf_passthrough_user_driver_data_func},
		[SXE2_VF_DRV_MODE_SET] = {SXE2_VF_DRV_MODE_SET,
					  sxe2_vf_drv_mode_set_func},
		[SXE2_VF_DRV_MODE_GET] = {SXE2_VF_DRV_MODE_GET,
					  sxe2_vf_drv_mode_get_func},

		[0] = {0, NULL}};

struct sxe2_mbx_msg_table *sxe2_mbx_msg_table_get(void)
{
	return &vf_msg_table[0];
}

void sxe2_mbx_msg_table_set(struct sxe2_vf_node *vf)
{
	vf->msg_table = &vf_msg_table[0];
}

static s32 sxe2_repr_addr_add_msg_handle(struct sxe2_vf_node *vf,
					 struct sxe2_mbx_msg_info *msg_info)
{
	s32 h_ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_vf_addr_msg *msg =
			(struct sxe2_vf_addr_msg *)(msg_info->buf +
						    SXE2VF_MBX_FULL_HDR_SIZE);
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	u32 i = 0;
	s32 ret;

	if (!sxe2_mbx_msg_vsi_id_is_valid(vf, le16_to_cpu(msg->vsi_id))) {
		h_ret = -EINVAL;
		goto l_msg_reply;
	}

	for (i = 0; i < msg->addr_cnt; i++) {
		u8 *mac_addr = msg->elem[i].addr;

		if (!is_unicast_ether_addr(mac_addr) ||
		    ether_addr_equal(mac_addr, vf->mac_addr.addr))
			continue;

		if (vf->prop.mac_from_pf) {
			LOG_DEV_ERR("VF attempting to override administratively set\n"
				    "MAC address\n");
			h_ret = -EINVAL;
			goto l_msg_reply;
		}
		if (msg->elem[i].type == SXE2_VF_MAC_TYPE_P)
			ether_addr_copy(vf->mac_addr.addr, mac_addr);

		break;
	}

l_msg_reply:
	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, h_ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("add mac addr cnt:%u complete cnt:%u ret:%d.\n",
			      msg->addr_cnt, i, ret);
	return ret;
}

static s32 sxe2_repr_addr_del_msg_handle(struct sxe2_vf_node *vf,
					 struct sxe2_mbx_msg_info *msg_info)
{
	s32 h_ret = SXE2_VF_ERR_SUCCESS;
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	s32 ret;

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, h_ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("repr mac addr del msg reply failed.ret:%d.\n", ret);
	return ret;
}

static s32 sxe2_repr_vlan_add_msg_func(struct sxe2_vf_node *vf,
				       struct sxe2_mbx_msg_info *msg_info)
{
	s32 h_ret = -EPERM;
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	s32 ret;

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, h_ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("repr vlan add msg reply failed.ret:%d.\n", ret);
	return ret;
}

static s32 sxe2_repr_user_vlan_add_msg_func(struct sxe2_vf_node *vf,
					    struct sxe2_mbx_msg_info *msg_info)
{
	s32 h_ret = -EPERM;
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	s32 ret;

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, h_ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("repr vlan add msg reply failed.ret:%d.\n", ret);
	return ret;
}

static s32 sxe2_repr_promisc_add_msg_func(struct sxe2_vf_node *vf,
					  struct sxe2_mbx_msg_info *msg_info)
{
	s32 h_ret = -EPERM;
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	s32 ret;

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, h_ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("repr vlan add msg reply failed.ret:%d.\n", ret);
	return ret;
}

static s32 sxe2_repr_vlan_del_msg_func(struct sxe2_vf_node *vf,
				       struct sxe2_mbx_msg_info *msg_info)
{
	s32 h_ret = -EPERM;
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_cmd_params params = {0};
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg_info->buf;
	u64 session_id = le64_to_cpu(cmd_hdr->session_id);
	s32 ret;

	sxe2_mbx_msg_reply_params_fill(&params, msg_info->opcode, NULL, 0,
				       vf->vf_idx, session_id, h_ret);
	ret = sxe2_mbx_msg_reply(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("repr vlan del msg reply failed.ret:%d.\n", ret);
	return ret;
}

struct sxe2_mbx_msg_table eswitch_vf_msg_table[SXE2_VF_OPCODE_NR] = {
		[SXE2_VF_VERSION_MATCH] = {SXE2_VF_VERSION_MATCH, sxe2_ver_msg_func},
		[SXE2_VF_RESET_REQUEST] = {SXE2_VF_RESET_REQUEST,
					   sxe2_reset_msg_func},
		[SXE2_VF_HW_RES_GET] = {SXE2_VF_HW_RES_GET, sxe2_res_get_msg_func},
		[SXE2_VF_STATS_GET] = {SXE2_VF_STATS_GET, sxe2_stats_get_msg_func},
		[SXE2_VF_STATS_PUSH] = {SXE2_VF_STATS_PUSH,
					sxe2_stats_push_msg_func},
		[SXE2_VF_RXQ_CFG_AND_ENABLE] = {SXE2_VF_RXQ_CFG_AND_ENABLE,
						sxe2_rxq_cfg_ena_msg_func},

		[SXE2_VF_MAC_ADDR_ADD] = {SXE2_VF_MAC_ADDR_ADD,
					  sxe2_repr_addr_add_msg_handle},
		[SXE2_VF_MAC_ADDR_DEL] = {SXE2_VF_MAC_ADDR_DEL,
					  sxe2_repr_addr_del_msg_handle},
		[SXE2_VF_MAC_ADDR_UPDATE] = {SXE2_VF_MAC_ADDR_UPDATE,
					     sxe2_repr_addr_update_msg_func},
		[SXE2_VF_PROMISC_UPDATE] = {SXE2_VF_PROMISC_UPDATE,
					    sxe2_repr_promisc_update_msg_func},

		[SXE2_VF_TXQ_CFG_AND_ENABLE] = {SXE2_VF_TXQ_CFG_AND_ENABLE,
						sxe2_mbx_txq_cfg_reply},
		[SXE2_VF_IRQ_MAP] = {SXE2_VF_IRQ_MAP, sxe2_irq_map_msg_func},
		[SXE2_VF_IRQ_UNMAP] = {SXE2_VF_IRQ_UNMAP, sxe2_irq_unmap_msg_func},
		[SXE2_VF_QUEUES_DISABLE] = {SXE2_VF_QUEUES_DISABLE,
					    sxe2_queues_dis_msg_func},
		[SXE2_VF_PROMISC_CFG] = {SXE2_VF_PROMISC_CFG,
					 sxe2_repr_promisc_add_msg_func},
		[SXE2_VF_VLAN_OFFLOAD_CFG] = {SXE2_VF_VLAN_OFFLOAD_CFG,
					      sxe2_vlan_offload_cfg_msg_func},
		[SXE2_VF_VLAN_FILTER_CFG] = {SXE2_VF_VLAN_FILTER_CFG,
					     sxe2_vlan_filter_cfg_msg_func},
		[SXE2_VF_VLAN_ADD] = {SXE2_VF_VLAN_ADD, sxe2_repr_vlan_add_msg_func},
		[SXE2_VF_VLAN_DEL] = {SXE2_VF_VLAN_DEL, sxe2_repr_vlan_del_msg_func},
		[SXE2_VF_USER_VLAN_PROCESS] = {SXE2_VF_USER_VLAN_PROCESS,
					       sxe2_repr_user_vlan_add_msg_func},
		[SXE2_VF_LINK_STATUS_GET] = {SXE2_VF_LINK_STATUS_GET,
					     sxe2_link_msg_func},
		[SXE2_VF_STATS_CLEAR] = {SXE2_VF_STATS_CLEAR,
					 sxe2_stats_clear_msg_func},

		[SXE2_VF_RDMA] = {SXE2_VF_RDMA, sxe2_rdma_msg_func},
		[SXE2_VF_QV_MAP] = {SXE2_VF_QV_MAP, sxe2_qv_map_unmap_msg_func},
		[SXE2_VF_QV_UNMAP] = {SXE2_VF_QV_UNMAP, sxe2_qv_map_unmap_msg_func},
		[SXE2_VF_RDMA_MGR_CMD] = {SXE2_VF_RDMA_MGR_CMD,
					  sxe2_vf_rdma_mgr_msg_func},

		[SXE2_VF_GET_RSS_KEY] = {SXE2_VF_GET_RSS_KEY,
					 sxe2_rss_key_get_msg_func},
		[SXE2_VF_GET_RSS_LUT] = {SXE2_VF_GET_RSS_LUT,
					 sxe2_rss_lut_get_msg_func},
		[SXE2_VF_SET_RSS_KEY] = {SXE2_VF_SET_RSS_KEY,
					 sxe2_rss_key_set_msg_func},
		[SXE2_VF_SET_RSS_LUT] = {SXE2_VF_SET_RSS_LUT,
					 sxe2_rss_lut_set_msg_func},
		[SXE2_VF_ADD_RSS_CFG] = {SXE2_VF_ADD_RSS_CFG,
					 sxe2_rss_cfg_add_msg_func},
		[SXE2_VF_CLEAR_RSS_CFG] = {SXE2_VF_CLEAR_RSS_CFG,
					   sxe2_rss_cfg_clear_msg_func},
		[SXE2_VF_SET_RSS_HASH_CTRL] = {SXE2_VF_SET_RSS_HASH_CTRL,
					       sxe2_rss_hash_ctrl_set_msg_func},
		[SXE2_VF_DEL_RSS_CFG] = {SXE2_VF_DEL_RSS_CFG,
					 sxe2_rss_cfg_del_msg_func},
		[SXE2_VF_ADD_DEFAULT_RSS_CFG] = {SXE2_VF_ADD_DEFAULT_RSS_CFG,
						 sxe2_rss_add_default_cfg_func},
		[SXE2_VF_REPLAY_RSS_CFG] = {SXE2_VF_REPLAY_RSS_CFG,
					    sxe2_rss_cfg_replay_func},

		[SXE2_VF_FNAV_FILTER_ADD] = {SXE2_VF_FNAV_FILTER_ADD,
					     sxe2_fnav_filter_add_msg_func},
		[SXE2_VF_FNAV_FILTER_DEL] = {SXE2_VF_FNAV_FILTER_DEL,
					     sxe2_fnav_filter_del_msg_func},
		[SXE2_VF_FNAV_FILTER_CLEAR] = {SXE2_VF_FNAV_FILTER_CLEAR,
					       sxe2_fnav_filter_clear_msg_func},
		[SXE2_VF_FNAV_ALLOC_STAT] = {SXE2_VF_FNAV_ALLOC_STAT,
					     sxe2_fnav_stat_alloc_msg_func},
		[SXE2_VF_FNAV_FREE_STAT] = {SXE2_VF_FNAV_FREE_STAT,
					    sxe2_fnav_stat_free_msg_func},
		[SXE2_VF_FNAV_QUERY_STAT] = {SXE2_VF_FNAV_QUERY_STAT,
					     sxe2_fnav_stat_query_msg_func},
		[SXE2_VF_FNAV_MATCH_CLEAR] = {SXE2_VF_FNAV_MATCH_CLEAR,
					      sxe2_fnav_match_clear_msg_func},

		[SXE2_VF_RXQ_DISABLE] = {SXE2_VF_RXQ_DISABLE, sxe2_rxq_dis_msg_func},
		[SXE2_VF_TXQ_DISABLE] = {SXE2_VF_TXQ_DISABLE, sxe2_txq_dis_msg_func},
		[SXE2_VF_GET_PTP_CLOCK] = {SXE2_VF_GET_PTP_CLOCK,
					   sxe2_ptp_get_time_msg_func},
		[SXE2_VF_RDMA_DUMP_PCAP] = {SXE2_VF_RDMA_DUMP_PCAP,
					    sxe2_vf_rdma_dump_pcap_msg_func},

		[SXE2_VF_IPSEC_SA_ADD] = {SXE2_VF_IPSEC_SA_ADD,
					  sxe2_vf_ipsec_sa_add_msg_func},
		[SXE2_VF_IPSEC_SA_CLEAR] = {SXE2_VF_IPSEC_SA_CLEAR,
					    sxe2_vf_ipsec_sa_clear_msg_func},
		[SXE2_VF_IPSEC_GET_CAPA] = {SXE2_VF_IPSEC_GET_CAPA,
					    sxe2_vf_ipsec_get_capa_msg_func},

		[SXE2_VF_GET_ETHTOOL_INFO] = {SXE2_VF_GET_ETHTOOL_INFO,
					      sxe2_vf_ethtool_info_get_msg_func},
#ifdef SXE2_SUPPORT_ACL
		[SXE2_VF_ACL_FILTER_ADD] = {SXE2_VF_ACL_FILTER_ADD,
					    sxe2_vf_acl_filter_add_msg_func},
		[SXE2_VF_ACL_FILTER_DEL] = {SXE2_VF_ACL_FILTER_DEL,
					    sxe2_vf_acl_filter_del_msg_func},
		[SXE2_VF_ACL_FILTER_CLEAR] = {SXE2_VF_ACL_FILTER_CLEAR,
					      sxe2_vf_acl_filter_clear_msg_func},
#endif
		[SXE2_VF_VSI_CFG] = {SXE2_VF_VSI_CFG, sxe2_vf_vsi_cfg_msg_func},
		[SXE2_VF_USER_DRIVER_RELEASE] = {SXE2_VF_USER_DRIVER_RELEASE,
				 sxe2_vf_user_driver_release_msg_func},
		[SXE2_VF_PASSTHROUGH_USER_VF_DATA] = {SXE2_VF_PASSTHROUGH_USER_VF_DATA,
				 sxe2_vf_passthrough_user_driver_data_func},
		[SXE2_VF_DRV_MODE_SET] = {SXE2_VF_DRV_MODE_SET,
					  sxe2_vf_drv_mode_set_func},
		[SXE2_VF_DRV_MODE_GET] = {SXE2_VF_DRV_MODE_GET,
					  sxe2_vf_drv_mode_get_func},

		[0] = {0, NULL}};

struct sxe2_mbx_msg_table *sxe2_esw_mbx_msg_table_get(void)
{
	return &eswitch_vf_msg_table[0];
}

static s32 sxe2_msg_len_check(struct sxe2_mbx_msg_info *msg_info)
{
	return 0;
}

static bool sxe2_opcode_is_support(struct sxe2_vf_node *vf,
				   struct sxe2_mbx_msg_info *msg_info)
{
	return true;
}

static bool sxe2_is_vf_init_opcode(u32 opcode)
{
	bool ret;

	switch (opcode) {
	case SXE2_VF_RESET_REQUEST:
	case SXE2_VF_VERSION_MATCH:
	case SXE2_VF_DRV_MODE_GET:
	case SXE2_VF_HW_RES_GET:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

static s32 sxe2_vf_status_check(struct sxe2_vf_node *vf,
				struct sxe2_mbx_msg_info *msg_info)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vf->adapter;

	if (test_bit(SXE2_VF_STATE_DIS, vf->states)) {
		ret = -EBUSY;
		LOG_ERROR_BDF("vf:%u disabled vf states:0x%lx.\n", vf->vf_idx,
			      *vf->states);
		return ret;
	}

	if (!test_bit(SXE2_VF_STATE_ACTIVE, vf->states) &&
	    !sxe2_is_vf_init_opcode(msg_info->opcode)) {
		ret = -EINVAL;
		LOG_ERROR_BDF("vf not active opcode:0x%x forbidden.\n",
			      msg_info->opcode);
	}

	return ret;
}

static s32 sxe2_vf_msg_check(struct sxe2_vf_node *vf,
			     struct sxe2_mbx_msg_info *msg_info)
{
	s32 ret = 0;

	(void)sxe2_msg_len_check(msg_info);
	(void)sxe2_opcode_is_support(vf, msg_info);

	ret = sxe2_vf_status_check(vf, msg_info);

	return ret;
}

static s32 sxe2_vf_msg_parse(struct sxe2_adapter *adapter, struct sxe2_recv_msg *msg,
			     struct sxe2_mbx_msg_info *msg_info)
{
	struct sxe2_drv_msg_hdr msg_hdr;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg->buf;
	u32 data_offset = 0;
	u32 raw_len = 0;
#ifndef SXE2_CFG_RELEASE
	u32 vf_id = le32_to_cpu(msg->desc.custom2);
#endif
	(void)memcpy((u8 *)&msg_hdr, msg->buf + cmd_hdr->hdr_len, sizeof(msg_hdr));
	msg_info->opcode = le32_to_cpu(msg_hdr.op_code);
	msg_info->msg_len = msg->buf_len;

	data_offset = cmd_hdr->hdr_len + msg_hdr.data_offset;
	raw_len = msg->buf_len - data_offset;
	if (le32_to_cpu(msg_hdr.data_len) != raw_len ||
	    msg_info->opcode >= SXE2_VF_OPCODE_NR) {
		LOG_ERROR("vf:%u desc msg len:%u and hdr msg len:%u mismatch.\n",
			  SXE2_VF_IDX(vf_id), raw_len,
			  le32_to_cpu(msg_hdr.data_len));
		return -SXE2_VF_ERR_PARAM;
	}

	if (msg_info->msg_len) {
		msg_info->buf = kzalloc(msg_info->msg_len, GFP_KERNEL);
		if (!msg_info->buf) {
			LOG_ERROR("vf:%u msg len:%u alloc failed.\n",
				  SXE2_VF_IDX(vf_id), raw_len);
			return -SXE2_VF_ERR_NO_MEMORY;
		}

		(void)memcpy(msg_info->buf, msg->buf, msg_info->msg_len);
	}
	LOG_INFO_BDF("vf:%u msg request opcode:0x%x raw_len:%u sid:0x%llx \t"
		     "trace_id:0x%llx.\n",
		     SXE2_VF_IDX(vf_id), msg_info->opcode, msg_info->msg_len,
		     le64_to_cpu(cmd_hdr->session_id),
		     le64_to_cpu(cmd_hdr->trace_id));

	return 0;
}

static s32 sxe2_vf_id_valid(struct sxe2_adapter *adapter, u32 vf_id)
{
	u8 src_type = (vf_id >> SXE2_MBX_DESC_SRC_TYPE_SHIFT) &
		      SXE2_MBX_DESC_SRC_TYPE_MASK;
	u8 vf_idx = vf_id & SXE2_VF_IDX_MASK;
	s32 ret = 0;

	if (src_type != SXE2_MBX_MSG_SRC_TYPE_VF ||
	    vf_idx >= adapter->vf_ctxt.num_vfs) {
		LOG_ERROR_BDF("invalid vf_id:%u num_vfs:%u maybe src_type \t"
			      "invalid.\n",
			      vf_id, adapter->vf_ctxt.num_vfs);
		ret = -SXE2_VF_ERR_INVALID_VF_ID;
	}

	return ret;
}

void sxe2_cmd_vf_msg_handler(struct sxe2_adapter *adapter, struct sxe2_recv_msg *msg)
{
	u32 vf_id = le32_to_cpu(msg->desc.custom2);
	struct sxe2_vf_node *vf;
	struct sxe2_mbx_msg_info msg_info = {0};
	struct sxe2_cmd_params param = {0};
	s32 ret;
	struct sxe2_cmd_hdr *cmd_hdr;
	u64 session_id;

	if (sxe2_vf_msg_parse(adapter, msg, &msg_info))
		return;

	ret = sxe2_vf_id_valid(adapter, vf_id);
	if (ret)
		goto l_free_msg_data;

	vf_id = SXE2_VF_IDX(vf_id);

	mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_id));
	vf = sxe2_vf_node_get(adapter, (u16)vf_id);
	if (!vf) {
		ret = -EINVAL;
		goto l_unlock;
	}

	ret = sxe2_vf_msg_check(vf, &msg_info);
	if (ret)
		goto l_unlock;

	if (vf->msg_table[msg_info.opcode].func) {
		vf->msg_table[msg_info.opcode].func(vf, &msg_info);
	} else {
		LOG_DEV_ERR("vf:%u mbx msg opcode:0x%x invalid func NULL.\n",
			    vf->vf_idx, msg_info.opcode);
		ret = -SXE2_VF_ERR_PARAM;
	}

l_unlock:
	mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_id));

l_free_msg_data:
	if (ret) {
		cmd_hdr = (struct sxe2_cmd_hdr *)msg_info.buf;
		session_id = le64_to_cpu(cmd_hdr->session_id);

		LOG_ERROR_BDF("vf:%u mbx msg opcode:0x%x sid:0x%llx fail.\n", vf_id,
			      msg_info.opcode, session_id);
		sxe2_mbx_msg_reply_params_fill(&param, msg_info.opcode, NULL, 0,
					       (u16)vf_id, session_id, ret);
		(void)sxe2_mbx_msg_reply(adapter, &param);
	}
	kfree(msg_info.buf);
}
