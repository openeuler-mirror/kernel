// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_mbx_msg.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/wait.h>
#include "sxe2vf.h"
#include "sxe2vf_mbx_msg.h"
#include "sxe2_mbx_public.h"
#include "sxe2_log.h"
#include "sxe2vf_rx.h"
#include "sxe2vf_tx.h"
#include "sxe2vf_regs.h"
#include "sxe2vf_netdev.h"
#include "sxe2vf_ethtool.h"
#include "sxe2vf_l2_filter.h"
#include "sxe2vf_irq.h"

STATIC DEFINE_PER_CPU(union sxe2vf_trace_info, sxe2vf_trace_id);

#define SXE2VF_TRACE_ID_CHIP_OUT_COUNT_MASK                                         \
	0x0003FFFFFFFFFFFFLLU
#define SXE2VF_TRACE_ID_CHIP_OUT_CPUID_MASK 0x3FFLLU
#define SXE2VF_TRACE_ID_CHIP_OUT_TYPE_MASK 0xFLLU
#define SXE2VF_VT_RESOURCE_SIZE                                                     \
	(sizeof(struct sxe2_vf_vfres_msg) +                                         \
	 (SXE2_VF_MAX_VSI_CNT * sizeof(struct sxe2_vf_vsi_res)))

STATIC void sxe2vf_trace_id_alloc(u64 *trace_id)
{
	union sxe2vf_trace_info *trace;
	u64 trace_id_count;

	preempt_disable();
	trace = this_cpu_ptr(&sxe2vf_trace_id);

	trace_id_count = trace->sxe2vf_trace_id_param.count;
	++trace_id_count;
	trace->sxe2vf_trace_id_param.count =
			(trace_id_count & SXE2VF_TRACE_ID_CHIP_OUT_COUNT_MASK);

	*trace_id = trace->id;
	preempt_enable();
}

void sxe2vf_mbx_msg_dflt_params_fill(struct sxe2vf_msg_params *params,
				     enum sxe2vf_resp_wait_mode mode,
				     enum sxe2_vf_opcode opc, void *in_data,
				     u32 in_len, void *out_data, u32 out_len)
{
	params->opcode = opc;
	params->mode = mode;
	params->in_data = in_data;
	params->in_len = (u16)in_len;
	params->out_data = out_data;
	params->out_len = (u16)out_len;

	sxe2vf_trace_id_alloc(&params->trace_id);
}

s32 sxe2vf_mbx_common_msg_send(struct sxe2vf_adapter *adapter,
			       enum sxe2_vf_opcode opcode, u8 *msg, u16 len)
{
	struct sxe2vf_msg_params params = {0};
	s32 ret = 0;

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY, opcode,
					msg, len, NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("opcode:0x%x send failed ret:%d.\n", opcode, ret);

	return ret;
}

#define SXE2VF_UCMD_TXQ_MODE_DEFAULT 0

s32 sxe2vf_txq_cfg_request(struct sxe2vf_adapter *adapter)
{
	u32 i;
	s32 ret;
	struct sxe2vf_queue *txq;
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_txq_ctxt_msg *msg;
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	struct sxe2_vf_txq_ctxt *ctxt;
	u32 len;
	u16 limit;
	u16 start;
	u16 send;
	s32 left;

	limit = (SXE2VF_MBX_RAW_MSG_MAX_SIZE - sizeof(struct sxe2_vf_txq_ctxt_msg)) /
		sizeof(struct sxe2_vf_txq_ctxt);
	left = vsi->txqs.q_cnt;
	start = 0;
	while (left > 0) {
		send = (u16)min_t(u16, limit, (u16)left);
		len = sizeof(*msg) + sizeof(struct sxe2_vf_txq_ctxt) * send;

		msg = kzalloc(len, GFP_KERNEL);
		if (!msg) {
			LOG_ERROR_BDF("txq msg mem %uB alloc failed.\n", len);
			return -ENOMEM;
		}

		msg->vsi_id = cpu_to_le16(vsi->vsi_id);
		msg->q_cnt = cpu_to_le16(send);
		ctxt = msg->ctxs;

		sxe2vf_for_txq_range(i, start, (start + send))
		{
			txq = vsi->txqs.q[i];
			ctxt = &msg->ctxs[i - start];
			ctxt->vsi_id = cpu_to_le16(vsi->vsi_id);
			ctxt->depth = cpu_to_le16(txq->depth);
			ctxt->dma_addr = cpu_to_le64(txq->desc.dma);
			ctxt->queue_id = cpu_to_le16((u16)i);
			ctxt->sched_mode = cpu_to_le32(SXE2VF_UCMD_TXQ_MODE_DEFAULT);
		}

		sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
						SXE2_VF_TXQ_CFG_AND_ENABLE, msg, len,
						NULL, 0);
		ret = sxe2vf_mbx_msg_send(adapter, &params);
		if (ret) {
			LOG_ERROR_BDF("txq cfg and enable start:%u send:%u\t"
				      "failed.\n",
				      start, send);
			kfree(msg);
			goto l_err;
		}

		left -= send;
		start += send;

		kfree(msg);
		LOG_INFO_BDF("txq cnt:%u limit:%u send:%u next start:%u.\n",
			     vsi->txqs.q_cnt, limit, send, start);
	}

l_err:
	return ret;
}

s32 sxe2vf_reset_msg_send(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_msg_params params = {0};
	s32 ret;

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NO_RESP,
					SXE2_VF_RESET_REQUEST, NULL, 0, NULL, 0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("vf reset msg send failed.(err:%d)\n", ret);

	return ret;
}

u16 sxe2vf_irq_cnt_min_get(struct sxe2vf_adapter *adapter)
{
	u16 irq_cnt = SXE2VF_EVENT_MSIX_CNT;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_KERNEL)
		irq_cnt += SXE2VF_LAN_MSIX_MIN_CNT + SXE2VF_RDMA_MSIX_MIN_CNT;
	else if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		irq_cnt += SXE2VF_DPDK_MSIX_MIN_CNT;
	else
		irq_cnt += SXE2VF_LAN_MSIX_MIN_CNT + SXE2VF_DPDK_MSIX_MIN_CNT +
			   SXE2VF_RDMA_MSIX_MIN_CNT;

	LOG_INFO_BDF("mode:%d min irq cnt:%u\n", sxe2vf_com_mode_get(adapter),
		     irq_cnt);

	return irq_cnt;
}

STATIC s32 sxe2vf_irqs_num_validate(struct sxe2vf_adapter *adapter,
				    struct sxe2_vf_vfres_msg *vf_res)
{
	u16 irq_cnt = le16_to_cpu(vf_res->max_vectors);
	u16 irq_min = sxe2vf_irq_cnt_min_get(adapter);

	if (irq_cnt < irq_min || irq_cnt > SXE2VF_IRQ_MAX_CNT) {
		LOG_ERROR_BDF("irq cnt invalid:%d min irq cnt:%u max irq cnt:%u\n",
			      irq_cnt, irq_min, SXE2VF_IRQ_MAX_CNT);
		return -EINVAL;
	}

	return 0;
}

STATIC u16 sxe2vf_queue_cnt_min_get(struct sxe2vf_adapter *adapter)
{
	u16 queue_cnt;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_KERNEL)
		queue_cnt = SXE2VF_ETH_QUEUE_CNT_MIN;
	else if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		queue_cnt = SXE2VF_DPDK_QUEUE_CNT_MIN;
	else
		queue_cnt = SXE2VF_ETH_QUEUE_CNT_MIN + SXE2VF_DPDK_QUEUE_CNT_MIN;

	LOG_INFO_BDF("mode:%d min queue cnt:%u\n", sxe2vf_com_mode_get(adapter),
		     queue_cnt);

	return queue_cnt;
}

STATIC s32 sxe2vf_queues_num_validate(struct sxe2vf_adapter *adapter,
				      struct sxe2_vf_vfres_msg *vf_res)
{
	u16 q_cnt = le16_to_cpu(vf_res->q_cnt);
	u16 q_min = sxe2vf_queue_cnt_min_get(adapter);
	u16 q_max = SXE2_VF_ETH_Q_NUM + SXE2_VF_DPDK_Q_NUM;

	if (q_cnt < q_min || q_cnt > q_max) {
		LOG_ERROR_BDF("irq cnt invalid:%d min:%d max:%u\n", q_cnt, q_min,
			      q_max);
		return -EINVAL;
	}

	return 0;
}

s32 sxe2vf_rxq_cfg_request(struct sxe2vf_adapter *adapter)
{
	s32 ret;
	u16 i;
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	struct sxe2_vf_rxq_msg *rxq_msg;
	struct sxe2_vf_rxq_ctxt *ctxt;
	struct sxe2vf_queue *rxq;
	u16 frame_size = (u16)(adapter->netdev->mtu + SXE2VF_PACKET_HDR_PAD);
	struct sxe2vf_msg_params params = {0};
	u32 len;
	u16 limit;
	u16 start;
	u16 send;
	s32 left;

	limit = (SXE2VF_MBX_RAW_MSG_MAX_SIZE - sizeof(struct sxe2_vf_rxq_msg)) /
		sizeof(struct sxe2_vf_rxq_ctxt);
	left = vsi->rxqs.q_cnt;
	start = 0;

	while (left > 0) {
		send = (u16)min_t(u16, limit, (u16)left);
		len = sizeof(*rxq_msg) + sizeof(struct sxe2_vf_rxq_ctxt) * send;

		rxq_msg = kzalloc(len, GFP_KERNEL);
		if (!rxq_msg) {
			LOG_ERROR_BDF("rxq msg mem %uB alloc failed.\n", len);
			return -ENOMEM;
		}

		rxq_msg->vsi_id = cpu_to_le16(vsi->vsi_id);
		rxq_msg->q_cnt = cpu_to_le16(send);
		rxq_msg->max_frame_size = cpu_to_le16(frame_size);
		ctxt = rxq_msg->ctxt;

		sxe2vf_for_rxq_range(i, start, (start + send))
		{
			rxq = vsi->rxqs.q[i];
			ctxt->buf_len  = cpu_to_le16(ALIGN(rxq->rx_buf_len,
							   BIT_ULL(SXE2VF_RXQ_CTX_DBUFF_SHIFT)));
			ctxt->depth = cpu_to_le16(rxq->depth);
			ctxt->dma_addr = cpu_to_le64(rxq->desc.dma);
			ctxt->queue_id = cpu_to_le16(i);

			if (test_bit(SXE2VF_RXQ_RXFCS_ENABLED, &rxq->flags))
				ctxt->keep_crc_en = true;
			else
				ctxt->keep_crc_en = false;

			if (test_bit(SXE2VF_RXQ_LRO_ENABLED, &rxq->flags))
				ctxt->lro_status = true;
			else
				ctxt->lro_status = false;
			ctxt++;
		}

		sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
						SXE2_VF_RXQ_CFG_AND_ENABLE, rxq_msg,
						len, NULL, 0);
		ret = sxe2vf_mbx_msg_send(adapter, &params);
		if (ret) {
			LOG_ERROR_BDF("rxq cfg and enable start:%u send:%u\t"
				      "failed.\n",
				      start, send);
			kfree(rxq_msg);
			goto l_err;
		}

		left -= send;
		start += send;

		kfree(rxq_msg);

		LOG_INFO_BDF("rxq cnt:%u limit:%u send:%u next start:%u.\n",
			     vsi->rxqs.q_cnt, limit, send, start);
	}

l_err:
	return ret;
}

STATIC void sxe2vf_sw_caps_set(struct sxe2vf_adapter *adapter,
			       struct sxe2_vf_vfres_msg *vf_res)
{
	struct sxe2vf_addr_node *f;
	u8 *cur_mac_addr = adapter->switch_ctxt.filter_ctxt.mac_filter.cur_mac_addr;
	s32 ret;
	u8 i;

	adapter->pf_id = (u8)(le16_to_cpu(vf_res->parent_pfid));
	adapter->vf_id_in_dev = le16_to_cpu(vf_res->vf_id_in_dev);

	adapter->irq_ctxt.max_cnt = le16_to_cpu(vf_res->max_vectors);
	adapter->q_ctxt.max_cnt = le16_to_cpu(vf_res->q_cnt);
	adapter->vsi_ctxt.vsi_cnt_max = le16_to_cpu(vf_res->num_vsis);

	for (i = 0; i < adapter->vsi_ctxt.vsi_cnt_max; i++)
		adapter->vsi_ctxt.vsi_ids[i] =
				le16_to_cpu(vf_res->vsi_res[i].vsi_id);

	adapter->rss_ctxt.rss_lut_type = le16_to_cpu(vf_res->rxft_cap.rss_lut_type);
	adapter->rss_ctxt.rss_key_size = le16_to_cpu(vf_res->rxft_cap.rss_key_size);
	adapter->rss_ctxt.rss_lut_size = le16_to_cpu(vf_res->rxft_cap.rss_lut_size);
	adapter->fnav_ctxt.space_bsize =
			le16_to_cpu(vf_res->rxft_cap.fnav_space_bsize);
	adapter->fnav_ctxt.space_gsize =
			le16_to_cpu(vf_res->rxft_cap.fnav_space_gsize);

	adapter->irq_ctxt.itr_gran = le16_to_cpu(vf_res->itr_gran);
	if (!adapter->irq_ctxt.itr_gran)
		adapter->irq_ctxt.itr_gran = SXE2VF_PFG_INT_CTL_ITR_GRAN_0;

	if (is_valid_ether_addr(vf_res->addr)) {
		f = sxe2vf_addr_find(adapter, cur_mac_addr);
		if (f) {
			clear_bit(SXE2VF_MAC_OWNER_NETDEV, &f->usage);
			if (f->usage == 0) {
				ret = sxe2vf_addr_node_del(adapter, cur_mac_addr);
				if (ret)
					LOG_ERROR_BDF("del mac addr node:%pM\t"
						      "failed.\n",
						      cur_mac_addr);
			}
		} else {
			LOG_ERROR_BDF("del mac addr:%pM failed.\n", cur_mac_addr);
		}
		ether_addr_copy(cur_mac_addr, vf_res->addr);
	}

	adapter->switch_ctxt.filter_ctxt.vlan_info.port_vlan_exist =
			vf_res->port_vlan_exsit;
	adapter->switch_ctxt.filter_ctxt.vlan_info.is_switchdev =
			vf_res->is_switchdev;
	adapter->switch_ctxt.filter_ctxt.vlan_info.max_cnt =
			le16_to_cpu(vf_res->max_vlan_cnt);
	adapter->switch_ctxt.filter_ctxt.vlan_info.dev_features = 0;
	adapter->aux_ctxt.cdev_info.pf_cnt = vf_res->pf_cnt;

	adapter->hw.fw_ver.main_version_id = vf_res->fw_ver.main_version_id;
	adapter->hw.fw_ver.sub_version_id = vf_res->fw_ver.sub_version_id;
	adapter->hw.fw_ver.fix_version_id = vf_res->fw_ver.fix_version_id;
	adapter->hw.fw_ver.build_id = vf_res->fw_ver.build_id;
	adapter->txsch_cap.layer_cap = vf_res->vf_txsch_cap.layer_cap;
	adapter->txsch_cap.tm_mid_node_num = vf_res->vf_txsch_cap.tm_mid_node_num;
	adapter->txsch_cap.prio_num = vf_res->vf_txsch_cap.prio_num;

	LOG_INFO_BDF("vsi cnt:%u hw_vsi_id[0]:%u hw_vsi_id[1]:%u queue cnt:%u\t"
		     "irq cnt:%u itr_gran:%u def_mac:%pM port_vlan_exist:%u\t"
		     "is_switchdev:%u\n"
		     "vlan_max_cnt:%u pf_cnt:%u main_ver:%u sub_ver:%u fix_ver:%u\t"
		     "build_id:%u mode:%d.\n",
		     adapter->vsi_ctxt.vsi_cnt_max, adapter->vsi_ctxt.vsi_ids[0],
		     adapter->vsi_ctxt.vsi_ids[1], adapter->q_ctxt.max_cnt,
		     adapter->irq_ctxt.max_cnt, adapter->irq_ctxt.itr_gran,
		     adapter->switch_ctxt.filter_ctxt.mac_filter.cur_mac_addr,
		     adapter->switch_ctxt.filter_ctxt.vlan_info.port_vlan_exist,
		     adapter->switch_ctxt.filter_ctxt.vlan_info.is_switchdev,
		     adapter->switch_ctxt.filter_ctxt.vlan_info.max_cnt,
		     adapter->aux_ctxt.cdev_info.pf_cnt,
		     adapter->hw.fw_ver.main_version_id,
		     adapter->hw.fw_ver.sub_version_id,
		     adapter->hw.fw_ver.fix_version_id, adapter->hw.fw_ver.build_id,
		     adapter->drv_mode);
}

static u16 sxe2vf_vsi_cnt_min_get(struct sxe2vf_adapter *adapter)
{
	u16 vsi_cnt;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_KERNEL)
		vsi_cnt = SXE2_VF_ETH_VSI_CNT;
	else if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		vsi_cnt = SXE2_VF_DPDK_VSI_CNT;
	else
		vsi_cnt = SXE2_VF_ETH_VSI_CNT + SXE2_VF_DPDK_VSI_CNT;

	LOG_INFO_BDF("mode:%d min vsi cnt:%u\n", sxe2vf_com_mode_get(adapter),
		     vsi_cnt);

	return vsi_cnt;
}

STATIC s32 sxe2vf_vsi_num_validate(struct sxe2vf_adapter *adapter,
				   struct sxe2_vf_vfres_msg *vf_res)
{
	if (vf_res->num_vsis < sxe2vf_vsi_cnt_min_get(adapter)) {
		LOG_ERROR_BDF("vsi cnt invalid:%u\n", vf_res->num_vsis);
		return -EINVAL;
	} else if (le16_to_cpu(vf_res->num_vsis) > SXE2_VF_MAX_VSI_CNT) {
		LOG_INFO_BDF("vsi num received:%d exceeds max num supported:%d\n",
			     le16_to_cpu(vf_res->num_vsis), SXE2_VF_MAX_VSI_CNT);

		vf_res->num_vsis = cpu_to_le16(SXE2_VF_MAX_VSI_CNT);
	}

	return 0;
}

STATIC void sxe2vf_hw_stats_to_cpu(struct sxe2_vf_vsi_hw_stats *stats,
				   struct sxe2_vf_vsi_hw_stats *new_stats)
{
	new_stats->rx_vsi_unicast_packets =
			le64_to_cpu(stats->rx_vsi_unicast_packets);
	new_stats->rx_vsi_bytes = le64_to_cpu(stats->rx_vsi_bytes);
	new_stats->tx_vsi_unicast_packets =
			le64_to_cpu(stats->tx_vsi_unicast_packets);
	new_stats->tx_vsi_bytes = le64_to_cpu(stats->tx_vsi_bytes);
	new_stats->rx_vsi_multicast_packets =
			le64_to_cpu(stats->rx_vsi_multicast_packets);
	new_stats->tx_vsi_multicast_packets =
			le64_to_cpu(stats->tx_vsi_multicast_packets);
	new_stats->rx_vsi_broadcast_packets =
			le64_to_cpu(stats->rx_vsi_broadcast_packets);
	new_stats->tx_vsi_broadcast_packets =
			le64_to_cpu(stats->tx_vsi_broadcast_packets);
}

STATIC s32 sxe2vf_stats_get_reply_process(struct sxe2vf_adapter *adapter,
					  struct sxe2_vf_hw_stats_rsp *rsp_stats)
{
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	struct sxe2_vf_vsi_hw_stats *new_stats = &vsi->vsi_stats.vsi_hw_stats;
	struct sxe2_vf_vsi_hw_stats *stats = &rsp_stats->hw_stats;

	sxe2vf_hw_stats_to_cpu(stats, new_stats);

	return 0;
}

s32 sxe2vf_stats_get_msg_send(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	struct sxe2vf_vsi_sw_stats *cur_stats = &vsi->vsi_stats.vsi_sw_stats;
	struct sxe2vf_msg_params params = {0};
	s32 ret;
	struct sxe2_vf_sw_stats msg = {0};
	struct sxe2_vf_hw_stats_rsp rsp = {{0}, 0};

	sxe2vf_vsi_sw_stats_update(vsi);
	msg.sw_stats.rx_bytes = cpu_to_le64(cur_stats->rx_bytes);
	msg.sw_stats.rx_packets = cpu_to_le64(cur_stats->rx_packets);
	msg.sw_stats.tx_bytes = cpu_to_le64(cur_stats->tx_bytes);
	msg.sw_stats.tx_packets = cpu_to_le64(cur_stats->tx_packets);

	msg.vsi_id = cpu_to_le16(adapter->vsi_ctxt.vf_vsi->vsi_id);

	msg.fnav_stats_idx = cpu_to_le16(adapter->fnav_ctxt.stat_idx);

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_STATS_GET, &msg, sizeof(msg), &rsp,
					sizeof(rsp));

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("get vf stats msg send failed.\n");
		goto l_out;
	}

	adapter->fnav_ctxt.fnav_match = le64_to_cpu(rsp.fnav_match);
	ret = sxe2vf_stats_get_reply_process(adapter, &rsp);
l_out:
	if (ret)
		LOG_ERROR_BDF("vf stats get failed.\n");

	return ret;
}

s32 sxe2vf_stats_push_msg_send(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	struct sxe2vf_vsi_sw_stats *cur_stats = &vsi->vsi_stats.vsi_sw_stats;
	struct sxe2vf_msg_params params = {0};
	s32 ret;
	struct sxe2_vf_sw_stats msg = {0};
	struct sxe2_vf_hw_stats_rsp rsp = {{0}, 0};

	sxe2vf_vsi_sw_stats_update(vsi);
	msg.sw_stats.rx_bytes = cpu_to_le64(cur_stats->rx_bytes);
	msg.sw_stats.rx_packets = cpu_to_le64(cur_stats->rx_packets);
	msg.sw_stats.tx_bytes = cpu_to_le64(cur_stats->tx_bytes);
	msg.sw_stats.tx_packets = cpu_to_le64(cur_stats->tx_packets);

	msg.vsi_id = cpu_to_le16(adapter->vsi_ctxt.vf_vsi->vsi_id);

	msg.fnav_stats_idx = cpu_to_le16(adapter->fnav_ctxt.stat_idx);

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_STATS_PUSH, &msg, sizeof(msg), &rsp,
					sizeof(rsp));

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("push vf stats msg send failed.\n");
		goto l_out;
	}

	ret = sxe2vf_stats_get_reply_process(adapter, &rsp);
l_out:
	if (ret)
		LOG_ERROR_BDF("vf stats push failed.\n");

	return ret;
}

s32 sxe2vf_irq_map_setup(struct sxe2vf_vsi *vsi)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	struct sxe2_vf_irq_map_msg *vsi_irqs_map;
	struct sxe2_vf_irq_map *irq_map;
	struct sxe2vf_irq_data *irq_data;
	u32 len;
	s32 ret;
	u16 i, q_irq_cnt = vsi->irqs.cnt;
	struct sxe2vf_msg_params params = {0};

	len = (sizeof(struct sxe2_vf_irq_map_msg) +
	       (q_irq_cnt * sizeof(struct sxe2_vf_irq_map)));
	vsi_irqs_map = kzalloc(len, GFP_KERNEL);
	if (!vsi_irqs_map) {
		LOG_ERROR_BDF("vsi irq map alloc failed.\n");
		return -ENOMEM;
	}

	vsi_irqs_map->num_irqs = cpu_to_le16(q_irq_cnt);
	vsi_irqs_map->vsi_id = cpu_to_le16(vsi->vsi_id);

	sxe2vf_for_each_vsi_irq(vsi, i)
	{
		irq_data = vsi->irqs.irq_data[i];
		irq_map = &vsi_irqs_map->irq_maps[i];

		irq_map->irq_id = cpu_to_le16(i);
		irq_map->rxq_map = cpu_to_le16((u16)irq_data->q_bitmap);
		irq_map->txq_map = cpu_to_le16((u16)irq_data->q_bitmap);
		irq_map->txitr_idx = cpu_to_le16(irq_data->tx.itr_idx);
		irq_map->rxitr_idx = cpu_to_le16(irq_data->rx.itr_idx);
	}

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_IRQ_MAP, vsi_irqs_map, len, NULL, 0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);

	LOG_INFO_BDF("itr qs map msg:0x%x ret:%d.\n", SXE2_VF_IRQ_MAP, ret);

	kfree(vsi_irqs_map);
	return ret;
}

s32 sxe2vf_irq_map_clear(struct sxe2vf_vsi *vsi)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	struct sxe2_vf_irq_unmap_msg vsi_irqs_unmap = {};

	struct sxe2vf_msg_params params = {0};
	s32 ret;

	vsi_irqs_unmap.vsi_id = cpu_to_le16(vsi->vsi_id);

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_IRQ_UNMAP, &vsi_irqs_unmap,
					sizeof(struct sxe2_vf_irq_unmap_msg), NULL,
					0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);

	LOG_INFO_BDF("itr unmap msg:0x%x ret:%d.\n", SXE2_VF_IRQ_UNMAP, ret);

	return ret;
}

STATIC void sxe2vf_link_update(struct sxe2vf_adapter *adapter,
			       struct sxe2_vf_link_msg *link_msg)
{
	struct net_device *netdev = adapter->netdev;

	lockdep_assert_held(&adapter->vsi_ctxt.lock);

	if (!adapter->vsi_ctxt.vf_vsi) {
		LOG_INFO_BDF("vf vsi not create yet.\n");
		return;
	}

	adapter->link_ctxt.speed = le32_to_cpu(link_msg->speed);
	adapter->link_ctxt.link_up = link_msg->status;
	if (adapter->vsi_ctxt.vf_vsi) {
		if (adapter->link_ctxt.link_up &&
		    !test_bit(SXE2VF_VSI_CLOSE, adapter->vsi_ctxt.vf_vsi->state)) {
			netif_tx_start_all_queues(netdev);
			netif_carrier_on(netdev);
		} else {
			netif_tx_stop_all_queues(netdev);
			netif_carrier_off(netdev);
		}
		LOG_INFO_BDF("link update speed:%u link_up:%u vsi state:0x%lx\t"
			     "carrier:%d.\n",
			     adapter->link_ctxt.speed, adapter->link_ctxt.link_up,
			     *adapter->vsi_ctxt.vf_vsi->state,
			     netif_carrier_ok(netdev));
	}
}

STATIC s32 sxe2vf_links_msg_func(struct sxe2vf_adapter *adapter, void *body)
{
	struct sxe2_vf_link_msg *link_msg = (struct sxe2_vf_link_msg *)body;

	mutex_lock(&adapter->vsi_ctxt.lock);
	sxe2vf_link_update(adapter, link_msg);
	(void)sxe2_com_irq_notifier_call_chain(&adapter->com_ctxt,
					       SXE2_COM_EC_LINK_CHG);
	mutex_unlock(&adapter->vsi_ctxt.lock);

	return 0;
}

s32 sxe2vf_vlan_offload_msg_send(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_vlan_info *vlan_info =
			&adapter->switch_ctxt.filter_ctxt.vlan_info;
	struct sxe2vf_vlan_offload *vlan_offload = &vlan_info->vlan_offload;
	struct sxe2_vf_vlan_offload_cfg vlan_cfg = {0};
	enum sxe2_vf_opcode opcode = SXE2_VF_VLAN_OFFLOAD_CFG;
	s32 ret;

	vlan_cfg.ctag_insert_enable = vlan_offload->ctag_insert_enable;
	vlan_cfg.stag_insert_enable = vlan_offload->stag_insert_enable;
	vlan_cfg.ctag_strip_enable = vlan_offload->ctag_strip_enable;
	vlan_cfg.stag_strip_enable = vlan_offload->stag_strip_enable;

	ret = sxe2vf_mbx_common_msg_send(adapter, opcode, (u8 *)&vlan_cfg,
					 sizeof(vlan_cfg));
	if (ret)
		LOG_WARN_BDF("vlan offload msg send result:%d.\n", ret);

	LOG_INFO_BDF("vlan offload msg handle.\n");
	return ret;
}

s32 sxe2vf_vlan_msg_send(struct sxe2vf_adapter *adapter, struct sxe2vf_vlan *vlan,
			 bool add)
{
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_vlan_filter_msg *msg;
	u16 len;
	s32 ret;
	enum sxe2_vf_opcode opcode;

	len = (u16)struct_size(msg, elem, 1);
	msg = kzalloc(len, GFP_KERNEL);
	if (!msg) {
		LOG_ERROR_BDF("vlan tpid:0x%x vid:%u prio:%u alloc failed.\n",
			      vlan->tpid, vlan->vid, vlan->prio);
		return -ENOMEM;
	}

	msg->vsi_id = cpu_to_le16(adapter->vsi_ctxt.vf_vsi->vsi_id);
	msg->vlan_cnt = cpu_to_le16(1);
	msg->elem[0].tpid = cpu_to_le16(vlan->tpid);
	msg->elem[0].vid = cpu_to_le16(vlan->vid);

	if (add)
		opcode = SXE2_VF_VLAN_ADD;
	else
		opcode = SXE2_VF_VLAN_DEL;

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY, opcode,
					msg, len, NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("vlan tpid:0x%x vid:%u prio:%u send failed %u.\n",
			      vlan->tpid, vlan->vid, vlan->prio, ret);
	kfree(msg);

	return ret;
}

s32 sxe2vf_user_vlan_msg_send(struct sxe2vf_adapter *adapter, u16 vsi_id,
			      struct sxe2vf_vlan *vlan, bool is_add)
{
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_user_vlan_msg msg = {0};
	s32 ret;

	msg.is_add = is_add;
	msg.vsi_id = cpu_to_le16(vsi_id);
	msg.vlan.tpid = cpu_to_le16(vlan->tpid);
	msg.vlan.vid = cpu_to_le16(vlan->vid);

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_USER_VLAN_PROCESS, &msg, sizeof(msg),
					NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("vlan tpid:0x%x vid:%u prio:%u send failed %u.\n",
			      vlan->tpid, vlan->vid, vlan->prio, ret);

	return ret;
}

STATIC bool sxe2vf_is_in_reset(struct sxe2vf_adapter *adapter)
{
	enum sxe2vf_dev_state state;
	enum sxe2vf_reset_type reset_type;

	sxe2vf_dev_state_get(adapter, &state, &reset_type);

	if (state == SXE2VF_DEVSTATE_STOPPED || state == SXE2VF_DEVSTATE_RESETTING)
		return true;
	else
		return false;
}

STATIC bool sxe2vf_hw_vfr_is_occur(struct sxe2vf_hw *hw)
{
	u32 val;
	bool ret = false;
	struct sxe2vf_adapter *adapter = hw->adapter;

	val = sxe2vf_reg_read(hw, SXE2VF_MBX_RQ_LEN);
	ret = val & SXE2VF_MBX_Q_LEN_VFE_M;
	if (!!ret)
		LOG_INFO_BDF("vf reset occur\n");

	return ret;
}

void sxe2vf_wait_in_resetting(struct sxe2vf_adapter *adapter, bool is_close)
{
	s32 ret = 0;
	u16 detect_times;
	u16 over_times = SXE2VF_RESET_DETEC_WAIT_COUNT;

	if (sxe2vf_is_in_reset(adapter)) {
		LOG_INFO_BDF("vf is in resetting or removing.(err:%d)\n", ret);
		return;
	}

	ret = sxe2vf_reset_msg_send(adapter);
	if (ret) {
		LOG_DEV_INFO("reset request failed.(err:%d)\n", ret);
		return;
	}

	if (!is_close)
		over_times = SXE2VF_RESET_ROBACK_WAIT_COUNT;

	for (detect_times = 0; detect_times < over_times; detect_times++) {
		if (sxe2vf_hw_vfr_is_occur(&adapter->hw))
			break;
		msleep(SXE2VF_RESET_WAIT_MIN);
	}

	if (detect_times >= over_times)
		LOG_DEV_INFO("vf wait resetting time out(%d), rc:%d.\n", over_times,
			     ret);
}

s32 sxe2vf_txrxq_dis_request(struct sxe2vf_adapter *adapter, bool is_close)
{
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_qps_dis_msg msg = {0};
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	s32 ret = 0;

	msg.qps_cnt = cpu_to_le16(vsi->txqs.q_cnt);
	msg.vsi_id = cpu_to_le16(vsi->vsi_id);

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_QUEUES_DISABLE, &msg, sizeof(msg),
					NULL, 0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("txrx queues disable failed.(err:%d)\n", ret);
		sxe2vf_wait_in_resetting(adapter, is_close);
	}
	return ret;
}

s32 sxe2vf_promisc_set_msg_send(struct sxe2vf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct sxe2_vf_promisc_msg msg = {0};
	u32 promisc_flags = 0;
	s32 ret = 0;

	mutex_lock(&adapter->switch_ctxt.flag_lock);

	if (!sxe2vf_promisc_mode_changed(adapter)) {
		LOG_INFO_BDF("promisc mode is not change.\n");
		goto l_out;
	}

	adapter->switch_ctxt.filter_ctxt.cur_promisc_flags = netdev->flags;

	if ((adapter->switch_ctxt.filter_ctxt.cur_promisc_flags & IFF_ALLMULTI) &&
	    (!(adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &
	       SXE2_VF_PROMISC_MULTICAST)))
		promisc_flags |= SXE2_VF_PROMISC_MULTICAST;

	if ((adapter->switch_ctxt.filter_ctxt.cur_promisc_flags & IFF_PROMISC) &&
	    (!(adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &
	       SXE2_VF_PROMISC)))
		promisc_flags |= SXE2_VF_PROMISC | SXE2_VF_PROMISC_MULTICAST;

	if (adapter->netdev->features & NETIF_F_HW_VLAN_CTAG_FILTER)
		promisc_flags |= SXE2_VF_VLAN_FILTER;

	msg.is_user = false;
	msg.vsi_id = cpu_to_le16(adapter->vsi_ctxt.vf_vsi->vsi_id);
	msg.flags = cpu_to_le32(promisc_flags);

	ret = sxe2vf_mbx_common_msg_send(adapter, SXE2_VF_PROMISC_CFG, (u8 *)&msg,
					 sizeof(msg));
	if (ret)
		LOG_ERROR_BDF("set promisc msg handle result:%d.\n", ret);

l_out:
	mutex_unlock(&adapter->switch_ctxt.flag_lock);
	return ret;
}

s32 sxe2vf_user_promisc_set_msg_send(struct sxe2vf_adapter *adapter, u16 vsi_id)
{
	struct sxe2_vf_promisc_msg msg = {0};
	u32 promisc_flags = 0;
	s32 ret = 0;

	if (adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags & IFF_ALLMULTI)
		promisc_flags |= SXE2_VF_PROMISC_MULTICAST;
	if (adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags & IFF_PROMISC)
		promisc_flags |= SXE2_VF_PROMISC;

	msg.is_user = true;
	msg.vsi_id = cpu_to_le16(vsi_id);
	msg.flags = cpu_to_le32(promisc_flags);

	ret = sxe2vf_mbx_common_msg_send(adapter, SXE2_VF_PROMISC_CFG, (u8 *)&msg,
					 sizeof(msg));
	if (ret)
		LOG_ERROR_BDF("set promisc msg handle result:%d.\n", ret);

	return ret;
}

s32 sxe2vf_user_promisc_update_msg_send(struct sxe2vf_adapter *adapter, u16 vsi_id,
					bool to_user, bool is_promisc)
{
	struct sxe2_vf_promisc_update_msg msg = {0};
	s32 ret = 0;

	msg.to_user = to_user;
	msg.is_promisc = is_promisc;
	if (to_user)
		msg.vsi_id = cpu_to_le16(vsi_id);
	else
		msg.vsi_id = cpu_to_le16(adapter->vsi_ctxt.vf_vsi->vsi_id);

	ret = sxe2vf_mbx_common_msg_send(adapter, SXE2_VF_PROMISC_UPDATE, (u8 *)&msg,
					 sizeof(msg));
	if (ret)
		LOG_ERROR_BDF("update promisc msg handle result:%d.\n", ret);

	return ret;
}

static void sxe2vf_addr_type_set(struct sxe2_vf_addr *msg,
				 const struct sxe2vf_mac *mac_info)
{
	msg->type = mac_info->attr.is_vf_mac ? SXE2_VF_MAC_TYPE_P
					     : SXE2_VF_MAC_TYPE_C;
}

s32 sxe2vf_mac_msg_send(struct sxe2vf_adapter *adapter, struct sxe2vf_mac *mac_info,
			bool add, bool is_user, u16 vsi_id)
{
	struct sxe2_vf_addr_msg *msg;
	u16 len;
	s32 ret = 0;
	enum sxe2_vf_opcode opcode;

	len = (u16)struct_size(msg, elem, 1);
	msg = kzalloc(len, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto l_out;
	}

	msg->is_user = is_user;
	msg->vsi_id = vsi_id;

	msg->addr_cnt = cpu_to_le16(1);
	ether_addr_copy(msg->elem[0].addr, mac_info->macaddr);
	sxe2vf_addr_type_set(&msg->elem[0], mac_info);

	if (add)
		opcode = SXE2_VF_MAC_ADDR_ADD;
	else
		opcode = SXE2_VF_MAC_ADDR_DEL;

	ret = sxe2vf_mbx_common_msg_send(adapter, opcode, (u8 *)msg, len);
	if (ret)
		LOG_ERROR_BDF("mac opcode:0x%x send failed ret %d.\n", opcode, ret);

	kfree(msg);

	LOG_INFO_BDF("mac msg handle.\n");

l_out:
	return ret;
}

s32 sxe2vf_mac_update_msg_send(struct sxe2vf_adapter *adapter, const u8 *macaddr,
			       bool to_user)
{
	struct sxe2_vf_addr_update_msg msg = {0};
	s32 ret = 0;

	msg.to_user = to_user;
	ether_addr_copy(msg.addr, macaddr);
	msg.vsi_id = cpu_to_le16(adapter->vsi_ctxt.vf_vsi->vsi_id);

	ret = sxe2vf_mbx_common_msg_send(adapter, SXE2_VF_MAC_ADDR_UPDATE,
					 (u8 *)(&msg), sizeof(msg));
	if (ret)
		LOG_ERROR_BDF("mac opcode:0x%x send failed ret %d.\n",
			      SXE2_VF_MAC_ADDR_UPDATE, ret);

	LOG_INFO_BDF("mac msg handle.\n");
	return ret;
}

s32 sxe2vf_vlan_filter_msg_send(struct sxe2vf_adapter *adapter, bool is_user)
{
	struct sxe2vf_vlan_filter *filter_offload;
	struct sxe2_vf_vlan_filter_cfg filter_cfg = {0};
	enum sxe2_vf_opcode opcode = SXE2_VF_VLAN_FILTER_CFG;
	s32 ret;

	if (is_user)
		filter_offload = &adapter->switch_ctxt.user_fltr_ctxt.vlan_info
						  .filter_offload;
	else
		filter_offload = &adapter->switch_ctxt.filter_ctxt.vlan_info
						  .filter_offload;

	filter_cfg.is_user = is_user;
	filter_cfg.ctag_filter_enable = filter_offload->ctag_filter_enable;
	filter_cfg.stag_filter_enable = filter_offload->stag_filter_enable;

	ret = sxe2vf_mbx_common_msg_send(adapter, opcode, (u8 *)&filter_cfg,
					 sizeof(filter_cfg));
	if (ret)
		LOG_WARN_BDF("vlan filter msg send failed %d.\n", ret);

	LOG_INFO_BDF("vlan filter msg handle.\n");
	return ret;
}

#ifdef SXE2VF_MAC_VLAN_CLEAR
static void sxe2vf_vlan_msg_size_modify(u16 *count, u32 *len)
{
	struct sxe2_vf_vlan_filter_msg *msg;

	*len = struct_size(msg, elem, *count);

	if (*len >
	    SXE2VF_MBX_RAW_MSG_MAX_SIZE) {
		LOG_WARN("Too many vlan changes in one request\n");
		*count = (SXE2VF_MBX_RAW_MSG_MAX_SIZE -
			  sizeof(struct sxe2_vf_vlan_filter_msg)) /
			 sizeof(struct sxe2_vf_vlan);
		*len = struct_size(msg, elem, *count);
	}
}

static void sxe2vf_addr_msg_size_modify(u16 *count, u32 *len)
{
	struct sxe2_vf_addr_msg *msg;

	*len = struct_size(msg, elem, *count);

	if (*len >
	    SXE2VF_MBX_RAW_MSG_MAX_SIZE) {
		LOG_WARN("Too many MAC changes in one request\n");
		*count = (SXE2VF_MBX_RAW_MSG_MAX_SIZE -
			  sizeof(struct sxe2_vf_addr_msg)) /
			 sizeof(struct sxe2_vf_addr);
		*len = struct_size(msg, elem, *count);
	}
}

s32 sxe2vf_vlan_clear_msg_send(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_vlan_info *vlan_info =
			&adapter->switch_ctxt.filter_ctxt.vlan_info;
	struct sxe2_vf_vlan_filter_msg *msg;
	struct sxe2vf_vlan_node *f;
	u32 len;
	u32 buf_len;
	s32 ret = 0;
	u16 i = 0;
	u16 count = 0;
	u16 left = 0;

	list_for_each_entry(f, &vlan_info->vlan_list, list) left++;

	if (!left)
		goto l_out;

	count = left;
	sxe2vf_vlan_msg_size_modify(&count, &len);
	buf_len = len;
	msg = kzalloc(len, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto l_out;
	}

	list_for_each_entry(f, &vlan_info->vlan_list, list) {
		msg->elem->tpid = cpu_to_le16(f->vlan.tpid);
		msg->elem->vid = cpu_to_le16(f->vlan.vid);
		i++;
		left--;
		if (i == count || left == 0) {
			msg->vsi_id = cpu_to_le16(adapter->vsi_ctxt.vf_vsi->vsi_id);
			msg->vlan_cnt = cpu_to_le16(count);

			sxe2vf_mbx_common_msg_send(adapter, SXE2_VF_VLAN_DEL,
						   (u8 *)msg, len);

			count = left;
			sxe2vf_vlan_msg_size_modify(&count, &len);

			(void)memset(msg, 0, buf_len);
		}
	}

	kfree(msg);

	LOG_INFO_BDF("mac clear msg handle.\n");

l_out:
	return ret;
}

s32 sxe2vf_mac_clear_msg_send(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_mac_filter *filter =
			&adapter->switch_ctxt.filter_ctxt.mac_filter;
	struct sxe2_vf_addr_msg *msg;
	struct sxe2vf_addr_node *f;
	struct sxe2vf_addr_node *ftmp;
	u32 len;
	u32 buf_len;
	s32 ret = 0;
	u16 i = 0;
	u16 count = 0;
	u16 left = 0;

	list_for_each_entry(f, &filter->mac_addr_list, list) left++;

	if (!left)
		goto l_out;

	count = left;
	sxe2vf_addr_msg_size_modify(&count, &len);
	buf_len = len;
	msg = kzalloc(len, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto l_out;
	}

	list_for_each_entry_safe(f, ftmp, &filter->mac_addr_list, list) {
		ether_addr_copy(msg->elem[i].addr, f->mac.macaddr);
		sxe2vf_addr_type_set(&msg->elem[i], &f->mac);
		i++;
		left--;
		if (i == count || left == 0) {
			msg->vsi_id = cpu_to_le16(adapter->vsi_ctxt.vf_vsi->vsi_id);
			msg->addr_cnt = cpu_to_le16(count);

			sxe2vf_mbx_common_msg_send(adapter, SXE2_VF_MAC_ADDR_DEL,
						   (u8 *)msg, len);

			count = left;
			sxe2vf_addr_msg_size_modify(&count, &len);

			(void)memset(msg, 0, buf_len);
		}
	}

	kfree(msg);

	LOG_INFO_BDF("mac clear msg handle.\n");

l_out:
	return ret;
}
#endif
s32 sxe2vf_qv_map_msg_send(struct sxe2vf_adapter *adapter,
			   struct aux_qvlist_info *qvl_info, bool map)
{
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_qv_map_msg *qvmap_msg;
	s32 ret;
	u32 i;
	u32 size;
	enum sxe2_vf_opcode opcode;

	if (!qvl_info || !qvl_info->num_vectors) {
		LOG_INFO_BDF("Invalid MSIX vector information from IDC driver\n");
		return -EINVAL;
	}

	size = (u32)(sizeof(struct sxe2_vf_qv_map_msg) +
		     (sizeof(struct sxe2_vf_qv_info) * qvl_info->num_vectors));

	qvmap_msg = kzalloc(size, GFP_KERNEL);
	if (!qvmap_msg) {
		LOG_INFO_BDF("memory not enough! buffer is nullptr.\n");
		return -ENOMEM;
	}

	qvmap_msg->num_vectors = qvl_info->num_vectors;

	for (i = 0; i < qvmap_msg->num_vectors; i++) {
		struct aux_qv_info *aux_qv_info = &qvl_info->qv_info[i];
		struct sxe2_vf_qv_info *vc_qv_info = &qvmap_msg->qv_info[i];

		vc_qv_info->v_idx = aux_qv_info->v_idx;
		vc_qv_info->ceq_idx = aux_qv_info->ceq_idx;
		vc_qv_info->aeq_idx = aux_qv_info->aeq_idx;
		vc_qv_info->itr_idx = aux_qv_info->itr_idx;
	}

	opcode = map ? SXE2_VF_QV_MAP : SXE2_VF_QV_UNMAP;
	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY, opcode,
					qvmap_msg, size, NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	kfree(qvmap_msg);
	return ret;
}

s32 sxe2vf_aux_mgr_msg_send(struct sxe2vf_adapter *adapter, u32 opcode, u8 *req_msg,
			    u16 req_len, u8 *recv_msg, u16 recv_len)
{
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_rdma_mgr_cmd_msg *auxmgr_msg;
	u32 size;
	s32 ret;

	size = req_len + sizeof(*auxmgr_msg);
	auxmgr_msg = kzalloc(size, GFP_KERNEL);
	if (!auxmgr_msg) {
		LOG_INFO_BDF("invalid params! buffer is nullptr.\n");
		return -ENOMEM;
	}

	auxmgr_msg->opcode = opcode;
	auxmgr_msg->msg_len = req_len;
	auxmgr_msg->resv_len = recv_len;
	(void)memcpy(auxmgr_msg->msg, req_msg, req_len);

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_RDMA_MGR_CMD, auxmgr_msg, size,
					recv_msg, recv_len);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	kfree(auxmgr_msg);
	return ret;
}

s32 sxe2vf_link_status_request(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_msg_params params = {0};
	s32 ret;
	struct sxe2_vf_link_msg link_msg = {0};

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_LINK_STATUS_GET, NULL, 0, &link_msg,
					sizeof(struct sxe2_vf_link_msg));

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (!ret)
		sxe2vf_link_update(adapter, &link_msg);

	return ret;
}

s32 sxe2vf_com_link_info_request(struct sxe2vf_adapter *adapter, u8 *link_state,
				 u32 *link_speed)
{
	struct sxe2vf_msg_params params = {0};
	s32 ret;
	struct sxe2_vf_link_msg link_msg = {0};

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_LINK_STATUS_GET, NULL, 0, &link_msg,
					sizeof(struct sxe2_vf_link_msg));

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (!ret) {
		*link_speed = le32_to_cpu(link_msg.speed);
		*link_state = link_msg.status;
	}

	if (!link_msg.status)
		*link_state = SXE2_LINK_SPEED_VF_UNKNOWN;

	return ret;
}

s32 sxe2vf_ethtool_info_request(struct sxe2vf_adapter *adapter,
				struct sxe2_msg_ethtool_info *link_cfg)
{
	struct sxe2vf_msg_params params = {0};
	s32 ret;

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_GET_ETHTOOL_INFO, NULL, 0, link_cfg,
					sizeof(struct sxe2_msg_ethtool_info));

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_INFO_BDF("vf get ethtool info failed (err:%d).\n", ret);

	return ret;
}

s32 sxe2vf_rdma_msg_send(struct sxe2vf_adapter *adapter, u8 *msg, u16 len,
			 u8 *recv_msg, u16 recv_len)
{
	struct sxe2vf_msg_params params = {0};
	s32 ret;

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_RDMA, msg, len, recv_msg, recv_len);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("rdma msg send failed.(err:%d)\n", ret);

	return ret;
}

STATIC s32 sxe2vf_reset_msg_func(struct sxe2vf_adapter *adapter, void *body)
{
	LOG_INFO_BDF("rcv reset notify flag:0x%lx.\n", *adapter->flags);

	sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_VFR_NOTIFY, SXE2VF_RESET_NONE);
	sxe2vf_wkq_schedule(adapter, SXE2VF_WK_MONITOR_IM, 0);

	return 0;
}

struct sxe2vf_mbx_msg_table pf_msg_table[SXE2_VF_OPCODE_NR] = {
		[SXE2_VF_LINK_UPDATE_NOTIFY] = {SXE2_VF_LINK_UPDATE_NOTIFY,
						sxe2vf_links_msg_func},
		[SXE2_VF_RESET_NOTIFY] = {SXE2_VF_RESET_NOTIFY,
					  sxe2vf_reset_msg_func},
};

struct sxe2vf_mbx_msg_table *sxe2vf_mbx_msg_table_get(void)
{
	return &pf_msg_table[0];
}

void sxe2vf_trace_id_init(void)
{
	u32 cpu;
	union sxe2vf_trace_info *id;

	for_each_possible_cpu(cpu) {
		id = (union sxe2vf_trace_info *)&per_cpu(sxe2vf_trace_id, cpu);

		id->sxe2vf_trace_id_param.cpu_id =
				(cpu & SXE2VF_TRACE_ID_CHIP_OUT_CPUID_MASK);
		id->sxe2vf_trace_id_param.count = 0;
		id->sxe2vf_trace_id_param.type =
				(SXE2VF_MSG_TYPE_VF_TO_PF &
				 SXE2VF_TRACE_ID_CHIP_OUT_TYPE_MASK);
	}
}

s32 sxe2vf_drv_ver_match(struct sxe2vf_adapter *adapter)
{
	struct sxe2_vf_ver_msg vf_ver;
	struct sxe2_vf_ver_msg pf_ver;
	struct sxe2vf_msg_params params = {0};
	s32 ret;
	u16 major = 0;
	u16 minor = 0;

	vf_ver.major = cpu_to_le16(SXE2_VF_VERSION_MAJOR);
	vf_ver.minor = cpu_to_le16(SXE2_VF_VERSION_MINOR);

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_POLLING,
					SXE2_VF_VERSION_MATCH, &vf_ver,
					sizeof(struct sxe2_vf_ver_msg), &pf_ver,
					sizeof(struct sxe2_vf_ver_msg));

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (!ret) {
		major = le16_to_cpu(pf_ver.major);
		minor = le16_to_cpu(pf_ver.minor);

		if (major != SXE2_VF_VERSION_MAJOR) {
			ret = -EIO;
			LOG_DEV_ERR("unsupport pf version expected %d.%d\t"
				    "received %d.%d\n",
				    SXE2_VF_VERSION_MAJOR, SXE2_VF_VERSION_MINOR,
				    major, minor);
			goto l_out;
		}
		adapter->pf_ver.major = major;
		adapter->pf_ver.minor = minor;
	} else {
		ret = -ETIMEDOUT;
		LOG_ERROR_BDF("get pf version fail!\n");
	}

l_out:
	LOG_INFO_BDF("opcode:0x%x vf version:%d.%d pf version:%d.%d\t"
		     "ret:%d.\n",
		     SXE2_VF_VERSION_MATCH, SXE2_VF_VERSION_MAJOR,
		     SXE2_VF_VERSION_MINOR, major, minor, ret);

	return ret;
}

s32 sxe2vf_func_caps_init(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_vfres_msg_req vf_req;
	struct sxe2_vf_vfres_msg vf_res;
	s32 ret;

	vf_req.driver_type = SXE2_DRIVER_TYPE_VF;
	vf_req.support_sw_stats = 1;
	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_POLLING,
					SXE2_VF_HW_RES_GET, &vf_req, sizeof(vf_req),
					&vf_res, sizeof(struct sxe2_vf_vfres_msg));

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("hw caps init failed.%d\n", ret);
		goto l_out;
	}

	ret = sxe2vf_irqs_num_validate(adapter, &vf_res);
	if (ret) {
		LOG_ERROR_BDF("irq cnt: invalid.%d\n", ret);
		goto l_out;
	}

	ret = sxe2vf_queues_num_validate(adapter, &vf_res);
	if (ret) {
		LOG_ERROR_BDF("queue cnt: invalid.%d\n", ret);
		goto l_out;
	}

	ret = sxe2vf_vsi_num_validate(adapter, &vf_res);
	if (ret) {
		LOG_ERROR_BDF("vsi cnt invalid.%d\n", ret);
		goto l_out;
	}

	sxe2vf_sw_caps_set(adapter, &vf_res);

l_out:
	return ret;
}

void sxe2vf_func_caps_deinit(struct sxe2vf_adapter *adapter)
{
	struct sxe2_vf_vfres_msg vf_res;

	(void)memset(&vf_res, 0, sizeof(vf_res));

	sxe2vf_sw_caps_set(adapter, &vf_res);
}

s32 __sxe2vf_drv_mode_get(struct sxe2vf_adapter *adapter,
			  struct sxe2_vf_drv_mode_resp *vf_resp, u32 resp_len,
			  enum sxe2vf_resp_wait_mode mode)
{
	s32 ret = 0;
	struct sxe2vf_msg_params params = {0};

	sxe2vf_mbx_msg_dflt_params_fill(&params, mode, SXE2_VF_DRV_MODE_GET, NULL, 0,
					vf_resp, resp_len);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("drv mode get failed.%d\n", ret);

	return ret;
}

s32 sxe2vf_drv_mode_get(struct sxe2vf_adapter *adapter,
			enum sxe2vf_resp_wait_mode mode)
{
	s32 ret = 0;
	struct sxe2_vf_drv_mode_resp vf_resp = {0};

	ret = __sxe2vf_drv_mode_get(adapter, &vf_resp, sizeof(vf_resp), mode);
	if (!ret) {
		if (vf_resp.drv_mode != SXE2_COM_MODULE_UNDEFINED) {
			adapter->drv_mode = vf_resp.drv_mode;
			goto end;
		} else {
			ret = -EINVAL;
		}
	}

	if (sxe2vf_g_com_mode_get() != SXE2_COM_MODULE_UNDEFINED) {
		adapter->drv_mode = sxe2vf_g_com_mode_get();
		ret = 0;
	}

end:
	return ret;
}

s32 sxe2vf_drv_mode_set(struct sxe2vf_adapter *adapter, enum sxe2_com_module type)
{
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_drv_mode_req vf_req;
	s32 ret;

	vf_req.drv_mode = type;
	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NO_RESP,
					SXE2_VF_DRV_MODE_SET, &vf_req,
					sizeof(vf_req), NULL, 0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("drv mode set failed.%d\n", ret);

	return ret;
}

s32 sxe2vf_ipsec_get_capa_msg_send(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_get_capa_response msg;
	s32 ret = 0;
	struct sxe2vf_msg_params params = {0};

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_IPSEC_GET_CAPA, NULL, 0, &msg,
					sizeof(struct sxe2vf_get_capa_response));
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (!ret) {
		adapter->ipsec_ctxt.max_rx_sa_cnt = msg.rx_sa_cnt;
		adapter->ipsec_ctxt.max_tx_sa_cnt = msg.tx_sa_cnt;
	} else {
		adapter->ipsec_ctxt.max_rx_sa_cnt = 0;
		adapter->ipsec_ctxt.max_tx_sa_cnt = 0;
	}

	return ret;
}

s32 sxe2vf_ipsec_add_txsa_msg_send(struct sxe2vf_adapter *adapter,
				   struct sxe2vf_tx_sa *sa_info, bool is_restore)
{
	struct sxe2_vf_ipsec_sa_add_msg req;
	struct sxe2_vf_ipsec_sa_add_resp resp;
	s32 ret = 0;
	struct sxe2vf_msg_params params = {0};

	req.dir = SXE2_IPSEC_DIR_TX;
	req.sa_idx = SXE2_IPSEC_INVALID_SA_IDX;

	req.mode = 0;
	if (sa_info->is_auth)
		req.mode |= SXE2_MBX_IPSEC_AUTH;

	if (sa_info->engine)
		req.mode |= SXE2_MBX_IPSEC_SM4;

	(void)memcpy(req.enc_key, sa_info->enc_key, SXE2_MBX_IPSEC_KEY_LEN);
	(void)memcpy(req.auth_key, sa_info->auth_key, SXE2_MBX_IPSEC_KEY_LEN);
	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_IPSEC_SA_ADD,
					&req, sizeof(struct sxe2_vf_ipsec_sa_add_msg), &resp,
					sizeof(struct sxe2_vf_ipsec_sa_add_resp));

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_DEV_ERR("Failed to call mbx add sa.error code :%d\n", ret);
	else
		sa_info->hw_index = (u16)resp.sa_idx;

	return ret;
}

s32 sxe2vf_ipsec_add_rxsa_msg_send(struct sxe2vf_adapter *adapter,
				   struct sxe2vf_rx_sa *sa_info, bool is_restore)
{
	struct sxe2_vf_ipsec_sa_add_msg req;
	struct sxe2_vf_ipsec_sa_add_resp resp;
	struct sxe2vf_msg_params params = {0};
	s32 ret = 0;

	req.dir = SXE2_IPSEC_DIR_RX;
	req.sa_idx = SXE2_IPSEC_INVALID_SA_IDX;

	req.mode = 0;
	if (sa_info->is_auth)
		req.mode |= SXE2_MBX_IPSEC_AUTH;

	if (sa_info->engine)
		req.mode |= SXE2_MBX_IPSEC_SM4;

	if (sa_info->ipv6) {
		req.mode |= SXE2_MBX_IPSEC_IPV6;

		(void)memcpy(req.addr, sa_info->ipaddr, SCBGE_MBX_IPSEC_IPV6_LEN);
	} else {
		(void)memcpy(req.addr, sa_info->ipaddr, SCBGE_MBX_IPSEC_IPV4_LEN);
	}
	req.spi = sa_info->spi;
	(void)memcpy(req.enc_key, sa_info->enc_key, SXE2_MBX_IPSEC_KEY_LEN);
	(void)memcpy(req.auth_key, sa_info->auth_key, SXE2_MBX_IPSEC_KEY_LEN);
	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_IPSEC_SA_ADD,
					&req, sizeof(struct sxe2_vf_ipsec_sa_add_msg), &resp,
					sizeof(struct sxe2_vf_ipsec_sa_add_resp));

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_DEV_ERR("Failed to call mbx add sa.error code :%d\n", ret);
	else
		sa_info->hw_index = (u16)resp.sa_idx;

	return ret;
}

s32 sxe2vf_ipsec_clear_sa_msg_send(struct sxe2vf_adapter *adapter, u8 direction,
				   u32 sa_index)
{
	struct sxe2_vf_ipsec_sa_del_msg req;
	s32 ret = 0;
	struct sxe2vf_msg_params params = {0};

	req.dir = direction;
	req.sa_idx = cpu_to_le16((u16)sa_index);
	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_IPSEC_SA_CLEAR,
					&req, sizeof(struct sxe2_vf_ipsec_sa_del_msg), NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("Failed to call mbx delete sa.error code :%d\n", ret);

	return ret;
}

s32 sxe2vf_rdma_dump_pcap_msg_send(struct sxe2vf_adapter *adapter, u8 *mac,
				   bool is_add)
{
	struct sxe2vf_rdma_dump_pcap_msg req;
	s32 ret = 0;
	struct sxe2vf_msg_params params = {0};

	(void)memcpy(req.mac, mac, ETH_ALEN);
	req.is_add = is_add;

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_RDMA_DUMP_PCAP, &req, sizeof(req),
					NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("Failed to call mbx delete sa.error code :%d\n", ret);

	return ret;
}

#ifdef SXE2_SUPPORT_ACL
s32 sxe2vf_acl_filter_clear_msg_send(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2vf_msg_params params = {0};

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_ACL_FILTER_CLEAR, NULL, 0, NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("Failed to call mbx clear acl filter.error code :%d\n",
			      ret);
	}

	return ret;
}
#endif
