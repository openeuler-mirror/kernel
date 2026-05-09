// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_com_stats.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2vf_com_ioctl.h"
#include "sxe2_ioctl_chnl.h"
#include "sxe2_log.h"
#include "sxe2vf_vsi.h"
#include "sxe2_drv_cmd.h"
#include "sxe2_com_cdev.h"
#include "sxe2vf_com_stats.h"
#include "sxe2_mbx_public.h"

STATIC s32 sxe2vf_com_get_stats_msg_send(struct sxe2vf_adapter *adapter,
					 struct sxe2_vf_sw_stats *req,
					 struct sxe2_vf_hw_stats_rsp *rsp)
{
	struct sxe2vf_msg_params params = {0};
	s32 ret = 0;

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_STATS_GET, req, sizeof(*req), rsp,
					sizeof(*rsp));
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("get vf stats msg send failed.\n");
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2vf_com_clear_stats_msg_send(struct sxe2vf_adapter *adapter,
					   u16 vsi_id_in_dev)
{
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_vsi_res msg = {0};
	s32 ret = 0;

	msg.vsi_id = cpu_to_le16(vsi_id_in_dev);
	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_STATS_CLEAR, &msg, sizeof(msg), NULL, 0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("clear vf stats msg send failed.\n");
		goto l_end;
	}

l_end:
	return ret;
}

STATIC void sxe2vf_com_vsi_stats_calc(const struct sxe2_vf_vsi_hw_stats *new_stats,
				      struct sxe2_vf_vsi_hw_stats *old_stats,
				      struct sxe2_vf_vsi_hw_stats *stats)
{
	stats->rx_vsi_unicast_packets = new_stats->rx_vsi_unicast_packets -
					old_stats->rx_vsi_unicast_packets;
	stats->rx_vsi_bytes = new_stats->rx_vsi_bytes - old_stats->rx_vsi_bytes;
	stats->tx_vsi_unicast_packets = new_stats->tx_vsi_unicast_packets -
					old_stats->tx_vsi_unicast_packets;
	stats->tx_vsi_bytes = new_stats->tx_vsi_bytes - old_stats->tx_vsi_bytes;
	stats->rx_vsi_multicast_packets = new_stats->rx_vsi_multicast_packets -
					  old_stats->rx_vsi_multicast_packets;
	stats->tx_vsi_multicast_packets = new_stats->tx_vsi_multicast_packets -
					  old_stats->tx_vsi_multicast_packets;
	stats->rx_vsi_broadcast_packets = new_stats->rx_vsi_broadcast_packets -
					  old_stats->rx_vsi_broadcast_packets;
	stats->tx_vsi_broadcast_packets = new_stats->tx_vsi_broadcast_packets -
					  old_stats->tx_vsi_broadcast_packets;
}

s32 sxe2vf_com_vsi_stat_get(struct sxe2vf_adapter *adapter, struct sxe2_obj *obj,
			    struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_vsi_stats_req *req = (struct sxe2_drv_vsi_stats_req *)
			sxe2vf_com_req_data_copy_to_kernel(cmd_buf);
	struct sxe2_drv_vsi_stats_resp resp = {0};
	struct sxe2_vf_sw_stats msg = {0};
	struct sxe2_vf_hw_stats_rsp rsp = {{0}, 0};
	struct sxe2_vf_vsi_hw_stats stats = {0};
	s32 ret = 0;

	msg.sw_stats.rx_bytes = req->sw_stats.rx_bytes;
	msg.sw_stats.rx_packets = req->sw_stats.rx_packets;
	msg.sw_stats.tx_bytes = req->sw_stats.tx_bytes;
	msg.sw_stats.tx_packets = req->sw_stats.tx_packets;
	msg.vsi_id = req->vsi_id;
	msg.fnav_stats_idx = cpu_to_le16(SXE2_VF_FNAV_INVALID_STAT_IDX);

	ret = sxe2vf_com_get_stats_msg_send(adapter, &msg, &rsp);
	if (ret) {
		LOG_ERROR_BDF("get vf stats msg send failed.\n");
		goto l_end;
	}

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK) {
		resp.rx_vsi_unicast_packets =
				le64_to_cpu(rsp.hw_stats.rx_vsi_unicast_packets);
		resp.rx_vsi_bytes = le64_to_cpu(rsp.hw_stats.rx_vsi_bytes);
		resp.tx_vsi_unicast_packets =
				le64_to_cpu(rsp.hw_stats.tx_vsi_unicast_packets);
		resp.tx_vsi_bytes = le64_to_cpu(rsp.hw_stats.tx_vsi_bytes);
		resp.rx_vsi_multicast_packets =
				le64_to_cpu(rsp.hw_stats.rx_vsi_multicast_packets);
		resp.tx_vsi_multicast_packets =
				le64_to_cpu(rsp.hw_stats.tx_vsi_multicast_packets);
		resp.rx_vsi_broadcast_packets =
				le64_to_cpu(rsp.hw_stats.rx_vsi_broadcast_packets);
		resp.tx_vsi_broadcast_packets =
				le64_to_cpu(rsp.hw_stats.tx_vsi_broadcast_packets);
	} else if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_MIXED) {
		struct sxe2_vf_vsi_hw_stats *old_stats =
				&adapter->vsi_ctxt.vf_vsi->vsi_stats.parse_vsi_hw_stats;

		sxe2vf_com_vsi_stats_calc(&rsp.hw_stats, old_stats, &stats);
		resp.rx_vsi_unicast_packets = stats.rx_vsi_unicast_packets;
		resp.rx_vsi_bytes = stats.rx_vsi_bytes;
		resp.tx_vsi_unicast_packets = stats.tx_vsi_unicast_packets;
		resp.tx_vsi_bytes = stats.tx_vsi_bytes;
		resp.rx_vsi_multicast_packets = stats.rx_vsi_multicast_packets;
		resp.tx_vsi_multicast_packets = stats.tx_vsi_multicast_packets;
		resp.rx_vsi_broadcast_packets = stats.rx_vsi_broadcast_packets;
		resp.tx_vsi_broadcast_packets = stats.tx_vsi_broadcast_packets;
	} else {
		LOG_ERROR_BDF("invalid com mode %d\n", sxe2vf_com_mode_get(adapter));
		ret = -EINVAL;
		goto l_end;
	}

	if (copy_to_user(cmd_buf->resp_data, &resp, sizeof(resp))) {
		LOG_ERROR_BDF("copy_to_user failed.\n");
		ret = -EFAULT;
		goto l_end;
	}
	cmd_buf->resp_len = sizeof(resp);

	LOG_INFO_BDF("sxe2vf com vsi[%d] stats get is completed.\n", req->vsi_id);

l_end:
	kfree(req);
	return ret;
}

s32 sxe2vf_com_vsi_stat_clear(struct sxe2vf_adapter *adapter, struct sxe2_obj *obj,
			      struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;
	struct sxe2_vf_sw_stats msg = {0};
	struct sxe2_vf_hw_stats_rsp rsp = {{0}, 0};

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK) {
		ret = sxe2vf_com_clear_stats_msg_send(adapter, cmd_buf->vsi_id);
		if (ret)
			LOG_INFO_BDF("sxe2vf com vsi[%d] stats clear is completed.\n",
				     cmd_buf->vsi_id);
		goto l_end;
	} else if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_MIXED) {
		msg.vsi_id = cmd_buf->vsi_id;
		msg.fnav_stats_idx = cpu_to_le16(SXE2_VF_FNAV_INVALID_STAT_IDX);

		ret = sxe2vf_com_get_stats_msg_send(adapter, &msg, &rsp);
		if (ret) {
			LOG_ERROR_BDF("get vf stats msg send failed.\n");
			goto l_end;
		}

		memcpy(&adapter->vsi_ctxt.vf_vsi->vsi_stats.parse_vsi_hw_stats,
		       &rsp.hw_stats, sizeof(rsp.hw_stats));
	} else {
		LOG_ERROR_BDF("invalid com mode %d\n", sxe2vf_com_mode_get(adapter));
		ret = -EINVAL;
		goto l_end;
	}

	LOG_INFO_BDF("sxe2vf com vsi[%d] stats clear is completed.\n", cmd_buf->vsi_id);
l_end:
	return ret;
}
