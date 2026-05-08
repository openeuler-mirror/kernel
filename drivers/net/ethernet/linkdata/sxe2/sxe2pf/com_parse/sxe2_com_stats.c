// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_stats.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_com_ioctl.h"
#include "sxe2_ioctl_chnl.h"
#include "sxe2_log.h"
#include "sxe2_vsi.h"
#include "sxe2_drv_cmd.h"
#include "sxe2_com_cdev.h"
#include "sxe2_com_stats.h"
#include "sxe2_ethtool.h"

#define SXE2_COM_CALC_READCLEAR_STATS(S, N, O) ((S) = (N) - (O))
#define SXE2_COM_CALC_ADD_STATS(S, N, O) ((S) = (N) + (O))

STATIC inline void sxe2_com_calc_nonclear_stats(u64 *s, u64 n, u64 *o)
{
	if (n >= *o)
		*s += n - *o;
	else
		*s = n;
	*o = n;
}

STATIC void sxe2_com_vsi_stats_calc(const struct sxe2_vsi_hw_stats *new_stats,
				    struct sxe2_vsi_hw_stats *old_stats,
				    struct sxe2_vsi_hw_stats *stats)
{
	SXE2_COM_CALC_READCLEAR_STATS(stats->rx_vsi_unicast_packets,
				      new_stats->rx_vsi_unicast_packets,
				      old_stats->rx_vsi_unicast_packets);
	SXE2_COM_CALC_READCLEAR_STATS(stats->rx_vsi_bytes, new_stats->rx_vsi_bytes,
				      old_stats->rx_vsi_bytes);
	SXE2_COM_CALC_READCLEAR_STATS(stats->tx_vsi_unicast_packets,
				      new_stats->tx_vsi_unicast_packets,
				      old_stats->tx_vsi_unicast_packets);
	SXE2_COM_CALC_READCLEAR_STATS(stats->tx_vsi_bytes, new_stats->tx_vsi_bytes,
				      old_stats->tx_vsi_bytes);
	SXE2_COM_CALC_READCLEAR_STATS(stats->rx_vsi_multicast_packets,
				      new_stats->rx_vsi_multicast_packets,
				      old_stats->rx_vsi_multicast_packets);
	SXE2_COM_CALC_READCLEAR_STATS(stats->tx_vsi_multicast_packets,
				      new_stats->tx_vsi_multicast_packets,
				      old_stats->tx_vsi_multicast_packets);
	SXE2_COM_CALC_READCLEAR_STATS(stats->rx_vsi_broadcast_packets,
				      new_stats->rx_vsi_broadcast_packets,
				      old_stats->rx_vsi_broadcast_packets);
	SXE2_COM_CALC_READCLEAR_STATS(stats->tx_vsi_broadcast_packets,
				      new_stats->tx_vsi_broadcast_packets,
				      old_stats->tx_vsi_broadcast_packets);
}

STATIC void sxe2_com_cp_vsi_stats_accumulate(const struct sxe2_vsi_hw_stats *k_stats,
					     struct sxe2_vsi_hw_stats *u_stats,
					     struct sxe2_vsi_hw_stats *stats)
{
	if (!k_stats || !u_stats || !stats)
		return;

	SXE2_COM_CALC_ADD_STATS(stats->rx_vsi_unicast_packets,
				k_stats->rx_vsi_unicast_packets,
				u_stats->rx_vsi_unicast_packets);
	SXE2_COM_CALC_ADD_STATS(stats->rx_vsi_bytes, k_stats->rx_vsi_bytes,
				u_stats->rx_vsi_bytes);
	SXE2_COM_CALC_ADD_STATS(stats->tx_vsi_unicast_packets,
				k_stats->tx_vsi_unicast_packets,
				u_stats->tx_vsi_unicast_packets);
	SXE2_COM_CALC_ADD_STATS(stats->tx_vsi_bytes, k_stats->tx_vsi_bytes,
				u_stats->tx_vsi_bytes);
	SXE2_COM_CALC_ADD_STATS(stats->rx_vsi_multicast_packets,
				k_stats->rx_vsi_multicast_packets,
				u_stats->rx_vsi_multicast_packets);
	SXE2_COM_CALC_ADD_STATS(stats->tx_vsi_multicast_packets,
				k_stats->tx_vsi_multicast_packets,
				u_stats->tx_vsi_multicast_packets);
	SXE2_COM_CALC_ADD_STATS(stats->rx_vsi_broadcast_packets,
				k_stats->rx_vsi_broadcast_packets,
				u_stats->rx_vsi_broadcast_packets);
	SXE2_COM_CALC_ADD_STATS(stats->tx_vsi_broadcast_packets,
				k_stats->tx_vsi_broadcast_packets,
				u_stats->tx_vsi_broadcast_packets);
}

STATIC void sxe2_com_vsi_stats_copy_to_user(struct sxe2_drv_vsi_stats_resp *resp,
					    struct sxe2_vsi_hw_stats *stats)
{
	resp->rx_vsi_unicast_packets = stats->rx_vsi_unicast_packets;
	resp->rx_vsi_bytes = stats->rx_vsi_bytes;
	resp->tx_vsi_unicast_packets = stats->tx_vsi_unicast_packets;
	resp->tx_vsi_bytes = stats->tx_vsi_bytes;
	resp->rx_vsi_multicast_packets = stats->rx_vsi_multicast_packets;
	resp->tx_vsi_multicast_packets = stats->tx_vsi_multicast_packets;
	resp->rx_vsi_broadcast_packets = stats->rx_vsi_broadcast_packets;
	resp->tx_vsi_broadcast_packets = stats->tx_vsi_broadcast_packets;
}

s32 sxe2_com_vsi_stat_get(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			  struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_vsi_stats_req *req =
		(struct sxe2_drv_vsi_stats_req *)sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	struct sxe2_drv_vsi_stats_resp resp = {0};
	struct sxe2_vsi *vsi = NULL;
	struct sxe2_vsi_hw_stats stats = {0};
	struct sxe2_vsi_hw_stats *last_stats = NULL;
	struct sxe2_vsi_hw_stats k_stats = {0};
	struct sxe2_vsi_hw_stats u_stats = {0};
	struct sxe2_vf_node *vf = NULL;
	s32 ret = 0;
	u16 vf_idx = cmd_buf->repr_id;
	u16 vsi_id = req->vsi_id;

	if (!req) {
		LOG_ERROR_BDF("invalid vsi stats get req.\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (obj->func_type == SXE2_PF && vf_idx < SXE2_VF_NUM) {
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
		vf = sxe2_vf_node_get(adapter, vf_idx);
		if (!vf) {
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
			LOG_ERROR_BDF("vf not found, vf_idx=%u\n", vf_idx);
			ret = -EINVAL;
			goto l_end;
		}
		ret = sxe2_check_vf_ready_for_cfg(vf);
		if (ret) {
			LOG_ERROR_BDF("VF %u not ready for mac cfg.\n", vf_idx);
		} else {
			if (vf->vsi) {
				last_stats = &vf->vsi->vsi_stats.parse_vsi_hw_stats;
				sxe2_hw_vsi_stats_update(vf->vsi);
				sxe2_com_vsi_stats_calc(&vf->vsi->vsi_stats.vsi_hw_stats,
							last_stats, &k_stats);
			} else {
				LOG_INFO_BDF("vf %u vsi not found.\n", vf_idx);
			}

			if (vf->dpdk_vf_vsi) {
				last_stats = &vf->dpdk_vf_vsi->vsi_stats.parse_vsi_hw_stats;
				sxe2_hw_vsi_stats_update(vf->dpdk_vf_vsi);
				sxe2_com_vsi_stats_calc(&vf->dpdk_vf_vsi->vsi_stats.vsi_hw_stats,
							last_stats, &u_stats);
			} else {
				LOG_ERROR_BDF("vf %u dpdk vsi not found.\n", vf_idx);
			}

			sxe2_com_cp_vsi_stats_accumulate(&k_stats, &u_stats, &stats);
		}
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	} else {
		mutex_lock(&adapter->vsi_ctxt.lock);
		vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
		if (!vsi) {
			mutex_unlock(&adapter->vsi_ctxt.lock);
			LOG_ERROR_BDF("invalid vsi id:%d.\n", vsi_id);
			ret = -EINVAL;
			goto l_end;
		}

		if (vsi->type == SXE2_VSI_T_DPDK_PF) {
			last_stats = &vsi->vsi_stats.parse_vsi_hw_stats;
			sxe2_hw_vsi_stats_update(vsi);
			sxe2_com_vsi_stats_calc(&vsi->vsi_stats.vsi_hw_stats, last_stats,
						&stats);
		}
		mutex_unlock(&adapter->vsi_ctxt.lock);
	}

	sxe2_com_vsi_stats_copy_to_user(&resp, &stats);
	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed.\n");
		ret = -EFAULT;
		goto l_end;
	}
	cmd_buf->resp_len = sizeof(resp);
	LOG_INFO_BDF("sxe2 com vsi[%d] stats get is completed.\n", vsi_id);

l_end:
	kfree(req);
	return ret;
}

s32 sxe2_com_vsi_stat_clear(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			    struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_vsi *vsi = NULL;
	struct sxe2_vsi_hw_stats *last_stats = NULL;
	struct sxe2_vf_node *vf = NULL;
	s32 ret = 0;
	u16 vsi_id = cmd_buf->vsi_id;
	u16 vf_idx = cmd_buf->repr_id;

	if (obj->func_type == SXE2_PF && vf_idx < SXE2_VF_NUM) {
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
		vf = sxe2_vf_node_get(adapter, vf_idx);
		if (!vf) {
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
			LOG_ERROR_BDF("vf not found, vf_idx=%u\n", vf_idx);
			ret = -EINVAL;
			goto l_end;
		}
		ret = sxe2_check_vf_ready_for_cfg(vf);
		if (ret) {
			LOG_ERROR_BDF("VF %u not ready for mac cfg.\n", vf_idx);
		} else {
			if (vf->vsi) {
				sxe2_hw_vsi_stats_update(vf->vsi);
				last_stats = &vf->vsi->vsi_stats.parse_vsi_hw_stats;
				(void)memcpy(last_stats, &vf->vsi->vsi_stats.vsi_hw_stats,
					     sizeof(*last_stats));
			} else {
				LOG_INFO_BDF("vf %u vsi not found.\n", vf_idx);
			}

			if (vf->dpdk_vf_vsi) {
				sxe2_hw_vsi_stats_update(vf->dpdk_vf_vsi);
				last_stats = &vf->dpdk_vf_vsi->vsi_stats.parse_vsi_hw_stats;
				(void)memcpy(last_stats,
					     &vf->dpdk_vf_vsi->vsi_stats.vsi_hw_stats,
					     sizeof(*last_stats));
			} else {
				LOG_INFO_BDF("vf %u dpdk vsi not found.\n", vf_idx);
			}
		}
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	} else {
		mutex_lock(&adapter->vsi_ctxt.lock);
		vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
		if (!vsi) {
			mutex_unlock(&adapter->vsi_ctxt.lock);
			LOG_ERROR_BDF("invalid vsi id:%d.\n", vsi_id);
			ret = -EINVAL;
			goto l_end;
		}

		if (vsi->type == SXE2_VSI_T_DPDK_PF) {
			sxe2_hw_vsi_stats_update(vsi);
			last_stats = &vsi->vsi_stats.parse_vsi_hw_stats;
			(void)memcpy(last_stats, &vsi->vsi_stats.vsi_hw_stats,
				     sizeof(*last_stats));
		}
		mutex_unlock(&adapter->vsi_ctxt.lock);
	}
	LOG_INFO_BDF("sxe2 com vsi[%d] stats clear is completed.\n", vsi_id);

l_end:
	return ret;
}

STATIC void sxe2_com_mac_nonclear_stats_calc(const struct sxe2_pf_hw_stats *new_stats,
					     struct sxe2_pf_hw_stats *old_stats,
					     struct sxe2_pf_hw_stats *stats)
{
	u8 i = 0;

	sxe2_com_calc_nonclear_stats(&stats->rx_oversize_good, new_stats->rx_oversize_good,
				     &old_stats->rx_oversize_good);
	sxe2_com_calc_nonclear_stats(&stats->rx_discards_phy, new_stats->rx_discards_phy,
				     &old_stats->rx_discards_phy);
	sxe2_com_calc_nonclear_stats(&stats->rx_undersize_good,
				     new_stats->rx_undersize_good,
				     &old_stats->rx_undersize_good);
	sxe2_com_calc_nonclear_stats(&stats->rx_runt_error, new_stats->rx_runt_error,
				     &old_stats->rx_runt_error);
	sxe2_com_calc_nonclear_stats(&stats->rx_jabbers, new_stats->rx_jabbers,
				     &old_stats->rx_jabbers);
	sxe2_com_calc_nonclear_stats(&stats->tx_frame_good, new_stats->tx_frame_good,
				     &old_stats->tx_frame_good);
	sxe2_com_calc_nonclear_stats(&stats->rx_frame_good, new_stats->rx_frame_good,
				     &old_stats->rx_frame_good);
	sxe2_com_calc_nonclear_stats(&stats->rx_crc_errors, new_stats->rx_crc_errors,
				     &old_stats->rx_crc_errors);
	sxe2_com_calc_nonclear_stats(&stats->tx_bytes_good, new_stats->tx_bytes_good,
				     &old_stats->tx_bytes_good);
	sxe2_com_calc_nonclear_stats(&stats->rx_bytes_good, new_stats->rx_bytes_good,
				     &old_stats->rx_bytes_good);
	sxe2_com_calc_nonclear_stats(&stats->tx_multicast_good,
				     new_stats->tx_multicast_good,
				     &old_stats->tx_multicast_good);
	sxe2_com_calc_nonclear_stats(&stats->tx_broadcast_good,
				     new_stats->tx_broadcast_good,
				     &old_stats->tx_broadcast_good);
	sxe2_com_calc_nonclear_stats(&stats->rx_multicast_good,
				     new_stats->rx_multicast_good,
				     &old_stats->rx_multicast_good);
	sxe2_com_calc_nonclear_stats(&stats->rx_broadcast_good,
				     new_stats->rx_broadcast_good,
				     &old_stats->rx_broadcast_good);
	sxe2_com_calc_nonclear_stats(&stats->rx_len_errors, new_stats->rx_len_errors,
				     &old_stats->rx_len_errors);
	sxe2_com_calc_nonclear_stats(&stats->rx_out_of_range_errors,
				     new_stats->rx_out_of_range_errors,
				     &old_stats->rx_out_of_range_errors);
	sxe2_com_calc_nonclear_stats(&stats->rx_oversize_pkts_phy,
				     new_stats->rx_oversize_pkts_phy,
				     &old_stats->rx_oversize_pkts_phy);
	sxe2_com_calc_nonclear_stats(&stats->rx_symbol_err, new_stats->rx_symbol_err,
				     &old_stats->rx_symbol_err);
	sxe2_com_calc_nonclear_stats(&stats->rx_pause_frame, new_stats->rx_pause_frame,
				     &old_stats->rx_pause_frame);
	sxe2_com_calc_nonclear_stats(&stats->tx_pause_frame, new_stats->tx_pause_frame,
				     &old_stats->tx_pause_frame);
	sxe2_com_calc_nonclear_stats(&stats->tx_dropped_link_down,
				     new_stats->tx_dropped_link_down,
				     &old_stats->tx_dropped_link_down);
	sxe2_com_calc_nonclear_stats(&stats->tx_bytes_good_bad,
				     new_stats->tx_bytes_good_bad,
				     &old_stats->tx_bytes_good_bad);
	sxe2_com_calc_nonclear_stats(&stats->tx_frame_good_bad,
				     new_stats->tx_frame_good_bad,
				     &old_stats->tx_frame_good_bad);
	sxe2_com_calc_nonclear_stats(&stats->rx_size_64, new_stats->rx_size_64,
				     &old_stats->rx_size_64);
	sxe2_com_calc_nonclear_stats(&stats->rx_size_65_127, new_stats->rx_size_65_127,
				     &old_stats->rx_size_65_127);
	sxe2_com_calc_nonclear_stats(&stats->rx_size_128_255, new_stats->rx_size_128_255,
				     &old_stats->rx_size_128_255);
	sxe2_com_calc_nonclear_stats(&stats->rx_size_256_511, new_stats->rx_size_256_511,
				     &old_stats->rx_size_256_511);
	sxe2_com_calc_nonclear_stats(&stats->rx_size_512_1023, new_stats->rx_size_512_1023,
				     &old_stats->rx_size_512_1023);
	sxe2_com_calc_nonclear_stats(&stats->rx_size_1024_1522,
				     new_stats->rx_size_1024_1522,
				     &old_stats->rx_size_1024_1522);
	sxe2_com_calc_nonclear_stats(&stats->rx_size_1523_max, new_stats->rx_size_1523_max,
				     &old_stats->rx_size_1523_max);
	sxe2_com_calc_nonclear_stats(&stats->rx_illegal_bytes, new_stats->rx_illegal_bytes,
				     &old_stats->rx_illegal_bytes);
	sxe2_com_calc_nonclear_stats(&stats->tx_unicast, new_stats->tx_unicast,
				     &old_stats->tx_unicast);
	sxe2_com_calc_nonclear_stats(&stats->tx_broadcast, new_stats->tx_broadcast,
				     &old_stats->tx_broadcast);
	sxe2_com_calc_nonclear_stats(&stats->tx_multicast, new_stats->tx_multicast,
				     &old_stats->tx_multicast);
	sxe2_com_calc_nonclear_stats(&stats->tx_vlan_packet_good,
				     new_stats->tx_vlan_packet_good,
				     &old_stats->tx_vlan_packet_good);
	sxe2_com_calc_nonclear_stats(&stats->tx_size_64, new_stats->tx_size_64,
				     &old_stats->tx_size_64);
	sxe2_com_calc_nonclear_stats(&stats->tx_size_65_127, new_stats->tx_size_65_127,
				     &old_stats->tx_size_65_127);
	sxe2_com_calc_nonclear_stats(&stats->tx_size_128_255, new_stats->tx_size_128_255,
				     &old_stats->tx_size_128_255);
	sxe2_com_calc_nonclear_stats(&stats->tx_size_256_511, new_stats->tx_size_256_511,
				     &old_stats->tx_size_256_511);
	sxe2_com_calc_nonclear_stats(&stats->tx_size_512_1023, new_stats->tx_size_512_1023,
				     &old_stats->tx_size_512_1023);
	sxe2_com_calc_nonclear_stats(&stats->tx_size_1024_1522,
				     new_stats->tx_size_1024_1522,
				     &old_stats->tx_size_1024_1522);
	sxe2_com_calc_nonclear_stats(&stats->tx_size_1523_max, new_stats->tx_size_1523_max,
				     &old_stats->tx_size_1523_max);
	sxe2_com_calc_nonclear_stats(&stats->tx_underflow_error,
				     new_stats->tx_underflow_error,
				     &old_stats->tx_underflow_error);
	sxe2_com_calc_nonclear_stats(&stats->rx_byte_good_bad, new_stats->rx_byte_good_bad,
				     &old_stats->rx_byte_good_bad);
	sxe2_com_calc_nonclear_stats(&stats->rx_frame_good_bad,
				     new_stats->rx_frame_good_bad,
				     &old_stats->rx_frame_good_bad);
	sxe2_com_calc_nonclear_stats(&stats->rx_unicast_good, new_stats->rx_unicast_good,
				     &old_stats->rx_unicast_good);
	sxe2_com_calc_nonclear_stats(&stats->rx_vlan_packets, new_stats->rx_vlan_packets,
				     &old_stats->rx_vlan_packets);
	for (i = 0; i < SXE2_MAX_USER_PRIORITY; i++) {
		sxe2_com_calc_nonclear_stats(&stats->prio_xoff_rx[i],
					     new_stats->prio_xoff_rx[i],
					     &old_stats->prio_xoff_rx[i]);
		sxe2_com_calc_nonclear_stats(&stats->prio_xoff_tx[i],
					     new_stats->prio_xoff_tx[i],
					     &old_stats->prio_xoff_tx[i]);
		sxe2_com_calc_nonclear_stats(&stats->prio_xon_rx[i],
					     new_stats->prio_xon_rx[i],
					     &old_stats->prio_xon_rx[i]);
		sxe2_com_calc_nonclear_stats(&stats->prio_xon_tx[i],
					     new_stats->prio_xon_tx[i],
					     &old_stats->prio_xon_tx[i]);
		sxe2_com_calc_nonclear_stats(&stats->prio_xon_2_xoff[i],
					     new_stats->prio_xon_2_xoff[i],
					     &old_stats->prio_xon_2_xoff[i]);
	}
}

STATIC void sxe2_com_mac_readclear_stats_calc(const struct sxe2_pf_hw_stats *new_stats,
					      struct sxe2_pf_hw_stats *old_stats,
					      struct sxe2_pf_hw_stats *stats)
{
	u8 i = 0;

	SXE2_COM_CALC_READCLEAR_STATS(stats->rx_discards_ips_phy,
				      new_stats->rx_discards_ips_phy,
				      old_stats->rx_discards_ips_phy);
	SXE2_COM_CALC_READCLEAR_STATS(stats->rx_out_of_buffer,
				      new_stats->rx_out_of_buffer,
				      old_stats->rx_out_of_buffer);
	SXE2_COM_CALC_READCLEAR_STATS(stats->rx_qblock_drop, new_stats->rx_qblock_drop,
				      old_stats->rx_qblock_drop);
	SXE2_COM_CALC_READCLEAR_STATS(stats->rx_pcs_symbol_err_phy,
				      new_stats->rx_pcs_symbol_err_phy,
				      old_stats->rx_pcs_symbol_err_phy);
	SXE2_COM_CALC_READCLEAR_STATS(stats->rx_corrected_bits_phy,
				      new_stats->rx_corrected_bits_phy,
				      old_stats->rx_corrected_bits_phy);
	SXE2_COM_CALC_READCLEAR_STATS(stats->rx_err_lane_0_phy,
				      new_stats->rx_err_lane_0_phy,
				      old_stats->rx_err_lane_0_phy);
	SXE2_COM_CALC_READCLEAR_STATS(stats->rx_err_lane_1_phy,
				      new_stats->rx_err_lane_1_phy,
				      old_stats->rx_err_lane_1_phy);
	SXE2_COM_CALC_READCLEAR_STATS(stats->rx_err_lane_2_phy,
				      new_stats->rx_err_lane_2_phy,
				      old_stats->rx_err_lane_2_phy);
	SXE2_COM_CALC_READCLEAR_STATS(stats->rx_err_lane_3_phy,
				      new_stats->rx_err_lane_3_phy,
				      old_stats->rx_err_lane_3_phy);
	for (i = 0; i < SXE2_MAX_USER_PRIORITY; i++) {
		SXE2_COM_CALC_READCLEAR_STATS(stats->rx_prio_buf_discard[i],
					      new_stats->rx_prio_buf_discard[i],
					      old_stats->rx_prio_buf_discard[i]);
	}
}

STATIC void sxe2_com_mac_stats_copy_to_user(struct sxe2_drv_mac_stats_resp *resp,
					    struct sxe2_pf_hw_stats *stats)
{
	u8 i = 0;

	resp->rx_out_of_buffer = stats->rx_out_of_buffer;
	resp->rx_qblock_drop = stats->rx_qblock_drop;
	resp->tx_frame_good = stats->tx_frame_good;
	resp->rx_frame_good = stats->rx_frame_good;
	resp->rx_crc_errors = stats->rx_crc_errors;
	resp->tx_bytes_good = stats->tx_bytes_good;
	resp->rx_bytes_good = stats->rx_bytes_good;
	resp->tx_multicast_good = stats->tx_multicast_good;
	resp->tx_broadcast_good = stats->tx_broadcast_good;
	resp->rx_multicast_good = stats->rx_multicast_good;
	resp->rx_broadcast_good = stats->rx_broadcast_good;
	resp->rx_len_errors = stats->rx_len_errors;
	resp->rx_out_of_range_errors = stats->rx_out_of_range_errors;
	resp->rx_oversize_pkts_phy = stats->rx_oversize_pkts_phy;
	resp->rx_symbol_err = stats->rx_symbol_err;
	resp->rx_pause_frame = stats->rx_pause_frame;
	resp->tx_pause_frame = stats->tx_pause_frame;
	resp->rx_discards_phy = stats->rx_discards_phy;
	resp->rx_discards_ips_phy = stats->rx_discards_ips_phy;
	resp->tx_dropped_link_down = stats->tx_dropped_link_down;
	resp->rx_undersize_good = stats->rx_undersize_good;
	resp->rx_runt_error = stats->rx_runt_error;
	resp->tx_bytes_good_bad = stats->tx_bytes_good_bad;
	resp->tx_frame_good_bad = stats->tx_frame_good_bad;
	resp->rx_jabbers = stats->rx_jabbers;
	resp->rx_size_64 = stats->rx_size_64;
	resp->rx_size_65_127 = stats->rx_size_65_127;
	resp->rx_size_128_255 = stats->rx_size_128_255;
	resp->rx_size_256_511 = stats->rx_size_256_511;
	resp->rx_size_512_1023 = stats->rx_size_512_1023;
	resp->rx_size_1024_1522 = stats->rx_size_1024_1522;
	resp->rx_size_1523_max = stats->rx_size_1523_max;
	resp->rx_pcs_symbol_err_phy = stats->rx_pcs_symbol_err_phy;
	resp->rx_corrected_bits_phy = stats->rx_corrected_bits_phy;
	resp->rx_err_lane_0_phy = stats->rx_err_lane_0_phy;
	resp->rx_err_lane_1_phy = stats->rx_err_lane_1_phy;
	resp->rx_err_lane_2_phy = stats->rx_err_lane_2_phy;
	resp->rx_err_lane_3_phy = stats->rx_err_lane_3_phy;
	resp->rx_illegal_bytes = stats->rx_illegal_bytes;
	resp->rx_oversize_good = stats->rx_oversize_good;
	resp->tx_unicast = stats->tx_unicast;
	resp->tx_broadcast = stats->tx_broadcast;
	resp->tx_multicast = stats->tx_multicast;
	resp->tx_vlan_packet_good = stats->tx_vlan_packet_good;
	resp->tx_size_64 = stats->tx_size_64;
	resp->tx_size_65_127 = stats->tx_size_65_127;
	resp->tx_size_128_255 = stats->tx_size_128_255;
	resp->tx_size_256_511 = stats->tx_size_256_511;
	resp->tx_size_512_1023 = stats->tx_size_512_1023;
	resp->tx_size_1024_1522 = stats->tx_size_1024_1522;
	resp->tx_size_1523_max = stats->tx_size_1523_max;
	resp->tx_underflow_error = stats->tx_underflow_error;
	resp->rx_byte_good_bad = stats->rx_byte_good_bad;
	resp->rx_frame_good_bad = stats->rx_frame_good_bad;
	resp->rx_unicast_good = stats->rx_unicast_good;
	resp->rx_vlan_packets = stats->rx_vlan_packets;
	for (i = 0; i < SXE2_MAX_USER_PRIORITY; i++) {
		resp->rx_prio_buf_discard[i] = stats->rx_prio_buf_discard[i];
		resp->prio_xoff_rx[i] = stats->prio_xoff_rx[i];
		resp->prio_xoff_tx[i] = stats->prio_xoff_tx[i];
		resp->prio_xon_rx[i] = stats->prio_xon_rx[i];
		resp->prio_xon_tx[i] = stats->prio_xon_tx[i];
		resp->prio_xon_2_xoff[i] = stats->prio_xon_2_xoff[i];
	}
}

s32 sxe2_com_mac_stat_get(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			  struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_mac_stats_resp *resp = NULL;
	struct sxe2_pf_hw_stats *hw_stats = &adapter->pf_stats.parse_pf_hw_stats;
	struct sxe2_pf_hw_stats *last_hw_stats =
			&adapter->pf_stats.parse_last_pf_hw_stats;
	s32 ret = 0;

	resp = kzalloc(sizeof(*resp), GFP_KERNEL);
	if (!resp) {
		LOG_ERROR_BDF("kzalloc mr mem failed.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	sxe2_hw_pf_stats_update(adapter);
	sxe2_com_mac_nonclear_stats_calc(&adapter->pf_stats.last_pf_hw_stats,
					 last_hw_stats, hw_stats);
	sxe2_com_mac_readclear_stats_calc(&adapter->pf_stats.pf_hw_stats, last_hw_stats,
					  hw_stats);

	sxe2_com_mac_stats_copy_to_user(resp, hw_stats);
	if (sxe2_com_resp_copy_to_user(cmd_buf, resp, sizeof(*resp), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed.\n");
		ret = -EFAULT;
		goto l_end;
	}
	cmd_buf->resp_len = sizeof(*resp);

	LOG_INFO_BDF("sxe2 com pf[%d] stats get is completed.\n", adapter->pf_idx);

l_end:
	kfree(resp);
	return ret;
}

s32 sxe2_com_mac_stat_clear(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			    struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_pf_hw_stats *hw_stats = &adapter->pf_stats.parse_pf_hw_stats;
	struct sxe2_pf_hw_stats *last_hw_stats =
			&adapter->pf_stats.parse_last_pf_hw_stats;
	u8 i = 0;

	sxe2_hw_pf_stats_update(adapter);

	(void)memcpy(last_hw_stats, &adapter->pf_stats.last_pf_hw_stats,
		     sizeof(*last_hw_stats));
	(void)memset(hw_stats, 0, sizeof(*last_hw_stats));

	last_hw_stats->rx_discards_ips_phy =
			adapter->pf_stats.pf_hw_stats.rx_discards_ips_phy;
	last_hw_stats->rx_out_of_buffer = adapter->pf_stats.pf_hw_stats.rx_out_of_buffer;
	last_hw_stats->rx_qblock_drop = adapter->pf_stats.pf_hw_stats.rx_qblock_drop;
	last_hw_stats->rx_pcs_symbol_err_phy =
			adapter->pf_stats.pf_hw_stats.rx_pcs_symbol_err_phy;
	last_hw_stats->rx_corrected_bits_phy =
			adapter->pf_stats.pf_hw_stats.rx_corrected_bits_phy;
	last_hw_stats->rx_err_lane_0_phy =
			adapter->pf_stats.pf_hw_stats.rx_err_lane_0_phy;
	last_hw_stats->rx_err_lane_1_phy =
			adapter->pf_stats.pf_hw_stats.rx_err_lane_1_phy;
	last_hw_stats->rx_err_lane_2_phy =
			adapter->pf_stats.pf_hw_stats.rx_err_lane_2_phy;
	last_hw_stats->rx_err_lane_3_phy =
			adapter->pf_stats.pf_hw_stats.rx_err_lane_3_phy;
	for (i = 0; i < SXE2_MAX_USER_PRIORITY; i++) {
		last_hw_stats->rx_prio_buf_discard[i] =
				adapter->pf_stats.pf_hw_stats.rx_prio_buf_discard[i];
	}

	LOG_INFO_BDF("sxe2 com pf[%d] stats clear is completed.\n", adapter->pf_idx);
	return 0;
}
