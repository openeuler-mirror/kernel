/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef _UB_UBASE_COMM_STATS_H_
#define _UB_UBASE_COMM_STATS_H_

#include <linux/auxiliary_bus.h>

#define UBASE_STATS_MAX_VL_NUM	16
#define UBASE_MAX_PORT_NUM	64

struct ubase_ub_dl_stats {
	u64	dl_tx_vl0_pkt_num;
	u64	dl_tx_vl1_pkt_num;
	u64	dl_tx_vl2_pkt_num;
	u64	dl_tx_vl3_pkt_num;
	u64	dl_tx_vl4_pkt_num;
	u64	dl_tx_vl5_pkt_num;
	u64	dl_tx_vl6_pkt_num;
	u64	dl_tx_vl7_pkt_num;
	u64	dl_tx_vl8_pkt_num;
	u64	dl_tx_vl9_pkt_num;
	u64	dl_tx_vl10_pkt_num;
	u64	dl_tx_vl11_pkt_num;

	u64	dl_rx_vl0_pkt_num;
	u64	dl_rx_vl1_pkt_num;
	u64	dl_rx_vl2_pkt_num;
	u64	dl_rx_vl3_pkt_num;
	u64	dl_rx_vl4_pkt_num;
	u64	dl_rx_vl5_pkt_num;
	u64	dl_rx_vl6_pkt_num;
	u64	dl_rx_vl7_pkt_num;
	u64	dl_rx_vl8_pkt_num;
	u64	dl_rx_vl9_pkt_num;
	u64	dl_rx_vl10_pkt_num;
	u64	dl_rx_vl11_pkt_num;

	u64	dl_tx_busi_pkt_num;
	u64	dl_tx_busi_block_num;
	u64	dl_tx_busi_flit_num;
	u64	dl_rx_busi_pkt_num;
	u64	dl_rx_busi_block_num;
	u64	dl_rx_busi_flit_num;
	u64	dl_tx_ctrl_pkt_num;
	u64	dl_tx_ctrl_pkt_flit_num;
	u64	dl_rx_ctrl_pkt_num;
	u64	dl_rx_ctrl_pkt_flit_num;

	u64	dl_rx_vl0_from_nl_crd;
	u64	dl_rx_vl1_from_nl_crd;
	u64	dl_rx_vl2_from_nl_crd;
	u64	dl_rx_vl3_from_nl_crd;
	u64	dl_rx_vl4_from_nl_crd;
	u64	dl_rx_vl5_from_nl_crd;
	u64	dl_rx_vl6_from_nl_crd;
	u64	dl_rx_vl7_from_nl_crd;
	u64	dl_rx_vl8_from_nl_crd;
	u64	dl_rx_vl9_from_nl_crd;
	u64	dl_rx_vl10_from_nl_crd;
	u64	dl_rx_vl11_from_nl_crd;

	u64	dl_tx_vl0_to_nl_crd;
	u64	dl_tx_vl1_to_nl_crd;
	u64	dl_tx_vl2_to_nl_crd;
	u64	dl_tx_vl3_to_nl_crd;
	u64	dl_tx_vl4_to_nl_crd;
	u64	dl_tx_vl5_to_nl_crd;
	u64	dl_tx_vl6_to_nl_crd;
	u64	dl_tx_vl7_to_nl_crd;
	u64	dl_tx_vl8_to_nl_crd;
	u64	dl_tx_vl9_to_nl_crd;
	u64	dl_tx_vl10_to_nl_crd;
	u64	dl_tx_vl11_to_nl_crd;

	u64	dl_tx_recv_ack_flit;
	u64	dl_rx_send_ack_flit;
	u64	dl_retry_req_sum;
	u64	dl_retry_ack_sum;
	u64	dl_crc_error_sum;

	u64	dl_tx_vl12_pkt_num;
	u64	dl_tx_vl13_pkt_num;
	u64	dl_tx_vl14_pkt_num;
	u64	dl_tx_vl15_pkt_num;

	u64	dl_rx_vl12_pkt_num;
	u64	dl_rx_vl13_pkt_num;
	u64	dl_rx_vl14_pkt_num;
	u64	dl_rx_vl15_pkt_num;

	u64	dl_rx_vl12_from_nl_crd;
	u64	dl_rx_vl13_from_nl_crd;
	u64	dl_rx_vl14_from_nl_crd;
	u64	dl_rx_vl15_from_nl_crd;

	u64	dl_tx_vl12_to_nl_crd;
	u64	dl_tx_vl13_to_nl_crd;
	u64	dl_tx_vl14_to_nl_crd;
	u64	dl_tx_vl15_to_nl_crd;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
	KABI_RESERVE(7)
	KABI_RESERVE(8)
	KABI_RESERVE(9)
	KABI_RESERVE(10)
	KABI_RESERVE(11)
	KABI_RESERVE(12)
};

struct ubase_eth_mac_stats {
	u64	tx_fragment_pkts;
	u64	tx_undersize_pkts;
	u64	tx_undermin_pkts;

	u64	tx_64_octets_pkts;
	u64	tx_65_127_octets_pkts;
	u64	tx_128_255_octets_pkts;
	u64	tx_256_511_octets_pkts;
	u64	tx_512_1023_octets_pkts;
	u64	tx_1024_1518_octets_pkts;
	u64	tx_1519_2047_octets_pkts;
	u64	tx_2048_4095_octets_pkts;
	u64	tx_4096_8191_octets_pkts;
	u64	tx_8192_9216_octets_pkts;
	u64	tx_9217_12287_octets_pkts;
	u64	tx_12288_16383_octets_pkts;
	u64	tx_1519_max_octets_bad_pkts;
	u64	tx_1519_max_octets_good_pkts;
	u64	tx_oversize_pkts;
	u64	tx_jabber_pkts;
	u64	tx_bad_pkts;
	u64	tx_bad_octets;
	u64	tx_good_pkts;
	u64	tx_good_octets;
	u64	tx_total_pkts;
	u64	tx_total_octets;
	u64	tx_unicast_pkts;
	u64	tx_multicast_pkts;
	u64	tx_broadcast_pkts;

	u64	tx_pause_pkts;
	u64	tx_pfc_pkts;
	u64	tx_pri0_pfc_pkts;
	u64	tx_pri1_pfc_pkts;
	u64	tx_pri2_pfc_pkts;
	u64	tx_pri3_pfc_pkts;
	u64	tx_pri4_pfc_pkts;
	u64	tx_pri5_pfc_pkts;
	u64	tx_pri6_pfc_pkts;
	u64	tx_pri7_pfc_pkts;

	u64	tx_mac_ctrl_pkts;
	u64	tx_unfilter_pkts;
	u64	tx_1588_pkts;
	u64	tx_err_all_pkts;
	u64	tx_from_app_good_pkts;
	u64	tx_from_app_bad_pkts;

	u64	rx_fragment_pkts;
	u64	rx_undersize_pkts;
	u64	rx_undermin_pkts;

	u64	rx_64_octets_pkts;
	u64	rx_65_127_octets_pkts;
	u64	rx_128_255_octets_pkts;
	u64	rx_256_511_octets_pkts;
	u64	rx_512_1023_octets_pkts;
	u64	rx_1024_1518_octets_pkts;
	u64	rx_1519_2047_octets_pkts;
	u64	rx_2048_4095_octets_pkts;
	u64	rx_4096_8191_octets_pkts;
	u64	rx_8192_9216_octets_pkts;
	u64	rx_9217_12287_octets_pkts;
	u64	rx_12288_16383_octets_pkts;
	u64	rx_1519_max_octets_bad_pkts;
	u64	rx_1519_max_octets_good_pkts;

	u64	rx_oversize_pkts;
	u64	rx_jabber_pkts;
	u64	rx_bad_pkts;
	u64	rx_bad_octets;
	u64	rx_good_pkts;
	u64	rx_good_octets;
	u64	rx_total_pkts;
	u64	rx_total_octets;
	u64	rx_unicast_pkts;
	u64	rx_multicast_pkts;
	u64	rx_broadcast_pkts;

	u64	rx_pause_pkts;
	u64	rx_pfc_pkts;
	u64	rx_pri0_pfc_pkts;
	u64	rx_pri1_pfc_pkts;
	u64	rx_pri2_pfc_pkts;
	u64	rx_pri3_pfc_pkts;
	u64	rx_pri4_pfc_pkts;
	u64	rx_pri5_pfc_pkts;
	u64	rx_pri6_pfc_pkts;
	u64	rx_pri7_pfc_pkts;

	u64	rx_mac_ctrl_pkts;
	u64	rx_symbol_err_pkts;
	u64	rx_fcs_err_pkts;
	u64	rx_send_app_good_pkts;
	u64	rx_send_app_bad_pkts;
	u64	rx_unfilter_pkts;

	u64	tx_merge_frame_ass_error_pkts;
	u64	tx_merge_frame_ass_ok_pkts;
	u64	tx_merge_frame_frag_count;
	u64	rx_merge_frame_ass_error_pkts;
	u64	rx_merge_frame_ass_ok_pkts;
	u64	rx_merge_frame_frag_count;
	u64	rx_merge_frame_smd_error_pkts;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
	KABI_RESERVE(7)
	KABI_RESERVE(8)
	KABI_RESERVE(9)
	KABI_RESERVE(10)
	KABI_RESERVE(11)
	KABI_RESERVE(12)
};

/**
 * struct ubase_perf_stats_result - traffic bandwidth statistics results
 * @valid: data valid flag, 0-invalid, 1-valid
 * @resv0: reserved bits
 * @port_id: port id
 * @resv1: reserved bits
 * @tx_port_bw: tx port bandwidth
 * @rx_port_bw: rx port bandwidth
 * @tx_vl_bw: tx vl bandwidth
 * @rx_vl_bw: rx vl bandwidth
 * @tx_max_port_bw: tx port max bandwidth
 * @rx_max_port_bw: rx port max bandwidth
 */
struct ubase_perf_stats_result {
	u8	valid : 1;
	u8	resv0 : 7;
	u8	port_id;
	u8	resv1[2];
	u32	tx_port_bw; /* kbps */
	u32	rx_port_bw;
	u32	tx_vl_bw[UBASE_STATS_MAX_VL_NUM];
	u32	rx_vl_bw[UBASE_STATS_MAX_VL_NUM];
	u32	tx_max_port_bw;
	u32	rx_max_port_bw;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ubase_ub_dl_pkt_stats_result - ub dl packet bytes statistics results
 * @valid: data valid flag, 0-invalid, 1-valid
 * @resv0: reserved bits
 * @port_id: port id
 * @resv1: reserved bits
 * @tx_pkt_bytes: tx dl packet bytes
 * @rx_pkt_bytes: rx dl packet bytes
 */
struct ubase_ub_dl_pkt_stats_result {
	u8	valid : 1;
	u8	resv0 : 7;
	u8	port_id;
	u8	resv1[2];

	u64	tx_pkt_bytes;
	u64	rx_pkt_bytes;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
};

void ubase_clear_eth_port_stats(struct auxiliary_device *adev);
int ubase_get_ub_port_stats(struct auxiliary_device *adev, u16 port_id,
			    struct ubase_ub_dl_stats *data);
int ubase_get_eth_port_stats(struct auxiliary_device *adev,
			     struct ubase_eth_mac_stats *data);
int ubase_perf_stats(struct auxiliary_device *adev, u64 port_bitmap, u32 period,
		     struct ubase_perf_stats_result *data, u32 data_size);
int ubase_get_ub_dl_pkt_stats(struct auxiliary_device *adev, u64 port_bitmap,
			      struct ubase_ub_dl_pkt_stats_result *data,
			      u32 data_size);
int ubase_open_perf_stats(struct auxiliary_device *adev, u64 port_bitmap,
			  u32 period);
int ubase_query_perf_stats(struct auxiliary_device *adev, u64 port_bitmap,
			   struct ubase_perf_stats_result *data, u32 data_size);
int ubase_close_perf_stats(struct auxiliary_device *adev, u64 port_bitmap);

#endif /* _UBASE_COMM_STATS_H_ */
