/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_dfx.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_DFX_H__
#define __SXE2_DFX_H__

#include <linux/types.h>
#include <linux/kernel.h>

#include "sxe2.h"

union sxe2_rxft_ppe_protocol_info {
	u32 val;
	struct {
		u32 protocol_id : 8;
		u32 protocol_offset : 8;
		u32 rsv : 16;
	} reg;
};

struct sxe2_rxft_dbg_ppe_info_action_type_1 {
	u32 action_type : 5;
	u32 action_pro : 3;
	u32 pkt_tc : 3;
	u32 port : 2;
	u32 pkt_len : 14;
	u32 src_pf : 3;
	u32 src_vf_1_0 : 2;

	u32 srx_vf_7_2 : 6;
	u32 src_txvsi : 10;
	u32 src_pf_vf_vm_flg : 2;
	u32 pkt_type : 10;
	u32 head0_addr_63_60 : 4;

	u32 head0_addr_72_64 : 9;
	u32 head1_addr : 13;
	u32 head_addr_valid : 1;
	u32 dst_pf : 3;
	u32 dst_vf_5_0 : 6;

	u32 dst_vf_7_6 : 2;
	u32 dst_vsi : 10;
	u32 dst_pf_vf_vm_flg : 2;
	u32 up : 3;
	u32 tcp_syn : 1;
	u32 tcp_ack : 1;
	u32 tcp_rst : 1;
	u32 tcp_fin : 1;
	u32 l2_mac_err : 1;
	u32 bypass_switch : 1;
	u32 bypass_acl : 1;
	u32 bypass_rxft : 1;
	u32 drop : 1;
	u32 parser_abort : 1;
	u32 malicious_abort : 1;
	u32 packet_source_type : 2;
	u32 pkt_source : 2;

	u32 fd_program : 1;
	u32 fd_program_dummy : 1;
	u32 lan_tx_sw : 2;
	u32 rdma_tx_swap : 1;
	u32 pkt_dest : 2;
	u32 icrc_err : 1;
	u32 ipeh : 1;
	u32 esp : 1;
	u32 mpls : 1;
	u32 fragment : 1;
	u32 checksum_offload : 1;
	u32 ipe : 1;
	u32 l4e : 1;
	u32 eipe : 1;
	u32 eudpe : 1;
	u32 mac_in_mac : 1;
	u32 pkt_err : 6;
	u32 mirr_id : 6;
	u32 mirr_type : 2;

	u32 multicast_copy : 1;
	u32 umbcast : 2;
	u32 tunnel_type : 5;
	u32 oam : 1;
	u32 flow_id_vld : 1;
	u32 rsv : 1;
	u32 acl_hit : 1;
	u32 macsec_err : 2;
	u32 last_action : 1;
	u32 last_mc_pkt : 1;
	u32 first_action : 1;
	u32 protocol_id0 : 8;
	u32 protocol_offset0_6_0 : 7;

	u32 protocol_offset0_7 : 1;
	u32 protocol_id1 : 8;
	u32 protocol_offset1 : 8;
	u32 protocol_id2 : 8;
	u32 protocol_offset2_6_0 : 7;

	u32 protocol_offset2_7 : 1;
	u32 protocol_id3 : 8;
	u32 protocol_offset3 : 8;
	u32 protocol_id4 : 8;
	u32 protocol_offset4_6_0 : 7;

	u32 protocol_offset4_7 : 1;
	u32 protocol_id5 : 8;
	u32 protocol_offset5 : 8;
	u32 protocol_id6 : 8;
	u32 protocol_offset6_6_0 : 7;

	u32 protocol_offset6_7 : 1;
	u32 protocol_id7 : 8;
	u32 protocol_offset7 : 8;
	u32 protocol_id8 : 8;
	u32 protocol_offset8_6_0 : 7;

	u32 protocol_offset8_7 : 1;
	u32 protocol_id9 : 8;
	u32 protocol_offset9 : 8;
	u32 protocol_id10 : 8;
	u32 protocol_offset10_6_0 : 7;

	u32 protocol_offset10_7 : 1;
	u32 protocol_id11 : 8;
	u32 protocol_offset11 : 8;
	u32 protocol_id12 : 8;
	u32 protocol_offset12_6_0 : 7;

	u32 protocol_offset12_7 : 1;
	u32 protocol_id13 : 8;
	u32 protocol_offset13 : 8;
	u32 protocol_id14 : 8;
	u32 protocol_offset14_6_0 : 7;

	u32 protocol_offset14_7 : 1;
	u32 protocol_id15 : 8;
	u32 protocol_offset15 : 8;
	u32 protocol_id_num : 5;
	u32 sw_profile_id : 8;
	u32 acl_profile_id_1_0 : 2;

	u32 acl_profile_id_6_2 : 5;
	u32 fd_profile_id : 7;
	u32 flow_id : 16;
	u32 flow_id_pri : 3;
	u32 rsv1 : 1;

	u32 rsv2;

	u32 rsv3;

	u32 rsv4;

	u32 rsv5;

	u32 rsv6 : 6;
	u32 sdf_hash : 12;
	u32 sdf_pri : 6;
	u32 fd_prog_drop : 1;
	u32 trace_level : 2;
	u32 pkt_src_bfd : 1;
	u32 to_host : 1;
	u32 to_mng : 1;
	u32 to_lan : 1;
	u32 to_roce : 1;
};

struct sxe2_rxft_dbg_ppe_info_action_type_9 {
	u32 action_type : 5;
	u32 action_pro : 3;
	u32 pkt_tc : 3;
	u32 port : 2;
	u32 pkt_len : 14;
	u32 src_pf : 3;
	u32 src_vf_31_30 : 2;

	u32 srx_vf_37_32 : 6;
	u32 src_txvsi : 10;
	u32 src_pf_vf_vm_flg : 2;
	u32 pkt_type : 10;
	u32 head0_addr_63_60 : 4;

	u32 head0_addr_72_64 : 9;
	u32 head1_addr : 13;
	u32 head_addr_valid : 1;
	u32 dst_pf : 3;
	u32 dst_vf_95_90 : 6;

	u32 dst_vf_97_96 : 2;
	u32 dst_vsi : 10;
	u32 dst_pf_vf_vm_flg : 2;
	u32 up : 3;
	u32 tcp_syn : 1;
	u32 tcp_ack : 1;
	u32 tcp_rst : 1;
	u32 tcp_fin : 1;
	u32 l2_mac_err : 1;
	u32 bypass_switch : 1;
	u32 bypass_acl : 1;
	u32 bypass_rxft : 1;
	u32 drop : 1;
	u32 parser_abort : 1;
	u32 malicious_abort : 1;
	u32 packet_source_type : 2;
	u32 pkt_source : 2;

	u32 fd_program : 1;
	u32 fd_program_dummy : 1;
	u32 lan_tx_sw : 2;
	u32 rdma_tx_swap : 1;
	u32 pkt_dest : 2;
	u32 icrc_err : 1;
	u32 ipeh : 1;
	u32 esp : 1;
	u32 mpls : 1;
	u32 fragment : 1;
	u32 checksum_offload : 1;
	u32 ipe : 1;
	u32 l4e : 1;
	u32 eipe : 1;
	u32 eudpe : 1;
	u32 rsv0 : 1;
	u32 pkt_err : 6;
	u32 mirr_id : 6;
	u32 mirr_type : 2;

	u32 multicast_copy : 1;
	u32 umbcast : 2;
	u32 tunnel_type : 5;
	u32 oam : 1;
	u32 flow_id_vld : 1;
	u32 switch_hit : 1;
	u32 acl_hit : 1;
	u32 macsec_err : 2;
	u32 last_action : 1;
	u32 last_mc_pkt : 1;
	u32 first_action : 1;
	u32 protocol_id0 : 8;
	u32 protocol_offset0_6_0 : 7;

	u32 protocol_offset0_7 : 1;
	u32 protocol_id1 : 8;
	u32 protocol_offset1 : 8;
	u32 protocol_id2 : 8;
	u32 protocol_offset2_6_0 : 7;

	u32 protocol_offset2_7 : 1;
	u32 protocol_id3 : 8;
	u32 protocol_offset3 : 8;
	u32 protocol_id4 : 8;
	u32 protocol_offset4_6_0 : 7;

	u32 protocol_offset4_7 : 1;
	u32 protocol_id5 : 8;
	u32 protocol_offset5 : 8;
	u32 protocol_id6 : 8;
	u32 protocol_offset6_6_0 : 7;

	u32 protocol_offset6_7 : 1;
	u32 protocol_id7 : 8;
	u32 protocol_offset7 : 8;
	u32 protocol_id8 : 8;
	u32 protocol_offset8_6_0 : 7;

	u32 protocol_offset8_7 : 1;
	u32 protocol_id9 : 8;
	u32 protocol_offset9 : 8;
	u32 protocol_id10 : 8;
	u32 protocol_offset10_6_0 : 7;

	u32 protocol_offset10_7 : 1;
	u32 protocol_id11 : 8;
	u32 protocol_offset11 : 8;
	u32 protocol_id12 : 8;
	u32 protocol_offset12_6_0 : 7;

	u32 protocol_offset12_7 : 1;
	u32 protocol_id13 : 8;
	u32 protocol_offset13 : 8;
	u32 protocol_id14 : 8;
	u32 protocol_offset14_6_0 : 7;

	u32 protocol_offset14_7 : 1;
	u32 protocol_id15 : 8;
	u32 protocol_offset15 : 8;
	u32 protocol_id_num : 5;
	u32 sw_profile_id : 8;
	u32 acl_profile_id_1_0 : 2;

	u32 acl_profile_id_6_2 : 5;
	u32 fd_profile_id : 7;
	u32 flow_id : 16;
	u32 flow_id_pri : 3;
	u32 queue_buf_num_0 : 1;

	u32 queue_buf_num_10_1 : 10;
	u32 toqueue : 3;
	u32 queue_hit_flag : 4;
	u32 queue_sel_result : 2;
	u32 rsv1 : 13;
};

struct sxe2_rxft_dbg_ppe_info_action_type_10 {
	u32 action_type : 5;
	u32 action_pro : 3;
	u32 pkt_tc : 3;
	u32 port : 2;
	u32 pkt_len : 14;
	u32 src_pf : 3;
	u32 src_vf_31_30 : 2;

	u32 srx_vf_37_32 : 6;
	u32 src_txvsi : 10;
	u32 src_pf_vf_vm_flg : 2;
	u32 pkt_type : 10;
	u32 head0_addr_63_60 : 4;

	u32 head0_addr_72_64 : 9;
	u32 head1_addr : 13;
	u32 head_addr_valid : 1;
	u32 dst_pf : 3;
	u32 dst_vf_95_90 : 6;

	u32 dst_vf_97_96 : 2;
	u32 dst_vsi : 10;
	u32 dst_pf_vf_vm_flg : 2;
	u32 up : 3;
	u32 tcp_syn : 1;
	u32 tcp_ack : 1;
	u32 tcp_rst : 1;
	u32 tcp_fin : 1;
	u32 l2_mac_err : 1;
	u32 bypass_switch : 1;
	u32 bypass_acl : 1;
	u32 bypass_rxft : 1;
	u32 drop : 1;
	u32 parser_abort : 1;
	u32 malicious_abort : 1;
	u32 packet_source_type : 2;
	u32 pkt_source : 2;

	u32 fd_program : 1;
	u32 fd_program_dummy : 1;
	u32 lan_tx_sw : 2;
	u32 rdma_tx_swap : 1;
	u32 pkt_dest : 2;
	u32 icrc_err : 1;
	u32 ipeh : 1;
	u32 esp : 1;
	u32 mpls : 1;
	u32 fragment : 1;
	u32 checksum_offload : 1;
	u32 ipe : 1;
	u32 l4e : 1;
	u32 eipe : 1;
	u32 eudpe : 1;
	u32 rsv0 : 1;
	u32 pkt_err : 6;
	u32 mirr_id : 6;
	u32 mirr_type : 2;

	u32 multicast_copy : 1;
	u32 umbcast : 2;
	u32 tunnel_type : 5;
	u32 oam : 1;
	u32 flow_id_vld : 1;
	u32 switch_hit : 1;
	u32 acl_hit : 1;
	u32 macsec_err : 2;
	u32 last_action : 1;
	u32 last_mc_pkt : 1;
	u32 first_action : 1;
	u32 protocol_id0 : 8;
	u32 protocol_offset0_6_0 : 7;

	u32 protocol_offset0_7 : 1;
	u32 protocol_id1 : 8;
	u32 protocol_offset1 : 8;
	u32 protocol_id2 : 8;
	u32 protocol_offset2_6_0 : 7;

	u32 protocol_offset2_7 : 1;
	u32 protocol_id3 : 8;
	u32 protocol_offset3 : 8;
	u32 protocol_id4 : 8;
	u32 protocol_offset4_6_0 : 7;

	u32 protocol_offset4_7 : 1;
	u32 protocol_id5 : 8;
	u32 protocol_offset5 : 8;
	u32 protocol_id6 : 8;
	u32 protocol_offset6_6_0 : 7;

	u32 protocol_offset6_7 : 1;
	u32 protocol_id7 : 8;
	u32 protocol_offset7 : 8;
	u32 protocol_id8 : 8;
	u32 protocol_offset8_6_0 : 7;

	u32 protocol_offset8_7 : 1;
	u32 protocol_id9 : 8;
	u32 protocol_offset9 : 8;
	u32 protocol_id10 : 8;
	u32 protocol_offset10_6_0 : 7;

	u32 protocol_offset10_7 : 1;
	u32 protocol_id11 : 8;
	u32 protocol_offset11 : 8;
	u32 protocol_id12 : 8;
	u32 protocol_offset12_6_0 : 7;

	u32 protocol_offset12_7 : 1;
	u32 protocol_id13 : 8;
	u32 protocol_offset13 : 8;
	u32 protocol_id14 : 8;
	u32 protocol_offset14_6_0 : 7;

	u32 protocol_offset14_7 : 1;
	u32 protocol_id15 : 8;
	u32 protocol_offset15 : 8;
	u32 protocol_id_num : 5;
	u32 sw_profile_id : 8;
	u32 acl_profile_id_1_0 : 2;

	u32 acl_profile_id_6_2 : 5;
	u32 fd_profile_id : 7;
	u32 flow_id : 16;
	u32 flow_id_pri : 3;
	u32 qindex_0 : 1;

	u32 qindex_10_1 : 10;
	u32 comp_queue : 1;
	u32 comp_report : 2;
	u32 fd_space : 2;
	u32 stat_cnt : 14;
	u32 stat_ena : 2;
	u32 evict_ena : 1;

	u32 to_queue : 3;
	u32 to_queue_prio : 3;
	u32 dpu_repie : 1;
	u32 fd_drop : 1;
	u32 flex : 7;
	u32 fd_flow_id : 16;
	u32 d_type_0 : 1;

	u32 d_type_3_1 : 3;
	u32 pcmd : 2;
	u32 desc_pro_prio : 2;
	u32 desc_prof : 6;
	u32 fd_vsi : 10;
	u32 swap : 1;
	u32 fdid_prio : 3;
	u32 fdid_did : 4;
	u32 fdid_0 : 1;

	u32 fdid_31_1 : 31;
	u32 rsv2 : 1;
};

struct sxe2_rxft_dbg_ppe_info_action_type_14 {
	u32 action_type : 5;
	u32 action_pro : 3;
	u32 pkt_tc : 3;
	u32 port : 2;
	u32 pkt_len : 14;
	u32 src_pf : 3;
	u32 src_vf_1_0 : 2;

	u32 srx_vf_7_2 : 6;
	u32 src_txvsi : 10;
	u32 src_pf_vf_vm_flg : 2;
	u32 pkt_type : 10;
	u32 head0_addr_63_60 : 4;

	u32 head0_addr_72_64 : 9;
	u32 head1_addr : 13;
	u32 head_addr_valid : 1;
	u32 dst_pf : 3;
	u32 dst_vf_5_0 : 6;

	u32 dst_vf_7_6 : 2;
	u32 dst_vsi : 10;
	u32 dst_pf_vf_vm_flg : 2;
	u32 up : 3;
	u32 tcp_syn : 1;
	u32 tcp_ack : 1;
	u32 tcp_rst : 1;
	u32 tcp_fin : 1;
	u32 l2_mac_err : 1;
	u32 bypass_switch : 1;
	u32 bypass_acl : 1;
	u32 bypass_rxft : 1;
	u32 drop : 1;
	u32 parser_abort : 1;
	u32 malicious_abort : 1;
	u32 packet_source_type : 2;
	u32 pkt_source : 2;

	u32 fd_program : 1;
	u32 fd_program_dummy : 1;
	u32 lan_tx_sw : 2;
	u32 rdma_tx_swap : 1;
	u32 pkt_dest : 2;
	u32 icrc_err : 1;
	u32 ipeh : 1;
	u32 esp : 1;
	u32 mpls : 1;
	u32 fragment : 1;
	u32 checksum_offload : 1;
	u32 ipe : 1;
	u32 l4e : 1;
	u32 eipe : 1;
	u32 eudpe : 1;
	u32 rsv0 : 1;
	u32 pkt_err : 6;
	u32 mirr_id : 6;
	u32 mirr_type : 2;

	u32 multicast_copy : 1;
	u32 umbcast : 2;
	u32 tunnel_type : 5;
	u32 oam : 1;
	u32 flow_id_vld : 1;
	u32 switch_hit : 1;
	u32 acl_hit : 1;
	u32 macsec_err : 2;
	u32 last_action : 1;
	u32 last_mc_pkt : 1;
	u32 first_action : 1;
	u32 protocol_id0 : 8;
	u32 protocol_offset0_6_0 : 7;

	u32 protocol_offset0_7 : 1;
	u32 protocol_id1 : 8;
	u32 protocol_offset1 : 8;
	u32 protocol_id2 : 8;
	u32 protocol_offset2_6_0 : 7;

	u32 protocol_offset2_7 : 1;
	u32 protocol_id3 : 8;
	u32 protocol_offset3 : 8;
	u32 protocol_id4 : 8;
	u32 protocol_offset4_6_0 : 7;

	u32 protocol_offset4_7 : 1;
	u32 protocol_id5 : 8;
	u32 protocol_offset5 : 8;
	u32 protocol_id6 : 8;
	u32 protocol_offset6_6_0 : 7;

	u32 protocol_offset6_7 : 1;
	u32 protocol_id7 : 8;
	u32 protocol_offset7 : 8;
	u32 protocol_id8 : 8;
	u32 protocol_offset8_6_0 : 7;

	u32 protocol_offset8_7 : 1;
	u32 protocol_id9 : 8;
	u32 protocol_offset9 : 8;
	u32 protocol_id10 : 8;
	u32 protocol_offset10_6_0 : 7;

	u32 protocol_offset10_7 : 1;
	u32 protocol_id11 : 8;
	u32 protocol_offset11 : 8;
	u32 protocol_id12 : 8;
	u32 protocol_offset12_6_0 : 7;

	u32 protocol_offset12_7 : 1;
	u32 protocol_id13 : 8;
	u32 protocol_offset13 : 8;
	u32 protocol_id14 : 8;
	u32 protocol_offset14_6_0 : 7;

	u32 protocol_offset14_7 : 1;
	u32 protocol_id15 : 8;
	u32 protocol_offset15 : 8;
	u32 protocol_id_num : 5;
	u32 rh_ip_offset : 8;
	u32 rh_vlan_offset1_0 : 2;

	u32 rh_vlan_offset7_2 : 6;
	u32 rh_vlan_vld : 1;
	u32 rh_dqpn : 18;
	u32 rsv1 : 6;
	u32 dst_rdma_mc_num_0 : 1;

	u32 dst_rdma_mc_num_12_1 : 12;
	u32 rdma_mc_cnt : 10;
	u32 rsv2 : 10;
};

void sxe2_fwc_rxft_ppe_info(struct sxe2_adapter *adapter);

void sxe2_fwc_ppe_dfx_show(struct sxe2_adapter *adapter);

#endif
