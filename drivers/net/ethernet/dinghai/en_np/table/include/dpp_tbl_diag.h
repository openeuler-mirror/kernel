/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_TBL_DIAG_H
#define DPP_TBL_DIAG_H

#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_tbl_pkt_cap.h"

const char *dpp_vport_table_attr_name_get(u32 attr);
const char *dpp_uplink_phy_port_table_attr_name_get(u32 attr);
const char *dpp_vqm_vfid_vlan_attr_name_get(u32 attr);

u32 diag_dpp_sdt_tbl_prt(u32 sdt_no);
u32 diag_dpp_se_smmu0_wr64(u16 slot, u16 vport, u32 base_addr, u32 index, u32 data0, u32 data1);
u32 diag_dpp_se_smmu0_rd64(u16 slot, u16 vport, u32 base_addr, u32 index);
u32 diag_dpp_se_smmu0_wr128(u16 slot, u16 vport, u32 base_addr, u32 index, u32 data0, u32 data1,
			    u32 data2, u32 data3);
u32 diag_dpp_se_smmu0_rd128(u16 slot, u16 vport, u32 base_addr, u32 index);
u32 diag_dpp_vport_mac_add(u16 slot, u16 vport, u16 sriov_vlan_tpid, u16 sriov_vlan_id, u8 mac0,
			   u8 mac1, u8 mac2, u8 mac3, u8 mac4, u8 mac5);
u32 diag_dpp_vport_mac_del(u16 slot, u16 vport, u16 sriov_vlan_tpid, u16 sriov_vlan_id, u8 mac0,
			   u8 mac1, u8 mac2, u8 mac3, u8 mac4, u8 mac5);
u32 diag_dpp_vport_batch_mac_add(u16 slot, u16 vport, u16 mac_num, u32 vlan_id, u16 mac16,
				 u32 mac32);
u32 diag_dpp_vport_batch_mac_del(u16 slot, u16 vport, u16 mac_num, u32 vlan_id, u16 mac16,
				 u32 mac32);
u32 diag_dpp_vport_mac_transter(u16 slot, u16 vport, u16 new_vport);
u32 diag_dpp_vport_mac_max_num(u16 slot, u16 vport);
u32 diag_dpp_vport_mac_flush_online(u16 slot, u16 vport);
u32 diag_dpp_vport_mac_flush_offline(u16 slot, u16 vport);
u32 diag_dpp_vport_mac_search(u16 slot, u16 vport, u16 sriov_vlan_tpid, u16 sriov_vlan_id, u8 mac0,
			      u8 mac1, u8 mac2, u8 mac3, u8 mac4, u8 mac5);
u32 diag_dpp_vport_mac_prt(u16 slot, u16 vport);
u32 diag_dpp_vport_mc_mac_add(u16 slot, u16 vport, u8 mac0, u8 mac1, u8 mac2, u8 mac3, u8 mac4,
			      u8 mac5);
u32 diag_dpp_vport_mc_mac_del(u16 slot, u16 vport, u8 mac0, u8 mac1, u8 mac2, u8 mac3, u8 mac4,
			      u8 mac5);
u32 diag_dpp_vport_batch_mc_mac_add(u16 slot, u16 vport, u16 mac_num, u8 mac0, u8 mac1, u8 mac2,
				    u8 mac3, u8 mac4, u8 mac5);
u32 diag_dpp_vport_batch_mc_mac_del(u16 slot, u16 vport, u16 mac_num, u8 mac0, u8 mac1, u8 mac2,
				    u8 mac3, u8 mac4, u8 mac5);
u32 diag_dpp_vport_mc_mac_transter(u16 slot, u16 vport, u16 new_vport);
u32 diag_dpp_vport_mc_mac_max_num(u16 slot, u16 vport);
u32 diag_dpp_vport_mc_mac_flush_online(u16 slot, u16 vport);
u32 diag_dpp_vport_mc_mac_flush_offline(u16 slot, u16 vport);
u32 diag_dpp_vport_mc_mac_prt(u16 slot, u16 vport);
u32 diag_dpp_vport_table_init(u16 slot, u16 vport);
u32 diag_dpp_vport_table_delete(u16 slot, u16 vport);
u32 diag_dpp_vport_table_set(u16 slot, u16 vport, u32 attr, u32 value);
u32 diag_dpp_vport_table_prt(u16 slot, u16 vport);

u32 diag_dpp_vport_egress_meter_en_set(u16 slot, u16 vport, u32 enable);
u32 diag_dpp_vport_egress_meter_en_prt(u16 slot, u16 vport);
u32 diag_dpp_vport_ingress_meter_en_set(u16 slot, u16 vport, u32 enable);
u32 diag_dpp_vport_ingress_meter_en_prt(u16 slot, u16 vport);
u32 diag_dpp_vport_egress_meter_mode_set(u16 slot, u16 vport, u32 mode);
u32 diag_dpp_vport_egress_meter_mode_prt(u16 slot, u16 vport);
u32 diag_dpp_vport_ingress_meter_mode_set(u16 slot, u16 vport, u32 mode);
u32 diag_dpp_vport_ingress_meter_mode_prt(u16 slot, u16 vport);

u32 diag_dpp_vport_rx_flow_hash_set(u16 slot, u16 vport, u32 hash_mode);
u32 diag_dpp_vport_rx_flow_hash_prt(u16 slot, u16 vport);
u32 diag_dpp_vport_hash_index_prt(u16 slot, u16 vport);
u32 diag_dpp_vport_hash_funcs_set(u16 slot, u16 vport, u32 funcs);
u32 diag_dpp_vport_rss_en_set(u16 slot, u16 vport, u32 enable);
u32 diag_dpp_vport_virtio_en_set(u16 slot, u16 vport, u32 enable);
u32 diag_dpp_vport_virtio_version_set(u16 slot, u16 vport, u32 version);
u32 diag_dpp_vport_promisc_en_set(u16 slot, u16 vport, u32 enable);
u32 diag_dpp_vport_business_vlan_offload_en_set(u16 slot, u16 vport, u32 enable);
u32 diag_dpp_vport_vlan_offload_en_set(u16 slot, u16 vport, u32 enable);

u32 diag_dpp_uplink_phy_port_table_set(u16 slot, u16 vport, u8 uplink_phy_port_id, u32 attr,
				       u32 value);
u32 diag_dpp_uplink_phy_port_table_prt(u16 slot, u16 vport, u8 uplink_phy_port_id);
u32 diag_dpp_uplink_phy_bond_vport(u16 slot, u16 vport, u8 uplink_phy_port_id);
u32 diag_dpp_uplink_phy_hardware_bond_set(u16 slot, u16 vport, u8 uplink_phy_port_id, u8 enable);
u32 diag_dpp_uplink_phy_lacp_pf_vqm_vfid_set(u16 slot, u16 vport, u8 uplink_phy_port_id,
					     u16 vqm_vfid);
u32 diag_dpp_uplink_phy_lacp_pf_memport_qid_set(u16 slot, u16 vport, u8 uplink_phy_port_id,
						u16 qid);
u32 diag_dpp_ptp_port_vfid_set(u16 slot, u16 vport, u32 ptp_port_vfid);
u32 diag_dpp_ptp_tc_enable_set(u16 slot, u16 vport, u32 ptp_tc_enable);
u32 diag_dpp_tm_flowid_pport_table_set(u16 slot, u16 vport, u8 uplink_phy_port_id, u32 flow_id);
u32 diag_dpp_tm_flowid_pport_table_del(u16 slot, u16 vport, u8 uplink_phy_port_id);
u32 diag_dpp_tm_pport_trust_mode_table_set(u16 slot, u16 vport, u8 uplink_phy_port_id, u32 mode);
u32 diag_dpp_tm_pport_trust_mode_table_del(u16 slot, u16 vport, u8 uplink_phy_port_id);
u32 diag_dpp_tm_pport_mcode_switch_set(u16 slot, u16 vport, u8 uplink_phy_port_id, u32 mode);
u32 diag_dpp_tm_pport_mcode_switch_del(u16 slot, u16 vport, u8 uplink_phy_port_id);

u32 diag_dpp_vport_bc_table_set(u16 slot, u16 vport, u32 enable);
u32 diag_dpp_vport_bc_table_prt(u16 slot, u16 vport);
u32 diag_dpp_vport_uc_promisc_table_set(u16 slot, u16 vport, u32 enable);
u32 diag_dpp_vport_uc_promisc_table_prt(u16 slot, u16 vport);
u32 diag_dpp_vport_mc_promisc_table_set(u16 slot, u16 vport, u32 enable);
u32 diag_dpp_vport_mc_promisc_table_prt(u16 slot, u16 vport);
u32 diag_dpp_rdma_trans_item_add(u16 slot, u16 vport, u8 mac0, u8 mac1, u8 mac2, u8 mac3, u8 mac4,
				 u8 mac5, u16 vhcaId);
u32 diag_dpp_rdma_trans_item_del(u16 slot, u16 vport, u8 mac0, u8 mac1, u8 mac2, u8 mac3, u8 mac4,
				 u8 mac5);
DPP_STATUS diag_dpp_pcie_channel_prt(void);
DPP_STATUS diag_dpp_se_hash_stat_prt(u32 slot_id, u32 fun_id);
DPP_STATUS diag_dpp_se_hash_stat_clr(u32 slot_id, u32 fun_id);
DPP_STATUS diag_dpp_hash_item_prt(u32 slot, u32 sdt_no);
u32 diag_dpp_vqm_vfid_vlan_init(u16 slot, u16 vport);
u32 diag_dpp_vqm_vfid_vlan_delete(u16 slot, u16 vport);
u32 diag_dpp_vqm_vfid_vlan_set(u16 slot, u16 vport, u32 attr, u32 value);
u32 diag_dpp_vqm_vfid_vlan_prt(u16 slot, u16 vport);
u32 diag_dpp_rxfh_set(u16 slot, u16 vport, u32 qid0, u32 qid1, u32 qid2, u32 qid3, u32 qnum);
u32 diag_dpp_rxfh_del(u16 slot, u16 vport);
u32 diag_dpp_rxfh_prt(u16 slot, u16 vport);
u32 diag_dpp_thash_key_set(u16 slot, u16 vport, u8 key0, u8 key1, u8 key2, u8 key3, u32 knum);
u32 diag_dpp_thash_key_prt(u16 slot, u16 vport);

u32 diag_dpp_vport_register_info_prt(void);

u32 diag_dpp_stat_mc_packet_rx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_bc_packet_rx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_1588_packet_rx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_1588_packet_tx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_1588_packet_drop_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_1588_enc_packet_rx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_1588_enc_packet_tx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_spoof_packet_drop_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_mcode_packet_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_port_RDMA_packet_msg_tx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_port_RDMA_packet_msg_rx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_plcr_packet_drop_tx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_plcr_packet_drop_rx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_MTU_packet_msg_tx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_MTU_packet_msg_rx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_port_uc_packet_rx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_port_uc_packet_tx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_port_mc_packet_rx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_port_mc_packet_tx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_port_bc_packet_rx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_port_bc_packet_tx_cnt_prt(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_asn_phyport_rx_pkt_cnt_get(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_psn_phyport_tx_pkt_cnt_get(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_psn_phyport_rx_pkt_cnt_get(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_psn_ack_phyport_tx_pkt_cnt_get(u16 slot, u16 vport, u32 index, u32 mode);
u32 diag_dpp_stat_psn_ack_phyport_rx_pkt_cnt_get(u16 slot, u16 vport, u32 index, u32 mode);

u32 diag_dpp_lag_group_create(u16 slot, u16 vport, u8 lag_id);
u32 diag_dpp_lag_group_delete(u16 slot, u16 vport, u8 lag_id);
u32 diag_dpp_lag_mode_set(u16 slot, u16 vport, u8 lag_id, u8 mode);
u32 diag_dpp_lag_group_hash_factor_set(u16 slot, u16 vport, u8 lag_id, u8 factor);
u32 diag_dpp_lag_group_member_add(u16 slot, u16 vport, u8 lag_id, u8 uplink_phy_port_id);
u32 diag_dpp_lag_group_member_del(u16 slot, u16 vport, u8 lag_id, u8 uplink_phy_port_id);
u32 diag_dpp_lag_table_prt(u16 slot, u16 vport, u8 lag_id);
u32 diag_dpp_tm_pport_dscp_map_table_set(u16 slot, u16 vport, u32 port, u32 dscp_id, u32 up_id);
u32 diag_dpp_tm_pport_dscp_map_table_del(u16 slot, u16 vport, u32 port, u32 dscp_id);
u32 diag_dpp_tm_pport_dscp_map_table_prt(u16 slot, u16 vport, u32 port, u32 dscp_id);
u32 diag_dpp_tm_pport_up_map_table_set(u16 slot, u16 vport, u32 port, u32 up_id, u32 tc_id);
u32 diag_dpp_tm_pport_up_map_table_del(u16 slot, u16 vport, u32 port, u32 up_id);
u32 diag_dpp_tm_pport_up_map_table_prt(u16 slot, u16 vport, u32 port, u32 up_id);
u32 diag_dpp_vport_vhca_id_add(u16 slot, u16 vport, u32 vhca_id);
u32 diag_dpp_vport_vhca_id_del(u16 slot, u16 vport, u32 vhca_id);
u32 diag_dpp_vport_vhca_id_table_prt(u16 slot, u16 vport, u32 vhca_id);
u32 diag_dpp_vport_reset(u16 slot, u16 vport);
u32 diag_dpp_vlan_filter_init(u16 slot, u16 vport);
u32 diag_dpp_add_vlan_filter(u16 slot, u16 vport, u16 vlan_id);
u32 diag_dpp_del_vlan_filter(u16 slot, u16 vport, u16 vlan_id);
u32 diag_dpp_vlan_filter_table_prt(u16 slot, u16 vport, u32 vlan_group_id);
void diag_dpp_fd_cfg_pre1(u32 smac, u32 dmac, u32 sip, u32 dip, u32 sport, u32 dport);
void diag_dpp_fd_cfg_pre2(u32 ethertype, u32 cvlan_pri, u32 vlan, u32 vxlan_vni, u32 vqm_vfid);
void diag_dpp_fd_cfg_pre3(u32 action_index, u32 action_index2, u32 count_id, u32 hash_alg,
			  u32 rss_hash_factor);
void diag_dpp_fd_cfg_pre4(u32 uplink_fd_id, u32 v_qid);
u32 diag_dpp_fd_cfg_add(u16 slot, u16 vport);
u32 diag_dpp_fd_cfg_del(u16 slot, u16 vport, u32 index);
u32 diag_dpp_fd_cfg_get(u16 slot, u16 vport, u32 index);
u32 diag_dpp_fd_cfg_search(u16 slot, u16 vport, u32 index);
u32 diag_dpp_fd_acl_index_req(u16 slot, u16 vport);
u32 diag_dpp_fd_acl_index_rel(u16 slot, u16 vport, u32 index);
u32 diag_dpp_fd_acl_all_delete(u16 slot, u16 vport);
void diag_dpp_acl_glb_data_prt(void);
DPP_STATUS diag_dpp_dtb_stat_ppu_cnt_clr(u16 slot, u16 vport, u32 rd_mode, u32 counter_id, u32 num);
DPP_STATUS diag_dpp_fd_acl_stat_clear(u16 slot, u16 vport);
DPP_STATUS diag_dpp_se_eram_res_prt(u16 slot, u16 vport);
DPP_STATUS diag_dpp_se_hash_res_prt(u16 slot, u16 vport);
DPP_STATUS diag_dpp_se_acl_res_prt(u16 slot, u16 vport);
DPP_STATUS diag_dpp_se_lpm_res_prt(u16 slot, u16 vport);
DPP_STATUS diag_dpp_se_ddr_res_prt(u16 slot, u16 vport);
DPP_STATUS diag_dpp_se_stat_res_prt(u16 slot, u16 vport);
void diag_dpp_eram_data_stub(u32 data0, u32 data1, u32 data2, u32 data3);
DPP_STATUS diag_dpp_eram_entry_insert(u16 slot, u16 vport, u32 sdt_no, u32 index);
DPP_STATUS diag_dpp_eram_entry_delete(u16 slot, u16 vport, u32 sdt_no, u32 index);
DPP_STATUS diag_dpp_eram_entry_get(u16 slot, u16 vport, u32 sdt_no, u32 index);
DPP_STATUS diag_dpp_stat_item_prt(u16 slot, u16 vport, u16 stat_item_no);
DPP_STATUS diag_dpp_stat_item_prt_all(u16 slot, u16 vport);
DPP_STATUS diag_dpp_stat_item_cnt_prt(u16 slot, u16 vport, u32 stat_item_no, u32 index,
				      u32 rd_mode);
u32 diag_dpp_glb_cfg_set(u16 slot, u16 vport, u32 glb_cfg_data_0, u32 glb_cfg_data_1,
			 u32 glb_cfg_data_2, u32 glb_cfg_data_3);
u32 diag_dpp_glb_cfg_prt(u16 slot, u16 vport);
u32 diag_dpp_pkt_capture_enable(u16 slot, u16 vport, enum zxdh_pkt_cap_point capture_pkt_flag);
u32 diag_dpp_pkt_capture_disable(u16 slot, u16 vport, enum zxdh_pkt_cap_point capture_pkt_flag);
u32 diag_dpp_pkt_capture_disable_all(u16 slot, u16 vport);
u32 diag_dpp_pkt_capture_enable_status_get(u16 slot, u16 vport);
u32 diag_dpp_pkt_capture_rule_index_to_tcam_index(u32 rule_index, enum zxdh_pkt_cap_mode rule_mode,
						  enum zxdh_pkt_cap_point capture_pkt_flag);
u32 diag_dpp_pkt_capture_tcam_index_to_rule_index(u32 tcam_index);
u32 diag_dpp_pkt_capture_item_l3_set(u32 sip_0, u32 sip_1, u32 sip_2, u32 sip_3, u32 dip_0,
				     u32 dip_1, u32 dip_2, u32 dip_3, u8 protocol);
u32 diag_dpp_pkt_capture_item_l2_set(u16 dmac_0, u32 dmac_1, u16 smac_0, u32 smac_1, u16 ethtype);
u32 diag_dpp_pkt_capture_item_l4_set(u16 dport, u16 sport, u32 qp);
u32 diag_dpp_pkt_capture_item_kw_set(u32 kw_0, u32 kw_1, u32 kw_2, u32 kw_3, u16 kw_off, u8 kw_len);
u32 diag_dpp_pkt_capture_item_insert(u16 slot, u16 vport, u32 tcam_index, u16 rule_config,
				     u8 capture_pkt_flag, u8 panel_id, u16 vqm_vfid, u16 vhca_id);
u32 diag_dpp_pkt_capture_item_delete(u16 slot, u16 vport, u32 tcam_index);
u32 diag_dpp_pkt_capture_table_dump(u16 slot, u16 vport);
u32 diag_dpp_pkt_capture_table_flush(u16 slot, u16 vport);
u32 diag_dpp_pkt_capture_speed_set(u16 slot, u16 vport, u32 speed);
u32 diag_dpp_pkt_capture_speed_get(u16 slot, u16 vport);
u32 diag_dpp_mcode_feature_get(u16 slot, u16 vport, u32 index);
u32 diag_dpp_pktrx_mcode_glb_cfg_write(u16 slot, u16 vport, u32 start_bit_no, u32 end_bit_no,
				       u32 glb_cfg_data_1);
u32 diag_dpp_l2d_psn_cfg_set(u16 slot, u16 vport, u8 psn_cfg);
u32 diag_dpp_l2d_psn_cfg_get(u16 slot, u16 vport);
u32 diag_dpp_dtb_dump_test(u16 slot, u16 vport, u32 num, u32 flag);
#endif
