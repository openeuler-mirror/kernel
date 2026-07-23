/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_TBL_API_H
#define DPP_TBL_API_H

#include "zxic_common.h"
#include "dpp_drv_eram.h"
#include "dpp_drv_acl.h"
#include "dpp_tbl_comm.h"
#include "dpp_tbl_stat.h"

#define SRIOV_VPORT_1588_EN \
	((u32)(offsetof(struct zxdh_sriov_vport_t, flag_1588_enable) / sizeof(u32)))
#define SRIOV_VPORT_VHCA ((u32)(offsetof(struct zxdh_sriov_vport_t, vhca) / sizeof(u32)))
// byte[12]
#define SRIOV_VPORT_RSS_HASH_FACTOR \
	((u32)(offsetof(struct zxdh_sriov_vport_t, rss_hash_factor) / sizeof(u32)))
// byte[11]
#define SRIOV_VPORT_HASH_ALG ((u32)(offsetof(struct zxdh_sriov_vport_t, hash_alg) / sizeof(u32)))
#define SRIOV_VPORT_UPLINK_PHY_PORT_ID \
	((u32)(offsetof(struct zxdh_sriov_vport_t, uplink_phy_port_id) / sizeof(u32)))
// byte[9:10]
#define SRIOV_VPORT_LAG_ID ((u32)(offsetof(struct zxdh_sriov_vport_t, lag_id) / sizeof(u32)))
#define SRIOV_VPORT_FD_VXLAN_OFFLOAD_EN \
	((u32)(offsetof(struct zxdh_sriov_vport_t, fd_vxlan_offload_en) / sizeof(u32)))
#define SRIOV_VPORT_PF_VQM_VFID \
	((u32)(offsetof(struct zxdh_sriov_vport_t, pf_vqm_vfid) / sizeof(u32)))
// byte[7:8]
#define SRIOV_VPORT_MTU ((u32)(offsetof(struct zxdh_sriov_vport_t, mtu) / sizeof(u32)))
// byte[5:6]
#define SRIOV_VPORT_HASH_SEARCH_INDEX \
	((u32)(offsetof(struct zxdh_sriov_vport_t, hash_search_index) / sizeof(u32)))
#define SRIOV_VPORT_PORT_BASE_QID \
	((u32)(offsetof(struct zxdh_sriov_vport_t, port_base_qid) / sizeof(u32)))
// byte[4]
#define SRIOV_VPORT_SPOOFCHK_EN_OFF \
	((u32)(offsetof(struct zxdh_sriov_vport_t, spoof_check_enable) / sizeof(u32)))
#define SRIOV_VPORT_NP_INGRESS_TM_EN_OFF \
	((u32)(offsetof(struct zxdh_sriov_vport_t, np_ingress_tm_enable) / sizeof(u32)))
#define SRIOV_VPORT_NP_EGRESS_TM_EN_OFF \
	((u32)(offsetof(struct zxdh_sriov_vport_t, np_egress_tm_enable) / sizeof(u32)))
#define SRIOV_VPORT_NP_INGRESS_MODE \
	((u32)(offsetof(struct zxdh_sriov_vport_t, np_ingress_meter_mode) / sizeof(u32)))
#define SRIOV_VPORT_NP_EGRESS_MODE \
	((u32)(offsetof(struct zxdh_sriov_vport_t, np_egress_meter_mode) / sizeof(u32)))
#define SRIOV_VPORT_NP_INGRESS_METER_EN_OFF \
	((u32)(offsetof(struct zxdh_sriov_vport_t, np_ingress_meter_enable) / sizeof(u32)))
#define SRIOV_VPORT_NP_EGRESS_METER_EN_OFF \
	((u32)(offsetof(struct zxdh_sriov_vport_t, np_egress_meter_enable) / sizeof(u32)))
// byte[3]
#define SRIOV_VPORT_VIRTIO_EN_OFF \
	((u32)(offsetof(struct zxdh_sriov_vport_t, virtio_enable) / sizeof(u32)))
#define SRIOV_VPORT_VIRTIO_VERSION \
	((u32)(offsetof(struct zxdh_sriov_vport_t, virtio_version) / sizeof(u32)))
#define SRIOV_VPORT_IS_VF ((u32)(offsetof(struct zxdh_sriov_vport_t, is_vf) / sizeof(u32)))
#define SRIOV_VPORT_VEPA_EN_OFF \
	((u32)(offsetof(struct zxdh_sriov_vport_t, vepa_enable) / sizeof(u32)))
#define SRIOV_VPORT_LAG_EN_OFF \
	((u32)(offsetof(struct zxdh_sriov_vport_t, lag_enable) / sizeof(u32)))
#define SRIOV_VPORT_FD_EN_OFF ((u32)(offsetof(struct zxdh_sriov_vport_t, fd_enable) / sizeof(u32)))
#define SRIOV_VPORT_INLINE_SEC_OFFLOAD \
	((u32)(offsetof(struct zxdh_sriov_vport_t, inline_sec_offload) / sizeof(u32)))
// byte[2]
#define SRIOV_VPORT_BUSINESS_EN_OFF \
	((u32)(offsetof(struct zxdh_sriov_vport_t, business_enable) / sizeof(u32)))
#define SRIOV_VPORT_IS_UP ((u32)(offsetof(struct zxdh_sriov_vport_t, is_up) / sizeof(u32)))
#define SRIOV_VPORT_OUTER_IP_CHECKSUM_OFFLOAD \
	((u32)(offsetof(struct zxdh_sriov_vport_t, outer_ip_checksum_offload) / sizeof(u32)))
#define SRIOV_VPORT_IP_CHKSUM \
	((u32)(offsetof(struct zxdh_sriov_vport_t, ip_checksum_offload) / sizeof(u32)))
#define SRIOV_VPORT_TCP_UDP_CHKSUM \
	((u32)(offsetof(struct zxdh_sriov_vport_t, tcp_udp_checksum_offload) / sizeof(u32)))
#define SRIOV_VPORT_IP_RECOMBINE \
	((u32)(offsetof(struct zxdh_sriov_vport_t, ip_recombine_offload) / sizeof(u32)))
#define SRIOV_VPORT_IPV4_TCP_ASSEMBLE \
	((u32)(offsetof(struct zxdh_sriov_vport_t, lro_offload) / sizeof(u32)))
#define SRIOV_VPORT_IPV6_TCP_ASSEMBLE \
	((u32)(offsetof(struct zxdh_sriov_vport_t, lro_offload) / sizeof(u32)))
#define SRIOV_VPORT_ACCELERATOR_OFFLOAD_FLAG \
	((u32)(offsetof(struct zxdh_sriov_vport_t, accelerator_offload_flag) / sizeof(u32)))
// byte[1]
#define SRIOV_VPORT_HW_BOND_EN_OFF \
	((u32)(offsetof(struct zxdh_sriov_vport_t, hw_bond_enable) / sizeof(u32)))
#define SRIOV_VPORT_RDMA_OFFLOAD_EN_OFF \
	((u32)(offsetof(struct zxdh_sriov_vport_t, rdma_offload_enable) / sizeof(u32)))
#define SRIOV_VPORT_PROMISC_EN \
	((u32)(offsetof(struct zxdh_sriov_vport_t, promisc_enable) / sizeof(u32)))
#define SRIOV_VPORT_VLAN_OFFLOAD_EN \
	((u32)(offsetof(struct zxdh_sriov_vport_t, sriov_vlan_offload_enable) / sizeof(u32)))
#define SRIOV_VPORT_BUSINESS_VLAN_OFFLOAD_EN                                             \
	((u32)(offsetof(struct zxdh_sriov_vport_t, sriov_business_vlan_offload_enable) / \
	       sizeof(u32)))
#define SRIOV_VPORT_RSS_EN_OFF \
	((u32)(offsetof(struct zxdh_sriov_vport_t, rss_enable) / sizeof(u32)))
#define SRIOV_VPORT_MTU_OFFLOAD_EN_OFF \
	((u32)(offsetof(struct zxdh_sriov_vport_t, mtu_offload_enable) / sizeof(u32)))

#define UPLINK_PHY_PORT_PF_VQM_VFID \
	((u32)(offsetof(struct zxdh_uplink_phy_port_t, pf_vqm_vfid) / sizeof(u32)))
#define UPLINK_PHY_PORT_LACP_PF_MEMPORT_QID \
	((u32)(offsetof(struct zxdh_uplink_phy_port_t, lacp_pf_memport_qid) / sizeof(u32)))
#define UPLINK_PHY_PORT_LACP_PF_VQM_VFID \
	((u32)(offsetof(struct zxdh_uplink_phy_port_t, lacp_pf_vqm_vfid) / sizeof(u32)))
#define UPLINK_PHY_PORT_IS_UP ((u32)(offsetof(struct zxdh_uplink_phy_port_t, is_up) / sizeof(u32)))
#define UPLINK_PHY_PORT_BOND_LINK_UP \
	((u32)(offsetof(struct zxdh_uplink_phy_port_t, bond_link_up) / sizeof(u32)))
#define UPLINK_PHY_PORT_HW_BOND_ENABLE \
	((u32)(offsetof(struct zxdh_uplink_phy_port_t, hw_bond_enable) / sizeof(u32)))
#define UPLINK_PHY_PORT_MTU ((u32)(offsetof(struct zxdh_uplink_phy_port_t, mtu) / sizeof(u32)))
#define UPLINK_PHY_PORT_MTU_OFFLOAD_ENABLE \
	((u32)(offsetof(struct zxdh_uplink_phy_port_t, mtu_offload_enable) / sizeof(u32)))
#define UPLINK_PHY_PORT_TM_BASE_QUEUE \
	((u32)(offsetof(struct zxdh_uplink_phy_port_t, tm_base_queue) / sizeof(u32)))
#define UPLINK_PHY_PORT_PTP_PORT_VFID \
	((u32)(offsetof(struct zxdh_uplink_phy_port_t, ptp_port_vfid) / sizeof(u32)))
#define UPLINK_PHY_PORT_MAGIC_PACKET_ENABLE \
	((u32)(offsetof(struct zxdh_uplink_phy_port_t, magic_packet_enable) / sizeof(u32)))
#define UPLINK_PHY_PORT_TM_SHAPE_ENABLE \
	((u32)(offsetof(struct zxdh_uplink_phy_port_t, tm_shape_enable) / sizeof(u32)))
#define UPLINK_PHY_PORT_PTP_TC_ENABLE \
	((u32)(offsetof(struct zxdh_uplink_phy_port_t, ptp_tc_enable) / sizeof(u32)))
#define UPLINK_PHY_PORT_TRUST_MODE \
	((u32)(offsetof(struct zxdh_uplink_phy_port_t, trust_mode) / sizeof(u32)))
#define UPLINK_PHY_PORT_PRIMARY_PF_VQM_VFID \
	((u32)(offsetof(struct zxdh_uplink_phy_port_t, primary_pf_vqm_vfid) / sizeof(u32)))
#define UPLINK_PHY_PORT_SRIOV_HD_BOND_EN \
	((u32)(offsetof(struct zxdh_uplink_phy_port_t, sriov_hdbond_enable) / sizeof(u32)))

#define VLAN_SRIOV_VLAN_TCI \
	((u32)(offsetof(struct zxdh_vqm_vfid_vlan_t, sriov_vlan_tci) / sizeof(u32)))
#define VLAN_SRIOV_VLAN_TPID \
	((u32)(offsetof(struct zxdh_vqm_vfid_vlan_t, sriov_vlan_tpid) / sizeof(u32)))
#define VLAN_SRIOV_BUSINESS_VLAN_TPID \
	((u32)(offsetof(struct zxdh_vqm_vfid_vlan_t, sriov_business_vlan_tpid) / sizeof(u32)))
#define VLAN_SRIOV_BUSINESS_VLAN_STRIP_OFFLIAD                                            \
	((u32)(offsetof(struct zxdh_vqm_vfid_vlan_t, sriov_business_vlan_strip_offload) / \
	       sizeof(u32)))
#define VLAN_SRIOV_BUSINESS_QINQ_VLAN_STRIP_OFFLOAD                                            \
	((u32)(offsetof(struct zxdh_vqm_vfid_vlan_t, sriov_business_qinq_vlan_strip_offload) / \
	       sizeof(u32)))
#define VLAN_SRIOV_BUSINESS_VLAN_FILTER \
	((u32)(offsetof(struct zxdh_vqm_vfid_vlan_t, sriov_business_vlan_filter) / sizeof(u32)))

#define DPP_RC_TBL_BASE (DPP_RC_DTB_BASE | 0x80000000)
#define DPP_RC_TBL_IS_FULL (DPP_RC_TBL_BASE | 0x0)

u32 dpp_vport_create(struct dpp_pf_info_t *pf_info);
u32 dpp_vport_create_by_vqm_vfid(struct dpp_pf_info_t *pf_info, u32 vqm_vfid);
u32 dpp_vport_delete(struct dpp_pf_info_t *pf_info);
u32 dpp_vport_attr_set(struct dpp_pf_info_t *pf_info, u32 attr, u32 value);
u32 dpp_vport_attr_get(struct dpp_pf_info_t *pf_info, struct zxdh_sriov_vport_t *port_attr_entry);
u32 dpp_vport_rx_flow_hash_set(struct dpp_pf_info_t *pf_info, u32 hash_mode);
u32 dpp_vport_rx_flow_hash_get(struct dpp_pf_info_t *pf_info, u32 *hash_mode);
u32 dpp_vport_base_qid_get(struct dpp_pf_info_t *pf_info, u32 *base_qid);
u32 dpp_vport_hash_index_get(struct dpp_pf_info_t *pf_info, u32 *hash_index);
u32 dpp_vport_hash_funcs_set(struct dpp_pf_info_t *pf_info, u8 funcs);
u32 dpp_vport_rss_en_set(struct dpp_pf_info_t *pf_info, u8 enable);
u32 dpp_vport_fd_en_set(struct dpp_pf_info_t *pf_info, u8 enable);
u32 dpp_vport_virtio_en_set(struct dpp_pf_info_t *pf_info, u8 enable);
u32 dpp_vport_virtio_version_set(struct dpp_pf_info_t *pf_info, u8 version);
u32 dpp_vport_promisc_en_set(struct dpp_pf_info_t *pf_info, u8 enable);
u32 dpp_vport_business_vlan_offload_en_set(struct dpp_pf_info_t *pf_info, u8 enable);
u32 dpp_vport_vlan_offload_en_set(struct dpp_pf_info_t *pf_info, u8 enable);

u32 dpp_vlan_filter_init(struct dpp_pf_info_t *pf_info);
u32 dpp_add_vlan_filter(struct dpp_pf_info_t *pf_info, u16 vlan_id);
u32 dpp_del_vlan_filter(struct dpp_pf_info_t *pf_info, u16 vlan_id);

u32 dpp_vport_bond_pf(struct dpp_pf_info_t *pf_info);
u32 dpp_vport_unbond_pf(struct dpp_pf_info_t *pf_info);

u32 dpp_rxfh_set(struct dpp_pf_info_t *pf_info, u32 *queue_list, u32 queue_num);
u32 dpp_rxfh_get(struct dpp_pf_info_t *pf_info, u32 *queue_list, u32 queue_num);
u32 dpp_rxfh_del(struct dpp_pf_info_t *pf_info);
u32 dpp_thash_key_set(struct dpp_pf_info_t *pf_info, u8 *hash_key, u32 key_num);
u32 dpp_thash_key_get(struct dpp_pf_info_t *pf_info, u8 *hash_key, u32 key_num);
u32 dpp_add_mac(struct dpp_pf_info_t *pf_info, const void *mac, u16 sriov_vlan_tpid,
		u16 sriov_vlan_id);
u32 dpp_del_mac(struct dpp_pf_info_t *pf_info, const void *mac, u16 sriov_vlan_tpid,
		u16 sriov_vlan_id);
u32 dpp_unicast_mac_search(struct dpp_pf_info_t *pf_info, const void *mac, u16 sriov_vlan_tpid,
			   u16 sriov_vlan_id, u16 *current_vport);
u32 dpp_batch_add_unicast_mac(struct dpp_pf_info_t *pf_info, u32 mac_num, const void *l2key);
u32 dpp_batch_del_unicast_mac(struct dpp_pf_info_t *pf_info, u32 mac_num, const void *l2key);
u32 dpp_unicast_mac_dump(struct dpp_pf_info_t *pf_info, struct MAC_VPORT_INFO *p_mac_arr,
			 u32 *p_mac_num);
u32 dpp_unicast_mac_transfer(struct dpp_pf_info_t *pf_info, struct dpp_pf_info_t *new_pf_info);
u32 dpp_unicast_mac_max_get(struct dpp_pf_info_t *pf_info, u32 *max_num);
u32 dpp_unicast_all_mac_delete(struct dpp_pf_info_t *pf_info);
u32 dpp_unicast_all_mac_online_delete(struct dpp_pf_info_t *pf_info);
u32 dpp_unicast_all_mac_soft_delete(struct dpp_pf_info_t *pf_info);

u32 dpp_multi_mac_add_member(struct dpp_pf_info_t *pf_info, const void *mac);
u32 dpp_multi_mac_del_member(struct dpp_pf_info_t *pf_info, const void *mac);
u32 dpp_batch_add_multicast_mac(struct dpp_pf_info_t *pf_info, u32 mac_num, const void *mac);
u32 dpp_batch_del_multicast_mac(struct dpp_pf_info_t *pf_info, u32 mac_num, const void *mac);
u32 dpp_multicast_mac_dump(struct dpp_pf_info_t *pf_info, struct MAC_VPORT_INFO *p_mac_arr,
			   u32 *p_mac_num);
u32 dpp_multicast_mac_transfer(struct dpp_pf_info_t *pf_info, struct dpp_pf_info_t *new_pf_info);
u32 dpp_multicast_mac_max_get(struct dpp_pf_info_t *pf_info, u32 *max_num);
u32 dpp_multicast_all_mac_delete(struct dpp_pf_info_t *pf_info);
u32 dpp_multicast_all_mac_online_delete(struct dpp_pf_info_t *pf_info);
u32 dpp_multicast_all_mac_soft_delete(struct dpp_pf_info_t *pf_info);

u32 dpp_ptp_port_vfid_set(struct dpp_pf_info_t *pf_info, u32 ptp_port_vfid);
u32 dpp_ptp_tc_enable_set(struct dpp_pf_info_t *pf_info, u32 ptp_tc_enable);

u32 dpp_ipsec_enc_entry_add(struct dpp_pf_info_t *pf_info, u32 index, u8 *sip, u8 *dip,
			    u8 *sip_mask, u8 *dip_mask, u32 is_ipv4, u32 sa_id);
u32 dpp_ipsec_enc_entry_del(struct dpp_pf_info_t *pf_info, u32 index);

u32 dpp_lag_group_create(struct dpp_pf_info_t *pf_info, u8 lag_id);
u32 dpp_lag_group_delete(struct dpp_pf_info_t *pf_info, u8 lag_id);
u32 dpp_lag_mode_set(struct dpp_pf_info_t *pf_info, u8 lag_id, u8 mode);
u32 dpp_lag_group_hash_factor_set(struct dpp_pf_info_t *pf_info, u8 lag_id, u8 factor);
u32 dpp_lag_group_member_add(struct dpp_pf_info_t *pf_info, u8 lag_id, u8 uplink_phy_port_id);
u32 dpp_lag_group_member_del(struct dpp_pf_info_t *pf_info, u8 lag_id, u8 uplink_phy_port_id);
u32 dpp_lag_hit_flag_get(struct dpp_pf_info_t *pf_info, u8 lag_id, u8 *hit_flag);

u32 dpp_uplink_phy_bond_vport(struct dpp_pf_info_t *pf_info, u8 uplink_phy_id);
u32 dpp_uplink_phy_hardware_bond_set(struct dpp_pf_info_t *pf_info, u8 uplink_phy_id, u8 enable);
u32 dpp_uplink_phy_lacp_pf_vqm_vfid_set(struct dpp_pf_info_t *pf_info, u8 uplink_phy_id,
					u16 vqm_vfid);
u32 dpp_uplink_phy_lacp_pf_memport_qid_set(struct dpp_pf_info_t *pf_info, u8 uplink_phy_id,
					   u16 qid);
u32 dpp_uplink_phy_attr_set(struct dpp_pf_info_t *pf_info, u8 uplink_phy_id, u32 attr, u32 value);

u32 dpp_vport_uc_promisc_set(struct dpp_pf_info_t *pf_info, u32 enable);
u32 dpp_vport_mc_promisc_set(struct dpp_pf_info_t *pf_info, u32 enable);

u32 dpp_stat_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_cnt);
u32 dpp_stat_item_cnt_get(struct dpp_pf_info_t *pf_info, u32 stat_item_no, u32 index, u32 rd_mode,
			  union dpp_stat_value_u *p_stat_value);
u32 dpp_stat_cnt_get_128(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_pkB_cnt,
			 u64 *p_pk_cnt);
u32 dpp_stat_mc_packet_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_cnt);
u32 dpp_stat_bc_packet_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_cnt);
u32 dpp_stat_1588_packet_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_cnt);
u32 dpp_stat_1588_packet_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_cnt);
u32 dpp_stat_1588_packet_drop_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				      u64 *p_cnt);
u32 dpp_stat_1588_enc_packet_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					u64 *p_cnt);
u32 dpp_stat_1588_enc_packet_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					u64 *p_cnt);
u32 dpp_stat_spoof_packet_drop_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_cnt);
u32 dpp_stat_mcode_packet_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_cnt);
u32 dpp_stat_port_RDMA_packet_msg_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					     u64 *p_pkB_cnt, u64 *p_pk_cnt);
u32 dpp_stat_port_RDMA_packet_msg_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					     u64 *p_pkB_cnt, u64 *p_pk_cnt);
u32 dpp_stat_plcr_packet_drop_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					 u64 *p_pkB_cnt, u64 *p_pk_cnt);
u32 dpp_stat_plcr_packet_drop_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					 u64 *p_pkB_cnt, u64 *p_pk_cnt);
u32 dpp_stat_MTU_packet_msg_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt);
u32 dpp_stat_MTU_packet_msg_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt);
u32 dpp_stat_port_uc_packet_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt);
u32 dpp_stat_port_uc_packet_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt);
u32 dpp_stat_port_mc_packet_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt);
u32 dpp_stat_port_mc_packet_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt);
u32 dpp_stat_port_bc_packet_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt);
u32 dpp_stat_port_bc_packet_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt);
u32 dpp_stat_fd_stat_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_pkB_cnt,
			     u64 *p_pk_cnt);

u32 dpp_vport_vhca_id_add(struct dpp_pf_info_t *pf_info, u32 vhca_id);
u32 dpp_vport_vhca_id_del(struct dpp_pf_info_t *pf_info, u32 vhca_id);
u32 dpp_add_rdma_trans_item(struct dpp_pf_info_t *pf_info, const void *mac, const u16 vhcaId);
u32 dpp_del_rdma_trans_item(struct dpp_pf_info_t *pf_info, const void *mac);
u32 dpp_rdma_trans_item_soft_delete(struct dpp_pf_info_t *pf_info);

u32 dpp_vqm_vfid_vlan_init(struct dpp_pf_info_t *pf_info);
u32 dpp_vqm_vfid_vlan_delete(struct dpp_pf_info_t *pf_info);
u32 dpp_vqm_vfid_vlan_set(struct dpp_pf_info_t *pf_info, u32 attr, u32 value);
u32 dpp_vqm_vfid_vlan_get(struct dpp_pf_info_t *pf_info,
			  struct zxdh_vqm_vfid_vlan_t *vqm_vfid_vlan_entry);
u32 dpp_fd_acl_index_request(struct dpp_pf_info_t *pf_info, u32 *p_index);
u32 dpp_fd_acl_index_release(struct dpp_pf_info_t *pf_info, u32 index);
u32 dpp_fd_acl_entry_add(struct dpp_pf_info_t *pf_info, u32 handle, u8 *key, u8 *key_mask,
			 u8 *result);
u32 dpp_fd_acl_entry_del(struct dpp_pf_info_t *pf_info, u32 index);
u32 dpp_fd_acl_entry_get(struct dpp_pf_info_t *pf_info, u32 handle, u8 *key, u8 *key_mask,
			 u8 *result);
u32 dpp_fd_acl_entry_search(struct dpp_pf_info_t *pf_info, u32 handle, u8 *key, u8 *key_mask,
			    u8 *result);
u32 dpp_fd_acl_all_delete(struct dpp_pf_info_t *pf_info);
u32 dpp_fd_acl_stat_clear(struct dpp_pf_info_t *pf_info);

u32 dpp_glb_cfg_set_0(struct dpp_pf_info_t *pf_info, u32 glb_cfg_data_0);
u32 dpp_glb_cfg_set_1(struct dpp_pf_info_t *pf_info, u32 glb_cfg_data_1);
u32 dpp_glb_cfg_set_2(struct dpp_pf_info_t *pf_info, u32 glb_cfg_data_2);
u32 dpp_glb_cfg_set_3(struct dpp_pf_info_t *pf_info, u32 glb_cfg_data_3);
u32 dpp_glb_cfg_get_0(struct dpp_pf_info_t *pf_info, u32 *p_glb_cfg_data_0);
u32 dpp_glb_cfg_get_1(struct dpp_pf_info_t *pf_info, u32 *p_glb_cfg_data_1);
u32 dpp_glb_cfg_get_2(struct dpp_pf_info_t *pf_info, u32 *p_glb_cfg_data_2);
u32 dpp_glb_cfg_get_3(struct dpp_pf_info_t *pf_info, u32 *p_glb_cfg_data_3);
u32 dpp_l2d_psn_cfg_set(struct dpp_pf_info_t *pf_info, u8 psn_cfg);
u32 dpp_l2d_psn_cfg_get(struct dpp_pf_info_t *pf_info, u32 *p_psn_cfg);
u32 dpp_stat_asn_phyport_rx_pkt_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					u64 *p_cnt);
u32 dpp_stat_psn_phyport_tx_pkt_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					u64 *p_cnt);
u32 dpp_stat_psn_phyport_rx_pkt_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					u64 *p_cnt);
u32 dpp_stat_psn_ack_phyport_tx_pkt_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					    u64 *p_cnt);
u32 dpp_stat_psn_ack_phyport_rx_pkt_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					    u64 *p_cnt);
u32 dpp_pktrx_mcode_glb_cfg_write(struct dpp_pf_info_t *pf_info, u32 start_bit_no, u32 end_bit_no,
				  u32 glb_cfg_data_1);
u32 dpp_mcode_feature_get(struct dpp_pf_info_t *pf_info, u32 index, u64 *feature);

u32 dpp_eram_entry_insert(struct dpp_pf_info_t *pf_info, u32 sdt_no, u32 index, u8 *p_data);
u32 dpp_eram_entry_delete(struct dpp_pf_info_t *pf_info, u32 sdt_no, u32 index);
u32 dpp_eram_entry_get(struct dpp_pf_info_t *pf_info, u32 sdt_no, u32 index, u8 *p_data);
struct dpp_dev_mngr_t *dpp_dev_mgr_get(void);
struct dpp_se_cfg *dpp_apt_get_se_cfg(struct dpp_dev_t *dev);
#endif
