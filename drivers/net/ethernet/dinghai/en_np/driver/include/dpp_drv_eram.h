/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_DRV_ERAM_H
#define DPP_DRV_ERAM_H

#include "zxic_common.h"
#include "dpp_apt_se_api.h"
#include "dpp_apt_se.h"

struct zxdh_vxlan_t {
	u64 port : 16;
	u64 rsv : 47;
	u64 hit_flag : 1;
};

struct zxdh_sriov_vport_t {
	// byte[15:16]
	u32 rsv6 /* : 16; */;

	// byte[13:14]
	u32 vhca /* : 10; */;
	u32 rsv5 /* : 5; */;

	// byte[12]
	u32 rss_hash_factor /* : 8; */;

	// byte[11]
	u32 hash_alg /* : 4; */;
	u32 uplink_phy_port_id /* : 4; */;

	// byte[9:10]
	u32 lag_id /* : 3; */;
	u32 fd_vxlan_offload_en /* : 1; */;
	u32 pf_vqm_vfid /* : 11; */;
	u32 rsv3 /* : 1; */;

	// byte[7:8]
	u32 mtu /* : 16; */;

	// byte[5:6]
	u32 port_base_qid /* : 12; */;
	u32 hash_search_index /* : 3; */;
	u32 rsv2 /* : 1; */;

	// byte[4]
	u32 np_egress_meter_enable /* : 1; */;
	u32 np_ingress_meter_enable /* : 1; */;
	u32 np_egress_meter_mode /* : 1; */;
	u32 np_ingress_meter_mode /* : 1; */;
	u32 np_egress_tm_enable /* : 1; */;
	u32 np_ingress_tm_enable /* : 1; */;
	u32 rsv1 /* : 1; */;
	u32 spoof_check_enable /* : 1; */;

	// byte[3]
	u32 inline_sec_offload /* : 1; */;
	u32 fd_enable /* : 1; */;
	u32 lag_enable /* : 1; */;
	u32 vepa_enable /* : 1; */;
	u32 is_vf /* : 1; */;
	u32 virtio_version /* : 2; */;
	u32 virtio_enable /* : 1; */;

	// byte[2]
	u32 accelerator_offload_flag /* : 1; */;
	u32 lro_offload /* : 1; */;
	u32 ip_recombine_offload /* : 1; */;
	u32 tcp_udp_checksum_offload /* : 1; */;
	u32 ip_checksum_offload /* : 1; */;
	u32 outer_ip_checksum_offload /* : 1; */;
	u32 is_up /* : 1; */;
	u32 business_enable /* : 1; */;

	// byte[1]
	u32 hw_bond_enable /* : 1; */;
	u32 rdma_offload_enable /* : 1; */;
	u32 promisc_enable /* : 1; */;
	u32 sriov_vlan_offload_enable /* : 1; */;
	u32 sriov_business_vlan_offload_enable /* : 1; */;
	u32 rss_enable /* : 1; */;
	u32 mtu_offload_enable /* : 1; */;
	u32 hit_flag /*: 1; */;

	// byte[13:14]
	u32 flag_1588_enable /*: 1; */;
};

struct zxdh_uplink_phy_port_t {
	u32 rsv6 /* : 5; */;
	u32 pf_vqm_vfid /* : 11; */;
	u32 rsv5 /* : 5; */;
	u32 lacp_pf_memport_qid /* : 12; */;
	u32 rsv4 /* : 4; */;
	u32 lacp_pf_vqm_vfid /* : 11; */;
	u32 rsv3 /* : 1; */;
	u32 is_up /* : 1; */;
	u32 bond_link_up /* : 1; */;
	u32 hw_bond_enable /* : 1; */;
	u32 mtu /* : 16; */;
	u32 mtu_offload_enable /* : 1; */;
	u32 rsv2 /* : 3; */;
	u32 tm_base_queue /* : 12; */;
	u32 ptp_port_vfid /* : 11; */;
	u32 rsv1 /* : 15 */;
	u32 magic_packet_enable /* : 1; */;
	u32 tm_shape_enable /* : 1; */;
	u32 ptp_tc_enable /* : 2; */;
	u32 trust_mode /* : 1; */;
	u32 hit_flag /* : 1; */;
	u32 primary_pf_vqm_vfid /* : 11; */;
	u32 sriov_hdbond_enable /* : 1; */;
};

struct zxdh_dscp_to_up_t {
	u32 rsv2 /* : 32; */;
	u32 up /* : 3; */;
	u32 rsv1 /* : 28; */;
	u32 hit_flag /* : 1;  */;
};

struct zxdh_up_to_tc_t {
	u32 rsv2 /* : 32; */;
	u32 tc /* : 3; */;
	u32 rsv1 /* : 28; */;
	u32 hit_flag /* : 1;  */;
};

struct zxdh_rss_to_vqid_t {
	u32 vqm_qid[8];
	u32 hit_flag;
};

struct zxdh_vlan_filter_t {
	u8 vport_bitmap[15];
	u8 rsv : 7;
	u8 hit_flag : 1;
};

struct zxdh_lag_t {
	u32 member_bitmap;
	u32 rsv2;
	u32 hash_factor;
	u32 bond_mode;
	u32 member_num;
	u32 rsv1;
	u32 hit_flag;
};

struct zxdh_bc_t {
	u64 bc_bitmap;
	u32 rsv2;
	u32 rsv1;
	u32 hit_flag;
};

struct zxdh_promisc_t {
	u64 bitmap;
	u32 rsv2;
	u32 rsv1;
	u32 pf_enable;
	u32 hit_flag;
};

struct zxdh_vhca_t {
	u32 rsv2;
	u32 vqm_vfid;
	u32 rsv1;
	u32 valid;
};

struct zxdh_network_attr_t {
	u32 rsv;
	u32 upf;
	u32 sdn_dyn_sriov_cni;
	u32 three_plane_aggr;
	u32 single_pipe;
	u32 hit_flag;
};

struct ovs_attr_para_t {
	u32 rsv1;
	u32 uplink_vqm_vfid;
	u32 rsv0;
	u32 is_passthrough;
};

struct upf_attr_para_t {
	u32 offload_eio_vfw;
	u32 offload_raw_vfw;
	u32 offload_eion_lb;
	u32 offload_raw_lb;
	u32 offload_eio;
	u32 offload_raw;
	u32 normal;
};
struct zxdh_vport_traffic_attr_t {
	union {
		struct ovs_attr_para_t ovs_attr;
		struct upf_attr_para_t upf_attr;
	} vport_traffic_attr;
	u32 hit_flag;
};

struct zxdh_vqm_vfid_vlan_t {
	u32 sriov_vlan_tci;
	u32 sriov_vlan_tpid;
	u32 sriov_business_vlan_tpid;
	u32 rsv;
	u32 sriov_business_vlan_strip_offload;
	u32 sriov_business_qinq_vlan_strip_offload;
	u32 sriov_business_vlan_filter;
	u32 hit_flag;
};

struct zxdh_fd_index_mng_t {
	u32 vport;
	u32 rsv;
	u32 hit_flag;
};

struct zxdh_pkt_cap_kw_mode_t {
	u64 rule2_key_word_off : 13;
	u64 rsv4 : 3;
	u64 rule2_key_word_len : 4;
	u64 rsv3 : 12;
	u64 rule1_key_word_off : 13;
	u64 rsv2 : 3;
	u64 rule1_key_word_len : 4;
	u64 rsv1 : 11;
	u64 hit_flag : 1;
};

struct zxdh_stat_attr_t {
	u32 valid;
	u32 mode;
	u32 addr_offset;
	u32 depth;
};

/*************eram call back ****************/
u32 dpp_apt_set_vxlan_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_vxlan_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_vport_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_vport_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_uplink_phy_port_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_uplink_phy_port_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_dscp_to_up_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_dscp_to_up_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_up_to_tc_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_up_to_tc_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_rss_to_vqid_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_rss_to_vqid_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_vlan_filter_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_vlan_filter_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_lag_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_lag_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_bc_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_bc_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_promisc_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_promisc_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_vhca_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_vhca_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_network_attr_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_network_attr_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_vport_traffic_attr_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_vport_traffic_attr_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_vqm_vfid_vlan_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_vqm_vfid_vlan_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_fd_index_mng(void *pData, u32 buff[4]);
u32 dpp_apt_get_fd_index_mng(void *pData, u32 buff[4]);

u32 dpp_apt_set_cap_keyword_attr_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_cap_keyword_attr_data(void *pData, u32 buff[4]);

u32 dpp_apt_set_stat_attr_data(void *pData, u32 buff[4]);
u32 dpp_apt_get_stat_attr_data(void *pData, u32 buff[4]);

struct se_apt_eram_convert_t *se_eram_callback_get(u32 sdt_no);

#endif
