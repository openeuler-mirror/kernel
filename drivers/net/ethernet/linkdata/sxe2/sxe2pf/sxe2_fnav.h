/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_fnav.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_FNAV_H__
#define __SXE2_FNAV_H__

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/if_ether.h>
#include <linux/idr.h>

#include "sxe2_vsi.h"
#include "sxe2_flow.h"

#ifdef SXE2_TEST
#define STATIC
#else
#define STATIC static
#endif

#define SXE2_FNAV_FLEX_WROD_SIZE 2

#define SXE2_FNAV_TUN_PKT_OFF	 (50)
#define SXE2_FNAV_VXLAN_UDP_LEN	 (16)
#define SXE2_FNAV_ETH_LEN	 (14)
#define SXE2_FNAV_GRE_HEADER_LEN (4)

#define SXE2_FNAV_MAX_RAW_PKT_SIZE (512 + SXE2_FNAV_TUN_PKT_OFF)

#define SXE2_ETH_TYPE_F_OFFSET	  12
#define SXE2_ETH_VLAN_TCI_OFFSET  14
#define SXE2_ETH_TYPE_VLAN_OFFSET 16

#define SXE2_IPV4_OUTER_LEN_OFFSET 16

#define SXE2_IPV4_SRC_ADDR_OFFSET      26
#define SXE2_IPV4_DST_ADDR_OFFSET      30
#define SXE2_IPV4_TCP_SRC_PORT_OFFSET  34
#define SXE2_IPV4_TCP_DST_PORT_OFFSET  36
#define SXE2_IPV4_UDP_SRC_PORT_OFFSET  34
#define SXE2_IPV4_UDP_DST_PORT_OFFSET  36
#define SXE2_IPV4_SCTP_SRC_PORT_OFFSET 34
#define SXE2_IPV4_SCTP_DST_PORT_OFFSET 36
#define SXE2_IPV4_UDP_LEN_OFFSET       38
#define SXE2_IPV4_PROTO_OFFSET	       23
#define SXE2_IPV6_SRC_ADDR_OFFSET      22
#define SXE2_IPV6_DST_ADDR_OFFSET      38
#define SXE2_IPV6_TCP_SRC_PORT_OFFSET  54
#define SXE2_IPV6_TCP_DST_PORT_OFFSET  56
#define SXE2_IPV6_UDP_SRC_PORT_OFFSET  54
#define SXE2_IPV6_UDP_DST_PORT_OFFSET  56
#define SXE2_IPV6_SCTP_SRC_PORT_OFFSET 54
#define SXE2_IPV6_SCTP_DST_PORT_OFFSET 56

#define SXE2_MAC_ETHTYPE_OFFSET 12
#define SXE2_IPV4_TOS_OFFSET	15
#define SXE2_IPV4_ID_OFFSET	18
#define SXE2_IPV4_TTL_OFFSET	22
#define SXE2_IPV6_TC_OFFSET	14
#define SXE2_IPV6_HLIM_OFFSET	21
#define SXE2_IPV6_PROTO_OFFSET	20
#define SXE2_IPV6_ID_OFFSET	58
#define SXE2_IPV4_NO_MAC_TOS_OFFSET	     1
#define SXE2_IPV4_NO_MAC_TTL_OFFSET	     8
#define SXE2_IPV4_NO_MAC_PROTO_OFFSET	     9
#define SXE2_IPV4_NO_MAC_SRC_ADDR_OFFSET     12
#define SXE2_IPV4_NO_MAC_DST_ADDR_OFFSET     16
#define SXE2_TCP4_NO_MAC_SRC_PORT_OFFSET     20
#define SXE2_TCP4_NO_MAC_DST_PORT_OFFSET     22
#define SXE2_UDP4_NO_MAC_SRC_PORT_OFFSET     20
#define SXE2_UDP4_NO_MAC_DST_PORT_OFFSET     22
#define SXE2_IPV6_NO_MAC_TC_OFFSET	     0
#define SXE2_IPV6_NO_MAC_HLIM_OFFSET	     7
#define SXE2_IPV6_NO_MAC_PROTO_OFFSET	     6
#define SXE2_IPV6_NO_MAC_SRC_ADDR_OFFSET     8
#define SXE2_IPV6_NO_MAC_DST_ADDR_OFFSET     24
#define SXE2_TCP6_NO_MAC_SRC_PORT_OFFSET     40
#define SXE2_TCP6_NO_MAC_DST_PORT_OFFSET     42
#define SXE2_UDP6_NO_MAC_SRC_PORT_OFFSET     40
#define SXE2_UDP6_NO_MAC_DST_PORT_OFFSET     42
#define SXE2_IPV4_GTPU_TEID_OFFSET	     46
#define SXE2_IPV4_GTPU_QFI_OFFSET	     56
#define SXE2_IPV6_GTPU_TEID_OFFSET	     66
#define SXE2_IPV6_GTPU_QFI_OFFSET	     76
#define SXE2_IPV4_GTPOGRE_TEID_OFFSET	     70
#define SXE2_IPV4_GTPOGRE_QFI_OFFSET	     80
#define SXE2_IPV6_GTPOGRE_TEID_OFFSET	     90
#define SXE2_IPV6_GTPOGRE_QFI_OFFSET	     100
#define SXE2_IPV4_L2TPV3_SESS_ID_OFFSET	     34
#define SXE2_IPV6_L2TPV3_SESS_ID_OFFSET	     54
#define SXE2_IPV4_ESP_SPI_OFFSET	     34
#define SXE2_IPV6_ESP_SPI_OFFSET	     54
#define SXE2_IPV4_AH_SPI_OFFSET		     38
#define SXE2_IPV6_AH_SPI_OFFSET		     58
#define SXE2_IPV4_NAT_T_ESP_SPI_OFFSET	     42
#define SXE2_IPV6_NAT_T_ESP_SPI_OFFSET	     62
#define SXE2_IPV4_VXLAN_VNI_OFFSET	     46
#define SXE2_ECPRI_TP0_PC_ID_OFFSET	     18
#define SXE2_IPV4_UDP_ECPRI_TP0_PC_ID_OFFSET 46
#define SXE2_IPV4_L2TPV2_SESS_ID_OFFSET	     46
#define SXE2_IPV6_L2TPV2_SESS_ID_OFFSET	     66
#define SXE2_IPV4_L2TPV2_LEN_SESS_ID_OFFSET  48
#define SXE2_IPV6_L2TPV2_LEN_SESS_ID_OFFSET  68

#define SXE2_FNAV_IPV4_PKT_FLAG_MF	 0x20
#define SXE2_FNAV_IPV4_PKT_FLAG_MF_SHIFT 8
#define SXE2_FNAV_IPV4_PKT_FLAG_DF	 0x40

#define SXE2_FNAV_INVALID_STAT_IDX 0xFFFF

#define SXE2_FNAV_L4_PROT_TCP    6
#define SXE2_FNAV_L4_PROT_UDP    17
#define SXE2_FNAV_L4_PROT_SCTP   132

enum sxe2_fnav_stat_idx {
	SXE2_FNAV_STAT_PF,
	SXE2_FNAV_STAT_CH,
	SXE2_ARFS_STAT_TCP4,
	SXE2_ARFS_STAT_UDP4,
	SXE2_ARFS_STAT_TCP6,
	SXE2_ARFS_STAT_UDP6,
	SXE2_FNAV_STAT_PF_MAX,
};

enum sxe2_hw_fnav_act_type {
	SXE2_FNAV_ACT_DROP,
	SXE2_FNAV_ACT_QINDEX,
	SXE2_FNAV_ACT_QGROUP,
	SXE2_FNAV_ACT_OTHER,
};

#define SXE2_FNAV_FLTR_HLIST_CNT 1024
#define SXE2_FNAV_FLTR_HLIST_MASK (SXE2_FNAV_FLTR_HLIST_CNT - 1)
#define SXE2_FNAV_HASH_FLD_MAX_SIZE 36
#define SXE2_FNAV_IPV4_ADDR_SIZE 4
#define SXE2_FNAV_IPV6_ADDR_SIZE 16
#define SXE2_FNAV_L4_PORT_SIZE 2
#define SXE2_FNAV_IP4_HASH_FLD_SIZE                                            \
	((SXE2_FNAV_IPV4_ADDR_SIZE + SXE2_FNAV_L4_PORT_SIZE) * 2)
#define SXE2_FNAV_IP6_HASH_FLD_SIZE                                            \
	((SXE2_FNAV_IPV6_ADDR_SIZE + SXE2_FNAV_L4_PORT_SIZE) * 2)

struct sxe2_fnav_base_pkt {
	enum sxe2_fnav_flow_type flow_type;
	u16 pkt_len;
	const u8 *pkt;
	u16 tun_pkt_len;
	const u8 *tun_pkt;
};

struct sxe2_fnav_v4 {
	__be32 dst_ip;
	__be32 src_ip;
	__be32 l4_header;
	__be32 sec_parm_idx;
	u8 tos;
	u8 ip_ver;
	u8 proto;
	u8 ttl;
	__be16 packet_id;
};

#define SXE2_IPV6_ADDR_LEN_TO_U32 4

struct sxe2_fnav_v6 {
	__be32 dst_ip[SXE2_IPV6_ADDR_LEN_TO_U32];
	__be32 src_ip[SXE2_IPV6_ADDR_LEN_TO_U32];
	__be32 l4_header;
	__be32 sec_parm_idx;
	u8 tc;
	u8 proto;
	u8 hlim;
	__be32 packet_id;
};

struct sxe2_fnav_l4 {
	__be16 dst_port;
	__be16 src_port;
};

struct sxe2_fnav_extra {
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	__be16 ether_type;
	__be32 usr_def[2];
	__be16 vlan_type;
	__be16 s_vlan_tci;
	__be16 c_vlan_tci;
	__be16 s_vlan_vid;
	__be16 c_vlan_vid;
};

struct sxe2_fnav_ipsec {
	__be32 sec_parm_idx;
};

struct sxe2_fnav_l2tpv3 {
	__be32 session_id;
};

struct sxe2_fnav_tunnel_id {
	union {
		__be32 vxlan_vni;
		__be32 geneve_vni;
		__be32 gtpu_teid;
		__be32 gre_tni;
	};
};

struct sxe2_fnav_filter_full_key {
	struct ethhdr eth, eth_mask;
	struct ethhdr eth_inner, eth_mask_inner;

	union {
		struct sxe2_fnav_v4 v4;
		struct sxe2_fnav_v6 v6;
	} ip, mask;

	union {
		struct sxe2_fnav_v4 v4;
		struct sxe2_fnav_v6 v6;
	} ip_inner, mask_inner;

	struct sxe2_fnav_l4 l4, l4_mask;
	struct sxe2_fnav_l4 l4_inner, l4_mask_inner;

	struct sxe2_fnav_extra ext_data;
	struct sxe2_fnav_extra ext_mask;

	struct sxe2_fnav_extra ext_data_inner;
	struct sxe2_fnav_extra ext_mask_inner;

	struct sxe2_fnav_tunnel_id tunnel_data;
	struct sxe2_fnav_tunnel_id tunnel_mask;

	bool has_flex_filed;
	u16 flex_offset;
	__be16 flex_word;

	bool flow_ext;
};

struct sxe2_fnav_filter {
	struct list_head l_node;
	struct hlist_node
		hl_node;
	u32 hash_val;
	bool hashed;
	bool conflict;
	u32 filter_loc;
	u8 fdid_prio;
	u16 q_index;
	u16 origin_q_index;
	u8 q_region;
	u8 act_prio;
	u16 ori_vsi_sw;
	u16 ori_vsi_hw;
	u16 dst_vsi_hw;
	u16 rule_vsi_sw;
	enum sxe2_hw_fnav_act_type
		act_type;
	enum sxe2_fnav_flow_type flow_type;
	struct sxe2_fnav_filter_full_key full_key;
	u8 complete_report;
	u8 stat_ctrl;
	u16 stat_index;
	u8 inputset[SXE2_FNAV_INPUT_CNT * 2];
	u8 fd_space;
	u8 tunn_fd_space;
	u32 vsi_flow_id;
	u8 tunn_flag;
	u16 vf_idx;
};

enum sxe2_fnav_filter_update_type {
	SXE2_FNAV_FILTER_UPDATE_ADMIN = 0,
	SXE2_FNAV_FILTER_UPDATE_PKT,
};

enum sxe2_fnav_fd_space_type {
	SXE2_FNAV_FD_SPACE_FROM_GUAR = 0,
	SXE2_FNAV_FD_SPACE_FROM_BEST_EFFORT,
	SXE2_FNAV_FD_SPACE_FROM_GUAR_1ST_BE_2ND,
	SXE2_FNAV_FD_SPACE_FROM_BE_1ST_GUAR_2ND,
};

struct sxe2_fnav_flow_context {
	struct sxe2_ppp_common_ctxt ppp;
};

enum sxe2_fnav_state {
	SXE2_FNAV_STATE_UNINIT,
	SXE2_FNAV_STATE_READY,
	SXE2_FNAV_STATE_RESET,
};

struct sxe2_fnav_stat_node {
	struct list_head l_node;
	u16 vsi_id;
	u16 stat_index;
	bool need_update;
};

struct sxe2_fnav_stat_ctxt {
	u16 stat_base;
	u16 stat_num;
	u16 stat_cnt;
	u16 stat_rsv_idx[SXE2_FNAV_STAT_PF_MAX];
	u64 vsi_fnav_match[SXE2_MAX_VSI_NUM];
	/* in order to protect the data */
	struct mutex fnav_stat_lock;
	struct list_head
		fnav_stat_list;
};

struct sxe2_fnav_context {
	u16 space_gcnt;
	u16 space_bcnt;
	u64 pkt_err_cnt;
	/* in order to protect the data */
	struct mutex filter_lock;
	/* in order to protect the data */
	struct mutex fnav_space_lock;
	struct hlist_head filter_hlist[SXE2_FNAV_FLTR_HLIST_CNT];
	enum sxe2_fnav_state state;
	/* in order to protect the data */
	struct mutex fnav_state_lock;

	struct sxe2_fnav_flow_context fnav_flow_ctxt;
	struct sxe2_fnav_stat_ctxt fnav_stat_ctxt;
};

void sxe2_fnav_ctxt_init(struct sxe2_adapter *adapter);

void sxe2_fnav_ctxt_deinit(struct sxe2_adapter *adapter);

void sxe2_fnav_enter_reset(struct sxe2_adapter *adapter, bool to_reset);

void sxe2_fnav_flow_ctxt_clean(struct sxe2_adapter *adapter);

s32 sxe2_fnav_flow_cfg_del(struct sxe2_adapter *adapter,
			   struct sxe2_fnav_flow_cfg *flow_cfg, bool is_tunnel);

s32 sxe2_fnav_flow_cfg_add(struct sxe2_vsi *vsi, struct sxe2_fnav_flow_cfg *flow_cfg,
			   struct sxe2_fnav_flow_seg *seg);

s32 sxe2_fnav_default_flow_set(struct sxe2_adapter *adapter);

bool sxe2_fnav_flow_sup_arfs(enum sxe2_fnav_flow_type flow_type);

void sxe2_fnav_filter_hash(struct sxe2_fnav_filter *filter);

s32 sxe2_pf_fnav_flow_cfg_clear(struct sxe2_adapter *adapter);

s32 sxe2_fnav_switch(struct sxe2_adapter *adapter, bool is_enable);

u32 sxe2_fnav_max_filter_cnt_get_by_vsi(struct sxe2_vsi *vsi);

struct sxe2_fnav_filter
*sxe2_fnav_find_filter_by_loc_unlock(struct sxe2_vsi_fnav *fnav_filter_ctxt, u32 loc);

struct sxe2_fnav_filter *
sxe2_fnav_find_filter_by_loc_lock(struct sxe2_vsi *vsi, u32 loc);

bool sxe2_fnav_filter_cmp_with_flow_type(struct sxe2_fnav_filter *fltrA,
					 struct sxe2_fnav_filter *fltrB);

bool sxe2_fnav_flow_cfg_full_match(struct sxe2_adapter *adapter,
				   enum sxe2_fnav_flow_type flow_type);

s32 sxe2_fnav_filter_inputset_fill(struct sxe2_vsi *vsi,
				   struct sxe2_fnav_filter *filter,
				   struct sxe2_fnav_flow_cfg *flow_cfg);

s32 sxe2_fnav_hw_filter_update_with_admin(struct sxe2_vsi *vsi,
					  struct sxe2_fnav_filter *filter,
					  struct sxe2_fnav_flow_cfg *flow_cfg,
					  bool is_add, bool is_tunn);

s32 sxe2_fnav_hw_filter_update_with_pkt(struct sxe2_vsi *vsi,
					struct sxe2_fnav_filter *filter,
					bool is_add, bool is_update, bool is_tunn);

s32 sxe2_fnav_default_flow_recovery_by_type(struct sxe2_vsi *vsi,
					    struct sxe2_fnav_flow_cfg *flow_cfg);

s32 sxe2_fnav_del_filter_by_loc(struct sxe2_vsi *vsi, u32 loc);

s32 sxe2_fwc_fnav_hw_clear(struct sxe2_adapter *adapter);

s32 sxe2_fnav_rule_reply(struct sxe2_adapter *adapter);

void sxe2_fwc_fnav_trace_trigger(struct sxe2_adapter *adapter);

void sxe2_fwc_fnav_trace_recorder(struct sxe2_adapter *adapter);

void sxe2_fwc_fnav_hw_sts(struct sxe2_adapter *adapter);

bool sxe2_fnav_flow_seg_compare(struct sxe2_fnav_flow_seg *seg_a,
				struct sxe2_fnav_flow_seg *seg_b);

s32 sxe2_fnav_hw_flow_del(struct sxe2_adapter *adapter,
			  struct sxe2_flow_info_node *flow);

s32 sxe2_vf_fnav_filter_inputset_fill(struct sxe2_vf_node *vf,
				      struct sxe2_fnav_filter *filter);

s32 sxe2_fnav_filter_clean_for_vf(struct sxe2_vf_node *vf, bool is_vfr);

u32 sxe2_fnav_num_avail_filter(struct sxe2_vsi *vsi);

s32 sxe2_flow_fnav_update_hw_prof_fv_mask(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					  u8 prof_id, u16 *masks);

s32 sxe2_fnav_gen_prgm_pkt(struct sxe2_adapter *adapter,
			   struct sxe2_fnav_filter *filter, u8 *pkt, bool frag,
			   bool tun);

s32 sxe2_pf_fnav_hw_filter_update(struct sxe2_vsi *vsi,
				  struct sxe2_fnav_filter *filter, bool is_add, bool is_update,
				  enum sxe2_fnav_filter_update_type update_type);

s32 sxe2_fnav_ptg_parse_from_ddp(u8 *data, u16 cnt, u16 base_id,
				 struct sxe2_adapter *adapter);

s32 sxe2_fnav_mask_parse_from_ddp(u8 *data, u16 cnt, u16 base_id,
				  struct sxe2_adapter *adapter);

void sxe2_fnav_flow_ctxt_init(struct sxe2_adapter *adapter);

s32 sxe2_fwc_fnav_space_cnt_get(struct sxe2_adapter *adapter, u16 vsi_id,
				u32 *gcnt_global, u32 *bcnt_global, u32 *gcnt_pf, u32 *bcnt_pf,
				u32 *gcnt_vsi, u32 *bcnt_vsi);

s32 sxe2_fnav_stat_idx_alloc_with_lock(struct sxe2_adapter *adapter,
				       u16 vsi_id, u16 *stat_index, bool need_update);

s32 sxe2_fnav_stat_idx_free_with_lock(struct sxe2_adapter *adapter,
				      u16 stat_index);

void sxe2_fnav_reserve_stat_idx_alloc(struct sxe2_adapter *adapter);

void sxe2_fnav_stat_ctxt_init(struct sxe2_adapter *adapter);

void sxe2_fnav_stat_ctxt_deinit(struct sxe2_adapter *adapter);

void sxe2_fnav_xlt2_dump(struct sxe2_adapter *adapter);

void sxe2_fnav_vsig_dump(struct sxe2_adapter *adapter);

void sxe2_fnav_prof_dump(struct sxe2_adapter *adapter);

void sxe2_fnav_mask_dump(struct sxe2_adapter *adapter);

void sxe2_fnav_stats_dump(struct sxe2_adapter *adapter);

s32 sxe2_fnav_filter_replay(struct sxe2_vsi *vsi, bool to_vf);

void sxe2_comm_fnav_msg_convert_fld(unsigned long *flds,
				    struct sxe2_fnav_comm_proto_hdr *proto_hdr);

struct sxe2_fnav_filter *
sxe2_comm_fnav_filter_search_for_dup(struct sxe2_vsi *vsi,
				     struct sxe2_fnav_filter *filter);

s32 sxe2_fnav_filter_del_hw(struct sxe2_vsi *vsi,
			    struct sxe2_fnav_filter *filter);

struct sxe2_fnav_filter
*sxe2_fnav_find_filter_by_flow_id_unlock(struct sxe2_vsi_fnav *vsi_fnav,
					 u32 flow_id);

s32 sxe2_fnav_del_filter_by_flow_id(struct sxe2_adapter *adapter,
				    u16 rule_vsi_id, u32 flow_id);

s32 sxe2_fnav_hw_stats_get(struct sxe2_adapter *adapter, u16 stat_index,
			   u32 is_clear,
			   enum sxe2_fnav_counter_bank_type bank_type,
			   struct sxe2_fwc_fnav_stats_resp *resp);

void sxe2_fnav_match_stats_get(struct sxe2_adapter *adapter, u16 stat_index, u16 vsi_id);

void sxe2_fnav_match_stats_update_batch(struct sxe2_adapter *adapter);

void sxe2_fnav_vf_cfg_clear(struct sxe2_adapter *adapter);

s32 sxe2_comm_add_fnav_filter(struct sxe2_adapter *adapter,
			      u16 ori_vsi_id, u16 dst_vsi_id, u16 rule_vsi_id,
			      struct sxe2_fnav_comm_full_msg *full_msg, u32 *flow_id);

void sxe2_fnav_clean_by_vsi(struct sxe2_vsi *vsi, bool need_clear_hw);

s32 sxe2_fnav_del_filter_by_vsi(struct sxe2_vsi *vsi);

s32 sxe2_fnav_filter_del(struct sxe2_vsi *rule_vsi, struct sxe2_fnav_filter *filter);

void sxe2_fnav_filter_free_by_vsi(struct sxe2_vsi *vsi);

void sxe2_fnav_flow_cfg_free(struct sxe2_vsi *vsi);

s32 sxe2_fnav_filter_add_hw(struct sxe2_vsi *vsi,
			    struct sxe2_fnav_filter *filter,
			    struct sxe2_fnav_flow_seg *segs);

struct sxe2_fnav_flow_cfg
*sxe2_fnav_find_flow_cfg_by_flow_type(struct sxe2_vsi *vsi,
				      enum sxe2_fnav_flow_type flow_type);

enum sxe2_fnav_flow_type sxe2_arfs_flow_to_fnav_flow(enum sxe2_fnav_flow_type flow_type);

void sxe2_fnav_filter_add_list_by_loc(struct sxe2_vsi *vsi,
				      struct sxe2_fnav_filter *filter);

s32 sxe2_pf_eth_fnav_init(struct sxe2_adapter *adapter);

void sxe2_pf_eth_fnav_deinit(struct sxe2_adapter *adapter);

s32 sxe2_pf_eth_fnav_rebuild(struct sxe2_adapter *adapter);

s32 sxe2_fnav_flow_cfg_clear_by_vsi(struct sxe2_vsi *vsi);

void sxe2_fnav_stats_free_by_vsi(struct sxe2_vsi *vsi);

void sxe2_eth_fnav_outer_hdr_set_eth(enum sxe2_fnav_flow_type flow_type,
				     struct sxe2_fnav_flow_seg *seg_outer);

#endif
