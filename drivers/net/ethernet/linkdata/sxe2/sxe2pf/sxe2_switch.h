/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_switch.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_SWITCH_H__
#define __SXE2_SWITCH_H__

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>

#include "sxe2_vsi.h"
#include "sxe2_flow_public.h"

#ifndef U8_MAX
#define U8_MAX (0xFF)
#endif

#ifndef U8_BITS
#define U8_BITS (8)
#endif

#ifdef SXE2_TEST
#define STATIC
#else
#define STATIC static
#endif

#define SXE2_FULL_KEY_RECIPE_ROOT_S (7)
#define SXE2_FULL_KEY_SOURCE_TYPE_S (5)

#define SXE2_IPV6_ADDR_LENGTH (16)

#define SXE2_VSID_PF_TO_DEV(id_in_pf, adapter)                                 \
			    (((adapter)->vsi_ctxt.vsi[(id_in_pf)])->idx_in_dev)

#define SXE2_VLAN_QOS_MAX (7)

#define SXE2_PROFILE_MAX_COUNT	    (256)
#define SXE2_SWITCH_PROFILE_FV_CNT  (48)

#define SXE2_VLAN(tpid, vid, prio) ((struct sxe2_vlan){ tpid, vid, prio })

struct sxe2_tc_rule_hash {
	struct hlist_node node;
	unsigned long cookie;
	struct sxe2_rule_info *rule_info;
};

enum sxe2_fwd_act_type {
	SXE2_FWD_TO_VSI = 0,
	SXE2_FWD_TO_VSI_LIST,
	SXE2_FWD_TO_Q,
	SXE2_FWD_TO_QGRP,
	SXE2_DROP_PACKET,
	SXE2_MIRROR_PACKET,
	SXE2_LARGE_ACTION,
	SXE2_INVAL_ACT
};

enum sxe2_vsi_list_type {
	SXE2_VSI_LIST_TYPE_FORWARD = 0,
	SXE2_VSI_LIST_TYPE_PRUNE,

	SXE2_VSI_LIST_TYPE_MAX,
};

struct sxe2_vsi_list_info {
	struct list_head list_entry;
	enum sxe2_vsi_list_type type;
	DECLARE_BITMAP(vsi_map, SXE2_VSI_MAX_CNT);
	u16 vsi_list_id;
	u16 rule_cnt;
	u16 need_bond;
};

struct sxe2_vsi_list_mgmt {
	enum sxe2_vsi_list_type type;
	struct list_head vsi_list_head;
	/* in order to protect the data */
	struct mutex vsi_list_lock;
};

struct sxe2_rule_action {
	enum sxe2_fwd_act_type type;
	union {
		u16 q_id : 11;
		u16 vsi_id : 10;
		u16 vsi_list_id : 10;
	} fwd_id;
	u8 lb_en;
	u8 lan_en;
	u8 q_high:1;
	u8 qgrp_size:3;
	u8 rsv:4;
};

enum sxe2_src_type {
	SXE2_SRC_TYPE_TX = 0,
	SXE2_SRC_TYPE_RX,
};

enum sxe2_pkt_src_type {
	SXE2_PKT_SRC_TYPE_LAN = 0,
	SXE2_PKT_SRC_TYPE_LOOPBACK_HOST,
	SXE2_PKT_SRC_TYPE_LOOPBACK_MNG,
	SXE2_PKT_SRC_TYPE_TRANSMIT,
};

struct sxe2_rule_filter {
	enum sxe2_src_type src_type;
	union {
		struct {
			u8 mac_addr[ETH_ALEN];
		} mac;
		struct {
			u16 vlan_id;
			u16 tpid;
			u8 tpid_valid;
		} vlan;
		struct {
			u16 vsi_id;
			u16 ethertype;
		} etype;
		struct {
			u16 vsi_id;
			u8 to_rdma;
			u8 packet_src_type;
		} srcvsi;
		struct {
			u16 vsi_id;
		} mac_spoofchk;
		struct {
			u16 hid;
			u8 mac_addr[ETH_ALEN];
		} mac_spoofchk_ext;
	} data;
};

struct sxe2_rule_info {
	struct list_head list_entry;
	struct sxe2_vsi_list_info *vsi_list;
	u16 recipe_id;
	u16 rule_id;
	struct sxe2_rule_filter fltr;
	struct sxe2_rule_action act;
	bool is_fwd;
	struct sxe2_tcf_fltr *tcf_fltr;
	struct list_head tc_rule_head;
	u16 hid;
};

struct sxe2_recipe {
	u8 is_root;
	u16 recipe_id;
	struct list_head rule_head;
	struct list_head restore_head;
	/* in order to protect the data */
	struct mutex rule_lock;
	DECLARE_HASHTABLE(ht_cookie, 10);
	DECLARE_HASHTABLE(ht_lkup, 10);
};

struct sxe2_profile_fv_item {
	u32 prot_id : 8;
	u32 offset : 9;
	u32 enable : 1;
	u32 rsv : 14;
};

struct sxe2_switch_context {
	u16 evb_mode;
	u8 switch_id;
	/* in order to protect the data */
	struct mutex evb_mode_lock;
	struct sxe2_vsi_list_mgmt vsi_list_mgmt[SXE2_VSI_LIST_TYPE_MAX];
	struct sxe2_recipe recipe[SXE2_DEFAULT_RECIPE_MAX];
	struct sxe2_recipe complex_recipe;
	struct sxe2_profile_fv_item **profile_fv_item;
	/* in order to protect the data */
	struct mutex lldp_rule_lock;
	/* in order to protect the data */
	struct mutex mac_addr_lock;
};

struct sxe2_ethtype_hdr {
	u16 ethtype_id;
} __packed;

struct sxe2_udp_tnl_hdr {
	u16 source;
	u16 dest;
	u16 len;
	u16 check;
	u16 field;
	u16 proto_type;
	u32 vni;
} __packed;

union sxe2_prot_hdr {
	struct sxe2_ether_hdr eth_hdr;
	struct sxe2_ethtype_hdr ethertype;
	struct sxe2_vlan_hdr vlan_hdr;
	struct sxe2_ipv4_hdr ipv4_hdr;
	struct sxe2_ipv6_hdr ipv6_hdr;
	struct sxe2_tcp_hdr tcp_hdr;
	struct sxe2_udp_hdr udp_hdr;
	struct sxe2_udp_tnl_hdr udp_tnl_hdr;
	struct sxe2_nvgre_hdr nvgre_hdr;
};

#define SXE2_MAC_OL_HW	 1
#define SXE2_MAC_IL_HW	 4
#define SXE2_ETYPE_OL_HW 9
#define SXE2_ETYPE_IL_HW 10
#define SXE2_VLAN_EX_HW	 16
#define SXE2_VLAN_OL_HW	 17
#define SXE2_IPV4_OL_HW	 32
#define SXE2_IPV4_IL_HW	 33
#define SXE2_IPV6_OL_HW	 40
#define SXE2_IPV6_IL_HW	 41
#define SXE2_TCP_IL_HW	 49
#define SXE2_UDP_OL_HW	 52
#define SXE2_UDP_IL_HW	 53
#define SXE2_GRE_HW	 64

#define SXE2_META_HW 0xff

#define SXE2_META_PKT_SRC_OFFSET       5
#define SXE2_META_PKT_DIRECTION_OFFSET 4
#define SXE2_META_VSI_NUM_OFFSET       1
#define SXE2_META_PKT_TO_RDMA_OFFSET   2

enum sxe2_protocol_filed_type {
	SXE2_META_PKT_SRC = 0,
	SXE2_META_PKT_DIRECTION,
	SXE2_META_VSI_NUM,
	SXE2_META_PKT_TO_RDMA,
	SXE2_OUTER_SMAC,
	SXE2_OUTER_DMAC,
	SXE2_INNER_SMAC,
	SXE2_INNER_DMAC,
	SXE2_OUTER_ETYPE,
	SXE2_INNER_ETYPE,
	SXE2_OUTER_VLAN_EX,
	SXE2_OUTER_VLAN,
	SXE2_OUTER_IPV4_SADDR,
	SXE2_OUTER_IPV4_DADDR,
	SXE2_OUTER_IPV4_TTL,
	SXE2_OUTER_IPV4_TOS,
	SXE2_OUTER_IPV4_PROT,
	SXE2_INNER_IPV4_SADDR,
	SXE2_INNER_IPV4_DADDR,
	SXE2_INNER_IPV4_TTL,
	SXE2_INNER_IPV4_TOS,
	SXE2_INNER_IPV4_PROT,
	SXE2_OUTER_IPV6_SADDR,
	SXE2_OUTER_IPV6_DADDR,
	SXE2_INNER_IPV6_SADDR,
	SXE2_INNER_IPV6_DADDR,
	SXE2_LAST_TCP_SPORT,
	SXE2_LAST_TCP_DPORT,
	SXE2_OUTER_UDP_SPORT,
	SXE2_OUTER_UDP_DPORT,
	SXE2_INNER_UDP_SPORT,
	SXE2_INNER_UDP_DPORT,
	SXE2_VXLAN_ENC_ID,
	SXE2_GENEVE_ENC_ID,
	SXE2_NVGRE_ENC_ID,

	SXE2_PROT_FIELD_LAST,
};

#define SXE2_PROT_OFFSET_VNI 12

struct sxe2_tcf_key_item {
	enum sxe2_protocol_filed_type type;
	union {
		union sxe2_prot_hdr hdr;
		u16 raw[sizeof(union sxe2_prot_hdr) / sizeof(u16)];
	} value;
	union {
		union sxe2_prot_hdr hdr;
		u16 raw[sizeof(union sxe2_prot_hdr) / sizeof(u16)];
	} mask;
};

enum sxe2_tunnel_type {
	SXE2_TNL_NONE = 0,
	SXE2_TNL_VXLAN,
	SXE2_TNL_GENEVE,
	SXE2_TNL_GRETAP,

	SXE2_TNL_ALL,
};

enum sxe2_rule_backup_type {
	SXE2_RULE_BACKUP_T_NO = 0,
	SXE2_RULE_BACKUP_T_LAST,
	SXE2_RULE_BACKUP_T_FIRST,

	SXE2_RULE_BACKUP_T_ALL,
};

struct sxe2_tc_rule_info {
	struct list_head list_entry;
	unsigned long cookie;
	u32 prio;
	u16 src_vsi_id;
	u16 dst_vsi_id;
	DECLARE_BITMAP(dst_vsi_map, SXE2_VSI_MAX_CNT);
	struct sxe2_vsi_list_info *vsi_list;
	enum sxe2_fwd_act_type action;
	struct sxe2_rule_action act;
	enum sxe2_rule_backup_type backup_type;
};

struct sxe2_tcf_fltr {
	struct hlist_node node;
	struct sxe2_rule_info *rule_info;
	unsigned long cookie;

	struct sxe2_adapter *adapter;
	u16 src_vsi_id;
	u16 dst_vsi_id;
	DECLARE_BITMAP(dst_vsi_map, SXE2_VSI_MAX_CNT);
	u16 dst_queue_id;
	u8 dst_queue_high:1;
	u8 dst_queue_group:3;
	u8 rsv:4;

	struct sxe2_tcf_key_item items[SXE2_PROT_FIELD_LAST];
	u16 word_cnt;

	enum sxe2_tunnel_type tunnel_type;
	u8 ip_proto;

	enum sxe2_fwd_act_type action;
	enum sxe2_src_type src_type;
	u8 priority;

	DECLARE_BITMAP(profiles, SXE2_MAX_NUM_PROFILES);

	u16 lkup_mask[SXE2_MAX_CHAIN_WORDS];
	u16 lkup_value[SXE2_MAX_CHAIN_WORDS];
	u16 lkup_index[SXE2_MAX_CHAIN_WORDS];

	u16 recipe_cnt;
	u16 recipe_id[SXE2_MAX_CHAIN_RECIPE];
	u16 rule_id[SXE2_MAX_CHAIN_RECIPE];

	u32 prio;

	bool cookie_invalid;

	bool is_user_rule;

	u16 rule_vsi_id;

	enum sxe2_rule_backup_type backup_type;
};

struct sxe2_user_cpx_fltr {
	struct sxe2_adapter *adapter;
	u16 src_vsi_id;
	u16 dst_vsi_id;
	DECLARE_BITMAP(dst_vsi_map, SXE2_VSI_MAX_CNT);
	u16 dst_queue_id;
	u8 dst_queue_high;
	u8 dst_queue_group;
	struct sxe2_tcf_key_item items[SXE2_PROT_FIELD_LAST];
	enum sxe2_tunnel_type tunnel_type;
	enum sxe2_fwd_act_type action;
	enum sxe2_src_type src_type;
	u32 prio;
	u16 rule_vsi_id;
	enum sxe2_rule_backup_type backup_type;
};

struct sxe2_switch_recipe {
	u8 rid : 6;
	u8 rcp_rsv0 : 1;
	u8 is_root : 1;
	u8 lookup_index0 : 7;
	u8 lookup_index0_valid : 1;
	u8 lookup_index1 : 7;
	u8 lookup_index1_valid : 1;
	u8 lookup_index2 : 7;
	u8 lookup_index2_valid : 1;
	u8 lookup_index3 : 7;
	u8 lookup_index3_valid : 1;
	u8 lookup_index4 : 7;
	u8 lookup_index4_valid : 1;
	u8 join_priority;
	u8 priority : 3;
	u8 need_pass_l2 : 1;
	u8 allow_pass_l2 : 1;
	u8 inverse_action : 1;
	u8 prune_idx : 2;
	u32 default_action : 19;
	u32 rcp_rsv1 : 4;
	u32 default_action_valid : 1;
	u32 rcp_rsv2 : 8;
	u32 fv4_bitmask : 16;
	u32 fv3_bitmask : 16;
	u32 fv2_bitmask : 16;
	u32 fv1_bitmask : 16;
	u32 fv0_bitmask : 16;
	u32 rcp_rsv3 : 16;
};

struct sxe2_user_context {
	/* in order to protect the data */
	struct mutex flag_lock;
	bool is_promisc_set;
	bool is_allmulti_set;
};

static inline void sxe2_switch_mac_node_del_and_free(struct sxe2_addr_node *mac_node)
{
	if (mac_node) {
		list_del(&mac_node->list);
		kfree(mac_node);
	}
}

s32 sxe2_switch_context_init(struct sxe2_adapter *adapter);

void sxe2_switch_context_deinit(struct sxe2_adapter *adapter);

s32 sxe2_mac_rule_add(struct sxe2_vsi *vsi, const u8 *mac);

s32 sxe2_mac_rule_del(struct sxe2_adapter *adapter,
		      u16 id_in_dev, const u8 *mac);

s32 sxe2_vlan_rule_add(struct sxe2_vsi *vsi, struct sxe2_vlan *vlan);

s32 sxe2_vlan_rule_del(struct sxe2_adapter *adapter,
		       u16 id_in_dev, struct sxe2_vlan *vlan);

s32 sxe2_promisc_rule_add(struct sxe2_vsi *vsi);

s32 sxe2_promisc_rule_del(struct sxe2_adapter *adapter, u16 id_in_dev);

bool sxe2_promisc_rule_in_use(struct sxe2_vsi *vsi);

s32 sxe2_allmulti_rule_add(struct sxe2_vsi *vsi);

s32 sxe2_allmulti_rule_del(struct sxe2_adapter *adapter, u16 id_in_dev);

bool sxe2_allmulti_rule_in_use(struct sxe2_vsi *vsi);

s32 sxe2_tx_etype_rule_add(struct sxe2_vsi *vsi, u16 etype);

s32 sxe2_tx_etype_rule_del(struct sxe2_adapter *adapter,
			   u16 id_in_dev, u16 etype);

s32 sxe2_tcf_rule_add(struct sxe2_adapter *adapter,
		      u16 vsi_id_in_dev, struct sxe2_tcf_fltr *fltr);

s32 sxe2_tcf_rule_del(struct sxe2_adapter *adapter,
		      u16 vsi_id_in_dev, struct sxe2_tcf_fltr *fltr);

void sxe2_vsi_fltr_clean(struct sxe2_vsi *vsi);
void sxe2_vsi_l2_fltr_clean(struct sxe2_vsi *vsi);
void sxe2_vsi_complex_fltr_clean(struct sxe2_vsi *vsi);

void sxe2_vsi_fltr_remove(struct sxe2_adapter *adapter, u16 id_in_dev);

void sxe2_vsi_l2_fltr_remove(struct sxe2_adapter *adapter, u16 id_in_dev);

void sxe2_vsi_complex_fltr_remove(struct sxe2_adapter *adapter,
				  u16 id_in_dev, bool to_restore);

s32 sxe2_switch_fltr_restore_prepare(struct sxe2_adapter *adapter);

s32 sxe2_vsi_complex_fltr_restore(struct sxe2_adapter *adapter, u16 vsi_id);

void sxe2_switch_fltr_restore_clean(struct sxe2_adapter *adapter);

s32 sxe2_vsi_l2_fltr_restore(struct sxe2_vsi *vsi);

s32 sxe2_rule_bridge_mode_update(struct sxe2_adapter *adapter);

void sxe2_switch_rule_hw_dump(struct sxe2_adapter *adapter);

void sxe2_fwc_switch_trace_rx_trigger(struct sxe2_adapter *adapter);

void sxe2_fwc_switch_trace_tx_trigger(struct sxe2_adapter *adapter);

void sxe2_fwc_switch_trace_recorder(struct sxe2_adapter *adapter);

void sxe2_fwc_hw_dfx_show(struct sxe2_adapter *adapter);

s32 sxe2_vlan_filter_control(struct sxe2_adapter *adapter, u16 vsi_hw_id,
			     bool en);

s32 sxe2_vsi_loopback_control(struct sxe2_adapter *adapter, u16 vsi_hw_id,
			      bool en);

s32 sxe2_vsi_spoofchk_control(struct sxe2_adapter *adapter, u16 vsi_hw_id,
			      bool en);

s32 sxe2_tcf_profile_find(struct sxe2_tcf_fltr *fltr);

void sxe2_tcf_match_meta_fill(struct sxe2_tcf_fltr *fltr);

static inline bool sxe2_tcf_item_is_empty(struct sxe2_tcf_fltr *fltr, u16 id)
{
	u16 tmp[sizeof(union sxe2_prot_hdr) / sizeof(u16)] = { 0 };

	if (memcmp(fltr->items[id].mask.raw, tmp, sizeof(tmp)) == 0)
		return true;
	return false;
}

s32 sxe2_vsi_vlan_zero_add(struct sxe2_vsi *vsi);

void sxe2_srcvsi_rule_prepare(struct sxe2_adapter *adapter,
			      u16 id_in_dev, struct sxe2_rule_info *rule);

s32 sxe2_srcvsi_rule_add(struct sxe2_vsi *vsi);

s32 sxe2_etype_fltr_init(struct sxe2_vsi *vsi);

s32 sxe2_rx_etype_rule_add(struct sxe2_vsi *vsi, u16 etype);

s32 sxe2_rx_etype_rule_del(struct sxe2_adapter *adapter,
			   u16 id_in_dev, u16 etype);

s32 sxe2_srcvsi_rule_del(struct sxe2_adapter *adapter, u16 id_in_dev);
s32 sxe2_src_vsi_prune_control(struct sxe2_adapter *adapter, u16 vsi_hw_id,
			       bool en);

s32 sxe2_vfs_complex_fltr_restore(struct sxe2_adapter *adapter);

s32 sxe2_pf_complex_fltr_restore(struct sxe2_adapter *adapter);

s32 sxe2_vsi_list_update_bond(struct sxe2_adapter *adapter,
			      struct sxe2_vsi_list_info *vsi_list,
			      struct sxe2_adapter *master_adapter,
			      bool linking);

s32 sxe2_fwc_switch_large_action_cfg(struct sxe2_adapter *adapter,
				     struct sxe2_fwc_switch_large_action *lgactionparm,
				     enum sxe2_drv_cmd_opcode opc);

s32 sxe2_sw_profile_parse_from_ddp(u8 *data, u16 cnt, u16 base_id,
				   struct sxe2_adapter *adapter);

s32 sxe2_default_mac_addr_get(struct sxe2_vsi *vsi, u8 *mac);

s32 sxe2_mac_addr_set(struct sxe2_vsi *vsi, const u8 *mac);

s32 sxe2_mac_spoofchk_rule_add(struct sxe2_adapter *adapter,
			       u16 id_in_dev);

s32 sxe2_mac_spoofchk_rule_del(struct sxe2_adapter *adapter,
			       u16 id_in_dev);

void sxe2_mac_spoofchk_rule_prepare(struct sxe2_adapter *adapter,
				    u16 id_in_dev, struct sxe2_rule_info *rule);

s32 sxe2_mac_spoofchk_ext_rule_add(struct sxe2_adapter *adapter,
				   u16 id_in_dev, const u8 *mac);

s32 sxe2_mac_spoofchk_ext_rule_del(struct sxe2_adapter *adapter,
				   u16 id_in_dev, const u8 *mac);

s32 sxe2_cur_mac_addr_set(struct sxe2_vsi *vsi, const u8 *mac);

void sxe2_switch_recipe_dump(struct sxe2_adapter *adapter);

void sxe2_switch_profile_recipemap_dump(struct sxe2_adapter *adapter);

void sxe2_switch_share_id_dump(struct sxe2_adapter *adapter);

s32 sxe2_vsi_loopback_control(struct sxe2_adapter *adapter, u16 vsi_hw_id,
			      bool en);

s32 sxe2_src_vsi_prune_control(struct sxe2_adapter *adapter, u16 vsi_hw_id,
			       bool en);

s32 sxe2_switch_dfx_irq_setup(struct sxe2_adapter *adapter, bool en);

s32 sxe2_switch_tc_samerule_del(struct sxe2_adapter *adapter,
				struct sxe2_rule_info *save_rule);

s32 sxe2_fwd_rule_remove(struct sxe2_adapter *adapter,
			 struct sxe2_rule_info *rule_info, bool free_sw);

struct sxe2_tc_rule_hash *sxe2_hash_cookie_find(struct sxe2_adapter *adapter,
						unsigned long cookie);

s32 sxe2_mac_rule_update(struct sxe2_adapter *adapter, const u8 *mac, u16 old_vsi, u16 new_vsi);

s32 sxe2_promisc_rule_update(struct sxe2_adapter *adapter, u16 old_vsi, u16 new_vsi);

s32 sxe2_allmulti_rule_update(struct sxe2_adapter *adapter, u16 old_vsi, u16 new_vsi);

s32 sxe2_fwd_rule_update(struct sxe2_adapter *adapter,
			 struct sxe2_rule_info *rule_info);

s32 sxe2_ucmd_unicast_mac_add(struct sxe2_adapter *adapter,
			      u16 vsi_id, const u8 *mac);

s32 sxe2_ucmd_multi_broad_mac_add(struct sxe2_adapter *adapter,
				  u16 vsi_id, const u8 *mac);

s32 sxe2_ucmd_unicast_mac_del(struct sxe2_adapter *adapter,
			      u16 vsi_id, const u8 *mac);

s32 sxe2_ucmd_multi_broad_mac_del(struct sxe2_adapter *adapter,
				  u16 vsi_id, const u8 *mac);

s32 sxe2_ucmd_promisc_rule_add(struct sxe2_adapter *adapter,
			       u16 vsi_id);

s32 sxe2_ucmd_promisc_rule_del(struct sxe2_adapter *adapter,
			       u16 vsi_id);

s32 sxe2_allmulti_rule_update(struct sxe2_adapter *adapter,
			      u16 old_vsi, u16 new_vsi);

s32 sxe2_ucmd_allmulti_rule_add(struct sxe2_adapter *adapter,
				u16 vsi_id);

s32 sxe2_ucmd_allmulti_rule_del(struct sxe2_adapter *adapter,
				u16 vsi_id);

s32 sxe2_ucmd_complex_fltr_proc(struct sxe2_user_cpx_fltr *user_cpx_fltr,
				bool is_add);

s32 sxe2_ucmd_vlan_filter_control(struct sxe2_adapter *adapter, u16 vsi_hw_id,
				  bool en);

s32 sxe2_ucmd_vlan_rule_process(struct sxe2_adapter *adapter, u16 vsi_hw_id,
				struct sxe2_vlan *vlan, bool add);

s32 sxe2_user_l2_feature_clean(struct sxe2_adapter *adapter, u16 vsi_hw_id);

s32 sxe2_mac_spoof_rule_update(struct sxe2_vsi *eth_vsi,
			       struct sxe2_vsi *user_vsi, u8 *mac_addr, bool to_user);
s32 sxe2_srcvsi_ext_rule_add(struct sxe2_vsi *vsi);

s32 sxe2_srcvsi_ext_rule_del(struct sxe2_adapter *adapter,
			     u16 vsi_id);
s32 sxe2_ucmd_srcvsi_ext_add(struct sxe2_adapter *adapter,
			     u16 vsi_id, u16 *vsi_id_list, u16 vsi_id_cnt);
s32 sxe2_ucmd_srcvsi_ext_del(struct sxe2_adapter *adapter,
			     u16 vsi_id);

#endif
