/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_SWITCH_H_
#define _MCE_SWITCH_H_

#include "mce.h"
#include "mce_fdir.h"
#include "mce_lib.h"
#include "mce_eswitch.h"
#include "mce_fltr.h"
#include "mce_vf_lib.h"

enum mce_tc_tunnel_type {
	TNL_TC_VXLAN = 0,
	TNL_TC_GENEVE,
	TNL_TC_GRETAP,
	TNL_TC_GTP,
	TNL_TC_GTPC,
	TNL_TC_GTPU,
	TNL_TC_ECPRI,
	TNL_TC_LAST = 0xFF,
	TNL_TC_ALL = 0xFF,
};

struct mce_sw_act_ctrl {
	/* Source VSI for LOOKUP_TX or source port for LOOKUP_RX */
	u16 src;
	u16 flag;
	enum mce_sw_fwd_act_type fltr_act;
	/* Depending on filter action */
	union {
		/* This is a queue ID in case of MCE_FWD_TO_Q and starting
		 * queue ID in case of MCE_FWD_TO_QGRP.
		 */
		u16 q_id : 11;
		u16 vsi_id : 10;
		u16 hw_vsi_id : 10;
		u16 vsi_list_id : 10;
	} fwd_id;
	/* software VSI handle */
	u16 vsi_handle;
	u8 qgrp_size;
};

struct mce_rule_query_data {
	/* Recipe ID for which the requested rule was added */
	u16 rid;
	/* Rule ID that was added or is supposed to be removed */
	u16 rule_id;
	/* vsi_handle for which Rule was added or is supposed to be removed */
	u16 vsi_handle;
};

	/* This structure allows to pass info about lb_en and lan_en
	 * flags to mce_add_adv_rule. Values in act would be used
	 * only if act_valid was set to true, otherwise dflt
	 * values would be used.
	 */
struct mce_adv_rule_flags_info {
	u32 act;
	u8 act_valid; /* indicate if flags in act are valid */
};

enum mce_protocol_type {
	MCE_MAC_OFOS = 0,
	MCE_MAC_IL,
	MCE_ETYPE_OL,
	MCE_ETYPE_IL,
	MCE_VLAN_OFOS,
	MCE_IPV4_OFOS,
	MCE_IPV4_IL,
	MCE_IPV6_OFOS,
	MCE_IPV6_IL,
	MCE_TCP_IL,
	MCE_UDP_OF,
	MCE_UDP_ILOS,
	MCE_SCTP_IL,
	MCE_VXLAN,
	MCE_GENEVE,
	MCE_VXLAN_GPE,
	MCE_NVGRE,
	MCE_GTP,
	MCE_GTP_NO_PAY,
	MCE_PPPOE,
	MCE_PFCP,
	MCE_L2TPV3,
	MCE_ESP,
	MCE_AH,
	MCE_NAT_T,
	MCE_VLAN_EX,
	MCE_VLAN_IN,
	MCE_HW_METADATA,
	MCE_PROTOCOL_LAST
};

enum mce_sw_tun_type {
	MCE_SW_NON_TUN = 0,
	MCE_SW_TUN_VXLAN = 1,
	MCE_SW_TUN_GRE,
	MCE_SW_TUN_GENEVE,
	MCE_SW_TUN_GTP_U,
	MCE_SW_TUN_GTP_C,
	MCE_SW_TUN_IPINIP,
	MCE_SW_TUN_MPLS_UDP,
};

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)

struct mce_adv_rule_info {
	/* Store metadata values in rule info */
	enum mce_sw_tun_type tun_type;
	u16 vlan_type;
	u16 fltr_rule_id;
	u32 priority;
	u16 src_vsi;
	struct mce_sw_act_ctrl sw_act;
	u8 add_dir_lkup;
	u16 lg_id;
	struct mce_adv_rule_flags_info flags_info;
};

#define MCE_ESWITCH_ACTION_ENTRIES 32
#define MCE_ESWITCH_RULES_ENTRIES MCE_ESWITCH_ACTION_ENTRIES
#define MCE_ESWITCH_RULES_SWITCHDEV_ENTRIES 12
#define MCE_ESWITCH_RULES_BCMC_ENTRIES 1
#define MCE_ESWITCH_RULES_LEGACY_ENTRIES                                  \
	(MCE_ESWITCH_RULES_ENTRIES - MCE_ESWITCH_RULES_SWITCHDEV_ENTRIES - \
	 MCE_ESWITCH_RULES_BCMC_ENTRIES)

struct mce_eswitch_pattern {
	struct {
		u8 dst_mac[ETH_ALEN];
		u16 vlan_id;
		u32 tunnel_tag;

		u16 ether_type;
		u32 dst_addr;
		u32 src_addr;
		u8 protocol;
		u16 l4_sport;
		u16 l4_dport;
		u32 vni;
		u32 tni;
		u32 teid;

		bool is_ipv6;
		u16 svport_id;
	} __packed __aligned(1) formatted;

	u16 dvport_id;
};

struct mce_eswitch_filter {
	struct list_head fltr_node;
	struct mce_eswitch_pattern lkup_pattern;
	u64 options;
	u16 meta_num;
	u8 eswitch_type;
	int rule_loc;
	bool drop_en;
};

struct mce_eswitch_handle {
	u16 max_eswitch_rule;
	u16 max_legacy_rule;
	u16 max_switchdev_rule;
	struct mce_lkup_meta meta_db[2][MCE_META_TYPE_MAX];
	struct list_head eswitch_legacy_head;
	DECLARE_BITMAP(avail_legacy, MCE_ESWITCH_RULES_LEGACY_ENTRIES);

	struct list_head eswitch_switchdev_head;
	DECLARE_BITMAP(avail_switchdev, MCE_ESWITCH_RULES_SWITCHDEV_ENTRIES);
};

struct mce_flow_ptype_match *
mce_eswitch_check_pattern_support(struct mce_pf *pf, u8 *compose,
				  struct mce_tc_flower_fltr *tc_fltr);
struct mce_eswitch_filter *
mce_meta_to_eswitch_legacy(struct mce_hw *hw,
			   struct mce_tc_flower_fltr *tc_fltr,
			   struct mce_eswitch_handle *handle, u16 meta_num,
			   bool is_ipv6, bool is_tunnel);
struct mce_eswitch_filter *
mce_meta_to_eswitch_switchdev(struct mce_hw *hw,
			      struct mce_tc_flower_fltr *tc_fltr,
			      struct mce_eswitch_handle *handle, u16 meta_num,
			      bool is_ipv6, bool is_tunnel);
#endif /* CONFIG_NET_CLS_FLOWER */
#endif /* _MCE_SWITCH_H_ */
