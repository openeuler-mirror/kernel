/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_ACL_H_
#define _NSE_ACL_H_

#define NSE_ACL_DEST_VSI_VLD_BIT 8
#define NSE_ACL_DEST_VSI_MASK    0xff

/* ACL lut ID enum values are specific to hardware */
enum nse_acl_lkup_type {
	NSE_ACL_LKUP_RX_DEST_VSI = 13,
	NSE_ACL_LKUP_TX_SRC_VSI,
	NSE_ACL_LKUP_OVS_MISS,
	NSE_ACL_LKUP_LAST,
};

/*nse_acl_fwd_act_type is related to lut node only,
 * that means signal action in lut node.
 * If Node state, NSE_ACL_LARGE_ACT is used.
 */
enum nse_acl_fwd_act_type {
	NSE_ACL_METER = 0,
	NSE_ACL_DROP,
	NSE_ACL_LARGE_ACT,
	NSE_ACL_INVAL_ACT,
};

struct nse_acl_meter_param {
	enum nse_sw_meter_mode mode;
	u64 rate;
	u64 burst;
	u16 meter_id; /*hw meter id*/
};

struct acl_pedit_headers {
	struct ethhdr  eth;
	struct vlan_hdr vlan;
	struct iphdr   ip4;
	struct ipv6hdr ip6;
	struct tcphdr  tcp;
	struct udphdr  udp;
};

struct nse_acl_pedit_headers {
	struct acl_pedit_headers	vals;
	struct acl_pedit_headers	masks;
	u32			pedits;
};

#define NSE_ACL_MAX_DU_METER_ACTIONS 2

struct nse_acl_large_action {
	u16 node_state_id;
	struct nse_node_state node_state;
	struct nse_sw_task_list *task_list;
	struct nse_sw_du_data *du_data;

	u32 flags;
#define NSE_ACL_LARGE_ACTION_DROP				BIT(0)
#define NSE_ACL_LARGE_ACTION_FWD_VSI			BIT(1)
#define NSE_ACL_LARGE_ACTION_COUNT				BIT(2)
#define NSE_ACL_LARGE_ACTION_DU_METER			BIT(3)
#define NSE_ACL_LARGE_ACTION_AU_NOP				BIT(5)
#define NSE_ACL_LARGE_ACTION_AU_DMAC_RW			BIT(6)
#define NSE_ACL_LARGE_ACTION_AU_SMAC_RW			BIT(7)
#define NSE_ACL_LARGE_ACTION_GOTO				BIT(8)

	struct nse_acl_pedit_headers hdrs;

	/*for meter param when there is du meter in large action*/
	u16 du_meter_cnt;
	struct nse_acl_meter_param du_meter_param[NSE_ACL_MAX_DU_METER_ACTIONS];
	u16 du_meter_id[NSE_ACL_MAX_DU_METER_ACTIONS];

	/*redirect to another Dest hw VSI when NSE_ACL_LARGE_ACTION_FWD_VSI is set*/
	u16 redirect_vsi;

	/*count info*/
	struct nse_sw_counter_pair *counter_p;

};

struct nse_acl_fltr_info {
	enum nse_acl_lkup_type lkup_type;
	enum nse_acl_fwd_act_type fltr_act;

	/*struct for acl large action
	 *when fltr_act is NSE_ACL_LARGE_ACT
	 */
	struct nse_acl_large_action lg_action;

	/* node ID returned by firmware once acl lut node is created */
	u16 node_id;

	/*for meter action when fltr_act is NSE_ACL_METER, not used in large action*/
	u16 meter_id;
	u64 packets_dropped;
	u64 bytes_dropped;
	struct nse_acl_meter_param meter_param;

	/*key to match or create*/
	u16 sw_id;
	u16 dst_hw_vsi;
	union {
		u16 src_lan_id;
		u16 src_hw_vsi;
	};
};

void nse_acl_remove_fltr(struct nse_hw *hw, struct nse_acl_fltr_info *fltr_info);

int nse_acl_add_fltr(struct nse_hw *hw, struct nse_acl_fltr_info *fltr_info);

int nse_acl_get_meter_stats(struct nse_hw *hw, struct nse_acl_fltr_info *fltr_info);

#endif
