/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_LPM_H_
#define _NSE_LPM_H_

extern u16 g_nse_ipv4_rt_lut_id;
extern u16 g_nse_ipv6_rt_lut_id;
extern u16 g_nse_dmac_ipv4_rt_lut_id;
extern u16 g_nse_dmac_ipv6_rt_lut_id;
extern struct hlist_head lpm_fltr_list;

#define NSE_LPM_WAIT_COUNTER_FREE_DELAY 100

#define NSE_LPM_DMAC_BIT_LEN 48

#define NSE_SW_MODE_LPM		NSE_SW_MODE_SWITCHDEV

#define NSE_LPM_FLWR_DYNAMIC_SUPPORT	1

#define NSE_MAX_LPM_LKUP_WORDS 19
#define NSE_MAX_LPM_LKUP_LUTS  NSE_MAX_SUB_NODE_NUM
#define NSE_ALL_MATCH_PREFIX_LEN	72

/* Mapping of software defined LUT ID to word_num , max prefix len, min prefix len... */
struct nse_lpm_map {
	bool is_first;
	u16 lkup_words;
	u16 lkup_max_prfx;
	u16 lkup_min_prfx;
	u16 cur_max_prfx;
};

struct nse_lpm_action {
	/*common info*/
	u16 large_act_id; /*same as note state id*/
	struct nse_node_state node_state;
	struct nse_sw_task_list *task_list;
	struct nse_sw_du_data *du_data;

	u32 flags;
#define NSE_LPM_ACTION_DROP				BIT(0)
#define NSE_LPM_ACTION_TO_LAN			BIT(1)
#define NSE_LPM_ACTION_FWD_VSI			BIT(2)
#define NSE_LPM_ACTION_COUNT			BIT(3)
#define NSE_LPM_ACTION_DEC_TTL			BIT(4)
#define NSE_LPM_ACTION_DEC_HLIMIT		BIT(5)

	enum nse_sw_fwd_act_type fltr_act;

	/*redirect/mirrored info*/
	struct nse_vsi *dest_vsi;
	/*count info*/
	struct nse_sw_counter_pair *counter_p;

};

struct nse_lpm_fltr {
	struct hlist_node lpm_node;

	u16 lut_id;
	u16 node_id;

	/* src chain id where this lpm filtr located */
	u8 chain_id;

	struct nse_lpm_action action;
	struct nse_ip_route_addr ip_key;
};

struct nse_adv_lpm_mgmt_list_entry {
	struct list_head list_entry;
	u16 lkups_cnt;
	struct nse_adv_lkup_elem *lkups;
	struct nse_adv_node_info node_info;
};

enum nse_lpm_lkup_type {
	NSE_LPM_LKUP_IPV4 = 7,
	NSE_LPM_LKUP_IPV6_H = 8,
	NSE_LPM_LKUP_IPV6_L = 9,
	NSE_LPM_LKUP_LAST
};

struct nse_lpm_info {
	enum nse_lpm_lkup_type lkup_type;
	enum nse_sw_fwd_act_type fltr_act;

	/* rule ID returned by firmware once filter rule is created */
	u16 fltr_node_id;

	struct nse_ip_route_addr ip_addr;
	u16 dst_vsi_id;
	u8 lb_en;
	u8 lan_en;
};

struct nse_lpm_mgmt_list_entry {
	struct list_head list_entry;
	struct nse_lpm_info info;
};

int
nse_lpm_add_ipv4_addr(struct nse_hw *hw, struct nse_lpm_info *info);

int
nse_lpm_del_ipv4_addr(struct nse_hw *hw, struct nse_lpm_info *info);

void
nse_dump_lpm_ipv4_entry(struct nse_hw *hw);

int
nse_erouter_add_lpm_fltr(struct nse_hw *hw,
		struct nse_lpm_fltr *fltr);
bool
nse_is_erouter_mode_en(struct nse_hw *hw);

void
nse_enable_erouter_mode(struct nse_hw *hw);

void
nse_disable_erouter_mode(struct nse_hw *hw);

void
nse_erouter_del_lpm_fltr(struct nse_hw *hw,
		struct nse_lpm_fltr *fltr);

void nse_dump_adv_lpm_lut_nodes(struct nse_hw *hw, u8 lut_id);

#endif
