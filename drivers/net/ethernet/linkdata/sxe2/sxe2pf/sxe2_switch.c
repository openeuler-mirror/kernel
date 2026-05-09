// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_switch.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_switch.h"
#include "sxe2_cmd.h"
#include "sxe2_vsi.h"
#include "sxe2.h"
#include "sxe2_log.h"
#include "sxe2_netdev.h"
#include "sxe2_hw.h"
#include "sxe2_common.h"
#include "sxe2_tc.h"
#include "sxe2_dcb.h"
#include "sxe2_rx.h"
#include <linux/if_bridge.h>

#ifdef SXE2_CFG_DEBUG
STATIC int l2_force_fkot;
module_param(l2_force_fkot, int, 0);
MODULE_PARM_DESC(l2_force_fkot,
		 "switch rule force add fkot (0=false(default), 1=true)");
STATIC int tc_force_fkot;
module_param(tc_force_fkot, int, 0);
MODULE_PARM_DESC(tc_force_fkot,
		 "switch rule force add fkot (0=false(default), 1=true)");
#endif

#define SWITCH_RULE_ACT_INFO_CPY(dst_rule_info, src_rule_info)                 \
	do {                                                                   \
		typeof(dst_rule_info) __dst_rule_info = (dst_rule_info);       \
		typeof(src_rule_info) __src_rule_info = (src_rule_info);       \
		memcpy(&(__dst_rule_info)->act, &(__src_rule_info)->act,       \
		       sizeof(struct sxe2_rule_action));                       \
		(__dst_rule_info)->tcf_fltr->action =                          \
			(__src_rule_info)->tcf_fltr->action;                   \
		(__dst_rule_info)->tcf_fltr->cookie =                          \
			(__src_rule_info)->tcf_fltr->cookie;                   \
		(__dst_rule_info)->tcf_fltr->prio =                            \
			(__src_rule_info)->tcf_fltr->prio;                     \
		(__dst_rule_info)->tcf_fltr->dst_vsi_id =                      \
			(__src_rule_info)->tcf_fltr->dst_vsi_id;               \
		memcpy((__dst_rule_info)->tcf_fltr->dst_vsi_map,               \
		       (__src_rule_info)->tcf_fltr->dst_vsi_map,               \
		       sizeof((__dst_rule_info)->tcf_fltr->dst_vsi_map));      \
		(__dst_rule_info)->tcf_fltr->src_vsi_id =                      \
			(__src_rule_info)->tcf_fltr->src_vsi_id;               \
		(__dst_rule_info)->tcf_fltr->backup_type =                     \
			(__src_rule_info)->tcf_fltr->backup_type;              \
		(__dst_rule_info)->vsi_list = (__src_rule_info)->vsi_list;     \
	} while (0)

#define SWITCH_TC_RULE_ACT_INFO_GET_FROM_RULE(dst_tc_rule_info, src_rule_info) \
	do {                                                                   \
		typeof(dst_tc_rule_info) __dst_tc_rule_info = (dst_tc_rule_info);       \
		typeof(src_rule_info) __src_rule_info = (src_rule_info);       \
		memcpy(&(__dst_tc_rule_info)->act, &(__src_rule_info)->act,        \
		       sizeof(struct sxe2_rule_action));                       \
		(__dst_tc_rule_info)->action =                                   \
			(__src_rule_info)->tcf_fltr->action;                     \
		(__dst_tc_rule_info)->cookie =                                   \
			(__src_rule_info)->tcf_fltr->cookie;                     \
		(__dst_tc_rule_info)->prio = (__src_rule_info)->tcf_fltr->prio;    \
		memcpy((__dst_tc_rule_info)->dst_vsi_map,                      \
		       (__src_rule_info)->tcf_fltr->dst_vsi_map,                   \
		       sizeof((__dst_tc_rule_info)->dst_vsi_map));           \
		(__dst_tc_rule_info)->src_vsi_id =                               \
			(__src_rule_info)->tcf_fltr->src_vsi_id;                 \
		(__dst_tc_rule_info)->dst_vsi_id =                               \
			(__src_rule_info)->tcf_fltr->dst_vsi_id;                 \
		(__dst_tc_rule_info)->backup_type =                     \
			(__src_rule_info)->tcf_fltr->backup_type;                  \
		(__dst_tc_rule_info)->vsi_list = (__src_rule_info)->vsi_list;    \
	} while (0)

#define SWITCH_TC_RULE_ACT_INFO_SET_TO_RULE(dst_rule_info, src_tc_rule_info)   \
	do {                                                                   \
		typeof(dst_rule_info) __dst_rule_info = (dst_rule_info);       \
		typeof(src_tc_rule_info) __src_tc_rule_info = (src_tc_rule_info);       \
		memcpy(&(__dst_rule_info)->act, &(__src_tc_rule_info)->act,        \
		       sizeof(struct sxe2_rule_action));                       \
		(__dst_rule_info)->tcf_fltr->action =                            \
			(__src_tc_rule_info)->action;                            \
		(__dst_rule_info)->tcf_fltr->cookie =                            \
			(__src_tc_rule_info)->cookie;                            \
		(__dst_rule_info)->tcf_fltr->prio = (__src_tc_rule_info)->prio;    \
		memcpy((__dst_rule_info)->tcf_fltr->dst_vsi_map,                      \
		       (__src_tc_rule_info)->dst_vsi_map,                   \
		       sizeof((__dst_rule_info)->tcf_fltr->dst_vsi_map));           \
		(__dst_rule_info)->tcf_fltr->dst_vsi_id =    \
			(__src_tc_rule_info)->dst_vsi_id;    \
		(__dst_rule_info)->tcf_fltr->src_vsi_id =    \
			(__src_tc_rule_info)->src_vsi_id;   \
		(__dst_rule_info)->tcf_fltr->backup_type =    \
			(__src_tc_rule_info)->backup_type;    \
		(__dst_rule_info)->vsi_list = (__src_tc_rule_info)->vsi_list;   \
	} while (0)

#define SWITCH_TC_RULE_ACT_INFO_GET_FROM_TC_RULE(dst_tc_rule_info, src_tc_rule_info) \
	do {                                                               \
		typeof(dst_tc_rule_info) __dst_tc_rule_info = (dst_tc_rule_info);       \
		typeof(src_tc_rule_info) __src_tc_rule_info = (src_tc_rule_info);       \
		memcpy(&(__dst_tc_rule_info)->act, &(__src_tc_rule_info)->act,	   \
		       sizeof(struct sxe2_rule_action));   \
		(__dst_tc_rule_info)->action =   \
			(__src_tc_rule_info)->action;    \
		(__dst_tc_rule_info)->cookie =   \
			(__src_tc_rule_info)->cookie;    \
		(__dst_tc_rule_info)->prio = (__src_tc_rule_info)->prio; \
		memcpy((__dst_tc_rule_info)->dst_vsi_map, \
		       (__src_tc_rule_info)->dst_vsi_map,  \
		       sizeof((__dst_tc_rule_info)->dst_vsi_map));   \
		(__dst_tc_rule_info)->src_vsi_id =   \
			(__src_tc_rule_info)->src_vsi_id;    \
		(__dst_tc_rule_info)->dst_vsi_id =   \
			(__src_tc_rule_info)->dst_vsi_id;    \
		(__dst_tc_rule_info)->backup_type =   \
			(__src_tc_rule_info)->backup_type;   \
		(__dst_tc_rule_info)->vsi_list = (__src_tc_rule_info)->vsi_list; \
	} while (0)

#define LOG_SWITCH_RULE_OPT(ret, type, ...)                                     \
	do {                                                                   \
		typeof(ret) __ret = (ret);                                     \
		if (__ret == -EEXIST || __ret == -ENOENT) {                        \
			LOG_WARN_BDF(type, ##__VA_ARGS__);                      \
		} else if (__ret) {                                              \
			LOG_ERROR_BDF(type, ##__VA_ARGS__);                     \
		} else {                                                       \
			LOG_DEBUG_BDF(type, ##__VA_ARGS__);                     \
		}                                                              \
	} while (0)

struct sxe2_prot_entry {
	enum sxe2_protocol_filed_type type;
	u8 prot_id;
};

static struct sxe2_prot_entry sxe2_prot_id_tbl[SXE2_PROT_FIELD_LAST] = {
	{ SXE2_META_PKT_SRC, SXE2_META_HW },
	{ SXE2_META_PKT_DIRECTION, SXE2_META_HW },
	{ SXE2_META_VSI_NUM, SXE2_META_HW },
	{ SXE2_META_PKT_TO_RDMA, SXE2_META_HW },
	{ SXE2_OUTER_SMAC, SXE2_MAC_OL_HW },
	{ SXE2_OUTER_DMAC, SXE2_MAC_OL_HW },
	{ SXE2_INNER_SMAC, SXE2_MAC_IL_HW },
	{ SXE2_INNER_DMAC, SXE2_MAC_IL_HW },
	{ SXE2_OUTER_ETYPE, SXE2_ETYPE_OL_HW },
	{ SXE2_INNER_ETYPE, SXE2_ETYPE_IL_HW },
	{ SXE2_OUTER_VLAN_EX, SXE2_VLAN_EX_HW },
	{ SXE2_OUTER_VLAN, SXE2_VLAN_OL_HW },
	{ SXE2_OUTER_IPV4_SADDR, SXE2_IPV4_OL_HW },
	{ SXE2_OUTER_IPV4_DADDR, SXE2_IPV4_OL_HW },
	{ SXE2_OUTER_IPV4_TTL, SXE2_IPV4_OL_HW },
	{ SXE2_OUTER_IPV4_TOS, SXE2_IPV4_OL_HW },
	{ SXE2_OUTER_IPV4_PROT, SXE2_IPV4_OL_HW },
	{ SXE2_INNER_IPV4_SADDR, SXE2_IPV4_IL_HW },
	{ SXE2_INNER_IPV4_DADDR, SXE2_IPV4_IL_HW },
	{ SXE2_INNER_IPV4_TTL, SXE2_IPV4_IL_HW },
	{ SXE2_INNER_IPV4_TOS, SXE2_IPV4_IL_HW },
	{ SXE2_INNER_IPV4_PROT, SXE2_IPV4_IL_HW },
	{ SXE2_OUTER_IPV6_SADDR, SXE2_IPV6_OL_HW },
	{ SXE2_OUTER_IPV6_DADDR, SXE2_IPV6_OL_HW },
	{ SXE2_INNER_IPV6_SADDR, SXE2_IPV6_IL_HW },
	{ SXE2_INNER_IPV6_DADDR, SXE2_IPV6_IL_HW },
	{ SXE2_LAST_TCP_SPORT, SXE2_TCP_IL_HW },
	{ SXE2_LAST_TCP_DPORT, SXE2_TCP_IL_HW },
	{ SXE2_OUTER_UDP_SPORT, SXE2_UDP_OL_HW },
	{ SXE2_OUTER_UDP_DPORT, SXE2_UDP_OL_HW },
	{ SXE2_INNER_UDP_SPORT, SXE2_UDP_IL_HW },
	{ SXE2_INNER_UDP_DPORT, SXE2_UDP_IL_HW },
	{ SXE2_VXLAN_ENC_ID, SXE2_UDP_OL_HW },
	{ SXE2_GENEVE_ENC_ID, SXE2_UDP_OL_HW },
	{ SXE2_NVGRE_ENC_ID, SXE2_GRE_HW },
};

static u32 sxe2_tc_rule_hash_func(const void *data)
{
	u32 hash;
	struct sxe2_tcf_fltr *fltr = (struct sxe2_tcf_fltr *)data;

	hash = jhash(&fltr->tunnel_type, sizeof(fltr->tunnel_type), 0);
	hash = jhash(&fltr->src_type, sizeof(fltr->src_type), hash);
	hash = jhash(fltr->lkup_index, sizeof(fltr->lkup_index), hash);
	hash = jhash(fltr->lkup_value, sizeof(fltr->lkup_value), hash);
	hash = jhash(fltr->lkup_mask, sizeof(fltr->lkup_mask), hash);
	hash = jhash(fltr->profiles, sizeof(fltr->profiles), hash);

	return hash;
}

static s32 sxe2_tc_rule_hash_cmp(struct sxe2_tcf_fltr *fltr_save,
				 struct sxe2_tcf_fltr *fltr_to_find)
{
	if (fltr_save->tunnel_type != fltr_to_find->tunnel_type ||
	    fltr_save->src_type != fltr_to_find->src_type) {
		return 1;
	}

	if (memcmp(fltr_save->lkup_index, fltr_to_find->lkup_index,
		   sizeof(fltr_save->lkup_index))) {
		return 1;
	}

	if (memcmp(fltr_save->lkup_mask, fltr_to_find->lkup_mask,
		   sizeof(fltr_save->lkup_mask))) {
		return 1;
	}

	if (memcmp(fltr_save->lkup_value, fltr_to_find->lkup_value,
		   sizeof(fltr_save->lkup_value))) {
		return 1;
	}

	if (memcmp(fltr_save->profiles, fltr_to_find->profiles,
		   sizeof(fltr_save->profiles))) {
		return 1;
	}

	return 0;
}

struct sxe2_tc_rule_hash *sxe2_hash_cookie_find(struct sxe2_adapter *adapter,
						unsigned long cookie)
{
	u32 key;
	struct sxe2_tc_rule_hash *rule_hash_node;

	key = jhash(&cookie, sizeof(cookie), 0);
	LOG_INFO_BDF("cookie hash key is:%u\n", key);
	hash_for_each_possible(adapter->switch_ctxt.complex_recipe.ht_cookie,
			       rule_hash_node, node, key) {
		if (rule_hash_node->cookie == cookie)
			return rule_hash_node;
	}
	return NULL;
}

static void sxe2_hash_cookie_del(struct sxe2_adapter *adapter,
				 unsigned long cookie)
{
	u32 key;
	struct sxe2_tc_rule_hash *rule_hash_node;

	key = jhash(&cookie, sizeof(cookie), 0);
	LOG_INFO_BDF("cookie hash key is:%u\n", key);
	hash_for_each_possible(adapter->switch_ctxt.complex_recipe.ht_cookie,
			       rule_hash_node, node, key) {
		if (rule_hash_node->cookie == cookie) {
			hash_del(&rule_hash_node->node);
			kfree(rule_hash_node);
			break;
		}
	}
}

static s32 sxe2_hash_cookie_add(struct sxe2_adapter *adapter,
				unsigned long cookie, struct sxe2_rule_info *rule_info)
{
	u32 key;
	s32 ret = 0;
	struct sxe2_tc_rule_hash *rule_hash_node;

	if (sxe2_hash_cookie_find(adapter, cookie)) {
		LOG_ERROR_BDF("cookie has exist in hash table\n");
		ret = -EEXIST;
		goto l_end;
	}

	key = jhash(&cookie, sizeof(cookie), 0);
	LOG_INFO_BDF("cookie hash key is:%u\n", key);
	rule_hash_node = kzalloc(sizeof(*rule_hash_node), GFP_KERNEL);
	if (!rule_hash_node) {
		LOG_ERROR_BDF("alloc memory failed\n");
		ret = -ENOMEM;
		goto l_end;
	}
	rule_hash_node->cookie = cookie;
	rule_hash_node->rule_info = rule_info;
	hash_add(adapter->switch_ctxt.complex_recipe.ht_cookie,
		 &rule_hash_node->node, key);

l_end:
	return ret;
}

static void *sxe2_hash_lkup_find(struct sxe2_adapter *adapter,
				 struct sxe2_tcf_fltr *fltr)
{
	u32 key;
	struct sxe2_tcf_fltr *save_fltr;

	key = sxe2_tc_rule_hash_func(fltr);
	LOG_INFO_BDF("cookie hash key is:%u\n", key);
	hash_for_each_possible(adapter->switch_ctxt.complex_recipe.ht_lkup,
			       save_fltr, node, key) {
		if (!sxe2_tc_rule_hash_cmp(save_fltr, fltr))
			return save_fltr;
	}
	return NULL;
}

static void sxe2_hash_lkup_del(struct sxe2_adapter *adapter,
			       struct sxe2_tcf_fltr *fltr)
{
	u32 key;
	struct sxe2_tcf_fltr *save_fltr;

	key = sxe2_tc_rule_hash_func(fltr);
	LOG_INFO_BDF("cookie hash key is:%u\n", key);
	hash_for_each_possible(adapter->switch_ctxt.complex_recipe.ht_lkup,
			       save_fltr, node, key) {
		if (!sxe2_tc_rule_hash_cmp(save_fltr, fltr)) {
			hash_del(&save_fltr->node);
			break;
		}
	}
}

static s32 sxe2_hash_lkup_add(struct sxe2_adapter *adapter,
			      struct sxe2_tcf_fltr *fltr)
{
	u32 key;
	s32 ret = 0;

	if (sxe2_hash_lkup_find(adapter, fltr)) {
		LOG_ERROR_BDF("fltr has exist in hash table\n");
		ret = -EEXIST;
		return ret;
	}
	key = sxe2_tc_rule_hash_func(fltr);
	LOG_INFO_BDF("cookie hash key is:%u\n", key);
	hash_add(adapter->switch_ctxt.complex_recipe.ht_lkup,
		 &fltr->node, key);
	return ret;
}

STATIC s32 sxe2_fwc_switch_rules_cfg(struct sxe2_adapter *adapter, void *req,
				     void *resp, u32 req_len, u32 resp_len,
				     enum sxe2_drv_cmd_opcode opc)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };

	sxe2_cmd_params_dflt_fill(&cmd, opc, req, req_len, resp, resp_len);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("switch req cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

STATIC s32
sxe2_fwc_switch_recipe_get(struct sxe2_adapter *adapter,
			   struct sxe2_fwc_switch_recipe *switch_recipe,
			   enum sxe2_drv_cmd_opcode opc)
{
	s32 ret;
	struct sxe2_cmd_params cmd	   = { 0 };
	struct sxe2_fwc_switch_recipe resp = { 0 };

	sxe2_cmd_params_dflt_fill(&cmd, opc, switch_recipe,
				  sizeof(*switch_recipe), &resp, sizeof(resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("switch recipe get cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	memcpy(switch_recipe, &resp, sizeof(*switch_recipe));

	return ret;
}

STATIC s32 sxe2_fwc_switch_profile_recipe_map_get(struct sxe2_adapter *adapter,
						  struct sxe2_fwc_switch_profile_recipe_map *map,
						  enum sxe2_drv_cmd_opcode opc)
{
	s32 ret;
	struct sxe2_cmd_params cmd		       = { 0 };
	struct sxe2_fwc_switch_profile_recipe_map resp = { 0 };

	sxe2_cmd_params_dflt_fill(&cmd, opc, map,
				  sizeof(*map), &resp,
				  sizeof(resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("switch recipe get cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	memcpy(map->map, resp.map, sizeof(map->map));

	return ret;
}

STATIC s32 sxe2_fwc_vsi_list_cfg(struct sxe2_adapter *adapter,
				 struct sxe2_fwc_switch_vsi_list *vsi_list_fwc,
				 u32 size, enum sxe2_drv_cmd_opcode opc)
{
	s32 ret;
	struct sxe2_cmd_params cmd		  = { 0 };
	struct sxe2_fwc_switch_vsi_list_resp resp = { 0 };

	sxe2_cmd_params_dflt_fill(&cmd, opc, vsi_list_fwc, size, &resp,
				  sizeof(resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("vsi list cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	vsi_list_fwc->vsi_list_id = resp.index;

	return ret;
}

s32 sxe2_fwc_switch_large_action_cfg(struct sxe2_adapter *adapter,
				     struct sxe2_fwc_switch_large_action *lgactionparm,
				     enum sxe2_drv_cmd_opcode opc)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };

	sxe2_cmd_params_dflt_fill(&cmd, opc, lgactionparm,
				  sizeof(*lgactionparm), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("switch req cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

void sxe2_switch_context_deinit(struct sxe2_adapter *adapter)
{
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	s32 i;

	mutex_destroy(&switch_ctxt->mac_addr_lock);

	for (i = 0; i < SXE2_VSI_LIST_TYPE_MAX; i++)
		mutex_destroy(&switch_ctxt->vsi_list_mgmt[i].vsi_list_lock);

	for (i = 0; i < SXE2_DEFAULT_RECIPE_MAX; i++)
		mutex_destroy(&switch_ctxt->recipe[i].rule_lock);

	mutex_destroy(&switch_ctxt->complex_recipe.rule_lock);

	if (!switch_ctxt->profile_fv_item)
		return;

	for (i = 0; i < SXE2_MAX_NUM_PROFILES; i++) {
		kfree(switch_ctxt->profile_fv_item[i]);
		switch_ctxt->profile_fv_item[i] = NULL;
	}
	kfree(switch_ctxt->profile_fv_item);
	switch_ctxt->profile_fv_item = NULL;
}

s32 sxe2_switch_context_init(struct sxe2_adapter *adapter)
{
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	s32 i;

	for (i = 0; i < SXE2_VSI_LIST_TYPE_MAX; i++) {
		switch_ctxt->vsi_list_mgmt[i].type = (enum sxe2_vsi_list_type)i;
		INIT_LIST_HEAD(&switch_ctxt->vsi_list_mgmt[i].vsi_list_head);
		mutex_init(&switch_ctxt->vsi_list_mgmt[i].vsi_list_lock);
	}

	for (i = 0; i < SXE2_DEFAULT_RECIPE_MAX; i++) {
		switch_ctxt->recipe[i].recipe_id = (u16)i;
		INIT_LIST_HEAD(&switch_ctxt->recipe[i].rule_head);
		INIT_LIST_HEAD(&switch_ctxt->recipe[i].restore_head);
		mutex_init(&switch_ctxt->recipe[i].rule_lock);
		if (i == SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK)
			switch_ctxt->recipe[i].is_root = false;
		else
			switch_ctxt->recipe[i].is_root = true;
	}

	INIT_LIST_HEAD(&switch_ctxt->complex_recipe.rule_head);
	INIT_LIST_HEAD(&switch_ctxt->complex_recipe.restore_head);

	hash_init(switch_ctxt->complex_recipe.ht_cookie);
	hash_init(switch_ctxt->complex_recipe.ht_lkup);

	mutex_init(&switch_ctxt->complex_recipe.rule_lock);

	switch_ctxt->profile_fv_item = kcalloc(SXE2_MAX_NUM_PROFILES,
					       sizeof(struct sxe2_profile_fv_item *),
					       GFP_KERNEL);
	if (!switch_ctxt->profile_fv_item) {
		LOG_DEV_ERR("alloc fv item memory failed\n");
		goto l_end;
	}
	for (i = 0; i < SXE2_MAX_NUM_PROFILES; i++) {
		switch_ctxt->profile_fv_item[i] =
			kcalloc(SXE2_SWITCH_PROFILE_FV_CNT,
				sizeof(struct sxe2_profile_fv_item),
				GFP_KERNEL);
		if (!switch_ctxt->profile_fv_item[i]) {
			LOG_DEV_ERR("alloc fv item %u memory failed\n", i);
			goto l_end;
		}
	}

	switch_ctxt->evb_mode = BRIDGE_MODE_VEB;

	mutex_init(&switch_ctxt->evb_mode_lock);
	adapter->switch_ctxt.switch_id = adapter->pf_idx;

	mutex_init(&adapter->user_pf_ctxt.flag_lock);
	mutex_init(&switch_ctxt->mac_addr_lock);

	return 0;

l_end:
	sxe2_switch_context_deinit(adapter);

	return -ENOMEM;
}

static void sxe2_switch_sw_rule_free(struct sxe2_adapter *adapter,
				     struct sxe2_rule_info *rule)
{
	struct list_head *tc_rule_head;
	struct sxe2_tc_rule_info *tc_list_itr = NULL;
	struct sxe2_tc_rule_info *tc_list_tmp = NULL;

	if (rule->tcf_fltr) {
		tc_rule_head = &rule->tc_rule_head;
		list_for_each_entry_safe(tc_list_itr, tc_list_tmp,
					 tc_rule_head, list_entry) {
			list_del(&tc_list_itr->list_entry);
			sxe2_hash_cookie_del(adapter, tc_list_itr->cookie);
			kfree(tc_list_itr);
		}
		kfree(rule->tcf_fltr);
	}
	kfree(rule);
}

STATIC struct sxe2_vsi_list_info *
sxe2_vsi_list_entry_find(struct sxe2_adapter *adapter, u16 *vsi_array,
			 s32 vsi_cnt, enum sxe2_vsi_list_type type)
{
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct list_head *list_head;
	struct sxe2_vsi_list_info *list_itr = NULL;
	struct sxe2_vsi_list_info *ret	    = NULL;
	s32 i;

	list_head = &switch_ctxt->vsi_list_mgmt[type].vsi_list_head;
	list_for_each_entry(list_itr, list_head, list_entry) {
		if (bitmap_weight(list_itr->vsi_map, SXE2_VSI_MAX_CNT) ==
		    vsi_cnt) {
			ret = list_itr;
			for (i = 0; i < vsi_cnt; i++) {
				if (!test_bit(vsi_array[i],
					      list_itr->vsi_map)) {
					ret = NULL;
					break;
				}
			}
			if (ret) {
				LOG_DEBUG_BDF("find vsi list success, \t"
					      "vsi list id %u with vsi count %d\n",
					      ret->vsi_list_id,
					      bitmap_weight(ret->vsi_map, SXE2_VSI_MAX_CNT));
				break;
			}
		}
	}

	return ret;
}

STATIC struct sxe2_vsi_list_info *
sxe2_vsi_list_create(struct sxe2_adapter *adapter, u16 *vsi_array, u16 vsi_cnt,
		     enum sxe2_vsi_list_type type, s32 *status)
{
	s32 ret;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct sxe2_fwc_switch_vsi_list *vsi_list_fwc;
	struct sxe2_vsi_list_info *new_vsi_list = NULL;
	u32 vsi_size				= vsi_cnt * sizeof(*vsi_array);
	s32 i;

	vsi_list_fwc = kzalloc(sizeof(*vsi_list_fwc) + vsi_size, GFP_KERNEL);
	if (!vsi_list_fwc) {
		LOG_ERROR_BDF("alloc memory failed\n");
		ret = -ENOMEM;
		goto l_end;
	}

	new_vsi_list = kzalloc(sizeof(*new_vsi_list), GFP_KERNEL);
	if (!new_vsi_list) {
		LOG_ERROR_BDF("alloc memory failed\n");
		ret = -ENOMEM;
		goto l_end;
	}

	if (type == SXE2_VSI_LIST_TYPE_PRUNE)
		vsi_list_fwc->flag |=
			cpu_to_le16(SXE2_CMD_SWITCH_VSI_FLAG_LIST_PRUNE);

	vsi_list_fwc->vsi_cnt = cpu_to_le16(vsi_cnt);
	for (i = 0; i < vsi_cnt; i++)
		vsi_list_fwc->vsi[i] = cpu_to_le16(vsi_array[i]);

	ret = sxe2_fwc_vsi_list_cfg(adapter, vsi_list_fwc,
				    sizeof(*vsi_list_fwc) + vsi_size,
				    SXE2_CMD_SWITCH_VSI_LIST_ADD);
	if (ret) {
		LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
		kfree(new_vsi_list);
		new_vsi_list = NULL;
		goto l_end;
	}

	new_vsi_list->type	  = type;
	new_vsi_list->vsi_list_id = le16_to_cpu(vsi_list_fwc->vsi_list_id);
	new_vsi_list->rule_cnt	  = 0;
	new_vsi_list->need_bond	  = 0;
	for (i = 0; i < vsi_cnt; i++)
		set_bit(vsi_array[i], new_vsi_list->vsi_map);

	list_add(&new_vsi_list->list_entry,
		 &switch_ctxt->vsi_list_mgmt[type].vsi_list_head);

	LOG_DEBUG_BDF("create vsi list success,\t"
		      "vsi list id %u with vsi count %d\n",
		      new_vsi_list->vsi_list_id,
		      bitmap_weight(new_vsi_list->vsi_map, SXE2_VSI_MAX_CNT));

l_end:
	kfree(vsi_list_fwc);
	vsi_list_fwc = NULL;

	*status = ret;
	return new_vsi_list;
}

s32 sxe2_vsi_list_update_bond(struct sxe2_adapter *adapter,
			      struct sxe2_vsi_list_info *vsi_list,
			      struct sxe2_adapter *master_adapter, bool linking)
{
	s32 ret;
	struct sxe2_fwc_switch_vsi_list *vsi_list_fwc = NULL;
	u16 vsi_cnt				      = 1;
	u16 vsi_size = (u16)(vsi_cnt * sizeof(u16));

	vsi_list_fwc = kzalloc(sizeof(*vsi_list_fwc) + vsi_size, GFP_KERNEL);
	if (!vsi_list_fwc) {
		LOG_DEV_ERR("alloc memory failed\n");
		ret = -ENOMEM;
		goto l_end;
	}

	if (linking)
		vsi_list_fwc->flag |= SXE2_CMD_SWITCH_VSI_FLAG_LIST_INC;

	vsi_list_fwc->flag |= SXE2_CMD_SWITCH_VSI_FLAG_LIST_PRUNE;
	vsi_list_fwc->vsi_list_id = cpu_to_le16(vsi_list->vsi_list_id);
	vsi_list_fwc->vsi_cnt = cpu_to_le16(vsi_cnt);
	vsi_list_fwc->vsi[0] = cpu_to_le16(master_adapter->vsi_ctxt.main_vsi->idx_in_dev);

	ret = sxe2_fwc_vsi_list_cfg(adapter, vsi_list_fwc,
				    sizeof(*vsi_list_fwc) + vsi_size,
				    SXE2_CMD_SWITCH_VSI_LIST_UPDATE);
	if (ret) {
		LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
		goto l_end;
	}

l_end:
	kfree(vsi_list_fwc);
	return ret;
}

STATIC s32 sxe2_vsi_list_update(struct sxe2_adapter *adapter,
				struct sxe2_vsi_list_info *vsi_list,
				u16 *vsi_array, u16 vsi_cnt,
				enum sxe2_vsi_list_type type, bool is_increase)
{
	s32 ret;
	struct sxe2_fwc_switch_vsi_list *vsi_list_fwc;
	u32 vsi_size = vsi_cnt * sizeof(*vsi_array);
	u16 i;

	vsi_list_fwc = kzalloc(sizeof(*vsi_list_fwc) + vsi_size, GFP_KERNEL);
	if (!vsi_list_fwc) {
		LOG_ERROR_BDF("alloc memory failed\n");
		ret = -ENOMEM;
		goto l_end;
	}

	if (type == SXE2_VSI_LIST_TYPE_PRUNE)
		vsi_list_fwc->flag |=
			cpu_to_le16(SXE2_CMD_SWITCH_VSI_FLAG_LIST_PRUNE);
	if (is_increase)
		vsi_list_fwc->flag |=
			cpu_to_le16(SXE2_CMD_SWITCH_VSI_FLAG_LIST_INC);

	vsi_list_fwc->vsi_list_id = cpu_to_le16(vsi_list->vsi_list_id);
	vsi_list_fwc->vsi_cnt	  = cpu_to_le16(vsi_cnt);

	for (i = 0; i < vsi_cnt; i++)
		vsi_list_fwc->vsi[i] = cpu_to_le16(vsi_array[i]);

	ret = sxe2_fwc_vsi_list_cfg(adapter, vsi_list_fwc,
				    sizeof(*vsi_list_fwc) + vsi_size,
				    SXE2_CMD_SWITCH_VSI_LIST_UPDATE);
	if (ret) {
		LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
		goto l_end;
	}

	for (i = 0; i < vsi_cnt; i++) {
		if (is_increase)
			set_bit(vsi_array[i], vsi_list->vsi_map);
		else
			clear_bit(vsi_array[i], vsi_list->vsi_map);
	}

l_end:
	kfree(vsi_list_fwc);
	vsi_list_fwc = NULL;
	return ret;
}

STATIC s32 sxe2_vsi_list_remove(struct sxe2_adapter *adapter,
				struct sxe2_vsi_list_info *vsi_list)
{
	s32 ret;
	struct sxe2_fwc_switch_vsi_list vsi_list_fwc = { 0 };

	if (vsi_list->type == SXE2_VSI_LIST_TYPE_PRUNE)
		vsi_list_fwc.flag |=
			cpu_to_le16(SXE2_CMD_SWITCH_VSI_FLAG_LIST_PRUNE);

	vsi_list_fwc.vsi_list_id = cpu_to_le16(vsi_list->vsi_list_id);

	ret = sxe2_fwc_vsi_list_cfg(adapter, &vsi_list_fwc,
				    sizeof(vsi_list_fwc),
				    SXE2_CMD_SWITCH_VSI_LIST_DEL);
	if (ret) {
		LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
		goto l_end;
	}

	list_del(&vsi_list->list_entry);

	LOG_DEBUG_BDF("free vsi list success, vsi list id %u\n",
		      vsi_list->vsi_list_id);

	kfree(vsi_list);

l_end:
	return ret;
}

STATIC void sxe2_vsi_list_refcnt_update(struct sxe2_adapter *adapter,
					struct sxe2_vsi_list_info *vsi_list,
					bool is_increase)
{
	if (is_increase) {
		vsi_list->rule_cnt++;
	} else {
		if (vsi_list->rule_cnt)
			vsi_list->rule_cnt--;
#ifdef SXE2_CFG_DEBUG
		else
			LOG_ERROR("vsi list %d is zero before decrease\n",
				  vsi_list->vsi_list_id);
#endif
		if (vsi_list->rule_cnt == 0)
			(void)sxe2_vsi_list_remove(adapter, vsi_list);
	}
}

STATIC struct sxe2_rule_info *
sxe2_rule_entry_find(struct sxe2_adapter *adapter,
		     struct sxe2_rule_info *rule_info)
{
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct list_head *list_head;
	struct sxe2_rule_info *list_itr = NULL;
	struct sxe2_rule_info *ret	= NULL;
	struct sxe2_tcf_fltr *tcf_fltr;

	if (!rule_info->tcf_fltr) {
		list_head =
			&switch_ctxt->recipe[rule_info->recipe_id].rule_head;
		list_for_each_entry(list_itr, list_head, list_entry) {
			if (!memcmp(&rule_info->fltr.data, &list_itr->fltr.data,
				    sizeof(rule_info->fltr.data)) &&
			    rule_info->fltr.src_type ==
				    list_itr->fltr.src_type) {
				ret = list_itr;
				break;
			}
		}
	} else {
		tcf_fltr = (struct sxe2_tcf_fltr *)sxe2_hash_lkup_find(adapter,
				rule_info->tcf_fltr);
		if (tcf_fltr)
			ret = tcf_fltr->rule_info;
	}

	if (ret)
		LOG_DEBUG_BDF("find rule success, rule id %u\n", ret->rule_id);

	return ret;
}

STATIC void sxe2_make_switch_full_key(struct sxe2_adapter *adapter,
				      struct sxe2_rule_info *rule,
				      u32 *full_key)
{
	struct sxe2_rule_filter *rule_filter = &rule->fltr;
	union sxe2_switch_full_key_dw0 full_key_d0;
	union sxe2_switch_full_key_dw1 full_key_d1;
	union sxe2_switch_full_key_dw2 full_key_d2;
	u8 *mac_addr;

	memset(&full_key_d0, 0, sizeof(full_key_d0));
	memset(&full_key_d1, 0, sizeof(full_key_d1));
	memset(&full_key_d2, 0, sizeof(full_key_d2));

	full_key_d0.field.rid = rule->recipe_id;
	if (adapter->switch_ctxt.recipe[rule->recipe_id].is_root)
		full_key_d0.field.is_root = 1;

	full_key_d0.field.fv0 = adapter->switch_ctxt.switch_id;

	if (rule->recipe_id == SXE2_DEFAULT_RECIPE_MAC) {
		mac_addr = rule_filter->data.mac.mac_addr;
		full_key_d1.field.fv1 =
			(u32)((mac_addr[0] << (u32)8) | mac_addr[1]);
		full_key_d1.field.fv2 =
			(u32)((mac_addr[2] << (u32)8) | mac_addr[3]);
		full_key_d2.field.fv3 =
			(u32)((mac_addr[4] << (u32)8) | mac_addr[5]);
	} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_VLAN) {
		full_key_d1.field.fv1 = rule_filter->data.vlan.tpid;
		full_key_d1.field.fv2 = rule_filter->data.vlan.vlan_id;
	} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_TX_ETYPE) {
		full_key_d1.field.fv1 |=
			(rule_filter->data.etype.vsi_id << SXE2_FV_VSI_NUM_OFFSET);
		full_key_d1.field.fv2 |=
			(SXE2_FV_DIRECTION_TX << SXE2_FV_DIRECTION_OFFSET);
		full_key_d2.field.fv3 = rule_filter->data.etype.ethertype;
	} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_RX_ETYPE) {
		full_key_d1.field.fv1 |=
			(SXE2_FV_DIRECTION_RX << SXE2_FV_DIRECTION_OFFSET);
		full_key_d1.field.fv2 = rule_filter->data.etype.ethertype;
	} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_ALLMULTI) {
		full_key_d1.field.fv1 |=
			(SXE2_FV_CAST_MULTI << SXE2_FV_CAST_OFFSET);
	} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_PROMISC) {
		if (rule_filter->src_type == SXE2_SRC_TYPE_TX)
			full_key_d1.field.fv1 |= (SXE2_FV_DIRECTION_TX
						  << SXE2_FV_DIRECTION_OFFSET);
		else
			full_key_d1.field.fv1 |= (SXE2_FV_DIRECTION_RX
						  << SXE2_FV_DIRECTION_OFFSET);
	} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_SRCVSI) {
		full_key_d1.field.fv1 |=
			(rule_filter->data.srcvsi.vsi_id << SXE2_FV_VSI_NUM_OFFSET);
		full_key_d1.field.fv2 |= (rule_filter->data.srcvsi.to_rdma
					  << SXE2_FV_PKT_TO_RDMA_OFFSET);
		full_key_d2.field.fv3 |=
			(rule_filter->data.srcvsi.packet_src_type
			 << SXE2_FV_PKT_SRC_OFFSET);
	} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_SRCVSI_EXT) {
		full_key_d1.field.fv1 |=
			(rule_filter->data.srcvsi.vsi_id << SXE2_FV_VSI_NUM_OFFSET);
		full_key_d1.field.fv2 |= (rule_filter->data.srcvsi.to_rdma
					  << SXE2_FV_PKT_TO_RDMA_OFFSET);
		full_key_d2.field.fv3 |=
			(rule_filter->data.srcvsi.packet_src_type
			 << SXE2_FV_PKT_SRC_OFFSET);
	} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK) {
		full_key_d1.field.fv1 |=
			(rule_filter->data.mac_spoofchk.vsi_id << SXE2_FV_VSI_NUM_OFFSET);
		full_key_d1.field.fv2 =
			(SXE2_FV_DIRECTION_TX << SXE2_FV_DIRECTION_OFFSET);
	} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK_EXT) {
		mac_addr = rule_filter->data.mac_spoofchk_ext.mac_addr;
		full_key_d1.field.fv1 =
			(u32)((mac_addr[0] << (u32)8) | mac_addr[1]);
		full_key_d1.field.fv2 =
			(u32)((mac_addr[2] << (u32)8) | mac_addr[3]);
		full_key_d2.field.fv3 =
			(u32)((mac_addr[4] << (u32)8) | mac_addr[5]);
		full_key_d2.field.fv4 = rule_filter->data.mac_spoofchk_ext.hid;
	}

	full_key[0] = cpu_to_le32(full_key_d0.val);
	full_key[1] = cpu_to_le32(full_key_d1.val);
	full_key[2] = cpu_to_le32(full_key_d2.val);
}

STATIC void sxe2_make_switch_action(struct sxe2_adapter *adapter,
				    struct sxe2_rule_info *rule_info,
				    u32 *action)
{
	u32 act = 0;

	switch (rule_info->act.type) {
	case SXE2_FWD_TO_VSI:
		if (rule_info->recipe_id != SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK) {
			act |= ((rule_info->act.fwd_id.vsi_id) << SXE2_SINGLE_ACT_VSI_ID_S) &
			       SXE2_SINGLE_ACT_VSI_ID_M;
			act |= SXE2_SINGLE_ACT_VSI_FORWARD | SXE2_SINGLE_ACT_VALID_BIT;
		}
		break;
	case SXE2_FWD_TO_VSI_LIST:
		act |= SXE2_SINGLE_ACT_VSI_LIST;
		act |= (rule_info->act.fwd_id.vsi_list_id
			<< SXE2_SINGLE_ACT_VSI_LIST_ID_S) &
		       SXE2_SINGLE_ACT_VSI_LIST_ID_M;
		if (rule_info->recipe_id == SXE2_DEFAULT_RECIPE_VLAN)
			act |= SXE2_SINGLE_ACT_PRUNE | SXE2_SINGLE_ACT_EGRESS |
			       SXE2_SINGLE_ACT_INGRESS;
		else
			act |= SXE2_SINGLE_ACT_VSI_FORWARD |
			       SXE2_SINGLE_ACT_VALID_BIT;
		break;
	case SXE2_FWD_TO_Q:
		act |= SXE2_SINGLE_ACT_TO_Q;
		act |= (rule_info->act.fwd_id.q_id
			<< SXE2_SINGLE_ACT_Q_INDEX_S) &
		       SXE2_SINGLE_ACT_Q_INDEX_M;
		act |= SXE2_SINGLE_ACT_Q_PRIORITY &
				rule_info->act.q_high;
		break;
	case SXE2_FWD_TO_QGRP:
		act |= SXE2_SINGLE_ACT_TO_Q;
		act |= (rule_info->act.fwd_id.q_id
			<< SXE2_SINGLE_ACT_Q_INDEX_S) &
		       SXE2_SINGLE_ACT_Q_INDEX_M;
		act |= (rule_info->act.qgrp_size
			<< SXE2_SINGLE_ACT_Q_REGION_S) &
		       SXE2_SINGLE_ACT_Q_REGION_M;
		act |= SXE2_SINGLE_ACT_Q_PRIORITY &
				rule_info->act.q_high;
		break;
	case SXE2_DROP_PACKET:
		act |= SXE2_SINGLE_ACT_VSI_FORWARD | SXE2_SINGLE_ACT_DROP |
		       SXE2_SINGLE_ACT_VALID_BIT;
		break;
	case SXE2_MIRROR_PACKET:
		act |= SXE2_SINGLE_ACT_MIRROR;
		act |= (rule_info->act.fwd_id.vsi_id << SXE2_SINGLE_ACT_VSI_ID_S) &
		       SXE2_SINGLE_ACT_VSI_ID_M;
		break;
	case SXE2_LARGE_ACTION:
		act |= SXE2_SINGLE_ACT_POINTER | SXE2_SINGLE_ACT_TO_LARGE |
		       SXE2_SINGLE_ACT_HASFWD;
		break;

	default:
		goto l_end;
	}

	if (rule_info->act.lb_en)
		act |= SXE2_SINGLE_ACT_LB_ENABLE;
	if (rule_info->act.lan_en)
		act |= SXE2_SINGLE_ACT_LAN_ENABLE;

l_end:
	*action = act;
}

STATIC void sxe2_switch_rule_fill(struct sxe2_adapter *adapter,
				  struct sxe2_rule_info *rule_info,
				  struct sxe2_fwc_switch_rule *rule_fwc,
				  bool is_del)
{
	u32 act = 0;

	if (!is_del)
		sxe2_make_switch_action(adapter, rule_info, &act);

	rule_fwc->recipe_id = cpu_to_le16(rule_info->recipe_id);
	rule_fwc->act	    = cpu_to_le32(act);
	rule_fwc->rule_id   = cpu_to_le16(rule_info->rule_id);

	sxe2_make_switch_full_key(adapter, rule_info, rule_fwc->full_key);

	LOG_DEBUG_BDF("rule_fwc, recipe id %d, act %x, full_key %08x:%08x:%08x\n",
		      le16_to_cpu(rule_fwc->recipe_id),
		      le32_to_cpu(rule_fwc->act),
		      le32_to_cpu(rule_fwc->full_key[0]),
		      le32_to_cpu(rule_fwc->full_key[1]),
		      le32_to_cpu(rule_fwc->full_key[2]));
}

STATIC void sxe2_switch_complex_rule_fill(struct sxe2_adapter *adapter,
					  struct sxe2_rule_info *rule_info,
					  struct sxe2_fwc_switch_complex_rule *rule_fwc,
					  bool is_del)
{
	u32 act = 0;
	u16 i, profile_id, profile_cnt;
	struct sxe2_tcf_fltr *fltr = rule_info->tcf_fltr;
	union sxe2_switch_full_key_dw0 full_key_d0;
	union sxe2_switch_full_key_dw1 full_key_d1;
	union sxe2_switch_full_key_dw2 full_key_d2;

	if (!is_del)
		sxe2_make_switch_action(adapter, rule_info, &act);

	rule_fwc->act = cpu_to_le32(act);

	profile_cnt = 0;
	profile_id  = 0;
	while (true) {
		profile_id = (u16)find_next_bit(fltr->profiles,
						SXE2_MAX_NUM_PROFILES,
						profile_id);
		if (profile_id >= SXE2_MAX_NUM_PROFILES)
			break;
		rule_fwc->profile_id[profile_cnt++] = cpu_to_le16(profile_id);
		profile_id++;
	}

	rule_fwc->profile_cnt = cpu_to_le16(profile_cnt);
	rule_fwc->rule_root   = cpu_to_le16(rule_info->rule_id);
	rule_fwc->word_cnt    = cpu_to_le16(fltr->word_cnt);
	rule_fwc->recipe_root = cpu_to_le16(rule_info->recipe_id);
	rule_fwc->recipe_cnt  = cpu_to_le16(fltr->recipe_cnt);
	rule_fwc->priority    = fltr->priority;

	for (i = 0; i < fltr->word_cnt; i++) {
		rule_fwc->lkup_mask[i] =
			cpu_to_le16(be16_to_cpu(fltr->lkup_mask[i]));
		rule_fwc->lkup_value[i] =
			cpu_to_le16(be16_to_cpu(fltr->lkup_value[i]));
		rule_fwc->lkup_index[i] = cpu_to_le16(fltr->lkup_index[i]);
	}

	for (i = 0; i < SXE2_MAX_CHAIN_WORDS; i++) {
		if ((i % SXE2_NUM_WORDS_RECIPE) == 0 &&
		    fltr->lkup_mask[i] != 0 && i + 3 < SXE2_MAX_CHAIN_WORDS) {
			full_key_d0.val	      = 0;
			full_key_d1.val	      = 0;
			full_key_d2.val	      = 0;
			full_key_d0.field.fv0 = rule_fwc->lkup_value[i];
			if (rule_fwc->lkup_mask[i + 1])
				full_key_d1.field.fv1 =
					rule_fwc->lkup_value[i + 1];
			if (rule_fwc->lkup_mask[i + 2])
				full_key_d1.field.fv2 =
					rule_fwc->lkup_value[i + 2];
			if (rule_fwc->lkup_mask[i + 3])
				full_key_d2.field.fv3 =
					rule_fwc->lkup_value[i + 3];
			LOG_DEBUG_BDF("full_key %08x:%08x:%08x\n",
				      cpu_to_le32(full_key_d0.val),
				      cpu_to_le32(full_key_d1.val),
				      cpu_to_le32(full_key_d2.val));
		}
	}

	for (i = 0; i < fltr->recipe_cnt; i++) {
		rule_fwc->rule_id[i]   = cpu_to_le16(fltr->rule_id[i]);
		rule_fwc->recipe_id[i] = cpu_to_le16(fltr->recipe_id[i]);
	}

	LOG_DEBUG_BDF("rule_fwc, profile cnt %d, recipe cnt %d, act %x\n",
		      le16_to_cpu(rule_fwc->profile_cnt),
		      le16_to_cpu(rule_fwc->recipe_cnt),
		      le32_to_cpu(rule_fwc->act));
}

STATIC struct sxe2_rule_info *
sxe2_fwd_rule_create(struct sxe2_adapter *adapter,
		     struct sxe2_rule_info *rule_info, s32 *status)
{
	s32 ret;
	struct sxe2_switch_context *switch_ctxt	   = &adapter->switch_ctxt;
	struct sxe2_rule_info *new_rule		   = NULL;
	struct sxe2_fwc_switch_rule rule_req	   = { 0 };
	struct sxe2_fwc_switch_rule_resp rule_resp = { 0 };
	struct sxe2_fwc_switch_complex_rule *cpx_rule_req = NULL;

	struct sxe2_fwc_switch_complex_rule_resp cpx_rule_resp = { 0 };
	u16 i;
	struct sxe2_tcf_fltr *new_fltr = NULL;

	cpx_rule_req = kzalloc(sizeof(*cpx_rule_req), GFP_KERNEL);
	if (!cpx_rule_req) {
		LOG_ERROR_BDF("alloc memory failed\n");
		ret = -ENOMEM;
		goto l_end;
	}

	new_rule = kzalloc(sizeof(*new_rule), GFP_KERNEL);
	if (!new_rule) {
		LOG_ERROR_BDF("alloc memory failed\n");
		ret = -ENOMEM;
		goto l_end;
	}

	if (rule_info->tcf_fltr) {
		new_fltr = kzalloc(sizeof(*new_fltr), GFP_KERNEL);
		if (!new_fltr) {
			LOG_ERROR_BDF("alloc memory failed\n");
			ret = -ENOMEM;
			goto l_end;
		}
		memcpy(new_fltr, rule_info->tcf_fltr, sizeof(*new_fltr));
	}

	if (!new_fltr) {
		sxe2_switch_rule_fill(adapter, rule_info, &rule_req, false);
#ifdef SXE2_CFG_DEBUG
		if (l2_force_fkot)
			rule_req.add_fkot = true;
#endif
		ret = sxe2_fwc_switch_rules_cfg(adapter, &rule_req, &rule_resp,
						sizeof(rule_req),
						sizeof(rule_resp),
						SXE2_CMD_SWITCH_RULE_ADD);
		if (ret) {
			LOG_ERROR_BDF("request to admin q failed, ret %d\n",
				      ret);
			goto l_end;
		}
		rule_info->rule_id = le16_to_cpu(rule_resp.index);
		rule_info->hid = (u16)(rule_resp.resv1[0] + (((u16)rule_resp.resv1[1]) << 8));
	} else {
#ifdef SXE2_CFG_DEBUG
		if (tc_force_fkot)
			cpx_rule_req->add_fkot = true;
#endif
		sxe2_switch_complex_rule_fill(adapter, rule_info, cpx_rule_req,
					      false);
		ret = sxe2_fwc_switch_rules_cfg(adapter, cpx_rule_req,
						&cpx_rule_resp,
						sizeof(*cpx_rule_req),
						sizeof(cpx_rule_resp),
						SXE2_CMD_SWITCH_RULE_CPX_ADD);
		if (ret) {
			LOG_ERROR_BDF("request to admin q failed, ret %d\n",
				      ret);
			goto l_end;
		}
		rule_info->recipe_id = le16_to_cpu(cpx_rule_resp.recipe_root);
		rule_info->rule_id   = le16_to_cpu(cpx_rule_resp.rule_root);
		new_fltr->recipe_cnt = le16_to_cpu(cpx_rule_resp.recipe_cnt);
		for (i = 0; i < new_fltr->recipe_cnt; i++) {
			new_fltr->rule_id[i] =
				le16_to_cpu(cpx_rule_resp.rule_id[i]);
			new_fltr->recipe_id[i] =
				le16_to_cpu(cpx_rule_resp.recipe_id[i]);
		}
	}

	memcpy(new_rule, rule_info, sizeof(*new_rule));
	new_rule->tcf_fltr = new_fltr;

	if (new_rule->vsi_list)
		sxe2_vsi_list_refcnt_update(adapter, new_rule->vsi_list, true);

	if (!new_rule->tcf_fltr) {
		list_add(&new_rule->list_entry,
			 &switch_ctxt->recipe[new_rule->recipe_id].rule_head);
	} else {
		new_fltr->rule_info = new_rule;
		INIT_LIST_HEAD(&new_rule->tc_rule_head);
		if (!new_rule->tcf_fltr->cookie_invalid) {
			ret = sxe2_hash_cookie_add(adapter, new_rule->tcf_fltr->cookie,
						   new_rule);
			if (ret) {
				LOG_ERROR_BDF("hash cookie add failed, ret %d\n", ret);
				goto l_end;
			}
		}

		ret = sxe2_hash_lkup_add(adapter, new_rule->tcf_fltr);
		if (ret) {
			LOG_ERROR_BDF("hash lkup add failed, ret %d\n", ret);
			goto l_end;
		}
	}

	LOG_DEBUG_BDF("create rule success, rule id %u\n", new_rule->rule_id);

l_end:
	*status = ret;
	if (ret) {
		kfree(new_fltr);
		kfree(new_rule);
		new_rule = NULL;
	}

	kfree(cpx_rule_req);

	return new_rule;
}

s32 sxe2_fwd_rule_update(struct sxe2_adapter *adapter,
			 struct sxe2_rule_info *rule_info)
{
	s32 ret;
	struct sxe2_fwc_switch_rule rule_fwc	   = { 0 };
	struct sxe2_fwc_switch_rule_resp rule_resp = { 0 };
	struct sxe2_fwc_switch_complex_rule *cpx_rule_req      = NULL;
	struct sxe2_fwc_switch_complex_rule_resp cpx_rule_resp = { 0 };

	cpx_rule_req = kzalloc(sizeof(*cpx_rule_req), GFP_KERNEL);
	if (!cpx_rule_req) {
		LOG_ERROR_BDF("alloc memory failed\n");
		ret = -ENOMEM;
		goto l_end;
	}

	if (!rule_info->tcf_fltr) {
		sxe2_switch_rule_fill(adapter, rule_info, &rule_fwc, false);

		ret = sxe2_fwc_switch_rules_cfg(adapter, &rule_fwc, &rule_resp,
						sizeof(rule_fwc),
						sizeof(rule_resp),
						SXE2_CMD_SWITCH_RULE_UPDATE);
		if (ret)
			LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
	} else {
		sxe2_switch_complex_rule_fill(adapter, rule_info, cpx_rule_req,
					      false);
		ret = sxe2_fwc_switch_rules_cfg(adapter, cpx_rule_req, &cpx_rule_resp,
						sizeof(*cpx_rule_req), sizeof(cpx_rule_resp),
						SXE2_CMD_SWITCH_RULE_CPX_UPDATE);
		if (ret)
			LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
	}
	kfree(cpx_rule_req);
l_end:
	return ret;
}

STATIC s32 sxe2_rule_fwd_id_update(struct sxe2_adapter *adapter,
				   struct sxe2_rule_info *rule_info,
				   struct sxe2_rule_info *save_rule)
{
	s32 ret = -EINVAL;
	struct sxe2_rule_info new_rule;

	memcpy(&new_rule, save_rule, sizeof(new_rule));

	if (rule_info->vsi_list && !save_rule->vsi_list) {
		new_rule.vsi_list = rule_info->vsi_list;
		new_rule.act.fwd_id.vsi_list_id =
			rule_info->vsi_list->vsi_list_id;

		new_rule.act.type = SXE2_FWD_TO_VSI_LIST;

	} else if (!rule_info->vsi_list && save_rule->vsi_list) {
		new_rule.vsi_list	   = NULL;
		new_rule.act.fwd_id.vsi_id = rule_info->act.fwd_id.vsi_id;

		new_rule.act.type = SXE2_FWD_TO_VSI;

	} else if (rule_info->vsi_list && save_rule->vsi_list) {
		new_rule.vsi_list = rule_info->vsi_list;
		new_rule.act.fwd_id.vsi_list_id =
			rule_info->vsi_list->vsi_list_id;

	} else {
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2_fwd_rule_update(adapter, &new_rule);
	if (ret) {
		LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
		goto l_end;
	}

	if (save_rule->vsi_list)
		sxe2_vsi_list_refcnt_update(adapter, save_rule->vsi_list, false);

	memcpy(save_rule, &new_rule, sizeof(*save_rule));

	if (save_rule->vsi_list)
		sxe2_vsi_list_refcnt_update(adapter, save_rule->vsi_list, true);

	LOG_DEBUG_BDF("update rule success, rule id %u\n", save_rule->rule_id);

l_end:
	return ret;
}

s32 sxe2_fwd_rule_remove(struct sxe2_adapter *adapter,
			 struct sxe2_rule_info *rule_info, bool free_sw)
{
	s32 ret						  = 0;
	struct sxe2_fwc_switch_rule rule_fwc		  = { 0 };
	struct sxe2_fwc_switch_rule_resp rule_resp	  = { 0 };
	struct sxe2_fwc_switch_complex_rule *cpx_rule_req = NULL;
	struct sxe2_fwc_switch_complex_rule_resp cpx_rule_resp = { 0 };

	cpx_rule_req = kzalloc(sizeof(*cpx_rule_req), GFP_KERNEL);
	if (!cpx_rule_req) {
		LOG_ERROR_BDF("alloc memory failed\n");
		ret = -ENOMEM;
		goto l_end;
	}

	if (!rule_info->tcf_fltr) {
		sxe2_switch_rule_fill(adapter, rule_info, &rule_fwc, true);

		ret = sxe2_fwc_switch_rules_cfg(adapter, &rule_fwc, &rule_resp,
						sizeof(rule_fwc),
						sizeof(rule_resp),
						SXE2_CMD_SWITCH_RULE_DEL);
		if (ret) {
			LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
			goto l_end;
		}
	} else {
		sxe2_switch_complex_rule_fill(adapter, rule_info, cpx_rule_req,
					      true);
		ret = sxe2_fwc_switch_rules_cfg(adapter, cpx_rule_req,
						&cpx_rule_resp,
						sizeof(*cpx_rule_req),
						sizeof(cpx_rule_resp),
						SXE2_CMD_SWITCH_RULE_CPX_DEL);
		if (ret) {
			LOG_ERROR_BDF("request to admin q failed, ret %d\n",
				      ret);
			goto l_end;
		}
	}

	if (rule_info->tcf_fltr) {
		if (!rule_info->tcf_fltr->cookie_invalid)
			sxe2_hash_cookie_del(adapter, rule_info->tcf_fltr->cookie);
		sxe2_hash_lkup_del(adapter, rule_info->tcf_fltr);
	} else {
		list_del(&rule_info->list_entry);
	}

	LOG_DEBUG_BDF("remove rule success, rule id %u\n", rule_info->rule_id);

	if (free_sw)
		sxe2_switch_sw_rule_free(adapter, rule_info);

l_end:
	kfree(cpx_rule_req);
	return ret;
}

STATIC s32 sxe2_switch_tc_rule_info_add(struct sxe2_rule_info *rule_info,
					struct sxe2_rule_info *save_rule)
{
	struct sxe2_tc_rule_info *list_itr     = NULL;
	struct sxe2_tc_rule_info *tc_rule_info = NULL;
	struct list_head *prev;
	u32 cnt = 0;

	tc_rule_info = kzalloc(sizeof(*tc_rule_info), GFP_KERNEL);
	if (!tc_rule_info)
		return -ENOMEM;

	SWITCH_TC_RULE_ACT_INFO_GET_FROM_RULE(tc_rule_info, rule_info);

	list_for_each_entry(list_itr, &save_rule->tc_rule_head, list_entry) {
		if (rule_info->tcf_fltr->prio == list_itr->prio) {
			kfree(tc_rule_info);
			return -EEXIST;
		} else if (rule_info->tcf_fltr->prio < list_itr->prio) {
			if (cnt == 0) {
				list_add(&tc_rule_info->list_entry,
					 &save_rule->tc_rule_head);
			} else {
				prev	   = list_itr->list_entry.prev;
				prev->next = &tc_rule_info->list_entry;
				tc_rule_info->list_entry.prev = prev;
				tc_rule_info->list_entry.next =
					&list_itr->list_entry;
				list_itr->list_entry.prev =
					&tc_rule_info->list_entry;
			}
			return 0;
		}
		cnt++;
	}
	list_add_tail(&tc_rule_info->list_entry, &save_rule->tc_rule_head);

	return 0;
}

STATIC s32 sxe2_switchdev_tc_samerule_add(struct sxe2_adapter *adapter,
					  struct sxe2_rule_info *rule_info,
					  struct sxe2_rule_info *save_rule)
{
	struct sxe2_tc_rule_info temp_rule_info;
	s32 ret = 0;
	unsigned long new_cookie;

	if (rule_info->tcf_fltr->cookie_invalid || save_rule->tcf_fltr->cookie_invalid) {
		LOG_ERROR_BDF("same rule add failed, cookie is invalid.\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (rule_info->tcf_fltr->prio == save_rule->tcf_fltr->prio) {
		LOG_ERROR_BDF("the prio is same\n");
		ret = -EEXIST;
		goto l_end;
	}

	new_cookie = rule_info->tcf_fltr->cookie;
	memset(&temp_rule_info, 0, sizeof(temp_rule_info));

	if (rule_info->tcf_fltr->prio < save_rule->tcf_fltr->prio) {
		SWITCH_TC_RULE_ACT_INFO_GET_FROM_RULE(&temp_rule_info, save_rule);

		SWITCH_RULE_ACT_INFO_CPY(save_rule, rule_info);

		ret = sxe2_fwd_rule_update(adapter, save_rule);
		if (ret) {
			LOG_ERROR_BDF("request to admin q failed, ret %d\n",
				      ret);
			SWITCH_TC_RULE_ACT_INFO_SET_TO_RULE(save_rule,
							    &temp_rule_info);
			goto l_end;
		}

		SWITCH_TC_RULE_ACT_INFO_SET_TO_RULE(rule_info, &temp_rule_info);
	}
	ret = sxe2_hash_cookie_add(adapter, new_cookie, save_rule);
	if (ret) {
		LOG_ERROR_BDF("hash cookie add failed, cookie:%lu, ret:%d\n", new_cookie, ret);
		goto l_end;
	}

	ret = sxe2_switch_tc_rule_info_add(rule_info, save_rule);
	if (ret)
		LOG_ERROR_BDF("tc_rule_info add failed, ret:%d\n", ret);

l_end:
	return ret;
}

STATIC struct sxe2_vsi_list_info *
sxe2_cpx_rule_vsi_list_create(struct sxe2_adapter *adapter,
			      struct sxe2_tcf_fltr *fltr, s32 *status)
{
	struct sxe2_vsi_list_info *vsi_list = NULL;
	u16 *vsi_id;
	u16 idx = 0;
	u16 i, vsi_cnt;

	vsi_cnt = bitmap_weight(fltr->dst_vsi_map, SXE2_VSI_MAX_CNT);
	vsi_id = kcalloc(vsi_cnt, sizeof(*vsi_id), GFP_KERNEL);
	if (!vsi_id) {
		LOG_ERROR_BDF("alloc memory failed\n");
		*status = -ENOMEM;
		goto l_end;
	}

	for (i = 0; i < vsi_cnt; i++) {
		idx = (u16)find_next_bit((unsigned long *)fltr->dst_vsi_map,
					 SXE2_VSI_MAX_CNT, idx);
		if (idx >= SXE2_VSI_MAX_CNT)
			break;
		vsi_id[i] = idx;
		idx++;
	}

	vsi_list = sxe2_vsi_list_create(adapter, vsi_id,
					vsi_cnt, SXE2_VSI_LIST_TYPE_FORWARD,
					status);
	kfree(vsi_id);
l_end:
	return vsi_list;
}

STATIC s32 sxe2_switchdev_user_samerule_add(struct sxe2_adapter *adapter,
					    struct sxe2_rule_info *rule_info,
					    struct sxe2_rule_info *save_rule)
{
	struct sxe2_tc_rule_info temp_rule_info;
	s32 ret = 0;
	bool new_vsi_list = false;
	struct sxe2_tc_rule_info *list_itr = NULL;

	if (rule_info->tcf_fltr->prio == save_rule->tcf_fltr->prio) {
		LOG_ERROR_BDF("the prio is same\n");
		ret = -EEXIST;
		goto l_end;
	}

	list_for_each_entry(list_itr, &save_rule->tc_rule_head, list_entry) {
		if (rule_info->tcf_fltr->prio == list_itr->prio) {
			LOG_ERROR_BDF("the prio is same\n");
			ret = -EEXIST;
			goto l_end;
		}
	}

	if (rule_info->act.type == SXE2_FWD_TO_VSI_LIST) {
		struct sxe2_vsi_list_info *vsi_list;

		vsi_list = sxe2_cpx_rule_vsi_list_create(adapter, rule_info->tcf_fltr, &ret);
		if (!vsi_list)
			goto l_end;

		rule_info->vsi_list = vsi_list;
		rule_info->act.fwd_id.vsi_list_id = vsi_list->vsi_list_id;
		sxe2_vsi_list_refcnt_update(adapter, rule_info->vsi_list, true);
		new_vsi_list = true;
	}

	memset(&temp_rule_info, 0, sizeof(temp_rule_info));
	if (rule_info->tcf_fltr->prio < save_rule->tcf_fltr->prio) {
		SWITCH_TC_RULE_ACT_INFO_GET_FROM_RULE(&temp_rule_info, save_rule);
		SWITCH_RULE_ACT_INFO_CPY(save_rule, rule_info);

		ret = sxe2_fwd_rule_update(adapter, save_rule);
		if (ret) {
			LOG_ERROR_BDF("request to admin q failed, ret %d\n",
				      ret);
			SWITCH_TC_RULE_ACT_INFO_SET_TO_RULE(save_rule, &temp_rule_info);
			if (new_vsi_list)
				(void)sxe2_vsi_list_remove(adapter, rule_info->vsi_list);
			rule_info->vsi_list = NULL;
			goto l_end;
		}

		SWITCH_TC_RULE_ACT_INFO_SET_TO_RULE(rule_info, &temp_rule_info);
	}

	ret = sxe2_switch_tc_rule_info_add(rule_info, save_rule);
	if (ret)
		LOG_ERROR_BDF("tc_rule_info add failed, ret:%d\n", ret);

l_end:
	return ret;
}

STATIC s32 sxe2_switch_save_rule_check(struct sxe2_adapter *adapter,
				       struct sxe2_rule_info *save_rule,
				       struct sxe2_rule_info *rule_info)
{
	s32 ret = 0;
	u16 vsi_id;

	if (save_rule->vsi_list) {
		vsi_id = rule_info->act.fwd_id.vsi_id;
		if (test_bit(vsi_id, save_rule->vsi_list->vsi_map))
			ret = -EEXIST;
	} else if (save_rule->act.type == SXE2_DROP_PACKET ||
		   save_rule->act.type == SXE2_MIRROR_PACKET ||
		   save_rule->recipe_id == SXE2_DEFAULT_RECIPE_SRCVSI ||
		   save_rule->recipe_id == SXE2_DEFAULT_RECIPE_SRCVSI_EXT ||
		   save_rule->recipe_id == SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK ||
		   save_rule->recipe_id == SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK_EXT) {
		if (rule_info->act.fwd_id.vsi_id == save_rule->act.fwd_id.vsi_id) {
			LOG_WARN_BDF("rule exist, rule id %d, same vsi %d\n",
				     save_rule->rule_id, rule_info->act.fwd_id.vsi_id);
			ret = -EEXIST;
		} else {
			LOG_ERROR_BDF("rule exist, rule id %d, exist vsi %d, request vsi %d\n",
				      save_rule->rule_id, save_rule->act.fwd_id.vsi_id,
				      rule_info->act.fwd_id.vsi_id);
			ret = -EINVAL;
		}
	} else if (save_rule->act.type == SXE2_FWD_TO_Q) {
		if (rule_info->act.fwd_id.q_id == save_rule->act.fwd_id.q_id) {
			LOG_WARN_BDF("rule exist, rule id %d, same queue %d\n",
				     save_rule->rule_id, rule_info->act.fwd_id.q_id);
			ret = -EEXIST;
		} else {
			LOG_ERROR_BDF("rule exist, rule id %d, exist queue %d, request queue %d\n",
				      save_rule->rule_id, save_rule->act.fwd_id.q_id,
				      rule_info->act.fwd_id.q_id);
			ret = -EINVAL;
		}
	} else if (save_rule->act.type == SXE2_FWD_TO_QGRP) {
		if (rule_info->act.fwd_id.q_id == save_rule->act.fwd_id.q_id &&
		    rule_info->act.qgrp_size == save_rule->act.qgrp_size) {
			LOG_WARN_BDF("rule exist, rule id %d, same queue group %d size %d\n",
				     save_rule->rule_id,
				     rule_info->act.fwd_id.q_id,
				     rule_info->act.qgrp_size);
			ret = -EEXIST;
		} else {
			LOG_ERROR_BDF("rule exist, rule id %d, exist group %d size %d, \t"
				      "request  group %d size %d\n",
				      save_rule->rule_id,
				      save_rule->act.fwd_id.q_id,
				      save_rule->act.qgrp_size,
				      rule_info->act.fwd_id.q_id,
				      rule_info->act.qgrp_size);
			ret = -EINVAL;
		}
	} else {
		if (rule_info->act.fwd_id.vsi_id ==
		    save_rule->act.fwd_id.vsi_id) {
			LOG_WARN_BDF("rule exist, rule id %d, same vsi %d\n",
				     save_rule->rule_id,
				     rule_info->act.fwd_id.vsi_id);
			ret = -EEXIST;
		}
	}

	return ret;
}

s32 sxe2_switch_tc_samerule_del(struct sxe2_adapter *adapter,
				struct sxe2_rule_info *save_rule)
{
	s32 ret				       = 0;
	struct sxe2_tc_rule_info *tc_rule_info = NULL;
	struct sxe2_tc_rule_info temp_rule_info;

	memset(&temp_rule_info, 0, sizeof(temp_rule_info));

	SWITCH_TC_RULE_ACT_INFO_GET_FROM_RULE(&temp_rule_info, save_rule);

	tc_rule_info = list_first_entry(&save_rule->tc_rule_head,
					struct sxe2_tc_rule_info, list_entry);

	SWITCH_TC_RULE_ACT_INFO_SET_TO_RULE(save_rule, tc_rule_info);

	ret = sxe2_fwd_rule_update(adapter, save_rule);
	if (ret) {
		LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
		SWITCH_TC_RULE_ACT_INFO_SET_TO_RULE(save_rule, &temp_rule_info);
		goto l_end;
	}

	sxe2_hash_cookie_del(adapter, temp_rule_info.cookie);

	list_del(&tc_rule_info->list_entry);
	kfree(tc_rule_info);

l_end:
	return ret;
}

STATIC s32 sxe2_switch_rule_add_new_list(struct sxe2_adapter *adapter,
					 struct sxe2_rule_info *rule_info,
					 struct sxe2_rule_info *save_rule,
					 enum sxe2_vsi_list_type vsi_list_type)
{
	s32 ret		  = 0;
	bool new_vsi_list = false;
	u16 vsi_array[2] = { 0 };
	struct sxe2_vsi_list_info *vsi_list;
	u16 vsi_id;

	ret = sxe2_switch_save_rule_check(adapter, save_rule, rule_info);
	if (ret)
		goto l_end;

	if (save_rule->vsi_list && !rule_info->is_fwd &&
	    save_rule->vsi_list->rule_cnt > 1) {
		if (bitmap_weight(save_rule->vsi_list->vsi_map,
				  SXE2_VSI_MAX_CNT) > 1) {
			LOG_ERROR_BDF("rule id %d vsi list id %d has multi vsi and multi ref cnt\n",
				      save_rule->rule_id,
				      save_rule->vsi_list->vsi_list_id);
			ret = -EIO;
			goto l_end;
		}
		vsi_array[0] = rule_info->act.fwd_id.vsi_id;
		vsi_array[1] = (u16)find_first_bit(save_rule->vsi_list->vsi_map,
						   SXE2_VSI_MAX_CNT);
		new_vsi_list = true;
	} else if (!save_rule->vsi_list) {
		vsi_array[0] = rule_info->act.fwd_id.vsi_id;
		vsi_array[1] = save_rule->act.fwd_id.vsi_id;
		new_vsi_list = true;
	}

	if (new_vsi_list) {
		vsi_list = sxe2_vsi_list_create(adapter, vsi_array, 2,
						vsi_list_type, &ret);
		if (!vsi_list)
			goto l_end;

		rule_info->vsi_list		  = vsi_list;
		rule_info->act.fwd_id.vsi_list_id = vsi_list->vsi_list_id;
		ret = sxe2_rule_fwd_id_update(adapter, rule_info, save_rule);
		if (ret) {
			(void)sxe2_vsi_list_remove(adapter, vsi_list);
			rule_info->vsi_list = NULL;
		}
	} else {
		if (!save_rule->vsi_list) {
			LOG_ERROR_BDF("rule id %d need update vsi list, but has no vsi list\n",
				      save_rule->rule_id);
			ret = -EIO;
			goto l_end;
		}
		vsi_id = rule_info->act.fwd_id.vsi_id;
		ret    = sxe2_vsi_list_update(adapter, save_rule->vsi_list,
					      &vsi_id, 1, vsi_list_type, true);
		if (ret)
			goto l_end;
	}
l_end:
	return ret;
}

STATIC s32 sxe2_legacy_user_samerule_add(struct sxe2_adapter *adapter,
					 struct sxe2_rule_info *rule_info,
					 struct sxe2_rule_info *save_rule)
{
	s32 ret = 0;
	struct sxe2_tc_rule_info *tc_rule_info = NULL;
	struct sxe2_tc_rule_info *rule_node = NULL;
	struct sxe2_tcf_fltr *new_fltr;
	struct sxe2_tc_rule_info temp_rule_info;
	bool new_vsi_list = false;

	new_fltr = rule_info->tcf_fltr;

	if (new_fltr->backup_type == SXE2_RULE_BACKUP_T_NO) {
		LOG_ERROR_BDF("new rule backup type is %u.\n", SXE2_RULE_BACKUP_T_NO);
		ret = -EINVAL;
		goto l_end;
	}

	if (!list_empty(&save_rule->tc_rule_head)) {
		tc_rule_info = list_first_entry(&save_rule->tc_rule_head,
						struct sxe2_tc_rule_info, list_entry);
	}

	if (tc_rule_info && tc_rule_info->backup_type != new_fltr->backup_type) {
		LOG_ERROR_BDF("current backup type is %u, but new rule backup type is %u.\n",
			      tc_rule_info->backup_type, new_fltr->backup_type);
		ret = -EINVAL;
		goto l_end;
	}

	if (!tc_rule_info || tc_rule_info->backup_type == new_fltr->backup_type) {
		rule_node = kzalloc(sizeof(*tc_rule_info), GFP_KERNEL);
		if (!rule_node) {
			ret = -ENOMEM;
			LOG_ERROR_BDF("alloc memory failed\n");
			goto l_end;
		}

		if (new_fltr->action == SXE2_FWD_TO_VSI_LIST) {
			struct sxe2_vsi_list_info *vsi_list;

			vsi_list = sxe2_cpx_rule_vsi_list_create(adapter, new_fltr, &ret);
			if (!vsi_list) {
				kfree(rule_node);
				goto l_end;
			}
			rule_info->vsi_list = vsi_list;
			rule_info->act.fwd_id.vsi_list_id = vsi_list->vsi_list_id;
			sxe2_vsi_list_refcnt_update(adapter, rule_info->vsi_list, true);
			new_vsi_list = true;
		}

		if (new_fltr->backup_type == SXE2_RULE_BACKUP_T_LAST) {
			memset(&temp_rule_info, 0, sizeof(temp_rule_info));
			SWITCH_TC_RULE_ACT_INFO_GET_FROM_RULE(&temp_rule_info, save_rule);
			SWITCH_RULE_ACT_INFO_CPY(save_rule, rule_info);
			ret = sxe2_fwd_rule_update(adapter, save_rule);
			if (ret) {
				LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
				SWITCH_TC_RULE_ACT_INFO_SET_TO_RULE(save_rule,
								    &temp_rule_info);
				if (new_vsi_list)
					(void)sxe2_vsi_list_remove(adapter, rule_info->vsi_list);
				rule_info->vsi_list = NULL;

				kfree(rule_node);
				goto l_end;
			}
			SWITCH_TC_RULE_ACT_INFO_GET_FROM_TC_RULE(rule_node, &temp_rule_info);
			list_add(&rule_node->list_entry, &save_rule->tc_rule_head);

		} else {
			SWITCH_TC_RULE_ACT_INFO_GET_FROM_RULE(rule_node, rule_info);
			list_add_tail(&rule_node->list_entry, &save_rule->tc_rule_head);
		}
	}

l_end:
	return ret;
}

STATIC void *sxe2_switch_cpx_samerule_check(struct sxe2_adapter *adapter,
					    struct sxe2_rule_info *rule_info,
					    struct sxe2_rule_info *save_rule)
{
	void *ret = NULL;
	struct sxe2_tc_rule_info *list_itr = NULL;
	struct sxe2_tcf_fltr *tcf_fltr = NULL;

	tcf_fltr = rule_info->tcf_fltr;
	if (tcf_fltr->action == save_rule->tcf_fltr->action &&
	    tcf_fltr->src_vsi_id == save_rule->tcf_fltr->src_vsi_id) {
		if ((tcf_fltr->action == SXE2_FWD_TO_VSI_LIST &&
		     !memcmp(tcf_fltr->dst_vsi_map, save_rule->tcf_fltr->dst_vsi_map,
		     sizeof(tcf_fltr->dst_vsi_map))) ||
		    (tcf_fltr->action != SXE2_FWD_TO_VSI_LIST &&
		     tcf_fltr->dst_vsi_id == save_rule->tcf_fltr->dst_vsi_id)) {
			ret = save_rule;
			goto l_end;
		}
	}

	list_for_each_entry(list_itr, &save_rule->tc_rule_head, list_entry) {
		if (tcf_fltr->action == list_itr->action &&
		    tcf_fltr->src_vsi_id == list_itr->src_vsi_id) {
			if ((tcf_fltr->action == SXE2_FWD_TO_VSI_LIST &&
			     !memcmp(tcf_fltr->dst_vsi_map, list_itr->dst_vsi_map,
			     sizeof(tcf_fltr->dst_vsi_map))) ||
			   (tcf_fltr->action != SXE2_FWD_TO_VSI_LIST &&
			    tcf_fltr->dst_vsi_id == list_itr->dst_vsi_id)) {
				ret = list_itr;
				goto l_end;
			}
		}
	}

l_end:
	if (ret) {
		LOG_INFO_BDF("There is a same rule, action type:%u, src_vsi:%u\n",
			     tcf_fltr->action, tcf_fltr->src_vsi_id);
	}

	return ret;
}

STATIC s32 sxe2_switch_user_rule_update(struct sxe2_adapter *adapter,
					struct sxe2_rule_info *save_rule)
{
	s32 ret				       = 0;
	struct sxe2_tc_rule_info *tc_rule_info = NULL;
	struct sxe2_tc_rule_info temp_rule_info;
	struct sxe2_vsi_list_info *vsi_list;

	vsi_list = save_rule->vsi_list;

	memset(&temp_rule_info, 0, sizeof(temp_rule_info));

	SWITCH_TC_RULE_ACT_INFO_GET_FROM_RULE(&temp_rule_info, save_rule);

	tc_rule_info = list_first_entry(&save_rule->tc_rule_head,
					struct sxe2_tc_rule_info, list_entry);

	SWITCH_TC_RULE_ACT_INFO_SET_TO_RULE(save_rule, tc_rule_info);

	ret = sxe2_fwd_rule_update(adapter, save_rule);
	if (ret) {
		LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
		SWITCH_TC_RULE_ACT_INFO_SET_TO_RULE(save_rule, &temp_rule_info);
		goto l_end;
	}

	if (vsi_list)
		(void)sxe2_vsi_list_remove(adapter, vsi_list);

	list_del(&tc_rule_info->list_entry);
	kfree(tc_rule_info);

l_end:
	return ret;
}

STATIC s32 sxe2_user_samerule_del(struct sxe2_adapter *adapter,
				  struct sxe2_rule_info *rule_info,
				  struct sxe2_rule_info *save_rule)
{
	s32 ret = 0;
	void *check_rule;
	struct sxe2_tc_rule_info *list_itr = NULL;
	struct sxe2_vsi_list_info *vsi_list;

	check_rule = sxe2_switch_cpx_samerule_check(adapter, rule_info, save_rule);
	if (!check_rule) {
		LOG_ERROR_BDF("can not find rule\n");
		ret = -ENOENT;
		goto l_end;
	} else if (save_rule == (struct sxe2_rule_info *)check_rule &&
				 list_empty(&save_rule->tc_rule_head)) {
		vsi_list = save_rule->vsi_list;
		ret = sxe2_fwd_rule_remove(adapter, save_rule, true);
		if (ret) {
			LOG_DEV_ERR("complex rule del failed, ret:%d\n", ret);
			goto l_end;
		}
		save_rule = NULL;

		if (vsi_list)
			(void)sxe2_vsi_list_remove(adapter, vsi_list);
	} else if (save_rule == (struct sxe2_rule_info *)check_rule) {
		ret = sxe2_switch_user_rule_update(adapter, save_rule);
		if (ret) {
			LOG_ERROR_BDF("switch tc samerule del failed, ret %d\n", ret);
			goto l_end;
		}
	} else {
		list_itr = (struct sxe2_tc_rule_info *)check_rule;
		if (list_itr->vsi_list) {
			(void)sxe2_vsi_list_remove(adapter,
						   list_itr->vsi_list);
			list_itr->vsi_list = NULL;
		}
		list_del(&list_itr->list_entry);
		kfree(list_itr);
	}

l_end:
	return ret;
}

STATIC s32 sxe2_switch_cpx_samerule_add(struct sxe2_adapter *adapter,
					struct sxe2_rule_info *rule_info,
					struct sxe2_rule_info *save_rule)
{
	s32 ret = 0;

	if (rule_info->tcf_fltr->is_user_rule != save_rule->tcf_fltr->is_user_rule) {
		ret = -EINVAL;
		LOG_ERROR_BDF("There is a same rule, type %s, ret %d\n",
			      save_rule->tcf_fltr->is_user_rule ? "user" : "not user", ret);
		goto l_end;
	}

	if (sxe2_switch_cpx_samerule_check(adapter, rule_info, save_rule)) {
		ret = -EEXIST;
		LOG_ERROR_BDF("There is a same rule, ret %d\n", ret);
		goto l_end;
	}

	if (test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags) &&
	    !save_rule->tcf_fltr->is_user_rule) {
		ret = sxe2_switchdev_tc_samerule_add(adapter, rule_info,
						     save_rule);
		if (ret) {
			LOG_ERROR_BDF("switchdev mode, kernel same rule process error\n");
			goto l_end;
		}
	} else if (test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags) &&
		   save_rule->tcf_fltr->is_user_rule) {
		ret = sxe2_switchdev_user_samerule_add(adapter, rule_info, save_rule);
		if (ret) {
			LOG_ERROR_BDF("switchdev mode, user same rule process error\n");
			goto l_end;
		}
	} else if (save_rule->tcf_fltr->is_user_rule) {
		ret = sxe2_legacy_user_samerule_add(adapter, rule_info, save_rule);
		if (ret)
			goto l_end;
	} else {
		LOG_ERROR_BDF("legacy mode, same rule process, but not user rule\n");
		ret = -EINVAL;
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_switch_rule_add(struct sxe2_adapter *adapter,
				struct sxe2_rule_info *rule_info)
{
	s32 ret					= 0;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	/* in order to protect the data */
	struct mutex *rule_lock;
	/* in order to protect the data */
	struct mutex *vsi_list_lock;
	struct sxe2_rule_info *save_rule;
	struct sxe2_vsi_list_info *vsi_list;
	enum sxe2_vsi_list_type vsi_list_type;
	bool new_vsi_list = false;

	u16 vsi_id;

	if (rule_info->is_fwd)
		vsi_list_type = SXE2_VSI_LIST_TYPE_FORWARD;
	else
		vsi_list_type = SXE2_VSI_LIST_TYPE_PRUNE;

	if (!rule_info->tcf_fltr)
		rule_lock = &switch_ctxt->recipe[rule_info->recipe_id].rule_lock;
	else
		rule_lock = &switch_ctxt->complex_recipe.rule_lock;

	vsi_list_lock = &switch_ctxt->vsi_list_mgmt[vsi_list_type].vsi_list_lock;

	mutex_lock(rule_lock);
	mutex_lock(vsi_list_lock);

	save_rule = sxe2_rule_entry_find(adapter, rule_info);

	if (!save_rule) {
		if (!rule_info->is_fwd) {
			vsi_id	 = rule_info->act.fwd_id.vsi_id;
			vsi_list = sxe2_vsi_list_entry_find(adapter, &vsi_id, 1,
							    vsi_list_type);
			if (!vsi_list) {
				vsi_list =
					sxe2_vsi_list_create(adapter, &vsi_id,
							     1, vsi_list_type,
							     &ret);
				if (!vsi_list)
					goto l_end;
				new_vsi_list = true;
			}
			rule_info->vsi_list = vsi_list;
			rule_info->act.fwd_id.vsi_list_id = vsi_list->vsi_list_id;
		} else if (rule_info->tcf_fltr &&
			rule_info->act.type == SXE2_FWD_TO_VSI_LIST) {
			vsi_list = sxe2_cpx_rule_vsi_list_create(adapter,
								 rule_info->tcf_fltr, &ret);
			if (!vsi_list)
				goto l_end;
			new_vsi_list = true;
			rule_info->vsi_list = vsi_list;
			rule_info->act.fwd_id.vsi_list_id = vsi_list->vsi_list_id;
		}

		if (!sxe2_fwd_rule_create(adapter, rule_info, &ret)) {
			if (new_vsi_list)
				(void)sxe2_vsi_list_remove(adapter,
							   rule_info->vsi_list);
			rule_info->vsi_list = NULL;
		}
	} else if (rule_info->tcf_fltr) {
		ret = sxe2_switch_cpx_samerule_add(adapter, rule_info,
						   save_rule);
		if (ret) {
			LOG_ERROR_BDF("switch tc same rule process error\n");
			goto l_end;
		}
	} else if (rule_info->recipe_id == SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK) {
		rule_info->hid = save_rule->hid;
		ret = -EEXIST;
	} else {
		ret = sxe2_switch_rule_add_new_list(adapter, rule_info,
						    save_rule, vsi_list_type);
	}

l_end:
	mutex_unlock(vsi_list_lock);
	mutex_unlock(rule_lock);

	return ret;
}

STATIC s32 sxe2_switch_rule_del_vsi(struct sxe2_adapter *adapter,
				    struct sxe2_rule_info *rule_info,
				    struct sxe2_rule_info *save_rule)
{
	s32 ret = 0;
#ifdef SXE2_CFG_DEBUG
	if (save_rule->vsi_list) {
		LOG_ERROR_BDF("rule %d forward to vsi, but vsi_list struct is not NULL\n",
			      save_rule->rule_id);
	}
#endif
	if (save_rule->act.fwd_id.vsi_id != rule_info->act.fwd_id.vsi_id) {
		LOG_WARN_BDF("rule %d forward to vsi is %d, but need to delete vsi is %d\n",
			     save_rule->rule_id, save_rule->act.fwd_id.vsi_id,
			     rule_info->act.fwd_id.vsi_id);
		ret = -ENOENT;
		goto l_end;
	}
	if (rule_info->tcf_fltr && !list_empty(&save_rule->tc_rule_head)) {
		ret = sxe2_switch_tc_samerule_del(adapter, save_rule);
		if (ret) {
			LOG_ERROR_BDF("switch tc samerule del failed, ret %d\n",
				      ret);
			goto l_end;
		}
	} else {
		ret = sxe2_fwd_rule_remove(adapter, save_rule, true);
		save_rule = NULL;
	}
l_end:
	return ret;
}

STATIC s32 sxe2_switch_rule_del_vsi_list(struct sxe2_adapter *adapter,
					 struct sxe2_rule_info *rule_info,
					 struct sxe2_rule_info *save_rule,
					 enum sxe2_vsi_list_type vsi_list_type)
{
	s32 ret	   = 0;
	u16 vsi_id = 0;
	struct sxe2_vsi_list_info *vsi_list;
#ifdef SXE2_CFG_DEBUG
	if (!save_rule->vsi_list) {
		LOG_ERROR_BDF("rule %d forward to vsi_left list, but vsi_list struct is NULL\n",
			      save_rule->rule_id);
		ret = -EINVAL;
		goto l_end;
	}
#endif
	vsi_id = rule_info->act.fwd_id.vsi_id;
	if (!test_bit(vsi_id, save_rule->vsi_list->vsi_map)) {
		LOG_WARN_BDF("rule %d forward to vsi list is %d, but it do not content vsi %d\n",
			     save_rule->rule_id, save_rule->vsi_list->vsi_list_id,
			     rule_info->act.fwd_id.vsi_id);
		ret = -ENOENT;
		goto l_end;
	}

	if (bitmap_weight(save_rule->vsi_list->vsi_map, SXE2_VSI_MAX_CNT) == 2 &&
	    rule_info->is_fwd) {
		vsi_id = (u16)find_first_bit(save_rule->vsi_list->vsi_map,
					     SXE2_VSI_MAX_CNT);
		if (vsi_id == rule_info->act.fwd_id.vsi_id)
			vsi_id = (u16)find_next_bit(save_rule->vsi_list->vsi_map,
						    SXE2_VSI_MAX_CNT, vsi_id + 1);

		rule_info->act.fwd_id.vsi_id = vsi_id;
		ret = sxe2_rule_fwd_id_update(adapter, rule_info, save_rule);
	} else if (bitmap_weight(save_rule->vsi_list->vsi_map,
				 SXE2_VSI_MAX_CNT) == 2 && !rule_info->is_fwd) {
		vsi_id = (u16)find_first_bit(save_rule->vsi_list->vsi_map,
					     SXE2_VSI_MAX_CNT);
		if (vsi_id == rule_info->act.fwd_id.vsi_id)
			vsi_id = (u16)find_next_bit(save_rule->vsi_list->vsi_map,
						   SXE2_VSI_MAX_CNT,
						   vsi_id + 1);
		vsi_list = sxe2_vsi_list_entry_find(adapter, &vsi_id, 1,
						    vsi_list_type);
		if (!vsi_list) {
			vsi_id = rule_info->act.fwd_id.vsi_id;
			ret = sxe2_vsi_list_update(adapter, save_rule->vsi_list,
						   &vsi_id, 1, vsi_list_type,
						   false);
			if (ret)
				goto l_end;
		} else {
			rule_info->vsi_list = vsi_list;
			rule_info->act.fwd_id.vsi_list_id =
				vsi_list->vsi_list_id;
			ret = sxe2_rule_fwd_id_update(adapter, rule_info,
						      save_rule);
			if (ret)
				goto l_end;
		}
	} else if (bitmap_weight(save_rule->vsi_list->vsi_map,
				 SXE2_VSI_MAX_CNT) == 1 &&
		   !rule_info->is_fwd) {
		vsi_list = save_rule->vsi_list;
		ret	 = sxe2_fwd_rule_remove(adapter, save_rule, true);
		if (ret)
			goto l_end;
		save_rule = NULL;
		sxe2_vsi_list_refcnt_update(adapter, vsi_list, false);

	} else {
		vsi_id = rule_info->act.fwd_id.vsi_id;
		ret    = sxe2_vsi_list_update(adapter, save_rule->vsi_list,
					      &vsi_id, 1, vsi_list_type, false);
		if (ret)
			goto l_end;
	}
l_end:
	return ret;
}

STATIC s32 sxe2_switch_rule_del_other(struct sxe2_adapter *adapter,
				      struct sxe2_rule_info *rule_info,
				      struct sxe2_rule_info *save_rule)
{
	s32 ret = 0;

	if (rule_info->tcf_fltr && !list_empty(&save_rule->tc_rule_head)) {
		ret = sxe2_switch_tc_samerule_del(adapter, save_rule);
		if (ret) {
			LOG_ERROR_BDF("switch tc samerule del failed, ret %d\n",
				      ret);
			goto l_end;
		}
	} else {
		ret = sxe2_fwd_rule_remove(adapter, save_rule, true);
		if (ret)
			goto l_end;
		save_rule = NULL;
	}
l_end:
	return ret;
}

STATIC s32 sxe2_switch_rule_del(struct sxe2_adapter *adapter,
				struct sxe2_rule_info *rule_info)
{
	s32 ret					= 0;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	/* in order to protect the data */
	struct mutex *rule_lock;
	/* in order to protect the data */
	struct mutex *vsi_list_lock;
	enum sxe2_vsi_list_type vsi_list_type;
	struct sxe2_rule_info *save_rule;

	if (rule_info->is_fwd)
		vsi_list_type = SXE2_VSI_LIST_TYPE_FORWARD;
	else
		vsi_list_type = SXE2_VSI_LIST_TYPE_PRUNE;

	if (!rule_info->tcf_fltr)
		rule_lock =
			&switch_ctxt->recipe[rule_info->recipe_id].rule_lock;
	else
		rule_lock = &switch_ctxt->complex_recipe.rule_lock;
	vsi_list_lock =
		&switch_ctxt->vsi_list_mgmt[vsi_list_type].vsi_list_lock;

	mutex_lock(rule_lock);
	mutex_lock(vsi_list_lock);

	save_rule = sxe2_rule_entry_find(adapter, rule_info);
	if (!save_rule) {
		LOG_ERROR_BDF("can not find rule\n");
		ret = -ENOENT;
		goto l_end;
	}

	if (rule_info->tcf_fltr && rule_info->tcf_fltr->is_user_rule) {
		ret = sxe2_user_samerule_del(adapter, rule_info, save_rule);
		if (ret)
			goto l_end;
	} else {
		rule_info->rule_id = save_rule->rule_id;
		rule_info->hid = save_rule->hid;
		if (save_rule->act.type == SXE2_FWD_TO_VSI) {
			ret = sxe2_switch_rule_del_vsi(adapter, rule_info, save_rule);
			if (ret)
				goto l_end;
		} else if (save_rule->act.type == SXE2_FWD_TO_VSI_LIST) {
			ret = sxe2_switch_rule_del_vsi_list(adapter, rule_info,
							    save_rule, vsi_list_type);
			if (ret)
				goto l_end;
		} else if (save_rule->act.type == SXE2_DROP_PACKET ||
			   save_rule->act.type == SXE2_FWD_TO_Q ||
			   save_rule->act.type == SXE2_FWD_TO_QGRP ||
			   save_rule->act.type == SXE2_MIRROR_PACKET ||
			   save_rule->act.type == SXE2_LARGE_ACTION) {
			ret = sxe2_switch_rule_del_other(adapter, rule_info, save_rule);
			if (ret)
				goto l_end;
		}
	}

l_end:
	mutex_unlock(vsi_list_lock);
	mutex_unlock(rule_lock);
	return ret;
}

STATIC void sxe2_mac_rule_prepare(struct sxe2_adapter *adapter,
				  u16 id_in_dev, const u8 *mac,
				  struct sxe2_rule_info *rule)
{
	rule->recipe_id = SXE2_DEFAULT_RECIPE_MAC;
	rule->act.type = SXE2_FWD_TO_VSI;
	rule->act.fwd_id.vsi_id = id_in_dev;
	rule->is_fwd = true;

	rule->act.lb_en = true;
	if (adapter->switch_ctxt.evb_mode == BRIDGE_MODE_VEB) {
		if (is_unicast_ether_addr(mac))
			rule->act.lan_en = false;
		else
			rule->act.lan_en = true;
	} else {
		rule->act.lan_en = true;
	}

	ether_addr_copy(rule->fltr.data.mac.mac_addr, mac);
	LOG_DEBUG_BDF("vsi %u prepare mac rule, mac %pM, evb_mode %d\n",
		      id_in_dev, rule->fltr.data.mac.mac_addr,
		      adapter->switch_ctxt.evb_mode);
}

s32 sxe2_default_mac_addr_get(struct sxe2_vsi *vsi, u8 *mac)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_cmd_params cmd   = { 0 };
	struct sxe2_fwc_switch_mac_info_resp resp;

	memset(&resp, 0, sizeof(resp));
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_MAC_ADDR_GET, NULL, 0, &resp,
				  sizeof(resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("switch default mac addr get failed, ret=%d\n", ret);
		ret = -EIO;
	}
	memcpy(mac, resp.mac_addr, sizeof(resp.mac_addr));
	return ret;
}

s32 sxe2_cur_mac_addr_set(struct sxe2_vsi *vsi, const u8 *mac)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_cmd_params cmd   = { 0 };
	struct sxe2_fwc_switch_mac_info req;

	memcpy(req.mac_addr, mac, sizeof(req.mac_addr));

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_MAC_ADDR_SET, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("switch mac addr set failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_mac_rule_add(struct sxe2_vsi *vsi, const u8 *mac)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	(void)mutex_lock(&vsi->adapter->switch_ctxt.evb_mode_lock);
	sxe2_mac_rule_prepare(adapter, vsi->idx_in_dev, mac, &rule_info);

	ret = sxe2_switch_rule_add(adapter, &rule_info);
	(void)mutex_unlock(&vsi->adapter->switch_ctxt.evb_mode_lock);
	LOG_SWITCH_RULE_OPT(ret, "vsi_id:%u mac_rule add ret:%d, rule_id:%d mac:%pM\n",
			    vsi->idx_in_dev, ret, rule_info.rule_id,
			    rule_info.fltr.data.mac.mac_addr);

	return ret;
}

s32 sxe2_mac_rule_del(struct sxe2_adapter *adapter, u16 id_in_dev, const u8 *mac)
{
	s32 ret			     = 0;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_mac_rule_prepare(adapter, id_in_dev, mac, &rule_info);

	ret = sxe2_switch_rule_del(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret, "vsi_id:%u mac_rule delete ret:%d, rule_id:%d mac:%pM\n",
			    id_in_dev, ret, rule_info.rule_id,
			    rule_info.fltr.data.mac.mac_addr);

	return ret;
}

STATIC void sxe2_vlan_rule_prepare(struct sxe2_adapter *adapter,
				   u16 id_in_dev, struct sxe2_vlan *vlan,
				   struct sxe2_rule_info *rule)
{
	rule->recipe_id = SXE2_DEFAULT_RECIPE_VLAN;
	rule->act.type = SXE2_FWD_TO_VSI_LIST;
	rule->act.fwd_id.vsi_id = id_in_dev;
	rule->is_fwd = false;

	rule->act.lb_en	 = false;
	rule->act.lan_en = true;

	rule->fltr.data.vlan.vlan_id	= vlan->vid;
	rule->fltr.data.vlan.tpid	= vlan->tpid;
	rule->fltr.data.vlan.tpid_valid = true;
	LOG_DEBUG_BDF("vsi %u prepare vlan rule, vlan id %d, tpid 0x%x\n",
		      id_in_dev, rule->fltr.data.vlan.vlan_id,
		      rule->fltr.data.vlan.tpid);
}

s32 sxe2_vlan_rule_add(struct sxe2_vsi *vsi, struct sxe2_vlan *vlan)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_vlan_rule_prepare(adapter, vsi->idx_in_dev, vlan, &rule_info);

	ret = sxe2_switch_rule_add(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret, "vsi_id:%u vlan_rule add ret:%d rule_id:%d vlan_id:%u tpid:0x%x\n",
			    vsi->idx_in_dev, ret, rule_info.rule_id, vlan->vid, vlan->tpid);

	return ret;
}

s32 sxe2_vlan_rule_del(struct sxe2_adapter *adapter, u16 id_in_dev, struct sxe2_vlan *vlan)
{
	s32 ret			     = 0;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_vlan_rule_prepare(adapter, id_in_dev, vlan, &rule_info);

	ret = sxe2_switch_rule_del(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret, "vsi_id:%u vlan_rule del ret:%d rule_id:%d vlan_id:%u tpid:0x%x\n",
			    id_in_dev, ret, rule_info.rule_id, vlan->vid, vlan->tpid);

	return ret;
}

void sxe2_srcvsi_rule_prepare(struct sxe2_adapter *adapter,
			      u16 id_in_dev, struct sxe2_rule_info *rule)
{
	rule->recipe_id = SXE2_DEFAULT_RECIPE_SRCVSI;
	rule->act.type = SXE2_FWD_TO_VSI;
	rule->act.fwd_id.vsi_id = id_in_dev;

	rule->is_fwd = true;

	rule->act.lb_en	 = false;
	rule->act.lan_en = false;

	rule->fltr.data.srcvsi.vsi_id = id_in_dev;
	rule->fltr.data.srcvsi.to_rdma =
		SXE2_FV_PKT_TO_RDMA_NO;
	rule->fltr.data.srcvsi.packet_src_type =
		SXE2_PKT_SRC_TYPE_LOOPBACK_HOST;

	rule->fltr.src_type = SXE2_SRC_TYPE_RX;
	LOG_DEBUG_BDF("vsi %u prepare source vsi prune rule\n", id_in_dev);
}

s32 sxe2_srcvsi_rule_add(struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_srcvsi_rule_prepare(adapter, vsi->idx_in_dev, &rule_info);

	ret = sxe2_switch_rule_add(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret,
			    "vsi_id:%u srcvsi_rule add ret:%d, rule_id:%d\n",
			    vsi->idx_in_dev, ret, rule_info.rule_id);

	return ret;
}

s32 sxe2_srcvsi_rule_del(struct sxe2_adapter *adapter, u16 id_in_dev)
{
	s32 ret			     = 0;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_srcvsi_rule_prepare(adapter, id_in_dev, &rule_info);

	ret = sxe2_switch_rule_del(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret,
			    "vsi_id:%u srcvsi_rule del ret:%d, rule_id:%d\n",
			    id_in_dev, ret, rule_info.rule_id);

	return ret;
}

STATIC void sxe2_srcvsi_ext_rule_prepare(struct sxe2_adapter *adapter,
					 u16 id_in_dev_fltr,
					 u16 id_in_dev_act, struct sxe2_rule_info *rule)
{
	rule->recipe_id = SXE2_DEFAULT_RECIPE_SRCVSI_EXT;
	rule->act.type = SXE2_FWD_TO_VSI;
	rule->act.fwd_id.vsi_id = id_in_dev_act;

	rule->is_fwd = true;

	rule->act.lb_en	 = false;
	rule->act.lan_en = false;

	rule->fltr.data.srcvsi.vsi_id = id_in_dev_fltr;
	rule->fltr.data.srcvsi.to_rdma =
		SXE2_FV_PKT_TO_RDMA_NO;
	rule->fltr.data.srcvsi.packet_src_type =
		SXE2_PKT_SRC_TYPE_LOOPBACK_HOST;

	rule->fltr.src_type = SXE2_SRC_TYPE_RX;
	LOG_DEBUG_BDF("vsi %u prepare source vsi prune rule\n", id_in_dev_fltr);
}

s32 sxe2_srcvsi_ext_rule_add(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2_rule_info rule_info;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (vsi->src_prune.vsi_id_k == SXE2_VSI_ID_INVALID ||
	    vsi->src_prune.vsi_id_u == SXE2_VSI_ID_INVALID) {
		goto l_end;
	}

	memset(&rule_info, 0, sizeof(rule_info));
	sxe2_srcvsi_ext_rule_prepare(adapter, vsi->src_prune.vsi_id_u,
				     vsi->src_prune.vsi_id_k, &rule_info);
	ret = sxe2_switch_rule_add(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret,
			    "vsi_id:%u srcvsi ext rule add fwd vsi:%u ret:%d, rule_id:%d\n",
			    vsi->src_prune.vsi_id_u, vsi->src_prune.vsi_id_k,
			    ret, rule_info.rule_id);
	if (ret)
		goto l_end;

	memset(&rule_info, 0, sizeof(rule_info));
	sxe2_srcvsi_ext_rule_prepare(adapter, vsi->src_prune.vsi_id_k,
				     vsi->src_prune.vsi_id_u, &rule_info);
	ret = sxe2_switch_rule_add(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret,
			    "vsi_id:%u srcvsi ext rule add fwd vsi:%u ret:%d, rule_id:%d\n",
			    vsi->src_prune.vsi_id_k, vsi->src_prune.vsi_id_u,
			    ret, rule_info.rule_id);
	if (ret) {
		memset(&rule_info, 0, sizeof(rule_info));
		sxe2_srcvsi_ext_rule_prepare(adapter, vsi->src_prune.vsi_id_u,
					     vsi->src_prune.vsi_id_k, &rule_info);
		(void)sxe2_switch_rule_del(adapter, &rule_info);
	}
l_end:
	return ret;
}

s32 sxe2_srcvsi_ext_rule_del(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;
	struct sxe2_rule_info rule_info;
	struct sxe2_vsi *vsi;

	vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("src vsi id_in_dev:%u is NULL.\n", vsi_id);
		goto l_end;
	}

	if (vsi->src_prune.vsi_id_k == SXE2_VSI_ID_INVALID ||
	    vsi->src_prune.vsi_id_u == SXE2_VSI_ID_INVALID) {
		goto l_end;
	}

	memset(&rule_info, 0, sizeof(rule_info));
	sxe2_srcvsi_ext_rule_prepare(adapter, vsi->src_prune.vsi_id_u,
				     vsi->src_prune.vsi_id_k, &rule_info);
	ret = sxe2_switch_rule_del(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret,
			    "vsi_id:%u srcvsi ext rule del fwd vsi:%u ret:%d, rule_id:%d\n",
			    vsi->src_prune.vsi_id_u, vsi->src_prune.vsi_id_k,
			    ret, rule_info.rule_id);

	memset(&rule_info, 0, sizeof(rule_info));
	sxe2_srcvsi_ext_rule_prepare(adapter, vsi->src_prune.vsi_id_k,
				     vsi->src_prune.vsi_id_u, &rule_info);
	ret = sxe2_switch_rule_del(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret,
			    "vsi_id:%u srcvsi ext rule del fwd vsi:%u ret:%d, rule_id:%d\n",
			    vsi->src_prune.vsi_id_k, vsi->src_prune.vsi_id_u,
			    ret, rule_info.rule_id);

	vsi->src_prune.vsi_id_k = SXE2_VSI_ID_INVALID;
	vsi->src_prune.vsi_id_u = SXE2_VSI_ID_INVALID;

l_end:
	return ret;
}

bool sxe2_promisc_rule_in_use(struct sxe2_vsi *vsi)
{
	bool ret				= false;
	struct sxe2_switch_context *switch_ctxt = &vsi->adapter->switch_ctxt;
	struct sxe2_rule_info *list_itr		= NULL;
	u16 recipe_id				= SXE2_DEFAULT_RECIPE_PROMISC;
	enum sxe2_vsi_list_type vsi_list_type	= SXE2_VSI_LIST_TYPE_FORWARD;
	struct list_head *list_head;
	/* in order to protect the data */
	struct mutex *rule_lock;
	/* in order to protect the data */
	struct mutex *vsi_list_lock;

	list_head = &switch_ctxt->recipe[recipe_id].rule_head;
	rule_lock = &switch_ctxt->recipe[recipe_id].rule_lock;
	vsi_list_lock =
		&switch_ctxt->vsi_list_mgmt[vsi_list_type].vsi_list_lock;

	mutex_lock(rule_lock);
	mutex_lock(vsi_list_lock);

	list_for_each_entry(list_itr, list_head, list_entry) {
		if ((list_itr->act.type == SXE2_FWD_TO_VSI &&
		     list_itr->act.fwd_id.vsi_id == vsi->idx_in_dev) ||
		    (list_itr->act.type == SXE2_FWD_TO_VSI_LIST &&
		     list_itr->vsi_list &&
		     test_bit(vsi->idx_in_dev, list_itr->vsi_list->vsi_map))) {
			ret = true;
			break;
		}
	}

	mutex_unlock(vsi_list_lock);
	mutex_unlock(rule_lock);

	return ret;
}

STATIC void sxe2_promisc_rule_prepare(struct sxe2_adapter *adapter,
				      u16 id_in_dev, struct sxe2_rule_info *rule)
{
	rule->recipe_id = SXE2_DEFAULT_RECIPE_PROMISC;
	rule->act.type = SXE2_FWD_TO_VSI;
	rule->act.fwd_id.vsi_id = id_in_dev;

	rule->is_fwd = true;

	rule->act.lb_en	 = false;
	rule->act.lan_en = false;

	rule->fltr.src_type = SXE2_SRC_TYPE_RX;
	LOG_DEBUG_BDF("vsi %u prepare promisc rule\n", id_in_dev);
}

s32 sxe2_promisc_rule_add(struct sxe2_vsi *vsi)
{
	s32 ret			     = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_promisc_rule_prepare(adapter, vsi->idx_in_dev, &rule_info);

	ret = sxe2_switch_rule_add(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret,
			    "vsi_id:%u promisc_rule add ret:%d, rule_id:%d\n",
			    vsi->idx_in_dev, ret, rule_info.rule_id);

	return ret;
}

s32 sxe2_promisc_rule_del(struct sxe2_adapter *adapter, u16 id_in_dev)
{
	s32 ret			     = 0;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_promisc_rule_prepare(adapter, id_in_dev, &rule_info);

	ret = sxe2_switch_rule_del(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret,
			    "vsi_id:%u promisc_rule del ret:%d, rule_id:%d\n",
			    id_in_dev, ret, rule_info.rule_id);

	return ret;
}

bool sxe2_allmulti_rule_in_use(struct sxe2_vsi *vsi)
{
	bool ret				= false;
	struct sxe2_switch_context *switch_ctxt = &vsi->adapter->switch_ctxt;
	struct sxe2_rule_info *list_itr		= NULL;
	u16 recipe_id				= SXE2_DEFAULT_RECIPE_ALLMULTI;
	enum sxe2_vsi_list_type vsi_list_type	= SXE2_VSI_LIST_TYPE_FORWARD;
	struct list_head *list_head;
	/* in order to protect the data */
	struct mutex *rule_lock;
	/* in order to protect the data */
	struct mutex *vsi_list_lock;

	list_head = &switch_ctxt->recipe[recipe_id].rule_head;
	rule_lock = &switch_ctxt->recipe[recipe_id].rule_lock;
	vsi_list_lock =
		&switch_ctxt->vsi_list_mgmt[vsi_list_type].vsi_list_lock;

	mutex_lock(rule_lock);
	mutex_lock(vsi_list_lock);

	list_for_each_entry(list_itr, list_head, list_entry) {
		if ((list_itr->act.type == SXE2_FWD_TO_VSI &&
		     list_itr->act.fwd_id.vsi_id == vsi->idx_in_dev) ||
		    (list_itr->act.type == SXE2_FWD_TO_VSI_LIST &&
		     list_itr->vsi_list &&
		     test_bit(vsi->idx_in_dev, list_itr->vsi_list->vsi_map))) {
			ret = true;
			break;
		}
	}

	mutex_unlock(vsi_list_lock);
	mutex_unlock(rule_lock);

	return ret;
}

STATIC void sxe2_allmulti_rule_prepare(struct sxe2_adapter *adapter,
				       u16 id_in_dev, struct sxe2_rule_info *rule)
{
	rule->recipe_id = SXE2_DEFAULT_RECIPE_ALLMULTI;
	rule->act.type = SXE2_FWD_TO_VSI;
	rule->act.fwd_id.vsi_id = id_in_dev;
	rule->is_fwd = true;

	rule->act.lb_en	 = true;
	rule->act.lan_en = true;

	LOG_DEBUG_BDF("vsi %u prepare allmulti rule\n", id_in_dev);
}

s32 sxe2_allmulti_rule_add(struct sxe2_vsi *vsi)
{
	s32 ret			     = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_allmulti_rule_prepare(adapter, vsi->idx_in_dev, &rule_info);

	ret = sxe2_switch_rule_add(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret,
			    "vsi_id:%u allmulti_rule add ret:%d, rule_id:%d\n",
			    vsi->idx_in_dev, ret, rule_info.rule_id);

	return ret;
}

s32 sxe2_allmulti_rule_del(struct sxe2_adapter *adapter, u16 id_in_dev)
{
	s32 ret			     = 0;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_allmulti_rule_prepare(adapter, id_in_dev, &rule_info);

	ret = sxe2_switch_rule_del(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret,
			    "vsi_id:%u allmulti_rule del ret:%d, rule_id:%d\n",
			    id_in_dev, ret, rule_info.rule_id);

	return ret;
}

STATIC void sxe2_tx_etype_rule_prepare(struct sxe2_adapter *adapter,
				       u16 id_in_dev, struct sxe2_rule_info *rule, u16 etype)
{
	rule->recipe_id = SXE2_DEFAULT_RECIPE_TX_ETYPE;
	rule->act.type = SXE2_DROP_PACKET;
	rule->act.fwd_id.vsi_id = id_in_dev;
	rule->is_fwd = true;

	rule->act.lb_en	 = false;
	rule->act.lan_en = true;

	rule->fltr.data.etype.ethertype = etype;
	rule->fltr.data.etype.vsi_id	= rule->act.fwd_id.vsi_id;
	rule->fltr.src_type		= SXE2_SRC_TYPE_TX;
	LOG_DEBUG_BDF("vsi %u prepare tx etype rule, etype %x\n", id_in_dev,
		      etype);
}

STATIC void sxe2_rx_etype_rule_prepare(struct sxe2_adapter *adapter,
				       u16 id_in_dev, struct sxe2_rule_info *rule, u16 etype)
{
	rule->recipe_id = SXE2_DEFAULT_RECIPE_RX_ETYPE;
	rule->act.type = SXE2_FWD_TO_VSI;
	rule->act.fwd_id.vsi_id = id_in_dev;
	rule->is_fwd = true;

	rule->act.lb_en	 = false;
	rule->act.lan_en = false;

	rule->fltr.data.etype.ethertype = etype;
	rule->fltr.src_type		= SXE2_SRC_TYPE_RX;
	LOG_DEBUG_BDF("vsi %u prepare rx etype rule, etype %x\n", id_in_dev, etype);
}

s32 sxe2_tx_etype_rule_add(struct sxe2_vsi *vsi, u16 etype)
{
	s32 ret			     = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_rule_info rule_info;

	if (test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags) && etype == ETH_P_LLDP) {
		LOG_DEBUG_BDF("do not need to set tx lldp drop rule in switchdev mode.\n");
		return 0;
	}

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_tx_etype_rule_prepare(adapter, vsi->idx_in_dev,
				   &rule_info, etype);

	ret = sxe2_switch_rule_add(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret,
			    "vsi_id:%u tx_etype_rule add ret:%d, rule_id:%d\n",
			    vsi->idx_in_dev, ret, rule_info.rule_id);

	return ret;
}

s32 sxe2_tx_etype_rule_del(struct sxe2_adapter *adapter, u16 id_in_dev, u16 etype)
{
	s32 ret			     = 0;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_tx_etype_rule_prepare(adapter, id_in_dev, &rule_info, etype);

	ret = sxe2_switch_rule_del(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret,
			    "vsi_id:%u tx_etype_rule del ret:%d, rule_id:%d\n",
			    id_in_dev, ret, rule_info.rule_id);

	return ret;
}

s32 sxe2_rx_etype_rule_add(struct sxe2_vsi *vsi, u16 etype)
{
	s32 ret			     = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_rx_etype_rule_prepare(adapter, vsi->idx_in_dev,
				   &rule_info, etype);

	ret = sxe2_switch_rule_add(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret,
			    "vsi_id:%u rx_etype_rule add ret:%d, rule_id:%d\n",
			    vsi->idx_in_dev, ret, rule_info.rule_id);

	return ret;
}

s32 sxe2_rx_etype_rule_del(struct sxe2_adapter *adapter, u16 id_in_dev, u16 etype)
{
	s32 ret			     = 0;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_rx_etype_rule_prepare(adapter, id_in_dev, &rule_info, etype);

	ret = sxe2_switch_rule_del(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret,
			    "vsi_id:%u rx_etype_rule del ret:%d, rule_id:%d\n",
			    id_in_dev, ret, rule_info.rule_id);

	return ret;
}

s32 sxe2_etype_fltr_init(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	bool islldpagent;
	struct sxe2_adapter *adapter = vsi->adapter;

	ret = sxe2_tx_etype_rule_add(vsi, ETH_P_PAUSE);
	if (ret)
		return ret;

	if (vsi->type == SXE2_VSI_T_PF ||
	    vsi->type == SXE2_VSI_T_DPDK_PF) {
		mutex_lock(&adapter->switch_ctxt.lldp_rule_lock);
		ret = sxe2_lldp_fw_agent_status_get(vsi->adapter, &islldpagent, NULL);
		LOG_DEBUG_BDF("sxe2 lldp agent_status islldpAgent:%u, ret:%d\n", islldpagent, ret);

		if (ret || islldpagent)
			ret = sxe2_tx_etype_rule_add(vsi, ETH_P_LLDP);
		else
			ret = sxe2_rx_etype_rule_add(vsi, ETH_P_LLDP);

		mutex_unlock(&adapter->switch_ctxt.lldp_rule_lock);
		if (ret)
			return ret;
	} else if (vsi->type == SXE2_VSI_T_VF || vsi->type == SXE2_VSI_T_DPDK_VF) {
		ret = sxe2_tx_etype_rule_add(vsi, ETH_P_LLDP);
		if (ret)
			return ret;
	}
	return ret;
}

static s32 sxe2_mac_spoofchk_hid_find(struct sxe2_adapter *adapter, u16 id_in_dev, u16 *hid)
{
	s32 ret = 0;
	struct sxe2_rule_info rule_info;
	/* in order to protect the data */
	struct mutex *rule_lock;
	struct sxe2_rule_info *save_rule;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_mac_spoofchk_rule_prepare(adapter, id_in_dev, &rule_info);

	rule_lock = &adapter->switch_ctxt.recipe[SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK].rule_lock;

	mutex_lock(rule_lock);
	save_rule = sxe2_rule_entry_find(adapter, &rule_info);
	if (save_rule) {
		*hid = save_rule->hid;
	} else {
		LOG_ERROR_BDF("There is no spoofchk not root rule, can not fill hid.\n");
		ret = -ENOENT;
	}
	mutex_unlock(rule_lock);

	return ret;
}

STATIC void sxe2_mac_spoofchk_ext_rule_prepare(struct sxe2_adapter *adapter,
					       u16 vsi_id_in_dev, struct sxe2_rule_info *rule,
					       u16 hid, const u8 *mac)
{
	rule->recipe_id = SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK_EXT;
	rule->act.type = SXE2_FWD_TO_VSI;
	rule->act.fwd_id.vsi_id = vsi_id_in_dev;
	rule->is_fwd = true;

	rule->act.lb_en	 = true;
	rule->act.lan_en = true;

	ether_addr_copy(rule->fltr.data.mac_spoofchk_ext.mac_addr, mac);
	rule->fltr.data.mac_spoofchk_ext.hid = hid;
	rule->fltr.src_type = SXE2_SRC_TYPE_TX;

	LOG_DEBUG_BDF("vsi %u prepare mac spoofchk_ext rule, mac %pM, hid %04x\n",
		      vsi_id_in_dev, mac, rule->fltr.data.mac_spoofchk_ext.hid);
}

s32 sxe2_mac_spoofchk_ext_rule_add(struct sxe2_adapter *adapter,
				   u16 id_in_dev, const u8 *mac)
{
	s32 ret;
	struct sxe2_rule_info rule_info;
	u16 hid;

	memset(&rule_info, 0, sizeof(rule_info));

	ret = sxe2_mac_spoofchk_hid_find(adapter, id_in_dev, &hid);
	if (ret) {
		LOG_ERROR_BDF("vsi %u can not find mac spoofchk rule\n", id_in_dev);
		return ret;
	}

	sxe2_mac_spoofchk_ext_rule_prepare(adapter, id_in_dev, &rule_info, hid, mac);

	ret = sxe2_switch_rule_add(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret, "vsi_id:%u mac spoofchk ext rule add \t"
			    "ret:%d, rule_id:%d, hid %04x, mac %pM\n",
			    id_in_dev, ret, rule_info.rule_id,
			    rule_info.fltr.data.mac_spoofchk_ext.hid, mac);

	return ret;
}

s32 sxe2_mac_spoofchk_ext_rule_del(struct sxe2_adapter *adapter,
				   u16 id_in_dev, const u8 *mac)
{
	s32 ret;
	struct sxe2_rule_info rule_info;
	u16 hid;

	memset(&rule_info, 0, sizeof(rule_info));

	ret = sxe2_mac_spoofchk_hid_find(adapter, id_in_dev, &hid);
	if (ret) {
		LOG_ERROR_BDF("vsi %u can not find mac spoofchk rule\n", id_in_dev);
		return ret;
	}

	sxe2_mac_spoofchk_ext_rule_prepare(adapter, id_in_dev, &rule_info, hid, mac);

	ret = sxe2_switch_rule_del(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret, "vsi_id:%u mac spoofchk ext rule del \t"
			    "ret:%d, rule_id:%d, hid %04x, mac %pM\n",
			    id_in_dev, ret, rule_info.rule_id,
			    rule_info.fltr.data.mac_spoofchk_ext.hid, mac);

	return ret;
}

void sxe2_mac_spoofchk_rule_prepare(struct sxe2_adapter *adapter,
				    u16 id_in_dev, struct sxe2_rule_info *rule)
{
	rule->recipe_id = SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK;
	rule->act.type = SXE2_FWD_TO_VSI;
	rule->act.fwd_id.vsi_id = id_in_dev;
	rule->is_fwd = true;

	rule->act.lb_en	 = false;
	rule->act.lan_en = false;

	rule->fltr.data.mac_spoofchk.vsi_id = id_in_dev;
	rule->fltr.src_type = SXE2_SRC_TYPE_TX;

	LOG_DEBUG_BDF("vsi %u prepare mac spoofchk rule\n", id_in_dev);
}

s32 sxe2_mac_spoofchk_rule_add(struct sxe2_adapter *adapter,
			       u16 id_in_dev)
{
	s32 ret;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_mac_spoofchk_rule_prepare(adapter, id_in_dev, &rule_info);

	ret = sxe2_switch_rule_add(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret, "vsi_id:%u mac_spoofchk_rule add ret:%d, rule_id:%d, hid %04x\n",
			    id_in_dev, ret, rule_info.rule_id, rule_info.hid);

	return ret;
}

s32 sxe2_mac_spoofchk_rule_del(struct sxe2_adapter *adapter, u16 id_in_dev)
{
	s32 ret;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	sxe2_mac_spoofchk_rule_prepare(adapter, id_in_dev, &rule_info);

	ret = sxe2_switch_rule_del(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret, "vsi_id:%u mac_spoofchk_rule del ret:%d, rule_id:%d, hid %04x\n",
			    id_in_dev, ret, rule_info.rule_id, rule_info.hid);

	return ret;
}

static bool sxe2_profile_is_empty(u16 profile_id, struct sxe2_adapter *adapter)
{
	struct sxe2_profile_fv_item fv_item[SXE2_SWITCH_PROFILE_FV_CNT];

	memset(fv_item, 0, sizeof(fv_item));

	if (memcmp(adapter->switch_ctxt.profile_fv_item[profile_id], fv_item,
		   sizeof(fv_item)) == 0)
		return true;
	return false;
}

static bool sxe2_profile_tunnel_check(u16 profile_id,
				      struct sxe2_tcf_fltr *fltr)
{
	s32 i;
	struct sxe2_profile_fv_item fv_item;
	struct sxe2_adapter *adapter = fltr->adapter;

	if (fltr->tunnel_type == SXE2_TNL_ALL)
		return true;

	for (i = 0; i < SXE2_SWITCH_PROFILE_FV_CNT; i++) {
		fv_item = adapter->switch_ctxt.profile_fv_item[profile_id][i];
		if (fv_item.prot_id == SXE2_UDP_OL_HW &&
		    fv_item.offset == SXE2_PROT_OFFSET_VNI && fv_item.enable) {
			if (fltr->tunnel_type == SXE2_TNL_VXLAN ||
			    fltr->tunnel_type == SXE2_TNL_GENEVE)
				return true;
			else
				return false;
		} else if (fv_item.prot_id == SXE2_GRE_HW && fv_item.enable) {
			if (fltr->tunnel_type == SXE2_TNL_GRETAP)
				return true;
			else
				return false;
		}
	}

	if (fltr->tunnel_type == SXE2_TNL_NONE)
		return true;
	return false;
}

s32 sxe2_sw_profile_parse_from_ddp(u8 *data, u16 cnt, u16 base_id,
				   struct sxe2_adapter *adapter)
{
	u16 i;
	u32 j;
	u16 profile_id;
	struct sxe2_profile_fv_item *ddp_profile_fv_item = NULL;

	if (!cnt || (base_id + cnt > (SXE2_PROFILE_MAX_COUNT - 1))) {
		LOG_ERROR_BDF("cnt:%u base_id:%u invalid.\n", cnt, base_id);
		return -EINVAL;
	}

	for (i = 0; i < cnt; i++) {
		profile_id = base_id + i;
		for (j = 0; j < SXE2_SWITCH_PROFILE_FV_CNT; j++) {
			ddp_profile_fv_item = (struct sxe2_profile_fv_item *)(((u32 *)data) +
					    (u64)i * SXE2_SWITCH_PROFILE_FV_CNT + j);
			memcpy(&adapter->switch_ctxt.profile_fv_item[profile_id][j],
			       ddp_profile_fv_item,
			       sizeof(struct sxe2_profile_fv_item));
		}
	}

	return 0;
}

static s32 sxe2_profile_fv_check(u16 profile_id, struct sxe2_tcf_fltr *fltr,
				 bool *match)
{
	struct sxe2_adapter *adapter = fltr->adapter;
	struct sxe2_tcf_key_item *item;
	s32 fv_idx;
	bool find;
	struct sxe2_profile_fv_item fv_item;
	u16 i, j, k;

	*match = false;

	fv_idx = 0;
	for (i = 0; i < SXE2_PROT_FIELD_LAST; i++) {
		if (sxe2_tcf_item_is_empty(fltr, i))
			continue;

		item = &fltr->items[i];
		for (j = 0; j < ARRAY_SIZE(item->mask.raw); j++) {
			if (!item->mask.raw[j])
				continue;
			find = false;
			for (k = 0; k < SXE2_SWITCH_PROFILE_FV_CNT; k++) {
				fv_item = adapter->switch_ctxt.profile_fv_item[profile_id][k];
				if (fv_item.enable &&
				    fv_item.prot_id == sxe2_prot_id_tbl[i].prot_id &&
				    (fv_item.offset == sizeof(u16) * j)) {
					find = true;
					if (fltr->lkup_mask[fv_idx] &&
					    (fltr->lkup_index[fv_idx] != k + 1)) {
						LOG_ERROR_BDF("profile fv conflict profile id %d\n",
							      profile_id);
						return -EIO;
					}
					fltr->lkup_value[fv_idx] = item->value.raw[j];
					fltr->lkup_mask[fv_idx] = item->mask.raw[j];
					fltr->lkup_index[fv_idx++] = k + 1;
					break;
				}
			}

			if (!find)
				return 0;
		}
	}

	*match = true;
	return 0;
}

void sxe2_tc_item_print(struct sxe2_tcf_fltr *user_cpx_fltr);

s32 sxe2_tcf_profile_find(struct sxe2_tcf_fltr *fltr)
{
	u16 prof_id, i;
	struct sxe2_adapter *adapter = fltr->adapter;
	s32 ret;
	bool match;

	sxe2_tc_item_print(fltr);

	for (prof_id = 0; prof_id < SXE2_MAX_NUM_PROFILES; prof_id++) {
		if (sxe2_profile_is_empty(prof_id, adapter))
			continue;

		if (!sxe2_profile_tunnel_check(prof_id, fltr))
			continue;

		ret = sxe2_profile_fv_check(prof_id, fltr, &match);
		if (ret)
			return ret;

		if (match) {
			set_bit(prof_id, fltr->profiles);
			LOG_DEBUG_BDF("profile id %d match\n", prof_id);
		}
	}

	if (bitmap_weight(fltr->profiles, SXE2_MAX_NUM_PROFILES) == 0) {
		LOG_ERROR_BDF("no profile can match request\n");
		return -EINVAL;
	}

	for (i = 0; i < SXE2_MAX_REPLY_RECIPE; i++) {
		LOG_DEBUG_BDF("lkup_mask 0x%x, 0x%x, 0x%x, 0x%x\n",
			      fltr->lkup_mask[i * SXE2_NUM_WORDS_RECIPE + 0],
			      fltr->lkup_mask[i * SXE2_NUM_WORDS_RECIPE + 1],
			      fltr->lkup_mask[i * SXE2_NUM_WORDS_RECIPE + 2],
			      fltr->lkup_mask[i * SXE2_NUM_WORDS_RECIPE + 3]);
		LOG_DEBUG_BDF("lkup_value %d, %d, %d, %d\n",
			      fltr->lkup_value[i * SXE2_NUM_WORDS_RECIPE + 0],
			      fltr->lkup_value[i * SXE2_NUM_WORDS_RECIPE + 1],
			      fltr->lkup_value[i * SXE2_NUM_WORDS_RECIPE + 2],
			      fltr->lkup_value[i * SXE2_NUM_WORDS_RECIPE + 3]);
		LOG_DEBUG_BDF("lkup_index %d, %d, %d, %d\n",
			      fltr->lkup_index[i * SXE2_NUM_WORDS_RECIPE + 0],
			      fltr->lkup_index[i * SXE2_NUM_WORDS_RECIPE + 1],
			      fltr->lkup_index[i * SXE2_NUM_WORDS_RECIPE + 2],
			      fltr->lkup_index[i * SXE2_NUM_WORDS_RECIPE + 3]);
	}

	return 0;
}

void sxe2_tcf_match_meta_fill(struct sxe2_tcf_fltr *fltr)
{
	struct sxe2_tcf_key_item *item;

	if (fltr->src_type == SXE2_SRC_TYPE_RX) {
		item = &fltr->items[SXE2_META_PKT_SRC];
		item->value.raw[SXE2_META_PKT_SRC_OFFSET] =
			cpu_to_be16((u16)(SXE2_FV_PKT_SRC_RX << SXE2_FV_PKT_SRC_OFFSET));
		item->mask.raw[SXE2_META_PKT_SRC_OFFSET] =
			cpu_to_be16((u16)SXE2_FV_PKT_SRC_MASK);
	} else {
		item = &fltr->items[SXE2_META_VSI_NUM];
		item->value.raw[SXE2_META_VSI_NUM_OFFSET] =
			cpu_to_be16(fltr->src_vsi_id << SXE2_FV_VSI_NUM_OFFSET);
		item->mask.raw[SXE2_META_VSI_NUM_OFFSET] =
			cpu_to_be16((u16)SXE2_FV_VSI_NUM_MASK);
		if (fltr->action == SXE2_MIRROR_PACKET) {
			item = &fltr->items[SXE2_META_PKT_SRC];
			item->value.raw[SXE2_META_PKT_SRC_OFFSET] =
				cpu_to_be16((u16)(SXE2_FV_PKT_SRC_TX << SXE2_FV_PKT_SRC_OFFSET));
			item->mask.raw[SXE2_META_PKT_SRC_OFFSET] =
				cpu_to_be16((u16)SXE2_FV_PKT_SRC_MASK);
		}
	}
}

STATIC s32 sxe2_tcf_rule_prepare(struct sxe2_adapter *adapter,
				 struct sxe2_tcf_fltr *fltr,
				 struct sxe2_rule_info *rule)
{
	s32 ret = 0;
	u16 idx = 0;

	rule->tcf_fltr = fltr;
	rule->is_fwd = true;
	rule->act.type = fltr->action;
	if (fltr->action == SXE2_FWD_TO_Q) {
		rule->act.fwd_id.q_id = fltr->dst_queue_id;
		rule->act.q_high = fltr->dst_queue_high;
	} else if (fltr->action == SXE2_FWD_TO_QGRP) {
		rule->act.fwd_id.q_id = fltr->dst_queue_id;
		rule->act.qgrp_size = fltr->dst_queue_group;
		rule->act.q_high = fltr->dst_queue_high;
	} else if (fltr->action == SXE2_FWD_TO_VSI) {
		rule->act.fwd_id.vsi_id = fltr->dst_vsi_id;
	} else if (fltr->action == SXE2_MIRROR_PACKET) {
		rule->act.fwd_id.vsi_id = fltr->dst_vsi_id;
	} else if (fltr->action == SXE2_LARGE_ACTION) {
		rule->act.fwd_id.vsi_id = fltr->dst_vsi_id;
	} else {
		LOG_DEBUG_BDF("action %d\n", fltr->action);
	}

	if (fltr->src_type == SXE2_SRC_TYPE_RX) {
		rule->act.lb_en  = false;
		rule->act.lan_en = false;
	} else {
		rule->act.lb_en  = true;
		rule->act.lan_en = false;

		sxe2_for_each_vsi(&adapter->vsi_ctxt, idx) {
			struct sxe2_vsi *vsi = adapter->vsi_ctxt.vsi[idx];

			if (!adapter->vsi_ctxt.vsi[idx])
				continue;

			if (vsi->type == SXE2_VSI_T_DPDK_PF ||
			    vsi->type == SXE2_VSI_T_PF) {
				if (fltr->dst_vsi_id == vsi->idx_in_dev) {
					rule->act.lb_en  = false;
					rule->act.lan_en = true;
					break;
				}

				if (fltr->action == SXE2_FWD_TO_VSI_LIST) {
					if (test_bit(vsi->idx_in_dev,
						     fltr->dst_vsi_map)) {
						ret = -EINVAL;
						LOG_SWITCH_RULE_OPT(ret, "vsi list action\t"
								    "include pf vsi %d\n",
								    vsi->idx_in_dev);
						goto l_end;
					}
				}
			}
		}

		if (fltr->action == SXE2_MIRROR_PACKET) {
			rule->act.lb_en  = false;
			rule->act.lan_en = false;
		}
		if (fltr->action == SXE2_LARGE_ACTION) {
			rule->act.lb_en  = false;
			rule->act.lan_en = false;
		}
	}
	LOG_DEBUG_BDF("dst_id %d, lb_en %d, lan_en %d\n", rule->act.fwd_id.q_id,
		      rule->act.lb_en, rule->act.lan_en);
l_end:
	return ret;
}

s32 sxe2_tcf_rule_add(struct sxe2_adapter *adapter,
		      u16 vsi_id_in_dev, struct sxe2_tcf_fltr *fltr)
{
	s32 ret;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));

	ret = sxe2_tcf_rule_prepare(adapter, fltr, &rule_info);
	if (ret)
		return ret;

	ret = sxe2_switch_rule_add(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret, "vsi_id:%u tc_rule cookie %lu add ret:%d, rule_id:%d\n",
			    vsi_id_in_dev, fltr->cookie, ret, rule_info.rule_id);

	return ret;
}

s32 sxe2_tcf_rule_del(struct sxe2_adapter *adapter,
		      u16 vsi_id_in_dev, struct sxe2_tcf_fltr *fltr)
{
	s32 ret;
	struct sxe2_rule_info rule_info;

	memset(&rule_info, 0, sizeof(rule_info));
	ret = sxe2_tcf_rule_prepare(adapter, fltr, &rule_info);
	if (ret)
		return ret;

	ret = sxe2_switch_rule_del(adapter, &rule_info);
	LOG_SWITCH_RULE_OPT(ret, "vsi_id:%u tc_rule cookie %lu del ret:%d, rule_id:%d\n",
			    vsi_id_in_dev, fltr->cookie, ret, rule_info.rule_id);

	return ret;
}

void sxe2_vsi_l2_fltr_clean(struct sxe2_vsi *vsi)
{
	struct sxe2_switch_context *switch_ctxt = &vsi->adapter->switch_ctxt;
	struct list_head *list_head;
	struct list_head *vsi_list_head;
	struct sxe2_rule_info *list_itr		= NULL;
	struct sxe2_rule_info *list_tmp		= NULL;
	struct sxe2_vsi_list_info *vsi_list	= NULL;
	struct sxe2_vsi_list_info *vsi_list_tmp = NULL;
	s32 recipe_id;
	s32 i;
	enum sxe2_vsi_list_type vsi_list_type;
	/* in order to protect the data */
	struct mutex *rule_lock;
	/* in order to protect the data */
	struct mutex *vsi_list_lock;
	s32 vsi_cnt;
	u16 vsi_left;

	for (recipe_id = 0; recipe_id < SXE2_DEFAULT_RECIPE_MAX; recipe_id++) {
		if (recipe_id != SXE2_DEFAULT_RECIPE_VLAN)
			vsi_list_type = SXE2_VSI_LIST_TYPE_FORWARD;
		else
			vsi_list_type = SXE2_VSI_LIST_TYPE_PRUNE;

		list_head = &switch_ctxt->recipe[recipe_id].rule_head;
		rule_lock = &switch_ctxt->recipe[recipe_id].rule_lock;
		vsi_list_lock = &switch_ctxt->vsi_list_mgmt[vsi_list_type].vsi_list_lock;
		mutex_lock(rule_lock);
		mutex_lock(vsi_list_lock);
		list_for_each_entry_safe(list_itr, list_tmp, list_head,
					 list_entry) {
			if (recipe_id == SXE2_DEFAULT_RECIPE_SRCVSI_EXT) {
				if (list_itr->act.fwd_id.vsi_id == vsi->idx_in_dev ||
				    list_itr->fltr.data.srcvsi.vsi_id == vsi->idx_in_dev){
					list_del(&list_itr->list_entry);
					kfree(list_itr);
					list_itr = NULL;
					continue;
				}
			}
			if ((list_itr->act.type == SXE2_FWD_TO_VSI ||
			     list_itr->act.type == SXE2_DROP_PACKET) &&
			    list_itr->act.fwd_id.vsi_id == vsi->idx_in_dev) {
				list_del(&list_itr->list_entry);
				kfree(list_itr);
				list_itr = NULL;
			} else if (list_itr->act.type == SXE2_FWD_TO_VSI_LIST &&
				   test_bit(vsi->idx_in_dev, list_itr->vsi_list->vsi_map)) {
				clear_bit(vsi->idx_in_dev, list_itr->vsi_list->vsi_map);
				vsi_cnt = bitmap_weight(list_itr->vsi_list->vsi_map,
							SXE2_VSI_MAX_CNT);
				if (vsi_list_type == SXE2_VSI_LIST_TYPE_FORWARD && vsi_cnt == 1) {
					list_itr->act.type = SXE2_FWD_TO_VSI;
					vsi_left = (u16)find_first_bit(list_itr->vsi_list->vsi_map,
								       SXE2_VSI_MAX_CNT);
					list_itr->act.fwd_id.vsi_id = vsi_left;
					list_itr->vsi_list	    = NULL;
				} else if (vsi_list_type == SXE2_VSI_LIST_TYPE_PRUNE &&
					   vsi_cnt == 0) {
					list_del(&list_itr->list_entry);
					kfree(list_itr);
					list_itr = NULL;
				}
			} else if (vsi_list_type == SXE2_VSI_LIST_TYPE_PRUNE &&
				   list_itr->act.type == SXE2_FWD_TO_VSI_LIST &&
				   bitmap_weight(list_itr->vsi_list->vsi_map,
						 SXE2_VSI_MAX_CNT) == 0) {
				list_del(&list_itr->list_entry);
				kfree(list_itr);
				list_itr = NULL;
			} else if (vsi_list_type == SXE2_VSI_LIST_TYPE_FORWARD &&
				   list_itr->act.type == SXE2_FWD_TO_VSI_LIST &&
				   bitmap_weight(list_itr->vsi_list->vsi_map,
						 SXE2_VSI_MAX_CNT) == 1) {
				list_itr->act.type = SXE2_FWD_TO_VSI;
				vsi_left = (u16)find_first_bit(list_itr->vsi_list->vsi_map,
							       SXE2_VSI_MAX_CNT);
				list_itr->act.fwd_id.vsi_id = vsi_left;
				list_itr->vsi_list	    = NULL;
			}
		}
		mutex_unlock(vsi_list_lock);
		mutex_unlock(rule_lock);
	}

	for (i = 0; i < SXE2_VSI_LIST_TYPE_MAX; i++) {
		vsi_list_head = &switch_ctxt->vsi_list_mgmt[i].vsi_list_head;
		vsi_list_lock = &switch_ctxt->vsi_list_mgmt[i].vsi_list_lock;
		mutex_lock(vsi_list_lock);
		list_for_each_entry_safe(vsi_list, vsi_list_tmp, vsi_list_head, list_entry) {
			if (i == SXE2_VSI_LIST_TYPE_FORWARD &&
			    bitmap_weight(vsi_list->vsi_map, SXE2_VSI_MAX_CNT) == 1) {
				list_del(&vsi_list->list_entry);
				kfree(vsi_list);
				vsi_list = NULL;
			} else if (i == SXE2_VSI_LIST_TYPE_PRUNE &&
				   bitmap_weight(vsi_list->vsi_map, SXE2_VSI_MAX_CNT) == 0) {
				list_del(&vsi_list->list_entry);
				kfree(vsi_list);
				vsi_list = NULL;
			}
		}
		mutex_unlock(vsi_list_lock);
	}
}

void sxe2_vsi_complex_fltr_clean(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter		= vsi->adapter;
	struct sxe2_switch_context *switch_ctxt = &vsi->adapter->switch_ctxt;
	struct sxe2_rule_info *rule_info = NULL;
	struct sxe2_tcf_fltr *tcf_fltr;
	/* in order to protect the data */
	struct mutex *rule_lock;
	/* in order to protect the data */
	struct mutex *vsi_list_lock;
	u32 bkt;
	struct hlist_node *temp;

	rule_lock     = &switch_ctxt->complex_recipe.rule_lock;
	vsi_list_lock = &switch_ctxt->vsi_list_mgmt[SXE2_VSI_LIST_TYPE_FORWARD].vsi_list_lock;
	mutex_lock(rule_lock);
	mutex_lock(vsi_list_lock);
	hash_for_each_safe(adapter->switch_ctxt.complex_recipe.ht_lkup, bkt, temp, tcf_fltr, node) {
		if (tcf_fltr->src_vsi_id == vsi->idx_in_dev) {
			rule_info = tcf_fltr->rule_info;
			sxe2_hash_cookie_del(adapter, tcf_fltr->cookie);
			sxe2_hash_lkup_del(adapter, tcf_fltr);
			LOG_DEBUG_BDF("clean rule success, rule id %u\n",
				      rule_info->rule_id);
			sxe2_switch_sw_rule_free(adapter, rule_info);
		}
	}

	mutex_unlock(vsi_list_lock);
	mutex_unlock(rule_lock);
}

void sxe2_vsi_fltr_clean(struct sxe2_vsi *vsi)
{
	sxe2_vsi_l2_fltr_clean(vsi);
	sxe2_vsi_complex_fltr_clean(vsi);
}

void sxe2_vsi_l2_fltr_remove(struct sxe2_adapter *adapter, u16 id_in_dev)
{
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct list_head *list_head;
	struct sxe2_rule_info *list_itr = NULL;
	struct sxe2_rule_info *tmp	= NULL;
	struct sxe2_vsi_list_info *vsi_list;
	struct sxe2_vlan vlan;
	s32 status;
	s32 recipe_id;
	u16 rule_id;
	struct list_head del_head;
	/* in order to protect the data */
	struct mutex *rule_lock;
	/* in order to protect the data */
	struct mutex *vsi_list_lock;
	enum sxe2_vsi_list_type vsi_list_type;

	INIT_LIST_HEAD(&del_head);
	for (recipe_id = 0; recipe_id < SXE2_DEFAULT_RECIPE_MAX; recipe_id++) {
		if (recipe_id != SXE2_DEFAULT_RECIPE_VLAN)
			vsi_list_type = SXE2_VSI_LIST_TYPE_FORWARD;
		else
			vsi_list_type = SXE2_VSI_LIST_TYPE_PRUNE;

		list_head = &switch_ctxt->recipe[recipe_id].rule_head;
		rule_lock = &switch_ctxt->recipe[recipe_id].rule_lock;
		vsi_list_lock = &switch_ctxt->vsi_list_mgmt[vsi_list_type].vsi_list_lock;
		mutex_lock(rule_lock);
		mutex_lock(vsi_list_lock);

		list_for_each_entry(list_itr, list_head, list_entry) {
			vsi_list = list_itr->vsi_list;
			if ((!vsi_list && list_itr->act.fwd_id.vsi_id == id_in_dev) ||
			    (vsi_list && test_bit(id_in_dev, vsi_list->vsi_map))) {
				tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);
				if (!tmp) {
					LOG_ERROR_BDF("alloc memory failed\n");
					mutex_unlock(vsi_list_lock);
					mutex_unlock(rule_lock);
					goto l_free;
				}
				memcpy(tmp, list_itr, sizeof(*list_itr));
				list_add(&tmp->list_entry, &del_head);
			}
		}
		mutex_unlock(vsi_list_lock);
		mutex_unlock(rule_lock);
	}

	list_for_each_entry(list_itr, &del_head, list_entry) {
		recipe_id = list_itr->recipe_id;
		rule_id	  = list_itr->rule_id;
		if (list_itr->recipe_id == SXE2_DEFAULT_RECIPE_MAC) {
			status = sxe2_mac_rule_del(adapter,
						   id_in_dev, list_itr->fltr.data.mac.mac_addr);
		} else if (list_itr->recipe_id == SXE2_DEFAULT_RECIPE_VLAN) {
			vlan.vid  = list_itr->fltr.data.vlan.vlan_id;
			vlan.tpid = list_itr->fltr.data.vlan.tpid;
			status	  = sxe2_vlan_rule_del(adapter, id_in_dev, &vlan);
		} else if (list_itr->recipe_id == SXE2_DEFAULT_RECIPE_TX_ETYPE) {
			status = sxe2_tx_etype_rule_del(adapter, id_in_dev,
							list_itr->fltr.data.etype.ethertype);
		} else if (list_itr->recipe_id == SXE2_DEFAULT_RECIPE_RX_ETYPE) {
			status = sxe2_rx_etype_rule_del(adapter, id_in_dev,
							list_itr->fltr.data.etype.ethertype);
		} else if (list_itr->recipe_id == SXE2_DEFAULT_RECIPE_ALLMULTI) {
			status = sxe2_allmulti_rule_del(adapter, id_in_dev);
		} else if (list_itr->recipe_id == SXE2_DEFAULT_RECIPE_PROMISC) {
			status = sxe2_promisc_rule_del(adapter, id_in_dev);
		} else if (list_itr->recipe_id == SXE2_DEFAULT_RECIPE_SRCVSI) {
			status = sxe2_srcvsi_rule_del(adapter, id_in_dev);
		} else if (list_itr->recipe_id == SXE2_DEFAULT_RECIPE_SRCVSI_EXT) {
			status = sxe2_srcvsi_ext_rule_del(adapter, id_in_dev);
		} else if (list_itr->recipe_id == SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK) {
			status = sxe2_mac_spoofchk_rule_del(adapter, id_in_dev);
		} else if (list_itr->recipe_id == SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK_EXT) {
			struct sxe2_rule_filter *fltr = &list_itr->fltr;

			status =
			 sxe2_mac_spoofchk_ext_rule_del(adapter, id_in_dev,
							fltr->data.mac_spoofchk_ext.mac_addr);
		} else {
			continue;
		}

		if (status && status != -ENOENT) {
			LOG_ERROR_BDF("remove l2 rule failure, recipe id %d, rule id %u\n",
				      recipe_id, rule_id);
		}
	}

l_free:
	list_for_each_entry_safe(list_itr, tmp, &del_head, list_entry) {
		list_del(&list_itr->list_entry);
		kfree(list_itr);
		list_itr = NULL;
	}
}

void sxe2_vsi_complex_fltr_remove(struct sxe2_adapter *adapter,
				  u16 id_in_dev, bool to_restore)
{
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct list_head *restore_head;
	/* in order to protect the data */
	struct mutex *rule_lock;
	/* in order to protect the data */
	struct mutex *vsi_list_lock;
	s32 ret = 0;
	struct sxe2_tcf_fltr *tcf_fltr;
	u32 bkt;
	struct hlist_node *temp;

	rule_lock     = &switch_ctxt->complex_recipe.rule_lock;
	restore_head  = &switch_ctxt->complex_recipe.restore_head;
	vsi_list_lock = &switch_ctxt->vsi_list_mgmt[SXE2_VSI_LIST_TYPE_FORWARD].vsi_list_lock;
	mutex_lock(rule_lock);
	mutex_lock(vsi_list_lock);
	hash_for_each_safe(adapter->switch_ctxt.complex_recipe.ht_lkup, bkt, temp, tcf_fltr, node) {
		if (tcf_fltr->src_vsi_id == id_in_dev ||
		    (tcf_fltr->is_user_rule &&
		     tcf_fltr->rule_vsi_id == id_in_dev)) {
			ret = sxe2_fwd_rule_remove(adapter, tcf_fltr->rule_info, false);
			if (ret) {
				LOG_ERROR_BDF("complex rule delete fail, ret %d\n", ret);
				break;
			}

			if (to_restore)
				list_add(&tcf_fltr->rule_info->list_entry, restore_head);
			else
				sxe2_switch_sw_rule_free(adapter, tcf_fltr->rule_info);
		}
	}
	mutex_unlock(vsi_list_lock);
	mutex_unlock(rule_lock);
}

void sxe2_vsi_fltr_remove(struct sxe2_adapter *adapter, u16 id_in_dev)
{
	sxe2_vsi_l2_fltr_remove(adapter, id_in_dev);
	sxe2_vsi_complex_fltr_remove(adapter, id_in_dev, false);
}

s32 sxe2_rule_bridge_mode_update(struct sxe2_adapter *adapter)
{
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct list_head *list_head;
	/* in order to protect the data */
	struct mutex *rule_lock;
	/* in order to protect the data */
	struct mutex *vsi_list_lock;
	struct sxe2_rule_info *rule_info = NULL;
	s32 ret				 = 0;

	list_head     = &switch_ctxt->recipe[SXE2_DEFAULT_RECIPE_MAC].rule_head;
	rule_lock     = &switch_ctxt->recipe[SXE2_DEFAULT_RECIPE_MAC].rule_lock;
	vsi_list_lock = &switch_ctxt->vsi_list_mgmt[SXE2_VSI_LIST_TYPE_FORWARD].vsi_list_lock;

	mutex_lock(rule_lock);
	mutex_lock(vsi_list_lock);
	list_for_each_entry(rule_info, list_head, list_entry) {
		u8 *addr = rule_info->fltr.data.mac.mac_addr;

		if (is_unicast_ether_addr(addr)) {
			if (adapter->switch_ctxt.evb_mode == BRIDGE_MODE_VEB)
				rule_info->act.lan_en = false;
			else
				rule_info->act.lan_en = true;

			ret = sxe2_fwd_rule_update(adapter, rule_info);
			if (ret)
				break;
		}
	}
	mutex_unlock(vsi_list_lock);
	mutex_unlock(rule_lock);

	return ret;
}

static s32 sxe2_switch_restore_list_fill(struct sxe2_adapter *adapter,
					 struct sxe2_rule_info *rule,
					 struct list_head *rule_head)
{
	s32 weight;
	s32 i;
	u16 vsi_id;
	struct sxe2_vsi_list_info *vsi_list;
	struct sxe2_rule_info *new_rule;
	struct sxe2_vsi *vsi;

	vsi_list = rule->vsi_list;
	if (!vsi_list) {
		list_del(&rule->list_entry);
		vsi = sxe2_vsi_get_by_idx(adapter, rule->act.fwd_id.vsi_id);
		if (vsi->type == SXE2_VSI_T_PF)
			list_add(&rule->list_entry, rule_head);
		else
			kfree(rule);
	} else {
		weight = bitmap_weight(vsi_list->vsi_map, SXE2_VSI_MAX_CNT);
		if (!weight || weight >= SXE2_VSI_MAX_CNT) {
			list_del(&rule->list_entry);
			kfree(rule);
			return 0;
		}
		for (i = 0, vsi_id = 0; i < weight; i++, vsi_id++) {
			vsi_id = (u16)find_next_bit(vsi_list->vsi_map,
						    SXE2_VSI_MAX_CNT, vsi_id);
			vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
			if (vsi && vsi->type == SXE2_VSI_T_PF) {
				new_rule = kzalloc(sizeof(*rule), GFP_KERNEL);
				if (!new_rule)
					return -ENOMEM;

				memcpy(new_rule, rule, sizeof(*rule));
				new_rule->vsi_list	    = NULL;
				new_rule->act.fwd_id.vsi_id = vsi_id;
				new_rule->act.type	    = SXE2_FWD_TO_VSI;
				list_add(&new_rule->list_entry, rule_head);
			}
		}
		list_del(&rule->list_entry);
		kfree(rule);
	}

	return 0;
}

s32 sxe2_switch_fltr_restore_prepare(struct sxe2_adapter *adapter)
{
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct list_head *list_head;
	struct list_head *restore_head;
	struct sxe2_vsi_list_info *vsi_list;
	struct sxe2_vsi_list_info *vsi_list_tmp;
	struct sxe2_rule_info *rule;
	struct sxe2_rule_info *rule_tmp;
	/* in order to protect the data */
	struct mutex *list_lock;
	s32 i;
	s32 ret = 0;
	struct sxe2_tcf_fltr *tcf_fltr;
	u32 bkt;
	struct hlist_node *temp;

	for (i = 0; i < SXE2_DEFAULT_RECIPE_MAX; i++) {
		list_head    = &switch_ctxt->recipe[i].rule_head;
		restore_head = &switch_ctxt->recipe[i].restore_head;
		list_lock    = &switch_ctxt->recipe[i].rule_lock;

		if (i == SXE2_DEFAULT_RECIPE_SRCVSI_EXT)
			continue;

		mutex_lock(list_lock);
		list_for_each_entry_safe(rule, rule_tmp, list_head, list_entry) {
			ret = sxe2_switch_restore_list_fill(adapter, rule,
							    restore_head);
			if (ret) {
				mutex_unlock(list_lock);
				return ret;
			}
		}
		mutex_unlock(list_lock);
	}

	list_head    = &switch_ctxt->complex_recipe.rule_head;
	restore_head = &switch_ctxt->complex_recipe.restore_head;
	list_lock    = &switch_ctxt->complex_recipe.rule_lock;
	mutex_lock(list_lock);
	hash_for_each_safe(adapter->switch_ctxt.complex_recipe.ht_lkup, bkt, temp, tcf_fltr, node) {
		rule = tcf_fltr->rule_info;

		if (!tcf_fltr->cookie_invalid)
			sxe2_hash_cookie_del(adapter, tcf_fltr->cookie);

		sxe2_hash_lkup_del(adapter, tcf_fltr);
		if (!rule->tcf_fltr->cookie_invalid)
			list_add(&rule->list_entry, restore_head);
		else
			sxe2_switch_sw_rule_free(adapter, rule);
	}
	mutex_unlock(list_lock);

	for (i = 0; i < SXE2_VSI_LIST_TYPE_MAX; i++) {
		list_head = &switch_ctxt->vsi_list_mgmt[i].vsi_list_head;
		list_lock = &switch_ctxt->vsi_list_mgmt[i].vsi_list_lock;

		mutex_lock(list_lock);
		list_for_each_entry_safe(vsi_list, vsi_list_tmp, list_head, list_entry) {
			list_del(&vsi_list->list_entry);
			kfree(vsi_list);
			vsi_list = NULL;
		}
		mutex_unlock(list_lock);
	}

	return 0;
}

void sxe2_switch_fltr_restore_clean(struct sxe2_adapter *adapter)
{
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct list_head *list_head;
	/* in order to protect the data */
	struct mutex *list_lock;
	struct sxe2_rule_info *rule;
	struct sxe2_rule_info *rule_tmp;
	s32 i;

	for (i = 0; i < SXE2_DEFAULT_RECIPE_MAX; i++) {
		list_head = &switch_ctxt->recipe[i].restore_head;

		list_lock = &switch_ctxt->recipe[i].rule_lock;
		mutex_lock(list_lock);
		list_for_each_entry_safe(rule, rule_tmp, list_head, list_entry) {
			list_del(&rule->list_entry);
			sxe2_switch_sw_rule_free(adapter, rule);
		}
		mutex_unlock(list_lock);
	}

	list_head = &switch_ctxt->complex_recipe.restore_head;
	list_lock = &switch_ctxt->complex_recipe.rule_lock;
	mutex_lock(list_lock);
	list_for_each_entry_safe(rule, rule_tmp, list_head, list_entry) {
		list_del(&rule->list_entry);
		sxe2_switch_sw_rule_free(adapter, rule);
	}
	mutex_unlock(list_lock);
}

STATIC s32 sxe2_vsi_lldp_fltr_update(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	bool islldpagent;
	s32 recipe_id;
	struct list_head *list_head;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_switch_context *switch_ctxt = &vsi->adapter->switch_ctxt;
	struct sxe2_rule_info *rule;
	struct sxe2_rule_info *rule_tmp;
	struct sxe2_rule_info *rule_tx_lldp = NULL;
	struct sxe2_rule_info *rule_rx_lldp = NULL;

	ret = sxe2_lldp_agent_event_init(adapter);
	if (ret) {
		LOG_ERROR_BDF("lldp event initfailed: %d\n", ret);
		goto l_out;
	}

	mutex_lock(&switch_ctxt->lldp_rule_lock);
	ret = sxe2_lldp_fw_agent_status_get(vsi->adapter, &islldpagent, NULL);
	if (ret) {
		LOG_ERROR_BDF("lldp status get failed:%d\n", ret);
		goto l_unlock;
	}
	LOG_DEBUG_BDF("sxe2 lldp agent status islldpAgent:%u\n", islldpagent);

	for (recipe_id = 0; recipe_id < SXE2_DEFAULT_RECIPE_MAX; recipe_id++) {
		if (recipe_id == SXE2_DEFAULT_RECIPE_TX_ETYPE ||
		    recipe_id == SXE2_DEFAULT_RECIPE_RX_ETYPE) {
			list_head = &switch_ctxt->recipe[recipe_id].rule_head;
			list_for_each_entry_safe(rule, rule_tmp, list_head, list_entry) {
				if (rule->act.fwd_id.vsi_id != vsi->idx_in_dev)
					continue;
				if (recipe_id == SXE2_DEFAULT_RECIPE_TX_ETYPE &&
				    rule->fltr.data.etype.ethertype == ETH_P_LLDP) {
					rule_tx_lldp = rule;
				} else if (recipe_id == SXE2_DEFAULT_RECIPE_RX_ETYPE &&
					   rule->fltr.data.etype.ethertype == ETH_P_LLDP) {
					rule_rx_lldp = rule;
				}
			}
		}
	}

	if (islldpagent) {
		if (!rule_tx_lldp) {
			ret = sxe2_tx_etype_rule_add(vsi, ETH_P_LLDP);
			if (ret) {
				LOG_ERROR_BDF("failed to add tx lldp rule, \t"
					      "lldp fltr update failed:%d\n", ret);
				goto l_unlock;
			}
		}
		if (rule_rx_lldp) {
			ret = sxe2_rx_etype_rule_del(adapter, vsi->idx_in_dev, ETH_P_LLDP);
			if (ret) {
				LOG_ERROR_BDF("failed to del rx lldp rule, \t"
					      "lldp fltr update failed:%d\n", ret);
				goto l_unlock;
			}
		}
	} else {
		if (rule_tx_lldp) {
			ret = sxe2_tx_etype_rule_del(adapter, vsi->idx_in_dev, ETH_P_LLDP);
			if (ret) {
				LOG_ERROR_BDF("failed to del tx lldp rule, \t"
					      "lldp fltr update failed:%d\n", ret);
				goto l_unlock;
			}
		}
		if (!rule_rx_lldp) {
			ret = sxe2_rx_etype_rule_add(vsi, ETH_P_LLDP);
			if (ret) {
				LOG_ERROR_BDF("failed to add rx lldp rule, \t"
					      "lldp fltr update failed:%d\n", ret);
				goto l_unlock;
			}
		}
	}

l_unlock:
	mutex_unlock(&switch_ctxt->lldp_rule_lock);

l_out:

	return ret;
}

s32 sxe2_vsi_l2_fltr_restore(struct sxe2_vsi *vsi)
{
	s32 ret					= 0;
	struct sxe2_adapter *adapter		= vsi->adapter;
	struct sxe2_switch_context *switch_ctxt = &vsi->adapter->switch_ctxt;
	struct list_head *list_head;
	struct sxe2_rule_info *rule;
	struct sxe2_rule_info *rule_tmp;
	struct sxe2_vlan vlan;
	s32 recipe_id;

	for (recipe_id = 0; recipe_id < SXE2_DEFAULT_RECIPE_MAX; recipe_id++) {
		list_head = &switch_ctxt->recipe[recipe_id].restore_head;

		list_for_each_entry_safe(rule, rule_tmp, list_head, list_entry) {
			if (rule->act.fwd_id.vsi_id != vsi->idx_in_dev)
				continue;
			if (rule->recipe_id == SXE2_DEFAULT_RECIPE_MAC) {
				ret = sxe2_mac_rule_add(vsi, rule->fltr.data.mac.mac_addr);
			} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_VLAN) {
				vlan.vid  = rule->fltr.data.vlan.vlan_id;
				vlan.tpid = rule->fltr.data.vlan.tpid;
				ret	  = sxe2_vlan_rule_add(vsi, &vlan);
			} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_TX_ETYPE) {
				ret = sxe2_tx_etype_rule_add(vsi, rule->fltr.data.etype.ethertype);
			} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_RX_ETYPE) {
				ret = sxe2_rx_etype_rule_add(vsi, rule->fltr.data.etype.ethertype);
			} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_ALLMULTI) {
				ret = sxe2_allmulti_rule_add(vsi);
			} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_PROMISC) {
				ret = sxe2_promisc_rule_add(vsi);
			} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_SRCVSI) {
				ret = sxe2_srcvsi_rule_add(vsi);
			} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_SRCVSI_EXT) {
				ret = sxe2_srcvsi_ext_rule_add(vsi);
			} else if (rule->recipe_id == SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK) {
				ret = sxe2_mac_spoofchk_rule_add(adapter, vsi->idx_in_dev);
			}

			if (ret == -EEXIST) {
				ret = 0;
			} else if (ret) {
				LOG_ERROR_BDF("add rule failure, ret %d, \t"
					      "vsi[%d] recipe id %d, old rule id %d\n",
					      ret, vsi->idx_in_dev, rule->recipe_id,
					      rule->rule_id);
				break;
			}
			list_del(&rule->list_entry);
			kfree(rule);
			rule = NULL;
		}

		if (ret)
			break;
	}

	if (vsi->type == SXE2_VSI_T_PF) {
		ret = sxe2_vsi_lldp_fltr_update(vsi);
		if (ret)
			LOG_ERROR_BDF("lldp fltr update failure, ret %d, vsi[%d]\n",
				      ret, vsi->idx_in_dev);

		ret = sxe2_cur_mac_addr_set(vsi, vsi->netdev->dev_addr);
		if (ret)
			LOG_ERROR_BDF("rebuild mac addr failed, mac %pM, ret %d\n",
				      vsi->netdev->dev_addr, ret);
	}

	return ret;
}

STATIC void sxe2_fltr_cookie_rule_update(struct sxe2_adapter *adapter, struct sxe2_rule_info *rule)
{
	struct list_head *tc_rule_head;
	struct sxe2_tc_rule_info *tc_list_itr = NULL;
	struct sxe2_tc_rule_info *tc_list_tmp = NULL;
	struct sxe2_tc_rule_hash *rule_hash_node = NULL;

	tc_rule_head = &rule->tc_rule_head;
	list_for_each_entry_safe(tc_list_itr, tc_list_tmp,
				 tc_rule_head, list_entry) {
		rule_hash_node = sxe2_hash_cookie_find(adapter, tc_list_itr->cookie);
		if (rule_hash_node)
			rule_hash_node->rule_info = rule;
	}
}

s32 sxe2_vsi_complex_fltr_restore(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret					= 0;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct list_head *list_head;
	struct sxe2_rule_info *rule;
	struct sxe2_rule_info *rule_tmp;
	struct sxe2_rule_info *new_rule;

	list_head = &switch_ctxt->complex_recipe.restore_head;
	list_for_each_entry_safe(rule, rule_tmp, list_head, list_entry) {
		if (rule->tcf_fltr->src_vsi_id != vsi_id)
			continue;

		sxe2_tcf_match_meta_fill(rule->tcf_fltr);

		ret = sxe2_tcf_rule_add(adapter, vsi_id, rule->tcf_fltr);

		if (ret == -EEXIST) {
			ret = 0;
		} else if (ret) {
			LOG_ERROR_BDF("add rule failure, ret %d, old rule id %d\n",
				      ret, rule->rule_id);
			break;
		}

		new_rule = sxe2_rule_entry_find(adapter, rule);
		if (new_rule) {
			INIT_LIST_HEAD(&new_rule->tc_rule_head);
			if (!list_empty(&rule->tc_rule_head)) {
				list_replace_init(&rule->tc_rule_head,
						  &new_rule->tc_rule_head);
				sxe2_fltr_cookie_rule_update(adapter, new_rule);
			}
		}
		list_del(&rule->list_entry);
		sxe2_switch_sw_rule_free(adapter, rule);
		rule = NULL;
	}

	return ret;
}

s32 sxe2_vfs_complex_fltr_restore(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	u16 vf_idx;
	struct sxe2_vf_node *vf_node;

	sxe2_for_each_vf(adapter, vf_idx) {
		vf_node = SXE2_VF_NODE(adapter, vf_idx);
		ret	= sxe2_vsi_complex_fltr_restore(adapter, vf_node->vsi_id[SXE2_VF_TYPE_ETH]);
		if (ret) {
			LOG_ERROR_BDF("vf:%u add complex rule failed, ret %d.\n",
				      vf_node->vf_idx, ret);
			break;
		}
	}

	return ret;
}

s32 sxe2_pf_complex_fltr_restore(struct sxe2_adapter *adapter)
{
	s32 ret = 0;

	ret = sxe2_vsi_complex_fltr_restore(adapter,
					    adapter->vsi_ctxt.main_vsi->idx_in_dev);
	if (ret) {
		LOG_ERROR_BDF("adapter %d complex filter restore failed, ret %d\n",
			      adapter->pf_idx, ret);
	}

	return ret;
}

STATIC void sxe2_switch_vsi_list_hw_dump(struct sxe2_adapter *adapter)
{
	struct list_head *list_head;
	/* in order to protect the data */
	struct mutex *rule_lock;
	s32 i, status;
	s8 *vsi_buff;
	u16 vsi_id				     = 0;
	struct sxe2_switch_context *switch_ctxt	     = &adapter->switch_ctxt;
	struct sxe2_vsi_list_info *vsi_list	     = NULL;
	struct sxe2_cmd_params cmd		     = { 0 };
	struct sxe2_fwc_switch_vsi_list vsi_list_fwc = { 0 };
	struct sxe2_fwc_switch_vsi_list_resp vsi_list_resp = { 0 };
	u32 idx, vsi_map[SXE2_VSI_LIST_DAT_LEN];

	LOG_DEV_INFO("=============switch vsi list dump start=============\n");

	for (i = 0; i < SXE2_VSI_LIST_TYPE_MAX; i++) {
		list_head = &switch_ctxt->vsi_list_mgmt[i].vsi_list_head;
		rule_lock = &switch_ctxt->vsi_list_mgmt[i].vsi_list_lock;

		if (i == SXE2_VSI_LIST_TYPE_PRUNE)
			vsi_list_fwc.flag |= cpu_to_le16(SXE2_CMD_SWITCH_VSI_FLAG_LIST_PRUNE);
		mutex_lock(rule_lock);
		list_for_each_entry(vsi_list, list_head, list_entry) {
			vsi_list_fwc.vsi_list_id = cpu_to_le16(vsi_list->vsi_list_id);

			sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_SWITCH_VSI_LIST_GET,
						  &vsi_list_fwc, sizeof(vsi_list_fwc),
						  &vsi_list_resp, sizeof(vsi_list_resp));
			status = sxe2_cmd_fw_exec(adapter, &cmd);
			if (status) {
				LOG_ERROR_BDF("switch vsi list cmd fail, \t"
					      "type %d, vsi list %d, ret=%d\n",
					      i, vsi_list->vsi_list_id, status);
				continue;
			}

			vsi_buff = kzalloc(4096, GFP_KERNEL);
			if (!vsi_buff)
				continue;
			vsi_id = 0;
			for (idx = 0; idx < SXE2_VSI_LIST_DAT_LEN; idx++)
				vsi_map[idx] = le32_to_cpu(vsi_list_resp.vsi[idx]);

			while (true) {
				vsi_id = (u16)find_next_bit((unsigned long *)vsi_map,
							    SXE2_VSI_MAX_CNT, vsi_id);
				if (vsi_id >= SXE2_VSI_MAX_CNT)
					break;
				snprintf(vsi_buff + strlen(vsi_buff), 4096 - strlen(vsi_buff),
					 "%d,", vsi_id);
				vsi_id++;
			}

			LOG_DEV_INFO("vsi list type %d, vsi list id %d, vsi:%s\n", i,
				     vsi_list->vsi_list_id, vsi_buff);

			kfree(vsi_buff);
			vsi_buff = NULL;
		}
		mutex_unlock(rule_lock);
	}

	LOG_DEV_INFO("==============switch vsi list dump end==============\n");
}

STATIC void sxe2_switch_rule_complex_hw_dump(struct sxe2_adapter *adapter)
{
	u32 action;
	s32 i, status, vsi_cnt;
	struct sxe2_tcf_fltr *tcf_fltr;
	u16 vsi_id				   = 0;
	u16 vsi_list_id				   = 0;
	struct sxe2_cmd_params cmd		   = { 0 };
	struct sxe2_fwc_switch_rule_resp rule_resp = { 0 };
	struct sxe2_fwc_switch_rule rule_fwc	   = { 0 };
	struct sxe2_rule_info *rule_info	   = NULL;
	struct sxe2_vsi_list_info *vsi_list	   = NULL;
	struct sxe2_switch_context *switch_ctxt	   = &adapter->switch_ctxt;
	/* in order to protect the data */
	struct mutex *rule_lock	    = &switch_ctxt->complex_recipe.rule_lock;
	u32 bkt;
	struct hlist_node *temp;

	LOG_DEV_INFO("===============switch complex rule dump start===============\n");
	mutex_lock(rule_lock);

	hash_for_each_safe(adapter->switch_ctxt.complex_recipe.ht_lkup, bkt, temp,
			   tcf_fltr, node) {
		rule_info = tcf_fltr->rule_info;
		for (i = 0; i < tcf_fltr->recipe_cnt; i++) {
			rule_fwc.rule_id = cpu_to_le16(tcf_fltr->rule_id[i]);
			rule_fwc.recipe_id =
				cpu_to_le16(tcf_fltr->recipe_id[i]);
			vsi_list = rule_info->vsi_list;
			sxe2_cmd_params_dflt_fill(&cmd,
						  SXE2_CMD_SWITCH_RULE_GET,
						  &rule_fwc, sizeof(rule_fwc),
						  &rule_resp,
						  sizeof(rule_resp));
			status = sxe2_cmd_fw_exec(adapter, &cmd);
			if (status) {
				LOG_ERROR_BDF("switch rule cmd fail, recipe %d, rule %d, ret=%d\n",
					      tcf_fltr->recipe_id[i], tcf_fltr->rule_id[i],
					      status);
				continue;
			}
			action = le32_to_cpu(rule_resp.act);

			if (rule_info->act.type == SXE2_FWD_TO_VSI)
				vsi_cnt = 1;
			else if (rule_info->act.type == SXE2_FWD_TO_VSI_LIST)
				vsi_cnt = bitmap_weight(vsi_list->vsi_map, SXE2_VSI_MAX_CNT);
			else
				vsi_cnt = 0;

			if (!vsi_list)
				vsi_id = (action & SXE2_SINGLE_ACT_VSI_ID_M) >>
					 SXE2_SINGLE_ACT_VSI_ID_S;
			else
				vsi_list_id = (action &
					       SXE2_SINGLE_ACT_VSI_LIST_ID_M) >>
					      SXE2_SINGLE_ACT_VSI_LIST_ID_S;

			if (rule_info->act.type == SXE2_FWD_TO_Q) {
				LOG_DEV_INFO("cookie %lu, recipe %d, rule_id %d, act %08x, \t"
					     "full_key %08x:%08x:%08x, vsi_cnt %d, lb_en %d, \t"
					     "lan_en %d, is_root %d, queue_id:%d\n",
					     tcf_fltr->cookie, tcf_fltr->recipe_id[i],
					     tcf_fltr->rule_id[i], action, rule_resp.full_key[0],
					     rule_resp.full_key[1], rule_resp.full_key[2],
					     vsi_cnt,
					     ((action & SXE2_SINGLE_ACT_LB_ENABLE) ? true : false),
					     ((action & SXE2_SINGLE_ACT_LAN_ENABLE) ? true : false),
					     rule_fwc.rule_id == rule_info->rule_id ? 1 : 0,
					     rule_info->act.fwd_id.q_id);
			} else {
				LOG_DEV_INFO("cookie %lu, recipe %d, rule_id %d, \t"
					     "act %08x, full_key %08x:%08x:%08x, \t"
					     "vsi_cnt %d, lb_en %d, lan_en %d, \t"
					     "is_root %d, vsi id %d, vsi_list_id %d, \t"
					     "ref_cnt %d\n",
					     tcf_fltr->cookie, tcf_fltr->recipe_id[i],
					     tcf_fltr->rule_id[i], action, rule_resp.full_key[0],
					     rule_resp.full_key[1], rule_resp.full_key[2],
					     vsi_cnt,
					     ((action & SXE2_SINGLE_ACT_LB_ENABLE) ? true : false),
					     ((action & SXE2_SINGLE_ACT_LAN_ENABLE) ? true : false),
					     rule_fwc.rule_id == rule_info->rule_id ? 1 : 0,
					     (vsi_list ? -1 : vsi_id),
					     (vsi_list ? vsi_list_id : -1),
					     le16_to_cpu(rule_resp.ref_cnt));
			}
		}
	}
	mutex_unlock(rule_lock);

	LOG_DEV_INFO("================switch complex rule dump end================\n");
}

#define LOG_DUMP_SWITCH_RULE(fmt, ...)                                         \
	LOG_DEV_INFO("recipe %d, rule_id %d, "                                 \
		     "act %08x, full_key %08x:%08x:%08x, "                     \
		     "vsi_cnt %d, lb_en %d, lan_en %d, " fmt,                  \
		     i, rule_info->rule_id, action, rule_resp.full_key[0],     \
		     rule_resp.full_key[1], rule_resp.full_key[2], vsi_cnt,    \
		     ((action & SXE2_SINGLE_ACT_LB_ENABLE) ? true : false),    \
		     ((action & SXE2_SINGLE_ACT_LAN_ENABLE) ? true : false),   \
		     ##__VA_ARGS__)

#define FULL_KEY_TO_MAC_ADDR()                                                 \
	do {                                                                   \
		mac_addr[0] = (u8)(full_key_d1.field.fv1 >> U8_BITS);          \
		mac_addr[1] = (u8)(full_key_d1.field.fv1 & U8_MAX);            \
		mac_addr[2] = (u8)(full_key_d1.field.fv2 >> U8_BITS);          \
		mac_addr[3] = (u8)(full_key_d1.field.fv2 & U8_MAX);            \
		mac_addr[4] = (u8)(full_key_d2.field.fv3 >> U8_BITS);          \
		mac_addr[5] = (u8)(full_key_d2.field.fv3 & U8_MAX);            \
	} while (0)

STATIC void sxe2_switch_rule_l2_hw_dump(struct sxe2_adapter *adapter)
{
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct list_head *list_head;
	/* in order to protect the data */
	struct mutex *rule_lock;
	struct sxe2_rule_info *rule_info	   = NULL;
	struct sxe2_vsi_list_info *vsi_list	   = NULL;
	struct sxe2_fwc_switch_rule rule_fwc	   = { 0 };
	struct sxe2_cmd_params cmd		   = { 0 };
	struct sxe2_fwc_switch_rule_resp rule_resp = { 0 };
	s32 i, status, vsi_cnt;
	u16 vsi_id	= 0;
	u16 src_vsi_id	= 0;
	u16 vsi_list_id = 0;
	u32 action;
	union sxe2_switch_full_key_dw1 full_key_d1;
	union sxe2_switch_full_key_dw2 full_key_d2;
	u8 mac_addr[ETH_ALEN];
	struct sxe2_vlan vlan;
	u16 etype;

	LOG_DEV_INFO("===============switch rule dump start===============\n");
	for (i = 0; i < SXE2_DEFAULT_RECIPE_MAX; i++) {
		list_head = &switch_ctxt->recipe[i].rule_head;
		rule_lock = &switch_ctxt->recipe[i].rule_lock;
		mutex_lock(rule_lock);
		list_for_each_entry(rule_info, list_head, list_entry) {
			rule_fwc.rule_id   = cpu_to_le16(rule_info->rule_id);
			rule_fwc.recipe_id = cpu_to_le16((u16)i);
			vsi_list	   = rule_info->vsi_list;
			sxe2_cmd_params_dflt_fill(&cmd,
						  SXE2_CMD_SWITCH_RULE_GET,
						  &rule_fwc, sizeof(rule_fwc),
						  &rule_resp,
						  sizeof(rule_resp));
			status = sxe2_cmd_fw_exec(adapter, &cmd);
			if (status) {
				LOG_ERROR_BDF("switch rule cmd fail, recipe %d, rule %d, ret=%d\n",
					      i, rule_info->rule_id, status);
				continue;
			}
			full_key_d1.val = le32_to_cpu(rule_resp.full_key[1]);
			full_key_d2.val = le32_to_cpu(rule_resp.full_key[2]);
			action		= le32_to_cpu(rule_resp.act);
			if (rule_info->act.type == SXE2_FWD_TO_VSI) {
				vsi_cnt = 1;
			} else if (rule_info->act.type == SXE2_FWD_TO_VSI_LIST) {
				vsi_cnt = bitmap_weight(vsi_list->vsi_map,
							SXE2_VSI_MAX_CNT);
			} else {
				vsi_cnt = 0;
			}
			if (!vsi_list)
				vsi_id = (action & SXE2_SINGLE_ACT_VSI_ID_M) >>
					 SXE2_SINGLE_ACT_VSI_ID_S;
			else
				vsi_list_id = (action &
					       SXE2_SINGLE_ACT_VSI_LIST_ID_M) >>
					      SXE2_SINGLE_ACT_VSI_LIST_ID_S;

			switch (i) {
			case SXE2_DEFAULT_RECIPE_MAC:
				FULL_KEY_TO_MAC_ADDR();
				LOG_DUMP_SWITCH_RULE("mac %pM, vsi id %d, vsi_list_id %d\n",
						     mac_addr, (vsi_list ? -1 : vsi_id),
						     (vsi_list ? vsi_list_id : -1));
				break;
			case SXE2_DEFAULT_RECIPE_VLAN:
				vlan.tpid = full_key_d1.field.fv1;
				vlan.vid  = full_key_d1.field.fv2;
				LOG_DUMP_SWITCH_RULE("tpid %x, vid %d, vsi_list_id %d\n",
						     vlan.tpid, vlan.vid, vsi_list_id);
				break;
			case SXE2_DEFAULT_RECIPE_TX_ETYPE:
				src_vsi_id = full_key_d1.field.fv1 & 0x03FF;
				etype	   = full_key_d2.field.fv3;
				LOG_DUMP_SWITCH_RULE("etype %x, is_rx %d, \t"
						     "src_vsi_id %d, vsi id %d, vsi_list_id %d\n",
						     etype, false, src_vsi_id,
						     (vsi_list ? -1 : vsi_id),
						     (vsi_list ? vsi_list_id : -1));
				break;
			case SXE2_DEFAULT_RECIPE_RX_ETYPE:
				etype = full_key_d1.field.fv2;
				LOG_DUMP_SWITCH_RULE("etype %x, is_rx %d, \t"
						     "vsi id %d, vsi_list_id %d\n",
						     etype, true, (vsi_list ? -1 : vsi_id),
						     (vsi_list ? vsi_list_id : -1));
				break;
			case SXE2_DEFAULT_RECIPE_ALLMULTI:
			case SXE2_DEFAULT_RECIPE_PROMISC:
				LOG_DUMP_SWITCH_RULE("vsi id %d, vsi_list_id %d\n",
						     (vsi_list ? -1 : vsi_id),
						     (vsi_list ? vsi_list_id : -1));
				break;
			case SXE2_DEFAULT_RECIPE_SRCVSI:
				src_vsi_id = full_key_d1.field.fv1 & 0x03FF;
				LOG_DUMP_SWITCH_RULE("src_vsi_id %d, vsi id %d\n",
						     src_vsi_id, vsi_id);
				break;
			case SXE2_DEFAULT_RECIPE_SRCVSI_EXT:
				src_vsi_id = full_key_d1.field.fv1 & 0x03FF;
				LOG_DUMP_SWITCH_RULE("src_vsi_ext_id %d, vsi id %d\n",
						     src_vsi_id, vsi_id);
				break;
			case SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK:
				FULL_KEY_TO_MAC_ADDR();
				LOG_DUMP_SWITCH_RULE("mac %pM, vsi id %d, vsi_list_id %d\n",
						     mac_addr, (vsi_list ? -1 : vsi_id),
						     (vsi_list ? vsi_list_id : -1));
				break;
			case SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK_EXT:
				FULL_KEY_TO_MAC_ADDR();
				LOG_DUMP_SWITCH_RULE("mac %pM, vsi id %d, vsi_list_id %d\n",
						     mac_addr, (vsi_list ? -1 : vsi_id),
						     (vsi_list ? vsi_list_id : -1));
				break;
			default:
				break;
			}
		}
		mutex_unlock(rule_lock);
	}
	LOG_DEV_INFO("================switch rule dump end================\n");
}

void sxe2_switch_rule_hw_dump(struct sxe2_adapter *adapter)
{
	sxe2_switch_rule_l2_hw_dump(adapter);
	sxe2_switch_rule_complex_hw_dump(adapter);
	sxe2_switch_vsi_list_hw_dump(adapter);
}

void sxe2_fwc_switch_trace_rx_trigger(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd	     = { 0 };
	struct sxe2_fwc_switch_trace_req req = { 0 };

	req.is_rx = true;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_SWITCH_TRACE_TRIGGER, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("switch trace trigger cmd fail, ret=%d\n", ret);
}

void sxe2_fwc_switch_trace_tx_trigger(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd	     = { 0 };
	struct sxe2_fwc_switch_trace_req req = { 0 };

	req.is_rx = false;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_SWITCH_TRACE_TRIGGER, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("switch trace trigger cmd fail, ret=%d\n", ret);
}

void sxe2_fwc_switch_trace_recorder(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_fwc_switch_trace_resp resp;
	struct sxe2_recp_trace_rcd *recp;
	s32 i;

	memset(&resp, 0, sizeof(resp));
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_SWITCH_TRACE_RECORDER, NULL, 0,
				  &resp, sizeof(resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("switch trace recorder cmd fail, ret=%d\n", ret);
		goto l_end;
	}

	LOG_DEV_INFO("=============switch trace recorder start=============\n");

	if (resp.og.done) {
		LOG_DEV_INFO("OG trace, status %d, profile id %d\n",
			     resp.og.status, resp.og.profile_id);
		for (i = 0; i < SXE2_SWITCH_FV_CNT; i++) {
			LOG_DEV_INFO("OG trace, fv[%d] 0x%04x\n", i,
				     le16_to_cpu(resp.og.fv[i]));
		}
	}

	if (resp.swe.done) {
		LOG_DEV_INFO("SWE trace, status %d\n", resp.swe.status);
		for (i = 0; i < SXE2_PACKET_MAX_RECIPES; i++) {
			recp = &resp.swe.recp[i];
			LOG_DEV_INFO("SWE trace, recipe id %d,\t"
				     "ht1/ht2/kt/fkot hit %d/%d/%d/%d, index %d\n",
				     le16_to_cpu(recp->recipe_id),
				     recp->ht1_hit, recp->ht2_hit, recp->kt_hit,
				     recp->fkot_hit, le16_to_cpu(recp->index));
		}
	}

	if (resp.rg.done) {
		LOG_DEV_INFO("RG trace, status %d\n", resp.rg.status);
		for (i = 0; i < SXE2_PACKET_INFO_DWORD_CNT; i++) {
			LOG_DEV_INFO("RG trace, packet info[%d] 0x%08x\n", i,
				     le32_to_cpu(resp.rg.ppe_info[i]));
		}
	}

	LOG_DEV_INFO("==============switch trace recorder end==============\n");

l_end:
	return;
}

void sxe2_switch_recipe_dump(struct sxe2_adapter *adapter)
{
	s32 ret;
	u8 i;
	struct sxe2_fwc_switch_recipe switch_recipe = { 0 };

	LOG_DEV_INFO("===============switch recipe dump start===============\n");

	for (i = 0; i < SXE2_MAX_NUM_RECIPES; i++) {
		memset(&switch_recipe, 0, sizeof(switch_recipe));
		switch_recipe.rid = i;
		ret = sxe2_fwc_switch_recipe_get(adapter, &switch_recipe,
						 SXE2_CMD_SWITCH_RECIPE_GET);
		if (ret) {
			LOG_DEV_ERR("switch recipe get fail, ret=%d\n", ret);
			return;
		}

		LOG_DEV_INFO("rid:%u, isRoot:%u, lpidx0:%u, lpidx0Vid:%u, \t"
			     "fv0msk:0x%x, lpidx1:%u, lpidx1Vid:%u, fv1msk:0x%x, \t"
			     "lpidx2:%u, lpidx2Vid:%u, fv2msk:0x%x, lpidx3:%u, \t"
			     "lpidx3Vid:%u, fv3msk:0x%x, lpidx4:%u, lpidx4Vid:%u, \t"
			     "fv4msk:0x%x, prio:%u, jprio:0x%x, inversAct:%u, \t"
			     "defAct:0x%x, defActValid:%u, ref_cnt %d\n",
			     switch_recipe.rid, switch_recipe.is_root,
			     switch_recipe.lookup_index0,
			     switch_recipe.lookup_index0_valid,
			     le16_to_cpu(switch_recipe.fv0_bitmask),
			     switch_recipe.lookup_index1,
			     switch_recipe.lookup_index1_valid,
			     le16_to_cpu(switch_recipe.fv1_bitmask),
			     switch_recipe.lookup_index2,
			     switch_recipe.lookup_index2_valid,
			     le16_to_cpu(switch_recipe.fv2_bitmask),
			     switch_recipe.lookup_index3,
			     switch_recipe.lookup_index3_valid,
			     le16_to_cpu(switch_recipe.fv3_bitmask),
			     switch_recipe.lookup_index4,
			     switch_recipe.lookup_index4_valid,
			     le16_to_cpu(switch_recipe.fv4_bitmask),
			     switch_recipe.priority, switch_recipe.join_priority,
			     switch_recipe.inverse_action,
			     le32_to_cpu((u32)switch_recipe.default_action),
			     switch_recipe.default_action_valid,
			     le16_to_cpu((u32)switch_recipe.ref_cnt));
	}
	LOG_DEV_INFO("===============switch recipe dump end===============\n");
}

void sxe2_switch_profile_recipemap_dump(struct sxe2_adapter *adapter)
{
	s32 ret;
	u16 i;
	struct sxe2_fwc_switch_profile_recipe_map profile_recipe_map = { 0 };
	u32 map[2];

	LOG_DEV_INFO("===============switch profile recipe map dump start===============\n");

	for (i = 2; i < SXE2_MAX_NUM_PROFILES; i++) {
		memset(&profile_recipe_map, 0, sizeof(profile_recipe_map));
		memset(map, 0, sizeof(map));
		profile_recipe_map.profile_id = cpu_to_le16(i);
		ret =
		 sxe2_fwc_switch_profile_recipe_map_get(adapter, &profile_recipe_map,
							SXE2_CMD_SWITCH_PROFILE_RECIPE_MAP_GET);
		if (ret) {
			LOG_DEV_ERR("switch profile recipe map get fail, ret=%d\n", ret);
			break;
		}
		memcpy(map, profile_recipe_map.map, sizeof(map));
		LOG_DEV_INFO("profile[%u] 0x%x 0x%x\n",
			     le16_to_cpu(profile_recipe_map.profile_id),
			     le32_to_cpu(profile_recipe_map.map[0]),
			     le32_to_cpu(profile_recipe_map.map[1]));
	}
	LOG_DEV_INFO("===============switch profile recipe map dump end===============\n");
}

void sxe2_switch_share_id_dump(struct sxe2_adapter *adapter)
{
	s32 ret;
	u16 i;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_fwc_switch_share_id *fwc_share_id;

	fwc_share_id = kzalloc(sizeof(*fwc_share_id), GFP_KERNEL);
	if (!fwc_share_id)
		return;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_SWITCH_SHARE_ID_GET, NULL,
				  0, fwc_share_id, sizeof(*fwc_share_id));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("switch share id get cmd fail, ret=%d\n", ret);

	LOG_DEV_INFO("===============switch share id dump start===============\n");

	LOG_DEV_INFO("usage 0x%x\n", le32_to_cpu(fwc_share_id->usage));
	for (i = 0; i < SXE2_MAX_NUM_RECIPES; i++) {
		LOG_DEV_INFO("recipe %d, share id %d, bitmap 0x%x\n",
			     i, le32_to_cpu(fwc_share_id->share_id[i]),
			     le32_to_cpu(fwc_share_id->bitmap[i]));
	}

	LOG_DEV_INFO("================switch share id dump end================\n");
	kfree(fwc_share_id);
}

struct sxe2_switch_dfx_stats_info {
	__le32 index;
	char name[32];
};

void sxe2_fwc_hw_dfx_show(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_fwc_switch_dfx_stats resp;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_HW_DFX_SHOW, NULL, 0, &resp,
				  sizeof(resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("switch trace trigger cmd fail, ret=%d\n", ret);
}

s32 sxe2_vlan_filter_control(struct sxe2_adapter *adapter, u16 vsi_hw_id,
			     bool en)
{
	s32 ret;
	struct sxe2_cmd_params cmd	    = { 0 };
	struct sxe2_fwc_vsi_vlan_filter req = { 0 };

	req.vsi_hw_id = cpu_to_le16(vsi_hw_id);
	req.enable    = (u8)en;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_VSI_VLAN_FILTER, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("vsi vlan filter cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_src_vsi_prune_control(struct sxe2_adapter *adapter, u16 vsi_hw_id,
			       bool en)
{
	s32 ret;
	struct sxe2_cmd_params cmd	  = { 0 };
	struct sxe2_fwc_vsi_src_prune req = { 0 };

	req.vsi_hw_id = cpu_to_le16(vsi_hw_id);
	req.enable    = (u8)en;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_VSI_SRC_PRUNE, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("vsi src prune action cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_vsi_loopback_control(struct sxe2_adapter *adapter, u16 vsi_hw_id,
			      bool en)
{
	s32 ret;
	struct sxe2_cmd_params cmd	 = { 0 };
	struct sxe2_fwc_vsi_loopback req = { 0 };

	req.vsi_hw_id = cpu_to_le16(vsi_hw_id);
	req.enable    = (u8)en;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_VSI_LOOPBACK, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("vsi lookback cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_vsi_spoofchk_control(struct sxe2_adapter *adapter, u16 vsi_hw_id,
			      bool en)
{
	s32 ret;
	struct sxe2_cmd_params cmd	 = { 0 };
	struct sxe2_fwc_vsi_spoofchk req = { 0 };

	req.vsi_hw_id	= cpu_to_le16(vsi_hw_id);
	req.mac_enable	= (u8)en;
	req.vlan_enable = (u8)en;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_VSI_SPOOFCHK, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("vsi spoofchk cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_switch_dfx_irq_setup(struct sxe2_adapter *adapter, bool en)
{
	s32 ret;
	struct sxe2_cmd_params cmd	   = { 0 };
	struct sxe2_fwc_switch_dfx_irq req = { 0 };

	req.enable = (u8)en;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_SWITCH_DFX_IRQ, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("switch dfx irq setup cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

STATIC bool sxe2_macvlan_mac_check(struct sxe2_adapter *adapter, const u8 *mac, u16 *vsi_id)
{
	u16 i;
	struct sxe2_vsi *vsi = NULL;

	sxe2_for_each_vsi(&adapter->vsi_ctxt, i) {
		vsi = adapter->vsi_ctxt.vsi[i];
		if (!vsi)
			continue;
		if (vsi->type == SXE2_VSI_T_MACVLAN &&
		    ether_addr_equal(mac, (u8 *)vsi->netdev->dev_addr)) {
			*vsi_id = vsi->idx_in_dev;
			return true;
		}
	}
	return false;
}

s32 sxe2_mac_rule_update(struct sxe2_adapter *adapter, const u8 *mac, u16 old_vsi, u16 new_vsi)
{
	s32 ret = 0;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct list_head *list_head;
	struct sxe2_rule_info *rule_info = NULL;
	/* in order to protect the data */
	struct mutex *rule_lock;
	/* in order to protect the data */
	struct mutex *vsi_list_lock;

	list_head     = &switch_ctxt->recipe[SXE2_DEFAULT_RECIPE_MAC].rule_head;
	rule_lock     = &switch_ctxt->recipe[SXE2_DEFAULT_RECIPE_MAC].rule_lock;
	vsi_list_lock = &switch_ctxt->vsi_list_mgmt[SXE2_VSI_LIST_TYPE_FORWARD].vsi_list_lock;

	mutex_lock(rule_lock);
	mutex_lock(vsi_list_lock);

	list_for_each_entry(rule_info, list_head, list_entry) {
		u8 *addr = rule_info->fltr.data.mac.mac_addr;

		if (ether_addr_equal(mac, addr)) {
			if (rule_info->vsi_list) {
				clear_bit(old_vsi, rule_info->vsi_list->vsi_map);
				set_bit(new_vsi, rule_info->vsi_list->vsi_map);
			} else {
				rule_info->act.fwd_id.vsi_id = new_vsi;
			}
			ret = sxe2_fwd_rule_update(adapter, rule_info);
			if (ret)
				LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
			break;
		}
	}

	mutex_unlock(vsi_list_lock);
	mutex_unlock(rule_lock);
	return ret;
}

s32 sxe2_mac_spoof_rule_update(struct sxe2_vsi *eth_vsi,
			       struct sxe2_vsi *user_vsi, u8 *mac_addr, bool to_user)
{
	s32 ret;
	struct sxe2_adapter *adapter = eth_vsi->adapter;

	if (to_user) {
		ret = sxe2_mac_spoofchk_ext_rule_del(adapter, eth_vsi->idx_in_dev, mac_addr);
		if (ret) {
			LOG_ERROR_BDF("mac %pM spoofchk del failed, vsi_id:%u\n",
				      mac_addr, eth_vsi->idx_in_dev);
			goto l_end;
		}

		ret = sxe2_mac_spoofchk_ext_rule_add(adapter, user_vsi->idx_in_dev, mac_addr);
		if (ret) {
			LOG_ERROR_BDF("mac %pM spoofchk add failed, vsi_id:%u\n",
				      mac_addr, user_vsi->idx_in_dev);
			(void)sxe2_mac_spoofchk_ext_rule_add(adapter,
							     eth_vsi->idx_in_dev, mac_addr);
			goto l_end;
		}
	} else {
		ret = sxe2_mac_spoofchk_ext_rule_del(adapter,
						     user_vsi->idx_in_dev, mac_addr);
		if (ret) {
			LOG_ERROR_BDF("mac %pM spoofchk del failed, vsi_id:%u\n",
				      mac_addr, user_vsi->idx_in_dev);
			goto l_end;
		}

		ret = sxe2_mac_spoofchk_ext_rule_add(adapter,
						     eth_vsi->idx_in_dev, mac_addr);
		if (ret) {
			LOG_ERROR_BDF("mac %pM spoofchk add failed, vsi_id:%u\n",
				      mac_addr, eth_vsi->idx_in_dev);
			(void)sxe2_mac_spoofchk_ext_rule_add(adapter,
							     user_vsi->idx_in_dev, mac_addr);
			goto l_end;
		}
	}

l_end:
	return ret;
}

STATIC s32 sxe2_unicast_user_mode_mac_add(struct sxe2_adapter *adapter,
					  u16 vsi_id, const u8 *mac)
{
	s32 ret = 0;
	struct sxe2_vsi *user_vsi;
	struct sxe2_mac_filter *user_mac_fltr;
	struct sxe2_addr_node *user_mac_node;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;

	mutex_lock(&adapter->vsi_ctxt.lock);
	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_vsi_unlock;
	}

	user_mac_fltr = &user_vsi->mac_filter;
	mutex_lock(&switch_ctxt->mac_addr_lock);

	user_mac_node = sxe2_mac_addr_find(user_vsi, mac);
	if (user_mac_node) {
		LOG_ERROR_BDF("mac:%pM has been in mac list.\n", mac);
		ret = -EEXIST;
		goto l_mac_list_unlock;
	}

	user_mac_node = kzalloc(sizeof(*user_mac_node), GFP_KERNEL);
	if (!user_mac_node) {
		LOG_ERROR_BDF("create list node for mac:%pM failed.\n", mac);
		ret = -ENOMEM;
		goto l_mac_list_unlock;
	}

	ret = sxe2_mac_rule_add(user_vsi, mac);
	if (ret) {
		kfree(user_mac_node);
		goto l_mac_list_unlock;
	}

	ether_addr_copy(user_mac_node->mac_addr, mac);
	list_add_tail(&user_mac_node->list, &user_mac_fltr->mac_addr_list);

l_mac_list_unlock:
	mutex_unlock(&switch_ctxt->mac_addr_lock);
l_vsi_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

	return ret;
}

STATIC s32 sxe2_unicast_com_mode_mac_add(struct sxe2_adapter *adapter,
					 u16 vsi_id, const u8 *mac)
{
	s32 ret = 0;
	struct sxe2_vsi *eth_vsi;
	struct sxe2_vsi *user_vsi;
	struct sxe2_mac_filter *user_mac_fltr;
	struct sxe2_addr_node *eth_mac_node;
	struct sxe2_addr_node *user_mac_node;
	u16 macvlan_vsi;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;

	mutex_lock(&adapter->vsi_ctxt.lock);
	eth_vsi = adapter->vsi_ctxt.main_vsi;

	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_vsi_unlock;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, user_vsi->state) ||
	    test_bit(SXE2_VSI_S_DISABLE, eth_vsi->state)) {
		ret = -EBUSY;
		goto l_vsi_unlock;
	}

	user_mac_fltr = &user_vsi->mac_filter;

	mutex_lock(&switch_ctxt->mac_addr_lock);

	user_mac_node = sxe2_mac_addr_find(user_vsi, mac);
	if (user_mac_node) {
		LOG_ERROR_BDF("mac:%pM has been in mac list.\n", mac);
		ret = -EEXIST;
		goto l_mac_list_unlock;
	}

	user_mac_node = kzalloc(sizeof(*user_mac_node), GFP_KERNEL);
	if (!user_mac_node) {
		LOG_ERROR_BDF("create list node for mac:%pM failed.\n", mac);
		ret = -ENOMEM;
		goto l_mac_list_unlock;
	}

	eth_mac_node = sxe2_mac_addr_find(eth_vsi, mac);
	if (eth_mac_node) {
		ret = sxe2_mac_rule_update(adapter, mac,
					   eth_vsi->idx_in_dev, user_vsi->idx_in_dev);
		if (ret) {
			kfree(user_mac_node);
			goto l_mac_list_unlock;
		}
	} else if (sxe2_macvlan_mac_check(adapter, mac, &macvlan_vsi)) {
		ret = sxe2_mac_rule_update(adapter, mac,
					   macvlan_vsi, user_vsi->idx_in_dev);
		if (ret) {
			kfree(user_mac_node);
			goto l_mac_list_unlock;
		}
	} else {
		ret = sxe2_mac_rule_add(user_vsi, mac);
		if (ret) {
			kfree(user_mac_node);
			goto l_mac_list_unlock;
		}
	}

	ether_addr_copy(user_mac_node->mac_addr, mac);
	list_add_tail(&user_mac_node->list, &user_mac_fltr->mac_addr_list);

l_mac_list_unlock:
	mutex_unlock(&switch_ctxt->mac_addr_lock);
l_vsi_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_ucmd_unicast_mac_add(struct sxe2_adapter *adapter,
			      u16 vsi_id, const u8 *mac)
{
	s32 ret = 0;

	LOG_DEBUG_BDF("User pf vsi:%u unicast mac %pM rule add.\n", vsi_id, mac);

	if (sxe2_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		ret = sxe2_unicast_user_mode_mac_add(adapter, vsi_id, mac);
	else
		ret = sxe2_unicast_com_mode_mac_add(adapter, vsi_id, mac);
	return ret;
}

s32 sxe2_ucmd_multi_broad_mac_add(struct sxe2_adapter *adapter,
				  u16 vsi_id, const u8 *mac)
{
	s32 ret = 0;
	struct sxe2_addr_node *user_mac_node;
	struct sxe2_vsi *user_vsi;
	struct sxe2_mac_filter *user_mac_fltr;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;

	LOG_DEBUG_BDF("User pf vsi:%u multi broad mac %pM rule add.\n", vsi_id, mac);

	mutex_lock(&adapter->vsi_ctxt.lock);

	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_vsi_unlock;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, user_vsi->state)) {
		ret = -EBUSY;
		goto l_vsi_unlock;
	}

	user_mac_fltr = &user_vsi->mac_filter;
	mutex_lock(&switch_ctxt->mac_addr_lock);
	user_mac_node = sxe2_mac_addr_find(user_vsi, mac);
	if (user_mac_node) {
		LOG_ERROR_BDF("mac:%pM has been in mac list.\n", mac);
		ret = -EEXIST;
		goto l_mac_list_unlock;
	}

	user_mac_node = kzalloc(sizeof(*user_mac_node), GFP_KERNEL);
	if (!user_mac_node) {
		LOG_ERROR_BDF("create list node for mac:%pM failed.\n", mac);
		ret = -ENOMEM;
		goto l_mac_list_unlock;
	}

	ret = sxe2_mac_rule_add(user_vsi, mac);
	if (ret) {
		kfree(user_mac_node);
		goto l_mac_list_unlock;
	}

	ether_addr_copy(user_mac_node->mac_addr, mac);
	list_add_tail(&user_mac_node->list, &user_mac_fltr->mac_addr_list);

l_mac_list_unlock:
	mutex_unlock(&switch_ctxt->mac_addr_lock);
l_vsi_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

STATIC s32 sxe2_unicast_com_mode_mac_del(struct sxe2_adapter *adapter,
					 u16 vsi_id, const u8 *mac)
{
	s32 ret = 0;
	struct sxe2_vsi *eth_vsi;
	struct sxe2_vsi *user_vsi;
	struct sxe2_addr_node *eth_mac_node;
	struct sxe2_addr_node *user_mac_node;
	u16 macvlan_vsi;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;

	mutex_lock(&adapter->vsi_ctxt.lock);

	eth_vsi = adapter->vsi_ctxt.main_vsi;
	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_vsi_unlock;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, user_vsi->state) ||
	    test_bit(SXE2_VSI_S_DISABLE, eth_vsi->state)) {
		ret = -EBUSY;
		goto l_vsi_unlock;
	}

	mutex_lock(&switch_ctxt->mac_addr_lock);
	user_mac_node = sxe2_mac_addr_find(user_vsi, mac);
	if (!user_mac_node) {
		LOG_WARN_BDF("mac:%pM is not in mac list\n", mac);
		goto l_mac_list_unlock;
	}

	eth_mac_node = sxe2_mac_addr_find(eth_vsi, mac);
	if (eth_mac_node) {
		ret = sxe2_mac_rule_update(adapter, mac,
					   user_vsi->idx_in_dev, eth_vsi->idx_in_dev);
		if (ret)
			goto l_mac_list_unlock;
	} else if (sxe2_macvlan_mac_check(adapter, mac, &macvlan_vsi)) {
		ret = sxe2_mac_rule_update(adapter, mac,
					   user_vsi->idx_in_dev, macvlan_vsi);
		if (ret)
			goto l_mac_list_unlock;
	} else {
		ret = sxe2_mac_rule_del(adapter, user_vsi->idx_in_dev, mac);
		if (ret)
			goto l_mac_list_unlock;
	}

	sxe2_switch_mac_node_del_and_free(user_mac_node);

l_mac_list_unlock:
	mutex_unlock(&switch_ctxt->mac_addr_lock);
l_vsi_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

STATIC s32 sxe2_unicast_user_mode_mac_del(struct sxe2_adapter *adapter,
					  u16 vsi_id, const u8 *mac)
{
	s32 ret = 0;
	struct sxe2_vsi *user_vsi;
	struct sxe2_addr_node *user_mac_node;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;

	mutex_lock(&adapter->vsi_ctxt.lock);
	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_vsi_unlock;
	}

	mutex_lock(&switch_ctxt->mac_addr_lock);

	user_mac_node = sxe2_mac_addr_find(user_vsi, mac);
	if (!user_mac_node) {
		LOG_ERROR_BDF("mac:%pM is not in mac list.\n", mac);
		ret = -EEXIST;
		goto l_mac_list_unlock;
	}

	ret = sxe2_mac_rule_del(adapter, user_vsi->idx_in_dev, mac);
	if (ret)
		goto l_mac_list_unlock;

	sxe2_switch_mac_node_del_and_free(user_mac_node);

l_mac_list_unlock:
	mutex_unlock(&switch_ctxt->mac_addr_lock);
l_vsi_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

	return ret;
}

s32 sxe2_ucmd_srcvsi_ext_add(struct sxe2_adapter *adapter,
			     u16 vsi_id, u16 *vsi_id_list, u16 vsi_id_cnt)
{
	s32 ret = 0;
	u16 vsi_id_temp = 0;
	u16 idx = 0;
	struct sxe2_vsi *vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);

	if (vsi_id_cnt != 2)  {
		LOG_ERROR_BDF("User src vsi list cnt just support two vsi id.\n");
		goto l_end;
	}

	vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("src vsi id_in_dev:%u is NULL.\n", vsi_id);
		goto l_end;
	}

	for (idx = 0; idx < vsi_id_cnt; idx++) {
		vsi_id_temp = vsi_id_list[idx];
		if (vsi_id_temp == SXE2_VSI_ID_INVALID) {
			LOG_ERROR_BDF("User src vsi list id:%u vsi id is invalid.\n", idx);
			goto l_end;
		}
		if (vsi_id_temp == vsi_id)
			vsi->src_prune.vsi_id_u = vsi_id_temp;
		else
			vsi->src_prune.vsi_id_k = vsi_id_temp;
	}

	ret = sxe2_srcvsi_ext_rule_add(vsi);

l_end:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_ucmd_srcvsi_ext_del(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;

	mutex_lock(&adapter->vsi_ctxt.lock);
	ret = sxe2_srcvsi_ext_rule_del(adapter, vsi_id);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_ucmd_unicast_mac_del(struct sxe2_adapter *adapter, u16 vsi_id, const u8 *mac)
{
	s32 ret = 0;

	LOG_DEBUG_BDF("User pf vsi:%u unicast mac %pM rule del.\n", vsi_id, mac);

	if (sxe2_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		ret = sxe2_unicast_user_mode_mac_del(adapter, vsi_id, mac);
	else
		ret = sxe2_unicast_com_mode_mac_del(adapter, vsi_id, mac);
	return ret;
}

s32 sxe2_ucmd_multi_broad_mac_del(struct sxe2_adapter *adapter, u16 vsi_id, const u8 *mac)
{
	s32 ret = 0;
	struct sxe2_addr_node *user_mac_node;
	struct sxe2_vsi *user_vsi;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;

	LOG_DEBUG_BDF("User pf vsi:%u multi broad mac %pM rule del.\n",
		      vsi_id, mac);

	mutex_lock(&adapter->vsi_ctxt.lock);

	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_vsi_unlock;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, user_vsi->state)) {
		ret = -EBUSY;
		goto l_vsi_unlock;
	}

	mutex_lock(&switch_ctxt->mac_addr_lock);
	user_mac_node = sxe2_mac_addr_find(user_vsi, mac);
	if (!user_mac_node) {
		LOG_ERROR_BDF("mac:%pM is not in mac list.\n", mac);
		ret = -EEXIST;
		goto l_mac_list_unlock;
	}

	ret = sxe2_mac_rule_del(adapter, user_vsi->idx_in_dev, mac);
	if (ret)
		goto l_mac_list_unlock;

	sxe2_switch_mac_node_del_and_free(user_mac_node);

l_mac_list_unlock:
	mutex_unlock(&switch_ctxt->mac_addr_lock);
l_vsi_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_promisc_rule_update(struct sxe2_adapter *adapter, u16 old_vsi, u16 new_vsi)
{
	s32 ret = 0;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct list_head *list_head;
	struct sxe2_rule_info *rule_info = NULL;
	/* in order to protect the data */
	struct mutex *rule_lock;
	/* in order to protect the data */
	struct mutex *vsi_list_lock;

	list_head     = &switch_ctxt->recipe[SXE2_DEFAULT_RECIPE_PROMISC].rule_head;
	rule_lock     = &switch_ctxt->recipe[SXE2_DEFAULT_RECIPE_PROMISC].rule_lock;
	vsi_list_lock = &switch_ctxt->vsi_list_mgmt[SXE2_VSI_LIST_TYPE_FORWARD].vsi_list_lock;

	mutex_lock(rule_lock);
	mutex_lock(vsi_list_lock);

	list_for_each_entry(rule_info, list_head, list_entry) {
		if (rule_info->vsi_list) {
			clear_bit(old_vsi, rule_info->vsi_list->vsi_map);
			set_bit(new_vsi, rule_info->vsi_list->vsi_map);
			ret = sxe2_fwd_rule_update(adapter, rule_info);
			if (ret)
				LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
		} else {
			rule_info->act.fwd_id.vsi_id = new_vsi;
			ret = sxe2_fwd_rule_update(adapter, rule_info);
			if (ret)
				LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
		}
		break;
	}

	mutex_unlock(vsi_list_lock);
	mutex_unlock(rule_lock);
	return ret;
}

STATIC s32 sxe2_com_mode_promisc_rule_add(struct sxe2_adapter *adapter,
					  u16 vsi_id)
{
	s32 ret = 0;
	struct sxe2_vsi *eth_vsi;
	struct sxe2_vsi *user_vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);
	mutex_lock(&adapter->user_pf_ctxt.flag_lock);

	eth_vsi = adapter->vsi_ctxt.main_vsi;
	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, user_vsi->state) ||
	    test_bit(SXE2_VSI_S_DISABLE, eth_vsi->state)) {
		ret = -EBUSY;
		goto l_end;
	}

	if (adapter->user_pf_ctxt.is_promisc_set) {
		LOG_ERROR_BDF("user vsi [id in dev:%u] has been set promisc\n",
			      user_vsi->idx_in_dev);
		ret = -EEXIST;
		goto l_end;
	}

	if (sxe2_promisc_rule_in_use(eth_vsi)) {
		ret = sxe2_promisc_rule_update(adapter, eth_vsi->idx_in_dev, user_vsi->idx_in_dev);
		if (ret)
			goto l_end;
	} else {
		ret = sxe2_promisc_rule_add(user_vsi);
		if (ret)
			goto l_end;
	}

	adapter->user_pf_ctxt.is_promisc_set = true;

l_end:
	mutex_unlock(&adapter->user_pf_ctxt.flag_lock);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

STATIC s32 sxe2_user_mode_promisc_rule_add(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;
	struct sxe2_vsi *user_vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);
	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, user_vsi->state)) {
		ret = -EBUSY;
		goto l_end;
	}

	if (adapter->user_pf_ctxt.is_promisc_set) {
		LOG_ERROR_BDF("user vsi [id in pf:%u] has been set promisc\n",
			      user_vsi->idx_in_dev);
		ret = -EEXIST;
		goto l_end;
	}

	ret = sxe2_promisc_rule_add(user_vsi);
	if (ret)
		goto l_end;

	adapter->user_pf_ctxt.is_promisc_set = true;

l_end:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_ucmd_promisc_rule_add(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;

	LOG_DEBUG_BDF("User pf vsi:%u promisc rule add.\n", vsi_id);

	if (sxe2_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		ret = sxe2_user_mode_promisc_rule_add(adapter, vsi_id);
	else
		ret = sxe2_com_mode_promisc_rule_add(adapter, vsi_id);
	return ret;
}

STATIC s32 sxe2_com_mode_promisc_rule_del(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;
	struct sxe2_vsi *eth_vsi;
	struct sxe2_vsi *user_vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);
	mutex_lock(&adapter->user_pf_ctxt.flag_lock);

	eth_vsi = adapter->vsi_ctxt.main_vsi;
	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, user_vsi->state) ||
	    test_bit(SXE2_VSI_S_DISABLE, eth_vsi->state)) {
		ret = -EBUSY;
		goto l_end;
	}

	if (!adapter->user_pf_ctxt.is_promisc_set) {
		LOG_WARN_BDF("user vsi [id in pf:%u] has not set promisc\n",
			     user_vsi->idx_in_dev);
		goto l_end;
	}

	if (eth_vsi->netdev->flags & IFF_PROMISC) {
		ret = sxe2_promisc_rule_update(adapter,
					       user_vsi->idx_in_dev, eth_vsi->idx_in_dev);
		if (ret)
			goto l_end;
	} else {
		ret = sxe2_promisc_rule_del(adapter, user_vsi->idx_in_dev);
		if (ret)
			goto l_end;
	}

	adapter->user_pf_ctxt.is_promisc_set = false;

l_end:
	mutex_unlock(&adapter->user_pf_ctxt.flag_lock);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

STATIC s32 sxe2_user_mode_promisc_rule_del(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;
	struct sxe2_vsi *user_vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);

	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, user_vsi->state)) {
		ret = -EBUSY;
		goto l_end;
	}

	if (!adapter->user_pf_ctxt.is_promisc_set) {
		LOG_WARN_BDF("user vsi [id in pf:%u] has not set promisc\n",
			     user_vsi->idx_in_dev);
		goto l_end;
	}

	ret = sxe2_promisc_rule_del(adapter, user_vsi->idx_in_dev);
	if (ret)
		goto l_end;

	adapter->user_pf_ctxt.is_promisc_set = false;

l_end:

	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_ucmd_promisc_rule_del(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;

	LOG_DEBUG_BDF("User pf vsi:%u promisc rule del.\n", vsi_id);

	if (sxe2_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		ret = sxe2_user_mode_promisc_rule_del(adapter, vsi_id);
	else
		ret = sxe2_com_mode_promisc_rule_del(adapter, vsi_id);
	return ret;
}

s32 sxe2_allmulti_rule_update(struct sxe2_adapter *adapter, u16 old_vsi, u16 new_vsi)
{
	s32 ret = 0;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct list_head *list_head;
	struct sxe2_rule_info *rule_info = NULL;
	/* in order to protect the data */
	struct mutex *rule_lock;
	/* in order to protect the data */
	struct mutex *vsi_list_lock;

	list_head     = &switch_ctxt->recipe[SXE2_DEFAULT_RECIPE_ALLMULTI].rule_head;
	rule_lock     = &switch_ctxt->recipe[SXE2_DEFAULT_RECIPE_ALLMULTI].rule_lock;
	vsi_list_lock = &switch_ctxt->vsi_list_mgmt[SXE2_VSI_LIST_TYPE_FORWARD].vsi_list_lock;

	mutex_lock(rule_lock);
	mutex_lock(vsi_list_lock);

	list_for_each_entry(rule_info, list_head, list_entry) {
		if (rule_info->vsi_list) {
			clear_bit(old_vsi, rule_info->vsi_list->vsi_map);
			set_bit(new_vsi, rule_info->vsi_list->vsi_map);
			ret = sxe2_fwd_rule_update(adapter, rule_info);
			if (ret)
				LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
		} else {
			rule_info->act.fwd_id.vsi_id = new_vsi;
			ret = sxe2_fwd_rule_update(adapter, rule_info);
			if (ret)
				LOG_ERROR_BDF("request to admin q failed, ret %d\n", ret);
		}
		break;
	}

	mutex_unlock(vsi_list_lock);
	mutex_unlock(rule_lock);
	return ret;
}

STATIC s32 sxe2_user_mode_allmulti_rule_add(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;
	struct sxe2_vsi *user_vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);

	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, user_vsi->state)) {
		ret = -EBUSY;
		goto l_end;
	}

	if (adapter->user_pf_ctxt.is_allmulti_set) {
		LOG_ERROR_BDF("user vsi [id in pf:%u] has been set allmulti\n",
			      user_vsi->idx_in_dev);
		ret = -EEXIST;
		goto l_end;
	}

	ret = sxe2_allmulti_rule_add(user_vsi);
	if (ret)
		goto l_end;

	adapter->user_pf_ctxt.is_allmulti_set = true;

l_end:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

STATIC s32 sxe2_com_mode_allmulti_rule_add(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;
	struct sxe2_vsi *eth_vsi;
	struct sxe2_vsi *user_vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);
	mutex_lock(&adapter->user_pf_ctxt.flag_lock);

	eth_vsi = adapter->vsi_ctxt.main_vsi;
	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, user_vsi->state) ||
	    test_bit(SXE2_VSI_S_DISABLE, eth_vsi->state)) {
		ret = -EBUSY;
		goto l_end;
	}

	if (adapter->user_pf_ctxt.is_allmulti_set) {
		LOG_ERROR_BDF("user vsi [id in pf:%u] has been set allmulti\n",
			      user_vsi->idx_in_dev);
		ret = -EEXIST;
		goto l_end;
	}

	if (sxe2_allmulti_rule_in_use(eth_vsi)) {
		ret = sxe2_allmulti_rule_update(adapter,
						eth_vsi->idx_in_dev, user_vsi->idx_in_dev);
		if (ret)
			goto l_end;
	} else {
		ret = sxe2_allmulti_rule_add(user_vsi);
		if (ret)
			goto l_end;
	}

	adapter->user_pf_ctxt.is_allmulti_set = true;

l_end:
	mutex_unlock(&adapter->user_pf_ctxt.flag_lock);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_ucmd_allmulti_rule_add(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;

	LOG_DEBUG_BDF("User pf vsi:%u allmulti rule add.\n", vsi_id);

	if (sxe2_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		ret = sxe2_user_mode_allmulti_rule_add(adapter, vsi_id);
	else
		ret = sxe2_com_mode_allmulti_rule_add(adapter, vsi_id);
	return ret;
}

STATIC s32 sxe2_user_mode_allmulti_rule_del(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;
	struct sxe2_vsi *user_vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);

	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, user_vsi->state)) {
		ret = -EBUSY;
		goto l_end;
	}

	if (!adapter->user_pf_ctxt.is_allmulti_set) {
		LOG_WARN_BDF("user vsi [id in pf:%u] has not set allmulti\n",
			     user_vsi->idx_in_dev);
		goto l_end;
	}

	ret = sxe2_allmulti_rule_del(adapter, user_vsi->idx_in_dev);
	if (ret)
		goto l_end;

	adapter->user_pf_ctxt.is_allmulti_set = false;

l_end:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

STATIC s32 sxe2_com_mode_allmulti_rule_del(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;
	struct sxe2_vsi *eth_vsi;
	struct sxe2_vsi *user_vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);
	mutex_lock(&adapter->user_pf_ctxt.flag_lock);

	eth_vsi = adapter->vsi_ctxt.main_vsi;
	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, user_vsi->state) ||
	    test_bit(SXE2_VSI_S_DISABLE, eth_vsi->state)) {
		ret = -EBUSY;
		goto l_end;
	}

	if (!adapter->user_pf_ctxt.is_allmulti_set) {
		LOG_WARN_BDF("user vsi [id in dev:%u] has not set allmulti\n",
			     user_vsi->idx_in_dev);
		goto l_end;
	}

	if ((eth_vsi->netdev->flags & IFF_ALLMULTI) ||
	    (eth_vsi->netdev->flags & IFF_PROMISC)) {
		ret = sxe2_allmulti_rule_update(adapter,
						user_vsi->idx_in_dev, eth_vsi->idx_in_dev);
		if (ret)
			goto l_end;
	} else {
		ret = sxe2_allmulti_rule_del(adapter, user_vsi->idx_in_dev);
		if (ret)
			goto l_end;
	}

	adapter->user_pf_ctxt.is_allmulti_set = false;

l_end:
	mutex_unlock(&adapter->user_pf_ctxt.flag_lock);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_ucmd_allmulti_rule_del(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;

	LOG_DEBUG_BDF("User pf vsi:%u allmulti rule del.\n", vsi_id);

	if (sxe2_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		ret = sxe2_user_mode_allmulti_rule_del(adapter, vsi_id);
	else
		ret = sxe2_com_mode_allmulti_rule_del(adapter, vsi_id);
	return ret;
}

static void sxe2_ucmd_complex_fltr_init(struct sxe2_user_cpx_fltr *user_cpx_fltr,
					struct sxe2_tcf_fltr *fltr)
{
	s32 i;
	u16 j;
	struct sxe2_tcf_key_item *item;
	struct sxe2_tcf_key_item *item_user;

	memset(fltr, 0, sizeof(*fltr));

	for (i = 0; i < SXE2_PROT_FIELD_LAST; i++) {
		item = &fltr->items[i];
		item_user = &user_cpx_fltr->items[i];

		item->type = i;
		for (j = 0; j < ARRAY_SIZE(item->mask.raw); j++) {
			item->mask.raw[j] = item_user->mask.raw[j];
			item->value.raw[j] = item_user->value.raw[j];
		}
	}

	fltr->adapter = user_cpx_fltr->adapter;
	fltr->src_vsi_id = user_cpx_fltr->src_vsi_id;
	fltr->dst_queue_id = user_cpx_fltr->dst_queue_id;
	fltr->dst_queue_high = user_cpx_fltr->dst_queue_high;
	fltr->dst_queue_group = user_cpx_fltr->dst_queue_group;
	fltr->tunnel_type = user_cpx_fltr->tunnel_type;
	fltr->action = user_cpx_fltr->action;
	fltr->src_type = user_cpx_fltr->src_type;
	fltr->prio = user_cpx_fltr->prio;
	fltr->rule_vsi_id = user_cpx_fltr->rule_vsi_id;
	fltr->backup_type = user_cpx_fltr->backup_type;
	fltr->cookie_invalid = true;
	fltr->is_user_rule = true;
	fltr->priority = SXE2_SWITCH_RECIPE_PRIO_7;
	memcpy(fltr->dst_vsi_map, user_cpx_fltr->dst_vsi_map, sizeof(fltr->dst_vsi_map));
	fltr->dst_vsi_id = user_cpx_fltr->dst_vsi_id;
}

static bool sxe2_tc_item_is_empty(struct sxe2_tcf_fltr *fltr, u16 id)
{
	u16 tmp[sizeof(union sxe2_prot_hdr) / sizeof(u16)] = { 0 };

	if (memcmp(fltr->items[id].mask.raw, tmp, sizeof(tmp)) == 0)
		return true;
	return false;
}

void sxe2_tc_item_print(struct sxe2_tcf_fltr *user_cpx_fltr)
{
	struct sxe2_adapter *adapter = user_cpx_fltr->adapter;
	struct sxe2_tcf_key_item *item;
	u16 i, j;

	for (i = 0; i < SXE2_PROT_FIELD_LAST; i++) {
		if (sxe2_tc_item_is_empty(user_cpx_fltr, i))
			continue;
		item = &user_cpx_fltr->items[i];
		for (j = 0; j < ARRAY_SIZE(item->mask.raw); j++) {
			if (!item->mask.raw[j])
				continue;
			LOG_DEBUG_BDF("item[%u][%u] value:0x%x mask:0x%x\n",
				      i, j, item->value.raw[j], item->mask.raw[j]);
		}
	}
}

static bool sxe2_user_cpx_item_is_empty(struct sxe2_user_cpx_fltr *fltr, u16 id)
{
	u16 tmp[sizeof(union sxe2_prot_hdr) / sizeof(u16)] = { 0 };

	if (memcmp(fltr->items[id].mask.raw, tmp, sizeof(tmp)) == 0)
		return true;
	return false;
}

STATIC void sxe2_user_cpx_item_print(struct sxe2_user_cpx_fltr *user_cpx_fltr)
{
	struct sxe2_adapter *adapter = user_cpx_fltr->adapter;
	struct sxe2_tcf_key_item *item;
	u16 i, j;

	for (i = 0; i < SXE2_PROT_FIELD_LAST; i++) {
		if (sxe2_user_cpx_item_is_empty(user_cpx_fltr, i))
			continue;
		item = &user_cpx_fltr->items[i];
		for (j = 0; j < ARRAY_SIZE(item->mask.raw); j++) {
			if (!item->mask.raw[j])
				continue;
			LOG_DEBUG_BDF("item[%u][%u] value:0x%x mask:0x%x\n",
				      i, j, item->value.raw[j], item->mask.raw[j]);
		}
	}
}

s32 sxe2_ucmd_complex_fltr_proc(struct sxe2_user_cpx_fltr *user_cpx_fltr,
				bool is_add)
{
	struct sxe2_tcf_fltr *fltr;
	struct sxe2_adapter *adapter = user_cpx_fltr->adapter;
	struct sxe2_vsi *vsi;
	struct sxe2_vsi *vsi_q;
	s32 ret = 0;
	u16 dst_vsi_cnt;
	u16 dst_vsi = 0;

	LOG_DEBUG_BDF("User complex rule %s. src_vsi:%u, dst_vsi:%u, \t"
		      "dst_queue_id:%u, dst_queue_high:%u, dst_queue_group:%u, \t"
		      "tunnel_type:%u, action_type:%u, src_type:%u, prio:%u, backtype:%u\n",
		      is_add ? "add" : "del",
		      user_cpx_fltr->src_vsi_id, user_cpx_fltr->dst_vsi_id,
		      user_cpx_fltr->dst_queue_id, user_cpx_fltr->dst_queue_high,
		      user_cpx_fltr->dst_queue_group, user_cpx_fltr->tunnel_type,
		      user_cpx_fltr->action, user_cpx_fltr->src_type,
		      user_cpx_fltr->prio, user_cpx_fltr->backup_type);

	while (true) {
		dst_vsi = (u16)find_next_bit((unsigned long *)user_cpx_fltr->dst_vsi_map,
					     SXE2_VSI_MAX_CNT, dst_vsi);
		if (dst_vsi >= SXE2_VSI_MAX_CNT)
			break;
		LOG_DEBUG_BDF("[in map]dst_vsi_id: %u ", dst_vsi);
		dst_vsi++;
	}

	sxe2_user_cpx_item_print(user_cpx_fltr);

	dst_vsi_cnt = bitmap_weight(user_cpx_fltr->dst_vsi_map, SXE2_VSI_MAX_CNT);
	if (user_cpx_fltr->action == SXE2_FWD_TO_VSI_LIST && dst_vsi_cnt <= 1) {
		LOG_ERROR_BDF("dst vsi count:%u, but action type is fwd to list\n",
			      dst_vsi_cnt);
		ret = -EINVAL;
		return ret;
	}

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr) {
		LOG_ERROR_BDF("alloc memory failed, size %ld\n", sizeof(*fltr));
		return -ENOMEM;
	}

	sxe2_ucmd_complex_fltr_init(user_cpx_fltr, fltr);

	sxe2_tcf_match_meta_fill(fltr);

	ret = sxe2_tcf_word_cnt_calc(fltr);
	if (ret)
		goto l_end;

	ret = sxe2_tcf_profile_find(fltr);
	if (ret)
		goto l_end;

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_idx(adapter, user_cpx_fltr->src_vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("src vsi id_in_dev:%u is NULL.\n", user_cpx_fltr->src_vsi_id);
		ret = -EINVAL;
		goto l_unlock;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		LOG_ERROR_BDF("src vsi id_in_dev:%u is disable .\n", user_cpx_fltr->src_vsi_id);
		ret = -EBUSY;
		goto l_unlock;
	}

	if (fltr->action == SXE2_FWD_TO_Q || fltr->action == SXE2_FWD_TO_QGRP) {
		vsi_q = sxe2_vsi_get_by_idx(adapter, user_cpx_fltr->dst_vsi_id);
		if (!vsi_q) {
			LOG_ERROR_BDF("dst vsi id_in_dev:%u is NULL\n", user_cpx_fltr->dst_vsi_id);
			ret = -EINVAL;
			goto l_unlock;
		}
		if (test_bit(SXE2_VSI_S_DISABLE, vsi_q->state)) {
			LOG_ERROR_BDF("dst vsi id_in_dev:%u is disable\n",
				      user_cpx_fltr->dst_vsi_id);
			ret = -EBUSY;
			goto l_unlock;
		}
		if (vsi_q->rxqs.q_cnt < user_cpx_fltr->dst_queue_id) {
			LOG_ERROR_BDF("dst vsi queue count %u insufficient for flow queue id %u\n",
				      vsi_q->rxqs.q_cnt, user_cpx_fltr->dst_queue_id);
			ret = -EINVAL;
			goto l_unlock;
		}
		fltr->dst_queue_id = vsi_q->rxqs.q[user_cpx_fltr->dst_queue_id]->idx_in_pf +
			     adapter->q_ctxt.rxq_base_idx_in_dev;
	}

	ret = is_add ? sxe2_tcf_rule_add(adapter, vsi->idx_in_dev, fltr) :
		       sxe2_tcf_rule_del(adapter, vsi->idx_in_dev, fltr);

	dst_vsi = 0;
	if (user_cpx_fltr->action == SXE2_FWD_TO_VSI_LIST) {
		LOG_DEBUG_BDF("user complex rule %s %s, rule vsi %u, src vsi %u dst vsi list\n",
			      is_add ? "add" : "del", ret ? "failed" : "success",
			      fltr->rule_vsi_id, fltr->src_vsi_id);
	} else {
		LOG_DEBUG_BDF("user complex rule %s %s, rule vsi %u, src vsi %u, \t"
			      "dst vsi %u, queue in dev %u\n",
			      is_add ? "add" : "del", ret ? "failed" : "success",
			      fltr->rule_vsi_id, fltr->src_vsi_id,
			      user_cpx_fltr->dst_vsi_id, fltr->dst_queue_id);
	}

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
l_end:
	kfree(fltr);
	return ret;
}

s32 sxe2_ucmd_vlan_rule_process(struct sxe2_adapter *adapter, u16 vsi_hw_id,
				struct sxe2_vlan *vlan, bool add)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi;

	LOG_DEBUG_BDF("User pf vsi:%u %s vlan rule, vid:%u, tpid:%u\n",
		      vsi_hw_id, add ? "add" : "del", vlan->vid, vlan->tpid);

	mutex_lock(&adapter->vsi_ctxt.lock);

	vsi = sxe2_vsi_get_by_idx(adapter, vsi_hw_id);
	if (!vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (add)
		ret = sxe2_vlan_rule_add(vsi, vlan);
	else
		ret = sxe2_vlan_rule_del(adapter, vsi->idx_in_dev, vlan);

l_end:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_ucmd_vlan_filter_control(struct sxe2_adapter *adapter, u16 vsi_hw_id,
				  bool en)
{
	LOG_DEBUG_BDF("User pf vsi:%u vlan filter set to %u.\n", vsi_hw_id, en);
	return sxe2_vlan_filter_control(adapter, vsi_hw_id, en);
}

static void sxe2_user_unicast_mac_rest(struct sxe2_adapter *adapter, struct sxe2_vsi *user_vsi,
				       struct sxe2_vsi *eth_vsi)
{
	s32 ret = 0;
	struct sxe2_addr_node *user_node;
	struct sxe2_addr_node *eth_node;
	struct sxe2_addr_node *tmp_1;
	struct sxe2_addr_node *tmp_2;
	struct sxe2_mac_filter *eth_mac_fltr;
	struct sxe2_mac_filter *user_mac_fltr;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;

	eth_mac_fltr = &eth_vsi->mac_filter;
	user_mac_fltr = &user_vsi->mac_filter;

	mutex_lock(&switch_ctxt->mac_addr_lock);
	list_for_each_entry_safe(user_node, tmp_1, &user_mac_fltr->mac_addr_list, list) {
		if (is_unicast_ether_addr(user_node->mac_addr)) {
			list_for_each_entry_safe(eth_node, tmp_2,
						 &eth_mac_fltr->mac_addr_list, list) {
				if (!memcmp(user_node->mac_addr, eth_node->mac_addr,
					    sizeof(user_node->mac_addr))) {
					ret = sxe2_mac_rule_update(adapter, user_node->mac_addr,
								   user_vsi->idx_in_dev,
								   eth_vsi->idx_in_dev);
					if (ret) {
						LOG_ERROR_BDF("user vsi %u mac %pM, \t"
							      "update to eth vsi %u failed.\n",
							      user_vsi->idx_in_dev,
							      user_node->mac_addr,
							      eth_vsi->idx_in_dev);
					}
					break;
				}
			}
		}

		sxe2_switch_mac_node_del_and_free(user_node);
	}
	mutex_unlock(&switch_ctxt->mac_addr_lock);
}

static void sxe2_user_mac_node_clean(struct sxe2_adapter *adapter, struct sxe2_vsi *user_vsi)
{
	struct sxe2_addr_node *user_node;
	struct sxe2_addr_node *tmp;
	struct sxe2_mac_filter *user_mac_fltr;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;

	user_mac_fltr = &user_vsi->mac_filter;

	mutex_lock(&switch_ctxt->mac_addr_lock);
	list_for_each_entry_safe(user_node, tmp, &user_mac_fltr->mac_addr_list, list) {
		sxe2_switch_mac_node_del_and_free(user_node);
	}
	mutex_unlock(&switch_ctxt->mac_addr_lock);
}

static void sxe2_user_promisc_allmulti_rest(struct sxe2_adapter *adapter, struct sxe2_vsi *user_vsi,
					    struct sxe2_vsi *eth_vsi)
{
	s32 ret = 0;

	mutex_lock(&adapter->user_pf_ctxt.flag_lock);
	if ((adapter->user_pf_ctxt.is_allmulti_set &&
	     (eth_vsi->netdev->flags & IFF_ALLMULTI)) ||
	    (eth_vsi->netdev->flags & IFF_PROMISC)) {
		ret = sxe2_allmulti_rule_update(adapter, user_vsi->idx_in_dev,
						eth_vsi->idx_in_dev);
		if (ret) {
			LOG_ERROR_BDF("user vsi %u allmulti rule, update to eth vsi %u failed.\n",
				      user_vsi->idx_in_dev, eth_vsi->idx_in_dev);
		}
	}
	if (adapter->user_pf_ctxt.is_promisc_set &&
	    eth_vsi->netdev->flags & IFF_PROMISC) {
		ret = sxe2_promisc_rule_update(adapter, user_vsi->idx_in_dev,
					       eth_vsi->idx_in_dev);
		if (ret) {
			LOG_ERROR_BDF("user vsi %u promisc rule, update to eth vsi %u failed.\n",
				      user_vsi->idx_in_dev, eth_vsi->idx_in_dev);
		}
	}

	adapter->user_pf_ctxt.is_allmulti_set = false;
	adapter->user_pf_ctxt.is_promisc_set = false;

	mutex_unlock(&adapter->user_pf_ctxt.flag_lock);
}

static void sxe2_user_promisc_allmulti_clean(struct sxe2_adapter *adapter,
					     struct sxe2_vsi *user_vsi)
{
	mutex_lock(&adapter->user_pf_ctxt.flag_lock);
	adapter->user_pf_ctxt.is_allmulti_set = false;
	adapter->user_pf_ctxt.is_promisc_set = false;
	mutex_unlock(&adapter->user_pf_ctxt.flag_lock);
}

s32 sxe2_user_l2_feature_clean(struct sxe2_adapter *adapter, u16 vsi_hw_id)
{
	s32 ret = 0;
	struct sxe2_vsi *user_vsi;
	struct sxe2_vsi *eth_vsi;

	LOG_DEBUG_BDF("User pf vsi:%u clean l2 feature.\n", vsi_hw_id);

	user_vsi = sxe2_vsi_get_by_idx(adapter, vsi_hw_id);
	if (!user_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (sxe2_com_mode_get(adapter) != SXE2_COM_MODULE_DPDK) {
		eth_vsi = adapter->vsi_ctxt.main_vsi;
		sxe2_user_unicast_mac_rest(adapter, user_vsi, eth_vsi);

		if (sxe2_eswitch_is_offload(adapter) && sxe2_vf_is_exist(adapter))
			(void)sxe2_eswitch_ucmd_uplink_resetto_ker(adapter);
		else
			sxe2_user_promisc_allmulti_rest(adapter, user_vsi, eth_vsi);
	} else {
		sxe2_user_mac_node_clean(adapter, user_vsi);
		sxe2_user_promisc_allmulti_clean(adapter, user_vsi);
	}

l_end:
	return ret;
}
