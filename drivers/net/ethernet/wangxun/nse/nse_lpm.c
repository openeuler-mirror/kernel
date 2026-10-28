// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_lib.h"
#include "nse_lpm.h"

static struct nse_lpm_map nse_lpm_mapping[NSE_MAX_LPM_LKUP_LUTS] = {
	{ true,			4,		64,
		0,				64},
	{ false,		3,		(64+48),
		64,				48},
	{ false,		3,		(64+48*2),		(64+48),		48},
	{ false,		3,		(64+48*3),		(64+48*2),		48},
	{ false,		3,		(64+48*4),		(64+48*3),		48},
	{ false,		3,		(64+48*5),		(64+48*4),		48},
};

u16 g_nse_ipv4_rt_lut_id = -1;
u16 g_nse_ipv6_rt_lut_id = -1;
u16 g_nse_dmac_ipv4_rt_lut_id = -1;
u16 g_nse_dmac_ipv6_rt_lut_id = -1;
struct hlist_head lpm_fltr_list;

/**
 * nse_lpm_find_rule_entry - Search a rule entry
 * @list_head: head of rule list
 * @f_info: rule information
 *
 * Helper function to search for a given rule entry
 * Returns pointer to entry storing the rule if found
 */
static struct nse_lpm_mgmt_list_entry *
nse_lpm_find_rule_entry(struct list_head *list_head,
		    struct nse_lpm_info *f_info)
{
	struct nse_lpm_mgmt_list_entry *list_itr, *ret = NULL;

	list_for_each_entry(list_itr, list_head, list_entry) {
		if (!memcmp(&f_info->ip_addr, &list_itr->info.ip_addr,
			    sizeof(f_info->ip_addr))) {
			ret = list_itr;
			break;
		}
	}
	return ret;
}

/**
 * nse_fill_lpm_node - Helper function to fill one lut node structure
 * @hw: pointer to the hardware structure
 * @f_info: entry containing packet forwarding information
 * @lut_node: lut node structure to be filled in based on f_info
 * @opc: lut nodes population command type - pass in the command opcode
 */
static void
nse_fill_lpm_node(struct nse_hw *hw, struct nse_lpm_info *f_info,
		 struct nse_aqc_lut_node_elem *lut_node,
		 enum nse_adminq_opc_category_switch_subcodes opc)
{
	u16 act = NSE_SINGLE_FWD_LAN_DISABLE, tmp = 0;
	struct nse_ip_route_addr *ip_addr = &f_info->ip_addr;

	if (opc == NSE_AQ_OPC_REMOVE_LUT_NODE || opc == NSE_AQ_OPC_GET_LUT_NODE) {
		lut_node->action = 0;
		lut_node->lut_id = cpu_to_le16(f_info->lkup_type);
		lut_node->node_id = cpu_to_le16(f_info->fltr_node_id);
		return;
	}

	switch (f_info->fltr_act) {
	case NSE_FWD_TO_VSI:
		act |= (NSE_SINGLE_ACT_TYPE_FWD << NSE_SINGLE_ACT_TYPE_FWD_S) &
			NSE_SINGLE_ACT_TYPE_FWD_M;

		act |= (f_info->dst_vsi_id << NSE_SINGLE_FWD_VSI_ID_S) &
			NSE_SINGLE_FWD_VSI_ID_M;

		if (f_info->lb_en)
			act |= (NSE_SINGLE_FWD_VSI_EN_LB << NSE_SINGLE_FWD_TYPE_S) &
					NSE_SINGLE_FWD_TYPE_M;
		else
			act |= (NSE_SINGLE_FWD_VSI_DIS_LB << NSE_SINGLE_FWD_TYPE_S) &
					NSE_SINGLE_FWD_TYPE_M;

		if (f_info->lan_en)
			act &= ~NSE_SINGLE_FWD_LAN_DISABLE;
		break;

	case NSE_FWD_TO_LAN:
		act |= (0 << NSE_SINGLE_FWD_VSI_LIST_ID_S) &
			NSE_SINGLE_FWD_VSI_LIST_ID_M;

		act |= (NSE_SINGLE_FWD_VSI_LIST_DIS_LB << NSE_SINGLE_FWD_TYPE_S) &
				NSE_SINGLE_FWD_TYPE_M;

		if (f_info->lan_en)
			act &= ~NSE_SINGLE_FWD_LAN_DISABLE;
		else
			act |= NSE_SINGLE_FWD_LAN_DISABLE;

		break;

	case NSE_DROP_PACKET:
		act |= (NSE_SINGLE_ACT_TYPE_FWD << NSE_SINGLE_ACT_TYPE_FWD_S) &
			NSE_SINGLE_ACT_TYPE_FWD_M;

		act |= (NSE_SINGLE_FWD_DROP << NSE_SINGLE_FWD_TYPE_S) &
				NSE_SINGLE_FWD_TYPE_M;
		break;

	default:
		return;
	}

	switch (f_info->lkup_type) {
	case NSE_LPM_LKUP_IPV4:
		tmp = be16_to_cpu(*((__force __be16 *)&ip_addr->dst_ip.v4));
		lut_node->key[4] = cpu_to_le16(tmp);
		tmp = be16_to_cpu(*((__force __be16 *)&ip_addr->dst_ip.v4 + 1));
		lut_node->key[3] = cpu_to_le16(tmp);
		lut_node->key[0] = cpu_to_le16((u16)(ip_addr->prefix_len & NSE_LPM_PREFIX_M));
		break;

	default:
		break;
	}

	lut_node->lut_id = cpu_to_le16(f_info->lkup_type);
	lut_node->action = cpu_to_le16(act);

	dev_info(nse_hw_to_dev(hw), "[%s, %d] lut id is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->lut_id));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] original node_id is 0x%x\n",
		 __func__, __LINE__, cpu_to_le16(lut_node->node_id));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key4 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[4]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key3 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[3]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key2 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[2]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key1 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[1]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key0 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[0]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] action is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->action));
}

/**
 * nse_lpm_create_pkt_node - create a new lpm entry to hw
 * @hw: pointer to the HW struct
 * @new_info: pointer to lpm entry info
 * @lut_info: pointer to lut information
 */
static int
nse_lpm_create_pkt_node(struct nse_hw *hw,
			struct nse_lpm_info *new_info,
			struct nse_lut_info *lut)
{
	struct nse_lpm_mgmt_list_entry *fm_entry;
	struct nse_aqc_lut_nodes *buf;
	struct nse_aqc_lut_node_elem *lpm_node;
	int status = 0;
	u16 buf_size = struct_size(buf, elem, 1);

	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	lpm_node = buf->elem;

	fm_entry = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*fm_entry),
				GFP_KERNEL);
	if (!fm_entry) {
		status = -ENOMEM;
		goto nse_lpm_create_pkt_node_exit;
	}

	fm_entry->info = *new_info;
	nse_fill_lpm_node(hw, &fm_entry->info, lpm_node,
			 NSE_AQ_OPC_ADD_LUT_NODE);

	status = nse_aq_lut_nodes(hw, buf, buf_size,
				 NSE_AQ_OPC_ADD_LUT_NODE, NULL);
	if (status) {
		devm_kfree(nse_hw_to_dev(hw), fm_entry);
		goto nse_lpm_create_pkt_node_exit;
	}

	fm_entry->info.fltr_node_id = le16_to_cpu(lpm_node->node_id);
	list_add_tail(&fm_entry->list_entry, &lut->filt_rules);

	dev_info(nse_hw_to_dev(hw), "[%s, %d] returned lpm node_id is %d\n", __func__, __LINE__,
				fm_entry->info.fltr_node_id);

nse_lpm_create_pkt_node_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_lpm_remove_pkt_node - remove a new lpm entry to hw
 * @hw: pointer to the HW struct
 * @new_info: pointer to lpm entry info
 * @lut_info: pointer to lut information
 */
static int
nse_lpm_remove_pkt_node(struct nse_hw *hw,
			struct nse_lpm_mgmt_list_entry *lpm_entry,
			struct nse_lut_info *lut)
{
	struct nse_aqc_lut_nodes *buf;
	struct nse_aqc_lut_node_elem *lpm_node;
	int status = 0;
	u16 buf_size = struct_size(buf, elem, 1);

	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	lpm_node = buf->elem;

	nse_fill_lpm_node(hw, &lpm_entry->info, lpm_node,
			 NSE_AQ_OPC_REMOVE_LUT_NODE);

	dev_info(nse_hw_to_dev(hw), "[%s, %d] start to remove node\n", __func__, __LINE__);
	dev_info(nse_hw_to_dev(hw), "[%s, %d] lut id is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lpm_node->lut_id));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] node_id is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lpm_node->node_id));

	status = nse_aq_lut_nodes(hw, buf, buf_size,
				 NSE_AQ_OPC_REMOVE_LUT_NODE, NULL);
	if (status)
		goto nse_lpm_remove_pkt_node_exit;

	/* Remove the software filter DB entry from the list */
	list_del(&lpm_entry->list_entry);
	devm_kfree(nse_hw_to_dev(hw), lpm_entry);

nse_lpm_remove_pkt_node_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_lpm_add_node - add single ip address lpm entry to hw
 * @hw: pointer to the HW struct
 * @new_entry: pointer to lpm entry info
 * @lut: pointer to lut information
 */
static int
nse_lpm_add_node(struct nse_hw *hw, struct nse_lpm_info *new_entry,
			struct nse_lut_info *lut)
{
	struct nse_lpm_mgmt_list_entry *m_entry = NULL;
	struct mutex *rule_lock;
	int err = 0;

	rule_lock = &lut->filt_rule_lock;
	mutex_lock(rule_lock);
	m_entry = nse_lpm_find_rule_entry(&lut->filt_rules, new_entry);
	if (m_entry) {
		dev_err(nse_hw_to_dev(hw), "ipv4 lpm node is existed\n");
		err = -EEXIST;
		goto err_nse_add_lpm_node;
	}

	err = nse_lpm_create_pkt_node(hw, new_entry, lut);
	if (err)
		dev_err(nse_hw_to_dev(hw), "Failed to create lpm node, err = %d\n", err);

err_nse_add_lpm_node:
	mutex_unlock(rule_lock);
	return err;
}

/**
 * nse_lpm_del_node - del single ip address lpm entry to hw
 * @hw: pointer to the HW struct
 * @new_entry: pointer to lpm entry info
 * @lut: pointer to lut information
 */
static int
nse_lpm_del_node(struct nse_hw *hw, struct nse_lpm_info *new_entry,
			struct nse_lut_info *lut)
{
	struct nse_lpm_mgmt_list_entry *m_entry = NULL;
	struct mutex *rule_lock;
	int err = 0;

	rule_lock = &lut->filt_rule_lock;
	mutex_lock(rule_lock);
	m_entry = nse_lpm_find_rule_entry(&lut->filt_rules, new_entry);
	if (!m_entry) {
		dev_info(nse_hw_to_dev(hw), "ipv4 lpm node is not existed\n");
		err = -ENOENT;
		goto err_nse_add_lpm_node;
	}

	err = nse_lpm_remove_pkt_node(hw, m_entry, lut);
	if (err)
		dev_err(nse_hw_to_dev(hw), "Failed to remove lpm node, err = %d\n", err);

err_nse_add_lpm_node:
	mutex_unlock(rule_lock);
	return err;
}

/**
 * nse_lpm_add_ipv4_addr - add single ipv4 address lpm entry
 * @hw: pointer to the HW struct
 * @lpm_entry: pointer to lpm entry info
 */
int
nse_lpm_add_ipv4_addr(struct nse_hw *hw, struct nse_lpm_info *lpm_entry)
{
	struct nse_lut_info *lut = NULL;
	u32 dip = 0, shift_len;
	int err = 0;

	if (!hw || !lpm_entry) {
		dev_err(nse_hw_to_dev(hw),
			"it's err that hw and info is NULL\n");
		return -EINVAL;
	}

	lut = &hw->switch_info->lut_list[NSE_LPM_LKUP_IPV4];

	if (lpm_entry->ip_addr.prefix_len > 32)
		lpm_entry->ip_addr.prefix_len = 32;

	if (lpm_entry->ip_addr.prefix_len == 0) {
		dev_err(nse_hw_to_dev(hw),
			"it's err that prefix len is 0\n");
		return -EINVAL;
	}

	shift_len = 32 - lpm_entry->ip_addr.prefix_len;
	dip = ntohl(lpm_entry->ip_addr.dst_ip.v4);
	dip = (dip >> shift_len) << shift_len;
	lpm_entry->ip_addr.dst_ip.v4 = htonl(dip);

	dev_info(nse_hw_to_dev(hw),
		"route's family is AF_INET, prefix_len is %d\n",
		lpm_entry->ip_addr.prefix_len);

	dev_info(nse_hw_to_dev(hw),
		"IPV4 subnet = %pI4\n",
		&lpm_entry->ip_addr.dst_ip.v4);

	err = nse_lpm_add_node(hw, lpm_entry, lut);
	if (err) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to add hw lpm node, err = %d\n", err);
	}

	return err;
}

/**
 * nse_lpm_del_ipv4_addr - del single ipv4 address lpm entry
 * @hw: pointer to the HW struct
 * @lpm_entry: pointer to lpm entry info
 */
int
nse_lpm_del_ipv4_addr(struct nse_hw *hw, struct nse_lpm_info *lpm_entry)
{
	struct nse_lut_info *lut = NULL;
	u32 dip = 0, shift_len;
	int err = 0;

	if (!hw || !lpm_entry) {
		dev_err(nse_hw_to_dev(hw),
			"it's err that hw and info is NULL\n");
		return -EINVAL;
	}

	lut = &hw->switch_info->lut_list[NSE_LPM_LKUP_IPV4];

	if (lpm_entry->ip_addr.prefix_len > 32)
		lpm_entry->ip_addr.prefix_len = 32;

	if (lpm_entry->ip_addr.prefix_len == 0) {
		dev_err(nse_hw_to_dev(hw),
			"it's err that prefix len is 0\n");
		return -EINVAL;
	}

	shift_len = 32 - lpm_entry->ip_addr.prefix_len;
	dip = htonl(lpm_entry->ip_addr.dst_ip.v4);
	dip = (dip >> shift_len) << shift_len;
	lpm_entry->ip_addr.dst_ip.v4 = ntohl(dip);

	dev_info(nse_hw_to_dev(hw),
		"route's family is AF_INET, prefix_len is %d\n",
		lpm_entry->ip_addr.prefix_len);

	dev_info(nse_hw_to_dev(hw),
		"IPV4 subnet = %pI4\n",
		&lpm_entry->ip_addr.dst_ip.v4);

	err = nse_lpm_del_node(hw, lpm_entry, lut);
	if (err) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to del hw lpm node, err = %d\n", err);
	}

	return err;
}

/**
 * nse_dump_lpm_ipv4_entry - dump all ipv4 address lpm entry
 * @hw: pointer to the HW struct
 */
void
nse_dump_lpm_ipv4_entry(struct nse_hw *hw)
{
	struct nse_lut_info *lut = NULL;
	struct nse_lpm_mgmt_list_entry *fm_entry;
	struct nse_lpm_info *lpm;
	struct list_head *rule_head;
	struct mutex *rule_lock; /* Lock to protect filter rule list */
	int i = 0;

	lut = &hw->switch_info->lut_list[NSE_LPM_LKUP_IPV4];
	rule_lock = &lut->filt_rule_lock;
	rule_head = &lut->filt_rules;

	if (list_empty(rule_head)) {
		dev_info(nse_hw_to_dev(hw),	"There is no ipv4 route entry!\n");
		return;
	}

	mutex_lock(rule_lock);
	list_for_each_entry(fm_entry, rule_head, list_entry) {
		lpm = &fm_entry->info;
		dev_info(nse_hw_to_dev(hw),	"ipv4_rt entry[%d]:\n", i);
		dev_info(nse_hw_to_dev(hw), "\t IPV4 Value = %pI4, prefix_len = %d, family = %d\n",
			&lpm->ip_addr.dst_ip.v4, lpm->ip_addr.prefix_len, lpm->ip_addr.family);
		dev_info(nse_hw_to_dev(hw), "\t lut_id = %d, node_id = %d, action type = %d\n",
			lpm->lkup_type, lpm->fltr_node_id, lpm->fltr_act);
		dev_info(nse_hw_to_dev(hw), "\t action detail: dest_vsi_id = %d, lb_en = %d, lan_en = %d\n",
			lpm->dst_vsi_id, lpm->lb_en, lpm->lan_en);
		i++;
	}
	mutex_unlock(rule_lock);

	dev_info(nse_hw_to_dev(hw), "Total ipv4_rt entry num is %d\n", i);
}

void nse_dump_adv_lpm_lut_nodes(struct nse_hw *hw, u8 lut_id)
{
	struct nse_switch_info *sw;
	struct nse_adv_lpm_mgmt_list_entry *adv_fltr = NULL;
	struct mutex *rule_lock; /* Lock to protect filter rule list */
	u16 j, i = 0;

	sw = hw->switch_info;
	rule_lock = &sw->lut_list[lut_id].filt_rule_lock;

	if (!sw->lut_list[lut_id].adv_rule) {
		dev_info(nse_hw_to_dev(hw), "Lut[%d] is a NULL Lkup Table\n", lut_id);
		return;
	}

	if (!sw->lut_list[lut_id].is_lpm) {
		dev_info(nse_hw_to_dev(hw), "Lut[%d] is not a lpm Table\n", lut_id);
		return;
	}

	mutex_lock(rule_lock);

	list_for_each_entry(adv_fltr, &sw->lut_list[lut_id].filt_rules,
			    list_entry) {
		dev_info(nse_hw_to_dev(hw), "Lut[%d] - Entry[%d]:\n", lut_id, i);
		if (adv_fltr->node_info.sw_act.fltr_act == NSE_FWD_TO_VSI) {
			dev_info(nse_hw_to_dev(hw), "It is to Single VSI: %d\n",
				adv_fltr->node_info.sw_act.fwd_id.vsi_id);
		} else if (adv_fltr->node_info.sw_act.fltr_act == NSE_LARGE_ACT) {
			dev_info(nse_hw_to_dev(hw), "It is a Large Action: node state id = %d\n",
				adv_fltr->node_info.sw_act.large_act_id);
		} else if (adv_fltr->node_info.sw_act.fltr_act == NSE_FWD_TO_VSI_LIST) {
			dev_info(nse_hw_to_dev(hw), "It is to VSI List: %d\n",
				adv_fltr->node_info.sw_act.fwd_id.vsi_list_id);
		}
		dev_info(nse_hw_to_dev(hw),
					"is_lpm = %d, prefix_len = %d, rx = %d, lb_en = %d, lan_en = %d\n",
					adv_fltr->node_info.is_lpm, adv_fltr->node_info.prefix_len,
					adv_fltr->node_info.rx,
					!!(adv_fltr->node_info.flags_info.act & NSE_LB_ENABLE),
					!!(adv_fltr->node_info.flags_info.act & NSE_LAN_ENABLE));
		dev_info(nse_hw_to_dev(hw), "tun_type = %d, act_type = %d, fwd_id = 0x%x, lg_act_id = 0x%x\n",
					adv_fltr->node_info.tun_type,
						adv_fltr->node_info.sw_act.fltr_act,
					adv_fltr->node_info.sw_act.fwd_id.vsi_id,
						adv_fltr->node_info.sw_act.large_act_id);
		dev_info(nse_hw_to_dev(hw), "root_node_id = 0x%x\n",
					adv_fltr->node_info.fltr_node_id);
		dev_info(nse_hw_to_dev(hw), "sub_node_id[0] = 0x%x\n",
			 adv_fltr->node_info.sub_fltr_node_id[0]);
		dev_info(nse_hw_to_dev(hw), "sub_node_id[1] = 0x%x\n",
			 adv_fltr->node_info.sub_fltr_node_id[1]);
		dev_info(nse_hw_to_dev(hw), "sub_node_id[2] = 0x%x\n",
			 adv_fltr->node_info.sub_fltr_node_id[2]);
		dev_info(nse_hw_to_dev(hw), "sub_node_id[3] = 0x%x\n",
			 adv_fltr->node_info.sub_fltr_node_id[3]);
		dev_info(nse_hw_to_dev(hw), "sub_node_id[4] = 0x%x\n",
			 adv_fltr->node_info.sub_fltr_node_id[4]);

		dev_info(nse_hw_to_dev(hw), "\t user match protocol header cnt = %d\n",
					adv_fltr->lkups_cnt);
		for (j = 0; j < adv_fltr->lkups_cnt; j++) {
			dev_info(nse_hw_to_dev(hw), "\t lkups[%d]: prot hdr type= %d\n",
				j, adv_fltr->lkups[j].type);

			if (adv_fltr->lkups[j].type == NSE_MAC_OFOS
				|| adv_fltr->lkups[j].type == NSE_MAC_IL) {
				dev_info(nse_hw_to_dev(hw), "\t DMac Address Value = %pM\n",
					adv_fltr->lkups[j].h_u.eth_hdr.dst_addr);
				dev_info(nse_hw_to_dev(hw), "\t SMac Address Value = %pM\n",
					adv_fltr->lkups[j].h_u.eth_hdr.src_addr);
				dev_info(nse_hw_to_dev(hw), "\t DMac Address Mask = %pM\n",
					adv_fltr->lkups[j].m_u.eth_hdr.dst_addr);
				dev_info(nse_hw_to_dev(hw), "\t SMac Address Mask = %pM\n",
					adv_fltr->lkups[j].m_u.eth_hdr.src_addr);
			} else if (adv_fltr->lkups[j].type == NSE_IPV4_OFOS
					|| adv_fltr->lkups[j].type == NSE_IPV4_IL) {
				dev_info(nse_hw_to_dev(hw), "\t IPV4 DIP Value = %pI4\n",
					&adv_fltr->lkups[j].h_u.ipv4_hdr.dst_addr);
				dev_info(nse_hw_to_dev(hw), "\t IPV4 SIP Value = %pI4\n",
					&adv_fltr->lkups[j].h_u.ipv4_hdr.src_addr);
				dev_info(nse_hw_to_dev(hw), "\t IPV4 DIP Mask = %pI4\n",
					&adv_fltr->lkups[j].m_u.ipv4_hdr.dst_addr);
				dev_info(nse_hw_to_dev(hw), "\t IPV4 SIP Mask = %pI4\n",
					&adv_fltr->lkups[j].m_u.ipv4_hdr.src_addr);
			} else if (adv_fltr->lkups[j].type == NSE_IPV6_OFOS
				|| adv_fltr->lkups[j].type == NSE_IPV6_IL) {
				dev_info(nse_hw_to_dev(hw), "\t IPV6 DIP Value = %pI6c\n",
					adv_fltr->lkups[j].h_u.ipv6_hdr.dst_addr);
				dev_info(nse_hw_to_dev(hw), "\t IPV6 SIP Value = %pI6c\n",
					adv_fltr->lkups[j].h_u.ipv6_hdr.src_addr);
				dev_info(nse_hw_to_dev(hw), "\t IPV6 DIP Mask = %pI6c\n",
					adv_fltr->lkups[j].m_u.ipv6_hdr.dst_addr);
				dev_info(nse_hw_to_dev(hw), "\t IPV6 SIP Mask = %pI6c\n",
					adv_fltr->lkups[j].m_u.ipv6_hdr.src_addr);
			} else if (adv_fltr->lkups[j].type == NSE_TCP_IL
				|| adv_fltr->lkups[j].type == NSE_UDP_OF
				|| adv_fltr->lkups[j].type == NSE_UDP_ILOS) {
				dev_info(nse_hw_to_dev(hw), "\t L4 Dport Value = %d\n",
					ntohs(adv_fltr->lkups[j].h_u.l4_hdr.dst_port));
				dev_info(nse_hw_to_dev(hw), "\t L4 Sport Value = %d\n",
					ntohs(adv_fltr->lkups[j].h_u.l4_hdr.src_port));
				dev_info(nse_hw_to_dev(hw), "\t L4 Dport Mask = %d\n",
					ntohs(adv_fltr->lkups[j].m_u.l4_hdr.dst_port));
				dev_info(nse_hw_to_dev(hw), "\t L4 Sport Mask = %d\n",
					ntohs(adv_fltr->lkups[j].m_u.l4_hdr.src_port));
			} else
				dev_info(nse_hw_to_dev(hw),
						"\t Not Supported to parse the key values\n");
		}

		i++;
	}

	mutex_unlock(rule_lock);
}

/**
 * nse_lpm_fill_node_info
 *
 * @hw: pointer to the HW struct
 * @fltr: lpm fltr information after previous parsing
 */
static int
nse_lpm_fill_node_info(struct nse_hw *hw,
		struct nse_lpm_fltr *fltr,
		struct nse_adv_node_info *node_info)
{
	struct nse_lpm_action *action = &fltr->action;
	struct nse_vsi *dest_vsi = NULL;

	node_info->sw_act.fltr_act = action->fltr_act;
	node_info->flags_info.act_valid = true;
	node_info->flags_info.act = 0;

	/*set dest vsi information*/
	switch (action->fltr_act) {
	case NSE_FWD_TO_VSI:
		dest_vsi = action->dest_vsi;
		node_info->sw_act.fwd_id.hw_vsi_id =
				nse_get_hw_vsi_num(hw, dest_vsi->idx);
		node_info->flags_info.act |= NSE_LB_ENABLE;
		break;
	case NSE_FWD_TO_LAN:
		node_info->flags_info.act |= NSE_LAN_ENABLE;
		break;
	case NSE_DROP_PACKET:
		break;
	default:
		dev_err(nse_hw_to_dev(hw),
			"Action type(%d) is not supported in erouter\n", action->fltr_act);
		return -EINVAL;
	}

	return 0;
}

/**
 * nse_lpm_count_lkups - determine lookup count for erouter filter
 * @ip_key: Pointer to lpm filter header structure
 *
 * Determine lookup count based on lpm fltr input for erouter filter.
 */
static int
nse_lpm_count_lkups(struct nse_ip_route_addr *ip_key)
{
	int lkups_cnt = 0;

	if (!ip_key)
		return 0;

	if (ip_key->is_w_dmac)
		lkups_cnt++;

	if (ip_key->family == AF_INET)
		lkups_cnt++;
	else if (ip_key->family == AF_INET6)
		lkups_cnt++;

	return lkups_cnt;
}

/**
 * nse_lpm_fill_rules - fill lkup element list based on lpm fltr
 * @fltr: pointer to lpm filter
 * @lkups: list of advance rule elements
 * @node_info: pointer to information about node
 *
 */
static int
nse_lpm_fill_rules(struct nse_lpm_fltr *fltr,
		  struct nse_adv_lkup_elem *lkups,
		  struct nse_adv_node_info *node_info)
{
	struct nse_ip_route_addr *ip_key = &fltr->ip_key;
	u8 broadcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	int i = 0;

	node_info->is_lpm = true;
	node_info->prefix_len = ip_key->prefix_len;
	node_info->tun_type = NSE_NON_TUN;

	if (ip_key->is_w_dmac) {
		ether_addr_copy(lkups[i].h_u.eth_hdr.dst_addr,
				ip_key->dst_mac);
		ether_addr_copy(lkups[i].m_u.eth_hdr.dst_addr,
				broadcast);
		i++;
	}

	if (ip_key->family == AF_INET) {
		lkups[i].type = NSE_IPV4_OFOS;
		lkups[i].h_u.ipv4_hdr.dst_addr = ip_key->dst_ip.v4;
		lkups[i].m_u.ipv4_hdr.dst_addr = cpu_to_be32(0xFFFFFFFF);
		i++;
	} else if (ip_key->family == AF_INET6) {
		struct nse_ipv6_hdr *ipv6_hdr, *ipv6_mask;

		lkups[i].type = NSE_IPV6_OFOS;

		ipv6_hdr = &lkups[i].h_u.ipv6_hdr;
		ipv6_mask = &lkups[i].m_u.ipv6_hdr;
		memcpy(&ipv6_hdr->dst_addr, &ip_key->dst_ip.v6.s6_addr,
		       sizeof(ip_key->dst_ip.v6.s6_addr));
		memset(&ipv6_mask->dst_addr, 0xFF,
			   sizeof(ip_key->dst_ip.v6.s6_addr));
		i++;
	}

	return i;
}

/**
 * nse_lpm_find_adv_rule_entry - Search a rule entry
 * @hw: pointer to the hardware structure
 * @lkups: lookup elements or match criteria for the advanced recipe, one
 *	   structure per protocol header
 * @lkups_cnt: number of protocols
 * @lut_id: lut ID for which we are finding the rule
 * @rinfo: other information regarding the rule/node e.g. priority and action info
 *
 * Helper function to search for a given advance rule entry
 * Returns pointer to entry storing the rule if found
 */
struct nse_adv_lpm_mgmt_list_entry *
nse_lpm_find_adv_rule_entry(struct nse_hw *hw, struct nse_adv_lkup_elem *lkups,
			u16 lkups_cnt, u16 lut_id,
			struct nse_adv_node_info *rinfo)
{
	struct nse_adv_lpm_mgmt_list_entry *list_itr;
	struct nse_switch_info *sw = hw->switch_info;
	int i;

	list_for_each_entry(list_itr, &sw->lut_list[lut_id].filt_rules,
			    list_entry) {
		bool lkups_matched = true;

		if (lkups_cnt != list_itr->lkups_cnt)
			continue;

		for (i = 0; i < list_itr->lkups_cnt; i++) {
			if (memcmp(&list_itr->lkups[i], &lkups[i],
				   sizeof(*lkups))) {
				lkups_matched = false;
				break;
			}
		}

		if (rinfo->tun_type == list_itr->node_info.tun_type &&
		    rinfo->prefix_len == list_itr->node_info.prefix_len &&
		    lkups_matched)
			return list_itr;
	}
	return NULL;
}

/**
 * nse_lpm_create_first_fit_lut_def - Create a lpm lut/recipe grouping
 * @hw: pointer to the hardware structure
 * @lkup_exts: an array of protocol header extractions
 * @rg_list: pointer to a list that stores new recipe groups
 * @recp_cnt: pointer to a variable that stores returned number of recipe groups
 *
 * Using exact match algorithm, take all the words that are still not done,
 * and start grouping them in 4-word groups.
 * Each group makes up one recipe template(lut)
 */
static int
nse_lpm_create_first_fit_lut_def(struct nse_hw *hw,
			      struct nse_prot_lkup_ext *lkup_exts,
			      struct list_head *lut_group_list,
			      u8 *lut_cnt)
{
	struct nse_pref_lut_group *grp = NULL;
	u16 lkup_words; /*max user lkup words in each lpm lut*/
	u8 j;

	*lut_cnt = 0;

	lkup_words = nse_lpm_mapping[0].lkup_words;

	/* Iterate every word in the lkups to check whether it is not done.
	 *  If yes then this word needs to be part of a new recipe.
	 */
	for (j = 0; j < lkup_exts->n_val_words; j++)
		if (!test_bit(j, lkup_exts->done)) {
			if (!grp ||
			    grp->n_val_pairs == lkup_words) {
				struct nse_lut_grp_entry *entry;

				entry = devm_kzalloc(nse_hw_to_dev(hw),
						     sizeof(*entry),
						     GFP_KERNEL);
				if (!entry)
					return -ENOMEM;

				list_add_tail(&entry->l_entry, lut_group_list);
				grp = &entry->lut_group;
				grp->n_val_pairs = 0;

				lkup_words = nse_lpm_mapping[*lut_cnt].lkup_words;

				(*lut_cnt)++;
			}

			grp->pairs[grp->n_val_pairs].prot_id =
				lkup_exts->fv_words[j].prot_id;
			grp->pairs[grp->n_val_pairs].off =
				lkup_exts->fv_words[j].off;
			grp->mask[grp->n_val_pairs] = lkup_exts->field_mask[j];
			grp->n_val_pairs++;
		}

	return 0;
}

/**
 * nse_create_lpm_lut_group - creates lpm lut/recipe group
 * @hw: pointer to hardware structure
 * @rm: recipe management list entry
 * @lkup_exts: lookup elements
 */
static int
nse_create_lpm_lut_group(struct nse_hw *hw, struct nse_lut_info *lut_info,
			struct nse_prot_lkup_ext *lkup_exts)
{
	u8 lut_count = 0;
	int status;

	lut_info->n_grp_count = 0;

	status = nse_lpm_create_first_fit_lut_def(hw, lkup_exts,
					       &lut_info->lut_group_list, &lut_count);
	if (!status) {
		lut_info->n_grp_count += lut_count;
		lut_info->n_ext_words = lkup_exts->n_val_words;
		memcpy(lut_info->ext_words, lkup_exts->fv_words,
			   sizeof(lut_info->ext_words));
		memcpy(lut_info->word_masks, lkup_exts->field_mask,
		       sizeof(lut_info->word_masks));
	}

	return status;
}

/**
 * nse_add_lpm_lut_internal - function to call AQ to alloc lpm switch lut,
 *				   and, bind current lut to profile's recipe.
 *				meanwhile, update profile's used_recipe_num.
 * @hw: pointer to hardware structure
 * @lut_info: recipe management list entry
 */
static int
nse_add_lpm_lut_internal(struct nse_hw *hw, struct nse_lut_info *lut_info)
{
	DECLARE_BITMAP(profiles_bm, NSE_MAX_NUM_PROFILES);
	DECLARE_BITMAP(result_idx_bm, NSE_MAX_FV_WORDS);
	struct nse_sw_fv_list_entry *fv_entry;
	struct nse_aqc_recipe_cfg *buf = NULL;
	struct nse_aqc_recipe_data_elem *rcp_elems;
	struct nse_lut_grp_entry *lut_entry;
	struct nse_switch_info *sw = hw->switch_info;
	struct nse_aqc_profile_cfg *prfl_buf;
	u16 prfl_buf_size;
	u16 free_idx_count;
	u16 buf_size;
	int status = 0;
	u8 recps = 0;
	u8 result_idx;
	u8 lut_index = 0;

	/*Get bitmap of all profiles that current new lut is associated with*/
	bitmap_zero(profiles_bm, NSE_MAX_NUM_PROFILES);

	list_for_each_entry(fv_entry, &lut_info->fv_list, list_entry) {
		set_bit(fv_entry->profile_id, profiles_bm);
	}

	/* Find the bitmap of free result index that can be used by
	 *  intermediate lut. all associated profile need be checked.
	 */
	bitmap_zero(result_idx_bm, NSE_MAX_FV_WORDS);
	free_idx_count = nse_find_free_recp_res_idx(hw, profiles_bm,
						result_idx_bm);
	dev_info(nse_hw_to_dev(hw), "Free result idx count: %d, need %d\n",
		free_idx_count,	(lut_info->n_grp_count == 1) ? 0 : lut_info->n_grp_count - 1);
	nse_debug(hw, NSE_DBG_SW, "Free result idx count: %d, need %d\n",
		  free_idx_count, (lut_info->n_grp_count == 1) ? 0 : lut_info->n_grp_count - 1);

	if (lut_info->n_grp_count > NSE_MAX_CHAIN_RECIPE)
		return -ENOSPC;

	buf_size = struct_size(buf, elem, lut_info->n_grp_count);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	rcp_elems = buf->elem;

	/* Step1.1: Start to build aqc buf per recipe*/
	result_idx = (u8)find_first_bit(result_idx_bm, NSE_MAX_FV_WORDS);
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		enum nse_status rt;
		u8 i;
		u16 lkup_words;
		bool is_first;

		is_first = nse_lpm_mapping[recps].is_first;
		lkup_words = nse_lpm_mapping[recps].lkup_words;

		/* 1) alloc a new lpm lut id */
		rt = nse_aq_alloc_free_lpm_lut_id(hw, &lut_entry->lut_id,
				NSE_AQ_OPC_ALLOC_RESOURCE);
		if (rt) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to alloc lpm lut id, err = %d\n",
				__func__, __LINE__, rt);
			status = -EIO;
			goto err_unroll;
		}

		/* 2) build recipe aqc info, except root flag & priority*/
		rcp_elems[recps].content.lut_id = cpu_to_le16(lut_entry->lut_id);
		rcp_elems[recps].content.ctrl_flg |= NSE_AQ_RECIPE_LPM_EN;

		if (!is_first && recps > 0) {
			rcp_elems[recps].content.lkup_indx[4] =
				(rcp_elems[recps - 1].content.result_indx >>
				 NSE_AQ_RECIPE_RSLT_INDX_S) &
				NSE_AQ_RECIPE_RSLT_INDX_G_M;
			rcp_elems[recps].content.mask[4] = cpu_to_le16(0xFFFF);
		}

		for (i = 0; i < lut_entry->lut_group.n_val_pairs; i++) {
			rcp_elems[recps].content.lkup_indx[lkup_words - i] =
				(u8)lut_entry->fv_idx[i];
			rcp_elems[recps].content.mask[lkup_words - i] =
				cpu_to_le16(lut_entry->fv_mask[i]);
		}

		/* handle result_index in buf, if current is chained recipe*/
		lut_entry->result_idx = NSE_INVALID_RSLT_IDX;
		if (lut_info->n_grp_count > 1 &&
			(recps + 1) != lut_info->n_grp_count) {
			/* check prefetched result index whether valid or not */
			if (result_idx >= NSE_MAX_FV_WORDS) {
				nse_debug(hw, NSE_DBG_SW, "No result index available\n");
				dev_err(nse_hw_to_dev(hw),
					"[%s, %d] No result index available\n",
					__func__, __LINE__);
				status = -ENOSPC;
				goto err_unroll;
			}
			lut_entry->result_idx = result_idx;
			rcp_elems[recps].content.result_indx |=
				(result_idx << NSE_AQ_RECIPE_RSLT_INDX_S) &
					NSE_AQ_RECIPE_RSLT_INDX_M;
			rcp_elems[recps].content.ctrl_flg |= NSE_AQ_RECIPE_RESULT_EN |
						NSE_AQ_RECIPE_ALTER_RESULT_EN;
			rcp_elems[recps].content.ignore_vld |= NSE_AQ_RECIPE_RESULT_SEL;
			/* prefetch result idx for next recipe */
			clear_bit(result_idx, result_idx_bm);
			result_idx = (u8)find_first_bit(result_idx_bm,
							NSE_MAX_FV_WORDS);
		}

		/*3) go to next recipe */
		recps++;
	}

	/*recps should be equal lut_info->n_grp_count, and not 0*/
	if (lut_info->n_grp_count != recps || (recps == 0)) {
		nse_debug(hw, NSE_DBG_SW,
			"Expected recps is not equal real recps\n");
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Expected recps is not equal real recps, n_grp_count = %d, recps = %d\n",
			__func__, __LINE__, lut_info->n_grp_count, recps);
		status = -EIO;
		goto err_unroll;
	}

	/* Step1.2: Start to handle root recipe*/
	rcp_elems[recps - 1].content.ctrl_flg |= NSE_AQ_RECIPE_IS_ROOT;
	lut_info->root_lut_id = le16_to_cpu(rcp_elems[recps - 1].content.lut_id);

	/*Step2: add recipe per profile.
	 * except recipe's priority, common recipe aqc buf is built
	 */
	prfl_buf_size = struct_size(prfl_buf, elems, 1);
	prfl_buf = devm_kzalloc(nse_hw_to_dev(hw), prfl_buf_size,
				GFP_KERNEL);
	if (!prfl_buf) {
		status = -ENOMEM;
		goto err_mem;
	}

	buf->count = cpu_to_le16(recps);
	list_for_each_entry(fv_entry, &lut_info->fv_list, list_entry) {
		struct nse_profile_info *profile;
		enum nse_status rt;
		u8 start_rcp_id;
		u8 i;

		profile = &sw->profile_list[fv_entry->profile_id];
		start_rcp_id = profile->used_recipe_num;
		if (profile->total_recipe_num < (profile->used_recipe_num + recps)) {
			dev_err(nse_hw_to_dev(hw),
				"Failed to add %d recipes in profile[%d], total = %d, used = %d\n",
				recps, profile->profile_id, profile->total_recipe_num,
				profile->used_recipe_num);
			status = -EIO;
			goto err_prfl_fail;
		}
		dev_info(nse_hw_to_dev(hw), "Start to add %d recps to Profile[%d]\n",
			 recps, profile->profile_id);
		for (i = 0; i < recps; i++) {
			buf->elem[i].profile_id = cpu_to_le16(profile->profile_id);
			buf->elem[i].recipe_id = start_rcp_id + i;
			/* it's hw internal priority, which is set to recipe id.
			 * 1 has higher priority than 2
			 */
			buf->elem[i].content.priority = buf->elem[i].recipe_id;
			dev_info(nse_hw_to_dev(hw), "\t Profile[%d] start to add recipe[%d]: lut id = %d, priority = %d\n",
				profile->profile_id, buf->elem[i].recipe_id,
				le16_to_cpu(buf->elem[i].content.lut_id),
					buf->elem[i].content.priority);

			dev_info(nse_hw_to_dev(hw), "\t\t mask[0~4] = [0x%x, 0x%x, 0x%x, 0x%x, 0x%x]\n",
				le16_to_cpu(buf->elem[i].content.mask[0]),
				le16_to_cpu(buf->elem[i].content.mask[1]),
				le16_to_cpu(buf->elem[i].content.mask[2]),
				le16_to_cpu(buf->elem[i].content.mask[3]),
				le16_to_cpu(buf->elem[i].content.mask[4]));

			dev_info(nse_hw_to_dev(hw), "\t\t lkup_Index[0~4] = [0x%x, 0x%x, 0x%x, 0x%x, 0x%x]\n",
				(buf->elem[i].content.lkup_indx[0]),
				(buf->elem[i].content.lkup_indx[1]),
				(buf->elem[i].content.lkup_indx[2]),
				(buf->elem[i].content.lkup_indx[3]),
				(buf->elem[i].content.lkup_indx[4]));

			dev_info(nse_hw_to_dev(hw), "\t\t ctrl_flag = 0x%x, ignore_vld = 0x%x, rslt_idx = 0x%x\n",
				(buf->elem[i].content.ctrl_flg),
				(buf->elem[i].content.ignore_vld),
				(buf->elem[i].content.result_indx >> NSE_AQ_RECIPE_RSLT_INDX_S));
		}

		/*add recipes to HW*/
		rt = nse_aq_add_recipe(hw, buf, buf_size);
		if (rt) {
			dev_err(nse_hw_to_dev(hw), "Failed to adminq add recipe, err = %d\n", rt);
			status = -EIO;
			goto err_prfl_fail;
		}
		for (i = 0; i < recps; i++)
			dev_info(nse_hw_to_dev(hw), "\t Profile[%d] finish to add recipe[%d]: lut id = %d\n",
				profile->profile_id, buf->elem[i].recipe_id,
				le16_to_cpu(buf->elem[i].content.lut_id));
	}

	/*Step3: Updata Software Lut List and Software Profile List */
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		struct nse_lut_info *lut;
		bool is_root, idx_found = false;
		u16 idx, buf_idx = 0;

		/*Step3.1 Start to updata Software Lut List*/

		/* find buffer index for copying some data */
		for (idx = 0; idx < lut_info->n_grp_count; idx++) {
			if (rcp_elems[idx].content.lut_id == cpu_to_le16(lut_entry->lut_id)) {
				buf_idx = idx;
				idx_found = true;
			}
		}

		if (!idx_found) {
			dev_err(nse_hw_to_dev(hw), "Failed to find correct Lut in recp adminq buf\n");
			status = -EIO;
			goto err_prfl_fail;
		}

		lut = &sw->lut_list[lut_entry->lut_id];
		is_root = (lut_info->root_lut_id == lut_entry->lut_id);
		lut->is_root = is_root;
		lut->lut_id = lut_entry->lut_id;
		lut->big_lut = (is_root && lut_info->n_grp_count > 1);
		memcpy(&lut->ext_words, lut_entry->lut_group.pairs,
		    lut_entry->lut_group.n_val_pairs * sizeof(struct nse_fv_word));

		/* set used rslt idx bitmap of global software lut DB */
		nse_collect_result_idx(&buf->elem[buf_idx], lut);

		/* for non-root recipes, also copy to the root, this
		 * allows easier matching of a complete chained recipe
		 */
		if (!is_root)
			nse_collect_result_idx(&buf->elem[buf_idx],
					       &sw->lut_list[lut_info->root_lut_id]);

		lut->n_ext_words = lut_entry->lut_group.n_val_pairs;
		lut->result_index = lut_entry->result_idx;
		lut->hw_prio = buf->elem[buf_idx].content.priority;
		lut->priority = lut_info->priority;
		lut->n_grp_count = lut_info->n_grp_count;
		lut->tun_type = lut_info->tun_type;
		lut->lut_created = true;
		lut->chain_id = lut_info->chain_id;

		/* Step3.2: update lut_bitmap per Software Profile */
		list_for_each_entry(fv_entry, &lut_info->fv_list, list_entry) {
			struct nse_profile_info *profile;
			u8 rcp_id;

			profile = &sw->profile_list[fv_entry->profile_id];
			set_bit(lut_entry->lut_id, profile->lut_bitmap);
			rcp_id = profile->used_recipe_num + lut_index;
			profile->lut_id[rcp_id] = lut_entry->lut_id;
			dev_info(nse_hw_to_dev(hw), "Lut_id of Profile[%d]_Recipe[%d] = %d\n",
					profile->profile_id, rcp_id, profile->lut_id[rcp_id]);
		}
		lut_index++;
	}

	/* Step3.3: update used_recipe_num per Software Profile */
	list_for_each_entry(fv_entry, &lut_info->fv_list, list_entry) {
		struct nse_profile_info *profile;

		profile = &sw->profile_list[fv_entry->profile_id];
		profile->used_recipe_num += recps;
	}

err_prfl_fail:
	devm_kfree(nse_hw_to_dev(hw), prfl_buf);
err_unroll:
err_mem:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_lpm_add_adv_lut - Add an advanced lpm lut that is not part of the default
 *				 the associated recipes of this lut can match lkups keys.
 * @hw: pointer to hardware structure
 * @lkups: lookup elements or match criteria for the advanced recipe,
 *			one structure per protocol header (protocol id)
 * @lkups_cnt: number of protocol headers
 * @rinfo: other information regarding the rule/node e.g. priority and action info
 * @lut_id: return the lut ID of the recipe created
 */
int
nse_lpm_add_adv_lut(struct nse_hw *hw, struct nse_adv_lkup_elem *lkups,
		   u16 lkups_cnt, struct nse_adv_node_info *rinfo, u16 *lut_id)
{
	DECLARE_BITMAP(fv_bitmap, NSE_MAX_NUM_PROFILES);
	/*lkup_exts: total match lkup extract from user,
	 *			not including rsult_index
	 */
	struct nse_prot_lkup_ext *lkup_exts = NULL;
	struct nse_lut_grp_entry *lut_entry;
	struct nse_sw_fv_list_entry *fv_entry;
	struct nse_lut_grp_entry *lut_tmp;
	struct nse_sw_fv_list_entry *fv_tmp;
	struct nse_lut_info *lut_info;
	int status = 0;
	u8 i;

	if (!lkups_cnt)
		return -EINVAL;

	lkup_exts = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*lkup_exts),
				 GFP_KERNEL);
	if (!lkup_exts)
		return -ENOMEM;

	/* Determine the number of words to be matched.
	 *  and check whether it exceeds chained_recipe's restriction or not
	 */
	for (i = 0; i < lkups_cnt; i++) {
		u16 count;

		if (lkups[i].type >= NSE_PROTOCOL_LAST) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Unsupported match filed\n",
				__func__, __LINE__);
			status = -EIO;
			goto err_free_lkup_exts;
		}
		/*transform lkups from Protocol ID header to FV word format*/
		count = nse_fill_valid_words(&lkups[i], lkup_exts);
		if (!count) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to change Protocol header to FV word\n",
				__func__, __LINE__);
			status = -EIO;
			goto err_free_lkup_exts;
		}
	}

	lut_info = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*lut_info),
				GFP_KERNEL);
	if (!lut_info) {
		status = -ENOMEM;
		goto err_free_lkup_exts;
	}

	lut_info->is_lpm = true;
	INIT_LIST_HEAD(&lut_info->fv_list);
	INIT_LIST_HEAD(&lut_info->lut_group_list);

	/* Get the profiles which can match current lkups, total 2 steps:
	 *        step1: Get profile type according to tunnel type of current lkups
	 *	    step2: Get exact profile IDs among profile type of step1
	 */
	nse_get_compat_fv_bitmap(hw, rinfo, fv_bitmap);
	status = nse_get_fv(hw, lkup_exts, fv_bitmap, &lut_info->fv_list);
	if (status) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] Failed to get fv\n",
			__func__, __LINE__);
		goto err_unroll;
	}

	/* Calculate how many luts are needed to match current lkups */
	status = nse_create_lpm_lut_group(hw, lut_info, lkup_exts);
	if (status) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] Failed to creat lut group, err = %d\n",
			__func__, __LINE__, status);
		goto err_unroll;
	}

	/* set the recipe priority if specified */
	lut_info->priority = (u8)rinfo->priority;

	/* fill nse_lut_grp_entry's fv_idx of lut group */
	status = nse_fill_fv_word_index(hw, &lut_info->fv_list,
				&lut_info->lut_group_list);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to fill_fv_word_index, err = %d\n",
			__func__, __LINE__, status);
		goto err_unroll;
	}

	/* Look for a lut which can matches our requested lkups */
	*lut_id = nse_find_lut(hw, lkup_exts, rinfo, true);
	if (*lut_id < NSE_MAX_NUM_LUTS) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] Lpm LUT is existed, lut id = %d\n",
			__func__, __LINE__, *lut_id);
		goto err_unroll;
	}

	lut_info->tun_type = rinfo->tun_type;

	lut_info->chain_id = rinfo->chain_id;

	/* Find lut failed, new single or chained lut need be added*/
	status = nse_add_lpm_lut_internal(hw, lut_info);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to add_lut_internal, err = %d\n",
			__func__, __LINE__, status);
		goto err_unroll;
	}

	*lut_id = lut_info->root_lut_id;

	hw->switch_info->lut_list[*lut_id].is_lpm = true;

	/* root lut's lkup_exts is copied from current lkups,
	 *   and intermediate lut is not.
	 */
	memcpy(&hw->switch_info->lut_list[*lut_id].lkup_exts, lkup_exts,
	       sizeof(*lkup_exts));

	/* Store fv_list/lut_group_list to golbal LUT DB,
	 * and fv_list/lut_group_list of local lut_info will be NULL,
	 * so we can fall to next code
	 */
	list_replace_init(&lut_info->fv_list,
		&hw->switch_info->lut_list[*lut_id].fv_list);

	list_replace_init(&lut_info->lut_group_list,
		&hw->switch_info->lut_list[*lut_id].lut_group_list);

err_unroll:
	list_for_each_entry_safe(lut_entry, lut_tmp,
		&lut_info->lut_group_list, l_entry) {
		list_del(&lut_entry->l_entry);
		devm_kfree(nse_hw_to_dev(hw), lut_entry);
	}

	list_for_each_entry_safe(fv_entry, fv_tmp,
		&lut_info->fv_list, list_entry) {
		list_del(&fv_entry->list_entry);
		devm_kfree(nse_hw_to_dev(hw), fv_entry);
	}

	/* lut_info is temporary,  lkup_exts/fv_list/lut_group_list
	 *  are copied to global switch_info->lut_list
	 */
	devm_kfree(nse_hw_to_dev(hw), lut_info);

err_free_lkup_exts:
	devm_kfree(nse_hw_to_dev(hw), lkup_exts);

	return status;
}

/**
 * nse_lpm_add_adv_node - create an lpm advanced node to HW lut
 * @hw: pointer to the hardware structure
 * @lkups: information on the words that needs to be looked up.
 *		   All words together makes one recipe or chained recipes
 *		   lkups based on HW protocol ID format
 * @lkups_cnt: num of entries in the lkups array
 * @rinfo: other information regarding the rule/node e.g. priority and action info
 * @added_entry: this will return lut_id, node_id and vsi_handle.
 *				should be ignored is case of error.
 *
 */
static int
nse_lpm_add_adv_node(struct nse_hw *hw, struct nse_adv_lkup_elem *lkups,
		 u16 lkups_cnt, struct nse_adv_node_info *rinfo,
		 struct nse_node_query_data *added_entry)
{
	struct nse_adv_lpm_mgmt_list_entry *m_entry, *adv_fltr = NULL;
	struct nse_switch_info *sw;
	struct nse_aqc_lut_nodes *buf = NULL;
	struct nse_aqc_lut_node_elem *lut_node;
	struct list_head *rule_head;
	struct nse_lut_grp_entry *lut_entry;
	struct nse_lut_info *lut_info;
	struct mutex *rule_lock;
	u16 lut_id = 0, i;
	u16 word_cnt, buf_size;
	u16 act = 0;
	u16 lg_act = 0;
	int status;
	u16 node_id, sub_node_id[NSE_MAX_SUB_NODE_NUM] = { 0 };

	/* Initialize profiles' result index bitmap */
	if (!hw->switch_info->prof_res_bm_init) {
		hw->switch_info->prof_res_bm_init = 1;
		nse_init_prof_result_bm(hw);
	}

	if (!lkups_cnt) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] it's error due to lkups_cnt is 0\n",
			__func__, __LINE__);
		return -EINVAL;
	}

	/* get num of FV words we need to match */
	word_cnt = 0;
	for (i = 0; i < lkups_cnt; i++) {
		u16 j, *ptr;

		ptr = (u16 *)&lkups[i].m_u;
		for (j = 0; j < sizeof(lkups->m_u) / sizeof(u16); j++)
			if (ptr[j] != 0)
				word_cnt++;
	}

	if (!word_cnt) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] it's error due to match word is 0\n",
			__func__, __LINE__);
		return -EINVAL;
	}

	if (word_cnt > NSE_MAX_LPM_LKUP_WORDS) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] match words(%d) up to max num\n",
			__func__, __LINE__, word_cnt);
		return -ENOSPC;
	}

	if (!(rinfo->sw_act.fltr_act == NSE_LARGE_ACT ||
		  rinfo->sw_act.fltr_act == NSE_FAST_ACT ||
	      rinfo->sw_act.fltr_act == NSE_FWD_TO_LAN ||
		  rinfo->sw_act.fltr_act == NSE_FWD_TO_VSI ||
		  rinfo->sw_act.fltr_act == NSE_FWD_TO_VSI_LIST ||
	      rinfo->sw_act.fltr_act == NSE_DROP_PACKET)) {
		dev_err(nse_hw_to_dev(hw), "Unsupported action type in lpm\n");
		return -EIO;
	}

	/* returned lut_id is root lut id */
	status = nse_lpm_add_adv_lut(hw, lkups, lkups_cnt, rinfo, &lut_id);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to add lpm advanced LUT\n",
			__func__, __LINE__);
		return status;
	}

	sw = hw->switch_info;
	lut_info = &sw->lut_list[lut_id];
	rule_lock = &lut_info->filt_rule_lock;

	mutex_lock(rule_lock);

	m_entry = nse_lpm_find_adv_rule_entry(hw, lkups, lkups_cnt, lut_id, rinfo);
	if (m_entry) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] lpm advanced node is existed\n",
			__func__, __LINE__);
		status = -EEXIST;
		goto err_nse_add_adv_node;
	}

	/* not find existed rule, start to add new rule/node.
	 * total 3 Steps.
	 */
	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf) {
		status = -ENOMEM;
		goto err_nse_add_adv_node;
	}

	buf->count = cpu_to_le16(1);
	lut_node = buf->elem;

	/* Step1: Build action info for root Lut node*/
	status = nse_build_adv_action_field(rinfo, &act, &lg_act);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to build action field info\n",
			__func__, __LINE__);
		goto err_nse_add_adv_node;
	}

	/* Step2: Based on returned root lut_id,
	 *		iterate lut group in lut_group_list of lut list info.
	 *		add node one by one per lut group.
	 */
	i = 0;
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		enum nse_status rt_status;
		bool is_last = false;
		bool is_first = false;
		u16 j, lkup_words, prefix_cur = 0;
		u16 min_prefix, max_prefix;

		buf->count = cpu_to_le16(1);
		memset(lut_node, 0, sizeof(*lut_node));

		is_first = nse_lpm_mapping[i].is_first;
		lkup_words = nse_lpm_mapping[i].lkup_words;
		max_prefix = nse_lpm_mapping[i].lkup_max_prfx;
		min_prefix = nse_lpm_mapping[i].lkup_min_prfx;

		if (rinfo->prefix_len <= max_prefix)
			is_last = true;

		/*2.1 build key*/
		if (!is_first) {
			lut_node->key[4] = cpu_to_le16(sub_node_id[i - 1]);
			prefix_cur += 16;
		}

		for (j = 0; j < lut_entry->lut_group.n_val_pairs; j++) {
			status = nse_fill_lkup_key_word(hw, lkups, lkups_cnt,
				&lut_entry->lut_group.pairs[j],
				&lut_node->key[lkup_words - j]);
			if (status) {
				dev_err(nse_hw_to_dev(hw),
					"[%s, %d] Failed to fill lkup key word\n",
					__func__, __LINE__);
				goto err_nse_add_adv_node;
			}
		}

		if (is_last)
			prefix_cur += rinfo->prefix_len - min_prefix;
		else
			prefix_cur = NSE_ALL_MATCH_PREFIX_LEN;

		lut_node->key[0] = cpu_to_le16(prefix_cur & NSE_LPM_PREFIX_M);

		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] current lut[%d]'s prefix len = %d, min_prefix = %d, max_prefix = %d, lkup_words = %d\n",
			__func__, __LINE__, i, prefix_cur, min_prefix, max_prefix, lkup_words);

		/*2.2 build action, only root is needed*/
		if (is_last) {
			lut_node->action = cpu_to_le16(act);
			lut_node->left_ptr = cpu_to_le16(lg_act);
		}

		/*2.3 request "add lut node" adminq cmd per lut group*/
		lut_node->lut_id = cpu_to_le16(lut_entry->lut_id);

		dev_info(nse_hw_to_dev(hw), "Start add lpm advanced node to lut[%d], is_last = %d, is_first = %d\n",
			lut_entry->lut_id, !!is_last, !!is_first);
		dev_info(nse_hw_to_dev(hw), "\t is_lg_act = %d, action/lg_id = 0x%x\n",
			!!(le16_to_cpu(lut_node->left_ptr) & NSE_LUT_NODE_LARGE_ACTION_EN),
			le16_to_cpu(lut_node->action));
		dev_info(nse_hw_to_dev(hw), "\t key_value[0~4]: [0x%x, 0x%x, 0x%x, 0x%x, 0x%x,]\n",
			le16_to_cpu(lut_node->key[0]), le16_to_cpu(lut_node->key[1]),
			le16_to_cpu(lut_node->key[2]), le16_to_cpu(lut_node->key[3]),
			le16_to_cpu(lut_node->key[4]));
		rt_status = nse_aq_lut_nodes(hw, buf, buf_size,
					 NSE_AQ_OPC_ADD_LUT_NODE, NULL);
		if (rt_status) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to add nse_aq_lut_nodes\n",
				__func__, __LINE__);
			status = -EIO;
			goto err_nse_add_adv_node;
		}
		dev_info(nse_hw_to_dev(hw), "\t return lpm node_id = 0x%x\n",
			le16_to_cpu(lut_node->node_id));
		sub_node_id[i] = le16_to_cpu(lut_node->node_id);
		i++;

		if (is_last) {
			node_id = le16_to_cpu(lut_node->node_id);
			break;
		}
	}

	/* Step3: add adv entry to software filter DB */
	adv_fltr = devm_kzalloc(nse_hw_to_dev(hw),
				sizeof(struct nse_adv_lpm_mgmt_list_entry),
				GFP_KERNEL);
	if (!adv_fltr) {
		status = -ENOMEM;
		goto err_nse_add_adv_node;
	}

	if (lkups_cnt) {
		adv_fltr->lkups = devm_kmemdup(nse_hw_to_dev(hw), lkups,
					       lkups_cnt * sizeof(*lkups),
					       GFP_KERNEL);
	} else {
		adv_fltr->lkups = NULL;
	}

	if (!adv_fltr->lkups) {
		status = -ENOMEM;
		goto err_nse_add_adv_node;
	}

	adv_fltr->lkups_cnt = lkups_cnt;
	adv_fltr->node_info = *rinfo;

	/* root node id & chained sub lut node id, used for removing */
	adv_fltr->node_info.fltr_node_id = node_id;
	memcpy(adv_fltr->node_info.sub_fltr_node_id, sub_node_id,
		sizeof(sub_node_id));

	/* Add rule entry to software DB list */
	sw = hw->switch_info;
	sw->lut_list[lut_id].adv_rule = true;
	rule_head = &sw->lut_list[lut_id].filt_rules;
	list_add_tail(&adv_fltr->list_entry, rule_head);

	if (added_entry) {
		/* [Note that]
		 * HW's view: maybe node id is not really in root lut id,
		 * we should get it's real lut id via prefix len when add/remove.
		 * SW's view: all lpm nodes stored in root lut 's filt_rules list head.
		 */
		added_entry->lut_id = lut_id;
		added_entry->node_id = adv_fltr->node_info.fltr_node_id;
	}

err_nse_add_adv_node:

	mutex_unlock(rule_lock);

	if (status && adv_fltr) {
		if (adv_fltr->lkups)
			devm_kfree(nse_hw_to_dev(hw), adv_fltr->lkups);
		devm_kfree(nse_hw_to_dev(hw), adv_fltr);
	}

	if (buf)
		devm_kfree(nse_hw_to_dev(hw), buf);

	return status;
}

/**
 * nse_lpm_fill_node_state_fwd - fill forward info into node state
 *	including drop/toLan/toVSI/toVsiList.
 *	one of them will be selected.
 *
 * @node_state: node state obj, which need initial.
 */
static int
nse_lpm_fill_node_state_fwd(struct nse_hw *hw,
		struct nse_lpm_fltr *fltr,
		struct nse_node_state *node_state, u16 *du_act_cnt)
{
	struct nse_du_action *du_action;
	struct nse_lpm_action *action = &fltr->action;
	struct nse_vsi *dest_vsi;

	if (!(action->flags &
		     (NSE_LPM_ACTION_DROP |
		      NSE_LPM_ACTION_TO_LAN |
		      NSE_LPM_ACTION_FWD_VSI))) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Fwd info is necessary when no dup action\n",
			__func__, __LINE__);
		return -EINVAL;
	}

	du_action = &node_state->du_action[*du_act_cnt];
	du_action->flags_info.act_valid = true;
	du_action->flags_info.act = 0;

	/*set dest vsi information*/
	switch (action->fltr_act) {
	case NSE_FWD_TO_VSI:
		dest_vsi = action->dest_vsi;
		du_action->fwd_id.hw_vsi_id =
				nse_get_hw_vsi_num(hw, dest_vsi->idx);
		du_action->du_act =	NSE_DU_ACT_FWD_TO_VSI;
		du_action->flags_info.act |= NSE_LB_ENABLE;
		(*du_act_cnt)++;
		break;
	case NSE_FWD_TO_LAN:
		du_action->du_act =	NSE_DU_ACT_FWD_TO_LAN;
		du_action->flags_info.act |= NSE_LAN_ENABLE;
		(*du_act_cnt)++;
		break;
	case NSE_DROP_PACKET:
		du_action->du_act =	NSE_DU_ACT_DROP_PACKET;
		(*du_act_cnt)++;
		break;
	default:
		break;
	}
	return 0;
}

/**
 * nse_fill_task_dec_ttl -
 *		fill task code and no task data.
 * @cur_task_list: task list object, fill task code to it.
 * @au_task_cnt: index of task in task list.
 */
static void
nse_fill_task_dec_ttl(struct nse_sw_task_list *cur_task_list,
		u16 *au_task_cnt)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_DEC_TTL;
	(*au_task_cnt)++;
}

/**
 * nse_fill_task_dec_hlimit -
 *		fill task code and no task data.
 * @cur_task_list: task list object, fill task code to it.
 * @au_task_cnt: index of task in task list.
 */
static void
nse_fill_task_dec_hlimit(struct nse_sw_task_list *cur_task_list,
		u16 *au_task_cnt)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_DEC_HLIMIT;
	(*au_task_cnt)++;
}

/**
 * nse_lpm_is_task_list_needed -
 * judge au task list is needed, according to current fltr actions
 *
 * @act_flags: current fltr actions flag
 */
static bool
nse_lpm_is_task_list_needed(u32 act_flags)
{
	return (act_flags & NSE_LPM_ACTION_DEC_TTL) ||
		(act_flags & NSE_LPM_ACTION_DEC_HLIMIT);
}

/**
 * nse_lpm_calc_au_task_cnt -
 * calculate task count according to actions information
 *
 * @tc_action: current fltr actions information
 */
static u16
nse_lpm_calc_au_task_cnt(struct nse_lpm_action *action)
{
	u16 task_cnt = 0;
	u32 act_flags = action->flags;

	if (act_flags & NSE_LPM_ACTION_DEC_TTL)
		task_cnt++;

	if (act_flags & NSE_LPM_ACTION_DEC_HLIMIT)
		task_cnt++;

	if (task_cnt > NSE_MAX_AU_TASK_NUM)
		return 0;

	return task_cnt;
}

/**
 * nse_lpm_calc_du_data_size -
 * calculate task data size according to actions information
 *
 * @action: current fltr actions information
 */
static u16
nse_lpm_calc_du_data_size(struct nse_lpm_action *action)
{
	u16 data_size = 0;

	return data_size;
}

/**
 * nse_lpm_add_large_action -
 *
 * @hw: pointer to the hardware structure
 * @fltr: lpm fltr information after previous parsing
 */
static int
nse_lpm_add_large_action(struct nse_hw *hw,
			struct nse_lpm_fltr *fltr)
{
	struct nse_node_state *node_state; /*local, alloc & free locally*/
	struct nse_sw_counter_pair *counter_p = NULL; /*global*/
	struct nse_sw_du_data *du_data = NULL; /*global*/
	struct nse_sw_task_list *task_list = NULL; /*global*/
	struct nse_sw_task_list *cur_task_list = NULL; /*local*/
	struct nse_lpm_action *action = &fltr->action;
	u32 act_flags = action->flags;
	u16 du_act_cnt = 0, au_task_cnt = 0, du_desc_cnt = 0;
	int ret = 0, dstry_ret = 0;

	node_state = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*node_state),
				 GFP_KERNEL);
	if (!node_state)
		return -ENOMEM;

	nse_init_node_state(node_state);

	/*1. build node_state du_action for HW DU*/
	if (act_flags & NSE_LPM_ACTION_COUNT) {
		counter_p = nse_sw_creat_counter_pair(hw, true);
		if (!counter_p) {
			ret = -ENOMEM;
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Unable to creat hw counter\n",
				__func__, __LINE__);
			goto add_large_action_fail;
		}

		node_state->du_action[du_act_cnt].hw_cnt_id =
			counter_p->p_counter.hw_id;
		node_state->du_action[du_act_cnt++].du_act =
			NSE_DU_ACT_COUNT_PACKET;

		node_state->du_action[du_act_cnt].hw_cnt_id =
			counter_p->b_counter.hw_id;
		node_state->du_action[du_act_cnt++].du_act =
			NSE_DU_ACT_COUNT_BYTE;

		action->counter_p = counter_p;
	}

	ret = nse_lpm_fill_node_state_fwd(hw, fltr, node_state, &du_act_cnt);
	if (ret) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] fail to fill fwd info in node state\n",
			__func__, __LINE__);
		goto add_large_action_fail;
	}

	/*2. build au_task_list & du_data/du_desc for HW AU*/
	if (nse_lpm_is_task_list_needed(act_flags)) {
		u16 d_size = 0, t_cnt = 0;
		u16 alloc_size;

		/*2.1 calculate task count and task data size.*/
		t_cnt = nse_lpm_calc_au_task_cnt(action);
		if (!t_cnt) {
			ret = -EIO;
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] fail to calculate task count\n",
				__func__, __LINE__);
			goto add_large_action_fail;
		}

		alloc_size = struct_size(cur_task_list, task, t_cnt);
		cur_task_list = devm_kzalloc(nse_hw_to_dev(hw), alloc_size,
					 GFP_KERNEL);
		if (!cur_task_list) {
			ret = -ENOMEM;
			goto add_large_action_fail;
		}
		cur_task_list->task_cnt = t_cnt;

		d_size = nse_lpm_calc_du_data_size(action);
		if (d_size) {
			du_data = nse_sw_creat_du_data(hw, d_size);
			if (!du_data) {
				ret = -ENOMEM;
				dev_err(nse_hw_to_dev(hw),
					"[%s, %d] Unable to creat du data\n",
					__func__, __LINE__);
				goto au_task_fail;
			}
			action->du_data = du_data;
			node_state->du_desc[du_desc_cnt].du_data_id =
								du_data->du_desc.du_data_id;
			node_state->du_desc[du_desc_cnt].data_size =
								du_data->du_desc.data_size;
			du_desc_cnt++;
		}

		/*2.2 build each task info to local variable cur_task_list,
		 * also build each task's data to du_data obj created above.
		 */
		if (act_flags & NSE_LPM_ACTION_DEC_TTL)
			nse_fill_task_dec_ttl(cur_task_list, &au_task_cnt);

		if (act_flags & NSE_LPM_ACTION_DEC_HLIMIT)
			nse_fill_task_dec_hlimit(cur_task_list, &au_task_cnt);

		/*2.3 add du data to FW after du data is built*/
		if (du_data) {
			ret = nse_sw_add_du_data(hw, du_data);
			if (ret) {
				ret = -EIO;
				dev_err(nse_hw_to_dev(hw),
					"[%s, %d] Fail to add du data\n",
					__func__, __LINE__);
				goto au_task_fail;
			}
		}

		/*2.4 get obj from task list table, based on cur_task_list.*/
		task_list = nse_sw_get_task_list(hw, cur_task_list);
		if (!task_list) {
			ret = -ENOMEM;
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Fail to get task list\n",
				__func__, __LINE__);
			goto au_task_fail;
		}
		action->task_list = task_list;
		node_state->task_list_id = task_list->task_list_id;
		devm_kfree(nse_hw_to_dev(hw), cur_task_list);
	}

	/*3. according to node_state info, add to hw */
	if (!du_act_cnt) {
		ret = -EIO;
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] no any single action in du_act\n",
			__func__, __LINE__);
		goto add_large_action_fail;
	}

	if (du_act_cnt == 1 && !au_task_cnt) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] It is single action! act type = %d\n",
			__func__, __LINE__, node_state->du_action[0].du_act);
		ret = 0;
		goto add_large_action_to_single;
	}

	node_state->is_lite = false;
	ret = nse_sw_add_node_state(hw, node_state, du_act_cnt,
			au_task_cnt, du_desc_cnt);

	if (ret || node_state->node_state_id == NSE_NODE_STATE_ID_INVALID) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Unable to add node state\n",
			__func__, __LINE__);
		goto add_large_action_fail;
	}

	/*4. copy node_state to software fltr DB */
	node_state->du_act_cnt = du_act_cnt;
	node_state->au_task_cnt = au_task_cnt;
	node_state->du_desc_cnt = du_desc_cnt;
	action->node_state = *node_state;
	action->large_act_id = node_state->node_state_id;
	devm_kfree(nse_hw_to_dev(hw), node_state);
	return 0;

au_task_fail:
	if (cur_task_list)
		devm_kfree(nse_hw_to_dev(hw), cur_task_list);

add_large_action_fail:
add_large_action_to_single:
	if (counter_p) {
		dstry_ret = nse_sw_destroy_counter_pair(hw, counter_p);
		action->counter_p = NULL;
		if (dstry_ret)
			dev_err(nse_hw_to_dev(hw), "fail to destroy hw counter\n");
	}
	if (task_list) {
		dstry_ret = nse_sw_put_task_list(hw, task_list);
		action->task_list = NULL;
		if (dstry_ret)
			dev_err(nse_hw_to_dev(hw), "fail to free task list\n");
	}

	if (du_data) {
		dstry_ret = nse_sw_destroy_du_data(hw, du_data);
		action->du_data = NULL;
		if (dstry_ret)
			dev_err(nse_hw_to_dev(hw), "fail to destroy hw du data\n");
	}
	devm_kfree(nse_hw_to_dev(hw), node_state);
	return ret;
}

/**
 * nse_erouter_add_lpm_fltr -
 *			add lpm fltr to HW.
 * @hw: pointer to the HW struct
 * @fltr: lpm fltr information after previous parsing
 */
int
nse_erouter_add_lpm_fltr(struct nse_hw *hw,
		struct nse_lpm_fltr *fltr)
{
	struct nse_ip_route_addr *ip_key = &fltr->ip_key;
	struct nse_adv_node_info node_info = { 0 };
	struct nse_node_query_data rule_added = { 0 };
	struct nse_adv_lkup_elem *lkups = NULL;
	int lkups_cnt;
	int i, ret;

	if (!nse_is_erouter_mode_en(hw)) {
		dev_err(nse_hw_to_dev(hw),
			"lpm fltr cannot be configured because lpm mode is disabled\n");
		return -EOPNOTSUPP;
	}

	/* 1. handle du_action in node state first */
	ret = nse_lpm_add_large_action(hw, fltr);
	if (ret) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Unable to add large action due to error\n",
			__func__, __LINE__);
		goto add_large_action_fail;
	}

	if (fltr->action.large_act_id != NSE_NODE_STATE_ID_INVALID) {
		node_info.sw_act.fltr_act = NSE_LARGE_ACT;
		node_info.sw_act.large_act_id = fltr->action.large_act_id;
		node_info.node_state = &fltr->action.node_state;
	} else {
		ret = nse_lpm_fill_node_info(hw, fltr, &node_info);
		if (ret) {
			dev_err(nse_hw_to_dev(hw), "[%s, %d] fail to fill node info\n",
				__func__, __LINE__);
			goto exit;
		}
	}
	node_info.sw_id = hw->port_info->sw_id;
	node_info.chain_id = fltr->chain_id;

	/* start to handle match(profile & recipe & Lut) and lut node */
	lkups_cnt = nse_lpm_count_lkups(ip_key);
	if (!lkups_cnt) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] lkups cnt is NULL after count it, ip family = %d\n",
			__func__, __LINE__, ip_key->family);
		return -EINVAL;
	}
	lkups = kcalloc(lkups_cnt, sizeof(*lkups), GFP_ATOMIC);
	if (!lkups)
		return -ENOMEM;

	/* transfer standand network header to HW protocolID format (lkups)
	 */
	i = nse_lpm_fill_rules(fltr, lkups, &node_info);
	if (i != lkups_cnt) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] Unable to lpm fill rules, i = %d, lkups_cnt = %d\n",
			__func__, __LINE__, i, lkups_cnt);
		ret = -EINVAL;
		goto exit;
	}

	dev_info(nse_hw_to_dev(hw), "[%s, %d] prot_header num = %d\n",
		__func__, __LINE__, lkups_cnt);

	for (i = 0; i < lkups_cnt; i++)
		dev_info(nse_hw_to_dev(hw), "[%s, %d] prot_header[%d]_type = %d\n",
			__func__, __LINE__, i, lkups[i].type);

	ret = nse_lpm_add_adv_node(hw, lkups, lkups_cnt, &node_info, &rule_added);
	if (ret == -EEXIST) {
		dev_err(nse_hw_to_dev(hw), "Unable to add lpm node because it already exist\n");
		ret = -EINVAL;
		goto exit;
	} else if (ret) {
		dev_err(nse_hw_to_dev(hw),
			"Unable to add lpm node due to error, err = %d\n", ret);
		goto exit;
	}

	/* store the output params, which are used for removing advanced filter later*/
	fltr->lut_id = rule_added.lut_id;
	fltr->node_id = rule_added.node_id;

exit:
	kfree(lkups);

add_large_action_fail:

	return ret;
}

/**
 * nse_rem_lpm_adv_node_by_id - removes existing advanced lpm node by ID
 * @hw: pointer to the hardware structure
 * @remove_entry: data struct which holds rule_id, VSI handle and recipe ID
 *
 */
int
nse_rem_lpm_adv_node(struct nse_hw *hw, struct nse_adv_lkup_elem *lkups,
		   u16 lkups_cnt, u16 lut_id, struct nse_adv_node_info *rinfo)
{
	struct nse_switch_info *sw = hw->switch_info;
	struct nse_aqc_lut_nodes *buf = NULL;
	struct nse_aqc_lut_node_elem *lut_node;
	struct nse_lut_info *lut_info = &sw->lut_list[lut_id];
	struct nse_lut_grp_entry *lut_entry;
	struct nse_adv_node_info *node_info;
	struct nse_adv_lpm_mgmt_list_entry *list_elem;
	struct mutex *rule_lock;
	enum nse_status status;
	u16 buf_size, i;
	int ret = 0;

	if (!lut_info || !lut_info->lut_created || !lut_info->is_lpm) {
		dev_err(nse_hw_to_dev(hw), "rem_lut[%d] is not created\n", lut_id);
		return -EINVAL;
	}

	rule_lock = &lut_info->filt_rule_lock;

	mutex_lock(rule_lock);
	list_elem = nse_lpm_find_adv_rule_entry(hw, lkups, lkups_cnt, lut_id, rinfo);
	if (!list_elem) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] lpm advanced node is not existed\n",
			__func__, __LINE__);
		ret = -ENOENT;
		goto err_nse_rem_adv_rule;
	}

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto err_nse_rem_adv_rule;
	}

	node_info = &list_elem->node_info;
	buf->count = cpu_to_le16(1);
	lut_node = buf->elem;
	i = 0;
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		bool is_last = false;
		u16  max_prefix;

		max_prefix = nse_lpm_mapping[i].lkup_max_prfx;

		if (node_info->prefix_len <= max_prefix)
			is_last = true;

		lut_node->lut_id = cpu_to_le16(lut_entry->lut_id);
		lut_node->node_id = cpu_to_le16(node_info->sub_fltr_node_id[i]);

		status = nse_aq_lut_nodes(hw, buf, buf_size,
					 NSE_AQ_OPC_REMOVE_LUT_NODE, NULL);
		if (status && status != NSE_ERR_DOES_NOT_EXIST) {
			dev_err(nse_hw_to_dev(hw), "Failed to remove lpm lut[%d] node_id[%d]\n",
				lut_entry->lut_id, node_info->sub_fltr_node_id[i]);
			ret = -EIO;
			goto err_nse_rem_adv_rule;
		}
		dev_info(nse_hw_to_dev(hw), "Success to remove lpm lut[%d] node_id[%d]\n",
			lut_entry->lut_id, node_info->sub_fltr_node_id[i]);
		i++;

		if (is_last)
			break;
	}

	/* release software adv entry memory */
	list_del(&list_elem->list_entry);
	devm_kfree(nse_hw_to_dev(hw), list_elem->lkups);
	devm_kfree(nse_hw_to_dev(hw), list_elem);
	if (list_empty(&sw->lut_list[lut_id].filt_rules))
		sw->lut_list[lut_id].adv_rule = false;

err_nse_rem_adv_rule:

	mutex_unlock(rule_lock);
	if (buf)
		devm_kfree(nse_hw_to_dev(hw), buf);

	return ret;
}

/**
 * nse_erouter_del_lpm_fltr -
 *			del lpm fltr from HW.
 * @hw: pointer to the HW struct
 * @fltr: lpm fltr information after previous parsing
 */
void
nse_erouter_del_lpm_fltr(struct nse_hw *hw,
		struct nse_lpm_fltr *fltr)
{
	struct nse_ip_route_addr *ip_key = &fltr->ip_key;
	struct nse_adv_node_info node_info = { 0 };
	struct nse_adv_lkup_elem *lkups = NULL;
	struct nse_lpm_action *action = &fltr->action;
	int lkups_cnt;
	int i, ret = 0, dstry_ret;

	if (!nse_is_erouter_mode_en(hw)) {
		dev_err(nse_hw_to_dev(hw),
			"lpm fltr cannot be deleted because lpm mode is disabled\n");
		return;
	}

	/* start to handle match(profile & recipe & Lut) and lut node */
	lkups_cnt = nse_lpm_count_lkups(ip_key);
	if (!lkups_cnt) {
		dev_err(nse_hw_to_dev(hw),
			"lkups cnt is NULL after count it, ip family = %d\n",
			ip_key->family);
		return;
	}

	lkups = kcalloc(lkups_cnt, sizeof(*lkups), GFP_ATOMIC);
	if (!lkups)
		return;

	/* transfer standand network header to HW protocolID format (lkups)
	 */
	i = nse_lpm_fill_rules(fltr, lkups, &node_info);
	if (i != lkups_cnt) {
		dev_err(nse_hw_to_dev(hw), "Unable to tc fill rules, i = %d, lkups_cnt = %d\n",
			i, lkups_cnt);
		ret = -EINVAL;
		goto exit;
	}

	ret = nse_rem_lpm_adv_node(hw, lkups, lkups_cnt, fltr->lut_id, &node_info);
	if (ret) {
		if (ret == -ENOENT)
			dev_info(nse_hw_to_dev(hw), "lpm filter does not exist, err = %d\n", ret);
		else
			dev_err(nse_hw_to_dev(hw), "Fail to delete lpm lut node, err = %d\n", ret);
	}

	if (action->large_act_id != NSE_NODE_STATE_ID_INVALID) {
		struct nse_node_state *node_state = &action->node_state;

		if (node_state->is_lite)
			ret = nse_sw_rem_lite_node_state(hw, &action->large_act_id);
		else
			ret = nse_sw_rem_node_state(hw, &action->large_act_id);

		action->large_act_id = NSE_NODE_STATE_ID_INVALID;
		if (ret) {
			dev_err(nse_hw_to_dev(hw),
				"Failed to remove lpm node state, err = %d\n", ret);
		}
	}

	if (action->counter_p) {
		dstry_ret = nse_sw_destroy_counter_pair(hw, action->counter_p);
		action->counter_p = NULL;
		if (dstry_ret)
			dev_err(nse_hw_to_dev(hw), "fail to destroy hw counter\n");
	}

	if (action->task_list) {
		dstry_ret = nse_sw_put_task_list(hw, action->task_list);
		action->task_list = NULL;
		if (dstry_ret)
			dev_err(nse_hw_to_dev(hw), "fail to free task list\n");
	}

	if (action->du_data) {
		dstry_ret = nse_sw_destroy_du_data(hw, action->du_data);
		action->du_data = NULL;
		if (dstry_ret)
			dev_err(nse_hw_to_dev(hw), "fail to destroy hw du data\n");
	}

exit:
	kfree(lkups);
}

/**
 * nse_is_erouter_mode_en -
 *			lpm mode is enable or not.
 * @hw: pointer to the HW struct
 */
bool
nse_is_erouter_mode_en(struct nse_hw *hw)
{
	struct nse_switch_info *sw = NULL;

	sw = hw->switch_info;
	if (!sw)
		return false;

	return sw->lpm_en;
}

/**
 * nse_enable_erouter_mode -
 *			enable switch to lpm mode.
 * @hw: pointer to the HW struct
 */
void
nse_enable_erouter_mode(struct nse_hw *hw)
{
	struct nse_switch_info *sw = NULL;
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	enum nse_sw_mode sw_mode;
	int ret;

	if (nse_bypass_switch) {
		dev_info(nse_hw_to_dev(hw),
			"Failed to enable lpm mode because nse_bypass_switch is 1\n");
		return;
	}

	if (nse_is_eswitch_mode_switchdev(pf)) {
		dev_warn(nse_hw_to_dev(hw),
			"Failed to enable lpm mode because switchdev is enabled\n");
		return;
	}

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY)) {
		dev_warn(nse_hw_to_dev(hw),
			"Failed to enable lpm mode because is hardware legacy switch\n");
		return;
	}

	sw = hw->switch_info;
	if (!sw)
		return;

	sw_mode = NSE_SW_MODE_LPM;

	ret = nse_sw_set_mode(hw, &sw_mode);
	if (ret) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] set hw to lpm mode err, err = %d, mode = %d\n",
			__func__, __LINE__, ret, sw_mode);
		return;
	}

	sw->lpm_en = true;

	dev_info(nse_hw_to_dev(hw),
		"Success to enable lpm mode: lpm_en = %d\n", sw->lpm_en);
}

/**
 * nse_cleanup_lpm_fltrs -
 *			delete all lpm flter.
 * @hw: pointer to the HW struct
 */
void
nse_cleanup_lpm_fltrs(struct nse_hw *hw)
{
	struct nse_lpm_fltr *fltr = NULL;
	struct hlist_node *node;

	hlist_for_each_entry_safe(fltr, node,
		&lpm_fltr_list, lpm_node) {
		hlist_del(&fltr->lpm_node);

		nse_erouter_del_lpm_fltr(hw, fltr);
	}

	g_nse_ipv4_rt_lut_id = -1;
	g_nse_ipv6_rt_lut_id = -1;
}

/**
 * nse_cleanup_lpm_fltrs -
 *			free all lpm lut id.
 * @hw: pointer to the HW struct
 */
void nse_del_all_adv_lpm_luts(struct nse_hw *hw)
{
	struct nse_lut_info *lut;
	enum nse_status status = NSE_SUCCESS;
	int i;

	lut = hw->switch_info->lut_list;

	for (i = NSE_MAX_NUM_LUTS; i > 0; i--) {
		if (!lut[i].lut_created || !lut[i].is_lpm)
			continue;

		dev_info(nse_hw_to_dev(hw),
			"start to free lut id[%d]'s nodes\n", lut[i].lut_id);

		status = nse_aq_alloc_free_lpm_lut_id(hw,
				&lut[i].lut_id, NSE_AQ_OPC_FREE_RESOURCE);
		if (status)
			dev_err(nse_hw_to_dev(hw),
				"Failed to free lut id[%d], err = %d\n",
				lut[i].lut_id, status);

		memset(&lut[i], 0, sizeof(struct nse_lut_info));
		lut[i].lut_id = i;
		INIT_LIST_HEAD(&lut[i].filt_rules);
		INIT_LIST_HEAD(&lut[i].filt_replay_rules);
		INIT_LIST_HEAD(&lut[i].fv_list);
		INIT_LIST_HEAD(&lut[i].lut_group_list);
		mutex_init(&lut[i].filt_rule_lock);
	}
}

/**
 * nse_disable_erouter_mode -
 *			disable switch lpm mode.
 * @hw: pointer to the HW struct
 */
void
nse_disable_erouter_mode(struct nse_hw *hw)
{
	struct nse_switch_info *sw = NULL;
	enum nse_sw_mode sw_mode;
	int ret;

	if (nse_bypass_switch) {
		dev_info(nse_hw_to_dev(hw),
			"Failed to disable lpm mode because nse_bypass_switch is 1\n");
		return;
	}

	sw = hw->switch_info;
	if (!sw)
		return;

	if (sw->lpm_en) {
		nse_cleanup_lpm_fltrs(hw);
		mdelay(NSE_LPM_WAIT_COUNTER_FREE_DELAY);
		nse_del_all_adv_rcp_per_profile(hw);
		nse_del_all_adv_lpm_luts(hw);
		sw->lpm_en = false;
		dev_info(nse_hw_to_dev(hw),
			"Success to disable lpm mode: lpm_en = %d\n", sw->lpm_en);

		sw_mode = NSE_SW_MODE_LEGACY;
		ret = nse_sw_set_mode(hw, &sw_mode);
		if (ret) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] set hw to lpm mode err, err = %d, mode = %d\n",
				__func__, __LINE__, ret, sw_mode);
		}
	} else
		dev_info(nse_hw_to_dev(hw),
			"lpm is already disabled: lpm_en = %d\n", sw->lpm_en);
}

