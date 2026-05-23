/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_tc.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include "ossl_knl.h"
#if (KERNEL_VERSION(5, 1, 1) <= LINUX_VERSION_CODE)
#include <net/flow_offload.h>
#include <net/ip_tunnels.h>
#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>

#include "nic_cfg_comm.h"
#include "hinic5_nic_cfg.h"
#include "hinic5_nic_dev.h"
#include "nic_tc_rule_defs.h"
#include "hinic5_tc.h"

#define TUNNEL_OPT_OFF 0
#define TUNNEL_OPT_ON 1

#define ENC_IPV4_TYPE 0
#define ENC_IPV6_TYPE 1
#define OFFSET_2BYTE 2

#define PFE_TUNNEL_OPT_SHIFT 22
#define PFE_TUNNEL_OPT_MASK 0x1
#define PFE_IPV6_SIP_SHIFT 16
#define PFE_IPV6_SIP_MASK 0x3F
#define PFE_IPV6_SIP_DIP_SHIFT 2
#define PFE_IPV6_SIP_DIP_MASK 0x3F
#define TYPE_OF_LACP 0x8809
#define TC_LACP_KEY_FLAG 0x3D
#define PFE_ACTION_TO_PORT 0x20

#define PFE_GROUP_VLD_SHIFT 8
#define PFE_GROUP_ID_MASK 0xFF
#define PFE_GROUP_CNT_MAX 64

#define GET_MASK_VAL(val, shift, mask) (((val) >> (shift)) & (mask))

enum parse_type {
	KEY_TYPE,
	MASK_TYPE
};

static const struct rhashtable_params tc_flow_ht_params = {
	.head_offset = offsetof(struct hinic5_tc_flow_node, node),
	.key_offset = offsetof(struct hinic5_tc_flow_node, cookie),
	.key_len = sizeof(((struct hinic5_tc_flow_node *)0)->cookie),
	.automatic_shrinking = true
};

static int hinic5_tc_info_init_from_reg(struct hinic5_nic_dev *nic_dev)
{
	struct hinic5_tc_info *tc_info = (struct hinic5_tc_info *)nic_dev->tc_info;
	struct hinic5_tc_pfe_cfg_reg_info cfg_info = {0};
	int ret;

	ret = hinic5_get_pfe_cfg(nic_dev->hwdev, &cfg_info);
	if (ret != 0)
		return ret;

	mutex_lock(&tc_info->tc_lock);
	tc_info->tunnel_opt = GET_MASK_VAL(cfg_info.reg_value,
					   PFE_TUNNEL_OPT_SHIFT,
					   PFE_TUNNEL_OPT_MASK);
	tc_info->ipv6_shift_value = GET_MASK_VAL(cfg_info.reg_value,
						 PFE_IPV6_SIP_SHIFT,
						 PFE_IPV6_SIP_MASK);
	tc_info->ipv6_shift_value2 = GET_MASK_VAL(cfg_info.reg_value2,
						  PFE_IPV6_SIP_DIP_SHIFT,
						  PFE_IPV6_SIP_DIP_MASK);
	mutex_unlock(&tc_info->tc_lock);

	return 0;
}

static int hinic5_tc_del_flow_handler(struct hinic5_nic_dev *nic_dev,
				      struct hinic5_tc_flow_node *flow_node)
{
	struct hinic5_tc_info *tc_info = (struct hinic5_tc_info *)nic_dev->tc_info;

	/* send del cmd to mpu */
	(void)hinic5_del_tc_flow_rule(nic_dev->hwdev, flow_node->rule_id);

	/* del flow from hashtable */
	rhashtable_remove_fast(&tc_info->flow_table, &flow_node->node,
			       tc_info->flow_ht_params);

	mutex_lock(&tc_info->tc_lock);
	clear_bit(flow_node->rule_id, tc_info->tcam_bitmap);
	mutex_unlock(&tc_info->tc_lock);

	hinic5_info(nic_dev, drv, "flow with cookie:%lx is deleted\n", flow_node->cookie);
	kfree(flow_node);

	return 0;
}

static void hinic5_tc_free_node(void *ptr, void *arg)
{
	kfree(ptr);
}

void hinic5_deinit_tc(struct hinic5_nic_dev *nic_dev)
{
	struct hinic5_tc_info *tc_info = (struct hinic5_tc_info *)nic_dev->tc_info;

	rhashtable_free_and_destroy(&tc_info->flow_table, hinic5_tc_free_node, NULL);

	hinic5_flush_tc_flow_rule(nic_dev->hwdev, tc_info->tcam_bitmap);

	kfree(tc_info);
	nic_dev->tc_info = NULL;
}

static void hinic5_tc_match_basic(struct flow_rule *rule, struct hinic5_tc_flow *flow)
{
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);
		if (match.key->n_proto != 0 && match.mask->n_proto != 0) {
			flow->l2_key.ether_type = match.key->n_proto;
			flow->l2_mask.ether_type = match.mask->n_proto;
			flow->key_flags |= BIT(HINIC5_TC_KEY_ETH_TYPE);

			if (match.key->n_proto == htons(ETH_P_IP) ||
			    match.key->n_proto == htons(ETH_P_IPV6)) {
				flow->l4_key.ip_proto = match.key->ip_proto;
				flow->l4_mask.ip_proto = match.mask->ip_proto;
				flow->key_flags |= BIT(HINIC5_TC_KEY_PROTOCOL);
			}
		}
	}
}

static void hinic5_tc_match_eth_addrs(struct flow_rule *rule, struct hinic5_tc_flow *flow)
{
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs match;

		flow_rule_match_eth_addrs(rule, &match);
		if (!is_zero_ether_addr(match.key->dst) && !is_zero_ether_addr(match.mask->dst)) {
			ether_addr_copy(flow->l2_key.dmac, match.key->dst);
			ether_addr_copy(flow->l2_mask.dmac, match.mask->dst);
			flow->key_flags |= BIT(HINIC5_TC_KEY_DST_MAC);
		}

		if (!is_zero_ether_addr(match.key->src) && !is_zero_ether_addr(match.mask->src)) {
			ether_addr_copy(flow->l2_key.smac, match.key->src);
			ether_addr_copy(flow->l2_mask.smac, match.mask->src);
			flow->key_flags |= BIT(HINIC5_TC_KEY_SRC_MAC);
		}
	}
}

static void hinic5_tc_match_vlan(struct flow_rule *rule, struct hinic5_tc_flow *flow)
{
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_vlan(rule, &match);
		flow->l2_key.vlan_tag = cpu_to_be16(match.key->vlan_id |
		    (match.key->vlan_priority << VLAN_PRIO_SHIFT));
		flow->l2_mask.vlan_tag = cpu_to_be16(match.mask->vlan_id |
		    (match.mask->vlan_priority << VLAN_PRIO_SHIFT));
		flow->key_flags |= BIT(HINIC5_TC_KEY_VLAN_TAG);

		if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CVLAN)) {
			flow_rule_match_cvlan(rule, &match);
			flow->l2_key.cvlan_tag = cpu_to_be16(match.key->vlan_id |
			    (match.key->vlan_priority << VLAN_PRIO_SHIFT));
			flow->l2_mask.cvlan_tag = cpu_to_be16(match.mask->vlan_id |
			    (match.mask->vlan_priority << VLAN_PRIO_SHIFT));
			flow->key_flags |= BIT(HINIC5_TC_KEY_CVLAN);
		}
	} else {
		flow->l2_key.vlan_tag = 0;
		flow->l2_mask.vlan_tag = 0;  /* For ipv4 non-vlan packets */
	}
}

static void hinic5_tc_match_ip_addrs(struct flow_rule *rule, struct hinic5_tc_flow *flow)
{
	struct flow_match_control ctrl_match;

	flow_rule_match_control(rule, &ctrl_match);

	if (ctrl_match.key->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS &&
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);
		flow->l3_key.ipv4.daddr.s_addr = match.key->dst;
		flow->l3_mask.ipv4.daddr.s_addr = match.mask->dst;
		flow->l3_key.ipv4.saddr.s_addr = match.key->src;
		flow->l3_mask.ipv4.saddr.s_addr = match.mask->src;

		flow->key_flags |= BIT(HINIC5_TC_KEY_IPV4);
	} else if (ctrl_match.key->addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS &&
		flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS)) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_ipv6_addrs(rule, &match);
		flow->l3_key.ipv6.daddr = match.key->dst;
		flow->l3_mask.ipv6.daddr = match.mask->dst;
		flow->l3_key.ipv6.saddr = match.key->src;
		flow->l3_mask.ipv6.saddr = match.mask->src;

		flow->key_flags |= BIT(HINIC5_TC_KEY_IPV6);
	}
}

static void hinic5_tc_match_enc_ip_addrs(struct flow_rule *rule, struct hinic5_tc_flow *flow,
					 struct hinic5_tc_info *tc_info)
{
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS)) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_enc_ipv4_addrs(rule, &match);
		flow->l3_key.enc_ipv4.daddr.s_addr = match.key->dst;
		flow->l3_mask.enc_ipv4.daddr.s_addr = match.mask->dst;
		flow->l3_key.enc_ipv4.saddr.s_addr = match.key->src;
		flow->l3_mask.enc_ipv4.saddr.s_addr = match.mask->src;
		flow->key_flags |= BIT(HINIC5_TC_KEY_ENC_IP);
		tc_info->enc_ip_type = ENC_IPV4_TYPE;
	} else if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS)) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_enc_ipv6_addrs(rule, &match);
		flow->l3_key.enc_ipv6.daddr = match.key->dst;
		flow->l3_mask.enc_ipv6.daddr = match.mask->dst;
		flow->l3_key.enc_ipv6.saddr = match.key->src;
		flow->l3_mask.enc_ipv6.saddr = match.mask->src;
		flow->key_flags |= BIT(HINIC5_TC_KEY_ENC_IP);
		tc_info->enc_ip_type = ENC_IPV6_TYPE;
	}
}

static void hinic5_tc_match_ports(struct flow_rule *rule, struct hinic5_tc_flow *flow)
{
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);
		flow->l4_key.ports.dport = match.key->dst;
		flow->l4_mask.ports.dport = match.mask->dst;
		flow->l4_key.ports.sport = match.key->src;
		flow->l4_mask.ports.sport = match.mask->src;

		flow->key_flags |= BIT(HINIC5_TC_KEY_PORTS);
	}
}

static void hinic5_tc_match_vni(struct flow_rule *rule, struct hinic5_tc_flow *flow)
{
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_KEYID)) {
		struct flow_match_enc_keyid match;

		flow_rule_match_enc_keyid(rule, &match);
		flow->l2_key.vni = be32_to_cpu(match.key->keyid);
		flow->l2_mask.vni = be32_to_cpu(match.mask->keyid);
		flow->key_flags |= BIT(HINIC5_TC_KEY_VNI);
	}
}

typedef void (*hinic5_tc_key_func)(const u8 *attr[], const struct hinic5_tc_info *tc_info, u8 *mem);

static void hinic5_tc_parse_key_field(struct hinic5_tc_flow *flow, const u8 *attr[])
{
	attr[HINIC5_TC_FIELD_ETH_TYPE] = (const u8 *)&flow->l2_key.ether_type;
	attr[HINIC5_TC_FIELD_VNI] = (const u8 *)&flow->l2_key.vni;
	attr[HINIC5_TC_FIELD_VLAN_TAG] = (const u8 *)&flow->l2_key.vlan_tag;
	attr[HINIC5_TC_FIELD_CVLAN_TAG] = (const u8 *)&flow->l2_key.cvlan_tag;
	attr[HINIC5_TC_FIELD_SRC_MAC] = (const u8 *)&flow->l2_key.smac[0];
	attr[HINIC5_TC_FIELD_DST_MAC] = (const u8 *)&flow->l2_key.dmac[0];
	attr[HINIC5_TC_FIELD_SRC_IP] = (const u8 *)&flow->l3_key.ipv4.saddr;
	attr[HINIC5_TC_FIELD_DST_IP] = (const u8 *)&flow->l3_key.ipv4.daddr;
	attr[HINIC5_TC_FIELD_ENC_DST_IP] = (const u8 *)&flow->l3_key.enc_ipv4.daddr;
	attr[HINIC5_TC_FIELD_SRC_IPV6] = (const u8 *)&flow->l3_key.ipv6.saddr;
	attr[HINIC5_TC_FIELD_DST_IPV6] = (const u8 *)&flow->l3_key.ipv6.daddr;
	attr[HINIC5_TC_FIELD_ENC_DST_IPV6] = (const u8 *)&flow->l3_key.enc_ipv6.daddr;
	attr[HINIC5_TC_FIELD_SRC_PORT] = (const u8 *)&flow->l4_key.ports.sport;
	attr[HINIC5_TC_FIELD_DST_PORT] = (const u8 *)&flow->l4_key.ports.dport;
	attr[HINIC5_TC_FIELD_PROTOCOL] = (const u8 *)&flow->l4_key.ip_proto;
}

static void hinic5_tc_parse_mask_field(struct hinic5_tc_flow *flow, const u8 *attr[])
{
	attr[HINIC5_TC_FIELD_ETH_TYPE] = (const u8 *)&flow->l2_mask.ether_type;
	attr[HINIC5_TC_FIELD_VNI] = (const u8 *)&flow->l2_mask.vni;
	attr[HINIC5_TC_FIELD_VLAN_TAG] = (const u8 *)&flow->l2_mask.vlan_tag;
	attr[HINIC5_TC_FIELD_CVLAN_TAG] = (const u8 *)&flow->l2_mask.cvlan_tag;
	attr[HINIC5_TC_FIELD_SRC_MAC] = (const u8 *)&flow->l2_mask.smac[0];
	attr[HINIC5_TC_FIELD_DST_MAC] = (const u8 *)&flow->l2_mask.dmac[0];
	attr[HINIC5_TC_FIELD_SRC_IP] = (const u8 *)&flow->l3_mask.ipv4.saddr;
	attr[HINIC5_TC_FIELD_DST_IP] = (const u8 *)&flow->l3_mask.ipv4.daddr;
	attr[HINIC5_TC_FIELD_ENC_DST_IP] = (const u8 *)&flow->l3_mask.enc_ipv4.daddr;
	attr[HINIC5_TC_FIELD_SRC_IPV6] = (const u8 *)&flow->l3_mask.ipv6.saddr;
	attr[HINIC5_TC_FIELD_DST_IPV6] = (const u8 *)&flow->l3_mask.ipv6.daddr;
	attr[HINIC5_TC_FIELD_ENC_DST_IPV6] = (const u8 *)&flow->l3_mask.enc_ipv6.daddr;
	attr[HINIC5_TC_FIELD_SRC_PORT] = (const u8 *)&flow->l4_mask.ports.sport;
	attr[HINIC5_TC_FIELD_DST_PORT] = (const u8 *)&flow->l4_mask.ports.dport;
	attr[HINIC5_TC_FIELD_PROTOCOL] = (const u8 *)&flow->l4_mask.ip_proto;
}

static u16 hinic5_tc_get_key_flags(u16 profile_id, u16 tunnel_opt)
{
	u16 key_flags[HINIC5_TC_PROFILE_MAX] = {0};

	key_flags[HINIC5_TC_PROFILE_TUN_ETH] = BIT(HINIC5_TC_KEY_VNI) |
						BIT(HINIC5_TC_KEY_SRC_MAC) |
						BIT(HINIC5_TC_KEY_DST_MAC) |
						BIT(HINIC5_TC_KEY_ETH_TYPE);

	key_flags[HINIC5_TC_PROFILE_TUN_ETH_VLAN] = BIT(HINIC5_TC_KEY_VNI) |
						BIT(HINIC5_TC_KEY_SRC_MAC) |
						BIT(HINIC5_TC_KEY_DST_MAC) |
						BIT(HINIC5_TC_KEY_ETH_TYPE) |
						BIT(HINIC5_TC_KEY_VLAN_TAG);

	key_flags[HINIC5_TC_PROFILE_TUN_ETH_QINQ] = BIT(HINIC5_TC_KEY_VNI) |
						BIT(HINIC5_TC_KEY_SRC_MAC) |
						BIT(HINIC5_TC_KEY_DST_MAC) |
						BIT(HINIC5_TC_KEY_ETH_TYPE) |
						BIT(HINIC5_TC_KEY_VLAN_TAG) |
						BIT(HINIC5_TC_KEY_CVLAN);

	key_flags[HINIC5_TC_PROFILE_ETH] = BIT(HINIC5_TC_KEY_SRC_MAC) | BIT(HINIC5_TC_KEY_DST_MAC) |
						BIT(HINIC5_TC_KEY_ETH_TYPE);

	key_flags[HINIC5_TC_PROFILE_ETH_VLAN] = BIT(HINIC5_TC_KEY_SRC_MAC) |
						BIT(HINIC5_TC_KEY_DST_MAC) |
						BIT(HINIC5_TC_KEY_ETH_TYPE) |
						BIT(HINIC5_TC_KEY_VLAN_TAG);

	key_flags[HINIC5_TC_PROFILE_ETH_QINQ] = BIT(HINIC5_TC_KEY_SRC_MAC) |
						BIT(HINIC5_TC_KEY_DST_MAC) |
						BIT(HINIC5_TC_KEY_ETH_TYPE) |
						BIT(HINIC5_TC_KEY_VLAN_TAG) |
						BIT(HINIC5_TC_KEY_CVLAN);

	key_flags[HINIC5_TC_PROFILE_TUN_ETH_IP4] = BIT(HINIC5_TC_KEY_VNI) |
						BIT(HINIC5_TC_KEY_DST_MAC) |
						BIT(HINIC5_TC_KEY_ETH_TYPE) |
						BIT(HINIC5_TC_KEY_IPV4) |
						BIT(HINIC5_TC_KEY_PROTOCOL);

	key_flags[HINIC5_TC_PROFILE_TUN_ETH_IP4_TCPORUDP] = BIT(HINIC5_TC_KEY_VNI) |
	BIT(HINIC5_TC_KEY_DST_MAC) |
						BIT(HINIC5_TC_KEY_ETH_TYPE) |
						BIT(HINIC5_TC_KEY_IPV4) |
						BIT(HINIC5_TC_KEY_PROTOCOL) |
						BIT(HINIC5_TC_KEY_PORTS);

	key_flags[HINIC5_TC_PROFILE_ETH_IP4] = BIT(HINIC5_TC_KEY_DST_MAC) |
						BIT(HINIC5_TC_KEY_IPV4) |
						BIT(HINIC5_TC_KEY_PROTOCOL);

	key_flags[HINIC5_TC_PROFILE_ETH_IP4_TCPORUDP] = BIT(HINIC5_TC_KEY_DST_MAC) |
						BIT(HINIC5_TC_KEY_IPV4) |
						BIT(HINIC5_TC_KEY_PROTOCOL) |
						BIT(HINIC5_TC_KEY_PORTS);

	if (tunnel_opt == TUNNEL_OPT_OFF) {
		key_flags[HINIC5_TC_PROFILE_TUN_ETH_IP6] = BIT(HINIC5_TC_KEY_VNI) |
						BIT(HINIC5_TC_KEY_IPV6) |
						BIT(HINIC5_TC_KEY_PROTOCOL);
		key_flags[HINIC5_TC_PROFILE_TUN_ETH_IP6_TCPORUDP] = BIT(HINIC5_TC_KEY_VNI) |
						BIT(HINIC5_TC_KEY_IPV6) |
						BIT(HINIC5_TC_KEY_PROTOCOL) |
						BIT(HINIC5_TC_KEY_PORTS);
	} else {
		key_flags[HINIC5_TC_PROFILE_TUN_ETH_IP6] = BIT(HINIC5_TC_KEY_VNI) |
						BIT(HINIC5_TC_KEY_SRC_MAC) |
						BIT(HINIC5_TC_KEY_DST_MAC) |
						BIT(HINIC5_TC_KEY_ETH_TYPE) |
						BIT(HINIC5_TC_KEY_IPV6) |
						BIT(HINIC5_TC_KEY_PROTOCOL);
		key_flags[HINIC5_TC_PROFILE_TUN_ETH_IP6_TCPORUDP] = BIT(HINIC5_TC_KEY_VNI) |
						BIT(HINIC5_TC_KEY_SRC_MAC) |
						BIT(HINIC5_TC_KEY_DST_MAC) |
						BIT(HINIC5_TC_KEY_ETH_TYPE) |
						BIT(HINIC5_TC_KEY_IPV6) |
						BIT(HINIC5_TC_KEY_PROTOCOL) |
						BIT(HINIC5_TC_KEY_PORTS);
	}

	key_flags[HINIC5_TC_PROFILE_ETH_IP6] = BIT(HINIC5_TC_KEY_DST_MAC) |
						BIT(HINIC5_TC_KEY_IPV6) |
						BIT(HINIC5_TC_KEY_PROTOCOL);

	key_flags[HINIC5_TC_PROFILE_ETH_IP6_TCPORUDP] = BIT(HINIC5_TC_KEY_DST_MAC) |
						BIT(HINIC5_TC_KEY_IPV6) |
						BIT(HINIC5_TC_KEY_PROTOCOL) |
						BIT(HINIC5_TC_KEY_PORTS);

	key_flags[HINIC5_TC_PROFILE_OUTER_IP_INNER_IP] = BIT(HINIC5_TC_KEY_ENC_IP) |
						BIT(HINIC5_TC_KEY_VNI) | BIT(HINIC5_TC_KEY_IPV4);

	key_flags[HINIC5_TC_PROFILE_OUTER_IP_INNER_IP_TCPORUDP] = BIT(HINIC5_TC_KEY_ENC_IP) |
						BIT(HINIC5_TC_KEY_VNI) |
						BIT(HINIC5_TC_KEY_IPV4) | BIT(HINIC5_TC_KEY_PORTS);

	return key_flags[profile_id];
}

static void hinic5_tc_get_key_tun_eth(const u8 *attr[],
				      const struct hinic5_tc_info *tc_info,
				      u8 *mem)
{
	struct hinic5_tc_rule_tun_eth *rule_st = (struct hinic5_tc_rule_tun_eth *)mem;

	WRITE_VNI(rule_st, attr[HINIC5_TC_FIELD_VNI]);
	WRITE_MAC(rule_st, smac, attr[HINIC5_TC_FIELD_SRC_MAC]);
	WRITE_MAC(rule_st, dmac, attr[HINIC5_TC_FIELD_DST_MAC]);
	WRITE_FIELD_U16(rule_st, ether_type, attr[HINIC5_TC_FIELD_ETH_TYPE]);
}

static void hinic5_tc_get_key_tun_eth_vlan(const u8 *attr[],
					   const struct hinic5_tc_info *tc_info,
					   u8 *mem)
{
	struct hinic5_tc_rule_tun_eth_vlan *rule_st = (struct hinic5_tc_rule_tun_eth_vlan *)mem;

	WRITE_VNI(rule_st, attr[HINIC5_TC_FIELD_VNI]);
	WRITE_MAC(rule_st, smac, attr[HINIC5_TC_FIELD_SRC_MAC]);
	WRITE_MAC(rule_st, dmac, attr[HINIC5_TC_FIELD_DST_MAC]);
	WRITE_FIELD_U16(rule_st, ether_type, attr[HINIC5_TC_FIELD_ETH_TYPE]);
	WRITE_FIELD_SPLIT_U16(rule_st, vlan_tag, attr[HINIC5_TC_FIELD_VLAN_TAG]);
}

static void hinic5_tc_get_key_tun_eth_qinq(const u8 *attr[],
					   const struct hinic5_tc_info *tc_info,
					   u8 *mem)
{
	struct hinic5_tc_rule_tun_eth_qinq *rule_st = (struct hinic5_tc_rule_tun_eth_qinq *)mem;

	WRITE_VNI(rule_st, attr[HINIC5_TC_FIELD_VNI]);
	WRITE_MAC(rule_st, smac, attr[HINIC5_TC_FIELD_SRC_MAC]);
	WRITE_MAC(rule_st, dmac, attr[HINIC5_TC_FIELD_DST_MAC]);
	WRITE_FIELD_U16(rule_st, ether_type, attr[HINIC5_TC_FIELD_ETH_TYPE]);
	WRITE_FIELD_SPLIT_U16(rule_st, vlan_tag, attr[HINIC5_TC_FIELD_VLAN_TAG]);
	WRITE_FIELD_U16(rule_st, cvlan_tag, attr[HINIC5_TC_FIELD_CVLAN_TAG]);
}

static void hinic5_tc_get_key_eth(const u8 *attr[], const struct hinic5_tc_info *tc_info, u8 *mem)
{
	struct hinic5_tc_rule_eth *rule_st = (struct hinic5_tc_rule_eth *)mem;

	WRITE_MAC(rule_st, smac, attr[HINIC5_TC_FIELD_SRC_MAC]);
	WRITE_MAC(rule_st, dmac, attr[HINIC5_TC_FIELD_DST_MAC]);
	WRITE_FIELD_U16(rule_st, ether_type, attr[HINIC5_TC_FIELD_ETH_TYPE]);
}

static void hinic5_tc_get_key_eth_vlan(const u8 *attr[],
				       const struct hinic5_tc_info *tc_info,
				       u8 *mem)
{
	struct hinic5_tc_rule_eth_vlan *rule_st = (struct hinic5_tc_rule_eth_vlan *)mem;

	WRITE_MAC(rule_st, smac, attr[HINIC5_TC_FIELD_SRC_MAC]);
	WRITE_MAC(rule_st, dmac, attr[HINIC5_TC_FIELD_DST_MAC]);
	WRITE_FIELD_U16(rule_st, ether_type, attr[HINIC5_TC_FIELD_ETH_TYPE]);
	WRITE_FIELD_U16(rule_st, vlan_tag, attr[HINIC5_TC_FIELD_VLAN_TAG]);
}

static void hinic5_tc_get_key_eth_qinq(const u8 *attr[],
				       const struct hinic5_tc_info *tc_info,
				       u8 *mem)
{
	struct hinic5_tc_rule_eth_qinq *rule_st = (struct hinic5_tc_rule_eth_qinq *)mem;

	WRITE_MAC(rule_st, smac, attr[HINIC5_TC_FIELD_SRC_MAC]);
	WRITE_MAC(rule_st, dmac, attr[HINIC5_TC_FIELD_DST_MAC]);
	WRITE_FIELD_U16(rule_st, ether_type, attr[HINIC5_TC_FIELD_ETH_TYPE]);
	WRITE_FIELD_U16(rule_st, vlan_tag, attr[HINIC5_TC_FIELD_VLAN_TAG]);
	WRITE_FIELD_U16(rule_st, cvlan_tag, attr[HINIC5_TC_FIELD_CVLAN_TAG]);
}

static void hinic5_tc_get_key_tun_eth_ip4(const u8 *attr[],
					  const struct hinic5_tc_info *tc_info,
					  u8 *mem)
{
	struct hinic5_tc_rule_tun_eth_ip4 *rule_st = (struct hinic5_tc_rule_tun_eth_ip4 *)mem;

	WRITE_VNI(rule_st, attr[HINIC5_TC_FIELD_VNI]);
	WRITE_MAC(rule_st, dmac, attr[HINIC5_TC_FIELD_DST_MAC]);
	WRITE_FIELD_SPLIT_U16(rule_st, ether_type, attr[HINIC5_TC_FIELD_ETH_TYPE]);
	WRITE_IP4(rule_st, sip, attr[HINIC5_TC_FIELD_SRC_IP]);
	WRITE_IP4(rule_st, dip, attr[HINIC5_TC_FIELD_DST_IP]);
	WRITE_FIELD_U8(rule_st, proto, attr[HINIC5_TC_FIELD_PROTOCOL]);
}

static void hinic5_tc_get_key_tun_eth_ip4_tcporudp(const u8 *attr[],
						   const struct hinic5_tc_info *tc_info,
						   u8 *mem)
{
	struct hinic5_tc_rule_tun_eth_ip4_tcporudp *rule_st =
			(struct hinic5_tc_rule_tun_eth_ip4_tcporudp *)mem;

	WRITE_VNI(rule_st, attr[HINIC5_TC_FIELD_VNI]);
	WRITE_MAC(rule_st, dmac, attr[HINIC5_TC_FIELD_DST_MAC]);
	WRITE_FIELD_SPLIT_U16(rule_st, ether_type, attr[HINIC5_TC_FIELD_ETH_TYPE]);
	WRITE_IP4(rule_st, sip, attr[HINIC5_TC_FIELD_SRC_IP]);
	WRITE_IP4(rule_st, dip, attr[HINIC5_TC_FIELD_DST_IP]);
	WRITE_FIELD_U8(rule_st, proto, attr[HINIC5_TC_FIELD_PROTOCOL]);
	WRITE_FIELD_U16(rule_st, sport, attr[HINIC5_TC_FIELD_SRC_PORT]);
	WRITE_FIELD_U16(rule_st, dport, attr[HINIC5_TC_FIELD_DST_PORT]);
}

static void hinic5_tc_get_key_eth_ip4(const u8 *attr[],
				      const struct hinic5_tc_info *tc_info,
				      u8 *mem)
{
	struct hinic5_tc_rule_eth_ip4 *rule_st = (struct hinic5_tc_rule_eth_ip4 *)mem;

	WRITE_FIELD_U16(rule_st, vlan_tag, attr[HINIC5_TC_FIELD_VLAN_TAG]);
	WRITE_MAC(rule_st, dmac, attr[HINIC5_TC_FIELD_DST_MAC]);
	WRITE_IP4(rule_st, sip, attr[HINIC5_TC_FIELD_SRC_IP]);
	WRITE_IP4(rule_st, dip, attr[HINIC5_TC_FIELD_DST_IP]);
	WRITE_FIELD_U8(rule_st, proto, attr[HINIC5_TC_FIELD_PROTOCOL]);
}

static void hinic5_tc_get_key_eth_ip4_tcporudp(const u8 *attr[],
					       const struct hinic5_tc_info *tc_info,
					       u8 *mem)
{
	struct hinic5_tc_rule_eth_ip4_tcporudp *rule_st =
			(struct hinic5_tc_rule_eth_ip4_tcporudp *)mem;

	WRITE_FIELD_U16(rule_st, vlan_tag, attr[HINIC5_TC_FIELD_VLAN_TAG]);
	WRITE_MAC(rule_st, dmac, attr[HINIC5_TC_FIELD_DST_MAC]);
	WRITE_IP4(rule_st, sip, attr[HINIC5_TC_FIELD_SRC_IP]);
	WRITE_IP4(rule_st, dip, attr[HINIC5_TC_FIELD_DST_IP]);
	WRITE_FIELD_U8(rule_st, proto, attr[HINIC5_TC_FIELD_PROTOCOL]);
	WRITE_FIELD_SPLIT_U16(rule_st, sport, attr[HINIC5_TC_FIELD_SRC_PORT]);
	WRITE_FIELD_U16(rule_st, dport, attr[HINIC5_TC_FIELD_DST_PORT]);
}

static void hinic5_tc_get_ip6_trunc(const u8 *ip6, u8 *trunc_mem, u16 ip6_bit_len, u16 shift)
{
	/* keep ip6 bits[shift+ip6_bit_len:shift] */
	u16 i, trunc_byte_idx, trunc_bit_idx;
	u16 start_bit = IP6_ADDR_128BITS - ip6_bit_len - shift;
	u8 bit_val;

	for (i = start_bit; i < start_bit + ip6_bit_len; i++) {
		trunc_byte_idx = (i - start_bit) / BYTE8_SIZE;
		trunc_bit_idx = BYTE8_SIZE - 1 - (i - start_bit) % BYTE8_SIZE;
		bit_val = (ip6[i / BYTE8_SIZE] >> (BYTE8_SIZE - 1 - i % BYTE8_SIZE)) & 1;
		trunc_mem[trunc_byte_idx] |= bit_val << trunc_bit_idx;
	}
}

static void hinic5_tc_set_ip6_trunc(const u8 *attr[], const struct hinic5_tc_info *tc_info,
				    struct hinic5_tc_ip6_trunc *ip6_trunc)
{
	switch (tc_info->profile_id) {
	case HINIC5_TC_PROFILE_TUN_ETH_IP6:
	case HINIC5_TC_PROFILE_TUN_ETH_IP6_TCPORUDP:
		hinic5_tc_get_ip6_trunc(attr[HINIC5_TC_FIELD_SRC_IPV6], ip6_trunc->sip6,
					IP6_ADDR_TRUNC_72BITS, tc_info->ipv6_shift_value2);
		attr[HINIC5_TC_FIELD_SRC_IPV6] = ip6_trunc->sip6;
		hinic5_tc_get_ip6_trunc(attr[HINIC5_TC_FIELD_DST_IPV6], ip6_trunc->dip6,
					IP6_ADDR_TRUNC_72BITS, tc_info->ipv6_shift_value2);
		attr[HINIC5_TC_FIELD_DST_IPV6] = ip6_trunc->dip6;
		break;
	case HINIC5_TC_PROFILE_ETH_IP6_TCPORUDP:
		hinic5_tc_get_ip6_trunc(attr[HINIC5_TC_FIELD_SRC_IPV6], ip6_trunc->sip6,
					IP6_ADDR_TRUNC_96BITS, tc_info->ipv6_shift_value);
		attr[HINIC5_TC_FIELD_SRC_IPV6] = ip6_trunc->sip6;
		break;
	default:
		break;
	}
}

static void hinic5_tc_get_key_tun_eth_ip6(const u8 *attr[],
					  const struct hinic5_tc_info *tc_info,
					  u8 *mem)
{
	struct hinic5_tc_rule_tun_eth_ip6_off *rule_st_off =
			(struct hinic5_tc_rule_tun_eth_ip6_off *)mem;
	struct hinic5_tc_rule_tun_eth_ip6_on *rule_st_on =
			(struct hinic5_tc_rule_tun_eth_ip6_on *)mem;
	struct hinic5_tc_ip6_trunc ip6_trunc = {0};

	if (tc_info->tunnel_opt == TUNNEL_OPT_OFF) {
		WRITE_VNI(rule_st_off, attr[HINIC5_TC_FIELD_VNI]);
		WRITE_IP6_128BITS_OPT_OFF(rule_st_off, sip6, attr[HINIC5_TC_FIELD_SRC_IPV6]);
		WRITE_IP6_128BITS_OPT_OFF(rule_st_off, dip6, attr[HINIC5_TC_FIELD_DST_IPV6]);
		WRITE_FIELD_U8(rule_st_off, proto, attr[HINIC5_TC_FIELD_PROTOCOL]);
	} else {
		hinic5_tc_set_ip6_trunc(attr, tc_info, &ip6_trunc);
		WRITE_VNI(rule_st_on, attr[HINIC5_TC_FIELD_VNI]);
		WRITE_MAC(rule_st_on, smac, attr[HINIC5_TC_FIELD_SRC_MAC]);
		WRITE_MAC(rule_st_on, dmac, attr[HINIC5_TC_FIELD_DST_MAC]);
		WRITE_FIELD_U16(rule_st_on, ether_type, attr[HINIC5_TC_FIELD_ETH_TYPE]);
		WRITE_SIP6_72BITS_OPT_ON(rule_st_on, attr[HINIC5_TC_FIELD_SRC_IPV6]);
		WRITE_DIP6_72BITS_OPT_ON(rule_st_on, attr[HINIC5_TC_FIELD_DST_IPV6]);
		WRITE_FIELD_U8(rule_st_on, proto, attr[HINIC5_TC_FIELD_PROTOCOL]);
	}
}

static void hinic5_tc_get_key_tun_eth_ip6_tcporudp(const u8 *attr[],
						   const struct hinic5_tc_info *tc_info,
						   u8 *mem)
{
	struct hinic5_tc_rule_tun_eth_ip6_tcporudp_off *rule_st_off =
			(struct hinic5_tc_rule_tun_eth_ip6_tcporudp_off *)mem;
	struct hinic5_tc_rule_tun_eth_ip6_tcporudp_on *rule_st_on =
			(struct hinic5_tc_rule_tun_eth_ip6_tcporudp_on *)mem;
	struct hinic5_tc_ip6_trunc ip6_trunc = {0};

	if (tc_info->tunnel_opt == TUNNEL_OPT_OFF) {
		WRITE_VNI(rule_st_off, attr[HINIC5_TC_FIELD_VNI]);
		WRITE_IP6_128BITS_OPT_OFF(rule_st_off, sip6, attr[HINIC5_TC_FIELD_SRC_IPV6]);
		WRITE_IP6_128BITS_OPT_OFF(rule_st_off, dip6, attr[HINIC5_TC_FIELD_DST_IPV6]);
		WRITE_FIELD_U8(rule_st_off, proto, attr[HINIC5_TC_FIELD_PROTOCOL]);
		WRITE_FIELD_U16(rule_st_off, sport, attr[HINIC5_TC_FIELD_SRC_PORT]);
		WRITE_FIELD_U16(rule_st_off, dport, attr[HINIC5_TC_FIELD_DST_PORT]);
	} else {
		hinic5_tc_set_ip6_trunc(attr, tc_info, &ip6_trunc);
		WRITE_VNI(rule_st_on, attr[HINIC5_TC_FIELD_VNI]);
		WRITE_MAC(rule_st_on, smac, attr[HINIC5_TC_FIELD_SRC_MAC]);
		WRITE_MAC(rule_st_on, dmac, attr[HINIC5_TC_FIELD_DST_MAC]);
		WRITE_FIELD_U16(rule_st_on, ether_type, attr[HINIC5_TC_FIELD_ETH_TYPE]);
		WRITE_SIP6_72BITS_OPT_ON(rule_st_on, attr[HINIC5_TC_FIELD_SRC_IPV6]);
		WRITE_DIP6_72BITS_OPT_ON(rule_st_on, attr[HINIC5_TC_FIELD_DST_IPV6]);
		WRITE_FIELD_U8(rule_st_on, proto, attr[HINIC5_TC_FIELD_PROTOCOL]);
		WRITE_FIELD_U16(rule_st_on, sport, attr[HINIC5_TC_FIELD_SRC_PORT]);
		WRITE_FIELD_U16(rule_st_on, dport, attr[HINIC5_TC_FIELD_DST_PORT]);
	}
}

static void hinic5_tc_get_key_eth_ip6(const u8 *attr[],
				      const struct hinic5_tc_info *tc_info,
				      u8 *mem)
{
	struct hinic5_tc_rule_eth_ip6 *rule_st = (struct hinic5_tc_rule_eth_ip6 *)mem;

	WRITE_MAC(rule_st, dmac, attr[HINIC5_TC_FIELD_DST_MAC]);
	WRITE_IP6_128BITS(rule_st, sip6, attr[HINIC5_TC_FIELD_SRC_IPV6]);
	WRITE_IP6_128BITS(rule_st, dip6, attr[HINIC5_TC_FIELD_DST_IPV6]);
	WRITE_FIELD_U8(rule_st, proto, attr[HINIC5_TC_FIELD_PROTOCOL]);
}

static void hinic5_tc_get_key_eth_ip6_tcporudp(const u8 *attr[],
					       const struct hinic5_tc_info *tc_info,
					       u8 *mem)
{
	struct hinic5_tc_rule_eth_ip6_tcporudp *rule_st =
			(struct hinic5_tc_rule_eth_ip6_tcporudp *)mem;
	struct hinic5_tc_ip6_trunc ip6_trunc = {0};

	hinic5_tc_set_ip6_trunc(attr, tc_info, &ip6_trunc);
	WRITE_MAC(rule_st, dmac, attr[HINIC5_TC_FIELD_DST_MAC]);
	WRITE_IP6_96BITS(rule_st, sip6, attr[HINIC5_TC_FIELD_SRC_IPV6]);
	WRITE_IP6_128BITS(rule_st, dip6, attr[HINIC5_TC_FIELD_DST_IPV6]);
	WRITE_FIELD_U8(rule_st, proto, attr[HINIC5_TC_FIELD_PROTOCOL]);
	WRITE_FIELD_U16(rule_st, sport, attr[HINIC5_TC_FIELD_SRC_PORT]);
	WRITE_FIELD_SPLIT_U16(rule_st, dport, attr[HINIC5_TC_FIELD_DST_PORT]);
}

static void hinic5_tc_get_key_outer_ip_inner_ip(const u8 *attr[],
						const struct hinic5_tc_info *tc_info,
						u8 *mem)
{
	struct hinic5_tc_rule_outer_ip_inner_ip *rule_st =
			(struct hinic5_tc_rule_outer_ip_inner_ip *)mem;

	if (tc_info->enc_ip_type == ENC_IPV4_TYPE) {
		WRITE_FIELD_U16(rule_st, outer_dip_6, attr[HINIC5_TC_FIELD_ENC_DST_IP]);
		WRITE_FIELD_U16(rule_st, outer_dip_7,
				attr[HINIC5_TC_FIELD_ENC_DST_IP] + OFFSET_2BYTE);
	} else {
		WRITE_IP6_128BITS(rule_st, outer_dip, attr[HINIC5_TC_FIELD_ENC_DST_IPV6]);
	}

	WRITE_VNI(rule_st, attr[HINIC5_TC_FIELD_VNI]);
	WRITE_IP4(rule_st, sip, attr[HINIC5_TC_FIELD_SRC_IP]);
	WRITE_IP4(rule_st, dip, attr[HINIC5_TC_FIELD_DST_IP]);
}

static void hinic5_tc_get_key_outer_ip_inner_ip_tcporudp(const u8 *attr[],
							 const struct hinic5_tc_info *tc_info,
							 u8 *mem)
{
	struct hinic5_tc_rule_outer_ip_inner_ip_tcporudp *rule_st =
			(struct hinic5_tc_rule_outer_ip_inner_ip_tcporudp *)mem;

	if (tc_info->enc_ip_type == ENC_IPV4_TYPE) {
		WRITE_FIELD_U16(rule_st, outer_dip_6, attr[HINIC5_TC_FIELD_ENC_DST_IP]);
		WRITE_FIELD_U16(rule_st, outer_dip_7,
				attr[HINIC5_TC_FIELD_ENC_DST_IP] + OFFSET_2BYTE);
	} else {
		WRITE_IP6_128BITS(rule_st, outer_dip, attr[HINIC5_TC_FIELD_ENC_DST_IPV6]);
	}

	WRITE_VNI(rule_st, attr[HINIC5_TC_FIELD_VNI]);
	WRITE_IP4(rule_st, sip, attr[HINIC5_TC_FIELD_SRC_IP]);
	WRITE_IP4(rule_st, dip, attr[HINIC5_TC_FIELD_DST_IP]);
	WRITE_FIELD_U16(rule_st, sport, attr[HINIC5_TC_FIELD_SRC_PORT]);
	WRITE_FIELD_SPLIT_U16(rule_st, dport, attr[HINIC5_TC_FIELD_DST_PORT]);
}

static hinic5_tc_key_func g_hinic5_tc_key_funcs[HINIC5_TC_PROFILE_MAX] = {
	hinic5_tc_get_key_tun_eth,
	hinic5_tc_get_key_tun_eth_vlan,
	hinic5_tc_get_key_tun_eth_qinq,
	hinic5_tc_get_key_eth,
	hinic5_tc_get_key_eth_vlan,
	hinic5_tc_get_key_eth_qinq,
	hinic5_tc_get_key_tun_eth_ip4,
	hinic5_tc_get_key_tun_eth_ip4_tcporudp,
	hinic5_tc_get_key_eth_ip4,
	hinic5_tc_get_key_eth_ip4_tcporudp,
	hinic5_tc_get_key_tun_eth_ip6,
	hinic5_tc_get_key_tun_eth_ip6_tcporudp,
	hinic5_tc_get_key_eth_ip6,
	hinic5_tc_get_key_eth_ip6_tcporudp,
	hinic5_tc_get_key_outer_ip_inner_ip,
	hinic5_tc_get_key_outer_ip_inner_ip_tcporudp,
};

static hinic5_tc_key_func hinic5_tc_get_key_func(u16 profile_id)
{
	return g_hinic5_tc_key_funcs[profile_id];
}

static int hinic5_tc_parse_key(struct hinic5_tc_flow *flow,
			       u8 *mem,
			       struct hinic5_nic_dev *nic_dev,
			       enum parse_type type)
{
	struct hinic5_tc_info *tc_info = (struct hinic5_tc_info *)nic_dev->tc_info;
	const u8 *attr[HINIC5_TC_FIELD_TYPE_MAX] = {NULL};
	u16 profile_id, tunnel_opt;
	hinic5_tc_key_func key_func = NULL;
	u16 flags;

	mutex_lock(&tc_info->tc_lock);
	profile_id = tc_info->profile_id;
	tunnel_opt = tc_info->tunnel_opt;
	mutex_unlock(&tc_info->tc_lock);

	/* verify profile_id */
	if (profile_id >= HINIC5_TC_PROFILE_MAX) {
		hinic5_err(nic_dev, drv, "profile_id exceed limit: profile_id = %u\n", profile_id);
		return -EINVAL;
	}

	hinic5_info(nic_dev, drv, "Get profile id : %u\n", profile_id);

	flags = hinic5_tc_get_key_flags(profile_id, tunnel_opt);
	if ((flow->key_flags & flags) != flags) {
		hinic5_err(nic_dev, drv, "flow key flags not match, flow_flags(%u) key_flags(%u)\n",
			   flow->key_flags, flags);
		return -EINVAL;
	}

	if (type == KEY_TYPE)
		hinic5_tc_parse_key_field(flow, attr);
	else
		hinic5_tc_parse_mask_field(flow, attr);

	key_func = hinic5_tc_get_key_func(profile_id);
	key_func(attr, tc_info, mem);

	return 0;
}

#define ACT_VXLAN_TBL_INDEX_BITS  8
#define ACT_FLOW_MARK_BITS        24
#define ACT_VLAN_SEL_BITS         3
#define ACT_COUNT_ID_BITS         9
#define ACT_CHECK_VLD(field_val, field_bits) ((field_val) < (1ULL << (field_bits)))

static int hinic5_tc_parse_action_tunnel(struct hinic5_tc_action_info *action,
					 const struct flow_action_entry *act)
{
	const struct ip_tunnel_info *tun_info = act->tunnel;
	const struct ip_tunnel_key *tun_key = &tun_info->key;
	u64 index = be64_to_cpu(tun_key->tun_id);

	if (ip_tunnel_info_af(tun_info) != AF_INET)
		return -EOPNOTSUPP; /* only IPv4 tunnel-encap is supported */

	if (!ACT_CHECK_VLD(index, ACT_VXLAN_TBL_INDEX_BITS))
		return -EINVAL;

	action->vxlan_tbl_index = (u8)index;
	action->action_flag |= BIT(HINIC5_TC_ACTION_VXLAN_ENCAP);

	return 0;
}

static void hinic5_tc_parse_action_output(struct hinic5_tc_action_info *action,
					  const struct flow_action_entry *act)
{
	// action queue + action output temporary stub solution
	/* output, chain_index[15:0]
	 * queue index, chain_index[23:16]
	 *queue flag, chain_index[31:24]
	 */
	action->output = act->chain_index & U16_MAX;
	action->action_flag |= BIT(HINIC5_TC_ACTION_FLOW_OUTPUT);
	if ((act->chain_index >> SHIFT_24BITS) > 0) {
		action->flow_queue = (u8)(act->chain_index >> SHIFT_16BITS);
		action->action_flag |= BIT(HINIC5_TC_ACTION_FLOW_QUEUE);
	}
}

static int hinic5_tc_parse_action(struct flow_action *flow_action, struct hinic5_nic_dev *nic_dev,
				  struct hinic5_tc_action_info *action)
{
	struct flow_action_entry *act = NULL;
	unsigned int i;

	if (!flow_action_has_entries(flow_action)) {
		hinic5_err(nic_dev, drv, "no actions\n");
		return -EINVAL;
	}

	flow_action_for_each(i, act, flow_action) {
		switch (act->id) {
		case FLOW_ACTION_DROP:
			action->action_flag |= BIT(HINIC5_TC_ACTION_FLOW_DROP);
			break;
		case FLOW_ACTION_ACCEPT: // action upcall function stub
			action->action_flag |= BIT(HINIC5_TC_ACTION_FLOW_UPCALL);
			break;
		case FLOW_ACTION_MARK:
			action->flow_mark = act->mark;
			if (!ACT_CHECK_VLD(action->flow_mark, ACT_FLOW_MARK_BITS))
				return -EINVAL;
			action->action_flag |= BIT(HINIC5_TC_ACTION_FLOW_MARK);
			break;
		case FLOW_ACTION_GOTO:
			hinic5_tc_parse_action_output(action, act);
			break;
#ifdef HAVE_FLOW_ACTION_PRIORITY
		case FLOW_ACTION_PRIORITY: // action count function stub
			action->count_id = (u16)act->priority;
			if (!ACT_CHECK_VLD(action->count_id, ACT_COUNT_ID_BITS))
				return -EINVAL;
			action->action_flag |= BIT(HINIC5_TC_ACTION_FLOW_COUNT);
			break;
#endif
		case FLOW_ACTION_VLAN_PUSH:
			action->vlan_tag = act->vlan.vid;
			action->vlan_sel = act->vlan.prio;
			if (!ACT_CHECK_VLD(action->vlan_sel, ACT_VLAN_SEL_BITS))
				return -EINVAL;
			action->action_flag |= BIT(HINIC5_TC_ACTION_FLOW_VLAN_PUSH);
			break;
		case FLOW_ACTION_VLAN_POP:
			action->action_flag |= BIT(HINIC5_TC_ACTION_FLOW_VLAN_POP);
			break;
		case FLOW_ACTION_TUNNEL_ENCAP:
			if (hinic5_tc_parse_action_tunnel(action, act) != 0)
				return -EOPNOTSUPP;
			break;
		case FLOW_ACTION_TUNNEL_DECAP:
			action->action_flag |= BIT(HINIC5_TC_ACTION_VXLAN_DECAP);
			break;
		default:
			hinic5_err(nic_dev, drv, "act(%u) not support offload\n", act->id);
			break;
		}
	}
	return 0;
}

int hinic5_tc_set_profile_id(struct hinic5_nic_dev *nic_dev, u16 profile_id)
{
	struct hinic5_tc_info *tc_info = (struct hinic5_tc_info *)nic_dev->tc_info;

	if (profile_id >= HINIC5_TC_PROFILE_MAX) {
		hinic5_err(nic_dev, drv, "profile_id exceed limit\n");
		return -EINVAL;
	}

	mutex_lock(&tc_info->tc_lock);
	tc_info->profile_id = profile_id;
	mutex_unlock(&tc_info->tc_lock);
	return 0;
}

static int hinic5_tc_set_flow_info(struct hinic5_nic_dev *nic_dev,
				   struct hinic5_tc_flow *flow,
				   struct hinic5_tc_cfg_info *info)
{
	int ret;

	/* parse key */
	ret = hinic5_tc_parse_key(flow, info->key_tcam_mem, nic_dev, KEY_TYPE);
	if (ret != 0) {
		hinic5_err(nic_dev, drv, "parse key failed\n");
		return -EINVAL;
	}

	/* parse mask, unassigned data set all f */
	memset(info->mask_tcam_mem, 0xFF, TC_ACL_KEY_BYTE);
	ret = hinic5_tc_parse_key(flow, info->mask_tcam_mem, nic_dev, MASK_TYPE);
	if (ret != 0) {
		hinic5_err(nic_dev, drv, "parse mask failed\n");
		return -EINVAL;
	}

	info->action = flow->actions;

	return 0;
}

static int hinic5_tc_parse_flow(struct flow_cls_offload *tc_flow_cmd,
				struct hinic5_nic_dev *nic_dev,
				struct hinic5_tc_flow *flow,
				struct hinic5_tc_info *tc_info)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(tc_flow_cmd);
	struct flow_dissector *dissector = rule->match.dissector;
	int ret;

	/* KEY_CONTROL and KEY_BASIC are needed for forming a meaningful key */
	if ((dissector->used_keys & BIT(FLOW_DISSECTOR_KEY_CONTROL)) == 0 ||
	    (dissector->used_keys & BIT(FLOW_DISSECTOR_KEY_BASIC)) == 0) {
		hinic5_err(nic_dev, drv, "cannot form TC key: used_keys = 0x%x\n",
			   (unsigned int)dissector->used_keys);
		return -EOPNOTSUPP;
	}

	/* parse action */
	ret = hinic5_tc_parse_action(&rule->action, nic_dev, &flow->actions);
	if (ret != 0) {
		hinic5_err(nic_dev, drv, "parse action failed\n");
		return -EINVAL;
	}

	/* save rule's info to flow */
	hinic5_tc_match_basic(rule, flow);
	hinic5_tc_match_eth_addrs(rule, flow);
	hinic5_tc_match_vlan(rule, flow);
	hinic5_tc_match_ip_addrs(rule, flow);
	hinic5_tc_match_enc_ip_addrs(rule, flow, tc_info);
	hinic5_tc_match_ports(rule, flow);
	hinic5_tc_match_vni(rule, flow);

	return 0;
}

static int hinic5_add_cls_flower(struct flow_cls_offload *cls_flower,
				 struct hinic5_nic_dev *nic_dev)
{
	struct hinic5_tc_info *tc_info = (struct hinic5_tc_info *)nic_dev->tc_info;
	struct hinic5_tc_flow_node *new_node = NULL, *old_node = NULL;
	struct hinic5_tc_cfg_info info = {0};
	struct hinic5_tc_flow *flow = NULL;
	int ret;

	ret = hinic5_tc_info_init_from_reg(nic_dev);
	if (ret != 0) {
		hinic5_err(nic_dev, drv, "pfe get cfg from reg failed\n");
		return -EOPNOTSUPP;
	}

	new_node = kzalloc(sizeof(*new_node), GFP_KERNEL);
	if (!new_node)
		return -ENOMEM;

	new_node->cookie = cls_flower->cookie;
	flow = &new_node->flow;

	/* If a flow exists with the same cookie, delete it */
	old_node = rhashtable_lookup_fast(&tc_info->flow_table, &cls_flower->cookie,
					  tc_info->flow_ht_params);
	if (old_node)
		hinic5_tc_del_flow_handler(nic_dev, old_node);

	ret = hinic5_tc_parse_flow(cls_flower, nic_dev, flow, tc_info);
	if (ret != 0)
		goto fail;

	/* trans flow to tc_cfg_info */
	ret = hinic5_tc_set_flow_info(nic_dev, flow, &info);
	if (ret != 0)
		goto fail;

	info.group_id = cls_flower->common.chain_index & PFE_GROUP_ID_MASK;
	if (info.group_id < PFE_GROUP_CNT_MAX) {
		info.group_vld = (cls_flower->common.chain_index >> PFE_GROUP_VLD_SHIFT) & 0x1;
	} else {
		hinic5_err(nic_dev, drv, "invalid group id:0x%x\n", info.group_id);
		goto fail;
	}

	/* send rule to mpu */
	ret = hinic5_add_tc_flow_rule(nic_dev->hwdev, &info, false);
	if (ret != 0)
		goto fail;
	new_node->rule_id = info.index;

	/* save rule in hashmap */
	ret = rhashtable_insert_fast(&tc_info->flow_table, &new_node->node,
				     tc_info->flow_ht_params);
	if (ret != 0) {
		hinic5_del_tc_flow_rule(nic_dev->hwdev, info.index);
		goto fail;
	}

	mutex_lock(&tc_info->tc_lock);
	set_bit(info.index, tc_info->tcam_bitmap);
	mutex_unlock(&tc_info->tc_lock);

	hinic5_info(nic_dev, drv, "Add tc rule cookie=0x%lx, index = %u\n",
		    cls_flower->cookie, info.index);

	return 0;
fail:
	kfree(new_node);
	hinic5_err(nic_dev, drv, "cookie=0x%lx error=%d\n",
		   cls_flower->cookie, ret);
	return ret;
}

static int hinic5_del_cls_flower(const struct flow_cls_offload *cls_flower,
				 struct hinic5_nic_dev *nic_dev)
{
	struct hinic5_tc_info *tc_info = (struct hinic5_tc_info *)nic_dev->tc_info;
	struct hinic5_tc_flow_node *flow_node = NULL;

	if (!tc_info)
		return 0;

	flow_node = rhashtable_lookup_fast(&tc_info->flow_table, &cls_flower->cookie,
					   tc_info->flow_ht_params);
	if (!flow_node) {
		hinic5_err(nic_dev, drv, "flow with cookie=0x%lx not exist\n",
			   cls_flower->cookie);
		return -EINVAL;
	}

	return hinic5_tc_del_flow_handler(nic_dev, flow_node);
}

int hinic5_setup_cls_flower(struct flow_cls_offload *cls_flower,
			    struct hinic5_nic_dev *nic_dev)
{
	if (!HINIC5_SUPPORT_FEATURE(nic_dev->hwdev, TC_FLOWER_OFFLOAD))
		return -EOPNOTSUPP;

	switch (cls_flower->command) {
	case FLOW_CLS_REPLACE:
		return hinic5_add_cls_flower(cls_flower, nic_dev);
	case FLOW_CLS_DESTROY:
		return hinic5_del_cls_flower(cls_flower, nic_dev);
	case FLOW_CLS_STATS:
		return -EOPNOTSUPP;
	default:
		return -EOPNOTSUPP;
	}
}

static int hinic5_setup_tc_block_cb(enum tc_setup_type type, void *type_data, void *cb_priv)
{
	struct hinic5_nic_dev *nic_dev = cb_priv;
	struct flow_cls_offload *cls_flower = (struct flow_cls_offload *)type_data;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return hinic5_setup_cls_flower(cls_flower, nic_dev);
	default:
		return -EOPNOTSUPP;
	}
}

static LIST_HEAD(hinic5_block_cb_list);

int hinic5_setup_tc(struct net_device *netdev, enum tc_setup_type type, void *type_data)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	switch (type) {
	case TC_SETUP_BLOCK:
		return flow_block_cb_setup_simple(type_data, &hinic5_block_cb_list,
						  hinic5_setup_tc_block_cb, nic_dev, nic_dev, true);
	default:
		return -EOPNOTSUPP;
	}
}

/* PFE default rule for LACP negotiation packets */
static int hinic5_set_default_rule_of_pfe_lcam(struct hinic5_nic_dev *nic_dev)
{
	struct hinic5_tc_info *tc_info = (struct hinic5_tc_info *)nic_dev->tc_info;
	struct hinic5_tc_cfg_info info = {0};
	struct hinic5_tc_flow flow = {0};
	u8 *mac = (u8 *)nic_dev->netdev->dev_addr;
	u8 lacp_dmac[ETH_ALEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x02};

	if (hinic5_func_type(nic_dev->hwdev) == TYPE_VF)
		return 0;

	tc_info->profile_id = HINIC5_TC_PROFILE_ETH_QINQ;
	flow.key_flags = TC_LACP_KEY_FLAG;
	flow.actions.action_flag = PFE_ACTION_TO_PORT;
	memset(flow.l2_mask.dmac, 0xff, ETH_ALEN);
	memset(flow.l2_mask.smac, 0xff, ETH_ALEN);
	memset(&flow.l2_mask.ether_type, 0xff, sizeof(flow.l2_mask.ether_type));
	memcpy(flow.l2_key.dmac, lacp_dmac, ETH_ALEN);
	flow.l2_key.ether_type = cpu_to_be16(TYPE_OF_LACP);
	memcpy(flow.l2_key.smac, mac, ETH_ALEN);

	/* trans flow to tc_cfg_info */
	(void)hinic5_tc_set_flow_info(nic_dev, &flow, &info);

	/* send rule to mpu */
	(void)hinic5_add_tc_flow_rule(nic_dev->hwdev, &info, true);

	mutex_lock(&tc_info->tc_lock);
	set_bit(info.index, tc_info->tcam_bitmap);
	mutex_unlock(&tc_info->tc_lock);

	tc_info->profile_id = HINIC5_TC_PROFILE_TUN_ETH;

	return 0;
}

int hinic5_init_tc(struct hinic5_nic_dev *nic_dev)
{
	struct hinic5_tc_info *tc_info = NULL;
	int ret;

	nic_dev->tc_info = kmalloc(sizeof(struct hinic5_tc_info), GFP_KERNEL);
	if (!nic_dev->tc_info)
		return -ENOMEM;
	tc_info = (struct hinic5_tc_info *)nic_dev->tc_info;

	tc_info->flow_ht_params = tc_flow_ht_params;
	ret = rhashtable_init(&tc_info->flow_table, &tc_info->flow_ht_params);
	if (ret != 0)
		goto tc_info_init_err;

	tc_info->profile_id = 0;
	mutex_init(&tc_info->tc_lock);
	memset(tc_info->tcam_bitmap, 0, sizeof(tc_info->tcam_bitmap));

	(void)hinic5_set_default_rule_of_pfe_lcam(nic_dev);

	return 0;

tc_info_init_err:
	kfree(tc_info);
	nic_dev->tc_info = NULL;
	return ret;
}

#endif
