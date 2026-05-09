// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_tc.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/netdevice.h>
#ifdef HAVE_FLOW_OFFLOAD_H
#include <net/flow_offload.h>
#endif
#include <net/vxlan.h>
#include <net/geneve.h>
#include <net/gre.h>
#include <net/udp_tunnel.h>
#include <linux/if_vlan.h>

#include "sxe2_compat.h"
#include "sxe2_vsi.h"
#include "sxe2_netdev.h"
#include "sxe2_log.h"
#include "sxe2_common.h"
#include "sxe2_tc.h"
#include "sxe2_switch.h"

#define SXE2_TC_FLOWER_MASK_32 0xFFFFFFFF
#define SXE2_TC_FLOWER_MASK_16 0xFFFF
#define SXE2_TC_FLOWER_VNI_MAX 0xFFFFFFU

enum sxe2_tunnel_type sxe2_tc_tun_type_get(struct net_device *tunnel_dev)
{
#ifdef HAVE_VXLAN_TYPE
	if (netif_is_vxlan(tunnel_dev))
		return SXE2_TNL_VXLAN;
#endif

#ifdef HAVE_GENEVE_TYPE
	if (netif_is_geneve(tunnel_dev))
		return SXE2_TNL_GENEVE;
#endif

#ifdef HAVE_GRETAP_TYPE
	if (netif_is_gretap(tunnel_dev) || netif_is_ip6gretap(tunnel_dev))
		return SXE2_TNL_GRETAP;
#endif

	return SXE2_TNL_NONE;
}

#if defined(HAVE_TC_FLOWER_ENC) && defined(HAVE_TC_INDIR_BLOCK)
static struct net_device *sxe2_tunnel_device_get(struct net_device *dev,
						 struct flow_rule *rule)
{
#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
	struct flow_action_entry *act;
	u32 i;

	if (sxe2_tc_tun_type_get(dev) != SXE2_TNL_NONE)
		return dev;

	if (rule->action.num_entries == 0)
		return NULL;

	i = rule->action.num_entries - 1;
	act = &rule->action.entries[i];
	if ((act->id == FLOW_ACTION_REDIRECT || act->id == FLOW_ACTION_MIRRED) &&
	    sxe2_tc_tun_type_get(act->dev) != SXE2_TNL_NONE)
		return act->dev;
#endif

	return NULL;
}
#endif

#if defined(HAVE_TC_FLOWER_ENC) && defined(HAVE_TC_INDIR_BLOCK)
static s32 sxe2_tc_set_ipv4(struct flow_match_ipv4_addrs *match,
			    struct sxe2_tcf_fltr *fltr, bool is_outer)
{
	struct sxe2_adapter *adapter = fltr->adapter;
	struct sxe2_tcf_key_item *item;

	if (match->key->dst) {
		if (is_outer)
			item = &fltr->items[SXE2_OUTER_IPV4_DADDR];
		else
			item = &fltr->items[SXE2_INNER_IPV4_DADDR];
		item->value.hdr.ipv4_hdr.daddr = match->key->dst;
		item->mask.hdr.ipv4_hdr.daddr  = match->mask->dst;
		LOG_DEBUG_BDF("prot_type %d, daddr[%d], mask[0x%x]\n",
			      item->type, match->key->dst, match->mask->dst);
	}
	if (match->key->src) {
		if (is_outer)
			item = &fltr->items[SXE2_OUTER_IPV4_SADDR];
		else
			item = &fltr->items[SXE2_INNER_IPV4_SADDR];
		item->value.hdr.ipv4_hdr.saddr = match->key->src;
		item->mask.hdr.ipv4_hdr.saddr  = match->mask->src;
		LOG_DEBUG_BDF("prot_type %d, saddr[%d], mask[0x%x]\n",
			      item->type, match->key->src, match->mask->src);
	}
	return 0;
}

static s32 sxe2_tc_set_ipv6(struct flow_match_ipv6_addrs *match,
			    struct sxe2_tcf_fltr *fltr, bool is_outer,
			    struct flow_cls_offload *cls_flower)
{
	struct sxe2_adapter *adapter = fltr->adapter;
	struct sxe2_tcf_key_item *item;

	if (ipv6_addr_loopback(&match->key->dst) ||
	    ipv6_addr_loopback(&match->key->src)) {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
		NL_SET_ERR_MSG_MOD(cls_flower->common.extack, "Bad IPv6, addr is LOOPBACK");
#endif
		return -EINVAL;
	}
	if (ipv6_addr_any(&match->mask->dst) && ipv6_addr_any(&match->mask->src)) {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
		NL_SET_ERR_MSG_MOD(cls_flower->common.extack, "Bad src/dest IPv6, addr is any");
#endif
		return -EINVAL;
	}

	if (!ipv6_addr_any(&match->mask->dst)) {
		if (is_outer)
			item = &fltr->items[SXE2_OUTER_IPV6_DADDR];
		else
			item = &fltr->items[SXE2_INNER_IPV6_DADDR];
		memcpy(item->value.hdr.ipv6_hdr.daddr, match->key->dst.s6_addr,
		       sizeof(match->key->dst.s6_addr));
		memcpy(item->mask.hdr.ipv6_hdr.daddr, match->mask->dst.s6_addr,
		       sizeof(match->mask->dst.s6_addr));
		LOG_DEBUG_BDF("prot_type %d, daddr[%d:%d:%d:%d], mask[0x%x:%x:%x:%x]\n",
			      item->type, match->key->dst.s6_addr32[0],
			      match->key->dst.s6_addr32[1],
			      match->key->dst.s6_addr32[2],
			      match->key->dst.s6_addr32[3],
			      match->mask->dst.s6_addr32[0],
			      match->mask->dst.s6_addr32[1],
			      match->mask->dst.s6_addr32[2],
			      match->mask->dst.s6_addr32[3]);
	}
	if (!ipv6_addr_any(&match->mask->src)) {
		if (is_outer)
			item = &fltr->items[SXE2_OUTER_IPV6_SADDR];
		else
			item = &fltr->items[SXE2_INNER_IPV6_SADDR];
		memcpy(item->value.hdr.ipv6_hdr.saddr, match->key->src.s6_addr,
		       sizeof(match->key->src.s6_addr));
		memcpy(item->mask.hdr.ipv6_hdr.saddr, match->mask->src.s6_addr,
		       sizeof(match->mask->src.s6_addr));
		LOG_DEBUG_BDF("prot_type %d, saddr[%d:%d:%d:%d], mask[0x%x:%x:%x:%x]\n",
			      item->type, match->key->src.s6_addr32[0],
			      match->key->src.s6_addr32[1],
			      match->key->src.s6_addr32[2],
			      match->key->src.s6_addr32[3],
			      match->mask->src.s6_addr32[0],
			      match->mask->src.s6_addr32[1],
			      match->mask->src.s6_addr32[2],
			      match->mask->src.s6_addr32[3]);
	}

	return 0;
}

static s32 sxe2_tc_set_ttl_tos(struct flow_match_ip *match,
			       struct sxe2_tcf_fltr *fltr, bool is_outer)
{
	struct sxe2_adapter *adapter = fltr->adapter;
	struct sxe2_tcf_key_item *item;

	if (match->mask->tos) {
		if (is_outer)
			item = &fltr->items[SXE2_OUTER_IPV4_TOS];
		else
			item = &fltr->items[SXE2_INNER_IPV4_TOS];
		item->value.hdr.ipv4_hdr.tos = match->key->tos;
		item->mask.hdr.ipv4_hdr.tos  = match->mask->tos;

		LOG_DEBUG_BDF("prot_type %d, tos[%d], mask[0x%x]\n",
			      item->type, match->key->tos, match->mask->tos);
	}

	if (match->mask->ttl) {
		if (is_outer)
			item = &fltr->items[SXE2_OUTER_IPV4_TTL];
		else
			item = &fltr->items[SXE2_INNER_IPV4_TTL];
		item->value.hdr.ipv4_hdr.ttl = match->key->ttl;
		item->mask.hdr.ipv4_hdr.ttl  = match->mask->ttl;

		LOG_DEBUG_BDF("prot_type %d, ttl[%d], mask[0x%x]\n",
			      item->type, match->key->ttl, match->mask->ttl);
	}

	return 0;
}

static inline s32 sxe2_match_key_parse_enc_keyid(struct flow_rule *rule,
						 struct sxe2_tcf_fltr *fltr)
{
	struct sxe2_adapter *adapter = fltr->adapter;
	struct flow_match_enc_keyid enc_keyid;
	struct sxe2_tcf_key_item *item;
	u32 key_id;

	flow_rule_match_enc_keyid(rule, &enc_keyid);
	if (!enc_keyid.mask->keyid ||
	    enc_keyid.mask->keyid != cpu_to_be32(SXE2_TC_FLOWER_MASK_32)) {
		LOG_DEV_ERR("bad mask for encap key_id 0x%04x, it must be 0xFFFFFFFF\n",
			    be32_to_cpu(enc_keyid.mask->keyid));
		return -EINVAL;
	}

	key_id = be32_to_cpu(enc_keyid.key->keyid);
	if ((fltr->tunnel_type == SXE2_TNL_VXLAN ||
	     fltr->tunnel_type == SXE2_TNL_GENEVE) &&
	    key_id > SXE2_TC_FLOWER_VNI_MAX) {
		LOG_DEV_ERR("VNI out of range : 0x%x\n", key_id);
		return -EINVAL;
	}

	if (fltr->tunnel_type == SXE2_TNL_VXLAN) {
		item = &fltr->items[SXE2_VXLAN_ENC_ID];
		item->value.hdr.udp_tnl_hdr.vni = cpu_to_be32(key_id << 8);
		memcpy(&item->mask.hdr.udp_tnl_hdr.vni, "\xff\xff\xff\x00", 4);
	} else if (fltr->tunnel_type == SXE2_TNL_GENEVE) {
		item = &fltr->items[SXE2_GENEVE_ENC_ID];
		item->value.hdr.udp_tnl_hdr.vni = cpu_to_be32(key_id << 8);
		memcpy(&item->mask.hdr.udp_tnl_hdr.vni, "\xff\xff\xff\x00", 4);
	} else if (fltr->tunnel_type == SXE2_TNL_GRETAP) {
		item = &fltr->items[SXE2_NVGRE_ENC_ID];
		item->value.hdr.nvgre_hdr.tni = cpu_to_be32(key_id);
		memcpy(&item->mask.hdr.nvgre_hdr.tni, "\xff\xff\xff\xff", 4);
	} else {
		return -EINVAL;
	}

	LOG_DEBUG_BDF("prot_type %d, keyid[%u], mask[0x%x]\n", item->type,
		      enc_keyid.key->keyid, enc_keyid.mask->keyid);
	return 0;
}

static inline s32 sxe2_match_key_parse_enc_ipv4(struct flow_rule *rule,
						struct sxe2_tcf_fltr *fltr)
{
	struct flow_match_ipv4_addrs match;

	flow_rule_match_enc_ipv4_addrs(rule, &match);
	if (sxe2_tc_set_ipv4(&match, fltr, true))
		return -EINVAL;

	return 0;
}

static inline s32 sxe2_match_key_parse_enc_ipv6(struct flow_rule *rule,
						struct sxe2_tcf_fltr *fltr,
						struct flow_cls_offload *cls_flower)
{
	struct flow_match_ipv6_addrs match;

	flow_rule_match_enc_ipv6_addrs(rule, &match);
	if (sxe2_tc_set_ipv6(&match, fltr, true, cls_flower))
		return -EINVAL;

	return 0;
}

static inline s32 sxe2_match_key_parse_enc_ip(struct flow_rule *rule,
					      struct sxe2_tcf_fltr *fltr)
{
	struct flow_match_ip match;

	flow_rule_match_enc_ip(rule, &match);
	return sxe2_tc_set_ttl_tos(&match, fltr, true);
}

static s32 sxe2_tc_set_ipv4_proto(struct flow_match_basic *match,
				  struct sxe2_tcf_fltr *fltr, bool is_outer)
{
	struct sxe2_adapter *adapter = fltr->adapter;
	struct sxe2_tcf_key_item *item;

	if (is_outer)
		item = &fltr->items[SXE2_OUTER_IPV4_PROT];
	else
		item = &fltr->items[SXE2_INNER_IPV4_PROT];
	item->value.hdr.ipv4_hdr.protocol = match->key->ip_proto;
	item->mask.hdr.ipv4_hdr.protocol  = match->mask->ip_proto;
	LOG_DEBUG_BDF("prot_type %d, ip_protocol[%d], mask[0x%x]\n",
		      item->type, item->value.hdr.ipv4_hdr.protocol,
		      item->mask.hdr.ipv4_hdr.protocol);

	return 0;
}

static inline s32 sxe2_match_key_parse_basic(struct flow_rule *rule,
					     struct sxe2_tcf_fltr *fltr)
{
	struct sxe2_adapter *adapter = fltr->adapter;
	u16 proto_mask		     = 0;
	u16 proto_key		     = 0;
	struct flow_match_basic match;
	struct sxe2_tcf_key_item *item;
	bool is_outer = true;

	flow_rule_match_basic(rule, &match);

	proto_key  = ntohs(match.key->n_proto);
	proto_mask = ntohs(match.mask->n_proto);

	if (proto_key == ETH_P_ALL || proto_key == 0) {
		proto_key  = 0;
		proto_mask = 0;
	}

	if (fltr->tunnel_type == SXE2_TNL_NONE)
		item = &fltr->items[SXE2_OUTER_ETYPE];
	else
		item = &fltr->items[SXE2_INNER_ETYPE];

	item->value.hdr.ethertype.ethtype_id = cpu_to_be16(proto_key);
	item->mask.hdr.ethertype.ethtype_id  = cpu_to_be16(proto_mask);
	fltr->ip_proto			     = match.key->ip_proto;

	if (fltr->tunnel_type != SXE2_TNL_NONE)
		is_outer = false;
	(void)sxe2_tc_set_ipv4_proto(&match, fltr, is_outer);

	LOG_DEBUG_BDF("prot_type %d, ethtype[%d], mask[0x%x], ip_proto %d\n",
		      item->type, match.key->n_proto, match.mask->n_proto,
		      fltr->ip_proto);
	return 0;
}

static inline s32 sxe2_match_key_parse_mac(struct flow_rule *rule,
					   struct sxe2_tcf_fltr *fltr)
{
	struct sxe2_adapter *adapter = fltr->adapter;
	struct flow_match_eth_addrs match;
	struct sxe2_tcf_key_item *item;

	flow_rule_match_eth_addrs(rule, &match);

	if (!is_zero_ether_addr(match.key->dst)) {
		if (fltr->tunnel_type == SXE2_TNL_NONE)
			item = &fltr->items[SXE2_OUTER_DMAC];
		else
			item = &fltr->items[SXE2_INNER_DMAC];
		ether_addr_copy(item->value.hdr.eth_hdr.dst_addr,
				match.key->dst);
		ether_addr_copy(item->mask.hdr.eth_hdr.dst_addr,
				match.mask->dst);
		LOG_DEBUG_BDF("prot_type %d, dmac[%pM], mask[%pM]\n",
			      item->type, match.key->dst, match.mask->dst);
	}

	if (!is_zero_ether_addr(match.key->src)) {
		if (fltr->tunnel_type == SXE2_TNL_NONE)
			item = &fltr->items[SXE2_OUTER_SMAC];
		else
			item = &fltr->items[SXE2_INNER_SMAC];
		ether_addr_copy(item->value.hdr.eth_hdr.src_addr,
				match.key->src);
		ether_addr_copy(item->mask.hdr.eth_hdr.src_addr,
				match.mask->src);
		LOG_DEBUG_BDF("prot_type %d, smac[%pM], mask[%pM]\n",
			      item->type, match.key->src, match.mask->src);
	}
	return 0;
}

static inline s32 sxe2_match_key_parse_vlan(struct net_device *filter_dev,
					    struct flow_rule *rule,
					    struct sxe2_tcf_fltr *fltr,
					    struct flow_cls_offload *cls_flower)
{
	struct sxe2_adapter *adapter = fltr->adapter;
	struct flow_dissector_key_vlan mask;
	struct flow_dissector_key_vlan key;
	struct flow_match_vlan match;
	struct sxe2_tcf_key_item *item;

	item = &fltr->items[SXE2_OUTER_VLAN_EX];
	if (is_vlan_dev(filter_dev)) {
		match.key		 = &key;
		match.key->vlan_id	 = vlan_dev_vlan_id(filter_dev);
		match.key->vlan_priority = 0;
		match.mask		 = &mask;
		memset(match.mask, 0xff, sizeof(*match.mask));
		match.mask->vlan_priority = 0;
	} else {
		flow_rule_match_vlan(rule, &match);
	}

	if (match.mask->vlan_id && match.mask->vlan_id != VLAN_VID_MASK) {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
		NL_SET_ERR_MSG_MOD(cls_flower->common.extack, "Bad VLAN mask");
#endif
		return -EINVAL;
	}

	if (match.mask->vlan_tpid) {
		item->value.hdr.vlan_hdr.type = match.key->vlan_tpid;
		item->mask.hdr.vlan_hdr.type  = match.mask->vlan_tpid;
		LOG_DEBUG_BDF("prot_type %d, vlan_tpid[%d], mask[0x%x]\n",
			      item->type, match.key->vlan_tpid,
			      match.mask->vlan_tpid);
	}

	if (match.mask->vlan_id) {
		item->value.hdr.vlan_hdr.vlan |=
			cpu_to_be16(match.key->vlan_id & VLAN_VID_MASK);
		item->mask.hdr.vlan_hdr.vlan |= cpu_to_be16(VLAN_VID_MASK);
		LOG_DEBUG_BDF("prot_type %d, vlan_id[%d], mask[0x%x], is_vlan_dev %d\n",
			      item->type, match.key->vlan_id, match.mask->vlan_id,
			      is_vlan_dev(filter_dev));
	}

	if (match.mask->vlan_priority) {
		item->value.hdr.vlan_hdr.vlan |=
			be16_encode_bits(match.key->vlan_priority, VLAN_PRIO_MASK);
		item->mask.hdr.vlan_hdr.vlan |= cpu_to_be16(VLAN_PRIO_MASK);
		LOG_DEBUG_BDF("prot_type %d, vlan_priority[%d], mask[0x%x], is_vlan_dev %d\n",
			      item->type, match.key->vlan_priority,
			      match.mask->vlan_priority, is_vlan_dev(filter_dev));
	}
	return 0;
}

#ifdef HAVE_FLOW_DISSECTOR_KEY_CVLAN
static inline s32 sxe2_match_key_parse_cvlan(struct flow_rule *rule,
					     struct sxe2_tcf_fltr *fltr,
					     struct flow_cls_offload *cls_flower)
{
	struct sxe2_adapter *adapter = fltr->adapter;
	struct flow_match_vlan match;
	struct sxe2_tcf_key_item *item;

	item = &fltr->items[SXE2_OUTER_VLAN];

	flow_rule_match_cvlan(rule, &match);
	if (match.mask->vlan_id && match.mask->vlan_id != VLAN_VID_MASK) {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
		NL_SET_ERR_MSG_MOD(cls_flower->common.extack, "Bad CVLAN mask");
#endif
		return -EINVAL;
	}

	if (match.mask->vlan_tpid) {
		item->value.hdr.vlan_hdr.type = match.key->vlan_tpid;
		item->mask.hdr.vlan_hdr.type  = match.mask->vlan_tpid;
		LOG_DEBUG_BDF("prot_type %d, vlan_tpid[%d], mask[0x%x]\n",
			      item->type, match.key->vlan_tpid,
			      match.mask->vlan_tpid);
	}

	if (match.mask->vlan_id) {
		item->value.hdr.vlan_hdr.vlan |=
			cpu_to_be16(match.key->vlan_id & VLAN_VID_MASK);
		item->mask.hdr.vlan_hdr.vlan |= cpu_to_be16(VLAN_VID_MASK);
		LOG_DEBUG_BDF("prot_type %d, vlan_id[%d], mask[0x%x]\n",
			      item->type, match.key->vlan_id,
			      match.mask->vlan_id);
	}

	if (match.mask->vlan_priority) {
		item->value.hdr.vlan_hdr.vlan |=
			be16_encode_bits(match.key->vlan_priority, VLAN_PRIO_MASK);
		item->mask.hdr.vlan_hdr.vlan |= cpu_to_be16(VLAN_PRIO_MASK);
		LOG_DEBUG_BDF("prot_type %d, vlan_priority[%d], mask[0x%x]\n",
			      item->type, match.key->vlan_priority,
			      match.mask->vlan_priority);
	}
	return 0;
}
#endif

static inline s32 sxe2_match_key_parse_control(struct flow_rule *rule,
					       struct sxe2_tcf_fltr *fltr,
					       struct flow_cls_offload *cls_flower)
{
	u16 addr_type = 0;
	struct flow_match_control match_c;
	bool is_outer = true;

	flow_rule_match_control(rule, &match_c);
	addr_type = match_c.key->addr_type;
	if (fltr->tunnel_type != SXE2_TNL_NONE)
		is_outer = false;

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);
		if (sxe2_tc_set_ipv4(&match, fltr, is_outer))
			return -EINVAL;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_ipv6_addrs(rule, &match);
		if (sxe2_tc_set_ipv6(&match, fltr, is_outer, cls_flower))
			return -EINVAL;
	}
	return 0;
}

static inline s32 sxe2_match_key_parse_ip(struct flow_rule *rule,
					  struct sxe2_tcf_fltr *fltr)
{
	struct flow_match_ip match;
	bool is_outer = true;

	flow_rule_match_ip(rule, &match);
	if (fltr->tunnel_type != SXE2_TNL_NONE)
		is_outer = false;

	return sxe2_tc_set_ttl_tos(&match, fltr, is_outer);
}

static inline s32 sxe2_match_key_parse_port(struct flow_rule *rule,
					    struct sxe2_tcf_fltr *fltr,
					    struct flow_cls_offload *cls_flower)
{
	struct sxe2_adapter *adapter = fltr->adapter;
	struct flow_match_ports match;
	struct sxe2_tcf_key_item *item;

	flow_rule_match_ports(rule, &match);
	if (fltr->ip_proto != IPPROTO_TCP && fltr->ip_proto != IPPROTO_UDP) {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
		NL_SET_ERR_MSG_MOD(cls_flower->common.extack,
				   "Only UDP and TCP transport are supported");
#endif
		return -EINVAL;
	}

	if (match.key->dst) {
		if (fltr->ip_proto == IPPROTO_TCP) {
			item = &fltr->items[SXE2_LAST_TCP_DPORT];
			item->value.hdr.tcp_hdr.dest = match.key->dst;
			item->mask.hdr.tcp_hdr.dest  = match.mask->dst;
		} else {
			if (fltr->tunnel_type == SXE2_TNL_NONE)
				item = &fltr->items[SXE2_OUTER_UDP_DPORT];
			else
				item = &fltr->items[SXE2_INNER_UDP_DPORT];
			item->value.hdr.udp_hdr.dest = match.key->dst;
			item->mask.hdr.udp_hdr.dest  = match.mask->dst;
		}
		LOG_DEBUG_BDF("prot_type %d, dport[%d], mask[0x%x]\n",
			      item->type, match.key->dst, match.mask->dst);
	}
	if (match.key->src) {
		if (fltr->ip_proto == IPPROTO_TCP) {
			item = &fltr->items[SXE2_LAST_TCP_SPORT];
			item->value.hdr.tcp_hdr.source = match.key->src;
			item->mask.hdr.tcp_hdr.source  = match.mask->src;
		} else {
			if (fltr->tunnel_type == SXE2_TNL_NONE)
				item = &fltr->items[SXE2_OUTER_UDP_SPORT];
			else
				item = &fltr->items[SXE2_INNER_UDP_SPORT];
			item->value.hdr.udp_hdr.source = match.key->src;
			item->mask.hdr.udp_hdr.source  = match.mask->src;
		}
		LOG_DEBUG_BDF("prot_type %d, sport[%d], mask[0x%x]\n",
			      item->type, match.key->src, match.mask->src);
	}

	return 0;
}

static s32 sxe2_tcf_match_tunnel_parse(enum sxe2_tunnel_type tunnel_type,
				       struct flow_rule *rule,
				       struct sxe2_tcf_fltr *fltr,
				       struct flow_cls_offload *cls_flower)
{
	struct flow_match_control enc_control;
	u16 addr_type = 0;
	s32 ret;

	fltr->tunnel_type = tunnel_type;
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_KEYID)) {
		ret = sxe2_match_key_parse_enc_keyid(rule, fltr);
		if (ret)
			return ret;
	}

	flow_rule_match_enc_control(rule, &enc_control);
	addr_type = enc_control.key->addr_type;

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		ret = sxe2_match_key_parse_enc_ipv4(rule, fltr);
		if (ret)
			return ret;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		ret = sxe2_match_key_parse_enc_ipv6(rule, fltr, cls_flower);
		if (ret)
			return ret;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IP)) {
		ret = sxe2_match_key_parse_enc_ip(rule, fltr);
		if (ret)
			return ret;
	}

	return 0;
}

static s32 sxe2_tcf_match_parse(struct net_device *filter_dev,
				struct sxe2_adapter *adapter,
				struct flow_cls_offload *cls_flower,
				struct sxe2_tcf_fltr *fltr)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls_flower);
	struct flow_dissector *dissector = rule->match.dissector;
	struct net_device *tunnel_dev;
	enum sxe2_tunnel_type tunnel_type;
	s32 ret;

	if (dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_CONTROL) | BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_VLAN) | BIT(FLOW_DISSECTOR_KEY_CVLAN) |
	      BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_PORTS) |
#ifdef HAVE_TC_FLOWER_ENC
	      BIT(FLOW_DISSECTOR_KEY_ENC_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_KEYID) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IP) |
#endif
	      BIT(FLOW_DISSECTOR_KEY_IP))) {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
		NL_SET_ERR_MSG_MOD(cls_flower->common.extack, "Unsupported key used");
#endif
		return -EOPNOTSUPP;
	}

	tunnel_dev = sxe2_tunnel_device_get(filter_dev, rule);
	if (tunnel_dev) {
		tunnel_type = sxe2_tc_tun_type_get(tunnel_dev);
		if (tunnel_type == SXE2_TNL_NONE) {
			LOG_DEV_ERR("Tunnel HW offload is not supported for the tunnel type");
			return -EOPNOTSUPP;
		}
		ret = sxe2_tcf_match_tunnel_parse(tunnel_type, rule, fltr, cls_flower);
		if (ret) {
			LOG_DEV_ERR("Failed to parse TC flower tunnel attributes");
			return ret;
		}
	} else {
		if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) ||
		    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) ||
		    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_KEYID)) {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
			NL_SET_ERR_MSG_MOD(cls_flower->common.extack,
					   "Tunnel key used, but device isn't a tunnel");
#endif
			return -EOPNOTSUPP;
		}
		fltr->tunnel_type = SXE2_TNL_NONE;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		ret = sxe2_match_key_parse_basic(rule, fltr);
		if (ret)
			return ret;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		ret = sxe2_match_key_parse_mac(rule, fltr);
		if (ret)
			return ret;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN) ||
	    is_vlan_dev(filter_dev)) {
		ret = sxe2_match_key_parse_vlan(filter_dev, rule, fltr, cls_flower);
		if (ret)
			return ret;
	}

#ifdef HAVE_FLOW_DISSECTOR_KEY_CVLAN
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CVLAN)) {
		ret = sxe2_match_key_parse_cvlan(rule, fltr, cls_flower);
		if (ret)
			return ret;
	}
#endif

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		ret = sxe2_match_key_parse_control(rule, fltr, cls_flower);
		if (ret)
			return ret;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
		ret = sxe2_match_key_parse_ip(rule, fltr);
		if (ret)
			return ret;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		ret = sxe2_match_key_parse_port(rule, fltr, cls_flower);
		if (ret)
			return ret;
	}

	return 0;
}
#endif

#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
static bool sxe2_is_uplink_netdev(struct net_device *dev)
{
	return sxe2_netdev_is(dev) || (sxe2_tc_tun_type_get(dev) != SXE2_TNL_NONE);
}

static bool sxe2_netdev_pf_check(struct sxe2_adapter *adapter,
				 struct net_device *out_dev)
{
	struct sxe2_netdev_priv *np;

	np = netdev_priv(out_dev);

	if (sxe2_tc_tun_type_get(out_dev) != SXE2_TNL_NONE)
		return true;

	if (sxe2_is_repr_netdev(out_dev) && np->repr->vf_node->adapter == adapter)
		return true;
	else if (sxe2_netdev_is(out_dev) && np->vsi->adapter == adapter)
		return true;

	return false;
}
#endif

static s32 sxe2_tcf_action_parse(struct net_device *filter_dev,
				 struct flow_cls_offload *cls_flower,
				 struct sxe2_tcf_fltr *fltr)
{
#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls_flower);
	struct flow_action *flow_action = &rule->action;
	struct flow_action_entry *act;
	struct sxe2_adapter *adapter = fltr->adapter;
	struct sxe2_netdev_priv *np;
	u32 i;
	u16 vsi_id = 0;

	if (!flow_action_has_entries(flow_action))
		return -EINVAL;

	for (i = 0; i < (flow_action)->num_entries; ++i) {
		act = &(flow_action)->entries[i];
		if (act->id == FLOW_ACTION_DROP) {
			fltr->dst_vsi_id = 0;
			fltr->action	 = SXE2_DROP_PACKET;
			if (sxe2_is_repr_netdev(filter_dev)) {
				fltr->src_type = SXE2_SRC_TYPE_TX;
			} else if (sxe2_is_uplink_netdev(filter_dev)) {
				fltr->src_type = SXE2_SRC_TYPE_RX;
			} else {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
				NL_SET_ERR_MSG_MOD(cls_flower->common.extack,
						   "Unsupported netdevice");
#endif
				return -EINVAL;
			}

			np = netdev_priv(filter_dev);
			if (sxe2_is_repr_netdev(filter_dev))
				fltr->src_vsi_id = np->repr->vf_node->vsi_id[SXE2_VF_TYPE_ETH];
			else if (sxe2_tc_tun_type_get(filter_dev) != SXE2_TNL_NONE)
				fltr->src_vsi_id = adapter->vsi_ctxt.main_vsi->idx_in_dev;
			else
				fltr->src_vsi_id = np->vsi->idx_in_dev;
		} else if (act->id == FLOW_ACTION_REDIRECT || act->id == FLOW_ACTION_MIRRED) {
			if (!sxe2_netdev_pf_check(adapter, act->dev)) {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
				NL_SET_ERR_MSG_MOD(cls_flower->common.extack,
						   "Unsupported netdevice");
#endif
				return -EINVAL;
			}

			fltr->action = (act->id == FLOW_ACTION_REDIRECT) ?
					SXE2_FWD_TO_VSI : SXE2_MIRROR_PACKET;
			if (sxe2_is_repr_netdev(filter_dev) && sxe2_is_repr_netdev(act->dev)) {
				fltr->src_type	 = SXE2_SRC_TYPE_TX;
				np		 = netdev_priv(filter_dev);
				fltr->src_vsi_id = np->repr->vf_node->vsi_id[SXE2_VF_TYPE_ETH];
				np		 = netdev_priv(act->dev);

				if (fltr->action == SXE2_FWD_TO_VSI_LIST)
					set_bit(np->repr->vf_node->vsi_id[SXE2_VF_TYPE_ETH],
						fltr->dst_vsi_map);
				else
					fltr->dst_vsi_id =
						np->repr->vf_node->vsi_id[SXE2_VF_TYPE_ETH];
			} else if (sxe2_is_repr_netdev(filter_dev) && sxe2_netdev_is(act->dev)) {
				fltr->src_type	 = SXE2_SRC_TYPE_TX;
				np		 = netdev_priv(filter_dev);
				fltr->src_vsi_id = np->repr->vf_node->vsi_id[SXE2_VF_TYPE_ETH];
				np		 = netdev_priv(act->dev);
				if (fltr->action == SXE2_FWD_TO_VSI_LIST)
					set_bit(np->vsi->idx_in_dev, fltr->dst_vsi_map);
				else
					fltr->dst_vsi_id = np->vsi->idx_in_dev;
			} else if (sxe2_netdev_is(filter_dev) &&
				   sxe2_is_repr_netdev(act->dev)) {
				fltr->src_type	 = SXE2_SRC_TYPE_RX;
				np		 = netdev_priv(filter_dev);
				fltr->src_vsi_id = np->vsi->idx_in_dev;
				np		 = netdev_priv(act->dev);
				if (fltr->action == SXE2_FWD_TO_VSI_LIST)
					set_bit(np->repr->vf_node->vsi_id[SXE2_VF_TYPE_ETH],
						fltr->dst_vsi_map);
				else
					fltr->dst_vsi_id =
						np->repr->vf_node->vsi_id[SXE2_VF_TYPE_ETH];
			} else if ((sxe2_tc_tun_type_get(filter_dev) != SXE2_TNL_NONE) &&
				   (sxe2_is_repr_netdev(act->dev))) {
				fltr->src_type = SXE2_SRC_TYPE_RX;
				fltr->src_vsi_id = adapter->vsi_ctxt.main_vsi->idx_in_dev;
				np = netdev_priv(act->dev);
				if (fltr->action == SXE2_FWD_TO_VSI_LIST)
					set_bit(np->repr->vf_node->vsi_id[SXE2_VF_TYPE_ETH],
						fltr->dst_vsi_map);
				else
					fltr->dst_vsi_id =
						np->repr->vf_node->vsi_id[SXE2_VF_TYPE_ETH];
			} else if ((sxe2_tc_tun_type_get(act->dev) !=
				    SXE2_TNL_NONE) &&
				   (sxe2_is_repr_netdev(filter_dev))) {
				fltr->src_type = SXE2_SRC_TYPE_TX;
				if (fltr->action == SXE2_FWD_TO_VSI_LIST)
					set_bit(adapter->vsi_ctxt.main_vsi->idx_in_dev,
						fltr->dst_vsi_map);
				else
					fltr->dst_vsi_id = adapter->vsi_ctxt.main_vsi->idx_in_dev;
				np = netdev_priv(filter_dev);
				fltr->src_vsi_id = np->repr->vf_node->vsi_id[SXE2_VF_TYPE_ETH];
			} else {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
				NL_SET_ERR_MSG_MOD(cls_flower->common.extack,
						   "Unsupported netdevice");
#endif
				return -EINVAL;
			}

			if ((fltr->action == SXE2_FWD_TO_VSI_LIST &&
			     test_bit(fltr->src_vsi_id, fltr->dst_vsi_map)) ||
			    (fltr->action != SXE2_FWD_TO_VSI_LIST &&
			     fltr->src_vsi_id == fltr->dst_vsi_id)) {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
				NL_SET_ERR_MSG_MOD(cls_flower->common.extack,
						   "can't forward from a device to itself");
#endif
				return -EOPNOTSUPP;
			}
		} else {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
			NL_SET_ERR_MSG_MOD(cls_flower->common.extack,
					   "Unsupported action");
#endif
			return -EINVAL;
		}
	}
	fltr->priority = SXE2_SWITCH_RECIPE_PRIO_7;

	if (fltr->action == SXE2_FWD_TO_VSI_LIST) {
		while (true) {
			vsi_id =
			 (u16)find_next_bit((unsigned long *)fltr->dst_vsi_map,
					    SXE2_VSI_MAX_CNT, vsi_id);
			if (vsi_id >= SXE2_VSI_MAX_CNT)
				break;
			LOG_DEBUG_BDF("src_id %d, dst_id %d, src_type %d\n", fltr->src_vsi_id,
				      vsi_id, fltr->src_type);
			vsi_id++;
		}
	} else {
		LOG_DEBUG_BDF("src_id %d, dst_id %d, src_type %d\n", fltr->src_vsi_id,
			      fltr->dst_vsi_id, fltr->src_type);
	}

#endif
	return 0;
}

static void sxe2_tcf_fltr_init(struct sxe2_adapter *adapter,
			       struct flow_cls_offload *cls_flower,
			       struct sxe2_tcf_fltr *fltr)
{
	s32 i;

	memset(fltr, 0, sizeof(*fltr));
	for (i = 0; i < SXE2_PROT_FIELD_LAST; i++)
		fltr->items[i].type = i;

	fltr->cookie  = cls_flower->cookie;
	fltr->adapter = adapter;
}

s32 sxe2_tcf_word_cnt_calc(struct sxe2_tcf_fltr *fltr)
{
	u16 i, j;
	struct sxe2_adapter *adapter = fltr->adapter;
	struct sxe2_tcf_key_item *item;

	fltr->word_cnt = 0;
	for (i = 0; i < SXE2_PROT_FIELD_LAST; i++) {
		if (sxe2_tcf_item_is_empty(fltr, i))
			continue;
		item = &fltr->items[i];
		for (j = 0; j < ARRAY_SIZE(item->mask.raw); j++)
			if (item->mask.raw[j])
				fltr->word_cnt++;
	}

	if (fltr->word_cnt > SXE2_MAX_CHAIN_WORDS) {
		LOG_ERROR_BDF("word count %d is bigger than limit %d\n",
			      fltr->word_cnt, SXE2_MAX_CHAIN_WORDS);
		return -EINVAL;
	}

	LOG_DEBUG_BDF("word count %d\n", fltr->word_cnt);
	return 0;
}

static s32 sxe2_tcf_fltr_add(struct sxe2_adapter *adapter,
			     struct net_device *netdev, u16 vsi_id_in_dev,
			     struct flow_cls_offload *cls_flower)
{
	struct sxe2_tcf_fltr *fltr;
	s32 ret	= 0;

	if (!test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags)) {
		LOG_ERROR_BDF("eswitch is not running\n");
		return -EOPNOTSUPP;
	}

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr) {
		LOG_DEV_ERR("alloc memory failed, size %ld\n", sizeof(*fltr));
		return -ENOMEM;
	}

	sxe2_tcf_fltr_init(adapter, cls_flower, fltr);

	ret = sxe2_tcf_action_parse(netdev, cls_flower, fltr);
	if (ret)
		goto l_end;

#if defined(HAVE_TC_FLOWER_ENC) && defined(HAVE_TC_INDIR_BLOCK)
	ret = sxe2_tcf_match_parse(netdev, adapter, cls_flower, fltr);
	if (ret)
		goto l_end;
#endif

	sxe2_tcf_match_meta_fill(fltr);

	ret = sxe2_tcf_word_cnt_calc(fltr);
	if (ret)
		goto l_end;

	ret = sxe2_tcf_profile_find(fltr);
	if (ret)
		goto l_end;
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
	fltr->prio = cls_flower->common.prio;
#endif
	ret = sxe2_tcf_rule_add(adapter, vsi_id_in_dev, fltr);

l_end:
	kfree(fltr);
	return ret;
}

STATIC bool sxe2_tcf_fltr_find_by_cookie(struct sxe2_adapter *adapter,
					 unsigned long cookie, bool del,
					 struct sxe2_rule_info **cplx_rule)
{
	struct list_head *tc_rule_list_head;
	/* in order to protect the data */
	struct mutex *rule_lock;
	struct sxe2_tc_rule_info *tc_list_itr = NULL;
	bool is_find			      = false;
	struct sxe2_tc_rule_hash *rule_hash_node;

	rule_lock = &adapter->switch_ctxt.complex_recipe.rule_lock;

	mutex_lock(rule_lock);
	rule_hash_node = sxe2_hash_cookie_find(adapter, cookie);
	if (!rule_hash_node) {
		is_find = false;
	} else {
		is_find = true;
		if (rule_hash_node->rule_info->tcf_fltr->cookie == cookie) {
			*cplx_rule = rule_hash_node->rule_info;
		} else {
			tc_rule_list_head = &rule_hash_node->rule_info->tc_rule_head;
			list_for_each_entry(tc_list_itr, tc_rule_list_head,
					    list_entry) {
				if (rule_hash_node->rule_info->tcf_fltr &&
				    tc_list_itr->cookie == cookie) {
					if (del) {
						list_del(&tc_list_itr->list_entry);
						hash_del(&rule_hash_node->node);
						kfree(rule_hash_node);
						kfree(tc_list_itr);
					}
					is_find = true;
					break;
				}
			}
		}
	}
	mutex_unlock(rule_lock);

	return is_find;
}

STATIC s32 sxe2_cls_flower_add(struct sxe2_adapter *adapter,
			       struct net_device *netdev, struct sxe2_vsi *vsi,
			       u16 vsi_id_in_dev, struct flow_cls_offload *cls_flower)
{
	struct sxe2_rule_info *save_rule = NULL;
	struct net_device *vsi_netdev;
	bool is_find = false;
	s32 ret;

	if (test_bit(SXE2_FLAG_FW_DCBX_AGENT, adapter->flags))
		return -EINVAL;

	if (sxe2_is_repr_netdev(netdev))
		vsi_netdev = netdev;
	else
		vsi_netdev  = vsi->netdev;

	if (!(vsi_netdev->features & NETIF_F_HW_TC)) {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
		if (netdev == vsi_netdev)
			NL_SET_ERR_MSG_MOD(cls_flower->common.extack,
					   "can't apply TC flower filters, \t"
					   "turn ON hw-tc-offload and try again");
#endif
		ret = -EINVAL;
		goto l_end;
	}

	is_find = sxe2_tcf_fltr_find_by_cookie(adapter, cls_flower->cookie,
					       false, &save_rule);
	if (is_find) {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
		if (save_rule) {
			NL_SET_ERR_MSG_MOD(cls_flower->common.extack,
					   "filter cookie already exists, ignoring");
		} else {
			NL_SET_ERR_MSG_MOD(cls_flower->common.extack,
					   "filter cookie already exists on backuplist, ignoring");
		}
#endif
		ret = -EEXIST;
		goto l_end;
	}

	ret = sxe2_tcf_fltr_add(adapter, netdev, vsi_id_in_dev, cls_flower);

l_end:
	return ret;
}

STATIC s32 sxe2_cls_flower_del(struct sxe2_adapter *adapter,
			       struct flow_cls_offload *cls_flower)
{
	struct sxe2_rule_info *save_rule = NULL;
	bool is_find			= false;
	s32 ret				= 0;

	is_find = sxe2_tcf_fltr_find_by_cookie(adapter, cls_flower->cookie,
					       true, &save_rule);
	if (!is_find) {
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
		NL_SET_ERR_MSG_MOD(cls_flower->common.extack, "filter cookie not exists");
#endif
		ret = -EINVAL;
		goto l_end;
	}

	if (!save_rule) {
		ret = 0;
		goto l_end;
	}

	if (!list_empty(&save_rule->tc_rule_head)) {
		ret = sxe2_switch_tc_samerule_del(adapter, save_rule);
		if (ret) {
			LOG_ERROR_BDF("switch tc samerule del failed, ret %d\n",
				      ret);
			goto l_end;
		}
	} else {
		ret = sxe2_fwd_rule_remove(adapter, save_rule, true);
		if (ret)
			LOG_DEV_ERR("cls flower del failed, ret:%d\n", ret);
	}

l_end:
	return ret;
}

s32 sxe2_setup_tc_cls_flower(struct sxe2_netdev_priv *np,
			     struct net_device *filter_dev,
			     struct flow_cls_offload *cls_flower)
{
	struct sxe2_vsi *vsi	     = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	s32 ret			     = 0;

#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
	if (cls_flower->common.chain_index)
		return -EOPNOTSUPP;
#endif

	if (!test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags)) {
		LOG_ERROR_BDF("eswitch is not running\n");
		return -EOPNOTSUPP;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		goto l_unlock;
	}

	if (cls_flower->command == FLOW_CLS_REPLACE)
		ret = sxe2_cls_flower_add(adapter, filter_dev, vsi, vsi->idx_in_dev, cls_flower);
	else if (cls_flower->command == FLOW_CLS_DESTROY)
		ret = sxe2_cls_flower_del(adapter, cls_flower);
	else
		ret = -EINVAL;

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
s32 sxe2_setup_tc_block_cb(enum tc_setup_type type, void *type_data,
			   void *cb_priv)
{
	struct sxe2_netdev_priv *np = (struct sxe2_netdev_priv *)cb_priv;

	if (type == TC_SETUP_CLSFLOWER)
		return sxe2_setup_tc_cls_flower(np, np->vsi->netdev, type_data);

	return -EOPNOTSUPP;
}

s32 sxe2_indr_setup_block_cb(enum tc_setup_type type, void *type_data,
			     void *indr_priv)
{
	struct sxe2_indr_block_priv *priv = indr_priv;
	struct sxe2_netdev_priv *np	  = priv->np;

	if (type == TC_SETUP_CLSFLOWER)
		return sxe2_setup_tc_cls_flower(np, priv->netdev, type_data);

	return -EOPNOTSUPP;
}
#endif
s32 sxe2_repr_setup_tc_cls_flower(struct sxe2_vf_repr *repr,
				  struct flow_cls_offload *cls_flower)
{
	s32 ret			     = 0;
	struct sxe2_adapter *adapter = repr->vf_node->adapter;
	u16 vsi_id_indev;

#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
	if (cls_flower->common.chain_index)
		return -EOPNOTSUPP;
#endif

	if (!test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags)) {
		LOG_ERROR_BDF("eswitch is not running\n");
		return -EOPNOTSUPP;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, adapter->vsi_ctxt.main_vsi->state)) {
		ret = -EBUSY;
		goto l_unlock;
	}

	vsi_id_indev = repr->vf_node->vsi_id[SXE2_VF_TYPE_ETH] - adapter->vsi_ctxt.base_idx_in_dev;

	if (cls_flower->command == FLOW_CLS_REPLACE)
		ret = sxe2_cls_flower_add(adapter, repr->netdev,
					  repr->src_vsi, vsi_id_indev, cls_flower);
	else if (cls_flower->command == FLOW_CLS_DESTROY)
		ret = sxe2_cls_flower_del(adapter, cls_flower);
	else
		ret = -EINVAL;

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
s32 sxe2_repr_setup_tc_block_cb(enum tc_setup_type type, void *type_data,
				void *cb_priv)
{
	struct sxe2_netdev_priv *np = (struct sxe2_netdev_priv *)cb_priv;

	if (type == TC_SETUP_CLSFLOWER)
		return sxe2_repr_setup_tc_cls_flower(np->repr, type_data);

	return -EOPNOTSUPP;
}
#endif

s32 sxe2_eswitch_vf_slow_path_rule_setup(struct sxe2_vf_node *vf_node,
					 bool is_user, bool is_add)
{
	struct sxe2_tcf_fltr *fltr;
	s32 ret	= 0;
	struct sxe2_adapter *adapter = vf_node->adapter;
	u16 qid_in_vsi;
	struct sxe2_vsi *esw_vsi;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr) {
		LOG_DEV_ERR("alloc memory failed, size %ld\n", sizeof(*fltr));
		return -ENOMEM;
	}

	fltr->action	 = SXE2_FWD_TO_Q;
	if (is_user)
		fltr->src_vsi_id = vf_node->vsi_id[SXE2_VF_TYPE_DPDK];
	else
		fltr->src_vsi_id = vf_node->vsi_id[SXE2_VF_TYPE_ETH];

	mutex_lock(&vf_node->repr_cfg_lock);

	if (vf_node->user_repr_valid)
		esw_vsi = adapter->eswitch_ctxt.user_esw_vsi;
	else
		esw_vsi = adapter->eswitch_ctxt.esw_vsi;

	qid_in_vsi	 = vf_node->vf_idx;
	fltr->dst_queue_id = esw_vsi->rxqs.q[qid_in_vsi]->idx_in_pf +
			     adapter->q_ctxt.rxq_base_idx_in_dev;
	fltr->dst_vsi_id = esw_vsi->idx_in_dev;
	fltr->src_type	  = SXE2_SRC_TYPE_TX;
	fltr->tunnel_type = SXE2_TNL_ALL;
	fltr->priority	  = SXE2_SWITCH_RECIPE_PRIO_6;
	fltr->adapter	  = adapter;
	fltr->cookie_invalid = true;

	sxe2_tcf_match_meta_fill(fltr);

	ret = sxe2_tcf_word_cnt_calc(fltr);
	if (ret)
		goto l_end;

	ret = sxe2_tcf_profile_find(fltr);
	if (ret)
		goto l_end;

	ret = is_add ? sxe2_tcf_rule_add(adapter, vf_node->vsi_id[SXE2_VF_TYPE_ETH], fltr) :
		       sxe2_tcf_rule_del(adapter, vf_node->vsi_id[SXE2_VF_TYPE_ETH], fltr);
	LOG_DEBUG_BDF("slowpath rule %s %s, src vsi %u, dst vsi %u, \t"
		      "queue in vsi %u, queue in dev %u\n",
		      is_add ? "add" : "del", ret ? "failed" : "success",
		      fltr->src_vsi_id, esw_vsi->idx_in_dev, qid_in_vsi, fltr->dst_queue_id);

l_end:
	mutex_unlock(&vf_node->repr_cfg_lock);
	kfree(fltr);
	return ret;
}

s32 sxe2_bond_single_rule_setup(struct sxe2_adapter *adapter, bool is_add)
{
	struct sxe2_tcf_fltr *fltr;
	s32 ret = 0;
	struct sxe2_tcf_key_item *item;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr) {
		LOG_DEV_ERR("alloc memory failed, size %ld\n", sizeof(*fltr));
		return -ENOMEM;
	}

	fltr->action	  = SXE2_LARGE_ACTION;
	fltr->src_vsi_id  = adapter->vsi_ctxt.main_vsi->idx_in_dev;
	fltr->dst_vsi_id = adapter->vsi_ctxt.main_vsi->idx_in_dev;
	fltr->src_type	  = SXE2_SRC_TYPE_RX;
	fltr->tunnel_type = SXE2_TNL_ALL;
	fltr->priority	  = SXE2_SWITCH_RECIPE_PRIO_7;
	fltr->adapter	  = adapter;
	fltr->cookie_invalid = true;

	item = &fltr->items[SXE2_META_PKT_TO_RDMA];
	item->value.raw[SXE2_META_PKT_TO_RDMA_OFFSET] =
		cpu_to_be16((u16)(SXE2_FV_PKT_TO_RDMA << SXE2_FV_PKT_TO_RDMA_OFFSET));
	item->mask.raw[SXE2_META_PKT_TO_RDMA_OFFSET] =
		cpu_to_be16((u16)SXE2_FV_PKT_TO_RDMA_MASK);

	sxe2_tcf_match_meta_fill(fltr);

	ret = sxe2_tcf_word_cnt_calc(fltr);
	if (ret)
		goto l_end;

	ret = sxe2_tcf_profile_find(fltr);
	if (ret)
		goto l_end;

	ret = is_add ? sxe2_tcf_rule_add(adapter, adapter->vsi_ctxt.main_vsi->idx_in_dev, fltr) :
		       sxe2_tcf_rule_del(adapter, adapter->vsi_ctxt.main_vsi->idx_in_dev, fltr);
	if (ret && ret != -EEXIST)
		LOG_ERROR_BDF("bond single rule %s failed, ret %d\n", is_add ? "add" : "del", ret);
	else
		LOG_DEBUG_BDF("bond single rule %s success\n", is_add ? "add" : "del");

l_end:
	kfree(fltr);
	return ret;
}

static s32 sxe2_rdma_mirror_rule_setup(struct sxe2_vsi *vsi, u8 *mac,
				       bool is_rx, bool is_add)
{
	struct sxe2_tcf_fltr *fltr;
	s32 ret = 0;
	struct sxe2_tcf_key_item *item;
	struct sxe2_adapter *adapter = vsi->adapter;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr) {
		LOG_DEV_ERR("alloc memory failed, size %ld\n", sizeof(*fltr));
		return -ENOMEM;
	}

	fltr->action	  = SXE2_MIRROR_PACKET;
	fltr->src_vsi_id  = vsi->idx_in_dev;
	fltr->dst_vsi_id = vsi->idx_in_dev;
	fltr->src_type	  = is_rx ? SXE2_SRC_TYPE_RX : SXE2_SRC_TYPE_TX;
	fltr->tunnel_type = SXE2_TNL_ALL;
	fltr->priority	  = SXE2_SWITCH_RECIPE_PRIO_7;
	fltr->adapter	  = adapter;
	fltr->cookie_invalid = true;

	item = &fltr->items[SXE2_META_PKT_TO_RDMA];
	item->value.raw[SXE2_META_PKT_TO_RDMA_OFFSET] =
		cpu_to_be16((u16)(SXE2_FV_PKT_TO_RDMA << SXE2_FV_PKT_TO_RDMA_OFFSET));
	item->mask.raw[SXE2_META_PKT_TO_RDMA_OFFSET] = cpu_to_be16((u16)SXE2_FV_PKT_TO_RDMA_MASK);

	if (is_rx) {
		item = &fltr->items[SXE2_OUTER_DMAC];
		ether_addr_copy(item->value.hdr.eth_hdr.dst_addr, mac);
		eth_broadcast_addr(item->mask.hdr.eth_hdr.dst_addr);
	} else {
		item = &fltr->items[SXE2_OUTER_SMAC];
		ether_addr_copy(item->value.hdr.eth_hdr.src_addr, mac);
		eth_broadcast_addr(item->mask.hdr.eth_hdr.src_addr);
	}

	item = &fltr->items[SXE2_META_PKT_DIRECTION];
	if (is_rx) {
		item->value.raw[SXE2_META_PKT_DIRECTION_OFFSET] =
			cpu_to_be16((u16)(SXE2_FV_DIRECTION_RX << SXE2_FV_DIRECTION_OFFSET));
	} else {
		item->value.raw[SXE2_META_PKT_DIRECTION_OFFSET] =
			cpu_to_be16((u16)(SXE2_FV_DIRECTION_TX << SXE2_FV_DIRECTION_OFFSET));
	}
	item->mask.raw[SXE2_META_PKT_DIRECTION_OFFSET] = cpu_to_be16((u16)SXE2_FV_DIRECTION_MASK);

	ret = sxe2_tcf_word_cnt_calc(fltr);
	if (ret)
		goto l_end;

	ret = sxe2_tcf_profile_find(fltr);
	if (ret)
		goto l_end;

	ret = is_add ? sxe2_tcf_rule_add(adapter, vsi->idx_in_dev, fltr) :
		       sxe2_tcf_rule_del(adapter, vsi->idx_in_dev, fltr);
	if (ret && ret != -EEXIST) {
		LOG_ERROR_BDF("rdma rx mirror rule %s failed, ret %d\n",
			      is_add ? "add" : "del", ret);
	} else {
		LOG_DEBUG_BDF("rdma rx mirror rule %s success\n",
			      is_add ? "add" : "del");
	}

l_end:
	kfree(fltr);
	return ret;
}

s32 sxe2_rdma_dump_pcap_setup(struct sxe2_vsi *vsi, u8 *mac, bool is_add)
{
	s32 ret = 0;

	ret = sxe2_rdma_mirror_rule_setup(vsi, mac, true, is_add);
	if (ret)
		goto l_end;

	ret = sxe2_rdma_mirror_rule_setup(vsi, mac, false, is_add);
	if (ret)
		(void)sxe2_rdma_mirror_rule_setup(vsi, mac, true, !is_add);

l_end:
	return ret;
}

s32 sxe2_eswitch_vf_slow_path_rule_update(struct sxe2_adapter *adapter,
					  u16 vsi_id, struct sxe2_vf_repr_cfg *repr_cfg)
{
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	/* in order to protect the data */
	struct mutex *rule_lock;
	/* in order to protect the data */
	struct mutex *vsi_list_lock;
	s32 ret = 0;
	struct sxe2_tcf_fltr *tcf_fltr;
	u32 bkt;
	struct hlist_node *temp;
	struct sxe2_rule_info *rule_info;

	rule_lock     = &switch_ctxt->complex_recipe.rule_lock;
	vsi_list_lock = &switch_ctxt->vsi_list_mgmt[SXE2_VSI_LIST_TYPE_FORWARD].vsi_list_lock;

	mutex_lock(rule_lock);
	mutex_lock(vsi_list_lock);
	hash_for_each_safe(adapter->switch_ctxt.complex_recipe.ht_lkup, bkt, temp, tcf_fltr, node) {
		if (tcf_fltr->src_vsi_id == vsi_id &&
		    tcf_fltr->action == SXE2_FWD_TO_Q &&
		    !tcf_fltr->is_user_rule) {
			rule_info = tcf_fltr->rule_info;
			if (repr_cfg->cfg_to_user)
				rule_info->tcf_fltr->dst_queue_id = repr_cfg->queue_in_dev_u;
			else
				rule_info->tcf_fltr->dst_queue_id = repr_cfg->queue_in_dev;

			rule_info->act.fwd_id.q_id = rule_info->tcf_fltr->dst_queue_id;
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
