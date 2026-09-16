// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
#include <net/tc_act/tc_ct.h>
#include <net/flow_offload.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_flow_table.h>
#include "nse.h"
#include "nse_tc_lib.h"
#include <net/tc_act/tc_ct.h>

struct nse_ct_ft {
	struct rhash_head node;
	u16 zone;
	/* nf ft is referenced by how many tc flower fltrs with ct action*/
	refcount_t refcount;
	struct nf_flowtable *nf_ft;
	/* ct entry's cookie id is used to hash*/
	struct rhashtable ct_entries_ht;
	struct nse_tc_ct_priv *ct_priv;
};

enum {
	NSE_CT_ENTRY_FLAG_VALID,
};

struct nse_ct_tuple {
	u16 addr_type;
	__be16 n_proto;
	u8 ip_proto;
	struct {
		union {
			__be32 src_v4;
			struct in6_addr src_v6;
		};
		union {
			__be32 dst_v4;
			struct in6_addr dst_v6;
		};
	} ip;
	struct {
		__be16 src;
		__be16 dst;
	} port;

	u16 zone;
};

struct nse_ct_entry {
	struct rhash_head node;
	struct rhash_head tuple_node;
	/*pointer to tuple obj of OS*/
	unsigned long cookie;
	/*not used now ,pointer to conntrack obj of OS, per skb*/
	unsigned long restore_cookie;
	struct nse_ct_tuple tuple;
	struct nse_tc_ct_priv *ct_priv;
	struct nse_tc_flower_fltr *fltr;
	refcount_t refcnt;
	unsigned long flags;
};

static const struct rhashtable_params zone_params = {
	.head_offset = offsetof(struct nse_ct_ft, node),
	.key_offset = offsetof(struct nse_ct_ft, zone),
	.key_len = sizeof(((struct nse_ct_ft *)0)->zone),
	.automatic_shrinking = true,
};

static const struct rhashtable_params ct_ht_params = {
	.head_offset = offsetof(struct nse_ct_entry, node),
	.key_offset = offsetof(struct nse_ct_entry, cookie),
	.key_len = sizeof(((struct nse_ct_entry *)0)->cookie),
	.automatic_shrinking = true,
	.min_size = 16 * 1024,
};

static const struct rhashtable_params tuples_ht_params = {
	.head_offset = offsetof(struct nse_ct_entry, tuple_node),
	.key_offset = offsetof(struct nse_ct_entry, tuple),
	.key_len = sizeof(((struct nse_ct_entry *)0)->tuple),
	.automatic_shrinking = true,
	.min_size = 16 * 1024,
};

/**
 * nse_parse_tc_ct_match - Parse TC flower filter's conntrack match field
 *
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to the VSI
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 */
int
nse_parse_tc_ct_match(struct net_device *filter_dev, struct nse_vsi *vsi,
			    struct flow_cls_offload *cls_flower,
			    struct nse_tc_flower_fltr *fltr)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls_flower);
	bool trk, est, untrk, unest, rpl, unrpl, new, unnew;
	struct flow_dissector_key_ct *mask, *key;
	struct nse_hw *hw = &vsi->back->hw;
	u16 ctstate = 0, ctstate_mask = 0;
	u16 ct_state_on, ct_state_off;
	u16 ct_state, ct_state_mask;
	struct flow_match_ct match;

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CT))
		return 0;

	flow_rule_match_ct(rule, &match);

	key = match.key;
	mask = match.mask;

	ct_state = key->ct_state;
	ct_state_mask = mask->ct_state;

	if (nse_tcam_less && !nse_is_two_lan_ports(hw)) {
		netdev_info(filter_dev,
			"ConnTrack action is unsupported in non-two ports card when tcam_less mode enabled");
		return -EOPNOTSUPP;
	}

	if (ct_state_mask & ~(TCA_FLOWER_KEY_CT_FLAGS_TRACKED |
						TCA_FLOWER_KEY_CT_FLAGS_REPLY |
						TCA_FLOWER_KEY_CT_FLAGS_NEW |
						TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED)) {
		netdev_info(filter_dev,
			"only ct_state trk, est, new and rpl are supported for offload");
		NL_SET_ERR_MSG_MOD(fltr->extack,
			"only ct_state trk, est, new and rpl are supported for offload");
		return -EOPNOTSUPP;
	}

	ct_state_on = ct_state & ct_state_mask;
	ct_state_off = (ct_state & ct_state_mask) ^ ct_state_mask;
	trk = ct_state_on & TCA_FLOWER_KEY_CT_FLAGS_TRACKED;
	new = ct_state_on & TCA_FLOWER_KEY_CT_FLAGS_NEW;
	est = ct_state_on & TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED;
	rpl = ct_state_on & TCA_FLOWER_KEY_CT_FLAGS_REPLY;
	untrk = ct_state_off & TCA_FLOWER_KEY_CT_FLAGS_TRACKED;
	unnew = ct_state_off & TCA_FLOWER_KEY_CT_FLAGS_NEW;
	unest = ct_state_off & TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED;
	unrpl = ct_state_off & TCA_FLOWER_KEY_CT_FLAGS_REPLY;
	ctstate |= trk ? NSE_CT_STATE_TRK_BIT : 0;
	ctstate |= new ? NSE_CT_STATE_NEW_BIT : 0;
	ctstate |= est ? NSE_CT_STATE_ESTABLISHED_BIT : 0;
	ctstate |= rpl ? NSE_CT_STATE_REPLY_BIT : 0;
	ctstate_mask |= (untrk || trk) ? NSE_CT_STATE_TRK_BIT : 0;
	ctstate_mask |= (unnew || new) ? NSE_CT_STATE_NEW_BIT : 0;
	ctstate_mask |= (unest || est) ? NSE_CT_STATE_ESTABLISHED_BIT : 0;
	ctstate_mask |= (unrpl || rpl) ? NSE_CT_STATE_REPLY_BIT : 0;

	fltr->flags |= NSE_TC_FLWR_FIELD_CT_STATE;
	fltr->ct_state = ctstate;
	fltr->ct_state_mask = ctstate_mask;

	netdev_info(filter_dev, "Start to set ct_state match:\n");
	netdev_info(filter_dev, "\t ct_state value(0x%x)/mask(0x%x)\n",
		ctstate, ctstate_mask);

	return 0;
}

/**
 * nse_tc_ct_entry_valid -
 *
 *	is this ct entry valid or not
 *
 * @entry: nse ct entry obj
 */
static bool
nse_tc_ct_entry_valid(struct nse_ct_entry *entry)
{
	return test_bit(NSE_CT_ENTRY_FLAG_VALID, &entry->flags);
}

/**
 * nse_tc_ct_entry_del -
 *
 *	delete a ct entry, and its tc fltr member
 *
 * @entry: nse ct entry obj
 */
static void nse_tc_ct_entry_del(struct nse_ct_entry *entry)
{
	struct nse_tc_ct_priv *ct_priv = entry->ct_priv;

	if (entry->fltr)
		nse_put_tc_fltr(entry->fltr->src_vsi, entry->fltr);

	spin_lock_bh(&ct_priv->ht_lock);
	rhashtable_remove_fast(&ct_priv->ct_tuples_ht, &entry->tuple_node,
			       tuples_ht_params);
	spin_unlock_bh(&ct_priv->ht_lock);

	kfree(entry);
}

/**
 * nse_tc_ct_entry_put -
 *
 *	put ct entry, refcnt will be decreased,
 *      and when refcnt is 0, ct entry will be deleted
 *
 * @entry: nse ct entry obj
 */
static void
nse_tc_ct_entry_put(struct nse_ct_entry *entry)
{
	if (!refcount_dec_and_test(&entry->refcnt))
		return;

	nse_tc_ct_entry_del(entry);
}

/**
 * nse_tc_ct_get_ct_metadata_action -
 *
 *	get a metadata action from tc flower flow rule
 *
 * @flow_rule: flower filter's flow rule information
 */
static struct flow_action_entry *
nse_tc_ct_get_ct_metadata_action(struct flow_rule *flow_rule)
{
	struct flow_action *flow_action = &flow_rule->action;
	struct flow_action_entry *act;
	int i;

	flow_action_for_each(i, act, flow_action) {
		if (act->id == FLOW_ACTION_CT_METADATA)
			return act;
	}

	return NULL;
}

/**
 * nse_tc_ct_rule_to_tuple -
 *
 *	extract tuple content from match fields
 *
 * @tuple: returned tuple object of driver
 * @rule: flower filter information from OS
 *
 */
static int
nse_tc_ct_rule_to_tuple(struct nse_ct_tuple *tuple, struct flow_rule *rule)
{
	struct flow_match_control control;
	struct flow_match_basic basic;

	flow_rule_match_basic(rule, &basic);
	flow_rule_match_control(rule, &control);

	tuple->n_proto = basic.key->n_proto;
	tuple->ip_proto = basic.key->ip_proto;
	tuple->addr_type = control.key->addr_type;

	if (tuple->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);
		tuple->ip.src_v4 = match.key->src;
		tuple->ip.dst_v4 = match.key->dst;
	} else if (tuple->addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_ipv6_addrs(rule, &match);
		tuple->ip.src_v6 = match.key->src;
		tuple->ip.dst_v6 = match.key->dst;
	} else {
		return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);
		switch (tuple->ip_proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			tuple->port.src = match.key->src;
			tuple->port.dst = match.key->dst;
			break;
		default:
			return -EOPNOTSUPP;
		}
	} else {
		return -EOPNOTSUPP;
	}

	return 0;
}

/**
 * nse_tc_ct_parse_match -
 *
 *	parse ct entry's match field
 *
 * @ct_priv: conntrack private information.
 * @rule: flower filter information
 * @fltr: returned tc filter entry
 */
static int
nse_tc_ct_parse_match(struct nse_tc_ct_priv *ct_priv,
			   struct flow_rule *rule,
			   struct nse_tc_flower_fltr *fltr)
{
	struct nse_tc_flower_lyr_2_4_hdrs *headers;
	struct nse_pf *pf = ct_priv->pf;
	u16 n_proto_mask = 0, n_proto_key = 0, addr_type = 0;

	headers = &fltr->outer_headers;
	fltr->tunnel_type = TNL_LAST;

	/* parse match configuration of ethertype and ip protocol type */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);

		n_proto_key = ntohs(match.key->n_proto);
		n_proto_mask = ntohs(match.mask->n_proto);

		if (n_proto_key == ETH_P_ALL || n_proto_key == 0) {
			n_proto_key = 0;
			n_proto_mask = 0;
		} else {
			fltr->flags |= NSE_TC_FLWR_FIELD_ETH_TYPE;
		}
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] Start to set KEY_BASIC match:\n",
				__func__, __LINE__);
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] \t ethernet_type value(0x%x)/mask(0x%x)\n",
				__func__, __LINE__,
				cpu_to_be16(n_proto_key), cpu_to_be16(n_proto_mask));
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] \t ip_type value(0x%x)/mask(0x%x)\n",
				__func__, __LINE__,
				match.key->ip_proto, match.mask->ip_proto);
		headers->l2_key.n_proto = cpu_to_be16(n_proto_key);
		headers->l2_mask.n_proto = cpu_to_be16(n_proto_mask);
		headers->l3_key.ip_proto = match.key->ip_proto;
		headers->l3_mask.ip_proto = match.mask->ip_proto;
	}

	/* parse match configuration of ip address, including ipv4 and ipv6 address */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control match;

		flow_rule_match_control(rule, &match);
		addr_type = match.key->addr_type;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);

		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] Start to set KEY_IPV4_ADDRS match\n",
				__func__, __LINE__);
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] \t ipv4 dst addrs key(%pI4)/mask(%pI4)\n",
				__func__, __LINE__,
				&match.key->dst, &match.mask->dst);
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] \t ipv4 src addrs key(%pI4)/mask(%pI4)\n",
				__func__, __LINE__,
				&match.key->src, &match.mask->src);

		if (nse_tc_set_ipv4(&match, fltr, headers, false))
			return -EINVAL;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_ipv6_addrs(rule, &match);

		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] Start to set KEY_IPV6_ADDRS match\n",
				__func__, __LINE__);
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] \t ipv6 dst addrs key(%pI6c)/mask(%pI6c)\n",
				__func__, __LINE__,
				&match.key->dst, &match.mask->dst);
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] \t ipv6 src addrs key(%pI6c)/mask(%pI6c)\n",
				__func__, __LINE__,
				&match.key->src, &match.mask->src);

		if (nse_tc_set_ipv6(&match, fltr, headers, false))
			return -EINVAL;
	}

	/* parse match configuration of l4 port */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);

		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] Start to set KEY_PORTS match\n",
				__func__, __LINE__);
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] \t ip protocol = 0x%x\n",
				__func__, __LINE__,
				headers->l3_key.ip_proto);
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] \t src port key(0x%x)/mask(0x%x)\n",
				__func__, __LINE__,
				match.key->src, match.mask->src);
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] \t dst port key(0x%x)/mask(0x%x)\n",
				__func__, __LINE__,
				match.key->dst, match.mask->dst);

		if (nse_tc_set_port(&match, fltr, headers, false))
			return -EINVAL;
		switch (headers->l3_key.ip_proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			break;
		default:
			return -EINVAL;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_TCP)) {
		struct flow_match_tcp match;

		flow_rule_match_tcp(rule, &match);

		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] Start to set TCP FLAG match:\n",
				__func__, __LINE__);
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] \t tcp_flag value(0x%x)/mask(0x%x)\n",
				__func__, __LINE__,
				match.key->flags, match.mask->flags);

		headers->l4_key.tcp_flags = match.key->flags;
		headers->l4_mask.tcp_flags = match.mask->flags;

		fltr->flags |= NSE_TC_FLWR_FIELD_TCP_FLAGS;
	}

	fltr->flags &= ~NSE_TC_FLWR_FIELD_IN_PORT;

	return 0;
}

/**
 * nse_tc_ct_parse_action -
 *
 *	parse ct entry's action
 *
 * @ct_priv: conntrack private information.
 * @rule: flower filter information
 * @fltr: returned tc filter entry
 */
static int
nse_tc_ct_parse_action(struct nse_tc_ct_priv *ct_priv,
			   struct flow_rule *rule,
			   struct nse_tc_flower_fltr *fltr)
{
	struct nse_pf *pf = ct_priv->pf;
	struct nse_pedit_headers *hdrs = &fltr->action.hdrs;
	struct nse_tc_flower_action *tc_action = &fltr->action;

	u16 ct_state = 0;
	int err = 0;
	struct flow_action *flow_action = &rule->action;
	struct flow_action_entry *act;
	struct flow_action_entry *meta;
	enum ip_conntrack_info ctinfo;
	struct flow_action_entry tmp_act;
	u32 mask, offset;
	int i;

	meta = nse_tc_ct_get_ct_metadata_action(rule);
	if (!meta)
		return -EOPNOTSUPP;
	ctinfo = meta->ct_metadata.cookie & NFCT_INFOMASK;

	/*goto post ct /ct_state md /count are always set*/
	ct_state |= NSE_CT_STATE_TRK_BIT;
	ct_state |= ctinfo == IP_CT_NEW ? NSE_CT_STATE_NEW_BIT : NSE_CT_STATE_ESTABLISHED_BIT;
	ct_state |= meta->ct_metadata.orig_dir ? 0 : NSE_CT_STATE_REPLY_BIT;
	tc_action->md_num = 1;
	tc_action->md_value[0] = ct_state;
	tc_action->dest_md_id[0] = NSE_CT_STATE_MDID;

	tc_action->dest_chain = NSE_POST_CT_CHAIN_ID;
	tc_action->flags = NSE_TC_FLWR_ACTION_SET_MD | NSE_TC_FLWR_ACTION_COUNT |
							NSE_TC_FLWR_ACTION_GOTO_CHAIN;

	flow_action_for_each(i, act, flow_action) {
		switch (act->id) {
		case FLOW_ACTION_MANGLE:

			tmp_act = *act;
			mask = ~act->mangle.mask;
			offset = act->mangle.offset;
			/* here we do some adapte work,
			 * after that we can call nse_tc_setup_pedit_action
			 */
			if (mask == 0xFFFF) {
				if (offset == 2) {
					tmp_act.mangle.offset = 0;
					/*1: don't care, 0: care*/
					tmp_act.mangle.mask = cpu_to_be32(0xFFFF0000);
					tmp_act.mangle.val = cpu_to_be32(act->mangle.val);
				} else if (offset == 0) {
					tmp_act.mangle.offset = 0;
					tmp_act.mangle.mask = cpu_to_be32(0x0000FFFF);
					tmp_act.mangle.val = cpu_to_be32(act->mangle.val << 16);
				} else {
					dev_err(nse_pf_to_dev(pf),
						"[%s, %d] Failed to get ct mangle value of port nat\n",
							__func__, __LINE__);
					return -EOPNOTSUPP;
				}
			} else if (mask == 0xFFFFFFFF)
				tmp_act.mangle.val = cpu_to_be32(act->mangle.val);
			else {
				dev_err(nse_pf_to_dev(pf),
					"[%s, %d] Failed to get ct mangle value\n",
						__func__, __LINE__);
				return -EOPNOTSUPP;
			}

			err = nse_tc_setup_pedit_action(nse_get_main_vsi(pf)->netdev,
						fltr, &tmp_act, hdrs);
			if (err) {
				dev_err(nse_pf_to_dev(pf),
					"[%s, %d] Failed to parse ct mangle action\n",
						__func__, __LINE__);
				return err;
			}
			break;
		case FLOW_ACTION_CT_METADATA:
			/* Handled earlier */
			continue;
		default:
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

/**
 * nse_tc_ct_entry_add_rules -
 *
 *	parse & add a ct entry to hw, which conntrack state into established
 *
 * @ct_priv: conntrack private information.
 * @flow_rule: flower filter information
 * @entry: returned ct entry
 */
static int
nse_tc_ct_entry_add_rules(struct nse_tc_ct_priv *ct_priv,
			   struct flow_rule *flow_rule,
			   struct nse_ct_entry *entry)
{
	int err = 0;
	struct nse_pf *pf = ct_priv->pf;
	struct nse_tc_flower_fltr *fltr = NULL;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return -ENOMEM;

	nse_tc_fltr_init(nse_get_main_vsi(pf), fltr);
	fltr->chain_id = NSE_CT_CHAIN_ID;

	/*1. parse ct match*/
	err = nse_tc_ct_parse_match(ct_priv, flow_rule, fltr);
	if (err) {
		dev_err(nse_pf_to_dev(pf),
			"[%s, %d] Failed to parse tc ct match, err: %d\n",
				__func__, __LINE__, err);
		goto err;
	}

	/* zone id should be match always*/
	fltr->zone = entry->tuple.zone;
	fltr->flags |= NSE_TC_FLWR_FIELD_ZONE_ID;

	/*2. parse ct action*/
	err = nse_tc_ct_parse_action(ct_priv, flow_rule, fltr);
	if (err) {
		dev_err(nse_pf_to_dev(pf),
			"[%s, %d] Failed to parse tc ct action, err: %d\n",
				__func__, __LINE__, err);
		goto err;
	}

	/*3. add fltr to hw ct table*/
	err = nse_eswitch_add_tc_fltr(nse_get_main_vsi(pf), fltr);
	if (err) {
		dev_err(nse_pf_to_dev(pf),
			"[%s, %d] Failed to add tc ct fltr, err: %d\n",
				__func__, __LINE__, err);
		goto err;
	}

	entry->fltr = fltr;
	return 0;

err:
	nse_put_tc_fltr(fltr->src_vsi, fltr);
	return err;
}

/**
 * nse_tc_ct_block_flow_offload_add -
 *
 *	add a ct entry when conntrack state into established
 *
 * @ft: callback private information stored by driver.
 * @flow: flower filter information
 */
static int
nse_tc_ct_block_flow_offload_add(struct nse_ct_ft *ft,
				  struct flow_cls_offload *flow)
{
	struct flow_rule *flow_rule = flow_cls_offload_flow_rule(flow);
	struct nse_tc_ct_priv *ct_priv = ft->ct_priv;
	struct flow_action_entry *meta_action;
	unsigned long cookie = flow->cookie;
	struct nse_ct_entry *entry;
	struct nse_pf *pf = ct_priv->pf;
	int err = 0;

	meta_action = nse_tc_ct_get_ct_metadata_action(flow_rule);
	if (!meta_action)
		return -EOPNOTSUPP;

	spin_lock_bh(&ct_priv->ht_lock);
	entry = rhashtable_lookup_fast(&ft->ct_entries_ht, &cookie, ct_ht_params);
	if (entry && refcount_inc_not_zero(&entry->refcnt)) {
		spin_unlock_bh(&ct_priv->ht_lock);
		nse_tc_ct_entry_put(entry);
		return -EEXIST;
	}
	spin_unlock_bh(&ct_priv->ht_lock);

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->tuple.zone = ft->zone;
	entry->cookie = flow->cookie;
	entry->restore_cookie = meta_action->ct_metadata.cookie;

	/*initial to 1, then +1 due to get once here*/
	refcount_set(&entry->refcnt, 2);
	entry->ct_priv = ct_priv;

	/* extract tuple content from match fields */
	err = nse_tc_ct_rule_to_tuple(&entry->tuple, flow_rule);
	if (err) {
		dev_err(nse_pf_to_dev(pf),
			"[%s, %d] Failed to get tuple from rule, err: %d\n",
				__func__, __LINE__, err);
		goto err_set_tuple;
	}

	dev_info(nse_pf_to_dev(pf),
		"[%s, %d] Start to add a established ct entry, zone = %d, cookie = %lx\n",
		__func__, __LINE__, entry->tuple.zone, entry->cookie);
	if (entry->tuple.addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] \t tuple is ipv4 type: ip_proto = %d, sip = %pI4, dip = %pI4, sport = %d, dport = %d\n",
			__func__, __LINE__, entry->tuple.ip_proto, &entry->tuple.ip.src_v4,
			&entry->tuple.ip.dst_v4, be16_to_cpu(entry->tuple.port.src),
			be16_to_cpu(entry->tuple.port.dst));
	} else if (entry->tuple.addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] \t tuple is ipv6 type: ip_proto = %d, sip = %pI6c, dip = %pI6c, sport = %d, dport = %d\n",
			__func__, __LINE__, entry->tuple.ip_proto, &entry->tuple.ip.src_v6,
			&entry->tuple.ip.dst_v6, be16_to_cpu(entry->tuple.port.src),
			be16_to_cpu(entry->tuple.port.dst));
	}

	spin_lock_bh(&ct_priv->ht_lock);
	err = rhashtable_lookup_insert_fast(&ft->ct_entries_ht, &entry->node,
					    ct_ht_params);
	if (err) {
		dev_err(nse_pf_to_dev(pf),
			"[%s, %d] Failed to insert into cookie rhashtable, err: %d\n",
				__func__, __LINE__, err);
		goto err_ct_entries_ht;
	}

	err = rhashtable_lookup_insert_fast(&ct_priv->ct_tuples_ht,
					    &entry->tuple_node,
					    tuples_ht_params);
	if (err) {
		dev_warn(nse_pf_to_dev(pf),
			"[%s, %d] Same tuple insert into tuple rhashtable again, err: %d\n",
				__func__, __LINE__, err);
		goto err_ct_tuple_ht;
	}
	spin_unlock_bh(&ct_priv->ht_lock);

	err = nse_tc_ct_entry_add_rules(ct_priv, flow_rule, entry);
	if (err) {
		dev_err(nse_pf_to_dev(pf),
			"[%s, %d] Failed to add ct entry, err: %d\n",
				__func__, __LINE__, err);
		goto err_add_rules;
	}

	set_bit(NSE_CT_ENTRY_FLAG_VALID, &entry->flags);

	/* release current reference here */
	nse_tc_ct_entry_put(entry);
	return 0;

err_add_rules:
	spin_lock_bh(&ct_priv->ht_lock);
	rhashtable_remove_fast(&ct_priv->ct_tuples_ht,
				   &entry->tuple_node,
				   tuples_ht_params);
err_ct_tuple_ht:
	rhashtable_remove_fast(&ft->ct_entries_ht,
				   &entry->node,
				   ct_ht_params);
err_ct_entries_ht:
	spin_unlock_bh(&ct_priv->ht_lock);
err_set_tuple:
	kfree(entry);
	return err;
}

/**
 * nse_tc_ct_block_flow_offload_del -
 *
 *	delete a ct entry when conntrack state into unestablished from established
 *
 * @ft: callback private information stored by driver.
 * @flow: flower filter information
 */
static int
nse_tc_ct_block_flow_offload_del(struct nse_ct_ft *ft,
				  struct flow_cls_offload *flow)
{
	struct nse_tc_ct_priv *ct_priv = ft->ct_priv;
	unsigned long cookie = flow->cookie;
	struct nse_ct_entry *entry;
	struct nse_pf *pf = ct_priv->pf;

	dev_info(nse_pf_to_dev(pf),
		"[%s, %d] Start to del a established ct entry, cookie = %lx\n",
		__func__, __LINE__, cookie);

	spin_lock_bh(&ct_priv->ht_lock);
	entry = rhashtable_lookup_fast(&ft->ct_entries_ht, &cookie, ct_ht_params);
	if (!entry) {
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] ct entry is not existed in hashtable, cookie = %lx\n",
			__func__, __LINE__, cookie);
		spin_unlock_bh(&ct_priv->ht_lock);
		return -ENOENT;
	}

	if (!nse_tc_ct_entry_valid(entry)) {
		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] ct entry is not valid in hashtable, cookie = %lx\n",
			__func__, __LINE__, cookie);
		spin_unlock_bh(&ct_priv->ht_lock);
		return -EINVAL;
	}

	rhashtable_remove_fast(&ft->ct_entries_ht, &entry->node, ct_ht_params);
	spin_unlock_bh(&ct_priv->ht_lock);

	nse_tc_ct_entry_put(entry);

	return 0;
}

/**
 * nse_tc_ct_block_flow_offload_stats -
 *
 *	get statistic a ct entry
 *
 * @ft: callback private information stored by driver.
 * @f: flower filter information
 */
static int
nse_tc_ct_block_flow_offload_stats(struct nse_ct_ft *ft,
				    struct flow_cls_offload *flow)
{
	struct nse_tc_ct_priv *ct_priv = ft->ct_priv;
	unsigned long cookie = flow->cookie;
	struct nse_ct_entry *entry;
	u64 lastuse, packets, bytes;
	struct nse_sw_counter_pair *counter_p;
	struct nse_tc_flower_fltr *fltr = NULL;

	spin_lock_bh(&ct_priv->ht_lock);
	entry = rhashtable_lookup_fast(&ft->ct_entries_ht, &cookie, ct_ht_params);
	if (!entry) {
		spin_unlock_bh(&ct_priv->ht_lock);
		return -ENOENT;
	}

	if (!nse_tc_ct_entry_valid(entry) || !refcount_inc_not_zero(&entry->refcnt)) {
		spin_unlock_bh(&ct_priv->ht_lock);
		goto err;
	}

	spin_unlock_bh(&ct_priv->ht_lock);

	fltr = entry->fltr;
	if (!fltr)
		goto err;

	counter_p = fltr->action.counter_p;
	if (!counter_p)
		goto err;

	nse_fc_query_cached(counter_p, &bytes, &packets, &lastuse);

	flow_stats_update(&flow->stats, bytes, packets, 0, lastuse,
			  FLOW_ACTION_HW_STATS_DELAYED);

	nse_tc_ct_entry_put(entry);
	return 0;

err:
	return -EINVAL;
}

/**
 * nse_tc_ct_block_flow_offload -
 *
 *	callback function,
 *		which will be called by a skb packet with established conntrack state.
 *
 * @type: should be TC_SETUP_CLSFLOWER
 * @type_data: flower filter information
 * @cb_priv: callback private information stored by driver.
 */
static int
nse_tc_ct_block_flow_offload(enum tc_setup_type type, void *type_data,
			      void *cb_priv)
{
	struct flow_cls_offload *f = type_data;
	struct nse_ct_ft *ft = cb_priv;
	struct nse_tc_ct_priv *ct_priv = ft->ct_priv;
	struct nse_pf *pf = ct_priv->pf;
	int err = 0;

	if (type != TC_SETUP_CLSFLOWER)
		return -EOPNOTSUPP;

	if (!nse_is_eswitch_mode_switchdev(pf) || !pf->switchdev.is_running)
		return -EOPNOTSUPP;

	switch (f->command) {
	case FLOW_CLS_REPLACE:
		mutex_lock(&ct_priv->ct_ctrl_lock);
		err = nse_tc_ct_block_flow_offload_add(ft, f);
		mutex_unlock(&ct_priv->ct_ctrl_lock);
		break;
	case FLOW_CLS_DESTROY:
		mutex_lock(&ct_priv->ct_ctrl_lock);
		err = nse_tc_ct_block_flow_offload_del(ft, f);
		mutex_unlock(&ct_priv->ct_ctrl_lock);
		break;
	case FLOW_CLS_STATS:
		err = nse_tc_ct_block_flow_offload_stats(ft, f);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

/**
 * nse_tc_ct_add_ft_cb -
 *			register a callback function to nf flowtable for zone 0.
 *
 * @ct_priv: golbal conntrack private information
 * @zone: zone id of conntrack, nf_ft is per zone
 * @nf_ft: per zone nf flowtable, which is for established ct entry add/del/stats
 */
static struct nse_ct_ft *
nse_tc_ct_add_ft_cb(struct nse_tc_ct_priv *ct_priv, u16 zone,
			struct nf_flowtable *nf_ft)
{
	struct nse_ct_ft *ft = NULL;
	int err = 0;

	ft = rhashtable_lookup_fast(&ct_priv->zone_ht, &zone, zone_params);
	if (ft) {
		refcount_inc(&ft->refcount);
		return ft;
	}

	ft = kzalloc(sizeof(*ft), GFP_KERNEL);
	if (!ft)
		return ERR_PTR(-ENOMEM);

	ft->zone = zone;
	ft->nf_ft = nf_ft;
	ft->ct_priv = ct_priv;
	refcount_set(&ft->refcount, 1);

	/*when ct established offload to hw, cookie id is used to hash*/
	err = rhashtable_init(&ft->ct_entries_ht, &ct_ht_params);
	if (err)
		goto err_init;

	err = rhashtable_insert_fast(&ct_priv->zone_ht, &ft->node,
				     zone_params);
	if (err)
		goto err_insert;

	err = nf_flow_table_offload_add_cb(ft->nf_ft,
					   nse_tc_ct_block_flow_offload, ft);
	if (err)
		goto err_add_cb;

	return ft;

err_add_cb:
	rhashtable_remove_fast(&ct_priv->zone_ht, &ft->node, zone_params);
err_insert:
	rhashtable_destroy(&ft->ct_entries_ht);
err_init:
	kfree(ft);
	return ERR_PTR(err);
}

/**
 * nse_tc_ct_flush_ft_entry -
 *		ct entries in ft need be deleted after nf ft callback is unregistered
 *
 * @ptr: ct entry object
 */
static void
nse_tc_ct_flush_ft_entry(void *ptr, void *arg)
{
	struct nse_ct_entry *entry = ptr;

	nse_tc_ct_entry_put(entry);
}

/**
 * nse_tc_ct_del_ft_cb -
 *			unregister a callback function to nf flowtable for zone 0.
 *
 * @ct_priv: golbal conntrack private information
 * @nf_ft: nf flowtable from ct action, which is for tuple ct entry add/del/stats
 */
static void
nse_tc_ct_del_ft_cb(struct nse_tc_ct_priv *ct_priv, struct nse_ct_ft *ft)
{
	if (!ft || !ct_priv)
		return;

	if (!refcount_dec_and_test(&ft->refcount))
		return;

	/* when ft is not referenced by any pre/post ct fltr,
	 * nf ft callback need be unregistered, and ct entries in ft need be deleted
	 */
	nf_flow_table_offload_del_cb(ft->nf_ft,
				     nse_tc_ct_block_flow_offload, ft);

	rhashtable_remove_fast(&ct_priv->zone_ht, &ft->node, zone_params);

	rhashtable_free_and_destroy(&ft->ct_entries_ht,
				    nse_tc_ct_flush_ft_entry,
				    ct_priv);
	kfree(ft);
}

/**
 * __nse_tc_ct_add_fltr -
 *			add tc flower rule with ct action to HW in switchdev mode.
 *			such rule is splited two filter: pre ct filter and post ct filter.
 *
 * @vsi: source vsi, where this rule add on
 * @fltr: tc flower information after previous parsing
 */
static int
__nse_tc_ct_add_fltr(struct nse_vsi *vsi,	struct nse_tc_flower_fltr *fltr)
{
	struct nse_pf *pf = (struct nse_pf *)vsi->back;
	struct nse_tc_ct_priv *ct_priv = &pf->switchdev.ct_priv;
	struct nse_tc_flower_action *tc_action = &fltr->action;
	struct nse_tc_ct_flow *ct_flow;
	struct nse_ct_ft *ft;
	u32 fte_id = 1;
	int err = 0;

	if (!ct_priv->pf)
		return -EOPNOTSUPP;

	ct_flow = kzalloc(sizeof(*ct_flow), GFP_KERNEL);
	if (!ct_flow)
		return -ENOMEM;

	ct_flow->pre_ct = kzalloc(sizeof(*(ct_flow->pre_ct)), GFP_KERNEL);
	if (!ct_flow->pre_ct)
		goto alloc_pre_err;

	ct_flow->post_ct = kzalloc(sizeof(*(ct_flow->post_ct)), GFP_KERNEL);
	if (!ct_flow->post_ct)
		goto alloc_post_err;

	nse_tc_fltr_init(vsi, ct_flow->post_ct);

	/* 1. register for ct established */
	ft = nse_tc_ct_add_ft_cb(ct_priv, tc_action->zone, tc_action->nf_ft);
	if (IS_ERR(ft)) {
		err = PTR_ERR(ft);
		dev_err(nse_pf_to_dev(pf), "Failed to add ct flowtable callback\n");
		goto register_cb_err;
	}
	ct_flow->ft = ft;

	/* 2. alloc a unique entry id to bind pre ct fltr and post ct fltr */
	err = idr_alloc_u32(&ct_priv->fte_ids, ct_flow, &fte_id,
			    NSE_FTE_ID_MAX, GFP_KERNEL);
	if (err) {
		dev_err(nse_pf_to_dev(pf),
			    "Failed to allocate fte id, err: %d\n", err);
		goto alloc_fte_err;
	}
	ct_flow->fte_id = (u16)fte_id;

	dev_info(nse_pf_to_dev(pf), "Allocated fte id = %d\n", fte_id);

	/* 3. add post ct fltr */
	memcpy(&ct_flow->post_ct->action, &fltr->action,
		sizeof(ct_flow->post_ct->action));
	ct_flow->post_ct->action.flags &= ~NSE_TC_FLWR_ACTION_CT;
	ct_flow->post_ct->action.flags &= ~NSE_TC_FLWR_ACTION_DECAP;

	/*fte id match field*/
	ct_flow->post_ct->flags = NSE_TC_FLWR_FIELD_FTE_ID;
	ct_flow->post_ct->fte_id = ct_flow->fte_id;
	ct_flow->post_ct->chain_id = NSE_POST_CT_CHAIN_ID;
	err = nse_eswitch_add_tc_fltr(vsi, ct_flow->post_ct);
	if (err) {
		dev_err(nse_pf_to_dev(pf),
			    "Failed to add post ct flower, err: %d\n", err);
		goto add_tc_post_fltr_err;
	}

	/* 4. add pre ct fltr */
	memcpy(ct_flow->pre_ct, fltr, sizeof(*(ct_flow->pre_ct)));
	memset(&ct_flow->pre_ct->action, 0, sizeof(ct_flow->pre_ct->action));
	nse_tc_fltr_init(vsi, ct_flow->pre_ct);

	ct_flow->pre_ct->action.md_num = 2;
	ct_flow->pre_ct->action.md_value[0] = ct_flow->fte_id;
	ct_flow->pre_ct->action.dest_md_id[0] = NSE_CT_FTE_ID_MDID;
	ct_flow->pre_ct->action.md_value[1] = fltr->action.zone;
	ct_flow->pre_ct->action.dest_md_id[1] = NSE_CT_ZONE_MDID;

	ct_flow->pre_ct->action.dest_chain = NSE_CT_CHAIN_ID;

	/* Modify the original rule's action to fwd and modify, leave decap */
	ct_flow->pre_ct->action.flags = fltr->action.flags & NSE_TC_FLWR_ACTION_DECAP;
	ct_flow->pre_ct->action.flags |= NSE_TC_FLWR_ACTION_SET_MD |
								NSE_TC_FLWR_ACTION_GOTO_CHAIN;

	err = nse_eswitch_add_tc_fltr(vsi, ct_flow->pre_ct);
	if (err) {
		dev_err(nse_pf_to_dev(pf),
			    "Failed to add pre ct flower, err: %d\n", err);
		goto add_tc_pre_fltr_err;
	}

	/* store ct flow to tc flower fltr*/
	fltr->ct_flow = ct_flow;
	return 0;

add_tc_pre_fltr_err:
	nse_del_tc_fltr(vsi, ct_flow->pre_ct);
add_tc_post_fltr_err:
	nse_del_tc_fltr(vsi, ct_flow->post_ct);
	idr_remove(&ct_priv->fte_ids, ct_flow->fte_id);
alloc_fte_err:
	nse_tc_ct_del_ft_cb(ct_priv, ct_flow->ft);
register_cb_err:
	kfree(ct_flow->post_ct);
alloc_post_err:
	kfree(ct_flow->pre_ct);
alloc_pre_err:
	kfree(ct_flow);
	fltr->ct_flow = NULL;
	return err;
}

/**
 * nse_tc_ct_add_fltr -
 *			add tc flower rule with ct action to HW in switchdev mode.
 * @vsi: source vsi, where this rule add on
 * @fltr: tc flower information after previous parsing
 */
int
nse_tc_ct_add_fltr(struct nse_vsi *vsi, struct nse_tc_flower_fltr *fltr)
{
	struct nse_pf *pf = (struct nse_pf *)vsi->back;
	struct nse_tc_ct_priv *ct_priv = &pf->switchdev.ct_priv;
	struct nse_tc_flower_action *tc_action = &fltr->action;
	bool clear_action = tc_action->ct_action & TCA_CT_ACT_CLEAR;
	int err = 0;

	if (!ct_priv->pf) {
		dev_err(nse_pf_to_dev(pf),
			    "ct action is not supported when ct private is NULL\n");
		return -EOPNOTSUPP;
	}

	dev_info(nse_pf_to_dev(pf),
			"Start to add tc flower fltr with ct action\n");

	mutex_lock(&ct_priv->control_lock);
	if (clear_action) {
		dev_err(nse_pf_to_dev(pf),
			    "clear ct action is not supported\n");
		err = -EOPNOTSUPP;
	} else
		err = __nse_tc_ct_add_fltr(vsi, fltr);
	mutex_unlock(&ct_priv->control_lock);

	return err;
}

/**
 * __nse_tc_ct_delete_fltr -
 *			delete tc flower rule with ct action to HW in switchdev mode.
 *			which has been splited two filter: pre ct fltr and post ct fltr.
 * @vsi: source vsi, where this rule add on
 * @fltr: tc flower information after previous parsing
 */
static void
__nse_tc_ct_delete_fltr(struct nse_vsi *vsi, struct nse_tc_flower_fltr *fltr)
{
	struct nse_tc_ct_flow *ct_flow = fltr->ct_flow;
	struct nse_pf *pf = (struct nse_pf *)vsi->back;
	struct nse_tc_ct_priv *ct_priv = &pf->switchdev.ct_priv;

	/* 1. remove pre ct fltr */
	nse_put_tc_fltr(vsi, ct_flow->pre_ct);

	/* 2. remove post ct fltr */
	nse_put_tc_fltr(vsi, ct_flow->post_ct);

	/* 3. release idr resource */
	idr_remove(&ct_priv->fte_ids, ct_flow->fte_id);

	/* 4. unregister nf ft cb*/
	nse_tc_ct_del_ft_cb(ct_priv, ct_flow->ft);

	kfree(ct_flow);
}

/**
 * nse_tc_ct_del_fltr -
 *			delete tc flower rule with ct action to HW in switchdev mode.
 * @vsi: source vsi, where this rule add on
 * @fltr: tc flower information after previous parsing
 */
void
nse_tc_ct_del_fltr(struct nse_vsi *vsi,	struct nse_tc_flower_fltr *fltr)
{
	struct nse_tc_ct_flow *ct_flow = fltr->ct_flow;
	struct nse_pf *pf = (struct nse_pf *)vsi->back;
	struct nse_tc_ct_priv *ct_priv = &pf->switchdev.ct_priv;

	if (!ct_flow)
		return;

	dev_info(nse_pf_to_dev(pf),
			"Start to delete tc conntrack fltr\n");

	mutex_lock(&ct_priv->control_lock);
	__nse_tc_ct_delete_fltr(vsi, fltr);
	mutex_unlock(&ct_priv->control_lock);
}

/**
 * nse_tc_ct_init - initial conntrack info in switchdev mode
 *
 *	- tuples hash table is used for skb to get conntrack in slowpath
 *
 * @pf: pointer to PF structure
 *
 */
int nse_tc_ct_init(struct nse_pf *pf)
{
	struct nse_tc_ct_priv *ct_priv = &pf->switchdev.ct_priv;

	ct_priv->pf = pf;
	idr_init(&ct_priv->fte_ids);
	spin_lock_init(&ct_priv->ht_lock);
	mutex_init(&ct_priv->control_lock);
	mutex_init(&ct_priv->ct_ctrl_lock);
	rhashtable_init(&ct_priv->zone_ht, &zone_params);
	rhashtable_init(&ct_priv->ct_tuples_ht, &tuples_ht_params);
	return 0;
}

/**
 * nse_tc_ct_init - cleanup conntrack info when disable switchdev mode
 *
 * @pf: pointer to PF structure
 *
 */
int nse_tc_ct_cleanup(struct nse_pf *pf)
{
	struct nse_tc_ct_priv *ct_priv = &pf->switchdev.ct_priv;

	ct_priv->pf = NULL;
	rhashtable_destroy(&ct_priv->zone_ht);
	rhashtable_destroy(&ct_priv->ct_tuples_ht);
	mutex_destroy(&ct_priv->ct_ctrl_lock);
	mutex_destroy(&ct_priv->control_lock);
	idr_destroy(&ct_priv->fte_ids);
	return 0;
}

