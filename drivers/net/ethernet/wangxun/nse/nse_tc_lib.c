// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
#include <net/tc_act/tc_csum.h>
#include <net/tc_act/tc_pedit.h>
#include <net/tc_act/tc_ct.h>
#include <net/psample.h>
#include "nse.h"
#include "nse_tc_lib.h"
#include "nse_lib.h"
#include "nse_fltr.h"
#include "nse_neigh.h"
#include "nse_tc_ct.h"

static int pedit_header_offsets[] = {
	[FLOW_ACT_MANGLE_HDR_TYPE_ETH] = offsetof(struct pedit_headers, eth),
	[FLOW_ACT_MANGLE_HDR_TYPE_IP4] = offsetof(struct pedit_headers, ip4),
	[FLOW_ACT_MANGLE_HDR_TYPE_IP6] = offsetof(struct pedit_headers, ip6),
	[FLOW_ACT_MANGLE_HDR_TYPE_TCP] = offsetof(struct pedit_headers, tcp),
	[FLOW_ACT_MANGLE_HDR_TYPE_UDP] = offsetof(struct pedit_headers, udp),
};

#define pedit_header(_ph, _htype) ((void *)(_ph) + pedit_header_offsets[_htype])

#define PEDIT_TCP_UDP_PORT_MASK	0xffff
#define PEDIT_ETH_DMAC_31_0		0x0
#define PEDIT_ETH_DMAC_47_32_SMAC_15_0	0x4
#define PEDIT_ETH_DMAC_47_32_MASK		0xffff
#define PEDIT_ETH_SMAC_15_0_MASK		0xffff0000

#define PEDIT_ETH_SMAC_47_16		0x8

/**
 * set_pedit_val
 *	- parsing OS pedit actions to nse pedit header
 *
 * @hdr_type: current pedit action's header type
 * @mask: current pedit action's mask (32bits, such as 0xf3000000)
 * @val: current pedit action's value (32bits)
 * @offset: current pedit action's offset (one byte per unit)
 * @hdrs: return nse pedit header after parsing pedit actions.
 */
static int set_pedit_val(u8 hdr_type, u32 mask, u32 val, u32 offset,
			 struct nse_pedit_headers *hdrs)
{
	u32 *curr_pmask, *curr_pval;

	curr_pmask = (u32 *)(pedit_header(&hdrs->masks, hdr_type) + offset);
	curr_pval  = (u32 *)(pedit_header(&hdrs->vals, hdr_type) + offset);

	if (*curr_pmask & mask)  /* disallow acting twice on the same location */
		goto out_err;

	*curr_pmask |= mask;
	*curr_pval  |= (val & mask);

	return 0;

out_err:
	return -EOPNOTSUPP;
}

/**
 * nse_tc_pedit_is_dmac
 *
 * @offset: offset in FLOW_ACT_MANGLE_HDR_TYPE_ETH
 * @mask: mask in FLOW_ACT_MANGLE_HDR_TYPE_ETH
 */
static bool
nse_tc_pedit_is_dmac(u32 offset, u32 mask)
{
	if (offset == PEDIT_ETH_DMAC_31_0)
		return true;
	if (offset == PEDIT_ETH_DMAC_47_32_SMAC_15_0 &&
		(mask & PEDIT_ETH_DMAC_47_32_MASK))
		return true;

	return false;
}

/**
 * nse_tc_pedit_is_smac
 *
 * @offset: offset in FLOW_ACT_MANGLE_HDR_TYPE_ETH
 * @mask: mask in FLOW_ACT_MANGLE_HDR_TYPE_ETH
 */
static bool
nse_tc_pedit_is_smac(u32 offset, u32 mask)
{
	if (offset == PEDIT_ETH_SMAC_47_16)
		return true;
	if (offset == PEDIT_ETH_DMAC_47_32_SMAC_15_0
		&& (mask & PEDIT_ETH_SMAC_15_0_MASK))
		return true;

	return false;
}

/**
 * nse_tc_setup_pedit_action
 *  -this function parse one pedit action,
 *		each action's value is limited to 32 bits.
 *  -such as SMAC header has 48 bits,
 *		two pedit actions will be sent by OS.
 *  -put parsed data to hdrs, which indicate the entire data of pedit.
 *
 * @filter_dev: Pointer to device on which filter is being added
 * @fltr: Pointer to TC flower filter structure
 * @act: Pointer to pedit action information from OS
 * @hdrs: Pointer to entire data of parsed pedit data.
 */
int
nse_tc_setup_pedit_action(struct net_device *filter_dev, struct nse_tc_flower_fltr *fltr,
			     const struct flow_action_entry *act,
			     struct nse_pedit_headers *hdrs)
{
	struct nse_tc_flower_action *tc_action = &fltr->action;
	int err = -EOPNOTSUPP;
	u8 htype;
	u32 mask, val, offset;
	u32 host_mask;

	htype = act->mangle.htype;
	if (htype == FLOW_ACT_MANGLE_UNSPEC) {
		netdev_err(filter_dev, "legacy pedit can't offloaded\n");
		NL_SET_ERR_MSG_MOD(fltr->extack, "legacy pedit can't offloaded");
		goto out_err;
	}

	mask = ~act->mangle.mask;
	val = act->mangle.val;
	offset = act->mangle.offset;

	netdev_info(filter_dev,
		"Current 32bit mangle: type = 0x%x, off = 0x%x, val = 0x%x, mask = 0x%x\n",
		htype, offset, val, mask);

	err = set_pedit_val(htype, mask, val, offset, hdrs);
	if (err) {
		netdev_err(filter_dev, "Failed to set pedit value\n");
		goto out_err;
	}

	hdrs->pedits++;

	tc_action->flags |= NSE_TC_FLWR_ACTION_REWRITE;
	switch (htype) {
/*	case FLOW_ACT_MANGLE_HDR_TYPE_ETH:*/
	case TCA_PEDIT_KEY_EX_HDR_TYPE_ETH:
		if (nse_tc_pedit_is_dmac(offset, mask))
			tc_action->rw_flag |= NSE_SW_REWRITE_L2_DMAC;
		else if (nse_tc_pedit_is_smac(offset, mask))
			tc_action->rw_flag |= NSE_SW_REWRITE_L2_SMAC;
		else if (offset == offsetof(struct vlan_ethhdr, h_vlan_TCI))
			tc_action->rw_flag |= NSE_SW_REWRITE_L2_VLAN_ID;
		else {
			netdev_err(filter_dev, "Unsupport L2 pedit field, offset = %d\n", offset);
			NL_SET_ERR_MSG_MOD(fltr->extack, "Unsupport L2 pedit field");
			err = -EOPNOTSUPP;
			goto out_err;
		}
		break;

/*	case FLOW_ACT_MANGLE_HDR_TYPE_IP4:*/
	case TCA_PEDIT_KEY_EX_HDR_TYPE_IP4:
		if (offset == offsetof(struct iphdr, saddr))
			tc_action->rw_flag |= NSE_SW_REWRITE_L3_SIP_V4;
		else if (offset == offsetof(struct iphdr, daddr))
			tc_action->rw_flag |= NSE_SW_REWRITE_L3_DIP_V4;
		else if (offset == offsetof(struct iphdr, ttl)) {
			struct nse_ipv4_ttl_word *ttl_word_mask;

			ttl_word_mask = (struct nse_ipv4_ttl_word *)&mask;

			if (ttl_word_mask->protocol || ttl_word_mask->check ||
				!ttl_word_mask->ttl) {
				netdev_err(filter_dev,
					"unsupported offload: invalid pedit IPv4 ttl action\n");
				NL_SET_ERR_MSG_MOD(fltr->extack,
					"unsupported offload: invalid pedit IPv4 ttl action");
				return -EOPNOTSUPP;
			}
			tc_action->rw_flag |= NSE_SW_REWRITE_L3_TTL_V4;
		} else if (offset == round_down(offsetof(struct iphdr, tos), 4)) {
			struct iphdr *tos_word_mask;

			tos_word_mask = (struct iphdr *)&mask;

			if (tos_word_mask->version || tos_word_mask->ihl ||
				tos_word_mask->tot_len || !tos_word_mask->tos) {
				netdev_err(filter_dev, "unsupported offload: invalid pedit IPv4 tos action\n");
				NL_SET_ERR_MSG_MOD(fltr->extack,
					"unsupported offload: invalid pedit IPv4 tos action");
				return -EOPNOTSUPP;
			}
			tc_action->rw_flag |= NSE_SW_REWRITE_L3_TOS_V4;
		} else {
			netdev_err(filter_dev,
				   "Unsupport L3 IPV4 pedit offset, offset = %d\n", offset);
			NL_SET_ERR_MSG_MOD(fltr->extack, "Unsupport L3 IPV4 pedit offset");
			err = -EOPNOTSUPP;
			goto out_err;
		}
		break;

/*	case FLOW_ACT_MANGLE_HDR_TYPE_IP6:*/
	case TCA_PEDIT_KEY_EX_HDR_TYPE_IP6:
		if (offset >= offsetof(struct ipv6hdr, saddr) &&
			offset < offsetof(struct ipv6hdr, daddr))
			tc_action->rw_flag |= NSE_SW_REWRITE_L3_SIP_V6;
		else if (offset >= offsetof(struct ipv6hdr, daddr) &&
			offset < offsetof(struct ipv6hdr, daddr) + 16)
			tc_action->rw_flag |= NSE_SW_REWRITE_L3_DIP_V6;
		else if (offset == round_down(offsetof(struct ipv6hdr, hop_limit), 4)) {
			struct nse_ipv6_hop_limit *hl_word_mask;

			hl_word_mask = (struct nse_ipv6_hop_limit *)&mask;

			if (hl_word_mask->nexthdr || hl_word_mask->payload_len ||
				!hl_word_mask->hop_limit) {
				netdev_err(filter_dev,
					"unsupported offload: invalid pedit IPv6 hoplimit action\n");
				NL_SET_ERR_MSG_MOD(fltr->extack,
					"unsupported offload: invalid pedit IPv6 hoplimit action");
				return -EOPNOTSUPP;
			}
			tc_action->rw_flag |= NSE_SW_REWRITE_L3_HLIMIT_V6;

		} else if (offset == 0) {
			struct nse_ipv6hdr_tos *ipv6_tos_mask;

			ipv6_tos_mask = (struct nse_ipv6hdr_tos *)&mask;

			if ((!ipv6_tos_mask->priority_hi && !ipv6_tos_mask->priority_lo) ||
				ipv6_tos_mask->version || ipv6_tos_mask->flow_lbl_hi ||
				ipv6_tos_mask->flow_lbl_lo) {
				netdev_err(filter_dev, "unsupported offload: invalid pedit IPv6 tos action\n");
				NL_SET_ERR_MSG_MOD(fltr->extack,
					"unsupported offload: invalid pedit IPv6 tos action");
				return -EOPNOTSUPP;
			}
			tc_action->rw_flag |= NSE_SW_REWRITE_L3_TOS_V6;
		} else {
			netdev_err(filter_dev,
				   "Unsupport L3 IPV6 pedit offset, offset = %d\n", offset);
			NL_SET_ERR_MSG_MOD(fltr->extack, "Unsupport L3 IPV6 pedit offset");
			err = -EOPNOTSUPP;
			goto out_err;
		}

		break;

	case TCA_PEDIT_KEY_EX_HDR_TYPE_TCP:
	case TCA_PEDIT_KEY_EX_HDR_TYPE_UDP:
		if (offset) {
			netdev_err(filter_dev, "Unsupport L4 pedit offset, offset = %d\n", offset);
			NL_SET_ERR_MSG_MOD(fltr->extack, "Unsupport L4 pedit offset");
			err = -EOPNOTSUPP;
			goto out_err;
		}

		host_mask = be32_to_cpu((__force __be32)mask);
		if (host_mask & PEDIT_TCP_UDP_PORT_MASK)
			tc_action->rw_flag |= NSE_SW_REWRITE_L4_DPORT;
		if ((host_mask >> 16) & PEDIT_TCP_UDP_PORT_MASK)
			tc_action->rw_flag |= NSE_SW_REWRITE_L4_SPORT;
		break;

	default:
		netdev_err(filter_dev, "Mangle header type(0x%x) is unsupportted\n", htype);
		err = -EOPNOTSUPP;
		goto out_err;
	}

	return 0;

out_err:
	return err;
}

/**
 * nse_tc_police_action
 *  -this function parse one police action,
 *
 * @filter_dev: Pointer to device on which filter is being added
 * @fltr: Pointer to TC flower filter structure
 * @act: Pointer to police action information from OS
 */
static int
nse_tc_police_action(struct net_device *filter_dev, struct nse_tc_flower_fltr *fltr,
			     const struct flow_action_entry *act)
{
	struct nse_tc_flower_action *tc_action;
	struct nse_sw_meter_param *params;

	tc_action = &fltr->action;
	params = &tc_action->meter_param;
	if (act->police.rate_bytes_ps) {
		params->mode = NSE_RATE_LIMIT_BPS;
		params->rate = act->police.rate_bytes_ps;
		params->burst = act->police.burst;
	} else if (act->police.rate_pkt_ps) {
		params->mode = NSE_RATE_LIMIT_PPS;
		params->rate = act->police.rate_pkt_ps;
		params->burst = act->police.burst_pkt;
	} else {
		netdev_err(filter_dev, "Tc flower Police Mode is unsupportted\n");
		return -EOPNOTSUPP;
	}
	params->index = act->hw_index;
	tc_action->flags |= NSE_TC_FLWR_ACTION_METER;

	netdev_info(filter_dev,
		"Success to set tc police action: meter idx = %d, mode = %d, rate = %lld, burst = %d\n",
		params->index, params->mode, params->rate, params->burst);

	return 0;
}

/**
 * nse_tc_ct_action
 *  -this function parse ct action,
 *
 * @filter_dev: Pointer to device on which filter is being added
 * @fltr: Pointer to TC flower filter structure
 * @act: Pointer to pedit action information from OS
 */
static int
nse_tc_ct_action(struct net_device *filter_dev, struct nse_tc_flower_fltr *fltr,
			     const struct flow_action_entry *act)
{
	struct nse_tc_flower_action *tc_action;

	tc_action = &fltr->action;

	if (fltr->chain_id) {
		netdev_err(filter_dev, "only chain id 0 is supportted in ct action\n");
		return -EOPNOTSUPP;
	}

	if (act->ct.action & TCA_CT_ACT_CLEAR) {
		netdev_err(filter_dev, "ct clear isn't supportted in ct action\n");
		return -EOPNOTSUPP;
	}

	netdev_info(filter_dev,
		"Success to set tc ct action: zone = 0x%x, ct_action = %d\n",
		act->ct.zone, act->ct.action);

	tc_action->zone = act->ct.zone;
	tc_action->ct_action = act->ct.action;
	tc_action->nf_ft = act->ct.flow_table;
	tc_action->flags |= NSE_TC_FLWR_ACTION_CT;

	return 0;
}

/**
 * nse_tc_vlan_action
 *  -this function parse vlan action,
 *
 * @filter_dev: Pointer to device on which filter is being added
 * @fltr: Pointer to TC flower filter structure
 * @act: Pointer to pedit action information from OS
 */
static int
nse_tc_vlan_action(struct net_device *filter_dev, struct nse_tc_flower_fltr *fltr,
			     const struct flow_action_entry *act)
{
	struct nse_tc_flower_action *tc_action;

	tc_action = &fltr->action;

	switch (act->id) {
	case FLOW_ACTION_VLAN_POP:
		tc_action->flags |= NSE_TC_FLWR_ACTION_VLAN_POP;
		netdev_info(filter_dev,
			"Success to set tc vlan pop action\n");
		break;
	case FLOW_ACTION_VLAN_PUSH:

		netdev_info(filter_dev,
			"Success to set tc vlan push action: Vid = 0x%x, Prio = %d, vlan_proto = 0x%x\n",
			act->vlan.vid, act->vlan.prio, act->vlan.proto);

		tc_action->vlan_vid = act->vlan.vid;
		tc_action->vlan_prio = act->vlan.prio;
		tc_action->vlan_proto = act->vlan.proto;
		if (!tc_action->vlan_proto)
			tc_action->vlan_proto = htons(ETH_P_8021Q);

		tc_action->flags |= NSE_TC_FLWR_ACTION_VLAN_PUSH;
		break;
	default:
		netdev_err(filter_dev, "Vlan tc action(0x%x) is not supportted\n", act->id);
		return -EINVAL;
	}

	return 0;
}

/**
 * add_tc_vlan_rewrite_action
 *  -this function parse vlan rewrite action,
 *
 * @filter_dev: Pointer to device on which filter is being added
 * @fltr: Pointer to TC flower filter structure
 * @act: Pointer to pedit action information from OS
 */
static int
add_tc_vlan_rewrite_action(struct net_device *filter_dev, struct nse_tc_flower_fltr *fltr,
			     const struct flow_action_entry *act, struct nse_pedit_headers *hdrs)
{
	u16 mask16 = NSE_TC_FLOWER_MASK_16;
	u16 val16 = (act->vlan.vid & VLAN_VID_MASK) | (act->vlan.prio << VLAN_PRIO_SHIFT);
	const struct flow_action_entry pedit_act = {
		.id = FLOW_ACTION_MANGLE,
		.mangle.htype = FLOW_ACT_MANGLE_HDR_TYPE_ETH,
		.mangle.offset = offsetof(struct vlan_ethhdr, h_vlan_TCI),
		.mangle.mask = ~(u32)be16_to_cpu(*(__be16 *)&mask16),
		.mangle.val = (u32)be16_to_cpu(*(__be16 *)&val16),
	};

	return nse_tc_setup_pedit_action(filter_dev, fltr, &pedit_act, hdrs);
}

/**
 * nse_tc_tun_get_type - get the tunnel type
 * @tunnel_dev: ptr to tunnel device
 * @rule: ptr to flow_rule
 *
 * This function detects appropriate tunnel_type if specified device is tunnel device
 */
int
nse_tc_tun_get_type(struct net_device *tunnel_dev,
		    struct flow_rule *rule)
{
#if IS_ENABLED(CONFIG_VXLAN)
	if (netif_is_vxlan(tunnel_dev))
		return TNL_VXLAN;
#endif

	return TNL_LAST;
}

/**
 * nse_is_on_same_switch - check both source and dest vsi are on same hw switch.
 *
 * @src_vsi: ptr to source in_port vsi
 * @dest_vsi: ptr to dest in_port vsi
 *
 */
static bool
nse_is_on_same_switch(struct nse_vsi *src_vsi, struct nse_vsi *dest_vsi)
{
	if (!src_vsi || !dest_vsi)
		return false;

	return (src_vsi->port_info->sw_id == dest_vsi->port_info->sw_id);
}

/**
 * nse_is_both_vsi_in_lag - check both source and dest vsi are in hw lag.
 *
 * @src_vsi: ptr to source in_port vsi
 * @dest_vsi: ptr to dest in_port vsi
 *
 */
static bool
nse_is_both_vsi_in_lag(struct nse_vsi *src_vsi, struct nse_vsi *dest_vsi)
{
	struct nse_pf *src_pf = NULL;
	struct nse_pf *dest_pf = NULL;

	if (!src_vsi || !dest_vsi)
		return false;

	src_pf = src_vsi->back;
	dest_pf = dest_vsi->back;

	if (!src_pf || !dest_pf)
		return false;

	return nse_is_pf_in_active_lag(src_pf) &&
				nse_is_pf_in_active_lag(dest_pf);
}

/**
 * nse_is_tunnel_supported - check the tunnel netdev whether support
 * @dev: ptr to tunnel device
 *
 */
static bool
nse_is_tunnel_supported(struct net_device *dev)
{
	return nse_tc_tun_get_type(dev, NULL) != TNL_LAST;
}

/**
 * nse_is_redirect_to_lag - check the target netdev whether to bond or not
 *
 * @vsi: Pointer to source VSI, pf main vsi or vf vsi. (it is pf vsi when virtual netdev)
 * @target_dev: the target netdev that redirect to
 */
static bool
nse_is_redirect_to_lag(struct nse_vsi *vsi,
				struct net_device *target_dev)
{
	bool is_lag = false;
	struct nse_vsi *uplink_vsi = vsi->back->switchdev.uplink_vsi;
	struct net_device *uplink_dev;
	struct net_device *uplink_upper;

	if (!uplink_vsi)
		return false;

	uplink_dev = uplink_vsi->netdev;

	rcu_read_lock();
	uplink_upper = netdev_master_upper_dev_get_rcu(uplink_dev);
	if (uplink_upper && netif_is_lag_master(uplink_upper) &&
				uplink_upper == target_dev) {
		is_lag = true;
	}
	rcu_read_unlock();
	return is_lag;
}
/**
 * nse_dup_tun_info - alloc and copy tunnel info to new memory.
 * @tun_info: ptr to ip tunnel information
 *
 */
struct ip_tunnel_info *nse_dup_tun_info(const struct ip_tunnel_info *tun_info)
{
	size_t tun_size = sizeof(*tun_info) + tun_info->options_len;

	return kmemdup(tun_info, tun_size, GFP_KERNEL);
}

/**
 * nse_tc_setup_redirect_action
 *		- Parse the redirect action for a TC filter in switchdev mode
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to source VSI, pf main vsi or vf vsi. (it is pf vsi when virtual netdev)
 * @fltr: Pointer to TC flower filter structure
 * @target_dev: the target netdev that redirect to
 */
static int
nse_tc_setup_redirect_action(struct net_device *filter_dev, struct nse_vsi *vsi,
				 struct nse_tc_flower_fltr *fltr,
			     struct net_device *target_dev)
{
	struct nse_tc_flower_action	*action	= &fltr->action;
	u16 dest_cnt = action->dest_cnt, i;
	struct nse_vsi *dest_vsi = NULL, *src_vsi = NULL;

	if (dest_cnt >= NSE_MAX_FLOW_FWD_DEST) {
		netdev_err(filter_dev, "num of redirect actions up to max limit\n");
		return -EOPNOTSUPP;
	}

	/* process encap first*/
	if (nse_is_tunnel_supported(target_dev)) {
		action->dests[dest_cnt].dest_vsi = vsi->back->switchdev.uplink_vsi;
		action->lan_en = 1;
		action->dest_cnt++;
		return 0;
	}

#if IS_ENABLED(CONFIG_NET_DEVLINK)
	{
		struct netdev_phys_item_id a_id = { };
		int err = 0;

		err = dev_get_port_parent_id(filter_dev, &a_id, true);
		netdev_info(filter_dev, "err = %d, its parent id len = %d\n", err, a_id.id_len);
		print_hex_dump(KERN_INFO, "\t", DUMP_PREFIX_ADDRESS,
			16, 1, a_id.id, MAX_PHYS_ITEM_ID_LEN, false);

		err = dev_get_port_parent_id(target_dev, &a_id, true);
		netdev_info(target_dev, "err = %d, its parent id len = %d\n", err, a_id.id_len);
		print_hex_dump(KERN_INFO, "\t", DUMP_PREFIX_ADDRESS,
			16, 1, a_id.id, MAX_PHYS_ITEM_ID_LEN, false);
	}

#endif

	if (nse_is_port_repr_netdev(target_dev)) {
		struct nse_repr *repr = nse_netdev_to_repr(target_dev);
		/*dest vsi maybe in other pf*/
		action->dests[dest_cnt].dest_vsi = repr->src_vsi;
	} else if (is_vlan_dev(target_dev) ||
		nse_is_redirect_to_lag(vsi, target_dev)) {
		action->dests[dest_cnt].dest_vsi = vsi->back->switchdev.uplink_vsi;
		action->lan_en = 1;
	} else if (netif_is_nse(target_dev)) {
		struct nse_netdev_priv *np = netdev_priv(target_dev);

		action->dests[dest_cnt].dest_vsi = np->vsi;
		action->lan_en = 1;
	} else {
		netdev_err(filter_dev, "Unsupported target netdevice in switchdev mode\n");
		NL_SET_ERR_MSG_MOD(fltr->extack,
			"Unsupported target netdevice in switchdev mode");
		return -EOPNOTSUPP;
	}

	/* in_port and out_port should be in same hw switch, except hw lag is enabled*/
	src_vsi = vsi;
	dest_vsi = action->dests[dest_cnt].dest_vsi;
	if (!nse_is_both_vsi_in_lag(src_vsi, dest_vsi)) {
		netdev_info(filter_dev,
			"src vsi id = %d, its sw id = %d, dest vsi id = %d, its sw id = %d\n",
			src_vsi->vsi_abs_num, src_vsi->port_info->sw_id,
			dest_vsi->vsi_abs_num, dest_vsi->port_info->sw_id);

		if (!nse_is_on_same_switch(src_vsi, dest_vsi)) {
			netdev_err(filter_dev,
				"devices are not on same hw e-switch, can't offload forwarding\n");
			NL_SET_ERR_MSG_MOD(fltr->extack,
				"devices are not on same hw e-switch, can't offload forwarding");
			return -EOPNOTSUPP;
		}
	}

	/*new out_port should not be same as previous out_ports*/
	for (i = 0; i < dest_cnt; i++) {
		if (action->dests[i].dest_vsi == dest_vsi) {
			netdev_err(filter_dev,
				"can't duplicate output to same device\n");
			NL_SET_ERR_MSG_MOD(fltr->extack,
				"can't duplicate output to same device");
			return -EOPNOTSUPP;
		}
	}

	action->dest_cnt++;
	return 0;
}

/**
 * nse_tc_setup_redirect_action
 *		- Parse the redirect action for a TC filter in switchdev mode
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to source VSI, pf main vsi or vf vsi. (it is pf vsi when virtual netdev)
 * @fltr: Pointer to TC flower filter structure
 * @target_dev: the target netdev that redirect to
 * @tun_info: the ptr to ip tunnel encap information
 */
static int
nse_tc_setup_encap_redirect_action(struct net_device *filter_dev, struct nse_vsi *vsi,
				 struct nse_tc_flower_fltr *fltr,
				 struct net_device *target_dev,
				 const struct ip_tunnel_info *tun_info)
{
	struct nse_tc_flower_action	*action	= &fltr->action;
	int err;

	if (!tun_info) {
		netdev_err(filter_dev, "Tunnel info is NULL when redirect to tunnel\n");
		return -EOPNOTSUPP;
	}
	if (!nse_is_tunnel_supported(target_dev)) {
		netdev_err(filter_dev, "Redirect target netdev(%s) is unsupportted with encap action\n",
			target_dev->name);
		NL_SET_ERR_MSG_MOD(fltr->extack,
			"Target redirect netdev is unsupportted with encap action");
		return -EOPNOTSUPP;
	}

	if (action->encap_cnt >= NSE_MAX_FLOW_ENCAP_CNT) {
		netdev_err(filter_dev, "More tunnel encap actions are not supported\n");
		NL_SET_ERR_MSG_MOD(fltr->extack,
			"More tunnel encap actions are not supported");
		return -EOPNOTSUPP;
	}

	action->encap_cnt++;
	action->dests[action->dest_cnt].flags |= NSE_TC_FLWR_ACTION_DEST_ENCAP_VLD;
	action->dests[action->dest_cnt].tun_info = nse_dup_tun_info(tun_info);
	action->dests[action->dest_cnt].target_dev = target_dev;
	err = nse_tc_setup_redirect_action(filter_dev, vsi, fltr, target_dev);
	if (err) {
		netdev_err(filter_dev, "Failed to set target dev when redirect to dev(%s)\n",
			target_dev->name);
		return err;
	}
	return 0;
}

/**
 * nse_tc_set_pppoe - Parse PPPoE fields from TC flower filter
 * @match: Pointer to flow match structure
 * @fltr: Pointer to filter structure
 * @headers: Pointer to outer header fields
 * @returns PPP protocol used in filter (ppp_ses or ppp_disc)
 */
static u16
nse_tc_set_pppoe(struct flow_match_pppoe *match,
		 struct nse_tc_flower_fltr *fltr,
		 struct nse_tc_flower_lyr_2_4_hdrs *headers)
{
	if (match->mask->session_id) {
		fltr->flags |= NSE_TC_FLWR_FIELD_PPPOE_SESSID;
		headers->pppoe_hdr.session_id = match->key->session_id;
	}

	if (match->mask->ppp_proto) {
		fltr->flags |= NSE_TC_FLWR_FIELD_PPP_PROTO;
		headers->pppoe_hdr.ppp_proto = match->key->ppp_proto;
	}

	return be16_to_cpu(match->key->type);
}

/**
 * nse_tc_set_ipv4 - Parse IPv4 addresses from TC flower filter
 * @match: Pointer to flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true , it is outer header for tunnel IPv4 address
 */
int
nse_tc_set_ipv4(struct flow_match_ipv4_addrs *match,
		struct nse_tc_flower_fltr *fltr,
		struct nse_tc_flower_lyr_2_4_hdrs *headers, bool is_encap)
{
	if (match->mask->dst) {
		if (is_encap)
			fltr->flags |= NSE_TC_FLWR_FIELD_ENC_DEST_IPV4;
		else
			fltr->flags |= NSE_TC_FLWR_FIELD_DEST_IPV4;
		headers->l3_key.dst_ipv4 = match->key->dst;
		headers->l3_mask.dst_ipv4 = match->mask->dst;
	}
	if (match->mask->src) {
		if (is_encap)
			fltr->flags |= NSE_TC_FLWR_FIELD_ENC_SRC_IPV4;
		else
			fltr->flags |= NSE_TC_FLWR_FIELD_SRC_IPV4;
		headers->l3_key.src_ipv4 = match->key->src;
		headers->l3_mask.src_ipv4 = match->mask->src;
	}

	if (is_encap)
		fltr->flow_attr.enc_ipv4_match = 1;
	else
		fltr->flow_attr.ipv4_match = 1;

	return 0;
}

/**
 * nse_tc_set_ipv6 - Parse IPv6 addresses from TC flower filter
 * @match: Pointer to flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true for tunnel IPv6 address
 */
int
nse_tc_set_ipv6(struct flow_match_ipv6_addrs *match,
		struct nse_tc_flower_fltr *fltr,
		struct nse_tc_flower_lyr_2_4_hdrs *headers, bool is_encap)
{
	struct nse_tc_l3_hdr *l3_key, *l3_mask;

	/* src and dest IPV6 address should not be LOOPBACK
	 * (0:0:0:0:0:0:0:1), which can be represented as ::1
	 */
	if (ipv6_addr_loopback(&match->key->dst) ||
	    ipv6_addr_loopback(&match->key->src)) {
		NL_SET_ERR_MSG_MOD(fltr->extack, "Bad IPv6, addr is LOOPBACK");
		return -EINVAL;
	}
	/* if src/dest IPv6 address is *,* error */
	if (ipv6_addr_any(&match->mask->dst) &&
	    ipv6_addr_any(&match->mask->src)) {
		NL_SET_ERR_MSG_MOD(fltr->extack, "Bad src/dest IPv6, addr is any");
		return -EINVAL;
	}
	if (!ipv6_addr_any(&match->mask->dst)) {
		if (is_encap)
			fltr->flags |= NSE_TC_FLWR_FIELD_ENC_DEST_IPV6;
		else
			fltr->flags |= NSE_TC_FLWR_FIELD_DEST_IPV6;
	}
	if (!ipv6_addr_any(&match->mask->src) &&
		!(fltr->flags & NSE_TC_FLWR_FIELD_ENC_DEST_IPV6) &&
		!(fltr->flags & NSE_TC_FLWR_FIELD_DEST_IPV6)) {
		/*don't match ipv6 dst and src addr both, regards as a limitation*/
		if (is_encap)
			fltr->flags |= NSE_TC_FLWR_FIELD_ENC_SRC_IPV6;
		else
			fltr->flags |= NSE_TC_FLWR_FIELD_SRC_IPV6;
	}

	l3_key = &headers->l3_key;
	l3_mask = &headers->l3_mask;

	if (fltr->flags & (NSE_TC_FLWR_FIELD_ENC_SRC_IPV6 |
			   NSE_TC_FLWR_FIELD_SRC_IPV6)) {
		memcpy(&l3_key->src_ipv6_addr, &match->key->src.s6_addr,
		       sizeof(match->key->src.s6_addr));
		memcpy(&l3_mask->src_ipv6_addr, &match->mask->src.s6_addr,
		       sizeof(match->mask->src.s6_addr));
	}
	if (fltr->flags & (NSE_TC_FLWR_FIELD_ENC_DEST_IPV6 |
			   NSE_TC_FLWR_FIELD_DEST_IPV6)) {
		memcpy(&l3_key->dst_ipv6_addr, &match->key->dst.s6_addr,
		       sizeof(match->key->dst.s6_addr));
		memcpy(&l3_mask->dst_ipv6_addr, &match->mask->dst.s6_addr,
		       sizeof(match->mask->dst.s6_addr));
	}

	if (is_encap)
		fltr->flow_attr.enc_ipv6_match = 1;
	else
		fltr->flow_attr.ipv6_match = 1;

	return 0;
}

/**
 * nse_tc_set_port - Parse ports from TC flower filter
 * @match: Flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true for tunnel port
 */
int
nse_tc_set_port(struct flow_match_ports *match,
		struct nse_tc_flower_fltr *fltr,
		struct nse_tc_flower_lyr_2_4_hdrs *headers, bool is_encap)
{
	if (match->mask->dst) {
		if (is_encap)
			fltr->flags |= NSE_TC_FLWR_FIELD_ENC_DEST_L4_PORT;
		else
			fltr->flags |= NSE_TC_FLWR_FIELD_DEST_L4_PORT;
		headers->l4_key.dst_port = match->key->dst;
		headers->l4_mask.dst_port = match->mask->dst;
	}
	if (match->mask->src) {
		if (is_encap)
			fltr->flags |= NSE_TC_FLWR_FIELD_ENC_SRC_L4_PORT;
		else
			fltr->flags |= NSE_TC_FLWR_FIELD_SRC_L4_PORT;
		headers->l4_key.src_port = match->key->src;
		headers->l4_mask.src_port = match->mask->src;
	}
	return 0;
}

/**
 * nse_tc_vxlan_udp_port - Parse and store vxlan udp port info
 * @pf: ptr to PF device
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 *
 *	match of vxlan's dst udp port is MUST required.
 */
static int
nse_tc_vxlan_udp_port(struct nse_pf *pf, struct flow_cls_offload *f,
		struct nse_tc_flower_fltr *fltr,
		struct nse_tc_flower_lyr_2_4_hdrs *headers)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct device *dev = nse_pf_to_dev(pf);
	struct flow_match_ports enc_ports;

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_PORTS)) {
		dev_err(dev, "UDP tunnel decap filter must include enc_dst_port condition\n");
		return -EOPNOTSUPP;
	}

	flow_rule_match_enc_ports(rule, &enc_ports);

	dev_info(dev, "Start to set KEY_ENC_PORTS match\n");
	dev_info(dev, "\t src port key(0x%x)/mask(0x%x)\n",
		enc_ports.key->src, enc_ports.mask->src);
	dev_info(dev, "\t dst port key(0x%x)/mask(0x%x)\n",
		enc_ports.key->dst, enc_ports.mask->dst);

	if (memchr_inv(&enc_ports.mask->dst, 0xff,
		       sizeof(enc_ports.mask->dst))) {
		dev_err(dev, "UDP tunnel decap filter must match enc_dst_port fully\n");
		return -EOPNOTSUPP;
	}

	if (enc_ports.mask->src) {
		dev_err(dev, "UDP tunnel decap filter don't support src port\n");
		return -EOPNOTSUPP;
	}

	/*l3 ip protocol type hard-coded to UDP, and full mask*/
	headers->l3_key.ip_proto = IPPROTO_UDP;
	headers->l3_mask.ip_proto = NSE_TC_FLOWER_MASK_8;

	return 0;
}

/**
 * nse_tc_udp_port_parse - Parse udp ports of tunnel outer header
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to VSI structure
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 */
static int
nse_tc_udp_port_parse(struct net_device *filter_dev, struct nse_vsi *vsi,
		 struct flow_cls_offload *f,
		 struct nse_tc_flower_fltr *fltr,
		 struct nse_tc_flower_lyr_2_4_hdrs *headers)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	enum nse_tunnel_type tunnel_type;
	struct nse_pf *pf = vsi->back;
	struct device *dev;
	int err = 0;

	dev = nse_pf_to_dev(pf);
	tunnel_type = nse_tc_tun_get_type(filter_dev, rule);

	switch (tunnel_type) {
	case TNL_VXLAN:
		err = nse_tc_vxlan_udp_port(pf, f, fltr, headers);
		if (err) {
			dev_err(dev, "Failed to parse vxlan udp port info\n");
			return err;
		}
		break;
	default:
		dev_err(dev, "Tunnel HW offload is not supported for the tunnel type: %d\n",
			tunnel_type);
		return -EOPNOTSUPP;
	}
	return err;
}

/**
 * nse_tc_vxlan_tun_info - Parse and store vxlan tunnel info
 * @pf: ptr to PF device
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 *
 * Parse vxlan tunnel attributes such as tunnel_id and store them.
 */
static int
nse_tc_vxlan_tun_info(struct nse_pf *pf, struct flow_cls_offload *f,
		struct nse_tc_flower_fltr *fltr)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_KEYID)) {
		struct device *dev = nse_pf_to_dev(pf);
		struct flow_match_enc_keyid enc_keyid;
		u32 key_id;

		flow_rule_match_enc_keyid(rule, &enc_keyid);
		if (!enc_keyid.mask->keyid) {
			dev_err(dev, "Bad mask for encap key_id of Vxlan 0x%04x, it must be non-zero\n",
				be32_to_cpu(enc_keyid.mask->keyid));
			return -EINVAL;
		}

		if (enc_keyid.mask->keyid !=
				cpu_to_be32(NSE_TC_FLOWER_MASK_32)) {
			dev_err(dev, "Bad mask value for encap key_id 0x%04x of Vxlan\n",
				be32_to_cpu(enc_keyid.mask->keyid));
			return -EINVAL;
		}

		key_id = be32_to_cpu(enc_keyid.key->keyid);
		/* VNI is only 3 bytes, applicable for VXLAN*/
		if (key_id > NSE_TC_FLOWER_VNI_MAX) {
			dev_err(dev, "Vxlan VNI out of range : 0x%x\n",
				key_id);
			return -EINVAL;
		}

		dev_info(dev, "Match Vxlan VNI ID = 0x%x\n", key_id);

		fltr->flags |= NSE_TC_FLWR_FIELD_TENANT_ID;
		fltr->tenant_id = enc_keyid.key->keyid;
	}

	return 0;
}

/**
 * nse_tc_tun_info_parse - Parse tunnel attributes from TC flower filter
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to VSI structure
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 */
static int
nse_tc_tun_info_parse(struct net_device *filter_dev, struct nse_vsi *vsi,
		 struct flow_cls_offload *f,
		 struct nse_tc_flower_fltr *fltr,
		 struct nse_tc_flower_lyr_2_4_hdrs *headers)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	enum nse_tunnel_type tunnel_type;
	struct nse_pf *pf = vsi->back;
	struct device *dev;
	int err = 0;

	dev = nse_pf_to_dev(pf);
	tunnel_type = nse_tc_tun_get_type(filter_dev, rule);

	switch (tunnel_type) {
	case TNL_VXLAN:
		err = nse_tc_vxlan_tun_info(pf, f, fltr);
		if (err) {
			dev_err(dev, "Failed to parse vxlan tunnel info\n");
			return err;
		}
		break;
	default:
		dev_err(dev, "Tunnel HW offload is not supported for the tunnel type: %d\n",
			tunnel_type);
		return -EOPNOTSUPP;
	}
	fltr->tunnel_type = tunnel_type;
	return err;
}

/**
 * nse_tc_enc_iph_parse - Parse ip header of tunnel outer header
 * @filter_dev: Pointer to device on which filter is being added
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 */
static int
nse_tc_enc_iph_parse(struct net_device *filter_dev,
		 struct flow_cls_offload *f,
		 struct nse_tc_flower_fltr *fltr,
		 struct nse_tc_flower_lyr_2_4_hdrs *headers)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_match_control enc_control;
	int err = 0;

	flow_rule_match_enc_control(rule, &enc_control);

	/* For tunnel addr_type used same key id`s as for non-tunnel */
	if (enc_control.key->addr_type == FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS ||
		enc_control.key->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_enc_ipv4_addrs(rule, &match);

		netdev_info(filter_dev,
			"Start to set KEY_ENC_IPV4_ADDRS match\n");
		netdev_info(filter_dev,
			"\t ipv4 dst addrs key(%pI4)/mask(%pI4)\n",
				&match.key->dst, &match.mask->dst);
		netdev_info(filter_dev,
			"\t ipv4 src addrs key(%pI4)/mask(%pI4)\n",
				&match.key->src, &match.mask->src);

		if (nse_tc_set_ipv4(&match, fltr, headers, true)) {
			netdev_err(filter_dev,
				"Failed to set match: ipv4 addrs of outer enc header\n");
			return -EINVAL;
		}
	} else if (enc_control.key->addr_type ==
					FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS ||
					enc_control.key->addr_type ==
					FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_enc_ipv6_addrs(rule, &match);

		netdev_info(filter_dev,
			"Start to set KEY_ENC_IPV6_ADDRS match\n");
		netdev_info(filter_dev,
			"\t ipv6 dst addrs key(%pI6c)/mask(%pI6c)\n",
				&match.key->dst, &match.mask->dst);
		netdev_info(filter_dev,
			"\t ipv6 src addrs key(%pI6c)/mask(%pI6c)\n",
				&match.key->src, &match.mask->src);

		if (nse_tc_set_ipv6(&match, fltr, headers, true)) {
			netdev_err(filter_dev,
				"Failed to set match: ipv6 addrs of outer enc header\n");
			return -EINVAL;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IP) &&
		(fltr->flow_attr.enc_ipv4_match || fltr->flow_attr.enc_ipv6_match)) {
		struct flow_match_ip match;

		flow_rule_match_enc_ip(rule, &match);

		netdev_info(filter_dev,
			"Start to set KEY_ENC_IP tos/ttl match\n");
		netdev_info(filter_dev,
			"\t ip tos key(0x%x)/mask(0x%x)\n",
				match.key->tos, match.mask->tos);
		netdev_info(filter_dev,
			"\t ip ttl key(0x%x)/mask(0x%x)\n",
				match.key->ttl, match.mask->ttl);

		if (match.mask->tos) {
			fltr->flags |= NSE_TC_FLWR_FIELD_ENC_IP_TOS;
			headers->l3_key.tos = match.key->tos;
			headers->l3_mask.tos = match.mask->tos;
		}

		if (match.mask->ttl) {
			fltr->flags |= NSE_TC_FLWR_FIELD_ENC_IP_TTL;
			headers->l3_key.ttl = match.key->ttl;
			headers->l3_mask.ttl = match.mask->ttl;
		}
	}

	return err;
}

/**
 * nse_parse_tunnel_attr - Parse outer tunnel header matching
 *	from TC flower filter, include l3 ip header/l4 ports/tunnel info
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to VSI structure
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 */
static int
nse_parse_tunnel_attr(struct net_device *filter_dev, struct nse_vsi *vsi,
		      struct flow_cls_offload *f,
		      struct nse_tc_flower_fltr *fltr,
		      struct nse_tc_flower_lyr_2_4_hdrs *headers)
{
	int err;

	err = nse_tc_enc_iph_parse(filter_dev, f, fltr, headers);
	if (err) {
		netdev_err(filter_dev, "Failed to parse ip header of tunnel\n");
		NL_SET_ERR_MSG_MOD(fltr->extack, "Failed to parse ip header of tunnel");
		return err;
	}

	err = nse_tc_udp_port_parse(filter_dev, vsi, f, fltr, headers);
	if (err) {
		netdev_err(filter_dev, "Failed to parse udp port of tunnel\n");
		NL_SET_ERR_MSG_MOD(fltr->extack, "Failed to parse udp port of tunnel");
		return err;
	}

	err = nse_tc_tun_info_parse(filter_dev, vsi, f, fltr, headers);
	if (err) {
		netdev_err(filter_dev, "Failed to parse tunnel info\n");
		NL_SET_ERR_MSG_MOD(fltr->extack, "Failed to parse tunnel info");
		return err;
	}

	return 0;
}

/* Tunnel device follows RFC 6040 4.2, see include/net/inet_ecn.h.
 * And changes inner ip_ecn based on outer ip_ecn as follows:
 *      +---------+----------------------------------------+
 *      |Arriving |         Arriving Outer Header          |
 *      |   Inner +---------+---------+---------+----------+
 *      |  Header | Not-ECT | ECT(0)  | ECT(1)  |   CE     |
 *      +---------+---------+---------+---------+----------+
 *      | Not-ECT | Not-ECT | Not-ECT | Not-ECT | <drop>   |
 *      |  ECT(0) |  ECT(0) | ECT(0)  | ECT(1)  |   CE*    |
 *      |  ECT(1) |  ECT(1) | ECT(1)  | ECT(1)* |   CE*    |
 *      |    CE   |   CE    |  CE     | CE      |   CE     |
 *      +---------+---------+---------+---------+----------+
 *
 * Tc matches on inner after decapsulation on tunnel device, but hw offload matches
 * the inner ip_ecn value before hardware decap action.
 *
 * Cells marked are changed from original inner packet ip_ecn value during decap, and
 * so matching those values on inner ip_ecn before decap will fail.
 *
 * The following helper allows offload when inner ip_ecn won't be changed by outer ip_ecn,
 * except for the outer ip_ecn = CE, where in all cases inner ip_ecn will be changed to CE,
 * and such we can drop the inner ip_ecn=CE match.
 */

static int nse_tc_verify_tunnel_ecn(struct net_device *filter_dev,
			struct nse_tc_flower_fltr *fltr,
			struct flow_cls_offload *f,
			bool *match_inner_ecn)
{
	u8 outer_ecn_mask = 0, outer_ecn_key = 0, inner_ecn_mask = 0, inner_ecn_key = 0;
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_match_ip match;

	*match_inner_ecn = true;

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IP)) {
		flow_rule_match_enc_ip(rule, &match);
		outer_ecn_key = match.key->tos & INET_ECN_MASK;
		outer_ecn_mask = match.mask->tos & INET_ECN_MASK;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
		flow_rule_match_ip(rule, &match);
		inner_ecn_key = match.key->tos & INET_ECN_MASK;
		inner_ecn_mask = match.mask->tos & INET_ECN_MASK;
	}

	if (outer_ecn_mask != 0 && outer_ecn_mask != INET_ECN_MASK) {
		netdev_err(filter_dev, "Partial match on enc_tos ecn bits isn't supported\n");
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "Partial match on enc_tos ecn bits isn't supported");
		return -EOPNOTSUPP;
	}

	if (!outer_ecn_mask) {
		if (!inner_ecn_mask)
			return 0;
		netdev_err(filter_dev,
			"Matching on tos ecn bits without also matching enc_tos ecn bits isn't supported\n");
		NL_SET_ERR_MSG_MOD(fltr->extack,
			       "Matching on tos ecn bits without also matching enc_tos ecn bits isn't supported");
		return -EOPNOTSUPP;
	}

	if (inner_ecn_mask && inner_ecn_mask != INET_ECN_MASK) {
		netdev_err(filter_dev,
			"Partial match on tos ecn bits with match on enc_tos ecn bits isn't supported\n");
		NL_SET_ERR_MSG_MOD(fltr->extack,
			       "Partial match on tos ecn bits with match on enc_tos ecn bits isn't supported");
		return -EOPNOTSUPP;
	}

	if (!inner_ecn_mask)
		return 0;

	/* Both inner and outer have full mask on ecn */
	if (outer_ecn_key == INET_ECN_ECT_1) {
		/* inner ecn might change by DECAP action */
		netdev_err(filter_dev,
			"Match on enc_tos ecn = ECT(1) isn't supported\n");
		NL_SET_ERR_MSG_MOD(fltr->extack, "Match on enc_tos ecn = ECT(1) isn't supported");
		return -EOPNOTSUPP;
	}

	if (outer_ecn_key != INET_ECN_CE)
		return 0;

	if (inner_ecn_key != INET_ECN_CE) {
		/* Can't happen in software, as packet ecn will be changed to CE after decap */
		netdev_err(filter_dev,
			"Match on tos enc_tos ecn = CE while match on tos ecn != CE isn't supported\n");
		NL_SET_ERR_MSG_MOD(fltr->extack,
			       "Match on tos enc_tos ecn = CE while match on tos ecn != CE isn't supported");
		return -EOPNOTSUPP;
	}

	/* outer ecn = CE, inner ecn = CE, as decap will change inner ecn to CE in anycase,
	 * drop match on inner ecn
	 */
	*match_inner_ecn = false;

	return 0;
}

/**
 * nse_tc_count_lkups - determine lookup count for switch filter
 * @flags: TC-flower flags
 * @headers: Pointer to TC flower filter header structure
 * @fltr: Pointer to outer TC filter structure
 *
 * Determine lookup count based on TC flower input for switch filter.
 */
static int
nse_tc_count_lkups(u32 flags, struct nse_tc_flower_lyr_2_4_hdrs *headers,
		   struct nse_tc_flower_fltr *fltr)
{
	int lkups_cnt = 0;

	if (flags & NSE_TC_FLWR_FIELD_IN_PORT)
		lkups_cnt++;

	if (flags & NSE_TC_FLWR_FIELD_CT_STATE)
		lkups_cnt++;

	if (flags & NSE_TC_FLWR_FIELD_FTE_ID)
		lkups_cnt++;

	if (flags & NSE_TC_FLWR_FIELD_ZONE_ID)
		lkups_cnt++;

	if (flags & NSE_TC_FLWR_FIELD_TENANT_ID)
		lkups_cnt++;

	if (flags & NSE_TC_FLWR_FIELD_ENC_DST_MAC)
		lkups_cnt++;

	if (flags & NSE_TC_FLWR_FIELD_ENC_OPTS)
		lkups_cnt++;

	if (flags & (NSE_TC_FLWR_FIELD_ENC_SRC_IPV4 |
		     NSE_TC_FLWR_FIELD_ENC_DEST_IPV4 |
		     NSE_TC_FLWR_FIELD_ENC_SRC_IPV6 |
		     NSE_TC_FLWR_FIELD_ENC_DEST_IPV6))
		lkups_cnt++;

	if (flags & (NSE_TC_FLWR_FIELD_ENC_IP_TOS |
		     NSE_TC_FLWR_FIELD_ENC_IP_TTL))
		lkups_cnt++;

	if (flags & NSE_TC_FLWR_FIELD_ENC_DEST_L4_PORT)
		lkups_cnt++;

	if (flags & NSE_TC_FLWR_FIELD_ETH_TYPE)
		lkups_cnt++;

	/* is MAC fields specified? */
	if (flags & (NSE_TC_FLWR_FIELD_DST_MAC | NSE_TC_FLWR_FIELD_SRC_MAC))
		lkups_cnt++;

	/* is VLAN specified? */
	if (flags & NSE_TC_FLWR_FIELD_VLAN)
		lkups_cnt++;

	/* is CVLAN specified? */
	if (flags & NSE_TC_FLWR_FIELD_CVLAN)
		lkups_cnt++;

	/* are PPPoE options specified? */
	if (flags & (NSE_TC_FLWR_FIELD_PPPOE_SESSID |
		     NSE_TC_FLWR_FIELD_PPP_PROTO))
		lkups_cnt++;

	/* are IPv[4|6] fields specified? */
	if (flags & (NSE_TC_FLWR_FIELD_DEST_IPV4 | NSE_TC_FLWR_FIELD_SRC_IPV4 |
		     NSE_TC_FLWR_FIELD_DEST_IPV6 | NSE_TC_FLWR_FIELD_SRC_IPV6))
		lkups_cnt++;

	if (flags & (NSE_TC_FLWR_FIELD_IP_TOS | NSE_TC_FLWR_FIELD_IP_TTL))
		lkups_cnt++;

	/* is L4 (TCP/UDP/any other L4 protocol fields) specified? */
	if (flags & (NSE_TC_FLWR_FIELD_DEST_L4_PORT |
				NSE_TC_FLWR_FIELD_TCP_FLAGS |
		     NSE_TC_FLWR_FIELD_SRC_L4_PORT))
		lkups_cnt++;

	return lkups_cnt;
}

/**
 * nse_sw_type_from_tunnel - transfer tunnel type
 * @type: tunnel_type
 *
 */
static enum nse_sw_tunnel_type
nse_sw_type_from_tunnel(enum nse_tunnel_type type)
{
	switch (type) {
	case TNL_VXLAN:
		return NSE_SW_TUN_VXLAN;

	default:
		return NSE_NON_TUN;
	}
}

static enum nse_protocol_type nse_proto_type_from_mac(bool inner)
{
	return inner ? NSE_MAC_IL : NSE_MAC_OFOS;
}

static enum nse_protocol_type nse_proto_type_from_etype(bool inner)
{
	return inner ? NSE_ETYPE_IL : NSE_ETYPE_OLOS;
}

static enum nse_protocol_type nse_proto_type_from_ipv4(bool inner)
{
	return inner ? NSE_IPV4_IL : NSE_IPV4_OFOS;
}

static enum nse_protocol_type nse_proto_type_from_ipv6(bool inner)
{
	return inner ? NSE_IPV6_IL : NSE_IPV6_OFOS;
}

static enum nse_protocol_type nse_proto_type_from_l4_port(u16 ip_proto)
{
	switch (ip_proto) {
	case IPPROTO_TCP:
		return NSE_TCP_IL;
	case IPPROTO_UDP:
		return NSE_UDP_ILOS;
	}

	return 0;
}

/**
 * nse_proto_type_from_tunnel - transfer nse_tunnel_type to nse_protocol_type
 * @type: nse_tunnel_type
 *
 */
static enum nse_protocol_type
nse_proto_type_from_tunnel(enum nse_tunnel_type type)
{
	switch (type) {
	case TNL_VXLAN:
		return NSE_VXLAN;
	default:
		return 0;
	}
}

/**
 * nse_tc_fill_tunnel_outer - fill lkup element list of tunnel outer header
 * @flags: TC flower field flags
 * @fltr: pointer to TC flower filter
 * @lkups: list of advance rule elements
 *
 */
static void
nse_tc_fill_tunnel_outer(u32 flags, struct nse_tc_flower_fltr *fltr,
			 struct nse_adv_lkup_elem *lkups, int *idx)
{
	struct nse_tc_flower_lyr_2_4_hdrs *hdr = &fltr->outer_headers;
	int i = *idx;

	if (flags & NSE_TC_FLWR_FIELD_TENANT_ID) {
		u32 tenant_id;

		lkups[i].type = nse_proto_type_from_tunnel(fltr->tunnel_type);
		switch (fltr->tunnel_type) {
		case TNL_VXLAN:
			tenant_id = be32_to_cpu(fltr->tenant_id) << 8;
			lkups[i].h_u.tnl_hdr.vni = cpu_to_be32(tenant_id);
			memcpy(&lkups[i].m_u.tnl_hdr.vni, "\xff\xff\xff\x00", 4);
			i++;
			break;
		default:
			break;
		}
	}

	if (flags & NSE_TC_FLWR_FIELD_ENC_DST_MAC) {
		lkups[i].type = nse_proto_type_from_mac(false);
		ether_addr_copy(lkups[i].h_u.eth_hdr.dst_addr,
				hdr->l2_key.dst_mac);
		ether_addr_copy(lkups[i].m_u.eth_hdr.dst_addr,
				hdr->l2_mask.dst_mac);
		i++;
	}

	if (flags & (NSE_TC_FLWR_FIELD_ENC_SRC_IPV4 |
		     NSE_TC_FLWR_FIELD_ENC_DEST_IPV4)) {
		lkups[i].type = nse_proto_type_from_ipv4(false);

		if (flags & NSE_TC_FLWR_FIELD_ENC_SRC_IPV4) {
			lkups[i].h_u.ipv4_hdr.src_addr = hdr->l3_key.src_ipv4;
			lkups[i].m_u.ipv4_hdr.src_addr = hdr->l3_mask.src_ipv4;
		}
		if (flags & NSE_TC_FLWR_FIELD_ENC_DEST_IPV4) {
			lkups[i].h_u.ipv4_hdr.dst_addr = hdr->l3_key.dst_ipv4;
			lkups[i].m_u.ipv4_hdr.dst_addr = hdr->l3_mask.dst_ipv4;
		}
		i++;
	}

	if (flags & (NSE_TC_FLWR_FIELD_ENC_SRC_IPV6 |
		     NSE_TC_FLWR_FIELD_ENC_DEST_IPV6)) {
		lkups[i].type = nse_proto_type_from_ipv6(false);

		if (flags & NSE_TC_FLWR_FIELD_ENC_SRC_IPV6) {
			memcpy(&lkups[i].h_u.ipv6_hdr.src_addr,
			       &hdr->l3_key.src_ipv6_addr,
			       sizeof(hdr->l3_key.src_ipv6_addr));
			memcpy(&lkups[i].m_u.ipv6_hdr.src_addr,
			       &hdr->l3_mask.src_ipv6_addr,
			       sizeof(hdr->l3_mask.src_ipv6_addr));
		}
		if (flags & NSE_TC_FLWR_FIELD_ENC_DEST_IPV6) {
			memcpy(&lkups[i].h_u.ipv6_hdr.dst_addr,
			       &hdr->l3_key.dst_ipv6_addr,
			       sizeof(hdr->l3_key.dst_ipv6_addr));
			memcpy(&lkups[i].m_u.ipv6_hdr.dst_addr,
			       &hdr->l3_mask.dst_ipv6_addr,
			       sizeof(hdr->l3_mask.dst_ipv6_addr));
		}
		i++;
	}

	if (fltr->flow_attr.enc_ipv4_match &&
		(flags & (NSE_TC_FLWR_FIELD_ENC_IP_TOS |
		      NSE_TC_FLWR_FIELD_ENC_IP_TTL))) {
		lkups[i].type = nse_proto_type_from_ipv4(false);

		if (flags & NSE_TC_FLWR_FIELD_ENC_IP_TOS) {
			lkups[i].h_u.ipv4_hdr.tos = hdr->l3_key.tos;
			lkups[i].m_u.ipv4_hdr.tos = hdr->l3_mask.tos;
		}

		if (flags & NSE_TC_FLWR_FIELD_ENC_IP_TTL) {
			lkups[i].h_u.ipv4_hdr.time_to_live = hdr->l3_key.ttl;
			lkups[i].m_u.ipv4_hdr.time_to_live = hdr->l3_mask.ttl;
		}

		i++;
	}

	if (fltr->flow_attr.enc_ipv6_match &&
	    (flags & (NSE_TC_FLWR_FIELD_ENC_IP_TOS |
		      NSE_TC_FLWR_FIELD_ENC_IP_TTL))) {
		struct nse_ipv6_hdr *hdr_h, *hdr_m;

		hdr_h = &lkups[i].h_u.ipv6_hdr;
		hdr_m = &lkups[i].m_u.ipv6_hdr;
		lkups[i].type = nse_proto_type_from_ipv6(false);

		if (flags & NSE_TC_FLWR_FIELD_ENC_IP_TOS) {
			hdr_h->be_ver_tc_flow =
				htonl((hdr->l3_key.tos <<
				       NSE_IPV6_HDR_TC_OFFSET) &
				      NSE_IPV6_HDR_TC_MASK);
			hdr_m->be_ver_tc_flow =
				htonl((hdr->l3_mask.tos <<
				       NSE_IPV6_HDR_TC_OFFSET) &
				      NSE_IPV6_HDR_TC_MASK);
		}

		if (flags & NSE_TC_FLWR_FIELD_ENC_IP_TTL) {
			hdr_h->hop_limit = hdr->l3_key.ttl;
			hdr_m->hop_limit = hdr->l3_mask.ttl;
		}

		i++;
	}

	if ((flags & NSE_TC_FLWR_FIELD_ENC_DEST_L4_PORT) &&
	    hdr->l3_key.ip_proto == IPPROTO_UDP) {
		lkups[i].type = NSE_UDP_OF;
		lkups[i].h_u.l4_hdr.dst_port = hdr->l4_key.dst_port;
		lkups[i].m_u.l4_hdr.dst_port = hdr->l4_mask.dst_port;
		i++;
	}

	*idx = i;
}

/**
 * nse_tc_fill_rules - fill lkup element list based on TC fltr
 * @flags: TC flower field flags
 * @tc_fltr: pointer to TC flower filter
 * @lkups: list of advance rule elements
 * @node_info: pointer to information about node
 * @l4_proto: pointer to information such as L4 proto type
 *
 * Fill nse_adv_lkup_elem list based on TC flower flags and
 * TC flower headers. This list should be used to add
 * advance filter in hardware.
 */
static int
nse_tc_fill_rules(u32 flags,
		  struct nse_tc_flower_fltr *tc_fltr,
		  struct nse_adv_lkup_elem *lkups,
		  struct nse_adv_node_info *node_info,
		  u16 *l4_proto)
{
	struct nse_tc_flower_lyr_2_4_hdrs *headers = &tc_fltr->outer_headers;
	bool inner = false;
	int i = 0;

	if (flags & NSE_TC_FLWR_FIELD_IN_PORT) {
		lkups[i].type = NSE_IN_PORT;
		lkups[i].h_u.in_port.in_port = cpu_to_be16(node_info->sw_act.in_port);
		lkups[i].m_u.in_port.in_port = cpu_to_be16(NSE_IN_PORT_MASK);
		i++;
	}

	if (flags & NSE_TC_FLWR_FIELD_CT_STATE) {
		lkups[i].type = NSE_CT_STATE;
		lkups[i].h_u.ct_state.ct_state = cpu_to_be16(tc_fltr->ct_state);
		lkups[i].m_u.ct_state.ct_state = cpu_to_be16(tc_fltr->ct_state_mask);
		i++;
	}

	if (flags & NSE_TC_FLWR_FIELD_FTE_ID) {
		lkups[i].type = NSE_FTE_ID;
		lkups[i].h_u.fte_id.fte_id = cpu_to_be16(tc_fltr->fte_id);
		lkups[i].m_u.fte_id.fte_id = cpu_to_be16(0xffff);
		i++;
	}

	if (flags & NSE_TC_FLWR_FIELD_ZONE_ID) {
		lkups[i].type = NSE_ZONE_ID;
		lkups[i].h_u.zone.zone = cpu_to_be16(tc_fltr->zone);
		lkups[i].m_u.zone.zone = cpu_to_be16(0xffff);
		i++;
	}

	node_info->tun_type = nse_sw_type_from_tunnel(tc_fltr->tunnel_type);

	if (tc_fltr->tunnel_type != TNL_LAST) {
		nse_tc_fill_tunnel_outer(flags, tc_fltr, lkups, &i);

		headers = &tc_fltr->inner_headers;
		inner = true;
	}

	if (flags & NSE_TC_FLWR_FIELD_ETH_TYPE) {
		lkups[i].type = nse_proto_type_from_etype(inner);
		lkups[i].h_u.ethertype.ethtype_id = headers->l2_key.n_proto;
		lkups[i].m_u.ethertype.ethtype_id = headers->l2_mask.n_proto;
		i++;
	}

	if (flags & (NSE_TC_FLWR_FIELD_DST_MAC |
		     NSE_TC_FLWR_FIELD_SRC_MAC)) {
		struct nse_tc_l2_hdr *l2_key, *l2_mask;

		l2_key = &headers->l2_key;
		l2_mask = &headers->l2_mask;

		lkups[i].type = nse_proto_type_from_mac(inner);
		if (flags & NSE_TC_FLWR_FIELD_DST_MAC) {
			ether_addr_copy(lkups[i].h_u.eth_hdr.dst_addr,
					l2_key->dst_mac);
			ether_addr_copy(lkups[i].m_u.eth_hdr.dst_addr,
					l2_mask->dst_mac);
		}
		if (flags & NSE_TC_FLWR_FIELD_SRC_MAC) {
			ether_addr_copy(lkups[i].h_u.eth_hdr.src_addr,
					l2_key->src_mac);
			ether_addr_copy(lkups[i].m_u.eth_hdr.src_addr,
					l2_mask->src_mac);
		}
		i++;
	}

	/* copy VLAN info */
	if (flags & NSE_TC_FLWR_FIELD_VLAN) {
		lkups[i].type = NSE_VLAN_OFOS;
		if (flags & NSE_TC_FLWR_FIELD_CVLAN)
			lkups[i].type = NSE_VLAN_EX;
		lkups[i].h_u.vlan_hdr.vlan = headers->vlan_hdr.vlan_id;
		lkups[i].m_u.vlan_hdr.vlan = cpu_to_be16(VLAN_VID_MASK);
		i++;
	}

	if (flags & NSE_TC_FLWR_FIELD_CVLAN) {
		lkups[i].type = NSE_VLAN_IN;
		lkups[i].h_u.vlan_hdr.vlan = headers->cvlan_hdr.vlan_id;
		lkups[i].m_u.vlan_hdr.vlan = cpu_to_be16(VLAN_VID_MASK);
		i++;
	}

	if (flags & (NSE_TC_FLWR_FIELD_PPPOE_SESSID |
		     NSE_TC_FLWR_FIELD_PPP_PROTO)) {
		struct nse_pppoe_hdr *vals, *masks;

		vals = &lkups[i].h_u.pppoe_hdr;
		masks = &lkups[i].m_u.pppoe_hdr;

		lkups[i].type = NSE_PPPOE;

		if (flags & NSE_TC_FLWR_FIELD_PPPOE_SESSID) {
			vals->session_id = headers->pppoe_hdr.session_id;
			masks->session_id = cpu_to_be16(0xFFFF);
		}

		if (flags & NSE_TC_FLWR_FIELD_PPP_PROTO) {
			vals->ppp_prot_id = headers->pppoe_hdr.ppp_proto;
			masks->ppp_prot_id = cpu_to_be16(0xFFFF);
		}

		i++;
	}

	/* copy L3 (IPv[4|6]: src, dest) address */
	if (flags & (NSE_TC_FLWR_FIELD_DEST_IPV4 |
		     NSE_TC_FLWR_FIELD_SRC_IPV4)) {
		struct nse_tc_l3_hdr *l3_key, *l3_mask;

		lkups[i].type = nse_proto_type_from_ipv4(inner);
		l3_key = &headers->l3_key;
		l3_mask = &headers->l3_mask;
		if (flags & NSE_TC_FLWR_FIELD_DEST_IPV4) {
			lkups[i].h_u.ipv4_hdr.dst_addr = l3_key->dst_ipv4;
			lkups[i].m_u.ipv4_hdr.dst_addr = l3_mask->dst_ipv4;
		}
		if (flags & NSE_TC_FLWR_FIELD_SRC_IPV4) {
			lkups[i].h_u.ipv4_hdr.src_addr = l3_key->src_ipv4;
			lkups[i].m_u.ipv4_hdr.src_addr = l3_mask->src_ipv4;
		}
		i++;
	} else if (flags & (NSE_TC_FLWR_FIELD_DEST_IPV6 |
			    NSE_TC_FLWR_FIELD_SRC_IPV6)) {
		struct nse_ipv6_hdr *ipv6_hdr, *ipv6_mask;
		struct nse_tc_l3_hdr *l3_key, *l3_mask;

		lkups[i].type = nse_proto_type_from_ipv6(inner);
		ipv6_hdr = &lkups[i].h_u.ipv6_hdr;
		ipv6_mask = &lkups[i].m_u.ipv6_hdr;
		l3_key = &headers->l3_key;
		l3_mask = &headers->l3_mask;

		if (flags & NSE_TC_FLWR_FIELD_DEST_IPV6) {
			memcpy(&ipv6_hdr->dst_addr, &l3_key->dst_ipv6_addr,
			       sizeof(l3_key->dst_ipv6_addr));
			memcpy(&ipv6_mask->dst_addr, &l3_mask->dst_ipv6_addr,
			       sizeof(l3_mask->dst_ipv6_addr));
		}
		if (flags & NSE_TC_FLWR_FIELD_SRC_IPV6) {
			memcpy(&ipv6_hdr->src_addr, &l3_key->src_ipv6_addr,
			       sizeof(l3_key->src_ipv6_addr));
			memcpy(&ipv6_mask->src_addr, &l3_mask->src_ipv6_addr,
			       sizeof(l3_mask->src_ipv6_addr));
		}
		i++;
	}

	if (headers->l2_key.n_proto == htons(ETH_P_IP) &&
	    (flags & (NSE_TC_FLWR_FIELD_IP_TOS | NSE_TC_FLWR_FIELD_IP_TTL))) {
		lkups[i].type = nse_proto_type_from_ipv4(inner);
		if (flags & NSE_TC_FLWR_FIELD_IP_TOS) {
			lkups[i].h_u.ipv4_hdr.tos = headers->l3_key.tos;
			lkups[i].m_u.ipv4_hdr.tos = headers->l3_mask.tos;
		}

		if (flags & NSE_TC_FLWR_FIELD_IP_TTL) {
			lkups[i].h_u.ipv4_hdr.time_to_live =
				headers->l3_key.ttl;
			lkups[i].m_u.ipv4_hdr.time_to_live =
				headers->l3_mask.ttl;
		}

		i++;
	}

	if (headers->l2_key.n_proto == htons(ETH_P_IPV6) &&
	    (flags & (NSE_TC_FLWR_FIELD_IP_TOS | NSE_TC_FLWR_FIELD_IP_TTL))) {
		struct nse_ipv6_hdr *hdr_h, *hdr_m;

		hdr_h = &lkups[i].h_u.ipv6_hdr;
		hdr_m = &lkups[i].m_u.ipv6_hdr;
		lkups[i].type = nse_proto_type_from_ipv6(inner);
		if (flags & NSE_TC_FLWR_FIELD_IP_TOS) {
			hdr_h->be_ver_tc_flow =
				htonl((headers->l3_key.tos <<
				       NSE_IPV6_HDR_TC_OFFSET) &
				      NSE_IPV6_HDR_TC_MASK);
			hdr_m->be_ver_tc_flow =
				htonl((headers->l3_mask.tos <<
				       NSE_IPV6_HDR_TC_OFFSET) &
				      NSE_IPV6_HDR_TC_MASK);
		}

		if (flags & NSE_TC_FLWR_FIELD_IP_TTL) {
			hdr_h->hop_limit = headers->l3_key.ttl;
			hdr_m->hop_limit = headers->l3_mask.ttl;
		}

		i++;
	}

	/* copy L4 (src, dest) port */
	if (flags & (NSE_TC_FLWR_FIELD_DEST_L4_PORT |
				NSE_TC_FLWR_FIELD_TCP_FLAGS |
		     NSE_TC_FLWR_FIELD_SRC_L4_PORT)) {
		struct nse_tc_l4_hdr *l4_key, *l4_mask;

		lkups[i].type =
			nse_proto_type_from_l4_port(headers->l3_key.ip_proto);
		l4_key = &headers->l4_key;
		l4_mask = &headers->l4_mask;

		if (flags & NSE_TC_FLWR_FIELD_DEST_L4_PORT) {
			lkups[i].h_u.l4_hdr.dst_port = l4_key->dst_port;
			lkups[i].m_u.l4_hdr.dst_port = l4_mask->dst_port;
		}
		if (flags & NSE_TC_FLWR_FIELD_SRC_L4_PORT) {
			lkups[i].h_u.l4_hdr.src_port = l4_key->src_port;
			lkups[i].m_u.l4_hdr.src_port = l4_mask->src_port;
		}
		if (flags & NSE_TC_FLWR_FIELD_TCP_FLAGS) {
			lkups[i].h_u.l4_hdr.tcp.flags = l4_key->tcp_flags;
			lkups[i].m_u.l4_hdr.tcp.flags = l4_mask->tcp_flags;
		}

		i++;
	}

	return i;
}

/**
 * is_repr_vsi_in_dests
 *
 * @action: parsed tc flower action info.
 * @fltr: tc flower information after previous parsing
 */
static bool
is_repr_vsi_in_dests(struct nse_tc_flower_action *action,
		struct nse_vsi *uplink_vsi)
{
	u16 i;
	u16 dest_cnt = action->dest_cnt;

	for (i = 0; i < dest_cnt; i++) {
		if (action->dests[i].dest_vsi != uplink_vsi)
			return true;
	}

	return false;
}

/**
 * nse_is_au_supported -
 * judge whether HW AU can support current actions or not
 *
 * @fltr: current parsed fltr information
 */
static bool
nse_is_au_supported(struct nse_tc_flower_fltr *fltr)
{
	/*todo - @hujiwei*/
	return true;
}

/**
 * nse_is_task_list_needed -
 * judge au task list is needed, according to current fltr actions
 *
 * @act_flags: current fltr actions flag
 */
static bool
nse_is_task_list_needed(u32 act_flags)
{
	return (act_flags & NSE_TC_FLWR_ACTION_REWRITE) ||
		(act_flags & NSE_TC_FLWR_ACTION_VLAN_PUSH) ||
		(act_flags & NSE_TC_FLWR_ACTION_VLAN_POP) ||
#if !NSE_TC_FLWR_COUNT_IN_DU
		(act_flags & NSE_TC_FLWR_ACTION_COUNT) ||
#endif
#if !NSE_TC_FLWR_METER_IN_DU
		(act_flags & NSE_TC_FLWR_ACTION_METER) ||
#endif
#if !NSE_TC_FLWR_FWD_IN_DU
		(act_flags & NSE_TC_FLWR_ACTION_DROP) ||
		(act_flags & NSE_TC_FLWR_ACTION_TO_LAN) ||
		(act_flags & NSE_TC_FLWR_ACTION_FWD_VSI) ||
		(act_flags & NSE_TC_FLWR_ACTION_FWD_VSI_LIST) ||
#endif
		(act_flags & NSE_TC_FLWR_ACTION_DUP) ||
		(act_flags & NSE_TC_FLWR_ACTION_SINGLE_ENCAP) ||
		(act_flags & NSE_TC_FLWR_ACTION_ALLOW);
}

/**
 * nse_calc_au_task_cnt -
 * calculate task count according to actions information
 *
 * @tc_action: current fltr actions information
 */
static u16
nse_calc_au_task_cnt(struct nse_tc_flower_action *tc_action)
{
	u16 task_cnt = 0;
	u32 act_flags = tc_action->flags;
	u32 rw_flags = tc_action->rw_flag;

#if !NSE_TC_FLWR_COUNT_IN_DU
	if (act_flags & NSE_TC_FLWR_ACTION_COUNT)
		task_cnt++;
#endif

#if !NSE_TC_FLWR_METER_IN_DU
	if (act_flags & NSE_TC_FLWR_ACTION_METER)
		task_cnt++;
#endif

#if !NSE_TC_FLWR_FWD_IN_DU
	if ((act_flags & NSE_TC_FLWR_ACTION_DROP) ||
		(act_flags & NSE_TC_FLWR_ACTION_TO_LAN) ||
		(act_flags & NSE_TC_FLWR_ACTION_FWD_VSI) ||
		(act_flags & NSE_TC_FLWR_ACTION_FWD_VSI_LIST))
		task_cnt++;
#endif

	if (act_flags & NSE_TC_FLWR_ACTION_ALLOW)
		task_cnt++;

	if (act_flags & NSE_TC_FLWR_ACTION_VLAN_PUSH)
		task_cnt++;

	if (act_flags & NSE_TC_FLWR_ACTION_VLAN_POP)
		task_cnt++;

	if (act_flags & NSE_TC_FLWR_ACTION_DUP)
		task_cnt++;

	if (act_flags & NSE_TC_FLWR_ACTION_SINGLE_ENCAP)
		task_cnt++;

	if (act_flags & NSE_TC_FLWR_ACTION_REWRITE) {
		if (rw_flags & NSE_SW_REWRITE_L2_DMAC)
			task_cnt++;
		if (rw_flags & NSE_SW_REWRITE_L2_SMAC)
			task_cnt++;
		if (rw_flags & NSE_SW_REWRITE_L2_VLAN_ID)
			task_cnt++;
		if (rw_flags & NSE_SW_REWRITE_L3_TOS_V4)
			task_cnt++;
		if (rw_flags & NSE_SW_REWRITE_L3_TTL_V4)
			task_cnt++;
		if (rw_flags & NSE_SW_REWRITE_L3_DIP_V4)
			task_cnt++;
		if (rw_flags & NSE_SW_REWRITE_L3_SIP_V4)
			task_cnt++;
		if (rw_flags & NSE_SW_REWRITE_L3_TOS_V6)
			task_cnt++;
		if (rw_flags & NSE_SW_REWRITE_L3_HLIMIT_V6)
			task_cnt++;
		if (rw_flags & NSE_SW_REWRITE_L3_DIP_V6)
			task_cnt++;
		if (rw_flags & NSE_SW_REWRITE_L3_SIP_V6)
			task_cnt++;
		if (rw_flags & NSE_SW_REWRITE_L4_DPORT)
			task_cnt++;
		if (rw_flags & NSE_SW_REWRITE_L4_SPORT)
			task_cnt++;
	}

	if (task_cnt > NSE_MAX_AU_TASK_NUM)
		return 0;

	return task_cnt;
}

/**
 * nse_calc_du_data_size -
 * calculate task data size according to actions information
 *
 * @tc_action: current fltr actions information
 */
static u16
nse_calc_du_data_size(struct nse_tc_flower_action *tc_action)
{
	u16 data_size = 0;
	u32 act_flags = tc_action->flags;
	u32 rw_flags = tc_action->rw_flag;

	if (act_flags & NSE_TC_FLWR_ACTION_VLAN_PUSH)
		data_size += NSE_TASK_PUSH_VLAN_DATA_LEN;

#if !NSE_TC_FLWR_COUNT_IN_DU
	if (act_flags & NSE_TC_FLWR_ACTION_COUNT)
		data_size += NSE_TASK_COUNT_DATA_LEN;
#endif

#if !NSE_TC_FLWR_METER_IN_DU
	if (act_flags & NSE_TC_FLWR_ACTION_METER)
		data_size += NSE_TASK_METER_DATA_LEN;
#endif

#if !NSE_TC_FLWR_FWD_IN_DU
	if ((act_flags & NSE_TC_FLWR_ACTION_DROP) ||
		(act_flags & NSE_TC_FLWR_ACTION_TO_LAN) ||
		(act_flags & NSE_TC_FLWR_ACTION_FWD_VSI) ||
		(act_flags & NSE_TC_FLWR_ACTION_FWD_VSI_LIST))
		data_size += NSE_TASK_FWD_DATA_LEN;
#endif

	if (act_flags & NSE_TC_FLWR_ACTION_REWRITE) {
		if (rw_flags & NSE_SW_REWRITE_L2_DMAC)
			data_size += NSE_TASK_REWRITE_MAC_DATA_LEN;
		if (rw_flags & NSE_SW_REWRITE_L2_SMAC)
			data_size += NSE_TASK_REWRITE_MAC_DATA_LEN;
		if (rw_flags & NSE_SW_REWRITE_L2_VLAN_ID)
			data_size += NSE_TASK_REWRITE_VLAN_DATA_LEN;
		if (rw_flags & NSE_SW_REWRITE_L3_TOS_V4)
			data_size += NSE_TASK_REWRITE_TOS_DATA_LEN;
		if (rw_flags & NSE_SW_REWRITE_L3_TTL_V4)
			data_size += NSE_TASK_REWRITE_TTL_DATA_LEN;
		if (rw_flags & NSE_SW_REWRITE_L3_DIP_V4)
			data_size += NSE_TASK_REWRITE_IP_DATA_LEN;
		if (rw_flags & NSE_SW_REWRITE_L3_SIP_V4)
			data_size += NSE_TASK_REWRITE_IP_DATA_LEN;
		if (rw_flags & NSE_SW_REWRITE_L3_TOS_V6)
			data_size += NSE_TASK_REWRITE_TOS_DATA_LEN;
		if (rw_flags & NSE_SW_REWRITE_L3_HLIMIT_V6)
			data_size += NSE_TASK_REWRITE_HLIMIT_DATA_LEN;
		if (rw_flags & NSE_SW_REWRITE_L3_DIP_V6)
			data_size += NSE_TASK_REWRITE_IPV6_DATA_LEN;
		if (rw_flags & NSE_SW_REWRITE_L3_SIP_V6)
			data_size += NSE_TASK_REWRITE_IPV6_DATA_LEN;
		if (rw_flags & NSE_SW_REWRITE_L4_DPORT)
			data_size += NSE_TASK_REWRITE_PORT_DATA_LEN;
		if (rw_flags & NSE_SW_REWRITE_L4_SPORT)
			data_size += NSE_TASK_REWRITE_PORT_DATA_LEN;
	}

	return data_size;
}

#if !NSE_TC_FLWR_FWD_IN_DU

/**
 * nse_fill_au_fwd_info -
 * @fltr: tc flower information after previous parsing.
 * @fwd: fwd encode information.
 */
static int
nse_fill_au_fwd_info(struct nse_tc_flower_fltr *fltr, u16 *fwd)
{
	struct nse_vsi *vsi = fltr->src_vsi;
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_vsi *uplink_vsi = vsi->back->switchdev.uplink_vsi;
	struct nse_tc_flower_action *action = &fltr->action;
	struct nse_vsi *dest_vsi;
	struct nse_vsi_list_map_info *vsi_list_info;
	bool lan_en = false, lb_en = false;
	u16 vsi_handle[NSE_MAX_FLOW_FWD_DEST];
	u16 act = 0, vsi_cnt = 0;
	u16 i, dest_cnt, fwd_id;

	if (fltr->src_vsi != uplink_vsi &&
			action->lan_en)
		lan_en = true;

	if (fltr->src_vsi != uplink_vsi &&
			is_repr_vsi_in_dests(action, uplink_vsi))
		lb_en = true;

	switch (action->fltr_act) {
	case NSE_FWD_TO_VSI:
		dest_vsi = action->dests[0].dest_vsi;
		fwd_id = nse_get_hw_vsi_num(&dest_vsi->back->hw, dest_vsi->idx);

		act |= (fwd_id << NSE_SINGLE_FWD_VSI_ID_S) &
			NSE_SINGLE_FWD_VSI_ID_M;

		act |= (NSE_SINGLE_ACT_TYPE_FWD <<
			NSE_SINGLE_ACT_TYPE_FWD_S) &
			NSE_SINGLE_ACT_TYPE_FWD_M;

		if (lb_en)
			act |= (NSE_SINGLE_FWD_VSI_EN_LB << NSE_SINGLE_FWD_TYPE_S) &
					NSE_SINGLE_FWD_TYPE_M;
		else
			act |= (NSE_SINGLE_FWD_VSI_DIS_LB << NSE_SINGLE_FWD_TYPE_S) &
					NSE_SINGLE_FWD_TYPE_M;

		if (lan_en)
			act &= ~NSE_SINGLE_FWD_LAN_DISABLE;
		else
			act |= NSE_SINGLE_FWD_LAN_DISABLE;

		break;
	case NSE_FWD_TO_VSI_LIST:
		dest_cnt = action->dest_cnt;
		for (i = 0; i < dest_cnt; i++) {
			dest_vsi = action->dests[i].dest_vsi;
			vsi_handle[i] = dest_vsi->idx;
			vsi_cnt++;
		}
		vsi_list_info = nse_sw_get_adv_vlist(hw, &vsi_handle[0], vsi_cnt);
		if (!vsi_list_info) {
			dev_err(nse_hw_to_dev(hw),
				"Failed to get advanced vsi list\n");
			return -EIO;
		}
		fltr->action.vsi_list_id = vsi_list_info->vsi_list_id;
		fltr->action.vsi_list_info = vsi_list_info;

		fwd_id = vsi_list_info->vsi_list_id;
		act |= (fwd_id  << NSE_SINGLE_FWD_VSI_LIST_ID_S) &
			NSE_SINGLE_FWD_VSI_LIST_ID_M;

		/* set action type to fwd */
		act |= (NSE_SINGLE_ACT_TYPE_FWD <<
			NSE_SINGLE_ACT_TYPE_FWD_S) &
			NSE_SINGLE_ACT_TYPE_FWD_M;

		if (lb_en)
			act |= (NSE_SINGLE_FWD_VSI_LIST_EN_LB << NSE_SINGLE_FWD_TYPE_S) &
					NSE_SINGLE_FWD_TYPE_M;
		else
			act |= (NSE_SINGLE_FWD_VSI_LIST_DIS_LB << NSE_SINGLE_FWD_TYPE_S) &
					NSE_SINGLE_FWD_TYPE_M;

		if (lan_en)
			act &= ~NSE_SINGLE_FWD_LAN_DISABLE;
		else
			act |= NSE_SINGLE_FWD_LAN_DISABLE;
		break;

	case NSE_FWD_TO_LAN:

		if (lb_en)
			act |= (NSE_SINGLE_FWD_VSI_EN_LB << NSE_SINGLE_FWD_TYPE_S) &
					NSE_SINGLE_FWD_TYPE_M;
		else
			act |= (NSE_SINGLE_FWD_VSI_DIS_LB << NSE_SINGLE_FWD_TYPE_S) &
					NSE_SINGLE_FWD_TYPE_M;

		if (lan_en)
			act &= ~NSE_SINGLE_FWD_LAN_DISABLE;
		else
			act |= NSE_SINGLE_FWD_LAN_DISABLE;

		break;
	case NSE_DROP_PACKET:
		/* set action type to fwd */
		act |= (NSE_SINGLE_ACT_TYPE_FWD <<
			NSE_SINGLE_ACT_TYPE_FWD_S) &
			NSE_SINGLE_ACT_TYPE_FWD_M;

		/* set fwd type to Drop */
		act |= (NSE_SINGLE_FWD_DROP << NSE_SINGLE_FWD_TYPE_S) &
				NSE_SINGLE_FWD_TYPE_M;

		break;
	default:
		dev_err(nse_hw_to_dev(hw),
			"Invalid fwd action type\n");
		return -EIO;
	}

	*fwd = act;
	return 0;
}

/**
 * nse_fill_task_au_fwd -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @fltr: tc flower information after previous parsing.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static int
nse_fill_task_au_fwd(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_tc_flower_fltr *fltr,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	int ret;
	u16 fwd_encode;
	__le16 act;

	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_AU_FWD;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_FWD_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	ret = nse_fill_au_fwd_info(fltr, &fwd_encode);
	act = cpu_to_le16(fwd_encode);
	memcpy(&du_desc->data[*cur_data_pos],
		&act, NSE_TASK_FWD_DATA_LEN);
	*cur_data_pos += NSE_TASK_FWD_DATA_LEN;
	return ret;
}
#endif

#if !NSE_TC_FLWR_METER_IN_DU
/**
 * nse_fill_task_au_meter -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @meter: allocated meter para.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_au_meter(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_sw_meter *meter,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	u32 count_id;
	__le32 tmp_cnt;
	__le16 tmp_meter;

	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_AU_METER;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_METER_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	count_id = (u32)meter->red_cnt_p->p_counter.hw_id;
	tmp_cnt = cpu_to_le32(count_id);
	memcpy(&du_desc->data[*cur_data_pos],
		&tmp_cnt, NSE_TASK_METER_RED_PCOUNT_LEN);
	*cur_data_pos += NSE_TASK_METER_RED_PCOUNT_LEN;

	count_id = (u32)meter->red_cnt_p->b_counter.hw_id;
	tmp_cnt = cpu_to_le32(count_id);
	memcpy(&du_desc->data[*cur_data_pos],
		&tmp_cnt, NSE_TASK_METER_RED_BCOUNT_LEN);
	*cur_data_pos += NSE_TASK_METER_RED_BCOUNT_LEN;

	count_id = (u32)meter->green_cnt_p->p_counter.hw_id;
	tmp_cnt = cpu_to_le32(count_id);
	memcpy(&du_desc->data[*cur_data_pos],
		&tmp_cnt, NSE_TASK_METER_GRN_PCOUNT_LEN);
	*cur_data_pos += NSE_TASK_METER_GRN_PCOUNT_LEN;

	count_id = (u32)meter->green_cnt_p->b_counter.hw_id;
	tmp_cnt = cpu_to_le32(count_id);
	memcpy(&du_desc->data[*cur_data_pos],
		&tmp_cnt, NSE_TASK_METER_GRN_BCOUNT_LEN);
	*cur_data_pos += NSE_TASK_METER_GRN_BCOUNT_LEN;

	tmp_meter = cpu_to_le16(meter->meter_id);
	memcpy(&du_desc->data[*cur_data_pos],
		&tmp_meter, NSE_TASK_METER_ID_LEN);
	*cur_data_pos += NSE_TASK_METER_ID_LEN;
}
#endif

#if !NSE_TC_FLWR_COUNT_IN_DU
/**
 * nse_fill_task_au_count -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @counter_p: allocated counter pair.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_au_count(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_sw_counter_pair *counter_p,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	u32 count_id;
	__le32 tmp_cnt;

	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_AU_COUNT;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_COUNT_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	count_id = (u32)counter_p->b_counter.hw_id;
	tmp_cnt = cpu_to_le32(count_id);
	memcpy(&du_desc->data[*cur_data_pos],
		&tmp_cnt, NSE_TASK_COUNT_BYTE_LEN);
	*cur_data_pos += NSE_TASK_COUNT_BYTE_LEN;

	count_id = (u32)counter_p->p_counter.hw_id;
	tmp_cnt = cpu_to_le32(count_id);
	memcpy(&du_desc->data[*cur_data_pos],
		&tmp_cnt, NSE_TASK_COUNT_PKT_LEN);
	*cur_data_pos += NSE_TASK_COUNT_PKT_LEN;
}
#endif

/**
 * nse_fc_query_cached -
 *		get cached statistic value
 */
void nse_fc_query_cached(struct nse_sw_counter_pair *counter_p,
			  u64 *o_bytes, u64 *o_packets, u64 *o_lastuse)
{
	struct nse_counter_cache cache;
	u64 lastuse = 0, packets = 0, bytes = 0;

	if (!counter_p)
		return;

	cache = counter_p->p_counter.cache;

	if (cache.val >= counter_p->p_counter.last_val)
		packets = cache.val - counter_p->p_counter.last_val;
	else {
		packets = (u64)(~0) - counter_p->p_counter.last_val;
		packets += cache.val;
	}
	lastuse = cache.lastuse;
	counter_p->p_counter.last_val = cache.val;

	cache = counter_p->b_counter.cache;
	if (cache.val >= counter_p->b_counter.last_val)
		bytes = cache.val - counter_p->b_counter.last_val;
	else {
		bytes = (u64)(~0) - counter_p->b_counter.last_val;
		bytes += cache.val;
	}
	lastuse = max_t(u64, lastuse, cache.lastuse);
	counter_p->b_counter.last_val = cache.val;

	*o_packets = packets;
	*o_bytes = bytes;
	*o_lastuse = lastuse;
}

/**
 * nse_fill_task_nop -
 *		fill task code and no task data.
 * @cur_task_list: task list object, fill task code to it.
 * @au_task_cnt: index of task in task list.
 * @nop_task_cnt: nop task count
 */
static void
nse_fill_task_nop(struct nse_sw_task_list *cur_task_list,
		u16 *au_task_cnt, u16 nop_task_cnt)
{
	u16 i;

	/*fill task code*/
	for (i = 0; i < nop_task_cnt; i++) {
		cur_task_list->task[*au_task_cnt].task_id =
				NSE_TASK_ID_NOP;
		(*au_task_cnt)++;
	}
}

/**
 * nse_fill_task_vlan_push -
 *		fill vlan push task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @tc_action: parsed vlan data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_vlan_push(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_tc_flower_action *tc_action,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	__be16 v_proto;
	__be16 v_id;

	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_VLAN_PUSH;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_PUSH_VLAN_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	v_proto = tc_action->vlan_proto;
	memcpy(&du_desc->data[*cur_data_pos],
		&v_proto, NSE_TASK_PUSH_VLAN_TYPE_LEN);
	*cur_data_pos += NSE_TASK_PUSH_VLAN_TYPE_LEN;

	v_id = htons(((tc_action->vlan_prio << NSE_TASK_PUSH_VLAN_PRIO_S) &
			NSE_TASK_PUSH_VLAN_PRIO_M) |
			(tc_action->vlan_vid & NSE_TASK_PUSH_VLAN_ID_M));
	memcpy(&du_desc->data[*cur_data_pos],
		&v_id, NSE_TASK_PUSH_VLAN_ID_LEN);
	*cur_data_pos += NSE_TASK_PUSH_VLAN_ID_LEN;
}

/**
 * nse_fill_task_vlan_pop -
 *		fill task code and no task data.
 * @cur_task_list: task list object, fill task code to it.
 * @au_task_cnt: index of task in task list.
 */
static void
nse_fill_task_vlan_pop(struct nse_sw_task_list *cur_task_list,
		u16 *au_task_cnt)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_VLAN_POP;
	(*au_task_cnt)++;
}

/**
 * nse_fill_task_rewrite_l4_dport -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_rewrite_l4_dport(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_L4_DPORT_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_PORT_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	if (rw_hdrs->masks.tcp.dest) {
		memcpy(&du_desc->data[*cur_data_pos],
			&rw_hdrs->vals.tcp.dest,
			NSE_TASK_REWRITE_PORT_VAL_LEN);
		*cur_data_pos += NSE_TASK_REWRITE_PORT_VAL_LEN;
		memcpy(&du_desc->data[*cur_data_pos],
			&rw_hdrs->masks.tcp.dest,
			NSE_TASK_REWRITE_PORT_MASK_LEN);
		*cur_data_pos += NSE_TASK_REWRITE_PORT_MASK_LEN;
	} else {
		memcpy(&du_desc->data[*cur_data_pos],
			&rw_hdrs->vals.udp.dest,
			NSE_TASK_REWRITE_PORT_VAL_LEN);
		*cur_data_pos += NSE_TASK_REWRITE_PORT_VAL_LEN;
		memcpy(&du_desc->data[*cur_data_pos],
			&rw_hdrs->masks.udp.dest,
			NSE_TASK_REWRITE_PORT_MASK_LEN);
		*cur_data_pos += NSE_TASK_REWRITE_PORT_MASK_LEN;
	}
}

/**
 * nse_fill_task_rewrite_l4_sport -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_rewrite_l4_sport(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_L4_SPORT_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_PORT_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	if (rw_hdrs->masks.tcp.source) {
		memcpy(&du_desc->data[*cur_data_pos],
			&rw_hdrs->vals.tcp.source,
			NSE_TASK_REWRITE_PORT_VAL_LEN);
		*cur_data_pos += NSE_TASK_REWRITE_PORT_VAL_LEN;
		memcpy(&du_desc->data[*cur_data_pos],
			&rw_hdrs->masks.tcp.source,
			NSE_TASK_REWRITE_PORT_MASK_LEN);
		*cur_data_pos += NSE_TASK_REWRITE_PORT_MASK_LEN;
	} else {
		memcpy(&du_desc->data[*cur_data_pos],
			&rw_hdrs->vals.udp.source,
			NSE_TASK_REWRITE_PORT_VAL_LEN);
		*cur_data_pos += NSE_TASK_REWRITE_PORT_VAL_LEN;
		memcpy(&du_desc->data[*cur_data_pos],
			&rw_hdrs->masks.udp.source,
			NSE_TASK_REWRITE_PORT_MASK_LEN);
		*cur_data_pos += NSE_TASK_REWRITE_PORT_MASK_LEN;
	}
}

/**
 * nse_fill_task_rewrite_l3_dip_v6 -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_rewrite_l3_dip_v6(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_L3_DIP_V6_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_IPV6_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->vals.ip6.daddr,
		NSE_TASK_REWRITE_IPV6_VAL_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_IPV6_VAL_LEN;
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->masks.ip6.daddr,
		NSE_TASK_REWRITE_IPV6_MASK_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_IPV6_MASK_LEN;
}

/**
 * nse_fill_task_rewrite_l3_sip_v6 -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_rewrite_l3_sip_v6(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_L3_SIP_V6_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_IPV6_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->vals.ip6.saddr,
		NSE_TASK_REWRITE_IPV6_VAL_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_IPV6_VAL_LEN;
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->masks.ip6.saddr,
		NSE_TASK_REWRITE_IPV6_MASK_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_IPV6_MASK_LEN;
}

/**
 * nse_fill_task_rewrite_l3_hlimit -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_rewrite_l3_hlimit(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_L3_HLIMIT_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_HLIMIT_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->vals.ip6.hop_limit,
		NSE_TASK_REWRITE_HLIMIT_VAL_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_HLIMIT_VAL_LEN;
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->masks.ip6.hop_limit,
		NSE_TASK_REWRITE_HLIMIT_MASK_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_HLIMIT_MASK_LEN;
}

/**
 * nse_fill_task_rewrite_l3_dip_v4 -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_rewrite_l3_dip_v4(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_L3_DIP_V4_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_IP_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->vals.ip4.daddr,
		NSE_TASK_REWRITE_IP_VAL_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_IP_VAL_LEN;
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->masks.ip4.daddr,
		NSE_TASK_REWRITE_IP_MASK_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_IP_MASK_LEN;
}

/**
 * nse_fill_task_rewrite_l3_sip_v4 -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_rewrite_l3_sip_v4(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_L3_SIP_V4_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_IP_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->vals.ip4.saddr,
		NSE_TASK_REWRITE_IP_VAL_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_IP_VAL_LEN;
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->masks.ip4.saddr,
		NSE_TASK_REWRITE_IP_MASK_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_IP_MASK_LEN;
}

/**
 * nse_fill_task_rewrite_l3_ttl -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_rewrite_l3_ttl(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_L3_TTL_V4_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_TTL_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->vals.ip4.ttl,
		NSE_TASK_REWRITE_TTL_VAL_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_TTL_VAL_LEN;
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->masks.ip4.ttl,
		NSE_TASK_REWRITE_TTL_MASK_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_TTL_MASK_LEN;
}

/**
 * nse_fill_task_rewrite_l3_v4_tos -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_rewrite_l3_v4_tos(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_L3_TOS_V4_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_TOS_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->vals.ip4.tos,
		NSE_TASK_REWRITE_TOS_VAL_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_TOS_VAL_LEN;
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->masks.ip4.tos,
		NSE_TASK_REWRITE_TOS_MASK_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_TOS_MASK_LEN;
}

/**
 * nse_fill_task_rewrite_l3_v6_tos -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_rewrite_l3_v6_tos(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	u8 tos, tos_msk;

	tos = (rw_hdrs->vals.ip6.priority << 4) |
				(rw_hdrs->vals.ip6.flow_lbl[0] >> 4);
	tos_msk = (rw_hdrs->masks.ip6.priority << 4) |
				(rw_hdrs->masks.ip6.flow_lbl[0] >> 4);

	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_L3_TOS_V6_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_TOS_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	du_desc->data[*cur_data_pos] = tos;
	*cur_data_pos += NSE_TASK_REWRITE_TOS_VAL_LEN;
	du_desc->data[*cur_data_pos] = tos_msk;
	*cur_data_pos += NSE_TASK_REWRITE_TOS_MASK_LEN;
}

/**
 * nse_fill_task_rewrite_l2_vlan -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_rewrite_l2_vlan(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_VLAN_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_VLAN_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->vals.vlan.h_vlan_TCI,
		NSE_TASK_REWRITE_VLAN_VAL_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_VLAN_VAL_LEN;
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->masks.vlan.h_vlan_TCI,
		NSE_TASK_REWRITE_VLAN_MASK_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_VLAN_MASK_LEN;
}

/**
 * nse_fill_task_rewrite_l2_dmac -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_rewrite_l2_dmac(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_L2_DMAC_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_MAC_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->vals.eth.h_dest,
		NSE_TASK_REWRITE_MAC_VAL_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_MAC_VAL_LEN;
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->masks.eth.h_dest,
		NSE_TASK_REWRITE_MAC_MASK_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_MAC_MASK_LEN;
}

/**
 * nse_fill_task_rewrite_l2_smac -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
static void
nse_fill_task_rewrite_l2_smac(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_L2_SMAC_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_MAC_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->vals.eth.h_source,
		NSE_TASK_REWRITE_MAC_VAL_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_MAC_VAL_LEN;
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->masks.eth.h_source,
		NSE_TASK_REWRITE_MAC_MASK_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_MAC_MASK_LEN;
}

/**
 * is_lite_node_state
 * @du_act_cnt: du action number
 * @au_task_cnt: au task number
 * @du_desc_cnt: du desc number
 */
static bool
is_lite_node_state(u16 du_act_cnt, u16 md_num,  u16 au_task_cnt, u16 du_desc_cnt)
{
	return (du_act_cnt + md_num) <= NSE_MAX_LITE_DU_ACTION_NUM &&
			!au_task_cnt &&
			!du_desc_cnt;
}

#if NSE_TC_FLWR_FWD_IN_DU

/**
 * nse_fill_node_state_fwd_info - fill forward info into node state
 *	including drop/toLan/toVSI/toVsiList.
 *	one of them will be selected.
 *
 * @node_state: node state obj, which need initial.
 */
static int
nse_fill_node_state_fwd_info(struct nse_vsi *vsi,
		struct nse_tc_flower_fltr *fltr,
		struct nse_node_state *node_state, u16 *du_act_cnt)
{
	struct nse_du_action *du_action;
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_vsi *uplink_vsi = vsi->back->switchdev.uplink_vsi;
	struct nse_tc_flower_action *action = &fltr->action;
	struct nse_vsi *dest_vsi;
	struct nse_vsi_list_map_info *vsi_list_info;
	u16 vsi_handle[NSE_MAX_FLOW_FWD_DEST];
	u16 vsi_cnt = 0;
	u16 i, dest_cnt;

	if (!(action->flags &
		     (NSE_TC_FLWR_ACTION_DROP |
		      NSE_TC_FLWR_ACTION_TO_LAN |
		      NSE_TC_FLWR_ACTION_FWD_VSI |
		      NSE_TC_FLWR_ACTION_FWD_VSI_LIST))) {
		dev_err(nse_hw_to_dev(hw), "Fwd info is necessary when no dup action\n");
		return -EIO;
	}

	du_action = &node_state->du_action[*du_act_cnt];
	du_action->flags_info.act_valid = true;
	du_action->flags_info.act = 0;

	if (fltr->src_vsi == uplink_vsi)
		du_action->rx = true;
	else
		du_action->rx = false;

	/*set toLan flag*/
	if (fltr->src_vsi != uplink_vsi &&
			action->lan_en)
		du_action->flags_info.act |= NSE_LAN_ENABLE;

	/*set LB flag*/
	if (fltr->src_vsi != uplink_vsi &&
			is_repr_vsi_in_dests(action, uplink_vsi))
		du_action->flags_info.act |= NSE_LB_ENABLE;

	/*set dest vsi information*/
	switch (action->fltr_act) {
	case NSE_FWD_TO_VSI:

		dest_cnt = action->dest_cnt;
		dest_vsi = NULL;
		if (du_action->rx)
			dest_vsi = action->dests[0].dest_vsi;
		else {
			if (dest_cnt > 2) {
				dev_err(nse_hw_to_dev(hw),
					"too many dest VSIs when FWD to VSI action on tx dir\n");
				return -EIO;
			}
			for (i = 0; i < dest_cnt; i++) {
				if (fltr->tc_flower) {
					if (action->dests[i].dest_vsi != uplink_vsi) {
						dest_vsi = action->dests[i].dest_vsi;
						break;
					}
				} else {
					dest_vsi = action->dests[i].dest_vsi;
					break;
				}
			}
		}

		if (!dest_vsi) {
			dev_err(nse_hw_to_dev(hw), "Single dest vsi is NULL!\n");
			return -EIO;
		}

		/*dest vsi maybe in other pf, so use dest_vsi->back->hw here*/
		du_action->fwd_id.hw_vsi_id =
				nse_get_hw_vsi_num(&dest_vsi->back->hw, dest_vsi->idx);
		du_action->du_act =	NSE_DU_ACT_FWD_TO_VSI;
		(*du_act_cnt)++;
		break;

	case NSE_FWD_TO_VSI_LIST:
		dest_cnt = action->dest_cnt;
		for (i = 0; i < dest_cnt; i++) {
			dest_vsi = action->dests[i].dest_vsi;
			if (fltr->tc_flower) {
				if (dest_vsi != uplink_vsi) {
					vsi_handle[i] = dest_vsi->idx;
					vsi_cnt++;
				}
			} else {
				vsi_handle[i] = dest_vsi->idx;
				vsi_cnt++;
			}
		}

		vsi_list_info = nse_sw_get_adv_vlist(hw, &vsi_handle[0], vsi_cnt);
		if (!vsi_list_info) {
			dev_err(nse_hw_to_dev(hw),
				"Failed to get advanced vsi list\n");
			return -EIO;
		}

		du_action->fwd_id.vsi_list_id = vsi_list_info->vsi_list_id;
		du_action->du_act =	NSE_DU_ACT_FWD_TO_VSI_LIST;
		fltr->action.vsi_list_id = vsi_list_info->vsi_list_id;
		fltr->action.vsi_list_info = vsi_list_info;
		(*du_act_cnt)++;
		break;
	case NSE_FWD_TO_LAN:
		du_action->du_act =	NSE_DU_ACT_FWD_TO_LAN;
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

#endif

/**
 * nse_get_route_and_out_devs -
 *		get the real outdev according to OS route out netdev
 *
 * @vsi: source vsi, where this rule add on
 * @dev: route dest netdev by OS route
 */
static int nse_get_route_and_out_devs(struct nse_vsi *vsi,
				  struct net_device *dev,
				  struct net_device **route_dev,
				  struct net_device **out_dev)
{
	*route_dev = dev;
	*out_dev = dev;
	return 0;
}

/**
 * nse_route_lookup_put
 *
 * @attr: route attribute after lookuping OS route
 */
static void nse_route_lookup_put(struct nse_tc_tun_route_attr *attr)
{
	if (attr->n)
		neigh_release(attr->n);
	if (attr->route_dev)
		dev_put(attr->route_dev);
}

/**
 * nse_route_lookup_ipv4_get -
 *		lookup OS route and neigh
 *
 * @vsi: source vsi, where this rule add on
 * @target_dev: out netdev,
 *		it should be virtual tunnel netdev here, such as vxlan netdev
 * @attr: tunnel attribute for lookup OS route
 */
static int nse_route_lookup_ipv4_get(struct nse_vsi *vsi,
				       struct net_device *target_dev,
				       struct nse_tc_tun_route_attr *attr)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct net_device *route_dev;
	struct net_device *out_dev;
	struct neighbour *n;
	struct rtable *rt;
	int ret;

#if IS_ENABLED(CONFIG_INET)
	rt = ip_route_output_key(dev_net(target_dev), &attr->fl.fl4);
	if (IS_ERR(rt)) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] ip_route_output_key err!\n",
			__func__, __LINE__);
		return PTR_ERR(rt);
	}

	if (rt->rt_type != RTN_UNICAST) {
		ret = -ENETUNREACH;
		goto err_rt_release;
	}
#else
	return -EOPNOTSUPP;
#endif

	ret = nse_get_route_and_out_devs(vsi, rt->dst.dev, &route_dev, &out_dev);
	if (ret < 0)
		goto err_rt_release;

	dev_hold(route_dev);

	if (!attr->ttl)
		attr->ttl = ip4_dst_hoplimit(&rt->dst);

	n = dst_neigh_lookup(&rt->dst, &attr->fl.fl4.daddr);
	if (!n) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] dst_neigh_lookup err!\n",
			__func__, __LINE__);
		ret = -ENOMEM;
		goto err_dev_release;
	}

	ip_rt_put(rt);
	attr->route_dev = route_dev;
	attr->out_dev = out_dev;
	attr->n = n;
	return 0;

err_dev_release:
	dev_put(route_dev);
err_rt_release:
	ip_rt_put(rt);
	return ret;
}

/**
 * nse_tc_tun_gen_v4_vxlan_header
 *		generate vxlan tunnel header from mac layer to vxlan header.
 *
 * @vsi: source vsi, where this rule add on
 * @encap_entry: alloced encap entry, put encap data into it.
 * @attr: tunnel attribute after lookup OS route
 */
static int
nse_tc_tun_gen_v4_vxlan_header(struct nse_vsi *vsi,
				struct nse_sw_encap_entry *encap_entry,
				struct nse_tc_tun_route_attr *attr)
{
	struct nse_total_vxlan_v4_header *hdr;
	const struct ip_tunnel_key *tun_key = &encap_entry->tun_info->key;
	struct iphdr *ip;
	struct udphdr *udp;
	struct vxlanhdr *vxh;
	__be32 tun_id;

	hdr = (struct nse_total_vxlan_v4_header *) encap_entry->du_desc.data;
	read_lock_bh(&attr->n->lock);
	ether_addr_copy(hdr->dst_mac, attr->n->ha);
	read_unlock_bh(&attr->n->lock);
	ether_addr_copy(hdr->src_mac, attr->route_dev->dev_addr);
	hdr->n_proto = htons(ETH_P_IP);

	ip = &hdr->ip_hdr;
	ip->version = 0x4;
	ip->ihl = 0x5;
	ip->tos = tun_key->tos;
	ip->protocol = IPPROTO_UDP;
	ip->frag_off = htons(IP_DF);
	ip->ttl = attr->ttl;
	ip->daddr = attr->fl.fl4.daddr;
	ip->saddr = attr->fl.fl4.saddr;

	udp = &hdr->udp_hdr;
	udp->dest = htons(IANA_VXLAN_UDP_PORT);
	udp->source = htons(0xC000);

	vxh = &hdr->vxlan_hdr;
	tun_id = tunnel_id_to_key32(tun_key->tun_id);
	vxh->vx_flags = VXLAN_HF_VNI;
	vxh->vx_vni = vxlan_vni_field(tun_id);

	return 0;
}

/**
 * nse_tc_tun_create_header_ipv4
 *		lookup OS route and neigh to build tunnel header,
 *		and copy tunnel header to encap entry's du data.
 *
 * @vsi: source vsi, where this rule add on
 * @target_dev: out netdev,
 *		it should be virtual tunnel netdev here, such as vxlan netdev
 * @encap_entry: alloced encap entry, put encap data into it.
 */
static int
nse_tc_tun_create_header_ipv4(struct nse_vsi *vsi,
				struct net_device *target_dev,
				struct nse_sw_encap_entry *encap_entry)
{
	struct nse_hw *hw = &vsi->back->hw;
	const struct ip_tunnel_key *tun_key = &encap_entry->tun_info->key;
	struct nse_tc_tun_route_attr attr = {};
	struct nse_neigh m_neigh = { 0 };
	int err = 0;
	u8 nud_state;

	/* 1. build attribute for searching OS route, and then lookup OS route */
	attr.fl.fl4.flowi4_tos = tun_key->tos;
	attr.fl.fl4.daddr = tun_key->u.ipv4.dst;
	attr.fl.fl4.saddr = tun_key->u.ipv4.src;
	attr.ttl = tun_key->ttl;
	err = nse_route_lookup_ipv4_get(vsi, target_dev, &attr);
	if (err) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] route lookup ipv4 err = %d\n",
			__func__, __LINE__, err);
		return err;
	}

	read_lock_bh(&attr.n->lock);
	nud_state = attr.n->nud_state;
	ether_addr_copy(encap_entry->dmac, attr.n->ha);
	read_unlock_bh(&attr.n->lock);

	/* 2. fill searched route and tun_key to encap du data*/
	switch (encap_entry->tun_type) {
	case TNL_VXLAN:
		err = nse_tc_tun_gen_v4_vxlan_header(vsi, encap_entry, &attr);
		if (err) {
			dev_err(nse_hw_to_dev(hw), "[%s, %d] Generate ipv4 vxlan header err!\n",
				__func__, __LINE__);
			goto release_neigh;
		}
		break;
	default:
		dev_err(nse_hw_to_dev(hw), "[%s, %d] encap tunnel_type(%d) is not supported!\n",
			__func__, __LINE__, encap_entry->tun_type);
		err = -EOPNOTSUPP;
		goto release_neigh;
	}

	/* 3. attach current encap entry to neigh object */
	m_neigh.family = attr.n->ops->family;
	memcpy(&m_neigh.dst_ip, attr.n->primary_key, attr.n->tbl->key_len);
	encap_entry->out_dev = attr.out_dev;
	encap_entry->route_dev_ifindex = attr.route_dev->ifindex;
	encap_entry->valid = true;

	err = nse_encap_entry_attach_neigh(hw, encap_entry, &m_neigh, attr.n->dev);
	if (err) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] attach encap entry to neigh object err!\n",
			__func__, __LINE__);
		goto release_neigh;
	}

	if (!(nud_state & NUD_VALID)) {
		dev_warn(nse_hw_to_dev(hw), "[%s, %d] nud_state is invalid!\n",
			__func__, __LINE__);
		encap_entry->valid = false;
		neigh_event_send(attr.n, NULL);
	}

	nse_route_lookup_put(&attr);
	return 0;

release_neigh:
	nse_route_lookup_put(&attr);
	return err;
}

#if IS_ENABLED(CONFIG_INET) && IS_ENABLED(CONFIG_IPV6)

/**
 * nse_tc_tun_gen_v6_vxlan_header
 *		generate vxlan ipv6 tunnel header from mac layer to vxlan header.
 *
 * @vsi: source vsi, where this rule add on
 * @encap_entry: alloced encap entry, put encap data into it.
 * @attr: tunnel attribute after lookup OS route
 */
static int
nse_tc_tun_gen_v6_vxlan_header(struct nse_vsi *vsi,
				struct nse_sw_encap_entry *encap_entry,
				struct nse_tc_tun_route_attr *attr)
{
	struct nse_total_vxlan_v6_header *hdr;
	const struct ip_tunnel_key *tun_key = &encap_entry->tun_info->key;
	struct ipv6hdr *ipv6;
	struct udphdr *udp;
	struct vxlanhdr *vxh;
	__be32 tun_id;

	hdr = (struct nse_total_vxlan_v6_header *) encap_entry->du_desc.data;
	read_lock_bh(&attr->n->lock);
	ether_addr_copy(hdr->dst_mac, attr->n->ha);
	read_unlock_bh(&attr->n->lock);
	ether_addr_copy(hdr->src_mac, attr->route_dev->dev_addr);
	hdr->n_proto = htons(ETH_P_IPV6);

	ipv6 = &hdr->ipv6_hdr;
	ip6_flow_hdr(ipv6, tun_key->tos, 0);
	ipv6->hop_limit   = attr->ttl;
	ipv6->daddr	  = attr->fl.fl6.daddr;
	ipv6->saddr	  = attr->fl.fl6.saddr;
	ipv6->nexthdr = IPPROTO_UDP;

	udp = &hdr->udp_hdr;
	udp->dest = htons(IANA_VXLAN_UDP_PORT);
	udp->source = htons(0xC000);

	vxh = &hdr->vxlan_hdr;
	tun_id = tunnel_id_to_key32(tun_key->tun_id);
	vxh->vx_flags = VXLAN_HF_VNI;
	vxh->vx_vni = vxlan_vni_field(tun_id);

	return 0;
}

/**
 * nse_route_lookup_ipv6_get -
 *		lookup OS ipv6 route and neigh
 *
 * @vsi: source vsi, where this rule add on
 * @target_dev: out netdev,
 *		it should be virtual tunnel netdev here, such as vxlan netdev
 * @attr: tunnel attribute for lookup OS route
 */
static int nse_route_lookup_ipv6_get(struct nse_vsi *vsi,
				       struct net_device *target_dev,
				       struct nse_tc_tun_route_attr *attr)
{
	struct net_device *route_dev;
	struct net_device *out_dev;
	struct dst_entry *dst;
	struct neighbour *n;
	int ret;

	dst = ipv6_stub->ipv6_dst_lookup_flow(dev_net(target_dev), NULL, &attr->fl.fl6,
						  NULL);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	if (!attr->ttl)
		attr->ttl = ip6_dst_hoplimit(dst);

	ret = nse_get_route_and_out_devs(vsi, dst->dev, &route_dev, &out_dev);
	if (ret < 0)
		goto err_dst_release;

	dev_hold(route_dev);
	n = dst_neigh_lookup(dst, &attr->fl.fl6.daddr);
	if (!n) {
		ret = -ENOMEM;
		goto err_dev_release;
	}

	dst_release(dst);
	attr->out_dev = out_dev;
	attr->route_dev = route_dev;
	attr->n = n;
	return 0;

err_dev_release:
	dev_put(route_dev);
err_dst_release:
	dst_release(dst);
	return ret;
}

/**
 * nse_tc_tun_create_header_ipv6
 *		lookup OS route and neigh to build tunnel header,
 *		and copy tunnel header to encap entry's du data.
 *
 * @vsi: source vsi, where this rule add on
 * @target_dev: out netdev,
 *		it should be virtual tunnel netdev here, such as vxlan netdev
 * @encap_entry: alloced encap entry, put encap data into it.
 */
static int
nse_tc_tun_create_header_ipv6(struct nse_vsi *vsi,
				struct net_device *target_dev,
				struct nse_sw_encap_entry *encap_entry)
{
	struct nse_hw *hw = &vsi->back->hw;
	const struct ip_tunnel_key *tun_key = &encap_entry->tun_info->key;
	struct nse_tc_tun_route_attr attr = {};
	struct nse_neigh m_neigh = { 0 };
	int err = 0;
	u8 nud_state;

	/* 1. build attribute for searching OS route, and then lookup OS route */
	attr.ttl = tun_key->ttl;
	attr.fl.fl6.flowlabel = ip6_make_flowinfo(RT_TOS(tun_key->tos), tun_key->label);
	attr.fl.fl6.daddr = tun_key->u.ipv6.dst;
	attr.fl.fl6.saddr = tun_key->u.ipv6.src;
	err = nse_route_lookup_ipv6_get(vsi, target_dev, &attr);
	if (err) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] route lookup ipv6 err = %d\n",
			__func__, __LINE__, err);
		return err;
	}
	read_lock_bh(&attr.n->lock);
	nud_state = attr.n->nud_state;
	read_unlock_bh(&attr.n->lock);

	/* 2. fill searched route and tun_key to encap du data*/
	switch (encap_entry->tun_type) {
	case TNL_VXLAN:
		err = nse_tc_tun_gen_v6_vxlan_header(vsi, encap_entry, &attr);
		if (err) {
			dev_err(nse_hw_to_dev(hw), "[%s, %d] Generate ipv6 vxlan header err!\n",
				__func__, __LINE__);
			goto release_neigh;
		}
		break;
	default:
		dev_err(nse_hw_to_dev(hw), "[%s, %d] encap tunnel_type(%d) is not supported!\n",
			__func__, __LINE__, encap_entry->tun_type);
		err = -EOPNOTSUPP;
		goto release_neigh;
	}

	/* 3. attach current encap entry to neigh object */
	m_neigh.family = attr.n->ops->family;
	memcpy(&m_neigh.dst_ip, attr.n->primary_key, attr.n->tbl->key_len);
	encap_entry->out_dev = attr.out_dev;
	encap_entry->route_dev_ifindex = attr.route_dev->ifindex;
	encap_entry->valid = true;

	err = nse_encap_entry_attach_neigh(hw, encap_entry, &m_neigh, attr.n->dev);
	if (err) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] attach encap entry to neigh object err!\n",
			__func__, __LINE__);
		goto release_neigh;
	}

	if (!(nud_state & NUD_VALID)) {
		dev_warn(nse_hw_to_dev(hw), "[%s, %d] nud_state is invalid!\n",
			__func__, __LINE__);
		encap_entry->valid = false;
		neigh_event_send(attr.n, NULL);
	}

	nse_route_lookup_put(&attr);
	return 0;

release_neigh:
	nse_route_lookup_put(&attr);
	return err;
}
#else
static int
nse_tc_tun_create_header_ipv6(struct nse_vsi *vsi,
				struct net_device *target_dev,
				struct nse_sw_encap_entry *encap_entry)
{
	return -EOPNOTSUPP;
}
#endif

/**
 * nse_tc_detach_fltr_encap -detach fltr to encap entry.
 * @fltr_encap_item: fltr encap item, which including encap entry point;
 */
void
nse_tc_fltr_detach_encap(struct nse_sw_encap_item *fltr_encap_item)
{
	struct nse_sw_encap_entry *encap_entry = NULL;

	if (!fltr_encap_item || !fltr_encap_item->e)
		return;

	encap_entry = fltr_encap_item->e;

	mutex_lock(&encap_entry->fltr_list_lock);
	list_del(&fltr_encap_item->list_entry);
	fltr_encap_item->e = NULL;
	mutex_unlock(&encap_entry->fltr_list_lock);
}

/**
 * nse_is_duplicated_encap_entry -
 *	 we will add a encap entry(e) to fltr, and its index will be encap_index
 *	 before adding, we check it from 0 to (encap_index - 1)
 *	 to find that whether a same entry existed or not.
 *
 * @vsi: source vsi, where this rule add on
 * @fltr: tc flower information after previous parsing
 * @encap_index: current encap index in encap items of fltr
 * @e: new encap entry
 *
 */
static bool nse_is_duplicated_encap_entry(struct nse_vsi *vsi,
			struct nse_tc_flower_fltr *fltr,
			int encap_index, struct nse_sw_encap_entry *e)
{
	struct nse_hw *hw = &vsi->back->hw;
	int i;

	for (i = 0; i < encap_index; i++) {
		if (fltr->action.encaps[i].e != e)
			continue;
		NL_SET_ERR_MSG_MOD(fltr->extack, "can't duplicate encap action");
		dev_err(nse_hw_to_dev(hw), "can't duplicate encap action\n");
		return true;
	}

	return false;
}

/**
 * nse_tc_attach_encap -attach single encap entry to fltr
 *
 * @vsi: source vsi, where this rule add on
 * @fltr: tc flower information after previous parsing
 * @encap_index: current encap index in encap items of fltr
 * @tc_action: tc flower action after previous parsing
 * @encap_entry: returned encap entry
 */
static int
nse_tc_attach_encap(struct nse_vsi *vsi,
				struct nse_tc_flower_fltr *fltr,
				int encap_index,
				struct nse_tc_flower_action *tc_action,
				struct nse_sw_encap_entry **encap_entry)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_switch_info *sw = hw->switch_info;
	struct nse_sw_encap_entry *e = NULL;
	struct ip_tunnel_info *tun_info = NULL;
	struct nse_sw_encap_key key = { 0 };
	struct net_device *target_dev;
	unsigned short family;
	int i, err = 0;
	u16 d_size;

	if (tc_action->encap_cnt > NSE_MAX_FLOW_ENCAP_CNT)
		return -EIO;

	/*1. build key */
	for (i = 0; i < tc_action->dest_cnt; i++) {
		if (tc_action->dests[i].flags & NSE_TC_FLWR_ACTION_DEST_ENCAP_VLD) {
			tun_info = tc_action->dests[i].tun_info;
			target_dev = tc_action->dests[i].target_dev;
			break;
		}
	}

	if (!tun_info) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] tun_info is NULL!\n",
			__func__, __LINE__);
		return -EIO;
	}

	family = ip_tunnel_info_af(tun_info);
	key.ip_tun_key = &tun_info->key;
	key.tun_type = nse_tc_tun_get_type(target_dev, NULL);

	/*2. find encap entry in global table according to key.
	 *    if match return existed encap entry / ref_cnt++.
	 */
	mutex_lock(&sw->encap_tbl_lock);
	e = nse_sw_find_encap_entry(hw, &key);
	if (e) {
		mutex_unlock(&sw->encap_tbl_lock);

		/* Check that entry was not already attached to this flow */
		if (nse_is_duplicated_encap_entry(vsi, fltr, encap_index, e))
			return -EOPNOTSUPP;

		refcount_inc(&e->ref_cnt);
		goto attach_fltr_to_encap_entry;
	}

	/*3. if find fail, alloc and creat a new encap entry, lookup route and neigh in OS.
	 * and copy to du desc.
	 */

	/*3.1 alloc hw encap entry du data obj*/
	if (family == AF_INET)
		d_size = NSE_DU_DATE_SIZE_64;
	else if (family == AF_INET6)
		d_size = NSE_DU_DATE_SIZE_96;

	e = nse_sw_creat_encap_entry(hw, d_size);
	if (!e) {
		dev_err(nse_hw_to_dev(hw), "Fail to creat hw encap entry\n");
		err = -ENOMEM;
		goto attach_encap_fail;
	}
	refcount_set(&e->ref_cnt, 1);
	e->tun_type = nse_tc_tun_get_type(target_dev, NULL);
	e->family = family;
	tun_info = nse_dup_tun_info(tun_info);
	if (!tun_info) {
		err = -ENOMEM;
		goto attach_encap_fail;
	}
	e->tun_info = tun_info;
	INIT_LIST_HEAD(&e->fltr_list);
	INIT_LIST_HEAD(&e->list_entry);
	mutex_init(&e->fltr_list_lock);
	/*3.2 fill hw encap entry du data content*/
	if (family == AF_INET)
		err = nse_tc_tun_create_header_ipv4(vsi, target_dev, e);
	else if (family == AF_INET6)
		err = nse_tc_tun_create_header_ipv6(vsi, target_dev, e);

	if (err) {
		dev_err(nse_hw_to_dev(hw), "Fail to creat encap tunnel header\n");
		goto attach_encap_fail;
	}

	/*3.3 update encap entry du data content*/
	err = nse_sw_add_encap_entry(hw, e);
	if (err) {
		dev_err(nse_hw_to_dev(hw), "Fail to add encap entry\n");
		goto attach_encap_fail;
	}
	list_add_tail(&e->list_entry, &hw->switch_info->encap_list_head);
	mutex_unlock(&sw->encap_tbl_lock);

attach_fltr_to_encap_entry:

	/*4  attach cur fltr flow to encap fltr list, used by neigh update.*/
	mutex_lock(&e->fltr_list_lock);
	fltr->action.encaps[encap_index].e = e;
	list_add_tail(&fltr->action.encaps[encap_index].list_entry, &e->fltr_list);
	fltr->action.encaps[encap_index].index = encap_index;
	mutex_unlock(&e->fltr_list_lock);

	dev_info(nse_hw_to_dev(hw),
		"Success to attach fltr encap item (%p) to encap entry(%p): encap idx = %d\n",
		&fltr->action.encaps[encap_index], e, encap_index);

	*encap_entry = e;
	return 0;

attach_encap_fail:
	mutex_unlock(&sw->encap_tbl_lock);
	if (e)
		nse_sw_destroy_encap_entry(hw, e);
	*encap_entry = NULL;
	return err;
}

#ifdef NSE_TC_FLWR_MULTI_ENCAP

/**
 * nse_tc_attach_encap -attach multi encap entry to fltr
 *
 * @vsi: source vsi, where this rule add on
 * @fltr: tc flower information after previous parsing
 * @tc_action: tc flower action after previous parsing
 * @m_encap_entry: returned multi encap entry
 */
static int
nse_tc_attach_m_encap(struct nse_vsi *vsi,
				struct nse_tc_flower_fltr *fltr,
				struct nse_tc_flower_action *tc_action,
				struct nse_sw_m_encap_entry **m_encap_entry)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_tc_flower_action *tmp_action;
	struct nse_sw_m_encap_key key = { 0 };
	struct nse_sw_m_encap_entry *e = NULL;
	struct ip_tunnel_info *tun_info[NSE_MAX_FLOW_ENCAP_CNT] = { NULL };
	struct net_device *target_dev[NSE_MAX_FLOW_ENCAP_CNT] = { NULL };
	unsigned short family;
	int i, err = 0, encap_idx = 0;
	u16 d_size;

	if (tc_action->encap_cnt > NSE_MAX_FLOW_ENCAP_CNT)
		return -EIO;

	/*1. build m_encap key */
	for (i = 0; i < tc_action->dest_cnt; i++) {
		if (tc_action->dests[i].flags & NSE_TC_FLWR_ACTION_DEST_ENCAP_VLD) {
			tun_info[encap_idx] = tc_action->dests[i].tun_info;
			target_dev[encap_idx++] = tc_action->dests[i].target_dev;
		}
	}

	if (tc_action->encap_cnt != encap_idx) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] multi tun_info is got enough\n",
			__func__, __LINE__);
		return -EIO;
	}

	family = ip_tunnel_info_af(tun_info[0]);
	key.tun_type = nse_tc_tun_get_type(target_dev[0], NULL);
	key.encap_cnt = tc_action->encap_cnt;

	tmp_action = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*tmp_action), GFP_KERNEL);
	if (!tmp_action)
		return -ENOMEM;

	for (i = 0; i < tc_action->encap_cnt; i++) {
		tmp_action->encap_cnt = 1;
		tmp_action->dest_cnt = 1;
		tmp_action->dests[0].tun_info = tun_info[i];
		tmp_action->dests[0].target_dev = target_dev[i];
		tmp_action->dests[0].flags |= NSE_TC_FLWR_ACTION_DEST_ENCAP_VLD;

		err = nse_tc_attach_encap(vsi, fltr, i, tmp_action, &(key.encap_entry[i]));

		if (err || !key.encap_entry[i]) {
			int j;

			for (j = i - 1; j >= 0; j--) {
				if (key.encap_entry[j]) {
					nse_tc_fltr_detach_encap(&tc_action->encaps[j]);
					err = nse_sw_put_encap_entry(hw, key.encap_entry[j]);
					if (err)
						dev_err(nse_hw_to_dev(hw),
							"fail to destroy hw encap entry\n");
				}
			}
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to attach single encap entry, tunnel idx = %d\n",
				__func__, __LINE__, i);
			devm_kfree(nse_hw_to_dev(hw), tmp_action);
			return err;
		}
	}

	devm_kfree(nse_hw_to_dev(hw), tmp_action);

	/*2. find m encap entry in global table according to key.
	 *    if match return existed m encap entry / ref_cnt++.
	 */

	mutex_lock(&hw->switch_info->m_encap_lock);

	e = nse_sw_find_m_encap_entry(hw, &key);
	if (e) {
		refcount_inc(&e->ref_cnt);
		mutex_unlock(&hw->switch_info->m_encap_lock);
		goto attach_fltr_to_encap_entry;
	}

	/*3. if find fail, alloc and creat a new encap entry, lookup route and neigh in OS.
	 * and copy to du desc.
	 */
	/*3.1 alloc hw m encap entry du data obj*/
	d_size = NSE_DU_DATE_SIZE_64;
	e = nse_sw_creat_m_encap_entry(hw, d_size);
	if (!e) {
		dev_err(nse_hw_to_dev(hw), "Fail to creat hw multi encap entry\n");
		err = -ENOMEM;
		goto attach_encap_fail;
	}
	refcount_set(&e->ref_cnt, 1);
	e->tun_type = key.tun_type;
	e->family = family;
	e->encap_cnt = tc_action->encap_cnt;
	memcpy(e->encap_entry, key.encap_entry,
		sizeof(struct nse_sw_encap_entry *) * NSE_MAX_FLOW_ENCAP_CNT);

	/*3.2 fill hw m encap entry du data content*/
	for (i = 0; i < tc_action->encap_cnt; i++) {
		u8 *data = e->du_desc.data;
		unsigned int offset = i * 4;
		u16 tmp = 0;
		__le16 fwd, desc;

		/*fwd info (only to Lan)*/
		tmp |= (NSE_SINGLE_FWD_VSI_DIS_LB << NSE_SINGLE_FWD_TYPE_S) &
					NSE_SINGLE_FWD_TYPE_M;
		tmp &= ~NSE_SINGLE_FWD_LAN_DISABLE;
		fwd = cpu_to_le16(tmp);
		data[offset] = tmp & 0xff;
		data[offset + 1] = tmp >> 8;

		/*tunnel desc*/
		tmp = 0;
		tmp |= (NSE_AQC_DU_DESC_SIZE_64B <<
			NSE_AQC_DU_DESC_SIZE_S) &
			NSE_AQC_DU_DESC_SIZE_M;
		tmp |= (e->encap_entry[i]->du_desc.du_data_id <<
			NSE_AQC_DU_DESC_DATA_ID_S) &
			NSE_AQC_DU_DESC_DATA_ID_M;
		desc = cpu_to_le16(tmp);
		data[offset + 2] = tmp & 0xff;
		data[offset + 3] = tmp >> 8;
	}

	/*3.3 update encap entry du data content*/
	err = nse_sw_add_m_encap_entry(hw, e);
	if (err) {
		dev_err(nse_hw_to_dev(hw), "Fail to add multi encap entry\n");
		goto attach_encap_fail;
	}

	list_add_tail(&e->list_entry, &hw->switch_info->m_encap_list_head);
	mutex_unlock(&hw->switch_info->m_encap_lock);

attach_fltr_to_encap_entry:

	*m_encap_entry = e;
	return 0;

attach_encap_fail:
	mutex_unlock(&hw->switch_info->m_encap_lock);
	if (e)
		nse_sw_destroy_m_encap_entry(hw, e);
	*m_encap_entry = NULL;
	return err;
}
#endif

#ifdef NSE_SUPPORT_FAST_FLWR

/**
 * nse_is_fast_flower - judge current fltr can be fast or not
 *
 * @act_flags: current fltr actions flag
 */
static bool
nse_is_fast_flower(u32 act_flags)
{
	return !(act_flags &
		~(NSE_TC_FLWR_ACTION_DROP |
		  NSE_TC_FLWR_ACTION_TO_LAN |
		  NSE_TC_FLWR_ACTION_FWD_VSI |
		  NSE_TC_FLWR_ACTION_COUNT));
}

/**
 * nse_tc_add_fast_action - add fast actions
 *
 * @vsi: source vsi, where this rule add on
 * @fltr: tc flower information after previous parsing
 */
static int
nse_tc_add_fast_action(struct nse_vsi *vsi,
			struct nse_tc_flower_fltr *fltr)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_tc_flower_action *tc_action = &fltr->action;
	struct nse_node_state *node_state = &tc_action->node_state;
	u32 act_flags = tc_action->flags;
	u16 du_act_cnt = 0;
	int err = 0;

	if (!(act_flags &
			(NSE_TC_FLWR_ACTION_DROP |
			 NSE_TC_FLWR_ACTION_TO_LAN |
			 NSE_TC_FLWR_ACTION_FWD_VSI |
			 NSE_TC_FLWR_ACTION_COUNT))) {
		dev_err(nse_hw_to_dev(hw),
			"Fast action don't support current act flag (0x%x)\n", act_flags);
		return -EINVAL;
	}

	nse_init_node_state(node_state);

	if (act_flags & NSE_TC_FLWR_ACTION_COUNT) {
		node_state->du_action[du_act_cnt++].du_act =
			NSE_DU_ACT_COUNT_PACKET;
		node_state->du_action[du_act_cnt++].du_act =
			NSE_DU_ACT_COUNT_BYTE;
	}

	if (act_flags & (NSE_TC_FLWR_ACTION_DROP |
					NSE_TC_FLWR_ACTION_TO_LAN |
					NSE_TC_FLWR_ACTION_FWD_VSI)) {
		err = nse_fill_node_state_fwd_info(vsi, fltr, node_state, &du_act_cnt);
		if (err) {
			dev_err(nse_hw_to_dev(hw), "Failed to fill fwd info of fast action\n");
			return -EINVAL;
		}
	}

	node_state->du_act_cnt = du_act_cnt;
	node_state->node_state_id = 0;
	node_state->is_fast = true;
	tc_action->large_act_id = node_state->node_state_id;
	return err;
}

#endif

/**
 * need_fast_node_count
 *					- judge current fltr is fast node and with count action
 * @fltr: tc flower information after previous parsing
 */
static bool
need_fast_node_count(struct nse_tc_flower_fltr *fltr)
{
	struct nse_tc_flower_action *tc_action = &fltr->action;
	u32 act_flags = tc_action->flags;

	return tc_action->node_state.is_fast &&
		(act_flags & NSE_TC_FLWR_ACTION_COUNT);
}

/**
 * nse_tc_get_fast_counter_id
 *					- get packet counter hw id and byte counter hw id
 * @fltr: tc flower information after previous parsing
 */
static int
nse_tc_get_fast_counter_id(struct nse_tc_flower_fltr *fltr,
		u16 *p_hw_id, u16 *b_hw_id)
{
	struct nse_node_state *node_state = &fltr->action.node_state;
	int ret = -EIO, i;
	bool p_found = false, b_found = false;

	for (i = 0; i < node_state->du_act_cnt; i++) {
		struct nse_du_action *du_action = &node_state->du_action[i];

		if (du_action->du_act == NSE_DU_ACT_COUNT_PACKET) {
			p_found = true;
			*p_hw_id = du_action->hw_cnt_id;
		} else if (du_action->du_act == NSE_DU_ACT_COUNT_BYTE) {
			b_found = true;
			*b_hw_id = du_action->hw_cnt_id;
		}
	}

	if (p_found && b_found)
		ret = 0;

	return ret;
}

/**
 * nse_tc_add_large_action -
 *
 * @vsi: source vsi, where this rule add on
 * @fltr: tc flower information after previous parsing
 */
int
nse_tc_add_large_action(struct nse_vsi *vsi,
			struct nse_tc_flower_fltr *fltr)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_node_state *node_state; /*local, alloc & free locally*/
	struct nse_sw_counter_pair *counter_p = NULL; /*global*/
	struct nse_sw_du_data *du_data = NULL; /*global*/
	struct nse_sw_encap_entry *encap_entry = NULL; /*global for single encap*/
#ifdef NSE_TC_FLWR_MULTI_ENCAP
	struct nse_sw_m_encap_entry *m_encap_entry = NULL; /*global for multi encap*/
#endif
	struct nse_sw_task_list *task_list = NULL; /*global*/
	struct nse_sw_meter *meter = NULL; /*global*/
	struct nse_sw_sflow *sflow = NULL; /*global*/
	struct nse_sw_task_list *cur_task_list = NULL; /*local*/
	struct nse_tc_flower_action *tc_action = &fltr->action;
	u32 act_flags = tc_action->flags;
	u16 du_act_cnt = 0, au_task_cnt = 0, du_desc_cnt = 0;
	int ret = 0, dstry_ret = 0;

#ifdef NSE_SUPPORT_FAST_FLWR
	if (nse_is_fast_flower(act_flags))
		return nse_tc_add_fast_action(vsi, fltr);
#endif

	node_state = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*node_state),
				 GFP_KERNEL);
	if (!node_state)
		return -ENOMEM;

	nse_init_node_state(node_state);

	/*1. build node_state du_action for HW DU*/
	if (act_flags & NSE_TC_FLWR_ACTION_DECAP)
		node_state->du_action[du_act_cnt++].du_act =
			NSE_DU_ACT_DECAP;

#ifdef NSE_TC_FLWR_SFLOW
	if (act_flags & NSE_TC_FLWR_ACTION_SFLOW) {
		ret = nse_sw_get_sflow(hw, &tc_action->sflow_info, &sflow);
		if (!sflow || ret) {
			dev_err(nse_hw_to_dev(hw), "Failed to get sw sflow, err = %d\n", ret);
			NL_SET_ERR_MSG_MOD(fltr->extack, "Failed to get sw sflow");
			goto add_large_action_fail;
		}

		node_state->du_action[du_act_cnt].sflow_vsi_id =
			nse_get_hw_vsi_num(hw, tc_action->sflow_dest_vsi->idx);
		node_state->du_action[du_act_cnt++].du_act =
			NSE_DU_ACT_SFLOW;

		tc_action->sflow = sflow;
	}
#endif

#if NSE_TC_FLWR_COUNT_IN_DU
	if (act_flags & NSE_TC_FLWR_ACTION_COUNT) {
		counter_p = nse_sw_creat_counter_pair(hw, true);
		if (!counter_p) {
			ret = -ENOMEM;
			dev_err(nse_hw_to_dev(hw), "Unable to creat hw counter\n");
			NL_SET_ERR_MSG_MOD(fltr->extack, "Unable to creat hw counter");
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

		tc_action->counter_p = counter_p;
	}
#endif

#if NSE_TC_FLWR_METER_IN_DU
	if (act_flags & NSE_TC_FLWR_ACTION_METER) {
		meter = nse_sw_get_meter(hw, &tc_action->meter_param);
		if (!meter) {
			ret = -ENOMEM;
			dev_err(nse_hw_to_dev(hw), "Failed to get sw meter\n");
			NL_SET_ERR_MSG_MOD(fltr->extack, "Failed to get sw meter");
			goto add_large_action_fail;
		}

		node_state->du_action[du_act_cnt].meter_id =
			meter->meter_id;
		node_state->du_action[du_act_cnt++].du_act =
			NSE_DU_ACT_METER;

		tc_action->meter = meter;
	}
#endif

	if (act_flags & NSE_TC_FLWR_ACTION_DUP) {
		node_state->du_action[du_act_cnt].copy_num =
			tc_action->copy_num;
		node_state->du_action[du_act_cnt++].du_act =
			NSE_DU_ACT_DUP;
	} else if (act_flags & NSE_TC_FLWR_ACTION_GOTO_CHAIN) {
		node_state->du_action[du_act_cnt].dest_chain =
			tc_action->dest_chain;
		node_state->du_action[du_act_cnt++].du_act =
			NSE_DU_ACT_GOTO_CHAIN;
		if (fltr->chain_id == 0 ||
				tc_action->dest_chain == NSE_CT_CHAIN_ID)
			node_state->is_slowp_orig = true;
	}
#if NSE_TC_FLWR_FWD_IN_DU
	else {
		ret = nse_fill_node_state_fwd_info(vsi, fltr, node_state, &du_act_cnt);
		if (ret) {
			dev_err(nse_hw_to_dev(hw), "fail to fill fwd info in node state\n");
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to fill fwd info in node state");
			goto add_large_action_fail;
		}
	}
#endif

	/* metedata du action should be last one*/
	if (act_flags & NSE_TC_FLWR_ACTION_SET_MD) {
		u8 i;

		for (i = 0; i < fltr->action.md_num; i++) {
			node_state->du_action[du_act_cnt].dest_mdid =
				fltr->action.dest_md_id[i];
			node_state->du_action[du_act_cnt++].du_act =
				NSE_DU_ACT_SET_GENERIC_MD;
		}
		for (i = 0; i < fltr->action.md_num; i++)
			/* meta value need another 16bits in node state*/
			node_state->md_value[i] = fltr->action.md_value[i];

		node_state->md_num = fltr->action.md_num;
	}

	/*2. build au_task_list & du_data/du_desc for HW AU*/
	if (nse_is_task_list_needed(act_flags) && nse_is_au_supported(fltr)) {
		u16 d_size = 0, t_cnt = 0;
		u16 cur_para = NSE_TASK_PARA_BASE, alloc_size;
		u16 cur_data_pos = 0;

		/*2.1 calculate task count and task data size.*/
		t_cnt = nse_calc_au_task_cnt(tc_action);
		if (!t_cnt) {
			ret = -EIO;
			dev_err(nse_hw_to_dev(hw), "fail to calculate task count\n");
			NL_SET_ERR_MSG_MOD(fltr->extack,
				"fail to calculate task count");
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

		d_size = nse_calc_du_data_size(tc_action);
		if (d_size) {
			du_data = nse_sw_creat_du_data(hw, d_size);
			if (!du_data) {
				ret = -ENOMEM;
				dev_err(nse_hw_to_dev(hw), "Unable to creat du data\n");
				NL_SET_ERR_MSG_MOD(fltr->extack,
					"Unable to creat du data");
				goto au_task_fail;
			}
			tc_action->du_data = du_data;
			node_state->du_desc[du_desc_cnt].du_data_id =
								du_data->du_desc.du_data_id;
			node_state->du_desc[du_desc_cnt].data_size =
								du_data->du_desc.data_size;
			du_desc_cnt++;
		}

		/*2.2 build each task info to local variable cur_task_list,
		 * also build each task's data to du_data obj created above.
		 */
		if (act_flags & NSE_TC_FLWR_ACTION_ALLOW)
			nse_fill_task_nop(cur_task_list, &au_task_cnt, 1);

#if !NSE_TC_FLWR_COUNT_IN_DU
		if (act_flags & NSE_TC_FLWR_ACTION_COUNT && du_data) {
			counter_p = nse_sw_creat_counter_pair(hw, true);
			if (!counter_p) {
				ret = -ENOMEM;
				dev_err(nse_hw_to_dev(hw), "Unable to creat hw counter for AU\n");
				NL_SET_ERR_MSG_MOD(fltr->extack,
						   "Unable to creat hw counter for AU");
				goto au_task_fail;
			}
			tc_action->counter_p = counter_p;
			nse_fill_task_au_count(cur_task_list, &du_data->du_desc,
				counter_p, &au_task_cnt, &cur_para, &cur_data_pos);
		}
#endif

#if !NSE_TC_FLWR_METER_IN_DU
		if (act_flags & NSE_TC_FLWR_ACTION_METER && du_data) {
			meter = nse_sw_get_meter(hw, &tc_action->meter_param);
			if (!meter) {
				ret = -ENOMEM;
				dev_err(nse_hw_to_dev(hw), "Failed to get sw meter\n");
				NL_SET_ERR_MSG_MOD(fltr->extack, "Failed to get sw meter");
				goto au_task_fail;
			}

			tc_action->meter = meter;
			nse_fill_task_au_meter(cur_task_list, &du_data->du_desc,
				meter, &au_task_cnt, &cur_para, &cur_data_pos);
		}
#endif

#if	!NSE_TC_FLWR_FWD_IN_DU
		if (((act_flags & NSE_TC_FLWR_ACTION_DROP) ||
			(act_flags & NSE_TC_FLWR_ACTION_TO_LAN) ||
			(act_flags & NSE_TC_FLWR_ACTION_FWD_VSI) ||
			(act_flags & NSE_TC_FLWR_ACTION_FWD_VSI_LIST)) && du_data) {
			ret = nse_fill_task_au_fwd(cur_task_list, &du_data->du_desc,
				fltr, &au_task_cnt, &cur_para, &cur_data_pos);
			if (ret) {
				dev_err(nse_hw_to_dev(hw), "Failed to fill au fwd task\n");
				NL_SET_ERR_MSG_MOD(fltr->extack,
						   "Failed to fill au fwd task");
				goto au_task_fail;
			}
		}
#endif

		if (act_flags & NSE_TC_FLWR_ACTION_REWRITE && du_data) {
			u32 rw_flags = tc_action->rw_flag;
			struct nse_pedit_headers *rw_hdrs = &tc_action->hdrs;
			struct nse_du_desc *du_desc = &du_data->du_desc;

			if (rw_flags & NSE_SW_REWRITE_L2_SMAC)
				nse_fill_task_rewrite_l2_smac(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);
			if (rw_flags & NSE_SW_REWRITE_L2_DMAC)
				nse_fill_task_rewrite_l2_dmac(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);
			if (rw_flags & NSE_SW_REWRITE_L2_VLAN_ID)
				nse_fill_task_rewrite_l2_vlan(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);
			if (rw_flags & NSE_SW_REWRITE_L3_TOS_V4)
				nse_fill_task_rewrite_l3_v4_tos(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);
			if (rw_flags & NSE_SW_REWRITE_L3_TTL_V4)
				nse_fill_task_rewrite_l3_ttl(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);
			if (rw_flags & NSE_SW_REWRITE_L3_SIP_V4)
				nse_fill_task_rewrite_l3_sip_v4(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);
			if (rw_flags & NSE_SW_REWRITE_L3_DIP_V4)
				nse_fill_task_rewrite_l3_dip_v4(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);
			if (rw_flags & NSE_SW_REWRITE_L3_TOS_V6)
				nse_fill_task_rewrite_l3_v6_tos(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);
			if (rw_flags & NSE_SW_REWRITE_L3_HLIMIT_V6)
				nse_fill_task_rewrite_l3_hlimit(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);
			if (rw_flags & NSE_SW_REWRITE_L3_SIP_V6)
				nse_fill_task_rewrite_l3_sip_v6(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);
			if (rw_flags & NSE_SW_REWRITE_L3_DIP_V6)
				nse_fill_task_rewrite_l3_dip_v6(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);
			if (rw_flags & NSE_SW_REWRITE_L4_SPORT)
				nse_fill_task_rewrite_l4_sport(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);
			if (rw_flags & NSE_SW_REWRITE_L4_DPORT)
				nse_fill_task_rewrite_l4_dport(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);
		}

		if (act_flags & NSE_TC_FLWR_ACTION_VLAN_POP)
			nse_fill_task_vlan_pop(cur_task_list, &au_task_cnt);

		if (act_flags & NSE_TC_FLWR_ACTION_VLAN_PUSH && du_data)
			nse_fill_task_vlan_push(cur_task_list, &du_data->du_desc,
				tc_action, &au_task_cnt, &cur_para, &cur_data_pos);

		/*Note: encap task should be processed at last*/
		if (act_flags & NSE_TC_FLWR_ACTION_DUP) {
#ifdef NSE_TC_FLWR_MULTI_ENCAP
			ret = nse_tc_attach_m_encap(vsi, fltr, tc_action, &m_encap_entry);
			if (!m_encap_entry || ret) {
				ret = -ENOMEM;
				dev_err(nse_hw_to_dev(hw), "Fail to attach multi encap entry\n");
				NL_SET_ERR_MSG_MOD(fltr->extack,
					"Fail to attach multi encap entry");
				goto au_task_fail;
			}

			tc_action->m_encap_entry = m_encap_entry;
			node_state->du_desc[du_desc_cnt].du_data_id =
								m_encap_entry->du_desc.du_data_id;
			node_state->du_desc[du_desc_cnt].data_size =
								m_encap_entry->du_desc.data_size;
			du_desc_cnt++;

			/*fill multi encap task code*/
			switch (m_encap_entry->tun_type) {
			case TNL_VXLAN:
				if (m_encap_entry->family == AF_INET)
					cur_task_list->task[au_task_cnt].task_id =
						NSE_TASK_ID_V4_VXLAN_M_ENCAP;
				else
					cur_task_list->task[au_task_cnt].task_id =
						NSE_TASK_ID_V6_VXLAN_M_ENCAP;
				break;
			default:
				ret = -EOPNOTSUPP;
				dev_err(nse_hw_to_dev(hw), "Unsupported tunnel type\n");
				NL_SET_ERR_MSG_MOD(fltr->extack, "Unsupported tunnel type");
				goto au_task_fail;
			}
			cur_task_list->task[au_task_cnt].data_para =
							NSE_TASK_PARA_BASE +
								(ALIGN(d_size, 32) >> 1);
			au_task_cnt++;
#else
			ret = -EOPNOTSUPP;
			dev_err(nse_hw_to_dev(hw), "Unsupport Multi encap actions now\n");
			goto au_task_fail;
#endif
		} else if (act_flags & NSE_TC_FLWR_ACTION_SINGLE_ENCAP) {
			ret = nse_tc_attach_encap(vsi, fltr, 0, tc_action, &encap_entry);
			if (!encap_entry || ret) {
				ret = -ENOMEM;
				dev_err(nse_hw_to_dev(hw), "Fail to attach encap entry\n");
				NL_SET_ERR_MSG_MOD(fltr->extack,
					"Fail to attach encap entry");
				goto au_task_fail;
			}

			tc_action->encap_entry = encap_entry;
			node_state->du_desc[du_desc_cnt].du_data_id =
								encap_entry->du_desc.du_data_id;
			node_state->du_desc[du_desc_cnt].data_size =
								encap_entry->du_desc.data_size;
			du_desc_cnt++;

			/*fill single encap task code*/
			switch (encap_entry->tun_type) {
			case TNL_VXLAN:
				if (encap_entry->family == AF_INET)
					cur_task_list->task[au_task_cnt].task_id =
						NSE_TASK_ID_V4_VXLAN_ENCAP;
				else
					cur_task_list->task[au_task_cnt].task_id =
						NSE_TASK_ID_V6_VXLAN_ENCAP;
				break;
			default:
				ret = -EOPNOTSUPP;
				dev_err(nse_hw_to_dev(hw), "Unsupported tunnel type\n");
				NL_SET_ERR_MSG_MOD(fltr->extack, "Unsupported tunnel type");
				goto au_task_fail;
			}
			cur_task_list->task[au_task_cnt].data_para =
							NSE_TASK_PARA_BASE +
								(ALIGN(d_size, 32) >> 1);
			au_task_cnt++;
		}

		/*2.3 add du data to FW after du data is built*/
		if (du_data) {
			ret = nse_sw_add_du_data(hw, du_data);
			if (ret) {
				ret = -EIO;
				dev_err(nse_hw_to_dev(hw), "Fail to add du data\n");
				NL_SET_ERR_MSG_MOD(fltr->extack, "Fail to add du data");
				goto au_task_fail;
			}
		}

		/*2.4 get obj from task list table, based on cur_task_list.*/
		task_list = nse_sw_get_task_list(hw, cur_task_list);
		if (!task_list) {
			ret = -ENOMEM;
			dev_err(nse_hw_to_dev(hw), "Fail to get task list\n");
			NL_SET_ERR_MSG_MOD(fltr->extack, "Fail to get task list");
			goto au_task_fail;
		}
		tc_action->task_list = task_list;
		node_state->task_list_id = task_list->task_list_id;
		devm_kfree(nse_hw_to_dev(hw), cur_task_list);
	}

	/*3. according to node_state info, add to hw */
#if NSE_TC_FLWR_FWD_IN_DU
	if (!du_act_cnt) {
		ret = -EIO;
		dev_err(nse_hw_to_dev(hw), "no any single action in du_act\n");
		NL_SET_ERR_MSG_MOD(fltr->extack, "no any single action in du_act");
		goto add_large_action_fail;
	}
#endif

	if (du_act_cnt == 1 && !au_task_cnt) {
		dev_info(nse_hw_to_dev(hw), "It is single action! act type = %d\n",
			node_state->du_action[0].du_act);
		ret = 0;
		goto add_large_action_to_single;
	}

	if (is_lite_node_state(du_act_cnt, node_state->md_num, au_task_cnt, du_desc_cnt)) {
		node_state->is_lite = true;
		ret = nse_sw_add_lite_node_state(hw, node_state, du_act_cnt);
	} else {
		node_state->is_lite = false;
		ret = nse_sw_add_node_state(hw, node_state, du_act_cnt,
				au_task_cnt, du_desc_cnt);
	}
	if (ret || node_state->node_state_id == NSE_NODE_STATE_ID_INVALID) {
		dev_err(nse_hw_to_dev(hw), "Unable to add node state\n");
		NL_SET_ERR_MSG_MOD(fltr->extack, "Unable to add node state");
		goto add_large_action_fail;
	}

	/*4. copy node_state to software fltr DB */
	node_state->du_act_cnt = du_act_cnt;
	node_state->au_task_cnt = au_task_cnt;
	node_state->du_desc_cnt = du_desc_cnt;
	tc_action->node_state = *node_state;
	tc_action->large_act_id = node_state->node_state_id;
	devm_kfree(nse_hw_to_dev(hw), node_state);
	return 0;

au_task_fail:
	if (cur_task_list)
		devm_kfree(nse_hw_to_dev(hw), cur_task_list);

add_large_action_fail:
	if (tc_action->vsi_list_id != NSE_TC_FLWR_VSI_LIST_ID_INVALID &&
		tc_action->vsi_list_info) {
		dstry_ret = nse_sw_put_adv_vlist(hw, tc_action->vsi_list_info);
		tc_action->vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;
		tc_action->vsi_list_info = NULL;
		if (dstry_ret) {
			dev_err(nse_hw_to_dev(hw), "fail to put adv vsi list\n");
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to put adv vsi list");
		}
	}

add_large_action_to_single:
	if (counter_p) {
		dstry_ret = nse_sw_destroy_counter_pair(hw, counter_p);
		tc_action->counter_p = NULL;
		if (dstry_ret) {
			dev_err(nse_hw_to_dev(hw), "fail to destroy hw counter\n");
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to destroy hw counter");
		}
	}
	if (task_list) {
		dstry_ret = nse_sw_put_task_list(hw, task_list);
		tc_action->task_list = NULL;
		if (dstry_ret) {
			dev_err(nse_hw_to_dev(hw), "fail to free task list\n");
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to free task list");
		}
	}
#ifdef NSE_TC_FLWR_SFLOW
	if (sflow) {
		dstry_ret = nse_sw_put_sflow(hw, sflow);
		tc_action->sflow = NULL;
		if (dstry_ret) {
			dev_err(nse_hw_to_dev(hw), "fail to free sflow\n");
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to free sflow");
		}
	}
#endif
	if (meter) {
		dstry_ret = nse_sw_put_meter(hw, meter);
		tc_action->meter = NULL;
		if (dstry_ret) {
			dev_err(nse_hw_to_dev(hw), "fail to free meter\n");
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to free meter");
		}
	}
	if (du_data) {
		dstry_ret = nse_sw_destroy_du_data(hw, du_data);
		tc_action->du_data = NULL;
		if (dstry_ret) {
			dev_err(nse_hw_to_dev(hw), "fail to destroy hw du data\n");
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to destroy hw du data");
		}
	}
	if (tc_action->encap_cnt) {
		int i;

		for (i = 0; i < tc_action->dest_cnt; i++) {
			kfree(tc_action->dests[i].tun_info);
			tc_action->dests[i].tun_info = NULL;
		}

		for (i = 0; i < tc_action->encap_cnt; i++)
			/*need detach encap entry's fltr list before put encap entry*/
			nse_tc_fltr_detach_encap(&tc_action->encaps[i]);
	}

	if (encap_entry) {
		dstry_ret = nse_sw_put_encap_entry(hw, encap_entry);
		tc_action->encap_entry = NULL;
		if (dstry_ret) {
			dev_err(nse_hw_to_dev(hw), "fail to destroy hw encap entry\n");
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to destroy hw encap entry");
		}
	}

	if (m_encap_entry) {
		dstry_ret = nse_sw_put_m_encap_entry(hw, m_encap_entry);
		tc_action->m_encap_entry = NULL;
		if (dstry_ret) {
			dev_err(nse_hw_to_dev(hw), "fail to destroy hw multi encap entry\n");
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to destroy hw multi encap entry");
		}
	}

	devm_kfree(nse_hw_to_dev(hw), node_state);
	return ret;
}

/**
 * nse_tc_fill_node_info
 *
 * @vsi: source vsi, where this rule add on
 * @fltr: tc flower information after previous parsing
 */
static int
nse_tc_fill_node_info(struct nse_vsi *vsi, struct nse_tc_flower_fltr *fltr,
		struct nse_adv_node_info *node_info)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_vsi *uplink_vsi = vsi->back->switchdev.uplink_vsi;
	struct nse_tc_flower_action *action = &fltr->action;
	u16 i, dest_cnt;

	node_info->sw_act.fltr_act = action->fltr_act;
	node_info->flags_info.act_valid = true;
	node_info->flags_info.act = 0;

	/*set src information*/
	if (fltr->src_vsi == uplink_vsi) {
		node_info->sw_act.flag |= NSE_FLTR_RX;
		node_info->sw_act.in_port = hw->lan_id;
		node_info->sw_act.in_port |= (NSE_IN_PORT_TYPE_LAN <<
				NSE_IN_PORT_TYPE_S) & NSE_IN_PORT_TYPE_M;
		node_info->rx = true;
	} else {
		node_info->sw_act.flag |= NSE_FLTR_TX;
		node_info->sw_act.in_port = nse_get_hw_vsi_num(hw, fltr->src_vsi->idx);
		node_info->sw_act.in_port |= (NSE_IN_PORT_TYPE_HOST <<
				NSE_IN_PORT_TYPE_S) & NSE_IN_PORT_TYPE_M;
		node_info->rx = false;
	}

	/*set toLan flag*/
	if (fltr->src_vsi != uplink_vsi &&
			action->lan_en)
		node_info->flags_info.act |= NSE_LAN_ENABLE;

	/*set LB flag*/
	if (fltr->src_vsi != uplink_vsi &&
			is_repr_vsi_in_dests(action, uplink_vsi))
		node_info->flags_info.act |= NSE_LB_ENABLE;

	/*set dest vsi information*/
	switch (action->fltr_act) {
	case NSE_FWD_TO_VSI:
		dest_cnt = action->dest_cnt;
		for (i = 0; i < dest_cnt; i++) {
			struct nse_vsi *dest_vsi = action->dests[i].dest_vsi;

			if (fltr->tc_flower) {
				if (dest_vsi != uplink_vsi)
					node_info->sw_act.fwd_id.hw_vsi_id =
							nse_get_hw_vsi_num(&dest_vsi->back->hw,
									   dest_vsi->idx);
			} else
				node_info->sw_act.fwd_id.hw_vsi_id =
						nse_get_hw_vsi_num(&dest_vsi->back->hw,
								   dest_vsi->idx);
		}
		break;
	case NSE_FWD_TO_VSI_LIST:
		node_info->sw_act.fwd_id.vsi_list_id = fltr->action.vsi_list_id;
		break;
	case NSE_FWD_TO_LAN:
	case NSE_DROP_PACKET:
	default:
		break;
	}

	return 0;
}

/**
 * nse_eswitch_set_mode -
 *			set hw to  switchdev mode.
 * @pf: primary function
 * @mode: DEVLINK_ESWITCH_MODE_SWITCHDEV
 *			or DEVLINK_ESWITCH_MODE_LEGACY
 */
int
nse_eswitch_set_mode(struct nse_pf *pf, u32 mode)
{
	enum nse_sw_mode sw_mode;
	struct nse_hw *hw = &pf->hw;
	int ret = 0;

	if (mode == DEVLINK_ESWITCH_MODE_SWITCHDEV)
		sw_mode = NSE_SW_MODE_SWITCHDEV;
	else if (mode == DEVLINK_ESWITCH_MODE_LEGACY)
		sw_mode = NSE_SW_MODE_LEGACY;
	else
		dev_err(nse_hw_to_dev(hw), "[%s, %d] switch mode err, mode = %d\n",
			__func__, __LINE__, mode);

	ret = nse_sw_set_mode(hw, &sw_mode);
	if (ret)
		dev_err(nse_hw_to_dev(hw), "[%s, %d] set hw to switch mode err, err = %d, mode = %d\n",
			__func__, __LINE__, ret, sw_mode);

	return ret;
}

/**
 * nse_eswitch_add_tc_fltr -
 *			add tc flower rule to HW in switchdev mode.
 * @vsi: source vsi, where this rule add on
 * @fltr: tc flower information after previous parsing
 */
int
nse_eswitch_add_tc_fltr(struct nse_vsi *vsi,
		struct nse_tc_flower_fltr *fltr)
{
	struct nse_tc_flower_lyr_2_4_hdrs *headers = &fltr->outer_headers;
	struct nse_adv_node_info node_info = { 0 };
	struct nse_node_query_data rule_added = { 0 };
	struct nse_hw *hw = &vsi->back->hw;
	/* lkup_elem is based on HW protocolID format */
	struct nse_adv_lkup_elem *lkups = NULL;
	u32 flags = fltr->flags;
	int lkups_cnt;
	int i, ret;

	/* 1. handle du_action in node state first */
	ret = nse_tc_add_large_action(vsi, fltr);
	if (ret) {
		dev_err(nse_hw_to_dev(hw), "Unable to add large action due to error\n");
		NL_SET_ERR_MSG_MOD(fltr->extack,
				"Unable to add large action due to error");
		goto add_large_action_fail;
	}

	if (fltr->action.large_act_id != NSE_TC_FLWR_LARGE_ACTION_INVALID) {
		node_info.sw_act.large_act_id = fltr->action.large_act_id;
		node_info.sw_act.is_lite = fltr->action.node_state.is_lite;
		node_info.sw_act.is_fast = fltr->action.node_state.is_fast;
		node_info.node_state = &fltr->action.node_state;

		if (node_info.sw_act.is_fast)
			node_info.sw_act.fltr_act = NSE_FAST_ACT;
		else
			node_info.sw_act.fltr_act = NSE_LARGE_ACT;

		/* build "fixed" key 0 - IN_PORT */
		if (fltr->src_vsi == vsi->back->switchdev.uplink_vsi) {
			node_info.sw_act.flag |= NSE_FLTR_RX;
			node_info.sw_act.in_port = hw->lan_id;
			node_info.sw_act.in_port |= (NSE_IN_PORT_TYPE_LAN <<
					NSE_IN_PORT_TYPE_S) & NSE_IN_PORT_TYPE_M;
			node_info.rx = true;
		} else {
			node_info.sw_act.flag |= NSE_FLTR_TX;
			node_info.sw_act.in_port = nse_get_hw_vsi_num(hw, fltr->src_vsi->idx);
			node_info.sw_act.in_port |= (NSE_IN_PORT_TYPE_HOST <<
					NSE_IN_PORT_TYPE_S) & NSE_IN_PORT_TYPE_M;
			node_info.rx = false;
		}
	} else {
		ret = nse_tc_fill_node_info(vsi, fltr, &node_info);
		if (ret) {
			dev_err(nse_hw_to_dev(hw), "fail to fill node info\n");
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to fill node info");
			goto exit;
		}
	}

	node_info.vsi_list_info = fltr->action.vsi_list_info;
	node_info.sw_id = hw->port_info->sw_id;

	node_info.chain_id = fltr->chain_id;

	/* start to handle match(profile & recipe & Lut) and lut node */
	lkups_cnt = nse_tc_count_lkups(flags, headers, fltr);
	lkups = kcalloc(lkups_cnt, sizeof(*lkups), GFP_ATOMIC);
	if (!lkups)
		return -ENOMEM;

	/* transfer standand network header (fltr->outer/inner_headers)
	 *  to HW protocolID format (lkups)
	 */
	i = nse_tc_fill_rules(flags, fltr, lkups, &node_info, NULL);
	if (i != lkups_cnt) {
		dev_err(nse_hw_to_dev(hw), "Unable to tc fill rules, i = %d, lkups_cnt = %d\n",
			i, lkups_cnt);
		ret = -EINVAL;
		goto exit;
	}

	dev_info(nse_hw_to_dev(hw), "[%s, %d] prot_header num = %d\n",
		__func__, __LINE__, lkups_cnt);

	for (i = 0; i < lkups_cnt; i++)
		dev_info(nse_hw_to_dev(hw), "[%s, %d] prot_header[%d]_type = %d\n",
			__func__, __LINE__, i, lkups[i].type);

	if (fltr->tunnel_type == TNL_VXLAN)
		node_info.tun_type = NSE_SW_TUN_VXLAN;

	/*add advanced node, only related to lut node.
	 * if large action/node state is used, other info such as
	 * node state/du data/task list should be handled before.
	 * tc flower should be always large action.
	 */
	ret = nse_add_adv_node(hw, lkups, lkups_cnt, &node_info, &rule_added);
	if (ret == -EEXIST) {
		dev_err(nse_hw_to_dev(hw), "Unable to add lut node because it already exist\n");
		NL_SET_ERR_MSG_MOD(fltr->extack, "Unable to add lut node because it already exist");
		ret = -EINVAL;
		goto exit;
	} else if (ret) {
		dev_err(nse_hw_to_dev(hw), "Unable to add lut node due to error\n");
		NL_SET_ERR_MSG_MOD(fltr->extack, "Unable to add lut node due to error");
		goto exit;
	}

	/* create fast node counter pair */
	if (need_fast_node_count(fltr)) {
		u16 p_hw_id = 0, b_hw_id = 0;

		ret = nse_tc_get_fast_counter_id(fltr, &p_hw_id, &b_hw_id);
		if (ret) {
			dev_err(nse_hw_to_dev(hw), "Unable to get fast node counter hw id\n");
			goto exit;
		}

		fltr->action.counter_p =
			nse_sw_creat_fast_counter_p(hw, p_hw_id, b_hw_id, true);
		if (!fltr->action.counter_p) {
			dev_err(nse_hw_to_dev(hw), "Unable to creat fast node counter pair\n");
			ret = -EIO;
			goto exit;
		}
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
 * nse_parse_cls_flower - Parse TC flower filters provided by kernel
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to the VSI
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 */
static int
nse_parse_cls_flower(struct net_device *filter_dev, struct nse_vsi *vsi,
		     struct flow_cls_offload *f,
		     struct nse_tc_flower_fltr *fltr)
{
	struct nse_tc_flower_lyr_2_4_hdrs *headers;
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	u16 n_proto_mask = 0, n_proto_key = 0, addr_type = 0;
	struct flow_dissector *dissector;
	bool match_inner_ecn = true;
	u32 unsupported_keys;

	/* headers point to outer header default*/
	headers = &fltr->outer_headers;
	dissector = rule->match.dissector;

	unsupported_keys = (u32)~(BIT(FLOW_DISSECTOR_KEY_CONTROL) |
			     BIT(FLOW_DISSECTOR_KEY_CT) |
			     BIT(FLOW_DISSECTOR_KEY_BASIC) |
			     BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
			     BIT(FLOW_DISSECTOR_KEY_CVLAN) |
			     BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
			     BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
			     BIT(FLOW_DISSECTOR_KEY_ENC_KEYID) |
			     BIT(FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) |
			     BIT(FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) |
			     BIT(FLOW_DISSECTOR_KEY_ENC_PORTS) |
			     BIT(FLOW_DISSECTOR_KEY_ENC_CONTROL) |
			     BIT(FLOW_DISSECTOR_KEY_IP) |
			     BIT(FLOW_DISSECTOR_KEY_ENC_IP) |
			     BIT(FLOW_DISSECTOR_KEY_PORTS));

	unsupported_keys &= ~BIT(FLOW_DISSECTOR_KEY_VLAN);
	unsupported_keys &= ~BIT(FLOW_DISSECTOR_KEY_PPPOE);

	if (dissector->used_keys & unsupported_keys) {
		netdev_info(filter_dev,
			"Tc flower used key(=0x%x) Unsupported\n",
				(unsigned int)dissector->used_keys);
		NL_SET_ERR_MSG_MOD(fltr->extack, "Unsupported key used");
		return -EOPNOTSUPP;
	}

	netdev_info(filter_dev, "Tc flower used key = 0x%x\n", (unsigned int)dissector->used_keys);
	netdev_info(filter_dev, "Tc flower src chain id = %d\n", fltr->chain_id);

	if (nse_is_tunnel_supported(filter_dev)) {
		int err;

		err = nse_parse_tunnel_attr(filter_dev, vsi, f, fltr, headers);
		if (err) {
			netdev_err(filter_dev,
				"Failed to parse TC flower tunnel attributes\n");
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Failed to parse TC flower tunnel attributes");
			return err;
		}

		err = nse_tc_verify_tunnel_ecn(filter_dev, fltr, f, &match_inner_ecn);
		if (err) {
			netdev_err(filter_dev,
				"Failed to verify tunnel ecn\n");
			NL_SET_ERR_MSG_MOD(fltr->extack, "Failed to verify tunnel ecn");
			return err;
		}

		/* header pointers should point to the inner headers, outer
		 * header were already set by nse_parse_tunnel_attr
		 */
		headers = &fltr->inner_headers;
		fltr->action.flags |= NSE_TC_FLWR_ACTION_DECAP;
	} else {
		fltr->tunnel_type = TNL_LAST;
	}

	/* start to parse general header: it is inner header for tunnel packet,
	 *  and it is outer header for normal packet
	 */

	/* parse match configuration of ethertype and ip protocol type */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);

		if (match.key->n_proto == htons(ETH_P_LLDP)) {
			netdev_err(filter_dev, "LLDP flower offload is unsupported\n");
			return -EOPNOTSUPP;
		}
		n_proto_key = ntohs(match.key->n_proto);
		n_proto_mask = ntohs(match.mask->n_proto);

		if (n_proto_key == ETH_P_ALL || n_proto_key == 0) {
			n_proto_key = 0;
			n_proto_mask = 0;
		} else {
			fltr->flags |= NSE_TC_FLWR_FIELD_ETH_TYPE;
		}

		netdev_info(filter_dev,	"Start to set KEY_BASIC match:\n");
		netdev_info(filter_dev,	"\t ethernet_type value(0x%x)/mask(0x%x)\n",
			cpu_to_be16(n_proto_key), cpu_to_be16(n_proto_mask));
		netdev_info(filter_dev,	"\t ip_type value(0x%x)/mask(0x%x)\n",
			match.key->ip_proto, match.mask->ip_proto);

		headers->l2_key.n_proto = cpu_to_be16(n_proto_key);
		headers->l2_mask.n_proto = cpu_to_be16(n_proto_mask);
		headers->l3_key.ip_proto = match.key->ip_proto;
		headers->l3_mask.ip_proto = match.mask->ip_proto;
	}

	/* parse match configuration of mac address, including src and dst mac addr */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs match;

		flow_rule_match_eth_addrs(rule, &match);

		if (!is_zero_ether_addr(match.key->dst)) {
			ether_addr_copy(headers->l2_key.dst_mac, match.key->dst);
			ether_addr_copy(headers->l2_mask.dst_mac, match.mask->dst);
			fltr->flags |= NSE_TC_FLWR_FIELD_DST_MAC;

			netdev_info(filter_dev,	"Start to set KEY_ETH_ADDRS dst match:\n");
			netdev_info(filter_dev,	"\t DMac Address Value = %pM\n", match.key->dst);
			netdev_info(filter_dev,	"\t DMac Address Mask = %pM\n", match.mask->dst);
		}

		if (!is_zero_ether_addr(match.key->src)) {
			ether_addr_copy(headers->l2_key.src_mac, match.key->src);
			ether_addr_copy(headers->l2_mask.src_mac, match.mask->src);
			fltr->flags |= NSE_TC_FLWR_FIELD_SRC_MAC;

			netdev_info(filter_dev, "Start to set KEY_ETH_ADDRS src match:\n");
			netdev_info(filter_dev, "\t SMac Address Value = %pM\n", match.key->src);
			netdev_info(filter_dev, "\t SMac Address Mask = %pM\n", match.mask->src);
		}
	}

	/* parse match configuration of stag */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN) ||
	    is_vlan_dev(filter_dev)) {
		struct flow_dissector_key_vlan mask;
		struct flow_dissector_key_vlan key;
		struct flow_match_vlan match;

		/* pvid of vlan netdev has high priority */
		if (is_vlan_dev(filter_dev)) {
			match.key = &key;
			match.key->vlan_id = vlan_dev_vlan_id(filter_dev);
			match.key->vlan_priority = 0;
			match.mask = &mask;
			memset(match.mask, 0xff, sizeof(*match.mask));
			match.mask->vlan_priority = 0;
		} else {
			flow_rule_match_vlan(rule, &match);
		}

		if (match.mask->vlan_id) {
			if (match.mask->vlan_id == VLAN_VID_MASK) {
				fltr->flags |= NSE_TC_FLWR_FIELD_VLAN;
			} else {
				netdev_info(filter_dev, "Bad VLAN mask\n");
				NL_SET_ERR_MSG_MOD(fltr->extack, "Bad VLAN mask");
				return -EINVAL;
			}
		}

		headers->vlan_hdr.vlan_id =
				cpu_to_be16(match.key->vlan_id & VLAN_VID_MASK);
		if (match.mask->vlan_priority)
			headers->vlan_hdr.vlan_prio = match.key->vlan_priority;

		netdev_info(filter_dev, "Start to set KEY_VLAN match:\n");
		netdev_info(filter_dev, "\t Vlan ID Value = 0x%x\n", match.key->vlan_id);
		netdev_info(filter_dev, "\t Vlan ID Mask must be 0xFFF\n");
		netdev_info(filter_dev, "\t Vlan priority Value = 0x%x\n",
			    match.key->vlan_priority);
	}

	/* parse match configuration of cvlan */
/*todo - @hujiwei - todo after double vlan finish*/

	/* parse match configuration of pppoe */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PPPOE)) {
		struct flow_match_pppoe match;

		flow_rule_match_pppoe(rule, &match);
		n_proto_key = nse_tc_set_pppoe(&match, fltr, headers);

		/* If ethertype equals ETH_P_PPP_SES, n_proto might be
		 * overwritten by encapsulated protocol (ppp_proto field) or set
		 * to 0. To correct this, flow_match_pppoe provides the type
		 * field, which contains the actual ethertype (ETH_P_PPP_SES).
		 */
		headers->l2_key.n_proto = cpu_to_be16(n_proto_key);
		headers->l2_mask.n_proto = cpu_to_be16(0xFFFF);
		fltr->flags |= NSE_TC_FLWR_FIELD_ETH_TYPE;
	}

	/* parse match configuration of ip address, including ipv4 and ipv6 address */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control match;

		flow_rule_match_control(rule, &match);

		if (match.mask->flags & FLOW_DIS_FIRST_FRAG) {
			netdev_err(filter_dev, "Match on frag first/later is not supported\n");
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Match on frag first/later is not supported");
			return -EOPNOTSUPP;
		}

		if (match.mask->flags & FLOW_DIS_IS_FRAGMENT)
			netdev_info(filter_dev, "Match on is_fragment, val is %d\n",
				!!(match.key->flags & FLOW_DIS_IS_FRAGMENT));

		addr_type = match.key->addr_type;
	}
	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);

		netdev_info(filter_dev,
			"Start to set KEY_IPV4_ADDRS match\n");
		netdev_info(filter_dev,
			"\t ipv4 dst addrs key(%pI4)/mask(%pI4)\n",
				&match.key->dst, &match.mask->dst);
		netdev_info(filter_dev,
			"\t ipv4 src addrs key(%pI4)/mask(%pI4)\n",
				&match.key->src, &match.mask->src);

		if (nse_tc_set_ipv4(&match, fltr, headers, false))
			return -EINVAL;
	}
	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_ipv6_addrs(rule, &match);

		netdev_info(filter_dev,
			"Start to set KEY_IPV6_ADDRS match\n");
		netdev_info(filter_dev,
			"\t ipv6 dst addrs key(%pI6c)/mask(%pI6c)\n",
				&match.key->dst, &match.mask->dst);
		netdev_info(filter_dev,
			"\t ipv6 src addrs key(%pI6c)/mask(%pI6c)\n",
				&match.key->src, &match.mask->src);

		if (nse_tc_set_ipv6(&match, fltr, headers, false))
			return -EINVAL;
	}

	/* parse match configuration of ip ttl and ip tos */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
		struct flow_match_ip match;

		flow_rule_match_ip(rule, &match);

		if (match.mask->tos) {
			fltr->flags |= NSE_TC_FLWR_FIELD_IP_TOS;
			headers->l3_key.tos = match.key->tos;
			headers->l3_mask.tos = match.mask->tos;
			if (!match_inner_ecn) {
				headers->l3_key.tos &= ~0x3;
				headers->l3_mask.tos &= ~0x3;
			}
		}

		if (match.mask->ttl) {
			fltr->flags |= NSE_TC_FLWR_FIELD_IP_TTL;
			headers->l3_key.ttl = match.key->ttl;
			headers->l3_mask.ttl = match.mask->ttl;
		}

		netdev_info(filter_dev,
			"Start to set KEY_IP tos/ttl match\n");
		netdev_info(filter_dev,
			"\t ip tos key(0x%x)/mask(0x%x)\n",
				headers->l3_key.tos, headers->l3_mask.tos);
		netdev_info(filter_dev,
			"\t ip ttl key(0x%x)/mask(0x%x)\n",
				match.key->ttl, match.mask->ttl);
	}

	/* parse match configuration of l4 port */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);

		netdev_info(filter_dev,
			"Start to set KEY_PORTS match\n");
		netdev_info(filter_dev,
			"\t ip protocol = 0x%x\n", headers->l3_key.ip_proto);
		netdev_info(filter_dev,
			"\t src port key(0x%x)/mask(0x%x)\n",
			match.key->src, match.mask->src);
		netdev_info(filter_dev,
			"\t dst port key(0x%x)/mask(0x%x)\n",
			match.key->dst, match.mask->dst);

		if (nse_tc_set_port(&match, fltr, headers, false))
			return -EINVAL;
		switch (headers->l3_key.ip_proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			break;
		default:
			netdev_err(filter_dev, "Only UDP and TCP transport are supported\n");
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Only UDP and TCP transport are supported");
			return -EINVAL;
		}
	}
	return 0;
}

/**
 * nse_csum_offload_supported - check tc action is supported or not.
 * @filter_dev: Pointer to device on which filter is being added
 * @update_flags: checksum update flags
 */
static bool
nse_csum_offload_supported(struct net_device *filter_dev,
				   u32 update_flags)
{
	u32 prot_flags = TCA_CSUM_UPDATE_FLAG_IPV4HDR | TCA_CSUM_UPDATE_FLAG_TCP |
			 TCA_CSUM_UPDATE_FLAG_UDP;

	if (update_flags & ~prot_flags) {
		netdev_warn(filter_dev,
			    "can't offload TC csum action for some header/s - flags %#x\n",
			    update_flags);
		return false;
	}

	return true;
}

/**
 * nse_rewrite_match_supported - check rewrite action is supported or not.
 * @filter_dev: Pointer to device on which filter is being added
 * @fltr: Pointer to TC flower filter structure
 */
static bool
nse_rewrite_match_supported(struct net_device *filter_dev,
		struct nse_tc_flower_fltr *fltr)
{
	struct nse_tc_flower_lyr_2_4_hdrs *headers = NULL;
	struct nse_tc_flower_action *tc_action = &fltr->action;
	bool modify_ip_header = false;
	u8 ip_proto = 0;

	if (fltr->action.flags & NSE_TC_FLWR_ACTION_DECAP)
		headers = &fltr->inner_headers;
	else
		headers = &fltr->outer_headers;

	ip_proto = headers->l3_key.ip_proto;
	modify_ip_header = (tc_action->rw_flag & NSE_SW_REWRITE_L3_SIP_V4) ||
					(tc_action->rw_flag & NSE_SW_REWRITE_L3_DIP_V4) ||
					(tc_action->rw_flag & NSE_SW_REWRITE_L3_TOS_V4) ||
					(tc_action->rw_flag & NSE_SW_REWRITE_L3_SIP_V6) ||
					(tc_action->rw_flag & NSE_SW_REWRITE_L3_DIP_V6) ||
					(tc_action->rw_flag & NSE_SW_REWRITE_L3_TOS_V6);

	if (modify_ip_header && ip_proto != IPPROTO_TCP &&
		ip_proto != IPPROTO_UDP && ip_proto != IPPROTO_ICMP) {
		netdev_info(filter_dev, "can't offload re-write of ip proto %d\n",
				ip_proto);
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "can't offload re-write of non TCP/UDP/ICMP");
		return false;
	}

	return true;
}

/**
 * nse_is_actions_supported - check tc action is supported or not.
 * @filter_dev: Pointer to device on which filter is being added
 * @fltr: Pointer to TC flower filter structure
 */
static int
nse_is_actions_supported(struct net_device *filter_dev,
		struct nse_tc_flower_fltr *fltr)
{
	struct nse_tc_flower_action *action = &fltr->action;

	if (action->encap_cnt && action->encap_cnt != action->dest_cnt)
		return -EOPNOTSUPP;

	if (action->flags & NSE_TC_FLWR_ACTION_DROP &&
		action->flags & NSE_TC_FLWR_ACTION_REWRITE) {
		netdev_info(filter_dev, "Drop with pedit action is not supported\n");
		NL_SET_ERR_MSG_MOD(fltr->extack,
			"Drop with pedit action is not supported");
		return -EOPNOTSUPP;
	}

	if (action->flags & NSE_TC_FLWR_ACTION_REWRITE &&
		!nse_rewrite_match_supported(filter_dev, fltr)) {
		return -EOPNOTSUPP;
	}

	if (action->flags & NSE_TC_FLWR_ACTION_GOTO_CHAIN &&
		(action->flags & NSE_TC_FLWR_ACTION_DROP ||
		action->flags & NSE_TC_FLWR_ACTION_TO_LAN ||
		action->flags & NSE_TC_FLWR_ACTION_FWD_VSI ||
		action->flags & NSE_TC_FLWR_ACTION_FWD_VSI_LIST ||
		action->flags & NSE_TC_FLWR_ACTION_DUP)) {
		netdev_err(filter_dev,
			"Goto can't do together with fwd action, flags = 0x%x\n",
			action->flags);
		return -EOPNOTSUPP;
	}

	if (action->flags & NSE_TC_FLWR_ACTION_GOTO_CHAIN &&
		(action->flags & NSE_TC_FLWR_ACTION_DECAP ||
		action->flags & NSE_TC_FLWR_ACTION_SINGLE_ENCAP)) {
		netdev_err(filter_dev,
			"Goto can't do together with decap/encap action, flags = 0x%x\n",
			action->flags);
		return -EOPNOTSUPP;
	}

	if (fltr->chain_id &&
		action->flags & NSE_TC_FLWR_ACTION_SFLOW) {
		netdev_err(filter_dev,
			"sflow action isn't supported when src_chain != 0, flags = 0x%x\n",
			action->flags);
		return -EOPNOTSUPP;
	}

	return 0;
}

/**
 * nse_dup_action_is_need
 * @action: parsed tc flower action info
 */
static bool
nse_dup_action_is_need(struct nse_tc_flower_action *action)
{
	//return (action->encap_cnt >= 1);
	u32 flags = action->flags;

	return ((flags & NSE_TC_FLWR_ACTION_SINGLE_ENCAP &&
			flags & NSE_TC_FLWR_ACTION_FWD_VSI) ||
			(flags & NSE_TC_FLWR_ACTION_SINGLE_ENCAP &&
			flags & NSE_TC_FLWR_ACTION_FWD_VSI_LIST) ||
			action->encap_cnt > 1);
}

/**
 * nse_post_parse_actions -parse entire actions after parsing one by one.
 * @action: parsed tc flower action info
 */
static void
nse_post_parse_actions(struct nse_tc_flower_action *action)
{
	/*Parse destinations after actions parsing*/
	if (action->dest_cnt == 1 && action->lan_en) {
		action->fltr_act = NSE_FWD_TO_LAN;
		action->flags |= NSE_TC_FLWR_ACTION_TO_LAN |
				NSE_TC_FLWR_ACTION_COUNT;
	}
#if	NSE_TC_FLWR_ALL_VLIST_FWD
	else if (action->dest_cnt) {
		action->fltr_act = NSE_FWD_TO_VSI_LIST;
		action->flags |= NSE_TC_FLWR_ACTION_FWD_VSI_LIST |
				NSE_TC_FLWR_ACTION_COUNT;
	}
#else
	else if (action->dest_cnt == 1 ||
		(action->dest_cnt == 2 && action->lan_en)) {
		action->fltr_act = NSE_FWD_TO_VSI;
		action->flags |= NSE_TC_FLWR_ACTION_FWD_VSI |
				NSE_TC_FLWR_ACTION_COUNT;
	} else if (action->dest_cnt > 1) {
		action->fltr_act = NSE_FWD_TO_VSI_LIST;
		action->flags |= NSE_TC_FLWR_ACTION_FWD_VSI_LIST |
				NSE_TC_FLWR_ACTION_COUNT;
	}
#endif

	/*set encap flag*/
	if (action->encap_cnt == 1)
		action->flags |= NSE_TC_FLWR_ACTION_SINGLE_ENCAP;

	/*set dup action*/
	if (nse_dup_action_is_need(action)) {
		u16 local_fwd = 0;

		action->flags &= ~(NSE_TC_FLWR_ACTION_FWD_VSI |
			NSE_TC_FLWR_ACTION_FWD_VSI_LIST | NSE_TC_FLWR_ACTION_TO_LAN |
			NSE_TC_FLWR_ACTION_SINGLE_ENCAP);
		action->flags |= NSE_TC_FLWR_ACTION_DUP;
		/* "-1" is due to exclude original pkt*/
		action->copy_num = action->encap_cnt + local_fwd - 1;
	}
}

/**
 * nse_parse_tc_flower_actions - Parse the actions for a TC filter
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to source VSI, pf main vsi or vf vsi. (it is pf vsi when virtual netdev)
 * @cls_flower: Pointer to TC flower offload structure
 * @fltr: Pointer to TC flower filter structure
 *
 * Parse the actions for a TC filter
 */
static int
nse_parse_tc_flower_actions(struct net_device *filter_dev, struct nse_vsi *vsi,
			    struct flow_cls_offload *cls_flower,
			    struct nse_tc_flower_fltr *fltr)
{
	struct nse_pedit_headers *hdrs = &fltr->action.hdrs;
	const struct ip_tunnel_info *tun_info = NULL;
	bool encap = false, decap = false;
	int err;
	int max_chain;

	struct flow_rule *rule = flow_cls_offload_flow_rule(cls_flower);
	struct flow_action *flow_action = &rule->action;
	struct flow_action_entry *act;
	int i;

	/* if there is no action in rule, return error */
	if (!flow_action_has_entries(flow_action)) {
		netdev_err(filter_dev, "Tc flower fltr has no Action\n");
		return -EINVAL;
	}

	if (!flow_action_hw_stats_check(flow_action, fltr->extack,
					FLOW_ACTION_HW_STATS_DELAYED_BIT)) {
		NL_SET_ERR_MSG_MOD(fltr->extack, "Flow action HW stats type is not supported");
		return -EOPNOTSUPP;
	}

	/* start to parse action one by one, only support switchdev mode*/
	flow_action_for_each(i, act, flow_action)
	{
		switch (act->id) {
		case FLOW_ACTION_DROP:
			fltr->action.fltr_act = NSE_DROP_PACKET;
			fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP |
				NSE_TC_FLWR_ACTION_COUNT;
			netdev_info(filter_dev, "Tc flower fltr set drop action\n");
			break;
		case FLOW_ACTION_CSUM:
			if (nse_csum_offload_supported(filter_dev, act->csum_flags))
				break;
			return -EOPNOTSUPP;
		case FLOW_ACTION_REDIRECT:
		case FLOW_ACTION_MIRRED:

			netdev_info(filter_dev,
				"Tc flower fltr set redirect action, target dev = %s\n",
				act->dev->name);

			if (encap) {
				err = nse_tc_setup_encap_redirect_action(filter_dev, vsi,
							fltr, act->dev, tun_info);
				encap = false;
			} else
				err = nse_tc_setup_redirect_action(filter_dev, vsi,
							fltr, act->dev);

			if (err) {
				netdev_err(filter_dev, "Failed to parse redirect action\n");
				return err;
			}

			break;
		case FLOW_ACTION_MANGLE:
			err = nse_tc_setup_pedit_action(filter_dev, fltr, act, hdrs);
			if (err) {
				netdev_err(filter_dev, "Failed to parse mangle action\n");
				return err;
			}
			break;
		case FLOW_ACTION_TUNNEL_DECAP:
			decap = true;
			break;
		case FLOW_ACTION_TUNNEL_ENCAP:
			tun_info = act->tunnel;
			if (tun_info)
				encap = true;
			else
				return -EOPNOTSUPP;

			netdev_info(filter_dev, "Tc flower fltr set TUNNEL_ENCAP action\n");
	    netdev_info(filter_dev, "\t tunnel type is %s\n",
				tun_info->mode & IP_TUNNEL_INFO_IPV6 ? "ipv6" : "ipv4");
			if (tun_info->mode & IP_TUNNEL_INFO_IPV6) {
				netdev_info(filter_dev, "\t IPV6 SIP Value = %pI6c\n",
					&tun_info->key.u.ipv6.src);
				netdev_info(filter_dev, "\t IPV6 DIP Value = %pI6c\n",
					&tun_info->key.u.ipv6.dst);
			} else {
				netdev_info(filter_dev, "\t IPV4 SIP Value = %pI4\n",
					&tun_info->key.u.ipv4.src);
				netdev_info(filter_dev, "\t IPV4 DIP Value = %pI4\n",
					&tun_info->key.u.ipv4.dst);
			}
			break;
		case FLOW_ACTION_POLICE:
			err = nse_tc_police_action(filter_dev, fltr, act);
			if (err) {
				netdev_err(filter_dev, "Failed to parse meter/police action\n");
				return err;
			}
			break;
		case FLOW_ACTION_VLAN_PUSH:
		case FLOW_ACTION_VLAN_POP:
			if (act->id == FLOW_ACTION_VLAN_PUSH &&
			    (fltr->action.flags & NSE_TC_FLWR_ACTION_VLAN_POP)) {
				/* Replace vlan pop+push with vlan modify */
				fltr->action.flags &= ~NSE_TC_FLWR_ACTION_VLAN_POP;
				err = add_tc_vlan_rewrite_action(filter_dev, fltr, act, hdrs);
			} else {
				err = nse_tc_vlan_action(filter_dev, fltr, act);
			}

			if (err) {
				netdev_err(filter_dev, "Failed to parse vlan action\n");
				return err;
			}
			break;
		case FLOW_ACTION_VLAN_MANGLE:
			err = add_tc_vlan_rewrite_action(filter_dev, fltr, act, hdrs);
			if (err) {
				netdev_err(filter_dev, "Failed to parse vlan rewrite action\n");
				return err;
			}
			break;

		case FLOW_ACTION_CT:
			err = nse_tc_ct_action(filter_dev, fltr, act);
			if (err) {
				netdev_err(filter_dev, "Failed to parse ct action\n");
				return err;
			}
			break;

		case FLOW_ACTION_GOTO:
			if (nse_tcam_less)
				max_chain = 0;
			else
				max_chain = NSE_MAX_CHAIN_NUM - 1;

			if (act->chain_index > max_chain) {
				netdev_err(filter_dev, "Dest chain id(%d) is bigger than max chain id(%d)\n",
					act->chain_index, max_chain);
				return -EOPNOTSUPP;
			}

			fltr->action.flags |= NSE_TC_FLWR_ACTION_GOTO_CHAIN |
				NSE_TC_FLWR_ACTION_COUNT;
			fltr->action.dest_chain = act->chain_index;
			netdev_info(filter_dev,
				"Tc flower fltr set goto action, dest chain = %d\n",
				fltr->action.dest_chain);
			break;
#ifdef NSE_TC_FLWR_SFLOW
		case FLOW_ACTION_SAMPLE:
			fltr->action.flags |= NSE_TC_FLWR_ACTION_SFLOW |
				NSE_TC_FLWR_ACTION_COUNT;
			fltr->action.sflow_info.rate = act->sample.rate;
			fltr->action.sflow_info.group_num =
						act->sample.psample_group->group_num;
			if (act->sample.truncate)
				fltr->action.sflow_info.trunc_size =
						act->sample.trunc_size;

			if (vsi == vsi->back->switchdev.uplink_vsi)
				fltr->action.sflow_dest_vsi = vsi->back->switchdev.uplink_vsi;
			else
				fltr->action.sflow_dest_vsi = vsi->back->switchdev.control_vsi;

			if (!fltr->action.sflow_dest_vsi) {
				netdev_err(filter_dev, "Failed to get sflow dest vsi\n");
				return -EIO;
			}
			netdev_info(filter_dev,
				"Tc flower fltr set sflow action, rate = %d, group = %d, is_trunc = %d, trunc_size = %d\n",
				act->sample.rate, act->sample.psample_group->group_num,
				act->sample.truncate, act->sample.trunc_size);
			break;
#endif
		default:
			netdev_info(filter_dev, "Unsupported action(=%d) in switchdev mode\n",
				act->id);
			NL_SET_ERR_MSG_MOD(fltr->extack,
				"Unsupported action in switchdev mode");
			return -EOPNOTSUPP;
		}
	}

	nse_post_parse_actions(&fltr->action);

	err = nse_is_actions_supported(filter_dev, fltr);
	if (err) {
		netdev_err(filter_dev, "Failed to check tc actions\n");
		return err;
	}

	return 0;
}

/**
 * nse_add_switch_fltr - Add TC flower filters
 * @vsi: Pointer to VSI
 * @fltr: Pointer to struct nse_tc_flower_fltr
 *
 * Add filter in HW switch block
 */
static int
nse_add_switch_fltr(struct nse_vsi *vsi, struct nse_tc_flower_fltr *fltr)
{
	struct nse_hw *hw = &vsi->back->hw;

	if (nse_is_eswitch_mode_switchdev(vsi->back)) {
		if (fltr->action.flags & NSE_TC_FLWR_ACTION_CT)
			return nse_tc_ct_add_fltr(vsi, fltr);

		return nse_eswitch_add_tc_fltr(vsi, fltr);
	}

	dev_err(nse_hw_to_dev(hw),
		"Failed to add switch fltr, not in switchdev mode\n");
	return -EOPNOTSUPP;
}

/**
 * nse_del_tc_fltr - deletes a filter from HW table
 * @vsi: Pointer to source VSI, pf main vsi or vf vsi. (it is pf vsi when virtual netdev)
 * @fltr: Pointer to struct nse_tc_flower_fltr
 *
 * This function deletes a filter from HW table and manages book-keeping
 */
void nse_del_tc_fltr(struct nse_vsi *vsi, struct nse_tc_flower_fltr *fltr)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_node_query_data node_rem;
	struct nse_tc_flower_action *tc_action = &fltr->action;
	int ret = 0;

	if (tc_action->flags & NSE_TC_FLWR_ACTION_CT)
		return nse_tc_ct_del_fltr(vsi, fltr);

	node_rem.lut_id = fltr->lut_id;
	node_rem.node_id = fltr->node_id;

#ifdef NSE_SUPPORT_FAST_FLWR
	if (tc_action->node_state.is_fast) {
		if (tc_action->node_state.is_fast_created) {
			ret = nse_rem_adv_fast_node(hw, &node_rem);
			if (ret)
				dev_err(nse_hw_to_dev(hw),
					"Failed to remove adv fast node, err = %d\n", ret);

			if (tc_action->counter_p) {
				ret = nse_sw_destroy_counter_pair(hw, tc_action->counter_p);
				tc_action->counter_p = NULL;
				if (ret)
					dev_err(nse_hw_to_dev(hw),
						"fail to destroy fast node counter, err = %d\n",
							ret);
			}
		}
		return;
	}
#endif

	/*Step1. remove advanced node, only related to lut node.
	 * if large action/node state is used, other info such as
	 * node state/du data/task list should be removed later.
	 * tc flower should be always large action.
	 */
	if (node_rem.node_id) {
		ret = nse_rem_adv_node_by_id(hw, &node_rem);
		if (ret) {
			if (ret == -ENOENT) {
				dev_err(nse_hw_to_dev(hw),
					"Filter does not exist, err = %d\n", ret);
				NL_SET_ERR_MSG_MOD(fltr->extack, "Filter does not exist");
			}
			dev_err(nse_hw_to_dev(hw), "fail to delete lut node, err = %d\n", ret);
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to delete lut node");
		}
	}

	/*Step2. after removing lut node,
	 * start to remove vsi_list/node state/counter/task list/du_data
	 */
	if (tc_action->vsi_list_id != NSE_TC_FLWR_VSI_LIST_ID_INVALID &&
		tc_action->vsi_list_info) {
		ret = nse_sw_put_adv_vlist(hw, tc_action->vsi_list_info);
		tc_action->vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;
		tc_action->vsi_list_info = NULL;
		if (ret) {
			dev_err(nse_hw_to_dev(hw), "Failed to put adv vsi list, err = %d\n", ret);
			NL_SET_ERR_MSG_MOD(fltr->extack, "Failed to put adv vsi list");
		}
	}

	if (tc_action->large_act_id != NSE_TC_FLWR_LARGE_ACTION_INVALID) {
		struct nse_node_state *node_state = &tc_action->node_state;

		if (node_state->is_lite)
			ret = nse_sw_rem_lite_node_state(hw, &tc_action->large_act_id);
		else
			ret = nse_sw_rem_node_state(hw, &tc_action->large_act_id);

		tc_action->large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
		if (ret) {
			dev_err(nse_hw_to_dev(hw), "Failed to remove node state, err = %d\n", ret);
			NL_SET_ERR_MSG_MOD(fltr->extack, "Failed to remove node state");
		}
	}

	if (tc_action->counter_p) {
		ret = nse_sw_destroy_counter_pair(hw, tc_action->counter_p);
		tc_action->counter_p = NULL;
		if (ret) {
			dev_err(nse_hw_to_dev(hw), "fail to destroy hw counter, err = %d\n", ret);
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to destroy hw counter");
		}
	}

	if (tc_action->task_list) {
		ret = nse_sw_put_task_list(hw, tc_action->task_list);
		tc_action->task_list = NULL;
		if (ret) {
			dev_err(nse_hw_to_dev(hw), "fail to free task list, err = %d\n", ret);
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to free task list");
		}
	}
#ifdef NSE_TC_FLWR_SFLOW
	if (tc_action->sflow) {
		ret = nse_sw_put_sflow(hw, tc_action->sflow);
		tc_action->sflow = NULL;
		if (ret) {
			dev_err(nse_hw_to_dev(hw), "fail to free sflow, err = %d\n", ret);
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to free sflow");
		}
	}
#endif

	if (tc_action->meter) {
		ret = nse_sw_put_meter(hw, tc_action->meter);
		tc_action->meter = NULL;
		if (ret) {
			dev_err(nse_hw_to_dev(hw), "fail to free meter, err = %d\n", ret);
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to free meter");
		}
	}

	if (tc_action->du_data) {
		ret = nse_sw_destroy_du_data(hw, tc_action->du_data);
		tc_action->du_data = NULL;
		if (ret) {
			dev_err(nse_hw_to_dev(hw), "fail to destroy hw du data, err = %d\n", ret);
			NL_SET_ERR_MSG_MOD(fltr->extack, "fail to destroy hw du data");
		}
	}

	if (tc_action->encap_cnt) {
		int i;

		for (i = 0; i < tc_action->dest_cnt; i++) {
			kfree(tc_action->dests[i].tun_info);
			tc_action->dests[i].tun_info = NULL;
		}

		for (i = 0; i < tc_action->encap_cnt; i++)
			/*need detach encap entry's fltr list before put encap entry*/
			nse_tc_fltr_detach_encap(&tc_action->encaps[i]);

		if (tc_action->encap_entry) {
			ret = nse_sw_put_encap_entry(hw, tc_action->encap_entry);
			tc_action->encap_entry = NULL;
			if (ret) {
				dev_err(nse_hw_to_dev(hw),
					"fail to destroy hw encap entry, err = %d\n", ret);
				NL_SET_ERR_MSG_MOD(fltr->extack, "fail to destroy hw encap entry");
			}
		}

		if (tc_action->m_encap_entry) {
			ret = nse_sw_put_m_encap_entry(hw, tc_action->m_encap_entry);
			tc_action->m_encap_entry = NULL;
			if (ret) {
				dev_err(nse_hw_to_dev(hw),
					"fail to destroy hw multi encap entry, err = %d\n", ret);
				NL_SET_ERR_MSG_MOD(fltr->extack,
						   "fail to destroy hw multi encap entry");
			}
		}
	}
}

/**
 * nse_get_tc_fltr - get a filter from HW table
 *      -  ref_cnt ++
 * @vsi: Pointer to source VSI, pf main vsi or vf vsi. (it is pf vsi when virtual netdev)
 * @fltr: Pointer to struct nse_tc_flower_fltr
 *
 */
void nse_get_tc_fltr(struct nse_tc_flower_fltr *fltr)
{
	refcount_inc(&fltr->ref_cnt);
}

/**
 * nse_put_tc_fltr - put a filter from HW table
 *      -- ref_cnt -- ,and delete the filter once ref_cnt == 0
 * @vsi: Pointer to source VSI, pf main vsi or vf vsi. (it is pf vsi when virtual netdev)
 * @fltr: Pointer to struct nse_tc_flower_fltr
 *
 */
void nse_put_tc_fltr(struct nse_vsi *vsi, struct nse_tc_flower_fltr *fltr)
{
	struct nse_hw *hw = &vsi->back->hw;

	if (!refcount_dec_and_test(&fltr->ref_cnt))
		return;
	dev_info(nse_hw_to_dev(hw), "Start to del fltr\n");
	dev_info(nse_hw_to_dev(hw),
		"\t fltr: cookie = %lx, lut_id = %d, node_id = 0x%x, node_state_id = 0x%x, ref_cnt = %d\n",
		fltr->cookie, fltr->lut_id, fltr->node_id,
		fltr->action.large_act_id, refcount_read(&fltr->ref_cnt));
	nse_del_tc_fltr(fltr->src_vsi, fltr);
	kfree(fltr);
}

/**
 * nse_tc_fltr_all_encaps_valid
 *	check current fltr's encap items are all valid
 *
 * @fltr: Pointer to struct nse_tc_flower_fltr
 *
 */
bool nse_tc_fltr_all_encaps_valid(struct nse_tc_flower_fltr *fltr)
{
	struct nse_tc_flower_action *tc_action = &fltr->action;
	bool encaps_vld = true;
	int i;

	for (i = 0; i < tc_action->encap_cnt; i++) {
		struct nse_sw_encap_item *encap_item = &tc_action->encaps[i];

		if (encap_item->e && !encap_item->e->valid) {
			encaps_vld = false;
			break;
		}
	}

	return encaps_vld;
}

/**
 * nse_tc_fltr_enable_slowpath - enable a filter's slowpath
 * @vsi: Pointer to VSI
 * @fltr: Pointer to struct nse_tc_flower_fltr
 *
 */
int nse_tc_fltr_enable_slowpath(struct nse_vsi *vsi, struct nse_tc_flower_fltr *fltr)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_tc_flower_action *action = &fltr->action;
	int err = 0;

	if (action->node_state.is_slowpath)
		return 0;

	if (fltr->action.large_act_id != NSE_TC_FLWR_LARGE_ACTION_INVALID) {
		err = nse_sw_set_slowpath(hw, &fltr->action.node_state, true);
		if (err)
			dev_err(nse_hw_to_dev(hw),
				"Failed to nse_sw_enable_slowpath, err = %d, node state id = %d\n",
				err, fltr->action.large_act_id);

		action->node_state.is_slowpath = true;
	}

	return err;
}

/**
 * nse_tc_fltr_disable_slowpath - disable a filter's slowpath
 * @vsi: Pointer to VSI
 * @fltr: Pointer to struct nse_tc_flower_fltr
 *
 */
int nse_tc_fltr_disable_slowpath(struct nse_vsi *vsi, struct nse_tc_flower_fltr *fltr)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_tc_flower_action *action = &fltr->action;
	int err = 0;

	if (!action->node_state.is_slowpath)
		return 0;

	if (fltr->action.large_act_id != NSE_TC_FLWR_LARGE_ACTION_INVALID) {
		err = nse_sw_set_slowpath(hw, &fltr->action.node_state, false);
		if (err)
			dev_err(nse_hw_to_dev(hw),
				"Failed to nse_sw_disable_slowpath, err = %d, node state id = %d\n",
				err, fltr->action.large_act_id);

		action->node_state.is_slowpath = false;
	}

	return err;
}

/**
 * nse_tc_fltr_init - initial TC flower filters
 * @vsi: Pointer to VSI
 * @fltr: Pointer to struct nse_tc_flower_fltr
 *
 */
void nse_tc_fltr_init(struct nse_vsi *vsi, struct nse_tc_flower_fltr *fltr)
{
	/* source VSI (it could be Uplink VSI, VF VSI) */
	fltr->src_vsi = vsi;
	fltr->tc_flower = true;
	refcount_set(&fltr->ref_cnt, 1);
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->flags |= NSE_TC_FLWR_FIELD_IN_PORT;
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;
	fltr->action.meter_param.mode = NSE_RATE_LIMIT_INVLID;
	fltr->action.node_state.is_slowpath = false;
	fltr->tunnel_type = TNL_LAST;
}

/**
 * nse_add_tc_fltr - adds a TC flower filter into HW
 * @netdev: Pointer to filter netdev,
 *          could be pf netdev , or vf repr netdev, or virtual netdev (such as vxlan netdev)
 * @vsi: Pointer to source VSI, pf main vsi or vf vsi. (it is pf vsi when virtual netdev)
 * @f: Pointer to flower offload structure
 * @__fltr: return pointer to struct nse_tc_flower_fltr
 *
 * This function parses TC-flower input fields, parses action,
 * and adds a filter.
 */
static int
nse_add_tc_fltr(struct net_device *netdev, struct nse_vsi *vsi,
		struct flow_cls_offload *f,
		struct nse_tc_flower_fltr **__fltr)
{
	struct nse_tc_flower_fltr *fltr;
	int err;

	*__fltr = NULL;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return -ENOMEM;

	fltr->cookie = f->cookie;
	fltr->extack = f->common.extack;

	nse_tc_fltr_init(vsi, fltr);

	fltr->chain_id = f->common.chain_index;

	err = nse_parse_cls_flower(netdev, vsi, f, fltr);
	if (err < 0)
		goto err;

	err = nse_parse_tc_ct_match(netdev, vsi, f, fltr);
	if (err) {
		netdev_err(netdev, "Failed to add conntrack actions, err = %d\n", err);
		goto err;
	}

	err = nse_parse_tc_flower_actions(netdev, vsi, f, fltr);
	if (err < 0)
		goto err;

	err = nse_add_switch_fltr(vsi, fltr);
	if (err < 0) {
		netdev_err(netdev, "Failed to add tc flower fltr, err = %d\n", err);
		goto err;
	}

	*__fltr = fltr;
	return 0;
err:
	nse_put_tc_fltr(vsi, fltr);
	return err;
}

/**
 * nse_find_tc_flower_fltr - Find the TC flower filter in the list
 * @pf: Pointer to PF
 * @cookie: filter specific cookie
 */
static struct nse_tc_flower_fltr *
nse_find_tc_flower_fltr(struct nse_pf *pf, unsigned long cookie)
{
	struct nse_tc_flower_fltr *fltr;

	hlist_for_each_entry(fltr, &pf->tc_flower_fltr_list, tc_flower_node)
		if (cookie == fltr->cookie)
			return fltr;

	return NULL;
}

/**
 * nse_add_cls_flower - add TC flower filters
 * @netdev: device on which filter is added
 * @vsi: Pointer to source VSI, pf main vsi or vf vsi. (it is pf vsi when virtual netdev)
 * @cls_flower: Pointer to flower offload structure
 */
int
nse_add_cls_flower(struct net_device *netdev, struct nse_vsi *vsi,
		   struct flow_cls_offload *cls_flower)
{
	struct netlink_ext_ack *extack = cls_flower->common.extack;
	struct net_device *vsi_netdev = vsi->netdev;
	struct nse_tc_flower_fltr *fltr;
	struct nse_pf *pf = vsi->back;
	int err;

	if (nse_is_reset_in_progress(pf->state)) {
		netdev_err(netdev,
				"Pf driver is not ready\n");
		return -EBUSY;
	}

	netdev_info(netdev,
			"Start to add tc flower fltr, cookie = %lx\n",
			cls_flower->cookie);

	/* if repr direct way, vsi_netdev should be its own netdev */
	if ((nse_tc_tun_get_type(netdev, NULL) == TNL_LAST) &&
		nse_is_port_repr_netdev(netdev))
		vsi_netdev = netdev;

	/* check whether hw-tc-offload is enabled or not */
	if (!(vsi_netdev->features & NETIF_F_HW_TC) &&
	    !test_bit(NSE_FLAG_CLS_FLOWER, pf->flags)) {
		netdev_err(vsi_netdev,
			"can't apply TC flower filters, turn ON hw-tc-offload and try again\n");
		/*if rule on virtual netdev with tc disable, there is no err log.*/
		if (netdev == vsi_netdev)
			NL_SET_ERR_MSG_MOD(extack,
				"can't apply TC flower filters, turn ON hw-tc-offload and try again");
		return -EINVAL;
	}

	/* check whether pf is in switchdev mode or not */
	if (!nse_is_eswitch_mode_switchdev(pf) || !pf->switchdev.is_running) {
		NL_SET_ERR_MSG_MOD(extack,
				   "can't apply TC flower filters, due to switchdev isn't running");
		netdev_err(vsi_netdev,
			"can't apply TC flower filters, due to switchdev isn't running\n");

		return -EINVAL;
	}

	/* check whether tc flower filter is existed already or not */
	mutex_lock(&pf->tc_flower_mutex);
	fltr = nse_find_tc_flower_fltr(pf, cls_flower->cookie);
	if (fltr) {
		NL_SET_ERR_MSG_MOD(extack,
				"filter cookie already exists, ignoring");
		netdev_warn(vsi_netdev,
				"filter cookie %lx already exists, ignoring\n",
				fltr->cookie);
		mutex_unlock(&pf->tc_flower_mutex);
		return -EEXIST;
	}

	mutex_unlock(&pf->tc_flower_mutex);

	/* add TC-flower filter into hardware */
	err = nse_add_tc_fltr(netdev, vsi, cls_flower, &fltr);
	if (err)
		return err;

	/* add filter into an ordered software list */
	mutex_lock(&pf->tc_flower_mutex);
	hlist_add_head(&fltr->tc_flower_node, &pf->tc_flower_fltr_list);
	mutex_unlock(&pf->tc_flower_mutex);

	return 0;
}

/**
 * nse_del_cls_flower - delete TC flower filters
 * @vsi: Pointer to source VSI, pf main vsi or vf vsi. (it is pf vsi when virtual netdev)
 * @cls_flower: Pointer to struct flow_cls_offload
 */
int
nse_del_cls_flower(struct nse_vsi *vsi, struct flow_cls_offload *cls_flower)
{
	struct netlink_ext_ack *extack = cls_flower->common.extack;
	struct nse_tc_flower_fltr *fltr;
	struct nse_pf *pf = vsi->back;
	struct net_device *vsi_netdev = vsi->netdev;

	dev_info(nse_pf_to_dev(pf),
			"Start to del tc flower fltr, cookie = %lx\n",
			cls_flower->cookie);

	if (!nse_is_eswitch_mode_switchdev(pf) || !pf->switchdev.is_running) {
		NL_SET_ERR_MSG_MOD(extack,
				   "can't del TC flower filters, due to switchdev isn't running");
		netdev_err(vsi_netdev,
			"can't del TC flower filters, due to switchdev isn't running\n");

		return 0;
	}

	/* find filter */
	mutex_lock(&pf->tc_flower_mutex);
	fltr = nse_find_tc_flower_fltr(pf, cls_flower->cookie);
	if (!fltr) {
		mutex_unlock(&pf->tc_flower_mutex);
		return -EINVAL;
	}

	fltr->extack = cls_flower->common.extack;

	/* delete filter from an ordered list */
	hlist_del(&fltr->tc_flower_node);

	nse_put_tc_fltr(vsi, fltr);

	mutex_unlock(&pf->tc_flower_mutex);

	return 0;
}

/**
 * nse_stats_cls_flower - get TC flower filter statistic
 * @vsi: Pointer to source VSI, pf main vsi or vf vsi. (it is pf vsi when virtual netdev)
 * @cls_flower: Pointer to struct flow_cls_offload
 */
int
nse_stats_cls_flower(struct nse_vsi *vsi, struct flow_cls_offload *cls_flower)
{
	struct nse_tc_flower_fltr *fltr;
	struct nse_pf *pf = vsi->back;
	struct nse_sw_counter_pair *counter_p;
	u64 lastuse = 0, packets = 0, bytes = 0;

	if (!nse_is_eswitch_mode_switchdev(pf) || !pf->switchdev.is_running)
		return 0;

	/* find filter */
	fltr = nse_find_tc_flower_fltr(pf, cls_flower->cookie);
	if (!fltr)
		goto err;

	fltr->extack = cls_flower->common.extack;

	if (fltr->action.flags & NSE_TC_FLWR_ACTION_CT) {
		struct nse_tc_ct_flow *ct_flow = fltr->ct_flow;

		if (!ct_flow)
			goto err;

		counter_p = ct_flow->post_ct->action.counter_p;
	} else
		counter_p = fltr->action.counter_p;

	if (!counter_p)
		goto err;

	nse_fc_query_cached(counter_p, &bytes, &packets, &lastuse);

	flow_stats_update(&cls_flower->stats, bytes, packets, 0, lastuse,
			  FLOW_ACTION_HW_STATS_DELAYED);

	return 0;

err:
	return -EINVAL;
}

/**
 * nse_replay_tc_fltrs - replay tc filters
 * @pf: pointer to PF struct
 */
void nse_replay_tc_fltrs(struct nse_pf *pf)
{
	struct nse_tc_flower_fltr *fltr;
	struct hlist_node *node;

	if (nse_bypass_switch)
		return;

	mutex_lock(&pf->tc_flower_mutex);

	hlist_for_each_entry_safe(fltr, node,
				  &pf->tc_flower_fltr_list,
				  tc_flower_node) {
		fltr->extack = NULL;
		nse_add_switch_fltr(fltr->src_vsi, fltr);
	}

	mutex_unlock(&pf->tc_flower_mutex);
}

/**
 * nse_cleanup_tc_fltrs - cleanup all tc flower filter in the list
 * @pf: Pointer to PF
 */
void
nse_cleanup_tc_fltrs(struct nse_pf *pf)
{
	struct nse_tc_flower_fltr *fltr;
	struct hlist_node *node;

	if (nse_bypass_switch)
		return;

	mutex_lock(&pf->tc_flower_mutex);

	hlist_for_each_entry_safe(fltr, node,
		&pf->tc_flower_fltr_list, tc_flower_node) {
		/* delete filter from an ordered list */
		hlist_del(&fltr->tc_flower_node);

		nse_put_tc_fltr(fltr->src_vsi, fltr);
	}

	mutex_unlock(&pf->tc_flower_mutex);
}

/**
 * nse_policer_validate: validate the policer parameter
 *
 * @act: Pointer to police action information from OS
 */
int nse_policer_validate(const struct flow_action_entry *act)
{
	if (act->police.exceed.act_id != FLOW_ACTION_DROP)
		return -EOPNOTSUPP;

	if (act->police.peakrate_bytes_ps ||
	    act->police.avrate || act->police.overhead)
		return -EOPNOTSUPP;

	return 0;
}

/**
 * nse_add_fl_police_action
 *  -this function parse one police action, and then creat a meter
 *
 * @pf: Pointer to PF
 * @act: Pointer to police action information from OS
 */
static int
nse_add_fl_police_action(struct nse_pf *pf,
			    const struct flow_action_entry *act)
{
	struct nse_sw_meter_param params;
	struct nse_sw_meter *meter = NULL;
	struct nse_hw *hw = &pf->hw;
	int ret = 0;

	ret = nse_policer_validate(act);
	if (ret) {
		dev_err(nse_hw_to_dev(hw), "Failed to validate policer\n");
		return ret;
	}

	params.index = act->hw_index;

	if (act->police.rate_bytes_ps) {
		params.mode = NSE_RATE_LIMIT_BPS;
		params.rate = act->police.rate_bytes_ps;
		params.burst = act->police.burst;
	} else if (act->police.rate_pkt_ps) {
		params.mode = NSE_RATE_LIMIT_PPS;
		params.rate = act->police.rate_pkt_ps;
		params.burst = act->police.burst_pkt;
	} else {
		ret = -EOPNOTSUPP;
		dev_err(nse_hw_to_dev(hw), "Police action Mode is unsupportted\n");
		goto fl_police_action_err;
	}

	dev_info(nse_hw_to_dev(hw),
		"Start to set hw police action: meter index = %d, mode = %d, rate = %lld, burst = %d\n",
		params.index, params.mode, params.rate, params.burst);

	meter = nse_sw_get_meter(hw, &params);
	if (!meter) {
		ret = -ENOMEM;
		dev_err(nse_hw_to_dev(hw), "Failed to get sw meter for fl police\n");
		goto fl_police_action_err;
	}

	dev_info(nse_hw_to_dev(hw),
		"Success to set fl police action: meter hw id = %d, mode = %d, rate = %lld, burst = %d\n",
		meter->meter_id, params.mode, params.rate, params.burst);

	return 0;

fl_police_action_err:
	return ret;
}

/**
 * nse_del_fl_police_action
 *  -this function get one meter, and then delete a meter
 *
 * @pf: Pointer to PF
 * @act: Pointer to police action information from OS
 */
static int
nse_del_fl_police_action(struct nse_pf *pf,
			     struct flow_offload_action *fl_act)
{
	struct nse_sw_meter_param params;
	struct nse_sw_meter *meter = NULL;
	struct nse_hw *hw = &pf->hw;
	int ret = 0;

	params.index = fl_act->index;

	mutex_lock(&hw->switch_info->meter_list_lock);
	meter = nse_sw_find_meter(hw, &params);
	mutex_unlock(&hw->switch_info->meter_list_lock);

	if (!meter) {
		ret = -EINVAL;
		dev_err(nse_hw_to_dev(hw), "Failed to find the fl police\n");
		goto del_fl_police_err;
	}

	if (refcount_read(&meter->ref_cnt) > 1) {
		ret = -EINVAL;
		dev_err(nse_hw_to_dev(hw),
			"Please del tc flower fltr which use this meter, meter id =%d\n",
			fl_act->index);
		goto del_fl_police_err;
	}

	ret = nse_sw_put_meter(hw, meter);
	if (ret)
		dev_err(nse_hw_to_dev(hw), "Failed to put police meter\n");

	return 0;

del_fl_police_err:
	return ret;
}

/**
 * nse_tc_meter_get_stats
 */
void
nse_tc_meter_get_stats(struct nse_sw_meter *meter,
			 u64 *bytes, u64 *packets, u64 *drops, u64 *lastuse)
{
	u64 bytes1 = 0, packets1 = 0, lastuse1 = 0;
	u64 bytes2 = 0, packets2 = 0, lastuse2 = 0;

	nse_fc_query_cached(meter->green_cnt_p, &bytes1, &packets1, &lastuse1);
	nse_fc_query_cached(meter->red_cnt_p, &bytes2, &packets2, &lastuse2);

	*bytes = bytes1 + bytes2;
	*packets = packets1 + packets2;
	*drops = packets2;
	*lastuse = max_t(u64, lastuse1, lastuse2);
}

/**
 * nse_stats_fl_police_action
 *  -this function get one meter, and then get stats a meter
 *
 * @pf: Pointer to PF
 * @act: Pointer to police action information from OS
 */
static int
nse_stats_fl_police_action(struct nse_pf *pf,
			     struct flow_offload_action *fl_act)
{
	struct nse_sw_meter_param params;
	struct nse_sw_meter *meter = NULL;
	struct nse_hw *hw = &pf->hw;
	u64 lastuse = 0, packets = 0, bytes = 0, drops = 0;
	int ret = 0;

	params.index = fl_act->index;

	mutex_lock(&hw->switch_info->meter_list_lock);
	meter = nse_sw_find_meter(hw, &params);
	mutex_unlock(&hw->switch_info->meter_list_lock);

	if (!meter) {
		ret = -EINVAL;
		dev_err(nse_hw_to_dev(hw),
			"Failed to find the fl police, index = %d\n", params.index);
		goto stats_fl_police_err;
	}

	nse_tc_meter_get_stats(meter, &bytes, &packets, &drops, &lastuse);

	flow_stats_update(&fl_act->stats, bytes, packets, drops, lastuse,
			  FLOW_ACTION_HW_STATS_DELAYED);
	return 0;

stats_fl_police_err:
	return ret;
}

/**
 * nse_add_fl_action - add flow action
 * @pf: Pointer to PF
 * @fl_act: Pointer to flow action structure
 */
int
nse_add_fl_action(struct nse_netdev_priv *np,
			 struct flow_offload_action *fl_act)
{
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct flow_action_entry *action;
	int i;

	if (!nse_is_eswitch_mode_switchdev(pf) || !pf->switchdev.is_running) {
		dev_info(nse_pf_to_dev(pf),
				"Unsupported to offload fl action when switchdev isn't running\n");
		return -EOPNOTSUPP;
	}

	if (!flow_offload_has_one_action(&fl_act->action)) {
		dev_info(nse_pf_to_dev(pf),
				"Unsupported to offload more than one action\n");
		return -EOPNOTSUPP;
	}

	flow_action_for_each(i, action, &fl_act->action) {
		switch (action->id) {
		case FLOW_ACTION_POLICE:
			return nse_add_fl_police_action(pf, action);
		default:
			dev_info(nse_pf_to_dev(pf),
					"Unsupported to offload add fl action(=%d)\n", action->id);
		}
	}
	return -EOPNOTSUPP;
}

/**
 * nse_add_fl_action - del flow action
 * @pf: Pointer to PF
 * @fl_act: Pointer to flow action structure
 */
int
nse_del_fl_action(struct nse_netdev_priv *np,
			 struct flow_offload_action *fl_act)
{
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;

	switch (fl_act->id) {
	case FLOW_ACTION_POLICE:
		return nse_del_fl_police_action(pf, fl_act);
	default:
		dev_info(nse_pf_to_dev(pf),
				"Unsupported to offload del fl action(=%d)\n", fl_act->id);
	}
	return -EOPNOTSUPP;
}

/**
 * nse_get_stats_fl_action - get flow statistic
 * @pf: Pointer to PF
 * @fl_act: Pointer to flow action structure
 */
int
nse_get_stats_fl_action(struct nse_netdev_priv *np,
			 struct flow_offload_action *fl_act)
{
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;

	if (!nse_is_eswitch_mode_switchdev(pf) || !pf->switchdev.is_running)
		return 0;

	switch (fl_act->id) {
	case FLOW_ACTION_POLICE:
		return nse_stats_fl_police_action(pf, fl_act);
	default:
		dev_info(nse_pf_to_dev(pf),
				"Unsupported to offload get stats fl action(=%d)\n", fl_act->id);
	}
	return -EOPNOTSUPP;
}

