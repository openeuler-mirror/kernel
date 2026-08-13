// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_fdir.h"
#include "mce_ethtool_fdir.h"

/* calls to mce_flow_add_prof require the number of segments in the array
 * for segs_cnt. In this code that is one more than the index.
 */
#define TNL_SEG_CNT(_TNL_) ((_TNL_) + 1)

/**
 * mce_fltr_to_ethtool_flow - convert filter type values to ethtool
 * flow type values
 * @flow: filter type to be converted
 *
 * Returns: the corresponding ethtool flow type.
 */
static int mce_fltr_to_ethtool_flow(enum mce_fltr_ptype flow)
{
	switch (flow) {
	case MCE_FLTR_PTYPE_IPV4_TCP:
		return TCP_V4_FLOW;
	case MCE_FLTR_PTYPE_IPV4_UDP:
		return UDP_V4_FLOW;
	case MCE_FLTR_PTYPE_IPV4_SCTP:
		return SCTP_V4_FLOW;
	case MCE_FLTR_PTYPE_IPV4_OTHER:
		return IPV4_USER_FLOW;
	case MCE_FLTR_PTYPE_IPV6_TCP:
		return TCP_V6_FLOW;
	case MCE_FLTR_PTYPE_IPV6_UDP:
		return UDP_V6_FLOW;
	case MCE_FLTR_PTYPE_IPV6_SCTP:
		return SCTP_V6_FLOW;
	case MCE_FLTR_PTYPE_IPV6_OTHER:
		return 0;
	case MCE_FLTR_PTYPE_NONF_ETH:
		return ETHER_FLOW;
	default:
		/* 0 is undefined ethtool flow */
		return 0;
	}
}

/**
 * mce_ethtool_flow_to_fltr - convert ethtool flow type to filter enum
 * @eth: Ethtool flow type to be converted
 *
 * Returns: flow enum
 */
static enum mce_fltr_ptype mce_ethtool_flow_to_fltr(int eth)
{
	switch (eth) {
	case TCP_V4_FLOW:
		return MCE_FLTR_PTYPE_IPV4_TCP;
	case UDP_V4_FLOW:
		return MCE_FLTR_PTYPE_IPV4_UDP;
	case SCTP_V4_FLOW:
		return MCE_FLTR_PTYPE_IPV4_SCTP;
	case IPV4_USER_FLOW:
		return MCE_FLTR_PTYPE_IPV4_OTHER;
	case TCP_V6_FLOW:
		return MCE_FLTR_PTYPE_IPV6_TCP;
	case UDP_V6_FLOW:
		return MCE_FLTR_PTYPE_IPV6_UDP;
	case SCTP_V6_FLOW:
		return MCE_FLTR_PTYPE_IPV6_SCTP;
	case ETHER_FLOW:
		return MCE_FLTR_PTYPE_NONF_ETH;
	default:
		return MCE_FLTR_PTYPE_NONE;
	}
}

/**
 * mce_get_ethtool_fdir_entry - fill ethtool structure with fdir filter data
 * @hw: hardware structure that contains filter list
 * @cmd: ethtool command data structure to receive the filter data
 *
 * Returns: 0 on success and -EINVAL on failure
 */
int mce_get_ethtool_fdir_entry(struct mce_hw *hw,
			       struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp = NULL;
	struct mce_fdir_fltr *rule = NULL;

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;

	mutex_lock(&hw->fdir_fltr_lock);

	rule = mce_fdir_find_fltr_by_idx(hw, fsp->location);
	if (!rule) {
		mutex_unlock(&hw->fdir_fltr_lock);
		return -EINVAL;
	}

	fsp->flow_type = mce_fltr_to_ethtool_flow(rule->flow_type);
	memset(&fsp->m_u, 0, sizeof(fsp->m_u));
	memset(&fsp->m_ext, 0, sizeof(fsp->m_ext));

	switch (fsp->flow_type) {
	case ETHER_FLOW:
		fsp->h_u.ether_spec.h_proto = rule->eth.type;
		fsp->m_u.ether_spec.h_proto = rule->eth_mask.type;
		memcpy(fsp->h_u.ether_spec.h_dest, rule->eth.dst,
		       sizeof(fsp->h_u.ether_spec.h_dest));
		memcpy(fsp->m_u.ether_spec.h_dest, rule->eth_mask.dst,
		       sizeof(fsp->m_u.ether_spec.h_dest));
		memcpy(fsp->h_u.ether_spec.h_source, rule->eth.src,
		       sizeof(fsp->h_u.ether_spec.h_source));
		memcpy(fsp->m_u.ether_spec.h_source, rule->eth_mask.src,
		       sizeof(fsp->m_u.ether_spec.h_source));
		break;
	case IPV4_USER_FLOW:
		fsp->h_u.usr_ip4_spec.ip_ver = ETH_RX_NFC_IP4;
		fsp->h_u.usr_ip4_spec.proto = rule->ip.v4.proto;
		fsp->h_u.usr_ip4_spec.l4_4_bytes = rule->ip.v4.l4_header;
		fsp->h_u.usr_ip4_spec.tos = rule->ip.v4.tos;
		fsp->h_u.usr_ip4_spec.ip4src = rule->ip.v4.src_ip;
		fsp->h_u.usr_ip4_spec.ip4dst = rule->ip.v4.dst_ip;
		fsp->m_u.usr_ip4_spec.ip4src = rule->mask.v4.src_ip;
		fsp->m_u.usr_ip4_spec.ip4dst = rule->mask.v4.dst_ip;
		fsp->m_u.usr_ip4_spec.ip_ver = 0xFF;
		fsp->m_u.usr_ip4_spec.proto = rule->mask.v4.proto;
		fsp->m_u.usr_ip4_spec.l4_4_bytes = rule->mask.v4.l4_header;
		fsp->m_u.usr_ip4_spec.tos = rule->mask.v4.tos;
		break;
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
		fsp->h_u.tcp_ip4_spec.psrc = rule->ip.v4.src_port;
		fsp->h_u.tcp_ip4_spec.pdst = rule->ip.v4.dst_port;
		fsp->h_u.tcp_ip4_spec.ip4src = rule->ip.v4.src_ip;
		fsp->h_u.tcp_ip4_spec.ip4dst = rule->ip.v4.dst_ip;
		fsp->m_u.tcp_ip4_spec.psrc = rule->mask.v4.src_port;
		fsp->m_u.tcp_ip4_spec.pdst = rule->mask.v4.dst_port;
		fsp->m_u.tcp_ip4_spec.ip4src = rule->mask.v4.src_ip;
		fsp->m_u.tcp_ip4_spec.ip4dst = rule->mask.v4.dst_ip;
		break;
	default:
		break;
	}

	if (rule->fltr_action & F_FLTR_ACTION_DROP) {
		fsp->ring_cookie = RX_CLS_FLOW_DISC;
	} else {
		if (rule->vfid)
			fsp->ring_cookie = (u64)rule->vfid << 32;
		fsp->ring_cookie |= rule->q_id;
	}

	mutex_unlock(&hw->fdir_fltr_lock);

	return 0;
}

/**
 * mce_get_fdir_fltr_ids - fill buffer with filter IDs of active filters
 * @hw: hardware structure containing the filter list
 * @cmd: ethtool command data structure
 * @rule_locs: ethtool array passed in from OS to receive filter IDs
 *
 * Returns: 0 as expected for success by ethtool
 */
int mce_get_fdir_fltr_ids(struct mce_hw *hw,
			  struct ethtool_rxnfc *cmd,
			    u32 *rule_locs)
{
	struct mce_fdir_fltr *f_rule;
	u32 cnt = 0;
	int val = 0;

	/* report total rule count */
	cmd->data = hw->func_caps.fd_fltr_guar;

	mutex_lock(&hw->fdir_fltr_lock);

	list_for_each_entry(f_rule, &hw->fdir_list_head, fltr_node) {
		if (cnt == cmd->rule_cnt) {
			val = -EMSGSIZE;
			goto release_lock;
		}
		rule_locs[cnt] = f_rule->fltr_id;
		cnt++;
	}

release_lock:
	mutex_unlock(&hw->fdir_fltr_lock);
	if (!val)
		cmd->rule_cnt = cnt;
	return val;
}

/**
 * mce_ntuple_check_ip4_seg - Check valid fields are provided for filter
 * @hw: hardware structure
 * @tcp_ip4_spec: mask data from ethtool
 * Returns: The result of the operation.
 */
static int mce_ntuple_check_ip4_seg(struct mce_hw *hw,
				    struct ethtool_tcpip4_spec *tcp_ip4_spec)
{
	/* make sure we don't have any empty rule */
	if (!tcp_ip4_spec->psrc && !tcp_ip4_spec->ip4src &&
	    !tcp_ip4_spec->pdst && !tcp_ip4_spec->ip4dst) {
		dev_err(hw->dev,
			"The parameters of the 4-tuple cannot all be empty\n");
		return -EINVAL;
	}
	/* filtering on TOS not supported */
	if (tcp_ip4_spec->tos) {
		dev_err(hw->dev, "filtering on TOS not supported\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

/**
 * mce_ntuple_check_ip4_usr_seg - Check valid fields are provided for filter
 * @hw: hardware structure
 * @usr_ip4_spec: ethtool userdef packet offset
 * Returns: The result of the operation.
 */
static int mce_ntuple_check_ip4_usr_seg(struct mce_hw *hw,
					struct ethtool_usrip4_spec *usr_ip4_spec)
{
	/* first 4 bytes of Layer 4 header */
	if (usr_ip4_spec->l4_4_bytes) {
		dev_err(hw->dev, "l4_4_bytes rules are not valid\n");
		return -EINVAL;
	}
	if (usr_ip4_spec->tos) {
		dev_err(hw->dev, "tos rules are not valid\n");
		return -EINVAL;
	}
	if (usr_ip4_spec->ip_ver) {
		dev_err(hw->dev, "ip_ver rules are not valid\n");
		return -EINVAL;
	}
	/* empty rules are not valid */
	if (!usr_ip4_spec->ip4src && !usr_ip4_spec->ip4dst) {
		if (!usr_ip4_spec->proto) {
			dev_err(hw->dev, "ip4 empty rules are not valid\n");
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * mce_ntuple_check_ether_input - Validate Ethernet fields for an ntuple filter.
 * @eth_spec: mask data from ethtool
 * Returns: The result of the operation.
 */
static int mce_ntuple_check_ether_input(struct ethhdr *eth_spec)
{
	if (!eth_spec->h_proto &&
	    is_zero_ether_addr(eth_spec->h_source) &&
	    is_zero_ether_addr(eth_spec->h_dest))
		return -EINVAL;

	return 0;
}

static bool mce_ethtool_fdir_vfid_is_pf(int vfid)
{
	return vfid == 0;
}

/**
 * mce_set_fdir_input_set - Set the input set for specified block
 * @vsi: pointer to target VSI
 * @fsp: pointer to ethtool Rx flow specification
 * @input: filter structure
 * Returns: The result of the operation.
 */
static int mce_set_fdir_input_set(struct mce_vsi *vsi,
				  struct ethtool_rx_flow_spec *fsp,
				    struct mce_fdir_fltr *input)
{
	struct mce_hw *hw = &vsi->back->hw;
	struct mce_pf *pf = vsi->back;
	int flow_type = 0, ret = 0;

	if (!fsp || !input)
		return -EINVAL;

	input->vfid = ethtool_get_flow_spec_ring_vf(fsp->ring_cookie);
	input->q_id = ethtool_get_flow_spec_ring(fsp->ring_cookie);

	/* vf no action drop */
	if (fsp->ring_cookie == RX_CLS_FLOW_DISC) {
		input->fltr_action = F_FLTR_ACTION_DROP;
		input->vfid = 0;
		input->q_id = 0;
		goto action_drop;
	}

	if (!mce_ethtool_fdir_vfid_is_pf(input->vfid)) {
		struct mce_vf *vf = mce_pf_to_vf(pf);

		if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
			dev_err(hw->dev, "cannot setup vf rule without SRIOV");
			return -EINVAL;
		}

		if (input->vfid > pf->num_vfs) {
			dev_err(hw->dev,
				"Failed to add filter, The VF number:%d cannot exceed "
				"the PF had turn on:%d\n",
				input->vfid - 1, pf->num_vfs);
			return -EINVAL;
		}

		if (input->q_id >= vf->vfinfo[input->vfid - 1].ring_cnt) {
			dev_err(hw->dev,
				"vf %d queue %u cannot exceed max queue num:%d\n",
				input->vfid - 1, input->q_id,
				vf->vfinfo[input->vfid - 1].ring_cnt);
			return -EINVAL;
		}
	} else {
		if (input->fltr_action != F_FLTR_ACTION_DROP &&
		    input->q_id >= vsi->num_rxq) {
			dev_err(hw->dev, "queue %u is invalid.\n",
				input->q_id);
			return -EINVAL;
		}
	}

action_drop:
	flow_type = fsp->flow_type & ~FLOW_EXT;
	input->fltr_id = fsp->location;
	input->flow_type = mce_ethtool_flow_to_fltr(flow_type);
	switch (flow_type) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
		ret = mce_ntuple_check_ip4_seg(hw, &fsp->m_u.tcp_ip4_spec);
		if (ret != 0)
			return ret;

		input->ip.v4.dst_port = fsp->h_u.tcp_ip4_spec.pdst;
		input->ip.v4.src_port = fsp->h_u.tcp_ip4_spec.psrc;
		input->ip.v4.dst_ip = fsp->h_u.tcp_ip4_spec.ip4dst;
		input->ip.v4.src_ip = fsp->h_u.tcp_ip4_spec.ip4src;
		input->mask.v4.dst_port = fsp->m_u.tcp_ip4_spec.pdst;
		input->mask.v4.src_port = fsp->m_u.tcp_ip4_spec.psrc;
		input->mask.v4.dst_ip = fsp->m_u.tcp_ip4_spec.ip4dst;
		input->mask.v4.src_ip = fsp->m_u.tcp_ip4_spec.ip4src;
		break;
	case IPV4_USER_FLOW:
		ret = mce_ntuple_check_ip4_usr_seg(hw, &fsp->m_u.usr_ip4_spec);
		if (ret != 0)
			return ret;

		input->ip.v4.dst_ip = fsp->h_u.usr_ip4_spec.ip4dst;
		input->ip.v4.src_ip = fsp->h_u.usr_ip4_spec.ip4src;
		input->ip.v4.l4_header = fsp->h_u.usr_ip4_spec.l4_4_bytes;
		input->ip.v4.proto = fsp->h_u.usr_ip4_spec.proto;
		input->ip.v4.ip_ver = fsp->h_u.usr_ip4_spec.ip_ver;
		input->ip.v4.tos = fsp->h_u.usr_ip4_spec.tos;
		input->mask.v4.dst_ip = fsp->m_u.usr_ip4_spec.ip4dst;
		input->mask.v4.src_ip = fsp->m_u.usr_ip4_spec.ip4src;
		input->mask.v4.l4_header = fsp->m_u.usr_ip4_spec.l4_4_bytes;
		input->mask.v4.proto = fsp->m_u.usr_ip4_spec.proto;
		input->mask.v4.ip_ver = fsp->m_u.usr_ip4_spec.ip_ver;
		input->mask.v4.tos = fsp->m_u.usr_ip4_spec.tos;
		break;
	case ETHER_FLOW:
		ret = mce_ntuple_check_ether_input(&fsp->m_u.ether_spec);
		if (ret != 0)
			return ret;

		memcpy(input->eth.dst, fsp->h_u.ether_spec.h_dest,
		       ETH_ALEN);
		memcpy(input->eth.src, fsp->h_u.ether_spec.h_source,
		       ETH_ALEN);
		memcpy(input->eth_mask.dst, fsp->m_u.ether_spec.h_dest,
		       ETH_ALEN);
		memcpy(input->eth_mask.src, fsp->m_u.ether_spec.h_source,
		       ETH_ALEN);
		input->eth.type = fsp->h_u.ether_spec.h_proto;
		input->eth_mask.type = fsp->m_u.ether_spec.h_proto;
		break;
	default:
		/* not doing un-parsed flow types */
		dev_err(hw->dev, "Unsupported flow type.\n");
		return -EINVAL;
	}

	return 0;
}

/* rule_vfid 0 is pf, 1 is vf 0 */
static struct vf_info *mce_get_vfinfo(struct mce_pf *pf, int rule_vfid)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_hw *hw = &pf->hw;

	/* vf info */
	if (rule_vfid && rule_vfid != 0xff)
		return &vf->vfinfo[rule_vfid - 1];

	/* sriov on use vf->vfinfo */
	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return &vf->vfinfo[PFINFO_IDX];

	return &pf->pfinfo;
}

static int __mce_handle_l2_filter(struct mce_hw *hw,
				  struct mce_fdir_fltr *rule, bool add)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct vf_info *vfinfo;
	int avail_id;
	int ret = 0;

	vfinfo = mce_get_vfinfo(pf, rule->vfid);

	if (add) {
		avail_id = find_first_zero_bit(vfinfo->avail_etype, MCE_MAX_ETYPE_CNT);
		if (avail_id >= MCE_MAX_ETYPE_CNT) {
			if (mce_ethtool_fdir_vfid_is_pf(rule->vfid)) {
				dev_info(mce_hw_to_dev(hw),
					 "Pf etype rules exceeds maximum allowed:%d\n",
					MCE_MAX_ETYPE_CNT);
			} else {
				dev_info(mce_hw_to_dev(hw),
					 "Vf:%d etype rules exceeds maximum allowed:%d\n",
					rule->vfid - 1, MCE_MAX_ETYPE_CNT);
			}
			return -EINVAL;
		}
		set_bit(avail_id, vfinfo->avail_etype);
		rule->etype_loc = avail_id;
		hw->fdir_active_fltr++;
		vfinfo->fdir_active_fltr++;
	} else {
		clear_bit(rule->etype_loc, vfinfo->avail_etype);
		hw->fdir_active_fltr--;
		vfinfo->fdir_active_fltr--;
	}
	return ret;
}

static int __mce_handle_ntuple_filter(struct mce_hw *hw,
				      struct mce_fdir_fltr *rule, bool add)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	int vfid = rule->vfid - 1, avail_id;
	struct vf_info *vfinfo;
	int ret = 0;

	vfinfo = mce_get_vfinfo(pf, rule->vfid);
	if (add) {
		avail_id = find_first_zero_bit(hw->avail_tuple5,
					       MCE_ACL_MAX_TUPLE5_CNT);
		if (avail_id >= MCE_ACL_MAX_TUPLE5_CNT) {
			if (mce_ethtool_fdir_vfid_is_pf(rule->vfid)) {
				dev_info(mce_hw_to_dev(hw),
					 "Pf ntuple rules exceeds maximum allowed:%d\n",
					MCE_ACL_MAX_TUPLE5_CNT);
			} else {
				dev_info(mce_hw_to_dev(hw),
					 "vf:%d ntuple rules exceeds maximum allowed:%d\n",
					vfid - 1, MCE_ACL_MAX_TUPLE5_CNT);
			}
			return -EINVAL;
		}
		set_bit(avail_id, hw->avail_tuple5);
		rule->tuple5_loc = avail_id;
		hw->fdir_active_fltr++;
		vfinfo->fdir_active_fltr++;
	} else {
		clear_bit(rule->tuple5_loc, hw->avail_tuple5);
		hw->fdir_active_fltr--;
		vfinfo->fdir_active_fltr--;
	}
	return ret;
}

int mce_handle_acl_filter(struct mce_hw *hw,
			  struct mce_fdir_fltr *rule, bool add)
{
	int ret = 0;

	if (rule->flow_type == MCE_FLTR_PTYPE_NONF_ETH)
		ret = __mce_handle_l2_filter(hw, rule, add);
	else
		ret = __mce_handle_ntuple_filter(hw, rule, add);

	if (ret < 0)
		return ret;

	if (add)
		hw->ops->add_ntuple_filter(hw, rule);
	else
		hw->ops->del_ntuple_filter(hw, rule);
	return ret;
}

/**
 * mce_add_ntuple_ethtool - Add/Remove Flow Director  or ACL filter
 * @vsi: pointer to target VSI
 * @cmd: command to add or delete the filter
 *
 * Returns: 0 on success and negative values for failure
 */
int mce_add_ntuple_ethtool(struct mce_vsi *vsi,
			   struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp = NULL;
	struct mce_hw *hw = &vsi->back->hw;
	struct mce_fdir_fltr *input = NULL;
	struct device *dev = hw->dev;
	int ret = 0;

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;
	if ((fsp->flow_type & FLOW_MAC_EXT) ||
	    ((fsp->flow_type & FLOW_EXT))) {
		return -EINVAL;
	}
	if (fsp->location >= hw->func_caps.fd_fltr_guar) {
		dev_err(dev, "Failed to add filter. "
			"The maximum number of flow director filters has been reached.\n");
		return -ENOSPC;
	}

	input = devm_kzalloc(dev, sizeof(*input), GFP_KERNEL);
	if (!input)
		return -ENOMEM;

	ret = mce_set_fdir_input_set(vsi, fsp, input);
	if (ret)
		goto free_input;

	mutex_lock(&hw->fdir_fltr_lock);
	ret = mce_fdir_is_dup_fltr(hw, input);
	if (ret) {
		if (mce_ethtool_fdir_vfid_is_pf(input->vfid))
			dev_warn(dev,
				 "Failed to add filter, duplicate filter exists for pf\n");
		else
			dev_warn(dev,
				 "Failed to add filter, duplicate filter exists for vf:%d\n",
				input->vfid - 1);
		ret = -EINVAL;
		goto release_lock;
	}
	ret = mce_handle_acl_filter(hw, input, true);
	if (ret)
		goto release_lock;
	list_add_tail(&input->fltr_node, &hw->fdir_list_head);

release_lock:
	mutex_unlock(&hw->fdir_fltr_lock);
free_input:
	if (ret)
		devm_kfree(dev, input);

	return ret;
}

/**
 * mce_del_ntuple_ethtool - delete Flow Director or ACL filter
 * @vsi: pointer to target VSI
 * @cmd: command to add or delete the filter
 *
 * Returns: 0 on success and negative values for failure
 */
int mce_del_ntuple_ethtool(struct mce_vsi *vsi,
			   struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp =
			(struct ethtool_rx_flow_spec *)&cmd->fs;
	struct mce_fdir_fltr *old_fltr = NULL;
	struct mce_hw *hw = &vsi->back->hw;

	if (!hw->fdir_active_fltr)
		return -EINVAL;

	if (fsp->location >= hw->func_caps.fd_fltr_guar) {
		dev_err(hw->dev, "Failed to add filter. "
			"The maximum number of flow director filters has been reached.\n");
		return -ENOSPC;
	}

	mutex_lock(&hw->fdir_fltr_lock);
	old_fltr = mce_fdir_find_fltr_by_idx(hw, fsp->location);
	if (old_fltr) {
		mce_handle_acl_filter(hw, old_fltr, false);
		list_del(&old_fltr->fltr_node);
		devm_kfree(hw->dev, old_fltr);
	}
	mutex_unlock(&hw->fdir_fltr_lock);

	return 0;
}
