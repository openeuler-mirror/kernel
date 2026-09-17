// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */

#include "mcevf.h"
#include "mcevf_fdir.h"
#include "mcevf_ethtool_fdir.h"

/* calls to mcevf_flow_add_prof require the number of segments in the array
 * for segs_cnt. In this code that is one more than the index.
 */
#define TNL_SEG_CNT(_TNL_) ((_TNL_) + 1)

/**
 * mcevf_fltr_to_ethtool_flow - convert filter type values to ethtool
 * flow type values
 * @flow: filter type to be converted
 *
 * Returns the corresponding ethtool flow type.
 */
static int mcevf_fltr_to_ethtool_flow(enum mcevf_fltr_ptype flow)
{
	switch (flow) {
	case MCEVF_FLTR_PTYPE_IPV4_TCP:
		return TCP_V4_FLOW;
	case MCEVF_FLTR_PTYPE_IPV4_UDP:
		return UDP_V4_FLOW;
	case MCEVF_FLTR_PTYPE_IPV4_SCTP:
		return SCTP_V4_FLOW;
	case MCEVF_FLTR_PTYPE_IPV4_OTHER:
		return IPV4_USER_FLOW;
	case MCEVF_FLTR_PTYPE_IPV6_TCP:
		return TCP_V6_FLOW;
	case MCEVF_FLTR_PTYPE_IPV6_UDP:
		return UDP_V6_FLOW;
	case MCEVF_FLTR_PTYPE_IPV6_SCTP:
		return SCTP_V6_FLOW;
	case MCEVF_FLTR_PTYPE_IPV6_OTHER:
		return IPV6_USER_FLOW;
	default:
		/* 0 is undefined ethtool flow */
		return 0;
	}
}

/**
 * mcevf_ethtool_flow_to_fltr - convert ethtool flow type to filter enum
 * @eth: Ethtool flow type to be converted
 *
 * Returns flow enum
 */
static enum mcevf_fltr_ptype mcevf_ethtool_flow_to_fltr(int eth)
{
	switch (eth) {
	case TCP_V4_FLOW:
		return MCEVF_FLTR_PTYPE_IPV4_TCP;
	case UDP_V4_FLOW:
		return MCEVF_FLTR_PTYPE_IPV4_UDP;
	case SCTP_V4_FLOW:
		return MCEVF_FLTR_PTYPE_IPV4_SCTP;
	case IPV4_USER_FLOW:
		return MCEVF_FLTR_PTYPE_IPV4_OTHER;
	case TCP_V6_FLOW:
		return MCEVF_FLTR_PTYPE_IPV6_TCP;
	case UDP_V6_FLOW:
		return MCEVF_FLTR_PTYPE_IPV6_UDP;
	case SCTP_V6_FLOW:
		return MCEVF_FLTR_PTYPE_IPV6_SCTP;
	case IPV6_USER_FLOW:
		return MCEVF_FLTR_PTYPE_IPV6_OTHER;
	default:
		return MCEVF_FLTR_PTYPE_NONE;
	}
}

/**
 * mcevf_get_ethtool_fdir_entry - fill ethtool structure with fdir filter data
 * @hw: hardware structure that contains filter list
 * @cmd: ethtool command data structure to receive the filter data
 *
 * Returns 0 on success and -EINVAL on failure
 */
int mcevf_get_ethtool_fdir_entry(struct mcevf_hw *hw,
				 struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp = NULL;
	struct mcevf_fdir_fltr *rule = NULL;

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;

	mutex_lock(&hw->fdir_fltr_lock);

	rule = mcevf_fdir_find_fltr_by_idx(hw, fsp->location);
	if (!rule) {
		mutex_unlock(&hw->fdir_fltr_lock);
		return -EINVAL;
	}

	fsp->flow_type = mcevf_fltr_to_ethtool_flow(rule->flow_type);
	memset(&fsp->m_u, 0, sizeof(fsp->m_u));
	memset(&fsp->m_ext, 0, sizeof(fsp->m_ext));

	switch (fsp->flow_type) {
	case IPV4_USER_FLOW:
		fsp->h_u.usr_ip4_spec.ip_ver = rule->ip.v4.ip_ver;
		fsp->h_u.usr_ip4_spec.proto = rule->ip.v4.proto;
		fsp->h_u.usr_ip4_spec.l4_4_bytes = rule->ip.v4.l4_header;
		fsp->h_u.usr_ip4_spec.tos = rule->ip.v4.tos;
		fsp->h_u.usr_ip4_spec.ip4src = rule->ip.v4.src_ip;
		fsp->h_u.usr_ip4_spec.ip4dst = rule->ip.v4.dst_ip;
		fsp->m_u.usr_ip4_spec.ip4src = rule->mask.v4.src_ip;
		fsp->m_u.usr_ip4_spec.ip4dst = rule->mask.v4.dst_ip;
		fsp->m_u.usr_ip4_spec.ip_ver = rule->mask.v4.ip_ver;
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
	case IPV6_USER_FLOW:
		fsp->h_u.usr_ip6_spec.l4_4_bytes = rule->ip.v6.l4_header;
		fsp->h_u.usr_ip6_spec.tclass = rule->ip.v6.tc;
		fsp->h_u.usr_ip6_spec.l4_proto = rule->ip.v6.proto;
		memcpy(fsp->h_u.tcp_ip6_spec.ip6src, rule->ip.v6.src_ip,
		       sizeof(struct in6_addr));
		memcpy(fsp->h_u.tcp_ip6_spec.ip6dst, rule->ip.v6.dst_ip,
		       sizeof(struct in6_addr));
		memcpy(fsp->m_u.tcp_ip6_spec.ip6src, rule->mask.v6.src_ip,
		       sizeof(struct in6_addr));
		memcpy(fsp->m_u.tcp_ip6_spec.ip6dst, rule->mask.v6.dst_ip,
		       sizeof(struct in6_addr));
		fsp->m_u.usr_ip6_spec.l4_4_bytes = rule->mask.v6.l4_header;
		fsp->m_u.usr_ip6_spec.tclass = rule->mask.v6.tc;
		fsp->m_u.usr_ip6_spec.l4_proto = rule->mask.v6.proto;
		break;
	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
	case SCTP_V6_FLOW:
		memcpy(fsp->h_u.tcp_ip6_spec.ip6src, rule->ip.v6.src_ip,
		       sizeof(struct in6_addr));
		memcpy(fsp->h_u.tcp_ip6_spec.ip6dst, rule->ip.v6.dst_ip,
		       sizeof(struct in6_addr));
		fsp->h_u.tcp_ip6_spec.psrc = rule->ip.v6.src_port;
		fsp->h_u.tcp_ip6_spec.pdst = rule->ip.v6.dst_port;
		memcpy(fsp->m_u.tcp_ip6_spec.ip6src, rule->mask.v6.src_ip,
		       sizeof(struct in6_addr));
		memcpy(fsp->m_u.tcp_ip6_spec.ip6dst, rule->mask.v6.dst_ip,
		       sizeof(struct in6_addr));
		fsp->m_u.tcp_ip6_spec.psrc = rule->mask.v6.src_port;
		fsp->m_u.tcp_ip6_spec.pdst = rule->mask.v6.dst_port;
		fsp->h_u.tcp_ip6_spec.tclass = rule->ip.v6.tc;
		fsp->m_u.tcp_ip6_spec.tclass = rule->mask.v6.tc;
		break;
	default:
		break;
	}

	if (rule->fltr_action & F_FLTR_ACTION_DROP)
		fsp->ring_cookie = RX_CLS_FLOW_DISC;
	else
		fsp->ring_cookie = rule->q_id;

	mutex_unlock(&hw->fdir_fltr_lock);

	return 0;
}

/**
 * mcevf_get_fdir_fltr_ids - fill buffer with filter IDs of active filters
 * @hw: hardware structure containing the filter list
 * @cmd: ethtool command data structure
 * @rule_locs: ethtool array passed in from OS to receive filter IDs
 *
 * Returns 0 as expected for success by ethtool
 */
int mcevf_get_fdir_fltr_ids(struct mcevf_hw *hw, struct ethtool_rxnfc *cmd,
			    u32 *rule_locs)
{
	struct mcevf_fdir_fltr *f_rule;
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
 * mcevf_set_fdir_input_set - Set the input set for specified block
 * @vsi: pointer to target VSI
 * @fsp: pointer to ethtool Rx flow specification
 * @input: filter structure
 */
static int mcevf_set_fdir_input_set(struct mcevf_vsi *vsi,
				    struct ethtool_rx_flow_spec *fsp,
				    struct mcevf_fdir_fltr *input)
{
	struct mcevf_hw *hw = &vsi->back->hw;
	int flow_type = 0;

	if (!fsp || !input)
		return -EINVAL;

	if (fsp->ring_cookie == RX_CLS_FLOW_DISC) {
		input->fltr_action = F_FLTR_ACTION_DROP;
	} else {
		input->q_id = ethtool_get_flow_spec_ring(fsp->ring_cookie);

		if (ethtool_get_flow_spec_ring_vf(fsp->ring_cookie)) {
			dev_err(hw->dev,
				"Failed to add filter. Flow director filters are not supported on VF queues.\n");
			return -EINVAL;
		}

		if (input->q_id >= vsi->num_rxq) {
			dev_err(hw->dev, "queue %u is invalid.\n",
				input->q_id);
			return -EINVAL;
		}
	}

	flow_type = fsp->flow_type & ~FLOW_EXT;
	input->fltr_id = fsp->location;
	input->flow_type = mcevf_ethtool_flow_to_fltr(flow_type);

	switch (flow_type) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
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
		input->ip.v4.dst_ip = fsp->h_u.usr_ip4_spec.ip4dst;
		input->ip.v4.src_ip = fsp->h_u.usr_ip4_spec.ip4src;
		input->ip.v4.l4_header = fsp->h_u.usr_ip4_spec.l4_4_bytes;
		input->ip.v4.proto = fsp->h_u.usr_ip4_spec.proto;
		input->ip.v4.ip_ver = fsp->h_u.usr_ip4_spec.ip_ver;
		input->ip.v4.tos = fsp->h_u.usr_ip4_spec.tos;
		input->mask.v4.dst_ip = fsp->m_u.usr_ip4_spec.ip4dst;
		input->mask.v4.src_ip = fsp->m_u.usr_ip4_spec.ip4src;
		input->mask.v4.l4_header =
			fsp->m_u.usr_ip4_spec.l4_4_bytes;
		input->mask.v4.proto = fsp->m_u.usr_ip4_spec.proto;
		input->mask.v4.ip_ver = fsp->m_u.usr_ip4_spec.ip_ver;
		input->mask.v4.tos = fsp->m_u.usr_ip4_spec.tos;
		break;
	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
	case SCTP_V6_FLOW:
		memcpy(input->ip.v6.dst_ip, fsp->h_u.usr_ip6_spec.ip6dst,
		       sizeof(struct in6_addr));
		memcpy(input->ip.v6.src_ip, fsp->h_u.usr_ip6_spec.ip6src,
		       sizeof(struct in6_addr));
		input->ip.v6.dst_port = fsp->h_u.tcp_ip6_spec.pdst;
		input->ip.v6.src_port = fsp->h_u.tcp_ip6_spec.psrc;
		input->ip.v6.tc = fsp->h_u.tcp_ip6_spec.tclass;
		memcpy(input->mask.v6.dst_ip, fsp->m_u.tcp_ip6_spec.ip6dst,
		       sizeof(struct in6_addr));
		memcpy(input->mask.v6.src_ip, fsp->m_u.tcp_ip6_spec.ip6src,
		       sizeof(struct in6_addr));
		input->mask.v6.dst_port = fsp->m_u.tcp_ip6_spec.pdst;
		input->mask.v6.src_port = fsp->m_u.tcp_ip6_spec.psrc;
		input->mask.v6.tc = fsp->m_u.tcp_ip6_spec.tclass;
		break;
	case IPV6_USER_FLOW:
		memcpy(input->ip.v6.dst_ip, fsp->h_u.usr_ip6_spec.ip6dst,
		       sizeof(struct in6_addr));
		memcpy(input->ip.v6.src_ip, fsp->h_u.usr_ip6_spec.ip6src,
		       sizeof(struct in6_addr));
		input->ip.v6.l4_header = fsp->h_u.usr_ip6_spec.l4_4_bytes;
		input->ip.v6.tc = fsp->h_u.usr_ip6_spec.tclass;

		/* if no protocol requested, use IPPROTO_NONE */
		if (!fsp->m_u.usr_ip6_spec.l4_proto)
			input->ip.v6.proto = IPPROTO_NONE;
		else
			input->ip.v6.proto =
				fsp->h_u.usr_ip6_spec.l4_proto;

		memcpy(input->mask.v6.dst_ip, fsp->m_u.usr_ip6_spec.ip6dst,
		       sizeof(struct in6_addr));
		memcpy(input->mask.v6.src_ip, fsp->m_u.usr_ip6_spec.ip6src,
		       sizeof(struct in6_addr));
		input->mask.v6.l4_header =
			fsp->m_u.usr_ip6_spec.l4_4_bytes;
		input->mask.v6.tc = fsp->m_u.usr_ip6_spec.tclass;
		input->mask.v6.proto = fsp->m_u.usr_ip6_spec.l4_proto;
		break;
	default:
		/* not doing un-parsed flow types */
		dev_err(hw->dev, "Unsupported flow type.\n");
		return -EINVAL;
	}

	return 0;
}

/**
 * mcevf_add_ntuple_ethtool - Add/Remove Flow Director  or ACL filter
 * @vsi: pointer to target VSI
 * @cmd: command to add or delete the filter
 *
 * Returns 0 on success and negative values for failure
 */
int mcevf_add_ntuple_ethtool(struct mcevf_vsi *vsi,
			     struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp = NULL;
	struct mcevf_fdir_fltr *input = NULL;
	struct mcevf_hw *hw = &vsi->back->hw;
	struct device *dev = hw->dev;
	int ret = 0;

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;

	if ((fsp->flow_type & FLOW_MAC_EXT) ||
	    ((fsp->flow_type & FLOW_EXT))) {
		return -EINVAL;
	}

	if (fsp->location >= hw->func_caps.fd_fltr_guar) {
		dev_err(dev,
			"Failed to add filter. The maximum number of flow director filters has been reached.\n");
		return -ENOSPC;
	}

	input = devm_kzalloc(dev, sizeof(*input), GFP_KERNEL);
	if (!input)
		return -ENOMEM;

	ret = mcevf_set_fdir_input_set(vsi, fsp, input);
	if (ret)
		goto free_input;

	mutex_lock(&hw->fdir_fltr_lock);
	ret = mcevf_fdir_is_dup_fltr(hw, input);
	if (ret) {
		ret = -EINVAL;
		goto release_lock;
	}

	hw->ops->add_ntuple_filter(hw, input);

	list_add_tail(&input->fltr_node, &hw->fdir_list_head);

release_lock:
	mutex_unlock(&hw->fdir_fltr_lock);
free_input:
	if (ret)
		devm_kfree(dev, input);

	return ret;
}

/**
 * mcevf_del_ntuple_ethtool - delete Flow Director or ACL filter
 * @vsi: pointer to target VSI
 * @cmd: command to add or delete the filter
 *
 * Returns 0 on success and negative values for failure
 */
int mcevf_del_ntuple_ethtool(struct mcevf_vsi *vsi,
			     struct ethtool_rxnfc *cmd)
{
	struct mcevf_hw *hw = &vsi->back->hw;
	struct ethtool_rx_flow_spec *fsp =
		(struct ethtool_rx_flow_spec *)&cmd->fs;
	struct mcevf_fdir_fltr *old_fltr = NULL;
	bool found = false;

	if (hw->fdir_active_fltr == 0)
		return -EINVAL;

	if (fsp->location >= hw->func_caps.fd_fltr_guar) {
		dev_err(hw->dev,
			"Failed to delete filter. Filter location is out of range.\n");
		return -ENOSPC;
	}

	mutex_lock(&hw->fdir_fltr_lock);
	old_fltr = mcevf_fdir_find_fltr_by_idx(hw, fsp->location);
	if (old_fltr) {
		hw->ops->del_ntuple_filter(hw, old_fltr);
		list_del(&old_fltr->fltr_node);
		devm_kfree(hw->dev, old_fltr);
		found = true;
	}
	mutex_unlock(&hw->fdir_fltr_lock);

	return found ? 0 : -EINVAL;
}
