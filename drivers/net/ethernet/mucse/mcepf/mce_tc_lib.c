// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_fdir.h"
#include "mce_tc_lib.h"
#include "mce_lib.h"
#include "mce_fltr.h"
#include "mce_pattern.h"
#include "mce_parse.h"
#include "mce_switch.h"
#include "mce_eswitch.h"
#include "mce_fdir_flow.h"
#include <net/gre.h>
#if IS_ENABLED(CONFIG_VXLAN)
#include <net/vxlan.h>
#endif
#if IS_ENABLED(CONFIG_GENEVE)
#include <net/geneve.h>
#endif
#include "mce_profile_mask.h"
#include "mce_netdev.h"

#define GTP1U_PORT 2152

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
#define MCE_TC_METADATA_LKUP_IDX 0

static void mce_tc_free_fdir_filter(struct mce_fdir_filter *filter)
{
	if (!filter)
		return;

	if (filter->mask_info) {
		kfree(filter->mask_info->field_bitmask);
		kfree(filter->mask_info);
	}
	kfree(filter);
}

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
/**
 * mce_is_tunnel_fltr - is this a tunnel filter
 * @f: Pointer to tc-flower filter
 *
 * This function should be called only after tunnel_type
 * of the filter is set by calling mce_tc_tun_parse()
 */
static bool __maybe_unused mce_is_tunnel_fltr(struct mce_tc_flower_fltr *f)
{
	return (f->tunnel_type == TNL_VXLAN ||
		f->tunnel_type == TNL_GENEVE ||
		f->tunnel_type == TNL_GRETAP ||
		f->tunnel_type == TNL_GTPU || f->tunnel_type == TNL_GTPC);
}
#endif /* CONFIG_NET_CLS_FLOWER */

struct mce_vsi *mce_locate_vsi_using_queue(struct mce_vsi *vsi,
					   int queue)
{
	return vsi;
}

/* fdir flow */
void *mce_get_engine_handle(struct mce_pf *pf, enum mce_flow_module type)
{
	struct mce_flow_engine_module *engine = NULL;
	int i;

	for (i = MCE_FLOW_FDIR; i < MCE_FLOW_MAX; i++) {
		engine = pf->flow_engine[i];

		if (!engine)
			continue;
		if (engine->type == type)
			return engine->handle;
	}

	return NULL;
}

int mce_init_flow_engine(struct mce_pf *pf, enum mce_flow_module module)
{
	struct device *dev = mce_pf_to_dev(pf);
	int err;

	if (module >= MCE_FLOW_MAX) {
		dev_err(dev, "%s module:%d init flow engine failed.\n",
			__func__, module);
		return -EOPNOTSUPP;
	}

	if (module == MCE_FLOW_FDIR) {
		if (test_bit(MCE_FLAGS_FDIR_FLOW_ENA, pf->flags)) {
			dev_err(dev, "%s fdir has been init.\n", __func__);
			return -EOPNOTSUPP;
		}

		if (pf->fdir_mode < 0 || pf->fdir_mode > MCE_FDIR_MAX_MODE) {
			dev_err(dev, "%s fdir mode:%d error, exit.\n", __func__,
				pf->fdir_mode);
			return -EOPNOTSUPP;
		}
	}

	pf->flow_engine[module] =
		kzalloc(sizeof(struct mce_flow_engine_module), GFP_KERNEL);
	if (!pf->flow_engine[module]) {
		dev_err(dev, "%s flow engine alloc memory failed.\n", __func__);
		return -ENOMEM;
	}

	if (module == MCE_FLOW_FDIR) {
		memcpy(pf->flow_engine[module], &mce_fdir_engine,
		       sizeof(struct mce_flow_engine_module));
		err = pf->flow_engine[module]->init(pf, &pf->flow_engine[module]->handle);
		if (err) {
			kfree(pf->flow_engine[module]);
			pf->flow_engine[module] = NULL;
			return err;
		}
		set_bit(MCE_FLAGS_FDIR_FLOW_ENA, pf->flags);
	}

	if (module == MCE_FLOW_ESWITCH) {
		memcpy(pf->flow_engine[module], &mce_eswitch_engine,
		       sizeof(struct mce_flow_engine_module));
		err = pf->flow_engine[module]->init(pf,
					      &pf->flow_engine[module]->handle);
		if (err) {
			kfree(pf->flow_engine[module]);
			pf->flow_engine[module] = NULL;
			return err;
		}
	}
	return 0;
}

void mce_deinit_flow_engine(struct mce_pf *pf, enum mce_flow_module module)
{
	struct mce_hw *hw = &pf->hw;

	if (!test_bit(MCE_FLAGS_FDIR_FLOW_ENA, pf->flags) &&
	    module == MCE_FLOW_FDIR)
		return;
	if (!pf->flow_engine[module])
		return;
	pf->flow_engine[module]->uinit(pf, module);
	kfree(pf->flow_engine[module]);
	if (module == MCE_FLOW_FDIR) {
		hw->ops->fd_deinit_hw(hw);
		clear_bit(MCE_FLAGS_FDIR_FLOW_ENA, pf->flags);
	}
}

/**
 * mce_tc_forward_action - Determine destination VSI and queue for the action
 * @vsi: Pointer to VSI
 * @tc_fltr: Pointer to TC flower filter structure
 * @dest_vsi: Pointer to VSI ptr
 *
 * Validates the tc forward action and determines the destination VSI and queue
 * for the forward action.
 */
static int __always_unused
mce_tc_forward_action(struct mce_vsi *vsi,
		      struct mce_tc_flower_fltr *tc_fltr,
			      struct mce_vsi **dest_vsi)
{
	struct mce_vsi *ch_vsi = NULL;
	struct mce_pf *pf = vsi->back;
	struct device *dev;

	dev = mce_pf_to_dev(pf);
	*dest_vsi = NULL;

	if (tc_fltr->action.fltr_act == MCE_FWD_TO_Q) {
		int q = tc_fltr->action.fwd.q.queue;

		ch_vsi = mce_locate_vsi_using_queue(vsi, q);
	} else if (tc_fltr->action.fltr_act == MCE_DROP_PACKET) {
		/* support drop packets */
		ch_vsi = mce_locate_vsi_using_queue(vsi, 0);
	} else {
		dev_err(dev,
			"Unable to add filter because of unsupported action %u (supported actions: drop or fwd to queue)\n",
			tc_fltr->action.fltr_act);
		return -EINVAL;
	}

	/* Must have valid "ch_vsi" (it could be main VSI or ADQ VSI */
	if (!ch_vsi) {
		dev_err(dev,
			"Unable to add filter because specified destination VSI doesn't exist\n");
		return -EINVAL;
	}

	*dest_vsi = ch_vsi;
	return 0;
}

static enum mce_protocol_type __maybe_unused
mce_proto_type_from_tunnel(enum mce_tunnel_type type)
{
	switch (type) {
	case TNL_VXLAN:
		return MCE_VXLAN;
	case TNL_GENEVE:
		return MCE_GENEVE;
	case TNL_GRETAP:
		return MCE_NVGRE;
	case TNL_GTPU:
		/* NO_PAY profiles will not work with GTP-U */
		return MCE_GTP;
	case TNL_GTPC:
		return MCE_GTP_NO_PAY;
	default:
		return 0;
	}
}

static enum mce_sw_tun_type
mce_sw_type_from_tunnel(enum mce_tunnel_type type)
{
	switch (type) {
	case TNL_VXLAN:
		return MCE_SW_TUN_VXLAN;
	case TNL_GENEVE:
		return MCE_SW_TUN_GENEVE;
	case TNL_GRETAP:
		return MCE_SW_TUN_GRE;
	case TNL_GTPU:
		return MCE_SW_TUN_GTP_U;
	case TNL_GTPC:
		return MCE_SW_TUN_GTP_C;
	case TNL_IPSEC:
		/* ipsec take as non tunnel */
		return MCE_SW_NON_TUN;
	default:
		return MCE_SW_NON_TUN;
	}
}

static bool mce_fd_is_support_bitmask(enum mce_fdir_mode_type fdir_mode,
				      u64 parse_list)
{
	if (fdir_mode == MCE_FDIR_EXACT_MACVLAN_MODE ||
	    fdir_mode == MCE_FDIR_SIGN_MACVLAN_MODE)
		return parse_list & (BIT_ULL(MCE_FLOW_ITEM_TYPE_ETH) |
				     BIT_ULL(MCE_FLOW_ITEM_TYPE_VLAN));
	return true;
}

static int mce_tc_fill_tunnel_outer(struct mce_tc_flower_fltr *tc_fltr,
				    u32 flags, struct mce_lkup_meta *meta,
				    u64 *inset, bool is_tunnel, void *handle,
				    u8 *fd_compose, int *bmask_num,
				    enum mce_fdir_mode_type fdir_mode)
{
	u64 lk_lists = 0, parse_list = 0;
	u32 meta_num = 0;
	int ret = 0, i;

	if (!is_tunnel)
		return 0;

	/* parse tunnel */
	lk_lists = MCE_PARSE_ENC_OUTER_FLOW_ITERM_LOOKUP_LISTS;
	for (i = 0; i < MCE_FLOW_ITEM_TYPE_MAX_NUM; i++) {
		/* if ok, get next meta form database */
		if (!ret)
			meta = mce_parse_get_next_meta(tc_fltr, handle,
						       &meta_num, is_tunnel);
		parse_list = lk_lists & BIT_ULL(i);
		switch (parse_list) {
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_ETH):
			ret = mce_parse_enc_eth(tc_fltr, flags, meta,
						inset, fd_compose,
						is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV4):
			ret = mce_parse_enc_ip4(tc_fltr, flags, meta,
						inset, fd_compose,
						is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV6):
			ret = mce_parse_enc_ip6(tc_fltr, flags, meta,
						inset, fd_compose,
						is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_UDP):
			ret = mce_parse_enc_udp(tc_fltr, flags, meta,
						inset, fd_compose,
						is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_VXLAN):
			ret = -1;
			if (tc_fltr->tunnel_type == TNL_VXLAN)
				ret = mce_parse_vxlan(tc_fltr, flags, meta,
						      inset, fd_compose,
						      is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_GENEVE):
			ret = -1;
			if (tc_fltr->tunnel_type == TNL_GENEVE)
				ret = mce_parse_geneve(tc_fltr, flags,
						       meta, inset,
						       fd_compose,
						       is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_NVGRE):
			ret = -1;
			if (tc_fltr->tunnel_type == TNL_GRETAP)
				ret = mce_parse_nvgre(tc_fltr, flags, meta,
						      inset, fd_compose,
						      is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_GTPC):
			ret = -1;
			if (tc_fltr->tunnel_type == TNL_GTPC)
				ret = mce_parse_gtpc(tc_fltr, flags, meta,
						     inset, fd_compose,
						     is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_GTPU):
			ret = -1;
			if (tc_fltr->tunnel_type == TNL_GTPU)
				ret = mce_parse_gtpu(tc_fltr, flags, meta,
						     inset, fd_compose,
						     is_tunnel);
			break;
		default:
			ret = -1;
			break;
		}

		if (!ret && !tc_fltr->parsed_inner &&
		    tc_fltr->f_module == MCE_FLOW_FDIR) {
			if (mce_fd_is_support_bitmask(fdir_mode, parse_list)) {
				*bmask_num +=
					mce_check_field_bitmask_valid(meta);
			}
		}
	}

	if (ret)
		meta_num--;
	return meta_num;
}

/**
 * mce_tc_flower_fill_rules - fill filter rules based on TC fltr
 * @hw: pointer to HW structure
 * @flags: TC flower field flags
 * @tc_fltr: pointer to TC flower filter
 * @filter: destination FDIR filter
 * @handle: mce_fdir_handle struct
 * @rule_info: pointer to information about rule
 * @fd_compose: compose list
 *
 * Fill mce_adv_lkup_elem list based on TC flower flags and
 * TC flower headers. This list should be used to add
 * advance filter in hardware.
 */
static int mce_tc_flower_fill_rules(struct mce_hw *hw, u32 flags,
				    struct mce_fdir_filter **filter,
				    struct mce_tc_flower_fltr *tc_fltr,
				    struct mce_fdir_handle *handle,
				    struct mce_adv_rule_info *rule_info,
				    u8 *fd_compose)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_field_bitmask_info *mask_info = NULL;
	int ret = 0, i, j, field_bitmask_num = 0;
	struct mce_lkup_meta *meta = NULL;
	u64 inset = 0, lk_lists;
	bool is_tunnel = false;
	u16 block_size = 0;
	u32 meta_num = 0;

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	u16 vlan_tpid = 0;
#endif /* CONFIG_NET_CLS_FLOWER */

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	rule_info->vlan_type = vlan_tpid;
#endif /* CONFIG_NET_CLS_FLOWER */

	if (test_bit(TNL_INNER_EN, hw->l2_fltr_flags))
		tc_fltr->parsed_inner = true;

	tc_fltr->f_module = MCE_FLOW_FDIR;
	rule_info->tun_type =
		mce_sw_type_from_tunnel(tc_fltr->tunnel_type);
	if (tc_fltr->tunnel_type != TNL_TC_LAST) {
		is_tunnel = true;
		meta_num = mce_tc_fill_tunnel_outer(tc_fltr, flags, meta, &inset, is_tunnel, handle,
						    fd_compose, &field_bitmask_num, pf->fdir_mode);
		if (!tc_fltr->parsed_inner && !!meta_num)
			goto only_parse_outer;
	}

	/* parse non-tunnel */
	ret = 0;
	lk_lists = MCE_PARSE_FLOW_ITERM_LOOKUP_LISTS;
	for (i = 0; i < MCE_FLOW_ITEM_TYPE_MAX_NUM; i++) {
		/* if ok, get next meta form database */
		if (!ret)
			meta = mce_parse_get_next_meta(tc_fltr, handle,
						       &meta_num, is_tunnel);
		switch (lk_lists & BIT_ULL(i)) {
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_ETH):
			ret = mce_parse_eth(tc_fltr, flags, meta, &inset,
					    fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_VLAN):
			ret = mce_parse_vlan(tc_fltr, flags, meta, &inset,
					     fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV4):
			ret = mce_parse_ip4(tc_fltr, flags, meta, &inset,
					    fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV6):
			ret = mce_parse_ip6(tc_fltr, flags, meta, &inset,
					    fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_UDP):
			ret = mce_parse_udp(tc_fltr, flags, meta, &inset,
					    fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_TCP):
			ret = mce_parse_tcp(tc_fltr, flags, meta, &inset,
					    fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_SCTP):
			ret = mce_parse_sctp(tc_fltr, flags, meta, &inset,
					     fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_ESP):
			ret = mce_parse_esp(tc_fltr, flags, meta, &inset,
					    fd_compose, is_tunnel);
			break;
		default:
			ret = -1;
			break;
		}
		if (!ret)
			field_bitmask_num +=
				mce_check_field_bitmask_valid(meta);
	}

only_parse_outer:
	meta = &handle->meta_db[is_tunnel][0];
	for (i = 0, j = 0; i < meta_num; i++) {
		if (!fd_compose[i])
			break;
		fd_logd(LOG_FDIR_DEBUG,
			"i:%d fd_compose:0x%02x meta_type:0x%02x\n", i,
			fd_compose[i], meta[i].type);
		j++;
	}
	meta_num = j;
	ret = mce_fd_check_params_valid(pf, tc_fltr, meta, meta_num, is_tunnel);
	if (ret)
		return ret;

	if (field_bitmask_num) {
		fd_logd(LOG_FDIR_DEBUG, "profile field bitmap en\n");
		fd_logd(LOG_FDIR_DEBUG, "meta_num:%d field_bitmask_num:%d\n",
			meta_num, field_bitmask_num);
		mask_info = kzalloc(sizeof(*mask_info),
				    GFP_KERNEL);
		if (!mask_info)
			return -ENOMEM;
		block_size = sizeof(struct mce_field_bitmask_block) *
			     field_bitmask_num;
		mask_info->field_bitmask = kzalloc(block_size, GFP_KERNEL);
		if (!mask_info->field_bitmask) {
			kfree(mask_info);
			return -ENOMEM;
		}
		meta = &handle->meta_db[is_tunnel][0];
		mce_fdir_field_mask_init(meta, meta_num, mask_info);
	}

	if (pf->fdir_mode == MCE_FDIR_EXACT_MACVLAN_MODE ||
	    pf->fdir_mode == MCE_FDIR_SIGN_MACVLAN_MODE) {
		*filter = mce_meta_to_fdir_rule_l2(hw, handle, meta_num, false,
						   is_tunnel);
	} else {
		*filter = mce_meta_to_fdir_rule(hw, handle, meta_num, false,
						is_tunnel);
	}

	if (!*filter)
		return -ENOMEM;

	(*filter)->mask_info = mask_info;
	(*filter)->options = inset;
	tc_fltr->tunnel_sw_type = rule_info->tun_type;
	tc_fltr->filter = *filter;

	return 0;
}

/**
 * mce_add_tc_flower_adv_fltr - add appropriate filter rules
 * @vsi: Pointer to VSI
 * @tc_fltr: Pointer to TC flower filter structure
 *
 * based on filter parameters using Advance recipes supported
 * by OS package.
 */
int mce_add_tc_flower_adv_fltr(struct mce_vsi *vsi,
			       struct mce_tc_flower_fltr *tc_fltr)
{
	struct mce_adv_rule_info rule_info = {};
	struct mce_fdir_handle *handle = NULL;
	struct mce_fdir_filter *filter = NULL;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &pf->hw;
	u32 flags = tc_fltr->flags;
	struct mce_vsi *ch_vsi;
	u8 *fd_compose = NULL;
	u16 prof_id = 0;
	int ret = 0;

	handle = (struct mce_fdir_handle *)mce_get_engine_handle(pf, MCE_FLOW_FDIR);
	if (!handle)
		return -EINVAL;
	if (mce_compose_init_item_type(&fd_compose))
		return -EINVAL;

	/* validate forwarding action VSI and queue */
	ret = mce_tc_forward_action(vsi, tc_fltr, &ch_vsi);
	if (ret)
		goto err_exit;

	ret = mce_tc_flower_fill_rules(hw, flags, &filter, tc_fltr, handle,
				       &rule_info, fd_compose);
	if (ret)
		goto err_exit;
	if (!mce_fdir_find_prof_id(pf, fd_compose, &prof_id, tc_fltr)) {
		dev_err(hw->dev, "fdir cannot find profile id\n");
		ret = -EINVAL;
		goto err_free_filter;
	}

	filter->profile_id = prof_id;
	if (mce_fdir_profile_mask_conflict(handle, filter)) {
		if (mce_is_arfs_using_perfect_flow(pf, prof_id)) {
			dev_err(hw->dev,
				"aRFS using perfect profile %u, cannot change input set\n",
				prof_id);
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
			NL_SET_ERR_MSG_MOD(tc_fltr->extack,
					   "aRFS is using this profile, cannot change input set");
#endif
			ret = -EBUSY;
		} else {
			dev_err(hw->dev,
				"fdir profile %u already uses a different input set\n",
				prof_id);
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
			NL_SET_ERR_MSG_MOD(tc_fltr->extack,
					   "profile already uses a different input set");
#endif
			ret = -EOPNOTSUPP;
		}
		goto err_free_filter;
	}

	hw_logd(LOG_FDIR_INFO,
		"%s: profile id:0x%x fltr->flags:0x%llx options:0x%llx\n",
		__func__, filter->profile_id, tc_fltr->flags, filter->options);
	ret = pf->flow_engine[MCE_FLOW_FDIR]->create(pf, filter, tc_fltr);
	goto err_exit;

err_free_filter:
	mce_tc_free_fdir_filter(filter);
	tc_fltr->filter = NULL;
err_exit:
	mce_compose_deinit_item_type(fd_compose);
	return ret;
}

/**
 * mce_tc_set_port - Parse ports from TC flower filter
 * @match: Flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true for tunnel port
 */
static int mce_tc_set_port(struct flow_match_ports match,
			   struct mce_tc_flower_fltr *fltr,
			     struct mce_tc_flower_lyr_2_4_hdrs *headers,
			     bool is_encap)
{
	if (match.key->dst) {
		fltr->flags |= MCE_TC_FLWR_FIELD_DEST_L4_PORT;
		headers->l4_key.dst_port = (match.key->dst);
		headers->l4_mask.dst_port = (match.mask->dst);
	}
	if (match.key->src) {
		fltr->flags |= MCE_TC_FLWR_FIELD_SRC_L4_PORT;
		headers->l4_key.src_port = (match.key->src);
		headers->l4_mask.src_port = (match.mask->src);
	}

	return 0;
}

/**
 * mce_tc_set_ipv4 - Parse IPv4 addresses from TC flower filter
 * @match: Pointer to flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true for tunnel IPv4 address
 */
static int mce_tc_set_ipv4(struct flow_match_ipv4_addrs *match,
			   struct mce_tc_flower_fltr *fltr,
			     struct mce_tc_flower_lyr_2_4_hdrs *headers,
			     bool is_encap)
{
	if (match->key->dst) {
		if (is_encap)
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_DEST_IPV4;
		else
			fltr->flags |= MCE_TC_FLWR_FIELD_DEST_IPV4;
		headers->l3_key.dst_ipv4 = match->key->dst;
		headers->l3_mask.dst_ipv4 = match->mask->dst;
	}
	if (match->key->src) {
		if (is_encap)
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_SRC_IPV4;
		else
			fltr->flags |= MCE_TC_FLWR_FIELD_SRC_IPV4;
		headers->l3_key.src_ipv4 = match->key->src;
		headers->l3_mask.src_ipv4 = match->mask->src;
	}
	return 0;
}

/**
 * mce_tc_set_ipv6 - Parse IPv6 addresses from TC flower filter
 * @match: Pointer to flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true for tunnel IPv6 address
 */
static int mce_tc_set_ipv6(struct flow_match_ipv6_addrs *match,
			   struct mce_tc_flower_fltr *fltr,
			     struct mce_tc_flower_lyr_2_4_hdrs *headers,
			     bool is_encap)
{
	struct mce_tc_l3_hdr *l3_key, *l3_mask;

	/* src and dest IPV6 address should not be LOOPBACK
	 * (0:0:0:0:0:0:0:1), which can be represented as ::1
	 */
	if (ipv6_addr_loopback(&match->key->dst) ||
	    ipv6_addr_loopback(&match->key->src)) {
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "Bad IPv6, addr is LOOPBACK");
		return -EINVAL;
	}
	/* if src/dest IPv6 address is *,* error */
	if (ipv6_addr_any(&match->mask->dst) &&
	    ipv6_addr_any(&match->mask->src)) {
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "Bad src/dest IPv6, addr is any");
		return -EINVAL;
	}
	if (!ipv6_addr_any(&match->mask->dst)) {
		if (is_encap)
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_DEST_IPV6;
		else
			fltr->flags |= MCE_TC_FLWR_FIELD_DEST_IPV6;
	}
	if (!ipv6_addr_any(&match->mask->src)) {
		if (is_encap)
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_SRC_IPV6;
		else
			fltr->flags |= MCE_TC_FLWR_FIELD_SRC_IPV6;
	}

	l3_key = &headers->l3_key;
	l3_mask = &headers->l3_mask;

	if (fltr->flags & (MCE_TC_FLWR_FIELD_ENC_SRC_IPV6 |
			   MCE_TC_FLWR_FIELD_SRC_IPV6)) {
		memcpy(&l3_key->src_ipv6_addr, &match->key->src.s6_addr,
		       sizeof(match->key->src.s6_addr));
		memcpy(&l3_mask->src_ipv6_addr, &match->mask->src.s6_addr,
		       sizeof(match->mask->src.s6_addr));
	}
	if (fltr->flags & (MCE_TC_FLWR_FIELD_ENC_DEST_IPV6 |
			   MCE_TC_FLWR_FIELD_DEST_IPV6)) {
		memcpy(&l3_key->dst_ipv6_addr, &match->key->dst.s6_addr,
		       sizeof(match->key->dst.s6_addr));
		memcpy(&l3_mask->dst_ipv6_addr, &match->mask->dst.s6_addr,
		       sizeof(match->mask->dst.s6_addr));
	}

	return 0;
}

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
/**
 * mce_is_tnl_gtp - detect if tunnel type is GTP or not
 * @tunnel_dev: ptr to tunnel device
 * @rule: ptr to flow_rule
 *
 * If curr_tnl_type is TNL_LAST and "flow_rule" is non-NULL, then
 * check if enc_dst_port is well known GTP port (2152)
 * if so - return true (indicating that tunnel type is GTP), otherwise false.
 */
static bool mce_is_tnl_gtp(struct net_device *tunnel_dev,
			   struct flow_rule *rule)
{
	/* if flow_rule is non-NULL, proceed with detecting possibility
	 * of GTP tunnel. Unlike VXLAN and GENEVE, there is no such API
	 * like  netif_is_gtp since GTP is not natively supported in kernel
	 */
	if (rule && (!is_vlan_dev(tunnel_dev))) {
		struct flow_match_ports match;
		u16 enc_dst_port;

		if (!flow_rule_match_key(rule,
					 FLOW_DISSECTOR_KEY_ENC_PORTS))
			return false;

		/* get ENC_PORTS info */
		flow_rule_match_enc_ports(rule, &match);
		enc_dst_port = be16_to_cpu(match.key->dst);

		/* Outer UDP port is GTP well known port,
		 * if 'enc_dst_port' matched with GTP well known port,
		 * return true from this function.
		 */
		return enc_dst_port == GTP1U_PORT;
	}
	return false;
}

/**
 * mce_tc_tun_get_type - get the tunnel type
 * @tunnel_dev: ptr to tunnel device
 * @rule: ptr to flow_rule
 * @fltr: flower rule
 *
 * This function detects appropriate tunnel_type if specified device is
 * tunnel device such as vxlan/geneve othertwise it tries to detect
 * tunnel type based on outer GTP port (2152)
 */
int mce_tc_tun_get_type(struct net_device *tunnel_dev,
			struct flow_rule *rule,
			struct mce_tc_flower_fltr *fltr)
{
#if IS_ENABLED(CONFIG_VXLAN)
	if (netif_is_vxlan(tunnel_dev))
		return TNL_VXLAN;
#endif
#if IS_ENABLED(CONFIG_GENEVE)
	if (netif_is_geneve(tunnel_dev))
		return TNL_GENEVE;
#endif
	if (netif_is_gretap(tunnel_dev) || netif_is_ip6gretap(tunnel_dev))
		return TNL_GRETAP;
	/* detect possibility of GTP tunnel type based on input */
	if (mce_is_tnl_gtp(tunnel_dev, rule))
		return TNL_GTPU;

	return TNL_LAST;
}

static bool mce_is_tunnel_supported(struct net_device *dev,
				    struct flow_rule *rule,
				    struct mce_tc_flower_fltr *fltr)
{
	int ret = 0;

	ret = mce_tc_tun_get_type(dev, rule, fltr);
	return ret != TNL_LAST;
}
#endif /* CONFIG_NET_CLS_FLOWER */

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
static bool mce_is_tunnel_supported_rule(struct flow_rule *rule)
{
	return (flow_rule_match_key(rule,
				    FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) ||
		flow_rule_match_key(rule,
				    FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) ||
		flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_KEYID) ||
		flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_PORTS));
}

static struct net_device *
mce_get_tunnel_device(struct net_device *dev, struct flow_rule *rule,
		      struct mce_tc_flower_fltr *fltr)
{
	struct flow_action_entry *act;
	int i;

	if (mce_is_tunnel_supported(dev, rule, fltr))
		return dev;

	flow_action_for_each(i, act, &rule->action) {
		if (act->id == FLOW_ACTION_REDIRECT &&
		    mce_is_tunnel_supported(act->dev, rule, fltr))
			return act->dev;
	}
	if (mce_is_tunnel_supported_rule(rule))
		return dev;

	return NULL;
}

/**
 * mce_tc_tun_info - Parse and store tunnel info
 * @pf: ptr to PF device
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @tunnel: type of tunnel (e.g. VxLAN, Geneve, GTP)
 *
 * Parse tunnel attributes such as tunnel_id and store them.
 */
static int mce_tc_tun_info(struct mce_pf *pf,
			   struct flow_cls_offload *f,
			     struct mce_tc_flower_fltr *fltr,
			     enum mce_tunnel_type tunnel)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);

	/* match on VNI */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_KEYID)) {
		struct device *dev = mce_pf_to_dev(pf);
		struct flow_match_enc_keyid enc_keyid;
		u32 key_id;

		flow_rule_match_enc_keyid(rule, &enc_keyid);
		if (!enc_keyid.mask->keyid) {
			dev_err(dev,
				"Bad mask for encap key_id 0x%04x, it must be non-zero\n",
				be32_to_cpu(enc_keyid.mask->keyid));
			return -EINVAL;
		}

		if (enc_keyid.mask->keyid !=
		    cpu_to_be32(MCE_TC_FLOWER_MASK_32)) {
			dev_err(dev,
				"Bad mask value for encap key_id 0x%04x\n",
				be32_to_cpu(enc_keyid.mask->keyid));
			return -EINVAL;
		}

		key_id = be32_to_cpu(enc_keyid.key->keyid);
		if (tunnel == TNL_VXLAN || tunnel == TNL_GENEVE) {
			/* VNI is only 3 bytes, applicable for VXLAN/GENEVE */
			if (key_id > MCE_TC_FLOWER_VNI_MAX) {
				dev_err(dev, "VNI out of range : 0x%x\n",
					key_id);
				return -EINVAL;
			}
		}
		fltr->flags |= MCE_TC_FLWR_FIELD_TENANT_ID;
		fltr->tenant_id = enc_keyid.key->keyid;
	}

	return 0;
}

/**
 * mce_tc_tun_parse - Parse tunnel attributes from TC flower filter
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to VSI structure
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 */
static int mce_tc_tun_parse(struct net_device *filter_dev,
			    struct mce_vsi *vsi,
			      struct flow_cls_offload *f,
			      struct mce_tc_flower_fltr *fltr,
			      struct mce_tc_flower_lyr_2_4_hdrs *headers)
{
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
#endif
	enum mce_tunnel_type tunnel_type;
	struct mce_pf *pf = vsi->back;
	struct device *dev;
	int err = 0;

	dev = mce_pf_to_dev(pf);
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	tunnel_type = mce_tc_tun_get_type(filter_dev, rule, fltr);
#else
	tunnel_type = TNL_LAST;
#endif

	if (tunnel_type == TNL_VXLAN || tunnel_type == TNL_GTPU ||
	    tunnel_type == TNL_GTPC || tunnel_type == TNL_GENEVE ||
	    /*tunnel_type == TNL_GRETAP || */ tunnel_type == TNL_IPSEC) {
		err = mce_tc_tun_info(pf, f, fltr, tunnel_type);
		if (err) {
			dev_err(dev,
				"Failed to parse tunnel (tunnel_type %u) attributes\n",
				tunnel_type);
			return err;
		}
	} else {
		dev_err(dev,
			"Tunnel HW offload is not supported for the tunnel type: %d\n",
			tunnel_type);
		return -EOPNOTSUPP;
	}
	fltr->tunnel_type = tunnel_type;
	if (headers->l3_key.ip_proto != IPPROTO_ESP)
		headers->l3_key.ip_proto = IPPROTO_UDP;
	return err;
}

/**
 * mce_parse_gtp_type - Sets GTP tunnel type to GTP-U or GTP-C
 * @match: Flow match structure
 * @fltr: Pointer to filter structure
 *
 * GTP-C/GTP-U is selected based on destination port number (enc_dst_port).
 * Before calling this funtcion, fltr->tunnel_type should be set to TNL_GTPU,
 * therefore making GTP-U the default choice (when destination port number is
 * not specified).
 */
static int mce_parse_gtp_type(struct flow_match_ports match,
			      struct mce_tc_flower_fltr *fltr)
{
	u16 dst_port;

	if (match.key->dst) {
		dst_port = be16_to_cpu(match.key->dst);

		switch (dst_port) {
#ifndef GTP1U_PORT
#define GTP1U_PORT 2152
#endif
		case GTP1U_PORT:
			break;
		case MCE_GTPC_PORT:
			fltr->tunnel_type = TNL_GTPC;
			break;
		default:
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Unsupported GTP port number");
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * mce_parse_tunnel_attr - Parse tunnel attributes from TC flower filter
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to VSI structure
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 */
static int
mce_parse_tunnel_attr(struct net_device *filter_dev,
		      struct mce_vsi *vsi, struct flow_cls_offload *f,
			struct mce_tc_flower_fltr *fltr,
			struct mce_tc_flower_lyr_2_4_hdrs *headers)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_match_control enc_control;
	int err;

	err = mce_tc_tun_parse(filter_dev, vsi, f, fltr, headers);
	if (err) {
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "failed to parse tunnel attributes");
		return err;
	}

	flow_rule_match_enc_control(rule, &enc_control);
	if (enc_control.key->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_enc_ipv4_addrs(rule, &match);
		if (mce_tc_set_ipv4(&match, fltr, headers, true))
			return -EINVAL;
	} else if (enc_control.key->addr_type ==
		   FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_enc_ipv6_addrs(rule, &match);
		if (mce_tc_set_ipv6(&match, fltr, headers, true))
			return -EINVAL;
	}

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IP)) {
		struct flow_match_ip match;

		flow_rule_match_enc_ip(rule, &match);

		if (match.mask->tos) {
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_IP_TOS;
			headers->l3_key.tos = match.key->tos;
			headers->l3_mask.tos = match.mask->tos;
		}

		if (match.mask->ttl) {
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_IP_TTL;
			headers->l3_key.ttl = match.key->ttl;
			headers->l3_mask.ttl = match.mask->ttl;
		}
	}
	#endif /* CONFIG_NET_CLS_FLOWER */

	if ((fltr->tunnel_type == TNL_VXLAN ||
	     fltr->tunnel_type == TNL_GENEVE) &&
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_enc_ports(rule, &match);
		if (match.key->dst) {
			fltr->flags |=
				MCE_TC_FLWR_FIELD_ENC_DEST_L4_PORT;
			/* tunnel packets unsupport src_port */
			headers->l4_key.dst_port = match.key->dst;
			headers->l4_mask.dst_port = match.mask->dst;
		}
	}

	if ((fltr->tunnel_type == TNL_GTPU ||
	     fltr->tunnel_type == TNL_GTPC) &&
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_enc_ports(rule, &match);

		if (mce_parse_gtp_type(match, fltr))
			return -EINVAL;
		if (match.key->dst) {
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_DEST_L4_PORT;
			/* tunnel packets unsupport src_port */
			headers->l4_key.dst_port = match.key->dst;
			headers->l4_mask.dst_port = match.mask->dst;
		}
	}

	return 0;
}
	#endif /* CONFIG_NET_CLS_FLOWER */

/**
 * mce_parse_cls_flower - Parse TC flower filters provided by kernel
 * @vsi: Pointer to the VSI
 * @filter_dev: Pointer to device on which filter is being added
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 */
static int mce_parse_cls_flower(struct net_device *filter_dev,
				struct mce_vsi *vsi,
				  struct flow_cls_offload *f,
				  struct mce_tc_flower_fltr *fltr)
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers =
		&fltr->outer_headers;
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	u16 n_proto_mask = 0, n_proto_key = 0, addr_type = 0;
	struct flow_dissector *dissector;
	struct mce_pf *pf = vsi->back;
	struct net_device *tunnel_dev;

	dissector = rule->match.dissector;

	if (dissector->used_keys & BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		if (pf->fdir_mode != MCE_FDIR_EXACT_MACVLAN_MODE &&
		    pf->fdir_mode != MCE_FDIR_SIGN_MACVLAN_MODE) {
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Not support in no macvlan mode");
			return -EOPNOTSUPP;
		}
	}

	if (dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_CONTROL) | BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_VLAN) |
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
	      BIT(FLOW_DISSECTOR_KEY_META) |
	      BIT(FLOW_DISSECTOR_KEY_PORTS))) {
		fd_logd(LOG_FDIR_DEBUG, "dissector used_keys:0x%llx\n",
			(unsigned long long)dissector->used_keys);
		NL_SET_ERR_MSG_MOD(fltr->extack, "Unsupported key used");
		return -EOPNOTSUPP;
	}
	tunnel_dev = mce_get_tunnel_device(filter_dev, rule, fltr);
	if (tunnel_dev) {
		int err;

		filter_dev = tunnel_dev;
		err = mce_parse_tunnel_attr(filter_dev, vsi, f, fltr,
					    headers);
		if (err) {
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Failed to parse TC flower tunnel attributes");
			return err;
		}

		/* header pointers should point to the inner headers, outer
		 * header were already set by mce_parse_tunnel_attr
		 */
		headers = &fltr->inner_headers;
	} else {
		fltr->tunnel_type = TNL_LAST;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);

		n_proto_key = ntohs(match.key->n_proto);
		n_proto_mask = ntohs(match.mask->n_proto);

		fltr->flags |= MCE_TC_FLWR_FIELD_ETH_TYPE_ID;
		headers->l2_key.n_proto = cpu_to_be16(n_proto_key);
		headers->l2_mask.n_proto = cpu_to_be16(n_proto_mask);
		headers->l3_key.ip_proto = match.key->ip_proto;
		headers->l3_mask.ip_proto = match.mask->ip_proto;

		switch (headers->l3_key.ip_proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_SCTP:
		case IPPROTO_IP:
		case IPPROTO_ESP:
			break;
		default:
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Only IP ESP UDP TCP and SCTP protocols are supported");
			return -EINVAL;
		}

		fd_logd(LOG_FDIR_DEBUG,
			"parse n_proto:0x%x nmask:0x%x ip_proto:0x%x ipmask:0x%x\n",
			headers->l2_key.n_proto, headers->l2_mask.n_proto,
			match.key->ip_proto, match.mask->ip_proto);
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs match;

		flow_rule_match_eth_addrs(rule, &match);

		if (!is_zero_ether_addr(match.key->dst)) {
			ether_addr_copy(headers->l2_key.dst_mac,
					match.key->dst);
			ether_addr_copy(headers->l2_mask.dst_mac,
					match.mask->dst);
			fltr->flags |= MCE_TC_FLWR_FIELD_DST_MAC;
		}

		if (!is_zero_ether_addr(match.key->src)) {
			ether_addr_copy(headers->l2_key.src_mac,
					match.key->src);
			ether_addr_copy(headers->l2_mask.src_mac,
					match.mask->src);
			fltr->flags |= MCE_TC_FLWR_FIELD_SRC_MAC;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN) ||
	    is_vlan_dev(filter_dev)) {
		struct flow_dissector_key_vlan mask;
		struct flow_dissector_key_vlan key;
		struct flow_match_vlan match;

		if (is_vlan_dev(filter_dev)) {
			match.key = &key;
			match.key->vlan_id = vlan_dev_vlan_id(filter_dev);
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
			match.key->vlan_tpid =
				vlan_dev_vlan_proto(filter_dev);
#endif /* CONFIG_NET_CLS_FLOWER */
			match.key->vlan_priority = 0;
			match.mask = &mask;
			memset(match.mask, 0xff, sizeof(*match.mask));
			match.mask->vlan_priority = 0;
		} else {
			flow_rule_match_vlan(rule, &match);
		}

		if (match.mask->vlan_id) {
			if (match.mask->vlan_id == VLAN_VID_MASK) {
				fltr->flags |= MCE_TC_FLWR_FIELD_VLAN;
				headers->vlan_hdr.vlan_id =
					cpu_to_be16(match.key->vlan_id &
						    VLAN_VID_MASK);
			} else {
				NL_SET_ERR_MSG_MOD(fltr->extack,
						   "Bad VLAN mask");
				return -EINVAL;
			}
		}

		if (match.mask->vlan_priority) {
			fltr->flags |= MCE_TC_FLWR_FIELD_VLAN_PRIO;
			headers->vlan_hdr.vlan_prio =
				be16_encode_bits(match.key->vlan_priority, VLAN_PRIO_MASK);
		}
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
		if (match.mask->vlan_tpid)
			headers->vlan_hdr.vlan_tpid = match.key->vlan_tpid;
#endif /* CONFIG_NET_CLS_FLOWER */
	}

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CVLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_cvlan(rule, &match);
		if (match.mask->vlan_id) {
			if (match.mask->vlan_id == VLAN_VID_MASK) {
				fltr->flags |= MCE_TC_FLWR_FIELD_CVLAN;
				headers->cvlan_hdr.vlan_id =
					cpu_to_be16(match.key->vlan_id &
						    VLAN_VID_MASK);
			} else {
				NL_SET_ERR_MSG_MOD(fltr->extack,
						   "Bad CVLAN mask");
				return -EINVAL;
			}
		}

		if (match.mask->vlan_priority) {
			fltr->flags |= MCE_TC_FLWR_FIELD_CVLAN_PRIO;
			headers->cvlan_hdr.vlan_prio =
				be16_encode_bits(match.key->vlan_priority, VLAN_PRIO_MASK);
		}
	}
#endif /* CONFIG_NET_CLS_FLOWER */

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control match;

		flow_rule_match_control(rule, &match);
		/* ip flags, first frag take as normal frag*/
		if (match.key->flags & FLOW_DIS_IS_FRAGMENT)
			fltr->flags |= MCE_TC_FLWR_FIELD_FLAGS_IS_FRAGMENT;
		if (match.key->flags & FLOW_DIS_FIRST_FRAG)
			fltr->flags |= MCE_TC_FLWR_FIELD_FLAGS_IS_FRAGMENT;
		addr_type = match.key->addr_type;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);
		if (mce_tc_set_ipv4(&match, fltr, headers, false))
			return -EINVAL;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_ipv6_addrs(rule, &match);
		if (mce_tc_set_ipv6(&match, fltr, headers, false))
			return -EINVAL;
	}

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
		struct flow_match_ip match;

		flow_rule_match_ip(rule, &match);

		if (match.mask->tos) {
			if (match.mask->tos != 0xff) {
				NL_SET_ERR_MSG_MOD(fltr->extack,
						   "unsupported ipv4/v6 tos mask");
				return -EOPNOTSUPP;
			}
			fltr->flags |= MCE_TC_FLWR_FIELD_IP_TOS;
			headers->l3_key.tos = match.key->tos;
			headers->l3_mask.tos = match.mask->tos;
			fd_logd(LOG_FDIR_DEBUG, "parse tos:0x%x mask:0x%x\n",
				match.key->tos, match.mask->tos);
		}

		if (match.mask->ttl) {
			fltr->flags |= MCE_TC_FLWR_FIELD_IP_TTL;
			headers->l3_key.ttl = match.key->ttl;
			headers->l3_mask.ttl = match.mask->ttl;
		}
	}
#endif /* CONFIG_NET_CLS_FLOWER */

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);
		if (mce_tc_set_port(match, fltr, headers, false))
			return -EINVAL;
		switch (headers->l3_key.ip_proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_SCTP:
			break;
		default:
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Only UDP TCP and SCTP transport are supported");
			return -EINVAL;
		}
	}

	return 0;
}

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
/**
 * mce_handle_tclass_action - Support directing to a traffic class or queue
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to TC flower offload structure
 * @fltr: Pointer to TC flower filter structure
 *
 * Support directing traffic to a traffic class or queue
 */
static int mce_handle_tclass_action(struct mce_vsi *vsi,
				    struct flow_cls_offload *cls_flower,
				      struct mce_tc_flower_fltr *fltr)
{
	unsigned int nrx = TC_H_MIN(cls_flower->classid);
	u32 num_tc;
	u32 queue;

	num_tc = (u32)netdev_get_num_tc(vsi->netdev);

	if (nrx < TC_H_MIN_PRIORITY) {
		/* user specified queue, hence action is forward to queue */
		if (nrx >= vsi->num_rxq) {
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Unable to add filter because specified queue is invalid");
			return -ENXIO;
		}

		queue = nrx;
		/* forward to queue */
		if (fltr->action.fltr_act != MCE_DROP_PACKET)
			fltr->action.fltr_act = MCE_FWD_TO_Q;
		fltr->action.fwd.q.queue = queue;
	} else if ((nrx - TC_H_MIN_PRIORITY) < num_tc) {
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "Unable to add filter because user specified not support hw_tc as forward action");
		return -EINVAL;
	} else {
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "Unable to add filter because user specified neither queue nor hw_tc as forward action");
		return -EINVAL;
	}

	return 0;
}

#endif

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
static bool mce_tc_is_dev_uplink(struct net_device *dev,
				 struct mce_tc_flower_fltr *fltr)
{
	return netif_is_mce(dev) ||
	       mce_is_tunnel_supported(dev, NULL, fltr);
}

static int mce_tc_setup_redirect_action(struct net_device *filter_dev,
					struct mce_tc_flower_fltr *fltr,
					struct net_device *target_dev)
{
	fltr->action.fltr_act = MCE_FWD_TO_VSI;

	if (mce_is_port_repr_netdev(filter_dev) &&
	    mce_is_port_repr_netdev(target_dev)) {
		struct mce_repr *repr = mce_netdev_to_repr(target_dev);

		fltr->dest_vsi = repr->src_vsi;
		fltr->direction = MCE_ESWITCH_FLTR_EGRESS;
	} else if (mce_is_port_repr_netdev(filter_dev) &&
		   mce_tc_is_dev_uplink(target_dev, fltr)) {
		struct mce_repr *repr = mce_netdev_to_repr(filter_dev);

		fltr->dest_vsi = repr->src_vsi->back->switchdev.uplink_vsi;
		fltr->direction = MCE_ESWITCH_FLTR_EGRESS;
	} else if (mce_tc_is_dev_uplink(filter_dev, fltr) &&
		   mce_is_port_repr_netdev(target_dev)) {
		struct mce_repr *repr = mce_netdev_to_repr(target_dev);

		fltr->dest_vsi = repr->src_vsi;
		fltr->direction = MCE_ESWITCH_FLTR_INGRESS;
	} else {
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "Unsupported netdevice in switchdev mode");
		return -EINVAL;
	}

	return 0;
}
#endif

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
static int __maybe_unused mce_tc_setup_drop_action(struct net_device *filter_dev,
						   struct mce_tc_flower_fltr *fltr)
{
	fltr->action.fltr_act = MCE_DROP_PACKET;

	if (mce_is_port_repr_netdev(filter_dev)) {
		struct mce_repr *repr = mce_netdev_to_repr(filter_dev);

		fltr->dest_vsi = repr->src_vsi;
		fltr->direction = MCE_ESWITCH_FLTR_EGRESS;
	} else if (mce_tc_is_dev_uplink(filter_dev, fltr)) {
		struct mce_netdev_priv *np = netdev_priv(filter_dev);
		struct mce_vsi *vsi = np->vsi;

		fltr->dest_vsi = vsi->back->switchdev.uplink_vsi;
		fltr->direction = MCE_ESWITCH_FLTR_INGRESS;
	} else {
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "Unsupported netdevice in switchdev mode");
		return -EINVAL;
	}

	return 0;
}
#endif /* CONFIG_NET_CLS_FLOWER */

static int mce_eswitch_tc_parse_action(struct net_device *filter_dev,
				       struct mce_tc_flower_fltr *fltr,
				       struct flow_action_entry *act)
{
	int err;

	switch (act->id) {
	case FLOW_ACTION_DROP:
		err = mce_tc_setup_drop_action(filter_dev, fltr);
		if (err)
			return err;

		break;
	case FLOW_ACTION_REDIRECT:
		err = mce_tc_setup_redirect_action(filter_dev, fltr,
						   act->dev);
		if (err)
			return err;

		break;

	default:
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "Unsupported action in switchdev mode");
		return -EINVAL;
	}

	return 0;
}

/**
 * mce_parse_tc_flower_actions - Parse the actions for a TC filter
 * @filter_dev: Ingress netdev
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to TC flower offload structure
 * @fltr: Pointer to TC flower filter structure
 *
 * Parse the actions for a TC filter
 */
static int
mce_parse_tc_flower_actions(struct net_device *filter_dev,
			    struct mce_vsi *vsi,
			      struct flow_cls_offload *cls_flower,
			      struct mce_tc_flower_fltr *fltr)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls_flower);
	struct flow_action *flow_action = &rule->action;
	struct flow_action_entry *act;
	int i;

	if (!flow_action_has_entries(flow_action))
		goto no_action;

	flow_action_for_each(i, act, flow_action) {
		if (mce_is_eswitch_mode_switchdev(vsi->back)) {
			int err = mce_eswitch_tc_parse_action(filter_dev,
							      fltr, act);

			if (err)
				return err;
			continue;
		}

		/* Drop action */
		if (act->id == FLOW_ACTION_DROP) {
			/* only support drop or pass */
			fltr->action.fltr_act = MCE_DROP_PACKET;
		}
		if (act->id == FLOW_ACTION_VLAN_POP) {
			/* Support VLAN pop; netdev configures VLAN status. */
			fltr->action.pop_vlan = true;
		}
	}

no_action:
	if (cls_flower->classid)
		return mce_handle_tclass_action(vsi, cls_flower, fltr);

	return 0;
}

static int mce_tc_eswitch_fill_rules(struct mce_hw *hw, u32 flags,
				     struct mce_eswitch_filter **filter,
				     struct mce_tc_flower_fltr *tc_fltr,
				     struct mce_eswitch_handle *handle,
				     struct mce_adv_rule_info *rule_info,
				     u8 *compose)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_flow_ptype_match *support;
	struct mce_lkup_meta *meta = NULL;
	u64 inset = 0, lk_lists;
	bool is_tunnel = false;
	int ret = 0, i, j;
	u32 meta_num = 0;

	/* eswitch unsupport parser inner mode */
	tc_fltr->parsed_inner = false;
	tc_fltr->f_module = MCE_FLOW_ESWITCH;
	rule_info->tun_type = mce_sw_type_from_tunnel(tc_fltr->tunnel_type);
	if (tc_fltr->tunnel_type != TNL_TC_LAST) {
		is_tunnel = true;
		meta_num = mce_tc_fill_tunnel_outer(tc_fltr, flags, meta,
						    &inset, is_tunnel, handle,
						    compose, NULL,
						    MCE_FDIR_MAX_MODE);
		goto only_parse_outer;
	}

	/* parse non-tunnel */
	ret = 0;
	lk_lists = MCE_PARSE_FLOW_ITERM_LOOKUP_LISTS;
	for (i = 0; i < MCE_FLOW_ITEM_TYPE_MAX_NUM; i++) {
		/* if ok, get next meta form database */
		if (!ret)
			meta = mce_parse_get_next_meta(tc_fltr, handle,
						       &meta_num, is_tunnel);
		switch (lk_lists & BIT_ULL(i)) {
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_ETH):
			ret = mce_parse_eth(tc_fltr, flags, meta, &inset,
					    compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_VLAN):
			ret = mce_parse_vlan(tc_fltr, flags, meta, &inset,
					     compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV4):
			ret = mce_parse_ip4(tc_fltr, flags, meta, &inset,
					    compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV6):
			ret = mce_parse_ip6(tc_fltr, flags, meta, &inset,
					    compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_UDP):
			ret = mce_parse_udp(tc_fltr, flags, meta, &inset,
					    compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_TCP):
			ret = mce_parse_tcp(tc_fltr, flags, meta, &inset,
					    compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_SCTP):
			ret = mce_parse_sctp(tc_fltr, flags, meta, &inset,
					     compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_ESP):
			ret = mce_parse_esp(tc_fltr, flags, meta, &inset,
					    compose, is_tunnel);
			break;
		default:
			ret = -1;
			break;
		}
	}

only_parse_outer:
	meta = &handle->meta_db[is_tunnel][0];
	for (i = 0, j = 0; i < meta_num; i++) {
		if (compose[i]) {
			fd_logd(LOG_FDIR_DEBUG,
				"i:%d compose:0x%02x meta_type:0x%02x\n", i,
				compose[i], meta[i].type);
			j++;
		}
		break;
	}
	meta_num = j;

	support = mce_eswitch_check_pattern_support(pf, compose, tc_fltr);
	if (!support) {
		dev_err(hw->dev, "eswitch pattern unsupport\n");
		return -EINVAL;
	}

	if (support->hw_type == MCE_ESW_MODE_LEGACY) {
		*filter =
			mce_meta_to_eswitch_legacy(hw, tc_fltr, handle, meta_num,
						   false, is_tunnel);
	} else {
		*filter =
			mce_meta_to_eswitch_switchdev(hw, tc_fltr, handle, meta_num,
						      false, is_tunnel);
	}

	if (!*filter)
		return -ENOMEM;

	(*filter)->eswitch_type = support->hw_type;
	(*filter)->options = inset;
	tc_fltr->tunnel_sw_type = rule_info->tun_type;
	tc_fltr->efilter = *filter;
	return 0;
}

static int mce_eswitch_add_tc_fltr(struct mce_vsi *vsi,
				   struct mce_tc_flower_fltr *tc_fltr)
{
	struct mce_eswitch_handle *handle = NULL;
	struct mce_eswitch_filter *filter = NULL;
	struct mce_adv_rule_info rule_info = {};
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &pf->hw;
	u32 flags = tc_fltr->flags;
	u8 *compose = NULL;
	int ret = 0;

	if (test_bit(TNL_INNER_EN, hw->l2_fltr_flags)) {
		netdev_err(vsi->netdev, "eswitch unsupport parse inner mode\n");
		return -EINVAL;
	}

	handle = (struct mce_eswitch_handle *)mce_get_engine_handle(pf, MCE_FLOW_ESWITCH);
	if (!handle)
		return -EINVAL;

	if (mce_compose_init_item_type(&compose))
		return -EINVAL;

	ret = mce_tc_eswitch_fill_rules(hw, flags, &filter, tc_fltr, handle,
					&rule_info, compose);
	if (ret)
		goto err_exit;

	ret = pf->flow_engine[MCE_FLOW_ESWITCH]->create(pf, filter, tc_fltr);
err_exit:
	mce_compose_deinit_item_type(compose);
	return ret;
}

/**
 * mce_add_switch_fltr - Add TC flower filters
 * @vsi: Pointer to VSI
 * @fltr: Pointer to struct mce_tc_flower_fltr
 *
 * Add filter in HW switch block
 */
static int mce_add_switch_fltr(struct mce_vsi *vsi,
			       struct mce_tc_flower_fltr *fltr)
{
	if (mce_is_eswitch_mode_switchdev(vsi->back))
		return mce_eswitch_add_tc_fltr(vsi, fltr);

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	if (fltr->action.fltr_act == MCE_FWD_TO_QGRP)
		return -EOPNOTSUPP;
#endif /* CONFIG_NET_CLS_FLOWER */
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	return mce_add_tc_flower_adv_fltr(vsi, fltr);
#else
	return -EOPNOTSUPP;
#endif /* CONFIG_NET_CLS_FLOWER */
}

/**
 * mce_add_tc_fltr - adds a TC flower filter
 * @netdev: Pointer to netdev
 * @vsi: Pointer to VSI
 * @f: Pointer to flower offload structure
 * @__fltr: Pointer to struct mce_tc_flower_fltr
 *
 * This function parses TC-flower input fields, parses action,
 * and adds a filter.
 */
static int mce_add_tc_fltr(struct net_device *netdev,
			   struct mce_vsi *vsi,
			     struct flow_cls_offload *f,
			     struct mce_tc_flower_fltr **__fltr)
{
	struct mce_tc_flower_fltr *fltr;
	int err;

	/* by default, set output to be INVALID */
	*__fltr = NULL;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return -ENOMEM;

	fltr->cookie = f->cookie;
	fltr->extack = f->common.extack;
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);

	err = mce_parse_cls_flower(netdev, vsi, f, fltr);
	if (err < 0)
		goto err;

	err = mce_parse_tc_flower_actions(netdev, vsi, f, fltr);
	if (err < 0)
		goto err;

	err = mce_add_switch_fltr(vsi, fltr);
	if (err < 0)
		goto err;

	/* return the newly created filter */
	*__fltr = fltr;

	return 0;
err:
	kfree(fltr);
	return err;
}

/**
 * mce_find_tc_flower_fltr - Find the TC flower filter in the list
 * @pf: Pointer to PF
 * @cookie: filter specific cookie
 */
static struct mce_tc_flower_fltr *
mce_find_tc_flower_fltr(struct mce_pf *pf, unsigned long cookie)
{
	struct mce_tc_flower_fltr *fltr;

	hlist_for_each_entry(fltr, &pf->tc_flower_fltr_list,
			     tc_flower_node)
		if (cookie == fltr->cookie)
			return fltr;

	return NULL;
}

/**
 * mce_fdir_flow_query_tc_flower_fltr - Find the TC flower filter in the list
 * @pf: Pointer to PF
 */
int mce_fdir_flow_query_tc_flower_fltr(struct mce_pf *pf)
{
	struct mce_tc_flower_fltr *fltr;

	hlist_for_each_entry(fltr, &pf->tc_flower_fltr_list, tc_flower_node)
		pf->flow_engine[MCE_FLOW_FDIR]->query(pf, fltr);
	return 0;
}

/**
 * mce_add_cls_flower - add TC flower filters
 * @netdev: Pointer to filter device
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to flower offload structure
 */
int
mce_add_cls_flower(struct net_device *netdev, struct mce_vsi *vsi,
		   struct flow_cls_offload *cls_flower)
{
	struct netlink_ext_ack *extack = cls_flower->common.extack;
	struct net_device *vsi_netdev = vsi->netdev;
	struct mce_tc_flower_fltr *fltr;
	struct mce_pf *pf = vsi->back;
	int err;

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "can't apply TC flower filters, turn off sriov and try again");
		return -EOPNOTSUPP;
	}

	if (!(vsi_netdev->features & NETIF_F_HW_TC) ||
	    !(vsi_netdev->wanted_features & NETIF_F_HW_TC)) {
		/* Based on TC indirect notifications from kernel, all ice
		 * devices get an instance of rule from higher level device.
		 * Avoid triggering explicit error in this case.
		 */
		if (netdev == vsi_netdev)
			NL_SET_ERR_MSG_MOD(extack,
					   "can't apply TC flower filters, turn ON hw-tc-offload and try again");
		return -EINVAL;
	}

	/* avoid duplicate entries, if exists - return error */
	fltr = mce_find_tc_flower_fltr(pf, cls_flower->cookie);
	if (fltr) {
		NL_SET_ERR_MSG_MOD(extack, "filter cookie already exists, ignoring");
		return -EEXIST;
	}
	/* prep and add TC-flower filter in HW */
	err = mce_add_tc_fltr(netdev, vsi, cls_flower, &fltr);
	if (err)
		return err;

	/* add filter into an ordered list */
	hlist_add_head(&fltr->tc_flower_node, &pf->tc_flower_fltr_list);
	return 0;
}

/**
 * mce_del_tc_fltr - deletes a filter from HW table
 * @vsi: Pointer to VSI
 * @fltr: Pointer to struct mce_tc_flower_fltr
 *
 * This function deletes a filter from HW table and manages book-keeping
 */
static int mce_del_tc_fltr(struct mce_vsi *vsi,
			   struct mce_tc_flower_fltr *fltr)
{
	struct mce_pf *pf = vsi->back;
	int err = 0;

	if (fltr->f_module == MCE_FLOW_ESWITCH)
		err = pf->flow_engine[MCE_FLOW_ESWITCH]->destroy(pf, fltr->efilter, fltr);
	else
		err = pf->flow_engine[MCE_FLOW_FDIR]->destroy(pf, fltr->filter, fltr);

	if (err) {
		if (err == -ENOENT) {
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Filter does not exist");
			return -ENOENT;
		}
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "Failed to delete TC flower filter");
		return -EIO;
	}

	return 0;
}

/**
 * mce_del_cls_flower - delete TC flower filters
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to struct flow_cls_offload
 */
int mce_del_cls_flower(struct mce_vsi *vsi,
		       struct flow_cls_offload *cls_flower)
{
	struct mce_tc_flower_fltr *fltr;
	struct mce_pf *pf = vsi->back;
	int err;

	fltr = mce_find_tc_flower_fltr(pf, cls_flower->cookie);
	if (!fltr) {
		/* TC may issue DESTROY to roll back a failed REPLACE before
		 * the filter was added to the driver's list. Treat unknown
		 * cookies as an idempotent delete so core cleanup can finish.
		 */
		return 0;
	}

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	fltr->extack = cls_flower->common.extack;
#endif
	err = mce_del_tc_fltr(vsi, fltr);
	if (err)
		return err;

	/* delete filter from an ordered list */
	hlist_del(&fltr->tc_flower_node);

	/* free the filter node */
	kfree(fltr);

	return 0;
}
#endif /* CONFIG_NET_CLS_FLOWER */
