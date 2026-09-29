// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_base.h"
#include "mce_irq.h"
#include "mce_lib.h"
#include "mce_sriov.h"
#include "mce_n20/mce_hw_n20.h"
#include "mce_arfs.h"
#include "mce_fdir_flow.h"
#include <net/inet_hashtables.h>
#include <net/tcp.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/inet6_hashtables.h>
#endif

#if IS_ENABLED(CONFIG_RFS_ACCEL) && IS_ENABLED(CONFIG_NET_CLS_FLOWER)

#define MCE_ARFS_UDP_IDLE_TIMEOUT msecs_to_jiffies(5000)

static struct mce_lkup_meta *
mce_arfs_find_meta(struct mce_arfs_entry *entry, enum flow_meta_type type);

/**
 * mce_is_arfs_active - helper to check is aRFS is active
 * @vsi: VSI to check
 */
static bool mce_is_arfs_active(struct mce_vsi *vsi)
{
	return !!vsi->arfs_fltr_list;
}

static bool mce_arfs_is_fdir_mode_supported(struct mce_pf *pf)
{
	return pf && pf->fdir_mode != MCE_FDIR_EXACT_MACVLAN_MODE &&
	       pf->fdir_mode != MCE_FDIR_SIGN_MACVLAN_MODE;
}

static bool mce_arfs_is_supported(struct mce_pf *pf)
{
	return mce_arfs_enable && mce_arfs_is_fdir_mode_supported(pf);
}

bool mce_is_arfs_using_perfect_flow(struct mce_pf *pf, u16 profile_id)
{
	struct mce_arfs_active_fltr_cntrs *cntrs;
	struct mce_vsi *vsi;

	if (!pf)
		return false;
	if (!mce_arfs_is_supported(pf))
		return false;

	vsi = mce_get_main_vsi(pf);
	if (!vsi || !vsi->arfs_fltr_cntrs)
		return false;

	cntrs = vsi->arfs_fltr_cntrs;
	/* Pair with the counter updates before checking active filter state. */
	smp_mb__before_atomic();
	switch (profile_id) {
	case MCE_PTYPE_IPV4_TCP:
		return atomic_read(&cntrs->active_tcpv4_cnt) > 0;
	case MCE_PTYPE_IPV6_TCP:
		return atomic_read(&cntrs->active_tcpv6_cnt) > 0;
	case MCE_PTYPE_IPV4_UDP:
		return atomic_read(&cntrs->active_udpv4_cnt) > 0;
	case MCE_PTYPE_IPV6_UDP:
		return atomic_read(&cntrs->active_udpv6_cnt) > 0;
	default:
		return false;
	}
}

bool mce_has_arfs_active_fltrs(struct mce_pf *pf)
{
	struct mce_arfs_active_fltr_cntrs *cntrs;
	struct mce_vsi *vsi;

	if (!pf)
		return false;
	if (!mce_arfs_is_supported(pf))
		return false;

	vsi = mce_get_main_vsi(pf);
	if (!vsi || !vsi->arfs_fltr_cntrs)
		return false;

	cntrs = vsi->arfs_fltr_cntrs;
	/* Pair with the counter updates before checking active filter state. */
	smp_mb__before_atomic();
	return atomic_read(&cntrs->active_tcpv4_cnt) > 0 ||
	       atomic_read(&cntrs->active_tcpv6_cnt) > 0 ||
	       atomic_read(&cntrs->active_udpv4_cnt) > 0 ||
	       atomic_read(&cntrs->active_udpv6_cnt) > 0;
}

bool mce_is_arfs_enabled(struct mce_pf *pf)
{
	struct mce_vsi *vsi;

	if (!pf)
		return false;

	vsi = mce_get_main_vsi(pf);
	return mce_arfs_is_supported(pf) && vsi && mce_is_arfs_active(vsi);
}

static u16 mce_arfs_fdir_queue(u16 rxq_idx)
{
	return rxq_idx;
}

static void mce_arfs_free_filter(struct mce_fdir_filter *filter)
{
	if (!filter)
		return;

	if (filter->mask_info) {
		kfree(filter->mask_info->field_bitmask);
		kfree(filter->mask_info);
	}
	kfree(filter);
}

static int mce_arfs_fill_lkup_pattern(struct mce_pf *pf,
				      struct mce_arfs_entry *e)
{
	struct mce_fdir_filter *filter = e->fltr_info.filter;
	union mce_fdir_pattern *lkup_pattern;
	struct mce_lkup_meta *meta;
	int i;

	if (!filter)
		return -EINVAL;

	lkup_pattern = &filter->lkup_pattern;
	memset(lkup_pattern, 0, sizeof(*lkup_pattern));
	filter->is_ipv6 = false;

	for (i = 0; i < MCE_META_TYPE_MAX; i++) {
		meta = &e->meta[i];
		if (meta->type == MCE_META_TYPE_MAX)
			break;

		switch (meta->type) {
		case MCE_ETH_META:
			lkup_pattern->formatted.ether_type =
				meta->hdr.eth_meta.ethtype_id;
			break;
		case MCE_IPV4_META:
			lkup_pattern->formatted.src_addr[0] =
				meta->hdr.ipv4_meta.src_addr;
			lkup_pattern->formatted.dst_addr[0] =
				meta->hdr.ipv4_meta.dst_addr;
			lkup_pattern->formatted.protocol =
				meta->hdr.ipv4_meta.protocol;
			break;
		case MCE_IPV6_META:
			memcpy(lkup_pattern->formatted.src_addr,
			       meta->hdr.ipv6_meta.src_addr,
			       sizeof(meta->hdr.ipv6_meta.src_addr));
			memcpy(lkup_pattern->formatted.dst_addr,
			       meta->hdr.ipv6_meta.dst_addr,
			       sizeof(meta->hdr.ipv6_meta.dst_addr));
			lkup_pattern->formatted.protocol =
				meta->hdr.ipv6_meta.protocol;
			filter->is_ipv6 = true;
			break;
		case MCE_UDP_META:
			lkup_pattern->formatted.l4_dport =
				meta->hdr.udp_meta.dst_port;
			lkup_pattern->formatted.l4_sport =
				meta->hdr.udp_meta.src_port;
			break;
		case MCE_TCP_META:
			lkup_pattern->formatted.l4_dport =
				meta->hdr.tcp_meta.dst_port;
			lkup_pattern->formatted.l4_sport =
				meta->hdr.tcp_meta.src_port;
			break;
		default:
			dev_err(mce_pf_to_dev(pf),
				"%s the rule type:0x%x is not exist option.\n",
				__func__, meta->type);
			return -EINVAL;
		}
	}

	return 0;
}

static int mce_arfs_alloc_filter(struct mce_pf *pf, struct mce_arfs_entry *e,
				 gfp_t gfp)
{
	struct mce_fdir_filter *filter;
	int ret;

	if (e->fltr_info.filter)
		return 0;

	filter = kzalloc(sizeof(*filter), gfp);
	if (!filter)
		return -ENOMEM;

	filter->options = e->options;
	filter->profile_id = e->profile_id;
	e->fltr_info.filter = filter;

	ret = mce_arfs_fill_lkup_pattern(pf, e);
	if (ret) {
		mce_arfs_free_filter(filter);
		e->fltr_info.filter = NULL;
	}

	return ret;
}

static int mce_arfs_fdir_del_fltr(struct mce_pf *pf, struct mce_arfs_entry *e)
{
	struct mce_tc_flower_fltr *fltr = &e->fltr_info;
	int ret;

	if (!e->hw_rule || !fltr->filter)
		return 0;

	ret = pf->flow_engine[MCE_FLOW_FDIR]->destroy(pf, fltr->filter, fltr);
	if (!ret) {
		pf_logd(LOG_ARFS,
			"arfs: fdir del fltr_id=%u flow_id=%u profile=%u queue=%u q_index=%d\n",
			fltr->fltr_id, e->flow_id, e->profile_id,
			fltr->action.fwd.q.queue, fltr->q_index);
		fltr->filter = NULL;
		e->hw_rule = false;
	} else {
		pf_logd(LOG_ARFS,
			"arfs: fdir del failed err=%d fltr_id=%u flow_id=%u queue=%u q_index=%d\n",
			ret, fltr->fltr_id, e->flow_id,
			fltr->action.fwd.q.queue, fltr->q_index);
	}

	return ret;
}

static int mce_arfs_fdir_add_fltr(struct mce_pf *pf, struct mce_arfs_entry *e)
{
	struct mce_tc_flower_fltr *fltr_info = &e->fltr_info;
	struct mce_field_bitmask_info *mask_info = NULL;
	struct mce_lkup_meta *meta = e->meta;
	struct mce_fdir_handle *handle;
	struct mce_fdir_filter *filter;
	int field_bitmask_num = 0;
	int meta_num = 0;
	bool had_hw_rule;
	int ret;
	int i;

	if (!mce_arfs_is_supported(pf))
		return -EOPNOTSUPP;

	if (!pf->flow_engine[MCE_FLOW_FDIR])
		return -EINVAL;

	had_hw_rule = e->hw_rule;
	if (had_hw_rule) {
		ret = mce_arfs_fdir_del_fltr(pf, e);
		if (ret)
			return ret;
	}

	ret = mce_arfs_alloc_filter(pf, e, GFP_KERNEL);
	if (ret)
		return ret;

	for (i = 0; i < MCE_META_TYPE_MAX; i++) {
		if (meta[i].type == MCE_META_TYPE_MAX)
			break;
		meta_num++;
		field_bitmask_num += mce_check_field_bitmask_valid(&meta[i]);
	}

	if (field_bitmask_num) {
		int block_size;

		mask_info = kzalloc(sizeof(*mask_info), GFP_KERNEL);
		if (!mask_info)
			return -ENOMEM;
		block_size = sizeof(struct mce_field_bitmask_block) *
			     field_bitmask_num;
		mask_info->field_bitmask = kzalloc(block_size, GFP_KERNEL);
		if (!mask_info->field_bitmask) {
			kfree(mask_info);
			return -ENOMEM;
		}
		meta = e->meta;
		mce_fdir_field_mask_init(meta, meta_num, mask_info);
	}

	filter = fltr_info->filter;
	filter->mask_info = mask_info;
	handle = (struct mce_fdir_handle *)mce_get_engine_handle(pf,
							  MCE_FLOW_FDIR);
	if (mce_fdir_profile_mask_conflict(handle, filter)) {
		pf_logd(LOG_ARFS,
			"arfs: skip profile=%u due to different FDIR input set\n",
			e->profile_id);
		e->hw_rule = false;
		return -EOPNOTSUPP;
	}

	ret = pf->flow_engine[MCE_FLOW_FDIR]->create(pf, filter, fltr_info);
	if (ret) {
		pf_logd(LOG_ARFS,
			"arfs: fdir add failed err=%d fltr_id=%u flow_id=%u profile=%u queue=%u q_index=%d\n",
			ret, fltr_info->fltr_id, e->flow_id, e->profile_id,
			fltr_info->action.fwd.q.queue, fltr_info->q_index);
		fltr_info->filter = NULL;
		e->hw_rule = false;
		return ret;
	}

	e->hw_rule = true;
	pf_logd(LOG_ARFS,
		"arfs: fdir %s fltr_id=%u flow_id=%u profile=%u queue=%u q_index=%d cpu=%u\n",
		had_hw_rule ? "update" : "add", fltr_info->fltr_id,
		e->flow_id, e->profile_id, fltr_info->action.fwd.q.queue,
		fltr_info->q_index, raw_smp_processor_id());
	return had_hw_rule ? 1 : 0;
}

static void mce_arfs_update_active_fltr_cntrs(struct mce_vsi *vsi,
					      struct mce_arfs_entry *entry,
					      bool add)
{
	struct mce_arfs_active_fltr_cntrs *cntrs;
	int val = add ? 1 : -1;

	if (!vsi || !entry || !vsi->arfs_fltr_cntrs)
		return;

	cntrs = vsi->arfs_fltr_cntrs;
	switch (entry->profile_id) {
	case MCE_PTYPE_IPV4_TCP:
		atomic_add(val, &cntrs->active_tcpv4_cnt);
		break;
	case MCE_PTYPE_IPV6_TCP:
		atomic_add(val, &cntrs->active_tcpv6_cnt);
		break;
	case MCE_PTYPE_IPV4_UDP:
		atomic_add(val, &cntrs->active_udpv4_cnt);
		break;
	case MCE_PTYPE_IPV6_UDP:
		atomic_add(val, &cntrs->active_udpv6_cnt);
		break;
	}
}

/**
 * mce_arfs_del_flow_rules - delete the rules passed in from HW
 * @vsi: VSI for the flow rules that need to be deleted
 * @del_list_head: head of the list of mce_arfs_entry(s) for rule deletion
 *
 * Loop through the delete list passed in and remove the rules from HW. After
 * each rule is deleted, disconnect and free the mce_arfs_entry because it is no
 * longer being referenced by the aRFS hash table.
 */
static void mce_arfs_del_flow_rules(struct mce_vsi *vsi,
				    struct hlist_head *del_list_head)
{
	struct mce_arfs_entry *e;
	struct hlist_node *n;
	struct mce_pf *pf;

	pf = vsi->back;

	hlist_for_each_entry_safe(e, n, del_list_head, list_entry) {
		bool had_hw_rule = e->hw_rule;
		int result;

		result = mce_arfs_fdir_del_fltr(pf, e);
		if (!result && had_hw_rule)
			mce_arfs_update_active_fltr_cntrs(vsi, e, false);
		else if (result)
			pf_logd(LOG_ARFS,
				"Unable to delete aRFS entry, err %d fltr_state %d fltr_id %d flow_id %d Q %d\n",
				result, e->fltr_state, e->fltr_info.fltr_id,
				e->flow_id, e->fltr_info.q_index);

		hlist_del_init(&e->list_entry);
		if (result && e->hw_rule) {
			/* Keep ownership and retry later. The entry was removed from
			 * the normal bucket while the hardware delete ran unlocked.
			 */
			e->fltr_state = MCE_ARFS_ACTIVE;
			spin_lock_bh(&vsi->arfs_lock);
			hlist_add_head(&e->list_entry,
				       &vsi->arfs_fltr_list[e->hash_idx]);
			spin_unlock_bh(&vsi->arfs_lock);
			continue;
		}

		mce_arfs_free_filter(e->fltr_info.filter);
		devm_kfree(mce_pf_to_dev(pf), e);
	}
}

/**
 * mce_arfs_add_flow_rules - add the rules passed in from HW
 * @vsi: VSI for the flow rules that need to be added
 * @add_list_head: head of the list of mce_arfs_entry_ptr(s) for rule addition
 *
 * Loop through the add list passed in and remove the rules from HW. After each
 * rule is added, disconnect and free the mce_arfs_entry_ptr node. Don't free
 * the mce_arfs_entry(s) because they are still being referenced in the aRFS
 * hash table.
 */
static void mce_arfs_add_flow_rules(struct mce_vsi *vsi,
				    struct hlist_head *add_list_head)
{
	struct mce_arfs_entry_ptr *ep;
	struct hlist_node *n;
	struct mce_pf *pf;

	pf = vsi->back;

	hlist_for_each_entry_safe(ep, n, add_list_head, list_entry) {
		bool had_hw_rule = ep->arfs_entry->hw_rule;
		int result;

		result = mce_arfs_fdir_add_fltr(pf, ep->arfs_entry);
		if (!result) {
			mce_arfs_update_active_fltr_cntrs(vsi, ep->arfs_entry,
							  true);
			ep->arfs_entry->fltr_state = MCE_ARFS_ACTIVE;
		} else if (result > 0) {
			ep->arfs_entry->fltr_state = MCE_ARFS_ACTIVE;
		} else {
			if (had_hw_rule && !ep->arfs_entry->hw_rule)
				mce_arfs_update_active_fltr_cntrs(vsi,
								  ep->arfs_entry,
								  false);
			pf_logd(LOG_ARFS,
				"Unable to add aRFS entry, err %d fltr_state %d fltr_id %d flow_id %d Q %d\n",
				result, ep->arfs_entry->fltr_state,
				ep->arfs_entry->fltr_info.fltr_id,
				ep->arfs_entry->flow_id,
				ep->arfs_entry->fltr_info.q_index);
			if (!ep->arfs_entry->hw_rule) {
				hlist_del(&ep->arfs_entry->list_entry);
				mce_arfs_free_filter(ep->arfs_entry->fltr_info.filter);
				devm_kfree(mce_pf_to_dev(pf), ep->arfs_entry);
			}
		}

		hlist_del(&ep->list_entry);
		devm_kfree(mce_pf_to_dev(pf), ep);
	}
}

static __be32 mce_arfs_ipv4_meta_to_addr(u32 addr)
{
	return cpu_to_be32(addr);
}

static __be16 mce_arfs_l4_meta_to_port(u16 port)
{
	return cpu_to_be16(port);
}

#if IS_ENABLED(CONFIG_IPV6)
static void mce_arfs_ipv6_meta_to_addr(struct in6_addr *addr, u32 meta_addr[4])
{
	__be32 *ip_hdr = (__be32 *)addr;
	int i;

	for (i = 0; i < 4; i++)
		ip_hdr[3 - i] = cpu_to_be32(meta_addr[i]);
}
#endif

static bool mce_arfs_tcp_socket_exists(struct mce_vsi *vsi,
				       struct mce_arfs_entry *entry)
{
	struct mce_lkup_meta *tcp_meta;
	struct sock *sk = NULL;
	__be16 sport;
	__be16 dport;

	tcp_meta = mce_arfs_find_meta(entry, MCE_TCP_META);
	if (!tcp_meta)
		return true;

	sport = mce_arfs_l4_meta_to_port(tcp_meta->hdr.tcp_meta.src_port);
	dport = mce_arfs_l4_meta_to_port(tcp_meta->hdr.tcp_meta.dst_port);

	rcu_read_lock();
	if (entry->profile_id == MCE_PTYPE_IPV4_TCP) {
		struct mce_lkup_meta *ip_meta;
		__be32 saddr;
		__be32 daddr;

		ip_meta = mce_arfs_find_meta(entry, MCE_IPV4_META);
		if (!ip_meta)
			goto out;

		saddr = mce_arfs_ipv4_meta_to_addr(ip_meta->hdr.ipv4_meta.src_addr);
		daddr = mce_arfs_ipv4_meta_to_addr(ip_meta->hdr.ipv4_meta.dst_addr);
		sk = inet_lookup_established(dev_net(vsi->netdev), &tcp_hashinfo,
					     saddr, sport, daddr, dport,
					     vsi->netdev->ifindex);
	} else if (entry->profile_id == MCE_PTYPE_IPV6_TCP) {
#if IS_ENABLED(CONFIG_IPV6)
		struct mce_lkup_meta *ip_meta;
		struct in6_addr saddr;
		struct in6_addr daddr;

		ip_meta = mce_arfs_find_meta(entry, MCE_IPV6_META);
		if (!ip_meta)
			goto out;

		mce_arfs_ipv6_meta_to_addr(&saddr, ip_meta->hdr.ipv6_meta.src_addr);
		mce_arfs_ipv6_meta_to_addr(&daddr, ip_meta->hdr.ipv6_meta.dst_addr);
		sk = __inet6_lookup_established(dev_net(vsi->netdev), &tcp_hashinfo,
						&saddr, sport, &daddr, ntohs(dport),
						vsi->netdev->ifindex, 0);
#endif
	}

out:
	if (sk)
		sock_gen_put(sk);
	rcu_read_unlock();

	return !!sk;
}

/**
 * mce_arfs_is_flow_expired - check if the aRFS entry has expired
 * @vsi: VSI containing the aRFS entry
 * @arfs_entry: aRFS entry that's being checked for expiration
 *
 * Return true if the flow has expired, else false. This function should be used
 * to determine whether or not an aRFS entry should be removed from the hardware
 * and software structures.
 */
static bool mce_arfs_is_flow_expired(struct mce_vsi *vsi,
				     struct mce_arfs_entry *arfs_entry)
{
	u16 prof_id = arfs_entry->profile_id;
	struct mce_pf *pf = vsi->back;
	u64 now;

	if (rps_may_expire_flow(vsi->netdev, arfs_entry->fltr_info.q_index,
				arfs_entry->flow_id,
				arfs_entry->fltr_info.fltr_id))
		return true;

	if ((prof_id == MCE_PTYPE_IPV4_TCP || prof_id == MCE_PTYPE_IPV6_TCP) &&
	    !mce_arfs_tcp_socket_exists(vsi, arfs_entry)) {
		pf_logd(LOG_ARFS,
			"arfs: tcp socket gone expire fltr_id=%u flow_id=%u profile=%u q_index=%u\n",
			arfs_entry->fltr_info.fltr_id, arfs_entry->flow_id,
			prof_id, arfs_entry->fltr_info.q_index);
		return true;
	}

	/* expiration timer only used for UDP filters */
	if (prof_id != MCE_PTYPE_IPV6_UDP && prof_id != MCE_PTYPE_IPV4_UDP)
		return false;

	now = get_jiffies_64();
	if (time_after64(now,
			 arfs_entry->time_activated + MCE_ARFS_UDP_IDLE_TIMEOUT)) {
		pf_logd(LOG_ARFS,
			"arfs: idle expire fltr_id=%u flow_id=%u profile=%u q_index=%u age_ms=%u\n",
			arfs_entry->fltr_info.fltr_id, arfs_entry->flow_id,
			prof_id, arfs_entry->fltr_info.q_index,
			jiffies_to_msecs(now - arfs_entry->time_activated));
		return true;
	}

	return false;
}

/**
 * mce_arfs_update_flow_rules - add/delete aRFS rules in HW
 * @vsi: the VSI to be forwarded to
 * @idx: index into the table of aRFS filter lists. Obtained from skb->hash
 * @add_list: list to populate with filters to be added to Flow Director
 * @del_list: list to populate with filters to be deleted from Flow Director
 *
 * Iterate over the hlist at the index given in the aRFS hash table and
 * determine if there are any aRFS entries that need to be either added or
 * deleted in the HW. If the aRFS entry is marked as MCE_ARFS_INACTIVE the
 * filter needs to be added to HW, else if it's marked as MCE_ARFS_ACTIVE and
 * the flow has expired delete the filter from HW. The caller of this function
 * is expected to add/delete rules on the add_list/del_list respectively.
 */
static void mce_arfs_update_flow_rules(struct mce_vsi *vsi, u16 idx,
				       struct hlist_head *add_list,
				       struct hlist_head *del_list)
{
	struct mce_arfs_entry *e;
	struct hlist_node *n;
	struct device *dev;

	dev = mce_pf_to_dev(vsi->back);

	/* go through the aRFS hlist at this idx and check for needed updates */
	hlist_for_each_entry_safe(e, n, &vsi->arfs_fltr_list[idx], list_entry)
		/* check if filter needs to be added to HW */
		if (e->fltr_state == MCE_ARFS_INACTIVE) {
			struct mce_arfs_entry_ptr *ep =
				devm_kzalloc(dev, sizeof(*ep), GFP_ATOMIC);
			u16 prof_id = e->profile_id;

			if (!ep)
				continue;
			INIT_HLIST_NODE(&ep->list_entry);
			/* reference aRFS entry to add HW filter */
			ep->arfs_entry = e;
			hlist_add_head(&ep->list_entry, add_list);
			/* expiration timer only used for UDP flows */
			if (prof_id == MCE_PTYPE_IPV6_UDP ||
			    prof_id == MCE_PTYPE_IPV4_UDP)
				e->time_activated = get_jiffies_64();
		} else if (e->fltr_state == MCE_ARFS_ACTIVE) {
			/* check if filter needs to be removed from HW */
			if (mce_arfs_is_flow_expired(vsi, e)) {
				/* remove aRFS entry from hash table for delete
				 * and to prevent referencing it the next time
				 * through this hlist index
				 */
				hlist_del(&e->list_entry);
				e->fltr_state = MCE_ARFS_TODEL;
				/* save reference to aRFS entry for delete */
				hlist_add_head(&e->list_entry, del_list);
			}
		}
}

void mce_sync_arfs_fltrs(struct mce_pf *pf)
{
	HLIST_HEAD(tmp_del_list);
	HLIST_HEAD(tmp_add_list);
	struct mce_vsi *pf_vsi;
	unsigned int i;

	pf_vsi = mce_get_main_vsi(pf);
	if (!pf_vsi)
		return;

	if (!mce_arfs_is_supported(pf))
		return;

	if (!mce_is_arfs_active(pf_vsi))
		return;

	if (!pf->flow_engine[MCE_FLOW_FDIR])
		return;

	spin_lock_bh(&pf_vsi->arfs_lock);
	/* Once we process aRFS for the PF VSI get out */
	for (i = 0; i < MCE_MAX_ARFS_LIST; i++)
		mce_arfs_update_flow_rules(pf_vsi, i, &tmp_add_list,
					   &tmp_del_list);
	spin_unlock_bh(&pf_vsi->arfs_lock);

	/* use list of mce_arfs_entry(s) for delete */
	mce_arfs_del_flow_rules(pf_vsi, &tmp_del_list);

	/* use list of mce_arfs_entry_ptr(s) for add */
	mce_arfs_add_flow_rules(pf_vsi, &tmp_add_list);
}

/**
 * mce_arfs_find_meta - find a metadata item in an ARFS entry
 * @entry: ARFS entry to search
 * @type: metadata type to find
 */
static struct mce_lkup_meta *
mce_arfs_find_meta(struct mce_arfs_entry *entry, enum flow_meta_type type)
{
	int i;

	for (i = 0; i < MCE_META_TYPE_MAX; i++) {
		if (entry->meta[i].type == MCE_META_TYPE_MAX)
			break;
		if (entry->meta[i].type == type)
			return &entry->meta[i];
	}

	return NULL;
}

static void mce_arfs_ipv6_addr_to_meta(u32 meta_addr[4],
				       const struct in6_addr *addr)
{
	const __be32 *ip_hdr = (const __be32 *)addr;
	int i;

	for (i = 0; i < 4; i++)
		meta_addr[i] = be32_to_cpu(ip_hdr[3 - i]);
}

/**
 * mce_arfs_cmp - compare flow to a saved ARFS entry's filter info
 * @entry: saved ARFS entry
 * @fk: flow dissector keys
 */
static bool mce_arfs_cmp(struct mce_arfs_entry *entry,
			 const struct flow_keys *fk)
{
	__be16 n_proto = fk->basic.n_proto;
	u8 ip_proto = fk->basic.ip_proto;
	struct mce_lkup_meta *ip_meta;
	struct mce_lkup_meta *l4_meta;
	u32 src_addr[4];
	u32 dst_addr[4];

	if (!entry)
		return false;

	if (n_proto == htons(ETH_P_IP)) {
		ip_meta = mce_arfs_find_meta(entry, MCE_IPV4_META);
		if (!ip_meta)
			return false;
		if (ip_meta->hdr.ipv4_meta.src_addr !=
		    be32_to_cpu(fk->addrs.v4addrs.src) ||
		    ip_meta->hdr.ipv4_meta.dst_addr !=
		    be32_to_cpu(fk->addrs.v4addrs.dst))
			return false;
		if (ip_meta->hdr.ipv4_meta.protocol != ip_proto)
			return false;
	} else if (n_proto == htons(ETH_P_IPV6)) {
		ip_meta = mce_arfs_find_meta(entry, MCE_IPV6_META);
		if (!ip_meta)
			return false;
		mce_arfs_ipv6_addr_to_meta(src_addr, &fk->addrs.v6addrs.src);
		mce_arfs_ipv6_addr_to_meta(dst_addr, &fk->addrs.v6addrs.dst);
		if (memcmp(ip_meta->hdr.ipv6_meta.src_addr,
			   src_addr, sizeof(src_addr)) ||
		    memcmp(ip_meta->hdr.ipv6_meta.dst_addr,
			   dst_addr, sizeof(dst_addr)))
			return false;
		if (ip_meta->hdr.ipv6_meta.protocol != ip_proto)
			return false;
	} else {
		return false;
	}

	if (ip_proto == IPPROTO_TCP) {
		l4_meta = mce_arfs_find_meta(entry, MCE_TCP_META);
		if (!l4_meta)
			return false;
		if (l4_meta->hdr.tcp_meta.dst_port != be16_to_cpu(fk->ports.dst) ||
		    l4_meta->hdr.tcp_meta.src_port != be16_to_cpu(fk->ports.src))
			return false;
	} else if (ip_proto == IPPROTO_UDP) {
		l4_meta = mce_arfs_find_meta(entry, MCE_UDP_META);
		if (!l4_meta)
			return false;
		if (l4_meta->hdr.udp_meta.dst_port != be16_to_cpu(fk->ports.dst) ||
		    l4_meta->hdr.udp_meta.src_port != be16_to_cpu(fk->ports.src))
			return false;
	} else {
		return false;
	}

	return true;
}

/**
 * mce_arfs_build_entry - builds an aRFS entry based on input
 * @vsi: destination VSI for this flow
 * @fk: flow dissector keys for creating the tuple
 * @rxq_idx: Rx queue to steer this flow to
 * @flow_id: passed down from the stack and saved for flow expiration
 *
 * returns an aRFS entry on success and NULL on failure
 */
static struct mce_arfs_entry *mce_arfs_build_entry(struct mce_vsi *vsi,
						   const struct flow_keys *fk,
						   u16 rxq_idx, u32 flow_id)
{
	u8 compose[MCE_FLOW_ITEM_TYPE_MAX_NUM];
	struct mce_tc_flower_fltr *tc_fltr;
	struct mce_arfs_entry *arfs_entry;
	struct mce_fdir_filter *filter;
	struct mce_pf *pf = vsi->back;
	struct mce_lkup_meta *meta;
	u16 prof_id = 0;
	u64 inset = 0;
	u64 lk_lists;
	int ret;
	int i;

	arfs_entry = devm_kzalloc(mce_pf_to_dev(pf), sizeof(*arfs_entry),
				  GFP_ATOMIC | __GFP_NOWARN);
	if (!arfs_entry)
		return NULL;

	filter = kzalloc(sizeof(*filter), GFP_ATOMIC);
	if (!filter) {
		devm_kfree(mce_pf_to_dev(pf), arfs_entry);
		return NULL;
	}
	tc_fltr = &arfs_entry->fltr_info;
	tc_fltr->filter = filter;
	tc_fltr->q_index = rxq_idx;
	tc_fltr->action.fwd.q.queue = mce_arfs_fdir_queue(rxq_idx);
	tc_fltr->action.fltr_act = MCE_FWD_TO_Q;
	tc_fltr->f_module = MCE_FLOW_FDIR;
	tc_fltr->fdir_owner = MCE_FDIR_RULE_OWNER_ARFS;
	meta = arfs_entry->meta;

	pf_logd(LOG_ARFS, "arfs: build flow_id=%u target_queue=%u proto=%u\n",
		flow_id, rxq_idx, fk->basic.ip_proto);

	memset(meta, 0, sizeof(struct mce_lkup_meta) * MCE_META_TYPE_MAX);
	for (i = 0; i < MCE_META_TYPE_MAX; i++)
		meta[i].type = MCE_META_TYPE_MAX;
	memset(compose, 0, sizeof(compose));

	ret = -1;
	lk_lists = MCE_PARSE_ARFS_FLOW_ITERM_LOOKUP_LISTS;
	for (i = 0; i < MCE_FLOW_ITEM_TYPE_MAX_NUM; i++) {
		/* if ok, get next meta from database */
		if (!ret)
			meta++;

		switch (lk_lists & BIT_ULL(i)) {
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_ETH):
			ret = mce_parse_arfs_eth(meta, fk, &inset, compose);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV4):
			ret = mce_parse_arfs_ip4(meta, fk, &inset, compose);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV6):
			ret = mce_parse_arfs_ip6(meta, fk, &inset, compose);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_UDP):
			ret = mce_parse_arfs_udp(meta, fk, &inset, compose);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_TCP):
			ret = mce_parse_arfs_tcp(meta, fk, &inset, compose);
			break;
		default:
			ret = -1;
			break;
		}
	}

	filter->options = inset;
	if (!mce_fdir_find_prof_id(pf, compose, &prof_id, tc_fltr)) {
		dev_err(mce_pf_to_dev(pf), "arfs cannot find profile id\n");
		goto err_exit;
	}
	filter->profile_id = prof_id;
	arfs_entry->options = inset;
	arfs_entry->profile_id = prof_id;
	tc_fltr->tunnel_sw_type = MCE_SW_NON_TUN;
	if (mce_arfs_fill_lkup_pattern(pf, arfs_entry))
		goto err_exit;
	arfs_entry->flow_id = flow_id;
	tc_fltr->fltr_id =
		atomic_inc_return(vsi->arfs_last_fltr_id) % RPS_NO_FILTER;
	if (net_ratelimit())
		pf_logd(LOG_ARFS,
			"arfs: build fltr_id=%u flow_id=%u profile=%u target_queue=%u proto=%u src=%pI4:%u dst=%pI4:%u cpu=%u\n",
			tc_fltr->fltr_id, flow_id, prof_id, rxq_idx,
			fk->basic.ip_proto, &fk->addrs.v4addrs.src,
			ntohs(fk->ports.src), &fk->addrs.v4addrs.dst,
			ntohs(fk->ports.dst), raw_smp_processor_id());
	return arfs_entry;

err_exit:
	mce_arfs_free_filter(filter);
	devm_kfree(mce_pf_to_dev(pf), arfs_entry);
	return NULL;
}

int mce_rx_flow_steer(struct net_device *netdev, const struct sk_buff *skb,
		      u16 rxq_idx, u32 flow_id)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_arfs_entry *arfs_entry;
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct flow_keys fk;
	__be16 n_proto;
	u8 ip_proto;
	u16 idx;
	int ret;

	if (unlikely(!mce_arfs_is_supported(pf)))
		return -EOPNOTSUPP;

	if (unlikely(!vsi->arfs_fltr_list))
		return -ENODEV;

	if (unlikely(!pf->flow_engine[MCE_FLOW_FDIR]))
		return -ENODEV;

	if (skb->encapsulation)
		return -EPROTONOSUPPORT;

	if (!skb_flow_dissect_flow_keys(skb, &fk, 0))
		return -EPROTONOSUPPORT;

	n_proto = fk.basic.n_proto;
	/* Support only IPV4 and IPV6 */
	if ((n_proto == htons(ETH_P_IP) && !ip_is_fragment(ip_hdr(skb))) ||
	    n_proto == htons(ETH_P_IPV6))
		ip_proto = fk.basic.ip_proto;
	else
		return -EPROTONOSUPPORT;

	/* Support only TCP and UDP */
	if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP)
		return -EPROTONOSUPPORT;

	/* choose the aRFS list bucket based on skb hash */
	idx = skb_get_hash_raw(skb) & MCE_ARFS_LST_MASK;

	/* search for entry in the bucket */
	spin_lock_bh(&vsi->arfs_lock);
	hlist_for_each_entry(arfs_entry, &vsi->arfs_fltr_list[idx],
			     list_entry) {
		struct mce_tc_flower_fltr *fltr_info = &arfs_entry->fltr_info;

		/* keep searching for the already existing arfs_entry flow */
		if (!mce_arfs_cmp(arfs_entry, &fk))
			continue;

		ret = fltr_info->fltr_id;

		if (fltr_info->q_index == rxq_idx ||
		    arfs_entry->fltr_state != MCE_ARFS_ACTIVE)
			goto out;
		/* update the queue to forward to on an already existing flow */
		if (net_ratelimit())
			pf_logd(LOG_ARFS,
				"arfs: retarget fltr_id=%u flow_id=%u old_queue=%d new_queue=%u fdir_queue=%u cpu=%u\n",
				fltr_info->fltr_id, arfs_entry->flow_id,
				fltr_info->q_index, rxq_idx,
				mce_arfs_fdir_queue(rxq_idx),
				raw_smp_processor_id());
		fltr_info->q_index = rxq_idx;
		fltr_info->action.fwd.q.queue = mce_arfs_fdir_queue(rxq_idx);
		arfs_entry->fltr_state = MCE_ARFS_INACTIVE;
		goto out_schedule_service_task;
	}

	arfs_entry = mce_arfs_build_entry(vsi, &fk, rxq_idx, flow_id);
	if (!arfs_entry) {
		ret = -ENOMEM;
		goto out;
	}

	ret = arfs_entry->fltr_info.fltr_id;
	arfs_entry->hash_idx = idx;
	INIT_HLIST_NODE(&arfs_entry->list_entry);
	hlist_add_head(&arfs_entry->list_entry, &vsi->arfs_fltr_list[idx]);
	if (net_ratelimit())
		pf_logd(LOG_ARFS,
			"arfs: request fltr_id=%u flow_id=%u hash_bucket=%u target_queue=%u cpu=%u\n",
			arfs_entry->fltr_info.fltr_id, flow_id, idx, rxq_idx,
			raw_smp_processor_id());
out_schedule_service_task:
	mce_service_task_schedule(pf);
out:
	spin_unlock_bh(&vsi->arfs_lock);
	return ret;
}

/**
 * mce_init_arfs_cntrs - initialize aRFS counter values
 * @vsi: VSI that aRFS counters need to be initialized on
 */
static int mce_init_arfs_cntrs(struct mce_vsi *vsi)
{
	if (!vsi || vsi->type != MCE_VSI_PF)
		return -EINVAL;

	vsi->arfs_fltr_cntrs =
		kzalloc(sizeof(*vsi->arfs_fltr_cntrs), GFP_KERNEL);
	if (!vsi->arfs_fltr_cntrs)
		return -ENOMEM;

	vsi->arfs_last_fltr_id =
		kzalloc(sizeof(*vsi->arfs_last_fltr_id), GFP_KERNEL);
	if (!vsi->arfs_last_fltr_id) {
		kfree(vsi->arfs_fltr_cntrs);
		vsi->arfs_fltr_cntrs = NULL;
		return -ENOMEM;
	}

	return 0;
}

/**
 * mce_init_arfs - initialize aRFS resources
 * @vsi: the VSI to be forwarded to
 */
void mce_init_arfs(struct mce_vsi *vsi)
{
	struct hlist_head *arfs_fltr_list;
	struct mce_pf *pf;
	unsigned int i;

	if (!vsi || vsi->type != MCE_VSI_PF || vsi->arfs_fltr_list)
		return;

	pf = vsi->back;
	if (!mce_arfs_enable) {
		pf_logd(LOG_ARFS,
			"arfs: disabled by module parameter arfs=0\n");
		return;
	}

	if (!mce_arfs_is_fdir_mode_supported(pf)) {
		pf_logd(LOG_ARFS,
			"arfs: disabled for fdir_mode=%d mac/vlan only mode\n",
			pf ? pf->fdir_mode : -1);
		return;
	}

	arfs_fltr_list =
		kcalloc(MCE_MAX_ARFS_LIST, sizeof(*arfs_fltr_list), GFP_KERNEL);
	if (!arfs_fltr_list)
		return;

	if (mce_init_arfs_cntrs(vsi))
		goto free_arfs_fltr_list;

	for (i = 0; i < MCE_MAX_ARFS_LIST; i++)
		INIT_HLIST_HEAD(&arfs_fltr_list[i]);

	spin_lock_init(&vsi->arfs_lock);

	vsi->arfs_fltr_list = arfs_fltr_list;

	return;

free_arfs_fltr_list:
	kfree(arfs_fltr_list);
}

/**
 * mce_clear_arfs - clear the aRFS hash table and any memory used for aRFS
 * @vsi: the VSI to be forwarded to
 */
int mce_clear_arfs(struct mce_vsi *vsi)
{
	struct device *dev;
	struct mce_pf *pf;
	unsigned int i;
	int err = 0;

	if (!vsi || vsi->type != MCE_VSI_PF || !vsi->back ||
	    !vsi->arfs_fltr_list)
		return 0;

	pf = vsi->back;
	dev = mce_pf_to_dev(pf);
	for (i = 0; i < MCE_MAX_ARFS_LIST; i++) {
		HLIST_HEAD(tmp_del_list);
		struct mce_arfs_entry *r;
		struct hlist_node *n;

		spin_lock_bh(&vsi->arfs_lock);
		hlist_for_each_entry_safe(r, n, &vsi->arfs_fltr_list[i],
					  list_entry) {
			hlist_del(&r->list_entry);
			hlist_add_head(&r->list_entry, &tmp_del_list);
		}
		spin_unlock_bh(&vsi->arfs_lock);

		hlist_for_each_entry_safe(r, n, &tmp_del_list, list_entry) {
			bool had_hw_rule = r->hw_rule;
			int ret = 0;

			if (r->hw_rule)
				ret = mce_arfs_fdir_del_fltr(pf, r);
			if (ret) {
				pf_logd(LOG_ARFS,
					"Unable to clear aRFS entry fltr_id %d flow_id %d Q %d\n",
					r->fltr_info.fltr_id, r->flow_id,
					r->fltr_info.q_index);
				if (!err)
					err = ret;
				r->fltr_state = MCE_ARFS_ACTIVE;
				hlist_del_init(&r->list_entry);
				spin_lock_bh(&vsi->arfs_lock);
				hlist_add_head(&r->list_entry,
					       &vsi->arfs_fltr_list[i]);
				spin_unlock_bh(&vsi->arfs_lock);
				continue;
			}

			if (had_hw_rule)
				mce_arfs_update_active_fltr_cntrs(vsi, r, false);
			hlist_del_init(&r->list_entry);
			mce_arfs_free_filter(r->fltr_info.filter);
			devm_kfree(dev, r);
		}
	}

	if (err)
		return err;

	kfree(vsi->arfs_fltr_list);
	vsi->arfs_fltr_list = NULL;
	kfree(vsi->arfs_last_fltr_id);
	vsi->arfs_last_fltr_id = NULL;
	kfree(vsi->arfs_fltr_cntrs);
	vsi->arfs_fltr_cntrs = NULL;
	return 0;
}

/**
 * mce_reset_clear_arfs - force-clear aRFS software state before hardware reset
 * @vsi: PF VSI owning the aRFS table
 *
 * Hardware is reset immediately after this helper returns, so an individual
 * hardware delete failure must not leave stale aRFS software state behind.
 */
void mce_reset_clear_arfs(struct mce_vsi *vsi)
{
	struct device *dev;
	struct mce_pf *pf;
	unsigned int i;

	if (!vsi || vsi->type != MCE_VSI_PF || !vsi->back ||
	    !vsi->arfs_fltr_list)
		return;

	pf = vsi->back;
	dev = mce_pf_to_dev(pf);
	for (i = 0; i < MCE_MAX_ARFS_LIST; i++) {
		HLIST_HEAD(tmp_del_list);
		struct mce_arfs_entry *r;
		struct hlist_node *n;

		spin_lock_bh(&vsi->arfs_lock);
		hlist_for_each_entry_safe(r, n, &vsi->arfs_fltr_list[i],
					  list_entry) {
			hlist_del(&r->list_entry);
			hlist_add_head(&r->list_entry, &tmp_del_list);
		}
		spin_unlock_bh(&vsi->arfs_lock);

		hlist_for_each_entry_safe(r, n, &tmp_del_list, list_entry) {
			bool had_hw_rule = r->hw_rule;
			int ret = 0;

			if (r->hw_rule && r->fltr_info.filter)
				ret = mce_fdir_flow_force_delete(pf,
								 r->fltr_info.filter,
								 &r->fltr_info);
			if (!r->hw_rule || ret)
				mce_arfs_free_filter(r->fltr_info.filter);
			if (had_hw_rule)
				mce_arfs_update_active_fltr_cntrs(vsi, r, false);

			r->fltr_info.filter = NULL;
			r->hw_rule = false;
			hlist_del_init(&r->list_entry);
			devm_kfree(dev, r);
		}
	}

	kfree(vsi->arfs_fltr_list);
	vsi->arfs_fltr_list = NULL;
	kfree(vsi->arfs_last_fltr_id);
	vsi->arfs_last_fltr_id = NULL;
	kfree(vsi->arfs_fltr_cntrs);
	vsi->arfs_fltr_cntrs = NULL;
}

/**
 * mce_free_cpu_rx_rmap - free setup CPU reverse map
 * @vsi: the VSI to be forwarded to
 */
void mce_free_cpu_rx_rmap(struct mce_vsi *vsi)
{
	struct net_device *netdev;

	if (!vsi || vsi->type != MCE_VSI_PF)
		return;

	netdev = vsi->netdev;
	if (!netdev || !netdev->rx_cpu_rmap)
		return;

	free_irq_cpu_rmap(netdev->rx_cpu_rmap);
	netdev->rx_cpu_rmap = NULL;
}

/**
 * mce_set_cpu_rx_rmap - setup CPU reverse map for each queue
 * @vsi: the VSI to be forwarded to
 */
int mce_set_cpu_rx_rmap(struct mce_vsi *vsi)
{
	struct net_device *netdev;
	struct mce_pf *pf;
	int i;

	if (!vsi || vsi->type != MCE_VSI_PF)
		return 0;

	netdev = vsi->netdev;
	if (!vsi->back || !netdev || !vsi->num_q_vectors)
		return -EINVAL;
	pf = vsi->back;
	if (!mce_arfs_is_supported(pf))
		return 0;

	pf_logd(LOG_ARFS,
		"Setup CPU RMAP: vsi type 0x%x, ifname %s, q_vectors %d\n",
		vsi->type, netdev->name, vsi->num_q_vectors);

	netdev->rx_cpu_rmap = alloc_irq_cpu_rmap(vsi->num_q_vectors);
	if (unlikely(!netdev->rx_cpu_rmap))
		return -EINVAL;

	mce_for_each_q_vector(vsi, i) {
		int irq_num;

		if (!vsi->q_vectors[i] ||
		    !(vsi->q_vectors[i]->num_ring_tx ||
		      vsi->q_vectors[i]->num_ring_rx))
			continue;

		irq_num = mce_get_irq_num(pf, vsi->base_vector + i);
		if (irq_cpu_rmap_add(netdev->rx_cpu_rmap,
				     irq_num)) {
			mce_free_cpu_rx_rmap(vsi);
			return -EINVAL;
		}
		pf_logd(LOG_ARFS, "arfs: rmap q_vector=%d irq=%d\n", i,
			irq_num);
	}

	return 0;
}

/**
 * mce_remove_arfs - remove/clear all aRFS resources
 * @pf: device private structure
 */
void mce_remove_arfs(struct mce_pf *pf)
{
	struct mce_vsi *pf_vsi;
	struct device *dev;
	unsigned int i;

	pf_vsi = mce_get_main_vsi(pf);
	if (!pf_vsi)
		return;

	if (!mce_clear_arfs(pf_vsi))
		return;

	dev_warn(mce_pf_to_dev(pf),
		 "aRFS hardware cleanup failed; defer remaining filter cleanup to FDIR teardown\n");

	/* Device teardown follows with FDIR engine teardown. Any filter whose
	 * destroy failed is still owned by the FDIR engine, so only drop the
	 * aRFS wrapper here and let engine teardown release the filter/profile.
	 */
	dev = mce_pf_to_dev(pf);
	for (i = 0; i < MCE_MAX_ARFS_LIST; i++) {
		struct mce_arfs_entry *r;
		struct hlist_node *n;

		spin_lock_bh(&pf_vsi->arfs_lock);
		hlist_for_each_entry_safe(r, n, &pf_vsi->arfs_fltr_list[i],
					  list_entry) {
			hlist_del(&r->list_entry);
			if (!r->hw_rule)
				mce_arfs_free_filter(r->fltr_info.filter);
			devm_kfree(dev, r);
		}
		spin_unlock_bh(&pf_vsi->arfs_lock);
	}

	kfree(pf_vsi->arfs_fltr_list);
	pf_vsi->arfs_fltr_list = NULL;
	kfree(pf_vsi->arfs_last_fltr_id);
	pf_vsi->arfs_last_fltr_id = NULL;
	kfree(pf_vsi->arfs_fltr_cntrs);
	pf_vsi->arfs_fltr_cntrs = NULL;
}

/**
 * mce_rebuild_arfs - clear current aRFS rules and rebuild software state
 * @pf: device private structure
 *
 * Return: 0 on success or a negative error code if hardware cleanup failed.
 */
int mce_rebuild_arfs(struct mce_pf *pf)
{
	struct mce_vsi *pf_vsi;
	int err;

	pf_vsi = mce_get_main_vsi(pf);
	if (!pf_vsi)
		return 0;

	err = mce_clear_arfs(pf_vsi);
	if (err)
		return err;

	if (pf_vsi->netdev &&
	    (pf_vsi->netdev->features & NETIF_F_NTUPLE) &&
	    (pf_vsi->netdev->features & NETIF_F_HW_TC))
		mce_init_arfs(pf_vsi);
	return 0;
}

#endif /* CONFIG_RFS_ACCEL && CONFIG_NET_CLS_FLOWER */
