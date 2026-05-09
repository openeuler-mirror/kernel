// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_arfs.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/cpu_rmap.h>
#include <net/flow_dissector.h>

#include "sxe2_compat.h"
#include "sxe2_common.h"
#include "sxe2_log.h"
#include "sxe2_netdev.h"
#include "sxe2_arfs.h"
#include "sxe2_tx.h"

#ifdef NEED_INCLUDE_NET_RPS_H
#include <net/rps.h>
#endif
#ifdef NEED_INCLUDE_NETDEV_RX_QUEUE_H
#include <net/netdev_rx_queue.h>
#endif

#ifdef CONFIG_RFS_ACCEL
#define SXE2_ARFS_TIME_DELTA_EXPIRATION msecs_to_jiffies(5000)

static void sxe2_arfs_filter_print(struct sxe2_adapter *adapter,
				   struct sxe2_arfs_filter *arfs_filter)
{
	bool is_v4;
	__be16 *ipv6_src, *ipv6_dst;
	struct sxe2_fnav_filter *fltr_info;

	if (!arfs_filter)
		return;

	fltr_info = &arfs_filter->filter_info;
	LOG_ARFS("filter state %u\n", arfs_filter->filter_state);

	is_v4 = (fltr_info->flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_TCP ||
		 fltr_info->flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_UDP);

	if (is_v4) {
		LOG_ARFS("ipv4 src_ip 0x%X, dst_ip 0x%X, ip_proto %u, src_port %u,\t"
			 "dst_port %u\n",
			 fltr_info->full_key.ip.v4.src_ip,
			 fltr_info->full_key.ip.v4.dst_ip,
			 fltr_info->full_key.ip.v4.proto,
			 be16_to_cpu(fltr_info->full_key.l4.src_port),
			 be16_to_cpu(fltr_info->full_key.l4.dst_port));
	} else {
		ipv6_src = (__be16 *)fltr_info->full_key.ip.v6.src_ip;
		ipv6_dst = (__be16 *)fltr_info->full_key.ip.v6.dst_ip;
		LOG_ARFS("ipv6 src_ip %x:%x:%x:%x:%x:%x:%x:%x, dst_ip\t"
			 "%x:%x:%x:%x:%x:%x:%x:%x,ip_proto %u, src_port %u,\t"
			 "dst_port %u\n",
			 be16_to_cpu(ipv6_src[0]), be16_to_cpu(ipv6_src[1]),
			 be16_to_cpu(ipv6_src[2]), be16_to_cpu(ipv6_src[3]),
			 be16_to_cpu(ipv6_src[4]), be16_to_cpu(ipv6_src[5]),
			 be16_to_cpu(ipv6_src[6]), be16_to_cpu(ipv6_src[7]),
			 be16_to_cpu(ipv6_dst[0]), be16_to_cpu(ipv6_dst[1]),
			 be16_to_cpu(ipv6_dst[2]), be16_to_cpu(ipv6_dst[3]),
			 be16_to_cpu(ipv6_dst[4]), be16_to_cpu(ipv6_dst[5]),
			 be16_to_cpu(ipv6_dst[6]), be16_to_cpu(ipv6_dst[7]),
			 fltr_info->full_key.ip.v6.proto,
			 be16_to_cpu(fltr_info->full_key.l4.src_port),
			 be16_to_cpu(fltr_info->full_key.l4.dst_port));
	}
	LOG_ARFS("flow_id %u, q_inedx %u, loc %u\n", arfs_filter->flow_id,
		 fltr_info->q_index, arfs_filter->filter_idx);
}

STATIC void sxe2_arfs_filter_print_screen(struct sxe2_adapter *adapter,
					  struct sxe2_arfs_filter *arfs_filter)
{
	bool is_v4;
	__be16 *ipv6_src, *ipv6_dst;
	struct sxe2_fnav_filter *fltr_info;

	if (!arfs_filter)
		return;

	fltr_info = &arfs_filter->filter_info;
	LOG_DEV_INFO("\tfilter state %u\n", arfs_filter->filter_state);

	is_v4 = (fltr_info->flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_TCP ||
		 fltr_info->flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_UDP);

	if (is_v4) {
		LOG_DEV_INFO("ipv4 src_ip 0x%X, dst_ip 0x%X, ip_proto %u, src_port\t"
			     "%u, dst_port %u\n",
			     fltr_info->full_key.ip.v4.src_ip,
			     fltr_info->full_key.ip.v4.dst_ip,
			     fltr_info->full_key.ip.v4.proto,
			     be16_to_cpu(fltr_info->full_key.l4.src_port),
			     be16_to_cpu(fltr_info->full_key.l4.dst_port));
	} else {
		ipv6_src = (__be16 *)fltr_info->full_key.ip.v6.src_ip;
		ipv6_dst = (__be16 *)fltr_info->full_key.ip.v6.dst_ip;
		LOG_DEV_INFO("ipv6 src_ip %x:%x:%x:%x:%x:%x:%x:%x, dst_ip\t"
			     "%x:%x:%x:%x:%x:%x:%x:%x, ip_proto %u, src_port %u,\t"
			     "dst_port %u\n",
			     be16_to_cpu(ipv6_src[0]), be16_to_cpu(ipv6_src[1]),
			     be16_to_cpu(ipv6_src[2]), be16_to_cpu(ipv6_src[3]),
			     be16_to_cpu(ipv6_src[4]), be16_to_cpu(ipv6_src[5]),
			     be16_to_cpu(ipv6_src[6]), be16_to_cpu(ipv6_src[7]),
			     be16_to_cpu(ipv6_dst[0]), be16_to_cpu(ipv6_dst[1]),
			     be16_to_cpu(ipv6_dst[2]), be16_to_cpu(ipv6_dst[3]),
			     be16_to_cpu(ipv6_dst[4]), be16_to_cpu(ipv6_dst[5]),
			     be16_to_cpu(ipv6_dst[6]), be16_to_cpu(ipv6_dst[7]),
			     fltr_info->full_key.ip.v6.proto,
			     be16_to_cpu(fltr_info->full_key.l4.src_port),
			     be16_to_cpu(fltr_info->full_key.l4.dst_port));
	}
	LOG_DEV_INFO("flow_id %u, q_inedx %u, loc %u\n", arfs_filter->flow_id,
		     fltr_info->q_index, arfs_filter->filter_idx);
}

s32 sxe2_arfs_enable(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	u32 i;

	adapter->arfs_ctxt.filter_list = kcalloc(SXE2_MAX_ARFS_LIST,
						 sizeof(struct hlist_head),
						 GFP_KERNEL);
	if (!adapter->arfs_ctxt.filter_list)
		return -ENOMEM;

	for (i = 0; i < SXE2_MAX_ARFS_LIST; i++)
		INIT_HLIST_HEAD(&adapter->arfs_ctxt.filter_list[i]);

	adapter->arfs_ctxt.last_filter_id = 0;
	memset(&adapter->arfs_ctxt.filter_cnt, 0,
	       sizeof(struct sxe2_arfs_active_filter_cnt));

	return ret;
}

void sxe2_arfs_disable(struct sxe2_adapter *adapter)
{
	u32 i = 0;
	s32 ret;
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_arfs_filter *filter;
	struct hlist_node *node;
	HLIST_HEAD(del_list);

	mutex_lock(&adapter->arfs_ctxt.update_list_lock);
	spin_lock_bh(&adapter->arfs_ctxt.filter_lock);
	if (likely(adapter->arfs_ctxt.filter_list)) {
		for (i = 0; i < SXE2_MAX_ARFS_LIST; i++) {
			hlist_for_each_entry_safe(filter, node,
						  &adapter->arfs_ctxt.filter_list[i],
						  hl_node) {
				hlist_del(&filter->hl_node);
				hlist_add_head(&filter->hl_node, &del_list);
			}
		}
		kfree(adapter->arfs_ctxt.filter_list);
		adapter->arfs_ctxt.filter_list = NULL;
	}
	spin_unlock_bh(&adapter->arfs_ctxt.filter_lock);

	hlist_for_each_entry_safe(filter, node, &del_list, hl_node) {
		if (filter->filter_state != SXE2_ARFS_FILTER_INACTIVE &&
		    filter->filter_state != SXE2_ARFS_FILTER_CONFLICT) {
			ret = sxe2_pf_fnav_hw_filter_update(vsi,
							    &filter->filter_info,
							    false, false,
							    SXE2_FNAV_FILTER_UPDATE_PKT);
			if (ret) {
				LOG_DEV_WARN("unable to delete aRFS filter, ret:%d\t"
					     "filter_state:%d filter_loc:%d\t"
					     "flow_id:%d queue:%d\n",
					     ret, filter->filter_state,
					     filter->filter_idx, filter->flow_id,
					     filter->filter_info.q_index);
			}
		}
		hlist_del(&filter->hl_node);
		devm_kfree(dev, filter);
	}

	adapter->arfs_ctxt.last_filter_id = 0;
	memset(&adapter->arfs_ctxt.filter_cnt, 0,
	       sizeof(struct sxe2_arfs_active_filter_cnt));
	mutex_unlock(&adapter->arfs_ctxt.update_list_lock);
}

s32 sxe2_arfs_init(struct sxe2_adapter *adapter)
{
	s32 ret = 0;

	adapter->arfs_ctxt.vsi_id_in_pf = SXE2_INVAL_U16;
	mutex_init(&adapter->arfs_ctxt.update_list_lock);
	spin_lock_init(&adapter->arfs_ctxt.filter_lock);

	if (test_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags))
		ret = sxe2_arfs_enable(adapter);

	return ret;
}

void sxe2_arfs_deinit(struct sxe2_adapter *adapter)
{
	sxe2_arfs_disable(adapter);
	mutex_destroy(&adapter->arfs_ctxt.update_list_lock);
}

void sxe2_arfs_clean(struct sxe2_adapter *adapter)
{
	u32 i = 0;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_arfs_filter *filter;
	struct hlist_node *node;

	mutex_lock(&adapter->arfs_ctxt.update_list_lock);
	spin_lock_bh(&adapter->arfs_ctxt.filter_lock);
	if (likely(adapter->arfs_ctxt.filter_list)) {
		for (i = 0; i < SXE2_MAX_ARFS_LIST; i++) {
			hlist_for_each_entry_safe(filter, node,
						  &adapter->arfs_ctxt.filter_list[i],
						  hl_node) {
				hlist_del(&filter->hl_node);
				devm_kfree(dev, filter);
			}
		}
	}
	spin_unlock_bh(&adapter->arfs_ctxt.filter_lock);

	adapter->arfs_ctxt.last_filter_id = 0;
	memset(&adapter->arfs_ctxt.filter_cnt, 0,
	       sizeof(struct sxe2_arfs_active_filter_cnt));
	mutex_unlock(&adapter->arfs_ctxt.update_list_lock);
}

s32 sxe2_cpu_rx_rmap_set(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = NULL;
	struct net_device *netdev = NULL;
	u32 i;

	if (!vsi || vsi->type != SXE2_VSI_T_PF)
		return 0;

	netdev = vsi->netdev;
	if (!netdev || !vsi->irqs.cnt)
		return -EINVAL;

	adapter = vsi->adapter;
	LOG_NETDEV_DEBUG("setup CPU RMAP: vsi type 0x%x, ifname %s, q_vectors %d\n",
			 vsi->type, netdev->name, vsi->irqs.cnt);

	netdev->rx_cpu_rmap = alloc_irq_cpu_rmap(vsi->irqs.cnt);
	if (unlikely(!netdev->rx_cpu_rmap))
		return -EINVAL;

	sxe2_for_each_vsi_irq(vsi, i)
	{
		if (irq_cpu_rmap_add(netdev->rx_cpu_rmap,
				     adapter->irq_ctxt
						    .msix_entries[vsi->irqs.irq_data[i]
										  ->idx_in_pf]
						    .vector)) {
			sxe2_cpu_rx_rmap_free(vsi);
			return -EINVAL;
		}
	}

	return 0;
}

void sxe2_cpu_rx_rmap_free(struct sxe2_vsi *vsi)
{
	struct net_device *netdev = NULL;

	if (!vsi || vsi->type != SXE2_VSI_T_PF)
		return;

	netdev = vsi->netdev;
	if (!netdev || !netdev->rx_cpu_rmap)
		return;

	free_irq_cpu_rmap(netdev->rx_cpu_rmap);
	netdev->rx_cpu_rmap = NULL;
}

STATIC bool sxe2_arfs_filter_cmp(struct sxe2_fnav_filter *fltr_info,
				 const struct flow_keys *fk)
{
	bool is_v4;

	if (!fltr_info || !fk)
		return false;

	is_v4 = (fltr_info->flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_TCP ||
		 fltr_info->flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_UDP);

	if (fk->basic.n_proto == htons(ETH_P_IP) && is_v4) {
		return (fltr_info->full_key.ip.v4.proto == fk->basic.ip_proto &&
			fltr_info->full_key.ip.v4.src_ip == fk->addrs.v4addrs.src &&
			fltr_info->full_key.ip.v4.dst_ip == fk->addrs.v4addrs.dst &&
			fltr_info->full_key.l4.src_port == fk->ports.src &&
			fltr_info->full_key.l4.dst_port == fk->ports.dst);
	} else if (fk->basic.n_proto == htons(ETH_P_IPV6) && !is_v4) {
		return (fltr_info->full_key.ip.v6.proto == fk->basic.ip_proto &&
			!memcmp(&fltr_info->full_key.ip.v6.src_ip,
				&fk->addrs.v6addrs.src, sizeof(struct in6_addr)) &&
			!memcmp(&fltr_info->full_key.ip.v6.dst_ip,
				&fk->addrs.v6addrs.dst, sizeof(struct in6_addr)) &&
			fltr_info->full_key.l4.src_port == fk->ports.src &&
			fltr_info->full_key.l4.dst_port == fk->ports.dst);
	}

	return false;
}

STATIC void sxe2_arfs_active_filter_cnt_update(struct sxe2_adapter *adapter,
					       struct sxe2_arfs_filter *filter,
					       bool add)
{
	struct sxe2_arfs_active_filter_cnt *filter_cnt =
			&adapter->arfs_ctxt.filter_cnt;

	switch (filter->filter_info.flow_type) {
	case SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_TCP:
		if (add)
			filter_cnt->tcp4_cnt++;
		else
			filter_cnt->tcp4_cnt--;
		break;
	case SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_UDP:
		if (add)
			filter_cnt->udp4_cnt++;
		else
			filter_cnt->udp4_cnt--;
		break;
	case SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_TCP:
		if (add)
			filter_cnt->tcp6_cnt++;
		else
			filter_cnt->tcp6_cnt--;
		break;
	case SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_UDP:
		if (add)
			filter_cnt->udp6_cnt++;
		else
			filter_cnt->udp6_cnt--;
		break;
	default:
		LOG_ERROR_BDF("aRFS: failed to update filter counters, invalid\t"
			      "filter type %d\n",
			      filter->filter_info.flow_type);
		break;
	}
}

STATIC struct sxe2_arfs_filter *sxe2_arfs_filter_build(struct sxe2_adapter *adapter,
						       const struct flow_keys *fk,
						       u16 rxq_idx, u32 flow_id,
						       u32 hash)
{
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_arfs_filter *arfs_filter = NULL;
	struct sxe2_fnav_filter *fltr_info;
	u8 ip_proto;

	arfs_filter = devm_kzalloc(dev, sizeof(*arfs_filter),
				   GFP_ATOMIC | __GFP_NOWARN);
	if (!arfs_filter) {
		LOG_ARFS("alloc arfs_filter memory failed\n");
		return NULL;
	}

	arfs_filter->filter_idx =
			adapter->arfs_ctxt.last_filter_id++ % RPS_NO_FILTER;
	fltr_info = &arfs_filter->filter_info;
	ip_proto = fk->basic.ip_proto;
	if (fk->basic.n_proto == htons(ETH_P_IP)) {
		fltr_info->flow_type =
				(ip_proto == IPPROTO_TCP)
						? SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_TCP
						: SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_UDP;
		fltr_info->full_key.ip.v4.proto = ip_proto;
		fltr_info->full_key.ip.v4.src_ip = fk->addrs.v4addrs.src;
		fltr_info->full_key.ip.v4.dst_ip = fk->addrs.v4addrs.dst;
		fltr_info->full_key.l4.src_port = fk->ports.src;
		fltr_info->full_key.l4.dst_port = fk->ports.dst;
	} else {
		fltr_info->flow_type =
				(ip_proto == IPPROTO_TCP)
						? SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_TCP
						: SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_UDP;
		fltr_info->full_key.ip.v6.proto = ip_proto;
		memcpy(&fltr_info->full_key.ip.v6.src_ip, &fk->addrs.v6addrs.src,
		       sizeof(struct in6_addr));
		memcpy(&fltr_info->full_key.ip.v6.dst_ip, &fk->addrs.v6addrs.dst,
		       sizeof(struct in6_addr));
		fltr_info->full_key.l4.src_port = fk->ports.src;
		fltr_info->full_key.l4.dst_port = fk->ports.dst;
	}
	fltr_info->filter_loc = hash;
	fltr_info->fdid_prio = SXE2_FNAV_TX_DESC_QW1_FDID_PRIO_THREE;
	fltr_info->ori_vsi_sw = vsi->id_in_pf;
	fltr_info->ori_vsi_hw = vsi->idx_in_dev;
	fltr_info->dst_vsi_hw = vsi->idx_in_dev;
	fltr_info->act_type = SXE2_FNAV_ACT_QINDEX;
	fltr_info->origin_q_index = rxq_idx;
	fltr_info->q_index = rxq_idx;
	fltr_info->q_region = 0;
	fltr_info->act_prio = SXE2_FNAV_TX_DESC_QW0_TOQ_PRIO_THREE;
	fltr_info->complete_report = SXE2_FNAV_TX_DESC_QW0_COMP_RPT_FAIL;
	fltr_info->stat_ctrl = SXE2_FNAV_TX_DESC_QW0_STAT_ENA_PKTS;
	if (fltr_info->flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_TCP) {
		fltr_info->stat_index =
				adapter->fnav_ctxt.fnav_stat_ctxt
						.stat_rsv_idx[SXE2_ARFS_STAT_TCP4];
	} else if (fltr_info->flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_UDP) {
		fltr_info->stat_index =
				adapter->fnav_ctxt.fnav_stat_ctxt
						.stat_rsv_idx[SXE2_ARFS_STAT_UDP4];
	} else if (fltr_info->flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_TCP) {
		fltr_info->stat_index =
				adapter->fnav_ctxt.fnav_stat_ctxt
						.stat_rsv_idx[SXE2_ARFS_STAT_TCP6];
	} else if (fltr_info->flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_UDP) {
		fltr_info->stat_index =
				adapter->fnav_ctxt.fnav_stat_ctxt
						.stat_rsv_idx[SXE2_ARFS_STAT_UDP6];
	}
	fltr_info->tunn_flag = SXE2_FNAV_TUN_FLAG_NO_TUNNEL;

	arfs_filter->flow_id = flow_id;
	arfs_filter->filter_state = SXE2_ARFS_FILTER_INACTIVE;
	arfs_filter->time_activated = 0;
	INIT_HLIST_NODE(&arfs_filter->hl_node);
	LOG_ARFS("build new filter\n");
	sxe2_arfs_filter_print(adapter, arfs_filter);

	return arfs_filter;
}

STATIC bool sxe2_arfs_flow_cfg_full_match(struct sxe2_adapter *adapter,
					  __be16 l3_proto, u8 l4_proto)
{
	enum sxe2_fnav_flow_type flow_type = SXE2_FNAV_FLOW_TYPE_NONE;
	struct sxe2_fnav_flow_cfg *flow_cfg = NULL;

	if (l3_proto == htons(ETH_P_IP) && l4_proto == IPPROTO_TCP)
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV4_TCP;
	else if (l3_proto == htons(ETH_P_IP) && l4_proto == IPPROTO_UDP)
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV4_UDP;
	else if (l3_proto == htons(ETH_P_IPV6) && l4_proto == IPPROTO_TCP)
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV6_TCP;
	else if (l3_proto == htons(ETH_P_IPV6) && l4_proto == IPPROTO_UDP)
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV6_UDP;
	else
		return false;

	flow_cfg = sxe2_fnav_find_flow_cfg_by_flow_type(adapter->vsi_ctxt.main_vsi,
							flow_type);
	if (!flow_cfg || flow_cfg->filter_cnt[SXE2_FNAV_SEG_NON_TUN] == 0 ||
	    flow_cfg->full_match) {
		return true;
	}
	return false;
}

int sxe2_rx_flow_steer(struct net_device *netdev, const struct sk_buff *skb,
		       u16 rxq_idx, u32 flow_id)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi = priv->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct flow_keys fk;
	__be16 n_proto;
	u8 ip_proto;
	u16 idx;
	struct sxe2_arfs_filter *arfs_filter;
	u32 hash;
	int ret = -EOPNOTSUPP;

	if (unlikely(!adapter->arfs_ctxt.filter_list)) {
		LOG_ARFS("filter list is NULL.\n");
		return -ENODEV;
	}

	if (skb->encapsulation) {
		LOG_ARFS("skb is encapsulation.\n");
		return -EPROTONOSUPPORT;
	}

	if (!skb_flow_dissect_flow_keys(skb, &fk, 0)) {
		LOG_ARFS("unsupport flow key, l3_proto 0x%X, l4_proto 0x%X\n",
			 ntohs(skb->protocol),
			 skb->protocol == htons(ETH_P_IP)
					 ? ip_hdr(skb)->protocol
					 : skb->protocol == htons(ETH_P_IPV6)
							   ? ipv6_hdr(skb)->nexthdr
							   : 0);
		return -EPROTONOSUPPORT;
	}

	if (fk.control.flags & FLOW_DIS_IS_FRAGMENT) {
		LOG_ARFS("unsupport fragment\n");
		return -EPROTONOSUPPORT;
	}

	n_proto = fk.basic.n_proto;
	if (n_proto == htons(ETH_P_IP) || n_proto == htons(ETH_P_IPV6)) {
		ip_proto = fk.basic.ip_proto;
	} else {
		LOG_ARFS("unsupport l3_proto 0x%X\n", ntohs(n_proto));
		return -EPROTONOSUPPORT;
	}

	if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP) {
		LOG_ARFS("unsupport l4_proto 0x%X\n", ip_proto);
		return -EPROTONOSUPPORT;
	}

	if (!sxe2_arfs_flow_cfg_full_match(adapter, n_proto, ip_proto)) {
		LOG_ARFS("flow is not full match, l3_proto 0x%X, l4_proto 0x%X\n",
			 ntohs(n_proto), ip_proto);
		return -EOPNOTSUPP;
	}

	hash = skb_get_hash_raw(skb);
	idx = hash & SXE2_ARFS_LIST_MASK;

	spin_lock_bh(&adapter->arfs_ctxt.filter_lock);
	if (unlikely(!adapter->arfs_ctxt.filter_list)) {
		LOG_ARFS("filter list is NULL.\n");
		ret = -ENODEV;
		goto l_out;
	}
	hlist_for_each_entry(arfs_filter, &adapter->arfs_ctxt.filter_list[idx],
			     hl_node) {
		struct sxe2_fnav_filter *filter_info = &arfs_filter->filter_info;

		if (!sxe2_arfs_filter_cmp(filter_info, &fk))
			continue;

		ret = arfs_filter->filter_idx;

		if (arfs_filter->filter_state != SXE2_ARFS_FILTER_ACTIVE)
			goto l_out;

		filter_info->origin_q_index = rxq_idx;
		filter_info->q_index = rxq_idx;
		arfs_filter->filter_state = SXE2_ARFS_FILTER_MODIFY;
		LOG_ARFS("modify q, ori_q %u, new_q %u, state %u\n",
			 filter_info->origin_q_index, rxq_idx,
			 arfs_filter->filter_state);

		goto schedule_work;
	}

	arfs_filter = sxe2_arfs_filter_build(adapter, &fk, rxq_idx, flow_id, hash);
	if (!arfs_filter) {
		ret = -ENOMEM;
		goto l_out;
	}
	ret = arfs_filter->filter_idx;
	hlist_add_head(&arfs_filter->hl_node, &adapter->arfs_ctxt.filter_list[idx]);

schedule_work:
	sxe2_monitor_work_schedule(adapter);
l_out:
	spin_unlock_bh(&adapter->arfs_ctxt.filter_lock);
	return ret;
}

STATIC bool sxe2_arfs_filter_expired(struct sxe2_adapter *adapter,
				     struct sxe2_arfs_filter *filter)
{
	struct net_device *netdev = adapter->vsi_ctxt.main_vsi->netdev;

	if (rps_may_expire_flow(netdev, filter->filter_info.q_index, filter->flow_id,
				filter->filter_idx)) {
		return true;
	}

	if (filter->filter_info.flow_type != SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_UDP &&
	    filter->filter_info.flow_type != SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_UDP) {
		return false;
	}

	return time_in_range64(filter->time_activated +
					       SXE2_ARFS_TIME_DELTA_EXPIRATION,
			       filter->time_activated, get_jiffies_64());
}

STATIC void sxe2_arfs_filter_sync_process_inactive(struct sxe2_adapter *adapter,
						   struct sxe2_arfs_filter *filter,
						   struct hlist_head *update_list,
						   struct hlist_head *del_list)
{
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	enum sxe2_fnav_flow_type flow_type = filter->filter_info.flow_type;
	enum sxe2_fnav_flow_type fnav_flow_type =
			sxe2_arfs_flow_to_fnav_flow(flow_type);
	struct sxe2_arfs_entry_ptr *ep = NULL;

	if (!sxe2_fnav_flow_cfg_full_match(adapter, fnav_flow_type)) {
		hlist_del(&filter->hl_node);
		hlist_add_head(&filter->hl_node, del_list);
		LOG_ARFS("full match change, del inactive filter[%u]\n",
			 filter->filter_idx);
	} else {
		ep = devm_kzalloc(dev, sizeof(*ep), GFP_ATOMIC | __GFP_NOWARN);
		if (!ep) {
			LOG_ARFS("alloc inactive ep memory failed\n");
			return;
		}
		INIT_HLIST_NODE(&ep->hl_node);
		ep->arfs_filter = filter;
		hlist_add_head(&ep->hl_node, update_list);
		if (flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_UDP ||
		    flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_UDP) {
			filter->time_activated = get_jiffies_64();
		}
		LOG_ARFS("add inactive filter[%u]\n", filter->filter_idx);
	}
}

STATIC void sxe2_arfs_filter_sync_process_modify(struct sxe2_adapter *adapter,
						 struct sxe2_arfs_filter *filter,
						 struct hlist_head *update_list,
						 struct hlist_head *del_list)
{
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	enum sxe2_fnav_flow_type flow_type = filter->filter_info.flow_type;
	struct sxe2_arfs_entry_ptr *ep = NULL;

	ep = devm_kzalloc(dev, sizeof(*ep), GFP_ATOMIC | __GFP_NOWARN);
	if (!ep) {
		LOG_ARFS("alloc modify ep memory failed\n");
		return;
	}
	INIT_HLIST_NODE(&ep->hl_node);
	ep->arfs_filter = filter;
	hlist_add_head(&ep->hl_node, update_list);
	if (flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_UDP ||
	    flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_UDP) {
		filter->time_activated = get_jiffies_64();
	}
	LOG_ARFS("add modify filter[%u]\n", filter->filter_idx);
}

STATIC void sxe2_arfs_filter_sync_process_conflict(struct sxe2_adapter *adapter,
						   struct sxe2_arfs_filter *filter,
						   struct hlist_head *update_list,
						   struct hlist_head *del_list)
{
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
#ifndef SXE2_CFG_RELEASE
	struct net_device *netdev = adapter->vsi_ctxt.main_vsi->netdev;
#endif
	enum sxe2_fnav_flow_type flow_type = filter->filter_info.flow_type;
	enum sxe2_fnav_flow_type fnav_flow_type =
			sxe2_arfs_flow_to_fnav_flow(flow_type);
	struct sxe2_arfs_entry_ptr *ep = NULL;

	if (!sxe2_fnav_flow_cfg_full_match(adapter, fnav_flow_type)) {
		hlist_del(&filter->hl_node);
		hlist_add_head(&filter->hl_node, del_list);
		LOG_ARFS("del conflict filter[%u], expire flow %d, timeout %d\n",
			 filter->filter_idx,
			 rps_may_expire_flow(netdev, filter->filter_info.q_index,
					     filter->flow_id, filter->filter_idx),
			 time_in_range64(filter->time_activated +
							 SXE2_ARFS_TIME_DELTA_EXPIRATION,
					 filter->time_activated, get_jiffies_64()));
	} else {
		if (sxe2_arfs_filter_expired(adapter, filter)) {
			hlist_del(&filter->hl_node);
			hlist_add_head(&filter->hl_node, del_list);
			LOG_ARFS("del conflict filter[%u], expire flow %d, timeout %d\n",
				 filter->filter_idx,
				 rps_may_expire_flow(netdev,
						     filter->filter_info.q_index,
						     filter->flow_id,
						     filter->filter_idx),
				 time_in_range64(filter->time_activated +
								 SXE2_ARFS_TIME_DELTA_EXPIRATION,
						 filter->time_activated,
						 get_jiffies_64()));
		} else {
			ep = devm_kzalloc(dev, sizeof(*ep),
					  GFP_ATOMIC | __GFP_NOWARN);
			if (!ep) {
				LOG_ARFS("alloc conflict ep memory failed\n");
				return;
			}
			INIT_HLIST_NODE(&ep->hl_node);
			ep->arfs_filter = filter;
			hlist_add_head(&ep->hl_node, update_list);
			if (flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_UDP ||
			    flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_UDP) {
				filter->time_activated = get_jiffies_64();
			}
			LOG_ARFS("add conflict filter[%u]\n", filter->filter_idx);
		}
	}
}

STATIC void sxe2_arfs_filter_sync_process_active(struct sxe2_adapter *adapter,
						 struct sxe2_arfs_filter *filter,
						 struct hlist_head *update_list,
						 struct hlist_head *del_list)
{
#ifndef SXE2_CFG_RELEASE
	struct net_device *netdev = adapter->vsi_ctxt.main_vsi->netdev;
#endif

	if (sxe2_arfs_filter_expired(adapter, filter)) {
		hlist_del(&filter->hl_node);
		filter->filter_state = SXE2_ARFS_FILTER_TODEL;
		hlist_add_head(&filter->hl_node, del_list);
		LOG_ARFS("del active filter[%u], expire flow %d, timeout %d\n",
			 filter->filter_idx,
			 rps_may_expire_flow(netdev, filter->filter_info.q_index,
					     filter->flow_id, filter->filter_idx),
			 time_in_range64(filter->time_activated +
							 SXE2_ARFS_TIME_DELTA_EXPIRATION,
					 filter->time_activated, get_jiffies_64()));
	}
}

STATIC void sxe2_arfs_filter_sync_process(struct sxe2_adapter *adapter,
					  struct sxe2_arfs_filter *filter,
					  struct hlist_head *update_list,
					  struct hlist_head *del_list)
{
	if (filter->filter_state == SXE2_ARFS_FILTER_INACTIVE) {
		sxe2_arfs_filter_sync_process_inactive(adapter, filter, update_list,
						       del_list);
	} else if (filter->filter_state == SXE2_ARFS_FILTER_MODIFY) {
		sxe2_arfs_filter_sync_process_modify(adapter, filter, update_list,
						     del_list);
	} else if (filter->filter_state == SXE2_ARFS_FILTER_CONFLICT) {
		sxe2_arfs_filter_sync_process_conflict(adapter, filter, update_list,
						       del_list);
	} else if (filter->filter_state == SXE2_ARFS_FILTER_ACTIVE) {
		sxe2_arfs_filter_sync_process_active(adapter, filter, update_list,
						     del_list);
	}
}

static bool sxe2_arfs_filter_compare(struct sxe2_fnav_filter *filter_a,
				     enum sxe2_fnav_flow_type flow_type_a,
				     struct sxe2_fnav_filter *filter_b,
				     enum sxe2_fnav_flow_type flow_type_b)
{
	bool is_v4, is_v6;

	if (!filter_a || !filter_b)
		return false;

	if (flow_type_a != flow_type_b)
		return false;

	is_v4 = (flow_type_a == SXE2_FNAV_FLOW_TYPE_IPV4_TCP ||
		 flow_type_a == SXE2_FNAV_FLOW_TYPE_IPV4_UDP);
	is_v6 = (flow_type_a == SXE2_FNAV_FLOW_TYPE_IPV6_TCP ||
		 flow_type_a == SXE2_FNAV_FLOW_TYPE_IPV6_UDP);

	if (is_v4) {
		return (filter_a->full_key.ip.v4.src_ip ==
					filter_b->full_key.ip.v4.src_ip &&
			filter_a->full_key.ip.v4.dst_ip ==
					filter_b->full_key.ip.v4.dst_ip &&
			filter_a->full_key.l4.src_port ==
					filter_b->full_key.l4.src_port &&
			filter_a->full_key.l4.dst_port ==
					filter_b->full_key.l4.dst_port);
	} else if (is_v6) {
		return (!memcmp(filter_a->full_key.ip.v6.src_ip,
				filter_b->full_key.ip.v6.src_ip,
				sizeof(struct in6_addr)) &&
			!memcmp(filter_a->full_key.ip.v6.dst_ip,
				filter_b->full_key.ip.v6.dst_ip,
				sizeof(struct in6_addr)) &&
			filter_a->full_key.l4.src_port ==
					filter_b->full_key.l4.src_port &&
			filter_a->full_key.l4.dst_port ==
					filter_b->full_key.l4.dst_port);
	}

	return false;
}

STATIC bool sxe2_arfs_filter_conflict(struct sxe2_adapter *adapter,
				      struct sxe2_fnav_filter *filter_info)
{
	bool ret = false;
	u32 idx;
	struct sxe2_fnav_filter *filter_tmp;

	sxe2_fnav_filter_hash(filter_info);

	idx = filter_info->hash_val & SXE2_FNAV_FLTR_HLIST_MASK;
	hlist_for_each_entry(filter_tmp, &adapter->fnav_ctxt.filter_hlist[idx],
			     hl_node) {
		ret = sxe2_arfs_filter_compare(filter_info,
					       sxe2_arfs_flow_to_fnav_flow(filter_info->flow_type),
					       filter_tmp, filter_tmp->flow_type);
		if (ret) {
			filter_tmp->conflict = true;
			break;
		}
	}

	return ret;
}

STATIC void sxe2_arfs_filters_del(struct sxe2_adapter *adapter,
				  struct hlist_head *del_list)
{
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;
	struct sxe2_arfs_filter *filter;
	struct hlist_node *node;
	s32 ret;
	bool conflict;

	mutex_lock(&adapter->fnav_ctxt.filter_lock);
	mutex_lock(&vsi->fnav.flow_cfg_lock);
	hlist_for_each_entry_safe(filter, node, del_list, hl_node) {
		if (filter->filter_state != SXE2_ARFS_FILTER_INACTIVE &&
		    filter->filter_state != SXE2_ARFS_FILTER_CONFLICT) {
			LOG_ARFS("del filter\n");
			sxe2_arfs_filter_print(adapter, filter);
			conflict = sxe2_arfs_filter_conflict(adapter,
							     &filter->filter_info);
			if (!conflict) {
				ret = sxe2_pf_fnav_hw_filter_update(vsi,
								    &filter->filter_info,
								    false,
								    false,
								    SXE2_FNAV_FILTER_UPDATE_PKT);
				if (!ret) {
					sxe2_arfs_active_filter_cnt_update(adapter,
									   filter, false);
				} else {
					LOG_DEV_WARN("unable to delete aRFS filter,\t"
						     "ret:%d filter_state:%d\t"
						     "filter_loc:%d flow_id:%d\t"
						     "queue:%d\n",
						     ret, filter->filter_state,
						     filter->filter_idx,
						     filter->flow_id,
						     filter->filter_info.q_index);
				}
			} else {
				sxe2_arfs_active_filter_cnt_update(adapter, filter,
								   false);
			}
		}
		hlist_del(&filter->hl_node);
		devm_kfree(dev, filter);
	}
	mutex_unlock(&vsi->fnav.flow_cfg_lock);
	mutex_unlock(&adapter->fnav_ctxt.filter_lock);
}

STATIC void sxe2_arfs_filters_update(struct sxe2_adapter *adapter,
				     struct hlist_head *update_list)
{
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;
	struct sxe2_arfs_filter *filter;
	struct sxe2_arfs_entry_ptr *ep;
	struct hlist_node *node;
	s32 ret;
	bool conflict;
	bool is_update;

	mutex_lock(&adapter->fnav_ctxt.filter_lock);
	hlist_for_each_entry_safe(ep, node, update_list, hl_node) {
		is_update = false;
		filter = ep->arfs_filter;
		LOG_ARFS("update filter\n");
		sxe2_arfs_filter_print(adapter, filter);
		conflict = sxe2_arfs_filter_conflict(adapter, &filter->filter_info);
		if (filter->filter_state == SXE2_ARFS_FILTER_INACTIVE) {
			if (conflict)
				filter->filter_state = SXE2_ARFS_FILTER_CONFLICT;
		} else if (filter->filter_state == SXE2_ARFS_FILTER_MODIFY) {
			if (conflict) {
				filter->filter_state = SXE2_ARFS_FILTER_CONFLICT;
				sxe2_arfs_active_filter_cnt_update(adapter, filter,
								   false);
			}
		}
		if (!conflict) {
			if (filter->filter_state == SXE2_ARFS_FILTER_MODIFY)
				is_update = true;
			ret = sxe2_pf_fnav_hw_filter_update(vsi,
							    &filter->filter_info,
							    true,
							    is_update,
							    SXE2_FNAV_FILTER_UPDATE_PKT);
			if (!ret) {
				if (filter->filter_state !=
				    SXE2_ARFS_FILTER_MODIFY) {
					sxe2_arfs_active_filter_cnt_update(adapter,
									   filter, true);
				}
				filter->filter_state = SXE2_ARFS_FILTER_ACTIVE;
			} else {
				LOG_DEV_WARN("unable to add aRFS filter, ret:%d\t"
					     "filter_state:%d filter_loc:%d\t"
					     "flow_id:%d queue:%d\n",
					     ret, filter->filter_state,
					     filter->filter_idx, filter->flow_id,
					     filter->filter_info.q_index);
			}
		}
		hlist_del(&ep->hl_node);
		devm_kfree(dev, ep);
	}
	mutex_unlock(&adapter->fnav_ctxt.filter_lock);
}

void sxe2_arfs_filters_sync(struct sxe2_adapter *adapter)
{
	HLIST_HEAD(tmp_del_list);
	HLIST_HEAD(tmp_update_list);
	u32 i;
	struct sxe2_arfs_filter *filter;
	struct hlist_node *node;

	if (sxe2_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return;

	mutex_lock(&adapter->arfs_ctxt.update_list_lock);
	mutex_lock(&adapter->vsi_ctxt.main_vsi->fnav.flow_cfg_lock);
	spin_lock_bh(&adapter->arfs_ctxt.filter_lock);
	if (likely(adapter->arfs_ctxt.filter_list)) {
		for (i = 0; i < SXE2_MAX_ARFS_LIST; i++) {
			hlist_for_each_entry_safe(filter, node,
						  &adapter->arfs_ctxt.filter_list[i],
						  hl_node) {
				sxe2_arfs_filter_sync_process(adapter, filter,
							      &tmp_update_list,
							      &tmp_del_list);
			}
		}
	}
	spin_unlock_bh(&adapter->arfs_ctxt.filter_lock);
	mutex_unlock(&adapter->vsi_ctxt.main_vsi->fnav.flow_cfg_lock);

	sxe2_arfs_filters_del(adapter, &tmp_del_list);
	sxe2_arfs_filters_update(adapter, &tmp_update_list);

	mutex_unlock(&adapter->arfs_ctxt.update_list_lock);
}

bool sxe2_arfs_flow_cfg_used(struct sxe2_adapter *adapter, u16 vsi_id,
			     enum sxe2_fnav_flow_type flow_type)
{
	if (vsi_id != adapter->arfs_ctxt.vsi_id_in_pf)
		return false;

	if (flow_type == SXE2_FNAV_FLOW_TYPE_IPV4_TCP)
		return adapter->arfs_ctxt.filter_cnt.tcp4_cnt > 0;
	else if (flow_type == SXE2_FNAV_FLOW_TYPE_IPV4_UDP)
		return adapter->arfs_ctxt.filter_cnt.udp4_cnt > 0;
	else if (flow_type == SXE2_FNAV_FLOW_TYPE_IPV6_TCP)
		return adapter->arfs_ctxt.filter_cnt.tcp6_cnt > 0;
	else if (flow_type == SXE2_FNAV_FLOW_TYPE_IPV6_UDP)
		return adapter->arfs_ctxt.filter_cnt.udp6_cnt > 0;
	else
		return false;
}

STATIC bool sxe2_rps_expire_flow(struct sxe2_adapter *adapter,
				 struct net_device *dev,
				 struct sxe2_arfs_filter *filter)
{
	struct netdev_rx_queue *rxqueue = dev->_rx + filter->filter_info.q_index;
	struct rps_dev_flow_table *flow_table;
	struct rps_dev_flow *rflow;
	bool expire = true;
	unsigned int cpu;

	LOG_DEV_INFO("\trps expire flow detect:");

	rcu_read_lock();
	flow_table = rcu_dereference(rxqueue->rps_flow_table);
	if (flow_table) {
		LOG_DEV_INFO("\tflow_id %u, mask %u\n", filter->flow_id,
			     flow_table->mask);
	}
	if (flow_table && filter->flow_id <= flow_table->mask) {
		rflow = &flow_table->flows[filter->flow_id];
		cpu = READ_ONCE(rflow->cpu);
		LOG_DEV_INFO("\tfilter_id %u, cpu %u, nr_cpu_ids %u, last_qtail %d\n",
			     filter->filter_idx, cpu, nr_cpu_ids,
			     (int)(rflow->last_qtail));
		if (cpu < nr_cpu_ids) {
			LOG_DEV_INFO("\tinput_queue_head %d",
				     (int)(per_cpu(softnet_data, cpu)
							   .input_queue_head));
		}
		if (rflow->filter == filter->filter_idx && cpu < nr_cpu_ids &&
		    ((int)(per_cpu(softnet_data, cpu).input_queue_head -
			   rflow->last_qtail) < (int)(10 * flow_table->mask)))
			expire = false;
	}
	rcu_read_unlock();

	LOG_DEV_INFO("\tfilter expire: %d\n", expire);

	return expire;
}

void sxe2_arfs_stats_dump(struct sxe2_adapter *adapter)
{
	u32 i = 0, j = 0;
	struct sxe2_arfs_filter *filter;
	struct hlist_node *node;

	LOG_DEV_INFO("active filter cnt:\n");

	mutex_lock(&adapter->arfs_ctxt.update_list_lock);
	LOG_DEV_INFO("\ttcp4: %u\n", adapter->arfs_ctxt.filter_cnt.tcp4_cnt);
	LOG_DEV_INFO("\tudp4: %u\n", adapter->arfs_ctxt.filter_cnt.udp4_cnt);
	LOG_DEV_INFO("\ttcp6: %u\n", adapter->arfs_ctxt.filter_cnt.tcp6_cnt);
	LOG_DEV_INFO("\tudp6: %u\n", adapter->arfs_ctxt.filter_cnt.udp6_cnt);
	LOG_DEV_INFO("list filter id: %u\n", adapter->arfs_ctxt.last_filter_id);

	spin_lock_bh(&adapter->arfs_ctxt.filter_lock);
	if (likely(adapter->arfs_ctxt.filter_list)) {
		for (i = 0; i < SXE2_MAX_ARFS_LIST; i++) {
			hlist_for_each_entry_safe(filter, node,
						  &adapter->arfs_ctxt.filter_list[i],
						  hl_node) {
				LOG_DEV_INFO("filter[%u]\n", j);
				sxe2_arfs_filter_print_screen(adapter, filter);
				sxe2_rps_expire_flow(adapter,
						     adapter->vsi_ctxt.main_vsi->netdev,
						     filter);
				j++;
			}
		}
	}
	spin_unlock_bh(&adapter->arfs_ctxt.filter_lock);

	mutex_unlock(&adapter->arfs_ctxt.update_list_lock);

	if (adapter->vsi_ctxt.main_vsi->netdev->rx_cpu_rmap) {
		for (i = 0; i < num_online_cpus(); i++) {
			LOG_DEV_INFO("cpu[%u] --> %u, dist: %u\n", i,
				     adapter->vsi_ctxt.main_vsi->netdev->rx_cpu_rmap
						     ->near[i]
						     .index,
				     adapter->vsi_ctxt.main_vsi->netdev->rx_cpu_rmap
						     ->near[i]
						     .dist);
		}
	}
}

#endif
