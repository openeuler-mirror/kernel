// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_txrx_lib.h"
#include "mce_txrx.h"
#include "mce_lib.h"

/**
 * mce_rx_hash - set the hash value in the skb
 * @rx_ring: descriptor ring
 * @rx_desc: specific descriptor
 * @skb: pointer to current skb
 */
static void mce_rx_hash(struct mce_ring *rx_ring,
			struct mce_rx_desc_up *rx_desc,
			  struct sk_buff *skb)
{
	enum pkt_hash_types hash_type = PKT_HASH_TYPE_NONE;
	struct mce_pf *pf = rx_ring->vsi->back;
	struct mce_hw *hw = &pf->hw;
	u32 hash = 0;
	u32 cmd;

	if (!(rx_ring->netdev->features & NETIF_F_RXHASH))
		return;

	hash = le32_to_cpu(rx_desc->rss_hash);
	cmd = le32_to_cpu(rx_desc->cmd);

	switch (GET_RD_O_L3_TYPE(cmd)) {
	case L3TYPE_IPv4:
	case L3TYPE_IPv6:
		if (hw->rss_hash_type & (MCE_F_HASH_IPV6 |
				MCE_F_HASH_IPV4)) {
			hash_type = PKT_HASH_TYPE_L3;
		}
	default:
		break;
	}

	switch (GET_RD_O_L4_TYPE(cmd)) {
	case L4TYPE_UDP:
	case L4TYPE_TCP:
	case L4TYPE_SCTP:
		if (hw->rss_hash_type & (MCE_F_HASH_IPV4_TCP |
				MCE_F_HASH_IPV4_UDP |
				MCE_F_HASH_IPV4_SCTP |
				MCE_F_HASH_IPV6_TCP |
				MCE_F_HASH_IPV6_UDP |
				MCE_F_HASH_IPV6_SCTP)) {
			hash_type = PKT_HASH_TYPE_L4;
		}
		break;
	default:
		break;
	}

	skb_set_hash(skb, hash, hash_type);
}

/**
 * mce_rx_csum - Indicate in skb if checksum is good
 * @rx_ring: the ring we care about
 * @skb: skb currently being received and modified
 * @rx_desc: the receive descriptor
 *
 * skb->protocol must be set before this function is called
 */
static void mce_process_rx_csum(struct mce_ring *rx_ring,
				struct sk_buff *skb,
				  struct mce_rx_desc_up *rx_desc)
{
	u16 err_cmd = le16_to_cpu(rx_desc->err_cmd);
	u32 cmd = le32_to_cpu(rx_desc->cmd);

	/* Start with CHECKSUM_NONE and by default csum_level = 0 */
	skb->ip_summed = CHECKSUM_NONE;
	skb_checksum_none_assert(skb);

	/* check if Rx checksum is enabled */
	if (!(rx_ring->netdev->features & NETIF_F_RXCSUM))
		goto checksum_none;

	if (GET_RD_ERR(err_cmd)) {
		u64_stats_update_begin(&rx_ring->ring_stats->syncp);
		(rx_ring->ring_stats->rx_stats.csum_err)++;
		u64_stats_update_end(&rx_ring->ring_stats->syncp);

		return;
	}

	switch (GET_RD_TUNNEL_TYPE(cmd)) {
	case INNER_VXLAN:
	case INNER_GRE:
	case INNER_GENEVE:
		skb->encapsulation = 1;
		break;
	default:
		break;
	}

	switch (GET_RD_O_L4_TYPE(cmd)) {
	case L4TYPE_UDP:
	case L4TYPE_TCP:
	case L4TYPE_SCTP:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		u64_stats_update_begin(&rx_ring->ring_stats->syncp);
		(rx_ring->ring_stats->rx_stats.csum_unnecessary)++;
		u64_stats_update_end(&rx_ring->ring_stats->syncp);
		return;
	default:
		break;
	}

checksum_none:
	u64_stats_update_begin(&rx_ring->ring_stats->syncp);
	(rx_ring->ring_stats->rx_stats.csum_none)++;
	u64_stats_update_end(&rx_ring->ring_stats->syncp);
}

#define __DEBUG_FOR_RXVLAN (0)

static struct sk_buff *mce_process_rx_vlan(struct mce_ring *rx_ring,
					   struct sk_buff *skb,
					   struct mce_rx_desc_up *rx_desc)
{
	u8 vlan_strip = GET_RD_VLAN_STRIP(le16_to_cpu(rx_desc->err_cmd));
	u8 vlan_valid = GET_RD_VLAN_VALID(le32_to_cpu(rx_desc->cmd));
	struct net_device *netdev = rx_ring->netdev;
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_pf *pf = np->vsi->back;
	bool ret = true;
	__be16 proto;
	u16 vlan_tpid = le16_to_cpu(rx_desc->vlan_tpid);
	u16 vlan_tag0 = le16_to_cpu(rx_desc->vlan_tag0);
	u16 vlan_tag1 = le16_to_cpu(rx_desc->vlan_tag1);

	if (!vlan_valid || !vlan_strip)
		return skb;

	if (MCE_INSERT_VLAN_CNT(pf))
		return skb;

	switch (vlan_strip) {
	case 1:
		if (GET_RD_VLAN_TPID_OUTER_TYPE(vlan_tpid) ==
		    MCE_VLAN_TYPE_8100)
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       vlan_tag0);
		else
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD),
					       vlan_tag0);
#if __DEBUG_FOR_RXVLAN
		pr_info("[debug] name:%s strip:1 outertype:%ld vlan0:%d\n",
			netdev->name,
			GET_RD_VLAN_TPID_OUTER_TYPE(vlan_tpid), vlan_tag0);
#endif
		break;
	case 2:
		if (GET_RD_VLAN_TPID_MIDDLE_TYPE(vlan_tpid) ==
		    MCE_VLAN_TYPE_8100)
			proto = htons(ETH_P_8021Q);
		else
			proto = htons(ETH_P_8021AD);
		skb = vlan_insert_tag_set_proto(skb, proto,
						vlan_tag1);
		if (!skb) {
			net_err_ratelimited("strip:2 failed to insert middle VLAN tag\n");
			ret = false;
			break;
		}

		if (GET_RD_VLAN_TPID_OUTER_TYPE(vlan_tpid) ==
		    MCE_VLAN_TYPE_8100)
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       vlan_tag0);
		else
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD),
					       vlan_tag0);
#if __DEBUG_FOR_RXVLAN
		pr_info("[debug] name:%s strip:2 outertype:%ld vlan0:%d middletype:%ld vlan1:%d\n",
			netdev->name,
			GET_RD_VLAN_TPID_OUTER_TYPE(vlan_tpid), vlan_tag0,
			GET_RD_VLAN_TPID_MIDDLE_TYPE(vlan_tpid), vlan_tag1);
#endif
		break;
	default:
		ret = false;
		break;
	}

	if (ret && pf->vlan_strip_cnt) {
		u64_stats_update_begin(&rx_ring->ring_stats->syncp);
		(rx_ring->ring_stats->rx_stats.stripped_vlan)++;
		u64_stats_update_end(&rx_ring->ring_stats->syncp);
	}

	return skb;
}

/**
 * mce_process_skb_fields - Populate skb header fields from Rx descriptor
 * @rx_ring: Rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being populated
 *
 * This function checks the ring, descriptor, and packet information in
 * order to populate the hash, checksum, VLAN, protocol, and
 * other fields within the skb.
 */
struct sk_buff *mce_process_skb_fields(struct mce_ring *rx_ring,
				       struct mce_rx_desc_up *rx_desc,
				       struct sk_buff *skb)
{
	mce_rx_hash(rx_ring, rx_desc, skb);

	mce_process_rx_csum(rx_ring, skb, rx_desc);

	skb = mce_process_rx_vlan(rx_ring, skb, rx_desc);
	if (!skb)
		return NULL;
	/* modifies the skb - consumes the enet header */
	skb->protocol = eth_type_trans(skb, rx_ring->netdev);

	return skb;
}
