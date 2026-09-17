// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */

#include "mcevf.h"
#include "mcevf_txrx_lib.h"
#include "mcevf_txrx.h"
#include "mcevf_lib.h"

/**
 * mcevf_rx_hash - set the hash value in the skb
 * @rx_ring: descriptor ring
 * @rx_desc: specific descriptor
 * @skb: pointer to current skb
 */
static void mcevf_rx_hash(struct mcevf_ring *rx_ring,
			  struct mcevf_rx_desc_up *rx_desc,
			  struct sk_buff *skb)
{
	struct mcevf_pf *pf = rx_ring->vsi->back;
	struct mcevf_hw *hw = &pf->hw;
	enum pkt_hash_types hash_type = PKT_HASH_TYPE_NONE;
	u32 hash = 0;

	if (!(rx_ring->netdev->features & NETIF_F_RXHASH))
		return;

	hash = le32_to_cpu(rx_desc->rss_hash);

	switch (GET_RD_O_L3_TYPE(rx_desc->cmd)) {
	case L3TYPE_IPV4:
	case L3TYPE_IPV6:
		if (hw->rss_hash_type &
		    (MCEVF_F_HASH_IPV6 | MCEVF_F_HASH_IPV4)) {
			hash_type = PKT_HASH_TYPE_L3;
		}
	default:
		break;
	}

	switch (GET_RD_O_L4_TYPE(rx_desc->cmd)) {
	case L4TYPE_UDP:
	case L4TYPE_TCP:
	case L4TYPE_SCTP:
		if (hw->rss_hash_type &
		    (MCEVF_F_HASH_IPV4_TCP | MCEVF_F_HASH_IPV4_UDP |
		     MCEVF_F_HASH_IPV4_SCTP | MCEVF_F_HASH_IPV6_TCP |
		     MCEVF_F_HASH_IPV6_UDP | MCEVF_F_HASH_IPV6_SCTP)) {
			hash_type = PKT_HASH_TYPE_L4;
		}
		break;
	default:
		break;
	}

	skb_set_hash(skb, hash, hash_type);
}

/**
 * mcevf_process_rx_csum - Indicate in skb if checksum is good
 * @rx_ring: the ring we care about
 * @skb: skb currently being received and modified
 * @rx_desc: the receive descriptor
 *
 * skb->protocol must be set before this function is called
 */
static void mcevf_process_rx_csum(struct mcevf_ring *rx_ring,
				  struct sk_buff *skb,
				  struct mcevf_rx_desc_up *rx_desc)
{
	/* Start with CHECKSUM_NONE and by default csum_level = 0 */
	skb->ip_summed = CHECKSUM_NONE;
	skb_checksum_none_assert(skb);

	/* check if Rx checksum is enabled */
	if ((!(rx_ring->netdev->features & NETIF_F_RXCSUM)) ||
	    (rx_ring->netdev->flags & IFF_PROMISC) ||
	    (rx_ring->netdev->features & NETIF_F_RXALL)) {
		goto checksum_none;
	}

	if (GET_RD_ERR(rx_desc->err_cmd)) {
		u64_stats_update_begin(&rx_ring->ring_stats->syncp);
		(rx_ring->ring_stats->rx_stats.csum_err)++;
		u64_stats_update_end(&rx_ring->ring_stats->syncp);
		return;
	}

	switch (GET_RD_TUNNEL_TYPE(rx_desc->cmd)) {
	case INNER_VXLAN:
	case INNER_GRE:
	case INNER_GENEVE:
		skb->csum_level = 1;
		break;
	default:
		break;
	}

	switch (GET_RD_O_L4_TYPE(rx_desc->cmd)) {
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

static bool mcevf_pf_vlan_hit(struct mcevf_pf *pf,
			      struct mcevf_rx_desc_up *rx_desc)
{
	if ((rx_desc->vlan_tag0 & 0xfff) == pf->vf_vlan &&
	    GET_RD_VLAN_TPID_OUTER_TYPE(rx_desc->vlan_tpid) ==
		    pf->vf_vlan_proto)
		return true;

	return false;
}

#define __DEBUG_FOR_RXVLAN (0)

static void mcevf_process_rx_vlan(struct mcevf_ring *rx_ring,
				  struct sk_buff *skb,
				  struct mcevf_rx_desc_up *rx_desc)
{
	struct net_device *netdev = rx_ring->netdev;
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_pf *pf = np->vsi->back;
#if __DEBUG_SKB_DUMP
	netdev_features_t features = netdev->features;
	bool valid_8021Q = !!(features & NETIF_F_HW_VLAN_CTAG_RX);
	bool valid_8021AD = !!(features & NETIF_F_HW_VLAN_STAG_RX);
	u8 qinq_valid = GET_RD_QINQ_VALID(rx_desc->cmd);
#endif
	u8 vlan_valid = GET_RD_VLAN_VALID(rx_desc->cmd);
	u8 vlan_strip = GET_RD_VLAN_STRIP(rx_desc->err_cmd);
	u16 proto;
	bool ret = true;

#if __DEBUG_SKB_DUMP
	pr_info("[debug] name:%s RX: ctagVlid:%d stagVlid:%d vlanVlid:%d vlan_strip:%d qinq_valid:%d skblen:%d\n",
		netdev->name, valid_8021Q, valid_8021AD, vlan_valid,
		vlan_strip, qinq_valid, skb->len);
	print_hex_dump(KERN_CONT, "rx_data: ", DUMP_PREFIX_OFFSET, 16, 1,
		       skb->data, skb->len, true);
	print_hex_dump(KERN_CONT, "rx_desc: ", DUMP_PREFIX_NONE, 16, 1,
		       rx_desc, 32, true);
#endif

	if (!vlan_valid || !vlan_strip)
		return;

	if (MCEVF_INSERT_VLAN_CNT(pf))
		return;

	switch (vlan_strip) {
	case 1:
		if (mcevf_pf_vlan_hit(pf, rx_desc))
			break;
		if (GET_RD_VLAN_TPID_OUTER_TYPE(rx_desc->vlan_tpid) ==
		    MCEVF_VLAN_TYPE_8100)
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       rx_desc->vlan_tag0);
		else
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD),
					       rx_desc->vlan_tag0);
#if __DEBUG_FOR_RXVLAN
		pr_info("[debug] name:%s strip:1 outertype:%d vlan0:%d\n",
			netdev->name,
			GET_RD_VLAN_TPID_OUTER_TYPE(rx_desc->vlan_tpid),
			rx_desc->vlan_tag0);
#endif
		break;
	case 2:
		if (GET_RD_VLAN_TPID_MIDDLE_TYPE(rx_desc->vlan_tpid) ==
		    MCEVF_VLAN_TYPE_8100)
			proto = htons(ETH_P_8021Q);
		else
			proto = htons(ETH_P_8021AD);
		skb = vlan_insert_tag_set_proto(skb, proto,
						rx_desc->vlan_tag1);
		if (!skb) {
			net_err_ratelimited("strip:2 failed to insert middle VLAN tag\n");
			ret = false;
			break;
		}

		if (mcevf_pf_vlan_hit(pf, rx_desc))
			break;
		if (GET_RD_VLAN_TPID_OUTER_TYPE(rx_desc->vlan_tpid) ==
		    MCEVF_VLAN_TYPE_8100)
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       rx_desc->vlan_tag0);
		else
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD),
					       rx_desc->vlan_tag0);
#if __DEBUG_FOR_RXVLAN
		pr_info("[debug] name:%s strip:2 outertype:%d vlan0:%d middletype:%d vlan1:%d\n",
			netdev->name,
			GET_RD_VLAN_TPID_OUTER_TYPE(rx_desc->vlan_tpid),
			rx_desc->vlan_tag0,
			GET_RD_VLAN_TPID_MIDDLE_TYPE(rx_desc->vlan_tpid),
			rx_desc->vlan_tag1);
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
}

/**
 * mcevf_process_skb_fields - Populate skb header fields from Rx descriptor
 * @rx_ring: Rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being populated
 *
 * This function checks the ring, descriptor, and packet information in
 * order to populate the hash, checksum, VLAN, protocol, and
 * other fields within the skb.
 */
void mcevf_process_skb_fields(struct mcevf_ring *rx_ring,
			      struct mcevf_rx_desc_up *rx_desc,
			      struct sk_buff *skb)
{
	mcevf_rx_hash(rx_ring, rx_desc, skb);
	mcevf_process_rx_csum(rx_ring, skb, rx_desc);
	mcevf_process_rx_vlan(rx_ring, skb, rx_desc);
	/* modifies the skb - consumes the enet header */
	skb->protocol = eth_type_trans(skb, rx_ring->netdev);
	/* Ensure network header points to L3 for GRO/stack consumers. */
	skb_reset_network_header(skb);
}
