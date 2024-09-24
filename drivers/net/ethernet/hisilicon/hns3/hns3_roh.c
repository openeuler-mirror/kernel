// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <net/arp.h>

#include "hns3_roh.h"
#include "hns3_enet.h"

static void hns3_extract_arp_ip_field(struct arphdr *arphdr, __be32 **sip,
				      __be32 **tip, unsigned char addr_len)
{
	unsigned char *arp_ptr = (unsigned char *)(arphdr + 1);

	arp_ptr += addr_len;
	*sip = (__be32 *)arp_ptr;
	arp_ptr += ARP_IP_LEN;
	arp_ptr += addr_len;
	*tip = (__be32 *)arp_ptr;
}

bool hns3_need_to_handle_roh_arp_req(struct sk_buff *skb)
{
	struct arphdr *arphdr = arp_hdr(skb);
	__be32 *sip, *tip;

	/* Intercept most non-ARP packets based on packet length. */
	if (skb->len > hns3_roh_arp_hlen_max(skb))
		return false;

	/* if txvlan offload is off, check encapsulated protocol in vlan. */
	if (eth_type_vlan(skb->protocol)) {
		struct vlan_hdr *vh = (struct vlan_hdr *)(skb->data + ETH_HLEN);

		if (vh->h_vlan_encapsulated_proto == htons(ETH_P_ARP) &&
		    arphdr->ar_op == htons(ARPOP_REQUEST))
			goto check_gratuitous_arp;
		return false;
	}

	/* if txvlan offload is on or it's a normal packet, check protocol. */
	if (skb->protocol != htons(ETH_P_ARP) ||
	    arphdr->ar_op != htons(ARPOP_REQUEST))
		return false;

	/* don't support Gratuitous ARP, which request packet where the source
	 * and destination IP are both set to the IP of the machine issuing the
	 * packet.
	 */
check_gratuitous_arp:
	hns3_extract_arp_ip_field(arphdr, &sip, &tip, skb->dev->addr_len);
	return *tip != *sip;
}

int hns3_handle_roh_arp_req(struct sk_buff *skb, struct hns3_nic_priv *priv)
{
	struct hnae3_handle *h = priv->ae_handle;
	struct hns3_enet_ring *ring;
	struct arphdr *arphdr;
	struct ethhdr *ethhdr;
	int reply_idx, len;
	__be32 *sip, *tip;

	/* use same queue num in rx */
	ring = &priv->ring[skb->queue_mapping + h->kinfo.num_tqps];
	reply_idx = ring->arp_reply_tail;
	reply_idx = hns3_roh_arp_reply_idx_move_fd(reply_idx);
	/* This smp_load_acquire() pairs with smp_store_release() in
	 * hns3_handle_roh_arp_reply().
	 */
	if (reply_idx == smp_load_acquire(&ring->arp_reply_head))
		return NETDEV_TX_BUSY;
	len = skb->len;

	if (skb_vlan_tagged(skb)) {
		ring->arp_reply[reply_idx].has_vlan = true;
		ring->arp_reply[reply_idx].vlan_tci = skb_vlan_tag_get(skb);
		if (likely(!skb_vlan_pop(skb)))
			len += VLAN_HLEN;
		else
			goto err_vlan_head;
	} else {
		ring->arp_reply[reply_idx].has_vlan = false;
	}

	ethhdr = eth_hdr(skb);
	arphdr = arp_hdr(skb);

	hns3_extract_arp_ip_field(arphdr, &sip, &tip, skb->dev->addr_len);
	ether_addr_copy(ring->arp_reply[reply_idx].dest_hw, ethhdr->h_source);
	ether_addr_copy(ring->arp_reply[reply_idx].src_hw, ethhdr->h_dest);
	ring->arp_reply[reply_idx].dest_ip = *sip;
	ring->arp_reply[reply_idx].src_ip = *tip;
	hns3_roh_update_mac_by_ip(be32_to_cpu(*tip),
				  ring->arp_reply[reply_idx].src_hw);
	/* This smp_store_release() pairs with smp_load_acquire() in
	 * hns3_handle_roh_arp_reply(). Ensure that the arp_reply_tail is
	 * update validly.
	 */
	smp_store_release(&ring->arp_reply_tail, reply_idx);

	ring = &priv->ring[skb->queue_mapping];
	u64_stats_update_begin(&ring->syncp);
	ring->stats.tx_pkts++;
	ring->stats.tx_bytes += len;
	u64_stats_update_end(&ring->syncp);

	dev_kfree_skb_any(skb);
	napi_schedule(&ring->tqp_vector->napi);
	return NETDEV_TX_OK;

err_vlan_head:
	hns3_ring_stats_update(ring, tx_vlan_err);
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static struct sk_buff *setup_arp_reply_skb(struct hns3_arp_reply *arp_reply,
					   struct hns3_nic_priv *priv)
{
	struct sk_buff *skb = arp_create(ARPOP_REPLY, ETH_P_ARP,
					 arp_reply->dest_ip, priv->netdev,
					 arp_reply->src_ip, arp_reply->dest_hw,
					 arp_reply->src_hw, arp_reply->dest_hw);
	if (!skb)
		return NULL;

	skb_reset_mac_header(skb);
	skb_reset_mac_len(skb);

	if (arp_reply->has_vlan) {
		skb = vlan_insert_tag_set_proto(skb, htons(ETH_P_8021Q),
						arp_reply->vlan_tci);
		if (!skb)
			return NULL;
		skb_reset_network_header(skb);
	}

	skb_reserve(skb, skb->mac_len);
	return skb;
}

void hns3_handle_roh_arp_reply(struct hns3_enet_tqp_vector *tqp_vector,
			       struct hns3_nic_priv *priv)
{
	struct hns3_arp_reply *arp_reply;
	struct hns3_enet_ring *ring;
	struct sk_buff *skb;
	int reply_idx;

	hns3_for_each_ring(ring, tqp_vector->rx_group) {
		/* This smp_load_acquire() pairs with smp_store_release() in
		 * hns3_handle_roh_arp_reply().
		 */
		while (smp_load_acquire(&ring->arp_reply_tail) !=
		       ring->arp_reply_head) {
			reply_idx = ring->arp_reply_head;
			reply_idx = hns3_roh_arp_reply_idx_move_fd(reply_idx);
			arp_reply = &ring->arp_reply[reply_idx];
			skb = setup_arp_reply_skb(arp_reply, priv);
			/* This smp_store_release() pairs with
			 * smp_load_acquire() in hns3_handle_roh_arp_req().
			 * Ensure that the arp_reply_head is update validly.
			 */
			smp_store_release(&ring->arp_reply_head, reply_idx);

			if (!skb) {
				hns3_ring_stats_update(ring, rx_err_cnt);
				continue;
			}
			napi_gro_receive(&tqp_vector->napi, skb);

			u64_stats_update_begin(&ring->syncp);
			ring->stats.rx_pkts++;
			ring->stats.rx_bytes += skb->len;
			u64_stats_update_end(&ring->syncp);
		}
	}
}
