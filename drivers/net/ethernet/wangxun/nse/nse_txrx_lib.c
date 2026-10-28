// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse_lib.h"
#include "nse_txrx_lib.h"
#include "nse_eswitch.h"
#include <net/busy_poll.h>

void nse_rx_ring_sync_tail_after_enable(struct nse_ring *rx_ring)
{
	writel_relaxed(rx_ring->next_to_use, rx_ring->tail);
}

/**
 * nse_release_rx_desc - Store the new tail and head values
 * @rx_ring: ring to bump
 * @val: new head index
 */
void nse_release_rx_desc(struct nse_ring *rx_ring, u16 val)
{
	u16 prev_ntu = rx_ring->next_to_use;

	rx_ring->next_to_use = val;

	/* update next to alloc since we have filled the ring */
	rx_ring->next_to_alloc = val;

	if (prev_ntu != val) {
		/* Force memory writes to complete before letting h/w
		 * know there are new descriptors to fetch. (Only
		 * applicable for weak-ordered memory model archs,
		 * such as IA-64).
		 */
		wmb();
		writel_relaxed(val, rx_ring->tail);
	}
}

/**
 * nse_ptype_to_htype - get a hash type
 * @ptype: the ptype value from the descriptor
 *
 * Returns appropriate hash type (such as PKT_HASH_TYPE_L2/L3/L4) to be used by
 * skb_set_hash based on PTYPE as parsed by HW Rx pipeline and is part of
 * Rx desc.
 */
static enum pkt_hash_types nse_ptype_to_htype(u8 ptype, u32 vsi_rss_ctl)
{
	struct nse_rx_ptype_decoded decoded = nse_decode_rx_desc_ptype(ptype);

	if (!decoded.known)
		return PKT_HASH_TYPE_NONE;
	if (decoded.payload_layer == NSE_RX_PTYPE_PAYLOAD_LAYER_PAY4) {
		if (decoded.inner_prot == NSE_RX_PTYPE_INNER_PROT_TCP &&
			((vsi_rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV4_TCP) ||
			(vsi_rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV6_TCP))) {
			return PKT_HASH_TYPE_L4;
		} else if (decoded.inner_prot == NSE_RX_PTYPE_INNER_PROT_UDP &&
			((vsi_rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV4_UDP) ||
			(vsi_rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV6_UDP))) {
			return PKT_HASH_TYPE_L4;
		}
		return PKT_HASH_TYPE_L3;
	}
	if (decoded.payload_layer == NSE_RX_PTYPE_PAYLOAD_LAYER_PAY3)
		return PKT_HASH_TYPE_L3;
	if (decoded.outer_ip == NSE_RX_PTYPE_OUTER_L2)
		return PKT_HASH_TYPE_L2;

	return PKT_HASH_TYPE_NONE;
}

/**
 * nse_rx_hash - set the hash value in the skb
 * @rx_ring: descriptor ring
 * @rx_desc: specific descriptor
 * @skb: pointer to current skb
 * @rx_ptype: the ptype value from the descriptor
 */
static void
nse_rx_hash(struct nse_ring *rx_ring, union nse_32b_rx_desc *rx_desc,
	    struct sk_buff *skb, u8 rx_ptype)
{
	struct nse_32b_rx_desc_nic *nic_mdid;
	u32 hash;

	if (!(rx_ring->netdev->features & NETIF_F_RXHASH))
		return;

	if (!nse_rx_ring_rxdid_has_rss_hash(rx_ring, rx_desc->wb.rxdid))
		return;

	/* not enqueued by RSS */
	if ((rx_desc->wb.qsrc_sport_md01valid & NSE_RXD_QSRC_M) != NSE_RXD_QSRC_RSS)
		return;

	nic_mdid = (struct nse_32b_rx_desc_nic *)rx_desc;
	hash = le32_to_cpu(nic_mdid->rss_hash);
	skb_set_hash(skb, hash, nse_ptype_to_htype(rx_ptype, rx_ring->vsi->rss_ctl));
}

#ifdef NSE_ADD_PROBES
/**
 * nse_rx_extra_counters - Update Rx csum counters
 * @vsi: the VSI we care about
 * @rx_status: status bits extracted from desc qword
 * @inner_prot: inner protocol of decoded ptype
 * @is_ipv4: if ptype is ipv4 or not
 */
static void
nse_rx_extra_counters(struct nse_vsi *vsi, u16 rx_status, u32 inner_prot,
		      bool is_ipv4)
{
	if (is_ipv4) {
		vsi->back->rx_ip4_cso++;
		if (rx_status & (BIT(NSE_RXD_STATUS0_XSUM_IPE_S) |
				 BIT(NSE_RXD_STATUS0_XSUM_EIPE_S)))
			vsi->back->rx_ip4_cso_err++;
	}

	switch (inner_prot) {
	case NSE_RX_PTYPE_INNER_PROT_TCP:
		vsi->back->rx_tcp_cso++;
		if (rx_status & BIT(NSE_RXD_STATUS0_XSUM_L4E_S))
			vsi->back->rx_tcp_cso_err++;
		break;
	case NSE_RX_PTYPE_INNER_PROT_UDP:
		vsi->back->rx_udp_cso++;
		if (rx_status & BIT(NSE_RXD_STATUS0_XSUM_L4E_S))
			vsi->back->rx_udp_cso_err++;
		break;
	case NSE_RX_PTYPE_INNER_PROT_SCTP:
		vsi->back->rx_sctp_cso++;
		if (rx_status & BIT(NSE_RXD_STATUS0_XSUM_L4E_S))
			vsi->back->rx_sctp_cso_err++;
		break;
	default:
		break;
	}
}
#endif /* NSE_ADD_PROBES */

/**
 * nse_rx_csum - Indicate in skb if checksum is good
 * @ring: the ring we care about
 * @skb: skb currently being received and modified
 * @rx_desc: the receive descriptor
 * @ptype: the packet type decoded by hardware
 *
 * skb->protocol must be set before this function is called
 */
static void
nse_rx_csum(struct nse_ring *ring, struct sk_buff *skb,
	    union nse_32b_rx_desc *rx_desc, u8 ptype)
{
	struct nse_rx_ptype_decoded decoded;
	u16 rx_status0;
	bool ipv4, ipv6;

	rx_status0 = le16_to_cpu(rx_desc->wb.status_error0);

	decoded = nse_decode_rx_desc_ptype(ptype);

	/* Start with CHECKSUM_NONE and by default csum_level = 0 */
	skb->ip_summed = CHECKSUM_NONE;
	skb_checksum_none_assert(skb);

	/* check if Rx checksum is enabled */
	if (!(ring->netdev->features & NETIF_F_RXCSUM))
		return;

	/* not a L3 IPv4/IPv6 packet */
	if (!(decoded.known && decoded.outer_ip))
		return;

	ipv4 = (decoded.outer_ip == NSE_RX_PTYPE_OUTER_IP) &&
	       (decoded.outer_ip_ver == NSE_RX_PTYPE_OUTER_IPV4);
	ipv6 = (decoded.outer_ip == NSE_RX_PTYPE_OUTER_IP) &&
	       (decoded.outer_ip_ver == NSE_RX_PTYPE_OUTER_IPV6);

#ifdef NSE_ADD_PROBES
	nse_rx_extra_counters(ring->vsi, rx_status0, decoded.inner_prot, ipv4);
#endif

	if (ipv4 && (rx_status0 & (BIT(NSE_RXD_STATUS0_XSUM_IPE_S) |
				   BIT(NSE_RXD_STATUS0_XSUM_EIPE_S))))
		goto checksum_fail;

	if (ipv6 && (rx_status0 & (BIT(NSE_RXD_STATUS0_IPV6EXADD_S))))
		goto checksum_fail;

	/* check for L4 errors and handle packets that were not able to be
	 * checksummed due to arrival speed
	 */
	if (rx_status0 & BIT(NSE_RXD_STATUS0_XSUM_L4E_S))
		goto checksum_fail;

	/* check for outer UDP checksum error in tunneled packets */
	if (rx_status0 & BIT(NSE_RXD_STATUS0_XSUM_EUDPE_S))
		goto checksum_fail;

	/* If there is an outer header present that might contain a checksum
	 * we need to bump the checksum level by 1 to reflect the fact that
	 * we are indicating we validated the inner checksum.
	 */
	if (decoded.tunnel_type >= NSE_RX_PTYPE_TUNNEL_IP_GRENAT)
		skb->csum_level = 1;

	/* Only report checksum unnecessary for TCP, UDP, or SCTP */
	switch (decoded.inner_prot) {
	case NSE_RX_PTYPE_INNER_PROT_TCP:
	case NSE_RX_PTYPE_INNER_PROT_UDP:
	case NSE_RX_PTYPE_INNER_PROT_SCTP:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		break;
	default:
		break;
	}
	ring->rx_stats.rx_csum_good++;
	return;

checksum_fail:
	ring->rx_stats.rx_csum_bad++;
}

static void nse_set_rsc_gso_size(struct nse_ring __maybe_unused *ring,
				   struct sk_buff *skb)
{
	u16 hdr_len = skb_headlen(skb);

	/* set gso_size to avoid messing up TCP MSS */
	skb_shinfo(skb)->gso_size = DIV_ROUND_UP((skb->len - hdr_len),
						 NSE_CB(skb)->append_cnt);
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
}

static void
nse_rx_rsc(struct nse_ring *rx_ring, struct sk_buff *skb)
{
	/* if append_cnt is 0 then frame is not RSC */
	if (!NSE_CB(skb)->append_cnt)
		return;

	skb->ip_summed = CHECKSUM_UNNECESSARY;

	rx_ring->rx_stats.rsc_merge_cnt += NSE_CB(skb)->append_cnt;
	rx_ring->rx_stats.rsc_flush++;

	nse_set_rsc_gso_size(rx_ring, skb);

	/* gso_size is computed using append_cnt so always clear it last */
	NSE_CB(skb)->append_cnt = 0;
}

/**
 * nse_process_skb_fields - Populate skb header fields from Rx descriptor
 * @rx_ring: Rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being populated
 * @ptype: the packet type decoded by hardware
 *
 * This function checks the ring, descriptor, and packet information in
 * order to populate the hash, checksum, VLAN, protocol, and
 * other fields within the skb.
 */
int
nse_process_skb_fields(struct nse_ring *rx_ring,
		       union nse_32b_rx_desc *rx_desc,
		       struct sk_buff *skb, u8 ptype)
{
	int ret = 0;
	int qsrc;

	qsrc = (rx_desc->wb.qsrc_sport_md01valid & NSE_RXD_QSRC_M) >> NSE_RXD_QSRC_S;
	rx_ring->rx_stats.qsrc_cnt[qsrc]++;

	nse_rx_hash(rx_ring, rx_desc, skb, ptype);

	/* modifies the skb - consumes the enet header */
#if IS_ENABLED(CONFIG_NET_DEVLINK)
	skb->protocol = eth_type_trans(skb, nse_eswitch_get_target_netdev
				       (rx_ring, rx_desc, skb));
#else
	skb->protocol = eth_type_trans(skb, rx_ring->netdev);
#endif

	nse_rx_csum(rx_ring, skb, rx_desc, ptype);

	nse_rx_rsc(rx_ring, skb);

	if (rx_ring->ptp_rx)
		nse_ptp_rx_hwtstamp(rx_ring, rx_desc, skb);

	if (!netif_is_nse(rx_ring->netdev))
		macvlan_count_rx((const struct macvlan_dev *)netdev_priv(rx_ring->netdev),
				 skb->len + ETH_HLEN, true, false);

#if defined(NSE_DEBUG_EXT)
	nse_test_suite_rss(rx_ring, rx_desc, skb, ptype);
	nse_test_suite_fdir(rx_ring, rx_desc, skb, ptype);
	nse_test_suite_rcsum(rx_ring, rx_desc, skb, ptype);
#endif

#if IS_ENABLED(CONFIG_NET_DEVLINK)
	if (nse_is_eswitch_mode_switchdev(rx_ring->pf))
		ret = nse_eswitch_restore_skb(rx_ring, rx_desc, skb);
#endif

	return ret;
}

/**
 * nse_receive_skb - Send a completed packet up the stack
 * @rx_ring: Rx ring in play
 * @skb: packet to send up
 * @vlan_tag: VLAN tag for packet
 *
 * This function sends the completed packet (via. skb) up the stack using
 * gro receive functions (with/without VLAN tag)
 */
void
nse_receive_skb(struct nse_ring *rx_ring, struct sk_buff *skb, u16 vlan_tag,
				u8 is_vlan)
{
	netdev_features_t features = rx_ring->netdev->features;

	if (is_vlan) {
#ifdef NSE_ADD_PROBES
		if ((features & NETIF_F_HW_VLAN_CTAG_RX)) {
			rx_ring->vsi->back->rx_q_vlano++;
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_tag);
		} else if ((features & NETIF_F_HW_VLAN_STAG_RX)) {
			rx_ring->vsi->back->rx_ad_vlano++;
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), vlan_tag);
		}
#else
		if ((features & NETIF_F_HW_VLAN_CTAG_RX))
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_tag);
		else if ((features & NETIF_F_HW_VLAN_STAG_RX))
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), vlan_tag);
#endif /* NSE_ADD_PROBES */
	}

	if (!nse_polling_mod)
		napi_gro_receive(&rx_ring->q_vector->napi, skb);
	else
		netif_receive_skb(skb);
}

/**
 * nse_xdp_ring_update_tail - Updates the XDP Tx ring tail register
 * @xdp_ring: XDP Tx ring
 *
 * This function updates the XDP Tx ring tail register.
 */
void nse_xdp_ring_update_tail(struct nse_ring *xdp_ring)
{
	/* don't write TAIL if in reset */
	if (nse_is_reset_in_progress(xdp_ring->pf->state))
		return;

	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.
	 */
	wmb();
	writel_relaxed(xdp_ring->next_to_use, xdp_ring->tail);
}

/* kind of like __vlan_get_protocol(), but operate on raw packet data instead of skb,
 * and we know raw packet data is linear, not skb page frags and children skb frags.
 */
static u16 nse_xmit_xdp_determine_mac_len(void *data, u16 size)
{
	u16 ret = ETH_HLEN;
	struct ethhdr *eh = data;
	struct vlan_hdr *vh = NULL;

	/* not a VLAN tagged packet */
	if (eh->h_proto != htons(ETH_P_8021Q) &&
		eh->h_proto != htons(ETH_P_8021AD)) {
		return ret;
	}

	vh = data + ETH_HLEN;

	while (ret < size) {
		ret += sizeof(struct vlan_hdr);

		if (vh->h_vlan_encapsulated_proto != htons(ETH_P_8021Q) &&
			vh->h_vlan_encapsulated_proto != htons(ETH_P_8021AD)) {
			break;
		}

		vh += 1;
	}

	/* if ret > size, then .... */
	return (ret <= size) ? ret : (ret - sizeof(struct vlan_hdr));
}

/**
 * nse_xmit_xdp_ring - submit single packet to XDP ring for transmission
 * @data: packet data pointer
 * @size: packet data size
 * @xdp_ring: XDP ring for transmission
 */
int nse_xmit_xdp_ring(void *data, u16 size, struct nse_ring *xdp_ring, bool more)
{
	u16 i = xdp_ring->next_to_use;
	struct nse_tx_desc *tx_desc;
	struct nse_tx_buf *tx_buf;
	u16 tx_rs_ntu = xdp_ring->tx_rs_ntu;
	u16 tx_rs;
	bool record_tx_rs = false;
	dma_addr_t dma;
	u64 mac_len = nse_xmit_xdp_determine_mac_len(data, size);
	u64 cmd_type_offset_bsz = 0;

	if (!unlikely(NSE_DESC_UNUSED(xdp_ring))) {
		xdp_ring->tx_stats.tx_busy++;
		return NSE_XDP_CONSUMED;
	}

	dma = dma_map_single(xdp_ring->dev, data, size, DMA_TO_DEVICE);
	if (dma_mapping_error(xdp_ring->dev, dma))
		return NSE_XDP_CONSUMED;

	tx_buf = &xdp_ring->tx_buf[i];
	tx_buf->bytecount = size;
	tx_buf->gso_segs = 1;
	tx_buf->raw_buf = data;

	/* record length, and DMA address */
	dma_unmap_len_set(tx_buf, len, size);
	dma_unmap_addr_set(tx_buf, dma, dma);

	tx_desc = NSE_TX_DESC(xdp_ring, i);
	tx_desc->buf_addr = cpu_to_le64(dma);

	cmd_type_offset_bsz |= (u64)NSE_TXD_EOP_M;

	if (nse_lan_tx_rs_optimize) {
		if (!more || NSE_DESC_UNUSED(xdp_ring) <= (xdp_ring->count >> 1)) {
			cmd_type_offset_bsz |= (u64)NSE_TXD_RS_M;

			record_tx_rs = true;
			tx_rs = i;
		}
	} else
		cmd_type_offset_bsz |= (u64)NSE_TXD_RS_M;

#if defined(NSE_DEBUG_EXT)
	if (cmd_type_offset_bsz & (u64)NSE_TXD_RS_M)
		xdp_ring->tx_stats.tx_rs++;
	else
		xdp_ring->tx_stats.tx_no_rs++;
#endif

	tx_desc->cmd_type_offset_bsz = nse_build_ctob(xdp_ring, cmd_type_offset_bsz,
						      (u64)size, size, true);

	tx_desc->cmd_type_offset_bsz |= cpu_to_le64((((mac_len >> 1) << NSE_TXD_MACLEN_S) & NSE_TXD_MACLEN_M));

	/* Make certain all of the status bits have been updated
	 * before next_to_watch is written.
	 */
	wmb();

	xdp_ring->xdp_tx_active++;
	i++;
	if (i == xdp_ring->count)
		i = 0;

	tx_buf->next_to_watch = tx_desc;
	xdp_ring->next_to_use = i;

	if (nse_lan_tx_rs_optimize && record_tx_rs) {
		xdp_ring->tx_rs_array[tx_rs_ntu] = tx_rs;

		tx_rs_ntu++;
		if (tx_rs_ntu == xdp_ring->count)
			tx_rs_ntu = 0;

		xdp_ring->tx_rs_ntu = tx_rs_ntu;
	}

	return NSE_XDP_TX;
}

/**
 * nse_xmit_xdp_buff - convert an XDP buffer to an XDP frame and send it
 * @xdp: XDP buffer
 * @xdp_ring: XDP Tx ring
 *
 * Returns negative on failure, 0 on success.
 */
int nse_xmit_xdp_buff(struct xdp_buff *xdp, struct nse_ring *xdp_ring)
{
	struct xdp_frame *xdpf = xdp_convert_buff_to_frame(xdp);

	if (unlikely(!xdpf))
		return NSE_XDP_CONSUMED;

	return nse_xmit_xdp_ring(xdpf->data, xdpf->len, xdp_ring, false);
}

/**
 * nse_finalize_xdp_rx - Bump XDP Tx tail and/or flush redirect map
 * @rx_ring: Rx ring
 * @xdp_res: Result of the receive batch
 *
 * This function bumps XDP Tx tail and/or flush redirect map, and
 * should be called when a batch of packets has been processed in the
 * napi loop.
 */
void nse_finalize_xdp_rx(struct nse_ring *rx_ring, unsigned int xdp_res)
{
	if (xdp_res & NSE_XDP_REDIR)
		xdp_do_flush();

	if (xdp_res & NSE_XDP_TX) {
		struct nse_ring *xdp_ring =
			rx_ring->vsi->xdp_rings[rx_ring->q_index];

		nse_xdp_ring_update_tail(xdp_ring);
	}
}

void nse_dump_rx_desc(struct device *dev, u16 q_idx, u16 desc_idx, union nse_32b_rx_desc *rx_desc)
{
	u16 val;
	u32 *raw_val32_ptr;
	int i;

	if (q_idx != NSE_INVAL_Q_INDEX && desc_idx < NSE_MAX_NUM_DESC)
		dev_info(dev, "------ rx_desc[q_idx=%d][desc_idx=%d]\n", q_idx, desc_idx);
	else if (q_idx != NSE_INVAL_Q_INDEX)
		dev_info(dev, "------ rx_desc[q_idx=%d][desc_idx=N]\n", q_idx);
	else if (desc_idx < NSE_MAX_NUM_DESC)
		dev_info(dev, "------ rx_desc[q_idx=N][desc_idx=%d]\n", desc_idx);
	else
		dev_info(dev, "------ rx_desc\n");

	dev_info(dev, "raw content:\n");
	raw_val32_ptr = (u32 *)rx_desc;
	for (i = 0; i < (sizeof(*rx_desc) / sizeof(u32)); i++) {
		dev_info(dev, "\t %08X\n", *raw_val32_ptr);
		raw_val32_ptr++;
	}

	if (!(rx_desc->wb.status_error0 & cpu_to_le16(NSE_RXD_STATUS0_DD_M))) {
		dev_info(dev, "DD = false\n");
		dev_info(dev, "pkt_addr = %lX\n",
			 (unsigned long)le64_to_cpu(rx_desc->read.pkt_addr));
	} else {
		dev_info(dev, "DD = true\n");

		dev_info(dev, "rxdid = %X\n", rx_desc->wb.rxdid);

		dev_info(dev, "qsrc_sport_md01valid = %X\n", rx_desc->wb.qsrc_sport_md01valid);
		dev_info(dev, "\t qsrc = %X\n",
			 (rx_desc->wb.qsrc_sport_md01valid & NSE_RXD_QSRC_M));
		dev_info(dev, "\t sport = %X\n",
			 (rx_desc->wb.qsrc_sport_md01valid & NSE_RXD_SPORT_M) >> NSE_RXD_SPORT_S);
		dev_info(dev, "\t md0_valid = %X\n",
			 !!(rx_desc->wb.qsrc_sport_md01valid & NSE_RXD_MD0_VALID_M));
		dev_info(dev, "\t md1_valid = %X\n",
			 !!(rx_desc->wb.qsrc_sport_md01valid & NSE_RXD_MD1_VALID_M));

		dev_info(dev, "l2tag1_nextp = %X\n", le16_to_cpu(rx_desc->wb.l2tag1_nextp));

		dev_info(dev, "md0 = %X\n", le16_to_cpu(rx_desc->wb.md0));

		dev_info(dev, "md1 = %X\n", le16_to_cpu(rx_desc->wb.md1));

		val = le16_to_cpu(rx_desc->wb.status_error0);
		dev_info(dev, "status_error0 = %X\n", val);
		dev_info(dev, "\t DD = %X\n", !!(val & NSE_RXD_STATUS0_DD_M));
		dev_info(dev, "\t EOP = %X\n", !!(val & NSE_RXD_STATUS0_EOP_M));
		dev_info(dev, "\t HBO = %X\n", !!(val & NSE_RXD_STATUS0_HBO_M));
		dev_info(dev, "\t EIPV6EX = %X\n", !!(val & NSE_RXD_STATUS0_EIPV6EX_M));
		dev_info(dev, "\t XSUM_IPE = %X\n", !!(val & NSE_RXD_STATUS0_XSUM_IPE_M));
		dev_info(dev, "\t XSUM_L4E = %X\n", !!(val & NSE_RXD_STATUS0_XSUM_L4E_M));
		dev_info(dev, "\t XSUM_EIPE = %X\n", !!(val & NSE_RXD_STATUS0_XSUM_EIPE_M));
		dev_info(dev, "\t XSUM_EUDPE = %X\n", !!(val & NSE_RXD_STATUS0_XSUM_EUDPE_M));
		dev_info(dev, "\t MIRR = %X\n", !!(val & NSE_RXD_STATUS0_MIRR_M));
		dev_info(dev, "\t IPV6EXADD = %X\n", !!(val & NSE_RXD_STATUS0_IPV6EXADD_M));
		dev_info(dev, "\t RXE = %X\n", !!(val & NSE_RXD_STATUS0_RXE_M));
		dev_info(dev, "\t CRCP = %X\n", !!(val & NSE_RXD_STATUS0_CRCP_M));
		dev_info(dev, "\t PTP = %X\n", !!(val & NSE_RXD_STATUS0_PTP_M));
		dev_info(dev, "\t L2TAG1P = %X\n", !!(val & NSE_RXD_STATUS0_L2TAG1P_M));
		dev_info(dev, "\t EXT_UDP_0 = %X\n", !!(val & NSE_RXD_STATUS0_EXT_UDP_0_M));
		dev_info(dev, "\t INT_UDP_0 = %X\n", !!(val & NSE_RXD_STATUS0_INT_UDP_0_M));

		dev_info(dev, "ptype = %X\n", rx_desc->wb.ptype);

		dev_info(dev, "misc = %X\n", rx_desc->wb.misc);

		val = le16_to_cpu(rx_desc->wb.pktlen_sph_reentry);
		dev_info(dev, "pktlen_sph_reentry = %X\n", val);
		dev_info(dev, "\t pktlen = %X(%d)\n",
			 (val & NSE_RXD_PKT_LEN_M), (val & NSE_RXD_PKT_LEN_M));
		dev_info(dev, "\t sph = %X\n", !!(val & NSE_RXD_SPH_M));
		dev_info(dev, "\t reentry = %X\n", !!(val & NSE_RXD_REENTRY_M));

		val = le16_to_cpu(rx_desc->wb.hdrlen_rsccnt);
		dev_info(dev, "hdrlen_rsccnt = %X\n", val);
		dev_info(dev, "\t hdrlen = %X(%d)\n",
			 (val & NSE_RXD_HDR_LEN_M), (val & NSE_RXD_HDR_LEN_M));
		dev_info(dev, "\t rsccnt = %X(%d)\n", (val & NSE_RXD_RSCCNT_M) >>
			 NSE_RXD_RSCCNT_S, (val & NSE_RXD_RSCCNT_M) >> NSE_RXD_RSCCNT_S);

		dev_info(dev, "status_error1 = %X\n", rx_desc->wb.status_error1);
		dev_info(dev, "\t V6M = %X\n",
			 !!(rx_desc->wb.status_error1 & NSE_RXD_STATUS1_V6M_M));
		dev_info(dev, "\t TLS = %X\n",
			 !!(rx_desc->wb.status_error1 & NSE_RXD_STATUS1_TLS_M));
		dev_info(dev, "\t L2TAG2P = %X\n",
			 !!(rx_desc->wb.status_error1 & NSE_RXD_STATUS1_L2TAG2P_M));
		dev_info(dev, "\t MD2_VALID = %X\n",
			 !!(rx_desc->wb.status_error1 & NSE_RXD_STATUS1_MD2_VALID_M));
		dev_info(dev, "\t MD3_VALID = %X\n",
			 !!(rx_desc->wb.status_error1 & NSE_RXD_STATUS1_MD3_VALID_M));
		dev_info(dev, "\t MD4_VALID = %X\n",
			 !!(rx_desc->wb.status_error1 & NSE_RXD_STATUS1_MD4_VALID_M));
		dev_info(dev, "\t MD5_VALID = %X\n",
			 !!(rx_desc->wb.status_error1 & NSE_RXD_STATUS1_MD5_VALID_M));
		dev_info(dev, "\t MD6_VALID = %X\n",
			 !!(rx_desc->wb.status_error1 & NSE_RXD_STATUS1_MD6_VALID_M));

		dev_info(dev, "ts_low = %X\n", rx_desc->wb.ts_low);

		dev_info(dev, "md6 = %X\n", le16_to_cpu(rx_desc->wb.md6));

		dev_info(dev, "l2tag2_1st = %X\n", le16_to_cpu(rx_desc->wb.l2tag2_1st));

		dev_info(dev, "l2tag2_2nd = %X\n", le16_to_cpu(rx_desc->wb.l2tag2_2nd));

		dev_info(dev, "md2 = %X\n", le16_to_cpu(rx_desc->wb.md2));

		dev_info(dev, "md3 = %X\n", le16_to_cpu(rx_desc->wb.md3));

		dev_info(dev, "md4 = %X\n", le16_to_cpu(rx_desc->wb.md4));

		dev_info(dev, "md5 = %X\n", le16_to_cpu(rx_desc->wb.md5));
	}
}

void nse_dump_tx_desc(struct device *dev, u16 q_idx, u16 desc_idx, struct nse_tx_desc *tx_desc)
{
	struct nse_tx_ctx_desc *cd = NULL;
	u16 val16;
	u32 val32;
	u64 val64;
	u32 *raw_val32_ptr;
	int i;
	char *desc_type = NULL;

	if (tx_desc->cmd_type_offset_bsz & cpu_to_le64(NSE_TXD_DD_M))
		desc_type = "write-back";
	else if (tx_desc->cmd_type_offset_bsz & cpu_to_le64(NSE_TXD_DTYPE_M))
		desc_type = "tx-context-desc";
	else
		desc_type = "tx-data-desc";

	if (q_idx != NSE_INVAL_Q_INDEX && desc_idx < NSE_MAX_NUM_DESC)
		dev_info(dev, "------ tx_desc[q_idx=%d][desc_idx=%d]: %s\n",
			 q_idx, desc_idx, desc_type);
	else if (q_idx != NSE_INVAL_Q_INDEX)
		dev_info(dev, "------ tx_desc[q_idx=%d][desc_idx=N]: %s\n", q_idx, desc_type);
	else if (desc_idx < NSE_MAX_NUM_DESC)
		dev_info(dev, "------ tx_desc[q_idx=N][desc_idx=%d]: %s\n", desc_idx, desc_type);
	else
		dev_info(dev, "------ tx_desc: %s\n", desc_type);

	dev_info(dev, "raw content:\n");
	raw_val32_ptr = (u32 *)tx_desc;
	for (i = 0; i < (sizeof(*tx_desc) / sizeof(u32)); i++) {
		dev_info(dev, "\t %08X\n", *raw_val32_ptr);
		raw_val32_ptr++;
	}

	if (tx_desc->cmd_type_offset_bsz & cpu_to_le64(NSE_TXD_DD_M)) {
		dev_info(dev, "DD = true\n");

		dev_info(dev, "buf_addr = %lX\n", (unsigned long)le64_to_cpu(tx_desc->buf_addr));
		dev_info(dev, "cmd_type_offset_bsz = %lX\n",
			 (unsigned long)le64_to_cpu(tx_desc->cmd_type_offset_bsz));
	} else {
		dev_info(dev, "DD = false\n");

		if (tx_desc->cmd_type_offset_bsz & cpu_to_le64(NSE_TXD_DTYPE_M)) {
			cd = (struct nse_tx_ctx_desc *)tx_desc;

			val32 = le32_to_cpu(cd->tunneling_params);
			dev_info(dev, "tunneling_params = %X\n", val32);
			dev_info(dev, "\t EIPT: %X\n",
				 (unsigned int)((val32 & NSE_TXD_CTX_EIPT_M) >>
						NSE_TXD_CTX_EIPT_S));
			dev_info(dev, "\t EIPLEN: %X\n",
				 (unsigned int)((val32 & NSE_TXD_CTX_EIPLEN_M) >>
						NSE_TXD_CTX_EIPLEN_S));
			dev_info(dev, "\t L4TUNT: %X\n",
				 (unsigned int)((val32 & NSE_TXD_CTX_L4TUNT_M) >>
						NSE_TXD_CTX_L4TUNT_S));
			dev_info(dev, "\t L4TUNLEN: %X\n",
				 (unsigned int)((val32 & NSE_TXD_CTX_L4TUNLEN_M) >>
						NSE_TXD_CTX_L4TUNLEN_S));
			dev_info(dev, "\t DECTTL: %X\n",
				 (unsigned int)((val32 & NSE_TXD_CTX_DECTTL_M) >>
						NSE_TXD_CTX_DECTTL_S));
			dev_info(dev, "\t L4T_CS: %X\n",
				 (unsigned int)((val32 & NSE_TXD_CTX_L4T_CS_M) >>
						NSE_TXD_CTX_L4T_CS_S));

			dev_info(dev, "l2tag2 = %X\n", le16_to_cpu(cd->l2tag2));

			val16 = le16_to_cpu(cd->control);
			dev_info(dev, "control = %X\n", val16);
			dev_info(dev, "\t TSEC: %X\n",
				 (unsigned int)((val16 & NSE_TXD_CTX_TSEC_M) >>
						NSE_TXD_CTX_TSEC_S));
			dev_info(dev, "\t PORTID: %X\n",
				 (unsigned int)((val16 & NSE_TXD_CTX_PORTID_M) >>
						NSE_TXD_CTX_PORTID_S));
			dev_info(dev, "\t CRCP: %X\n",
				 (unsigned int)((val16 & NSE_TXD_CTX_CRCP_M) >>
						NSE_TXD_CTX_CRCP_S));
			dev_info(dev, "\t TLS: %X\n",
				 (unsigned int)((val16 & NSE_TXD_CTX_TLS_M) >> NSE_TXD_CTX_TLS_S));
			dev_info(dev, "\t TX_MD: %X\n",
				 (unsigned int)((val16 & NSE_TXD_CTX_TX_MD_M) >>
						NSE_TXD_CTX_TX_MD_S));
			dev_info(dev, "\t TSYN_REG: %X\n",
				 (unsigned int)((val16 & NSE_TXD_CTX_TSYN_REG_M) >>
						NSE_TXD_CTX_TSYN_REG_S));

			val64 = le64_to_cpu(cd->qw1);
			dev_info(dev, "qw1 = %lX\n", (unsigned long)val64);
			dev_info(dev, "\t PORT_VLD: %X\n",
				 (unsigned int)((val64 & NSE_TXQ_CTX_PORT_VLD_M) >>
						NSE_TXQ_CTX_PORT_VLD_S));
			dev_info(dev, "\t PORT_LOCK: %X\n",
				 (unsigned int)((val64 & NSE_TXQ_CTX_PORT_LOCK_M) >>
						NSE_TXQ_CTX_PORT_LOCK_S));
			dev_info(dev, "\t TSO: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_TSO_M) >> NSE_TXD_CTX_TSO_S));
			dev_info(dev, "\t TSYN: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_TSYN_M) >>
						NSE_TXD_CTX_TSYN_S));
			dev_info(dev, "\t IL2TAG2: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_IL2TAG2_M) >>
						NSE_TXD_CTX_IL2TAG2_S));
			dev_info(dev, "\t IL2TAG_IL2H: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_IL2TAG_IL2H_M) >>
						NSE_TXD_CTX_IL2TAG_IL2H_S));
			dev_info(dev, "\t SWITCH: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_SWITCH_M) >>
						NSE_TXD_CTX_SWITCH_S));
			dev_info(dev, "\t DEST_QUEUE_VLD: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_DEST_QUEUE_VLD_M) >>
						NSE_TXD_CTX_DEST_QUEUE_VLD_S));
			dev_info(dev, "\t DEST_QUEUE: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_DEST_QUEUE_M) >>
						NSE_TXD_CTX_DEST_QUEUE_S));
			dev_info(dev, "\t DEST_VSI: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_DEST_VSI_M) >>
						NSE_TXD_CTX_DEST_VSI_S));
			dev_info(dev, "\t L2TAG1: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_L2TAG1_M) >>
						NSE_TXD_CTX_L2TAG1_S));
			dev_info(dev, "\t IL2TAG1: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_IL2TAG1_M) >>
						NSE_TXD_CTX_IL2TAG1_S));
			dev_info(dev, "\t MSS: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_MSS_M) >> NSE_TXD_CTX_MSS_S));
		} else {
			dev_info(dev, "buf_addr = %lX\n",
				 (unsigned long)le64_to_cpu(tx_desc->buf_addr));

			val64 = le64_to_cpu(tx_desc->cmd_type_offset_bsz);
			dev_info(dev, "cmd_type_offset_bsz = %lX\n", (unsigned long)val64);
			dev_info(dev, "\t L4TYPE: %X\n",
				 (unsigned int)((val64 & NSE_TXD_L4TYPE_M) >> NSE_TXD_L4TYPE_S));
			dev_info(dev, "\t IIPT: %X\n",
				 (unsigned int)((val64 & NSE_TXD_IIPT_M) >> NSE_TXD_IIPT_S));
			dev_info(dev, "\t L4LEN: %X\n",
				 (unsigned int)((val64 & NSE_TXD_L4LEN_M) >> NSE_TXD_L4LEN_S));
			dev_info(dev, "\t EOP: %X\n",
				 (unsigned int)((val64 & NSE_TXD_EOP_M) >> NSE_TXD_EOP_S));
			dev_info(dev, "\t RS: %X\n",
				 (unsigned int)((val64 & NSE_TXD_RS_M) >> NSE_TXD_RS_S));
			dev_info(dev, "\t L4CSUM: %X\n",
				 (unsigned int)((val64 & NSE_TXD_L4CSUM_M) >> NSE_TXD_L4CSUM_S));
			dev_info(dev, "\t RSV_1: %X\n",
				 (unsigned int)((val64 & NSE_TXD_RSV_1_M) >> NSE_TXD_RSV_1_S));
			dev_info(dev, "\t LOCAL_DATA: %X\n",
				 (unsigned int)((val64 & NSE_TXD_LOCAL_DATA_M) >>
						NSE_TXD_LOCAL_DATA_S));
			dev_info(dev, "\t CC: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CC_M) >> NSE_TXD_CC_S));
			dev_info(dev, "\t TLEN: %X\n",
				 (unsigned int)((val64 & NSE_TXD_TLEN_M) >> NSE_TXD_TLEN_S));
			dev_info(dev, "\t MACLEN: %X\n",
				 (unsigned int)((val64 & NSE_TXD_MACLEN_M) >> NSE_TXD_MACLEN_S));
			dev_info(dev, "\t IPLEN: %X\n",
				 (unsigned int)((val64 & NSE_TXD_IPLEN_M) >> NSE_TXD_IPLEN_S));
			dev_info(dev, "\t RSV_2: %X\n",
				 (unsigned int)((val64 & NSE_TXD_RSV_2_M) >> NSE_TXD_RSV_2_S));
			dev_info(dev, "\t BSIZE: %X\n",
				 (unsigned int)((val64 & NSE_TXD_BSIZE_M) >> NSE_TXD_BSIZE_S));
		}
	}
}

void nse_dump_lan_txcq_desc(struct device *dev, u16 q_idx, u32 desc_idx,
			    struct nse_lan_txcq_desc *desc)
{
	u32 val32 = le32_to_cpu(desc->data);

	if (q_idx != NSE_INVAL_Q_INDEX && desc_idx < NSE_DFLT_NUM_CQ_DESC)
		dev_info(dev, "------ cq_desc[q_idx=%d][desc_idx=%d]\n", q_idx, desc_idx);
	else if (q_idx != NSE_INVAL_Q_INDEX)
		dev_info(dev, "------ cq_desc[q_idx=%d][desc_idx=N]\n", q_idx);
	else if (desc_idx < NSE_DFLT_NUM_CQ_DESC)
		dev_info(dev, "------ cq_desc[q_idx=N][desc_idx=%d]\n", desc_idx);
	else
		dev_info(dev, "------ cq_desc\n");

	dev_info(dev, "raw content:\n");
	dev_info(dev, "\t %08X\n", val32);

	dev_info(dev, "TXQ_ID: %d\n", (val32 & NSE_LAN_TXCQD_TXQ_ID_M) >> NSE_LAN_TXCQD_TXQ_ID_S);
	dev_info(dev, "GENERATION: %d\n", (u32)((val32 & NSE_LAN_TXCQD_GENERATION_M) >>
		 NSE_LAN_TXCQD_GENERATION_S));
	dev_info(dev, "TX_HEAD: %d\n", (val32 & NSE_LAN_TXCQD_TX_HEAD_M) >>
		 NSE_LAN_TXCQD_TX_HEAD_S);
	dev_info(dev, "COMPLETION_TYPE: %d\n", (val32 & NSE_LAN_TXCQD_COMPLETION_TYPE_M) >>
		 NSE_LAN_TXCQD_COMPLETION_TYPE_S);
}

const struct nse_rx_ptype_decoded nse_ptype_lkup[256] = {
	NSE_PTT_UNUSED_ENTRY(16),
	NSE_PTT(17, L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY2),
	NSE_PTT(18, L2, NONE, NOF, NONE, NONE, NOF, NONE, NONE),
	NSE_PTT(19, L2, NONE, NOF, NONE, NONE, NOF, NONE, NONE),
	NSE_PTT(20, L2, NONE, NOF, NONE, NONE, NOF, NONE, NONE),
	NSE_PTT(21, L2, NONE, NOF, NONE, NONE, NOF, NONE, NONE),
	NSE_PTT(22, L2, NONE, NOF, NONE, NONE, NOF, NONE, NONE),
	NSE_PTT(23, L2, NONE, NOF, NONE, NONE, NOF, NONE, NONE),

	NSE_PTT_UNUSED_ENTRY(32),

	NSE_PTT(33, IP, IPV4, FRG, NONE, NONE, NOF, NONE, PAY3),
	NSE_PTT(34, IP, IPV4, NOF, NONE, NONE, NOF, NONE, PAY3),
	NSE_PTT(35, IP, IPV4, NOF, NONE, NONE, NOF, UDP,  PAY4),
	NSE_PTT(36, IP, IPV4, NOF, NONE, NONE, NOF, TCP,  PAY4),
	NSE_PTT(37, IP, IPV4, NOF, NONE, NONE, NOF, SCTP,  PAY4),
	NSE_PTT(38, IP, IPV4, NOF, NONE, NONE, NOF, ICMP,  PAY4),

	NSE_PTT_UNUSED_ENTRY(39),
	NSE_PTT_UNUSED_ENTRY(40),

	NSE_PTT(41, IP, IPV6, FRG, NONE, NONE, NOF, NONE, PAY3),
	NSE_PTT(42, IP, IPV6, NOF, NONE, NONE, NOF, NONE, PAY3),
	NSE_PTT(43, IP, IPV6, NOF, NONE, NONE, NOF, UDP,  PAY4),
	NSE_PTT(44, IP, IPV6, NOF, NONE, NONE, NOF, TCP,  PAY4),
	NSE_PTT(45, IP, IPV6, NOF, NONE, NONE, NOF, SCTP,  PAY4),
	NSE_PTT(46, IP, IPV6, NOF, NONE, NONE, NOF, ICMP,  PAY4),

	NSE_PTT_UNUSED_ENTRY(47),

	NSE_PTT(128, IP, IPV4, NOF, NONE, NONE, NOF, NONE, PAY2),

	NSE_PTT(129, IP, IPV4, NOF, IP_IP, IPV4, FRG, NONE, PAY3),
	NSE_PTT(130, IP, IPV4, NOF, IP_IP, IPV4, NOF, NONE, PAY3),
	NSE_PTT(131, IP, IPV4, NOF, IP_IP, IPV4, NOF, UDP, PAY4),
	NSE_PTT(132, IP, IPV4, NOF, IP_IP, IPV4, NOF, TCP, PAY4),
	NSE_PTT(133, IP, IPV4, NOF, IP_IP, IPV4, NOF, SCTP, PAY4),
	NSE_PTT(134, IP, IPV4, NOF, IP_IP, IPV4, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(135),
	NSE_PTT_UNUSED_ENTRY(136),

	NSE_PTT(137, IP, IPV4, NOF, IP_IP, IPV6, FRG, NONE, PAY3),
	NSE_PTT(138, IP, IPV4, NOF, IP_IP, IPV6, NOF, NONE, PAY3),
	NSE_PTT(139, IP, IPV4, NOF, IP_IP, IPV6, NOF, UDP, PAY4),
	NSE_PTT(140, IP, IPV4, NOF, IP_IP, IPV6, NOF, TCP, PAY4),
	NSE_PTT(141, IP, IPV4, NOF, IP_IP, IPV6, NOF, SCTP, PAY4),
	NSE_PTT(142, IP, IPV4, NOF, IP_IP, IPV6, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(143),

	NSE_PTT(144, IP, IPV4, NOF, IP_GRENAT, NONE, NOF, NONE, PAY2),

	NSE_PTT(145, IP, IPV4, NOF, IP_GRENAT, IPV4, FRG, NONE, PAY3),
	NSE_PTT(146, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, NONE, PAY3),
	NSE_PTT(147, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, UDP, PAY4),
	NSE_PTT(148, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, TCP, PAY4),
	NSE_PTT(149, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, SCTP, PAY4),
	NSE_PTT(150, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(151),
	NSE_PTT_UNUSED_ENTRY(152),

	NSE_PTT(153, IP, IPV4, NOF, IP_GRENAT, IPV6, FRG, NONE, PAY3),
	NSE_PTT(154, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, NONE, PAY3),
	NSE_PTT(155, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, UDP, PAY4),
	NSE_PTT(156, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, TCP, PAY4),
	NSE_PTT(157, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, SCTP, PAY4),
	NSE_PTT(158, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(159),

	NSE_PTT(160, IP, IPV4, NOF, IP_GRENAT_MAC, NONE, NOF, NONE, PAY2),

	NSE_PTT(161, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, FRG, NONE, PAY3),
	NSE_PTT(162, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, NONE, PAY3),
	NSE_PTT(163, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, UDP, PAY4),
	NSE_PTT(164, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, TCP, PAY4),
	NSE_PTT(165, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, SCTP, PAY4),
	NSE_PTT(166, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(167),
	NSE_PTT_UNUSED_ENTRY(168),

	NSE_PTT(169, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, FRG, NONE, PAY3),
	NSE_PTT(170, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, NONE, PAY3),
	NSE_PTT(171, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, UDP, PAY4),
	NSE_PTT(172, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, TCP, PAY4),
	NSE_PTT(173, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, SCTP, PAY4),
	NSE_PTT(174, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(175),

	NSE_PTT(192, IP, IPV6, NOF, NONE, NONE, NOF, NONE, PAY2),

	NSE_PTT(193, IP, IPV6, NOF, IP_IP, IPV4, FRG, NONE, PAY4),
	NSE_PTT(194, IP, IPV6, NOF, IP_IP, IPV4, NOF, NONE, PAY4),
	NSE_PTT(195, IP, IPV6, NOF, IP_IP, IPV4, NOF, UDP, PAY4),
	NSE_PTT(196, IP, IPV6, NOF, IP_IP, IPV4, NOF, TCP, PAY4),
	NSE_PTT(197, IP, IPV6, NOF, IP_IP, IPV4, NOF, SCTP, PAY4),
	NSE_PTT(198, IP, IPV6, NOF, IP_IP, IPV4, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(199),
	NSE_PTT_UNUSED_ENTRY(200),

	NSE_PTT(201, IP, IPV6, NOF, IP_IP, IPV6, FRG, NONE, PAY3),
	NSE_PTT(202, IP, IPV6, NOF, IP_IP, IPV6, NOF, NONE, PAY3),
	NSE_PTT(203, IP, IPV6, NOF, IP_IP, IPV6, NOF, UDP, PAY4),
	NSE_PTT(204, IP, IPV6, NOF, IP_IP, IPV6, NOF, TCP, PAY4),
	NSE_PTT(205, IP, IPV6, NOF, IP_IP, IPV6, NOF, SCTP, PAY4),
	NSE_PTT(206, IP, IPV6, NOF, IP_IP, IPV6, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(207),

	NSE_PTT(208, IP, IPV6, NOF, IP_GRENAT, NONE, NOF, NONE, PAY2),

	NSE_PTT(209, IP, IPV6, NOF, IP_GRENAT, IPV4, FRG, NONE, PAY3),
	NSE_PTT(210, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, NONE, PAY3),
	NSE_PTT(211, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, UDP, PAY4),
	NSE_PTT(212, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, TCP, PAY4),
	NSE_PTT(213, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, SCTP, PAY4),
	NSE_PTT(214, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(215),
	NSE_PTT_UNUSED_ENTRY(216),

	NSE_PTT(217, IP, IPV6, NOF, IP_GRENAT, IPV6, FRG, NONE, PAY3),
	NSE_PTT(218, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, NONE, PAY3),
	NSE_PTT(219, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, UDP, PAY4),
	NSE_PTT(220, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, TCP, PAY4),
	NSE_PTT(221, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, SCTP, PAY4),
	NSE_PTT(222, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(223),

	NSE_PTT(224, IP, IPV6, NOF, IP_GRENAT_MAC, NONE, NOF, NONE, PAY2),

	NSE_PTT(225, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, FRG, NONE, PAY3),
	NSE_PTT(226, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, NONE, PAY3),
	NSE_PTT(227, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, UDP, PAY4),
	NSE_PTT(228, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, TCP, PAY4),
	NSE_PTT(229, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, SCTP, PAY4),
	NSE_PTT(230, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(231),
	NSE_PTT_UNUSED_ENTRY(232),

	NSE_PTT(233, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, FRG, NONE, PAY3),
	NSE_PTT(234, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, NONE, PAY3),
	NSE_PTT(235, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, UDP, PAY4),
	NSE_PTT(236, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, TCP, PAY4),
	NSE_PTT(237, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, SCTP, PAY4),
	NSE_PTT(238, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(239),

	[240 ... 255] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

