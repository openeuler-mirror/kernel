// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include <net/gre.h>
#include <net/vxlan.h>
#include <net/mpls.h>
#include <linux/mpls.h>

#include "nse_txrx_lib.h"
#include "nse_eswitch.h"

#if defined(NSE_DEBUG_EXT)

void locate_final_l3_l4_hdr(struct sk_buff *skb,
		void **ret_l4_hdr,	/* tcp or udp */
		void **ret_l3_hdr,
		void **ret_1st_vlan_hdr,
		u16 *l3_proto,
		u8 *l4_proto);

void
nse_test_suite_rss(struct nse_ring *rx_ring, union nse_32b_rx_desc *rx_desc,
		   struct sk_buff *skb, u8 rx_ptype)
{
	struct nse_vsi *vsi = rx_ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_32b_rx_desc_nic *nic_mdid;
	struct nse_rx_ptype_decoded decoded = nse_decode_rx_desc_ptype(rx_ptype);
	u32 hash;
	struct tcphdr *tcph = NULL;
	void *l3_hdr = NULL;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	u16 l3_proto;
	u8 l4_proto;

	if (!pf->test_rss)
		return;

	locate_final_l3_l4_hdr(skb, (void **)&tcph, &l3_hdr, NULL, &l3_proto, &l4_proto);

	if (!tcph)
		return;

	if (l3_proto == ETH_P_IP)
		iph = (struct iphdr *)l3_hdr;
	else if (l3_proto == ETH_P_IPV6)
		ip6h = (struct ipv6hdr *)l3_hdr;
	else
		return;

	if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP)
		return;

	/* check based on TCP port.
	 *
	 * defined in <<82599 datasheet>> / 7.1.2.8.3 RSS Verification Suite
	 */
	if (tcph->dest != cpu_to_be16(1766) &&
		tcph->dest != cpu_to_be16(2794) &&
		tcph->dest != cpu_to_be16(4739) &&
		tcph->dest != cpu_to_be16(14230) &&
		tcph->dest != cpu_to_be16(38024) &&
		tcph->dest != cpu_to_be16(12898) &&
		tcph->dest != cpu_to_be16(2217) &&
		tcph->dest != cpu_to_be16(48228) &&
		tcph->dest != cpu_to_be16(1303) &&
		tcph->dest != cpu_to_be16(44251)) {
		return;	/* not test suite packet */
	}

	nse_printk("=== receiving a RSS test suite packet\n");

	if (iph) {
		nse_printk("IPv4 TCP: %pI4:%d -> %pI4:%d\n",
						&iph->saddr, be16_to_cpu(tcph->source),
							&iph->daddr, be16_to_cpu(tcph->dest));
	} else {
		nse_printk("IPv6 TCP: %pI6:%d -> %pI6:%d\n",
						&ip6h->saddr, be16_to_cpu(tcph->source),
							&ip6h->daddr, be16_to_cpu(tcph->dest));
	}

	nse_printk("RPSR ptype: 0x%X (%d) --- decode: payload_layer=%d, inner_prot=%d\n",
					rx_ptype, rx_ptype,
					decoded.payload_layer, decoded.inner_prot);
	if (decoded.payload_layer != NSE_RX_PTYPE_PAYLOAD_LAYER_PAY4 ||
		decoded.inner_prot != NSE_RX_PTYPE_INNER_PROT_TCP) {
		nse_printk("--- !!! BAD: how come it is not identified as TCP?\n");
	}

	if (!nse_rx_ring_rxdid_has_rss_hash(rx_ring, rx_desc->wb.rxdid)) {
		nse_printk("--- !!! BAD: howcome RXDID does not have RSS hash?\n");
		/* still print RSS field in rx-desc */
	}

	nic_mdid = (struct nse_32b_rx_desc_nic *)rx_desc;
	hash = le32_to_cpu(nic_mdid->rss_hash);

	nse_printk("RX-desc RXDID=%d, rss_hash(MD.0, MD.1) = %x\n",
		   rx_desc->wb.rxdid, nic_mdid->rss_hash);
	nse_printk("skb->hash = %x, enqueue to RXQ: %d\n", skb_get_hash_raw(skb), rx_ring->q_index);
}

void
nse_test_suite_fdir(struct nse_ring *rx_ring, union nse_32b_rx_desc *rx_desc,
		    struct sk_buff *skb, u8 rx_ptype)
{
	struct nse_vsi *vsi = rx_ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_32b_rx_desc_nic *nic_mdid;
	struct nse_rx_ptype_decoded decoded = nse_decode_rx_desc_ptype(rx_ptype);
	u16 hash, flow_id;
	struct tcphdr *tcph = NULL;
	void *l3_hdr = NULL;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	u16 l3_proto;
	u8 l4_proto;

	if (!pf->test_fdir)
		return;

	/* not enqueued by RSS */
	if ((rx_desc->wb.qsrc_sport_md01valid & NSE_RXD_QSRC_M) != NSE_RXD_QSRC_FD)
		return;

	locate_final_l3_l4_hdr(skb, (void **)&tcph, &l3_hdr, NULL, &l3_proto, &l4_proto);

	if (!tcph)
		return;

	if (l3_proto == ETH_P_IP)
		iph = (struct iphdr *)l3_hdr;
	else if (l3_proto == ETH_P_IPV6)
		ip6h = (struct ipv6hdr *)l3_hdr;
	else
		return;

	if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP)
		return;

	nse_printk("=== receiving a FDir test suite packet\n");

	if (iph) {
		nse_printk("IPv4 TCP: %pI4:%d -> %pI4:%d\n",
						&iph->saddr, be16_to_cpu(tcph->source),
							&iph->daddr, be16_to_cpu(tcph->dest));
	} else {
		nse_printk("IPv6 TCP: %pI6:%d -> %pI6:%d\n",
						&ip6h->saddr, be16_to_cpu(tcph->source),
							&ip6h->daddr, be16_to_cpu(tcph->dest));
	}

	nse_printk("RPSR ptype: 0x%X (%d) --- decode: payload_layer=%d, inner_prot=%d\n",
					rx_ptype, rx_ptype,
					decoded.payload_layer, decoded.inner_prot);

	nic_mdid = (struct nse_32b_rx_desc_nic *)rx_desc;

	hash = le16_to_cpu(nic_mdid->fdir_hash_result);
	flow_id = le16_to_cpu(nic_mdid->fdir_filter_id);

	nse_printk("RX-desc RXDID=%d, FDir bkt_hash=0x%X, flow_id=0x%X\n",
						rx_desc->wb.rxdid, hash, flow_id);

	nse_printk("enqueue to RXQ: %d\n", rx_ring->q_index);
}

void
nse_test_suite_rcsum(struct nse_ring *rx_ring, union nse_32b_rx_desc *rx_desc,
		     struct sk_buff *skb, u8 rx_ptype)
{
	struct nse_vsi *vsi = rx_ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_rx_ptype_decoded decoded = nse_decode_rx_desc_ptype(rx_ptype);
	struct tcphdr *tcph = NULL;
	void *l3_hdr = NULL;
	u16 l3_proto;
	u8 l4_proto;

	if (!pf->test_rcsum)
		return;

	locate_final_l3_l4_hdr(skb, (void **)&tcph, &l3_hdr, NULL, &l3_proto, &l4_proto);

	if (!tcph)
		return;

	if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP)
		return;

	/* check based on TCP port.
	 */
	if (tcph->dest != cpu_to_be16(pf->test_rcsum_dport))
		return;	/* not test suite packet */

	nse_printk("=== receiving a RX_CSUM test suite packet\n");

	nse_printk("RPSR ptype: 0x%X (%d) --- decode: payload_layer=%d, inner_prot=%d\n",
					rx_ptype, rx_ptype,
					decoded.payload_layer, decoded.inner_prot);

	nse_printk("skb: ip_summed = %d, csum_level/encapsulation = %d\n",
					(unsigned int)skb->ip_summed,
					skb->csum_level
				);

	nse_dump_rx_desc(dev, rx_ring->q_index, -1, rx_desc);		/* idx = -1, meaningless */
}

/* this function is inserted in
 *
 *		nse_clean_rx_irq()
 *		{
 *			vlan_tag = nse_get_vlan_tag_from_rx_desc(rx_desc);
 *
 *			nse_process_skb_fields(rx_ring, rx_desc, skb, rx_ptype);
 *
 *				skb->protocol = eth_type_trans(skb, rx_ring->netdev);
 *
 *
 *			nse_test_suite_rvlan()		# <--- insert here.
 *
 *
 *			nse_receive_skb(rx_ring, skb, vlan_tag);
 *		}
 *
 * to print some debug log.
 *
 *
 * remote host send some test VLAN-tagged packets to Amber, *
 * we print information about these test packets, like dump rxq-descriptor content.
 *
 *
 * This is used to verify:
 *
 *		whether HW identify and strip VLAN tag in packet, and write-back in rxq-descriptor,
 *		like expect by configuration.
 */
void
nse_test_suite_rvlan(struct nse_ring *rx_ring, union nse_32b_rx_desc *rx_desc,
		     struct sk_buff *skb, u8 rx_ptype, u16 vlan_tag)
{
	struct nse_vsi *vsi = rx_ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_rx_ptype_decoded decoded = nse_decode_rx_desc_ptype(rx_ptype);
	struct tcphdr *tcph = NULL;
	void *l3_hdr = NULL;
	struct vlan_hdr *o_vh = NULL;
	u16 l3_proto;
	u8 l4_proto;
	bool non_zero_vlan = vlan_tag & VLAN_VID_MASK;
	struct ethhdr *o_eh = NULL;
	int i;

	if (!pf->test_rvlan)
		return;

	locate_final_l3_l4_hdr(skb, (void **)&tcph, &l3_hdr, (void **)&o_vh, &l3_proto, &l4_proto);

	if (!tcph)
		return;

	if (tcph->dest != cpu_to_be16(pf->test_rvlan_dport))
		return;	/* not test suite packet */

	if (non_zero_vlan) {	/* there is a VLAN tag, and stripped and writeback in rx-desc */

		nse_printk("=== receiving a RX_VLAN test suite packet (with VLAN tag stripped in rx-desc, VID=%d)\n", (vlan_tag & VLAN_VID_MASK));
	} else {
		nse_printk("=== receiving a RX_VLAN test suite packet (may with VLAN not stripped) --- check its packet data and rx-desc\n");
	}

	nse_printk("RPSR ptype: 0x%X (%d) --- decode: payload_layer=%d, inner_prot=%d\n",
					rx_ptype, rx_ptype,
					decoded.payload_layer, decoded.inner_prot);

	if (o_vh) {
		o_eh = (struct ethhdr *)skb_mac_header(skb);

		nse_printk("VLAN header in packet data\n");

		nse_printk("o_eh->h_proto = %X\n", be16_to_cpu(o_eh->h_proto));

		for (i = 0; i < 8; i++) {
			nse_printk("o_vh-#%d -> h_vlan_TCI = %X, h_vlan_encapsulated_proto = %X\n",
						i,
						be16_to_cpu(o_vh->h_vlan_TCI),
						be16_to_cpu(o_vh->h_vlan_encapsulated_proto));

			if (o_vh->h_vlan_encapsulated_proto != cpu_to_be16(ETH_P_8021Q) &&
				o_vh->h_vlan_encapsulated_proto != cpu_to_be16(ETH_P_8021AD)) {
				break;
			}
			o_vh += 1;	/* nested VLAN */
		}
	}

	nse_dump_rx_desc(dev, rx_ring->q_index, -1, rx_desc);		/* idx = -1, meaningless */
}

void
nse_test_suite_tvlan(struct nse_ring *tx_ring,
					struct nse_tx_desc *desc,
					struct nse_tx_buf *first,
					struct sk_buff *skb,
					struct nse_tx_offload_params *offload)
{
	struct nse_vsi *vsi = tx_ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct ethhdr *eh = skb_eth_hdr(skb);
	struct device *dev = nse_pf_to_dev(pf);

	if (!pf->test_tvlan)
		return;

	/* hardcoded - only print this MAC */
	if (!(eh->h_dest[0] == 0x00 &&
		eh->h_dest[1] == 0x90 &&
		eh->h_dest[2] == 0x0b &&
		eh->h_dest[3] == 0x87 &&
		eh->h_dest[4] == 0x60 &&
		eh->h_dest[5] == 0x69))
		return;

	dev_info(dev, "skb = %lX\n", (unsigned long)skb);
	dev_info(dev, "\t skb_vlan_tag_present(): %d\n",
					skb_vlan_tag_present(skb));
	dev_info(dev, "\t VID: %d\n",
					skb_vlan_tag_get_id(skb));
	dev_info(dev, "\t CFI: %d\n",
					skb_vlan_tag_get_cfi(skb));
	dev_info(dev, "\t PRIO: %d\n",
					skb_vlan_tag_get_prio(skb));

	dev_info(dev, "tx_ring->flags:\n");
	dev_info(dev, "\t NSE_TX_FLAGS_VLAN_TAG_LOC_L2TAG2: %d\n",
					!!(tx_ring->flags & NSE_TX_FLAGS_VLAN_TAG_LOC_L2TAG2));
	dev_info(dev, "\t NSE_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1: %d\n",
					!!(tx_ring->flags & NSE_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1));

	dev_info(dev, "first->tx_flags:\n");
	dev_info(dev, "\t NSE_TX_FLAGS_HW_OUTER_SINGLE_VLAN: %d\n",
					!!(first->tx_flags & NSE_TX_FLAGS_HW_OUTER_SINGLE_VLAN));
	dev_info(dev, "\t NSE_TX_FLAGS_HW_VLAN: %d\n",
					!!(first->tx_flags & NSE_TX_FLAGS_HW_VLAN));

	nse_dump_tx_desc(dev, tx_ring->q_index, -1, desc);
}

void
nse_test_suite_tcsum_start(struct nse_ring *tx_ring,
					struct nse_tx_buf *first,
					struct sk_buff *skb)
{
	struct nse_vsi *vsi = tx_ring->vsi;
	struct nse_pf *pf = vsi->back;

	if (!pf->test_tcsum)
		return;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return;

	/* handled by TSO test suite */
	if (first->tx_flags & NSE_TX_FLAGS_TSO)
		return;

	if (tx_ring->test_tcsum_pktcnt_cntdown > 0)
		tx_ring->test_tcsum_pktcnt_cntdown--;
}

void
nse_test_suite_tcsum_dump_desc(struct nse_ring *tx_ring,
					struct nse_tx_desc *desc,
					struct nse_tx_buf *first,
					struct sk_buff *skb)
{
	struct nse_vsi *vsi = tx_ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);

	if (!pf->test_tcsum)
		return;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return;

	/* handled by TSO test suite */
	if (first->tx_flags & NSE_TX_FLAGS_TSO)
		return;

	if (tx_ring->test_tcsum_pktcnt_cntdown)
		return;

	nse_dump_tx_desc(dev, tx_ring->q_index, -1, desc);
}

void
nse_test_suite_tcsum_end(struct nse_ring *tx_ring)
{
	struct nse_vsi *vsi = tx_ring->vsi;
	struct nse_pf *pf = vsi->back;

	if (!pf->test_tcsum)
		return;

	if (!tx_ring->test_tcsum_pktcnt_cntdown)
		tx_ring->test_tcsum_pktcnt_cntdown = pf->test_tcsum_pktcnt_interval;
}

void
nse_test_suite_tso_start(struct nse_ring *tx_ring,
					struct nse_tx_buf *first,
					struct sk_buff *skb)
{
	struct nse_vsi *vsi = tx_ring->vsi;
	struct nse_pf *pf = vsi->back;

	if (!pf->test_tso)
		return;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return;

	if (!skb_is_gso(skb))
		return;

	if (!(first->tx_flags & NSE_TX_FLAGS_TSO))
		return;

	if (tx_ring->test_tso_pktcnt_cntdown > 0)
		tx_ring->test_tso_pktcnt_cntdown--;
}

void
nse_test_suite_tso_dump_desc(struct nse_ring *tx_ring,
					struct nse_tx_desc *desc,
					struct nse_tx_buf *first,
					struct sk_buff *skb)
{
	struct nse_vsi *vsi = tx_ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);

	if (!pf->test_tso)
		return;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return;

	if (!skb_is_gso(skb))
		return;

	if (!(first->tx_flags & NSE_TX_FLAGS_TSO))
		return;

	if (tx_ring->test_tso_pktcnt_cntdown)
		return;

	nse_dump_tx_desc(dev, tx_ring->q_index, -1, desc);
}

void
nse_test_suite_tso_end(struct nse_ring *tx_ring)
{
	struct nse_vsi *vsi = tx_ring->vsi;
	struct nse_pf *pf = vsi->back;

	if (!pf->test_tso)
		return;

	if (!tx_ring->test_tso_pktcnt_cntdown)
		tx_ring->test_tso_pktcnt_cntdown = pf->test_tso_pktcnt_interval;
}

/* test with RXDID: NSE_RXDID_FLEX_DBG_0 */
void
nse_test_suite_rxdid_dbg_0_desc(struct nse_ring *rx_ring, union nse_32b_rx_desc *rx_desc)
{
	struct nse_32b_rx_desc_dbg_0 *desc = (struct nse_32b_rx_desc_dbg_0 *)rx_desc;
	u16 poh_md_37;
	u16 bit;

	if (desc->rxdid != NSE_RXDID_FLEX_DBG_0)
		return;

	rx_ring->rx_stats.rxdid_dbg_0_cnt++;

	poh_md_37 = le16_to_cpu(desc->poh_md_37);

	if (poh_md_37)
		rx_ring->rx_stats.non_zero_poh_md_37++;

	bit = (poh_md_37 >> 11) & 0x1;	/* bit: 11 - rscfv - to_rdm_poh[219] in poh[223:208] */
	rx_ring->rx_stats.rscfv_cnt[bit]++;
}

void locate_final_l3_l4_hdr(struct sk_buff *skb,
		void **ret_l4_hdr,	/* tcp or udp */
		void **ret_l3_hdr,
		void **ret_1st_vlan_hdr,
		u16 *l3_proto,
		u8 *l4_proto)
{
	struct ethhdr *o_eh = NULL;
	struct vlan_hdr *o_vh = NULL;
	int i = 0;

	struct iphdr *o_iph = NULL;
	struct ipv6hdr *o_ip6h = NULL;

	struct tcphdr *tcph = NULL;	/* most inner */

	struct udphdr *o_udph = NULL;

	struct vxlanhdr *vxh = NULL;
	struct gre_base_hdr *greh = NULL;

	struct iphdr *i_iph = NULL;
	struct ipv6hdr *i_ip6h = NULL;

	struct ethhdr *i_eh = NULL;

	struct mpls_shim_hdr *mpls_label = NULL;
	u32 val32;

	*l3_proto = 0;
	*l4_proto = 0;

	o_eh = (struct ethhdr *)skb_mac_header(skb);
	if (!o_eh)
		return;

	if (o_eh->h_proto == cpu_to_be16(ETH_P_8021Q) ||
		o_eh->h_proto == cpu_to_be16(ETH_P_8021AD)) {
		o_vh = (struct vlan_hdr *)(o_eh + 1);

		if (ret_1st_vlan_hdr)
			*ret_1st_vlan_hdr = (void *)o_vh;

		for (i = 0; i < 8; i++) {
			if (o_vh->h_vlan_encapsulated_proto != cpu_to_be16(ETH_P_8021Q) &&
				o_vh->h_vlan_encapsulated_proto != cpu_to_be16(ETH_P_8021AD)) {
				break;
			}
			o_vh += 1;	/* nested VLAN */
		}
	}

	if (o_eh->h_proto == cpu_to_be16(ETH_P_IP) ||
		(o_vh && o_vh->h_vlan_encapsulated_proto == cpu_to_be16(ETH_P_IP))) {
		if (o_vh)
			o_iph = (struct iphdr *)(o_vh + 1);
		else
			o_iph = (struct iphdr *)(o_eh + 1);

find_o_iph:

		*l3_proto = ETH_P_IP;
		*l4_proto = o_iph->protocol;

		if (ip_is_fragment(o_iph))
			return;

		/* the following "o_iph + 1" are not accurate, not consider possible IPv4 options.
		 *
		 * anyhow, this is only for simple debug.
		 */

		if (o_iph->protocol == IPPROTO_TCP) {		//ip4-tcp

			tcph = (struct tcphdr *)(o_iph + 1);

			/* FOUND */
			*ret_l4_hdr = (void *)tcph;
			*ret_l3_hdr = (void *)o_iph;

			return;
		} else if (o_iph->protocol == IPPROTO_UDP) {	//ip4-udp (maybe vxlan, check later)
			o_udph = (struct udphdr *)(o_iph + 1);

			*ret_l3_hdr = (void *)o_iph;
		} else if (o_iph->protocol == IPPROTO_ICMP) {
			/* FOUND */
			*ret_l4_hdr = (void *)(o_iph + 1);
			*ret_l3_hdr = (void *)o_iph;

			return;
		} else if (o_iph->protocol == IPPROTO_IPIP) {	//ip4-ip4
			i_iph = (struct iphdr *)(o_iph + 1);
		} else if (o_iph->protocol == IPPROTO_IPV6) {	//ip4-ip6
			i_ip6h = (struct ipv6hdr *)(o_iph + 1);
		} else if (o_iph->protocol == IPPROTO_GRE) {	//ip4-gre (check inner later)
			greh = (struct gre_base_hdr *)(o_iph + 1);
		} else {
			return;
		}
	} else if (o_eh->h_proto == cpu_to_be16(ETH_P_IPV6) ||
		(o_vh && o_vh->h_vlan_encapsulated_proto == cpu_to_be16(ETH_P_IPV6))) {
		if (o_vh)
			o_ip6h = (struct ipv6hdr *)(o_vh + 1);
		else
			o_ip6h = (struct ipv6hdr *)(o_eh + 1);

find_o_ip6h:

		*l3_proto = ETH_P_IPV6;
		*l4_proto = o_ip6h->nexthdr;

		if (o_ip6h->nexthdr == IPPROTO_TCP) {		//ip6-tcp

			tcph = (struct tcphdr *)(o_ip6h + 1);

			/* FOUND */
			*ret_l4_hdr = (void *)tcph;
			*ret_l3_hdr = (void *)o_ip6h;

			return;
		} else if (o_ip6h->nexthdr == IPPROTO_UDP) {	//ip6-udp (maybe vxlan, check later)
			o_udph = (struct udphdr *)(o_ip6h + 1);

			*ret_l3_hdr = (void *)o_ip6h;
		} else if (o_ip6h->nexthdr == IPPROTO_ICMPV6) {		//ip6-icmp

			/* FOUND */
			*ret_l4_hdr = (void *)(o_ip6h + 1);
			*ret_l3_hdr = (void *)o_ip6h;

			return;
		} else if (o_ip6h->nexthdr == IPPROTO_IPIP) {	//ip6-ip4
			i_iph = (struct iphdr *)(o_ip6h + 1);
		} else if (o_ip6h->nexthdr == IPPROTO_IPV6) {	//ip6-ip6
			i_ip6h = (struct ipv6hdr *)(o_ip6h + 1);
		} else if (o_ip6h->nexthdr == IPPROTO_GRE) {	//ip6-gre (check inner later)
			greh = (struct gre_base_hdr *)(o_ip6h + 1);
		} else {
			return;
		}
	} else if (eth_p_mpls(o_eh->h_proto) ||
		(o_vh && eth_p_mpls(o_vh->h_vlan_encapsulated_proto))) {
		if (o_vh)
			mpls_label = (struct mpls_shim_hdr *)(o_vh + 1);
		else
			mpls_label = (struct mpls_shim_hdr *)(o_eh + 1);

		for (i = 0; i < 8; i++) {
			val32 = be32_to_cpu(mpls_label->label_stack_entry);

			if (val32 & MPLS_LS_S_MASK) {	//stack bottom

				val32 &= MPLS_LS_LABEL_MASK;
				val32 >>= MPLS_LS_LABEL_SHIFT;

				o_iph = (struct iphdr *)(mpls_label + 1);

				if (val32 == MPLS_LABEL_IPV4NULL || o_iph->version == 4) {
					goto find_o_iph;
				} else if (val32 == MPLS_LABEL_IPV6NULL || o_iph->version == 6) {
					o_iph = NULL;
					o_ip6h = (struct ipv6hdr *)(mpls_label + 1);
					goto find_o_ip6h;
				}
			}

			mpls_label += 1;	/* nested label */
		}

		return;
	} else {
		return;
	}

	if (i_iph || i_ip6h) {	//ip4-ip4, ip4-ip6, ip6-ip4, ip6-ip4

found_inner_l3:
		if (i_iph &&
			(i_iph->protocol == IPPROTO_TCP ||
			i_iph->protocol == IPPROTO_UDP ||
			i_iph->protocol == IPPROTO_ICMP)) {
			if (ip_is_fragment(i_iph))
				return;

			//tcph and udph are of same offset in their DPORT, so this cast is OK
			tcph = (struct tcphdr *)(i_iph + 1);

			/* FOUND */
			*ret_l4_hdr = (void *)tcph;
			*ret_l3_hdr = (void *)i_iph;

			*l3_proto = ETH_P_IP;
			*l4_proto = i_iph->protocol;

			return;
		} else if (i_ip6h &&
			(i_ip6h->nexthdr == IPPROTO_TCP ||
			i_ip6h->nexthdr == IPPROTO_UDP ||
			i_ip6h->nexthdr == IPPROTO_ICMPV6)) {
			//tcph and udph are of same offset in their DPORT, so this cast is OK
			tcph = (struct tcphdr *)(i_ip6h + 1);

			/* FOUND */
			*ret_l4_hdr = (void *)tcph;
			*ret_l3_hdr = (void *)i_ip6h;

			*l3_proto = ETH_P_IPV6;
			*l4_proto = i_ip6h->nexthdr;

			return;
		} else {
			return;
		}
	} else if (o_udph) {	//outter UDP, check if it is plain UDP, or vxlan
		if (o_udph->dest == cpu_to_be16(4789) ||		//vxlan port defined in RFC
				o_udph->dest == cpu_to_be16(4790) ||	//vxlan-gpe
				//linux 'vxlan_port' defined in vxlan.c
				o_udph->dest == cpu_to_be16(8472)) {
			vxh = (struct vxlanhdr *)(o_udph + 1);
			i_eh = (struct ethhdr *)(vxh + 1);

found_inner_l2:
			if (i_eh->h_proto == cpu_to_be16(ETH_P_IP)) {
				i_iph = (struct iphdr *)(i_eh + 1);
				goto found_inner_l3;
			} else if (i_eh->h_proto == cpu_to_be16(ETH_P_IPV6)) {
				i_ip6h = (struct ipv6hdr *)(i_eh + 1);
				goto found_inner_l3;
			} else {
				return;
			}
		} else {		//plain UDP
			//tcph and udph are of same offset in their DPORT, so this cast is OK
			tcph = (struct tcphdr *)o_udph;

			/* FOUND */
			*ret_l4_hdr = (void *)tcph;

			return;
		}
	} else if (greh) {		//ip4-gre, ip6-gre
		if (greh->protocol == cpu_to_be16(ETH_P_IP)) {
			i_iph = (struct iphdr *)(greh + 1);
			goto found_inner_l3;
		} else if (greh->protocol == cpu_to_be16(ETH_P_IPV6)) {
			i_ip6h = (struct ipv6hdr *)(greh + 1);
			goto found_inner_l3;
		} else if (greh->protocol == cpu_to_be16(ETH_P_TEB)) {
			i_eh = (struct ethhdr *)(greh + 1);
			goto found_inner_l2;
		} else {
			return;
		}
	}
}

#endif	/* #if defined(NSE_DEBUG_EXT) */

