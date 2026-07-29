/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef _MCEVF_LIB_H_
#define _MCEVF_LIB_H_

#include "mcevf.h"

#define __VLAN_ALLOWED(protocol)                           \
	(!!((protocol) == htons(ETH_P_8021Q) || \
	    (protocol) == htons(ETH_P_8021AD)))

#define MCEVF_INSERT_VLAN_CNT(pf) ((pf)->dvlan_ctrl.cnt)

#define __DEBUG_SKB_DUMP 0
#if __DEBUG_SKB_DUMP
#include <linux/highmem.h>

static inline void __mcevf_tx_skb_dump(const struct sk_buff *skb,
				       bool full_pkt)
{
	static atomic_t can_dump_full = ATOMIC_INIT(5);
	struct skb_shared_info *sh = skb_shinfo(skb);
	struct net_device *dev = skb->dev;
	struct sock *sk = skb->sk;
	struct sk_buff *list_skb;
	bool has_mac, has_trans;
	int headroom, tailroom;
	int i, len, seg_len;
	const char *level = KERN_WARNING;

	if (full_pkt)
		full_pkt = atomic_dec_if_positive(&can_dump_full) >= 0;

	if (full_pkt)
		len = skb->len;
	else
		len = min_t(int, skb->len, MAX_HEADER + 128);

	headroom = skb_headroom(skb);
	tailroom = skb_tailroom(skb);

	has_mac = skb_mac_header_was_set(skb);
	has_trans = skb_transport_header_was_set(skb);

	pr_debug("queue_mapping=%u skbaddr=%p vlan_tagged=%d vlan_proto=0x%04x\n"
	       "vlan_tci=0x%04x protocol=0x%04x\n"
	       "skb->head=%u skb->data=%u skb->tail=%u skb->end=%u\n"
	       "skb->datalen=%u skb_len=%u skb->truesize=%u headroom=%u headlen=%u tailroom=%u\n"
	       "mac=(%d,%d) net=(%d,%d) trans=%d\n"
	       "shinfo(txflags=%u nr_frags=%u gso(size=%u type=%u segs=%u))\n"
	       "csum(0x%x ip_summed=%u complete_sw=%u valid=%u level=%u)\n"
	       "hash(0x%x sw=%u l4=%u) proto=0x%04x pkttype=%u iif=%d\n",
	       skb->queue_mapping, skb, skb_vlan_tag_present(skb),
	       ntohs(skb->vlan_proto), skb_vlan_tag_get(skb),
	       ntohs(skb->protocol), skb->head, skb->data, skb->tail,
	       skb->end, skb->data_len, skb->len, skb->truesize, headroom,
	       skb_headlen(skb), tailroom, has_mac ? skb->mac_header : -1,
	       has_mac ? (skb->network_header - skb->mac_header) : -1,
	       skb->network_header,
	       has_trans ? skb_network_header_len(skb) : -1,
	       has_trans ? skb->transport_header : -1, sh->tx_flags,
	       sh->nr_frags, sh->gso_size, sh->gso_type, sh->gso_segs,
	       skb->csum, skb->ip_summed, skb->csum_complete_sw,
	       skb->csum_valid, skb->csum_level, skb->hash, skb->sw_hash,
	       skb->l4_hash, ntohs(skb->protocol), skb->pkt_type,
	       skb->skb_iif);
	if (dev)
		pr_debug("%sdev name=%s feat=0x%pNF\n", level, dev->name,
			 &dev->features);

	seg_len = min_t(int, skb_headlen(skb), len);
	if (seg_len)
		print_hex_dump(level, "skb linear:   ", DUMP_PREFIX_OFFSET,
			       16, 1, skb->data, seg_len, false);
	len -= seg_len;

	for (i = 0; len && i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		u32 p_off, p_len, copied;
		struct page *p;
		u8 *vaddr;

		p = skb_frag_address(frag);
		p_len = skb_frag_size(frag);
		seg_len = min_t(int, p_len, len);
		vaddr = kmap_atomic(p);
		print_hex_dump(level, "skb frag:     ", DUMP_PREFIX_OFFSET,
			       16, 1, vaddr, seg_len, false);
		kunmap_atomic(vaddr);
		len -= seg_len;
		if (!len)
			break;
	}

	if (full_pkt && skb_has_frag_list(skb)) {
		pr_debug("skb fraglist:\n");
		skb_walk_frags(skb, list_skb)
			__mcevf_tx_skb_dump(list_skb, true);
	}
}

#define mcevf_tx_skb_dump __mcevf_tx_skb_dump
#endif

struct mcevf_vsi *mcevf_vsi_setup(struct mcevf_pf *pf);
int mcevf_get_num_local_cpus(struct device *dev);
int mcevf_normalize_cpu_count(int num_cpus);
int mcevf_get_irq_res(struct mcevf_pf *pf, struct mcevf_res_tracker *res,
		      u16 needed, u16 start);
int mcevf_free_irq_res(struct mcevf_res_tracker *res, u16 needed,
		       u16 start);
void mcevf_vsi_cfg_frame_size(struct mcevf_vsi *vsi);
int mcevf_vsi_release(struct mcevf_vsi *vsi);
void mcevf_vsi_release_all(struct mcevf_pf *pf);
void mcevf_vsi_get_q_vector_q_base(struct mcevf_vsi *vsi, u16 vector_id,
				   u16 *txq, u16 *rxq);
int mcevf_vsi_open(struct mcevf_vsi *vsi);
void mcevf_vsi_close(struct mcevf_vsi *vsi);
int mcevf_down(struct mcevf_vsi *vsi);
int mcevf_up(struct mcevf_vsi *vsi);
void mcevf_update_tx_ring_stats(struct mcevf_ring *tx_ring, u64 pkts,
				u64 bytes);
void mcevf_update_rx_ring_stats(struct mcevf_ring *rx_ring, u64 pkts,
				u64 bytes);
void mcevf_vsi_free_tx_rings(struct mcevf_vsi *vsi);
void mcevf_vsi_free_rx_rings(struct mcevf_vsi *vsi);
int mcevf_vsi_rebuild(struct mcevf_vsi *vsi);
int mcevf_vsi_set_dflt_rss_lut(struct mcevf_vsi *vsi, int req_rss_size);
int mcevf_mbx_handle_pf_vlan(struct mcevf_hw *hw, u32 vtag);
void mcevf_pf_flags_reset_set(struct mcevf_pf *pf);
bool mcevf_pf_flags_reset_get(struct mcevf_pf *pf);
#endif /* _MCEVF_LIB_H_ */
