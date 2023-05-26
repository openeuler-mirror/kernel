// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Huawei Technologies Co., Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <net/xfrm.h>
#include <linux/netdevice.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/tcp.h>
#include <linux/sctp.h>
#include <linux/dma-mapping.h>
#include <linux/types.h>
#include <linux/u64_stats_sync.h>
#include <linux/module.h>
#include <linux/vmalloc.h>

#include "ossl_knl.h"
#include "hinic3_crm.h"
#include "hinic3_nic_qp.h"
#include "hinic3_nic_io.h"
#include "hinic3_nic_cfg.h"
#include "hinic3_srv_nic.h"
#include "hinic3_nic_dev.h"
#include "hinic3_tx.h"

#define MIN_SKB_LEN		32

#define MAX_PAYLOAD_OFFSET	221

#define NIC_QID(q_id, nic_dev)	((q_id) & ((nic_dev)->num_qps - 1))

#define HINIC3_TX_TASK_WRAPPED		1
#define HINIC3_TX_BD_DESC_WRAPPED	2

#define TXQ_STATS_INC(txq, field)			\
do {							\
	u64_stats_update_begin(&(txq)->txq_stats.syncp);	\
	(txq)->txq_stats.field++;				\
	u64_stats_update_end(&(txq)->txq_stats.syncp);	\
} while (0)

void hinic3_txq_get_stats(struct hinic3_txq *txq,
			  struct hinic3_txq_stats *stats)
{
	struct hinic3_txq_stats *txq_stats = &txq->txq_stats;
	unsigned int start;

	u64_stats_update_begin(&stats->syncp);
	do {
		start = u64_stats_fetch_begin(&txq_stats->syncp);
		stats->bytes = txq_stats->bytes;
		stats->packets = txq_stats->packets;
		stats->busy = txq_stats->busy;
		stats->wake = txq_stats->wake;
		stats->dropped = txq_stats->dropped;
	} while (u64_stats_fetch_retry(&txq_stats->syncp, start));
	u64_stats_update_end(&stats->syncp);
}

void hinic3_txq_clean_stats(struct hinic3_txq_stats *txq_stats)
{
	u64_stats_update_begin(&txq_stats->syncp);
	txq_stats->bytes = 0;
	txq_stats->packets = 0;
	txq_stats->busy = 0;
	txq_stats->wake = 0;
	txq_stats->dropped = 0;

	txq_stats->skb_pad_err = 0;
	txq_stats->frag_len_overflow = 0;
	txq_stats->offload_cow_skb_err = 0;
	txq_stats->map_frag_err = 0;
	txq_stats->unknown_tunnel_pkt = 0;
	txq_stats->frag_size_err = 0;
	txq_stats->rsvd1 = 0;
	txq_stats->rsvd2 = 0;
	u64_stats_update_end(&txq_stats->syncp);
}

static void txq_stats_init(struct hinic3_txq *txq)
{
	struct hinic3_txq_stats *txq_stats = &txq->txq_stats;

	u64_stats_init(&txq_stats->syncp);
	hinic3_txq_clean_stats(txq_stats);
}

static inline void hinic3_set_buf_desc(struct hinic3_sq_bufdesc *buf_descs,
				       dma_addr_t addr, u32 len)
{
	buf_descs->hi_addr = hinic3_hw_be32(upper_32_bits(addr));
	buf_descs->lo_addr = hinic3_hw_be32(lower_32_bits(addr));
	buf_descs->len  = hinic3_hw_be32(len);
}

static int tx_map_skb(struct hinic3_nic_dev *nic_dev, struct sk_buff *skb,
		      u16 valid_nr_frags, struct hinic3_txq *txq,
		      struct hinic3_tx_info *tx_info,
		      struct hinic3_sq_wqe_combo *wqe_combo)
{
	struct hinic3_sq_wqe_desc *wqe_desc = wqe_combo->ctrl_bd0;
	struct hinic3_sq_bufdesc *buf_desc = wqe_combo->bds_head;
	struct hinic3_dma_info *dma_info = tx_info->dma_info;
	struct pci_dev *pdev = nic_dev->pdev;
	skb_frag_t *frag = NULL;
	u32 j, i;
	int err;

	dma_info[0].dma = dma_map_single(&pdev->dev, skb->data, skb_headlen(skb), DMA_TO_DEVICE);
	if (dma_mapping_error(&pdev->dev, dma_info[0].dma)) {
		TXQ_STATS_INC(txq, map_frag_err);
		return -EFAULT;
	}

	dma_info[0].len = skb_headlen(skb);

	wqe_desc->hi_addr = hinic3_hw_be32(upper_32_bits(dma_info[0].dma));
	wqe_desc->lo_addr = hinic3_hw_be32(lower_32_bits(dma_info[0].dma));

	wqe_desc->ctrl_len = dma_info[0].len;

	for (i = 0; i < valid_nr_frags;) {
		frag = &(skb_shinfo(skb)->frags[i]);
		if (unlikely(i == wqe_combo->first_bds_num))
			buf_desc = wqe_combo->bds_sec2;

		i++;
		dma_info[i].dma = skb_frag_dma_map(&pdev->dev, frag, 0,
						   skb_frag_size(frag),
						   DMA_TO_DEVICE);
		if (dma_mapping_error(&pdev->dev, dma_info[i].dma)) {
			TXQ_STATS_INC(txq, map_frag_err);
			i--;
			err = -EFAULT;
			goto frag_map_err;
		}
		dma_info[i].len = skb_frag_size(frag);

		hinic3_set_buf_desc(buf_desc, dma_info[i].dma,
				    dma_info[i].len);
		buf_desc++;
	}

	return 0;

frag_map_err:
	for (j = 0; j < i;) {
		j++;
		dma_unmap_page(&pdev->dev, dma_info[j].dma,
			       dma_info[j].len, DMA_TO_DEVICE);
	}
	dma_unmap_single(&pdev->dev, dma_info[0].dma, dma_info[0].len,
			 DMA_TO_DEVICE);
	return err;
}

static inline void tx_unmap_skb(struct hinic3_nic_dev *nic_dev,
				struct sk_buff *skb, u16 valid_nr_frags,
				struct hinic3_dma_info *dma_info)
{
	struct pci_dev *pdev = nic_dev->pdev;
	int i;

	for (i = 0; i < valid_nr_frags;) {
		i++;
		dma_unmap_page(&pdev->dev,
			       dma_info[i].dma,
			       dma_info[i].len, DMA_TO_DEVICE);
	}

	dma_unmap_single(&pdev->dev, dma_info[0].dma,
			 dma_info[0].len, DMA_TO_DEVICE);
}

union hinic3_l4 {
	struct tcphdr *tcp;
	struct udphdr *udp;
	unsigned char *hdr;
};

enum sq_l3_type {
	UNKNOWN_L3TYPE = 0,
	IPV6_PKT = 1,
	IPV4_PKT_NO_CHKSUM_OFFLOAD = 2,
	IPV4_PKT_WITH_CHKSUM_OFFLOAD = 3,
};

enum sq_l4offload_type {
	OFFLOAD_DISABLE   = 0,
	TCP_OFFLOAD_ENABLE  = 1,
	SCTP_OFFLOAD_ENABLE = 2,
	UDP_OFFLOAD_ENABLE  = 3,
};

/* initialize l4_len and offset */
static void get_inner_l4_info(struct sk_buff *skb, union hinic3_l4 *l4,
			      u8 l4_proto, u32 *offset,
			      enum sq_l4offload_type *l4_offload)
{
	switch (l4_proto) {
	case IPPROTO_TCP:
		*l4_offload = TCP_OFFLOAD_ENABLE;
		/* To keep same with TSO, payload offset begins from paylaod */
		*offset = (l4->tcp->doff << TCP_HDR_DATA_OFF_UNIT_SHIFT) +
			   TRANSPORT_OFFSET(l4->hdr, skb);
		break;

	case IPPROTO_UDP:
		*l4_offload = UDP_OFFLOAD_ENABLE;
		*offset = TRANSPORT_OFFSET(l4->hdr, skb);
		break;
	default:
		break;
	}
}

static int hinic3_tx_csum(struct hinic3_txq *txq, struct hinic3_sq_task *task,
			  struct sk_buff *skb)
{
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (skb->encapsulation) {
		union hinic3_ip ip;
		u8 l4_proto;

		task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, TUNNEL_FLAG);

		ip.hdr = skb_network_header(skb);
		if (ip.v4->version == IPV4_VERSION) {
			l4_proto = ip.v4->protocol;
		} else if (ip.v4->version == IPV6_VERSION) {
			union hinic3_l4 l4;
			unsigned char *exthdr;
			__be16 frag_off;

#ifdef HAVE_OUTER_IPV6_TUNNEL_OFFLOAD
			task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, OUT_L4_EN);
#endif
			exthdr = ip.hdr + sizeof(*ip.v6);
			l4_proto = ip.v6->nexthdr;
			l4.hdr = skb_transport_header(skb);
			if (l4.hdr != exthdr)
				ipv6_skip_exthdr(skb, exthdr - skb->data,
						 &l4_proto, &frag_off);
		} else {
			l4_proto = IPPROTO_RAW;
		}

		if (l4_proto != IPPROTO_UDP ||
		    ((struct udphdr *)skb_transport_header(skb))->dest != VXLAN_OFFLOAD_PORT_LE) {
			TXQ_STATS_INC(txq, unknown_tunnel_pkt);
			/* Unsupport tunnel packet, disable csum offload */
			skb_checksum_help(skb);
			return 0;
		}
	}

	task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, INNER_L4_EN);

	return 1;
}

static void get_inner_l3_l4_type(struct sk_buff *skb, union hinic3_ip *ip,
				 union hinic3_l4 *l4,
				 enum sq_l3_type *l3_type, u8 *l4_proto)
{
	unsigned char *exthdr = NULL;

	if (ip->v4->version == IP4_VERSION) {
		*l3_type = IPV4_PKT_WITH_CHKSUM_OFFLOAD;
		*l4_proto = ip->v4->protocol;

#ifdef HAVE_OUTER_IPV6_TUNNEL_OFFLOAD
		/* inner_transport_header is wrong in centos7.0 and suse12.1 */
		l4->hdr = ip->hdr + ((u8)ip->v4->ihl << IP_HDR_IHL_UNIT_SHIFT);
#endif
	} else if (ip->v4->version == IP6_VERSION) {
		*l3_type = IPV6_PKT;
		exthdr = ip->hdr + sizeof(*ip->v6);
		*l4_proto = ip->v6->nexthdr;
		if (exthdr != l4->hdr) {
			__be16 frag_off = 0;
#ifndef HAVE_OUTER_IPV6_TUNNEL_OFFLOAD
			ipv6_skip_exthdr(skb, (int)(exthdr - skb->data),
					 l4_proto, &frag_off);
#else
			int pld_off = 0;

			pld_off = ipv6_skip_exthdr(skb,
						   (int)(exthdr - skb->data),
						   l4_proto, &frag_off);
			l4->hdr = skb->data + pld_off;
#endif
		}
	} else {
		*l3_type = UNKNOWN_L3TYPE;
		*l4_proto = 0;
	}
}

static void hinic3_set_tso_info(struct hinic3_sq_task *task, u32 *queue_info,
				enum sq_l4offload_type l4_offload,
				u32 offset, u32 mss)
{
	if (l4_offload == TCP_OFFLOAD_ENABLE) {
		*queue_info |= SQ_CTRL_QUEUE_INFO_SET(1U, TSO);
		task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, INNER_L4_EN);
	} else if (l4_offload == UDP_OFFLOAD_ENABLE) {
		*queue_info |= SQ_CTRL_QUEUE_INFO_SET(1U, UFO);
		task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, INNER_L4_EN);
	}

	/* Default enable L3 calculation */
	task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, INNER_L3_EN);

	*queue_info |= SQ_CTRL_QUEUE_INFO_SET(offset >> 1, PLDOFF);

	/* set MSS value */
	*queue_info = SQ_CTRL_QUEUE_INFO_CLEAR(*queue_info, MSS);
	*queue_info |= SQ_CTRL_QUEUE_INFO_SET(mss, MSS);
}

static int hinic3_tso(struct hinic3_sq_task *task, u32 *queue_info,
		      struct sk_buff *skb)
{
	enum sq_l4offload_type l4_offload = OFFLOAD_DISABLE;
	enum sq_l3_type l3_type;
	union hinic3_ip ip;
	union hinic3_l4 l4;
	u32 offset = 0;
	u8 l4_proto;
	int err;

	if (!skb_is_gso(skb))
		return 0;

	err = skb_cow_head(skb, 0);
	if (err < 0)
		return err;

	if (skb->encapsulation) {
		u32 gso_type = skb_shinfo(skb)->gso_type;
		/* L3 checksum always enable */
		task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, OUT_L3_EN);
		task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, TUNNEL_FLAG);

		l4.hdr = skb_transport_header(skb);
		ip.hdr = skb_network_header(skb);

		if (gso_type & SKB_GSO_UDP_TUNNEL_CSUM) {
			l4.udp->check = ~csum_magic(&ip, IPPROTO_UDP);
			task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, OUT_L4_EN);
		} else if (gso_type & SKB_GSO_UDP_TUNNEL) {
#ifdef HAVE_OUTER_IPV6_TUNNEL_OFFLOAD
			if (ip.v4->version == 6) {
				l4.udp->check = ~csum_magic(&ip, IPPROTO_UDP);
				task->pkt_info0 |=
					SQ_TASK_INFO0_SET(1U, OUT_L4_EN);
			}
#endif
		}

		ip.hdr = skb_inner_network_header(skb);
		l4.hdr = skb_inner_transport_header(skb);
	} else {
		ip.hdr = skb_network_header(skb);
		l4.hdr = skb_transport_header(skb);
	}

	get_inner_l3_l4_type(skb, &ip, &l4, &l3_type, &l4_proto);

	if (l4_proto == IPPROTO_TCP)
		l4.tcp->check = ~csum_magic(&ip, IPPROTO_TCP);
#ifdef HAVE_IP6_FRAG_ID_ENABLE_UFO
	else if (l4_proto == IPPROTO_UDP && ip.v4->version == 6)
		task->ip_identify =
			be32_to_cpu(skb_shinfo(skb)->ip6_frag_id);
#endif

	get_inner_l4_info(skb, &l4, l4_proto, &offset, &l4_offload);

#ifdef HAVE_OUTER_IPV6_TUNNEL_OFFLOAD
	u32 network_hdr_len;

	if (unlikely(l3_type == UNKNOWN_L3TYPE))
		network_hdr_len = 0;
	else
		network_hdr_len = l4.hdr - ip.hdr;

	if (unlikely(!offset)) {
		if (l3_type == UNKNOWN_L3TYPE)
			offset = ip.hdr - skb->data;
		else if (l4_offload == OFFLOAD_DISABLE)
			offset = ip.hdr - skb->data + network_hdr_len;
	}
#endif

	hinic3_set_tso_info(task, queue_info, l4_offload, offset,
			    skb_shinfo(skb)->gso_size);

	return 1;
}

static u32 hinic3_tx_offload(struct sk_buff *skb, struct hinic3_sq_task *task,
			     u32 *queue_info, struct hinic3_txq *txq)
{
	u32 offload = 0;
	int tso_cs_en;

	task->pkt_info0 = 0;
	task->ip_identify = 0;
	task->pkt_info2 = 0;
	task->vlan_offload = 0;

	tso_cs_en = hinic3_tso(task, queue_info, skb);
	if (tso_cs_en < 0) {
		offload = TX_OFFLOAD_INVALID;
		return offload;
	} else if (tso_cs_en) {
		offload |= TX_OFFLOAD_TSO;
	} else {
		tso_cs_en = hinic3_tx_csum(txq, task, skb);
		if (tso_cs_en)
			offload |= TX_OFFLOAD_CSUM;
	}

#define VLAN_INSERT_MODE_MAX 5
	if (unlikely(skb_vlan_tag_present(skb))) {
		/* select vlan insert mode by qid, default 802.1Q Tag type */
		hinic3_set_vlan_tx_offload(task, skb_vlan_tag_get(skb),
					   txq->q_id % VLAN_INSERT_MODE_MAX);
		offload |= TX_OFFLOAD_VLAN;
	}

	if (unlikely(SQ_CTRL_QUEUE_INFO_GET(*queue_info, PLDOFF) >
		     MAX_PAYLOAD_OFFSET)) {
		offload = TX_OFFLOAD_INVALID;
		return offload;
	}

	return offload;
}

static void get_pkt_stats(struct hinic3_tx_info *tx_info, struct sk_buff *skb)
{
	u32 ihs, hdr_len;

	if (skb_is_gso(skb)) {
#if (defined(HAVE_SKB_INNER_TRANSPORT_HEADER) && \
	defined(HAVE_SK_BUFF_ENCAPSULATION))
		if (skb->encapsulation) {
#ifdef HAVE_SKB_INNER_TRANSPORT_OFFSET
			ihs = skb_inner_transport_offset(skb) +
			      inner_tcp_hdrlen(skb);
#else
			ihs = (skb_inner_transport_header(skb) - skb->data) +
			      inner_tcp_hdrlen(skb);
#endif
		} else {
#endif
			ihs = skb_transport_offset(skb) + tcp_hdrlen(skb);
#if (defined(HAVE_SKB_INNER_TRANSPORT_HEADER) && \
	defined(HAVE_SK_BUFF_ENCAPSULATION))
		}
#endif
		hdr_len = (skb_shinfo(skb)->gso_segs - 1) * ihs;
		tx_info->num_bytes = skb->len + (u64)hdr_len;
	} else {
		tx_info->num_bytes = skb->len > ETH_ZLEN ? skb->len : ETH_ZLEN;
	}

	tx_info->num_pkts = 1;
}

static inline int hinic3_maybe_stop_tx(struct hinic3_txq *txq, u16 wqebb_cnt)
{
	if (likely(hinic3_get_sq_free_wqebbs(txq->sq) >= wqebb_cnt))
		return 0;

	/* We need to check again in a case another CPU has just
	 * made room available.
	 */
	netif_stop_subqueue(txq->netdev, txq->q_id);

	if (likely(hinic3_get_sq_free_wqebbs(txq->sq) < wqebb_cnt))
		return -EBUSY;

	/* there have enough wqebbs after queue is wake up */
	netif_start_subqueue(txq->netdev, txq->q_id);

	return 0;
}

static u16 hinic3_set_wqe_combo(struct hinic3_txq *txq,
				struct hinic3_sq_wqe_combo *wqe_combo,
				u32 offload, u16 num_sge, u16 *curr_pi)
{
	void *second_part_wqebbs_addr = NULL;
	void *wqe = NULL;
	u16 first_part_wqebbs_num, tmp_pi;

	wqe_combo->ctrl_bd0 = hinic3_get_sq_one_wqebb(txq->sq, curr_pi);
	if (!offload && num_sge == 1) {
		wqe_combo->wqe_type = SQ_WQE_COMPACT_TYPE;
		return hinic3_get_and_update_sq_owner(txq->sq, *curr_pi, 1);
	}

	wqe_combo->wqe_type = SQ_WQE_EXTENDED_TYPE;

	if (offload) {
		wqe_combo->task = hinic3_get_sq_one_wqebb(txq->sq, &tmp_pi);
		wqe_combo->task_type = SQ_WQE_TASKSECT_16BYTES;
	} else {
		wqe_combo->task_type = SQ_WQE_TASKSECT_46BITS;
	}

	if (num_sge > 1) {
		/* first wqebb contain bd0, and bd size is equal to sq wqebb
		 * size, so we use (num_sge - 1) as wanted weqbb_cnt
		 */
		wqe = hinic3_get_sq_multi_wqebbs(txq->sq, num_sge - 1, &tmp_pi,
						 &second_part_wqebbs_addr,
						 &first_part_wqebbs_num);
		wqe_combo->bds_head = wqe;
		wqe_combo->bds_sec2 = second_part_wqebbs_addr;
		wqe_combo->first_bds_num = first_part_wqebbs_num;
	}

	return hinic3_get_and_update_sq_owner(txq->sq, *curr_pi,
					      num_sge + (u16)!!offload);
}

/* *
 * hinic3_prepare_sq_ctrl - init sq wqe cs
 * @nr_descs: total sge_num, include bd0 in cs
 */
static void hinic3_prepare_sq_ctrl(struct hinic3_sq_wqe_combo *wqe_combo,
				   u32 queue_info, int nr_descs, u16 owner)
{
	struct hinic3_sq_wqe_desc *wqe_desc = wqe_combo->ctrl_bd0;

	if (wqe_combo->wqe_type == SQ_WQE_COMPACT_TYPE) {
		wqe_desc->ctrl_len |=
		    SQ_CTRL_SET(SQ_NORMAL_WQE, DATA_FORMAT) |
		    SQ_CTRL_SET(wqe_combo->wqe_type, EXTENDED) |
		    SQ_CTRL_SET(owner, OWNER);

		wqe_desc->ctrl_len = hinic3_hw_be32(wqe_desc->ctrl_len);
		/* compact wqe queue_info will transfer to ucode */
		wqe_desc->queue_info = 0;
		return;
	}

	wqe_desc->ctrl_len |= SQ_CTRL_SET(nr_descs, BUFDESC_NUM) |
			      SQ_CTRL_SET(wqe_combo->task_type, TASKSECT_LEN) |
			      SQ_CTRL_SET(SQ_NORMAL_WQE, DATA_FORMAT) |
			      SQ_CTRL_SET(wqe_combo->wqe_type, EXTENDED) |
			      SQ_CTRL_SET(owner, OWNER);

	wqe_desc->ctrl_len = hinic3_hw_be32(wqe_desc->ctrl_len);

	wqe_desc->queue_info = queue_info;
	wqe_desc->queue_info |= SQ_CTRL_QUEUE_INFO_SET(1U, UC);

	if (!SQ_CTRL_QUEUE_INFO_GET(wqe_desc->queue_info, MSS)) {
		wqe_desc->queue_info |=
		    SQ_CTRL_QUEUE_INFO_SET(TX_MSS_DEFAULT, MSS);
	} else if (SQ_CTRL_QUEUE_INFO_GET(wqe_desc->queue_info, MSS) <
		   TX_MSS_MIN) {
		/* mss should not less than 80 */
		wqe_desc->queue_info =
		    SQ_CTRL_QUEUE_INFO_CLEAR(wqe_desc->queue_info, MSS);
		wqe_desc->queue_info |= SQ_CTRL_QUEUE_INFO_SET(TX_MSS_MIN, MSS);
	}

	wqe_desc->queue_info = hinic3_hw_be32(wqe_desc->queue_info);
}

static netdev_tx_t hinic3_send_one_skb(struct sk_buff *skb,
				       struct net_device *netdev,
				       struct hinic3_txq *txq)
{
	struct hinic3_nic_dev *nic_dev = netdev_priv(netdev);
	struct hinic3_sq_wqe_combo wqe_combo = {0};
	struct hinic3_tx_info *tx_info = NULL;
	struct hinic3_sq_task task;
	u32 offload, queue_info = 0;
	u16 owner = 0, pi = 0;
	u16 wqebb_cnt, num_sge, valid_nr_frags;
	bool find_zero_sge_len = false;
	int err, i;

	if (unlikely(skb->len < MIN_SKB_LEN)) {
		if (skb_pad(skb, (int)(MIN_SKB_LEN - skb->len))) {
			TXQ_STATS_INC(txq, skb_pad_err);
			goto tx_skb_pad_err;
		}

		skb->len = MIN_SKB_LEN;
	}

	valid_nr_frags = 0;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		if (!skb_frag_size(&skb_shinfo(skb)->frags[i])) {
			find_zero_sge_len = true;
			continue;
		} else if (find_zero_sge_len) {
			TXQ_STATS_INC(txq, frag_size_err);
			goto tx_drop_pkts;
		}

		valid_nr_frags++;
	}

	num_sge = valid_nr_frags + 1;

	/* assume need normal TS format wqe, task info need 1 wqebb */
	wqebb_cnt = num_sge + 1;
	if (unlikely(hinic3_maybe_stop_tx(txq, wqebb_cnt))) {
		TXQ_STATS_INC(txq, busy);
		return NETDEV_TX_BUSY;
	}

	offload = hinic3_tx_offload(skb, &task, &queue_info, txq);
	if (unlikely(offload == TX_OFFLOAD_INVALID)) {
		TXQ_STATS_INC(txq, offload_cow_skb_err);
		goto tx_drop_pkts;
	} else if (!offload) {
		/* no TS in current wqe */
		wqebb_cnt -= 1;
		if (unlikely(num_sge == 1 && skb->len > COMPACET_WQ_SKB_MAX_LEN))
			goto tx_drop_pkts;
	}

	owner = hinic3_set_wqe_combo(txq, &wqe_combo, offload, num_sge, &pi);
	if (offload) {
		/* ip6_frag_id is big endiant, not need to transfer */
		wqe_combo.task->ip_identify = hinic3_hw_be32(task.ip_identify);
		wqe_combo.task->pkt_info0 = hinic3_hw_be32(task.pkt_info0);
		wqe_combo.task->pkt_info2 = hinic3_hw_be32(task.pkt_info2);
		wqe_combo.task->vlan_offload =
			hinic3_hw_be32(task.vlan_offload);
	}

	tx_info = &txq->tx_info[pi];
	tx_info->skb = skb;
	tx_info->wqebb_cnt = wqebb_cnt;
	tx_info->valid_nr_frags = valid_nr_frags;

	err = tx_map_skb(nic_dev, skb, valid_nr_frags, txq, tx_info,
			 &wqe_combo);
	if (err) {
		hinic3_rollback_sq_wqebbs(txq->sq, wqebb_cnt, owner);
		goto tx_drop_pkts;
	}

	get_pkt_stats(tx_info, skb);

	hinic3_prepare_sq_ctrl(&wqe_combo, queue_info, num_sge, owner);

	hinic3_write_db(txq->sq, txq->cos, SQ_CFLAG_DP,
			hinic3_get_sq_local_pi(txq->sq));

	return NETDEV_TX_OK;

tx_drop_pkts:
	dev_kfree_skb_any(skb);

tx_skb_pad_err:
	TXQ_STATS_INC(txq, dropped);

	return NETDEV_TX_OK;
}

netdev_tx_t hinic3_lb_xmit_frame(struct sk_buff *skb,
				 struct net_device *netdev)
{
	struct hinic3_nic_dev *nic_dev = netdev_priv(netdev);
	u16 q_id = skb_get_queue_mapping(skb);
	struct hinic3_txq *txq = &nic_dev->txqs[q_id];

	return hinic3_send_one_skb(skb, netdev, txq);
}

netdev_tx_t hinic3_xmit_frame(struct sk_buff *skb, struct net_device *netdev)
{
	struct hinic3_nic_dev *nic_dev = netdev_priv(netdev);
	struct hinic3_txq *txq = NULL;
	u16 q_id = skb_get_queue_mapping(skb);

	if (unlikely(!netif_carrier_ok(netdev))) {
		dev_kfree_skb_any(skb);
		HINIC3_NIC_STATS_INC(nic_dev, tx_carrier_off_drop);
		return NETDEV_TX_OK;
	}

	if (unlikely(q_id >= nic_dev->q_params.num_qps)) {
		txq = &nic_dev->txqs[0];
		HINIC3_NIC_STATS_INC(nic_dev, tx_invalid_qid);
		goto tx_drop_pkts;
	}
	txq = &nic_dev->txqs[q_id];

	return hinic3_send_one_skb(skb, netdev, txq);

tx_drop_pkts:
	dev_kfree_skb_any(skb);
	u64_stats_update_begin(&txq->txq_stats.syncp);
	txq->txq_stats.dropped++;
	u64_stats_update_end(&txq->txq_stats.syncp);

	return NETDEV_TX_OK;
}

static inline void tx_free_skb(struct hinic3_nic_dev *nic_dev,
			       struct hinic3_tx_info *tx_info)
{
	tx_unmap_skb(nic_dev, tx_info->skb, tx_info->valid_nr_frags,
		     tx_info->dma_info);
	dev_kfree_skb_any(tx_info->skb);
	tx_info->skb = NULL;
}

static void free_all_tx_skbs(struct hinic3_nic_dev *nic_dev, u32 sq_depth,
			     struct hinic3_tx_info *tx_info_arr)
{
	struct hinic3_tx_info *tx_info = NULL;
	u32 idx;

	for (idx = 0; idx < sq_depth; idx++) {
		tx_info = &tx_info_arr[idx];
		if (tx_info->skb)
			tx_free_skb(nic_dev, tx_info);
	}
}

int hinic3_tx_poll(struct hinic3_txq *txq, int budget)
{
	struct hinic3_nic_dev *nic_dev = netdev_priv(txq->netdev);
	struct hinic3_tx_info *tx_info = NULL;
	u64 tx_bytes = 0, wake = 0, nr_pkts = 0;
	int pkts = 0;
	u16 wqebb_cnt = 0;
	u16 hw_ci, sw_ci = 0, q_id = txq->sq->q_id;

	hw_ci = hinic3_get_sq_hw_ci(txq->sq);
	dma_rmb();
	sw_ci = hinic3_get_sq_local_ci(txq->sq);

	do {
		tx_info = &txq->tx_info[sw_ci];

		/* Whether all of the wqebb of this wqe is completed */
		if (hw_ci == sw_ci ||
		    ((hw_ci - sw_ci) & txq->q_mask) < tx_info->wqebb_cnt)
			break;

		sw_ci = (sw_ci + tx_info->wqebb_cnt) & (u16)txq->q_mask;
		prefetch(&txq->tx_info[sw_ci]);

		wqebb_cnt += tx_info->wqebb_cnt;

		tx_bytes += tx_info->num_bytes;
		nr_pkts += tx_info->num_pkts;
		pkts++;

		tx_free_skb(nic_dev, tx_info);
	} while (likely(pkts < budget));

	hinic3_update_sq_local_ci(txq->sq, wqebb_cnt);

	if (unlikely(__netif_subqueue_stopped(nic_dev->netdev, q_id) &&
		     hinic3_get_sq_free_wqebbs(txq->sq) >= 1 &&
		     test_bit(HINIC3_INTF_UP, &nic_dev->flags))) {
		struct netdev_queue *netdev_txq =
				netdev_get_tx_queue(txq->netdev, q_id);

		__netif_tx_lock(netdev_txq, smp_processor_id());
		/* To avoid re-waking subqueue with xmit_frame */
		if (__netif_subqueue_stopped(nic_dev->netdev, q_id)) {
			netif_wake_subqueue(nic_dev->netdev, q_id);
			wake++;
		}
		__netif_tx_unlock(netdev_txq);
	}

	u64_stats_update_begin(&txq->txq_stats.syncp);
	txq->txq_stats.bytes += tx_bytes;
	txq->txq_stats.packets += nr_pkts;
	txq->txq_stats.wake += wake;
	u64_stats_update_end(&txq->txq_stats.syncp);

	return pkts;
}

void hinic3_set_txq_cos(struct hinic3_nic_dev *nic_dev, u16 start_qid,
			u16 q_num, u8 cos)
{
	u16 idx;

	for (idx = 0; idx < q_num; idx++)
		nic_dev->txqs[idx + start_qid].cos = cos;
}

#define HINIC3_BDS_PER_SQ_WQEBB	\
	(HINIC3_SQ_WQEBB_SIZE / sizeof(struct hinic3_sq_bufdesc))

int hinic3_alloc_txqs_res(struct hinic3_nic_dev *nic_dev, u16 num_sq,
			  u32 sq_depth, struct hinic3_dyna_txq_res *txqs_res)
{
	struct hinic3_dyna_txq_res *tqres = NULL;
	int idx, i;
	u64 size;

	for (idx = 0; idx < num_sq; idx++) {
		tqres = &txqs_res[idx];

		size = sizeof(*tqres->tx_info) * sq_depth;
		tqres->tx_info = kzalloc(size, GFP_KERNEL);
		if (!tqres->tx_info) {
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Failed to alloc txq%d tx info\n", idx);
			goto err_out;
		}

		size = sizeof(*tqres->bds) *
			(sq_depth * HINIC3_BDS_PER_SQ_WQEBB +
			 HINIC3_MAX_SQ_SGE);
		tqres->bds = kzalloc(size, GFP_KERNEL);
		if (!tqres->bds) {
			kfree(tqres->tx_info);
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Failed to alloc txq%d bds info\n", idx);
			goto err_out;
		}
	}

	return 0;

err_out:
	for (i = 0; i < idx; i++) {
		tqres = &txqs_res[i];

		kfree(tqres->bds);
		kfree(tqres->tx_info);
	}

	return -ENOMEM;
}

void hinic3_free_txqs_res(struct hinic3_nic_dev *nic_dev, u16 num_sq,
			  u32 sq_depth, struct hinic3_dyna_txq_res *txqs_res)
{
	struct hinic3_dyna_txq_res *tqres = NULL;
	int idx;

	for (idx = 0; idx < num_sq; idx++) {
		tqres = &txqs_res[idx];

		free_all_tx_skbs(nic_dev, sq_depth, tqres->tx_info);
		kfree(tqres->bds);
		kfree(tqres->tx_info);
	}
}

int hinic3_configure_txqs(struct hinic3_nic_dev *nic_dev, u16 num_sq,
			  u32 sq_depth, struct hinic3_dyna_txq_res *txqs_res)
{
	struct hinic3_dyna_txq_res *tqres = NULL;
	struct hinic3_txq *txq = NULL;
	u16 q_id;
	u32 idx;

	for (q_id = 0; q_id < num_sq; q_id++) {
		txq = &nic_dev->txqs[q_id];
		tqres = &txqs_res[q_id];

		txq->q_depth = sq_depth;
		txq->q_mask = sq_depth - 1;

		txq->tx_info = tqres->tx_info;
		for (idx = 0; idx < sq_depth; idx++)
			txq->tx_info[idx].dma_info =
				&tqres->bds[idx * HINIC3_BDS_PER_SQ_WQEBB];

		txq->sq = hinic3_get_nic_queue(nic_dev->hwdev, q_id, HINIC3_SQ);
		if (!txq->sq) {
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Failed to get %u sq\n", q_id);
			return -EFAULT;
		}
	}

	return 0;
}

int hinic3_alloc_txqs(struct net_device *netdev)
{
	struct hinic3_nic_dev *nic_dev = netdev_priv(netdev);
	struct pci_dev *pdev = nic_dev->pdev;
	struct hinic3_txq *txq = NULL;
	u16 q_id, num_txqs = nic_dev->max_qps;
	u64 txq_size;

	txq_size = num_txqs * sizeof(*nic_dev->txqs);
	if (!txq_size) {
		nic_err(&pdev->dev, "Cannot allocate zero size txqs\n");
		return -EINVAL;
	}

	nic_dev->txqs = kzalloc(txq_size, GFP_KERNEL);
	if (!nic_dev->txqs) {
		nic_err(&pdev->dev, "Failed to allocate txqs\n");
		return -ENOMEM;
	}

	for (q_id = 0; q_id < num_txqs; q_id++) {
		txq = &nic_dev->txqs[q_id];
		txq->netdev = netdev;
		txq->q_id = q_id;
		txq->q_depth = nic_dev->q_params.sq_depth;
		txq->q_mask = nic_dev->q_params.sq_depth - 1;
		txq->dev = &pdev->dev;

		txq_stats_init(txq);
	}

	return 0;
}

void hinic3_free_txqs(struct net_device *netdev)
{
	struct hinic3_nic_dev *nic_dev = netdev_priv(netdev);

	kfree(nic_dev->txqs);
}

static bool is_hw_complete_sq_process(struct hinic3_io_queue *sq)
{
	u16 sw_pi, hw_ci;

	sw_pi = hinic3_get_sq_local_pi(sq);
	hw_ci = hinic3_get_sq_hw_ci(sq);

	return sw_pi == hw_ci;
}

#define HINIC3_FLUSH_QUEUE_TIMEOUT	1000
static int hinic3_stop_sq(struct hinic3_txq *txq)
{
	struct hinic3_nic_dev *nic_dev = netdev_priv(txq->netdev);
	unsigned long timeout;
	int err;

	timeout = msecs_to_jiffies(HINIC3_FLUSH_QUEUE_TIMEOUT) + jiffies;
	do {
		if (is_hw_complete_sq_process(txq->sq))
			return 0;

		usleep_range(900, 1000); /* sleep 900 us ~ 1000 us */
	} while (time_before(jiffies, timeout));

	/* force hardware to drop packets */
	timeout = msecs_to_jiffies(HINIC3_FLUSH_QUEUE_TIMEOUT) + jiffies;
	do {
		if (is_hw_complete_sq_process(txq->sq))
			return 0;

		err = hinic3_force_drop_tx_pkt(nic_dev->hwdev);
		if (err)
			break;

		usleep_range(9900, 10000); /* sleep 9900 us ~ 10000 us */
	} while (time_before(jiffies, timeout));

	/* Avoid msleep takes too long and get a fake result */
	if (is_hw_complete_sq_process(txq->sq))
		return 0;

	return -EFAULT;
}

/* should stop transmit any packets before calling this function */
int hinic3_flush_txqs(struct net_device *netdev)
{
	struct hinic3_nic_dev *nic_dev = netdev_priv(netdev);
	u16 qid;
	int err;

	for (qid = 0; qid < nic_dev->q_params.num_qps; qid++) {
		err = hinic3_stop_sq(&nic_dev->txqs[qid]);
		if (err)
			nicif_err(nic_dev, drv, netdev,
				  "Failed to stop sq%u\n", qid);
	}

	return 0;
}

