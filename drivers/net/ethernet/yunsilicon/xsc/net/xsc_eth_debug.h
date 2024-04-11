/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_ETH_DEBUG_H
#define XSC_ETH_DEBUG_H

#include "common/xsc_core.h"
#include <linux/netdevice.h>
#include "xsc_eth.h"

static bool debug;
#define FUN_LINE_FMT    "%s %d "

#ifdef XSC_DEBUG
#define ETH_DEBUG_LOG(fmt, ...) \
	do { \
		if (debug) \
			pr_info(FUN_LINE_FMT fmt, __func__, __LINE__, ##__VA_ARGS__); \
	} while (0)
#else
#define ETH_DEBUG_LOG(fmt, ...) do { } while (0)
#endif

#define XSC_MSG_LEVEL	(NETIF_MSG_LINK) // | NETIF_MSG_HW)

#define xsc_eth_dbg(mlevel, priv, format, ...)                    \
do {                                                            \
	if (NETIF_MSG_##mlevel & (priv)->msglevel)              \
		netdev_warn(priv->netdev, format,               \
			    ##__VA_ARGS__);                     \
} while (0)

#define WQE_CSEG_DUMP(seg_name, seg)						\
	do {                                                                    \
		ETH_DEBUG_LOG("dump %s:\n", seg_name);                          \
		ETH_DEBUG_LOG("cseg->has_pph: %d\n", (seg)->has_pph);             \
		ETH_DEBUG_LOG("cseg->so_type: %d\n", (seg)->so_type);             \
		ETH_DEBUG_LOG("cseg->so_hdr_len: %d\n", (seg)->so_hdr_len);       \
		ETH_DEBUG_LOG("cseg->so_data_size: %d\n", (seg)->so_data_size);   \
		ETH_DEBUG_LOG("cseg->msg_opcode: %d\n", (seg)->msg_opcode);      \
		ETH_DEBUG_LOG("cseg->wqe_id: %d\n", (seg)->wqe_id);               \
		ETH_DEBUG_LOG("cseg->ds_data_num: %d\n", (seg)->ds_data_num);     \
		ETH_DEBUG_LOG("cseg->msg_len: %d\n", (seg)->msg_len);             \
	} while (0)

#define WQE_DSEG_DUMP(seg_name, seg)						\
	do {                                                                    \
		ETH_DEBUG_LOG("dump %s:\n", seg_name);                          \
		ETH_DEBUG_LOG("dseg->va: %#llx\n", (seg)->va);                      \
		ETH_DEBUG_LOG("dseg->in_line: %d\n", (seg)->in_line);             \
		ETH_DEBUG_LOG("dseg->mkey: %d\n", (seg)->mkey);                   \
		ETH_DEBUG_LOG("dseg->seg_len: %d\n", (seg)->seg_len);             \
	} while (0)

static inline void skbdata_debug_dump(struct sk_buff *skb, u16 headlen, int direct)
{
	if (!debug)
		return;

	netdev_info(skb->dev, "pkt[%s]: skb_len=%d, head_len=%d\n",
		    (direct ? "tx" : "rx"), skb->len, headlen);

	if (skb) {
		char *buf = skb->data;
		int i, j;
		int pos;

		for (i = 0; i < headlen; i++) {
			if (i % 16 == 0)
				pr_info("%#4.4x  ", i);
			pr_info("%2.2x  ", ((unsigned char *)buf)[i]);
		}

		pr_info("\n");

		pos = headlen;
		for (j = 0; j < skb_shinfo(skb)->nr_frags; j++) {
			skb_frag_t *frag = &skb_shinfo(skb)->frags[j];
			int fsz = skb_frag_size(frag);

			buf = (char *)(page_address(frag->bv_page) + frag->bv_offset);
			for (i = 0; i < fsz; i++) {
				if (i % 16 == 0)
					pr_info("%#4.4x  ", i);
				pr_info("%2.2x  ", ((unsigned char *)buf)[i]);
			}

			pos += frag->bv_len;
		}
		pr_info("\n");
	}
}

#define ETH_SQ_STATE(sq)						\
	do { \
		if (test_bit(__QUEUE_STATE_STACK_XOFF, &(sq)->txq->state))	\
			ETH_DEBUG_LOG("sq is __QUEUE_STATE_STACK_XOFF\n");	\
		else if (test_bit(__QUEUE_STATE_DRV_XOFF, &(sq)->txq->state))   \
			ETH_DEBUG_LOG("sq is __QUEUE_STATE_DRV_XOFF\n");	\
		else								\
			ETH_DEBUG_LOG("sq is %ld\n", (sq)->txq->state);		\
	} while (0)

static inline void xsc_pkt_pph_dump(char *data, int len)
{
	int i;

	if (!debug)
		return;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			pr_info("%#4.4x  ", i);
		pr_info("%2.2x  ", ((unsigned char *)data)[i]);
	}
}

#endif /* XSC_ETH_DEBUG_H */
