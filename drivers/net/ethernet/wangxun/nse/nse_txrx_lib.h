/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_TXRX_LIB_H_
#define _NSE_TXRX_LIB_H_
#include "nse.h"

/**
 * nse_test_staterr - tests bits in Rx descriptor status and error fields
 * @status_err_n: Rx descriptor status_error0 or status_error1 bits
 * @stat_err_bits: value to mask
 *
 * This function does some fast chicanery in order to return the
 * value of the mask which is really only used for boolean tests.
 * The status_error_len doesn't need to be shifted because it begins
 * at offset zero.
 */
static inline bool
nse_test_staterr(__le16 status_err_n, const u16 stat_err_bits)
{
	return !!(status_err_n & cpu_to_le16(stat_err_bits));
}

static inline __le64
nse_build_ctob(struct nse_ring __maybe_unused *tx_ring, u64 cmd_type_offset_bsz,
	       u64 td_tlen, unsigned int size, bool __maybe_unused first_td)
{
	return cpu_to_le64((NSE_TX_DESC_DTYPE_DATA << NSE_TXD_DTYPE_S) |
				cmd_type_offset_bsz |
				((td_tlen << NSE_TXD_TLEN_S) & NSE_TXD_TLEN_M) |
				(((u64)size << NSE_TXD_BSIZE_S) & NSE_TXD_BSIZE_M));
}

/**
 * nse_get_vlan_tag_from_rx_desc - get VLAN from Rx flex descriptor
 * @rx_desc: Rx 32b flex descriptor with RXDID=2
 *
 * The OS and current PF implementation only support stripping a single VLAN tag
 * at a time, so there should only ever be 0 or 1 tags in the l2tag* fields. If
 * one is found return the tag, else return 0 to mean no VLAN tag was found.
 */
static inline u16
nse_get_vlan_tag_from_rx_desc(union nse_32b_rx_desc *rx_desc, u8 *is_vlan)
{
	u16 stat_err_bits;

	stat_err_bits = BIT(NSE_RXD_STATUS0_L2TAG1P_S);
	if (nse_test_staterr(rx_desc->wb.status_error0, stat_err_bits)) {
		*is_vlan = 1;
		return le16_to_cpu(rx_desc->wb.l2tag1_nextp);
	}

	stat_err_bits = BIT(NSE_RXD_STATUS1_L2TAG2P_S);
	if (rx_desc->wb.status_error1 & stat_err_bits) {
		*is_vlan = 1;
		return le16_to_cpu(rx_desc->wb.l2tag2_2nd);
	}

	return 0;
}

void nse_xdp_ring_update_tail(struct nse_ring *xdp_ring);

void nse_finalize_xdp_rx(struct nse_ring *rx_ring, unsigned int xdp_res);
int nse_xmit_xdp_buff(struct xdp_buff *xdp, struct nse_ring *xdp_ring);
int nse_xmit_xdp_ring(void *data, u16 size, struct nse_ring *xdp_ring, bool more);
void nse_release_rx_desc(struct nse_ring *rx_ring, u16 val);
void nse_rx_ring_sync_tail_after_enable(struct nse_ring *rx_ring);
int nse_process_skb_fields(struct nse_ring *rx_ring,
		       union nse_32b_rx_desc *rx_desc,
		       struct sk_buff *skb, u8 ptype);
void
nse_receive_skb(struct nse_ring *rx_ring, struct sk_buff *skb, u16 vlan_tag,
				u8 is_vlan);

void nse_dump_rx_desc(struct device *dev, u16 q_idx, u16 desc_idx, union nse_32b_rx_desc *rx_desc);
void nse_dump_tx_desc(struct device *dev, u16 q_idx, u16 desc_idx, struct nse_tx_desc *tx_desc);
void nse_dump_lan_txcq_desc(struct device *dev, u16 q_idx, u32 desc_idx,
			    struct nse_lan_txcq_desc *desc);

#endif

