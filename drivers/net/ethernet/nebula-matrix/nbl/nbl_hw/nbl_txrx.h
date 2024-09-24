/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_TXRX_H_
#define _NBL_TXRX_H_

#include "nbl_resource.h"

#define NBL_RING_TO_COMMON(ring)	((ring)->common)
#define NBL_RING_TO_DEV(ring)		((ring)->dma_dev)
#define NBL_RING_TO_DMA_DEV(ring)	((ring)->dma_dev)

#define NBL_MIN_DESC_NUM			128
#define NBL_MAX_DESC_NUM			32768

#define NBL_PACKED_DESC_F_NEXT			1
#define NBL_PACKED_DESC_F_WRITE			2

#define DEFAULT_MAX_PF_QUEUE_PAIRS_NUM		16
#define DEFAULT_MAX_VF_QUEUE_PAIRS_NUM		2

#define NBL_PACKED_DESC_F_AVAIL			7
#define NBL_PACKED_DESC_F_USED			15

#define NBL_TX_DESC(tx_ring, i)			(&(((tx_ring)->desc)[i]))
#define NBL_RX_DESC(rx_ring, i)			(&(((rx_ring)->desc)[i]))
#define NBL_TX_BUF(tx_ring, i)			(&(((tx_ring)->tx_bufs)[i]))
#define NBL_RX_BUF(rx_ring, i)			(&(((rx_ring)->rx_bufs)[i]))

#define DESC_NEEDED				(MAX_SKB_FRAGS + 4)

#define NBL_TX_POLL_WEIGHT			256

#define NBL_RX_BUF_256				256
#define NBL_RX_HDR_SIZE				NBL_RX_BUF_256
#define NBL_RX_BUF_WRITE			16
#define NBL_RX_PAD				(NET_IP_ALIGN + NET_SKB_PAD - NBL_BUFFER_HDR_LEN)

#define NBL_TXD_DATALEN_BITS			16
#define NBL_TXD_DATALEN_MAX			BIT(NBL_TXD_DATALEN_BITS)

#define MAX_DESC_NUM_PER_PKT			(32)

#define NBL_RX_BUFSZ				(2048)
#define NBL_RX_BUFSZ_ORDER			(11)

#define NBL_BUFFER_HDR_LEN			(sizeof(struct nbl_rx_extend_head))

#define NBL_ETH_FRAME_MIN_SIZE			60

#define NBL_TX_TSO_MSS_MIN			(256)
#define NBL_TX_TSO_MSS_MAX			(16383)
#define NBL_TX_TSO_L2L3L4_HDR_LEN_MIN		(42)
#define NBL_TX_TSO_L2L3L4_HDR_LEN_MAX		(128)
#define NBL_TX_CHECKSUM_OFFLOAD_L2L3L4_HDR_LEN_MAX (255)
#define IP_VERSION_V4				(4)
#define NBL_TX_FLAGS_TSO			BIT(0)

#define NBL_TX_TOTAL_HEADERLEN_SHIFT		24

#define NBL_RX_DMA_ATTR				(DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)
#define NBL_RX_PAGE_PER_FRAGS			(PAGE_SIZE >> NBL_RX_BUFSZ_ORDER)

/* TX inner IP header type */
enum nbl_tx_iipt {
	NBL_TX_IIPT_NONE = 0x0,
	NBL_TX_IIPT_IPV6 = 0x1,
	NBL_TX_IIPT_IPV4 = 0x2,
	NBL_TX_IIPT_RSV  = 0x3
};

/* TX L4 packet type */
enum nbl_tx_l4t {
	NBL_TX_L4T_NONE = 0x0,
	NBL_TX_L4T_TCP  = 0x1,
	NBL_TX_L4T_UDP  = 0x2,
	NBL_TX_L4T_RSV  = 0x3
};

struct nbl_tx_hdr_param {
	u8 l4s_pbrac_mode;
	u8 l4s_hdl_ind;
	u8 l4s_sync_ind;
	u8 tso;
	u16 l4s_sid;
	u16 mss;
	u8 mac_len;
	u8 ip_len;
	u8 l4_len;
	u8 l4_type;
	u8 inner_ip_type;
	u8 l3_csum_en;
	u8 l4_csum_en;
	u16 total_hlen;
	u16 dport_id:10;
	u16 fwd:2;
	u16 dport:3;
	u16 rss_lag_en:1;
};

union nbl_tx_extend_head {
	struct {
		/* DW0 */
		u32 mac_len :5;
		u32 ip_len :5;
		u32 l4_len :4;
		u32 l4_type :2;
		u32 inner_ip_type :2;
		u32 external_ip_type :2;
		u32 external_ip_len :5;
		u32 l4_tunnel_type :2;
		u32 l4_tunnel_len :5;
		/* DW1 */
		u32 l4s_sid :10;
		u32 l4s_sync_ind :1;
		u32 l4s_redun_ind :1;
		u32 l4s_redun_head_ind :1;
		u32 l4s_hdl_ind :1;
		u32 l4s_pbrac_mode :1;
		u32 rsv0 :2;
		u32 mss :14;
		u32 tso :1;
		/* DW2 */
		/* if dport = NBL_TX_DPORT_ETH; dport_info = 0
		 * if dport = NBL_TX_DPORT_HOST; dport_info = host queue id
		 * if dport = NBL_TX_DPORT_ECPU; dport_info = ecpu queue_id
		 */
		u32 dport_info :11;
		/* if dport = NBL_TX_DPORT_ETH; dport_id[3:0] = eth port id, dport_id[9:4] = lag id
		 * if dport = NBL_TX_DPORT_HOST; dport_id[9:0] = host vsi_id
		 * if dport = NBL_TX_DPORT_ECPU; dport_id[9:0] = ecpu vsi_id
		 */
		u32 dport_id :10;
#define NBL_TX_DPORT_ID_LAG_OFFSET	(4)
		u32 dport :3;
#define NBL_TX_DPORT_ETH		(0)
#define NBL_TX_DPORT_HOST		(1)
#define NBL_TX_DPORT_ECPU		(2)
#define NBL_TX_DPORT_EMP		(3)
#define NBL_TX_DPORT_BMC		(4)
		u32 fwd :2;
#define NBL_TX_FWD_TYPE_DROP		(0)
#define NBL_TX_FWD_TYPE_NORMAL		(1)
#define NBL_TX_FWD_TYPE_RSV		(2)
#define NBL_TX_FWD_TYPE_CPU_ASSIGNED	(3)
		u32 rss_lag_en :1;
		u32 l4_csum_en :1;
		u32 l3_csum_en :1;
		u32 rsv1 :3;
	};
	struct bootis_hdr {
		/* DW0 */
		u32 mac_len :5;
		u32 ip_len :5;
		u32 l4_len :4;
		u32 l4_type :2;
		u32 inner_ip_type :2;
		u32 external_ip_type :2;
		u32 external_ip_len :5;
		u32 l4_tunnel_type :2;
		u32 l4_tunnel_len :5;
		/* DW1 */
		u32 l4s_sid :10;
		u32 inner_l3_cs :1;
		u32 inner_l4_cs :1;
		u32 dport :3;
		u32 tag_idx :2;
		u32 mss :14;
		u32 tso :1;
		/* DW2 */
		u32 dport_info :11;
		u32 dport_id :12;
		u32 tag_en :1;
		u32 fwd :2;
		u32 rss_lag_en :1;
		u32 l4_csum_en :1;
		u32 l3_csum_en :1;
		u32 rsv1 :3;
	} bootis;
};

struct nbl_rx_extend_head {
	/* DW0 */
	/* 0x0:eth, 0x1:host, 0x2:ecpu, 0x3:emp, 0x4:bcm */
	uint32_t sport :3;
	uint32_t dport_info :11;
	/* sport = 0, sport_id[3:0] = eth id,
	 * sport = 1, sport_id[9:0] = host vsi_id,
	 * sport = 2, sport_id[9:0] = ecpu vsi_id,
	 */
	uint32_t sport_id :10;
	/* 0x0:drop, 0x1:normal, 0x2:cpu upcall */
	uint32_t fwd :2;
	uint32_t rsv0 :6;
	/* DW1 */
	uint32_t error_code :6;
	uint32_t ptype :10;
	uint32_t profile_id :4;
	uint32_t checksum_status :1;
	uint32_t rsv1 :1;
	uint32_t l4s_sid :10;
	/* DW2 */
	uint32_t rsv3 :2;
	uint32_t l4s_hdl_ind :1;
	uint32_t l4s_tcp_offset :14;
	uint32_t l4s_resync_ind :1;
	uint32_t l4s_check_ind :1;
	uint32_t l4s_dec_ind :1;
	uint32_t rsv2 :4;
	uint32_t num_buffers :8;
} __packed;

static inline u16 nbl_unused_rx_desc_count(struct nbl_res_rx_ring *ring)
{
	u16 ntc = ring->next_to_clean;
	u16 ntu = ring->next_to_use;

	return ((ntc > ntu) ? 0 : ring->desc_num) + ntc - ntu - 1;
}

static inline u16 nbl_unused_tx_desc_count(struct nbl_res_tx_ring *ring)
{
	u16 ntc = ring->next_to_clean;
	u16 ntu = ring->next_to_use;

	return ((ntc > ntu) ? 0 : ring->desc_num) + ntc - ntu - 1;
}

#endif
