/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_TXRX_H_
#define _NBL_TXRX_H_

#include <linux/indirect_call_wrapper.h>

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
#define NBL_RX_PAD				(NET_IP_ALIGN + NET_SKB_PAD)
#define NBL_RXBUF_MIN_ORDER			(10)
#define NBL_XDP_RX_HARD_BUFF			(NET_IP_ALIGN + NET_SKB_PAD)

#define NBL_TXD_DATALEN_BITS			16
#define NBL_TXD_DATALEN_MAX			BIT(NBL_TXD_DATALEN_BITS)

#define NBL_RX_BUFSZ				(2048)
#define NBL_RX_BUFSZ_LARGE			(4096)

/* support one page rcv two pkts for mtu 1500. Now only intel nic use the 192 headrom */
#define NBL_XDP_HEADROM_SIZE			(192)

#define NBL_BUFFER_HDR_LEN(rx_ring)		((rx_ring)->extheader_rx_len)

#define NBL_ETH_FRAME_MIN_SIZE			60

#define NBL_TX_TSO_MSS_MIN			(256)
#define NBL_TX_TSO_MSS_MAX			(16383)
#define NBL_DRACO_TX_TSO_MSS_MIN		(64)
#define NBL_DRACO_TX_TSO_PKT_MAX		(9622)
#define NBL_TX_TSO_L2L3L4_HDR_LEN_MIN		(42)
#define NBL_TX_TSO_L2L3L4_HDR_LEN_MAX		(128)
#define NBL_DRACO_TX_TSO_L2L3L4_HDR_LEN_MIN	(42)
#define NBL_DRACO_TX_TSO_L2L3L4_HDR_LEN_MAX	(255)
#define NBL_TX_CHECKSUM_OFFLOAD_L2L3L4_HDR_LEN_MAX (255)
#define NBL_DRACO_TX_CHECKSUM_OFFLOAD_L2L3L4_HDR_LEN_MAX (255)
#define IP_VERSION_V4				(4)
#define NBL_TX_FLAGS_TSO			BIT(0)
#define NBL_TX_FLAGS_IPV4			BIT(1)
#define NBL_TX_FLAGS_IPV6			BIT(2)

#define NBL_TX_TOTAL_HEADERLEN_SHIFT		24
#define NBL_TX_TSO_SHIFT			15

#define NBL_RX_DMA_ATTR				(DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)

#define NBL_KTLS_SYNC_PKT_LEN			30
#define NBL_KTLS_PER_CELL_LEN			4096
#define NBL_KTLS_MAX_CELL_LEN			6144

#define NBL_KTLS_INIT_LEN_LEONIS		52
#define NBL_KTLS_INIT_LEN_DRACO			60
#define NBL_KTLS_SYNC_LEN_LEONIS		18
#define NBL_KTLS_SYNC_LEN_DRACO			58

#define NBL_TX_EXTHEADER_LEN_DEFAULT		12
#define NBL_TX_EXTHEADER_LEN_DRACO		16
#define NBL_RX_EXTHEADER_LEN_DEFAULT		12
#define NBL_RX_EXTHEADER_LEN_DRACO_HALF_OFFLOAD	16

/* TX outer IP header type */
enum nbl_tx_oipt {
	NBL_TX_OIPT_NONE = 0x0,
	NBL_TX_OIPT_IPV6 = 0x1,
	NBL_TX_OIPT_IPV4 = 0x2,
	NBL_TX_OIPT_RSV  = 0x3
};

/* TX tunnel type */
enum nbl_tx_tunnel_type {
	NBL_TX_L4TUNT_NOT_TUNNEL = 0x0,
	NBL_TX_L4TUNT_UDP_TUNNEL  = 0x1,
	NBL_TX_L4TUNT_GRE_TUNNEL  = 0x2,
	NBL_TX_L4TUNT_RSV  = 0x3
};

#define NBL_RX_PTYPE_TNL_MASK			(0x80)
#define NBL_RX_PTYPE_TNL_BASE_MASK		(0x40)
#define NBL_RX_PTYPE_TNL_L3_MASK		(0x20)
#define NBL_RX_PTYPE_NXT_PROTO_MASK		(0x10)
#define NBL_RX_PTYPE_L3_MASK			(0x8)
#define NBL_RX_PTYPE_L4_MASK			(0x2)
#define NBL_RX_PTYPE_UDP_TUNNEL_MASK		(0xC0)
#define NBL_RX_PTYPE_UDP_TUNNEL_L4_MASK (NBL_RX_PTYPE_L4_MASK | NBL_RX_PTYPE_UDP_TUNNEL_MASK)
#define NBL_RX_PTYPE_TUNNEL_L4_MASK (NBL_RX_PTYPE_L4_MASK | NBL_RX_PTYPE_TNL_MASK)
/* low 2bit for l4 ptype, 0/1 is tcp/udp, 2/3 for others/unknown. So bit 1 means invalid l4 */
#define NBL_RX_PTYPE_VALID_L4			(0)
#define NBL_RX_PTYPE_VALID_L3			(0)
#define NBL_RX_PTYPE_UDP_TUNNEL			(0xC0)
#define NBL_RX_PTYPE_TUNNEL			(0x80)
#define NBL_RX_PTYPE_UDP_TUNNEL_VALID_L4	(NBL_RX_PTYPE_UDP_TUNNEL | NBL_RX_PTYPE_VALID_L4)
#define NBL_RX_PTYPE_TUNNEL_VALID_L4		(NBL_RX_PTYPE_TUNNEL | NBL_RX_PTYPE_VALID_L4)

enum {
	NBL_RX_PTYPE_NOT_TNL,
	NBL_RX_PTYPE_TNL,
};

enum {
	NBL_RX_PTYPE_TNL_BASE_IP_TUNNEL,
	NBL_RX_PTYPE_TNL_BASE_UDP_TUNNEL,
};

enum {
	NBL_RX_PTYPE_TNL_L3_IPV4,
	NBL_RX_PTYPE_TNL_L3_IPV6,
};

enum {
	NBL_RX_PTYPE_L3_IPV4,
	NBL_RX_PTYPE_L3_IPV6,
	NBL_RX_PTYPE_L3_OTHER,
	NBL_RX_PTYPE_L3_UNKNOWN,
};

enum {
	NBL_RX_PTYPE_L4_TCP,
	NBL_RX_PTYPE_L4_UDP,
	NBL_RX_PTYPE_L4_OTHER,
	NBL_RX_PTYPE_L4_UNKNOWN,
};

struct nbl_ktls_sync_packet {
	struct nbl_tx_extend_head_leonis pkthdr;
	struct nbl_ktls_sync_payload_leonis sync_payload;
	u8 redata[NBL_KTLS_MAX_CELL_LEN];
};

enum nbl_ktls_sync_retval {
	NBL_KTLS_SYNC_DONE,
	NBL_KTLS_SYNC_SKIP_NO_DATA,
	NBL_KTLS_SYNC_FAIL,
};

#define NBL_XDP_FLAG_TX			BIT(0)
#define NBL_XDP_FLAG_REDIRECT		BIT(1)
#define NBL_XDP_FLAG_DROP		BIT(2)
#define NBL_XDP_FLAG_OVERSIZE		BIT(3)
#define NBL_XDP_FLAG_MULTICAST		BIT(4)

struct nbl_xdp_output {
	u64 bytes;
	u16 flags;
};

DECLARE_STATIC_KEY_FALSE(nbl_xdp_locking_key);

static inline u16 nbl_unused_tx_desc_count(struct nbl_res_tx_ring *ring)
{
	u16 ntc = ring->next_to_clean;
	u16 ntu = ring->next_to_use;

	return ((ntc > ntu) ? 0 : ring->desc_num) + ntc - ntu - 1;
}

#if IS_ENABLED(CONFIG_TLS_DEVICE)
static inline bool nbl_ktls_device_offload(struct sk_buff *skb)
{
	return tls_is_skb_tx_device_offloaded(skb);
}
#endif

static inline void nbl_ktls_bigint_decrement(u8 *data, int len)
{
	int i;

	for (i = len - 1; i >= 0; i--) {
		if (data[i] == 0) {
			data[i] = 0xFF;
		} else {
			--data[i];
			break;
		}
	}
}

void nbl_res_fill_tx_extend_header_df200(void *hdr, void *param);
u16 nbl_res_parse_rx_extend_header_df200(struct nbl_res_rx_ring *ring, void *hdr,
					 struct sk_buff *skb);
void nbl_res_fill_tx_extend_header_vm(void *hdr, void *param);
u16 nbl_res_parse_rx_extend_header_vm(struct nbl_res_rx_ring *ring, void *hdr,
				      struct sk_buff *skb);
u16 nbl_res_parse_rx_extend_header_leonis(struct nbl_res_rx_ring *ring, void *hdr,
					  struct sk_buff *skb);
u16 nbl_res_parse_rx_extend_header_draco(struct nbl_res_rx_ring *ring, void *hdr,
					 struct sk_buff *skb);
void nbl_res_fill_ktls_init_payload_leonis(void *init_payload,
					   struct nbl_ktls_offload_context_tx *priv_tx);
void nbl_res_fill_ktls_init_payload_draco(void *init_payload,
					  struct nbl_ktls_offload_context_tx *priv_tx);
void nbl_res_fill_ktls_sync_payload_draco(void *sync_payload,
					  struct nbl_ktls_offload_context_tx *priv_tx);
netdev_features_t nbl_res_txrx_features_check_df200_common(struct sk_buff *skb,
							   struct net_device *dev,
							   netdev_features_t features);
#define NBL_CALL_RX_PARSE(f, ...)	\
	INDIRECT_CALL_2(f, nbl_res_parse_rx_extend_header_leonis, \
			nbl_res_parse_rx_extend_header_draco, __VA_ARGS__)

#define NBL_CALL_KTLS_INIT(f, ...)	\
	INDIRECT_CALL_2(f, nbl_res_fill_ktls_init_payload_leonis, \
			nbl_res_fill_ktls_init_payload_draco, __VA_ARGS__)

static inline
struct nbl_res_tx_ring *nbl_res_txrx_select_xdp_ring(struct nbl_txrx_mgt *txrx_mgt)
{
	int ring_idx;
	int cpu_id = smp_processor_id();
	struct nbl_res_tx_ring *xdp_ring;

	if (!txrx_mgt->xdp_ring_num)
		return NULL;

	if (static_key_enabled(&nbl_xdp_locking_key))
		ring_idx = cpu_id % txrx_mgt->xdp_ring_num;
	else
		ring_idx = cpu_id;

	xdp_ring = txrx_mgt->tx_rings[ring_idx + txrx_mgt->xdp_ring_offset];
	return xdp_ring;
}

static inline bool nbl_res_txrx_is_xdp_ring(struct nbl_res_tx_ring *ring)
{
	return READ_ONCE(ring->xdp_prog) ? true : false;
}

netdev_features_t nbl_res_txrx_features_check_leonis(struct sk_buff *skb,
						     struct net_device *dev,
						     netdev_features_t features);

netdev_features_t nbl_res_txrx_features_check_draco(struct sk_buff *skb,
						    struct net_device *dev,
						    netdev_features_t features);

#if IS_ENABLED(CONFIG_TLS_DEVICE)
bool nbl_ktls_send_resync_packet_leonis(struct nbl_resource_mgt *res_mgt,
					struct nbl_res_tx_ring *tx_ring,
					struct nbl_ktls_offload_context_tx *priv_tx,
					struct nbl_tx_resync_info *info);
bool nbl_ktls_send_resync_packet_draco(struct nbl_resource_mgt *res_mgt,
				       struct nbl_res_tx_ring *tx_ring,
				       struct nbl_ktls_offload_context_tx *priv_tx,
				       struct nbl_tx_resync_info *info);
#endif

int nbl_txrx_mgt_init_leonis(struct nbl_resource_mgt *res_mgt);
int nbl_txrx_mgt_init_draco(struct nbl_resource_mgt *res_mgt);

#if IS_ENABLED(CONFIG_TLS_DEVICE)
static inline void nbl_resync_update_sn(struct net_device *netdev, struct sk_buff *skb, u16 offset)
{
	struct ethhdr *eth = (struct ethhdr *)(skb->data);
	struct net *net = dev_net(netdev);
	struct sock *sk;
	struct tls_context *tls_ctx;
	struct nbl_ktls_offload_context_rx **ctx;
	struct nbl_ktls_offload_context_rx *priv;
	struct iphdr *iph;
	struct tcphdr *th;
	int depth = 0;
	__be32 seq;

	skb->mac_len = ETH_HLEN;
	(void)__vlan_get_protocol(skb, eth->h_proto, &depth);
	iph = (struct iphdr *)(skb->data + depth);

	if (iph->version == 4) {
		depth += iph->ihl * 4;
		th = (void *)iph + iph->ihl * 4;
		sk = inet_lookup_established(net, net->ipv4.tcp_death_row.hashinfo,
					     iph->saddr, th->source, iph->daddr,
					     th->dest, netdev->ifindex);
	} else {
		struct ipv6hdr *ipv6h = (struct ipv6hdr *)iph;

		depth += sizeof(struct ipv6hdr);
		th = (void *)ipv6h + sizeof(struct ipv6hdr);
		sk = __inet6_lookup_established(net, net->ipv4.tcp_death_row.hashinfo,
						&ipv6h->saddr, th->source,
						&ipv6h->daddr, ntohs(th->dest),
						netdev->ifindex, 0);
	}

	depth += th->doff * 4;
	if (unlikely(!sk))
		return;

	if (unlikely(sk->sk_state == TCP_TIME_WAIT))
		goto unref;
	seq = th->seq;
	seq = htonl(ntohl(seq) + offset - depth - 1);
	tls_offload_rx_resync_request(sk, seq);
	tls_ctx = tls_get_ctx(sk);
	ctx = __tls_driver_ctx(tls_ctx, TLS_OFFLOAD_CTX_DIR_RX);
	priv = *ctx;
	priv->tcp_seq = ntohl(th->seq);

unref:
	sock_gen_put(sk);
}
#endif

#endif
