/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_ETHTOOL_H_
#define _NSE_ETHTOOL_H_

struct nse_stats {
	char stat_string[ETH_GSTRING_LEN];
	int sizeof_stat;
	int stat_offset;
};

#define NSE_STAT(_type, _name, _stat) { \
	.stat_string = _name, \
	.sizeof_stat = sizeof_field(_type, _stat), \
	.stat_offset = offsetof(_type, _stat) \
}

#define NSE_VSI_STAT(_name, _stat) \
		NSE_STAT(struct nse_vsi, _name, _stat)
#define NSE_PF_STAT(_name, _stat) \
		NSE_STAT(struct nse_pf, _name, _stat)

#ifdef UNIFIED_STATS
#define PICK(legacy_stat, unified_stat) unified_stat
#else
#define PICK(legacy_stat, unified_stat) legacy_stat
#endif

/* VSI stats ( HW stats or SW stats ) */
#define NSE_VSI_RX_PKTS				"rx_packets"
#define NSE_VSI_RX_BYTES			"rx_bytes"
#define NSE_VSI_RX_UNICAST			"rx_unicast"
#define NSE_VSI_RX_MULTICAST		"rx_multicast"
#define NSE_VSI_RX_BROADCAST		"rx_broadcast"
#define NSE_VSI_RX_DROPPED_ERR		PICK("rx_dropped_err", "rx-dropped-err_pkts")
#define NSE_VSI_RX_DROPPED_NO_DESC	PICK("rx_dropped_no_desc", "rx-dropped-no-desc_pkts")
#define NSE_VSI_RX_DROPPED_DPKT		PICK("rx_dropped_dpkt", "rx-dropped-dpkt_pkts")
#define NSE_VSI_RX_ALLOC_FAIL		PICK("rx_alloc_fail", "rx-buf-alloc-fail_events")
#define NSE_VSI_RX_PAGE_ALLOC_FAIL	PICK("rx_pg_alloc_fail", "rx-page-alloc-fail_events")
#ifdef NSE_ADD_PROBES
#define NSE_VSI_RX_PAGE_REUSE		"rx_page_reuse"
#endif

#define NSE_VSI_TX_PKTS				"tx_packets"
#define NSE_VSI_TX_BYTES			"tx_bytes"
#define NSE_VSI_TX_UNICAST			"tx_unicast"
#define NSE_VSI_TX_MULTICAST		"tx_multicast"
#define NSE_VSI_TX_BROADCAST		"tx_broadcast"
#define NSE_VSI_TX_LINEARIZE		PICK("tx_linearized", "tx-linearized_pkts")
#define NSE_VSI_TX_BUSY				PICK("tx_busy", "tx-busy_events")
#define NSE_VSI_TX_RESTART			"tx_restart"

#define NSE_VSI_RX_CSUM_GOOD		"rx_csum_good"
#define NSE_VSI_RX_CSUM_BAD			"rx_csum_bad"
#define NSE_VSI_FDIR_MATCH			"fdir_match"
#define NSE_VSI_FDIR_MISS			"fdir_miss"

/* HW port stats */
#define NSE_PORT_RX_PACKETS		PICK("rx_packets.nic", "port-rx_pkts")
#define NSE_PORT_RX_BYTES		PICK("rx_bytes.nic", "port-rx_bytes")
#define NSE_PORT_RX_UNICAST		PICK("rx_unicast.nic", "port-rx-unicast_pkts")
#define NSE_PORT_RX_MULTICAST		PICK("rx_multicast.nic", "port-rx-multicast_pkts")
#define NSE_PORT_RX_BROADCAST		PICK("rx_broadcast.nic", "port-rx-broadcast_pkts")
#define NSE_PORT_RX_SIZE_64		PICK("rx_size_64.nic", "port-rx_size-64_pkts")
#define NSE_PORT_RX_SIZE_127		PICK("rx_size_127.nic", "port-rx_size-127_pkts")
#define NSE_PORT_RX_SIZE_255		PICK("rx_size_255.nic", "port-rx_size-255_pkts")
#define NSE_PORT_RX_SIZE_511		PICK("rx_size_511.nic", "port-rx_size-511_pkts")
#define NSE_PORT_RX_SIZE_1023		PICK("rx_size_1023.nic", "port-rx_size-1023_pkts")
#define NSE_PORT_RX_SIZE_1023_MAX	PICK("rx_size_1024_to_max.nic", "port-rx_size-1024-to-max_pkts")
#define NSE_PORT_RX_ERRORS			PICK("rx_errors.nic", "port-rx_errors")
#define NSE_PORT_RX_LEN_ERRORS		PICK("rx_length_errors.nic", "port-rx-length_errors")
#define NSE_PORT_RX_CRC_ERRORS		PICK("rx_crc_errors.nic", "port-rx-crc_errors")
#define NSE_PORT_RX_RUNT_ERRORS		PICK("rx_runt_errors.nic", "port-rx-runt_errors")
#define NSE_PORT_RX_JABBER_ERRORS	PICK("rx_jabber_errors.nic", "port-rx-jabber_errors")

#define NSE_PORT_RX_DROPPED		PICK("rx_dropped.nic", "port-rx-dropped_pkts")

#define NSE_PORT_TX_PACKETS		PICK("tx_packets.nic", "port-tx_pkts")
#define NSE_PORT_TX_BYTES		PICK("tx_bytes.nic", "port-tx_bytes")
#define NSE_PORT_TX_UNICAST		PICK("tx_unicast.nic", "port-tx-unicast_pkts")
#define NSE_PORT_TX_MULTICAST		PICK("tx_multicast.nic", "port-tx-multicast_pkts")
#define NSE_PORT_TX_BROADCAST		PICK("tx_broadcast.nic", "port-tx-broadcast_pkts")
#define NSE_PORT_TX_SIZE_64		PICK("tx_size_64.nic", "port-tx_size-64_pkts")
#define NSE_PORT_TX_SIZE_127		PICK("tx_size_127.nic", "port-tx_size-127_pkts")
#define NSE_PORT_TX_SIZE_255		PICK("tx_size_255.nic", "port-tx_size-255_pkts")
#define NSE_PORT_TX_SIZE_511		PICK("tx_size_511.nic", "port-tx_size-511_pkts")
#define NSE_PORT_TX_SIZE_1023		PICK("tx_size_1023.nic", "port-tx_size-1023_pkts")
#define NSE_PORT_TX_SIZE_1023_MAX	PICK("tx_size_1024_to_max.nic", "port-tx_size-1024-to-max_pkts")
#define NSE_PORT_TX_UNDERFLOW_ERRORS	PICK("tx_underflow_errors.nic", "port-tx-underflow_errors")

#define NSE_PORT_TX_TIMEOUT		PICK("tx_timeout.nic", "port-tx-timeout_events")

#define NSE_PORT_TX_ERRORS		PICK("tx_errors.nic", "port-tx_errors")

#define NSE_PORT_RX_PAUSE			PICK("link_pause_rx.nic", "port-rx-pause_events")
#define NSE_PORT_RX_LINK_XOFF		PICK("link_xoff_rx.nic", "port-rx-xoff_events")
#define NSE_PORT_RX_LINK_XON		PICK("link_xon_rx.nic", "port-rx-xon_events")
#define NSE_PORT_TX_PAUSE			PICK("link_pause_tx.nic", "port-tx-pause_events")
#define NSE_PORT_TX_LINK_XOFF		PICK("link_xoff_tx.nic", "port-tx-xoff_events")
#define NSE_PORT_TX_LINK_XON		PICK("link_xon_tx.nic", "port-tx-xon_events")
#define NSE_PORT_RX_PFC				PICK("rx_priority.nic", "port-rx-prio_events")
#define NSE_PORT_RX_PRIO_XOFF	PICK("rx_priority_%u_xoff.nic", "port-rx-xoff_prio-%u_events")
#define NSE_PORT_RX_PRIO_XON		PICK("rx_priority_%u_xon.nic", "port-rx-xon_prio-%u_events")
#define NSE_PORT_TX_PFC				PICK("tx_priority.nic", "port-tx-prio_events")
#define NSE_PORT_TX_PRIO_XOFF	PICK("tx_priority_%u_xoff.nic", "port-tx-xoff_prio-%u_events")
#define NSE_PORT_TX_PRIO_XON		PICK("tx_priority_%u_xon.nic", "port-tx-xon_prio-%u_events")

#ifdef NSE_ADD_PROBES
#define NSE_PORT_TX_TCP_SEGMENTS	PICK("tx_tcp_segments.nic", "port-tx-tcp-segments_cnt")
#define NSE_PORT_TX_UDP_SEGMENTS	PICK("tx_udp_segments.nic", "port-tx-udp-segments_cnt")
#define NSE_PORT_RX_TCP_CSO		PICK("rx_tcp_cso.nic", "port-rx-tcp-csum-offload_cnt")
#define NSE_PORT_TX_TCP_CSO		PICK("tx_tcp_cso.nic", "port-tx-tcp-csum-offload_cnt")
#define NSE_PORT_RX_UDP_CSO		PICK("rx_udp_cso.nic", "port-rx-udp-csum-offload_cnt")
#define NSE_PORT_TX_UDP_CSO		PICK("tx_udp_cso.nic", "port-tx-udp-csum-offload_cnt")
#define NSE_PORT_RX_SCTP_CSO		PICK("rx_sctp_cso.nic", "port-rx-sctp-csum-offload_cnt")
#define NSE_PORT_TX_SCTP_CSO		PICK("tx_sctp_cso.nic", "port-tx-sctp-csum-offload_cnt")
#define NSE_PORT_RX_IP4_CSO		PICK("rx_ip4_cso.nic", "port-rx-ipv4-csum-offload_cnt")
#define NSE_PORT_TX_IP4_CSO		PICK("tx_ip4_cso.nic", "port-tx-ipv4-csum-offload_cnt")
#define NSE_PORT_RX_IP4_CSO_ERROR	PICK("rx_ip4_cso_error.nic", "port-rx-ipv4-csum_errors")
#define NSE_PORT_RX_TCP_CSO_ERROR	PICK("rx_tcp_cso_error.nic", "port-rx-tcp-csum_errors")
#define NSE_PORT_RX_UDP_CSO_ERROR	PICK("rx_udp_cso_error.nic", "port-rx-udp-csum_errors")
#define NSE_PORT_RX_SCTP_CSO_ERROR	PICK("rx_sctp_cso_error.nic", "port-rx-sctp-csum_errors")
#define NSE_PORT_TX_L3_CSO_ERROR	PICK("tx_l3_cso_err.nic", "port-tx-layer-3-csum_errors")
#define NSE_PORT_TX_L4_CSO_ERROR	PICK("tx_l4_cso_err.nic", "port-tx-layer-4-csum_errors")
#define NSE_PORT_RX_Q_VLANO		PICK("rx_vlano.nic", "port-rx-q-vlan-offload_pkts")
#define NSE_PORT_TX_Q_VLANO		PICK("tx_vlano.nic", "port-tx-q-vlan-offload_pkts")
#define NSE_PORT_RX_AD_VLANO		PICK("rx_ad_vlano.nic", "port-rx-ad-vlan-offload_pkts")
#define NSE_PORT_TX_AD_VLANO		PICK("tx_ad_vlano.nic", "port-tx-ad-vlan-offload_pkts")
#endif /* NSE_ADD_PROBES */

/* per-queue stats: struct nse_q_stats */
#define NSE_TXQ_PACKETS			PICK("tx_queue-%u.packets", "txq-%u.pkts")
#define NSE_TXQ_BYTES			PICK("tx_queue-%u.bytes", "txq-%u.bytes")
#define NSE_RXQ_PACKETS			PICK("rx_queue-%u.packets", "rxq-%u.pkts")
#define NSE_RXQ_BYTES			PICK("rx_queue-%u.bytes", "rxq-%u.bytes")
#ifdef NSE_ADD_PROBES
#define NSE_TXQ_NAPI_POLL		PICK("tx_queue-%u.napi_cnt", "txq-%u.napi_cnt")
#define NSE_RXQ_NAPI_POLL		PICK("rx_queue-%u.napi_cnt", "rxq-%u.napi_cnt")
#endif /* NSE_ADD_PROBES */

#define NSE_XDP_TXQ_PACKETS		PICK("xdp_tx_queue-%u.packets", "xdp_txq-%u.pkts")
#define NSE_XDP_TXQ_BYTES		PICK("xdp_tx_queue-%u.bytes", "xdp_txq-%u.bytes")
#ifdef NSE_ADD_PROBES
#define NSE_XDP_TXQ_NAPI_POLL	PICK("xdp_tx_queue-%u.napi_cnt", "xdp_txq-%u.napi_cnt")
#endif /* NSE_ADD_PROBES */

/* struct nse_cq_stats */
#define NSE_TXCQ_PACKETS		PICK("tx_cqueue-%u.packets", "tx_cq-%u.pkts")
#define NSE_TXCQ_BYTES			PICK("tx_cqueue-%u.bytes", "tx_cq-%u.bytes")
#define NSE_TXCQ_CQE_CNT		PICK("tx_cqueue-%u.cqe_cnt", "tx_cq-%u.cqe_cnt")
#define NSE_TXCQ_GEN_FLIP_CNT	PICK("tx_cqueue-%u.flip_cnt", "tx_cq-%u.flip_cnt")
#define NSE_TXCQ_TXQE_CNT		PICK("tx_cqueue-%u.txqe_cnt", "tx_cq-%u.txqe_cnt")
#ifdef NSE_ADD_PROBES
#define NSE_TXCQ_NAPI_POLL		PICK("tx_cqueue-%u.napi_cnt", "tx_cq-%u.napi_cnt")
#endif

#ifdef NSE_ADD_PROBES
/* macvlan stats */
#define L2_FWD_TX_PKTS1			PICK("l2-fwd-%s-tx.packets", "tx-l2-fwd_q-%s.pkts")
#define L2_FWD_TX_BYTES1		PICK("l2-fwd-%s-tx.bytes", "tx-l2-fwd_q-%s.bytes")
#define L2_FWD_TX_PKTS2			PICK("l2-fwd-%i-tx.packets", "tx-l2-fwd_q-%i.pkts")
#define L2_FWD_TX_BYTES2		PICK("l2-fwd-%i-tx.bytes", "tx-l2-fwd_q-%i.bytes")
#define L2_FWD_RX_PKTS1			PICK("l2-fwd-%s-rx.packets", "rx-l2-fwd_q-%s.pkts")
#define L2_FWD_RX_BYTES1		PICK("l2-fwd-%s-rx.bytes", "rx-l2-fwd_q-%s.bytes")
#define L2_FWD_RX_PKTS2			PICK("l2-fwd-%i-rx.packets", "rx-l2-fwd_q-%i.pkts")
#define L2_FWD_RX_BYTES2		PICK("l2-fwd-%i-rx_bytes", "rx-l2-fwd_q-%i_bytes")
#endif /* NSE_ADD_PROBES */

#endif /* !_NSE_ETHTOOL_H_ */
