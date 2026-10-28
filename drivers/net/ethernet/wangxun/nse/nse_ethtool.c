// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include <linux/ethtool.h>

#include "nse.h"
#include "nse_ethtool.h"
#include "nse_fltr.h"
#include "nse_irq.h"
#include "nse_lib.h"
#include "nse_dcb_lib.h"
#include "nse_dcb_nl.h"
#include "nse_fdir.h"

/* SELF-TEST */
enum nse_ethtool_test_id {
	NSE_ETH_TEST_REG = 0,
	NSE_ETH_TEST_EEPROM,
	NSE_ETH_TEST_INTR,
	NSE_ETH_TEST_LOOP,
	NSE_ETH_TEST_LINK,
};

static const char nse_gstrings_test[][ETH_GSTRING_LEN] = {
	"Register test  (offline)",
	"EEPROM test    (offline)",
	"Interrupt test (offline)",
	"Loopback test  (offline)",
	"Link test   (on/offline)",
};

#define NSE_TEST_LEN (sizeof(nse_gstrings_test) / ETH_GSTRING_LEN)

/* These PF_STATs might look like duplicates of some NETDEV_STATs,
 * but they aren't. This device is capable of supporting multiple
 * VSIs/netdevs on a single PF. The NETDEV_STATs are for individual
 * netdevs whereas the PF_STATs are for the physical function that's
 * hosting these netdevs.
 *
 * The PF_STATs are appended to the netdev stats only when ethtool -S
 * is queried on the base PF netdev.
 */
static const struct nse_stats nse_gstrings_lan_stats[] = {
	NSE_PF_STAT(NSE_PORT_RX_PACKETS, stats.rx_pkts_good_bad),
	NSE_PF_STAT(NSE_PORT_RX_BYTES, stats.rx_bytes_good_bad),
	NSE_PF_STAT(NSE_PORT_RX_UNICAST, stats.rx_unicast_good),
	NSE_PF_STAT(NSE_PORT_RX_MULTICAST, stats.rx_multicast_good),
	NSE_PF_STAT(NSE_PORT_RX_BROADCAST, stats.rx_broadcast_good),
	NSE_PF_STAT(NSE_PORT_RX_SIZE_64, stats.rx_64_good_bad),
	NSE_PF_STAT(NSE_PORT_RX_SIZE_127, stats.tx_64_to_127_good_bad),
	NSE_PF_STAT(NSE_PORT_RX_SIZE_255, stats.rx_128_to_255_good_bad),
	NSE_PF_STAT(NSE_PORT_RX_SIZE_511, stats.rx_256_to_511_good_bad),
	NSE_PF_STAT(NSE_PORT_RX_SIZE_1023, stats.rx_512_to_1023_good_bad),
	NSE_PF_STAT(NSE_PORT_RX_SIZE_1023_MAX, stats.rx_1024_to_max_good_bad),
	NSE_PF_STAT(NSE_PORT_RX_ERRORS, stats.rx_error),
	NSE_PF_STAT(NSE_PORT_RX_LEN_ERRORS, stats.rx_length_error),
	NSE_PF_STAT(NSE_PORT_RX_CRC_ERRORS, stats.rx_crc_error),
	NSE_PF_STAT(NSE_PORT_RX_RUNT_ERRORS, stats.rx_runt_error),
	NSE_PF_STAT(NSE_PORT_RX_JABBER_ERRORS, stats.rx_jabber_error),

	NSE_PF_STAT(NSE_PORT_TX_PACKETS, stats.tx_pkts_good_bad),
	NSE_PF_STAT(NSE_PORT_TX_BYTES, stats.tx_bytes_good_bad),
	NSE_PF_STAT(NSE_PORT_TX_UNICAST, stats.tx_unicast_good_bad),
	NSE_PF_STAT(NSE_PORT_TX_MULTICAST, stats.tx_multicast_good_bad),
	NSE_PF_STAT(NSE_PORT_TX_BROADCAST, stats.tx_broadcast_good_bad),
	NSE_PF_STAT(NSE_PORT_TX_SIZE_64, stats.tx_64_good_bad),
	NSE_PF_STAT(NSE_PORT_TX_SIZE_127, stats.tx_64_to_127_good_bad),
	NSE_PF_STAT(NSE_PORT_TX_SIZE_255, stats.tx_128_to_255_good_bad),
	NSE_PF_STAT(NSE_PORT_TX_SIZE_511, stats.tx_256_to_511_good_bad),
	NSE_PF_STAT(NSE_PORT_TX_SIZE_1023, stats.tx_512_to_1023_good_bad),
	NSE_PF_STAT(NSE_PORT_TX_SIZE_1023_MAX, stats.tx_1024_to_max_good_bad),
	NSE_PF_STAT(NSE_PORT_TX_UNDERFLOW_ERRORS, stats.tx_underflow_error),

	NSE_PF_STAT(NSE_PORT_TX_TIMEOUT, tx_timeout_count),

	NSE_PF_STAT(NSE_PORT_RX_PAUSE, stats.rx_lfc),
	NSE_PF_STAT(NSE_PORT_RX_LINK_XOFF, stats.rx_lfc_xoff),
	NSE_PF_STAT(NSE_PORT_RX_LINK_XON, stats.rx_lfc_xon),
	NSE_PF_STAT(NSE_PORT_TX_PAUSE, stats.tx_lfc),
	NSE_PF_STAT(NSE_PORT_TX_LINK_XOFF, stats.tx_lfc_xoff),
	NSE_PF_STAT(NSE_PORT_TX_LINK_XON, stats.tx_lfc_xon),

	NSE_PF_STAT(NSE_PORT_RX_PFC, stats.rx_pfc),
	NSE_PF_STAT(NSE_PORT_TX_PFC, stats.tx_pfc),

#ifdef NSE_ADD_PROBES
	NSE_PF_STAT(NSE_PORT_TX_TCP_SEGMENTS, tcp_segs),
	NSE_PF_STAT(NSE_PORT_TX_UDP_SEGMENTS, udp_segs),
	NSE_PF_STAT(NSE_PORT_RX_TCP_CSO, rx_tcp_cso),
	NSE_PF_STAT(NSE_PORT_TX_TCP_CSO, tx_tcp_cso),
	NSE_PF_STAT(NSE_PORT_RX_UDP_CSO, rx_udp_cso),
	NSE_PF_STAT(NSE_PORT_TX_UDP_CSO, tx_udp_cso),
	NSE_PF_STAT(NSE_PORT_RX_SCTP_CSO, rx_sctp_cso),
	NSE_PF_STAT(NSE_PORT_TX_SCTP_CSO, tx_sctp_cso),
	NSE_PF_STAT(NSE_PORT_RX_IP4_CSO, rx_ip4_cso),
	NSE_PF_STAT(NSE_PORT_TX_IP4_CSO, tx_ip4_cso),
	NSE_PF_STAT(NSE_PORT_RX_IP4_CSO_ERROR, rx_ip4_cso_err),
	NSE_PF_STAT(NSE_PORT_RX_TCP_CSO_ERROR, rx_tcp_cso_err),
	NSE_PF_STAT(NSE_PORT_RX_UDP_CSO_ERROR, rx_udp_cso_err),
	NSE_PF_STAT(NSE_PORT_RX_SCTP_CSO_ERROR, rx_sctp_cso_err),
	NSE_PF_STAT(NSE_PORT_TX_L3_CSO_ERROR, tx_l3_cso_err),
	NSE_PF_STAT(NSE_PORT_TX_L4_CSO_ERROR, tx_l4_cso_err),
	NSE_PF_STAT(NSE_PORT_RX_Q_VLANO, rx_q_vlano),
	NSE_PF_STAT(NSE_PORT_TX_Q_VLANO, tx_q_vlano),
	NSE_PF_STAT(NSE_PORT_RX_AD_VLANO, rx_ad_vlano),
	NSE_PF_STAT(NSE_PORT_TX_AD_VLANO, tx_ad_vlano),
#endif
};

static const struct nse_stats nse_gstrings_vsi_stats[] = {
	NSE_VSI_STAT(NSE_VSI_RX_PKTS, sw_stats.rx_pkts),
	NSE_VSI_STAT(NSE_VSI_RX_BYTES, hw_stats.rx_goct),
	NSE_VSI_STAT(NSE_VSI_RX_UNICAST, hw_stats.rx_upkt),
	NSE_VSI_STAT(NSE_VSI_RX_MULTICAST, hw_stats.rx_mpkt),
	NSE_VSI_STAT(NSE_VSI_RX_BROADCAST, hw_stats.rx_bpkt),
	NSE_VSI_STAT(NSE_VSI_RX_DROPPED_ERR, hw_stats.rx_drop_err),
	NSE_VSI_STAT(NSE_VSI_RX_DROPPED_NO_DESC, hw_stats.rx_drop_no_desc),
	NSE_VSI_STAT(NSE_VSI_RX_DROPPED_DPKT, hw_stats.rx_dpkt),
	NSE_VSI_STAT(NSE_VSI_RX_ALLOC_FAIL, sw_stats.rx_buf_failed),
	NSE_VSI_STAT(NSE_VSI_RX_PAGE_ALLOC_FAIL, sw_stats.rx_page_failed),
#ifdef NSE_ADD_PROBES
	NSE_VSI_STAT(NSE_VSI_RX_PAGE_REUSE, sw_stats.rx_page_reuse),
#endif /* NSE_ADD_PROBES */

	NSE_VSI_STAT(NSE_VSI_RX_CSUM_GOOD, sw_stats.rx_csum_good),
	NSE_VSI_STAT(NSE_VSI_RX_CSUM_BAD, sw_stats.rx_csum_bad),

	NSE_VSI_STAT(NSE_VSI_TX_PKTS, sw_stats.tx_pkts),
	NSE_VSI_STAT(NSE_VSI_TX_BYTES, hw_stats.tx_gotc),
	NSE_VSI_STAT(NSE_VSI_TX_UNICAST, hw_stats.tx_uptc),
	NSE_VSI_STAT(NSE_VSI_TX_MULTICAST, hw_stats.tx_mptc),
	NSE_VSI_STAT(NSE_VSI_TX_BROADCAST, hw_stats.tx_bptc),

	NSE_VSI_STAT(NSE_VSI_TX_LINEARIZE, sw_stats.tx_linearize),
	NSE_VSI_STAT(NSE_VSI_TX_BUSY, sw_stats.tx_busy),
	NSE_VSI_STAT(NSE_VSI_TX_RESTART, sw_stats.tx_restart),

	NSE_VSI_STAT(NSE_VSI_FDIR_MATCH, sw_stats.fdir_match),
	NSE_VSI_STAT(NSE_VSI_FDIR_MISS, sw_stats.fdir_miss),
};

static int nse_q_stats_len(struct net_device *netdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	int stats_size, total_slen = 0;

	/* RXQ stats: regular-RXQ (may including its XDP stats), macvlan-RXQ ( add later )
	 */
	stats_size = sizeof(struct nse_q_stats);

	total_slen += vsi->alloc_rxq * (stats_size / sizeof(u64));
#ifdef NSE_ADD_PROBES
	stats_size = sizeof(struct nse_xdp_stats);
	total_slen += vsi->alloc_rxq * (stats_size / sizeof(u64));
#endif

	/* TXQ stats: regular-TXQ, XDP-TXQ, macvlan-TXQ ( add later )
	 */

	total_slen += vsi->alloc_txq * (stats_size / sizeof(u64));
	total_slen += vsi->num_xdp_txq * (stats_size / sizeof(u64));

	/* CQ stats
	 */
	if (vsi->type == NSE_VSI_PF && vsi->sw_conf.lan_tx_use_cq) {
		stats_size = sizeof(struct nse_cq_stats);
		total_slen += vsi->alloc_txcq * (stats_size / sizeof(u64));
	}

	/* macvlan VSI RXQ/TXQ --- add to previous RXQ and TXQ
	 */
#ifdef NSE_ADD_PROBES
	if (vsi->type == NSE_VSI_PF && nse_is_offloaded_macvlan_ena(pf)) {
		stats_size = sizeof(struct nse_q_stats);

		total_slen += (pf->sw_conf.max_macvlans * 2) * (stats_size / sizeof(u64));
		/* the napi_poll_cnt isn't included in the MACVLAN stats so reduce
		 * the count by that many so the stats get printed correctly
		 *
		 * see:
		 *		nse_get_macvlan_tx_strings()
		 *		nse_get_macvlan_tx_stats()
		 *
		 *		nse_get_macvlan_rx_strings()
		 *		nse_get_macvlan_rx_stats()
		 */
		total_slen -= (pf->sw_conf.max_macvlans * 2);
	}
#endif /* NSE_ADD_PROBES */

	return total_slen;
}

#define NSE_LAN_STATS_LEN	ARRAY_SIZE(nse_gstrings_lan_stats)

#define NSE_LAN_PFC_STATS_LEN ( \
		(sizeof_field(struct nse_pf, stats.rx_pfc_xoff) + \
		 sizeof_field(struct nse_pf, stats.rx_pfc_xon) + \
		 sizeof_field(struct nse_pf, stats.tx_pfc_xoff) + \
		 sizeof_field(struct nse_pf, stats.tx_pfc_xon)) \
		 / sizeof(u64))

#define NSE_VSI_STATS_LEN	ARRAY_SIZE(nse_gstrings_vsi_stats)

#define NSE_ALL_STATS_LEN(n)	(NSE_LAN_STATS_LEN + NSE_LAN_PFC_STATS_LEN + \
				 NSE_VSI_STATS_LEN + nse_q_stats_len(n))

struct nse_priv_flag {
	char name[ETH_GSTRING_LEN];
	u32 bitno;			/* bit position in pf->flags */
};

#define NSE_PRIV_FLAG(_name, _bitno) { \
	.name = _name, \
	.bitno = _bitno, \
}

static const struct nse_priv_flag nse_gstrings_priv_flags[] = {
	NSE_PRIV_FLAG("fw-lldp-agent", NSE_FLAG_FW_LLDP_AGENT_ENA),
	NSE_PRIV_FLAG("fw-lldp-dcbx-subagent", NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA),
	NSE_PRIV_FLAG("legacy-rx", NSE_FLAG_LEGACY_RX),
	NSE_PRIV_FLAG("vf-true-promisc-support", NSE_FLAG_VF_TRUE_PROMISC_ENA),
	NSE_PRIV_FLAG("vf-vlan-pruning", NSE_FLAG_VF_VLAN_PRUNING),
};

#define NSE_PRIV_FLAG_ARRAY_SIZE	ARRAY_SIZE(nse_gstrings_priv_flags)

static void
__nse_get_drvinfo(struct net_device *netdev, struct ethtool_drvinfo *drvinfo,
		  struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	u32 fw_version;

	strscpy(drvinfo->driver, KBUILD_MODNAME, sizeof(drvinfo->driver));
	strscpy(drvinfo->version, nse_drv_ver, sizeof(drvinfo->version));

	fw_version = ((u32)hw->fw_ver.major_ver << 24) |
					((u32)hw->fw_ver.minor_ver << 16) |
					((u32)hw->fw_ver.mini_ver << 8) |
					((u32)hw->fw_ver.build_ver);

	snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version), "0x%08X", fw_version);

	strscpy(drvinfo->bus_info, pci_name(pf->pdev),
		sizeof(drvinfo->bus_info));
}

static void
nse_get_drvinfo(struct net_device *netdev, struct ethtool_drvinfo *drvinfo)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);

	__nse_get_drvinfo(netdev, drvinfo, np->vsi);

	drvinfo->n_priv_flags = NSE_PRIV_FLAG_ARRAY_SIZE;
}

static u32 nse_get_msglevel(struct net_device *netdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_pf *pf = np->vsi->back;

	if (pf->hw.debug_mask)
		netdev_info(netdev, "hw debug_mask: 0x%llX\n",
			    pf->hw.debug_mask);

	return pf->msg_enable;
}

static void nse_set_msglevel(struct net_device *netdev, u32 data)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_pf *pf = np->vsi->back;

	if (NSE_DBG_USER & data)
		pf->hw.debug_mask = data;

	pf->msg_enable = data;
}

/**
 * nse_active_vfs - check if there are any active VFs
 * @pf: board private structure
 *
 * Returns true if an active VF is found, otherwise returns false
 */
static bool nse_active_vfs(struct nse_pf *pf)
{
	bool active = false;
	struct nse_vf *vf;
	unsigned int bkt;

	rcu_read_lock();
	nse_for_each_vf_rcu(pf, bkt, vf) {
		if (test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
			active = true;
			break;
		}
	}
	rcu_read_unlock();

	return active;
}

/**
 * nse_link_test - perform a link test on a given net_device
 * @netdev: network interface device structure
 *
 * This function performs one of the self-tests required by ethtool.
 * Returns 0 on success, non-zero on failure.
 */
static u64 nse_link_test(struct net_device *netdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_hw *hw = &np->vsi->back->hw;
	struct nse_aqc_eth_get_link_status lk_sts;
	u32 ls;
	enum nse_status ret;

	netdev_info(netdev, "link test\n");
	ret = nse_aq_eth_get_link_status(hw, &lk_sts);
	if (!ret) {
		ls = le32_to_cpu(lk_sts.link_status);
	} else {
		netdev_err(netdev, "get link status failed, err = %d\n",
			   ret);
		return 1;
	}

	if (!ls)
		return 2;

	return 0;
}

/**
 * nse_lbtest_prepare_rings - configure Tx/Rx test rings
 * @vsi: pointer to the VSI structure
 *
 * Function configures rings of a VSI for loopback test without
 * enabling interrupts or informing the kernel about new queues.
 *
 * Returns 0 on success, negative on failure.
 */
static int nse_lbtest_prepare_rings(struct nse_vsi *vsi)
{
	int status;

	status = nse_vsi_setup_tx_rings(vsi);
	if (status)
		goto err_setup_tx_ring;

	status = nse_vsi_setup_rx_rings(vsi);
	if (status)
		goto err_setup_rx_ring;

	status = nse_vsi_cfg(vsi);
	if (status)
		goto err_setup_rx_ring;

	status = nse_vsi_start_all_rx_rings(vsi);
	if (status)
		goto err_start_rx_ring;

	status = nse_vsi_start_lan_tx_rings(vsi);
	if (status)
		goto err_start_rx_ring;

	/* Make sure the rings are enabled before the tail pointers are
	 * synced to the hardware.
	 */
	mb();

	nse_vsi_sync_tail_all_rx_rings(vsi);

	return 0;

err_start_rx_ring:
	nse_vsi_free_rx_rings(vsi);
err_setup_rx_ring:
	nse_vsi_stop_lan_tx_rings(vsi, false);
err_setup_tx_ring:
	nse_vsi_free_tx_rings(vsi);

	return status;
}

#define NSE_LB_FRAME_SIZE 64
/**
 * nse_lbtest_create_frame - create test packet
 * @pf: pointer to the PF structure
 * @ret_data: allocated frame buffer
 * @size: size of the packet data
 *
 * Function allocates a frame with a test pattern on specific offsets.
 * Returns 0 on success, non-zero on failure.
 */
static int nse_lbtest_create_frame(struct nse_pf *pf, u8 **ret_data, u16 size)
{
	u8 *data;

	if (!pf)
		return -EINVAL;

	data = devm_kzalloc(nse_pf_to_dev(pf), size, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* Since the ethernet test frame should always be at least
	 * 64 bytes long, fill some octets in the payload with test data.
	 */
	memset(data, 0xFF, size);
	data[32] = 0xDE;
	data[42] = 0xAD;
	data[44] = 0xBE;
	data[46] = 0xEF;

	*ret_data = data;

	return 0;
}

/**
 * nse_diag_send - send test frames to the test ring
 * @tx_ring: pointer to the transmit ring
 * @data: pointer to the raw packet data
 * @size: size of the packet to send
 *
 * Function sends loopback packets on a test Tx ring.
 */
static int nse_diag_send(struct nse_ring *tx_ring, u8 *data, u16 size)
{
	struct nse_tx_desc *tx_desc;
	struct nse_tx_buf *tx_buf;
	dma_addr_t dma;
	u64 td_cmd;

	tx_desc = NSE_TX_DESC(tx_ring, tx_ring->next_to_use);
	tx_buf = &tx_ring->tx_buf[tx_ring->next_to_use];

	dma = dma_map_single(tx_ring->dev, data, size, DMA_TO_DEVICE);
	if (dma_mapping_error(tx_ring->dev, dma))
		return -EINVAL;

	tx_desc->buf_addr = cpu_to_le64(dma);

	/* These flags are required for a descriptor to be pushed out */
	td_cmd = (u64)NSE_TXD_LAST_DESC_CMD;
	tx_desc->cmd_type_offset_bsz =
		cpu_to_le64(
				(((u64)(0xe >> 1) << NSE_TXD_MACLEN_S) & NSE_TXD_MACLEN_M) |
				(NSE_TX_DESC_DTYPE_DATA << NSE_TXD_DTYPE_S) |
				td_cmd |
				(((u64)size << NSE_TXD_TLEN_S) & NSE_TXD_TLEN_M) |
				(((u64)size << NSE_TXD_BSIZE_S) & NSE_TXD_BSIZE_M));

	tx_buf->next_to_watch = tx_desc;

	/* Force memory write to complete before letting h/w know
	 * there are new descriptors to fetch.
	 */
	wmb();

	tx_ring->next_to_use++;
	if (tx_ring->next_to_use >= tx_ring->count)
		tx_ring->next_to_use = 0;

	writel_relaxed(tx_ring->next_to_use, tx_ring->tail);

	/* Wait until the packets get transmitted to the receive queue. */
	usleep_range(1000, 2000);
	dma_unmap_single(tx_ring->dev, dma, size, DMA_TO_DEVICE);

	return 0;
}

/**
 * nse_lbtest_check_frame - verify received loopback frame
 * @frame: pointer to the raw packet data
 *
 * Function verifies received test frame with a pattern.
 * Returns true if frame matches the pattern, false otherwise.
 */
static bool nse_lbtest_check_frame(u8 *frame)
{
	/* Validate bytes of a frame under offsets chosen earlier */
	if (frame[32] == 0xDE &&
	    frame[42] == 0xAD &&
	    frame[44] == 0xBE &&
	    frame[46] == 0xEF &&
	    frame[48] == 0xFF)
		return true;

	return false;
}

/**
 * nse_lbtest_receive_frames - receive and verify test frames
 * @rx_ring: pointer to the receive ring
 *
 * Function receives loopback packets and verify their correctness.
 * Returns number of received valid frames.
 */
static int nse_lbtest_receive_frames(struct nse_ring *rx_ring)
{
	struct nse_rx_buf *rx_buf;
	int valid_frames, i;
	u8 *received_buf;

	valid_frames = 0;

	for (i = 0; i < rx_ring->count; i++) {
		union nse_32b_rx_desc *rx_desc;

		rx_desc = NSE_RX_DESC(rx_ring, i);
		if (!(rx_desc->wb.status_error0 &
		    (cpu_to_le16(BIT(NSE_RXD_STATUS0_DD_S)) |
		     cpu_to_le16(BIT(NSE_RXD_STATUS0_EOP_S)))))
			continue;

		rx_buf = &rx_ring->rx_buf[i];
		received_buf = page_address(rx_buf->page) + rx_buf->page_offset;
		if (nse_lbtest_check_frame(received_buf))
			valid_frames++;
	}

	return valid_frames;
}

/**
 * nse_lbtest_disable_rings - disable Tx/Rx test rings after loopback test
 * @vsi: pointer to the VSI structure
 *
 * Function stops and frees VSI rings after a loopback test.
 * Returns 0 on success, negative on failure.
 */
static int nse_lbtest_disable_rings(struct nse_vsi *vsi)
{
	int status;

	status = nse_vsi_stop_lan_tx_rings(vsi, false);
	if (status)
		netdev_err(vsi->netdev, "Failed to stop Tx rings, VSI %d error %d\n",
			   vsi->vsi_abs_num, status);

	status = nse_vsi_stop_all_rx_rings(vsi, false);
	if (status)
		netdev_err(vsi->netdev, "Failed to stop Rx rings, VSI %d error %d\n",
			   vsi->vsi_abs_num, status);

	nse_vsi_free_tx_rings(vsi);
	nse_vsi_free_rx_rings(vsi);

	return status;
}

/**
 * nse_loopback_test - perform a loopback test on a given net_device
 * @netdev: network interface device structure
 *
 * This function performs one of the self-tests required by ethtool.
 * Returns 0 on success, non-zero on failure.
 */
static u64 nse_loopback_test(struct net_device *netdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *orig_vsi = np->vsi, *test_vsi;
	struct nse_pf *pf = orig_vsi->back;
	struct nse_hw *hw = &pf->hw;
	u8 broadcast[ETH_ALEN], ret = 0;
	int num_frames, valid_frames;
	struct nse_ring *tx_ring;
	struct nse_ring *rx_ring;
	struct device *dev;
	u8 *tx_frame;
	int i;

	dev = nse_pf_to_dev(pf);
	netdev_info(netdev, "loopback test\n");

	test_vsi = nse_lb_vsi_setup(pf, pf->hw.port_info);
	if (!test_vsi) {
		dev_err(dev, "[%s] FAIL: lb_vsi_setup()\n", __func__);
		return 1;
	}

	/* for FPGA test */
	if (nse_bypass_switch)
		nse_switch_rpp_set_bypass(&pf->hw, true, test_vsi->vsi_abs_num, 0xFF);

	test_vsi->netdev = netdev;
	tx_ring = test_vsi->tx_rings[0];
	rx_ring = test_vsi->rx_rings[0];

	if (nse_lbtest_prepare_rings(test_vsi)) {
		dev_err(dev, "[%s] FAIL: lbtest_prepare_rings( test_vsi vsi_abs_id=%d)\n",
			__func__, test_vsi->vsi_abs_num);
		ret = 2;
		goto lbtest_vsi_close;
	}

	if (nse_alloc_rx_bufs(rx_ring, rx_ring->count)) {
		dev_err(dev, "[%s] FAIL: alloc_rx_bufs( test_vsi vsi_abs_id=%d )\n",
			__func__, test_vsi->vsi_abs_num);
		ret = 3;
		goto lbtest_rings_dis;
	}

	/* Enable MAC loopback in firmware */
	if (nse_lmac_set_basic_cfg_lm(&pf->hw, true)) {
		dev_err(dev, "[%s] FAIL: lmac_set_basic_cfg_lm(true)\n", __func__);
		ret = 4;
		goto lbtest_mac_dis;
	}

	/* Test VSI needs to receive broadcast packets */
	eth_broadcast_addr(broadcast);
	if (nse_fltr_add_mac(test_vsi, broadcast, NSE_FWD_TO_VSI)) {
		dev_err(dev, "[%s] FAIL: fltr_add_mac(bc_addr)\n", __func__);
		ret = 5;
		goto lbtest_mac_dis;
	}

	if (nse_lbtest_create_frame(pf, &tx_frame, NSE_LB_FRAME_SIZE)) {
		dev_err(dev, "[%s] FAIL: lbtest_create_frame()\n", __func__);
		ret = 7;
		goto remove_mac_filters;
	}

	num_frames = min_t(int, tx_ring->count, 32);
	for (i = 0; i < num_frames; i++) {
		if (nse_diag_send(tx_ring, tx_frame, NSE_LB_FRAME_SIZE)) {
			dev_err(dev, "[%s] FAIL: diag_send( i = %d )\n", __func__, i);
			ret = 8;
			goto lbtest_free_frame;
		}
	}

	usleep_range(10000, 20000);	/* delay a while for receive frames writeback DD */

	valid_frames = nse_lbtest_receive_frames(rx_ring);
	if (!valid_frames) {
		dev_err(dev, "[%s] FAIL: lbtest_receive_frames(), receive valid_frames (0)\n",
			__func__);
		ret = 9;
	} else if (valid_frames != num_frames) {
		dev_err(dev, "[%s] FAIL: lbtest_receive_frames(), receive valid_frames (%d) != num_frames (%d)\n",
					__func__, valid_frames, num_frames);
		ret = 10;
	}

lbtest_free_frame:
	devm_kfree(dev, tx_frame);
remove_mac_filters:
	if (nse_fltr_remove_mac(test_vsi, broadcast, NSE_FWD_TO_VSI))
		netdev_err(netdev, "Could not remove MAC filter for the test VSI\n");
lbtest_mac_dis:
	/* Disable MAC loopback after the test is completed. */
	if (nse_lmac_set_basic_cfg_lm(&pf->hw, false))
		netdev_err(netdev, "Could not disable MAC loopback\n");
lbtest_rings_dis:
	if (nse_lbtest_disable_rings(test_vsi))
		netdev_err(netdev, "Could not disable test rings\n");
lbtest_vsi_close:
	test_vsi->netdev = NULL;
	if (nse_vsi_release(test_vsi))
		netdev_err(netdev, "Failed to remove the test VSI\n");

	/* for FPGA test */
	if (nse_bypass_switch)
		nse_switch_rpp_set_bypass(&pf->hw, true, pf->bypass_switch_vsi_abs_id, 0xFF);

	nse_debug(hw, NSE_DBG_SYS, "[%s] exit, ret=%d\n", __func__, ret);

	return ret;
}

/**
 * nse_self_test - handler function for performing a self-test by ethtool
 * @netdev: network interface device structure
 * @eth_test: ethtool_test structure
 * @data: required by ethtool.self_test
 *
 * This function is called after invoking 'ethtool -t devname' command where
 * devname is the name of the network device on which ethtool should operate.
 * It performs a set of self-tests to check if a device works properly.
 */
static void
nse_self_test(struct net_device *netdev, struct ethtool_test *eth_test,
	      u64 *data)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	bool if_running = netif_running(netdev);
	struct nse_pf *pf = np->vsi->back;
	struct device *dev;

	dev = nse_pf_to_dev(pf);

	if (eth_test->flags == ETH_TEST_FL_OFFLINE) {
		netdev_info(netdev, "offline testing starting\n");

		set_bit(NSE_TESTING, pf->state);

		if (nse_active_vfs(pf)) {
			dev_warn(dev, "Please take active VFs and Netqueues offline and restart adapter\n");
			data[NSE_ETH_TEST_REG] = 1;
			data[NSE_ETH_TEST_EEPROM] = 1;
			data[NSE_ETH_TEST_INTR] = 1;
			data[NSE_ETH_TEST_LOOP] = 1;
			data[NSE_ETH_TEST_LINK] = 1;
			eth_test->flags |= ETH_TEST_FL_FAILED;
			clear_bit(NSE_TESTING, pf->state);
			goto skip_ol_tests;
		}
		/* If the device is online then take it offline */
		if (if_running)
			/* indicate we're in test mode */
			dev_change_flags(netdev, netdev->flags & ~IFF_UP, NULL);

		data[NSE_ETH_TEST_LINK] = nse_link_test(netdev);
		data[NSE_ETH_TEST_EEPROM] = 0; /* eeprom test not ready */
		data[NSE_ETH_TEST_INTR] = 0; /* intr test not ready */
		data[NSE_ETH_TEST_LOOP] = nse_loopback_test(netdev);
		data[NSE_ETH_TEST_REG] = 0; /* reg test not ready */

		if (data[NSE_ETH_TEST_LINK] ||
		    data[NSE_ETH_TEST_EEPROM] ||
		    data[NSE_ETH_TEST_LOOP] ||
		    data[NSE_ETH_TEST_INTR] ||
		    data[NSE_ETH_TEST_REG])
			eth_test->flags |= ETH_TEST_FL_FAILED;

		clear_bit(NSE_TESTING, pf->state);

		if (if_running) {
			int status = dev_change_flags(netdev,
						      netdev->flags | IFF_UP,
						      NULL);

			if (status) {
				nse_dev_err_errno(dev, status,
						  "Could not bring up device %s",
						  pf->int_name);
			}
		}
	} else {
		/* Online tests */
		netdev_info(netdev, "online testing starting\n");

		data[NSE_ETH_TEST_LINK] = nse_link_test(netdev);
		if (data[NSE_ETH_TEST_LINK])
			eth_test->flags |= ETH_TEST_FL_FAILED;

		/* Offline only tests, not run in online; pass by default */
		data[NSE_ETH_TEST_REG] = 0;
		data[NSE_ETH_TEST_EEPROM] = 0;
		data[NSE_ETH_TEST_INTR] = 0;
		data[NSE_ETH_TEST_LOOP] = 0;
	}

skip_ol_tests:
	netdev_info(netdev, "testing finished\n");
}

#ifdef NSE_ADD_PROBES
/**
 * nse_get_xdp_rx_strings
 * @q: queue index
 * @num_rxq: number of rx queue
 * @loc_in_buf: ptr to ptr to location in buffer (input and output param)
 *
 * This function returns Rx queue XDP related counters strings
 */
static void
nse_get_xdp_rx_strings(unsigned int q, u16 num_rxq, char **loc_in_buf)
{
	char *p;

	if (!loc_in_buf || q >= num_rxq)
		return;

	p = *loc_in_buf;

	snprintf(p, ETH_GSTRING_LEN, "xdp-rx_q-%u_pkts", q);
	p += ETH_GSTRING_LEN;
	snprintf(p, ETH_GSTRING_LEN, "xdp-rx_q-%u_bytes", q);
	p += ETH_GSTRING_LEN;
	snprintf(p, ETH_GSTRING_LEN, "xdp-rx-passed_q-%u_pkts", q);
	p += ETH_GSTRING_LEN;
	snprintf(p, ETH_GSTRING_LEN, "xdp-rx-dropped_q-%u_pkts", q);
	p += ETH_GSTRING_LEN;
	snprintf(p, ETH_GSTRING_LEN, "xdp-rx-tx_q-%u_pkts", q);
	p += ETH_GSTRING_LEN;
	snprintf(p, ETH_GSTRING_LEN, "xdp-tx-fail_q-%u_pkts", q);
	p += ETH_GSTRING_LEN;
	snprintf(p, ETH_GSTRING_LEN, "xdp-rx-unknown_q-%u_pkts", q);
	p += ETH_GSTRING_LEN;
	snprintf(p, ETH_GSTRING_LEN, "xdp-rx-redirected_q-%u_pkts", q);
	p += ETH_GSTRING_LEN;
	snprintf(p, ETH_GSTRING_LEN, "xdp-rx-redir-fail_q-%u_pkts", q);
	p += ETH_GSTRING_LEN;

	/* copy back updated length */
	*loc_in_buf = p;
}

/**
 * nse_get_xdp_rx_stats - get stats for Rx rings if XDP is enabled
 * @xdp_stats: ptr to stats being updated
 * @data: ptr to data
 * @idx: ptr to idx in data buffer (input/output param)
 *
 * This function reads XDP per-action Rx statistics.
 */
static void
nse_get_xdp_rx_stats(struct nse_xdp_stats *xdp_stats, u64 *data, int *idx)
{
	bool set = !!xdp_stats;
	int i;

	if (!idx)
		return;

	i = *idx; /* start index in data buffer */

	data[i++] = set ? xdp_stats->xdp_rx_pkts : 0;
	data[i++] = set ? xdp_stats->xdp_rx_bytes : 0;
	data[i++] = set ? xdp_stats->xdp_pass : 0;
	data[i++] = set ? xdp_stats->xdp_drop : 0;
	data[i++] = set ? xdp_stats->xdp_tx : 0;
	data[i++] = set ? xdp_stats->xdp_tx_fail : 0;
	data[i++] = set ? xdp_stats->xdp_unknown : 0;
	data[i++] = set ? xdp_stats->xdp_redirect : 0;
	data[i++] = set ? xdp_stats->xdp_redirect_fail : 0;

	/* copy back updated index */
	*idx = i;
}
#endif /* NSE_ADD_PROBES */

/**
 * nse_get_xdp_tx_strings
 * @vsi: pointer to the VSI structure
 * @loc_in_buf: ptr to ptr to location in buffer (input and output param)
 *
 * This function returns Tx queue XDP related counters strings
 */
static void
nse_get_xdp_tx_strings(struct nse_vsi *vsi, char **loc_in_buf)
{
	char *p;
	u16 q;

	if (!vsi || !loc_in_buf)
		return;

	for (q = 0; q < vsi->num_xdp_txq; ++q) {
		p = *loc_in_buf;

		snprintf(p, ETH_GSTRING_LEN, NSE_XDP_TXQ_PACKETS, q);
		p += ETH_GSTRING_LEN;
		snprintf(p, ETH_GSTRING_LEN, NSE_XDP_TXQ_BYTES, q);
		p += ETH_GSTRING_LEN;

#ifdef NSE_ADD_PROBES
		snprintf(p, ETH_GSTRING_LEN, NSE_XDP_TXQ_NAPI_POLL, q);
		p += ETH_GSTRING_LEN;
#endif /* NSE_ADD_PROBES */

		/* copy back updated length */
		*loc_in_buf = p;
	}
}

/**
 * nse_get_xdp_tx_stats - get stats for XDP Tx rings if XDP is enabled
 * @vsi: pointer to the VSI structure
 * @data: ptr to data
 * @idx: ptr to idx in data buffer (input/output param)
 *
 * This function reads XDP per-action Tx statistics.
 */
static void
nse_get_xdp_tx_stats(struct nse_vsi *vsi, u64 *data, int *idx)
{
	int i, q;

	if (!idx || !vsi || !vsi->xdp_rings)
		return;

	i = *idx; /* start index in data buffer */

	for (q = 0; q < vsi->num_xdp_txq; ++q) {
		struct nse_q_stats *stats;
		struct nse_ring *ring;

		ring = vsi->xdp_rings[q];

		stats = !!ring ? &ring->stats : NULL;

		data[i++] = !!ring ? stats->pkts : 0;
		data[i++] = !!ring ? stats->bytes : 0;
#ifdef NSE_ADD_PROBES
		data[i++] = !!ring ? stats->napi_poll_cnt : 0;
#endif
	}

	/* copy back updated index */
	*idx = i;
}

#ifdef NSE_ADD_PROBES
/**
 * nse_get_macvlan
 * @id: macvlan ID
 * @pf: pointer to the PF structure
 *
 * Returns the MACVLAN matching the provided ID
 */
static struct nse_macvlan *nse_get_macvlan(int id, struct nse_pf *pf)
{
	struct nse_macvlan *mv;

	/* If the ID is not marked as in use, no need to search */
	if (!(test_bit(id, pf->avail_macvlan)))
		return NULL;

	list_for_each_entry(mv, &pf->macvlan_list, list) {
		if (id == mv->id)
			return mv;
	}

	return NULL;
}

/**
 * nse_get_macvlan_tx_strings
 * @pf: pointer to the PF structure
 * @loc_in_buf: ptr to ptr to location in buffer (input and output param)
 *
 * This function returns Tx related strings for MACVLAN offload
 */
static void nse_get_macvlan_tx_strings(struct nse_pf *pf, char **loc_in_buf)
{
	struct nse_hw *hw = &pf->hw;
	char *p;
	int i;

	if (!nse_is_offloaded_macvlan_ena(pf))
		return;

	if (!loc_in_buf)
		return;

	p = *loc_in_buf;

	for (i = 0; i < pf->sw_conf.max_macvlans; i++) {
		struct nse_macvlan *mv = nse_get_macvlan(i, pf);

		if (mv) {
			snprintf(p, ETH_GSTRING_LEN, L2_FWD_TX_PKTS1,
				 mv->vdev->name);
			p += ETH_GSTRING_LEN;
			snprintf(p, ETH_GSTRING_LEN, L2_FWD_TX_BYTES1,
				 mv->vdev->name);
			p += ETH_GSTRING_LEN;
		} else {
			snprintf(p, ETH_GSTRING_LEN, L2_FWD_TX_PKTS2, i);
			p += ETH_GSTRING_LEN;
			snprintf(p, ETH_GSTRING_LEN, L2_FWD_TX_BYTES2, i);
			p += ETH_GSTRING_LEN;
		}
	}

	/* copy back updated length */
	*loc_in_buf = p;
}

/**
 * nse_get_macvlan_tx_stats
 * @pf: pointer to the PF structure
 * @data: ptr to data
 * @idx: ptr to idx in data buffer (input/output param)
 *
 * This function is used to collect Tx statistics for MACVLAN offload
 */
static void nse_get_macvlan_tx_stats(struct nse_pf *pf, u64 *data, int *idx)
{
	struct nse_hw *hw = &pf->hw;
	int i, j;

	if (!nse_is_offloaded_macvlan_ena(pf))
		return;

	if (!idx)
		return;

	j = *idx;

	for (i = 0; i < pf->sw_conf.max_macvlans; i++) {
		struct nse_macvlan *mv;

		mv = nse_get_macvlan(i, pf);
		if (mv) {
			data[j++] = mv->vsi->net_stats.tx_packets;
			data[j++] = mv->vsi->net_stats.tx_bytes;
		} else {
			data[j++] = 0;
			data[j++] = 0;
		}
	}

	/* copy back updated index */
	*idx = j;
}

/**
 * nse_get_macvlan_rx_strings
 * @pf: pointer to the PF structure
 * @loc_in_buf: ptr to ptr to location in buffer (input and output param)
 *
 * This function returns Rx related strings for MACVLAN offload
 */
static void nse_get_macvlan_rx_strings(struct nse_pf *pf, char **loc_in_buf)
{
	struct nse_hw *hw = &pf->hw;
	char *p;
	int i;

	if (!nse_is_offloaded_macvlan_ena(pf))
		return;

	if (!loc_in_buf)
		return;

	p = *loc_in_buf;

	for (i = 0; i < pf->sw_conf.max_macvlans; i++) {
		struct nse_macvlan *mv = nse_get_macvlan(i, pf);

		if (mv) {
			snprintf(p, ETH_GSTRING_LEN, L2_FWD_RX_PKTS1,
				 mv->vdev->name);
			p += ETH_GSTRING_LEN;
			snprintf(p, ETH_GSTRING_LEN, L2_FWD_RX_BYTES1,
				 mv->vdev->name);
			p += ETH_GSTRING_LEN;
		} else {
			snprintf(p, ETH_GSTRING_LEN, L2_FWD_RX_PKTS2, i);
			p += ETH_GSTRING_LEN;
			snprintf(p, ETH_GSTRING_LEN, L2_FWD_RX_BYTES2, i);
			p += ETH_GSTRING_LEN;
		}
	}

	/* copy back updated length */
	*loc_in_buf = p;
}

/**
 * nse_get_macvlan_rx_stats
 * @pf: private board structure
 * @data: ptr to data
 * @idx: ptr to idx in data buffer (input/output param)
 *
 * This function is used to collect statistics for MACVLAN offload
 */
static void
nse_get_macvlan_rx_stats(struct nse_pf *pf, u64 *data, int *idx)
{
	struct nse_hw *hw = &pf->hw;
	int i, j;

	if (!nse_is_offloaded_macvlan_ena(pf))
		return;

	if (!idx)
		return;

	j = *idx;

	for (i = 0; i < pf->sw_conf.max_macvlans; i++) {
		struct nse_macvlan *mv;

		mv = nse_get_macvlan(i, pf);
		if (mv) {
			data[j++] = mv->vsi->net_stats.rx_packets;
			data[j++] = mv->vsi->net_stats.rx_bytes;
		} else {
			data[j++] = 0;
			data[j++] = 0;
		}
	}

	/* copy back updated index */
	*idx = j;
}
#endif /* NSE_ADD_PROBES */

static void
__nse_get_strings(struct net_device *netdev, u32 stringset, u8 *data,
		  struct nse_vsi *vsi)
{
	char *p = (char *)data;
	unsigned int i;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < NSE_VSI_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 nse_gstrings_vsi_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}
		if (nse_is_port_repr_netdev(netdev))
			return;

		/* RXQ stat strings: regular-RXQ (may including its XDP stats), macvlan VSI RXQ
		 */
		nse_for_each_alloc_rxq(vsi, i) {
			snprintf(p, ETH_GSTRING_LEN, NSE_RXQ_PACKETS, i);
			p += ETH_GSTRING_LEN;
			snprintf(p, ETH_GSTRING_LEN, NSE_RXQ_BYTES, i);
			p += ETH_GSTRING_LEN;
#ifdef NSE_ADD_PROBES
			snprintf(p, ETH_GSTRING_LEN, NSE_RXQ_NAPI_POLL, i);
			p += ETH_GSTRING_LEN;
#endif /* NSE_ADD_PROBES */

#ifdef NSE_ADD_PROBES
			nse_get_xdp_rx_strings(i, vsi->num_rxq, &p);
#endif /* NSE_ADD_PROBES */
		}

#ifdef NSE_ADD_PROBES
		nse_get_macvlan_rx_strings(vsi->back, &p);
#endif /* NSE_ADD_PROBES */

		/* TXQ stat strings: regular-TXQ, XDP-TXQ, macvlan VSI TXQ
		 */
		nse_for_each_alloc_txq(vsi, i) {
			snprintf(p, ETH_GSTRING_LEN, NSE_TXQ_PACKETS, i);
			p += ETH_GSTRING_LEN;
			snprintf(p, ETH_GSTRING_LEN, NSE_TXQ_BYTES, i);
			p += ETH_GSTRING_LEN;
#ifdef NSE_ADD_PROBES
			snprintf(p, ETH_GSTRING_LEN, NSE_TXQ_NAPI_POLL, i);
			p += ETH_GSTRING_LEN;
#endif /* NSE_ADD_PROBES */
		}

		nse_get_xdp_tx_strings(vsi, &p);

#ifdef NSE_ADD_PROBES
		nse_get_macvlan_tx_strings(vsi->back, &p);
#endif /* NSE_ADD_PROBES */

		/* CQ stat strings
		 */
		if (vsi->type == NSE_VSI_PF && vsi->sw_conf.lan_tx_use_cq) {
			nse_for_each_lan_txcq(vsi, i) {
				snprintf(p, ETH_GSTRING_LEN, NSE_TXCQ_PACKETS, i);
				p += ETH_GSTRING_LEN;
				snprintf(p, ETH_GSTRING_LEN, NSE_TXCQ_BYTES, i);
				p += ETH_GSTRING_LEN;
				snprintf(p, ETH_GSTRING_LEN, NSE_TXCQ_CQE_CNT, i);
				p += ETH_GSTRING_LEN;
				snprintf(p, ETH_GSTRING_LEN, NSE_TXCQ_GEN_FLIP_CNT, i);
				p += ETH_GSTRING_LEN;
				snprintf(p, ETH_GSTRING_LEN, NSE_TXCQ_TXQE_CNT, i);
				p += ETH_GSTRING_LEN;
#ifdef NSE_ADD_PROBES
				snprintf(p, ETH_GSTRING_LEN, NSE_TXCQ_NAPI_POLL, i);
				p += ETH_GSTRING_LEN;
#endif /* NSE_ADD_PROBES */
			}
		}

		/* only PF-main-VSI have the following port-level stats
		 */
		if (vsi->type != NSE_VSI_PF)
			return;

		for (i = 0; i < NSE_LAN_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 nse_gstrings_lan_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}

		for (i = 0; i < NSE_MAX_USER_PRIORITY; i++) {
			snprintf(p, ETH_GSTRING_LEN, NSE_PORT_RX_PRIO_XOFF, i);
			p += ETH_GSTRING_LEN;
			snprintf(p, ETH_GSTRING_LEN, NSE_PORT_RX_PRIO_XON, i);
			p += ETH_GSTRING_LEN;
		}

		for (i = 0; i < NSE_MAX_USER_PRIORITY; i++) {
			snprintf(p, ETH_GSTRING_LEN, NSE_PORT_TX_PRIO_XOFF, i);
			p += ETH_GSTRING_LEN;
			snprintf(p, ETH_GSTRING_LEN, NSE_PORT_TX_PRIO_XON, i);
			p += ETH_GSTRING_LEN;
		}
		break;
	case ETH_SS_TEST:
		memcpy(data, nse_gstrings_test, NSE_TEST_LEN * ETH_GSTRING_LEN);
		break;
	case ETH_SS_PRIV_FLAGS:
		for (i = 0; i < NSE_PRIV_FLAG_ARRAY_SIZE; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 nse_gstrings_priv_flags[i].name);
			p += ETH_GSTRING_LEN;
		}
		break;
	default:
		break;
	}
}

static void nse_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);

	__nse_get_strings(netdev, stringset, data, np->vsi);
}

/**
 * nse_nway_reset - restart autonegotiation
 * @netdev: network interface device structure
 */
static int nse_nway_reset(struct net_device *netdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	int err;

	/* If VSI state is up, then restart autoneg with link up */
	if (!test_bit(NSE_DOWN, vsi->back->state))
		err = nse_set_link(vsi, true);
	else
		err = nse_set_link(vsi, false);

	return err;
}

/**
 * nse_get_priv_flags - report device private flags
 * @netdev: network interface device structure
 *
 * The get string set count and the string set should be matched for each
 * flag returned. Add new strings for each flag to the nse_gstrings_priv_flags
 * array.
 *
 * Returns a u32 bitmap of flags.
 */
static u32 nse_get_priv_flags(struct net_device *netdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	u32 i, ret_flags = 0;

	for (i = 0; i < NSE_PRIV_FLAG_ARRAY_SIZE; i++) {
		const struct nse_priv_flag *priv_flag;

		priv_flag = &nse_gstrings_priv_flags[i];

		if (test_bit(priv_flag->bitno, pf->flags))
			ret_flags |= BIT(i);
	}

	return ret_flags;
}

/**
 * nse_set_priv_flags - set private flags
 * @netdev: network interface device structure
 * @flags: bit flags to be set
 */
static int nse_set_priv_flags(struct net_device *netdev, u32 flags)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	DECLARE_BITMAP(change_flags, NSE_PF_FLAGS_NBITS);
	DECLARE_BITMAP(orig_flags, NSE_PF_FLAGS_NBITS);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	enum nse_status status;
	struct device *dev = nse_pf_to_dev(pf);
	int ret = 0;
	u32 i;

	if (flags > BIT(NSE_PRIV_FLAG_ARRAY_SIZE))
		return -EINVAL;

	set_bit(NSE_FLAG_ETHTOOL_CTXT, pf->flags);

	bitmap_copy(orig_flags, pf->flags, NSE_PF_FLAGS_NBITS);
	for (i = 0; i < NSE_PRIV_FLAG_ARRAY_SIZE; i++) {
		const struct nse_priv_flag *priv_flag;

		priv_flag = &nse_gstrings_priv_flags[i];

		if (flags & BIT(i))
			set_bit(priv_flag->bitno, pf->flags);
		else
			clear_bit(priv_flag->bitno, pf->flags);
	}

	bitmap_xor(change_flags, pf->flags, orig_flags, NSE_PF_FLAGS_NBITS);

	/* FW-LLDP-agent */
	if (!nse_is_fw_fea_set(hw, NSE_FW_FEA_SUPPORT_LLDP)) {
		if (test_bit(NSE_FLAG_FW_LLDP_AGENT_ENA, change_flags) ||
			test_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, change_flags)) {
			dev_info(dev, "FW-LLDP not supported, ignore related priv_flags change\n");
		}

		clear_bit(NSE_FLAG_FW_LLDP_AGENT_ENA, change_flags);
		clear_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, change_flags);

		clear_bit(NSE_FLAG_FW_LLDP_AGENT_ENA, pf->flags);
		clear_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, pf->flags);
	}

	if (test_bit(NSE_FLAG_FW_LLDP_AGENT_ENA, change_flags)) {
		/* disable FW-LLDP-agent */
		if (!test_bit(NSE_FLAG_FW_LLDP_AGENT_ENA, pf->flags)) {
			/* stop subagents */
			(void)nse_aq_fw_lldp_dcbx_subagent_start_stop(hw, false);

			/* stop agent */
			status = nse_aq_fw_lldp_agent_start_stop(hw, false);
			if (status)
				dev_warn(dev, "fw-lldp-agent fail to actually stop\n");

			/* change this field, because subagent stopped */
			pf->dcbx_cap &= ~DCB_CAP_DCBX_LLD_MANAGED;
			pf->dcbx_cap |= DCB_CAP_DCBX_HOST;

			hw->port_info->qos_cfg.dcbx_mode = NSE_QOS_DCBX_MODE_HOST;

			clear_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, pf->flags);

			/*  init DCB to default config --- because FW-LLDP-DCBx subagent should be
			 * stopped
			 */
			status = nse_init_pf_dcb(pf, false, true);
			if (status)
				dev_warn(dev, "Fail to init DCB\n");

			dev_info(dev, "fw-lldp-agent is now inactive\n");

			/* even we fail to actually stop agent and subagent,
			 * our NSE_FLAG_FW_LLDP_AGENT_ENA would be cleared,
			 *  later would not handle any event from agent which should have been
			 * stopped
			 */

		} else {		/* enable FW-LLDP-agent */

			/* enable agent only, not any subagents */
			status = nse_aq_fw_lldp_agent_start_stop(hw, true);
			if (status) {
				dev_warn(dev, "fw-lldp-agent fail to start\n");

				/* toggle bit back to previous state */
				change_bit(NSE_FLAG_FW_LLDP_AGENT_ENA, pf->flags);

			} else {
				/* Remove rule to direct LLDP packets to default VSI.
				 * The FW LLDP engine will now be consuming them.
				 */
				nse_cfg_sw_lldp(vsi, false, false);

				dev_info(dev, "fw-lldp-agent is now active\n");
			}
		}
	}

	/* FW-LLDP-DCBx-subagent */
	if (test_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, change_flags)) {
		/* disable subagent */
		if (!test_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, pf->flags)) {
			/* stop the subagent*/
			(void)nse_aq_fw_lldp_dcbx_subagent_start_stop(hw, false);

			pf->dcbx_cap &= ~DCB_CAP_DCBX_LLD_MANAGED;
			pf->dcbx_cap |= DCB_CAP_DCBX_HOST;

			hw->port_info->qos_cfg.dcbx_mode = NSE_QOS_DCBX_MODE_HOST;

			/*  init DCB to default config --- because FW-LLDP-DCBx subagent should be
			 * stopped
			 */
			status = nse_init_pf_dcb(pf, false, true);
			if (status)
				dev_warn(dev, "Fail to init DCB\n");

			dev_info(dev, "fw-lldp-dcbx-subagent is now inactive\n");

			/* even we fail to actually stop agent,
			 * our NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA would be cleared,
			 *  later would not handle any event from agent which should have been
			 * stopped
			 */

		} else {		/* enable subagent */

			/* subagent need owner agent enabled */
			if (!test_bit(NSE_FLAG_FW_LLDP_AGENT_ENA, pf->flags)) {
				dev_info(dev, "fw-lldp-agent is now inactive, can not activate fw-lldp-dcbx-subagent\n");

				/* toggle bit back to previous state */
				change_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, pf->flags);

			} else {
				status = nse_aq_fw_lldp_dcbx_subagent_start_stop(hw, true);

				if (status) {
					dev_warn(dev, "fw-lldp-dcbx-agent fail to start\n");

					/* toggle bit back to previous state */
					change_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, pf->flags);

				} else {
					/* later would get notification from FW */

					pf->dcbx_cap &= ~DCB_CAP_DCBX_HOST;
					pf->dcbx_cap |= DCB_CAP_DCBX_LLD_MANAGED;

					hw->port_info->qos_cfg.dcbx_mode = NSE_QOS_DCBX_MODE_FW;

					dev_info(dev, "fw-lldp-dcbx-subagent is now active\n");
				}
			}
		}
	}

	if (test_bit(NSE_FLAG_LEGACY_RX, change_flags)) {
		/* down and up VSI so that changes of Rx cfg are reflected. */
		if (!test_and_set_bit(NSE_VSI_DOWN, vsi->state)) {
			nse_down(vsi);
			nse_up(vsi);
		}
	}

	/* don't allow modification of this flag when a single VF is in
	 * promiscuous mode because it's not supported
	 */
	if (test_bit(NSE_FLAG_VF_TRUE_PROMISC_ENA, change_flags) &&
	    nse_is_any_vf_in_unicast_promisc(pf)) {
		dev_err(dev, "Changing vf-true-promisc-support flag while VF(s) are in promiscuous mode not supported\n");
		/* toggle bit back to previous state */
		change_bit(NSE_FLAG_VF_TRUE_PROMISC_ENA, pf->flags);
		ret = -EAGAIN;
	}

	if (test_bit(NSE_FLAG_VF_VLAN_PRUNING, change_flags) &&
	    nse_has_vfs(pf)) {
		dev_err(dev, "vf-vlan-pruning: VLAN pruning cannot be changed while VFs are active.\n");
		/* toggle bit back to previous state */
		change_bit(NSE_FLAG_VF_VLAN_PRUNING, pf->flags);
		ret = -EOPNOTSUPP;
	}

	clear_bit(NSE_FLAG_ETHTOOL_CTXT, pf->flags);
	return ret;
}

static int nse_get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		/* The number (and order) of strings reported *must* remain
		 * constant for a given netdevice. This function must not
		 * report a different number based on run time parameters
		 * (such as the number of queues in use, or the setting of
		 * a private ethtool flag). This is due to the nature of the
		 * ethtool stats API.
		 *
		 * Userspace programs such as ethtool must make 3 separate
		 * ioctl requests, one for size, one for the strings, and
		 * finally one for the stats. Since these cross into
		 * userspace, changes to the number or size could result in
		 * undefined memory access or incorrect string<->value
		 * correlations for statistics.
		 *
		 * Even if it appears to be safe, changes to the size or
		 * order of strings will suffer from race conditions and are
		 * not safe.
		 */
		return NSE_ALL_STATS_LEN(netdev);
	case ETH_SS_TEST:
		return NSE_TEST_LEN;
	case ETH_SS_PRIV_FLAGS:
		return NSE_PRIV_FLAG_ARRAY_SIZE;
	default:
		return -EOPNOTSUPP;
	}
}

static void
__nse_get_ethtool_stats(struct net_device *netdev,
			struct ethtool_stats __always_unused *stats, u64 *data,
			struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_ring *ring;
	struct nse_txcq_ring *cq_ring;
	unsigned int i = 0, j = 0;
	char *p;

	nse_update_pf_stats(pf);
	nse_update_vsi_stats(vsi);

	for (j = 0; j < NSE_VSI_STATS_LEN; j++) {
		p = (char *)vsi + nse_gstrings_vsi_stats[j].stat_offset;
		data[i++] = (nse_gstrings_vsi_stats[j].sizeof_stat ==
			     sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
	}
	if (nse_is_port_repr_netdev(netdev))
		return;
	/* populate per queue stats */
	rcu_read_lock();

	/* RXQ stats: regular-RXQ (may including its XDP stats), macvlan-RXQ
	 */
	nse_for_each_alloc_rxq(vsi, j) {
		ring = vsi->rx_rings[j];

		data[i++] = ring ? ring->stats.pkts : 0;
		data[i++] = ring ? ring->stats.bytes : 0;
#ifdef NSE_ADD_PROBES
		data[i++] = ring ? ring->stats.napi_poll_cnt : 0;
#endif

#ifdef NSE_ADD_PROBES
		nse_get_xdp_rx_stats(ring ? &ring->xdp_stats : NULL, data, &i);
#endif /* NSE_ADD_PROBES */
	}

#ifdef NSE_ADD_PROBES
	nse_get_macvlan_rx_stats(vsi->back, data, &i);
#endif /* NSE_ADD_PROBES */

	/* TXQ stats: regular-TXQ, XDP-TXQ, macvlan-TXQ
	 */
	nse_for_each_alloc_txq(vsi, j) {
		ring = vsi->tx_rings[j];

		data[i++] = ring ? ring->stats.pkts : 0;
		data[i++] = ring ? ring->stats.bytes : 0;
#ifdef NSE_ADD_PROBES
		data[i++] = ring ? ring->stats.napi_poll_cnt : 0;
#endif
	}

	nse_get_xdp_tx_stats(vsi, data, &i);

#ifdef NSE_ADD_PROBES
	nse_get_macvlan_tx_stats(vsi->back, data, &i);
#endif /* NSE_ADD_PROBES */

	/* CQ stats
	 */
	if (vsi->type == NSE_VSI_PF && vsi->sw_conf.lan_tx_use_cq) {
		nse_for_each_lan_txcq(vsi, j) {
			cq_ring = vsi->txcq_rings[j];

			data[i++] = cq_ring ? cq_ring->stats.pkts : 0;
			data[i++] = cq_ring ? cq_ring->stats.bytes : 0;
			data[i++] = cq_ring ? cq_ring->stats.cqe_cnt : 0;
			data[i++] = cq_ring ? cq_ring->stats.gen_flip_cnt : 0;
			data[i++] = cq_ring ? cq_ring->stats.txqe_cnt : 0;
#ifdef NSE_ADD_PROBES
			data[i++] = cq_ring ? cq_ring->stats.napi_poll_cnt : 0;
#endif
		}
	}

	rcu_read_unlock();

	if (vsi->type != NSE_VSI_PF)
		return;

	for (j = 0; j < NSE_LAN_STATS_LEN; j++) {
		p = (char *)pf + nse_gstrings_lan_stats[j].stat_offset;
		data[i++] = (nse_gstrings_lan_stats[j].sizeof_stat ==
			     sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
	}

	for (j = 0; j < NSE_MAX_USER_PRIORITY; j++) {
		data[i++] = pf->stats.rx_pfc_xoff[j];
		data[i++] = pf->stats.rx_pfc_xon[j];
	}

	for (j = 0; j < NSE_MAX_USER_PRIORITY; j++) {
		data[i++] = pf->stats.tx_pfc_xoff[j];
		data[i++] = pf->stats.tx_pfc_xon[j];
	}
}

static void
nse_get_ethtool_stats(struct net_device *netdev,
		      struct ethtool_stats __always_unused *stats, u64 *data)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);

	__nse_get_ethtool_stats(netdev, stats, data, np->vsi);
}

/**
 * nse_get_rss_hash_opt - Retrieve hash fields for a given flow-type
 * @vsi: the VSI being configured
 * @nfc: ethtool rxnfc command
 */
static int
nse_get_rss_hash_opt(struct nse_vsi *vsi, struct ethtool_rxnfc *cmd)
{
	u32 rss_ctl = vsi->rss_ctl;

	cmd->data = 0;

	switch (cmd->flow_type) {
	case TCP_V4_FLOW:

		cmd->data |= RXH_IP_SRC | RXH_IP_DST;

		if (rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV4_TCP)
			cmd->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;

		break;

	case UDP_V4_FLOW:

		cmd->data |= RXH_IP_SRC | RXH_IP_DST;

		if (rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV4_UDP)
			cmd->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;

		break;

	case SCTP_V4_FLOW:
	case AH_ESP_V4_FLOW:
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case IPV4_FLOW:

		cmd->data |= RXH_IP_SRC | RXH_IP_DST;

		break;

	case TCP_V6_FLOW:

		cmd->data |= RXH_IP_SRC | RXH_IP_DST;

		if (rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV6_TCP)
			cmd->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;

		break;

	case UDP_V6_FLOW:

		cmd->data |= RXH_IP_SRC | RXH_IP_DST;

		if (rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV6_UDP)
			cmd->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;

		break;

	case SCTP_V6_FLOW:
	case AH_ESP_V6_FLOW:
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
	case IPV6_FLOW:

		cmd->data |= RXH_IP_SRC | RXH_IP_DST;

		break;

	default:
		return -EINVAL;
	}

	return 0;
}

/**
 * nse_get_rxnfc - command to get Rx flow classification rules
 * @netdev: network interface device structure
 * @cmd: ethtool rxnfc command
 * @rule_locs: buffer to rturn Rx flow classification rules
 *
 * Returns Success if the command is supported.
 */
static int
nse_get_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd,
	      u32 *rule_locs)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	int ret = -EOPNOTSUPP;

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = vsi->num_rxq;
		ret = 0;
		break;
	case ETHTOOL_GRXCLSRLCNT:
		cmd->rule_cnt = cb->filter_count;
		/* report max rule count */
		cmd->data = (cb->mode == FDIR_CTL_FILTER_MODE_PERFECT) ?
					(cb->max_num_pfilter_pf_vsi - 2) :
					(cb->max_num_sfilter_pf_vsi - 2);
		ret = 0;
		break;
	case ETHTOOL_GRXCLSRULE:
		ret = nse_get_ethtool_ntuple(vsi, cmd);
		break;
	case ETHTOOL_GRXCLSRLALL:
		ret = nse_get_ethtool_ntuple_ids(vsi, cmd, rule_locs);
		break;
	case ETHTOOL_GRXFH:
		ret = nse_get_rss_hash_opt(vsi, cmd);
		break;
	default:
		break;
	}

	return ret;
}

/**
 * nse_set_rss_hash_opt - Enable/Disable flow types for RSS hash
 * @vsi: the VSI being configured
 * @nfc: ethtool rxnfc command
 *
 * Returns Success if the flow input set is supported.
 */
static int
nse_set_rss_hash_opt(struct nse_vsi *vsi, struct ethtool_rxnfc *nfc)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	u32 old_alg, new_alg;
	int ret;

	old_alg = new_alg = vsi->rss_ctl_user_req_alg;

	if (nfc->data & ~(RXH_IP_SRC | RXH_IP_DST |
			  RXH_L4_B_0_1 | RXH_L4_B_2_3))
		return -EINVAL;

	switch (nfc->flow_type) {
	case TCP_V4_FLOW:
	case TCP_V6_FLOW:
	case UDP_V4_FLOW:
	case UDP_V6_FLOW:

		if (!(nfc->data & RXH_IP_SRC) ||
			!(nfc->data & RXH_IP_DST))
			return -EINVAL;

		switch (nfc->data & (RXH_L4_B_0_1 | RXH_L4_B_2_3)) {
		case 0:
			if (nfc->flow_type == TCP_V4_FLOW)
				new_alg &= ~NSE_VSI_RSS_CTL_ALG_IPV4_TCP;
			else if (nfc->flow_type == TCP_V6_FLOW)
				new_alg &= ~NSE_VSI_RSS_CTL_ALG_IPV6_TCP;
			else if (nfc->flow_type == UDP_V4_FLOW)
				new_alg &= ~NSE_VSI_RSS_CTL_ALG_IPV4_UDP;
			else if (nfc->flow_type == UDP_V6_FLOW)
				new_alg &= ~NSE_VSI_RSS_CTL_ALG_IPV6_UDP;

			break;

		case (RXH_L4_B_0_1 | RXH_L4_B_2_3):
			if (nfc->flow_type == TCP_V4_FLOW)
				new_alg |= NSE_VSI_RSS_CTL_ALG_IPV4_TCP;
			else if (nfc->flow_type == TCP_V6_FLOW)
				new_alg |= NSE_VSI_RSS_CTL_ALG_IPV6_TCP;
			else if (nfc->flow_type == UDP_V4_FLOW)
				new_alg |= NSE_VSI_RSS_CTL_ALG_IPV4_UDP;
			else if (nfc->flow_type == UDP_V6_FLOW)
				new_alg |= NSE_VSI_RSS_CTL_ALG_IPV6_UDP;

			break;

		default:
			return -EINVAL;
		}

		break;

	case AH_ESP_V4_FLOW:
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case SCTP_V4_FLOW:
	case AH_ESP_V6_FLOW:
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
	case SCTP_V6_FLOW:
		if (!(nfc->data & RXH_IP_SRC) ||
		    !(nfc->data & RXH_IP_DST) ||
		    (nfc->data & RXH_L4_B_0_1) ||
		    (nfc->data & RXH_L4_B_2_3))
			return -EINVAL;

		break;

	default:
		return -EINVAL;
	}

	/* if we changed something we need to update flags */
	if (new_alg != old_alg) {
		vsi->rss_ctl_user_req_alg = new_alg;

		ret = nse_vsi_cfg_rss_ctl(vsi);
		if (ret) {
			dev_err(dev, "cfg_rss_ctl failed, vsi num = %d, error = %d\n",
				vsi->vsi_abs_num, ret);

			/* restore old value, if any failure */
			vsi->rss_ctl_user_req_alg = old_alg;

			return ret;
		}
	}

	return 0;
}

/**
 * nse_set_rxnfc - command to set Rx flow rules.
 * @netdev: network interface device structure
 * @cmd: ethtool rxnfc command
 *
 * Returns 0 for success and negative values for errors
 */
static int nse_set_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;

	switch (cmd->cmd) {
	case ETHTOOL_SRXCLSRLINS:
		return nse_add_ethtool_ntuple(vsi, cmd);
	case ETHTOOL_SRXCLSRLDEL:
		return nse_del_ethtool_ntuple(vsi, cmd);
	case ETHTOOL_SRXFH:
		return nse_set_rss_hash_opt(vsi, cmd);
	default:
		break;
	}
	return -EOPNOTSUPP;
}

/**
 * nse_get_rxfh_key_size - get the RSS hash key size
 * @netdev: network interface device structure
 *
 * Returns the table size.
 */
static u32 nse_get_rxfh_key_size(struct net_device __always_unused *netdev)
{
	return NSE_RSS_KEY_SIZE;
}

/**
 * nse_get_rxfh_indir_size - get the Rx flow hash indirection table size
 * @netdev: network interface device structure
 *
 * Returns the table size.
 */
static u32 nse_get_rxfh_indir_size(struct net_device *netdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);

	return np->vsi->rss_lut_size_aligned;
}

/**
 * nse_get_rxfh - get the Rx flow hash indirection table
 * @netdev: network interface device structure
 * @indir: indirection table
 * @key: hash key
 * @hfunc: hash function
 *
 * Reads the indirection table directly from the hardware.
 */
static int
nse_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key, u8 *hfunc)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	int err, i;
	u16 *lut;

	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;

	if (!indir)
		return 0;

	lut = kcalloc(vsi->rss_lut_size_aligned, sizeof(u16), GFP_KERNEL);
	if (!lut)
		return -ENOMEM;

	err = nse_get_rss_key(vsi, key);
	if (err)
		goto out;

	err = nse_get_rss_lut(vsi, lut, vsi->rss_lut_size_aligned);
	if (err)
		goto out;

	for (i = 0; i < vsi->rss_lut_size_aligned; i++)
		indir[i] = (u32)(lut[i]);

out:
	kfree(lut);
	return err;
}

/**
 * nse_set_rxfh - set the Rx flow hash indirection table
 * @netdev: network interface device structure
 * @indir: indirection table
 * @key: hash key
 * @hfunc: hash function
 *
 * Returns -EINVAL if the table specifies an invalid queue ID, otherwise
 * returns 0 after programming the table.
 */
static int
nse_set_rxfh(struct net_device *netdev, const u32 *indir, const u8 *key,
	     const u8 hfunc)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	int i;
	int err = 0;

	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;

	if (key) {
		if (!vsi->rss_hkey_user) {
			vsi->rss_hkey_user =
				devm_kzalloc(dev, NSE_RSS_KEY_SIZE,
					     GFP_KERNEL);
			if (!vsi->rss_hkey_user)
				return -ENOMEM;
		}
		memcpy(vsi->rss_hkey_user, key, NSE_RSS_KEY_SIZE);

		err = nse_set_rss_key(vsi, vsi->rss_hkey_user);
		if (err)
			return err;
	}

	if (indir) {
		/* Verify user input. */
		for (i = 0; i < vsi->rss_lut_size_aligned; i++)
			if (indir[i] >= vsi->num_rxq)
				return -EINVAL;

		if (!vsi->rss_lut_user) {
			vsi->rss_lut_user = devm_kzalloc(dev,
							 sizeof(u16) * vsi->rss_lut_size_aligned,
							 GFP_KERNEL);
			if (!vsi->rss_lut_user)
				return -ENOMEM;
		}

		/* Each 32 bits pointed by 'indir' is stored with a lut entry */
		for (i = 0; i < vsi->rss_lut_size_aligned; i++)
			vsi->rss_lut_user[i] = (u8)(indir[i]);

		err = nse_set_rss_lut(vsi, vsi->rss_lut_user, vsi->rss_lut_size_aligned);
		if (err)
			return err;
	}

	return 0;
}

static int
nse_get_ts_info(struct net_device *dev, struct ethtool_ts_info *info)
{
	struct nse_pf *pf = nse_netdev_to_pf(dev);

	/* only report timestamping if PTP is enabled */
	if (!test_bit(NSE_FLAG_PTP, pf->flags))
		return ethtool_op_get_ts_info(dev, info);

	info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
				SOF_TIMESTAMPING_RX_SOFTWARE |
				SOF_TIMESTAMPING_SOFTWARE |
				SOF_TIMESTAMPING_TX_HARDWARE |
				SOF_TIMESTAMPING_RX_HARDWARE |
				SOF_TIMESTAMPING_RAW_HARDWARE;

	info->phc_index = nse_get_ptp_clock_index(pf);

	info->tx_types = BIT(HWTSTAMP_TX_OFF) | BIT(HWTSTAMP_TX_ON);

	info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) | BIT(HWTSTAMP_FILTER_ALL);

	return 0;
}

static void
nse_get_ringparam(struct net_device *netdev,
		  struct ethtool_ringparam *ring,
		  struct kernel_ethtool_ringparam __always_unused *kernel_rp,
		  struct netlink_ext_ack __always_unused *extack)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;

	ring->rx_max_pending = NSE_MAX_NUM_DESC;
	ring->tx_max_pending = NSE_MAX_NUM_DESC;
	ring->rx_pending = vsi->rx_rings[0]->count;
	ring->tx_pending = vsi->tx_rings[0]->count;

	/* Rx mini and jumbo rings are not supported */
	ring->rx_mini_max_pending = 0;
	ring->rx_jumbo_max_pending = 0;
	ring->rx_mini_pending = 0;
	ring->rx_jumbo_pending = 0;
}

static int
nse_set_ringparam(struct net_device *netdev,
		  struct ethtool_ringparam *ring,
		  struct kernel_ethtool_ringparam __always_unused *kernel_rp,
		  struct netlink_ext_ack __always_unused *extack)
{
	struct nse_ring *tx_rings = NULL, *rx_rings = NULL;
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_ring *xdp_rings = NULL;
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	int i, timeout = 50, err = 0;
	u16 new_rx_cnt, new_tx_cnt;

	if (ring->tx_pending > NSE_MAX_NUM_DESC ||
	    ring->tx_pending < NSE_MIN_NUM_DESC ||
	    ring->rx_pending > NSE_MAX_NUM_DESC ||
	    ring->rx_pending < NSE_MIN_NUM_DESC) {
		netdev_err(netdev, "Descriptors requested (Tx: %d / Rx: %d) out of range [%d-%d] (increment %d)\n",
			   ring->tx_pending, ring->rx_pending,
			   NSE_MIN_NUM_DESC, NSE_MAX_NUM_DESC,
			   NSE_REQ_DESC_MULTIPLE);
		return -EINVAL;
	}

	new_tx_cnt = ALIGN(ring->tx_pending, NSE_REQ_DESC_MULTIPLE);
	if (new_tx_cnt != ring->tx_pending)
		netdev_info(netdev, "Requested Tx descriptor count rounded up to %d\n",
			    new_tx_cnt);
	new_rx_cnt = ALIGN(ring->rx_pending, NSE_REQ_DESC_MULTIPLE);
	if (new_rx_cnt != ring->rx_pending)
		netdev_info(netdev, "Requested Rx descriptor count rounded up to %d\n",
			    new_rx_cnt);

	/* if nothing to do return success */
	if (new_tx_cnt == vsi->tx_rings[0]->count &&
	    new_rx_cnt == vsi->rx_rings[0]->count) {
		netdev_dbg(netdev, "Nothing to change, descriptor count is same as requested\n");
		return 0;
	}

	/* If there is a AF_XDP UMEM attached to any of Rx rings,
	 * disallow changing the number of descriptors -- regardless
	 * if the netdev is running or not.
	 */
	if (nse_xsk_any_rx_ring_ena(vsi))
		return -EBUSY;

	while (test_and_set_bit(NSE_CFG_BUSY, pf->state)) {
		timeout--;
		if (!timeout)
			return -EBUSY;
		usleep_range(1000, 2000);
	}

	/* set for the next time the netdev is started */
	if (!(vsi->netdev->flags & IFF_UP)) {
		for (i = 0; i < vsi->alloc_txq; i++)
			vsi->tx_rings[i]->count = new_tx_cnt;
		for (i = 0; i < vsi->alloc_rxq; i++)
			vsi->rx_rings[i]->count = new_rx_cnt;
		if (nse_is_xdp_ena_vsi(vsi))
			for (i = 0; i < vsi->num_xdp_txq; i++)
				vsi->xdp_rings[i]->count = new_tx_cnt;
		vsi->num_tx_desc = (u16)new_tx_cnt;
		vsi->num_rx_desc = (u16)new_rx_cnt;
		netdev_dbg(netdev, "Link is down, descriptor count change happens when link is brought up\n");
		goto done;
	}

	if (new_tx_cnt == vsi->tx_rings[0]->count)
		goto process_rx;

	/* alloc updated Tx resources */
	netdev_info(netdev, "Changing Tx descriptor count from %d to %d\n",
		    vsi->tx_rings[0]->count, new_tx_cnt);

	tx_rings = kcalloc(vsi->num_txq, sizeof(*tx_rings), GFP_KERNEL);
	if (!tx_rings) {
		err = -ENOMEM;
		goto done;
	}

	nse_for_each_txq(vsi, i) {
		/* clone ring and setup updated count */
		tx_rings[i] = *vsi->tx_rings[i];
		tx_rings[i].count = new_tx_cnt;
		tx_rings[i].desc = NULL;
		tx_rings[i].tx_buf = NULL;
		err = nse_setup_tx_ring(&tx_rings[i]);
		if (err) {
			while (i--)
				nse_clean_tx_ring(&tx_rings[i]);
			kfree(tx_rings);
			goto done;
		}
	}

	if (!nse_is_xdp_ena_vsi(vsi))
		goto process_rx;

	/* alloc updated XDP resources */
	netdev_info(netdev, "Changing XDP descriptor count from %d to %d\n",
		    vsi->xdp_rings[0]->count, new_tx_cnt);

	xdp_rings = kcalloc(vsi->num_xdp_txq, sizeof(*xdp_rings), GFP_KERNEL);
	if (!xdp_rings) {
		err = -ENOMEM;
		goto free_tx;
	}

	for (i = 0; i < vsi->num_xdp_txq; i++) {
		/* clone ring and setup updated count */
		xdp_rings[i] = *vsi->xdp_rings[i];
		xdp_rings[i].count = new_tx_cnt;
		xdp_rings[i].desc = NULL;
		xdp_rings[i].tx_buf = NULL;
		err = nse_setup_tx_ring(&xdp_rings[i]);
		if (err) {
			while (i--)
				nse_clean_tx_ring(&xdp_rings[i]);
			kfree(xdp_rings);
			goto free_tx;
		}
		nse_set_ring_xdp(&xdp_rings[i]);
	}

process_rx:
	if (new_rx_cnt == vsi->rx_rings[0]->count)
		goto process_link;

	/* alloc updated Rx resources */
	netdev_info(netdev, "Changing Rx descriptor count from %d to %d\n",
		    vsi->rx_rings[0]->count, new_rx_cnt);

	rx_rings = kcalloc(vsi->num_rxq, sizeof(*rx_rings), GFP_KERNEL);
	if (!rx_rings) {
		err = -ENOMEM;
		goto done;
	}

	nse_for_each_rxq(vsi, i) {
		/* clone ring and setup updated count */
		rx_rings[i] = *vsi->rx_rings[i];
		rx_rings[i].count = new_rx_cnt;
		rx_rings[i].desc = NULL;
		rx_rings[i].rx_buf = NULL;

		rx_rings[i].tail = vsi->back->hw.hw_addr + NSE_REG_ST;

		err = nse_setup_rx_ring(&rx_rings[i]);
		if (err)
			goto rx_unwind;

		/* allocate Rx buffers */
		err = nse_alloc_rx_bufs(&rx_rings[i],
					NSE_DESC_UNUSED(&rx_rings[i]));
rx_unwind:
		if (err) {
			while (i) {
				i--;
				nse_free_rx_ring(&rx_rings[i]);
			}
			kfree(rx_rings);
			err = -ENOMEM;
			goto free_tx;
		}
	}

process_link:
	/* Bring interface down, copy in the new ring info, then restore the
	 * interface. if VSI is up, bring it down and then back up
	 */
	if (!test_and_set_bit(NSE_VSI_DOWN, vsi->state)) {
		nse_down(vsi);

		if (tx_rings) {
			nse_for_each_txq(vsi, i) {
				nse_free_tx_ring(vsi->tx_rings[i]);
				*vsi->tx_rings[i] = tx_rings[i];
			}
			kfree(tx_rings);
		}

		if (rx_rings) {
			nse_for_each_rxq(vsi, i) {
				nse_free_rx_ring(vsi->rx_rings[i]);
				/* copy the real tail offset */
				rx_rings[i].tail = vsi->rx_rings[i]->tail;
				/* this is to fake out the allocation routine
				 * into thinking it has to realloc everything
				 * but the recycling logic will let us re-use
				 * the buffers allocated above
				 */
				rx_rings[i].next_to_use = 0;
				rx_rings[i].next_to_clean = 0;
				rx_rings[i].next_to_alloc = 0;
				*vsi->rx_rings[i] = rx_rings[i];
			}
			kfree(rx_rings);
		}

		if (xdp_rings) {
			for (i = 0; i < vsi->num_xdp_txq; i++) {
				nse_free_tx_ring(vsi->xdp_rings[i]);
				*vsi->xdp_rings[i] = xdp_rings[i];
			}
			kfree(xdp_rings);
		}

		vsi->num_tx_desc = new_tx_cnt;
		vsi->num_rx_desc = new_rx_cnt;
		nse_up(vsi);
	}
	goto done;

free_tx:
	/* error cleanup if the Rx allocations failed after getting Tx */
	if (tx_rings) {
		nse_for_each_txq(vsi, i)
			nse_free_tx_ring(&tx_rings[i]);
		kfree(tx_rings);
	}

done:
	clear_bit(NSE_CFG_BUSY, pf->state);
	return err;
}

static void
nse_get_pauseparam(struct net_device *netdev, struct ethtool_pauseparam *pause)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_port_info *pi = np->vsi->port_info;
	struct nse_dcbx_cfg *dcbx_cfg = &pi->qos_cfg.local_dcbx_cfg;
	struct nse_lmac_phy_info *lpinfo = &pi->lmac_phy_info;

	/* Initialize pause params */
	pause->rx_pause = 0;
	pause->tx_pause = 0;

	/* PFC enabled so report LFC as off */
	if (dcbx_cfg->pfc.pfcena)
		return;

	if (dcbx_cfg->pfc.pfcena ||
		lpinfo->fc_info.current_mode == NSE_FC_PFC ||
		lpinfo->fc_info.current_mode == NSE_FC_LFC_NONE) {
		pause->rx_pause = 0;
		pause->tx_pause = 0;
	} else if (lpinfo->fc_info.current_mode == NSE_FC_LFC_RX_PAUSE) {
		pause->rx_pause = 1;
		pause->tx_pause = 0;
	} else if (lpinfo->fc_info.current_mode == NSE_FC_LFC_TX_PAUSE) {
		pause->rx_pause = 0;
		pause->tx_pause = 1;
	} else if (lpinfo->fc_info.current_mode == NSE_FC_LFC_FULL) {
		pause->rx_pause = 1;
		pause->tx_pause = 1;
	}

	pause->autoneg = lpinfo->fc_info.autoneg_lfc;
}

static int
nse_set_pauseparam(struct net_device *netdev, struct ethtool_pauseparam *pause)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_port_info *pi = vsi->port_info;
	struct nse_dcbx_cfg *dcbx_cfg = &pi->qos_cfg.local_dcbx_cfg;
	enum nse_fc_mode new_req_mode;
	enum nse_status status;

	/* Changing the port's flow control is not supported if this isn't the
	 * PF VSI
	 */
	if (vsi->type != NSE_VSI_PF) {
		netdev_info(netdev, "Changing flow control parameters only supported for PF VSI\n");
		return -EOPNOTSUPP;
	}

	if (dcbx_cfg->pfc.pfcena) {
		netdev_info(netdev, "Priority flow control enabled. Cannot set link flow control.\n");
		return -EOPNOTSUPP;
	}

	if ((pause->rx_pause && pause->tx_pause) || pause->autoneg)
		new_req_mode = NSE_FC_LFC_FULL;
	else if (pause->rx_pause && !pause->tx_pause)
		new_req_mode = NSE_FC_LFC_RX_PAUSE;
	else if (!pause->rx_pause && pause->tx_pause)
		new_req_mode = NSE_FC_LFC_TX_PAUSE;
	else if (!pause->rx_pause && !pause->tx_pause)
		new_req_mode = NSE_FC_LFC_NONE;
	else
		return -EINVAL;

	if (pi->lmac_phy_info.fc_info.req_mode == new_req_mode ||
		pi->lmac_phy_info.fc_info.current_mode == new_req_mode)
		return 0;

	pi->lmac_phy_info.fc_info.req_mode = new_req_mode;

	status = nse_set_dcb_cfg_lw(pi, NSE_DCB_CFG_CHG_TYPE_PFC);
	if (status) {
		netdev_err(netdev, "FAIL: configure LFC, status=%d\n", status);
		return -EIO;
	}

	pi->lmac_phy_info.fc_info.current_mode = new_req_mode;

	pi->lmac_phy_info.fc_info.autoneg_lfc = !!(pause->autoneg);

	/* TODO: if backplane, should start AN73? --- like set_fecparam() */

	return 0;
}

/**
 * nse_get_max_txq - return the maximum number of Tx queues for in a PF
 * @pf: PF structure
 */
u16 nse_get_max_txq_main_vsi_netdev(struct nse_pf *pf, struct nse_vsi *main_vsi)
{
	u16 max, offset = 0;

	if (main_vsi && main_vsi->vsi_txq_space_start != NSE_INVAL_Q_ID) {
		offset = main_vsi->vsi_txq_space_start;

		/* direct before free area */
		max = nse_get_avail_txq_count_contig_before_offset(pf, offset);

		/* already allocated txq area */
		max += main_vsi->alloc_txq;

		offset = main_vsi->vsi_txq_space_start + main_vsi->alloc_txq;

		/* direct after free area */
		max += nse_get_avail_txq_count_contig_from_offset(pf, offset);

	} else {
		max = nse_get_avail_txq_count_max_contig(pf);
	}

	if (max > pf->main_vsi_lan_txqs_max)
		max = pf->main_vsi_lan_txqs_max;

	if (nse_main_vsi_max_lanq_num && max > nse_main_vsi_max_lanq_num)
		max = nse_main_vsi_max_lanq_num;

	return max;
}

/**
 * nse_get_max_rxq - return the maximum number of Rx queues for in a PF
 * @pf: PF structure
 */
u16 nse_get_max_rxq_main_vsi_netdev(struct nse_pf *pf, struct nse_vsi *main_vsi)
{
	u16 max, offset = 0;

	if (main_vsi && main_vsi->vsi_rxq_space_start != NSE_INVAL_Q_ID) {
		offset = main_vsi->vsi_rxq_space_start;

		/* direct before free area */
		max = nse_get_avail_rxq_count_contig_before_offset(pf, offset);

		/* already allocated RXQ area */
		max += main_vsi->alloc_rxq;

		offset = main_vsi->vsi_rxq_space_start + main_vsi->alloc_rxq;

		/* direct after free area */
		max += nse_get_avail_rxq_count_contig_from_offset(pf, offset);

	} else {
		max = nse_get_avail_rxq_count_max_contig(pf);
	}

	if (max > pf->main_vsi_lan_rxqs_max)
		max = pf->main_vsi_lan_rxqs_max;

	if (nse_main_vsi_max_lanq_num && max > nse_main_vsi_max_lanq_num)
		max = nse_main_vsi_max_lanq_num;

	return max;
}

/**
 * nse_get_combined_cnt - return the current number of combined channels
 * @vsi: PF VSI pointer
 *
 * Go through all queue vectors and count ones that have both Rx and Tx ring
 * attached
 */
static u16 nse_get_main_vsi_cur_combined_cnt(struct nse_vsi *vsi)
{
	u16 combined = 0;
	int q_idx;

	nse_for_each_q_vector(vsi, q_idx) {
		struct nse_q_vector *q_vector = vsi->q_vectors[q_idx];

		if (q_vector->rx.ring && q_vector->tx.ring)
			combined += q_vector->num_ring_rx;
	}

	return combined;
}

static u16 nse_get_main_vsi_netdev_max_combined_cnt(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	u16 max_rxq, max_txq;

	max_rxq = nse_get_max_rxq_main_vsi_netdev(pf, vsi);
	max_txq = nse_get_max_txq_main_vsi_netdev(pf, vsi);

	return min(max_rxq, max_txq);
}

/**
 * nse_get_channels - get the current and max supported channels
 * @dev: network interface device structure
 * @ch: ethtool channel data structure
 */
static void
nse_get_channels(struct net_device *dev, struct ethtool_channels *ch)
{
	struct nse_netdev_priv *np = netdev_priv(dev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;

	/* report maximum channels */
	ch->max_combined = nse_get_main_vsi_netdev_max_combined_cnt(vsi);

	/* report current channels */
	ch->combined_count = nse_get_main_vsi_cur_combined_cnt(vsi);

	if (test_bit(NSE_FLAG_MACVLAN_ENA, pf->flags)) {
		/* L2 forwarding devices are single queue so we infer one
		 * device is one channel
		 */
		ch->max_combined += pf->max_num_macvlan;
		ch->combined_count += pf->num_macvlan;
	}

	/* report other queues */
	ch->other_count = 0;
	ch->max_other = 0;
}

/**
 * nse_set_channels - set the number channels
 * @dev: network interface device structure
 * @ch: ethtool channel data structure
 */
static int nse_set_channels(struct net_device *dev, struct ethtool_channels *ch)
{
	struct nse_netdev_priv *np = netdev_priv(dev);
	struct nse_vsi *vsi = np->vsi;	/* main_vsi */
	struct nse_pf *pf = vsi->back;
	u16 curr_combined, new_combined, max_combined;
	int err;

	if (!ch->combined_count || ch->rx_count || ch->tx_count)
		return -EINVAL;

	/* do not support changing other_count */
	if (ch->other_count)
		return -EINVAL;

	if (test_bit(NSE_FLAG_MACVLAN_ENA, pf->flags)) {
		netdev_err(dev, "Cannot set channels when L2 forwarding enabled\n");
		return -EOPNOTSUPP;
	}

	if (vsi->sw_conf.fdir_ena && pf->hw.fdir_cb.filter_count) {
		netdev_err(dev, "Cannot set channels when Flow Director filters are active\n");
		return -EOPNOTSUPP;
	}

	curr_combined = nse_get_main_vsi_cur_combined_cnt(vsi);
	max_combined = nse_get_main_vsi_netdev_max_combined_cnt(vsi);

	new_combined = ch->combined_count;

	if (new_combined < vsi->tc_cfg.numtc) {
		netdev_err(dev, "Cannot set less channels, than Traffic Classes you have (%u)\n",
			   vsi->tc_cfg.numtc);
		return -EINVAL;
	}

	if (new_combined > max_combined) {
		netdev_err(dev, "should not set more than max_combined (%d)\n",
						   max_combined);
		return -EINVAL;
	}

	err = nse_vsi_recfg_qs(vsi, new_combined, new_combined);
	if (err)
		goto channels_out;

	err = netif_is_rxfh_configured(dev);
	if (!err) {
		err = nse_vsi_set_dflt_rss_lut(vsi, new_combined);
		goto channels_out;
	}

channels_out:
	if (nse_is_aux_ena(pf)) {
		set_bit(NSE_FLAG_UNPLUG_AUX_DEV, pf->flags);
		set_bit(NSE_FLAG_PLUG_AUX_DEV, pf->flags);
	}

	return err;
}

/**
 * nse_get_wol - get current Wake on LAN configuration
 * @netdev: network interface devnse structure
 * @wol: Ethtool structure to retrieve WoL settings
 */
static void nse_get_wol(struct net_device *netdev, struct ethtool_wolinfo *wol)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_pf *pf = np->vsi->back;

	if (np->vsi->type != NSE_VSI_PF)
		netdev_warn(netdev, "Wake on LAN is not supported on this interface!\n");

	/* Get WoL settings based on the HW capability */
	if (nse_is_wol_supported(&pf->hw)) {
		wol->supported = WAKE_MAGIC;
		wol->wolopts = pf->wol_ena ? WAKE_MAGIC : 0;
	} else {
		wol->supported = 0;
		wol->wolopts = 0;
	}
}

/**
 * nse_set_wol - set Wake on LAN on supported device
 * @netdev: network interface device structure
 * @wol: Ethtool structure to set WoL
 */
static int nse_set_wol(struct net_device *netdev, struct ethtool_wolinfo *wol)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;

	if (vsi->type != NSE_VSI_PF || !nse_is_wol_supported(&pf->hw))
		return -EOPNOTSUPP;

	/* only magic packet is supported */
	if (wol->wolopts && wol->wolopts != WAKE_MAGIC)
		return -EOPNOTSUPP;

	/* Set WoL only if there is a new value */
	if (pf->wol_ena != !!wol->wolopts) {
		pf->wol_ena = !!wol->wolopts;
		device_set_wakeup_enable(nse_pf_to_dev(pf), pf->wol_ena);
		netdev_dbg(netdev, "WoL magic packet %sabled\n",
			   pf->wol_ena ? "en" : "dis");
	}

	return 0;
}

/**
 * nse_get_q_coalesce - get a queue's ITR/INTRL (coalesce) settings
 * @vsi: VSI associated to the queue for getting ITR/INTRL (coalesce) settings
 * @ec: coalesce settings to program the device with
 * @q_num: update ITR/INTRL (coalesce) settings for this queue number/index
 *
 * Return 0 on success, and negative under the following conditions:
 * 1. Getting Tx or Rx ITR/INTRL (coalesce) settings failed.
 * 2. The q_num passed in is not a valid number/index for Tx and Rx rings.
 */
static int
nse_get_q_coalesce(struct nse_vsi *vsi, struct ethtool_coalesce *ec, int q_num)
{
	struct nse_q_vector *q_vector;

	if (q_num < vsi->num_rxq) {
		q_vector = vsi->rx_rings[q_num]->q_vector;

		ec->use_adaptive_rx_coalesce = ITR_IS_DYNAMIC(q_vector);
		ec->rx_coalesce_usecs = q_vector->itr_setting;
		ec->rx_coalesce_usecs_high = q_vector->intrl;

		return 0;

	} else {
		return -EINVAL;
	}
}

/**
 * __nse_get_coalesce - get ITR/INTRL values for the device
 * @netdev: pointer to the netdev associated with this query
 * @ec: ethtool structure to fill with driver's coalesce settings
 * @q_num: queue number to get the coalesce settings for
 *
 * If the caller passes in a negative q_num then we return coalesce settings
 * based on queue number 0, else use the actual q_num passed in.
 */
static int
__nse_get_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
		   int q_num)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;

	if (q_num < 0)
		q_num = 0;

	if (nse_get_q_coalesce(vsi, ec, q_num))
		return -EINVAL;

	return 0;
}

static int
nse_get_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
		 struct kernel_ethtool_coalesce __maybe_unused *kec,
		 struct netlink_ext_ack __maybe_unused *extack)

{
	return __nse_get_coalesce(netdev, ec, -1);
}

static int
nse_get_per_q_coalesce(struct net_device *netdev, u32 q_num,
		       struct ethtool_coalesce *ec)
{
	return __nse_get_coalesce(netdev, ec, q_num);
}

/**
 * nse_set_rc_coalesce - set ITR values for specific ring container
 * @c_type: container type, Rx or Tx
 * @ec: ethtool structure from user to update ITR settings
 * @rc: ring container that the ITR values will come from
 * @vsi: VSI associated to the ring container
 *
 * Set specific ITR values. This is done per nse_ring_container because each
 * q_vector can have 1 or more rings and all of said ring(s) will have the same
 * ITR values.
 *
 * Returns 0 on success, negative otherwise.
 */
static int
nse_set_qvec_coalesce(struct ethtool_coalesce *ec,
		    struct nse_q_vector *q_vector, struct nse_vsi *vsi)
{
	const char *c_type_str = "rx";
	u32 use_adaptive_coalesce, coalesce_usecs;
	struct nse_pf *pf = vsi->back;
	u16 itr_setting;

	if (!q_vector->num_ring_rx && !q_vector->num_ring_tx)
		return -EINVAL;

	if (ec->rx_coalesce_usecs_high > NSE_INTRL_INTERVAL_MAX_USEC ||
	    (ec->rx_coalesce_usecs_high &&
	     ec->rx_coalesce_usecs_high < pf->hw.intrl_gran)) {
		netdev_info(vsi->netdev, "Invalid value, %s-usecs-high valid values are 0 (disabled), %d-%d\n",
			    c_type_str, pf->hw.intrl_gran,
			    NSE_INTRL_INTERVAL_MAX_USEC);
		return -EINVAL;
	}
	if (ec->rx_coalesce_usecs_high != q_vector->intrl &&
	    ec->use_adaptive_rx_coalesce) {
		netdev_info(vsi->netdev, "Invalid value, %s-usecs-high cannot be changed if adaptive-rx is enabled\n",
			    c_type_str);
		return -EINVAL;
	}

	use_adaptive_coalesce = ec->use_adaptive_rx_coalesce;
	coalesce_usecs = ec->rx_coalesce_usecs;

	itr_setting = q_vector->itr_setting;
	if (coalesce_usecs != itr_setting && use_adaptive_coalesce) {
		netdev_info(vsi->netdev, "%s interrupt throttling cannot be changed if adaptive-%s is enabled\n",
			    c_type_str, c_type_str);
		return -EINVAL;
	}

	if (coalesce_usecs > NSE_ITR_INTERVAL_MAX_USEC) {
		netdev_info(vsi->netdev, "Invalid value, %s-usecs range is 0-%d\n",
			    c_type_str, NSE_ITR_INTERVAL_MAX_USEC);
		return -EINVAL;
	}

	if (use_adaptive_coalesce) {
		q_vector->itr_mode = ITR_DYNAMIC;
	} else {
		q_vector->itr_mode = ITR_STATIC;
		/* store user facing value how it was set */
		q_vector->itr_setting = coalesce_usecs;

		if (ec->rx_coalesce_usecs_high != q_vector->intrl)
			q_vector->intrl = ec->rx_coalesce_usecs_high;

		/* write the change to the register */
		nse_write_itr(q_vector, coalesce_usecs);

		/* force writes to take effect immediately, the flush shouldn't
		 * be done in the functions above because the intent is for
		 * them to do lazy writes.
		 */
		nse_flush(&pf->hw);
	}

	/* if use_adaptive_coalesce == true, then intrl need to restore to 4 us.
	 *
	 *  otherwise, if use_adaptive_coalesce == false, then intrl need to set to q_vector->intrl
	 * ( default 0 or user may specify rx_coalesce_usecs_high )
	 */
	nse_set_q_vector_intrl(q_vector);

	return 0;
}

/**
 * nse_set_q_coalesce - set a queue's ITR/INTRL (coalesce) settings
 * @vsi: VSI associated to the queue that need updating
 * @ec: coalesce settings to program the device with
 * @q_num: update ITR/INTRL (coalesce) settings for this queue number/index
 *
 * Return 0 on success, and negative under the following conditions:
 * 1. Setting Tx or Rx ITR/INTRL (coalesce) settings failed.
 * 2. The q_num passed in is not a valid number/index for Tx and Rx rings.
 */
static int
nse_set_q_coalesce(struct nse_vsi *vsi, struct ethtool_coalesce *ec, int q_num)
{
	if (q_num < vsi->num_rxq) {
		if (nse_set_qvec_coalesce(ec,
					vsi->rx_rings[q_num]->q_vector,
					vsi))
			return -EINVAL;
	} else if (q_num < vsi->num_txq) {
		if (nse_set_qvec_coalesce(ec,
					vsi->tx_rings[q_num]->q_vector,
					vsi))
			return -EINVAL;
	} else {
		return -EINVAL;
	}

	return 0;
}

/**
 * nse_print_if_odd_usecs - print message if user tries to set odd [tx|rx]-usecs
 * @netdev: netdev used for print
 * @itr_setting: previous user setting
 * @use_adaptive_coalesce: if adaptive coalesce is enabled or being enabled
 * @coalesce_usecs: requested value of [tx|rx]-usecs
 * @c_type_str: either "rx" or "tx" to match user set field of [tx|rx]-usecs
 */
static void
nse_print_if_odd_usecs(struct net_device *netdev, u16 itr_setting,
		       u32 use_adaptive_coalesce, u32 coalesce_usecs,
		       const char *c_type_str)
{
	if (use_adaptive_coalesce)
		return;

	if (itr_setting != coalesce_usecs && (coalesce_usecs % 2))
		netdev_info(netdev, "User set %s-usecs to %d, Rounding down set %s-usecs to %d\n",
			    c_type_str, coalesce_usecs,
			    c_type_str, ITR_REG_ALIGN(coalesce_usecs));
}

/**
 * __nse_set_coalesce - set ITR/INTRL values for the device
 * @netdev: pointer to the netdev associated with this query
 * @ec: ethtool structure to fill with driver's coalesce settings
 * @q_num: queue number to get the coalesce settings for
 *
 * If the caller passes in a negative q_num then we set the coalesce settings
 * for all Tx/Rx queues, else use the actual q_num passed in.
 */
static int
__nse_set_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
		   int q_num)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;

	if (pf->sw_conf.min_itr_no_intrl) {
		dev_err(nse_pf_to_dev(vsi->back), "[%s] don't allow change ITR or INTRL because min_itr_no_intrl = 1\n",
			__func__);
		return -EOPNOTSUPP;
	}

	if (q_num < 0) {
		struct nse_q_vector *q_vector = vsi->q_vectors[0];
		int v_idx;

		if (q_vector) {
			nse_print_if_odd_usecs(netdev, q_vector->itr_setting,
					       ec->use_adaptive_rx_coalesce,
					       ec->rx_coalesce_usecs, "rx");
		}

		nse_for_each_q_vector(vsi, v_idx) {
			/* In some cases if DCB is configured the num_[rx|tx]q
			 * can be less than vsi->num_q_vectors. This check
			 * accounts for that so we don't report a false failure
			 */
			if (v_idx >= vsi->num_rxq && v_idx >= vsi->num_txq)
				goto set_complete;

			if (nse_set_q_coalesce(vsi, ec, v_idx))
				return -EINVAL;

			nse_set_q_vector_intrl(vsi->q_vectors[v_idx]);
		}
		goto set_complete;
	}

	if (nse_set_q_coalesce(vsi, ec, q_num))
		return -EINVAL;

	nse_set_q_vector_intrl(vsi->q_vectors[q_num]);

set_complete:
	return 0;
}

static int
nse_set_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
		 struct kernel_ethtool_coalesce __maybe_unused *kec,
		 struct netlink_ext_ack __maybe_unused *extack)
{
	return __nse_set_coalesce(netdev, ec, -1);
}

static int
nse_set_per_q_coalesce(struct net_device *netdev, u32 q_num,
		       struct ethtool_coalesce *ec)
{
	return __nse_set_coalesce(netdev, ec, q_num);
}

static const struct ethtool_ops nse_ethtool_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_RX_USECS |
				     ETHTOOL_COALESCE_USE_ADAPTIVE_RX |
				     ETHTOOL_COALESCE_RX_USECS_HIGH,
	.get_link_ksettings	= nse_get_link_ksettings,
	.set_link_ksettings	= nse_set_link_ksettings,
	.get_drvinfo		= nse_get_drvinfo,
	.get_wol		= nse_get_wol,
	.set_wol		= nse_set_wol,
	.get_msglevel		= nse_get_msglevel,
	.set_msglevel		= nse_set_msglevel,

	.self_test		= nse_self_test,

	.get_link		= ethtool_op_get_link,
	.get_coalesce		= nse_get_coalesce,
	.set_coalesce		= nse_set_coalesce,
	.get_strings		= nse_get_strings,
	.get_ethtool_stats      = nse_get_ethtool_stats,
	.get_priv_flags		= nse_get_priv_flags,
	.set_priv_flags		= nse_set_priv_flags,
	.get_sset_count		= nse_get_sset_count,
	.get_rxnfc		= nse_get_rxnfc,
	.set_rxnfc		= nse_set_rxnfc,
	.get_ringparam		= nse_get_ringparam,
	.set_ringparam		= nse_set_ringparam,
	.nway_reset		= nse_nway_reset,
	.get_pauseparam		= nse_get_pauseparam,
	.set_pauseparam		= nse_set_pauseparam,
	.get_rxfh_key_size	= nse_get_rxfh_key_size,
	.get_rxfh_indir_size	= nse_get_rxfh_indir_size,
	.get_rxfh		= nse_get_rxfh,
	.set_rxfh		= nse_set_rxfh,
	.get_channels		= nse_get_channels,
	.set_channels		= nse_set_channels,
	.get_ts_info		= nse_get_ts_info,
	.get_per_queue_coalesce	= nse_get_per_q_coalesce,
	.set_per_queue_coalesce	= nse_set_per_q_coalesce,
	.get_fecparam		= nse_get_fecparam,
	.set_fecparam		= nse_set_fecparam,
};

/**
 * nse_repr_set_coalesce - set coalesce settings for all queues
 * @netdev: pointer to the netdev associated with this query
 * @ec: ethtool structure to read the requested coalesce settings
 * @kec: kernel coalesce parameter
 * @extack: kernel extack parameter
 *
 * Return 0 on success, negative otherwise.
 */
static int
nse_repr_set_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
		      struct kernel_ethtool_coalesce __maybe_unused *kec,
		      struct netlink_ext_ack __maybe_unused *extack)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_ring *rx_ring;
	int v_idx;

	if (ec->rx_coalesce_usecs_high > NSE_INTRL_INTERVAL_MAX_USEC ||
	    (ec->rx_coalesce_usecs_high &&
	     ec->rx_coalesce_usecs_high < pf->hw.intrl_gran)) {
		netdev_info(vsi->netdev, "Invalid value,  rx-usecs-high valid values are 0 (disabled), %d-%d\n",
			    pf->hw.intrl_gran, NSE_INTRL_INTERVAL_MAX_USEC);
		return -EINVAL;
	}

	nse_for_each_q_vector(vsi, v_idx) {
		rx_ring = vsi->rx_rings[v_idx];
		nse_write_intrl(rx_ring->q_vector, ec->rx_coalesce_usecs_high);
		rx_ring->q_vector->intrl = ec->rx_coalesce_usecs_high;
	}

	return 0;
}

/**
 * nse_repr_get_coalesce - get coalesce settings
 * @netdev: pointer to the netdev associated with this query
 * @ec: ethtool structure to read the requested coalesce settings
 * @kec: kernel coalesce parameter
 * @extack: kernel extack parameter
 *
 * Since all queues have the same Rx coalesce high settings,
 * read the value from te first queue.
 *
 * Return 0 on success, negative otherwise.
 */
static int
nse_repr_get_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
		      struct kernel_ethtool_coalesce __maybe_unused *kec,
		      struct netlink_ext_ack __maybe_unused *extack)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;

	if (!vsi->rx_rings || !vsi->rx_rings[0]->q_vector->rx.ring)
		return -EINVAL;

	ec->rx_coalesce_usecs_high = vsi->rx_rings[0]->q_vector->intrl;

	return 0;
}

static void
nse_repr_get_drvinfo(struct net_device *netdev,
		     struct ethtool_drvinfo *drvinfo)
{
	struct nse_repr *repr = nse_netdev_to_repr(netdev);

	if (nse_check_vf_ready_for_cfg(repr->vf))
		return;

	__nse_get_drvinfo(netdev, drvinfo, repr->src_vsi);
}

static void
nse_repr_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	struct nse_repr *repr = nse_netdev_to_repr(netdev);

	/* for port representors only ETH_SS_STATS is supported */
	if (nse_check_vf_ready_for_cfg(repr->vf) ||
	    stringset != ETH_SS_STATS)
		return;

	__nse_get_strings(netdev, stringset, data, repr->src_vsi);
}

static void
nse_repr_get_ethtool_stats(struct net_device *netdev,
			   struct ethtool_stats __always_unused *stats,
			   u64 *data)
{
	struct nse_repr *repr = nse_netdev_to_repr(netdev);

	if (nse_check_vf_ready_for_cfg(repr->vf))
		return;

	__nse_get_ethtool_stats(netdev, stats, data, repr->src_vsi);
}

static int nse_repr_get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return NSE_VSI_STATS_LEN;
	default:
		return -EOPNOTSUPP;
	}
}

static const struct ethtool_ops nse_ethtool_repr_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_RX_USECS_HIGH,
	.get_coalesce		= nse_repr_get_coalesce,
	.set_coalesce		= nse_repr_set_coalesce,
	.get_drvinfo		= nse_repr_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_strings		= nse_repr_get_strings,
	.get_ethtool_stats      = nse_repr_get_ethtool_stats,
	.get_sset_count		= nse_repr_get_sset_count,
};

/**
 * nse_set_ethtool_repr_ops - setup VF's port representor ethtool ops
 * @netdev: network interface device structure
 */
void nse_set_ethtool_repr_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &nse_ethtool_repr_ops;
}

/**
 * nse_set_ethtool_ops - setup netdev ethtool ops
 * @netdev: network interface device structure
 *
 * setup netdev ethtool ops with ice specific ops
 */
void nse_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &nse_ethtool_ops;
}

