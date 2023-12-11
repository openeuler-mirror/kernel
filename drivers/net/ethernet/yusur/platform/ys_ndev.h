/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_NETDEV_H_
#define __YS_NETDEV_H_

#include <linux/netdevice.h>
#include <linux/types.h>

#include "ys_pdev.h"
#include "../net/ys_ethtool_ops.h"

#define YS_IF_FEATURE_PTP_TS 0x1

enum {
	LAN_STATS_TX64_BYTES_CNT,
	LAN_STATS_TX65_128_BYTES_CNT,
	LAN_STATS_TX129_256_BYTES_CNT,
	LAN_STATS_TX257_512_BYTES_CNT,
	LAN_STATS_TX513_1024_BYTES_CNT,
	LAN_STATS_TX1025_1514_BYTES_CNT,
	LAN_STATS_TX1515_2048_BYTES_CNT,
	LAN_STATS_TX2049_4096_BYTES_CNT,
	LAN_STATS_TX4097_8192_BYTES_CNT,
	LAN_STATS_TX8193_9600_BYTES_CNT,
	LAN_STATS_TX9600_PLUS_BYTES_CNT,
	LAN_STATS_TX_SHORT_60_BYTES_CNT,
	LAN_STATS_TX_OVER_9600_BYTES_CNT,
	LAN_STATS_TX_OTHER_BYTES_CNT,
	LAN_STATS_TX_IPV4_CNT,
	LAN_STATS_TX_IPV6_CNT,
	LAN_STATS_TX_IPV4_VLAN_CNT,
	LAN_STATS_TX_IPV6_VLAN_CNT,
	LAN_STATS_TX_UNICAST_CNT,
	LAN_STATS_TX_BROADCAST_CNT,
	LAN_STATS_TX_MULTICAST_IPV4_CNT,
	LAN_STATS_TX_MULTICAST_IPV6_CNT,
	LAN_STATS_TX_LOSS_PKT_CNT,
	LAN_STATS_TX_CHECKSUM_ERROR_CNT,
	LAN_STATS_TX_FCS_ERROR_CNT,
	LAN_STATS_RX64_BYTES_CNT,
	LAN_STATS_RX65_128_BYTES_CNT,
	LAN_STATS_RX129_256_BYTES_CNT,
	LAN_STATS_RX257_512_BYTES_CNT,
	LAN_STATS_RX513_1024_BYTES_CNT,
	LAN_STATS_RX1025_1514_BYTES_CNT,
	LAN_STATS_RX1515_2048_BYTES_CNT,
	LAN_STATS_RX2049_4096_BYTES_CNT,
	LAN_STATS_RX4097_8192_BYTES_CNT,
	LAN_STATS_RX8193_9600_BYTES_CNT,
	LAN_STATS_RX9600_PLUS_BYTES_CNT,
	LAN_STATS_RX_SHORT_60_BYTES_CNT,
	LAN_STATS_RX_OVER_9600_BYTES_CNT,
	LAN_STATS_RX_OTHER_BYTES_CNT,
	LAN_STATS_RX_IPV4_CNT,
	LAN_STATS_RX_IPV6_CNT,
	LAN_STATS_RX_IPV4_VLAN_CNT,
	LAN_STATS_RX_IPV6_VLAN_CNT,
	LAN_STATS_RX_UNICAST_CNT,
	LAN_STATS_RX_BROADCAST_CNT,
	LAN_STATS_RX_MULTICAST_IPV4_CNT,
	LAN_STATS_RX_MULTICAST_IPV6_CNT,
	LAN_STATS_RX_LOSS_PKT_CNT,
	LAN_STATS_RX_CHECKSUM_ERROR_CNT,
	LAN_STATS_RX_FCS_ERROR_CNT,
	LAN_STATS_INFO_LEN,
};

struct ys_stats {
	u64 tx_pkt_64_bytes;
	u64 tx_pkt_65_128_bytes;
	u64 tx_pkt_129_256_bytes;
	u64 tx_pkt_257_512_bytes;
	u64 tx_pkt_513_1024_bytes;
	u64 tx_pkt_1025_1514_bytes;
	u64 tx_pkt_1515_2048_bytes;
	u64 tx_pkt_2049_4096_bytes;
	u64 tx_pkt_4097_8192_bytes;
	u64 tx_pkt_8193_9600_bytes;
	u64 tx_pkt_9600_plus_bytes;
	u64 tx_pkt_short_than_60_bytes;
	u64 tx_pkt_over_than_9600_bytes;
	u64 tx_pkt_other_bytes;
	u64 tx_ipv4;
	u64 tx_ipv6;
	u64 tx_ipv4_vlan;
	u64 tx_ipv6_vlan;
	u64 tx_unicast;
	u64 tx_broadcast;
	u64 tx_multicast_ipv4;
	u64 tx_multicast_ipv6;
	u64 tx_loss_packet;
	u64 tx_checksum_error;
	u64 tx_fcs_error;
	u64 rx_pkt_64_bytes;
	u64 rx_pkt_65_128_bytes;
	u64 rx_pkt_129_256_bytes;
	u64 rx_pkt_257_512_bytes;
	u64 rx_pkt_513_1024_bytes;
	u64 rx_pkt_1025_1514_bytes;
	u64 rx_pkt_1515_2048_bytes;
	u64 rx_pkt_2049_4096_bytes;
	u64 rx_pkt_4097_8192_bytes;
	u64 rx_pkt_8193_9600_bytes;
	u64 rx_pkt_9600_plus_bytes;
	u64 rx_pkt_short_than_60_bytes;
	u64 rx_pkt_over_than_9600_bytes;
	u64 rx_pkt_other_bytes;
	u64 rx_ipv4;
	u64 rx_ipv6;
	u64 rx_ipv4_vlan;
	u64 rx_ipv6_vlan;
	u64 rx_unicast;
	u64 rx_broadcast;
	u64 rx_multicast_ipv4;
	u64 rx_multicast_ipv6;
	u64 rx_loss_packet;
	u64 rx_checksum_error;
	u64 rx_fcs_error;
};

struct ys_ethtool_string {
	u32 stats_len;
	struct ys_stats *ys_eth_stats;
	u64 lan_stats[LAN_STATS_INFO_LEN];
	u32 priv_flag_len;
	u32 self_test_len;
};

struct ys_ndev_priv {
	struct pci_dev *pdev;
	struct net_device *ndev;
	/* stats lock */
	spinlock_t stats_lock;
	/* state lock */
	struct mutex state_lock;
	struct rtnl_link_stats64 netdev_stats;

	void *adp_priv;

	/* base queue offset of parent device.
	 *
	 * According to normal logic, only the qbase of sf and representor
	 * is not equal to zero because of sharing hardware isolation domain.
	 *
	 * But k2 is a freak, all function, both pf and vf use absolute offset.
	 */
	u32 qbase;

	struct timer_list link_timer;
	struct delayed_work update_stats_work;

	int rs_fec;
	struct ys_ethtool_hw_ops *ys_eth_hw;
	struct ys_ethtool_string eth_string;
	struct ethtool_coalesce *ec;

	struct ys_ndev_hw_ops *ys_ndev_hw;
};

/* for adev func */
struct net_device *ys_ndev_create(struct ys_pdev_priv *pdev_priv,
				  int port_id, int queue);
void ys_ndev_destroy(struct net_device *ndev);

/* for pdev func */
int ys_ndev_init(struct ys_pdev_priv *pdev_priv);
void ys_ndev_uninit(struct ys_pdev_priv *pdev_priv);

#endif /* __YS_NDEV_H_ */
