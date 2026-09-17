// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */

#include "mcevf.h"
#include "mcevf_lib.h"
#include "mcevf_netdev.h"
#include "mcevf_ethtool.h"
#include "mcevf_ethtool_fdir.h"
#include "mcevf_version.h"
#include "mcevf_virtchnl.h"

static const struct mcevf_stats mcevf_gstrings_net_stats[] = {
	MCEVF_NETDEV_STAT("tx_packets", net_stats.tx_packets),
	MCEVF_NETDEV_STAT("tx_bytes", net_stats.tx_bytes),
	MCEVF_NETDEV_STAT("rx_packets", net_stats.rx_packets),
	MCEVF_NETDEV_STAT("rx_bytes", net_stats.rx_bytes),
};

#define MCEVF_NET_STATS_LEN ARRAY_SIZE(mcevf_gstrings_net_stats)

static const struct mcevf_stats mcevf_gstrings_ofld_stats[] = {
#if __MCEVF_GET_RING_STATS_BY_HW
	MCEVF_OFLD_STAT("tx_unicast", ofld_stats.tx_unicast),
	MCEVF_OFLD_STAT("tx_multicast", ofld_stats.tx_multicast),
	MCEVF_OFLD_STAT("tx_broadcast", ofld_stats.tx_broadcast),
	MCEVF_OFLD_STAT("rx_unicast", ofld_stats.rx_unicast),
	MCEVF_OFLD_STAT("rx_multicast", ofld_stats.rx_multicast),
	MCEVF_OFLD_STAT("rx_broadcast", ofld_stats.rx_broadcast),
#endif
	MCEVF_OFLD_STAT("rx_miss_drop", ofld_stats.rx_miss_drop),
	MCEVF_OFLD_STAT("tx_inserted_vlan", ofld_stats.tx_inserted_vlan),
	MCEVF_OFLD_STAT("rx_stripped_vlan", ofld_stats.rx_stripped_vlan),
	MCEVF_OFLD_STAT("rx_csum_err", ofld_stats.rx_csum_err),
	MCEVF_OFLD_STAT("rx_csum_unnecessary", ofld_stats.rx_csum_unnecessary),
	MCEVF_OFLD_STAT("rx_csum_none", ofld_stats.rx_csum_none),
};

#define MCEVF_OFLD_STATS_LEN ARRAY_SIZE(mcevf_gstrings_ofld_stats)

static const struct mcevf_stats mcevf_gstrings_txq_stats[] = {
	MCEVF_QUEUE_STAT("packets", tx_stats.pkts),
	MCEVF_QUEUE_STAT("bytes", tx_stats.bytes),
	MCEVF_QUEUE_STAT("tx_busy", tx_stats.tx_busy),
	MCEVF_QUEUE_STAT("inserted_vlan", tx_stats.inserted_vlan),
	MCEVF_QUEUE_STAT("period_intr_drop", tx_stats.period_intr_drop),
};

#define MCEVF_TXQ_STATS_LEN ARRAY_SIZE(mcevf_gstrings_txq_stats)

static const struct mcevf_stats mcevf_gstrings_rxq_stats[] = {
	MCEVF_QUEUE_STAT("packets", rx_stats.pkts),
	MCEVF_QUEUE_STAT("bytes", rx_stats.bytes),
	MCEVF_QUEUE_STAT("miss_drop", rx_stats.miss_drop),
	MCEVF_QUEUE_STAT("stripped_vlan", rx_stats.stripped_vlan),
	MCEVF_QUEUE_STAT("csum_err", rx_stats.csum_err),
	MCEVF_QUEUE_STAT("csum_unnecessary", rx_stats.csum_unnecessary),
	MCEVF_QUEUE_STAT("csum_none", rx_stats.csum_none),
};

#define MCEVF_RXQ_STATS_LEN ARRAY_SIZE(mcevf_gstrings_rxq_stats)

static int mcevf_q_stats_len(struct net_device *netdev)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	int total_slen = 0;

	total_slen += np->vsi->num_txq * (MCEVF_TXQ_STATS_LEN);
	total_slen += np->vsi->num_rxq * (MCEVF_RXQ_STATS_LEN);

	return total_slen;
}

#define MCEVF_ALL_STATS_LEN(n)                          \
	(MCEVF_NET_STATS_LEN + MCEVF_OFLD_STATS_LEN + \
	 mcevf_q_stats_len(n))

struct mcevf_priv_flag {
	char name[ETH_GSTRING_LEN];
	u32 bitno; /* bit position in pf->flags */
};

#define MCEVF_PRIV_FLAG(_name, _bitno)          \
	{                                       \
		.name = _name, .bitno = _bitno, \
	}

static const struct mcevf_priv_flag mcevf_gstrings_priv_flags[] = {
	//MCEVF_PRIV_FLAG("hw_dim", MCEVF_FLAG_HW_DIM_ENA),
	//MCEVF_PRIV_FLAG("sw_dim", MCEVF_FLAG_SW_DIM_ENA),
	MCEVF_PRIV_FLAG("tunnel_inner", MCEVF_FLAG_TUNNEL_INNER_ENA),
	//MCEVF_PRIV_FLAG("DSCP", MCEVF_FLAG_DSCP_ENA),
	//MCEVF_PRIV_FLAG("PFC", MCEVF_FLAG_PFC_ENA),
};

/* DSCP PFC vf cannot change */
#define MCEVF_PRIV_FLAG_ARRAY_SIZE ARRAY_SIZE(mcevf_gstrings_priv_flags)

static void mcevf_get_drvinfo(struct net_device *netdev,
			      struct ethtool_drvinfo *drvinfo)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_hw *hw = &vsi->back->hw;

	strscpy(drvinfo->driver, DRIVER_NAME, sizeof(drvinfo->driver));
	strscpy(drvinfo->version, DRV_VERSION, sizeof(drvinfo->version));
	snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version),
		 "%u.%u.%u.%03u", ((unsigned char *)&hw->fw_version)[3],
		 ((unsigned char *)&hw->fw_version)[2],
		 ((unsigned char *)&hw->fw_version)[1],
		 ((unsigned char *)&hw->fw_version)[0]);
	strscpy(drvinfo->bus_info, pci_name(vsi->back->pdev),
		sizeof(drvinfo->bus_info));

	drvinfo->n_stats = MCEVF_ALL_STATS_LEN(netdev);
}

/**
 * mcevf_get_link_ksettings - Get Link Speed and Duplex settings
 * @netdev: network interface device structure
 * @cmd: ethtool command
 *
 * Reports speed/duplex settings. Because this is a VF, we don't know what
 * kind of link we really have, so we fake it.
 **/
static int mcevf_get_link_ksettings(struct net_device *netdev,
				    struct ethtool_link_ksettings *cmd)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_port_info *pi = vsi->port_info;

	ethtool_link_ksettings_zero_link_mode(cmd, supported);
	ethtool_link_ksettings_zero_link_mode(cmd, advertising);

	cmd->base.autoneg = AUTONEG_DISABLE;
	cmd->base.port = PORT_NONE;
	cmd->base.duplex = DUPLEX_FULL;

#ifndef SPEED_25000
#define MCEVF_SPEED_25000 25000
	if (pi->link_speed == MCEVF_SPEED_25000) {
		netdev_info(netdev,
			    "Speed is 25G, display unsupported by this version of ethtool.\n");
		return 0;
	}
#endif

	cmd->base.speed = pi->link_speed;
	return 0;
}

#ifndef ETHTOOL_GLINKSETTINGS
/**
 * mcevf_get_settings - Get Link Speed and Duplex settings
 * @netdev: network interface device structure
 * @ecmd: ethtool command
 *
 * Reports speed/duplex settings based on media type.  Since we've backported
 * the new API constructs to use in the old API, this ends up just being
 * a wrapper to mcevf_get_link_ksettings.
 **/
static int mcevf_get_settings(struct net_device *netdev,
			      struct ethtool_cmd *ecmd)
{
	struct ethtool_link_ksettings ks;

	mcevf_get_link_ksettings(netdev, &ks);
	_kc_ethtool_ksettings_to_cmd(&ks, ecmd);
	ecmd->transceiver = XCVR_EXTERNAL;
	return 0;
}
#endif /* !ETHTOOL_GLINKSETTINGS */

static int mcevf_get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return MCEVF_ALL_STATS_LEN(netdev);
	case ETH_SS_PRIV_FLAGS:
		return MCEVF_PRIV_FLAG_ARRAY_SIZE;
	default:
		return -EOPNOTSUPP;
	}
}

static void mcevf_get_strings(struct net_device *netdev, u32 stringset,
			      u8 *data)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	u32 i = 0;
	u32 j = 0;
	u8 *p = data;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < MCEVF_NET_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 mcevf_gstrings_net_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}

		for (i = 0; i < MCEVF_OFLD_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 mcevf_gstrings_ofld_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}

		mcevf_for_each_txq(vsi, i) {
			for (j = 0; j < MCEVF_TXQ_STATS_LEN; j++) {
				snprintf(p, ETH_GSTRING_LEN, "tx_%u_%s", i,
					 mcevf_gstrings_txq_stats[j]
						 .stat_string);
				p += ETH_GSTRING_LEN;
			}
		}

		mcevf_for_each_rxq(vsi, i) {
			for (j = 0; j < MCEVF_RXQ_STATS_LEN; j++) {
				snprintf(p, ETH_GSTRING_LEN, "rx_%u_%s", i,
					 mcevf_gstrings_rxq_stats[j]
						 .stat_string);
				p += ETH_GSTRING_LEN;
			}
		}
		break;
	case ETH_SS_PRIV_FLAGS:
		for (i = 0; i < MCEVF_PRIV_FLAG_ARRAY_SIZE; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 mcevf_gstrings_priv_flags[i].name);
			p += ETH_GSTRING_LEN;
		}
		break;
	default:
		break;
	}
}

static void
mcevf_get_ethtool_stats(struct net_device *netdev,
			struct ethtool_stats __always_unused *stats,
			  u64 *data)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_ring *tx_ring;
	struct mcevf_ring *rx_ring;
	u32 j = 0;
	u32 k = 0;
	int i = 0;
	char *p;

	mcevf_update_vsi_ring_stats(vsi);

	for (j = 0; j < MCEVF_NET_STATS_LEN; j++) {
		p = (char *)vsi +
		    mcevf_gstrings_net_stats[j].stat_offset;
		data[i++] = (mcevf_gstrings_net_stats[j].sizeof_stat ==
			     sizeof(u64)) ?
				    *(u64 *)p :
				    *(u32 *)p;
	}

	for (j = 0; j < MCEVF_OFLD_STATS_LEN; j++) {
		p = (char *)vsi +
		    mcevf_gstrings_ofld_stats[j].stat_offset;
		data[i++] = (mcevf_gstrings_ofld_stats[j].sizeof_stat ==
			     sizeof(u64)) ?
				    *(u64 *)p :
				    *(u32 *)p;
	}

	/* populate per queue stats */
	rcu_read_lock();

	mcevf_for_each_txq(vsi, j) {
		tx_ring = READ_ONCE(vsi->tx_rings[j]);
		if (tx_ring && tx_ring->ring_stats) {
			for (k = 0; k < MCEVF_TXQ_STATS_LEN; k++) {
				p = (char *)(tx_ring->ring_stats) +
				    mcevf_gstrings_txq_stats[k]
					    .stat_offset;
				data[i++] = (mcevf_gstrings_txq_stats[k]
						     .sizeof_stat ==
					     sizeof(u64)) ?
						    *(u64 *)p :
						    *(u32 *)p;
			}
		} else {
			for (k = 0; k < MCEVF_TXQ_STATS_LEN; k++)
				data[i++] = 0;
		}
	}

	mcevf_for_each_rxq(vsi, j) {
		rx_ring = READ_ONCE(vsi->rx_rings[j]);
		if (rx_ring && rx_ring->ring_stats) {
			for (k = 0; k < MCEVF_RXQ_STATS_LEN; k++) {
				p = (char *)(rx_ring->ring_stats) +
				    mcevf_gstrings_rxq_stats[k]
					    .stat_offset;
				data[i++] = (mcevf_gstrings_rxq_stats[k]
						     .sizeof_stat ==
					     sizeof(u64)) ?
						    *(u64 *)p :
						    *(u32 *)p;
			}
		} else {
			for (k = 0; k < MCEVF_RXQ_STATS_LEN; k++)
				data[i++] = 0;
		}
	}

	rcu_read_unlock();
}

/**
 * mcevf_get_priv_flags - report device private flags
 * @netdev: network interface device structure
 *
 * The get string set count and the string set should be matched for each
 * flag returned. Add new strings for each flag to the mcevf_gstrings_priv_flags
 * array.
 *
 * Returns a u32 bitmap of flags.
 */
static u32 mcevf_get_priv_flags(struct net_device *netdev)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_pf *pf = vsi->back;
	u32 i, ret_flags = 0;

	for (i = 0; i < MCEVF_PRIV_FLAG_ARRAY_SIZE; i++) {
		const struct mcevf_priv_flag *priv_flag;

		priv_flag = &mcevf_gstrings_priv_flags[i];

		if (test_bit(priv_flag->bitno, pf->flags))
			ret_flags |= BIT(i);
	}

	return ret_flags;
}

/**
 * mcevf_set_priv_flags - set private flags
 * @netdev: network interface device structure
 * @flags: bit flags to be set
 */
static int mcevf_set_priv_flags(struct net_device *netdev, u32 flags)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_pf *pf = vsi->back;
	struct mcevf_hw *hw = &pf->hw;
	DECLARE_BITMAP(orig_flags, MCEVF_PF_FLAGS_NBITS);
	DECLARE_BITMAP(change_flags, MCEVF_PF_FLAGS_NBITS);
	u32 i;
	bool on;

	if (flags & ~GENMASK(MCEVF_PRIV_FLAG_ARRAY_SIZE - 1, 0))
		return -EINVAL;

	bitmap_copy(orig_flags, pf->flags, MCEVF_PF_FLAGS_NBITS);
	for (i = 0; i < MCEVF_PRIV_FLAG_ARRAY_SIZE; i++) {
		const struct mcevf_priv_flag *priv_flag;

		priv_flag = &mcevf_gstrings_priv_flags[i];

		if (flags & BIT(i))
			set_bit(priv_flag->bitno, pf->flags);
		else
			clear_bit(priv_flag->bitno, pf->flags);
	}
	bitmap_xor(change_flags, pf->flags, orig_flags,
		   MCEVF_PF_FLAGS_NBITS);

	if (test_bit(MCEVF_FLAG_HW_DIM_ENA, change_flags)) {
		on = !!test_bit(MCEVF_FLAG_HW_DIM_ENA, pf->flags);
		if (on)
			clear_bit(MCEVF_FLAG_SW_DIM_ENA, pf->flags);

		mcevf_for_each_txq(vsi, i) {
			struct mcevf_ring *txring = vsi->tx_rings[i];

			hw->ops->set_txring_hw_dim(txring, on);
			if (on) {
				txring->q_vector->tx.dim_params.mode =
					ITR_HW_DYNAMIC;
			} else {
				if (test_bit(MCEVF_FLAG_SW_DIM_ENA, pf->flags))
					txring->q_vector->tx.dim_params.mode =
						ITR_SW_DYNAMIC;
				else
					txring->q_vector->tx.dim_params.mode =
						ITR_STATIC;
			}
		}
		mcevf_for_each_rxq(vsi, i) {
			struct mcevf_ring *rxring = vsi->rx_rings[i];

			hw->ops->set_rxring_hw_dim(rxring, on);
			if (on) {
				rxring->q_vector->rx.dim_params.mode =
					ITR_HW_DYNAMIC;
			} else {
				if (test_bit(MCEVF_FLAG_SW_DIM_ENA, pf->flags))
					rxring->q_vector->rx.dim_params.mode =
						ITR_SW_DYNAMIC;
				else
					rxring->q_vector->rx.dim_params.mode =
						ITR_STATIC;
			}
		}
	}

	if (test_bit(MCEVF_FLAG_SW_DIM_ENA, change_flags)) {
		on = !!test_bit(MCEVF_FLAG_SW_DIM_ENA, pf->flags);
		if (on)
			clear_bit(MCEVF_FLAG_HW_DIM_ENA, pf->flags);

		mcevf_for_each_txq(vsi, i) {
			struct mcevf_ring *txring = vsi->tx_rings[i];

			hw->ops->set_txring_hw_dim(txring, on);
			if (on) {
				txring->q_vector->tx.dim_params.mode =
					ITR_SW_DYNAMIC;
			} else {
				if (test_bit(MCEVF_FLAG_HW_DIM_ENA, pf->flags))
					txring->q_vector->tx.dim_params.mode =
						ITR_HW_DYNAMIC;
				else
					txring->q_vector->tx.dim_params.mode =
						ITR_STATIC;
			}
		}

		mcevf_for_each_rxq(vsi, i) {
			struct mcevf_ring *rxring = vsi->rx_rings[i];

			hw->ops->set_rxring_hw_dim(rxring, on);
			if (on) {
				rxring->q_vector->rx.dim_params.mode =
					ITR_SW_DYNAMIC;
			} else {
				if (test_bit(MCEVF_FLAG_HW_DIM_ENA, pf->flags))
					rxring->q_vector->rx.dim_params.mode =
						ITR_HW_DYNAMIC;
				else
					rxring->q_vector->rx.dim_params.mode =
						ITR_STATIC;
			}
		}
	}

	if (test_bit(MCEVF_FLAG_TUNNEL_INNER_ENA, change_flags)) {
		on = !!test_bit(MCEVF_FLAG_TUNNEL_INNER_ENA, pf->flags);
		hw->ops->set_tun_select_inner(hw, on);
		pf->tun_inner = on;
	}

	return 0;
}

/**
 * mcevf_get_rss_hash_opt - Retrieve hash fields for a given flow-type
 * @hw: the VSI being configured
 * @nfc: ethtool rxnfc command
 */
static void mcevf_get_rss_hash_opt(struct mcevf_hw *hw,
				   struct ethtool_rxnfc *nfc)
{
	u32 hdrs = hw->rss_hash_type;
	bool on = false;

	nfc->data = 0;

	switch (nfc->flow_type) {
	case TCP_V4_FLOW:
		if (hdrs & MCEVF_F_HASH_IPV4_TCP)
			on = true;
		break;
	case UDP_V4_FLOW:
		if (hdrs & MCEVF_F_HASH_IPV4_UDP)
			on = true;
		break;
	case SCTP_V4_FLOW:
		if (hdrs & MCEVF_F_HASH_IPV4_SCTP)
			on = true;
		break;
	case TCP_V6_FLOW:
		if (hdrs & MCEVF_F_HASH_IPV6_TCP)
			on = true;
		break;
	case UDP_V6_FLOW:
		if (hdrs & MCEVF_F_HASH_IPV6_UDP)
			on = true;
		break;
	case SCTP_V6_FLOW:
		if (hdrs & MCEVF_F_HASH_IPV6_SCTP)
			on = true;
		break;
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case AH_ESP_V4_FLOW:
		if (hdrs & MCEVF_F_HASH_IPV4)
			break;
		return;
	case AH_V6_FLOW:
	case AH_ESP_V6_FLOW:
	case ESP_V6_FLOW:
		if (hdrs & MCEVF_F_HASH_IPV6)
			break;
		return;
	default:
		return;
	}

	nfc->data |= (u64)RXH_IP_SRC;
	nfc->data |= (u64)RXH_IP_DST;

	if (on) {
		nfc->data |= (u64)RXH_L4_B_0_1;
		nfc->data |= (u64)RXH_L4_B_2_3;
	}
}

/**
 * mcevf_get_rxnfc - command to get Rx flow classification rules
 * @netdev: network interface device structure
 * @cmd: ethtool rxnfc command
 * @rule_locs: buffer to return Rx flow classification rules
 *
 * Returns Success if the command is supported.
 */
static int mcevf_get_rxnfc(struct net_device *netdev,
			   struct ethtool_rxnfc *cmd,
			     u32 __always_unused *rule_locs)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_hw *hw = &vsi->back->hw;
	int ret = -EOPNOTSUPP;

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = vsi->num_rxq;
		ret = 0;
		break;
	case ETHTOOL_GRXFH:
		mcevf_get_rss_hash_opt(hw, cmd);
		ret = 0;
		break;
	default:
		break;
	}

	return ret;
}

/**
 * mcevf_set_rss_hash_opt - Enable/Disable flow types for RSS hash
 * @vsi: the VSI being configured
 * @nfc: ethtool rxnfc command
 *
 * Returns Success if the flow input set is supported.
 */
static int mcevf_set_rss_hash_opt(struct mcevf_vsi *vsi,
				  struct ethtool_rxnfc *nfc)
{
	struct mcevf_hw *hw = &vsi->back->hw;
	u32 hash_type = 0;
	bool on;

	if (!(nfc->data & RXH_IP_SRC) || !(nfc->data & RXH_IP_DST)) {
		netdev_warn(vsi->netdev, "src_ip and dst_ip must both on!\n");
		return -EOPNOTSUPP;
	}

	if (!!(nfc->data & RXH_L4_B_0_1) != !!(nfc->data & RXH_L4_B_2_3)) {
		netdev_warn(vsi->netdev,
			    "src_port and dst_port must both on or off!\n");
		return -EOPNOTSUPP;
	}

	on = !!(nfc->data & RXH_L4_B_0_1);

	switch (nfc->flow_type) {
	case TCP_V4_FLOW:
		hash_type |= MCEVF_F_HASH_IPV4_TCP;
		break;
	case UDP_V4_FLOW:
		hash_type |= MCEVF_F_HASH_IPV4_UDP;
		break;
	case SCTP_V4_FLOW:
		hash_type |= MCEVF_F_HASH_IPV4_SCTP;
		break;
	case TCP_V6_FLOW:
		hash_type |= MCEVF_F_HASH_IPV6_TCP;
		break;
	case UDP_V6_FLOW:
		hash_type |= MCEVF_F_HASH_IPV6_UDP;
		break;
	case SCTP_V6_FLOW:
		hash_type |= MCEVF_F_HASH_IPV6_SCTP;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (on)
		hw->rss_hash_type |= hash_type;
	else
		hw->rss_hash_type &= ~hash_type;
	hw->ops->set_rss_hash_type(hw);
	return 0;
}

/**
 * mcevf_set_rxnfc - command to set Rx flow rules.
 * @netdev: network interface device structure
 * @cmd: ethtool rxnfc command
 *
 * Returns 0 for success and negative values for errors
 */
static int mcevf_set_rxnfc(struct net_device *netdev,
			   struct ethtool_rxnfc *cmd)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;

	switch (cmd->cmd) {
	case ETHTOOL_SRXFH:
		return mcevf_set_rss_hash_opt(vsi, cmd);
	default:
		break;
	}
	return -EOPNOTSUPP;
}

#if defined(ETHTOOL_GRSSH) && defined(ETHTOOL_SRSSH)
/**
 * mcevf_get_rxfh_key_size - get the RSS hash key size
 * @netdev: network interface device structure
 *
 * Returns the table size.
 */
static u32
mcevf_get_rxfh_key_size(struct net_device __always_unused *netdev)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_hw *hw = &vsi->back->hw;

	return hw->func_caps.common_cap.rss_key_size;
}

/**
 * mcevf_get_rxfh_indir_size - get the Rx flow hash indirection table size
 * @netdev: network interface device structure
 *
 * Returns the table size.
 */
static u32 mcevf_get_rxfh_indir_size(struct net_device *netdev)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_hw *hw = &vsi->back->hw;

	return hw->func_caps.common_cap.rss_table_size;
}

static int mcevf_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key,
			  u8 *hfunc)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_hw *hw = &vsi->back->hw;
	int i = 0;

	if (hfunc)
		*hfunc = hw->rss_hfunc;
	if (!indir)
		return 0;
	for (i = 0; i < hw->func_caps.common_cap.rss_table_size; i++) {
		indir[i] = (netdev->features & NETIF_F_RXHASH) ?
				   (u32)hw->rss_table[i] : 0;
	}

	if (key) {
		memcpy(key, hw->rss_key,
		       (hw->func_caps.common_cap.rss_key_size));
	}
	return 0;
}

/**
 * mcevf_set_rxfh - set the Rx flow hash indirection table
 * @netdev: network interface device structure
 * @rxfh: ethtool RSS params including indirection table and hash key
 * @extack: extended ack for error reporting
 *
 * Returns -EINVAL if the table specifies an invalid queue ID, otherwise
 * returns 0 after programming the table.
 */
static int mcevf_set_rxfh(struct net_device *netdev, const u32 *indir,
			  const u8 *key, const u8 hfunc)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_pf *pf = vsi->back;
	struct mcevf_hw *hw = &pf->hw;

	if (!test_bit(MCEVF_FLAG_RSS_ENA, pf->flags)) {
		/* RSS not supported return error here */
		netdev_warn(netdev,
			    "RSS is not configured on this VSI!\n");
		return -EIO;
	}

	if (indir) {
		int i;

		for (i = 0; i < hw->func_caps.common_cap.rss_table_size;
		     i++) {
			if (indir[i] >= vsi->num_rxq)
				return -EINVAL;
		}
	}

	if (hfunc != ETH_RSS_HASH_NO_CHANGE &&
	    (hfunc != ETH_RSS_HASH_TOP && hfunc != ETH_RSS_HASH_XOR)) {
		return -EOPNOTSUPP;
	}

	if (hfunc && hfunc != hw->rss_hfunc) {
		hw->rss_hfunc = hfunc;
		hw->ops->set_rss_hash(hw, netdev->features);
	}

	if (key) {
		memcpy(hw->rss_key, key,
		       (hw->func_caps.common_cap.rss_key_size));
		hw->ops->set_rss_key(hw);
	}

	if (indir) {
		int i;

		for (i = 0; i < hw->func_caps.common_cap.rss_table_size; i++)
			hw->rss_table[i] = (u16)indir[i];
		hw->ops->set_rss_table(hw, vsi->num_rxq);
	}

	return 0;
}
#endif /* ETHTOOL_GRSSH && ETHTOOL_SRSSH */

/**
 * mcevf_get_max_txq - return the maximum number of Tx queues for in a PF
 * @pf: PF structure
 */
static int mcevf_get_max_txq(struct mcevf_pf *pf)
{
	return min_t(int, (u16)num_online_cpus(),
		     (u16)pf->hw.func_caps.common_cap.num_txq);
}

/**
 * mcevf_get_max_rxq - return the maximum number of Rx queues for in a PF
 * @pf: PF structure
 */
static int mcevf_get_max_rxq(struct mcevf_pf *pf)
{
	return min_t(int, (u16)num_online_cpus(),
		     (u16)pf->hw.func_caps.common_cap.num_rxq);
}

/**
 * mcevf_get_combined_cnt - return the current number of combined channels
 * @vsi: PF VSI pointer
 *
 * Go through all queue vectors and count ones that have both Rx and Tx ring
 * attached
 */
static u32 mcevf_get_combined_cnt(struct mcevf_vsi *vsi)
{
	u32 combined = 0;
	int q_idx;

	mcevf_for_each_q_vector(vsi, q_idx) {
		struct mcevf_q_vector *q_vector = vsi->q_vectors[q_idx];

		if (q_vector->rx.ring && q_vector->tx.ring)
			combined++;
	}

	return combined;
}

static int mcevf_get_max_queue_msix_cnt(struct mcevf_pf *pf)
{
	return max_t(int, 0,
		     pf->num_msix_cnt - pf->num_mbox_irqs -
		     pf->num_rdma_irqs);
}

/**
 * mcevf_get_channels - get the current and max supported channels
 * @dev: network interface device structure
 * @ch: ethtool channel data structure
 */
static void mcevf_get_channels(struct net_device *dev,
			       struct ethtool_channels *ch)
{
	struct mcevf_netdev_priv *np = netdev_priv(dev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_pf *pf = vsi->back;

	/* report maximum channels */
	ch->max_rx = mcevf_get_max_rxq(pf);
	ch->max_tx = mcevf_get_max_txq(pf);
	ch->max_rx = ch->max_tx = mcevf_get_max_queue_msix_cnt(pf);
	ch->max_combined = min_t(int, ch->max_rx, ch->max_tx);

	ch->max_rx = 0;
	ch->max_tx = 0;

	/* report current channels */
	ch->combined_count = mcevf_get_combined_cnt(vsi);
	//ch->rx_count = vsi->num_rxq - ch->combined_count;
	//ch->tx_count = vsi->num_txq - ch->combined_count;

	ch->rx_count = 0;
	ch->tx_count = 0;

	/* report other queues */
	ch->other_count = pf->num_mbox_irqs;
	ch->max_other = ch->other_count;
}

/**
 * mcevf_set_channels - set the number channels
 * @dev: network interface device structure
 * @ch: ethtool channel data structure
 */
static int mcevf_set_channels(struct net_device *dev,
			      struct ethtool_channels *ch)
{
	struct mcevf_netdev_priv *np = netdev_priv(dev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_pf *pf = vsi->back;
	struct mcevf_hw *hw = &pf->hw;
	int new_rx = 0, new_tx = 0;
	u32 curr_combined;

	if (pf->hw.fdir_active_fltr) {
		netdev_err(dev,
			   "Cannot set channels when Flow Director filters are active\n");
		return -EOPNOTSUPP;
	}

	if (ch->other_count && ch->other_count != pf->num_mbox_irqs) {
		netdev_err(dev, "Changing other channels is not supported\n");
		return -EINVAL;
	}

	curr_combined = mcevf_get_combined_cnt(vsi);

	/* these checks are for cases where user didn't specify a particular
	 * value on cmd line but we get non-zero value anyway via
	 * get_channels(); look at ethtool.c in ethtool repository (the user
	 * space part), particularly, do_schannels() routine
	 */
	if (ch->rx_count == vsi->num_rxq - curr_combined)
		ch->rx_count = 0;
	if (ch->tx_count == vsi->num_txq - curr_combined)
		ch->tx_count = 0;
	if (ch->combined_count == curr_combined)
		ch->combined_count = 0;

	if (!(ch->combined_count || (ch->rx_count && ch->tx_count))) {
		if (!ch->combined_count && !ch->rx_count && !ch->tx_count)
			return 0;

		netdev_err(dev,
			   "Please specify at least 1 Rx and 1 Tx channel\n");
		return -EINVAL;
	}

	new_rx = ch->combined_count + ch->rx_count;
	new_tx = ch->combined_count + ch->tx_count;

	if (new_rx > mcevf_get_max_rxq(pf)) {
		netdev_err(dev, "Maximum allowed Rx channels is %d\n",
			   mcevf_get_max_rxq(pf));
		return -EINVAL;
	}
	if (new_tx > mcevf_get_max_txq(pf)) {
		netdev_err(dev, "Maximum allowed Tx channels is %d\n",
			   mcevf_get_max_txq(pf));
		return -EINVAL;
	}

	/* need notify ring cnt to pf for tx_max_rate */
	if (hw->virtchnl.ops->notify_ring_cnt(hw, new_tx)) {
		netdev_err(dev,
			   "Cannot changed channels because pf had setuped redir filters on this vf\n");
		return -EINVAL;
	}

	return mcevf_vsi_recfg_qs(vsi, new_rx, new_tx, false);
}

static void
mcevf_get_ringparam(struct net_device *netdev, struct ethtool_ringparam *ring,
		    struct kernel_ethtool_ringparam __always_unused *kernel_rp,
		    struct netlink_ext_ack __always_unused *extack)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;

	ring->rx_max_pending = MCEVF_MAX_NUM_DESC;
	ring->tx_max_pending = MCEVF_MAX_NUM_DESC;
	ring->rx_pending = vsi->rx_rings[0]->count;
	ring->tx_pending = vsi->tx_rings[0]->count;

	/* Rx mini and jumbo rings are not supported */
	ring->rx_mini_max_pending = 0;
	ring->rx_jumbo_max_pending = 0;
	ring->rx_mini_pending = 0;
	ring->rx_jumbo_pending = 0;
}

static int
mcevf_set_ringparam(struct net_device *netdev, struct ethtool_ringparam *ring,
		    struct kernel_ethtool_ringparam __always_unused *kernel_rp,
		    struct netlink_ext_ack __always_unused *extack)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_ring *tx_rings = NULL;
	struct mcevf_ring *rx_rings = NULL;
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_pf *pf = vsi->back;
	int i, timeout = 50, err = 0;
	u16 new_rx_cnt, new_tx_cnt;

	if (ring->tx_pending > MCEVF_MAX_NUM_DESC ||
	    ring->tx_pending < MCEVF_MIN_NUM_DESC ||
	    ring->rx_pending > MCEVF_MAX_NUM_DESC ||
	    ring->rx_pending < MCEVF_MIN_NUM_DESC) {
		netdev_err(netdev,
			   "Descriptors requested (Tx: %d / Rx: %d) out of range [%d-%d] (increment %d)\n",
			   ring->tx_pending, ring->rx_pending, MCEVF_MIN_NUM_DESC,
			   MCEVF_MAX_NUM_DESC, MCEVF_REQ_DESC_MULTIPLE);
		return -EINVAL;
	}

	new_tx_cnt = ALIGN(ring->tx_pending, MCEVF_REQ_DESC_MULTIPLE);
	if (new_tx_cnt != ring->tx_pending)
		netdev_info(netdev,
			    "Requested Tx descriptor count rounded up to %d\n",
			    new_tx_cnt);
	new_rx_cnt = ALIGN(ring->rx_pending, MCEVF_REQ_DESC_MULTIPLE);
	if (new_rx_cnt != ring->rx_pending)
		netdev_info(netdev,
			    "Requested Rx descriptor count rounded up to %d\n",
			    new_rx_cnt);

	/* if nothing to do return success */
	if (new_tx_cnt == vsi->tx_rings[0]->count &&
	    new_rx_cnt == vsi->rx_rings[0]->count) {
		netdev_dbg(netdev,
			   "Nothing to change, descriptor count is same as requested\n");
		return 0;
	}

	while (test_and_set_bit(MCEVF_CFG_BUSY, pf->state)) {
		timeout--;
		if (!timeout)
			return -EBUSY;
		usleep_range(1000, 2000);
	}

	/* set for the next time the netdev is started */
	if (!netif_running(vsi->netdev)) {
		mcevf_for_each_txq(vsi, i)
			vsi->tx_rings[i]->count = new_tx_cnt;
		mcevf_for_each_rxq(vsi, i)
			vsi->rx_rings[i]->count = new_rx_cnt;

		vsi->num_tx_desc = (u16)new_tx_cnt;
		vsi->num_rx_desc = (u16)new_rx_cnt;
		netdev_dbg(netdev,
			   "Link is down, descriptor count change happens when link is brought up\n");
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

	mcevf_for_each_txq(vsi, i) {
		/* clone ring and setup updated count */
		tx_rings[i] = *vsi->tx_rings[i];
		tx_rings[i].count = new_tx_cnt;
		tx_rings[i].desc = NULL;
		tx_rings[i].tx_buf = NULL;
		err = mcevf_setup_tx_ring(&tx_rings[i]);
		if (err) {
			while (i--)
				mcevf_clean_tx_ring(&tx_rings[i]);
			kfree(tx_rings);
			tx_rings = NULL;
			goto done;
		}
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

	mcevf_for_each_rxq(vsi, i) {
		/* clone ring and setup updated count */
		rx_rings[i] = *vsi->rx_rings[i];
		rx_rings[i].count = new_rx_cnt;
		rx_rings[i].desc = NULL;
		rx_rings[i].rx_buf = NULL;
		err = mcevf_setup_rx_ring(&rx_rings[i]);
		if (err) {
			while (i) {
				i--;
				mcevf_free_rx_ring(&rx_rings[i]);
			}
			kfree(rx_rings);
			rx_rings = NULL;
			err = -ENOMEM;
			goto free_tx;
		}
	}

process_link:
	/* Bring interface down, copy in the new ring info, then restore the
	 * interface. if VSI is up, bring it down and then back up
	 */
	if (!test_and_set_bit(MCEVF_VSI_DOWN, vsi->state)) {
		mcevf_down(vsi);

		if (tx_rings) {
			mcevf_for_each_txq(vsi, i) {
				mcevf_free_tx_ring(vsi->tx_rings[i]);
				*vsi->tx_rings[i] = tx_rings[i];
			}
			kfree(tx_rings);
			tx_rings = NULL;
		}

		if (rx_rings) {
			mcevf_for_each_rxq(vsi, i) {
				mcevf_free_rx_ring(vsi->rx_rings[i]);
				*vsi->rx_rings[i] = rx_rings[i];
			}
			kfree(rx_rings);
			rx_rings = NULL;
		}

		vsi->num_tx_desc = new_tx_cnt;
		vsi->num_rx_desc = new_rx_cnt;
		mcevf_up(vsi);
	}
	goto done;

free_tx:
	/* error cleanup if the Rx allocations failed after getting Tx */
	if (tx_rings) {
		mcevf_for_each_txq(vsi, i)
			mcevf_free_tx_ring(&tx_rings[i]);
	}

done:
	kfree(rx_rings);
	kfree(tx_rings);
	clear_bit(MCEVF_CFG_BUSY, pf->state);
	return err;
}

static u32 mcevf_get_msglevel(struct net_device *netdev)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_pf *pf = np->vsi->back;

	return pf->msg_enable;
}

static void mcevf_set_msglevel(struct net_device *netdev, u32 data)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_pf *pf = np->vsi->back;

	pf->msg_enable = data;
}

static int mcevf_get_q_coalesce(struct mcevf_vsi *vsi,
				struct ethtool_coalesce *ec, int q_num)
{
	struct mcevf_ring_container *rx;
	struct mcevf_ring_container *tx;

	if (q_num < 0 || q_num >= vsi->num_q_vectors ||
	    q_num >= vsi->num_rxq || q_num >= vsi->num_txq ||
	    !vsi->q_vectors[q_num])
		return -EINVAL;

	rx = &vsi->q_vectors[q_num]->rx;
	tx = &vsi->q_vectors[q_num]->tx;

	if (rx->dim_params.mode == ITR_STATIC)
		ec->use_adaptive_rx_coalesce = ITR_STATIC;
	else
		ec->use_adaptive_rx_coalesce = ITR_DYNAMIC;

	ec->rx_coalesce_usecs = rx->dim_params.usecs;
	ec->rx_max_coalesced_frames = rx->dim_params.frames;

	if (tx->dim_params.mode == ITR_STATIC)
		ec->use_adaptive_tx_coalesce = ITR_STATIC;
	else
		ec->use_adaptive_tx_coalesce = ITR_DYNAMIC;

	ec->tx_coalesce_usecs = tx->dim_params.usecs;
	ec->tx_max_coalesced_frames = tx->dim_params.frames;

	return 0;
}

static int __mcevf_get_coalesce(struct net_device *netdev,
				struct ethtool_coalesce *ec, int q_num)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;

	if (q_num < 0)
		q_num = 0;

	if (mcevf_get_q_coalesce(vsi, ec, q_num))
		return -EINVAL;
	return 0;
}

#ifndef ETHTOOL_COALESCE_USECS
/**
 * mcevf_is_coalesce_param_invalid - check for unsupported coalesce parameters
 * @ec: ethtool structure to fill with driver's coalesce settings
 */
static bool mcevf_is_coalesce_param_invalid(struct ethtool_coalesce *ec)
{
	if (ec->rx_coalesce_usecs_irq || ec->rx_max_coalesced_frames_irq ||
	    ec->tx_coalesce_usecs_irq || ec->tx_max_coalesced_frames_irq ||
	    ec->stats_block_coalesce_usecs || ec->pkt_rate_low ||
	    ec->rx_coalesce_usecs_low || ec->rx_max_coalesced_frames_low ||
	    ec->tx_coalesce_usecs_low || ec->tx_max_coalesced_frames_low ||
	    ec->pkt_rate_high || ec->rx_max_coalesced_frames_high ||
	    ec->tx_coalesce_usecs_high || ec->tx_max_coalesced_frames_high ||
	    ec->rate_sample_interval)
		return true;
	return false;
}
#endif /* !ETHTOOL_COALESCE_USECS */

static int mcevf_check_coalesce_param(struct net_device *netdev,
				      struct ethtool_coalesce *ec)
{
	if (ec->tx_coalesce_usecs > MCEVF_MAX_INTR_TIME ||
	    ec->tx_coalesce_usecs <= 0) {
		netdev_info(netdev,
			    "Invalid value, tx_coalesce_usecs valid values are 1 - %d\n",
			    MCEVF_MAX_INTR_TIME);
		return -EINVAL;
	}

	if (ec->tx_max_coalesced_frames > MCEVF_MAX_INTR_PKTS ||
	    ec->tx_max_coalesced_frames <= 0) {
		netdev_info(netdev,
			    "Invalid value, tx_coalesce_frames valid values are 1 - %d\n",
			    MCEVF_MAX_INTR_PKTS);
		return -EINVAL;
	}

	if (ec->rx_coalesce_usecs > MCEVF_MAX_INTR_TIME ||
	    ec->rx_coalesce_usecs <= 0) {
		netdev_info(netdev,
			    "Invalid value, rx_coalesce_usecs valid values are 1 - %d\n",
			    MCEVF_MAX_INTR_TIME);
		return -EINVAL;
	}

	if (ec->rx_max_coalesced_frames > MCEVF_MAX_INTR_PKTS ||
	    ec->rx_max_coalesced_frames <= 0) {
		netdev_info(netdev,
			    "Invalid value, rx_coalesce_frames valid values are 1 - %d\n",
			    MCEVF_MAX_INTR_PKTS);
		return -EINVAL;
	}
	return 0;
}

static void mcevf_set_q_coalesce(struct mcevf_vsi *vsi,
				 struct ethtool_coalesce *ec, int q_num)
{
	struct mcevf_q_vector *q_vector = vsi->q_vectors[q_num];
	struct mcevf_intr_coalesce *dim_params;
	struct mcevf_hw *hw = &vsi->back->hw;
	struct mcevf_ring *ring;

	dim_params = &q_vector->rx.dim_params;

	if (ec->use_adaptive_rx_coalesce) {
		dim_params->mode = ITR_DYNAMIC;
	} else {
		dim_params->mode = ITR_STATIC;
		dim_params->frames = ec->rx_max_coalesced_frames;
		dim_params->usecs = ec->rx_coalesce_usecs;
		mcevf_rc_for_each_ring(ring, q_vector->rx) {
			hw->ops->set_rxring_intr_coal(ring);
		}
	}

	dim_params = &q_vector->tx.dim_params;

	if (ec->use_adaptive_tx_coalesce) {
		dim_params->mode = ITR_DYNAMIC;
	} else {
		dim_params->mode = ITR_STATIC;
		dim_params->frames = ec->tx_max_coalesced_frames;
		dim_params->usecs = ec->tx_coalesce_usecs;
		mcevf_rc_for_each_ring(ring, q_vector->tx) {
			hw->ops->set_txring_intr_coal(ring);
		}
	}
}

static int __mcevf_set_coalesce(struct net_device *netdev,
				struct ethtool_coalesce *ec, int q_num)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_pf *pf = vsi->back;
	int i = 0;

	if (test_bit(MCEVF_FLAG_HW_DIM_ENA, pf->flags)) {
		netdev_info(netdev,
			    "Invalid value, because hw dim is enabled\n");
		return -EINVAL;
	}

#ifndef ETHTOOL_COALESCE_USECS
	if (mcevf_is_coalesce_param_invalid(ec))
		return -EOPNOTSUPP;
#endif /* !ETHTOOL_COALESCE_USECS */
	if (mcevf_check_coalesce_param(netdev, ec))
		return -EINVAL;

	if (q_num >= 0) {
		if (q_num >= vsi->num_q_vectors || q_num >= vsi->num_rxq ||
		    q_num >= vsi->num_txq || !vsi->q_vectors[q_num])
			return -EINVAL;
		mcevf_set_q_coalesce(vsi, ec, q_num);
		return 0;
	}

	mcevf_for_each_q_vector(vsi, i)
		mcevf_set_q_coalesce(vsi, ec, i);
	return 0;
}

static int
mcevf_get_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
		   struct kernel_ethtool_coalesce __maybe_unused *kec,
		   struct netlink_ext_ack __maybe_unused *extack)
{
	return __mcevf_get_coalesce(netdev, ec, -1);
}

/**
 * mcevf_set_coalesce - set coalesce settings for all queues
 * @netdev: pointer to the netdev associated with this query
 * @ec: ethtool structure to read the requested coalesce settings
 * @kec: kernel coalesce parameter
 * @extack: kernel extack parameter
 *
 * Return 0 on success, negative otherwise.
 */
static int
mcevf_set_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
		   struct kernel_ethtool_coalesce __maybe_unused *kec,
		   struct netlink_ext_ack __maybe_unused *extack)
{
	return __mcevf_set_coalesce(netdev, ec, -1);
}

#ifdef ETHTOOL_PERQUEUE
static int mcevf_get_per_q_coalesce(struct net_device *netdev, u32 q_num,
				    struct ethtool_coalesce *ec)
{
	if (q_num > INT_MAX)
		return -EINVAL;

	return __mcevf_get_coalesce(netdev, ec, (int)q_num);
}
#endif /* ETHTOOL_PERQUEUE */

#ifdef ETHTOOL_PERQUEUE
static int mcevf_set_per_q_coalesce(struct net_device *netdev, u32 q_num,
				    struct ethtool_coalesce *ec)
{
	if (q_num > INT_MAX)
		return -EINVAL;

	return __mcevf_set_coalesce(netdev, ec, (int)q_num);
}
#endif /* ETHTOOL_PERQUEUE */

static const struct ethtool_ops mcevf_ethtool_ops = {
	.get_drvinfo = mcevf_get_drvinfo,
	.get_sset_count = mcevf_get_sset_count,
	.get_strings = mcevf_get_strings,
	.get_link = ethtool_op_get_link,
	.get_ethtool_stats = mcevf_get_ethtool_stats,
	.get_priv_flags = mcevf_get_priv_flags,
	.set_priv_flags = mcevf_set_priv_flags,
	.get_rxnfc = mcevf_get_rxnfc,
	.set_rxnfc = mcevf_set_rxnfc,
#if defined(ETHTOOL_GRSSH) && defined(ETHTOOL_SRSSH)
	.get_rxfh_key_size = mcevf_get_rxfh_key_size,
	.get_rxfh_indir_size = mcevf_get_rxfh_indir_size,
	.get_rxfh = mcevf_get_rxfh,
	.set_rxfh = mcevf_set_rxfh,
#endif /* ETHTOOL_GRSSH && ETHTOOL_SRSSH */
	.get_channels = mcevf_get_channels,
	.set_channels = mcevf_set_channels,
#ifdef ETHTOOL_GLINKSETTINGS
	.get_link_ksettings = mcevf_get_link_ksettings,
#else
	.get_settings = mcevf_get_settings,
#endif /* ETHTOOL_GLINKSETTINGS */
	.get_ringparam = mcevf_get_ringparam,
	.set_ringparam = mcevf_set_ringparam,
	.get_msglevel = mcevf_get_msglevel,
	.set_msglevel = mcevf_set_msglevel,
#ifdef ETHTOOL_COALESCE_USECS
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
				     ETHTOOL_COALESCE_MAX_FRAMES |
				     ETHTOOL_COALESCE_USE_ADAPTIVE,
#endif /* ETHTOOL_COALESCE_USECS */
	.get_coalesce = mcevf_get_coalesce,
	.set_coalesce = mcevf_set_coalesce,
#ifdef ETHTOOL_PERQUEUE
	.get_per_queue_coalesce = mcevf_get_per_q_coalesce,
	.set_per_queue_coalesce = mcevf_set_per_q_coalesce,
#endif /* ETHTOOL_PERQUEUE */
};

void mcevf_set_ethtool_ops(struct net_device *netdev)
{
#ifndef ETHTOOL_OPS_COMPAT
	netdev->ethtool_ops = &mcevf_ethtool_ops;
#else
	SET_ETHTOOL_OPS(netdev, &mcevf_ethtool_ops);
#endif
}
