// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include <linux/uaccess.h>
#include <linux/firmware.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>

#include "mce.h"
#include "mce_base.h"
#include "mce_lib.h"
#include "mce_netdev.h"
#include "mce_ethtool.h"
#include "mce_ethtool_fdir.h"
#include "mce_vf_lib.h"
#include "mce_version.h"
#include "mce_dcb.h"
#include "mce_repr.h"
#include "mce_fwchnl.h"
#include "mce_arfs.h"

/* EEPROM byte offsets */
#define SFF_MODULE_ID_OFFSET 0x00
#define SFF_DIAG_SUPPORT_OFFSET 0x5c
#define SFF_MODULE_REVISION_ADDR 0x01

#define SFF_MODULE_ID_SFF 0x2
#define SFF_MODULE_ID_SFP 0x3
#define SFF_MODULE_ID_QSFP 0xc
#define SFF_MODULE_ID_QSFP_PLUS 0xd
#define SFF_MODULE_ID_QSFP28 0x11

#define MCE_SFF_8636_V1_3 0x03

#define MCE_REGS_LEN 1

enum mce_ethtool_test_id {
	MCE_ETH_TEST_REG = 0,
	MCE_ETH_TEST_EEPROM,
	MCE_ETH_TEST_INTR,
	MCE_ETH_TEST_LOOP,
	MCE_ETH_TEST_LINK,
};

static const char mce_gstrings_test[][ETH_GSTRING_LEN] = {
	"Register test  (offline)", "Eeprom test    (offline)",
	"Interrupt test (offline)", "Loopback test  (offline)",
	"Link test   (on/offline)"
};

#define MCE_TEST_LEN (sizeof(mce_gstrings_test) / ETH_GSTRING_LEN)

static const struct mce_stats mce_gstrings_net_stats[] = {
	MCE_NETDEV_STAT("rx_packets", net_stats.rx_packets),
	MCE_NETDEV_STAT("rx_bytes", net_stats.rx_bytes),
	MCE_NETDEV_STAT("tx_packets", net_stats.tx_packets),
	MCE_NETDEV_STAT("tx_bytes", net_stats.tx_bytes),
};

#define MCE_NET_STATS_LEN ARRAY_SIZE(mce_gstrings_net_stats)

static const struct mce_stats mce_gstrings_ofld_stats[] = {
	MCE_OFLD_STAT("tx_unicast", ofld_stats.tx_unicast),
	MCE_OFLD_STAT("tx_multicast", ofld_stats.tx_multicast),
	MCE_OFLD_STAT("tx_broadcast", ofld_stats.tx_broadcast),
	MCE_OFLD_STAT("rx_unicast", ofld_stats.rx_unicast),
	MCE_OFLD_STAT("rx_multicast", ofld_stats.rx_multicast),
	MCE_OFLD_STAT("rx_broadcast", ofld_stats.rx_broadcast),
	MCE_OFLD_STAT("rx_miss_drop", ofld_stats.rx_miss_drop),
	MCE_OFLD_STAT("rx_page_alloc_ok", rx_page_alloc_ok),
	MCE_OFLD_STAT("rx_page_failed", rx_page_failed),
	MCE_OFLD_STAT("rx_page_reuse_ok", rx_page_reuse_ok),
	MCE_OFLD_STAT("rx_page_reuse_reserved", rx_page_reuse_reserved),
	MCE_OFLD_STAT("rx_page_reuse_refcnt", rx_page_reuse_refcnt),
	MCE_OFLD_STAT("rx_page_reuse_offset", rx_page_reuse_offset),
	MCE_OFLD_STAT("tx_inserted_vlan", ofld_stats.tx_inserted_vlan),
	MCE_OFLD_STAT("rx_stripped_vlan", ofld_stats.rx_stripped_vlan),
	MCE_OFLD_STAT("rx_csum_err", ofld_stats.rx_csum_err),
	MCE_OFLD_STAT("rx_csum_unnecessary", ofld_stats.rx_csum_unnecessary),
	MCE_OFLD_STAT("rx_csum_none", ofld_stats.rx_csum_none),
};

#define MCE_OFLD_STATS_LEN ARRAY_SIZE(mce_gstrings_ofld_stats)

static const struct mce_stats mce_gstrings_hw_stats[] = {
	MCE_HW_STAT("tx_vport_rdma_unicast_packets",
		    stats.tx_vport_rdma_unicast_packets),
	MCE_HW_STAT("tx_vport_rdma_unicast_bytes",
		    stats.tx_vport_rdma_unicast_bytes),
	MCE_HW_STAT("rx_vport_rdma_unicast_packets",
		    stats.rx_vport_rdma_unicast_packets),
	MCE_HW_STAT("rx_vport_rdma_unicast_bytes",
		    stats.rx_vport_rdma_unicast_bytes),
	MCE_HW_STAT("np_cnp_sent", stats.np_cnp_sent),
	MCE_HW_STAT("rp_cnp_handled", stats.rn_cnp_handled),
	MCE_HW_STAT("np_ecn_marked_roce_packets",
		    stats.np_ecn_marked_roce_packets),
	MCE_HW_STAT("rp_cnp_ignored", stats.rp_cnp_ignored),
	MCE_HW_STAT("out_of_sequence", stats.out_of_sequence),
	MCE_HW_STAT("packet_seq_err", stats.packet_seq_err),
	MCE_HW_STAT("ack_timeout_err", stats.ack_timeout_err),
	MCE_HW_STAT("rx_crc_err", stats.rx_crc_err),
	MCE_HW_STAT("dmac_filter_count", stats.dmac_filter_drop),
};

#define MCE_HW_STATS_LEN ARRAY_SIZE(mce_gstrings_hw_stats)

#if MCE_MAC_STATS_EN
static const struct mce_stats mce_gstrings_mac_stats[] = {
	MCE_HW_STAT("rx_fcs_error_frames_num", mac_stats.rx_fcs_err),
	MCE_HW_STAT("rx_good_frame_num", mac_stats.rx_good_pkts),
	MCE_HW_STAT("rx_good_bytes", mac_stats.rx_good_bytes),
	MCE_HW_STAT("rx_bad_frame_num", mac_stats.rx_bad_pkts),
	MCE_HW_STAT("rx_good_and_bad_bytes_num", mac_stats.rx_good_bad_bytes),
	MCE_HW_STAT("rx_good_and_bad_frame_num", mac_stats.rx_good_bad_pkts),
	MCE_HW_STAT("rx_undersize_pkts", mac_stats.rx_undersize_err),
	MCE_HW_STAT("rx_len_oversize_pkts", mac_stats.rx_oversize_err),
	MCE_HW_STAT("rx_jabber_err_pkts", mac_stats.rx_jabber_err),
	MCE_HW_STAT("rx_less_64byes_with_crc_err", mac_stats.rx_runt_err),
	MCE_HW_STAT("rx_discard_num", mac_stats.rx_discard_pkts),
	MCE_HW_STAT("rx_good_pause_frame_num", mac_stats.rx_pause_pkts),
	MCE_HW_STAT("rx_good_vlan_frame_num", mac_stats.rx_vlan_pkts),
	MCE_HW_STAT("rx_good_pfc_priority_0", mac_stats.rx_pfc_pri0_pkts),
	MCE_HW_STAT("rx_good_pfc_priority_1", mac_stats.rx_pfc_pri1_pkts),
	MCE_HW_STAT("rx_good_pfc_priority_2", mac_stats.rx_pfc_pri2_pkts),
	MCE_HW_STAT("rx_good_pfc_priority_3", mac_stats.rx_pfc_pri3_pkts),
	MCE_HW_STAT("rx_good_pfc_priority_4", mac_stats.rx_pfc_pri4_pkts),
	MCE_HW_STAT("rx_good_pfc_priority_5", mac_stats.rx_pfc_pri5_pkts),
	MCE_HW_STAT("rx_good_pfc_priority_6", mac_stats.rx_pfc_pri6_pkts),
	MCE_HW_STAT("rx_good_pfc_priority_7", mac_stats.rx_pfc_pri7_pkts),
	MCE_HW_STAT("rx_good_unicast_frame_num", mac_stats.rx_unicast_pkts),
	MCE_HW_STAT("rx_good_mlticast_frame_num", mac_stats.rx_multicast_pkts),
	MCE_HW_STAT("rx_good_broadcast_frame_num", mac_stats.rx_broadcast_pkts),
	MCE_HW_STAT("rx_good_and_bad_64bytes_frame", mac_stats.rx_64octes_pkts),
	MCE_HW_STAT("rx_good_and_bad_65to127Octs_pkts",
		    mac_stats.rx_65to127_octes_pkts),
	MCE_HW_STAT("rx_good_and_bad_128OctsTo255Octs_pkts",
		    mac_stats.rx_128to255_octes_pkts),
	MCE_HW_STAT("rx_good_and_bad_256OctsTo511Octs_pkts",
		    mac_stats.rx_256to511_octes_pkts),
	MCE_HW_STAT("rx_good_and_bad_512OctsTo1023Octs_pkts",
		    mac_stats.rx_512to1023_octes_pkts),
	MCE_HW_STAT("rx_good_and_bad_1024OctsTo1518Octs_pkts",
		    mac_stats.rx_1024to1518_octes_pkts),
	MCE_HW_STAT("rx_good_and_bad_1519toMaxOcts_pkts",
		    mac_stats.rx_1519tomax_octes_pkts),

	MCE_HW_STAT("tx_good_frame_num", mac_stats.tx_good_pkts),
	MCE_HW_STAT("tx_good_bytes", mac_stats.tx_good_bytes),
	MCE_HW_STAT("tx_bad_frame_num", mac_stats.tx_bad_pkts),
	MCE_HW_STAT("tx_good_and_bad_bytes_num", mac_stats.tx_good_bad_bytes),
	MCE_HW_STAT("tx_good_and_bad_frame_num", mac_stats.tx_good_bad_pkts),
	MCE_HW_STAT("tx_len_oversize_pkts", mac_stats.tx_oversize_err),
	MCE_HW_STAT("tx_jabber_err_pkts", mac_stats.tx_jabber_err),
	MCE_HW_STAT("tx_good_pause_frame_num", mac_stats.tx_pause_pkts),
	MCE_HW_STAT("tx_good_vlan_frame_num", mac_stats.tx_vlan_pkts),
	MCE_HW_STAT("tx_good_pfc_priority_0", mac_stats.tx_pfc_pri0_pkts),
	MCE_HW_STAT("tx_good_pfc_priority_1", mac_stats.tx_pfc_pri1_pkts),
	MCE_HW_STAT("tx_good_pfc_priority_2", mac_stats.tx_pfc_pri2_pkts),
	MCE_HW_STAT("tx_good_pfc_priority_3", mac_stats.tx_pfc_pri3_pkts),
	MCE_HW_STAT("tx_good_pfc_priority_4", mac_stats.tx_pfc_pri4_pkts),
	MCE_HW_STAT("tx_good_pfc_priority_5", mac_stats.tx_pfc_pri5_pkts),
	MCE_HW_STAT("tx_good_pfc_priority_6", mac_stats.tx_pfc_pri6_pkts),
	MCE_HW_STAT("tx_good_pfc_priority_7", mac_stats.tx_pfc_pri7_pkts),
	MCE_HW_STAT("tx_good_unicast_frame_num", mac_stats.tx_unicast_pkts),
	MCE_HW_STAT("tx_good_multicast_frame_num", mac_stats.tx_multicast_pkts),
	MCE_HW_STAT("tx_good_broadcast_frame_num", mac_stats.tx_broadcast_pkts),
	MCE_HW_STAT("tx_good_and_bad_64Bytes_frame", mac_stats.tx_64octes_pkts),
	MCE_HW_STAT("tx_good_and_bad_65to127Octs_pkts",
		    mac_stats.tx_65to127_octes_pkts),
	MCE_HW_STAT("tx_good_and_bad_128OctsTo255Octs_pkts",
		    mac_stats.tx_128to255_octes_pkts),
	MCE_HW_STAT("tx_good_and_bad_256OctsTo511Octs pkts",
		    mac_stats.tx_256to511_octes_pkts),
	MCE_HW_STAT("tx_good_and_bad_512OctsTo1023Octs_pkts",
		    mac_stats.tx_512to1023_octes_pkts),
	MCE_HW_STAT("tx_good_and_bad_1024OctsTo1518Octs_pkts",
		    mac_stats.tx_1024to1518_octes_pkts),
	MCE_HW_STAT("tx_good_and_bad_1519toMaxOcts_pkts",
		    mac_stats.tx_1519tomax_octes_pkts),
};

#define MCE_MAC_STATS_LEN ARRAY_SIZE(mce_gstrings_mac_stats)
#endif /* MCE_MAC_STATS_EN */
static const struct mce_stats mce_gstrings_txq_stats[] = {
	MCE_QUEUE_STAT("packets", tx_stats.pkts),
	MCE_QUEUE_STAT("bytes", tx_stats.bytes),
#if __MCE_GET_RING_STATS_BY_HW
	MCE_QUEUE_STAT("unicast", tx_stats.unicast),
	MCE_QUEUE_STAT("multicast", tx_stats.multicast),
	MCE_QUEUE_STAT("broadcast", tx_stats.broadcast),
#endif
	MCE_QUEUE_STAT("inserted_vlan", tx_stats.inserted_vlan),
	MCE_QUEUE_STAT("drop", tx_stats.tx_drop),
	MCE_QUEUE_STAT("xmit_intr_count", tx_stats.xmit_intr_drop),
	MCE_QUEUE_STAT("poll_intr_count", tx_stats.poll_intr_drop),
	MCE_QUEUE_STAT("period_intr_count", tx_stats.period_intr_drop),
};

#define MCE_TXQ_STATS_LEN ARRAY_SIZE(mce_gstrings_txq_stats)

static const struct mce_stats mce_gstrings_rxq_stats[] = {
	MCE_QUEUE_STAT("packets", rx_stats.pkts),
	MCE_QUEUE_STAT("bytes", rx_stats.bytes),
#if __MCE_GET_RING_STATS_BY_HW
	MCE_QUEUE_STAT("unicast", rx_stats.unicast),
	MCE_QUEUE_STAT("multicast", rx_stats.multicast),
	MCE_QUEUE_STAT("broadcast", rx_stats.broadcast),
#endif
	MCE_QUEUE_STAT("miss_drop", rx_stats.miss_drop),
	MCE_QUEUE_STAT("pp_alloc_ok", rx_stats.pp_alloc_ok),
	MCE_QUEUE_STAT("pp_alloc_fail", rx_stats.pp_alloc_fail),
	MCE_QUEUE_STAT("pp_recycle", rx_stats.pp_recycle),
	MCE_QUEUE_STAT("pp_put", rx_stats.pp_put),
	MCE_QUEUE_STAT("pp_re_poll", rx_stats.pp_re_poll),
	MCE_QUEUE_STAT("page_reuse_ok", rx_stats.page_reuse_ok),
	MCE_QUEUE_STAT("page_reuse_reserved", rx_stats.page_reuse_reserved),
	MCE_QUEUE_STAT("page_reuse_refcnt", rx_stats.page_reuse_refcnt),
	MCE_QUEUE_STAT("page_reuse_offset", rx_stats.page_reuse_offset),
	MCE_QUEUE_STAT("stripped_vlan", rx_stats.stripped_vlan),
	MCE_QUEUE_STAT("csum_err", rx_stats.csum_err),
	MCE_QUEUE_STAT("csum_unnecessary", rx_stats.csum_unnecessary),
	MCE_QUEUE_STAT("csum_none", rx_stats.csum_none),
};

#define MCE_RXQ_STATS_LEN ARRAY_SIZE(mce_gstrings_rxq_stats)

static int mce_q_stats_len(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_dcb *dcb = pf->dcb;
	int total_slen = 0;

	if (test_bit(MCE_DCB_EN, dcb->flags))
		total_slen += np->vsi->num_txq * (MCE_TXQ_STATS_LEN);
	else
		total_slen += np->vsi->num_txq_real * (MCE_TXQ_STATS_LEN);

	total_slen += np->vsi->num_rxq * (MCE_RXQ_STATS_LEN);

	return total_slen;
}

#define MCE_ALL_STATS_LEN(n)                                         \
	(MCE_NET_STATS_LEN + MCE_OFLD_STATS_LEN + MCE_HW_STATS_LEN + \
	 MCE_MAC_STATS_LEN + mce_q_stats_len(n))

struct mce_priv_flag {
	char name[ETH_GSTRING_LEN];
	u32 bitno; /* bit position in pf->flags */
};

#define MCE_PRIV_FLAG(_name, _bitno) \
	{                            \
		.name = _name,       \
		.bitno = _bitno,     \
	}

static const struct mce_priv_flag mce_gstrings_priv_flags[] = {
	MCE_PRIV_FLAG("vf-true-promisc-support", MCE_FLAG_VF_TRUE_PROMISC_ENA),
	MCE_PRIV_FLAG("vf-rqa-tcpsync-support", MCE_FLAG_VF_RQA_TCPSYNC_ENA),
	MCE_PRIV_FLAG("dscp", MCE_FLAG_DSCP_ENA),
	MCE_PRIV_FLAG("capture-rdma", MCE_FLAG_CAPTURE_RDMA_ENA),
	MCE_PRIV_FLAG("ddp_extra_en", MCE_FLAG_DDP_EXTRA_ENA),
	MCE_PRIV_FLAG("evb_vepa", MCE_FLAG_EVB_VEPA_ENA),
	MCE_PRIV_FLAG("link-down-on-close", MCE_FLAG_FORCE_LINK_ENA),
	MCE_PRIV_FLAG("rx_buffer_manually", MCE_FLAG_RX_BUFFER_MANUALLY),
	MCE_PRIV_FLAG("lldp_tx_en", MCE_FLAG_LLDP_TX_EN),
	MCE_PRIV_FLAG("pf-anti-spoof", MCE_FLAG_PF_ANTISPOOF),
	MCE_PRIV_FLAG("vlan_to_q_map", MCE_FLAG_PF_VLAN_Q_MAP),
	MCE_PRIV_FLAG("dcb_tools_control", MCE_FLAG_PF_DCB_TOOLS),
	MCE_PRIV_FLAG("pfc_rr_mode", MCE_FLAG_PFC_RR_MODE),
};

#define MCE_PRIV_FLAG_ARRAY_SIZE ARRAY_SIZE(mce_gstrings_priv_flags)

/**
 * mce_phy_type_to_ethtool - convert the phy_types to ethtool link modes
 * @netdev: network interface device structure
 * @ks: ethtool link ksettings struct to fill out
 */
static void mce_phy_type_to_ethtool(struct net_device *netdev,
				    struct ethtool_link_ksettings *ks)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_port_info *pi;
	struct mce_hw *hw;
	int i;

	hw = &vsi->back->hw;
	hw->ops->update_fw_stat(hw);
	pi = hw->port_info;

	linkmode_zero(ks->link_modes.supported);
	linkmode_zero(ks->link_modes.advertising);

	for (i = 0; i < ARRAY_SIZE(phy_type_lkup); i++) {
		if ((pi->sup_module_type & phy_type_lkup[i].module_type) &&
		    (pi->sup_speed_list & phy_type_lkup[i].hw_link_speed)) {
			linkmode_set_bit(phy_type_lkup[i].link_mode,
					 ks->link_modes.supported);
		}

		if ((pi->adv_module_type & phy_type_lkup[i].module_type) &&
		    (pi->adv_speed_list & phy_type_lkup[i].hw_link_speed))
			linkmode_set_bit(phy_type_lkup[i].link_mode,
					 ks->link_modes.advertising);
	}
}

static bool mce_get_link_duplex(struct mce_hw *hw)
{
	hw->ops->update_fw_stat(hw);
	return !!hw->fw_stat.stat0.duplex;
}

static bool mce_get_link_autoneg(struct mce_hw *hw)
{
	struct mce_port_info *pi = hw->port_info;
	struct mce_phy_ability *abi;

	hw->ops->update_fw_stat(hw);
	abi = (struct mce_phy_ability *)&hw->fw_stat.stat2.v;
	if (pi->media_type == MCE_MEDIA_BACKPLANE)
		return !!hw->fw_stat.stat0.autoneg;
	else
		return !abi->force_speed_by_user;
}

#define __MCE_BITS_TIMEOUT 50
#define __MCE_BITS_SLEEP_MAX 2000
#define __MCE_BITS_SLEEP_MIN 1000

static int mce_setup_autoneg(struct mce_hw *hw,
			     struct ethtool_link_ksettings *ks,
			     u8 autoneg_enabled, u8 *autoneg_changed,
			     struct net_device *netdev)
{
	int err = 0;

	*autoneg_changed = 0;

	/* Check autoneg */
	if (autoneg_enabled == AUTONEG_ENABLE) {
		if (!ethtool_link_ksettings_test_link_mode(ks, supported,
							   Autoneg)) {
			netdev_info(netdev,
				    "Autoneg not supported on this phy.\n");
			err = -EINVAL;
		}
		if (!mce_get_link_autoneg(hw))
			*autoneg_changed = 1;
	} else {
		if (mce_get_link_autoneg(hw))
			*autoneg_changed = 1;
	}

	return err;
}

static bool mce_check_force_speed_valid(struct mce_hw *hw, u32 speed)
{
	if (READ_ONCE(hw->disable_40_100g_card_25g_and_below)) {
		if (hw->max_speed == SPEED_100000)
			return speed == SPEED_100000 || speed == SPEED_40000;

		if (hw->max_speed == SPEED_40000)
			return speed == SPEED_40000;
	}

	if (hw->max_speed == SPEED_100000)
		return speed == SPEED_100000 || speed == SPEED_40000 ||
		       speed == SPEED_25000 || speed == SPEED_10000 ||
		       speed == SPEED_1000;

	if (hw->max_speed == SPEED_40000)
		return speed == SPEED_40000 || speed == SPEED_25000 ||
		       speed == SPEED_10000 || speed == SPEED_1000;

	if (hw->max_speed == SPEED_25000)
		return speed == SPEED_25000 || speed == SPEED_10000 ||
		       speed == SPEED_1000;

	return false;
}

static int mce_setup_mac_link(struct mce_hw *hw, u32 speed, bool duplex,
			      bool an)
{
	struct mce_port_info *pi = hw->port_info;
	enum FORCE_SPEED fspeed = NO_FORCE_SPEED;
	int err = 0;

	if (!mce_check_force_speed_valid(hw, speed)) {
		/* if an enabled, speed can be unknown */
		if (!(an && speed == (__u32)SPEED_UNKNOWN))
			return -EINVAL;
	}

	if (pi->media_type == MCE_MEDIA_BACKPLANE)
		mce_mbx_set_autoneg(hw, an);
	else
		mce_mbx_set_autoneg(hw, false);

	mce_mbx_set_duplex(hw, an ? true : duplex);

	if (speed < SPEED_1000)
		fspeed = NO_FORCE_SPEED;
	if (speed == SPEED_1000)
		fspeed = FORCE_1G;
	else if (speed == SPEED_10000)
		fspeed = FORCE_10G;
	else if (speed == SPEED_25000)
		fspeed = FORCE_25G;
	else if (speed == SPEED_40000)
		fspeed = FORCE_40G;
	else if (speed == SPEED_100000)
		fspeed = FORCE_100G;

	/* if non-backplane, when an == 1, fspeed == NO_FORCE_SPEED */
	if (an && pi->media_type != MCE_MEDIA_BACKPLANE)
		fspeed = NO_FORCE_SPEED;

	err = mce_mbx_set_force_speed(hw, fspeed);
	hw_logd(LOG_LINK_INFO,
		"%s meida_type:0x%x speed:%d fspeed:%d duplex:0x%x an:0x%x\n",
		__func__, pi->media_type, speed, fspeed, duplex, an);
	return err;
}

/**
 * mce_get_settings_link_up - Get Link settings for when link is up
 * @ks: ethtool ksettings to fill in
 * @netdev: network interface device structure
 */
static void mce_get_settings_link_up(struct ethtool_link_ksettings *ks,
				     struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_port_info *pi;
	struct mce_hw *hw;

	hw = &vsi->back->hw;
	pi = hw->port_info;

	mce_phy_type_to_ethtool(netdev, ks);

	switch (pi->link_speed) {
	case SPEED_25000:
		ks->base.speed = SPEED_25000;
		break;
	case SPEED_40000:
		ks->base.speed = SPEED_40000;
		break;
	case SPEED_10000:
		ks->base.speed = SPEED_10000;
		break;
	case SPEED_1000:
		ks->base.speed = SPEED_1000;
		break;
	case SPEED_100:
		ks->base.speed = SPEED_100;
		break;
	case SPEED_10:
		ks->base.speed = SPEED_10;
		break;
	default:
		netdev_info(netdev,
			    "WARNING: Unrecognized link_speed (0x%x).\n",
			    pi->link_speed);
		break;
	}

	ks->base.duplex = mce_get_link_duplex(hw);

	netdev_logd(LOG_LINK_INFO,
		    "%s an:0x%x speed:%d duplex:0x%x fc.current_mode:0x%x\n",
		    __func__, mce_get_link_autoneg(hw), pi->link_speed,
		    ks->base.duplex, vsi->back->fc.current_mode);
}

/**
 * mce_get_settings_link_down - Get the Link settings when link is down
 * @ks: ethtool ksettings to fill in
 * @netdev: network interface device structure
 *
 * Reports link settings that can be determined when link is down
 */
static void mce_get_settings_link_down(struct ethtool_link_ksettings *ks,
				       struct net_device *netdev)
{
	/* link is down and the driver needs to fall back on
	 * supported PHY types to figure out what info to display
	 */
	mce_phy_type_to_ethtool(netdev, ks);

	/* With no link, speed and duplex are unknown */
	ks->base.speed = SPEED_UNKNOWN;
	ks->base.duplex = DUPLEX_UNKNOWN;
}

static int mce_get_link_ksettings(struct net_device *netdev,
				  struct ethtool_link_ksettings *ks)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_port_info *pi;
	struct mce_hw *hw;
	/* ethtool -k ethX */

	hw = &vsi->back->hw;
	ethtool_link_ksettings_zero_link_mode(ks, supported);
	ethtool_link_ksettings_zero_link_mode(ks, advertising);

	hw->ops->update_fw_stat(hw);
	mce_get_port_phy_ability(hw);
	pi = hw->port_info;
	pi->link_up = hw->fw_stat.stat0.linkup;
	pi->link_speed = speed_unzip(hw->fw_stat.stat0.s_speed);

	if (pi->link_up)
		mce_get_settings_link_up(ks, netdev);
	else
		mce_get_settings_link_down(ks, netdev);

	/* set autoneg settings */
	ks->base.autoneg = mce_get_link_autoneg(hw) ? AUTONEG_ENABLE :
						      AUTONEG_DISABLE;
	switch (pi->media_type) {
	case MCE_MEDIA_FIBER:
		ethtool_link_ksettings_add_link_mode(ks, supported, FIBRE);
		ks->base.port = PORT_FIBRE;
		break;
	case MCE_MEDIA_BACKPLANE:
		ethtool_link_ksettings_add_link_mode(ks, supported, Backplane);
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     Backplane);
		ks->base.port = PORT_NONE;
		break;
	case MCE_MEDIA_COPPER:
		fallthrough;
	case MCE_MEDIA_DA:
		ethtool_link_ksettings_add_link_mode(ks, supported, FIBRE);
		ethtool_link_ksettings_add_link_mode(ks, advertising, FIBRE);
		ks->base.port = PORT_DA;
		break;
	case MCE_MEDIA_BASET:
		ethtool_link_ksettings_add_link_mode(ks, supported, TP);
		ethtool_link_ksettings_add_link_mode(ks, advertising, TP);
		ks->base.port = PORT_TP;
		break;
	case MCE_MEDIA_NONE:
		ks->base.port = PORT_NONE;
		break;
	case MCE_MEDIA_UNKNOWN:
		ks->base.port = PORT_OTHER;
		break;
	default:
		ks->base.port = PORT_OTHER;
		break;
	}

	/* flow control is symmetric and always supported */
	ethtool_link_ksettings_add_link_mode(ks, supported, Pause);

	switch (vsi->back->fc.current_mode) {
	case MCE_FC_FULL:
		ethtool_link_ksettings_add_link_mode(ks, advertising, Pause);
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     Asym_Pause);
		break;
	case MCE_FC_TX_PAUSE:
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     Asym_Pause);
		break;
	case MCE_FC_RX_PAUSE:
		ethtool_link_ksettings_add_link_mode(ks, advertising, Pause);
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     Asym_Pause);
		break;
	default:
		ethtool_link_ksettings_del_link_mode(ks, advertising, Pause);
		ethtool_link_ksettings_del_link_mode(ks, advertising,
						     Asym_Pause);
		break;
	}

	if (ks->base.autoneg) {
		ethtool_link_ksettings_add_link_mode(ks, supported, Autoneg);
		ethtool_link_ksettings_add_link_mode(ks, advertising, Autoneg);
	}

	netdev_logd(LOG_LINK_INFO,
		    "%s an:0x%x speed:%d duplex:0x%x fc.current_mode:0x%x\n",
		    __func__, mce_get_link_autoneg(hw), pi->link_speed,
		    ks->base.duplex, vsi->back->fc.current_mode);

	return 0;
}

/**
 * mce_set_link_ksettings - Set Speed and Duplex
 * @netdev: network interface device structure
 * @ks: ethtool ksettings
 *
 * Set speed/duplex per media_types advertised/forced
 * ethtool -s ethX speed xx autoneg off
 * Returns: The result of the operation.
 */
static int mce_set_link_ksettings(struct net_device *netdev,
				  const struct ethtool_link_ksettings *ks)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct ethtool_link_ksettings copy_ks = *ks;
	struct ethtool_link_ksettings safe_ks = {};
	struct mce_vsi *vsi = np->vsi;
	struct mce_port_info *pi;
	u8 autoneg_changed = 0;
	struct mce_hw *hw;
	int timeout;
	u8 autoneg;
	int err;

	hw = &vsi->back->hw;
	pi = hw->port_info;
	hw->ops->update_fw_stat(hw);
	mce_get_port_phy_ability(hw);

	/* save autoneg out of ksettings */
	autoneg = copy_ks.base.autoneg;
	hw_logd(LOG_LINK_INFO,
		"%s %s set link: speed=%d port=%d duplex=%d autoneg=%d phy_address=%d\n",
		__func__, netdev->name, copy_ks.base.speed, copy_ks.base.port,
		copy_ks.base.duplex, copy_ks.base.autoneg,
		copy_ks.base.phy_address);
	if (autoneg == AUTONEG_DISABLE &&
	    !mce_check_force_speed_valid(hw, copy_ks.base.speed)) {
		netdev_info(netdev, "Force speed %u is not supported.\n",
			    copy_ks.base.speed);
		return -EINVAL;
	}

	/* Get link modes supported by hardware.*/
	mce_get_link_ksettings(netdev, &safe_ks);
	/* default support Pause/Asym_Pause*/
	ethtool_link_ksettings_add_link_mode(&safe_ks, supported, Pause);
	ethtool_link_ksettings_add_link_mode(&safe_ks, supported, Asym_Pause);
	ethtool_link_ksettings_add_link_mode(&safe_ks, supported, Autoneg);
	/* and check against modes requested by user.
	 * Return an error if unsupported mode was set.
	 */
	if (!bitmap_subset(copy_ks.link_modes.advertising,
			   safe_ks.link_modes.supported,
			   __ETHTOOL_LINK_MODE_MASK_NBITS)) {
		netdev_info(netdev,
			    "The selected speed is not supported by the current media.\n");
		if (logd_if(LOG_LINK_INFO)) {
			int bit_idx;

			for_each_set_bit(bit_idx,
					 copy_ks.link_modes.advertising,
					 __ETHTOOL_LINK_MODE_MASK_NBITS)
				netdev_info(netdev, "adv %d\n", bit_idx);
			for_each_set_bit(bit_idx, safe_ks.link_modes.supported,
					 __ETHTOOL_LINK_MODE_MASK_NBITS)
				netdev_info(netdev, "safe %d\n", bit_idx);
		}
		err = -EOPNOTSUPP;
		goto done;
	}

	timeout = __MCE_BITS_TIMEOUT;
	while (test_and_set_bit(MCE_CFG_BUSY, vsi->back->state)) {
		timeout--;
		if (!timeout) {
			err = -EBUSY;
			goto done;
		}
		usleep_range(__MCE_BITS_SLEEP_MIN, __MCE_BITS_SLEEP_MAX);
	}

	/* Check autoneg */
	err = mce_setup_autoneg(hw, &safe_ks, autoneg, &autoneg_changed,
				netdev);
	if (err)
		goto done;

	if (ks->base.speed == pi->link_speed && !autoneg_changed) {
		netdev_info(netdev,
			    "Nothing changed, exiting without setting anything.\n");
		goto done;
	}

	hw_logd(LOG_LINK_INFO, "%s %s set link: speed=%d->%d autoneg=%d\n",
		__func__, netdev->name, pi->link_speed, ks->base.speed,
		autoneg);
	err = mce_setup_mac_link(hw, ks->base.speed, true, autoneg);
	if (err) {
		netdev_info(netdev, "Set phy config failed,\n");
		goto done;
	}

done:
	clear_bit(MCE_CFG_BUSY, vsi->back->state);

	return err;
}

static int mce_get_regs_len(struct net_device *netdev)
{
	return MCE_REGS_LEN * sizeof(u32);
}

/* ethtool -d ethX */
static void mce_get_regs(struct net_device *netdev, struct ethtool_regs *regs,
			 void *p)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_hw *hw = &np->vsi->back->hw;
	u32 *regs_buff = p;
	int i;

	memset(p, 0, MCE_REGS_LEN * sizeof(u32));

	for (i = 0; i < MCE_REGS_LEN; i++)
		regs_buff[i] = rd32(hw, i * sizeof(u32));
}

/* ethtool -i ethX */
static void mce_get_drvinfo(struct net_device *netdev,
			    struct ethtool_drvinfo *drvinfo)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &vsi->back->hw;

	unsigned char *pxe_version __maybe_unused =
		(unsigned char *)&hw->fw_stat.pxe_version;
	unsigned char *fw_version __maybe_unused =
		(unsigned char *)&hw->fw_stat.fw_version;

	strscpy(drvinfo->driver, DRIVER_NAME, sizeof(drvinfo->driver));

	strscpy(drvinfo->version, DRV_VERSION, sizeof(drvinfo->version));

	if (hw->fw_stat.pxe_version) {
		snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version),
			 "%u.%u.%u.%u  %u.%u.%u.%u", fw_version[3],
			 fw_version[2], fw_version[1], fw_version[0],
			 pxe_version[3], pxe_version[2], pxe_version[1],
			 pxe_version[0]);
	} else {
		snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version),
			 "%u.%u.%u.%u", fw_version[3], fw_version[2],
			 fw_version[1], fw_version[0]);
	}

	strscpy(drvinfo->bus_info, pci_name(vsi->back->pdev),
		sizeof(drvinfo->bus_info));

	drvinfo->testinfo_len = MCE_TEST_LEN;
	drvinfo->regdump_len = mce_get_regs_len(netdev);
	drvinfo->n_stats = MCE_ALL_STATS_LEN(netdev);
}

/* ethtool eth2 |grep Wake-on */
static void mce_get_wol(struct net_device *netdev, struct ethtool_wolinfo *wol)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_hw *hw = &np->vsi->back->hw;

	wol->wolopts = 0;

	hw->ops->update_fw_stat(hw);
	if (hw->fw_stat.stat2.wol_supported)
		wol->supported = WAKE_MAGIC;
	else
		wol->supported = 0;
	if (hw->fw_stat.stat2.wol_enabled)
		wol->wolopts = WAKE_MAGIC;
}

/* ethtool -s eth2 wol g */
static int mce_set_wol(struct net_device *netdev, struct ethtool_wolinfo *wol)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_hw *hw = &np->vsi->back->hw;
	int wol_supported_type = WAKE_MAGIC;
	bool wol_enable = false;
	u32 wol_supported = 0;

	hw->ops->update_fw_stat(hw);
	wol_supported = hw->fw_stat.stat2.wol_supported;
	if (!!wol->wolopts) {
		if ((wol->wolopts & ~wol_supported_type) || !wol_supported)
			return -EOPNOTSUPP;
	}

	wol_enable = !!(wol->wolopts & WAKE_MAGIC);
	if (mce_mbx_wol_set(hw, wol_enable))
		wol_enable = false;
	device_set_wakeup_enable(&hw->pdev->dev, wol_enable);
	return 0;
}

/* ethtool -r ethX
 * restart autoneg
 */
static int mce_nway_reset_autoneg(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_hw *hw = &np->vsi->back->hw;
	int ret = 0;

	ret = mce_mbx_set_link_restart_autoneg(hw);
	if (ret) {
		netdev_info(netdev, "link restart failed\n");
		return -EIO;
	}

	return 0;
}

static bool mce_link_test(struct mce_hw *hw)
{
	struct mce_port_info *pi = hw->port_info;

	if (!pi)
		return true;

	return !pi->link_up;
}

static bool mce_reg_test(struct mce_hw *hw)
{
	return !((rd32(hw, 0x70000) & 0xfff00000) == 0x20200000);
}

/* ethtool --test  ethX */
static void mce_diag_test(struct net_device *netdev,
			  struct ethtool_test *eth_test, u64 *data)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_pf *pf = np->vsi->back;
	struct mce_hw *hw = &pf->hw;

	set_bit(MCE_FLAGS_SELF_TESTING, pf->flags);
	if (eth_test->flags == ETH_TEST_FL_OFFLINE) {
		netdev_info(netdev, "offline testing starting\n");

		data[MCE_ETH_TEST_REG] = mce_reg_test(hw);
		data[MCE_ETH_TEST_EEPROM] = 0;
		data[MCE_ETH_TEST_INTR] = 0;
		data[MCE_ETH_TEST_LOOP] = 0;
		data[MCE_ETH_TEST_LINK] = mce_link_test(hw);

		if (data[MCE_ETH_TEST_LINK] || data[MCE_ETH_TEST_REG])
			eth_test->flags |= ETH_TEST_FL_FAILED;
	} else {
		netdev_info(netdev, "online testing starting\n");

		data[MCE_ETH_TEST_REG] = 0;
		data[MCE_ETH_TEST_EEPROM] = 0;
		data[MCE_ETH_TEST_INTR] = 0;
		data[MCE_ETH_TEST_LOOP] = 0;
		data[MCE_ETH_TEST_LINK] = mce_link_test(hw);
		if (data[MCE_ETH_TEST_LINK])
			eth_test->flags |= ETH_TEST_FL_FAILED;
	}
	clear_bit(MCE_FLAGS_SELF_TESTING, pf->flags);
}

static int mce_get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_TEST:
		return MCE_TEST_LEN;
	case ETH_SS_STATS:
		return MCE_ALL_STATS_LEN(netdev);
	case ETH_SS_PRIV_FLAGS:
		return MCE_PRIV_FLAG_ARRAY_SIZE;
	default:
		return -EOPNOTSUPP;
	}
}

static void mce_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &vsi->back->hw;
	u8 *p = data;
	u32 i = 0;
	u32 j = 0;

	switch (stringset) {
	case ETH_SS_TEST:
		memcpy(data, mce_gstrings_test, MCE_TEST_LEN * ETH_GSTRING_LEN);
		break;
	case ETH_SS_STATS:
		for (i = 0; i < MCE_NET_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 mce_gstrings_net_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}

		for (i = 0; i < MCE_OFLD_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 mce_gstrings_ofld_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}

		for (i = 0; i < MCE_HW_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 mce_gstrings_hw_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}
#if MCE_MAC_STATS_EN
		for (i = 0; i < MCE_MAC_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 mce_gstrings_mac_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}
#endif /* MCE_MAC_STATS_EN */
		mce_for_each_txq_new(vsi, i) {
			if (!vsi->tx_rings[i])
				continue;
			if (!vsi->tx_rings[i]->q_vector)
				continue;
			for (j = 0; j < MCE_TXQ_STATS_LEN; j++) {
				snprintf(p, ETH_GSTRING_LEN, "txq_%u(%u)_%s",
					 vsi->tx_rings[i]->idx_os, i,
					 mce_gstrings_txq_stats[j].stat_string);
				p += ETH_GSTRING_LEN;
			}
		}

		mce_for_each_rxq_new(vsi, i) {
			if (!vsi->rx_rings[i]->q_vector)
				continue;
			for (j = 0; j < MCE_RXQ_STATS_LEN; j++) {
				snprintf(p, ETH_GSTRING_LEN, "rxq_%u_%s", i,
					 mce_gstrings_rxq_stats[j].stat_string);
				p += ETH_GSTRING_LEN;
			}
		}

		break;
	case ETH_SS_PRIV_FLAGS: {
		hw->ops->update_fw_stat(hw);
		for (i = 0; i < MCE_PRIV_FLAG_ARRAY_SIZE; i++) {
			if (mce_gstrings_priv_flags[i].bitno ==
				    MCE_FLAG_FORCE_LINK_ENA &&
				    hw->fw_stat.stat0.force_link_cap ==
				    FOCE_LINK_UP_ON_CLOSE_CAP) {
				/* "force-link-up-on-close", */
				snprintf(p, ETH_GSTRING_LEN, "%s", "link-up-on-close");
				p += ETH_GSTRING_LEN;
			} else {
				snprintf(p, ETH_GSTRING_LEN, "%s",
					 mce_gstrings_priv_flags[i].name);
				p += ETH_GSTRING_LEN;
			}
		}
		break;
	}

	default:
		break;
	}
}

/* ethtool -m ethX */
static int mce_get_sfp_module_info(struct net_device *netdev,
				   struct ethtool_modinfo *modinfo)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_hw *hw = &np->vsi->back->hw;
	u8 module_id, diag_supported, ext_type;
	int rc;

	hw->ops->update_fw_stat(hw);

	if (hw->fw_stat.stat0.is_backplane || hw->fw_stat.stat0.is_sgmii)
		return -EINVAL;

	/* Check if firmware supports reading module EEPROM. */
	rc = mce_read_sfp_module_eeprom(hw, 0xA0, SFF_MODULE_ID_OFFSET,
					&module_id, 1);
	if (rc || module_id == 0xff)
		return -EIO;

	rc = mce_read_sfp_module_eeprom(hw, 0xA0, SFF_DIAG_SUPPORT_OFFSET,
					&diag_supported, 1);
	if (rc)
		return -EIO;
	switch (module_id) {
	case SFF_MODULE_ID_SFF:
	case SFF_MODULE_ID_SFP:
		modinfo->type = ETH_MODULE_SFF_8472;
		modinfo->eeprom_len = ETH_MODULE_SFF_8472_LEN;
		if (!diag_supported)
			modinfo->eeprom_len = ETH_MODULE_SFF_8436_LEN;
		break;
	case SFF_MODULE_ID_QSFP:
		modinfo->type = ETH_MODULE_SFF_8436;
		modinfo->eeprom_len = ETH_MODULE_SFF_8436_MAX_LEN;
		break;
	case SFF_MODULE_ID_QSFP_PLUS:
		/* Check if firmware supports reading module EEPROM. */
		rc = mce_read_sfp_module_eeprom(hw, 0xA0, SFF_MODULE_REVISION_ADDR, &ext_type, 1);
		if (rc)
			return -EIO;

		if (ext_type < MCE_SFF_8636_V1_3) {
			modinfo->type = ETH_MODULE_SFF_8436;
			modinfo->eeprom_len = ETH_MODULE_SFF_8436_MAX_LEN;
		} else {
			modinfo->type = ETH_MODULE_SFF_8636;
			modinfo->eeprom_len = ETH_MODULE_SFF_8636_MAX_LEN;
		}

		break;
	case SFF_MODULE_ID_QSFP28:
		modinfo->type = ETH_MODULE_SFF_8636;
		modinfo->eeprom_len = ETH_MODULE_SFF_8636_MAX_LEN;
		break;
	default:
		netdev_err(netdev,
			   "SFP module type unrecognized or no SFP connector.\n");
		return -EINVAL;
	}
	return 0;
}

/* SFF-8636/8436 (QSFP/QSFP+/QSFP28) paged memory access:
 *   - page0 = 256 bytes: Lower Page 00h via 0xA0[0-127], Upper Page 00h
 *     via 0xA2[128-255] (page select 0)
 *   - page1/2/3 = 128 bytes each via 0xA2[128-255], selected through the
 *     page-select register at 0xA0[127].
 * The 0xA2 register window is always 128-255.
 */
#define MCE_QSFP_PAGE0_LEN  256
#define MCE_QSFP_LOWER_LEN  128
#define MCE_QSFP_PAGE_LEN   128
#define MCE_QSFP_PAGE_SEL   127
#define MCE_QSFP_REG_OFFSET 128

static int mce_get_qsfp_module_eeprom(struct mce_hw *hw, u16 start,
				      u16 length, u8 *data)
{
	int left = length;
	int page, reg_in_page, cnt, rc;
	int offset = start;
	u8 orig_page;

	memset(data, 0, length);

	rc = mce_read_sfp_module_eeprom(hw, 0xA0, MCE_QSFP_PAGE_SEL,
					&orig_page, 1);
	if (rc)
		return rc;

	while (left > 0) {
		if (offset < MCE_QSFP_LOWER_LEN) {
			cnt = min(left, MCE_QSFP_LOWER_LEN - offset);
			rc = mce_read_sfp_module_eeprom(hw, 0xA0, offset,
							data, cnt);
		} else {
			/* read 128-255 */
			page = (offset - MCE_QSFP_LOWER_LEN) /
			       MCE_QSFP_PAGE_LEN;
			reg_in_page = MCE_QSFP_REG_OFFSET;
			cnt = min(left, MCE_QSFP_PAGE_LEN);

			rc = mce_write_sfp_module_eeprom(hw, 0xA0,
							 MCE_QSFP_PAGE_SEL,
							 page);
			if (rc)
				goto out_restore;
			rc = mce_read_sfp_module_eeprom(hw, 0xA0, reg_in_page,
							data, cnt);
		}
		if (rc)
			goto out_restore;

		offset += cnt;
		data += cnt;
		left -= cnt;
	}

out_restore:
	mce_write_sfp_module_eeprom(hw, 0xA0, MCE_QSFP_PAGE_SEL, orig_page);
	return rc;
}

/* ethtool -m ethX */
static int mce_get_sfp_module_eeprom(struct net_device *netdev,
				     struct ethtool_eeprom *eeprom, u8 *data)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_hw *hw = &np->vsi->back->hw;

	u16 start = eeprom->offset, length = eeprom->len;
	u8 module_id;
	int rc;

	rc = mce_read_sfp_module_eeprom(hw, 0xA0, SFF_MODULE_ID_OFFSET,
					&module_id, 1);
	if (rc)
		return rc;

	/* QSFP family requires paged (banked) upper-memory access. */
	switch (module_id) {
	case SFF_MODULE_ID_QSFP:
	case SFF_MODULE_ID_QSFP_PLUS:
	case SFF_MODULE_ID_QSFP28:
		if (start >= ETH_MODULE_SFF_8436_MAX_LEN)
			return -EINVAL;
		if (start + length > ETH_MODULE_SFF_8436_MAX_LEN)
			length = ETH_MODULE_SFF_8436_MAX_LEN - start;
		return mce_get_qsfp_module_eeprom(hw, start, length, data);
	default:
		break;
	}

	memset(data, 0, eeprom->len);

	/* SFF/SFF-8472: linear 0xA0 (0-255) then 0xA2 (256-511). */
	if (start < ETH_MODULE_SFF_8436_LEN) {
		if (start + length > ETH_MODULE_SFF_8436_LEN)
			length = ETH_MODULE_SFF_8436_LEN - start;
		rc = mce_read_sfp_module_eeprom(hw, 0xA0, start, data, length);
		if (rc)
			return rc;
		start += length;
		data += length;
		length = eeprom->len - length;
	}

	if (length) {
		start -= ETH_MODULE_SFF_8436_LEN;
		rc = mce_read_sfp_module_eeprom(hw, 0xA2, start, data, length);
	}

	return rc;
}

/* ethtool -p ethX */
static int mce_led_set_phys_id(struct net_device *netdev,
			       enum ethtool_phys_id_state state)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_hw *hw = &np->vsi->back->hw;

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		mce_fw_set_led(hw, LED_ACTIVE);
		return 2;
	case ETHTOOL_ID_ON:
		mce_fw_set_led(hw, LED_ACT_ON);
		break;
	case ETHTOOL_ID_OFF:
		mce_fw_set_led(hw, LED_ACT_OFF);
		break;
	case ETHTOOL_ID_INACTIVE:
		mce_fw_set_led(hw, LED_INACTIVE);
		break;
	default:
		return -ENOENT;
	}
	return 0;
}

/* ethtool -S ethX */
static void mce_get_ethtool_stats(struct net_device *netdev,
				  struct ethtool_stats __always_unused *stats,
				  u64 *data)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_ring *tx_ring;
	struct mce_ring *rx_ring;
	u32 j = 0;
	u32 k = 0;
	int i = 0;
	char *p;

#if MCE_MAC_STATS_EN
	mce_update_mac_stats(pf);
#endif /* MCE_MAC_STATS_EN */
	mce_update_vsi_ring_stats(vsi);
	mce_update_pf_stats(pf);

	for (j = 0; j < MCE_NET_STATS_LEN; j++) {
		p = (char *)vsi + mce_gstrings_net_stats[j].stat_offset;
		data[i++] =
			(mce_gstrings_net_stats[j].sizeof_stat == sizeof(u64)) ?
				*(u64 *)p :
				*(u32 *)p;
	}

	for (j = 0; j < MCE_OFLD_STATS_LEN; j++) {
		p = (char *)vsi + mce_gstrings_ofld_stats[j].stat_offset;
		data[i++] = (mce_gstrings_ofld_stats[j].sizeof_stat ==
			     sizeof(u64)) ?
				    *(u64 *)p :
				    *(u32 *)p;
	}

	for (j = 0; j < MCE_HW_STATS_LEN; j++) {
		p = (char *)pf + mce_gstrings_hw_stats[j].stat_offset;
		data[i++] =
			(mce_gstrings_hw_stats[j].sizeof_stat == sizeof(u64)) ?
				*(u64 *)p :
				*(u32 *)p;
	}

#if MCE_MAC_STATS_EN
	for (j = 0; j < MCE_MAC_STATS_LEN; j++) {
		p = (char *)pf + mce_gstrings_mac_stats[j].stat_offset;
		data[i++] =
			(mce_gstrings_mac_stats[j].sizeof_stat == sizeof(u64)) ?
				*(u64 *)p :
				*(u32 *)p;
	}
#endif /* MCE_MAC_STATS_EN */

	/* populate per queue stats */
	rcu_read_lock();

	mce_for_each_txq_new(vsi, j) {
		if (!vsi->tx_rings[j])
			continue;
		if (!vsi->tx_rings[j]->q_vector)
			continue;
		tx_ring = READ_ONCE(vsi->tx_rings[j]);
		if (tx_ring && tx_ring->ring_stats) {
			for (k = 0; k < MCE_TXQ_STATS_LEN; k++) {
				p = (char *)(tx_ring->ring_stats) +
				    mce_gstrings_txq_stats[k].stat_offset;
				data[i++] =
					(mce_gstrings_txq_stats[k].sizeof_stat ==
					 sizeof(u64)) ?
						*(u64 *)p :
						*(u32 *)p;
			}
		} else {
			for (k = 0; k < MCE_TXQ_STATS_LEN; k++)
				data[i++] = 0;
		}
	}

	mce_for_each_rxq_new(vsi, j) {
		if (!vsi->rx_rings[j]->q_vector)
			continue;
		rx_ring = READ_ONCE(vsi->rx_rings[j]);
		if (rx_ring && rx_ring->ring_stats) {
			for (k = 0; k < MCE_RXQ_STATS_LEN; k++) {
				p = (char *)(rx_ring->ring_stats) +
				    mce_gstrings_rxq_stats[k].stat_offset;
				data[i++] =
					(mce_gstrings_rxq_stats[k].sizeof_stat ==
					 sizeof(u64)) ?
						*(u64 *)p :
						*(u32 *)p;
			}
		} else {
			for (k = 0; k < MCE_RXQ_STATS_LEN; k++)
				data[i++] = 0;
		}
	}

	rcu_read_unlock();
}

/**
 * mce_get_priv_flags - report device private flags
 * @netdev: network interface device structure
 *
 * The get string set count and the string set should be matched for each
 * flag returned. Add new strings for each flag to the mce_gstrings_priv_flags
 * array.
 * ethtool --show-private ethX
 *
 * Returns: a u32 bitmap of flags.
 */
static u32 mce_get_priv_flags(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &pf->hw;
	u32 i, ret_flags = 0;

	hw->ops->update_fw_stat(hw);
	if (hw->fw_stat.stat0.force_link_status == FOCE_LINK_SETTED)
		set_bit(MCE_FLAG_FORCE_LINK_ENA, pf->flags);
	else
		clear_bit(MCE_FLAG_FORCE_LINK_ENA, pf->flags);
	if (hw->fw_stat.stat0.lldp_tx_en)
		set_bit(MCE_FLAG_LLDP_TX_EN, pf->flags);
	else
		clear_bit(MCE_FLAG_LLDP_TX_EN, pf->flags);

	for (i = 0; i < MCE_PRIV_FLAG_ARRAY_SIZE; i++) {
		const struct mce_priv_flag *priv_flag;

		priv_flag = &mce_gstrings_priv_flags[i];

		if (test_bit(priv_flag->bitno, pf->flags))
			ret_flags |= BIT(i);
	}

	return ret_flags;
}

/**
 * mce_set_priv_flags - set private flags
 * @netdev: network interface device structure
 * @flags: bit flags to be set
 *
 * ethtool --set-private ethX <x>  <v>
 * Returns: The result of the operation.
 */
static int mce_set_priv_flags(struct net_device *netdev, u32 flags)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &pf->hw;
	DECLARE_BITMAP(orig_flags, MCE_PF_FLAGS_NBITS);
	DECLARE_BITMAP(change_flags, MCE_PF_FLAGS_NBITS);
	bool on;
	u32 i;

	if (flags > BIT(MCE_PRIV_FLAG_ARRAY_SIZE))
		return -EINVAL;

	bitmap_copy(orig_flags, pf->flags, MCE_PF_FLAGS_NBITS);

	/* set new priv to pf->flags */
	for (i = 0; i < MCE_PRIV_FLAG_ARRAY_SIZE; i++) {
		const struct mce_priv_flag *priv_flag;

		priv_flag = &mce_gstrings_priv_flags[i];

		if (flags & BIT(i))
			set_bit(priv_flag->bitno, pf->flags);
		else
			clear_bit(priv_flag->bitno, pf->flags);
	}
	bitmap_xor(change_flags, pf->flags, orig_flags, MCE_PF_FLAGS_NBITS);

	if (test_bit(MCE_FLAG_VF_TRUE_PROMISC_ENA, change_flags)) {
		on = !!test_bit(MCE_FLAG_VF_TRUE_PROMISC_ENA, pf->flags);
		if (on)
			mce_vf_setup_true_promisc(pf);
		else
			mce_vf_del_true_promisc(pf);
	}

	if (test_bit(MCE_FLAG_FORCE_LINK_ENA, change_flags)) {
		on = !!test_bit(MCE_FLAG_FORCE_LINK_ENA, pf->flags);
		if (on)
			mce_mbx_set_force_link_on_close(hw, true);
		else
			mce_mbx_set_force_link_on_close(hw, false);
	}

	if (test_bit(MCE_FLAG_VF_RQA_TCPSYNC_ENA, change_flags)) {
		on = !!test_bit(MCE_FLAG_VF_RQA_TCPSYNC_ENA, pf->flags);
		mce_vf_setup_rqa_tcp_sync_en(pf, on);
	}

	if (test_bit(MCE_FLAG_HW_DIM_ENA, change_flags)) {
		on = !!test_bit(MCE_FLAG_HW_DIM_ENA, pf->flags);
		/* if hw on, must close sw_dim */
		if (on)
			clear_bit(MCE_FLAG_SW_DIM_ENA, pf->flags);

		mce_for_each_txq_new(vsi, i) {
			struct mce_ring *txring;

			if (!vsi->tx_rings[i])
				continue;
			txring = vsi->tx_rings[i];
			if (!txring->q_vector)
				continue;
			hw->ops->set_txring_hw_dim(txring, on);
			if (on) {
				txring->q_vector->tx.dim_params.mode =
					ITR_HW_DYNAMIC;
			} else {
				if (test_bit(MCE_FLAG_SW_DIM_ENA, pf->flags))
					txring->q_vector->tx.dim_params.mode =
						ITR_SW_DYNAMIC;
				else
					txring->q_vector->tx.dim_params.mode =
						ITR_STATIC;
			}
		}
		mce_for_each_rxq_new(vsi, i) {
			struct mce_ring *rxring = vsi->rx_rings[i];

			if (!rxring->q_vector)
				continue;
			hw->ops->set_rxring_hw_dim(rxring, on);
			if (on) {
				rxring->q_vector->rx.dim_params.mode =
					ITR_HW_DYNAMIC;
			} else {
				if (test_bit(MCE_FLAG_SW_DIM_ENA, pf->flags))
					rxring->q_vector->rx.dim_params.mode =
						ITR_SW_DYNAMIC;
				else
					rxring->q_vector->rx.dim_params.mode =
						ITR_STATIC;
			}
		}
	}

	if (test_bit(MCE_FLAG_SW_DIM_ENA, change_flags)) {
		bool on_hw;

		on = !!test_bit(MCE_FLAG_SW_DIM_ENA, pf->flags);

		/* if sw_dim on, force close hw_dim */
		if (on)
			clear_bit(MCE_FLAG_HW_DIM_ENA, pf->flags);

		on_hw = !!test_bit(MCE_FLAG_HW_DIM_ENA, pf->flags);

		mce_for_each_txq_new(vsi, i) {
			struct mce_ring *txring = vsi->tx_rings[i];

			if (!txring->q_vector)
				continue;

			hw->ops->set_txring_hw_dim(txring, on_hw);

			if (on)
				txring->q_vector->tx.dim_params.mode =
					ITR_SW_DYNAMIC;
			else
				txring->q_vector->tx.dim_params.mode =
					ITR_STATIC;
		}

		mce_for_each_rxq_new(vsi, i) {
			struct mce_ring *rxring = vsi->rx_rings[i];

			if (!rxring->q_vector)
				continue;
			hw->ops->set_rxring_hw_dim(rxring, on_hw);
			if (on)
				rxring->q_vector->rx.dim_params.mode =
					ITR_SW_DYNAMIC;
			else
				rxring->q_vector->rx.dim_params.mode =
					ITR_STATIC;
		}
	}

	if (test_bit(MCE_FLAG_DSCP_ENA, change_flags)) {
		struct iidc_event *event;

		on = !!test_bit(MCE_FLAG_DSCP_ENA, pf->flags);
		if (on) {
			set_bit(MCE_DSCP_EN, pf->dcb->flags);
			mce_set_vf_dscp(netdev, true);
			/* echo all vf status */
		} else {
			clear_bit(MCE_DSCP_EN, pf->dcb->flags);
			mce_set_vf_dscp(netdev, false);
			/* echo all vf status */
		}
		/* if change mode should echo to mrdma? */

		hw->ops->set_dscp(hw, pf->dcb);
		event = kzalloc(sizeof(*event), GFP_KERNEL);
		set_bit(IIDC_EVENT_PRIO_MODE_CHNG, event->type);
		mce_send_event_to_auxs(pf, event);
		kfree(event);
	}

	if (test_bit(MCE_FLAG_CAPTURE_RDMA_ENA, change_flags)) {
		on = !!test_bit(MCE_FLAG_CAPTURE_RDMA_ENA, pf->flags);

		/* sriov confict */
		if (on && test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
			netdev_info(netdev, "cannot capture rdma with sriov on\n");
			on = false;
			clear_bit(MCE_FLAG_CAPTURE_RDMA_ENA, pf->flags);
		}
		if (on)
			hw->ops->set_capture_rdma(hw, true);
		else
			hw->ops->set_capture_rdma(hw, false);
	}

	if (test_bit(MCE_FLAG_DDP_EXTRA_ENA, change_flags)) {
		on = !!test_bit(MCE_FLAG_DDP_EXTRA_ENA, pf->flags);
		hw->ops->set_ddp_extra_en(hw, on);
	}

	if (test_bit(MCE_FLAG_LLDP_TX_EN, change_flags)) {
		on = !!test_bit(MCE_FLAG_LLDP_TX_EN, pf->flags);
		if (hw->ops->set_lldp_tx_en(hw, on))
			return -EIO;
	}

	if (test_bit(MCE_FLAG_EVB_VEPA_ENA, change_flags)) {
		on = !!test_bit(MCE_FLAG_EVB_VEPA_ENA, pf->flags);
		if (mce_vf_set_evb_vepa_mode(hw, on)) {
			if (on) {
				clear_bit(MCE_FLAG_EVB_VEPA_ENA, pf->flags);
				netdev_warn(netdev,
					    "Failed to turn on EVB VEPA mode!\n");
			} else {
				set_bit(MCE_FLAG_EVB_VEPA_ENA, pf->flags);
				netdev_warn(netdev,
					    "Failed to turn off EVB VEPA mode!\n");
			}
		}
	}

	if (test_bit(MCE_FLAG_PF_ANTISPOOF, change_flags)) {
		on = !!test_bit(MCE_FLAG_PF_ANTISPOOF, pf->flags);

		if (!on && test_bit(MCE_FLAG_EVB_VEPA_ENA, pf->flags)) {
			set_bit(MCE_FLAG_PF_ANTISPOOF, pf->flags);
			on = true;
			netdev_warn(netdev,
				    "Cannot turn off pf anti-spoof in evb vepa mode!\n");
		}

		if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
			if (on) {
				hw->vf.ops->set_vf_spoofchk_mac(hw, PFINFO_IDX,
								true, true);
			} else {
				hw->vf.ops->set_vf_spoofchk_mac(hw, PFINFO_IDX,
								false, true);
			}
		}
	}
	if (test_bit(MCE_FLAG_PF_DCB_TOOLS, change_flags)) {
		struct mce_dcb *dcb = pf->dcb;

		on = !!test_bit(MCE_FLAG_PF_DCB_TOOLS, pf->flags);
		if (on)
			set_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
		else
			clear_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
	}

	if (test_bit(MCE_FLAG_PFC_RR_MODE, change_flags)) {
		on = !!test_bit(MCE_FLAG_PFC_RR_MODE, pf->flags);

		hw->ops->update_pfc_rr_mode(hw, on);
	}

	return 0;
}

/**
 * mce_get_rss_hash_opt - Retrieve hash fields for a given flow-type
 * @hw: the VSI being configured
 * @nfc: ethtool rxnfc command
 */
static void mce_get_rss_hash_opt(struct mce_hw *hw, struct ethtool_rxnfc *nfc)
{
	u32 hdrs = hw->rss_hash_type;
	bool on = false;

	nfc->data = 0;

	switch (nfc->flow_type) {
	case TCP_V4_FLOW:
		if (hdrs & MCE_F_HASH_IPV4_TCP)
			on = true;
		break;
	case UDP_V4_FLOW:
		if (hdrs & MCE_F_HASH_IPV4_UDP)
			on = true;
		break;
	case SCTP_V4_FLOW:
		if (hdrs & MCE_F_HASH_IPV4_SCTP)
			on = true;
		break;
	case TCP_V6_FLOW:
		if (hdrs & MCE_F_HASH_IPV6_TCP)
			on = true;
		break;
	case UDP_V6_FLOW:
		if (hdrs & MCE_F_HASH_IPV6_UDP)
			on = true;
		break;
	case SCTP_V6_FLOW:
		if (hdrs & MCE_F_HASH_IPV6_SCTP)
			on = true;
		break;
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case AH_ESP_V4_FLOW:
		if (hdrs & MCE_F_HASH_IPV4)
			break;
		return;
	case AH_V6_FLOW:
	case AH_ESP_V6_FLOW:
	case ESP_V6_FLOW:
		if (hdrs & MCE_F_HASH_IPV6)
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
 * mce_get_rxnfc - command to get Rx flow classification rules
 * @netdev: network interface device structure
 * @cmd: ethtool rxnfc command
 * @rule_locs: buffer to return Rx flow classification rules
 * ethtool --show-rxfh ethX
 *
 *
 * Returns: Success if the command is supported.
 */
static int mce_get_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd,
			 u32 __always_unused *rule_locs)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &vsi->back->hw;
	int ret = -EOPNOTSUPP;

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = vsi->num_rxq;
		ret = 0;
		break;
	case ETHTOOL_GRXCLSRLCNT:
		cmd->rule_cnt = hw->fdir_active_fltr;
		cmd->data = hw->func_caps.fd_fltr_guar;
		ret = 0;
		break;
	case ETHTOOL_GRXCLSRULE:
		ret = mce_get_ethtool_fdir_entry(hw, cmd);
		break;
	case ETHTOOL_GRXCLSRLALL:
		ret = mce_get_fdir_fltr_ids(hw, cmd, (u32 *)rule_locs);
		break;
	case ETHTOOL_GRXFH:
		mce_get_rss_hash_opt(hw, cmd);
		ret = 0;
		break;
	default:
		break;
	}

	return ret;
}

/**
 * mce_set_rss_hash_opt - Enable/Disable flow types for RSS hash
 * @vsi: the VSI being configured
 * @nfc: ethtool rxnfc command
 *
 * Returns: Success if the flow input set is supported.
 */
static int mce_set_rss_hash_opt(struct mce_vsi *vsi, struct ethtool_rxnfc *nfc)
{
	struct mce_hw *hw = &vsi->back->hw;
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
		hash_type |= MCE_F_HASH_IPV4_TCP;
		break;
	case UDP_V4_FLOW:
		hash_type |= MCE_F_HASH_IPV4_UDP;
		break;
	case SCTP_V4_FLOW:
		hash_type |= MCE_F_HASH_IPV4_SCTP;
		break;
	case TCP_V6_FLOW:
		hash_type |= MCE_F_HASH_IPV6_TCP;
		break;
	case UDP_V6_FLOW:
		hash_type |= MCE_F_HASH_IPV6_UDP;
		break;
	case SCTP_V6_FLOW:
		hash_type |= MCE_F_HASH_IPV6_SCTP;
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
 * mce_set_rxnfc - command to set Rx flow rules.
 * @netdev: network interface device structure
 * @cmd: ethtool rxnfc command
 *
 * Returns: 0 for success and negative values for errors
 */
static int mce_set_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &vsi->back->hw;

	switch (cmd->cmd) {
	case ETHTOOL_SRXCLSRLINS:
		if ((hw->hw_flags & MCE_F_NTUPLE))
			return mce_add_ntuple_ethtool(vsi, cmd);
		break;
	case ETHTOOL_SRXCLSRLDEL:
		if ((hw->hw_flags & MCE_F_NTUPLE))
			return mce_del_ntuple_ethtool(vsi, cmd);
		break;
	case ETHTOOL_SRXFH:
		return mce_set_rss_hash_opt(vsi, cmd);
	default:
		break;
	}
	return -EOPNOTSUPP;
}

/**
 * mce_get_rxfh_key_size - get the RSS hash key size
 * @netdev: network interface device structure
 * ethtool --show-rxfh  ethX
 *
 * Returns: the table size.
 */
static u32 mce_get_rxfh_key_size(struct net_device __always_unused *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &vsi->back->hw;

	return hw->func_caps.common_cap.rss_key_size;
}

/**
 * mce_get_rxfh_indir_size - get the Rx flow hash indirection table size
 * @netdev: network interface device structure
 *
 * Returns: the table size.
 */
static u32 mce_get_rxfh_indir_size(struct net_device *netdev)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);

	return pf->rss_tb_size;
}

static int mce_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key,
			u8 *hfunc)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &pf->hw;
	int i = 0;
	u8 *lut;

	if (hfunc)
		*hfunc = hw->rss_hfunc;

	if (!indir)
		return 0;

	lut = kzalloc(pf->rss_tb_size, GFP_KERNEL);
	if (!lut)
		return -ENOMEM;

	for (i = 0; i < pf->rss_tb_size; i++) {
		if (netdev->features & NETIF_F_RXHASH)
			indir[i] = (u32)(hw->rss_table[i]);
		else
			indir[i] = 0;
	}

	if (key) {
		memcpy(key, hw->rss_key,
		       (hw->func_caps.common_cap.rss_key_size));
	}
	kfree(lut);
	return 0;
}

static int mce_set_rxfh(struct net_device *netdev, const u32 *indir,
			const u8 *key, const u8 hfunc)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_hw *hw = &pf->hw;

	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != hw->rss_hfunc) {
		if (hfunc != ETH_RSS_HASH_TOP && hfunc != ETH_RSS_HASH_XOR)
			return -EOPNOTSUPP;
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

		for (i = 0; i < pf->rss_tb_size; i++)
			hw->rss_table[i] = (u16)(indir[i]);
		mce_set_rss_table(hw, PFINFO_IDX, vsi->num_rxq);
	}

	return 0;
}

/**
 * mce_get_combined_cnt - return the current number of combined channels
 * @vsi: PF VSI pointer
 *
 * Go through all queue vectors and count ones that have both Rx and Tx ring
 * attached
 * Returns: The result of the operation.
 */
static u32 mce_get_combined_cnt(struct mce_vsi *vsi)
{
	return vsi->num_txq_real;
}

static int mce_get_max_queue_msix_cnt(struct mce_pf *pf)
{
	return pf->num_msix_cnt - pf->num_mbox_irqs - pf->num_rdma_irqs;
}

/**
 * mce_get_channels - get the current and max supported channels
 * @dev: network interface device structure
 * @ch: ethtool channel data structure
 *
 * ethtool -l ethX
 */
static void mce_get_channels(struct net_device *dev,
			     struct ethtool_channels *ch)
{
	struct mce_netdev_priv *np = netdev_priv(dev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &pf->hw;

	/* report maximum channels */
	ch->max_rx = pf->max_pf_rxqs / pf->num_max_tc;
	ch->max_tx = pf->max_pf_txqs / pf->num_max_tc;

	ch->max_tx = mce_get_max_queue_msix_cnt(pf);
	ch->max_rx = ch->max_tx;
	ch->max_combined = min_t(int, ch->max_rx, ch->max_tx);

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		ch->max_combined =
			min_t(int, ch->max_combined, hw->vf_max_ring);
	ch->max_rx = 0;
	ch->max_tx = 0;

	/* report current channels */
	ch->combined_count = mce_get_combined_cnt(vsi);
	ch->rx_count = 0;
	ch->tx_count = 0;

	/* report other queues */
	ch->other_count = pf->num_mbox_irqs;
	ch->max_other = ch->other_count;
}

/**
 * mce_set_channels - set the number channels
 * @dev: network interface device structure
 * @ch: ethtool channel data structure
 * ethtool -L ethX
 * Returns: The result of the operation.
 */
static int mce_set_channels(struct net_device *dev, struct ethtool_channels *ch)
{
	struct mce_netdev_priv *np = netdev_priv(dev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	struct mce_hw *hw = &pf->hw;
	int new_rx = 0, new_tx = 0;
	bool old_ets = false;
	bool old_pfc = false;
	u32 curr_combined;
	int dcb_tool = 0;

	if (pf->hw.fdir_active_fltr) {
		netdev_err(dev, "Cannot set channels when etype or ntuple filters are active\n");
		return -EOPNOTSUPP;
	}

	if (mce_has_arfs_active_fltrs(pf)) {
		netdev_err(dev, "Cannot set channels when aRFS filters are active\n");
		return -EOPNOTSUPP;
	}

	if (test_bit(MCE_FLAG_PF_RQA_TCPSYNC_ENA, pf->flags)) {
		netdev_err(dev,
			   "Cannot set channels when tcpsync filters are active\n");
		return -EOPNOTSUPP;
	}

	if (test_and_clear_bit(MCE_MQPRIO_CHANNEL, pf->dcb->flags)) {
		pf->hw.ops->disable_tc(&pf->hw);
		pf->hw.ops->clr_q_to_tc(&pf->hw);
	}

	curr_combined = mce_get_combined_cnt(vsi);

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
		netdev_err(dev,
			   "Please specify at least 1 Rx and 1 Tx channel\n");
		return -EINVAL;
	}

	new_rx = ch->combined_count + ch->rx_count;
	new_tx = ch->combined_count + ch->tx_count;

	if (new_rx > pf->max_pf_rxqs) {
		netdev_err(dev, "Maximum allowed Rx channels is %d\n",
			   pf->max_pf_rxqs);
		return -EINVAL;
	}
	if (new_tx > pf->max_pf_txqs) {
		netdev_err(dev, "Maximum allowed Tx channels is %d\n",
			   pf->max_pf_txqs);
		return -EINVAL;
	}

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		if (new_rx > hw->vf_max_ring || new_tx > hw->vf_max_ring) {
			netdev_err(dev,
				   "Maximum allowed Tx channels is %d wthen turn sriov\n",
				hw->vf_max_ring);
			return -EINVAL;
		}
	}

	if (netif_running(dev)) {
		/* if channels change, we should close ets and pfc in default */
		if (test_bit(MCE_ETS_EN, pf->dcb->flags))
			old_ets = true;

		if (test_bit(MCE_PFC_EN, pf->dcb->flags))
			old_pfc = true;

		clear_bit(MCE_ETS_EN, pf->dcb->flags);
		clear_bit(MCE_PFC_EN, pf->dcb->flags);
		/* clean it */
		/* todo */
		mce_dcb_tc_default(&dcb->cur_tccfg);
		mce_dcb_tc_default(&dcb->new_tccfg);
		mce_dcb_ets_default(&dcb->cur_etscfg);
		mce_dcb_ets_default(&dcb->new_etscfg);
		mce_dcb_pfc_default(&dcb->cur_pfccfg);
		mce_dcb_pfc_default(&dcb->new_pfccfg);
		/* set default */
		/* clean hw setup */
		mce_dcb_update_hwpfccfg(pf->dcb);
		mce_dcb_update_hwetscfg(pf->dcb);
	}
	set_bit(MCE_FLAG_USR_CHANGE_QNUM_ENA, pf->flags);
	mce_vsi_recfg_qs(vsi, new_rx, new_tx);

#ifdef CONFIG_DCB
	if (netif_running(dev)) {
		if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags)) {
			dcb_tool = 1;
			/* temp close it */
			clear_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
		}

		/* restore ets and pfc setup */
		if (old_ets)
			dev->dcbnl_ops->ieee_setets(dev, &dcb->ets_os);

		if (old_pfc)
			dev->dcbnl_ops->ieee_setpfc(dev, &dcb->pfc_os);
		if (dcb_tool)
			set_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
	}
#endif
	return 0;
}

static void mce_get_ringparam(struct net_device *netdev,
			      struct ethtool_ringparam *ring,
			      struct kernel_ethtool_ringparam __always_unused *kernel_ring,
			      struct netlink_ext_ack __always_unused *extack)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	/* ethtool -g ethX */

	ring->rx_max_pending = MCE_MAX_NUM_DESC;
	ring->tx_max_pending = MCE_MAX_NUM_DESC;
	ring->rx_pending = vsi->num_rx_desc;
	ring->tx_pending = vsi->num_tx_desc;

	/* Rx mini and jumbo rings are not supported */
	ring->rx_mini_max_pending = 0;
	ring->rx_jumbo_max_pending = 0;
	ring->rx_mini_pending = 0;
	ring->rx_jumbo_pending = 0;
}

static int mce_set_ringparam(struct net_device *netdev,
			     struct ethtool_ringparam *ring,
			     struct kernel_ethtool_ringparam __always_unused *kernel_ring,
			     struct netlink_ext_ack __always_unused *extack)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_ring *tx_rings = NULL;
	struct mce_ring *rx_rings = NULL;
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	int i, timeout = 50, err = 0;
	u16 new_rx_cnt, new_tx_cnt;
	/* ethtool -G eth2 rx 512  tx 512 */

	if (ring->tx_pending > MCE_MAX_NUM_DESC ||
	    ring->tx_pending < MCE_MIN_NUM_DESC ||
	    ring->rx_pending > MCE_MAX_NUM_DESC ||
	    ring->rx_pending < MCE_MIN_NUM_DESC) {
		netdev_err(netdev,
			   "Descriptors requested (Tx: %d / Rx: %d) out of range [%d-%d] (increment %d)\n",
			ring->tx_pending, ring->rx_pending, MCE_MIN_NUM_DESC,
			MCE_MAX_NUM_DESC, MCE_REQ_DESC_MULTIPLE);
		return -EINVAL;
	}

	new_tx_cnt = ALIGN(ring->tx_pending, MCE_REQ_DESC_MULTIPLE);
	if (new_tx_cnt != ring->tx_pending)
		netdev_info(netdev,
			    "Requested Tx descriptor count rounded up to %d\n",
			    new_tx_cnt);
	new_rx_cnt = ALIGN(ring->rx_pending, MCE_REQ_DESC_MULTIPLE);
	if (new_rx_cnt != ring->rx_pending)
		netdev_info(netdev,
			    "Requested Rx descriptor count rounded up to %d\n",
			    new_rx_cnt);

	/* if nothing to do return success */
	if (new_tx_cnt == vsi->num_tx_desc && new_rx_cnt == vsi->num_rx_desc) {
		netdev_dbg(netdev,
			   "Nothing to change, descriptor count is same as requested\n");
		return 0;
	}

	while (test_and_set_bit(MCE_CFG_BUSY, pf->state)) {
		timeout--;
		if (!timeout)
			return -EBUSY;
		usleep_range(1000, 2000);
	}

	/* set for the next time the netdev is started */
	if (!netif_running(vsi->netdev)) {
		mce_for_each_txq_new(vsi, i) {
			if (!vsi->tx_rings[i])
				continue;
			if (!vsi->tx_rings[i]->q_vector)
				continue;
			vsi->tx_rings[i]->count = new_tx_cnt;
		}
		mce_for_each_rxq_new(vsi, i) {
			if (!vsi->rx_rings[i]->q_vector)
				continue;
			vsi->rx_rings[i]->count = new_rx_cnt;
		}

		vsi->num_tx_desc = (u16)new_tx_cnt;
		vsi->num_rx_desc = (u16)new_rx_cnt;
		netdev_dbg(netdev,
			   "Link is down, descriptor count change happens when link is brought up\n");
		goto done;
	}

	if (new_tx_cnt == vsi->num_tx_desc)
		goto process_rx;

	/* alloc updated Tx resources */
	netdev_info(netdev, "Changing Tx descriptor count from %d to %d\n",
		    vsi->num_tx_desc, new_tx_cnt);

	tx_rings = kcalloc(vsi->alloc_txq, sizeof(*tx_rings), GFP_KERNEL);
	if (!tx_rings) {
		err = -ENOMEM;
		goto done;
	}

	mce_for_each_txq_new(vsi, i) {
		if (!vsi->tx_rings[i])
			continue;
		if (!vsi->tx_rings[i]->q_vector)
			continue;
		/* clone ring and setup updated count */
		tx_rings[i] = *vsi->tx_rings[i];
		tx_rings[i].count = new_tx_cnt;
		tx_rings[i].desc = NULL;
		tx_rings[i].tx_buf = NULL;
		err = mce_setup_tx_ring(&tx_rings[i]);
		if (err) {
			while (i--)
				mce_clean_tx_ring(&tx_rings[i]);
			kfree(tx_rings);
			tx_rings = NULL;
			goto done;
		}
	}

process_rx:
	if (new_rx_cnt == vsi->num_rx_desc)
		goto process_link;

	/* alloc updated Rx resources */
	netdev_info(netdev, "Changing Rx descriptor count from %d to %d\n",
		    vsi->num_rx_desc, new_rx_cnt);

	rx_rings = kcalloc(vsi->alloc_rxq, sizeof(*rx_rings), GFP_KERNEL);
	if (!rx_rings) {
		err = -ENOMEM;
		goto done;
	}

	mce_for_each_rxq_new(vsi, i) {
		if (!vsi->rx_rings[i]->q_vector)
			continue;
		/* clone ring and setup updated count */
		rx_rings[i] = *vsi->rx_rings[i];
		rx_rings[i].count = new_rx_cnt;
		rx_rings[i].desc = NULL;
		rx_rings[i].rx_buf = NULL;
		err = mce_setup_rx_ring(&rx_rings[i]);
		if (err) {
			while (i) {
				i--;
				mce_free_rx_ring(&rx_rings[i]);
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
	if (!test_and_set_bit(MCE_VSI_DOWN, vsi->state)) {
		mce_down(vsi);

		if (tx_rings) {
			mce_for_each_txq_new(vsi, i) {
				if (!vsi->tx_rings[i])
					continue;
				if (!vsi->tx_rings[i]->q_vector)
					continue;
				mce_free_tx_ring(vsi->tx_rings[i]);
				*vsi->tx_rings[i] = tx_rings[i];
			}
			kfree(tx_rings);
			tx_rings = NULL;
		}

		if (rx_rings) {
			mce_for_each_rxq_new(vsi, i) {
				if (!vsi->rx_rings[i]->q_vector)
					continue;
				mce_free_rx_ring(vsi->rx_rings[i]);
				*vsi->rx_rings[i] = rx_rings[i];
			}
			kfree(rx_rings);
			rx_rings = NULL;
		}

		vsi->num_tx_desc = new_tx_cnt;
		vsi->num_rx_desc = new_rx_cnt;
		mce_up(vsi);
	}
	goto done;

free_tx:
	/* error cleanup if the Rx allocations failed after getting Tx */
	if (tx_rings) {
		mce_for_each_txq_new(vsi, i) {
			if (!vsi->tx_rings[i])
				continue;
			if (!vsi->tx_rings[i]->q_vector)
				continue;
			mce_free_tx_ring(&tx_rings[i]);
		}
	}

done:
	kfree(rx_rings);
	kfree(tx_rings);
	clear_bit(MCE_CFG_BUSY, pf->state);
	return err;
}

/* ethtool ethX */
static u32 mce_get_msglevel(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_pf *pf = np->vsi->back;

	return pf->msg_enable;
}

/**
 * ethtool -s ethX msglvl xx
 * ethtool -s ethX msglvl <type> on|off
 * ethtool -s eth2 msglvl probe off
 * @netdev: network interface device structure
 * @data: new message level
 */
static void mce_set_msglevel(struct net_device *netdev, u32 data)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_pf *pf = np->vsi->back;

	pf->msg_enable = data;
}

/**
 * mce_get_pauseparam - Get Flow Control status
 * @netdev: network interface device structure
 * @pause: ethernet pause (flow control) parameters
 *
 * Get autonegotiated flow control status from link status.
 * ethtool -a ethX
 */
static void mce_get_pauseparam(struct net_device *netdev,
			       struct ethtool_pauseparam *pause)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = (struct mce_pf *)(vsi->back);
	struct mce_flow_control *fc = &pf->fc;

	pause->rx_pause = 0;
	pause->tx_pause = 0;

	pause->autoneg = ((fc->auto_pause == MCE_PAUSE_EN) ? AUTONEG_ENABLE :
							     AUTONEG_DISABLE);

	/* PFC enabled so report LFC as off */

	/* Get flow control status based on autonegotiation */
	switch (fc->current_mode) {
	case MCE_FC_TX_PAUSE:
		pause->tx_pause = 1;
		break;
	case MCE_FC_RX_PAUSE:
		pause->rx_pause = 1;
		break;
	case MCE_FC_FULL:
		pause->tx_pause = 1;
		pause->rx_pause = 1;
		break;
	default:
		break;
	}
}

static int mce_get_eeprom_len(struct net_device *netdev)
{
	return EEPROM_MAX_SIZE;
}

/* ethtool -e ethX
 * ethtool -e eth2 offset 0   length 16
 */
static int mce_get_eeprom(struct net_device *netdev,
			  struct ethtool_eeprom *eeprom, u8 *data)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	int offset = eeprom->offset, len = eeprom->len;
	struct mce_hw *hw = &np->vsi->back->hw;

	if (offset >= EEPROM_MAX_SIZE || (offset + len) > EEPROM_MAX_SIZE)
		return -EINVAL;

	return mce_mbx_dump_eeprom(hw, offset, data, len);
}

/**
 * mce_set_pauseparam - Set Flow Control parameter
 * @netdev: network interface device structure
 * @pause: return Tx/Rx flow control status
 *
 * ethtool -A ethX rx on txon autoneg on
 * Returns: The result of the operation.
 */
static int mce_set_pauseparam(struct net_device *netdev,
			      struct ethtool_pauseparam *pause)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = (struct mce_pf *)(vsi->back);
	struct mce_flow_control *fc = &pf->fc;
	struct mce_hw *hw = &pf->hw;
	u32 is_an;

	/* Changing the port's flow control is not supported
	 * if this isn't thePF VSI
	 */
	if (vsi->type != MCE_VSI_PF) {
		netdev_info(netdev, "Changing flow control parameters only supported for PF VSI\n");
		return -EOPNOTSUPP;
	}

	if (test_bit(MCE_PFC_EN, pf->dcb->flags)) {
		netdev_info(netdev, "The NIC is currently in PFC mode. The pause change cannot take effect\n");
		return -EOPNOTSUPP;
	}

	is_an = ((fc->auto_pause == MCE_PAUSE_EN) ? AUTONEG_ENABLE :
						    AUTONEG_DISABLE);

	if (pause->autoneg != is_an) {
		netdev_info(netdev, "Sorry, We do not yet support autoneg\n");
		return -EOPNOTSUPP;
	}

	/* If we have link and don't have autoneg */
	if (!test_bit(MCE_DOWN, pf->state)) {
		/* Send message that it might not necessarily work*/
		netdev_info(netdev, "Autoneg did not complete so changing "
				    "settings may not result in an actual "
				    "change.\n");
	}

	/* PFC enabled so report LFC as off */

	if (pause->rx_pause && pause->tx_pause)
		fc->req_mode = MCE_FC_FULL;
	else if (pause->rx_pause && !pause->tx_pause)
		fc->req_mode = MCE_FC_RX_PAUSE;
	else if (!pause->rx_pause && pause->tx_pause)
		fc->req_mode = MCE_FC_TX_PAUSE;
	else if (!pause->rx_pause && !pause->tx_pause)
		fc->req_mode = MCE_FC_NONE;
	else
		return -EINVAL;

	if (fc->current_mode != fc->req_mode)
		hw->ops->set_pause_en_only(hw);

	return 0;
}

/* ethtool --show-fec  ethX */
static int mce_get_fecparam(struct net_device *netdev,
			    struct ethtool_fecparam *fecparam)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_hw *hw = &np->vsi->back->hw;
	int active_fec, configed_fec;

	hw->ops->update_fw_stat(hw);

	active_fec = hw->fw_stat.stat0.active_fec;
	configed_fec = hw->fw_stat.stat0.configed_fec;

	hw_logd(LOG_FEC, "configed_fec:%d active_fec:%d\n", configed_fec,
		active_fec);

	if (hw->fw_stat.stat0.is_sgmii) {
		fecparam->fec = ETHTOOL_FEC_OFF;
		fecparam->active_fec = ETHTOOL_FEC_OFF;
		return 0;
	}

	if (active_fec == ST_FEC_BASER)
		fecparam->active_fec = ETHTOOL_FEC_BASER;
	else if (active_fec == ST_FEC_RS)
		fecparam->active_fec = ETHTOOL_FEC_RS;
	else if (active_fec == ST_FEC_AUTO)
		fecparam->active_fec = ETHTOOL_FEC_AUTO;
	else
		fecparam->active_fec = ETHTOOL_FEC_OFF;

	if (hw->fw_stat.stat0.configed_fec == ST_FEC_BASER)
		fecparam->fec = ETHTOOL_FEC_BASER;
	else if (hw->fw_stat.stat0.configed_fec == ST_FEC_RS)
		fecparam->fec = ETHTOOL_FEC_RS;
	else if (hw->fw_stat.stat0.configed_fec == ST_FEC_AUTO)
		fecparam->fec = ETHTOOL_FEC_AUTO;
	else
		fecparam->fec = ETHTOOL_FEC_OFF;
	if (hw->fw_stat.stat0.sfp_mod_abs == 0) {
		/* no sfp plugin */
		fecparam->fec = ETHTOOL_FEC_AUTO | ETHTOOL_FEC_RS |
				ETHTOOL_FEC_BASER;
	}
	return 0;
}

static int mce_set_fecparam(struct net_device *netdev,
			    struct ethtool_fecparam *fecparam)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_hw *hw = &np->vsi->back->hw;

	if (fecparam->fec & ETHTOOL_FEC_OFF)
		return mce_mbx_set_fec(hw, FEC_NONE);
	else if (fecparam->fec & ETHTOOL_FEC_RS)
		return mce_mbx_set_fec(hw, FEC_RS);
	else if (fecparam->fec & ETHTOOL_FEC_BASER)
		return mce_mbx_set_fec(hw, FEC_BASER);
	else if (fecparam->fec & ETHTOOL_FEC_AUTO)
		return mce_mbx_set_fec(hw, FEC_AUTO);
	return -EINVAL;
}

static int mce_get_eee(struct net_device *netdev, struct ethtool_eee *edata)
{
	return -EOPNOTSUPP;
}

static int mce_set_eee(struct net_device *netdev, struct ethtool_eee *edata)
{
	return -EOPNOTSUPP;
}

/* ethtool --get-dump ethX */
__maybe_unused static int mce_get_dump_flag(struct net_device *netdev,
					    struct ethtool_dump *dump)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_hw *hw = &np->vsi->back->hw;
	int ret;

	ret = mce_mbx_get_dump(hw, 0, NULL, 0, &dump->flag, &dump->version);
	if (ret < 0) {
		netdev_err(netdev, "%s: ret:%d\n", __func__, ret);
		return -EIO;
	}
	dump->len = ret;
	return 0;
}

/* ethtool --get-dump ethX data a.log */
__maybe_unused static int mce_get_dump_data(struct net_device *netdev,
					    struct ethtool_dump *dump,
					    void *buffer)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_hw *hw = &np->vsi->back->hw;
	int ret;

	ret = mce_mbx_get_dump(hw, dump->flag, buffer, dump->len, &dump->flag,
			       &dump->version);
	if (ret < 0)
		return ret;
	dump->len = ret;

	return 0;
}

/* ethtool --set-dump ethX  0x01000000 */
__maybe_unused static int mce_set_dump(struct net_device *netdev,
				       struct ethtool_dump *dump)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_hw *hw = &np->vsi->back->hw;

	mce_mbx_set_dump(hw, dump->flag);
	return 0;
}

static int mce_get_coalesce(struct net_device *netdev,
			    struct ethtool_coalesce *ec,
			    struct kernel_ethtool_coalesce __always_unused *kernel_coal,
			    struct netlink_ext_ack __always_unused *extack)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_ring_container *rx = &vsi->q_vectors[0]->rx;
	struct mce_ring_container *tx = &vsi->q_vectors[0]->tx;
	struct mce_ring_container *rc;
	/* ethtool -C ethX */

	if (rx->dim_params.mode == ITR_STATIC) {
		ec->use_adaptive_rx_coalesce = ITR_STATIC;
		ec->rx_coalesce_usecs = rx->dim_params.usecs;
		ec->rx_max_coalesced_frames = rx->dim_params.frames;
	} else {
		/* if dynamic return low and high */
		ec->use_adaptive_rx_coalesce = ITR_DYNAMIC;
		rc = &vsi->q_vectors[0]->rx;
		if (rc->dim.mode == DIM_CQ_PERIOD_MODE_START_FROM_EQE) {
			ec->rx_coalesce_usecs_low = 1;
			ec->rx_coalesce_usecs_high = 256;
			ec->rx_max_coalesced_frames_low = 256;
			ec->rx_max_coalesced_frames_high = 256;
		} else {
			ec->rx_coalesce_usecs_low = 2;
			ec->rx_coalesce_usecs_high = 64;
			ec->rx_max_coalesced_frames_low = 64;
			ec->rx_max_coalesced_frames_high = 256;
		}
	}

	if (tx->dim_params.mode == ITR_STATIC) {
		ec->use_adaptive_tx_coalesce = ITR_STATIC;
		ec->tx_coalesce_usecs = tx->dim_params.usecs;
		ec->tx_max_coalesced_frames = tx->dim_params.frames;
	} else {
		ec->use_adaptive_tx_coalesce = ITR_DYNAMIC;
		rc = &vsi->q_vectors[0]->tx;
		/* fixed number not good */
		if (rc->dim.mode == DIM_CQ_PERIOD_MODE_START_FROM_EQE) {
			ec->tx_coalesce_usecs_low = 1;
			ec->tx_coalesce_usecs_high = 128;
			ec->tx_max_coalesced_frames_low = 128;
			ec->tx_max_coalesced_frames_high = 128;
		} else {
			ec->tx_coalesce_usecs_low = 5;
			ec->tx_coalesce_usecs_high = 64;
			ec->tx_max_coalesced_frames_low = 32;
			ec->tx_max_coalesced_frames_high = 128;
		}
	}

	return 0;
}

static int mce_set_coalesce(struct net_device *netdev,
			    struct ethtool_coalesce *ec,
			    struct kernel_ethtool_coalesce __always_unused *kernel_coal,
			    struct netlink_ext_ack __always_unused *extack)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	u32 tx_usecs = 0, tx_frames = 0;
	u32 rx_usecs = 0, rx_frames = 0;
	struct mce_vsi *vsi = np->vsi;
	struct mce_q_vector *q_vector = vsi->q_vectors[0];
	struct mce_pf *pf = (struct mce_pf *)(vsi->back);
	struct mce_hw_operations *hw_ops = pf->hw.ops;
	struct mce_ring *ring;
	int i = 0;
	u32 value;

	if (test_bit(MCE_FLAG_HW_DIM_ENA, pf->flags)) {
		netdev_info(netdev,
			    "Invalid value, because hw dim is enabled\n");
		return -EINVAL;
	}

	if (q_vector->rx.dim_params.mode == ITR_SW_DYNAMIC) {
		if (ec->rx_max_coalesced_frames_irq ||
		    ec->rx_max_coalesced_frames ||
		    ec->rx_coalesce_usecs)
			return -EINVAL;
	} else {
	}

	if (q_vector->tx.dim_params.mode == ITR_SW_DYNAMIC) {
		if (ec->tx_max_coalesced_frames_irq ||
		    ec->tx_max_coalesced_frames ||
		    ec->tx_coalesce_usecs)
			return -EINVAL;
	} else {
	}

	if (ec->tx_coalesce_usecs < MCE_MAX_INTR_TIME &&
	    ec->tx_coalesce_usecs > 0) {
		tx_usecs = ec->tx_coalesce_usecs;
	} else {
		value = clamp_t(u32, ec->tx_coalesce_usecs, 1,
				MCE_MAX_INTR_TIME);
		tx_usecs = value;
	}

	if (ec->tx_max_coalesced_frames < MCE_MAX_INTR_PKTS &&
	    ec->tx_max_coalesced_frames > 0) {
		tx_frames = ec->tx_max_coalesced_frames;
	} else {
		value = clamp_t(u32, ec->tx_max_coalesced_frames, 1,
				MCE_MAX_INTR_PKTS);
		tx_frames = value;
	}

	if (ec->rx_coalesce_usecs < MCE_MAX_INTR_TIME &&
	    ec->rx_coalesce_usecs > 0) {
		rx_usecs = ec->rx_coalesce_usecs;
	} else {
		value = clamp_t(u32, ec->rx_coalesce_usecs, 1,
				MCE_MAX_INTR_TIME);
		rx_usecs = value;
	}

	if (ec->rx_max_coalesced_frames < MCE_MAX_INTR_PKTS &&
	    ec->rx_max_coalesced_frames > 0) {
		rx_frames = ec->rx_max_coalesced_frames;
	} else {
		value = clamp_t(u32, ec->rx_max_coalesced_frames, 1,
				MCE_MAX_INTR_PKTS);
		rx_frames = value;
	}

	mce_for_each_q_vector(vsi, i) {
		q_vector = vsi->q_vectors[i];

		if (ec->use_adaptive_rx_coalesce) {
			q_vector->rx.dim_params.mode = ITR_SW_DYNAMIC;
		} else {
			q_vector->rx.dim_params.mode = ITR_STATIC;
			q_vector->rx.dim_params.frames = rx_frames;
			q_vector->rx.dim_params.usecs = rx_usecs;
			mce_rc_for_each_ring(ring, q_vector->rx) {
				hw_ops->set_rxring_intr_coal(ring);
			}
		}

		if (ec->use_adaptive_tx_coalesce) {
			q_vector->tx.dim_params.mode = ITR_SW_DYNAMIC;
		} else {
			q_vector->tx.dim_params.mode = ITR_STATIC;
			q_vector->tx.dim_params.frames = tx_frames;
			q_vector->tx.dim_params.usecs = tx_usecs;
			mce_rc_for_each_ring(ring, q_vector->tx) {
				hw_ops->set_txring_intr_coal(ring);
			}
		}
	}

	return 0;
}

static int mce_get_ts_info(struct net_device *dev, struct ethtool_ts_info *info)
{
	struct mce_netdev_priv *np = netdev_priv(dev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;

	if (!IS_REACHABLE(CONFIG_PTP_1588_CLOCK) ||
	    !(pf->flags2 & MCE_FLAG2_PTP_ENABLED))
		return ethtool_op_get_ts_info(dev, info);

#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
	info->phc_index = pf->ptp_clock ? ptp_clock_index(pf->ptp_clock) : -1;
	info->so_timestamping = SOF_TIMESTAMPING_TX_HARDWARE |
		SOF_TIMESTAMPING_RX_HARDWARE |
		SOF_TIMESTAMPING_RX_SOFTWARE |
		SOF_TIMESTAMPING_TX_SOFTWARE |
		SOF_TIMESTAMPING_SOFTWARE |
		SOF_TIMESTAMPING_RAW_HARDWARE;
	info->tx_types = BIT(HWTSTAMP_TX_OFF) | BIT(HWTSTAMP_TX_ON);
	info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) |
		BIT(HWTSTAMP_FILTER_PTP_V1_L4_EVENT) |
		BIT(HWTSTAMP_FILTER_PTP_V1_L4_SYNC) |
		BIT(HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ) |
		BIT(HWTSTAMP_FILTER_PTP_V2_L4_SYNC) |
		BIT(HWTSTAMP_FILTER_PTP_V2_L4_EVENT) |
		BIT(HWTSTAMP_FILTER_PTP_V2_L2_EVENT) |
		BIT(HWTSTAMP_FILTER_PTP_V2_L2_SYNC) |
		BIT(HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ) |
		BIT(HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ) |
		BIT(HWTSTAMP_FILTER_PTP_V2_EVENT) |
		BIT(HWTSTAMP_FILTER_PTP_V2_SYNC) |
		BIT(HWTSTAMP_FILTER_PTP_V2_DELAY_REQ) |
		BIT(HWTSTAMP_FILTER_NTP_ALL) |
		BIT(HWTSTAMP_FILTER_ALL);
#endif
	return 0;
}

int mce_flash_firmware(struct mce_pf *pf, enum REGION_IN region, const u8 *data,
		       int bytes)
{
	struct mce_hw *hw = &pf->hw;
	int fw_partition = 1;

	switch (region) {
	case PART_FW: {
		if (*((u32 *)(data + 0x1C)) != N20_FW_MAGIC)
			return -EINVAL;
		fw_partition = 1;
		break;
	}

	case PART_PXE: {
		if ((*((u16 *)(data)) != 0xaa55) &&
		    (*((u16 *)(data)) != 0x5a4d)) {
			return -EINVAL;
		}
		fw_partition = 3;
		break;
	}

	case PART_MACSN: {
		if (*((u32 *)(data)) != MAC_SN_MAGIC)
			return -EINVAL;
		fw_partition = 4;
		break;
	}
	default: {
		return -EINVAL;
	}
	}
	return mce_fw_update_firmware(hw, fw_partition, data, bytes);
}

static int mce_flash_firmware_from_file(struct net_device *dev,
					struct mce_pf *pf, int region,
					const char *filename)
{
	const struct firmware *fw;
	int rc;

	rc = request_firmware(&fw, filename, &dev->dev);
	if (rc != 0) {
		netdev_err(dev, "Error %d requesting firmware file: %s\n", rc,
			   filename);
		return rc;
	}

	rc = mce_flash_firmware(pf, region, fw->data, fw->size);
	release_firmware(fw);
	return rc;
}

/* ethtool -f ethX xx.img.bin */
static int mce_flash_device(struct net_device *dev, struct ethtool_flash *flash)
{
	struct mce_netdev_priv *np = netdev_priv(dev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;

	return mce_flash_firmware_from_file(dev, pf, flash->region,
					    flash->data);
}

static const struct ethtool_ops mce_ethtool_ops = {
	.get_link_ksettings = mce_get_link_ksettings,
	.set_link_ksettings = mce_set_link_ksettings,

	.get_drvinfo = mce_get_drvinfo,

	.get_regs_len = mce_get_regs_len,
	.get_regs = mce_get_regs,

	.get_wol = mce_get_wol,
	.set_wol = mce_set_wol,
	.nway_reset = mce_nway_reset_autoneg,

	.self_test = mce_diag_test,

	.get_sset_count = mce_get_sset_count,
	.get_strings = mce_get_strings,
	.get_link = ethtool_op_get_link,
	.get_ethtool_stats = mce_get_ethtool_stats,
	.set_phys_id = mce_led_set_phys_id,
	.get_priv_flags = mce_get_priv_flags,
	.set_priv_flags = mce_set_priv_flags,
	.get_module_info = mce_get_sfp_module_info,
	.get_module_eeprom = mce_get_sfp_module_eeprom,
	.get_rxnfc = mce_get_rxnfc,
	.set_rxnfc = mce_set_rxnfc,
	.get_rxfh_key_size = mce_get_rxfh_key_size,
	.get_rxfh_indir_size = mce_get_rxfh_indir_size,
	.get_rxfh = mce_get_rxfh,
	.set_rxfh = mce_set_rxfh,
	.get_channels = mce_get_channels,
	.set_channels = mce_set_channels,
	.get_ringparam = mce_get_ringparam,
	.set_ringparam = mce_set_ringparam,
	.get_msglevel = mce_get_msglevel,
	.set_msglevel = mce_set_msglevel,
	.get_pauseparam = mce_get_pauseparam,
	.set_pauseparam = mce_set_pauseparam,
	.get_eeprom_len = mce_get_eeprom_len,
	.get_eeprom = mce_get_eeprom,
	.get_fecparam = mce_get_fecparam,
	.set_fecparam = mce_set_fecparam,
	.get_eee = mce_get_eee,
	.set_eee = mce_set_eee,
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
				     ETHTOOL_COALESCE_MAX_FRAMES |
				     ETHTOOL_COALESCE_USE_ADAPTIVE |
				     ETHTOOL_COALESCE_RX_USECS_LOW |
				     ETHTOOL_COALESCE_RX_USECS_HIGH |
				     ETHTOOL_COALESCE_RX_MAX_FRAMES_LOW |
				     ETHTOOL_COALESCE_RX_MAX_FRAMES_HIGH |
				     ETHTOOL_COALESCE_TX_USECS_LOW |
				     ETHTOOL_COALESCE_TX_USECS_HIGH |
				     ETHTOOL_COALESCE_TX_MAX_FRAMES_LOW |
				     ETHTOOL_COALESCE_TX_MAX_FRAMES_HIGH,

	.get_dump_flag = mce_get_dump_flag,
	.get_dump_data = mce_get_dump_data,
	.set_dump = mce_set_dump,

	.get_coalesce = mce_get_coalesce,
	.set_coalesce = mce_set_coalesce,
	.get_ts_info = mce_get_ts_info,
	.flash_device = mce_flash_device,
};

void mce_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &mce_ethtool_ops;
}

static void mce_repr_get_drvinfo(struct net_device *dev,
				 struct ethtool_drvinfo *drvinfo)
{
	strscpy(drvinfo->driver, MCE_REPR_DRIVERINFO, sizeof(drvinfo->driver));
}

static void mce_repr_get_ringparam(struct net_device *netdev,
				   struct ethtool_ringparam *ring,
				   struct kernel_ethtool_ringparam __always_unused *kernel_ring,
				   struct netlink_ext_ack __always_unused *extack)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_repr *repr = np->repr;

	ring->rx_max_pending = U32_MAX;
	ring->rx_pending = repr->rx_pring_size;
}

static int mce_repr_set_ringparam(struct net_device *netdev,
				  struct ethtool_ringparam *ring,
				  struct kernel_ethtool_ringparam __always_unused *kernel_ring,
				  struct netlink_ext_ack __always_unused *extack)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_repr *repr = np->repr;

	if (ring->rx_mini_pending || ring->rx_jumbo_pending || ring->tx_pending)
		return -EINVAL;

	repr->rx_pring_size = ring->rx_pending;
	return 0;
}

static const struct ethtool_ops mce_ethtool_repr_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_RX_USECS_HIGH,
	.get_drvinfo = mce_repr_get_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_ringparam = mce_repr_get_ringparam,
	.set_ringparam = mce_repr_set_ringparam,
};

/**
 * mce_set_ethtool_repr_ops - setup VF's port representor ethtool ops
 * @netdev: network interface device structure
 */
void mce_set_ethtool_repr_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &mce_ethtool_repr_ops;
}
