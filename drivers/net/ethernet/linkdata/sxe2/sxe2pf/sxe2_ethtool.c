// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_ethtool.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_compat.h"
#include "sxe2_ethtool.h"
#include "sxe2_tx.h"
#include "sxe2_rx.h"
#include "sxe2_queue.h"
#include "sxe2_netdev.h"
#include "sxe2_log.h"
#include "sxe2_rss.h"
#include "sxe2_flow.h"
#include "sxe2_msg.h"
#include "sxe2_fnav.h"
#include "sxe2_ipsec.h"
#include "sxe2_debugfs.h"
#include "sxe2_upgrade.h"
#include "sxe2_xsk.h"
#include "sxe2_mbx_public.h"
#include "sxe2_cmd.h"
#include "sxe2_monitor.h"
#include "sxe2_dcb.h"
#include "sxe2_acl.h"

#define SXE2_VSI_TX_QC(vsi, q_idx)	   (&(vsi)->txqs.q[(q_idx)]->irq_data->tx)
#define SXE2_VSI_RX_QC(vsi, q_idx)	   (&(vsi)->rxqs.q[(q_idx)]->irq_data->rx)
#define SXE2_Q_TYPE_STR_RX		   "rx"
#define SXE2_Q_TYPE_STR_TX		   "tx"
#define SXE2_MODULE_SFF_ADDR_MODE	   (0x04)
#define SXE2_MODULE_SFF_DIAG_CAPAB	   (0x40)
#define SXE2_MODULE_REVISION_ADDR	   (0x01)
#define SXE2_MODULE_SFF_PHY_DEV_IDENTIFIER (0x00)
#define SXE2_MODULE_SFF_8472_COMP	   (0x5E)
#define SXE2_MODULE_SFF_8472_SWAP	   (0x5C)
#define SXE2_MODULE_QSFP_MAX_LEN	   (640)

#define SXE2_SELFTEST_RTN_LINKDOWN (0x1)
#define SXE2_SELFTEST_RTN_FAIL (0x2)

#define SXE2_MODULE_REVISION_SFF_8436 (0x2)

#define SXE2_MODULE_REPEAT_TIMES (4)

#define EEPROM_DATALEN		 (1)
#define SFF_READ_BLOCK_SIZE_8	 (8)
#define SXE2_REG_VERSION	 (1)
#define SXE2_COALESCE_QNUM_INVAL (0xFFFFFFFF)

#define SXE2_SFF_STATUS_INDICATER (0x2)

#define SXE2_SFF_FLAT_MEM (BIT(2))

#define L2_FWD_TX_PKTS1	 "l2-fwd-%s-tx_pkts"
#define L2_FWD_TX_PKTS2	 "l2-fwd-%i-tx_pkts"
#define L2_FWD_RX_PKTS1	 "l2-fwd-%s-rx_pkts"
#define L2_FWD_RX_PKTS2	 "l2-fwd-%i-rx_pkts"
#define L2_FWD_TX_BYTES1 "l2-fwd-%s-tx_bytes"
#define L2_FWD_TX_BYTES2 "l2-fwd-%i-tx_bytes"
#define L2_FWD_RX_BYTES1 "l2-fwd-%s-rx_bytes"
#define L2_FWD_RX_BYTES2 "l2-fwd-%i-rx_bytes"

#define ETHTOOL_SELFTEST_SLEEP_MIN   (10000)
#define ETHTOOL_SELFTEST_SLEEP_MAX   (20000)
#define ETHTOOL_SELFTEST_FRAME_COUNT (32)

u8 lbtest_unicast[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x01, 0x02, 0x03 };

void __sxe2_get_drvinfo(struct net_device *netdev,
			struct ethtool_drvinfo *drvinfo, struct sxe2_adapter *adapter)
{
	struct sxe2_fw_ver_msg *fw_ver = &adapter->hw.fw_ver;

	strscpy(drvinfo->driver, SXE2_DRV_NAME, sizeof(drvinfo->driver));
	strscpy(drvinfo->version, SXE2_VERSION, sizeof(drvinfo->version));

	(void)snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version),
		       "%u.%u.%u.%u", fw_ver->main_version_id,
		       fw_ver->sub_version_id, fw_ver->fix_version_id,
		       fw_ver->build_id);

	strscpy(drvinfo->bus_info, pci_name(adapter->pdev),
		sizeof(drvinfo->bus_info));
}

STATIC void sxe2_get_drvinfo(struct net_device *netdev,
			     struct ethtool_drvinfo *drvinfo)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);

	__sxe2_get_drvinfo(netdev, drvinfo, priv->vsi->adapter);
	drvinfo->n_priv_flags = SXE2_PRIV_FLAG_ARRAY_SIZE;
}

STATIC int sxe2_get_regs_len(struct net_device __always_unused *netdev)
{
	return sizeof(sxe2_regs_dump_list);
}

STATIC void sxe2_get_regs(struct net_device *netdev, struct ethtool_regs *regs,
			  void *p)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter  = priv->vsi->adapter;
	struct sxe2_hw *hw	      = &adapter->hw;
	u32 i;
	u32 *regs_buf = (u32 *)p;

	regs->version = SXE2_REG_VERSION;
	for (i = 0; i < ARRAY_SIZE(sxe2_regs_dump_list); ++i)
		regs_buf[i] = sxe2_read_reg(hw, sxe2_regs_dump_list[i]);
}

STATIC u32 sxe2_get_msglevel(struct net_device *netdev)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter  = priv->vsi->adapter;

#ifndef CONFIG_DYNAMIC_DEBUG
	if (adapter->msglvl_ctxt.debug_mask) {
		LOG_NETDEV_INFO("debug_mask: 0x%11llx\n",
				adapter->msglvl_ctxt.debug_mask);
	}
#endif

	return adapter->msglvl_ctxt.msg_enable;
}

STATIC void sxe2_set_msglevel(struct net_device *netdev, u32 data)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter  = priv->vsi->adapter;

#ifndef CONFIG_DYNAMIC_DEBUG
	if (SXE2_DBG_USER & data)
		adapter->msglvl_ctxt.debug_mask = data;
	else
		adapter->msglvl_ctxt.msg_enable = data;
#else
	adapter->msglvl_ctxt.msg_enable = data;
#endif
}

#ifdef SXE2_MACVLAN_STATS

static void sxe2_get_macvlan_tx_strings(struct sxe2_adapter *adapter, u8 **data)
{
	u8 *p;
	int i;

	if (!data)
		return;
	p = *data;

	for (i = 0; i < SXE2_MAX_MACVLANS; i++) {
		struct sxe2_macvlan *mv = sxe2_get_macvlan(i, adapter);

		if (mv) {
			ethtool_sprintf(&p, L2_FWD_TX_PKTS1, mv->vdev->name);
			ethtool_sprintf(&p, L2_FWD_TX_BYTES1, mv->vdev->name);
		} else {
			ethtool_sprintf(&p, L2_FWD_TX_PKTS2, i);
			ethtool_sprintf(&p, L2_FWD_TX_BYTES2, i);
		}
	}
	*data = p;
}

static void sxe2_get_macvlan_tx_stats(struct sxe2_adapter *adapter, u64 *data,
				      int *idx)
{
	int i, j;

	if (!idx)
		return;

	j = *idx;

	for (i = 0; i < SXE2_MAX_MACVLANS; i++) {
		struct sxe2_macvlan *mv = sxe2_get_macvlan(i, adapter);

		if (mv) {
			data[j++] = mv->vsi->vsi_stats.txqs_stats.packets;
			data[j++] = mv->vsi->vsi_stats.txqs_stats.bytes;
		} else {
			data[j++] = 0;
			data[j++] = 0;
		}
	}

	*idx = j;
}

static void sxe2_get_macvlan_rx_strings(struct sxe2_adapter *adapter, u8 **data)
{
	u8 *p;
	int i;

	if (!data)
		return;
	p = *data;

	for (i = 0; i < SXE2_MAX_MACVLANS; i++) {
		struct sxe2_macvlan *mv = sxe2_get_macvlan(i, adapter);

		if (mv) {
			ethtool_sprintf(&p, L2_FWD_RX_PKTS1, mv->vdev->name);
			ethtool_sprintf(&p, L2_FWD_RX_BYTES1, mv->vdev->name);
		} else {
			ethtool_sprintf(&p, L2_FWD_RX_PKTS2, i);
			ethtool_sprintf(&p, L2_FWD_RX_BYTES2, i);
		}
	}
	*data = p;
}

static void sxe2_get_macvlan_rx_stats(struct sxe2_adapter *adapter, u64 *data,
				      int *idx)
{
	int i, j;

	if (!idx)
		return;

	j = *idx;

	for (i = 0; i < SXE2_MAX_MACVLANS; i++) {
		struct sxe2_macvlan *mv = sxe2_get_macvlan(i, adapter);

		if (mv) {
			data[j++] = mv->vsi->vsi_stats.rxqs_stats.packets;
			data[j++] = mv->vsi->vsi_stats.rxqs_stats.bytes;
		} else {
			data[j++] = 0;
			data[j++] = 0;
		}
	}

	*idx = j;
}
#endif

static void sxe2_get_tx_stats(struct sxe2_vsi *vsi, u64 *data, u32 *idx)
{
	struct sxe2_queue *tx_q;
	u64 pkts, bytes;
	u32 i, j;

	if (!idx)
		return;

	i = *idx;

	sxe2_for_each_vsi_txq(vsi, j) {
		tx_q = READ_ONCE(vsi->txqs.q[j]);
		sxe2_fetch_u64_data_per_ring(&tx_q->syncp, tx_q->stats, &pkts,
					     &bytes);
		data[i++] = pkts;
		data[i++] = bytes;
		data[i++] = tx_q->stats->tx_stats.tx_tso_packets;
		data[i++] = tx_q->stats->tx_stats.tx_tso_bytes;
		data[i++] = tx_q->stats->tx_stats.tx_tso_linearize_chk;
		data[i++] = tx_q->stats->tx_stats.tx_vlan_insert;
		data[i++] = tx_q->stats->tx_stats.tx_csum_none;
		data[i++] = tx_q->stats->tx_stats.tx_csum_partial;
		data[i++] = tx_q->stats->tx_stats.tx_csum_partial_inner;
		data[i++] = tx_q->stats->tx_stats.tx_busy;
		data[i++] = tx_q->stats->tx_stats.tx_queue_dropped;
		data[i++] = tx_q->stats->tx_stats.tx_xmit_more;
		data[i++] = tx_q->stats->tx_stats.tx_restart;
		data[i++] = tx_q->stats->tx_stats.tx_linearize;
	}

	*idx = i;
}

static void sxe2_get_rx_stats(struct sxe2_vsi *vsi, u64 *data, u32 *idx)
{
	struct sxe2_queue *rx_q;
	u64 pkts, bytes;
	u32 i, j;

	if (!idx)
		return;

	i = *idx;

	sxe2_for_each_vsi_rxq(vsi, j) {
		rx_q = READ_ONCE(vsi->rxqs.q[j]);
		sxe2_fetch_u64_data_per_ring(&rx_q->syncp, rx_q->stats, &pkts,
					     &bytes);
		data[i++] = pkts;
		data[i++] = bytes;
		data[i++] = rx_q->stats->rx_stats.rx_csum_unnecessary;
		data[i++] = rx_q->stats->rx_stats.rx_csum_none;
		data[i++] = rx_q->stats->rx_stats.rx_csum_complete;
		data[i++] = rx_q->stats->rx_stats.rx_csum_unnecessary_inner;
		data[i++] = rx_q->stats->rx_stats.rx_csum_err;
		data[i++] = rx_q->stats->rx_stats.rx_lro_packets;
		data[i++] = rx_q->stats->rx_stats.rx_lro_bytes;
		data[i++] = rx_q->stats->rx_stats.rx_lro_count;
		data[i++] = rx_q->stats->rx_stats.rx_vlan_strip;
		data[i++] = rx_q->stats->rx_stats.rx_pkts_sw_drop;
		data[i++] = rx_q->stats->rx_stats.rx_buff_alloc_err;
		data[i++] = rx_q->stats->rx_stats.rx_pg_alloc_fail;
		data[i++] = rx_q->stats->rx_stats.rx_page_alloc;
		data[i++] = rx_q->stats->rx_stats.rx_non_eop_descs;

		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xdp_drop;
		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xdp_redirect;
		data[i++] =
			rx_q->stats->rx_stats.xdp_stats.rx_xdp_redirect_fail;
		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xdp_pkts;
		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xdp_bytes;
		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xdp_pass;
		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xdp_unknown;
		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xdp_tx_xmit;
		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xdp_tx_xmit_fail;

		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xsk_drop;
		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xsk_redirect;
		data[i++] =
			rx_q->stats->rx_stats.xdp_stats.rx_xsk_redirect_fail;
		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xsk_packets;
		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xsk_bytes;
		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xsk_pass;
		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xsk_unknown;
		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xsk_tx_xmit;
		data[i++] = rx_q->stats->rx_stats.xdp_stats.rx_xsk_tx_xmit_fail;
		data[i++] = rx_q->stats->rx_stats.rx_pa_err;
	}

	*idx = i;
}

static int sxe2_get_ts_info(struct net_device *dev,
			    struct ethtool_ts_info *info)
{
	struct sxe2_netdev_priv *netpriv = netdev_priv(dev);
	struct sxe2_adapter *adapter	 = netpriv->vsi->adapter;

	info->so_timestamping =
		SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE |
		SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE |
		SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
	info->tx_types = (1 << HWTSTAMP_TX_OFF) | (1 << HWTSTAMP_TX_ON);

	info->rx_filters =
		BIT(HWTSTAMP_FILTER_NONE) | BIT(HWTSTAMP_FILTER_PTP_V2_EVENT);
	info->phc_index = sxe2_ptp_clock_idx_get(adapter);

	return 0;
}

static void sxe2_get_ipsec_strings(struct sxe2_adapter *adapter, u8 **data)
{
	u8 *p;

	if (!data)
		return;

	p = *data;

	ethtool_sprintf(&p, "ipsec_rx_offload_ok");
	ethtool_sprintf(&p, "ipsec_rx_decrypt_fail");
	ethtool_sprintf(&p, "ipsec_rx_invalid_state");
	ethtool_sprintf(&p, "ipsec_rx_invalid_sp");

	ethtool_sprintf(&p, "ipsec_tx_offload_ok");
	ethtool_sprintf(&p, "ipsec_tx_invalid_state");
	ethtool_sprintf(&p, "ipsec_tx_invalid_sp");

	*data = p;
}

void __sxe2_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	u32 i;
	u8 *p = data;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < SXE2_VSI_SW_STATS_LEN; i++)
			ethtool_sprintf(&p, sxe2_gstrings_vsi_sw_stats[i].stats_string);
		for (i = 0; i < SXE2_VSI_HW_STATS_LEN; i++)
			ethtool_sprintf(&p, sxe2_gstrings_vsi_hw_stats[i].stats_string);

		for (i = 0; i < SXE2_PF_HW_STATS_LEN; i++)
			ethtool_sprintf(&p, sxe2_gstrings_pf_hw_stats[i].stats_string);
		for (i = 0; i < SXE2_PF_SW_STATS_LEN; i++)
			ethtool_sprintf(&p, sxe2_gstrings_pf_sw_stats[i].stats_string);
		for (i = 0; i < SXE2_TC_MAX_CNT; i++)
			ethtool_sprintf(&p, "rx_prio%u_buf_discard", i);

		sxe2_for_each_vsi_txq(vsi, i) {
			ethtool_sprintf(&p, "tx%u_packets", i);
			ethtool_sprintf(&p, "tx%u_bytes", i);
			ethtool_sprintf(&p, "tx%u_tso_packets", i);
			ethtool_sprintf(&p, "tx%u_tso_bytes", i);
			ethtool_sprintf(&p, "tx%u_tso_linearize_chk", i);
			ethtool_sprintf(&p, "tx%u_added_vlan_packets", i);
			ethtool_sprintf(&p, "tx%u_csum_none", i);
			ethtool_sprintf(&p, "tx%u_csum_partial", i);
			ethtool_sprintf(&p, "tx%u_csum_partial_inner", i);
			ethtool_sprintf(&p, "tx%u_stopped", i);
			ethtool_sprintf(&p, "tx%u_dropped", i);
			ethtool_sprintf(&p, "tx%u_xmit_more", i);
			ethtool_sprintf(&p, "tx%u_wake", i);
			ethtool_sprintf(&p, "tx%u_linearize", i);
		}

#ifdef SXE2_MACVLAN_STATS
		mutex_lock(&vsi->adapter->vsi_ctxt.lock);
		sxe2_get_macvlan_tx_strings(vsi->adapter, &p);
		mutex_unlock(&vsi->adapter->vsi_ctxt.lock);
#endif

		sxe2_for_each_vsi_rxq(vsi, i) {
			ethtool_sprintf(&p, "rx%u_packets", i);
			ethtool_sprintf(&p, "rx%u_bytes", i);
			ethtool_sprintf(&p, "rx%u_csum_unnecessary", i);
			ethtool_sprintf(&p, "rx%u_csum_none", i);
			ethtool_sprintf(&p, "rx%u_csum_complete", i);
			ethtool_sprintf(&p, "rx%u_csum_unnecessary_inner", i);
			ethtool_sprintf(&p, "rx%u_csum_err", i);
			ethtool_sprintf(&p, "rx%u_lro_packets", i);
			ethtool_sprintf(&p, "rx%u_lro_bytes", i);
			ethtool_sprintf(&p, "rx%u_lro_count", i);
			ethtool_sprintf(&p, "rx%u_removed_vlan_packets", i);
			ethtool_sprintf(&p, "rx%u_pkts_sw_drop", i);
			ethtool_sprintf(&p, "rx%u_buff_alloc_err", i);
			ethtool_sprintf(&p, "rx%u_pg_alloc_fail", i);
			ethtool_sprintf(&p, "rx%u_page_alloc", i);
			ethtool_sprintf(&p, "rx%u_non_eop_descs", i);

			ethtool_sprintf(&p, "rx%u_xdp_drop", i);
			ethtool_sprintf(&p, "rx%u_xdp_redirect", i);
			ethtool_sprintf(&p, "rx%u_xdp_redirect_fail", i);
			ethtool_sprintf(&p, "rx%u_xdp_pkts", i);
			ethtool_sprintf(&p, "rx%u_xdp_bytes", i);
			ethtool_sprintf(&p, "rx%u_xdp_pass", i);
			ethtool_sprintf(&p, "rx%u_xdp_unknown", i);
			ethtool_sprintf(&p, "rx%u_xdp_xmit", i);
			ethtool_sprintf(&p, "rx%u_xdp_xmit_fail", i);

			ethtool_sprintf(&p, "rx%u_xsk_drop", i);
			ethtool_sprintf(&p, "rx%u_xsk_redirect", i);
			ethtool_sprintf(&p, "rx%u_xsk_redirect_fail", i);
			ethtool_sprintf(&p, "rx%u_xsk_packets", i);
			ethtool_sprintf(&p, "rx%u_xsk_bytes", i);
			ethtool_sprintf(&p, "rx%u_xsk_pass", i);
			ethtool_sprintf(&p, "rx%u_xsk_unknown", i);
			ethtool_sprintf(&p, "rx%u_xsk_xmit", i);
			ethtool_sprintf(&p, "rx%u_xsk_xmit_fail", i);
			ethtool_sprintf(&p, "rx%u_pa_err", i);
		}

#ifdef SXE2_MACVLAN_STATS
		mutex_lock(&vsi->adapter->vsi_ctxt.lock);
		sxe2_get_macvlan_rx_strings(vsi->adapter, &p);
		mutex_unlock(&vsi->adapter->vsi_ctxt.lock);
#endif

		sxe2_get_ipsec_strings(vsi->adapter, &p);

		sxe2_for_each_prioirty(i) {
			ethtool_sprintf(&p, "tx_prio%u_xon_phy", i);
			ethtool_sprintf(&p, "tx_prio%u_xoff_phy", i);
			ethtool_sprintf(&p, "rx_prio%u_xon_phy", i);
			ethtool_sprintf(&p, "rx_prio%u_xoff_phy", i);
		}

		break;
	case ETH_SS_TEST:
		sxe2_ethtool_selftest_strings(netdev, data);
		break;
	case ETH_SS_PRIV_FLAGS:
		for (i = 0; i < SXE2_PRIV_FLAG_ARRAY_SIZE; i++)
			ethtool_sprintf(&p, sxe2_gstrings_priv_flags[i].name);
		break;
	default:
		break;
	}
}

void __sxe2_repr_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	u32 i;
	u8 *p = data;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < SXE2_VSI_HW_STATS_LEN; i++)
			ethtool_sprintf(&p, sxe2_gstrings_vsi_hw_stats[i].stats_string);
		break;
	default:
		break;
	}
}

STATIC void sxe2_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	__sxe2_get_strings(netdev, stringset, data);
}

STATIC s32 sxe2_identify_led_ctrl(struct sxe2_adapter *adapter, bool is_blink)
{
	s32 ret			   = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_led_ctrl ctrl;

	ctrl.mode = (is_blink) ? SXE2_IDENTIFY_LED_BLINK_ON :
					 SXE2_IDENTIFY_LED_BLINK_OFF;
	ctrl.duration = 0;

	sxe2_cmd_params_no_interruptible_fill(&cmd, SXE2_CMD_LED_CTRL, &ctrl,
					      sizeof(ctrl), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("led ctrl failed, is_blink=%d, ret=%d\n",
			      is_blink, ret);
		ret = -EIO;
		goto l_out;
	}

l_out:
	return ret;
}

STATIC int sxe2_set_phys_id(struct net_device *netdev,
			    enum ethtool_phys_id_state state)
{
	bool led_active;
	int ret			      = 0;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter  = priv->vsi->adapter;

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		led_active = true;
		break;
	case ETHTOOL_ID_INACTIVE:
		led_active = false;
		break;
	default:
		ret = -EINVAL;
		LOG_ERROR_BDF("identify led dont support ON/OFF, state=%d\n",
			      state);
		goto l_out;
	}
	ret = sxe2_identify_led_ctrl(adapter, led_active);
	if (ret) {
		LOG_ERROR_BDF("led ctrl failed, ret=%d\n", ret);
		goto l_out;
	}
	LOG_INFO_BDF("led ctrl succeed!\n");
l_out:
	return ret;
}

STATIC void sxe2_hw_vsi_stats_set(struct sxe2_adapter *adapter,
				  struct sxe2_fwc_vsi_stats_resp *resp)
{
	u16 i, j;
	struct sxe2_vsi *vsi;
	u16 vsi_cnt = le16_to_cpu(resp->vsi_cnt);

	for (i = 0; i < vsi_cnt; i++) {
		sxe2_for_each_vsi(&adapter->vsi_ctxt, j) {
			vsi = adapter->vsi_ctxt.vsi[j];
			if (!vsi)
				continue;

			if (vsi->idx_in_dev ==
			    le16_to_cpu(resp->vsi_stats[i].vsi_id)) {
				vsi->vsi_stats.vsi_hw_stats.rx_vsi_unicast_packets +=
				  le64_to_cpu(resp->vsi_stats[i].stats.rx_vsi_unicast_packets);

				vsi->vsi_stats.vsi_hw_stats.rx_vsi_bytes +=
				   le64_to_cpu(resp->vsi_stats[i].stats.rx_vsi_bytes);

				vsi->vsi_stats.vsi_hw_stats.tx_vsi_unicast_packets +=
				  le64_to_cpu(resp->vsi_stats[i].stats.tx_vsi_unicast_packets);

				vsi->vsi_stats.vsi_hw_stats.tx_vsi_bytes +=
				  le64_to_cpu(resp->vsi_stats[i].stats.tx_vsi_bytes);

				vsi->vsi_stats.vsi_hw_stats.rx_vsi_multicast_packets +=
				  le64_to_cpu(resp->vsi_stats[i].stats.rx_vsi_multicast_packets);

				vsi->vsi_stats.vsi_hw_stats.tx_vsi_multicast_packets +=
				  le64_to_cpu(resp->vsi_stats[i].stats.tx_vsi_multicast_packets);

				vsi->vsi_stats.vsi_hw_stats.rx_vsi_broadcast_packets +=
				  le64_to_cpu(resp->vsi_stats[i].stats.rx_vsi_broadcast_packets);

				vsi->vsi_stats.vsi_hw_stats.tx_vsi_broadcast_packets +=
				  le64_to_cpu(resp->vsi_stats[i].stats.tx_vsi_broadcast_packets);
			}
		}
	}
}

STATIC void sxe2_pf_nonclear_hw_stats_set(struct sxe2_adapter *adapter,
					  u64 *last_value, u64 current_value,
					  u64 *new_value)
{
	if (adapter->pf_stats.stat_prev_loaded) {
		if (current_value >= *last_value)
			*new_value += current_value - *last_value;
		else
			*new_value += current_value + BIT_ULL(32) - *last_value;
	}

	*last_value = current_value;
}

STATIC void sxe2_pf_nonclear_hw_stats64_set(struct sxe2_adapter *adapter,
					    u64 *last_value, u64 current_value,
					    u64 *new_value)
{
	if (adapter->pf_stats.stat_prev_loaded) {
		if (current_value >= *last_value)
			*new_value += current_value - *last_value;
		else
			*new_value = current_value;
	}

	*last_value = current_value;
}

STATIC void sxe2_pf_hw_stats_set(struct sxe2_adapter *adapter,
				 struct sxe2_pf_hw_stats *stats,
				 struct sxe2_fwc_pf_stats_resp *resp)
{
	u8 i;
	struct sxe2_pf_hw_stats *last_pf_hw_stats =
		&adapter->pf_stats.last_pf_hw_stats;

	if (adapter->pf_stats.stat_prev_loaded) {
		stats->rx_out_of_buffer += le64_to_cpu(resp->stats.rx_out_of_buffer);
		stats->rx_pcs_symbol_err_phy += le64_to_cpu(resp->stats.rx_pcs_symbol_err_phy);
		stats->rx_corrected_bits_phy += le64_to_cpu(resp->stats.rx_corrected_bits_phy);
		stats->rx_err_lane_0_phy += le64_to_cpu(resp->stats.rx_err_lane_0_phy);
		stats->rx_err_lane_1_phy += le64_to_cpu(resp->stats.rx_err_lane_1_phy);
		stats->rx_err_lane_2_phy += le64_to_cpu(resp->stats.rx_err_lane_2_phy);
		stats->rx_err_lane_3_phy += le64_to_cpu(resp->stats.rx_err_lane_3_phy);
		stats->rx_discards_ips_phy += le64_to_cpu(resp->stats.rx_discards_ips_phy);

		for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
			stats->rx_prio_buf_discard[i] +=
				le64_to_cpu(resp->stats.rx_prio_buf_discard[i]);
	}

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->prio_xoff_rx[i],
						le64_to_cpu(resp->stats.prio_xoff_rx[i]),
						&stats->prio_xoff_rx[i]);
		sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->prio_xon_rx[i],
						le64_to_cpu(resp->stats.prio_xon_rx[i]),
						&stats->prio_xon_rx[i]);
		sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->prio_xoff_tx[i],
						le64_to_cpu(resp->stats.prio_xoff_tx[i]),
						&stats->prio_xoff_tx[i]);
		sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->prio_xon_tx[i],
						le64_to_cpu(resp->stats.prio_xon_tx[i]),
						&stats->prio_xon_tx[i]);
		sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->prio_xon_2_xoff[i],
						le64_to_cpu(resp->stats.prio_xon_2_xoff[i]),
						&stats->prio_xon_2_xoff[i]);
	}

	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_pause,
					le64_to_cpu(resp->stats.rx_pause),
					&stats->rx_pause);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_pause,
					le64_to_cpu(resp->stats.tx_pause),
					&stats->tx_pause);

	sxe2_pf_nonclear_hw_stats64_set(adapter,
					&last_pf_hw_stats->tx_frame_good,
					le64_to_cpu(resp->stats.tx_frame_good),
					&stats->tx_frame_good);
	sxe2_pf_nonclear_hw_stats64_set(adapter,
					&last_pf_hw_stats->rx_frame_good,
					le64_to_cpu(resp->stats.rx_frame_good),
					&stats->rx_frame_good);
	sxe2_pf_nonclear_hw_stats64_set(adapter,
					&last_pf_hw_stats->rx_crc_errors,
					le64_to_cpu(resp->stats.rx_crc_errors),
					&stats->rx_crc_errors);
	sxe2_pf_nonclear_hw_stats64_set(adapter,
					&last_pf_hw_stats->tx_bytes_good,
					le64_to_cpu(resp->stats.tx_bytes_good),
					&stats->tx_bytes_good);
	sxe2_pf_nonclear_hw_stats64_set(adapter,
					&last_pf_hw_stats->rx_bytes_good,
					le64_to_cpu(resp->stats.rx_bytes_good),
					&stats->rx_bytes_good);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_multicast_good,
					le64_to_cpu(resp->stats.tx_multicast_good),
					&stats->tx_multicast_good);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_broadcast_good,
					le64_to_cpu(resp->stats.tx_broadcast_good),
					&stats->tx_broadcast_good);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_multicast_good,
					le64_to_cpu(resp->stats.rx_multicast_good),
					&stats->rx_multicast_good);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_broadcast_good,
					le64_to_cpu(resp->stats.rx_broadcast_good),
					&stats->rx_broadcast_good);
	sxe2_pf_nonclear_hw_stats64_set(adapter,
					&last_pf_hw_stats->rx_len_errors,
					le64_to_cpu(resp->stats.rx_len_errors),
					&stats->rx_len_errors);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_out_of_range_errors,
					le64_to_cpu(resp->stats.rx_out_of_range_errors),
					&stats->rx_out_of_range_errors);
	sxe2_pf_nonclear_hw_stats_set(adapter, &last_pf_hw_stats->rx_oversize_pkts_phy,
				      le64_to_cpu(resp->stats.rx_oversize_pkts_phy),
				      &stats->rx_oversize_pkts_phy);
	sxe2_pf_nonclear_hw_stats64_set(adapter,
					&last_pf_hw_stats->rx_symbol_err,
					le64_to_cpu(resp->stats.rx_symbol_err),
					&stats->rx_symbol_err);
	sxe2_pf_nonclear_hw_stats64_set(adapter,
					&last_pf_hw_stats->rx_pause_frame,
					le64_to_cpu(resp->stats.rx_pause_frame),
					&stats->rx_pause_frame);
	sxe2_pf_nonclear_hw_stats64_set(adapter,
					&last_pf_hw_stats->tx_pause_frame,
					le64_to_cpu(resp->stats.tx_pause_frame),
					&stats->tx_pause_frame);

	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_discards_phy,
					le64_to_cpu(resp->stats.rx_discards_phy),
					&stats->rx_discards_phy);

	stats->rx_discards_phy =
		stats->rx_discards_phy + stats->rx_discards_ips_phy;

	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_dropped_link_down,
					le64_to_cpu(resp->stats.tx_dropped_link_down),
					&stats->tx_dropped_link_down);

	sxe2_pf_nonclear_hw_stats_set(adapter, &last_pf_hw_stats->rx_undersize_good,
				      le64_to_cpu(resp->stats.rx_undersize_good),
				      &stats->rx_undersize_good);

	sxe2_pf_nonclear_hw_stats_set(adapter, &last_pf_hw_stats->rx_runt_error,
				      le64_to_cpu(resp->stats.rx_runt_error),
				      &stats->rx_runt_error);

	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_bytes_good_bad,
					le64_to_cpu(resp->stats.tx_bytes_good_bad),
					&stats->tx_bytes_good_bad);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_frame_good_bad,
					le64_to_cpu(resp->stats.tx_frame_good_bad),
					&stats->tx_frame_good_bad);

	sxe2_pf_nonclear_hw_stats_set(adapter, &last_pf_hw_stats->rx_jabbers,
				      le64_to_cpu(resp->stats.rx_jabbers),
				      &stats->rx_jabbers);

	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_size_64,
					le64_to_cpu(resp->stats.rx_size_64),
					&stats->rx_size_64);
	sxe2_pf_nonclear_hw_stats64_set(adapter,
					&last_pf_hw_stats->rx_size_65_127,
					le64_to_cpu(resp->stats.rx_size_65_127),
					&stats->rx_size_65_127);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_size_128_255,
					le64_to_cpu(resp->stats.rx_size_128_255),
					&stats->rx_size_128_255);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_size_256_511,
					le64_to_cpu(resp->stats.rx_size_256_511),
					&stats->rx_size_256_511);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_size_512_1023,
					le64_to_cpu(resp->stats.rx_size_512_1023),
					&stats->rx_size_512_1023);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_size_1024_1522,
					le64_to_cpu(resp->stats.rx_size_1024_1522),
					&stats->rx_size_1024_1522);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_size_1523_max,
					le64_to_cpu(resp->stats.rx_size_1523_max),
					&stats->rx_size_1523_max);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_illegal_bytes,
					le64_to_cpu(resp->stats.rx_illegal_bytes),
					&stats->rx_illegal_bytes);

	sxe2_pf_nonclear_hw_stats_set(adapter,
				      &last_pf_hw_stats->rx_oversize_good,
				      le64_to_cpu(resp->stats.rx_oversize_good),
				      &stats->rx_oversize_good);

	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_unicast,
					le64_to_cpu(resp->stats.tx_unicast),
					&stats->tx_unicast);
	sxe2_pf_nonclear_hw_stats64_set(adapter,
					&last_pf_hw_stats->tx_broadcast,
					le64_to_cpu(resp->stats.tx_broadcast),
					&stats->tx_broadcast);
	sxe2_pf_nonclear_hw_stats64_set(adapter,
					&last_pf_hw_stats->tx_multicast,
					le64_to_cpu(resp->stats.tx_multicast),
					&stats->tx_multicast);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_vlan_packet_good,
					le64_to_cpu(resp->stats.tx_vlan_packet_good),
					&stats->tx_vlan_packet_good);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_size_64,
					le64_to_cpu(resp->stats.tx_size_64),
					&stats->tx_size_64);
	sxe2_pf_nonclear_hw_stats64_set(adapter,
					&last_pf_hw_stats->tx_size_65_127,
					le64_to_cpu(resp->stats.tx_size_65_127),
					&stats->tx_size_65_127);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_size_128_255,
					le64_to_cpu(resp->stats.tx_size_128_255),
					&stats->tx_size_128_255);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_size_256_511,
					le64_to_cpu(resp->stats.tx_size_256_511),
					&stats->tx_size_256_511);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_size_512_1023,
					le64_to_cpu(resp->stats.tx_size_512_1023),
					&stats->tx_size_512_1023);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_size_1024_1522,
					le64_to_cpu(resp->stats.tx_size_1024_1522),
					&stats->tx_size_1024_1522);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_size_1523_max,
					le64_to_cpu(resp->stats.tx_size_1523_max),
					&stats->tx_size_1523_max);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->tx_underflow_error,
					le64_to_cpu(resp->stats.tx_underflow_error),
					&stats->tx_underflow_error);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_byte_good_bad,
					le64_to_cpu(resp->stats.rx_byte_good_bad),
					&stats->rx_byte_good_bad);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_frame_good_bad,
					le64_to_cpu(resp->stats.rx_frame_good_bad),
					&stats->rx_frame_good_bad);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_unicast_good,
					le64_to_cpu(resp->stats.rx_unicast_good),
					&stats->rx_unicast_good);
	sxe2_pf_nonclear_hw_stats64_set(adapter, &last_pf_hw_stats->rx_vlan_packets,
					le64_to_cpu(resp->stats.rx_vlan_packets),
					&stats->rx_vlan_packets);

	stats->fnav_match += le64_to_cpu(resp->stats.fnav_match);

	stats->spoof_mac_packets = le64_to_cpu(resp->stats.spoof_mac_packets);
	stats->spoof_vlan_packets = le64_to_cpu(resp->stats.spoof_vlan_packets);
	adapter->pf_stats.stat_prev_loaded = true;
}

s32 sxe2_fwc_get_pf_stats(struct sxe2_adapter *adapter)
{
	s32 ret				    = 0;
	struct sxe2_cmd_params cmd	    = {};
	struct sxe2_fwc_pf_stats_req req    = {};
	struct sxe2_fwc_pf_stats_resp *resp = NULL;
	struct sxe2_pf_hw_stats *stats	    = &adapter->pf_stats.pf_hw_stats;

	resp = kzalloc(sizeof(*resp), GFP_KERNEL);
	if (!resp) {
		LOG_DEV_ERR("alloc memory fail.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	req.fnav_stats_idx =
		adapter->fnav_ctxt.fnav_stat_ctxt.stat_rsv_idx[SXE2_FNAV_STAT_PF];

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_GET_PF_STATS, &req,
				  sizeof(req), resp,
				  sizeof(struct sxe2_fwc_pf_stats_resp));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("get stats failed, ret=%d\n", ret);
		goto l_end;
	}
	sxe2_pf_hw_stats_set(adapter, stats, resp);
l_end:
	kfree(resp);

	return ret;
}

void sxe2_hw_pf_stats_update(struct sxe2_adapter *adapter)
{
	(void)sxe2_fwc_get_pf_stats(adapter);
}

static void sxe2_sw_pf_stats_update(struct sxe2_adapter *adapter)
{
	adapter->pf_stats.pf_sw_stats.fnav_prgm_err =
		adapter->fnav_ctxt.pkt_err_cnt;
}

void sxe2_sw_vsi_stats_update(struct sxe2_vsi *vsi)
{
	struct sxe2_vsi_sw_stats cur_stats;
	struct sxe2_vsi_qs_stats *vsi_qs_stats = &vsi->vsi_qs_stats;
	struct sxe2_queue_stats *txq_stats, *rxq_stats;
	u64 pkts, bytes;
	u8 j;

	(void)memset(&cur_stats, 0, sizeof(cur_stats));

	if (!test_bit(SXE2_VSI_S_DOWN, vsi->state)) {
		sxe2_for_each_vsi_txq(vsi, j) {
			txq_stats = &vsi_qs_stats->txqs_stats[j];
			sxe2_fetch_u64_data_per_ring(&txq_stats->syncp,
						     txq_stats, &pkts, &bytes);
			cur_stats.tx_packets += pkts;
			cur_stats.tx_bytes += bytes;
			cur_stats.tx_restart += txq_stats->tx_stats.tx_restart;
			cur_stats.tx_busy += txq_stats->tx_stats.tx_busy;
			cur_stats.tx_linearize +=
				txq_stats->tx_stats.tx_linearize;
			cur_stats.tx_vlan_insert +=
				txq_stats->tx_stats.tx_vlan_insert;
			cur_stats.tx_tso_packets +=
				txq_stats->tx_stats.tx_tso_packets;
			cur_stats.tx_tso_bytes +=
				txq_stats->tx_stats.tx_tso_bytes;
			cur_stats.tx_csum_none +=
				txq_stats->tx_stats.tx_csum_none;
			cur_stats.tx_csum_partial +=
				txq_stats->tx_stats.tx_csum_partial;
			cur_stats.tx_csum_partial_inner +=
				txq_stats->tx_stats.tx_csum_partial_inner;
			cur_stats.tx_queue_dropped +=
				txq_stats->tx_stats.tx_queue_dropped;
			cur_stats.tx_xmit_more +=
				txq_stats->tx_stats.tx_xmit_more;
			cur_stats.tx_tso_linearize_chk +=
				txq_stats->tx_stats.tx_tso_linearize_chk;
		}

		sxe2_for_each_vsi_rxq(vsi, j) {
			rxq_stats = &vsi_qs_stats->rxqs_stats[j];
			sxe2_fetch_u64_data_per_ring(&rxq_stats->syncp,
						     rxq_stats, &pkts, &bytes);
			cur_stats.rx_packets += pkts;
			cur_stats.rx_bytes += bytes;
			cur_stats.rx_buff_alloc_err +=
				rxq_stats->rx_stats.rx_buff_alloc_err;
			cur_stats.rx_pg_alloc_fail +=
				rxq_stats->rx_stats.rx_pg_alloc_fail;
			cur_stats.rx_lro_count +=
				rxq_stats->rx_stats.rx_lro_count;
			cur_stats.rx_lro_packets +=
				rxq_stats->rx_stats.rx_lro_packets;
			cur_stats.rx_vlan_strip +=
				rxq_stats->rx_stats.rx_vlan_strip;
			cur_stats.rx_csum_err +=
				rxq_stats->rx_stats.rx_csum_err;
			cur_stats.rx_csum_unnecessary +=
				rxq_stats->rx_stats.rx_csum_unnecessary;
			cur_stats.rx_csum_none +=
				rxq_stats->rx_stats.rx_csum_none;
			cur_stats.rx_csum_complete +=
				rxq_stats->rx_stats.rx_csum_complete;
			cur_stats.rx_csum_unnecessary_inner +=
				rxq_stats->rx_stats.rx_csum_unnecessary_inner;
			cur_stats.rx_lro_bytes +=
				rxq_stats->rx_stats.rx_lro_bytes;
			cur_stats.rx_pkts_sw_drop +=
				rxq_stats->rx_stats.rx_pkts_sw_drop;
			cur_stats.rx_page_alloc +=
				rxq_stats->rx_stats.rx_page_alloc;
			cur_stats.rx_non_eop_descs +=
				rxq_stats->rx_stats.rx_non_eop_descs;

			cur_stats.rx_xdp_pkts +=
				rxq_stats->rx_stats.xdp_stats.rx_xdp_pkts;
			cur_stats.rx_xdp_bytes +=
				rxq_stats->rx_stats.xdp_stats.rx_xdp_bytes;
			cur_stats.rx_xdp_pass +=
				rxq_stats->rx_stats.xdp_stats.rx_xdp_pass;
			cur_stats.rx_xdp_drop +=
				rxq_stats->rx_stats.xdp_stats.rx_xdp_drop;
			cur_stats.rx_xdp_unknown +=
				rxq_stats->rx_stats.xdp_stats.rx_xdp_unknown;
			cur_stats.rx_xdp_redirect +=
				rxq_stats->rx_stats.xdp_stats.rx_xdp_redirect;
			cur_stats.rx_xdp_redirect_fail +=
				rxq_stats->rx_stats.xdp_stats.rx_xdp_redirect_fail;
			cur_stats.rx_xdp_tx_xmit +=
				rxq_stats->rx_stats.xdp_stats.rx_xdp_tx_xmit;
			cur_stats.rx_xdp_tx_xmit_fail +=
				rxq_stats->rx_stats.xdp_stats.rx_xdp_tx_xmit_fail;

			cur_stats.rx_xsk_redirect_fail +=
				rxq_stats->rx_stats.xdp_stats.rx_xsk_redirect_fail;
			cur_stats.rx_xsk_redirect +=
				rxq_stats->rx_stats.xdp_stats.rx_xsk_redirect;
			cur_stats.rx_xsk_unknown +=
				rxq_stats->rx_stats.xdp_stats.rx_xsk_unknown;
			cur_stats.rx_xsk_pass +=
				rxq_stats->rx_stats.xdp_stats.rx_xsk_pass;
			cur_stats.rx_xsk_packets +=
				rxq_stats->rx_stats.xdp_stats.rx_xsk_packets;
			cur_stats.rx_xsk_bytes +=
				rxq_stats->rx_stats.xdp_stats.rx_xsk_bytes;
			cur_stats.rx_xsk_drop +=
				rxq_stats->rx_stats.xdp_stats.rx_xsk_drop;
			cur_stats.rx_xsk_tx_xmit +=
				rxq_stats->rx_stats.xdp_stats.rx_xsk_tx_xmit;
			cur_stats.rx_xsk_tx_xmit_fail +=
				rxq_stats->rx_stats.xdp_stats.rx_xsk_tx_xmit_fail;

			cur_stats.rx_pa_err += rxq_stats->rx_stats.rx_pa_err;
		}
		(void)memcpy(&vsi->vsi_stats.vsi_sw_stats, &cur_stats,
			     sizeof(cur_stats));
	}
}

STATIC s32 sxe2_fwc_get_vsi_stats(struct sxe2_adapter *adapter,
				  struct sxe2_fwc_vsi_stats_req *req,
				  struct sxe2_fwc_vsi_stats_resp *resp,
				  u32 in_len, u32 out_len)
{
	s32 ret			   = 0;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_GET_VSI_STATS, req, in_len,
				  resp, out_len);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("get %d vsi stats failed, req size=%d, resp size=%d, ret=%d\n",
			      le16_to_cpu(req->vsi_cnt), in_len, out_len, ret);
		goto l_end;
		;
	}
	sxe2_hw_vsi_stats_set(adapter, resp);
l_end:
	return ret;
}

void sxe2_hw_vsi_stats_update(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter	     = vsi->adapter;
	struct sxe2_fwc_vsi_stats_req req    = {};
	struct sxe2_fwc_vsi_stats_resp *resp = NULL;

	resp = kzalloc(sizeof(*resp), GFP_KERNEL);
	if (!resp) {
		LOG_DEV_ERR("alloc memory fail.\n");
		return;
	}

	req.vsi_cnt    = cpu_to_le16(1);
	req.vsi_ids[0] = cpu_to_le16(vsi->idx_in_dev);

	(void)sxe2_fwc_get_vsi_stats(adapter, &req, resp,
				     sizeof(struct sxe2_fwc_vsi_stats_req),
				     sizeof(struct sxe2_fwc_vsi_stats_resp));
	kfree(resp);
}

STATIC void sxe2_hw_vsi_stats_update_all(struct sxe2_adapter *adapter)
{
	u16 i;
	u16 idx				     = 0;
	struct sxe2_fwc_vsi_stats_req req    = { 0 };
	struct sxe2_fwc_vsi_stats_resp *resp = NULL;
	struct sxe2_vsi *vsi		     = NULL;

	resp = kzalloc(sizeof(*resp), GFP_KERNEL);
	if (!resp) {
		LOG_DEV_ERR("alloc memory fail.\n");
		return;
	}

	sxe2_for_each_vsi(&adapter->vsi_ctxt, i) {
		vsi = adapter->vsi_ctxt.vsi[i];
		if (!vsi)
			continue;
		req.vsi_ids[idx] = cpu_to_le16(vsi->idx_in_dev);
		idx++;
		if (idx == SXE2_CMD_VSI_STATS_MAX_CNT) {
			req.vsi_cnt = idx;
			(void)sxe2_fwc_get_vsi_stats(adapter, &req, resp,
						     sizeof(struct sxe2_fwc_vsi_stats_req),
						     sizeof(struct sxe2_fwc_vsi_stats_resp));
			idx = 0;
		}
	}

	if (idx > 0) {
		req.vsi_cnt = idx;
		(void)sxe2_fwc_get_vsi_stats(adapter, &req, resp,
					     sizeof(struct sxe2_fwc_vsi_stats_req),
					     sizeof(struct sxe2_fwc_vsi_stats_resp));
	}
	kfree(resp);
}

STATIC void sxe2_repr_accumulate_sw_stats(struct rtnl_link_stats64 *stats,
					  struct sxe2_vsi *vsi)
{
	struct sxe2_vsi_hw_stats *vsi_hw_stats;

	if (!vsi)
		return;

	vsi_hw_stats = &vsi->vsi_stats.vsi_hw_stats;

	stats->rx_packets += vsi->vsi_stats.vsi_sw_stats.rx_packets;
	stats->rx_bytes   += vsi->vsi_stats.vsi_sw_stats.rx_bytes;
	stats->tx_packets += vsi->vsi_stats.vsi_sw_stats.tx_packets;
	stats->tx_bytes   += vsi->vsi_stats.vsi_sw_stats.tx_bytes;
	stats->multicast  += vsi_hw_stats->rx_vsi_multicast_packets;
}

STATIC void sxe2_repr_accumulate_hw_stats(struct rtnl_link_stats64 *stats,
					  struct sxe2_vsi *vsi)
{
	struct sxe2_vsi_hw_stats *vsi_hw_stats;

	if (!vsi)
		return;

	vsi_hw_stats = &vsi->vsi_stats.vsi_hw_stats;

	stats->rx_packets += vsi_hw_stats->rx_vsi_unicast_packets +
				vsi_hw_stats->rx_vsi_multicast_packets +
				vsi_hw_stats->rx_vsi_broadcast_packets;
	stats->rx_bytes   += vsi_hw_stats->rx_vsi_bytes;
	stats->multicast  += vsi_hw_stats->rx_vsi_multicast_packets;

	stats->tx_packets += vsi_hw_stats->tx_vsi_unicast_packets +
				vsi_hw_stats->tx_vsi_multicast_packets +
				vsi_hw_stats->tx_vsi_broadcast_packets;
	stats->tx_bytes   += vsi_hw_stats->tx_vsi_bytes;
}

void sxe2_repr_vf_vsis_stats_acculate_update(struct sxe2_adapter *adapter)
{
	u16 vf_idx;
	struct sxe2_vf_node *vf = NULL;
	struct rtnl_link_stats64 stats;

	sxe2_for_each_vf(adapter, vf_idx) {
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
		vf = SXE2_VF_NODE(adapter, vf_idx);
		if (!vf) {
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
			continue;
		}

		memset(&stats, 0, sizeof(stats));

		mutex_lock(&adapter->vsi_ctxt.lock);

		if (test_bit(SXE2_FLAG_VFSWSTATS_ENABLE, adapter->flags))
			sxe2_repr_accumulate_sw_stats(&stats, vf->vsi);
		else
			sxe2_repr_accumulate_hw_stats(&stats, vf->vsi);

		sxe2_repr_accumulate_hw_stats(&stats, vf->dpdk_vf_vsi);

		memcpy(&adapter->repr_vf_stats.repr_link_stats64[vf_idx], &stats, sizeof(stats));

		mutex_unlock(&adapter->vsi_ctxt.lock);
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	}
}

void sxe2_stats_update(struct sxe2_adapter *adapter)
{
	sxe2_hw_pf_stats_update(adapter);

	sxe2_hw_vsi_stats_update_all(adapter);

	sxe2_fnav_match_stats_update_batch(adapter);
}

static void sxe2_get_ipsec_stats(struct sxe2_vsi *vsi, u64 *data, u32 *idx)
{
	u32 i, j;
	u64 rx_offload_success	   = 0;
	u64 rx_error_decrypt_fail  = 0;
	u64 rx_error_invalid_state = 0;
	u64 rx_error_invalid_sp	   = 0;
	u64 tx_offload_success	   = 0;
	u64 tx_error_invalid_state = 0;
	u64 tx_error_invalid_sp	   = 0;
	struct sxe2_queue *q;

	if (!idx)
		return;

	i = *idx;

	sxe2_for_each_vsi_rxq(vsi, j) {
		q = READ_ONCE(vsi->rxqs.q[j]);
		rx_offload_success += q->stats->ipsec_stats.rx_offload_success;
		rx_error_decrypt_fail +=
			q->stats->ipsec_stats.rx_error_decrypt_fail;
		rx_error_invalid_state +=
			q->stats->ipsec_stats.rx_error_invalid_state;
		rx_error_invalid_sp +=
			q->stats->ipsec_stats.rx_error_invalid_sp;
	}
	data[i++] = rx_offload_success;
	data[i++] = rx_error_decrypt_fail;
	data[i++] = rx_error_invalid_state;
	data[i++] = rx_error_invalid_sp;

	sxe2_for_each_vsi_txq(vsi, j) {
		q = READ_ONCE(vsi->txqs.q[j]);
		tx_offload_success += q->stats->ipsec_stats.tx_offload_success;
		tx_error_invalid_state +=
			q->stats->ipsec_stats.tx_error_invalid_state;
		tx_error_invalid_sp +=
			q->stats->ipsec_stats.tx_error_invalid_sp;
	}
	data[i++] = tx_offload_success;
	data[i++] = tx_error_invalid_state;
	data[i++] = tx_error_invalid_sp;

	*idx = i;
}

void __sxe2_get_ethtool_stats(struct net_device *netdev,
			      struct ethtool_stats __always_unused *stats,
			      u64 *data, struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter	       = vsi->adapter;
	struct sxe2_pf_hw_stats *pf_hw_stats   = &adapter->pf_stats.pf_hw_stats;
	struct sxe2_pf_sw_stats *pf_sw_stats   = &adapter->pf_stats.pf_sw_stats;
	struct sxe2_vsi_sw_stats *vsi_sw_stats = &vsi->vsi_stats.vsi_sw_stats;
	struct sxe2_vsi_hw_stats *vsi_hw_stats = &vsi->vsi_stats.vsi_hw_stats;

	u8 j;
	u32 i = 0;
	char *p;

	mutex_lock(&adapter->vsi_ctxt.lock);

	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state))
		goto l_unlock;

	sxe2_hw_pf_stats_update(adapter);

	sxe2_sw_pf_stats_update(adapter);

	sxe2_hw_vsi_stats_update(vsi);

	sxe2_sw_vsi_stats_update(vsi);

	for (j = 0; j < SXE2_VSI_SW_STATS_LEN; j++) {
		p = (char *)vsi_sw_stats +
		    sxe2_gstrings_vsi_sw_stats[j].stats_offset;
		data[i++] = *(u64 *)p;
	}

	for (j = 0; j < SXE2_VSI_HW_STATS_LEN; j++) {
		p = (char *)vsi_hw_stats +
		    sxe2_gstrings_vsi_hw_stats[j].stats_offset;
		data[i++] = *(u64 *)p;
	}

	for (j = 0; j < SXE2_PF_HW_STATS_LEN; j++) {
		p = (char *)pf_hw_stats +
		    sxe2_gstrings_pf_hw_stats[j].stats_offset;
		data[i++] = *(u64 *)p;
	}

	for (j = 0; j < SXE2_PF_SW_STATS_LEN; j++) {
		p = (char *)pf_sw_stats +
		    sxe2_gstrings_pf_sw_stats[j].stats_offset;
		data[i++] = *(u64 *)p;
	}
	for (j = 0; j < IEEE_8021QAZ_MAX_TCS; j++)
		data[i++] = pf_hw_stats->rx_prio_buf_discard[j];

	sxe2_get_tx_stats(vsi, data, &i);

#ifdef SXE2_MACVLAN_STATS
	sxe2_get_macvlan_tx_stats(vsi->adapter; data, &i);
#endif

	sxe2_get_rx_stats(vsi, data, &i);

#ifdef SXE2_MACVLAN_STATS
	sxe2_get_macvlan_rx_stats(vsi->adapter; data, &i);
#endif

	sxe2_get_ipsec_stats(vsi, data, &i);

	sxe2_for_each_prioirty(j) {
		data[i++] = pf_hw_stats->prio_xon_tx[j];
		data[i++] = pf_hw_stats->prio_xoff_tx[j];
		data[i++] = pf_hw_stats->prio_xon_rx[j];
		data[i++] = pf_hw_stats->prio_xoff_rx[j];
	}

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
}

void __sxe2_repr_get_ethtool_stats(struct net_device *netdev,
				   struct ethtool_stats __always_unused *stats,
				   u64 *data, struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter	       = vsi->adapter;
	struct sxe2_vsi_hw_stats *vsi_hw_stats;
	u8 j;
	u32 i = 0;
	char *p;
	struct sxe2_vf_node *vf_node = vsi->vf_node;
	struct sxe2_vsi *user_vsi;
	s32 ret			     = 0;

	LOG_INFO_BDF("vsi %d, get ethtool stats.\n", vsi->idx_in_dev);
	mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_node->vf_idx));

	ret = sxe2_check_vf_ready_for_cfg(vf_node);
	if (ret) {
		LOG_ERROR_BDF("vf:%u pf flags:0x%lx vf states:0x%lx not ready.\n",
			      vf_node->vf_idx, *adapter->flags, *vf_node->states);
		goto l_unlock;
	}

	sxe2_hw_vsi_stats_update(vsi);

	vsi_hw_stats = &vsi->vsi_stats.vsi_hw_stats;
	for (j = 0; j < SXE2_VSI_HW_STATS_LEN; j++) {
		p = (char *)vsi_hw_stats +
		    sxe2_gstrings_vsi_hw_stats[j].stats_offset;
		data[i++] = *(u64 *)p;
	}

	user_vsi = vf_node->dpdk_vf_vsi;
	if (user_vsi)  {
		sxe2_hw_vsi_stats_update(user_vsi);
		i = 0;
		vsi_hw_stats = &user_vsi->vsi_stats.vsi_hw_stats;
		for (j = 0; j < SXE2_VSI_HW_STATS_LEN; j++) {
			p = (char *)vsi_hw_stats +
			    sxe2_gstrings_vsi_hw_stats[j].stats_offset;
			data[i++] += *(u64 *)p;
		}
	}

l_unlock:
	mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_node->vf_idx));
}

STATIC void sxe2_get_ethtool_stats(struct net_device *netdev,
				   struct ethtool_stats __always_unused *stats,
				   u64 *data)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;

	__sxe2_get_ethtool_stats(netdev, stats, data, vsi);
}

STATIC int sxe2_get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return (int)SXE2_ALL_STATS_LEN(netdev);
	case ETH_SS_TEST:
		return sxe2_ethtool_selftest_count(netdev);
	case ETH_SS_PRIV_FLAGS:
		return SXE2_PRIV_FLAG_ARRAY_SIZE;
	default:
		return -EOPNOTSUPP;
	}
}

#ifdef GET_RINGPARAM_NEED_2_PARAMS
STATIC void sxe2_get_ringparam(struct net_device *netdev,
			       struct ethtool_ringparam *ring)
#else
STATIC void sxe2_get_ringparam(struct net_device *netdev,
			       struct ethtool_ringparam *ring,
			       struct kernel_ethtool_ringparam *kernel_ring,
			       struct netlink_ext_ack *extack)
#endif
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state))
		goto l_unlock;

	ring->rx_max_pending = SXE2_MAX_NUM_DESC;
	ring->tx_max_pending = SXE2_MAX_NUM_DESC;
	ring->rx_pending     = vsi->rxqs.q[0]->depth;
	ring->tx_pending     = vsi->txqs.q[0]->depth;

	ring->rx_mini_max_pending  = 0;
	ring->rx_jumbo_max_pending = 0;
	ring->rx_mini_pending	   = 0;
	ring->rx_jumbo_pending	   = 0;

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
}

static s32 sxe2_ethtool_checkparam(struct net_device *netdev,
				   struct ethtool_ringparam *ring,
				   u32 *tx_desc_num, u32 *rx_desc_num)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;

	if (ring->rx_mini_pending || ring->rx_jumbo_pending) {
		LOG_NETDEV_ERR("do not support set rx_mini_pending=%u or rx_jumbo_pending=%u\n",
			       ring->rx_mini_pending, ring->rx_jumbo_pending);
		return -EINVAL;
	}
	if (ring->tx_pending > SXE2_MAX_NUM_DESC ||
	    ring->tx_pending < SXE2_MIN_NUM_DESC) {
		LOG_NETDEV_ERR("tx queue depth(%d) is out of range [%d-%d] (increment %d)\n",
			       ring->tx_pending, SXE2_MIN_NUM_DESC, SXE2_MAX_NUM_DESC,
			       SXE2_DESC_ALIGN_32);
		return -EINVAL;
	}
	if (ring->rx_pending > SXE2_MAX_NUM_DESC ||
	    ring->rx_pending < SXE2_MIN_NUM_DESC) {
		LOG_NETDEV_ERR("rx queue depth(%d) is out of range [%d-%d] (increment %d)\n",
			       ring->rx_pending, SXE2_MIN_NUM_DESC, SXE2_MAX_NUM_DESC,
			       SXE2_DESC_ALIGN_32);
		return -EINVAL;
	}
	*tx_desc_num = ALIGN(ring->tx_pending, SXE2_DESC_ALIGN_32);
	if (*tx_desc_num != ring->tx_pending)
		LOG_NETDEV_INFO("requested tx descriptor count changed to %d\n",
				*tx_desc_num);

	*rx_desc_num = ALIGN(ring->rx_pending, SXE2_DESC_ALIGN_32);
	if (*rx_desc_num != ring->rx_pending)
		LOG_NETDEV_INFO("requested rx descriptor count changed to %d\n",
				*rx_desc_num);
	return 0;
}

static void sxe2_ringparam_set_offline(struct sxe2_vsi *vsi, u32 tx_size,
				       u32 rx_size)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct net_device *netdev    = vsi->netdev;

	u32 i;

	if (vsi->txqs.depth == tx_size) {
		LOG_NETDEV_DEBUG("tx desc depth[%d] not changed.\n", tx_size);
	} else {
		LOG_NETDEV_DEBUG("link is down, tx desc depth chang from [%d] to [%d] happens \t"
				 "when link is brought up.\n",
				 vsi->txqs.depth, tx_size);
		sxe2_for_each_vsi_txq(vsi, i) {
			vsi->txqs.q[i]->depth = (u16)tx_size;
		}

		if (sxe2_xdp_is_enable(vsi)) {
			for (i = 0; i < vsi->num_xdp_txq; i++)
				vsi->xdp_rings.q[i]->depth = (u16)tx_size;

			vsi->xdp_rings.depth = (u16)tx_size;
		}

		vsi->txqs.depth = (u16)tx_size;
	}

	if (vsi->rxqs.depth == rx_size) {
		LOG_NETDEV_DEBUG("rx desc depth[%d] not changed.\n", rx_size);
	} else {
		LOG_NETDEV_DEBUG("link is down, rx desc depth chang from [%d] to [%d] happens \t"
				 "when link is brought up.\n",
				 vsi->rxqs.depth, rx_size);
		sxe2_for_each_vsi_rxq(vsi, i) {
			vsi->rxqs.q[i]->depth = (u16)rx_size;
		}
		vsi->rxqs.depth = (u16)rx_size;
	}
}

#ifdef SET_RINGPARAM_NEED_2_PARAMS
STATIC int sxe2_set_ringparam(struct net_device *netdev,
			      struct ethtool_ringparam *ring)
#else
STATIC int sxe2_set_ringparam(struct net_device *netdev,
			      struct ethtool_ringparam *ring,
			      struct kernel_ethtool_ringparam *kernel_ring,
			      struct netlink_ext_ack *extack)
#endif
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;
	s32 ret			      = 0;
	u32 new_rx_size, new_tx_size;
	u32 old_rx_size, old_tx_size;

	ret = sxe2_ethtool_checkparam(netdev, ring, &new_tx_size, &new_rx_size);
	if (ret)
		goto out;

	old_rx_size = vsi->rxqs.depth;
	old_tx_size = vsi->txqs.depth;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		goto l_unlock;
	}

	if (netif_running(vsi->netdev)) {
		ret = sxe2_vsi_close(vsi);
		if (ret) {
			LOG_DEBUG_BDF("vsi close failed, vsi %d error %d\n",
				      vsi->idx_in_dev, ret);
			goto l_unlock;
		}
	}

	sxe2_ringparam_set_offline(vsi, new_tx_size, new_rx_size);

	if (netif_running(vsi->netdev)) {
		ret = sxe2_vsi_open(vsi);
		if (ret) {
			LOG_DEBUG_BDF("vsi open failed, vsi %d error %d\n",
				      vsi->idx_in_dev, ret);
			sxe2_ringparam_set_offline(vsi, old_tx_size,
						   old_rx_size);
			ret = sxe2_vsi_open(vsi);
			if (ret) {
				LOG_DEBUG_BDF("vsi open failed, vsi %d error %d\n",
					      vsi->idx_in_dev, ret);
			}
		}
	}

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
out:
	return ret;
}

STATIC void sxe2_analysis_hdrs(struct ethtool_rxnfc *nfc, unsigned long *hdrs)
{
	bitmap_zero(hdrs, SXE2_FLOW_HDR_MAX);
	switch (nfc->flow_type) {
	case TCP_V4_FLOW:
		set_bit(SXE2_FLOW_HDR_IPV4, hdrs);
		set_bit(SXE2_FLOW_HDR_TCP, hdrs);
		break;
	case UDP_V4_FLOW:
		set_bit(SXE2_FLOW_HDR_IPV4, hdrs);
		set_bit(SXE2_FLOW_HDR_UDP, hdrs);
		break;
	case SCTP_V4_FLOW:
		set_bit(SXE2_FLOW_HDR_IPV4, hdrs);
		set_bit(SXE2_FLOW_HDR_SCTP, hdrs);
		break;
	case TCP_V6_FLOW:
		set_bit(SXE2_FLOW_HDR_IPV6, hdrs);
		set_bit(SXE2_FLOW_HDR_TCP, hdrs);
		break;
	case UDP_V6_FLOW:
		set_bit(SXE2_FLOW_HDR_IPV6, hdrs);
		set_bit(SXE2_FLOW_HDR_UDP, hdrs);
		break;
	case SCTP_V6_FLOW:
		set_bit(SXE2_FLOW_HDR_IPV6, hdrs);
		set_bit(SXE2_FLOW_HDR_SCTP, hdrs);
		break;
	default:
		break;
	}
}

STATIC void sxe2_get_rss_flow(struct sxe2_vsi *vsi, struct ethtool_rxnfc *nfc)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	DECLARE_BITMAP(hash_flds, SXE2_FLOW_FLD_ID_MAX);
	DECLARE_BITMAP(hdrs, SXE2_FLOW_HDR_MAX);

	nfc->data = 0;

	if (sxe2_is_safe_mode(adapter)) {
		LOG_DEV_ERR("ethtool get rx flow hash in safe mode is not supported.\n");
		return;
	}

	sxe2_analysis_hdrs(nfc, hdrs);
	if (bitmap_empty(hdrs, SXE2_FLOW_HDR_MAX)) {
		LOG_INFO_BDF("header type is not valid, vsi:%d\n",
			     vsi->id_in_pf);
		return;
	}

	sxe2_rss_get_hash_cfg_with_hdrs(&adapter->rss_flow_ctxt, vsi->id_in_pf,
					hdrs, hash_flds);
	if (bitmap_empty(hash_flds, SXE2_FLOW_FLD_ID_MAX)) {
		LOG_INFO_BDF("no hash fields found for the given header type, vsi:%d\n",
			     vsi->id_in_pf);
		return;
	}

	if (test_bit(SXE2_FLOW_FLD_ID_IPV4_SA, hash_flds) ||
	    test_bit(SXE2_FLOW_FLD_ID_IPV6_SA, hash_flds)) {
		nfc->data |= (u64)RXH_IP_SRC;
	}

	if (test_bit(SXE2_FLOW_FLD_ID_IPV4_DA, hash_flds) ||
	    test_bit(SXE2_FLOW_FLD_ID_IPV6_DA, hash_flds)) {
		nfc->data |= (u64)RXH_IP_DST;
	}

	if (test_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, hash_flds) ||
	    test_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, hash_flds) ||
	    test_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, hash_flds)) {
		nfc->data |= (u64)RXH_L4_B_0_1;
	}

	if (test_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, hash_flds) ||
	    test_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, hash_flds) ||
	    test_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, hash_flds)) {
		nfc->data |= (u64)RXH_L4_B_2_3;
	}
}

STATIC u32 sxe2_ntuple_max_filter_cnt_get_by_vsi(struct sxe2_vsi *vsi)
{
	u32 acl_filter_cnt = 0;
	u32 fnav_filter_cnt = 0;
#ifdef SXE2_SUPPORT_ACL
	if (test_bit(SXE2_FLAG_ACL_CAPABLE, vsi->adapter->flags))
		acl_filter_cnt = vsi->adapter->acl_ctxt.acl_tbl_info->max_slot_cnt;
#endif
	fnav_filter_cnt = sxe2_fnav_max_filter_cnt_get_by_vsi(vsi);

	return acl_filter_cnt + fnav_filter_cnt;
}

STATIC enum sxe2_fnav_flow_type sxe2_ethtool_flow_to_type(u32 flow)
{
	enum sxe2_fnav_flow_type flow_type;

	switch (flow) {
	case ETHER_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_ETH;
		break;
	case TCP_V4_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV4_TCP;
		break;
	case UDP_V4_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV4_UDP;
		break;
	case SCTP_V4_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV4_SCTP;
		break;
	case IPV4_USER_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV4_OTHER;
		break;
	case TCP_V6_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV6_TCP;
		break;
	case UDP_V6_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV6_UDP;
		break;
	case SCTP_V6_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV6_SCTP;
		break;
	case IPV6_USER_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV6_OTHER;
		break;
	default:
		flow_type = SXE2_FNAV_FLOW_TYPE_NONE;
		break;
	}

	return flow_type;
}

STATIC u32 sxe2_flow_type_to_ethtool_flow(enum sxe2_fnav_flow_type flow_type)
{
	switch (flow_type) {
	case SXE2_FNAV_FLOW_TYPE_ETH:
		return ETHER_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
		return TCP_V4_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
		return UDP_V4_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV4_SCTP:
		return SCTP_V4_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV4_OTHER:
		return IPV4_USER_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
		return TCP_V6_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
		return UDP_V6_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV6_SCTP:
		return SCTP_V6_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV6_OTHER:
		return IPV6_USER_FLOW;
	default:
		return 0;
	}
}

STATIC int sxe2_ethtool_fnav_filter_get_by_loc(struct sxe2_vsi *vsi,
					       struct ethtool_rxnfc *cmd)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	int ret = 0;
	struct ethtool_rx_flow_spec *fsp =
		(struct ethtool_rx_flow_spec *)&cmd->fs;
	struct sxe2_fnav_filter *filter;
	u64 vf_id = 0;

	mutex_lock(&adapter->fnav_ctxt.filter_lock);
	filter = sxe2_fnav_find_filter_by_loc_unlock(&vsi->fnav,
						     fsp->location);

	if (!filter) {
		LOG_ERROR_BDF("filter in loc[%u] is not found.\n",
			      fsp->location);
		ret = -EINVAL;
		goto l_unlock;
	}

	fsp->flow_type = sxe2_flow_type_to_ethtool_flow(filter->flow_type);

	memset(&fsp->m_u, 0, sizeof(fsp->m_u));
	memset(&fsp->m_ext, 0, sizeof(fsp->m_ext));

	switch (fsp->flow_type) {
	case ETHER_FLOW:
		fsp->h_u.ether_spec = filter->full_key.eth;
		fsp->m_u.ether_spec = filter->full_key.eth_mask;
		break;
	case IPV4_USER_FLOW:
		fsp->h_u.usr_ip4_spec.ip_ver = ETH_RX_NFC_IP4;
		fsp->h_u.usr_ip4_spec.proto  = filter->full_key.ip.v4.proto;
		fsp->h_u.usr_ip4_spec.l4_4_bytes =
			filter->full_key.ip.v4.l4_header;
		fsp->h_u.usr_ip4_spec.tos    = filter->full_key.ip.v4.tos;
		fsp->h_u.usr_ip4_spec.ip4src = filter->full_key.ip.v4.src_ip;
		fsp->h_u.usr_ip4_spec.ip4dst = filter->full_key.ip.v4.dst_ip;
		fsp->m_u.usr_ip4_spec.ip4src = filter->full_key.mask.v4.src_ip;
		fsp->m_u.usr_ip4_spec.ip4dst = filter->full_key.mask.v4.dst_ip;
		fsp->m_u.usr_ip4_spec.ip_ver = 0xFF;
		fsp->m_u.usr_ip4_spec.proto  = filter->full_key.mask.v4.proto;
		fsp->m_u.usr_ip4_spec.l4_4_bytes =
			filter->full_key.mask.v4.l4_header;
		fsp->m_u.usr_ip4_spec.tos = filter->full_key.mask.v4.tos;
		break;
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
		fsp->h_u.tcp_ip4_spec.psrc   = filter->full_key.l4.src_port;
		fsp->h_u.tcp_ip4_spec.pdst   = filter->full_key.l4.dst_port;
		fsp->h_u.tcp_ip4_spec.ip4src = filter->full_key.ip.v4.src_ip;
		fsp->h_u.tcp_ip4_spec.ip4dst = filter->full_key.ip.v4.dst_ip;
		fsp->h_u.tcp_ip4_spec.tos    = filter->full_key.ip.v4.tos;
		fsp->m_u.tcp_ip4_spec.psrc = filter->full_key.l4_mask.src_port;
		fsp->m_u.tcp_ip4_spec.pdst = filter->full_key.l4_mask.dst_port;
		fsp->m_u.tcp_ip4_spec.ip4src = filter->full_key.mask.v4.src_ip;
		fsp->m_u.tcp_ip4_spec.ip4dst = filter->full_key.mask.v4.dst_ip;
		fsp->m_u.tcp_ip4_spec.tos    = filter->full_key.mask.v4.tos;
		break;
	case IPV6_USER_FLOW:
		fsp->h_u.usr_ip6_spec.l4_4_bytes =
			filter->full_key.ip.v6.l4_header;
		fsp->h_u.usr_ip6_spec.tclass   = filter->full_key.ip.v6.tc;
		fsp->h_u.usr_ip6_spec.l4_proto = filter->full_key.ip.v6.proto;
		memcpy(fsp->h_u.tcp_ip6_spec.ip6src,
		       filter->full_key.ip.v6.src_ip, sizeof(struct in6_addr));
		memcpy(fsp->h_u.tcp_ip6_spec.ip6dst,
		       filter->full_key.ip.v6.dst_ip, sizeof(struct in6_addr));
		memcpy(fsp->m_u.tcp_ip6_spec.ip6src,
		       filter->full_key.mask.v6.src_ip,
		       sizeof(struct in6_addr));
		memcpy(fsp->m_u.tcp_ip6_spec.ip6dst,
		       filter->full_key.mask.v6.dst_ip,
		       sizeof(struct in6_addr));
		fsp->m_u.usr_ip6_spec.l4_4_bytes =
			filter->full_key.mask.v6.l4_header;
		fsp->m_u.usr_ip6_spec.tclass   = filter->full_key.mask.v6.tc;
		fsp->m_u.usr_ip6_spec.l4_proto = filter->full_key.mask.v6.proto;
		break;
	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
	case SCTP_V6_FLOW:
		memcpy(fsp->h_u.tcp_ip6_spec.ip6src,
		       filter->full_key.ip.v6.src_ip, sizeof(struct in6_addr));
		memcpy(fsp->h_u.tcp_ip6_spec.ip6dst,
		       filter->full_key.ip.v6.dst_ip, sizeof(struct in6_addr));
		fsp->h_u.tcp_ip6_spec.psrc = filter->full_key.l4.src_port;
		fsp->h_u.tcp_ip6_spec.pdst = filter->full_key.l4.dst_port;
		memcpy(fsp->m_u.tcp_ip6_spec.ip6src,
		       filter->full_key.mask.v6.src_ip,
		       sizeof(struct in6_addr));
		memcpy(fsp->m_u.tcp_ip6_spec.ip6dst,
		       filter->full_key.mask.v6.dst_ip,
		       sizeof(struct in6_addr));
		fsp->m_u.tcp_ip6_spec.psrc = filter->full_key.l4_mask.src_port;
		fsp->m_u.tcp_ip6_spec.pdst = filter->full_key.l4_mask.dst_port;
		fsp->h_u.tcp_ip6_spec.tclass = filter->full_key.ip.v6.tc;
		fsp->m_u.tcp_ip6_spec.tclass = filter->full_key.mask.v6.tc;
		break;
	default:
		break;
	}

	if (filter->act_type == SXE2_FNAV_ACT_DROP) {
		fsp->ring_cookie = RX_CLS_FLOW_DISC;
	} else {
		fsp->ring_cookie = filter->origin_q_index;
		if (filter->ori_vsi_hw != filter->dst_vsi_hw) {
			vf_id = filter->vf_idx + 1;
			vf_id <<= ETHTOOL_RX_FLOW_SPEC_RING_VF_OFF;
			fsp->ring_cookie |= vf_id;
		}
	}

	if (filter->full_key.flow_ext) {
		fsp->flow_type |= FLOW_EXT;
		memcpy(fsp->h_ext.data, filter->full_key.ext_data.usr_def,
		       sizeof(fsp->h_ext.data));
		memcpy(fsp->m_ext.data, filter->full_key.ext_mask.usr_def,
		       sizeof(fsp->m_ext.data));
		fsp->h_ext.vlan_etype = filter->full_key.ext_data.vlan_type;
		fsp->m_ext.vlan_etype = filter->full_key.ext_mask.vlan_type;
		fsp->h_ext.vlan_tci   = filter->full_key.ext_data.s_vlan_tci;
		fsp->m_ext.vlan_tci   = filter->full_key.ext_mask.s_vlan_tci;
	}

l_unlock:
	mutex_unlock(&adapter->fnav_ctxt.filter_lock);
	return ret;
}

STATIC int sxe2_ethtool_ntuple_filter_locs_get(struct sxe2_vsi *vsi,
					       struct ethtool_rxnfc *cmd,
					       u32 *filter_locs)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	int ret			     = 0;
	unsigned int cnt	     = 0;
	struct sxe2_fnav_filter *filter;

	cmd->data = sxe2_ntuple_max_filter_cnt_get_by_vsi(vsi);
	if (cmd->data == 0)
		return -EOPNOTSUPP;
	mutex_lock(&adapter->fnav_ctxt.filter_lock);

	list_for_each_entry(filter, &vsi->fnav.filter_list,
			    l_node) {
		if (cnt == cmd->rule_cnt) {
			ret = -EMSGSIZE;
			break;
		}
		filter_locs[cnt] = filter->filter_loc;
		cnt++;
	}
	mutex_unlock(&adapter->fnav_ctxt.filter_lock);

	if (!ret)
		cmd->rule_cnt = cnt;

	return ret;
}

STATIC int sxe2_get_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd,
			  u32 __always_unused *rule_locs)
{
	int ret			      = -EOPNOTSUPP;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;

	if (sxe2_is_safe_mode(adapter)) {
		LOG_DEV_ERR("ethtool get rx flow in safe mode is not supported.\n");
		return -EINVAL;
	}

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = vsi->rss_ctxt.queue_size;
		ret	  = 0;
		break;
	case ETHTOOL_GRXCLSRLCNT:
		cmd->rule_cnt = vsi->fnav.filter_cnt;
		cmd->data     = sxe2_ntuple_max_filter_cnt_get_by_vsi(vsi);
		ret	      = 0;
		break;
	case ETHTOOL_GRXCLSRULE:
		ret = sxe2_ethtool_fnav_filter_get_by_loc(vsi, cmd);
		break;
	case ETHTOOL_GRXCLSRLALL:
		ret = sxe2_ethtool_ntuple_filter_locs_get(vsi, cmd,
							  (u32 *)rule_locs);
		break;
	case ETHTOOL_GRXFH:
		sxe2_get_rss_flow(vsi, cmd);
		ret = 0;
		break;
	default:
		break;
	}

	return ret;
}

STATIC void sxe2_analysis_hash_flds(struct ethtool_rxnfc *nfc,
				    unsigned long *hash_flds)
{
	bitmap_zero(hash_flds, SXE2_FLOW_FLD_ID_MAX);
	if (nfc->data & RXH_IP_SRC || nfc->data & RXH_IP_DST) {
		switch (nfc->flow_type) {
		case TCP_V4_FLOW:
		case UDP_V4_FLOW:
		case SCTP_V4_FLOW:
			if (nfc->data & RXH_IP_SRC)
				set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, hash_flds);

			if (nfc->data & RXH_IP_DST)
				set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, hash_flds);

			break;
		case TCP_V6_FLOW:
		case UDP_V6_FLOW:
		case SCTP_V6_FLOW:
			if (nfc->data & RXH_IP_SRC)
				set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, hash_flds);

			if (nfc->data & RXH_IP_DST)
				set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, hash_flds);

			break;
		default:
			break;
		}
	}

	if (nfc->data & RXH_L4_B_0_1 || nfc->data & RXH_L4_B_2_3) {
		switch (nfc->flow_type) {
		case TCP_V4_FLOW:
		case TCP_V6_FLOW:
			if (nfc->data & RXH_L4_B_0_1)
				set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, hash_flds);
			if (nfc->data & RXH_L4_B_2_3)
				set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, hash_flds);
			break;
		case UDP_V4_FLOW:
		case UDP_V6_FLOW:
			if (nfc->data & RXH_L4_B_0_1)
				set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, hash_flds);
			if (nfc->data & RXH_L4_B_2_3)
				set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, hash_flds);
			break;
		case SCTP_V4_FLOW:
		case SCTP_V6_FLOW:
			if (nfc->data & RXH_L4_B_0_1)
				set_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, hash_flds);
			if (nfc->data & RXH_L4_B_2_3)
				set_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, hash_flds);
			break;
		default:
			break;
		}
	}
}

STATIC int sxe2_set_rss_flow(struct sxe2_vsi *vsi, struct ethtool_rxnfc *nfc)
{
	int ret = 0;
	DECLARE_BITMAP(hdrs, SXE2_FLOW_HDR_MAX);
	DECLARE_BITMAP(hash_flds, SXE2_FLOW_FLD_ID_MAX);
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_rss_hash_cfg cfg;

	sxe2_analysis_hdrs(nfc, hdrs);
	if (bitmap_empty(hdrs, SXE2_FLOW_HDR_MAX)) {
		LOG_ERROR_BDF("invalid header type! vsi type: %u, idx: %u\n",
			      vsi->type, vsi->id_in_pf);
		return -EINVAL;
	}

	sxe2_analysis_hash_flds(nfc, hash_flds);
	if (bitmap_empty(hash_flds, SXE2_FLOW_FLD_ID_MAX)) {
		LOG_ERROR_BDF("invalid field type! vsi type: %u, idx: %u\n",
			      vsi->type, vsi->id_in_pf);
		return -EINVAL;
	}

	cfg.hdr_type = SXE2_RSS_ANY_HEADERS;
	bitmap_copy(cfg.headers, hdrs, SXE2_FLOW_HDR_MAX);
	bitmap_copy(cfg.hash_flds, hash_flds, SXE2_FLOW_FLD_ID_MAX);
	cfg.symm = false;

	ret = sxe2_add_rss_flow(&adapter->rss_flow_ctxt, vsi->id_in_pf, &cfg);
	if (ret != 0) {
		LOG_ERROR_BDF("invalid field type! vsi type: %u, idx: %u\n",
			      vsi->type, vsi->id_in_pf);
		return -EINVAL;
	}

	return 0;
}

#define SXE2_USERDEF_FLEX_WORD_M  GENMASK_ULL(15, 0)
#define SXE2_USERDEF_FLEX_OFF_S	  16
#define SXE2_USERDEF_FLEX_OFF_M	  GENMASK_ULL(31, SXE2_USERDEF_FLEX_OFF_S)
#define SXE2_USERDEF_FLEX_FLTR_M  GENMASK_ULL(31, 0)
#define SXE2_USERDEF_FLEX_MAX_OFF 0x1fe

STATIC int sxe2_ethtool_parse_ntuple_userdef(struct sxe2_fnav_filter *filter,
					     struct ethtool_rx_flow_spec *fsp)
{
	u64 value, mask;

	if (!(fsp->flow_type & FLOW_EXT))
		return 0;

	value = be64_to_cpu(*((__force __be64 *)fsp->h_ext.data));
	mask  = be64_to_cpu(*((__force __be64 *)fsp->m_ext.data));
	if (!mask)
		return 0;

	LOG_DEBUG("user-def param:0x%llx.\n", value);

	if (!((mask & SXE2_USERDEF_FLEX_FLTR_M) == SXE2_USERDEF_FLEX_FLTR_M) ||
	    value > SXE2_USERDEF_FLEX_FLTR_M) {
		return -EINVAL;
	}

	filter->full_key.flex_word =
		cpu_to_be16((u16)(value & SXE2_USERDEF_FLEX_WORD_M));
	filter->full_key.flex_offset =
		(u16)FIELD_GET(SXE2_USERDEF_FLEX_OFF_M, value);
	if (filter->full_key.flex_offset > SXE2_USERDEF_FLEX_MAX_OFF)
		return -EINVAL;

	filter->full_key.has_flex_filed = true;

	return 0;
}

STATIC int sxe2_ethtool_fnav_seg_eth_fill(struct ethhdr *eth_spec,
					  struct sxe2_fnav_flow_seg *seg)
{
	int ret = 0;

	set_bit(SXE2_FLOW_HDR_ETH, seg->headers);

	if (eth_spec->h_proto == htons(0xFFFF)) {
		set_bit(SXE2_FLOW_FLD_ID_ETH_TYPE, seg->fields);
	} else if (eth_spec->h_proto) {
		LOG_WARN("proto mask must be 0x0000 or 0xffff.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	if (is_broadcast_ether_addr(eth_spec->h_source)) {
		set_bit(SXE2_FLOW_FLD_ID_ETH_SA, seg->fields);
	} else if (!is_zero_ether_addr(eth_spec->h_source)) {
		LOG_WARN("src mask must be 00:00:00:00:00:00 or ff:ff:ff:ff:ff:ff.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	if (is_broadcast_ether_addr(eth_spec->h_dest)) {
		set_bit(SXE2_FLOW_FLD_ID_ETH_DA, seg->fields);
	} else if (!is_zero_ether_addr(eth_spec->h_dest)) {
		LOG_WARN("dst mask must be 00:00:00:00:00:00 or ff:ff:ff:ff:ff:ff.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

l_end:
	return ret;
}

STATIC bool sxe2_ethtool_vlan_seg_valid(struct ethtool_rx_flow_spec *fsp)
{
	bool ret = fsp->m_ext.vlan_etype || fsp->m_ext.vlan_tci;

	if (fsp->m_ext.vlan_etype &&
	    !(fsp->h_ext.vlan_etype == cpu_to_be16(ETH_P_8021Q) ||
	      fsp->h_ext.vlan_etype == cpu_to_be16(ETH_P_8021AD))) {
		ret = false;
		goto l_end;
	}

	if (fsp->m_ext.vlan_tci && ntohs(fsp->h_ext.vlan_tci) >= VLAN_N_VID) {
		ret = false;
		goto l_end;
	}

	if (fsp->m_u.ether_spec.h_proto && fsp->m_ext.vlan_tci &&
	    !fsp->m_ext.vlan_etype) {
		LOG_WARN("Filter with proto and vlan require also vlan-etype.\n");
		ret = false;
		goto l_end;
	}

l_end:
	return ret;
}

STATIC int sxe2_ethtool_fnav_seg_vlan_fill(struct ethtool_flow_ext *ext_mask,
					   struct sxe2_fnav_flow_seg *seg)
{
	int ret = 0;

	set_bit(SXE2_FLOW_HDR_VLAN, seg->headers);

	if (ext_mask->vlan_etype) {
		if (ext_mask->vlan_etype != htons(0xFFFF)) {
			ret = -EOPNOTSUPP;
			goto l_end;
		}
		set_bit(SXE2_FLOW_FLD_ID_S_TPID, seg->fields);
	}

	if (ext_mask->vlan_tci) {
		if (ext_mask->vlan_tci != htons(0xFFFF)) {
			ret = -EOPNOTSUPP;
			goto l_end;
		}
		set_bit(SXE2_FLOW_FLD_ID_S_TCI, seg->fields);
	}

l_end:
	return ret;
}

static int
sxe2_ethtool_fnav_l4_ip4_seg_valid(struct ethtool_tcpip4_spec *l4_ip4_spec)
{
	int ret = 0;

	if (!l4_ip4_spec->psrc && !l4_ip4_spec->ip4src && !l4_ip4_spec->pdst &&
	    !l4_ip4_spec->ip4dst && !l4_ip4_spec->tos) {
		ret = -EINVAL;
		goto l_end;
	}

l_end:
	return ret;
}

STATIC int sxe2_ethtool_fnav_seg_l4_ip4_fill(struct ethtool_rx_flow_spec *fsp,
					     enum sxe2_flow_hdr l4_proto,
					     struct sxe2_fnav_flow_seg *seg,
					     bool *full_match)
{
	int ret = 0;
	enum sxe2_flow_fld_id sport, dport;
	struct ethtool_tcpip4_spec *l4_ip4_spec = &fsp->m_u.tcp_ip4_spec;

	ret = sxe2_ethtool_fnav_l4_ip4_seg_valid(l4_ip4_spec);
	if (ret) {
		LOG_ERROR("l4 ipv4 seg is invalid, ret:%d.", ret);
		goto l_end;
	}

	if (fsp->m_ext.vlan_etype || fsp->m_ext.vlan_tci ||
	    !(is_zero_ether_addr(fsp->m_ext.h_dest))) {
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	switch (l4_proto) {
	case SXE2_FLOW_HDR_TCP:
		sport = SXE2_FLOW_FLD_ID_TCP_SRC_PORT;
		dport = SXE2_FLOW_FLD_ID_TCP_DST_PORT;
		break;
	case SXE2_FLOW_HDR_UDP:
		sport = SXE2_FLOW_FLD_ID_UDP_SRC_PORT;
		dport = SXE2_FLOW_FLD_ID_UDP_DST_PORT;
		break;
	case SXE2_FLOW_HDR_SCTP:
		sport = SXE2_FLOW_FLD_ID_SCTP_SRC_PORT;
		dport = SXE2_FLOW_FLD_ID_SCTP_DST_PORT;
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}
	if (ret) {
		LOG_ERROR("l4 protocol type is invalid, ret:%d.\n", ret);
		goto l_end;
	}

	*full_match = true;
	set_bit(SXE2_FLOW_HDR_IPV4, seg->headers);
	set_bit((int)l4_proto, seg->headers);

	if (l4_ip4_spec->ip4src == htonl(0xFFFFFFFF)) {
		set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, seg->fields);
	} else if (!l4_ip4_spec->ip4src) {
		*full_match = false;
	} else {
		LOG_ERROR("src-ip is invalid.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	if (l4_ip4_spec->ip4dst == htonl(0xFFFFFFFF)) {
		set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, seg->fields);
	} else if (!l4_ip4_spec->ip4dst) {
		*full_match = false;
	} else {
		LOG_ERROR("dst-ip is invalid.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	if (l4_ip4_spec->psrc == htons(0xFFFF)) {
		set_bit((int)sport, seg->fields);
	} else if (!l4_ip4_spec->psrc) {
		*full_match = false;
	} else {
		LOG_ERROR("src-port is invalid.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	if (l4_ip4_spec->pdst == htons(0xFFFF)) {
		set_bit((int)dport, seg->fields);
	} else if (!l4_ip4_spec->pdst) {
		*full_match = false;
	} else {
		LOG_ERROR("dst-port is invalid.\n");
		ret = -EOPNOTSUPP;
	}

	if (l4_ip4_spec->tos == 0xFF) {
		set_bit(SXE2_FLOW_FLD_ID_IPV4_TOS, seg->fields);
		*full_match = false;
	} else if (l4_ip4_spec->tos) {
		LOG_ERROR("tos is invalid.\n");
		ret = -EOPNOTSUPP;
	}

l_end:
	return ret;
}

static int
sxe2_ethtool_fnav_usr_ip4_seg_valid(struct ethtool_usrip4_spec *usr_ip4_spec)
{
	if (usr_ip4_spec->l4_4_bytes)
		return -EOPNOTSUPP;
	if (usr_ip4_spec->ip_ver)
		return -EOPNOTSUPP;
	if (!usr_ip4_spec->ip4src && !usr_ip4_spec->ip4dst &&
	    !usr_ip4_spec->tos && !usr_ip4_spec->proto)
		return -EINVAL;

	return 0;
}

STATIC int sxe2_ethtool_fnav_seg_usr_ip4_fill(struct ethtool_rx_flow_spec *fsp,
					      struct sxe2_fnav_flow_seg *seg,
					      bool *full_match)
{
	int ret					 = 0;
	struct ethtool_usrip4_spec *usr_ip4_spec = &fsp->m_u.usr_ip4_spec;

	ret = sxe2_ethtool_fnav_usr_ip4_seg_valid(usr_ip4_spec);
	if (ret) {
		LOG_ERROR("usr ipv4 seg is invalid, ret:%d.", ret);
		goto l_end;
	}

	if (fsp->m_ext.vlan_etype || fsp->m_ext.vlan_tci ||
	    !(is_zero_ether_addr(fsp->m_ext.h_dest))) {
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	if (usr_ip4_spec->proto == 0xFF &&
	    (fsp->h_u.usr_ip4_spec.proto == SXE2_FNAV_L4_PROT_TCP ||
	     fsp->h_u.usr_ip4_spec.proto == SXE2_FNAV_L4_PROT_UDP ||
	     fsp->h_u.usr_ip4_spec.proto == SXE2_FNAV_L4_PROT_SCTP)) {
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	*full_match = true;
	set_bit(SXE2_FLOW_HDR_IPV4, seg->headers);

	if (usr_ip4_spec->ip4src == htonl(0xFFFFFFFF)) {
		set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, seg->fields);
	} else if (!usr_ip4_spec->ip4src) {
		*full_match = false;
	} else {
		LOG_ERROR("src-ip is invalid.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	if (usr_ip4_spec->ip4dst == htonl(0xFFFFFFFF)) {
		set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, seg->fields);
	} else if (!usr_ip4_spec->ip4dst) {
		*full_match = false;
	} else {
		LOG_ERROR("dst-ip is invalid.\n");
		ret = -EOPNOTSUPP;
	}

	if (usr_ip4_spec->tos == 0xFF) {
		set_bit(SXE2_FLOW_FLD_ID_IPV4_TOS, seg->fields);
		*full_match = false;
	} else if (usr_ip4_spec->tos) {
		LOG_ERROR("tos is invalid.\n");
		ret = -EOPNOTSUPP;
	}

	if (usr_ip4_spec->proto == 0xFF) {
		set_bit(SXE2_FLOW_FLD_ID_IPV4_PROT, seg->fields);
		*full_match = false;
	} else if (usr_ip4_spec->proto) {
		LOG_ERROR("proto is invalid.\n");
		ret = -EOPNOTSUPP;
	}

l_end:
	return ret;
}

static int
sxe2_ethtool_fnav_l4_ip6_seg_valid(struct ethtool_tcpip6_spec *l4_ip6_spec)
{
	int ret = 0;

	if (ipv6_addr_any((struct in6_addr *)l4_ip6_spec->ip6src) &&
	    ipv6_addr_any((struct in6_addr *)l4_ip6_spec->ip6dst) &&
	    !l4_ip6_spec->psrc && !l4_ip6_spec->pdst && !l4_ip6_spec->tclass) {
		ret = -EINVAL;
		goto l_end;
	}

l_end:
	return ret;
}

static inline bool sxe2_ethtool_ntuple_ipv6_mask_full(const __be32 *a)
{
	return (a[0] & a[1] & a[2] & a[3]) == cpu_to_be32(0xffffffff);
}

STATIC int sxe2_ethtool_fnav_seg_l4_ip6_fill(struct ethtool_rx_flow_spec *fsp,
					     enum sxe2_flow_hdr l4_proto,
					     struct sxe2_fnav_flow_seg *seg,
					     bool *full_match)
{
	int ret = 0;
	enum sxe2_flow_fld_id sport, dport;
	struct ethtool_tcpip6_spec *l4_ip6_spec = &fsp->m_u.tcp_ip6_spec;

	ret = sxe2_ethtool_fnav_l4_ip6_seg_valid(l4_ip6_spec);
	if (ret) {
		LOG_ERROR("l4 ipv6 seg is invalid, ret:%d.", ret);
		goto l_end;
	}

	if (fsp->m_ext.vlan_etype || fsp->m_ext.vlan_tci ||
	    !(is_zero_ether_addr(fsp->m_ext.h_dest))) {
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	switch (l4_proto) {
	case SXE2_FLOW_HDR_TCP:
		sport = SXE2_FLOW_FLD_ID_TCP_SRC_PORT;
		dport = SXE2_FLOW_FLD_ID_TCP_DST_PORT;
		break;
	case SXE2_FLOW_HDR_UDP:
		sport = SXE2_FLOW_FLD_ID_UDP_SRC_PORT;
		dport = SXE2_FLOW_FLD_ID_UDP_DST_PORT;
		break;
	case SXE2_FLOW_HDR_SCTP:
		sport = SXE2_FLOW_FLD_ID_SCTP_SRC_PORT;
		dport = SXE2_FLOW_FLD_ID_SCTP_DST_PORT;
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}
	if (ret) {
		LOG_ERROR("l4 protocol type is invalid, ret:%d.\n", ret);
		goto l_end;
	}

	*full_match = true;
	set_bit(SXE2_FLOW_HDR_IPV6, seg->headers);
	set_bit((int)l4_proto, seg->headers);

	if (sxe2_ethtool_ntuple_ipv6_mask_full(l4_ip6_spec->ip6src)) {
		set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, seg->fields);
	} else if (ipv6_addr_any((struct in6_addr *)l4_ip6_spec->ip6src)) {
		*full_match = false;
	} else {
		LOG_ERROR("src-ip is invalid.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	if (sxe2_ethtool_ntuple_ipv6_mask_full(l4_ip6_spec->ip6dst)) {
		set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, seg->fields);
	} else if (ipv6_addr_any((struct in6_addr *)l4_ip6_spec->ip6dst)) {
		*full_match = false;
	} else {
		LOG_ERROR("dst-ip is invalid.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	if (l4_ip6_spec->psrc == htons(0xFFFF)) {
		set_bit((int)sport, seg->fields);
	} else if (!l4_ip6_spec->psrc) {
		*full_match = false;
	} else {
		LOG_ERROR("src-port is invalid.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	if (l4_ip6_spec->pdst == htons(0xFFFF)) {
		set_bit((int)dport, seg->fields);
	} else if (!l4_ip6_spec->pdst) {
		*full_match = false;
	} else {
		LOG_ERROR("dst-port is invalid.\n");
		ret = -EOPNOTSUPP;
	}

	if (l4_ip6_spec->tclass == 0xFF) {
		set_bit(SXE2_FLOW_FLD_ID_IPV6_DSCP, seg->fields);
		*full_match = false;
	} else if (l4_ip6_spec->tclass) {
		LOG_ERROR("tclass is invalid.\n");
		ret = -EOPNOTSUPP;
	}

l_end:
	return ret;
}

static int
sxe2_ethtool_fnav_usr_ip6_seg_valid(struct ethtool_usrip6_spec *usr_ip6_spec)
{
	if (usr_ip6_spec->l4_4_bytes)
		return -EOPNOTSUPP;
	if (ipv6_addr_any((struct in6_addr *)usr_ip6_spec->ip6src) &&
	    ipv6_addr_any((struct in6_addr *)usr_ip6_spec->ip6dst) &&
	    !usr_ip6_spec->l4_proto && !usr_ip6_spec->tclass)
		return -EINVAL;

	return 0;
}

STATIC int sxe2_fnav_seg_usr_ip6_addr_fill(const __be32 *addr,
					   enum sxe2_flow_fld_id fld_id,
					   struct sxe2_fnav_flow_seg *seg,
					   bool *full_match)
{
	int ret = 0;

	if (sxe2_ethtool_ntuple_ipv6_mask_full(addr))
		set_bit((int)fld_id, seg->fields);
	else if (ipv6_addr_any((struct in6_addr *)addr))
		*full_match = false;
	else
		ret = -EOPNOTSUPP;

	return ret;
}

STATIC int sxe2_ethtool_fnav_seg_usr_ip6_fill(struct ethtool_rx_flow_spec *fsp,
					      struct sxe2_fnav_flow_seg *seg,
					      bool *full_match)
{
	int ret					 = 0;
	struct ethtool_usrip6_spec *usr_ip6_spec = &fsp->m_u.usr_ip6_spec;

	ret = sxe2_ethtool_fnav_usr_ip6_seg_valid(usr_ip6_spec);
	if (ret) {
		LOG_ERROR("usr ipv6 seg is invalid, ret:%d.", ret);
		goto l_end;
	}

	if (fsp->m_ext.vlan_etype || fsp->m_ext.vlan_tci ||
	    !(is_zero_ether_addr(fsp->m_ext.h_dest))) {
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	if (usr_ip6_spec->l4_proto == 0xFF &&
	    (fsp->h_u.usr_ip6_spec.l4_proto == SXE2_FNAV_L4_PROT_TCP ||
	     fsp->h_u.usr_ip6_spec.l4_proto == SXE2_FNAV_L4_PROT_UDP ||
	     fsp->h_u.usr_ip6_spec.l4_proto == SXE2_FNAV_L4_PROT_SCTP)) {
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	*full_match = true;
	set_bit(SXE2_FLOW_HDR_IPV6, seg->headers);

	ret = sxe2_fnav_seg_usr_ip6_addr_fill(usr_ip6_spec->ip6src,
					      SXE2_FLOW_FLD_ID_IPV6_SA, seg,
					      full_match);
	if (ret) {
		LOG_ERROR("src-ip is invalid.\n");
		goto l_end;
	}

	ret = sxe2_fnav_seg_usr_ip6_addr_fill(usr_ip6_spec->ip6dst,
					      SXE2_FLOW_FLD_ID_IPV6_DA, seg,
					      full_match);
	if (ret)
		LOG_ERROR("dst-ip is invalid.\n");

	if (usr_ip6_spec->tclass == 0xFF) {
		set_bit(SXE2_FLOW_FLD_ID_IPV6_DSCP, seg->fields);
		*full_match = false;
	} else if (usr_ip6_spec->tclass) {
		LOG_ERROR("tclass is invalid.\n");
		ret = -EOPNOTSUPP;
	}

	if (usr_ip6_spec->l4_proto == 0xFF) {
		set_bit(SXE2_FLOW_FLD_ID_IPV6_PROT, seg->fields);
		*full_match = false;
	} else if (usr_ip6_spec->l4_proto) {
		LOG_ERROR("proto is invalid.\n");
		ret = -EOPNOTSUPP;
	}

l_end:
	return ret;
}

STATIC int sxe2_ethtool_fnav_seg_fill(struct ethtool_rx_flow_spec *fsp,
				      struct sxe2_fnav_flow_seg *seg,
				      bool *full_match)
{
	int ret = 0;
	enum sxe2_fnav_flow_type flow_type =
		sxe2_ethtool_flow_to_type(fsp->flow_type & ~FLOW_EXT);
	struct ethhdr *eth_spec = &fsp->m_u.ether_spec;

	switch (flow_type) {
	case SXE2_FNAV_FLOW_TYPE_ETH:
		if (is_zero_ether_addr(eth_spec->h_source) &&
		    is_zero_ether_addr(eth_spec->h_dest) &&
		    !eth_spec->h_proto &&
		    !fsp->m_ext.vlan_etype &&
		    !fsp->m_ext.vlan_tci) {
			ret = -EINVAL;
			break;
		}
		ret = sxe2_ethtool_fnav_seg_eth_fill(&fsp->m_u.ether_spec, seg);
		if (ret)
			break;

		if (fsp->m_ext.vlan_etype || fsp->m_ext.vlan_tci) {
			if (!sxe2_ethtool_vlan_seg_valid(fsp)) {
				ret = -EINVAL;
				break;
			}
			ret = sxe2_ethtool_fnav_seg_vlan_fill(&fsp->m_ext, seg);
		}
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
		ret = sxe2_ethtool_fnav_seg_l4_ip4_fill(fsp, SXE2_FLOW_HDR_TCP,
							seg, full_match);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
		ret = sxe2_ethtool_fnav_seg_l4_ip4_fill(fsp, SXE2_FLOW_HDR_UDP,
							seg, full_match);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_SCTP:
		ret = sxe2_ethtool_fnav_seg_l4_ip4_fill(fsp, SXE2_FLOW_HDR_SCTP,
							seg, full_match);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_OTHER:
		ret = sxe2_ethtool_fnav_seg_usr_ip4_fill(fsp, seg, full_match);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
		ret = sxe2_ethtool_fnav_seg_l4_ip6_fill(fsp, SXE2_FLOW_HDR_TCP,
							seg, full_match);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
		ret = sxe2_ethtool_fnav_seg_l4_ip6_fill(fsp, SXE2_FLOW_HDR_UDP,
							seg, full_match);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_SCTP:
		ret = sxe2_ethtool_fnav_seg_l4_ip6_fill(fsp, SXE2_FLOW_HDR_SCTP,
							seg, full_match);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_OTHER:
		ret = sxe2_ethtool_fnav_seg_usr_ip6_fill(fsp, seg, full_match);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	seg->is_tunnel = false;

	return ret;
}

STATIC s32 sxe2_ethtool_fnav_flow_cfg_parse(struct sxe2_vsi *vsi,
					    struct ethtool_rx_flow_spec *fsp,
					    struct sxe2_fnav_filter *filter,
					    struct sxe2_fnav_flow_seg *segs)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	int                  ret      = 0;
	struct sxe2_fnav_flow_seg *seg	   = NULL;
	struct sxe2_fnav_flow_seg *seg_tun = NULL;
	bool full_match    = false;

	memset(segs, 0, sizeof(struct sxe2_fnav_flow_seg) * SXE2_FNAV_SEG_MAX);
	seg = &segs[0];
	ret = sxe2_ethtool_fnav_seg_fill(fsp, seg, &full_match);
	if (ret) {
		LOG_ERROR_BDF("ethtool fill fnav seg failed, ret:%d.\n", ret);
		goto l_end;
	}

	if (filter->full_key.has_flex_filed) {
		full_match	   = false;
		seg->raw[0].offset = filter->full_key.flex_offset;
		seg->raw[0].len	   = SXE2_FNAV_FLEX_WROD_SIZE;
		seg->raw_cnt	   = 1;
	}

	if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY) {
		seg_tun = &segs[1];
		memcpy(seg_tun, seg, sizeof(*seg));
	}

	sxe2_eth_fnav_outer_hdr_set_eth(filter->flow_type, seg);

l_end:
	return ret;
}

STATIC int
sxe2_ethtool_fnav_full_key_fill(struct ethtool_rx_flow_spec *fsp,
				struct sxe2_fnav_filter_full_key *full_key)
{
	int ret = 0;
	enum sxe2_fnav_flow_type flow_type =
		sxe2_ethtool_flow_to_type(fsp->flow_type & ~FLOW_EXT);

	if (fsp->flow_type & FLOW_EXT) {
		memcpy(full_key->ext_data.usr_def, fsp->h_ext.data,
		       sizeof(full_key->ext_data.usr_def));
		full_key->ext_data.vlan_type  = fsp->h_ext.vlan_etype;
		full_key->ext_data.s_vlan_tci = fsp->h_ext.vlan_tci;
		memcpy(full_key->ext_mask.usr_def, fsp->m_ext.data,
		       sizeof(full_key->ext_mask.usr_def));
		full_key->ext_mask.vlan_type  = fsp->m_ext.vlan_etype;
		full_key->ext_mask.s_vlan_tci = fsp->m_ext.vlan_tci;
		full_key->flow_ext	      = true;
	}

	switch (flow_type) {
	case SXE2_FNAV_FLOW_TYPE_ETH:
		full_key->eth	   = fsp->h_u.ether_spec;
		full_key->eth_mask = fsp->m_u.ether_spec;
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
	case SXE2_FNAV_FLOW_TYPE_IPV4_SCTP:
		full_key->l4.dst_port	   = fsp->h_u.tcp_ip4_spec.pdst;
		full_key->l4.src_port	   = fsp->h_u.tcp_ip4_spec.psrc;
		full_key->ip.v4.dst_ip	   = fsp->h_u.tcp_ip4_spec.ip4dst;
		full_key->ip.v4.src_ip	   = fsp->h_u.tcp_ip4_spec.ip4src;
		full_key->ip.v4.tos	   = fsp->h_u.tcp_ip4_spec.tos;
		full_key->l4_mask.dst_port = fsp->m_u.tcp_ip4_spec.pdst;
		full_key->l4_mask.src_port = fsp->m_u.tcp_ip4_spec.psrc;
		full_key->mask.v4.dst_ip   = fsp->m_u.tcp_ip4_spec.ip4dst;
		full_key->mask.v4.src_ip   = fsp->m_u.tcp_ip4_spec.ip4src;
		full_key->mask.v4.tos	   = fsp->m_u.tcp_ip4_spec.tos;
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_OTHER:
		full_key->ip.v4.dst_ip	    = fsp->h_u.usr_ip4_spec.ip4dst;
		full_key->ip.v4.src_ip	    = fsp->h_u.usr_ip4_spec.ip4src;
		full_key->ip.v4.l4_header   = fsp->h_u.usr_ip4_spec.l4_4_bytes;
		full_key->ip.v4.proto	    = fsp->h_u.usr_ip4_spec.proto;
		full_key->ip.v4.tos	    = fsp->h_u.usr_ip4_spec.tos;
		full_key->mask.v4.dst_ip    = fsp->m_u.usr_ip4_spec.ip4dst;
		full_key->mask.v4.src_ip    = fsp->m_u.usr_ip4_spec.ip4src;
		full_key->mask.v4.l4_header = fsp->m_u.usr_ip4_spec.l4_4_bytes;
		full_key->mask.v4.proto	    = fsp->m_u.usr_ip4_spec.proto;
		full_key->mask.v4.tos	    = fsp->m_u.usr_ip4_spec.tos;
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
	case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
	case SXE2_FNAV_FLOW_TYPE_IPV6_SCTP:
		memcpy(full_key->ip.v6.dst_ip, fsp->h_u.tcp_ip6_spec.ip6dst,
		       sizeof(struct in6_addr));
		memcpy(full_key->ip.v6.src_ip, fsp->h_u.tcp_ip6_spec.ip6src,
		       sizeof(struct in6_addr));
		full_key->l4.dst_port = fsp->h_u.tcp_ip6_spec.pdst;
		full_key->l4.src_port = fsp->h_u.tcp_ip6_spec.psrc;
		full_key->ip.v6.tc    = fsp->h_u.tcp_ip6_spec.tclass;
		memcpy(full_key->mask.v6.dst_ip, fsp->m_u.tcp_ip6_spec.ip6dst,
		       sizeof(struct in6_addr));
		memcpy(full_key->mask.v6.src_ip, fsp->m_u.tcp_ip6_spec.ip6src,
		       sizeof(struct in6_addr));
		full_key->l4_mask.dst_port = fsp->m_u.tcp_ip6_spec.pdst;
		full_key->l4_mask.src_port = fsp->m_u.tcp_ip6_spec.psrc;
		full_key->mask.v6.tc	   = fsp->m_u.tcp_ip6_spec.tclass;
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_OTHER:
		memcpy(full_key->ip.v6.dst_ip, fsp->h_u.usr_ip6_spec.ip6dst,
		       sizeof(struct in6_addr));
		memcpy(full_key->ip.v6.src_ip, fsp->h_u.usr_ip6_spec.ip6src,
		       sizeof(struct in6_addr));
		full_key->ip.v6.l4_header = fsp->h_u.usr_ip6_spec.l4_4_bytes;
		full_key->ip.v6.tc	  = fsp->h_u.usr_ip6_spec.tclass;

		if (!fsp->m_u.usr_ip6_spec.l4_proto)
			full_key->ip.v6.proto = IPPROTO_NONE;
		else
			full_key->ip.v6.proto = fsp->h_u.usr_ip6_spec.l4_proto;

		memcpy(full_key->mask.v6.dst_ip, fsp->m_u.usr_ip6_spec.ip6dst,
		       sizeof(struct in6_addr));
		memcpy(full_key->mask.v6.src_ip, fsp->m_u.usr_ip6_spec.ip6src,
		       sizeof(struct in6_addr));
		full_key->mask.v6.l4_header = fsp->m_u.usr_ip6_spec.l4_4_bytes;
		full_key->mask.v6.tc	    = fsp->m_u.usr_ip6_spec.tclass;
		full_key->mask.v6.proto	    = fsp->m_u.usr_ip6_spec.l4_proto;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

STATIC int sxe2_ethtool_fnav_filter_fill(struct sxe2_vsi *vsi,
					 struct ethtool_rx_flow_spec *fsp,
					 struct sxe2_fnav_filter *filter)
{
	int ret = 0;
	u64 ring;
	u16 vf;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_vf_node *vf_node = NULL;

	filter->flow_type =
		sxe2_ethtool_flow_to_type(fsp->flow_type & ~FLOW_EXT);
	if (filter->flow_type == SXE2_FNAV_FLOW_TYPE_NONE) {
		LOG_ERROR_BDF("unsupport flow type, fsp->flow_type:%d\n",
			      fsp->flow_type & ~FLOW_EXT);
		ret = -EINVAL;
		goto l_end;
	}

	filter->filter_loc = fsp->location;
	filter->fdid_prio = SXE2_FNAV_TX_DESC_QW1_FDID_PRIO_THREE;

	filter->ori_vsi_sw = vsi->id_in_pf;
	filter->ori_vsi_hw = vsi->idx_in_dev;
	filter->dst_vsi_hw = vsi->idx_in_dev;
	filter->rule_vsi_sw = vsi->id_in_pf;

	if (fsp->ring_cookie == RX_CLS_FLOW_DISC) {
		filter->act_type       = SXE2_FNAV_ACT_DROP;
		filter->origin_q_index = 0;
		filter->q_index	       = 0;
	} else if ((~(ETHTOOL_RX_FLOW_SPEC_RING |
		      ETHTOOL_RX_FLOW_SPEC_RING_VF)) &
		   fsp->ring_cookie) {
		LOG_DEV_ERR("failed to add filter. unsupported action %lld.\n",
			    fsp->ring_cookie);
		ret = -EOPNOTSUPP;
		goto l_end;
	} else {
		ring = (u32)ethtool_get_flow_spec_ring(fsp->ring_cookie);
		vf   = (u16)ethtool_get_flow_spec_ring_vf(fsp->ring_cookie);
		if (!vf) {
			if (ring >= vsi->rxqs.q_cnt)
				return -EINVAL;
			filter->origin_q_index = (u16)ring;
		} else {
			vf--;
			vf_node = sxe2_vf_node_get(adapter, vf);
			if (!vf_node || !vf_node->vsi ||
			    vf_node->vsi->idx_in_dev >= SXE2_VSI_NUM) {
				ret = -EINVAL;
				LOG_ERROR_BDF("add fnav filter failed, \t"
					      "vf node get failed, vf:%u\n", vf);
				goto l_end;
			}
			if (ring >= vf_node->vsi->rxqs.q_cnt) {
				ret = -EINVAL;
				LOG_ERROR_BDF("add fnav filter failed, queue index is invalid, \t"
					      "vf:%u, qidx:%llu, vf_qcnt:%u\n",
					      vf, ring, vf_node->vsi->rxqs.q_cnt);
				goto l_end;
			}
			filter->vf_idx	       = vf;
			filter->dst_vsi_hw     = vf_node->vsi->idx_in_dev;
			filter->origin_q_index = (u16)ring;
			LOG_DEBUG_BDF("add vf queues fnav filter, vf:%u, \t"
				      "queue:%llu, vf_vsi:%u, vf_qcnt:%u",
				      vf, ring, vf_node->vsi->id_in_pf,
				      vf_node->vsi->rxqs.q_cnt);
		}
		filter->act_type = SXE2_FNAV_ACT_QINDEX;
		filter->q_index	 = (u16)ring;
	}

	filter->q_region	= 0;
	filter->act_prio	= SXE2_FNAV_TX_DESC_QW0_TOQ_PRIO_THREE;
	filter->complete_report = SXE2_FNAV_TX_DESC_QW0_COMP_RPT_FAIL;
	filter->stat_ctrl	= SXE2_FNAV_TX_DESC_QW0_STAT_ENA_PKTS;
	filter->stat_index = adapter->fnav_ctxt.fnav_stat_ctxt.stat_rsv_idx[SXE2_FNAV_STAT_PF];

	INIT_HLIST_NODE(&filter->hl_node);

	ret = sxe2_ethtool_fnav_full_key_fill(fsp, &filter->full_key);

	if (test_bit(SXE2_FLAG_FNAV_TUNNEL_ENABLE, adapter->flags))
		filter->tunn_flag = SXE2_FNAV_TUN_FLAG_ANY;

l_end:
	return ret;
}

STATIC struct sxe2_fnav_filter *
sxe2_ethtool_fnav_filter_search_for_dup(struct sxe2_vsi *vsi,
					struct sxe2_fnav_filter *filter)
{
	bool ret;
	struct sxe2_fnav_filter *filter_tmp  = NULL;
	struct sxe2_fnav_filter *filter_find = NULL;

	list_for_each_entry(filter_tmp, &vsi->fnav.filter_list, l_node) {
		ret = sxe2_fnav_filter_cmp_with_flow_type(filter, filter_tmp);
		if (ret) {
			if (!(filter->filter_loc == filter_tmp->filter_loc &&
			      (filter->q_index != filter_tmp->q_index ||
			       filter->dst_vsi_hw != filter_tmp->dst_vsi_hw))) {
				filter_find = filter_tmp;
			}
			break;
		}
	}
	return filter_find;
}

#ifdef SXE2_SUPPORT_ACL
STATIC bool sxe2_is_acl_filter(struct ethtool_rx_flow_spec *fsp)
{
	struct ethtool_tcpip4_spec *tcp_ip4_spec;
	struct ethtool_usrip4_spec *usr_ip4_spec;
	struct ethhdr *eth_spec;

	switch (fsp->flow_type & ~FLOW_EXT) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
		tcp_ip4_spec = &fsp->m_u.tcp_ip4_spec;

		if (tcp_ip4_spec->ip4src &&
		    tcp_ip4_spec->ip4src != htonl(0xFFFFFFFF))
			return true;

		if (tcp_ip4_spec->ip4dst &&
		    tcp_ip4_spec->ip4dst != htonl(0xFFFFFFFF))
			return true;

		if (!tcp_ip4_spec->ip4src && !tcp_ip4_spec->ip4dst &&
		    !tcp_ip4_spec->psrc && !tcp_ip4_spec->pdst &&
		    !tcp_ip4_spec->tos)
			return true;

		if (tcp_ip4_spec->psrc && tcp_ip4_spec->psrc != htons(0xFFFF))
			return true;

		if (tcp_ip4_spec->pdst && tcp_ip4_spec->pdst != htons(0xFFFF))
			return true;

		break;
	case IPV4_USER_FLOW:
		usr_ip4_spec = &fsp->m_u.usr_ip4_spec;

		if (usr_ip4_spec->ip4src &&
		    usr_ip4_spec->ip4src != htonl(0xFFFFFFFF))
			return true;

		if (usr_ip4_spec->ip4dst &&
		    usr_ip4_spec->ip4dst != htonl(0xFFFFFFFF))
			return true;

		if (!usr_ip4_spec->ip4src && !usr_ip4_spec->ip4dst)
			return true;

		break;
	case ETHER_FLOW:
		eth_spec = &fsp->m_u.ether_spec;

		if (fsp->m_ext.vlan_tci || fsp->m_ext.vlan_etype)
			return false;

		if (!is_broadcast_ether_addr(eth_spec->h_dest) &&
		    !is_zero_ether_addr(eth_spec->h_dest))
			return true;

		if (!is_broadcast_ether_addr(eth_spec->h_source) &&
		    !is_zero_ether_addr(eth_spec->h_source))
			return true;

		if (eth_spec->h_proto && eth_spec->h_proto != htons(0xFFFF))
			return true;

		if (!eth_spec->h_proto &&
		    is_zero_ether_addr(eth_spec->h_source) &&
		    is_zero_ether_addr(eth_spec->h_dest))
			return true;

		break;
	}

	return false;
}

STATIC s32 sxe2_acl_ethtool_input_parse(struct sxe2_vsi *vsi, struct ethtool_rx_flow_spec *fsp,
					struct sxe2_acl_filter *filter)
{
	int ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;

	filter->flow_type =
			sxe2_ethtool_flow_to_type(fsp->flow_type & ~FLOW_EXT);
	if (filter->flow_type == SXE2_FNAV_FLOW_TYPE_NONE) {
		LOG_ERROR_BDF("unsupport flow type, fsp->flow_type:%d\n",
			      fsp->flow_type & ~FLOW_EXT);
		ret = -EINVAL;
		goto l_end;
	}

	filter->filter_id = SXE2_GEN_FILTER_ID(vsi->idx_in_dev, fsp->location);
	ret = sxe2_ethtool_fnav_full_key_fill(fsp, &filter->full_key);

l_end:
	return ret;
}

STATIC s32 sxe2_acl_ethtool_action_parse(struct sxe2_acl_flow_action *acts,
					 struct ethtool_rx_flow_spec *fsp,
					 struct sxe2_acl_filter *filter)
{
	int ret = 0;

	if (fsp->ring_cookie == RX_CLS_FLOW_DISC) {
		acts[0].type = SXE2_ACL_ACT_DROP;
		acts[0].data.acl_act.mdid = SXE2_ACL_ACTION_MDID_PKT_DROP;
		acts[0].data.acl_act.prio = 3;
		acts[0].data.acl_act.value = 0;
	} else {
		acts[0].type = SXE2_ACL_ACT_QINDEX;
		acts[0].data.acl_act.mdid = SXE2_ACL_ACTION_MDID_RX_DST_Q;
		acts[0].data.acl_act.prio = 3;
		acts[0].data.acl_act.value = ethtool_get_flow_spec_ring(fsp->ring_cookie);
	}

	return ret;
}

STATIC int sxe2_ethtool_acl_seg_eth_fill(struct ethhdr *eth_spec,
					 struct sxe2_fnav_flow_seg *seg)
{
	int ret = 0;

	set_bit(SXE2_FLOW_HDR_ETH, seg->headers);

	if (eth_spec->h_proto) {
		LOG_WARN("Ether proto type is not supported.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	set_bit(SXE2_FLOW_FLD_ID_ETH_SA, seg->fields);
	set_bit(SXE2_FLOW_FLD_ID_ETH_DA, seg->fields);

l_end:
	return ret;
}

STATIC int sxe2_ethtool_acl_seg_l4_ip4_fill(struct ethtool_rx_flow_spec *fsp,
					    enum sxe2_flow_hdr l4_proto,
					    struct sxe2_fnav_flow_seg *seg)
{
	int ret = 0;
	enum sxe2_flow_fld_id sport, dport;
	struct ethtool_tcpip4_spec *l4_ip4_spec = &fsp->m_u.tcp_ip4_spec;

	ret = sxe2_ethtool_fnav_l4_ip4_seg_valid(l4_ip4_spec);
	if (ret) {
		LOG_ERROR("l4 ipv4 seg is invalid, ret:%d.", ret);
		goto l_end;
	}

	switch (l4_proto) {
	case SXE2_FLOW_HDR_TCP:
		sport = SXE2_FLOW_FLD_ID_TCP_SRC_PORT;
		dport = SXE2_FLOW_FLD_ID_TCP_DST_PORT;
		break;
	case SXE2_FLOW_HDR_UDP:
		sport = SXE2_FLOW_FLD_ID_UDP_SRC_PORT;
		dport = SXE2_FLOW_FLD_ID_UDP_DST_PORT;
		break;
	case SXE2_FLOW_HDR_SCTP:
		sport = SXE2_FLOW_FLD_ID_SCTP_SRC_PORT;
		dport = SXE2_FLOW_FLD_ID_SCTP_DST_PORT;
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}
	if (ret) {
		LOG_ERROR("l4 protocol type is invalid, ret:%d.\n", ret);
		goto l_end;
	}

	set_bit(SXE2_FLOW_HDR_IPV4, seg->headers);
	set_bit((int)l4_proto, seg->headers);

	set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, seg->fields);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, seg->fields);
	set_bit((int)sport, seg->fields);
	set_bit((int)dport, seg->fields);

l_end:
	return ret;
}

STATIC int sxe2_ethtool_acl_seg_usr_ip4_fill(struct ethtool_rx_flow_spec *fsp,
					     struct sxe2_fnav_flow_seg *seg)
{
	int ret					 = 0;
	struct ethtool_usrip4_spec *usr_ip4_spec = &fsp->m_u.usr_ip4_spec;

	ret = sxe2_ethtool_fnav_usr_ip4_seg_valid(usr_ip4_spec);
	if (ret) {
		LOG_ERROR("usr ipv4 seg is invalid, ret:%d.", ret);
		goto l_end;
	}

	if (usr_ip4_spec->proto == 0xFF &&
	    (fsp->h_u.usr_ip4_spec.proto == SXE2_FNAV_L4_PROT_TCP ||
	     fsp->h_u.usr_ip4_spec.proto == SXE2_FNAV_L4_PROT_UDP ||
	     fsp->h_u.usr_ip4_spec.proto == SXE2_FNAV_L4_PROT_SCTP)) {
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	set_bit(SXE2_FLOW_HDR_IPV4, seg->headers);

	set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, seg->fields);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, seg->fields);

l_end:
	return ret;
}

STATIC int sxe2_ethtool_acl_seg_fill(struct ethtool_rx_flow_spec *fsp,
				     struct sxe2_fnav_flow_seg *seg)
{
	int ret = 0;
	enum sxe2_fnav_flow_type flow_type =
		sxe2_ethtool_flow_to_type(fsp->flow_type & ~FLOW_EXT);

	switch (flow_type) {
	case SXE2_FNAV_FLOW_TYPE_ETH:
		ret = sxe2_ethtool_acl_seg_eth_fill(&fsp->h_u.ether_spec, seg);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
		ret = sxe2_ethtool_acl_seg_l4_ip4_fill(fsp, SXE2_FLOW_HDR_TCP,
						       seg);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
		ret = sxe2_ethtool_acl_seg_l4_ip4_fill(fsp, SXE2_FLOW_HDR_UDP,
						       seg);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_SCTP:
		ret = sxe2_ethtool_acl_seg_l4_ip4_fill(fsp, SXE2_FLOW_HDR_SCTP,
						       seg);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_OTHER:
		ret = sxe2_ethtool_acl_seg_usr_ip4_fill(fsp, seg);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	seg->is_tunnel = false;

	return ret;
}

STATIC s32 sxe2_acl_ethtool_flow_cfg_add(struct sxe2_vsi *vsi,
					 struct ethtool_rx_flow_spec *fsp)
{
	s32 ret = 0;
	struct sxe2_fnav_flow_seg *seg = NULL;
	enum sxe2_fnav_flow_type flow_type;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_acl_flow_cfg *flow_cfg = NULL;
	bool new_alloc_flow = false;

	flow_type = sxe2_ethtool_flow_to_type(fsp->flow_type & ~FLOW_EXT);
	if (flow_type == SXE2_FNAV_FLOW_TYPE_NONE) {
		LOG_ERROR_BDF("unsupport flow type, fsp->flow_type:%d\n",
			      fsp->flow_type & ~FLOW_EXT);
		ret = -EINVAL;
		goto l_end;
	}

	seg = devm_kzalloc(dev, sizeof(*seg), GFP_KERNEL);
	if (!seg) {
		LOG_ERROR_BDF("no memory for seg.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	flow_cfg = sxe2_acl_find_flow_cfg_by_flow_type(vsi, flow_type);
	if (!flow_cfg) {
		flow_cfg = devm_kzalloc(dev, sizeof(*flow_cfg), GFP_KERNEL);
		if (!flow_cfg) {
			LOG_ERROR_BDF("no memory for flow cfg.\n");
			ret = -ENOMEM;
			goto l_free;
		}
		new_alloc_flow = true;
		flow_cfg->flow_type = flow_type;
	}

	ret = sxe2_ethtool_acl_seg_fill(fsp, seg);
	if (ret) {
		LOG_ERROR_BDF("ethtool fill fnav seg failed, ret:%d.\n", ret);
		goto l_free_flow_cfg;
	}

	ret = sxe2_acl_flow_cfg_add(vsi, flow_cfg, seg);
	if (ret == -EEXIST) {
		LOG_DEBUG_BDF("acl flow config exists, skip creation.\n");
		devm_kfree(dev, seg);
		if (new_alloc_flow)
			devm_kfree(dev, flow_cfg);

		ret = 0;
	} else if (ret) {
		LOG_ERROR_BDF("outer rule add failed, ret:%d\n", ret);
		goto l_free_flow_cfg;
	}

	if (ret == 0 && new_alloc_flow)
		sxe2_acl_flow_cfg_add_list(vsi, flow_cfg);

	goto l_end;

l_free_flow_cfg:
	if (new_alloc_flow)
		devm_kfree(dev, flow_cfg);

l_free:
	devm_kfree(dev, seg);
l_end:
	return ret;
}

s32 sxe2_acl_add_rule_ethtool(struct sxe2_vsi *vsi, struct ethtool_rx_flow_spec *fsp)
{
	s32 ret = 0;
	struct sxe2_acl_flow_action acts[1];
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_acl_filter *filter = NULL;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	if (!test_bit(SXE2_FLAG_ACL_CAPABLE, adapter->flags))
		return -EOPNOTSUPP;

	filter = devm_kzalloc(dev, sizeof(*filter), GFP_KERNEL);
	if (!filter) {
		LOG_ERROR_BDF("no memory for input.\n");
		ret = -ENOMEM;
		goto l_free;
	}

	ret = sxe2_acl_ethtool_input_parse(vsi, fsp, filter);
	if (ret) {
		LOG_ERROR_BDF("acl check input set failed.\n");
		goto l_free;
	}

	ret = sxe2_acl_ethtool_action_parse(acts, fsp, filter);
	if (ret) {
		LOG_ERROR_BDF("acl check action set failed.\n");
		goto l_free;
	}

	ret = sxe2_acl_ethtool_flow_cfg_add(vsi, fsp);
	if (ret) {
		LOG_ERROR_BDF("acl flow cfg add failed, ret:%d\n", ret);
		goto l_free;
	}

	ret = sxe2_acl_lut_entry_add(vsi, filter, acts);
	if (ret) {
		LOG_ERROR_BDF("acl lut entry add failed, ret:%d\n", ret);
		goto l_free;
	}

	goto l_end;

l_free:
	devm_kfree(dev, filter);
l_end:
	return ret;
}
#endif
STATIC int sxe2_ethtool_ntuple_filter_add(struct sxe2_vsi *vsi,
					  struct ethtool_rxnfc *cmd)
{
	int ret;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev	     = SXE2_ADAPTER_TO_DEV(adapter);
	struct ethtool_rx_flow_spec *fsp;
	struct sxe2_fnav_filter *filter		= NULL;
	struct sxe2_fnav_filter *filter_dup	= NULL;
	struct sxe2_fnav_filter *filter_loc_old = NULL;
	u32 avail_filter_num			= 0;
	u32 max_filter_cnt;
	u8 filter_need = 0;
	struct sxe2_fnav_flow_seg segs[SXE2_FNAV_SEG_MAX];

	if (!test_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags)) {
		LOG_DEV_ERR("ntuple feature is not enabled, \t"
			    "please type in \"ethtool -K {dev} ntuple on\" \t"
			    "to enable ntuple firstly.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	mutex_lock(&adapter->fnav_ctxt.fnav_state_lock);
	if (adapter->fnav_ctxt.state != SXE2_FNAV_STATE_READY) {
		ret = -EBUSY;
		goto l_unlock;
	}

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;

	if (fsp->flow_type & FLOW_MAC_EXT) {
		LOG_ERROR_BDF("unsupport flow type \"FLOW_MAC_EXT\".\n");
		ret = -EOPNOTSUPP;
		goto l_unlock;
	}

	max_filter_cnt = sxe2_ntuple_max_filter_cnt_get_by_vsi(vsi);

	if (fsp->location >= max_filter_cnt) {
		LOG_ERROR_BDF("location overflow, loc:%u, max_cnt:%u.\n",
			      fsp->location, max_filter_cnt);
		ret = -ENOSPC;
		goto l_unlock;
	}
#ifdef SXE2_SUPPORT_ACL
	if (sxe2_is_acl_filter(fsp)) {
		mutex_unlock(&adapter->fnav_ctxt.fnav_state_lock);
		ret = sxe2_acl_add_rule_ethtool(vsi, fsp);
		if (ret)
			LOG_ERROR_BDF("acl add rule failed, ret:%d\n", ret);

		goto l_end;
	}
#endif
	mutex_lock(&adapter->fnav_ctxt.filter_lock);

	filter_need = test_bit(SXE2_FLAG_FNAV_TUNNEL_ENABLE, adapter->flags) ? 2 : 1;
	filter_loc_old = sxe2_fnav_find_filter_by_loc_unlock(&vsi->fnav, fsp->location);
	if (filter_loc_old)
		avail_filter_num = filter_loc_old->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY ? 2 : 1;

	avail_filter_num += sxe2_fnav_num_avail_filter(vsi);
	if (avail_filter_num < filter_need) {
		LOG_ERROR_BDF("filter cnt overflow, filter_need:%u.\n",
			      filter_need);
		ret = -ENOSPC;
		goto l_filter_unlock;
	}

	filter = devm_kzalloc(dev, sizeof(*filter), GFP_KERNEL);
	if (!filter) {
		LOG_ERROR_BDF("no memory.\n");
		ret = -ENOMEM;
		goto l_filter_unlock;
	}

	ret = sxe2_ethtool_parse_ntuple_userdef(filter, fsp);
	if (ret) {
		LOG_ERROR_BDF("invalid user-def param:0x%llx.\n",
			      be64_to_cpu(*((__force __be64 *)fsp->h_ext.data)));
		ret = -EINVAL;
		goto l_filter_unlock;
	}

	ret = sxe2_ethtool_fnav_filter_fill(vsi, fsp, filter);
	if (ret) {
		LOG_ERROR_BDF("ethtool fnav filter fill failed, ret:%d\n", ret);
		goto l_filter_unlock;
	}

	filter_dup = sxe2_ethtool_fnav_filter_search_for_dup(vsi, filter);
	if (filter_dup) {
		LOG_DEV_ERR("duplicate rule is detected, id:%u.\n",
			    filter_dup->filter_loc);
		ret = -EINVAL;
		goto l_filter_unlock;
	}

	if (filter_loc_old) {
		ret = sxe2_fnav_filter_del(vsi, filter_loc_old);
		if (ret)
			goto l_filter_unlock;
	}

	ret = sxe2_ethtool_fnav_flow_cfg_parse(vsi, fsp, filter, segs);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf fnav parse pattern fail ret: %d ! \t"
			      "vsi type: %u, idx: %u\n", ret, vsi->type, vsi->id_in_pf);
		goto l_filter_unlock;
	}
	ret = sxe2_fnav_filter_add_hw(vsi, filter, segs);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf fnav parse pattern fail ret: %d ! vsi type: %u, idx: %u\n",
			      ret, vsi->type, vsi->id_in_pf);
		goto l_filter_unlock;
	}

	sxe2_fnav_filter_add_list_by_loc(vsi, filter);

	LOG_INFO_BDF("add filter success, flow_type: %d, total cnt: %u\n",
		     fsp->flow_type, vsi->fnav.filter_cnt);

l_filter_unlock:
	mutex_unlock(&adapter->fnav_ctxt.filter_lock);
l_unlock:
	mutex_unlock(&adapter->fnav_ctxt.fnav_state_lock);
l_end:
	if (filter && ret)
		devm_kfree(dev, filter);

	return ret;
}

STATIC int sxe2_ethtool_ntuple_filter_del(struct sxe2_vsi *vsi,
					  struct ethtool_rxnfc *cmd)
{
	int ret			     = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct ethtool_rx_flow_spec *fsp =
		(struct ethtool_rx_flow_spec *)&cmd->fs;

	mutex_lock(&adapter->fnav_ctxt.fnav_state_lock);
	if (adapter->fnav_ctxt.state != SXE2_FNAV_STATE_READY) {
		mutex_unlock(&adapter->fnav_ctxt.fnav_state_lock);
		ret = -EBUSY;
		goto l_end;
	}
	ret = sxe2_fnav_del_filter_by_loc(vsi, fsp->location);
	mutex_unlock(&adapter->fnav_ctxt.fnav_state_lock);
#ifdef SXE2_SUPPORT_ACL
	if (ret == -ENOENT) {
		ret =
		   sxe2_acl_del_filter_by_id(vsi,
					     SXE2_GEN_FILTER_ID(vsi->idx_in_dev, fsp->location));
	}
#endif
l_end:
	return ret;
}

STATIC bool sxe2_ethtool_fnav_is_action_to_vf(struct sxe2_adapter *adapter,
					      struct ethtool_rxnfc *cmd, u16 *vf_idx)
{
	struct ethtool_rx_flow_spec *fsp;
	u64                       vf;
	struct sxe2_fnav_filter  *filter    = NULL;
	bool                      is_to_vf  = false;
	struct sxe2_vsi          *vsi       = adapter->vsi_ctxt.main_vsi;

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;

	switch (cmd->cmd) {
	case ETHTOOL_SRXCLSRLINS:
		if (fsp->ring_cookie == RX_CLS_FLOW_DISC ||
		    ((~(ETHTOOL_RX_FLOW_SPEC_RING |
			ETHTOOL_RX_FLOW_SPEC_RING_VF)) &
		     fsp->ring_cookie)) {
			break;
		}
		vf = ethtool_get_flow_spec_ring_vf(fsp->ring_cookie);
		if (vf) {
			is_to_vf = true;
			*vf_idx	 = (u16)(vf - 1);
		}
		break;
	case ETHTOOL_SRXCLSRLDEL:
		filter = sxe2_fnav_find_filter_by_loc_lock(vsi,
							   fsp->location);
		if (filter && filter->ori_vsi_hw != filter->dst_vsi_hw)
			is_to_vf = true;
		break;
	default:
		break;
	}
	return is_to_vf;
}

STATIC int sxe2_set_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd)
{
	int ret			      = -EOPNOTSUPP;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;
	u16 vf_idx		      = 0;
	bool is_action_to_vf	      = false;

	LOG_DEBUG_BDF("set rxnfc, cmd: %u\n", cmd->cmd);

	if (sxe2_is_safe_mode(adapter)) {
		LOG_DEV_ERR("ethtool set rx flow in safe mode is not supported.\n");
		return -EINVAL;
	}

	is_action_to_vf =
		sxe2_ethtool_fnav_is_action_to_vf(adapter, cmd, &vf_idx);
	if (is_action_to_vf) {
		if (sxe2_vf_id_check(adapter, vf_idx)) {
			LOG_ERROR_BDF("vf id is invalid, vf:%u\n", vf_idx);
			return -EINVAL;
		}
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	}
	mutex_lock(&adapter->vsi_ctxt.lock);

	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		goto l_unlock;
	}

	switch (cmd->cmd) {
	case ETHTOOL_SRXCLSRLINS:
		ret = sxe2_ethtool_ntuple_filter_add(vsi, cmd);
		break;
	case ETHTOOL_SRXCLSRLDEL:
		ret = sxe2_ethtool_ntuple_filter_del(vsi, cmd);
		break;
	case ETHTOOL_SRXFH:
		ret = sxe2_set_rss_flow(vsi, cmd);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	if (is_action_to_vf)
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));

	return ret;
}

STATIC u32 sxe2_get_rxft_key_size(struct net_device __always_unused *netdev)
{
	return SXE2_RSS_HASH_KEY_SIZE;
}

STATIC u32 sxe2_get_rxft_indir_size(struct net_device *netdev)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;

	LOG_DEBUG_BDF("rss lut size: %u\n", vsi->rss_ctxt.lut_size);

	return (u32)vsi->rss_ctxt.lut_size;
}

#ifdef HAVE_ETHTOOL_RXFH_PARAM
STATIC int sxe2_get_rxfh(struct net_device *netdev,
			 struct ethtool_rxfh_param *rxfh)
#else
STATIC int sxe2_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key,
			 u8 *hfunc)
#endif
{
	int ret			      = 0;
	u32 i			      = 0;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;

	if (sxe2_is_safe_mode(adapter)) {
		LOG_DEV_ERR("ethtool get rx flow hash in safe mode is not supported.\n");
		return -EINVAL;
	}

#ifdef HAVE_ETHTOOL_RXFH_PARAM
	u32 *indir  = rxfh->indir;
	u8 *key	    = rxfh->key;

	rxfh->hfunc = ETH_RSS_HASH_TOP;
#else
	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;
#endif

	if (indir) {
		if (vsi->rss_ctxt.lut) {
			for (i = 0; i < vsi->rss_ctxt.lut_size; i++)
				indir[i] = (u32)(vsi->rss_ctxt.lut[i]);
		}
	}

	if (key) {
		if (vsi->rss_ctxt.hkey)
			memcpy((key), vsi->rss_ctxt.hkey, SXE2_RSS_HASH_KEY_SIZE);
	}

	return ret;
}

#ifdef HAVE_ETHTOOL_RXFH_PARAM
STATIC int sxe2_set_rxfh(struct net_device *netdev,
			 struct ethtool_rxfh_param *rxfh,
			 struct netlink_ext_ack *extack)
#else
STATIC int sxe2_set_rxfh(struct net_device *netdev, const u32 *indir,
			 const u8 *key, const u8 hfunc)
#endif
{
	int ret			      = 0;
	u32 i			      = 0;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;
	struct device *dev	      = SXE2_ADAPTER_TO_DEV(adapter);
	u8 *user_key		      = NULL;
	u8 *user_lut		      = NULL;
#ifdef HAVE_ETHTOOL_RXFH_PARAM
	const u32 *indir	      = rxfh->indir;
	const u8 *key		      = rxfh->key;
	const u8 hfunc		      = rxfh->hfunc;
#endif

	if (sxe2_is_safe_mode(adapter)) {
		LOG_DEV_ERR("ethtool set rx flow hash in safe mode is not supported.\n");
		return -EINVAL;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		goto l_unlock;
	}

	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP) {
		ret = -EOPNOTSUPP;
		goto l_unlock;
	}

	if (key) {
		user_key =
			devm_kzalloc(dev, SXE2_RSS_HASH_KEY_SIZE, GFP_KERNEL);
		if (!user_key) {
			LOG_ERROR_BDF("no memory for user hash key.\n");
			ret = -ENOMEM;
			goto l_unlock;
		}
		memcpy(user_key, key, SXE2_RSS_HASH_KEY_SIZE);
	}

	if (indir) {
		user_lut =
			devm_kzalloc(dev, vsi->rss_ctxt.lut_size, GFP_KERNEL);
		if (!user_lut) {
			LOG_ERROR_BDF("no memory for user lut.\n");
			ret	      = -ENOMEM;
			goto l_unlock;
		}
		for (i = 0; i < vsi->rss_ctxt.lut_size; i++)
			user_lut[i] = (u8)(indir[i]);
	}

	if (key) {
		ret = sxe2_fwc_rss_hkey_set(vsi, user_key);
		if (ret) {
			LOG_ERROR_BDF("set hash key failed, ret: %d.\n", ret);
			goto l_unlock;
		}
		if (vsi->rss_ctxt.hkey) {
			memcpy(vsi->rss_ctxt.hkey, user_key,
			       SXE2_RSS_HASH_KEY_SIZE);
		}
	}

	if (indir) {
		ret = sxe2_fwc_rss_lut_set(vsi, user_lut,
					   vsi->rss_ctxt.lut_size);
		if (ret) {
			LOG_ERROR_BDF("set rss lut failed, ret: %d.\n", ret);
			goto l_unlock;
		}
		if (vsi->rss_ctxt.lut)
			memcpy(vsi->rss_ctxt.lut, user_lut, vsi->rss_ctxt.lut_size);
	}

l_unlock:
	if (user_key)
		devm_kfree(dev, user_key);

	if (user_lut)
		devm_kfree(dev, user_lut);

	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

static s32 sxe2_get_tx_qc_coalesce(struct ethtool_coalesce *ec,
				   struct sxe2_q_container *qc)
{
	if (!qc->list.cnt)
		return -EINVAL;

	ec->use_adaptive_tx_coalesce = SXE2_IS_ITR_DYNAMIC(qc);
	ec->tx_coalesce_usecs	     = qc->itr_setting;

	return 0;
}

static s32 sxe2_get_rx_qc_coalesce(struct ethtool_coalesce *ec,
				   struct sxe2_q_container *qc)
{
	if (!qc->list.cnt)
		return -EINVAL;

	ec->use_adaptive_rx_coalesce = SXE2_IS_ITR_DYNAMIC(qc);
	ec->rx_coalesce_usecs	     = qc->itr_setting;
	ec->rx_coalesce_usecs_high   = qc->list.next->irq_data->rate_limit;

	return 0;
}

static s32 sxe2_get_queue_coalesce(struct sxe2_vsi *vsi,
				   struct ethtool_coalesce *ec, u32 q_idx)
{
	if (q_idx < vsi->txqs.q_cnt && q_idx < vsi->rxqs.q_cnt) {
		if (sxe2_get_tx_qc_coalesce(ec, SXE2_VSI_TX_QC(vsi, q_idx)))
			return -EINVAL;
		if (sxe2_get_rx_qc_coalesce(ec, SXE2_VSI_RX_QC(vsi, q_idx)))
			return -EINVAL;
	} else if (q_idx < vsi->txqs.q_cnt) {
		if (sxe2_get_tx_qc_coalesce(ec, SXE2_VSI_TX_QC(vsi, q_idx)))
			return -EINVAL;
	} else if (q_idx < vsi->rxqs.q_cnt) {
		if (sxe2_get_rx_qc_coalesce(ec, SXE2_VSI_RX_QC(vsi, q_idx)))
			return -EINVAL;
	} else {
		return -EINVAL;
	}

	return 0;
}

static s32 sxe2_get_coalesce_interval(struct net_device *netdev,
				      struct ethtool_coalesce *ec, u32 q_idx)
{
	s32 ret			      = 0;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;

	mutex_lock(&adapter->vsi_ctxt.lock);

	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		goto l_unlock;
	}

	if (q_idx == SXE2_COALESCE_QNUM_INVAL)
		q_idx = 0;

	if (sxe2_get_queue_coalesce(vsi, ec, q_idx))
		ret = -EINVAL;

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

#ifdef GET_COALESCE_NEED_2_PARAMS
STATIC int sxe2_get_coalesce(struct net_device *netdev,
			     struct ethtool_coalesce *ec)
#else
STATIC int sxe2_get_coalesce(struct net_device *netdev,
			     struct ethtool_coalesce *ec,
			     struct kernel_ethtool_coalesce *kernel_coal,
			     struct netlink_ext_ack *extack)
#endif
{
	return sxe2_get_coalesce_interval(netdev, ec, SXE2_COALESCE_QNUM_INVAL);
}

STATIC int sxe2_get_per_queue_coalesce(struct net_device *netdev, u32 q_idx,
				       struct ethtool_coalesce *ec)
{
	return sxe2_get_coalesce_interval(netdev, ec, q_idx);
}

STATIC void sxe2_invalid_itr_print(struct net_device *netdev,
				   u32 use_adaptive_coalesce,
				   u32 coalesce_usecs, const s8 *q_type_str)
{
	struct sxe2_netdev_priv *np  = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;
	struct sxe2_hw *hw	     = &adapter->hw;

	if (use_adaptive_coalesce)
		return;

	if (coalesce_usecs % hw->hw_cfg.itr_gran)
		LOG_NETDEV_INFO("user set %s-usecs to invalid value %d, \t"
				"device only support values that multiple of %d. \t"
				"rounding down and attempting to set %s-usecs to %d ",
				q_type_str, coalesce_usecs, hw->hw_cfg.itr_gran, q_type_str,
				rounddown(coalesce_usecs, hw->hw_cfg.itr_gran));
}

static void sxe2_invalid_rate_limit_print(struct net_device *netdev,
					  struct ethtool_coalesce *ec)
{
	struct sxe2_netdev_priv *np  = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;
	struct sxe2_hw *hw	     = &adapter->hw;

	if (ec->use_adaptive_tx_coalesce || ec->use_adaptive_rx_coalesce)
		return;

	if (ec->rx_coalesce_usecs_high % hw->hw_cfg.credit_interval_gran)
		LOG_NETDEV_INFO("user set rx_coalesce_usecs_high to invalid value %d, \t"
				"device only support values that multiple of %d. rounding down \t"
				"and attempting to set rx_coalesce_usecs_high to %d\n",
				ec->rx_coalesce_usecs_high,
				hw->hw_cfg.credit_interval_gran,
				rounddown(ec->rx_coalesce_usecs_high,
					  hw->hw_cfg.credit_interval_gran));
}

STATIC void sxe2_invalid_coalesce_print(struct net_device *netdev,
					struct ethtool_coalesce *ec)
{
	sxe2_invalid_itr_print(netdev, ec->use_adaptive_tx_coalesce,
			       ec->tx_coalesce_usecs, SXE2_Q_TYPE_STR_TX);
	sxe2_invalid_itr_print(netdev, ec->use_adaptive_rx_coalesce,
			       ec->rx_coalesce_usecs, SXE2_Q_TYPE_STR_RX);
	sxe2_invalid_rate_limit_print(netdev, ec);
}

STATIC s32 sxe2_set_qc_itr(struct sxe2_q_container *qc, const s8 *q_type_str,
			   u32 use_adaptive_coalesce, u32 coalesce_usecs)
{
	struct sxe2_irq_data *irq_data = qc->list.next->irq_data;
	struct sxe2_vsi *vsi	       = irq_data->vsi;
	struct sxe2_adapter *adapter   = vsi->adapter;
	struct sxe2_hw *hw	       = &adapter->hw;
	u32 itr_setting		       = qc->itr_setting;
	struct net_device *netdev      = vsi->netdev;

	if (!use_adaptive_coalesce) {
		if (coalesce_usecs >
		    SXE2_VF_INT_ITR_INTERVAL * hw->hw_cfg.itr_gran) {
			LOG_NETDEV_INFO("invalid value, %s-usecs range is 0-%d\n",
					q_type_str,
					SXE2_VF_INT_ITR_INTERVAL * hw->hw_cfg.itr_gran);
			return -EINVAL;
		}
		qc->itr_mode = SXE2_ITR_STATIC;
		qc->itr_setting =
			rounddown(coalesce_usecs, hw->hw_cfg.itr_gran);
		sxe2_hw_irq_itr_set(hw, irq_data->idx_in_pf, qc->itr_idx,
				    (u16)coalesce_usecs);
		(void)sxe2_flush(hw);
	} else {
		if (coalesce_usecs != itr_setting) {
			LOG_NETDEV_INFO("%s interrupt throttling cannot be changed \t"
					"if adaptive-%s is enabled. \t"
					"coalesce from %d to %d,adaptive is %d\n",
					q_type_str, q_type_str, itr_setting,
					coalesce_usecs, use_adaptive_coalesce);
			return -EINVAL;
		}
		qc->itr_mode = SXE2_ITR_DYNAMIC;
	}
	return 0;
}

static s32 sxe2_set_qc_rate_limit(struct ethtool_coalesce *ec,
				  struct sxe2_q_container *qc,
				  struct sxe2_vsi *vsi)
{
	struct sxe2_irq_data *irq_data = qc->list.next->irq_data;
	struct sxe2_adapter *adapter   = irq_data->vsi->adapter;
	struct sxe2_hw *hw	       = &adapter->hw;
	struct net_device *netdev      = vsi->netdev;

	if (ec->rx_coalesce_usecs_high >
		    SXE2_PF_INT_RATE_CREDIT_INTERVAL_MAX *
			    hw->hw_cfg.credit_interval_gran ||
	    (ec->rx_coalesce_usecs_high &&
	     ec->rx_coalesce_usecs_high < hw->hw_cfg.credit_interval_gran)) {
		LOG_NETDEV_INFO("invalid value, rx_coalesce_usecs_high valid \t"
				"values are 0(disabled), value:%d ,valid range:[%d-%d]\n",
				ec->rx_coalesce_usecs_high,
				hw->hw_cfg.credit_interval_gran,
				SXE2_PF_INT_RATE_CREDIT_INTERVAL_MAX *
				hw->hw_cfg.credit_interval_gran);
		return -EINVAL;
	}

	if (ec->rx_coalesce_usecs_high != irq_data->rate_limit &&
	    (ec->use_adaptive_rx_coalesce || ec->use_adaptive_tx_coalesce)) {
		LOG_NETDEV_INFO("invalid value, rx_coalesce_usecs_high can be modified \t"
				"only when adaptive-tx and adaptive-rx is disabled\n");
		return -EINVAL;
	}

	if ((u16)ec->rx_coalesce_usecs_high != irq_data->rate_limit)
		irq_data->rate_limit = (u16)ec->rx_coalesce_usecs_high;

	sxe2_hw_irq_rate_limit_set(hw, irq_data->idx_in_pf,
				   irq_data->rate_limit);

	return 0;
}

static s32 sxe2_set_all_queue_coalesce(struct net_device *netdev,
				       struct ethtool_coalesce *ec)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	u16 irq_idx;
	s32 ret;
	struct sxe2_irq_data *irq_data;

	sxe2_for_each_vsi_irq(vsi, irq_idx) {
		irq_data = vsi->irqs.irq_data[irq_idx];
		if (SXE2_IRQ_HAS_TXQ(irq_data)) {
			ret = sxe2_set_qc_itr(&irq_data->tx, SXE2_Q_TYPE_STR_TX,
					      ec->use_adaptive_tx_coalesce,
					      ec->tx_coalesce_usecs);
			if (ret)
				return ret;
		}
		if (SXE2_IRQ_HAS_RXQ(irq_data)) {
			ret = sxe2_set_qc_itr(&irq_data->rx, SXE2_Q_TYPE_STR_RX,
					      ec->use_adaptive_rx_coalesce,
					      ec->rx_coalesce_usecs);
			if (ret)
				return ret;
			ret = sxe2_set_qc_rate_limit(ec, &irq_data->rx, vsi);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static s32 sxe2_set_queue_coalesce(struct net_device *netdev,
				   struct ethtool_coalesce *ec, u32 q_idx)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	s32 ret;

	if (q_idx < vsi->txqs.q_cnt && q_idx < vsi->rxqs.q_cnt) {
		ret = sxe2_set_qc_itr(SXE2_VSI_TX_QC(vsi, q_idx),
				      SXE2_Q_TYPE_STR_TX,
				      ec->use_adaptive_tx_coalesce,
				      ec->tx_coalesce_usecs);
		if (ret)
			return ret;

		ret = sxe2_set_qc_itr(SXE2_VSI_RX_QC(vsi, q_idx),
				      SXE2_Q_TYPE_STR_RX,
				      ec->use_adaptive_rx_coalesce,
				      ec->rx_coalesce_usecs);
		if (ret)
			return ret;
		ret = sxe2_set_qc_rate_limit(ec, SXE2_VSI_RX_QC(vsi, q_idx),
					     vsi);
		if (ret)
			return ret;
	} else if (q_idx < vsi->txqs.q_cnt) {
		ret = sxe2_set_qc_itr(SXE2_VSI_TX_QC(vsi, q_idx),
				      SXE2_Q_TYPE_STR_TX,
				      ec->use_adaptive_tx_coalesce,
				      ec->tx_coalesce_usecs);
		if (ret)
			return ret;
	} else if (q_idx < vsi->rxqs.q_cnt) {
		ret = sxe2_set_qc_itr(SXE2_VSI_RX_QC(vsi, q_idx),
				      SXE2_Q_TYPE_STR_RX,
				      ec->use_adaptive_rx_coalesce,
				      ec->rx_coalesce_usecs);
		if (ret)
			return ret;
		ret = sxe2_set_qc_rate_limit(ec, SXE2_VSI_RX_QC(vsi, q_idx),
					     vsi);
		if (ret)
			return ret;
	} else {
		return -EINVAL;
	}

	return 0;
}

static s32 sxe2_set_coalesce_interval(struct net_device *netdev,
				      struct ethtool_coalesce *ec, u32 q_idx)
{
	s32 ret			      = 0;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;

	mutex_lock(&adapter->vsi_ctxt.lock);

	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		goto l_unlock;
	}

	if (q_idx == SXE2_COALESCE_QNUM_INVAL)
		ret = sxe2_set_all_queue_coalesce(netdev, ec);
	else
		ret = sxe2_set_queue_coalesce(netdev, ec, q_idx);

	if (ret)
		goto l_unlock;

	sxe2_invalid_coalesce_print(netdev, ec);

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

#ifdef SET_COALESCE_NEED_2_PARAMS
STATIC int sxe2_set_coalesce(struct net_device *netdev,
			     struct ethtool_coalesce *ec)
#else
STATIC int sxe2_set_coalesce(struct net_device *netdev,
			     struct ethtool_coalesce *ec,
			     struct kernel_ethtool_coalesce *kernel_coal,
			     struct netlink_ext_ack *extack)
#endif
{
	return sxe2_set_coalesce_interval(netdev, ec, SXE2_COALESCE_QNUM_INVAL);
}

STATIC int sxe2_set_per_queue_coalesce(struct net_device *netdev, u32 q_idx,
				       struct ethtool_coalesce *ec)
{
	return sxe2_set_coalesce_interval(netdev, ec, q_idx);
}

STATIC u16 sxe2_max_rxq_get(struct sxe2_adapter *adapter)
{
	u16 max_rxq;

	max_rxq =
		(u16)min3(adapter->irq_ctxt.irq_layout.lan, (u16)num_online_cpus(),
			  (u16)adapter->q_ctxt.max_rxq_cnt);
	return (max_rxq > SXE2_VSI_TXRX_Q_MAX_CNT) ? SXE2_VSI_TXRX_Q_MAX_CNT :
						     max_rxq;
}

STATIC u16 sxe2_max_txq_get(struct sxe2_adapter *adapter)
{
	u16 max_txq;

	max_txq =
		(u16)min3(adapter->irq_ctxt.irq_layout.lan, (u16)num_online_cpus(),
			  (u16)adapter->q_ctxt.max_txq_cnt);
	return (max_txq > SXE2_VSI_TXRX_Q_MAX_CNT) ? SXE2_VSI_TXRX_Q_MAX_CNT :
						     max_txq;
}

STATIC u32 sxe2_combined_cnt_get(struct sxe2_vsi *vsi)
{
	u32 combined = 0;
	s32 i;

	sxe2_for_each_vsi_irq(vsi, i) {
		struct sxe2_irq_data *irq_data = vsi->irqs.irq_data[i];

		if (irq_data->rx.list.cnt && irq_data->tx.list.cnt)
			combined++;
	}

	return combined;
}

STATIC void sxe2_channels_get(struct net_device *netdev,
			      struct ethtool_channels *channel)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;

	mutex_lock(&adapter->vsi_ctxt.lock);

	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state))
		goto l_unlock;

	channel->max_rx = sxe2_max_rxq_get(adapter);
	channel->max_tx = sxe2_max_txq_get(adapter);
	channel->max_combined =
		(u32)min_t(int, channel->max_rx, channel->max_tx);

	channel->combined_count = sxe2_combined_cnt_get(vsi);
	channel->rx_count	= vsi->rxqs.q_cnt - channel->combined_count;
	channel->tx_count	= vsi->txqs.q_cnt - channel->combined_count;

	if (test_bit(SXE2_FLAG_MACVLAN_ENABLE, adapter->flags)) {
		channel->max_combined += adapter->macvlan_ctxt.max_num_macvlan;
		channel->combined_count += adapter->macvlan_ctxt.num_macvlan;
	}

	channel->other_count = 1;
	channel->max_other   = channel->other_count;

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
}

STATIC u32 sxe2_ethtool_priv_flags_get(struct net_device *netdev)
{
	u32 i, flags = 0;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;
	const struct sxe2_priv_flag *priv_flag;

	for (i = 0; i < SXE2_PRIV_FLAG_ARRAY_SIZE; i++) {
		priv_flag = &sxe2_gstrings_priv_flags[i];
		if (test_bit((int)priv_flag->adapter_flag_bitno,
			     adapter->flags))
			flags |= (u32)BIT(i);
	}
	return flags;
}

STATIC void sxe2_fnav_tunnel_flag_set(struct sxe2_adapter *adapter, u32 flags)
{
	if ((flags & BIT(SXE2_ETHTOOL_PRIV_FLAG_FNAV_TUNNEL)) &&
	    !test_bit(SXE2_FLAG_FNAV_TUNNEL_ENABLE, adapter->flags)) {
		set_bit(SXE2_FLAG_FNAV_TUNNEL_ENABLE, adapter->flags);
	} else if (!(flags & BIT(SXE2_ETHTOOL_PRIV_FLAG_FNAV_TUNNEL)) &&
		   test_bit(SXE2_FLAG_FNAV_TUNNEL_ENABLE, adapter->flags)) {
		clear_bit(SXE2_FLAG_FNAV_TUNNEL_ENABLE, adapter->flags);
	}
}

static s32 sxe2_legacy_rx_flag_set(struct sxe2_adapter *adapter, u32 flags)
{
	s32 ret			  = 0;
	bool need_downup	  = false;
	struct sxe2_vsi *vsi	  = adapter->vsi_ctxt.main_vsi;
	struct net_device *netdev = vsi->netdev;
	bool old_legacy_rx =
		(test_bit(SXE2_FLAG_LEGACY_RX_ENABLE, adapter->flags) != 0);

	if ((flags & BIT(SXE2_ETHTOOL_PRIV_FLAG_LEGACY_RX)) &&
	    !test_bit(SXE2_FLAG_LEGACY_RX_ENABLE, adapter->flags)) {
		need_downup = true;
		set_bit(SXE2_FLAG_LEGACY_RX_ENABLE, adapter->flags);
	} else if (!(flags & BIT(SXE2_ETHTOOL_PRIV_FLAG_LEGACY_RX)) &&
		   test_bit(SXE2_FLAG_LEGACY_RX_ENABLE, adapter->flags)) {
		need_downup = true;
		clear_bit(SXE2_FLAG_LEGACY_RX_ENABLE, adapter->flags);
	}

	if (need_downup) {
		ret = sxe2_vsi_down_up(vsi);
		if (ret) {
			if (old_legacy_rx) {
				set_bit(SXE2_FLAG_LEGACY_RX_ENABLE,
					adapter->flags);
			} else {
				clear_bit(SXE2_FLAG_LEGACY_RX_ENABLE,
					  adapter->flags);
			}
			LOG_NETDEV_ERR("set legacy rx priv flag err %d\n", ret);
		}
	}

	return ret;
}

STATIC int sxe2_ethtool_priv_flags_set(struct net_device *netdev, u32 flags)
{
	s32 ret			      = 0;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;
	bool part_failed	      = false;

	if (flags >= BIT(SXE2_PRIV_FLAG_ARRAY_SIZE)) {
		ret = -EINVAL;
		goto l_out;
	}

	ret = sxe2_legacy_rx_flag_set(adapter, flags);
	if (ret)
		part_failed = true;

	if ((flags & BIT(SXE2_ETHTOOL_PRIV_FLAG_MDD_AUTO_RESET_VF)) &&
	    !test_bit(SXE2_FLAG_MDD_AUTO_RESET_VF, adapter->flags)) {
		set_bit(SXE2_FLAG_MDD_AUTO_RESET_VF, adapter->flags);
	} else if (!(flags & BIT(SXE2_ETHTOOL_PRIV_FLAG_MDD_AUTO_RESET_VF)) &&
		   test_bit(SXE2_FLAG_MDD_AUTO_RESET_VF, adapter->flags)) {
		clear_bit(SXE2_FLAG_MDD_AUTO_RESET_VF, adapter->flags);
	}

	if ((flags & BIT(SXE2_ETHTOOL_PRIV_FLAG_DCBX_AGENT)) &&
	    !test_bit(SXE2_FLAG_FW_DCBX_AGENT, adapter->flags)) {
		ret = sxe2_dcbx_agent_enable(adapter);
	} else if (!(flags & BIT(SXE2_ETHTOOL_PRIV_FLAG_DCBX_AGENT)) &&
		   test_bit(SXE2_FLAG_FW_DCBX_AGENT, adapter->flags)) {
		ret = sxe2_dcbx_agent_disable(adapter);
	}

	sxe2_fnav_tunnel_flag_set(adapter, flags);

	if ((flags & BIT(SXE2_ETHTOOL_PRIV_FLAG_LINK_DOWN_ON_CLOSE)) &&
	    !test_bit(SXE2_FLAG_LINK_DOWN_ON_CLOSE, adapter->flags)) {
		LOG_NETDEV_WARN("Setting link-down-on-close enabled on this port\n");
		set_bit(SXE2_FLAG_LINK_DOWN_ON_CLOSE, adapter->flags);
	} else if (!(flags & BIT(SXE2_ETHTOOL_PRIV_FLAG_LINK_DOWN_ON_CLOSE)) &&
		   test_bit(SXE2_FLAG_LINK_DOWN_ON_CLOSE, adapter->flags)) {
		clear_bit(SXE2_FLAG_LINK_DOWN_ON_CLOSE, adapter->flags);
	}

	if (part_failed)
		ret = -EINVAL;

l_out:
	return ret;
}

s32 sxe2_fwc_sff_eeprom_get(struct sxe2_adapter *adapter, bool is_qsfp,
			    u16 bus_addr, u16 page, u16 offset, u16 data_len,
			    struct sxe2_sfp_resp *sff_value)
{
	s32 ret			    = 0;
	struct sxe2_sfp_req sfp_req = {};
	struct sxe2_cmd_params cmd  = {};

	sfp_req.is_wr	 = 0;
	sfp_req.is_qsfp	 = (u8)is_qsfp;
	sfp_req.bus_addr = cpu_to_le16(bus_addr);
	sfp_req.page_cnt = cpu_to_le16(page);
	sfp_req.offset	 = cpu_to_le16(offset);
	sfp_req.data_len = cpu_to_le16(data_len);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_GET_OPT_DATA_INFO, &sfp_req,
				  sizeof(sfp_req), sff_value,
				  sizeof(*sff_value) + data_len);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("get sff eeprom failed, ret=%d\n", ret);
		goto l_end;
	}

l_end:
	return ret;
}

STATIC int sxe2_module_info_get(struct net_device *netdev,
				struct ethtool_modinfo *modinfo)
{
	int ret				= 0;
	struct sxe2_netdev_priv *priv	= netdev_priv(netdev);
	struct sxe2_vsi *vsi		= priv->vsi;
	struct sxe2_adapter *adapter	= vsi->adapter;
	struct sxe2_sfp_resp *sff_value =
		kzalloc(sizeof(struct sxe2_sfp_resp) + sizeof(u8) * EEPROM_DATALEN,
			GFP_KERNEL);
	struct sxe2_sfp_resp *sff8472_comp =
		kzalloc(sizeof(struct sxe2_sfp_resp) + sizeof(u8) * EEPROM_DATALEN,
			GFP_KERNEL);
	struct sxe2_sfp_resp *sff8472_swap =
		kzalloc(sizeof(struct sxe2_sfp_resp) + sizeof(u8) * EEPROM_DATALEN,
			GFP_KERNEL);
	struct sxe2_sfp_resp *sff8636_rev =
		kzalloc(sizeof(struct sxe2_sfp_resp) + sizeof(u8) * EEPROM_DATALEN,
			GFP_KERNEL);

	if (!sff_value || !sff8472_comp || !sff8472_swap || !sff8636_rev) {
		ret = -ENOSPC;
		LOG_NETDEV_ERR("sff module info get, there is no space to alloc.\n");
		goto l_out;
	}

	ret = sxe2_fwc_sff_eeprom_get(adapter, 0, SXE2_SFP_E2P_I2C_7BIT_ADDR0,
				      0, SXE2_MODULE_SFF_PHY_DEV_IDENTIFIER,
				      EEPROM_DATALEN, sff_value);
	if (ret)
		goto l_out;

	switch (sff_value->data[0]) {
	case SXE2_SFP_TYPE_SFP:
		ret = sxe2_fwc_sff_eeprom_get(adapter, 0,
					      SXE2_SFP_E2P_I2C_7BIT_ADDR0, 0,
					      SXE2_MODULE_SFF_8472_COMP,
					      EEPROM_DATALEN, sff8472_comp);
		if (ret)
			goto l_out;

		ret = sxe2_fwc_sff_eeprom_get(adapter, 0,
					      SXE2_SFP_E2P_I2C_7BIT_ADDR0, 0,
					      SXE2_MODULE_SFF_8472_SWAP,
					      EEPROM_DATALEN, sff8472_swap);
		if (ret)
			goto l_out;

		if (sff8472_swap->data[0] & SXE2_MODULE_SFF_ADDR_MODE) {
			modinfo->type	    = ETH_MODULE_SFF_8079;
			modinfo->eeprom_len = ETH_MODULE_SFF_8079_LEN;
		} else if (sff8472_comp->data[0] &&
			   (sff8472_swap->data[0] &
			    SXE2_MODULE_SFF_DIAG_CAPAB)) {
			modinfo->type	    = ETH_MODULE_SFF_8472;
			modinfo->eeprom_len = ETH_MODULE_SFF_8472_LEN;
		} else {
			modinfo->type	    = ETH_MODULE_SFF_8079;
			modinfo->eeprom_len = ETH_MODULE_SFF_8079_LEN;
		}
		break;
	case SXE2_SFP_TYPE_QSFP_PLUS:
	case SXE2_SFP_TYPE_QSFP28:
		ret = sxe2_fwc_sff_eeprom_get(adapter, 1,
					      SXE2_SFP_E2P_I2C_7BIT_ADDR0, 0,
					      SXE2_MODULE_REVISION_ADDR,
					      EEPROM_DATALEN, sff8636_rev);
		if (ret)
			goto l_out;

		if (sff8636_rev->data[0] > SXE2_MODULE_REVISION_SFF_8436) {
			modinfo->type	    = ETH_MODULE_SFF_8636;
			modinfo->eeprom_len = SXE2_MODULE_QSFP_MAX_LEN;
		} else {
			modinfo->type	    = ETH_MODULE_SFF_8436;
			modinfo->eeprom_len = SXE2_MODULE_QSFP_MAX_LEN;
		}
		break;
	default:
		LOG_NETDEV_WARN("sff module type not recognized.\n");
		ret = -EINVAL;
		goto l_out;
	}
	LOG_INFO_BDF("get module info ok.\n");
l_out:
	kfree(sff_value);

	kfree(sff8472_comp);

	kfree(sff8472_swap);

	kfree(sff8636_rev);

	return ret;
}

STATIC int sxe2_module_eeprom_get(struct net_device *netdev,
				  struct ethtool_eeprom *eeprom, u8 *data)
{
	int ret			      = 0;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;
	bool is_sfp		      = false;
	u32 i, j, k;
	u16 offset = 0;
	u8 page	   = 0;
	u8 addr	   = SXE2_SFP_E2P_I2C_7BIT_ADDR0;
	struct sxe2_sfp_resp *sff_value =
		kzalloc(sizeof(struct sxe2_sfp_resp) +
				SFF_READ_BLOCK_SIZE_8 * sizeof(u8),
			GFP_KERNEL);
	u8 upper_page_enable = 0;

	if (!sff_value) {
		ret = -ENOSPC;
		LOG_NETDEV_ERR("sff module eeprom get, there is no space to alloc.\n");
		goto l_out;
	}

	if (!eeprom || !eeprom->len || !data) {
		ret = -EINVAL;
		goto l_out;
	}

	ret = sxe2_fwc_sff_eeprom_get(adapter, 0, SXE2_SFP_E2P_I2C_7BIT_ADDR0,
				      0, SXE2_MODULE_SFF_PHY_DEV_IDENTIFIER,
				      SFF_READ_BLOCK_SIZE_8, sff_value);
	if (ret)
		goto l_out;

	if (sff_value->data[0] == SXE2_SFP_TYPE_SFP)
		is_sfp = true;

	upper_page_enable = sff_value->data[SXE2_SFF_STATUS_INDICATER];
	memset(data, 0, eeprom->len);
	for (i = 0; i < SFF_READ_BLOCK_SIZE_8; i++)
		sff_value->data[i] = 0;

	for (i = 0; i < eeprom->len; i += SFF_READ_BLOCK_SIZE_8) {
		offset = (u16)(eeprom->offset + i);
		page   = 0;

		if (is_sfp) {
			if (offset >= ETH_MODULE_SFF_8079_LEN) {
				offset -= ETH_MODULE_SFF_8079_LEN;
				addr = SXE2_SFP_E2P_I2C_7BIT_ADDR1;
			}
		} else {
			while (offset >= ETH_MODULE_SFF_8436_LEN) {
				offset -= ETH_MODULE_SFF_8436_LEN / 2;
				page++;
			}
		}

		if (page != 0 && (upper_page_enable & SXE2_SFF_FLAT_MEM))
			page = 0;

		for (j = 0; j < SXE2_MODULE_REPEAT_TIMES; j++) {
			ret = sxe2_fwc_sff_eeprom_get(adapter, !is_sfp, addr, page,
						      (u8)offset, SFF_READ_BLOCK_SIZE_8,
						      sff_value);
			LOG_NETDEV_DEBUG("SFF %02X %02X %02X %X = \t"
					 "%02X%02X%02X%02X.%02X%02X%02X%02X (%X)\n",
					 addr, offset, page, is_sfp,
					 sff_value->data[0], sff_value->data[1],
					 sff_value->data[2], sff_value->data[3],
					 sff_value->data[4], sff_value->data[5],
					 sff_value->data[6], sff_value->data[7],
					 ret);
			if (ret) {
				usleep_range(1500, 2500);
				for (k = 0; k < SFF_READ_BLOCK_SIZE_8;
				     k++) {
					sff_value->data[k] = 0;
				}
				continue;
			}
			break;
		}

		if ((i + SFF_READ_BLOCK_SIZE_8) < eeprom->len) {
			for (k = 0; k < SFF_READ_BLOCK_SIZE_8; k++)
				*(data + i + k) = sff_value->data[k];
		} else {
			for (k = 0; i + k < eeprom->len; k++)
				*(data + i + k) = sff_value->data[k];
		}
	}

l_out:
	kfree(sff_value);

	return ret;
}

#ifdef SUPPORTED_ETHTOOL_EEPROM_BY_PAGE
STATIC int sxe2_module_eeprom_get_by_page(struct net_device *netdev,
					  const struct ethtool_module_eeprom *page_data,
					  struct netlink_ext_ack *extack)
{
	s32 ret;
	struct ethtool_eeprom eeprom = {0};
	u32	offset = page_data->offset;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;
	struct sxe2_sfp_resp *sff_value =
		kzalloc(sizeof(struct sxe2_sfp_resp) + sizeof(u8) * SFF_READ_BLOCK_SIZE_8,
			GFP_KERNEL);

	if (!sff_value) {
		ret = -ENOSPC;
		LOG_NETDEV_ERR("sff module eeprom get, there is no space to alloc.\n");
		return ret;
	}

	ret = sxe2_fwc_sff_eeprom_get(adapter, 0, SXE2_SFP_E2P_I2C_7BIT_ADDR0,
				      0, SXE2_MODULE_SFF_PHY_DEV_IDENTIFIER,
				      SFF_READ_BLOCK_SIZE_8, sff_value);
	if (ret)
		goto end;

	if (page_data->page)
		offset += page_data->page * (ETH_MODULE_SFF_8079_LEN / 2);

	if (sff_value->data[0] == SXE2_SFP_TYPE_SFP &&
	    page_data->i2c_address == SXE2_SFP_E2P_I2C_7BIT_ADDR1) {
		offset += ETH_MODULE_SFF_8079_LEN;
	}

	eeprom.offset = offset;
	eeprom.len = page_data->length;

	ret = sxe2_module_eeprom_get(netdev, &eeprom, page_data->data);
	if (ret < 0)
		goto end;

	ret = (int)page_data->length;
end:
	kfree(sff_value);
	return ret;
}
#endif

STATIC s32 sxe2_lbtest_txrx_cfg(struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;

	ret = sxe2_tx_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("open: tx config err, ret=%d\n", ret);
		goto l_end;
	}

	ret = sxe2_rx_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("open: rx config err, ret=%d\n", ret);
		goto l_rx_fail;
	}
	return 0;
l_rx_fail:
	sxe2_tx_rings_res_free(vsi);
l_end:
	return ret;
}

STATIC s32 sxe2_lbtest_txrx_free(struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;
	bool need_reset = false;

	ret = sxe2_vsi_down(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi down failed, vsi %d error %d\n",
			      vsi->idx_in_dev, ret);
	}

	sxe2_vsi_irqs_clear_free(vsi);

	if (need_reset)
		sxe2_trigger_and_wait_resetting(adapter);

	sxe2_tx_rings_res_free(vsi);

	sxe2_rx_rings_res_free(vsi);

	return ret;
}

STATIC s32 sxe2_lbtest_create_frame(struct device *dev, u8 *mac, u8 **ret_data,
				    u16 size)
{
	u8 *data;

	if (!dev)
		return -EINVAL;

	data = devm_kzalloc(dev, size, GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	memset(data, 0xFF, size);

	memcpy(data, mac, ETH_ALEN);

	data[32] = 0xDE;
	data[42] = 0xAD;
	data[44] = 0xBE;
	data[46] = 0xEF;

	*ret_data = data;

	return 0;
}

STATIC s32 sxe2_lbtest_frames_xmit(struct sxe2_queue *txq, u8 *data, u16 size)
{
	union sxe2_tx_data_desc *tx_desc;
	struct sxe2_tx_buf *tx_buf;
	dma_addr_t dma;
	u64 td_cmd;
	s32 ret = 0;

	tx_desc = SXE2_TX_DESC(txq, txq->next_to_use);
	tx_buf	= &txq->tx_buf[txq->next_to_use];

	dma = dma_map_single(txq->dev, data, size, DMA_TO_DEVICE);
	if (dma_mapping_error(txq->dev, dma)) {
		ret = -EINVAL;
		goto l_out;
	}
	tx_desc->read.buf_addr = cpu_to_le64(dma);

	td_cmd = (u64)(SXE2_TXDD_CMD_EOP | SXE2_TXDD_CMD_RS);
	tx_desc->read.cmd_type_offset_bsz =
		cpu_to_le64(SXE2_TX_DESC_DTYPE_DATA | (td_cmd << SXE2_TXDD_CMD_S) |
			    ((u64)0 << SXE2_TXDD_OFFSET_S) |
			    ((u64)size << SXE2_TXDD_BUF_SZ_S) |
			    ((u64)0 << SXE2_TXDD_L2TAG1_S));

	tx_buf->next_to_watch = tx_desc;

	/* in order to force CPU ordering */
	wmb();

	txq->next_to_use++;
	if (txq->next_to_use >= txq->depth)
		txq->next_to_use = 0;

	writel(txq->next_to_use, txq->desc.tail);

	usleep_range(ETHTOOL_SELFTEST_SLEEP_MIN, ETHTOOL_SELFTEST_SLEEP_MAX);
	dma_unmap_single(txq->dev, dma, size, DMA_TO_DEVICE);

l_out:
	return ret;
}

STATIC bool sxe2_lbtest_frame_check(u8 *frame)
{
	bool ret = false;

	if (frame[32] == 0xDE && frame[42] == 0xAD && frame[44] == 0xBE &&
	    frame[46] == 0xEF && frame[48] == 0xFF) {
		ret = true;
	}

	return ret;
}

STATIC s32 sxe2_lbtest_frames_receive(struct sxe2_queue *rxq)
{
	struct sxe2_rx_buf *rx_buf;
	s32 frames_num, i;
	u8 *received_buf;
	struct sxe2_vsi *vsi	     = rxq->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	union sxe2_rx_desc *rx_desc;

	frames_num = 0;
	for (i = 0; i < rxq->depth; i++) {
		rx_desc = SXE2_RX_DESC(rxq, i);
		if (!(sxe2_desc_status0_err_test(rx_desc->wb.status0_err,
						 BIT(SXE2_RX_DESC_STATUS0_EOP) |
						 BIT(SXE2_RX_DESC_STATUS0_DD)))) {
			LOG_DEBUG_BDF("Check lb packet status0:0x%x\n",
				      rx_desc->wb.status0_err);
			continue;
		}
		rx_buf	     = &rxq->rx_buf[i];
		received_buf = page_address(rx_buf->page) + rx_buf->pg_offset;
		if (sxe2_lbtest_frame_check(received_buf)) {
			LOG_DEBUG_BDF("check lbtest frame OK.\n");
			frames_num++;
		} else {
			LOG_ERROR_BDF("failed to checkout lbtest frame. status0_err=0x%x\n",
				      rx_desc->wb.status0_err);
		}
	}

	return frames_num;
}

STATIC s32 sxe2_lbtest_loopback_set(struct sxe2_adapter *adapter, bool enable)
{
	struct sxe2_cmd_params cmd = { 0 };
	s32 ret;
	struct sxe2_fw_loop_back_config req;

	req.enable = (u8)enable;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ETHTOOL_LOOPBACK_SET, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to set loopback,enable=%d ret=%d\n",
			      enable, ret);
	}

	return ret;
}

static bool sxe2_vfs_is_active(struct sxe2_adapter *adapter)
{
	struct sxe2_vf_node *vf_node;
	u16 vf_idx;

	sxe2_for_each_vf(adapter, vf_idx) {
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
		vf_node = sxe2_vf_node_get(adapter, vf_idx);
		if (vf_node &&
		    test_bit(SXE2_VF_STATE_ACTIVE, vf_node->states)) {
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
			return true;
		}
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	}
	return false;
}

static s32 sxe2_frames_loopback(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	s32 frames_num, frames_valid;
	s32 i;
	u8 *tx_frame;
	struct sxe2_queue *txq, *rxq;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev	     = SXE2_ADAPTER_TO_DEV(adapter);
	struct net_device *netdev    = vsi->netdev;

	txq = vsi->txqs.q[0];
	rxq = vsi->rxqs.q[0];

	ret = sxe2_lbtest_create_frame(dev, lbtest_unicast, &tx_frame,
				       SXE2_LB_FRAME_SIZE);
	if (ret) {
		LOG_NETDEV_ERR("failed to create loopback frame.\n");
		goto l_end;
	}

	frames_num = min_t(s32, txq->depth, ETHTOOL_SELFTEST_FRAME_COUNT);
	for (i = 0; i < frames_num; i++) {
		ret = sxe2_lbtest_frames_xmit(txq, tx_frame,
					      SXE2_LB_FRAME_SIZE);
		if (ret) {
			LOG_NETDEV_ERR("failed to send test frame.\n");
			goto frame_free;
		}
	}

	frames_valid = sxe2_lbtest_frames_receive(rxq);
	if (!frames_valid) {
		LOG_NETDEV_ERR("failed to receive loopback packets.\n");
		ret = -EFAULT;
	} else if (frames_valid != frames_num) {
		LOG_NETDEV_ERR("failed to receive all loopback packets.\n");
		ret = -EFAULT;
	}

frame_free:
	devm_kfree(dev, tx_frame);

l_end:
	return ret;
}

static s32 sxe2_lbtest_vsi_open(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2_queue *rxq;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct net_device *netdev    = vsi->netdev;

	ret = sxe2_lbtest_txrx_cfg(vsi);
	if (ret) {
		LOG_NETDEV_ERR("failed to config txrx for the loopback test.\n");
		goto l_err;
	}

	rxq = vsi->rxqs.q[0];

	if (sxe2_rx_buffers_alloc(rxq, SXE2_DESC_UNUSED(rxq))) {
		ret = -ENOMEM;
		LOG_NETDEV_ERR("failed to alloc rx buffer for the loopback test.\n");
		goto free_txrx;
	}

	ret = sxe2_vsi_irqs_configure(vsi);
	if (ret) {
		ret = -ENOMEM;
		LOG_NETDEV_ERR("failed to config vsi for the loopback test.\n");
		goto config_err;
	}

	return 0;

config_err:
	(void)sxe2_txqs_stop(vsi);
	(void)sxe2_rxqs_stop(vsi);

free_txrx:
	if (sxe2_lbtest_txrx_free(vsi))
		LOG_NETDEV_ERR("could not disable test rings\n");

l_err:
	return ret;
}

STATIC s32 sxe2_loopback_test(struct net_device *netdev)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;
	bool if_running		      = false;
	struct sxe2_vsi *test_vsi;
	s32 status, ret = 0;
	bool link_status;

	mutex_lock(&adapter->link_ctxt.link_status_lock);
	link_status = sxe2_get_pf_link_status(adapter);
	mutex_unlock(&adapter->link_ctxt.link_status_lock);
	if (!link_status) {
		LOG_NETDEV_ERR("nic link is down, loopback test failed.\n");
		return SXE2_SELFTEST_RTN_FAIL;
	}

	if (sxe2_vfs_is_active(adapter))
		return -EFAULT;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		goto vsi_unlock;
	}

	if_running = netif_running(netdev);
	if (if_running) {
		LOG_DEBUG_BDF("close vsi before online test.\n");
		ret = sxe2_vsi_close(vsi);
		if (ret) {
			LOG_NETDEV_ERR("main vsi close failed.\n");
			goto vsi_unlock;
		}
	}

	test_vsi = sxe2_loopback_vsi_create(adapter);
	if (!test_vsi) {
		LOG_NETDEV_ERR("failed to create a VSI for the loopback test\n");
		ret = -ENOMEM;
		goto vsi_unlock;
	}

	ret = sxe2_lbtest_vsi_open(test_vsi);
	if (ret)
		goto vsi_destroy;

	ret = sxe2_lbtest_loopback_set(adapter, true);
	if (ret) {
		LOG_NETDEV_ERR("failed to enable mac loopback.\n");
		goto mac_loopback_set_failed;
	}

	ret = sxe2_mac_rule_add(test_vsi, lbtest_unicast);
	if (ret) {
		LOG_NETDEV_ERR("failed to add mac rule.\n");
		goto mac_rule_add_failed;
	}

	ret = sxe2_frames_loopback(test_vsi);

	if (sxe2_mac_rule_del(adapter, test_vsi->idx_in_dev, lbtest_unicast))
		LOG_NETDEV_ERR("failed to remove mac rule from test vsi.\n");

mac_rule_add_failed:
	if (sxe2_lbtest_loopback_set(adapter, false))
		LOG_NETDEV_ERR("failed to disable mac loopback.\n");

mac_loopback_set_failed:
	if (sxe2_lbtest_txrx_free(test_vsi))
		LOG_NETDEV_ERR("could not disable test rings\n");

vsi_destroy:
	test_vsi->netdev = NULL;
	sxe2_vsi_destroy_unlock(test_vsi);

vsi_unlock:
	if (if_running) {
		LOG_DEBUG_BDF("Re open vsi after online test.\n");
		status = sxe2_vsi_open(vsi);
		if (status) {
			LOG_NETDEV_ERR("failed to open device %s, error %d\n",
				       adapter->dev_name, status);
		}
	}

	mutex_unlock(&adapter->vsi_ctxt.lock);

	return ret;
}

STATIC s32 sxe2_link_test(struct net_device *netdev)
{
	bool port_state;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi = priv->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (!netif_carrier_ok(netdev))
		return SXE2_SELFTEST_RTN_LINKDOWN;

	mutex_lock(&adapter->link_ctxt.link_status_lock);
	port_state = sxe2_get_pf_link_status(adapter);
	mutex_unlock(&adapter->link_ctxt.link_status_lock);

	return port_state ? 0 : SXE2_SELFTEST_RTN_LINKDOWN;
}

STATIC s32 sxe2_intr_test(struct net_device *netdev)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi = priv->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_hw *hw = &adapter->hw;
	u64 sw_irq_cnt_old = adapter->irq_ctxt.event_irq_cnt;
	s32 ret = 0;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		mutex_unlock(&adapter->vsi_ctxt.lock);
		return ret;
	}

	LOG_NETDEV_INFO("interrupt test\n");

	sxe2_hw_irq_trigger(hw, SXE2_EVENT_IRQ_IDX);

	usleep_range(1000, 2000);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return (sw_irq_cnt_old == adapter->irq_ctxt.event_irq_cnt);
}

typedef s32 (*sxe2_selftest_func)(struct net_device *);

struct sxe2_selftest {
	char name[ETH_GSTRING_LEN];
	sxe2_selftest_func func;
	bool offline;
};

static struct sxe2_selftest sxe2_selftest_suite[] = {
	{ "Link Test", sxe2_link_test, false },
	{ "Intr Test", sxe2_intr_test, true },
	{ "Loopback Test", sxe2_loopback_test, true },
};

void sxe2_ethtool_selftest(struct net_device *netdev,
			   struct ethtool_test *eth_test, u64 *data)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter = priv->vsi->adapter;

	struct sxe2_selftest st;
	u32 i, count = 0;

	for (i = 0; i < ARRAY_SIZE(sxe2_selftest_suite); i++) {
		st = sxe2_selftest_suite[i];
		if (!(eth_test->flags & ETH_TEST_FL_OFFLINE) && st.offline) {
			LOG_NETDEV_INFO("[%d] %s can only perform in offline mode..\n",
					i, st.name);
			continue;
		}
		LOG_NETDEV_INFO("\t[%d] %s start..\n", i, st.name);
		data[count] = (u64)st.func(netdev);
		LOG_NETDEV_INFO("\t[%d] %s end: result(%lld)\n", i, st.name,
				data[count]);
		count++;
	}
	for (i = 0; i < count; i++) {
		if (data[i]) {
			eth_test->flags |= ETH_TEST_FL_FAILED;
			break;
		}
	}
	LOG_NETDEV_INFO("self test out: status flags(0x%x)\n", eth_test->flags);
}

int sxe2_ethtool_selftest_count(struct net_device *netdev)
{
	return ARRAY_SIZE(sxe2_selftest_suite);
}

void sxe2_ethtool_selftest_strings(struct net_device *netdev, u8 *data)
{
	struct sxe2_selftest st;
	u32 i;

	if (!data)
		return;
	for (i = 0; i < ARRAY_SIZE(sxe2_selftest_suite); i++) {
		st = sxe2_selftest_suite[i];
		memcpy(data + ((size_t)i * (size_t)ETH_GSTRING_LEN), st.name,
		       ETH_GSTRING_LEN);
	}
}

static void sxe2_get_pauseparam(struct net_device *netdev,
				struct ethtool_pauseparam *pause)
{
	struct sxe2_netdev_priv *np  = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;
	struct sxe2_fwc_lfc_info lfc = { 0 };
	struct sxe2_cmd_params cmd   = { 0 };
	struct sxe2_dcbx_cfg *curr_cfg;
	s32 ret;

	struct flm_ethtool_get_link_resp link_cfg;

	ret = sxe2_get_link_configure(adapter, &link_cfg);
	if (ret) {
		LOG_ERROR_BDF("link get cmd fail, ret=%d\n", ret);
		return;
	}

	pause->autoneg = link_cfg.local_an_en.advertis_an;

	curr_cfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	pause->rx_pause = 0;
	pause->tx_pause = 0;

	if (curr_cfg->pfc.enable)
		goto l_out;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LINK_FLOW_CONTROL_GET, NULL, 0,
				  &lfc, sizeof(lfc));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("fc get cmd fail, ret=%d\n", ret);
		return;
	}

	pause->rx_pause = adapter->lfc_ctxt.rx_en;
	pause->tx_pause = adapter->lfc_ctxt.tx_en;

	LOG_INFO_BDF("link get cmd fw tx %d rx %d driver tx %d rx %d, ret=%d\n",
		     lfc.tx_en, lfc.rx_en,
		     adapter->lfc_ctxt.tx_en, adapter->lfc_ctxt.rx_en, ret);

l_out:
	return;
}

static int sxe2_set_pauseparam(struct net_device *netdev,
			       struct ethtool_pauseparam *pause)
{
	struct sxe2_netdev_priv *np  = netdev_priv(netdev);
	struct sxe2_vsi *vsi	     = np->vsi;
	struct sxe2_vsi *dpdk_vsi    = NULL;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_fwc_lfc_info lfc = { 0 };
	struct sxe2_cmd_params cmd   = { 0 };
	struct sxe2_dcbx_cfg *curr_cfg;
	s32 ret = 0;
	struct flm_ethtool_get_link_resp link_cfg;
	u32 is_an;
	bool changed = false;
	u8 old_fc = SXE2_FC_MODE_DISABLE;
	u8 new_fc = SXE2_FC_MODE_DISABLE;

	(void)sxe2_fc_get(adapter, vsi->idx_in_dev, &old_fc);

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		LOG_ERROR_BDF("vsi disabled, try later.\n");
		goto vsi_unlock;
	}
	memset(&adapter->lfc_ctxt, 0, sizeof(struct sxe2_lfc_context));
	curr_cfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	if (vsi->type != SXE2_VSI_T_PF) {
		LOG_DEV_ERR("changing flow control parameters only supported for PF VSI\n");
		ret = -EOPNOTSUPP;
		goto vsi_unlock;
	}
	ret = sxe2_get_link_configure(adapter, &link_cfg);
	if (ret) {
		LOG_ERROR_BDF("link get cmd fail, ret=%d\n", ret);
		ret = -EIO;
		goto vsi_unlock;
	}

	is_an = link_cfg.local_an_en.advertis_an;
	if (pause->autoneg != is_an) {
		LOG_DEV_INFO("To change autoneg please use: ethtool -s <dev> autoneg <on|off>\n");
		ret = -EOPNOTSUPP;
		goto vsi_unlock;
	}
	if (curr_cfg->pfc.enable) {
		LOG_DEV_INFO("priority flow control enabled. Cannot set link flow control.\n");
		ret = -EOPNOTSUPP;
		goto vsi_unlock;
	}

	if (is_an) {
		ret = sxe2_link_set_fc_configure(adapter,
						 (u8)pause->tx_pause,
						 (u8)pause->rx_pause);
		if (ret) {
			LOG_ERROR_BDF("link set fc cmd fail, ret=%d\n", ret);
			ret = -EIO;
			goto vsi_unlock;
		}
	} else {
		memset(&lfc, 0, sizeof(lfc));
		if (pause->rx_pause) {
			lfc.rx_en = true;
			adapter->lfc_ctxt.rx_en = true;
		}

		if (pause->tx_pause) {
			lfc.tx_en = true;
			adapter->lfc_ctxt.tx_en = true;
		}

		lfc.fc_mode = SXE2_FC_MODE_LFC;
		sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LINK_FLOW_CONTROL_SET,
					  &lfc, sizeof(lfc), NULL, 0);

		ret = sxe2_cmd_fw_exec(adapter, &cmd);
		if (ret) {
			LOG_ERROR_BDF("fc set cmd fail, ret=%d\n", ret);
			ret = -EIO;
			goto vsi_unlock;
		}
	}

	dpdk_vsi = sxe2_vsi_get_by_type_unlock(adapter, SXE2_VSI_T_DPDK_PF);
	if (dpdk_vsi)
		sxe2_set_fc_flag(dpdk_vsi, pause->tx_pause || pause->rx_pause);
	sxe2_set_fc_flag(vsi, pause->tx_pause || pause->rx_pause);

	ret = sxe2_vsi_down_up_unlock(adapter->vsi_ctxt.main_vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi down up failed, ret=%d\n", ret);
		goto vsi_unlock;
	}

	LOG_INFO_BDF("lfc set tx %d rx %d.\n", pause->tx_pause, pause->rx_pause);

vsi_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

	(void)sxe2_fc_get(adapter, vsi->idx_in_dev, &new_fc);
	if (new_fc != old_fc)
		changed = true;

	if (changed && ret == 0)
		(void)sxe2_com_irq_notifier_call_chain(&adapter->com_ctxt,
						       SXE2_COM_FC_ST_CHANGE);

	return ret;
}

u32 sxe2_speed_switch_set_configure(u32 speed)
{
	u32 switch_speed;

	if (speed == SXE2_ETHTOOL_SPEED_10GB)
		switch_speed = SXE2_SET_LINK_SPEED_CFG_10G;
	else if (speed == SXE2_ETHTOOL_SPEED_25GB)
		switch_speed = SXE2_SET_LINK_SPEED_CFG_25G;
	else if (speed == SXE2_ETHTOOL_SPEED_50GB)
		switch_speed = SXE2_SET_LINK_SPEED_CFG_50G;
	else if (speed == SXE2_ETHTOOL_SPEED_100GB)
		switch_speed = SXE2_SET_LINK_SPEED_CFG_100G;
	else if (speed == SXE2_ETHTOOL_SPEED_AUTO)
		switch_speed = SXE2_SET_LINK_SPEED_CFG_AUTO;
	else
		switch_speed = SXE2_SET_LINK_SPEED_CFG_MAX;

	return switch_speed;
}

u32 sxe2_speed_dut_switch_cfg(s32 speed)
{
	u32 switch_speed;

	if (speed == SXE2_SET_LINK_SPEED_CFG_10G)
		switch_speed = SXE2_ETHTOOL_SPEED_10GB;
	else if (speed == SXE2_SET_LINK_SPEED_CFG_25G)
		switch_speed = SXE2_ETHTOOL_SPEED_25GB;
	else if (speed == SXE2_SET_LINK_SPEED_CFG_50G)
		switch_speed = SXE2_ETHTOOL_SPEED_50GB;
	else if (speed == SXE2_SET_LINK_SPEED_CFG_100G)
		switch_speed = SXE2_ETHTOOL_SPEED_100GB;
	else if (speed == SXE2_SET_LINK_SPEED_CFG_AUTO)
		switch_speed = SXE2_ETHTOOL_SPEED_AUTO;
	else
		switch_speed = SXE2_LINK_SPEED_UNKNOWN;

	return switch_speed;
}

s32 sxe2_link_get_pasist_info(struct sxe2_adapter *adapter, struct flm_link_info_pasist *cfg)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = { 0 };

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_PERSIST_GET_LINK_CFG, NULL, 0,
				  cfg, sizeof(*cfg));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("set_speed pasist, ret=%d\n", ret);
		ret = -EIO;
		goto out;
	}

	LOG_INFO_BDF("get persist cfg speed=[%d], fec=[%d],\t"
		     "linkup=[%d],fc_tx=[%d],fc_rx=[%d] .\n",
		     cfg->speed, cfg->fec_mode, cfg->link_status, cfg->fc_mode.tx_en,
		     cfg->fc_mode.rx_en);

out:
	return ret;
}

STATIC void sxe2_get_active_fec(struct sxe2_adapter *adapter, struct ethtool_fecparam *fecparam)
{
	int ret = 0;
	struct ethtool_flm_link_info currect_info;
	struct sxe2_cmd_params cmd = { 0 };
	enum flm_fec_mode fec;

	ret = sxe2_get_cur_link_state(adapter, &currect_info);
	if (ret) {
		LOG_ERROR_BDF("failed to link currect info, ret=%d\n", ret);
		fecparam->active_fec = ETHTOOL_FEC_NONE;
		return;
	}

	if (currect_info.link_status == SXE2_LINK_DOWN) {
		LOG_ERROR_BDF("link state is down");
		fecparam->active_fec = ETHTOOL_FEC_NONE;
		return;
	}

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_SFP_GET_FEC_CFG, NULL, 0, &fec,
				  sizeof(fec));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("fec get cmd fail, ret=%d\n", ret);
		fecparam->active_fec = ETHTOOL_FEC_NONE;
		return;
	}

	switch (fec) {
	case FLM_FEC_AUTO:
		fecparam->active_fec = ETHTOOL_FEC_AUTO;
		break;
	case FLM_FEC_528:
	case FLM_FEC_544:
		fecparam->active_fec = ETHTOOL_FEC_RS;
		break;
	case FLM_FEC_BSFEC:
		fecparam->active_fec = ETHTOOL_FEC_BASER;
		break;
	case FLM_FEC_NONE:
		fecparam->active_fec = ETHTOOL_FEC_OFF;
		break;
	default:
		fecparam->active_fec = ETHTOOL_FEC_OFF;
		break;
	}
}

STATIC void sxe2_get_fw_cur_fec(struct sxe2_adapter *adapter, struct ethtool_fecparam *fecparam)
{
	int ret = 0;
	struct flm_link_info_pasist currect_info;

	ret = sxe2_link_get_pasist_info(adapter, &currect_info);
	if (ret) {
		LOG_ERROR_BDF("failed to link currect info, ret=%d\n", ret);
		fecparam->fec = ETHTOOL_FEC_AUTO;
		return;
	}

	if (currect_info.fec_mode == FLM_FEC_AUTO)
		fecparam->fec |= ETHTOOL_FEC_AUTO;
	else if (currect_info.fec_mode == FLM_FEC_NONE)
		fecparam->fec |= ETHTOOL_FEC_OFF;
	else if (currect_info.fec_mode == FLM_FEC_BSFEC)
		fecparam->fec |= ETHTOOL_FEC_BASER;
	else if (currect_info.fec_mode == FLM_FEC_528)
		fecparam->fec |= ETHTOOL_FEC_RS;
	else if (currect_info.fec_mode == FLM_FEC_544)
		fecparam->fec |= ETHTOOL_FEC_RS;
	else
		fecparam->fec |= ETHTOOL_FEC_AUTO;
}

STATIC int sxe2_get_fec(struct net_device *netdev,
			struct ethtool_fecparam *fecparam)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter  = priv->vsi->adapter;

	sxe2_get_active_fec(adapter, fecparam);

	sxe2_get_fw_cur_fec(adapter, fecparam);

	return 0;
}

STATIC int sxe2_set_fec(struct net_device *netdev,
			struct ethtool_fecparam *fecparam)
{
	int ret			      = 0;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter  = priv->vsi->adapter;
	enum sxe2_fec_mode fec;
	struct sxe2_cmd_params cmd = { 0 };
	struct ethtool_flm_link_info currect_info;

	switch (fecparam->fec) {
	case ETHTOOL_FEC_AUTO:
		fec = SXE2_ETHTOOL_FEC_AUTO;
		break;
	case ETHTOOL_FEC_RS:
		fec = SXE2_ETHTOOL_FEC_RS;
		break;
	case ETHTOOL_FEC_BASER:
		fec = SXE2_ETHTOOL_FEC_BASER;
		break;
	case ETHTOOL_FEC_OFF:
		fec = SXE2_ETHTOOL_FEC_OFF;
		break;
	case ETHTOOL_FEC_NONE:
		fec = SXE2_ETHTOOL_FEC_NONE;
		break;
	default:
		LOG_INFO_BDF("fec mode Unsupported! fecparam->fec %d\n",
			     fecparam->fec);
		fec = SXE2_ETHTOOL_FEC_NONE;
		break;
	}

	ret = sxe2_get_cur_link_state(adapter, &currect_info);
	if (ret) {
		LOG_ERROR_BDF("failed to link currect info, ret=%d\n", ret);
		return ret;
	}

	if (adapter->link_ctxt.fec == fec && currect_info.link_status) {
		LOG_INFO_BDF("user set fec[%d] is not change ,current fec[%d]",
			     fec, adapter->link_ctxt.fec);
		return ret;
	}

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_SFP_SET_FEC_CFG, &fec,
				  sizeof(fec), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("fc set cmd fail, ret=%d\n", ret);

	adapter->link_ctxt.fec = fec;

	return ret;
}

void sxe2_stop_lfc(struct sxe2_adapter *adapter)
{
	struct sxe2_fwc_lfc_info lfc = { 0 };
	struct sxe2_cmd_params cmd   = { 0 };
	struct sxe2_dcbx_cfg *curr_cfg;
	s32 ret;

	curr_cfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	if (curr_cfg->pfc.enable) {
		LOG_DEV_INFO("priority flow control enabled. No need stop link flow control.\n");
		return;
	}

	memset(&lfc, 0, sizeof(lfc));
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LINK_FLOW_CONTROL_SET, &lfc,
				  sizeof(lfc), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("lfc set cmd fail, ret=%d\n", ret);
		return;
	}
}

STATIC s32 sxe2_link_set_configure(struct sxe2_adapter *adapter, u32 speed)
{
	s32 ret			   = 0;
	struct sxe2_cmd_params cmd = { 0 };
	struct flm_link_config req;

	req.speed = speed;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ETHTOOL_SET_LINKINFO_CFG, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to link cfg, ret=%d\n", ret);
		goto out;
	}

out:
	return ret;
}

s32 sxe2_link_set_fc_configure(struct sxe2_adapter *adapter, u8 tx_fc, u8 rx_fc)
{
	s32 ret			   = 0;
	struct sxe2_cmd_params cmd = { 0 };
	struct flm_link_info req	   = { 0 };

	req.fec			   = adapter->link_ctxt.fec;
	req.speed		   = adapter->link_ctxt.current_link_speed;
	req.fc_mode.rx_en	   = rx_fc;
	req.fc_mode.tx_en	   = tx_fc;
	req.port_num		   = adapter->port_idx;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_SFP_SET_LINK_CFG, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to link cfg, ret=%d\n", ret);
		ret = -EIO;
		goto out;
	}

out:
	return ret;
}

s32 sxe2_set_link_autoneg_en(struct sxe2_adapter *adapter, u32 an_en)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };
	struct configure_an req;

	memset(&req, 0, sizeof(req));
	req.an_en = an_en;
	req.port  = adapter->port_idx;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FLM_AN_SET, &req, sizeof(req),
				  NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("fc set cmd fail, ret=%d\n", ret);
		goto out;
	}

out:
	return ret;
}

s32 sxe2_get_link_configure(struct sxe2_adapter *adapter,
			    struct flm_ethtool_get_link_resp *link_cfg)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };
	struct flm_ethtool_get_link_req req;

	req.port_num = adapter->port_idx;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ETHTOOL_GET_LINKINFO_CFG, &req,
				  sizeof(req), link_cfg,
				  sizeof(struct flm_ethtool_get_link_resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to link cfg, ret=%d\n", ret);
		ret = -EIO;
		goto out;
	}

out:
	return ret;
}

s32 sxe2_get_support_speed_ability(struct sxe2_adapter *adapter,
				   struct support_speed_ability_mode *speed_ability)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_SUPPORT_SPEED_GET_CFG, NULL, 0,
				  speed_ability,
				  sizeof(struct support_speed_ability_mode));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to link cfg, ret=%d\n", ret);
		ret = -EIO;
		goto out;
	}

out:
	return ret;
}

static void sxe2_ethtool_support_fec_get(struct support_speed_ability_mode *speed_ability,
					 struct ethtool_link_ksettings *ks)
{
	ethtool_link_ksettings_add_link_mode(ks, supported, FEC_NONE);
	if (speed_ability->ability_speed_100Gcr4 || speed_ability->ability_speed_100Gkr4)
		ethtool_link_ksettings_add_link_mode(ks, supported, FEC_RS);

	if (speed_ability->ability_speed_50Gcr2 || speed_ability->ability_speed_50Gkr2)
		ethtool_link_ksettings_add_link_mode(ks, supported, FEC_RS);

	if (speed_ability->ability_speed_25Gcr || speed_ability->ability_speed_25Gkr ||
	    speed_ability->ability_speed_25Gkrcr || speed_ability->ability_speed_25Gkrcr_s) {
		ethtool_link_ksettings_add_link_mode(ks, supported, FEC_BASER);
		ethtool_link_ksettings_add_link_mode(ks, supported, FEC_RS);
	}

	if (speed_ability->ability_speed_10Gkr) {
		ethtool_link_ksettings_add_link_mode(ks, supported, FEC_BASER);
		ethtool_link_ksettings_add_link_mode(ks, supported, FEC_RS);
	}
}

s32 sxe2_phy_type_to_ethtool(struct net_device *netdev,
			     struct ethtool_link_ksettings *ks)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;
	s32 ret = 0;
	struct flm_ethtool_get_link_resp link_cfg;
	struct support_speed_ability_mode speed_ability;
	struct flm_link_info_pasist pasist_info;

	ethtool_link_ksettings_zero_link_mode(ks, supported);
	ethtool_link_ksettings_zero_link_mode(ks, advertising);
	(void)memset(&speed_ability, 0, sizeof(struct support_speed_ability_mode));
	(void)memset(&pasist_info, 0, sizeof(struct flm_link_info_pasist));
	(void)memset(&link_cfg, 0, sizeof(struct flm_ethtool_get_link_resp));

	ret = sxe2_get_link_configure(adapter, &link_cfg);
	if (ret)
		LOG_ERROR_BDF("failed to link cfg, ret=%d\n", ret);

	ret = sxe2_get_support_speed_ability(adapter, &speed_ability);
	if (ret)
		LOG_ERROR_BDF("failed to get  speed_ability, ret=%d\n", ret);

	ret = sxe2_link_get_pasist_info(adapter, &pasist_info);
	if (ret)
		LOG_ERROR_BDF("failed to get  speed_ability, ret=%d\n", ret);

	if (speed_ability.ability_speed_10Gkr) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     10000baseKR_Full);
		if (link_cfg.current_an_en.current_an &&
		    (pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_10G ||
		     pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     10000baseKR_Full);
		}
	}
	if (speed_ability.ability_speed_25Gcr ||
	    speed_ability.ability_speed_25Gkrcr_s) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     25000baseCR_Full);
		if (link_cfg.current_an_en.current_an &&
		    (pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_25G ||
		     pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     25000baseCR_Full);
		}
	}
	if (speed_ability.ability_speed_25Gkr) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     25000baseKR_Full);
		if (link_cfg.current_an_en.current_an &&
		    (pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_25G ||
		     pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     25000baseKR_Full);
		}
	}
	if (speed_ability.ability_speed_50Gcr2) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     50000baseCR2_Full);
		if (link_cfg.current_an_en.current_an &&
		    (pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_50G ||
		     pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     50000baseCR2_Full);
		}
	}
	if (speed_ability.ability_speed_50Gkr2) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     50000baseKR2_Full);
		if (link_cfg.current_an_en.current_an &&
		    (pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_50G ||
		     pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     50000baseKR2_Full);
		}
	}
	if (speed_ability.ability_speed_100Gkr4) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     100000baseKR4_Full);
		if (link_cfg.current_an_en.current_an &&
		    (pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_100G ||
		     pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     100000baseKR4_Full);
		}
	}
	if (speed_ability.ability_speed_100Gcr4) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     100000baseCR4_Full);
		if (link_cfg.current_an_en.current_an &&
		    (pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_100G ||
		     pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     100000baseCR4_Full);
		}
	}
	if (speed_ability.ability_speed_100Gsr4) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     100000baseSR4_Full);
		if (link_cfg.current_an_en.current_an &&
		    (pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_100G ||
		     pasist_info.speed == SXE2_SET_LINK_SPEED_CFG_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     100000baseSR4_Full);
		}
	}

	if (link_cfg.an_publicity.an_mode.speed_ability_10Gkr) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     10000baseKR_Full);
	}
	if (link_cfg.an_publicity.an_mode.speed_ability_25Gkrcr ||
	    link_cfg.an_publicity.an_mode.speed_ability_25Gkrcr_s) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     25000baseKR_Full);
	}
	if (link_cfg.an_publicity.an_np_mode.speed_ability_25Gkr) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     25000baseKR_Full);
	}
	if (link_cfg.an_publicity.an_np_mode.speed_ability_25Gcr) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     25000baseCR_Full);
	}
	if (link_cfg.an_publicity.an_np_mode.speed_ability_50Gcr2) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     50000baseCR2_Full);
	}
	if (link_cfg.an_publicity.an_np_mode.speed_ability_50Gkr2) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     50000baseKR2_Full);
	}
	if (link_cfg.an_publicity.an_mode.speed_ability_100Gcr4) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     100000baseCR4_Full);
	}
	if (link_cfg.an_publicity.an_mode.speed_ability_100Gkr4) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     100000baseKR4_Full);
	}

	sxe2_ethtool_support_fec_get(&speed_ability, ks);

	return ret;
}

s32 sxe2_get_cur_link_state(struct sxe2_adapter *adapter,
			    struct ethtool_flm_link_info *currect_info)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_CURRENT_SPEED_GET_CFG,
				  NULL, 0, currect_info,
				  sizeof(struct ethtool_flm_link_info));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to link currect info, ret=%d\n", ret);
		ret = -EIO;
		goto out;
	}

out:
	return ret;
}

static void sxe2_advertise_fec_get(struct ethtool_link_ksettings *ks,
				   struct flm_ethtool_get_link_resp *link_cfg,
				   struct ethtool_flm_link_info *currect_info)
{
	if (currect_info->link_status == SXE2_LINK_UP) {
		ethtool_link_ksettings_add_link_mode(ks, advertising, FEC_NONE);
		if (link_cfg->advertis_fec.fec_br)
			ethtool_link_ksettings_add_link_mode(ks, advertising, FEC_BASER);

		if (link_cfg->advertis_fec.fec_528 || link_cfg->advertis_fec.fec_544)
			ethtool_link_ksettings_add_link_mode(ks, advertising, FEC_RS);
	}
}

static void sxe2_advertise_link_mode_get(struct ethtool_link_ksettings *ks,
					 struct flm_ethtool_get_link_resp *link_cfg,
					 struct ethtool_flm_link_info *currect_info)
{
	if (!link_cfg->current_an_en.current_an) {
		if ((currect_info->speed == SXE2_SET_LINK_SPEED_CFG_10G ||
		     currect_info->speed == SXE2_SET_LINK_SPEED_CFG_AUTO) &&
		    ethtool_link_ksettings_test_link_mode(ks, supported, 10000baseKR_Full
			)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     10000baseKR_Full);
		}

		if ((currect_info->speed == SXE2_SET_LINK_SPEED_CFG_25G ||
		     currect_info->speed == SXE2_SET_LINK_SPEED_CFG_AUTO) &&
		    ethtool_link_ksettings_test_link_mode(ks, supported, 25000baseCR_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     25000baseCR_Full);
		}

		if ((currect_info->speed == SXE2_SET_LINK_SPEED_CFG_25G ||
		     currect_info->speed == SXE2_SET_LINK_SPEED_CFG_AUTO) &&
		    ethtool_link_ksettings_test_link_mode(ks, supported, 25000baseKR_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     25000baseKR_Full);
		}

		if ((currect_info->speed == SXE2_SET_LINK_SPEED_CFG_50G ||
		     currect_info->speed == SXE2_SET_LINK_SPEED_CFG_AUTO) &&
		    ethtool_link_ksettings_test_link_mode(ks, supported, 50000baseCR2_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     50000baseCR2_Full);
		}

		if ((currect_info->speed == SXE2_SET_LINK_SPEED_CFG_50G ||
		     currect_info->speed == SXE2_SET_LINK_SPEED_CFG_AUTO) &&
		    ethtool_link_ksettings_test_link_mode(ks, supported, 50000baseKR2_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     50000baseKR2_Full);
		}

		if ((currect_info->speed == SXE2_SET_LINK_SPEED_CFG_100G ||
		     currect_info->speed == SXE2_SET_LINK_SPEED_CFG_AUTO) &&
		    ethtool_link_ksettings_test_link_mode(ks, supported, 100000baseKR4_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     100000baseKR4_Full);
		}

		if ((currect_info->speed == SXE2_SET_LINK_SPEED_CFG_100G ||
		     currect_info->speed == SXE2_SET_LINK_SPEED_CFG_AUTO) &&
		    ethtool_link_ksettings_test_link_mode(ks, supported, 100000baseCR4_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     100000baseCR4_Full);
		}

		if ((currect_info->speed == SXE2_SET_LINK_SPEED_CFG_100G ||
		     currect_info->speed == SXE2_SET_LINK_SPEED_CFG_AUTO) &&
		    ethtool_link_ksettings_test_link_mode(ks, supported, 100000baseSR4_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     100000baseSR4_Full);
		}
	}
}

STATIC int sxe2_get_link_requir_cfg(struct net_device *netdev,
				    struct ethtool_link_ksettings *ks, u32 *speed)
{
	s32 ret = 0;
	u32 supported;
	u32 advertising;
	u32 lp_advertising;
	struct flm_ethtool_get_link_resp link_cfg;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;
	struct ethtool_flm_link_info currect_info;

	(void)ethtool_convert_link_mode_to_legacy_u32(&supported,
						ks->link_modes.supported);
	(void)ethtool_convert_link_mode_to_legacy_u32(&advertising,
						ks->link_modes.advertising);
	(void)ethtool_convert_link_mode_to_legacy_u32(&lp_advertising,
						ks->link_modes.lp_advertising);

	ret = sxe2_get_link_configure(adapter, &link_cfg);
	if (ret) {
		LOG_ERROR_BDF("failed to link cfg, ret=%d\n", ret);
		link_cfg.optical_module.current_connection = SXE2_FW_CONNECT_MDDE_UNKNOWN;
	}

	ret = sxe2_get_cur_link_state(adapter, &currect_info);
	if (ret) {
		LOG_ERROR_BDF("failed to link currect info, ret=%d\n", ret);
		link_cfg.optical_module.current_connection = SXE2_FW_CONNECT_MDDE_UNKNOWN;
	}

	sxe2_advertise_fec_get(ks, &link_cfg, &currect_info);

	sxe2_advertise_link_mode_get(ks, &link_cfg, &currect_info);
	*speed = sxe2_speed_dut_switch_cfg(currect_info.speed);
	if (currect_info.link_status) {
		switch (*speed) {
		case SXE2_ETHTOOL_SPEED_10GB:
			ks->base.speed = SPEED_10000;
			ks->base.duplex = DUPLEX_FULL;
			break;
		case SXE2_ETHTOOL_SPEED_25GB:
			ks->base.speed	= SPEED_25000;
			ks->base.duplex = DUPLEX_FULL;
			break;
		case SXE2_ETHTOOL_SPEED_50GB:
			ks->base.speed	= SPEED_50000;
			ks->base.duplex = DUPLEX_FULL;
			break;
		case SXE2_ETHTOOL_SPEED_100GB:
			ks->base.speed	= SPEED_100000;
			ks->base.duplex = DUPLEX_FULL;
			break;
		default:
			ks->base.speed	= SPEED_UNKNOWN;
			ks->base.duplex = DUPLEX_UNKNOWN;
			break;
		}
	} else {
		ks->base.speed	= SPEED_UNKNOWN;
		ks->base.duplex = DUPLEX_UNKNOWN;
	}

	switch (link_cfg.optical_module.current_connection) {
	case SXE2_FW_CONNECT_MODE_TRANSCEIVER:
		ethtool_link_ksettings_add_link_mode(ks, supported, FIBRE);
		ks->base.port = PORT_FIBRE;
		break;
	case SXE2_FW_CONNECT_MODE_BACKPLANE:
		ethtool_link_ksettings_add_link_mode(ks, supported, Backplane);
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     Backplane);
		ks->base.port = PORT_NONE;
		break;
	case SXE2_FW_CONNECT_MODE_DAC:
		ethtool_link_ksettings_add_link_mode(ks, supported, TP);
		ethtool_link_ksettings_add_link_mode(ks, advertising, TP);
		ks->base.port = PORT_DA;
		break;
	case SXE2_FW_CONNECT_MODE_AOC:
		ethtool_link_ksettings_add_link_mode(ks, supported, FIBRE);
		ethtool_link_ksettings_add_link_mode(ks, advertising, FIBRE);
		ks->base.port = PORT_FIBRE;
		break;
	default:
		ks->base.port = PORT_OTHER;
		break;
	}

	ethtool_link_ksettings_add_link_mode(ks, supported, Pause);
	if (link_cfg.sxe2_ana_fsm == SXE2_AN_GOOD) {
		if (link_cfg.partner_pause_result.tx_en &&
		    link_cfg.partner_pause_result.rx_en) {
			ethtool_link_ksettings_add_link_mode(ks, lp_advertising,
							     Pause);
		} else if (link_cfg.partner_pause_result.tx_en) {
			ethtool_link_ksettings_add_link_mode(ks, lp_advertising,
							     Pause);
			ethtool_link_ksettings_add_link_mode(ks, lp_advertising,
							     Asym_Pause);
		} else if (link_cfg.partner_pause_result.rx_en) {
			ethtool_link_ksettings_add_link_mode(ks, lp_advertising,
							     Asym_Pause);
		} else {
			ethtool_link_ksettings_del_link_mode(ks, lp_advertising,
							     Pause);
			ethtool_link_ksettings_del_link_mode(ks, lp_advertising,
							     Asym_Pause);
		}
	}

	return ret;
}

static int sxe2_get_link_ksettings(struct net_device *netdev,
				   struct ethtool_link_ksettings *ks)
{
	u32 supported;
	u32 advertising;
	u32 lp_advertising;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi = priv->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	u32 speed = 0;
	s32 ret = 0;
	struct flm_ethtool_get_link_resp link_cfg;

	(void)ethtool_convert_link_mode_to_legacy_u32(&supported,
						ks->link_modes.supported);
	(void)ethtool_convert_link_mode_to_legacy_u32(&advertising,
						ks->link_modes.advertising);
	(void)ethtool_convert_link_mode_to_legacy_u32(&lp_advertising,
						ks->link_modes.lp_advertising);

	ret = sxe2_phy_type_to_ethtool(netdev, ks);
	if (ret)
		LOG_ERROR_BDF("failed to get phy type, ret=%d\n", ret);

	ret = sxe2_get_link_configure(adapter, &link_cfg);
	if (ret)
		LOG_ERROR_BDF("failed to link cfg, ret=%d\n", ret);

	ks->base.autoneg = link_cfg.current_an_en.current_an;
	ret = sxe2_get_link_requir_cfg(netdev, ks, &speed);
	if (ret)
		LOG_ERROR_BDF("get link requir cfg failed, ret=%d\n", ret);

	adapter->link_ctxt.current_link_speed = speed;
	if (link_cfg.configed_pause_result.tx_en &&
	    link_cfg.configed_pause_result.rx_en) {
		ethtool_link_ksettings_add_link_mode(ks, advertising, Pause);
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     Asym_Pause);
	} else if (link_cfg.configed_pause_result.tx_en) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     Asym_Pause);
	} else if (link_cfg.configed_pause_result.rx_en) {
		ethtool_link_ksettings_add_link_mode(ks, advertising, Pause);
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     Asym_Pause);
	} else {
		ethtool_link_ksettings_add_link_mode(ks, advertising, Pause);
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     Asym_Pause);
	}

	if (link_cfg.local_an_en.suppert_an)
		ethtool_link_ksettings_add_link_mode(ks, supported, Autoneg);

	if (link_cfg.local_an_en.advertis_an)
		ethtool_link_ksettings_add_link_mode(ks, advertising, Autoneg);

	return ret;
}

u32 sxe2_ksettings_find_adv_link_speed(const struct ethtool_link_ksettings *ks)
{
	u32 adv_link_speed = 0;

	if (ethtool_link_ksettings_test_link_mode(ks, advertising,
						  10000baseKR_Full))
		adv_link_speed |= LINK_SPEED_10G;
	if (ethtool_link_ksettings_test_link_mode(ks, advertising,
						  10000baseSR_Full))
		adv_link_speed |= LINK_SPEED_10G;
	if (ethtool_link_ksettings_test_link_mode(ks, advertising,
						  100000baseCR4_Full) ||
	    ethtool_link_ksettings_test_link_mode(ks, advertising,
						  100000baseSR4_Full) ||
	    ethtool_link_ksettings_test_link_mode(ks, advertising,
						  100000baseLR4_ER4_Full) ||
	    ethtool_link_ksettings_test_link_mode(ks, advertising,
						  100000baseKR4_Full))
		adv_link_speed |= LINK_SPEED_100G;

	if (ethtool_link_ksettings_test_link_mode(ks, advertising,
						  25000baseCR_Full) ||
	    ethtool_link_ksettings_test_link_mode(ks, advertising,
						  25000baseSR_Full) ||
	    ethtool_link_ksettings_test_link_mode(ks, advertising,
						  25000baseKR_Full))
		adv_link_speed |= LINK_SPEED_25G;

	if (ethtool_link_ksettings_test_link_mode(ks, advertising,
						  50000baseCR2_Full) ||
	    ethtool_link_ksettings_test_link_mode(ks, advertising,
						  50000baseKR2_Full))
		adv_link_speed |= LINK_SPEED_50G;
	if (ethtool_link_ksettings_test_link_mode(ks, advertising,
						  50000baseSR2_Full))
		adv_link_speed |= LINK_SPEED_50G;

	return adv_link_speed;
}

static u32 sxe2_get_usr_req_link_speed(u32 adv_link_speed)
{
	u8 speed_cnt = 0;
	u32 user_req_link_speed = 0;

	if (adv_link_speed & LINK_SPEED_10G) {
		speed_cnt++;
		user_req_link_speed = SXE2_ETHTOOL_SPEED_10GB;
	}

	if (adv_link_speed & LINK_SPEED_25G) {
		speed_cnt++;
		user_req_link_speed = SXE2_ETHTOOL_SPEED_25GB;
	}

	if (adv_link_speed & LINK_SPEED_50G) {
		speed_cnt++;
		user_req_link_speed = SXE2_ETHTOOL_SPEED_50GB;
	}

	if (adv_link_speed & LINK_SPEED_100G) {
		speed_cnt++;
		user_req_link_speed = SXE2_ETHTOOL_SPEED_100GB;
	}

	if (speed_cnt > 1)
		user_req_link_speed = SXE2_ETHTOOL_SPEED_AUTO;

	return user_req_link_speed;
}

static bool sxe2_check_is_advertise_set(const struct ethtool_link_ksettings *ks,
					u32 current_link_speed)
{
	if (ks->base.speed == SXE2_PF_DOWN_ETHTOOL_BASE_SPEED)
		return true;

	if (ks->base.speed == current_link_speed)
		return true;

	return false;
}

static bool sxe2_check_usr_link_speed_change(struct ethtool_flm_link_info *currect_info,
					     const struct ethtool_link_ksettings *ks,
					     u32 *user_link_speed,
					     u32 current_link_speed,
					     struct flm_link_info_pasist *pasist_info)
{
	u32 last_pasist_speed = sxe2_speed_dut_switch_cfg(pasist_info->speed);

	if (sxe2_check_is_advertise_set(ks, current_link_speed)) {
		if (currect_info->link_status == SXE2_LINK_UP) {
			if (*user_link_speed != SXE2_ETHTOOL_SPEED_AUTO &&
			    *user_link_speed != current_link_speed)
				return true;

			if (last_pasist_speed != *user_link_speed)
				return true;

		} else {
			if (ks->base.speed != SXE2_PF_DOWN_ETHTOOL_BASE_SPEED)
				*user_link_speed = ks->base.speed;

			return true;
		}
	} else {
		if (ks->base.speed != current_link_speed) {
			*user_link_speed = ks->base.speed;
			return true;
		}
	}

	return false;
}

static bool sxe2_check_speed_param_valid(u32 user_link_speed)
{
	bool ret = false;

	switch (user_link_speed) {
	case SXE2_ETHTOOL_SPEED_10GB:
	case SXE2_ETHTOOL_SPEED_25GB:
	case SXE2_ETHTOOL_SPEED_50GB:
	case SXE2_ETHTOOL_SPEED_100GB:
	case SXE2_ETHTOOL_SPEED_AUTO:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

static int sxe2_set_link_ksettings(struct net_device *netdev,
				   const struct ethtool_link_ksettings *ks)
{
	s32 ret				      = 0;
	struct sxe2_netdev_priv *priv	      = netdev_priv(netdev);
	struct sxe2_vsi *vsi		      = priv->vsi;
	struct sxe2_adapter *adapter	      = vsi->adapter;
	struct ethtool_link_ksettings copy_ks = *ks;
	struct ethtool_link_ksettings safe_ks = {};
	u8 autoneg;
	bool autoneg_change = 0;
	u32 adv_link_speed = 0;
	u32 current_link_speed = 0;
	u32 usr_link_speed = 0;
	struct ethtool_flm_link_info currect_info;
	struct flm_ethtool_get_link_resp link_cfg;
	struct flm_link_info_pasist pasist_info;

	autoneg = copy_ks.base.autoneg;
	memset(&safe_ks, 0, sizeof(safe_ks));
	safe_ks.base.cmd = copy_ks.base.cmd;
	safe_ks.base.link_mode_masks_nwords =
		copy_ks.base.link_mode_masks_nwords;
	ret = sxe2_get_link_ksettings(netdev, &safe_ks);
	if (ret) {
		LOG_ERROR_BDF("get link ksetting failed to link cfg, ret=%d\n",
			      ret);
		goto l_end;
	}

	ret = sxe2_get_cur_link_state(adapter, &currect_info);
	if (ret) {
		LOG_ERROR_BDF("failed to link currect info, ret=%d\n", ret);
		goto l_end;
	}

	ret = sxe2_get_link_configure(adapter, &link_cfg);
	if (ret) {
		LOG_ERROR_BDF("failed to link cfg, ret=%d\n", ret);
		goto l_end;
	}

	ret = sxe2_link_get_pasist_info(adapter, &pasist_info);
	if (ret)
		LOG_ERROR_BDF("failed to get usr pasit info, ret=%d\n", ret);

	if (link_cfg.optical_module.current_connection == SXE2_FW_CONNECT_MDDE_UNKNOWN) {
		ret = -EIO;
		LOG_ERROR_BDF("medial set cmd fail, ret=%d\n", ret);
		goto l_end;
	}

	if (link_cfg.current_an_en.current_an == AUTONEG_DISABLE &&
	    autoneg == AUTONEG_ENABLE) {
		ret = sxe2_set_link_autoneg_en(adapter, autoneg);
		if (ret) {
			LOG_ERROR_BDF("failed to autoneg, ret=%d\n", ret);
			goto l_end;
		}
		autoneg_change = 1;
	} else if ((link_cfg.current_an_en.current_an == AUTONEG_ENABLE) &&
		   (autoneg == AUTONEG_DISABLE)) {
		ret = sxe2_set_link_autoneg_en(adapter, autoneg);
		if (ret) {
			LOG_ERROR_BDF("failed to autoneg, ret=%d\n", ret);
			goto l_end;
		}
		autoneg_change = 1;
	}

	adv_link_speed = sxe2_ksettings_find_adv_link_speed(ks);
	usr_link_speed = sxe2_get_usr_req_link_speed(adv_link_speed);
	current_link_speed = adapter->link_ctxt.current_link_speed;
	if (!autoneg_change) {
		if (!sxe2_check_usr_link_speed_change(&currect_info,
						      ks,
						      &usr_link_speed,
						      current_link_speed, &pasist_info)) {
			LOG_INFO_BDF("linkup and config same not set!!\n");
			goto l_end;
		}
	} else {
		if (ks->base.speed != current_link_speed &&
		    ks->base.speed != SXE2_PF_DOWN_ETHTOOL_BASE_SPEED)
			usr_link_speed = ks->base.speed;
	}

	if (!sxe2_check_speed_param_valid(usr_link_speed))
		return -EOPNOTSUPP;

	if (currect_info.link_status == SXE2_LINK_UP) {
		netif_carrier_off(netdev);
		netif_tx_stop_all_queues(netdev);
		LOG_INFO_BDF("set ksetting carrier off link down.\n");
	}

	ret = sxe2_link_set_configure(adapter, usr_link_speed);
	if (ret)
		LOG_ERROR_BDF("Set phy link config failed\n");

	if (ret != 0) {
		if (autoneg_change)
			ret = 0;

		if (currect_info.link_status == SXE2_LINK_UP &&
		    (usr_link_speed == SXE2_ETHTOOL_SPEED_AUTO ||
		     usr_link_speed == current_link_speed)) {
			ret = 0;
		}

		if (currect_info.link_status == SXE2_LINK_UP) {
			netif_carrier_on(netdev);
			netif_tx_start_all_queues(netdev);
		}
	}

	adapter->link_ctxt.current_link_speed = adv_link_speed;
l_end:

	return ret;
}

STATIC int sxe2_set_channels_fnav_check(struct sxe2_adapter *adapter,
					u32 new_cnt)
{
	int ret				= 0;
	struct sxe2_fnav_filter *filter = NULL;
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;

	mutex_lock(&adapter->fnav_ctxt.filter_lock);
	list_for_each_entry(filter, &vsi->fnav.filter_list,
			    l_node) {
		if (filter->act_type == SXE2_FNAV_ACT_QINDEX &&
		    filter->q_index >= new_cnt) {
			ret = -EINVAL;
			LOG_ERROR_BDF("change channel fnav check failed, loc=%u, q_id=%u.\n",
				      filter->filter_loc, filter->q_index);
			break;
		}
	}
	mutex_unlock(&adapter->fnav_ctxt.filter_lock);
	return ret;
}

static s32 sxe2_channels_check(struct net_device *netdev,
			       struct ethtool_channels *ch)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;

	s32 ret	   = 0;
	u32 new_rx = 0, new_tx = 0;

	new_rx = ch->combined_count + ch->rx_count;
	new_tx = ch->combined_count + ch->tx_count;

	if (new_rx < vsi->tc.tc_cnt) {
		LOG_NETDEV_ERR("cannot set less Rx channels,\t"
			       "than Traffic Classes you have (%u)\n",
			       vsi->tc.tc_cnt);
		ret = -EINVAL;
		goto l_end;
	}

	if (new_tx < vsi->tc.tc_cnt) {
		LOG_NETDEV_ERR("cannot set less Tx channels, \t"
			       "than Traffic Classes you have (%u)\n",
			       vsi->tc.tc_cnt);
		ret = -EINVAL;
		goto l_end;
	}

	if (new_rx > sxe2_max_rxq_get(adapter)) {
		LOG_NETDEV_ERR("ethtool set channels failed, maximum allowed rx channels is %u\n",
			       sxe2_max_rxq_get(adapter));
		ret = -EINVAL;
		goto l_end;
	}

	if (new_tx > sxe2_max_txq_get(adapter)) {
		LOG_NETDEV_ERR("ethtool set channels failed, maximum allowed tx channels is %u\n",
			       sxe2_max_txq_get(adapter));
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2_set_channels_fnav_check(adapter, new_rx);
	if (ret)
		goto l_end;

l_end:
	return ret;
}

s32 sxe2_vsi_qs_reassign(struct net_device *netdev, struct ethtool_channels *ch)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;
	u32 cur_combined;
	u32 new_rx = 0, new_tx = 0;
	s32 ret = 0;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		LOG_ERROR_BDF("vsi disabled, try later.\n");
		goto l_unlock;
	}

	if (sxe2_is_safe_mode(adapter)) {
		LOG_NETDEV_ERR("ethtool set channels in safe mode is not supported\n");
		ret = -EOPNOTSUPP;
		goto l_unlock;
	}

	if (test_bit(SXE2_FLAG_MACVLAN_ENABLE, adapter->flags)) {
		LOG_NETDEV_ERR("cannot set channels when L2 forwarding enabled\n");
		ret = -EOPNOTSUPP;
		goto l_unlock;
	}

	cur_combined = sxe2_combined_cnt_get(vsi);
	if (ch->rx_count == vsi->rxqs.q_cnt - cur_combined)
		ch->rx_count = 0;
	if (ch->tx_count == vsi->txqs.q_cnt - cur_combined)
		ch->tx_count = 0;
	if (ch->combined_count == cur_combined)
		ch->combined_count = 0;

	if (!(ch->combined_count || (ch->rx_count && ch->tx_count))) {
		LOG_NETDEV_ERR("ethtool set channels failed, \t"
			       "please specify at least 1 rx and 1 tx channel\n");
		ret = -EINVAL;
		goto l_unlock;
	}
	new_rx = ch->combined_count + ch->rx_count;
	new_tx = ch->combined_count + ch->tx_count;

	if (new_rx > SXE2_VSI_TXRX_Q_MAX_CNT ||
	    new_tx > SXE2_VSI_TXRX_Q_MAX_CNT) {
		ret = -EINVAL;
		LOG_NETDEV_ERR("ethtool set channels failed, \t"
			       "a maximum of 256 queues can be allocated\n");
		goto l_unlock;
	}

	ret = sxe2_channels_check(netdev, ch);
	if (ret)
		goto l_unlock;

	if (netdev->features & NETIF_F_NTUPLE)
		sxe2_arfs_disable(adapter);

	if (!new_rx && !new_tx)
		goto l_unlock;

	if (new_tx)
		vsi->txqs.req_q_cnt = (u16)new_tx;
	if (new_rx)
		vsi->rxqs.req_q_cnt = (u16)new_rx;

	if (!netif_running(vsi->netdev)) {
		ret = sxe2_vsi_rebuild(vsi, false);
		if (ret)
			goto rebuild_err;
		LOG_DEV_DEBUG("link is down, \t"
			      "queue count change happens when link is brought up\n");
		goto update_filter;
	}

	(void)sxe2_vsi_close(vsi);
	ret = sxe2_vsi_rebuild(vsi, false);
	if (ret)
		goto rebuild_err;

update_filter:
	if (netdev->features & NETIF_F_NTUPLE) {
		if (sxe2_arfs_enable(adapter))
			LOG_NETDEV_WARN("arfs enable failed when set channel!");
	}

	if (!netif_is_rxfh_configured(netdev)) {
		ret = sxe2_rss_lut_reset(vsi, vsi->rxqs.req_q_cnt);
		if (ret)
			goto rebuild_err;
	}
	goto l_unlock;

rebuild_err:
	LOG_DEV_ERR("error during VSI rebuild: %d. Unload and reload the driver.\n",
		    ret);
l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

static int sxe2_channels_set(struct net_device *netdev,
			     struct ethtool_channels *ch)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;
	struct sxe2_adapter *adapter  = vsi->adapter;
	s32 ret			      = 0;

	ret = sxe2_vsi_qs_reassign(netdev, ch);
	if (ret)
		return ret;

	ret = sxe2_netdev_q_cnt_set(netdev, vsi->txqs.q_cnt, vsi->rxqs.q_cnt,
				    true);
	if (ret) {
		LOG_ERROR_BDF("new_tx:%u new_rx:%u set netdev queue cnt failed.\n",
			      vsi->txqs.q_cnt, vsi->rxqs.q_cnt);
		goto l_rollback;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		LOG_ERROR_BDF("vsi disabled, try later.\n");
		goto l_out;
	}

	if (netif_running(vsi->netdev) && sxe2_vsi_open(vsi)) {
		ret = -EIO;
		goto l_out;
	}

l_out:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;

l_rollback:
	mutex_lock(&adapter->vsi_ctxt.lock);
	(void)sxe2_vsi_disable_unlock(vsi);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

STATIC s32 sxe2_flash_device(struct net_device *dev,
			     struct ethtool_flash *flash)
{
	if (flash->region == ETHTOOL_FLASH_ALL_REGIONS ||
	    flash->region > SXE2_INVAL_U16)
		return sxe2_flash_package_from_file(dev, flash->data,
						    flash->region);
	else
		return -EPERM;
}

#ifdef SUPPORT_ETHTOOL_GET_RMON_STATS
static void sxe2_get_rmon_stats(struct net_device *netdev,
				struct ethtool_rmon_stats *rmon_stats,
				const struct ethtool_rmon_hist_range **ranges)
{
	struct sxe2_netdev_priv *priv	     = netdev_priv(netdev);
	struct sxe2_vsi *vsi		     = priv->vsi;
	struct sxe2_adapter *adapter	     = vsi->adapter;
	struct sxe2_pf_hw_stats *pf_hw_stats = &adapter->pf_stats.pf_hw_stats;

	mutex_lock(&adapter->vsi_ctxt.lock);

	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state))
		goto l_unlock;

	sxe2_hw_pf_stats_update(adapter);

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

	rmon_stats->undersize_pkts = pf_hw_stats->rx_undersize_good;
	rmon_stats->fragments	   = pf_hw_stats->rx_runt_error;
	rmon_stats->jabbers	   = pf_hw_stats->rx_jabbers;
	rmon_stats->oversize_pkts  = pf_hw_stats->rx_oversize_good;

	rmon_stats->hist[0] = pf_hw_stats->rx_size_64;
	rmon_stats->hist[1] = pf_hw_stats->rx_size_65_127;
	rmon_stats->hist[2] = pf_hw_stats->rx_size_128_255;
	rmon_stats->hist[3] = pf_hw_stats->rx_size_256_511;
	rmon_stats->hist[4] = pf_hw_stats->rx_size_512_1023;
	rmon_stats->hist[5] = pf_hw_stats->rx_size_1024_1522;
	rmon_stats->hist[6] = pf_hw_stats->rx_size_1523_max;

	*ranges = sxe2_rmon_ranges;
}
#endif

static const struct ethtool_ops sxe2_ethtool_ops = {
#ifdef SUPPORTED_COALESCE_PARAMS
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
				     ETHTOOL_COALESCE_USE_ADAPTIVE |
				     ETHTOOL_COALESCE_RX_USECS_HIGH,
#endif
	.get_drvinfo		= sxe2_get_drvinfo,
	.get_regs_len		= sxe2_get_regs_len,
	.get_regs		= sxe2_get_regs,
	.get_strings		= sxe2_get_strings,
	.get_ethtool_stats	= sxe2_get_ethtool_stats,
	.get_priv_flags		= sxe2_ethtool_priv_flags_get,
	.set_priv_flags		= sxe2_ethtool_priv_flags_set,
	.get_sset_count		= sxe2_get_sset_count,
	.get_ringparam		= sxe2_get_ringparam,
	.set_ringparam		= sxe2_set_ringparam,
	.get_coalesce		= sxe2_get_coalesce,
	.set_coalesce		= sxe2_set_coalesce,
	.get_per_queue_coalesce = sxe2_get_per_queue_coalesce,
	.set_per_queue_coalesce = sxe2_set_per_queue_coalesce,
	.get_channels		= sxe2_channels_get,
	.set_channels		= sxe2_channels_set,

	.get_module_info     = sxe2_module_info_get,
	.get_module_eeprom   = sxe2_module_eeprom_get,
#ifdef SUPPORTED_ETHTOOL_EEPROM_BY_PAGE
	.get_module_eeprom_by_page  = sxe2_module_eeprom_get_by_page,
#endif

#ifndef SXE2_HARDWARE_SIM
	.self_test	     = sxe2_ethtool_selftest,
#endif
	.get_pauseparam	     = sxe2_get_pauseparam,
	.set_pauseparam	     = sxe2_set_pauseparam,
	.get_rxnfc	     = sxe2_get_rxnfc,
	.set_rxnfc	     = sxe2_set_rxnfc,
	.get_rxfh_key_size   = sxe2_get_rxft_key_size,
	.get_rxfh_indir_size = sxe2_get_rxft_indir_size,
	.get_rxfh	     = sxe2_get_rxfh,
	.set_rxfh	     = sxe2_set_rxfh,
	.set_phys_id	     = sxe2_set_phys_id,
	.get_ts_info	     = sxe2_get_ts_info,
	.flash_device	     = sxe2_flash_device,
#ifdef SUPPORT_ETHTOOL_GET_RMON_STATS
	.get_rmon_stats	     = sxe2_get_rmon_stats,
#endif

	.get_msglevel = sxe2_get_msglevel,
	.set_msglevel = sxe2_set_msglevel,
	.get_link     = ethtool_op_get_link,

	.get_fecparam	    = sxe2_get_fec,
	.set_fecparam	    = sxe2_set_fec,
	.get_link_ksettings = sxe2_get_link_ksettings,
	.set_link_ksettings = sxe2_set_link_ksettings,
};

static const struct ethtool_ops sxe2_ethtool_ops_for_safe_mode = {
#ifdef SUPPORTED_COALESCE_PARAMS
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
				     ETHTOOL_COALESCE_USE_ADAPTIVE |
				     ETHTOOL_COALESCE_RX_USECS_HIGH,
#endif
	.get_drvinfo	   = sxe2_get_drvinfo,
	.get_regs_len	   = sxe2_get_regs_len,
	.get_regs	   = sxe2_get_regs,
	.get_msglevel	   = sxe2_get_msglevel,
	.set_msglevel	   = sxe2_set_msglevel,
	.get_link	   = ethtool_op_get_link,
	.get_strings	   = sxe2_get_strings,
	.get_ethtool_stats = sxe2_get_ethtool_stats,
	.get_sset_count	   = sxe2_get_sset_count,
	.get_ringparam	   = sxe2_get_ringparam,
	.set_ringparam	   = sxe2_set_ringparam,
	.get_channels	   = sxe2_channels_get,
};

void sxe2_ethtool_ops_set(struct net_device *netdev)
{
	netdev->ethtool_ops = &sxe2_ethtool_ops;
}

void sxe2_ethtool_ops_set_for_safe_mode(struct net_device *netdev)
{
	netdev->ethtool_ops = &sxe2_ethtool_ops_for_safe_mode;
}
