// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include "xsc_eth_stats.h"
#include "xsc_eth_debug.h"
#include "xsc_eth_ethtool.h"
#include "xsc_eth.h"
#include "common/xsc_cmd.h"
#include "common/xsc_pp.h"
#include "common/port.h"
#include "xsc_eth_dim.h"

typedef int (*xsc_pflag_handler)(struct net_device *dev, bool enable);

struct pflag_desc {
	char name[ETH_GSTRING_LEN];
	xsc_pflag_handler handler;
};

static const char * const fpga_type_name[] = {"S", "L"};
static const char * const hps_ddr_name[] = {"1", "2", "4", "unknown"};
static const char * const onchip_ft_name[] = {"N", "O" };
static const char * const rdma_icrc_name[] = {"N", "C" };
static const char * const ma_xbar_name[] = {"N", "X" };
static const char * const anlt_fec_name[] = {"N", "A" };
static const char * const pp_tbl_dma_name[] = {"N", "D" };
static const char * const pct_exp_name[] = {"N", "E" };

enum {
	XSC_ST_LINK_STATE,
	XSC_ST_LINK_SPEED,
	XSC_ST_HEALTH_INFO,
#ifdef CONFIG_INET
	XSC_ST_LOOPBACK,
#endif
	XSC_ST_NUM,
};

const char xsc_self_tests[XSC_ST_NUM][ETH_GSTRING_LEN] = {
	"Link Test",
	"Speed Test",
	"Health Test",
#ifdef CONFIG_INET
	"Loopback Test",
#endif
};

static int xsc_test_loopback(struct xsc_adapter *adapter)
{
	if (adapter->status != XSCALE_ETH_DRIVER_OK) {
		netdev_err(adapter->netdev,
			   "\tCan't perform loopback test while device is down\n");
		return -ENODEV;
	}
	return 0;
}

static int xsc_test_health_info(struct xsc_adapter *adapter)
{
	struct xsc_core_health *health = &adapter->xdev->priv.health;

	return health->sick ? 1 : 0;
}

static int xsc_test_link_state(struct xsc_adapter *adapter)
{
	u8 port_state;

	if (!netif_carrier_ok(adapter->netdev))
		return 1;

	port_state = xsc_eth_get_link_status(adapter);
	return port_state == 0 ? 1 : 0;
}

static int xsc_test_link_speed(struct xsc_adapter *adapter)
{
	struct xsc_event_linkinfo linkinfo;

	if (xsc_eth_get_link_info(adapter, &linkinfo))
		return 1;

	return 0;
}

static int set_pflag_rx_no_csum_complete(struct net_device *dev,
					 bool enable)
{
	struct xsc_adapter *priv = netdev_priv(dev);

	XSC_SET_PFLAG(&priv->nic_param, XSC_PFLAG_RX_NO_CSUM_COMPLETE, enable);

	return 0;
}

static int set_pflag_sniffer(struct net_device *dev, bool enable)
{
	struct xsc_adapter *priv = netdev_priv(dev);

	XSC_SET_PFLAG(&priv->nic_param, XSC_PFLAG_SNIFFER, enable);

	return 0;
}

static int set_pflag_dropless_rq(struct net_device *dev,
				 bool enable)
{
	struct xsc_adapter *priv = netdev_priv(dev);

	XSC_SET_PFLAG(&priv->nic_param, XSC_PFLAG_DROPLESS_RQ, enable);

	return 0;
}

static int set_pflag_rx_copy_break(struct net_device *dev,
				   bool enable)
{
	struct xsc_adapter *priv = netdev_priv(dev);

	XSC_SET_PFLAG(&priv->nic_param, XSC_PFLAG_RX_COPY_BREAK, enable);

	return 0;
}

static int cqe_mode_to_period_mode(bool val)
{
	return val ? XSC_CQ_PERIOD_MODE_START_FROM_CQE : XSC_CQ_PERIOD_MODE_START_FROM_EQE;
}

static int set_pflag_cqe_based_moder(struct net_device *dev, bool enable,
				     bool is_rx_cq)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	u8 cq_period_mode, current_cq_period_mode;
	struct xsc_eth_params new_params;
	int err;

	cq_period_mode = cqe_mode_to_period_mode(enable);

	current_cq_period_mode = is_rx_cq ?
		priv->nic_param.rx_cq_moderation.cq_period_mode :
		priv->nic_param.tx_cq_moderation.cq_period_mode;

	if (cq_period_mode == current_cq_period_mode)
		return 0;

	new_params = priv->nic_param;
	if (is_rx_cq)
		xsc_set_rx_cq_mode_params(&new_params, cq_period_mode);
	else
		xsc_set_tx_cq_mode_params(&new_params, cq_period_mode);

	priv->nic_param = new_params;

	err = xsc_safe_switch_channels(priv, NULL, NULL);
	return err;
}

static int set_pflag_rx_cqe_moder(struct net_device *dev, bool enable)
{
	return set_pflag_cqe_based_moder(dev, enable, true);
}

static int set_pflag_tx_cqe_moder(struct net_device *dev, bool enable)
{
	return set_pflag_cqe_based_moder(dev, enable, false);
}

static const struct pflag_desc xsc_priv_flags[XSC_NUM_PFLAGS] = {
	{ "rx_no_csum_complete",	set_pflag_rx_no_csum_complete },
	{ "sniffer",			set_pflag_sniffer },
	{ "dropless_rq",		set_pflag_dropless_rq},
	{ "rx_copy_break",		set_pflag_rx_copy_break},
	{ "rx_cqe_moder",		set_pflag_rx_cqe_moder},
	{ "tx_cqe_moder",		set_pflag_tx_cqe_moder},
};

static int xsc_handle_pflag(struct net_device *dev,
			    u32 wanted_flags,
			    enum xsc_eth_priv_flag flag)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	bool enable = !!(wanted_flags & BIT(flag));
	u32 changes = wanted_flags ^ priv->nic_param.pflags;
	int err;

	if (!(changes & BIT(flag)))
		return 0;

	err = xsc_priv_flags[flag].handler(dev, enable);
	if (err)
		netdev_err(dev, "%s private flag '%s' failed err %d\n",
			   enable ? "Enable" : "Disable",
			   xsc_priv_flags[flag].name, err);

	return err;
}

static int xsc_set_priv_flags(struct net_device *dev, u32 pflags)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	enum xsc_eth_priv_flag pflag;
	int err;

	mutex_lock(&priv->state_lock);

	for (pflag = 0; pflag < XSC_NUM_PFLAGS; pflag++) {
		err = xsc_handle_pflag(dev, pflags, pflag);
		if (err)
			break;
	}

	mutex_unlock(&priv->state_lock);

	/* Need to fix some features.. */
	netdev_update_features(dev);

	return err;
}

static int xsc_get_module_info(struct net_device *netdev,
			       struct ethtool_modinfo *modinfo)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;
	int size_read = 0;
	u8 data[4] = {0};

	size_read = xsc_query_module_eeprom(xdev, 0, 3, data);
	if (size_read < 3)
		return -EIO;

	/* data[0] = identifier byte */
	switch (data[0]) {
	case XSC_MODULE_ID_QSFP:
		modinfo->type       = ETH_MODULE_SFF_8436;
		modinfo->eeprom_len = ETH_MODULE_SFF_8436_MAX_LEN;
		break;
	case XSC_MODULE_ID_QSFP_PLUS:
	case XSC_MODULE_ID_QSFP28:
		/* data[1] = revision id */
		if (data[0] == XSC_MODULE_ID_QSFP28 || data[1] >= 0x3) {
			modinfo->type       = ETH_MODULE_SFF_8636;
			modinfo->eeprom_len = ETH_MODULE_SFF_8636_MAX_LEN;
		} else {
			modinfo->type       = ETH_MODULE_SFF_8436;
			modinfo->eeprom_len = ETH_MODULE_SFF_8436_MAX_LEN;
		}
		break;
	case XSC_MODULE_ID_SFP:
		modinfo->type       = ETH_MODULE_SFF_8472;
		modinfo->eeprom_len = ETH_MODULE_SFF_8472_LEN;
		break;
	case XSC_MODULE_ID_QSFP_DD:
	case XSC_MODULE_ID_DSFP:
	case XSC_MODULE_ID_QSFP_PLUS_CMIS:
		modinfo->type       = ETH_MODULE_SFF_8636;
		/* Verify if module EEPROM is a flat memory. In case of flat
		 * memory only page 00h (0-255 bytes) can be read. Otherwise
		 * upper pages 01h and 02h can also be read. Upper pages 10h
		 * and 11h are currently not supported by the driver.
		 */
		if (data[2] & 0x80)
			modinfo->eeprom_len = ETH_MODULE_SFF_8636_LEN;
		else
			modinfo->eeprom_len = ETH_MODULE_SFF_8472_LEN;
		break;
	default:
		netdev_err(priv->netdev, "%s: cable type not recognized:0x%x\n",
			   __func__, data[0]);
		return -EINVAL;
	}

	return 0;
}

static int xsc_get_module_eeprom(struct net_device *netdev,
				 struct ethtool_eeprom *ee,
				 u8 *data)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;
	int offset = ee->offset;
	int size_read;
	int i = 0;

	if (!ee->len)
		return -EINVAL;

	memset(data, 0, ee->len);

	while (i < ee->len) {
		size_read = xsc_query_module_eeprom(xdev, offset, ee->len - i, data + i);

		if (!size_read)
			/* Done reading */
			return 0;

		if (size_read < 0) {
			netdev_err(priv->netdev, "%s: xsc_query_eeprom failed:0x%x\n",
				   __func__, size_read);
			return 0;
		}

		i += size_read;
		offset += size_read;
	}

	return 0;
}

static u32 xsc_get_priv_flags(struct net_device *dev)
{
	struct xsc_adapter *priv = netdev_priv(dev);

	return priv->nic_param.pflags;
}

static void xsc_set_drv_fw_version(struct ethtool_drvinfo *info, struct xsc_core_device *xdev)
{
	u8 fw_ver_major = xdev->fw_version_major;
	u8 fw_ver_minor = xdev->fw_version_minor;
	u16 fw_ver_patch = xdev->fw_version_patch;
	u32 fw_ver_tweak = xdev->fw_version_tweak;
	u8 fw_ver_extra_flag = xdev->fw_version_extra_flag;

	if (fw_ver_tweak == 0) {
		if (fw_ver_extra_flag == 0) {
			snprintf(info->fw_version, sizeof(info->fw_version), "v%u.%u.%u",
				 fw_ver_major, fw_ver_minor, fw_ver_patch);
		} else {
			snprintf(info->fw_version, sizeof(info->fw_version), "v%u.%u.%u-dirty",
				 fw_ver_major, fw_ver_minor, fw_ver_patch);
		}
	} else {
		if (fw_ver_extra_flag == 0) {
			snprintf(info->fw_version, sizeof(info->fw_version), "v%u.%u.%u+%u",
				 fw_ver_major, fw_ver_minor, fw_ver_patch, fw_ver_tweak);
		} else {
			snprintf(info->fw_version, sizeof(info->fw_version), "v%u.%u.%u+%u-dirty",
				 fw_ver_major, fw_ver_minor, fw_ver_patch, fw_ver_tweak);
		}
	}
}

static void xsc_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	struct xsc_adapter *adapter = netdev_priv(dev);

	snprintf(info->driver, sizeof(info->driver), "%s", XSCALE_DRIVER_NAME);

	if (HOTFIX_NUM == 0)
		snprintf(info->version, sizeof(info->version), "%d.%d.%d.%d",
			 BRANCH_VERSION, MAJOR_VERSION, MINOR_VERSION, BUILD_VERSION);
	else
		snprintf(info->version, sizeof(info->version), "%d.%d.%d.%d.H%d",
			 BRANCH_VERSION, MAJOR_VERSION, MINOR_VERSION, BUILD_VERSION, HOTFIX_NUM);

	xsc_set_drv_fw_version(info, adapter->xdev);
	strscpy(info->bus_info, pci_name(adapter->pdev), sizeof(info->bus_info));
}

static void xsc_fill_stats_strings(struct xsc_adapter *adapter, u8 *data)
{
	int i, idx = 0;

	for (i = 0; i < xsc_num_stats_grps; i++)
		idx = xsc_stats_grps[i].fill_strings(adapter, data, idx);
}

static int xsc_self_test_num(struct xsc_adapter *adapter)
{
	return ARRAY_SIZE(xsc_self_tests);
}

static void xsc_ethtool_get_strings(struct xsc_adapter *adapter, u32 stringset, u8 *data)
{
	int i;

	switch (stringset) {
	case ETH_SS_STATS:
		xsc_fill_stats_strings(adapter, data);
		break;
	case ETH_SS_PHY_STATS:
		xsc_get_prs_chk_err_stats_strings(adapter, data);
		break;
	case ETH_SS_TEST:
		for (i = 0; i < xsc_self_test_num(adapter); i++)
			strscpy(data + i * ETH_GSTRING_LEN,
				xsc_self_tests[i],
				ETH_GSTRING_LEN);
		break;
	case ETH_SS_PRIV_FLAGS:
		for (i = 0; i < XSC_NUM_PFLAGS; i++)
			strscpy(data + i * ETH_GSTRING_LEN,
				xsc_priv_flags[i].name,
				ETH_GSTRING_LEN);
		break;
	default:
		ETH_DEBUG_LOG("wrong stringset\n");
		break;
	}
}

static void xsc_get_strings(struct net_device *dev, u32 stringset, u8 *data)
{
	struct xsc_adapter *adapter = netdev_priv(dev);

	xsc_ethtool_get_strings(adapter, stringset, data);
}

static int xsc_ethtool_get_sset_count(struct xsc_adapter *adapter, int sset)
{
	int i, num_stats = 0;

	switch (sset) {
	case ETH_SS_STATS:
		for (i = 0; i < xsc_num_stats_grps; i++)
			num_stats += xsc_stats_grps[i].get_num_stats(adapter);
		return num_stats;
	case ETH_SS_PHY_STATS:
		return xsc_get_prs_chk_err_stats_count(adapter);
	case ETH_SS_PRIV_FLAGS:
		return XSC_NUM_PFLAGS;
	case ETH_SS_TEST:
		return xsc_self_test_num(adapter);
	default:
		return -EOPNOTSUPP;
	}
}

static int xsc_get_sset_count(struct net_device *dev, int sset)
{
	struct xsc_adapter *adapter = netdev_priv(dev);

	return xsc_ethtool_get_sset_count(adapter, sset);
}

static int (*xsc_st_func[XSC_ST_NUM])(struct xsc_adapter *) = {
	xsc_test_link_state,
	xsc_test_link_speed,
	xsc_test_health_info,
#ifdef CONFIG_INET
	xsc_test_loopback,
#endif
};

static void xsc_self_test(struct net_device *ndev, struct ethtool_test *etest, u64 *buf)
{
	struct xsc_adapter *priv = netdev_priv(ndev);
	int i;

	memset(buf, 0, sizeof(u64) * XSC_ST_NUM);

	mutex_lock(&priv->state_lock);
	netdev_info(ndev, "Self test begin..\n");

	for (i = 0; i < XSC_ST_NUM; i++) {
		netdev_info(ndev, "\t[%d] %s start..\n",
			    i, xsc_self_tests[i]);
		buf[i] = xsc_st_func[i](priv);
		netdev_info(ndev, "\t[%d] %s end: result(%lld)\n",
			    i, xsc_self_tests[i], buf[i]);
	}

	mutex_unlock(&priv->state_lock);

	for (i = 0; i < XSC_ST_NUM; i++) {
		if (buf[i]) {
			etest->flags |= ETH_TEST_FL_FAILED;
			break;
		}
	}
	netdev_info(ndev, "Self test out: status flags(0x%x)\n",
		    etest->flags);
}

static void xsc_update_stats(struct xsc_adapter *adapter)
{
	int i;

	for (i = xsc_num_stats_grps - 1; i >= 0; i--)
		if (xsc_stats_grps[i].update_stats)
			xsc_stats_grps[i].update_stats(adapter);
}

static void xsc_ethtool_get_ethtool_stats(struct xsc_adapter *adapter,
					  struct ethtool_stats *stats, u64 *data)
{
	int i, idx = 0;

	mutex_lock(&adapter->state_lock);
	xsc_update_stats(adapter);
	mutex_unlock(&adapter->state_lock);

	for (i = 0; i < xsc_num_stats_grps; i++)
		idx = xsc_stats_grps[i].fill_stats(adapter, data, idx);
}

static void xsc_get_ethtool_stats(struct net_device *dev,
				  struct ethtool_stats *stats, u64 *data)
{
	struct xsc_adapter *adapter = netdev_priv(dev);

	xsc_ethtool_get_ethtool_stats(adapter, stats, data);
}

static void xsc_get_ethtool_phy_stats(struct net_device *dev,
				      struct ethtool_stats *stats, u64 *data)
{
	struct xsc_adapter *adapter = netdev_priv(dev);

	xsc_fill_prs_chk_err_stats(adapter, data);
}

static u32 xsc_get_msglevel(struct net_device *dev)
{
	return ((struct xsc_adapter *)netdev_priv(dev))->msglevel;
}

static void xsc_set_msglevel(struct net_device *dev, u32 val)
{
	((struct xsc_adapter *)netdev_priv(dev))->msglevel = val;
}

static void xsc_get_ringparam(struct net_device *dev,
			      struct ethtool_ringparam *param,
			      struct kernel_ethtool_ringparam *kernel_param,
			      struct netlink_ext_ack *extack)
{
	struct xsc_adapter *priv = netdev_priv(dev);

	param->rx_max_pending = 8192; //hack for H3C
	param->rx_pending     = priv->nic_param.rq_size;
	param->tx_max_pending = 8192; //hack for H3C
	param->tx_pending     = priv->nic_param.sq_size;
}

static int xsc_set_ringparam(struct net_device *dev,
			     struct ethtool_ringparam *param,
			     struct kernel_ethtool_ringparam *kernel_param,
			     struct netlink_ext_ack *extack)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	u32 old_rq_size, old_sq_size;
	int err = 0;

	if (param->rx_jumbo_pending) {
		netdev_info(priv->netdev, "%s: rx_jumbo_pending not supported\n",
			    __func__);
		return -EINVAL;
	}
	if (param->rx_mini_pending) {
		netdev_info(priv->netdev, "%s: rx_mini_pending not supported\n",
			    __func__);
		return -EINVAL;
	}

	if (param->rx_pending < BIT(XSC_MIN_LOG_RQ_SZ)) {
		netdev_info(priv->netdev, "%s: rx_pending (%d) < min (%ld)\n",
			    __func__, param->rx_pending, BIT(XSC_MIN_LOG_RQ_SZ));
		return -EINVAL;
	}
	if (param->rx_pending > priv->nic_param.rq_max_size) {
		netdev_info(priv->netdev, "%s: rx_pending (%d) > max (%d)\n",
			    __func__, param->rx_pending, priv->nic_param.rq_max_size);
		param->rx_pending = priv->nic_param.rq_max_size;
	}

	if (param->tx_pending < BIT(XSC_MIN_LOG_SQ_SZ)) {
		netdev_info(priv->netdev, "%s: tx_pending (%d) < min (%ld)\n",
			    __func__, param->tx_pending, BIT(XSC_MIN_LOG_SQ_SZ));
		return -EINVAL;
	}
	if (param->tx_pending > priv->nic_param.sq_max_size) {
		netdev_info(priv->netdev, "%s: tx_pending (%d) > max (%d)\n",
			    __func__, param->tx_pending, priv->nic_param.sq_max_size);
		param->tx_pending = priv->nic_param.sq_max_size;
	}

	if (param->rx_pending == priv->nic_param.rq_size &&
	    param->tx_pending == priv->nic_param.sq_size)
		return 0;

	mutex_lock(&priv->state_lock);

	if (priv->status != XSCALE_ETH_DRIVER_OK)
		goto unlock;

	old_rq_size = priv->nic_param.rq_size;
	old_sq_size = priv->nic_param.sq_size;
	priv->nic_param.rq_size = param->rx_pending;
	priv->nic_param.sq_size = param->tx_pending;

	netdev_info(priv->netdev, "%s: tx_pending(%d->%d), rx_pending(%d->%d)\n",
		    __func__, old_sq_size, param->tx_pending,
		    old_rq_size, priv->nic_param.rq_size);
	err = xsc_safe_switch_channels(priv, NULL, NULL);
	if (err) {
		priv->nic_param.rq_size = old_rq_size;
		priv->nic_param.sq_size = old_sq_size;
		netdev_err(priv->netdev, "%s: set ringparams failed, err=%d\n",
			   __func__, err);
	}

unlock:
	mutex_unlock(&priv->state_lock);

	return err;
}

static void xsc_get_channels(struct net_device *dev, struct ethtool_channels *ch)
{
	struct xsc_adapter *priv = netdev_priv(dev);

	mutex_lock(&priv->state_lock);

	ch->max_combined   = priv->nic_param.max_num_ch;
	ch->combined_count = priv->nic_param.num_channels;

	mutex_unlock(&priv->state_lock);
}

static int  xsc_set_channels(struct net_device *dev, struct ethtool_channels *ch)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct xsc_eth_params *params = &priv->nic_param;
	unsigned int ch_max = params->max_num_ch;
	unsigned int ch_num_old = params->num_channels;
	unsigned int count = ch->combined_count;
	int err = 0;

	if (!count) {
		netdev_info(priv->netdev, "%s: combined_count=0 not supported\n", __func__);
		return -EINVAL;
	}

	if (ch->rx_count || ch->tx_count) {
		netdev_info(priv->netdev, "%s: separate rx/tx count not supported\n", __func__);
		return -EINVAL;
	}

	if (count > ch_max) {
		netdev_info(priv->netdev, "%s: count (%d) > max (%d)\n",
			    __func__, count, ch_max);
		return -EINVAL;
	}

	if (ch_num_old == count)
		return 0;

	mutex_lock(&priv->state_lock);

	params->num_channels = count;

	if (priv->status != XSCALE_ETH_DRIVER_OK) {
		err = xsc_eth_num_channels_changed(priv);
		if (err)
			params->num_channels = ch_num_old;
		goto out;
	}

	/* Switch to new channels, set new parameters and close old ones */
	err = xsc_safe_switch_channels(priv, NULL, xsc_eth_num_channels_changed);

out:
	mutex_unlock(&priv->state_lock);
	netdev_info(priv->netdev, "set combined_cnt=%d, err=%d\n", count, err);

	return err;
}

static int flow_type_to_traffic_type(u32 flow_type)
{
	switch (flow_type) {
	case IPV4_FLOW:
		return XSC_TT_IPV4;
	case TCP_V4_FLOW:
		return XSC_TT_IPV4_TCP;
	case UDP_V4_FLOW:
		return XSC_TT_IPV4_TCP;
	case IPV6_FLOW:
		return XSC_TT_IPV6;
	case TCP_V6_FLOW:
		return XSC_TT_IPV6_TCP;
	case UDP_V6_FLOW:
		return XSC_TT_IPV6_TCP;
	case AH_V4_FLOW:
		return XSC_TT_IPV4_IPSEC_AH;
	case AH_V6_FLOW:
		return XSC_TT_IPV6_IPSEC_AH;
	case ESP_V4_FLOW:
		return XSC_TT_IPV4_IPSEC_ESP;
	case ESP_V6_FLOW:
		return XSC_TT_IPV6_IPSEC_ESP;
	default:
		return -EINVAL;
	}
}

static int xsc_get_rss_hash_opt(struct xsc_adapter *priv,
				struct ethtool_rxnfc *nfc)
{
	u32 hash_field = 0;
	int tt;

	tt = flow_type_to_traffic_type(nfc->flow_type);
	if (tt < 0)
		return -EINVAL;

	hash_field = priv->rss_params.rx_hash_fields[tt];
	nfc->data = 0;

	if (hash_field & XSC_HASH_FIELD_SEL_PROTO)
		nfc->data |= RXH_L3_PROTO;
	if (tt == XSC_TT_IPV4_TCP) {
		if (hash_field & XSC_HASH_FIELD_SEL_SRC_IP)
			nfc->data |= RXH_IP_SRC;
		if (hash_field & XSC_HASH_FIELD_SEL_DST_IP)
			nfc->data |= RXH_IP_DST;
		if (hash_field & XSC_HASH_FIELD_SEL_SPORT)
			nfc->data |= RXH_L4_B_0_1;
		if (hash_field & XSC_HASH_FIELD_SEL_DPORT)
			nfc->data |= RXH_L4_B_2_3;
	} else if (tt == XSC_TT_IPV6_TCP) {
		if (hash_field & XSC_HASH_FIELD_SEL_SRC_IPV6)
			nfc->data |= RXH_IP_SRC;
		if (hash_field & XSC_HASH_FIELD_SEL_DST_IPV6)
			nfc->data |= RXH_IP_DST;
		if (hash_field & XSC_HASH_FIELD_SEL_SPORT_V6)
			nfc->data |= RXH_L4_B_0_1;
		if (hash_field & XSC_HASH_FIELD_SEL_DPORT_V6)
			nfc->data |= RXH_L4_B_2_3;
	}

	return 0;
}

static int xsc_set_rss_hash_opt(struct xsc_adapter *priv,
				struct ethtool_rxnfc *nfc)
{
	u32 rx_hash_field = XSC_HASH_FIELD_SEL_PROTO;
	u32 change = 0;
	int ret = 0;
	int tt;

	tt = flow_type_to_traffic_type(nfc->flow_type);
	if (tt < 0)
		return -EINVAL;

	/*  RSS does not support anything other than hashing to queues
	 *  on src IP, dest IP, TCP/UDP src port and TCP/UDP dest
	 *  port.
	 */
	if (nfc->flow_type != TCP_V4_FLOW &&
	    nfc->flow_type != TCP_V6_FLOW &&
	    nfc->flow_type != UDP_V4_FLOW &&
	    nfc->flow_type != UDP_V6_FLOW)
		return -EOPNOTSUPP;

	if (nfc->data & ~(RXH_IP_SRC | RXH_IP_DST |
			  RXH_L4_B_0_1 | RXH_L4_B_2_3))
		return -EOPNOTSUPP;

	if (nfc->flow_type == TCP_V4_FLOW) {
		if (nfc->data & RXH_IP_SRC)
			rx_hash_field |= XSC_HASH_FIELD_SEL_SRC_IP;
		if (nfc->data & RXH_IP_DST)
			rx_hash_field |= XSC_HASH_FIELD_SEL_DST_IP;
		if (nfc->data & RXH_L4_B_0_1)
			rx_hash_field |= XSC_HASH_FIELD_SEL_SPORT;
		if (nfc->data & RXH_L4_B_2_3)
			rx_hash_field |= XSC_HASH_FIELD_SEL_DPORT;
	} else if (nfc->flow_type == TCP_V6_FLOW) {
		if (nfc->data & RXH_IP_SRC)
			rx_hash_field |= XSC_HASH_FIELD_SEL_SRC_IPV6;
		if (nfc->data & RXH_IP_DST)
			rx_hash_field |= XSC_HASH_FIELD_SEL_DST_IPV6;
		if (nfc->data & RXH_L4_B_0_1)
			rx_hash_field |= XSC_HASH_FIELD_SEL_SPORT_V6;
		if (nfc->data & RXH_L4_B_2_3)
			rx_hash_field |= XSC_HASH_FIELD_SEL_DPORT_V6;
	} else {
		return 0;
	}

	mutex_lock(&priv->state_lock);
	if (rx_hash_field != priv->rss_params.rx_hash_fields[tt]) {
		change |= BIT(XSC_RSS_HASH_TEMP_UPDATE);
		priv->rss_params.rx_hash_fields[tt] = rx_hash_field;
	}

	xsc_core_info(priv->xdev, "flow_type=%d, change=0x%x, hash_tmpl=0x%x\n",
		      nfc->flow_type, change, rx_hash_field);
	if (change)
		ret = xsc_eth_modify_nic_hca(priv, change);

	mutex_unlock(&priv->state_lock);
	return ret;
}

static int xsc_get_rxnfc(struct net_device *dev, struct ethtool_rxnfc *info, u32 *rule_locs)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct xsc_eth_params *params = &priv->nic_param;
	int err = 0;

	if (info->cmd == ETHTOOL_GRXRINGS) {
		info->data = params->num_channels;
		return 0;
	}

	switch (info->cmd) {
	case ETHTOOL_GRXFH:
		err = xsc_get_rss_hash_opt(priv, info);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

static int xsc_set_rxnfc(struct net_device *dev, struct ethtool_rxnfc *cmd)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	int err = 0;

	switch (cmd->cmd) {
	case ETHTOOL_SRXFH:
		err = xsc_set_rss_hash_opt(priv, cmd);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

static u32 xsc_get_rxfh_key_size(struct net_device *dev)
{
	struct xsc_adapter *priv = netdev_priv(dev);

	return sizeof(priv->rss_params.toeplitz_hash_key);
}

static u32 xsc_get_rxfh_indir_size(struct net_device *netdev)
{
	return XSC_INDIR_RQT_SIZE;
}

static int xsc_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key, u8 *hfunc)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_rss_params *rss = &priv->rss_params;

	if (indir)
		memcpy(indir, rss->indirection_rqt,
		       sizeof(rss->indirection_rqt));

	if (key)
		memcpy(key, rss->toeplitz_hash_key,
		       sizeof(rss->toeplitz_hash_key));

	if (hfunc)
		*hfunc = rss->hfunc;

	return 0;
}

static int xsc_set_rxfh(struct net_device *dev, const u32 *indir, const u8 *key, const u8 hfunc)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct xsc_rss_params *rss = &priv->rss_params;
	u32 refresh = 0;
	int err = 0;

	if (hfunc != ETH_RSS_HASH_NO_CHANGE &&
	    hfunc != ETH_RSS_HASH_XOR &&
	    hfunc != ETH_RSS_HASH_TOP)
		return -EINVAL;

	mutex_lock(&priv->state_lock);

	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != rss->hfunc) {
		rss->hfunc = hfunc;
		refresh |= BIT(XSC_RSS_HASH_FUNC_UPDATE);
	}

	if (key) {
		memcpy(rss->toeplitz_hash_key, key, sizeof(rss->toeplitz_hash_key));
		if (rss->hfunc == ETH_RSS_HASH_TOP)
			refresh |= BIT(XSC_RSS_HASH_KEY_UPDATE);
	}

	if (refresh > 0 && priv->status == XSCALE_ETH_DRIVER_OK)
		err = xsc_eth_modify_nic_hca(priv, refresh);

	mutex_unlock(&priv->state_lock);

	return err;
}

static int xsc_get_link_ksettings(struct net_device *netdev,
				  struct ethtool_link_ksettings *cmd)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	struct xsc_event_linkinfo linkinfo;
	u32 nbits = 0;

	if (xsc_eth_get_link_info(adapter, &linkinfo))
		return -EINVAL;

	cmd->base.port = linkinfo.port;
	cmd->base.duplex = linkinfo.duplex;
	cmd->base.autoneg = linkinfo.autoneg;
	switch (linkinfo.linkspeed) {
	case MODULE_SPEED_UNKNOWN:
		cmd->base.speed = LINKSPEED_MODE_UNKNOWN;
		break;
	case MODULE_SPEED_10G:
		cmd->base.speed = LINKSPEED_MODE_10G;
		break;
	case MODULE_SPEED_25G:
		cmd->base.speed = LINKSPEED_MODE_25G;
		break;
	case MODULE_SPEED_40G_R4:
		cmd->base.speed = LINKSPEED_MODE_40G;
		break;
	case MODULE_SPEED_50G_R:
	case MODULE_SPEED_50G_R2:
		cmd->base.speed = LINKSPEED_MODE_50G;
		break;
	case MODULE_SPEED_100G_R2:
	case MODULE_SPEED_100G_R4:
		cmd->base.speed = LINKSPEED_MODE_100G;
		break;
	case MODULE_SPEED_200G_R4:
	case MODULE_SPEED_200G_R8:
		cmd->base.speed = LINKSPEED_MODE_200G;
		break;
	case MODULE_SPEED_400G_R8:
	case MODULE_SPEED_400G_R4:
		cmd->base.speed = LINKSPEED_MODE_400G;
		break;
	default:
		cmd->base.speed = LINKSPEED_MODE_25G;
		break;
	}

	//when link down, show speed && duplex as unknown
	if (!linkinfo.linkstatus) {
		cmd->base.duplex = DUPLEX_UNKNOWN;
		cmd->base.speed = LINKSPEED_MODE_UNKNOWN;
	}

	ethtool_link_ksettings_zero_link_mode(cmd, supported);
	ethtool_link_ksettings_zero_link_mode(cmd, advertising);

	nbits = min_t(u32, __ETHTOOL_LINK_MODE_MASK_NBITS,
		      sizeof(linkinfo.supported_speed) * 8);
	bitmap_copy(cmd->link_modes.supported,
		    (unsigned long *)linkinfo.supported_speed, nbits);

	nbits = min_t(u32, __ETHTOOL_LINK_MODE_MASK_NBITS,
		      sizeof(linkinfo.advertising_speed) * 8);
	bitmap_copy(cmd->link_modes.advertising,
		    (unsigned long *)linkinfo.advertising_speed, nbits);

	nbits = min_t(u32, __ETHTOOL_LINK_MODE_MASK_NBITS,
		      sizeof(linkinfo.supported) * 8);
	bitmap_or(cmd->link_modes.supported, cmd->link_modes.supported,
		  (unsigned long *)&linkinfo.supported, nbits);

	nbits = min_t(u32, __ETHTOOL_LINK_MODE_MASK_NBITS,
		      sizeof(linkinfo.advertising) * 8);
	bitmap_or(cmd->link_modes.advertising, cmd->link_modes.advertising,
		  (unsigned long *)&linkinfo.advertising, nbits);

	return 0;
}

static int xsc_set_link_ksettings(struct net_device *netdev,
				  const struct ethtool_link_ksettings *cmd)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	struct xsc_event_linkinfo linkinfo;
	int err = 0, i;

	if (!adapter) {
		pr_err("%s fail to find adapter\n", __func__);
		return -EINVAL;
	}

	memset(&linkinfo, 0, sizeof(struct xsc_event_linkinfo));

	linkinfo.port = cmd->base.port;
	linkinfo.duplex = cmd->base.duplex;
	linkinfo.autoneg = cmd->base.autoneg;
	linkinfo.linkspeed = cpu_to_be32(cmd->base.speed);

	bitmap_copy((unsigned long *)linkinfo.supported_speed,
		    cmd->link_modes.supported, __ETHTOOL_LINK_MODE_MASK_NBITS);
	bitmap_copy((unsigned long *)linkinfo.advertising_speed,
		    cmd->link_modes.advertising, __ETHTOOL_LINK_MODE_MASK_NBITS);

	for (i = 0; i < ARRAY_SIZE(linkinfo.supported_speed); i++) {
		linkinfo.supported_speed[i] = be64_to_cpu(linkinfo.supported_speed[i]);
		linkinfo.advertising_speed[i] = be64_to_cpu(linkinfo.advertising_speed[i]);
	}

	err = xsc_eth_set_link_info(adapter, &linkinfo);
	if (err)
		xsc_core_err(adapter->xdev, "fail to set link info err %d\n", err);

	return err;
}

struct xsc_ethtool_link_ext_state_opcode_mapping {
	u32 state_opcode;
	enum ethtool_link_ext_state link_ext_state;
	u8 link_ext_substate;
};

static const struct xsc_ethtool_link_ext_state_opcode_mapping
xsc_link_ext_state_opcode_map[] = {
	{1, ETHTOOL_LINK_EXT_STATE_EEPROM_ISSUE, 0},
	{2, ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE,
		ETHTOOL_LINK_EXT_SUBSTATE_CI_UNSUPPORTED_CABLE},
	{6, ETHTOOL_LINK_EXT_STATE_AUTONEG,
		ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED},
	{7, ETHTOOL_LINK_EXT_STATE_AUTONEG,
		ETHTOOL_LINK_EXT_SUBSTATE_AN_ACK_NOT_RECEIVED},
	{8, ETHTOOL_LINK_EXT_STATE_AUTONEG,
		ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_HCD},
	{10, ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE,
		ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_INHIBIT_TIMEOUT},
	{19, ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE,
		ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_FRAME_LOCK_NOT_ACQUIRED},
	{20, ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE,
		ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_PARTNER_DID_NOT_SET_RECEIVER_READY},
	{21, ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH,
		ETHTOOL_LINK_EXT_SUBSTATE_LLM_FC_FEC_IS_NOT_LOCKED},
	{22, ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH,
		ETHTOOL_LINK_EXT_SUBSTATE_LLM_RS_FEC_IS_NOT_LOCKED},
	{23, ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH,
		ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_GET_ALIGN_STATUS},
	{24, ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH,
		ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_AM_LOCK},
	{25, ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH,
		ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_BLOCK_LOCK},
	{26, ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY,
		ETHTOOL_LINK_EXT_SUBSTATE_BSI_LARGE_NUMBER_OF_PHYSICAL_ERRORS},
	{27, ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY,
		ETHTOOL_LINK_EXT_SUBSTATE_BSI_UNSUPPORTED_RATE},
};

static void
xsc_set_link_ext_state(struct xsc_ethtool_link_ext_state_opcode_mapping
		       link_ext_state_mapping,
		       struct ethtool_link_ext_state_info *link_ext_state_info)
{
	switch (link_ext_state_mapping.link_ext_state) {
	case ETHTOOL_LINK_EXT_STATE_AUTONEG:
		link_ext_state_info->autoneg =
			link_ext_state_mapping.link_ext_substate;
		break;
	case ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE:
		link_ext_state_info->link_training =
			link_ext_state_mapping.link_ext_substate;
		break;
	case ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH:
		link_ext_state_info->link_logical_mismatch =
			link_ext_state_mapping.link_ext_substate;
		break;
	case ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY:
		link_ext_state_info->bad_signal_integrity =
			link_ext_state_mapping.link_ext_substate;
		break;
	case ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE:
		link_ext_state_info->cable_issue =
			link_ext_state_mapping.link_ext_substate;
		break;
	default:
		break;
	}

	link_ext_state_info->link_ext_state = link_ext_state_mapping.link_ext_state;
}

static int xsc_get_link_ext_state(struct net_device *dev,
				  struct ethtool_link_ext_state_info *link_ext_state_info)
{
	struct xsc_ethtool_link_ext_state_opcode_mapping link_ext_state_mapping;
	struct xsc_adapter *adapter = netdev_priv(dev);
	struct xsc_link_sub_state_mbox_in in;
	struct xsc_link_sub_state_mbox_out out;
	int i, err;
	u32 state_code;

	if (netif_carrier_ok(dev))
		return -ENODATA;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_GET_LINK_SUB_STATE);

	err = xsc_cmd_exec(adapter->xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(adapter->xdev, "failed to get link ext state, err=%d, status=%d\n",
			     err, out.hdr.status);
		return -ENOEXEC;
	}

	state_code = be32_to_cpu(out.state_code);

	for (i = 0; i < ARRAY_SIZE(xsc_link_ext_state_opcode_map); i++) {
		link_ext_state_mapping = xsc_link_ext_state_opcode_map[i];
		if (link_ext_state_mapping.state_opcode == state_code) {
			xsc_set_link_ext_state(link_ext_state_mapping,
					       link_ext_state_info);
			return 0;
		}
	}

	return -ENODATA;
}

static int xsc_set_phys_id(struct net_device *dev, enum ethtool_phys_id_state state)
{
	struct xsc_adapter *adapter = netdev_priv(dev);
	struct xsc_core_device *xdev = adapter->xdev;
	int ret = 0;

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		xsc_eth_set_led_status(xdev->pf_id, adapter);
		break;
	case ETHTOOL_ID_INACTIVE:
		xsc_eth_set_led_status(LED_ACT_ON_HW, adapter);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return ret;
}

static int xsc_set_fecparam(struct net_device *netdev,
			    struct ethtool_fecparam *fec)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	struct xsc_event_modify_fecparam_mbox_in in;
	struct xsc_event_modify_fecparam_mbox_out out;
	u32 new_fec = fec->fec;
	int err = 0;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_FEC_PARAM);
	in.fec = cpu_to_be32(new_fec);

	err = xsc_cmd_exec(adapter->xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(adapter->xdev, "failed to set fec param, err=%d, status=%d\n",
			     err, out.hdr.status);
		return -ENOEXEC;
	}

	return err;
}

static int xsc_get_fecparam(struct net_device *netdev,
			    struct ethtool_fecparam *fec)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	struct xsc_event_query_fecparam_mbox_in in;
	struct xsc_event_query_fecparam_mbox_out out;
	int err = 0;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_FEC_PARAM);

	err = xsc_cmd_exec(adapter->xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(adapter->xdev, "failed to get fec param, err=%d, status=%d\n",
			     err, out.hdr.status);
		return -ENOEXEC;
	}

	fec->active_fec = be32_to_cpu(out.active_fec);
	fec->fec = be32_to_cpu(out.fec_cfg);

	return err;
}

static int xsc_get_coalesce(struct net_device *netdev,
			    struct ethtool_coalesce *coal,
			    struct kernel_ethtool_coalesce *kernel_coal,
			    struct netlink_ext_ack *extack)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	xsc_dim_cq_moder_t *rx_moder, *tx_moder;

	rx_moder = &priv->nic_param.rx_cq_moderation;
	coal->rx_coalesce_usecs		= rx_moder->usec;
	coal->rx_max_coalesced_frames	= rx_moder->pkts;
	coal->use_adaptive_rx_coalesce	= priv->nic_param.rx_dim_enabled;

	tx_moder = &priv->nic_param.tx_cq_moderation;
	coal->tx_coalesce_usecs		= tx_moder->usec;
	coal->tx_max_coalesced_frames	= tx_moder->pkts;
	coal->use_adaptive_tx_coalesce	= priv->nic_param.tx_dim_enabled;
	coal->rx_coalesce_usecs_low	= priv->nic_param.rx_dim_usecs_low;
	coal->rx_max_coalesced_frames_low = priv->nic_param.rx_dim_frames_low;

	kernel_coal->use_cqe_mode_rx =
		XSC_GET_PFLAG(&priv->nic_param, XSC_PFLAG_RX_CQE_BASED_MODER);
	kernel_coal->use_cqe_mode_tx =
		XSC_GET_PFLAG(&priv->nic_param, XSC_PFLAG_TX_CQE_BASED_MODER);

	return 0;
}

static int xsc_set_coalesce(struct net_device *netdev,
			    struct ethtool_coalesce *coal,
			    struct kernel_ethtool_coalesce *kernel_coal,
			    struct netlink_ext_ack *extack)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	xsc_dim_cq_moder_t *rx_moder, *tx_moder;
	struct xsc_eth_params new_params = {};
	int err = 0;
	bool reset_rx, reset_tx;
	u8 mode;

	if (coal->tx_coalesce_usecs > XSC_MAX_COAL_TIME ||
	    coal->rx_coalesce_usecs > XSC_MAX_COAL_TIME ||
	    coal->rx_coalesce_usecs_low > XSC_MAX_COAL_TIME) {
		netdev_info(priv->netdev, "%s: maximum coalesce time supported is %u usecs\n",
			    __func__, XSC_MAX_COAL_TIME);
		return -ERANGE;
	}

	if (coal->tx_max_coalesced_frames > XSC_MAX_COAL_FRAMES ||
	    coal->rx_max_coalesced_frames > XSC_MAX_COAL_FRAMES ||
	    coal->rx_max_coalesced_frames_low > XSC_MAX_COAL_FRAMES) {
		netdev_info(priv->netdev, "%s: maximum coalesced frames supported is %u\n",
			    __func__, XSC_MAX_COAL_FRAMES);
		return -ERANGE;
	}

	mutex_lock(&priv->state_lock);
	new_params = priv->nic_param;

	rx_moder          = &new_params.rx_cq_moderation;
	rx_moder->usec    = coal->rx_coalesce_usecs;
	rx_moder->pkts    = coal->rx_max_coalesced_frames;
	new_params.rx_dim_enabled = !!coal->use_adaptive_rx_coalesce;
	new_params.rx_dim_usecs_low = coal->rx_coalesce_usecs_low;
	new_params.rx_dim_frames_low = coal->rx_max_coalesced_frames_low;

	tx_moder          = &new_params.tx_cq_moderation;
	tx_moder->usec    = coal->tx_coalesce_usecs;
	tx_moder->pkts    = coal->tx_max_coalesced_frames;
	new_params.tx_dim_enabled = !!coal->use_adaptive_tx_coalesce;

	if (priv->status != XSCALE_ETH_DRIVER_OK) {
		priv->nic_param = new_params;
		goto out;
	}

	reset_rx = !!coal->use_adaptive_rx_coalesce != priv->nic_param.rx_dim_enabled;
	reset_tx = !!coal->use_adaptive_tx_coalesce != priv->nic_param.tx_dim_enabled;

	if (rx_moder->cq_period_mode != kernel_coal->use_cqe_mode_rx) {
		rx_moder->cq_period_mode = kernel_coal->use_cqe_mode_rx;
		XSC_SET_PFLAG(&new_params, XSC_PFLAG_RX_CQE_BASED_MODER,
			      rx_moder->cq_period_mode ==
			      XSC_CQ_PERIOD_MODE_START_FROM_CQE);
		reset_rx = true;
	}
	if (tx_moder->cq_period_mode != kernel_coal->use_cqe_mode_tx) {
		tx_moder->cq_period_mode = kernel_coal->use_cqe_mode_tx;
		XSC_SET_PFLAG(&new_params, XSC_PFLAG_TX_CQE_BASED_MODER,
			      tx_moder->cq_period_mode ==
			      XSC_CQ_PERIOD_MODE_START_FROM_CQE);
		reset_tx = true;
	}

	if (reset_rx) {
		mode = XSC_GET_PFLAG(&new_params, XSC_PFLAG_RX_CQE_BASED_MODER);

		xsc_set_rx_cq_mode_params(&new_params, mode);
	}
	if (reset_tx) {
		mode = XSC_GET_PFLAG(&new_params, XSC_PFLAG_TX_CQE_BASED_MODER);

		xsc_set_tx_cq_mode_params(&new_params, mode);
	}

	priv->nic_param = new_params;
	if (!reset_rx && !reset_tx)
		goto out;

	err = xsc_safe_switch_channels(priv, NULL, NULL);

out:
	mutex_unlock(&priv->state_lock);
	return err;
}

static void xsc_get_pauseparam(struct net_device *netdev,
			       struct ethtool_pauseparam *pause)
{
	pause->autoneg = 0;
	pause->rx_pause = 0;
	pause->tx_pause = 0;
}

static void xsc_get_pause_stats(struct net_device *netdev,
				struct ethtool_pause_stats *stats)
{
	stats->tx_pause_frames = 0;
	stats->rx_pause_frames = 0;
}

static int xsc_set_pauseparam(struct net_device *netdev,
			      struct ethtool_pauseparam *pause)
{
	return -EOPNOTSUPP;
}

static const struct ethtool_ops xsc_ethtool_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
				     ETHTOOL_COALESCE_MAX_FRAMES |
#ifdef ETHTOOL_COALESCE_USECS_LOW_HIGH
				     ETHTOOL_COALESCE_USECS_LOW_HIGH |
#endif
#ifdef ETHTOOL_COALESCE_MAX_FRAMES_LOW_HIGH
				     ETHTOOL_COALESCE_MAX_FRAMES_LOW_HIGH |
#endif
				     ETHTOOL_COALESCE_USE_ADAPTIVE,
	.get_drvinfo = xsc_get_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_link_ext_state  = xsc_get_link_ext_state,
	.get_strings = xsc_get_strings,
	.get_sset_count = xsc_get_sset_count,
	.get_ethtool_stats = xsc_get_ethtool_stats,
	.get_ethtool_phy_stats = xsc_get_ethtool_phy_stats,
	.get_ringparam = xsc_get_ringparam,
	.set_ringparam = xsc_set_ringparam,
	.set_channels = xsc_set_channels,
	.get_channels = xsc_get_channels,
	.get_coalesce = xsc_get_coalesce,
	.set_coalesce = xsc_set_coalesce,
	.get_ts_info = NULL,
	.get_link_ksettings = xsc_get_link_ksettings,
	.set_link_ksettings = xsc_set_link_ksettings,
	.get_rxfh_key_size = xsc_get_rxfh_key_size,
	.get_rxfh_indir_size = xsc_get_rxfh_indir_size,
	.get_rxfh = xsc_get_rxfh,
	.set_rxfh = xsc_set_rxfh,
	.get_rxnfc = xsc_get_rxnfc,
	.set_rxnfc = xsc_set_rxnfc,
	.get_module_info   = xsc_get_module_info,
	.get_module_eeprom = xsc_get_module_eeprom,
	.get_pauseparam = xsc_get_pauseparam,
	.set_pauseparam = xsc_set_pauseparam,
	.get_pause_stats = xsc_get_pause_stats,
	.get_priv_flags = xsc_get_priv_flags,
	.set_priv_flags = xsc_set_priv_flags,
	.get_msglevel = xsc_get_msglevel,
	.set_msglevel = xsc_set_msglevel,
	.self_test    = xsc_self_test,
	.set_phys_id  = xsc_set_phys_id,
	.get_fecparam = xsc_get_fecparam,
	.set_fecparam  = xsc_set_fecparam,
};

void eth_set_ethtool_ops(struct net_device *dev)
{
	dev->ethtool_ops = &xsc_ethtool_ops;
}
