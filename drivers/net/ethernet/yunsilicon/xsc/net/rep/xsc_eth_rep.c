// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/etherdevice.h>
#include <linux/mutex.h>
#include <linux/idr.h>
#include "common/vport.h"
#include "common/xsc_lag.h"
#include "common/xsc_core.h"
#include "../../pci/eswitch.h"
#include "../../pci/devlink.h"
#include "../../pci/eswitch_offloads.h"
#include "../xsc_eth.h"
#include "../xsc_eth_ethtool.h"
#include "../xsc_eth_txrx.h"
#include "xsc_eth_rep.h"
#include "xsc_rep_tc.h"
#include "neigh.h"
#include "common/tc_flow.h"

#define XSC_REP_PARAMS_DEF_NUM_CHANNELS 1

struct xsc_eswitch_rep *xsc_get_vf_rep(const struct xsc_adapter *adapter);

int xsc_eth_rep_enable_nic_hca(struct xsc_adapter *adapter)
{
	struct xsc_core_device *xdev = adapter->xdev;
	struct net_device *netdev = adapter->netdev;
	struct xsc_enable_vf_rep_in in = {};
	struct xsc_enable_vf_rep_out out = {};
	u16 caps = 0;
	u16 caps_mask = 0;
	int err;
	struct xsc_eswitch_rep *rep = xsc_get_vf_rep(adapter);

	if (!rep) {
		xsc_core_err(xdev, "invalid adapter\n");
		return -EINVAL;
	}

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ESW_ENABLE_VF_REP);

	in.rss.rss_en = 1;
	in.rss.rqn_base = cpu_to_be16(adapter->channels.rqn_base -
				xdev->caps.raweth_rss_qp_id_base);
	in.rss.rqn_num = cpu_to_be16(adapter->channels.num_chl);
	in.rss.hash_tmpl = cpu_to_be32(adapter->rss_params.rss_hash_tmpl);
	in.rss.hfunc = hash_func_type(adapter->rss_params.hfunc);

	if (netdev->features & NETIF_F_RXCSUM)
		caps |= BIT(XSC_TBM_CAP_HASH_PPH);
	caps_mask |= BIT(XSC_TBM_CAP_HASH_PPH);

	in.nic.caps = cpu_to_be16(caps);
	in.nic.caps_mask = cpu_to_be16(caps_mask);

	in.vf_rep.vport_number = be16_to_cpu(rep->vport);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "failed, err=%d, status=%d\n", err, out.hdr.status);
		return -ENOEXEC;
	}

	xsc_core_info(xdev, "caps=0x%x, caps_mask=0x%x\n", caps, caps_mask);

	return 0;
}

int xsc_eth_rep_modify_nic_hca(struct xsc_adapter *adapter, u16 flags)
{
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_modify_vf_rep_in in = {};
	struct xsc_modify_vf_rep_out out = {};
	int err;
	struct xsc_eswitch_rep *rep = xsc_get_vf_rep(adapter);

	if (!rep) {
		xsc_core_err(xdev, "invalid adapter\n");
		return -EINVAL;
	}

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ESW_MODIFY_VF_REP);

	in.rss.rqn_base = cpu_to_be16(adapter->channels.rqn_base -
				xdev->caps.raweth_rss_qp_id_base);
	in.rss.rqn_num = cpu_to_be16(adapter->channels.num_chl);

	in.nic.caps_mask = cpu_to_be16(flags);

	in.vf_rep.vport_number = be16_to_cpu(rep->vport);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "failed, err=%d, status=%d\n", err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

int xsc_eth_rep_disable_nic_hca(struct xsc_adapter *adapter)
{
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_disable_vf_rep_in in = {};
	struct xsc_disable_vf_rep_out out = {};
	int err;
	struct xsc_eswitch_rep *rep = xsc_get_vf_rep(adapter);

	if (!rep) {
		xsc_core_err(xdev, "invalid adapter\n");
		return -EINVAL;
	}

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ESW_DISABLE_VF_REP);

	in.vf_rep.vport_number = be16_to_cpu(rep->vport);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "failed, err=%d, status=%d\n", err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

bool xsc_is_uplink_rep(const struct xsc_adapter *adapter)
{
	struct xsc_rep_priv *rpriv = adapter->ppriv;
	struct xsc_eswitch_rep *rep;

	if (!XSC_ESWITCH_MANAGER(adapter->xdev))
		return false;

	if (!rpriv)
		return false;

	rep = rpriv->rep;
	return (rep->vport == XSC_VPORT_UPLINK);
}
EXPORT_SYMBOL(xsc_is_uplink_rep);

bool xsc_eswitch_uplink_rep(const struct net_device *netdev)
{
	return netdev->netdev_ops == &xsc_netdev_ops &&
	       xsc_is_uplink_rep(netdev_priv(netdev));
}
EXPORT_SYMBOL(xsc_eswitch_uplink_rep);

bool xsc_is_vf_rep(const struct net_device *netdev)
{
	return netdev->netdev_ops == &xsc_netdev_ops_rep;
}
EXPORT_SYMBOL(xsc_is_vf_rep);

struct xsc_eswitch_rep *xsc_get_vf_rep(const struct xsc_adapter *adapter)
{
	struct xsc_rep_priv *rpriv = adapter->ppriv;

	if (!xsc_is_vf_rep(adapter->netdev) || !rpriv)
		return NULL;

	return rpriv->rep;
}
EXPORT_SYMBOL(xsc_get_vf_rep);

void xsc_uplink_netdev_set(struct xsc_core_device *xdev, struct net_device *netdev)
{
	struct xsc_eswitch *esw = xdev->priv.eswitch;

	mutex_lock(&esw->offloads.uplink_netdev_lock);
	esw->offloads.uplink_netdev = netdev;
	mutex_unlock(&esw->offloads.uplink_netdev_lock);
}
EXPORT_SYMBOL(xsc_uplink_netdev_set);

static inline struct net_device *xsc_uplink_netdev_get(struct xsc_core_device *xdev)
{
	struct xsc_eswitch *esw = xdev->priv.eswitch;

	return esw->offloads.uplink_netdev;
}

static int xsc_rep_open(struct net_device *dev)
{
	struct xsc_adapter *adapter = netdev_priv(dev);
	struct xsc_rep_priv *rpriv = adapter->ppriv;
	struct xsc_eswitch_rep *rep = rpriv->rep;
	int err;

	mutex_lock(&adapter->state_lock);
	err = xsc_eth_open_locked(dev);
	if (err)
		goto unlock;

	if (!xsc_modify_vport_admin_state(adapter->xdev,
					  rep->vport, 1,
					  XSC_VPORT_ADMIN_STATE_UP))
		netif_carrier_on(dev);

unlock:
	mutex_unlock(&adapter->state_lock);
	return err;
}

static int xsc_rep_close(struct net_device *dev)
{
	struct xsc_adapter *adapter = netdev_priv(dev);
	struct xsc_rep_priv *rpriv = adapter->ppriv;
	struct xsc_eswitch_rep *rep = rpriv->rep;
	int err;

	mutex_lock(&adapter->state_lock);

	xsc_modify_vport_admin_state(adapter->xdev,
				     rep->vport, 1,
				     XSC_VPORT_ADMIN_STATE_DOWN);
	err = xsc_eth_close_locked(dev);
	mutex_unlock(&adapter->state_lock);

	return err;
}

static u16 xsc_rep_select_queue(struct net_device *dev, struct sk_buff *skb,
				struct net_device *sb_dev)
{
	return 0;
}

static int xsc_rep_change_carrier(struct net_device *dev, bool new_carrier)
{
	struct xsc_adapter *adapter = netdev_priv(dev);
	struct xsc_rep_priv *rpriv = adapter->ppriv;
	struct xsc_eswitch_rep *rep = rpriv->rep;
	int err;

	if (new_carrier) {
		err = xsc_modify_vport_admin_state(adapter->xdev, rep->vport, 1,
						   XSC_VPORT_ADMIN_STATE_UP);
		if (err)
			return err;
		netif_carrier_on(dev);
	} else {
		err = xsc_modify_vport_admin_state(adapter->xdev, rep->vport, 1,
						   XSC_VPORT_ADMIN_STATE_DOWN);
		if (err)
			return err;
		netif_carrier_off(dev);
	}
	return 0;
}

extern const struct pflag_desc xsc_priv_flags[XSC_NUM_PFLAGS];

static void xsc_rep_get_strings(struct net_device *dev,
				u32 stringset, uint8_t *data)
{
	struct xsc_adapter *adapter = netdev_priv(dev);
	int i;

	switch (stringset) {
	case ETH_SS_STATS:
		xsc_rep_fill_stats_strings(adapter, data);
		break;
	case ETH_SS_PRIV_FLAGS:
		for (i = 0; i < XSC_NUM_PFLAGS; i++)
			strscpy(data + i * ETH_GSTRING_LEN,
				xsc_priv_flags[i].name,
				ETH_GSTRING_LEN);
		break;
	}
}

static void xsc_rep_get_ethtool_stats(struct net_device *dev,
				      struct ethtool_stats *stats, u64 *data)
{
	struct xsc_adapter *adapter = netdev_priv(dev);

	xsc_rep_ethtool_get_stats(adapter, stats, data);
}

static int xsc_rep_get_sset_count(struct net_device *dev, int sset)
{
	struct xsc_adapter *adapter = netdev_priv(dev);

	switch (sset) {
	case ETH_SS_STATS:
		return xsc_rep_stats_total_num(adapter);
	case ETH_SS_PRIV_FLAGS:
		return XSC_NUM_PFLAGS;
	default:
		return -EOPNOTSUPP;
	}
}

const struct net_device_ops xsc_netdev_ops_rep = {
	.ndo_open                = xsc_rep_open,
	.ndo_stop                = xsc_rep_close,
	.ndo_start_xmit          = xsc_eth_xmit_start,
	.ndo_select_queue        = xsc_rep_select_queue,

	.ndo_change_mtu = xsc_eth_change_mtu,

	.ndo_change_carrier      = xsc_rep_change_carrier,
	.ndo_get_stats64	 = xsc_get_stats,

	.ndo_get_phys_port_name = xsc_get_phys_port_name,
	.ndo_setup_tc = xsc_rep_setup_tc,

	.ndo_get_port_parent_id  = xsc_get_port_parent_id,
};

static const struct ethtool_ops xsc_rep_ethtool_ops = {
	.get_drvinfo	   = xsc_get_drvinfo,
	.get_link	   = ethtool_op_get_link,

	.get_strings       = xsc_rep_get_strings,
	.get_sset_count    = xsc_rep_get_sset_count,
	.get_ethtool_stats = xsc_rep_get_ethtool_stats,

	.get_link_ksettings  = xsc_get_link_ksettings,
	.set_link_ksettings  = xsc_set_link_ksettings,

	.get_ringparam     = xsc_get_ringparam,
	.set_ringparam     = xsc_set_ringparam,
	.get_channels      = xsc_get_channels,
	.set_channels      = xsc_set_channels,
	.get_rxfh_key_size  = xsc_get_rxfh_key_size,
	.get_rxfh_indir_size = xsc_get_rxfh_indir_size,

	.get_priv_flags = xsc_get_priv_flags,
	.set_priv_flags = xsc_set_priv_flags,
};

static void xsc_build_rep_netdev(struct net_device *netdev,
				 struct xsc_core_device *xdev)
{
	SET_NETDEV_DEV(netdev, xdev->device);

	netdev->netdev_ops = &xsc_netdev_ops_rep;

	eth_hw_addr_random(netdev);

	netdev->ethtool_ops = &xsc_rep_ethtool_ops;

	xsc_eth_mtu_set(netdev);

	netdev->watchdog_timeo    = 15 * HZ;

	netdev->hw_features    |= NETIF_F_HW_TC;

	netdev->hw_features    |= NETIF_F_SG;
	netdev->hw_features    |= NETIF_F_IP_CSUM;
	netdev->hw_features    |= NETIF_F_IPV6_CSUM;
	netdev->hw_features    |= NETIF_F_GRO;
	netdev->hw_features    |= NETIF_F_RXCSUM;

	netdev->features |= netdev->hw_features;
}

static void xsc_cleanup_rep(struct xsc_adapter *adapter)
{
}

static int xsc_init_ul_rep_rx(struct xsc_adapter *adapter)
{
	return 0;
}

static int xsc_init_rep_rx(struct xsc_adapter *adapter)
{
	return 0;
}

static void xsc_cleanup_ul_rep_rx(struct xsc_adapter *adapter)
{
}

static void xsc_cleanup_rep_rx(struct xsc_adapter *adapter)
{
}

static void xsc_uplink_rep_enable(struct xsc_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

#ifdef CONFIG_XSC_CORE_EN_DCB
	xsc_dcbnl_initialize(adapter);
#endif

	netdev->wanted_features |= NETIF_F_HW_TC;
	netdev->features |= NETIF_F_HW_TC;

	rtnl_lock();
	if (netif_running(netdev))
		xsc_eth_open(netdev);
	netif_device_attach(netdev);
	rtnl_unlock();
}

static void xsc_uplink_rep_disable(struct xsc_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	rtnl_lock();
	if (netif_running(netdev))
		xsc_eth_close(netdev);
	netif_device_detach(netdev);
	rtnl_unlock();

	netdev->wanted_features &= ~NETIF_F_HW_TC;
	netdev->features &= ~NETIF_F_HW_TC;
}

static void xsc_rep_enable(struct xsc_adapter *adapter)
{
}

static void xsc_rep_disable(struct xsc_adapter *adapter)
{
}

static int xsc_rep_max_nch_limit(struct xsc_core_device *xdev)
{
	return XSC_REP_PARAMS_DEF_NUM_CHANNELS;
}

static int xsc_init_uplink_rep_tx(struct xsc_rep_priv *rpriv)
{
	struct xsc_rep_uplink_priv *uplink_priv;
	struct net_device *netdev;
	struct xsc_adapter *priv;
	int err = 0;

	netdev = rpriv->netdev;
	priv = netdev_priv(netdev);
	uplink_priv = &rpriv->uplink_priv;

	err = xsc_rep_tc_init(rpriv);
	if (err)
		return err;

#ifdef CONFIG_XSC_OFFLOAD_TUN
	xsc_init_port_tun_entropy(&uplink_priv->tun_entropy, priv->xdev);
#endif

#ifdef	CONFIG_XSC_OFFLOAD_OVS
	err = xsc_rep_tc_netdevice_event_register(rpriv);
	if (err) {
		xsc_core_err(priv->xdev,
			     "Failed to register netdev notifier, err: %d\n", err);
		goto err_event_reg;
	}
#endif

	return 0;
#ifdef	CONFIG_XSC_OFFLOAD_OVS
err_event_reg:
#endif
	xsc_rep_tc_cleanup(rpriv);
	return err;
}

static void xsc_cleanup_uplink_rep_tx(struct xsc_rep_priv *rpriv)
{
#ifdef	CONFIG_XSC_OFFLOAD_OVS
	xsc_rep_tc_netdevice_event_unregister(rpriv);
#endif

	xsc_rep_tc_cleanup(rpriv);
}

static int xsc_init_rep_tx(struct xsc_adapter *adapter)
{
	struct xsc_rep_priv *rpriv = adapter->ppriv;
	int err;

	err = xsc_rep_neigh_init(rpriv);
	if (err)
		goto err_neigh_init;

	if (rpriv->rep->vport == XSC_VPORT_UPLINK) {
		err = xsc_init_uplink_rep_tx(rpriv);
		if (err)
			goto err_init_tx;
	}

	err = xsc_tc_ht_init(&rpriv->tc_ht);
	if (err)
		goto err_ht_init;
	return 0;

err_ht_init:
	if (rpriv->rep->vport == XSC_VPORT_UPLINK)
		xsc_cleanup_uplink_rep_tx(rpriv);
err_init_tx:
	xsc_rep_neigh_cleanup(rpriv);
err_neigh_init:
	return err;
}

static void xsc_cleanup_rep_tx(struct xsc_adapter *adapter)
{
	struct xsc_rep_priv *rpriv = adapter->ppriv;

	xsc_tc_ht_cleanup(&rpriv->tc_ht);

	if (rpriv->rep->vport == XSC_VPORT_UPLINK)
		xsc_cleanup_uplink_rep_tx(rpriv);

	xsc_rep_neigh_cleanup(rpriv);
}

static const struct xsc_profile xsc_rep_profile = {
	.init		= xsc_eth_nic_init,
	.cleanup	= xsc_cleanup_rep,
	.init_rx	= xsc_init_rep_rx,
	.cleanup_rx	= xsc_cleanup_rep_rx,
	.init_tx	= xsc_init_rep_tx,
	.cleanup_tx	= xsc_cleanup_rep_tx,
	.enable		= xsc_rep_enable,
	.disable	= xsc_rep_disable,
	.rx_handlers	= &xsc_rx_handlers_nic,
	.max_nch_limit	= xsc_rep_max_nch_limit,
	.max_tc		= 1,
};

static const struct xsc_profile xsc_uplink_rep_profile = {
	.init		= xsc_eth_nic_init,
	.cleanup	= xsc_cleanup_rep,
	.init_rx	= xsc_init_ul_rep_rx,
	.cleanup_rx	= xsc_cleanup_ul_rep_rx,
	.init_tx	= xsc_init_rep_tx,
	.cleanup_tx	= xsc_cleanup_rep_tx,
	.enable		= xsc_uplink_rep_enable,
	.disable	= xsc_uplink_rep_disable,
	.rx_handlers	= &xsc_rx_handlers_nic,
	.max_nch_limit	= xsc_max_nch_limit,
	.max_tc		= 1,
};

bool xsc_is_vf_rep_profile(const struct xsc_profile *profile)
{
	return profile == &xsc_rep_profile;
}
EXPORT_SYMBOL(xsc_is_vf_rep_profile);

static int xsc_eth_uplink_priv_change(struct xsc_adapter *adapter)
{
	unsigned int node = dev_to_node(adapter->dev);
	int num_txqs = adapter->nic_param.num_channels * adapter->nic_param.num_tc;

	adapter->txq2sq = kcalloc_node(num_txqs, sizeof(*adapter->txq2sq),
				       GFP_KERNEL, node);
	if (unlikely(!adapter->txq2sq))
		return -ENOMEM;

	adapter->stats = kvzalloc(sizeof(*adapter->stats), GFP_KERNEL);
	if (unlikely(!adapter->stats))
		return -ENOMEM;

	return 0;
}

static void xsc_eth_uplink_priv_cleanup(struct xsc_adapter *adapter)
{
	kfree(adapter->txq2sq);
	adapter->txq2sq = NULL;

	kfree(adapter->stats);
	adapter->stats = NULL;

	flush_workqueue(adapter->workq);
}

static int
xsc_netdev_attach_profile(struct net_device *netdev, struct xsc_core_device *xdev,
			  const struct xsc_profile *new_profile, void *new_ppriv)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	int err;

	netif_carrier_off(netdev);
	adapter->profile = new_profile;
	adapter->ppriv = new_ppriv;

	err = new_profile->init(adapter->netdev);
	if (err)
		goto err;

	err = xsc_eth_uplink_priv_change(adapter);
	if (err)
		goto err;

	err = xsc_attach_netdev(adapter);
	if (err)
		goto err_attach;

	return 0;

err_attach:
	new_profile->cleanup(adapter);
err:
	return err;
}

static int xsc_netdev_change_profile(struct xsc_adapter *adapter,
				     const struct xsc_profile *new_profile, void *new_ppriv)
{
	const struct xsc_profile *orig_profile = adapter->profile;
	struct net_device *netdev = adapter->netdev;
	struct xsc_core_device *xdev = adapter->xdev;
	void *orig_ppriv = adapter->ppriv;
	int err, rollback_err;

	/* cleanup old profile */
	xsc_detach_netdev(adapter);
	adapter->profile->cleanup(adapter);
	xsc_eth_uplink_priv_cleanup(adapter);

	err = xsc_netdev_attach_profile(netdev, xdev, new_profile, new_ppriv);
	if (err) { /* roll back to original profile */
		xsc_core_err(xdev, "failed to init new profile, err=%d\n",  err);
		goto rollback;
	}

	return 0;

rollback:
	rollback_err = xsc_netdev_attach_profile(netdev, xdev, orig_profile, orig_ppriv);
	if (rollback_err)
		xsc_core_err(xdev, "failed to rollback to orig profile, err=%d\n",
			     rollback_err);
	return err;
}

static int
xsc_vport_uplink_rep_load(struct xsc_core_device *xdev, struct xsc_eswitch_rep *rep)
{
	struct xsc_adapter *adapter = netdev_priv(xsc_uplink_netdev_get(xdev));
	struct xsc_rep_priv *rpriv = xsc_rep_to_rep_priv(rep);

	rpriv->netdev = xsc_uplink_netdev_get(xdev);

	return xsc_netdev_change_profile(adapter, &xsc_uplink_rep_profile, rpriv);
}

static int
xsc_vport_vf_rep_load(struct xsc_core_device *xdev, struct xsc_eswitch_rep *rep)
{
	struct xsc_rep_priv *rpriv = xsc_rep_to_rep_priv(rep);
	const struct xsc_profile *profile;
	struct net_device *netdev;
	struct xsc_adapter *adapter;
	int err;

	profile = &xsc_rep_profile;
	netdev = xsc_create_netdev(xdev, profile);
	if (!netdev) {
		xsc_core_warn(xdev, "Failed to create representor netdev for vport %d\n",
			      rep->vport);
		return -EINVAL;
	}

	xsc_build_rep_netdev(netdev, xdev);

	rpriv->netdev = netdev;

	adapter = netdev_priv(netdev);
	adapter->profile = profile;
	adapter->ppriv = rpriv;

	err = profile->init(netdev);
	if (err) {
		netdev_warn(netdev, "rep profile init failed, %d\n", err);
		goto err_destroy_netdev;
	}

	err = xsc_attach_netdev(netdev_priv(netdev));
	if (err) {
		netdev_warn(netdev,
			    "Failed to attach representor netdev for vport %d\n",
			    rep->vport);
		goto err_cleanup_profile;
	}

	err = register_netdev(netdev);
	if (err) {
		netdev_warn(netdev,
			    "Failed to register representor netdev for vport %d\n",
			    rep->vport);
		goto err_detach_netdev;
	}

	return 0;

err_detach_netdev:
	xsc_detach_netdev(netdev_priv(netdev));
err_cleanup_profile:
	adapter->profile->cleanup(adapter);
err_destroy_netdev:
	xsc_destroy_netdev(netdev_priv(netdev));
	return err;
}

static int
xsc_vport_rep_load(struct xsc_core_device *dev, struct xsc_eswitch_rep *rep)
{
	struct xsc_rep_priv *rpriv;
	int err;

	rpriv = kvzalloc(sizeof(*rpriv), GFP_KERNEL);
	if (!rpriv)
		return -ENOMEM;

	/* rpriv->rep to be looked up when profile->init() is called */
	rpriv->rep = rep;
	rep->rep_data[REP_ETH].priv = rpriv;

	if (rep->vport == XSC_VPORT_UPLINK)
		err = xsc_vport_uplink_rep_load(dev, rep);
	else
		err = xsc_vport_vf_rep_load(dev, rep);

	if (err)
		kvfree(rpriv);

	return err;
}

static void
xsc_vport_uplink_rep_unload(struct xsc_rep_priv *rpriv)
{
	struct net_device *netdev = rpriv->netdev;
	struct xsc_adapter *adapter = netdev_priv(netdev);

	xsc_netdev_change_profile(adapter, &xsc_nic_profile, NULL);
}

static void
xsc_vport_rep_unload(struct xsc_eswitch_rep *rep)
{
	struct xsc_rep_priv *rpriv = xsc_rep_to_rep_priv(rep);
	struct net_device *netdev = rpriv->netdev;
	struct xsc_adapter *adapter = netdev_priv(netdev);
	void *ppriv = adapter->ppriv;

	if (rep->vport == XSC_VPORT_UPLINK) {
		xsc_vport_uplink_rep_unload(rpriv);
		goto free_ppriv;
	}

	unregister_netdev(netdev);
	xsc_detach_netdev(adapter);
	adapter->profile->cleanup(adapter);
	xsc_destroy_netdev(adapter);
free_ppriv:
	kvfree(ppriv);
}

static void *xsc_vport_rep_get_proto_dev(struct xsc_eswitch_rep *rep)
{
	struct xsc_rep_priv *rpriv;

	rpriv = xsc_rep_to_rep_priv(rep);

	return rpriv->netdev;
}

static const struct xsc_eswitch_rep_ops rep_ops = {
	.load = xsc_vport_rep_load,
	.unload = xsc_vport_rep_unload,
	.get_proto_dev = xsc_vport_rep_get_proto_dev,
};

void xsc_rep_register_vport_reps(struct xsc_core_device *xdev)
{
	xsc_eswitch_register_vport_reps(xdev, &rep_ops, REP_ETH);
}

void xsc_rep_unregister_vport_reps(struct xsc_core_device *xdev)
{
	xsc_eswitch_unregister_vport_reps(xdev, REP_ETH);
}

