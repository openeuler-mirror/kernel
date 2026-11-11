// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_eswitch.h"
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#include "nse_devlink.h"
#endif /* CONFIG_NET_DEVLINK */
#include "nse_sriov.h"
#include "nse_tc_lib.h"
#include "nse_lib.h"
#include "nse_repr_sysfs.h"

/**
 * nse_netdev_to_repr - Get port representor for given netdevice
 * @netdev: pointer to port representor netdev
 */
struct nse_repr *nse_netdev_to_repr(const struct net_device *netdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);

	return np->repr;
}

/**
 * nse_repr_get_sw_port_id - get port ID associated with representor
 * @repr: pointer to port representor
 */
static int nse_repr_get_sw_port_id(struct nse_repr *repr)
{
	return repr->vf->pf->hw.pcore_pf_id;
}

/**
 * nse_repr_get_phys_port_name - get phys port name
 * @netdev: pointer to port representor netdev
 * @buf: write here port name
 * @len: max length of buf
 */
static int
nse_repr_get_phys_port_name(struct net_device *netdev, char *buf, size_t len)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_repr *repr = np->repr;
	int res;

#if IS_ENABLED(CONFIG_NET_DEVLINK)
	/* Devlink port is registered and devlink core is taking care of name formatting. */
	if (repr->vf->devlink_port.devlink)
		return -EOPNOTSUPP;
#endif /* CONFIG_NET_DEVLINK */

	res = snprintf(buf, len, "pf%dvfr%d", nse_repr_get_sw_port_id(repr),
		       repr->vf->vf_id);
	if (res <= 0)
		return -EOPNOTSUPP;
	return 0;
}

/**
 * nse_repr_get_stats64 - get VF stats for VFPR use
 * @netdev: pointer to port representor netdev
 * @stats: pointer to struct where stats can be stored
 */
static void
nse_repr_get_stats64(struct net_device *netdev, struct rtnl_link_stats64 *stats)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi_hw_stats *cur_stats;
	struct nse_vsi *vsi;

	if (nse_is_vf_disabled(np->repr->vf))
		return;
	vsi = np->repr->src_vsi;

	nse_update_vsi_stats(vsi);
	cur_stats = &vsi->hw_stats;

	stats->tx_packets = cur_stats->tx_gptc;
	stats->rx_packets = cur_stats->rx_gpkt;
	stats->tx_bytes = cur_stats->tx_gotc;
	stats->rx_bytes = cur_stats->rx_goct;
	stats->multicast = cur_stats->rx_mpkt;
	stats->tx_errors = cur_stats->tx_dptc;
	stats->tx_dropped = cur_stats->tx_dptc;
	stats->rx_dropped = cur_stats->rx_dpkt;
}

/**
 * nse_repr_open - Enable port representor's network interface
 * @netdev: network interface device structure
 *
 * The open entry point is called when a port representor's network
 * interface is made active by the system (IFF_UP). Corresponding
 * VF is notified about link status change.
 *
 * Returns 0 on success
 */
static int nse_repr_open(struct net_device *netdev)
{
	struct nse_repr *repr = nse_netdev_to_repr(netdev);
	struct nse_vf *vf;

	vf = repr->vf;
	vf->link_forced = true;
	vf->link_up = true;
	nse_vc_notify_vf_link_state(vf, true);

	netif_carrier_on(netdev);
	netif_tx_start_all_queues(netdev);

	return 0;
}

/**
 * nse_repr_stop - Disable port representor's network interface
 * @netdev: network interface device structure
 *
 * The stop entry point is called when a port representor's network
 * interface is de-activated by the system. Corresponding
 * VF is notified about link status change.
 *
 * Returns 0 on success
 */
static int nse_repr_stop(struct net_device *netdev)
{
	struct nse_repr *repr = nse_netdev_to_repr(netdev);
	struct nse_vf *vf;

	vf = repr->vf;
	vf->link_forced = true;
	vf->link_up = false;
	nse_vc_notify_vf_link_state(vf, true);

	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);

	return 0;
}

/**
 * nse_repr_sp_stats64 - get slow path stats for port representor
 * @dev: network interface device structure
 * @stats: netlink stats structure
 *
 * RX/TX stats are being swapped here to be consistent with VF stats. In slow
 * path, port representor receives data when the corresponding VF is sending it
 * (and vice versa), TX and RX bytes/packets are effectively swapped on port
 * representor.
 */
static int
nse_repr_sp_stats64(const struct net_device *dev,
		    struct rtnl_link_stats64 *stats)
{
	struct nse_repr *repr = nse_netdev_to_repr(dev);

	stats->rx_packets = repr->rx_packets;
	stats->rx_bytes = repr->rx_bytes;

	stats->tx_packets = repr->tx_packets;
	stats->tx_bytes = repr->tx_bytes;

	return 0;
}

static bool
nse_repr_ndo_has_offload_stats(const struct net_device *dev, int attr_id)
{
	return attr_id == IFLA_OFFLOAD_XSTATS_CPU_HIT;
}

static int
nse_repr_ndo_get_offload_stats(int attr_id, const struct net_device *dev,
			       void *sp)
{
	if (attr_id == IFLA_OFFLOAD_XSTATS_CPU_HIT)
		return nse_repr_sp_stats64(dev, (struct rtnl_link_stats64 *)sp);

	return -EINVAL;
}

static int
nse_repr_setup_tc_cls_flower(struct nse_repr *repr,
			     struct flow_cls_offload *flower)
{
	switch (flower->command) {
	case FLOW_CLS_REPLACE:
		return nse_add_cls_flower(repr->netdev, repr->src_vsi, flower);
	case FLOW_CLS_DESTROY:
		return nse_del_cls_flower(repr->src_vsi, flower);
	case FLOW_CLS_STATS:
		return nse_stats_cls_flower(repr->src_vsi, flower);
	default:
		return -EINVAL;
	}
}

static int
nse_repr_setup_tc_block_cb(enum tc_setup_type type, void *type_data,
			   void *cb_priv)
{
	struct flow_cls_offload *flower = (struct flow_cls_offload *)type_data;
	struct nse_netdev_priv *np = (struct nse_netdev_priv *)cb_priv;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return nse_repr_setup_tc_cls_flower(np->repr, flower);
	default:
		return -EOPNOTSUPP;
	}
}

static LIST_HEAD(nse_repr_block_cb_list);

static int
nse_repr_setup_tc(struct net_device *netdev, enum tc_setup_type type,
		  void *type_data)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);

	switch (type) {
	case TC_SETUP_BLOCK:
		return flow_block_cb_setup_simple((struct flow_block_offload *)
						  type_data,
						  &nse_repr_block_cb_list,
						  nse_repr_setup_tc_block_cb,
						  np, np, true);
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * nse_repr_change_mtu - NDO callback to change the MTU on port representor
 * @netdev: network interface device structure
 * @new_mtu: new value for MTU
 *
 * Returns 0 on success, negative on failure
 */
static int nse_repr_change_mtu(struct net_device *netdev, int new_mtu)
{
	int err;

	err = nse_check_mtu_valid(netdev, new_mtu);
	if (err)
		return err;

	netdev->mtu = (unsigned int)new_mtu;

	return 0;
}

static const struct net_device_ops nse_repr_netdev_ops = {
	.ndo_get_phys_port_name = nse_repr_get_phys_port_name,
	.ndo_get_stats64 = nse_repr_get_stats64,
	.ndo_open = nse_repr_open,
	.ndo_stop = nse_repr_stop,
#if IS_ENABLED(CONFIG_NET_DEVLINK)
	.ndo_start_xmit = nse_eswitch_port_start_xmit,
	.ndo_change_mtu = nse_repr_change_mtu,
	.ndo_setup_tc = nse_repr_setup_tc,
#endif /* CONFIG_NET_DEVLINK */
	.ndo_has_offload_stats = nse_repr_ndo_has_offload_stats,
	.ndo_get_offload_stats = nse_repr_ndo_get_offload_stats,
};

/**
 * nse_is_port_repr_netdev - Check if a given netdevice is a port representor
 * netdev
 * @netdev: pointer to netdev
 */
bool nse_is_port_repr_netdev(struct net_device *netdev)
{
	return netdev && (netdev->netdev_ops == &nse_repr_netdev_ops);
}

/**
 * nse_repr_reg_netdev - register port representor netdev
 * @netdev: pointer to port representor netdev
 */
static int
nse_repr_reg_netdev(struct net_device *netdev)
{
	int ret;

	eth_hw_addr_random(netdev);
	netdev->netdev_ops = &nse_repr_netdev_ops;
	nse_set_ethtool_repr_ops(netdev);

	netdev->hw_features |= NETIF_F_HW_TC;
	netdev->features |= NETIF_F_HW_TC;

	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);

	ret = register_netdev(netdev);

	netdev->features &= ~NETIF_F_GRO;

	return ret;
}

/**
 * nse_repr_add - add representor for VF
 * @vf: pointer to VF structure
 */
static int nse_repr_add(struct nse_vf *vf)
{
	struct nse_q_vector *q_vector;
	struct nse_netdev_priv *np;
	struct nse_repr *repr;
	struct nse_vsi *vsi;
	int err;

	vsi = nse_get_vf_vsi(vf);
	if (!vsi)
		return -EINVAL;

	repr = kzalloc(sizeof(*repr), GFP_KERNEL);
	if (!repr)
		return -ENOMEM;

	repr->netdev = alloc_etherdev(sizeof(struct nse_netdev_priv));
	if (!repr->netdev) {
		err =  -ENOMEM;
		goto err_alloc;
	}

	repr->src_vsi = vsi;
	repr->vf = vf;
	vf->repr = repr;
	np = netdev_priv(repr->netdev);
	np->repr = repr;

	q_vector = kzalloc(sizeof(*q_vector), GFP_KERNEL);
	if (!q_vector) {
		err = -ENOMEM;
		goto err_alloc_q_vector;
	}
	repr->q_vector = q_vector;

#if IS_ENABLED(CONFIG_NET_DEVLINK)
	err = nse_devlink_create_vf_port(vf);
	if (err)
		goto err_devlink;

	repr->netdev->min_mtu = ETH_MIN_MTU;
	repr->netdev->max_mtu = NSE_MAX_MTU;
#endif /* CONFIG_NET_DEVLINK */

	SET_NETDEV_DEV(repr->netdev, nse_pf_to_dev(vf->pf));

#if IS_ENABLED(CONFIG_NET_DEVLINK)
	SET_NETDEV_DEVLINK_PORT(repr->netdev, &vf->devlink_port);
#endif /* CONFIG_NET_DEVLINK */

	err = nse_repr_reg_netdev(repr->netdev);
	if (err)
		goto err_netdev;

#if IS_ENABLED(CONFIG_NET_DEVLINK)
#endif /* CONFIG_NET_DEVLINK */

	nse_virtchnl_set_repr_ops(vf);

	nse_create_rep_sysfs(repr);

	return 0;

err_netdev:
#if IS_ENABLED(CONFIG_NET_DEVLINK)
	nse_devlink_destroy_vf_port(vf);
err_devlink:
#endif /* CONFIG_NET_DEVLINK */
	kfree(repr->q_vector);
	vf->repr->q_vector = NULL;
err_alloc_q_vector:
	free_netdev(repr->netdev);
	repr->netdev = NULL;
err_alloc:
	kfree(repr);
	vf->repr = NULL;
	return err;
}

/**
 * nse_repr_rem - remove representor from VF
 * @vf: pointer to VF structure
 */
static void nse_repr_rem(struct nse_vf *vf)
{
	if (!vf->repr)
		return;

	nse_acl_destrory_hw_repr_meter(vf->repr->src_vsi, &vf->repr->rep_meter);
	nse_cleanup_rep_sysfs(vf->repr);

#if IS_ENABLED(CONFIG_NET_DEVLINK)
	nse_devlink_destroy_vf_port(vf);
#endif /* CONFIG_NET_DEVLINK */
	kfree(vf->repr->q_vector);
	vf->repr->q_vector = NULL;
	unregister_netdev(vf->repr->netdev);
	free_netdev(vf->repr->netdev);
	vf->repr->netdev = NULL;
	kfree(vf->repr);
	vf->repr = NULL;

	nse_virtchnl_set_dflt_ops(vf);
}

/**
 * nse_repr_rem_from_all_vfs - remove port representor for all VFs
 * @pf: pointer to PF structure
 */
void nse_repr_rem_from_all_vfs(struct nse_pf *pf)
{
	struct nse_vf *vf;
	unsigned int bkt;

	lockdep_assert_held(&pf->vfs.table_lock);

	nse_for_each_vf(pf, bkt, vf)
		nse_repr_rem(vf);
}

/**
 * nse_repr_add_for_all_vfs - add port representor for all VFs
 * @pf: pointer to PF structure
 */
int nse_repr_add_for_all_vfs(struct nse_pf *pf)
{
	struct nse_vf *vf;
	unsigned int bkt;
	int err;

	lockdep_assert_held(&pf->vfs.table_lock);

	nse_for_each_vf(pf, bkt, vf) {
		err = nse_repr_add(vf);
		if (err)
			goto err;
	}

	return 0;

err:
	nse_repr_rem_from_all_vfs(pf);

	return err;
}

/**
 * nse_repr_start_tx_queues - start Tx queues of port representor
 * @repr: pointer to repr structure
 */
void nse_repr_start_tx_queues(struct nse_repr *repr)
{
	netif_carrier_on(repr->netdev);
	netif_tx_start_all_queues(repr->netdev);
}

/**
 * nse_repr_stop_tx_queues - stop Tx queues of port representor
 * @repr: pointer to repr structure
 */
void nse_repr_stop_tx_queues(struct nse_repr *repr)
{
	netif_carrier_off(repr->netdev);
	netif_tx_stop_all_queues(repr->netdev);
}

/**
 * nse_repr_set_traffic_vsi - set traffic VSI for port representor
 * @repr: repr on with VSI will be set
 * @vsi: pointer to VSI that will be used by port representor to pass traffic
 */
void nse_repr_set_traffic_vsi(struct nse_repr *repr, struct nse_vsi *vsi)
{
	struct nse_netdev_priv *np = netdev_priv(repr->netdev);

	np->vsi = vsi;
}

