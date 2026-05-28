// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/netdevice.h>
#include <linux/if_macvlan.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/rtnetlink.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include "xsc_rep_tc.h"
#include "neigh.h"
#include "common/tc_flow.h"
#include "common/fs_cmd.h"
#include "../../pci/fs_chains.h"
#include "common/tc_priv.h"

struct xsc_rep_indr_block_priv {
	struct net_device *netdev;
	struct xsc_rep_priv *rpriv;
	enum flow_block_binder_type binder_type;

	struct list_head list;
};

#ifdef CONFIG_XSC_OFFLOAD_TUN
int xsc_rep_encap_entry_attach(struct xsc_adapter *priv,
			       struct xsc_encap_entry *e,
			       struct xsc_neigh *x_neigh,
			       struct net_device *neigh_dev)
{
	struct xsc_rep_priv *rpriv = priv->ppriv;
	struct xsc_rep_uplink_priv *uplink_priv = &rpriv->uplink_priv;
	struct xsc_tun_entropy *tun_entropy = &uplink_priv->tun_entropy;
	struct xsc_neigh_hash_entry *nhe;
	int err;

	err = xsc_tun_entropy_refcount_inc(tun_entropy, e->reformat_type);
	if (err)
		return err;

	mutex_lock(&rpriv->neigh_update.encap_lock);
	nhe = xsc_rep_neigh_entry_lookup(priv, x_neigh);
	if (!nhe) {
		err = xsc_rep_neigh_entry_create(priv, x_neigh, neigh_dev, &nhe);
		if (err) {
			mutex_unlock(&rpriv->neigh_update.encap_lock);
			xsc_tun_entropy_refcount_dec(tun_entropy,
						     e->reformat_type);
			return err;
		}
	}

	e->nhe = nhe;
	spin_lock(&nhe->encap_list_lock);
	list_add_rcu(&e->encap_list, &nhe->encap_list);
	spin_unlock(&nhe->encap_list_lock);

	mutex_unlock(&rpriv->neigh_update.encap_lock);

	return 0;
}

void xsc_rep_encap_entry_detach(struct xsc_adapter *priv,
				struct xsc_encap_entry *e)
{
	struct xsc_rep_priv *rpriv = priv->ppriv;
	struct xsc_rep_uplink_priv *uplink_priv = &rpriv->uplink_priv;
	struct xsc_tun_entropy *tun_entropy = &uplink_priv->tun_entropy;

	if (!e->nhe)
		return;

	spin_lock(&e->nhe->encap_list_lock);
	list_del_rcu(&e->encap_list);
	spin_unlock(&e->nhe->encap_list_lock);

	xsc_rep_neigh_entry_release(e->nhe);
	e->nhe = NULL;
	xsc_tun_entropy_refcount_dec(tun_entropy, e->reformat_type);
}
#endif

void xsc_rep_update_flows(struct xsc_adapter *priv, struct xsc_encap_entry *e,
			  bool neigh_connected, unsigned char ha[ETH_ALEN])
{
#ifdef CONFIG_XSC_OFFLOAD_TUN
	struct ethhdr *eth = (struct ethhdr *)e->encap_header;
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;
	bool encap_connected;
	LIST_HEAD(flow_list);

	ASSERT_RTNL();

	mutex_lock(&esw->offloads.encap_tbl_lock);
	encap_connected = !!(e->flags & XSC_ENCAP_ENTRY_VALID);
	if (encap_connected == neigh_connected && ether_addr_equal(e->h_dest, ha))
		goto unlock;

	xsc_take_all_encap_flows(e, &flow_list);

	if ((e->flags & XSC_ENCAP_ENTRY_VALID) &&
	    (!neigh_connected || !ether_addr_equal(e->h_dest, ha)))
		xsc_tc_encap_flows_del(priv, e, &flow_list);

	if (neigh_connected && !(e->flags & XSC_ENCAP_ENTRY_VALID)) {
		struct net_device *route_dev;

		ether_addr_copy(e->h_dest, ha);
		ether_addr_copy(eth->h_dest, ha);
		/* Update the encap source mac, in case that we delete
		 * the flows when encap source mac changed.
		 */
		route_dev = __dev_get_by_index(dev_net(priv->netdev), e->route_dev_ifindex);
		if (route_dev)
			ether_addr_copy(eth->h_source, route_dev->dev_addr);

		xsc_tc_encap_flows_add(priv, e, &flow_list);
	}
unlock:
	mutex_unlock(&esw->offloads.encap_tbl_lock);
	xsc_put_flow_list(priv, &flow_list);
#endif
}

static int xsc_rep_setup_tc_cls_flower(struct xsc_adapter *priv,
				       struct flow_cls_offload *cls_flower, int flags)
{
	switch (cls_flower->command) {
	case FLOW_CLS_REPLACE:
		return xsc_configure_flower(priv->netdev, priv, cls_flower, flags);
	case FLOW_CLS_DESTROY:
		return xsc_delete_flower(priv->netdev, priv, cls_flower, flags);
	case FLOW_CLS_STATS:
#ifdef CONFIG_XSC_OFFLOAD_COUNTER
		return xsc_stats_flower(priv->netdev, priv, cls_flower, flags);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

#ifdef CONFIG_XSC_OFFLOAD_METER
static void xsc_tc_stats_matchall(struct xsc_adapter *priv,
				  struct tc_cls_matchall_offload *ma)
{
	struct xsc_rep_priv *rpriv = priv->ppriv;
	u64 dbytes;
	u64 dpkts;

	dpkts = priv->stats.rep_stats.vport_rx_packets - rpriv->prev_vf_vport_stats.rx_packets;
	dbytes = priv->stats.rep_stats.vport_rx_bytes - rpriv->prev_vf_vport_stats.rx_bytes;
	xsc_stats_copy_rep_stats(&rpriv->prev_vf_vport_stats, &priv->stats.rep_stats);
	flow_stats_update(&ma->stats, dbytes, dpkts, 0, jiffies,
			  FLOW_ACTION_HW_STATS_DELAYED);
}

static int xsc_rep_setup_tc_cls_matchall(struct xsc_adapter *priv,
					 struct tc_cls_matchall_offload *ma)
{
	switch (ma->command) {
	case TC_CLSMATCHALL_REPLACE:
		return xsc_tc_configure_matchall(priv, ma);
	case TC_CLSMATCHALL_DESTROY:
		return xsc_tc_delete_matchall(priv, ma);
	case TC_CLSMATCHALL_STATS:
		xsc_tc_stats_matchall(priv, ma);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}
#endif

static int xsc_rep_setup_tc_cb(enum tc_setup_type type, void *type_data,
			       void *cb_priv)
{
	unsigned long flags = XSC_TC_FLAG(INGRESS) | XSC_TC_FLAG(ESW_OFFLOAD);
	struct xsc_adapter *priv = cb_priv;

	if (!priv->netdev || !netif_device_present(priv->netdev))
		return -EOPNOTSUPP;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return xsc_rep_setup_tc_cls_flower(priv, type_data, flags);
#ifdef CONFIG_XSC_OFFLOAD_METER
	case TC_SETUP_CLSMATCHALL:
		return xsc_rep_setup_tc_cls_matchall(priv, type_data);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

static int xsc_rep_setup_ft_cb(enum tc_setup_type type, void *type_data,
			       void *cb_priv)
{
	struct flow_cls_offload tmp, *f = type_data;
	struct xsc_adapter *priv = cb_priv;
	struct xsc_eswitch *esw;
	unsigned long flags;
	int err;

	flags = XSC_TC_FLAG(INGRESS) |
		XSC_TC_FLAG(ESW_OFFLOAD) |
		XSC_TC_FLAG(FT_OFFLOAD);
	esw = priv->xdev->priv.eswitch;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		memcpy(&tmp, f, sizeof(*f));

		if (!xsc_chains_prios_supported(esw_chains(esw)))
			return -EOPNOTSUPP;

		/* Re-use tc offload path by moving the ft flow to the
		 * reserved ft chain.
		 *
		 * FT offload can use prio range [0, INT_MAX], so we normalize
		 * it to range [1, xsc_esw_chains_get_prio_range(esw)]
		 * as with tc, where prio 0 isn't supported.
		 *
		 * We only support chain 0 of FT offload.
		 */
		if (tmp.common.prio >= xsc_chains_get_prio_range(esw_chains(esw)))
			return -EOPNOTSUPP;
		if (tmp.common.chain_index != 0)
			return -EOPNOTSUPP;

		tmp.common.chain_index = xsc_chains_get_nf_ft_chain(esw_chains(esw));
		tmp.common.prio++;
		err = xsc_rep_setup_tc_cls_flower(priv, &tmp, flags);
		memcpy(&f->stats, &tmp.stats, sizeof(f->stats));
		return err;
	default:
		return -EOPNOTSUPP;
	}
}

static LIST_HEAD(xsc_rep_block_tc_cb_list);
static LIST_HEAD(xsc_rep_block_ft_cb_list);

int xsc_rep_setup_tc(struct net_device *dev, enum tc_setup_type type,
		     void *type_data)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct flow_block_offload *f = type_data;

	f->unlocked_driver_cb = true;

	switch (type) {
	case TC_SETUP_BLOCK:
		return flow_block_cb_setup_simple(type_data,
						  &xsc_rep_block_tc_cb_list,
						  xsc_rep_setup_tc_cb,
						  priv, priv, true);
	case TC_SETUP_FT:
		return flow_block_cb_setup_simple(type_data,
						  &xsc_rep_block_ft_cb_list,
						  xsc_rep_setup_ft_cb,
						  priv, priv, true);
	default:
		return -EOPNOTSUPP;
	}
}

int xsc_rep_tc_init(struct xsc_rep_priv *rpriv)
{
	struct xsc_rep_uplink_priv *uplink_priv = &rpriv->uplink_priv;
	int err;

	mutex_init(&uplink_priv->unready_flows_lock);
	INIT_LIST_HEAD(&uplink_priv->unready_flows);

	/* init shared tc flow table */
	err = xsc_tc_esw_init(uplink_priv);
	return err;
}

void xsc_rep_tc_cleanup(struct xsc_rep_priv *rpriv)
{
	/* delete shared tc flow table */
	xsc_tc_esw_cleanup(&rpriv->uplink_priv);
	mutex_destroy(&rpriv->uplink_priv.unready_flows_lock);
}

void xsc_tc_reoffload_flows_work(struct work_struct *work)
{
	struct xsc_rep_uplink_priv *rpriv =
		container_of(work, struct xsc_rep_uplink_priv,
			     reoffload_flows_work);
	struct xsc_tc_flow *flow, *tmp;

	mutex_lock(&rpriv->unready_flows_lock);
	list_for_each_entry_safe(flow, tmp, &rpriv->unready_flows, unready) {
		if (!xsc_tc_add_fdb_flow(flow->priv, flow, NULL))
			unready_flow_del(flow);
	}
	mutex_unlock(&rpriv->unready_flows_lock);
}

void xsc_rep_tc_enable(struct xsc_adapter *priv)
{
	struct xsc_rep_priv *rpriv = priv->ppriv;

	INIT_WORK(&rpriv->uplink_priv.reoffload_flows_work,
		  xsc_tc_reoffload_flows_work);
}

void xsc_rep_tc_disable(struct xsc_adapter *priv)
{
	struct xsc_rep_priv *rpriv = priv->ppriv;

	cancel_work_sync(&rpriv->uplink_priv.reoffload_flows_work);
}

int xsc_rep_tc_event_port_affinity(struct xsc_adapter *priv)
{
	struct xsc_rep_priv *rpriv = priv->ppriv;

	queue_work(priv->workq, &rpriv->uplink_priv.reoffload_flows_work);

	return NOTIFY_OK;
}

static LIST_HEAD(xsc_block_cb_list);

#ifdef	CONFIG_XSC_OFFLOAD_OVS
static struct xsc_rep_indr_block_priv *
xsc_rep_indr_block_priv_lookup(struct xsc_rep_priv *rpriv,
			       struct net_device *netdev,
			       enum flow_block_binder_type binder_type)
{
	struct xsc_rep_indr_block_priv *cb_priv;

	list_for_each_entry(cb_priv,
			    &rpriv->uplink_priv.tc_indr_block_priv_list,
			    list)
		if (cb_priv->netdev == netdev &&
		    cb_priv->binder_type == binder_type)
			return cb_priv;

	return NULL;
}

static int xsc_rep_indr_offload(struct net_device *netdev,
				struct flow_cls_offload *flower,
				struct xsc_rep_indr_block_priv *indr_priv,
				unsigned long flags)
{
	struct xsc_adapter *priv = netdev_priv(indr_priv->rpriv->netdev);
	int err = 0;

	if (!netif_device_present(indr_priv->rpriv->netdev))
		return -EOPNOTSUPP;

	switch (flower->command) {
	case FLOW_CLS_REPLACE:
		err = xsc_configure_flower(netdev, priv, flower, flags);
		break;
	case FLOW_CLS_DESTROY:
		err = xsc_delete_flower(netdev, priv, flower, flags);
		break;
	case FLOW_CLS_STATS:
#ifdef CONFIG_XSC_OFFLOAD_COUNTER
		err = xsc_stats_flower(netdev, priv, flower, flags);
		break;
#endif
	default:
		err = -EOPNOTSUPP;
	}

	return err;
}

static int xsc_rep_indr_setup_tc_cb(enum tc_setup_type type,
				    void *type_data, void *indr_priv)
{
	unsigned long flags = XSC_TC_FLAG(ESW_OFFLOAD);
	struct xsc_rep_indr_block_priv *priv = indr_priv;

	flags |= (priv->binder_type == FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS) ?
		XSC_TC_FLAG(EGRESS) :
		XSC_TC_FLAG(INGRESS);

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return xsc_rep_indr_offload(priv->netdev, type_data, priv,
					      flags);
	default:
		return -EOPNOTSUPP;
	}
}

static int xsc_rep_indr_setup_ft_cb(enum tc_setup_type type,
				    void *type_data, void *indr_priv)
{
	struct xsc_rep_indr_block_priv *priv = indr_priv;
	struct flow_cls_offload *f = type_data;
	struct flow_cls_offload tmp;
	struct xsc_adapter *adapter;
	struct xsc_eswitch *esw;
	unsigned long flags;
	int err;

	adapter = netdev_priv(priv->rpriv->netdev);
	esw = adapter->xdev->priv.eswitch;

	flags = XSC_TC_FLAG(EGRESS) |
		XSC_TC_FLAG(ESW_OFFLOAD) |
		XSC_TC_FLAG(FT_OFFLOAD);

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		memcpy(&tmp, f, sizeof(*f));

		/* Re-use tc offload path by moving the ft flow to the
		 * reserved ft chain.
		 *
		 * FT offload can use prio range [0, INT_MAX], so we normalize
		 * it to range [1, xsc_esw_chains_get_prio_range(esw)]
		 * as with tc, where prio 0 isn't supported.
		 *
		 * We only support chain 0 of FT offload.
		 */
		if (!xsc_chains_prios_supported(esw_chains(esw)) ||
		    tmp.common.prio >= xsc_chains_get_prio_range(esw_chains(esw)) ||
		    tmp.common.chain_index)
			return -EOPNOTSUPP;

		tmp.common.chain_index = xsc_chains_get_nf_ft_chain(esw_chains(esw));
		tmp.common.prio++;
		err = xsc_rep_indr_offload(priv->netdev, &tmp, priv, flags);
		memcpy(&f->stats, &tmp.stats, sizeof(f->stats));
		return err;
	default:
		return -EOPNOTSUPP;
	}
}

static void xsc_rep_indr_block_unbind(void *cb_priv)
{
	struct xsc_rep_indr_block_priv *indr_priv = cb_priv;

	list_del(&indr_priv->list);
	kfree(indr_priv);
}

static bool xsc_rep_macvlan_mode_supported(const struct net_device *dev)
{
	struct macvlan_dev *macvlan = netdev_priv(dev);

	return macvlan->mode == MACVLAN_MODE_PASSTHRU;
}

static bool
xsc_rep_check_indr_block_supported(struct xsc_rep_priv *rpriv,
				   struct net_device *netdev,
				   struct flow_block_offload *f)
{
	struct xsc_adapter *priv = netdev_priv(rpriv->netdev);
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;
	struct net_device *macvlan_real_dev;

	if (f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS &&
	    f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS)
		return false;

#ifdef CONFIG_XSC_OFFLOAD_TUN
	if (xsc_tc_tun_device_to_offload(priv, netdev))
		return true;
#endif

	if (is_vlan_dev(netdev) && vlan_dev_real_dev(netdev) == rpriv->netdev)
		return true;

	if (netif_is_macvlan(netdev)) {
		if (!xsc_rep_macvlan_mode_supported(netdev)) {
			netdev_warn(netdev, "Offloading ingress filter is supported only with macvlan passthru mode");
			return false;
		}

		macvlan_real_dev = macvlan_dev_real_dev(netdev);

		if (macvlan_real_dev == rpriv->netdev)
			return true;
		if (netif_is_bond_master(macvlan_real_dev))
			return true;
	}

#ifdef CONFIG_XSC_OFFLOAD_OVS
	if (netif_is_ovs_master(netdev) && f->binder_type == FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS &&
	    xsc_tc_int_port_supported(esw))
		return true;
#endif

	return false;
}

static int
xsc_rep_indr_setup_block(struct net_device *netdev, struct Qdisc *sch,
			 struct xsc_rep_priv *rpriv,
			 struct flow_block_offload *f,
			 flow_setup_cb_t *setup_cb, void *data,
			 void (*cleanup)(struct flow_block_cb *block_cb))
{
	struct xsc_rep_indr_block_priv *indr_priv;
	struct flow_block_cb *block_cb;

	if (!xsc_rep_check_indr_block_supported(rpriv, netdev, f))
		return -EOPNOTSUPP;

	f->unlocked_driver_cb = true;
	f->driver_block_list = &xsc_block_cb_list;

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		indr_priv = xsc_rep_indr_block_priv_lookup(rpriv, netdev, f->binder_type);
		if (indr_priv)
			return -EEXIST;

		indr_priv = kmalloc(sizeof(*indr_priv), GFP_KERNEL);
		if (!indr_priv)
			return -ENOMEM;

		indr_priv->netdev = netdev;
		indr_priv->rpriv = rpriv;
		indr_priv->binder_type = f->binder_type;
		list_add(&indr_priv->list,
			 &rpriv->uplink_priv.tc_indr_block_priv_list);

		block_cb = flow_indr_block_cb_alloc(setup_cb, indr_priv, indr_priv,
						    xsc_rep_indr_block_unbind,
						    f, netdev, sch, data, rpriv,
						    cleanup);
		if (IS_ERR(block_cb)) {
			list_del(&indr_priv->list);
			kfree(indr_priv);
			return PTR_ERR(block_cb);
		}
		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &xsc_block_cb_list);

		return 0;
	case FLOW_BLOCK_UNBIND:
		indr_priv = xsc_rep_indr_block_priv_lookup(rpriv, netdev, f->binder_type);
		if (!indr_priv)
			return -ENOENT;

		block_cb = flow_block_cb_lookup(f->block, setup_cb, indr_priv);
		if (!block_cb)
			return -ENOENT;

		flow_indr_block_cb_remove(block_cb, f);
		list_del(&block_cb->driver_list);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int
xsc_rep_indr_replace_act(struct xsc_rep_priv *rpriv,
			 struct flow_offload_action *fl_act)

{
	struct xsc_adapter *priv = netdev_priv(rpriv->netdev);
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;
	enum xsc_flow_namespace_type ns_type;
	struct flow_action_entry *action;
	struct xsc_tc_act *act;
	bool add = false;
	int i;

	/* There is no use case currently for more than one action (e.g. pedit).
	 * when there will be, need to handle cleaning multiple actions on err.
	 */
	if (!flow_offload_has_one_action(&fl_act->action))
		return -EOPNOTSUPP;

	if (is_xdev_switchdev_mode(priv->xdev))
		ns_type = XSC_FLOW_NAMESPACE_FDB;
	else
		ns_type = XSC_FLOW_NAMESPACE_KERNEL;

	flow_action_for_each(i, action, &fl_act->action) {
		act = xsc_tc_act_get(action->id, ns_type);
		if (!act)
			continue;

		if (!act->offload_action)
			continue;

		if (!act->offload_action(priv, fl_act, action))
			add = true;
	}

	return add ? 0 : -EOPNOTSUPP;
}

static int
xsc_rep_indr_destroy_act(struct xsc_rep_priv *rpriv, struct flow_offload_action *fl_act)
{
	struct xsc_adapter *priv = netdev_priv(rpriv->netdev);
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;
	enum xsc_flow_namespace_type ns_type;
	struct xsc_tc_act *act;

	if (is_xdev_switchdev_mode(priv->xdev))
		ns_type = XSC_FLOW_NAMESPACE_FDB;
	else
		ns_type = XSC_FLOW_NAMESPACE_KERNEL;

	act = xsc_tc_act_get(fl_act->id, ns_type);
	if (!act || !act->destroy_action)
		return -EOPNOTSUPP;

	return act->destroy_action(priv, fl_act);
}

#ifdef CONFIG_XSC_OFFLOAD_COUNTER
static int
xsc_rep_indr_stats_act(struct xsc_rep_priv *rpriv, struct flow_offload_action *fl_act)

{
	struct xsc_adapter *priv = netdev_priv(rpriv->netdev);
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;
	enum xsc_flow_namespace_type ns_type;
	struct xsc_tc_act *act;

	if (is_xdev_switchdev_mode(priv->xdev))
		ns_type = XSC_FLOW_NAMESPACE_FDB;
	else
		ns_type = XSC_FLOW_NAMESPACE_KERNEL;

	act = xsc_tc_act_get(fl_act->id, ns_type);
	if (!act || !act->stats_action)
		return xsc_tc_fill_action_stats(priv, fl_act);

	return act->stats_action(priv, fl_act);
}
#endif

static int
xsc_rep_indr_setup_act(struct xsc_rep_priv *rpriv, struct flow_offload_action *fl_act)
{
	switch (fl_act->command) {
	case FLOW_ACT_REPLACE:
		return xsc_rep_indr_replace_act(rpriv, fl_act);
	case FLOW_ACT_DESTROY:
		return xsc_rep_indr_destroy_act(rpriv, fl_act);
#ifdef CONFIG_XSC_OFFLOAD_COUNTER
	case FLOW_ACT_STATS:
		return xsc_rep_indr_stats_act(rpriv, fl_act);
#endif
	default:
		return -EOPNOTSUPP;
	}
}
#endif

#ifdef	CONFIG_XSC_OFFLOAD_OVS
static int
xsc_rep_indr_no_dev_setup(struct xsc_rep_priv *rpriv,
			  enum tc_setup_type type, void *data)
{
	if (!data)
		return -EOPNOTSUPP;

	switch (type) {
	case TC_SETUP_ACT:
		return xsc_rep_indr_setup_act(rpriv, data);
	default:
		return -EOPNOTSUPP;
	}
}

static
int xsc_rep_indr_setup_cb(struct net_device *netdev, struct Qdisc *sch, void *cb_priv,
			  enum tc_setup_type type, void *type_data, void *data,
			  void (*cleanup)(struct flow_block_cb *block_cb))
{
	if (!netdev)
		return xsc_rep_indr_no_dev_setup(cb_priv, type, data);

	switch (type) {
	case TC_SETUP_BLOCK:
		return xsc_rep_indr_setup_block(netdev, sch, cb_priv, type_data,
						xsc_rep_indr_setup_tc_cb,
						data, cleanup);
	case TC_SETUP_FT:
		return xsc_rep_indr_setup_block(netdev, sch, cb_priv, type_data,
						xsc_rep_indr_setup_ft_cb,
						data, cleanup);
	default:
		return -EOPNOTSUPP;
	}
}

int xsc_rep_tc_netdevice_event_register(struct xsc_rep_priv *rpriv)
{
	struct xsc_rep_uplink_priv *uplink_priv = &rpriv->uplink_priv;

	/* init indirect block notifications */
	INIT_LIST_HEAD(&uplink_priv->tc_indr_block_priv_list);

	return flow_indr_dev_register(xsc_rep_indr_setup_cb, rpriv);
}
EXPORT_SYMBOL(xsc_rep_tc_netdevice_event_register);

void xsc_rep_tc_netdevice_event_unregister(struct xsc_rep_priv *rpriv)
{
	flow_indr_dev_unregister(xsc_rep_indr_setup_cb, rpriv,
				 xsc_rep_indr_block_unbind);
}
#endif
