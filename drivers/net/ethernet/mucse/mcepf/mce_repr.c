// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_eswitch.h"
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#include "mce_devlink.h"
#endif /* CONFIG_NET_DEVLINK */
#include "mce_sriov.h"
#include "mce_tc_lib.h"
#include "mce_lib.h"
#include "mce_repr.h"
#include "mce_txrx_lib.h"

int mce_repr_poll(struct napi_struct *napi, int weight)
{
	return weight;
}

static void __maybe_unused mce_repr_rx_hash(struct mce_repr *repr,
					    struct mce_rx_desc_up *rx_desc,
					    struct sk_buff *skb)
{
	enum pkt_hash_types hash_type = PKT_HASH_TYPE_NONE;
	u32 hash = 0;
	u32 cmd;

	if (!(repr->netdev->features & NETIF_F_RXHASH))
		return;

	hash = le32_to_cpu(rx_desc->rss_hash);
	cmd = le32_to_cpu(rx_desc->cmd);

	switch (GET_RD_O_L3_TYPE(cmd)) {
	case L3TYPE_IPv4:
	case L3TYPE_IPv6:
		hash_type = PKT_HASH_TYPE_L3;
	default:
		break;
	}

	switch (GET_RD_O_L4_TYPE(cmd)) {
	case L4TYPE_UDP:
	case L4TYPE_TCP:
	case L4TYPE_SCTP:
		hash_type = PKT_HASH_TYPE_L4;
		break;
	default:
		break;
	}

	skb_set_hash(skb, hash, hash_type);
}

static void __maybe_unused
mce_repr_process_rx_csum(struct mce_repr *repr, struct mce_rx_desc_up *rx_desc,
			 struct sk_buff *skb)
{
	u16 err_cmd = le16_to_cpu(rx_desc->err_cmd);
	u32 cmd = le32_to_cpu(rx_desc->cmd);

	/* Start with CHECKSUM_NONE and by default csum_level = 0 */
	skb->ip_summed = CHECKSUM_NONE;
	skb_checksum_none_assert(skb);

	/* check if Rx checksum is enabled */
	if ((!(repr->netdev->features & NETIF_F_RXCSUM)) ||
	    (repr->netdev->flags & IFF_PROMISC) ||
	    (repr->netdev->features & NETIF_F_RXALL)) {
		return;
	}

	if (GET_RD_ERR(err_cmd)) {
		repr->stats.rx_csum_err++;
		return;
	}

	switch (GET_RD_TUNNEL_TYPE(cmd)) {
	case INNER_VXLAN:
	case INNER_GRE:
	case INNER_GENEVE:
		skb->encapsulation = 1;
		break;
	default:
		break;
	}

	switch (GET_RD_O_L4_TYPE(cmd)) {
	case L4TYPE_UDP:
	case L4TYPE_TCP:
	case L4TYPE_SCTP:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		return;
	default:
		break;
	}
}

static __maybe_unused struct sk_buff *
mce_process_rx_vlan(struct mce_pf *pf, struct mce_repr *repr,
		    struct mce_rx_desc_up *rx_desc, struct sk_buff *skb)
{
	u8 vlan_strip = GET_RD_VLAN_STRIP(le16_to_cpu(rx_desc->err_cmd));
	u8 vlan_valid = GET_RD_VLAN_VALID(le32_to_cpu(rx_desc->cmd));
	__be16 proto;
	u16 vlan_tpid = le16_to_cpu(rx_desc->vlan_tpid);
	u16 vlan_tag0 = le16_to_cpu(rx_desc->vlan_tag0);
	u16 vlan_tag1 = le16_to_cpu(rx_desc->vlan_tag1);

	if (!vlan_valid || !vlan_strip)
		return skb;

	if (MCE_INSERT_VLAN_CNT(pf))
		return skb;

	switch (vlan_strip) {
	case 1:
		if (GET_RD_VLAN_TPID_OUTER_TYPE(vlan_tpid) ==
		    MCE_VLAN_TYPE_8100)
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       vlan_tag0);
		else
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD),
					       vlan_tag0);
		break;
	case 2:
		if (GET_RD_VLAN_TPID_MIDDLE_TYPE(vlan_tpid) ==
		    MCE_VLAN_TYPE_8100)
			proto = htons(ETH_P_8021Q);
		else
			proto = htons(ETH_P_8021AD);
		skb = vlan_insert_tag_set_proto(skb, proto,
						vlan_tag1);
		if (!skb) {
			net_err_ratelimited("strip:2 failed to insert middle VLAN tag\n");
			break;
		}

		if (GET_RD_VLAN_TPID_OUTER_TYPE(vlan_tpid) ==
		    MCE_VLAN_TYPE_8100)
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       vlan_tag0);
		else
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD),
					       vlan_tag0);
		break;
	default:
		break;
	}

	return skb;
}

static int mce_repr_open(struct net_device *netdev)
{
	netif_carrier_on(netdev);
	netif_tx_start_all_queues(netdev);
	netdev_info(netdev, "open\n");
	return 0;
}

static int mce_repr_stop(struct net_device *netdev)
{
	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);
	netdev_info(netdev, "down\n");
	return 0;
}

/**
 * mce_netdev_to_repr - Get port representor for given netdevice
 * @netdev: pointer to port representor netdev
 * Returns: The result of the operation.
 */
struct mce_repr *mce_netdev_to_repr(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);

	return np->repr;
}

static void mce_repr_get_stats64(struct net_device *dev,
				 struct rtnl_link_stats64 *stats)
{
	struct mce_netdev_priv *np = netdev_priv(dev);
	struct mce_repr *repr = np->repr;

	stats->rx_packets = repr->stats.rx_packets;
	stats->tx_packets = repr->stats.tx_packets;
	stats->rx_bytes = repr->stats.rx_bytes;
	stats->tx_bytes = repr->stats.tx_bytes;
	stats->rx_dropped = repr->stats.rx_dropped;
	stats->tx_errors = repr->stats.tx_errors;
}

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
static int mce_repr_setup_tc_cls_flower(struct mce_repr *repr,
					struct flow_cls_offload *flower)
{
	switch (flower->command) {
	case FLOW_CLS_REPLACE:
		return mce_add_cls_flower(repr->netdev, repr->src_vsi, flower);
	case FLOW_CLS_DESTROY:
		return mce_del_cls_flower(repr->src_vsi, flower);
	default:
		return -EINVAL;
	}
}

static int mce_repr_setup_tc_block_cb(enum tc_setup_type type,
				      void *type_data, void *cb_priv)
{
	struct flow_cls_offload *flower = type_data;
	struct mce_netdev_priv *np = cb_priv;

	if (type == TC_SETUP_CLSFLOWER)
		return mce_repr_setup_tc_cls_flower(np->repr, flower);
	return -EOPNOTSUPP;
}

static LIST_HEAD(mce_repr_block_cb_list);

static int mce_repr_setup_tc(struct net_device *netdev,
			     enum tc_setup_type type, void *type_data)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return mce_repr_setup_tc_cls_flower(np->repr, type_data);
	case TC_SETUP_BLOCK:
		return flow_block_cb_setup_simple(type_data,
						  &mce_repr_block_cb_list,
						  mce_repr_setup_tc_block_cb, np, np,
						  true);
	default:
		return -EOPNOTSUPP;
	}
}
#endif

static const struct net_device_ops mce_repr_netdev_ops = {
	.ndo_get_stats64 = mce_repr_get_stats64,
	.ndo_open = mce_repr_open,
	.ndo_stop = mce_repr_stop,
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	.ndo_setup_tc = mce_repr_setup_tc,
#endif
};

/**
 * mce_is_port_repr_netdev - Check if a given netdevice is a port representor
 * netdev
 * @netdev: pointer to netdev
 * Returns: The result of the operation.
 */
bool mce_is_port_repr_netdev(struct net_device *netdev)
{
	return netdev && (netdev->netdev_ops == &mce_repr_netdev_ops);
}

/**
 * mce_repr_reg_netdev - register port representor netdev
 * @repr: port representor to register
 * Returns: The result of the operation.
 */
static int mce_repr_reg_netdev(struct mce_repr *repr)
{
	struct net_device *netdev = repr->netdev;
	struct vf_info *vfinfo = repr->vfinfo;

	if (is_valid_ether_addr(vfinfo->vf_mac_addr)) {
		eth_hw_addr_random(netdev);
	} else {
		netdev_warn(netdev,
			    "vf id:%d Invalid MAC address in list; "
			    "using random MAC",
			    repr->vfid);
		eth_hw_addr_random(netdev);
	}

	netdev->netdev_ops = &mce_repr_netdev_ops;
	mce_set_ethtool_repr_ops(netdev);
	netdev->hw_features |= NETIF_F_HW_TC;

	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);

	return register_netdev(netdev);
}

static int mce_repr_add(struct mce_pf *pf, int vfid)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_q_vector *q_vector;
	struct mce_netdev_priv *np;
	struct vf_info *vfinfo;
	struct mce_repr *repr;
	struct mce_vsi *vsi;
	int err = 0;

	vsi = mce_get_vf_vsi(pf, vfid);

	if (!vsi)
		return -EINVAL;

	vfinfo = &vf->vfinfo[vfid];
	repr = kzalloc(sizeof(*repr), GFP_KERNEL);
	if (!repr)
		return -ENOMEM;

	repr->netdev = alloc_etherdev(sizeof(struct mce_netdev_priv));
	if (!repr->netdev) {
		err = -ENOMEM;
		goto err_alloc;
	}
	vsi->netdev = repr->netdev;
	repr->src_vsi = vsi;
	repr->vfinfo = vfinfo;
	repr->vfid = vfid;
	repr->dft_ring_id = vfid * pf->max_pf_txqs;
	vfinfo->repr = repr;
	vfinfo->pf = pf;
	np = netdev_priv(repr->netdev);
	np->repr = repr;
	q_vector = kzalloc(sizeof(*q_vector), GFP_KERNEL);
	if (!q_vector) {
		err = -ENOMEM;
		goto err_alloc_q_vector;
	}
	repr->q_vector = q_vector;
	q_vector->repr = repr;
	repr->rx_pring_size = MCE_REP_DEFAULT_PSEUDO_RING_SIZE;
	INIT_LIST_HEAD(&repr->rx_list);
	spin_lock_init(&repr->rx_lock);
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#endif /* CONFIG_NET_DEVLINK */
	SET_NETDEV_DEV(repr->netdev, mce_pf_to_dev(pf));
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#endif /* CONFIG_NET_DEVLINK */
	err = mce_repr_reg_netdev(repr);
	if (err)
		goto err_netdev;
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#endif /* CONFIG_NET_DEVLINK */
	return 0;
err_netdev:
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#endif /* CONFIG_NET_DEVLINK */
	kfree(repr->q_vector);
	vfinfo->repr->q_vector = NULL;
err_alloc_q_vector:
	free_netdev(repr->netdev);
	repr->netdev = NULL;
err_alloc:
	kfree(repr);
	repr = NULL;
	return err;
}

/**
 * mce_repr_rem - remove representor from VF
 * @pf: PF containing the representor
 * @vfid: VF identifier
 */
static void mce_repr_rem(struct mce_pf *pf, int vfid)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct vf_info *vfinfo;

	vfinfo = &vf->vfinfo[vfid];
	if (!vfinfo->repr)
		return;

	kfree(vfinfo->repr->q_vector);
	vfinfo->repr->q_vector = NULL;
	unregister_netdev(vfinfo->repr->netdev);
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#endif /* CONFIG_NET_DEVLINK */
	free_netdev(vfinfo->repr->netdev);
	vfinfo->repr->netdev = NULL;
	kfree(vfinfo->repr);
	vfinfo->repr = NULL;
}

/**
 * mce_repr_rem_from_all_vfs - remove port representor for all VFs
 * @pf: pointer to PF structure
 */
void mce_repr_rem_from_all_vfs(struct mce_pf *pf)
{
	int i = 0;

	mce_for_each_vf_id(pf, i)
		mce_repr_rem(pf, i);
}

/**
 * mce_repr_add_for_all_vfs - add port representor for all VFs
 * @pf: pointer to PF structure
 * Returns: The result of the operation.
 */
int mce_repr_add_for_all_vfs(struct mce_pf *pf)
{
	int err, i = 0;

	mce_for_each_vf_id(pf, i) {
		err = mce_repr_add(pf, i);
		if (err)
			goto err;
	}

	return 0;
err:
	mce_repr_rem_from_all_vfs(pf);
	return err;
}
