// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_ethtool.h"

static void nbl_serv_set_link_state(struct nbl_service_mgt *serv_mgt, struct net_device *netdev);

static void nbl_serv_set_queue_param(struct nbl_serv_ring *ring, u16 desc_num,
				     struct nbl_txrx_queue_param *param, u16 vsi_id,
				     u16 global_vector_id)
{
	param->vsi_id = vsi_id;
	param->dma = ring->dma;
	param->desc_num = desc_num;
	param->local_queue_id = ring->local_queue_id / 2;
	param->global_vector_id = global_vector_id;
	param->intr_en = 1;
	param->intr_mask = 1;
	param->extend_header = 1;
	param->rxcsum = 1;
	param->split = 0;
}

/**
 * In virtio mode, the emulator triggers the configuration of
 * txrx_registers only based on tx_ring, so the rx_info needs
 * to be delivered first before the tx_info can be delivered.
 */
int nbl_serv_setup_queues(struct nbl_service_mgt *serv_mgt, struct nbl_serv_ring_vsi_info *vsi_info)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_txrx_queue_param param = {0};
	struct nbl_serv_ring *ring;
	struct nbl_serv_vector *vector;
	u16 start = vsi_info->ring_offset, end = vsi_info->ring_offset + vsi_info->ring_num;
	int i, ret = 0;

	for (i = start; i < end; i++) {
		vector = &ring_mgt->vectors[i];
		ring = &ring_mgt->rx_rings[i];
		nbl_serv_set_queue_param(ring, ring_mgt->rx_desc_num, &param,
					 vsi_info->vsi_id, vector->global_vector_id);

		ret = disp_ops->setup_queue(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param, false);
		if (ret)
			return ret;
	}

	for (i = start; i < end; i++) {
		vector = &ring_mgt->vectors[i];
		ring = &ring_mgt->tx_rings[i];

		nbl_serv_set_queue_param(ring, ring_mgt->tx_desc_num, &param,
					 vsi_info->vsi_id, vector->global_vector_id);

		ret = disp_ops->setup_queue(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param, true);
		if (ret)
			return ret;
	}

	return 0;
}

void nbl_serv_flush_rx_queues(struct nbl_service_mgt *serv_mgt, u16 ring_offset, u16 ring_num)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int i;

	for (i = ring_offset; i < ring_offset + ring_num; i++)
		disp_ops->kick_rx_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), i);
}

int nbl_serv_setup_rings(struct nbl_service_mgt *serv_mgt, struct net_device *netdev,
			 struct nbl_serv_ring_vsi_info *vsi_info, bool use_napi)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	u16 start = vsi_info->ring_offset, end = vsi_info->ring_offset + vsi_info->ring_num;
	int i, ret = 0;

	for (i = start; i < end; i++) {
		ring_mgt->tx_rings[i].dma =
			disp_ops->start_tx_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), i);
		if (!ring_mgt->tx_rings[i].dma) {
			netdev_err(netdev, "Fail to start tx ring %d", i);
			ret = -EFAULT;
			break;
		}
	}
	if (i != end) {
		while (--i + 1 > start)
			disp_ops->stop_tx_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), i);
		goto tx_err;
	}

	for (i = start; i < end; i++) {
		ring_mgt->rx_rings[i].dma =
			disp_ops->start_rx_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), i, use_napi);
		if (!ring_mgt->rx_rings[i].dma) {
			netdev_err(netdev, "Fail to start rx ring %d", i);
			ret = -EFAULT;
			break;
		}
	}
	if (i != end) {
		while (--i + 1 > start)
			disp_ops->stop_rx_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), i);
		goto rx_err;
	}

	return 0;

rx_err:
	for (i = start; i < end; i++)
		disp_ops->stop_tx_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), i);
tx_err:
	return ret;
}

void nbl_serv_stop_rings(struct nbl_service_mgt *serv_mgt,
			 struct nbl_serv_ring_vsi_info *vsi_info)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u16 start = vsi_info->ring_offset, end = vsi_info->ring_offset + vsi_info->ring_num;
	int i;

	for (i = start; i < end; i++)
		disp_ops->stop_tx_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), i);

	for (i = start; i < end; i++)
		disp_ops->stop_rx_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), i);
}

static int nbl_serv_set_tx_rings(struct nbl_serv_ring_mgt *ring_mgt,
				 struct net_device *netdev, struct device *dev)
{
	int i;
	u16 ring_num = ring_mgt->tx_ring_num;

	ring_mgt->tx_rings = devm_kcalloc(dev, ring_num, sizeof(*ring_mgt->tx_rings), GFP_KERNEL);
	if (!ring_mgt->tx_rings)
		return -ENOMEM;

	for (i = 0; i < ring_num; i++)
		ring_mgt->tx_rings[i].index = i;

	return 0;
}

static void nbl_serv_remove_tx_ring(struct nbl_serv_ring_mgt *ring_mgt, struct device *dev)
{
	devm_kfree(dev, ring_mgt->tx_rings);
	ring_mgt->tx_rings = NULL;
}

static int nbl_serv_set_rx_rings(struct nbl_serv_ring_mgt *ring_mgt,
				 struct net_device *netdev, struct device *dev)
{
	int i;
	u16 ring_num = ring_mgt->rx_ring_num;

	ring_mgt->rx_rings = devm_kcalloc(dev, ring_num, sizeof(*ring_mgt->rx_rings), GFP_KERNEL);
	if (!ring_mgt->rx_rings)
		return -ENOMEM;

	for (i = 0; i < ring_num; i++)
		ring_mgt->rx_rings[i].index = i;

	return 0;
}

static void nbl_serv_remove_rx_ring(struct nbl_serv_ring_mgt *ring_mgt, struct device *dev)
{
	devm_kfree(dev, ring_mgt->rx_rings);
	ring_mgt->rx_rings = NULL;
}

static int nbl_serv_set_vectors(struct nbl_service_mgt *serv_mgt,
				struct net_device *netdev, struct device *dev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_resource_pt_ops *pt_ops = NBL_ADAPTER_TO_RES_PT_OPS(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int i;
	u16 ring_num = ring_mgt->rx_ring_num;

	ring_mgt->vectors = devm_kcalloc(dev, ring_num, sizeof(*ring_mgt->vectors), GFP_KERNEL);
	if (!ring_mgt->vectors)
		return -ENOMEM;

	for (i = 0; i < ring_num; i++) {
		ring_mgt->vectors[i].napi =
			disp_ops->get_vector_napi(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), i);
		netif_napi_add(netdev, ring_mgt->vectors[i].napi, pt_ops->napi_poll);
		ring_mgt->vectors[i].netdev = netdev;
	}

	return 0;
}

static void nbl_serv_remove_vectors(struct nbl_serv_ring_mgt *ring_mgt, struct device *dev)
{
	int i;
	u16 ring_num = ring_mgt->rx_ring_num;

	for (i = 0; i < ring_num; i++)
		netif_napi_del(ring_mgt->vectors[i].napi);

	devm_kfree(dev, ring_mgt->vectors);
	ring_mgt->vectors = NULL;
}

static struct nbl_serv_vlan_node *nbl_serv_alloc_vlan_node(void)
{
	struct nbl_serv_vlan_node *vlan_node = NULL;

	vlan_node = kzalloc(sizeof(*vlan_node), GFP_ATOMIC);
	if (!vlan_node)
		return NULL;

	INIT_LIST_HEAD(&vlan_node->node);
	return vlan_node;
}

static void nbl_serv_free_vlan_node(struct nbl_serv_vlan_node *vlan_node)
{
	kfree(vlan_node);
}

static struct nbl_serv_submac_node *nbl_serv_alloc_submac_node(void)
{
	struct nbl_serv_submac_node *submac_node = NULL;

	submac_node = kzalloc(sizeof(*submac_node), GFP_ATOMIC);
	if (!submac_node)
		return NULL;

	INIT_LIST_HEAD(&submac_node->node);
	return submac_node;
}

static void nbl_serv_free_submac_node(struct nbl_serv_submac_node *submac_node)
{
	kfree(submac_node);
}

static void nbl_serv_del_all_vlans(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_vlan_node *vlan_node, *vlan_node_safe;

	list_for_each_entry_safe(vlan_node, vlan_node_safe, &flow_mgt->vlan_list, node) {
		disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
				      vlan_node->vid, NBL_COMMON_TO_VSI_ID(common));

		list_del(&vlan_node->node);
		nbl_serv_free_vlan_node(vlan_node);
	}
}

static void nbl_serv_del_all_submacs(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_submac_node *submac_node, *submac_node_safe;

	list_for_each_entry_safe(submac_node, submac_node_safe, &flow_mgt->submac_list, node) {
		disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), submac_node->mac,
				      NBL_DEFAULT_VLAN_ID, NBL_COMMON_TO_VSI_ID(common));

		list_del(&submac_node->node);
		nbl_serv_free_submac_node(submac_node);
	}
}

static int nbl_serv_ipv6_exthdr_num(struct sk_buff *skb, int start, u8 nexthdr)
{
	int exthdr_num = 0;
	struct ipv6_opt_hdr _hdr, *hp;
	unsigned int hdrlen;

	while (ipv6_ext_hdr(nexthdr)) {
		if (nexthdr == NEXTHDR_NONE)
			return -1;

		hp = skb_header_pointer(skb, start, sizeof(_hdr), &_hdr);
		if (!hp)
			return -1;

		exthdr_num++;

		if (nexthdr == NEXTHDR_FRAGMENT)
			hdrlen = 8;
		else if (nexthdr == NEXTHDR_AUTH)
			hdrlen = ipv6_authlen(hp);
		else
			hdrlen = ipv6_optlen(hp);

		nexthdr = hp->nexthdr;
		start += hdrlen;
	}

	return exthdr_num;
}

static void nbl_serv_set_sfp_state(void *priv, struct net_device *netdev, u8 eth_id,
				   bool open, bool is_force)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int ret = 0;

	if (test_bit(NBL_FLAG_LINK_DOWN_ON_CLOSE, serv_mgt->flags) || is_force) {
		if (open) {
			ret = disp_ops->set_sfp_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						      eth_id, NBL_SFP_MODULE_ON);
			if (ret)
				netdev_info(netdev, "Fail to open sfp\n");
			else
				netdev_info(netdev, "open sfp\n");
		} else {
			ret = disp_ops->set_sfp_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						      eth_id, NBL_SFP_MODULE_OFF);
			if (ret)
				netdev_info(netdev, "Fail to close sfp\n");
			else
				netdev_info(netdev, "close sfp\n");
		}
	}
}

static void nbl_serv_set_netdev_carrier_state(void *priv, struct net_device *netdev, u8 link_state)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);

	if (test_bit(NBL_DOWN, adapter->state))
		return;

	if (link_state) {
		if (!netif_carrier_ok(netdev)) {
			netif_carrier_on(netdev);
			netdev_info(netdev, "Set nic link up\n");
		}
	} else {
		if (netif_carrier_ok(netdev)) {
			netif_carrier_off(netdev);
			netdev_info(netdev, "Set nic link down\n");
		}
	}
}

static void nbl_serv_set_link_state(struct nbl_service_mgt *serv_mgt, struct net_device *netdev)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	u8 eth_id = NBL_COMMON_TO_ETH_ID(common);
	struct nbl_eth_link_info eth_link_info = {0};
	int ret = 0;

	ret = disp_ops->get_link_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					eth_id, &eth_link_info);
	if (ret) {
		netdev_err(netdev, "Fail to get_link_state err %d\n", ret);
		eth_link_info.link_status = 1;
	}

	nbl_serv_set_netdev_carrier_state(serv_mgt, netdev, eth_link_info.link_status);
}

int nbl_serv_vsi_open(void *priv, struct net_device *netdev, u16 vsi_index,
		      u16 real_qps, bool use_napi)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info = &ring_mgt->vsi_info[vsi_index];
	int ret = 0;

	if (vsi_info->started)
		return 0;

	ret = nbl_serv_setup_rings(serv_mgt, netdev, vsi_info, use_napi);
	if (ret) {
		netdev_err(netdev, "Fail to setup rings\n");
		goto setup_rings_fail;
	}

	ret = nbl_serv_setup_queues(serv_mgt, vsi_info);
	if (ret) {
		netdev_err(netdev, "Fail to setup queues\n");
		goto setup_queue_fail;
	}
	nbl_serv_flush_rx_queues(serv_mgt, vsi_info->ring_offset, vsi_info->ring_num);

	ret = disp_ops->cfg_dsch(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				 vsi_info->vsi_id, true);
	if (ret) {
		netdev_err(netdev, "Fail to setup dsch\n");
		goto setup_dsch_fail;
	}

	vsi_info->active_ring_num = real_qps;
	ret = disp_ops->setup_cqs(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_info->vsi_id, real_qps);
	if (ret)
		goto setup_cqs_fail;

	vsi_info->started = true;
	return 0;

setup_cqs_fail:
	disp_ops->cfg_dsch(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
			   NBL_COMMON_TO_VSI_ID(common), false);
setup_dsch_fail:
	disp_ops->remove_all_queues(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				    NBL_COMMON_TO_VSI_ID(common));
setup_queue_fail:
	nbl_serv_stop_rings(serv_mgt, vsi_info);
setup_rings_fail:
	return ret;
}

int nbl_serv_vsi_stop(void *priv, u16 vsi_index)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info = &ring_mgt->vsi_info[vsi_index];

	if (!vsi_info->started)
		return 0;

	vsi_info->started = false;
	/* modify defalt action and rss configuration */
	disp_ops->remove_cqs(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_info->vsi_id);

	/* disable and rest tx/rx logic queue */
	disp_ops->remove_all_queues(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_info->vsi_id);

	/* clear dsch config */
	disp_ops->cfg_dsch(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_info->vsi_id, false);
	/* free tx and rx bufs */
	nbl_serv_stop_rings(serv_mgt, vsi_info);

	return 0;
}

static int nbl_serv_switch_traffic_default_dest(void *priv, u16 from_vsi, u16 to_vsi)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct net_device *dev = net_resource_mgt->netdev;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_serv_vlan_node *vlan_node;
	int ret;

	list_for_each_entry(vlan_node, &flow_mgt->vlan_list, node) {
		disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
				      vlan_node->vid, from_vsi);
		ret = disp_ops->add_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
					    vlan_node->vid, to_vsi);
		if (ret) {
			netdev_err(dev, "Fail to cfg macvlan on vid %u in vsi switch",
				   vlan_node->vid);
			goto fail;
		}
	}

	/* trigger submac update */
	net_resource_mgt->rxmode_set_required |= NBL_FLAG_AQ_MODIFY_MAC_FILTER;
	net_resource_mgt->rxmode_set_required |= NBL_FLAG_AQ_CONFIGURE_PROMISC_MODE;
	nbl_common_queue_work(&net_resource_mgt->rx_mode_async, false, false);

	/* arp/nd traffic */
	disp_ops->del_multi_rule(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), from_vsi);
	ret = disp_ops->add_multi_rule(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), to_vsi);
	if (ret)
		goto add_multi_fail;

	return 0;

add_multi_fail:
	disp_ops->add_multi_rule(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), from_vsi);
fail:
	list_for_each_entry(vlan_node, &flow_mgt->vlan_list, node) {
		disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
				      vlan_node->vid, to_vsi);
		disp_ops->add_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
				      vlan_node->vid, from_vsi);
	}

	return -EINVAL;
}

static int nbl_serv_abnormal_event_to_queue(int event_type)
{
	switch (event_type) {
	case NBL_ABNORMAL_EVENT_DVN:
		return NBL_TX;
	case NBL_ABNORMAL_EVENT_UVN:
		return NBL_RX;
	default:
		return event_type;
	}
}

static dma_addr_t nbl_serv_netdev_queue_restore(struct nbl_service_mgt *serv_mgt,
						u16 local_queue_id, int type)
{
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_vector *vector = &ring_mgt->vectors[local_queue_id];

	if (type == NBL_TX)
		netif_stop_subqueue(vector->netdev, local_queue_id);

	return disp_ops->restore_abnormal_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       local_queue_id, type);
}

static int nbl_serv_netdev_queue_restart(struct nbl_service_mgt *serv_mgt,
					 u16 local_queue_id, int type)
{
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_vector *vector = &ring_mgt->vectors[local_queue_id];

	if (type == NBL_TX)
		netif_start_subqueue(vector->netdev, local_queue_id);

	return disp_ops->restart_abnormal_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       local_queue_id, type);
}

static dma_addr_t nbl_serv_chan_restore_netdev_queue_req(struct nbl_service_mgt *serv_mgt,
							 u16 local_queue_id, u16 func_id, int type)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	struct nbl_chan_param_restore_queue param = {0};
	struct nbl_chan_send_info chan_send = {0};
	dma_addr_t dma = 0;
	int ret = 0;

	param.local_queue_id = local_queue_id;
	param.type = type;

	NBL_CHAN_SEND(chan_send, func_id, NBL_CHAN_MSG_RESTORE_NETDEV_QUEUE,
		      &param, sizeof(param), &dma, sizeof(dma), 1);
	ret = chan_ops->send_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_send);
	if (ret)
		return 0;

	return dma;
}

static void nbl_serv_chan_restore_netdev_queue_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	struct nbl_chan_param_restore_queue *param = (struct nbl_chan_param_restore_queue *)data;
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	struct nbl_chan_ack_info chan_ack;
	dma_addr_t dma = 0;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	if (param->local_queue_id < vsi_info->ring_offset ||
	    param->local_queue_id >= vsi_info->ring_offset + vsi_info->ring_num ||
	    !vsi_info->ring_num)
		return;

	dma = nbl_serv_netdev_queue_restore(serv_mgt, param->local_queue_id, param->type);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_RESTORE_NETDEV_QUEUE, msg_id,
		     NBL_CHAN_RESP_OK, &dma, sizeof(dma));
	chan_ops->send_ack(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_ack);
}

static int nbl_serv_chan_restart_netdev_queue_req(struct nbl_service_mgt *serv_mgt,
						  u16 local_queue_id, u16 func_id, int type)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	struct nbl_chan_param_restart_queue param = {0};
	struct nbl_chan_send_info chan_send = {0};

	param.local_queue_id = local_queue_id;
	param.type = type;

	NBL_CHAN_SEND(chan_send, func_id, NBL_CHAN_MSG_RESTART_NETDEV_QUEUE,
		      &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_send);
}

static void nbl_serv_chan_restart_netdev_queue_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	struct nbl_chan_param_restart_queue *param = (struct nbl_chan_param_restart_queue *)data;
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	struct nbl_chan_ack_info chan_ack;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	if (param->local_queue_id < vsi_info->ring_offset ||
	    param->local_queue_id >= vsi_info->ring_offset + vsi_info->ring_num ||
	    !vsi_info->ring_num)
		return;

	nbl_serv_netdev_queue_restart(serv_mgt, param->local_queue_id, param->type);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_RESTART_NETDEV_QUEUE, msg_id,
		     NBL_CHAN_RESP_OK, NULL, 0);
	chan_ops->send_ack(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_ack);
}

static void nbl_serv_restore_queue(struct nbl_service_mgt *serv_mgt, u16 vsi_id,
				   u16 local_queue_id, u16 type, bool dif_err)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u16 func_id = disp_ops->get_function_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	u16 global_queue_id;
	dma_addr_t dma = 0;
	int ret = 0;

	dma = nbl_serv_chan_restore_netdev_queue_req(serv_mgt, local_queue_id, func_id, type);
	if (!dma)
		return;

	ret = disp_ops->restore_hw_queue(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id,
					 local_queue_id, dma, type);
	if (ret)
		return;

	nbl_serv_chan_restart_netdev_queue_req(serv_mgt, local_queue_id, func_id, type);

	if (dif_err && type == NBL_TX) {
		global_queue_id =
			disp_ops->get_vsi_global_queue_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							  vsi_id, local_queue_id);
		nbl_info(common, NBL_DEBUG_COMMON,
			 "dvn int_status:0, queue_id:%d\n", global_queue_id);
	}
}

static void nbl_serv_handle_tx_timeout(struct work_struct *work)
{
	struct nbl_serv_net_resource_mgt *serv_net_resource_mgt =
		container_of(work, struct nbl_serv_net_resource_mgt, tx_timeout);
	struct nbl_service_mgt *serv_mgt = serv_net_resource_mgt->serv_mgt;
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	int i = 0;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	for (i = vsi_info->ring_offset; i < vsi_info->ring_offset + vsi_info->ring_num; i++) {
		if (ring_mgt->tx_rings[i].need_recovery) {
			nbl_serv_restore_queue(serv_mgt, vsi_info->vsi_id, i, NBL_TX, false);
			ring_mgt->tx_rings[i].need_recovery = false;
		}
	}
}

int nbl_serv_netdev_open(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_serv_ring_vsi_info *vsi_info;
	int num_cpus, real_qps, ret = 0;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	if (!test_bit(NBL_DOWN, adapter->state))
		return -EBUSY;

	netdev_info(netdev, "Nbl open\n");
	netif_carrier_off(netdev);

	nbl_serv_set_sfp_state(serv_mgt, netdev, NBL_COMMON_TO_ETH_ID(common), true, false);

	if (vsi_info->active_ring_num) {
		real_qps = vsi_info->active_ring_num;
	} else {
		num_cpus = num_online_cpus();
		real_qps = num_cpus > vsi_info->ring_num ? vsi_info->ring_num : num_cpus;
	}

	ret = nbl_serv_vsi_open(serv_mgt, netdev, NBL_VSI_DATA, real_qps, 1);
	if (ret)
		goto vsi_open_fail;

	ret = netif_set_real_num_tx_queues(netdev, real_qps);
	if (ret)
		goto setup_real_qps_fail;
	ret = netif_set_real_num_rx_queues(netdev, real_qps);
	if (ret)
		goto setup_real_qps_fail;

	netif_tx_start_all_queues(netdev);
	clear_bit(NBL_DOWN, adapter->state);
	set_bit(NBL_RUNNING, adapter->state);
	nbl_serv_set_link_state(serv_mgt, netdev);

	netdev_info(netdev, "Nbl open ok!\n");

	return 0;

setup_real_qps_fail:
	nbl_serv_vsi_stop(serv_mgt, NBL_VSI_DATA);
vsi_open_fail:
	return ret;
}

int nbl_serv_netdev_stop(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_serv_ring_vsi_info *vsi_info;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	if (!test_bit(NBL_RUNNING, adapter->state))
		return -EBUSY;

	netdev_info(netdev, "Nbl stop\n");
	set_bit(NBL_DOWN, adapter->state);
	clear_bit(NBL_RUNNING, adapter->state);

	nbl_serv_set_sfp_state(serv_mgt, netdev, NBL_COMMON_TO_ETH_ID(common), false, false);

	netif_tx_stop_all_queues(netdev);
	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	nbl_serv_vsi_stop(serv_mgt, NBL_VSI_DATA);

	netdev_info(netdev, "Nbl stop ok!\n");

	return 0;
}

static int nbl_serv_change_mtu(struct net_device *netdev, int new_mtu)
{
	netdev->mtu = new_mtu;
	return 0;
}

static int nbl_serv_set_mac(struct net_device *dev, void *p)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_serv_vlan_node *vlan_node;
	struct sockaddr *addr = p;
	struct nbl_netdev_priv *priv = netdev_priv(dev);
	u16 vsi_id = priv->default_vsi_id;
	int ret = 0;

	if (!is_valid_ether_addr(addr->sa_data)) {
		netdev_err(dev, "Temp to change a invalid mac address %pM\n", addr->sa_data);
		return -EADDRNOTAVAIL;
	}

	if (ether_addr_equal(dev->dev_addr, addr->sa_data))
		return 0;

	list_for_each_entry(vlan_node, &flow_mgt->vlan_list, node) {
		disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
				      vlan_node->vid, vsi_id);
		ret = disp_ops->add_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), addr->sa_data,
					    vlan_node->vid, vsi_id);
		if (ret) {
			netdev_err(dev, "Fail to cfg macvlan on vid %u", vlan_node->vid);
			goto fail;
		}
	}

	disp_ops->set_spoof_check_addr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				       vsi_id, addr->sa_data);

	ether_addr_copy(flow_mgt->mac, addr->sa_data);
	eth_hw_addr_set(dev, addr->sa_data);

	if (!NBL_COMMON_TO_VF_CAP(common))
		disp_ops->set_eth_mac_addr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					   addr->sa_data, NBL_COMMON_TO_ETH_ID(common));

	return 0;
fail:
	list_for_each_entry(vlan_node, &flow_mgt->vlan_list, node) {
		disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), addr->sa_data,
				      vlan_node->vid, vsi_id);
		disp_ops->add_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
				      vlan_node->vid, vsi_id);
	}
	return -EAGAIN;
}

static int nbl_serv_rx_add_vid(struct net_device *dev, __be16 proto, u16 vid)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_netdev_priv *priv = netdev_priv(dev);
	struct nbl_serv_vlan_node *vlan_node;
	u16 vsi_id = priv->default_vsi_id;
	int ret = 0;

	if (vid == NBL_DEFAULT_VLAN_ID)
		return 0;

	nbl_debug(common, NBL_DEBUG_COMMON, "add mac-vlan dev for proto 0x%04x, vid %u.",
		  be16_to_cpu(proto), vid);

	list_for_each_entry(vlan_node, &flow_mgt->vlan_list, node) {
		nbl_debug(common, NBL_DEBUG_COMMON, "add mac-vlan dev vid %u.", vlan_node->vid);
		if (vlan_node->vid == vid)
			return 0;
	}

	vlan_node = nbl_serv_alloc_vlan_node();
	if (!vlan_node)
		return -EAGAIN;

	ret = disp_ops->add_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				    flow_mgt->mac, vid, vsi_id);
	if (ret) {
		nbl_serv_free_vlan_node(vlan_node);
		return -EAGAIN;
	}

	vlan_node->vid = vid;
	list_add(&vlan_node->node, &flow_mgt->vlan_list);

	return 0;
}

static int nbl_serv_rx_kill_vid(struct net_device *dev, __be16 proto, u16 vid)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_netdev_priv *priv = netdev_priv(dev);
	struct nbl_serv_vlan_node *vlan_node;
	u16 vsi_id = priv->default_vsi_id;

	if (vid == NBL_DEFAULT_VLAN_ID)
		return 0;

	nbl_debug(common, NBL_DEBUG_COMMON, "del mac-vlan dev for proto 0x%04x, vid %u.",
		  be16_to_cpu(proto), vid);

	list_for_each_entry(vlan_node, &flow_mgt->vlan_list, node) {
		nbl_debug(common, NBL_DEBUG_COMMON, "del mac-vlan dev vid %u.", vlan_node->vid);
		if (vlan_node->vid == vid) {
			disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
					      vid, vsi_id);

			list_del(&vlan_node->node);
			nbl_serv_free_vlan_node(vlan_node);

			break;
		}
	}

	return 0;
}

static void nbl_serv_get_stats64(struct net_device *netdev, struct rtnl_link_stats64 *stats)
{
	struct nbl_queue_stats queue_stats = { 0 };
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	u16 start, end;
	int i;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	start = vsi_info->ring_offset;
	end = vsi_info->ring_offset + vsi_info->ring_num;

	if (!stats)
		return;

	for (i = start; i < end; i++) {
		disp_ops->get_queue_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  i, &queue_stats, true);
		stats->tx_packets += queue_stats.packets;
		stats->tx_bytes += queue_stats.bytes;
	}

	for (i = start; i < end; i++) {
		disp_ops->get_queue_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  i, &queue_stats, false);
		stats->rx_packets += queue_stats.packets;
		stats->rx_bytes += queue_stats.bytes;
	}

	stats->multicast = 0;
	stats->rx_errors = 0;
	stats->tx_errors = 0;
	stats->rx_length_errors = 0;
	stats->rx_crc_errors = 0;
	stats->rx_frame_errors = 0;
	stats->rx_dropped = 0;
	stats->tx_dropped = 0;
}

static void nbl_modify_submacs(struct nbl_serv_net_resource_mgt *net_resource_mgt)
{
	struct netdev_hw_addr *ha;
	struct nbl_service_mgt *serv_mgt = net_resource_mgt->serv_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_netdev_priv *priv = netdev_priv(net_resource_mgt->netdev);
	struct nbl_serv_submac_node *submac_node;
	int uc_count, i, ret = 0;
	u16 vsi_id = priv->default_vsi_id;
	u8 *buf = NULL;
	u16 len;

	spin_lock_bh(&net_resource_mgt->mac_vlan_list_lock);
	uc_count = netdev_uc_count(net_resource_mgt->netdev);

	if (uc_count) {
		len = uc_count * ETH_ALEN;
		buf = kzalloc(len, GFP_ATOMIC);

		if (!buf) {
			spin_unlock_bh(&net_resource_mgt->mac_vlan_list_lock);
			return;
		}

		i = 0;
		netdev_hw_addr_list_for_each(ha, &net_resource_mgt->netdev->uc) {
			if (i >= len)
				break;
			memcpy(&buf[i], ha->addr, ETH_ALEN);
			i += ETH_ALEN;
		}

		net_resource_mgt->rxmode_set_required &= ~NBL_FLAG_AQ_MODIFY_MAC_FILTER;
	}
	spin_unlock_bh(&net_resource_mgt->mac_vlan_list_lock);

	nbl_serv_del_all_submacs(serv_mgt);

	for (i = 0; i < uc_count; i++) {
		submac_node = nbl_serv_alloc_submac_node();
		if (!submac_node)
			break;

		ret = disp_ops->add_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &buf[i * ETH_ALEN],
					    0, vsi_id);
		if (ret) {
			nbl_serv_free_submac_node(submac_node);
			break;
		}

		ether_addr_copy(submac_node->mac, &buf[i * ETH_ALEN]);
		list_add(&submac_node->node, &flow_mgt->submac_list);
	}

	kfree(buf);
}

static void nbl_modify_promisc_mode(struct nbl_serv_net_resource_mgt *net_resource_mgt)
{
	struct nbl_netdev_priv *priv = netdev_priv(net_resource_mgt->netdev);
	struct nbl_service_mgt *serv_mgt = net_resource_mgt->serv_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u16 mode = 0;

	spin_lock_bh(&net_resource_mgt->current_netdev_promisc_flags_lock);
	if (net_resource_mgt->curr_promiscuout_mode & (IFF_PROMISC | IFF_ALLMULTI))
		mode = 1;

	net_resource_mgt->rxmode_set_required &= ~NBL_FLAG_AQ_CONFIGURE_PROMISC_MODE;
	spin_unlock_bh(&net_resource_mgt->current_netdev_promisc_flags_lock);

	disp_ops->set_promisc_mode(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				   priv->default_vsi_id, mode);
}

static struct nbl_mac_filter *nbl_find_filter(struct nbl_adapter *adapter, const u8 *macaddr)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_mac_filter *f;

	if (!macaddr)
		return NULL;

	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	list_for_each_entry(f, &net_resource_mgt->mac_filter_list, list) {
		if (ether_addr_equal(macaddr, f->macaddr))
			return f;
	}

	return NULL;
}

static void nbl_free_filter(struct nbl_serv_net_resource_mgt *net_resource_mgt)
{
	struct nbl_mac_filter *f;
	struct list_head *pos, *n;

	list_for_each_safe(pos, n, &net_resource_mgt->mac_filter_list) {
		f = list_entry(pos, struct nbl_mac_filter, list);
		list_del(&f->list);
		kfree(f);
	}
}

static struct nbl_mac_filter *nbl_add_filter(struct nbl_adapter *adapter, const u8 *macaddr)
{
	struct nbl_mac_filter *f;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;

	if (!macaddr)
		return NULL;

	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	f = nbl_find_filter(adapter, macaddr);
	if (!f) {
		f = kzalloc(sizeof(*f), GFP_ATOMIC);
		if (!f)
			return f;

		ether_addr_copy(f->macaddr, macaddr);
		list_add_tail(&f->list, &net_resource_mgt->mac_filter_list);
		net_resource_mgt->rxmode_set_required |= NBL_FLAG_AQ_MODIFY_MAC_FILTER;
	}

	return f;
}

static int nbl_addr_unsync(struct net_device *netdev, const u8 *addr)
{
	struct nbl_adapter *adapter;
	struct nbl_mac_filter *f;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;

	adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	if (ether_addr_equal(addr, netdev->dev_addr))
		return 0;

	f = nbl_find_filter(adapter, addr);
	if (f) {
		list_del(&f->list);
		kfree(f);
		net_resource_mgt->rxmode_set_required |= NBL_FLAG_AQ_MODIFY_MAC_FILTER;
	}

	return 0;
}

static int nbl_addr_sync(struct net_device *netdev, const u8 *addr)
{
	struct nbl_adapter *adapter;

	adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	if (ether_addr_equal(addr, netdev->dev_addr))
		return 0;

	if (nbl_add_filter(adapter, addr))
		return 0;
	else
		return -ENOMEM;
}

static bool nbl_serv_promisc_mode_changed(struct net_device *dev)
{
	struct nbl_adapter *adapter;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;

	adapter = NBL_NETDEV_TO_ADAPTER(dev);
	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	return (net_resource_mgt->curr_promiscuout_mode ^ dev->flags)
		& (IFF_PROMISC | IFF_ALLMULTI);
}

static void nbl_serv_set_rx_mode(struct net_device *dev)
{
	struct nbl_adapter *adapter;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;

	adapter = NBL_NETDEV_TO_ADAPTER(dev);
	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	spin_lock_bh(&net_resource_mgt->mac_vlan_list_lock);
	__dev_uc_sync(dev, nbl_addr_sync, nbl_addr_unsync);
	spin_unlock_bh(&net_resource_mgt->mac_vlan_list_lock);

	if (!NBL_COMMON_TO_VF_CAP(NBL_SERV_MGT_TO_COMMON(serv_mgt))) { /* only pf support */
		spin_lock_bh(&net_resource_mgt->current_netdev_promisc_flags_lock);
		if (nbl_serv_promisc_mode_changed(dev)) {
			net_resource_mgt->rxmode_set_required |= NBL_FLAG_AQ_CONFIGURE_PROMISC_MODE;
			net_resource_mgt->curr_promiscuout_mode = dev->flags;
		}
		spin_unlock_bh(&net_resource_mgt->current_netdev_promisc_flags_lock);
	}

	nbl_common_queue_work(&net_resource_mgt->rx_mode_async, false, false);
}

static void nbl_serv_change_rx_flags(struct net_device *dev, int flag)
{
	struct nbl_adapter *adapter;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;

	adapter = NBL_NETDEV_TO_ADAPTER(dev);
	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	spin_lock_bh(&net_resource_mgt->current_netdev_promisc_flags_lock);
	if (nbl_serv_promisc_mode_changed(dev)) {
		net_resource_mgt->rxmode_set_required |= NBL_FLAG_AQ_CONFIGURE_PROMISC_MODE;
		net_resource_mgt->curr_promiscuout_mode = dev->flags;
	}
	spin_unlock_bh(&net_resource_mgt->current_netdev_promisc_flags_lock);

	nbl_common_queue_work(&net_resource_mgt->rx_mode_async, false, false);
}

static netdev_features_t
nbl_serv_features_check(struct sk_buff *skb, struct net_device *dev, netdev_features_t features)
{
	u32 l2_l3_hrd_len = 0, l4_hrd_len = 0, total_hrd_len = 0;
	u8 l4_proto = 0;
	__be16 protocol, frag_off;
	int ret;
	unsigned char *exthdr;
	unsigned int offset = 0;
	int nexthdr = 0;
	int exthdr_num = 0;
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		unsigned char *hdr;
	} l4;

	/* No point in doing any of this if neither checksum nor GSO are
	 * being requested for this frame. We can rule out both by just
	 * checking for CHECKSUM_PARTIAL.
	 */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	/* We cannot support GSO if the MSS is going to be less than
	 * 256 bytes or bigger than 16383 bytes. If it is then we need to drop support for GSO.
	 */
	if (skb_is_gso(skb) && (skb_shinfo(skb)->gso_size < NBL_TX_TSO_MSS_MIN ||
				skb_shinfo(skb)->gso_size > NBL_TX_TSO_MSS_MAX))
		features &= ~NETIF_F_GSO_MASK;

	l2_l3_hrd_len = (u32)(skb_transport_header(skb) - skb->data);

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);
	protocol = vlan_get_protocol(skb);

	if (protocol == htons(ETH_P_IP)) {
		l4_proto = ip.v4->protocol;
	} else if (protocol == htons(ETH_P_IPV6)) {
		exthdr = ip.hdr + sizeof(*ip.v6);
		l4_proto = ip.v6->nexthdr;
		if (l4.hdr != exthdr) {
			ret = ipv6_skip_exthdr(skb, exthdr - skb->data, &l4_proto, &frag_off);
			if (ret < 0)
				goto out_rm_features;
		}

		/* IPV6 extension headers
		 * (1) donot support routing and destination extension headers
		 * (2) support 2 extension headers mostly
		 */
		nexthdr = ipv6_find_hdr(skb, &offset, NEXTHDR_ROUTING, NULL, NULL);
		if (nexthdr == NEXTHDR_ROUTING) {
			netdev_info(dev, "skb contain ipv6 routing ext header\n");
			goto out_rm_features;
		}

		nexthdr = ipv6_find_hdr(skb, &offset, NEXTHDR_DEST, NULL, NULL);
		if (nexthdr == NEXTHDR_DEST) {
			netdev_info(dev, "skb contain ipv6 routing dest header\n");
			goto out_rm_features;
		}

		exthdr_num = nbl_serv_ipv6_exthdr_num(skb, exthdr - skb->data, ip.v6->nexthdr);
		if (exthdr_num < 0 || exthdr_num > 2) {
			netdev_info(dev, "skb ipv6 exthdr_num:%d\n", exthdr_num);
			goto out_rm_features;
		}
	} else {
		goto out_rm_features;
	}

	switch (l4_proto) {
	case IPPROTO_TCP:
		l4_hrd_len = (l4.tcp->doff) * 4;
		break;
	case IPPROTO_UDP:
		l4_hrd_len = sizeof(struct udphdr);
		break;
	case IPPROTO_SCTP:
		l4_hrd_len = sizeof(struct sctphdr);
		break;
	default:
		goto out_rm_features;
	}

	total_hrd_len = l2_l3_hrd_len + l4_hrd_len;

	// TX checksum offload support total header len is [0, 255]
	if (total_hrd_len > NBL_TX_CHECKSUM_OFFLOAD_L2L3L4_HDR_LEN_MAX)
		goto out_rm_features;

	// TSO support total header len is [42, 128]
	if (total_hrd_len < NBL_TX_TSO_L2L3L4_HDR_LEN_MIN ||
	    total_hrd_len > NBL_TX_TSO_L2L3L4_HDR_LEN_MAX)
		features &= ~NETIF_F_GSO_MASK;

	if (skb->encapsulation)
		goto out_rm_features;

	return features;

out_rm_features:
	return features & ~(NETIF_F_IP_CSUM |
			    NETIF_F_IPV6_CSUM |
			    NETIF_F_SCTP_CRC |
			    NETIF_F_GSO_MASK);
}

static void nbl_serv_tx_timeout(struct net_device *netdev, unsigned int txqueue)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(priv);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	ring_mgt->tx_rings[vsi_info->ring_offset + txqueue].need_recovery = true;
	ring_mgt->tx_rings[vsi_info->ring_offset + txqueue].tx_timeout_count++;

	nbl_warn(common, NBL_DEBUG_QUEUE, "TX timeout on queue %d", txqueue);

	nbl_common_queue_work(&NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt)->tx_timeout, false, false);
}

static int nbl_serv_get_phys_port_name(struct net_device *dev, char *name, size_t len)
{
	struct nbl_common_info *common = NBL_NETDEV_TO_COMMON(dev);
	u8 pf_id;

	pf_id = common->eth_id;
	if ((NBL_COMMON_TO_ETH_MODE(common) == NBL_TWO_ETHERNET_PORT) && common->eth_id == 2)
		pf_id = 1;

	if (snprintf(name, len, "p%u", pf_id) >= len)
		return -EINVAL;
	return 0;
}

static int nbl_serv_get_port_parent_id(struct net_device *dev, struct netdev_phys_item_id *ppid)
{
	struct nbl_netdev_priv *priv = netdev_priv(dev);
	struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(priv);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u8 mac[ETH_ALEN];

	disp_ops->get_base_mac_addr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), mac);

	ppid->id_len = ETH_ALEN;
	memcpy(&ppid->id, mac, ppid->id_len);

	return 0;
}

static int nbl_serv_register_net(void *priv, struct nbl_register_net_param *register_param,
				 struct nbl_register_net_result *register_result)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int p4_type, ret = 0;

	ret = disp_ops->register_net(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				     register_param, register_result);
	if (ret)
		return ret;

	p4_type = disp_ops->get_p4_used(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	switch (p4_type) {
	case NBL_P4_DEFAULT:
		set_bit(NBL_FLAG_P4_DEFAULT, serv_mgt->flags);
		break;
	default:
		nbl_warn(NBL_SERV_MGT_TO_COMMON(serv_mgt), NBL_DEBUG_CUSTOMIZED_P4,
			 "Unknown P4 type %d", p4_type);
	}

	return 0;
}

static int nbl_serv_unregister_net(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->unregister_net(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_setup_txrx_queues(void *priv, u16 vsi_id, u16 queue_num, u16 net_vector_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_vector *vector;
	int i, ret = 0;

	/* Clear cfgs, in case this function exited abnormaly last time */
	disp_ops->clear_queues(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);

	/* queue_num include user&kernel queue */
	ret = disp_ops->alloc_txrx_queues(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id, queue_num);
	if (ret)
		return -EFAULT;

	/* ring_mgt->tx_ring_number only for kernel use */
	for (i = 0; i < ring_mgt->tx_ring_num; i++) {
		ring_mgt->tx_rings[i].local_queue_id = NBL_PAIR_ID_GET_TX(i);
		ring_mgt->rx_rings[i].local_queue_id = NBL_PAIR_ID_GET_RX(i);

		vector = &ring_mgt->vectors[i];
		vector->local_vector_id = i + net_vector_id;
		vector->global_vector_id =
			disp_ops->get_global_vector(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						    vsi_id, vector->local_vector_id);
		vector->irq_enable_base =
			disp_ops->get_msix_irq_enable_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							   vector->global_vector_id,
							   &vector->irq_data);

		disp_ops->set_vector_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  vector->irq_enable_base,
					  vector->irq_data, i,
					  ring_mgt->net_msix_mask_en);
	}

	return 0;
}

static void nbl_serv_remove_txrx_queues(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_ring_mgt *ring_mgt;
	struct nbl_dispatch_ops *disp_ops;

	ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->free_txrx_queues(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);
}

static int nbl_serv_setup_q2vsi(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->setup_q2vsi(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);
}

static void nbl_serv_remove_q2vsi(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->remove_q2vsi(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);
}

static int nbl_serv_setup_rss(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->setup_rss(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);
}

static void nbl_serv_remove_rss(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->remove_rss(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);
}

static int nbl_serv_alloc_rings(void *priv, struct net_device *netdev,
				u16 tx_num, u16 rx_num, u16 desc_num)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct device *dev;
	struct nbl_serv_ring_mgt *ring_mgt;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;

	dev = NBL_SERV_MGT_TO_DEV(serv_mgt);
	ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ring_mgt->tx_ring_num = tx_num;
	ring_mgt->rx_ring_num = rx_num;
	ring_mgt->tx_desc_num = desc_num;
	ring_mgt->rx_desc_num = desc_num;

	ret = disp_ops->alloc_rings(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), netdev,
				    tx_num, rx_num, ring_mgt->tx_desc_num,
				    ring_mgt->rx_desc_num);
	if (ret)
		goto alloc_rings_fail;

	ret = nbl_serv_set_tx_rings(ring_mgt, netdev, dev);
	if (ret)
		goto set_tx_fail;
	ret = nbl_serv_set_rx_rings(ring_mgt, netdev, dev);
	if (ret)
		goto set_rx_fail;

	ret = nbl_serv_set_vectors(serv_mgt, netdev, dev);
	if (ret)
		goto set_vectors_fail;

	return 0;

set_vectors_fail:
	nbl_serv_remove_rx_ring(ring_mgt, dev);
set_rx_fail:
	nbl_serv_remove_tx_ring(ring_mgt, dev);
set_tx_fail:
	disp_ops->remove_rings(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
alloc_rings_fail:
	return ret;
}

static void nbl_serv_free_rings(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct device *dev;
	struct nbl_serv_ring_mgt *ring_mgt;
	struct nbl_dispatch_ops *disp_ops;

	dev = NBL_SERV_MGT_TO_DEV(serv_mgt);
	ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	nbl_serv_remove_vectors(ring_mgt, dev);
	nbl_serv_remove_rx_ring(ring_mgt, dev);
	nbl_serv_remove_tx_ring(ring_mgt, dev);

	disp_ops->remove_rings(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_enable_napis(void *priv, u16 vsi_index)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info = &ring_mgt->vsi_info[vsi_index];
	u16 start = vsi_info->ring_offset, end = vsi_info->ring_offset + vsi_info->ring_num;
	int i;

	for (i = start; i < end; i++)
		napi_enable(ring_mgt->vectors[i].napi);

	return 0;
}

static void nbl_serv_disable_napis(void *priv, u16 vsi_index)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info = &ring_mgt->vsi_info[vsi_index];
	u16 start = vsi_info->ring_offset, end = vsi_info->ring_offset + vsi_info->ring_num;
	int i;

	for (i = start; i < end; i++)
		napi_disable(ring_mgt->vectors[i].napi);
}

static void nbl_serv_set_mask_en(void *priv, bool enable)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_ring_mgt *ring_mgt;

	ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);

	ring_mgt->net_msix_mask_en = enable;
}

static int nbl_serv_start_net_flow(void *priv, struct net_device *netdev, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_serv_vlan_node *vlan_node;
	int ret = 0;

	/* Clear cfgs, in case this function exited abnormaly last time */
	disp_ops->clear_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);

	if (!list_empty(&flow_mgt->vlan_list))
		return -ECONNRESET;

	ret = disp_ops->add_multi_rule(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);
	if (ret)
		goto add_multi_fail;

	vlan_node = nbl_serv_alloc_vlan_node();
	if (!vlan_node)
		goto alloc_fail;

	ether_addr_copy(flow_mgt->mac, netdev->dev_addr);
	ret = disp_ops->add_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
				    NBL_DEFAULT_VLAN_ID, vsi_id);
	if (ret)
		goto add_macvlan_fail;

	vlan_node->vid = 0;

	list_add(&vlan_node->node, &flow_mgt->vlan_list);
	return 0;

add_macvlan_fail:
	nbl_serv_free_vlan_node(vlan_node);
alloc_fail:
	disp_ops->del_multi_rule(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);
add_multi_fail:
	return ret;
}

static void nbl_serv_stop_net_flow(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);

	nbl_serv_del_all_vlans(serv_mgt);
	nbl_serv_del_all_submacs(serv_mgt);

	disp_ops->del_multi_rule(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);

	disp_ops->set_vf_spoof_check(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				     vsi_id, -1, false);
	memset(flow_mgt->mac, 0, sizeof(flow_mgt->mac));
}

static int nbl_serv_set_lldp_flow(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->add_lldp_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);
}

static void nbl_serv_remove_lldp_flow(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->del_lldp_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);
}

static int nbl_serv_start_mgt_flow(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->setup_multi_group(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static void nbl_serv_stop_mgt_flow(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->remove_multi_group(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static u32 nbl_serv_get_tx_headroom(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_tx_headroom(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

/**
 * This ops get flexible product capability from ctrl device, if the device has not manager cap, it
 * need get capability from ctr device by channel
 */
static bool nbl_serv_get_product_flex_cap(void *priv, enum nbl_flex_cap_type cap_type)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_product_flex_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						       cap_type);
}

/**
 * This ops get fix product capability from resource layer, this capability fix by product_type, no
 * need get from ctrl device
 */
static bool nbl_serv_get_product_fix_cap(void *priv, enum nbl_fix_cap_type cap_type)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						       cap_type);
}

static int nbl_serv_init_chip(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_common_info *common;
	struct device *dev;
	int ret = 0;

	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	dev = NBL_COMMON_TO_DEV(common);

	ret = disp_ops->init_chip_module(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret) {
		dev_err(dev, "init_chip_module failed\n");
		goto module_init_fail;
	}

	ret = disp_ops->queue_init(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret) {
		dev_err(dev, "queue_init failed\n");
		goto queue_init_fail;
	}

	ret = disp_ops->vsi_init(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret) {
		dev_err(dev, "vsi_init failed\n");
		goto vsi_init_fail;
	}

	return 0;

vsi_init_fail:
queue_init_fail:
module_init_fail:
	return ret;
}

static int nbl_serv_destroy_chip(void *p)
{
	return 0;
}

static int nbl_serv_configure_msix_map(void *priv, u16 num_net_msix, u16 num_others_msix,
				       bool net_msix_mask_en)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ret = disp_ops->configure_msix_map(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), num_net_msix,
					   num_others_msix, net_msix_mask_en);
	if (ret)
		return -EIO;

	return 0;
}

static int nbl_serv_destroy_msix_map(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ret = disp_ops->destroy_msix_map(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret)
		return -EIO;

	return 0;
}

static int nbl_serv_enable_mailbox_irq(void *priv, u16 vector_id, bool enable_msix)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ret = disp_ops->enable_mailbox_irq(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					   vector_id, enable_msix);
	if (ret)
		return -EIO;

	return 0;
}

static int nbl_serv_enable_abnormal_irq(void *priv, u16 vector_id, bool enable_msix)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ret = disp_ops->enable_abnormal_irq(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    vector_id, enable_msix);
	if (ret)
		return -EIO;

	return 0;
}

static irqreturn_t nbl_serv_clean_rings(int __always_unused irq, void *data)
{
	struct nbl_serv_vector *vector = (struct nbl_serv_vector *)data;

	napi_schedule_irqoff(vector->napi);

	return IRQ_HANDLED;
}

static int nbl_serv_request_net_irq(void *priv, struct nbl_msix_info_param *msix_info)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct nbl_serv_ring *tx_ring, *rx_ring;
	struct nbl_serv_vector *vector;
	u32 irq_num;
	int i, ret = 0;

	for (i = 0; i < ring_mgt->tx_ring_num; i++) {
		tx_ring = &ring_mgt->tx_rings[i];
		rx_ring = &ring_mgt->rx_rings[i];
		vector = &ring_mgt->vectors[i];
		vector->tx_ring = tx_ring;
		vector->rx_ring = rx_ring;

		irq_num = msix_info->msix_entries[i].vector;
		snprintf(vector->name, sizeof(vector->name) - 1, "%s%03d-%s-%02u", "NBL",
			 NBL_COMMON_TO_VSI_ID(common), "TxRx", i);
		ret = devm_request_irq(dev, irq_num, nbl_serv_clean_rings, 0,
				       vector->name, vector);
		if (ret) {
			nbl_err(common, NBL_DEBUG_INTR,
				"TxRx Queue %u requests MSIX irq failed %d", i, ret);
			goto request_irq_err;
		}
	}

	net_resource_mgt->num_net_msix = msix_info->msix_num;

	return 0;

request_irq_err:
	while (--i + 1) {
		vector = &ring_mgt->vectors[i];

		irq_num = msix_info->msix_entries[i].vector;
		devm_free_irq(dev, irq_num, vector);
	}
	return ret;
}

static void nbl_serv_free_net_irq(void *priv, struct nbl_msix_info_param *msix_info)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct nbl_serv_vector *vector;
	u32 irq_num;
	int i;

	for (i = 0; i < ring_mgt->tx_ring_num; i++) {
		vector = &ring_mgt->vectors[i];

		irq_num = msix_info->msix_entries[i].vector;
		devm_free_irq(dev, irq_num, vector);
	}
}

static u16 nbl_serv_get_global_vector(void *priv, u16 local_vector_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_global_vector(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					   NBL_COMMON_TO_VSI_ID(common), local_vector_id);
}

static u16 nbl_serv_get_msix_entry_id(void *priv, u16 local_vector_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_msix_entry_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					   NBL_COMMON_TO_VSI_ID(common), local_vector_id);
}

static u16 nbl_serv_get_vsi_id(void *priv, u16 func_id, u16 type)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_vsi_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), func_id, type);
}

static void nbl_serv_get_eth_id(void *priv, u16 vsi_id, u8 *eth_mode, u8 *eth_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_eth_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id, eth_mode, eth_id);
}

static void nbl_serv_get_user_queue_info(void *priv, u16 *queue_num, u16 *queue_size, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->get_user_queue_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				      queue_num, queue_size, vsi_id);
}

static int nbl_serv_enable_lag_protocol(void *priv, u16 vsi_id, bool lag_en)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int ret = 0;

	if (lag_en)
		ret = disp_ops->add_lag_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);
	else
		disp_ops->del_lag_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);

	return ret;
}

static void nbl_serv_net_stats_update_task(struct work_struct *work)
{
	struct nbl_serv_net_resource_mgt *serv_net_resource_mgt =
		container_of(work, struct nbl_serv_net_resource_mgt, net_stats_update);
	struct nbl_service_mgt *serv_mgt;

	serv_mgt = serv_net_resource_mgt->serv_mgt;

	nbl_serv_update_stats(serv_mgt, false);
}

static void nbl_serv_rx_mode_async_task(struct work_struct *work)
{
	struct nbl_serv_net_resource_mgt *serv_net_resource_mgt =
		container_of(work, struct nbl_serv_net_resource_mgt, rx_mode_async);

	if (serv_net_resource_mgt->rxmode_set_required & NBL_FLAG_AQ_MODIFY_MAC_FILTER)
		nbl_modify_submacs(serv_net_resource_mgt);

	if (serv_net_resource_mgt->rxmode_set_required & NBL_FLAG_AQ_CONFIGURE_PROMISC_MODE)
		nbl_modify_promisc_mode(serv_net_resource_mgt);
}

static void nbl_serv_net_task_service_timer(struct timer_list *t)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					from_timer(net_resource_mgt, t, serv_timer);

	mod_timer(&net_resource_mgt->serv_timer,
		  round_jiffies(net_resource_mgt->serv_timer_period + jiffies));
	nbl_common_queue_work(&net_resource_mgt->net_stats_update, false, false);
}

static void nbl_serv_setup_flow_mgt(struct nbl_serv_flow_mgt *flow_mgt)
{
	INIT_LIST_HEAD(&flow_mgt->vlan_list);
	INIT_LIST_HEAD(&flow_mgt->submac_list);
}

static void nbl_serv_register_restore_netdev_queue(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);

	if (!chan_ops->check_queue_exist(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	chan_ops->register_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
			       NBL_CHAN_MSG_RESTORE_NETDEV_QUEUE,
			       nbl_serv_chan_restore_netdev_queue_resp, serv_mgt);

	chan_ops->register_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
			       NBL_CHAN_MSG_RESTART_NETDEV_QUEUE,
			       nbl_serv_chan_restart_netdev_queue_resp, serv_mgt);
}

static void nbl_serv_remove_net_resource_mgt(void *priv)
{
	struct device *dev;
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	dev = NBL_COMMON_TO_DEV(common);

	if (net_resource_mgt) {
		del_timer_sync(&net_resource_mgt->serv_timer);
		nbl_common_release_task(&net_resource_mgt->rx_mode_async);
		nbl_common_release_task(&net_resource_mgt->net_stats_update);
		nbl_common_release_task(&net_resource_mgt->tx_timeout);
		nbl_free_filter(net_resource_mgt);
		devm_kfree(dev, net_resource_mgt);
		NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt) = NULL;
	}
}

static int nbl_serv_phy_init(struct nbl_serv_net_resource_mgt *net_resource_mgt)
{
	struct nbl_service_mgt *serv_mgt = net_resource_mgt->serv_mgt;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	u8 eth_id = NBL_COMMON_TO_ETH_ID(common);
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->get_phy_caps(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
			       eth_id, &net_resource_mgt->phy_caps);

	disp_ops->get_phy_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				eth_id, &net_resource_mgt->phy_state);

	return ret;
}

static int nbl_serv_setup_net_resource_mgt(void *priv, struct net_device *netdev)
{
	struct device *dev;
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	dev = NBL_COMMON_TO_DEV(common);
	net_resource_mgt = devm_kzalloc(dev, sizeof(struct nbl_serv_net_resource_mgt), GFP_KERNEL);
	if (!net_resource_mgt)
		return -ENOMEM;

	net_resource_mgt->netdev = netdev;
	net_resource_mgt->serv_mgt = serv_mgt;
	NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt) = net_resource_mgt;

	nbl_serv_phy_init(net_resource_mgt);
	nbl_serv_register_restore_netdev_queue(serv_mgt);
	timer_setup(&net_resource_mgt->serv_timer, nbl_serv_net_task_service_timer, 0);

	net_resource_mgt->serv_timer_period = HZ;
	nbl_common_alloc_task(&net_resource_mgt->rx_mode_async, nbl_serv_rx_mode_async_task);
	nbl_common_alloc_task(&net_resource_mgt->net_stats_update, nbl_serv_net_stats_update_task);
	nbl_common_alloc_task(&net_resource_mgt->tx_timeout, nbl_serv_handle_tx_timeout);

	INIT_LIST_HEAD(&net_resource_mgt->mac_filter_list);
	INIT_LIST_HEAD(&net_resource_mgt->indr_dev_priv_list);
	spin_lock_init(&net_resource_mgt->mac_vlan_list_lock);
	spin_lock_init(&net_resource_mgt->current_netdev_promisc_flags_lock);
	net_resource_mgt->get_stats_jiffies = jiffies;

	mod_timer(&net_resource_mgt->serv_timer,
		  round_jiffies(jiffies + net_resource_mgt->serv_timer_period));

	return 0;
}

static int nbl_serv_enable_adminq_irq(void *priv, u16 vector_id, bool enable_msix)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ret = disp_ops->enable_adminq_irq(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    vector_id, enable_msix);
	if (ret)
		return -EIO;

	return 0;
}

static u8 __iomem *nbl_serv_get_hw_addr(void *priv, size_t *size)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_hw_addr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), size);
}

static u64 nbl_serv_get_real_hw_addr(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_real_hw_addr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);
}

static u16 nbl_serv_get_function_id(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_function_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);
}

static void nbl_serv_get_real_bdf(void *priv, u16 vsi_id, u8 *bus, u8 *dev, u8 *function)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_real_bdf(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id,
				      bus, dev, function);
}

static int nbl_serv_get_devlink_info(struct devlink *devlink, struct devlink_info_req *req,
				     struct netlink_ext_ack *extack)
{
	struct nbl_devlink_priv *priv = devlink_priv(devlink);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv->priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	char firmware_version[NBL_DEVLINK_INFO_FRIMWARE_VERSION_LEN] = {0};
	int ret = 0;

	disp_ops->get_firmware_version(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				       firmware_version, sizeof(firmware_version));
	if (ret)
		return ret;

	ret = devlink_info_version_fixed_put(req, "FW Version:", firmware_version);
	if (ret)
		return ret;

	return ret;
}

/* Why do we need this?
 * Because the original function in kernel cannot handle when we set subvendor and subdevice
 * to be 0xFFFF, so write a correct one.
 */
bool nbl_serv_pldmfw_op_pci_match_record(struct pldmfw *context, struct pldmfw_record *record)
{
	struct pci_dev *pdev = to_pci_dev(context->dev);
	struct nbl_serv_pldm_pci_record_id id = {
		.vendor = PCI_ANY_ID,
		.device = PCI_ANY_ID,
		.subsystem_vendor = PCI_ANY_ID,
		.subsystem_device = PCI_ANY_ID,
	};
	struct pldmfw_desc_tlv *desc;
	bool ret;

	list_for_each_entry(desc, &record->descs, entry) {
		u16 value;
		u16 *ptr;

		switch (desc->type) {
		case PLDM_DESC_ID_PCI_VENDOR_ID:
			ptr = &id.vendor;
			break;
		case PLDM_DESC_ID_PCI_DEVICE_ID:
			ptr = &id.device;
			break;
		case PLDM_DESC_ID_PCI_SUBVENDOR_ID:
			ptr = &id.subsystem_vendor;
			break;
		case PLDM_DESC_ID_PCI_SUBDEV_ID:
			ptr = &id.subsystem_device;
			break;
		default:
			/* Skip unrelated TLVs */
			continue;
		}

		value = get_unaligned_le16(desc->data);
		/* A value of zero for one of the descriptors is sometimes
		 * used when the record should ignore this field when matching
		 * device. For example if the record applies to any subsystem
		 * device or vendor.
		 */
		if (value)
			*ptr = (int)value;
		else
			*ptr = PCI_ANY_ID;
	}

	if ((id.vendor == (u16)PCI_ANY_ID || id.vendor == pdev->vendor) &&
	    (id.device == (u16)PCI_ANY_ID || id.device == pdev->device) &&
	    (id.subsystem_vendor == (u16)PCI_ANY_ID ||
	     id.subsystem_vendor == pdev->subsystem_vendor) &&
	    (id.subsystem_device == (u16)PCI_ANY_ID ||
	     id.subsystem_device == pdev->subsystem_device))
		ret = true;
	else
		ret = false;

	return ret;
}

static int nbl_serv_send_package_data(struct pldmfw *context, const u8 *data, u16 length)
{
	struct nbl_serv_update_fw_priv *priv = container_of(context, struct nbl_serv_update_fw_priv,
							    context);
	struct nbl_service_mgt *serv_mgt = priv->serv_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	int ret = 0;

	nbl_info(common, NBL_DEBUG_DEVLINK, "Send package data");

	ret = disp_ops->flash_lock(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret)
		return ret;

	ret = disp_ops->flash_prepare(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret)
		disp_ops->flash_unlock(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));

	return 0;
}

static int nbl_serv_send_component_table(struct pldmfw *context, struct pldmfw_component *component,
					 u8 transfer_flags)
{
	struct nbl_serv_update_fw_priv *priv = container_of(context, struct nbl_serv_update_fw_priv,
							    context);
	struct nbl_service_mgt *serv_mgt = priv->serv_mgt;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	nbl_info(common, NBL_DEBUG_DEVLINK, "Send component table, id %d", component->identifier);

	return 0;
}

static int nbl_serv_flash_component(struct pldmfw *context, struct pldmfw_component *component)
{
	struct nbl_serv_update_fw_priv *priv = container_of(context, struct nbl_serv_update_fw_priv,
							    context);
	struct nbl_service_mgt *serv_mgt = priv->serv_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	u32 component_crc, calculated_crc;
	size_t data_len = component->component_size - NBL_DEVLINK_FLASH_COMPONENT_CRC_SIZE;
	int ret = 0;

	nbl_info(common, NBL_DEBUG_DEVLINK, "Flash component table, id %d", component->identifier);

	component_crc = *(u32 *)((u8 *)component->component_data + data_len);
	calculated_crc = crc32_le(~0, component->component_data, data_len) ^ ~0;
	if (component_crc != calculated_crc) {
		nbl_err(common, NBL_DEBUG_DEVLINK, "Flash component crc error");
		disp_ops->flash_unlock(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
		return -EFAULT;
	}

	ret = disp_ops->flash_image(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), component->identifier,
				    component->component_data, data_len);
	if (ret)
		disp_ops->flash_unlock(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));

	return ret;
}

static int nbl_serv_finalize_update(struct pldmfw *context)
{
	struct nbl_serv_update_fw_priv *priv = container_of(context, struct nbl_serv_update_fw_priv,
							    context);
	struct nbl_service_mgt *serv_mgt = priv->serv_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	int ret = 0;

	nbl_info(common, NBL_DEBUG_DEVLINK, "Flash activate");

	ret = disp_ops->flash_activate(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));

	disp_ops->flash_unlock(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	return ret;
}

static const struct pldmfw_ops nbl_update_fw_ops = {
	.match_record = nbl_serv_pldmfw_op_pci_match_record,
	.send_package_data = nbl_serv_send_package_data,
	.send_component_table = nbl_serv_send_component_table,
	.flash_component = nbl_serv_flash_component,
	.finalize_update = nbl_serv_finalize_update,
};

static int nbl_serv_update_firmware(struct nbl_service_mgt *serv_mgt, const struct firmware *fw,
				    struct netlink_ext_ack *extack)
{
	struct nbl_serv_update_fw_priv priv = {0};
	int ret = 0;

	priv.context.ops = &nbl_update_fw_ops;
	priv.context.dev = NBL_SERV_MGT_TO_DEV(serv_mgt);
	priv.extack = extack;
	priv.serv_mgt = serv_mgt;

	ret = pldmfw_flash_image(&priv.context, fw);

	return ret;
}

static int nbl_serv_update_devlink_flash(struct devlink *devlink,
					 struct devlink_flash_update_params *params,
					 struct netlink_ext_ack *extack)
{
	struct nbl_devlink_priv *priv = devlink_priv(devlink);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv->priv;
	int ret = 0;

	devlink_flash_update_status_notify(devlink, "Flash start", NULL, 0, 0);

	ret = nbl_serv_update_firmware(serv_mgt, params->fw, extack);

	if (ret)
		devlink_flash_update_status_notify(devlink, "Flash failed", NULL, 0, 0);
	else
		devlink_flash_update_status_notify(devlink,
						   "Flash finished, please reboot to take effect",
						   NULL, 0, 0);
	return ret;
}

static u32 nbl_serv_get_adminq_tx_buf_size(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_adminq_tx_buf_size(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static bool nbl_serv_check_fw_heartbeat(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->check_fw_heartbeat(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static bool nbl_serv_check_fw_reset(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->check_fw_reset(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static void nbl_serv_get_common_irq_num(void *priv, struct nbl_common_irq_num *irq_num)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	irq_num->mbx_irq_num = disp_ops->get_mbx_irq_num(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static void nbl_serv_get_ctrl_irq_num(void *priv, struct nbl_ctrl_irq_num *irq_num)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	irq_num->adminq_irq_num = disp_ops->get_adminq_irq_num(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	irq_num->abnormal_irq_num =
		disp_ops->get_abnormal_irq_num(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static u32 nbl_serv_get_chip_temperature(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_chip_temperature(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static u32 nbl_serv_get_chip_temperature_max(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_chip_temperature_max(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static u32 nbl_serv_get_chip_temperature_crit(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_chip_temperature_crit(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_get_module_temperature(void *priv, u8 eth_id, enum nbl_module_temp_type type)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_module_temperature(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), eth_id, type);
}

static int nbl_serv_get_port_attributes(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ret = disp_ops->get_port_attributes(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret)
		return -EIO;

	return 0;
}

static int nbl_serv_update_ring_num(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->update_ring_num(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_enable_port(void *priv, bool enable)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ret = disp_ops->enable_port(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), enable);
	if (ret)
		return -EIO;

	return 0;
}

static int nbl_serv_set_eth_mac_addr(void *priv, u8 *mac, u8 eth_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	if (NBL_COMMON_TO_VF_CAP(common))
		return 0;
	else
		return disp_ops->set_eth_mac_addr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						  mac, eth_id);
}

static void nbl_serv_adapt_desc_gother(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->adapt_desc_gother(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static void nbl_serv_process_flr(void *priv, u16 vfid)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->flr_clear_queues(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vfid);
	disp_ops->flr_clear_flows(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vfid);
	disp_ops->flr_clear_interrupt(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vfid);
	disp_ops->flr_clear_net(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vfid);
}

static void nbl_serv_recovery_abnormal(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->unmask_all_interrupts(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static void nbl_serv_keep_alive(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->keep_alive(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_register_vsi_info(void *priv, u16 vsi_index, u16 vsi_id,
				      u16 queue_offset, u16 queue_num)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ring_mgt->vsi_info[vsi_index].vsi_index = vsi_index;
	ring_mgt->vsi_info[vsi_index].vsi_id = vsi_id;
	ring_mgt->vsi_info[vsi_index].ring_offset = queue_offset;
	ring_mgt->vsi_info[vsi_index].ring_num = queue_num;
	if (disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  NBL_ITR_DYNAMIC))
		ring_mgt->vsi_info[vsi_index].itr_dynamic = true;

	disp_ops->register_vsi_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				    vsi_index, queue_offset, queue_num);

	return disp_ops->register_vsi2q(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					vsi_index, vsi_id, queue_offset, queue_num);
}

static int nbl_serv_st_open(struct inode *inode, struct file *filep)
{
	struct nbl_serv_st_mgt *p = container_of(inode->i_cdev, struct nbl_serv_st_mgt, cdev);

	filep->private_data = p;

	return 0;
}

static ssize_t nbl_serv_st_write(struct file *file, const char __user *ubuf,
				 size_t size, loff_t *ppos)
{
	return 0;
}

static ssize_t nbl_serv_st_read(struct file *file, char __user *ubuf, size_t size, loff_t *ppos)
{
	return 0;
}

static int nbl_serv_st_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static int nbl_serv_process_passthrough(struct nbl_service_mgt *serv_mgt,
					unsigned int cmd, unsigned long arg)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_passthrough_fw_cmd_param *param = NULL, *result = NULL;
	int ret = 0;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param)
		goto alloc_param_fail;

	result = kzalloc(sizeof(*result), GFP_KERNEL);
	if (!result)
		goto alloc_result_fail;

	ret = copy_from_user(param, (void *)arg, _IOC_SIZE(cmd));
	if (ret) {
		nbl_err(common, NBL_DEBUG_ST, "Bad access %d.\n", ret);
		return ret;
	}

	nbl_debug(common, NBL_DEBUG_ST, "Passthough opcode: %d\n", param->opcode);

	ret = disp_ops->passthrough_fw_cmd(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param, result);
	if (ret)
		goto passthrough_fail;

	ret = copy_to_user((void *)arg, result, _IOC_SIZE(cmd));

passthrough_fail:
	kfree(result);
alloc_result_fail:
	kfree(param);
alloc_param_fail:
	return ret;
}

static long nbl_serv_st_unlock_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct nbl_serv_st_mgt *st_mgt = file->private_data;
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)st_mgt->serv_mgt;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	int ret = 0;

	if (_IOC_TYPE(cmd) != IOCTL_TYPE) {
		nbl_err(common, NBL_DEBUG_ST, "cmd %u, bad magic 0x%x/0x%x.\n",
			cmd, _IOC_TYPE(cmd), IOCTL_TYPE);
		return -ENOTTY;
	}

	if (_IOC_DIR(cmd) & _IOC_READ)
		ret = !access_ok((void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		ret = !access_ok((void __user *)arg, _IOC_SIZE(cmd));
	if (ret) {
		nbl_err(common, NBL_DEBUG_ST, "Bad access.\n");
		return ret;
	}

	switch (cmd) {
	case IOCTL_PASSTHROUGH:
		ret = nbl_serv_process_passthrough(serv_mgt, cmd, arg);
		break;
	default:
		nbl_err(common, NBL_DEBUG_ST, "Unknown cmd %d.\n", cmd);
		return -EFAULT;
	}

	return ret;
}

static const struct file_operations st_ops = {
	.owner = THIS_MODULE,
	.open = nbl_serv_st_open,
	.write = nbl_serv_st_write,
	.read = nbl_serv_st_read,
	.unlocked_ioctl = nbl_serv_st_unlock_ioctl,
	.release = nbl_serv_st_release,
};

static int nbl_serv_alloc_subdev_id(struct nbl_software_tool_table *st_table)
{
	int subdev_id;

	subdev_id = find_first_zero_bit(st_table->devid, NBL_ST_MAX_DEVICE_NUM);
	if (subdev_id == NBL_ST_MAX_DEVICE_NUM)
		return -ENOSPC;
	set_bit(subdev_id, st_table->devid);

	return subdev_id;
}

static void nbl_serv_free_subdev_id(struct nbl_software_tool_table *st_table, int id)
{
	clear_bit(id, st_table->devid);
}

static int nbl_serv_setup_st(void *priv, void *st_table_param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_software_tool_table *st_table = (struct nbl_software_tool_table *)st_table_param;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_st_mgt *st_mgt = NBL_SERV_MGT_TO_ST_MGT(serv_mgt);
	struct device *test_device;
	char name[NBL_RESTOOL_NAME_LEN] = {0};
	dev_t devid;
	int id, subdev_id, ret = 0;

	id = NBL_COMMON_TO_BOARD_ID(common);

	subdev_id = nbl_serv_alloc_subdev_id(st_table);
	if (subdev_id < 0)
		goto alloc_subdev_id_fail;

	devid = MKDEV(st_table->major, subdev_id);

	if (!NBL_COMMON_TO_PCI_FUNC_ID(common))
		snprintf(name, sizeof(name), "/nblst/nblst%04x_conf%d",
			 NBL_COMMON_TO_PDEV(common)->device, id);
	else
		snprintf(name, sizeof(name), "/nblst/nblst%04x_conf%d.%d",
			 NBL_COMMON_TO_PDEV(common)->device, id, NBL_COMMON_TO_PCI_FUNC_ID(common));

	st_mgt = devm_kzalloc(NBL_COMMON_TO_DEV(common), sizeof(*st_mgt), GFP_KERNEL);
	if (!st_mgt)
		goto malloc_fail;

	st_mgt->serv_mgt = serv_mgt;

	st_mgt->major = MAJOR(devid);
	st_mgt->minor = MINOR(devid);
	st_mgt->devno = devid;
	st_mgt->subdev_id = subdev_id;

	cdev_init(&st_mgt->cdev, &st_ops);
	ret = cdev_add(&st_mgt->cdev, devid, 1);
	if (ret)
		goto cdev_add_fail;

	test_device = device_create(st_table->cls, NULL, st_mgt->devno, NULL, name);
	if (IS_ERR(test_device)) {
		ret = -EBUSY;
		goto device_create_fail;
	}

	NBL_SERV_MGT_TO_ST_MGT(serv_mgt) = st_mgt;
	return 0;

device_create_fail:
	cdev_del(&st_mgt->cdev);
cdev_add_fail:
	devm_kfree(NBL_COMMON_TO_DEV(common), st_mgt);
malloc_fail:
	nbl_serv_free_subdev_id(st_table, subdev_id);
alloc_subdev_id_fail:
	return ret;
}

static void nbl_serv_remove_st(void *priv, void *st_table_param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_software_tool_table *st_table = (struct nbl_software_tool_table *)st_table_param;
	struct nbl_serv_st_mgt *st_mgt = NBL_SERV_MGT_TO_ST_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	if (!st_mgt)
		return;

	device_destroy(st_table->cls, st_mgt->devno);
	cdev_del(&st_mgt->cdev);

	nbl_serv_free_subdev_id(st_table, st_mgt->subdev_id);

	NBL_SERV_MGT_TO_ST_MGT(serv_mgt) = NULL;
	devm_kfree(NBL_COMMON_TO_DEV(common), st_mgt);
}

static void nbl_serv_form_p4_name(struct nbl_common_info *common, int type, char *name, u16 len)
{
	char eth_num[NBL_P4_NAME_LEN] = {0};

	switch (NBL_COMMON_TO_ETH_MODE(common)) {
	case 1:
		snprintf(eth_num, sizeof(eth_num), "single");
		break;
	case 2:
		snprintf(eth_num, sizeof(eth_num), "dual");
		break;
	case 4:
		snprintf(eth_num, sizeof(eth_num), "quad");
		break;
	default:
		nbl_err(common, NBL_DEBUG_CUSTOMIZED_P4, "Unknown P4 type %d", type);
		return;
	}

	switch (type) {
	case NBL_P4_DEFAULT:
		/* No need to load default p4 file */
		break;
	default:
		nbl_err(common, NBL_DEBUG_CUSTOMIZED_P4, "Unknown P4 type %d", type);
	}
}

static int nbl_serv_load_p4(struct nbl_service_mgt *serv_mgt,
			    const struct firmware *fw, char *verify_code)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	const struct elf32_hdr *elf_hdr = (struct elf32_hdr *)fw->data;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct elf32_shdr *shdr;
	struct nbl_load_p4_param param;
	u8 *strtab, *name, *product_code = NULL;
	int i, ret = 0;

	if (memcmp(elf_hdr->e_ident, NBL_P4_ELF_IDENT, NBL_P4_ELF_IDENT_LEN)) {
		nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4, "Invalid ELF file");
		return -EINVAL;
	}

	memset(&param, 0, sizeof(param));

	shdr = (struct elf32_shdr *)((u8 *)elf_hdr + elf_hdr->e_shoff);
	strtab = (u8 *)elf_hdr + shdr[elf_hdr->e_shstrndx].sh_offset;

	for (i = 0; i < elf_hdr->e_shnum; i++)
		if (shdr[i].sh_type == SHT_NOTE) {
			name = strtab + shdr[i].sh_name;
			if (!strncmp(name, NBL_P4_PRODUCT_INFO_SECTION_NAME,
				     sizeof(NBL_P4_PRODUCT_INFO_SECTION_NAME)))
				product_code = (u8 *)elf_hdr + shdr[i].sh_offset;
		}

	if (!product_code) {
		nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4, "Product code not exist");
		return -EINVAL;
	}

	if (strncmp(product_code, verify_code, NBL_P4_VERIFY_CODE_LEN)) {
		nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4, "Invalid product code %32s",
			 product_code);
		return -EINVAL;
	}

	param.start = 1;
	ret = disp_ops->load_p4(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param);
	if (ret)
		return ret;

	for (i = 0; i < elf_hdr->e_shnum; i++)
		if (shdr[i].sh_type == SHT_PROGBITS && !(shdr[i].sh_flags & SHF_EXECINSTR)) {
			if (shdr[i].sh_size > NBL_P4_SECTION_LEN_MAX) {
				nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4, "Section oversize %d",
					 shdr[i].sh_size);
				return -EINVAL;
			}

			memset(&param, 0, sizeof(param));
			/* name is used for distinguish configuration, not used for now */
			strscpy(param.name, strtab + shdr[i].sh_name, sizeof(param.name));
			param.addr = shdr[i].sh_addr;
			param.size = shdr[i].sh_size;
			param.section_index = i;
			param.section_offset = 0;
			param.data = (u8 *)elf_hdr + shdr[i].sh_offset;

			ret = disp_ops->load_p4(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param);
			if (ret)
				return ret;
		}

	memset(&param, 0, sizeof(param));
	param.end = 1;
	ret = disp_ops->load_p4(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param);
	if (ret)
		return ret;

	return 0;
}

static __maybe_unused void nbl_serv_load_default_p4(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->load_p4_default(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_init_p4(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	const struct firmware *fw;
	char name[NBL_P4_NAME_LEN] = {0};
	char verify_code[NBL_P4_NAME_LEN] = {0};
	int type, ret = 0;

	type = disp_ops->get_p4_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), verify_code);
	if (type < 0 || type > NBL_P4_TYPE_MAX)
		return -ENOENT;

	if (type == NBL_P4_DEFAULT)
		goto out;

	nbl_serv_form_p4_name(common, type, name, sizeof(name));
	ret = firmware_request_nowarn(&fw, name, NBL_SERV_MGT_TO_DEV(serv_mgt));
	if (ret)
		goto out;

	ret = nbl_serv_load_p4(serv_mgt, fw, verify_code);

	release_firmware(fw);

out:
	if (type == NBL_P4_DEFAULT || ret) {
		nbl_info(common, NBL_DEBUG_CUSTOMIZED_P4, "Load P4 default");
		nbl_serv_load_default_p4(serv_mgt);
		disp_ops->set_p4_used(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), NBL_P4_DEFAULT);
	} else {
		nbl_info(common, NBL_DEBUG_CUSTOMIZED_P4, "Load P4 %d", type);
		disp_ops->set_p4_used(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), type);
	}

	/* We always return OK, because at the very least we would use default P4 */
	return 0;
}

static int nbl_serv_set_spoof_check_addr(void *priv, u8 *mac)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	return disp_ops->set_spoof_check_addr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					      NBL_COMMON_TO_VSI_ID(common), mac);
}

u16 nbl_serv_get_vf_base_vsi_id(void *priv, u16 func_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_vf_base_vsi_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), func_id);
}

static int nbl_serv_get_board_id(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_board_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_process_abnormal_event(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_abnormal_event_info abnomal_info;
	struct nbl_abnormal_details *detail;
	u16 local_queue_id;
	int type, i, ret = 0;

	memset(&abnomal_info, 0, sizeof(abnomal_info));

	ret = disp_ops->process_abnormal_event(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &abnomal_info);
	if (!ret)
		return ret;

	for (i = 0; i < NBL_ABNORMAL_EVENT_MAX; i++) {
		detail = &abnomal_info.details[i];

		if (!detail->abnormal)
			continue;

		type = nbl_serv_abnormal_event_to_queue(i);
		local_queue_id = disp_ops->get_local_queue_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							      detail->vsi_id, detail->qid);
		if (local_queue_id == U16_MAX)
			return 0;

		nbl_serv_restore_queue(serv_mgt, detail->vsi_id, local_queue_id, type, true);
	}

	return 0;
}

static struct nbl_service_ops serv_ops = {
	.init_chip = nbl_serv_init_chip,
	.destroy_chip = nbl_serv_destroy_chip,
	.init_p4 = nbl_serv_init_p4,

	.configure_msix_map = nbl_serv_configure_msix_map,
	.destroy_msix_map = nbl_serv_destroy_msix_map,
	.enable_mailbox_irq = nbl_serv_enable_mailbox_irq,
	.enable_abnormal_irq = nbl_serv_enable_abnormal_irq,
	.enable_adminq_irq = nbl_serv_enable_adminq_irq,
	.request_net_irq = nbl_serv_request_net_irq,
	.free_net_irq = nbl_serv_free_net_irq,
	.get_global_vector = nbl_serv_get_global_vector,
	.get_msix_entry_id = nbl_serv_get_msix_entry_id,
	.get_common_irq_num = nbl_serv_get_common_irq_num,
	.get_ctrl_irq_num = nbl_serv_get_ctrl_irq_num,
	.get_chip_temperature = nbl_serv_get_chip_temperature,
	.get_chip_temperature_max = nbl_serv_get_chip_temperature_max,
	.get_chip_temperature_crit = nbl_serv_get_chip_temperature_crit,
	.get_module_temperature = nbl_serv_get_module_temperature,
	.get_port_attributes = nbl_serv_get_port_attributes,
	.update_ring_num = nbl_serv_update_ring_num,
	.enable_port = nbl_serv_enable_port,
	.set_sfp_state = nbl_serv_set_sfp_state,

	.register_net = nbl_serv_register_net,
	.unregister_net = nbl_serv_unregister_net,
	.setup_txrx_queues = nbl_serv_setup_txrx_queues,
	.remove_txrx_queues = nbl_serv_remove_txrx_queues,
	.setup_q2vsi = nbl_serv_setup_q2vsi,
	.remove_q2vsi = nbl_serv_remove_q2vsi,
	.setup_rss = nbl_serv_setup_rss,
	.remove_rss = nbl_serv_remove_rss,
	.register_vsi_info = nbl_serv_register_vsi_info,

	.alloc_rings = nbl_serv_alloc_rings,
	.free_rings = nbl_serv_free_rings,
	.enable_napis = nbl_serv_enable_napis,
	.disable_napis = nbl_serv_disable_napis,
	.set_mask_en = nbl_serv_set_mask_en,
	.start_net_flow = nbl_serv_start_net_flow,
	.stop_net_flow = nbl_serv_stop_net_flow,
	.set_lldp_flow = nbl_serv_set_lldp_flow,
	.remove_lldp_flow = nbl_serv_remove_lldp_flow,
	.start_mgt_flow = nbl_serv_start_mgt_flow,
	.stop_mgt_flow = nbl_serv_stop_mgt_flow,
	.get_tx_headroom = nbl_serv_get_tx_headroom,
	.get_product_flex_cap	= nbl_serv_get_product_flex_cap,
	.get_product_fix_cap	= nbl_serv_get_product_fix_cap,
	.set_spoof_check_addr = nbl_serv_set_spoof_check_addr,

	.vsi_open = nbl_serv_vsi_open,
	.vsi_stop = nbl_serv_vsi_stop,
	.switch_traffic_default_dest = nbl_serv_switch_traffic_default_dest,
	.get_user_queue_info = nbl_serv_get_user_queue_info,

	/* For netdev ops */
	.netdev_open = nbl_serv_netdev_open,
	.netdev_stop = nbl_serv_netdev_stop,
	.change_mtu = nbl_serv_change_mtu,
	.set_mac = nbl_serv_set_mac,
	.rx_add_vid = nbl_serv_rx_add_vid,
	.rx_kill_vid = nbl_serv_rx_kill_vid,
	.get_stats64 = nbl_serv_get_stats64,
	.set_rx_mode = nbl_serv_set_rx_mode,
	.change_rx_flags = nbl_serv_change_rx_flags,
	.features_check = nbl_serv_features_check,
	.get_phys_port_name = nbl_serv_get_phys_port_name,
	.get_port_parent_id = nbl_serv_get_port_parent_id,
	.tx_timeout = nbl_serv_tx_timeout,

	.get_vsi_id = nbl_serv_get_vsi_id,
	.get_eth_id = nbl_serv_get_eth_id,
	.setup_net_resource_mgt = nbl_serv_setup_net_resource_mgt,
	.remove_net_resource_mgt = nbl_serv_remove_net_resource_mgt,
	.enable_lag_protocol = nbl_serv_enable_lag_protocol,
	.get_hw_addr = nbl_serv_get_hw_addr,
	.get_real_hw_addr = nbl_serv_get_real_hw_addr,
	.get_function_id = nbl_serv_get_function_id,
	.get_real_bdf = nbl_serv_get_real_bdf,
	.set_eth_mac_addr = nbl_serv_set_eth_mac_addr,
	.process_abnormal_event = nbl_serv_process_abnormal_event,
	.adapt_desc_gother = nbl_serv_adapt_desc_gother,
	.process_flr = nbl_serv_process_flr,
	.get_board_id = nbl_serv_get_board_id,
	.recovery_abnormal = nbl_serv_recovery_abnormal,
	.keep_alive = nbl_serv_keep_alive,

	.get_devlink_info = nbl_serv_get_devlink_info,
	.update_devlink_flash = nbl_serv_update_devlink_flash,
	.get_adminq_tx_buf_size = nbl_serv_get_adminq_tx_buf_size,

	.check_fw_heartbeat = nbl_serv_check_fw_heartbeat,
	.check_fw_reset = nbl_serv_check_fw_reset,
	.set_netdev_carrier_state = nbl_serv_set_netdev_carrier_state,

	.setup_st = nbl_serv_setup_st,
	.remove_st = nbl_serv_remove_st,
	.get_vf_base_vsi_id = nbl_serv_get_vf_base_vsi_id,
};

/* Structure starts here, adding an op should not modify anything below */
static int nbl_serv_setup_serv_mgt(struct nbl_common_info *common,
				   struct nbl_service_mgt **serv_mgt)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	*serv_mgt = devm_kzalloc(dev, sizeof(struct nbl_service_mgt), GFP_KERNEL);
	if (!*serv_mgt)
		return -ENOMEM;

	NBL_SERV_MGT_TO_COMMON(*serv_mgt) = common;
	nbl_serv_setup_flow_mgt(NBL_SERV_MGT_TO_FLOW_MGT(*serv_mgt));

	set_bit(NBL_FLAG_MINI_DRIVER, (*serv_mgt)->flags);

	return 0;
}

static void nbl_serv_remove_serv_mgt(struct nbl_common_info *common,
				     struct nbl_service_mgt **serv_mgt)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	devm_kfree(dev, *serv_mgt);
	*serv_mgt = NULL;
}

static void nbl_serv_remove_ops(struct device *dev, struct nbl_service_ops_tbl **serv_ops_tbl)
{
	devm_kfree(dev, *serv_ops_tbl);
	*serv_ops_tbl = NULL;
}

static int nbl_serv_setup_ops(struct device *dev, struct nbl_service_ops_tbl **serv_ops_tbl,
			      struct nbl_service_mgt *serv_mgt)
{
	*serv_ops_tbl = devm_kzalloc(dev, sizeof(struct nbl_service_ops_tbl), GFP_KERNEL);
	if (!*serv_ops_tbl)
		return -ENOMEM;

	NBL_SERV_OPS_TBL_TO_OPS(*serv_ops_tbl) = &serv_ops;
	nbl_serv_setup_ethtool_ops(&serv_ops);
	NBL_SERV_OPS_TBL_TO_PRIV(*serv_ops_tbl) = serv_mgt;

	return 0;
}

int nbl_serv_init(void *p, struct nbl_init_param *param)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_service_mgt **serv_mgt;
	struct nbl_service_ops_tbl **serv_ops_tbl;
	struct nbl_dispatch_ops_tbl *disp_ops_tbl;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	int ret = 0;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	serv_mgt = (struct nbl_service_mgt **)&NBL_ADAPTER_TO_SERV_MGT(adapter);
	serv_ops_tbl = &NBL_ADAPTER_TO_SERV_OPS_TBL(adapter);
	disp_ops_tbl = NBL_ADAPTER_TO_DISP_OPS_TBL(adapter);
	chan_ops_tbl = NBL_ADAPTER_TO_CHAN_OPS_TBL(adapter);
	disp_ops = disp_ops_tbl->ops;

	ret = nbl_serv_setup_serv_mgt(common, serv_mgt);
	if (ret)
		goto setup_mgt_fail;

	ret = nbl_serv_setup_ops(dev, serv_ops_tbl, *serv_mgt);
	if (ret)
		goto setup_ops_fail;

	NBL_SERV_MGT_TO_DISP_OPS_TBL(*serv_mgt) = disp_ops_tbl;
	NBL_SERV_MGT_TO_CHAN_OPS_TBL(*serv_mgt) = chan_ops_tbl;
	disp_ops->get_resource_pt_ops(disp_ops_tbl->priv, &(*serv_ops_tbl)->pt_ops);

	return 0;

setup_ops_fail:
	nbl_serv_remove_serv_mgt(common, serv_mgt);
setup_mgt_fail:
	return ret;
}

void nbl_serv_remove(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_service_mgt **serv_mgt;
	struct nbl_service_ops_tbl **serv_ops_tbl;

	if (!adapter)
		return;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	serv_mgt = (struct nbl_service_mgt **)&NBL_ADAPTER_TO_SERV_MGT(adapter);
	serv_ops_tbl = &NBL_ADAPTER_TO_SERV_OPS_TBL(adapter);

	nbl_serv_remove_ops(dev, serv_ops_tbl);
	nbl_serv_remove_serv_mgt(common, serv_mgt);
}
