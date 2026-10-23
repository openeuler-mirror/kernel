// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */
#include "nbl_ethtool.h"
#include "nbl_ktls.h"
#include "nbl_ipsec.h"
#include "nbl_macsec.h"
#include "nbl_p4_version.h"
#include "nbl_tc.h"
#include <crypto/hash.h>

static void nbl_serv_set_link_state(void *priv, struct net_device *netdev);
static int nbl_serv_update_default_vlan(struct nbl_service_mgt *serv_mgt, u16 vid);

static void nbl_serv_set_queue_param(struct nbl_serv_ring *ring, u16 desc_num,
				     struct nbl_txrx_queue_param *param, u16 vsi_id,
				     u16 global_vector_id, u16 half_offload_en)
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
	param->half_offload_en = half_offload_en;
}

static int nbl_serv_setup_queues(struct nbl_service_mgt *serv_mgt,
				 struct nbl_serv_ring_vsi_info *vsi_info,
				 u16 half_offload_en)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_txrx_queue_param param = {0};
	struct nbl_serv_ring *ring;
	struct nbl_serv_vector *vector;
	u16 start = vsi_info->ring_offset, end = vsi_info->ring_offset + vsi_info->ring_num;
	int vector_offset = 0;
	int i, ret = 0;
	bool interleave_seg_disable;
	struct nbl_ch_prm_setup_queue setup_q_prm;

	interleave_seg_disable = test_bit(NBL_FLAG_INTERLEAVE_SEG_DISABLE, &serv_mgt->flags);

	if (vsi_info->vsi_index == NBL_VSI_XDP)
		vector_offset = ring_mgt->xdp_ring_offset;

	for (i = start; i < end; i++) {
		vector = &ring_mgt->vectors[i - vector_offset];
		ring = &ring_mgt->rx_rings[i];
		nbl_serv_set_queue_param(ring, ring_mgt->rx_desc_num, &param,
					 vsi_info->vsi_id, vector->global_vector_id,
					 half_offload_en);
		memcpy(&setup_q_prm.param, &param, sizeof(param));
		setup_q_prm.is_tx = false;
		setup_q_prm.interleave_seg_disable = false;
		ret = disp_ops->setup_queue(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &setup_q_prm);
		if (ret)
			return ret;
	}

	for (i = start; i < end; i++) {
		vector = &ring_mgt->vectors[i - vector_offset];
		ring = &ring_mgt->tx_rings[i];
		nbl_serv_set_queue_param(ring, ring_mgt->tx_desc_num, &param,
					 vsi_info->vsi_id, vector->global_vector_id,
					 half_offload_en);
		memcpy(&setup_q_prm.param, &param, sizeof(param));
		setup_q_prm.is_tx = true;
		setup_q_prm.interleave_seg_disable = interleave_seg_disable;
		ret = disp_ops->setup_queue(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &setup_q_prm);
		if (ret)
			return ret;
	}

	return 0;
}

static void nbl_serv_flush_rx_queues(struct nbl_service_mgt *serv_mgt, u16 ring_offset,
				     u16 ring_num)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int i;

	for (i = ring_offset; i < ring_offset + ring_num; i++)
		disp_ops->kick_rx_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), i);
}

static int nbl_serv_setup_rings(struct nbl_service_mgt *serv_mgt, struct net_device *netdev,
				struct nbl_serv_ring_vsi_info *vsi_info, bool use_napi)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	u16 start = vsi_info->ring_offset, end = vsi_info->ring_offset + vsi_info->ring_num;
	int i, ret = 0;
	bool interleave_seg_disable;
	bool rxq_large_buf;
	struct nbl_tx_ring_start_param tx_ring_prm;
	struct nbl_rx_ring_start_param rx_ring_prm;

	interleave_seg_disable = test_bit(NBL_FLAG_INTERLEAVE_SEG_DISABLE, &serv_mgt->flags);
	rxq_large_buf = test_bit(NBL_FLAG_RXQ_LARGE_BUFF, &serv_mgt->flags);
	tx_ring_prm.interleave_seg_disable = interleave_seg_disable;
	tx_ring_prm.queue_size = ring_mgt->tx_desc_num;
	for (i = start; i < end; i++) {
		tx_ring_prm.ring_index = i;
		ring_mgt->tx_rings[i].dma =
			disp_ops->start_tx_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &tx_ring_prm);
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

	rx_ring_prm.rxq_large_buf = rxq_large_buf;
	rx_ring_prm.queue_size = ring_mgt->rx_desc_num;
	rx_ring_prm.use_napi = use_napi;
	for (i = start; i < end; i++) {
		rx_ring_prm.ring_index = i;
		ring_mgt->rx_rings[i].dma =
			disp_ops->start_rx_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &rx_ring_prm);
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

static void nbl_serv_stop_rings(struct nbl_service_mgt *serv_mgt,
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

static int nbl_serv_register_xdp_rxq(struct nbl_service_mgt *serv_mgt,
				     struct nbl_serv_ring_mgt *ring_mgt)
{
	u16 ring_num;
	int i, j;
	int ret;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_serv_ring_vsi_info *vsi_info;

	if (ring_mgt->xdp_ring_offset == ring_mgt->tx_ring_num)
		return 0;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	ring_num = vsi_info->ring_num;
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	for (i = 0; i < ring_num; i++) {
		ret = disp_ops->register_xdp_rxq(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), i);
		if (ret)
			goto register_xdp_err;
	}

	return 0;
register_xdp_err:
	for (j = 0; j < i; j++)
		disp_ops->unregister_xdp_rxq(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), j);

	return -1;
}

static void nbl_serv_unregister_xdp_rxq(struct nbl_service_mgt *serv_mgt,
					struct nbl_serv_ring_mgt *ring_mgt)
{
	u16 ring_num;
	int i;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_serv_ring_vsi_info *vsi_info;

	if (ring_mgt->xdp_ring_offset == ring_mgt->tx_ring_num)
		return;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	ring_num = vsi_info->ring_num;
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	for (i = 0; i < ring_num; i++)
		disp_ops->unregister_xdp_rxq(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), i);
}

static int nbl_serv_set_vectors(struct nbl_service_mgt *serv_mgt,
				struct net_device *netdev, struct device *dev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_resource_pt_ops *pt_ops = NBL_ADAPTER_TO_RES_PT_OPS(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int i;
	u16 ring_num = ring_mgt->xdp_ring_offset;

	ring_mgt->vectors = devm_kcalloc(dev, ring_num, sizeof(*ring_mgt->vectors), GFP_KERNEL);
	if (!ring_mgt->vectors)
		return -ENOMEM;

	for (i = 0; i < ring_num; i++) {
		ring_mgt->vectors[i].nbl_napi =
			disp_ops->get_vector_napi(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), i);
		netif_napi_add(netdev, &ring_mgt->vectors[i].nbl_napi->napi, pt_ops->napi_poll);
		ring_mgt->vectors[i].netdev = netdev;
		cpumask_clear(&ring_mgt->vectors[i].cpumask);
	}

	return 0;
}

static void nbl_serv_remove_vectors(struct nbl_serv_ring_mgt *ring_mgt, struct device *dev)
{
	int i;
	u16 ring_num = ring_mgt->xdp_ring_offset;

	for (i = 0; i < ring_num; i++)
		netif_napi_del(&ring_mgt->vectors[i].nbl_napi->napi);

	devm_kfree(dev, ring_mgt->vectors);
	ring_mgt->vectors = NULL;
}

static void nbl_serv_check_flow_table_spec(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_ch_prm_flow_table_spec spec_prm;
	int ret;

	if (!flow_mgt->force_promisc)
		return;

	spec_prm.vlan_list_cnt = flow_mgt->vlan_list_cnt;
	spec_prm.unicast_mac_cnt = flow_mgt->unicast_mac_cnt + 1;
	spec_prm.multi_mac_cnt = flow_mgt->multi_mac_cnt;
	ret = disp_ops->check_flow_table_spec(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &spec_prm);

	if (!ret) {
		flow_mgt->force_promisc = 0;
		flow_mgt->pending_async_work = 1;
	}
}

static bool nbl_serv_check_need_flow_rule(u8 *mac, u16 promisc)
{
	if (promisc & (BIT(NBL_USER_FLOW) | BIT(NBL_MIRROR)))
		return false;

	if (!is_multicast_ether_addr(mac) && (promisc & BIT(NBL_PROMISC)))
		return false;

	if (is_multicast_ether_addr(mac) && (promisc & BIT(NBL_ALLMULTI)))
		return false;

	return true;
}

static struct nbl_serv_vlan_node *nbl_serv_alloc_vlan_node(void)
{
	struct nbl_serv_vlan_node *vlan_node = NULL;

	vlan_node = kzalloc(sizeof(*vlan_node), GFP_ATOMIC);
	if (!vlan_node)
		return NULL;

	INIT_LIST_HEAD(&vlan_node->node);
	vlan_node->ref_cnt = 1;
	vlan_node->primary_mac_effective = 0;
	vlan_node->sub_mac_effective = 0;

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
	submac_node->effective = 0;

	return submac_node;
}

static void nbl_serv_free_submac_node(struct nbl_serv_submac_node *submac_node)
{
	kfree(submac_node);
}

static int nbl_serv_update_submac_node_effective(struct nbl_service_mgt *serv_mgt,
						 struct nbl_serv_submac_node *submac_node,
						 bool effective,
						 u16 vsi)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct net_device *dev = net_resource_mgt->netdev;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_serv_vlan_node *vlan_node;
	bool force_promisc = 0;
	int ret = 0;

	if (submac_node->effective == effective)
		return 0;

	list_for_each_entry(vlan_node, &flow_mgt->vlan_list, node) {
		if (!vlan_node->sub_mac_effective)
			continue;

		if (effective) {
			ret = disp_ops->add_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						    submac_node->mac, vlan_node->vid, vsi);
			if (ret)
				goto del_macvlan_node;
		} else {
			disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					      submac_node->mac, vlan_node->vid, vsi);
		}
	}
	submac_node->effective = effective;
	if (effective)
		flow_mgt->active_submac_list++;
	else
		flow_mgt->active_submac_list--;

	return 0;

del_macvlan_node:
	list_for_each_entry(vlan_node, &flow_mgt->vlan_list, node) {
		if (vlan_node->sub_mac_effective)
			disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					      submac_node->mac, vlan_node->vid, vsi);
	}

	if (ret) {
		force_promisc = 1;
		if (flow_mgt->force_promisc ^ force_promisc) {
			flow_mgt->force_promisc = force_promisc;
			flow_mgt->pending_async_work = 1;
			netdev_info(dev, "Reached MAC filter limit, forcing promisc/allmuti moden");
		}
	}

	return 0;
}

static int nbl_serv_update_vlan_node_effective(struct nbl_service_mgt *serv_mgt,
					       struct nbl_serv_vlan_node *vlan_node,
					       bool effective,
					       u16 vsi)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct net_device *dev = net_resource_mgt->netdev;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_serv_submac_node *submac_node;
	bool force_promisc = 0;
	int ret = 0, i = 0;

	if (vlan_node->primary_mac_effective == effective &&
	    vlan_node->sub_mac_effective == effective)
		return 0;

	if (effective && !vlan_node->primary_mac_effective) {
		ret = disp_ops->add_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    flow_mgt->mac, vlan_node->vid, vsi);
		if (ret)
			goto check_ret;
	} else if (!effective && vlan_node->primary_mac_effective) {
		disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				      flow_mgt->mac, vlan_node->vid, vsi);
	}

	vlan_node->primary_mac_effective = effective;

	for (i = 0; i < NBL_SUBMAC_MAX; i++)
		list_for_each_entry(submac_node, &flow_mgt->submac_list[i], node) {
			if (!submac_node->effective)
				continue;

			if (effective && !vlan_node->sub_mac_effective) {
				ret = disp_ops->add_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							    submac_node->mac, vlan_node->vid, vsi);
				if (ret)
					goto del_macvlan_node;
			} else if (!effective && vlan_node->sub_mac_effective) {
				disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						      submac_node->mac, vlan_node->vid, vsi);
			}
		}

	vlan_node->sub_mac_effective = effective;

	return 0;

del_macvlan_node:
	for (i = 0; i < NBL_SUBMAC_MAX; i++)
		list_for_each_entry(submac_node, &flow_mgt->submac_list[i], node) {
			if (submac_node->effective)
				disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						      submac_node->mac, vlan_node->vid, vsi);
		}
check_ret:
	if (ret) {
		force_promisc = 1;
		if (flow_mgt->force_promisc ^ force_promisc) {
			flow_mgt->force_promisc = force_promisc;
			flow_mgt->pending_async_work = 1;
			netdev_info(dev, "Reached VLAN filter limit, forcing promisc/allmuti moden");
		}
	}

	if (vlan_node->primary_mac_effective == effective)
		return 0;

	if (!NBL_COMMON_TO_VF_CAP(NBL_SERV_MGT_TO_COMMON(serv_mgt)))
		return 0;

	return ret;
}

static void nbl_serv_del_submac_node(struct nbl_service_mgt *serv_mgt, u8 *mac, u16 vsi)
{
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_serv_submac_node *submac_node, *submac_node_safe;
	struct list_head *submac_head;

	if (is_multicast_ether_addr(mac))
		submac_head = &flow_mgt->submac_list[NBL_SUBMAC_MULTI];
	else
		submac_head = &flow_mgt->submac_list[NBL_SUBMAC_UNICAST];

	list_for_each_entry_safe(submac_node, submac_node_safe, submac_head, node)
		if (ether_addr_equal(submac_node->mac, mac)) {
			if (submac_node->effective)
				nbl_serv_update_submac_node_effective(serv_mgt,
								      submac_node, 0, vsi);
			list_del(&submac_node->node);
			flow_mgt->submac_list_cnt--;
			if (is_multicast_ether_addr(submac_node->mac))
				flow_mgt->multi_mac_cnt--;
			else
				flow_mgt->unicast_mac_cnt--;
			nbl_serv_free_submac_node(submac_node);
			break;
		}
}

static int nbl_serv_add_submac_node(struct nbl_service_mgt *serv_mgt, u8 *mac, u16 vsi, u16 promisc)
{
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_serv_submac_node *submac_node;
	struct list_head *submac_head;

	if (is_multicast_ether_addr(mac))
		submac_head = &flow_mgt->submac_list[NBL_SUBMAC_MULTI];
	else
		submac_head = &flow_mgt->submac_list[NBL_SUBMAC_UNICAST];

	list_for_each_entry(submac_node, submac_head, node) {
		if (ether_addr_equal(submac_node->mac, mac))
			return 0;
	}

	submac_node = nbl_serv_alloc_submac_node();
	if (!submac_node)
		return -ENOMEM;

	submac_node->effective = 0;
	ether_addr_copy(submac_node->mac, mac);
	if (nbl_serv_check_need_flow_rule(mac, promisc) &&
	    (flow_mgt->trusted_en || flow_mgt->active_submac_list < NBL_NO_TRUST_MAX_MAC)) {
		nbl_serv_update_submac_node_effective(serv_mgt, submac_node, 1, vsi);
	}

	list_add(&submac_node->node, submac_head);
	flow_mgt->submac_list_cnt++;
	if (is_multicast_ether_addr(mac))
		flow_mgt->multi_mac_cnt++;
	else
		flow_mgt->unicast_mac_cnt++;

	return 0;
}

static void nbl_serv_update_mcast_submac(struct nbl_service_mgt *serv_mgt, bool multi_effective,
					 bool unicast_effective, u16 vsi)
{
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_serv_submac_node *submac_node;

	list_for_each_entry(submac_node, &flow_mgt->submac_list[NBL_SUBMAC_MULTI], node)
		nbl_serv_update_submac_node_effective(serv_mgt, submac_node,
						      multi_effective, vsi);

	list_for_each_entry(submac_node, &flow_mgt->submac_list[NBL_SUBMAC_UNICAST], node)
		nbl_serv_update_submac_node_effective(serv_mgt, submac_node,
						      unicast_effective, vsi);
}

static void nbl_serv_update_promisc_vlan(struct nbl_service_mgt *serv_mgt, bool effective, u16 vsi)
{
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_serv_vlan_node *vlan_node;

	list_for_each_entry(vlan_node, &flow_mgt->vlan_list, node)
		nbl_serv_update_vlan_node_effective(serv_mgt, vlan_node, effective, vsi);
}

static void nbl_serv_del_all_vlans(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_vlan_node *vlan_node, *vlan_node_safe;

	rtnl_lock();
	list_for_each_entry_safe(vlan_node, vlan_node_safe, &flow_mgt->vlan_list, node) {
		if (vlan_node->primary_mac_effective)
			disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
					      vlan_node->vid, NBL_COMMON_TO_VSI_ID(common));

		list_del(&vlan_node->node);
		nbl_serv_free_vlan_node(vlan_node);
	}
	rtnl_unlock();
}

static void nbl_serv_del_all_submacs(struct nbl_service_mgt *serv_mgt, u16 vsi)
{
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_serv_submac_node *submac_node, *submac_node_safe;
	int i;

	rtnl_lock();
	for (i = 0; i < NBL_SUBMAC_MAX; i++)
		list_for_each_entry_safe(submac_node, submac_node_safe,
					 &flow_mgt->submac_list[i], node) {
			nbl_serv_update_submac_node_effective(serv_mgt, submac_node, 0, vsi);
			list_del(&submac_node->node);
			flow_mgt->submac_list_cnt--;
			if (is_multicast_ether_addr(submac_node->mac))
				flow_mgt->multi_mac_cnt--;
			else
				flow_mgt->unicast_mac_cnt--;
			nbl_serv_free_submac_node(submac_node);
		}
	rtnl_unlock();
}

static int nbl_serv_validate_tc_config(struct tc_mqprio_qopt_offload *mqprio_qopt,
				       struct nbl_common_info *common, u16 num_active_queues)
{
	u64 tx_rate = 0;
	int i, num_qps = 0;

	if (mqprio_qopt->qopt.num_tc > NBL_MAX_QUEUE_TC_NUM || mqprio_qopt->qopt.num_tc < 1) {
		nbl_err(common, NBL_DEBUG_QUEUE, "Invalid num_tc %u", mqprio_qopt->qopt.num_tc);
		return -EINVAL;
	}

	for (i = 0; i < mqprio_qopt->qopt.num_tc; i++) {
		if (!mqprio_qopt->qopt.count[i] || mqprio_qopt->qopt.offset[i] != num_qps) {
			nbl_err(common, NBL_DEBUG_QUEUE, "Invalid offset%u, num_qps:%u for tc %d",
				mqprio_qopt->qopt.offset[i], num_qps, i);
			return -EINVAL;
		}

		if (mqprio_qopt->min_rate[i]) {
			nbl_err(common, NBL_DEBUG_QUEUE,
				"Invalid min tx rate (greater than 0) specified for TC %d", i);
			return -EINVAL;
		}

		/* kernel unit is Bps, convert to Mbps */
		tx_rate = div_u64(mqprio_qopt->max_rate[i], NBL_TC_MBPS_DIVSIOR);

		if (mqprio_qopt->max_rate[i] && tx_rate < NBL_TC_WEIGHT_GRAVITY) {
			nbl_err(common, NBL_DEBUG_QUEUE,
				"Invalid max tx rate for TC %d, minimum %d Mbps",
				i, NBL_TC_WEIGHT_GRAVITY);
			return -EINVAL;
		}

		if (tx_rate % NBL_TC_WEIGHT_GRAVITY != 0) {
			nbl_err(common, NBL_DEBUG_QUEUE,
				"Invalid max tx rate for TC %d, not divisible by %d",
				i, NBL_TC_MBPS_DIVSIOR);
			return -EINVAL;
		}

		num_qps += mqprio_qopt->qopt.count[i];
	}

	if (num_qps > num_active_queues) {
		nbl_err(common, NBL_DEBUG_QUEUE, "Cannot support requested number of queues");
		return -EINVAL;
	}

	return 0;
}

static int nbl_serv_setup_tc_mqprio(struct net_device *netdev, void *type_data)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(priv);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_tc_mgt *tc_mgt = NBL_SERV_MGT_TO_TC_MGT(serv_mgt);
	struct tc_mqprio_qopt_offload *mqprio_qopt = type_data;
	struct nbl_tc_qidsc_param param;
	u8 num_tc = mqprio_qopt->qopt.num_tc, total_qps = 0;
	struct nbl_serv_ring_vsi_info *vsi_info;
	int i, ret = 0;

	if (!netif_device_present(netdev))
		return -ENODEV;

	memset(&param, 0, sizeof(param));

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	param.vsi_id = vsi_info->vsi_id;

	if (!mqprio_qopt->qopt.hw) {
		/*hw 1 to hw 0*/
		if (tc_mgt->state == NBL_TC_RUNNING) {
			/*reset the tc configuration*/
			netdev_reset_tc(netdev);
			netif_tx_stop_all_queues(netdev);
			netif_carrier_off(netdev);
			netif_tx_disable(netdev);

			nbl_serv_vsi_stop(serv_mgt, NBL_VSI_DATA);

			param.origin_qps = tc_mgt->total_qps;
			disp_ops->cfg_qdisc_mqprio(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param);

			total_qps = tc_mgt->orig_num_active_queues;
			tc_mgt->num_tc = 0;
			tc_mgt->state = NBL_TC_INVALID;

			goto exit;
		} else {
			return 0;
		}
	}

	if (mqprio_qopt->mode != TC_MQPRIO_MODE_CHANNEL)
		return -EOPNOTSUPP;

	if (tc_mgt->state != NBL_TC_INVALID) {
		netdev_err(netdev, "TC configuration already exists");
		return -EINVAL;
	}

	ret = nbl_serv_validate_tc_config(mqprio_qopt, common, vsi_info->ring_num);
	if (ret) {
		netdev_err(netdev, "TC config invalid");
		return ret;
	}

	if (tc_mgt->num_tc == num_tc)
		return 0;

	if (num_tc > NBL_MAX_TC_NUM) {
		netdev_err(netdev, "num_tc max to 8 but set %d\n", num_tc);
		return -EINVAL;
	}

	for (i = 0; i < num_tc; i++) {
		total_qps += mqprio_qopt->qopt.count[i];
		param.info[i].count = mqprio_qopt->qopt.count[i];
		param.info[i].offset = mqprio_qopt->qopt.offset[i];
		param.info[i].max_tx_rate = div_u64(mqprio_qopt->max_rate[i], NBL_TC_MBPS_DIVSIOR);
	}

	tc_mgt->num_tc = num_tc;
	tc_mgt->orig_num_active_queues = vsi_info->active_ring_num;

	netif_tx_stop_all_queues(netdev);
	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	nbl_serv_vsi_stop(serv_mgt, NBL_VSI_DATA);

	param.num_tc = num_tc;
	param.enable = true;
	param.origin_qps = tc_mgt->orig_num_active_queues;
	param.gravity = NBL_TC_WEIGHT_GRAVITY;
	ret = disp_ops->cfg_qdisc_mqprio(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param);
	if (ret) {
		netdev_err(netdev, "Fail to cfg qdisc mqprio");
		tc_mgt->num_tc = 0;
		goto exit;
	}

	netdev_reset_tc(netdev);
	/* Report the tc mapping up the stack */
	netdev_set_num_tc(netdev, num_tc);
	for (i = 0; i < num_tc; i++)
		netdev_set_tc_queue(netdev, i, mqprio_qopt->qopt.count[i],
				    mqprio_qopt->qopt.offset[i]);

	tc_mgt->state = NBL_TC_RUNNING;
exit:
	/* If the device are unregistering, we cannot set queue nums or start them,
	 * otherwise we will hold the refcnt forever and block the unregistering process.
	 *
	 * Note: ndo_stop will not help, cause ndo_stop(in dev_close_many) execs
	 * before ndo_setup_tc(in dev_shutdown) when unregistering
	 */
	if (total_qps && NETREG_REGISTERED == netdev->reg_state &&
	    !test_bit(NBL_DOWN, adapter->state)) {
		netif_set_real_num_rx_queues(netdev, total_qps);
		netif_set_real_num_tx_queues(netdev, total_qps);

		nbl_serv_vsi_open(serv_mgt, netdev, NBL_VSI_DATA, total_qps, 1);

		netif_tx_start_all_queues(netdev);
		nbl_serv_set_link_state(serv_mgt, netdev);
	}

	tc_mgt->total_qps = total_qps;
	return ret;
}

static void nbl_serv_reset_tc_mqprio(struct net_device *dev)
{
	struct tc_mqprio_qopt_offload mqprio_qopt;

	memset(&mqprio_qopt, 0, sizeof(mqprio_qopt));
	nbl_serv_setup_tc_mqprio(dev, &mqprio_qopt);
}

static void nbl_serv_set_sfp_state(void *priv, u8 eth_id,
				   bool open, bool is_force)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_set_sfp_state sfp_prm = {0};
	int ret = 0;

	if (test_bit(NBL_FLAG_LINK_DOWN_ON_CLOSE, &serv_mgt->flags) || is_force) {
		sfp_prm.eth_id = eth_id;
		if (open) {
			sfp_prm.state = NBL_SFP_MODULE_ON;
			ret = disp_ops->set_sfp_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						      &sfp_prm);
			nbl_info(common, NBL_DEBUG_COMMON, "open sfp ret: %d", ret);
		} else {
			sfp_prm.state = NBL_SFP_MODULE_OFF;
			ret = disp_ops->set_sfp_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						      &sfp_prm);
			nbl_info(common, NBL_DEBUG_COMMON, "close sfp ret: %d", ret);
		}
	}
}

static int nbl_serv_get_firmware_version(void *priv, struct nbl_ch_prm_get_firmware_version *output)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->get_firmware_version(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), output);

	return 0;
}

static void nbl_serv_set_netdev_carrier_state(void *priv, struct net_device *netdev, u8 link_state)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;

	if (test_bit(NBL_DOWN, adapter->state))
		return;

	switch (net_resource_mgt->link_forced) {
	case IFLA_VF_LINK_STATE_AUTO:
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
		return;
	case IFLA_VF_LINK_STATE_ENABLE:
		netif_carrier_on(netdev);
		return;
	case IFLA_VF_LINK_STATE_DISABLE:
		netif_carrier_off(netdev);
		return;
	default:
		netif_carrier_on(netdev);
		return;
	}
}

static void nbl_serv_set_port_state_update(void *priv, u8 port_state_update)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;

	net_resource_mgt->port_state_update = port_state_update;
}

static void nbl_serv_set_link_state(void *priv, struct net_device *netdev)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	u16 vsi_id = NBL_COMMON_TO_VSI_ID(common);
	u8 eth_id = NBL_COMMON_TO_ETH_ID(common);
	struct nbl_eth_link_info eth_link_info = {0};
	int ret = 0;

	net_resource_mgt->link_forced =
		disp_ops->get_link_forced(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);

	if (net_resource_mgt->link_forced == IFLA_VF_LINK_STATE_AUTO) {
		ret = disp_ops->get_link_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       eth_id, &eth_link_info);
		if (ret) {
			netdev_err(netdev, "Fail to get_link_state err %d\n", ret);
			eth_link_info.link_status = 1;
		}
	}

	nbl_serv_set_netdev_carrier_state(serv_mgt, netdev, eth_link_info.link_status);
}

static int nbl_serv_rep_netdev_open(struct net_device *netdev)
{
	int ret = 0;

	netdev_info(netdev, "Nbl rep open\n");
	ret = netif_set_real_num_tx_queues(netdev, 1);
	if (ret)
		goto fail;
	ret = netif_set_real_num_rx_queues(netdev, 1);
	if (ret)
		goto fail;

	netif_tx_start_all_queues(netdev);
	netif_carrier_on(netdev);
	netdev_info(netdev, "Nbl rep open ok!\n");

	return 0;

fail:
	return ret;
}

static int nbl_serv_rep_netdev_stop(struct net_device *netdev)
{
	netdev_info(netdev, "Nbl rep stop\n");
	netif_tx_stop_all_queues(netdev);
	netif_carrier_off(netdev);
	netif_tx_disable(netdev);
	netdev_info(netdev, "Nbl rep stop ok!\n");

	return 0;
}

static void nbl_serv_cfg_rx_half_offload(void *priv, struct net_device *netdev,
					 struct nbl_serv_ring_vsi_info *vsi_info,
					 u16 *enable)
{
	enum nbl_fix_cap_type cap_type = NBL_UDF_EXTRACT_CAP;
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	u16 half_offload_en = false;
	u16 rx_vlan_mode;
	u16 rss_hash_mode;
	struct nbl_cfg_rx_half_offload_param half_prm = {0};
	struct nbl_ch_prm_cfg_rx_vlan_parse vlan_prm = {0};
	struct nbl_ch_prm_cfg_rss_hash rss_prm = {0};
	struct nbl_cfg_txrx_vlan_param tvlan_prm = {0};

	if (!(ring_mgt->ethtool_rx_vlan_mode)) {
		if (!(netdev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
		    !(netdev->features & NETIF_F_HW_VLAN_STAG_RX))
			rx_vlan_mode = RX_VLAN_PARSE_OFF;
		else if ((netdev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
			 !(netdev->features & NETIF_F_HW_VLAN_STAG_RX))
			rx_vlan_mode = RX_VLAN_PARSE_CVLAN;
		else if (!(netdev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
			 (netdev->features & NETIF_F_HW_VLAN_STAG_RX))
			rx_vlan_mode = RX_VLAN_PARSE_SVLAN;
		else
			rx_vlan_mode = RX_VLAN_PARSE_CVLAN_OR_SVLAN;
	} else {
		rx_vlan_mode = ring_mgt->ethtool_rx_vlan_mode;
	}

	/* vlan offload priority higher than vlan subinterface */
	switch (net_resource_mgt->vlan_proto) {
	case ETH_P_8021Q:
		rx_vlan_mode = RX_VLAN_PARSE_CVLAN;
		break;
	case ETH_P_8021AD:
		rx_vlan_mode = RX_VLAN_PARSE_SVLAN;
		break;
	default:
		break;
	};

	if (!(ring_mgt->ethtool_rss_hash_mode)) {
		if (netdev->features & NETIF_F_RXHASH)
			rss_hash_mode = RX_RSS_HASH_ON;
		else
			rss_hash_mode = RX_RSS_HASH_OFF;
	} else {
		rss_hash_mode = ring_mgt->ethtool_rss_hash_mode;
	}

	if (rss_hash_mode > RX_RSS_HASH_OFF)
		half_offload_en = true;

	if (!disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					   &cap_type))
		half_offload_en = false;

	netdev_info(netdev, "set half_offload_en:%d, rx_vlan_mode:%d, rss_hash_mode:%d\n",
		    half_offload_en, rx_vlan_mode, rss_hash_mode);
	*enable = half_offload_en;

	half_prm.vsi_index = NBL_VSI_DATA;
	half_prm.half_offload_en = half_offload_en;
	disp_ops->cfg_rx_half_offload(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &half_prm);
	vlan_prm.vsi_id = vsi_info->vsi_id;
	vlan_prm.rx_vlan_mode = rx_vlan_mode;
	disp_ops->cfg_rx_vlan_parse(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vlan_prm);
	rss_prm.vsi_id = vsi_info->vsi_id;
	rss_prm.rss_hash_mode = rss_hash_mode;
	disp_ops->cfg_rss_hash(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &rss_prm);

	tvlan_prm.vlan_tci = net_resource_mgt->vlan_tci;
	tvlan_prm.vlan_proto = net_resource_mgt->vlan_proto;
	tvlan_prm.vsi_index = NBL_VSI_DATA;
	disp_ops->cfg_txrx_vlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &tvlan_prm);
}

int nbl_serv_vsi_open(void *priv, struct net_device *netdev, u16 vsi_index,
		      u16 real_qps, bool use_napi)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info = &ring_mgt->vsi_info[vsi_index];
	u16 half_offload_en = 0;
	struct nbl_cfg_txrx_vlan_param tvlan_prm = {0};
	int ret = 0;

	if (vsi_info->started)
		return 0;

	if (vsi_index == NBL_VSI_DATA)
		nbl_serv_cfg_rx_half_offload(serv_mgt, netdev, vsi_info, &half_offload_en);

	ret = nbl_serv_setup_rings(serv_mgt, netdev, vsi_info, use_napi);
	if (ret) {
		netdev_err(netdev, "Fail to setup rings\n");
		goto setup_rings_fail;
	}

	ret = nbl_serv_setup_queues(serv_mgt, vsi_info, half_offload_en);
	if (ret) {
		netdev_err(netdev, "Fail to setup queues\n");
		goto setup_queue_fail;
	}
	nbl_serv_flush_rx_queues(serv_mgt, vsi_info->ring_offset, vsi_info->ring_num);

	ring_mgt->half_offload_en = half_offload_en;
	if (vsi_index == NBL_VSI_DATA) {
		tvlan_prm.vlan_tci = net_resource_mgt->vlan_tci;
		tvlan_prm.vlan_proto = net_resource_mgt->vlan_proto;
		tvlan_prm.vsi_index = vsi_index;
		disp_ops->cfg_txrx_vlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &tvlan_prm);
	}

	ret = disp_ops->cfg_dsch(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				 vsi_info->vsi_id, true);
	if (ret) {
		netdev_err(netdev, "Fail to setup dsch\n");
		goto setup_dsch_fail;
	}

	vsi_info->active_ring_num = real_qps;
	ret = disp_ops->setup_cqs(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				  vsi_info->vsi_id, real_qps, false);
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

static int nbl_serv_vsi_hw_stop(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	/* disable and rest tx/rx logic queue */
	disp_ops->remove_all_queues(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);

	/* modify defalt action and rss configuration */
	disp_ops->remove_cqs(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id);

	/* clear dsch config */
	disp_ops->cfg_dsch(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id, false);

	return 0;
}

int nbl_serv_vsi_stop(void *priv, u16 vsi_index)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info = &ring_mgt->vsi_info[vsi_index];

	if (!vsi_info->started)
		return 0;

	vsi_info->started = false;
	nbl_serv_vsi_hw_stop(priv, vsi_info->vsi_id);

	/* free tx and rx bufs */
	nbl_serv_stop_rings(serv_mgt, vsi_info);

	return 0;
}

static struct nbl_mac_filter *nbl_add_filter(struct list_head *head,
					     const u8 *macaddr)
{
	struct nbl_mac_filter *f;

	if (!macaddr)
		return NULL;

	f = kzalloc(sizeof(*f), GFP_ATOMIC);
	if (!f)
		return f;

	ether_addr_copy(f->macaddr, macaddr);
	list_add_tail(&f->list, head);

	return f;
}

static int nbl_serv_suspend_data_vsi_traffic(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct net_device *dev = net_resource_mgt->netdev;
	struct nbl_netdev_priv *net_priv = netdev_priv(dev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_ch_prm_cfg_multi_mcast mcast;
	struct nbl_ch_prm_set_promisc_mode promisc_prm = {0};

	rtnl_lock();
	mcast.vsi = net_priv->data_vsi;
	mcast.enable = 0;
	disp_ops->cfg_multi_mcast(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &mcast);
	promisc_prm.vsi_id = net_priv->data_vsi;
	promisc_prm.mode = 0;
	disp_ops->set_promisc_mode(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &promisc_prm);

	nbl_serv_update_promisc_vlan(serv_mgt, 0, net_priv->data_vsi);
	disp_ops->add_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
			      0, net_priv->user_vsi);

	flow_mgt->promisc &= ~BIT(NBL_PROMISC);
	flow_mgt->promisc &= ~BIT(NBL_ALLMULTI);
	flow_mgt->promisc |= BIT(NBL_USER_FLOW);
	rtnl_unlock();

	nbl_common_queue_work(&net_resource_mgt->rx_mode_async, false);

	return 0;
}

static int nbl_serv_restore_vsi_traffic(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct net_device *dev = net_resource_mgt->netdev;
	struct nbl_netdev_priv *net_priv = netdev_priv(dev);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_cfg_multi_mcast mcast;
	struct nbl_ch_prm_set_promisc_mode promisc_prm = {0};

	rtnl_lock();
	disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
			      0, net_priv->user_vsi);
	mcast.vsi = net_priv->user_vsi;
	mcast.enable = 0;
	disp_ops->cfg_multi_mcast(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &mcast);
	promisc_prm.vsi_id = net_priv->user_vsi;
	promisc_prm.mode = 0;
	disp_ops->set_promisc_mode(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &promisc_prm);
	flow_mgt->promisc &= ~BIT(NBL_USER_FLOW);
	rtnl_unlock();
	nbl_common_queue_work(&net_resource_mgt->rx_mode_async, false);

	return 0;
}

static int nbl_serv_switch_traffic_default_dest(void *priv, int op)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;

	if (op == NBL_DEV_KERNEL_TO_USER)
		nbl_serv_suspend_data_vsi_traffic(serv_mgt);
	else if (op == NBL_DEV_USER_TO_KERNEL)
		nbl_serv_restore_vsi_traffic(serv_mgt);

	return 0;
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

static int nbl_serv_stop_abnormal_sw_queue(struct nbl_service_mgt *serv_mgt,
					   u16 local_queue_id, int type)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_stop_abnormal_sw_queue_param prm = {0};

	prm.local_queue_id = local_queue_id;
	prm.type = type;

	return disp_ops->stop_abnormal_sw_queue(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						&prm);
}

static int nbl_serv_chan_stop_abnormal_sw_queue_req(struct nbl_service_mgt *serv_mgt,
						    u16 local_queue_id, u16 func_id, int type)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	struct nbl_chan_param_stop_abnormal_sw_queue param = {0};
	struct nbl_chan_send_info chan_send = {0};
	int ret = 0;

	param.local_queue_id = local_queue_id;
	param.type = type;

	NBL_CHAN_SEND(chan_send, func_id, NBL_CHAN_MSG_STOP_ABNORMAL_SW_QUEUE,
		      &param, sizeof(param), NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_send);

	return ret;
}

static void nbl_serv_chan_stop_abnormal_sw_queue_resp(void *priv, u16 src_id, u16 msg_id,
						      void *data, u32 data_len)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	struct nbl_chan_param_stop_abnormal_sw_queue *param =
					(struct nbl_chan_param_stop_abnormal_sw_queue *)data;
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	struct nbl_chan_ack_info chan_ack;
	int ret = 0;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	if (param->local_queue_id < vsi_info->ring_offset ||
	    param->local_queue_id >= vsi_info->ring_offset + vsi_info->ring_num ||
	    !vsi_info->ring_num) {
		ret = -EINVAL;
		goto send_ack;
	}

	ret = nbl_serv_stop_abnormal_sw_queue(serv_mgt, param->local_queue_id, param->type);

send_ack:
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_STOP_ABNORMAL_SW_QUEUE, msg_id,
		     ret, NULL, 0);
	chan_ops->send_ack(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_ack);
}

static dma_addr_t nbl_serv_netdev_queue_restore(struct nbl_service_mgt *serv_mgt,
						u16 local_queue_id, int type)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_abnormal_ring_param prm = {0};

	prm.ring_index = local_queue_id;
	prm.type = type;

	return disp_ops->restore_abnormal_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       &prm);
}

static int nbl_serv_netdev_queue_restart(struct nbl_service_mgt *serv_mgt,
					 u16 local_queue_id, int type)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_abnormal_ring_param prm = {0};

	prm.ring_index = local_queue_id;
	prm.type = type;

	return disp_ops->restart_abnormal_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       &prm);
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
	int ret = NBL_CHAN_RESP_OK;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	if (param->local_queue_id < vsi_info->ring_offset ||
	    param->local_queue_id >= vsi_info->ring_offset + vsi_info->ring_num ||
	    !vsi_info->ring_num) {
		ret = -EINVAL;
		goto send_ack;
	}

	dma = nbl_serv_netdev_queue_restore(serv_mgt, param->local_queue_id, param->type);

send_ack:
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_RESTORE_NETDEV_QUEUE, msg_id,
		     ret, &dma, sizeof(dma));
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
	int ret = 0;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	if (param->local_queue_id < vsi_info->ring_offset ||
	    param->local_queue_id >= vsi_info->ring_offset + vsi_info->ring_num ||
	    !vsi_info->ring_num) {
		ret = -EINVAL;
		goto send_ack;
	}

	ret = nbl_serv_netdev_queue_restart(serv_mgt, param->local_queue_id, param->type);

send_ack:
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_RESTART_NETDEV_QUEUE, msg_id,
		     ret, NULL, 0);
	chan_ops->send_ack(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_ack);
}

static int
nbl_serv_start_abnormal_hw_queue(struct nbl_service_mgt *serv_mgt, u16 vsi_id, u16 local_queue_id,
				 dma_addr_t dma, int type)
{
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_txrx_queue_param param = {0};
	struct nbl_serv_vector *vector;
	struct nbl_serv_ring *ring;
	int ret = 0;
	bool interleave_seg_disable;
	struct nbl_ch_prm_setup_queue setup_q_prm;

	interleave_seg_disable = test_bit(NBL_FLAG_INTERLEAVE_SEG_DISABLE, &serv_mgt->flags);

	switch (type) {
	case NBL_TX:
		vector = &ring_mgt->vectors[local_queue_id];
		ring = &ring_mgt->tx_rings[local_queue_id];
		ring->dma = dma;
		nbl_serv_set_queue_param(ring, ring_mgt->tx_desc_num, &param, vsi_id,
					 vector->global_vector_id, ring_mgt->half_offload_en);
		memcpy(&setup_q_prm.param, &param, sizeof(param));
		setup_q_prm.is_tx = true;
		setup_q_prm.interleave_seg_disable = interleave_seg_disable;
		ret = disp_ops->setup_queue(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &setup_q_prm);
		return ret;
	case NBL_RX:
		vector = &ring_mgt->vectors[local_queue_id];
		ring = &ring_mgt->rx_rings[local_queue_id];
		ring->dma = dma;

		nbl_serv_set_queue_param(ring, ring_mgt->rx_desc_num, &param, vsi_id,
					 vector->global_vector_id, ring_mgt->half_offload_en);
		memcpy(&setup_q_prm.param, &param, sizeof(param));
		setup_q_prm.is_tx = false;
		setup_q_prm.interleave_seg_disable = false;
		ret = disp_ops->setup_queue(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &setup_q_prm);
		return 0;
	default:
		break;
	}

	return -EINVAL;
}

static void nbl_serv_restore_queue(struct nbl_service_mgt *serv_mgt, u16 vsi_id,
				   u16 local_queue_id, u16 type, bool dif_err)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u16 func_id = disp_ops->get_function_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_ch_prm_stop_abnormal_hw_queue prm = {0};
	u16 global_queue_id;
	dma_addr_t dma = 0;
	int ret = 0;

	while (!rtnl_trylock())
		msleep(20);

	ret = nbl_serv_chan_stop_abnormal_sw_queue_req(serv_mgt, local_queue_id, func_id, type);
	if (ret)
		goto unlock;

	prm.vsi_id = vsi_id;
	prm.local_queue_id = local_queue_id;
	prm.type = type;

	ret = disp_ops->stop_abnormal_hw_queue(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       &prm);
	if (ret)
		goto unlock;

	dma = nbl_serv_chan_restore_netdev_queue_req(serv_mgt, local_queue_id, func_id, type);
	if (!dma)
		goto unlock;

	ret = nbl_serv_start_abnormal_hw_queue(serv_mgt, vsi_id, local_queue_id, dma, type);
	if (ret)
		goto unlock;

	ret = nbl_serv_chan_restart_netdev_queue_req(serv_mgt, local_queue_id, func_id, type);
	if (ret)
		goto unlock;

	if (dif_err && type == NBL_TX) {
		struct nbl_ch_prm_get_vsi_global_qid prm = {0};

		prm.vsi_id = vsi_id;
		prm.local_qid = local_queue_id;

		global_queue_id =
			disp_ops->get_vsi_global_qid(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						     &prm);
		nbl_info(common, NBL_DEBUG_COMMON,
			 "dvn int_status:0, queue_id:%d\n", global_queue_id);
	}

unlock:
	rtnl_unlock();
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

static void nbl_serv_update_link_state(struct work_struct *work)
{
	struct nbl_serv_net_resource_mgt *serv_net_resource_mgt =
		container_of(work, struct nbl_serv_net_resource_mgt, update_link_state);
	struct nbl_service_mgt *serv_mgt = serv_net_resource_mgt->serv_mgt;

	nbl_serv_set_link_state(serv_mgt, serv_net_resource_mgt->netdev);
}

static int nbl_serv_chan_notify_link_forced_req(struct nbl_service_mgt *serv_mgt, u16 func_id)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	struct nbl_chan_send_info chan_send = {0};

	NBL_CHAN_SEND(chan_send, func_id, NBL_CHAN_MSG_NOTIFY_LINK_FORCED, NULL, 0, NULL, 0, 1);
	return chan_ops->send_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_send);
}

static void nbl_serv_chan_notify_link_forced_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	struct nbl_chan_ack_info chan_ack;

	if (!net_resource_mgt)
		return;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_NOTIFY_LINK_FORCED, msg_id,
		     NBL_CHAN_RESP_OK, NULL, 0);
	chan_ops->send_ack(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_ack);

	nbl_serv_set_port_state_update(serv_mgt, true);
	nbl_common_queue_work(&net_resource_mgt->update_link_state, false);
}

static void nbl_serv_register_link_forced_notify(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);

	if (!chan_ops->check_queue_exist(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	chan_ops->register_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
			       NBL_CHAN_MSG_NOTIFY_LINK_FORCED,
			       nbl_serv_chan_notify_link_forced_resp, serv_mgt);
}

static void nbl_serv_update_vlan(struct work_struct *work)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
		container_of(work, struct nbl_serv_net_resource_mgt, update_vlan);
	struct nbl_service_mgt *serv_mgt = net_resource_mgt->serv_mgt;
	struct net_device *netdev = net_resource_mgt->netdev;
	int was_running, err;
	u16 vid;

	vid = net_resource_mgt->vlan_tci & VLAN_VID_MASK;
	nbl_serv_update_default_vlan(serv_mgt, vid);

	rtnl_lock();
	was_running = netif_running(netdev);

	if (was_running) {
		err = nbl_serv_netdev_stop(netdev);
		if (err) {
			netdev_err(netdev, "Netdev stop failed while update_vlan\n");
			goto netdev_stop_fail;
		}

		err = nbl_serv_netdev_open(netdev);
		if (err) {
			netdev_err(netdev, "Netdev open failed after setting ringparam\n");
			goto netdev_open_fail;
		}
	}

netdev_stop_fail:
netdev_open_fail:
	rtnl_unlock();
}

static int nbl_serv_chan_notify_vlan_req(struct nbl_service_mgt *serv_mgt, u16 func_id,
					 struct nbl_serv_notify_vlan_param *param)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	struct nbl_chan_send_info chan_send = {0};

	NBL_CHAN_SEND(chan_send, func_id, NBL_CHAN_MSG_NOTIFY_VLAN,
		      param, sizeof(*param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_send);
}

static void nbl_serv_chan_notify_vlan_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	struct nbl_serv_notify_vlan_param *param = (struct nbl_serv_notify_vlan_param *)data;
	struct nbl_chan_ack_info chan_ack;

	net_resource_mgt->vlan_tci = param->vlan_tci;
	net_resource_mgt->vlan_proto = param->vlan_proto;

	nbl_common_queue_work(&net_resource_mgt->update_vlan, false);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_NOTIFY_VLAN, msg_id,
		     NBL_CHAN_RESP_OK, NULL, 0);
	chan_ops->send_ack(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_ack);
}

static void nbl_serv_register_vlan_notify(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);

	if (!chan_ops->check_queue_exist(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	chan_ops->register_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), NBL_CHAN_MSG_NOTIFY_VLAN,
			       nbl_serv_chan_notify_vlan_resp, serv_mgt);
}

static int nbl_serv_chan_notify_trust_req(struct nbl_service_mgt *serv_mgt,
					  u16 func_id, bool trusted)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	struct nbl_chan_send_info chan_send = {0};

	NBL_CHAN_SEND(chan_send, func_id, NBL_CHAN_MSG_NOTIFY_TRUST, &trusted, sizeof(trusted),
		      NULL, 0, 1);
	return chan_ops->send_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_send);
}

static void nbl_serv_chan_notify_trust_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	bool *trusted = (bool *)data;
	struct nbl_chan_ack_info chan_ack;

	flow_mgt->trusted_en = *trusted;
	flow_mgt->trusted_update = 1;
	nbl_common_queue_work(&net_resource_mgt->rx_mode_async, false);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_NOTIFY_TRUST, msg_id,
		     NBL_CHAN_RESP_OK, NULL, 0);
	chan_ops->send_ack(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_ack);
}

static void nbl_serv_register_trust_notify(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);

	if (!chan_ops->check_queue_exist(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	chan_ops->register_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), NBL_CHAN_MSG_NOTIFY_TRUST,
			       nbl_serv_chan_notify_trust_resp, serv_mgt);
}

static void nbl_serv_update_mirror_outputport(struct work_struct *work)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
		container_of(work, struct nbl_serv_net_resource_mgt, update_mirror_outputport);
	struct nbl_service_mgt *serv_mgt = net_resource_mgt->serv_mgt;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	bool mirror;

	mirror = !!(flow_mgt->promisc & BIT(NBL_MIRROR));
	nbl_event_notify(NBL_EVENT_MIRROR_OUTPUTPORT_DEVLAYER, &mirror,
			 NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));

	nbl_common_queue_work(&net_resource_mgt->rx_mode_async, false);
}

static int nbl_serv_chan_notify_mirror_outputport_req(struct nbl_service_mgt *serv_mgt, u16 func_id,
						      bool opcode)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	struct nbl_chan_send_info chan_send = {0};

	NBL_CHAN_SEND(chan_send, func_id, NBL_CHAN_MSG_MIRROR_OUTPUTPORT_NOTIFY,
		      &opcode, sizeof(bool), NULL, 0, 1);
	return chan_ops->send_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_send);
}

static void nbl_serv_chan_notify_mirror_outputport_resp(void *priv, u16 src_id, u16 msg_id,
							void *data, u32 data_len)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	bool opcode = *(bool *)data;
	struct nbl_chan_ack_info chan_ack;

	if (!!(flow_mgt->promisc & BIT(NBL_MIRROR)) ^ opcode) {
		if (opcode)
			flow_mgt->promisc |= BIT(NBL_MIRROR);
		else
			flow_mgt->promisc &= ~BIT(NBL_MIRROR);
		nbl_common_queue_work(&net_resource_mgt->update_mirror_outputport, false);
	}

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_MIRROR_OUTPUTPORT_NOTIFY, msg_id,
		     NBL_CHAN_RESP_OK, NULL, 0);
	chan_ops->send_ack(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_ack);
}

static void nbl_serv_register_mirror_outputport_notify(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);

	if (!chan_ops->check_queue_exist(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	chan_ops->register_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
			       NBL_CHAN_MSG_MIRROR_OUTPUTPORT_NOTIFY,
			       nbl_serv_chan_notify_mirror_outputport_resp, serv_mgt);
}

static int nbl_serv_chan_get_vf_stats_req(struct nbl_service_mgt *serv_mgt,
					  u16 func_id, struct nbl_vf_stats *vf_stats)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	struct nbl_chan_send_info chan_send = {0};

	NBL_CHAN_SEND(chan_send, func_id, NBL_CHAN_MSG_GET_VF_STATS,
		      NULL, 0, vf_stats, sizeof(*vf_stats), 1);
	return chan_ops->send_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_send);
}

static void nbl_serv_chan_get_vf_stats_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);
	struct nbl_chan_ack_info chan_ack;
	struct nbl_vf_stats vf_stats = {0};
	struct nbl_stats stats = { 0 };
	int err = NBL_CHAN_RESP_OK;

	disp_ops->get_net_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &stats);

	vf_stats.rx_packets = stats.rx_packets;
	vf_stats.tx_packets = stats.tx_packets;
	vf_stats.rx_bytes = stats.rx_bytes;
	vf_stats.tx_bytes = stats.tx_bytes;
	vf_stats.multicast = stats.rx_multicast_packets;
	vf_stats.rx_dropped = 0;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_VF_STATS, msg_id,
		     err, &vf_stats, sizeof(vf_stats));
	chan_ops->send_ack(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt), &chan_ack);
}

static void nbl_serv_register_get_vf_stats(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);

	if (!chan_ops->check_queue_exist(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	chan_ops->register_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
			       NBL_CHAN_MSG_GET_VF_STATS,
			       nbl_serv_chan_get_vf_stats_resp, serv_mgt);
}

int nbl_serv_netdev_open(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_tc_mgt *tc_mgt = NBL_SERV_MGT_TO_TC_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_serv_ring_vsi_info *vsi_info;
	int num_cpus, real_qps, ret = 0;
	bool netdev_open = true;

	if (!test_bit(NBL_DOWN, adapter->state))
		return -EBUSY;

	netdev_info(netdev, "Nbl open\n");

	if (ring_mgt->xdp_prog)
		nbl_event_notify(NBL_EVENT_NETDEV_STATE_CHANGE, &netdev_open,
				 NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));

	netif_carrier_off(netdev);
	nbl_serv_set_sfp_state(serv_mgt, NBL_COMMON_TO_ETH_ID(common), true, false);
	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	if (tc_mgt->num_tc) {
		real_qps = tc_mgt->total_qps;
	} else if (vsi_info->active_ring_num) {
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

	netif_tx_wake_all_queues(netdev);
	clear_bit(NBL_DOWN, adapter->state);
	set_bit(NBL_RUNNING, adapter->state);
	nbl_serv_set_link_state(serv_mgt, netdev);

	netdev_info(netdev, "Nbl open ok!\n");

	return 0;

setup_real_qps_fail:
	nbl_serv_vsi_stop(serv_mgt, NBL_VSI_DATA);
vsi_open_fail:
	netdev_open = false;
	if (ring_mgt->xdp_prog)
		nbl_event_notify(NBL_EVENT_NETDEV_STATE_CHANGE, &netdev_open,
				 NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	return ret;
}

int nbl_serv_netdev_stop(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	bool netdev_open = false;

	if (!test_bit(NBL_RUNNING, adapter->state))
		return 0;

	netdev_info(netdev, "Nbl stop\n");
	set_bit(NBL_DOWN, adapter->state);
	clear_bit(NBL_RUNNING, adapter->state);

	nbl_serv_set_sfp_state(serv_mgt, NBL_COMMON_TO_ETH_ID(common), false, false);

	netif_tx_stop_all_queues(netdev);
	netif_carrier_off(netdev);
	netif_tx_disable(netdev);
	synchronize_net();
	synchronize_rcu();
	nbl_serv_vsi_stop(serv_mgt, NBL_VSI_DATA);

	if (ring_mgt->xdp_prog)
		nbl_event_notify(NBL_EVENT_NETDEV_STATE_CHANGE, &netdev_open,
				 NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));

	netdev_info(netdev, "Nbl stop ok!\n");

	return 0;
}

static int nbl_serv_change_rep_mtu(struct net_device *netdev, int new_mtu)
{
	netdev->mtu = new_mtu;
	return 0;
}

static int nbl_serv_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int was_running = 0, err = 0;
	int max_mtu = 0;
	int ret = 0;
	int rtnl_locked = rtnl_is_locked(); /* is call by os, it has locked */

	ret = disp_ops->check_mtu(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), 0, new_mtu, &max_mtu);
	if (ret) {
		netdev_warn(netdev, "Mtu(%d) > %d, too big for an XDP program not aware of multi buffer\n",
			    new_mtu, max_mtu);
		return -EINVAL;
	}

	if (new_mtu) {
		netdev->mtu = new_mtu;
		nbl_event_notify(NBL_EVENT_CHANGE_MTU, &new_mtu,
				 NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));

		was_running = netif_running(netdev);
		if (was_running) {
			if (!rtnl_locked)
				rtnl_lock();

			err = nbl_serv_netdev_stop(netdev);
			if (err) {
				netdev_err(netdev, "Netdev stop failed while change mtu\n");
				goto out;
			}

			err = nbl_serv_netdev_open(netdev);
			if (err) {
				netdev_err(netdev, "Netdev open failed after change mtu\n");
				goto out;
			}

			if (!rtnl_locked)
				rtnl_unlock();
		}
	}

	disp_ops->set_mtu(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
			  NBL_COMMON_TO_VSI_ID(common), new_mtu);

	return 0;

out:
	if (!rtnl_locked)
		rtnl_unlock();

	return -EFAULT;
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
	struct nbl_ch_prm_set_spoof_check_addr spoof_prm;
	int ret = 0;

	memset(&spoof_prm, 0, sizeof(spoof_prm));
	if (!is_valid_ether_addr(addr->sa_data)) {
		netdev_err(dev, "Temp to change a invalid mac address %pM\n", addr->sa_data);
		return -EADDRNOTAVAIL;
	}

	if (ether_addr_equal(flow_mgt->mac, addr->sa_data))
		return 0;

	list_for_each_entry(vlan_node, &flow_mgt->vlan_list, node) {
		if (!vlan_node->primary_mac_effective)
			continue;
		disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
				      vlan_node->vid, priv->data_vsi);
		ret = disp_ops->add_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), addr->sa_data,
					    vlan_node->vid, priv->data_vsi);
		if (ret) {
			netdev_err(dev, "Fail to cfg macvlan on vid %u", vlan_node->vid);
			goto fail;
		}
	}

	if (flow_mgt->promisc & BIT(NBL_USER_FLOW)) {
		disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
				      0, priv->user_vsi);
		ret = disp_ops->add_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), addr->sa_data,
					    0, priv->user_vsi);
		if (ret) {
			netdev_err(dev, "Fail to cfg macvlan on vid %u for user", 0);
			goto fail;
		}
	}

	spoof_prm.vsi_id = priv->data_vsi;
	ether_addr_copy(spoof_prm.mac, addr->sa_data);
	disp_ops->set_spoof_check_addr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &spoof_prm);

	ether_addr_copy(flow_mgt->mac, addr->sa_data);
	eth_hw_addr_set(dev, addr->sa_data);

	if (!NBL_COMMON_TO_VF_CAP(common))
		disp_ops->set_eth_mac_addr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					   addr->sa_data, NBL_COMMON_TO_ETH_ID(common));

	return 0;
fail:
	list_for_each_entry(vlan_node, &flow_mgt->vlan_list, node) {
		if (!vlan_node->primary_mac_effective)
			continue;
		disp_ops->del_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), addr->sa_data,
				      vlan_node->vid, priv->data_vsi);
		disp_ops->add_macvlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flow_mgt->mac,
				      vlan_node->vid, priv->data_vsi);
	}
	return -EAGAIN;
}

static int nbl_serv_rx_add_vid(struct net_device *dev, __be16 proto, u16 vid)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_netdev_priv *priv = netdev_priv(dev);
	struct nbl_serv_vlan_node *vlan_node;
	bool effective = true;
	int ret = 0;

	if (vid == NBL_DEFAULT_VLAN_ID)
		return 0;

	if (flow_mgt->vid != 0)
		effective = false;

	if (!flow_mgt->unicast_flow_enable)
		effective = false;

	if (!flow_mgt->trusted_en && flow_mgt->vlan_list_cnt >= NBL_NO_TRUST_MAX_VLAN)
		return -ENOSPC;

	nbl_debug(common, NBL_DEBUG_COMMON, "add mac-vlan dev for proto 0x%04x, vid %u.",
		  be16_to_cpu(proto), vid);

	list_for_each_entry(vlan_node, &flow_mgt->vlan_list, node) {
		nbl_debug(common, NBL_DEBUG_COMMON, "add mac-vlan dev vid %u.", vlan_node->vid);
		if (vlan_node->vid == vid) {
			vlan_node->ref_cnt++;
			return 0;
		}
	}

	vlan_node = nbl_serv_alloc_vlan_node();
	if (!vlan_node)
		return -ENOMEM;

	vlan_node->vid = vid;
	ret = nbl_serv_update_vlan_node_effective(serv_mgt, vlan_node, effective, priv->data_vsi);
	if (ret)
		goto add_macvlan_failed;
	list_add(&vlan_node->node, &flow_mgt->vlan_list);
	flow_mgt->vlan_list_cnt++;

	nbl_serv_check_flow_table_spec(serv_mgt);

	return 0;

add_macvlan_failed:
	nbl_serv_free_vlan_node(vlan_node);
	return ret;
}

static int nbl_serv_rx_kill_vid(struct net_device *dev, __be16 proto, u16 vid)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_netdev_priv *priv = netdev_priv(dev);
	struct nbl_serv_vlan_node *vlan_node;

	if (vid == NBL_DEFAULT_VLAN_ID)
		return 0;

	nbl_debug(common, NBL_DEBUG_COMMON, "del mac-vlan dev for proto 0x%04x, vid %u.",
		  be16_to_cpu(proto), vid);

	list_for_each_entry(vlan_node, &flow_mgt->vlan_list, node) {
		nbl_debug(common, NBL_DEBUG_COMMON, "del mac-vlan dev vid %u.", vlan_node->vid);
		if (vlan_node->vid == vid) {
			vlan_node->ref_cnt--;
			if (!vlan_node->ref_cnt) {
				nbl_serv_update_vlan_node_effective(serv_mgt, vlan_node,
								    0, priv->data_vsi);
				list_del(&vlan_node->node);
				flow_mgt->vlan_list_cnt--;
				nbl_serv_free_vlan_node(vlan_node);
			}
			break;
		}
	}

	nbl_serv_check_flow_table_spec(serv_mgt);

	return 0;
}

static int nbl_serv_update_default_vlan(struct nbl_service_mgt *serv_mgt, u16 vid)
{
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_serv_vlan_node *vlan_node = NULL;
	struct nbl_serv_vlan_node *node, *tmp;
	struct nbl_common_info *common;
	int ret;
	u16 vsi;
	bool other_effective = false;

	if (flow_mgt->vid == vid)
		return 0;

	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	vsi = NBL_COMMON_TO_VSI_ID(common);
	rtnl_lock();

	list_for_each_entry(node, &flow_mgt->vlan_list, node) {
		if (node->vid == vid) {
			node->ref_cnt++;
			vlan_node = node;
			break;
		}
	}

	if (!vlan_node)
		vlan_node = nbl_serv_alloc_vlan_node();

	if (!vlan_node) {
		rtnl_unlock();
		return -ENOMEM;
	}

	vlan_node->vid = vid;
	/* restore to default vlan id 0, we need restore other vlan interface */
	if (!vid)
		other_effective = true;
	list_for_each_entry_safe(node, tmp, &flow_mgt->vlan_list, node) {
		if (node->vid == flow_mgt->vid && node != vlan_node) {
			node->ref_cnt--;
			if (!node->ref_cnt) {
				nbl_serv_update_vlan_node_effective(serv_mgt, node, 0, vsi);
				list_del(&node->node);
				nbl_serv_free_vlan_node(node);
			}
		} else if (node->vid != vid) {
			nbl_serv_update_vlan_node_effective(serv_mgt, node,
							    other_effective, vsi);
		}
	}

	ret = nbl_serv_update_vlan_node_effective(serv_mgt, vlan_node, 1, vsi);
	if (ret)
		goto free_vlan_node;

	if (vlan_node->ref_cnt == 1)
		list_add(&vlan_node->node, &flow_mgt->vlan_list);

	flow_mgt->vid = vid;
	rtnl_unlock();

	return 0;

free_vlan_node:
	vlan_node->ref_cnt--;
	if (!vlan_node->ref_cnt)
		nbl_serv_free_vlan_node(vlan_node);
	rtnl_unlock();

	return ret;
}

static void nbl_serv_get_stats64(struct net_device *netdev, struct rtnl_link_stats64 *stats)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_stats net_stats = { 0 };

	if (!stats) {
		netdev_err(netdev, "get_link_stats64 stats is null\n");
		return;
	}

	if (!netif_device_present(netdev))
		return;

	disp_ops->get_net_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &net_stats);

	stats->rx_packets = net_stats.rx_packets;
	stats->tx_packets = net_stats.tx_packets;
	stats->rx_bytes = net_stats.rx_bytes;
	stats->tx_bytes = net_stats.tx_bytes;
	stats->multicast = net_stats.rx_multicast_packets;

	stats->rx_errors = 0;
	stats->tx_errors = 0;
	stats->rx_length_errors = netdev->stats.rx_length_errors;
	stats->rx_crc_errors = netdev->stats.rx_crc_errors;
	stats->rx_frame_errors = netdev->stats.rx_frame_errors;
	stats->rx_dropped = 0;
	stats->tx_dropped = 0;
}

static int nbl_addr_unsync(struct net_device *netdev, const u8 *addr)
{
	struct nbl_adapter *adapter;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;

	adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	if (ether_addr_equal(addr, netdev->dev_addr))
		return 0;

	if (!nbl_add_filter(&net_resource_mgt->tmp_del_filter_list, addr))
		return -ENOMEM;

	net_resource_mgt->update_submac = 1;
	return 0;
}

static int nbl_addr_sync(struct net_device *netdev, const u8 *addr)
{
	struct nbl_adapter *adapter;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;

	adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	if (ether_addr_equal(addr, netdev->dev_addr))
		return 0;

	if (!nbl_add_filter(&net_resource_mgt->tmp_add_filter_list, addr))
		return -ENOMEM;

	net_resource_mgt->update_submac = 1;
	return 0;
}

static void nbl_modify_submacs(struct nbl_serv_net_resource_mgt *net_resource_mgt)
{
	struct nbl_service_mgt *serv_mgt = net_resource_mgt->serv_mgt;
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct net_device *netdev = net_resource_mgt->netdev;
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_mac_filter *filter, *safe_filter;

	INIT_LIST_HEAD(&net_resource_mgt->tmp_add_filter_list);
	INIT_LIST_HEAD(&net_resource_mgt->tmp_del_filter_list);
	net_resource_mgt->update_submac = 0;

	netif_addr_lock_bh(netdev);
	__dev_uc_sync(net_resource_mgt->netdev, nbl_addr_sync, nbl_addr_unsync);
	__dev_mc_sync(net_resource_mgt->netdev, nbl_addr_sync, nbl_addr_unsync);
	netif_addr_unlock_bh(netdev);

	if (!net_resource_mgt->update_submac)
		return;

	rtnl_lock();
	list_for_each_entry_safe(filter, safe_filter,
				 &net_resource_mgt->tmp_del_filter_list, list) {
		nbl_serv_del_submac_node(serv_mgt, filter->macaddr, priv->data_vsi);
		list_del(&filter->list);
		kfree(filter);
	}

	list_for_each_entry_safe(filter, safe_filter,
				 &net_resource_mgt->tmp_add_filter_list, list) {
		nbl_serv_add_submac_node(serv_mgt, filter->macaddr,
					 priv->data_vsi, flow_mgt->promisc);
		list_del(&filter->list);
		kfree(filter);
	}

	nbl_serv_check_flow_table_spec(serv_mgt);
	rtnl_unlock();
}

static void nbl_modify_promisc_mode(struct nbl_serv_net_resource_mgt *net_resource_mgt)
{
	enum nbl_fix_cap_type cap_type = NBL_PROMISC_NOT_SUPPORT;
	struct net_device *netdev = net_resource_mgt->netdev;
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_service_mgt *serv_mgt = net_resource_mgt->serv_mgt;
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	bool mode = 0, multi = 0;
	bool need_flow = 1;
	bool unicast_enable, multicast_enable;
	struct nbl_ch_prm_cfg_multi_mcast mcast;
	struct nbl_ch_prm_set_promisc_mode promisc_prm = {0};

	rtnl_lock();
	net_resource_mgt->curr_promiscuout_mode = netdev->flags;

	if (((netdev->flags & (IFF_PROMISC)) || flow_mgt->force_promisc) &&
	    !NBL_COMMON_TO_VF_CAP(NBL_SERV_MGT_TO_COMMON(serv_mgt)))
		mode = 1;

	if ((netdev->flags & (IFF_PROMISC | IFF_ALLMULTI)) || flow_mgt->force_promisc)
		multi = 1;

	if (flow_mgt->promisc & (BIT(NBL_USER_FLOW) | BIT(NBL_MIRROR))) {
		multi = 0;
		mode = 0;
		need_flow = 0;
	}

	if (!flow_mgt->trusted_en)
		multi = 0;

	if (disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  &cap_type))
		mode = 0;

	unicast_enable = !mode && need_flow;
	multicast_enable = !multi && need_flow;

	if ((flow_mgt->promisc & BIT(NBL_PROMISC)) ^ (mode << NBL_PROMISC))
		if (!NBL_COMMON_TO_VF_CAP(NBL_SERV_MGT_TO_COMMON(serv_mgt))) {
			promisc_prm.vsi_id = priv->data_vsi;
			promisc_prm.mode = mode;
			disp_ops->set_promisc_mode(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						   &promisc_prm);
			if (mode)
				flow_mgt->promisc |= BIT(NBL_PROMISC);
			else
				flow_mgt->promisc &= ~BIT(NBL_PROMISC);
		}

	if ((flow_mgt->multicast_flow_enable ^ multicast_enable) && multi) {
		nbl_serv_update_mcast_submac(serv_mgt, multicast_enable,
					     unicast_enable, priv->data_vsi);
		flow_mgt->multicast_flow_enable = multicast_enable;
	}

	if ((flow_mgt->promisc & BIT(NBL_ALLMULTI)) ^ (multi << NBL_ALLMULTI)) {
		mcast.vsi = priv->data_vsi;
		mcast.enable = multi;
		disp_ops->cfg_multi_mcast(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &mcast);
		if (multi)
			flow_mgt->promisc |= BIT(NBL_ALLMULTI);
		else
			flow_mgt->promisc &= ~BIT(NBL_ALLMULTI);
	}

	if ((flow_mgt->multicast_flow_enable ^ multicast_enable) && !multi) {
		nbl_serv_update_mcast_submac(serv_mgt, multicast_enable,
					     unicast_enable, priv->data_vsi);
		flow_mgt->multicast_flow_enable = multicast_enable;
	}

	if (flow_mgt->unicast_flow_enable ^ unicast_enable) {
		nbl_serv_update_promisc_vlan(serv_mgt, unicast_enable, priv->data_vsi);
		flow_mgt->unicast_flow_enable = unicast_enable;
	}

	if (flow_mgt->trusted_update) {
		flow_mgt->trusted_update = 0;
		if (flow_mgt->active_submac_list < flow_mgt->submac_list_cnt)
			nbl_serv_update_mcast_submac(serv_mgt, flow_mgt->multicast_flow_enable,
						     flow_mgt->unicast_flow_enable, priv->data_vsi);
	}
	rtnl_unlock();
}

static void nbl_serv_set_rx_mode(struct net_device *dev)
{
	struct nbl_adapter *adapter;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;

	adapter = NBL_NETDEV_TO_ADAPTER(dev);
	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	nbl_common_queue_work(&net_resource_mgt->rx_mode_async, false);
}

static void nbl_serv_change_rx_flags(struct net_device *dev, int flag)
{
	struct nbl_adapter *adapter;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;

	adapter = NBL_NETDEV_TO_ADAPTER(dev);
	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	nbl_common_queue_work(&net_resource_mgt->rx_mode_async, false);
}

static int nbl_serv_config_rxhash(void *priv, bool enable)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct device *dev = NBL_SERV_MGT_TO_DEV(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	u32 rxfh_indir_size = 0;
	u32 *indir = NULL;
	int i = 0;

	disp_ops->get_rxfh_indir_size(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				&NBL_COMMON_TO_VSI_ID(common), &rxfh_indir_size);
	indir = devm_kcalloc(dev, rxfh_indir_size, sizeof(u32), GFP_KERNEL);
	if (!indir)
		return -ENOMEM;
	if (enable) {
		if (ring_mgt->rss_indir_user) {
			memcpy(indir, ring_mgt->rss_indir_user, rxfh_indir_size * sizeof(u32));
		} else {
			for (i = 0; i < rxfh_indir_size; i++)
				indir[i] = i % vsi_info->active_ring_num;
		}
	}
	disp_ops->set_rxfh_indir(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					NBL_COMMON_TO_VSI_ID(common),
					indir, rxfh_indir_size);
	devm_kfree(dev, indir);
	return 0;
}

static int nbl_serv_set_features(struct net_device *netdev, netdev_features_t features)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(priv);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	netdev_features_t changed = netdev->features ^ features;
	int rx_vlan_features_changed = false;
	int rss_hash_features_changed = false;
	int was_running;
	int err = 0;
	u16 vsi_id = NBL_COMMON_TO_VSI_ID(common);
	bool enable = false;

	if (changed & (NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_STAG_RX)) {
		rx_vlan_features_changed = true;
		if (!(features & NETIF_F_HW_VLAN_CTAG_RX) &&
		    !(features & NETIF_F_HW_VLAN_STAG_RX))
			ring_mgt->ethtool_rx_vlan_mode = RX_VLAN_PARSE_OFF;
		if ((features & NETIF_F_HW_VLAN_CTAG_RX) &&
		    !(features & NETIF_F_HW_VLAN_STAG_RX))
			ring_mgt->ethtool_rx_vlan_mode = RX_VLAN_PARSE_CVLAN;
		else if (!(features & NETIF_F_HW_VLAN_CTAG_RX) &&
			 (features & NETIF_F_HW_VLAN_STAG_RX))
			ring_mgt->ethtool_rx_vlan_mode = RX_VLAN_PARSE_SVLAN;
		else if ((features & NETIF_F_HW_VLAN_CTAG_RX) &&
			 (features & NETIF_F_HW_VLAN_STAG_RX))
			ring_mgt->ethtool_rx_vlan_mode = RX_VLAN_PARSE_CVLAN_OR_SVLAN;
	}

	if (!common->is_vf) {
		if (changed & NETIF_F_NTUPLE) {
			enable = !!(features & NETIF_F_NTUPLE);

			disp_ops->config_fd_flow_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						NBL_CHAN_FDIR_RULE_NORMAL, vsi_id, enable);
		}
	}

	if (changed & NETIF_F_RXHASH) {
		rss_hash_features_changed = true;
		if (features & NETIF_F_RXHASH)
			ring_mgt->ethtool_rss_hash_mode = RX_RSS_HASH_ON;
		else
			ring_mgt->ethtool_rss_hash_mode = RX_RSS_HASH_OFF;
		enable = !!(features & NETIF_F_RXHASH);
		nbl_serv_config_rxhash(serv_mgt, enable);
	}

	if (rx_vlan_features_changed || rss_hash_features_changed) {
		was_running = netif_running(netdev);

		if (was_running) {
			err = nbl_serv_netdev_stop(netdev);
			if (err) {
				netdev_err(netdev, "Netdev stop failed while setting ringparam\n");
				goto netdev_stop_fail;
			}
		}

		if (was_running) {
			err = nbl_serv_netdev_open(netdev);
			if (err) {
				netdev_err(netdev, "Netdev open failed after setting ringparam\n");
				goto netdev_open_fail;
			}
		}
	}

	return 0;

netdev_open_fail:
netdev_stop_fail:
	return -EIO;
}

static int nbl_serv_config_fd_flow_state(void *priv, enum nbl_chan_fdir_rule_type type, u32 state)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	u16 vsi_id = NBL_COMMON_TO_VSI_ID(common);

	return disp_ops->config_fd_flow_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					      type, vsi_id, state);
}

static LIST_HEAD(nbl_serv_block_cb_list);

static int nbl_serv_setup_tc(struct net_device *dev, enum tc_setup_type type, void *type_data)
{
	struct nbl_netdev_priv *priv = netdev_priv(dev);

	if (!priv)
		return -EINVAL;

	switch (type) {
	case TC_SETUP_BLOCK: {
		return flow_block_cb_setup_simple((struct flow_block_offload *)type_data,
						  &nbl_serv_block_cb_list,
						  nbl_serv_setup_tc_block_cb,
						  priv, priv, true);
	}
	case TC_SETUP_QDISC_MQPRIO:
		return nbl_serv_setup_tc_mqprio(dev, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

static int nbl_serv_set_vf_mac(struct net_device *dev, int vf_id, u8 *mac)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(dev);
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u16 function_id = U16_MAX;
	u8 default_mac[6] = {0};
	int i;

	if (vf_id >= net_resource_mgt->total_vfs || !net_resource_mgt->vf_info)
		return -EINVAL;

	function_id = disp_ops->get_vf_function_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						   NBL_COMMON_TO_VSI_ID(common), vf_id);

	if (function_id == U16_MAX) {
		netdev_info(dev, "vf id %d invalid\n", vf_id);
		return -EINVAL;
	}
	if (is_multicast_ether_addr(mac))
		return -EINVAL;
	if (!ether_addr_equal(default_mac, mac)) {
		for (i = 0; i < net_resource_mgt->total_vfs; i++) {
			if (i == vf_id)
				continue;
			if (ether_addr_equal(net_resource_mgt->vf_info[i].mac, mac) &&
			    net_resource_mgt->vf_info[i].vlan ==
			    net_resource_mgt->vf_info[vf_id].vlan)
				return -EINVAL;
		}
	}

	ether_addr_copy(net_resource_mgt->vf_info[vf_id].mac, mac);

	disp_ops->register_func_mac(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), mac, function_id);

	return 0;
}

static int nbl_serv_set_vf_rate(struct net_device *dev, int vf_id, int min_rate, int max_rate)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(dev);
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u16 function_id = U16_MAX;
	int ret = 0;

	function_id = nbl_serv_get_vf_function_id(serv_mgt, vf_id);
	if (function_id == U16_MAX) {
		netdev_info(dev, "vf id %d invalid\n", vf_id);
		return -EINVAL;
	}

	if (vf_id < net_resource_mgt->num_vfs)
		ret = disp_ops->set_tx_rate(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    function_id, max_rate, 0);

	if (!ret)
		net_resource_mgt->vf_info[vf_id].max_tx_rate = max_rate;

	ret = disp_ops->register_func_rate(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					   function_id, max_rate);

	return ret;
}

static int nbl_serv_set_vf_spoofchk(struct net_device *dev, int vf_id, bool ena)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(dev);
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_set_vf_spoof_check vf_spoof_prm = {0};
	int ret = 0;

	if (vf_id >= net_resource_mgt->total_vfs || !net_resource_mgt->vf_info)
		return -EINVAL;

	if (vf_id < net_resource_mgt->num_vfs) {
		vf_spoof_prm.vsi_id = NBL_COMMON_TO_VSI_ID(common);
		vf_spoof_prm.vf_id = vf_id;
		vf_spoof_prm.enable = ena;
		ret = disp_ops->set_vf_spoof_check(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						   &vf_spoof_prm);
	}

	if (!ret)
		net_resource_mgt->vf_info[vf_id].spoof_check = ena;

	return ret;
}

static int nbl_serv_set_vf_link_state(struct net_device *dev, int vf_id, int link_state)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(dev);
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u16 function_id = U16_MAX;
	bool should_notify = false;
	int ret = 0;

	if (vf_id >= net_resource_mgt->total_vfs || !net_resource_mgt->vf_info)
		return -EINVAL;

	function_id = disp_ops->get_vf_function_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						   NBL_COMMON_TO_VSI_ID(common), vf_id);

	if (function_id == U16_MAX) {
		netdev_info(dev, "vf id %d invalid\n", vf_id);
		return -EINVAL;
	}

	ret = disp_ops->register_func_link_forced(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						  function_id, link_state, &should_notify);
	if (!ret && should_notify)
		nbl_serv_chan_notify_link_forced_req(serv_mgt, function_id);

	if (!ret)
		net_resource_mgt->vf_info[vf_id].state = link_state;

	return ret;
}

static int nbl_serv_set_vf_trust(struct net_device *dev, int vf_id, bool trusted)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(dev);
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
						NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u16 function_id = U16_MAX;
	bool should_notify = false;
	int ret = 0;

	if (vf_id >= net_resource_mgt->total_vfs || !net_resource_mgt->vf_info)
		return -EINVAL;

	function_id = disp_ops->get_vf_function_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						   NBL_COMMON_TO_VSI_ID(common), vf_id);

	if (function_id == U16_MAX) {
		netdev_info(dev, "vf id %d invalid\n", vf_id);
		return -EINVAL;
	}

	ret = disp_ops->register_func_trust(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    function_id, trusted, &should_notify);
	if (!ret && should_notify)
		nbl_serv_chan_notify_trust_req(serv_mgt, function_id, trusted);

	if (!ret)
		net_resource_mgt->vf_info[vf_id].trusted = trusted;

	return ret;
}

static int __used nbl_serv_set_vf_tx_rate(struct net_device *dev,
					  int vf_id, int tx_rate,
					  int burst, bool burst_en)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(dev);
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u16 function_id = U16_MAX;
	int ret = 0;

	function_id = nbl_serv_get_vf_function_id(serv_mgt, vf_id);
	if (function_id == U16_MAX) {
		netdev_info(dev, "vf id %d invalid\n", vf_id);
		return -EINVAL;
	}
	if (!burst_en)
		burst = net_resource_mgt->vf_info[vf_id].meter_tx_burst;

	if (vf_id < net_resource_mgt->num_vfs)
		ret = disp_ops->set_tx_rate(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    function_id, tx_rate, burst);

	if (!ret) {
		net_resource_mgt->vf_info[vf_id].meter_tx_rate = tx_rate;
		if (burst_en)
			net_resource_mgt->vf_info[vf_id].meter_tx_burst = burst;
	}

	return ret;
}

static int __used nbl_serv_set_vf_rx_rate(struct net_device *dev,
					  int vf_id, int rx_rate,
					  int burst, bool burst_en)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(dev);
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u16 function_id = U16_MAX;
	int ret = 0;

	function_id = nbl_serv_get_vf_function_id(serv_mgt, vf_id);
	if (function_id == U16_MAX) {
		netdev_info(dev, "vf id %d invalid\n", vf_id);
		return -EINVAL;
	}
	if (!burst_en)
		burst = net_resource_mgt->vf_info[vf_id].meter_tx_burst;

	if (vf_id < net_resource_mgt->num_vfs)
		ret = disp_ops->set_rx_rate(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    function_id, rx_rate, burst);

	if (!ret) {
		net_resource_mgt->vf_info[vf_id].meter_rx_rate = rx_rate;
		if (burst_en)
			net_resource_mgt->vf_info[vf_id].meter_rx_burst = burst;
	}

	return ret;
}

static int nbl_serv_set_vf_vlan(struct net_device *dev, int vf_id, u16 vlan, u8 qos, __be16 proto)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(dev);
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_notify_vlan_param param = {0};
	int ret = 0;
	int i;
	u16 function_id = U16_MAX;
	bool should_notify = false;
	u8 default_mac[6] = {0};

	if (vf_id >= net_resource_mgt->total_vfs || !net_resource_mgt->vf_info)
		return -EINVAL;

	if (vlan > 4095 || qos > 7)
		return -EINVAL;
	if (!ether_addr_equal(default_mac, net_resource_mgt->vf_info[vf_id].mac)) {
		for (i = 0; i < net_resource_mgt->total_vfs; i++) {
			if (i == vf_id)
				continue;
			if (ether_addr_equal(net_resource_mgt->vf_info[i].mac,
					     net_resource_mgt->vf_info[vf_id].mac) &&
					     net_resource_mgt->vf_info[i].vlan == vlan)
				return -EINVAL;
			}
	}

	function_id = disp_ops->get_vf_function_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						   NBL_COMMON_TO_VSI_ID(common), vf_id);

	if (function_id == U16_MAX) {
		netdev_info(dev, "vf id %d invalid\n", vf_id);
		return -EINVAL;
	}

	if (vlan) {
		param.vlan_tci = (vlan & VLAN_VID_MASK) | (qos << VLAN_PRIO_SHIFT);
		param.vlan_proto = ntohs(proto);
	} else {
		proto = 0;
		qos = 0;
	}

	ret = disp_ops->register_func_vlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), function_id,
					   param.vlan_tci, param.vlan_proto,
					   &should_notify);
	if (should_notify && !ret) {
		ret = nbl_serv_chan_notify_vlan_req(serv_mgt, function_id, &param);
		if (ret)
			disp_ops->register_func_vlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						     function_id, 0, 0, &should_notify);
	}
	if (!ret) {
		net_resource_mgt->vf_info[vf_id].vlan = vlan;
		net_resource_mgt->vf_info[vf_id].vlan_proto = ntohs(proto);
		net_resource_mgt->vf_info[vf_id].vlan_qos = qos;
	}

	return ret;
}

static int nbl_serv_get_vf_config(struct net_device *dev, int vf_id, struct ifla_vf_info *ivi)
{
	struct nbl_netdev_priv *priv = netdev_priv(dev);
	struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(priv);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_serv_vf_info *vf_info = net_resource_mgt->vf_info;

	if (!netif_device_present(dev))
		return -EOPNOTSUPP;

	if (vf_id >= net_resource_mgt->total_vfs || !net_resource_mgt->vf_info)
		return -EINVAL;

	ivi->vf = vf_id;
	ivi->spoofchk = vf_info[vf_id].spoof_check;
	ivi->linkstate = vf_info[vf_id].state;
	ivi->max_tx_rate = vf_info[vf_id].max_tx_rate;
	ivi->vlan = vf_info[vf_id].vlan;
	ivi->trusted = vf_info[vf_id].trusted;
	ivi->vlan_proto = htons(vf_info[vf_id].vlan_proto);
	ivi->qos = vf_info[vf_id].vlan_qos;
	ivi->trusted = vf_info[vf_id].trusted;
	ether_addr_copy(ivi->mac, vf_info[vf_id].mac);

	return 0;
}

static bool nbl_serv_check_vf_is_active(void *priv, u16 func_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->check_vf_is_active(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), func_id);
}

static int nbl_serv_get_vf_stats(struct net_device *dev, int vf_id, struct ifla_vf_stats *vf_stats)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(dev);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_vf_stats stats = {0};
	u16 func_id = U16_MAX;
	u8 is_vdpa = 0;
	int ret = 0;

	func_id = disp_ops->get_vf_function_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						   NBL_COMMON_TO_VSI_ID(common), vf_id);
	if (func_id == U16_MAX) {
		netdev_info(dev, "vf id %d invalid\n", vf_id);
		return -EINVAL;
	}

	ret = disp_ops->check_vf_is_active(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), func_id);
	if (!ret)
		return 0;

	ret = disp_ops->check_vf_is_vdpa(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), func_id, &is_vdpa);
	if (!ret && is_vdpa)
		ret = disp_ops->get_vdpa_vf_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						  func_id, &stats);
	else
		ret = nbl_serv_chan_get_vf_stats_req(serv_mgt, func_id, &stats);

	if (ret)
		return -EIO;

	vf_stats->rx_packets = stats.rx_packets;
	vf_stats->tx_packets = stats.tx_packets;
	vf_stats->rx_bytes = stats.rx_bytes;
	vf_stats->tx_bytes = stats.tx_bytes;
	vf_stats->broadcast = stats.broadcast;
	vf_stats->multicast = stats.multicast;
	vf_stats->rx_dropped = stats.rx_dropped;
	vf_stats->tx_dropped = stats.tx_dropped;

	return 0;
}

static u8 nbl_get_dscp_up(struct nbl_serv_net_resource_mgt *net_resource_mgt, struct sk_buff *skb)
{
	u8 dscp = 0;

	if (skb->protocol == htons(ETH_P_IP))
		dscp = ipv4_get_dsfield(ip_hdr(skb)) >> 2;
	else if (skb->protocol == htons(ETH_P_IPV6))
		dscp = ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;

	return net_resource_mgt->qos_info.dscp2prio_map[dscp];
}

static u16 nbl_serv_select_queue(struct net_device *netdev, struct sk_buff *skb
	, struct net_device *sb_dev
)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);

	if (priv->trust_mode == NBL_TRUST_MODE_DSCP) {
		struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(priv);
		struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
		struct nbl_serv_net_resource_mgt *net_resource_mgt =
						NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

		skb->priority = nbl_get_dscp_up(net_resource_mgt, skb);
	}

	return netdev_pick_tx(netdev, skb, sb_dev);
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

	nbl_common_queue_work(&NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt)->tx_timeout, false);
}

static int nbl_serv_bridge_getlink(struct sk_buff *skb, u32 pid, u32 seq,
				   struct net_device *netdev, u32 filter_mask, int nlflags)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(priv);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	u16 bmode;

	bmode = net_resource_mgt->bridge_mode;

	return ndo_dflt_bridge_getlink(skb, pid, seq, netdev, bmode, 0, 0, nlflags,
				       filter_mask, NULL);
}

static int nbl_serv_bridge_setlink(struct net_device *netdev, struct nlmsghdr *nlh,
				   u16 flags, struct netlink_ext_ack *extack)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(priv);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nlattr *attr, *br_spec;
	u16 mode;
	int ret, rem;

	br_spec = nlmsg_find_attr(nlh, sizeof(struct ifinfomsg), IFLA_AF_SPEC);

	nla_for_each_nested(attr, br_spec, rem) {
		if (nla_type(attr) != IFLA_BRIDGE_MODE)
			continue;

		mode = nla_get_u16(attr);
		if (mode != BRIDGE_MODE_VEPA && mode != BRIDGE_MODE_VEB)
			return -EINVAL;

		if (mode == net_resource_mgt->bridge_mode)
			continue;

		ret = disp_ops->set_bridge_mode(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), mode);
		if (ret) {
			netdev_info(netdev, "bridge_setlink failed 0x%x", ret);
			return ret;
		}

		net_resource_mgt->bridge_mode = mode;
	}

	return 0;
}

static int nbl_serv_get_phys_port_name(struct net_device *dev, char *name, size_t len)
{
	struct nbl_common_info *common = NBL_NETDEV_TO_COMMON(dev);
	u8 pf_id;

	if (common->devlink_port && common->devlink_port->devlink)
		return -EOPNOTSUPP;

	pf_id = NBL_COMMON_TO_LOGIC_ETH_ID(common);
	if (snprintf(name, len, "p%u", pf_id) >= len)
		return -EOPNOTSUPP;
	return 0;
}

static int nbl_serv_get_port_parent_id(struct net_device *dev, struct netdev_phys_item_id *ppid)
{
	struct nbl_netdev_priv *priv = netdev_priv(dev);
	struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(priv);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_NETDEV_TO_COMMON(dev);
	u8 mac[ETH_ALEN];

	if (common->devlink_port && common->devlink_port->devlink)
		return -EOPNOTSUPP;

	/* return success to avoid linkwatch_do_dev report warnning */
	if (test_bit(NBL_FATAL_ERR, adapter->state) ||
	    test_bit(NBL_PCI_ERR_RECOVERING, adapter->state))
		return 0;

	disp_ops->get_base_mac_addr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), mac);

	ppid->id_len = ETH_ALEN;
	memcpy(&ppid->id, mac, ppid->id_len);

	return 0;
}

static int nbl_serv_register_net(void *priv, struct nbl_ch_prm_register_net_info *param,
				 struct nbl_register_net_result *register_result)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int p4_type, ret = 0;

	ret = disp_ops->register_net(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				     param, register_result);
	if (ret)
		return ret;

	p4_type = disp_ops->get_p4_used(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	switch (p4_type) {
	case NBL_P4_DEFAULT:
		set_bit(NBL_FLAG_P4_DEFAULT, &serv_mgt->flags);
		break;
	default:
		nbl_warn(NBL_SERV_MGT_TO_COMMON(serv_mgt), NBL_DEBUG_CUSTOMIZED_P4,
			 "Unknown P4 type %d", p4_type);
	}

	return 0;
}

static int nbl_serv_unregister_net(void *priv, u16 func_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->unregister_net(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &func_id);
}

static int nbl_serv_setup_txrx_queues(void *priv, u16 vsi_id, u16 queue_num, u16 net_vector_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_vector *vector;
	int i, ret = 0;
	struct nbl_ch_prm_get_global_vec global_vec;
	struct nbl_vec_info_param vec_prm;
	struct nbl_ch_prm_alloc_txrx_queues txrx_q_prm;

	/* queue_num include user&kernel queue */
	txrx_q_prm.vsi_id = vsi_id;
	txrx_q_prm.queue_num = queue_num;
	ret = disp_ops->alloc_txrx_queues(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &txrx_q_prm);
	if (ret)
		return -EFAULT;

	/* ring_mgt->tx_ring_number only for kernel use */
	for (i = 0; i < ring_mgt->tx_ring_num; i++) {
		ring_mgt->tx_rings[i].local_queue_id = NBL_PAIR_ID_GET_TX(i);
		ring_mgt->rx_rings[i].local_queue_id = NBL_PAIR_ID_GET_RX(i);
	}

	for (i = 0; i < ring_mgt->xdp_ring_offset; i++) {
		vector = &ring_mgt->vectors[i];
		vector->local_vector_id = i + net_vector_id;
		global_vec.vsi_id = vsi_id;
		global_vec.vector_id = vector->local_vector_id;
		vector->global_vector_id =
			disp_ops->get_global_vector(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						    &global_vec);
		vector->irq_enable_base =
			disp_ops->get_msix_irq_enable_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							   vector->global_vector_id,
							   &vector->irq_data,
							   &vector->irq_mask_data);

		vec_prm.irq_enable_base = vector->irq_enable_base;
		vec_prm.irq_data = vector->irq_data;
		vec_prm.index = i;
		vec_prm.mask_en = ring_mgt->net_msix_mask_en;
		disp_ops->set_vector_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vec_prm);
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

	disp_ops->free_txrx_queues(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);
}

static int nbl_serv_init_tx_rate(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u16 func_id;
	int ret = 0;

	if (net_resource_mgt->max_tx_rate) {
		func_id = disp_ops->get_function_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);
		ret = disp_ops->set_tx_rate(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    func_id, net_resource_mgt->max_tx_rate, 0);
	}

	return ret;
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

static int nbl_serv_setup_rss_indir(void *priv, u16 vsi_index)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct device *dev = NBL_SERV_MGT_TO_DEV(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info = &ring_mgt->vsi_info[vsi_index];
	u32 rxfh_indir_size = 0;
	u16 vsi_id = vsi_info->vsi_id;
	int num_cpus = 0, real_qps = 0;
	u32 *indir = NULL;
	int i = 0;

	disp_ops->get_rxfh_indir_size(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				      &vsi_id, &rxfh_indir_size);
	indir = devm_kcalloc(dev, rxfh_indir_size, sizeof(u32), GFP_KERNEL);
	if (!indir)
		return -ENOMEM;

	num_cpus = num_online_cpus();
	real_qps = num_cpus > vsi_info->ring_num ? vsi_info->ring_num : num_cpus;

	for (i = 0; i < rxfh_indir_size; i++)
		indir[i] = i % real_qps;

	disp_ops->set_rxfh_indir(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				 vsi_id, indir, rxfh_indir_size);
	devm_kfree(dev, indir);
	return 0;
}

static int nbl_serv_alloc_rings(void *priv, struct nbl_ring_param *param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct device *dev;
	struct nbl_serv_ring_mgt *ring_mgt;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;

	dev = NBL_SERV_MGT_TO_DEV(serv_mgt);
	ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ring_mgt->tx_ring_num = param->tx_ring_num;
	ring_mgt->rx_ring_num = param->rx_ring_num;
	ring_mgt->tx_desc_num = param->queue_size;
	ring_mgt->rx_desc_num = param->queue_size;
	ring_mgt->xdp_ring_offset = param->xdp_ring_offset;

	ret = disp_ops->alloc_rings(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);
	if (ret)
		goto alloc_rings_fail;

	ret = nbl_serv_set_tx_rings(ring_mgt, param->netdev, dev);
	if (ret)
		goto set_tx_fail;

	ret = nbl_serv_set_rx_rings(ring_mgt, param->netdev, dev);
	if (ret)
		goto set_rx_fail;

	ret = nbl_serv_set_vectors(serv_mgt, param->netdev, dev);
	if (ret)
		goto set_vectors_fail;

	ret = nbl_serv_register_xdp_rxq(serv_mgt, ring_mgt);
	if (ret)
		goto register_xdp_err;

	return 0;

register_xdp_err:
	nbl_serv_remove_vectors(ring_mgt, dev);
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

	nbl_serv_unregister_xdp_rxq(serv_mgt, ring_mgt);
	nbl_serv_remove_vectors(ring_mgt, dev);
	nbl_serv_remove_rx_ring(ring_mgt, dev);
	nbl_serv_remove_tx_ring(ring_mgt, dev);

	disp_ops->remove_rings(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static void nbl_serv_set_mask_en(void *priv, bool enable)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_ring_mgt *ring_mgt;

	ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);

	ring_mgt->net_msix_mask_en = enable;
}

static int nbl_serv_start_net_flow(void *priv, struct net_device *netdev, u16 vsi_id, u16 vid,
				   bool trusted)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_serv_vlan_node *vlan_node;
	u8 mac[ETH_ALEN];
	int ret = 0;

	flow_mgt->unicast_flow_enable = true;
	flow_mgt->multicast_flow_enable = true;
	/* Clear cfgs, in case this function exited abnormaly last time */
	disp_ops->clear_accel_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);
	disp_ops->clear_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);
	disp_ops->set_mtu(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
			  NBL_COMMON_TO_VSI_ID(common), netdev->mtu);
	if (!common->is_vf)
		disp_ops->config_fd_flow_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       NBL_CHAN_FDIR_RULE_NORMAL, vsi_id, 1);

	if (!list_empty(&flow_mgt->vlan_list))
		return -ECONNRESET;

	ret = disp_ops->add_multi_rule(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);
	if (ret)
		goto add_multi_fail;

	vlan_node = nbl_serv_alloc_vlan_node();
	if (!vlan_node)
		goto alloc_fail;

	flow_mgt->vid = vid;
	vlan_node->vid = vid;
	ether_addr_copy(flow_mgt->mac, netdev->dev_addr);
	rtnl_lock();
	ret = nbl_serv_update_vlan_node_effective(serv_mgt, vlan_node, 1, vsi_id);
	rtnl_unlock();
	if (ret)
		goto add_macvlan_fail;

	rtnl_lock();
	list_add(&vlan_node->node, &flow_mgt->vlan_list);
	rtnl_unlock();
	flow_mgt->vlan_list_cnt++;

	memset(mac, 0xFF, ETH_ALEN);
	rtnl_lock();
	ret = nbl_serv_add_submac_node(serv_mgt, mac, vsi_id, 0);
	rtnl_unlock();
	if (ret)
		goto add_submac_failed;

	/*if flow_mgt->promisc is allmulti, this means that during resume,
	 *flow_mgt->trusted_en is the value awating resumption, can't change to trusted
	 */
	if (flow_mgt->promisc & BIT(NBL_ALLMULTI)) {
		flow_mgt->promisc &= ~BIT(NBL_ALLMULTI);
		nbl_common_queue_work(&net_resource_mgt->rx_mode_async, false);
	} else {
		flow_mgt->trusted_en = trusted;
	}

	return 0;

add_submac_failed:
	rtnl_lock();
	nbl_serv_update_vlan_node_effective(serv_mgt, vlan_node, 0, vsi_id);
	list_del(&vlan_node->node);
	rtnl_unlock();
add_macvlan_fail:
	nbl_serv_free_vlan_node(vlan_node);
alloc_fail:
	disp_ops->del_multi_rule(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);
add_multi_fail:
	return ret;
}

static void nbl_serv_stop_net_flow(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct net_device *dev = net_resource_mgt->netdev;
	struct nbl_netdev_priv *net_priv = netdev_priv(dev);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_ch_prm_cfg_multi_mcast mcast;

	nbl_serv_del_all_submacs(serv_mgt, net_priv->data_vsi);
	nbl_serv_del_all_vlans(serv_mgt);

	if (!common->is_vf)
		disp_ops->config_fd_flow_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       NBL_CHAN_FDIR_RULE_NORMAL, vsi_id, 0);

	disp_ops->del_multi_rule(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);

	if (flow_mgt->promisc & BIT(NBL_ALLMULTI)) {
		mcast.vsi = vsi_id;
		mcast.enable = 0;
		disp_ops->cfg_multi_mcast(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &mcast);
	}

	memset(flow_mgt->mac, 0, sizeof(flow_mgt->mac));
}

static void nbl_serv_unregister_upcall_port(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->unregister_upcall_port(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static void nbl_serv_clear_flow(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->clear_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);
}

static int nbl_serv_set_promisc_mode(void *priv, struct nbl_ch_prm_set_promisc_mode *param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->set_promisc_mode(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);
}

static int nbl_serv_cfg_multi_mcast(void *priv, struct nbl_ch_prm_cfg_multi_mcast *param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->cfg_multi_mcast(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);
}

static int nbl_serv_set_lldp_flow(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->add_lldp_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);
}

static int nbl_serv_remove_lldp_flow(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->del_lldp_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);
}

static int nbl_serv_start_mgt_flow(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int ret = 0;

	ret = disp_ops->alloc_kt(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret)
		return ret;

	ret = disp_ops->setup_multi_group(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret)
		return ret;

	ret = disp_ops->setup_ecn_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret)
		return ret;
	ret = disp_ops->set_rdma_rx_vsi_remap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), true);
	return ret;
}

static void nbl_serv_stop_mgt_flow(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_tx_mirror_to_rdma mirror_param = {.mt_id = 0, .enable = false};

	disp_ops->remove_multi_group(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	disp_ops->remove_ecn_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	disp_ops->set_rdma_rx_vsi_remap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), false);
	disp_ops->configure_tx_mirror_to_rdma(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &mirror_param);
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

	return disp_ops->get_product_flex_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &cap_type);
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
						       &cap_type);
}

static int nbl_serv_enable_driver(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->set_driver_status(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), true);
	return 0;
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

	ret = disp_ops->init_queue(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret) {
		dev_err(dev, "queue_init failed\n");
		goto queue_init_fail;
	}

	ret = disp_ops->init_vsi(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
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
	enum nbl_fix_cap_type cap_type = NBL_NEED_DESTROY_CHIP;
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)p;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	if (!disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					   &cap_type))
		return 0;

	disp_ops->set_driver_status(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), false);
	return 0;
}

static int nbl_serv_configure_msix_map(void *priv, u16 func_id,
				       u16 num_net_msix, u16 num_others_msix,
				       bool net_msix_mask_en)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;
	struct nbl_ch_prm_cfg_msix_map msix_map;

	msix_map.sfid = func_id;
	msix_map.num_net_msix = num_net_msix;
	msix_map.num_others_msix = num_others_msix;
	msix_map.net_msix_mask_en = net_msix_mask_en;
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ret = disp_ops->configure_msix_map(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					   &msix_map);
	if (ret)
		return -EIO;

	return 0;
}

static int nbl_serv_destroy_msix_map(void *priv, u16 func_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ret = disp_ops->destroy_msix_map(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &func_id);
	if (ret)
		return -EIO;

	return 0;
}

static int nbl_serv_enable_mailbox_irq(void *priv, u16 func_id, u16 vector_id, bool enable_msix)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;
	struct nbl_ch_prm_enable_irq mbx_irq;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	mbx_irq.sfid = func_id;
	mbx_irq.vector_id = vector_id;
	mbx_irq.enable_msix = enable_msix;
	ret = disp_ops->enable_mailbox_irq(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &mbx_irq);
	if (ret)
		return -EIO;

	return 0;
}

static int nbl_serv_enable_abnormal_irq(void *priv, u16 func_id, u16 vector_id, bool enable_msix)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;
	struct nbl_ch_prm_enable_irq ab_irq;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ab_irq.sfid = func_id;
	ab_irq.vector_id = vector_id;
	ab_irq.enable_msix = enable_msix;
	ret = disp_ops->enable_abnormal_irq(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &ab_irq);
	if (ret)
		return -EIO;

	return 0;
}

static int nbl_serv_enable_sfp_plug_irq(void *priv, u16 vector_id, bool enable_msix)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;
	struct nbl_ch_prm_enable_irq irq;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	irq.vector_id = vector_id;
	irq.enable_msix = enable_msix;
	ret = disp_ops->enable_sfp_plug_irq(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    &irq);
	if (ret)
		return -EIO;

	return 0;
}

static irqreturn_t nbl_serv_clean_rings(int __always_unused irq, void *data)
{
	struct nbl_serv_vector *vector = (struct nbl_serv_vector *)data;

	vector->nbl_napi->irq_cnt++;
	/* set irq raised flag */
	atomic_set_release(&vector->nbl_napi->is_irq, 1);
	napi_schedule_irqoff(&vector->nbl_napi->napi);

	return IRQ_HANDLED;
}

static irqreturn_t nbl_serv_clean_rings_mask(int __always_unused irq, void *data)
{
	struct nbl_serv_vector *vector = (struct nbl_serv_vector *)data;

	vector->nbl_napi->irq_cnt++;
	if (napi_schedule_prep(&vector->nbl_napi->napi)) {
		vector->nbl_napi->mask_cnt++;
		writel(vector->irq_mask_data, vector->irq_enable_base);
		/* set irq raised flag */
		atomic_set_release(&vector->nbl_napi->is_irq, 1);
		__napi_schedule_irqoff(&vector->nbl_napi->napi);
	}

	return IRQ_HANDLED;
}

void nbl_serv_cpu_affinity_init(void *priv, u16 ring_num)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	int i;

	for (i = 0; i < ring_num; i++) {
		cpumask_set_cpu(cpumask_local_spread(i, dev_to_node(NBL_COMMON_TO_DEV(common))),
				&ring_mgt->vectors[i].cpumask);
		if (NBL_COMMON_TO_ETH_MAX_SPEED(common) < SPEED_100000)
			netif_set_xps_queue(ring_mgt->vectors[i].netdev,
					    &ring_mgt->vectors[i].cpumask, i);
	}
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

	for (i = 0; i < ring_mgt->xdp_ring_offset; i++) {
		tx_ring = &ring_mgt->tx_rings[i];
		rx_ring = &ring_mgt->rx_rings[i];
		vector = &ring_mgt->vectors[i];
		vector->tx_ring = tx_ring;
		vector->rx_ring = rx_ring;

		irq_num = msix_info->msix_entries[i].vector;
		snprintf(vector->name, sizeof(vector->name), "nbl_txrx%d@pci:%s",
			 i, pci_name(NBL_COMMON_TO_PDEV(common)));
		if (vector->irq_mask_data)
			ret = devm_request_irq(dev, irq_num, nbl_serv_clean_rings_mask, 0,
					       vector->name, vector);
		else
			ret = devm_request_irq(dev, irq_num, nbl_serv_clean_rings, 0,
					       vector->name, vector);
		if (ret) {
			nbl_err(common, NBL_DEBUG_INTR, "TxRx Queue %u requests MSIX irq failed with error %d",
				i, ret);
			goto request_irq_err;
		}
		if (!cpumask_empty(&vector->cpumask))
			irq_set_affinity_hint(irq_num, &vector->cpumask);
	}

	net_resource_mgt->num_net_msix = msix_info->msix_num;

	return 0;

request_irq_err:
	while (--i + 1) {
		vector = &ring_mgt->vectors[i];

		irq_num = msix_info->msix_entries[i].vector;
		irq_set_affinity_hint(irq_num, NULL);
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

	for (i = 0; i < ring_mgt->xdp_ring_offset; i++) {
		vector = &ring_mgt->vectors[i];

		irq_num = msix_info->msix_entries[i].vector;
		irq_set_affinity_hint(irq_num, NULL);
		devm_free_irq(dev, irq_num, vector);
	}
}

static u16 nbl_serv_get_global_vector(void *priv, u16 local_vector_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_get_global_vec global_vec;

	global_vec.vsi_id = NBL_COMMON_TO_VSI_ID(common);
	global_vec.vector_id = local_vector_id;
	return disp_ops->get_global_vector(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &global_vec);
}

static u16 nbl_serv_get_vsi_id(void *priv, u16 func_id, u16 type)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_get_vsi param;

	param.sfid = func_id;
	param.type = type;
	return disp_ops->get_vsi_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param);
}

static int nbl_serv_get_my_pf(void *priv, u16 *sfid, u8 *my_pf)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_my_pf(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), sfid, my_pf);
}

static int nbl_serv_get_eth_id(void *priv, struct nbl_ch_prm_get_eth_id *param,
			       struct nbl_ch_prm_get_eth_id *output)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_eth_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param, output);
}

void nbl_serv_get_rep_drop_stats(struct nbl_service_mgt *serv_mgt, u16 rep_vsi_id,
				 struct nbl_rep_stats *rep_stats)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_serv_rep_drop *rep_drop;
	u16 rep_data_index;

	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	rep_data_index = disp_ops->get_rep_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &rep_vsi_id);
	if (rep_data_index >= net_resource_mgt->num_vfs)
		return;

	rep_drop = &net_resource_mgt->rep_drop[rep_data_index];
	rep_stats->dropped = rep_drop->tx_dropped;
}

static void nbl_serv_rep_get_stats64(struct net_device *netdev, struct rtnl_link_stats64 *stats)
{
	struct nbl_netdev_priv *rep_priv = netdev_priv(netdev);
	struct nbl_rep_stats rep_stats = { 0 };
	struct nbl_get_rep_stats_param rep_stats_prm = {0};
	struct nbl_adapter *adapter;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;

	adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	if (!adapter) {
		netdev_err(netdev, "rep get stats, adapter is null\n");
		return;
	}
	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	if (!stats) {
		netdev_err(netdev, "rep get stats, stats is null\n");
		return;
	}

	rep_stats_prm.rep_vsi_id = rep_priv->rep->rep_vsi_id;
	rep_stats_prm.is_tx = true;
	disp_ops->get_rep_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &rep_stats_prm, &rep_stats);
	stats->tx_packets += rep_stats.packets;
	stats->tx_bytes += rep_stats.bytes;

	rep_stats_prm.is_tx = false;
	disp_ops->get_rep_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &rep_stats_prm, &rep_stats);
	stats->rx_packets += rep_stats.packets;
	stats->rx_bytes += rep_stats.bytes;

	nbl_serv_get_rep_drop_stats(serv_mgt, rep_priv->rep->rep_vsi_id, &rep_stats);
	stats->tx_dropped += rep_stats.dropped;
	stats->rx_dropped = 0;
	stats->multicast = 0;
	stats->rx_errors = 0;
	stats->tx_errors = 0;
	stats->rx_length_errors = 0;
	stats->rx_crc_errors = 0;
	stats->rx_frame_errors = 0;
}

static void nbl_serv_rep_set_rx_mode(struct net_device *dev)
{
}

static int nbl_serv_rep_set_mac(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data)) {
		netdev_err(dev, "Temp to change a invalid mac address %pM\n", addr->sa_data);
		return -EADDRNOTAVAIL;
	}

	if (ether_addr_equal(dev->dev_addr, addr->sa_data))
		return 0;

	return -EOPNOTSUPP;
}

static int nbl_serv_rep_rx_add_vid(struct net_device *dev, __be16 proto, u16 vid)
{
	if (vid == NBL_DEFAULT_VLAN_ID)
		return 0;

	return -EAGAIN;
}

static int nbl_serv_rep_rx_kill_vid(struct net_device *dev, __be16 proto, u16 vid)
{
	if (vid == NBL_DEFAULT_VLAN_ID)
		return 0;

	return -EAGAIN;
}

static LIST_HEAD(nbl_serv_rep_block_cb_list);

static int nbl_serv_rep_setup_tc(struct net_device *dev, enum tc_setup_type type, void *type_data)
{
	struct nbl_netdev_priv *priv = netdev_priv(dev);

	if (!priv)
		return -EINVAL;

	switch (type) {
	case TC_SETUP_BLOCK: {
		return flow_block_cb_setup_simple((struct flow_block_offload *)type_data,
						  &nbl_serv_rep_block_cb_list,
						  nbl_serv_setup_tc_block_cb,
						  priv, priv, true);
	}
	default:
		return -EOPNOTSUPP;
	}
}

static int nbl_serv_rep_get_phys_port_name(struct net_device *dev, char *name, size_t len)
{
	struct nbl_netdev_priv *priv = netdev_priv(dev);
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(dev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u16 vf_base_vsi_id;
	u16 vf_id;
	u8 pf_id;

	pf_id = common->eth_id;
	if ((NBL_COMMON_TO_ETH_MODE(common) == NBL_TWO_ETHERNET_PORT) && common->eth_id == 2)
		pf_id = 1;

	vf_base_vsi_id = disp_ops->get_vf_base_vsi_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						      NBL_COMMON_TO_MGT_PF(common));
	vf_id =  priv->rep->rep_vsi_id - vf_base_vsi_id;
	if (snprintf(name, len, "pf%uvf%u", pf_id, vf_id) >= len)
		return -EINVAL;
	return 0;
}

static int nbl_serv_rep_get_port_parent_id(struct net_device *dev, struct netdev_phys_item_id *ppid)
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

static struct nbl_indr_dev_priv *nbl_find_indr_dev_priv(void *priv, struct net_device *netdev,
							int binder_type)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_indr_dev_priv *indr_priv;

	if (!netdev)
		return NULL;

	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	list_for_each_entry(indr_priv, &net_resource_mgt->indr_dev_priv_list, list)
		if (indr_priv->indr_dev == netdev && indr_priv->binder_type == binder_type)
			return indr_priv;

	return NULL;
}

static void nbl_serv_indr_dev_block_unbind(void *priv)
{
	struct nbl_indr_dev_priv *indr_priv = priv;
	struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(indr_priv->dev_priv);
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);

	list_del(&indr_priv->list);
	devm_kfree(dev, indr_priv);
}

static LIST_HEAD(nbl_serv_indr_block_cb_list);

static int nbl_serv_indr_dev_setup_block(struct net_device *netdev, struct Qdisc *sch,
					 struct nbl_netdev_priv *dev_priv,
					 struct flow_block_offload *flow_bo,
					 flow_setup_cb_t *setup_cb, void *data,
					 void (*cleanup)(struct flow_block_cb *block_cb))
{
	struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(dev_priv);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct nbl_indr_dev_priv *indr_priv = NULL;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NULL;
	struct flow_block_cb *block_cb = NULL;

	if (flow_bo->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS &&
	    (flow_bo->binder_type == FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS &&
	    !netif_is_ovs_master(netdev)))
		return -EOPNOTSUPP;

	flow_bo->unlocked_driver_cb = true;
	flow_bo->driver_block_list = &nbl_serv_indr_block_cb_list;
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	switch (flow_bo->command) {
	case FLOW_BLOCK_BIND:
		indr_priv = nbl_find_indr_dev_priv(serv_mgt, netdev, flow_bo->binder_type);
		if (indr_priv)
			return -EEXIST;

		indr_priv = devm_kzalloc(dev, sizeof(struct nbl_indr_dev_priv), GFP_KERNEL);
		if (!indr_priv)
			return -ENOMEM;

		indr_priv->indr_dev = netdev;
		indr_priv->dev_priv = dev_priv;
		indr_priv->binder_type = flow_bo->binder_type;
		list_add_tail(&indr_priv->list, &net_resource_mgt->indr_dev_priv_list);

		block_cb = flow_indr_block_cb_alloc(setup_cb, indr_priv, indr_priv,
						    nbl_serv_indr_dev_block_unbind, flow_bo,
						    netdev, sch, data, dev_priv, cleanup);
		if (IS_ERR(block_cb)) {
			netdev_err(netdev, "indr block cb alloc fail\n");
			list_del(&indr_priv->list);
			devm_kfree(dev, indr_priv);
			return PTR_ERR(block_cb);
		}
		flow_block_cb_add(block_cb, flow_bo);
		list_add_tail(&block_cb->driver_list, &nbl_serv_indr_block_cb_list);
		break;
	case FLOW_BLOCK_UNBIND:
		indr_priv = nbl_find_indr_dev_priv(serv_mgt, netdev, flow_bo->binder_type);
		if (!indr_priv)
			return -ENOENT;

		block_cb = flow_block_cb_lookup(flow_bo->block, setup_cb, indr_priv);
		if (!block_cb)
			return -ENOENT;
		flow_indr_block_cb_remove(block_cb, flow_bo);
		list_del(&block_cb->driver_list);
		break;
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int nbl_serv_indr_dev_setup_tc(struct net_device *dev, struct Qdisc *sch, void *cb_priv,
				      enum tc_setup_type type, void *type_data, void *data,
				      void (*cleanup)(struct flow_block_cb *block_cb))
{
	struct nbl_netdev_priv *priv = cb_priv;

	if (!priv)
		return -EINVAL;

	switch (type) {
	case TC_SETUP_BLOCK:
		return nbl_serv_indr_dev_setup_block(dev, sch, priv, type_data,
						     nbl_serv_indr_setup_tc_block_cb,
						     data, cleanup);
	default:
		return -EOPNOTSUPP;
	}
}

static void nbl_serv_get_rep_feature(void *priv, struct nbl_register_net_result *register_result)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->get_rep_feature(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), register_result);
}

static void nbl_serv_get_rep_queue_num(void *priv, u8 *base_queue_id, u8 *rep_queue_num)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);

	*base_queue_id = (u8)ring_mgt->vsi_info[NBL_VSI_CTRL].ring_offset;
	*rep_queue_num = (u8)ring_mgt->vsi_info[NBL_VSI_CTRL].ring_num;
}

static void nbl_serv_get_rep_queue_info(void *priv, u16 *queue_num, u16 *queue_size)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_get_queue_info param = { 0 };

	disp_ops->get_rep_queue_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param);
	*queue_num = param.queue_num;
	*queue_size = param.queue_size;
}

static void nbl_serv_get_user_queue_info(void *priv, u16 *queue_num, u16 *queue_size, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_get_queue_info param = { 0 };

	disp_ops->get_user_queue_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id, &param);
	*queue_num = param.queue_num;
	*queue_size = param.queue_size;
}

static int nbl_serv_rep_enqueue(struct sk_buff *skb,
				struct nbl_serv_rep_queue_mgt *rep_queue_mgt)
{
	if (rep_queue_mgt->size == 0)
		return -EINVAL;

	return ptr_ring_produce(&rep_queue_mgt->ring, skb);
}

static struct sk_buff *nbl_serv_rep_dequeue(struct nbl_serv_rep_queue_mgt *rep_queue_mgt)
{
	struct sk_buff *skb;

	if (rep_queue_mgt->size == 0)
		return NULL;

	if (__ptr_ring_empty(&rep_queue_mgt->ring))
		skb = NULL;
	else
		skb = __ptr_ring_consume(&rep_queue_mgt->ring);

	if (unlikely(!skb)) {
		/* order the failed consume against the empty re-check below */
		smp_mb__after_atomic();
		if (!__ptr_ring_empty(&rep_queue_mgt->ring))
			skb = __ptr_ring_consume(&rep_queue_mgt->ring);
	}

	return skb;
}

static inline bool nbl_serv_rep_queue_mgt_start(struct nbl_serv_rep_queue_mgt *rep_queue_mgt)
{
	return spin_trylock(&rep_queue_mgt->seq_lock);
}

static inline void nbl_serv_rep_queue_mgt_end(struct nbl_serv_rep_queue_mgt *rep_queue_mgt)
{
	spin_unlock(&rep_queue_mgt->seq_lock);
}

static void nbl_serv_rep_update_drop_stats(void *priv, struct sk_buff *skb)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	u16 rep_vsi_id;
	u16 rep_data_index;

	rep_vsi_id = *(u16 *)&skb->cb[NBL_SKB_FILL_VSI_ID_OFF];
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	rep_data_index = disp_ops->get_rep_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &rep_vsi_id);
	dev_kfree_skb_any(skb);
	if (rep_data_index >= net_resource_mgt->num_vfs)
		return;

	u64_stats_update_begin(&net_resource_mgt->rep_drop[rep_data_index].rep_drop_syncp);
	net_resource_mgt->rep_drop[rep_data_index].tx_dropped++;
	u64_stats_update_end(&net_resource_mgt->rep_drop[rep_data_index].rep_drop_syncp);
}

static void nbl_serv_rep_queue_mgt_run(struct nbl_serv_rep_queue_mgt *rep_queue_mgt,
				       struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_resource_pt_ops *pt_ops = NBL_ADAPTER_TO_RES_PT_OPS(adapter);
	struct sk_buff *skb;
	netdev_tx_t ret = NETDEV_TX_OK;
	int i = 0;

	skb = nbl_serv_rep_dequeue(rep_queue_mgt);
	if (!skb)
		return;
	for (; skb; skb = nbl_serv_rep_dequeue(rep_queue_mgt)) {
		ret = pt_ops->rep_xmit(skb, rep_queue_mgt->netdev);
		if (ret == NETDEV_TX_BUSY) {
			if (net_ratelimit())
				netdev_dbg(netdev, "dequeue skb tx busy!\n");
			/* never hang in sirq too long, so if a tx_busy is returned, drop it */
			nbl_serv_rep_update_drop_stats(serv_mgt, skb);
		}
		if (i++ >= NBL_DEFAULT_REP_TX_MAX_NUM)
			return;
	}
}

static netdev_tx_t nbl_serv_rep_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct nbl_netdev_priv *rep_priv = netdev_priv(netdev);
	struct nbl_adapter *adapter;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_rep_queue_mgt *rep_queue_mgt;
	int ret;
	u8 rep_queue_idx;
	u8 i;
	bool has_locked_flag = false;

	adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);

	rep_queue_idx = (rep_priv->rep->rep_vsi_id - 1) % rep_priv->rep->rep_queue_num;
	rep_queue_mgt = &serv_mgt->rep_queue_mgt[rep_queue_idx];
	skb->queue_mapping = rep_queue_idx + rep_priv->rep->base_queue_id;
	*(u16 *)(&skb->cb[NBL_SKB_FILL_VSI_ID_OFF]) = rep_priv->rep->rep_vsi_id;
	skb->cb[NBL_SKB_FILL_EXT_HDR_OFF] = NBL_REP_FILL_EXT_HDR;
	ret = nbl_serv_rep_enqueue(skb, rep_queue_mgt);

	if (unlikely(ret)) {
		if (net_ratelimit())
			netdev_info(netdev, "rep enqueue fail, size:%d, rep_vsi_id:%d!!\n",
				    rep_queue_mgt->size, rep_priv->rep->rep_vsi_id);
	}
	for (i = 0; i < NBL_DEFAULT_REP_TX_RETRY_NUM; i++) {
		if (nbl_serv_rep_queue_mgt_start(rep_queue_mgt)) {
			has_locked_flag = true;
			nbl_serv_rep_queue_mgt_run(rep_queue_mgt, netdev);
			nbl_serv_rep_queue_mgt_end(rep_queue_mgt);
		}
	}

	if (has_locked_flag) {
		if (ret)
			ret = NET_XMIT_CN;
		else
			ret = NET_XMIT_SUCCESS;
	}

	if (likely(ret)) {
		/* enqueue failed but get lock succ, need a retry */
		if (ret == NET_XMIT_CN) {
			return NETDEV_TX_BUSY;
		} else if (ret == NET_XMIT_SUCCESS) {
			/* enqueue succ and get lock succ, rep_xmit regard as a ok */
			return NETDEV_TX_OK;
		}
		/* enqueue and get lock failed, free skb and no need a retry */
		nbl_serv_rep_update_drop_stats(serv_mgt, skb);
		return NETDEV_TX_OK;
	}

	/* enqueue succ but get lock failed, rep_xmit regard as a ok */
	return NETDEV_TX_OK;
}

static int nbl_serv_alloc_rep_queue_mgt(void *priv, struct net_device *netdev)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct device *dev;
	int i, ret;
	u8 base_queue_id;
	u8 rep_queue_num;

	if (!serv_mgt)
		return -EINVAL;

	dev = NBL_SERV_MGT_TO_DEV(serv_mgt);

	dev_info(dev, "nbl serv alloc rep queue mgt start\n");
	nbl_serv_get_rep_queue_num(serv_mgt, &base_queue_id, &rep_queue_num);
	dev_dbg(dev, "base_queue_id:%u, rep_queue_num:%u\n", base_queue_id, rep_queue_num);

	serv_mgt->rep_queue_mgt = devm_kcalloc(dev, rep_queue_num,
					       sizeof(struct nbl_serv_rep_queue_mgt), GFP_KERNEL);
	if (!serv_mgt->rep_queue_mgt)
		return -ENOMEM;
	for (i = 0; i < rep_queue_num; i++) {
		ret = ptr_ring_init(&serv_mgt->rep_queue_mgt[i].ring,
				    NBL_REP_QUEUE_MGT_DESC_NUM, GFP_KERNEL);
		if (ret) {
			dev_err(dev, "ptr ring init failed\n");
			goto free_ptr_ring;
		}

		spin_lock_init(&serv_mgt->rep_queue_mgt[i].seq_lock);
		serv_mgt->rep_queue_mgt[i].size = NBL_REP_QUEUE_MGT_DESC_NUM;
		serv_mgt->rep_queue_mgt[i].netdev = netdev;
		dev_info(dev, "rep_queue_mgt init success\n");
	}
	dev_info(dev, "nbl serv alloc rep queue mgt end\n");

	return 0;

free_ptr_ring:
	for (; i >= 0; i--)
		ptr_ring_cleanup(&serv_mgt->rep_queue_mgt[i].ring, 0);

	devm_kfree(dev, serv_mgt->rep_queue_mgt);
	serv_mgt->rep_queue_mgt = NULL;
	return -ENOMEM;
}

static int nbl_serv_free_rep_queue_mgt(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct device *dev;
	int i;
	u8 base_queue_id;
	u8 rep_queue_num;

	if (!serv_mgt)
		return -EINVAL;

	dev = NBL_SERV_MGT_TO_DEV(serv_mgt);
	if (!serv_mgt->rep_queue_mgt)
		return -EINVAL;

	nbl_serv_get_rep_queue_num(serv_mgt, &base_queue_id, &rep_queue_num);
	for (i = 0; i < rep_queue_num; i++)
		ptr_ring_cleanup(&serv_mgt->rep_queue_mgt[i].ring, 0);

	dev_info(dev, "ptr ring cleanup\n");
	devm_kfree(dev, serv_mgt->rep_queue_mgt);
	serv_mgt->rep_queue_mgt = NULL;

	return 0;
}

static int nbl_serv_set_eswitch_mode(void *priv, u16 switch_mode)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common =  NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_ch_prm_set_func_vld prm = {0};

	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	if (switch_mode == NBL_ESWITCH_OFFLOADS) {
		prm.eth_id = common->eth_id;
		prm.vld = false;
		disp_ops->set_dport_fc_th_vld(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
		if (net_resource_mgt->lag_info && net_resource_mgt->lag_info->lag_num > 1)
			disp_ops->set_shaping_dport_vld(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							&prm);
	} else {
		prm.eth_id = common->eth_id;
		prm.vld = true;
		disp_ops->set_dport_fc_th_vld(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
		if (net_resource_mgt->lag_info && net_resource_mgt->lag_info->lag_num > 1)
			disp_ops->set_shaping_dport_vld(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							&prm);
	}
	return disp_ops->set_eswitch_mode(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &switch_mode);
}

static u16 nbl_serv_get_eswitch_mode(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_eswitch_mode(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_alloc_rep_data(void *priv, struct nbl_alloc_rep_data_param *param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct device *dev;

	if (!serv_mgt)
		return -EINVAL;

	dev = NBL_SERV_MGT_TO_DEV(serv_mgt);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	net_resource_mgt->rep_drop = devm_kcalloc(dev, param->num_vfs,
						  sizeof(struct nbl_serv_rep_drop),
						  GFP_KERNEL);
	if (!net_resource_mgt->rep_drop)
		return -ENOMEM;

	net_resource_mgt->num_vfs = param->num_vfs;
	return disp_ops->alloc_rep_data(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);
}

static void nbl_serv_free_rep_data(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct device *dev;

	if (!serv_mgt)
		return;

	dev = NBL_SERV_MGT_TO_DEV(serv_mgt);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	if (net_resource_mgt->rep_drop)
		devm_kfree(dev, net_resource_mgt->rep_drop);
	disp_ops->free_rep_data(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static void nbl_serv_set_rep_netdev_info(void *priv, void *rep_data)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->set_rep_netdev_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), rep_data);
}

static void nbl_serv_unset_rep_netdev_info(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->unset_rep_netdev_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_disable_phy_flow(void *priv, u8 eth_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->disable_phy_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &eth_id);
}

static int nbl_serv_enable_phy_flow(void *priv, u8 eth_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->enable_phy_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &eth_id);
}

static void nbl_serv_init_acl(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->init_acl(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static void nbl_serv_uninit_acl(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->uninit_acl(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_set_upcall_rule(void *priv, u8 eth_id, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_ch_prm_set_upcall param = {0};

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->add_nd_upcall_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_id, 0);

	param.eth_id = eth_id;
	param.vsi_id = vsi_id;

	return disp_ops->set_upcall_rule(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param);
}

static int nbl_serv_unset_upcall_rule(void *priv, u8 eth_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->del_nd_upcall_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));

	return disp_ops->unset_upcall_rule(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &eth_id);
}

static int nbl_serv_switchdev_init_cmdq(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	return disp_ops->switchdev_init_cmdq(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_switchdev_deinit_cmdq(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	return disp_ops->switchdev_deinit_cmdq(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_set_tc_flow_info(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->set_tc_flow_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_unset_tc_flow_info(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	return disp_ops->unset_tc_flow_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_get_tc_flow_info(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_tc_flow_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_register_indr_dev_tc_offload(void *priv, struct net_device *netdev)
{
	struct nbl_netdev_priv *dev_priv = netdev_priv(netdev);

	return flow_indr_dev_register(nbl_serv_indr_dev_setup_tc, dev_priv);
}

static void nbl_serv_unregister_indr_dev_tc_offload(void *priv, struct net_device *netdev)
{
	struct nbl_netdev_priv *dev_priv = netdev_priv(netdev);

	flow_indr_dev_unregister(nbl_serv_indr_dev_setup_tc, dev_priv,
				 nbl_serv_indr_dev_block_unbind);
}

static void nbl_serv_set_lag_info(void *priv, u8 lag_id, u16 lag_num)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(common);

	net_resource_mgt->lag_info = devm_kzalloc(dev, sizeof(struct nbl_serv_lag_info),
						  GFP_KERNEL);
	if (!net_resource_mgt->lag_info)
		return;

	net_resource_mgt->lag_info->lag_id = lag_id;
	net_resource_mgt->lag_info->lag_num = lag_num;

	dev_info(dev, "set lag info, lag_id:%d, mem_num:%d\n", lag_id, lag_num);
}

static void nbl_serv_unset_lag_info(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(common);

	if (net_resource_mgt->lag_info) {
		devm_kfree(dev, net_resource_mgt->lag_info);
		net_resource_mgt->lag_info = NULL;
	}
}

static void nbl_serv_set_netdev_ops(void *priv,
				    const struct net_device_ops *netdev_ops,
				    bool is_pf)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct device *dev = NBL_SERV_MGT_TO_DEV(serv_mgt);

	dev_info(dev, "set netdev ops:%p is_pf:%d\n", netdev_ops, is_pf);
	if (is_pf)
		net_resource_mgt->netdev_ops.pf_netdev_ops = (void *)netdev_ops;
	else
		net_resource_mgt->netdev_ops.rep_netdev_ops = (void *)netdev_ops;
}

static int nbl_serv_set_lag_status(void *priv, bool *lag_en)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->set_lag_status(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), lag_en);
}

static int nbl_serv_enable_lag_protocol(void *priv,
					struct nbl_ch_prm_enable_lag_protocol *param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int ret = 0;

	ret = disp_ops->enable_lag_protocol(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);
	if (param->lag_en)
		ret = disp_ops->add_lag_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					     &NBL_COMMON_TO_VSI_ID(common));
	else
		disp_ops->del_lag_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				       &NBL_COMMON_TO_VSI_ID(common));
	return ret;
}

static int nbl_serv_cfg_lag_hash_algorithm(void *priv,
					   struct nbl_ch_prm_cfg_lag_hash_algorithm *param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->cfg_lag_hash_algorithm(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);
}

static int nbl_serv_cfg_lag_member_fwd(void *priv, struct nbl_ch_prm_cfg_lag_member_fwd *param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_cfg_lag_mcc mcc_prm = {0};

	mcc_prm.eth_id = param->eth_id;
	mcc_prm.lag_id = param->lag_id;
	mcc_prm.enable = param->fwd;
	disp_ops->cfg_lag_mcc(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &mcc_prm);
	return disp_ops->cfg_lag_member_fwd(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);
}

static int nbl_serv_cfg_lag_member_list(void *priv, struct nbl_lag_member_list_param *param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common =  NBL_SERV_MGT_TO_COMMON(serv_mgt);
	int ret = 0;
	u16 cur_eswitch_mode = NBL_ESWITCH_NONE;
	bool shaping_vld = true;
	struct nbl_ch_prm_set_func_vld prm = {0};

	ret = disp_ops->cfg_lag_member_list(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);
	if (ret)
		return ret;

	ret = disp_ops->cfg_duppkt_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);
	if (ret)
		return ret;

	cur_eswitch_mode = disp_ops->get_eswitch_mode(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (cur_eswitch_mode == NBL_ESWITCH_OFFLOADS) {
		shaping_vld = param->lag_num > 1 ? false : true;
		prm.eth_id = common->eth_id;
		prm.vld = shaping_vld;
		disp_ops->set_shaping_dport_vld(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
	}

	ret = disp_ops->cfg_eth_bond_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);
	if (ret)
		return ret;

	ret = disp_ops->cfg_duppkt_mcc(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);

	return ret;
}

static int nbl_serv_cfg_lag_member_up_attr(void *priv,
					   struct nbl_ch_prm_cfg_lag_member_up_attr *param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->cfg_lag_member_up_attr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);
}

static void nbl_serv_update_drop_stats(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	if (!net_resource_mgt->hw_stats.update_ustore)
		return;

	disp_ops->get_pkt_drop_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static void nbl_serv_net_stats_update_task(struct work_struct *work)
{
	struct nbl_serv_net_resource_mgt *serv_net_resource_mgt =
		container_of(work, struct nbl_serv_net_resource_mgt, net_stats_update);
	struct nbl_service_mgt *serv_mgt;

	serv_mgt = serv_net_resource_mgt->serv_mgt;
	nbl_serv_update_stats(serv_mgt, false);
	nbl_serv_update_drop_stats(serv_mgt);
}

static void nbl_serv_rx_mode_async_task(struct work_struct *work)
{
	struct nbl_serv_net_resource_mgt *serv_net_resource_mgt =
		container_of(work, struct nbl_serv_net_resource_mgt, rx_mode_async);
	struct nbl_service_mgt *serv_mgt = serv_net_resource_mgt->serv_mgt;
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct net_device *netdev = serv_net_resource_mgt->netdev;
	struct sockaddr addr = {0};

	if (!ether_addr_equal(flow_mgt->mac, netdev->dev_addr)) {
		ether_addr_copy(addr.sa_data, netdev->dev_addr);
		rtnl_lock();
		nbl_serv_set_mac(netdev, &addr);
		rtnl_unlock();
	}

	nbl_modify_submacs(serv_net_resource_mgt);
	nbl_modify_promisc_mode(serv_net_resource_mgt);
}

static void nbl_serv_net_task_service_timer(struct timer_list *t)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
		container_of(t, struct nbl_serv_net_resource_mgt, serv_timer);
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(net_resource_mgt->netdev);
	struct nbl_service_mgt *serv_mgt = net_resource_mgt->serv_mgt;
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);

	mod_timer(&net_resource_mgt->serv_timer,
		  round_jiffies(net_resource_mgt->serv_timer_period + jiffies));

	if (test_bit(NBL_PCI_ERR_RECOVERING, adapter->state))
		return;

	nbl_common_queue_work(&net_resource_mgt->net_stats_update, false);
	if (flow_mgt->pending_async_work) {
		nbl_common_queue_work(&net_resource_mgt->rx_mode_async, false);
		flow_mgt->pending_async_work = 0;
	}
}

static void nbl_serv_setup_flow_mgt(struct nbl_serv_flow_mgt *flow_mgt)
{
	int i = 0;

	INIT_LIST_HEAD(&flow_mgt->vlan_list);
	for (i = 0; i < NBL_SUBMAC_MAX; i++)
		INIT_LIST_HEAD(&flow_mgt->submac_list[i]);
}

static void nbl_serv_register_restore_netdev_queue(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt);

	if (!chan_ops->check_queue_exist(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
					 NBL_CHAN_TYPE_MAILBOX))
		return;

	chan_ops->register_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
			       NBL_CHAN_MSG_STOP_ABNORMAL_SW_QUEUE,
			       nbl_serv_chan_stop_abnormal_sw_queue_resp, serv_mgt);

	chan_ops->register_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
			       NBL_CHAN_MSG_RESTORE_NETDEV_QUEUE,
			       nbl_serv_chan_restore_netdev_queue_resp, serv_mgt);

	chan_ops->register_msg(NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt),
			       NBL_CHAN_MSG_RESTART_NETDEV_QUEUE,
			       nbl_serv_chan_restart_netdev_queue_resp, serv_mgt);
}

static void nbl_serv_set_wake(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	u8 eth_id = NBL_COMMON_TO_ETH_ID(common);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	if (!common->is_vf && common->is_ocp)
		disp_ops->set_wol(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), eth_id, common->wol_ena);
}

static void nbl_serv_remove_net_resource_mgt(void *priv)
{
	struct device *dev;
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	dev = NBL_COMMON_TO_DEV(common);

	nbl_serv_set_wake(serv_mgt);
	nbl_common_release_task(&net_resource_mgt->rx_mode_async);
	nbl_common_release_task(&net_resource_mgt->net_stats_update);
	nbl_common_release_task(&net_resource_mgt->tx_timeout);

	if (common->is_vf) {
		nbl_common_release_task(&net_resource_mgt->update_link_state);
		nbl_common_release_task(&net_resource_mgt->update_vlan);
		nbl_common_release_task(&net_resource_mgt->update_mirror_outputport);
	}

	nbl_serv_unset_lag_info(priv);
	devm_kfree(dev, net_resource_mgt);
	NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt) = NULL;
}

static void nbl_serv_stop_net_resource_mgt(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	timer_delete_sync(&net_resource_mgt->serv_timer);
}

static void nbl_serv_stop_net_dev_timer(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	timer_delete_sync(&net_resource_mgt->serv_timer);
}

static void nbl_serv_start_net_dev_timer(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	mod_timer(&net_resource_mgt->serv_timer,
		  round_jiffies(net_resource_mgt->serv_timer_period + jiffies));
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
			       &eth_id, &net_resource_mgt->phy_caps);

	/* disable wol when driver init */
	if (!common->is_vf && common->is_ocp)
		ret = disp_ops->set_wol(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), eth_id, false);

	return ret;
}

static void nbl_init_qos_config(struct nbl_serv_net_resource_mgt *net_resource_mgt)
{
	struct nbl_service_mgt *serv_mgt = net_resource_mgt->serv_mgt;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_ch_prm_configure_qos qos_param = {0};
	struct nbl_ch_prm_get_pfc_buffer_size param = {0};
	struct nbl_ch_prm_get_pfc_buffer_size_resp output = {0};
	int i;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	if (common->is_vf)
		return;

	qos_info->rdma_bw = NBL_MAX_BW >> 1;
	qos_info->rdma_rate = NBL_COMMON_TO_ETH_MAX_SPEED(common);
	qos_info->net_rate = NBL_COMMON_TO_ETH_MAX_SPEED(common);
#ifdef CONFIG_DCB
	qos_info->dcbx_mode = DCB_CAP_DCBX_HOST | DCB_CAP_DCBX_VER_IEEE | DCB_CAP_DCBX_VER_CEE;
#endif
	for (i = 0; i < NBL_DSCP_MAX; i++)
		qos_info->dscp2prio_map[i] = i / NBL_MAX_PFC_PRIORITIES;

	for (i = 0; i < NBL_MAX_PFC_PRIORITIES; i++) {
		param.eth_id =  NBL_COMMON_TO_ETH_ID(common);
		param.prio = i;
		disp_ops->get_pfc_buffer_size(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					      &param,
					      &output);
		qos_info->buffer_sizes[i][0] = output.xoff;
		qos_info->buffer_sizes[i][1] = output.xon;
	}
	qos_param.eth_id = NBL_COMMON_TO_ETH_ID(common);
	qos_param.trust = qos_info->trust_mode;
	memcpy(qos_param.pfc, qos_info->pfc, NBL_MAX_PFC_PRIORITIES);
	memcpy(qos_param.dscp2prio_map, qos_info->dscp2prio_map, NBL_DSCP_MAX);
	disp_ops->configure_qos(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &qos_param);
}

static int nbl_serv_init_hw_stats(void *priv, const struct nbl_init_param *param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	u8 eth_id = NBL_COMMON_TO_ETH_ID(common);
	struct nbl_serv_ring_vsi_info *vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	struct nbl_chan_param_drop_stats_resp drop_stats = {0};
	int ret = 0;

	net_resource_mgt->hw_stats.total_uvn_stat_pkt_drop =
		devm_kcalloc(dev, vsi_info->ring_num, sizeof(u64), GFP_KERNEL);
	if (!net_resource_mgt->hw_stats.total_uvn_stat_pkt_drop) {
		ret = -ENOMEM;
		goto alloc_total_uvn_stat_pkt_drop_fail;
	}

	if (param->caps.has_ctrl) {
		net_resource_mgt->hw_stats.update_ustore = true;
		nbl_serv_update_drop_stats(serv_mgt); /* call it before get ustore_init_stats */
	}

	if (!common->is_vf) {
		disp_ops->get_total_pkt_drop_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), 0,
						   STAT_TYPE_FAKE, &drop_stats);
		net_resource_mgt->hw_stats.start_fake_drop = drop_stats.rx_drop_packets;
		ret = disp_ops->get_total_pkt_drop_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							 eth_id, STAT_TYPE_USTORE, &drop_stats);
		if (ret)
			goto get_total_pkt_drop_stats_fail;
		net_resource_mgt->hw_stats.start_drop_stats.rx_drop_packets =
			drop_stats.rx_drop_packets;
		net_resource_mgt->hw_stats.start_drop_stats.rx_trun_packets =
			drop_stats.rx_trun_packets;
	}

	return 0;

get_total_pkt_drop_stats_fail:
	devm_kfree(dev, net_resource_mgt->hw_stats.total_uvn_stat_pkt_drop);
alloc_total_uvn_stat_pkt_drop_fail:
	return ret;
}

static int nbl_serv_remove_hw_stats(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(common);

	devm_kfree(dev, net_resource_mgt->hw_stats.total_uvn_stat_pkt_drop);
	return 0;
}

static int nbl_serv_get_rx_dropped(void *priv, u64 *rx_dropped, u64 *rx_dropped_queue_disable)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_chan_param_drop_stats_resp drop_stats = {0};
	void *disp = NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt);
	u8 eth_id = NBL_COMMON_TO_ETH_ID(common);
	int i = 0;

	for (i = 0; i < vsi_info->active_ring_num; i++)
		*rx_dropped += net_resource_mgt->hw_stats.total_uvn_stat_pkt_drop[i];

	if (!common->is_vf) {
		disp_ops->get_total_pkt_drop_stats(disp, eth_id, STAT_TYPE_USTORE, &drop_stats);
		*rx_dropped += drop_stats.rx_drop_packets -
			net_resource_mgt->hw_stats.start_drop_stats.rx_drop_packets;
		*rx_dropped += drop_stats.rx_trun_packets -
			net_resource_mgt->hw_stats.start_drop_stats.rx_trun_packets;

		disp_ops->get_total_pkt_drop_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						   eth_id, STAT_TYPE_RX_DROPPED_QUEUE_DISABLE,
						   &drop_stats);
		*rx_dropped_queue_disable = drop_stats.rx_drop_packets;
	}
	return 0;
}

static int nbl_serv_setup_net_resource_mgt(void *priv, struct net_device *netdev,
					   u16 vlan_proto, u16 vlan_tci, u32 rate)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct nbl_serv_net_resource_mgt *net_resource_mgt;

	net_resource_mgt = devm_kzalloc(dev, sizeof(struct nbl_serv_net_resource_mgt), GFP_KERNEL);
	if (!net_resource_mgt)
		return -ENOMEM;

	net_resource_mgt->netdev = netdev;
	net_resource_mgt->serv_mgt = serv_mgt;
	net_resource_mgt->vlan_proto = vlan_proto;
	net_resource_mgt->vlan_tci = vlan_tci;
	net_resource_mgt->max_tx_rate = rate;
	NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt) = net_resource_mgt;

	nbl_serv_register_restore_netdev_queue(serv_mgt);
	if (common->is_vf) {
		nbl_serv_register_link_forced_notify(serv_mgt);
		nbl_serv_register_vlan_notify(serv_mgt);
		nbl_serv_register_get_vf_stats(serv_mgt);
		nbl_serv_register_trust_notify(serv_mgt);
		nbl_serv_register_mirror_outputport_notify(serv_mgt);
	}

	timer_setup(&net_resource_mgt->serv_timer, nbl_serv_net_task_service_timer, 0);
	nbl_common_alloc_task(&net_resource_mgt->rx_mode_async, nbl_serv_rx_mode_async_task);
	nbl_common_alloc_task(&net_resource_mgt->net_stats_update, nbl_serv_net_stats_update_task);
	nbl_common_alloc_task(&net_resource_mgt->tx_timeout, nbl_serv_handle_tx_timeout);
	if (common->is_vf) {
		nbl_common_alloc_task(&net_resource_mgt->update_link_state,
				      nbl_serv_update_link_state);
		nbl_common_alloc_task(&net_resource_mgt->update_vlan,
				      nbl_serv_update_vlan);
		nbl_common_alloc_task(&net_resource_mgt->update_mirror_outputport,
				      nbl_serv_update_mirror_outputport);
	}

	INIT_LIST_HEAD(&net_resource_mgt->indr_dev_priv_list);
	INIT_LIST_HEAD(&net_resource_mgt->tmp_add_filter_list);
	INIT_LIST_HEAD(&net_resource_mgt->tmp_del_filter_list);
	net_resource_mgt->get_stats_jiffies = jiffies;
	nbl_serv_set_port_state_update(serv_mgt, true);

	return 0;
}

static void nbl_serv_start_net_resource_mgt(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	u32 delay_time;
	unsigned long hw_stats_delay_time = 0;

	net_resource_mgt->hw_stats_period = NBL_HW_STATS_PERIOD_SECONDS * HZ;
	net_resource_mgt->serv_timer_period = HZ;
	get_random_bytes(&delay_time, sizeof(delay_time));
	hw_stats_delay_time = delay_time % net_resource_mgt->hw_stats_period;
	mod_timer(&net_resource_mgt->serv_timer,
		  jiffies + net_resource_mgt->serv_timer_period + hw_stats_delay_time);

	nbl_serv_phy_init(net_resource_mgt);
	nbl_init_qos_config(net_resource_mgt);
}

static int nbl_serv_enable_adminq_irq(void *priv, u16 vector_id, bool enable_msix)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	int ret = 0;
	struct nbl_ch_prm_enable_irq irq;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	irq.vector_id = vector_id;
	irq.enable_msix = enable_msix;
	ret = disp_ops->enable_adminq_irq(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &irq);
	if (ret)
		return -EIO;

	return 0;
}

static int nbl_serv_enable_up_rdma_bypass(void *priv, u16 vsi_id, bool enable)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_flow_mgt *flow_mgt = NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt);
	struct nbl_enable_up_rdma_bypass_param bypass_prm;

	memset(&bypass_prm, 0, sizeof(bypass_prm));
	bypass_prm.vsi_id = vsi_id;
	bypass_prm.enable = enable;
	memcpy(bypass_prm.mac, flow_mgt->mac, ETH_ALEN);

	return disp_ops->enable_up_rdma_bypass(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       &bypass_prm);
}

static void nbl_serv_get_rdma_cap_num(void *priv, u16 *cap_num, u16 *my_cap_num)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->get_rdma_cap_num(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), cap_num, my_cap_num);
}

static void nbl_serv_setup_rdma_id(void *priv, struct ida *adev_ida, struct ida *grc_adev_ida,
				   struct mutex *lock)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->setup_rdma_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), adev_ida, grc_adev_ida, lock);
}

static void nbl_serv_remove_rdma_id(void *priv, struct ida *adev_ida, struct ida *grc_adev_ida,
				    struct mutex *lock)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->remove_rdma_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), adev_ida, grc_adev_ida, lock);
}

static int nbl_serv_register_rdma_grc_id(void *priv, u16 vsi_id, int *grc_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->register_rdma_grc_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id, grc_id);
}

static void nbl_serv_unregister_rdma_grc_id(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->unregister_rdma_grc_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);
}

static int nbl_serv_register_rdma(void *priv, u16 vsi_id, struct nbl_rdma_register_param *param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->register_rdma(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id, param);
}

static void nbl_serv_unregister_rdma(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->unregister_rdma(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);
}

static u8 __iomem *nbl_serv_get_hw_addr(void *priv, size_t *size)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_hw_addr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), size);
}

static u8 __iomem *nbl_serv_get_rdma_hw_addr(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_rdma_hw_addr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static u64 nbl_serv_get_real_hw_addr(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_real_hw_addr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);
}

static u16 nbl_serv_get_function_id(void *priv, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_function_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id);
}

static void nbl_serv_get_real_bdf(void *priv, u16 vsi_id, u8 *bus, u8 *dev, u8 *function)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_get_real_bdf output = {0};

	disp_ops->get_real_bdf(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id, &output);
	*bus = output.bus;
	*dev = output.dev;
	*function = output.function;
}

static int nbl_serv_get_devlink_info(struct devlink *devlink, struct devlink_info_req *req,
				     struct netlink_ext_ack *extack)
{
	struct nbl_devlink_priv *priv = devlink_priv(devlink);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv->priv;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	int ret = 0;

	ret = devlink_info_version_fixed_put(req, "FW Version:", common->firmware_version);
	if (ret)
		return ret;

	return ret;
}

/* Why do we need this?
 * Because the original function in kernel cannot handle when we set subvendor and subdevice
 * to be 0xFFFF, so write a correct one.
 */
static bool nbl_serv_pldmfw_op_pci_match_record(struct pldmfw *context,
						struct pldmfw_record *record)
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
	struct nbl_flash_image_param flash_prm = {0};
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

	flash_prm.module = component->identifier;
	flash_prm.data = component->component_data;
	flash_prm.len = data_len;
	ret = disp_ops->flash_image(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &flash_prm);
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

int nbl_serv_update_firmware(struct nbl_service_mgt *serv_mgt, const struct firmware *fw,
			     struct netlink_ext_ack *extack)
{
	struct nbl_serv_update_fw_priv priv = {{0}};
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
	irq_num->sfp_plug_irq_num =
		disp_ops->get_sfp_plug_irq_num(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_check_offload_status(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;
	bool is_down = false;
	int ret;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ret = disp_ops->check_offload_status(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &is_down);

	/* ovs down, need to delete related pmd flow rules */
	if (is_down)
		disp_ops->del_nd_upcall_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));

	return ret;
}

static int nbl_serv_get_chip_temperature(void *priv, enum nbl_hwmon_type type, u32 senser_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_get_hwmon hw_mon;

	hw_mon.type = type;
	hw_mon.senser_id = senser_id;
	return disp_ops->get_chip_temperature(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &hw_mon);
}

static int nbl_serv_get_module_temperature(void *priv, u8 eth_id, enum nbl_hwmon_type type)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_get_hwmon hw_mon;

	hw_mon.type = type;
	hw_mon.senser_id = eth_id;
	return disp_ops->get_module_temperature(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &hw_mon);
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

static int nbl_serv_update_template_config(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int ret = 0;

	ret = disp_ops->update_ring_num(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret)
		return ret;

	ret = disp_ops->update_rdma_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret)
		return ret;

	ret = disp_ops->update_rdma_mem_type(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret)
		return ret;

	ret = disp_ops->update_internal_cfg(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (ret)
		return ret;

	return 0;
}

static int nbl_serv_get_part_number(void *priv, char *part_number)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_part_number(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), part_number);
}

static int nbl_serv_get_serial_number(void *priv, char *serial_number)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_serial_number(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), serial_number);
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

static void nbl_serv_init_port(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->init_port(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
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

static int nbl_serv_process_sfp_plug_event(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->process_sfp_plug_event(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static int nbl_serv_get_owned_pf_bitmap(void *priv,
					unsigned long **owned_pf_bitmap, u8 *max_pf, u16 *bdf)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_owned_pf_bitmap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					     owned_pf_bitmap, max_pf, bdf);
}

static void nbl_serv_adapt_desc_gother(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	if (test_bit(NBL_FLAG_HIGH_THROUGHPUT, &serv_mgt->flags))
		disp_ops->set_desc_high_throughput(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	else
		disp_ops->adapt_desc_gother(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static void nbl_serv_process_qinfo_cfg(void *priv, u16 vfid)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->flr_qinfo_cfg(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vfid);
}

static void nbl_serv_process_flr(void *priv, u16 vfid)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->flr_clear_queues(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vfid);
	disp_ops->flr_clear_accel_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vfid);
	disp_ops->flr_clear_flows(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vfid);
	disp_ops->flr_clear_accel(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vfid);
	disp_ops->flr_clear_interrupt(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vfid);
	disp_ops->flr_clear_rdma(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vfid);
	disp_ops->flr_clear_net(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vfid);
}

static u16 nbl_serv_covert_vfid_to_vsi_id(void *priv, u16 vfid)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->covert_vfid_to_vsi_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vfid);
}

static int nbl_serv_register_vsi_info(void *priv, struct nbl_vsi_param *vsi_param)
{
	enum nbl_fix_cap_type cap_type = NBL_ITR_DYNAMIC;
	u16 vsi_index = vsi_param->index;
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u32 num_cpus;
	struct nbl_vsi_ring_param ring_prm;

	ring_mgt->vsi_info[vsi_index].vsi_index = vsi_index;
	ring_mgt->vsi_info[vsi_index].vsi_id = vsi_param->vsi_id;
	ring_mgt->vsi_info[vsi_index].ring_offset = vsi_param->queue_offset;
	ring_mgt->vsi_info[vsi_index].ring_num = vsi_param->queue_num;

	/* init active ring number before first open, guarantee fd direct config check success. */
	num_cpus = num_online_cpus();
	ring_mgt->vsi_info[vsi_index].active_ring_num = (u16)num_cpus > vsi_param->queue_num ?
							vsi_param->queue_num : (u16)num_cpus;

	if (disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  &cap_type))
		ring_mgt->vsi_info[vsi_index].itr_dynamic = true;

	/**
	 * Clear cfg, in case this function exited abnormally last time.
	 * only for data vsi, vf in vm only support data vsi.
	 * DPDK user vsi can not leak resource.
	 */
	if (vsi_index == NBL_VSI_DATA)
		disp_ops->clear_queues(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				       &vsi_param->vsi_id);

	ring_prm.vsi_index = vsi_index;
	ring_prm.ring_num = vsi_param->queue_num;
	ring_prm.ring_offset = vsi_param->queue_offset;
	disp_ops->register_vsi_ring(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &ring_prm);

	return disp_ops->register_vsi2q(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), vsi_index,
					vsi_param->vsi_id, vsi_param->queue_offset,
					vsi_param->queue_num);
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
	struct nbl_serv_st_mgt *st_mgt = NBL_SERV_MGT_TO_ST_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_passthrough_fw_cmd_param *param = NULL, *result = NULL;
	int ret = 0;

	if (st_mgt && st_mgt->real_st_name_valid)
		return -EOPNOTSUPP;

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

static int nbl_serv_process_st_info(struct nbl_service_mgt *serv_mgt,
				    unsigned int cmd, unsigned long arg)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_st_mgt *st_mgt = NBL_SERV_MGT_TO_ST_MGT(serv_mgt);
	struct nbl_st_info_param *param = NULL;
	int ret = 0;

	nbl_debug(common, NBL_DEBUG_ST, "Get st info\n");

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param)
		return -ENOMEM;

	strscpy(param->driver_name, NBL_DRIVER_NAME, sizeof(param->driver_name));
	if (net_resource_mgt && net_resource_mgt->netdev)
		strscpy(param->netdev_name[0], net_resource_mgt->netdev->name,
			sizeof(param->netdev_name[0]));

	strscpy(param->driver_ver, NBL_DRIVER_VERSION, sizeof(param->driver_ver));

	param->bus = common->bus;
	param->devid = common->devid;
	param->function = common->function;
	param->domain = pci_domain_nr(NBL_COMMON_TO_PDEV(common)->bus);
	param->version = IOCTL_ST_INFO_VERSION;
	if (common->product_type == NBL_LEONIS_TYPE)
		param->nic_type = NBL_NIC_TYPE_SNIC_V1R1;
	else if (common->product_type == NBL_DRACO_TYPE)
		param->nic_type = NBL_NIC_TYPE_SNIC_V2R1;

	param->real_chrdev_flag = st_mgt->real_st_name_valid;
	if (st_mgt && st_mgt->real_st_name_valid)
		memcpy(param->real_chrdev_name, st_mgt->real_st_name,
		       sizeof(param->real_chrdev_name));

	ret = copy_to_user((void *)arg, param, _IOC_SIZE(cmd));

	kfree(param);
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
	case IOCTL_ST_INFO:
		ret = nbl_serv_process_st_info(serv_mgt, cmd, arg);
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

static void nbl_serv_register_real_st_name(void *priv, char *st_name)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_st_mgt *st_mgt = NBL_SERV_MGT_TO_ST_MGT(serv_mgt);

	st_mgt->real_st_name_valid = true;
	memcpy(st_mgt->real_st_name, st_name, NBL_RESTOOL_NAME_LEN);
}

static int nbl_serv_setup_st(void *priv, void *st_table_param, char *st_name)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_software_tool_table *st_table = (struct nbl_software_tool_table *)st_table_param;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_st_mgt *st_mgt = NBL_SERV_MGT_TO_ST_MGT(serv_mgt);
	struct device *char_device;
	char name[NBL_RESTOOL_NAME_LEN] = {0};
	dev_t devid;
	int id, subdev_id, ret = 0;

	id = NBL_COMMON_TO_BOARD_ID(common);

	subdev_id = nbl_serv_alloc_subdev_id(st_table);
	if (subdev_id < 0)
		goto alloc_subdev_id_fail;

	devid = MKDEV(st_table->major, subdev_id);

	if (!NBL_COMMON_TO_PCI_FUNC_ID(common))
		snprintf(name, sizeof(name), "nblst%04x_conf%d",
			 NBL_COMMON_TO_PDEV(common)->device, id);
	else
		snprintf(name, sizeof(name), "nblst%04x_conf%d.%d",
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

	char_device = device_create(st_table->cls, NULL, st_mgt->devno, NULL, name);
	if (IS_ERR(char_device)) {
		ret = -EBUSY;
		goto device_create_fail;
	}

	memcpy(st_name, name, NBL_RESTOOL_NAME_LEN);
	memcpy(st_mgt->st_name, name, NBL_RESTOOL_NAME_LEN);
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

static void nbl_serv_form_p4_name(struct nbl_common_info *common, int type, char *name,
				  u16 len, u32 version)
{
	char eth_num[NBL_P4_NAME_LEN] = {0};
	char ver[NBL_P4_NAME_LEN] = {0};

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

	switch (version) {
	case 0:
		snprintf(ver, sizeof(ver), "lg");
		break;
	case 1:
		snprintf(ver, sizeof(ver), "hg");
		break;
	}

	switch (type) {
	case NBL_P4_DEFAULT:
		/* No need to load default p4 file */
		snprintf(name, len, "nbl/snic_v3r1/m18xxx_%s_port_p4_%s", eth_num, ver);
		break;
	default:
		nbl_err(common, NBL_DEBUG_CUSTOMIZED_P4, "Unknown P4 type %d", type);
	}
}

static int nbl_serv_calculate_md5sum(struct nbl_common_info *common, const u8 *data,
				     u32 data_len, char *md5_string)
{
	struct shash_desc *shash;
	struct crypto_shash *tfm;
	u8 md5_result[NBL_MD5SUM_LEN];
	int i;
	int ret;

	tfm = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(tfm)) {
		nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4, "Failed to allocate MD5 transform\n");
		return PTR_ERR(tfm);
	}

	shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!shash) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}

	shash->tfm = tfm;

	ret = crypto_shash_init(shash);
	if (ret) {
		nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4, "Failed to initialize MD5\n");
		kfree(shash);
		crypto_free_shash(tfm);
		return ret;
	}

	ret = crypto_shash_update(shash, data, data_len);
	if (ret) {
		nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4, "Failed to update MD5\n");
		kfree(shash);
		crypto_free_shash(tfm);
		return ret;
	}

	ret = crypto_shash_final(shash, md5_result);
	if (ret) {
		nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4, "Failed to finalize MD5\n");
		kfree(shash);
		crypto_free_shash(tfm);
		return ret;
	}

	for (i = 0; i < NBL_MD5SUM_LEN; i++)
		sprintf(md5_string + i * 2, "%02x", md5_result[i]);

	md5_string[32] = '\0';

	kfree(shash);
	crypto_free_shash(tfm);

	return 0;
}

static char *nbl_serv_get_md5_verify(int type, u16 version, u8 eth_num)
{
	if (version == 1) {
		switch (eth_num) {
		case 1: return NBL_SINGLE_PORT_HG_P4_MD5;
		case 2: return NBL_DUAL_PORT_HG_P4_MD5;
		case 4: return NBL_QUAD_PORT_HG_P4_MD5;
		default: return NULL;
		}
	} else if (version == 0) {
		switch (eth_num) {
		case 1: return NBL_SINGLE_PORT_LG_P4_MD5;
		case 2: return NBL_DUAL_PORT_LG_P4_MD5;
		case 4: return NBL_QUAD_PORT_LG_P4_MD5;
		default: return NULL;
		}
	}

	return NULL;
}

static int nbl_serv_load_p4(struct nbl_service_mgt *serv_mgt,
			    const struct firmware *fw, char *verify_code, int type, u16 version)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	const struct elf32_hdr *elf_hdr = (struct elf32_hdr *)fw->data;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct elf32_shdr *shdr;
	struct nbl_load_p4_param param;
	u8 *strtab, *name, *product_code = NULL;
	int i;
	char md5_result[33];
	char *md5_verify;
	u32 p4_size = 0;

	if (memcmp(elf_hdr->e_ident, NBL_P4_ELF_IDENT, NBL_P4_ELF_IDENT_LEN)) {
		nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4,
			 "Invalid ELF file, load defalut p4 configuration");
		return 0;
	}

	md5_verify = nbl_serv_get_md5_verify(type, version, NBL_COMMON_TO_ETH_MODE(common));

	if (nbl_serv_calculate_md5sum(common, fw->data, fw->size, md5_result)) {
		nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4,
			 "elf md5sum calculate failed, load defalut p4 configuration");
		return 0;
	}

	nbl_info(common, NBL_DEBUG_CUSTOMIZED_P4, "load p4 md5sum: %s\n", md5_result);

	if (!md5_verify || strncmp(md5_verify, md5_result, 33))
		nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4,
			 "elf file does not match driver version, function may be abnormal\n");

	memset(&param, 0, sizeof(param));

	shdr = (struct elf32_shdr *)((u8 *)elf_hdr + elf_hdr->e_shoff);
	strtab = (u8 *)elf_hdr + shdr[elf_hdr->e_shstrndx].sh_offset;

	for (i = 0; i < elf_hdr->e_shnum; i++)
		if (shdr[i].sh_type == SHT_NOTE) {
			name = strtab + shdr[i].sh_name;
			product_code = (u8 *)elf_hdr + shdr[i].sh_offset;
		}

	if (!product_code) {
		nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4,
			 "Product code not exist, function may be abnormal");
		return 0;
	}

	if (strncmp(product_code, verify_code, NBL_P4_VERIFY_CODE_LEN)) {
		nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4,
			 "Invalid product code %32s, function may be abnormal", product_code);
		return 0;
	}

	param.start = 1;
	disp_ops->load_p4(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param);

	for (i = 0; i < elf_hdr->e_shnum; i++)
		if (shdr[i].sh_type == SHT_PROGBITS && !(shdr[i].sh_flags & SHF_EXECINSTR)) {
			memset(&param, 0, sizeof(param));
			/* name is used for distinguish configuration, not used for now */
			strscpy(param.name, strtab + shdr[i].sh_name, sizeof(param.name));
			param.addr = shdr[i].sh_addr;
			param.size = shdr[i].sh_size;
			param.section_index = i;
			param.section_offset = 0;
			param.data = (u8 *)elf_hdr + shdr[i].sh_offset;
			p4_size += param.size;

			disp_ops->load_p4(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param);
		}

	memset(&param, 0, sizeof(param));
	param.end = 1;
	disp_ops->load_p4(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param);

	return 0;
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
	u32 version;

	version = disp_ops->get_p4_version(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	type = disp_ops->get_p4_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), verify_code);
	if (type < 0 || type > NBL_P4_TYPE_MAX) {
		nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4,
			 "p4 type is invalid, load defalut p4 configuration\n");
		return 0;
	}

	nbl_serv_form_p4_name(common, type, name, sizeof(name), version);

	ret = firmware_request_nowarn(&fw, name, NBL_SERV_MGT_TO_DEV(serv_mgt));

	if (ret) {
		nbl_warn(common, NBL_DEBUG_CUSTOMIZED_P4,
			 "p4 elf not found, load defalut p4 configuration\n");
		goto out;
	}

	ret = nbl_serv_load_p4(serv_mgt, fw, verify_code, type, version);

	release_firmware(fw);

out:
	if (ret)
		type = NBL_FLAG_P4_DEFAULT;

	nbl_info(common, NBL_DEBUG_CUSTOMIZED_P4, "Load P4 %d", type);
	disp_ops->set_p4_used(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &type);

	/* We always return OK, because at the very least we would use default P4 */
	return 0;
}

static int nbl_serv_set_spoof_check_addr(void *priv, u8 *mac)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_ch_prm_set_spoof_check_addr spoof_prm;

	memset(&spoof_prm, 0, sizeof(spoof_prm));
	spoof_prm.vsi_id = NBL_COMMON_TO_VSI_ID(common);
	ether_addr_copy(spoof_prm.mac, mac);

	return disp_ops->set_spoof_check_addr(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &spoof_prm);
}

static u16 nbl_serv_get_vf_base_vsi_id(void *priv, u16 func_id)
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
		struct nbl_get_local_queue_id_param prm = {0};

		detail = &abnomal_info.details[i];

		if (!detail->abnormal)
			continue;

		prm.vsi_id = detail->vsi_id;
		prm.global_queue_id = detail->qid;

		type = nbl_serv_abnormal_event_to_queue(i);
		local_queue_id = disp_ops->get_local_queue_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							      &prm);
		if (local_queue_id == U16_MAX)
			return 0;

		nbl_serv_restore_queue(serv_mgt, detail->vsi_id, local_queue_id, type, true);
	}

	return 0;
}

static int nbl_serv_cfg_bond_shaping(void *priv, struct nbl_ch_prm_cfg_bond_shaping *param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->cfg_bond_shaping(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);
}

static int nbl_serv_cfg_bgid_back_pressure(void *priv,
					   struct nbl_ch_prm_cfg_bgid_back_pressure *param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->cfg_bgid_back_pressure(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);
}

static void nbl_serv_cfg_eth_bond_event(void *priv, bool enable)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->cfg_eth_bond_event(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), enable);
}

static ssize_t nbl_serv_vf_mac_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "usage: write MAC ADDR to set mac address\n");
}

static ssize_t nbl_serv_vf_mac_store(struct kobject *kobj, struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	u8 mac[ETH_ALEN];
	int ret = 0;

	ret = sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		     &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	if (ret != ETH_ALEN)
		return -EINVAL;

	ret = nbl_serv_set_vf_mac(NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt)->netdev,
				  vf_info->vf_id, mac);
	return ret ? ret : count;
}

static ssize_t nbl_serv_vf_trust_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "usage: write <ON|OFF> to set vf trust\n");
}

static ssize_t nbl_serv_vf_trust_store(struct kobject *kobj, struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	bool trusted = false;
	int ret = 0;

	if (sysfs_streq(buf, "ON"))
		trusted = true;
	else if (sysfs_streq(buf, "OFF"))
		trusted = false;
	else
		return -EINVAL;

	ret = nbl_serv_set_vf_trust(NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt)->netdev,
				    vf_info->vf_id, trusted);
	return ret ? ret : count;
}

static ssize_t nbl_serv_vf_vlan_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf,
		       "usage: write <Vlan:Qos[:Proto]> to set VF Vlan, Qos, and optionally Vlan Protocol (default 802.1Q)\n");
}

static ssize_t nbl_serv_vf_vlan_store(struct kobject *kobj, struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	char vproto_ext[5] = {'\0'};
	__be16 vlan_proto;
	u16 vlan_id;
	u8 qos;
	int ret = 0;

	ret = sscanf(buf, "%hu:%hhu:802.%4s", &vlan_id, &qos, vproto_ext);
	if (ret == 3) {
		if ((strcmp(vproto_ext, "1AD") == 0) ||
		    (strcmp(vproto_ext, "1ad") == 0))
			vlan_proto = htons(ETH_P_8021AD);
		else if ((strcmp(vproto_ext, "1Q") == 0) ||
			 (strcmp(vproto_ext, "1q") == 0))
			vlan_proto = htons(ETH_P_8021Q);
		else
			return -EINVAL;
	} else {
		ret = sscanf(buf, "%hu:%hhu", &vlan_id, &qos);
		if (ret != 2)
			return -EINVAL;
		vlan_proto = htons(ETH_P_8021Q);
	}

	ret = nbl_serv_set_vf_vlan(NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt)->netdev,
				   vf_info->vf_id, vlan_id, qos, vlan_proto);
	return ret ? ret : count;
}

static ssize_t nbl_serv_vf_max_tx_rate_show(struct kobject *kobj, struct kobj_attribute *attr,
					    char *buf)
{
	return sprintf(buf, "usage: write RATE to set max_tx_rate(Mbps)\n");
}

static ssize_t nbl_serv_vf_max_tx_rate_store(struct kobject *kobj, struct kobj_attribute *attr,
					     const char *buf, size_t count)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	int max_tx_rate = 0, ret = 0;

	ret = kstrtos32(buf, 0, &max_tx_rate);
	if (ret)
		return -EINVAL;

	ret = nbl_serv_set_vf_rate(NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt)->netdev,
				   vf_info->vf_id, 0, max_tx_rate);
	return ret ? ret : count;
}

static ssize_t nbl_serv_vf_spoofchk_show(struct kobject *kobj, struct kobj_attribute *attr,
					 char *buf)
{
	return sprintf(buf, "usage: write <ON|OFF> to set vf spoof check\n");
}

static ssize_t nbl_serv_vf_spoofchk_store(struct kobject *kobj, struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	bool enable = false;
	int ret = 0;

	if (sysfs_streq(buf, "ON"))
		enable = true;
	else if (sysfs_streq(buf, "OFF"))
		enable = false;
	else
		return -EINVAL;

	ret = nbl_serv_set_vf_spoofchk(NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt)->netdev,
				       vf_info->vf_id, enable);
	return ret ? ret : count;
}

static ssize_t nbl_serv_vf_link_state_show(struct kobject *kobj, struct kobj_attribute *attr,
					   char *buf)
{
	return sprintf(buf, "usage: write <AUTO|ENABLE|DISABLE> to set vf link state\n");
}

static ssize_t nbl_serv_vf_link_state_store(struct kobject *kobj, struct kobj_attribute *attr,
					    const char *buf, size_t count)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	int state = 0, ret = 0;

	if (sysfs_streq(buf, "AUTO"))
		state = IFLA_VF_LINK_STATE_AUTO;
	else if (sysfs_streq(buf, "ENABLE"))
		state = IFLA_VF_LINK_STATE_ENABLE;
	else if (sysfs_streq(buf, "DISABLE"))
		state = IFLA_VF_LINK_STATE_DISABLE;
	else
		return -EINVAL;

	ret = nbl_serv_set_vf_link_state(NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt)->netdev,
					 vf_info->vf_id, state);
	return ret ? ret : count;
}

static ssize_t nbl_serv_vf_stats_show(struct kobject *kobj, struct kobj_attribute *attr,
				      char *buf)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	struct net_device *netdev = serv_mgt->net_resource_mgt->netdev;
	struct ifla_vf_stats stats = { 0 };
	int ret = 0;

	ret = nbl_serv_get_vf_stats(netdev, vf_info->vf_id, &stats);
	if (ret) {
		netdev_info(netdev, "get_vf %d stats failed %d\n", vf_info->vf_id, ret);
		return ret;
	}

	return scnprintf(buf, PAGE_SIZE,
		"tx_packets      : %llu\ntx_bytes        : %llu\ntx_dropped      : %llu\nrx_packets      : %llu\nrx_bytes        : %llu\nrx_dropped      : %llu\nrx_broadcast    : %llu\nrx_multicast    : %llu\n",
		stats.tx_packets, stats.tx_bytes, stats.tx_dropped,
		stats.rx_packets, stats.rx_bytes, stats.rx_dropped,
		stats.broadcast, stats.multicast
	);
}

static ssize_t nbl_serv_vf_tx_rate_show(struct kobject *kobj, struct kobj_attribute *attr,
					char *buf)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, tx_bps_kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	int rate = net_resource_mgt->vf_info[vf_info->vf_id].meter_tx_rate;

	return sprintf(buf, "max tx rate(Mbps): %d\n", rate);
}

static ssize_t nbl_serv_vf_tx_rate_store(struct kobject *kobj, struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, tx_bps_kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	int tx_rate = 0, ret = 0;

	ret = kstrtos32(buf, 0, &tx_rate);
	if (ret)
		return -EINVAL;

	ret = nbl_serv_set_vf_tx_rate(NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt)->netdev,
				      vf_info->vf_id, tx_rate, 0, false);
	return ret ? ret : count;
}

static ssize_t nbl_serv_vf_tx_burst_show(struct kobject *kobj, struct kobj_attribute *attr,
					 char *buf)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, tx_bps_kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	int burst = net_resource_mgt->vf_info[vf_info->vf_id].meter_tx_burst;

	return sprintf(buf, "max burst depth %d\n", burst);
}

static ssize_t nbl_serv_vf_tx_burst_store(struct kobject *kobj, struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, tx_bps_kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	int burst = 0, ret = 0;
	int rate = net_resource_mgt->vf_info[vf_info->vf_id].meter_tx_rate;

	ret = kstrtos32(buf, 0, &burst);
	if (ret)
		return -EINVAL;
	if (burst >= NBL_MAX_BURST)
		return -EINVAL;

	if (rate || !burst)
		ret = nbl_serv_set_vf_tx_rate(NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt)->netdev,
					      vf_info->vf_id, rate, burst, true);
	else
		return -EINVAL;

	return ret ? ret : count;
}

static ssize_t nbl_serv_vf_rx_rate_show(struct kobject *kobj, struct kobj_attribute *attr,
					char *buf)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, rx_bps_kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	int rate = net_resource_mgt->vf_info[vf_info->vf_id].meter_rx_rate;

	return sprintf(buf, "max rx rate(Mbps): %d\n", rate);
}

static ssize_t nbl_serv_vf_rx_rate_store(struct kobject *kobj, struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, rx_bps_kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	int rx_rate = 0, ret = 0;

	ret = kstrtos32(buf, 0, &rx_rate);
	if (ret)
		return -EINVAL;

	ret = nbl_serv_set_vf_rx_rate(NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt)->netdev,
				      vf_info->vf_id, rx_rate, 0, false);
	return ret ? ret : count;
}

static ssize_t nbl_serv_vf_rx_burst_show(struct kobject *kobj, struct kobj_attribute *attr,
					 char *buf)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, rx_bps_kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	int burst = net_resource_mgt->vf_info[vf_info->vf_id].meter_rx_burst;

	return sprintf(buf, "max burst depth %d\n", burst);
}

static ssize_t nbl_serv_vf_rx_burst_store(struct kobject *kobj, struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	struct nbl_serv_vf_info *vf_info = container_of(kobj, struct nbl_serv_vf_info, rx_bps_kobj);
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)vf_info->priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	int burst = 0, ret = 0;
	int rate = net_resource_mgt->vf_info[vf_info->vf_id].meter_rx_rate;

	ret = kstrtos32(buf, 0, &burst);
	if (ret)
		return -EINVAL;
	if (burst > NBL_MAX_BURST)
		return -EINVAL;

	if (rate || !burst)
		ret = nbl_serv_set_vf_rx_rate(NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt)->netdev,
					      vf_info->vf_id, rate, burst, true);
	else
		return -EINVAL;

	return ret ? ret : count;
}

static ssize_t nbl_serv_vf_config_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct kobj_attribute *kattr = container_of(attr, struct kobj_attribute, attr);

	if (kattr->show)
		return kattr->show(kobj, kattr, buf);

	return -EIO;
}

static ssize_t nbl_serv_vf_config_store(struct kobject *kobj, struct attribute *attr,
					const char *buf, size_t count)
{
	struct kobj_attribute *kattr = container_of(attr, struct kobj_attribute, attr);

	if (kattr->show)
		return kattr->store(kobj, kattr, buf, count);

	return -EIO;
}

static void dir_release(struct kobject *kobj)
{
	//TODO
}

static struct kobj_attribute nbl_attr_vf_mac = {
	.attr = {.name = "mac",
		 .mode = 0644},
	.show = nbl_serv_vf_mac_show,
	.store = nbl_serv_vf_mac_store,
};

static struct kobj_attribute nbl_attr_vf_vlan = {
	.attr = {.name = "vlan",
		 .mode = 0644},
	.show = nbl_serv_vf_vlan_show,
	.store = nbl_serv_vf_vlan_store,
};

static struct kobj_attribute nbl_attr_vf_trust = {
	.attr = {.name = "trust",
		 .mode = 0644},
	.show = nbl_serv_vf_trust_show,
	.store = nbl_serv_vf_trust_store,
};

static struct kobj_attribute nbl_attr_vf_max_tx_rate = {
	.attr = {.name = "max_tx_rate",
		 .mode = 0644},
	.show = nbl_serv_vf_max_tx_rate_show,
	.store = nbl_serv_vf_max_tx_rate_store,
};

static struct kobj_attribute nbl_attr_vf_spoofcheck = {
	.attr = {.name = "spoofcheck",
		 .mode = 0644},
	.show = nbl_serv_vf_spoofchk_show,
	.store = nbl_serv_vf_spoofchk_store,
};

static struct kobj_attribute nbl_attr_vf_tx_rate = {
	.attr = {.name = "rate",
		 .mode = 0644},
	.show = nbl_serv_vf_tx_rate_show,
	.store = nbl_serv_vf_tx_rate_store,
};

static struct kobj_attribute nbl_attr_vf_tx_burst = {
	.attr = {.name = "burst",
		 .mode = 0644},
	.show = nbl_serv_vf_tx_burst_show,
	.store = nbl_serv_vf_tx_burst_store,
};

static struct kobj_attribute nbl_attr_vf_rx_rate = {
	.attr = {.name = "rate",
		 .mode = 0644},
	.show = nbl_serv_vf_rx_rate_show,
	.store = nbl_serv_vf_rx_rate_store,
};

static struct kobj_attribute nbl_attr_vf_rx_burst = {
	.attr = {.name = "burst",
		 .mode = 0644},
	.show = nbl_serv_vf_rx_burst_show,
	.store = nbl_serv_vf_rx_burst_store,
};

static struct kobj_attribute nbl_attr_vf_link_state = {
	.attr = {.name = "link_state",
		 .mode = 0644},
	.show = nbl_serv_vf_link_state_show,
	.store = nbl_serv_vf_link_state_store,
};

static struct kobj_attribute nbl_attr_vf_stats = {
	.attr = {.name = "stats",
		 .mode = 0444},
	.show = nbl_serv_vf_stats_show,
};

static struct attribute *nbl_vf_config_attrs[] = {
	&nbl_attr_vf_mac.attr,
	&nbl_attr_vf_vlan.attr,
	&nbl_attr_vf_trust.attr,
	&nbl_attr_vf_max_tx_rate.attr,
	&nbl_attr_vf_spoofcheck.attr,
	&nbl_attr_vf_link_state.attr,
	&nbl_attr_vf_stats.attr,
	NULL,
};

ATTRIBUTE_GROUPS(nbl_vf_config);

static struct attribute *nbl_vf_tx_config_attrs[] = {
	&nbl_attr_vf_tx_rate.attr,
	&nbl_attr_vf_tx_burst.attr,
	NULL,
};

ATTRIBUTE_GROUPS(nbl_vf_tx_config);

static struct attribute *nbl_vf_rx_config_attrs[] = {
	&nbl_attr_vf_rx_rate.attr,
	&nbl_attr_vf_rx_burst.attr,
	NULL,
};

ATTRIBUTE_GROUPS(nbl_vf_rx_config);

static const struct sysfs_ops nbl_sysfs_ops_vf = {
	.show = nbl_serv_vf_config_show,
	.store = nbl_serv_vf_config_store,
};

static const struct kobj_type nbl_kobj_vf_type = {
	.sysfs_ops = &nbl_sysfs_ops_vf,
	.default_groups = nbl_vf_config_groups,
};

static const struct kobj_type nbl_kobj_dir = {
	.release = dir_release,
};

static const struct kobj_type nbl_kobj_vf_tx_type = {
	.sysfs_ops = &nbl_sysfs_ops_vf,
	.default_groups = nbl_vf_tx_config_groups,
};

static const struct kobj_type nbl_kobj_vf_rx_type = {
	.sysfs_ops = &nbl_sysfs_ops_vf,
	.default_groups = nbl_vf_rx_config_groups,
};

static int nbl_serv_setup_vf_sysfs(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_serv_vf_info *vf_info = net_resource_mgt->vf_info;
	int i = 0, ret = 0;
	int index = 0;

	for (i = 0; i < net_resource_mgt->num_vfs; i++) {
		index = i;
		vf_info[i].priv = serv_mgt;
		vf_info[i].vf_id = (u16)i;

		ret = kobject_init_and_add(&vf_info[i].kobj, &nbl_kobj_vf_type,
					   net_resource_mgt->sriov_kobj, "%d", i);
		if (ret)
			goto err;

		ret = kobject_init_and_add(&vf_info[i].meters_kobj, &nbl_kobj_dir,
					   &vf_info[i].kobj, "meters");
		if (ret)
			goto err;
		ret = kobject_init_and_add(&vf_info[i].rx_kobj, &nbl_kobj_dir,
					   &vf_info[i].meters_kobj, "rx");
		if (ret)
			goto err;
		ret = kobject_init_and_add(&vf_info[i].tx_kobj, &nbl_kobj_dir,
					   &vf_info[i].meters_kobj, "tx");
		if (ret)
			goto err;
		ret = kobject_init_and_add(&vf_info[i].rx_bps_kobj, &nbl_kobj_vf_rx_type,
					   &vf_info[i].rx_kobj, "bps");
		if (ret)
			goto err;
		ret = kobject_init_and_add(&vf_info[i].tx_bps_kobj, &nbl_kobj_vf_tx_type,
					   &vf_info[i].tx_kobj, "bps");
		if (ret)
			goto err;
	}

	return 0;

err:
	for (i = 0; i <= index; i++) {
		if (vf_info[i].tx_bps_kobj.state_initialized)
			kobject_put(&vf_info[i].tx_bps_kobj);
		if (vf_info[i].rx_bps_kobj.state_initialized)
			kobject_put(&vf_info[i].rx_bps_kobj);
		if (vf_info[i].tx_kobj.state_initialized)
			kobject_put(&vf_info[i].tx_kobj);
		if (vf_info[i].rx_kobj.state_initialized)
			kobject_put(&vf_info[i].rx_kobj);
		if (vf_info[i].meters_kobj.state_initialized)
			kobject_put(&vf_info[i].meters_kobj);
		if (vf_info[i].kobj.state_initialized)
			kobject_put(&vf_info[i].kobj);
	}

	return ret;
}

static void nbl_serv_remove_vf_sysfs(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_serv_vf_info *vf_info = net_resource_mgt->vf_info;
	int i = 0;

	for (i = 0; i < net_resource_mgt->num_vfs; i++) {
		kobject_put(&vf_info[i].tx_bps_kobj);
		kobject_put(&vf_info[i].rx_bps_kobj);
		kobject_put(&vf_info[i].tx_kobj);
		kobject_put(&vf_info[i].rx_kobj);
		kobject_put(&vf_info[i].meters_kobj);
		kobject_put(&vf_info[i].kobj);
	}
}

static int nbl_serv_setup_vf_config(void *priv, int num_vfs, bool is_flush)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_vf_info *vf_info = net_resource_mgt->vf_info;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_ch_prm_init_vf_msix_map msix_map;
	u16 func_id = U16_MAX;
	u16 vlan_tci;
	bool should_notify;
	int i, ret = 0;
	struct nbl_ch_prm_set_vf_spoof_check vf_spoof_prm = {0};

	net_resource_mgt->num_vfs = num_vfs;

	for (i = 0; i < net_resource_mgt->num_vfs; i++) {
		func_id = disp_ops->get_vf_function_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						       NBL_COMMON_TO_VSI_ID(common), i);

		if (func_id == U16_MAX) {
			nbl_err(common, NBL_DEBUG_MAIN, "vf id %d invalid\n", i);
			return -EINVAL;
		}

		msix_map.sfid = func_id;
		msix_map.enable = !is_flush;
		disp_ops->init_vf_msix_map(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &msix_map);

		disp_ops->register_func_mac(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    vf_info[i].mac, func_id);

		vlan_tci = (vf_info[i].vlan & VLAN_VID_MASK) |
			   (vf_info[i].vlan_qos << VLAN_PRIO_SHIFT);
		ret = disp_ops->register_func_vlan(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), func_id,
						   vlan_tci, vf_info[i].vlan_proto,
						   &should_notify);
		if (ret)
			break;

		ret = disp_ops->register_func_trust(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						    func_id, vf_info[i].trusted,
						    &should_notify);

		if (ret)
			break;

		ret = disp_ops->register_func_rate(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), func_id,
						   vf_info[i].max_tx_rate);
		if (ret)
			break;

		ret = disp_ops->set_tx_rate(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    func_id, vf_info[i].max_tx_rate, 0);
		if (ret)
			break;

		ret = disp_ops->set_rx_rate(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    func_id, vf_info[i].meter_rx_rate, 0);
		if (ret)
			break;

		vf_spoof_prm.vsi_id = NBL_COMMON_TO_VSI_ID(common);
		vf_spoof_prm.vf_id = i;
		vf_spoof_prm.enable = vf_info[i].spoof_check;
		ret = disp_ops->set_vf_spoof_check(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						   &vf_spoof_prm);
		if (ret)
			break;

		/* No need to notify vf, vf will get link forced when probe,
		 * Here we only flush the config.
		 */
		ret = disp_ops->register_func_link_forced(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							  func_id, vf_info[i].state,
							  &should_notify);
		if (ret)
			break;
	}

	if (!ret && net_resource_mgt->sriov_kobj && !is_flush)
		ret = nbl_serv_setup_vf_sysfs(serv_mgt);

	if (ret)
		net_resource_mgt->num_vfs = 0;

	return ret;
}

static void nbl_serv_remove_vf_config(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_serv_vf_info *vf_info = net_resource_mgt->vf_info;
	int i;

	nbl_serv_remove_vf_sysfs(serv_mgt);

	for (i = 0; i < net_resource_mgt->num_vfs; i++)
		memset(&vf_info[i], 0, sizeof(vf_info[i]));

	nbl_serv_setup_vf_config(priv, net_resource_mgt->num_vfs, true);

	net_resource_mgt->num_vfs = 0;
}

static void nbl_serv_register_dev_name(void *priv, u16 vsi_id, char *name)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_pf_name param = {0};

	param.vsi_id = vsi_id;
	strscpy(param.dev_name, name, sizeof(param.dev_name));
	disp_ops->register_dev_name(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param);
}

static void nbl_serv_get_dev_name(void *priv, u16 vsi_id, char *name)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_pf_name param;
	struct nbl_ch_prm_pf_name output;

	param.vsi_id = vsi_id;
	disp_ops->get_dev_name(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param, &output);
	strscpy(name, output.dev_name, sizeof(output.dev_name));
}

static int nbl_serv_setup_vf_resource(void *priv, int num_vfs)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_serv_vf_info *vf_info;
	struct device *dev = NBL_SERV_MGT_TO_DEV(serv_mgt);
	int i;

	net_resource_mgt->total_vfs = num_vfs;

	net_resource_mgt->vf_info = devm_kcalloc(dev, net_resource_mgt->total_vfs,
						 sizeof(struct nbl_serv_vf_info), GFP_KERNEL);
	if (!net_resource_mgt->vf_info)
		return -ENOMEM;

	vf_info = net_resource_mgt->vf_info;
	for (i = 0; i < net_resource_mgt->total_vfs; i++) {
		vf_info[i].state = IFLA_VF_LINK_STATE_AUTO;
		vf_info[i].spoof_check = false;
	}

	net_resource_mgt->sriov_kobj = kobject_create_and_add("sriov", &dev->kobj);
	if (!net_resource_mgt->sriov_kobj)
		nbl_warn(NBL_SERV_MGT_TO_COMMON(serv_mgt), NBL_DEBUG_MAIN,
			 "Fail to create sriov sysfs");

	return 0;
}

static void nbl_serv_remove_vf_resource(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct device *dev = NBL_SERV_MGT_TO_DEV(serv_mgt);

	nbl_serv_remove_vf_config(priv);

	kobject_put(net_resource_mgt->sriov_kobj);

	if (net_resource_mgt->vf_info) {
		devm_kfree(dev, net_resource_mgt->vf_info);
		net_resource_mgt->vf_info = NULL;
	}
}

static void nbl_serv_cfg_fd_update_event(void *priv, bool enable)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->cfg_fd_update_event(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), enable);
}

#if IS_ENABLED(CONFIG_MACSEC)
static int nbl_serv_init_macsec(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_macsec_info *macsec = NULL;

	macsec = kzalloc(sizeof(*macsec), GFP_KERNEL);
	if (!macsec)
		return -ENOMEM;

	INIT_LIST_HEAD(&macsec->macsec_dev_list);
	mutex_init(&macsec->lock);

	serv_mgt->macsec = macsec;

	return 0;
}

static void nbl_serv_uninit_macsec(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_macsec_info *macsec = serv_mgt->macsec;

	if (!macsec)
		return;

	mutex_destroy(&macsec->lock);
	kfree(macsec);
	serv_mgt->macsec = NULL;
}
#endif

static void nbl_serv_get_xdp_queue_info(void *priv, u16 *queue_num, u16 *queue_size, u16 vsi_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_get_queue_info output = {0};

	disp_ops->get_xdp_queue_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi_id, &output);
	*queue_num = output.queue_num;
	*queue_size = output.queue_size;
}

static void nbl_serv_assgin_xdp_prog(struct net_device *netdev, struct bpf_prog *prog)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct bpf_prog *old_prog;

	old_prog = xchg(&ring_mgt->xdp_prog, prog);
	if (old_prog)
		bpf_prog_put(old_prog);

	disp_ops->set_rings_xdp_prog(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), (void *)prog);
}

static int nbl_serv_setup_xdp_prog(struct net_device *netdev, struct bpf_prog *prog,
				   struct netlink_ext_ack *extack)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	int was_running;
	int err;
	int xdp_max_mtu;

	if (prog && test_bit(NBL_USER, adapter->state))
		return -EIO;

	if (!ring_mgt->vsi_info[NBL_VSI_XDP].ring_num)
		return -ENOSPC;

	err = disp_ops->check_mtu(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), 1,
				  netdev->mtu, &xdp_max_mtu);
	if (err) {
		netdev_err(netdev, "max MTU for XDP usage is %d\n", xdp_max_mtu);
		return -EINVAL;
	}

	was_running = netif_running(netdev);
	if (was_running) {
		err = nbl_serv_netdev_stop(netdev);
		if (err) {
			netdev_err(netdev, "Netdev stop failed while setup prog\n");
			return err;
		}
	}

	nbl_serv_assgin_xdp_prog(netdev, prog);

	if (was_running) {
		err = nbl_serv_netdev_open(netdev);
		if (err) {
			netdev_err(netdev, "Netdev open failed after setup prog\n");
			return err;
		}
	}

	if (prog)
		set_bit(NBL_XDP, adapter->state);
	else
		clear_bit(NBL_XDP, adapter->state);

	return 0;
}

static int nbl_serv_set_xdp(struct net_device *netdev, struct netdev_bpf *xdp)
{
	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return nbl_serv_setup_xdp_prog(netdev, xdp->prog, xdp->extack);
	default:
		return -EINVAL;
	}
}

static void nbl_serv_set_hw_status(void *priv, enum nbl_hw_status hw_status)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->set_hw_status(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), hw_status);
}

static void nbl_serv_check_hw_status(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->check_hw_status(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static enum nbl_hw_status nbl_serv_get_hw_status(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_hw_status(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static void nbl_serv_get_active_func_bitmaps(void *priv, unsigned long *bitmap, int max_func)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->get_active_func_bitmaps(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), bitmap, max_func);
}

static int nbl_serv_configure_qos(void *priv, u8 eth_id, u8 *pfc, u8 trust, u8 *dscp2prio_map)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_netdev_priv *net_priv = netdev_priv(net_resource_mgt->netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int ret;
	struct nbl_ch_prm_configure_qos qos_param = {0};

	qos_param.eth_id = eth_id;
	qos_param.trust = trust;
	memcpy(qos_param.pfc, pfc, NBL_MAX_PFC_PRIORITIES);
	memcpy(qos_param.dscp2prio_map, dscp2prio_map, NBL_DSCP_MAX);
	ret = disp_ops->configure_qos(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &qos_param);

	net_resource_mgt->qos_info.trust_mode = trust;
	net_priv->trust_mode = trust;
	memcpy(net_resource_mgt->qos_info.dscp2prio_map, dscp2prio_map, NBL_DSCP_MAX);
	memcpy(net_resource_mgt->qos_info.pfc, pfc, NBL_MAX_PFC_PRIORITIES);
	return ret;
}

static struct nbl_qos_info *nbl_serv_qos_info(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;

	return &net_resource_mgt->qos_info;
}

static int nbl_serv_configure_rdma_bw(void *priv, u8 eth_id, int rdma_bw)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_ch_prm_configure_rdma_bw rdma_param = {0};
	int ret;

	rdma_param.eth_id = eth_id;
	rdma_param.rdma_bw = rdma_bw;
	ret = disp_ops->configure_rdma_bw(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &rdma_param);
	if (ret) {
		nbl_err(common, NBL_DEBUG_MAIN, "configure rdma bw failed ret %d\n", ret);
		return ret;
	}

	qos_info->rdma_bw = rdma_bw;

	return 0;
}

static int nbl_serv_set_pfc_buffer_size(void *priv, u8 eth_id, u8 prio, int xoff, int xon)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_ch_prm_set_pfc_buffer_size param = {0};
	int ret;

	param.eth_id = eth_id;
	param.prio = prio;
	param.xoff = xoff;
	param.xon = xon;
	ret = disp_ops->set_pfc_buffer_size(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    &param);

	if (ret) {
		nbl_err(common, NBL_DEBUG_MAIN, "configure pfc buffer size failed ret %d\n", ret);
		return ret;
	}

	qos_info->buffer_sizes[prio][0] = xoff;
	qos_info->buffer_sizes[prio][1] = xon;

	return ret;
}

static int nbl_serv_get_pfc_buffer_size(void *priv, u8 eth_id, u8 prio, int *xoff, int *xon)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_get_pfc_buffer_size param = {0};
	struct nbl_ch_prm_get_pfc_buffer_size_resp output = {0};
	int ret;

	ret = disp_ops->get_pfc_buffer_size(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    &param, &output);
	*xoff = output.xoff;
	*xon = output.xon;

	return ret;
}

#ifdef CONFIG_DCB
static u8 nbl_serv_dcb_get_num_tc(struct net_device *netdev, struct ieee_ets *ets)
{
	bool tc_unused = false;
	u8 num_tc = 0;
	u8 ret = 0;
	int i;

	/* Scan the ETS Config Priority Table to find traffic classes
	 * enabled and create a bitmask of enabled TCs
	 */
	for (i = 0; i < CEE_DCBX_MAX_PRIO; i++)
		num_tc |= BIT(ets->prio_tc[i]);

	/* Scan bitmask for contiguous TCs starting with TC0 */
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (num_tc & BIT(i)) {
			if (!tc_unused) {
				ret++;
			} else {
				netdev_err(netdev, "Non-contiguous TCs - Disabling DCB\n");
				return 1;
			}
		} else {
			tc_unused = true;
		}
	}

	/* There is always at least 1 TC */
	if (!ret)
		ret = 1;

	return ret;
}

static int nbl_serv_bwchk(struct net_device *netdev, struct ieee_ets *ets)
{
	u8 num_tc, total_bw = 0;
	int i;

	num_tc = nbl_serv_dcb_get_num_tc(netdev, ets);

	/* no bandwidth checks required if there's only one TC, so assign
	 * all bandwidth to TC0 and return
	 */
	if (num_tc == 1) {
		ets->tc_reco_bw[0] = NBL_TC_MAX_BW;
		return 0;
	}

	for (i = 0; i < num_tc; i++)
		total_bw += ets->tc_reco_bw[i];

	if (!total_bw) {
		ets->tc_reco_bw[0] = NBL_TC_MAX_BW;
	} else if (total_bw != NBL_TC_MAX_BW) {
		netdev_err(netdev, "Invalid config, total bandwidth must equal 100\n");
		return -EINVAL;
	}

	return 0;
}

static int nbl_serv_ieee_setets(struct net_device *netdev, struct ieee_ets *ets)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct ieee_ets ets_tmp = {0};
	struct nbl_ch_prm_set_tc_wgt tc_wgt_param = {0};
	int bwcfg = 0, bwrec = 0;
	int ret;
	int i;

	memcpy(&ets_tmp, ets, sizeof(ets_tmp));

	if (nbl_serv_bwchk(netdev, &ets_tmp))
		return -EINVAL;

	for (i = 0; i < NBL_MAX_TC_NUM; i++) {
		bwcfg += ets->tc_tx_bw[i];
		bwrec += ets->tc_reco_bw[i];
	}

	if (!bwcfg)
		ets_tmp.tc_tx_bw[0] = NBL_TC_MAX_BW;

	if (!bwrec)
		ets_tmp.tc_reco_bw[0] = NBL_TC_MAX_BW;
	tc_wgt_param.vsi_id = NBL_COMMON_TO_VSI_ID(common);
	tc_wgt_param.num_tc = NBL_MAX_TC_NUM;
	memcpy(tc_wgt_param.weight, ets_tmp.tc_tx_bw, NBL_MAX_TC_NUM);
	ret = disp_ops->set_tc_wgt(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &tc_wgt_param);
	if (ret) {
		nbl_err(common, NBL_DEBUG_MAIN, "set_tc_wgt failed ret %d\n", ret);
		return ret;
	}

	memcpy(&qos_info->ets, &ets_tmp, sizeof(struct ieee_ets));
	return 0;
}

static int nbl_serv_ieee_getets(struct net_device *netdev, struct ieee_ets *ets)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;

	memcpy(ets, &qos_info->ets, sizeof(struct ieee_ets));
	ets->ets_cap = NBL_MAX_TC_NUM;
	return 0;
}

static int nbl_serv_ieee_delapp(struct net_device *netdev, struct dcb_app *app)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_ch_prm_configure_qos qos_param = {0};
	int ret;

	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP ||
	    app->protocol >= NBL_DSCP_MAX)
		return -EINVAL;

	if (qos_info->dscp2prio_map[app->protocol] != app->priority)
		return -ENOENT;

	ret = dcb_ieee_delapp(netdev, app);
	if (ret != -ENOENT && ret != 0)
		return ret;

	qos_info->dscp2prio_map[app->protocol] = 0;

	qos_param.eth_id = NBL_COMMON_TO_ETH_ID(common);
	qos_param.trust = qos_info->trust_mode;
	memcpy(qos_param.pfc, qos_info->pfc, NBL_MAX_PFC_PRIORITIES);
	memcpy(qos_param.dscp2prio_map, qos_info->dscp2prio_map, NBL_DSCP_MAX);
	ret = disp_ops->configure_qos(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &qos_param);

	if (ret) {
		nbl_err(common, NBL_DEBUG_MAIN, "delapp configure dscp2prio failed ret %d\n", ret);
		return ret;
	}

	return 0;
}

static int nbl_serv_ieee_setapp(struct net_device *netdev, struct dcb_app *app)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_ch_prm_configure_qos qos_param = {0};
	int ret;

	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP ||
	    app->protocol >= NBL_DSCP_MAX)
		return -EINVAL;

	if (qos_info->dscp2prio_map[app->protocol] == app->priority)
		return 0;

	ret = dcb_ieee_setapp(netdev, app);
	if (ret)
		return ret;

	qos_info->trust_mode = NBL_TRUST_MODE_DSCP;
	priv->trust_mode = NBL_TRUST_MODE_DSCP;
	qos_info->dscp2prio_map[app->protocol] = app->priority;
	qos_param.eth_id = NBL_COMMON_TO_ETH_ID(common);
	qos_param.trust = qos_info->trust_mode;
	memcpy(qos_param.pfc, qos_info->pfc, NBL_MAX_PFC_PRIORITIES);
	memcpy(qos_param.dscp2prio_map, qos_info->dscp2prio_map, NBL_DSCP_MAX);
	ret = disp_ops->configure_qos(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &qos_param);

	if (ret) {
		nbl_err(common, NBL_DEBUG_MAIN, "setapp configure dscp2prio failed ret %d\n", ret);
		return ret;
	}

	return 0;
}

static void nbl_serv_dcbnl_getpfccfg(struct net_device *netdev, int prio, u8 *setting)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;

	if (prio >= NBL_MAX_PFC_PRIORITIES)
		return;

	*setting = qos_info->pfc[prio];
}

static int nbl_serv_dcbnl_getnumtcs(struct net_device *netdev, int tcid, u8 *num)
{
	*num = NBL_MAX_TC_NUM;

	return 0;
}

static void nbl_serv_dcbnl_setpfccfg(struct net_device *netdev, int prio, u8 set)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	u8 pfc[NBL_MAX_PFC_PRIORITIES] = {0};
	struct nbl_ch_prm_configure_qos qos_param = {0};
	int ret;

	if (prio >= NBL_MAX_PFC_PRIORITIES)
		return;

	if (qos_info->pfc[prio] == set)
		return;

	memcpy(pfc, qos_info->pfc, NBL_MAX_PFC_PRIORITIES);
	pfc[prio] = set;

	qos_param.eth_id = NBL_COMMON_TO_ETH_ID(common);
	qos_param.trust = net_resource_mgt->qos_info.trust_mode;
	memcpy(qos_param.pfc, pfc, NBL_MAX_PFC_PRIORITIES);
	memcpy(qos_param.dscp2prio_map, net_resource_mgt->qos_info.dscp2prio_map, NBL_DSCP_MAX);
	ret = disp_ops->configure_qos(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &qos_param);
	if (ret) {
		nbl_err(common, NBL_DEBUG_MAIN, "configure pfc failed ret %d\n", ret);
		return;
	}

	memcpy(qos_info->pfc, pfc, NBL_MAX_PFC_PRIORITIES);
}

static int nbl_serv_ieee_setpfc(struct net_device *netdev, struct ieee_pfc *pfc)
{
	u8 i;

	for (i = 0 ; i < NBL_MAX_PFC_PRIORITIES; i++) {
		if (pfc->pfc_en & BIT(i))
			nbl_serv_dcbnl_setpfccfg(netdev, i, 1);
		else
			nbl_serv_dcbnl_setpfccfg(netdev, i, 0);
	}
	return 0;
}

static int nbl_serv_ieee_getpfc(struct net_device *netdev, struct ieee_pfc *pfc)
{
	u8 i;
	u8 setting;

	for (i = 0; i < NBL_MAX_PFC_PRIORITIES; i++) {
		nbl_serv_dcbnl_getpfccfg(netdev, i, &setting);
		if (setting)
			pfc->pfc_en |= BIT(i);
		else
			pfc->pfc_en &= ~(BIT(i));
	}
	return 0;
}

static u8 nbl_serv_dcbnl_getcap(struct net_device *netdev, int capid, u8 *cap)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;

	*cap = true;

	switch (capid) {
	case DCB_CAP_ATTR_PG:
		*cap = true;
		break;
	case DCB_CAP_ATTR_PFC:
		*cap = true;
		break;
	case DCB_CAP_ATTR_UP2TC:
		*cap = false;
		break;
	case DCB_CAP_ATTR_PG_TCS:
		*cap = 0x80;
		break;
	case DCB_CAP_ATTR_PFC_TCS:
		*cap = 0x80;
		break;
	case DCB_CAP_ATTR_GSP:
		*cap = false;
		break;
	case DCB_CAP_ATTR_BCN:
		*cap = false;
		break;
	case DCB_CAP_ATTR_DCBX:
		*cap = qos_info->dcbx_mode;
		break;
	default:
		*cap = false;
		break;
	}
	return 0;
}

static u8 nbl_serv_ieee_getdcbx(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;

	return qos_info->dcbx_mode;
}

static u8 nbl_serv_ieee_setdcbx(struct net_device *netdev, u8 mode)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;

	qos_info->dcbx_mode = mode;

	return 0;
}

static u8 nbl_serv_dcnbl_setstate(struct net_device *netdev, u8 state)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;

	if (qos_info->dcbx_state == state)
		return NBL_DCB_NO_HW_CHG;

	qos_info->dcbx_state = state;
	return NBL_DCB_HW_CHG;
}

static u8 nbl_serv_dcnbl_getstate(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;

	return qos_info->dcbx_state;
}

static u8 nbl_serv_dcnbl_getpfcstate(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;
	int i;

	for (i = 0; i < NBL_MAX_PFC_PRIORITIES; i++)
		if (qos_info->pfc[i])
			return 1;

	return 0;
}
#endif

static void nbl_serv_get_board_info(void *priv, struct nbl_board_port_info *board_info)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->get_board_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), board_info);
}

static int nbl_serv_set_rate_limit(void *priv, u16 func_id, enum nbl_traffic_type type, u32 rate)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_qos_info *qos_info = &net_resource_mgt->qos_info;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_ch_prm_set_rate_limit param = {0};
	int ret = 0;

	param.sfid = func_id;
	param.type = type;
	param.rate = rate;
	ret = disp_ops->set_rate_limit(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param);
	if (ret) {
		nbl_err(common, NBL_DEBUG_MAIN, "set_rate type %d failed ret %d\n", type, ret);
		return ret;
	}

	if (type == NBL_TRAFFIC_RDMA_TYPE)
		qos_info->rdma_rate = rate;
	else
		qos_info->net_rate = rate;

	return ret;
}

static void nbl_serv_get_mirror_table_id(void *priv, u16 vsi_id, int dir, bool mirror_en,
					 u8 *mt_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_get_mirror_table_id param = {0};
	struct nbl_ch_prm_get_mirror_table_id output = {0};

	param.vsi_id = vsi_id;
	param.dir = dir;
	param.mirror_en = mirror_en;
	disp_ops->get_mirror_table_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				      &param, &output);
	*mt_id = output.mt_id;
}

static int nbl_serv_configure_mirror(void *priv, u16 func_id, bool mirror_en, int dir,
				     u8 mt_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_mirror param = {0};
	int ret;

	nbl_event_notify(NBL_EVENT_MIRROR_SELECTPORT, &mirror_en,
			 NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	param.dir = dir;
	param.mirror_en = mirror_en;
	param.mt_id = mt_id;
	param.sfid = func_id;
	ret = disp_ops->configure_mirror(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					 &param);
	return ret;
}

static int nbl_serv_configure_tx_mirror_to_rdma(void *priv,
						struct nbl_ch_prm_tx_mirror_to_rdma *param)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->configure_tx_mirror_to_rdma(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						     param);
}

static int nbl_serv_configure_mirror_table(void *priv, bool mirror_en,
					   u16 func_id, u8 mt_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ch_prm_mirror_table param;
	int ret;

	if (mirror_en) {
		ret = disp_ops->check_vf_is_active(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), func_id);
		if (!ret)
			return -EIO;
	}
	param.mirror_en = mirror_en;
	param.func_id = func_id;
	param.mt_id = mt_id;
	ret = disp_ops->configure_mirror_table(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       &param);

	if (disp_ops->check_vf_is_active(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), func_id))
		nbl_serv_chan_notify_mirror_outputport_req(serv_mgt, func_id, mirror_en);
	return ret;
}

static int nbl_serv_clear_mirror_cfg(void *priv, u16 func_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	int ret;

	if (common->is_vf)
		return 0;
	ret = disp_ops->clear_mirror_cfg(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					 &func_id);

	return ret;
}

u16 nbl_serv_get_vf_function_id(void *priv, int vf_id)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	if (vf_id >= net_resource_mgt->total_vfs || !net_resource_mgt->vf_info)
		return U16_MAX;

	return disp_ops->get_vf_function_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    NBL_COMMON_TO_VSI_ID(common), vf_id);
}

static void nbl_serv_cfg_mirror_outputport_event(void *priv, bool enable)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->cfg_mirror_outputport_event(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), enable);
}

static struct nbl_service_ops serv_ops = {
	.init_chip = nbl_serv_init_chip,
	.destroy_chip = nbl_serv_destroy_chip,
	.enable_driver = nbl_serv_enable_driver,
	.init_p4 = nbl_serv_init_p4,

	.configure_msix_map = nbl_serv_configure_msix_map,
	.destroy_msix_map = nbl_serv_destroy_msix_map,
	.enable_mailbox_irq = nbl_serv_enable_mailbox_irq,
	.enable_abnormal_irq = nbl_serv_enable_abnormal_irq,
	.enable_sfp_plug_irq = nbl_serv_enable_sfp_plug_irq,
	.enable_adminq_irq = nbl_serv_enable_adminq_irq,
	.request_net_irq = nbl_serv_request_net_irq,
	.free_net_irq = nbl_serv_free_net_irq,
	.get_global_vector = nbl_serv_get_global_vector,
	.get_common_irq_num = nbl_serv_get_common_irq_num,
	.get_ctrl_irq_num = nbl_serv_get_ctrl_irq_num,
	.get_chip_temperature = nbl_serv_get_chip_temperature,
	.get_module_temperature = nbl_serv_get_module_temperature,
	.get_port_attributes = nbl_serv_get_port_attributes,
	.update_template_config = nbl_serv_update_template_config,
	.get_part_number = nbl_serv_get_part_number,
	.get_serial_number = nbl_serv_get_serial_number,
	.enable_port = nbl_serv_enable_port,
	.init_port = nbl_serv_init_port,
	.set_sfp_state = nbl_serv_set_sfp_state,
	.get_firmware_version = nbl_serv_get_firmware_version,

	.register_net = nbl_serv_register_net,
	.unregister_net = nbl_serv_unregister_net,
	.setup_txrx_queues = nbl_serv_setup_txrx_queues,
	.remove_txrx_queues = nbl_serv_remove_txrx_queues,
	.check_offload_status = nbl_serv_check_offload_status,
	.init_tx_rate = nbl_serv_init_tx_rate,
	.setup_q2vsi = nbl_serv_setup_q2vsi,
	.remove_q2vsi = nbl_serv_remove_q2vsi,
	.setup_rss = nbl_serv_setup_rss,
	.remove_rss = nbl_serv_remove_rss,
	.setup_rss_indir = nbl_serv_setup_rss_indir,
	.register_vsi_info = nbl_serv_register_vsi_info,

	.cpu_affinity_init = nbl_serv_cpu_affinity_init,
	.alloc_rings = nbl_serv_alloc_rings,
	.free_rings = nbl_serv_free_rings,
	.set_mask_en = nbl_serv_set_mask_en,
	.start_net_flow = nbl_serv_start_net_flow,
	.stop_net_flow = nbl_serv_stop_net_flow,
	.unregister_upcall_port = nbl_serv_unregister_upcall_port,
	.clear_flow = nbl_serv_clear_flow,
	.set_promisc_mode = nbl_serv_set_promisc_mode,
	.cfg_multi_mcast = nbl_serv_cfg_multi_mcast,
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
	.vsi_hw_stop = nbl_serv_vsi_hw_stop,
	.switch_traffic_default_dest = nbl_serv_switch_traffic_default_dest,
	.config_fd_flow_state = nbl_serv_config_fd_flow_state,
	.set_link_state = nbl_serv_set_link_state,

	/* For netdev ops */
	.netdev_open = nbl_serv_netdev_open,
	.netdev_stop = nbl_serv_netdev_stop,
	.change_mtu = nbl_serv_change_mtu,
	.change_rep_mtu = nbl_serv_change_rep_mtu,
	.set_mac = nbl_serv_set_mac,
	.rx_add_vid = nbl_serv_rx_add_vid,
	.rx_kill_vid = nbl_serv_rx_kill_vid,
	.get_stats64 = nbl_serv_get_stats64,
	.set_rx_mode = nbl_serv_set_rx_mode,
	.change_rx_flags = nbl_serv_change_rx_flags,
	.set_features = nbl_serv_set_features,
	.setup_tc = nbl_serv_setup_tc,
	.reset_tc_mqprio = nbl_serv_reset_tc_mqprio,
	.get_phys_port_name = nbl_serv_get_phys_port_name,
	.get_port_parent_id = nbl_serv_get_port_parent_id,
	.tx_timeout = nbl_serv_tx_timeout,
	.bridge_setlink = nbl_serv_bridge_setlink,
	.bridge_getlink = nbl_serv_bridge_getlink,
	.set_vf_spoofchk = nbl_serv_set_vf_spoofchk,
	.set_vf_link_state = nbl_serv_set_vf_link_state,
	.set_vf_mac = nbl_serv_set_vf_mac,
	.set_vf_rate = nbl_serv_set_vf_rate,
	.set_vf_vlan = nbl_serv_set_vf_vlan,
	.get_vf_config = nbl_serv_get_vf_config,
	.get_vf_stats = nbl_serv_get_vf_stats,
	.select_queue = nbl_serv_select_queue,
	.set_vf_trust = nbl_serv_set_vf_trust,
	.check_vf_is_active = nbl_serv_check_vf_is_active,

	/* For rep associated */
	.rep_netdev_open = nbl_serv_rep_netdev_open,
	.rep_netdev_stop = nbl_serv_rep_netdev_stop,
	.rep_start_xmit = nbl_serv_rep_start_xmit,
	.rep_get_stats64 = nbl_serv_rep_get_stats64,
	.rep_set_rx_mode = nbl_serv_rep_set_rx_mode,
	.rep_set_mac = nbl_serv_rep_set_mac,
	.rep_rx_add_vid = nbl_serv_rep_rx_add_vid,
	.rep_rx_kill_vid = nbl_serv_rep_rx_kill_vid,
	.rep_setup_tc = nbl_serv_rep_setup_tc,
	.rep_get_phys_port_name = nbl_serv_rep_get_phys_port_name,
	.rep_get_port_parent_id = nbl_serv_rep_get_port_parent_id,
	.get_rep_feature = nbl_serv_get_rep_feature,
	.get_rep_queue_num = nbl_serv_get_rep_queue_num,
	.get_rep_queue_info = nbl_serv_get_rep_queue_info,
	.get_user_queue_info = nbl_serv_get_user_queue_info,
	.alloc_rep_queue_mgt = nbl_serv_alloc_rep_queue_mgt,
	.free_rep_queue_mgt = nbl_serv_free_rep_queue_mgt,
	.set_eswitch_mode = nbl_serv_set_eswitch_mode,
	.get_eswitch_mode = nbl_serv_get_eswitch_mode,
	.alloc_rep_data = nbl_serv_alloc_rep_data,
	.free_rep_data = nbl_serv_free_rep_data,
	.set_rep_netdev_info = nbl_serv_set_rep_netdev_info,
	.unset_rep_netdev_info = nbl_serv_unset_rep_netdev_info,
	.disable_phy_flow = nbl_serv_disable_phy_flow,
	.enable_phy_flow = nbl_serv_enable_phy_flow,
	.init_acl = nbl_serv_init_acl,
	.uninit_acl = nbl_serv_uninit_acl,
	.set_upcall_rule = nbl_serv_set_upcall_rule,
	.unset_upcall_rule = nbl_serv_unset_upcall_rule,
	.switchdev_init_cmdq = nbl_serv_switchdev_init_cmdq,
	.switchdev_deinit_cmdq = nbl_serv_switchdev_deinit_cmdq,
	.set_tc_flow_info = nbl_serv_set_tc_flow_info,
	.unset_tc_flow_info = nbl_serv_unset_tc_flow_info,
	.get_tc_flow_info = nbl_serv_get_tc_flow_info,
	.register_indr_dev_tc_offload = nbl_serv_register_indr_dev_tc_offload,
	.unregister_indr_dev_tc_offload = nbl_serv_unregister_indr_dev_tc_offload,
	.set_lag_info = nbl_serv_set_lag_info,
	.unset_lag_info = nbl_serv_unset_lag_info,
	.set_netdev_ops = nbl_serv_set_netdev_ops,

	.get_vsi_id = nbl_serv_get_vsi_id,
	.get_my_pf = nbl_serv_get_my_pf,
	.get_eth_id = nbl_serv_get_eth_id,
	.setup_net_resource_mgt = nbl_serv_setup_net_resource_mgt,
	.remove_net_resource_mgt = nbl_serv_remove_net_resource_mgt,
	.start_net_resource_mgt = nbl_serv_start_net_resource_mgt,
	.stop_net_resource_mgt = nbl_serv_stop_net_resource_mgt,
	.stop_net_dev_timer = nbl_serv_stop_net_dev_timer,
	.start_net_dev_timer = nbl_serv_start_net_dev_timer,

	.set_lag_status = nbl_serv_set_lag_status,
	.init_hw_stats = nbl_serv_init_hw_stats,
	.remove_hw_stats = nbl_serv_remove_hw_stats,
	.get_rx_dropped = nbl_serv_get_rx_dropped,
	.enable_lag_protocol = nbl_serv_enable_lag_protocol,
	.cfg_lag_hash_algorithm = nbl_serv_cfg_lag_hash_algorithm,
	.cfg_lag_member_fwd = nbl_serv_cfg_lag_member_fwd,
	.cfg_lag_member_list = nbl_serv_cfg_lag_member_list,
	.cfg_lag_member_up_attr = nbl_serv_cfg_lag_member_up_attr,
	.cfg_bond_shaping = nbl_serv_cfg_bond_shaping,
	.cfg_bgid_back_pressure = nbl_serv_cfg_bgid_back_pressure,
	.get_board_info = nbl_serv_get_board_info,

	.enable_up_rdma_bypass = nbl_serv_enable_up_rdma_bypass,
	.get_rdma_cap_num = nbl_serv_get_rdma_cap_num,
	.setup_rdma_id = nbl_serv_setup_rdma_id,
	.remove_rdma_id = nbl_serv_remove_rdma_id,
	.register_rdma_grc_id = nbl_serv_register_rdma_grc_id,
	.unregister_rdma_grc_id = nbl_serv_unregister_rdma_grc_id,
	.register_rdma = nbl_serv_register_rdma,
	.unregister_rdma = nbl_serv_unregister_rdma,
	.get_hw_addr = nbl_serv_get_hw_addr,
	.get_rdma_hw_addr = nbl_serv_get_rdma_hw_addr,
	.get_real_hw_addr = nbl_serv_get_real_hw_addr,
	.get_function_id = nbl_serv_get_function_id,
	.get_real_bdf = nbl_serv_get_real_bdf,
	.set_eth_mac_addr = nbl_serv_set_eth_mac_addr,
	.process_abnormal_event = nbl_serv_process_abnormal_event,
	.process_sfp_plug_event = nbl_serv_process_sfp_plug_event,
	.get_owned_pf_bitmap = nbl_serv_get_owned_pf_bitmap,
	.adapt_desc_gother = nbl_serv_adapt_desc_gother,
	.process_flr = nbl_serv_process_flr,
	.process_qinfo_cfg = nbl_serv_process_qinfo_cfg,
	.get_board_id = nbl_serv_get_board_id,
	.covert_vfid_to_vsi_id = nbl_serv_covert_vfid_to_vsi_id,

	.get_mirror_table_id = nbl_serv_get_mirror_table_id,
	.configure_mirror = nbl_serv_configure_mirror,
	.configure_mirror_table = nbl_serv_configure_mirror_table,
	.clear_mirror_cfg = nbl_serv_clear_mirror_cfg,
	.get_devlink_info = nbl_serv_get_devlink_info,
	.update_devlink_flash = nbl_serv_update_devlink_flash,
	.get_adminq_tx_buf_size = nbl_serv_get_adminq_tx_buf_size,

	.check_fw_heartbeat = nbl_serv_check_fw_heartbeat,
	.check_fw_reset = nbl_serv_check_fw_reset,
	.set_netdev_carrier_state = nbl_serv_set_netdev_carrier_state,
	.set_port_state_update = nbl_serv_set_port_state_update,
	.cfg_eth_bond_event = nbl_serv_cfg_eth_bond_event,
	.cfg_fd_update_event = nbl_serv_cfg_fd_update_event,

	.setup_st = nbl_serv_setup_st,
	.remove_st = nbl_serv_remove_st,
	.register_real_st_name = nbl_serv_register_real_st_name,

	.get_vf_base_vsi_id = nbl_serv_get_vf_base_vsi_id,

	.setup_vf_config = nbl_serv_setup_vf_config,
	.remove_vf_config = nbl_serv_remove_vf_config,
	.register_dev_name = nbl_serv_register_dev_name,
	.get_dev_name = nbl_serv_get_dev_name,
	.setup_vf_resource = nbl_serv_setup_vf_resource,
	.remove_vf_resource = nbl_serv_remove_vf_resource,

#if IS_ENABLED(CONFIG_MACSEC)
	.init_macsec = nbl_serv_init_macsec,
	.uninit_macsec = nbl_serv_uninit_macsec,
#endif
	.get_xdp_queue_info = nbl_serv_get_xdp_queue_info,
	.set_xdp = nbl_serv_set_xdp,
	.set_hw_status = nbl_serv_set_hw_status,
	.check_hw_status = nbl_serv_check_hw_status,
	.get_hw_status = nbl_serv_get_hw_status,
	.get_active_func_bitmaps = nbl_serv_get_active_func_bitmaps,
	.configure_qos = nbl_serv_configure_qos,
	.get_qos_info = nbl_serv_qos_info,
	.set_pfc_buffer_size = nbl_serv_set_pfc_buffer_size,
	.get_pfc_buffer_size = nbl_serv_get_pfc_buffer_size,
	.configure_rdma_bw = nbl_serv_configure_rdma_bw,
	.set_rate_limit = nbl_serv_set_rate_limit,
#ifdef CONFIG_DCB
	.ieee_setets = nbl_serv_ieee_setets,
	.ieee_getets = nbl_serv_ieee_getets,
	.ieee_setpfc = nbl_serv_ieee_setpfc,
	.ieee_getpfc = nbl_serv_ieee_getpfc,
	.ieee_setapp = nbl_serv_ieee_setapp,
	.ieee_delapp = nbl_serv_ieee_delapp,
	.dcbnl_setpfccfg = nbl_serv_dcbnl_setpfccfg,
	.dcbnl_getpfccfg = nbl_serv_dcbnl_getpfccfg,
	.dcbnl_getnumtcs = nbl_serv_dcbnl_getnumtcs,
	.ieee_getdcbx = nbl_serv_ieee_getdcbx,
	.ieee_setdcbx = nbl_serv_ieee_setdcbx,
	.dcbnl_getcap = nbl_serv_dcbnl_getcap,
	.dcbnl_getstate = nbl_serv_dcnbl_getstate,
	.dcbnl_setstate = nbl_serv_dcnbl_setstate,
	.dcbnl_getpfcstate = nbl_serv_dcnbl_getpfcstate,
#endif
	.get_vf_function_id = nbl_serv_get_vf_function_id,
	.cfg_mirror_outputport_event = nbl_serv_cfg_mirror_outputport_event,
	.configure_tx_mirror_to_rdma = nbl_serv_configure_tx_mirror_to_rdma,
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

	return 0;
}

static void nbl_serv_remove_serv_mgt(struct nbl_common_info *common,
				     struct nbl_service_mgt **serv_mgt)
{
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(*serv_mgt);

	if (ring_mgt->rss_indir_user)
		devm_kfree(dev, ring_mgt->rss_indir_user);
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
	nbl_serv_setup_ktls_ops(&serv_ops);
	nbl_serv_setup_xfrm_ops(&serv_ops);
	nbl_serv_setup_macsec_ops(&serv_ops);
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
	disp_ops->get_res_pt_tbl(disp_ops_tbl->priv, &(*serv_ops_tbl)->pt_tbl);

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
