// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_resource_leonis.h"
#include "nbl_resource.h"
#include "nbl_txrx.h"
#include "nbl_fd.h"

static u16 nbl_res_leonis_txhdr_offset[NBL_TX_MAX] = {
	[NBL_FWD] = FIELD_LOC(2, NBL_TX_LEONIS_FWD_OFFSET, 1),
	[NBL_DPORT] = FIELD_LOC(2, NBL_TX_LEONIS_DPORT_OFFSET, 1),
	[NBL_DPORT_ID] = FIELD_LOC(2, NBL_TX_LEONIS_DPORT_ID_OFFSET, 1),
	[NBL_MSS] = FIELD_LOC(1, NBL_TX_LEONIS_MSS_OFFSET, 1),
	[NBL_CSUM] = FIELD_LOC(2, NBL_TX_LEONIS_CSUM_OFFSET, 1),
	[NBL_TLS_IDX] = FIELD_LOC(1, NBL_TX_LEONIS_TLS_ID_OFFSET, 1),
	[NBL_TLS_FLAG] = FIELD_LOC(1, NBL_TX_LEONIS_TLS_FLAG_OFFSET, 1),
};

static int nbl_res_get_queue_num(void *priv, u16 func_id, u16 *tx_queue_num, u16 *rx_queue_num);

static void nbl_res_setup_common_ops(struct nbl_resource_mgt *res_mgt)
{
	res_mgt->common_ops.get_queue_num = nbl_res_get_queue_num;
}

static int nbl_res_get_rep_queue_info(void *priv, struct nbl_ch_prm_get_queue_info *output)
{
	output->queue_size = NBL_DEFAULT_DESC_NUM;
	output->queue_num = NBL_DEFAULT_REP_HW_QUEUE_NUM;
	return 0;
}

static int nbl_res_get_queue_num(void *priv, u16 func_id, u16 *tx_queue_num, u16 *rx_queue_num)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)(priv);
	int pfid, vfid;

	nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pfid, &vfid);

	*tx_queue_num = nbl_res_get_pfvf_queue_num(res_mgt, pfid, vfid);
	*rx_queue_num = nbl_res_get_pfvf_queue_num(res_mgt, pfid, vfid);

	return 0;
}

static int nbl_res_save_qinfo_cfg(struct nbl_resource_mgt *res_mgt, u16 func_id)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_qinfo_cfg_table *qinfo = &NBL_RES_MGT_TO_QINFO_CFG(res_mgt)[func_id];
	dma_addr_t dma_addr = 0;
	u32 size_bwind =  0;

	phy_ops->get_qinfo_tx(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), func_id, &dma_addr, &size_bwind);
	qinfo->dma_addr = dma_addr;
	qinfo->size_bwind = size_bwind;

	return 0;
}

static int nbl_res_save_vf_bar_info(struct nbl_resource_mgt *res_mgt,
				    struct nbl_ch_prm_register_net_info *param)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_sriov_info *sriov_info = &NBL_RES_MGT_TO_SRIOV_INFO(res_mgt)[param->sfid];
	u64 pf_bar_start;
	u64 vf_bar_start;
	u16 pf_bdf;
	u64 vf_bar_size;
	u16 total_vfs;
	u16 offset;
	u16 stride;

	if (param->sfid < NBL_RES_MGT_TO_PF_NUM(res_mgt)) {
		pf_bar_start = phy_ops->get_pf_bar_addr(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
							param->sfid);
		sriov_info->pf_bar_start = pf_bar_start;
		dev_info(dev, "sriov_info, pf_bar_start:%llx\n", sriov_info->pf_bar_start);
	}

	pf_bdf = (u16)sriov_info->bdf;
	vf_bar_size = param->vf_bar_size;
	total_vfs = param->total_vfs;
	offset = param->offset;
	stride = param->stride;

	if (total_vfs) {
		sriov_info->offset = offset;
		sriov_info->stride = stride;
		vf_bar_start = phy_ops->get_vf_bar_addr(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
							param->sfid);
		sriov_info->vf_bar_start = vf_bar_start;
		sriov_info->vf_bar_len = div64_u64(vf_bar_size, total_vfs);

		dev_info(dev, "sriov_info, bdf:%x:%x.%x, num_vfs:%d, start_vf_func_id:%d, offset:%d, stride:%d, vf_bar_start: %llx",
			 PCI_BUS_NUM(pf_bdf), PCI_SLOT(pf_bdf & 0xff), PCI_FUNC(pf_bdf & 0xff),
			 sriov_info->num_vfs, sriov_info->start_vf_func_id, offset, stride,
			 sriov_info->vf_bar_start);
	}

	return 0;
}

static int nbl_res_register_net(void *priv, struct nbl_ch_prm_register_net_info *param,
				struct nbl_register_net_result *register_result)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_vdpa_status **vf_status = NBL_RES_MGT_TO_VDPA_VF_STATS(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	netdev_features_t csumo_features = 0;
	netdev_features_t tso_features = 0;
	netdev_features_t pf_features = 0;
	netdev_features_t vlano_features = 0;
	u16 tx_queue_num, rx_queue_num;
	u8 mac[ETH_ALEN] = {0};
	u16 vsi_id;
	int ret = 0;

	if (param->sfid < NBL_MAX_PF) {
		nbl_res_get_eth_mac(res_mgt, mac, nbl_res_pf_id_to_eth_id(res_mgt, param->sfid));
		pf_features = NBL_FEATURE(NETIF_F_NTUPLE);
		register_result->trusted = 1;
	} else {
		ether_addr_copy(mac, vsi_info->mac_info[param->sfid].mac);
		register_result->trusted = vsi_info->mac_info[param->sfid].trusted;
	}
	ether_addr_copy(register_result->mac, mac);

	if (performance_mode & BIT(NBL_QUIRKS_NO_TOE)) {
		csumo_features = NBL_FEATURE(NETIF_F_RXCSUM) |
				NBL_FEATURE(NETIF_F_IP_CSUM) |
				NBL_FEATURE(NETIF_F_IPV6_CSUM);
		tso_features = NBL_FEATURE(NETIF_F_TSO) |
			NBL_FEATURE(NETIF_F_TSO6) |
			NBL_FEATURE(NETIF_F_GSO_UDP_L4);
	}

	if (param->sfid < NBL_MAX_PF) /* vf unsupport */
		vlano_features = NBL_FEATURE(NETIF_F_HW_VLAN_CTAG_TX) |
				 NBL_FEATURE(NETIF_F_HW_VLAN_CTAG_RX) |
				 NBL_FEATURE(NETIF_F_HW_VLAN_STAG_TX) |
				 NBL_FEATURE(NETIF_F_HW_VLAN_STAG_RX);

	register_result->hw_features |= pf_features |
					csumo_features |
					tso_features |
					vlano_features |
					NBL_FEATURE(NETIF_F_SG) |
					NBL_FEATURE(NETIF_F_HW_TC) |
					NBL_FEATURE(NETIF_F_RXHASH);

	register_result->features |= register_result->hw_features |
				     NBL_FEATURE(NETIF_F_HW_TC) |
				     NBL_FEATURE(NETIF_F_HW_VLAN_CTAG_FILTER) |
				     NBL_FEATURE(NETIF_F_HW_VLAN_STAG_FILTER);

	register_result->vlan_features = register_result->features;

	register_result->max_mtu = NBL_MAX_JUMBO_FRAME_SIZE - NBL_PKT_HDR_PAD;

	register_result->vlan_proto = vsi_info->mac_info[param->sfid].vlan_proto;
	register_result->vlan_tci = vsi_info->mac_info[param->sfid].vlan_tci;
	register_result->rate = vsi_info->mac_info[param->sfid].rate;

	nbl_res_get_queue_num(res_mgt, param->sfid, &tx_queue_num, &rx_queue_num);
	register_result->tx_queue_num = tx_queue_num;
	register_result->rx_queue_num = rx_queue_num;
	register_result->queue_size = NBL_DEFAULT_DESC_NUM;

	if (param->is_vdpa) {
		set_bit(param->sfid, resource_info->vdpa.vdpa_func_bitmap);

		if (!vf_status[param->sfid]) {
			vf_status[param->sfid] = devm_kzalloc(dev, sizeof(struct nbl_vdpa_status),
							      GFP_KERNEL);
			if (!vf_status[param->sfid]) {
				ret = -ENOMEM;
				goto alloc_nbl_vf_stats_fail;
			}
		}
		vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, param->sfid, NBL_VSI_DATA);
		phy_ops->get_dstat_vsi_stat(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id,
					    &vf_status[param->sfid]->init_stats.tx_packets,
					    &vf_status[param->sfid]->init_stats.tx_bytes);
		phy_ops->get_ustat_vsi_stat(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id,
					    &vf_status[param->sfid]->init_stats.rx_packets,
					    &vf_status[param->sfid]->init_stats.rx_bytes);
		memcpy(&vf_status[param->sfid]->prev_stats, &vf_status[param->sfid]->init_stats,
		       sizeof(vf_status[param->sfid]->prev_stats));
		vf_status[param->sfid]->timestamp = jiffies;
	} else {
		clear_bit(param->sfid, resource_info->vdpa.vdpa_func_bitmap);
	}

	if (param->sfid >= NBL_RES_MGT_TO_PF_NUM(res_mgt))
		return nbl_res_save_qinfo_cfg(res_mgt, param->sfid);

	ret = nbl_res_save_vf_bar_info(res_mgt, param);
	if (ret)
		goto save_vf_bar_info_fail;

	return ret;

save_vf_bar_info_fail:
alloc_nbl_vf_stats_fail:
	return ret;
}

static u16 nbl_res_get_vsi_id(void *priv, struct nbl_ch_prm_get_vsi *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return nbl_res_func_id_to_vsi_id(res_mgt, param->sfid, param->type);
}

static int nbl_res_get_eth_id(void *priv, struct nbl_ch_prm_get_eth_id *param,
			      struct nbl_ch_prm_get_eth_id *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	u16 pf_id = nbl_res_vsi_id_to_pf_id(res_mgt, param->vsi_id);

	output->eth_mode = eth_info->eth_num;
	if (pf_id < eth_info->eth_num) {
		output->eth_id = eth_info->eth_id[pf_id];
		output->logic_eth_id = pf_id;
	/* if pf_id > eth_num, use eth_id 0 */
	} else {
		output->eth_id = eth_info->eth_id[0];
		output->logic_eth_id = 0;
	}

	return 0;
}

static u8 __iomem *nbl_res_get_hw_addr(void *priv, size_t *size)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->get_hw_addr(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), size);
}

static u64 nbl_res_get_real_hw_addr(void *priv, u16 *vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, *vsi_id);

	return nbl_res_get_func_bar_base_addr(res_mgt, func_id);
}

static u16 nbl_res_get_function_id(void *priv, u16 *vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return nbl_res_vsi_id_to_func_id(res_mgt, *vsi_id);
}

static int nbl_res_get_real_bdf(void *priv, u16 *vsi_id, struct nbl_ch_prm_get_real_bdf *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, *vsi_id);

	nbl_res_func_id_to_bdf(res_mgt, func_id, &output->bus, &output->dev, &output->function);

	return 0;
}

static void nbl_res_get_base_mac_addr(void *priv, u8 *mac)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	nbl_res_get_eth_mac(res_mgt, mac, nbl_res_pf_id_to_eth_id(res_mgt, 0));
}

static int nbl_res_set_pmd_debug(void *priv, bool pmd_debug)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_rep_offload_status *rep_status = &res_mgt->pmd_status.rep_status;

	rep_status->pmd_debug = pmd_debug;
	return 0;
}

static void nbl_res_set_offload_status(void *priv, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_upcall_port_info *upcall_port_info =
				&res_mgt->pmd_status.upcall_port_info;
	struct nbl_rep_offload_status *rep_status =
				&res_mgt->pmd_status.rep_status;

	if (!upcall_port_info->upcall_port_active ||
	    upcall_port_info->func_id != func_id)
		return;

	rep_status->timestamp = jiffies;
}

static void nbl_res_vdpa_itr_update(struct nbl_resource_mgt *res_mgt,
				    u16 func_id, bool active)
{
	struct nbl_vdpa_info *vdpa_info = &res_mgt->resource_info->vdpa;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_vdpa_status *vdpa_vf_stats = vdpa_info->vf_stats[func_id];
	struct nbl_vf_stats cur_stats = {0}, *prev_stats;
	u64 tx_rates = 0, rx_rates = 0, pkt_rates = 0, time_diff;
	u16 itr_level = 0;
	u16 vsi_id;
	struct nbl_get_intr_suppress_level_param suppress_prm = {0};
	struct nbl_ch_prm_set_intr_suppress_level set_prm = {0};

	if (!vdpa_vf_stats)
		return;

	if (active) {
		vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);
		phy_ops->get_dstat_vsi_stat(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id,
					    &cur_stats.tx_packets, &cur_stats.tx_bytes);
		phy_ops->get_ustat_vsi_stat(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id,
					    &cur_stats.rx_packets, &cur_stats.rx_bytes);

		time_diff = jiffies - vdpa_vf_stats->timestamp;
		if (time_diff > 0) {
			prev_stats = &vdpa_vf_stats->prev_stats;
			tx_rates = div64_u64(cur_stats.tx_packets - prev_stats->tx_packets,
					     time_diff) * HZ;
			rx_rates = div64_u64(cur_stats.rx_packets - prev_stats->rx_packets,
					     time_diff) * HZ;
			pkt_rates = max_t(u64, tx_rates, rx_rates);

			suppress_prm.rate = pkt_rates;
			suppress_prm.last_level = vdpa_vf_stats->itr_level;
			itr_level = nbl_res_intr_get_suppress_level(res_mgt,
								    &suppress_prm);
		} else {
			itr_level = vdpa_vf_stats->itr_level;
		}

		memcpy(&vdpa_vf_stats->prev_stats, &cur_stats, sizeof(cur_stats));
		vdpa_vf_stats->timestamp = jiffies;
	}

	if (itr_level != vdpa_vf_stats->itr_level) {
		set_prm.sfid = func_id;
		set_prm.vector_num = U16_MAX;
		set_prm.level = itr_level;
		nbl_res_intr_set_intr_suppress_level(res_mgt, &set_prm);
		vdpa_vf_stats->itr_level = itr_level;
	}
}

static int nbl_res_check_offload_status(void *priv, bool *is_down)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *res_info = res_mgt->resource_info;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_upcall_port_info *upcall_port_info =
				&res_mgt->pmd_status.upcall_port_info;
	struct nbl_rep_offload_status *rep_status =
				&res_mgt->pmd_status.rep_status;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int i;
	u16 func_id;
	u32 start, batch_cnt;

	if (!upcall_port_info->upcall_port_active)
		return 0;

	/* check pmd debug, no check if pmd_debug is on */
	if (rep_status->pmd_debug) {
		nbl_info(common, NBL_DEBUG_FLOW, "pmd is in debug mode now");
		rep_status->timestamp = jiffies;
		return 0;
	}

	start = res_info->vdpa.start;
	batch_cnt = NBL_VDPA_ITR_BATCH_CNT;
	if (rep_status->timestamp && time_after(jiffies, rep_status->timestamp + 30 * HZ)) {
		for (i = 0; i < NBL_OFFLOAD_STATUS_MAX_VSI; i++)
			clear_bit(i, rep_status->rep_vsi_bitmap);

		for (i = 0; i < NBL_OFFLOAD_STATUS_MAX_ETH; i++)
			clear_bit(i, rep_status->rep_eth_bitmap);

		upcall_port_info->upcall_port_active = false;
		nbl_err(common, NBL_DEBUG_FLOW, "offload found inactive!");
		phy_ops->clear_profile_table_action(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
		phy_ops->ipro_chksum_err_ctrl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), 0);
		nbl_res_update_offload_status(res_mgt);
		*is_down = true;

		start = 0;
		batch_cnt = NBL_MAX_FUNC;
	}

	i = 0;
	for (; start < NBL_MAX_FUNC;) {
		func_id = find_next_bit(res_info->vdpa.vdpa_func_bitmap, NBL_MAX_FUNC, start);
		if (func_id >= NBL_MAX_FUNC) {
			start = 0;
			break;
		}
		i++;
		start = func_id + 1;

		nbl_res_vdpa_itr_update(res_mgt, func_id,
					upcall_port_info->upcall_port_active);
		if (i >= batch_cnt)
			break;
	}

	res_info->vdpa.start = start;

	return 0;
}

static void nbl_res_get_rep_feature(void *priv, struct nbl_register_net_result *register_result)
{
	netdev_features_t csumo_features;

	csumo_features = NBL_FEATURE(NETIF_F_RXCSUM) |
			 NBL_FEATURE(NETIF_F_IP_CSUM) |
			 NBL_FEATURE(NETIF_F_IPV6_CSUM) |
			 NBL_FEATURE(NETIF_F_SCTP_CRC);
	register_result->hw_features = csumo_features | NBL_FEATURE(NETIF_F_HW_TC);
	register_result->features |= csumo_features | NBL_FEATURE(NETIF_F_HW_TC);
	register_result->max_mtu = NBL_MAX_JUMBO_FRAME_SIZE - NBL_PKT_HDR_PAD;
}

static int nbl_res_alloc_rep_data(void *priv, struct nbl_alloc_rep_data_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eswitch_info *eswitch_info = NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);

	eswitch_info->rep_data = devm_kcalloc(dev, param->num_vfs,
					      sizeof(struct nbl_rep_data), GFP_KERNEL);
	if (!eswitch_info->rep_data)
		return -ENOMEM;
	eswitch_info->num_vfs = param->num_vfs;
	eswitch_info->vf_base_vsi_id = param->vf_base_vsi_id;
	return 0;
}

static void nbl_res_free_rep_data(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eswitch_info **eswitch_info = &NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);

	if ((*eswitch_info)->rep_data) {
		devm_kfree(dev, (*eswitch_info)->rep_data);
		(*eswitch_info)->rep_data = NULL;
	}
	(*eswitch_info)->num_vfs = 0;
}

static void nbl_res_set_rep_netdev_info(void *priv, void *rep_data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eswitch_info *eswitch_info = NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_rep_data *rep = (struct nbl_rep_data *)rep_data;
	u16 rep_data_index;

	rep_data_index = nbl_res_get_rep_idx(eswitch_info, rep->rep_vsi_id);
	if (rep_data_index >= eswitch_info->num_vfs)
		return;
	eswitch_info->rep_data[rep_data_index].rep_vsi_id = rep->rep_vsi_id;
	eswitch_info->rep_data[rep_data_index].netdev = rep->netdev;
	nbl_info(common, NBL_DEBUG_RESOURCE, "nbl set rep netdev rep_vsi_id %d netdev %p\n",
		 rep->rep_vsi_id, rep->netdev);
}

static void nbl_res_unset_rep_netdev_info(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eswitch_info *eswitch_info = NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt);

	memset(eswitch_info->rep_data, 0,
	       eswitch_info->num_vfs * sizeof(struct nbl_rep_data));
}

static struct net_device *nbl_res_get_rep_netdev_info(void *priv, u16 rep_data_index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eswitch_info *eswitch_info = NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt);

	if (rep_data_index >= eswitch_info->num_vfs)
		return NULL;
	return eswitch_info->rep_data[rep_data_index].netdev;
}

static int nbl_res_disable_phy_flow(void *priv, u8 *eth_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return nbl_res_set_phy_flow(res_mgt, *eth_id, true);
}

static int nbl_res_enable_phy_flow(void *priv, u8 *eth_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return nbl_res_set_phy_flow(res_mgt, *eth_id, false);
}

static void nbl_res_init_acl(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	if (!res_mgt->resource_info->init_acl_refcnt)
		phy_ops->init_acl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));

	res_mgt->resource_info->init_acl_refcnt++;
}

static void nbl_res_uninit_acl(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	res_mgt->resource_info->init_acl_refcnt--;

	if (!res_mgt->resource_info->init_acl_refcnt)
		phy_ops->uninit_acl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
}

static int nbl_res_set_upcall_rule(void *priv, struct nbl_ch_prm_set_upcall *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->set_upcall_rule(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					param->eth_id, param->vsi_id);
}

static int nbl_res_unset_upcall_rule(void *priv, u8 *eth_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->unset_upcall_rule(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), *eth_id);
}

static void nbl_res_get_rep_stats(void *priv, struct nbl_get_rep_stats_param *param,
				  struct nbl_rep_stats *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eswitch_info *eswitch_info = NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt);
	struct nbl_rep_data *rep_data;
	u16 rep_data_index = 0;

	if (!eswitch_info || eswitch_info->mode != NBL_ESWITCH_OFFLOADS ||
	    ((nbl_res_get_rep_idx(eswitch_info, param->rep_vsi_id)) == U32_MAX))
		return;

	rep_data_index = nbl_res_get_rep_idx(eswitch_info, param->rep_vsi_id);
	if (rep_data_index >= eswitch_info->num_vfs)
		return;
	rep_data = &eswitch_info->rep_data[rep_data_index];
	if (rep_data->rep_vsi_id != param->rep_vsi_id)
		return;

	if (param->is_tx) {
		output->packets = rep_data->tx_packets;
		output->bytes   = rep_data->tx_bytes;
	} else {
		output->packets = rep_data->rx_packets;
		output->bytes   = rep_data->rx_bytes;
	}
}

static u16 nbl_res_get_rep_index(void *priv, u16 *rep_vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eswitch_info *eswitch_info = NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt);

	return nbl_res_get_rep_idx(eswitch_info, *rep_vsi_id);
}

static void nbl_res_register_net_rep(void *priv, u16 pf_id, u16 vf_id,
				     struct nbl_register_net_rep_result *result)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_rep_offload_status *rep_status =
				&res_mgt->pmd_status.rep_status;
	int pf_id_tmp, vf_id_tmp;

	pf_id_tmp = pf_id;
	if (vf_id == U16_MAX)
		vf_id_tmp = U32_MAX;
	else
		vf_id_tmp = vf_id;

	result->vsi_id = nbl_res_pfvfid_to_vsi_id(res_mgt, pf_id_tmp, vf_id_tmp, NBL_VSI_DATA);
	result->func_id = nbl_res_pfvfid_to_func_id(res_mgt, pf_id_tmp, vf_id_tmp);

	if (result->vsi_id >= NBL_OFFLOAD_STATUS_MAX_VSI) {
		nbl_err(common, NBL_DEBUG_RESOURCE,
			"register_net_rep pf %d vf %d vsi_id %d err\n",
			pf_id, vf_id, result->vsi_id);
		return;
	}

	set_bit(result->vsi_id, rep_status->rep_vsi_bitmap);
	nbl_res_update_offload_status(res_mgt);
}

static void nbl_res_unregister_net_rep(void *priv, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_rep_offload_status *rep_status =
				&res_mgt->pmd_status.rep_status;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	if (vsi_id >= NBL_OFFLOAD_STATUS_MAX_VSI) {
		nbl_err(common, NBL_DEBUG_RESOURCE,
			"unregister_net_rep vsi_id %d err\n", vsi_id);
		return;
	}

	/* set rss to l4 */
	phy_ops->set_epro_rss_default(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id, 0);
	clear_bit(vsi_id, rep_status->rep_vsi_bitmap);
	nbl_res_update_offload_status(res_mgt);
}

static void nbl_res_register_eth_rep(void *priv, u8 eth_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_rep_offload_status *rep_status =
				&res_mgt->pmd_status.rep_status;

	if (eth_id >= NBL_OFFLOAD_STATUS_MAX_ETH) {
		nbl_err(common, NBL_DEBUG_RESOURCE,
			"register_eth_rep eth_id %d err\n", eth_id);
		return;
	}
	set_bit(eth_id, rep_status->rep_eth_bitmap);
	nbl_res_update_offload_status(res_mgt);
}

static void nbl_res_unregister_eth_rep(void *priv, u8 eth_id)
{
	struct nbl_resource_mgt *res_mgt =
				(struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_rep_offload_status *rep_status =
				&res_mgt->pmd_status.rep_status;

	if (eth_id >= NBL_OFFLOAD_STATUS_MAX_ETH) {
		nbl_err(common, NBL_DEBUG_RESOURCE,
			"unregister_eth_rep eth_id %d err\n", eth_id);
		return;
	}

	clear_bit(eth_id, rep_status->rep_eth_bitmap);
	nbl_res_update_offload_status(res_mgt);
}

static int nbl_res_register_upcall_port(void *priv, u16 func_id)
{
	int pf_id, vf_id, i;
	u8 eth_id;
	struct nbl_resource_mgt *res_mgt =
				(struct nbl_resource_mgt *)priv;
	struct nbl_upcall_port_info *upcall_port_info =
				&res_mgt->pmd_status.upcall_port_info;
	struct nbl_rep_offload_status *rep_status =
				&res_mgt->pmd_status.rep_status;
	u16 vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id,
					       NBL_VSI_SERV_PF_DATA_TYPE);
	nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pf_id, &vf_id);
	eth_id = nbl_res_pf_id_to_eth_id(res_mgt, pf_id);

	rep_status->timestamp = jiffies;
	if (!upcall_port_info->upcall_port_active) {
		upcall_port_info->func_id = func_id;
		upcall_port_info->upcall_port_active = true;

		for (i = 0; i < NBL_OFFLOAD_STATUS_MAX_VSI; i++)
			clear_bit(i, rep_status->rep_vsi_bitmap);

		for (i = 0; i < NBL_OFFLOAD_STATUS_MAX_ETH; i++)
			clear_bit(i, rep_status->rep_eth_bitmap);

		set_bit(vsi_id, rep_status->rep_vsi_bitmap);
		set_bit(eth_id, rep_status->rep_eth_bitmap);

		memset(res_mgt->pmd_status.other_pmd_cfg, true,
		       sizeof(res_mgt->pmd_status.other_pmd_cfg));
		nbl_res_update_offload_status(res_mgt);
		return 0;
	}

	if (func_id != upcall_port_info->func_id) {
		nbl_err(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_RESOURCE,
			"can not add rep port with two pf port, register_upcall_port failed\n");
		return -EINVAL;
	}

	return 0;
}

static void nbl_res_unregister_upcall_port(void *priv, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt =
				(struct nbl_resource_mgt *)priv;
	struct nbl_upcall_port_info *upcall_port_info =
				&res_mgt->pmd_status.upcall_port_info;
	struct nbl_rep_offload_status *rep_status =
				&res_mgt->pmd_status.rep_status;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_ch_prm_set_decap_set decap_set;
	int i;

	memset(&decap_set, 0, sizeof(decap_set));

	if (!upcall_port_info->upcall_port_active ||
	    upcall_port_info->func_id != func_id)
		return;

	for (i = 0; i < NBL_OFFLOAD_STATUS_MAX_VSI; i++)
		clear_bit(i, rep_status->rep_vsi_bitmap);

	for (i = 0; i < NBL_OFFLOAD_STATUS_MAX_ETH; i++)
		clear_bit(i, rep_status->rep_eth_bitmap);

	memset(res_mgt->pmd_status.other_pmd_cfg, false, sizeof(res_mgt->pmd_status.other_pmd_cfg));
	nbl_res_update_offload_status(res_mgt);

#define NBL_IPRO_DECAP_SET_LEN 16
	/* clear ipro udl */
	for (i = 0; i < NBL_IPRO_DECAP_SET_LEN; i++) {
		decap_set.idx = i;
		nbl_flow_set_decap_set(priv, &decap_set);
	}

	phy_ops->clear_profile_table_action(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	phy_ops->ipro_chksum_err_ctrl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), 0);
	upcall_port_info->upcall_port_active = false;
}

static void nbl_res_init_offload_fwd(void *priv, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->init_offload_fwd(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), func_id);
}

static void nbl_res_init_cmdq(void *priv, void *data, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_chan_cmdq_init_info *cmdq_param =
		(struct nbl_chan_cmdq_init_info *)data;
	u8 bus;
	u8 dev;
	u8 func;

	nbl_res_func_id_to_bdf(res_mgt, func_id, &bus, &dev, &func);
	cmdq_param->bdf_num = (u16)PCI_DEVID(bus, PCI_DEVFN(dev, func));

	phy_ops->init_cmdq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), data, func_id);
}

static void nbl_res_destroy_cmdq(void *priv)
{
	struct nbl_resource_mgt *res_mgt =
		(struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->destroy_cmdq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
}

static void nbl_res_reset_cmdq(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_chan_cmdq_init_info cmdq_param;

	phy_ops->reset_cmdq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), &cmdq_param);
}

static void nbl_res_init_rep(void *priv, u16 vsi_id, u8 inner_type,
			     u8 outer_type, u8 rep_type)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->init_rep(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id,
			  inner_type, outer_type, rep_type, 0);
}

static void nbl_res_init_flow(void *priv, void *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->init_flow(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param);
}

static void nbl_res_deinit_flow(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->deinit_flow(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
}

static void nbl_res_offload_flow_rule(void *priv, void *data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->offload_flow_rule(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), data);
}

static void nbl_res_get_flow_acl_switch(void *priv, u8 *acl_enable)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->get_flow_acl_switch(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				     acl_enable);
}

static void nbl_res_cfg_tnl_offload_profile(void *priv, u8 mode)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->cfg_tnl_offload_profile(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mode);
}

static void nbl_res_get_line_rate_info(void *priv, void *data, void *result)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->get_line_rate_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), data, result);
}

static int nbl_res_init_vdpaq(void *priv, u16 func_id, u64 pa, u32 size)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u8 bus, dev, func;
	u16 bdf;

	nbl_res_func_id_to_bdf(res_mgt, func_id, &bus, &dev, &func);
	bdf = PCI_DEVID(bus, PCI_DEVFN(dev, func));

	return phy_ops->init_vdpaq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), func_id, bdf, pa, size);
}

static void nbl_res_destroy_vdpaq(void *priv, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->destroy_vdpaq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), func_id);
}

static int nbl_res_get_upcall_port(void *priv, u16 *bdf)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_upcall_port_info *upcall_port_info =
				&res_mgt->pmd_status.upcall_port_info;
	u8 bus, dev, func;

	if (!upcall_port_info->upcall_port_active)
		return U32_MAX;

	nbl_res_func_id_to_bdf(res_mgt, upcall_port_info->func_id, &bus, &dev, &func);
	*bdf = (u16)PCI_DEVID(common->bus, PCI_DEVFN(dev, func));
	return 0;
}

static void nbl_res_get_reg_dump(void *priv, u32 *data, u32 len)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->get_reg_dump(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), data, len);
}

static int nbl_res_get_reg_dump_len(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->get_reg_dump_len(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
}

static int nbl_res_process_abnormal_event(void *priv, struct nbl_abnormal_event_info *abnomal_info)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->process_abnormal_event(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), abnomal_info);
}

static int nbl_res_cfg_lag_hash_algorithm(void *priv,
					  struct nbl_ch_prm_cfg_lag_hash_algorithm *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->cfg_lag_hash_algorithm(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					       param->eth_id, param->lag_id, param->hash_type);
}

static int nbl_res_cfg_lag_member_fwd(void *priv,
				      struct nbl_ch_prm_cfg_lag_member_fwd *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->cfg_lag_member_fwd(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					   param->eth_id, param->lag_id, param->fwd);
}

static int nbl_res_cfg_lag_member_list(void *priv, struct nbl_lag_member_list_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->cfg_lag_member_list(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param);
}

static int nbl_res_cfg_lag_member_up_attr(void *priv,
					  struct nbl_ch_prm_cfg_lag_member_up_attr *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->cfg_lag_member_up_attr(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					       param->eth_id, param->lag_id, param->enable);
}

static int nbl_res_cfg_bond_shaping(void *priv, struct nbl_ch_prm_cfg_bond_shaping *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->cfg_bond_shaping(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->eth_id,
					 res_mgt->resource_info->board_info.eth_speed,
					 param->enable);
}

static int nbl_res_cfg_bgid_back_pressure(void *priv,
					  struct nbl_ch_prm_cfg_bgid_back_pressure *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->cfg_bgid_back_pressure(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->main_eth_id,
					param->other_eth_id, param->enable,
					res_mgt->resource_info->board_info.eth_speed);

	return 0;
}

static int nbl_res_switchdev_init_cmdq(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_mgt *chan_mgt = NBL_RES_MGT_TO_CHAN_PRIV(res_mgt);
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(NBL_RES_MGT_TO_COMMON(res_mgt));

	return chan_ops->init_cmdq(dev, chan_mgt);
}

static int nbl_res_switchdev_deinit_cmdq(void *priv, u8 index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_mgt *chan_mgt = NBL_RES_MGT_TO_CHAN_PRIV(res_mgt);
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(NBL_RES_MGT_TO_COMMON(res_mgt));

	return chan_ops->deinit_cmdq(dev, chan_mgt, index);
}

static int nbl_res_set_tc_flow_info(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int i = 0;

	if (common->tc_inst_id >= NBL_TC_FLOW_INST_COUNT) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow set inst_id=%d is invalid.\n",
			common->tc_inst_id);
		return -EINVAL;
	}

	if (!tc_flow_mgt->pf_set_tc_count) {
		nbl_tc_set_flow_info(tc_flow_mgt, common->tc_inst_id);
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow set inst_id=%d success.\n",
			 common->tc_inst_id);

		nbl_info(common, NBL_DEBUG_FLOW, "tc flow set kgen cvlan zero, set ped vsi type zero\n");
		phy_ops->set_tc_kgen_cvlan_zero(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));

		for (i = 0; i < NBL_TPID_PORT_NUM; i++)
			phy_ops->set_ped_tab_vsi_type(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), i, 0);
	}

	tc_flow_mgt->pf_set_tc_count++;
	phy_ops->ipro_chksum_err_ctrl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), 1);
	nbl_info(common, NBL_DEBUG_FLOW, "tc flow set pf_set_tc_count++=%d\n",
		 tc_flow_mgt->pf_set_tc_count);

	return 0;
}

static int nbl_res_unset_tc_flow_info(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int ret = 0;
	int i = 0;

	if (common->tc_inst_id >= NBL_TC_FLOW_INST_COUNT) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow unset inst_id=%d is invalid.\n",
			common->tc_inst_id);
		return -EINVAL;
	}

	tc_flow_mgt->pf_set_tc_count--;
	nbl_info(common, NBL_DEBUG_FLOW, "tc flow set pf_set_tc_count--=%d\n",
		 tc_flow_mgt->pf_set_tc_count);

	if (!tc_flow_mgt->pf_set_tc_count) {
		ret = nbl_tc_flow_flush_flow(res_mgt);
		if (ret)
			return -EINVAL;

		nbl_info(common, NBL_DEBUG_FLOW, "tc flow unset kgen cvlan, set ped vsi type zero\n");
		phy_ops->unset_tc_kgen_cvlan(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));

		for (i = 0; i < NBL_TPID_PORT_NUM; i++) {
			if (tc_flow_mgt->port_tpid_type[i] != 0) {
				phy_ops->set_ped_tab_vsi_type(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
							      i, 0);
				tc_flow_mgt->port_tpid_type[i] = 0;
			}
		}

		nbl_tc_unset_flow_info(common->tc_inst_id);
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow unset inst_id=%d success.\n",
			 common->tc_inst_id);

		phy_ops->ipro_chksum_err_ctrl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), 0);
	}

	return 0;
}

static int nbl_res_get_tc_flow_info(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	if (common->tc_inst_id >= NBL_TC_FLOW_INST_COUNT) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow get inst_id=%d is invalid.\n",
			common->tc_inst_id);
		return -EINVAL;
	}

	if (NBL_COMMON_TO_PCI_FUNC_ID(common))
		NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt) = nbl_tc_get_flow_info(common->tc_inst_id);
	nbl_info(common, NBL_DEBUG_FLOW, "tc flow get inst_id=%d success.\n",
		 common->tc_inst_id);

	return 0;
}

static int nbl_res_get_owned_pf_bitmap(void *priv,
				       unsigned long **owned_pf_bitmap, u8 *max_pf, u16 *bdf)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	u8 bus = common->hw_bus;

	*owned_pf_bitmap = resource_info->owned_pf_bitmap;
	*max_pf = NBL_MAX_PF_LEONIS;
	*bdf = PCI_DEVID(bus, PCI_DEVFN(common->devid, NBL_COMMON_TO_PCI_FUNC_ID(common)));

	return 0;
}

static int nbl_res_get_p4_info(void *priv, char *verify_code)
{
	/* We actually only care about the snic-v3r1 part, won't check m18xxx */
	strscpy(verify_code, "snic_v3r1_m18xxx", NBL_P4_NAME_LEN);

	return NBL_P4_DEFAULT;
}

static int nbl_res_get_p4_used(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);

	return resource_info->p4_used;
}

static int nbl_res_set_p4_used(void *priv, int *p4_type)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);

	resource_info->p4_used = *p4_type;

	return 0;
}

static u32 nbl_res_get_p4_version(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return res_mgt->resource_info->board_info.p4_version;
}

static int nbl_res_load_p4(void *priv, struct nbl_load_p4_param *p4_param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	if (p4_param->start || p4_param->end)
		return 0;

	phy_ops->load_p4(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), p4_param->addr,
			 p4_param->size, p4_param->data);

	return 0;
}

static void nbl_res_get_board_info(void *priv, struct nbl_board_port_info *board_info)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	memcpy(board_info, &res_mgt->resource_info->board_info, sizeof(*board_info));
}

static u16 nbl_res_get_vf_base_vsi_id(void *priv, u16 pf_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return nbl_res_pfvfid_to_vsi_id(res_mgt, pf_id, 0, NBL_VSI_DATA);
}

static void nbl_res_flr_clear_net(void *priv, u16 vf_id)
{
	u16 func_id = vf_id + NBL_MAX_PF;
	u16 vsi_id = nbl_res_func_id_to_vsi_id(priv, func_id, NBL_VSI_DATA);

	nbl_res_unregister_rdma(priv, &vsi_id);

	nbl_res_unregister_net(priv, &func_id);
}

static void nbl_res_flr_clear_rdma(void *priv, u16 vf_id)
{
	u16 func_id = vf_id + NBL_MAX_PF;
	u16 vsi_id = nbl_res_func_id_to_vsi_id(priv, func_id, NBL_VSI_DATA);

	nbl_res_unregister_rdma(priv, &vsi_id);
}

static u16 nbl_res_covert_vfid_to_vsi_id(void *priv, u16 vf_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 func_id = vf_id + NBL_MAX_PF;

	return nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);
}

static bool nbl_res_check_vf_is_active(void *priv, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return nbl_res_vf_is_active(res_mgt, func_id);
}

static int nbl_res_check_vf_is_vdpa(void *priv, u16 func_id, u8 *is_vdpa)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);

	*is_vdpa = test_bit(func_id, resource_info->vdpa.vdpa_func_bitmap);
	return 0;
}

static int nbl_res_get_vdpa_vf_stats(void *priv, u16 func_id, struct nbl_vf_stats *vf_stats)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_vdpa_status *vdpa_vf_stats = NULL;
	struct nbl_vf_stats vdpa_vf_stats_current = {0}, *init_stats;
	u16 vsi_id;

	if (NBL_RES_MGT_TO_VDPA_VF_STATS(res_mgt) &&
	    NBL_RES_MGT_TO_VDPA_VF_STATS(res_mgt)[func_id]) {
		vdpa_vf_stats = NBL_RES_MGT_TO_VDPA_VF_STATS(res_mgt)[func_id];
		init_stats = &vdpa_vf_stats->init_stats;
	} else {
		dev_err(dev, "function %d vdpa_vf_stats is NULL\n", func_id);
		return -EFAULT;
	}

	vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);
	phy_ops->get_dstat_vsi_stat(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id,
				    &vdpa_vf_stats_current.tx_packets,
				    &vdpa_vf_stats_current.tx_bytes);
	phy_ops->get_ustat_vsi_stat(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id,
				    &vdpa_vf_stats_current.rx_packets,
				    &vdpa_vf_stats_current.rx_bytes);

	vf_stats->tx_packets = vdpa_vf_stats_current.tx_packets - init_stats->tx_packets;
	vf_stats->tx_bytes = vdpa_vf_stats_current.tx_bytes - init_stats->tx_bytes;
	vf_stats->rx_packets = vdpa_vf_stats_current.rx_packets - init_stats->rx_packets;
	vf_stats->rx_bytes = vdpa_vf_stats_current.rx_bytes - init_stats->rx_bytes;

	return 0;
}

static int nbl_res_get_pkt_drop_stats(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_chan_param_drop_stats_resp *drop_stats = NBL_RES_MGT_TO_DROP_STATS(res_mgt);
	struct nbl_chan_param_drop_stats_resp drop_stats_temp = {0};
	u32 uvn_drop_queue_disable = 0;
	u8 eth_id = 0;
	u16 cnt;
	int i = 0;

	for (i = 0; i < eth_info->eth_num; i++) {
		eth_id = eth_info->eth_id[i];
		phy_ops->get_ustore_pkt_drop_stats(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						   eth_id, &drop_stats_temp);
		drop_stats[eth_id].rx_drop_packets += drop_stats_temp.rx_drop_packets;
		drop_stats[eth_id].rx_trun_packets += drop_stats_temp.rx_trun_packets;
	}
	cnt = phy_ops->get_fake_drop_stats(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	NBL_RES_MGT_TO_FAKE_STATS(res_mgt) += cnt;

	if (!resource_info->uvn_drop_queue_disable_init) {
		phy_ops->get_uvn_drop_queue_disable(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						    &uvn_drop_queue_disable);
		resource_info->start_uvn_drop_queue_disable = uvn_drop_queue_disable;
		resource_info->uvn_drop_queue_disable_init = true;
	}

	return 0;
}

static int nbl_res_get_total_pkt_drop_stats(void *priv,
					    struct nbl_chan_param_get_total_drop *param,
					    struct nbl_chan_param_drop_stats_resp *nbl_drop_stats)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_chan_param_drop_stats_resp *drop_stats = NBL_RES_MGT_TO_DROP_STATS(res_mgt);
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u32 uvn_drop_queue_disable = 0;

	if (param->op_type == STAT_TYPE_USTORE) {
		nbl_drop_stats->rx_drop_packets = drop_stats[param->eth_id].rx_drop_packets;
		nbl_drop_stats->rx_trun_packets = drop_stats[param->eth_id].rx_trun_packets;
	} else if (param->op_type == STAT_TYPE_FAKE) {
		nbl_drop_stats->rx_drop_packets = NBL_RES_MGT_TO_FAKE_STATS(res_mgt);
	} else if (param->op_type == STAT_TYPE_RX_DROPPED_QUEUE_DISABLE) {
		phy_ops->get_uvn_drop_queue_disable(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						    &uvn_drop_queue_disable);
		nbl_drop_stats->rx_drop_packets = uvn_drop_queue_disable -
						resource_info->start_uvn_drop_queue_disable;
	} else {
		return -EINVAL;
	}
	return 0;
}

static int nbl_res_get_board_id(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	return NBL_COMMON_TO_BOARD_ID(common);
}

static int nbl_res_get_eth_bond_info(void *priv, struct nbl_bond_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_eth_bond_info *eth_bond_info = NBL_RES_MGT_TO_ETH_BOND_INFO(res_mgt);
	struct nbl_eth_bond_entry *entry = NULL;
	int num = 0, i = 0, j = 0, pf_id = 0;

	for (i = 0; i < NBL_LAG_MAX_NUM; i++) {
		entry = &eth_bond_info->entry[i];

		if (!entry->lag_num)
			continue;

		for (j = 0; j < entry->lag_num; j++) {
			pf_id = nbl_res_eth_id_to_pf_id(res_mgt, entry->eth_id[j]);

			param->info[num].port[j].eth_id = entry->eth_id[j];
			param->info[num].port[j].vsi_id =
				nbl_res_pfvfid_to_vsi_id(res_mgt, pf_id, -1, NBL_VSI_DATA);
			param->info[num].port[j].is_active =
				phy_ops->get_lag_fwd(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						     entry->eth_id[j]);
		}

		param->info[num].mem_num = entry->lag_num;
		param->info[num].lag_id = entry->lag_id;

		num++;
	}

	param->lag_num = num;

	return 0;
}

static void nbl_rx_csum_leonis(struct nbl_res_rx_ring *rx_ring, struct sk_buff *skb,
			       struct nbl_rx_extend_head_leonis *rx_hdr_param)
{
	skb->ip_summed = CHECKSUM_NONE;
	skb_checksum_none_assert(skb);

	/* if user disable RX Checksum Offload, then stack verify the rx checksum */
	if (!(rx_ring->netdev->features & NETIF_F_RXCSUM))
		return;

	if (!rx_hdr_param->checksum_status)
		return;

	if (rx_hdr_param->error_code) {
		rx_ring->rx_stats.rx_csum_errors++;
		return;
	}

	/* For tunnel pkts, indicates inner csum offload */

	skb->ip_summed = CHECKSUM_UNNECESSARY;
	rx_ring->rx_stats.rx_csum_packets++;
}

static inline int nbl_rx_vlan_pop(struct nbl_res_rx_ring *rx_ring, struct sk_buff *skb)
{
	struct vlan_ethhdr *veth;
	__be16 vlan_proto;
	u16 vlan_tci;
	u16 flag;

	if (!rx_ring->vlan_proto) {
		struct ethhdr *eth = (struct ethhdr *)skb->data;
		__be16 ether_type = eth->h_proto;

		if (ether_type != htons(ETH_P_8021Q) && ether_type != htons(ETH_P_8021AD))
			return 0;
		veth = (struct vlan_ethhdr *)skb->data;
		vlan_proto = veth->h_vlan_proto;
		vlan_tci = ntohs(veth->h_vlan_TCI);
		flag = (rx_ring->netdev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
			(ether_type == htons(ETH_P_8021Q));
		flag |= (rx_ring->netdev->features & NETIF_F_HW_VLAN_STAG_RX) &&
			(ether_type == htons(ETH_P_8021AD));
		if (flag) {
			memmove(skb->data + VLAN_HLEN, skb->data, 2 * ETH_ALEN);
			__skb_pull(skb, VLAN_HLEN);
			rx_ring->rx_stats.rx_removed_vlan_packets += 1;
			__vlan_hwaccel_put_tag(skb, vlan_proto, vlan_tci);
		}
		return 0;
	}

	veth = (struct vlan_ethhdr *)skb->data;
	vlan_proto = veth->h_vlan_proto;
	vlan_tci = ntohs(veth->h_vlan_TCI);
	if (rx_ring->vlan_proto != ntohs(vlan_proto) ||
	    (rx_ring->vlan_tci & VLAN_VID_MASK) != (vlan_tci & VLAN_VID_MASK))
		return 1;

	memmove(skb->data + VLAN_HLEN, skb->data, 2 * ETH_ALEN);
	__skb_pull(skb, VLAN_HLEN);

	return 0;
}

#if IS_ENABLED(CONFIG_TLS_DEVICE)
static inline int nbl_ktls_rx_handle_skb_leonis(struct nbl_res_rx_ring *rx_ring,
						struct sk_buff *skb,
						struct nbl_rx_extend_head_leonis *rx_hdr_param)
{
	if (!rx_hdr_param->l4s_hdl_ind)
		return 0;

	if (rx_hdr_param->l4s_dec_ind) {
		skb->decrypted = 1;
		rx_ring->rx_stats.tls_decrypted_packets++;
	} else if (rx_hdr_param->l4s_resync_ind) {
		rx_ring->rx_stats.tls_resync_req_num++;
		nbl_resync_update_sn(rx_ring->netdev, skb, rx_hdr_param->l4s_tcp_offset);
		dev_dbg(NBL_RING_TO_DEV(rx_ring), "ingress ktls %u resync sn\n",
			rx_hdr_param->l4s_sid);
	} else if (!rx_hdr_param->l4s_check_ind) {
		dev_dbg(NBL_RING_TO_DEV(rx_ring), "ingress ktls %u auth fail\n",
			rx_hdr_param->l4s_sid);
	} else {
		dev_err(NBL_RING_TO_DEV(rx_ring), "ingress ktls %u unknown error\n",
			rx_hdr_param->l4s_sid);
	}

	return 0;
}
#endif

u16 nbl_res_parse_rx_extend_header_leonis(struct nbl_res_rx_ring *ring, void *hdr,
					  struct sk_buff *skb)
{
	struct nbl_rx_extend_head_leonis *pkthdr = hdr;
	int drop = 0;

	nbl_rx_csum_leonis(ring, skb, pkthdr);
	drop = nbl_rx_vlan_pop(ring, skb);
	if (drop)
		return U16_MAX;

#if IS_ENABLED(CONFIG_TLS_DEVICE)
	nbl_ktls_rx_handle_skb_leonis(ring, skb, pkthdr);
#endif

	return pkthdr->sport_id;
}

static u32 nbl_res_get_perf_dump_length(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->get_perf_dump_length(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
}

static u32 nbl_res_get_perf_dump_data(void *priv,
				      struct nbl_ch_prm_get_perf_dump_data *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->get_perf_dump_data(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->buffer,
					   param->size);
}

static int nbl_res_clear_mirror_cfg(void *priv, u16 *func_id)
{
	u16 data_vsi, user_vsi;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	data_vsi = nbl_res_func_id_to_vsi_id(res_mgt, *func_id, NBL_VSI_DATA);
	user_vsi = nbl_res_func_id_to_vsi_id(res_mgt, *func_id, NBL_VSI_USER);

	phy_ops->clear_mirror_cfg(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), data_vsi);
	phy_ops->clear_mirror_cfg(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), user_vsi);

	return 0;
}

static void nbl_res_set_rx_csum_drop(void *priv, bool enable)
{
	enum nbl_fix_cap_type cap_type = NBL_RX_CSUM_ERR_DROP_CAP;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	if (!nbl_res_get_fix_capability(res_mgt, &cap_type))
		return;

	phy_ops->ipro_chksum_err_ctrl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), enable);
	phy_ops->set_dpa_chksum_errcode(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), enable);
}

static void nbl_res_cfg_vlan_filtering(void *priv, bool filter)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->cfg_vlan_filtering(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), filter);
}

static int nbl_res_get_lag_ports_max(void *priv)
{
	return 2;
}

static struct nbl_resource_ops res_ops = {
	.register_net = nbl_res_register_net,
	.unregister_net = nbl_res_unregister_net,
	.check_active_vf = nbl_res_check_active_vf,
	.get_base_mac_addr = nbl_res_get_base_mac_addr,
	.get_vsi_id = nbl_res_get_vsi_id,
	.get_my_pf = nbl_res_get_my_pf,
	.get_eth_id = nbl_res_get_eth_id,
	.get_rep_feature = nbl_res_get_rep_feature,
	.get_rep_queue_info = nbl_res_get_rep_queue_info,
	.get_user_queue_info = nbl_res_get_user_queue_info,
	.alloc_rep_data = nbl_res_alloc_rep_data,
	.free_rep_data = nbl_res_free_rep_data,
	.set_rep_netdev_info = nbl_res_set_rep_netdev_info,
	.unset_rep_netdev_info = nbl_res_unset_rep_netdev_info,
	.get_rep_netdev_info = nbl_res_get_rep_netdev_info,
	.disable_phy_flow = nbl_res_disable_phy_flow,
	.enable_phy_flow = nbl_res_enable_phy_flow,
	.init_acl = nbl_res_init_acl,
	.uninit_acl = nbl_res_uninit_acl,
	.set_upcall_rule = nbl_res_set_upcall_rule,
	.unset_upcall_rule = nbl_res_unset_upcall_rule,
	.set_shaping_dport_vld = nbl_res_set_shaping_dport_vld,
	.set_dport_fc_th_vld = nbl_res_set_dport_fc_th_vld,
	.get_rep_stats = nbl_res_get_rep_stats,
	.get_rep_index = nbl_res_get_rep_index,
	.setup_rdma_id = nbl_res_setup_rdma_id,
	.remove_rdma_id = nbl_res_remove_rdma_id,
	.register_rdma_grc_id = nbl_res_register_rdma_grc_id,
	.unregister_rdma_grc_id = nbl_res_unregister_rdma_grc_id,
	.register_rdma = nbl_res_register_rdma,
	.unregister_rdma = nbl_res_unregister_rdma,
	.get_hw_addr = nbl_res_get_hw_addr,
	.get_real_hw_addr = nbl_res_get_real_hw_addr,
	.get_function_id = nbl_res_get_function_id,
	.get_real_bdf = nbl_res_get_real_bdf,
	.get_product_flex_cap = nbl_res_get_flex_capability,
	.get_product_fix_cap = nbl_res_get_fix_capability,
	.register_net_rep = nbl_res_register_net_rep,
	.unregister_net_rep = nbl_res_unregister_net_rep,
	.register_eth_rep = nbl_res_register_eth_rep,
	.unregister_eth_rep = nbl_res_unregister_eth_rep,
	.register_upcall_port = nbl_res_register_upcall_port,
	.unregister_upcall_port = nbl_res_unregister_upcall_port,
	.check_offload_status = nbl_res_check_offload_status,
	.set_offload_status = nbl_res_set_offload_status,
	.init_offload_fwd = nbl_res_init_offload_fwd,
	.init_cmdq = nbl_res_init_cmdq,
	.destroy_cmdq = nbl_res_destroy_cmdq,
	.reset_cmdq = nbl_res_reset_cmdq,
	.init_rep = nbl_res_init_rep,
	.init_flow = nbl_res_init_flow,
	.deinit_flow = nbl_res_deinit_flow,
	.offload_flow_rule = nbl_res_offload_flow_rule,
	.get_flow_acl_switch = nbl_res_get_flow_acl_switch,
	.cfg_tnl_offload_profile = nbl_res_cfg_tnl_offload_profile,
	.get_line_rate_info = nbl_res_get_line_rate_info,
	.get_chip_temperature = nbl_res_get_chip_temperature,
	.dump_func_info = nbl_res_dump_func_info,
	.get_board_info = nbl_res_get_board_info,
	.flr_clear_net = nbl_res_flr_clear_net,
	.flr_clear_rdma = nbl_res_flr_clear_rdma,
	.covert_vfid_to_vsi_id = nbl_res_covert_vfid_to_vsi_id,
	.check_vf_is_active = nbl_res_check_vf_is_active,
	.check_vf_is_vdpa = nbl_res_check_vf_is_vdpa,
	.get_vdpa_vf_stats = nbl_res_get_vdpa_vf_stats,
	.get_pkt_drop_stats = nbl_res_get_pkt_drop_stats,
	.get_total_pkt_drop_stats = nbl_res_get_total_pkt_drop_stats,

	.init_vdpaq = nbl_res_init_vdpaq,
	.destroy_vdpaq = nbl_res_destroy_vdpaq,
	.get_upcall_port = nbl_res_get_upcall_port,

	.get_reg_dump = nbl_res_get_reg_dump,
	.get_reg_dump_len = nbl_res_get_reg_dump_len,
	.process_abnormal_event = nbl_res_process_abnormal_event,
	.get_owned_pf_bitmap = nbl_res_get_owned_pf_bitmap,

	.cfg_lag_hash_algorithm = nbl_res_cfg_lag_hash_algorithm,
	.cfg_lag_member_fwd = nbl_res_cfg_lag_member_fwd,
	.cfg_lag_member_list = nbl_res_cfg_lag_member_list,
	.cfg_lag_member_up_attr = nbl_res_cfg_lag_member_up_attr,
	.cfg_bond_shaping = nbl_res_cfg_bond_shaping,
	.cfg_bgid_back_pressure = nbl_res_cfg_bgid_back_pressure,
	.get_lag_ports_max = nbl_res_get_lag_ports_max,
	.check_lag_nosupport = nbl_res_check_lag_nosupport,

	.cfg_eth_bond_info = nbl_res_cfg_eth_bond_info,
	.get_eth_bond_info = nbl_res_get_eth_bond_info,

	.switchdev_init_cmdq = nbl_res_switchdev_init_cmdq,
	.switchdev_deinit_cmdq = nbl_res_switchdev_deinit_cmdq,
	.set_tc_flow_info = nbl_res_set_tc_flow_info,
	.unset_tc_flow_info = nbl_res_unset_tc_flow_info,
	.get_tc_flow_info = nbl_res_get_tc_flow_info,

	.get_p4_info = nbl_res_get_p4_info,
	.get_p4_used = nbl_res_get_p4_used,
	.set_p4_used = nbl_res_set_p4_used,
	.get_vf_base_vsi_id = nbl_res_get_vf_base_vsi_id,
	.load_p4 = nbl_res_load_p4,
	.get_p4_version = nbl_res_get_p4_version,

	.get_board_id = nbl_res_get_board_id,
	.set_pmd_debug = nbl_res_set_pmd_debug,

	.get_xdp_queue_info = nbl_res_get_xdp_queue_info,
	.set_hw_status = nbl_res_set_hw_status,
	.check_hw_status = nbl_res_check_hw_status,
	.get_hw_status = nbl_res_get_hw_status,

	.configure_qos = nbl_res_configure_qos,
	.configure_rdma_bw = nbl_res_configure_rdma_bw,
	.set_pfc_buffer_size = nbl_res_set_pfc_buffer_size,
	.get_pfc_buffer_size = nbl_res_get_pfc_buffer_size,
	.set_rate_limit = nbl_res_set_rate_limit,

	.get_perf_dump_length = nbl_res_get_perf_dump_length,
	.get_perf_dump_data = nbl_res_get_perf_dump_data,

	.register_dev_name = nbl_res_register_dev_name,
	.get_dev_name = nbl_res_get_dev_name,

	.get_mirror_table_id = nbl_res_get_mirror_table_id,
	.configure_mirror = nbl_res_configure_mirror,
	.clear_mirror_cfg = nbl_res_clear_mirror_cfg,
	.set_rx_csum_drop = nbl_res_set_rx_csum_drop,
	.cfg_vlan_filtering = nbl_res_cfg_vlan_filtering,
};

void nbl_res_fill_ktls_init_payload_leonis(void *init_payload,
					   struct nbl_ktls_offload_context_tx *priv_tx)
{
	struct nbl_ktls_init_payload_leonis *init_payload_leonis = init_payload;

	init_payload_leonis->initial = 1;
	init_payload_leonis->sync = 0;
	init_payload_leonis->sid = priv_tx->index;
	memcpy(init_payload_leonis->iv, priv_tx->iv, NBL_KTLS_IV_LEN);
	memcpy(init_payload_leonis->rec_num, priv_tx->rec_num, NBL_KTLS_REC_LEN);
	/* Since the logic will add 1 to iv and rec_seq before using them,
	 * to ensure the consistency of software and hardware,
	 * the software will be delivered after subtracting 1
	 */
	nbl_ktls_bigint_decrement(init_payload_leonis->iv, NBL_KTLS_IV_LEN);
	nbl_ktls_bigint_decrement(init_payload_leonis->rec_num, NBL_KTLS_REC_LEN);
}

static struct nbl_res_product_ops product_ops = {
	.queue_mgt_init			= nbl_queue_mgt_init_leonis,
	.setup_qid_map_table		= nbl_res_queue_setup_qid_map_table_leonis,
	.remove_qid_map_table		= nbl_res_queue_remove_qid_map_table_leonis,
	.init_qid_map_table		= nbl_res_queue_init_qid_map_table,
	.get_rss_ret_base_and_size	= nbl_res_queue_get_rss_ret_base_and_size_leonis,
	.get_rxfh_indir			= nbl_res_queue_get_rxfh_indir_leonis,
	.get_hash_fields		= nbl_res_queue_get_hash_fields_leonis,
	.set_hash_fields		= nbl_res_queue_set_hash_fields_leonis,
	.intr_mgt_init			= nbl_intr_mgt_init_leonis,
	.txrx_mgt_init			= nbl_txrx_mgt_init_leonis,
	.parse_rx_extend_header		= nbl_res_parse_rx_extend_header_leonis,
	.features_check			= nbl_res_txrx_features_check_leonis,
	.config_key			= nbl_fd_config_key_leonis,
	.handle_queue_update		= nbl_fd_handle_queue_update_leonis,
#if IS_ENABLED(CONFIG_TLS_DEVICE)
	.fill_ktls_init_payload		= nbl_res_fill_ktls_init_payload_leonis,
	.ktls_send_resync_packet	= nbl_ktls_send_resync_packet_leonis,
#endif
	.adminq_mgt_init		= nbl_adminq_mgt_init_leonis,
	.tx_exthdr_offset		= nbl_res_leonis_txhdr_offset,
};

static bool is_ops_inited;
static int nbl_res_setup_res_mgt(struct nbl_common_info *common,
				 struct nbl_resource_mgt **res_mgt)
{
	struct device *dev;
	struct nbl_resource_info *resource_info;

	dev = NBL_COMMON_TO_DEV(common);
	*res_mgt = devm_kzalloc(dev, sizeof(struct nbl_resource_mgt), GFP_KERNEL);
	if (!*res_mgt)
		return -ENOMEM;
	NBL_RES_MGT_TO_COMMON(*res_mgt) = common;

	resource_info = devm_kzalloc(dev, sizeof(struct nbl_resource_info), GFP_KERNEL);
	if (!resource_info)
		return -ENOMEM;
	NBL_RES_MGT_TO_RES_INFO(*res_mgt) = resource_info;

	return 0;
}

static void nbl_res_remove_res_mgt(struct nbl_common_info *common,
				   struct nbl_resource_mgt **res_mgt)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	devm_kfree(dev, NBL_RES_MGT_TO_RES_INFO(*res_mgt));
	devm_kfree(dev, *res_mgt);
	*res_mgt = NULL;
}

static void nbl_res_remove_ops(struct device *dev, struct nbl_resource_ops_tbl **res_ops_tbl)
{
	devm_kfree(dev, *res_ops_tbl);
	*res_ops_tbl = NULL;
}

static int nbl_res_setup_ops(struct device *dev, struct nbl_resource_ops_tbl **res_ops_tbl,
			     struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;

	*res_ops_tbl = devm_kzalloc(dev, sizeof(struct nbl_resource_ops_tbl), GFP_KERNEL);
	if (!*res_ops_tbl)
		return -ENOMEM;

	if (!is_ops_inited) {
		ret = nbl_flow_setup_ops_leonis(&res_ops);
		if (ret)
			goto setup_fail;

		ret = nbl_tc_flow_setup_ops_leonis(&res_ops);
		if (ret)
			goto setup_fail;

		ret = nbl_queue_setup_ops(&res_ops);
		if (ret)
			goto setup_fail;

		ret = nbl_txrx_setup_ops(&res_ops);
		if (ret)
			goto setup_fail;

		ret = nbl_intr_setup_ops(&res_ops);
		if (ret)
			goto setup_fail;

		ret = nbl_vsi_setup_ops(&res_ops);
		if (ret)
			goto setup_fail;

		ret = nbl_adminq_setup_ops(&res_ops);
		if (ret)
			goto setup_fail;

		ret = nbl_accel_setup_ops(&res_ops, false);
		if (ret)
			goto setup_fail;

		ret = nbl_fd_setup_ops(&res_ops);
		if (ret)
			goto setup_fail;

		is_ops_inited = true;
	}

	NBL_RES_OPS_TBL_TO_OPS(*res_ops_tbl) = &res_ops;
	NBL_RES_OPS_TBL_TO_PRIV(*res_ops_tbl) = res_mgt;

	return 0;

setup_fail:
	nbl_res_remove_ops(dev, res_ops_tbl);
	return -EAGAIN;
}

static int nbl_res_dev_setup_eswitch_info(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_eswitch_info *eswitch_info;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	eswitch_info = devm_kzalloc(dev, sizeof(struct nbl_eswitch_info), GFP_KERNEL);
	if (!eswitch_info)
		return -ENOMEM;
	NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt) = eswitch_info;

	return 0;
}

static void nbl_res_pf_dev_remove_eswitch_info(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_eswitch_info **eswitch_info = &NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt);

	if (!(*eswitch_info))
		return;
	devm_kfree(dev, *eswitch_info);
	*eswitch_info = NULL;
}

static int nbl_res_ctrl_dev_setup_qinfo_tx(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_qinfo_cfg_table *qinfo;

	qinfo = devm_kcalloc(dev, NBL_MAX_FUNC, sizeof(struct nbl_qinfo_cfg_table), GFP_KERNEL);
	if (!qinfo)
		return -ENOMEM;
	NBL_RES_MGT_TO_QINFO_CFG(res_mgt) = qinfo;
	return 0;
}

static void nbl_res_ctrl_dev_remove_qinfo_tx(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_qinfo_cfg_table **qinfo = &NBL_RES_MGT_TO_QINFO_CFG(res_mgt);

	if (!(*qinfo))
		return;
	devm_kfree(dev, *qinfo);
	*qinfo = NULL;
}

static int nbl_res_ctrl_dev_setup_eth_info(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_eth_info *eth_info;
	struct nbl_eth_bond_info *eth_bond_info;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u32 eth_num = 0;
	u32 eth_bitmap, eth_id;
	int i;

	eth_info = devm_kzalloc(dev, sizeof(struct nbl_eth_info), GFP_KERNEL);
	if (!eth_info)
		return -ENOMEM;

	NBL_RES_MGT_TO_ETH_INFO(res_mgt) = eth_info;

	eth_bond_info = devm_kzalloc(dev, sizeof(struct nbl_eth_bond_info), GFP_KERNEL);
	if (!eth_bond_info)
		return -ENOMEM;

	NBL_RES_MGT_TO_ETH_BOND_INFO(res_mgt) = eth_bond_info;

	eth_info->eth_num = (u8)phy_ops->get_fw_eth_num(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	eth_bitmap = phy_ops->get_fw_eth_map(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	/* for 2 eth port board, the eth_id is 0, 2 */
	for (i = 0; i < NBL_MAX_ETHERNET; i++) {
		if ((1 << i) & eth_bitmap) {
			set_bit(i, eth_info->eth_bitmap);
			eth_info->eth_id[eth_num] = i;
			eth_info->logic_eth_id[i] = eth_num;
			eth_num++;
		}
	}
	mutex_init(&eth_info->eth_lock);
	for (i = 0; i < NBL_RES_MGT_TO_PF_NUM(res_mgt); i++) {
		/* if pf_id <= eth_num, the pf relate corresponding eth_id*/
		if (i < eth_num) {
			eth_id = eth_info->eth_id[i];
			eth_info->pf_bitmap[eth_id] |= BIT(i);
		}
		/* if pf_id > eth_num, the pf relate eth 0*/
		else
			eth_info->pf_bitmap[0] |= BIT(i);
	}

	return 0;
}

static void nbl_res_ctrl_dev_remove_eth_info(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_eth_info **eth_info = &NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_eth_bond_info **eth_bond_info = &NBL_RES_MGT_TO_ETH_BOND_INFO(res_mgt);

	if (*eth_bond_info) {
		devm_kfree(dev, *eth_bond_info);
		*eth_bond_info = NULL;
	}

	if (*eth_info) {
		devm_kfree(dev, *eth_info);
		*eth_info = NULL;
	}
}

static int nbl_res_ctrl_dev_sriov_info_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct device *dev =  NBL_COMMON_TO_DEV(common);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_sriov_info *sriov_info;
	u32 vf_fid, vf_startid, vf_endid = NBL_MAX_VF;
	u16 func_id;
	u16 function;

	sriov_info = devm_kcalloc(dev, NBL_RES_MGT_TO_PF_NUM(res_mgt),
				  sizeof(struct nbl_sriov_info), GFP_KERNEL);
	if (!sriov_info)
		return -ENOMEM;

	NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) = sriov_info;

	for (func_id = 0; func_id < NBL_RES_MGT_TO_PF_NUM(res_mgt); func_id++) {
		sriov_info = &NBL_RES_MGT_TO_SRIOV_INFO(res_mgt)[func_id];
		function = NBL_COMMON_TO_PCI_FUNC_ID(common) + func_id;

		common->hw_bus = (u8)phy_ops->get_real_bus(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
		sriov_info->bdf = PCI_DEVID(common->hw_bus,
					    PCI_DEVFN(common->devid, function));
		vf_fid = phy_ops->get_host_pf_fid(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), func_id);
		vf_startid = vf_fid & 0xFFFF;
		vf_endid = (vf_fid >> 16) & 0xFFFF;
		sriov_info->start_vf_func_id = vf_startid + NBL_MAX_PF_LEONIS;
		sriov_info->num_vfs = vf_endid - vf_startid;
		if (res_info->max_vf_bypf_num == 0)
			res_info->max_vf_bypf_num = sriov_info->num_vfs;
	}

	res_info->max_vf_num = vf_endid;

	return 0;
}

static void nbl_res_ctrl_dev_sriov_info_remove(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_sriov_info **sriov_info = &NBL_RES_MGT_TO_SRIOV_INFO(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);

	if (!(*sriov_info))
		return;

	devm_kfree(dev, *sriov_info);
	*sriov_info = NULL;
}

static void nbl_res_ctrl_dev_vdpa_vf_stats_remove(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_vdpa_status **vf_status = NBL_RES_MGT_TO_VDPA_VF_STATS(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	int i = 0;

	for (i = 0; i < NBL_MAX_FUNC; i++) {
		if (vf_status[i]) {
			devm_kfree(dev, vf_status[i]);
			vf_status[i] = NULL;
		}
	}
}

static int nbl_res_ctrl_dev_vsi_info_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct device *dev =  NBL_COMMON_TO_DEV(common);
	struct nbl_vsi_info *vsi_info;
	struct nbl_sriov_info *sriov_info;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	int i;

	vsi_info = devm_kcalloc(dev, NBL_RES_MGT_TO_PF_NUM(res_mgt),
				sizeof(struct nbl_vsi_info), GFP_KERNEL);
	if (!vsi_info)
		return -ENOMEM;

	NBL_RES_MGT_TO_VSI_INFO(res_mgt) = vsi_info;
	/**
	 * case 1 two port(2pf)
	 * pf0,pf1(NBL_VSI_SERV_PF_DATA_TYPE) vsi is 0,512
	 * pf0,pf1(NBL_VSI_SERV_PF_CTLR_TYPE) vsi is 1,513
	 * pf0,pf1(NBL_VSI_SERV_PF_USER_TYPE) vsi is 2,514
	 * pf0,pf1(NBL_VSI_SERV_PF_XDP_TYPE) vsi is 3,515
	 * pf0.vf0-pf0.vf255(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 4-259
	 * pf1.vf0-pf1.vf255(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 516-771
	 * pf2-pf7(NBL_VSI_SERV_PF_EXTRA_TYPE) vsi 260-265(if exist)
	 * case 2 four port(4pf)
	 * pf0,pf1,pf2,pf3(NBL_VSI_SERV_PF_DATA_TYPE) vsi is 0,256,512,768
	 * pf0,pf1,pf2,pf3(NBL_VSI_SERV_PF_CTLR_TYPE) vsi is 1,257,513,769
	 * pf0,pf1,pf2,pf3(NBL_VSI_SERV_PF_USER_TYPE) vsi is 2,258,514,770
	 * pf0,pf1,pf2,pf3(NBL_VSI_SERV_PF_XDP_TYPE) vsi is 3,259,515,771
	 * pf0.vf0-pf0.vf127(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 4-131
	 * pf1.vf0-pf1.vf127(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 260-387
	 * pf2.vf0-pf2.vf127(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 516-643
	 * pf3.vf0-pf3.vf127(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 772-899
	 * pf4-pf7(NBL_VSI_SERV_PF_EXTRA_TYPE) vsi 132-135(if exist)
	 */

	vsi_info->num = eth_info->eth_num;
	for (i = 0; i < vsi_info->num; i++) {
		vsi_info->serv_info[i][NBL_VSI_SERV_PF_DATA_TYPE].base_id = i
			* NBL_VSI_ID_GAP(vsi_info->num);
		vsi_info->serv_info[i][NBL_VSI_SERV_PF_DATA_TYPE].num = 1;
		vsi_info->serv_info[i][NBL_VSI_SERV_PF_CTLR_TYPE].base_id =
		    vsi_info->serv_info[i][NBL_VSI_SERV_PF_DATA_TYPE].base_id
		    + vsi_info->serv_info[i][NBL_VSI_SERV_PF_DATA_TYPE].num;
		vsi_info->serv_info[i][NBL_VSI_SERV_PF_CTLR_TYPE].num = 1;
		vsi_info->serv_info[i][NBL_VSI_SERV_PF_USER_TYPE].base_id =
		    vsi_info->serv_info[i][NBL_VSI_SERV_PF_CTLR_TYPE].base_id
		    + vsi_info->serv_info[i][NBL_VSI_SERV_PF_CTLR_TYPE].num;
		vsi_info->serv_info[i][NBL_VSI_SERV_PF_USER_TYPE].num = 1;
		vsi_info->serv_info[i][NBL_VSI_SERV_PF_XDP_TYPE].base_id =
		    vsi_info->serv_info[i][NBL_VSI_SERV_PF_USER_TYPE].base_id
		    + vsi_info->serv_info[i][NBL_VSI_SERV_PF_USER_TYPE].num;
		vsi_info->serv_info[i][NBL_VSI_SERV_PF_XDP_TYPE].num = 1;
		vsi_info->serv_info[i][NBL_VSI_SERV_VF_DATA_TYPE].base_id =
		    vsi_info->serv_info[i][NBL_VSI_SERV_PF_XDP_TYPE].base_id
		    + vsi_info->serv_info[i][NBL_VSI_SERV_PF_XDP_TYPE].num;
		sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + i;
		vsi_info->serv_info[i][NBL_VSI_SERV_VF_DATA_TYPE].num = sriov_info->num_vfs;
	}

	/* pf_id >= eth_num, it belong pf0's switch */
	vsi_info->serv_info[0][NBL_VSI_SERV_PF_EXTRA_TYPE].base_id =
	    vsi_info->serv_info[0][NBL_VSI_SERV_VF_DATA_TYPE].base_id
	    + vsi_info->serv_info[0][NBL_VSI_SERV_VF_DATA_TYPE].num;
	vsi_info->serv_info[0][NBL_VSI_SERV_PF_EXTRA_TYPE].num =
		NBL_RES_MGT_TO_PF_NUM(res_mgt) - vsi_info->num;

	return 0;
}

static void nbl_res_ctrl_dev_remove_vsi_info(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_vsi_info **vsi_info = &NBL_RES_MGT_TO_VSI_INFO(res_mgt);

	if (!(*vsi_info))
		return;

	devm_kfree(dev, *vsi_info);
	*vsi_info = NULL;
}

static int nbl_res_ring_num_info_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_net_ring_num_info *num_info = &resource_info->net_ring_num_info;

	num_info->pf_def_max_net_qp_num = NBL_DEFAULT_PF_HW_QUEUE_NUM;
	num_info->vf_def_max_net_qp_num = NBL_DEFAULT_VF_HW_QUEUE_NUM;

	return 0;
}

static int nbl_res_ctrl_dev_drop_stats_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct device *dev =  NBL_COMMON_TO_DEV(common);
	struct nbl_chan_param_drop_stats_resp *drop_stats;

	drop_stats = devm_kcalloc(dev, NBL_MAX_ETHERNET,
				  sizeof(*drop_stats), GFP_KERNEL);
	if (!drop_stats)
		return -ENOMEM;

	NBL_RES_MGT_TO_DROP_STATS(res_mgt) = drop_stats;

	return 0;
}

static void nbl_res_ctrl_dev_drop_stats_remove(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_chan_param_drop_stats_resp **drop_stats = &NBL_RES_MGT_TO_DROP_STATS(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);

	if (!(*drop_stats))
		return;

	devm_kfree(dev, *drop_stats);
	*drop_stats = NULL;
}

static int nbl_res_init_pf_num(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u32 pf_mask;
	u32 pf_num = 0;
	int i;

	pf_mask = phy_ops->get_host_pf_mask(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), 0);
	for (i = 0; i < NBL_MAX_PF_LEONIS; i++) {
		if (!(pf_mask & (1 << i)))
			pf_num++;
		else
			break;
	}

	NBL_RES_MGT_TO_PF_NUM(res_mgt) = pf_num;

	if (!pf_num)
		return -1;

	/* leonis only pf0 has ctrl cap, so it own all the pf */
	for (i = 0; i < pf_num; i++)
		set_bit(i, resource_info->owned_pf_bitmap);

	return 0;
}

static void nbl_res_init_board_info(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->get_board_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				&res_mgt->resource_info->board_info);
}

static void nbl_rdma_mgt_start(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_rdma_info *rdma_info = &resource_info->rdma_info;

	rdma_info->pf_msix_num = NBL_RES_RDMA_INTR_NUM;
	rdma_info->vf_msix_num = NBL_RES_RDMA_INTR_NUM;
	rdma_info->rdma_max_func_num = NBL_RES_RDMA_MAX;
}

static void nbl_res_stop(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	nbl_res_set_rx_csum_drop(res_mgt, false);
	nbl_fd_mgt_stop(res_mgt);
	nbl_queue_mgt_stop(res_mgt);
	nbl_txrx_mgt_stop(res_mgt);
	nbl_intr_mgt_stop(res_mgt);
	nbl_adminq_mgt_stop(res_mgt);
	nbl_vsi_mgt_stop(res_mgt);
	nbl_accel_mgt_stop(res_mgt);
	nbl_flow_mgt_stop_leonis(res_mgt);
	nbl_res_ctrl_dev_drop_stats_remove(res_mgt);
	nbl_res_ctrl_dev_vdpa_vf_stats_remove(res_mgt);
	nbl_res_ctrl_dev_remove_vsi_info(res_mgt);
	nbl_res_ctrl_dev_remove_eth_info(res_mgt);
	nbl_res_ctrl_dev_remove_qinfo_tx(res_mgt);
	nbl_res_ctrl_dev_sriov_info_remove(res_mgt);
	nbl_res_pf_dev_remove_eswitch_info(res_mgt);

	/*only pf0 need tc_flow_mgt_stop*/
	if (!common->is_vf && !NBL_COMMON_TO_PCI_FUNC_ID(common)) {
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow stop tc flow mgt");
		nbl_tc_flow_mgt_stop_leonis(res_mgt);
	}
}

static int nbl_res_start(struct nbl_resource_mgt *res_mgt,
			 struct nbl_func_caps caps)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	int ret = 0;

	if (caps.has_ctrl) {
		ret = nbl_res_check_fw_working(res_mgt);
		if (ret) {
			nbl_err(common, NBL_DEBUG_RESOURCE, "fw is not working");
			return ret;
		}

		nbl_res_init_board_info(res_mgt);

		ret = nbl_res_init_pf_num(res_mgt);
		if (ret) {
			nbl_err(common, NBL_DEBUG_RESOURCE, "pf number is illegal");
			return ret;
		}

		ret = nbl_res_ctrl_dev_sriov_info_init(res_mgt);
		if (ret) {
			nbl_err(common, NBL_DEBUG_RESOURCE, "Failed to init sr_iov info");
			return ret;
		}

		ret = nbl_res_ctrl_dev_setup_eth_info(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_res_ctrl_dev_setup_qinfo_tx(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_res_ctrl_dev_vsi_info_init(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_res_ring_num_info_init(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_res_ctrl_dev_drop_stats_init(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_flow_mgt_start_leonis(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_tc_flow_mgt_start_leonis(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_queue_mgt_start(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_vsi_mgt_start(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_intr_mgt_start(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_accel_mgt_start(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_fd_mgt_start(res_mgt);
		if (ret)
			goto start_fail;

		nbl_rdma_mgt_start(res_mgt);

		nbl_res_set_flex_capability(res_mgt, NBL_DUMP_FLOW_CAP);
		nbl_res_set_flex_capability(res_mgt, NBL_DUMP_FD_CAP);
		nbl_res_set_flex_capability(res_mgt, NBL_DUMP_FUNC_INFO_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_OFFLOAD_NETWORK_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_FW_HB_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_FW_RESET_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_CLEAN_ADMINDQ_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_ADAPT_DESC_GOTHER);
		nbl_res_set_fix_capability(res_mgt, NBL_PROCESS_FLR_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_RESET_CTRL_CAP);
		/* leonis af need a pmd_debug for dpdk gdb debug */
		nbl_res_set_fix_capability(res_mgt, NBL_PMD_DEBUG);
		nbl_res_set_fix_capability(res_mgt, NBL_HIGH_THROUGHPUT_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_HEALTH_REPORT_TEMP_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_HEALTH_REPORT_REBOOT_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_DVN_DESC_REQ_SYSFS_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_ABNORMAL_INTR_SYSFS_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_NEED_DESTROY_CHIP);
		nbl_res_set_fix_capability(res_mgt, NBL_RX_CSUM_ERR_DROP_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_VLAN_FILTERING_DISABLE_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_RXFH_KEY_SET_CAP);
		nbl_res_set_flex_capability(res_mgt, NBL_SECURITY_TLS_CAP);
		nbl_res_set_flex_capability(res_mgt, NBL_SECURITY_IPSEC_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_IPSEC_AGE_CAP);
	}

	ret = nbl_adminq_mgt_start(res_mgt, FIRMWARE_MAGIC_LEONIS, caps.has_ctrl);
	if (ret)
		goto start_fail;

	if (caps.has_net) {
		ret = nbl_txrx_mgt_start(res_mgt);
		if (ret)
			goto start_fail;

		if (!caps.is_vf) {
			ret = nbl_res_dev_setup_eswitch_info(res_mgt);
			if (ret)
				goto start_fail;
		}
	}

	if (!caps.is_vf) {
		nbl_res_set_fix_capability(res_mgt, NBL_LINK_DOWN_ON_CLOSE);
		nbl_res_set_fix_capability(res_mgt, NBL_P4_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_RESTOOL_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TX_FC_SEGREGATGE_ENABLE);
		nbl_res_set_fix_capability(res_mgt, NBL_XDP_ENHANCE);
		nbl_res_set_fix_capability(res_mgt, NBL_HWMON_TEMP_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_QOS_SYSFS_CAP);
	}

	nbl_res_set_fix_capability(res_mgt, NBL_TASK_CLEAN_MAILBOX_CAP);
	nbl_res_set_fix_capability(res_mgt, NBL_ITR_DYNAMIC);
	nbl_res_set_fix_capability(res_mgt, NBL_MSIX_AUTO_MASK_CAP);
	nbl_res_set_fix_capability(res_mgt, NBL_TASK_RESET_CAP);
	nbl_res_set_fix_capability(res_mgt, NBL_MIRROR_SYSFS_CAP);
	nbl_res_set_fix_capability(res_mgt, NBL_INTERLEAVE_SEG_DISABLE);
	nbl_res_set_fix_capability(res_mgt, NBL_RXQ_LARGE_BUF);
	nbl_res_set_fix_capability(res_mgt, NBL_RESUME_CAP);
	nbl_res_set_fix_capability(res_mgt, NBL_XDP_CAP);

	return 0;

start_fail:
	nbl_res_stop(res_mgt);
	return ret;
}

int nbl_res_init_leonis(void *p, struct nbl_init_param *param)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_resource_mgt **res_mgt;
	struct nbl_resource_ops_tbl **res_ops_tbl;
	struct nbl_phy_ops_tbl *phy_ops_tbl;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	int ret = 0;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	res_mgt = (struct nbl_resource_mgt **)&NBL_ADAPTER_TO_RES_MGT(adapter);
	res_ops_tbl = &NBL_ADAPTER_TO_RES_OPS_TBL(adapter);
	phy_ops_tbl = NBL_ADAPTER_TO_PHY_OPS_TBL(adapter);
	chan_ops_tbl = NBL_ADAPTER_TO_CHAN_OPS_TBL(adapter);

	ret = nbl_res_setup_res_mgt(common, res_mgt);
	if (ret)
		goto setup_mgt_fail;

	nbl_res_setup_common_ops(*res_mgt);
	NBL_RES_MGT_TO_CHAN_OPS_TBL(*res_mgt) = chan_ops_tbl;
	NBL_RES_MGT_TO_PHY_OPS_TBL(*res_mgt) = phy_ops_tbl;

	NBL_RES_MGT_TO_PROD_OPS(*res_mgt) = &product_ops;

	ret = nbl_res_start(*res_mgt, param->caps);
	if (ret)
		goto start_fail;

	ret = nbl_res_setup_ops(dev, res_ops_tbl, *res_mgt);
	if (ret)
		goto setup_ops_fail;

	return 0;

setup_ops_fail:
	nbl_res_stop(*res_mgt);
start_fail:
	nbl_res_remove_res_mgt(common, res_mgt);
setup_mgt_fail:
	return ret;
}

void nbl_res_remove_leonis(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_resource_mgt **res_mgt;
	struct nbl_resource_ops_tbl **res_ops_tbl;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	res_mgt = (struct nbl_resource_mgt **)&NBL_ADAPTER_TO_RES_MGT(adapter);
	res_ops_tbl = &NBL_ADAPTER_TO_RES_OPS_TBL(adapter);

	nbl_res_remove_ops(dev, res_ops_tbl);
	nbl_res_stop(*res_mgt);
	nbl_res_remove_res_mgt(common, res_mgt);
}
