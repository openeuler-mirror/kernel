// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include <linux/bitfield.h>
#include "nbl_resource_draco.h"
#include "nbl_flow_draco.h"
#include "nbl_txrx.h"
#include "nbl_fd.h"
#include "nbl_tc_flow_draco.h"

extern int vf_queue_num;

static u16 nbl_res_draco_txhdr_offset[NBL_TX_MAX] = {
	[NBL_FWD] = FIELD_LOC(2, NBL_TX_DRACO_FWD_OFFSET, 1),
	[NBL_DPORT] = FIELD_LOC(2, NBL_TX_DRACO_DPORT_OFFSET, 1),
	[NBL_DPORT_ID] = FIELD_LOC(2, NBL_TX_DRACO_DPORT_ID_OFFSET, 1),
	[NBL_MSS] = FIELD_LOC(0, 0, 0),
	[NBL_CSUM] = FIELD_LOC(2, NBL_TX_DRACO_CSUM_OFFSET, 1),
	[NBL_TLS_IDX] = FIELD_LOC(1, NBL_TX_DRACO_TLS_OFFSET, 1),
	[NBL_TLS_FLAG] = FIELD_LOC(1, NBL_TX_DRACO_TLS_FLAG_OFFSET, 1),
};

static int nbl_res_get_queue_num(void *priv, u16 func_id, u16 *tx_queue_num, u16 *rx_queue_num);

static void nbl_res_setup_common_ops(struct nbl_resource_mgt *res_mgt)
{
	res_mgt->common_ops.get_queue_num = nbl_res_get_queue_num;
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
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_sriov_info *sriov_info;
	u64 pf_bar_start;
	u16 pf_bdf;
	u64 vf_bar_start;
	u64 vf_bar_size;
	u16 total_vfs;
	u16 offset;
	u16 stride;
	int diff;

	diff = nbl_common_pf_id_subtraction_mgtpf_id(common, param->sfid);
	sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + diff;

	pf_bar_start = param->pf_bar_start;
	if (pf_bar_start) {
		sriov_info->pf_bar_start = pf_bar_start;
		dev_info(dev, "pf %d, pf_bar_start:%llx\n", param->sfid, sriov_info->pf_bar_start);
	}

	pf_bdf = param->pf_bdf;
	vf_bar_start = param->vf_bar_start;
	vf_bar_size = param->vf_bar_size;
	total_vfs = param->total_vfs;
	offset = param->offset;
	stride = param->stride;

	if (total_vfs) {
		sriov_info->offset = offset;
		sriov_info->stride = stride;
		sriov_info->vf_bar_start = vf_bar_start;
		sriov_info->vf_bar_len = div64_u64(vf_bar_size, total_vfs);

		dev_info(dev, "pf %d, real bdf %u, bdf:%x:%x.%x, num_vfs:%d, start_vf_func_id:%d, offset:%d, stride:%d",
			 sriov_info->bdf, param->sfid,
			 PCI_BUS_NUM(pf_bdf), PCI_SLOT(pf_bdf & 0xff), PCI_FUNC(pf_bdf & 0xff),
			 sriov_info->num_vfs, sriov_info->start_vf_func_id, offset, stride);
	}

	return 0;
}

static int nbl_res_get_owned_pf_bitmap(void *priv,
				       unsigned long **owned_pf_bitmap, u8 *max_pf, u16 *bdf)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_sriov_info *sriov_info;

	sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt);

	*owned_pf_bitmap = resource_info->owned_pf_bitmap;
	*max_pf = NBL_MAX_PF_DRACO;
	*bdf = sriov_info->bdf;

	return 0;
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
	output->eth_id = eth_info->eth_id[pf_id];
	output->logic_eth_id = pf_id;

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
	netdev_features_t dflt_features = 0;
	netdev_features_t csumo_features = 0;
	netdev_features_t tso_features = 0;
	netdev_features_t vlano_features = 0;
	u16 tx_queue_num, rx_queue_num;
	u8 mac[ETH_ALEN] = {0};
	u16 vsi_id;
	int ret = 0;

	dflt_features = NBL_FEATURE(NETIF_F_RXHASH);
	if (param->sfid < NBL_RES_MGT_TO_PF_NUM(res_mgt))
		dflt_features |= NBL_FEATURE(NETIF_F_NTUPLE);
	csumo_features = NBL_FEATURE(NETIF_F_RXCSUM) |
			 NBL_FEATURE(NETIF_F_IP_CSUM) |
			 NBL_FEATURE(NETIF_F_IPV6_CSUM);

	tso_features = NBL_FEATURE(NETIF_F_TSO) |
		       NBL_FEATURE(NETIF_F_TSO6) |
		       NBL_FEATURE(NETIF_F_GSO_UDP_L4) |
		       NBL_FEATURE(NETIF_F_GSO_UDP_TUNNEL) |
		       NBL_FEATURE(NETIF_F_GSO_UDP_TUNNEL_CSUM) |
		       NBL_FEATURE(NETIF_F_GSO_GRE) |
		       NBL_FEATURE(NETIF_F_GSO_GRE_CSUM) |
		       NBL_FEATURE(NETIF_F_GSO_IPXIP4) |
		       NBL_FEATURE(NETIF_F_GSO_IPXIP6) |
		       NBL_FEATURE(NETIF_F_GSO_PARTIAL);
	if (param->sfid < NBL_MAX_PF)
		vlano_features = NBL_FEATURE(NETIF_F_HW_VLAN_CTAG_TX) |
				 NBL_FEATURE(NETIF_F_HW_VLAN_CTAG_RX) |
				 NBL_FEATURE(NETIF_F_HW_VLAN_STAG_TX) |
				 NBL_FEATURE(NETIF_F_HW_VLAN_STAG_RX);

	register_result->hw_features |= dflt_features |
					csumo_features |
					tso_features |
					vlano_features |
					NBL_FEATURE(NETIF_F_SG) |
					NBL_FEATURE(NETIF_F_HW_TC);
	register_result->features |= register_result->hw_features |
				     NBL_FEATURE(NETIF_F_HW_TC) |
				     NBL_FEATURE(NETIF_F_HW_VLAN_CTAG_FILTER) |
				     NBL_FEATURE(NETIF_F_HW_VLAN_STAG_FILTER);
	register_result->vlan_features = register_result->features;
	register_result->hw_enc_features = dflt_features |
					   csumo_features |
					   tso_features |
					   vlano_features;

	register_result->max_mtu = NBL_MAX_JUMBO_FRAME_SIZE - NBL_PKT_HDR_PAD;
	register_result->vlan_proto = vsi_info->mac_info[param->sfid].vlan_proto;
	register_result->vlan_tci = vsi_info->mac_info[param->sfid].vlan_tci;
	register_result->rate = vsi_info->mac_info[param->sfid].rate;
	if (param->sfid < NBL_MAX_PF) {
		nbl_res_get_eth_mac(res_mgt, mac, nbl_res_pf_id_to_eth_id(res_mgt, param->sfid));
		register_result->trusted = 1;
	} else {
		ether_addr_copy(mac, vsi_info->mac_info[param->sfid].mac);
		register_result->trusted = vsi_info->mac_info[param->sfid].trusted;
	}
	ether_addr_copy(register_result->mac, mac);

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

static int nbl_res_get_rep_queue_info(void *priv, struct nbl_ch_prm_get_queue_info *output)
{
	output->queue_size = NBL_DEFAULT_DESC_NUM;
	output->queue_num = NBL_DEFAULT_DRACO_REP_HW_QUEUE_NUM;
	return 0;
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

static u16 nbl_res_get_vf_base_vsi_id(void *priv, u16 pf_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return nbl_res_pfvfid_to_vsi_id(res_mgt, pf_id, 0, NBL_VSI_DATA);
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
	struct nbl_phy_ops_tbl *phy_ops_tbl = NBL_RES_MGT_TO_PHY_OPS_TBL(res_mgt);
	struct nbl_phy_ops *phy_ops;

	if (!tc_flow_mgt) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow mgt is NULL.\n");
		return -EINVAL;
	}

	if (!phy_ops_tbl) {
		nbl_err(common, NBL_DEBUG_FLOW, "phy ops tbl is NULL.\n");
		return -EINVAL;
	}

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	if (!phy_ops) {
		nbl_err(common, NBL_DEBUG_FLOW, "phy ops is NULL.\n");
		return -EINVAL;
	}

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
	struct nbl_phy_ops_tbl *phy_ops_tbl = NBL_RES_MGT_TO_PHY_OPS_TBL(res_mgt);
	struct nbl_phy_ops *phy_ops;

	if (common->tc_inst_id >= NBL_TC_FLOW_INST_COUNT) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow unset inst_id=%d is invalid.\n",
			common->tc_inst_id);
		return -EINVAL;
	}

	if (!tc_flow_mgt || !tc_flow_mgt->pf_set_tc_count) {
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow mgt is NULL or pf_set_tc_count is zero.\n");
		return 0;
	}

	if (!phy_ops_tbl) {
		nbl_err(common, NBL_DEBUG_FLOW, "phy ops tbl is NULL.\n");
		return -EINVAL;
	}

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	if (!phy_ops) {
		nbl_err(common, NBL_DEBUG_FLOW, "phy ops is NULL.\n");
		return -EINVAL;
	}

	tc_flow_mgt->pf_set_tc_count--;
	nbl_info(common, NBL_DEBUG_FLOW, "tc flow set pf_set_tc_count--=%d\n",
		 tc_flow_mgt->pf_set_tc_count);

	if (!tc_flow_mgt->pf_set_tc_count) {
		if (nbl_tc_flow_flush_flow_draco(res_mgt))
			return -EINVAL;
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow unset kgen cvlan, set ped vsi type zero\n");
		phy_ops->unset_tc_kgen_cvlan(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));

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

	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow get inst_id=%d success.\n", common->tc_inst_id);

	return 0;
}

static void nbl_res_init_offload_fwd(void *priv, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->init_offload_fwd(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), func_id);
}

static void nbl_res_init_rep(void *priv, u16 vsi_id, u8 inner_type,
			     u8 outer_type, u8 rep_type)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);

	phy_ops->init_rep(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id,
			  inner_type, outer_type, rep_type, queue_mgt->rss_key_range_oft);
}

static void nbl_res_init_flow(void *priv, void *para)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->init_flow(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), para);
}

static void nbl_res_deinit_flow(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);

	phy_ops->clear_em(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), pf_id);
}

static void nbl_res_set_slave_swd_id(void *priv, u16 swd_id, u16 pf_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);
	int i;

	for (i = NBL_VSI_SERV_PF_USER_TYPE; i < NBL_VSI_SERV_PF_EXTRA_TYPE; i++)
		phy_ops->set_slave_swd_id(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					    vsi_info->serv_info[0][i].base_id,
					    vsi_info->serv_info[0][i].num, swd_id, pf_id);
}

static int nbl_res_check_offload_status(void *priv, bool *is_down)
{
	/* todo: draco */
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

static int nbl_res_process_abnormal_event(void *priv,
					  struct nbl_abnormal_event_info *abnomal_info)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->process_abnormal_event(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), abnomal_info);
}

static void nbl_res_get_board_info(void *priv, struct nbl_board_port_info *board_info)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	memcpy(board_info, &res_mgt->resource_info->board_info, sizeof(*board_info));
}

static int nbl_res_init_vdpaq(void *priv, u16 func_id, u64 pa, u32 size)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u8 bus, dev, func;
	u16 bdf;
	int pfid, vfid;

	nbl_res_func_id_to_bdf(res_mgt, func_id, &bus, &dev, &func);
	bdf = PCI_DEVID(bus, PCI_DEVFN(dev, func));

	nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pfid, &vfid);

	return phy_ops->init_vdpaq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vfid, bdf, pa, size);
}

static void nbl_res_destroy_vdpaq(void *priv, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int pfid, vfid;

	nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pfid, &vfid);

	phy_ops->destroy_vdpaq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vfid);
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

static inline void nbl_rx_csum_draco(struct nbl_res_rx_ring *rx_ring, struct sk_buff *skb,
				     u8 ptype, u8 cksum)
{
	skb->ip_summed = CHECKSUM_NONE;

	/* if user disable RX Checksum Offload, then stack verify the rx checksum */
	if (!(rx_ring->netdev->features & NETIF_F_RXCSUM) || !(cksum & NBL_CHECKSUM_CHECKED))
		return;

	/* only check L4 checksum error */
	if (cksum & NBL_CHECKSUM_REPORT_L4_CHECKSUM) {
		rx_ring->rx_stats.rx_csum_errors++;
		return;
	}

	if (((ptype & NBL_RX_PTYPE_L4_MASK) == NBL_RX_PTYPE_VALID_L4) ||
	    ((ptype & NBL_RX_PTYPE_UDP_TUNNEL_MASK) == NBL_RX_PTYPE_UDP_TUNNEL)) {
		/* non-tunnel packet TCP/UDP,
		 * or nvgre tunnel packet with inner TCP/UDP
		 * or gre tunnel packet (no gre checksum) with inner TCP/UDP
		 * or ipip tunnel packet with inner TCP/UDP
		 */
		skb->ip_summed = CHECKSUM_UNNECESSARY;

		/* udp tunnel packet with inner TCP/UDP */
		if ((ptype & NBL_RX_PTYPE_UDP_TUNNEL_L4_MASK) == NBL_RX_PTYPE_UDP_TUNNEL_VALID_L4) {
			skb->csum_level = 1;
			skb->encapsulation = 1;
		}

		if ((ptype & NBL_RX_PTYPE_TUNNEL_L4_MASK) == NBL_RX_PTYPE_TUNNEL_VALID_L4)
			rx_ring->rx_stats.rx_csum_inner_packets++;
		else
			rx_ring->rx_stats.rx_csum_packets++;
	}
}

static inline int nbl_rx_vlan_parse_draco(struct nbl_res_rx_ring *rx_ring, struct sk_buff *skb,
					  u16 vlan_hdr)
{
	u16 vlan_proto;
	u16 vid = vlan_hdr & 0xFFF;

	if (!vid)
		return !!rx_ring->vlan_proto;

	/* vlan pop enable */
	if (vlan_hdr & 0x1000)
		vlan_proto = htons(ETH_P_8021AD);
	else
		vlan_proto = htons(ETH_P_8021Q);

	if (!rx_ring->vlan_proto) {
		rx_ring->rx_stats.rx_removed_vlan_packets += 1;
		__vlan_hwaccel_put_tag(skb, vlan_proto, vlan_hdr & 0xEFFF);
		return 0;
	}

	if (rx_ring->vlan_proto != ntohs(vlan_proto) ||
	    rx_ring->vlan_tci != vid)
		return 1;

	return 0;
}

#if IS_ENABLED(CONFIG_TLS_DEVICE)
static inline int nbl_ktls_rx_handle_skb_draco(struct nbl_res_rx_ring *rx_ring,
					       struct sk_buff *skb,
					       struct nbl_rx_extend_head_draco *rx_hdr_param)
{
	if (rx_hdr_param->l4s_dec_ind) {
		if (rx_hdr_param->l4s_check_ind) {
			skb->decrypted = 1;
			rx_ring->rx_stats.tls_decrypted_packets++;
			dev_dbg(NBL_RING_TO_DEV(rx_ring), "ingress ktls %u decrypted\n",
				rx_hdr_param->l4s_sid);
		} else {
			dev_err(NBL_RING_TO_DEV(rx_ring), "ingress ktls %u auth fail\n",
				rx_hdr_param->l4s_sid);
		}
	} else if (rx_hdr_param->l4s_resync_ind) {
		rx_ring->rx_stats.tls_resync_req_num++;
		nbl_resync_update_sn(rx_ring->netdev, skb, rx_hdr_param->l4s_tcp_offset);
		dev_info(NBL_RING_TO_DEV(rx_ring), "ingress ktls %u resync sn\n",
			 rx_hdr_param->l4s_sid);
	} else {
		dev_dbg(NBL_RING_TO_DEV(rx_ring), "ingress ktls %u bypass\n",
			rx_hdr_param->l4s_sid);
	}

	return 0;
}
#endif

#define NBL_RX_HDR_SPORT GENMASK_ULL(19, 11)
#define NBL_RX_HDR_PTYPE GENMASK_ULL(27, 20)
#define NBL_RX_HDR_CKSUM GENMASK_ULL(32, 28)
#define NBL_RX_HDR_VLAN GENMASK_ULL(23, 8)
#define NBL_RX_HDR_RSS GENMASK_ULL(63, 32)
#if IS_ENABLED(CONFIG_TLS_DEVICE)
#define NBL_RX_HDR_TLS_VLD GENMASK_ULL(46, 46)
#endif

u16 nbl_res_parse_rx_extend_header_draco(struct nbl_res_rx_ring *ring, void *hdr,
					 struct sk_buff *skb)
{
	u64 hdr_low = *(u64 *)hdr;
	u64 hdr_high = *((u64 *)(hdr) + 1);
	int drop = 0;
	u32 rss_hash = FIELD_GET(NBL_RX_HDR_RSS, hdr_high);
	u16 vlan_hdr = FIELD_GET(NBL_RX_HDR_VLAN, hdr_high);
	u16 port_id = FIELD_GET(NBL_RX_HDR_SPORT, hdr_low);
	u8 ptype = FIELD_GET(NBL_RX_HDR_PTYPE, hdr_low);
	u8 cksum = FIELD_GET(NBL_RX_HDR_CKSUM, hdr_low);
#if IS_ENABLED(CONFIG_TLS_DEVICE)
	u8 tls_vld = FIELD_GET(NBL_RX_HDR_TLS_VLD, hdr_low);
#endif

	nbl_rx_csum_draco(ring, skb, ptype, cksum);
	if ((ring->netdev->features & NETIF_F_RXHASH) && rss_hash) {
		enum pkt_hash_types htype = PKT_HASH_TYPE_L2;

		if ((ptype & NBL_RX_PTYPE_L4_MASK) == NBL_RX_PTYPE_VALID_L4)
			htype = PKT_HASH_TYPE_L4;
		else if ((ptype & NBL_RX_PTYPE_L3_MASK) == NBL_RX_PTYPE_VALID_L3)
			htype = PKT_HASH_TYPE_L3;
		skb_set_hash(skb, rss_hash, htype);
		ring->rx_stats.rx_rss_hash_packets += 1;
	}
	drop = nbl_rx_vlan_parse_draco(ring, skb, vlan_hdr);
	if (drop)
		return U16_MAX;

#if IS_ENABLED(CONFIG_TLS_DEVICE)
	if (tls_vld)
		nbl_ktls_rx_handle_skb_draco(ring, skb, (struct nbl_rx_extend_head_draco *)hdr);
#endif
	return port_id;
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

static int nbl_res_cfg_bond_shaping(void *priv, struct nbl_ch_prm_cfg_bond_shaping *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->cfg_bond_shaping(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->eth_id,
					 res_mgt->resource_info->board_info.eth_speed,
					 param->enable);
}

static int nbl_res_set_mtu(void *priv, u16 vsi_id, u16 mtu)
{
	enum nbl_fix_cap_type cap_type = NBL_UDF_EXTRACT_CAP;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	u16 rx_vlan_vsi_id;

	phy_ops->set_mtu(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id, mtu);
	if (nbl_res_get_fix_capability(res_mgt, &cap_type) && func_id < NBL_MAX_PF) {
		rx_vlan_vsi_id =  RDMA_RX_VLAN_VSI_ID(vsi_id);
		phy_ops->set_mtu(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), rx_vlan_vsi_id, mtu);
	}

	return 0;
}

static int nbl_res_register_upcall_port(void *priv, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_upcall_port_info *upcall_port_info = &res_mgt->pmd_status.upcall_port_info;
	struct nbl_rep_offload_status *rep_status = &res_mgt->pmd_status.rep_status;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int i;
	u16 vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);
	u8 eth_id = nbl_res_pf_id_to_eth_id(res_mgt, func_id);

	phy_ops->cfg_nodport_upcall(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id, true);
	rep_status->timestamp = jiffies;
	if (!upcall_port_info->upcall_port_active) {
		upcall_port_info->func_id = func_id;
		upcall_port_info->upcall_port_active = true;
		upcall_port_info->has_upcall = true;

		for (i = 0; i < NBL_OFFLOAD_STATUS_MAX_VSI; i++)
			clear_bit(i, rep_status->rep_vsi_bitmap);

		for (i = 0; i < NBL_OFFLOAD_STATUS_MAX_ETH; i++)
			clear_bit(i, rep_status->rep_eth_bitmap);

		set_bit(vsi_id, rep_status->rep_vsi_bitmap);

		nbl_devcomm_send_event(res_mgt->pmd_status.comp_dev, NBL_DEVCOMM_PMD_CFG_ADD_EVENT,
				       NBL_DEVCOMM_PMD_CFG_ADD_EVENT, &eth_id);
		nbl_res_update_offload_status(res_mgt);
		flow_mgt->offload_status = NBL_FLOW_OFFLOAD;
		nbl_info(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_RESOURCE,
			 "register_upcall_port %u success\n", vsi_id);
		return 0;
	}

	nbl_err(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_RESOURCE,
		"register_upcall_port repeatly\n");
	return -EIO;
}

static void nbl_res_unregister_upcall_port(void *priv, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_upcall_port_info *upcall_port_info =
				&res_mgt->pmd_status.upcall_port_info;
	struct nbl_rep_offload_status *rep_status = &res_mgt->pmd_status.rep_status;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int i;
	u8 eth_id = nbl_res_pf_id_to_eth_id(res_mgt, func_id);
	u16 vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);

	if (!upcall_port_info->upcall_port_active) {
		dev_dbg(dev, "abort func_id %d unregister upcall, as upcall_port_active:%d\n",
			func_id, upcall_port_info->upcall_port_active);
		return;
	}

	if (upcall_port_info->func_id != func_id) {
		nbl_err(common, NBL_DEBUG_RESOURCE,
			"func_id %d unregister upcall failed, upcall_port_info->func_id:%d\n",
			func_id, upcall_port_info->func_id);
		return;
	}

	for (i = 0; i < NBL_OFFLOAD_STATUS_MAX_VSI; i++)
		clear_bit(i, rep_status->rep_vsi_bitmap);

	for (i = 0; i < NBL_OFFLOAD_STATUS_MAX_ETH; i++)
		clear_bit(i, rep_status->rep_eth_bitmap);

	nbl_devcomm_send_event(res_mgt->pmd_status.comp_dev, NBL_DEVCOMM_PMD_CFG_DEL_EVENT,
			       NBL_DEVCOMM_PMD_CFG_DEL_EVENT, &eth_id);
	flow_mgt->offload_status = NBL_FLOW_NON_OFFLOAD;
	nbl_res_update_offload_status(res_mgt);

	upcall_port_info->upcall_port_active = false;
	nbl_flow_restore_flow(res_mgt, true);
	phy_ops->cfg_nodport_upcall(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id, false);

	nbl_info(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_RESOURCE,
		 "unregister_upcall_port %u success\n", func_id);
}

static void nbl_res_register_net_rep(void *priv, u16 pf_id, u16 vf_id,
				     struct nbl_register_net_rep_result *result)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_rep_offload_status *rep_status = &res_mgt->pmd_status.rep_status;
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
	struct nbl_rep_offload_status *rep_status = &res_mgt->pmd_status.rep_status;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);

	if (vsi_id >= NBL_OFFLOAD_STATUS_MAX_VSI) {
		nbl_err(common, NBL_DEBUG_RESOURCE,
			"unregister_net_rep vsi_id %d err\n", vsi_id);
		return;
	}

	/* set rss to l4 */
	phy_ops->set_epro_rss_default(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				      vsi_id, queue_mgt->rss_key_range_oft);
	clear_bit(vsi_id, rep_status->rep_vsi_bitmap);
	nbl_res_update_offload_status(res_mgt);
}

static void nbl_res_register_eth_rep(void *priv, u8 eth_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_rep_offload_status *rep_status = &res_mgt->pmd_status.rep_status;

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
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_rep_offload_status *rep_status = &res_mgt->pmd_status.rep_status;

	if (eth_id >= NBL_OFFLOAD_STATUS_MAX_ETH) {
		nbl_err(common, NBL_DEBUG_RESOURCE,
			"unregister_eth_rep eth_id %d err\n", eth_id);
		return;
	}

	clear_bit(eth_id, rep_status->rep_eth_bitmap);
	nbl_res_update_offload_status(res_mgt);
}

static int nbl_res_disable_phy_flow(void *priv, u8 *eth_id)
{
	int ret;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u8 pf_id = nbl_res_eth_id_to_pf_id(res_mgt, *eth_id);
	int diff = nbl_common_pf_id_subtraction_mgtpf_id(common, pf_id);
	u16 vsi_id = vsi_info->serv_info[diff][NBL_VSI_SERV_PF_CTLR_TYPE].base_id;

	/* set flow default action */
	ret = nbl_phy_cfg_flow_default_action(res_mgt, vsi_id, *eth_id, true);
	if (ret)
		return ret;

	/* TODO: write ACL0 upcall rule for ICMPv6 NS & NA */
	NBL_OPS_CALL(phy_ops->init_hol, (NBL_RES_MGT_TO_PHY_PRIV(res_mgt)));

	return nbl_res_set_phy_flow(res_mgt, *eth_id, true);
}

static int nbl_res_enable_phy_flow(void *priv, u8 *eth_id)
{
	int ret;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);
	u8 pf_id = nbl_res_eth_id_to_pf_id(res_mgt, *eth_id);
	int diff = nbl_common_pf_id_subtraction_mgtpf_id(common, pf_id);
	u16 vsi_id = vsi_info->serv_info[diff][NBL_VSI_SERV_PF_CTLR_TYPE].base_id;

	/* set flow default action */
	ret = nbl_phy_cfg_flow_default_action(res_mgt, vsi_id, *eth_id, false);
	if (ret)
		return ret;

	nbl_flow_restore_flow(res_mgt, true);
	return nbl_res_set_phy_flow(res_mgt, *eth_id, false);
}

static void nbl_res_flr_clear_net(void *priv, u16 vf_id)
{
	u16 func_id = vf_id + NBL_MAX_PF;
	u16 vsi_id;

	vsi_id = nbl_res_func_id_to_vsi_id(priv, func_id, NBL_VSI_DATA);
	nbl_res_unregister_net(priv, &func_id);
}

static void nbl_res_flr_clear_rdma(void *priv, u16 vf_id)
{
	u16 func_id = vf_id + NBL_MAX_PF;
	u16 vsi_id;

	vsi_id = nbl_res_func_id_to_vsi_id(priv, func_id, NBL_VSI_DATA);
	nbl_res_unregister_rdma(priv, &vsi_id);
}

static u16 nbl_res_covert_vfid_to_vsi_id(void *priv, u16 vf_id)
{
	return nbl_res_vfid_to_vsi_id(priv, vf_id);
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
	struct nbl_chan_param_drop_stats_resp *drop_stats = NBL_RES_MGT_TO_DROP_STATS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_chan_param_drop_stats_resp drop_stats_temp = {0};
	u32 uvn_drop_queue_disable = 0;
	u32 curr;
	u32 pre = NBL_RES_MGT_TO_PRE_FAKE_STATS(res_mgt);
	u32 delta;

	phy_ops->get_ustore_pkt_drop_stats(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					   common->eth_id, &drop_stats_temp);
	drop_stats->rx_drop_packets = drop_stats_temp.rx_drop_packets;
	drop_stats->rx_trun_packets = drop_stats_temp.rx_trun_packets;

	if (!resource_info->uvn_drop_queue_disable_init) {
		phy_ops->get_uvn_drop_queue_disable(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						    &uvn_drop_queue_disable);
		resource_info->start_uvn_drop_queue_disable = uvn_drop_queue_disable;
		resource_info->uvn_drop_queue_disable_init = true;
	}

	curr = phy_ops->get_fake_drop_stats(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	delta = curr - pre;
	NBL_RES_MGT_TO_FAKE_STATS(res_mgt) += delta;
	NBL_RES_MGT_TO_PRE_FAKE_STATS(res_mgt) = curr;
	return 0;
}

static int nbl_res_get_total_pkt_drop_stats(void *priv,
					    struct nbl_chan_param_get_total_drop *param,
					    struct nbl_chan_param_drop_stats_resp *nbl_drop_stats)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_chan_param_drop_stats_resp *drop_stats = NBL_RES_MGT_TO_DROP_STATS(res_mgt);
	u32 uvn_drop_queue_disable = 0;

	if (param->op_type == STAT_TYPE_USTORE) {
		nbl_drop_stats->rx_drop_packets = drop_stats->rx_drop_packets;
		nbl_drop_stats->rx_trun_packets = drop_stats->rx_trun_packets;
	} else if (param->op_type == STAT_TYPE_FAKE) {
		nbl_drop_stats->rx_drop_packets =
			NBL_RES_MGT_TO_FAKE_STATS(res_mgt);
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

static int nbl_res_get_eth_bond_info(void *priv, struct nbl_bond_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_eth_bond_info *eth_bond_info = NBL_RES_MGT_TO_ETH_BOND_INFO(res_mgt);
	struct nbl_eth_bond_entry *entry = NULL;
	int num = 0, i = 0, j = 0;

	for (i = 0; i < NBL_LAG_MAX_NUM; i++) {
		entry = &eth_bond_info->entry[i];

		if (!entry->lag_num)
			continue;

		for (j = 0; j < entry->lag_num; j++) {
			param->info[num].port[j].eth_id = entry->eth_id[j];
			param->info[num].port[j].vsi_id = entry->vsi_id[j];
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

static int nbl_res_configure_tx_mirror_to_rdma(void *priv,
					       struct nbl_ch_prm_tx_mirror_to_rdma *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	int ret = 0;

	if (param->enable)
		ret = nbl_fd_configure_tx_mirror_to_rdma(res_mgt, param->mt_id);

	if (!param->enable || ret)
		nbl_fd_remove_tx_mirror_to_rdma(res_mgt);

	return ret;
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
	u8 dir = 0;

	if (!nbl_res_get_fix_capability(res_mgt, &cap_type))
		return;

	phy_ops->ipro_chksum_err_select(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), enable, dir);
	phy_ops->pa_chksum_err_report(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), enable, dir);
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

static int nbl_res_get_lag_ports_max(void *priv)
{
	return 2;
}

static struct nbl_resource_ops res_ops = {
	.get_owned_pf_bitmap		= nbl_res_get_owned_pf_bitmap,
	.register_net			= nbl_res_register_net,
	.unregister_net			= nbl_res_unregister_net,
	.check_active_vf		= nbl_res_check_active_vf,
	.get_vsi_id			= nbl_res_get_vsi_id,
	.get_my_pf			= nbl_res_get_my_pf,
	.get_eth_id			= nbl_res_get_eth_id,
	.check_offload_status		= nbl_res_check_offload_status,
	.get_reg_dump			= nbl_res_get_reg_dump,
	.get_reg_dump_len		= nbl_res_get_reg_dump_len,
	.process_abnormal_event		= nbl_res_process_abnormal_event,
	.get_board_info			= nbl_res_get_board_info,
	.dump_func_info			= nbl_res_dump_func_info,
	.set_mtu			= nbl_res_set_mtu,
	.get_user_queue_info		= nbl_res_get_user_queue_info,
	.get_xdp_queue_info		= nbl_res_get_xdp_queue_info,
	.configure_qos			= nbl_res_configure_qos,
	.configure_rdma_bw		= nbl_res_configure_rdma_bw,
	.set_pfc_buffer_size		= nbl_res_set_pfc_buffer_size,
	.get_pfc_buffer_size		= nbl_res_get_pfc_buffer_size,
	.set_rate_limit			= nbl_res_set_rate_limit,
	.flr_clear_net			= nbl_res_flr_clear_net,
	.flr_clear_rdma			= nbl_res_flr_clear_rdma,
	.covert_vfid_to_vsi_id		= nbl_res_covert_vfid_to_vsi_id,
	.check_vf_is_active		= nbl_res_check_vf_is_active,
	.get_pkt_drop_stats		= nbl_res_get_pkt_drop_stats,
	.get_total_pkt_drop_stats	= nbl_res_get_total_pkt_drop_stats,
	.get_rep_feature		= nbl_res_get_rep_feature,
	.get_rep_queue_info		= nbl_res_get_rep_queue_info,
	.alloc_rep_data			= nbl_res_alloc_rep_data,
	.free_rep_data			= nbl_res_free_rep_data,
	.set_rep_netdev_info		= nbl_res_set_rep_netdev_info,
	.unset_rep_netdev_info		= nbl_res_unset_rep_netdev_info,
	.get_rep_netdev_info		= nbl_res_get_rep_netdev_info,
	.get_vf_base_vsi_id		= nbl_res_get_vf_base_vsi_id,

	/* offload*/
	.init_offload_fwd		= nbl_res_init_offload_fwd,
	.init_rep			= nbl_res_init_rep,
	.init_flow			= nbl_res_init_flow,
	.deinit_flow			= nbl_res_deinit_flow,
	.set_slave_swd_id		= nbl_res_set_slave_swd_id,
	.set_upcall_rule		= nbl_res_set_upcall_rule,
	.unset_upcall_rule		= nbl_res_unset_upcall_rule,
	.get_rep_stats			= nbl_res_get_rep_stats,
	.get_rep_index			= nbl_res_get_rep_index,
	.switchdev_init_cmdq		= nbl_res_switchdev_init_cmdq,
	.switchdev_deinit_cmdq		= nbl_res_switchdev_deinit_cmdq,
	.set_tc_flow_info		= nbl_res_set_tc_flow_info,
	.unset_tc_flow_info		= nbl_res_unset_tc_flow_info,
	.get_tc_flow_info		= nbl_res_get_tc_flow_info,

	/* vdpa */
	.init_vdpaq			= nbl_res_init_vdpaq,
	.destroy_vdpaq			= nbl_res_destroy_vdpaq,
	.check_vf_is_vdpa		= nbl_res_check_vf_is_vdpa,
	.get_vdpa_vf_stats		= nbl_res_get_vdpa_vf_stats,

	/* rdma */
	.setup_rdma_id			= nbl_res_setup_rdma_id,
	.remove_rdma_id			= nbl_res_remove_rdma_id,
	.register_rdma_grc_id		= nbl_res_register_rdma_grc_id,
	.unregister_rdma_grc_id		= nbl_res_unregister_rdma_grc_id,
	.register_rdma			= nbl_res_register_rdma,
	.unregister_rdma		= nbl_res_unregister_rdma,
	.get_hw_addr			= nbl_res_get_hw_addr,
	.get_real_hw_addr		= nbl_res_get_real_hw_addr,
	.get_function_id		= nbl_res_get_function_id,
	.get_real_bdf			= nbl_res_get_real_bdf,
	.cfg_lag_hash_algorithm		= nbl_res_cfg_lag_hash_algorithm,
	.cfg_lag_member_fwd		= nbl_res_cfg_lag_member_fwd,
	.cfg_lag_member_list		= nbl_res_cfg_lag_member_list,
	.cfg_bond_shaping		= nbl_res_cfg_bond_shaping,
	.get_lag_ports_max		= nbl_res_get_lag_ports_max,
	.check_lag_nosupport		= nbl_res_check_lag_nosupport,

	.get_product_flex_cap		= nbl_res_get_flex_capability,
	.get_product_fix_cap		= nbl_res_get_fix_capability,

	/* coexistence */
	.register_upcall_port		= nbl_res_register_upcall_port,
	.unregister_upcall_port		= nbl_res_unregister_upcall_port,
	.register_net_rep		= nbl_res_register_net_rep,
	.unregister_net_rep		= nbl_res_unregister_net_rep,
	.register_eth_rep		= nbl_res_register_eth_rep,
	.unregister_eth_rep		= nbl_res_unregister_eth_rep,
	.disable_phy_flow		= nbl_res_disable_phy_flow,
	.enable_phy_flow		= nbl_res_enable_phy_flow,

	.register_dev_name		= nbl_res_register_dev_name,
	.get_dev_name			= nbl_res_get_dev_name,

	.cfg_eth_bond_info		= nbl_res_cfg_eth_bond_info,
	.get_eth_bond_info		= nbl_res_get_eth_bond_info,

	.get_chip_temperature		= nbl_res_get_chip_temperature,

	/* mirror */
	.get_mirror_table_id		= nbl_res_get_mirror_table_id,
	.configure_mirror		= nbl_res_configure_mirror,
	.configure_tx_mirror_to_rdma	= nbl_res_configure_tx_mirror_to_rdma,
	.clear_mirror_cfg		= nbl_res_clear_mirror_cfg,

	.set_rx_csum_drop = nbl_res_set_rx_csum_drop,
	.set_hw_status = nbl_res_set_hw_status,
	.check_hw_status = nbl_res_check_hw_status,
	.get_hw_status = nbl_res_get_hw_status,
	.get_perf_dump_length		= nbl_res_get_perf_dump_length,
	.get_perf_dump_data		= nbl_res_get_perf_dump_data,
};

void nbl_res_fill_ktls_init_payload_draco(void *init_payload,
					  struct nbl_ktls_offload_context_tx *priv_tx)
{
	struct nbl_ktls_init_payload_draco *init_payload_draco = init_payload;

	init_payload_draco->initial = 1;
	init_payload_draco->sync = 0;
	init_payload_draco->type = priv_tx->crypto_type;
	init_payload_draco->hlen1 = 6;
	init_payload_draco->hlen2 = 1;
	init_payload_draco->plen1 = 0;
	init_payload_draco->plen2 = 0;
	memcpy(init_payload_draco->rec_num, priv_tx->rec_num, NBL_KTLS_REC_LEN);
	memcpy(init_payload_draco->iv, priv_tx->iv, NBL_KTLS_IV_LEN);
	memcpy(init_payload_draco->salt, priv_tx->salt, NBL_KTLS_SALT_LEN);
	memcpy(init_payload_draco->key, priv_tx->key, NBL_KTLS_KEY_LEN);
}

void nbl_res_fill_ktls_sync_payload_draco(void *sync_payload,
					  struct nbl_ktls_offload_context_tx *priv_tx)
{
	struct nbl_ktls_sync_payload_draco *sync_payload_draco = sync_payload;

	sync_payload_draco->sync = 1;
	sync_payload_draco->type = priv_tx->crypto_type;
	sync_payload_draco->redlen = priv_tx->sync_redlen;
	memcpy(sync_payload_draco->salt, priv_tx->salt, NBL_KTLS_SALT_LEN);
	memcpy(sync_payload_draco->key, priv_tx->key, NBL_KTLS_KEY_LEN);
	memcpy(sync_payload_draco->rec_num, &priv_tx->sync_rec_num, NBL_KTLS_REC_LEN);
	memcpy(sync_payload_draco->iv, &priv_tx->sync_iv, NBL_KTLS_IV_LEN);
}

static struct nbl_res_product_ops product_ops = {
	.queue_mgt_init			= nbl_queue_mgt_init_draco,
	.init_epro_vpt_extra		= nbl_res_queue_init_epro_vpt_extra,
	.setup_qid_map_table		= nbl_res_queue_setup_qid_map_table_draco,
	.get_rss_ret_base_and_size	= nbl_res_queue_get_rss_ret_base_and_size_draco,
	.get_rxfh_indir			= nbl_res_queue_get_rxfh_indir_draco,
	.get_hash_fields		= nbl_res_queue_get_hash_fields_draco,
	.set_hash_fields		= nbl_res_queue_set_hash_fields_draco,
	.intr_mgt_init			= nbl_intr_mgt_init_draco,
	.txrx_mgt_init			= nbl_txrx_mgt_init_draco,
	.parse_rx_extend_header		= nbl_res_parse_rx_extend_header_draco,
	.features_check			= nbl_res_txrx_features_check_draco,
	.config_key			= nbl_fd_config_key_draco,
	.handle_queue_update		= nbl_fd_handle_queue_update_draco,
#if IS_ENABLED(CONFIG_TLS_DEVICE)
	.fill_ktls_init_payload		= nbl_res_fill_ktls_init_payload_draco,
	.ktls_send_resync_packet	= nbl_ktls_send_resync_packet_draco,
#endif
	.adminq_mgt_init		= nbl_adminq_mgt_init_draco,
	.tx_exthdr_offset		= nbl_res_draco_txhdr_offset,
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
		ret = nbl_flow_setup_ops_draco(&res_ops);
		if (ret)
			goto setup_fail;

		ret = nbl_tc_flow_setup_ops_draco(&res_ops);
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

		ret = nbl_accel_setup_ops(&res_ops, true);
		if (ret)
			goto setup_fail;

		ret = nbl_adminq_setup_ops(&res_ops);
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
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	eswitch_info = devm_kzalloc(dev, sizeof(struct nbl_eswitch_info), GFP_KERNEL);
	if (!eswitch_info)
		return -ENOMEM;
	eswitch_info->rep_data = devm_kcalloc(dev, NBL_VSI_ID_GAP(NBL_COMMON_TO_ETH_MODE(common)),
					      sizeof(struct nbl_rep_data), GFP_KERNEL);
	if (!eswitch_info->rep_data) {
		devm_kfree(dev, eswitch_info);
		eswitch_info = NULL;
		return -ENOMEM;
	}
	NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt) = eswitch_info;

	return 0;
}

static void nbl_res_pf_dev_remove_eswitch_info(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_eswitch_info **eswitch_info = &NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt);

	if (!(*eswitch_info))
		return;
	if ((*eswitch_info)->rep_data)
		devm_kfree(dev, (*eswitch_info)->rep_data);
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
	struct device *dev;
	struct nbl_eth_info *eth_info;
	struct nbl_eth_bond_info *eth_bond_info;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	u16 func_id = NBL_COMMON_TO_MGT_PF(common);
	int i;
	u8 eth_id;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u32 eth_bitmap = 0;
	u32 eth_num = 0;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
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

	/* setup owned_pf_bitmap */
	set_bit(func_id, resource_info->owned_pf_bitmap);
	/* for pf0, if there are pfs whose pf_id > eth_num, then their mgt_pf is pf0 */
	/* 2 port, mgt_pf of PF2-PF7 is PF0 */
	/* 4 port, mgt_pf of PF4-PF7 is PF0 */
	if (func_id == 0) {
		for (i = eth_info->eth_num; i < NBL_RES_MGT_TO_PF_NUM(res_mgt); i++)
			set_bit(i, resource_info->owned_pf_bitmap);
	}
	dev_info(dev, "owned_pf_bitmap:0x%lx\n", *resource_info->owned_pf_bitmap);

	/* setup eth_info->eth_id[] */
	/* for 2 eth port board, the eth_id is 0, 2 */
	for (i = 0; i < NBL_MAX_ETHERNET; i++) {
		if ((1 << i) & eth_bitmap) {
			if (func_id == eth_num)
				set_bit(i, eth_info->eth_bitmap);
			eth_info->eth_id[eth_num] = i;
			eth_info->logic_eth_id[i] = eth_num;
			eth_num++;
		}
	}
	mutex_init(&eth_info->eth_lock);
	/* setup eth_info->pf_bitmap[] */
	for (i = 0; i < NBL_RES_MGT_TO_PF_NUM(res_mgt); i++) {
		/* if pf_id <= eth_num, the pf relate corresponding eth_id */
		if (i < eth_info->eth_num) {
			eth_id = eth_info->eth_id[i];
			eth_info->pf_bitmap[eth_id] |= BIT(i);
		}
		/* if pf_id > eth_num, the pf relate eth 0 */
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
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct device *dev =  NBL_COMMON_TO_DEV(common);
	struct nbl_sriov_info *sriov_info = NULL;
	u32 vf_fid, vf_startid, vf_endid;
	u16 pf_func_id = NBL_COMMON_TO_MGT_PF(common);
	u16 func_id = 0;
	u16 function;
	int diff;
	u8 bus = 0;
	u8 devid = 0;
	u8 func = 0;

	sriov_info = devm_kcalloc(dev, NBL_RES_MGT_TO_PF_NUM(res_mgt),
				  sizeof(struct nbl_sriov_info), GFP_KERNEL);
	if (!sriov_info)
		return -ENOMEM;

	NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) = sriov_info;

	function = NBL_COMMON_TO_PCI_FUNC_ID(common);
	sriov_info->bdf = resource_info->bdf;
	vf_fid = phy_ops->get_host_pf_fid(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), pf_func_id);
	vf_startid = vf_fid & 0xFFFF;
	vf_endid = (vf_fid >> 16) & 0xFFFF;
	sriov_info->start_vf_func_id = vf_startid + NBL_MAX_PF_DRACO;
	sriov_info->num_vfs = vf_endid - vf_startid;
	resource_info->max_vf_bypf_num = sriov_info->num_vfs;

	dev_info(dev, "func_id:%d, bdf:%x:%x.%x, start_vf_func_id:%d, num_vfs:%d\n",
		 pf_func_id, PCI_BUS_NUM(sriov_info->bdf), PCI_SLOT(sriov_info->bdf & 0xff),
		 PCI_FUNC(sriov_info->bdf & 0xff),
		 sriov_info->start_vf_func_id, sriov_info->num_vfs);

	if (pf_func_id == 0) {
		for (func_id = NBL_PF_NUM_DRACO;
		     func_id < NBL_RES_MGT_TO_PF_NUM(res_mgt); func_id++) {
			diff = nbl_common_pf_id_subtraction_mgtpf_id(common, func_id);
			sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + diff;

			bus = PCI_BUS_NUM(resource_info->bdf);
			devid = PCI_SLOT(resource_info->bdf & 0xff);
			func = PCI_FUNC(resource_info->bdf & 0xff) + func_id;
			sriov_info->bdf = PCI_DEVID(bus, PCI_DEVFN(devid, func));
			vf_fid = phy_ops->get_host_pf_fid(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
							  func_id);
			vf_startid = vf_fid & 0xFFFF;
			vf_endid = (vf_fid >> 16) & 0xFFFF;
			sriov_info->start_vf_func_id = vf_startid + NBL_MAX_PF_DRACO;
			sriov_info->num_vfs = vf_endid - vf_startid;

			dev_info(dev, "func_id:%d, bdf:%x:%x.%x, start_vf_func_id:%d, num_vfs:%d\n",
				 func_id, PCI_BUS_NUM(sriov_info->bdf),
				 PCI_SLOT(sriov_info->bdf & 0xff),
				 PCI_FUNC(sriov_info->bdf & 0xff),
				 sriov_info->start_vf_func_id, sriov_info->num_vfs);
		}
	}

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

static void nbl_res_capture_bdf(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	u16 func_id = 0;
	u16 bdf = 0;
	u8 mgt_pf = 0;

	phy_ops->capture_bdf(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), &func_id, &mgt_pf, &bdf);

	/* mgt_pf of PF4-PF7 is PF0 */
	if (func_id >= NBL_PF_NUM_DRACO && func_id < NBL_MAX_PF_DRACO)
		mgt_pf = 0;

	NBL_COMMON_TO_MGT_PF(common) = mgt_pf;
	resource_info->bdf = bdf;

	dev_info(dev, "func_id:%d, mgt_pf:%d, bdf:%x:%x.%x\n",
		 func_id, mgt_pf,
		 PCI_BUS_NUM(bdf), PCI_SLOT(bdf & 0xff), PCI_FUNC(bdf & 0xff));
}

static void nbl_res_init_board_info(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->get_board_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				&res_mgt->resource_info->board_info);
}

static int nbl_res_init_pf_num(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	u32 pf_mask;
	u32 pf_num = 0;
	int i;

	for (i = 0; i < NBL_MAX_PF_DRACO; i++) {
		pf_mask = phy_ops->get_host_pf_mask(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), i);
		if (!(pf_mask & (1 << 15)))
			pf_num++;
	}

	NBL_RES_MGT_TO_PF_NUM(res_mgt) = pf_num;

	dev_info(dev, "pf_num:%x\n", pf_num);

	if (!pf_num)
		return -1;

	return 0;
}

static void nbl_res_ctrl_dev_vdpa_vf_stats_remove(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_vdpa_status **vdpa_vf_stats = NBL_RES_MGT_TO_VDPA_VF_STATS(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	int i = 0;

	for (i = 0; i < NBL_MAX_FUNC; i++) {
		if (vdpa_vf_stats[i]) {
			devm_kfree(dev, vdpa_vf_stats[i]);
			vdpa_vf_stats[i] = NULL;
		}
	}
}

static int nbl_res_ctrl_dev_vsi_info_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct device *dev =  NBL_COMMON_TO_DEV(common);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	u16 func_id = NBL_COMMON_TO_MGT_PF(common);
	struct nbl_vsi_info *vsi_info;
	int diff;
	struct nbl_sriov_info *sriov_info;
	int vsi_gap;

	diff = nbl_common_pf_id_subtraction_mgtpf_id(common, func_id);
	sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + diff;

	if (eth_info->eth_num == NBL_TWO_ETHERNET_PORT)
		vsi_gap = NBL_TWO_ETHERNET_VSI_ID_GAP_DRACO;
	else
		vsi_gap = NBL_FOUR_ETHERNET_VSI_ID_GAP_DRACO;

	vsi_info = devm_kzalloc(dev, sizeof(struct nbl_vsi_info), GFP_KERNEL);
	if (!vsi_info)
		return -ENOMEM;

	NBL_RES_MGT_TO_VSI_INFO(res_mgt) = vsi_info;

	/**
	 * case1 two port(2pf)
	 * pf0,pf1(NBL_VSI_SERV_PF_DATA_TYPE) vsi is 0,3
	 * pf0,pf1(NBL_VSI_SERV_PF_USER_TYPE) vsi is 1,4
	 * pf0,pf1(NBL_VSI_SERV_PF_XDP_TYPE) vsi is 2,5
	 * pf0,pf1(NBL_VSI_SERV_PF_CTLR_TYPE) vsi is 12,13
	 * pf0(NBL_VSI_SERV_PF_EXTRA_TYPE) vsi is 14-19
	 * pf0.vf0-pf0.vf127(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 20-147
	 * pf1.vf0-pf1.vf255(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 148-275
	 *
	 * case2 four port(4pf)
	 * pf0,pf1,pf2,pf3(NBL_VSI_SERV_PF_DATA_TYPE) vsi is 0,3,6,9
	 * pf0,pf1,pf2,pf3(NBL_VSI_SERV_PF_USER_TYPE) vsi is 1,4,7,10
	 * pf0,pf1,pf2,pf3(NBL_VSI_SERV_PF_XDP_TYPE) vsi is 2,5,8,11
	 * pf0,pf1,pf2,pf3(NBL_VSI_SERV_PF_CTLR_TYPE) vsi is 12-15
	 * pf0(NBL_VSI_SERV_PF_EXTRA_TYPE) vsi is 16-19
	 * pf0.vf0-pf0.vf63(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 20-83
	 * pf1.vf0-pf1.vf63(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 84-147
	 * pf2.vf0-pf2.vf63(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 148-211
	 * pf3.vf0-pf3.vf63(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 212-275
	 */

	vsi_info->num = 1;
	vsi_info->serv_info[0][NBL_VSI_SERV_PF_DATA_TYPE].base_id =
		NBL_COMMON_TO_MGT_PF(common) * NBL_PF_RSS_BIG_SIZE_VSI_NUM;
	vsi_info->serv_info[0][NBL_VSI_SERV_PF_DATA_TYPE].num = 1;
	vsi_info->serv_info[0][NBL_VSI_SERV_PF_USER_TYPE].base_id =
		vsi_info->serv_info[0][NBL_VSI_SERV_PF_DATA_TYPE].base_id
		+ vsi_info->serv_info[0][NBL_VSI_SERV_PF_DATA_TYPE].num;
	vsi_info->serv_info[0][NBL_VSI_SERV_PF_USER_TYPE].num = 1;
	vsi_info->serv_info[0][NBL_VSI_SERV_PF_XDP_TYPE].base_id =
		vsi_info->serv_info[0][NBL_VSI_SERV_PF_USER_TYPE].base_id
		+ vsi_info->serv_info[0][NBL_VSI_SERV_PF_USER_TYPE].num;
	vsi_info->serv_info[0][NBL_VSI_SERV_PF_XDP_TYPE].num = 1;
	vsi_info->serv_info[0][NBL_VSI_SERV_PF_CTLR_TYPE].base_id =
		NBL_VSI_RSS_SIZE_COMMON_BASE_ID + NBL_COMMON_TO_MGT_PF(common);
	vsi_info->serv_info[0][NBL_VSI_SERV_PF_CTLR_TYPE].num = 1;

	vsi_info->serv_info[0][NBL_VSI_SERV_PF_EXTRA_TYPE].base_id =
				vsi_info->serv_info[0][NBL_VSI_SERV_PF_CTLR_TYPE].base_id
				+ eth_info->eth_num;
	vsi_info->serv_info[0][NBL_VSI_SERV_PF_EXTRA_TYPE].num = 1;
	vsi_info->serv_info[0][NBL_VSI_SERV_VF_DATA_TYPE].base_id =
			NBL_VSI_VF_BASE_ID + NBL_COMMON_TO_MGT_PF(common) * vsi_gap;
	vsi_info->serv_info[0][NBL_VSI_SERV_VF_DATA_TYPE].num = sriov_info->num_vfs;

	dev_info(dev, "pf base_id:%d, pf ctr base_id:%d, pf user base_id:%d, pf xdp base_id:%d, vf base_id:%d, pf extra base_id:%d\n",
		 vsi_info->serv_info[0][NBL_VSI_SERV_PF_DATA_TYPE].base_id,
		 vsi_info->serv_info[0][NBL_VSI_SERV_PF_CTLR_TYPE].base_id,
		 vsi_info->serv_info[0][NBL_VSI_SERV_PF_USER_TYPE].base_id,
		 vsi_info->serv_info[0][NBL_VSI_SERV_PF_XDP_TYPE].base_id,
		 vsi_info->serv_info[0][NBL_VSI_SERV_VF_DATA_TYPE].base_id,
		 vsi_info->serv_info[0][NBL_VSI_SERV_PF_EXTRA_TYPE].base_id);

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

	drop_stats = devm_kzalloc(dev, sizeof(*drop_stats), GFP_KERNEL);
	if (!drop_stats)
		return -ENOMEM;

	NBL_RES_MGT_TO_DROP_STATS(res_mgt) = drop_stats;

	return 0;
}

static void nbl_rdma_mgt_start(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_rdma_info *rdma_info = &resource_info->rdma_info;

	rdma_info->pf_msix_num = NBL_RES_RDMA_PF_INTR_NUM;
	rdma_info->vf_msix_num = NBL_RES_RDMA_VF_INTR_NUM;
	rdma_info->mem_type = 0;
	rdma_info->rdma_max_func_num = NBL_RES_RDMA_MAX_DRACO;
}

static int nbl_res_pmdcfg_comp_event_cb(int event, void *priv_data, void *event_data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv_data;
	u8 eth_id = *(u8 *)event_data;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	nbl_info(common, NBL_DEBUG_RESOURCE, "receive comp pmd cfg eth_id:%d, type:%d\n",
		 eth_id, event);

	switch (event) {
	case NBL_DEVCOMM_PMD_CFG_ADD_EVENT:
		res_mgt->pmd_status.other_pmd_cfg[eth_id] = true;
		break;
	case NBL_DEVCOMM_PMD_CFG_DEL_EVENT:
		res_mgt->pmd_status.other_pmd_cfg[eth_id] = false;
		break;
	default:
		break;
	}

	nbl_res_update_offload_status(res_mgt);

	return 0;
}

static int nbl_res_register_pmdcfg_comp(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_devcomm_comp_dev *comp_dev;
	struct nbl_devcomm_match_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.key.val = pci_domain_nr(common->pdev->bus) << 16 | common->pdev->bus->number;
	comp_dev = nbl_devcomm_register_component(NBL_DEVCOMM_PMDCFG,
						  &attr,
						  nbl_res_pmdcfg_comp_event_cb,
						  res_mgt);
	if (!comp_dev)
		return -ENOMEM;

	res_mgt->pmd_status.comp_dev = comp_dev;

	return 0;
}

static void nbl_res_unregister_pmdcfg_comp(struct nbl_resource_mgt *res_mgt)
{
	nbl_devcomm_unregister_component(res_mgt->pmd_status.comp_dev);
}

static void nbl_res_stop(struct nbl_resource_mgt *res_mgt)
{
	nbl_res_set_rx_csum_drop(res_mgt, false);
	nbl_fd_mgt_stop(res_mgt);
	nbl_adminq_mgt_stop(res_mgt);
	nbl_queue_mgt_stop(res_mgt);
	nbl_res_unregister_pmdcfg_comp(res_mgt);
	nbl_txrx_mgt_stop(res_mgt);
	nbl_intr_mgt_stop(res_mgt);
	nbl_vsi_mgt_stop(res_mgt);
	nbl_accel_mgt_stop(res_mgt);
	nbl_flow_mgt_stop_draco(res_mgt);
	nbl_res_ctrl_dev_vdpa_vf_stats_remove(res_mgt);
	nbl_res_ctrl_dev_remove_vsi_info(res_mgt);
	nbl_res_ctrl_dev_remove_eth_info(res_mgt);
	nbl_res_ctrl_dev_remove_qinfo_tx(res_mgt);
	nbl_res_ctrl_dev_sriov_info_remove(res_mgt);
	nbl_res_pf_dev_remove_eswitch_info(res_mgt);
	nbl_tc_flow_mgt_stop_draco(res_mgt);
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

		nbl_res_capture_bdf(res_mgt);

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

		ret = nbl_flow_mgt_start_draco(res_mgt);
		if (ret)
			goto start_fail;
		ret = nbl_tc_flow_mgt_start_draco(res_mgt);
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

		ret = nbl_res_register_pmdcfg_comp(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_adminq_mgt_start(res_mgt, FIRMWARE_MAGIC_DRACO, true);
		if (ret)
			goto start_fail;

		ret = nbl_fd_mgt_start(res_mgt);
		if (ret)
			goto start_fail;

		nbl_rdma_mgt_start(res_mgt);
		nbl_res_set_flex_capability(res_mgt, NBL_DUMP_FLOW_CAP);
		nbl_res_set_flex_capability(res_mgt, NBL_DUMP_FD_CAP);
		nbl_res_set_flex_capability(res_mgt, NBL_DUMP_FUNC_INFO_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_RESTOOL_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_PRIO_STATS_CAP);
		nbl_res_set_flex_capability(res_mgt, NBL_SECURITY_TLS_CAP);
		nbl_res_set_flex_capability(res_mgt, NBL_SECURITY_IPSEC_CAP);
		nbl_res_set_flex_capability(res_mgt, NBL_SECURITY_MACSEC_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_PROCESS_FLR_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_XDP_ENHANCE);
		nbl_res_set_fix_capability(res_mgt, NBL_DEVSHR_IDX_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_LINK_DOWN_ON_CLOSE);
		nbl_res_set_fix_capability(res_mgt, NBL_TX_FC_SEGREGATGE_ENABLE);
		nbl_res_set_fix_capability(res_mgt, NBL_RX_CSUM_ERR_DROP_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_DVN_DESC_REQ_SYSFS_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_NEED_DESTROY_CHIP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_FW_HB_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_FW_RESET_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_HEALTH_REPORT_REBOOT_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_HWMON_TEMP_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_QOS_SYSFS_CAP);
		/* common->function is init in dev layer, use hw func to avoid in vm passthough */
		if (!NBL_COMMON_TO_MGT_PF(common)) {
			nbl_res_set_fix_capability(res_mgt, NBL_TASK_ADAPT_DESC_GOTHER);
			nbl_res_set_fix_capability(res_mgt, NBL_HIGH_THROUGHPUT_CAP);
		}
		nbl_res_set_fix_capability(res_mgt, NBL_XDP_CAP);
	}

	if (caps.has_net) {
		nbl_res_capture_bdf(res_mgt);

		ret = nbl_txrx_mgt_start(res_mgt);
		if (ret)
			goto start_fail;

		if (!caps.is_vf) {
			ret = nbl_res_dev_setup_eswitch_info(res_mgt);
			if (ret)
				goto start_fail;
		}
	}

	nbl_res_set_fix_capability(res_mgt, NBL_TASK_CLEAN_MAILBOX_CAP);
	nbl_res_set_fix_capability(res_mgt, NBL_MSIX_AUTO_MASK_CAP);
	nbl_res_set_fix_capability(res_mgt, NBL_MSIX_FAST_RESTRAIN_CAP);
	nbl_res_set_fix_capability(res_mgt, NBL_UDF_EXTRACT_CAP);
	nbl_res_set_fix_capability(res_mgt, NBL_ITR_DYNAMIC);
	nbl_res_set_fix_capability(res_mgt, NBL_MIRROR_SYSFS_CAP);
	nbl_res_set_fix_capability(res_mgt, NBL_RXQ_LARGE_BUF);
	nbl_res_set_fix_capability(res_mgt, NBL_RXFH_KEY_SET_CAP);
	nbl_res_set_fix_capability(res_mgt, NBL_RESUME_CAP);

	return 0;

start_fail:
	nbl_res_stop(res_mgt);
	return ret;
}

int nbl_res_init_draco(void *p, struct nbl_init_param *param)
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

void nbl_res_remove_draco(void *p)
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
