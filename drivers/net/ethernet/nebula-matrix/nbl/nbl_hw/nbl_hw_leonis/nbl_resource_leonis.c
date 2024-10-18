// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_resource_leonis.h"

MODULE_VERSION(NBL_LEONIS_DRIVER_VERSION);

static void nbl_res_setup_common_ops(struct nbl_resource_mgt *res_mgt)
{
}

static int nbl_res_pf_to_eth_id(struct nbl_resource_mgt *res_mgt, u16 pf_id)
{
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);

	if (pf_id >= NBL_MAX_PF)
		return 0;

	return eth_info->eth_id[pf_id];
}

static u32 nbl_res_get_pfvf_queue_num(struct nbl_resource_mgt *res_mgt, int pfid, int vfid)
{
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_net_ring_num_info *num_info = &res_info->net_ring_num_info;
	u16 func_id = nbl_res_pfvfid_to_func_id(res_mgt, pfid, vfid);
	u32 queue_num = 0;

	if (vfid >= 0) {
		if (num_info->net_max_qp_num[func_id] != 0)
			queue_num = num_info->net_max_qp_num[func_id];
		else
			queue_num = num_info->vf_def_max_net_qp_num;
	} else {
		if (num_info->net_max_qp_num[func_id] != 0)
			queue_num = num_info->net_max_qp_num[func_id];
		else
			queue_num = num_info->pf_def_max_net_qp_num;
	}

	if (queue_num > NBL_MAX_TXRX_QUEUE_PER_FUNC) {
		nbl_warn(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_QUEUE,
			 "Invalid queue num %u for func %d, use default", queue_num, func_id);
		queue_num = vfid >= 0 ? NBL_DEFAULT_VF_HW_QUEUE_NUM : NBL_DEFAULT_PF_HW_QUEUE_NUM;
	}

	return queue_num;
}

static void nbl_res_get_user_queue_info(void *priv, u16 *queue_num, u16 *queue_size, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_net_ring_num_info *num_info = &res_info->net_ring_num_info;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);

	if (num_info->net_max_qp_num[func_id] != 0)
		*queue_num = num_info->net_max_qp_num[func_id];
	else
		*queue_num = num_info->pf_def_max_net_qp_num;

	*queue_size = NBL_DEFAULT_DESC_NUM;

	if (*queue_num > NBL_MAX_TXRX_QUEUE_PER_FUNC) {
		nbl_warn(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_QUEUE,
			 "Invalid user queue num %d for func %d, use default", *queue_num, func_id);
		*queue_num = NBL_DEFAULT_PF_HW_QUEUE_NUM;
	}
}

static int nbl_res_get_queue_num(struct nbl_resource_mgt *res_mgt,
				 u16 func_id, u16 *tx_queue_num, u16 *rx_queue_num)
{
	int pfid, vfid;

	nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pfid, &vfid);

	*tx_queue_num = nbl_res_get_pfvf_queue_num(res_mgt, pfid, vfid);
	*rx_queue_num = nbl_res_get_pfvf_queue_num(res_mgt, pfid, vfid);

	return 0;
}

static int nbl_res_save_vf_bar_info(struct nbl_resource_mgt *res_mgt,
				    u16 func_id, struct nbl_register_net_param *register_param)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_sriov_info *sriov_info = &NBL_RES_MGT_TO_SRIOV_INFO(res_mgt)[func_id];
	u64 pf_bar_start;
	u16 pf_bdf;
	u64 vf_bar_start;
	u64 vf_bar_size;
	u16 total_vfs;
	u16 offset;
	u16 stride;

	pf_bar_start = register_param->pf_bar_start;
	if (pf_bar_start) {
		sriov_info->pf_bar_start = pf_bar_start;
		dev_info(dev, "sriov_info, pf_bar_start:%llx\n", sriov_info->pf_bar_start);
	}

	pf_bdf = register_param->pf_bdf;
	vf_bar_start = register_param->vf_bar_start;
	vf_bar_size = register_param->vf_bar_size;
	total_vfs = register_param->total_vfs;
	offset = register_param->offset;
	stride = register_param->stride;

	if (total_vfs) {
		if (pf_bdf != sriov_info->bdf) {
			dev_err(dev, "PF bdf donot equal, af record = %u, real pf bdf: %u\n",
				sriov_info->bdf, pf_bdf);
			return -EIO;
		}
		sriov_info->offset = offset;
		sriov_info->stride = stride;
		sriov_info->vf_bar_start = vf_bar_start;
		sriov_info->vf_bar_len = vf_bar_size / total_vfs;

		dev_info(dev, "sriov_info, bdf:%x:%x.%x, num_vfs:%d\n",
			 PCI_BUS_NUM(pf_bdf), PCI_SLOT(pf_bdf & 0xff),
			 PCI_FUNC(pf_bdf & 0xff), sriov_info->num_vfs);
		dev_info(dev, "start_vf_func_id:%d, offset:%d, stride:%d\n",
			 sriov_info->start_vf_func_id, offset, stride);
	}

	return 0;
}

static int nbl_res_prepare_vf_chan(struct nbl_resource_mgt *res_mgt,
				   u16 func_id, struct nbl_register_net_param *register_param)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_sriov_info *sriov_info = &NBL_RES_MGT_TO_SRIOV_INFO(res_mgt)[func_id];
	u16 pf_bdf;
	u16 total_vfs;
	u16 offset;
	u16 stride;
	u8 pf_bus;
	u8 pf_devfn;
	u16 vf_id;
	u8 bus;
	u8 devfn;
	u8 devid;
	u8 function;
	u16 vf_func_id;

	pf_bdf = register_param->pf_bdf;
	total_vfs = register_param->total_vfs;
	offset = register_param->offset;
	stride = register_param->stride;

	if (total_vfs) {
		if (pf_bdf != sriov_info->bdf) {
			dev_err(dev, "PF bdf donot equal, af record = %u, real pf bdf: %u\n",
				sriov_info->bdf, pf_bdf);
			return -EIO;
		}

		/* Configure mailbox qinfo_map_table for the pf's all vf,
		 * so vf's mailbox is ready, vf can use mailbox.
		 */
		pf_bus = PCI_BUS_NUM(sriov_info->bdf);
		pf_devfn = sriov_info->bdf & 0xff;
		for (vf_id = 0; vf_id < sriov_info->num_vfs; vf_id++) {
			vf_func_id = sriov_info->start_vf_func_id + vf_id;

			bus = pf_bus + ((pf_devfn + offset + stride * vf_id) >> 8);
			devfn = (pf_devfn + offset + stride * vf_id) & 0xff;
			devid = PCI_SLOT(devfn);
			function = PCI_FUNC(devfn);

			phy_ops->cfg_mailbox_qinfo(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						   vf_func_id, bus, devid, function);
		}
	}

	return 0;
}

static int nbl_res_update_active_vf_num(struct nbl_resource_mgt *res_mgt, u16 func_id,
					bool add_flag)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_resource_info *resource_info = res_mgt->resource_info;
	struct nbl_sriov_info *sriov_info = res_mgt->resource_info->sriov_info;
	int pfid = 0;
	int vfid = 0;
	int ret;

	ret = nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pfid, &vfid);
	if (ret) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "convert func id to pfvfid failed\n");
		return ret;
	}

	if (vfid == U32_MAX)
		return 0;

	if (add_flag) {
		if (!test_bit(func_id, resource_info->func_bitmap)) {
			sriov_info[pfid].active_vf_num++;
			set_bit(func_id, resource_info->func_bitmap);
		}
	} else if (sriov_info[pfid].active_vf_num) {
		if (test_bit(func_id, resource_info->func_bitmap)) {
			sriov_info[pfid].active_vf_num--;
			clear_bit(func_id, resource_info->func_bitmap);
		}
	}

	return 0;
}

static int nbl_res_register_net(void *priv, u16 func_id,
				struct nbl_register_net_param *register_param,
				struct nbl_register_net_result *register_result)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	netdev_features_t csumo_features = 0;
	netdev_features_t tso_features = 0;
	u16 tx_queue_num, rx_queue_num;
	u8 mac[ETH_ALEN] = {0};
	int ret = 0;

	csumo_features = NBL_FEATURE(NETIF_F_RXCSUM) |
			NBL_FEATURE(NETIF_F_IP_CSUM) |
			NBL_FEATURE(NETIF_F_IPV6_CSUM);
	tso_features = NBL_FEATURE(NETIF_F_TSO) |
		NBL_FEATURE(NETIF_F_TSO6) |
		NBL_FEATURE(NETIF_F_GSO_UDP_L4);

	register_result->hw_features |= csumo_features |
					tso_features |
					NBL_FEATURE(NETIF_F_SG) |
					NBL_FEATURE(NETIF_F_HW_TC);
	register_result->features |= register_result->hw_features |
				     NBL_FEATURE(NETIF_F_HW_TC) |
				     NBL_FEATURE(NETIF_F_HW_VLAN_CTAG_FILTER) |
				     NBL_FEATURE(NETIF_F_HW_VLAN_STAG_FILTER);

	register_result->max_mtu = NBL_MAX_JUMBO_FRAME_SIZE - NBL_PKT_HDR_PAD;

	if (func_id < NBL_MAX_PF)
		nbl_res_get_eth_mac(res_mgt, mac, nbl_res_pf_to_eth_id(res_mgt, func_id));
	memcpy(register_result->mac, mac, ETH_ALEN);

	nbl_res_get_queue_num(res_mgt, func_id, &tx_queue_num, &rx_queue_num);
	register_result->tx_queue_num = tx_queue_num;
	register_result->rx_queue_num = rx_queue_num;
	register_result->queue_size = NBL_DEFAULT_DESC_NUM;

	ret = nbl_res_update_active_vf_num(res_mgt, func_id, 1);
	if (ret) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "change active vf num failed with ret: %d\n",
			ret);
		goto update_active_vf_fail;
	}

	if (func_id >= NBL_RES_MGT_TO_PF_NUM(res_mgt))
		return 0;

	ret = nbl_res_save_vf_bar_info(res_mgt, func_id, register_param);
	if (ret)
		goto save_vf_bar_info_fail;

	ret = nbl_res_prepare_vf_chan(res_mgt, func_id, register_param);
	if (ret)
		goto prepare_vf_chan_fail;

	nbl_res_open_sfp(res_mgt, nbl_res_pf_to_eth_id(res_mgt, func_id));

	return ret;

prepare_vf_chan_fail:
save_vf_bar_info_fail:
update_active_vf_fail:
	return -EIO;
}

static int nbl_res_unregister_net(void *priv, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return nbl_res_update_active_vf_num(res_mgt, func_id, 0);
}

static u16 nbl_res_get_vsi_id(void *priv, u16 func_id, u16 type)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return nbl_res_func_id_to_vsi_id(res_mgt, func_id, type);
}

static void nbl_res_get_eth_id(void *priv, u16 vsi_id, u8 *eth_mode, u8 *eth_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	u16 pf_id = nbl_res_vsi_id_to_pf_id(res_mgt, vsi_id);

	*eth_mode = eth_info->eth_num;
	if (pf_id < eth_info->eth_num)
		*eth_id = eth_info->eth_id[pf_id];
	/* if pf_id > eth_num, use eth_id 0 */
	else
		*eth_id = eth_info->eth_id[0];
}

static u8 __iomem *nbl_res_get_hw_addr(void *priv, size_t *size)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->get_hw_addr(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), size);
}

static u64 nbl_res_get_real_hw_addr(void *priv, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);

	return nbl_res_get_func_bar_base_addr(res_mgt, func_id);
}

static u16 nbl_res_get_function_id(void *priv, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
}

static void nbl_res_get_real_bdf(void *priv, u16 vsi_id, u8 *bus, u8 *dev, u8 *function)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);

	nbl_res_func_id_to_bdf(res_mgt, func_id, bus, dev, function);
}

static u32 nbl_res_check_active_vf(void *priv, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_sriov_info *sriov_info = res_mgt->resource_info->sriov_info;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	int pfid = 0;
	int vfid = 0;
	int ret;

	ret = nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pfid, &vfid);
	if (ret) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "convert func id to pfvfid failed\n");
		return ret;
	}

	return sriov_info[pfid].active_vf_num;
}

static void nbl_res_get_base_mac_addr(void *priv, u8 *mac)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	nbl_res_get_eth_mac(res_mgt, mac, nbl_res_pf_to_eth_id(res_mgt, 0));
}

static u32 nbl_res_get_chip_temperature(void *priv)
{
	struct nbl_resource_mgt_leonis *res_mgt_leonis =
		(struct nbl_resource_mgt_leonis *)priv;
	struct nbl_resource_mgt *res_mgt = &res_mgt_leonis->res_mgt;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->get_chip_temperature(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
}

static u32 nbl_res_get_chip_temperature_max(void *priv)
{
	return NBL_LEONIS_TEMP_MAX;
}

static u32 nbl_res_get_chip_temperature_crit(void *priv)
{
	return NBL_LEONIS_TEMP_CRIT;
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

static int nbl_res_get_driver_info(void *priv, struct nbl_driver_info *driver_info)
{
	strscpy(driver_info->driver_version, NBL_LEONIS_DRIVER_VERSION,
		sizeof(driver_info->driver_version));
	return 1;
}

static int nbl_res_get_p4_info(void *priv, char *verify_code)
{
	/* We actually only care about the snic-v3r1 part, won't check m181xx */
	strscpy(verify_code, "snic_v3r1_m181xx", NBL_P4_NAME_LEN);

	return NBL_P4_DEFAULT;
}

static int nbl_res_get_p4_used(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);

	return resource_info->p4_used;
}

static int nbl_res_set_p4_used(void *priv, int p4_type)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);

	resource_info->p4_used = p4_type;

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

	if (nbl_res_vf_is_active(priv, func_id))
		nbl_res_unregister_net(priv, func_id);
}

static int nbl_res_get_board_id(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	return NBL_COMMON_TO_BOARD_ID(common);
}

static struct nbl_resource_ops res_ops = {
	.register_net = nbl_res_register_net,
	.unregister_net = nbl_res_unregister_net,
	.check_active_vf = nbl_res_check_active_vf,
	.get_base_mac_addr = nbl_res_get_base_mac_addr,
	.get_vsi_id = nbl_res_get_vsi_id,
	.get_eth_id = nbl_res_get_eth_id,
	.get_user_queue_info = nbl_res_get_user_queue_info,
	.get_hw_addr = nbl_res_get_hw_addr,
	.get_real_hw_addr = nbl_res_get_real_hw_addr,
	.get_function_id = nbl_res_get_function_id,
	.get_real_bdf = nbl_res_get_real_bdf,
	.get_product_flex_cap = nbl_res_get_flex_capability,
	.get_product_fix_cap = nbl_res_get_fix_capability,
	.get_chip_temperature = nbl_res_get_chip_temperature,
	.get_chip_temperature_max = nbl_res_get_chip_temperature_max,
	.get_chip_temperature_crit = nbl_res_get_chip_temperature_crit,
	.get_driver_info = nbl_res_get_driver_info,
	.get_board_info = nbl_res_get_board_info,
	.flr_clear_net = nbl_res_flr_clear_net,

	.get_reg_dump = nbl_res_get_reg_dump,
	.get_reg_dump_len = nbl_res_get_reg_dump_len,
	.process_abnormal_event = nbl_res_process_abnormal_event,

	.get_p4_info = nbl_res_get_p4_info,
	.get_p4_used = nbl_res_get_p4_used,
	.set_p4_used = nbl_res_set_p4_used,
	.get_vf_base_vsi_id = nbl_res_get_vf_base_vsi_id,

	.get_board_id = nbl_res_get_board_id,
};

static struct nbl_res_product_ops product_ops = {
	.queue_mgt_init			= nbl_queue_mgt_init_leonis,
	.setup_qid_map_table		= nbl_res_queue_setup_qid_map_table_leonis,
	.remove_qid_map_table		= nbl_res_queue_remove_qid_map_table_leonis,
	.init_qid_map_table		= nbl_res_queue_init_qid_map_table,
};

static bool is_ops_inited;
static int nbl_res_setup_res_mgt(struct nbl_common_info *common,
				 struct nbl_resource_mgt_leonis **res_mgt_leonis)
{
	struct device *dev;
	struct nbl_resource_info *resource_info;

	dev = NBL_COMMON_TO_DEV(common);
	*res_mgt_leonis = devm_kzalloc(dev, sizeof(struct nbl_resource_mgt_leonis), GFP_KERNEL);
	if (!*res_mgt_leonis)
		return -ENOMEM;
	NBL_RES_MGT_TO_COMMON(&(*res_mgt_leonis)->res_mgt) = common;

	resource_info = devm_kzalloc(dev, sizeof(struct nbl_resource_info), GFP_KERNEL);
	if (!resource_info)
		return -ENOMEM;
	NBL_RES_MGT_TO_RES_INFO(&(*res_mgt_leonis)->res_mgt) = resource_info;

	return 0;
}

static void nbl_res_remove_res_mgt(struct nbl_common_info *common,
				   struct nbl_resource_mgt_leonis **res_mgt_leonis)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	devm_kfree(dev, NBL_RES_MGT_TO_RES_INFO(&(*res_mgt_leonis)->res_mgt));
	devm_kfree(dev, *res_mgt_leonis);
	*res_mgt_leonis = NULL;
}

static void nbl_res_remove_ops(struct device *dev, struct nbl_resource_ops_tbl **res_ops_tbl)
{
	devm_kfree(dev, *res_ops_tbl);
	*res_ops_tbl = NULL;
}

static int nbl_res_setup_ops(struct device *dev, struct nbl_resource_ops_tbl **res_ops_tbl,
			     struct nbl_resource_mgt_leonis *res_mgt_leonis)
{
	int ret = 0;

	*res_ops_tbl = devm_kzalloc(dev, sizeof(struct nbl_resource_ops_tbl), GFP_KERNEL);
	if (!*res_ops_tbl)
		return -ENOMEM;

	if (!is_ops_inited) {
		ret = nbl_flow_setup_ops_leonis(&res_ops);
		if (ret)
			goto setup_fail;

		ret = nbl_queue_setup_ops_leonis(&res_ops);
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

		is_ops_inited = true;
	}

	NBL_RES_OPS_TBL_TO_OPS(*res_ops_tbl) = &res_ops;
	NBL_RES_OPS_TBL_TO_PRIV(*res_ops_tbl) = res_mgt_leonis;

	return 0;

setup_fail:
	nbl_res_remove_ops(dev, res_ops_tbl);
	return -EAGAIN;
}

static int nbl_res_ctrl_dev_setup_eth_info(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_eth_info *eth_info;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u32 eth_num = 0;
	u32 eth_bitmap, eth_id;
	int i;

	eth_info = devm_kzalloc(dev, sizeof(struct nbl_eth_info), GFP_KERNEL);
	if (!eth_info)
		return -ENOMEM;

	NBL_RES_MGT_TO_ETH_INFO(res_mgt) = eth_info;

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

static int nbl_res_ctrl_dev_sriov_info_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct device *dev =  NBL_COMMON_TO_DEV(common);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_sriov_info *sriov_info;
	u32 vf_fid, vf_startid, vf_endid;
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

		sriov_info->bdf = PCI_DEVID(common->bus,
					    PCI_DEVFN(common->devid, function));
		vf_fid = phy_ops->get_host_pf_fid(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
							func_id);
		vf_startid = vf_fid & 0xFFFF;
		vf_endid = (vf_fid >> 16) & 0xFFFF;
		sriov_info->start_vf_func_id = vf_startid + NBL_MAX_PF_LEONIS;
		sriov_info->num_vfs = vf_endid - vf_startid;
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
	 * 1 two port(2pf)
	 * pf0,pf1(NBL_VSI_SERV_PF_DATA_TYPE) vsi is 0,512
	 * pf0,pf1(NBL_VSI_SERV_PF_CTLR_TYPE) vsi is 1,513
	 * pf0,pf1(NBL_VSI_SERV_PF_USER_TYPE) vsi is 2,514
	 * pf0.vf0-pf0.vf255(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 3-258
	 * pf1.vf0-pf1.vf255(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 515-770
	 * pf2-pf7(NBL_VSI_SERV_PF_EXTRA_TYPE) vsi 259-264(if exist)
	 * 2 four port(4pf)
	 * pf0,pf1,pf2,pf3(NBL_VSI_SERV_PF_DATA_TYPE) vsi is 0,256,512,768
	 * pf0,pf1,pf2,pf3(NBL_VSI_SERV_PF_CTLR_TYPE) vsi is 1,257,513,769
	 * pf0,pf1,pf2,pf3(NBL_VSI_SERV_PF_USER_TYPE) vsi is 2,258,514,770
	 * pf0.vf0-pf0.vf127(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 3-130
	 * pf1.vf0-pf1.vf127(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 259-386
	 * pf2.vf0-pf2.vf127(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 515-642
	 * pf3.vf0-pf3.vf127(NBL_VSI_SERV_VF_DATA_TYPE) vsi is 771-898
	 * pf4-pf7(NBL_VSI_SERV_PF_EXTRA_TYPE) vsi 387-390(if exist)
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
		vsi_info->serv_info[i][NBL_VSI_SERV_VF_DATA_TYPE].base_id =
		    vsi_info->serv_info[i][NBL_VSI_SERV_PF_USER_TYPE].base_id
		    + vsi_info->serv_info[i][NBL_VSI_SERV_PF_USER_TYPE].num;
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

static int nbl_res_check_fw_working(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	unsigned long fw_pong_current = 0;
	unsigned long seconds_current = 0;
	unsigned long sleep_us = USEC_PER_MSEC;
	u64 timeout_us = 100 * USEC_PER_MSEC;
	ktime_t timeout;

	seconds_current = (unsigned long)ktime_get_real_seconds();
	phy_ops->set_fw_pong(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), seconds_current - 1);
	phy_ops->set_fw_ping(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), seconds_current);

	timeout = ktime_add_us(ktime_get(), timeout_us);
	might_sleep_if((sleep_us) != 0);

	for (;;) {
		fw_pong_current = phy_ops->get_fw_pong(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
		if (fw_pong_current == seconds_current)
			break;
		if (timeout_us &&  ktime_compare(ktime_get(), timeout) > 0) {
			fw_pong_current = phy_ops->get_fw_pong(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
			break;
		}
		if (sleep_us)
			usleep_range((sleep_us >> 2) + 1, sleep_us);
	}

	if (fw_pong_current == seconds_current)
		return 0;
	else
		return -ETIMEDOUT;
}

static int nbl_res_init_pf_num(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u32 pf_mask;
	u32 pf_num = 0;
	int i;

	pf_mask = phy_ops->get_host_pf_mask(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	for (i = 0; i < NBL_MAX_PF_LEONIS; i++) {
		if (!(pf_mask & (1 << i)))
			pf_num++;
		else
			break;
	}

	NBL_RES_MGT_TO_PF_NUM(res_mgt) = pf_num;

	if (!pf_num)
		return -1;

	return 0;
}

static void nbl_res_init_board_info(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->get_board_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				&res_mgt->resource_info->board_info);
}

static void nbl_res_stop(struct nbl_resource_mgt_leonis *res_mgt_leonis)
{
	struct nbl_resource_mgt *res_mgt = &res_mgt_leonis->res_mgt;

	nbl_queue_mgt_stop(res_mgt);
	nbl_txrx_mgt_stop(res_mgt);
	nbl_intr_mgt_stop(res_mgt);
	nbl_adminq_mgt_stop(res_mgt);
	nbl_vsi_mgt_stop(res_mgt);
	nbl_flow_mgt_stop_leonis(res_mgt);
	nbl_res_ctrl_dev_remove_vsi_info(res_mgt);
	nbl_res_ctrl_dev_sriov_info_remove(res_mgt);
}

static int nbl_res_start(struct nbl_resource_mgt_leonis *res_mgt_leonis,
			 struct nbl_func_caps caps)
{
	struct nbl_resource_mgt *res_mgt = &res_mgt_leonis->res_mgt;
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

		ret = nbl_res_ctrl_dev_vsi_info_init(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_res_ring_num_info_init(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_flow_mgt_start_leonis(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_queue_mgt_start(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_vsi_mgt_start(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_adminq_mgt_start(res_mgt);
		if (ret)
			goto start_fail;

		ret = nbl_intr_mgt_start(res_mgt);
		if (ret)
			goto start_fail;

		nbl_res_set_flex_capability(res_mgt, NBL_SECURITY_ACCEL_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_DUMP_FLOW_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_FW_HB_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_FW_RESET_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_CLEAN_ADMINDQ_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_RESTOOL_CAP);
		nbl_res_set_fix_capability(res_mgt, NBL_TASK_ADAPT_DESC_GOTHER);
		nbl_res_set_fix_capability(res_mgt, NBL_PROCESS_FLR_CAP);
	}

	if (caps.has_net) {
		ret = nbl_txrx_mgt_start(res_mgt);
		if (ret)
			goto start_fail;
	}

	nbl_res_set_fix_capability(res_mgt, NBL_HWMON_TEMP_CAP);
	nbl_res_set_fix_capability(res_mgt, NBL_TASK_CLEAN_MAILBOX_CAP);
	nbl_res_set_fix_capability(res_mgt, NBL_ITR_DYNAMIC);
	nbl_res_set_fix_capability(res_mgt, NBL_P4_CAP);
	nbl_res_set_fix_capability(res_mgt, NBL_TASK_KEEP_ALIVE);

	return 0;

start_fail:
	nbl_res_stop(res_mgt_leonis);
	return ret;
}

int nbl_res_init_leonis(void *p, struct nbl_init_param *param)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_resource_mgt_leonis **res_mgt_leonis;
	struct nbl_resource_ops_tbl **res_ops_tbl;
	struct nbl_phy_ops_tbl *phy_ops_tbl;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	int ret = 0;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	res_mgt_leonis = (struct nbl_resource_mgt_leonis **)&NBL_ADAPTER_TO_RES_MGT(adapter);
	res_ops_tbl = &NBL_ADAPTER_TO_RES_OPS_TBL(adapter);
	phy_ops_tbl = NBL_ADAPTER_TO_PHY_OPS_TBL(adapter);
	chan_ops_tbl = NBL_ADAPTER_TO_CHAN_OPS_TBL(adapter);

	ret = nbl_res_setup_res_mgt(common, res_mgt_leonis);
	if (ret)
		goto setup_mgt_fail;

	nbl_res_setup_common_ops(&(*res_mgt_leonis)->res_mgt);
	NBL_RES_MGT_TO_CHAN_OPS_TBL(&(*res_mgt_leonis)->res_mgt) = chan_ops_tbl;
	NBL_RES_MGT_TO_PHY_OPS_TBL(&(*res_mgt_leonis)->res_mgt) = phy_ops_tbl;

	NBL_RES_MGT_TO_PROD_OPS(&(*res_mgt_leonis)->res_mgt) = &product_ops;

	ret = nbl_res_start(*res_mgt_leonis, param->caps);
	if (ret)
		goto start_fail;

	ret = nbl_res_setup_ops(dev, res_ops_tbl, *res_mgt_leonis);
	if (ret)
		goto setup_ops_fail;

	return 0;

setup_ops_fail:
	nbl_res_stop(*res_mgt_leonis);
start_fail:
	nbl_res_remove_res_mgt(common, res_mgt_leonis);
setup_mgt_fail:
	return ret;
}

void nbl_res_remove_leonis(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_resource_mgt_leonis **res_mgt;
	struct nbl_resource_ops_tbl **res_ops_tbl;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	res_mgt = (struct nbl_resource_mgt_leonis **)&NBL_ADAPTER_TO_RES_MGT(adapter);
	res_ops_tbl = &NBL_ADAPTER_TO_RES_OPS_TBL(adapter);

	nbl_res_remove_ops(dev, res_ops_tbl);
	nbl_res_stop(*res_mgt);
	nbl_res_remove_res_mgt(common, res_mgt);
}
