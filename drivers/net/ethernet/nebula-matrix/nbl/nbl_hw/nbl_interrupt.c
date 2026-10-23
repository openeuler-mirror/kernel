// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_interrupt.h"
#include "nbl_hw_draco/nbl_resource_draco.h"
#include "nbl_hw_leonis/nbl_resource_leonis.h"
static int nbl_res_intr_destroy_msix_map(void *priv, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct device *dev, *dma_dev;
	struct nbl_phy_ops *phy_ops;
	struct nbl_interrupt_mgt *intr_mgt;
	struct nbl_msix_map_table *msix_map_table;
	u16 *interrupts;
	u16 intr_num;
	u16 i;
	int ret = 0;

	if (!res_mgt)
		return -EINVAL;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);
	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	dma_dev = NBL_RES_MGT_TO_DMA_DEV(res_mgt);

	/* use ctrl dev bdf */
	phy_ops->configure_msix_map(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), func_id, false,
				    0, 0, 0, 0);

	intr_num = intr_mgt->func_intr_res[func_id].num_interrupts;
	interrupts = intr_mgt->func_intr_res[func_id].interrupts;

	if (!intr_num)
		return 0;

	for (i = 0; i < intr_num; i++) {
		if (interrupts[i] >= (NBL_INTR_MGT_TO_MAX_OTHER_INTERRUPT(intr_mgt) +
				      NBL_INTR_MGT_TO_MSIX_TABLE_RANGE_OFT(intr_mgt)))
			clear_bit((interrupts[i] - NBL_INTR_MGT_TO_MAX_OTHER_INTERRUPT(intr_mgt) -
				   NBL_INTR_MGT_TO_MSIX_TABLE_RANGE_OFT(intr_mgt)) / 2,
				  intr_mgt->interrupt_net_bitmap);
		else
			clear_bit((interrupts[i] -
				   NBL_INTR_MGT_TO_MSIX_TABLE_RANGE_OFT(intr_mgt)) / 2,
				  intr_mgt->interrupt_others_bitmap);

		phy_ops->configure_msix_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), func_id, false,
					     interrupts[i], 0, 0, 0, false);
	}

	kfree(interrupts);
	intr_mgt->func_intr_res[func_id].interrupts = NULL;
	intr_mgt->func_intr_res[func_id].num_interrupts = 0;

	msix_map_table = &intr_mgt->func_intr_res[func_id].msix_map_table;
	dma_free_coherent(dma_dev, msix_map_table->size, msix_map_table->base_addr,
			  msix_map_table->dma);
	msix_map_table->size = 0;
	msix_map_table->base_addr = NULL;
	msix_map_table->dma = 0;

	return ret;
}

static int nbl_res_intr_configure_msix_map(void *priv, struct nbl_ch_prm_cfg_msix_map *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct device *dev, *dma_dev;
	struct nbl_phy_ops *phy_ops;
	struct nbl_interrupt_mgt *intr_mgt;
	struct nbl_common_info *common;
	struct nbl_msix_map_table *msix_map_table;
	struct nbl_msix_map *msix_map_entries;
	u16 *interrupts;
	u16 requested;
	u16 intr_index;
	u16 i;
	u8 bus, devid, function;
	bool msix_mask_en;
	int ret = 0;

	if (!res_mgt)
		return -EINVAL;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);
	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	dma_dev = NBL_RES_MGT_TO_DMA_DEV(res_mgt);
	common = NBL_RES_MGT_TO_COMMON(res_mgt);

	dev_info(dev, "func_id:%d, num_net_msix:%d, num_others_msix:%d\n",
		 param->sfid, param->num_net_msix, param->num_others_msix);

	if (intr_mgt->func_intr_res[param->sfid].interrupts)
		nbl_res_intr_destroy_msix_map(priv, param->sfid);

	nbl_res_func_id_to_bdf(res_mgt, param->sfid, &bus, &devid, &function);

	msix_map_table = &intr_mgt->func_intr_res[param->sfid].msix_map_table;
	WARN_ON(msix_map_table->base_addr);
	msix_map_table->size = sizeof(struct nbl_msix_map) *
			       NBL_INTR_MGT_TO_MSIX_MAP_TABLE_MAX_ENTRIES(intr_mgt);
	msix_map_table->base_addr = dma_alloc_coherent(dma_dev, msix_map_table->size,
						       &msix_map_table->dma,
						       GFP_ATOMIC | __GFP_ZERO);
	if (!msix_map_table->base_addr) {
		pr_err("Allocate DMA memory for function msix map table failed\n");
		msix_map_table->size = 0;
		return -ENOMEM;
	}

	requested = param->num_net_msix + param->num_others_msix;
	interrupts = kcalloc(requested, sizeof(interrupts[0]), GFP_ATOMIC);
	if (!interrupts) {
		pr_err("Allocate function interrupts array failed\n");
		ret = -ENOMEM;
		goto alloc_interrupts_err;
	}

	intr_mgt->func_intr_res[param->sfid].interrupts = interrupts;
	intr_mgt->func_intr_res[param->sfid].num_interrupts = requested;
	intr_mgt->func_intr_res[param->sfid].num_net_interrupts = param->num_net_msix;

	for (i = 0; i < param->num_net_msix; i += 2) {
		intr_index = find_first_zero_bit(intr_mgt->interrupt_net_bitmap,
						 NBL_INTR_MGT_TO_MAX_NET_INTERRUPT(intr_mgt) / 2);
		if (intr_index == NBL_INTR_MGT_TO_MAX_NET_INTERRUPT(intr_mgt) / 2)
			break;
		interrupts[i] = (intr_index * 2) + NBL_INTR_MGT_TO_MAX_OTHER_INTERRUPT(intr_mgt) +
				NBL_INTR_MGT_TO_MSIX_TABLE_RANGE_OFT(intr_mgt);
		if (i < param->num_net_msix - 1)
			interrupts[i + 1] = (intr_index * 2 + 1) +
					    NBL_INTR_MGT_TO_MAX_OTHER_INTERRUPT(intr_mgt) +
					    NBL_INTR_MGT_TO_MSIX_TABLE_RANGE_OFT(intr_mgt);
		set_bit(intr_index, intr_mgt->interrupt_net_bitmap);
	}

	i = min_t(u16, param->num_net_msix, i);
	for (; i < requested; i += 2) {
		intr_index = find_first_zero_bit(intr_mgt->interrupt_others_bitmap,
						 NBL_INTR_MGT_TO_MAX_OTHER_INTERRUPT(intr_mgt) / 2);
		if (intr_index == NBL_INTR_MGT_TO_MAX_OTHER_INTERRUPT(intr_mgt) / 2) {
			pr_err("There is no available other interrupt left\n");
			ret = -EAGAIN;
			goto get_interrupt_err;
		}
		interrupts[i] = intr_index * 2 + NBL_INTR_MGT_TO_MSIX_TABLE_RANGE_OFT(intr_mgt);
		if (i < requested - 1)
			interrupts[i + 1] = (intr_index * 2 + 1) +
					    NBL_INTR_MGT_TO_MSIX_TABLE_RANGE_OFT(intr_mgt);
		set_bit(intr_index, intr_mgt->interrupt_others_bitmap);
	}

	msix_map_entries = msix_map_table->base_addr;
	for (i = 0; i < requested; i++) {
		msix_map_entries[i].global_msix_index = interrupts[i];
		msix_map_entries[i].valid = 1;

		if (i < param->num_net_msix && param->net_msix_mask_en)
			msix_mask_en = 1;
		else
			msix_mask_en = 0;
		phy_ops->configure_msix_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->sfid, true,
					     interrupts[i], bus, devid, function, msix_mask_en);
		if (i < param->num_net_msix)
			phy_ops->set_coalesce(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					      interrupts[i], 0, 0);
	}

	/* get ctrl dev's bdf */
	nbl_res_func_id_to_bdf(res_mgt, NBL_COMMON_TO_MGT_PF(common), &bus, &devid, &function);
	/* use ctrl dev bdf */
	phy_ops->configure_msix_map(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->sfid, true,
				    msix_map_table->dma, bus, devid, function);

	return 0;

get_interrupt_err:
	while (i--) {
		intr_index = interrupts[i];
		if (intr_index >= (NBL_INTR_MGT_TO_MAX_OTHER_INTERRUPT(intr_mgt) +
				   NBL_INTR_MGT_TO_MSIX_TABLE_RANGE_OFT(intr_mgt)))
			clear_bit((intr_index - NBL_INTR_MGT_TO_MAX_OTHER_INTERRUPT(intr_mgt) -
				   NBL_INTR_MGT_TO_MSIX_TABLE_RANGE_OFT(intr_mgt)) / 2,
				  intr_mgt->interrupt_net_bitmap);
		else
			clear_bit((intr_index - NBL_INTR_MGT_TO_MSIX_TABLE_RANGE_OFT(intr_mgt)) / 2,
				  intr_mgt->interrupt_others_bitmap);
	}
	kfree(interrupts);
	intr_mgt->func_intr_res[param->sfid].num_interrupts = 0;
	intr_mgt->func_intr_res[param->sfid].interrupts = NULL;

alloc_interrupts_err:
	dma_free_coherent(dma_dev, msix_map_table->size, msix_map_table->base_addr,
			  msix_map_table->dma);
	msix_map_table->size = 0;
	msix_map_table->base_addr = NULL;
	msix_map_table->dma = 0;

	return ret;
}

static int nbl_res_init_vf_msix_map(void *priv, struct nbl_ch_prm_init_vf_msix_map *param)
{
#define NBL_VF_NET_MSIX_NUM (4)
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 net_msix_num = NBL_VF_NET_MSIX_NUM;
	u16 tx_queue_num = 0;
	u16 rx_queue_num = 0;
	struct nbl_ch_prm_cfg_msix_map msix_map;

	if (param->enable) {
		if (res_mgt->common_ops.get_queue_num) {
			res_mgt->common_ops.get_queue_num(priv, param->sfid,
							  &tx_queue_num, &rx_queue_num);
			net_msix_num = tx_queue_num + rx_queue_num;
		}

		msix_map.sfid = param->sfid;
		msix_map.num_net_msix = net_msix_num;
		msix_map.num_others_msix = 1;
		msix_map.net_msix_mask_en = true;
		return nbl_res_intr_configure_msix_map(priv, &msix_map);
	}

	nbl_res_intr_destroy_msix_map(priv, param->sfid);

	return 0;
}

static int nbl_res_intr_destroy_msix_map_export(void *priv, u16 *func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	int ret = 0;
	struct nbl_ch_prm_init_vf_msix_map msix_map;

	ret = nbl_res_intr_destroy_msix_map(priv, *func_id);

	if (*func_id >= NBL_RES_MGT_TO_PF_NUM(res_mgt)) {
		msix_map.sfid = *func_id;
		msix_map.enable = true;
		ret |= nbl_res_init_vf_msix_map(priv, &msix_map);
	}

	return ret;
}

static int nbl_res_intr_enable_mailbox_irq(void *priv, struct nbl_ch_prm_enable_irq *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;
	struct nbl_interrupt_mgt *intr_mgt;
	u16 global_vector_id;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);

	global_vector_id = intr_mgt->func_intr_res[param->sfid].interrupts[param->vector_id];
	phy_ops->enable_mailbox_irq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->sfid,
				    param->enable_msix, global_vector_id);

	return 0;
}

static int nbl_res_intr_enable_abnormal_irq(void *priv, struct nbl_ch_prm_enable_irq *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;
	struct nbl_interrupt_mgt *intr_mgt;
	u16 global_vector_id;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);

	global_vector_id = intr_mgt->func_intr_res[param->sfid].interrupts[param->vector_id];
	phy_ops->enable_abnormal_irq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->enable_msix,
				     global_vector_id);
	return 0;
}

static u8 *nbl_res_get_msix_irq_enable_info(void *priv, u16 global_vector_id,
					    u32 *irq_data, u32 *irq_mask_data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->get_msix_irq_enable_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_vector_id,
						 irq_data, irq_mask_data);
}

static u16 nbl_res_intr_get_global_vector(void *priv, struct nbl_ch_prm_get_global_vec *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_interrupt_mgt *intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, param->vsi_id);

	return intr_mgt->func_intr_res[func_id].interrupts[param->vector_id];
}

static int nbl_res_intr_get_coalesce(void *priv,
				     struct nbl_ch_prm_get_coalesce_req *param,
				     struct nbl_ch_prm_get_coalesce *ec)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_interrupt_mgt *intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);
	u16 global_vector_id;
	u16 pnum = 0;
	u16 rate = 0;

	global_vector_id = intr_mgt->func_intr_res[param->sfid].interrupts[param->vector_id];
	phy_ops->get_coalesce(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_vector_id, &pnum, &rate);
	/* tx and rx using the same interrupt */
	NBL_SET_INTR_COALESCE(ec, rate, pnum, rate, pnum);
	return 0;
}

static int nbl_res_set_msix_fast_restrain(void *priv,
					  struct nbl_set_msix_fast_restrain_param *prm)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->set_msix_fast_restrain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					prm->global_vector_id, prm->pnum, prm->rate);
	return 0;
}

static int nbl_res_intr_set_coalesce(void *priv, struct nbl_ch_prm_set_coalesce *prm)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_interrupt_mgt *intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);
	u16 global_vector_id;
	u16 vector_base = prm->local_vector_id;
	int i;

	for (i = 0; i < prm->vector_num; i++) {
		global_vector_id = intr_mgt->func_intr_res[prm->sfid].interrupts[vector_base + i];
		phy_ops->set_coalesce(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_vector_id,
				      prm->rx_max_coalesced_frames,
				      prm->rx_coalesce_usecs);
	}
	return 0;
}

static int nbl_res_intr_enable_adminq_irq(void *priv, struct nbl_ch_prm_enable_irq *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;
	struct nbl_interrupt_mgt *intr_mgt;
	u16 global_vector_id;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);

	global_vector_id = intr_mgt->func_intr_res[0].interrupts[param->vector_id];
	phy_ops->enable_adminq_irq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->enable_msix,
				   global_vector_id);
	return 0;
}

static int nbl_res_intr_get_mbx_irq_num(void *priv)
{
	return 1;
}

static int nbl_res_intr_get_adminq_irq_num(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);

	if (chan_ops->check_queue_exist(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt),
					NBL_CHAN_TYPE_ADMINQ))
		return 1;
	else
		return 0;
}

u16 nbl_res_intr_get_suppress_level(void *priv,
				    struct nbl_get_intr_suppress_level_param *prm)
{
	switch (prm->last_level) {
	case NBL_INTR_SUPPRESS_LEVEL0:
		if (prm->rate > NBL_INTR_SUPPRESS_LEVEL1_THRESHOLD)
			return NBL_INTR_SUPPRESS_LEVEL1;
		else
			return NBL_INTR_SUPPRESS_LEVEL0;
	case NBL_INTR_SUPPRESS_LEVEL1:
		if (prm->rate > NBL_INTR_SUPPRESS_LEVEL2_THRESHOLD)
			return NBL_INTR_SUPPRESS_LEVEL2;
		else if (prm->rate > NBL_INTR_SUPPRESS_LEVEL1_DOWNGRADE_THRESHOLD)
			return NBL_INTR_SUPPRESS_LEVEL1;
		else
			return NBL_INTR_SUPPRESS_LEVEL0;
	case NBL_INTR_SUPPRESS_LEVEL2:
		if (prm->rate > NBL_INTR_SUPPRESS_LEVEL2_DOWNGRADE_THRESHOLD)
			return NBL_INTR_SUPPRESS_LEVEL2;
		else
			return NBL_INTR_SUPPRESS_LEVEL1;
	default:
		return NBL_INTR_SUPPRESS_LEVEL0;
	}
}

int nbl_res_intr_set_intr_suppress_level(void *priv,
					 struct nbl_ch_prm_set_intr_suppress_level *prm)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_interrupt_mgt *intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);
	u16 global_vector_id;
	u16 vector_base = prm->local_vector_id;
	u16 vector_num = prm->vector_num;
	u16 pnum, rate;
	int i;

	switch (prm->level) {
	case NBL_INTR_SUPPRESS_LEVEL1:
		if (res_mgt->resource_info->board_info.eth_speed == NBL_FW_PORT_SPEED_100G) {
			pnum = NBL_INTR_SUPPRESS_LEVEL1_100G_PNUM;
			rate = NBL_INTR_SUPPRESS_LEVEL1_100G_RATE;
		} else {
			pnum = NBL_INTR_SUPPRESS_LEVEL1_25G_PNUM;
			rate = NBL_INTR_SUPPRESS_LEVEL1_25G_RATE;
		}
		break;
	case NBL_INTR_SUPPRESS_LEVEL2:
		if (res_mgt->resource_info->board_info.eth_speed == NBL_FW_PORT_SPEED_100G) {
			pnum = NBL_INTR_SUPPRESS_LEVEL2_100G_PNUM;
			rate = NBL_INTR_SUPPRESS_LEVEL2_100G_RATE;
		} else {
			pnum = NBL_INTR_SUPPRESS_LEVEL1_25G_PNUM;
			rate = NBL_INTR_SUPPRESS_LEVEL1_25G_RATE;
		}
		break;
	default:
		pnum = NBL_INTR_SUPPRESS_LEVEL0_PNUM;
		rate = NBL_INTR_SUPPRESS_LEVEL0_RATE;
		break;
	}

	if (vector_num == U16_MAX)
		vector_num = intr_mgt->func_intr_res[prm->sfid].num_net_interrupts;

	for (i = 0; i < vector_num; i++) {
		global_vector_id = intr_mgt->func_intr_res[prm->sfid].interrupts[vector_base + i];
		phy_ops->set_coalesce(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				      global_vector_id, pnum, rate);
	}
	return 0;
}

static void nbl_res_flr_clear_interrupt(void *priv, u16 vf_id)
{
}

static int nbl_res_set_suppress_level_fast(void *priv,
					   struct nbl_set_intr_suppress_level_fast_param *prm)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 pnum, rate;

	switch (prm->level) {
	case NBL_INTR_SUPPRESS_LEVEL1:
	case NBL_INTR_SUPPRESS_LEVEL2:
		pnum = NBL_INTR_SUPPRESS_LEVEL1_DRACO_25G_PNUM;
		rate = NBL_INTR_SUPPRESS_LEVEL1_DRACO_25G_RATE;
		break;
	default:
		pnum = NBL_INTR_SUPPRESS_LEVEL0_PNUM;
		rate = NBL_INTR_SUPPRESS_LEVEL0_RATE;
		break;
	}

	phy_ops->set_msix_fast_restrain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					prm->global_vector_id, pnum, rate);
	return 0;
}

static void nbl_res_dump_abnormal_intr(void *priv, struct seq_file *m)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->dump_abnormal_intr(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), m);
}

/* NBL_INTR_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_INTR_OPS_TBL								\
do {											\
	NBL_INTR_SET_OPS(init_vf_msix_map, nbl_res_init_vf_msix_map);			\
	NBL_INTR_SET_OPS(configure_msix_map, nbl_res_intr_configure_msix_map);		\
	NBL_INTR_SET_OPS(destroy_msix_map, nbl_res_intr_destroy_msix_map_export);	\
	NBL_INTR_SET_OPS(enable_mailbox_irq, nbl_res_intr_enable_mailbox_irq);		\
	NBL_INTR_SET_OPS(enable_abnormal_irq, nbl_res_intr_enable_abnormal_irq);	\
	NBL_INTR_SET_OPS(enable_adminq_irq, nbl_res_intr_enable_adminq_irq);		\
	NBL_INTR_SET_OPS(get_msix_irq_enable_info, nbl_res_get_msix_irq_enable_info);	\
	NBL_INTR_SET_OPS(get_global_vector, nbl_res_intr_get_global_vector);		\
	NBL_INTR_SET_OPS(get_coalesce, nbl_res_intr_get_coalesce);			\
	NBL_INTR_SET_OPS(set_coalesce, nbl_res_intr_set_coalesce);			\
	NBL_INTR_SET_OPS(set_msix_fast_restrain, nbl_res_set_msix_fast_restrain);	\
	NBL_INTR_SET_OPS(get_mbx_irq_num, nbl_res_intr_get_mbx_irq_num);		\
	NBL_INTR_SET_OPS(get_adminq_irq_num, nbl_res_intr_get_adminq_irq_num);		\
	NBL_INTR_SET_OPS(get_abnormal_irq_num, nbl_res_intr_get_abnormal_irq_num);	\
	NBL_INTR_SET_OPS(get_intr_suppress_level, nbl_res_intr_get_suppress_level);	\
	NBL_INTR_SET_OPS(set_intr_suppress_level, nbl_res_intr_set_intr_suppress_level);\
	NBL_INTR_SET_OPS(set_intr_suppress_level_fast, nbl_res_set_suppress_level_fast);\
	NBL_INTR_SET_OPS(flr_clear_interrupt, nbl_res_flr_clear_interrupt);		\
	NBL_INTR_SET_OPS(dump_abnormal_intr, nbl_res_dump_abnormal_intr);			\
} while (0)

/* Structure starts here, adding an op should not modify anything below */
static int nbl_intr_setup_mgt(struct device *dev, struct nbl_interrupt_mgt **intr_mgt)
{
	*intr_mgt = devm_kzalloc(dev, sizeof(struct nbl_interrupt_mgt), GFP_KERNEL);
	if (!*intr_mgt)
		return -ENOMEM;

	return 0;
}

static void nbl_intr_remove_mgt(struct device *dev, struct nbl_interrupt_mgt **intr_mgt)
{
	devm_kfree(dev, *intr_mgt);
	*intr_mgt = NULL;
}

void nbl_intr_mgt_init_draco(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_interrupt_mgt *intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	u32 range_oft, range_size;

	phy_ops->get_table_range(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				 NBL_COMMON_TO_MGT_PF(common), NBL_ADDR_MSIX,
				 NBL_RES_MGT_TO_PF_NUM(res_mgt), &range_oft, &range_size);

	intr_mgt->msix_map_table_max_entries = NBL_MSIX_MAP_TABLE_MAX_ENTRIES_DRACO;
	intr_mgt->msix_table_range_oft = range_oft;
	intr_mgt->max_other_interrupt = range_size;
	intr_mgt->max_net_interrupt = 0;

	dev_info(dev, "msix, range_oft:%d, range_size:%d, msix_map_table_max_entries:%d, msix_table_range_oft:%d, max_other_interrupt:%d, max_net_interrupt:%d\n",
		 range_oft, range_size,
		 intr_mgt->msix_map_table_max_entries, intr_mgt->msix_table_range_oft,
		 intr_mgt->max_other_interrupt, intr_mgt->max_net_interrupt);
}

void nbl_intr_mgt_init_leonis(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_interrupt_mgt *intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);

	intr_mgt->msix_map_table_max_entries = NBL_MSIX_MAP_TABLE_MAX_ENTRIES_LEONIS;
	intr_mgt->msix_table_range_oft = 0;
	intr_mgt->max_other_interrupt = NBL_MAX_OTHER_INTERRUPT_LEONIS;
	intr_mgt->max_net_interrupt = NBL_MAX_NET_INTERRUPT_LEONIS;
}

int nbl_intr_mgt_start(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_interrupt_mgt **intr_mgt;
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);
	int ret = 0;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	intr_mgt = &NBL_RES_MGT_TO_INTR_MGT(res_mgt);

	ret = nbl_intr_setup_mgt(dev, intr_mgt);
	if (ret)
		return ret;

	NBL_OPS_CALL(product_ops->intr_mgt_init, (res_mgt));

	return 0;
}

void nbl_intr_mgt_stop(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_interrupt_mgt **intr_mgt;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	intr_mgt = &NBL_RES_MGT_TO_INTR_MGT(res_mgt);

	if (!(*intr_mgt))
		return;

	nbl_intr_remove_mgt(dev, intr_mgt);
}

int nbl_intr_setup_ops(struct nbl_resource_ops *res_ops)
{
#define NBL_INTR_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_INTR_OPS_TBL;
#undef  NBL_INTR_SET_OPS

	return 0;
}

void nbl_intr_remove_ops(struct nbl_resource_ops *res_ops)
{
#define NBL_INTR_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = NULL; ; } while (0)
	NBL_INTR_OPS_TBL;
#undef  NBL_INTR_SET_OPS
}
