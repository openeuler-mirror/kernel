// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_interrupt.h"

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

	WARN_ON(!interrupts);
	for (i = 0; i < intr_num; i++) {
		if (interrupts[i] >= NBL_MAX_OTHER_INTERRUPT)
			clear_bit(interrupts[i] - NBL_MAX_OTHER_INTERRUPT,
				  intr_mgt->interrupt_net_bitmap);
		else
			clear_bit(interrupts[i], intr_mgt->interrupt_others_bitmap);

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

static int nbl_res_intr_configure_msix_map(void *priv, u16 func_id, u16 num_net_msix,
					   u16 num_others_msix, bool net_msix_mask_en)
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

	if (intr_mgt->func_intr_res[func_id].interrupts)
		nbl_res_intr_destroy_msix_map(priv, func_id);

	nbl_res_func_id_to_bdf(res_mgt, func_id, &bus, &devid, &function);

	msix_map_table = &intr_mgt->func_intr_res[func_id].msix_map_table;
	WARN_ON(msix_map_table->base_addr);
	msix_map_table->size = sizeof(struct nbl_msix_map) * NBL_MSIX_MAP_TABLE_MAX_ENTRIES;
	msix_map_table->base_addr = dma_alloc_coherent(dma_dev, msix_map_table->size,
						       &msix_map_table->dma,
						       GFP_ATOMIC | __GFP_ZERO);
	if (!msix_map_table->base_addr) {
		pr_err("Allocate DMA memory for function msix map table failed\n");
		msix_map_table->size = 0;
		return -ENOMEM;
	}

	requested = num_net_msix + num_others_msix;
	interrupts = kcalloc(requested, sizeof(interrupts[0]), GFP_ATOMIC);
	if (!interrupts) {
		pr_err("Allocate function interrupts array failed\n");
		ret = -ENOMEM;
		goto alloc_interrupts_err;
	}

	intr_mgt->func_intr_res[func_id].interrupts = interrupts;
	intr_mgt->func_intr_res[func_id].num_interrupts = requested;

	for (i = 0; i < num_net_msix; i++) {
		intr_index = find_first_zero_bit(intr_mgt->interrupt_net_bitmap,
						 NBL_MAX_NET_INTERRUPT);
		if (intr_index == NBL_MAX_NET_INTERRUPT) {
			pr_err("There is no available interrupt left\n");
			ret = -EAGAIN;
			goto get_interrupt_err;
		}
		interrupts[i] = intr_index + NBL_MAX_OTHER_INTERRUPT;
		set_bit(intr_index, intr_mgt->interrupt_net_bitmap);
	}

	for (i = num_net_msix; i < requested; i++) {
		intr_index = find_first_zero_bit(intr_mgt->interrupt_others_bitmap,
						 NBL_MAX_OTHER_INTERRUPT);
		if (intr_index == NBL_MAX_OTHER_INTERRUPT) {
			pr_err("There is no available interrupt left\n");
			ret = -EAGAIN;
			goto get_interrupt_err;
		}
		interrupts[i] = intr_index;
		set_bit(intr_index, intr_mgt->interrupt_others_bitmap);
	}

	msix_map_entries = msix_map_table->base_addr;
	for (i = 0; i < requested; i++) {
		msix_map_entries[i].global_msix_index = interrupts[i];
		msix_map_entries[i].valid = 1;

		if (i < num_net_msix && net_msix_mask_en)
			msix_mask_en = 1;
		else
			msix_mask_en = 0;
		phy_ops->configure_msix_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), func_id, true,
					     interrupts[i], bus, devid, function, msix_mask_en);
		if (i < num_net_msix)
			phy_ops->set_coalesce(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					      interrupts[i], 0, 0);
	}

	/* use ctrl dev bdf */
	phy_ops->configure_msix_map(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), func_id, true,
				    msix_map_table->dma, common->bus, common->devid,
				    NBL_COMMON_TO_PCI_FUNC_ID(common));

	return 0;

get_interrupt_err:
	while (i--) {
		intr_index = interrupts[i];
		if (intr_index >= NBL_MAX_OTHER_INTERRUPT)
			clear_bit(intr_index - NBL_MAX_OTHER_INTERRUPT,
				  intr_mgt->interrupt_net_bitmap);
		else
			clear_bit(intr_index, intr_mgt->interrupt_others_bitmap);
	}
	kfree(interrupts);
	intr_mgt->func_intr_res[func_id].num_interrupts = 0;
	intr_mgt->func_intr_res[func_id].interrupts = NULL;

alloc_interrupts_err:
	dma_free_coherent(dma_dev, msix_map_table->size, msix_map_table->base_addr,
			  msix_map_table->dma);
	msix_map_table->size = 0;
	msix_map_table->base_addr = NULL;
	msix_map_table->dma = 0;

	return ret;
}

static int nbl_res_intr_enable_mailbox_irq(void *priv, u16 func_id, u16 vector_id, bool enable_msix)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;
	struct nbl_interrupt_mgt *intr_mgt;
	u16 global_vector_id;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);

	global_vector_id = intr_mgt->func_intr_res[func_id].interrupts[vector_id];
	phy_ops->enable_mailbox_irq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), func_id, enable_msix,
				    global_vector_id);

	return 0;
}

static int nbl_res_intr_enable_abnormal_irq(void *priv, u16 vector_id, bool enable_msix)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;
	struct nbl_interrupt_mgt *intr_mgt;
	u16 global_vector_id;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);

	global_vector_id = intr_mgt->func_intr_res[0].interrupts[vector_id];
	phy_ops->enable_abnormal_irq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), enable_msix,
				     global_vector_id);
	return 0;
}

static int nbl_res_intr_enable_msix_irq(void *priv, u16 global_vector_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->enable_msix_irq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_vector_id);
	return 0;
}

static u8 *nbl_res_get_msix_irq_enable_info(void *priv, u16 global_vector_id, u32 *irq_data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->get_msix_irq_enable_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_vector_id,
						 irq_data);
}

static u16 nbl_res_intr_get_global_vector(void *priv, u16 vsi_id, u16 local_vector_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_interrupt_mgt *intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);

	return intr_mgt->func_intr_res[func_id].interrupts[local_vector_id];
}

static u16 nbl_res_intr_get_msix_entry_id(void *priv, u16 vsi_id, u16 local_vector_id)
{
	return local_vector_id;
}

static void nbl_res_intr_get_coalesce(void *priv, u16 func_id, u16 vector_id,
				      struct ethtool_coalesce *ec)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_interrupt_mgt *intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);
	u16 global_vector_id;
	u16 pnum = 0;
	u16 rate = 0;

	global_vector_id = intr_mgt->func_intr_res[func_id].interrupts[vector_id];
	phy_ops->get_coalesce(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_vector_id, &pnum, &rate);
	/* tx and rx using the same interrupt */
	ec->tx_coalesce_usecs = rate;
	ec->tx_max_coalesced_frames = pnum;
	ec->rx_coalesce_usecs = rate;
	ec->rx_max_coalesced_frames = pnum;
}

static void nbl_res_intr_set_coalesce(void *priv, u16 func_id, u16 vector_id,
				      u16 num_net_msix, u16 pnum, u16 rate)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_interrupt_mgt *intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);
	u16 global_vector_id;
	int i;

	for (i = 0; i < num_net_msix; i++) {
		global_vector_id = intr_mgt->func_intr_res[func_id].interrupts[vector_id + i];
		phy_ops->set_coalesce(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				      global_vector_id, pnum, rate);
	}
}

static int nbl_res_intr_enable_adminq_irq(void *priv, u16 vector_id, bool enable_msix)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;
	struct nbl_interrupt_mgt *intr_mgt;
	u16 global_vector_id;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);

	global_vector_id = intr_mgt->func_intr_res[0].interrupts[vector_id];
	phy_ops->enable_adminq_irq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), enable_msix,
				     global_vector_id);
	return 0;
}

static int nbl_res_intr_get_mbx_irq_num(void *priv)
{
	return 1;
}

static int nbl_res_intr_get_adminq_irq_num(void *priv)
{
	return 1;
}

static int nbl_res_intr_get_abnormal_irq_num(void *priv)
{
	return 1;
}

static u16 nbl_res_intr_get_suppress_level(void *priv, u64 rates, u16 last_level)
{
	switch (last_level) {
	case NBL_INTR_SUPPRESS_LEVEL0:
		if (rates > NBL_INTR_SUPPRESS_LEVEL1_THRESHOLD)
			return NBL_INTR_SUPPRESS_LEVEL1;
		else
			return NBL_INTR_SUPPRESS_LEVEL0;
	case NBL_INTR_SUPPRESS_LEVEL1:
		if (rates > NBL_INTR_SUPPRESS_LEVEL1_DOWNGRADE_THRESHOLD)
			return NBL_INTR_SUPPRESS_LEVEL1;
		else
			return NBL_INTR_SUPPRESS_LEVEL0;
	default:
		return NBL_INTR_SUPPRESS_LEVEL0;
	}
}

static void nbl_res_intr_set_intr_suppress_level(void *priv, u16 func_id, u16 vector_id,
						 u16 num_net_msix, u16 level)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_interrupt_mgt *intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);
	u16 global_vector_id;
	u16 pnum, rate;
	int i;

	switch (level) {
	case NBL_INTR_SUPPRESS_LEVEL1:
		if (res_mgt->resource_info->board_info.eth_speed == NBL_FW_PORT_SPEED_100G) {
			pnum = NBL_INTR_SUPPRESS_LEVEL1_100G_PNUM;
			rate = NBL_INTR_SUPPRESS_LEVEL1_100G_RATE;
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
	for (i = 0; i < num_net_msix; i++) {
		global_vector_id = intr_mgt->func_intr_res[func_id].interrupts[vector_id + i];
		phy_ops->set_coalesce(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				      global_vector_id, pnum, rate);
	}
}

static void nbl_res_flr_clear_interrupt(void *priv, u16 vf_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 func_id = vf_id + NBL_MAX_PF;
	struct nbl_interrupt_mgt *intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);

	if (intr_mgt->func_intr_res[func_id].interrupts)
		nbl_res_intr_destroy_msix_map(priv, func_id);
}

static void nbl_res_intr_unmask(struct nbl_resource_mgt *res_mgt, u16 interrupts_id)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->enable_msix_irq(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), interrupts_id);
}

static void nbl_res_unmask_all_interrupts(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_interrupt_mgt *intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);
	int i, j;

	for (i = 0; i < NBL_MAX_PF; i++) {
		if (intr_mgt->func_intr_res[i].interrupts) {
			for (j = 0; j < intr_mgt->func_intr_res[i].num_interrupts; j++)
				nbl_res_intr_unmask(res_mgt,
						    intr_mgt->func_intr_res[i].interrupts[j]);
		}
	}
}

/* NBL_INTR_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_INTR_OPS_TBL								\
do {											\
	NBL_INTR_SET_OPS(configure_msix_map, nbl_res_intr_configure_msix_map);		\
	NBL_INTR_SET_OPS(destroy_msix_map, nbl_res_intr_destroy_msix_map);		\
	NBL_INTR_SET_OPS(enable_mailbox_irq, nbl_res_intr_enable_mailbox_irq);		\
	NBL_INTR_SET_OPS(enable_abnormal_irq, nbl_res_intr_enable_abnormal_irq);	\
	NBL_INTR_SET_OPS(enable_adminq_irq, nbl_res_intr_enable_adminq_irq);		\
	NBL_INTR_SET_OPS(enable_msix_irq, nbl_res_intr_enable_msix_irq);		\
	NBL_INTR_SET_OPS(get_msix_irq_enable_info, nbl_res_get_msix_irq_enable_info);	\
	NBL_INTR_SET_OPS(get_global_vector, nbl_res_intr_get_global_vector);		\
	NBL_INTR_SET_OPS(get_msix_entry_id, nbl_res_intr_get_msix_entry_id);		\
	NBL_INTR_SET_OPS(get_coalesce, nbl_res_intr_get_coalesce);			\
	NBL_INTR_SET_OPS(set_coalesce, nbl_res_intr_set_coalesce);			\
	NBL_INTR_SET_OPS(get_mbx_irq_num, nbl_res_intr_get_mbx_irq_num);		\
	NBL_INTR_SET_OPS(get_adminq_irq_num, nbl_res_intr_get_adminq_irq_num);		\
	NBL_INTR_SET_OPS(get_abnormal_irq_num, nbl_res_intr_get_abnormal_irq_num);	\
	NBL_INTR_SET_OPS(get_intr_suppress_level, nbl_res_intr_get_suppress_level);	\
	NBL_INTR_SET_OPS(set_intr_suppress_level, nbl_res_intr_set_intr_suppress_level);\
	NBL_INTR_SET_OPS(flr_clear_interrupt, nbl_res_flr_clear_interrupt);		\
	NBL_INTR_SET_OPS(unmask_all_interrupts, nbl_res_unmask_all_interrupts);		\
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

int nbl_intr_mgt_start(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_interrupt_mgt **intr_mgt;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	intr_mgt = &NBL_RES_MGT_TO_INTR_MGT(res_mgt);

	return nbl_intr_setup_mgt(dev, intr_mgt);
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
