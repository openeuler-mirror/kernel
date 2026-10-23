// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_queue.h"
#include "nbl_hw_draco/nbl_resource_draco.h"
#include "nbl_hw_leonis/nbl_resource_leonis.h"

static u16 nbl_res_queue_get_vsi_global_qid(void *priv,
					    struct nbl_ch_prm_get_vsi_global_qid *param);
static u16 nbl_res_queue_get_vsi_local_qid(void *priv, u16 vsi_id, u16 global_qid);
static int nbl_res_queue_reset_uvn_pkt_drop_stats(void *priv, u16 func_id, u16 global_queue_id);

struct nbl_queue_vsi_info *
nbl_res_queue_get_vsi_info(struct nbl_resource_mgt *res_mgt, u16 vsi_id)
{
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info;
	u16 func_id;
	int i;

	func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	queue_info = &queue_mgt->queue_info[func_id];

	for (i = 0; i < NBL_VSI_MAX; i++)
		if (queue_info->vsi_info[i].vsi_id == vsi_id && queue_info->vsi_info[i].vld)
			return &queue_info->vsi_info[i];

	return NULL;
}

static int nbl_res_queue_get_net_id(struct nbl_queue_mgt *queue_mgt, u16 func_id, u16 vsi_type)
{
	switch (vsi_type) {
	case NBL_VSI_DATA:
		return func_id;
	case NBL_VSI_XDP:
		return func_id;
	case NBL_VSI_USER:
		return func_id + queue_mgt->aux_netid_offset;
	case NBL_VSI_CTRL:
		return func_id + queue_mgt->aux_netid_offset;
	default:
		return func_id + queue_mgt->aux_netid_offset;
	}
}

/* Structure starts here, adding an op should not modify anything below */
static int nbl_queue_setup_mgt(struct device *dev, struct nbl_queue_mgt **queue_mgt)
{
	*queue_mgt = devm_kzalloc(dev, sizeof(struct nbl_queue_mgt), GFP_KERNEL);
	if (!*queue_mgt)
		return -ENOMEM;

	return 0;
}

static void nbl_queue_remove_mgt(struct device *dev, struct nbl_queue_mgt **queue_mgt)
{
	devm_kfree(dev, *queue_mgt);
	*queue_mgt = NULL;
}

int nbl_queue_mgt_start(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_queue_mgt **queue_mgt;
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);
	int ret = 0;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	queue_mgt = &NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);

	ret = nbl_queue_setup_mgt(dev, queue_mgt);
	if (ret)
		return ret;

	ret = NBL_OPS_CALL(product_ops->queue_mgt_init, (res_mgt));

	return ret;
}

void nbl_queue_mgt_stop(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_queue_mgt **queue_mgt;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	queue_mgt = &NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);

	if (!(*queue_mgt))
		return;

	nbl_queue_remove_mgt(dev, queue_mgt);
}

static int nbl_res_queue_setup_queue_info(struct nbl_resource_mgt *res_mgt, u16 func_id,
					  u16 num_queues)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	struct nbl_event_queue_update_data event_data;
	u64 *queues_context;
	u16 *txrx_queues;
	u32 *uvn_stat_pkt_drop;
	u16 queue_index;
	int i, ret = 0;

	nbl_info(common, NBL_DEBUG_QUEUE,
		 "Setup qid map, func_id:%d, num_queues:%d", func_id, num_queues);

	txrx_queues = kcalloc(num_queues, sizeof(txrx_queues[0]), GFP_ATOMIC);
	if (!txrx_queues) {
		ret = -ENOMEM;
		goto alloc_txrx_queues_fail;
	}

	queues_context = kcalloc(num_queues * 2, sizeof(queues_context[0]), GFP_ATOMIC);
	if (!queues_context) {
		ret = -ENOMEM;
		goto alloc_queue_contex_fail;
	}

	uvn_stat_pkt_drop = kcalloc(num_queues, sizeof(*uvn_stat_pkt_drop), GFP_ATOMIC);
	if (!uvn_stat_pkt_drop) {
		ret = -ENOMEM;
		goto alloc_uvn_stat_pkt_drop_fail;
	}

	queue_info->num_txrx_queues = num_queues;
	queue_info->txrx_queues = txrx_queues;
	queue_info->queues_context = queues_context;
	queue_info->uvn_stat_pkt_drop = uvn_stat_pkt_drop;

	for (i = 0; i < num_queues; i++) {
		queue_index = find_first_zero_bit(queue_mgt->txrx_queue_bitmap,
						  NBL_QUEUE_MGT_TO_MAX_QUEUE(queue_mgt));
		if (queue_index == NBL_QUEUE_MGT_TO_MAX_QUEUE(queue_mgt)) {
			nbl_err(common, NBL_DEBUG_QUEUE, "There is no available txrx queues left\n");
			ret = -ENOSPC;
			goto get_txrx_queue_fail;
		}
		txrx_queues[i] = queue_index + NBL_QUEUE_MGT_TO_QUEUE_BASE_IDX(queue_mgt);
		set_bit(queue_index, queue_mgt->txrx_queue_bitmap);
	}

	event_data.func_id = func_id;
	event_data.ring_num = num_queues;
	event_data.map = txrx_queues;
	nbl_event_notify(NBL_EVENT_QUEUE_ALLOC, &event_data, NBL_COMMON_TO_VSI_ID(common),
			 NBL_COMMON_TO_BOARD_ID(common));

	return 0;

get_txrx_queue_fail:
	kfree(uvn_stat_pkt_drop);
	while (--i + 1) {
		queue_index = txrx_queues[i] - NBL_QUEUE_MGT_TO_QUEUE_BASE_IDX(queue_mgt);
		clear_bit(queue_index, queue_mgt->txrx_queue_bitmap);
	}
	queue_info->num_txrx_queues = 0;
	queue_info->txrx_queues = NULL;
alloc_uvn_stat_pkt_drop_fail:
	kfree(queues_context);
alloc_queue_contex_fail:
	kfree(txrx_queues);
alloc_txrx_queues_fail:
	return ret;
}

static void nbl_res_queue_remove_queue_info(struct nbl_resource_mgt *res_mgt, u16 func_id)
{
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	u16 i;

	for (i = 0; i < queue_info->num_txrx_queues; i++)
		clear_bit(queue_info->txrx_queues[i] - NBL_QUEUE_MGT_TO_QUEUE_BASE_IDX(queue_mgt),
			  queue_mgt->txrx_queue_bitmap);

	kfree(queue_info->txrx_queues);
	kfree(queue_info->queues_context);
	kfree(queue_info->uvn_stat_pkt_drop);
	queue_info->txrx_queues = NULL;
	queue_info->queues_context = NULL;
	queue_info->uvn_stat_pkt_drop = NULL;

	queue_info->num_txrx_queues = 0;
}

static inline u64 nbl_res_queue_qid_map_key(struct nbl_qid_map_table qid_map)
{
	u64 notify_addr_l = qid_map.notify_addr_l;
	u64 notify_addr_h = qid_map.notify_addr_h;

	return (notify_addr_h << NBL_QID_MAP_NOTIFY_ADDR_LOW_PART_LEN) | notify_addr_l;
}

static void nbl_res_queue_set_qid_map_table(struct nbl_resource_mgt *res_mgt, u16 tail)
{
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_qid_map_param param;
	int i;

	param.qid_map = kcalloc(tail, sizeof(param.qid_map[0]), GFP_ATOMIC);
	if (!param.qid_map)
		return;

	for (i = 0; i < tail; i++)
		param.qid_map[i] = queue_mgt->qid_map_table[i];

	param.start = 0;
	param.len = tail;

	phy_ops->set_qid_map_table(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), &param,
				   queue_mgt->qid_map_select);
	queue_mgt->qid_map_select = !queue_mgt->qid_map_select;
	phy_ops->set_qid_map_ready(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), true);

	kfree(param.qid_map);
}

int nbl_res_queue_init_qid_map_table(struct nbl_resource_mgt *res_mgt,
				     struct nbl_queue_mgt *queue_mgt, struct nbl_phy_ops *phy_ops)
{
	struct nbl_qid_map_table invalid_qid_map;
	struct nbl_qid_map_param param;
	int i;

	/* Fill the non-active HW table with all-F (invalid) entries first. */
	memset(&invalid_qid_map, 0, sizeof(invalid_qid_map));
	invalid_qid_map.local_qid = 0x1FF;
	invalid_qid_map.notify_addr_l = 0x7FFFFF;
	invalid_qid_map.notify_addr_h = 0xFFFFFFFF;
	invalid_qid_map.global_qid = 0xFFF;
	invalid_qid_map.ctrlq_flag = 0X1;

	param.qid_map = kcalloc(NBL_QID_MAP_TABLE_ENTRIES,
				sizeof(param.qid_map[0]), GFP_ATOMIC);
	if (!param.qid_map)
		return -ENOMEM;

	for (i = 0; i < NBL_QID_MAP_TABLE_ENTRIES; i++)
		param.qid_map[i] = invalid_qid_map;
	param.start = 0;
	param.len = NBL_QID_MAP_TABLE_ENTRIES;

	phy_ops->set_qid_map_table(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), &param,
				   !queue_mgt->qid_map_select);
	kfree(param.qid_map);

	nbl_res_queue_set_qid_map_table(res_mgt, NBL_QID_MAP_TABLE_ENTRIES);

	return 0;
}

int nbl_res_queue_setup_qid_map_table_leonis(struct nbl_resource_mgt *res_mgt, u16 func_id,
					     u64 notify_addr)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	struct nbl_qid_map_table qid_map;
	u64 key;
	u16 *txrx_queues = queue_info->txrx_queues;
	u16 qid_map_entries = queue_info->num_txrx_queues, qid_map_base, tail;
	int i;

	/* Get base location */
	queue_info->notify_addr = notify_addr;
	key = notify_addr >> NBL_QID_MAP_NOTIFY_ADDR_SHIFT;

	for (i = 0; i < NBL_QID_MAP_TABLE_ENTRIES; i++) {
		WARN_ON(key == nbl_res_queue_qid_map_key(queue_mgt->qid_map_table[i]));
		if (key < nbl_res_queue_qid_map_key(queue_mgt->qid_map_table[i])) {
			qid_map_base = i;
			break;
		}
	}
	if (i == NBL_QID_MAP_TABLE_ENTRIES) {
		nbl_err(common, NBL_DEBUG_QUEUE, "No valid qid map key for func %d", func_id);
		return -ENOSPC;
	}

	/* Calc tail, we will set the qid_map from 0 to tail.
	 * We have to make sure that this range (0, tail) can cover all the changes, which need to
	 * consider all the two tables. Therefore, it is necessary to store each table's tail, and
	 * always use the larger one between this table's tail and the added tail.
	 *
	 * The reason can be illustrated in the following example:
	 * Step 1: del some entries, which happens on table 1, and each table could be
	 *      Table 0: 0 - 31 used
	 *      Table 1: 0 - 15 used
	 *      SW     : queue_mgt->total_qid_map_entries = 16
	 * Step 2: add 2 entries, which happens on table 0, if we use 16 + 2 as the tail, then
	 *      Table 0: 0 - 17 correctly added, 18 - 31 garbage data
	 *      Table 1: 0 - 15 used
	 *      SW     : queue_mgt->total_qid_map_entries = 18
	 * And this is definitely wrong, it should use 32, table 0's original tail
	 */
	queue_mgt->total_qid_map_entries += qid_map_entries;
	tail = max(queue_mgt->total_qid_map_entries,
		   queue_mgt->qid_map_tail[queue_mgt->qid_map_select]);
	queue_mgt->qid_map_tail[queue_mgt->qid_map_select] = queue_mgt->total_qid_map_entries;

	/* Update qid map */
	for (i = NBL_QID_MAP_TABLE_ENTRIES - qid_map_entries; i > qid_map_base; i--)
		queue_mgt->qid_map_table[i - 1 + qid_map_entries] = queue_mgt->qid_map_table[i - 1];

	for (i = 0; i < queue_info->num_txrx_queues; i++) {
		qid_map.local_qid = 2 * i + 1;
		qid_map.notify_addr_l = key;
		qid_map.notify_addr_h = key >> NBL_QID_MAP_NOTIFY_ADDR_LOW_PART_LEN;
		qid_map.global_qid = txrx_queues[i];
		qid_map.ctrlq_flag = 0;
		queue_mgt->qid_map_table[qid_map_base + i] = qid_map;
	}

	nbl_res_queue_set_qid_map_table(res_mgt, tail);

	return 0;
}

void nbl_res_queue_remove_qid_map_table_leonis(struct nbl_resource_mgt *res_mgt, u16 func_id)
{
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	struct nbl_qid_map_table qid_map;
	u64 key;
	u16 qid_map_entries = queue_info->num_txrx_queues, qid_map_base, tail;
	int i;

	/* Get base location */
	key = queue_info->notify_addr >> NBL_QID_MAP_NOTIFY_ADDR_SHIFT;

	for (i = 0; i < NBL_QID_MAP_TABLE_ENTRIES; i++) {
		if (key == nbl_res_queue_qid_map_key(queue_mgt->qid_map_table[i])) {
			qid_map_base = i;
			break;
		}
	}
	if (i == NBL_QID_MAP_TABLE_ENTRIES)
		return;

	/* Calc tail, we will set the qid_map from 0 to tail.
	 * We have to make sure that this range (0, tail) can cover all the changes, which need to
	 * consider all the two tables. Therefore, it is necessary to store each table's tail, and
	 * always use the larger one between this table's tail and the driver-stored tail.
	 *
	 * The reason can be illustrated in the following example:
	 * Step 1: del some entries, which happens on table 1, and each table could be
	 *      Table 0: 0 - 31 used
	 *      Table 1: 0 - 15 used
	 *      SW     : queue_mgt->total_qid_map_entries = 16
	 * Step 2: del 2 entries, which happens on table 0, if we use 16 as the tail, then
	 *      Table 0: 0 - 13 correct, 14 - 31 garbage data
	 *      Table 1: 0 - 15 used
	 *      SW     : queue_mgt->total_qid_map_entries = 14
	 * And this is definitely wrong, it should use 32, table 0's original tail
	 */
	tail = max(queue_mgt->total_qid_map_entries,
		   queue_mgt->qid_map_tail[queue_mgt->qid_map_select]);
	queue_mgt->total_qid_map_entries -= qid_map_entries;
	queue_mgt->qid_map_tail[queue_mgt->qid_map_select] = queue_mgt->total_qid_map_entries;

	/* Update qid map */
	memset(&qid_map, U8_MAX, sizeof(qid_map));

	for (i = qid_map_base; i < NBL_QID_MAP_TABLE_ENTRIES - qid_map_entries; i++)
		queue_mgt->qid_map_table[i] = queue_mgt->qid_map_table[i + qid_map_entries];
	for (; i < NBL_QID_MAP_TABLE_ENTRIES; i++)
		queue_mgt->qid_map_table[i] = qid_map;

	nbl_res_queue_set_qid_map_table(res_mgt, tail);
}

int nbl_res_queue_setup_qid_map_table_draco(struct nbl_resource_mgt *res_mgt, u16 func_id,
					    u64 notify_addr)
{
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int pfid, vfid;
	int i;
	int ret;
	u8 is_vf = 0;

	ret = nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pfid, &vfid);
	if (ret) {
		dev_err(dev, "convert func id %d to pfvfid failed\n", func_id);
		return ret;
	}

	if (vfid != U32_MAX)
		is_vf = 1;

	for (i = 0; i < queue_info->num_txrx_queues; i++)
		phy_ops->set_net_qid_table(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					   func_id, queue_info->txrx_queues[i], i, is_vf);

	return 0;
}

static int nbl_res_queue_setup_q2vsi(void *priv, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_info *queue_info = NULL;
	struct nbl_queue_vsi_info *vsi_info = NULL;
	u16 func_id;
	int ret = 0, i;

	func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	queue_info = &queue_mgt->queue_info[func_id];
	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	if (!vsi_info)
		return -ENOENT;

	/*config ipro queue tbl*/
	for (i = vsi_info->queue_offset;
	     i < vsi_info->queue_offset + vsi_info->queue_num && i < queue_info->num_txrx_queues;
	     i++) {
		ret = phy_ops->cfg_ipro_queue_tbl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						  queue_info->txrx_queues[i], vsi_id, 1);
		if (ret) {
			while (--i + 1)
				phy_ops->cfg_ipro_queue_tbl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
							    queue_info->txrx_queues[i], 0, 0);
			return ret;
		}
	}

	return 0;
}

static void nbl_res_queue_remove_q2vsi(void *priv, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_info *queue_info = NULL;
	struct nbl_queue_vsi_info *vsi_info = NULL;
	u16 func_id;
	int i;

	func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	queue_info = &queue_mgt->queue_info[func_id];
	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	if (!vsi_info)
		return;

	/*config ipro queue tbl*/
	for (i = vsi_info->queue_offset;
	     i < vsi_info->queue_offset + vsi_info->queue_num && i < queue_info->num_txrx_queues;
	     i++)
		phy_ops->cfg_ipro_queue_tbl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					    queue_info->txrx_queues[i], 0, 0);
}

int nbl_res_queue_get_rss_ret_base_and_size_leonis(struct nbl_resource_mgt *res_mgt,
						   u16 vsi_id, u16 queue_num,
						   struct nbl_queue_vsi_info *vsi_info)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	u32 rss_ret_base_start;
	u32 rss_ret_base_end;
	int index;
	int i;
	int j;
	int k;
	int success = 1;
	int ret = -EFAULT;
	u16 func_id;
	u16 rss_entry_count;
	u16 rss_entry_size;
	u16 count;

	rss_entry_size = (vsi_info->queue_num + NBL_EPRO_RSS_ENTRY_SIZE_UNIT - 1)
			  / NBL_EPRO_RSS_ENTRY_SIZE_UNIT;
	rss_entry_size = (u16)ilog2(roundup_pow_of_two(rss_entry_size));
	count = (u16)(NBL_EPRO_RSS_ENTRY_SIZE_UNIT << rss_entry_size);

	vsi_info->rss_entry_size_unit = NBL_EPRO_RSS_ENTRY_SIZE_UNIT;
	func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_info->vsi_id);
	if (func_id < NBL_MAX_ETHERNET &&
	    (vsi_info->vsi_index == NBL_VSI_DATA || vsi_info->vsi_index == NBL_VSI_USER)) {
		rss_ret_base_start = 0;
		rss_ret_base_end = NBL_EPRO_PF_RSS_RET_TBL_DEPTH;
		vsi_info->rss_entry_size = NBL_EPRO_PF_RSS_ENTRY_SIZE;
		rss_entry_count = NBL_EPRO_PF_RSS_RET_TBL_COUNT;
	} else {
		rss_ret_base_start = NBL_EPRO_PF_RSS_RET_TBL_DEPTH;
		rss_ret_base_end = NBL_EPRO_RSS_RET_TBL_DEPTH;
		vsi_info->rss_entry_size = rss_entry_size;
		rss_entry_count = count;
	}

	for (i = rss_ret_base_start; i < rss_ret_base_end;) {
		index = find_next_zero_bit(queue_mgt->rss_ret_bitmap,
					   rss_ret_base_end, i);
		if (index == rss_ret_base_end) {
			nbl_err(common, NBL_DEBUG_QUEUE, "There is no available rss ret left");
			break;
		}

		success = 1;
		for (j = index + 1; j < (index + rss_entry_count); j++) {
			if (j >= rss_ret_base_end) {
				success = 0;
				break;
			}

			if (test_bit(j, queue_mgt->rss_ret_bitmap)) {
				success = 0;
				break;
			}
		}
		if (success) {
			for (k = index; k < (index + rss_entry_count); k++)
				set_bit(k, queue_mgt->rss_ret_bitmap);
			vsi_info->rss_ret_base = index;
			ret = 0;
			break;
		}
		i = j;
	}

	return ret;
}

int nbl_res_queue_get_rss_ret_base_and_size_draco(struct nbl_resource_mgt *res_mgt,
						  u16 vsi_id, u16 queue_num,
						  struct nbl_queue_vsi_info *vsi_info)
{
	/* for draco, vsi's rss table is placed at a fixed location in q_map_tbl table,
	 * and has fixed entry size.
	 *
	 * for vsi[0-11], every vsi has 4 q_map_tbl, namely 128 rss entry
	 * for vsi[12-275], every vsi has 1 q_map_tbl, namely 32 rss entry
	 */
	if (vsi_id < 12) {
		vsi_info->rss_entry_size = 2;
		vsi_info->rss_ret_base = vsi_id * 128;
	} else {
		vsi_info->rss_entry_size = 0;
		vsi_info->rss_ret_base = (vsi_id - 12) * 32 + 128 * 12;
	}

	vsi_info->rss_entry_size_unit = NBL_EPRO_RSS_ENTRY_SIZE_UNIT_DRACO;

	return 0;
}

int nbl_res_queue_setup_rss(void *priv, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_queue_vsi_info *vsi_info = NULL;
	int ret = 0;

	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	if (!vsi_info)
		return -ENOENT;

	ret = NBL_OPS_CALL(product_ops->get_rss_ret_base_and_size,
			   (res_mgt, vsi_id, vsi_info->queue_num, vsi_info));
	if (ret)
		return -ENOSPC;

	vsi_info->rss_vld = true;

	dev_info(dev, "vsi_id:%d, rss_entry_size:%d, rss_ret_base:%d\n",
		 vsi_id, vsi_info->rss_entry_size, vsi_info->rss_ret_base);

	return 0;
}

static void nbl_res_queue_remove_rss(void *priv, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_vsi_info *vsi_info = NULL;
	u16 rss_ret_base = 0, rss_entry_size_unit = 0, rss_entry_size = 0, count = 0;
	int i;

	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	if (!vsi_info)
		return;

	if (!vsi_info->rss_vld)
		return;

	rss_ret_base = vsi_info->rss_ret_base;
	rss_entry_size = vsi_info->rss_entry_size;
	rss_entry_size_unit = vsi_info->rss_entry_size_unit;
	count = rss_entry_size_unit << rss_entry_size;

	for (i = rss_ret_base; i < (rss_ret_base + count); i++)
		clear_bit(i, queue_mgt->rss_ret_bitmap);

	vsi_info->rss_vld = false;
}

static void nbl_res_queue_setup_queue_cfg(struct nbl_queue_info *queue_info,
					  struct nbl_queue_cfg_param *cfg_param,
					  struct nbl_txrx_queue_param *queue_param,
					  bool is_tx, bool interleave_seg_disable)
{
	cfg_param->desc = queue_param->dma;
	cfg_param->size = queue_param->desc_num;
	cfg_param->global_vector = queue_param->global_vector_id;
	cfg_param->global_queue_id = queue_info->txrx_queues[queue_param->local_queue_id];

	cfg_param->avail = queue_param->avail;
	cfg_param->used = queue_param->used;
	cfg_param->extend_header = queue_param->extend_header;
	cfg_param->split = queue_param->split;
	cfg_param->last_avail_idx = queue_param->cxt;

	cfg_param->intr_en = queue_param->intr_en;
	cfg_param->intr_mask = queue_param->intr_mask;

	cfg_param->tx = is_tx;
	cfg_param->interleave_seg_disable = interleave_seg_disable;
	cfg_param->vsi_id = queue_param->vsi_id;
	cfg_param->rxcsum = queue_param->rxcsum;
	cfg_param->half_offload_en = queue_param->half_offload_en;
}

static void nbl_res_queue_update_netid_refnum(struct nbl_queue_mgt *queue_mgt, u16 net_id, bool add)
{
	if (net_id >= NBL_MAX_NET_ID)
		return;

	if (add) {
		queue_mgt->net_id_ref_vsinum[net_id]++;
	} else {
		/* probe call clear_queue first, so judge nor zero to support disable dsch more than
		 * once
		 */
		if (queue_mgt->net_id_ref_vsinum[net_id])
			queue_mgt->net_id_ref_vsinum[net_id]--;
	}
}

static u16 nbl_res_queue_get_netid_refnum(struct nbl_queue_mgt *queue_mgt, u16 net_id)
{
	if (net_id >= NBL_MAX_NET_ID)
		return 0;
	return queue_mgt->net_id_ref_vsinum[net_id];
}

static void nbl_res_queue_setup_hw_dq(struct nbl_resource_mgt *res_mgt,
				      struct nbl_queue_cfg_param *queue_cfg,
				      u16 func_id, u16 vsi_id)
{
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	struct nbl_queue_vsi_info *vsi_info;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_vnet_queue_info_param param = {0};
	u16 global_queue_id = queue_cfg->global_queue_id;
	u8 bus, dev, func;
	int ret = 0;

	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	if (!vsi_info)
		return;

	nbl_res_func_id_to_bdf(res_mgt, func_id, &bus, &dev, &func);
	queue_info->split = queue_cfg->split;
	queue_info->queue_size = queue_cfg->size;

	param.function_id = func;
	param.device_id = dev;
	param.bus_id = bus;
	param.valid = 1;

	if (queue_cfg->intr_en) {
		param.msix_idx = queue_cfg->global_vector;
		param.msix_idx_valid = 1;
	}

	if (queue_cfg->tx) {
		phy_ops->set_vnet_queue_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), &param,
					     NBL_PAIR_ID_GET_TX(global_queue_id));
		ret = phy_ops->lso_dsch_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue_id);
		phy_ops->disable_dvn(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue_id);
		if (ret)
			ret = phy_ops->lso_dsch_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						      global_queue_id);
		phy_ops->reset_dvn_cfg(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue_id);
		if (!queue_cfg->extend_header)
			phy_ops->restore_dvn_context(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						     global_queue_id, queue_cfg->split,
						     queue_cfg->last_avail_idx);
		phy_ops->cfg_tx_queue(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				      queue_cfg, global_queue_id);
		if (nbl_res_queue_get_netid_refnum(queue_mgt, vsi_info->net_id))
			phy_ops->cfg_q2tc_netid(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						global_queue_id, vsi_info->net_id, 1);

	} else {
		phy_ops->set_vnet_queue_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), &param,
					     NBL_PAIR_ID_GET_RX(global_queue_id));
		phy_ops->disable_uvn(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue_id);
		phy_ops->rsc_cache_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue_id);
		phy_ops->reset_uvn_cfg(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue_id);
		nbl_res_queue_reset_uvn_pkt_drop_stats(res_mgt, func_id, global_queue_id);
		if (!queue_cfg->extend_header)
			phy_ops->restore_uvn_context(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						     global_queue_id, queue_cfg->split,
						     queue_cfg->last_avail_idx);
		phy_ops->cfg_rx_queue(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), queue_cfg,
				      global_queue_id);
	}
}

static void nbl_res_queue_remove_hw_dq(struct nbl_resource_mgt *res_mgt,
				       struct nbl_queue_cfg_param *queue_cfg, u16 func_id,
				       u16 local_queue_id)
{
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 global_queue = queue_cfg->global_queue_id;
	int ret = 0;

	if (queue_cfg->tx) {
		ret = phy_ops->lso_dsch_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
		if (ret) {
			pr_err("lso_dsch_drain failed\n");
			return;
		}
		phy_ops->clear_vnet_queue_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					       NBL_PAIR_ID_GET_TX(global_queue));

		phy_ops->disable_dvn(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);

		queue_info->queues_context[NBL_PAIR_ID_GET_TX(local_queue_id)] =
			phy_ops->save_dvn_ctx(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					      global_queue, queue_info->split);
		phy_ops->reset_dvn_cfg(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
	} else {
		phy_ops->clear_vnet_queue_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					       NBL_PAIR_ID_GET_RX(global_queue));
		phy_ops->disable_uvn(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
		phy_ops->rsc_cache_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);

		queue_info->queues_context[NBL_PAIR_ID_GET_RX(local_queue_id)] =
			phy_ops->save_uvn_ctx(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					      global_queue, queue_info->split,
					      queue_info->queue_size);

		phy_ops->reset_uvn_cfg(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
		nbl_res_queue_reset_uvn_pkt_drop_stats(res_mgt, func_id, global_queue);
	}
}

static void nbl_res_queue_remove_all_hw_dq(struct nbl_resource_mgt *res_mgt, u16 func_id,
					   struct nbl_queue_vsi_info *vsi_info)
{
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 start = vsi_info->queue_offset, end = vsi_info->queue_offset + vsi_info->queue_num;
	u16 global_queue;
	int i;
	int ret = 0;

	if (!queue_info->txrx_queues || !queue_info->queues_context)
		return;
	for (i = start; i < end; i++) {
		global_queue = queue_info->txrx_queues[i];

		ret = phy_ops->lso_dsch_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
		phy_ops->disable_dvn(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
		if (ret)
			ret = phy_ops->lso_dsch_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						      global_queue);
	}

	for (i = start; i < end; i++) {
		global_queue = queue_info->txrx_queues[i];

		phy_ops->disable_uvn(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
		phy_ops->rsc_cache_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
	}

	for (i = start; i < end; i++) {
		global_queue = queue_info->txrx_queues[i];
		queue_info->queues_context[NBL_PAIR_ID_GET_RX(i)] =
			phy_ops->save_uvn_ctx(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					      global_queue, queue_info->split,
					      queue_info->queue_size);
		queue_info->queues_context[NBL_PAIR_ID_GET_TX(i)] =
			phy_ops->save_dvn_ctx(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					      global_queue, queue_info->split);
	}

	for (i = start; i < end; i++) {
		global_queue = queue_info->txrx_queues[i];
		phy_ops->reset_uvn_cfg(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
		nbl_res_queue_reset_uvn_pkt_drop_stats(res_mgt, func_id, global_queue);
		phy_ops->reset_dvn_cfg(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
	}

	for (i = start; i < end; i++) {
		global_queue = queue_info->txrx_queues[i];
		phy_ops->clear_vnet_queue_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					       NBL_PAIR_ID_GET_RX(global_queue));
		phy_ops->clear_vnet_queue_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					       NBL_PAIR_ID_GET_TX(global_queue));
	}
}

static int nbl_res_queue_init_epro_rss_key(struct nbl_resource_mgt *res_mgt,
					   struct nbl_phy_ops *phy_ops)
{
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	int ret = 0;

	ret = phy_ops->init_epro_rss_key(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					 queue_mgt->rss_key_range_oft);
	return ret;
}

static int nbl_res_queue_init_epro_vpt_table(struct nbl_resource_mgt *res_mgt,
					     u16 func_id, u16 bmode, bool binit)
{
	enum nbl_fix_cap_type cap_type = NBL_UDF_EXTRACT_CAP;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_sriov_info *sriov_info;
	void *p = NBL_RES_MGT_TO_PHY_PRIV(res_mgt);
	int pfid, vfid;
	u16 vsi_id, vf_vsi_id;
	int diff;
	int i = 0;
	u16 rx_vlan_vsi_id = 0;

	diff = nbl_common_pf_id_subtraction_mgtpf_id(common, func_id);
	sriov_info = &NBL_RES_MGT_TO_SRIOV_INFO(res_mgt)[diff];

	vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);
	nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pfid, &vfid);

	if (sriov_info->bdf != 0) {
		/* init pf vsi */
		for (i = 0; i < NBL_VSI_MAX; i++) {
			vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, i);
			phy_ops->init_epro_vpt_tbl(p,
						   vsi_id, bmode, binit,
						   queue_mgt->rss_key_range_oft);
			if (nbl_res_get_fix_capability(res_mgt, &cap_type) &&
			    i == NBL_VSI_DATA) {
				rx_vlan_vsi_id = RDMA_RX_VLAN_VSI_ID(vsi_id);
				phy_ops->init_epro_vpt_tbl(p, rx_vlan_vsi_id, bmode, binit,
							   queue_mgt->rss_key_range_oft);
			}
		}

		for (vfid = 0; vfid < sriov_info->num_vfs; vfid++) {
			vf_vsi_id = nbl_res_pfvfid_to_vsi_id(res_mgt, pfid, vfid, NBL_VSI_DATA);
			if (vf_vsi_id == 0xFFFF)
				continue;

			phy_ops->init_epro_vpt_tbl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						   vf_vsi_id, bmode, binit,
						   queue_mgt->rss_key_range_oft);
		}
	}

	return 0;
}

static int nbl_res_queue_init_ipro_dn_sport_tbl(struct nbl_resource_mgt *res_mgt,
						u16 func_id, u16 bmode, bool binit)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_sriov_info *sriov_info;
	int pfid, vfid;
	u16 eth_id, vsi_id, vf_vsi_id;
	int diff, i;

	diff = nbl_common_pf_id_subtraction_mgtpf_id(common, func_id);
	sriov_info = &NBL_RES_MGT_TO_SRIOV_INFO(res_mgt)[diff];

	vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);
	nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pfid, &vfid);

	if (sriov_info->bdf != 0) {
		eth_id = nbl_res_vsi_id_to_eth_id(res_mgt, vsi_id);

		for (i = 0; i < NBL_VSI_MAX; i++) {
			vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, i);
			phy_ops->cfg_ipro_dn_sport_tbl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						       vsi_id, eth_id, bmode, binit);
		}

		for (vfid = 0; vfid < sriov_info->num_vfs; vfid++) {
			vf_vsi_id = nbl_res_pfvfid_to_vsi_id(res_mgt, pfid, vfid, NBL_VSI_DATA);
			if (vf_vsi_id == 0xFFFF)
				continue;

			phy_ops->cfg_ipro_dn_sport_tbl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
							vf_vsi_id, eth_id, bmode, binit);
		}
	}

	return 0;
}

static int nbl_res_queue_set_bridge_mode(void *priv, u16 func_id, u16 bmode)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	int ret = 0;

	ret = nbl_res_queue_init_ipro_dn_sport_tbl(res_mgt, func_id, bmode, false);
	if (ret)
		goto init_ipro_dn_sport_tbl_fail;

	ret = nbl_res_queue_init_epro_vpt_table(res_mgt, func_id, bmode, false);
	if (ret)
		goto init_epro_vpt_table_fail;

init_epro_vpt_table_fail:
init_ipro_dn_sport_tbl_fail:
	return ret;
}

static int nbl_res_queue_init_rss(struct nbl_resource_mgt *res_mgt,
				  struct nbl_queue_mgt *queue_mgt,
				  struct nbl_phy_ops *phy_ops)
{
	return nbl_res_queue_init_epro_rss_key(res_mgt, phy_ops);
}

static int nbl_res_queue_alloc_txrx_queues(void *priv, struct nbl_ch_prm_alloc_txrx_queues *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);
	u64 notify_addr;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, param->vsi_id);
	int ret = 0;

	notify_addr = nbl_res_get_func_bar_base_addr(res_mgt, func_id);

	ret = nbl_res_queue_setup_queue_info(res_mgt, func_id, param->queue_num);
	if (ret)
		goto setup_queue_info_fail;

	ret = NBL_OPS_CALL(product_ops->setup_qid_map_table, (res_mgt, func_id, notify_addr));
	if (ret)
		goto setup_qid_map_fail;

	ret = nbl_res_prepare_vf_chan(res_mgt, func_id);
	if (ret)
		goto prepare_vf_chan_fail;

	nbl_res_update_active_vf_num(res_mgt, func_id, 1);

	return 0;

prepare_vf_chan_fail:
setup_qid_map_fail:
	nbl_res_queue_remove_queue_info(res_mgt, func_id);
setup_queue_info_fail:
	return ret;
}

static int nbl_res_queue_free_txrx_queues(void *priv, u16 *vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, *vsi_id);
	struct nbl_event_queue_update_data event_data;

	nbl_res_update_active_vf_num(res_mgt, func_id, 0);
	NBL_OPS_CALL(product_ops->remove_qid_map_table, (res_mgt, func_id));
	nbl_res_queue_remove_queue_info(res_mgt, func_id);
	event_data.func_id = func_id;
	event_data.ring_num = 0;
	event_data.map = NULL;
	nbl_event_notify(NBL_EVENT_QUEUE_ALLOC, &event_data, NBL_COMMON_TO_VSI_ID(res_mgt->common),
			 NBL_COMMON_TO_BOARD_ID(res_mgt->common));
	return 0;
}

static int nbl_res_queue_register_vsi2q(void *priv, u16 vsi_index, u16 vsi_id,
					u16 queue_offset, u16 queue_num)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = NULL;
	struct nbl_queue_vsi_info *vsi_info = NULL;
	u16 func_id;

	func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	queue_info = &queue_mgt->queue_info[func_id];
	vsi_info = &queue_info->vsi_info[vsi_index];

	memset(vsi_info, 0, sizeof(*vsi_info));

	vsi_info->vld = 1;
	vsi_info->vsi_index = vsi_index;
	vsi_info->vsi_id = vsi_id;
	vsi_info->queue_offset = queue_offset;
	vsi_info->queue_num = queue_num;

	vsi_info->net_id = nbl_res_queue_get_net_id(queue_mgt, func_id, vsi_info->vsi_index);

	return 0;
}

static void nbl_res_queue_params_modify(struct nbl_resource_mgt *res_mgt, bool is_dpdk)
{
	u8 eth_speed;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_adapt_desc_gother *adapt_desc_gother = &queue_mgt->adapt_desc_gother;

	adapt_desc_gother->is_dpdk = is_dpdk;

	if (!queue_mgt->dvn_desc_req.desc_req_need || queue_mgt->dvn_desc_req.is_desc_req_cfg)
		return;

	eth_speed = res_mgt->resource_info->board_info.eth_speed;
	phy_ops->set_dvn_desc_req_dpdk(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), eth_speed, is_dpdk);
}

static int nbl_res_queue_setup_queue(void *priv, struct nbl_ch_prm_setup_queue *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_cfg_param cfg_param = {0};
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, param->param.vsi_id);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];

	if (!param->param.intr_en && !queue_info->is_dpdk) {
		queue_info->is_dpdk = true;
		queue_info->dpdk_vsi = param->param.vsi_id;
		queue_mgt->dpdk_cnt++;
		if (queue_mgt->dpdk_cnt == 1)
			nbl_res_queue_params_modify(res_mgt, 1);
	}

	nbl_res_queue_setup_queue_cfg(queue_info, &cfg_param, &param->param, param->is_tx,
				      param->interleave_seg_disable);

	nbl_res_queue_setup_hw_dq(res_mgt, &cfg_param, func_id, param->param.vsi_id);

	return 0;
}

static int nbl_res_queue_remove_queue(void *priv, struct nbl_ch_prm_setup_queue *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_cfg_param cfg_param = {0};
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, param->param.vsi_id);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];

	if (queue_info->is_dpdk && queue_info->dpdk_vsi == param->param.vsi_id) {
		queue_info->is_dpdk = false;
		queue_mgt->dpdk_cnt--;
		if (!queue_mgt->dpdk_cnt)
			nbl_res_queue_params_modify(res_mgt, 0);
	}
	nbl_res_queue_setup_queue_cfg(queue_info, &cfg_param, &param->param, param->is_tx, 0);
	nbl_res_queue_remove_hw_dq(res_mgt, &cfg_param, func_id, param->param.local_queue_id);
	return 0;
}

static void nbl_res_queue_remove_all_queues(void *priv, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	struct nbl_queue_vsi_info *vsi_info = NULL;

	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	if (!vsi_info)
		return;

	if (queue_info->is_dpdk && queue_info->dpdk_vsi == vsi_id) {
		queue_info->is_dpdk = false;
		queue_mgt->dpdk_cnt--;
		if (!queue_mgt->dpdk_cnt)
			nbl_res_queue_params_modify(res_mgt, 0);
	}
	nbl_res_queue_remove_all_hw_dq(res_mgt, func_id, vsi_info);
}

static int nbl_res_queue_cfg_dsch(void *priv, u16 vsi_id, bool vld)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_vsi_info *vsi_info;
	u16 group_id = nbl_res_vsi_id_to_eth_id(res_mgt, vsi_id); /* group_id is same with eth_id */
	u16 start = 0, end = 0;
	int i, ret = 0;

	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	if (!vsi_info)
		return -ENOENT;

	start = vsi_info->queue_offset;
	end = vsi_info->queue_num + vsi_info->queue_offset;

	if (!queue_info->txrx_queues)
		return 0;
	/* When setting up, g2p -> n2g -> q2tc; when down, q2tc -> n2g -> g2p */
	if (!vld) {
		phy_ops->deactive_shaping(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_info->net_id);
		for (i = start; i < end; i++)
			phy_ops->cfg_q2tc_netid(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						queue_info->txrx_queues[i], vsi_info->net_id, vld);
		nbl_res_queue_update_netid_refnum(queue_mgt, vsi_info->net_id, false);
	}

	if (!nbl_res_queue_get_netid_refnum(queue_mgt, vsi_info->net_id)) {
		ret = phy_ops->cfg_dsch_net_to_group(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					     vsi_info->net_id, group_id, vld);
		if (ret)
			return ret;
	}

	if (vld) {
		for (i = start; i < end; i++)
			phy_ops->cfg_q2tc_netid(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						queue_info->txrx_queues[i], vsi_info->net_id, vld);
		phy_ops->active_shaping(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_info->net_id);
		nbl_res_queue_update_netid_refnum(queue_mgt, vsi_info->net_id, true);
	}

	return 0;
}

static int nbl_res_queue_setup_cqs(void *priv, u16 vsi_id, u16 real_qps, bool rss_indir_set)
{
	enum nbl_fix_cap_type cap_type = NBL_UDF_EXTRACT_CAP;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info;
	struct nbl_queue_vsi_info *vsi_info = NULL;
	u16 rx_vlan_vsi_id;
	u16 func_id;

	func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	queue_info = &queue_mgt->queue_info[func_id];

	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	if (!vsi_info)
		return -ENOENT;

	if (real_qps == vsi_info->curr_qps)
		return 0;

	if (real_qps && rss_indir_set)
		phy_ops->cfg_epro_rss_ret(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					  vsi_info->rss_ret_base,
					  vsi_info->rss_entry_size_unit,
					  vsi_info->rss_entry_size, real_qps,
					  queue_info->txrx_queues + vsi_info->queue_offset, NULL);

	if (!vsi_info->curr_qps) {
		phy_ops->set_epro_rss_pt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id,
					 vsi_info->rss_ret_base, vsi_info->rss_entry_size);
		if (nbl_res_get_fix_capability(res_mgt, &cap_type) &&
		    func_id < NBL_MAX_PF) {
			rx_vlan_vsi_id = RDMA_RX_VLAN_VSI_ID(vsi_id);
			if (rx_vlan_vsi_id != U16_MAX)
				phy_ops->set_epro_rss_pt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
							 rx_vlan_vsi_id,
							 vsi_info->rss_ret_base,
							 vsi_info->rss_entry_size);
		}
	}

	vsi_info->curr_qps = real_qps;
	vsi_info->curr_qps_static = real_qps;
	return 0;
}

static void nbl_res_queue_remove_cqs(void *priv, u16 vsi_id)
{
	enum nbl_fix_cap_type cap_type = NBL_UDF_EXTRACT_CAP;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_vsi_info *vsi_info = NULL;
	u16 rx_vlan_vsi_id;
	u16 func_id;

	func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	if (!vsi_info)
		return;

	phy_ops->clear_epro_rss_pt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id);
	if (nbl_res_get_fix_capability(res_mgt, &cap_type) && func_id < NBL_MAX_PF) {
		rx_vlan_vsi_id = RDMA_RX_VLAN_VSI_ID(vsi_id);
		if (rx_vlan_vsi_id != U16_MAX)
			phy_ops->clear_epro_rss_pt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						 rx_vlan_vsi_id);
	}

	vsi_info->curr_qps = 0;
}

static int nbl_res_queue_init_switch(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	int i;

	for_each_set_bit(i, eth_info->eth_bitmap, NBL_MAX_ETHERNET)
		phy_ops->setup_queue_switch(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), i);

	return 0;
}

static int nbl_res_init_queue(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 func_id = NBL_COMMON_TO_MGT_PF(common);
	struct nbl_queue_mgt *queue_mgt;
	struct nbl_phy_ops *phy_ops;
	int i, ret = 0;
	u8 eth_id = 0;

	if (!res_mgt)
		return -EINVAL;

	queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	ret = NBL_OPS_CALL(product_ops->init_qid_map_table, (res_mgt, queue_mgt, phy_ops));
	if (ret)
		goto init_queue_fail;

	ret = nbl_res_queue_init_rss(res_mgt, queue_mgt, phy_ops);
	if (ret)
		goto init_queue_fail;

	ret = nbl_res_queue_init_switch(res_mgt);
	if (ret)
		goto init_queue_fail;

	for_each_set_bit(i, NBL_RES_MGT_TO_OWNED_PF_BITMAP(res_mgt),
			 NBL_RES_MGT_TO_PF_NUM(res_mgt)) {
		nbl_res_queue_init_epro_vpt_table(res_mgt, i, BRIDGE_MODE_VEB, true);
		nbl_res_queue_init_ipro_dn_sport_tbl(res_mgt, i, BRIDGE_MODE_VEB, true);
	}

	ret = NBL_OPS_CALL(product_ops->init_epro_vpt_extra,
			   (res_mgt, nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA)));
	if (ret)
		goto init_queue_fail;

	eth_id = eth_info->eth_id[func_id];
	phy_ops->init_pfc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), eth_id, NBL_MAX_ETHERNET, 0, 0);

	return 0;

init_queue_fail:
	return ret;
}

static int nbl_res_queue_get_queue_err_stats(void *priv,
					     struct nbl_ch_prm_get_queue_err_stats *param,
					     struct nbl_queue_err_stats *queue_err_stats)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[param->sfid];
	struct nbl_phy_ops *phy_ops;
	u16 global_queue_id;

	if (param->queue_id >= queue_info->num_txrx_queues)
		return -EINVAL;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	global_queue_id = queue_info->txrx_queues[param->queue_id];

	if (param->is_tx)
		phy_ops->get_tx_queue_err_stats(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						global_queue_id, queue_err_stats);
	else
		phy_ops->get_rx_queue_err_stats(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						global_queue_id, queue_err_stats);

	return 0;
}

static int nbl_res_queue_cfg_qdisc_mqprio(void *priv, struct nbl_tc_qidsc_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info;
	struct nbl_queue_vsi_info *vsi_info = NULL;
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	u64 max_rate = 0;
	u64 total_tx_rate = 0, max_tc_rate = 0;
	u16 func_id, curr_qps = 0, queue_id = 0;
	u8 *weight;
	bool is_active = false;
	int i, j, gravity;

	func_id = nbl_res_vsi_id_to_func_id(res_mgt, param->vsi_id);
	queue_info = &queue_mgt->queue_info[func_id];
	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, param->vsi_id);

	for (i = 0; i < param->num_tc; i++)
		total_tx_rate += param->info[i].max_tx_rate;

	switch (res_info->board_info.eth_speed) {
	case NBL_FW_PORT_SPEED_100G:
		max_rate = NBL_RATE_MBPS_100G;
		break;
	case NBL_FW_PORT_SPEED_25G:
		max_rate = NBL_RATE_MBPS_25G;
		break;
	case NBL_FW_PORT_SPEED_10G:
		max_rate = NBL_RATE_MBPS_10G;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (total_tx_rate > max_rate) {
		nbl_err(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_QUEUE,
			"Invalid total_tx_rate: %llu mbps, should within %llu mbps",
			total_tx_rate, max_rate);
		return -EINVAL;
	}

	for (i = 0; i < vsi_info->curr_qps; i++) {
		queue_id = queue_info->txrx_queues[i + vsi_info->queue_offset];
		phy_ops->lso_dsch_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), queue_id);
		is_active |= phy_ops->check_q2tc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), queue_id);
	}

	/* Config tc */
	for (i = 0; i < param->num_tc; i++)
		for (j = 0; j < param->info[i].count; j++) {
			phy_ops->cfg_q2tc_tcid(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					       queue_info->txrx_queues[curr_qps +
								       vsi_info->queue_offset], i);
			curr_qps++;
		}

	for (i = curr_qps; i < param->origin_qps; i++)
		phy_ops->cfg_q2tc_tcid(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				       queue_info->txrx_queues[i + vsi_info->queue_offset], 0);

	/* Config weight */
	weight = kcalloc(param->num_tc, sizeof(*weight), GFP_KERNEL);
	if (!weight)
		return -ENOMEM;

	for (i = 0; i < param->num_tc; i++)
		if (param->info[i].max_tx_rate > max_tc_rate)
			max_tc_rate = param->info[i].max_tx_rate;

	gravity = max_tc_rate / NBL_SHAPING_WGT_MAX + 1;

	for (i = 0; i < param->num_tc; i++)
		weight[i] = div64_u64(param->info[i].max_tx_rate, gravity);
	phy_ops->set_tc_wgt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_info->net_id,
			    weight, param->num_tc);

	/* Config shaping */
	phy_ops->set_shaping(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_info->net_id, total_tx_rate, 0,
			     param->enable && total_tx_rate, is_active);

	kfree(weight);
	return 0;
}

static int nbl_res_queue_set_tc_wgt(void *priv, struct nbl_ch_prm_set_tc_wgt *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_vsi_info *vsi_info = NULL;
	u8 *weight_to_set;
	int i;

	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, param->vsi_id);
	weight_to_set = kcalloc(param->num_tc, sizeof(*weight_to_set), GFP_KERNEL);
	if (!weight_to_set)
		return -ENOMEM;

	for (i = 0; i < param->num_tc; i++)
		weight_to_set[i] = param->weight[i] * NBL_SHAPING_WGT_MAX / NBL_TC_MAX_BW;
	phy_ops->set_tc_wgt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_info->net_id,
			    weight_to_set, param->num_tc);

	kfree(weight_to_set);
	return 0;
}

static void nbl_res_restore_tc_mgt(void *priv, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_vsi_info *vsi_info = NULL;
	u8 *weight;
	int i;

	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	if (!vsi_info)
		return;
	weight = kcalloc(NBL_MAX_TC_NUM, sizeof(*weight), GFP_KERNEL);
	if (!weight)
		return;

	for (i = 0; i < NBL_MAX_TC_NUM; i++)
		weight[i] = 1;
	phy_ops->set_tc_wgt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_info->net_id,
			    weight, NBL_MAX_TC_NUM);

	kfree(weight);
}

static int nbl_res_queue_get_rxfh_indir_size(void *priv, u16 *vsi_id, u32 *rxfh_indir_size)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_vsi_info *vsi_info = NULL;

	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, *vsi_id);
	if (!vsi_info)
		return 0;

	*rxfh_indir_size = vsi_info->rss_entry_size_unit << vsi_info->rss_entry_size;
	return 0;
}

static u16 nbl_res_queue_get_local_queue_id(void *priv,
					    struct nbl_get_local_queue_id_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 vsi_id = param->vsi_id;
	u16 global_queue_id = param->global_queue_id;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	int i;

	queue_info = &queue_mgt->queue_info[func_id];

	if (queue_info->txrx_queues)
		for (i = 0; i < queue_info->num_txrx_queues; i++)
			if (global_queue_id == queue_info->txrx_queues[i])
				return i;

	return U16_MAX;
}

void nbl_res_queue_get_rxfh_indir_leonis(void *priv, u16 vsi_id, u32 *indir)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_vsi_info *vsi_info = NULL;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 i, indir_size;
	struct nbl_get_local_queue_id_param prm = {0};

	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	if (!vsi_info)
		return;

	phy_ops->read_rss_indir(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id, indir,
				vsi_info->rss_ret_base, vsi_info->rss_entry_size);

	indir_size = NBL_EPRO_RSS_ENTRY_SIZE_UNIT << vsi_info->rss_entry_size;
	prm.vsi_id = vsi_id;
	for (i = 0; i < indir_size; i++) {
		prm.global_queue_id = indir[i];
		indir[i] = nbl_res_queue_get_local_queue_id(res_mgt, &prm);
		indir[i] -= vsi_info->queue_offset;
	}
}

void nbl_res_queue_get_rxfh_indir_draco(void *priv, u16 vsi_id, u32 *indir)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_vsi_info *vsi_info = NULL;
	struct nbl_queue_info *queue_info = NULL;
	u32 rss_ret[NBL_RSS_RET_MAX_SIZE];
	u16 func_id = 0;
	u32 rxfh_indir_size = 0;
	int i = 0;

	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	if (!vsi_info)
		return;

	phy_ops->get_epro_rss_ret(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					vsi_info->rss_ret_base,
					vsi_info->rss_entry_size_unit,
					vsi_info->rss_entry_size,
					rss_ret);

	nbl_res_queue_get_rxfh_indir_size(priv, &vsi_id, &rxfh_indir_size);
	func_id = NBL_COMMON_TO_MGT_PF(common);
	queue_info = &queue_mgt->queue_info[func_id];
	/* global queue to local queue */
	for (i = 0; i < rxfh_indir_size; i++) {
		indir[i] = nbl_res_queue_get_vsi_local_qid(res_mgt, vsi_id, rss_ret[i])
				- vsi_info->queue_offset;
	}
}

static void nbl_res_queue_get_rxfh_indir(void *priv, u16 vsi_id, u32 *indir)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);

	NBL_OPS_CALL(product_ops->get_rxfh_indir, (res_mgt, vsi_id, indir));
}

int nbl_res_queue_init_epro_vpt_extra(struct nbl_resource_mgt *res_mgt, u16 vsi_id)
{
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 func_id = NBL_COMMON_TO_MGT_PF(common);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 extra_vsi_id;
	u16 rss_entry_size_unit;
	u16 rss_entry_size;
	u16 rss_ret_base;
	u32 indir_size;
	u32 *rss_ret;

	extra_vsi_id = RDMA_RX_VLAN_VSI_ID(vsi_id);
	rss_entry_size = 0;
	rss_ret_base = (extra_vsi_id - 12) * 32 + 128 * 12;
	rss_entry_size_unit = NBL_EPRO_RSS_ENTRY_SIZE_UNIT_DRACO;
	indir_size = rss_entry_size_unit << rss_entry_size;

	queue_info->extra_vsi_rss_ret_base = rss_ret_base;

	rss_ret = kcalloc(indir_size, sizeof(u32), GFP_KERNEL);
	if (!rss_ret)
		return -ENOMEM;

	phy_ops->cfg_epro_rss_ret(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				  rss_ret_base, rss_entry_size_unit,
				  rss_entry_size, 0, NULL, rss_ret);

	kfree(rss_ret);

	return 0;
}

static int nbl_res_queue_set_rxfh_indir(void *priv, u16 vsi_id, const u32 *indir, u32 indir_size)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_vsi_info *vsi_info = NULL;
	struct nbl_queue_info *queue_info = NULL;
	struct nbl_ch_prm_get_vsi_global_qid prm = {0};
	u32 *rss_ret;
	u16 func_id = 0;
	int i = 0;

	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	if (!vsi_info)
		return -ENOENT;

	if (indir) {
		rss_ret = kcalloc(indir_size, sizeof(indir[0]), GFP_KERNEL);
		if (!rss_ret)
			return -ENOMEM;
		func_id = NBL_COMMON_TO_MGT_PF(common);
		queue_info = &queue_mgt->queue_info[func_id];
		/* local queue to global queue */
		prm.vsi_id = vsi_id;
		for (i = 0; i < indir_size; i++) {
			prm.local_qid = vsi_info->queue_offset + indir[i];
			rss_ret[i] = nbl_res_queue_get_vsi_global_qid(res_mgt, &prm);
		}
		phy_ops->cfg_epro_rss_ret(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					  vsi_info->rss_ret_base,
					  vsi_info->rss_entry_size_unit,
					  vsi_info->rss_entry_size, 0,
					  NULL, rss_ret);
		kfree(rss_ret);
	}
	return 0;
}

int nbl_res_queue_set_epro_rss_ret(void *priv, u16 slot_index, u16 global_queue_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 func_id = NBL_COMMON_TO_MGT_PF(common);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	u32 fd_rss_ret_index = 0;
	int ret = 0;

	fd_rss_ret_index = queue_info->extra_vsi_rss_ret_base + slot_index;
	ret = phy_ops->set_epro_rss_ret(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					fd_rss_ret_index, global_queue_id);
	return ret;
}

static void nbl_res_queue_get_rxfh_rss_key_size(void *priv, u32 *rxfh_rss_key_size)
{
	*rxfh_rss_key_size = NBL_EPRO_RSS_SK_SIZE;
}

static void nbl_res_rss_key_reverse_order(u8 *key)
{
	u8 temp;
	int i;

	for (i = 0; i < (NBL_EPRO_RSS_PER_KEY_SIZE / 2); i++) {
		temp = key[i];
		key[i] = key[NBL_EPRO_RSS_PER_KEY_SIZE - 1 - i];
		key[NBL_EPRO_RSS_PER_KEY_SIZE - 1 - i] = temp;
	}
}

static int nbl_res_queue_get_rxfh_rss_key(void *priv,
					  struct nbl_ch_prm_get_rxfh_rss_key *prm,
					  struct nbl_ch_prm_get_rxfh_key *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int i;

	phy_ops->get_vsi_rss_key(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), prm->vsi_id, output->rss_key);

	for (i = 0; i < NBL_EPRO_RSS_KEY_NUM; i++)
		nbl_res_rss_key_reverse_order(output->rss_key + i * NBL_EPRO_RSS_PER_KEY_SIZE);

	return 0;
}

static bool nbl_res_queue_rss_key_is_used_by_other_vsi(struct nbl_resource_mgt *res_mgt,
						       u16 *self_vsi_id, u16 table_id)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_sriov_info *sriov_info;
	int pfid, vfid;
	u16 vsi_id, vf_vsi_id;
	int diff;
	int i = 0;
	u16 func_id = 0;
	u8 rss_hash_key_sel = 0;

	func_id = NBL_COMMON_TO_MGT_PF(common);
	nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pfid, &vfid);
	diff = nbl_common_pf_id_subtraction_mgtpf_id(common, func_id);
	sriov_info = &NBL_RES_MGT_TO_SRIOV_INFO(res_mgt)[diff];
	if (sriov_info->bdf != 0) {
		for (i = 0; i < NBL_VSI_MAX; i++) {
			vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, i);
			if (vsi_id == self_vsi_id[i])
				continue;

			phy_ops->get_rss_hash_key_sel(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						      vsi_id, &rss_hash_key_sel);
			if (rss_hash_key_sel == table_id)
				return true;
		}

		for (vfid = 0; vfid < sriov_info->num_vfs; vfid++) {
			vf_vsi_id = nbl_res_pfvfid_to_vsi_id(res_mgt, pfid, vfid, NBL_VSI_DATA);
			if (vf_vsi_id == 0xFFFF)
				continue;

			if (vf_vsi_id == self_vsi_id[NBL_VSI_DATA])
				continue;

			phy_ops->get_rss_hash_key_sel(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						      vf_vsi_id, &rss_hash_key_sel);
			if (rss_hash_key_sel == table_id)
				return true;
		}
	}

	return false;
}

static bool nbl_res_queue_rss_key_is_same(void *priv, const u8 *rss_key, u16 table_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u8 rss_key_temp[NBL_EPRO_RSS_SK_SIZE];

	phy_ops->get_rss_key(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), rss_key_temp, table_id);

	if (!memcmp(rss_key, rss_key_temp, NBL_EPRO_RSS_SK_SIZE))
		return true;
	else
		return false;
}

static int nbl_res_queue_set_rxfh_rss_key(void *priv,
					  struct nbl_ch_prm_set_rxfh_rss_key *prm)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int i = 0;
	int start = queue_mgt->rss_key_range_oft;
	int end = queue_mgt->rss_key_range_oft + queue_mgt->rss_key_range_size;
	int pf_id, vf_id;
	u16 ref_vsi_id[NBL_VSI_MAX];
	u16 func_id;
	u8 rss_key_temp[NBL_EPRO_RSS_SK_SIZE];

	for (i = 0; i < NBL_VSI_MAX; i++)
		ref_vsi_id[i] = U16_MAX;

	memcpy(rss_key_temp, prm->rss_key, NBL_EPRO_RSS_SK_SIZE);
	for (i = 0; i < NBL_EPRO_RSS_KEY_NUM; i++)
		nbl_res_rss_key_reverse_order(rss_key_temp + i * NBL_EPRO_RSS_PER_KEY_SIZE);

	for (i = start; i < end; i++) {
		if (nbl_res_queue_rss_key_is_same(priv, rss_key_temp, i))
			break;
	}

	ref_vsi_id[NBL_VSI_DATA] = prm->vsi_id;
	func_id = nbl_res_vsi_id_to_func_id(priv, prm->vsi_id);
	nbl_res_func_id_to_pfvfid(priv, func_id, &pf_id, &vf_id);
	if (vf_id == U32_MAX)
		ref_vsi_id[NBL_VSI_USER] = nbl_res_func_id_to_vsi_id(res_mgt, func_id,
								     NBL_VSI_USER);

	/* if rss_key already exists in the rss_key_table */
	if (i < end) {
		phy_ops->set_rss_hash_key_sel(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), prm->vsi_id, i);
		if (ref_vsi_id[NBL_VSI_USER] != U16_MAX)
			phy_ops->set_rss_hash_key_sel(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						      ref_vsi_id[NBL_VSI_USER], i);
		return 0;
	}

	for (i = start + 1; i < end; i++) {
		if (!nbl_res_queue_rss_key_is_used_by_other_vsi(priv, ref_vsi_id, i))
			break;
	}
	if (i < end) {
		phy_ops->set_rss_key(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), rss_key_temp, i);
		phy_ops->set_rss_hash_key_sel(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), prm->vsi_id, i);
		if (ref_vsi_id[NBL_VSI_USER] != U16_MAX)
			phy_ops->set_rss_hash_key_sel(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						      ref_vsi_id[NBL_VSI_USER], i);
		return 0;
	}

	if (queue_mgt->rss_replace) {
		phy_ops->set_rss_key(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), rss_key_temp, U16_MAX);
		return 0;
	}

	return -EIO;
}

static int nbl_res_queue_get_rss_alg_sel(void *priv, u16 *vsi_id, u8 *alg_sel)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->get_rss_alg_sel(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				 *vsi_id, nbl_res_vsi_id_to_eth_id(res_mgt, *vsi_id), alg_sel);

	return 0;
}

static int nbl_res_queue_set_rss_alg_sel(void *priv, struct nbl_ch_prm_set_rxfh_rss_alg_sel *prm)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int ret = 0;

	ret = phy_ops->set_rss_alg_sel(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), prm->vsi_id,
				       prm->rss_alg_sel);
	return ret;
}

int nbl_res_queue_get_hash_fields_leonis(void *priv, u16 vsi_id, int flow_type, u64 *hash_fields)
{
	switch (flow_type) {
	case NBL_FLOW_TYPE_TCPV4:
	case NBL_FLOW_TYPE_TCPV6:
	case NBL_FLOW_TYPE_UDPV4:
	case NBL_FLOW_TYPE_UDPV6:
		break;
	default:
		return -EOPNOTSUPP;
	}

	*hash_fields = 0;
	*hash_fields = NBL_HASH_FILED_SRC_IP | NBL_HASH_FILED_DST_IP |
			NBL_HASH_FILED_L4_SPORT | NBL_HASH_FILED_L4_DPORT;

	return 0;
}

int nbl_res_queue_set_hash_fields_leonis(void *priv, u16 vsi_id, int flow_type, u64 hash_fields)
{
	switch (flow_type) {
	case NBL_FLOW_TYPE_TCPV4:
	case NBL_FLOW_TYPE_TCPV6:
	case NBL_FLOW_TYPE_UDPV4:
	case NBL_FLOW_TYPE_UDPV6:
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (hash_fields == (NBL_HASH_FILED_SRC_IP | NBL_HASH_FILED_DST_IP |
				NBL_HASH_FILED_L4_SPORT | NBL_HASH_FILED_L4_DPORT))
		return 0;
	else
		return -EOPNOTSUPP;
}

int nbl_res_queue_get_hash_fields_draco(void *priv, u16 vsi_id, int flow_type, u64 *hash_fields)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u64 tempt_sel = 0;

	phy_ops->get_rss_hash_tmpt_sel(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				       vsi_id, flow_type, &tempt_sel);

	*hash_fields = 0;
	if (flow_type == NBL_FLOW_TYPE_TCPV4) {
		if (tempt_sel & TMPT_SEL_TCPV4_SIP)
			*hash_fields |= NBL_HASH_FILED_SRC_IP;
		if (tempt_sel & TMPT_SEL_TCPV4_DIP)
			*hash_fields |= NBL_HASH_FILED_DST_IP;
		if (tempt_sel & TMPT_SEL_TCPV4_SP)
			*hash_fields |= NBL_HASH_FILED_L4_SPORT;
		if (tempt_sel & TMPT_SEL_TCPV4_DP)
			*hash_fields |= NBL_HASH_FILED_L4_DPORT;
	} else if (flow_type == NBL_FLOW_TYPE_TCPV6) {
		if (tempt_sel & TMPT_SEL_TCPV6_SIP)
			*hash_fields |= NBL_HASH_FILED_SRC_IP;
		if (tempt_sel & TMPT_SEL_TCPV6_DIP)
			*hash_fields |= NBL_HASH_FILED_DST_IP;
		if (tempt_sel & TMPT_SEL_TCPV6_SP)
			*hash_fields |= NBL_HASH_FILED_L4_SPORT;
		if (tempt_sel & TMPT_SEL_TCPV6_DP)
			*hash_fields |= NBL_HASH_FILED_L4_DPORT;
	} else if (flow_type == NBL_FLOW_TYPE_UDPV4) {
		if (tempt_sel & TMPT_SEL_UDPV4_SIP)
			*hash_fields |= NBL_HASH_FILED_SRC_IP;
		if (tempt_sel & TMPT_SEL_UDPV4_DIP)
			*hash_fields |= NBL_HASH_FILED_DST_IP;
		if (tempt_sel & TMPT_SEL_UDPV4_SP)
			*hash_fields |= NBL_HASH_FILED_L4_SPORT;
		if (tempt_sel & TMPT_SEL_UDPV4_DP)
			*hash_fields |= NBL_HASH_FILED_L4_DPORT;
	} else if (flow_type == NBL_FLOW_TYPE_UDPV6) {
		if (tempt_sel & TMPT_SEL_UDPV6_SIP)
			*hash_fields |= NBL_HASH_FILED_SRC_IP;
		if (tempt_sel & TMPT_SEL_UDPV6_DIP)
			*hash_fields |= NBL_HASH_FILED_DST_IP;
		if (tempt_sel & TMPT_SEL_UDPV6_SP)
			*hash_fields |= NBL_HASH_FILED_L4_SPORT;
		if (tempt_sel & TMPT_SEL_UDPV6_DP)
			*hash_fields |= NBL_HASH_FILED_L4_DPORT;
	} else if (flow_type == NBL_FLOW_TYPE_SCTPV4) {
		if (tempt_sel & TMPT_SEL_SCTPV4_SIP)
			*hash_fields |= NBL_HASH_FILED_SRC_IP;
		if (tempt_sel & TMPT_SEL_SCTPV4_DIP)
			*hash_fields |= NBL_HASH_FILED_DST_IP;
		if (tempt_sel & TMPT_SEL_SCTPV4_SP)
			*hash_fields |= NBL_HASH_FILED_L4_SPORT;
		if (tempt_sel & TMPT_SEL_SCTPV4_DP)
			*hash_fields |= NBL_HASH_FILED_L4_DPORT;
	} else if (flow_type == NBL_FLOW_TYPE_SCTPV6) {
		if (tempt_sel & TMPT_SEL_SCTPV6_SIP)
			*hash_fields |= NBL_HASH_FILED_SRC_IP;
		if (tempt_sel & TMPT_SEL_SCTPV6_DIP)
			*hash_fields |= NBL_HASH_FILED_DST_IP;
		if (tempt_sel & TMPT_SEL_SCTPV6_SP)
			*hash_fields |= NBL_HASH_FILED_L4_SPORT;
		if (tempt_sel & TMPT_SEL_SCTPV6_DP)
			*hash_fields |= NBL_HASH_FILED_L4_DPORT;
	} else {
		return -EOPNOTSUPP;
	}

	return 0;
}

int nbl_res_queue_set_hash_fields_draco(void *priv, u16 vsi_id, int flow_type, u64 hash_fields)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int ret = 0;

	ret = phy_ops->set_rss_hash_tmpt_sel(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					     vsi_id, flow_type, hash_fields);

	return ret;
}

static int nbl_res_queue_get_hash_fields(void *priv, u16 vsi_id, int flow_type, u64 *hash_fields)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);
	int ret = 0;

	ret = NBL_OPS_CALL(product_ops->get_hash_fields, (res_mgt, vsi_id, flow_type, hash_fields));

	return ret;
}

static int nbl_res_queue_set_hash_fields(void *priv, u16 vsi_id, int flow_type, u64 hash_fields)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);
	int ret = 0;

	ret = NBL_OPS_CALL(product_ops->set_hash_fields, (res_mgt, vsi_id, flow_type, hash_fields));

	return ret;
}

static int nbl_res_queue_clear_queues(void *priv, u16 *vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, *vsi_id);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	struct nbl_tc_qidsc_param param;

	memset(&param, 0, sizeof(param));

	nbl_res_queue_remove_rss(priv, *vsi_id);
	if (func_id >= NBL_MAX_PF)
		phy_ops->set_epro_rss_default(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					      *vsi_id, queue_mgt->rss_key_range_oft);
	nbl_res_queue_remove_q2vsi(priv, *vsi_id);
	nbl_res_restore_tc_mgt(priv, *vsi_id);
	if (!queue_info->num_txrx_queues)
		return 0;

	/* clear shapping */
	param.vsi_id = *vsi_id;
	param.enable = false;
	nbl_res_queue_cfg_qdisc_mqprio(priv, &param);
	nbl_res_queue_remove_cqs(res_mgt, *vsi_id);
	nbl_res_queue_remove_all_queues(res_mgt, *vsi_id);
	nbl_res_queue_cfg_dsch(res_mgt, *vsi_id, false);
	nbl_res_queue_free_txrx_queues(res_mgt, vsi_id);

	return 0;
}

static u16 nbl_res_queue_get_vsi_local_qid(void *priv, u16 vsi_id, u16 global_qid)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	int i = 0;

	if (!queue_info->num_txrx_queues)
		return 0xFFFF;

	for (i = 0; i < queue_info->num_txrx_queues; i++) {
		if (queue_info->txrx_queues[i] == global_qid)
			break;
	}

	if (i < queue_info->num_txrx_queues)
		return i;
	else
		return 0xFFFF;
}

/* for pmd driver */
static u16 nbl_res_queue_get_vsi_global_qid(void *priv,
					    struct nbl_ch_prm_get_vsi_global_qid *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 vsi_id = param->vsi_id;
	u16 local_qid = param->local_qid;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];

	if (!queue_info->num_txrx_queues)
		return 0xFFFF;

	if (local_qid >= queue_info->num_txrx_queues)
		return 0xFFFF;

	return queue_info->txrx_queues[local_qid];
}

static int nbl_res_queue_cfg_log(void *priv, u16 vsi_id, u16 qps, bool vld)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 global_queue, i;

	if (!queue_info->num_txrx_queues)
		return 0;

	for (i = 0; i < qps; i++) {
		global_queue = queue_info->txrx_queues[i];
		phy_ops->cfg_vnet_qinfo_log(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					    NBL_PAIR_ID_GET_RX(global_queue), vld);
		phy_ops->cfg_vnet_qinfo_log(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					    NBL_PAIR_ID_GET_TX(global_queue), vld);
	}

	return 0;
}

static u64 nbl_req_queue_get_ctx(void *priv, u16 vsi_id, u16 qid)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];

	if (!queue_info->num_txrx_queues)
		return 0xffff;

	return queue_info->queues_context[qid];
}

static u16 nbl_get_adapt_desc_gother_level(u16 last_level, u64 rates, bool is_dpdk)
{
	if (is_dpdk)
		return NBL_ADAPT_DESC_GOTHER_LEVEL0;
	switch (last_level) {
	case NBL_ADAPT_DESC_GOTHER_LEVEL0:
		if (rates > NBL_ADAPT_DESC_GOTHER_LEVEL1_TH)
			return NBL_ADAPT_DESC_GOTHER_LEVEL1;
		else
			return NBL_ADAPT_DESC_GOTHER_LEVEL0;
	case NBL_ADAPT_DESC_GOTHER_LEVEL1:
		if (rates > NBL_ADAPT_DESC_GOTHER_LEVEL1_DOWNGRADE_TH)
			return NBL_ADAPT_DESC_GOTHER_LEVEL1;
		else
			return NBL_ADAPT_DESC_GOTHER_LEVEL0;
	default:
		return NBL_ADAPT_DESC_GOTHER_LEVEL0;
	}
}

static u16 nbl_get_adapt_desc_gother_timeout(struct nbl_queue_mgt *queue_mgt, u16 level)
{
	switch (level) {
	case NBL_ADAPT_DESC_GOTHER_LEVEL0:
		return queue_mgt->desc_gother_level0_timeout;
	case NBL_ADAPT_DESC_GOTHER_LEVEL1:
		return queue_mgt->desc_gother_level1_timeout;
	default:
		return queue_mgt->desc_gother_level0_timeout;
	}
}

static void nbl_res_queue_adapt_desc_gother(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_adapt_desc_gother *adapt_desc_gother = &queue_mgt->adapt_desc_gother;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u32 last_uvn_desc_rd_entry = adapt_desc_gother->uvn_desc_rd_entry;
	u64 last_get_stats_jiffies = adapt_desc_gother->get_desc_stats_jiffies;
	u64 time_diff;
	u32 uvn_desc_rd_entry;
	u32 rx_rate;
	u16 level, last_level, timeout;

	last_level = adapt_desc_gother->level;
	time_diff = jiffies - last_get_stats_jiffies;
	uvn_desc_rd_entry = phy_ops->get_uvn_desc_entry_stats(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	rx_rate = div64_u64(uvn_desc_rd_entry - last_uvn_desc_rd_entry, time_diff) * HZ;
	adapt_desc_gother->get_desc_stats_jiffies = jiffies;
	adapt_desc_gother->uvn_desc_rd_entry = uvn_desc_rd_entry;

	level = nbl_get_adapt_desc_gother_level(last_level, rx_rate, adapt_desc_gother->is_dpdk);
	if (level != last_level) {
		timeout = nbl_get_adapt_desc_gother_timeout(queue_mgt, level);
		phy_ops->set_uvn_desc_wr_timeout(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), timeout);
		adapt_desc_gother->level = level;
	}
}

static void nbl_res_queue_set_desc_high_throughput(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_adapt_desc_gother *adapt_desc_gother = &queue_mgt->adapt_desc_gother;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	if (adapt_desc_gother->level != NBL_ADAPT_DESC_GOTHER_LEVEL1) {
		phy_ops->set_uvn_desc_wr_timeout(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						queue_mgt->desc_gother_level1_timeout);
		adapt_desc_gother->level = NBL_ADAPT_DESC_GOTHER_LEVEL1;
	}
}

static void nbl_res_flr_clear_queues(void *priv, u16 vf_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 func_id = vf_id + NBL_MAX_PF;
	u16 vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);

	nbl_res_queue_clear_queues(priv, &vsi_id);
}

static void nbl_res_flr_qinfo_cfg(void *priv, u16 vf_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 func_id = vf_id + NBL_MAX_PF;
	struct nbl_qinfo_cfg_table *qinfo = &NBL_RES_MGT_TO_QINFO_CFG(res_mgt)[func_id];

	phy_ops->set_qinfo_tx(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), func_id,
				      qinfo->dma_addr, qinfo->size_bwind);
}

static int nbl_res_queue_restore_tx_queue(struct nbl_resource_mgt *res_mgt, u16 vsi_id,
					  u16 local_queue_id, dma_addr_t dma)
{
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_info *queue_info;
	struct nbl_queue_vsi_info *vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	struct nbl_queue_cfg_param queue_cfg = {0};
	u16 global_queue, func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	int ret = 0;

	if (!vsi_info)
		return -ENOSPC;

	queue_info = &queue_mgt->queue_info[func_id];
	global_queue = queue_info->txrx_queues[local_queue_id];

	phy_ops->get_tx_queue_cfg(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), &queue_cfg, global_queue);
	/* Rectify size, in register it is log2(size) */
	queue_cfg.size = queue_info->queue_size;
	/* DMA addr is realloced, updated it */
	queue_cfg.desc = dma;

	ret = phy_ops->lso_dsch_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
	phy_ops->disable_dvn(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
	if (ret)
		ret = phy_ops->lso_dsch_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);

	phy_ops->reset_dvn_cfg(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);

	phy_ops->cfg_tx_queue(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), &queue_cfg, global_queue);
	phy_ops->cfg_q2tc_netid(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				global_queue, vsi_info->net_id, 1);

	return 0;
}

static int nbl_res_queue_restore_rx_queue(struct nbl_resource_mgt *res_mgt, u16 vsi_id,
					  u16 local_queue_id, dma_addr_t dma)
{
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_info *queue_info;
	struct nbl_queue_cfg_param queue_cfg = {0};
	u16 global_queue, func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);

	queue_info = &queue_mgt->queue_info[func_id];
	global_queue = queue_info->txrx_queues[local_queue_id];

	phy_ops->get_rx_queue_cfg(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), &queue_cfg, global_queue);
	/* Rectify size, in register it is log2(size) */
	queue_cfg.size = queue_info->queue_size;
	/* DMA addr is realloced, updated it */
	queue_cfg.desc = dma;

	phy_ops->disable_uvn(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
	phy_ops->rsc_cache_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);

	phy_ops->reset_uvn_cfg(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
	nbl_res_queue_reset_uvn_pkt_drop_stats(res_mgt, func_id, global_queue);

	phy_ops->cfg_rx_queue(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), &queue_cfg, global_queue);

	return 0;
}

static int nbl_res_queue_restore_hw_queue(void *priv,
					  struct nbl_ch_prm_restore_hw_queue *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 vsi_id = param->vsi_id;
	u16 local_queue_id = param->local_queue_id;
	dma_addr_t dma = param->dma;
	int type = param->type;

	switch (type) {
	case NBL_TX:
		return nbl_res_queue_restore_tx_queue(res_mgt, vsi_id, local_queue_id, dma);
	case NBL_RX:
		return nbl_res_queue_restore_rx_queue(res_mgt, vsi_id, local_queue_id, dma);
	default:
		break;
	}

	return -EINVAL;
}

static int nbl_res_queue_stop_abnormal_hw_queue(void *priv,
						struct nbl_ch_prm_stop_abnormal_hw_queue *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 vsi_id = param->vsi_id;
	u16 local_queue_id = param->local_queue_id;
	int type = param->type;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_info *queue_info;
	u16 global_queue, func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	int ret = 0;

	queue_info = &queue_mgt->queue_info[func_id];
	global_queue = queue_info->txrx_queues[local_queue_id];
	switch (type) {
	case NBL_TX:
		ret = phy_ops->lso_dsch_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
		phy_ops->disable_dvn(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
		if (ret)
			ret = phy_ops->lso_dsch_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						      global_queue);
		phy_ops->reset_dvn_cfg(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
		return 0;
	case NBL_RX:
		phy_ops->disable_uvn(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
		phy_ops->rsc_cache_drain(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);

		phy_ops->reset_uvn_cfg(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), global_queue);
		nbl_res_queue_reset_uvn_pkt_drop_stats(res_mgt, func_id, global_queue);
		return 0;
	default:
		break;
	}

	return -EINVAL;
}

static int nbl_res_queue_set_tx_rate(void *priv, u16 func_id, int tx_rate, int burst)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	struct nbl_queue_vsi_info *vsi_info = NULL;
	u16 vsi_id, queue_id;
	bool is_active = false;
	int max_rate = 0, i;

	vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);
	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);

	if (!vsi_info)
		return 0;

	switch (res_info->board_info.eth_speed) {
	case NBL_FW_PORT_SPEED_100G:
		max_rate = NBL_RATE_MBPS_100G;
		break;
	case NBL_FW_PORT_SPEED_25G:
		max_rate = NBL_RATE_MBPS_25G;
		break;
	case NBL_FW_PORT_SPEED_10G:
		max_rate = NBL_RATE_MBPS_10G;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (tx_rate > max_rate)
		return -EINVAL;

	if (queue_info->txrx_queues)
		for (i = 0; i < vsi_info->curr_qps; i++) {
			queue_id = queue_info->txrx_queues[i + vsi_info->queue_offset];
			is_active |= phy_ops->check_q2tc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
							 queue_id);
		}

	/* Config shaping */
	return phy_ops->set_shaping(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_info->net_id, tx_rate,
				    burst, !!(tx_rate), is_active);
}

static int nbl_res_queue_set_rx_rate(void *priv, u16 func_id, int rx_rate, int burst)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_vsi_info *vsi_info = NULL;
	u16 vsi_id;
	int max_rate = 0;

	vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);
	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);

	if (!vsi_info)
		return 0;

	switch (res_info->board_info.eth_speed) {
	case NBL_FW_PORT_SPEED_100G:
		max_rate = NBL_RATE_MBPS_100G;
		break;
	case NBL_FW_PORT_SPEED_25G:
		max_rate = NBL_RATE_MBPS_25G;
		break;
	case NBL_FW_PORT_SPEED_10G:
		max_rate = NBL_RATE_MBPS_10G;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (rx_rate > max_rate)
		return -EINVAL;

	/* Config ucar */
	return phy_ops->set_ucar(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id, rx_rate,
				 burst, !!(rx_rate));
}

static void nbl_res_queue_get_active_func_bitmaps(void *priv, unsigned long *bitmap, int max_func)
{
	int i;
	int func_id_end;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	func_id_end = max_func > NBL_MAX_FUNC ? NBL_MAX_FUNC : max_func;

	for (i = 0; i < func_id_end; i++) {
		if (!nbl_res_check_func_active_by_queue(res_mgt, i))
			continue;
		set_bit(i, bitmap);
	}
}

static int nbl_res_queue_configure_mirror_table(void *priv,
						struct nbl_ch_prm_mirror_table *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info;
	struct nbl_event_mirror_outputport_data blacklist_data = {0};
	u16 vsi_id;
	u16 queue_id = 0;

	queue_info =  &queue_mgt->queue_info[param->func_id];
	if (queue_info->num_txrx_queues)
		queue_id = queue_info->txrx_queues[0];

	blacklist_data.opcode = param->mirror_en;
	blacklist_data.func_id = param->func_id;
	nbl_event_notify(NBL_EVENT_MIRROR_OUTPUTPORT, &blacklist_data, NBL_COMMON_TO_VSI_ID(common),
			 NBL_COMMON_TO_BOARD_ID(common));

	vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, param->func_id, NBL_VSI_DATA);

	return phy_ops->configure_mirror_table(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					       param->mirror_en, vsi_id, queue_id, param->mt_id);
}

static void nbl_res_queue_set_dvn_desc_req(void *priv, u32 desc_req)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->set_dvn_desc_req(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), desc_req);
	queue_mgt->dvn_desc_req.is_desc_req_cfg = true;
}

static u32 nbl_res_queue_get_dvn_desc_req(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->get_dvn_desc_req(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
}

static int nbl_res_queue_reset_uvn_pkt_drop_stats(void *priv, u16 func_id, u16 global_queue_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = &queue_mgt->queue_info[func_id];
	u16 vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);
	u16 local_queue_id;
	struct nbl_get_local_queue_id_param prm = {0};

	prm.vsi_id = vsi_id;
	prm.global_queue_id = global_queue_id;

	local_queue_id = nbl_res_queue_get_local_queue_id(res_mgt, &prm);
	queue_info->uvn_stat_pkt_drop[local_queue_id] = 0;
	return 0;
}

static int nbl_res_queue_get_uvn_pkt_drop_stats(void *priv, u16 vsi_id,
						u16 num_queues, u32 *uvn_stat_pkt_drop)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_queue_info *queue_info = NULL;
	struct nbl_queue_vsi_info *vsi_info = NULL;
	u16 func_id = 0;
	u32 pkt_drop_num = 0;
	int i = 0;

	func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	queue_info = &queue_mgt->queue_info[func_id];
	vsi_info = nbl_res_queue_get_vsi_info(res_mgt, vsi_id);
	if (!vsi_info)
		return -ENOENT;

	for (i = vsi_info->queue_offset;
	     i < vsi_info->queue_offset + num_queues &&
	     i < queue_info->num_txrx_queues; i++) {
		phy_ops->get_uvn_pkt_drop_stats(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						queue_info->txrx_queues[i], &pkt_drop_num);
		*uvn_stat_pkt_drop = pkt_drop_num - queue_info->uvn_stat_pkt_drop[i];
		uvn_stat_pkt_drop++;
		queue_info->uvn_stat_pkt_drop[i] = pkt_drop_num;
	}

	return 0;
}

/* NBL_QUEUE_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_QUEUE_OPS_TBL									\
do {												\
	NBL_QUEUE_SET_OPS(alloc_txrx_queues, nbl_res_queue_alloc_txrx_queues);			\
	NBL_QUEUE_SET_OPS(free_txrx_queues, nbl_res_queue_free_txrx_queues);			\
	NBL_QUEUE_SET_OPS(register_vsi2q, nbl_res_queue_register_vsi2q);			\
	NBL_QUEUE_SET_OPS(setup_q2vsi, nbl_res_queue_setup_q2vsi);				\
	NBL_QUEUE_SET_OPS(remove_q2vsi, nbl_res_queue_remove_q2vsi);				\
	NBL_QUEUE_SET_OPS(setup_rss, nbl_res_queue_setup_rss);					\
	NBL_QUEUE_SET_OPS(remove_rss, nbl_res_queue_remove_rss);				\
	NBL_QUEUE_SET_OPS(setup_queue, nbl_res_queue_setup_queue);				\
	NBL_QUEUE_SET_OPS(remove_queue, nbl_res_queue_remove_queue);				\
	NBL_QUEUE_SET_OPS(remove_all_queues, nbl_res_queue_remove_all_queues);			\
	NBL_QUEUE_SET_OPS(cfg_dsch, nbl_res_queue_cfg_dsch);					\
	NBL_QUEUE_SET_OPS(setup_cqs, nbl_res_queue_setup_cqs);					\
	NBL_QUEUE_SET_OPS(remove_cqs, nbl_res_queue_remove_cqs);				\
	NBL_QUEUE_SET_OPS(init_queue, nbl_res_init_queue);					\
	NBL_QUEUE_SET_OPS(get_queue_err_stats, nbl_res_queue_get_queue_err_stats);		\
	NBL_QUEUE_SET_OPS(cfg_qdisc_mqprio, nbl_res_queue_cfg_qdisc_mqprio);			\
	NBL_QUEUE_SET_OPS(get_rxfh_indir_size, nbl_res_queue_get_rxfh_indir_size);		\
	NBL_QUEUE_SET_OPS(get_rxfh_indir, nbl_res_queue_get_rxfh_indir);			\
	NBL_QUEUE_SET_OPS(set_rxfh_indir, nbl_res_queue_set_rxfh_indir);			\
	NBL_QUEUE_SET_OPS(get_rxfh_rss_key_size, nbl_res_queue_get_rxfh_rss_key_size);		\
	NBL_QUEUE_SET_OPS(get_rxfh_rss_key, nbl_res_queue_get_rxfh_rss_key);			\
	NBL_QUEUE_SET_OPS(set_rxfh_rss_key, nbl_res_queue_set_rxfh_rss_key);			\
	NBL_QUEUE_SET_OPS(get_rss_alg_sel, nbl_res_queue_get_rss_alg_sel);			\
	NBL_QUEUE_SET_OPS(set_rss_alg_sel, nbl_res_queue_set_rss_alg_sel);			\
	NBL_QUEUE_SET_OPS(get_hash_fields, nbl_res_queue_get_hash_fields);			\
	NBL_QUEUE_SET_OPS(set_hash_fields, nbl_res_queue_set_hash_fields);			\
	NBL_QUEUE_SET_OPS(clear_queues, nbl_res_queue_clear_queues);				\
	NBL_QUEUE_SET_OPS(get_vsi_global_qid, nbl_res_queue_get_vsi_global_qid);		\
	NBL_QUEUE_SET_OPS(cfg_queue_log, nbl_res_queue_cfg_log);				\
	NBL_QUEUE_SET_OPS(get_queue_ctx, nbl_req_queue_get_ctx);				\
	NBL_QUEUE_SET_OPS(adapt_desc_gother, nbl_res_queue_adapt_desc_gother);			\
	NBL_QUEUE_SET_OPS(set_desc_high_throughput, nbl_res_queue_set_desc_high_throughput);	\
	NBL_QUEUE_SET_OPS(flr_clear_queues, nbl_res_flr_clear_queues);				\
	NBL_QUEUE_SET_OPS(flr_qinfo_cfg, nbl_res_flr_qinfo_cfg);				\
	NBL_QUEUE_SET_OPS(restore_hw_queue, nbl_res_queue_restore_hw_queue);			\
	NBL_QUEUE_SET_OPS(get_local_queue_id, nbl_res_queue_get_local_queue_id);		\
	NBL_QUEUE_SET_OPS(set_bridge_mode, nbl_res_queue_set_bridge_mode);			\
	NBL_QUEUE_SET_OPS(set_tx_rate, nbl_res_queue_set_tx_rate);				\
	NBL_QUEUE_SET_OPS(set_rx_rate, nbl_res_queue_set_rx_rate);				\
	NBL_QUEUE_SET_OPS(stop_abnormal_hw_queue, nbl_res_queue_stop_abnormal_hw_queue);	\
	NBL_QUEUE_SET_OPS(get_active_func_bitmaps, nbl_res_queue_get_active_func_bitmaps);	\
	NBL_QUEUE_SET_OPS(set_tc_wgt, nbl_res_queue_set_tc_wgt);				\
	NBL_QUEUE_SET_OPS(configure_mirror_table, nbl_res_queue_configure_mirror_table);	\
	NBL_QUEUE_SET_OPS(get_dvn_desc_req, nbl_res_queue_get_dvn_desc_req);			\
	NBL_QUEUE_SET_OPS(set_dvn_desc_req, nbl_res_queue_set_dvn_desc_req);			\
	NBL_QUEUE_SET_OPS(get_uvn_pkt_drop_stats, nbl_res_queue_get_uvn_pkt_drop_stats);	\
} while (0)

int nbl_queue_setup_ops(struct nbl_resource_ops *res_ops)
{
#define NBL_QUEUE_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_QUEUE_OPS_TBL;
#undef  NBL_QUEUE_SET_OPS

	return 0;
}

void nbl_queue_remove_ops(struct nbl_resource_ops *res_ops)
{
#define NBL_QUEUE_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = NULL; ; } while (0)
	NBL_QUEUE_OPS_TBL;
#undef  NBL_QUEUE_SET_OPS
}

int nbl_queue_mgt_init_leonis(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_qid_map_table invalid_qid_map;
	int i = 0;

	queue_mgt->qid_map_select = NBL_MASTER_QID_MAP_TABLE;
	queue_mgt->queue_base_idx = 0;
	queue_mgt->max_queue = NBL_MAX_TXRX_QUEUE;
	queue_mgt->aux_netid_offset = NBL_AUX_NET_ID_OFFSET_LEONIS;
	queue_mgt->dvn_desc_req.desc_req_need = true;
	queue_mgt->pf_func_max_qp = NBL_MAX_TXRX_QUEUE_FUNC_LEONIS;
	queue_mgt->pf_func_max_qp_chk = NBL_MAX_TXRX_QUEUE_FUNC_LEONIS;
	queue_mgt->vf_func_max_qp = NBL_MAX_TXRX_QUEUE_FUNC_LEONIS;
	queue_mgt->pf_vsi_max_qp = NBL_MAX_TXRX_QUEUE_VSI_LEONIS;
	queue_mgt->vf_vsi_max_qp = NBL_MAX_TXRX_QUEUE_VSI_LEONIS;
	queue_mgt->check_allpf_qp = true;
	queue_mgt->pf_coexist_vsi_max_qp = NBL_VSI_PF_LEGACY_QUEUE_NUM_MAX;
	queue_mgt->rss_replace = true;
	queue_mgt->desc_gother_level0_timeout = NBL_ADAPT_DESC_GOTHER_LEVEL0_TIMEOUT;
	queue_mgt->desc_gother_level1_timeout = NBL_ADAPT_DESC_GOTHER_LEVEL1_TIMEOUT;

	memset(&invalid_qid_map, 0, sizeof(invalid_qid_map));
	invalid_qid_map.local_qid = 0x1FF;
	invalid_qid_map.notify_addr_l = 0x7FFFFF;
	invalid_qid_map.notify_addr_h = 0xFFFFFFFF;
	invalid_qid_map.global_qid = 0xFFF;
	invalid_qid_map.ctrlq_flag = 0X1;
	for (i = 0; i < NBL_QID_MAP_TABLE_ENTRIES; i++)
		queue_mgt->qid_map_table[i] = invalid_qid_map;

	return 0;
}

int nbl_queue_mgt_init_draco(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	u16 func_id = 0;
	u8 eth_id = 0;
	u8 eth_num = 0;
	u32 range_oft, range_size;

	phy_ops->get_table_range(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				 NBL_COMMON_TO_MGT_PF(common), NBL_ADDR_QUEUE,
				 eth_info->eth_num, &range_oft, &range_size);
	queue_mgt->queue_base_idx = range_oft;
	queue_mgt->max_queue = range_size;
	queue_mgt->aux_netid_offset = NBL_AUX_NET_ID_OFFSET_DRACO;
	queue_mgt->pf_func_max_qp = NBL_MAX_TXRX_QUEUE_FUNC_PF_DRACO;
	queue_mgt->pf_func_max_qp_chk = NBL_MAX_TXRX_QUEUE_FUNC_PF_DRACO_CHK;
	queue_mgt->vf_func_max_qp = NBL_MAX_TXRX_QUEUE_FUNC_VF_DRACO;
	queue_mgt->pf_vsi_max_qp = NBL_MAX_TXRX_QUEUE_VSI_PF_DRACO;
	queue_mgt->vf_vsi_max_qp = NBL_MAX_TXRX_QUEUE_VSI_VF_DRACO;
	queue_mgt->pf_coexist_vsi_max_qp = NBL_MAX_TXRX_QUEUE_VSI_PF_DRACO * 2;
	queue_mgt->desc_gother_level0_timeout = NBL_ADAPT_DESC_GOTHER_LEVEL0_TIMEOUT_DRACO;
	queue_mgt->desc_gother_level1_timeout = NBL_ADAPT_DESC_GOTHER_LEVEL1_TIMEOUT_DRACO;

	func_id = NBL_COMMON_TO_MGT_PF(common);
	eth_id = eth_info->eth_id[func_id];
	eth_num = eth_info->eth_num;
	queue_mgt->rss_key_range_oft = func_id * (NBL_RSS_KEY_NUM / eth_num);
	queue_mgt->rss_key_range_size = NBL_RSS_KEY_NUM / eth_num;
	dev_info(dev, "queue range_oft:%d range_size:%d, rss key range_oft:%d range_size:%d\n",
		 queue_mgt->queue_base_idx, queue_mgt->max_queue,
		 queue_mgt->rss_key_range_oft, queue_mgt->rss_key_range_size);
	return 0;
}
