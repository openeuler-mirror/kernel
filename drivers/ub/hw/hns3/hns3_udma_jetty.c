// SPDX-License-Identifier: GPL-2.0
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include <linux/slab.h>
#include "urma/ubcore_types.h"
#include "hns3_udma_tp.h"
#include "hns3_udma_jfc.h"
#include "hns3_udma_jfr.h"
#include "hns3_udma_db.h"
#include "hns3_udma_dfx.h"
#include "hns3_udma_jetty.h"

static void init_jetty_cfg(struct udma_jetty *jetty,
			   struct ubcore_jetty_cfg *cfg)
{
	jetty->shared_jfr = cfg->flag.bs.share_jfr;
	jetty->tp_mode = cfg->trans_mode;
	jetty->ubcore_jetty.jetty_cfg = *cfg;
	jetty->send_jfc = to_udma_jfc(cfg->send_jfc);
}

static void udma_fill_jetty_um_qp_attr(struct udma_dev *dev,
				       struct udma_jetty *jetty,
				       struct ubcore_ucontext *uctx,
				       struct ubcore_jetty_cfg *cfg)
{
	struct udma_ucontext *udma_ctx = to_udma_ucontext(uctx);
	struct udma_qp_attr *qp_attr = &jetty->qp.qp_attr;

	qp_attr->is_tgt = false;
	qp_attr->is_jetty = true;
	qp_attr->uctx = uctx;
	qp_attr->pdn = udma_ctx->pdn;
	qp_attr->send_jfc = to_udma_jfc(cfg->send_jfc);
	qp_attr->jetty = jetty;
	qp_attr->cap.max_send_wr = cfg->jfs_depth;
	qp_attr->cap.max_send_sge = cfg->max_send_sge;
	qp_attr->cap.max_inline_data = cfg->max_inline_data;
	qp_attr->cap.rnr_retry = cfg->rnr_retry;
	qp_attr->cap.ack_timeout = cfg->err_timeout;
	qp_attr->qp_type = QPT_UD;
	qp_attr->jfr = jetty->udma_jfr;
	qp_attr->qpn_map = &jetty->qpn_map;
	qp_attr->recv_jfc = to_udma_jfc(cfg->recv_jfc);
	qp_attr->eid_index = udma_ctx->eid_index;
	if (jetty->ubcore_jetty.jetty_cfg.priority >= dev->caps.sl_num) {
		qp_attr->priority =
			dev->caps.sl_num > 0 ? dev->caps.sl_num - 1 : 0;
		dev_err(dev->dev, "The setted priority (%d) should smaller than the max priority (%d), priority (%d) is used\n",
			jetty->ubcore_jetty.jetty_cfg.priority,
			dev->caps.sl_num, qp_attr->priority);
	} else {
		qp_attr->priority = jetty->ubcore_jetty.jetty_cfg.priority;
	}
}

static int udma_modify_qp_jetty(struct udma_dev *dev, struct udma_jetty *jetty,
				enum udma_qp_state target_state)
{
	union ubcore_tp_attr_mask ubcore_attr_mask;
	struct udma_modify_tp_attr m_attr = {};
	struct udma_qp *qp;
	int ret;

	qp = &jetty->qp;
	qp->udma_device = dev;
	qp->send_jfc = qp->qp_attr.send_jfc;
	qp->recv_jfc = qp->qp_attr.recv_jfc;

	m_attr.sgid_index = qp->qp_attr.eid_index;
	ubcore_attr_mask.value = 0;
	qp->m_attr = &m_attr;

	ret = udma_modify_qp_common(qp, NULL, ubcore_attr_mask, jetty->qp.state, target_state);
	if (ret)
		dev_err(dev->dev, "failed to modify qpc to RTS in Jetty.\n");

	qp->state = target_state;
	return ret;
}

static int set_jetty_jfr(struct udma_dev *dev, struct udma_jetty *jetty,
			 struct ubcore_jetty_cfg *cfg, uint32_t srqn)
{
	if (cfg->jfr) {
		jetty->shared_jfr = true;
		jetty->udma_jfr = to_udma_jfr(cfg->jfr);
	} else {
		jetty->shared_jfr = false;
		jetty->udma_jfr = get_udma_jfr(&dev->ub_dev, srqn);
		if (!jetty->udma_jfr) {
			dev_err(dev->dev,
				"failed to find jfr, srqn:%u.\n", srqn);
			return -EINVAL;
		}
	}

	return 0;
}

static int alloc_jetty_um_qp(struct udma_dev *dev, struct udma_jetty *jetty,
			     struct ubcore_jetty_cfg *cfg,
			     struct ubcore_udata *udata)
{
	int ret;

	udma_fill_jetty_um_qp_attr(dev, jetty, udata->uctx, cfg);

	ret = udma_create_qp_common(dev, &jetty->qp, udata);
	if (ret) {
		dev_err(dev->dev, "failed create qp for um jetty.\n");
		return ret;
	}

	ret = udma_init_qpc(dev, &jetty->qp);
	if (ret) {
		udma_destroy_qp_common(dev, &jetty->qp, NULL);
		return ret;
	}

	jetty->qp.state = QPS_RESET;
	ret = udma_modify_qp_jetty(dev, jetty, QPS_RTS);
	if (ret)
		udma_destroy_qp_common(dev, &jetty->qp, NULL);

	return ret;
}

static void set_jetty_ext_sge_param(struct udma_jetty *jetty)
{
	struct ubcore_jetty_cfg *jetty_cfg = &jetty->ubcore_jetty.jetty_cfg;
	uint32_t max_inline_data;
	uint32_t wqe_sge_cnt = 0;
	uint32_t total_sge_cnt;
	uint32_t ext_sge_cnt;
	uint32_t sq_wqe_cnt;
	uint32_t max_gs;

	sq_wqe_cnt = jetty->rc_node.wqe_cnt;
	jetty->rc_node.sge_shift = UDMA_SGE_SHIFT;
	max_inline_data = roundup_pow_of_two(jetty_cfg->max_inline_data);
	ext_sge_cnt = max_inline_data / UDMA_SGE_SIZE;

	max_gs = max_t(uint32_t, ext_sge_cnt, jetty_cfg->max_send_sge);
	if (max_gs > UDMA_SGE_IN_WQE)
		wqe_sge_cnt = max_gs - UDMA_SGE_IN_WQE;

	if (wqe_sge_cnt) {
		total_sge_cnt = roundup_pow_of_two(sq_wqe_cnt * wqe_sge_cnt);
		jetty->rc_node.sge_cnt = max(total_sge_cnt,
					     (uint32_t)UDMA_PAGE_SIZE /
					     UDMA_SGE_SIZE);
	}
}

static int set_jetty_buf_attr(struct udma_dev *udma_dev,
			      struct udma_jetty *jetty,
			      struct udma_buf_attr *buf_attr)
{
	uint32_t total_buff_size = 0;
	uint32_t cfg_depth;
	uint32_t buf_size;
	uint32_t idx = 0;

	/* SQ WQE */
	jetty->rc_node.sge_offset = 0;
	cfg_depth = roundup_pow_of_two(jetty->ubcore_jetty.jetty_cfg.jfs_depth);
	jetty->rc_node.wqe_cnt = cfg_depth < UDMA_MIN_JFS_DEPTH ?
				 UDMA_MIN_JFS_DEPTH : cfg_depth;
	jetty->rc_node.wqe_shift = UDMA_SQ_WQE_SHIFT;
	set_jetty_ext_sge_param(jetty);

	buf_size = to_udma_hem_entries_size(jetty->rc_node.wqe_cnt,
					    jetty->rc_node.wqe_shift);
	if (buf_size > 0) {
		buf_attr->region[idx].size = buf_size;
		buf_attr->region[idx].hopnum = udma_dev->caps.wqe_sq_hop_num;
		idx++;
		total_buff_size += buf_size;
	}
	/* extend SGE WQE in SQ */
	jetty->rc_node.sge_offset = total_buff_size;

	buf_size = to_udma_hem_entries_size(jetty->rc_node.sge_cnt,
					    jetty->rc_node.sge_shift);
	if (buf_size > 0) {
		buf_attr->region[idx].size = buf_size;
		buf_attr->region[idx].hopnum = udma_dev->caps.wqe_sge_hop_num;
		idx++;
		total_buff_size += buf_size;
	}

	if (total_buff_size < 1) {
		dev_err(udma_dev->dev, "jetty buf size is invalid, size = %u.\n",
			total_buff_size);
		return -EINVAL;
	}

	buf_attr->region_count = idx;
	buf_attr->mtt_only = false;
	buf_attr->page_shift = UDMA_HW_PAGE_SHIFT;

	return 0;
}

static int alloc_jetty_buf(struct udma_dev *dev, struct udma_jetty *jetty,
			   struct ubcore_jetty_cfg *cfg, struct ubcore_udata *udata)
{
	struct udma_create_jetty_ucmd ucmd = {};
	struct udma_buf_attr buf_attr = {};
	int ret;

	if (!udata)
		return -EINVAL;

	ret = copy_from_user(&ucmd, (void *)udata->udrv_data->in_addr,
			     min(udata->udrv_data->in_len,
				 (uint32_t)sizeof(ucmd)));
	if (ret) {
		dev_err(dev->dev,
			"failed to copy jetty udata, ret = %d.\n",
			ret);
		return -EFAULT;
	}

	ret = set_jetty_jfr(dev, jetty, cfg, ucmd.jfr_id);
	if (ret)
		return ret;

	if (cfg->trans_mode == UBCORE_TP_UM) {
		ret = alloc_jetty_um_qp(dev, jetty, cfg, udata);
		if (ret)
			return ret;
	} else if (cfg->trans_mode == UBCORE_TP_RM) {
		xa_init(&jetty->srm_node_table);
	} else if (cfg->trans_mode == UBCORE_TP_RC) {
		ret = udma_db_map_user(dev, ucmd.sdb_addr, &jetty->rc_node.sdb);
		if (ret) {
			dev_err(dev->dev,
				"failed to map user sdb_addr, ret = %d.\n",
				ret);
			return ret;
		}

		jetty->rc_node.buf_addr = ucmd.buf_addr;
		jetty->rc_node.context = to_udma_ucontext(udata->uctx);
		if (!ucmd.buf_addr) {
			jetty->dca_en = true;
			return 0;
		}

		ret = set_jetty_buf_attr(dev, jetty, &buf_attr);
		if (ret) {
			dev_err(dev->dev,
				"failed to set jetty buf attr, ret = %d.\n",
				ret);
			return ret;
		}

		if (!jetty->shared_jfr) {
			jetty->rc_node.mtr = jetty->udma_jfr->buf_mtr;
			return 0;
		}

		ret = udma_mtr_create(dev, &jetty->rc_node.mtr, &buf_attr,
				      PAGE_SHIFT + dev->caps.mtt_ba_pg_sz,
				      ucmd.buf_addr, !!udata);
		if (ret) {
			dev_err(dev->dev,
				"failed to create WQE mtr for RC Jetty, ret = %d.\n",
				ret);
			udma_db_unmap_user(dev, &jetty->rc_node.sdb);
			return ret;
		}
	}

	return 0;
}

static int alloc_jetty_id(struct udma_dev *udma_dev, struct udma_jetty *jetty)
{
	struct udma_jetty_table *jetty_table = &udma_dev->jetty_table;
	struct udma_ida *jetty_ida = &jetty_table->jetty_ida;
	int ret;
	int id;

	id = ida_alloc_range(&jetty_ida->ida, jetty_ida->min, jetty_ida->max,
			     GFP_KERNEL);
	if (id < 0) {
		dev_err(udma_dev->dev, "failed to alloc jetty_id(%d).\n", id);
		return id;
	}
	jetty->jetty_id = (uint32_t)id;
	jetty->ubcore_jetty.id = jetty->jetty_id;

	ret = xa_err(xa_store(&jetty_table->xa, jetty->jetty_id, jetty,
			      GFP_KERNEL));
	if (ret) {
		dev_err(udma_dev->dev, "failed to store Jetty, ret = %d.\n",
			ret);
		ida_free(&jetty_ida->ida, id);
	}

	return ret;
}

static int alloc_common_jetty_id(struct udma_dev *udma_dev, struct udma_jetty *jetty)
{
	struct udma_jetty_table *jetty_table = &udma_dev->jetty_table;
	int ret;

	ret = alloc_common_qpn(udma_dev, jetty->send_jfc, &jetty->jetty_id);
	if (ret)
		return ret;

	ret = xa_err(xa_store(&jetty_table->xa, jetty->jetty_id, jetty, GFP_KERNEL));
	if (ret) {
		dev_err(udma_dev->dev, "failed to store Jetty, ret = %d.\n",
			ret);
		free_common_qpn(udma_dev, jetty->jetty_id);
		return ret;
	}
	jetty->ubcore_jetty.id = jetty->jetty_id;

	return ret;
}

static void free_common_jetty_id(struct udma_dev *udma_dev, struct udma_jetty *jetty)
{
	xa_erase(&udma_dev->jetty_table.xa, jetty->jetty_id);
	free_common_qpn(udma_dev, jetty->jetty_id);
}

static void store_jetty_id(struct udma_dev *udma_dev, struct udma_jetty *jetty)
{
	struct jetty_list *jetty_new;
	struct jetty_list *jetty_now;
	unsigned long flags;
	spinlock_t *lock;
	int ret;
	int i;

	ret = udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return;

	jetty_new = kzalloc(sizeof(struct jetty_list), GFP_KERNEL);
	if (!jetty_new) {
		read_unlock(&g_udma_dfx_list[i].rwlock);
		return;
	}

	lock = &g_udma_dfx_list[i].dfx->jetty_list->node_lock;
	spin_lock_irqsave(lock, flags);
	list_for_each_entry(jetty_now,
			    &g_udma_dfx_list[i].dfx->jetty_list->node, node) {
		if (jetty_now->jetty_id == jetty->jetty_id) {
			jetty_now->jfs_depth =
				jetty->ubcore_jetty.jetty_cfg.jfs_depth;
			jetty_now->jfr_depth =
				jetty->ubcore_jetty.jetty_cfg.jfr_depth;
			jetty_now->pri =
				jetty->ubcore_jetty.jetty_cfg.priority;
			jetty_now->jfr_id = jetty->udma_jfr->jfrn;
			jetty_now->jfc_s_id = jetty->ubcore_jetty.jetty_cfg.send_jfc->id;
			jetty_now->jfc_r_id = jetty->ubcore_jetty.jetty_cfg.recv_jfc->id;
			goto found;
		}
	}

	jetty_new->jetty_id = jetty->jetty_id;
	jetty_new->jfs_depth = jetty->ubcore_jetty.jetty_cfg.jfs_depth;
	jetty_new->jfr_depth = jetty->ubcore_jetty.jetty_cfg.jfr_depth;
	jetty_new->pri = jetty->ubcore_jetty.jetty_cfg.priority;
	jetty_new->jfr_id = jetty->udma_jfr->jfrn;
	jetty_new->jfc_s_id = jetty->ubcore_jetty.jetty_cfg.send_jfc->id;
	jetty_new->jfc_r_id = jetty->ubcore_jetty.jetty_cfg.recv_jfc->id;
	list_add(&jetty_new->node, &g_udma_dfx_list[i].dfx->jetty_list->node);
	++g_udma_dfx_list[i].dfx->jetty_cnt;
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_udma_dfx_list[i].rwlock);

	return;

found:
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_udma_dfx_list[i].rwlock);
	kfree(jetty_new);
}

static void delete_jetty_id(struct udma_dev *udma_dev,
			    struct udma_jetty *jetty)
{
	struct jetty_list *jetty_now, *jetty_tmp;
	unsigned long flags;
	spinlock_t *lock;
	int ret;
	int i;

	ret = udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return;

	lock = &g_udma_dfx_list[i].dfx->jetty_list->node_lock;
	spin_lock_irqsave(lock, flags);
	list_for_each_entry_safe(jetty_now, jetty_tmp,
				 &g_udma_dfx_list[i].dfx->jetty_list->node,
				 node) {
		if (jetty_now->jetty_id == jetty->jetty_id) {
			list_del(&jetty_now->node);
			--g_udma_dfx_list[i].dfx->jetty_cnt;
			kfree(jetty_now);
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_udma_dfx_list[i].rwlock);
}

static void free_jetty_id(struct udma_dev *udma_dev, struct udma_jetty *jetty)
{
	struct udma_jetty_table *jetty_table = &udma_dev->jetty_table;
	struct udma_ida *jetty_ida = &jetty_table->jetty_ida;

	xa_erase(&jetty_table->xa, jetty->jetty_id);
	ida_free(&jetty_ida->ida, (int)jetty->jetty_id);
}

struct ubcore_jetty *udma_create_jetty(struct ubcore_device *dev,
				       struct ubcore_jetty_cfg *cfg,
				       struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct udma_jetty *jetty;
	int ret;

	if (!udma_dev->rm_support && cfg->trans_mode == UBCORE_TP_RM) {
		dev_err(udma_dev->dev, "RM mode jetty is not supported.\n");
		return NULL;
	}

	jetty = kzalloc(sizeof(struct udma_jetty), GFP_KERNEL);
	if (!jetty)
		return NULL;

	init_jetty_cfg(jetty, cfg);
	if (cfg->trans_mode == UBCORE_TP_RM)
		ret = alloc_jetty_id(udma_dev, jetty);
	else
		ret = alloc_common_jetty_id(udma_dev, jetty);
	if (ret)
		goto err_alloc_jetty_id;

	if (cfg->trans_mode == UBCORE_TP_RM)
		init_jetty_x_qpn_bitmap(udma_dev, &jetty->qpn_map,
					udma_dev->caps.num_jetty_shift,
					UDMA_JETTY_QPN_PREFIX, jetty->jetty_id);

	ret = alloc_jetty_buf(udma_dev, jetty, cfg, udata);
	if (ret) {
		dev_err(udma_dev->dev, "alloc Jetty buf failed.\n");
		goto err_alloc_jetty_buf;
	}

	mutex_init(&jetty->tp_mutex);

	if (dfx_switch)
		store_jetty_id(udma_dev, jetty);

	return &jetty->ubcore_jetty;

err_alloc_jetty_buf:
	if (cfg->trans_mode == UBCORE_TP_RM)
		clean_jetty_x_qpn_bitmap(&jetty->qpn_map);
	if (cfg->trans_mode == UBCORE_TP_RM)
		free_jetty_id(udma_dev, jetty);
	else
		free_common_jetty_id(udma_dev, jetty);
err_alloc_jetty_id:
	kfree(jetty);

	return NULL;
}

static int free_jetty_buf(struct udma_dev *dev, struct udma_jetty *jetty)
{
	int ret = 0;

	if (jetty->tp_mode == UBCORE_TP_UM) {
		ret = udma_modify_qp_jetty(dev, jetty, QPS_RESET);
		if (ret)
			dev_err(dev->dev,
				"modify qp(0x%llx) to RESET failed for um jetty.\n",
				jetty->qp.qpn);

		udma_destroy_qp_common(dev, &jetty->qp, NULL);
	} else if (jetty->tp_mode == UBCORE_TP_RC && !jetty->dca_en) {
		udma_db_unmap_user(dev, &jetty->rc_node.sdb);
		if (jetty->shared_jfr)
			udma_mtr_destroy(dev, &jetty->rc_node.mtr);
	}

	return ret;
}

int udma_destroy_jetty(struct ubcore_jetty *jetty)
{
	struct udma_jetty *udma_jetty;
	struct udma_dev *udma_dev;
	int ret;

	udma_jetty = to_udma_jetty(jetty);
	udma_dev = to_udma_dev(jetty->ub_dev);

	ret = free_jetty_buf(udma_dev, udma_jetty);
	if (udma_jetty->tp_mode == UBCORE_TP_RM)
		clean_jetty_x_qpn_bitmap(&udma_jetty->qpn_map);

	if (dfx_switch)
		delete_jetty_id(udma_dev, udma_jetty);

	if (udma_jetty->tp_mode == UBCORE_TP_RM)
		free_jetty_id(udma_dev, udma_jetty);
	else
		free_common_jetty_id(udma_dev, udma_jetty);
	kfree(udma_jetty);

	return ret;
}

struct ubcore_tjetty *udma_import_jetty(struct ubcore_device *dev,
					struct ubcore_tjetty_cfg *cfg,
					struct ubcore_udata *udata)
{
	struct ubcore_tjetty *tjetty;

	tjetty = kcalloc(1, sizeof(struct ubcore_tjetty), GFP_KERNEL);
	if (!tjetty)
		return NULL;

	return tjetty;
}

int udma_unimport_jetty(struct ubcore_tjetty *tjetty)
{
	kfree(tjetty);

	return 0;
}
