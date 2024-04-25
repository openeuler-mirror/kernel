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

#include "urma/ubcore_uapi.h"
#include "hns3_udma_abi.h"
#include "hns3_udma_hem.h"
#include "hns3_udma_tp.h"
#include "hns3_udma_jfc.h"
#include "hns3_udma_dfx.h"
#include "hns3_udma_jfs.h"

static int init_jfs_cfg(struct udma_dev *dev, struct udma_jfs *jfs,
			struct ubcore_jfs_cfg *cfg)
{
	if (!cfg->depth || cfg->depth > dev->caps.max_wqes ||
	    cfg->max_sge > dev->caps.max_sq_sg) {
		dev_err(dev->dev, "invalid jfs cfg, depth = %u, sge = %u.\n",
			cfg->depth, cfg->max_sge);
		return -EINVAL;
	}
	memcpy(&jfs->ubcore_jfs.jfs_cfg, cfg, sizeof(struct ubcore_jfs_cfg));
	jfs->jfc = to_udma_jfc(cfg->jfc);
	jfs->tp_mode = cfg->trans_mode;

	return 0;
}

static int udma_modify_jfs_um_qp(struct udma_dev *dev, struct udma_jfs *jfs,
				 enum udma_qp_state target_state)
{
	union ubcore_tp_attr_mask ubcore_attr_mask;
	struct udma_modify_tp_attr m_attr = {};
	struct udma_qp *qp;
	int ret;

	qp = &jfs->um_qp;
	qp->udma_device = dev;
	qp->send_jfc = qp->qp_attr.send_jfc;
	qp->recv_jfc = qp->qp_attr.recv_jfc;

	m_attr.sgid_index = qp->qp_attr.eid_index;
	ubcore_attr_mask.value = 0;
	qp->m_attr = &m_attr;

	ret = udma_modify_qp_common(qp, NULL, ubcore_attr_mask, qp->state, target_state);
	if (ret)
		dev_err(dev->dev, "failed to modify qpc to RTS.\n");

	jfs->um_qp.state = target_state;

	return ret;
}

static void udma_fill_jfs_um_qp_attr(struct udma_dev *dev, struct udma_jfs *jfs,
				     struct udma_qp_attr *qp_attr,
				     struct ubcore_ucontext *uctx,
				     struct ubcore_jfs_cfg *cfg)
{
	struct udma_ucontext *udma_ctx = to_udma_ucontext(uctx);

	qp_attr->is_tgt = false;
	qp_attr->is_jetty = false;
	qp_attr->jfs = jfs;
	qp_attr->uctx = uctx;
	qp_attr->pdn = udma_ctx->pdn;
	qp_attr->cap.max_send_wr = cfg->depth;
	qp_attr->cap.max_send_sge = cfg->max_sge;
	qp_attr->cap.max_inline_data = cfg->max_inline_data;
	qp_attr->cap.rnr_retry = cfg->rnr_retry;
	qp_attr->cap.ack_timeout = cfg->err_timeout;
	qp_attr->qp_type = QPT_UD;
	qp_attr->recv_jfc = NULL;
	qp_attr->send_jfc = to_udma_jfc(cfg->jfc);
	qp_attr->eid_index = udma_ctx->eid_index;
	if (jfs->ubcore_jfs.jfs_cfg.priority >= dev->caps.sl_num) {
		qp_attr->priority = dev->caps.sl_num > 0 ?
				    dev->caps.sl_num - 1 : 0;
		dev_err(dev->dev,
			"set priority (%u) should smaller than the MAX (%u), (%u) is used\n",
			jfs->ubcore_jfs.jfs_cfg.priority, dev->caps.sl_num,
			qp_attr->priority);
	} else {
		qp_attr->priority = jfs->ubcore_jfs.jfs_cfg.priority;
	}
}

static int create_jfs_um_qp(struct udma_dev *dev, struct udma_jfs *jfs,
			    struct ubcore_jfs_cfg *cfg, struct ubcore_udata *udata)
{
	int ret;

	udma_fill_jfs_um_qp_attr(dev, jfs, &jfs->um_qp.qp_attr, udata->uctx, cfg);
	jfs->um_qp.qp_attr.qpn_map = &jfs->qpn_map;
	ret = udma_create_qp_common(dev, &jfs->um_qp, udata);
	if (ret) {
		dev_err(dev->dev, "failed to create qp for um jfs.\n");
		return ret;
	}

	ret = udma_init_qpc(dev, &jfs->um_qp);
	if (ret)
		udma_destroy_qp_common(dev, &jfs->um_qp, NULL);

	return ret;
}

static int destroy_jfs_qp(struct udma_dev *dev, struct udma_jfs *jfs)
{
	int ret = 0;

	ret = udma_modify_jfs_um_qp(dev, jfs, QPS_RESET);
	if (ret)
		dev_err(dev->dev,
			"failed to modify qp(0x%llx) to RESET for um jfs.\n",
			jfs->um_qp.qpn);

	udma_destroy_qp_common(dev, &jfs->um_qp, NULL);

	return ret;
}

static int alloc_jfs_buf(struct udma_dev *udma_dev, struct udma_jfs *jfs,
			 struct ubcore_jfs_cfg *cfg,
			 struct ubcore_udata *udata)
{
	struct hns3_udma_create_jfs_ucmd ucmd = {};
	int ret = 0;

	if (udata) {
		ret = copy_from_user(&ucmd, (void *)udata->udrv_data->in_addr,
				     min(udata->udrv_data->in_len,
					 (uint32_t)sizeof(ucmd)));
		if (ret) {
			dev_err(udma_dev->dev,
				"failed to copy jfs udata, ret = %d.\n", ret);
			return -EFAULT;
		}
	}

	ret = create_jfs_um_qp(udma_dev, jfs, cfg, udata);
	if (ret)
		return ret;

	jfs->um_qp.state = QPS_RESET;
	ret = udma_modify_jfs_um_qp(udma_dev, jfs, QPS_RTS);
	if (ret)
		udma_destroy_qp_common(udma_dev, &jfs->um_qp, NULL);

	return ret;
}

static int alloc_jfs_id(struct udma_dev *udma_dev, struct udma_jfs *jfs)
{
	struct udma_jfs_table *jfs_table = &udma_dev->jfs_table;
	int ret;

	ret = alloc_common_qpn(udma_dev, jfs->jfc, &jfs->jfs_id);
	if (ret) {
		dev_err(udma_dev->dev, "failed to alloc common jfs_id(%d).\n",
			ret);
		return ret;
	}

	ret = xa_err(xa_store(&jfs_table->xa, jfs->jfs_id, jfs, GFP_KERNEL));
	if (ret) {
		dev_err(udma_dev->dev, "failed to store JFS, ret = %d.\n", ret);
		goto store_err;
	}

	jfs->ubcore_jfs.id = jfs->jfs_id;

	return ret;
store_err:
	free_common_qpn(udma_dev, jfs->jfs_id);

	return ret;
}

static void store_jfs_id(struct udma_dev *udma_dev, struct udma_jfs *jfs)
{
	struct jfs_list *jfs_new;
	struct jfs_list *jfs_now;
	unsigned long flags;
	spinlock_t *lock;
	int ret;
	int i;

	ret = udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return;

	jfs_new = kzalloc(sizeof(struct jfs_list), GFP_KERNEL);
	if (!jfs_new) {
		read_unlock(&g_udma_dfx_list[i].rwlock);
		return;
	}

	lock = &g_udma_dfx_list[i].dfx->jfs_list->node_lock;
	spin_lock_irqsave(lock, flags);
	list_for_each_entry(jfs_now,
			    &g_udma_dfx_list[i].dfx->jfs_list->node, node) {
		if (jfs_now->jfs_id == jfs->jfs_id) {
			jfs_now->depth = jfs->ubcore_jfs.jfs_cfg.depth;
			jfs_now->pri = jfs->ubcore_jfs.jfs_cfg.priority;
			jfs_now->jfc_id = jfs->ubcore_jfs.jfs_cfg.jfc->id;
			goto found;
		}
	}

	jfs_new->jfs_id = jfs->jfs_id;
	jfs_new->depth = jfs->ubcore_jfs.jfs_cfg.depth;
	jfs_new->pri = jfs->ubcore_jfs.jfs_cfg.priority;
	jfs_new->jfc_id = jfs->ubcore_jfs.jfs_cfg.jfc->id;
	list_add(&jfs_new->node, &g_udma_dfx_list[i].dfx->jfs_list->node);
	++g_udma_dfx_list[i].dfx->jfs_cnt;
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_udma_dfx_list[i].rwlock);

	return;

found:
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_udma_dfx_list[i].rwlock);
	kfree(jfs_new);
}

static void delete_jfs_id(struct udma_dev *udma_dev, struct udma_jfs *jfs)
{
	struct jfs_list *jfs_now, *jfs_tmp;
	unsigned long flags;
	spinlock_t *lock;
	int ret;
	int i;

	ret = udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return;

	lock = &g_udma_dfx_list[i].dfx->jfs_list->node_lock;
	spin_lock_irqsave(lock, flags);
	list_for_each_entry_safe(jfs_now, jfs_tmp,
				 &g_udma_dfx_list[i].dfx->jfs_list->node,
				 node) {
		if (jfs_now->jfs_id == jfs->jfs_id) {
			list_del(&jfs_now->node);
			--g_udma_dfx_list[i].dfx->jfs_cnt;
			kfree(jfs_now);
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_udma_dfx_list[i].rwlock);
}

static void free_jfs_id(struct udma_dev *udma_dev, struct udma_jfs *jfs)
{
	struct udma_jfs_table *jfs_table = &udma_dev->jfs_table;

	xa_erase(&jfs_table->xa, jfs->jfs_id);
	free_common_qpn(udma_dev, jfs->jfs_id);
}

struct ubcore_jfs *udma_create_jfs(struct ubcore_device *dev, struct ubcore_jfs_cfg *cfg,
				   struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct udma_jfs *jfs;
	int ret;

	jfs = kcalloc(1, sizeof(struct udma_jfs), GFP_KERNEL);
	if (!jfs)
		return NULL;

	ret = init_jfs_cfg(udma_dev, jfs, cfg);
	if (ret)
		goto err_init_cfg;

	ret = alloc_jfs_id(udma_dev, jfs);
	if (ret)
		goto err_alloc_jfs_id;

	ret = alloc_jfs_buf(udma_dev, jfs, cfg, udata);
	if (ret) {
		dev_err(udma_dev->dev, "alloc jfs buf failed.\n");
		goto err_alloc_jfs_buf;
	}

	if (dfx_switch)
		store_jfs_id(udma_dev, jfs);

	return &jfs->ubcore_jfs;

err_alloc_jfs_buf:
	free_jfs_id(udma_dev, jfs);
err_alloc_jfs_id:
err_init_cfg:
	kfree(jfs);

	return NULL;
}

int udma_destroy_jfs(struct ubcore_jfs *jfs)
{
	struct udma_dev *udma_dev = to_udma_dev(jfs->ub_dev);
	struct udma_jfs *udma_jfs = to_udma_jfs(jfs);

	destroy_jfs_qp(udma_dev, udma_jfs);

	if (dfx_switch)
		delete_jfs_id(udma_dev, udma_jfs);

	free_jfs_id(udma_dev, udma_jfs);

	kfree(udma_jfs);

	return 0;
}
