// SPDX-License-Identifier: GPL-2.0
/* Huawei HNS3_UDMA Linux driver
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

#include <linux/vmalloc.h>
#include "hns3_udma_hem.h"
#include "hns3_udma_cmd.h"
#include "hns3_udma_db.h"
#include "hns3_udma_jfc.h"
#include "hns3_udma_dfx.h"

static int hns3_udma_hw_create_cq(struct hns3_udma_dev *dev,
				  struct hns3_udma_cmd_mailbox *mailbox, uint32_t cqn)
{
	struct hns3_udma_cmq_desc desc;
	struct hns3_udma_mbox *mb;

	mb = (struct hns3_udma_mbox *)desc.data;
	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_POST_MB, false);
	mbox_desc_init(mb, mailbox->dma, 0, cqn, HNS3_UDMA_CMD_CREATE_CQC);

	return hns3_udma_cmd_mbox(dev, &desc, HNS3_UDMA_CMD_TIMEOUT_MSECS, 0);
}

static int hns3_udma_hw_destroy_cq(struct hns3_udma_dev *dev, uint32_t cqn)
{
	struct hns3_udma_cmq_desc desc;
	struct hns3_udma_mbox *mb;

	mb = (struct hns3_udma_mbox *)desc.data;
	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_POST_MB, false);
	mbox_desc_init(mb, 0, 0, cqn, HNS3_UDMA_CMD_DESTROY_CQC);

	return hns3_udma_cmd_mbox(dev, &desc, HNS3_UDMA_CMD_TIMEOUT_MSECS, 0);
}

static int check_jfc_cfg(struct hns3_udma_dev *udma_dev, struct ubcore_jfc_cfg *cfg)
{
	if (!cfg->depth || cfg->depth > udma_dev->caps.max_cqes) {
		dev_err(udma_dev->dev,
			"failed to check jfc attr depth = 0x%x.\n",
			cfg->depth);
		return -EINVAL;
	}

	if (cfg->ceqn >= udma_dev->caps.num_comp_vectors) {
		dev_err(udma_dev->dev, "failed to check ceqn = %u, max = %d.\n",
			cfg->ceqn, udma_dev->caps.num_comp_vectors);
		return -EINVAL;
	}

	return 0;
}

static int check_poe_attr(struct hns3_udma_dev *udma_dev,
			  struct hns3_udma_jfc_attr_ex *jfc_attr_ex)
{
	if (!(udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_POE)) {
		dev_err(udma_dev->dev, "Unsupport POE JFC.\n");
		return -EINVAL;
	}

	return 0;
}

static int check_notify_attr(struct hns3_udma_dev *udma_dev,
			     struct hns3_udma_jfc_attr_ex *jfc_attr_ex)
{
	if (!(udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_WRITE_NOTIFY)) {
		dev_err(udma_dev->dev, "Unsupport NOTIFY JFC.\n");
		return -EINVAL;
	}

	switch (jfc_attr_ex->notify_mode) {
	case HNS3_UDMA_JFC_NOTIFY_MODE_4B_ALIGN:
	case HNS3_UDMA_JFC_NOTIFY_MODE_DDR_4B_ALIGN:
		break;
	case HNS3_UDMA_JFC_NOTIFY_MODE_64B_ALIGN:
	case HNS3_UDMA_JFC_NOTIFY_MODE_DDR_64B_ALIGN:
		dev_err(udma_dev->dev, "Doesn't support notify mode %u.\n",
			jfc_attr_ex->notify_mode);
		return -EINVAL;
	default:
		dev_err(udma_dev->dev, "Invalid notify mode %u.\n",
			jfc_attr_ex->notify_mode);
		return -EINVAL;
	}

	if (jfc_attr_ex->notify_addr & HNS3_UDMA_ADDR_4K_MASK) {
		dev_err(udma_dev->dev,
			"Notify addr should be aligned to 4k.\n");
		return -EINVAL;
	}

	return 0;
}

static int check_jfc_attr_ex(struct hns3_udma_dev *udma_dev,
			     struct hns3_udma_jfc_attr_ex *jfc_attr_ex)
{
	int ret;

	switch (jfc_attr_ex->create_flags) {
	case HNS3_UDMA_JFC_CREATE_ENABLE_POE_MODE:
		ret = check_poe_attr(udma_dev, jfc_attr_ex);
		break;
	case HNS3_UDMA_JFC_CREATE_ENABLE_NOTIFY:
		ret = check_notify_attr(udma_dev, jfc_attr_ex);
		break;
	default:
		dev_err(udma_dev->dev, "Invalid create flags %llu.\n",
			jfc_attr_ex->create_flags);
		return -EINVAL;
	}

	return ret;
}

static int check_create_jfc(struct hns3_udma_dev *udma_dev,
			    struct ubcore_jfc_cfg *cfg,
			    struct hns3_udma_create_jfc_ucmd *ucmd,
			    struct ubcore_udata *udata)
{
	unsigned long byte;
	int ret;

	if (!udata || !udata->udrv_data) {
		dev_err(udma_dev->dev, "jfc udata or udrv_data is null.\n");
		return -EINVAL;
	}

	if (!udata->udrv_data->in_addr ||
	    udata->udrv_data->in_len < sizeof(struct hns3_udma_create_jfc_ucmd)) {
		dev_err(udma_dev->dev, "Invalid jfc in_len %u or addr is null.\n",
			udata->udrv_data->in_len);
		return -EINVAL;
	}

	byte = copy_from_user((void *)ucmd, (void *)udata->udrv_data->in_addr,
			      sizeof(struct hns3_udma_create_jfc_ucmd));
	if (byte) {
		dev_err(udma_dev->dev,
			"failed to copy JFC udata, byte = %lu.\n", byte);
		return -EFAULT;
	}

	ret = check_jfc_cfg(udma_dev, cfg);
	if (ret) {
		dev_err(udma_dev->dev, "failed to check JFC cfg.\n");
		return ret;
	}

	if (ucmd->jfc_attr_ex.jfc_ex_mask &
	    HNS3_UDMA_JFC_NOTIFY_OR_POE_CREATE_FLAGS) {
		if (udma_dev->notify_addr)
			ucmd->jfc_attr_ex.notify_addr = udma_dev->notify_addr;

		ret = check_jfc_attr_ex(udma_dev, &ucmd->jfc_attr_ex);
		if (ret) {
			dev_err(udma_dev->dev,
				"failed to check JFC attr ex.\n");
			return ret;
		}
	}

	return 0;
}

static void set_jfc_param(struct hns3_udma_jfc *udma_jfc, struct ubcore_jfc_cfg *cfg)
{
	udma_jfc->jfc_depth = roundup_pow_of_two(cfg->depth);
	memcpy(&udma_jfc->ubcore_jfc.jfc_cfg, cfg, sizeof(struct ubcore_jfc_cfg));
}

static void init_jfc(struct hns3_udma_jfc *udma_jfc, struct hns3_udma_create_jfc_ucmd *ucmd)
{
	spin_lock_init(&udma_jfc->lock);
	INIT_LIST_HEAD(&udma_jfc->sq_list);
	INIT_LIST_HEAD(&udma_jfc->rq_list);
	if (ucmd->jfc_attr_ex.jfc_ex_mask & HNS3_UDMA_JFC_NOTIFY_OR_POE_CREATE_FLAGS)
		udma_jfc->jfc_attr_ex = ucmd->jfc_attr_ex;
}

static int alloc_jfc_cqe_buf(struct hns3_udma_dev *dev, struct hns3_udma_jfc *jfc,
			     struct ubcore_udata *udata, uint64_t addr)
{
	struct hns3_udma_buf_attr buf_attr = {};
	int ret;

	buf_attr.page_shift = PAGE_SHIFT;
	buf_attr.region[0].size = jfc->jfc_depth * dev->caps.cqe_sz;
	buf_attr.region[0].hopnum = dev->caps.cqe_hop_num;
	buf_attr.region_count = 1;
	ret = hns3_udma_mtr_create(dev, &jfc->mtr, &buf_attr,
			      dev->caps.cqe_ba_pg_sz + PAGE_SHIFT,
			      addr, udata ? true : false);
	if (ret)
		dev_err(dev->dev,
			"failed to alloc JFC buf, ret = %d.\n", ret);

	return ret;
}

static void free_jfc_cqe_buf(struct hns3_udma_dev *dev, struct hns3_udma_jfc *jfc)
{
	hns3_udma_mtr_destroy(dev, &jfc->mtr);
}

static int alloc_jfc_buf(struct hns3_udma_dev *udma_dev, struct hns3_udma_jfc *udma_jfc,
			 struct ubcore_udata *udata,
			 struct hns3_udma_create_jfc_ucmd *ucmd)
{
	struct hns3_udma_ucontext *udma_uctx = to_hns3_udma_ucontext(udata->uctx);
	struct hns3_udma_create_jfc_resp resp = {};
	unsigned long byte;
	int ret;

	if (!udata->udrv_data->out_addr ||
	    udata->udrv_data->out_len < sizeof(resp)) {
		dev_err(udma_dev->dev,
			"Invalid jfc out: len %u or addr is null.\n",
			udata->udrv_data->out_len);
		return -EINVAL;
	}

	ret = alloc_jfc_cqe_buf(udma_dev, udma_jfc, udata, ucmd->buf_addr);
	if (ret)
		return ret;

	if (udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_CQ_RECORD_DB) {
		ret = hns3_udma_db_map_user(udma_uctx, ucmd->db_addr, &udma_jfc->db);
		if (ret) {
			dev_err(udma_dev->dev,
				"failed to map JFC db, ret = %d.\n", ret);
			goto db_err;
		}
		udma_jfc->jfc_caps |= HNS3_UDMA_JFC_CAP_RECORD_DB;
	}

	resp.jfc_caps = udma_jfc->jfc_caps;
	byte = copy_to_user((void *)udata->udrv_data->out_addr, &resp,
			    sizeof(resp));
	if (byte) {
		dev_err(udma_dev->dev,
			"failed to copy jfc resp, byte = %lu.\n", byte);
		ret = -EFAULT;
		goto err_copy;
	}

	refcount_set(&udma_jfc->refcount, 1);
	init_completion(&udma_jfc->free);
	udma_jfc->hns3_udma_uctx = udma_uctx;
	return ret;

err_copy:
	if (udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_CQ_RECORD_DB) {
		hns3_udma_db_unmap_user(udma_uctx, &udma_jfc->db);
		udma_jfc->jfc_caps &= ~HNS3_UDMA_JFC_CAP_RECORD_DB;
	}
db_err:
	free_jfc_cqe_buf(udma_dev, udma_jfc);

	return ret;
}

static void set_write_notify_param(struct hns3_udma_jfc *udma_jfc,
				   struct hns3_udma_jfc_context *jfc_context)
{
	uint8_t device_mode;

	if (udma_jfc->jfc_attr_ex.notify_mode == HNS3_UDMA_JFC_NOTIFY_MODE_4B_ALIGN)
		device_mode = HNS3_UDMA_NOTIFY_DEV;
	else
		device_mode = HNS3_UDMA_NOTIFY_DDR;

	hns3_udma_reg_enable(jfc_context, CQC_NOTIFY_EN);
	hns3_udma_reg_write(jfc_context, CQC_NOTIFY_DEVICE_EN, device_mode);
	/* Supports only 4B alignment. */
	hns3_udma_reg_write(jfc_context, CQC_NOTIFY_MODE, HNS3_UDMA_NOTIFY_MODE_4B);
	hns3_udma_reg_write(jfc_context, CQC_NOTIFY_ADDR_0,
			    (uint32_t)hns3_udma_get_field64(udma_jfc->jfc_attr_ex.notify_addr,
			    CQC_NOTIFY_ADDR_0_M, CQC_NOTIFY_ADDR_0_S));
	hns3_udma_reg_write(jfc_context, CQC_POE_QID,
			    (uint32_t)hns3_udma_get_field64(udma_jfc->jfc_attr_ex.notify_addr,
			    CQC_NOTIFY_ADDR_1_M, CQC_NOTIFY_ADDR_1_S));
	hns3_udma_reg_write(jfc_context, CQC_NOTIFY_ADDR_2,
			    (uint32_t)hns3_udma_get_field64(udma_jfc->jfc_attr_ex.notify_addr,
			    CQC_NOTIFY_ADDR_2_M, CQC_NOTIFY_ADDR_2_S));
	hns3_udma_reg_write(jfc_context, CQC_NOTIFY_ADDR_3,
			    (uint32_t)hns3_udma_get_field64(udma_jfc->jfc_attr_ex.notify_addr,
			    CQC_NOTIFY_ADDR_3_M, CQC_NOTIFY_ADDR_3_S));
	hns3_udma_reg_write(jfc_context, CQC_NOTIFY_ADDR_4,
			    (uint32_t)hns3_udma_get_field64(udma_jfc->jfc_attr_ex.notify_addr,
			    CQC_NOTIFY_ADDR_4_M, CQC_NOTIFY_ADDR_4_S));
	hns3_udma_reg_write(jfc_context, CQC_NOTIFY_ADDR_5,
			    (uint32_t)hns3_udma_get_field64(udma_jfc->jfc_attr_ex.notify_addr,
			    CQC_NOTIFY_ADDR_5_M, CQC_NOTIFY_ADDR_5_S));
	hns3_udma_reg_write(jfc_context, CQC_NOTIFY_ADDR_6,
			    (uint32_t)hns3_udma_get_field64(udma_jfc->jfc_attr_ex.notify_addr,
			    CQC_NOTIFY_ADDR_6_M, CQC_NOTIFY_ADDR_6_S));
}

static void hns3_udma_write_jfc_cqc(struct hns3_udma_dev *udma_dev, struct hns3_udma_jfc *udma_jfc,
				    void *mb_buf, uint64_t *mtts, uint64_t dma_handle)
{
	struct hns3_udma_jfc_context *jfc_context;

	jfc_context = (struct hns3_udma_jfc_context *)mb_buf;
	memset(jfc_context, 0, sizeof(*jfc_context));

	hns3_udma_reg_write(jfc_context, CQC_CQ_ST, CQ_STATE_VALID);
	hns3_udma_reg_write(jfc_context, CQC_ARM_ST, NO_ARMED);

	hns3_udma_reg_write(jfc_context, CQC_SHIFT, ilog2(udma_jfc->jfc_depth));
	hns3_udma_reg_write(jfc_context, CQC_CEQN, udma_jfc->ubcore_jfc.jfc_cfg.ceqn);
	hns3_udma_reg_write(jfc_context, CQC_CQN, udma_jfc->cqn);

	hns3_udma_reg_write(jfc_context, CQC_CQE_SIZE, CQE_SIZE_64B);

	hns3_udma_reg_write(jfc_context, CQC_CQE_CUR_BLK_ADDR_L,
		       to_hr_hw_page_addr(mtts[0]));
	hns3_udma_reg_write(jfc_context, CQC_CQE_CUR_BLK_ADDR_H,
		       upper_32_bits(to_hr_hw_page_addr(mtts[0])));
	hns3_udma_reg_write(jfc_context, CQC_CQE_HOP_NUM,
		       udma_dev->caps.cqe_hop_num ==
		       HNS3_UDMA_HOP_NUM_0 ? 0 : udma_dev->caps.cqe_hop_num);
	hns3_udma_reg_write(jfc_context, CQC_CQE_NEX_BLK_ADDR_L,
		       to_hr_hw_page_addr(mtts[1]));
	hns3_udma_reg_write(jfc_context, CQC_CQE_NEX_BLK_ADDR_H,
		       upper_32_bits(to_hr_hw_page_addr(mtts[1])));
	hns3_udma_reg_write(jfc_context, CQC_CQE_BAR_PG_SZ,
		       to_hr_hw_page_shift(udma_jfc->mtr.hem_cfg.ba_pg_shift));
	hns3_udma_reg_write(jfc_context, CQC_CQE_BUF_PG_SZ,
		       to_hr_hw_page_shift(udma_jfc->mtr.hem_cfg.buf_pg_shift));
	hns3_udma_reg_write(jfc_context, CQC_CQE_BA_L,
		       dma_handle >> CQC_CQE_BA_L_OFFSET);
	hns3_udma_reg_write(jfc_context, CQC_CQE_BA_H,
		       dma_handle >> CQC_CQE_BA_H_OFFSET);
	hns3_udma_reg_write(jfc_context, CQC_CQ_MAX_CNT, HNS3_UDMA_CQ_DEFAULT_BURST_NUM);
	hns3_udma_reg_write(jfc_context, CQC_CQ_PERIOD, HNS3_UDMA_CQ_DEFAULT_INTERVAL);
	if (udma_jfc->jfc_caps & HNS3_UDMA_JFC_CAP_RECORD_DB) {
		hns3_udma_reg_enable(jfc_context, CQC_DB_RECORD_EN);
		hns3_udma_reg_write(jfc_context, CQC_CQE_DB_RECORD_ADDR_L,
			       lower_32_bits(udma_jfc->db.dma) >>
			       DMA_DB_RECORD_SHIFT);
		hns3_udma_reg_write(jfc_context, CQC_CQE_DB_RECORD_ADDR_H,
			       upper_32_bits(udma_jfc->db.dma));
	}

	if (udma_jfc->jfc_attr_ex.create_flags ==
	    HNS3_UDMA_JFC_CREATE_ENABLE_POE_MODE) {
		hns3_udma_reg_enable(jfc_context, CQC_POE_EN);
		hns3_udma_reg_write(jfc_context, CQC_POE_NUM,
			       udma_jfc->jfc_attr_ex.poe_channel);
	}

	if (udma_jfc->jfc_attr_ex.create_flags == HNS3_UDMA_JFC_CREATE_ENABLE_NOTIFY)
		set_write_notify_param(udma_jfc, jfc_context);
}

static int hns3_udma_create_jfc_cqc(struct hns3_udma_dev *udma_dev,
				    struct hns3_udma_jfc *udma_jfc,
				    uint64_t *mtts, uint64_t dma_handle)
{
	struct hns3_udma_cmd_mailbox *mailbox;
	int ret;

	mailbox = hns3_udma_alloc_cmd_mailbox(udma_dev);
	if (IS_ERR(mailbox)) {
		dev_err(udma_dev->dev, "failed to alloc mailbox for CQC.\n");
		return PTR_ERR(mailbox);
	}

	hns3_udma_write_jfc_cqc(udma_dev, udma_jfc, mailbox->buf, mtts, dma_handle);

	ret = hns3_udma_hw_create_cq(udma_dev, mailbox, udma_jfc->cqn);
	if (ret)
		dev_err(udma_dev->dev,
			"failed to send create cmd for jfc(0x%llx), ret = %d.\n",
			udma_jfc->cqn, ret);

	hns3_udma_free_cmd_mailbox(udma_dev, mailbox);

	return ret;
}

static int alloc_jfc_cqc(struct hns3_udma_dev *udma_dev, struct hns3_udma_jfc *udma_jfc)
{
	struct hns3_udma_jfc_table *jfc_table = &udma_dev->jfc_table;
	uint64_t mtts[MTT_MIN_COUNT] = {};
	uint64_t dma_handle;
	int ret;

	ret = hns3_udma_mtr_find(udma_dev, &udma_jfc->mtr, 0, mtts,
				 ARRAY_SIZE(mtts), &dma_handle);
	if (!ret) {
		dev_err(udma_dev->dev,
			"failed to find JFC mtr, ret = %d.\n", ret);
		return -EINVAL;
	}

	ret = hns3_udma_table_get(udma_dev, &jfc_table->table, udma_jfc->cqn);
	if (ret) {
		dev_err(udma_dev->dev,
			"failed to get JFC(0x%llx) context, ret = %d.\n",
			udma_jfc->cqn, ret);
		return ret;
	}

	ret = xa_err(xa_store(&jfc_table->xa, udma_jfc->cqn, udma_jfc,
			      GFP_KERNEL));
	if (ret) {
		dev_err(udma_dev->dev, "failed to store JFC, ret = %d.\n", ret);
		goto err_put;
	}

	ret = hns3_udma_create_jfc_cqc(udma_dev, udma_jfc, mtts, dma_handle);
	if (ret)
		goto err_xa;

	udma_jfc->arm_sn = 1;
	return 0;

err_xa:
	xa_erase(&jfc_table->xa, udma_jfc->cqn);
err_put:
	hns3_udma_table_put(udma_dev, &jfc_table->table, udma_jfc->cqn);

	return ret;
}

static void store_jfc_id(struct hns3_udma_dev *udma_dev, struct hns3_udma_jfc *udma_jfc)
{
	struct jfc_list *jfc_new;
	struct jfc_list *jfc_now;
	unsigned long flags;
	spinlock_t *lock;
	int ret;
	int i;

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return;

	jfc_new = kzalloc(sizeof(struct jfc_list), GFP_KERNEL);
	if (!jfc_new) {
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
		return;
	}

	lock = &g_hns3_udma_dfx_list[i].dfx->jfc_list->node_lock;
	spin_lock_irqsave(lock, flags);
	list_for_each_entry(jfc_now,
			    &g_hns3_udma_dfx_list[i].dfx->jfc_list->node, node) {
		if (jfc_now->jfc_id == udma_jfc->cqn)
			goto found;
	}

	jfc_new->jfc_id = udma_jfc->cqn;
	list_add(&jfc_new->node, &g_hns3_udma_dfx_list[i].dfx->jfc_list->node);
	++g_hns3_udma_dfx_list[i].dfx->jfc_cnt;
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	return;

found:
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
	kfree(jfc_new);
}

static void delete_jfc_id(struct hns3_udma_dev *udma_dev, struct hns3_udma_jfc *udma_jfc)
{
	struct jfc_list *jfc_now, *jfc_tmp;
	unsigned long flags;
	spinlock_t *lock;
	int ret;
	int i;

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return;

	lock = &g_hns3_udma_dfx_list[i].dfx->jfc_list->node_lock;
	spin_lock_irqsave(lock, flags);
	list_for_each_entry_safe(jfc_now, jfc_tmp,
				 &g_hns3_udma_dfx_list[i].dfx->jfc_list->node,
				 node) {
		if (jfc_now->jfc_id == udma_jfc->cqn) {
			list_del(&jfc_now->node);
			--g_hns3_udma_dfx_list[i].dfx->jfc_cnt;
			kfree(jfc_now);
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
}

static void free_jfc_cqc(struct hns3_udma_dev *udma_dev, struct hns3_udma_jfc *udma_jfc)
{
	struct hns3_udma_jfc_table *jfc_table = &udma_dev->jfc_table;
	int ret;

	ret = hns3_udma_hw_destroy_cq(udma_dev, udma_jfc->cqn);
	if (ret)
		dev_err(udma_dev->dev, "destroy failed (%d) for JFC %llu.\n",
			ret, udma_jfc->cqn);

	xa_erase(&jfc_table->xa, udma_jfc->cqn);
}

static void free_jfc_buf(struct hns3_udma_dev *udma_dev, struct hns3_udma_jfc *udma_jfc)
{
	/* wait for all interrupt processed */
	if (refcount_dec_and_test(&udma_jfc->refcount))
		complete(&udma_jfc->free);
	wait_for_completion(&udma_jfc->free);

	if (udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_CQ_RECORD_DB)
		hns3_udma_db_unmap_user(udma_jfc->hns3_udma_uctx, &udma_jfc->db);
	hns3_udma_mtr_destroy(udma_dev, &udma_jfc->mtr);
}

void hns3_udma_put_cq_bankid_for_uctx(struct hns3_udma_ucontext *uctx)
{
	struct hns3_udma_dev *ub_dev = to_hns3_udma_dev(uctx->uctx.ub_dev);
	struct hns3_udma_jfc_table *jfc_table = &ub_dev->jfc_table;

	mutex_lock(&jfc_table->bank_mutex);
	jfc_table->ctx_num[uctx->cq_bank_id]--;
	mutex_unlock(&jfc_table->bank_mutex);
}

uint8_t hns3_udma_get_cq_bankid_for_uctx(struct hns3_udma_dev *ub_dev)
{
	struct hns3_udma_jfc_table *jfc_table = &ub_dev->jfc_table;
	uint32_t least_load;
	uint8_t bankid = 0;
	uint8_t i;

	mutex_lock(&jfc_table->bank_mutex);
	least_load = jfc_table->ctx_num[0];
	for (i = 1; i < HNS3_UDMA_CQ_BANK_NUM; i++) {
		if (jfc_table->ctx_num[i] < least_load) {
			least_load = jfc_table->ctx_num[i];
			bankid = i;
		}
	}
	jfc_table->ctx_num[bankid]++;
	mutex_unlock(&jfc_table->bank_mutex);

	return bankid;
}

static inline uint8_t select_cq_bankid(struct ubcore_udata *udata)
{
	struct hns3_udma_ucontext *uctx = to_hns3_udma_ucontext(udata->uctx);

	return uctx->cq_bank_id;
}

static int alloc_jfc_id(struct hns3_udma_dev *udma_dev, struct hns3_udma_jfc *udma_jfc,
			struct ubcore_udata *udata)
{
	struct hns3_udma_jfc_table *jfc_table = &udma_dev->jfc_table;
	struct hns3_udma_bank *bank;
	uint8_t bankid;
	int id;

	bankid = select_cq_bankid(udata);
	bank = &jfc_table->bank[bankid];

	id = ida_alloc_range(&bank->ida, bank->min, bank->max, GFP_KERNEL);
	if (id < 0)
		return id;

	/* the lower 2 bits is bankid */
	udma_jfc->cqn = (id << CQ_BANKID_SHIFT) | bankid;
	udma_jfc->ubcore_jfc.id = udma_jfc->cqn;

	return 0;
}

static void free_jfc_id(struct hns3_udma_dev *udma_dev, struct hns3_udma_jfc *udma_jfc)
{
	struct hns3_udma_jfc_table *jfc_table = &udma_dev->jfc_table;
	struct hns3_udma_bank *bank;

	bank = &jfc_table->bank[get_jfc_bankid(udma_jfc->cqn)];
	ida_free(&bank->ida, udma_jfc->cqn >> CQ_BANKID_SHIFT);
}

struct ubcore_jfc *hns3_udma_create_jfc(struct ubcore_device *dev, struct ubcore_jfc_cfg *cfg,
				   struct ubcore_udata *udata)
{
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(dev);
	struct hns3_udma_create_jfc_ucmd ucmd = {};
	struct hns3_udma_jfc *udma_jfc;
	int ret;

	ret = check_create_jfc(udma_dev, cfg, &ucmd, udata);
	if (ret)
		goto err;

	udma_jfc = kzalloc(sizeof(*udma_jfc), GFP_KERNEL);
	if (!udma_jfc)
		goto err;

	init_jfc(udma_jfc, &ucmd);

	set_jfc_param(udma_jfc, cfg);

	ret = alloc_jfc_buf(udma_dev, udma_jfc, udata, &ucmd);
	if (ret)
		goto err_jfc;

	ret = alloc_jfc_id(udma_dev, udma_jfc, udata);
	if (ret)
		goto err_jfc_buf;

	ret = alloc_jfc_cqc(udma_dev, udma_jfc);
	if (ret)
		goto err_jfc_id;

	if (dfx_switch)
		store_jfc_id(udma_dev, udma_jfc);

	return &udma_jfc->ubcore_jfc;

err_jfc_id:
	free_jfc_id(udma_dev, udma_jfc);
err_jfc_buf:
	free_jfc_buf(udma_dev, udma_jfc);
err_jfc:
	kfree(udma_jfc);
err:
	return NULL;
}

int hns3_udma_destroy_jfc(struct ubcore_jfc *jfc)
{
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(jfc->ub_dev);
	struct hns3_udma_jfc *udma_jfc = to_hns3_udma_jfc(jfc);

	free_jfc_cqc(udma_dev, udma_jfc);

	if (dfx_switch)
		delete_jfc_id(udma_dev, udma_jfc);

	free_jfc_id(udma_dev, udma_jfc);
	free_jfc_buf(udma_dev, udma_jfc);
	kfree(udma_jfc);

	return 0;
}

int hns3_udma_modify_jfc(struct ubcore_jfc *ubcore_jfc, struct ubcore_jfc_attr *attr,
			 struct ubcore_udata *udata)
{
	struct hns3_udma_dev *udma_device = to_hns3_udma_dev(ubcore_jfc->ub_dev);
	uint16_t cq_period = attr->moderate_period;
	uint16_t cq_count = attr->moderate_count;
	struct hns3_udma_jfc_context *jfc_context;
	struct hns3_udma_jfc_context *cqc_mask;
	struct hns3_udma_cmd_mailbox *mailbox;
	struct hns3_udma_cmq_desc desc;
	struct hns3_udma_mbox *mb;
	int ret;

	if (!(attr->mask & (UBCORE_JFC_MODERATE_COUNT |
			    UBCORE_JFC_MODERATE_PERIOD))) {
		dev_err(udma_device->dev,
			"JFC modify mask is not set or invalid.\n");
		return -EINVAL;
	}

	mailbox = hns3_udma_alloc_cmd_mailbox(udma_device);
	if (IS_ERR(mailbox)) {
		dev_err(udma_device->dev, "failed to alloc mailbox for CQ.\n");
		return -ENOMEM;
	}

	jfc_context = (struct hns3_udma_jfc_context *)mailbox->buf;
	cqc_mask = (struct hns3_udma_jfc_context *)mailbox->buf + 1;

	memset(cqc_mask, 0xff, sizeof(*cqc_mask));
	if (attr->mask & UBCORE_JFC_MODERATE_COUNT) {
		hns3_udma_reg_write(jfc_context, CQC_CQ_MAX_CNT, cq_count);
		hns3_udma_reg_clear(cqc_mask, CQC_CQ_MAX_CNT);
	}

	if (attr->mask & UBCORE_JFC_MODERATE_PERIOD) {
		hns3_udma_reg_write(jfc_context, CQC_CQ_PERIOD, cq_period);
		hns3_udma_reg_clear(cqc_mask, CQC_CQ_PERIOD);
	}

	mb = (struct hns3_udma_mbox *)desc.data;
	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_POST_MB, false);
	mbox_desc_init(mb, mailbox->dma, 0, ubcore_jfc->id,
		       HNS3_UDMA_CMD_MODIFY_CQC);

	ret = hns3_udma_cmd_mbox(udma_device, &desc, HNS3_UDMA_CMD_TIMEOUT_MSECS, 0);
	if (ret)
		dev_err(udma_device->dev,
			"failed to send modify cmd for jfc(0x%x), ret = %d.\n",
			ubcore_jfc->id, ret);
	hns3_udma_free_cmd_mailbox(udma_device, mailbox);

	return ret;
}

void hns3_udma_jfc_completion(struct hns3_udma_dev *udma_dev, uint32_t cqn)
{
	struct ubcore_jfc *ubcore_jfc;
	struct hns3_udma_jfc *udma_jfc;

	udma_jfc = (struct hns3_udma_jfc *)xa_load(&udma_dev->jfc_table.xa, cqn);
	if (!udma_jfc) {
		dev_warn(udma_dev->dev,
			 "Completion event for bogus CQ 0x%06x.\n", cqn);
		return;
	}

	ubcore_jfc = &udma_jfc->ubcore_jfc;
	if (ubcore_jfc->jfce_handler)
		ubcore_jfc->jfce_handler(ubcore_jfc);
}

void hns3_udma_jfc_event(struct hns3_udma_dev *udma_dev, uint32_t cqn, int event_type)
{
	struct device *dev = udma_dev->dev;
	struct hns3_udma_jfc *udma_jfc;
	struct ubcore_jfc *ubcore_jfc;
	struct ubcore_event event;

	if (event_type != HNS3_UDMA_EVENT_TYPE_JFC_ACCESS_ERROR &&
	    event_type != HNS3_UDMA_EVENT_TYPE_JFC_OVERFLOW) {
		dev_err(dev, "Unexpected event type 0x%x on CQ 0x%06x.\n",
			event_type, cqn);
		return;
	}

	xa_lock(&udma_dev->jfc_table.xa);
	udma_jfc = (struct hns3_udma_jfc *)xa_load(&udma_dev->jfc_table.xa, cqn);
	if (udma_jfc)
		refcount_inc(&udma_jfc->refcount);
	xa_unlock(&udma_dev->jfc_table.xa);

	if (!udma_jfc) {
		dev_warn(dev, "Async event for bogus CQ 0x%06x.\n", cqn);
		return;
	}

	ubcore_jfc = &udma_jfc->ubcore_jfc;
	if (ubcore_jfc->jfae_handler) {
		event.ub_dev = ubcore_jfc->ub_dev;
		event.element.jfc = ubcore_jfc;
		event.event_type = UBCORE_EVENT_JFC_ERR;
		ubcore_jfc->jfae_handler(&event, ubcore_jfc->uctx);
	}

	if (refcount_dec_and_test(&udma_jfc->refcount))
		complete(&udma_jfc->free);
}
