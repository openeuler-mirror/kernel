// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt
#define pr_fmt(fmt) "UDMA: " fmt

#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <ub/urma/ubcore_uapi.h>
#include "udma_common.h"
#include "udma_dev.h"
#include <uapi/ub/urma/udma/udma_abi.h>
#include "udma_cmd.h"
#include "udma_jetty.h"
#include "udma_segment.h"
#include "udma_jfs.h"

static bool udma_check_vma(struct udma_dev *dev, struct vm_area_struct *vma)
{
	return (vma->vm_start == dev->sq_reserved_info.va_start) &&
	       (vma->vm_end == dev->sq_reserved_info.va_start + dev->sq_reserved_info.va_size) &&
	       (vma->vm_flags & VM_WIPEONFORK) && (vma->vm_flags & VM_DONTEXPAND) &&
	       (vma->vm_flags & VM_DONTCOPY) && (vma->vm_flags & VM_IO);
}

static void udma_u_free_sq_buf(struct udma_dev *dev, struct udma_jetty_queue *sq)
{
	struct vm_area_struct *vma;

	if (dev->sq_reserved_info.sq_reserved) {
		if (dev->caps.sva_sep_mode_en) {
			udma_ioummu_unmap(sq->udma_ctx, UMMU_INVALID_TID, sq->buf.addr,
					  sq->reserved_info.len);
			sg_free_table(sq->sgt);
			kfree(sq->sgt);
			sq->sgt = NULL;
		}

		if (current->mm) {
			mmap_write_lock(current->mm);
			vma = find_vma(current->mm, sq->buf.addr);
			if (vma != NULL && vma->vm_start <= sq->buf.addr &&
			    vma->vm_end >= sq->buf.addr + sq->reserved_info.len)
				zap_vma_ptes(vma, sq->buf.addr, sq->reserved_info.len);
			mmap_write_unlock(current->mm);
		}
		udma_free_pages(sq->reserved_info.pg, sq->reserved_info.order);
	} else if (sq->buf.is_hugepage) {
		udma_free_u_hugepage(sq->udma_ctx, sq->buf.addr);
	} else {
		udma_put_map_page_priv(sq->udma_ctx, sq->buf.page_priv);
	}
}

void udma_free_sq_buf(struct udma_dev *dev, struct udma_jetty_queue *sq)
{
	if (sq->buf.kva) {
		if (!sq->cstm)
			udma_k_free_buf(dev, &sq->buf);
		kfree(sq->wrid);
		sq->wrid = NULL;
		return;
	}

	if (sq->non_pin)
		return;

	udma_u_free_sq_buf(dev, sq);
}

static int udma_do_ioummu_map(struct udma_dev *dev, struct udma_jetty_queue *sq, uint64_t buf_addr)
{
	struct page *page_list[1];
	int ret;

	sq->sgt = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!sq->sgt)
		return -ENOMEM;

	page_list[0] = sq->reserved_info.pg;
	ret = udma_create_sgt_from_pages(sq->sgt, page_list, 1,
					 PAGE_SIZE << sq->reserved_info.order);
	if (ret) {
		dev_err(dev->dev, "failed to create sg table, ret=%d.\n", ret);
		goto err_create_sgt;
	}

	ret = udma_ioummu_map(sq->udma_ctx, UMMU_INVALID_TID, IOMMU_READ | IOMMU_WRITE,
			      buf_addr, sq->sgt);
	if (ret) {
		dev_err(dev->dev, "failed to map sgt, ret=%d.\n", ret);
		goto err_ioummu_map;
	}

	return ret;

err_ioummu_map:
	sg_free_table(sq->sgt);
err_create_sgt:
	kfree(sq->sgt);
	sq->sgt = NULL;

	return ret;
}

static int
udma_reserved_u_sq_buf(struct udma_dev *dev, struct udma_jetty_queue *sq,
		       struct udma_create_jetty_ucmd *ucmd)
{
	struct vm_area_struct *vma;
	uint64_t buf_addr;
	uint32_t buf_len;
	int ret;

	buf_addr = dev->sq_reserved_info.va_per_ue +
		   sq->id * dev->sq_reserved_info.size_per_jetty;
	buf_len = (ubase_adev_prealloc_supported(dev->comdev.adev)) ?
		ALIGN(ucmd->buf_len, UDMA_HUGEPAGE_SIZE) : ALIGN(ucmd->buf_len, PAGE_SIZE);
	sq->reserved_info.order = get_order(buf_len);

	if (buf_len > dev->sq_reserved_info.size_per_jetty) {
		dev_err(dev->dev, "the sq_buffer(%u) is greater than the available_buffer(%llu).\n",
			buf_len, dev->sq_reserved_info.size_per_jetty);
		return -EINVAL;
	}

	mmap_write_lock(current->mm);
	vma = find_vma(current->mm, buf_addr);
	if (vma == NULL || vma->vm_start > buf_addr || vma->vm_end < buf_addr + buf_len) {
		dev_err(dev->dev, "failed to find_vma.\n");
		ret = -EINVAL;
		goto err_unlock;
	}

	if (!udma_check_vma(dev, vma)) {
		dev_err(dev->dev, "invalid vma, this vma is not created by the udma.\n");
		ret = -EINVAL;
		goto err_unlock;
	}

	sq->reserved_info.pg = udma_alloc_pages(GFP_KERNEL | __GFP_ZERO | GFP_HIGHUSER_MOVABLE,
								sq->reserved_info.order);
	if (sq->reserved_info.pg == NULL) {
		dev_err(dev->dev, "failed to alloc_pages, order=%u.\n", sq->reserved_info.order);
		ret = -ENOMEM;
		goto err_unlock;
	}

	if (dev->caps.sva_sep_mode_en) {
		ret = udma_do_ioummu_map(dev, sq, buf_addr);
		if (ret)
			goto err_alloc;
	}

	ret = udma_remap_pfn_range(vma, buf_addr, (uint64_t)page_to_pfn(sq->reserved_info.pg),
				   buf_len, vma->vm_page_prot);
	if (ret) {
		dev_err(dev->dev, "failed to remap_pfn, ret=%d.\n", ret);
		goto err_remap;
	}

	sq->buf.addr = buf_addr;
	sq->reserved_info.len = buf_len;

	mmap_write_unlock(current->mm);

	return ret;
err_remap:
	if (dev->caps.sva_sep_mode_en) {
		udma_ioummu_unmap(sq->udma_ctx, UMMU_INVALID_TID, buf_addr, buf_len);
		sg_free_table(sq->sgt);
		kfree(sq->sgt);
		sq->sgt = NULL;
	}
err_alloc:
	udma_free_pages(sq->reserved_info.pg, sq->reserved_info.order);
err_unlock:
	mmap_write_unlock(current->mm);

	return ret;
}

static int udma_u_alloc_sq_buf(struct udma_dev *dev, struct udma_jetty_queue *sq,
			       struct udma_create_jetty_ucmd *ucmd)
{
	int ret = 0;

	if (dev->sq_reserved_info.sq_reserved) {
		ret = udma_reserved_u_sq_buf(dev, sq, ucmd);
	} else if (ucmd->is_hugepage) {
		if (!udma_alloc_u_hugepage(sq->udma_ctx, sq->buf.addr, sq->buf.len)) {
			dev_err(dev->dev, "failed to create sq.\n");
			return -ENOMEM;
		}
		sq->buf.is_hugepage = true;
	} else {
		sq->buf.page_priv = udma_get_map_page_priv(sq->udma_ctx, sq->buf.addr, sq->buf.len);
		if (sq->buf.page_priv == NULL) {
			dev_err(dev->dev, "failed to get sq page.\n");
			return -EINVAL;
		}
	}

	return ret;
}

int udma_alloc_u_sq_buf(struct udma_dev *dev, struct udma_jetty_queue *sq,
			struct udma_create_jetty_ucmd *ucmd)
{
	int ret = 0;

	if (ucmd->sqe_bb_cnt == 0 || ucmd->buf_len == 0) {
		dev_err(dev->dev, "invalid param, sqe_bb_cnt=%u, buf_len=%u.\n",
			ucmd->sqe_bb_cnt, ucmd->buf_len);
		return -EINVAL;
	}

	sq->sqe_bb_cnt = ucmd->sqe_bb_cnt;
	sq->buf.entry_cnt = ucmd->buf_len >> WQE_BB_SIZE_SHIFT;
	sq->buf.addr = ucmd->buf_addr;
	sq->buf.len = ucmd->buf_len;
	if (sq->non_pin) {
		if (dev->caps.sva_sep_mode_en) {
			dev_err(dev->dev, "sep mode not support non_pin.\n");
			ret = -EINVAL;
		}
		return ret;
	}

	ret = udma_u_alloc_sq_buf(dev, sq, ucmd);
	if (ret)
		dev_err(dev->dev, "failed to alloc sq buf, ret = %d.\n", ret);

	return ret;
}

int udma_alloc_k_sq_buf(struct udma_dev *dev, struct udma_jetty_queue *sq,
			struct ubcore_jfs_cfg *jfs_cfg)
{
	uint32_t wqe_bb_depth;
	uint32_t sqe_bb_cnt;
	uint32_t size;
	int ret;

	if (!jfs_cfg->flag.bs.lock_free)
		spin_lock_init(&sq->lock);

	sq->max_inline_size = jfs_cfg->max_inline_data;
	sq->max_sge_num = jfs_cfg->max_sge;
	sq->tid = dev->tid;
	sq->lock_free = jfs_cfg->flag.bs.lock_free;

	sqe_bb_cnt = sq_cal_wqebb_num(SQE_WRITE_NOTIFY_CTL_LEN,
				      get_max_sge_num(jfs_cfg->max_sge, sq->max_inline_size));
	sq->sqe_bb_cnt = sqe_bb_cnt > (uint32_t)MAX_WQEBB_NUM ? (uint32_t)MAX_WQEBB_NUM :
			 sqe_bb_cnt;

	wqe_bb_depth = roundup_pow_of_two(sq->sqe_bb_cnt * jfs_cfg->depth);
	sq->buf.entry_size = UDMA_JFS_WQEBB_SIZE;
	size = ALIGN(wqe_bb_depth * sq->buf.entry_size, UDMA_HW_PAGE_SIZE);
	sq->buf.entry_cnt = size >> WQE_BB_SIZE_SHIFT;

	if (!sq->cstm) {
		ret = udma_k_alloc_buf(dev, &sq->buf);
		if (ret) {
			dev_err(dev->dev, "failed to alloc sq buffer, id=%u.\n", sq->id);
			return ret;
		}
	}

	sq->wrid = kcalloc(1, sq->buf.entry_cnt * sizeof(uint64_t), GFP_KERNEL);
	if (!sq->wrid) {
		if (!sq->cstm)
			udma_k_free_buf(dev, &sq->buf);
		return -ENOMEM;
	}

	udma_set_kernel_db_addr(dev, sq);
	sq->kva_curr = sq->buf.kva;

	return 0;
}

void udma_init_jfsc(struct udma_dev *dev, struct ubcore_jfs_cfg *cfg,
		    struct udma_jfs *jfs, void *mb_buf)
{
	struct udma_jetty_ctx *ctx = (struct udma_jetty_ctx *)mb_buf;
	uint8_t i;

	ctx->state = JETTY_READY;
	ctx->jfs_mode = JFS;
	ctx->type = to_udma_type(cfg->trans_mode);
	ctx->sl = dev->udma_sl[UDMA_DEFAULT_SL_NUM];
	if (ctx->type == JETTY_RM) {
		ctx->sl = dev->priority_info[cfg->priority].SL;
	} else if (ctx->type == JETTY_UM) {
		ctx->sl = dev->unic_sl[UDMA_DEFAULT_SL_NUM];
		for (i = 0; i < dev->unic_sl_num; i++)
			if (cfg->priority == dev->unic_sl[i])
				ctx->sl = cfg->priority;
	}
	ctx->sqe_base_addr_l = (jfs->sq.buf.addr >> SQE_VA_L_OFFSET) &
			       (uint32_t)SQE_VA_L_VALID_BIT;
	ctx->sqe_base_addr_h = (jfs->sq.buf.addr >> SQE_VA_H_OFFSET) &
			       (uint32_t)SQE_VA_H_VALID_BIT;
	ctx->sqe_token_id_l = jfs->sq.tid & (uint32_t)SQE_TOKEN_ID_L_MASK;
	ctx->sqe_token_id_h = (jfs->sq.tid >> SQE_TOKEN_ID_H_OFFSET) &
			      (uint32_t)SQE_TOKEN_ID_H_MASK;
	ctx->sqe_bb_shift = ilog2(roundup_pow_of_two(jfs->sq.buf.entry_cnt));
	ctx->tx_jfcn = cfg->jfc->id;
	ctx->ta_timeout = to_ta_timeout(cfg->err_timeout);

	if (!!(dev->caps.feature & UDMA_CAP_FEATURE_RNR_RETRY))
		ctx->rnr_retry_num = cfg->rnr_retry;

	ctx->user_data_l = jfs->jfs_addr;
	ctx->user_data_h = jfs->jfs_addr >> UDMA_USER_DATA_H_OFFSET;
	ctx->seid_idx = cfg->eid_index;
	ctx->err_mode = cfg->flag.bs.error_suspend;
	ctx->cmp_odr = cfg->flag.bs.outorder_comp;
	ctx->avail_sgmt_ost = AVAIL_SGMT_OST_INIT;
	ctx->pi_type = jfs->sq.pi_type;
	ctx->sqe_pld_tokenid = jfs->sq.tid & (uint32_t)SQE_PLD_TOKEN_ID_MASK;
	ctx->next_send_ssn = get_random_u16();
	ctx->next_rcv_ssn = ctx->next_send_ssn;
}

int udma_verify_jfs_param(struct udma_dev *dev, struct ubcore_jfs_cfg *cfg,
			  bool enable_stars)
{
	if (!cfg->depth || cfg->depth > dev->caps.jfs.depth ||
	    cfg->max_sge > dev->caps.jfs_sge || cfg->trans_mode == UBCORE_TP_RC) {
		dev_err(dev->dev,
			"jfs param is invalid, depth = %u, seg = %u, max_depth = %u, max_jfs_seg = %u, trans_mode = %u.\n",
			cfg->depth, cfg->max_sge, dev->caps.jfs.depth,
			dev->caps.jfs_sge, cfg->trans_mode);
		return -EINVAL;
	}

	if (enable_stars && cfg->max_inline_data != 0 &&
	    cfg->max_inline_data > dev->caps.jfs_inline_sz) {
		dev_err(dev->dev, "jfs param is invalid, inline_data:%u, max_inline_len:%u.\n",
			cfg->max_inline_data, dev->caps.jfs_inline_sz);
		return -EINVAL;
	}

	if (enable_stars && cfg->max_rsge > dev->caps.jfs_rsge) {
		dev_err(dev->dev, "jfs param is invalid, rsge:%u, max_rsge:%u.\n",
			cfg->max_rsge, dev->caps.jfs_rsge);
		return -EINVAL;
	}

	if (cfg->priority >= UDMA_MAX_PRIORITY) {
		dev_err(dev->dev, "kernel mode jfs priority is out of range, priority is %u.\n",
			cfg->priority);
		return -EINVAL;
	}

	return 0;
}

void udma_dfx_store_jfs_id(struct udma_dev *udma_dev, struct udma_jfs *udma_jfs)
{
	struct udma_dfx_jfs *jfs;
	int ret;

	jfs = (struct udma_dfx_jfs *)xa_load(&udma_dev->dfx_info->jfs.table,
					     udma_jfs->sq.id);
	if (jfs) {
		dev_warn(udma_dev->dev, "jfs_id(%u) already exists in DFX.\n",
			 udma_jfs->sq.id);
		return;
	}

	jfs = kzalloc(sizeof(*jfs), GFP_KERNEL);
	if (!jfs)
		return;

	jfs->id = udma_jfs->sq.id;
	jfs->depth = udma_jfs->sq.buf.entry_cnt / udma_jfs->sq.sqe_bb_cnt;

	write_lock(&udma_dev->dfx_info->jfs.rwlock);
	ret = xa_err(xa_store(&udma_dev->dfx_info->jfs.table, udma_jfs->sq.id,
			      jfs, GFP_KERNEL));
	if (ret) {
		write_unlock(&udma_dev->dfx_info->jfs.rwlock);
		dev_err(udma_dev->dev, "store jfs_id(%u) to table failed in DFX.\n",
			udma_jfs->sq.id);
		kfree(jfs);
		return;
	}

	++udma_dev->dfx_info->jfs.cnt;
	write_unlock(&udma_dev->dfx_info->jfs.rwlock);
}

static int udma_create_hw_jfs_ctx(struct udma_dev *dev, struct udma_jfs *jfs,
				    struct ubcore_jfs_cfg *cfg)
{
	struct ubase_mbx_attr attr = {};
	struct udma_jetty_ctx ctx = {};
	int ret;

	if (cfg->priority >= UDMA_MAX_PRIORITY) {
		dev_err(dev->dev, "kernel mode jfs priority is out of range, priority is %u.\n",
			cfg->priority);
		return -EINVAL;
	}

	udma_init_jfsc(dev, cfg, jfs, &ctx);
	attr.tag = jfs->sq.id;
	attr.op = UDMA_CMD_CREATE_JFS_CONTEXT;
	ret = post_mailbox_update_ctx(dev, &ctx, sizeof(ctx), &attr);
	if (ret) {
		dev_err(dev->dev, "failed to upgrade JFSC, ret = %d.\n", ret);
		return ret;
	}

	return 0;
}

static int udma_get_user_jfs_cmd(struct udma_dev *dev, struct udma_jfs *jfs,
				 struct ubcore_udata *udata,
				 struct udma_create_jetty_ucmd *ucmd)
{
	struct udma_context *uctx;
	unsigned long byte;

	if (udata) {
		if (!udata->udrv_data) {
			dev_err(dev->dev, "udrv_data is null.\n");
			return -EINVAL;
		}

		if (!udata->udrv_data->in_addr || udata->udrv_data->in_len < sizeof(*ucmd)) {
			dev_err(dev->dev, "jfs in_len %u or addr is invalid.\n",
				udata->udrv_data->in_len);
			return -EINVAL;
		}

		byte = copy_from_user(ucmd, (void *)(uintptr_t)udata->udrv_data->in_addr,
				      sizeof(*ucmd));
		if (byte) {
			dev_err(dev->dev,
				"failed to copy jfs udata, ret = %lu.\n", byte);
			return -EFAULT;
		}

		uctx = to_udma_context(udata->uctx);
		jfs->sq.udma_ctx = uctx;
		jfs->sq.tid = uctx->tid;
		jfs->jfs_addr = ucmd->jetty_addr;
		jfs->sq.pi_type = ucmd->pi_type;
		jfs->sq.non_pin = ucmd->non_pin;
		jfs->sq.jetty_type = (enum udma_jetty_type)ucmd->jetty_type;
		jfs->sq.id = ucmd->jfs_id;
	} else {
		jfs->jfs_addr = (uintptr_t)&jfs->sq;
		jfs->sq.jetty_type = UDMA_URMA_NORMAL_JETTY_TYPE;
	}

	return 0;
}

static int udma_jfs_copy_resp(struct udma_dev *dev, struct udma_jetty_queue *sq,
			      struct ubcore_udata *udata)
{
	struct udma_create_jetty_resp resp = {};
	unsigned long byte;

	if (sq->non_pin || !dev->sq_reserved_info.sq_reserved)
		return 0;

	if (udma_check_base_param(udata->udrv_data->out_addr,
				  udata->udrv_data->out_len, sizeof(resp))) {
		dev_err(dev->dev, "invalid out_addr or out_len=%u.\n",
			udata->udrv_data->out_len);
		return -EINVAL;
	}

	resp.buf_addr = sq->buf.addr;

	byte = copy_to_user((void *)(uintptr_t)udata->udrv_data->out_addr,
			    &resp, sizeof(resp));
	if (byte) {
		dev_err(dev->dev, "failed to copy_to_user, ret=%lu.\n", byte);
		return -EFAULT;
	}

	return 0;
}

static void free_jfs_id(struct udma_jfs *jfs, struct udma_dev *dev)
{
	if (jfs->sq.id < dev->caps.jetty.start_idx)
		udma_id_free(&dev->rsvd_jetty_ida_table, jfs->sq.id);
	else
		udma_adv_id_free(&dev->jetty_table.bitmap_table,
				 jfs->sq.id, false);
}

static int udma_alloc_jfs_sq(struct udma_dev *dev, struct ubcore_jfs_cfg *cfg,
			     struct udma_jfs *jfs, struct ubcore_udata *udata)
{
	struct udma_create_jetty_ucmd ucmd = {};
	int ret;

	ret = udma_get_user_jfs_cmd(dev, jfs, udata, &ucmd);
	if (ret)
		goto err_get_user_cmd;

	ret = alloc_jetty_id(dev, &jfs->sq, jfs->sq.id, NULL);
	if (ret) {
		dev_err(dev->dev, "failed to alloc_id.\n");
		goto err_alloc_id;
	}
	jfs->ubcore_jfs.jfs_id.id = jfs->sq.id;
	jfs->ubcore_jfs.jfs_cfg = *cfg;
	udma_set_query_flush_time(&jfs->sq, cfg->err_timeout);

	ret = xa_err(xa_store(&dev->jetty_table.xa, jfs->sq.id, &jfs->sq, GFP_KERNEL));
	if (ret) {
		dev_err(dev->dev, "failed to store_sq(%u), ret=%d.\n", jfs->sq.id, ret);
		goto err_store_sq;
	}

	ret = udata ? udma_alloc_u_sq_buf(dev, &jfs->sq, &ucmd) :
		udma_alloc_k_sq_buf(dev, &jfs->sq, cfg);
	if (ret)
		goto err_alloc_sq_buf;

	jfs->sq.trans_mode = cfg->trans_mode;
	if (udata) {
		ret = udma_jfs_copy_resp(dev, &jfs->sq, udata);
		if (ret)
			goto err_copy_resp;
	}

	return ret;

err_copy_resp:
	udma_free_sq_buf(dev, &jfs->sq);
err_alloc_sq_buf:
	xa_erase(&dev->jetty_table.xa, jfs->sq.id);
err_store_sq:
	free_jfs_id(jfs, dev);
err_alloc_id:
err_get_user_cmd:
	return ret;
}

static void udma_free_jfs_sq(struct udma_dev *dev, struct udma_jfs *ujfs)
{
	udma_free_sq_buf(dev, &ujfs->sq);
	xa_erase(&dev->jetty_table.xa, ujfs->sq.id);
	free_jfs_id(ujfs, dev);
}

int udma_active_jfs(struct ubcore_jfs *jfs, struct ubcore_udata *udata)
{
	struct udma_dev *dev = to_udma_dev(jfs->ub_dev);
	struct ubcore_jfs_cfg *cfg = &jfs->jfs_cfg;
	struct udma_jfs *ujfs = to_udma_jfs(jfs);
	int ret;

	if (cfg->trans_mode == UBCORE_TP_RC) {
		dev_err(dev->dev, "jfs not support RC transmode.\n");
		return -EINVAL;
	}

	ret = udma_alloc_jfs_sq(dev, cfg, ujfs, udata);
	if (ret) {
		dev_err(dev->dev, "failed to alloc_jfs_sq, ret = %d.\n", ret);
		return ret;
	}

	ret = udma_create_hw_jfs_ctx(dev, ujfs, cfg);
	if (ret) {
		dev_err(dev->dev,
			"post mailbox create jfs ctx failed, ret = %d.\n", ret);
		goto err_create_hw_jfs;
	}

	ujfs->mode = UDMA_NORMAL_JFS_TYPE;
	ujfs->sq.state = UBCORE_JETTY_STATE_READY;
	refcount_set(&ujfs->ae_refcount, 1);
	init_completion(&ujfs->ae_comp);
	if (dfx_switch)
		udma_dfx_store_jfs_id(dev, ujfs);

	ujfs->sq.activated = true;
	return 0;

err_create_hw_jfs:
	udma_free_jfs_sq(dev, ujfs);

	return ret;
}

struct ubcore_jfs *udma_create_jfs(struct ubcore_device *ub_dev,
				   struct ubcore_jfs_cfg *cfg,
				   struct ubcore_udata *udata)
{
	struct udma_dev *dev = to_udma_dev(ub_dev);
	struct udma_jfs *jfs;
	int ret;

	if (cfg->trans_mode == UBCORE_TP_RC) {
		dev_err(dev->dev, "jfs not support RC transmode.\n");
		return ERR_PTR(-EINVAL);
	}

	jfs = kcalloc(1, sizeof(*jfs), GFP_KERNEL);
	if (!jfs)
		return ERR_PTR(-ENOMEM);

	ret = udma_alloc_jfs_sq(dev, cfg, jfs, udata);
	if (ret) {
		dev_err(dev->dev, "failed to alloc_jfs_sq, ret = %d.\n", ret);
		goto err_alloc_sq;
	}

	ret = udma_create_hw_jfs_ctx(dev, jfs, cfg);
	if (ret) {
		dev_err(dev->dev,
			"post mailbox create jfs ctx failed, ret = %d.\n", ret);
		goto err_create_hw_jfs;
	}

	jfs->mode = UDMA_NORMAL_JFS_TYPE;
	jfs->sq.state = UBCORE_JETTY_STATE_READY;
	jfs->sq.activated = true;
	refcount_set(&jfs->ae_refcount, 1);
	init_completion(&jfs->ae_comp);
	if (dfx_switch)
		udma_dfx_store_jfs_id(dev, jfs);

	return &jfs->ubcore_jfs;

err_create_hw_jfs:
	udma_free_jfs_sq(dev, jfs);
err_alloc_sq:
	kfree(jfs);
	return ERR_PTR(ret);
}

static void udma_free_jfs_detail(struct ubcore_jfs *jfs)
{
	struct udma_dev *dev = to_udma_dev(jfs->ub_dev);
	struct udma_jfs *ujfs = to_udma_jfs(jfs);

	udma_clean_cqe_for_jetty(dev, &ujfs->sq, jfs->jfs_cfg.jfc, NULL);

	xa_erase(&dev->jetty_table.xa, ujfs->sq.id);

	if (refcount_dec_and_test(&ujfs->ae_refcount))
		complete(&ujfs->ae_comp);
	wait_for_completion(&ujfs->ae_comp);

	if (dfx_switch)
		udma_dfx_delete_id(dev, &dev->dfx_info->jfs, jfs->jfs_id.id);

	if (ujfs->mode == UDMA_NORMAL_JFS_TYPE)
		udma_free_sq_buf(dev, &ujfs->sq);
	else
		kfree(ujfs->sq.wrid);

	free_jfs_id(ujfs, dev);
}

int udma_deactive_jfs(struct ubcore_jfs *jfs, struct ubcore_udata *udata)
{
	struct udma_dev *dev = to_udma_dev(jfs->ub_dev);
	struct udma_jfs *ujfs = to_udma_jfs(jfs);
	int ret;

	if (!ujfs->sq.activated) {
		dev_info_ratelimited(dev->dev, "jetty no need deactivate.\n");
		return 0;
	}

	if (!ujfs->ue_rx_closed && udma_close_ue_rx(dev, true, true, false, 0)) {
		dev_err(dev->dev, "close ue rx failed when destroying jfs.\n");
		return -EINVAL;
	}

	ret = udma_modify_and_destroy_jetty(dev, &ujfs->sq);
	if (ret) {
		dev_info(dev->dev, "udma modify error and destroy jfs failed, id: %u.\n",
			 jfs->jfs_id.id);
		if (!ujfs->ue_rx_closed)
			udma_open_ue_rx(dev, true, true, false, 0);
		return ret;
	}

	udma_free_jfs_detail(jfs);
	udma_open_ue_rx(dev, true, true, false, 0);
	ujfs->sq.activated = false;

	return 0;
}

int udma_destroy_jfs(struct ubcore_jfs *jfs)
{
	int ret = udma_deactive_jfs(jfs, NULL);

	if (!ret)
		kfree(jfs);

	return ret;
}

int udma_destroy_jfs_batch(struct ubcore_jfs **jfs, int jfs_cnt, int *bad_jfs_index)
{
	struct udma_jetty_queue **sq_list;
	struct udma_jetty_queue *sq;
	uint32_t active_jfs_cnt = 0;
	struct udma_dev *udma_dev;
	uint32_t i;
	int ret;

	if (!jfs) {
		pr_err("jfs array is null.\n");
		return -EINVAL;
	}

	if (!jfs_cnt) {
		pr_err("jfs cnt is 0.\n");
		return -EINVAL;
	}

	udma_dev = to_udma_dev(jfs[0]->ub_dev);

	sq_list = kcalloc(jfs_cnt, sizeof(*sq_list), GFP_KERNEL);
	if (!sq_list)
		return -ENOMEM;

	for (i = 0; i < (uint32_t)jfs_cnt; i++) {
		sq = &(to_udma_jfs(jfs[i])->sq);
		if (sq->activated)
			sq_list[active_jfs_cnt++] = sq;
	}

	ret = udma_batch_modify_and_destroy_jetty(udma_dev, sq_list, active_jfs_cnt, bad_jfs_index);
	if (ret) {
		dev_err(udma_dev->dev,
			 "udma batch modify error and destroy jfs failed.\n");
		kfree(sq_list);
		return ret;
	}

	for (i = 0; i < active_jfs_cnt; i++)
		udma_free_jfs_detail(&(to_udma_jfs_from_queue(sq_list[i])->ubcore_jfs));

	kfree(sq_list);

	for (i = 0; i < (uint32_t)jfs_cnt; i++)
		kfree(jfs[i]);

	return 0;
}

static int udma_modify_jfs_state(struct udma_dev *udma_dev, struct udma_jfs *udma_jfs,
				 struct ubcore_jfs_attr *attr)
{
	int ret;

	switch (attr->state) {
	case UBCORE_JETTY_STATE_RESET:
		ret = udma_destroy_hw_jetty_ctx(udma_dev, udma_jfs->sq.id);
		break;
	case UBCORE_JETTY_STATE_READY:
		ret = udma_create_hw_jfs_ctx(udma_dev, udma_jfs, &udma_jfs->ubcore_jfs.jfs_cfg);
		if (ret)
			break;

		udma_reset_sw_k_jetty_queue(&udma_jfs->sq);
		break;
	default:
		ret = udma_close_ue_rx(udma_dev, true, true, false, 0);
		if (ret)
			break;

		if (!(udma_dev->caps.feature & UDMA_CAP_FEATURE_UE_RX_CLOSE)) {
			if (udma_modify_jetty_precondition(udma_dev, &udma_jfs->sq)) {
				ret = -ENOMEM;
				udma_open_ue_rx(udma_dev, true, true, false, 0);
				break;
			}
		}

		ret = udma_set_jetty_state(udma_dev, udma_jfs->sq.id, to_jetty_state(attr->state));
		if (ret)
			udma_open_ue_rx(udma_dev, true, true, false, 0);
		else
			udma_jfs->ue_rx_closed = true;
		break;
	}

	return ret;
}

int udma_modify_jfs(struct ubcore_jfs *jfs, struct ubcore_jfs_attr *attr,
		    struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(jfs->ub_dev);
	struct udma_jfs *udma_jfs = to_udma_jfs(jfs);
	int ret = 0;

	if (!(attr->mask & UBCORE_JFS_STATE)) {
		dev_err(udma_dev->dev, "modify jfs mask is error or not set, jfs_id = %u.\n",
			udma_jfs->sq.id);
		return -EINVAL;
	}

	if (udma_jfs->sq.state == attr->state) {
		dev_info_ratelimited(udma_dev->dev, "jfs state has been %s.\n",
				     to_state_name(attr->state));
		return 0;
	}

	if (!verify_modify_jetty(udma_jfs->sq.state, attr->state)) {
		dev_err(udma_dev->dev, "not support modify jfs state from %s to %s.\n",
			to_state_name(udma_jfs->sq.state), to_state_name(attr->state));
		return -EINVAL;
	}

	ret = udma_modify_jfs_state(udma_dev, udma_jfs, attr);
	if (ret) {
		dev_err(udma_dev->dev, "modify jfs %u state to %u failed.\n",
			udma_jfs->sq.id, attr->state);
		return ret;
	}

	udma_jfs->sq.state = attr->state;

	return 0;
}

static void fill_imm_data_or_token_for_cr(struct udma_dev *udma_dev,
					  struct udma_sqe_ctl *sqe_ctl,
					  struct ubcore_cr *cr,
					  uint32_t opcode)
{
	switch (opcode) {
	case UDMA_OPC_SEND:
	case UDMA_OPC_WRITE:
	case UDMA_OPC_READ:
	case UDMA_OPC_CAS:
	case UDMA_OPC_FAA:
		break;
	case UDMA_OPC_SEND_WITH_IMM:
		memcpy(&cr->imm_data, (void *)sqe_ctl + SQE_SEND_IMM_FIELD,
		       sizeof(uint64_t));
		break;
	case UDMA_OPC_SEND_WITH_INVALID:
		cr->invalid_token.token_id = sqe_ctl->rmt_addr_l_or_token_id;
		cr->invalid_token.token_value.token = sqe_ctl->rmt_addr_h_or_token_value;
		break;
	case UDMA_OPC_WRITE_WITH_IMM:
		memcpy(&cr->imm_data, (void *)sqe_ctl + SQE_WRITE_IMM_FIELD,
		       sizeof(uint64_t));
		break;
	default:
		dev_err(udma_dev->dev, "Flush invalid opcode :%u.\n", opcode);
		break;
	}
}

static void fill_cr_by_sqe_ctl(struct udma_dev *udma_dev,
			       struct udma_sqe_ctl *sqe_ctl,
			       struct ubcore_cr *cr)
{
	uint32_t opcode = sqe_ctl->opcode;
	struct udma_normal_sge *sge;
	uint32_t src_sge_num = 0;
	uint64_t total_len = 0;
	uint32_t ctrl_len;
	uint32_t i;

	fill_imm_data_or_token_for_cr(udma_dev, sqe_ctl, cr, opcode);

	cr->tpn = sqe_ctl->tpn;
	cr->remote_id.id = sqe_ctl->rmt_obj_id;
	memcpy(cr->remote_id.eid.raw, sqe_ctl->rmt_eid, UBCORE_EID_SIZE);

	if (sqe_ctl->inline_en) {
		cr->completion_len = sqe_ctl->inline_msg_len;
		return;
	}

	src_sge_num = sqe_ctl->sge_num;
	ctrl_len = get_ctl_len(opcode);
	sge = (struct udma_normal_sge *)((void *)sqe_ctl + ctrl_len);

	for (i = 0; i < src_sge_num; i++) {
		total_len += sge->length;
		sge++;
	}

	if (total_len > UINT32_MAX) {
		cr->completion_len = UINT32_MAX;
		dev_warn(udma_dev->dev, "total len %llu is overflow.\n", total_len);
	} else {
		cr->completion_len = total_len;
	}
}

static void udma_copy_from_sq(struct udma_jetty_queue *sq, uint32_t wqebb_cnt,
			      struct udma_jfs_wqebb *tmp_sq)
{
	uint32_t field_h;
	uint32_t field_l;
	uint32_t offset;
	uint32_t remain;

	remain = sq->buf.entry_cnt - (sq->ci & (sq->buf.entry_cnt - 1));
	offset = (sq->ci & (sq->buf.entry_cnt - 1)) * UDMA_JFS_WQEBB_SIZE;
	field_h = remain > wqebb_cnt ? wqebb_cnt : remain;
	field_l = wqebb_cnt - field_h;

	memcpy(tmp_sq, sq->buf.kva + offset, field_h * sizeof(*tmp_sq));

	if (field_l)
		memcpy(tmp_sq + field_h, sq->buf.kva, field_l * sizeof(*tmp_sq));
}

static uint32_t get_wqebb_num(struct udma_sqe_ctl *sqe_ctl)
{
	uint32_t opcode = sqe_ctl->opcode;
	uint32_t sqe_ctl_len = get_ctl_len(opcode);

	switch (opcode) {
	case UDMA_OPC_SEND:
	case UDMA_OPC_SEND_WITH_IMM:
	case UDMA_OPC_SEND_WITH_INVALID:
	case UDMA_OPC_WRITE:
	case UDMA_OPC_WRITE_WITH_IMM:
		if (sqe_ctl->inline_en)
			return (sqe_ctl_len + sqe_ctl->inline_msg_len - 1) /
				UDMA_JFS_WQEBB_SIZE + 1;
		break;
	case UDMA_OPC_CAS:
	case UDMA_OPC_FAA:
		return ATOMIC_WQEBB_CNT;
	case UDMA_OPC_NOP:
		return NOP_WQEBB_CNT;
	default:
		break;
	}

	return sq_cal_wqebb_num(sqe_ctl_len, sqe_ctl->sge_num);
}

void udma_flush_sq(struct udma_dev *udma_dev,
		   struct udma_jetty_queue *sq, struct ubcore_cr *cr)
{
	struct udma_jfs_wqebb tmp_sq[MAX_WQEBB_NUM] = {};

	udma_copy_from_sq(sq, MAX_WQEBB_NUM, tmp_sq);
	fill_cr_by_sqe_ctl(udma_dev, (struct udma_sqe_ctl *)tmp_sq, cr);
	cr->status = UBCORE_CR_WR_UNHANDLED;
	cr->user_ctx = sq->wrid[sq->ci & (sq->buf.entry_cnt - 1)];
	/* Fill in UINT8_MAX for send direction */
	cr->opcode = UINT8_MAX;
	cr->local_id = sq->id;

	sq->ci += get_wqebb_num((struct udma_sqe_ctl *)tmp_sq);
}

int udma_flush_jfs(struct ubcore_jfs *jfs, int cr_cnt, struct ubcore_cr *cr)
{
	struct udma_dev *udma_dev = to_udma_dev(jfs->ub_dev);
	struct udma_jfs *udma_jfs = to_udma_jfs(jfs);
	struct udma_jetty_queue *sq = &udma_jfs->sq;
	int n_flushed;

	if (!sq->flush_flag)
		return 0;

	if (!jfs->jfs_cfg.flag.bs.lock_free)
		spin_lock(&sq->lock);

	for (n_flushed = 0; n_flushed < cr_cnt; n_flushed++) {
		if (sq->ci == sq->pi)
			break;
		udma_flush_sq(udma_dev, sq, cr + n_flushed);
	}

	if (!jfs->jfs_cfg.flag.bs.lock_free)
		spin_unlock(&sq->lock);

	return n_flushed;
}

static uint8_t udma_get_jfs_opcode(enum ubcore_opcode opcode)
{
	switch (opcode) {
	case UBCORE_OPC_SEND:
		return UDMA_OPC_SEND;
	case UBCORE_OPC_SEND_IMM:
		return UDMA_OPC_SEND_WITH_IMM;
	case UBCORE_OPC_SEND_INVALIDATE:
		return UDMA_OPC_SEND_WITH_INVALID;
	case UBCORE_OPC_WRITE:
		return UDMA_OPC_WRITE;
	case UBCORE_OPC_WRITE_IMM:
		return UDMA_OPC_WRITE_WITH_IMM;
	case UBCORE_OPC_READ:
		return UDMA_OPC_READ;
	case UBCORE_OPC_CAS:
		return UDMA_OPC_CAS;
	case UBCORE_OPC_FADD:
		return UDMA_OPC_FAA;
	case UBCORE_OPC_NOP:
		return UDMA_OPC_NOP;
	default:
		return UDMA_OPC_INVALID;
	}
}

static int
udma_fill_sw_sge(struct udma_dev *dev, struct udma_sqe_ctl *sqe_ctl,
		 struct ubcore_jfs_wr *wr, uint32_t max_inline_size,
		 struct udma_normal_sge *sge)
{
	struct ubcore_sge *sge_info;
	uint32_t total_len = 0;
	uint32_t sge_num = 0;
	uint32_t num_sge;
	uint32_t i;

	switch (wr->opcode) {
	case UBCORE_OPC_SEND:
	case UBCORE_OPC_SEND_IMM:
	case UBCORE_OPC_SEND_INVALIDATE:
		sge_info = wr->send.src.sge;
		num_sge = wr->send.src.num_sge;
		break;
	case UBCORE_OPC_WRITE:
	case UBCORE_OPC_WRITE_IMM:
		sge_info = wr->rw.src.sge;
		num_sge = wr->rw.src.num_sge;
		break;
	default:
		return -EINVAL;
	}

	if (wr->flag.bs.inline_flag) {
		for (i = 0; i < num_sge; i++) {
			if (total_len + sge_info[i].len > max_inline_size) {
				dev_info(dev->dev, "inline_size %u is over max_size %u.\n",
					 total_len + sge_info[i].len, max_inline_size);
				return -EINVAL;
			}

			memcpy((void *)(uintptr_t)sge + total_len,
			       (void *)(uintptr_t)sge_info[i].addr,
			       sge_info[i].len);
			total_len += sge_info[i].len;
		}
		sqe_ctl->inline_msg_len = total_len;
	} else {
		for (i = 0; i < num_sge; i++) {
			if (sge_info[i].len == 0)
				continue;
			sge->va = sge_info[i].addr;
			sge->length = sge_info[i].len;
			sge++;
			sge_num++;
		}
		sqe_ctl->sge_num = sge_num;
	}

	return 0;
}

static int
udma_k_fill_send_sqe(struct udma_dev *dev, struct udma_sqe_ctl *sqe_ctl,
		     struct ubcore_jfs_wr *wr, struct ubcore_tjetty *tjetty,
		     uint32_t max_inline_size)
{
	struct udma_target_jetty *udma_tjetty;
	struct udma_token_info *token_info;
	struct udma_segment *udma_seg;
	struct udma_normal_sge *sge;

	sge = (struct udma_normal_sge *)(sqe_ctl + 1);

	if (udma_fill_sw_sge(dev, sqe_ctl, wr, max_inline_size, sge))
		return -EINVAL;

	udma_tjetty = to_udma_tjetty(tjetty);
	sqe_ctl->target_hint = wr->send.target_hint;
	sqe_ctl->rmt_obj_id = tjetty->cfg.id.id;
	sqe_ctl->token_en = udma_tjetty->token_value_valid;
	sqe_ctl->rmt_token_value = udma_tjetty->token_value;

	if (wr->opcode == UBCORE_OPC_SEND_IMM) {
		memcpy((void *)sqe_ctl + SQE_SEND_IMM_FIELD, &wr->send.imm_data,
		       sizeof(uint64_t));
	} else if (wr->opcode == UBCORE_OPC_SEND_INVALIDATE) {
		udma_seg = to_udma_seg(wr->send.tseg);
		token_info = (struct udma_token_info *)&sqe_ctl->rmt_addr_l_or_token_id;
		token_info->token_id = udma_seg->tid;
		token_info->token_value = udma_seg->token_value;
	}

	return 0;
}

static int
udma_k_fill_write_sqe(struct udma_dev *dev, struct udma_sqe_ctl *sqe_ctl,
		      struct ubcore_jfs_wr *wr, struct ubcore_tjetty *tjetty,
		      uint32_t max_inline_size)
{
	struct udma_token_info *token_info;
	struct udma_segment *udma_seg;
	struct udma_normal_sge *sge;
	struct ubcore_sge *sge_info;
	uint32_t ctrl_len;

	ctrl_len = get_ctl_len(sqe_ctl->opcode);
	sge = (struct udma_normal_sge *)((void *)sqe_ctl + ctrl_len);

	if (udma_fill_sw_sge(dev, sqe_ctl, wr, max_inline_size, sge))
		return -EINVAL;

	sge_info = wr->rw.dst.sge;
	udma_seg = to_udma_seg(sge_info[0].tseg);

	sqe_ctl->target_hint = wr->rw.target_hint;
	sqe_ctl->rmt_obj_id = udma_seg->tid;
	sqe_ctl->token_en = udma_seg->token_value_valid;
	sqe_ctl->rmt_token_value = udma_seg->token_value;
	sqe_ctl->rmt_addr_l_or_token_id = sge_info[0].addr & (uint32_t)SQE_CTL_RMA_ADDR_BIT;
	sqe_ctl->rmt_addr_h_or_token_value =
			(sge_info[0].addr >> (uint32_t)SQE_CTL_RMA_ADDR_OFFSET) &
			(uint32_t)SQE_CTL_RMA_ADDR_BIT;

	if (sqe_ctl->opcode == UDMA_OPC_WRITE_WITH_IMM) {
		memcpy((void *)sqe_ctl + SQE_WRITE_IMM_FIELD, &wr->rw.notify_data,
		       sizeof(uint64_t));
		token_info = (struct udma_token_info *)
			     ((void *)sqe_ctl + WRITE_IMM_TOKEN_FIELD);
		token_info->token_id = tjetty->cfg.id.id;
		token_info->token_value = tjetty->cfg.token_value.token;
	}

	return 0;
}

static int udma_k_fill_read_sqe(struct udma_sqe_ctl *sqe_ctl, struct ubcore_jfs_wr *wr)
{
	struct udma_segment *udma_seg;
	struct udma_normal_sge *sge;
	struct ubcore_sge *sge_info;
	uint32_t sge_num = 0;
	uint32_t num;

	sge = (struct udma_normal_sge *)(sqe_ctl + 1);
	sge_info = wr->rw.dst.sge;

	for (num = 0; num < wr->rw.dst.num_sge; num++) {
		if (sge_info[num].len == 0)
			continue;
		sge->va = sge_info[num].addr;
		sge->length = sge_info[num].len;
		sge++;
		sge_num++;
	}

	sge_info = wr->rw.src.sge;
	udma_seg = to_udma_seg(sge_info[0].tseg);

	sqe_ctl->sge_num = sge_num;
	sqe_ctl->rmt_obj_id = udma_seg->tid;
	sqe_ctl->token_en = udma_seg->token_value_valid;
	sqe_ctl->rmt_token_value = udma_seg->token_value;
	sqe_ctl->rmt_addr_l_or_token_id = sge_info[0].addr & (uint32_t)SQE_CTL_RMA_ADDR_BIT;
	sqe_ctl->rmt_addr_h_or_token_value =
			(sge_info[0].addr >> (uint32_t)SQE_CTL_RMA_ADDR_OFFSET) &
			(uint32_t)SQE_CTL_RMA_ADDR_BIT;

	return 0;
}

static bool
udma_k_check_atomic_len(struct udma_dev *dev, uint32_t len, uint8_t opcode)
{
	switch (len) {
	case UDMA_ATOMIC_LEN_4:
	case UDMA_ATOMIC_LEN_8:
		return true;
	case UDMA_ATOMIC_LEN_16:
		if (opcode == UBCORE_OPC_CAS)
			return true;
		dev_err(dev->dev, "the atomic opcode must be CAS when len is 16.\n");
		return false;
	default:
		dev_err(dev->dev, "invalid atomic len %u.\n", len);
		return false;
	}
}

static int
udma_k_fill_cas_sqe(struct udma_dev *dev, struct udma_sqe_ctl *sqe_ctl,
		    struct ubcore_jfs_wr *wr)
{
	struct udma_segment *udma_seg;
	struct udma_normal_sge *sge;
	struct ubcore_sge *sge_info;

	sge_info = wr->cas.src;
	if (!udma_k_check_atomic_len(dev, sge_info->len, wr->opcode))
		return -EINVAL;

	sge = (struct udma_normal_sge *)(sqe_ctl + 1);

	sge->va = sge_info->addr;
	sge->length = sge_info->len;

	sge_info = wr->cas.dst;
	udma_seg = to_udma_seg(sge_info->tseg);

	sqe_ctl->sge_num = UDMA_ATOMIC_SGE_NUM;
	sqe_ctl->rmt_obj_id = udma_seg->tid;
	sqe_ctl->token_en = udma_seg->token_value_valid;
	sqe_ctl->rmt_token_value = udma_seg->token_value;
	sqe_ctl->rmt_addr_l_or_token_id = sge_info->addr & (uint32_t)SQE_CTL_RMA_ADDR_BIT;
	sqe_ctl->rmt_addr_h_or_token_value = (sge_info->addr >> (uint32_t)SQE_CTL_RMA_ADDR_OFFSET) &
			(uint32_t)SQE_CTL_RMA_ADDR_BIT;

	if (sge->length <= UDMA_ATOMIC_LEN_8) {
		memcpy((void *)sqe_ctl + SQE_ATOMIC_DATA_FIELD,
		       &wr->cas.swap_data, sge->length);
		memcpy((void *)sqe_ctl + SQE_ATOMIC_DATA_FIELD + sge->length,
		       &wr->cas.cmp_data, sge->length);
	} else {
		memcpy((void *)sqe_ctl + SQE_ATOMIC_DATA_FIELD,
		       (void *)(uintptr_t)wr->cas.swap_addr, sge->length);
		memcpy((void *)sqe_ctl + SQE_ATOMIC_DATA_FIELD + sge->length,
		       (void *)(uintptr_t)wr->cas.cmp_addr, sge->length);
	}

	return 0;
}

static int
udma_k_fill_faa_sqe(struct udma_dev *dev, struct udma_sqe_ctl *sqe_ctl,
		    struct ubcore_jfs_wr *wr)
{
	struct udma_segment *udma_seg;
	struct udma_normal_sge *sge;
	struct ubcore_sge *sge_info;

	sge_info = wr->faa.src;
	if (!udma_k_check_atomic_len(dev, sge_info->len, wr->opcode))
		return -EINVAL;

	sge = (struct udma_normal_sge *)(sqe_ctl + 1);

	sge->va = sge_info->addr;
	sge->length = sge_info->len;

	sge_info = wr->faa.dst;
	udma_seg = to_udma_seg(sge_info->tseg);

	sqe_ctl->sge_num = UDMA_ATOMIC_SGE_NUM;
	sqe_ctl->rmt_obj_id = udma_seg->tid;
	sqe_ctl->token_en = udma_seg->token_value_valid;
	sqe_ctl->rmt_token_value = udma_seg->token_value;
	sqe_ctl->rmt_addr_l_or_token_id = sge_info->addr & (uint32_t)SQE_CTL_RMA_ADDR_BIT;
	sqe_ctl->rmt_addr_h_or_token_value = (sge_info->addr >> (uint32_t)SQE_CTL_RMA_ADDR_OFFSET) &
			(uint32_t)SQE_CTL_RMA_ADDR_BIT;

	if (sge->length <= UDMA_ATOMIC_LEN_8)
		memcpy((void *)sqe_ctl + SQE_ATOMIC_DATA_FIELD, &wr->faa.operand,
		       sge->length);
	else
		memcpy((void *)sqe_ctl + SQE_ATOMIC_DATA_FIELD,
		       (void *)(uintptr_t)wr->faa.operand_addr, sge->length);

	return 0;
}

static int udma_fill_normal_sge(struct udma_dev *dev, struct udma_sqe_ctl *sqe_ctl,
				uint32_t max_inline_size, struct ubcore_jfs_wr *wr,
				struct ubcore_tjetty *tjetty)
{
	switch (sqe_ctl->opcode) {
	case UDMA_OPC_SEND:
	case UDMA_OPC_SEND_WITH_IMM:
	case UDMA_OPC_SEND_WITH_INVALID:
		return udma_k_fill_send_sqe(dev, sqe_ctl, wr, tjetty,
					    max_inline_size);
	case UDMA_OPC_WRITE:
		return udma_k_fill_write_sqe(dev, sqe_ctl, wr, tjetty, max_inline_size);
	case UDMA_OPC_WRITE_WITH_IMM:
		return udma_k_fill_write_sqe(dev, sqe_ctl, wr, tjetty,
					     max_inline_size > SQE_WRITE_IMM_INLINE_SIZE ?
					     SQE_WRITE_IMM_INLINE_SIZE : max_inline_size);
	case UDMA_OPC_READ:
		return udma_k_fill_read_sqe(sqe_ctl, wr);
	case UDMA_OPC_CAS:
		return udma_k_fill_cas_sqe(dev, sqe_ctl, wr);
	case UDMA_OPC_FAA:
		return udma_k_fill_faa_sqe(dev, sqe_ctl, wr);
	default:
		return -EINVAL;
	}
}

static int udma_k_set_sqe(struct udma_sqe_ctl *sqe_ctl, struct ubcore_jfs_wr *wr,
			  struct udma_jetty_queue *sq, uint8_t opcode,
			  struct udma_dev *dev)
{
	struct udma_target_jetty *udma_tjetty;
	struct ubcore_tjetty *tjetty;
	int ret = 0;

	sqe_ctl->cqe = wr->flag.bs.complete_enable;
	sqe_ctl->owner = (sq->pi & sq->buf.entry_cnt) == 0 ? 1 : 0;
	sqe_ctl->opcode = opcode;
	sqe_ctl->place_odr = wr->flag.bs.place_order;

	if (opcode == UDMA_OPC_NOP)
		return 0;

	if (sq->trans_mode == UBCORE_TP_RC)
		tjetty = sq->rc_tjetty;
	else
		tjetty = wr->tjetty;

	udma_tjetty = to_udma_tjetty(tjetty);

	sqe_ctl->tpn = tjetty->vtpn->vtpn;
	sqe_ctl->fence = wr->flag.bs.fence;
	sqe_ctl->comp_order = wr->flag.bs.comp_order;
	sqe_ctl->se = wr->flag.bs.solicited_enable;
	sqe_ctl->inline_en = wr->flag.bs.inline_flag;
	sqe_ctl->rmt_jetty_type = tjetty->cfg.type;
	memcpy(sqe_ctl->rmt_eid, &udma_tjetty->le_eid.raw, sizeof(uint8_t) *
		UDMA_SQE_RMT_EID_SIZE);

	ret = udma_fill_normal_sge(dev, sqe_ctl, sq->max_inline_size, wr, tjetty);
	if (ret)
		dev_err(dev->dev, "Failed to fill normal sge, opcode :%u in wr.\n",
			(uint8_t)wr->opcode);

	return ret;
}

static bool udma_k_check_sge_num(uint8_t opcode, struct udma_jetty_queue *sq,
				 struct ubcore_jfs_wr *wr)
{
	switch (opcode) {
	case UDMA_OPC_CAS:
	case UDMA_OPC_FAA:
		return sq->max_sge_num == 0;
	case UDMA_OPC_READ:
		return wr->rw.dst.num_sge > UDMA_JFS_MAX_SGE_READ ||
		       wr->rw.dst.num_sge > sq->max_sge_num;
	case UDMA_OPC_WRITE_WITH_IMM:
		return wr->rw.src.num_sge > UDMA_JFS_MAX_SGE_WRITE_IMM ||
		       wr->rw.src.num_sge > sq->max_sge_num;
	case UDMA_OPC_SEND:
	case UDMA_OPC_SEND_WITH_IMM:
	case UDMA_OPC_SEND_WITH_INVALID:
		return wr->send.src.num_sge > sq->max_sge_num;
	default:
		return wr->rw.src.num_sge > sq->max_sge_num;
	}
}

static void udma_copy_to_sq(struct udma_jetty_queue *sq, uint32_t wqebb_cnt,
			    struct udma_jfs_wqebb *tmp_sq)
{
	uint32_t remain = sq->buf.entry_cnt - (sq->pi & (sq->buf.entry_cnt - 1));
	uint32_t field_h;
	uint32_t field_l;

	field_h = remain > wqebb_cnt ? wqebb_cnt : remain;
	field_l = wqebb_cnt - field_h;

	memcpy(sq->kva_curr, tmp_sq, field_h * sizeof(*tmp_sq));

	if (field_l)
		memcpy(sq->buf.kva, tmp_sq + field_h, field_l * sizeof(*tmp_sq));
}

static void *udma_k_inc_ptr_wrap(uint32_t sq_buf_size, uint32_t wqebb_size,
				 uint8_t *sq_base_addr, uint8_t *sq_buf_curr)
{
	uint8_t *sq_buf_end;

	sq_buf_end = (uint8_t *)(sq_buf_size + sq_base_addr);

	sq_buf_curr = ((sq_buf_curr + wqebb_size) < sq_buf_end) ?
		       (sq_buf_curr + wqebb_size) : sq_base_addr + (sq_buf_curr +
		       wqebb_size - sq_buf_end);

	return sq_buf_curr;
}

static int udma_post_one_wr(struct udma_jetty_queue *sq, struct ubcore_jfs_wr *wr,
			    struct udma_dev *udma_dev, struct udma_sqe_ctl **wqe_addr,
			    bool *dwqe_enable)
{
	struct udma_jfs_wqebb tmp_sq[MAX_WQEBB_NUM] = {};
	uint32_t wqebb_cnt;
	uint8_t opcode;
	uint32_t i;
	int ret;

	opcode = udma_get_jfs_opcode(wr->opcode);
	if (unlikely(opcode == UDMA_OPC_INVALID)) {
		dev_err(udma_dev->dev, "Invalid opcode :%u.\n", wr->opcode);
		return -EINVAL;
	}

	if (unlikely(udma_k_check_sge_num(opcode, sq, wr))) {
		dev_err(udma_dev->dev, "WR sge num invalid.\n");
		return -EINVAL;
	}

	ret = udma_k_set_sqe((struct udma_sqe_ctl *)(void *)tmp_sq, wr, sq,
			     opcode, udma_dev);
	if (ret)
		return ret;

	wqebb_cnt = get_wqebb_num((struct udma_sqe_ctl *)(void *)tmp_sq);
	if (wqebb_cnt == 1 && !!(udma_dev->caps.feature & UDMA_CAP_FEATURE_DIRECT_WQE))
		*dwqe_enable = true;

	if (to_check_sq_overflow(sq, wqebb_cnt)) {
		dev_err(udma_dev->dev, "JFS overflow, wqebb_cnt:%u.\n", wqebb_cnt);
		return -ENOMEM;
	}

	udma_copy_to_sq(sq, wqebb_cnt, tmp_sq);

	*wqe_addr = (struct udma_sqe_ctl *)sq->kva_curr;

	sq->kva_curr = udma_k_inc_ptr_wrap(sq->buf.entry_cnt * sq->buf.entry_size,
					   wqebb_cnt * sq->buf.entry_size,
					   (uint8_t *)sq->buf.kva,
					   (uint8_t *)sq->kva_curr);

	for (i = 0; i < wqebb_cnt; i++)
		sq->wrid[(sq->pi + i) & (sq->buf.entry_cnt - 1)] = wr->user_ctx;

	sq->pi += wqebb_cnt;

	return 0;
}

#ifdef ST64B
static void st64b(uint64_t *src, uint64_t *dst)
{
	asm volatile (
		"mov x9, %0\n"
		"mov x10, %1\n"
		"ldr x0, [x9]\n"
		"ldr x1, [x9, #8]\n"
		"ldr x2, [x9, #16]\n"
		"ldr x3, [x9, #24]\n"
		"ldr x4, [x9, #32]\n"
		"ldr x5, [x9, #40]\n"
		"ldr x6, [x9, #48]\n"
		"ldr x7, [x9, #56]\n"
		".inst 0xf83f9140\n"
		::"r" (src), "r"(dst):"cc", "memory"
	);
}
#endif

static void udma_write_dsqe(struct udma_jetty_queue *sq,
			    struct udma_sqe_ctl *ctrl)
{
#define DWQE_SIZE 8
	int i;

	ctrl->sqe_bb_idx = sq->pi;

#ifdef ST64B
	st64b(((uint64_t *)ctrl), (uint64_t *)sq->dwqe_addr);
#else
	for (i = 0; i < DWQE_SIZE; i++)
		writeq_relaxed(*((uint64_t *)ctrl + i),
				(uint64_t *)sq->dwqe_addr + i);
#endif
}

/* thanks to drivers/infiniband/hw/bnxt_re/ib_verbs.c */
int udma_post_sq_wr(struct udma_dev *udma_dev, struct udma_jetty_queue *sq,
		    struct ubcore_jfs_wr *wr, struct ubcore_jfs_wr **bad_wr)
{
	struct udma_sqe_ctl *wqe_addr;
	bool dwqe_enable = false;
	struct ubcore_jfs_wr *it;
	unsigned long flags;
	int wr_cnt = 0;
	int ret = 0;

	if (!sq->lock_free)
		spin_lock_irqsave(&sq->lock, flags);

	for (it = wr; it != NULL; it = (struct ubcore_jfs_wr *)(void *)it->next) {
		ret = udma_post_one_wr(sq, it, udma_dev, &wqe_addr, &dwqe_enable);
		if (ret) {
			*bad_wr = it;
			goto err_post_wr;
		}
		wr_cnt++;
	}

err_post_wr:
	if (unlikely(sq->db_status)) {
		sq->need_ring_db = true;
	} else {
		if (likely(wr_cnt && udma_dev->status != UDMA_SUSPEND)) {
			wmb(); /* set sqe before doorbell */
			if (wr_cnt == 1 && dwqe_enable && (sq->pi - sq->ci == 1))
				udma_write_dsqe(sq, wqe_addr);
			else
				udma_k_update_sq_db(sq);
		}
	}

	if (!sq->lock_free)
		spin_unlock_irqrestore(&sq->lock, flags);

	return ret;
}

int udma_post_jfs_wr(struct ubcore_jfs *jfs, struct ubcore_jfs_wr *wr,
		     struct ubcore_jfs_wr **bad_wr)
{
	struct udma_dev *udma_dev = to_udma_dev(jfs->ub_dev);
	struct udma_jfs *udma_jfs = to_udma_jfs(jfs);
	int ret;

	ret = udma_post_sq_wr(udma_dev, &udma_jfs->sq, wr, bad_wr);
	if (ret)
		dev_err(udma_dev->dev, "Failed to post jfs wr, sq_id = %u.\n",
			udma_jfs->sq.id);

	return ret;
}

int udma_alloc_jfs(struct ubcore_device *dev, struct ubcore_jfs_cfg *cfg,
		   struct ubcore_jfs **jfs, struct ubcore_udata *udata)
{
	struct udma_jfs *udma_jfs;

	udma_jfs = kzalloc(sizeof(*udma_jfs), GFP_KERNEL);
	if (!udma_jfs)
		return -ENOMEM;

	udma_jfs->ubcore_jfs.jfs_cfg = *cfg;

	*jfs = &udma_jfs->ubcore_jfs;

	return 0;
}

int udma_free_jfs(struct ubcore_jfs *jfs, struct ubcore_udata *udata)
{
	kfree(jfs);

	return 0;
}

int udma_set_jfs_opt(struct ubcore_jfs *jfs, uint64_t opt, void *buf,
		     uint32_t len, struct ubcore_udata *udata)
{
	struct udma_jetty_opt_attr attr = {opt, buf, len, JFS_MODE, PERM_W, !!udata};
	struct udma_dev *udma_dev = to_udma_dev(jfs->ub_dev);
	struct udma_jfs *udma_jfs = to_udma_jfs(jfs);
	int ret;

	ret = udma_verify_jetty_opt(udma_dev, attr);
	if (ret == -EEXIST)
		return 0;

	if (ret)
		return ret;

	if (opt == UBCORE_JFS_ID) {
		udma_jfs->sq.id = *(uint32_t *)buf;
		return 0;
	}

	return udma_set_jetty_field(udma_dev, &udma_jfs->sq, opt, buf);
}

int udma_get_jfs_opt(struct ubcore_jfs *jfs, uint64_t opt, void *buf,
		     uint32_t len, struct ubcore_udata *udata)
{
	struct udma_jetty_opt_attr attr = {opt, buf, len, JFS_MODE, PERM_R, !!udata};
	struct udma_dev *udma_dev = to_udma_dev(jfs->ub_dev);
	struct udma_jfs *udma_jfs = to_udma_jfs(jfs);
	int ret;

	ret = udma_verify_jetty_opt(udma_dev, attr);
	if (ret == -EEXIST)
		return 0;

	if (ret)
		return ret;

	udma_get_jfs_cfg_field(&jfs->jfs_cfg, opt, buf);

	return udma_get_jetty_field(udma_dev, &udma_jfs->sq, opt, buf);
}
