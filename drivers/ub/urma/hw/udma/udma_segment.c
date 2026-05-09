// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt

#include <linux/iommu.h>
#include <linux/slab.h>
#include <linux/ummu_core.h>
#include "udma_common.h"
#include "udma_cmd.h"
#include "udma_eid.h"
#include "udma_tid.h"
#include "udma_segment.h"

static int udma_pin_segment(struct ubcore_device *ub_dev, struct ubcore_seg_cfg *cfg,
			    struct udma_segment *seg, bool is_writable)
{
	struct udma_dev *udma_dev = to_udma_dev(ub_dev);
	struct udma_umem_param param;
	int ret = 0;

	param.ub_dev = ub_dev;
	param.va = cfg->va;
	param.len = cfg->len;

	param.flag.bs.writable = is_writable;
	param.flag.bs.non_pin = cfg->flag.bs.non_pin;
	param.is_kernel = seg->kernel_mode;

	seg->umem = udma_umem_get(&param);
	if (IS_ERR(seg->umem)) {
		ret = PTR_ERR(seg->umem);
		dev_err(udma_dev->dev,
			"failed to get segment umem, ret = %d.\n", ret);
	}

	return ret;
}

static void udma_unpin_seg(struct udma_segment *seg, bool dirty)
{
	if (!seg->core_tseg.seg.attr.bs.non_pin)
		udma_umem_release(seg->umem, seg->kernel_mode, dirty);
}

static int udma_check_seg_cfg(struct udma_dev *udma_dev, struct ubcore_seg_cfg *cfg)
{
	if (!cfg->token_id || cfg->flag.bs.access >= UDMA_SEGMENT_ACCESS_GUARD ||
	    cfg->flag.bs.token_policy >= UBCORE_TOKEN_SIGNED) {
		dev_err(udma_dev->dev,
			"error segment input, access = %d, token_policy = %d, or null key_id.\n",
			cfg->flag.bs.access, cfg->flag.bs.token_policy);
		return -EINVAL;
	}

	return 0;
}

static void udma_init_seg_cfg(struct udma_segment *seg, struct ubcore_seg_cfg *cfg)
{
	seg->core_tseg.token_id = cfg->token_id;
	seg->core_tseg.seg.token_id = cfg->token_id->token_id;
	seg->core_tseg.seg.attr.value = cfg->flag.value;
	seg->token_value = cfg->token_value.token;
	seg->token_value_valid = cfg->flag.bs.token_policy != UBCORE_TOKEN_NONE;
	seg->addr = cfg->va;
	seg->length = cfg->len;
}

static int udma_u_get_seg_perm(struct ubcore_seg_cfg *cfg)
{
	bool local_only_flag = cfg->flag.bs.access & UBCORE_ACCESS_LOCAL_ONLY;
	bool atomic_flag = cfg->flag.bs.access & UBCORE_ACCESS_ATOMIC;
	bool write_flag = cfg->flag.bs.access & UBCORE_ACCESS_WRITE;
	bool read_flag = cfg->flag.bs.access & UBCORE_ACCESS_READ;

	/* After setting ACCESS_LOCAL, other operations cannot be configured. */
	if (local_only_flag && !atomic_flag && !write_flag && !read_flag)
		return UMMU_DEV_ATOMIC | UMMU_DEV_WRITE | UMMU_DEV_READ;

	/* Atomic require additional configuration of write and read. */
	if (!local_only_flag && atomic_flag && write_flag && read_flag)
		return UMMU_DEV_ATOMIC | UMMU_DEV_WRITE | UMMU_DEV_READ;

	/* Write require additional configuration of read. */
	if (!local_only_flag && !atomic_flag && write_flag && read_flag)
		return UMMU_DEV_WRITE | UMMU_DEV_READ;

	if (!local_only_flag && !atomic_flag && !write_flag && read_flag)
		return UMMU_DEV_READ;

	/* All other configurations are illegal. */
	return 0;
}

static int udma_sva_grant(struct ubcore_seg_cfg *cfg, struct iommu_sva *ksva)
{
#define UDMA_TOKEN_VALUE_INPUT 0
	struct ummu_seg_attr seg_attr = {.token = NULL, .e_bit = UMMU_EBIT_ON};
	struct ummu_token_info token_info;
	int perm;
	int ret;

	perm = udma_u_get_seg_perm(cfg);

	seg_attr.e_bit = (enum ummu_ebit_state)cfg->flag.bs.access &
			  UBCORE_ACCESS_LOCAL_ONLY;

	if (cfg->flag.bs.token_policy == UBCORE_TOKEN_NONE) {
		return iommu_sva_grant(ksva, (void *)(uintptr_t)cfg->va, cfg->len,
					    perm, (void *)&seg_attr);
	} else {
		seg_attr.token = &token_info;
		token_info.input = UDMA_TOKEN_VALUE_INPUT;
		token_info.tokenVal = cfg->token_value.token;
		ret = iommu_sva_grant(ksva, (void *)(uintptr_t)cfg->va, cfg->len,
					    perm, (void *)&seg_attr);
		token_info.tokenVal = 0;

		return ret;
	}
}

static void udma_dfx_store_seg(struct udma_dev *udma_dev,
			       struct ubcore_seg_cfg *cfg)
{
	struct udma_dfx_seg *seg;
	int ret;

	seg = (struct udma_dfx_seg *)xa_load(&udma_dev->dfx_info->seg.table,
					     cfg->token_id->token_id);
	if (seg) {
		dev_warn(udma_dev->dev, "segment already exists in DFX.\n");
		return;
	}

	seg = kzalloc(sizeof(*seg), GFP_KERNEL);
	if (!seg)
		return;

	seg->id = cfg->token_id->token_id;
	seg->ubva.va = cfg->va;
	seg->len = cfg->len;
	seg->token_value = cfg->token_value;

	write_lock(&udma_dev->dfx_info->seg.rwlock);
	ret = xa_err(xa_store(&udma_dev->dfx_info->seg.table, cfg->token_id->token_id,
			      seg, GFP_KERNEL));
	if (ret) {
		write_unlock(&udma_dev->dfx_info->seg.rwlock);
		dev_err(udma_dev->dev, "store segment to table failed in DFX.\n");
		kfree(seg);
		return;
	}

	++udma_dev->dfx_info->seg.cnt;
	write_unlock(&udma_dev->dfx_info->seg.rwlock);
}

static void udma_dfx_delete_seg(struct udma_dev *udma_dev, uint32_t token_id,
				uint64_t va)
{
	struct udma_dfx_seg *seg;

	write_lock(&udma_dev->dfx_info->seg.rwlock);
	seg = (struct udma_dfx_seg *)xa_load(&udma_dev->dfx_info->seg.table,
					     token_id);
	if (seg && seg->id == token_id && seg->ubva.va == va) {
		xa_erase(&udma_dev->dfx_info->seg.table, token_id);
		seg->token_value.token = 0;
		kfree(seg);
		--udma_dev->dfx_info->seg.cnt;
	}
	write_unlock(&udma_dev->dfx_info->seg.rwlock);
}

static int pin_pages_and_ioummu_map(struct ubcore_device *ub_dev, struct udma_context *ctx,
				    struct udma_segment *seg, struct ubcore_seg_cfg *cfg, int tid)
{
	uint32_t access = seg->core_tseg.seg.attr.bs.access;
	int prot = IOMMU_WRITE | IOMMU_READ;
	int ret;

	ret = udma_pin_segment(ub_dev, cfg, seg, true);
	if (unlikely(ret)) {
		prot = IOMMU_READ;
		ret = udma_pin_segment(ub_dev, cfg, seg, false);
		if (unlikely(ret)) {
			dev_err(ctx->dev->dev, "pin sva segment failed, ret = %d.\n", ret);
			return ret;
		}
	}
	ret = udma_ioummu_map(ctx, (access & UBCORE_ACCESS_LOCAL_ONLY) ? UMMU_INVALID_TID : tid,
						   prot, seg->addr, &(seg->umem->append.sgt));
	if (unlikely(ret)) {
		udma_umem_release(seg->umem, seg->kernel_mode, false);
		dev_err(ctx->dev->dev, "ioummu map failed, ret = %d.\n", ret);
	}
	return ret;
}

static void unpin_pages_and_unioummu_map(struct udma_context *ctx, struct udma_segment *seg,
					 int tid)
{
	uint32_t access = seg->core_tseg.seg.attr.bs.access;

	udma_ioummu_unmap(ctx, (access & UBCORE_ACCESS_LOCAL_ONLY) ? UMMU_INVALID_TID : tid,
			  seg->addr, PAGE_SIZE * udma_cal_npages(seg->addr, seg->length));
	udma_umem_release(seg->umem, seg->kernel_mode, true);
}

struct ubcore_target_seg *udma_register_seg(struct ubcore_device *ub_dev,
					    struct ubcore_seg_cfg *cfg,
					    struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(ub_dev);
	struct udma_tid *udma_tid;
	struct udma_segment *seg;
	struct iommu_sva *ksva;
	int ret = 0;

	ret = udma_check_seg_cfg(udma_dev, cfg);
	if (ret)
		return NULL;

	seg = kzalloc(sizeof(*seg), GFP_KERNEL);
	if (!seg)
		return NULL;

	seg->kernel_mode = udata == NULL;
	udma_init_seg_cfg(seg, cfg);
	udma_tid = to_udma_tid(seg->core_tseg.token_id);

	if (udata && udma_dev->caps.sva_sep_mode_en) {
		ret = pin_pages_and_ioummu_map(ub_dev, to_udma_context(udata->uctx), seg,
					       cfg, udma_tid->tid);
		if (ret) {
			dev_err(udma_dev->dev, "ioummu map failed, ret = %d.\n", ret);
			goto err_pin_seg;
		}
		return &seg->core_tseg;
	}

	if (!cfg->flag.bs.non_pin) {
		ret = udma_pin_segment(ub_dev, cfg, seg,
				       !!(cfg->flag.bs.access & UBCORE_ACCESS_WRITE));
		if (ret) {
			dev_err(udma_dev->dev, "pin segment failed, ret = %d.\n", ret);
			goto err_pin_seg;
		}
	}

	if (udata)
		return &seg->core_tseg;

	mutex_lock(&udma_dev->ksva_mutex);
	ksva = (struct iommu_sva *)xa_load(&udma_dev->ksva_table, udma_tid->tid);
	if (!ksva) {
		dev_err(udma_dev->dev,
			"unable to get ksva while register segment, token maybe is free.\n");
		goto err_load_ksva;
	}

	ret = udma_sva_grant(cfg, ksva);
	if (ret) {
		dev_err(udma_dev->dev,
			"ksva grant failed token policy %d, access %d, ret = %d.\n",
			cfg->flag.bs.token_policy, cfg->flag.bs.access, ret);
		goto err_load_ksva;
	}
	mutex_unlock(&udma_dev->ksva_mutex);

	if (dfx_switch)
		udma_dfx_store_seg(udma_dev, cfg);

	return &seg->core_tseg;

err_load_ksva:
	mutex_unlock(&udma_dev->ksva_mutex);
	udma_unpin_seg(seg, false);
err_pin_seg:
	seg->token_value = 0;
	kfree(seg);
	return NULL;
}

int udma_unregister_seg(struct ubcore_target_seg *ubcore_seg)
{
	struct udma_tid *udma_tid = to_udma_tid(ubcore_seg->token_id);
	struct udma_dev *udma_dev = to_udma_dev(ubcore_seg->ub_dev);
	struct udma_segment *seg = to_udma_seg(ubcore_seg);
	struct ummu_token_info token_info;
	struct iommu_sva *ksva;
	int ret;

	if (!seg->kernel_mode)
		goto common_process;

	mutex_lock(&udma_dev->ksva_mutex);
	ksva = (struct iommu_sva *)xa_load(&udma_dev->ksva_table, udma_tid->tid);
	if (!ksva) {
		dev_warn(udma_dev->dev,
			 "unable to get ksva while unregister segment, token maybe is free.\n");
	} else {
		if (seg->token_value_valid) {
			token_info.tokenVal = seg->token_value;
			ret = iommu_sva_ungrant(ksva,
						     (void *)(uintptr_t)ubcore_seg->seg.ubva.va,
						     ubcore_seg->seg.len, &token_info);
			token_info.tokenVal = 0;
		} else {
			ret = iommu_sva_ungrant(ksva,
						     (void *)(uintptr_t)ubcore_seg->seg.ubva.va,
						     ubcore_seg->seg.len, NULL);
		}
		if (ret) {
			mutex_unlock(&udma_dev->ksva_mutex);
			dev_err(udma_dev->dev, "unregister segment failed, ret = %d.\n", ret);
			return ret;
		}
	}
	mutex_unlock(&udma_dev->ksva_mutex);

	if (dfx_switch)
		udma_dfx_delete_seg(udma_dev, ubcore_seg->token_id->token_id,
				    ubcore_seg->seg.ubva.va);

common_process:
	if (!seg->kernel_mode && udma_dev->caps.sva_sep_mode_en)
		unpin_pages_and_unioummu_map(to_udma_context(ubcore_seg->uctx), seg, udma_tid->tid);
	else
		udma_unpin_seg(seg, true);
	seg->token_value = 0;
	kfree(seg);

	return 0;
}

struct ubcore_target_seg *udma_import_seg(struct ubcore_device *dev,
					  struct ubcore_target_seg_cfg *cfg,
					  struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct udma_segment *seg;

	if (cfg->seg.attr.bs.token_policy > UBCORE_TOKEN_PLAIN_TEXT) {
		dev_err(udma_dev->dev, "invalid token policy = %d.\n",
			cfg->seg.attr.bs.token_policy);
		return NULL;
	}

	seg = kzalloc(sizeof(*seg), GFP_KERNEL);
	if (!seg)
		return NULL;

	if (cfg->seg.attr.bs.token_policy != UBCORE_TOKEN_NONE) {
		seg->token_value = cfg->token_value.token;
		seg->token_value_valid = true;
	}

	seg->tid = cfg->seg.token_id >> UDMA_TID_SHIFT;

	return &seg->core_tseg;
}

int udma_unimport_seg(struct ubcore_target_seg *tseg)
{
	struct udma_segment *seg;

	seg = to_udma_seg(tseg);
	seg->token_value = 0;
	kfree(seg);

	return 0;
}
