// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_cq.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <rdma/uverbs_ioctl.h>
#include <rdma/ib_umem.h>
#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/stddef.h>
#include <linux/sysfs.h>

#include "sxe2_compat.h"
#include "sxe2-abi.h"
#include "sxe2_drv_cq.h"
#include "sxe2_drv_eq.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_db.h"
#include "sxe2_drv_rdma_rcms.h"
#include "sxe2_drv_rdma_pble.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_cq_debugfs.h"

#define DRV_CQC_PAGESZ_WIDTH	 (5)
#define DRV_PBL_INDEX_HIGH_SHIFT (32)
#define SXE2_DRV_RDMA_MINCQ_SIZE (4)
#define SXE2_CQC_PHY_ADDR_OFFSET 8

#define SXE2_CQ_DB_NOTE_CMD_SN_SHIFT (29)
#define SXE2_CQ_DB_NOTE_CMD_SN	     (3)

static inline u32 drv_get_cqe_count(u32 ncqe)
{
	ncqe++;
	ncqe = (u32)roundup_pow_of_two(ncqe);
	if (ncqe < SXE2_DRV_RDMA_MINCQ_SIZE)
		ncqe = SXE2_DRV_RDMA_MINCQ_SIZE;
	return ncqe;
}

void drv_rdma_cq_set_pbl(struct sxe2_pbl_pble_rsrc *pble_rsrc,
			 struct sxe2_rdma_cq *cq, size_t page_sz, u32 ncont,
			 struct drv_rdma_soft_cqc *cqc)
{
	u32 pbl_cnt = 0;
	u64 page_addr;
	u64 temp_liner_addr;
	struct ib_block_iter biter;

	if (ncont != 1) {
		temp_liner_addr = cq->palloc.pble_info.liner_addr;
		rdma_umem_for_each_dma_block(cq->cq_umem, &biter, page_sz) {
			page_addr = rdma_block_iter_dma_address(&biter);
			sxe2_pbl_set_pble(pble_rsrc, temp_liner_addr, page_addr,
					  false);
			if (++pbl_cnt == cq->palloc.needed_pble_cnt)
				break;
			temp_liner_addr += sizeof(u64);
		}
	} else {
		rdma_umem_for_each_dma_block(cq->cq_umem, &biter, page_sz) {
			cqc->pbl_index = rdma_block_iter_dma_address(&biter);
		}
	}
}

#ifdef CREATE_CQ_V1
STATIC long sxe2_drv_create_cq_user(struct sxe2_rdma_device *rdma_dev,
				    struct ib_udata *udata,
				    struct sxe2_rdma_cq *cq,
				    struct sxe2_cq_init_info *info,
				    u32 entries, struct ib_ucontext *ibucontext)
#else
STATIC long sxe2_drv_create_cq_user(struct sxe2_rdma_device *rdma_dev,
				    struct ib_udata *udata,
				    struct sxe2_rdma_cq *cq,
				    struct sxe2_cq_init_info *info, u32 entries)

#endif
{
	long ret;
	u32 ncont;
	ulong page_size;
	struct sxe2_create_cq_req ucmd;
	struct drv_rdma_soft_cqc *cqc;
#ifdef IB_UMEM_GET_V3
#endif
	if (udata->inlen < sizeof(ucmd)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("invalid udata create cq, ret (%ld)\n",
				     ret);
		goto end;
	}

	cq->user_mode = true;
	memset(&ucmd, 0, sizeof(ucmd));
	if (ib_copy_from_udata(&ucmd, udata, udata->inlen)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR("copy fail len %zu , ret (%ld)\n",
				     udata->inlen, ret);
		goto end;
	}
#ifdef IB_UMEM_GET_V2
	cq->cq_umem = ib_umem_get(udata, ucmd.user_cq_buf,
				  entries * sizeof(struct sxe2_cqe),
				  IB_ACCESS_LOCAL_WRITE);
#elif defined(IB_UMEM_GET_V1)
	cq->cq_umem = ib_umem_get(udata, ucmd.user_cq_buf,
				  entries * sizeof(struct sxe2_cqe),
				  IB_ACCESS_LOCAL_WRITE, 0);
#elif defined(IB_UMEM_GET_V3)
		cq->cq_umem = ib_umem_get(ibucontext, ucmd.user_cq_buf,
					  entries * sizeof(struct sxe2_cqe),
					  IB_ACCESS_LOCAL_WRITE, 0);
#else
	cq->cq_umem = ib_umem_get(&rdma_dev->ibdev, ucmd.user_cq_buf,
				  entries * sizeof(struct sxe2_cqe),
				  IB_ACCESS_LOCAL_WRITE);
#endif
	if (IS_ERR(cq->cq_umem)) {
		ret = PTR_ERR(cq->cq_umem);
		DRV_RDMA_LOG_DEV_ERR(
			"pin buf ret bufaddr %#llx  entries %u, ret (%ld)\n",
			ucmd.user_cq_buf, entries, ret);
		goto end;
	}
#ifdef HAVE_NO_IB_UMEM_FIND_BEST_PGSZ
	page_size = sxe2_set_best_pagesz(ucmd.user_cq_buf, cq->cq_umem,
					log_page_size_2_bitmap(DRV_CQC_PAGESZ_WIDTH, PAGE_SHIFT));
#else
	page_size = sxe2_umem_find_best_pgsz(cq->cq_umem, DRV_CQC_PAGESZ_WIDTH,
					     PAGE_SHIFT, 0);
#endif
	if (!page_size) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("pin buf ret bufaddr %#llx, ret (%ld)\n",
				     ucmd.user_cq_buf, ret);
		goto err_cq_umem;
	}
#ifdef HAVE_IB_UMEM_NUM_DMA_BLOCKS_NOT_SUPPORT
	ncont = sxe2_ib_umem_num_dma_blocks(cq->cq_umem, page_size, 0);
#else
	ncont = ib_umem_num_dma_blocks(cq->cq_umem, page_size);
#endif
	DRV_RDMA_LOG_DEV_INFO(
		"addr %#llx, size %lu, npages %zu, page_size %lu, ncont %u\n",
		ucmd.user_cq_buf, entries * sizeof(struct sxe2_cqe),
		ib_umem_num_pages(cq->cq_umem), page_size, ncont);

	cqc = &info->cqc;
	if (ncont != 1) {
		ret = sxe2_pbl_get_pble(rdma_dev->rdma_func->pble_rsrc,
					&cq->palloc, ncont, PBL_OBJ_CQ);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR("cq get pble failed. ret:%ld\n",
					     ret);
			goto err_cq_umem;
		}
		drv_rdma_cq_set_pbl(rdma_dev->rdma_func->pble_rsrc, cq,
				    page_size, ncont, cqc);
		cqc->pbl_index = cq->palloc.pbl_index;
		cqc->pbl_mode  = cq->palloc.pbl_mode.cq_eq_mode;
	} else {
		drv_rdma_cq_set_pbl(rdma_dev->rdma_func->pble_rsrc, cq,
				    page_size, ncont, cqc);
		cqc->pbl_mode = CQ_EQ_PA_FIRST_MODE;
	}
#ifdef IB_UMEM_GET_V2
	cq->db_umem =
		ib_umem_get(udata, ucmd.user_cq_db_note, SXE2_RDMA_DB_NOTE_SIZE,
			    IB_ACCESS_LOCAL_WRITE);
#elif defined(IB_UMEM_GET_V1)
	cq->db_umem =
		ib_umem_get(udata, ucmd.user_cq_db_note, SXE2_RDMA_DB_NOTE_SIZE,
			    IB_ACCESS_LOCAL_WRITE, 0);
#elif defined(IB_UMEM_GET_V3)
	cq->db_umem = ib_umem_get(ibucontext, ucmd.user_cq_db_note,
				  SXE2_RDMA_DB_NOTE_SIZE,
				  IB_ACCESS_LOCAL_WRITE, 0);
#else
	cq->db_umem =
		ib_umem_get(&rdma_dev->ibdev, ucmd.user_cq_db_note,
			    SXE2_RDMA_DB_NOTE_SIZE, IB_ACCESS_LOCAL_WRITE);
#endif
	if (IS_ERR(cq->db_umem)) {
		ret = PTR_ERR(cq->db_umem);
		DRV_RDMA_LOG_DEV_ERR("pin buf ret bufaddr %#llx , ret (%ld)\n",
				     ucmd.user_cq_db_note, ret);
		goto err_db_umem;
	}

#ifdef HAVE_IB_UMEM_SG_HEAD
	info->db_pa = sg_dma_address(cq->db_umem->sg_head.sgl) +
		      (ucmd.user_cq_db_note & ~PAGE_MASK);
#else
	info->db_pa = sg_dma_address(cq->db_umem->sgt_append.sgt.sgl) +
		      (ucmd.user_cq_db_note & ~PAGE_MASK);
#endif
	info->cq_uk_init_info.ncqe = entries;

	cqc->log_page_size = order_base_2(page_size);
	cqc->page_offset   = 0;

	ret = 0;
	goto end;

err_db_umem:
	if (ncont != 1) {
		sxe2_pbl_free_pble(rdma_dev->rdma_func->pble_rsrc,
				   cq->palloc.pble_info.liner_addr,
				   cq->palloc.needed_pble_cnt, false);
	}
err_cq_umem:
	ib_umem_release(cq->cq_umem);
	cq->cq_umem = NULL;
end:
	return ret;
}

STATIC int sxe2_drv_create_cq_kernel(struct sxe2_rdma_device *rdma_dev,
				     struct sxe2_rdma_cq *cq,
				     struct sxe2_cq_init_info *info,
				     u32 entries)
{
	int ret = 0;
	u32 cqe_count;
	u32 cq_size;
	struct sxe2_rdma_ctx_dev *dev_ctx;
	struct drv_rdma_soft_cqc *cqc;
	struct sxe2_rdma_cq_uk_init_info *uk_info;

	if ((entries < 1) || (entries > rdma_dev->rdma_func->max_cqe)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("invalid entries:%d, ret:%d\n", entries,
				     ret);
		goto end;
	}

	dev_ctx	  = &(rdma_dev->rdma_func->ctx_dev);
	cqe_count = drv_get_cqe_count(entries);
	if ((cqe_count < SXE2_RDMA_MIN_CQ_SIZE) ||
	    (cqe_count > SXE2_RDMA_MAX_CQ_SIZE)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("cq size(%d) invalid.ret:%d", cqe_count,
				     ret);
		goto end;
	}

	cq_size = (u32)cqe_count * sizeof(struct sxe2_cqe);

	cq->kmem.size = ALIGN(round_up(cq_size, 4096), 4096);
	cq->kmem.va   = dma_alloc_coherent(dev_ctx->hw->device, cq->kmem.size,
					   &cq->kmem.pa, GFP_KERNEL);
	if (!cq->kmem.va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("kernel cq buf alloc failed, ret:%d\n",
				     ret);
		goto end;
	}
	memset(cq->kmem.va, 0, cq->kmem.size);

	cq->kmem_db.size = SXE2_RDMA_DB_NOTE_SIZE;
	cq->kmem_db.va =
		dma_alloc_coherent(dev_ctx->hw->device, cq->kmem_db.size,
				   &cq->kmem_db.pa, GFP_KERNEL);
	if (!cq->kmem_db.va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"kernel cq db note buf alloc failed, ret:%d\n", ret);
		goto err_db_alloc;
	}
	memset(cq->kmem_db.va, 0, cq->kmem_db.size);
	set_32bit_val(cq->kmem_db.va, 4,
		      (__u32)(SXE2_CQ_DB_NOTE_CMD_SN)
			      << SXE2_CQ_DB_NOTE_CMD_SN_SHIFT);

	info->cq_pa = cq->kmem.pa;
	info->db_pa = cq->kmem_db.pa;

	uk_info		       = &info->cq_uk_init_info;
	uk_info->ncqe	       = cqe_count;
	uk_info->cq_base       = cq->kmem.va;
	uk_info->doorbell_note = cq->kmem_db.va;

	cqc		   = &info->cqc;
	cqc->log_page_size = order_base_2(PAGE_SIZE);
	cqc->page_offset   = offset_in_page(cq->kmem.pa);
	cqc->pbl_mode	   = CQ_EQ_PA_FIRST_MODE;
	cqc->pbl_index	   = cq->kmem.pa;
	goto end;

err_db_alloc:
	dma_free_coherent(dev_ctx->hw->device, cq->kmem.size, cq->kmem.va,
			  cq->kmem.pa);
	cq->kmem.va = NULL;

end:
	return ret;
}

STATIC void sxe2_drv_destroy_cq_user(struct sxe2_rdma_device *rdma_dev,
				     struct sxe2_rdma_cq *cq,
				     struct ib_udata *udata)
{
	ib_umem_release(cq->cq_umem);
	cq->cq_umem = NULL;

	ib_umem_release(cq->db_umem);
	cq->db_umem = NULL;

	if (cq->cq_ctx.cqc.pbl_mode != CQ_EQ_PA_FIRST_MODE) {
		sxe2_pbl_free_pble(rdma_dev->rdma_func->pble_rsrc,
				   cq->palloc.pble_info.liner_addr,
				   cq->palloc.needed_pble_cnt, false);
	}
}

STATIC void sxe2_drv_destroy_cq_kernel(struct sxe2_rdma_pci_f *rdma_func,
				       struct sxe2_rdma_cq *cq)
{
	dma_free_coherent(rdma_func->ctx_dev.hw->device, cq->kmem.size,
			  cq->kmem.va, cq->kmem.pa);
	cq->kmem.va = NULL;
	dma_free_coherent(rdma_func->ctx_dev.hw->device, cq->kmem_db.size,
			  cq->kmem_db.va, cq->kmem_db.pa);
	cq->kmem_db.va = NULL;
}

void sxe2_rdma_uk_cq_init(struct sxe2_rdma_cq_uk *cq,
			  struct sxe2_rdma_cq_uk_init_info *info)
{
	cq->cq_base	  = info->cq_base;
	cq->cqe_alloc_db  = info->cqe_alloc_db;
	cq->cq_id	  = info->cq_id;
	cq->ncqe	  = info->ncqe;
	cq->doorbell_note = info->doorbell_note;
	SXE2_RING_INIT(cq->cq_ring, cq->ncqe);
	cq->polarity = 1;
	cq->arm_sn = SXE2_RDMA_CQ_ARM_SN;
}

void sxe2_drv_cq_ctx_init(struct sxe2_rdma_device *rdma_dev,
			  struct sxe2_rdma_cq *cq,
			  struct sxe2_cq_init_info *info)
{
	struct sxe2_rdma_ctx_cq *cq_ctx;
	u32 st_mode = 0;
	s32 cpu_id  = 0;

	cq_ctx = &cq->cq_ctx;

	cq_ctx->back_cq = cq;
	cq_ctx->cq_type = SXE2_RDMA_CQ_TYPE_IO;
	cq_ctx->cq_pa	= info->cq_pa;
	cq_ctx->db_pa	= info->db_pa;
	cq_ctx->dev	= &(rdma_dev->rdma_func->ctx_dev);
	cq_ctx->vsi	= &rdma_dev->vsi;

	sxe2_rdma_uk_cq_init(&cq_ctx->cq_uk, &info->cq_uk_init_info);

	cq_ctx->cqc.eqn		 = info->cqc.eqn;
	cq_ctx->cqc.log_dbr_size = info->cqc.log_dbr_size;
	cq_ctx->cqc.log_cq_size	 = info->cqc.log_cq_size;
	cq_ctx->cqc.scqe_break_moderation_en =
		rdma_dev->rdma_func->scqe_break_moderation_en;
	cq_ctx->cqc.oi		 = info->cqc.oi;
	cq_ctx->cqc.sw_owner_bit = 0;
	cq_ctx->cqc.sw_status	 = 0XF;
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "cq_sw_status_err", rdma_dev, cq_ctx);
#endif
	cq_ctx->cqc.pbl_index	  = info->cqc.pbl_index;
	cq_ctx->cqc.dbr_addr	  = info->cqc.dbr_addr;
	cq_ctx->cqc.log_page_size = info->cqc.log_page_size;
	cq_ctx->cqc.page_offset	  = info->cqc.page_offset;
	cq_ctx->cqc.pbl_mode	  = info->cqc.pbl_mode;
	cq_ctx->cqc.cq_max_count  = 0;
	cq_ctx->cqc.cq_period	  = 0;
	cq_ctx->cqc.TPH_en =
		sxe2_drv_core_is_tph_enable(rdma_dev, true, &st_mode);
	if (cq_ctx->cqc.TPH_en) {
		if (st_mode != MODE_NO_ST)
			cpu_id = TPH_GET_CPU();
		cq_ctx->cqc.TPH_value =
			(cpu_id & TPH_CPUID_MASK) | PH_DWHR << 8;
	}
	cq_ctx->cqc.vsi_index = info->cqc.vsi_index;

	DRV_RDMA_LOG_DEV_DEBUG(
		"cq:%d cqc : ceqn %#x, dbsz %#x, cqsz %#x, scqe_break_moderation_en %x,\n"
		"\toi %d, sw_owner_bit %d, sw_status %#x, pbl %#llx,\n"
		"\tdbr %#llx, pgsz %#x, pg_offset %#x, pblm %#x,\n\n"
		"\tcq_max_count %d, cq_period %d, TPH_value %d, TPH_en %d, vsi_id %#x\n",
		cq_ctx->cq_uk.cq_id, cq_ctx->cqc.eqn, cq_ctx->cqc.log_dbr_size,
		cq_ctx->cqc.log_cq_size, cq_ctx->cqc.scqe_break_moderation_en,
		cq_ctx->cqc.oi, cq_ctx->cqc.sw_owner_bit, cq_ctx->cqc.sw_status,
		cq_ctx->cqc.pbl_index, cq_ctx->cqc.dbr_addr,
		cq_ctx->cqc.log_page_size, cq_ctx->cqc.page_offset,
		cq_ctx->cqc.pbl_mode, cq_ctx->cqc.cq_max_count,
		cq_ctx->cqc.cq_period, cq_ctx->cqc.TPH_value,
		cq_ctx->cqc.TPH_en, cq_ctx->cqc.vsi_index);
}

int sxe2_drv_cq_destroy(struct sxe2_rdma_ctx_cq *cq, u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct sxe2_cq_wqe *cq_wqe;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;
	int ret;

	mq	 = cq->dev->mq;
	rdma_dev = to_rdmadev(mq->dev);
	wqe	 = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get next wqe failed, ret (%d)\n", ret);
		goto end;
	}

	cq_wqe				= (struct sxe2_cq_wqe *)wqe;
	cq_wqe->sw_status		= 0;
	cq_wqe->op			= SXE2_MQ_OP_DESTROY_CQ;
	cq_wqe->cqn			= cq->cq_uk.cq_id;
	cq_wqe->WQE_Valid		= mq->polarity;
	cq_wqe->physical_buffer_address = 0;

	if (post_sq)
		sxe2_kpost_mq(mq);

	ret = 0;

end:
	return ret;
}

void sxe2_drv_cq_destroy_op(struct sxe2_rdma_device *rdma_dev,
			    struct sxe2_rdma_ctx_cq *cq)
{
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		DRV_RDMA_LOG_DEV_ERR("get mq_request failed\n");
		goto end;
	}

	mq_info				 = &mq_request->info;
	mq_info->mq_cmd			 = MQ_OP_DESTROY_CQ;
	mq_info->post_mq		 = 1;
	mq_info->in.u.cq_destroy.cq	 = cq;
	mq_info->in.u.cq_destroy.scratch = (uintptr_t)mq_request;
	mq_info->destroy		 = true;
	sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);

end:
	return;
}

static void sxe2_drv_cq_wqe_init(struct sxe2_cq_wqe *cq_wqe,
				 struct sxe2_rdma_ctx_cq *cq,
				 struct sxe2_mq_ctx *mq)
{
	cq_wqe->eqn			 = cq->cqc.eqn;
	cq_wqe->log_dbr_size		 = cq->cqc.log_dbr_size;
	cq_wqe->log_cq_size		 = cq->cqc.log_cq_size;
	cq_wqe->scqe_break_moderation_en = cq->cqc.scqe_break_moderation_en;
	cq_wqe->oi			 = cq->cqc.oi;
	cq_wqe->sw_owner_bit		 = cq->cqc.sw_owner_bit;
	cq_wqe->sw_status		 = cq->cqc.sw_status;
	cq_wqe->pbl_index		 = cq->cqc.pbl_index;
	cq_wqe->dbr_addr		 = cq->cqc.dbr_addr;
	cq_wqe->op			 = SXE2_MQ_OP_CREATE_CQ;
	cq_wqe->cqn			 = cq->cq_uk.cq_id;
	cq_wqe->WQE_Valid		 = mq->polarity;
	cq_wqe->physical_buffer_address	 = 0;
	cq_wqe->log_page_size		 = cq->cqc.log_page_size;
	cq_wqe->page_offset		 = cq->cqc.page_offset;
	cq_wqe->pbl_mode		 = cq->cqc.pbl_mode;
	cq_wqe->cq_max_count		 = cq->cqc.cq_max_count;
	cq_wqe->cq_period		 = cq->cqc.cq_period;
	cq_wqe->TPH_value		 = cq->cqc.TPH_value;
	cq_wqe->TPH_en			 = cq->cqc.TPH_en;
	cq_wqe->vsi_index		 = cq->cqc.vsi_index;
}

static void sxe2_drv_cq_create_err_inject(struct sxe2_rdma_device *rdma_dev,
					  struct sxe2_cq_wqe *cq_wqe,
					  struct sxe2_rdma_ctx_cq *cq)
{
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_cqn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, cq_wqe, cq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_cqn");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_cqcn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, cq_wqe, cq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_cqcn");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_cq_swState",
		     &rdma_dev->rdma_func->mq.err_cqe_val, cq_wqe, cq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_cq_swState");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_cq_size",
		     &rdma_dev->rdma_func->mq.err_cqe_val, cq_wqe, cq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_cq_size");
#endif
}

int sxe2_drv_cq_create(struct sxe2_rdma_ctx_cq *cq, u64 scratch,
		       bool check_overflow, bool post_sq)
{
	__le64 *wqe;
	struct sxe2_cq_wqe *cq_wqe;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;
	int ret;

	mq	 = cq->dev->mq;
	rdma_dev = to_rdmadev(mq->dev);
	if (((cq->cq_uk.cq_id >
	      (mq->dev->rcms_info->rcms_obj[SXE2_RCMS_OBJ_CQ].max_cnt - 1)) ||
	     (cq->cqc.eqn) > (cq->dev->rcms_info->max_ceqs - 1))) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF(
			"invalid cq_id:%d or ceq_id:%d , ret (%d)\n",
			cq->cq_uk.cq_id, cq->cqc.eqn, ret);
		goto end;
	}

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	if (rdma_dev->rdma_func->mq.ops_failed[MQ_OP_CREATE_CQ]) {
		DRV_RDMA_LOG_DEBUG_BDF("MQ:opcode %u inject op failed tri\n",
				       MQ_OP_CREATE_CQ);
		ret = -EBUSY;
		goto end;
	}
#endif

	wqe = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR_BDF("get next wqe failed, ret (%d)\n", ret);
		goto end;
	}

	cq_wqe = (struct sxe2_cq_wqe *)wqe;
	sxe2_drv_cq_wqe_init(cq_wqe, cq, mq);

	sxe2_drv_cq_create_err_inject(rdma_dev, cq_wqe, cq);

	if (post_sq)
		sxe2_kpost_mq(mq);

	ret = 0;

end:
	return ret;
}

int sxe2_drv_cq_create_op(struct sxe2_rdma_device *rdma_dev,
			  struct sxe2_rdma_ctx_cq *cq)
{
	int ret;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get mq_request failed, ret (%d)\n", ret);
		goto end;
	}
	mq_info				       = &mq_request->info;
	mq_info->mq_cmd			       = MQ_OP_CREATE_CQ;
	mq_info->post_mq		       = 1;
	mq_info->in.u.cq_create.cq	       = cq;
	mq_info->in.u.cq_create.check_overflow = true;
	mq_info->in.u.cq_create.scratch	       = (uintptr_t)mq_request;
	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);
	if (ret != 0)
		DRV_RDMA_LOG_DEV_ERR("handle create cq failed, ret (%d)\n",
				     ret);

end:
	return ret;
}

#ifdef CREATE_CQ_V1
static int sxe2_create_cq_param_check(const struct ib_cq_init_attr *attr,
				      struct ib_udata *udata)
{
	int ret = 0;

	if (!attr) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR("invalid param create cq, ret (%d)\n", ret);
		goto end;
	}

	if (udata &&
	    (udata->outlen < offsetofend(struct sxe2_create_cq_resp, ncqe))) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR("invalid udata create cq, ret (%d)\n", ret);
		goto end;
	}

	if ((attr->flags & ~(IB_UVERBS_CQ_FLAGS_IGNORE_OVERRUN |
			     IB_UVERBS_CQ_FLAGS_TIMESTAMP_COMPLETION))) {
		ret = -EOPNOTSUPP;
		DRV_RDMA_LOG_ERROR("inv flags %u, ret (%d)\n", attr->flags,
				   ret);
		goto end;
	}
end:
	return ret;
}
#else
static int sxe2_create_cq_param_check(struct ib_cq *ibcq,
					  const struct ib_cq_init_attr *attr,
				      struct ib_udata *udata)
{
	int ret = 0;

	if (!ibcq || !attr) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR("invalid param create cq, ret (%d)\n", ret);
		goto end;
	}

	if (udata &&
	    (udata->outlen < offsetofend(struct sxe2_create_cq_resp, ncqe))) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR("invalid udata create cq, ret (%d)\n", ret);
		goto end;
	}

	if ((attr->flags & ~(IB_UVERBS_CQ_FLAGS_IGNORE_OVERRUN |
			     IB_UVERBS_CQ_FLAGS_TIMESTAMP_COMPLETION))) {
		ret = -EOPNOTSUPP;
		DRV_RDMA_LOG_ERROR("inv flags %u, ret (%d)\n", attr->flags,
				   ret);
		goto end;
	}
end:
	return ret;
}

#endif
#ifdef CREATE_CQ_V1
static int sxe2_drv_create_cq(struct ib_udata *udata, struct sxe2_rdma_cq *cq,
			      struct sxe2_cq_init_info *info,
			      struct sxe2_rdma_device *rdma_dev,
			      int entries, struct ib_ucontext *ibucontext)
#else
static int sxe2_drv_create_cq(struct ib_udata *udata, struct sxe2_rdma_cq *cq,
			      struct sxe2_cq_init_info *info,
			      struct sxe2_rdma_device *rdma_dev, int entries)
#endif
{
	int ret = 0;

	if (udata) {
		#ifdef CREATE_CQ_V1
		ret = sxe2_drv_create_cq_user(rdma_dev, udata, cq, info,
					      entries, ibucontext);
		#else
		ret = sxe2_drv_create_cq_user(rdma_dev, udata, cq, info,
					      entries);
		#endif
		if (unlikely(ret))
			DRV_RDMA_LOG_DEV_ERR(
				"user create cq failed, ret (%d)\n", ret);
	} else {
		ret = sxe2_drv_create_cq_kernel(rdma_dev, cq, info, entries);
		if (unlikely(ret))
			DRV_RDMA_LOG_DEV_ERR(
				"kernel create cq failed, ret (%d)\n", ret);
	}

	return ret;
}

static void sxe2_drv_destroy_cq(struct ib_udata *udata, struct sxe2_rdma_cq *cq,
				struct sxe2_rdma_device *rdma_dev,
				struct sxe2_rdma_pci_f *rdma_func)
{
	if (udata)
		sxe2_drv_destroy_cq_user(rdma_dev, cq, udata);
	else
		sxe2_drv_destroy_cq_kernel(rdma_func, cq);
}

#ifdef CREATE_CQ_V1
struct ib_cq *sxe2_kcreate_cq(struct ib_device *ibdev, const struct ib_cq_init_attr *attr,
		    struct ib_ucontext *ibucontext, struct ib_udata *udata)
{
	int ret;
	int entries;
	u32 cq_num = 0;
	struct sxe2_rdma_device *rdma_dev = to_dev(ibdev);
	struct sxe2_rdma_pci_f *rdma_func;
	struct sxe2_rdma_cq *cq;
	struct sxe2_cq_init_info info;
	struct sxe2_create_cq_resp resp = {};

	ret = sxe2_create_cq_param_check(attr, udata);
	if (ret != 0)
		goto end;

	cq	  = kzalloc(sizeof(*cq), GFP_KERNEL);
	if (!cq) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("cq kzalloc failed\n");
		goto end;
	}

	entries	  = attr->cqe;
	rdma_func = rdma_dev->rdma_func;
	ret = sxe2_kalloc_rsrc(rdma_func, rdma_func->allocated_cqs,
			       rdma_func->max_cq, &cq_num, &rdma_func->next_cq);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("get cq_num failed, ret (%d)\n", ret);
		goto free_cq;
	}
	refcount_set(&cq->refcnt, 1);
	spin_lock_init(&cq->lock);
	INIT_LIST_HEAD(&cq->cmpl_generated);
	atomic_set(&cq->armed, 0);
	memset(&info, 0, sizeof(struct sxe2_cq_init_info));
	info.dev		   = &rdma_func->ctx_dev;
	info.cq_uk_init_info.cq_id = cq_num;

	DRV_RDMA_LOG_INFO("cq db map:%p\n", rdma_func->db->map);
	info.cq_uk_init_info.cqe_alloc_db =
		(__le64 *)(rdma_func->db->map + SXE2_RDMA_DB_CQ_ARM_OFFSET);
	DRV_RDMA_LOG_INFO("cqe_alloc_db :%p\n",
			  info.cq_uk_init_info.cqe_alloc_db);
	cq->cq_num = (u16)cq_num;
	ret	   = sxe2_drv_create_cq(udata, cq, &info, rdma_dev, entries, ibucontext);
	if (ret != 0)
		goto free_rsrc;

	cq->ibcq.cqe = info.cq_uk_init_info.ncqe;
	if (attr->comp_vector < rdma_func->ceqs_count)
		info.cqc.eqn = attr->comp_vector;

	if (attr->flags & IB_UVERBS_CQ_FLAGS_IGNORE_OVERRUN)
		info.cqc.oi = 1;

	info.cqc.log_cq_size  = ilog2(info.cq_uk_init_info.ncqe);
	info.cqc.log_dbr_size = ilog2(info.cq_uk_init_info.ncqe / 2);
	info.cqc.dbr_addr     = info.db_pa;
	info.cqc.vsi_index    = rdma_dev->vsi.vsi_idx;
	sxe2_drv_cq_ctx_init(rdma_dev, cq, &info);
	ret = sxe2_drv_cq_create_op(rdma_dev, &cq->cq_ctx);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("kcreate cq op failed, ret (%d)\n", ret);
		goto err_op;
	}

	ret = drv_rdma_debug_cq_add(rdma_dev, cq);
	if (unlikely(ret)) {
		DRV_RDMA_LOG_DEV_ERR(
			"failed adding CQ %#x to debug file system, ret (%d)\n",
			cq->cq_num, ret);
		goto destroy_cq;
	}

	if (udata) {
		resp.cq_id = info.cq_uk_init_info.cq_id;
		resp.ncqe  = info.cq_uk_init_info.ncqe;
		if (ib_copy_to_udata(udata, &resp,
				     min(sizeof(resp), udata->outlen))) {
			DRV_RDMA_LOG_DEV_ERR("copy2user failed cqn %#x\n",
					     resp.cq_id);
			ret = -EFAULT;

			drv_rdma_debug_cq_remove(rdma_dev, cq);

			goto destroy_cq;
		}
	}

	DRV_RDMA_LOG_DEV_INFO("create cq end, cqn:%d\n",
			      info.cq_uk_init_info.cq_id);

	rdma_func->cq_table[cq_num] = cq;
	init_completion(&cq->free_cq);
	ret = 0;
	goto end;

destroy_cq:
	sxe2_drv_cq_destroy_op(rdma_dev, &cq->cq_ctx);
err_op:
	sxe2_drv_destroy_cq(udata, cq, rdma_dev, rdma_func);
free_rsrc:
	sxe2_kfree_rsrc(rdma_func, rdma_func->allocated_cqs, cq_num);
free_cq:
	kfree(cq);
end:
	return ret ? ERR_PTR(ret) : &cq->ibcq;
}

#else
int sxe2_kcreate_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr,
		    struct ib_udata *udata)
{
	int ret;
	int entries;
	u32 cq_num = 0;
	struct ib_device *ibdev;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_pci_f *rdma_func;
	struct sxe2_rdma_cq *cq;
	struct sxe2_cq_init_info info;
	struct sxe2_create_cq_resp resp = {};

	ret = sxe2_create_cq_param_check(ibcq, attr, udata);
	if (ret != 0)
		goto end;

	ibdev	  = ibcq->device;
	entries	  = attr->cqe;
	rdma_dev  = to_dev(ibdev);
	cq	  = to_scq(ibcq);
	rdma_func = rdma_dev->rdma_func;
	ret = sxe2_kalloc_rsrc(rdma_func, rdma_func->allocated_cqs,
			       rdma_func->max_cq, &cq_num, &rdma_func->next_cq);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("get cq_num failed, ret (%d)\n", ret);
		goto end;
	}
	refcount_set(&cq->refcnt, 1);
	spin_lock_init(&cq->lock);
	INIT_LIST_HEAD(&cq->cmpl_generated);
	atomic_set(&cq->armed, 0);
	memset(&info, 0, sizeof(struct sxe2_cq_init_info));
	info.dev		   = &rdma_func->ctx_dev;
	info.cq_uk_init_info.cq_id = cq_num;

	DRV_RDMA_LOG_INFO("cq db map:%p\n", rdma_func->db->map);
	info.cq_uk_init_info.cqe_alloc_db =
		(__le64 *)(rdma_func->db->map + SXE2_RDMA_DB_CQ_ARM_OFFSET);
	DRV_RDMA_LOG_INFO("cqe_alloc_db :%p\n",
			  info.cq_uk_init_info.cqe_alloc_db);
	cq->cq_num = cq_num;
	ret	   = sxe2_drv_create_cq(udata, cq, &info, rdma_dev, entries);
	if (ret != 0)
		goto free_rsrc;

	cq->ibcq.cqe = info.cq_uk_init_info.ncqe;
	if (attr->comp_vector < rdma_func->ceqs_count)
		info.cqc.eqn = attr->comp_vector;

	if (attr->flags & IB_UVERBS_CQ_FLAGS_IGNORE_OVERRUN)
		info.cqc.oi = 1;

	info.cqc.log_cq_size  = ilog2(info.cq_uk_init_info.ncqe);
	info.cqc.log_dbr_size = ilog2(info.cq_uk_init_info.ncqe / 2);
	info.cqc.dbr_addr     = info.db_pa;
	info.cqc.vsi_index    = rdma_dev->vsi.vsi_idx;
	sxe2_drv_cq_ctx_init(rdma_dev, cq, &info);
	ret = sxe2_drv_cq_create_op(rdma_dev, &cq->cq_ctx);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("kcreate cq op failed, ret (%d)\n", ret);
		goto err_op;
	}

	ret = drv_rdma_debug_cq_add(rdma_dev, cq);
	if (unlikely(ret)) {
		DRV_RDMA_LOG_DEV_ERR(
			"failed adding CQ %#x to debug file system, ret (%d)\n",
			cq->cq_num, ret);
		goto destroy_cq;
	}

	if (udata) {
		resp.cq_id = info.cq_uk_init_info.cq_id;
		resp.ncqe  = info.cq_uk_init_info.ncqe;
		if (ib_copy_to_udata(udata, &resp,
				     min(sizeof(resp), udata->outlen))) {
			DRV_RDMA_LOG_DEV_ERR("copy2user failed cqn %#x\n",
					     resp.cq_id);
			ret = -EFAULT;

			drv_rdma_debug_cq_remove(rdma_dev, cq);

			goto destroy_cq;
		}
	}

	DRV_RDMA_LOG_DEV_INFO("create cq end, cqn:%d\n",
			      info.cq_uk_init_info.cq_id);

	rdma_func->cq_table[cq_num] = cq;
	init_completion(&cq->free_cq);
	ret = 0;
	goto end;

destroy_cq:
	sxe2_drv_cq_destroy_op(rdma_dev, &cq->cq_ctx);
err_op:
	sxe2_drv_destroy_cq(udata, cq, rdma_dev, rdma_func);
free_rsrc:
	sxe2_kfree_rsrc(rdma_func, rdma_func->allocated_cqs, cq_num);
end:
	return ret;
}
#endif

int sxe2_drv_cq_query(struct sxe2_rdma_ctx_cq *cq, u64 query_pa, u64 scratch,
		      bool post_sq)
{
	__le64 *wqe;
	struct sxe2_cq_wqe *cq_wqe;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;
	int ret;

	mq	 = cq->dev->mq;
	rdma_dev = to_rdmadev(mq->dev);
	wqe	 = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get next wqe failed, ret (%d)\n", ret);
		goto end;
	}

	cq_wqe				= (struct sxe2_cq_wqe *)wqe;
	cq_wqe->op			= SXE2_MQ_OP_QUERY_CQ;
	cq_wqe->cqn			= cq->cq_uk.cq_id;
	cq_wqe->WQE_Valid		= mq->polarity;
	cq_wqe->physical_buffer_address = query_pa >> SXE2_CQC_PHY_ADDR_OFFSET;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_cqn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, cq_wqe, cq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_cqn");
#endif

	if (post_sq)
		sxe2_kpost_mq(mq);

	ret = 0;

end:
	return ret;
}

int sxe2_drv_cq_query_op(struct sxe2_rdma_device *rdma_dev,
			 struct sxe2_rdma_ctx_cq *cq, u64 query_pa)
{
	int ret;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get mq_request failed, ret (%d)\n", ret);
		goto end;
	}

	mq_info				= &mq_request->info;
	mq_info->mq_cmd			= MQ_OP_QUERY_CQ;
	mq_info->post_mq		= 1;
	mq_info->in.u.cq_query.cq	= cq;
	mq_info->in.u.cq_query.scratch	= (uintptr_t)mq_request;
	mq_info->in.u.cq_query.query_pa = query_pa;
	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);
	if (ret != 0)
		DRV_RDMA_LOG_DEV_ERR("handle query cq failed, ret (%d)\n", ret);

end:
	return ret;
}

int sxe2_drv_cq_modify(struct sxe2_rdma_ctx_cq *cq, struct sxe2_rdma_cqc *cqc,
		       u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct sxe2_cq_wqe *cq_wqe;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;
	int ret;

	mq	 = cq->dev->mq;
	rdma_dev = to_rdmadev(mq->dev);
	wqe	 = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get next wqe failed, ret (%d)\n", ret);
		goto end;
	}

	cq_wqe				 = (struct sxe2_cq_wqe *)wqe;
	cq_wqe->eqn			 = cqc->scqc.eqn;
	cq_wqe->log_dbr_size		 = cqc->scqc.log_dbr_size;
	cq_wqe->log_cq_size		 = cqc->scqc.log_cq_size;
	cq_wqe->scqe_break_moderation_en = cqc->scqc.scqe_break_moderation_en;
	cq_wqe->oi			 = cqc->scqc.oi;
	cq_wqe->sw_owner_bit		 = cqc->scqc.sw_owner_bit;
	cq_wqe->sw_status		 = cqc->scqc.sw_status;
	cq_wqe->pbl_index		 = cqc->scqc.pbl_index;
	cq_wqe->dbr_addr		 = cqc->scqc.dbr_addr;
	cq_wqe->op			 = SXE2_MQ_OP_MODIFY_CQ;
	cq_wqe->cqn			 = cq->cq_uk.cq_id;
	cq_wqe->WQE_Valid		 = mq->polarity;
	cq_wqe->physical_buffer_address	 = 0;
	cq_wqe->log_page_size		 = cqc->scqc.log_page_size;
	cq_wqe->page_offset		 = cqc->scqc.page_offset;
	cq_wqe->pbl_mode		 = cqc->scqc.pbl_mode;
	cq_wqe->cq_max_count		 = cqc->scqc.cq_max_count;
	cq_wqe->cq_period		 = cqc->scqc.cq_period;
	cq_wqe->TPH_value		 = cqc->scqc.TPH_value;
	cq_wqe->TPH_en			 = cqc->scqc.TPH_en;
	cq_wqe->vsi_index		 = cqc->scqc.vsi_index;
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_cqn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, cq_wqe, cq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_cqn");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_cq_swState",
		     &rdma_dev->rdma_func->mq.err_cqe_val, cq_wqe, cq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_cq_swState");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_cq_size",
		     &rdma_dev->rdma_func->mq.err_cqe_val, cq_wqe, cq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_cq_size");
#endif

	if (post_sq)
		sxe2_kpost_mq(mq);
	ret = 0;

end:
	return ret;
}

int sxe2_drv_cq_modify_op(struct sxe2_rdma_device *rdma_dev,
			  struct sxe2_rdma_ctx_cq *cq,
			  struct sxe2_rdma_cqc *cqc)
{
	int ret;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get mq_request failed, ret (%d)\n", ret);
		goto end;
	}

	mq_info				= &mq_request->info;
	mq_info->mq_cmd			= MQ_OP_MODIFY_CQ;
	mq_info->post_mq		= 1;
	mq_info->in.u.cq_modify.cq	= cq;
	mq_info->in.u.cq_modify.scratch = (uintptr_t)mq_request;
	mq_info->in.u.cq_modify.cqc	= cqc;
	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);
	if (ret != 0)
		DRV_RDMA_LOG_DEV_ERR("handle modify cq failed, ret (%d)\n",
				     ret);

end:
	return ret;
}

int sxe2_kmodify_cq(struct ib_cq *cq_in, u16 cq_count, u16 cq_period)
{
	int ret;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_cq *cq;
	struct sxe2_rdma_cqc *ctx;
	struct sxe2_rdma_dma_mem query_cq;
	struct sxe2_rdma_ctx_dev *dev_ctx;

	rdma_dev = to_dev(cq_in->device);
	dev_ctx	 = &(rdma_dev->rdma_func->ctx_dev);
	cq	 = to_scq(cq_in);

	if (unlikely(cq_period > SXE2_MAX_CQ_PERIOD)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("cq period inv %u, ret (%d)\n", cq_period,
				     ret);
		goto end;
	}

	memset(&query_cq, 0, sizeof(query_cq));
	query_cq.size = sizeof(struct sxe2_rdma_cqc);
	query_cq.va   = dma_alloc_coherent(dev_ctx->hw->device, query_cq.size,
					   &query_cq.pa, GFP_KERNEL);
	if (!query_cq.va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("query cq ctx alloc failed. ret:%d\n",
				     ret);
		goto end;
	}
	memset(query_cq.va, 0, query_cq.size);

	ret = sxe2_drv_cq_query_op(rdma_dev, &cq->cq_ctx, query_cq.pa);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("query cq failed, ret (%d)\n", ret);
		goto free_ctx;
	}

	ctx		       = (struct sxe2_rdma_cqc *)query_cq.va;
	ctx->scqc.cq_max_count = cq_count;
	ctx->scqc.cq_period    = cq_period;

	ret = sxe2_drv_cq_modify_op(rdma_dev, &cq->cq_ctx, ctx);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR(
			"modify cq max_count:%d, period:%d failed, ret (%d)\n",
			cq_count, cq_period, ret);
		goto free_ctx;
	}

	DRV_RDMA_LOG_DEV_INFO("modify cq max_count:%d, period:%d\n", cq_count,
			      cq_period);

free_ctx:
	dma_free_coherent(dev_ctx->hw->device, query_cq.size, query_cq.va,
			  query_cq.pa);
	query_cq.va = NULL;

end:
	return ret;
}

void sxe2_drv_cq_add_ref(struct sxe2_rdma_cq *cq)
{
	refcount_inc(&cq->refcnt);
}

void sxe2_drv_cq_rem_ref(struct sxe2_rdma_cq *cq)
{
	struct sxe2_rdma_pci_f *rdma_func =
		container_of(cq->cq_ctx.dev, struct sxe2_rdma_pci_f, ctx_dev);
	unsigned long flag = 0;
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev = to_rdmadev(cq->cq_ctx.dev);

	spin_lock_irqsave(&rdma_func->cqtable_lock, flag);
	if (!refcount_dec_and_test(&cq->refcnt)) {
		spin_unlock_irqrestore(&rdma_func->cqtable_lock, flag);
		DRV_RDMA_LOG_DEV_ERR("cq is used by other\n");
		goto end;
	}

	rdma_func->cq_table[cq->cq_num] = NULL;
	spin_unlock_irqrestore(&rdma_func->cqtable_lock, flag);
	complete(&cq->free_cq);

end:
	return;
}

void sxe2_cq_remove_cmpls_list(struct sxe2_rdma_cq *cq)
{
	struct sxe2_cq_cmpl_gen *cmpl_node;
	struct list_head *tmp_node, *list_node;

	list_for_each_safe(list_node, tmp_node, &cq->cmpl_generated) {
		cmpl_node =
			list_entry(list_node, struct sxe2_cq_cmpl_gen, list);
		list_del(&cmpl_node->list);
		kfree(cmpl_node);
	}
}

void sxe2_drv_cleanup_ceqes(struct sxe2_rdma_ctx_cq *cq,
			    struct sxe2_rdma_ctx_ceq *ceq)
{
	struct sxe2_rdma_ctx_cq *next_cq;
	u8 ceq_polarity = ceq->polarity;
	__le64 *ceqe;
	u8 polarity;
	u64 temp;
	u32 next;
	u32 i;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(ceq->dev);

	next = SXE2_RING_GET_NEXT_TAIL(ceq->ceq_ring, 0);

	for (i = 1; i <= SXE2_RING_SIZE(ceq->ceq_ring); i++) {
		if (rdma_dev->cache_line_64_en == false)
			ceqe = SXE2_GET_CEQ_ELEM_AT_POS(ceq, next);
		else
			ceqe = SXE2_GET_CEQ_ELEM_AT_POS_HYGON(ceq, next);

		get_64bit_val(ceqe, 0, &temp);
		polarity = (u8)FIELD_GET(SXE2_CEQE_VALID, temp);
		if (polarity != ceq_polarity)
			return;

		next_cq = (struct sxe2_rdma_ctx_cq *)(unsigned long)LS_64_1(
			temp, 1);
		if (cq == next_cq)
			set_64bit_val(ceqe, 0, temp & SXE2_CEQE_VALID);

		next = SXE2_RING_GET_NEXT_TAIL(ceq->ceq_ring, i);
		if (!next)
			ceq_polarity ^= 1;
	}
}

#ifdef RDMA_DESTROY_CQ_VER_3
void sxe2_kdestroy_cq(struct ib_cq *cq_in, struct ib_udata *udata)
#elif defined RDMA_DESTROY_CQ_VER_4
int sxe2_kdestroy_cq(struct ib_cq *cq_in)
#else
int sxe2_kdestroy_cq(struct ib_cq *cq_in, struct ib_udata *udata)
#endif

{
	int ret;
	unsigned long flag = 0;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_cq *cq;
	struct sxe2_rdma_ctx_dev *ctx_dev;
	struct sxe2_rdma_ctx_ceq *ceq_ctx;
	struct sxe2_rdma_ceq *ceq;
	struct sxe2_rdma_pci_f *rdma_func;

	if (!cq_in) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR("invalid cq resource\n");
		goto end;
	}

	rdma_dev  = to_dev(cq_in->device);
	cq	  = to_scq(cq_in);
	ctx_dev	  = cq->cq_ctx.dev;
	ceq_ctx	  = ctx_dev->ceq[cq->cq_ctx.cqc.eqn];
	ceq	  = container_of(ceq_ctx, struct sxe2_rdma_ceq, ctx_ceq);
	rdma_func = rdma_dev->rdma_func;

	spin_lock_irqsave(&cq->lock, flag);
	if (!list_empty(&cq->cmpl_generated))
		sxe2_cq_remove_cmpls_list(cq);

	spin_unlock_irqrestore(&cq->lock, flag);

	sxe2_drv_cq_rem_ref(cq);
	wait_for_completion(&cq->free_cq);

	sxe2_drv_cq_destroy_op(rdma_dev, &cq->cq_ctx);

	spin_lock_irqsave(&ceq->ce_lock, flag);
	sxe2_drv_cleanup_ceqes(&cq->cq_ctx, ceq_ctx);
	spin_unlock_irqrestore(&ceq->ce_lock, flag);

#ifndef RDMA_DESTROY_CQ_VER_4
	if (udata)
		sxe2_drv_destroy_cq_user(rdma_dev, cq, udata);
	else
		sxe2_drv_destroy_cq_kernel(rdma_func, cq);
#endif

	drv_rdma_debug_cq_remove(rdma_dev, cq);

	sxe2_kfree_rsrc(rdma_func, rdma_func->allocated_cqs,
			cq->cq_ctx.cq_uk.cq_id);
	ret = 0;

end:
#ifdef RDMA_DESTROY_CQ_VER_3
	return;
#else
	return ret;
#endif
}

static inline int sxe2_drv_mcq_create_done(struct sxe2_rdma_ctx_cq *mcq)
{
	struct sxe2_mq_ctx *mq;

	mq = mcq->dev->mq;

	return sxe2_kpoll_mcq(mq, SXE2_MQ_OP_CREATE_CQ, NULL);
}

int sxe2_drv_mcq_create(struct sxe2_rdma_ctx_cq *mcq, u64 scratch,
			bool check_overflow, bool post_sq)
{
	int ret;
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev = to_rdmadev(mcq->dev);

	if (rdma_dev->rdma_func->reset)
		return -EBUSY;

	ret = sxe2_drv_cq_create(mcq, scratch, check_overflow, post_sq);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("mcq create failed, ret (%d)\n", ret);
		goto end;
	}

	if (post_sq) {
		ret = sxe2_drv_mcq_create_done(mcq);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR(
				"wait mcq create done err, ret (%d)\n", ret);
			goto end;
		}
	}
	mcq->dev->mq->process_mq_fpt = sxe2_rcms_update_fptes_cmd_complete;
	ret			     = 0;

end:
	return ret;
}

void sxe2_drv_mcq_ctx_init(struct sxe2_rdma_ctx_cq *cq_ctx,
			   struct sxe2_rdma_mcq_init_info *info)
{
	struct sxe2_rdma_device *rdma_dev;
	u32 st_mode = 0;
	s32 cpu_id  = 0;

	rdma_dev = to_rdmadev(cq_ctx->dev);

	cq_ctx->cq_type = SXE2_RDMA_CQ_TYPE_MQ;
	cq_ctx->cq_pa	= info->cq_pa;
	cq_ctx->db_pa	= info->db_pa;
	cq_ctx->dev	= info->dev;
	cq_ctx->vsi	= info->vsi;

	cq_ctx->cq_uk.cq_base	    = info->cq_base;
	cq_ctx->cq_uk.cqe_alloc_db  = info->cqe_alloc_db;
	cq_ctx->cq_uk.doorbell_note = info->doorbell_note;
	cq_ctx->cq_uk.cq_id	    = 0;
	cq_ctx->cq_uk.ncqe	    = SXE2_MCQ_SIZE;
	cq_ctx->cq_uk.polarity	    = 1;
	cq_ctx->cq_uk.arm_sn	    = SXE2_RDMA_CQ_ARM_SN;
	SXE2_RING_INIT(cq_ctx->cq_uk.cq_ring, SXE2_MCQ_SIZE);

	cq_ctx->cqc.eqn		 = info->cqc.eqn;
	cq_ctx->cqc.log_dbr_size = info->cqc.log_dbr_size;
	cq_ctx->cqc.log_cq_size	 = info->cqc.log_cq_size;
	cq_ctx->cqc.scqe_break_moderation_en =
		rdma_dev->rdma_func->scqe_break_moderation_en;
	cq_ctx->cqc.oi		  = rdma_dev->rdma_func->oi;
	cq_ctx->cqc.sw_owner_bit  = 0;
	cq_ctx->cqc.sw_status	  = 0xF;
	cq_ctx->cqc.pbl_index	  = info->cqc.pbl_index;
	cq_ctx->cqc.dbr_addr	  = info->cqc.dbr_addr;
	cq_ctx->cqc.log_page_size = info->cqc.log_page_size;
	cq_ctx->cqc.page_offset	  = info->cqc.page_offset;
	cq_ctx->cqc.pbl_mode	  = info->cqc.pbl_mode;
	cq_ctx->cqc.cq_max_count  = 0;
	cq_ctx->cqc.cq_period	  = 0;
	cq_ctx->cqc.TPH_en =
		sxe2_drv_core_is_tph_enable(rdma_dev, true, &st_mode);
	if (cq_ctx->cqc.TPH_en) {
		if (st_mode != MODE_NO_ST)
			cpu_id = TPH_GET_CPU();
		cq_ctx->cqc.TPH_value =
			(cpu_id & TPH_CPUID_MASK) | PH_DWHR << 8;
	}
	cq_ctx->cqc.vsi_index = info->cqc.vsi_index;

	DRV_RDMA_LOG_DEV_DEBUG(
		"cq:%d cqc : ceqn %#x, dbsz %#x, cqsz %#x, scqe_break_moderation_en %x,\n"
		"\toi %d, sw_owner_bit %d, sw_status %#x, pbl %#llx,\n"
		"\tdbr %#llx, pgsz %#x, pg_offset %#x, pblm %#x,\n"
		"\tcq_max_count %d, cq_period %d, TPH_value %d, TPH_en %d, vsi_id %#x\n",
		cq_ctx->cq_uk.cq_id, cq_ctx->cqc.eqn, cq_ctx->cqc.log_dbr_size,
		cq_ctx->cqc.log_cq_size, cq_ctx->cqc.scqe_break_moderation_en,
		cq_ctx->cqc.oi, cq_ctx->cqc.sw_owner_bit, cq_ctx->cqc.sw_status,
		cq_ctx->cqc.pbl_index, cq_ctx->cqc.dbr_addr,
		cq_ctx->cqc.log_page_size, cq_ctx->cqc.page_offset,
		cq_ctx->cqc.pbl_mode, cq_ctx->cqc.cq_max_count,
		cq_ctx->cqc.cq_period, cq_ctx->cqc.TPH_value,
		cq_ctx->cqc.TPH_en, cq_ctx->cqc.vsi_index);
}

static int sxe2_drv_mcq_destroy(struct sxe2_rdma_ctx_cq *mcq, u64 scratch,
				bool post_sq)
{
	u32 tail, val, error;
	__le64 *wqe;
	struct sxe2_cq_wqe *cq_wqe;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;
	int ret = 0;

	mq	 = mcq->dev->mq;
	rdma_dev = to_rdmadev(mq->dev);

	wqe = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get next wqe failed, ret (%d)\n", ret);
		goto end;
	}

	cq_wqe				= (struct sxe2_cq_wqe *)wqe;
	cq_wqe->sw_status		= 0;
	cq_wqe->op			= SXE2_MQ_OP_DESTROY_CQ;
	cq_wqe->cqn			= mcq->cq_uk.cq_id;
	cq_wqe->WQE_Valid		= mq->polarity;
	cq_wqe->physical_buffer_address = 0;

	sxe2_kget_mq_reg_info(mq, &val, &tail, &error);

	if (post_sq) {
		sxe2_kpost_mq(mq);
		ret = sxe2_kpoll_mq_registers(mq, tail,
					      mq->dev->hw_attrs.max_done_count);
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
		if (rdma_dev->rdma_func->mq.ops_failed[MQ_OP_DESTROY_CQ] &&
		    !ret) {
			DRV_RDMA_LOG_DEV_DEBUG(
				"MQ:opcode %u inject op failed tri\n",
				MQ_OP_DESTROY_CQ);
			ret = -EBUSY;
		}
#endif
	}
	mq->process_mq_fpt = sxe2_rcms_update_fptes_cmd;

end:
	return ret;
}

int sxe2_create_mcq(struct sxe2_rdma_device *rdma_dev)
{
	int ret;
	struct sxe2_rdma_pci_f *rdma_func   = rdma_dev->rdma_func;
	struct sxe2_rdma_ctx_dev *dev	    = &rdma_func->ctx_dev;
	struct sxe2_rdma_mcq_init_info info = {};
	struct sxe2_rdma_mcq *mcq	    = &rdma_func->mcq;

	dev->mcq      = &mcq->ctx_cq;
	dev->mcq->dev = dev;
	info.dev      = dev;
	mcq->mem_cq.size =
		ALIGN(sizeof(struct sxe2_cqe) * SXE2_MCQ_SIZE, 0x100);
	mcq->mem_cq.va = dma_alloc_coherent(dev->hw->device, mcq->mem_cq.size,
					    &mcq->mem_cq.pa, GFP_KERNEL);
	if (!mcq->mem_cq.va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("mcq buf alloc failed, ret (%d)\n", ret);
		goto end;
	}
	memset(mcq->mem_cq.va, 0, mcq->mem_cq.size);

	mcq->mem_db_note.size = SXE2_RDMA_DB_NOTE_SIZE;
	ret = sxe2_kget_aligned_mem(rdma_func, &mcq->mem_db_note,
				    mcq->mem_db_note.size, SXE2_DB_NOTE_M);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("mcq db note buf alloc failed, ret (%d)\n",
				     ret);
		goto db_mem_alloc_err;
	}
	set_32bit_val(mcq->mem_db_note.va, 4,
		      (__u32)(SXE2_CQ_DB_NOTE_CMD_SN)
			      << SXE2_CQ_DB_NOTE_CMD_SN_SHIFT);

	mcq->ctx_cq.back_cq = mcq;
	mcq->ctx_cq.dev	    = dev;
	mcq->ctx_cq.vsi	    = &rdma_dev->vsi;

	info.cq_base	       = mcq->mem_cq.va;
	info.cq_pa	       = mcq->mem_cq.pa;
	info.doorbell_note     = mcq->mem_db_note.va;
	info.db_pa	       = mcq->mem_db_note.pa;
	info.dev	       = &rdma_func->ctx_dev;
	info.cqc.eqn	       = 0;
	info.cqc.log_cq_size   = ilog2(SXE2_MCQ_SIZE);
	info.cqc.log_dbr_size  = ilog2(SXE2_MCQ_SIZE / 2);
	info.cqc.log_page_size = order_base_2(PAGE_SIZE);
	info.cqc.page_offset   = offset_in_page(info.cq_pa);
	info.cqc.dbr_addr      = info.db_pa;
	info.cqc.vsi_index     = rdma_dev->vsi.vsi_idx;
	info.vsi	       = &rdma_func->default_vsi;
	info.cqc.pbl_mode      = CQ_EQ_PA_FIRST_MODE;
	info.cqc.pbl_index     = info.cq_pa;

	DRV_RDMA_LOG_DEV_INFO("mcq db map:%p\n", rdma_func->db->map);
	info.cqe_alloc_db =
		(__le64 *)(rdma_func->db->map + SXE2_RDMA_DB_CQ_ARM_OFFSET);
	DRV_RDMA_LOG_DEV_INFO("mcqe_alloc_db :%p\n", info.cqe_alloc_db);

	dev->mcq->back_cq = mcq;
	sxe2_drv_mcq_ctx_init(dev->mcq, &info);

	ret = sxe2_drv_mcq_create(dev->mcq, 0, true, true);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("mcq create failed, ret (%d)\n", ret);
		goto db_mem_alloc_err;
	}

	ret = drv_rdma_debug_mcq_add(rdma_dev, mcq);
	if (unlikely(ret)) {
		DRV_RDMA_LOG_DEV_ERR(
			"failed adding CQ %#x to debug file system, ret (%d)\n",
			0, ret);
		sxe2_drv_mcq_destroy(dev->mcq, 0, true);
	}

db_mem_alloc_err:
	if (ret) {
		dma_free_coherent(dev->hw->device, mcq->mem_cq.size,
				  mcq->mem_cq.va, mcq->mem_cq.pa);
		mcq->mem_cq.va = NULL;
	}

end:
	return ret;
}

void sxe2_destroy_mcq(struct sxe2_rdma_device *rdma_dev)
{
	int ret				  = 0;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	struct sxe2_rdma_ctx_dev *dev	  = &rdma_func->ctx_dev;
	struct sxe2_rdma_mcq *mcq	  = &rdma_func->mcq;
	bool hw_rsrc_clean		  = false;

	hw_rsrc_clean = sxe2_get_hw_rsrc_clean_flag(dev);
	if (!rdma_func->reset || !hw_rsrc_clean) {
		ret = sxe2_drv_mcq_destroy(dev->mcq, 0, true);
		if (ret)
			DRV_RDMA_LOG_DEV_ERR("mcq destroy failed, ret (%d)\n",
					     ret);
	}

	drv_rdma_debug_mcq_remove(rdma_dev, mcq);

	dma_free_coherent(dev->hw->device, mcq->mem_cq.size, mcq->mem_cq.va,
			  mcq->mem_cq.pa);
	mcq->mem_cq.va = NULL;
}
