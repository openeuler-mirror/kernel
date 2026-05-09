// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_pd.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <rdma/ib_verbs.h>
#include <rdma/uverbs_ioctl.h>

#include "sxe2_drv_pd.h"
#include "sxe2-abi.h"
#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_rdma_log.h"

#ifdef ALLOC_PD_V1
struct ib_pd *sxe2_kalloc_pd(struct ib_device *ibdev, struct ib_ucontext *ibucontext,
									struct ib_udata *udata)
{
	int ret;
	u32 pd_id;
	struct sxe2_rdma_pd *pd = NULL;
	struct sxe2_alloc_pd_resp resp;
	struct sxe2_rdma_device *rdma_dev = to_dev(ibdev);
	struct sxe2_rdma_kcontext *ucontext;
	struct sxe2_rdma_ctx_pd *pd_ctx;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	pd = kzalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("pd kzalloc failed\n");
		goto end;
	}

	ret = sxe2_kalloc_rsrc(rdma_func, rdma_func->allocated_pds,
			       rdma_func->max_pd, &pd_id, &rdma_func->next_pd);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("drv pd alloc failed , ret (%d)\n", ret);
		goto free_pd;
	}

	pd_ctx = &pd->pd_ctx;
	if (udata) {
		ucontext = to_rdma_kcontext(ibucontext);
		pd_ctx->pd_id	= pd_id;
		pd_ctx->abi_ver = ucontext->abi_ver;
		pd_ctx->dev	= &rdma_func->ctx_dev;

		resp.pd_id = pd_id;
		if (ib_copy_to_udata(udata, &resp, sizeof(resp))) {
			DRV_RDMA_LOG_DEV_ERR("ib_copy_to_udata fail\n");
			ret = -EFAULT;
			sxe2_kfree_rsrc(rdma_func, rdma_func->allocated_pds,
					pd_id);
			goto end;
		}
	} else {
		pd_ctx->pd_id	= pd_id;
		pd_ctx->abi_ver = 0;
		pd_ctx->dev	= &rdma_func->ctx_dev;
	}

	DRV_RDMA_LOG_DEV_DEBUG("pd alloc resp.pdn:%u\n", pd_id);
	goto end;

free_pd:
	kfree(pd);
end:
	return ret ? ERR_PTR(ret) : &pd->ibpd;
}
#else
int sxe2_kalloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	int ret;
	u32 pd_id;
	struct sxe2_rdma_pd *pd = to_kpd(ibpd);
	struct sxe2_alloc_pd_resp resp;
	struct sxe2_rdma_device *rdma_dev = to_dev(ibpd->device);
	struct sxe2_rdma_kcontext *ucontext;
	struct sxe2_rdma_ctx_pd *pd_ctx;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
#ifdef HAVE_NO_RDMA_UDATA_TO_DRV_CONTEXT
	struct ib_ucontext      *ibucontext;
#endif
	ret = sxe2_kalloc_rsrc(rdma_func, rdma_func->allocated_pds,
			       rdma_func->max_pd, &pd_id, &rdma_func->next_pd);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("drv pd alloc failed , ret (%d)\n", ret);
		goto end;
	}

	pd_ctx = &pd->pd_ctx;
	if (udata) {
#ifdef HAVE_NO_RDMA_UDATA_TO_DRV_CONTEXT
		ibucontext = rdma_device_to_drv_context(ibpd->device);
		ucontext = to_rdma_kcontext(ibucontext);
#else
		ucontext = rdma_udata_to_drv_context(
			udata, struct sxe2_rdma_kcontext, ibucontext);
#endif
		pd_ctx->pd_id	= pd_id;
		pd_ctx->abi_ver = ucontext->abi_ver;
		pd_ctx->dev	= &rdma_func->ctx_dev;

		resp.pd_id = pd_id;
		if (ib_copy_to_udata(udata, &resp, sizeof(resp))) {
			DRV_RDMA_LOG_DEV_ERR("ib_copy_to_udata fail\n");
			ret = -EFAULT;
			sxe2_kfree_rsrc(rdma_func, rdma_func->allocated_pds,
					pd_id);
			goto end;
		}
	} else {
		pd_ctx->pd_id	= pd_id;
		pd_ctx->abi_ver = 0;
		pd_ctx->dev	= &rdma_func->ctx_dev;
	}

	DRV_RDMA_LOG_DEV_DEBUG("pd alloc resp.pdn:%u\n", pd_id);

end:
	return ret;
}
#endif

#ifdef DEALLOC_PD_VER_3
void sxe2_kdealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
#elif defined DEALLOC_PD_VER_4
int sxe2_kdealloc_pd(struct ib_pd *ibpd)
#else
int sxe2_kdealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
#endif

{
	struct sxe2_rdma_pd *drv_pd	  = to_kpd(ibpd);
	struct sxe2_rdma_device *rdma_dev = to_dev(ibpd->device);
#ifndef DEALLOC_PD_VER_4
	(void)udata;
#endif
	DRV_RDMA_LOG_DEV_DEBUG("pd:%d dealloc\n", drv_pd->pd_ctx.pd_id);

	sxe2_kfree_rsrc(rdma_dev->rdma_func, rdma_dev->rdma_func->allocated_pds,
			drv_pd->pd_ctx.pd_id);
#ifdef DEALLOC_PD_VER_3
	return;
#else
	return 0;
#endif
}
