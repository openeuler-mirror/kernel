// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/kref.h>
#include <linux/random.h>
#include <linux/debugfs.h>
#include <linux/export.h>
#include <rdma/ib_umem.h>
#include "common/xsc_cmd.h"
#include <linux/dma-direct.h>
#include "ib_umem_ex.h"
#include "xsc_ib.h"

#ifndef MLX_PEER_SUPPORT
static void xsc_invalidate_umem(void *invalidation_cookie,
				struct ib_umem_ex *umem,
				unsigned long addr, size_t size);
#endif

enum {
	DEF_CACHE_SIZE	= 10,
};

struct ib_mr *xsc_ib_get_dma_mr(struct ib_pd *pd, int acc)
{
	struct xsc_ib_dev *dev = to_mdev(pd->device);
	struct xsc_core_device *xdev = dev->xdev;
	struct xsc_register_mr_mbox_in *in;
	struct xsc_register_mr_request *req;
	struct xsc_ib_mr *mr;
	int err;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	return &mr->ibmr;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_free;
	}

	req = &in->req;
	req->acc = convert_access(acc) | XSC_ACCESS_MODE_PA;
	req->pdn = cpu_to_be32(to_mpd(pd)->pdn | XSC_MKEY_LEN64);
	req->va_base = 0;

	err = xsc_core_create_mkey(xdev, &mr->mmr);
	if (err)
		goto err_in;
	req->mkey = cpu_to_be32(mr->mmr.key);
	err = xsc_core_register_mr(xdev, &mr->mmr, in, sizeof(*in));
	if (err)
		goto err_reg_mr;
	kfree(in);
	mr->ibmr.lkey = mr->mmr.key;
	mr->ibmr.rkey = mr->mmr.key;
	mr->umem = NULL;

	return &mr->ibmr;
err_reg_mr:
	xsc_core_destroy_mkey(xdev, &mr->mmr);
err_in:
	kfree(in);

err_free:
	kfree(mr);

	return ERR_PTR(err);
}

void xsc_fill_pas(int npages, u64 *pas, __be64 *req_pas)
{
	int i;

	for (i = 0; i < npages; i++)
		req_pas[i] = cpu_to_be64(pas[i]);
}

static struct xsc_ib_mr *reg_create(struct ib_pd *pd, u64 virt_addr,
				    u64 length, struct ib_umem *umem,
				    int npages, u64 *pas, int page_shift,
				    int access_flags)
{
	struct xsc_ib_dev *dev = to_mdev(pd->device);
	struct xsc_register_mr_mbox_in *in;
	struct xsc_ib_mr *mr;
	int inlen;
	int err;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		err = -ENOMEM;
		goto err_0;
	}

	inlen = sizeof(*in) + sizeof(*in->req.pas) * npages;
	in = xsc_vzalloc(inlen);
	if (!in) {
		err = -ENOMEM;
		goto err_1;
	}
	err = xsc_core_create_mkey(dev->xdev, &mr->mmr);
	if (err) {
		xsc_ib_warn(dev, "create mkey failed\n");
		goto err_2;
	}

	xsc_fill_pas(npages, pas, in->req.pas);

	in->req.acc = convert_access(access_flags);
	in->req.pa_num = cpu_to_be32(npages);
	in->req.pdn = cpu_to_be32(to_mpd(pd)->pdn);
	in->req.va_base = cpu_to_be64(virt_addr);
	in->req.map_en = XSC_MPT_MAP_EN;
	in->req.len = cpu_to_be32((u32)length);
	in->req.page_mode = (page_shift == XSC_PAGE_SHIFT_4K ? XSC_PAGE_MODE_4K :
			(page_shift == XSC_PAGE_SHIFT_64K ? XSC_PAGE_MODE_64K :
			(page_shift == XSC_PAGE_SHIFT_2M ? XSC_PAGE_MODE_2M : XSC_PAGE_MODE_1G)));
	in->req.mkey = cpu_to_be32(mr->mmr.key);
	err = xsc_core_register_mr(dev->xdev, &mr->mmr, in, inlen);
	if (err) {
		xsc_ib_warn(dev, "register mr failed, err = %d\n", err);
		goto err_reg_mr;
	}
	mr->umem = umem;
	xsc_vfree(in);
	vfree(pas);

	xsc_ib_dbg(dev, "mkey = 0x%x\n", mr->mmr.key);

	return mr;
err_reg_mr:
	xsc_core_destroy_mkey(dev->xdev, &mr->mmr);
err_2:
	xsc_vfree(in);
err_1:
	kfree(mr);
err_0:
	vfree(pas);

	return ERR_PTR(err);
}

struct ib_mr *xsc_ib_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				 u64 virt_addr, int access_flags,
				 struct ib_udata *udata)
{
	struct xsc_ib_dev *dev = to_mdev(pd->device);
	struct xsc_ib_mr *mr = NULL;
	struct ib_umem_ex *umem_ex;
	struct ib_umem *umem;
	int page_shift;
	int npages;
	u64 *pas;
	int err;
	int using_peer_mem = 0;
	struct ib_peer_memory_client *ib_peer_mem = NULL;
	struct xsc_ib_peer_id *xsc_ib_peer_id = NULL;

	xsc_ib_dbg(dev, "start 0x%llx, virt_addr 0x%llx, length 0x%llx\n",
		   start, virt_addr, length);

	umem = ib_umem_get(&dev->ib_dev, start, length, access_flags);
	if (IS_ERR(umem)) {
		// check client peer memory
#ifndef MLX_PEER_SUPPORT
		u8 peer_exists = 0;

		umem_ex = ib_client_umem_get(pd->uobject->context,
					     start, length, access_flags, 0, &peer_exists);
		if (!peer_exists) {
			xsc_ib_dbg(dev, "umem get failed\n");
			return (void *)umem;
		}
		ib_peer_mem = umem_ex->ib_peer_mem;
		xsc_ib_peer_id = kzalloc(sizeof(*xsc_ib_peer_id), GFP_KERNEL);
		if (!xsc_ib_peer_id) {
			err = -ENOMEM;
			goto error;
		}
		init_completion(&xsc_ib_peer_id->comp);
		err = ib_client_umem_activate_invalidation_notifier(umem_ex,
								    xsc_invalidate_umem,
								    xsc_ib_peer_id);
		if (err)
			goto error;
		using_peer_mem = 1;
#else
		xsc_ib_warn(dev, "umem get failed\n");
		return (void *)umem;
#endif

	} else {
		umem_ex = ib_umem_ex(umem);
		if (IS_ERR(umem_ex)) {
			err = -ENOMEM;
			goto error;
		}
	}
	umem = &umem_ex->umem;

	err = xsc_find_best_pgsz(umem, 0x40211000, start, &npages, &page_shift, &pas);
	if (err) {
		vfree(pas);
		pas = NULL;
		xsc_ib_warn(dev, "find best page size failed\n");
		goto error;
	}
	if (!npages) {
		xsc_ib_warn(dev, "avoid zero region\n");
		err = -EINVAL;
		goto error;
	}

	xsc_ib_dbg(dev, "npages %d, page_shift %d\n", npages, page_shift);

	mr = reg_create(pd, virt_addr, length, umem, npages, pas, page_shift, access_flags);
	if (IS_ERR(mr)) {
		err = PTR_ERR(mr);
		goto error;
	}

	xsc_ib_dbg(dev, "mkey 0x%x\n", mr->mmr.key);

	mr->umem = umem;
	mr->npages = npages;
	spin_lock(&dev->mr_lock);
	dev->xdev->dev_res->reg_pages += npages;
	spin_unlock(&dev->mr_lock);
	mr->ibmr.lkey = mr->mmr.key;
	mr->ibmr.rkey = mr->mmr.key;
	mr->ibmr.length = length;
	atomic_set(&mr->invalidated, 0);
	if (ib_peer_mem) {
		init_completion(&mr->invalidation_comp);
		xsc_ib_peer_id->mr = mr;
		mr->peer_id = xsc_ib_peer_id;
		complete(&xsc_ib_peer_id->comp);
	}

	return &mr->ibmr;

error:
	if (xsc_ib_peer_id) {
		complete(&xsc_ib_peer_id->comp);
		kfree(xsc_ib_peer_id);
		xsc_ib_peer_id = NULL;
	}

	ib_umem_ex_release(umem_ex);
	return ERR_PTR(err);
}

xsc_ib_dereg_mr_def()
{
	struct xsc_ib_dev *dev = to_mdev(ibmr->device);
	struct xsc_ib_mr *mr = to_mmr(ibmr);
	struct ib_umem *umem = mr->umem;
	struct ib_umem_ex *umem_ex = (struct ib_umem_ex *)umem;
	int npages = mr->npages;
	int err;

	xsc_ib_dbg(dev, "dereg mkey = 0x%x\n", mr->mmr.key);

	if (atomic_inc_return(&mr->invalidated) > 1) {
		/* In case there is inflight invalidation call pending for its termination */
		wait_for_completion(&mr->invalidation_comp);
		kfree(mr);
		return 0;
	}

	if (mr->npages) {
		err = xsc_core_dereg_mr(dev->xdev, &mr->mmr);
		if (err) {
			xsc_ib_warn(dev, "failed to dereg mr 0x%x (%d)\n",
				    mr->mmr.key, err);
			return err;
		}
	}

	err = xsc_core_destroy_mkey(dev->xdev, &mr->mmr);
	if (err) {
		xsc_ib_warn(dev, "failed to destroy mkey 0x%x (%d)\n",
			    mr->mmr.key, err);
		return err;
	}

	if (umem_ex) {
		ib_umem_ex_release(umem_ex);
		spin_lock(&dev->mr_lock);
		dev->xdev->dev_res->reg_pages -= npages;
		spin_unlock(&dev->mr_lock);
	}

	kfree(mr);

	return 0;
}

#ifndef MLX_PEER_SUPPORT
static void xsc_invalidate_umem(void *invalidation_cookie,
				struct ib_umem_ex *umem,
				unsigned long addr,
				size_t size)
{
	struct xsc_ib_mr *mr;
	struct xsc_ib_dev *dev;
	struct xsc_ib_peer_id *peer_id = (struct xsc_ib_peer_id *)invalidation_cookie;

	wait_for_completion(&peer_id->comp);
	if (!peer_id->mr)
		return;

	mr = peer_id->mr;
	/* This function is called under client peer lock so its resources are race protected */
	if (atomic_inc_return(&mr->invalidated) > 1) {
		umem->invalidation_ctx->inflight_invalidation = 1;
		return;
	}

	umem->invalidation_ctx->peer_callback = 1;
	dev = to_mdev(mr->ibmr.device);
	xsc_core_destroy_mkey(dev->xdev, &mr->mmr);
	xsc_core_dereg_mr(dev->xdev, &mr->mmr);
	complete(&mr->invalidation_comp);
}
#endif

xsc_ib_alloc_mr_def()
{
	struct xsc_ib_dev *dev = to_mdev(pd->device);
	struct xsc_ib_mr *mr;
	int err;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return NULL;
	mr->npages = 0;
	mr->mmr.pd = to_mpd(pd)->pdn;
	mr->pas = kcalloc(max_num_sg, sizeof(__be64), GFP_KERNEL);
	if (!mr->pas)
		goto err_alloc;
	err = xsc_core_create_mkey(dev->xdev, &mr->mmr);
	if (err)
		goto err_create_mkey;
	mr->ibmr.lkey = mr->mmr.key;
	mr->ibmr.rkey = mr->mmr.key;
	mr->ibmr.device = &dev->ib_dev;

	return &mr->ibmr;
err_create_mkey:
	kfree(mr->pas);
err_alloc:
	kfree(mr);
	return NULL;
}

static int xsc_set_page(struct ib_mr *ibmr, u64 pa)
{
	struct xsc_ib_mr *mmr = to_mmr(ibmr);

	mmr->pas[mmr->npages] = pa;
	mmr->npages++;
	return 0;
}

int xsc_ib_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg,
		     int sg_nents, unsigned int *sg_offset)
{
	struct xsc_ib_mr *mmr = to_mmr(ibmr);

	mmr->npages = 0;
	return ib_sg_to_pages(ibmr, sg, sg_nents, sg_offset, xsc_set_page);
}

int xsc_wr_reg_mr(struct xsc_ib_dev *dev, const struct ib_send_wr *wr)
{
	const struct ib_reg_wr *reg_wr = container_of(wr, struct ib_reg_wr, wr);
	struct ib_mr *ibmr = reg_wr->mr;
	struct xsc_ib_mr *mmr = to_mmr(ibmr);
	struct xsc_register_mr_mbox_in *in;
	int inlen;
	int i;
	int err;
	__be64 *pas;

	inlen = sizeof(*in) + sizeof(__be64) * mmr->npages;
	in = kzalloc(inlen, GFP_ATOMIC);
	if (!in)
		return -ENOMEM;

	in->req.pdn = cpu_to_be32(mmr->mmr.pd);
	in->req.pa_num = cpu_to_be32(mmr->npages);
	in->req.len = cpu_to_be32(ibmr->length);
	in->req.mkey = cpu_to_be32(ibmr->rkey);
	in->req.acc = convert_access(reg_wr->access);
	in->req.page_mode = 0;
	in->req.map_en = XSC_MPT_MAP_EN;
	in->req.va_base = cpu_to_be64(ibmr->iova);
	pas = in->req.pas;
	for (i = 0; i < mmr->npages; i++)
		pas[i] = cpu_to_be64(mmr->pas[i]);
	err = xsc_core_register_mr(dev->xdev, &mmr->mmr, in, sizeof(*in));

	kfree(in);
	return err;
}

int xsc_wr_invalidate_mr(struct xsc_ib_dev *dev, const struct ib_send_wr *wr)
{
	struct xsc_core_mr mr;
	int err = 0;

	if (!wr)
		return -1;
	mr.key = wr->ex.invalidate_rkey;
	err = xsc_core_dereg_mr(dev->xdev, &mr);
	return err;
}

void xsc_reg_local_dma_mr(struct xsc_core_device *dev)
{
	struct xsc_register_mr_mbox_in in;
	int err = 0;

	in.req.pdn = 0;
	in.req.pa_num = 0;
	in.req.len = 0;
	in.req.mkey = cpu_to_be32(0xFF);
	in.req.acc = XSC_PERM_LOCAL_WRITE | XSC_PERM_LOCAL_READ;
	in.req.page_mode = 0;
	in.req.map_en = !(XSC_MPT_MAP_EN);
	in.req.va_base = 0;

	err = xsc_core_register_mr(dev, NULL, &in, sizeof(in));
	if (err)
		xsc_core_err(dev, "\n");
}

