// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/slab.h>

#include "roce.h"
#include "roce_main_extension.h"
#include "roce_xrc.h"

static int roce3_rdma_xrcd_alloc(void *hwdev, u32 *xrcdn)
{
	struct rdma_comp_priv *comp_priv = NULL;

	if ((hwdev == NULL) || (xrcdn == NULL)) {
		pr_err("%s: Hwdev or xrcdn is null\n", __func__);
		return -EINVAL;
	}

	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}

	*xrcdn = rdma_bitmap_alloc(&comp_priv->xrcd_bitmap);
	if (*xrcdn == RDMA_INVALID_INDEX) {
		pr_err("%s: Can't get valid xrcdn, err(%d)\n", __func__, -ENOMEM);
		return -ENOMEM;
	}

	return 0;
}

static void roce3_rdma_xrcd_free(void *hwdev, u32 xrcdn)
{
	struct rdma_comp_priv *comp_priv = NULL;

	if (hwdev == NULL) {
		pr_err("%s: Hwdev is null\n", __func__);
		return;
	}

	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return;
	}

	rdma_bitmap_free(&comp_priv->xrcd_bitmap, xrcdn);
}

static int roce3_init_xrcd(struct ib_device *ibdev, struct roce3_device *rdev,
	struct roce3_xrcd *xrcd)
{
	int ret = 0;
	struct ib_cq_init_attr cq_attr = { 0 };

	ret = roce3_rdma_xrcd_alloc(rdev->hwdev, &xrcd->xrcdn);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc rdma xrcd, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_alloc_xrcdn;
	}

	xrcd->pd = ib_alloc_pd(ibdev, 0); /*lint !e119*/

	if (IS_ERR(xrcd->pd)) {
		ret = (int)PTR_ERR(xrcd->pd);
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc pd, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_alloc_pd;
	}

	cq_attr.cqe = 1;
	xrcd->cq = ib_create_cq(ibdev, NULL, NULL, xrcd, &cq_attr);
	if (IS_ERR(xrcd->cq)) {
		ret = (int)PTR_ERR(xrcd->cq);
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to create cq, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_create_cq;
	}
	return 0;

err_create_cq:
	ib_dealloc_pd(xrcd->pd);

err_alloc_pd:
	roce3_rdma_xrcd_free(rdev->hwdev, xrcd->xrcdn);

err_alloc_xrcdn:
	return ret;
}

int roce3_alloc_xrcd(struct ib_xrcd *ibxrcd, struct ib_udata *udata)
{
	struct roce3_device *rdev = to_roce3_dev(ibxrcd->device);
	struct roce3_xrcd *xrcd = to_roce3_xrcd(ibxrcd);

	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	return roce3_init_xrcd(ibxrcd->device, rdev, xrcd);
}

int roce3_dealloc_xrcd(struct ib_xrcd *ibxrcd, struct ib_udata *udata)
{
	struct roce3_device *rdev = NULL;
	struct roce3_xrcd *xrcd = NULL;

	if (ibxrcd == NULL) {
		pr_err("[ROCE, ERR] %s: Ibxrcd is null\n", __func__);
		return -EINVAL;
	}

	rdev = to_roce3_dev(ibxrcd->device);
	xrcd = to_roce3_xrcd(ibxrcd);
	ib_destroy_cq(xrcd->cq);

	ib_dealloc_pd(xrcd->pd);
	roce3_rdma_xrcd_free(rdev->hwdev, xrcd->xrcdn);
	return 0;
}
