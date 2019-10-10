/*
 * Copyright (c) 2016 Hisilicon Limited.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "roce_k_compat.h"

#include <linux/platform_device.h>
#include <linux/pci.h>
#include <uapi/rdma/hns-abi.h>
#include "hns_roce_device.h"

static int hns_roce_pd_alloc(struct hns_roce_dev *hr_dev, unsigned long *pdn)
{
	return hns_roce_bitmap_alloc(&hr_dev->pd_bitmap, pdn);
}

static void hns_roce_pd_free(struct hns_roce_dev *hr_dev, unsigned long pdn)
{
	hns_roce_bitmap_free(&hr_dev->pd_bitmap, pdn, BITMAP_NO_RR);
}

static int hns_roce_xrcd_alloc(struct hns_roce_dev *hr_dev,
			       unsigned long *xrcdn)
{
	return hns_roce_bitmap_alloc(&hr_dev->xrcd_bitmap, xrcdn);
}

static void hns_roce_xrcd_free(struct hns_roce_dev *hr_dev,
			       unsigned long xrcdn)
{
	hns_roce_bitmap_free(&hr_dev->xrcd_bitmap, xrcdn, BITMAP_NO_RR);
}

int hns_roce_init_pd_table(struct hns_roce_dev *hr_dev)
{
	return hns_roce_bitmap_init(&hr_dev->pd_bitmap, hr_dev->caps.num_pds,
				    hr_dev->caps.num_pds - 1,
				    hr_dev->caps.reserved_pds, 0);
}

void hns_roce_cleanup_pd_table(struct hns_roce_dev *hr_dev)
{
	hns_roce_bitmap_cleanup(&hr_dev->pd_bitmap);
}

int hns_roce_init_xrcd_table(struct hns_roce_dev *hr_dev)
{
	return hns_roce_bitmap_init(&hr_dev->xrcd_bitmap,
				    hr_dev->caps.num_xrcds,
				    hr_dev->caps.num_xrcds - 1,
				    hr_dev->caps.reserved_xrcds, 0);
}

void hns_roce_cleanup_xrcd_table(struct hns_roce_dev *hr_dev)
{
	hns_roce_bitmap_cleanup(&hr_dev->xrcd_bitmap);
}

struct ib_pd *hns_roce_alloc_pd(struct ib_device *ib_dev,
				struct ib_ucontext *context,
				struct ib_udata *udata)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);
	struct device *dev = hr_dev->dev;
	struct hns_roce_pd *pd;
	int ret;

	pd = kzalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd)
		return ERR_PTR(-ENOMEM);

	ret = hns_roce_pd_alloc(to_hr_dev(ib_dev), &pd->pdn);
	if (ret) {
		kfree(pd);
		dev_err(dev, "[alloc_pd]hns_roce_pd_alloc failed(%d)!\n", ret);
		return ERR_PTR(ret);
	}

#ifdef CONFIG_NEW_KERNEL
	if (context) {
		struct hns_roce_ib_alloc_pd_resp uresp = {.pdn = pd->pdn};

		if (ib_copy_to_udata(udata, &uresp, sizeof(uresp))) {
			hns_roce_pd_free(to_hr_dev(ib_dev), pd->pdn);
			dev_err(dev, "[alloc_pd]ib_copy_to_udata failed, pd - 0x%lx!\n",
				pd->pdn);
			kfree(pd);
			return ERR_PTR(-EFAULT);
		}
	}

#else
	if (context) {
		if (ib_copy_to_udata(udata, &pd->pdn, sizeof(u64))) {
			hns_roce_pd_free(to_hr_dev(ib_dev), pd->pdn);
			dev_err(dev, "[alloc_pd]ib_copy_to_udata failed!, pd -0x%lx\n",
				pd->pdn);
			kfree(pd);
			return ERR_PTR(-EFAULT);
		}
	}

#endif

	rdfx_func_cnt(hr_dev, RDFX_FUNC_ALLOC_PD);
	rdfx_alloc_rdfx_pd(hr_dev, pd);
	hns_roce_inc_rdma_hw_stats(ib_dev, HW_STATS_PD_ALLOC);

	return &pd->ibpd;
}
EXPORT_SYMBOL_GPL(hns_roce_alloc_pd);

int hns_roce_dealloc_pd(struct ib_pd *pd)
{

	rdfx_func_cnt(to_hr_dev(pd->device), RDFX_FUNC_DEALLOC_PD);
	rdfx_release_rdfx_pd(to_hr_dev(pd->device), to_hr_pd(pd)->pdn);
	hns_roce_inc_rdma_hw_stats(pd->device, HW_STATS_PD_DEALLOC);

	hns_roce_pd_free(to_hr_dev(pd->device), to_hr_pd(pd)->pdn);
	kfree(to_hr_pd(pd));

	return 0;
}
EXPORT_SYMBOL_GPL(hns_roce_dealloc_pd);

struct ib_xrcd *hns_roce_ib_alloc_xrcd(struct ib_device *ib_dev,
				       struct ib_ucontext *context,
				       struct ib_udata *udata)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);
	struct ib_cq_init_attr cq_attr = {};
	struct hns_roce_xrcd *xrcd;
	int ret;

	if (!(hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_XRC))
		return ERR_PTR(-EINVAL);

	xrcd = kzalloc(sizeof(*xrcd), GFP_KERNEL);
	if (!xrcd)
		return ERR_PTR(-ENOMEM);

	ret = hns_roce_xrcd_alloc(hr_dev, &xrcd->xrcdn);
	if (ret) {
		kfree(xrcd);
		dev_err(hr_dev->dev,
			"[alloc_xrcd]hns_roce_xrcd_alloc failed(%d)!\n", ret);
		return ERR_PTR(ret);
	}

	xrcd->pd = ib_alloc_pd(ib_dev, 0);
	if (IS_ERR_OR_NULL(xrcd->pd)) {
		ret = PTR_ERR(xrcd->pd);
		goto err_dealloc_xrcd;
	}

	cq_attr.cqe = 1;
	xrcd->cq = ib_create_cq(ib_dev, NULL, NULL, xrcd, &cq_attr);
	if (IS_ERR_OR_NULL(xrcd->cq)) {
		ret = PTR_ERR(xrcd->cq);
		goto err_dealloc_pd;
	}

	return &xrcd->ibxrcd;

err_dealloc_pd:
	ib_dealloc_pd(xrcd->pd);

err_dealloc_xrcd:
	hns_roce_xrcd_free(hr_dev, xrcd->xrcdn);

	kfree(xrcd);
	return ERR_PTR(ret);
}

int hns_roce_ib_dealloc_xrcd(struct ib_xrcd *xrcd)
{
	ib_destroy_cq(to_hr_xrcd(xrcd)->cq);
	ib_dealloc_pd(to_hr_xrcd(xrcd)->pd);
	hns_roce_xrcd_free(to_hr_dev(xrcd->device), to_hr_xrcd(xrcd)->xrcdn);
	kfree(xrcd);

	return 0;
}

int hns_roce_uar_alloc(struct hns_roce_dev *hr_dev, struct hns_roce_uar *uar)
{
	struct resource *res;
	int ret;

	/* Using bitmap to manager UAR index */
	ret = hns_roce_bitmap_alloc(&hr_dev->uar_table.bitmap, &uar->logic_idx);
	if (ret == -1)
		return -ENOMEM;

	if (uar->logic_idx > 0 && hr_dev->caps.phy_num_uars > 1)
		uar->index = (uar->logic_idx - 1) %
			     (hr_dev->caps.phy_num_uars - 1) + 1;
	else
		uar->index = 0;

	if (!dev_is_pci(hr_dev->dev)) {
		res = platform_get_resource(hr_dev->pdev, IORESOURCE_MEM, 0);
		if (!res) {
			dev_err(&hr_dev->pdev->dev, "memory resource not found!\n");
			return -EINVAL;
		}
		uar->pfn = ((res->start) >> PAGE_SHIFT) + uar->index;
	} else {
		uar->pfn = ((pci_resource_start(hr_dev->pci_dev,
			     HNS_ROCE_PCI_BAR_NR)) >> PAGE_SHIFT);
	}

	return 0;
}

void hns_roce_uar_free(struct hns_roce_dev *hr_dev, struct hns_roce_uar *uar)
{
	hns_roce_bitmap_free(&hr_dev->uar_table.bitmap, uar->logic_idx,
			     BITMAP_NO_RR);
}

int hns_roce_init_uar_table(struct hns_roce_dev *hr_dev)
{
	return hns_roce_bitmap_init(&hr_dev->uar_table.bitmap,
				    hr_dev->caps.num_uars,
				    hr_dev->caps.num_uars - 1,
				    hr_dev->caps.reserved_uars, 0);
}

void hns_roce_cleanup_uar_table(struct hns_roce_dev *hr_dev)
{
	hns_roce_bitmap_cleanup(&hr_dev->uar_table.bitmap);
}
