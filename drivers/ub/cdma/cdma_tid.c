// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define dev_fmt(fmt) "CDMA: " fmt

#include <linux/iommu.h>
#include <linux/ummu_core.h>

#include "cdma.h"
#include "cdma_tid.h"

static int cdma_enable_sva_feature(struct cdma_dev *cdev)
{
	int ret;

	ret = iommu_dev_enable_feature(cdev->dev, IOMMU_DEV_FEAT_KSVA);
	if (ret) {
		dev_err(cdev->dev, "cdma enable ksva failed, ret = %d\n", ret);
		return ret;
	}

	ret = iommu_dev_enable_feature(cdev->dev, IOMMU_DEV_FEAT_IOPF);
	if (ret) {
		dev_err(cdev->dev, "cdma enable iopf feature failed, ret = %d\n",
			ret);
		goto disable_ksva_feature;
	}

	ret = iommu_dev_enable_feature(cdev->dev, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		dev_err(cdev->dev, "cdma enable sva failed, ret = %d\n", ret);
		goto disable_iopf_feature;
	}

	return 0;

disable_iopf_feature:
	iommu_dev_disable_feature(cdev->dev, IOMMU_DEV_FEAT_IOPF);
disable_ksva_feature:
	iommu_dev_disable_feature(cdev->dev, IOMMU_DEV_FEAT_KSVA);

	return ret;
}


static void cdma_disable_sva_feature(struct cdma_dev *cdev)
{
	iommu_dev_disable_feature(cdev->dev, IOMMU_DEV_FEAT_SVA);
	iommu_dev_disable_feature(cdev->dev, IOMMU_DEV_FEAT_IOPF);
	iommu_dev_disable_feature(cdev->dev, IOMMU_DEV_FEAT_KSVA);
}

int cdma_alloc_dev_tid(struct cdma_dev *cdev)
{
	struct ummu_seg_attr seg_attr = {
		.token = NULL,
		.e_bit = UMMU_EBIT_ON
	};
	struct ummu_param drvdata = {
		.mode = MAPT_MODE_TABLE
	};
	int ret;

	ret = cdma_enable_sva_feature(cdev);
	if (ret)
		return ret;

	cdev->ksva = iommu_ksva_bind_device(cdev->dev, &drvdata);
	if (IS_ERR(cdev->ksva)) {
		dev_err(cdev->dev, "ksva bind device failed\n");
		ret = -EINVAL;
		goto disable_sva_feature;
	}

	ret = ummu_get_tid(cdev->dev, cdev->ksva, &cdev->tid);
	if (ret) {
		dev_err(cdev->dev,
			"get tid for cdma device failed, ret = %d\n", ret);
		goto unbind_device;
	}

	ret = iommu_sva_grant(cdev->ksva, 0, CDMA_MAX_GRANT_SIZE,
			      UMMU_DEV_WRITE | UMMU_DEV_READ, &seg_attr);
	if (ret) {
		dev_err(cdev->dev,
			"sva grant range for cdma device failed, ret = %d\n",
			ret);
		goto unbind_device;
	}

	return 0;

unbind_device:
	iommu_ksva_unbind_device(cdev->ksva);
disable_sva_feature:
	cdma_disable_sva_feature(cdev);

	return ret;
}

void cdma_free_dev_tid(struct cdma_dev *cdev)
{
	int ret;

	ret = iommu_sva_ungrant(cdev->ksva, 0, CDMA_MAX_GRANT_SIZE, NULL);
	if (ret)
		dev_warn(cdev->dev,
			 "sva ungrant range for cdma device failed, ret = %d\n",
			 ret);

	iommu_ksva_unbind_device(cdev->ksva);
	cdma_disable_sva_feature(cdev);
}
