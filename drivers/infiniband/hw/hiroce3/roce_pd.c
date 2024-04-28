// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/slab.h>

#include "roce.h"
#include "roce_main_extension.h"
#include "roce_pd.h"

int roce3_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	int ret;
	struct roce3_pd *pd = to_roce3_pd(ibpd);
	struct roce3_device *rdev = to_roce3_dev(ibpd->device);

	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	ret = roce3_rdma_pd_alloc(rdev->hwdev, &pd->pdn);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc pdn, ret(%d), func_id(%u)\n",
			__func__, ret, rdev->glb_func_id);
		goto err_out;
	}

	pd->func_id = rdev->glb_func_id;
	if (udata) {
		if (ib_copy_to_udata(udata, &pd->pdn, PD_RESP_SIZE) != 0) {
			ret = -EFAULT;
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to copy data to user space, func_id(%u)\n",
				__func__, rdev->glb_func_id);
			goto err_copy_to_user;
		}
	}

	return 0;

err_copy_to_user:
	roce3_rdma_pd_free(rdev->hwdev, pd->pdn);
err_out:
	return ret;
}

int roce3_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct roce3_pd *pd = NULL;
	struct roce3_device *rdev = NULL;

	if (ibpd == NULL) {
		pr_err("[ROCE, ERR] %s: Ibpd is null\n", __func__);
		return -EINVAL;
	}

	pd = to_roce3_pd(ibpd);
	rdev = to_roce3_dev(ibpd->device);

	roce3_rdma_pd_free(rdev->hwdev, pd->pdn);

	return 0;
}
