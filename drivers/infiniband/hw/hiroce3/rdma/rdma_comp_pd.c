// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/module.h>
#include <linux/netdevice.h>

#include "hinic3_hw.h"
#include "rdma_comp.h"

int roce3_rdma_pd_alloc(void *hwdev, u32 *pdn)
{
	struct rdma_comp_priv *comp_priv = NULL;

	if ((hwdev == NULL) || (pdn == NULL)) {
		pr_err("%s: Hwdev or pdn is null\n", __func__);
		return -EINVAL;
	}

	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}

	*pdn = rdma_bitmap_alloc(&comp_priv->pd_bitmap);
	if (*pdn == RDMA_INVALID_INDEX) {
		pr_err("%s: Can't get valid pdn, err(%d)\n", __func__, -ENOMEM);
		return -ENOMEM;
	}

	return 0;
}

void roce3_rdma_pd_free(void *hwdev, u32 pdn)
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

	rdma_bitmap_free(&comp_priv->pd_bitmap, pdn);
}
