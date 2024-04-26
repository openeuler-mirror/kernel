// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd
#include "roce_mr.h"
#include "roce_main_extension.h"
#include "roce_mr_extension.h"

#ifdef ROCE_STANDARD
int roce3_check_alloc_mr_type(enum ib_mr_type mr_type)
{
	int ret = 0;

	if (mr_type != IB_MR_TYPE_MEM_REG) {
		ret = -EINVAL;
		pr_err("[ROCE, ERR] %s: mr_type is invalid. mr_type:%u\n", __func__, mr_type);
	}

	return ret;
}

enum rdma_mr_type roce3_get_mrtype(enum ib_mr_type ib_mr_type)
{
	switch (ib_mr_type) {
	case IB_MR_TYPE_MEM_REG:
		return RDMA_DMA_MR;

	default:
		return RDMA_DMA_MR;
	}
}
#endif

