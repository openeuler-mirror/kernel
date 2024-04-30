/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_MR_EXTEND_H
#define ROCE_MR_EXTEND_H

#include <rdma/ib_verbs.h>

#include "hinic3_rdma.h"

#include "roce.h"

int roce3_check_alloc_mr_type(enum ib_mr_type mr_type);
enum rdma_mr_type roce3_get_mrtype(enum ib_mr_type ib_mr_type);

#endif

