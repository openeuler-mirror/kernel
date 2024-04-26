/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_SRQ_EXTENSION_H
#define ROCE_SRQ_EXTENSION_H

#include "roce_srq.h"

void roce3_srq_container_init(struct ib_srq_init_attr *init_attr,
struct roce3_srq *rsrq, struct roce3_device *rdev);

void roce3_create_user_srq_update_ext(u32 *cqn, u32 srqn);

#endif /* ROCE_SRQ_EXTENSION_H */
