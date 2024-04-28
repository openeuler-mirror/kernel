/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_QP_POST_SEND_EXTEND_H
#define ROCE_QP_POST_SEND_EXTEND_H

#include <rdma/ib_verbs.h>
#include "roce_qp.h"

int roce3_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
const struct ib_send_wr **bad_wr);

#endif // ROCE_QP_POST_SEND_EXTEND_H
