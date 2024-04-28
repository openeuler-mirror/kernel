// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include "roce_qp_post_send_extension.h"

int roce3_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
	const struct ib_send_wr **bad_wr)
{
	return roce3_post_send_standard(ibqp, (const struct ib_send_wr *)wr,
		(const struct ib_send_wr **)bad_wr);
}
