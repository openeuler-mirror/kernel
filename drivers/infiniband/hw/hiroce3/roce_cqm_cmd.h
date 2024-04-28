/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_CQM_CMD_H
#define ROCE_CQM_CMD_H

#include "hinic3_cqm.h"

#include "roce.h"

void roce3_cqm_cmd_free_inoutbuf(void *ex_handle, struct tag_cqm_cmd_buf *cqm_cmd_inbuf,
				 struct tag_cqm_cmd_buf *cqm_cmd_outbuf);
int roce3_cqm_cmd_zalloc_inoutbuf(void *ex_handle, struct tag_cqm_cmd_buf **cqm_cmd_inbuf,
				  u16 inbuf_size, struct tag_cqm_cmd_buf **cqm_cmd_outbuf,
				  u16 outbuf_size);

#endif // ROCE_CQM_CMD_H
