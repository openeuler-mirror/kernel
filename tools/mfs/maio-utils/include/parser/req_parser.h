// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */
#ifndef __REQ_PARSER_H__
#define __REQ_PARSER_H__

#include <stdint.h>

int parser_init(uint32_t fs_mode, const char *mntpoint);
void parser_destory(void);
int maio_parse_req(void *buf, int size);

#endif
