/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_nictool.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_NICTOOL_H
#define HINIC5_NICTOOL_H

#include "hinic5_mt.h"
#include "hinic5_crm.h"
#include "hinic5_hw_mt.h"
#include "hinic5_chip_info.h"

#ifndef MAX_SIZE
#define MAX_SIZE (16)
#endif

#ifndef _LLT_TEST_
#define DBGTOOL_PAGE_ORDER (10)
#else
#define DBGTOOL_PAGE_ORDER (1)
#endif

#define MAX_CARD_NUM (64)

int hinic5_nictool_k_init(void *hwdev, void *chip_node);
void hinic5_nictool_k_uninit(void *hwdev, void *chip_node);

void hinic5_get_all_chip_id(void *id_info);

void hinic5_get_card_info(const void *hwdev, const void *bufin, void *bufout);

bool hinic5_is_in_host(void);

int hinic5_get_pf_id(struct card_node *chip_node, u32 port_id, u32 *pf_id, u32 *isvalid);

void hinic5_get_mbox_cnt(const void *hwdev, void *buf_out);

extern struct hinic5_uld_info hinic5_g_uld_info[SERVICE_T_MAX];

#endif
