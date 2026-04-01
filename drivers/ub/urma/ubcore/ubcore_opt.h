/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: ubcore opt list
 * Author: Chen JingWei
 * Create: 2025-11-21
 * Note:
 * History: 2025-11-21: Create file
 */
#ifndef UBCORE_OPT_H
#define UBCORE_OPT_H
#include <ub/urma/ubcore_types.h>
#include "ubcore_tp.h"

#define UBCORE_CFG_MASK 0

enum ubcore_field_target_t {
	TARGET_CFG,
	TARGET_OPT,
	TARGET_NO_STORE,
};

struct ubcore_opt_map {
	uint64_t opt;           /* opt id (eg. URMA_JFC_DEPTH) */
	uint64_t mask;          /* bit mask value for this opt (eg. URMA_JFC_DEPTH_MASK) */
	enum ubcore_field_target_t tgt; /* which sub-struct the field belongs to */
	size_t offset;          /* offsetof(sub-struct, member) */
	size_t size;            /* sizeof(member) */
};

extern const struct ubcore_opt_map g_ubcore_jfs_opt_table[];
extern const size_t g_ubcore_jfs_opt_map_count;
extern const struct ubcore_opt_map g_ubcore_jfr_opt_table[];
extern const size_t g_ubcore_jfr_opt_map_count;
extern const struct ubcore_opt_map g_ubcore_jfc_opt_table[];
extern const size_t g_ubcore_jfc_opt_map_count;
extern const struct ubcore_opt_map g_ubcore_jetty_opt_table[];
extern const size_t g_ubcore_jetty_opt_map_count;

#define UBCORE_JFS_SQE_BASE_ADDR_MASK       (1ULL << 0)
#define UBCORE_JFS_ID_MASK                  (1ULL << 1)
#define UBCORE_JFS_DB_ADDR_MASK             (1ULL << 2)
#define UBCORE_JFS_DB_STATUS_MASK           (1ULL << 3)
#define UBCORE_JFS_PI_MASK                  (1ULL << 4)
#define UBCORE_JFS_PI_TYPE_MASK             (1ULL << 5)
#define UBCORE_JFS_CI_MASK                  (1ULL << 6)

#define UBCORE_JFR_RQE_BASE_ADDR_MASK       (1ULL << 0)
#define UBCORE_JFR_ID_MASK                  (1ULL << 1)
#define UBCORE_JFR_DB_ADDR_MASK             (1ULL << 2)
#define UBCORE_JFR_DB_STATUS_MASK           (1ULL << 3)
#define UBCORE_JFR_PI_MASK                  (1ULL << 4)
#define UBCORE_JFR_PI_TYPE_MASK             (1ULL << 5)
#define UBCORE_JFR_CI_MASK                  (1ULL << 6)

#define UBCORE_JFC_CQE_BASE_ADDR_MASK       (1ULL << 0)
#define UBCORE_JFC_ID_MASK                  (1ULL << 1)
#define UBCORE_JFC_DB_ADDR_MASK             (1ULL << 2)
#define UBCORE_JFC_DB_STATUS_MASK           (1ULL << 3)
#define UBCORE_JFC_PI_MASK                  (1ULL << 4)
#define UBCORE_JFC_PI_TYPE_MASK             (1ULL << 5)
#define UBCORE_JFC_CI_MASK                  (1ULL << 6)

#endif
