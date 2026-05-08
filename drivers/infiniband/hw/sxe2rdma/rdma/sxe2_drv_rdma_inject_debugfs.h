/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_inject_debugfs.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef _SXE2_DRV_RDMA_INJECT_DEBUGFS_H_
#define _SXE2_DRV_RDMA_INJECT_DEBUGFS_H_

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
#include <linux/debugfs.h>
#include "sxe2_drv_rdma_inject.h"
#include "sxe2_drv_rdma_common.h"

#define DEBUGFS_ROOT_DIR	"sxe2"
#define INJECT_NAME_MAX_LEN	(120)
#define INJECT_USR_DATA_LEN	(64)
#define INJECT_SNPRINTF_LEN_MAX (2 * 1024 * 1024)

#define INJECT_DEBUG_SNPRINTF(rsp, lens, ...)                                  \
	{                                                                      \
		u32 _injected_len_ = (u32)snprintf(                            \
			rsp, INJECT_SNPRINTF_LEN_MAX, __VA_ARGS__);            \
		lens += _injected_len_;                                        \
		rsp += _injected_len_;                                         \
	}
typedef bool (*inject_filter_func)(struct sxe2_injection *, const char *);

struct inject_custom_show_rsp {
	u32 mid;
	s32 alive;
	s8 name[INJECT_NAME_MAX_LEN];
	s8 usr_data[INJECT_USR_DATA_LEN];
	enum inject_type type;
};

enum inject_attr {
	INJECT_ATTR_MID,
	INJECT_ATTR_NAME,
	INJECT_ATTR_STATUS,
	INJECT_ATTR_ALIVE,
	INJECT_ATTR_TYPE,
	INJECT_ATTR_USERDATA,
	INJECT_MAX_ATTR,
};

void sxe2_drv_inject_clean_debug_files(struct sxe2_rdma_device *dev);

void sxe2_drv_inject_create_debugfs_files(struct sxe2_rdma_device *dev);

struct dentry *sxe2_drv_debugfs_get_dev_root(struct sxe2_rdma_device *dev);

int sxe2_drv_inject_show_read_parse_args(char *cmd, char *rsp,
					 inject_filter_func *filter,
					 char **attr, u32 *len);

#endif

#endif
