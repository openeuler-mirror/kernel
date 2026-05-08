/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_log_export.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_LOG_EXPORT_H__
#define __SXE2_LOG_EXPORT_H__

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/sysfs.h>
#include <linux/mutex.h>

struct sxe2_adapter;

#define SXE2_DUMP_FILE_DIR_LEN  (128)
#define SXE2_DUMP_FILE_NAME_LEN (256)

struct sxe2_export_file_info {
	u8           filename[SXE2_DUMP_FILE_NAME_LEN];
	struct file *fp;
	u64          file_size;
	u32          file_w_cnt;
	u32          file_status;
	u8           reserved[4];
};

struct sxe2_export_context {
	struct sxe2_adapter       *adapter;
	struct sxe2_export_file_info file;
	u32 file_size_limit;
};

s32 sxe2_log_export_init(struct sxe2_adapter *adapter);

void sxe2_log_export_deinit(struct sxe2_adapter *adapter);

s32 sxe2_event_log_export(struct sxe2_adapter *adapter, void *buf, u32 buf_len);

#endif
