/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_fw_update.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_FW_UPDATE_H
#define HINIC5_FW_UPDATE_H

#include "hinic5_hwif_inner.h"
#include "hinic5_hw_cfg.h"
#include "hinic5_hw_mt.h"

#define FW_UPDATE_DDR_MAX		(1536 * 1024) /* 1.5 MB */

#define FW_UPDATE_CHIP_CACHELINE	256

/* Reference: updatefw.h */
#define FW_HOW_ACTIVE_TYPE_NPU			2

struct tag_fw_update_bat_l3i_entry {
	u32        page_order;
	u32        buf_size;
	void       *buf_va;
	dma_addr_t buf_pa;
};

struct tag_fw_update_handle {
	struct hinic5_hwdev *hwdev;
	struct device *dev;

	u8  gpa_check_enable;

	u8  smf_enabled[CHIP_SMF_NUM_MAX];
	u32 smf_enabled_num;

	struct tag_fw_update_bat_l3i_entry bat_l3i_entries[CHIP_SMF_NUM_MAX];
};

struct fw_section_data {
	u8 *data;
	u32 data_cap;
	u32 data_size;
	u32 data_off;
	u32 verified : 1;
	u32 rsvd : 31;
};

struct fw_update_context {
	u32 update_started : 1;
	u32 rsvd : 31;
	struct fw_section_data sec_text;
	struct fw_section_data sec_phy;
};

/**
 * @brief hinic5_fw_update_init - init firmware update resource
 * @param hwdev_hdl: device pointer to hwdev
 * @retval zero: success
 * @retval non-zero: failure
 */
int hinic5_fw_update_init(void *hwdev_hdl);

/**
 * @brief hinic5_fw_update_deinit - deinit firmware update resource
 * @param hwdev_hdl: device pointer to hwdev
 */
void hinic5_fw_update_deinit(void *hwdev_hdl);

/**
 * @brief hinic5_fw_update_free_context - free update context
 * @param context_hdl: pointer to update context
 */
void hinic5_fw_update_free_context(void *update_context_hdl);

/**
 * @brief hinic5_fw_update_ddr_enabled -
 *        whether L3I is enabled to support firmware's hot update
 * @param hwdev_hdl: device pointer to hwdev
 * @retval true: This function is enables L3I
 * @retval false: This function does not enable L3I
 */
bool hinic5_fw_update_ddr_enabled(void *hwdev_hdl);

/**
 * @brief hinic5_fw_update_cmd_update - handle cmd UPDATE_FW
 * @retval zero: success
 * @retval non-zero: failure
 */
int hinic5_fw_update_cmd_update(void *hwdev_hdl, struct hinic5_mt_cmd_info *cmd_info);

/**
 * @brief hinic5_fw_update_cmd_update - handle cmd HOT_ACTIVE_FW
 * @retval zero: success
 * @retval non-zero: failure
 */
int hinic5_fw_update_cmd_hot_active(void *hwdev_hdl, struct hinic5_mt_cmd_info *cmd_info);

#endif
