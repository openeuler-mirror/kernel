/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_chip_info.h
 * Version       : Initial Draft
 * Created       : 2025/8/13
 * Last Modified : 2026/09/16
 * Description   : SDK's inner chip related structure and macro defined here.
 */

#ifndef HINIC5_CHIP_INFO_H
#define HINIC5_CHIP_INFO_H

#include <linux/mutex.h>
#include <linux/spinlock.h>
#include "hinic5_crm.h"
#include "hinic5_mt.h"

/**
 * @brief struct card_node
 * @details Defines a struct named card_node, representing a network card node
 */
struct card_node {
	struct list_head node;                       /**< Represents a list head */
	struct list_head func_list;                  /**< Represents a function list head */
	char chip_name[IFNAMSIZ];                    /**< Stores the chip name */
	void *log_info;                              /**< Points to log information */
	void *dbgtool_info;                          /**< Points to debug tool information */
	spinlock_t dbgtool_info_lock;           	 /**< Protects fm_show update context */
	void *func_handle_array[MAX_FUNCTION_NUM];   /**< Stores function handles */
	u16 func_num;                                /**< function count */
	u32 rsvd1;
	void *priv_data;                             /**< Points to private data */
	u64 rsvd2;
	void *fw_update_context;                     /**< Points to firmware update context */
	struct mutex fw_update_context_lock;            /**< Protects firmware update context */
	struct hinic5_non_ptp_info *non_ptp_info;    /**< Non-PTP time difference information */
	u64 id;                                      /**< Chip unique id identifier */
	atomic_t ref_cnt;                            /**< Reference count */
};
#endif
