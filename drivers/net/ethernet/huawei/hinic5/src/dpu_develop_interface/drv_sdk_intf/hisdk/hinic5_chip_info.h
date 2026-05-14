/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_chip_info.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : sdk's inner chip related structure and macro defined here.
 */


#ifndef HINIC5_CHIP_INFO_H
#define HINIC5_CHIP_INFO_H

#include "hinic5_crm.h"
#include "hinic5_mt.h"

/**
 * @brief struct card_node
 * @details define a struct named card_node, representing a network card node
 */
struct card_node {
	struct list_head node;                       /**< list head */
	struct list_head func_list;                  /**< function list head */
	char chip_name[IFNAMSIZ];                    /**< chip name storage */
	void *log_info;                              /**< log information pointer */
	void *dbgtool_info;                          /**< debug tool information pointer */
	spinlock_t dbgtool_info_lock;           	 /**< protects fm_show update context */
	void *func_handle_array[MAX_FUNCTION_NUM];   /**< function handle storage */
	u16 func_num;                                /**< function count */
	u32 rsvd1;
	atomic_t channel_busy_cnt;                   /**< channel busy count */
	void *priv_data;                             /**< private data pointer */
	u64 rsvd2;
	void *fw_update_context;                     /**< firmware update context pointer */
	spinlock_t fw_update_context_lock;           /**< protects firmware update context */
	struct hinic5_non_ptp_info *non_ptp_info;    /**< non-ptp time difference information */
	bool exception_flag;                         /**< fatal exception occurred flag */
	u64 id;                                      /**< chip unique id */
};
#endif
