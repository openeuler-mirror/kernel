/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hw_mt.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_HW_MT_H
#define HINIC5_HW_MT_H

#include "hinic5_mt.h"
#include "hinic5_lld.h"

struct sm_in_st {
	int node;
	int id;
	int instance;
};

struct sm_out_st {
	u64 val1;
	u64 val2;
};

struct up_log_msg_st {
	u32 rd_len;
	u32 addr;
};

struct csr_write_st {
	u32 rd_len;
	u32 addr;
	u8 *data;
};

struct hinic5_mt_cmd_info {
	u8 mod;
	u16 cmd;
	void *buf_in;
	u16 in_size;
	void *buf_out;
	u16 *out_size;
	u32 timeout;
};

int hinic5_get_func_type(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
		  void *buf_out, const u32 *out_size);

int hinic5_get_func_id(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
		void *buf_out, const u32 *out_size);

int hinic5_get_hw_driver_stats(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			void *buf_out, const u32 *out_size);

int hinic5_clear_hw_driver_stats(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			  void *buf_out, const u32 *out_size);

int hinic5_get_self_test_result(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			 void *buf_out, const u32 *out_size);

int hinic5_get_chip_faults_stats(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			  void *buf_out, const u32 *out_size);

#ifndef __WIN__
/**
 * @brief alloc input buffer
 * @param hwdev: device pointer to hwdev
 * @param nt_msg: message module struct
 * @param in_size: input buffer size
 * @param buf_in: input buffer
 *
 * @return
 *      @retval zero: success
 *      @retval non-zero: failure
 */

int hinic5_alloc_buff_in(void *hwdev, const struct msg_module *nt_msg, u32 in_size, void **buf_in);

/**
 * @brief alloc output buffer
 * @param hwdev: device pointer to hwdev
 * @param nt_msg: message module struct
 * @param out_size: input buffer size
 * @param buf_out: output buffer
 *
 * @return
 *      @retval zero: success
 *      @retval non-zero: failure
 */

int hinic5_alloc_buff_out(void *hwdev, const struct msg_module *nt_msg, u32 out_size, void **buf_out);

/**
 * @brief free input buffer
 * @param hwdev: device pointer to hwdev
 * @param nt_msg: message module struct
 * @param buf_in: input buffer
 *
 * @return
 *      @retval zero: success
 *      @retval non-zero: failure
 */

void hinic5_free_buff_in(void *hwdev, const struct msg_module *nt_msg, void *buf_in);

/**
 * @brief free output buffer
 * @param hwdev: device pointer to hwdev
 * @param nt_msg: message module struct
 * @param buf_out: output buffer
 *
 * @return
 *      @retval zero: success
 *      @retval non-zero: failure
 */

void hinic5_free_buff_out(void *hwdev, const struct msg_module *nt_msg, void *buf_out);

/**
 * @brief copy from message buffer to user buffer
 * @param nt_msg: message module struct
 * @param out_size: message buffer size
 * @param buf_out: message buffer
 *
 * @return
 *      @retval zero: success
 *      @retval non-zero: failure
 */

int hinic5_copy_buf_out_to_user(const struct msg_module *nt_msg, u32 out_size, void *buf_out);
#endif
/**
 * @brief send message to mpu
 * @param hwdev: device pointer to hwdev
 * @param nt_msg: message module struct
 * @param buf_in: input buffer
 * @param in_size: input buffer size
 * @param buf_out: output buffer
 * @param out_size: output buffer size
 *
 * @return
 *      @retval zero: success
 *      @retval non-zero: failure
 */

int hinic5_send_to_mpu(void *hwdev, struct msg_module *nt_msg,
		void *buf_in, u32 in_size, void *buf_out, u32 *out_size);

/**
 * @brief send message to npu
 * @param hwdev: device pointer to hwdev
 * @param nt_msg: message module struct
 * @param buf_in: input buffer
 * @param in_size: input buffer size
 * @param buf_out: output buffer
 * @param out_size: output buffer size
 *
 * @return
 *      @retval zero: success
 *      @retval non-zero: failure
 */

int hinic5_send_to_npu(void *hwdev, const struct msg_module *nt_msg,
		void *buf_in, u32 in_size, void *buf_out, u32 *out_size);

/**
 * @brief send message to sm
 * @param hwdev: device pointer to hwdev
 * @param nt_msg: message module struct
 * @param buf_in: input buffer
 * @param in_size: input buffer size
 * @param buf_out: output buffer
 * @param out_size: output buffer size
 *
 * @return
 *      @retval zero: success
 *      @retval non-zero: failure
 */

int hinic5_send_to_sm(void *hwdev, const struct msg_module *nt_msg,
	       void *buf_in, u32 in_size, void *buf_out, u32 *out_size);

#endif
