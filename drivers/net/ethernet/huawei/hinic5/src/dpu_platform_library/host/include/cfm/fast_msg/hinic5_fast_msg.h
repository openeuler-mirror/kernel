/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_fast_msg.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_FAST_MSG_H
#define HINIC5_FAST_MSG_H

#include <linux/types.h>
#include <linux/workqueue.h>
#include "fast_msg_common_define.h"
#include "comm_defs.h"
#include "hinic5_hw.h"

#define FAST_MSG_ENTRY_SIZE             2
#define FAST_MSG_ENTRY_UNIT             1024
#define FAST_MSG_ENTRY_SIZE_B           (FAST_MSG_ENTRY_UNIT * FAST_MSG_ENTRY_SIZE)
#define HISDK5_FAST_MSG_MAX_PAGE_NUM    32
#define MAX_FAST_MSG_RQ_DEPTH           2048
#define FAST_MSG_RQ_OFFSET_MASK         0xFFF
#define FAST_MSG_RECV_MAX_CONCURRENT    10

/* Indicate fast msg upper layer message format type */
enum hisdk5_fast_msg_ulp_format {
	HISDK5_FAST_MSG_ULP_FROMAT_NONE = 0,
	HISDK5_FAST_MSG_ULP_FROMAT_MIG = 1,
	/* 4bit width, type must be less than 16 */
	HISDK5_FAST_MSG_ULP_FROMAT_MAX = 16
};

typedef void (*hinic5_fast_msg_rq_cb)(hisdk5_fast_msg_buf *rq_msg, void *fast_msg_rq_data);
typedef void (*hinic5_fast_msg_forward_cb)(void *data);

enum hisdk5_fast_msg_work_entry_type {
	MSG_WORK_ENTRY_RECV_FAST_MSG,
	MSG_WORK_ENTRY_FORWARDING
};

struct hisdk5_fast_msg_recv_entry {
	struct list_head entry;
	u32 type;
	union {
		u32 rq_offset;
		struct {
			void *forward_data;
			hinic5_fast_msg_forward_cb forward_cb;
		};
	};
};

struct hisdk5_fast_msg_recv_work {
	struct work_struct work;
	struct hisdk5_fast_msg_to_func *fast_msg_to_func;
	struct list_head msg_head;
	spinlock_t lock;/* spinlock protecting the msg_head and work queue data */
};

struct hisdk5_fast_msg_to_func {
	void *hwdev;

	u32 fast_msg_rq_depth;
	u32 fast_msg_rq_page_size;
	u32 fast_msg_rq_page_num;

	void *rq_mem[HISDK5_FAST_MSG_MAX_PAGE_NUM];
	dma_addr_t rq_mem_paddr[HISDK5_FAST_MSG_MAX_PAGE_NUM];

	struct workqueue_struct *workq;

	hinic5_fast_msg_rq_cb fast_msg_rq_cb[HINIC5_MOD_MAX];
	void *fast_msg_rq_data[HINIC5_MOD_MAX];

	u32 num_concurrent_work;
	struct hisdk5_fast_msg_recv_work *recv_concurrent_work;
	struct hisdk5_fast_msg_recv_entry *recv_entries;
};

void hinic5_fast_msg_rq_handler(void *pri_handle, u32 ceqe_data);
void hinic5_fast_msg_recv_handler(struct work_struct *work);

int hinic5_fast_msg_register_cb(void *hwdev, u8 mod, hinic5_fast_msg_rq_cb callback, void *pri_data);
void hinic5_fast_msg_unregister_cb(void *hwdev, u8 mod);
int hinic5_fast_msg_send(void *hwdev, struct hinic5_cmd_buf *cmd_buf, u64 *out_parm);

/**
 * @brief fast msg message reorder execution
 *
 * @param hwdev SDK handle
 * @param src_func_id fastmsg message source function id
 * @param data callback function private data
 * @param callback callback function pointer
 *
 * @details After a function receives a fastmsg message, if the message needs to wait for all previous messages
 *      from another function to be processed, then fastmsg needs to be re-chained to ensure the message is
 *      processed serially in the task of another function
 *
 * @return: 0 - message added to list successfully, other - message added to list failed
 */
int hinic5_fast_msg_forward(void *hwdev, u16 src_func_id, void *data, hinic5_fast_msg_forward_cb callback);

/**
 * @brief Check if current function supports fast msg
 *
 * @param hwdev SDK handle
 *
 * @return: true - supported, false - not supported.
 */
bool hinic5_support_fast_msg(void *hwdev);

#endif