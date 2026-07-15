/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_mgmt.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_MGMT_H
#define HINIC5_MGMT_H

#include <linux/types.h>
#include <linux/completion.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include "comm_defs.h"
#include "mpu_cmd_base_defs.h"
#include "hinic5_hw.h"
#include "hinic5_api_cmd.h"
#include "hinic5_hwdev.h"

#define HINIC5_MGMT_WQ_NAME			"hinic5_mgmt"

#define HINIC5_CLP_REG_GAP			0x20
#define HINIC5_CLP_INPUT_BUF_LEN_HOST		4096UL
#define HINIC5_CLP_DATA_UNIT_HOST		4UL

enum clp_data_type {
	HINIC5_CLP_REQ_HOST = 0,
	HINIC5_CLP_RSP_HOST = 1
};

enum clp_reg_type {
	HINIC5_CLP_BA_HOST = 0,
	HINIC5_CLP_SIZE_HOST = 1,
	HINIC5_CLP_LEN_HOST = 2,
	HINIC5_CLP_START_REQ_HOST = 3,
	HINIC5_CLP_READY_RSP_HOST = 4
};

#define HINIC5_CLP_REQ_SIZE_OFFSET		0
#define HINIC5_CLP_RSP_SIZE_OFFSET		16
#define HINIC5_CLP_BASE_OFFSET			0
#define HINIC5_CLP_LEN_OFFSET			0
#define HINIC5_CLP_START_OFFSET			31
#define HINIC5_CLP_READY_OFFSET			31
#define HINIC5_CLP_OFFSET(member)		(HINIC5_CLP_##member##_OFFSET)

#define HINIC5_CLP_SIZE_MASK			0x7ffUL
#define HINIC5_CLP_BASE_MASK			0x7ffffffUL
#define HINIC5_CLP_LEN_MASK			0x7ffUL
#define HINIC5_CLP_START_MASK			0x1UL
#define HINIC5_CLP_READY_MASK			0x1UL
#define HINIC5_CLP_MASK(member)			(HINIC5_CLP_##member##_MASK)

#define HINIC5_CLP_DELAY_CNT_MAX		200UL
#define HINIC5_CLP_SRAM_SIZE_REG_MAX		0x3ff
#define HINIC5_CLP_SRAM_BASE_REG_MAX		0x7ffffff
#define HINIC5_CLP_LEN_REG_MAX			0x3ff
#define HINIC5_CLP_START_OR_READY_REG_MAX	0x1

struct hinic5_recv_msg {
	void			*msg;

	u16			msg_len;
	u16			rsvd1;
	enum hinic5_mod_type	mod;

	u16			cmd;
	u8			seq_id;
	u8			rsvd2;
	u16			msg_id;
	u16			rsvd3;

	int			async_mgmt_to_pf;
	u32			rsvd4;

	struct completion	recv_done;
};

struct hinic5_msg_head {
	u8	status;
	u8	version;
	u8	resp_aeq_num;
	u8	rsvd0[5];
};

enum comm_pf_to_mgmt_event_state {
	SEND_EVENT_UNINIT = 0,
	SEND_EVENT_START,
	SEND_EVENT_SUCCESS,
	SEND_EVENT_FAIL,
	SEND_EVENT_TIMEOUT,
	SEND_EVENT_END,
};

enum hinic5_mgmt_msg_cb_state {
	HINIC5_MGMT_MSG_CB_REG = 0,
	HINIC5_MGMT_MSG_CB_RUNNING,
};

struct hinic5_clp_pf_to_mgmt {
	struct semaphore	clp_msg_lock;
	void			*clp_msg_buf;
};

struct hinic5_msg_pf_to_mgmt {
	struct hinic5_hwdev		*hwdev;

	/* Async cmd can not be scheduling */
	spinlock_t			async_msg_lock;
	struct semaphore		sync_msg_lock;

	struct workqueue_struct		*workq;

	void				*async_msg_buf;
	void				*sync_msg_buf;
	void				*mgmt_ack_buf;

	struct hinic5_recv_msg		recv_msg_from_mgmt;
	struct hinic5_recv_msg		recv_resp_msg_from_mgmt;

	u16				async_msg_id;
	u16				sync_msg_id;
	u32				rsvd1;
	struct hinic5_api_cmd_chain	*cmd_chain[HINIC5_API_CMD_MAX];

	hinic5_mgmt_msg_cb		recv_mgmt_msg_cb[HINIC5_MOD_HW_MAX];
	void				*recv_mgmt_msg_data[HINIC5_MOD_HW_MAX];
	ulong			    mgmt_msg_cb_state[HINIC5_MOD_HW_MAX];

	void				*async_msg_cb_data[HINIC5_MOD_HW_MAX];

	/* lock when sending msg */
	spinlock_t			sync_event_lock;
	enum comm_pf_to_mgmt_event_state event_flag;
	u64				rsvd2;
};

struct hinic5_mgmt_msg_handle_work {
	struct work_struct	work;
	struct hinic5_msg_pf_to_mgmt *pf_to_mgmt;

	void			*msg;
	u16			msg_len;
	u16			rsvd1;

	enum hinic5_mod_type	mod;
	u16			cmd;
	u16			msg_id;

	int			async_mgmt_to_pf;
};

void hinic5_mgmt_msg_aeqe_handler(void *hwdev, u8 *header, u8 size);

int hinic5_pf_to_mgmt_init(struct hinic5_hwdev *hwdev);

void hinic5_pf_to_mgmt_free(struct hinic5_hwdev *hwdev);

int hinic5_pf_to_mgmt_sync(void *hwdev, u8 mod, u16 cmd, void *buf_in,
			   u16 in_size, void *buf_out, u16 *out_size,
			   u32 timeout);
int hinic5_pf_to_mgmt_async(void *hwdev, u8 mod, u16 cmd, const void *buf_in,
			    u16 in_size);

int hinic5_pf_msg_to_mgmt_sync(void *hwdev, u8 mod, u16 cmd, void *buf_in,
			       u16 in_size, void *buf_out, u16 *out_size,
			       u32 timeout);

int hinic5_api_cmd_read_ack(void *hwdev, u8 dest, const void *cmd, u16 size,
			    void *ack, u16 ack_size);

int hinic5_api_cmd_write_nack(void *hwdev, u8 dest, const void *cmd, u16 size);

int hinic5_pf_clp_to_mgmt(void *hwdev, u8 mod, u16 cmd, const void *buf_in,
			  u16 in_size, void *buf_out, const u16 *out_size);

int hinic5_clp_pf_to_mgmt_init(struct hinic5_hwdev *hwdev);

void hinic5_clp_pf_to_mgmt_free(struct hinic5_hwdev *hwdev);

#endif
