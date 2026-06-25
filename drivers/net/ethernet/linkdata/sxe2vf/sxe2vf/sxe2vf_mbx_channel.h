/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_mbx_channel.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#include <linux/types.h>
#include <linux/mutex.h>

#include "sxe2_mbx_public.h"

#ifndef __SXE2VF_MBX_CHANNEL_H__
#define __SXE2VF_MBX_CHANNEL_H__

struct sxe2vf_adapter;

#define SXE2VF_MSG_RETRY_INTERVAL 10
#define SXE2VF_MSG_RETRY_COUNT 3
#define SXE2VF_MSG_WB_WAIT_INTERVAL 10
#define SXE2VF_MSG_RQ_WEIGHT 256

#define SXE2VF_MBX_Q_DESC_CNT 32

#define SXE2VF_MBX_SEND_RETRY_CNT 5

#define SXE2VF_MBX_DESC_LB_SIZE 512

#define SXE2VF_MBX_DESC_DD BIT(0)
#define SXE2VF_MBX_DESC_COMPLETE BIT(1)
#define SXE2VF_MBX_DESC_ERROR BIT(2)
#define SXE2VF_MBX_DESC_LB BIT(9)
#define SXE2VF_MBX_DESC_READ BIT(10)
#define SXE2VF_MBX_DESC_BUF BIT(12)
#define SXE2VF_MBX_DESC_NO_INTR BIT(13)

#define SXE2VF_MBX_DONE (SXE2VF_MBX_DESC_DD | SXE2VF_MBX_DESC_COMPLETE | SXE2VF_MBX_DESC_ERROR)

#define SXE2VF_MBX_BUF_SIZE 4096

#define SXE2VF_MBX_RQ_WEIGHT 256

#define SXE2VF_MBX_TIMEOUT (1)
#define SXE2VF_MBX_CHECK_INT (1)

#define SXE2VF_MBX_MSG_HTABLE_ORDER 8

#ifndef secs_to_jiffies
#define secs_to_jiffies(_secs) msecs_to_jiffies((_secs) * 1000)
#endif

#define SXE2VF_MSG_DFLT_TIMEOUT (60)

#define SXE2_MSG_SESSION_ADD_ONE (1ULL)

enum sxe2vf_desc_err_code {
	SXE2VF_MBX_DESC_ERR_NONE = 0,
	SXE2VF_MBX_DESC_ERR_DES_ERR,
	SXE2VF_MBX_DESC_ERR_BUF_ERR,
	SXE2VF_MBX_DESC_ERR_BUF_NUM_ERR,
	SXE2VF_MBX_DESC_ERR_SRC_BUSY,
	SXE2VF_MBX_DESC_ERR_DATA_LEN_LACK,
	SXE2VF_MBX_DESC_ERR_DATA_LEN_LACK2,
	SXE2VF_MBX_DESC_ERR_SESSION_BUFFER_OV,
	SXE2VF_MBX_DESC_ERR_CMD_BUFFER_OV,
	SXE2VF_MBX_DESC_ERR_IN_OUT_LEN_LACK,
	SXE2VF_MBX_DESC_ERR_UNKNOWN_OPCODE,
	SXE2VF_MBX_DESC_ERR_UNKNOWN_CMD_TYPE,
	SXE2VF_MBX_DESC_ERR_ADMINQ_STATE,
	SXE2VF_MBX_DESC_ERR_FIND_JOB,
	SXE2VF_MBX_DESC_ERR_NONE_START,
	SXE2VF_MBX_DESC_ERR_NR,
};

struct sxe2vf_mbx_ring {
	void *va;
	dma_addr_t pa;
	size_t size;
};

struct sxe2vf_mbx_desc {
	__le16 flags;
	__le16 opcode;
	__le16 data_len;
	__le16 ret;
	__le32 custom0;
	__le32 custom1;
	__le32 custom2;
	__le32 custom3;
	__le32 buf_addr_h;
	__le32 buf_addr_l;
};

#define SXE2VF_MBX_Q_DESC(queue, i) (&(((struct sxe2vf_mbx_desc *)((queue)->desc.va))[i]))
#define SXE2VF_MBX_Q_BUF(queue, i) ((queue)->buf[i].va)

#define SXE2VF_MBX_Q_DESC_UNUSED(queue)             \
	({ \
		typeof(queue) __queue = (queue); \
		((u16)((((__queue)->ntc > (__queue)->ntu) ? 0 : \
		(__queue)->depth) + (__queue)->ntc - (__queue)->ntu - 1)); \
	})

#define SXE2VF_RING_IDX_INC(i, depth)                                       \
	do {                             \
		typeof(i) *p = &(i);         \
		(*p)++;                      \
		if ((*p) == (depth))         \
			(*p) = 0;                \
	} while (0)

#define SXE2VF_HW_DONE(desc) (le16_to_cpu((desc)->flags) & SXE2VF_MBX_DONE)

struct sxe2vf_mbx_queue {
	u16 depth;
	u16 buf_size;
	u16 ntu;
	u16 ntc;
	struct sxe2vf_mbx_ring desc;
	struct sxe2vf_mbx_ring *buf;

	/* in order to protect the data */
	struct mutex lock;
};

struct sxe2vf_mbx_waitq {
	/* in order to protect the data */
	spinlock_t lock;
	wait_queue_head_t wq;
	DECLARE_HASHTABLE(table, SXE2VF_MBX_MSG_HTABLE_ORDER);
};

enum sxe2vf_msg_state {
	SXE2VF_MSG_STATE_WAITING = 0,
	SXE2VF_MSG_STATE_DONE,
	SXE2VF_MSG_STATE_CANCELED,
	SXE2VF_MSG_STATE_FAULT,
};

struct sxe2vf_wait_entry {
	struct hlist_node entry;
	u64 session_id;
	enum sxe2vf_msg_state state;
	u16 rcv_len;
	void *rcv_buf;
};

struct sxe2vf_msg_ctxt {
	struct sxe2vf_adapter *adapter;
	enum sxe2_vf_opcode opcode;
	u64 session_id;
	unsigned long expired_time;
	struct sxe2vf_cmd_hdr *full_msg;
	struct sxe2vf_wait_entry *wait_entry;
	struct sxe2vf_msg_params *msg_raw;
	u16 rcv_len;
	void *rcv_buf;
};

struct sxe2vf_notify_msg_list {
	struct list_head head;

	/* in order to protect the data */
	struct mutex lock;
};

struct sxe2vf_channel_context {
	struct sxe2vf_mbx_queue rxq;
	struct sxe2vf_mbx_queue txq;
	struct sxe2vf_mbx_waitq waitq;
	struct sxe2vf_notify_msg_list list;
};

enum sxe2vf_resp_wait_mode {
	SXE2VF_MSG_RESP_WAIT_NO_RESP,
	SXE2VF_MSG_RESP_WAIT_NOTIFY,
	SXE2VF_MSG_RESP_WAIT_POLLING,
};

struct sxe2vf_msg_params {
	u64 trace_id;
	u32 err_code;
	u32 opcode;
	u16 in_len;
	void *in_data;
	u16 out_len;
	void *out_data;
	enum sxe2vf_resp_wait_mode mode;
	u32 timeout;
};

struct sxe2vf_mbx_rcv {
	struct list_head node;
	u16 buf_len;
	struct sxe2vf_mbx_desc desc;
	u8 buf[];
};

void sxe2vf_mbx_channel_deinit(struct sxe2vf_adapter *adapter);

s32 sxe2vf_mbx_channel_init(struct sxe2vf_adapter *adapter);

s32 sxe2vf_mbx_msg_rcv(struct sxe2vf_adapter *adapter);

s32 sxe2vf_mbx_msg_send(struct sxe2vf_adapter *adapter, struct sxe2vf_msg_params *params_s);

bool sxe2vf_mbx_tx_done(struct sxe2vf_mbx_desc *desc);

void sxe2vf_mbx_resource_free(struct sxe2vf_adapter *adapter);

s32 sxe2vf_err_code_trans_mbx(s32 err);

void sxe2vf_cmd_session_id_init(void);

void sxe2vf_waitq_entry_cancel(struct sxe2vf_adapter *adapter);

void sxe2vf_notify_msg_list_clear(struct sxe2vf_adapter *adapter);

void sxe2vf_notify_msg_wk_cb(struct work_struct *work);

s32 sxe2vf_dev_state_check(struct sxe2vf_adapter *adapter);

#endif
