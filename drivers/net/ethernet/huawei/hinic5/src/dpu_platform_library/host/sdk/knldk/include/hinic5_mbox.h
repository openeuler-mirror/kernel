/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_mbox.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_MBOX_H
#define HINIC5_MBOX_H

#include <linux/workqueue.h>
#include <linux/mutex.h>

#include "comm_defs.h"
#include "hinic5_crm.h"
#include "mpu_mailbox_msg_header.h"
#include "hinic5_hwdev.h"

#define HINIC5_MBOX_PF_SEND_ERR				0x1

#define HINIC5_MGMT_SRC_ID				0x1FFF
#define HINIC5_MAX_FUNCTIONS				4096
#define MBOX_SEG_LEN_UNIT 0x4
#define MBOX_MSG_LEN_UNIT 0x4

#define HINIC5_MSG_HEADER_SRC_GLB_FUNC_IDX_SHIFT	0
#define HINIC5_MSG_HEADER_STATUS_SHIFT			13
#define HINIC5_MSG_HEADER_VERSION_SHIFT			14
#define HINIC5_MSG_HEADER_SOURCE_SHIFT			15
#define HINIC5_MSG_HEADER_AEQ_ID_SHIFT			16
#define HINIC5_MSG_HEADER_MSG_ID_SHIFT			18
#define HINIC5_MSG_HEADER_CMD_SHIFT			22

#define HINIC5_MSG_HEADER_V0_MSG_LEN_SHIFT			32
#define HINIC5_MSG_HEADER_V1_MSG_LEN_SHIFT			32
#define HINIC5_MSG_HEADER_V0_MODULE_SHIFT			43
#define HINIC5_MSG_HEADER_V1_MODULE_SHIFT			43
#define HINIC5_MSG_HEADER_V0_SEG_LEN_SHIFT			48
#define HINIC5_MSG_HEADER_V1_SEG_LEN_SHIFT			50
#define HINIC5_MSG_HEADER_NO_ACK_SHIFT			54
#define HINIC5_MSG_HEADER_DATA_TYPE_SHIFT		55
#define HINIC5_MSG_HEADER_SEQID_SHIFT			56
#define HINIC5_MSG_HEADER_LAST_SHIFT			62
#define HINIC5_MSG_HEADER_DIRECTION_SHIFT		63

#define HINIC5_MSG_HEADER_SRC_GLB_FUNC_IDX_MASK		0x1FFF
#define HINIC5_MSG_HEADER_STATUS_MASK			0x1
#define HINIC5_MSG_HEADER_VERSION_MASK			0x1
#define HINIC5_MSG_HEADER_SOURCE_MASK			0x1
#define HINIC5_MSG_HEADER_AEQ_ID_MASK			0x3
#define HINIC5_MSG_HEADER_MSG_ID_MASK			0xF
#define HINIC5_MSG_HEADER_CMD_MASK			0x3FF

#define HINIC5_MSG_HEADER_V0_MSG_LEN_MASK			0x7FF
#define HINIC5_MSG_HEADER_V1_MSG_LEN_MASK			0x1FF
#define HINIC5_MSG_HEADER_V0_MODULE_MASK			0x1F
#define HINIC5_MSG_HEADER_V1_MODULE_MASK			0x3F
#define HINIC5_MSG_HEADER_V0_SEG_LEN_MASK			0x3F
#define HINIC5_MSG_HEADER_V1_SEG_LEN_MASK			0xF
#define HINIC5_MSG_HEADER_NO_ACK_MASK			0x1
#define HINIC5_MSG_HEADER_DATA_TYPE_MASK		0x1
#define HINIC5_MSG_HEADER_SEQID_MASK			0x3F
#define HINIC5_MSG_HEADER_LAST_MASK			0x1
#define HINIC5_MSG_HEADER_DIRECTION_MASK		0x1

#define HINIC5_MSG_HEADER_GET(val, field)	\
		(((val) >> HINIC5_MSG_HEADER_##field##_SHIFT) & \
		 HINIC5_MSG_HEADER_##field##_MASK)
#define HINIC5_MSG_HEADER_SET(val, field)	\
		((u64)(((u64)(val)) & HINIC5_MSG_HEADER_##field##_MASK) << \
		 HINIC5_MSG_HEADER_##field##_SHIFT)

#define HINIC5_MSG_HEADER_GET_V0(val, field)	\
	(((val) >> HINIC5_MSG_HEADER_V0_##field##_SHIFT) & \
	 HINIC5_MSG_HEADER_V0_##field##_MASK)
#define HINIC5_MSG_HEADER_SET_V0(val, field)	\
	((u64)(((u64)(val)) & HINIC5_MSG_HEADER_V0_##field##_MASK) << \
	 HINIC5_MSG_HEADER_V0_##field##_SHIFT)

#define HINIC5_MSG_HEADER_GET_V1(val, field)	\
	(((val) >> HINIC5_MSG_HEADER_V1_##field##_SHIFT) & \
	 HINIC5_MSG_HEADER_V1_##field##_MASK)
#define HINIC5_MSG_HEADER_SET_V1(val, field)	\
	((u64)(((u64)(val)) & HINIC5_MSG_HEADER_V1_##field##_MASK) << \
	 HINIC5_MSG_HEADER_V1_##field##_SHIFT)

enum hinic5_msg_direction_type {
	HINIC5_MSG_DIRECT_SEND	= 0,
	HINIC5_MSG_RESPONSE	= 1,
};

enum hinic5_msg_segment_type {
	NOT_LAST_SEGMENT	= 0,
	LAST_SEGMENT		= 1,
};

enum hinic5_msg_ack_type {
	HINIC5_MSG_ACK,
	HINIC5_MSG_NO_ACK,
};

enum hinic5_data_type {
	HINIC5_DATA_INLINE	= 0,
	HINIC5_DATA_DMA		= 1,
};

enum hinic5_msg_src_type {
	HINIC5_MSG_FROM_MGMT	= 0,
	HINIC5_MSG_FROM_MBOX	= 1,
};

enum hinic5_msg_aeq_type {
	HINIC5_ASYNC_MSG_AEQ	= 0,
	/* indicate dest func or mgmt cpu which aeq to response mbox message */
	HINIC5_MBOX_RSP_MSG_AEQ	= 1,
	/* indicate mgmt cpu which aeq to response api cmd message */
	HINIC5_MGMT_RSP_MSG_AEQ	= 2,
};

#define HINIC5_MBOX_WQ_NAME	"hinic5_mbox"

struct mbox_msg_info {
	u64 header;
	u8 msg_id;
	u8 status; /* can only use 1 bit */
};

struct hinic5_msg_desc {
	void			*msg;
	u16			msg_len;
	u8			seq_id;
	u8			mod;
	u16			cmd;
	struct mbox_msg_info	msg_info;
};

struct hinic5_msg_channel {
	struct hinic5_msg_desc	resp_msg;
	struct hinic5_msg_desc	recv_msg;

	atomic_t		recv_msg_cnt;
};

/* Receive other functions mbox message */
struct hinic5_recv_mbox {
	void *msg;
	u16			msg_len;
	u8			msg_id;
	u8			mod;
	u16			cmd;
	u16			src_func_idx;

	enum hinic5_msg_ack_type ack_type;
	u32			rsvd1;

	void *resp_buff;
};

struct hinic5_send_mbox {
	u8			*data;

	u64			*wb_status; /* write back status */
	void			*wb_vaddr;
	dma_addr_t		wb_paddr;
};

enum mbox_event_state {
	EVENT_START = 0,
	EVENT_FAIL,
	EVENT_SUCCESS,
	EVENT_TIMEOUT,
	EVENT_END,
};

enum hinic5_mbox_cb_state {
	HINIC5_VF_MBOX_CB_REG = 0,
	HINIC5_VF_MBOX_CB_RUNNING,
	HINIC5_PF_MBOX_CB_REG,
	HINIC5_PF_MBOX_CB_RUNNING,
	HINIC5_PPF_MBOX_CB_REG,
	HINIC5_PPF_MBOX_CB_RUNNING,
	HINIC5_PPF_TO_PF_MBOX_CB_REG,
	HINIC5_PPF_TO_PF_MBOX_CB_RUNNIG,
};

struct mbox_dma_msg {
	u32		xor;
	u32		dma_addr_high;
	u32		dma_addr_low;
	u32		msg_len;
	u64		rsvd;
};

struct mbox_dma_queue {
	void			*dma_buff_vaddr;
	dma_addr_t		dma_buff_paddr;

	u16			depth;
	u16			prod_idx;
	u16			cons_idx;
};

struct hinic5_mbox {
	struct hinic5_hwdev	*hwdev;

	bool			lock_channel_en;
	ulong		channel_stop;
	u16			cur_msg_channel;
	u32			rsvd1;

	/* lock for send mbox message and ack message */
	struct mutex		mbox_send_lock;
	/* lock for send mbox message */
	struct mutex		msg_send_lock;
	struct hinic5_send_mbox	send_mbox;

	struct mbox_dma_queue	sync_msg_queue;
	struct mbox_dma_queue	async_msg_queue;

	struct workqueue_struct	*workq;

	struct hinic5_msg_channel mgmt_msg; /* driver and MGMT CPU */
	struct hinic5_msg_channel *host_msg; /* PPF message between hosts */
	struct hinic5_msg_channel *func_msg; /* PF to VF or VF to PF */
	u16			num_func_msg;
	bool			support_h2h_msg; /* host to host */

	/* vf receive pf/ppf callback */
	hinic5_vf_mbox_cb	vf_mbox_cb[HINIC5_MOD_MAX];
	void			*vf_mbox_data[HINIC5_MOD_MAX];
	/* pf/ppf receive vf callback */
	hinic5_pf_mbox_cb	pf_mbox_cb[HINIC5_MOD_MAX];
	void			*pf_mbox_data[HINIC5_MOD_MAX];
	/* ppf receive pf/ppf callback */
	hinic5_ppf_mbox_cb	ppf_mbox_cb[HINIC5_MOD_MAX];
	void			*ppf_mbox_data[HINIC5_MOD_MAX];
	/* pf receive ppf callback */
	hinic5_pf_recv_from_ppf_mbox_cb	pf_recv_ppf_mbox_cb[HINIC5_MOD_MAX];
	void			*pf_recv_ppf_mbox_data[HINIC5_MOD_MAX];
	ulong		ppf_to_pf_mbox_cb_state[HINIC5_MOD_MAX];
	ulong		ppf_mbox_cb_state[HINIC5_MOD_MAX];
	ulong		pf_mbox_cb_state[HINIC5_MOD_MAX];
	ulong		vf_mbox_cb_state[HINIC5_MOD_MAX];

	u8			send_msg_id;
	u8			rsvd2;
	u16			rsvd3;
	enum mbox_event_state	event_flag;
	/* lock for mbox event flag */
	spinlock_t		mbox_lock;
	u64			rsvd4;
};

struct hinic5_mbox_work {
	struct work_struct	work;
	struct hinic5_mbox	*func_to_func;
	struct hinic5_recv_mbox	*recv_mbox;
	struct hinic5_msg_channel *msg_ch;
};

struct vf_cmd_check_handle {
	u16 cmd;
	bool (*check_cmd)(struct hinic5_hwdev *hwdev, u16 src_func_idx,
			  void *buf_in, u16 in_size);
};

void hinic5_mbox_func_aeqe_handler(void *handle, u8 *header, u8 size);

bool hinic5_mbox_check_cmd_valid(struct hinic5_hwdev *hwdev,
				 struct vf_cmd_check_handle *cmd_handle,
				 u16 vf_id, u16 cmd, void *buf_in, u16 in_size,
				 u8 size);

int hinic5_func_to_func_init(struct hinic5_hwdev *hwdev);

void hinic5_func_to_func_free(struct hinic5_hwdev *hwdev);

int hinic5_send_mbox_to_mgmt(struct hinic5_hwdev *hwdev, u8 mod, u16 cmd,
			     void *buf_in, u16 in_size, void *buf_out,
			     u16 *out_size, u32 timeout, u16 channel);

void hinic5_response_mbox_to_mgmt(struct hinic5_hwdev *hwdev, u8 mod, u16 cmd,
				  void *buf_in, u16 in_size, u16 msg_id);

int hinic5_send_mbox_to_mgmt_no_ack(struct hinic5_hwdev *hwdev, u8 mod, u16 cmd,
				    void *buf_in, u16 in_size, u16 channel);
int hinic5_mbox_to_func(struct hinic5_mbox *func_to_func, u8 mod, u16 cmd,
			u16 dst_func, void *buf_in, u16 in_size,
			void *buf_out, u16 *out_size, u32 timeout, u16 channel);

int hinic5_mbox_init_host_msg_channel(struct hinic5_hwdev *hwdev);

int hinic5_mbox_set_channel_status(struct hinic5_hwdev *hwdev, u16 channel,
				   bool enable);

void hinic5_mbox_enable_channel_lock(struct hinic5_hwdev *hwdev, bool enable);

void mbox_msg_header_set_last(u64 *header, u16 msg_len, u8 mod,
			      u16 seg_len, struct hinic5_hwdev *hwdev);
#define V0_MOD_ID_MAX 32
static inline u64 hinic5_mbox_set_msg_len(u8 version, u16 msg_len)
{
	if (version != 0)
		return HINIC5_MSG_HEADER_SET_V1(msg_len / MBOX_MSG_LEN_UNIT, MSG_LEN);
	else
		return HINIC5_MSG_HEADER_SET_V0(msg_len, MSG_LEN);
}

static inline u16 hinic5_mbox_get_msg_len(u8 version, u64 *header)
{
	if (version != 0)
		return (u16)(HINIC5_MSG_HEADER_GET_V1(*header, MSG_LEN) * MBOX_MSG_LEN_UNIT);
	else
		return HINIC5_MSG_HEADER_GET_V0(*header, MSG_LEN);
}

static inline u64 hinic5_mbox_set_seg_len(u8 version, u16 seg_len)
{
	if (version != 0)
		return HINIC5_MSG_HEADER_SET_V1(seg_len / MBOX_SEG_LEN_UNIT, SEG_LEN);
	else
		return HINIC5_MSG_HEADER_SET_V0(seg_len, SEG_LEN);
}

static inline u8 hinic5_mbox_get_seg_len(u8 version, const u64 *header)
{
	if (version != 0)
		return (u8)(HINIC5_MSG_HEADER_GET_V1(*header, SEG_LEN) * MBOX_SEG_LEN_UNIT);
	else
		return HINIC5_MSG_HEADER_GET_V0(*header, SEG_LEN);
}

static inline u64 hinic5_mbox_set_mod_id(u8 version, u8 mod)
{
	if (version != 0)
		return HINIC5_MSG_HEADER_SET_V1(mod, MODULE);
	else
		return HINIC5_MSG_HEADER_SET_V0(mod, MODULE);
}

static inline u8 hinic5_mbox_get_mod_id(u8 version, const u64 *header)
{
	if (version != 0)
		return HINIC5_MSG_HEADER_GET_V1(*header, MODULE);
	else
		return HINIC5_MSG_HEADER_GET_V0(*header, MODULE);
}

static inline u64 hinic5_mbox_set_version(u8 version)
{
	if (version != 0)
		return HINIC5_MSG_HEADER_SET(MPU_MAILBOX_HEADER_VER_1, VERSION);
	else
		return HINIC5_MSG_HEADER_SET(MPU_MAILBOX_HEADER_VER_0, VERSION);
}

static inline u8 hinic5_mbox_get_version(const struct hinic5_hwdev *hwdev, const u64 *header)
{
	return HINIC5_MSG_HEADER_GET(*header, VERSION);
}

#define MBOX_SEGLEN_MASK_V0			\
	HINIC5_MSG_HEADER_SET_V0(HINIC5_MSG_HEADER_V0_SEG_LEN_MASK, SEG_LEN)
#define MBOX_SEGLEN_MASK_V1			\
	HINIC5_MSG_HEADER_SET_V1(HINIC5_MSG_HEADER_V1_SEG_LEN_MASK, SEG_LEN)

static inline u64 hinic5_mbox_get_seg_len_mask(u8 version)
{
	if (version != 0)
		return MBOX_SEGLEN_MASK_V1;
	else
		return MBOX_SEGLEN_MASK_V0;
}

static inline u8 hinic5_mbox_get_send_version(const struct hinic5_hwdev *hwdev, u8 mod)
{
	if (COMM_SUPPORT_MBOX_HEAD_VER1(hwdev) && mod >= V0_MOD_ID_MAX)
		return MPU_MAILBOX_HEADER_VER_1;
	return MPU_MAILBOX_HEADER_VER_0;
}

#endif

