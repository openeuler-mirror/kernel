/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPHW_MBOX_H
#define SPHW_MBOX_H

#include "sphw_crm.h"

#define SPHW_MBOX_PF_SEND_ERR				0x1

#define SPHW_MGMT_SRC_ID				0x1FFF
#define SPHW_MAX_FUNCTIONS				4096

/* message header define */
#define SPHW_MSG_HEADER_SRC_GLB_FUNC_IDX_SHIFT		0
#define SPHW_MSG_HEADER_STATUS_SHIFT			13
#define SPHW_MSG_HEADER_SOURCE_SHIFT			15
#define SPHW_MSG_HEADER_AEQ_ID_SHIFT			16
#define SPHW_MSG_HEADER_MSG_ID_SHIFT			18
#define SPHW_MSG_HEADER_CMD_SHIFT			22

#define SPHW_MSG_HEADER_MSG_LEN_SHIFT			32
#define SPHW_MSG_HEADER_MODULE_SHIFT			43
#define SPHW_MSG_HEADER_SEG_LEN_SHIFT			48
#define SPHW_MSG_HEADER_NO_ACK_SHIFT			54
#define SPHW_MSG_HEADER_DATA_TYPE_SHIFT			55
#define SPHW_MSG_HEADER_SEQID_SHIFT			56
#define SPHW_MSG_HEADER_LAST_SHIFT			62
#define SPHW_MSG_HEADER_DIRECTION_SHIFT			63

#define SPHW_MSG_HEADER_SRC_GLB_FUNC_IDX_MASK		0x1FFF
#define SPHW_MSG_HEADER_STATUS_MASK			0x1
#define SPHW_MSG_HEADER_SOURCE_MASK			0x1
#define SPHW_MSG_HEADER_AEQ_ID_MASK			0x3
#define SPHW_MSG_HEADER_MSG_ID_MASK			0xF
#define SPHW_MSG_HEADER_CMD_MASK			0x3FF

#define SPHW_MSG_HEADER_MSG_LEN_MASK			0x7FF
#define SPHW_MSG_HEADER_MODULE_MASK			0x1F
#define SPHW_MSG_HEADER_SEG_LEN_MASK			0x3F
#define SPHW_MSG_HEADER_NO_ACK_MASK			0x1
#define SPHW_MSG_HEADER_DATA_TYPE_MASK			0x1
#define SPHW_MSG_HEADER_SEQID_MASK			0x3F
#define SPHW_MSG_HEADER_LAST_MASK			0x1
#define SPHW_MSG_HEADER_DIRECTION_MASK			0x1

#define SPHW_MSG_HEADER_GET(val, field)	\
		(((val) >> SPHW_MSG_HEADER_##field##_SHIFT) & \
		 SPHW_MSG_HEADER_##field##_MASK)
#define SPHW_MSG_HEADER_SET(val, field)	\
		((u64)(((u64)(val)) & SPHW_MSG_HEADER_##field##_MASK) << \
		 SPHW_MSG_HEADER_##field##_SHIFT)

#define IS_DMA_MBX_MSG(dst_func)	((dst_func) == SPHW_MGMT_SRC_ID)

enum sphw_msg_direction_type {
	SPHW_MSG_DIRECT_SEND	= 0,
	SPHW_MSG_RESPONSE	= 1,
};

enum sphw_msg_segment_type {
	NOT_LAST_SEGMENT	= 0,
	LAST_SEGMENT		= 1,
};

enum sphw_msg_ack_type {
	SPHW_MSG_ACK,
	SPHW_MSG_NO_ACK,
};

enum sphw_data_type {
	SPHW_DATA_INLINE	= 0,
	SPHW_DATA_DMA		= 1,
};

enum sphw_msg_src_type {
	SPHW_MSG_FROM_MGMT	= 0,
	SPHW_MSG_FROM_MBOX	= 1,
};

enum sphw_msg_aeq_type {
	SPHW_ASYNC_MSG_AEQ	= 0,
	/* indicate dest func or mgmt cpu which aeq to response mbox message */
	SPHW_MBOX_RSP_MSG_AEQ	= 1,
	/* indicate mgmt cpu which aeq to response api cmd message */
	SPHW_MGMT_RSP_MSG_AEQ	= 2,
};

#define SPHW_MBOX_WQ_NAME	"sphw_mbox"

enum sphw_mbox_seg_errcode {
	MBOX_ERRCODE_NO_ERRORS		= 0,
	/* VF send the mailbox data to the wrong destination functions */
	MBOX_ERRCODE_VF_TO_WRONG_FUNC	= 0x100,
	/* PPF send the mailbox data to the wrong destination functions */
	MBOX_ERRCODE_PPF_TO_WRONG_FUNC	= 0x200,
	/* PF send the mailbox data to the wrong destination functions */
	MBOX_ERRCODE_PF_TO_WRONG_FUNC	= 0x300,
	/* The mailbox data size is set to all zero */
	MBOX_ERRCODE_ZERO_DATA_SIZE	= 0x400,
	/* The sender function attribute has not been learned by hardware */
	MBOX_ERRCODE_UNKNOWN_SRC_FUNC	= 0x500,
	/* The receiver function attr has not been learned by hardware */
	MBOX_ERRCODE_UNKNOWN_DES_FUNC	= 0x600,
};

struct mbox_msg_info {
	u8 msg_id;
	u8 status;	/* can only use 1 bit */
};

struct sphw_msg_desc {
	void			*msg;
	u16			msg_len;
	u8			seq_id;
	u8			mod;
	u16			cmd;
	struct mbox_msg_info	msg_info;
};

struct sphw_msg_channel {
	struct sphw_msg_desc	resp_msg;
	struct sphw_msg_desc	recv_msg;

	atomic_t		recv_msg_cnt;
};

/* Receive other functions mbox message */
struct sphw_recv_mbox {
	void			*msg;
	u16			msg_len;
	u8			msg_id;
	u8			mod;
	u16			cmd;
	u16			src_func_idx;
	enum sphw_msg_ack_type	ack_type;
	void			*resp_buff;
};

struct sphw_send_mbox {
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

enum sphw_mbox_cb_state {
	SPHW_VF_MBOX_CB_REG = 0,
	SPHW_VF_MBOX_CB_RUNNING,
	SPHW_PF_MBOX_CB_REG,
	SPHW_PF_MBOX_CB_RUNNING,
	SPHW_PPF_MBOX_CB_REG,
	SPHW_PPF_MBOX_CB_RUNNING,
	SPHW_PPF_TO_PF_MBOX_CB_REG,
	SPHW_PPF_TO_PF_MBOX_CB_RUNNIG,
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

struct sphw_mbox {
	struct sphw_hwdev	*hwdev;

	bool			lock_channel_en;
	unsigned long		channel_stop;
	u16			cur_msg_channel;

	/* lock for send mbox message and ack message */
	struct mutex		mbox_send_lock;
	/* lock for send mbox message */
	struct mutex		msg_send_lock;
	struct sphw_send_mbox	send_mbox;

	struct mbox_dma_queue	sync_msg_queue;
	struct mbox_dma_queue	async_msg_queue;

	struct workqueue_struct	*workq;

	struct sphw_msg_channel mgmt_msg;	/* driver and MGMT CPU */
	struct sphw_msg_channel *host_msg;	/* PPF message between hosts */
	struct sphw_msg_channel *func_msg;	/* PF to VF or VF to PF */
	u16			num_func_msg;
	bool			support_h2h_msg; /* host to host */

	/* vf receive pf/ppf callback */
	sphw_vf_mbox_cb		vf_mbox_cb[SPHW_MOD_MAX];
	void			*vf_mbox_data[SPHW_MOD_MAX];
	/* pf/ppf receive vf callback */
	sphw_pf_mbox_cb		pf_mbox_cb[SPHW_MOD_MAX];
	void			*pf_mbox_data[SPHW_MOD_MAX];
	/* ppf receive pf/ppf callback */
	sphw_ppf_mbox_cb	ppf_mbox_cb[SPHW_MOD_MAX];
	void			*ppf_mbox_data[SPHW_MOD_MAX];
	/* pf receive ppf callback */
	sphw_pf_recv_from_ppf_mbox_cb	pf_recv_ppf_mbox_cb[SPHW_MOD_MAX];
	void			*pf_recv_ppf_mbox_data[SPHW_MOD_MAX];
	unsigned long		ppf_to_pf_mbox_cb_state[SPHW_MOD_MAX];
	unsigned long		ppf_mbox_cb_state[SPHW_MOD_MAX];
	unsigned long		pf_mbox_cb_state[SPHW_MOD_MAX];
	unsigned long		vf_mbox_cb_state[SPHW_MOD_MAX];

	u8			send_msg_id;
	enum mbox_event_state	event_flag;
	/* lock for mbox event flag */
	spinlock_t		mbox_lock;
};

struct sphw_mbox_work {
	struct work_struct	work;
	struct sphw_mbox	*func_to_func;
	struct sphw_recv_mbox	*recv_mbox;
	struct sphw_msg_channel *msg_ch;
};

struct vf_cmd_check_handle {
	u16 cmd;
	bool (*check_cmd)(struct sphw_hwdev *hwdev, u16 src_func_idx,
			  void *buf_in, u16 in_size);
};

void sphw_mbox_func_aeqe_handler(void *handle, u8 *header, u8 size);

int sphw_func_to_func_init(struct sphw_hwdev *hwdev);

void sphw_func_to_func_free(struct sphw_hwdev *hwdev);

int sphw_send_mbox_to_mgmt(struct sphw_hwdev *hwdev, u8 mod, u16 cmd,
			   void *buf_in, u16 in_size, void *buf_out,
			   u16 *out_size, u32 timeout, u16 channel);

void sphw_response_mbox_to_mgmt(struct sphw_hwdev *hwdev, u8 mod, u16 cmd,
				void *buf_in, u16 in_size, u16 msg_id);

int sphw_send_mbox_to_mgmt_no_ack(struct sphw_hwdev *hwdev, u8 mod, u16 cmd,
				  void *buf_in, u16 in_size, u16 channel);
int sphw_mbox_to_func(struct sphw_mbox *func_to_func, u8 mod, u16 cmd,
		      u16 dst_func, void *buf_in, u16 in_size,
		      void *buf_out, u16 *out_size, u32 timeout, u16 channel);

int sphw_mbox_ppf_to_host(void *hwdev, u8 mod, u16 cmd, u8 host_id,
			  void *buf_in, u16 in_size, void *buf_out,
			  u16 *out_size, u32 timeout, u16 channel);

int sphw_mbox_init_host_msg_channel(struct sphw_hwdev *hwdev);

void sphw_mbox_enable_channel_lock(struct sphw_hwdev *hwdev, bool enable);

#endif
