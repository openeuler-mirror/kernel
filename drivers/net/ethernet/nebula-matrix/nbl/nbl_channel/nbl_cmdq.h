/* SPDX-License-Identifier: GPL-2.0 */
/* Nebula-matrix DPDK user-network
 * Copyright(c) 2021-2030 nBL, Inc.
 */
#ifndef _NBL_CMDQ_H
#define _NBL_CMDQ_H

#include "nbl_channel.h"
#include "nbl_core.h"

#define NBL_CMDQ_HI_DWORD(x) ((u32)(((x) >> 32) & 0xFFFFFFFF))
#define NBL_CMDQ_LO_DWORD(x) ((u32)(x) & 0xFFFFFFFF)

#define NBL_CMDQ_TIMEOUT		100000
#define NBL_CMDQ_HALF_DESC_LENGTH	16
#define NBL_CMDQ_PARAM_BYTES		8
#define NBL_CMDQ_PARAM_HALF_BITS	32
/* command resend and reset */
#define NBL_CMDQ_RESEND_MAX_TIMES	3

/* initial value of descriptor */
#define NBL_CMDQ_DESC_FLAG_DD		BIT(0)
#define NBL_CMDQ_DESC_FLAG_ERR		BIT(1)
#define NBL_CMDQ_DESC_FLAG_BUF_IN	BIT(2)
#define NBL_CMDQ_DESC_FLAG_BUF_OUT	BIT(3)
#define NBL_CMDQ_DESC_FLAG_SI		BIT(4)
#define NBL_CMDQ_DESC_FLAG_EI		BIT(5)
#define NBL_CMDQ_DESC_FLAG_IF_ERR	BIT(6)
#define NBL_CMDQ_DESC_FLAG_HIT		BIT(7)
#define NBL_CMDQ_DESC_FLAG_IF_ERR_OFT	8
#define NBL_CMDQ_DESC_FLAG_IF_ERR_MASK	(0b11)
#define NBL_CMDQ_DESC_FLAG_DONE		BIT(15)

#define NBL_CMDQ_SQ_WAIT_USEC	1
#define NBL_CMDQ_WAIT_WARN	10
#define NBL_CMDQ_BUF_SIZE	256
#define NBL_CMDQ_RING_DEPTH	4096	/* max: 2^16 */
#define NBL_CMDQ_RQ_RING_DEPTH	4096	/* max: 2^15 */
#define NBL_CMDQ_DOORBELL_MASK	0x1FFFF
#define NBL_CMDQ_WAIT_DESC_US	50

enum nbl_cmdq_cmd_status {
	NBL_CMD_STATUS_HW_READY,
	NBL_CMD_STATUS_SW_READY,
	NBL_CMD_STATUS_HW_ERROR,
	NBL_CMD_STATUS_CLEAN_READY,
};

enum nbl_cmdq_cmd_type {
	NBL_CMD_TYPE_BARE,
	NBL_CMD_TYPE_HW_R,
	NBL_CMD_TYPE_HW_W,
	NBL_CMD_TYPE_HW_RW,
};

enum nbl_cmdq_exe_status {
	NBL_CMD_EXE_STATUS_SUCCESS,
	NBL_CMD_EXE_STATUS_FAIL,
	NBL_CMD_EXE_STATUS_ERROR,
	NBL_CMD_EXE_STATUS_NOHIT,
};

enum nbl_cmdq_fem_fail_code {
	NBL_CMDQ_ERRCODE_KEY_FULL = 1,
	NBL_CMDQ_ERRCODE_KEY_MISS,
	NBL_CMDQ_ERRCODE_KT_PF_UNMATCH,
	NBL_CMDQ_ERRCODE_KT_INDEX,
	NBL_CMDQ_ERRCODE_NO_KT_BLK,
	NBL_CMDQ_ERRCODE_KT_UNMATCH = 7,
	NBL_CMDQ_ERRCODE_OFT_WRITE = 8,
};

enum nbl_draco_cmd_status {
	NBL_DRACO_CMD_SUCCESS,
	NBL_DRACO_CMD_FAIL,
	NBL_DRACO_CMD_ERROR,
	NBL_DRACO_CMD_NOHIT,
};

#define NBL_CMD_DESC_INTF_ERR_OFT 5
#define NBL_CMD_DESC_PRO_ERR_MASK 0b00011111

struct nbl_cmdq_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
};

/**
 * @brief: command ring, with pointers to ring/buffer memory
 * @dma_head:
 * @buffer:
 * @cmd_buf:
 */
struct nbl_cmd_ring {
	struct nbl_cmdq_dma_mem desc;		/* descriptor ring memory */
	struct nbl_cmdq_dma_mem in_mem;
	struct nbl_cmdq_dma_mem out_mem;
	struct nbl_cmdq_dma_mem *in_buffer_info;	/* buffer detail information */
	struct nbl_cmdq_dma_mem *out_buffer_info;	/* buffer detail information */
	void *in_buffer_dma_head;		/* buffer dma head */
	void *out_buffer_dma_head;		/* buffer dma head */

	u16 count;				/* count of descriptors */
	u16 next_to_use;
	u16 next_to_clean;

	/* only 17 bit valid for send queue, and 16 for receive queue */
	u32 doorbell;

	/* for queue tracking */
	u32 head;
	u32 tail;
	u32 len;
	u32 cmdq_enable;
	u32 cmdq_interrupt;
	u32 msgq_curr_rst;
	u32 msgq_interrupt;
	u32 msgq_enable;

	/* ring base address */
	u32 bah;
	u32 bal;
};

struct nbl_cmd_queue {
	struct nbl_cmd_ring sq_ring; /* command send queue */
	u16 sq_buf_size;
	u16 cmd_ring_depth;
	spinlock_t sq_lock;  /* used to lock the send queue */
	u32 sq_timeout;
	enum nbl_cmd_status sq_last_status;
	bool in_reset;

	struct nbl_channel_mgt *chan_mgt;
};

struct nbl_cmdq_mgt {
	struct nbl_cmd_queue cmd_queue;
	u16 cmdq_refcount;
};

#pragma pack(1)
/**
 * struct nbl_cmd_desc - Admin queue descriptor
 * @brief: admin queue descriptor, 32 Bytes
 * @flags: basic properties of the descriptor
 * @block: firmware divide the register tables into blocks, sections, tables
 * @module: same as above
 * @table: same as above
 * @opcode: add, delete, flush, update etc.
 * @errorcode: command error returned by the firmware
 * @datalen: valid length of the buffer
 * @param_high: and _low, optional parameters for the command
 * @recv_high: and _low, buffer address for receiving data
 * @send_high: and _low, buffer address for sending data
 */
struct nbl_cmd_desc {
	u32 flags:16;
	u32 block:5;
	u32 module:5;
	u32 table:4;
	u32 rsv:2;
	u32 opcode:8;
	u32 errorcode:8;
	u32 datalen:12;
	u32 seq:4;
	u32 param_low;
	u32 param_high;
	u32 recv_low;
	u32 recv_high;
	u32 send_low;
	u32 send_high;
};

struct nbl_draco_cmd_desc {
	u32 cmd_status:2;
	u32 cmd_type:2;
	u32 si:1;
	u32 rsv0:11;
	u32 module:4;
	u32 table:4;
	u32 opcode:4;
	u32 rsv1:4;
	u32 errcode:8;
	u32 exe_status:2;
	u32 rsv2:6;
	u32 cmd_len:8;
	u32 rsv3:8;
	u32 param_low;
	u32 param_high;
	u32 recv_low; /* hardware writeback */
	u32 recv_high;
	u32 send_low; /* hardware read */
	u32 send_high;
};

union nbl_cmdq_notify_val {
	struct {
		u16 qid:2;
		u16 rsv:14;
		u16 tail_ptr;
	} info;

	u32 value;
};

struct nbl_cmd_rq_desc {
	u32 head_data;
	u32 contents[7];
};

struct nbl_cmd_rq_desc_age {
	u32 start_offset:17;
	u32 reserved0:15;
	u32 bitmap0;
	u32 bitmap1;
	u32 bitmap2;
	u32 bitmap3;
	u32 reserved1;
	u32 reserved2;
};

#pragma pack()

#define NBL_CMDQ_GET_DESC(ring, index)	\
	(&(((struct nbl_cmd_desc *)((ring).desc.va))[index]))
#define NBL_DRACO_CMDQ_GET_DESC(ring, index)	\
	(&(((struct nbl_draco_cmd_desc *)((ring).desc.va))[index]))

#define NBL_CMDQ_GET_RQ_DESC(ring, index)	\
	(&(((struct nbl_cmd_rq_desc *)((ring).desc.va))[(index) + 1]))

int nbl_chan_cmdq_mgt_start(struct device *dev, void *priv);
int nbl_chan_cmdq_mgt_stop(struct device *dev, void *priv, u8 inst_id);
int nbl_chan_send_cmdq(void *priv, const void *hdr, void *cmd);

# endif  /* _NBL_CMDQ_H */
