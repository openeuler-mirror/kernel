/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_CHANNEL_H_
#define _NBL_CHANNEL_H_

#include "nbl_core.h"

#define NBL_CHAN_MGT_TO_COMMON(chan_mgt)	((chan_mgt)->common)
#define NBL_CHAN_MGT_TO_DEV(chan_mgt)		NBL_COMMON_TO_DEV(NBL_CHAN_MGT_TO_COMMON(chan_mgt))
#define NBL_CHAN_MGT_TO_PHY_OPS_TBL(chan_mgt)	((chan_mgt)->phy_ops_tbl)
#define NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt)	(NBL_CHAN_MGT_TO_PHY_OPS_TBL(chan_mgt)->ops)
#define NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt)	(NBL_CHAN_MGT_TO_PHY_OPS_TBL(chan_mgt)->priv)
#define NBL_CHAN_MGT_TO_MAILBOX(chan_mgt)	((chan_mgt)->chan_info[NBL_CHAN_TYPE_MAILBOX])
#define NBL_CHAN_MGT_TO_ADMINQ(chan_mgt)	((chan_mgt)->chan_info[NBL_CHAN_TYPE_ADMINQ])
#define NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type)	((chan_mgt)->chan_info[chan_type])

#define NBL_CHAN_TX_RING_TO_DESC(tx_ring, i)							\
	(&(((union nbl_chan_tx_desc *)((tx_ring)->desc))[i]))
#define NBL_CHAN_RX_RING_TO_DESC(rx_ring, i)							\
	(&(((union nbl_chan_rx_desc *)((rx_ring)->desc))[i]))
#define NBL_CHAN_TX_RING_TO_BUF(tx_ring, i)  (&(((tx_ring)->buf)[i]))
#define NBL_CHAN_RX_RING_TO_BUF(rx_ring, i)  (&(((rx_ring)->buf)[i]))

#define NBL_CHAN_GET_INFO(chan_mgt, id)								\
({												\
	typeof(chan_mgt) _chan_mgt = (chan_mgt);						\
	((id) == NBL_CHAN_ADMINQ_FUNCTION_ID && NBL_CHAN_MGT_TO_ADMINQ(_chan_mgt) ?		\
		 NBL_CHAN_MGT_TO_ADMINQ(_chan_mgt) : NBL_CHAN_MGT_TO_MAILBOX(_chan_mgt));	\
})

#define NBL_CHAN_TX_WAIT_US				100
#define NBL_CHAN_TX_PFVF_WAIT_TIMES			100
#define NBL_CHAN_TX_PF2EMP_WAIT_TIMES			4000
#define NBL_CHAN_TX_PF2EMP_FIRST_REKICK_WAIT_TIMES	100

#define NBL_CHAN_TX_WAIT_ACK_US_MIN		100
#define NBL_CHAN_TX_WAIT_ACK_US_MAX		120
#define NBL_CHAN_TX_WAIT_ACK_TIMES		50000

#define NBL_CHAN_QUEUE_LEN			256
#define NBL_CHAN_BUF_LEN			4096

#define NBL_CHAN_TX_DESC_EMBEDDED_DATA_LEN	16
#define NBL_CHAN_RESEND_MAX_TIMES		(3)

#define NBL_CHAN_TX_DESC_AVAIL			BIT(0)
#define NBL_CHAN_TX_DESC_USED			BIT(1)
#define NBL_CHAN_RX_DESC_WRITE			BIT(1)
#define NBL_CHAN_RX_DESC_AVAIL			BIT(3)
#define NBL_CHAN_RX_DESC_USED			BIT(4)

#define NBL_CHAN_PFVF_ACK_WAIT_TIME		(1 * HZ)
#define NBL_CHAN_PF2EMP_ACK_WAIT_TIME		(2 * HZ)
/**
 * leonis PF1-PF3 driver need operate emp, it need forward to pf0, and then pf0
 * foward to emp. So thest message wait time need large (NBL_CHAN_TX_PF2EMP_WAIT_TIMES
 * +  NBL_CHAN_PFVF_ACK_WAIT_TIME)
 */
#define NBL_CHAN_PF_RELAY_EMP_ACK_WAIT_TIME	(4 * HZ)

#define __DESC_R_SELECT(desc, fld_leonis, fld_draco)			\
({									\
	typeof(desc) _desc = (desc);				\
	(!chan_info || chan_info->product_type == NBL_LEONIS_TYPE) ?	\
		(_desc)->NBL_NAME(fld_leonis) :				\
		(_desc)->draco.NBL_NAME(fld_draco);			\
})

#define DESC_R(desc, field)					\
({								\
	__DESC_R_SELECT(desc, field, field##_v2);		\
})

#define DESC_W(desc, field, val)					\
({									\
	typeof(val) _val = (val);					\
	typeof(desc) _desc = (desc);					\
	if (!chan_info || chan_info->product_type == NBL_LEONIS_TYPE)	\
		_desc->NBL_NAME(field) = _val;				\
	else								\
		_desc->draco.NBL_NAME(field##_v2) = _val;		\
})

/* adminq */
#define NBL_ADMINQ_QUEUE_LEN			256
#define NBL_ADMINQ_BUF_LEN			4096

#define NBL_CHAN_HANDLER_TBL_BUCKET_SIZE	512

enum {
	NBL_MB_RX_QID = 0,
	NBL_MB_TX_QID = 1,
};

enum {
	NBL_MBX_STATUS_IDLE = 0,
	NBL_MBX_STATUS_WAITING,
	NBL_MBX_STATUS_ACKD,
	NBL_MBX_STATUS_TIMEOUT,
};

struct nbl_chan_tx_param {
	enum nbl_chan_msg_type msg_type;
	void *arg;
	size_t arg_len;
	u16 dstid;
	u16 msgid;
};

struct nbl_chan_buf {
	void *va;
	dma_addr_t pa;
	size_t size;
};

union nbl_chan_tx_desc {
	struct {
		u16 flags;
		u16 srcid;
		u16 dstid;
		u16 data_len;
		u16 buf_len;
		u64 buf_addr;
		u16 msg_type;
		u8 data[16];
		u16 msgid;
		u8 rsv[26];
	} __packed;
	struct draco_chan_tx_desc {
		u16 flags_v2;
		u16 srcid_v2;
		u16 dstid_v2;
		u16 data_len_v2;
		u64 buf_addr_v2;
		u16 buf_len_v2;
		u16 msg_type_v2;
		u8 data_v2[16];
		u16 msgid_v2;
		u8 rsv_v2[26];
	} __packed draco;
} __packed;

union nbl_chan_rx_desc {
	struct {
		u16 flags;
		u32 buf_len;
		u16 buf_id;
		u64 buf_addr;
	} __packed;
	struct draco_chan_rx_desc {
		u16 flags_v2;
		u16 buf_id_v2;
		u32 buf_len_v2;
		u64 buf_addr_v2;
	} __packed draco;
} __packed;

struct nbl_chan_ring {
	void *desc;
	struct nbl_chan_buf *buf;

	u16 next_to_use;
	u16 tail_ptr;
	u16 next_to_clean;

	dma_addr_t dma;
};

#define NBL_CHAN_MSG_INDEX_MAX			64
#define NBL_CHAN_MSG_LOC_MAX			1024

union nbl_chan_msg_id {
	struct nbl_chan_msg_id_info {
		u16 index:6;
		u16 loc:10;
	} info;
	u16 id;
};

struct nbl_chan_waitqueue_head {
	struct wait_queue_head wait_queue;
	atomic_t status;
	char *ack_data;
	int acked;
	int ack_err;
	u16 ack_data_len;
	u16 need_waked;
	u16 msg_type;
	u8 msg_index;
};

struct nbl_chan_notify_userdev {
	DECLARE_BITMAP(msgtype, NBL_CHAN_MSG_MAILBOX_MAX);
	struct mutex lock; /* used to protect eventfd and shm_msg_ring */
	struct eventfd_ctx *eventfd;
	void *shm_msg_ring;
};

struct nbl_chan_info {
	struct nbl_chan_ring txq;
	struct nbl_chan_ring rxq;
	struct nbl_chan_waitqueue_head *wait;
	/* spinlock_t */
	spinlock_t txq_lock;

	struct work_struct *clean_task;

	u16 wait_head_index;

	u16 num_txq_entries;
	u16 num_rxq_entries;
	u16 txq_buf_size;
	u16 rxq_buf_size;

	u16 txq_reset_times;
	u16 rxq_reset_times;

	DECLARE_BITMAP(state, NBL_CHAN_STATE_NBITS);

	u8 chan_type;
	/* three consecutive failures will freeze the queue until recovery via debugfs */
	u8 failed_cnt;
	bool inited;

	enum nbl_product_type product_type;
};

struct nbl_chan_msg_node_data {
	nbl_chan_resp func;
	void *priv;
};

struct nbl_chan_translate_pending_msg {
	struct nbl_chan_send_info *msg;
	int ack_ret;
};

#define NBL_USERDEV_TRANSLATE_MAX	8
struct nbl_channel_mgt {
	struct nbl_common_info *common;
	struct nbl_phy_ops_tbl *phy_ops_tbl;
	struct nbl_chan_info *chan_info[NBL_CHAN_TYPE_MAX];
	struct nbl_cmdq_mgt *cmdq_mgt;
	struct nbl_chan_notify_userdev *notify;
	/* spinlock_t */
	spinlock_t translate_lock;
	struct nbl_chan_translate_pending_msg pend_msg[NBL_USERDEV_TRANSLATE_MAX];
	void *handle_hash_tbl;
};

/* Mgt structure for each product.
 * Every indivisual mgt must have the common mgt as its first member, and contains its unique
 * data structure in the reset of it.
 */
struct nbl_channel_mgt_common {
	struct nbl_channel_mgt chan_mgt;
};

#endif
