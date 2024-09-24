/* SPDX-License-Identifier: GPL-2.0*/
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

#define NBL_CHAN_TX_RING_TO_DESC(tx_ring, i) \
	(&(((struct nbl_chan_tx_desc *)((tx_ring)->desc))[i]))
#define NBL_CHAN_RX_RING_TO_DESC(rx_ring, i) \
	(&(((struct nbl_chan_rx_desc *)((rx_ring)->desc))[i]))
#define NBL_CHAN_TX_RING_TO_BUF(tx_ring, i)  (&(((tx_ring)->buf)[i]))
#define NBL_CHAN_RX_RING_TO_BUF(rx_ring, i)  (&(((rx_ring)->buf)[i]))

#define NBL_CHAN_TX_WAIT_US			100
#define NBL_CHAN_TX_REKICK_WAIT_TIMES		2000
#define NBL_CHAN_TX_WAIT_TIMES			10000

#define NBL_CHAN_TX_WAIT_ACK_US_MIN		100
#define NBL_CHAN_TX_WAIT_ACK_US_MAX		120
#define NBL_CHAN_TX_WAIT_ACK_TIMES		50000

#define NBL_CHAN_QUEUE_LEN			256
#define NBL_CHAN_BUF_LEN			4096

#define NBL_CHAN_TX_DESC_EMBEDDED_DATA_LEN	16
#define NBL_CHAN_RESEND_MAX_TIMES		(5)

#define NBL_CHAN_TX_DESC_AVAIL			BIT(0)
#define NBL_CHAN_TX_DESC_USED			BIT(1)
#define NBL_CHAN_RX_DESC_WRITE			BIT(1)
#define NBL_CHAN_RX_DESC_AVAIL			BIT(3)
#define NBL_CHAN_RX_DESC_USED			BIT(4)

#define NBL_CHAN_ACK_WAIT_TIME			(5 * HZ)

/* adminq */
#define NBL_ADMINQ_QUEUE_LEN			256
#define NBL_ADMINQ_BUF_LEN			4096

#define NBL_CHAN_HANDLER_TBL_BUCKET_SIZE	512

enum {
	NBL_MB_RX_QID = 0,
	NBL_MB_TX_QID = 1,
};

enum {
	NBL_MBX_STATUS_WAITING = 0,
	NBL_MBX_STATUS_TIMEOUT = -1,
};

struct nbl_chan_buf {
	void *va;
	dma_addr_t pa;
	size_t size;
};

struct nbl_chan_tx_desc {
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

struct nbl_chan_rx_desc {
	u16 flags;
	u32 buf_len;
	u16 buf_id;
	u64 buf_addr;
} __packed;

struct nbl_chan_ring {
	void *desc;
	struct nbl_chan_buf *buf;

	u16 next_to_use;
	u16 tail_ptr;
	u16 next_to_clean;

	dma_addr_t dma;
};

struct nbl_chan_waitqueue_head {
	struct wait_queue_head wait_queue;
	char *ack_data;
	int acked;
	int ack_err;
	u16 ack_data_len;
	u16 need_waked;
	u16 msg_type;
	u8 status;
};

struct nbl_chan_notify_userdev {
	DECLARE_BITMAP(msgtype, NBL_CHAN_MSG_MAILBOX_MAX);
	struct mutex lock; /* used to protect eventfd and shm_msg_ring */
	struct eventfd_ctx *eventfd;
	void *shm_msg_ring;
};

#define NBL_CHAN_KEEPALIVE_DEFAULT_TIMEOUT			(10 * HZ)
#define NBL_CHAN_KEEPALIVE_MAX_TIMEOUT				(1024 * HZ)
#define NBL_CHAN_KEEPALIVE_TIMEOUT_UPDATE_GAP			(10 * HZ)
#define NBL_CHAN_KEEPALIVE_TIMEOUT_UPDATE_THRESH		(3)

struct nbl_chan_keepalive_info {
	struct delayed_work keepalive_task;
	void *chan_mgt;
	u32 timeout;
	u16 keepalive_dest;
	u8 success_cnt;
	u8 fail_cnt;
};

struct nbl_chan_info {
	struct nbl_chan_ring txq;
	struct nbl_chan_ring rxq;
	struct nbl_chan_waitqueue_head *wait;
	/* spinlock_t */
	spinlock_t txq_lock;

	struct work_struct *clean_task;
	struct nbl_chan_keepalive_info keepalive;

	u16 num_txq_entries;
	u16 num_rxq_entries;
	u16 txq_buf_size;
	u16 rxq_buf_size;

	u16 txq_reset_times;
	u16 rxq_reset_times;

	DECLARE_BITMAP(state, NBL_CHAN_STATE_NBITS);

	u8 chan_type;
};

struct nbl_chan_msg_node_data {
	nbl_chan_resp func;
	void *priv;
};

struct nbl_channel_mgt {
	struct nbl_common_info *common;
	struct nbl_phy_ops_tbl *phy_ops_tbl;
	struct nbl_chan_info *chan_info[NBL_CHAN_TYPE_MAX];
	struct nbl_chan_notify_userdev *notify;
	void *handle_hash_tbl;
};

/* Mgt structure for each product.
 * Every indivisual mgt must have the common mgt as its first member, and contains its unique
 * data structure in the reset of it.
 */
struct nbl_channel_mgt_leonis {
	struct nbl_channel_mgt chan_mgt;
};

struct nbl_channel_mgt_bootis {
	struct nbl_channel_mgt chan_mgt;
};

#endif
