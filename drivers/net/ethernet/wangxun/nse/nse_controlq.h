/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_CONTROLQ_H_
#define _NSE_CONTROLQ_H_

#include <linux/list.h>
#include <linux/spinlock.h>
#include "nse_adminq_cmd.h"

/* Maximum buffer lengths for all control queue types */
#define NSE_AQ_MAX_BUF_LEN 4096
#define NSE_MBXQ_MAX_BUF_LEN 4096

#define NSE_CTLQ_SQ_SEND_CMD_FLAG_NO_WAIT		0x1

#define NSE_CTL_Q_DESC(R, i) \
	(&(((struct nse_aq_desc *)((R).desc_buf.va))[i]))

#define NSE_CTL_Q_DESC_UNUSED(R) \
	((u16)((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->count) + \
	       (R)->next_to_clean - (R)->next_to_use - 1))

/* Different control queue types: These are mainly for SW consumption. */
enum nse_ctl_q {
	NSE_CTL_Q_UNKNOWN = 0,
	NSE_CTL_Q_ADMIN,
	NSE_CTL_Q_MAILBOX,
	NSE_CTL_Q_UTIL,		/* utilq for fdir programming */
};

/* Control Queue timeout settings - max delay (20000 x 100) = 2000 000 usec = 2 s */
#define NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE	20000	/* Count 20000 times */
#define NSE_CTL_Q_SQ_CMD_USEC			100    /* Check every 100 usec */

#define NSE_CTL_Q_ADMIN_INIT_TIMEOUT	10    /* Count 10 times */
#define NSE_CTL_Q_ADMIN_INIT_MSEC	100   /* Check every 100msec */

struct nse_ctl_q_ring {
	void *dma_head;			/* Virtual address to DMA head */
	struct nse_dma_mem desc_buf;	/* descriptor ring memory */
	void *cmd_buf;			/* command buffer memory */

	union {
		struct nse_dma_mem *sq_bi;
		struct nse_dma_mem *rq_bi;
	} r;

	u16 count;		/* Number of descriptors */

	/* used for interrupt processing */
	u16 next_to_use;
	u16 next_to_clean;

	/* used for queue tracking */
	u32 head;
	u32 tail;
	u32 len;
	u32 bah;
	u32 bal;
	u32 len_mask;
	u32 len_crit_mask;
	u32 head_mask;
};

/* sq transaction details */
struct nse_sq_cd {
	struct nse_aq_desc *wb_desc;
};

#define NSE_CTL_Q_DETAILS(R, i) (&(((struct nse_sq_cd *)((R).cmd_buf))[i]))

/* rq event information */
struct nse_rq_event_info {
	struct nse_aq_desc desc;
	u16 msg_len;
	u16 buf_len;
	u8 *msg_buf;

	u32 src;	/* 0 from aq, 1 from msgbox(V2P) */
#define NSE_RQ_EVENT_INFO_SRC_AQ		0
#define NSE_RQ_EVENT_INFO_SRC_MSGBOX	1

	struct list_head list;	/* linked into rq_evt_list */
};

/* Control Queue (AQM-Q) information */
struct nse_ctl_q_info {
	enum nse_ctl_q qtype;
	struct nse_ctl_q_ring rq;	/* receive queue */
	struct nse_ctl_q_ring sq;	/* send queue */
	u32 sq_cmd_timeout;		/* send queue cmd write back timeout */
	u16 num_rq_entries;		/* receive queue depth */
	u16 num_sq_entries;		/* send queue depth */
	u16 rq_buf_size;		/* receive queue buffer size */
	u16 sq_buf_size;		/* send queue buffer size */
	enum nse_aq_err sq_last_status;	/* last status on send queue */

	struct mutex sq_lock;		/* Send queue lock */

	union {
		struct mutex mtx;
		spinlock_t spl;
	} rq_lock;					/* Receive queue lock - mutex or spinlock */

	struct list_head rq_evt_list;
	spinlock_t rq_evt_list_lock;
};

#define NSE_SHUTDOWN_CTLQ_FLAG_WAIT_FW_SHUTDOWN		0x1

#endif /* _NSE_CONTROLQ_H_ */

