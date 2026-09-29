/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSEVF_ADMINQ_H_
#define _NSEVF_ADMINQ_H_

#include "nsevf_osdep.h"
#include "nsevf_status.h"
#include "nsevf_adminq_cmd.h"

#define NSEVF_AQM_Q_DESC(R, i) \
	(&(((struct nsevf_aq_desc *)((R).desc_buf.va))[i]))

#define NSEVF_AQM_Q_DESC_ALIGNMENT 4096

struct nsevf_ctl_q_ring {
	struct nsevf_virt_mem dma_head; /* space for dma structures */
	struct nsevf_dma_mem desc_buf; /* descriptor ring memory */
	struct nsevf_virt_mem cmd_buf; /* command buffer memory */

	union {
		struct nsevf_dma_mem *asq_bi;
		struct nsevf_dma_mem *arq_bi;
	} r;

	u16 count; /* Number of descriptors */
	u16 rx_buf_len; /* Admin Receive Queue buffer length */

	/* used for interrupt processing */
	u16 next_to_use;
	u16 next_to_clean;

	/* used for queue tracking */
	u32 head;
	u32 tail;
	u32 len;
	u32 bah;
	u32 bal;
};

/* ASQ transaction details */
struct nsevf_asq_cmd_details {
	void *callback; /* cast from type NSEVF_ADMINQ_CALLBACK */
	u16 flags_ena;
	u16 flags_dis;
	bool async;
	bool postpone;
	struct nsevf_aq_desc *wb_desc;
};

#define NSEVF_AQM_Q_DETAILS(R, i) \
	(&(((struct nsevf_asq_cmd_details *)((R).cmd_buf.va))[i]))

/* ARQ event information */
struct nsevf_arq_event_info {
	struct nsevf_aq_desc desc;
	u16 msg_len;
	u16 buf_len;
	u8 *msg_buf; /* expect beginning is v_hdr (struct nse_aqc_mbx_cmd_buff_hdr) */
	u8 *vch_msg_content; /* always set to be (msg_buf + sizeof(v_hdr) */
	u16 vch_msg_len; /* msg_len - sizeof(v_hdr) */

	u16 msg_type; /* response or event */
};

/* Different control queue types: These are mainly for SW consumption. */
enum nsevf_ctl_q {
	NSEVF_CTL_Q_UNKNOWN = 0,
	NSEVF_CTL_Q_ADMIN,
	NSEVF_CTL_Q_MAILBOX,
	NSEVF_CTL_Q_UTIL, /* utilq for fdir programming */
};

/* Ctl Queue (AQM-Q) information */
struct nsevf_ctl_q_info {
	enum nsevf_ctl_q qtype;
	struct nsevf_ctl_q_ring arq; /* receive queue */
	struct nsevf_ctl_q_ring asq; /* send queue */
	u32 asq_cmd_timeout; /* send queue cmd write back timeout*/
	u16 num_arq_entries; /* receive queue depth */
	u16 num_asq_entries; /* send queue depth */
	u16 arq_buf_size; /* receive queue buffer size */
	u16 asq_buf_size; /* send queue buffer size */

	struct nsevf_spinlock asq_spinlock; /* Send queue spinlock */
	struct nsevf_spinlock arq_spinlock; /* Receive queue spinlock */

	/* last status values on send and receive queues */
	enum nse_aq_err asq_last_status;
	enum nse_aq_err arq_last_status;
};

/**
 * nsevf_aq_rc_to_posix - convert errors to user-land codes
 * @aq_ret: AdminQ handler error code can override aq_rc
 * @aq_rc: AdminQ firmware error code to convert
 **/
static inline int nsevf_aq_rc_to_posix(int aq_ret, int aq_rc)
{
	int aq_to_posix[] = {
		0, /* NSEVF_AQ_RC_OK */
		-EPERM, /* NSEVF_AQ_RC_EPERM */
		-ENOENT, /* NSEVF_AQ_RC_ENOENT */
		-ESRCH, /* NSEVF_AQ_RC_ESRCH */
		-EINTR, /* NSEVF_AQ_RC_EINTR */
		-EIO, /* NSEVF_AQ_RC_EIO */
		-ENXIO, /* NSEVF_AQ_RC_ENXIO */
		-E2BIG, /* NSEVF_AQ_RC_E2BIG */
		-EAGAIN, /* NSEVF_AQ_RC_EAGAIN */
		-ENOMEM, /* NSEVF_AQ_RC_ENOMEM */
		-EACCES, /* NSEVF_AQ_RC_EACCES */
		-EFAULT, /* NSEVF_AQ_RC_EFAULT */
		-EBUSY, /* NSEVF_AQ_RC_EBUSY */
		-EEXIST, /* NSEVF_AQ_RC_EEXIST */
		-EINVAL, /* NSEVF_AQ_RC_EINVAL */
		-ENOTTY, /* NSEVF_AQ_RC_ENOTTY */
		-ENOSPC, /* NSEVF_AQ_RC_ENOSPC */
		-EOPNOTSUPP, /* NSEVF_AQ_RC_ENOSYS */
		-ERANGE, /* NSEVF_AQ_RC_ERANGE */
		-EPIPE, /* NSEVF_AQ_RC_EFLUSHED */
		-ESPIPE, /* NSEVF_AQ_RC_BAD_ADDR */
		-EROFS, /* NSEVF_AQ_RC_EMODE */
		-EFBIG, /* NSEVF_AQ_RC_EFBIG */
	};

	/* aq_rc is invalid if AQ timed out */
	if (aq_ret == NSEVF_ERR_ADMIN_QUEUE_TIMEOUT)
		return -EAGAIN;

	if (!((u32)aq_rc < (sizeof(aq_to_posix) / sizeof((aq_to_posix)[0]))))
		return -ERANGE;

	return aq_to_posix[aq_rc];
}

/* general information */
#define NSEVF_AQ_LARGE_BUF 512

/* Control Queue timeout settings - max delay (20000 x 100) = 2000 000 usec = 2 s */
#define NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE 20000 /* Count 20000 times */
#define NSE_CTL_Q_SQ_CMD_USEC 100 /* Check every 100 usec */

void nsevf_fill_default_direct_cmd_desc(struct nsevf_aq_desc *desc,
					u8 opc_category, u8 opc_subcode);

void nsevf_aq_wait(unsigned int usec);

#define NSE_SHUTDOWN_CTLQ_FLAG_WAIT_FW_SHUTDOWN 0x1

#endif /* _NSEVF_ADMINQ_H_ */
