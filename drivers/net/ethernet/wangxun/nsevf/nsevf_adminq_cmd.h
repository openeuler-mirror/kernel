/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSEVF_ADMINQ_CMD_H_
#define _NSEVF_ADMINQ_CMD_H_

#include "nsevf_osdep.h"

struct nse_aq_desc {
	__le16 flags;
/* command flags and offsets */
#define NSE_AQ_FLAG_DD_S 0
#define NSE_AQ_FLAG_DD BIT(0)

#define NSE_AQ_FLAG_RETVAL_S 1
#define NSE_AQ_FLAG_RETVAL_M NSE_M(0x7F, 1)

#define NSE_AQ_FLAG_WB_S 8
#define NSE_AQ_FLAG_WB BIT(8)

#define NSE_AQ_FLAG_LB_S 9
#define NSE_AQ_FLAG_LB BIT(9)

#define NSE_AQ_FLAG_RD_S 10
#define NSE_AQ_FLAG_RD BIT(10)

#define NSE_AQ_FLAG_BUF_S 12
#define NSE_AQ_FLAG_BUF BIT(12)

#define NSE_AQ_FLAG_SI_S 13
#define NSE_AQ_FLAG_SI BIT(13)

#define NSE_AQ_FLAG_EI_S 14
#define NSE_AQ_FLAG_EI BIT(14)

#define NSE_AQ_FLAG_FE_S 15
#define NSE_AQ_FLAG_FE BIT(15)

	union {
		__le16 opcode;
		struct {
			u8 opc_subcode;
			u8 opc_category;
		};
	};
#define MAKE_AQC_OPCODE(category, subcode) (((category) << 8) | (subcode))

	__le16 datalen;

	__le16 mailbox_id; /* bits: 6.0-7.0 + 7.1~7.7(reserved) */
#define NSE_AQ_MAILBOX_ID_S 0
#define NSE_AQ_MAILBOX_ID_M NSE_M(0x1FF, 0)

#define NSE_AQ_MAILBOX_ID_VSI_MAX 0x100 /* MUST < 256 */

#define NSE_AQ_MAILBOX_ID_PF 0x100
#define NSE_AQ_MAILBOX_ID_FW 0x1FF

	union {
		__le32 addr_high;
		__le32 param0;
	};
	union {
		__le32 addr_low;
		__le32 param1;
	};
} __packed;

#define nsevf_aq_desc nse_aq_desc

/* FW defined boundary for a large buffer, 4k >= Large buffer > 512 bytes */
#define NSEVF_AQ_LG_BUF 512

/* error codes */
enum nse_aq_err {
	NSE_AQ_RC_OK = 0, /* Success */

	NSE_AQ_RC_EIO, /* I/O error */

	NSE_AQ_RC_EINVAL, /* Invalid argument */
	NSE_AQ_RC_ERANGE, /* Parameter out of range */

	NSE_AQ_RC_EPERM, /* Operation not permitted */
	NSE_AQ_RC_EFAULT, /* Bad address */

	NSE_AQ_RC_ENOENT, /* No such element */
	NSE_AQ_RC_EEXIST, /* Object already exists */

	NSE_AQ_RC_EAGAIN, /* Try again */
	NSE_AQ_RC_EBUSY, /* Device or resource busy */
	NSE_AQ_RC_ETIMEOUT = NSE_AQ_RC_EBUSY,

	NSE_AQ_RC_EINPROGRESS,

	NSE_AQ_RC_ENOMEM, /* Out of memory */
	NSE_AQ_RC_ENOSPC, /* No space left or allocation failure */

	NSE_AQ_RC_ENOTSUPP,
	NSE_AQ_RC_EBADOP = NSE_AQ_RC_ENOTSUPP,

	/*************************************
	 *
	 * the range [96 - 127] starting from here.
	 *
	 ***************************************/

	NSE_AQ_RC_EACCES_FW_IN_UPDATE = 127, /* FW live Update in progress */
};

enum nse_adminq_opc_category {
	NSE_AQ_OPC_CATEGORY_BASIC = 0x0,
	NSE_AQ_OPC_CATEGORY_COMM = 0x6,
};

enum nse_adminq_opc_category_basic_subcodes {
	NSE_AQ_OPC_Q_SHUTDOWN = 0x3,
};

enum nse_adminq_opc_category_comm_subcodes {
	NSE_AQ_OPC_SEND_MSG_TO_PF = 0x0,
	NSE_AQ_OPC_SEND_MSG_TO_VF = 0x1,
};

static inline bool nse_sq_cmd_is_no_wait(u8 opc_category, u8 opc_subcode)
{
	if (opc_category == NSE_AQ_OPC_CATEGORY_BASIC &&
	    opc_subcode == NSE_AQ_OPC_Q_SHUTDOWN)
		return true;

	return false;
}

extern u16 nse_aqc_opc_send_msg_to_vf;
extern u16 nse_aqc_opc_send_msg_to_pf;

struct nse_aqc_mbx_cmd_buff_hdr {
	__le32 cookie_high; /* used as vch: u32 v_opcode */
	__le32 cookie_low; /* used as vch: u32 v_retval */
} __packed;

struct nsevf_aqc_generic_common_hdr {
	u8 magic;

	u8 lan_channel_id;
	u8 lan_id;
	u8 lan_channel_pf_id;

	__le16 vsi_abs_id;
	u8 pcore_id;
	u8 pf_id_in_pcore;
} __packed;

#endif /* _NSEVF_ADMINQ_CMD_H_ */
