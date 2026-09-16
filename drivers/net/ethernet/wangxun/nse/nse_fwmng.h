/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_FWMNG_H
#define _NSE_FWMNG_H

#include <linux/types.h>

#include "nse_osdep.h"
#include "nse_type.h"

enum nse_fwmng_cmd_category {
	NSE_FWMNG_CMD_CATEGORY_LINK			= 0x0,

	NSE_FWMNG_CMD_CATEGORY_RNOC_ACCESS	= 0x1,

	NSE_FWMNG_CMD_CATEGORY_FLASH_CMD	= 0x2,

	NSE_FWMNG_CMD_CATEGORY_FLASH_DATA	= 0x3,

	NSE_FWMNG_CMD_CATEGORY_RESET		= 0x4,

	NSE_FWMNG_CMD_CATEGORY_EFUSE		= 0x5,

	NSE_FWMNG_CMD_CATEGORY_MISC			= 0x6,

	NSE_FWMNG_CMD_CATEGORY_MAX			= 0x7,
};

enum nse_fwmng_cmd_category_reset_subcodes {
	NSE_FWMNG_CMD_HIGH_RESET			= 0x0,

	NSE_FWMNG_CMD_AQM_ERROR				= 0x2,
};

enum nse_fwmng_cmd_category_misc_subcodes {
	NSE_FWMNG_CMD_EXT					= 0x0,

	NSE_FWMNG_CMD_TX_TS_EVT				= 0x1,
};

#define MAKE_FWMNG_CMD_CODE(category, subcode) (((category) << 4) | (subcode))

#define NSE_FWMNG_CMD_RESPONSE_FLAG	0x80	/* bit[7] of register: RSP */

#define NSE_FWMNG_CMD_REQ_RSP_GET_ID(regval)	((regval) & 0x7F)	/* 7 bits [0:6] */

extern u32 fwmng_cmd_id_high_reset;
extern u32 fwmng_evt_id_aqm_err;

struct nse_fwmng_cmd_req_generic {
	u32 cmd;
	u32 cmd_buf[4];
};

struct nse_fwmng_cmd_rsp_generic {
	u32 rsp;
	u32 rsp_buf[4];
};
#define NSE_FWMNG_STATUS_OK					0
#define NSE_FWMNG_STATUS_EXIST_OLD_RSP		1
#define NSE_FWMNG_STATUS_REQ_TIMEOUT		2
#define NSE_FWMNG_STATUS_RSP_TIMEOUT		3
#define NSE_FWMNG_STATUS_RSP_NOT_MATCH_REQ	4

#define NSE_FWMNG_FLAG_CHECK_OLD_RSP		BIT(0)
#define NSE_FWMNG_FLAG_WAIT_REQ				BIT(1)
#define NSE_FWMNG_FLAG_WAIT_RSP				BIT(2)
#define NSE_FWMNG_FLAG_CHECK_RSP_MATCH		BIT(3)

#define NSE_FWMNG_CLEAR_RSP_VALID_ONLY		BIT(0)
#define NSE_FWMNG_CLEAR_RSP_ONLY			BIT(1)
#define NSE_FWMNG_CLEAR_RSP_ALL				BIT(2)

void fwmng_clear_rsp(struct nse_hw *hw, bool fwmng_locked, unsigned int clear_rsp_op);

void fwmng_read_clear_rsp(struct nse_hw *hw,
					struct nse_fwmng_cmd_rsp_generic *cmd_rsp,
					bool fwmng_locked,
					unsigned int clear_rsp_op);

int __fwmng_send_req_read_rsp_unlocked(struct nse_hw *hw,
						struct nse_fwmng_cmd_req_generic *cmd_req,
						struct nse_fwmng_cmd_rsp_generic *cmd_rsp,
						unsigned int flags,
						unsigned int wait_tick_us,
						unsigned int wait_times,
						unsigned int *detail_status);
int __fwmng_send_req_read_rsp(struct nse_hw *hw,
						struct nse_fwmng_cmd_req_generic *cmd_req,
						struct nse_fwmng_cmd_rsp_generic *cmd_rsp,
						unsigned int flags,
						unsigned int wait_tick_us,
						unsigned int wait_times,
						unsigned int *detail_status);

int fwmng_high_reset_send_request_only(struct nse_hw *hw, enum nse_reset_req reset_req,
				       bool fwmng_locked);

#endif

