/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_STATUS_H_
#define _NSE_STATUS_H_

/* Error Codes */
enum nse_status {
	NSE_SUCCESS				= 0,

	/* Generic codes : Range -1..-49 */
	NSE_ERR_PARAM					= -1,
	NSE_ERR_NOT_IMPL				= -2,
	NSE_ERR_NOT_READY				= -3,
	NSE_ERR_NOT_SUPPORTED			= -4,
	NSE_ERR_BAD_PTR					= -5,
	NSE_ERR_INVAL_SIZE				= -6,
	NSE_ERR_EPERM					= -7,
	NSE_ERR_DEVICE_NOT_SUPPORTED	= -8,
	NSE_ERR_RESET_FAILED			= -9,
	NSE_ERR_FW_API_VER				= -10,
	NSE_ERR_NO_MEMORY				= -11,
	NSE_ERR_CFG						= -12,
	NSE_ERR_OUT_OF_RANGE			= -13,
	NSE_ERR_ALREADY_EXISTS			= -14,
	NSE_ERR_DOES_NOT_EXIST			= -15,
	NSE_ERR_IN_USE					= -16,
	NSE_ERR_MAX_LIMIT				= -17,
	NSE_ERR_HIGH_RESET_ONGOING		= -18,
	NSE_ERR_HW_TABLE				= -19,
	NSE_ERR_AGAIN					= -20,
	NSE_ERR_BUSY					= -21,
	NSE_ERR_IN_PROGRESS				= -22,
	NSE_ERR_IO						= -23,

	/* NVM specific error codes: Range -50..-59 */
	NSE_ERR_NVM						= -50,
	NSE_ERR_NVM_CHECKSUM			= -51,
	NSE_ERR_BUF_TOO_SHORT			= -52,

	/* special error codes related to FW: Range: -80, -99*/
	NSE_ERR_FW_IN_UPDATE			= -80,

	/* ARQ/ASQ specific error codes. Range -100..-109 */
	NSE_ERR_AQ_ERROR				= -100,
	NSE_ERR_AQ_TIMEOUT				= -101,
	NSE_ERR_AQ_FULL					= -102,
	NSE_ERR_AQ_NO_WORK				= -103,
	NSE_ERR_AQ_EMPTY				= -104,
	NSE_ERR_AQ_FW_CRITICAL			= -105,
};

#endif /* _NSE_STATUS_H_ */

