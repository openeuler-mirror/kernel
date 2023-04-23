/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 3snic Technologies Co., Ltd */

#ifndef SSS_HWIF_ADM_COMMON_H
#define SSS_HWIF_ADM_COMMON_H

/* ADM_STATUS_0 CSR: 0x0030+adm msg id*0x080 */
#define SSS_ADM_MSG_STATE_CI_MASK			0xFFFFFFU
#define SSS_ADM_MSG_STATE_CI_SHIFT		0

#define SSS_ADM_MSG_STATE_FSM_MASK				0xFU
#define SSS_ADM_MSG_STATE_FSM_SHIFT				24

#define SSS_ADM_MSG_STATE_CHKSUM_ERR_MASK		0x3U
#define SSS_ADM_MSG_STATE_CHKSUM_ERR_SHIFT		28

#define SSS_ADM_MSG_STATE_CPLD_ERR_MASK			0x1U
#define SSS_ADM_MSG_STATE_CPLD_ERR_SHIFT		30

#define SSS_GET_ADM_MSG_STATE(val, member)			\
		(((val) >> SSS_ADM_MSG_STATE_##member##_SHIFT) & \
			SSS_ADM_MSG_STATE_##member##_MASK)
#endif
