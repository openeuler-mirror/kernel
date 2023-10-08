/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: ubcore opcode header file
 * Author: Qian Guoxin, Ouyang Changchun
 * Create: 2023-2-28
 * Note:
 * History: 2023-2-28: Create file
 */

#ifndef UBCORE_OPCODE_H
#define UBCORE_OPCODE_H

/* opcode definition */
/* Must be consistent with urma_opcode_t */
enum ubcore_opcode {
	UBCORE_OPC_WRITE = 0x00,
	UBCORE_OPC_WRITE_IMM = 0x01,
	UBCORE_OPC_WRITE_NOTIFY = 0x02, // not support result
					// will return for UBCORE_OPC_WRITE_NOTIFY
	UBCORE_OPC_READ = 0x10,
	UBCORE_OPC_CAS = 0x20,
	UBCORE_OPC_FAA = 0x21,
	UBCORE_OPC_CAS_WITH_MASK = 0x24,
	UBCORE_OPC_FAA_WITH_MASK = 0x25,
	UBCORE_OPC_SEND = 0x40, // remote JFR/jetty ID
	UBCORE_OPC_SEND_IMM = 0x41, // remote JFR/jetty ID
	UBCORE_OPC_SEND_INVALIDATE = 0x42, // remote JFR/jetty ID and seg token id
	UBCORE_OPC_NOP = 0x51,
	UBCORE_OPC_LAST
};

/* completion information */
/* Must be consistent with urma_cr_status_t */
enum ubcore_cr_status { // completion record status
	UBCORE_CR_SUCCESS = 0,
	UBCORE_CR_LOC_LEN_ERR, // Local data too long error
	UBCORE_CR_LOC_OPERATION_ERR, // Local operation err
	UBCORE_CR_LOC_PROTECTION_ERR, // Local memory protection error
	UBCORE_CR_LOC_ACCESS_ERR, // Access to local memory error when WRITE_WITH_IMM
	UBCORE_CR_REM_INVALID_REQ_ERR,
	UBCORE_CR_REM_ACCESS_ERR, // Memory access protection error occurred in the remote node
	UBCORE_CR_REM_OPERATION_ERR,
	UBCORE_CR_RETRY_CNT_EXC_ERR, // Retransmission exceeds the maximum number of times
	UBCORE_CR_RNR_RETRY_CNT_EXC_ERR, // RNR retries exceeded the maximum number:
					// remote jfr has no buffer
	UBCORE_CR_FATAL_ERR,
	UBCORE_CR_WR_FLUSH_ERR,
	UBCORE_CR_RESP_TIMEOUT_ERR,
	UBCORE_CR_MORE_TO_POLL_ERR,
	UBCORE_CR_GENERAL_ERR
};

/* Must be consistent with urma_cr_opcode_t */
enum ubcore_cr_opcode {
	UBCORE_CR_OPC_SEND = 0x00,
	UBCORE_CR_OPC_SEND_WITH_IMM,
	UBCORE_CR_OPC_SEND_WITH_INV,
	UBCORE_CR_OPC_WRITE_WITH_IMM
};

#endif
