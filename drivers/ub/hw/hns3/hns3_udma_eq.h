/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
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
 */

#ifndef _UDMA_EQ_H
#define _UDMA_EQ_H

#include <linux/types.h>
#include "hns3_udma_cmd.h"

struct udma_eq_context {
	uint32_t	data[16];
};

#define UDMA_EQ_STATE_VALID		1
#define UDMA_EQ_INIT_EQE_CNT		0
#define UDMA_EQ_INIT_PROD_IDX		0
#define UDMA_EQ_INIT_REPORT_TIMER	0
#define UDMA_EQ_INIT_MSI_IDX		0
#define UDMA_EQ_INIT_CONS_IDX		0
#define UDMA_EQ_INIT_NXT_EQE_BA		0

#define EQC_FIELD_LOC(h, l) ((uint64_t)(h) << 32 | (l))

#define EQC_EQ_ST EQC_FIELD_LOC(1, 0)
#define EQC_EQE_HOP_NUM EQC_FIELD_LOC(3, 2)
#define EQC_OVER_IGNORE EQC_FIELD_LOC(4, 4)
#define EQC_COALESCE EQC_FIELD_LOC(5, 5)
#define EQC_ARM_ST EQC_FIELD_LOC(7, 6)
#define EQC_EQN EQC_FIELD_LOC(15, 8)
#define EQC_EQE_CNT EQC_FIELD_LOC(31, 16)
#define EQC_EQE_BA_PG_SZ EQC_FIELD_LOC(35, 32)
#define EQC_EQE_BUF_PG_SZ EQC_FIELD_LOC(39, 36)
#define EQC_EQ_PROD_INDX EQC_FIELD_LOC(63, 40)
#define EQC_EQ_MAX_CNT EQC_FIELD_LOC(79, 64)
#define EQC_EQ_PERIOD EQC_FIELD_LOC(95, 80)
#define EQC_EQE_REPORT_TIMER EQC_FIELD_LOC(127, 96)
#define EQC_EQE_BA_L EQC_FIELD_LOC(159, 128)
#define EQC_EQE_BA_H EQC_FIELD_LOC(188, 160)
#define EQC_SHIFT EQC_FIELD_LOC(199, 192)
#define EQC_MSI_INDX EQC_FIELD_LOC(207, 200)
#define EQC_CUR_EQE_BA_L EQC_FIELD_LOC(223, 208)
#define EQC_CUR_EQE_BA_M EQC_FIELD_LOC(255, 224)
#define EQC_CUR_EQE_BA_H EQC_FIELD_LOC(259, 256)
#define EQC_EQ_CONS_INDX EQC_FIELD_LOC(287, 264)
#define EQC_NEX_EQE_BA_L EQC_FIELD_LOC(319, 288)
#define EQC_NEX_EQE_BA_H EQC_FIELD_LOC(339, 320)
#define EQC_EQE_SIZE EQC_FIELD_LOC(341, 340)

#define UDMA_CEQE_COMP_CQN_S 0
#define UDMA_CEQE_COMP_CQN_M GENMASK(23, 0)

#define UDMA_AEQE_EVENT_TYPE_S 0
#define UDMA_AEQE_EVENT_TYPE_M GENMASK(7, 0)

#define UDMA_AEQE_SUB_TYPE_S 8
#define UDMA_AEQE_SUB_TYPE_M GENMASK(15, 8)

#define UDMA_AEQE_EVENT_QUEUE_NUM_S 0
#define UDMA_AEQE_EVENT_QUEUE_NUM_M GENMASK(23, 0)

#define EQC_EQE_BA_L_SHIFT	3
#define EQC_EQE_BA_H_SHIFT	35
#define EQC_CUR_EQE_BA_L_SHIFT	12
#define EQC_CUR_EQE_BA_M_SHIFT	28
#define EQC_CUR_EQE_BA_H_SHIFT	60
#define EQC_NEX_EQE_BA_L_SHIFT	12
#define EQC_NEX_EQE_BA_H_SHIFT	44
#define UDMA_VF_INT_ST_AEQ_OVERFLOW_S	0
#define UDMA_VF_ABN_INT_EN_S 0

struct udma_eq_db {
	uint32_t	data[2];
};

struct fmea_ram_ecc {
	uint32_t	is_ecc_err;
	uint32_t	res_type;
	uint32_t	index;
};

enum ecc_resource_type {
	ECC_RESOURCE_QPC,
	ECC_RESOURCE_CQC,
	ECC_RESOURCE_MPT,
	ECC_RESOURCE_SRQC,
	ECC_RESOURCE_GMV,
	ECC_RESOURCE_QPC_TIMER,
	ECC_RESOURCE_CQC_TIMER,
	ECC_RESOURCE_SCCC,
	ECC_RESOURCE_COUNT,
};

static const struct {
	const char	*name;
	uint8_t		read_bt0_op;
	uint8_t		write_bt0_op;
} fmea_ram_res[] = {
	{ "ECC_RESOURCE_QPC",
	  UDMA_CMD_READ_QPC_BT0, UDMA_CMD_WRITE_QPC_BT0 },
	{ "ECC_RESOURCE_CQC",
	  UDMA_CMD_READ_CQC_BT0, UDMA_CMD_WRITE_CQC_BT0 },
	{ "ECC_RESOURCE_MPT",
	  UDMA_CMD_READ_MPT_BT0, UDMA_CMD_WRITE_MPT_BT0 },
	{ "ECC_RESOURCE_SRQC",
	  UDMA_CMD_READ_SRQC_BT0, UDMA_CMD_WRITE_SRQC_BT0 },
	/* ECC_RESOURCE_GMV is handled by cmdq, not mailbox */
	{ "ECC_RESOURCE_GMV",
	  0, 0 },
	{ "ECC_RESOURCE_QPC_TIMER",
	  UDMA_CMD_READ_QPC_TIMER_BT0, UDMA_CMD_WRITE_QPC_TIMER_BT0 },
	{ "ECC_RESOURCE_CQC_TIMER",
	  UDMA_CMD_READ_CQC_TIMER_BT0, UDMA_CMD_WRITE_CQC_TIMER_BT0 },
	{ "ECC_RESOURCE_SCCC",
	  UDMA_CMD_READ_SCCC_BT0, UDMA_CMD_WRITE_SCCC_BT0 },
};

#define EQ_DB_FIELD_LOC(h, l) ((uint64_t)(h) << 32 | (l))

#define UDMA_EQ_DB_TAG EQ_DB_FIELD_LOC(7, 0)
#define UDMA_EQ_DB_CMD EQ_DB_FIELD_LOC(17, 16)
#define UDMA_EQ_DB_CI EQ_DB_FIELD_LOC(55, 32)

#define UDMA_EQ_ARMED			1
#define UDMA_EQ_ALWAYS_ARMED		3

#define UDMA_EQ_DB_CMD_AEQ		0x0
#define UDMA_EQ_DB_CMD_AEQ_ARMED	0x1
#define UDMA_EQ_DB_CMD_CEQ		0x2
#define UDMA_EQ_DB_CMD_CEQ_ARMED	0x3

int udma_init_eq_table(struct udma_dev *udma_dev);
void udma_cleanup_eq_table(struct udma_dev *udma_dev);

#endif /* _UDMA_EQ_H */
