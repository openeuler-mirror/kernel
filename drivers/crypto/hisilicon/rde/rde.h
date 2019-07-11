/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2019 HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */


#ifndef HISI_RDE_H
#define HISI_RDE_H

#include <linux/list.h>
#include "../qm.h"
#include "rde_usr_if.h"

#undef pr_fmt
#define pr_fmt(fmt)	"hisi_rde: " fmt

struct hisi_rde_ctrl;

enum hisi_rde_status {
	HISI_RDE_RESET,
};

struct hisi_rde {
	struct hisi_qm qm;
	struct list_head list;
	struct hisi_rde_ctrl *ctrl;
	struct work_struct reset_work;
	unsigned long status;
};

//#define DEBUG

#define RDE_CM_LOAD_ENABLE		1
#define RDE_MPCC_MAX_SRC_NUM	17
#define RDE_FLEXEC_MAX_SRC_NUM	32
#define RDE_MPCC_CMSIZE			2176
#define RDE_FLEXEC_CMSIZE			1024
#define RDE_BUF_TYPE_SHIFT			3
#define SGL_DATA_OFFSET_SHIFT		8
#define RDE_COEF_GF_SHIFT			32
#define RDE_LBA_BLK					8
#define RDE_LBA_DWORD_CNT			5
#define DIF_CHK_GRD_CTRL_SHIFT	4
#define DIF_CHK_REF_CTRL_SHIFT	32
#define DIF_LBA_SHIFT					32
#define DIF_GEN_PAD_CTRL_SHIFT	32
#define DIF_GEN_REF_CTRL_SHIFT	35
#define DIF_GEN_APP_CTRL_SHIFT		38
#define DIF_GEN_VER_CTRL_SHIFT	41
#define DIF_GEN_GRD_CTRL_SHIFT	44
#define DIF_APP_TAG_SHIFT			48
#define DIF_VERSION_SHIFT			56
#define RDE_TASK_DONE_STATUS		0x80
#define RDE_CRC16_IV					0x301004
#define RDE_PRP_PAGE_SIZE			0x30122c
#define RDE_SGL_SGE_OFFSET			0x301228
#define RDE_ALG_TYPE_MSK			0x60
#define RDE_BUF_TYPE_MSK			0x18
#define RDE_MAX_PLATE_NUM			32
#define SRC_ADDR_TABLE_NUM		48
#define DST_ADDR_TABLE_NUM		26
#define SRC_DIF_TABLE_NUM			20
#define DST_DIF_TABLE_NUM			17
#define RDE_STATUS_MSK				0x7f
#define RDE_DONE_MSK				0x1
#define RDE_DONE_SHIFT				7
#define RDE_PER_SRC_COEF_SIZE		32
#define RDE_PER_SRC_COEF_TIMES	4

struct hisi_rde *find_rde_device(int node);
int hisi_rde_abnormal_fix(struct hisi_qm *qm);

#endif
