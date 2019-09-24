/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2019 HiSilicon Limited. */

#ifndef __HISI_HPRE_H
#define __HISI_HPRE_H

#include <linux/list.h>
#include "../qm.h"

#define HPRE_SQE_SIZE			sizeof(struct hpre_sqe)
#define HPRE_SQ_SIZE			(HPRE_SQE_SIZE * QM_Q_DEPTH)
#define QM_CQ_SIZE			(QM_CQE_SIZE * QM_Q_DEPTH)
#define HPRE_PF_DEF_Q_NUM		64
#define HPRE_PF_DEF_Q_BASE		0
#define HPRE_RESET			0
#define HPRE_WAIT_DELAY	1000

struct hpre_ctrl;

struct hpre {
	struct hisi_qm qm;
	struct list_head list;
	struct hpre_ctrl *ctrl;
	unsigned long status;
};

enum hpre_alg_type {
	HPRE_ALG_NC_NCRT = 0x0,
	HPRE_ALG_NC_CRT = 0x1,
	HPRE_ALG_KG_STD = 0x2,
	HPRE_ALG_KG_CRT = 0x3,
	HPRE_ALG_DH_G2 = 0x4,
	HPRE_ALG_DH = 0x5,
	HPRE_ALG_PRIME = 0x6,
	HPRE_ALG_MOD = 0x7,
	HPRE_ALG_MOD_INV = 0x8,
	HPRE_ALG_MUL = 0x9,
	HPRE_ALG_COPRIME = 0xA
};

struct hpre_sqe {
	__le32 dw0;
	__u8 task_len1;
	__u8 task_len2;
	__u8 mrttest_num;
	__u8 resv1;
	__le64 key;
	__le64 in;
	__le64 out;
	__le16 tag;
	__le16 resv2;
#define _HPRE_SQE_ALIGN_EXT	7
	__le32 rsvd1[_HPRE_SQE_ALIGN_EXT];
};

struct hpre *find_hpre_device(int node);
int hpre_algs_register(void);
void hpre_algs_unregister(void);

#endif
