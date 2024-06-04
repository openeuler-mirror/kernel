// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 */

#ifndef _HISI_L3T_H
#define _HISI_L3T_H

/* L3T register definition */
#define L3T_VERSION		0x1cf0
#define L3T_LOCK_CTRL		0x0440
#define L3T_LOCK_AREA		0x0444
#define L3T_LOCK_START_L	0x0448
#define L3T_LOCK_START_H	0x044C
#define L3T_LOCK_STEP		0x10

#define L3T_REG_NUM		4

extern struct mutex l3t_mutex;

struct hisi_l3t {
	struct device *dev;
	void __iomem *base;
	int sccl_id;
	int ccl_id;
	int nid;
};

struct hisi_sccl {
	int nid;			/* numa node id */
	int ccl_cnt;			/* ccl count for this sccl */
	struct hisi_l3t **l3t;
};

struct hisi_sccl *hisi_l3t_get_sccl(int nid);
void hisi_l3t_read(struct hisi_l3t *l3t, int slot_idx, unsigned long *s_addr,
		     int *size);
void hisi_l3t_lock(struct hisi_l3t *l3t, int slot_idx, unsigned long s_addr,
		   int size);
void hisi_l3t_unlock(struct hisi_l3t *l3t, int slot_idx);

int l3t_shared_lock(int nid, unsigned long pfn, unsigned long size);
int l3t_shared_unlock(int nid, unsigned long pfn, unsigned long size);

#endif
