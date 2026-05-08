/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_lag.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_LAG_H__
#define __SXE2_LAG_H__
#include "sxe2_netdev.h"
#include "sxe2_drv_aux.h"
#include <linux/netdevice.h>

#define SXE2_LAG_PF0 0
#define SXE2_LAG_PF1 1

#define SXE2_MAX_PF_NUM	      4
#define SXE2_MAX_BOND_DEV_NUM 2

#define SXE2_LAG_EVENT_UNSET	   0
#define SXE2_LAG_EVENT_CHANGEUPPER BIT(0)
#define SXE2_LAG_EVENT_BONDINFO	   BIT(1)

#define SXE2_LAG_MODE_NONE	    0
#define SXE2_LAG_MODE_ACTIVE_BACKUP 1
#define SXE2_LAG_MODE_ACTIVE_ACTIVE 2

#define sxe2_for_each_user_prio(type) \
	for ((type) = 0; (type) < SXE2_MAX_USER_PRIORITY; (type)++)

enum sxe2_lag_flags {
	SXE2_LAG_FLAGS_WK_PENDING,
	SXE2_LAG_FLAGS_WK_PROCESS,
	SXE2_LAG_FLAGS_NBITS
};

enum sxe2_lag_adapter_type {
	SXE2_LAG_ADAPTER_TYPE_PRIMARY,
	SXE2_LAG_ADAPTER_TYPE_REDUNDANT,
	SXE2_LAG_ADAPTER_TYPE_ACTIVE,
};

enum sxe2_lag_work_state {
	SXE2_LAG_WK_ST_UNSET,
	SXE2_LAG_WK_ST_WAIT_PROC,
	SXE2_LAG_WK_ST_DONE,
};

enum sxe2_lag_state {
	SXE2_LAG_STATE_UNINIT,
	SXE2_LAG_STATE_READY,
	SXE2_LAG_STATE_RESET,
};

struct sxe2_lag_list {
	struct list_head node;
	struct sxe2_lag_context *lag;
};

struct sxe2_lag_dev_info {
	int slave_state;
	int slave_link;
};

struct sxe2_lag_work {
	struct work_struct task;
	struct sxe2_lag_context *lag;
	enum sxe2_lag_work_state state;
	struct sxe2_lag_dev_info
		info[SXE2_MAX_BOND_DEV_NUM];
	int bond_mode;
	unsigned int event;
	unsigned long is_bonded : 1;
};

struct sxe2_lag_context {
	struct sxe2_adapter *adapters
		[SXE2_MAX_BOND_DEV_NUM];
	struct aux_rdma_qset_params
		rdma_qset[SXE2_MAX_USER_PRIORITY];
	struct aux_rdma_multi_qset_params
		rdma_qsets[SXE2_MAX_USER_PRIORITY];
	struct notifier_block notif_block;

	/* in order to protect the data */
	struct mutex lock;
	struct workqueue_struct *wkq;
	struct sxe2_lag_work lag_wk;

	unsigned long flags;

	u8 serial_num[SXE2_SERIAL_NUM_LEN];
	int active_id;
	int ref_num;
	int bond_mode;
	int bond_id;
	bool bonded;
	enum sxe2_lag_state state[SXE2_MAX_BOND_DEV_NUM];
};

bool sxe2_lag_support(struct sxe2_adapter *adapter);

int sxe2_lag_init(struct sxe2_adapter *adapter);

void sxe2_lag_deinit(struct sxe2_adapter *adapter);

void sxe2_lag_init_once(void);

void sxe2_lag_alloced_node_move(struct aux_core_dev_info *cdev_info,
				u8 user_pri, bool is_aa);

void sxe2_lag_deinit_once(void);

void sxe2_lag_aa_failover(struct sxe2_lag_context *lag,
			  struct aux_core_dev_info *cdev, u8 dest);
void sxe2_lag_aa_reclaim_node(struct sxe2_lag_context *lag,
			      struct aux_core_dev_info *cdev, u8 user_pri);

void sxe2_lag_ab_reclaim_node(struct sxe2_lag_context *lag,
			      struct aux_core_dev_info *cdev, u8 user_pri);

bool sxe2_lag_is_bonded(struct sxe2_adapter *adapter);

void sxe2_lag_stop(struct sxe2_adapter *adapter);

void sxe2_lag_rebuild(struct sxe2_adapter *adapter);

void sxe2_lag_proc(struct sxe2_adapter *adapter);

struct sxe2_adapter *sxe2_lag_role_find(struct sxe2_lag_context *lag,
					int role);
#endif
