/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_dev_ctrl.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DEV_CTRL_H__
#define __SXE2_DEV_CTRL_H__

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>

#define SXE2_PF_STOPPED 0

struct sxe2_adapter;

enum sxe2_dev_state {
	SXE2_DEVSTATE_INITIAL = 0,
	SXE2_DEVSTATE_ACCESSIBLE,
	SXE2_DEVSTATE_RUNNING,
	SXE2_DEVSTATE_ABNORMAL,
	SXE2_DEVSTATE_RESETTING,
	SXE2_DEVSTATE_FAULT,
};

enum sxe2_reset_type {
	SXE2_RESET_INVAL = 0,
	SXE2_RESET_CORER,
	SXE2_RESET_PFR,
	SXE2_RESET_VFR,
	SXE2_RESET_MAX,
};

enum sxe2_dev_ctrl_task_state {
	SXE2_DEV_CTRL_WORK_SCHED,
	SXE2_DEV_CTRL_WORK_DISABLED,
};

enum sxe2_pf_stop_flags {
	SXE2_PF_STOP_NORMAL	       = 0,
	SXE2_PF_STOP_RESET_NOTICE_RDMA = BIT(0),
	SXE2_PF_STOP_CANCEL_CMD_QUEUE  = BIT(1),
};

enum sxe2_vf_reset_flags {
	SXE2_VF_RESET_FLAG_NOTIFY = BIT(0),
};

enum sxe2_err_print_flags {
	SXE2_PRINT_CORE_RESET = BIT(0),
	SXE2_PRINT_ECC_ERROR = BIT(1),
	SXE2_PRINT_REG_CFG_ERR = BIT(2),
	SXE2_PRINT_RAM_CONFLICT = BIT(3),
};

struct sxe2_dev_ctrl_context {
	enum sxe2_dev_state dev_state;
	enum sxe2_reset_type reset_type;
	unsigned long flag;
	u16 corer_cnt;
	u16 pfr_cnt;
	u8 rebuild_failed;
	u32 last_heartbeat_value;
	unsigned long last_heartbeat_time;
	struct work_struct work;
	unsigned long work_state;
	struct timer_list timer;
	unsigned long period;
	/* in order to protect the data */
	struct mutex pf_lock;
	/* in order to protect the data */
	spinlock_t state_lock;
	/* in order to protect the data */
	spinlock_t wq_lock;
	/* in order to protect the data */
	spinlock_t cmd_list_lock;
	u32 print_flag;
#ifdef SXE2_CFG_DEBUG
	u8 heart_beat_ena;
	u8 pad[3];
#endif
};

void sxe2_dev_state_get(struct sxe2_adapter *adapter,
			enum sxe2_dev_state *state,
			enum sxe2_reset_type *reset_type);

void sxe2_dev_state_set(struct sxe2_adapter *adapter,
			enum sxe2_dev_state dev_state,
			enum sxe2_reset_type reset_type);

s32 sxe2_stop_drop(struct sxe2_adapter *adapter);

void sxe2_dev_ctrl_work_schedule(struct sxe2_adapter *adapter);

void sxe2_dev_ctrl_init(struct sxe2_adapter *adapter);

void sxe2_dev_ctrl_deinit(struct sxe2_adapter *adapter);

void sxe2_dev_ctrl_init_once(struct sxe2_adapter *adapter);

void sxe2_dev_ctrl_deinit_once(struct sxe2_adapter *adapter);

s32 sxe2_dev_ctrl_work_create(void);

void sxe2_dev_ctrl_work_destroy(void);

s32 sxe2_wait_reset_done(struct sxe2_adapter *adapter,
			 enum sxe2_reset_type reset_type);

void sxe2_pf_stop(struct sxe2_adapter *adapter, u16 stop_flag);

s32 sxe2_lfc_rebuild_set(struct sxe2_adapter *adapter);

s32 sxe2_pf_rebuild(struct sxe2_adapter *adapter);

s32 sxe2_fwc_clear_pf_cfg(struct sxe2_adapter *adapter);

s32 sxe2_fwc_clear_vf_cfg(struct sxe2_adapter *adapter, u16 vf_id);

s32 sxe2_reset_async(struct sxe2_adapter *adapter,
		     enum sxe2_reset_type reset_type);

s32 sxe2_reset_sync(struct sxe2_adapter *adapter,
		    enum sxe2_reset_type reset_type);

void sxe2_dev_ctrl_work_stop(struct sxe2_adapter *adapter);

void sxe2_dev_ctrl_work_start(struct sxe2_adapter *adapter);

bool sxe2_corer_check(struct sxe2_adapter *adapter);

s32 sxe2_reset_vf(struct sxe2_adapter *adapter, u16 vf_id, u32 flag);

s32 sxe2_reset_all_vfs(struct sxe2_adapter *adapter);

void sxe2_vfs_stop(struct sxe2_adapter *adapter);

void sxe2_vf_stop(struct sxe2_vf_node *vf_node);

s32 sxe2_wait_vfr_done(struct sxe2_adapter *adapter, u16 vf_id);

void sxe2_trigger_and_wait_resetting(struct sxe2_adapter *adapter);

s32 sxe2_wait_fw_init(struct sxe2_adapter *adapter);

#endif
