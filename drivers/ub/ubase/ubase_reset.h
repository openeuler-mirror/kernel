/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_RESET_H__
#define __UBASE_RESET_H__

#include "ubase_dev.h"

#define UBASE_RST_ING_REG		0x00018040
#define UBASE_RST_ING_RST_DONE_B	0

#define UBASE_RESET_SCHED_TIMEOUT	(10 * HZ)

#define UBASE_RST_WAIT_REG_COUNT	60
#define UBASE_RST_WAIT_REG_TIME		50
#define UBASE_RST_WAIT_CMD_COUNT	60
#define UBASE_RST_WAIT_CMD_TIME		50

#define UBASE_RST_UE_WAIT_REG_TIME	200
#define UBASE_RST_WAIT_TIME		100
#define UBASE_RST_MAX_RETRY_CNT		5

struct ubase_notify_ue_reset_cmd {
	u16	bus_ue_id;
	u16	single;
	u8	rsv[20];
};

struct ubase_ue_reset_ready_cmd {
	u16	ue_unready_num;
	u8	rsv[22];
};

void ubase_suspend(struct ubase_dev *udev);
void ubase_resume(struct ubase_dev *udev, int pret);
void ubase_reset_service(struct ubase_delay_work *ubase_work);
void __ubase_reset_event(struct ubase_dev *udev,
			 enum ubase_reset_type reset_type);
void ubase_port_reset(struct ubase_dev *udev);
void ubase_errhandle_service_task(struct ubase_delay_work *ubase_work);
void ubase_reset_task_schedule_immediately(struct ubase_dev *udev);
int ubase_reset_done(struct ubase_dev *udev);
static inline int ubase_init_ue_reset_reg(struct ubase_dev *udev)
{
	/*
	 * force to init the reset register of UEs.
	 * because the value of the register is incorrect for UE when the MUE
	 * is removed and then probed immediately after a reset failure.
	 */
	if (test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return 0;
	return ubase_reset_done(udev);
};

#endif /* __UBASE_RESET_H__ */
