/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_TP_H__
#define __UBASE_TP_H__

#include <linux/netdevice.h>

#include "ubase_dev.h"

#define UBASE_WAIT_TP_FLUSH_TOTAL_STEPS	12

struct ubase_tp_ctx {
	u32 rsvd0;
	u32 wqe_ba_l;
	u32 wqe_ba_h : 20;
	u32 rsvd1 : 12;
	u32 rsvd2[5];
	u32 rsvd3_0 : 4;
	u32 tp_wqe_token_id : 20;
	u32 rsvd3_1 : 8;
	u32 rsvd4[5];
	u32 rsvd5 : 4;
	u32 reorder_q_addr_l : 28;
	u32 reorder_q_addr_h : 24;
	u32 rsvd6 : 8;
	u32 rsvd7[5];
	u32 scc_token : 19;
	u32 rsvd8 : 13;
	u32 rsvd9[4];
	u32 rsvd10_0 : 24;
	u32 scc_token_1 : 4;
	u32 rsvd10_1 : 4;
	u32 rsvd11[37];
};

struct ubase_tpg {
	u32		mb_tpgn;
	u8		tpg_state;
	u8		vl;
	atomic_t	tp_fd_cnt;
	u8		tp_cnt;
	unsigned long	valid_tp;
	u32		start_tpn;
	u32		tp_shift;
};

struct ubase_tp_fd_work {
	struct work_struct work;
	struct ubase_dev *udev;
	u32 tpn;
};

int ubase_send_tp_flush_done_notice(struct ubase_dev *udev, u32 tpn);
int ubase_ae_tp_flush_done(struct notifier_block *nb, unsigned long event,
			   void *data);
int ubase_ae_tp_level_error(struct notifier_block *nb, unsigned long event,
			    void *data);
int ubase_dev_init_tp_tpg(struct ubase_dev *udev);
void ubase_dev_uninit_tp_tpg(struct ubase_dev *udev);

#endif /* __UBASE_TP_H__ */
