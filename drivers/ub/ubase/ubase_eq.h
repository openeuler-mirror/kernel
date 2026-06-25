/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_EQ_H__
#define __UBASE_EQ_H__

#include <linux/sched.h>
#include <linux/spinlock_types_raw.h>
#include <ub/ubase/ubase_comm_eq.h>

#include "ubase.h"

#define UBASE_MIN_IRQ_NUM 3 /* for misc aeq ceq */

#define UBASE_EQ_ALWAYS_ARMED		0x2
#define UBASE_EQ_COALESCE_0		0
#define UBASE_EQ_INIT_PROD_IDX		0
#define UBASE_EQ_INIT_CONS_IDX		0
#define UBASE_EQ_STAT_INVALID		0
#define UBASE_EQ_STAT_VALID		1

#define UBASE_CTX_SHIFT_BASE		6
#define UBASE_DEFAULT_EQE_SIZE		64
#define UBASE_EQE_BA_L_OFFSET		12
#define UBASE_EQE_BA_L_VALID_BIT	GENMASK(19, 0)
#define UBASE_EQE_BA_H_OFFSET		32
#define UBASE_EQE_BA_H_VALID_BIT	GENMASK(31, 0)

#define UBASE_CEQ_CEQE_OWNER_BIT	BIT(31)
#define UBASE_CEQE_COMP_CQN_M		GENMASK(19, 0)
#define UBASE_EQ_DB_CMD_CEQ		0x2
#define EQC_EQ_DEFAULT_PERIOD_INDX	4U

#define UBASE_INT_NAME_LEN 32

#define UBASE_AE_LEVEL_NUM 3

/* Vector0 interrupt CMDQ event source register(RW) */
#define UBASE_VECTOR0_CMDQ_SRC_REG	0x18004
/* Vector0 interrupt CTRLQ event source register(RW) */
#define UBASE_VECTOR0_CTRLQ_SRC_REG	0x18014
/* Vector0 interrupt control register */
#define UBASE_MISC_VECTOR_REG_OFFSET	0x18020
/* Software handshake 0 register(RW) */
#define UBASE_SW_HANDSHAKE_0_REG	0x18044
/* CMDQ register bits for RX event */
#define UBASE_VECTOR0_RX_CMDQ_INT_B	1
/* CTRLQ register bits for RX event */
#define UBASE_VECTOR0_RX_CTRLQ_INT_B	0
/* Software handshake 0 register bit for ras report */
#define UBASE_SW_HANDSHAKE_0_RAS_B		0
#define UBASE_SW_HANDSHAKE_0_PORT_RESET_B	1
#define UBASE_SW_HANDSHAKE_0_HIMAC_RESET_B	2

enum ubase_async_event_cause_bit {
	UBASE_ASYNC_EVENT_CRQ_B,
	UBASE_ASYNC_EVENT_RAS_B,
	UBASE_ASYNC_EVENT_CTRLQ_B,
};

enum ubase_eqc_irqn {
	UBASE_MISC_IRQ_INDEX,
	UBASE_AEQ_IRQ_INDEX,
	UBASE_CEQ_IRQ_INDEX,
};

struct ubase_irq {
	char	name[UBASE_INT_NAME_LEN];
	int	irqn;
};

struct ubase_eq_db {
	u8 eqn;
	u8 rsv0;
	__le16 type : 2;
	__le16 rsv1 : 14;

	__le32 ci : 24;
	__le32 rsv2 : 8;
};

struct ubase_ceqe {
	u32 comp;
	u32 rsv[15];
};

struct ubase_eq_addr {
	void		*addr;
	struct page	*page;
	dma_addr_t	dma_addr;
	size_t		size;
};

struct ubase_eq {
	void __iomem		*db_reg;
	struct ubase_eq_addr	addr;
	u32			eqn;
	u32			entries_num;
	u32			state;
	u32			arm_st;
	u8			eqe_size;
	u32			eq_period;
	u32			coalesce_cnt;
	int			irqn;
	u32			eqc_irqn; /* irqn for eqc */
	u32			cons_index;
};

struct ubase_eq_ctx {
	/* DW0 */
	u32 state : 2;
	u32 arm_st : 2;
	u32 eqe_size : 1;
	u32 rsv0 : 3;
	u32 pi : 24;

	/* DW1 */
	u32 shift : 5;
	u32 eqe_coalesce_period : 3;
	u32 ci : 24;

	/* DW2 */
	u32 eqe_coalesce_cnt : 10;
	u32 rsv1 : 2;
	u32 eqe_base_addr_l : 20;

	/* DW3 */
	u32 eqe_base_addr_h;

	/* DW4 */
	u32 eqe_token_id : 20;
	u32 rsv2 : 12;

	/* DW5 */
	u32 eqe_token_value;

	/* DW6 */
	u32 irq_num : 16;
	u32 rsv3_1 : 16;

	/* DW7 */
	u32 rsv3_2;

	/* DW8 */
	u32 eqn : 8;
	u32 eqe_cnt : 10;
	u32 rsv4 : 12;
	u32 eqe_report_timer_l : 2;

	/* DW9 */
	u32 eqe_report_timer_h;

	/* DW10 */
	u32 funid : 8;
	u32 pi_bypass : 24;

	/* DW11 */
	u32 state2 : 2;
	u32 rsv5_1 : 30;

	/* DW12~DW15 */
	u32 rsv5_2[4];
};

struct ubase_ceq {
	struct ubase_dev	*udev;
	struct ubase_eq		eq;
};

struct ubase_aeq {
	struct ubase_dev	*udev;
	struct ubase_eq		eq;
	struct ubase_event_nb	cb[UBASE_AE_LEVEL_NUM];
	struct completion	poll;
	struct task_struct	*ae_task;
	raw_spinlock_t		aeq_lock;
};

struct ubase_ceqs {
	struct ubase_ceq	*ceq;
	u32			num;
};

struct ubase_irq_table {
	struct mutex			ceq_lock;
	struct ubase_ceqs		ceqs;
	struct ubase_aeq		aeq;
	struct blocking_notifier_head	nh[UBASE_DRV_MAX][UBASE_EVENT_TYPE_MAX];

	struct ubase_irq		**irqs; /* first one for misc */
	u32				irqs_num;
};

struct ubase_aeq_work {
	struct ubase_dev	*udev;
	struct work_struct	work;
	struct ubase_aeqe	aeqe;
};

int ubase_irq_table_init(struct ubase_dev *udev);
void ubase_irq_table_uninit(struct ubase_dev *udev);
void ubase_irq_table_free(struct ubase_dev *udev);

int ubase_register_ae_event(struct ubase_dev *udev);
void ubase_unregister_ae_event(struct ubase_dev *udev);

void ubase_enable_misc_vector(struct ubase_dev *udev, bool enable);
void ubase_disable_ce_irqs(struct ubase_dev *udev);
void ubase_errhandle_task_schedule(struct ubase_dev *udev);
void ubase_ctrlq_task_schedule(struct ubase_dev *udev, unsigned long delay);
#endif /* __UBASE_EQ_H__ */
