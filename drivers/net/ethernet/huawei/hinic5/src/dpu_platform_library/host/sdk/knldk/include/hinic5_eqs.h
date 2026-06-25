/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_eqs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_EQS_H
#define HINIC5_EQS_H

#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>

#include "hinic5_common.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_hwdev.h"
#include "hinic5_hwif_inner.h"

#define HINIC5_MAX_AEQS			4
#define HINIC5_MAX_CEQS			32

#define HINIC5_AEQ_MAX_PAGES		4
#define HINIC5_CEQ_MAX_PAGES		8

#define HINIC5_AEQE_SIZE		64
#define HINIC5_CEQE_SIZE		4

#define HINIC5_AEQE_DESC_SIZE		4
#define HINIC5_AEQE_DATA_SIZE		\
			(HINIC5_AEQE_SIZE - HINIC5_AEQE_DESC_SIZE)

#define HINIC5_AEQ_CPU_AFFINITY_MAX	16

#if defined(__UEFI__)
#define HINIC5_DEFAULT_AEQ_LEN		64
#define HINIC5_DEFAULT_CEQ_LEN		1024
#elif defined(__PANGEA_BINARY__)
#define HINIC5_DEFAULT_AEQ_LEN		64
#define HINIC5_DEFAULT_CEQ_LEN		8192
#elif (!defined(__PANGEA_BINARY__) && defined(__HIFC__))
#define HINIC5_DEFAULT_AEQ_LEN		4096
#define HINIC5_DEFAULT_CEQ_LEN		8192
#else
#define HINIC5_DEFAULT_AEQ_LEN		0x10000
#define HINIC5_DEFAULT_CEQ_LEN		0x10000
#endif

#define HINIC5_MIN_EQ_PAGE_SIZE		0x1000   /* min eq page size 4K Bytes */
#define HINIC5_MAX_EQ_PAGE_SIZE		0x400000 /* max eq page size 4M Bytes */

#define HINIC5_MIN_AEQ_LEN		64
#define HINIC5_MAX_AEQ_LEN		\
	((HINIC5_MAX_EQ_PAGE_SIZE / HINIC5_AEQE_SIZE) * HINIC5_AEQ_MAX_PAGES)

#define HINIC5_MIN_CEQ_LEN		64
#define HINIC5_MAX_CEQ_LEN		\
	((HINIC5_MAX_EQ_PAGE_SIZE / HINIC5_CEQE_SIZE) * HINIC5_CEQ_MAX_PAGES)
#define	HINIC5_CEQ_ID_CMDQ		0

#define EQ_IRQ_NAME_LEN			64

#define EQ_USLEEP_LOW_BOUND		900
#define EQ_USLEEP_HIG_BOUND		1000

enum hinic5_eq_type {
	HINIC5_AEQ,
	HINIC5_CEQ
};

enum hinic5_eq_intr_mode {
	HINIC5_INTR_MODE_ARMED,
	HINIC5_INTR_MODE_ALWAYS,
};

enum hinic5_eq_ci_arm_state {
	HINIC5_EQ_NOT_ARMED,
	HINIC5_EQ_ARMED,
};

struct hinic5_eq {
	struct hinic5_hwdev		*hwdev;
	u16				q_id;
	u16				rsvd1;
	enum hinic5_eq_type		type;
	u32				page_size;
	u32				orig_page_size;
	u32				eq_len;

	u32				cons_idx;
	u16				wrapped;
	u16				rsvd2;

	u16				elem_size;
	u16				num_pages;
	u32				num_elem_in_pg;

	struct irq_info			eq_irq;
	char				irq_name[EQ_IRQ_NAME_LEN];

	struct hinic5_dma_addr_align	*eq_pages;

	struct work_struct		aeq_work;
	struct tasklet_struct		ceq_tasklet;

	u64				hard_intr_jif;
	u64				soft_intr_jif;

	int				cpu;
	u64				rsvd3;
};

struct hinic5_aeq_elem {
	u8	aeqe_data[HINIC5_AEQE_DATA_SIZE];
	u32	desc;
};

enum hinic5_aeq_cb_state {
	HINIC5_AEQ_HW_CB_REG = 0,
	HINIC5_AEQ_HW_CB_RUNNING,
	HINIC5_AEQ_SW_CB_REG,
	HINIC5_AEQ_SW_CB_RUNNING,
};

struct hinic5_stateless_aeqs {
	hinic5_aeq_swe_cb       stateless_aeq_swe_cb;
	void                    *stateless_aeq_swe_cb_data;
	ulong                   stateless_aeq_sw_cb_state;
};

struct hinic5_aeqs {
	struct hinic5_hwdev     *hwdev;

	hinic5_aeq_hwe_cb       aeq_hwe_cb[HINIC5_MAX_AEQ_EVENTS];
	void                    *aeq_hwe_cb_data[HINIC5_MAX_AEQ_EVENTS];
	hinic5_aeq_swe_cb       aeq_swe_cb[HINIC5_MAX_AEQ_SW_EVENTS];
	void                    *aeq_swe_cb_data[HINIC5_MAX_AEQ_SW_EVENTS];
	ulong                   aeq_hw_cb_state[HINIC5_MAX_AEQ_EVENTS];
	ulong                   aeq_sw_cb_state[HINIC5_MAX_AEQ_SW_EVENTS];

	struct hinic5_eq        aeq[HINIC5_MAX_AEQS];
	u16                     num_aeqs;
	u16                     rsvd1;
	u32                     rsvd2;

	int			aeq_cpu_affinity[HINIC5_AEQ_CPU_AFFINITY_MAX];
	unsigned int		aeq_cpu_affinity_nargs;

	struct workqueue_struct *workq;
};

enum hinic5_ceq_cb_state {
	HINIC5_CEQ_CB_REG = 0,
	HINIC5_CEQ_CB_RUNNING,
};

struct hinic5_ceqs {
	struct hinic5_hwdev     *hwdev;

	hinic5_ceq_event_cb     ceq_cb[HINIC5_MAX_CEQ_EVENTS];
	void                    *ceq_cb_data[HINIC5_MAX_CEQ_EVENTS];
	void                    *ceq_data[HINIC5_MAX_CEQ_EVENTS];
	ulong	                ceq_cb_state[HINIC5_MAX_CEQ_EVENTS];

	struct hinic5_eq        ceq[HINIC5_MAX_CEQS];
	u16                     num_ceqs;
	u16                     rsvd1;
	u32                     rsvd2;
};

int hinic5_aeqs_init(struct hinic5_hwdev *hwdev, u16 num_aeqs,
		     struct irq_info *msix_entries);

void hinic5_aeqs_free(struct hinic5_hwdev *hwdev);

int hinic5_ceqs_init(struct hinic5_hwdev *hwdev, u16 num_ceqs,
		     struct irq_info *msix_entries);

void hinic5_ceqs_free(struct hinic5_hwdev *hwdev);

void hinic5_get_ceq_irqs(struct hinic5_hwdev *hwdev, struct irq_info *irqs,
			 u16 *num_irqs);

void hinic5_get_aeq_irqs(struct hinic5_hwdev *hwdev, struct irq_info *irqs,
			 u16 *num_irqs);

void hinic5_dump_ceq_info(struct hinic5_hwdev *hwdev);

void hinic5_dump_aeq_info(struct hinic5_hwdev *hwdev);

int hinic5_reschedule_eq(struct hinic5_hwdev *hwdev, enum hinic5_eq_type type,
			 u16 eq_id);

int hinic5_init_stateless_aeqs(void *hwdev);

void hinic5_stateless_aeqs_free(void *hwdev);

u8 hinic5_nic_sw_aeqe_handler(void *hwdev, u8 event, u8 *data);

#if defined(__UEFI__) || defined(__VMWARE__)
void hinic5_simulated_irq_aeq(struct hinic5_hwdev *hwdev);
#elif defined(__WIN__)
bool hinic5_eq_intr_handler(void *hwdev, int msix_entry_idx);
#endif

#endif
