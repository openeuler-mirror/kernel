/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_eqs.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#ifndef __UEFI__
#include <linux/cpumask.h>
#endif

#include "hinic5_vram_common.h"

#include "ossl_knl.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_common.h"
#include "hinic5_hwdev.h"
#include "hinic5_hwif_inner.h"
#include "hinic5_hw.h"
#include "hinic5_csr_inner.h"
#include "hinic5_hw_comm.h"
#include "hinic5_prof_adap.h"
#include "hinic5_eqs.h"

#define HINIC5_EQS_WQ_NAME			"hinic5_eqs"

#define AEQ_CTRL_0_INTR_IDX_SHIFT		0
#define AEQ_CTRL_0_DMA_ATTR_SHIFT		12
#define AEQ_CTRL_0_PCI_INTF_IDX_SHIFT		20
#define AEQ_CTRL_0_INTR_MODE_SHIFT		31

#define AEQ_CTRL_0_INTR_IDX_MASK		0x3FFU
#define AEQ_CTRL_0_DMA_ATTR_MASK		0x3FU
#define AEQ_CTRL_0_PCI_INTF_IDX_MASK		0x7U
#define AEQ_CTRL_0_INTR_MODE_MASK		0x1U

#define AEQ_CTRL_0_SET(val, member)		\
			(((val) & AEQ_CTRL_0_##member##_MASK) << \
			 AEQ_CTRL_0_##member##_SHIFT)

#define AEQ_CTRL_0_CLEAR(val, member)		\
			((val) & (~(AEQ_CTRL_0_##member##_MASK << \
				    AEQ_CTRL_0_##member##_SHIFT)))

#define AEQ_CTRL_1_LEN_SHIFT			0
#define AEQ_CTRL_1_ELEM_SIZE_SHIFT		24
#define AEQ_CTRL_1_PAGE_SIZE_SHIFT		28

#define AEQ_CTRL_1_LEN_MASK			0x1FFFFFU
#define AEQ_CTRL_1_ELEM_SIZE_MASK		0x3U
#define AEQ_CTRL_1_PAGE_SIZE_MASK		0xFU

#define AEQ_CTRL_1_SET(val, member)		\
			(((val) & AEQ_CTRL_1_##member##_MASK) << \
			 AEQ_CTRL_1_##member##_SHIFT)

#define AEQ_CTRL_1_CLEAR(val, member)		\
			((val) & (~(AEQ_CTRL_1_##member##_MASK << \
				    AEQ_CTRL_1_##member##_SHIFT)))

#define HINIC5_EQ_PROD_IDX_MASK			0xFFFFF
#define HINIC5_TASK_PROCESS_EQE_LIMIT		1024
#define HINIC5_EQ_UPDATE_CI_STEP		64

static u32 g_aeq_len = HINIC5_DEFAULT_AEQ_LEN;
module_param(g_aeq_len, uint, 0444);
MODULE_PARM_DESC(g_aeq_len,
		 "aeq depth, valid range is " __stringify(HINIC5_MIN_AEQ_LEN)
		 " - " __stringify(HINIC5_MAX_AEQ_LEN));

static u32 g_ceq_len = HINIC5_DEFAULT_CEQ_LEN;
module_param(g_ceq_len, uint, 0444);
MODULE_PARM_DESC(g_ceq_len,
		 "ceq depth, valid range is " __stringify(HINIC5_MIN_CEQ_LEN)
		 " - " __stringify(HINIC5_MAX_CEQ_LEN));

static u32 g_num_ceqe_in_tasklet = HINIC5_TASK_PROCESS_EQE_LIMIT;
module_param(g_num_ceqe_in_tasklet, uint, 0444);
MODULE_PARM_DESC(g_num_ceqe_in_tasklet,
		 "The max number of ceqe can be processed in tasklet, default = 1024");

static int g_aeq_cpu_affinity[HINIC5_AEQ_CPU_AFFINITY_MAX];
static unsigned int g_aeq_cpu_affinity_nargs;
module_param_array_named(aeq_cpu_affinity, g_aeq_cpu_affinity,
			 int, &g_aeq_cpu_affinity_nargs, 0444);
MODULE_PARM_DESC(aeq_cpu_affinity, "Aeqs cpu affinity, max num 16");

#define CEQ_CTRL_0_INTR_IDX_SHIFT		0
#define CEQ_CTRL_0_DMA_ATTR_SHIFT		12
#define CEQ_CTRL_0_LIMIT_KICK_SHIFT		20
#define CEQ_CTRL_0_PCI_INTF_IDX_SHIFT		24
#define CEQ_CTRL_0_PAGE_SIZE_SHIFT		27
#define CEQ_CTRL_0_INTR_MODE_SHIFT		31

#define CEQ_CTRL_0_INTR_IDX_MASK		0x3FFU
#define CEQ_CTRL_0_DMA_ATTR_MASK		0x3FU
#define CEQ_CTRL_0_LIMIT_KICK_MASK		0xFU
#define CEQ_CTRL_0_PCI_INTF_IDX_MASK		0x7U
#define CEQ_CTRL_0_PAGE_SIZE_MASK		0xF
#define CEQ_CTRL_0_INTR_MODE_MASK		0x1U

#define CEQ_CTRL_0_SET(val, member)		\
			(((val) & CEQ_CTRL_0_##member##_MASK) << \
			 CEQ_CTRL_0_##member##_SHIFT)

#define CEQ_CTRL_1_LEN_SHIFT			0
#define CEQ_CTRL_1_GLB_FUNC_ID_SHIFT		20

#define CEQ_CTRL_1_LEN_MASK			0xFFFFFU
#define CEQ_CTRL_1_GLB_FUNC_ID_MASK		0xFFFU

#define CEQ_CTRL_1_SET(val, member)		\
			(((val) & CEQ_CTRL_1_##member##_MASK) << \
			 CEQ_CTRL_1_##member##_SHIFT)

#define EQ_ELEM_DESC_TYPE_SHIFT			0
#define EQ_ELEM_DESC_SRC_SHIFT			7
#define EQ_ELEM_DESC_SIZE_SHIFT			8
#define EQ_ELEM_DESC_WRAPPED_SHIFT		31

#define EQ_ELEM_DESC_TYPE_MASK			0x7FU
#define EQ_ELEM_DESC_SRC_MASK			0x1U
#define EQ_ELEM_DESC_SIZE_MASK			0xFFU
#define EQ_ELEM_DESC_WRAPPED_MASK		0x1U

#define EQ_ELEM_DESC_GET(val, member)		\
			(((val) >> EQ_ELEM_DESC_##member##_SHIFT) & \
			 EQ_ELEM_DESC_##member##_MASK)

#define EQ_CONS_IDX_CONS_IDX_SHIFT		0
#define EQ_CONS_IDX_INT_ARMED_SHIFT		31

#define EQ_CONS_IDX_CONS_IDX_MASK		0x1FFFFFU
#define EQ_CONS_IDX_INT_ARMED_MASK		0x1U

#define EQ_CONS_IDX_SET(val, member)		\
			(((val) & EQ_CONS_IDX_##member##_MASK) << \
			 EQ_CONS_IDX_##member##_SHIFT)

#define EQ_CONS_IDX_CLEAR(val, member)		\
			((val) & (~(EQ_CONS_IDX_##member##_MASK << \
				    EQ_CONS_IDX_##member##_SHIFT)))

#define EQ_CI_SIMPLE_INDIR_CI_SHIFT		0
#define EQ_CI_SIMPLE_INDIR_ARMED_SHIFT		21
#define EQ_CI_SIMPLE_INDIR_AEQ_IDX_SHIFT	30
#define EQ_CI_SIMPLE_INDIR_CEQ_IDX_SHIFT	24

#define EQ_CI_SIMPLE_INDIR_CI_MASK		0x1FFFFFU
#define EQ_CI_SIMPLE_INDIR_ARMED_MASK		0x1U
#define EQ_CI_SIMPLE_INDIR_AEQ_IDX_MASK		0x3U
#define EQ_CI_SIMPLE_INDIR_CEQ_IDX_MASK		0xFFU

#define EQ_CI_SIMPLE_INDIR_SET(val, member)		\
			(((val) & EQ_CI_SIMPLE_INDIR_##member##_MASK) << \
			 EQ_CI_SIMPLE_INDIR_##member##_SHIFT)

#define EQ_CI_SIMPLE_INDIR_CLEAR(val, member)		\
			((val) & (~(EQ_CI_SIMPLE_INDIR_##member##_MASK << \
				    EQ_CI_SIMPLE_INDIR_##member##_SHIFT)))

#define EQ_WRAPPED(eq)	((u32)(eq)->wrapped << EQ_VALID_SHIFT)

#define EQ_CONS_IDX(eq)	((eq)->cons_idx | \
			 ((u32)(eq)->wrapped << EQ_WRAPPED_SHIFT))

#define EQ_CONS_IDX_REG_ADDR(eq)	\
			(((eq)->type == HINIC5_AEQ) ? \
			 HINIC5_CSR_AEQ_CONS_IDX_ADDR : \
			 HINIC5_CSR_CEQ_CONS_IDX_ADDR)
#define EQ_CI_SIMPLE_INDIR_REG_ADDR(eq)	\
			(((eq)->type == HINIC5_AEQ) ? \
			 HINIC5_CSR_AEQ_CI_SIMPLE_INDIR_ADDR : \
			 HINIC5_CSR_CEQ_CI_SIMPLE_INDIR_ADDR)

#define EQ_PROD_IDX_REG_ADDR(eq)	\
			(((eq)->type == HINIC5_AEQ) ? \
			 HINIC5_CSR_AEQ_PROD_IDX_ADDR : \
			 HINIC5_CSR_CEQ_PROD_IDX_ADDR)

#define HINIC5_EQ_HI_PHYS_ADDR_REG(type, pg_num)	\
			((u32)((type == HINIC5_AEQ) ? \
			 HINIC5_AEQ_HI_PHYS_ADDR_REG(pg_num) : \
			 HINIC5_CEQ_HI_PHYS_ADDR_REG(pg_num)))

#define HINIC5_EQ_LO_PHYS_ADDR_REG(type, pg_num)	\
			((u32)((type == HINIC5_AEQ) ? \
			 HINIC5_AEQ_LO_PHYS_ADDR_REG(pg_num) : \
			 HINIC5_CEQ_LO_PHYS_ADDR_REG(pg_num)))

#define GET_EQ_NUM_PAGES(eq, size)	\
			((u16)(ALIGN((u32)((eq)->eq_len * (eq)->elem_size), \
				     (size)) / (size)))

#define HINIC5_EQ_MAX_PAGES(eq)		\
			((eq)->type == HINIC5_AEQ ? HINIC5_AEQ_MAX_PAGES : \
			 HINIC5_CEQ_MAX_PAGES)

#define GET_EQ_NUM_ELEMS(eq, pg_size)	((pg_size) / (u32)(eq)->elem_size)

#define GET_EQ_ELEMENT(eq, idx)		\
	(((u8 *)(eq)->eq_pages[(idx) / (eq)->num_elem_in_pg].align_vaddr) + \
	 (u32)(((idx) & ((eq)->num_elem_in_pg - 1)) * (eq)->elem_size))

#define GET_AEQ_ELEM(eq, idx)		\
			((struct hinic5_aeq_elem *)GET_EQ_ELEMENT((eq), (idx)))

#define GET_CEQ_ELEM(eq, idx)		((u32 *)GET_EQ_ELEMENT((eq), (idx)))

#define GET_CURR_AEQ_ELEM(eq)		GET_AEQ_ELEM((eq), (eq)->cons_idx)

#define GET_CURR_CEQ_ELEM(eq)		GET_CEQ_ELEM((eq), (eq)->cons_idx)

#define PAGE_IN_4K(page_size)		((page_size) >> 12)
#define EQ_SET_HW_PAGE_SIZE_VAL(eq)	\
			((u32)ilog2(PAGE_IN_4K((eq)->page_size)))

#define ELEMENT_SIZE_IN_32B(eq)		(((eq)->elem_size) >> 5)
#define EQ_SET_HW_ELEM_SIZE_VAL(eq)	((u32)ilog2(ELEMENT_SIZE_IN_32B(eq)))

#define AEQ_DMA_ATTR_DEFAULT			0
#define CEQ_DMA_ATTR_DEFAULT			0

#define CEQ_LMT_KICK_DEFAULT			0

#define EQ_MSIX_RESEND_TIMER_CLEAR		1

#define EQ_WRAPPED_SHIFT			20

#define	EQ_VALID_SHIFT				31

#define CEQE_TYPE_SHIFT				23
#define CEQE_TYPE_MASK				0x7

#define CEQE_TYPE(type)			(((type) >> CEQE_TYPE_SHIFT) & \
					 CEQE_TYPE_MASK)

#define CEQE_DATA_MASK				0x3FFFFFF
#define CEQE_DATA(data)				((data) & CEQE_DATA_MASK)

#define aeq_to_aeqs(eq) \
		container_of((eq) - (eq)->q_id, struct hinic5_aeqs, aeq[0])

#define ceq_to_ceqs(eq) \
		container_of((eq) - (eq)->q_id, struct hinic5_ceqs, ceq[0])

#ifdef __VMWARE__
static void ceq_interrupt(void *data, u32 irq);
static void aeq_interrupt(void *data, u32 irq);
#else
static irqreturn_t ceq_interrupt(int irq, void *data);
static irqreturn_t aeq_interrupt(int irq, void *data);
#endif

static void ceq_tasklet(ulong ceq_data);

/**
 * hinic5_aeq_register_hw_cb - register aeq callback for specific event
 * @hwdev: the pointer to hw device
 * @pri_handle: the pointer to private invoker device
 * @event: event for the handler
 * @hw_cb: callback function
 **/
int hinic5_aeq_register_hw_cb(void *hwdev, void *pri_handle, enum hinic5_aeq_type event,
			      hinic5_aeq_hwe_cb hwe_cb)
{
	struct hinic5_aeqs *aeqs = NULL;

	if (!hwdev || !hwe_cb || event >= HINIC5_MAX_AEQ_EVENTS)
		return -EINVAL;

	aeqs = ((struct hinic5_hwdev *)hwdev)->aeqs;
	if (!aeqs)
		return -EINVAL;

	aeqs->aeq_hwe_cb[event] = hwe_cb;
	aeqs->aeq_hwe_cb_data[event] = pri_handle;

	set_bit(HINIC5_AEQ_HW_CB_REG, &aeqs->aeq_hw_cb_state[event]);

	return 0;
}

/**
 * hinic5_aeq_unregister_hw_cb - unregister the aeq callback for specific event
 * @hwdev: the pointer to hw device
 * @event: event for the handler
 **/
void hinic5_aeq_unregister_hw_cb(void *hwdev, enum hinic5_aeq_type event)
{
	struct hinic5_aeqs *aeqs = NULL;

	if (!hwdev || event >= HINIC5_MAX_AEQ_EVENTS)
		return;

	aeqs = ((struct hinic5_hwdev *)hwdev)->aeqs;
	if (!aeqs) {
		pr_err("aeqs is null\n");
		return;
	}

	clear_bit(HINIC5_AEQ_HW_CB_REG, &aeqs->aeq_hw_cb_state[event]);

	while (test_bit(HINIC5_AEQ_HW_CB_RUNNING,
			&aeqs->aeq_hw_cb_state[event]))
		usleep_range(EQ_USLEEP_LOW_BOUND, EQ_USLEEP_HIG_BOUND);

	aeqs->aeq_hwe_cb[event] = NULL;
}

/**
 * hinic5_aeq_register_swe_cb - register aeq callback for sw event
 * @hwdev: the pointer to hw device
 * @pri_handle: the pointer to private invoker device
 * @event: soft event for the handler
 * @sw_cb: callback function
 **/
int hinic5_aeq_register_swe_cb(void *hwdev, void *pri_handle, enum hinic5_aeq_sw_type event,
			       hinic5_aeq_swe_cb aeq_swe_cb)
{
	struct hinic5_aeqs *aeqs = NULL;

	if (!hwdev || !aeq_swe_cb || event >= HINIC5_MAX_AEQ_SW_EVENTS)
		return -EINVAL;

	aeqs = ((struct hinic5_hwdev *)hwdev)->aeqs;
	if (!aeqs)
		return -EINVAL;

	aeqs->aeq_swe_cb[event] = aeq_swe_cb;
	aeqs->aeq_swe_cb_data[event] = pri_handle;

	set_bit(HINIC5_AEQ_SW_CB_REG, &aeqs->aeq_sw_cb_state[event]);

	return 0;
}

/**
 * hinic5_aeq_unregister_swe_cb - unregister the aeq callback for sw event
 * @hwdev: the pointer to hw device
 * @event: soft event for the handler
 **/
void hinic5_aeq_unregister_swe_cb(void *hwdev, enum hinic5_aeq_sw_type event)
{
	struct hinic5_aeqs *aeqs = NULL;

	if (!hwdev || event >= HINIC5_MAX_AEQ_SW_EVENTS)
		return;

	aeqs = ((struct hinic5_hwdev *)hwdev)->aeqs;
	if (!aeqs) {
		pr_err("aeqs is null\n");
		return;
	}

	clear_bit(HINIC5_AEQ_SW_CB_REG, &aeqs->aeq_sw_cb_state[event]);

	while (test_bit(HINIC5_AEQ_SW_CB_RUNNING,
			&aeqs->aeq_sw_cb_state[event]))
		usleep_range(EQ_USLEEP_LOW_BOUND, EQ_USLEEP_HIG_BOUND);

	aeqs->aeq_swe_cb[event] = NULL;
}

/**
 * hinic5_ceq_register_cb - register ceq callback for specific event
 * @hwdev: the pointer to hw device
 * @pri_handle: the pointer to private invoker device
 * @event: event for the handler
 * @ceq_cb: callback function
 **/
int hinic5_ceq_register_cb(void *hwdev, void *pri_handle, enum hinic5_ceq_event event,
			   hinic5_ceq_event_cb callback)
{
	struct hinic5_ceqs *ceqs = NULL;

#ifdef __UEFI__
	return 0;
#endif

	if (!hwdev || event >= HINIC5_MAX_CEQ_EVENTS)
		return -EINVAL;

	ceqs = ((struct hinic5_hwdev *)hwdev)->ceqs;
	if (!ceqs)
		return 0;

	ceqs->ceq_cb[event] = callback;
	ceqs->ceq_cb_data[event] = pri_handle;

	set_bit(HINIC5_CEQ_CB_REG, &ceqs->ceq_cb_state[event]);

	return 0;
}
EXPORT_SYMBOL(hinic5_ceq_register_cb);

/**
 * hinic5_ceq_unregister_cb - unregister ceq callback for specific event
 * @hwdev: the pointer to hw device
 * @event: event for the handler
 **/
void hinic5_ceq_unregister_cb(void *hwdev, enum hinic5_ceq_event event)
{
	struct hinic5_ceqs *ceqs = NULL;

#ifdef __UEFI__
	return;
#endif

	if (!hwdev || event >= HINIC5_MAX_CEQ_EVENTS)
		return;

	ceqs = ((struct hinic5_hwdev *)hwdev)->ceqs;
	if (!ceqs)
		return;

	clear_bit(HINIC5_CEQ_CB_REG, &ceqs->ceq_cb_state[event]);

	while (test_bit(HINIC5_CEQ_CB_RUNNING, &ceqs->ceq_cb_state[event]))
		usleep_range(EQ_USLEEP_LOW_BOUND, EQ_USLEEP_HIG_BOUND);

	ceqs->ceq_cb[event] = NULL;
}
EXPORT_SYMBOL(hinic5_ceq_unregister_cb);

/**
 * set_eq_cons_idx - write the cons idx to the hw
 * @eq: The event queue to update the cons idx for
 * @cons idx: consumer index value
 **/
static void set_eq_cons_idx(struct hinic5_eq *eq, u32 arm_state)
{
	u32 eq_wrap_ci, val;
	u32 addr = EQ_CI_SIMPLE_INDIR_REG_ADDR(eq);

	eq_wrap_ci = EQ_CONS_IDX(eq);

#ifndef __UEFI__
	/* if use poll mode only eq0 use int_arm mode */
	if (eq->q_id != 0 && eq->hwdev->poll)
		val = EQ_CI_SIMPLE_INDIR_SET(HINIC5_EQ_NOT_ARMED, ARMED);
	else
#endif
		val = EQ_CI_SIMPLE_INDIR_SET(arm_state, ARMED);
	if (eq->type == HINIC5_AEQ) {
		val = val |
			EQ_CI_SIMPLE_INDIR_SET(eq_wrap_ci, CI) |
			EQ_CI_SIMPLE_INDIR_SET(eq->q_id, AEQ_IDX);
	} else {
		val = val |
			EQ_CI_SIMPLE_INDIR_SET(eq_wrap_ci, CI) |
			EQ_CI_SIMPLE_INDIR_SET(eq->q_id, CEQ_IDX);
	}

	hinic5_hwif_write_reg(eq->hwdev->hwif, addr, val);
}

/**
 * ceq_event_handler - handle for the ceq events
 * @ceqs: ceqs part of the chip
 * @ceqe: ceq element of the event
 **/
static void ceq_event_handler(struct hinic5_ceqs *ceqs, u32 ceqe)
{
	struct hinic5_hwdev *hwdev = ceqs->hwdev;
	enum hinic5_ceq_event event = CEQE_TYPE(ceqe);
	u32 ceqe_data = CEQE_DATA(ceqe);

	if (event >= HINIC5_MAX_CEQ_EVENTS) {
		sdk_err(hwdev->dev_hdl, "Ceq unknown event:%d, ceqe date: 0x%x\n",
			event, ceqe_data);
		return;
	}

	set_bit(HINIC5_CEQ_CB_RUNNING, &ceqs->ceq_cb_state[event]);

	if (ceqs->ceq_cb[event] &&
	    test_bit(HINIC5_CEQ_CB_REG, &ceqs->ceq_cb_state[event]))
		ceqs->ceq_cb[event](ceqs->ceq_cb_data[event], ceqe_data);

	clear_bit(HINIC5_CEQ_CB_RUNNING, &ceqs->ceq_cb_state[event]);
}

static void aeq_elem_handler(struct hinic5_eq *eq, u32 aeqe_desc)
{
	struct hinic5_aeqs *aeqs = aeq_to_aeqs(eq);
	struct hinic5_aeq_elem *aeqe_pos = NULL;
	enum hinic5_aeq_type event;
	enum hinic5_aeq_sw_type sw_type;
	u32 sw_event;
	u8 data[HINIC5_AEQE_DATA_SIZE], size;

	aeqe_pos = GET_CURR_AEQ_ELEM(eq);

	eq->hwdev->cur_recv_aeq_cnt++;

	event = EQ_ELEM_DESC_GET(aeqe_desc, TYPE);
	if (EQ_ELEM_DESC_GET(aeqe_desc, SRC) != 0) {
		sw_event = event;
		sw_type = sw_event >= HINIC5_NIC_FATAL_ERROR_MAX ?
			   HINIC5_STATEFUL_EVENT : HINIC5_STATELESS_EVENT;
		/* SW event uses only the first 8B */
		memcpy(data, aeqe_pos->aeqe_data, HINIC5_AEQE_DATA_SIZE);
		hinic5_be32_to_cpu(data, HINIC5_AEQE_DATA_SIZE);
		set_bit(HINIC5_AEQ_SW_CB_RUNNING,
			&aeqs->aeq_sw_cb_state[sw_type]);
		if (aeqs->aeq_swe_cb[sw_type] &&
		    test_bit(HINIC5_AEQ_SW_CB_REG,
			     &aeqs->aeq_sw_cb_state[sw_type]))
			aeqs->aeq_swe_cb[sw_type](aeqs->aeq_swe_cb_data[sw_type], event, data);

		clear_bit(HINIC5_AEQ_SW_CB_RUNNING,
			  &aeqs->aeq_sw_cb_state[sw_type]);
		return;
	}

	if (event < HINIC5_MAX_AEQ_EVENTS) {
		memcpy(data, aeqe_pos->aeqe_data, HINIC5_AEQE_DATA_SIZE);
		hinic5_be32_to_cpu(data, HINIC5_AEQE_DATA_SIZE);

		size = EQ_ELEM_DESC_GET(aeqe_desc, SIZE);
		set_bit(HINIC5_AEQ_HW_CB_RUNNING,
			&aeqs->aeq_hw_cb_state[event]);
		if (aeqs->aeq_hwe_cb[event] &&
		    test_bit(HINIC5_AEQ_HW_CB_REG,
			     &aeqs->aeq_hw_cb_state[event]))
			aeqs->aeq_hwe_cb[event](aeqs->aeq_hwe_cb_data[event], data, size);
		clear_bit(HINIC5_AEQ_HW_CB_RUNNING,
			  &aeqs->aeq_hw_cb_state[event]);
		return;
	}
	sdk_warn(eq->hwdev->dev_hdl, "Unknown aeq hw event %d\n", event);
}

/**
 * aeq_irq_handler - handler for the aeq event
 * @eq: the async event queue of the event
 **/
static bool aeq_irq_handler(struct hinic5_eq *eq)
{
	struct hinic5_aeq_elem *aeqe_pos = NULL;
	u32 aeqe_desc;
	u32 i, eqe_cnt = 0;

	for (i = 0; i < HINIC5_TASK_PROCESS_EQE_LIMIT; i++) {
		aeqe_pos = GET_CURR_AEQ_ELEM(eq);

		/* Data in HW is in Big endian Format */
		aeqe_desc = be32_to_cpu(aeqe_pos->desc);

		/* HW updates wrapped bit, when it adds eq element event */
		if (EQ_ELEM_DESC_GET(aeqe_desc, WRAPPED) == eq->wrapped)
			return false;

		dma_rmb();

		aeq_elem_handler(eq, aeqe_desc);

		eq->cons_idx++;

		if (eq->cons_idx == eq->eq_len) {
			eq->cons_idx = 0;
			eq->wrapped = (eq->wrapped == 0);
		}

		if (++eqe_cnt >= HINIC5_EQ_UPDATE_CI_STEP) {
			eqe_cnt = 0;
			set_eq_cons_idx(eq, HINIC5_EQ_NOT_ARMED);
		}
	}

	return true;
}

/**
 * ceq_irq_handler - handler for the ceq event
 * @eq: the completion event queue of the event
 **/
static bool ceq_irq_handler(struct hinic5_eq *eq)
{
	struct hinic5_ceqs *ceqs = ceq_to_ceqs(eq);
	u32 ceqe, eqe_cnt = 0;
	u32 i;

	for (i = 0; i < g_num_ceqe_in_tasklet; i++) {
		ceqe = *(GET_CURR_CEQ_ELEM(eq));
		ceqe = be32_to_cpu(ceqe);

		/* HW updates wrapped bit, when it adds eq element event */
		if (EQ_ELEM_DESC_GET(ceqe, WRAPPED) == eq->wrapped)
			return false;

		ceq_event_handler(ceqs, ceqe);

		eq->cons_idx++;

		if (eq->cons_idx == eq->eq_len) {
			eq->cons_idx = 0;
			eq->wrapped = (eq->wrapped == 0);
		}

		if (++eqe_cnt >= HINIC5_EQ_UPDATE_CI_STEP) {
			eqe_cnt = 0;
			set_eq_cons_idx(eq, HINIC5_EQ_NOT_ARMED);
		}
	}

	return true;
}

static void reschedule_eq_handler(struct hinic5_eq *eq)
{
	if (eq->type == HINIC5_AEQ) {
		struct hinic5_aeqs *aeqs = aeq_to_aeqs(eq);

		queue_work_on(hisdk5_get_work_cpu_affinity(eq->hwdev, WORK_TYPE_AEQ),
			      aeqs->workq, &eq->aeq_work);
	} else {
		tasklet_schedule(&eq->ceq_tasklet);
	}
}

int hinic5_reschedule_eq(struct hinic5_hwdev *hwdev, enum hinic5_eq_type type,
			 u16 eq_id)
{
	if (type == HINIC5_AEQ) {
		if (eq_id >= hwdev->aeqs->num_aeqs)
			return -EINVAL;

		reschedule_eq_handler(&hwdev->aeqs->aeq[eq_id]);
	} else {
		if (eq_id >= hwdev->ceqs->num_ceqs)
			return -EINVAL;

		reschedule_eq_handler(&hwdev->ceqs->ceq[eq_id]);
	}

	return 0;
}

/**
 * eq_irq_handler - handler for the eq event
 * @data: the event queue of the event
 **/
static bool eq_irq_handler(void *data)
{
	struct hinic5_eq *eq = (struct hinic5_eq *)data;
	bool uncompleted = false;

	if (eq->type == HINIC5_AEQ)
		uncompleted = aeq_irq_handler(eq);
	else
		uncompleted = ceq_irq_handler(eq);

	set_eq_cons_idx(eq, uncompleted ? HINIC5_EQ_NOT_ARMED :
			HINIC5_EQ_ARMED);

	return uncompleted;
}

#if defined(__UEFI__) || defined(__VMWARE__)
void hinic5_simulated_irq_aeq(struct hinic5_hwdev *hwdev)
{
	struct hinic5_aeqs *aeqs = NULL;
	struct hinic5_eq *eq = NULL;
	int q_id;

	if (!hwdev)
		return;

	aeqs = hwdev->aeqs;

	for (q_id = 0; q_id < aeqs->num_aeqs; q_id++) {
		eq = &aeqs->aeq[q_id];

		if (eq->type != HINIC5_AEQ)
			break;
		eq_irq_handler(eq);
	}
}
#elif defined(__WIN__)

static struct hinic5_eq *find_eq(struct hinic5_hwdev *hwdev, int msix_entry_idx)
{
	struct hinic5_aeqs *aeqs = hwdev->aeqs;
	struct hinic5_ceqs *ceqs = hwdev->ceqs;
	int i;

	for (i = 0; i < aeqs->num_aeqs; i++) {
		struct hinic5_eq *eq = &aeqs->aeq[i];

		if (eq->eq_irq.msix_entry_idx == msix_entry_idx)
			return eq;
	}

	if (!ceqs)
		return NULL;

	for (i = 0; i < ceqs->num_ceqs; i++) {
		struct hinic5_eq *eq = &ceqs->ceq[i];

		if (eq->eq_irq.msix_entry_idx == msix_entry_idx)
			return eq;
	}

	return NULL;
}

/* for windows */
bool hinic5_eq_intr_handler(void *hwdev, int msix_entry_idx)
{
	struct hinic5_eq *eq;

	eq = find_eq(hwdev, msix_entry_idx);
	if (!eq) {
		pr_err("Can't find eq in eq interrupt handler\n");
		return false;
	}

	return eq_irq_handler(eq);
}
#endif

/**
 * eq_irq_work - eq work for the event
 * @work: the work that is associated with the eq
 **/
static void eq_irq_work(struct work_struct *work)
{
	struct hinic5_eq *eq = container_of(work, struct hinic5_eq, aeq_work);

	if (eq_irq_handler(eq))
		reschedule_eq_handler(eq);
}

/**
 * aeq_interrupt - aeq interrupt handler
 * @irq: irq number
 * @data: the async event queue of the event
 **/
#ifdef __VMWARE__
static void aeq_interrupt(void *data, u32 irq)
#else
static irqreturn_t aeq_interrupt(int irq, void *data)
#endif
{
	struct hinic5_eq *aeq = (struct hinic5_eq *)data;
	struct hinic5_hwdev *hwdev = aeq->hwdev;
	struct hinic5_aeqs *aeqs = aeq_to_aeqs(aeq);
	struct workqueue_struct *workq = aeqs->workq;
	int cpu;

	/* clear resend timer cnt register */
	hinic5_misx_intr_clear_resend_bit(hwdev, aeq->eq_irq.msix_entry_idx,
					  EQ_MSIX_RESEND_TIMER_CLEAR);

	cpu = hisdk5_get_work_cpu_affinity(hwdev, WORK_TYPE_AEQ);
	if (cpu == WORK_CPU_UNBOUND)
		cpu = aeq->cpu;

	queue_work_on(cpu, workq, &aeq->aeq_work);

#ifdef __VMWARE__
	return;
#else
	return IRQ_HANDLED;
#endif
}

/**
 * ceq_tasklet - ceq tasklet for the event
 * @ceq_data: data that will be used by the tasklet(ceq)
 **/
static void ceq_tasklet(ulong ceq_data)
{
	struct hinic5_eq *eq = (struct hinic5_eq *)(uintptr_t)ceq_data;

	eq->soft_intr_jif = jiffies;

	if (eq_irq_handler(eq))
		reschedule_eq_handler(eq);
}

/**
 * ceq_interrupt - ceq interrupt handler
 * @irq: irq number
 * @data: the completion event queue of the event
 **/
#ifdef __VMWARE__
static void ceq_interrupt(void *data, u32 irq)
#else
static irqreturn_t ceq_interrupt(int irq, void *data)
#endif
{
	struct hinic5_eq *ceq = (struct hinic5_eq *)data;

	ceq->hard_intr_jif = jiffies;

	/* clear resend timer counters */
	hinic5_misx_intr_clear_resend_bit(ceq->hwdev,
					  ceq->eq_irq.msix_entry_idx,
					  EQ_MSIX_RESEND_TIMER_CLEAR);

	tasklet_schedule(&ceq->ceq_tasklet);

#ifdef __VMWARE__
	return;
#else
	return IRQ_HANDLED;
#endif
}

/**
 * set_eq_ctrls - setting eq's ctrls registers
 * @eq: the event queue for setting
 **/
static int set_eq_ctrls(struct hinic5_eq *eq)
{
	enum hinic5_eq_type type = eq->type;
	struct hinic5_hwif *hwif = eq->hwdev->hwif;
	struct irq_info *eq_irq = &eq->eq_irq;
	u32 addr, val, ctrl0, ctrl1, page_size_val, elem_size;
	u32 pci_intf_idx = HINIC5_PCI_INTF_IDX(hwif);
	int err;

	if (type == HINIC5_AEQ) {
		/* set ctrl0 */
		addr = HINIC5_CSR_AEQ_CTRL_0_ADDR;

		val = hinic5_hwif_read_reg(hwif, addr);

		val = AEQ_CTRL_0_CLEAR(val, INTR_IDX) &
			AEQ_CTRL_0_CLEAR(val, DMA_ATTR) &
			AEQ_CTRL_0_CLEAR(val, PCI_INTF_IDX) &
			AEQ_CTRL_0_CLEAR(val, INTR_MODE);

		ctrl0 = AEQ_CTRL_0_SET(eq_irq->msix_entry_idx, INTR_IDX) |
			AEQ_CTRL_0_SET(AEQ_DMA_ATTR_DEFAULT, DMA_ATTR) |
			AEQ_CTRL_0_SET(pci_intf_idx, PCI_INTF_IDX) |
			AEQ_CTRL_0_SET(HINIC5_INTR_MODE_ARMED, INTR_MODE);

		val |= ctrl0;

		hinic5_hwif_write_reg(hwif, addr, val);

		/* set ctrl1 */
		addr = HINIC5_CSR_AEQ_CTRL_1_ADDR;

		page_size_val = EQ_SET_HW_PAGE_SIZE_VAL(eq);
		elem_size = EQ_SET_HW_ELEM_SIZE_VAL(eq);

		ctrl1 = AEQ_CTRL_1_SET(eq->eq_len, LEN)	|
			AEQ_CTRL_1_SET(elem_size, ELEM_SIZE)	|
			AEQ_CTRL_1_SET(page_size_val, PAGE_SIZE);

		hinic5_hwif_write_reg(hwif, addr, ctrl1);
	} else {
		page_size_val = EQ_SET_HW_PAGE_SIZE_VAL(eq);
		ctrl0 = CEQ_CTRL_0_SET(eq_irq->msix_entry_idx, INTR_IDX) |
			CEQ_CTRL_0_SET(CEQ_DMA_ATTR_DEFAULT, DMA_ATTR)	|
			CEQ_CTRL_0_SET(CEQ_LMT_KICK_DEFAULT, LIMIT_KICK) |
			CEQ_CTRL_0_SET(pci_intf_idx, PCI_INTF_IDX) |
			CEQ_CTRL_0_SET(page_size_val, PAGE_SIZE) |
			CEQ_CTRL_0_SET(HINIC5_INTR_MODE_ARMED, INTR_MODE);

		ctrl1 = CEQ_CTRL_1_SET(eq->eq_len, LEN);

		/* set ceq ctrl reg through mgmt cpu */
		err = hinic5_set_ceq_ctrl_reg(eq->hwdev, eq->q_id, ctrl0,
					      ctrl1);
		if (err != 0)
			return err;
	}

	return 0;
}

/**
 * ceq_elements_init - Initialize all the elements in the ceq
 * @eq: the event queue
 * @init_val: value to init with it the elements
 **/
static void ceq_elements_init(struct hinic5_eq *eq, u32 init_val)
{
	u32 *ceqe = NULL;
	u32 i;

	for (i = 0; i < eq->eq_len; i++) {
		ceqe = GET_CEQ_ELEM(eq, i);
		*(ceqe) = cpu_to_be32(init_val);
	}

	wmb();    /* Write the init values */
}

/**
 * aeq_elements_init - initialize all the elements in the aeq
 * @eq: the event queue
 * @init_val: value to init with it the elements
 **/
static void aeq_elements_init(struct hinic5_eq *eq, u32 init_val)
{
	struct hinic5_aeq_elem *aeqe = NULL;
	u32 i;

	for (i = 0; i < eq->eq_len; i++) {
		aeqe = GET_AEQ_ELEM(eq, i);
		aeqe->desc = cpu_to_be32(init_val);
	}

	wmb();   /* Write the init values */
}

static void eq_elements_init(struct hinic5_eq *eq, u32 init_val)
{
	if (eq->type == HINIC5_AEQ)
		aeq_elements_init(eq, init_val);
	else
		ceq_elements_init(eq, init_val);
}

/**
 * alloc_eq_pages - allocate the pages for the queue
 * @eq: the event queue
 **/
static int alloc_eq_pages(struct hinic5_eq *eq)
{
	struct hinic5_hwif *hwif = eq->hwdev->hwif;
	struct hinic5_dma_addr_align *eq_page = NULL;
	u32 reg, init_val;
	u16 pg_idx, i;
	int err;
	gfp_t gfp_hinic5_vram;

	eq->eq_pages = kcalloc(eq->num_pages, sizeof(*eq->eq_pages),
			       GFP_KERNEL);
	if (!eq->eq_pages)
		return -ENOMEM;

	gfp_hinic5_vram = hinic5_hinic5_vram_get_gfp_hinic5_vram();

	for (pg_idx = 0; pg_idx < eq->num_pages; pg_idx++) {
		eq_page = &eq->eq_pages[pg_idx];
		err = hinic5_dma_zalloc_coherent_align(eq->hwdev->dev_hdl,
						       eq->page_size,
						       HINIC5_MIN_EQ_PAGE_SIZE,
						       GFP_KERNEL | gfp_hinic5_vram,
						       eq_page);
		if (err != 0) {
			sdk_err(eq->hwdev->dev_hdl, "Failed to alloc eq page, page index: %u\n",
				pg_idx);
			goto dma_alloc_err;
		}

		reg = HINIC5_EQ_HI_PHYS_ADDR_REG(eq->type, pg_idx);
		hinic5_hwif_write_reg(hwif, reg,
				      upper_32_bits(eq_page->align_paddr));

		reg = HINIC5_EQ_LO_PHYS_ADDR_REG(eq->type, pg_idx);
		hinic5_hwif_write_reg(hwif, reg,
				      lower_32_bits(eq_page->align_paddr));
	}

	eq->num_elem_in_pg = GET_EQ_NUM_ELEMS(eq, eq->page_size);
	if ((eq->num_elem_in_pg & (eq->num_elem_in_pg - 1)) != 0) {
		sdk_err(eq->hwdev->dev_hdl, "Number element in eq page != power of 2\n");
		err = -EINVAL;
		goto dma_alloc_err;
	}
	init_val = EQ_WRAPPED(eq);

	eq_elements_init(eq, init_val);

	return 0;

dma_alloc_err:
	for (i = 0; i < pg_idx; i++)
		hinic5_dma_free_coherent_align(eq->hwdev->dev_hdl,
					       &eq->eq_pages[i]);

	kfree(eq->eq_pages);

	return err;
}

/**
 * free_eq_pages - free the pages of the queue
 * @eq: the event queue
 **/
static void free_eq_pages(struct hinic5_eq *eq)
{
	u16 pg_idx;

	for (pg_idx = 0; pg_idx < eq->num_pages; pg_idx++)
		hinic5_dma_free_coherent_align(eq->hwdev->dev_hdl,
					       &eq->eq_pages[pg_idx]);

	kfree(eq->eq_pages);
}

static inline u32 get_page_size(const struct hinic5_eq *eq)
{
	u32 total_size;
	u32 count;

	total_size = ALIGN((eq->eq_len * eq->elem_size),
			   HINIC5_MIN_EQ_PAGE_SIZE);
	if (total_size <= (HINIC5_EQ_MAX_PAGES(eq) * HINIC5_MIN_EQ_PAGE_SIZE))
		return HINIC5_MIN_EQ_PAGE_SIZE;

	count = (u32)(ALIGN((total_size / HINIC5_EQ_MAX_PAGES(eq)),
		      HINIC5_MIN_EQ_PAGE_SIZE) / HINIC5_MIN_EQ_PAGE_SIZE);

	/* round up to nearest power of two */
	count = 1U << (u8)fls(count - 1);

	return ((u32)HINIC5_MIN_EQ_PAGE_SIZE) * count;
}

#ifdef __VMWARE__
static VMK_ReturnStatus eq_intr_ack_handler(void *data, vmk_intr_cookie intr_cookie)
{
	return VMK_OK;
}
#endif

static int request_eq_irq(struct hinic5_eq *eq, struct irq_info *entry)
{
	int err = 0;
#ifdef __VMWARE__
	VMK_ReturnStatus st = VMK_OK;
#endif

	if (eq->type == HINIC5_AEQ)
		INIT_WORK(&eq->aeq_work, eq_irq_work);
	else
		tasklet_init(&eq->ceq_tasklet, ceq_tasklet, (ulong)(uintptr_t)eq);

	if (eq->type == HINIC5_AEQ) {
		snprintf(eq->irq_name, sizeof(eq->irq_name),
			 "hinic5_aeq%u@dev:%s", eq->q_id, dev_name(eq->hwdev->dev_hdl));
#ifdef __VMWARE__
		st = request_irq(eq->hwdev->adapter_hdl, entry->irq_id,
				 eq_intr_ack_handler, aeq_interrupt,
				 eq->irq_name, eq);
		if (st)
			err = VMK_FAILURE;
		else
			err = 0;
#else

		err = request_irq(entry->irq_id, aeq_interrupt, 0UL,
				  eq->irq_name, eq);
#endif
	} else {
		snprintf(eq->irq_name, sizeof(eq->irq_name),
			 "hinic5_ceq%u@dev:%s", eq->q_id, dev_name(eq->hwdev->dev_hdl));
#ifdef __VMWARE__
		st = request_irq(eq->hwdev->adapter_hdl, entry->irq_id,
				 eq_intr_ack_handler, ceq_interrupt,
				 eq->irq_name, eq);
		if (st)
			err = VMK_FAILURE;
		else
			err = 0;

#else
		err = request_irq(entry->irq_id, ceq_interrupt, 0UL,
				  eq->irq_name, eq);
#endif
	}

	return err;
}

static void reset_eq(struct hinic5_eq *eq)
{
	/* clear eq_len to force eqe drop in hardware */
	if (eq->type == HINIC5_AEQ)
		hinic5_hwif_write_reg(eq->hwdev->hwif,
				      HINIC5_CSR_AEQ_CTRL_1_ADDR, 0);
	else
		hinic5_set_ceq_ctrl_reg(eq->hwdev, eq->q_id, 0, 0);

	wmb(); /* clear eq_len before clear prod idx */

	hinic5_hwif_write_reg(eq->hwdev->hwif, EQ_PROD_IDX_REG_ADDR(eq), 0);
}

static void set_eq_cpu(struct hinic5_eq *eq, struct hinic5_hwdev *hwdev)
{
	struct hinic5_aeqs *aeqs = hwdev->aeqs;
	u32 i;

	eq->cpu = WORK_CPU_UNBOUND;

	if (eq->type == HINIC5_AEQ && aeqs->aeq_cpu_affinity_nargs > 0) {
		i = hinic5_global_func_id(hwdev) + eq->q_id;
		eq->cpu = aeqs->aeq_cpu_affinity[i % aeqs->aeq_cpu_affinity_nargs];
	}
}

/**
 * init_eq - initialize eq
 * @eq:	the event queue
 * @hwdev: the pointer to hw device
 * @q_id: Queue id number
 * @q_len: the number of EQ elements
 * @type: the type of the event queue, ceq or aeq
 * @entry: msix entry associated with the event queue
 * Return: 0 - Success, Negative - failure
 **/
static int init_eq(struct hinic5_eq *eq, struct hinic5_hwdev *hwdev, u16 q_id,
		   u32 q_len, enum hinic5_eq_type type, struct irq_info *entry)
{
	int err = 0;

	eq->hwdev = hwdev;
	eq->q_id = q_id;
	eq->type = type;
	eq->eq_len = q_len;

	/* Indirect access should set q_id first */
	hinic5_hwif_write_reg(hwdev->hwif, HINIC5_EQ_INDIR_IDX_ADDR(eq->type),
			      eq->q_id);
	wmb(); /* write index before config */

	reset_eq(eq);

	eq->cons_idx = 0;
	eq->wrapped = 0;

	eq->elem_size = (type == HINIC5_AEQ) ? HINIC5_AEQE_SIZE : HINIC5_CEQE_SIZE;

	eq->page_size = get_page_size(eq);
	eq->orig_page_size = eq->page_size;
	eq->num_pages = GET_EQ_NUM_PAGES(eq, eq->page_size);

	if (eq->num_pages > HINIC5_EQ_MAX_PAGES(eq)) {
		sdk_err(hwdev->dev_hdl, "Number pages: %u too many pages for eq\n",
			eq->num_pages);
		return -EINVAL;
	}

	err = alloc_eq_pages(eq);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to allocate pages for eq\n");
		return err;
	}

	eq->eq_irq.msix_entry_idx = entry->msix_entry_idx;
	eq->eq_irq.irq_id = entry->irq_id;

	hinic5_set_msix_state(hwdev, entry->msix_entry_idx,
			      HINIC5_MSIX_DISABLE);
	err = set_eq_ctrls(eq);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to set ctrls for eq\n");
		goto init_eq_ctrls_err;
	}

	set_eq_cons_idx(eq, HINIC5_EQ_ARMED);

	err = request_eq_irq(eq, entry);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl,
			"Failed to request irq for the eq, err: %d\n", err);
		goto req_irq_err;
	}

	set_eq_cpu(eq, hwdev);

	return 0;

init_eq_ctrls_err:
req_irq_err:
	free_eq_pages(eq);
	return err;
}

/**
 * remove_eq - remove eq
 * @eq:	the event queue
 **/
static void remove_eq(struct hinic5_eq *eq)
{
	struct irq_info *entry = &eq->eq_irq;

	hinic5_set_msix_state(eq->hwdev, entry->msix_entry_idx,
			      HINIC5_MSIX_DISABLE);
	synchronize_irq(entry->irq_id);

	free_irq(entry->irq_id, eq);

	/* Indirect access should set q_id first */
	hinic5_hwif_write_reg(eq->hwdev->hwif,
			      HINIC5_EQ_INDIR_IDX_ADDR(eq->type),
			      eq->q_id);

	wmb(); /* write index before config */

	if (eq->type == HINIC5_AEQ) {
		cancel_work_sync(&eq->aeq_work);

		/* clear eq_len to avoid hw access host memory */
		hinic5_hwif_write_reg(eq->hwdev->hwif,
				      HINIC5_CSR_AEQ_CTRL_1_ADDR, 0);
	} else {
		tasklet_kill(&eq->ceq_tasklet);

		hinic5_set_ceq_ctrl_reg(eq->hwdev, eq->q_id, 0, 0);
	}

	/* update cons_idx to avoid invalid interrupt */
	eq->cons_idx = hinic5_hwif_read_reg(eq->hwdev->hwif,
					    EQ_PROD_IDX_REG_ADDR(eq));
	set_eq_cons_idx(eq, HINIC5_EQ_NOT_ARMED);

	free_eq_pages(eq);
}

void hinic5_aeqs_valid_params(struct hinic5_hwdev *hwdev)
{
	if (g_aeq_len < HINIC5_MIN_AEQ_LEN || g_aeq_len > HINIC5_MAX_AEQ_LEN) {
		sdk_warn(hwdev->dev_hdl,
			 "Module Parameter g_aeq_len value %u out of range, resetting to %d\n",
			 g_aeq_len, HINIC5_DEFAULT_AEQ_LEN);
		g_aeq_len = HINIC5_DEFAULT_AEQ_LEN;
	}
}

#ifndef __UEFI__
static void hinic5_aeqs_dump_cpu_affinity(struct hinic5_hwdev *hwdev)
{
	struct hinic5_aeqs *aeqs = NULL;
	u16 q_id;

	if (!hwdev || !hwdev->aeqs)
		return;
	aeqs = hwdev->aeqs;

	pr_info("func %u aeq cpu affinity:", hinic5_global_func_id(hwdev));
	for (q_id = 0; q_id < aeqs->num_aeqs; q_id++)
		pr_info(" %d", aeqs->aeq[q_id].cpu);
}

void hinic5_filter_online_cpus(int *cpus, unsigned int *cpus_nargs)
{
	unsigned int i, j, n;
	int cpu;

	if (!cpus || !cpus_nargs || *cpus_nargs == 0)
		return;

	n = *cpus_nargs;
	j = 0;
	for (i = 0; i < n; i++) {
		cpu = cpus[i];
		if (cpu >= 0 && cpu < num_possible_cpus() && (cpu_online(cpu) != 0)) {
			cpus[j] = cpus[i];
			j++;
		}
	}
	*cpus_nargs = j;
}

static void hinic5_filter_aeq_cpu_affinity(struct hinic5_hwdev *hwdev)
{
	struct hinic5_aeqs *aeqs = hwdev->aeqs;
	u32 i;

	if (aeqs->aeq_cpu_affinity_nargs > 0) {
		hinic5_filter_online_cpus(aeqs->aeq_cpu_affinity,
					  &aeqs->aeq_cpu_affinity_nargs);
		pr_info("aeq cpu candidates (%u):", aeqs->aeq_cpu_affinity_nargs);
		for (i = 0; i < aeqs->aeq_cpu_affinity_nargs; ++i)
			pr_info(" %d", aeqs->aeq_cpu_affinity[i]);
	}
}
#endif

void hinic5_set_aeq_cpu_affinity(struct hinic5_hwdev *hwdev)
{
	struct hinic5_aeqs *aeqs = hwdev->aeqs;

	aeqs->aeq_cpu_affinity_nargs = 0;

	if (g_aeq_cpu_affinity_nargs > 0) {
		memcpy(aeqs->aeq_cpu_affinity, g_aeq_cpu_affinity,
		       sizeof(int) * HINIC5_AEQ_CPU_AFFINITY_MAX);
		aeqs->aeq_cpu_affinity_nargs = g_aeq_cpu_affinity_nargs;
#ifndef __UEFI__
		hinic5_filter_aeq_cpu_affinity(hwdev);
#endif
	}
}

/**
 * hinic5_aeqs_init - init all the aeqs
 * @hwdev: the pointer to hw device
 * @num_aeqs: number of AEQs
 * @msix_entries: msix entries associated with the event queues
 * Return: 0 - Success, Negative - failure
 **/
int hinic5_aeqs_init(struct hinic5_hwdev *hwdev, u16 num_aeqs,
		     struct irq_info *msix_entries)
{
	struct hinic5_aeqs *aeqs = NULL;
	int err;
	u16 i, q_id;

	if (!hwdev)
		return -EINVAL;

	aeqs = kzalloc(sizeof(*aeqs), GFP_KERNEL);
	if (!aeqs)
		return -ENOMEM;

	hwdev->aeqs = aeqs;
	aeqs->hwdev = hwdev;
	aeqs->num_aeqs = num_aeqs;
	aeqs->workq = alloc_workqueue(HINIC5_EQS_WQ_NAME, WQ_MEM_RECLAIM,
				      HINIC5_MAX_AEQS);
	if (!aeqs->workq) {
		sdk_err(hwdev->dev_hdl, "Failed to initialize aeq workqueue\n");
		err = -ENOMEM;
		goto create_work_err;
	}

	hinic5_aeqs_valid_params(hwdev);
	hinic5_set_aeq_cpu_affinity(hwdev);

	for (q_id = 0; q_id < num_aeqs; q_id++) {
		err = init_eq(&aeqs->aeq[q_id], hwdev, q_id, g_aeq_len,
			      HINIC5_AEQ, &msix_entries[q_id]);
		if (err != 0) {
			sdk_err(hwdev->dev_hdl, "Failed to init aeq %u\n",
				q_id);
			goto init_aeq_err;
		}
	}
	for (q_id = 0; q_id < num_aeqs; q_id++)
		hinic5_set_msix_state(hwdev, msix_entries[q_id].msix_entry_idx,
				      HINIC5_MSIX_ENABLE);

#ifndef __UEFI__
	hinic5_aeqs_dump_cpu_affinity(hwdev);
#endif
	return 0;

init_aeq_err:
	for (i = 0; i < q_id; i++)
		remove_eq(&aeqs->aeq[i]);

	destroy_workqueue(aeqs->workq);

create_work_err:
	kfree(aeqs);

	return err;
}

/**
 * hinic5_aeqs_free - free all the aeqs
 * @hwdev: the pointer to hw device
 **/
void hinic5_aeqs_free(struct hinic5_hwdev *hwdev)
{
	struct hinic5_aeqs *aeqs = hwdev->aeqs;
	u32 aeq_event = (u32)HINIC5_HW_INTER_INT;
	u32 sw_aeq_event = (u32)HINIC5_STATELESS_EVENT;
	u16 q_id;

	for (q_id = 0; q_id < aeqs->num_aeqs; q_id++)
		remove_eq(&aeqs->aeq[q_id]);

	for (; sw_aeq_event < (u32)HINIC5_MAX_AEQ_SW_EVENTS; sw_aeq_event++)
		hinic5_aeq_unregister_swe_cb(hwdev, (enum hinic5_aeq_sw_type)sw_aeq_event);

	for (; aeq_event < (u32)HINIC5_MAX_AEQ_EVENTS; aeq_event++)
		hinic5_aeq_unregister_hw_cb(hwdev, (enum hinic5_aeq_type)aeq_event);

	destroy_workqueue(aeqs->workq);

	kfree(aeqs);
}

/**
 * hinic5_nic_sw_aeqe_stats - count ucode aeq for sw event
 * @hwdev: the pointer to hw device
 * @event: soft event for the handler
 * @data: cqe data
 **/
u8 hinic5_nic_sw_aeqe_stats(void *hwdev, u8 event, u8 *data)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev)
		return 0;

	sdk_err(dev->dev_hdl, "Received nic ucode aeq event type: 0x%x, data: 0x%llx\n",
		event, *((u64 *)data));

	if (event < HINIC5_NIC_FATAL_ERROR_MAX)
		atomic_inc(&dev->hw_stats.nic_ucode_event_stats[event]);

	return 0;
}
EXPORT_SYMBOL(hinic5_nic_sw_aeqe_stats);

/**
 * hinic5_init_stateless_aeqs - init stateless_aeqs
 * @hwdev: the pointer to hw device
 * Return: 0 - Success, Negative - failure
 **/
int hinic5_init_stateless_aeqs(void *hwdev)
{
	struct hinic5_stateless_aeqs *stateless_aeqs = NULL;

	if (!hwdev)
		return -EINVAL;

	stateless_aeqs = kzalloc(sizeof(*stateless_aeqs), GFP_KERNEL);
	if (!stateless_aeqs)
		return -ENOMEM;

	((struct hinic5_hwdev *)hwdev)->stateless_aeqs = stateless_aeqs;

	return 0;
}

/**
 * hinic5_stateless_aeqs_free - free stateless_aeqs
 * @hwdev: the pointer to hw device
 **/
void hinic5_stateless_aeqs_free(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;
	struct hinic5_stateless_aeqs *stateless_aeqs = NULL;

	if (!hwdev)
		return;

	stateless_aeqs = dev->stateless_aeqs;
	if (!stateless_aeqs)
		return;

	clear_bit(HINIC5_AEQ_SW_CB_REG, &stateless_aeqs->stateless_aeq_sw_cb_state);

	while (test_bit(HINIC5_AEQ_SW_CB_RUNNING,
			&stateless_aeqs->stateless_aeq_sw_cb_state))
		usleep_range(EQ_USLEEP_LOW_BOUND, EQ_USLEEP_HIG_BOUND);

	stateless_aeqs->stateless_aeq_swe_cb = NULL;
	stateless_aeqs->stateless_aeq_swe_cb_data = NULL;
	kfree(stateless_aeqs);
}

/**
 * hinic5_register_stateless_aeqs - init stateless_aeqs
 * @hwdev: the pointer to hw device
 * Return: 0 - Success, Negative - failure
 **/
int hinic5_register_stateless_aeqs(void *hwdev, void *pri_handle,
				   hinic5_aeq_swe_cb stateless_aeq_swe_cb)
{
	struct hinic5_stateless_aeqs *stateless_aeqs = NULL;

	if (!hwdev)
		return -EINVAL;

	stateless_aeqs = ((struct hinic5_hwdev *)hwdev)->stateless_aeqs;
	if (!stateless_aeqs)
		return -EINVAL;

	stateless_aeqs->stateless_aeq_swe_cb = stateless_aeq_swe_cb;
	stateless_aeqs->stateless_aeq_swe_cb_data = pri_handle;
	set_bit(HINIC5_AEQ_SW_CB_REG, &stateless_aeqs->stateless_aeq_sw_cb_state);

	return 0;
}
EXPORT_SYMBOL(hinic5_register_stateless_aeqs);

/**
 * hinic5_unregister_stateless_aeqs - free stateless_aeqs
 * @hwdev: the pointer to hw device
 **/
void hinic5_unregister_stateless_aeqs(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;
	struct hinic5_stateless_aeqs *stateless_aeqs = NULL;

	if (!hwdev)
		return;

	stateless_aeqs = dev->stateless_aeqs;
	if (!stateless_aeqs)
		return;

	clear_bit(HINIC5_AEQ_SW_CB_REG, &stateless_aeqs->stateless_aeq_sw_cb_state);

	while (test_bit(HINIC5_AEQ_SW_CB_RUNNING,
			&stateless_aeqs->stateless_aeq_sw_cb_state))
		usleep_range(EQ_USLEEP_LOW_BOUND, EQ_USLEEP_HIG_BOUND);

	stateless_aeqs->stateless_aeq_swe_cb = NULL;
	stateless_aeqs->stateless_aeq_swe_cb_data = NULL;
}
EXPORT_SYMBOL(hinic5_unregister_stateless_aeqs);

u8 hinic5_nic_sw_aeqe_handler(void *hwdev, u8 event, u8 *data)
{
	struct hinic5_hwdev *dev = hwdev;
	struct hinic5_stateless_aeqs *stateless_aeqs = NULL;

	if (!dev)
		return 0;

	stateless_aeqs = dev->stateless_aeqs;

	set_bit(HINIC5_AEQ_SW_CB_RUNNING,
		&stateless_aeqs->stateless_aeq_sw_cb_state);
	if (stateless_aeqs->stateless_aeq_swe_cb &&
	    test_bit(HINIC5_AEQ_SW_CB_REG,
		     &stateless_aeqs->stateless_aeq_sw_cb_state))
		stateless_aeqs->stateless_aeq_swe_cb(stateless_aeqs->stateless_aeq_swe_cb_data,
						     event, data);

	clear_bit(HINIC5_AEQ_SW_CB_RUNNING,
		  &stateless_aeqs->stateless_aeq_sw_cb_state);

	return 0;
}

/**
 * hinic5_ceqs_init - init all the ceqs
 * @hwdev: the pointer to hw device
 * @num_ceqs: number of CEQs
 * @msix_entries: msix entries associated with the event queues
 * Return: 0 - Success, Negative - failure
 **/
int hinic5_ceqs_init(struct hinic5_hwdev *hwdev, u16 num_ceqs,
		     struct irq_info *msix_entries)
{
	struct hinic5_ceqs *ceqs = NULL;
	int err;
	u16 i, q_id;

	ceqs = kzalloc(sizeof(*ceqs), GFP_KERNEL);
	if (!ceqs)
		return -ENOMEM;

	hwdev->ceqs = ceqs;

	ceqs->hwdev = hwdev;
	ceqs->num_ceqs = num_ceqs;

	if (g_ceq_len < HINIC5_MIN_CEQ_LEN || g_ceq_len > HINIC5_MAX_CEQ_LEN) {
		sdk_warn(hwdev->dev_hdl, "Module Parameter g_ceq_len value %u out of range, resetting to %d\n",
			 g_ceq_len, HINIC5_DEFAULT_CEQ_LEN);
		g_ceq_len = HINIC5_DEFAULT_CEQ_LEN;
	}

	if (g_num_ceqe_in_tasklet == 0) {
		sdk_warn(hwdev->dev_hdl, "Module Parameter g_num_ceqe_in_tasklet can not be zero, resetting to %d\n",
			 HINIC5_TASK_PROCESS_EQE_LIMIT);
		g_num_ceqe_in_tasklet = HINIC5_TASK_PROCESS_EQE_LIMIT;
	}
	for (q_id = 0; q_id < num_ceqs; q_id++) {
		err = init_eq(&ceqs->ceq[q_id], hwdev, q_id, g_ceq_len,
			      HINIC5_CEQ, &msix_entries[q_id]);
		if (err != 0) {
			sdk_err(hwdev->dev_hdl, "Failed to init ceq %u\n",
				q_id);
			goto init_ceq_err;
		}
	}
	for (q_id = 0; q_id < num_ceqs; q_id++)
		hinic5_set_msix_state(hwdev, msix_entries[q_id].msix_entry_idx,
				      HINIC5_MSIX_ENABLE);

	for (i = 0; i < (u16)HINIC5_MAX_CEQ_EVENTS; i++)
		ceqs->ceq_cb_state[i] = 0;

	return 0;

init_ceq_err:
	for (i = 0; i < q_id; i++)
		remove_eq(&ceqs->ceq[i]);

	kfree(ceqs);

	return err;
}

/**
 * hinic5_ceqs_free - free all the ceqs
 * @hwdev: the pointer to hw device
 **/
void hinic5_ceqs_free(struct hinic5_hwdev *hwdev)
{
	struct hinic5_ceqs *ceqs = hwdev->ceqs;
	u32 ceq_event = (u32)HINIC5_CMDQ;
	u16 q_id;

	for (q_id = 0; q_id < ceqs->num_ceqs; q_id++)
		remove_eq(&ceqs->ceq[q_id]);

	for (; ceq_event < (u32)HINIC5_MAX_CEQ_EVENTS; ceq_event++)
		hinic5_ceq_unregister_cb(hwdev, (enum hinic5_ceq_event)ceq_event);

	kfree(ceqs);
}

void hinic5_get_ceq_irqs(struct hinic5_hwdev *hwdev, struct irq_info *irqs,
			 u16 *num_irqs)
{
	struct hinic5_ceqs *ceqs = hwdev->ceqs;
	u16 q_id;

	for (q_id = 0; q_id < ceqs->num_ceqs; q_id++) {
		irqs[q_id].irq_id = ceqs->ceq[q_id].eq_irq.irq_id;
		irqs[q_id].msix_entry_idx =
			ceqs->ceq[q_id].eq_irq.msix_entry_idx;
	}

	*num_irqs = ceqs->num_ceqs;
}

void hinic5_get_aeq_irqs(struct hinic5_hwdev *hwdev, struct irq_info *irqs,
			 u16 *num_irqs)
{
	struct hinic5_aeqs *aeqs = hwdev->aeqs;
	u16 q_id;

	for (q_id = 0; q_id < aeqs->num_aeqs; q_id++) {
		irqs[q_id].irq_id = aeqs->aeq[q_id].eq_irq.irq_id;
		irqs[q_id].msix_entry_idx =
			aeqs->aeq[q_id].eq_irq.msix_entry_idx;
	}

	*num_irqs = aeqs->num_aeqs;
}

void hinic5_dump_aeq_info(struct hinic5_hwdev *hwdev)
{
	struct hinic5_aeq_elem *aeqe_pos = NULL;
	struct hinic5_eq *eq = NULL;
	u32 addr, ci, pi, ctrl0, idx;
	int q_id;

	for (q_id = 0; q_id < hwdev->aeqs->num_aeqs; q_id++) {
		eq = &hwdev->aeqs->aeq[q_id];
		/* Indirect access should set q_id first */
		hinic5_hwif_write_reg(eq->hwdev->hwif, HINIC5_EQ_INDIR_IDX_ADDR(eq->type),
				      eq->q_id);
		wmb(); /* write index before config */

		addr = HINIC5_CSR_AEQ_CTRL_0_ADDR;

		ctrl0 = hinic5_hwif_read_reg(hwdev->hwif, addr);

		idx = hinic5_hwif_read_reg(hwdev->hwif, HINIC5_EQ_INDIR_IDX_ADDR(eq->type));

		addr = EQ_CONS_IDX_REG_ADDR(eq);
		ci = hinic5_hwif_read_reg(hwdev->hwif, addr);
		addr = EQ_PROD_IDX_REG_ADDR(eq);
		pi = hinic5_hwif_read_reg(hwdev->hwif, addr);
		aeqe_pos = GET_CURR_AEQ_ELEM(eq);
		sdk_err(hwdev->dev_hdl,
			"Aeq id: %d, idx: %u, ctrl0: 0x%08x, ci: 0x%08x, pi: 0x%x, work_state: 0x%x, wrap: %u, desc: 0x%x swci:0x%x\n",
			q_id, idx, ctrl0, ci, pi, work_busy(&eq->aeq_work),
			eq->wrapped, be32_to_cpu(aeqe_pos->desc),  eq->cons_idx);
	}

	hinic5_show_chip_err_info(hwdev);
}

void hinic5_dump_ceq_info(struct hinic5_hwdev *hwdev)
{
	struct hinic5_eq *eq = NULL;
	u32 addr, ci, pi;
	int q_id;

	if (!hwdev->ceqs)
		return;

	for (q_id = 0; q_id < hwdev->ceqs->num_ceqs; q_id++) {
		eq = &hwdev->ceqs->ceq[q_id];
		/* Indirect access should set q_id first */
		hinic5_hwif_write_reg(eq->hwdev->hwif,
				      HINIC5_EQ_INDIR_IDX_ADDR(eq->type),
				      eq->q_id);
		wmb(); /* write index before config */

		addr = EQ_CONS_IDX_REG_ADDR(eq);
		ci = hinic5_hwif_read_reg(hwdev->hwif, addr);
		addr = EQ_PROD_IDX_REG_ADDR(eq);
		pi = hinic5_hwif_read_reg(hwdev->hwif, addr);
		sdk_err(hwdev->dev_hdl,
			"Ceq id: %d, ci: 0x%08x, sw_ci: 0x%08x, pi: 0x%x, tasklet_state: 0x%lx, wrap: %u, ceqe: 0x%x\n",
			q_id, ci, eq->cons_idx, pi,
			tasklet_state(&eq->ceq_tasklet),
			eq->wrapped, be32_to_cpu(*(GET_CURR_CEQ_ELEM(eq))));

		sdk_err(hwdev->dev_hdl, "Ceq last response hard interrupt time: %u\n",
			jiffies_to_msecs(jiffies - eq->hard_intr_jif));
		sdk_err(hwdev->dev_hdl, "Ceq last response soft interrupt time: %u\n",
			jiffies_to_msecs(jiffies - eq->soft_intr_jif));
	}

	hinic5_show_chip_err_info(hwdev);
}

int hinic5_get_ceq_info(void *hwdev, u16 q_id, struct hinic5_ceq_info *ceq_info)
{
	struct hinic5_hwdev *dev = hwdev;
	struct hinic5_eq *eq = NULL;

	if (!hwdev || !ceq_info)
		return -EINVAL;

	if (q_id >= dev->ceqs->num_ceqs)
		return -EINVAL;

	eq = &dev->ceqs->ceq[q_id];
	ceq_info->q_len = eq->eq_len;
	ceq_info->num_pages = eq->num_pages;
	ceq_info->page_size = eq->page_size;
	ceq_info->num_elem_in_pg = eq->num_elem_in_pg;
	ceq_info->elem_size = eq->elem_size;
	sdk_info(dev->dev_hdl, "get_ceq_info: qid=0x%x page_size=%u\n",
		 q_id, eq->page_size);

	return 0;
}
EXPORT_SYMBOL(hinic5_get_ceq_info);

int hinic5_init_single_ceq_status(void *hwdev, u16 q_id)
{
	int err = 0;
	struct hinic5_hwdev *dev = hwdev;
	struct hinic5_eq *eq = NULL;

	if (!hwdev) {
		pr_err("%s(%d), hwdev is null\n", __func__, __LINE__);
		return -EINVAL;
	}

	if (q_id >= dev->ceqs->num_ceqs) {
		sdk_err(dev->dev_hdl, "q_id=%u is larger than num_ceqs %u.\n",
			q_id, dev->ceqs->num_ceqs);
		return -EINVAL;
	}

	eq = &dev->ceqs->ceq[q_id];
	/* Indirect access should set q_id first */
	hinic5_hwif_write_reg(dev->hwif, HINIC5_EQ_INDIR_IDX_ADDR(eq->type), eq->q_id);
	wmb(); /* write index before config */

	reset_eq(eq);

	err = set_eq_ctrls(eq);
	if (err != 0) {
		sdk_err(dev->dev_hdl, "Failed to set ctrls for eq\n");
		return err;
	}
	set_eq_cons_idx(eq, HINIC5_EQ_ARMED);

	return 0;
}
EXPORT_SYMBOL(hinic5_init_single_ceq_status);

int hinic5_get_ceq_page_phy_addr(void *hwdev, u16 q_id,
				 u16 page_idx, u64 *page_phy_addr)
{
	struct hinic5_hwdev *dev = hwdev;
	struct hinic5_eq *eq = NULL;

	if (!hwdev || !page_phy_addr)
		return -EINVAL;

	if (q_id >= dev->ceqs->num_ceqs)
		return -EINVAL;

	eq = &dev->ceqs->ceq[q_id];
	if (page_idx >= eq->num_pages)
		return -EINVAL;

	*page_phy_addr = eq->eq_pages[page_idx].align_paddr;
	sdk_info(dev->dev_hdl, "ceq_page_phy_addr: 0x%llx page_idx=%u\n",
		 eq->eq_pages[page_idx].align_paddr, page_idx);

	return 0;
}
EXPORT_SYMBOL(hinic5_get_ceq_page_phy_addr);

int hinic5_set_ceq_irq_disable(void *hwdev, u16 q_id)
{
	struct hinic5_hwdev *dev = hwdev;
	struct hinic5_eq *ceq = NULL;

	if (!hwdev || !dev->ceqs)
		return -EINVAL;

	if (q_id >= dev->ceqs->num_ceqs)
		return -EINVAL;

	ceq = &dev->ceqs->ceq[q_id];

	hinic5_set_msix_state(ceq->hwdev, ceq->eq_irq.msix_entry_idx,
			      HINIC5_MSIX_DISABLE);

	return 0;
}
EXPORT_SYMBOL(hinic5_set_ceq_irq_disable);
