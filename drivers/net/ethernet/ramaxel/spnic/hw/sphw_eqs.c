// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/delay.h>

#include "sphw_crm.h"
#include "sphw_hw.h"
#include "sphw_common.h"
#include "sphw_hwdev.h"
#include "sphw_hwif.h"
#include "sphw_hw.h"
#include "sphw_csr.h"
#include "sphw_hw_comm.h"
#include "sphw_prof_adap.h"
#include "sphw_eqs.h"

#define SPHW_EQS_WQ_NAME			"sphw_eqs"

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

#define SPHW_EQ_PROD_IDX_MASK			0xFFFFF
#define SPHW_TASK_PROCESS_EQE_LIMIT		1024
#define SPHW_EQ_UPDATE_CI_STEP			64

static uint g_aeq_len = SPHW_DEFAULT_AEQ_LEN;
module_param(g_aeq_len, uint, 0444);
MODULE_PARM_DESC(g_aeq_len,
		 "aeq depth, valid range is " __stringify(SPHW_MIN_AEQ_LEN)
		 " - " __stringify(SPHW_MAX_AEQ_LEN));

static uint g_ceq_len = SPHW_DEFAULT_CEQ_LEN;
module_param(g_ceq_len, uint, 0444);
MODULE_PARM_DESC(g_ceq_len,
		 "ceq depth, valid range is " __stringify(SPHW_MIN_CEQ_LEN)
		 " - " __stringify(SPHW_MAX_CEQ_LEN));

static uint g_num_ceqe_in_tasklet = SPHW_TASK_PROCESS_EQE_LIMIT;
module_param(g_num_ceqe_in_tasklet, uint, 0444);
MODULE_PARM_DESC(g_num_ceqe_in_tasklet,
		 "The max number of ceqe can be processed in tasklet, default = 1024");

#define CEQ_CTRL_0_INTR_IDX_SHIFT		0
#define CEQ_CTRL_0_DMA_ATTR_SHIFT		12
#define CEQ_CTRL_0_LIMIT_KICK_SHIFT		20
#define CEQ_CTRL_0_PCI_INTF_IDX_SHIFT		24
#define CEQ_CTRL_0_PAGE_SIZE_SHIFT		27
#define CEQ_CTRL_0_INTR_MODE_SHIFT		31

#define CEQ_CTRL_0_INTR_IDX_MASK		0x3FFU
#define CEQ_CTRL_0_DMA_ATTR_MASK		0x3FU
#define CEQ_CTRL_0_LIMIT_KICK_MASK		0xFU
#define CEQ_CTRL_0_PCI_INTF_IDX_MASK		0x3U
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
			(((eq)->type == SPHW_AEQ) ? \
			 SPHW_CSR_AEQ_CONS_IDX_ADDR : \
			 SPHW_CSR_CEQ_CONS_IDX_ADDR)
#define EQ_CI_SIMPLE_INDIR_REG_ADDR(eq)	\
			(((eq)->type == SPHW_AEQ) ? \
			 SPHW_CSR_AEQ_CI_SIMPLE_INDIR_ADDR : \
			 SPHW_CSR_CEQ_CI_SIMPLE_INDIR_ADDR)

#define EQ_PROD_IDX_REG_ADDR(eq)	\
			(((eq)->type == SPHW_AEQ) ? \
			 SPHW_CSR_AEQ_PROD_IDX_ADDR : \
			 SPHW_CSR_CEQ_PROD_IDX_ADDR)

#define SPHW_EQ_HI_PHYS_ADDR_REG(type, pg_num)	\
			((u32)((type == SPHW_AEQ) ? \
			 SPHW_AEQ_HI_PHYS_ADDR_REG(pg_num) : \
			 SPHW_CEQ_HI_PHYS_ADDR_REG(pg_num)))

#define SPHW_EQ_LO_PHYS_ADDR_REG(type, pg_num)	\
			((u32)((type == SPHW_AEQ) ? \
			 SPHW_AEQ_LO_PHYS_ADDR_REG(pg_num) : \
			 SPHW_CEQ_LO_PHYS_ADDR_REG(pg_num)))

#define GET_EQ_NUM_PAGES(eq, size)	\
			((u16)(ALIGN((u32)((eq)->eq_len * (eq)->elem_size), \
				     (size)) / (size)))

#define SPHW_EQ_MAX_PAGES(eq)		\
			((eq)->type == SPHW_AEQ ? SPHW_AEQ_MAX_PAGES : \
			 SPHW_CEQ_MAX_PAGES)

#define GET_EQ_NUM_ELEMS(eq, pg_size)	((pg_size) / (u32)(eq)->elem_size)

#define GET_EQ_ELEMENT(eq, idx)		\
	(((u8 *)(eq)->eq_pages[(idx) / (eq)->num_elem_in_pg].align_vaddr) + \
	 (u32)(((idx) & ((eq)->num_elem_in_pg - 1)) * (eq)->elem_size))

#define GET_AEQ_ELEM(eq, idx)		\
			((struct sphw_aeq_elem *)GET_EQ_ELEMENT((eq), (idx)))

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

#define CEQE_TYPE(type)			(((type) >> CEQE_TYPE_SHIFT) &	\
					 CEQE_TYPE_MASK)

#define CEQE_DATA_MASK				0x3FFFFFF
#define CEQE_DATA(data)				((data) & CEQE_DATA_MASK)

#define aeq_to_aeqs(eq) \
		container_of((eq) - (eq)->q_id, struct sphw_aeqs, aeq[0])

#define ceq_to_ceqs(eq) \
		container_of((eq) - (eq)->q_id, struct sphw_ceqs, ceq[0])

static irqreturn_t ceq_interrupt(int irq, void *data);
static irqreturn_t aeq_interrupt(int irq, void *data);

static void ceq_tasklet(ulong eq_tasklet);

/**
 * sphw_aeq_register_hw_cb - register aeq callback for specific event
 * @hwdev: the pointer to hw device
 * @event: event for the handler
 * @hw_cb: callback function
 **/
int sphw_aeq_register_hw_cb(void *hwdev, enum sphw_aeq_type event, sphw_aeq_hwe_cb hwe_cb)
{
	struct sphw_aeqs *aeqs = NULL;

	if (!hwdev || !hwe_cb || event >= SPHW_MAX_AEQ_EVENTS)
		return -EINVAL;

	aeqs = ((struct sphw_hwdev *)hwdev)->aeqs;

	aeqs->aeq_hwe_cb[event] = hwe_cb;

	set_bit(SPHW_AEQ_HW_CB_REG, &aeqs->aeq_hw_cb_state[event]);

	return 0;
}

/**
 * sphw_aeq_unregister_hw_cb - unregister the aeq callback for specific event
 * @hwdev: the pointer to hw device
 * @event: event for the handler
 **/
void sphw_aeq_unregister_hw_cb(void *hwdev, enum sphw_aeq_type event)
{
	struct sphw_aeqs *aeqs = NULL;

	if (!hwdev || event >= SPHW_MAX_AEQ_EVENTS)
		return;

	aeqs = ((struct sphw_hwdev *)hwdev)->aeqs;

	clear_bit(SPHW_AEQ_HW_CB_REG, &aeqs->aeq_hw_cb_state[event]);

	while (test_bit(SPHW_AEQ_HW_CB_RUNNING,
			&aeqs->aeq_hw_cb_state[event]))
		usleep_range(EQ_USLEEP_LOW_BOUND, EQ_USLEEP_HIG_BOUND);

	aeqs->aeq_hwe_cb[event] = NULL;
}

/**
 * sphw_aeq_register_swe_cb - register aeq callback for sw event
 * @hwdev: the pointer to hw device
 * @event: soft event for the handler
 * @sw_cb: callback function
 **/
int sphw_aeq_register_swe_cb(void *hwdev, enum sphw_aeq_sw_type event, sphw_aeq_swe_cb aeq_swe_cb)
{
	struct sphw_aeqs *aeqs = NULL;

	if (!hwdev || !aeq_swe_cb || event >= SPHW_MAX_AEQ_SW_EVENTS)
		return -EINVAL;

	aeqs = ((struct sphw_hwdev *)hwdev)->aeqs;

	aeqs->aeq_swe_cb[event] = aeq_swe_cb;

	set_bit(SPHW_AEQ_SW_CB_REG, &aeqs->aeq_sw_cb_state[event]);

	return 0;
}

/**
 * sphw_aeq_unregister_swe_cb - unregister the aeq callback for sw event
 * @hwdev: the pointer to hw device
 * @event: soft event for the handler
 **/
void sphw_aeq_unregister_swe_cb(void *hwdev, enum sphw_aeq_sw_type event)
{
	struct sphw_aeqs *aeqs = NULL;

	if (!hwdev || event >= SPHW_MAX_AEQ_SW_EVENTS)
		return;

	aeqs = ((struct sphw_hwdev *)hwdev)->aeqs;

	clear_bit(SPHW_AEQ_SW_CB_REG, &aeqs->aeq_sw_cb_state[event]);

	while (test_bit(SPHW_AEQ_SW_CB_RUNNING,
			&aeqs->aeq_sw_cb_state[event]))
		usleep_range(EQ_USLEEP_LOW_BOUND, EQ_USLEEP_HIG_BOUND);

	aeqs->aeq_swe_cb[event] = NULL;
}

/**
 * sphw_ceq_register_cb - register ceq callback for specific event
 * @hwdev: the pointer to hw device
 * @event: event for the handler
 * @ceq_cb: callback function
 **/
int sphw_ceq_register_cb(void *hwdev, enum sphw_ceq_event event, sphw_ceq_event_cb callback)
{
	struct sphw_ceqs *ceqs = NULL;

	if (!hwdev || event >= SPHW_MAX_CEQ_EVENTS)
		return -EINVAL;

	ceqs = ((struct sphw_hwdev *)hwdev)->ceqs;

	ceqs->ceq_cb[event] = callback;

	set_bit(SPHW_CEQ_CB_REG, &ceqs->ceq_cb_state[event]);

	return 0;
}

/**
 * sphw_ceq_unregister_cb - unregister ceq callback for specific event
 * @hwdev: the pointer to hw device
 * @event: event for the handler
 **/
void sphw_ceq_unregister_cb(void *hwdev, enum sphw_ceq_event event)
{
	struct sphw_ceqs *ceqs = NULL;

	if (!hwdev || event >= SPHW_MAX_CEQ_EVENTS)
		return;

	ceqs = ((struct sphw_hwdev *)hwdev)->ceqs;

	clear_bit(SPHW_CEQ_CB_REG, &ceqs->ceq_cb_state[event]);

	while (test_bit(SPHW_CEQ_CB_RUNNING, &ceqs->ceq_cb_state[event]))
		usleep_range(EQ_USLEEP_LOW_BOUND, EQ_USLEEP_HIG_BOUND);

	ceqs->ceq_cb[event] = NULL;
}

/**
 * set_eq_cons_idx - write the cons idx to the hw
 * @eq: The event queue to update the cons idx for
 * @cons idx: consumer index value
 **/
static void set_eq_cons_idx(struct sphw_eq *eq, u32 arm_state)
{
	u32 eq_wrap_ci, val;
	u32 addr = EQ_CI_SIMPLE_INDIR_REG_ADDR(eq);

	eq_wrap_ci = EQ_CONS_IDX(eq);
	val = EQ_CI_SIMPLE_INDIR_SET(arm_state, ARMED);
	if (eq->type == SPHW_AEQ) {
		val = val |
			EQ_CI_SIMPLE_INDIR_SET(eq_wrap_ci, CI) |
			EQ_CI_SIMPLE_INDIR_SET(eq->q_id, AEQ_IDX);
	} else {
		val = val |
			EQ_CI_SIMPLE_INDIR_SET(eq_wrap_ci, CI) |
			EQ_CI_SIMPLE_INDIR_SET(eq->q_id, CEQ_IDX);
	}

	sphw_hwif_write_reg(eq->hwdev->hwif, addr, val);
}

/**
 * ceq_event_handler - handle for the ceq events
 * @ceqs: ceqs part of the chip
 * @ceqe: ceq element of the event
 **/
static void ceq_event_handler(struct sphw_ceqs *ceqs, u32 ceqe)
{
	struct sphw_hwdev *hwdev = ceqs->hwdev;
	enum sphw_ceq_event event = CEQE_TYPE(ceqe);
	u32 ceqe_data = CEQE_DATA(ceqe);

	if (event >= SPHW_MAX_CEQ_EVENTS) {
		sdk_err(hwdev->dev_hdl, "Ceq unknown event:%d, ceqe date: 0x%x\n",
			event, ceqe_data);
		return;
	}

	set_bit(SPHW_CEQ_CB_RUNNING, &ceqs->ceq_cb_state[event]);

	if (ceqs->ceq_cb[event] &&
	    test_bit(SPHW_CEQ_CB_REG, &ceqs->ceq_cb_state[event]))
		ceqs->ceq_cb[event](hwdev, ceqe_data);

	clear_bit(SPHW_CEQ_CB_RUNNING, &ceqs->ceq_cb_state[event]);
}

static void aeq_elem_handler(struct sphw_eq *eq, u32 aeqe_desc)
{
	struct sphw_aeqs *aeqs = aeq_to_aeqs(eq);
	struct sphw_aeq_elem *aeqe_pos;
	enum sphw_aeq_type event;
	enum sphw_aeq_sw_type sw_type;
	u32 sw_event;
	u8 data[SPHW_AEQE_DATA_SIZE], size;

	aeqe_pos = GET_CURR_AEQ_ELEM(eq);

	event = EQ_ELEM_DESC_GET(aeqe_desc, TYPE);
	if (EQ_ELEM_DESC_GET(aeqe_desc, SRC)) {
		sw_event = event;
		sw_type = sw_event >= SPHW_NIC_FATAL_ERROR_MAX ?
			   SPHW_STATEFULL_EVENT :
			   SPHW_STATELESS_EVENT;
		/* SW event uses only the first 8B */
		memcpy(data, aeqe_pos->aeqe_data, SPHW_AEQE_DATA_SIZE);
		sphw_be32_to_cpu(data, SPHW_AEQE_DATA_SIZE);
		set_bit(SPHW_AEQ_SW_CB_RUNNING,
			&aeqs->aeq_sw_cb_state[sw_type]);
		if (aeqs->aeq_swe_cb[sw_type] &&
		    test_bit(SPHW_AEQ_SW_CB_REG,
			     &aeqs->aeq_sw_cb_state[sw_type]))
			aeqs->aeq_swe_cb[sw_type](aeqs->hwdev, event, data);

		clear_bit(SPHW_AEQ_SW_CB_RUNNING,
			  &aeqs->aeq_sw_cb_state[sw_type]);
		return;
	}

	if (event < SPHW_MAX_AEQ_EVENTS) {
		memcpy(data, aeqe_pos->aeqe_data, SPHW_AEQE_DATA_SIZE);
		sphw_be32_to_cpu(data, SPHW_AEQE_DATA_SIZE);

		size = EQ_ELEM_DESC_GET(aeqe_desc, SIZE);
		set_bit(SPHW_AEQ_HW_CB_RUNNING,
			&aeqs->aeq_hw_cb_state[event]);
		if (aeqs->aeq_hwe_cb[event] &&
		    test_bit(SPHW_AEQ_HW_CB_REG,
			     &aeqs->aeq_hw_cb_state[event]))
			aeqs->aeq_hwe_cb[event](aeqs->hwdev, data, size);
		clear_bit(SPHW_AEQ_HW_CB_RUNNING,
			  &aeqs->aeq_hw_cb_state[event]);
		return;
	}
	sdk_warn(eq->hwdev->dev_hdl, "Unknown aeq hw event %d\n", event);
}

/**
 * aeq_irq_handler - handler for the aeq event
 * @eq: the async event queue of the event
 **/
static bool aeq_irq_handler(struct sphw_eq *eq)
{
	struct sphw_aeq_elem *aeqe_pos = NULL;
	u32 aeqe_desc;
	u32 i, eqe_cnt = 0;

	for (i = 0; i < SPHW_TASK_PROCESS_EQE_LIMIT; i++) {
		aeqe_pos = GET_CURR_AEQ_ELEM(eq);

		/* Data in HW is in Big endian Format */
		aeqe_desc = be32_to_cpu(aeqe_pos->desc);

		/* HW updates wrapped bit, when it adds eq element event */
		if (EQ_ELEM_DESC_GET(aeqe_desc, WRAPPED) == eq->wrapped)
			return false;

		aeq_elem_handler(eq, aeqe_desc);

		eq->cons_idx++;

		if (eq->cons_idx == eq->eq_len) {
			eq->cons_idx = 0;
			eq->wrapped = !eq->wrapped;
		}

		if (++eqe_cnt >= SPHW_EQ_UPDATE_CI_STEP) {
			eqe_cnt = 0;
			set_eq_cons_idx(eq, SPHW_EQ_NOT_ARMED);
		}
	}

	return true;
}

/**
 * ceq_irq_handler - handler for the ceq event
 * @eq: the completion event queue of the event
 **/
static bool ceq_irq_handler(struct sphw_eq *eq)
{
	struct sphw_ceqs *ceqs = ceq_to_ceqs(eq);
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
			eq->wrapped = !eq->wrapped;
		}

		if (++eqe_cnt >= SPHW_EQ_UPDATE_CI_STEP) {
			eqe_cnt = 0;
			set_eq_cons_idx(eq, SPHW_EQ_NOT_ARMED);
		}
	}

	return true;
}

static void reschedule_eq_handler(struct sphw_eq *eq)
{
	if (eq->type == SPHW_AEQ) {
		struct sphw_aeqs *aeqs = aeq_to_aeqs(eq);
		struct workqueue_struct *workq = aeqs->workq;
		struct sphw_eq_work *aeq_work = &eq->aeq_work;

		queue_work_on(sphw_get_work_cpu_affinity(eq->hwdev, WORK_TYPE_AEQ),
			      workq, &aeq_work->work);
	} else {
		tasklet_schedule(&eq->ceq_tasklet);
	}
}

/**
 * eq_irq_handler - handler for the eq event
 * @data: the event queue of the event
 **/
static bool eq_irq_handler(void *data)
{
	struct sphw_eq *eq = (struct sphw_eq *)data;
	bool uncompleted = false;

	if (eq->type == SPHW_AEQ)
		uncompleted = aeq_irq_handler(eq);
	else
		uncompleted = ceq_irq_handler(eq);

	set_eq_cons_idx(eq, uncompleted ? SPHW_EQ_NOT_ARMED :
			SPHW_EQ_ARMED);

	return uncompleted;
}

/**
 * eq_irq_work - eq work for the event
 * @work: the work that is associated with the eq
 **/
static void eq_irq_work(struct work_struct *work)
{
	struct sphw_eq_work *aeq_work =
			container_of(work, struct sphw_eq_work, work);

	if (eq_irq_handler(aeq_work->data))
		reschedule_eq_handler(aeq_work->data);
}

/**
 * aeq_interrupt - aeq interrupt handler
 * @irq: irq number
 * @data: the async event queue of the event
 **/
static irqreturn_t aeq_interrupt(int irq, void *data)
{
	struct sphw_eq *aeq = (struct sphw_eq *)data;
	struct sphw_hwdev *hwdev = aeq->hwdev;
	struct sphw_aeqs *aeqs = aeq_to_aeqs(aeq);
	struct workqueue_struct *workq = aeqs->workq;
	struct sphw_eq_work *aeq_work = NULL;

	/* clear resend timer cnt register */
	sphw_misx_intr_clear_resend_bit(hwdev, aeq->eq_irq.msix_entry_idx,
					EQ_MSIX_RESEND_TIMER_CLEAR);

	aeq_work = &aeq->aeq_work;
	aeq_work->data = aeq;

	queue_work_on(sphw_get_work_cpu_affinity(hwdev, WORK_TYPE_AEQ),
		      workq, &aeq_work->work);

	return IRQ_HANDLED;
}

/**
 * ceq_tasklet - ceq tasklet for the event
 * @ceq_data: data that will be used by the tasklet(ceq)
 **/
static void ceq_tasklet(ulong ceq_data)
{
	struct sphw_ceq_tasklet_data *ceq_tasklet_data =
				(struct sphw_ceq_tasklet_data *)ceq_data;
	struct sphw_eq *eq = (struct sphw_eq *)ceq_tasklet_data->data;

	eq->soft_intr_jif = jiffies;

	if (eq_irq_handler(ceq_tasklet_data->data))
		reschedule_eq_handler(ceq_tasklet_data->data);
}

/**
 * ceq_interrupt - ceq interrupt handler
 * @irq: irq number
 * @data: the completion event queue of the event
 **/
static irqreturn_t ceq_interrupt(int irq, void *data)
{
	struct sphw_eq *ceq = (struct sphw_eq *)data;
	struct sphw_ceq_tasklet_data *ceq_tasklet_data = NULL;

	ceq->hard_intr_jif = jiffies;

	/* clear resend timer counters */
	sphw_misx_intr_clear_resend_bit(ceq->hwdev, ceq->eq_irq.msix_entry_idx,
					EQ_MSIX_RESEND_TIMER_CLEAR);

	ceq_tasklet_data = &ceq->ceq_tasklet_data;
	ceq_tasklet_data->data = data;
	tasklet_schedule(&ceq->ceq_tasklet);

	return IRQ_HANDLED;
}

/**
 * set_eq_ctrls - setting eq's ctrls registers
 * @eq: the event queue for setting
 **/
static int set_eq_ctrls(struct sphw_eq *eq)
{
	enum sphw_eq_type type = eq->type;
	struct sphw_hwif *hwif = eq->hwdev->hwif;
	struct irq_info *eq_irq = &eq->eq_irq;
	u32 addr, val, ctrl0, ctrl1, page_size_val, elem_size;
	u32 pci_intf_idx = SPHW_PCI_INTF_IDX(hwif);
	int err;

	if (type == SPHW_AEQ) {
		/* set ctrl0 */
		addr = SPHW_CSR_AEQ_CTRL_0_ADDR;

		val = sphw_hwif_read_reg(hwif, addr);

		val = AEQ_CTRL_0_CLEAR(val, INTR_IDX) &
			AEQ_CTRL_0_CLEAR(val, DMA_ATTR) &
			AEQ_CTRL_0_CLEAR(val, PCI_INTF_IDX) &
			AEQ_CTRL_0_CLEAR(val, INTR_MODE);

		ctrl0 = AEQ_CTRL_0_SET(eq_irq->msix_entry_idx, INTR_IDX) |
			AEQ_CTRL_0_SET(AEQ_DMA_ATTR_DEFAULT, DMA_ATTR) |
			AEQ_CTRL_0_SET(pci_intf_idx, PCI_INTF_IDX) |
			AEQ_CTRL_0_SET(SPHW_INTR_MODE_ARMED, INTR_MODE);

		val |= ctrl0;

		sphw_hwif_write_reg(hwif, addr, val);

		/* set ctrl1 */
		addr = SPHW_CSR_AEQ_CTRL_1_ADDR;

		page_size_val = EQ_SET_HW_PAGE_SIZE_VAL(eq);
		elem_size = EQ_SET_HW_ELEM_SIZE_VAL(eq);

		ctrl1 = AEQ_CTRL_1_SET(eq->eq_len, LEN)	|
			AEQ_CTRL_1_SET(elem_size, ELEM_SIZE)	|
			AEQ_CTRL_1_SET(page_size_val, PAGE_SIZE);

		sphw_hwif_write_reg(hwif, addr, ctrl1);

	} else {
		page_size_val = EQ_SET_HW_PAGE_SIZE_VAL(eq);
		ctrl0 = CEQ_CTRL_0_SET(eq_irq->msix_entry_idx, INTR_IDX) |
			CEQ_CTRL_0_SET(CEQ_DMA_ATTR_DEFAULT, DMA_ATTR)	|
			CEQ_CTRL_0_SET(CEQ_LMT_KICK_DEFAULT, LIMIT_KICK) |
			CEQ_CTRL_0_SET(pci_intf_idx, PCI_INTF_IDX) |
			CEQ_CTRL_0_SET(page_size_val, PAGE_SIZE) |
			CEQ_CTRL_0_SET(SPHW_INTR_MODE_ARMED, INTR_MODE);

		ctrl1 = CEQ_CTRL_1_SET(eq->eq_len, LEN);

		/* set ceq ctrl reg through mgmt cpu */
		err = sphw_set_ceq_ctrl_reg(eq->hwdev, eq->q_id, ctrl0, ctrl1);
		if (err)
			return err;
	}

	return 0;
}

/**
 * ceq_elements_init - Initialize all the elements in the ceq
 * @eq: the event queue
 * @init_val: value to init with it the elements
 **/
static void ceq_elements_init(struct sphw_eq *eq, u32 init_val)
{
	u32 *ceqe = NULL;
	u32 i;

	for (i = 0; i < eq->eq_len; i++) {
		ceqe = GET_CEQ_ELEM(eq, i);
		*(ceqe) = cpu_to_be32(init_val);
	}

	wmb();	/* Write the init values */
}

/**
 * aeq_elements_init - initialize all the elements in the aeq
 * @eq: the event queue
 * @init_val: value to init with it the elements
 **/
static void aeq_elements_init(struct sphw_eq *eq, u32 init_val)
{
	struct sphw_aeq_elem *aeqe = NULL;
	u32 i;

	for (i = 0; i < eq->eq_len; i++) {
		aeqe = GET_AEQ_ELEM(eq, i);
		aeqe->desc = cpu_to_be32(init_val);
	}

	wmb();	/* Write the init values */
}

static void eq_elements_init(struct sphw_eq *eq, u32 init_val)
{
	if (eq->type == SPHW_AEQ)
		aeq_elements_init(eq, init_val);
	else
		ceq_elements_init(eq, init_val);
}

/**
 * alloc_eq_pages - allocate the pages for the queue
 * @eq: the event queue
 **/
static int alloc_eq_pages(struct sphw_eq *eq)
{
	struct sphw_hwif *hwif = eq->hwdev->hwif;
	struct sphw_dma_addr_align *eq_page = NULL;
	u32 reg, init_val;
	u16 pg_idx, i;
	int err;

	eq->eq_pages = kcalloc(eq->num_pages, sizeof(*eq->eq_pages),
			       GFP_KERNEL);
	if (!eq->eq_pages) {
		sdk_err(eq->hwdev->dev_hdl, "Failed to alloc eq pages description\n");
		return -ENOMEM;
	}

	for (pg_idx = 0; pg_idx < eq->num_pages; pg_idx++) {
		eq_page = &eq->eq_pages[pg_idx];
		err = sphw_dma_alloc_coherent_align(eq->hwdev->dev_hdl, eq->page_size,
						    SPHW_MIN_EQ_PAGE_SIZE, GFP_KERNEL, eq_page);
		if (err) {
			sdk_err(eq->hwdev->dev_hdl, "Failed to alloc eq page, page index: %hu\n",
				pg_idx);
			goto dma_alloc_err;
		}

		reg = SPHW_EQ_HI_PHYS_ADDR_REG(eq->type, pg_idx);
		sphw_hwif_write_reg(hwif, reg, upper_32_bits(eq_page->align_paddr));

		reg = SPHW_EQ_LO_PHYS_ADDR_REG(eq->type, pg_idx);
		sphw_hwif_write_reg(hwif, reg, lower_32_bits(eq_page->align_paddr));
	}

	eq->num_elem_in_pg = GET_EQ_NUM_ELEMS(eq, eq->page_size);
	if (eq->num_elem_in_pg & (eq->num_elem_in_pg - 1)) {
		sdk_err(eq->hwdev->dev_hdl, "Number element in eq page != power of 2\n");
		err = -EINVAL;
		goto dma_alloc_err;
	}
	init_val = EQ_WRAPPED(eq);

	eq_elements_init(eq, init_val);

	return 0;

dma_alloc_err:
	for (i = 0; i < pg_idx; i++)
		sphw_dma_free_coherent_align(eq->hwdev->dev_hdl, &eq->eq_pages[i]);

	kfree(eq->eq_pages);

	return err;
}

/**
 * free_eq_pages - free the pages of the queue
 * @eq: the event queue
 **/
static void free_eq_pages(struct sphw_eq *eq)
{
	u16 pg_idx;

	for (pg_idx = 0; pg_idx < eq->num_pages; pg_idx++)
		sphw_dma_free_coherent_align(eq->hwdev->dev_hdl, &eq->eq_pages[pg_idx]);

	kfree(eq->eq_pages);
}

static inline u32 get_page_size(struct sphw_eq *eq)
{
	u32 total_size;
	u32 count;

	total_size = ALIGN((eq->eq_len * eq->elem_size),
			   SPHW_MIN_EQ_PAGE_SIZE);

	if (total_size <= (SPHW_EQ_MAX_PAGES(eq) * SPHW_MIN_EQ_PAGE_SIZE))
		return SPHW_MIN_EQ_PAGE_SIZE;

	count = (u32)(ALIGN((total_size / SPHW_EQ_MAX_PAGES(eq)),
		      SPHW_MIN_EQ_PAGE_SIZE) / SPHW_MIN_EQ_PAGE_SIZE);

	/* round up to nearest power of two */
	count = 1U << (u8)fls((int)(count - 1));

	return ((u32)SPHW_MIN_EQ_PAGE_SIZE) * count;
}

static int request_eq_irq(struct sphw_eq *eq, struct irq_info *entry)
{
	int err = 0;

	if (eq->type == SPHW_AEQ) {
		struct sphw_eq_work *aeq_work = &eq->aeq_work;

		INIT_WORK(&aeq_work->work, eq_irq_work);
	} else {
		tasklet_init(&eq->ceq_tasklet, ceq_tasklet,
			     (ulong)(&eq->ceq_tasklet_data));
	}

	if (eq->type == SPHW_AEQ) {
		snprintf(eq->irq_name, sizeof(eq->irq_name),
			 "sphw_aeq%u@pci:%s", eq->q_id,
			 pci_name(eq->hwdev->pcidev_hdl));

		err = request_irq(entry->irq_id, aeq_interrupt, 0UL,
				  eq->irq_name, eq);
	} else {
		snprintf(eq->irq_name, sizeof(eq->irq_name),
			 "sphw_ceq%u@pci:%s", eq->q_id,
			 pci_name(eq->hwdev->pcidev_hdl));
		err = request_irq(entry->irq_id, ceq_interrupt, 0UL,
				  eq->irq_name, eq);
	}

	return err;
}

static void reset_eq(struct sphw_eq *eq)
{
	/* clear eq_len to force eqe drop in hardware */
	if (eq->type == SPHW_AEQ)
		sphw_hwif_write_reg(eq->hwdev->hwif, SPHW_CSR_AEQ_CTRL_1_ADDR, 0);
	else
		sphw_set_ceq_ctrl_reg(eq->hwdev, eq->q_id, 0, 0);

	wmb(); /* clear eq_len before clear prod idx */

	sphw_hwif_write_reg(eq->hwdev->hwif, EQ_PROD_IDX_REG_ADDR(eq), 0);
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
static int init_eq(struct sphw_eq *eq, struct sphw_hwdev *hwdev, u16 q_id,
		   u32 q_len, enum sphw_eq_type type, struct irq_info *entry)
{
	int err = 0;

	eq->hwdev = hwdev;
	eq->q_id = q_id;
	eq->type = type;
	eq->eq_len = q_len;

	/* Indirect access should set q_id first */
	sphw_hwif_write_reg(hwdev->hwif, SPHW_EQ_INDIR_IDX_ADDR(eq->type), eq->q_id);
	wmb(); /* write index before config */

	reset_eq(eq);

	eq->cons_idx = 0;
	eq->wrapped = 0;

	eq->elem_size = (type == SPHW_AEQ) ? SPHW_AEQE_SIZE : SPHW_CEQE_SIZE;

	eq->page_size = get_page_size(eq);
	eq->orig_page_size = eq->page_size;
	eq->num_pages = GET_EQ_NUM_PAGES(eq, eq->page_size);
	if (eq->num_pages > SPHW_EQ_MAX_PAGES(eq)) {
		sdk_err(hwdev->dev_hdl, "Number pages: %u too many pages for eq\n",
			eq->num_pages);
		return -EINVAL;
	}

	err = alloc_eq_pages(eq);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to allocate pages for eq\n");
		return err;
	}

	eq->eq_irq.msix_entry_idx = entry->msix_entry_idx;
	eq->eq_irq.irq_id = entry->irq_id;

	err = set_eq_ctrls(eq);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to set ctrls for eq\n");
		goto init_eq_ctrls_err;
	}

	set_eq_cons_idx(eq, SPHW_EQ_ARMED);

	err = request_eq_irq(eq, entry);
	if (err) {
		sdk_err(hwdev->dev_hdl,
			"Failed to request irq for the eq, err: %d\n", err);
		goto req_irq_err;
	}

	sphw_set_msix_state(hwdev, entry->msix_entry_idx, SPHW_MSIX_DISABLE);

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
static void remove_eq(struct sphw_eq *eq)
{
	struct irq_info *entry = &eq->eq_irq;

	sphw_set_msix_state(eq->hwdev, entry->msix_entry_idx, SPHW_MSIX_DISABLE);
	synchronize_irq(entry->irq_id);

	free_irq(entry->irq_id, eq);

	/* Indirect access should set q_id first */
	sphw_hwif_write_reg(eq->hwdev->hwif, SPHW_EQ_INDIR_IDX_ADDR(eq->type), eq->q_id);

	wmb(); /* write index before config */

	if (eq->type == SPHW_AEQ) {
		struct sphw_eq_work *aeq_work = &eq->aeq_work;

		cancel_work_sync(&aeq_work->work);

		/* clear eq_len to avoid hw access host memory */
		sphw_hwif_write_reg(eq->hwdev->hwif, SPHW_CSR_AEQ_CTRL_1_ADDR, 0);
	} else {
		tasklet_kill(&eq->ceq_tasklet);

		sphw_set_ceq_ctrl_reg(eq->hwdev, eq->q_id, 0, 0);
	}

	/* update cons_idx to avoid invalid interrupt */
	eq->cons_idx = sphw_hwif_read_reg(eq->hwdev->hwif, EQ_PROD_IDX_REG_ADDR(eq));
	set_eq_cons_idx(eq, SPHW_EQ_NOT_ARMED);

	free_eq_pages(eq);
}

/**
 * sphw_aeqs_init - init all the aeqs
 * @hwdev: the pointer to hw device
 * @num_aeqs: number of AEQs
 * @msix_entries: msix entries associated with the event queues
 * Return: 0 - Success, Negative - failure
 **/
int sphw_aeqs_init(struct sphw_hwdev *hwdev, u16 num_aeqs, struct irq_info *msix_entries)
{
	struct sphw_aeqs *aeqs = NULL;
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
	aeqs->workq = alloc_workqueue(SPHW_EQS_WQ_NAME, WQ_MEM_RECLAIM, SPHW_MAX_AEQS);
	if (!aeqs->workq) {
		sdk_err(hwdev->dev_hdl, "Failed to initialize aeq workqueue\n");
		err = -ENOMEM;
		goto create_work_err;
	}

	if (g_aeq_len < SPHW_MIN_AEQ_LEN || g_aeq_len > SPHW_MAX_AEQ_LEN) {
		sdk_warn(hwdev->dev_hdl, "Module Parameter g_aeq_len value %u out of range, resetting to %d\n",
			 g_aeq_len, SPHW_DEFAULT_AEQ_LEN);
		g_aeq_len = SPHW_DEFAULT_AEQ_LEN;
	}

	for (q_id = 0; q_id < num_aeqs; q_id++) {
		err = init_eq(&aeqs->aeq[q_id], hwdev, q_id, g_aeq_len,
			      SPHW_AEQ, &msix_entries[q_id]);
		if (err) {
			sdk_err(hwdev->dev_hdl, "Failed to init aeq %u\n",
				q_id);
			goto init_aeq_err;
		}
	}
	for (q_id = 0; q_id < num_aeqs; q_id++)
		sphw_set_msix_state(hwdev, msix_entries[q_id].msix_entry_idx, SPHW_MSIX_ENABLE);

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
 * sphw_aeqs_free - free all the aeqs
 * @hwdev: the pointer to hw device
 **/
void sphw_aeqs_free(struct sphw_hwdev *hwdev)
{
	struct sphw_aeqs *aeqs = hwdev->aeqs;
	enum sphw_aeq_type aeq_event = SPHW_HW_INTER_INT;
	enum sphw_aeq_sw_type sw_aeq_event = SPHW_STATELESS_EVENT;
	u16 q_id;

	for (q_id = 0; q_id < aeqs->num_aeqs; q_id++)
		remove_eq(&aeqs->aeq[q_id]);

	for (; sw_aeq_event < SPHW_MAX_AEQ_SW_EVENTS; sw_aeq_event++)
		sphw_aeq_unregister_swe_cb(hwdev, sw_aeq_event);

	for (; aeq_event < SPHW_MAX_AEQ_EVENTS; aeq_event++)
		sphw_aeq_unregister_hw_cb(hwdev, aeq_event);

	destroy_workqueue(aeqs->workq);

	kfree(aeqs);
}

/**
 * sphw_ceqs_init - init all the ceqs
 * @hwdev: the pointer to hw device
 * @num_ceqs: number of CEQs
 * @msix_entries: msix entries associated with the event queues
 * Return: 0 - Success, Negative - failure
 **/
int sphw_ceqs_init(struct sphw_hwdev *hwdev, u16 num_ceqs, struct irq_info *msix_entries)
{
	struct sphw_ceqs *ceqs;
	int err;
	u16 i, q_id;

	ceqs = kzalloc(sizeof(*ceqs), GFP_KERNEL);
	if (!ceqs)
		return -ENOMEM;

	hwdev->ceqs = ceqs;

	ceqs->hwdev = hwdev;
	ceqs->num_ceqs = num_ceqs;

	if (g_ceq_len < SPHW_MIN_CEQ_LEN || g_ceq_len > SPHW_MAX_CEQ_LEN) {
		sdk_warn(hwdev->dev_hdl, "Module Parameter g_ceq_len value %u out of range, resetting to %d\n",
			 g_ceq_len, SPHW_DEFAULT_CEQ_LEN);
		g_ceq_len = SPHW_DEFAULT_CEQ_LEN;
	}

	if (!g_num_ceqe_in_tasklet) {
		sdk_warn(hwdev->dev_hdl, "Module Parameter g_num_ceqe_in_tasklet can not be zero, resetting to %d\n",
			 SPHW_TASK_PROCESS_EQE_LIMIT);
		g_num_ceqe_in_tasklet = SPHW_TASK_PROCESS_EQE_LIMIT;
	}
	for (q_id = 0; q_id < num_ceqs; q_id++) {
		err = init_eq(&ceqs->ceq[q_id], hwdev, q_id, g_ceq_len,
			      SPHW_CEQ, &msix_entries[q_id]);
		if (err) {
			sdk_err(hwdev->dev_hdl, "Failed to init ceq %u\n",
				q_id);
			goto init_ceq_err;
		}
	}
	for (q_id = 0; q_id < num_ceqs; q_id++)
		sphw_set_msix_state(hwdev, msix_entries[q_id].msix_entry_idx, SPHW_MSIX_ENABLE);

	return 0;

init_ceq_err:
	for (i = 0; i < q_id; i++)
		remove_eq(&ceqs->ceq[i]);

	kfree(ceqs);

	return err;
}

/**
 * sphw_ceqs_free - free all the ceqs
 * @hwdev: the pointer to hw device
 **/
void sphw_ceqs_free(struct sphw_hwdev *hwdev)
{
	struct sphw_ceqs *ceqs = hwdev->ceqs;
	enum sphw_ceq_event ceq_event = SPHW_CMDQ;
	u16 q_id;

	for (q_id = 0; q_id < ceqs->num_ceqs; q_id++)
		remove_eq(&ceqs->ceq[q_id]);

	for (; ceq_event < SPHW_MAX_CEQ_EVENTS; ceq_event++)
		sphw_ceq_unregister_cb(hwdev, ceq_event);

	kfree(ceqs);
}

void sphw_get_ceq_irqs(struct sphw_hwdev *hwdev, struct irq_info *irqs, u16 *num_irqs)
{
	struct sphw_ceqs *ceqs = hwdev->ceqs;
	u16 q_id;

	for (q_id = 0; q_id < ceqs->num_ceqs; q_id++) {
		irqs[q_id].irq_id = ceqs->ceq[q_id].eq_irq.irq_id;
		irqs[q_id].msix_entry_idx =
			ceqs->ceq[q_id].eq_irq.msix_entry_idx;
	}

	*num_irqs = ceqs->num_ceqs;
}

void sphw_get_aeq_irqs(struct sphw_hwdev *hwdev, struct irq_info *irqs, u16 *num_irqs)
{
	struct sphw_aeqs *aeqs = hwdev->aeqs;
	u16 q_id;

	for (q_id = 0; q_id < aeqs->num_aeqs; q_id++) {
		irqs[q_id].irq_id = aeqs->aeq[q_id].eq_irq.irq_id;
		irqs[q_id].msix_entry_idx =
			aeqs->aeq[q_id].eq_irq.msix_entry_idx;
	}

	*num_irqs = aeqs->num_aeqs;
}

void sphw_dump_aeq_info(struct sphw_hwdev *hwdev)
{
	struct sphw_aeq_elem *aeqe_pos = NULL;
	struct sphw_eq *eq = NULL;
	u32 addr, ci, pi, ctrl0, idx;
	int q_id;

	for (q_id = 0; q_id < hwdev->aeqs->num_aeqs; q_id++) {
		eq = &hwdev->aeqs->aeq[q_id];
		/* Indirect access should set q_id first */
		sphw_hwif_write_reg(eq->hwdev->hwif, SPHW_EQ_INDIR_IDX_ADDR(eq->type), eq->q_id);
		wmb(); /* write index before config */

		addr = SPHW_CSR_AEQ_CTRL_0_ADDR;

		ctrl0 = sphw_hwif_read_reg(hwdev->hwif, addr);

		idx = sphw_hwif_read_reg(hwdev->hwif, SPHW_EQ_INDIR_IDX_ADDR(eq->type));

		addr = EQ_CONS_IDX_REG_ADDR(eq);
		ci = sphw_hwif_read_reg(hwdev->hwif, addr);
		addr = EQ_PROD_IDX_REG_ADDR(eq);
		pi = sphw_hwif_read_reg(hwdev->hwif, addr);
		aeqe_pos = GET_CURR_AEQ_ELEM(eq);
		sdk_err(hwdev->dev_hdl, "Aeq id: %d, idx: %u, ctrl0: 0x%08x, ci: 0x%08x, pi: 0x%x, work_state: 0x%x, wrap: %u, desc: 0x%x\n",
			q_id, idx, ctrl0, ci, pi, work_busy(&eq->aeq_work.work),
			eq->wrapped, be32_to_cpu(aeqe_pos->desc));
	}
}

void sphw_dump_ceq_info(struct sphw_hwdev *hwdev)
{
	struct sphw_eq *eq = NULL;
	u32 addr, ci, pi;
	int q_id;

	for (q_id = 0; q_id < hwdev->ceqs->num_ceqs; q_id++) {
		eq = &hwdev->ceqs->ceq[q_id];
		/* Indirect access should set q_id first */
		sphw_hwif_write_reg(eq->hwdev->hwif, SPHW_EQ_INDIR_IDX_ADDR(eq->type), eq->q_id);
		wmb(); /* write index before config */

		addr = EQ_CONS_IDX_REG_ADDR(eq);
		ci = sphw_hwif_read_reg(hwdev->hwif, addr);
		addr = EQ_PROD_IDX_REG_ADDR(eq);
		pi = sphw_hwif_read_reg(hwdev->hwif, addr);
		sdk_err(hwdev->dev_hdl, "Ceq id: %d, ci: 0x%08x, sw_ci: 0x%08x, pi: 0x%x, tasklet_state: 0x%lx, wrap: %u, ceqe: 0x%x\n",
			q_id, ci, eq->cons_idx, pi, eq->ceq_tasklet.state,
			eq->wrapped, be32_to_cpu(*(GET_CURR_CEQ_ELEM(eq))));

		sdk_err(hwdev->dev_hdl, "Ceq last response hard interrupt time: %u\n",
			jiffies_to_msecs(jiffies - eq->hard_intr_jif));
		sdk_err(hwdev->dev_hdl, "Ceq last response soft interrupt time: %u\n",
			jiffies_to_msecs(jiffies - eq->soft_intr_jif));
	}
}
