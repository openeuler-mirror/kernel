// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/semaphore.h>
#include <linux/interrupt.h>
#include <linux/vmalloc.h>

#include "sphw_crm.h"
#include "sphw_hw.h"
#include "sphw_common.h"
#include "sphw_hwdev.h"
#include "sphw_csr.h"
#include "sphw_hwif.h"
#include "sphw_eqs.h"
#include "sphw_api_cmd.h"
#include "sphw_mgmt.h"
#include "sphw_mbox.h"
#include "sphw_wq.h"
#include "sphw_cmdq.h"
#include "sphw_hw_cfg.h"
#include "sphw_hw_comm.h"
#include "sphw_prof_adap.h"

static bool disable_stateful_load;
module_param(disable_stateful_load, bool, 0444);
MODULE_PARM_DESC(disable_stateful_load, "Disable stateful load - default is false");

static bool disable_cfg_comm;
module_param(disable_cfg_comm, bool, 0444);
MODULE_PARM_DESC(disable_cfg_comm, "disable_cfg_comm or not - default is false");

static unsigned int wq_page_order = SPHW_MAX_WQ_PAGE_SIZE_ORDER;
module_param(wq_page_order, uint, 0444);
MODULE_PARM_DESC(wq_page_order, "Set wq page size order, wq page size is 4K * (2 ^ wq_page_order) - default is 8");

enum sphw_pcie_nosnoop {
	SPHW_PCIE_SNOOP = 0,
	SPHW_PCIE_NO_SNOOP = 1,
};

enum sphw_pcie_tph {
	SPHW_PCIE_TPH_DISABLE = 0,
	SPHW_PCIE_TPH_ENABLE = 1,
};

#define SPHW_DMA_ATTR_INDIR_IDX_SHIFT				0

#define SPHW_DMA_ATTR_INDIR_IDX_MASK				0x3FF

#define SPHW_DMA_ATTR_INDIR_IDX_SET(val, member)			\
		(((u32)(val) & SPHW_DMA_ATTR_INDIR_##member##_MASK) << \
			SPHW_DMA_ATTR_INDIR_##member##_SHIFT)

#define SPHW_DMA_ATTR_INDIR_IDX_CLEAR(val, member)		\
		((val) & (~(SPHW_DMA_ATTR_INDIR_##member##_MASK	\
			<< SPHW_DMA_ATTR_INDIR_##member##_SHIFT)))

#define SPHW_DMA_ATTR_ENTRY_ST_SHIFT				0
#define SPHW_DMA_ATTR_ENTRY_AT_SHIFT				8
#define SPHW_DMA_ATTR_ENTRY_PH_SHIFT				10
#define SPHW_DMA_ATTR_ENTRY_NO_SNOOPING_SHIFT			12
#define SPHW_DMA_ATTR_ENTRY_TPH_EN_SHIFT			13

#define SPHW_DMA_ATTR_ENTRY_ST_MASK				0xFF
#define SPHW_DMA_ATTR_ENTRY_AT_MASK				0x3
#define SPHW_DMA_ATTR_ENTRY_PH_MASK				0x3
#define SPHW_DMA_ATTR_ENTRY_NO_SNOOPING_MASK			0x1
#define SPHW_DMA_ATTR_ENTRY_TPH_EN_MASK			0x1

#define SPHW_DMA_ATTR_ENTRY_SET(val, member)			\
		(((u32)(val) & SPHW_DMA_ATTR_ENTRY_##member##_MASK) << \
			SPHW_DMA_ATTR_ENTRY_##member##_SHIFT)

#define SPHW_DMA_ATTR_ENTRY_CLEAR(val, member)		\
		((val) & (~(SPHW_DMA_ATTR_ENTRY_##member##_MASK	\
			<< SPHW_DMA_ATTR_ENTRY_##member##_SHIFT)))

#define SPHW_PCIE_ST_DISABLE			0
#define SPHW_PCIE_AT_DISABLE			0
#define SPHW_PCIE_PH_DISABLE			0

#define PCIE_MSIX_ATTR_ENTRY			0

#define SPHW_CHIP_PRESENT			1
#define SPHW_CHIP_ABSENT			0

#define SPHW_DEAULT_EQ_MSIX_PENDING_LIMIT	0
#define SPHW_DEAULT_EQ_MSIX_COALESC_TIMER_CFG	0xFF
#define SPHW_DEAULT_EQ_MSIX_RESEND_TIMER_CFG	7

#define SPHW_HWDEV_WQ_NAME			"sphw_hardware"
#define SPHW_WQ_MAX_REQ			10

static void sphw_init_heartbeat_detect(struct sphw_hwdev *hwdev);
static void sphw_destroy_heartbeat_detect(struct sphw_hwdev *hwdev);

typedef void (*mgmt_event_cb)(void *handle, void *buf_in, u16 in_size,
			      void *buf_out, u16 *out_size);

struct mgmt_event_handle {
	u16 cmd;
	mgmt_event_cb proc;
};

int pf_handle_vf_comm_mbox(void *handle, void *pri_handle,
			   u16 vf_id, u16 cmd, void *buf_in,
			   u16 in_size, void *buf_out, u16 *out_size)
{
	struct sphw_hwdev *hwdev = handle;

	if (!hwdev)
		return -EINVAL;

	sdk_warn(hwdev->dev_hdl, "Unsupported vf mbox event %u to process\n",
		 cmd);

	return 0;
}

int vf_handle_pf_comm_mbox(void *handle, void *pri_handle, u16 cmd, void *buf_in,
			   u16 in_size, void *buf_out, u16 *out_size)
{
	struct sphw_hwdev *hwdev = handle;

	if (!hwdev)
		return -EINVAL;

	sdk_warn(hwdev->dev_hdl, "Unsupported pf mbox event %u to process\n",
		 cmd);
	return 0;
}

static void chip_fault_show(struct sphw_hwdev *hwdev, struct sphw_fault_event *event)
{
	char fault_level[FAULT_LEVEL_MAX][FAULT_SHOW_STR_LEN + 1] = {
		"fatal", "reset", "host", "flr", "general", "suggestion"};
	char level_str[FAULT_SHOW_STR_LEN + 1];
	u8 level;

	memset(level_str, 0, FAULT_SHOW_STR_LEN + 1);
	level = event->event.chip.err_level;
	if (level < FAULT_LEVEL_MAX)
		strncpy(level_str, fault_level[level],
			FAULT_SHOW_STR_LEN);
	else
		strncpy(level_str, "Unknown", FAULT_SHOW_STR_LEN);

	if (level == FAULT_LEVEL_SERIOUS_FLR)
		dev_err(hwdev->dev_hdl, "err_level: %u [%s], flr func_id: %u\n",
			level, level_str, event->event.chip.func_id);

	dev_err(hwdev->dev_hdl, "Module_id: 0x%x, err_type: 0x%x, err_level: %u[%s], err_csr_addr: 0x%08x, err_csr_value: 0x%08x\n",
		event->event.chip.node_id,
		event->event.chip.err_type, level, level_str,
		event->event.chip.err_csr_addr,
		event->event.chip.err_csr_value);
}

static void fault_report_show(struct sphw_hwdev *hwdev,
			      struct sphw_fault_event *event)
{
	char fault_type[FAULT_TYPE_MAX][FAULT_SHOW_STR_LEN + 1] = {
		"chip", "ucode", "mem rd timeout", "mem wr timeout",
		"reg rd timeout", "reg wr timeout", "phy fault"
	};
	char type_str[FAULT_SHOW_STR_LEN + 1];
	struct fault_event_stats *fault = NULL;

	sdk_err(hwdev->dev_hdl, "Fault event report received, func_id: %u\n",
		sphw_global_func_id(hwdev));

	memset(type_str, 0, FAULT_SHOW_STR_LEN + 1);
	if (event->type < FAULT_TYPE_MAX)
		strncpy(type_str, fault_type[event->type],
			strlen(fault_type[event->type]));
	else
		strncpy(type_str, "Unknown", strlen("Unknown"));

	sdk_err(hwdev->dev_hdl, "Fault type: %u [%s]\n", event->type, type_str);
	/* 0, 1, 2 and 3 word Represents array event->event.val index */
	sdk_err(hwdev->dev_hdl, "Fault val[0]: 0x%08x, val[1]: 0x%08x, val[2]: 0x%08x, val[3]: 0x%08x\n",
		event->event.val[0], event->event.val[1], event->event.val[2],
		event->event.val[3]);

	fault = &hwdev->hw_stats.fault_event_stats;

	switch (event->type) {
	case FAULT_TYPE_CHIP:
		chip_fault_show(hwdev, event);
		break;
	case FAULT_TYPE_UCODE:
		atomic_inc(&fault->fault_type_stat[event->type]);
		sdk_err(hwdev->dev_hdl, "Cause_id: %u, core_id: %u, c_id: %u, epc: 0x%08x\n",
			event->event.ucode.cause_id, event->event.ucode.core_id,
			event->event.ucode.c_id, event->event.ucode.epc);
		break;
	case FAULT_TYPE_MEM_RD_TIMEOUT:
	case FAULT_TYPE_MEM_WR_TIMEOUT:
		atomic_inc(&fault->fault_type_stat[event->type]);
		sdk_err(hwdev->dev_hdl, "Err_csr_ctrl: 0x%08x, err_csr_data: 0x%08x, ctrl_tab: 0x%08x, mem_index: 0x%08x\n",
			event->event.mem_timeout.err_csr_ctrl,
			event->event.mem_timeout.err_csr_data,
			event->event.mem_timeout.ctrl_tab,
			event->event.mem_timeout.mem_index);
		break;
	case FAULT_TYPE_REG_RD_TIMEOUT:
	case FAULT_TYPE_REG_WR_TIMEOUT:
		atomic_inc(&fault->fault_type_stat[event->type]);
		sdk_err(hwdev->dev_hdl, "Err_csr: 0x%08x\n",
			event->event.reg_timeout.err_csr);
		break;
	case FAULT_TYPE_PHY_FAULT:
		atomic_inc(&fault->fault_type_stat[event->type]);
		sdk_err(hwdev->dev_hdl, "Op_type: %u, port_id: %u, dev_ad: %u, csr_addr: 0x%08x, op_data: 0x%08x\n",
			event->event.phy_fault.op_type,
			event->event.phy_fault.port_id,
			event->event.phy_fault.dev_ad,
			event->event.phy_fault.csr_addr,
			event->event.phy_fault.op_data);
		break;
	default:
		break;
	}
}

static void fault_event_handler(void *dev, void *buf_in, u16 in_size,
				void *buf_out, u16 *out_size)
{
	struct sphw_cmd_fault_event *fault_event = NULL;
	struct sphw_event_info event_info;
	struct sphw_hwdev *hwdev = dev;
	u8 fault_src = SPHW_FAULT_SRC_TYPE_MAX;
	u8 fault_level;

	if (in_size != sizeof(*fault_event)) {
		sdk_err(hwdev->dev_hdl, "Invalid fault event report, length: %u, should be %ld\n",
			in_size, sizeof(*fault_event));
		return;
	}

	fault_event = buf_in;
	fault_report_show(hwdev, &fault_event->event);

	if (fault_event->event.type == FAULT_TYPE_CHIP)
		fault_level = fault_event->event.event.chip.err_level;
	else
		fault_level = FAULT_LEVEL_FATAL;

	if (hwdev->event_callback) {
		event_info.type = SPHW_EVENT_FAULT;
		memcpy(&event_info.info, &fault_event->event,
		       sizeof(struct sphw_fault_event));
		event_info.info.fault_level = fault_level;
		hwdev->event_callback(hwdev->event_pri_handle, &event_info);
	}

	if (fault_event->event.type <= FAULT_TYPE_REG_WR_TIMEOUT)
		fault_src = fault_event->event.type;
	else if (fault_event->event.type == FAULT_TYPE_PHY_FAULT)
		fault_src = SPHW_FAULT_SRC_HW_PHY_FAULT;

	sphw_fault_post_process(hwdev, fault_src, fault_level);
}

static void ffm_event_msg_handler(void *hwdev, void *buf_in, u16 in_size,
				  void *buf_out, u16 *out_size)
{
	struct ffm_intr_info *intr = NULL;
	struct sphw_hwdev *dev = hwdev;

	if (in_size != sizeof(*intr)) {
		sdk_err(dev->dev_hdl, "Invalid fault event report, length: %u, should be %ld.\n",
			in_size, sizeof(*intr));
		return;
	}

	intr = buf_in;

	sdk_err(dev->dev_hdl, "node_id: 0x%x, err_type: 0x%x, err_level: %u, err_csr_addr: 0x%08x, err_csr_value: 0x%08x\n",
		intr->node_id, intr->err_type, intr->err_level,
		intr->err_csr_addr, intr->err_csr_value);
}

const struct mgmt_event_handle mgmt_event_proc[] = {
	{
		.cmd	= COMM_MGMT_CMD_FAULT_REPORT,
		.proc	= fault_event_handler,
	},

	{
		.cmd	= COMM_MGMT_CMD_FFM_SET,
		.proc	= ffm_event_msg_handler,
	},
};

void pf_handle_mgmt_comm_event(void *handle, void *pri_handle, u16 cmd,
			       void *buf_in, u16 in_size, void *buf_out,
			       u16 *out_size)
{
	struct sphw_hwdev *hwdev = handle;
	u32 i, event_num = ARRAY_LEN(mgmt_event_proc);

	if (!hwdev)
		return;

	for (i = 0; i < event_num; i++) {
		if (cmd == mgmt_event_proc[i].cmd) {
			if (mgmt_event_proc[i].proc)
				mgmt_event_proc[i].proc(handle, buf_in, in_size,
							buf_out, out_size);

			return;
		}
	}

	sdk_warn(hwdev->dev_hdl, "Unsupported mgmt cpu event %u to process\n",
		 cmd);
}

void sphw_set_chip_present(void *hwdev)
{
	((struct sphw_hwdev *)hwdev)->chip_present_flag = SPHW_CHIP_PRESENT;
}

void sphw_set_chip_absent(void *hwdev)
{
	struct sphw_hwdev *dev = hwdev;

	sdk_err(dev->dev_hdl, "Card not present\n");
	dev->chip_present_flag = SPHW_CHIP_ABSENT;
}

int sphw_get_chip_present_flag(const void *hwdev)
{
	if (!hwdev)
		return 0;

	return ((struct sphw_hwdev *)hwdev)->chip_present_flag;
}

/* TODO */
void sphw_force_complete_all(void *hwdev)
{
}

void sphw_detect_hw_present(void *hwdev)
{
	u32 addr, attr1;

	addr = SPHW_CSR_FUNC_ATTR1_ADDR;
	attr1 = sphw_hwif_read_reg(((struct sphw_hwdev *)hwdev)->hwif, addr);
	if (attr1 == SPHW_PCIE_LINK_DOWN) {
		sphw_set_chip_absent(hwdev);
		sphw_force_complete_all(hwdev);
	}
}

/**
 * dma_attr_table_init - initialize the default dma attributes
 * @hwdev: the pointer to hw device
 **/
static int dma_attr_table_init(struct sphw_hwdev *hwdev)
{
	u32 addr, val, dst_attr;

	/* Use indirect access should set entry_idx first*/
	addr = SPHW_CSR_DMA_ATTR_INDIR_IDX_ADDR;
	val = sphw_hwif_read_reg(hwdev->hwif, addr);
	val = SPHW_DMA_ATTR_INDIR_IDX_CLEAR(val, IDX);

	val |= SPHW_DMA_ATTR_INDIR_IDX_SET(PCIE_MSIX_ATTR_ENTRY, IDX);

	sphw_hwif_write_reg(hwdev->hwif, addr, val);

	wmb(); /* write index before config */

	addr = SPHW_CSR_DMA_ATTR_TBL_ADDR;
	val = sphw_hwif_read_reg(hwdev->hwif, addr);
	dst_attr = SPHW_DMA_ATTR_ENTRY_SET(SPHW_PCIE_ST_DISABLE, ST)	|
		SPHW_DMA_ATTR_ENTRY_SET(SPHW_PCIE_AT_DISABLE, AT)	|
		SPHW_DMA_ATTR_ENTRY_SET(SPHW_PCIE_PH_DISABLE, PH)	|
		SPHW_DMA_ATTR_ENTRY_SET(SPHW_PCIE_SNOOP, NO_SNOOPING)	|
		SPHW_DMA_ATTR_ENTRY_SET(SPHW_PCIE_TPH_DISABLE, TPH_EN);
	if (dst_attr == val)
		return 0;

	return sphw_set_dma_attr_tbl(hwdev, PCIE_MSIX_ATTR_ENTRY, SPHW_PCIE_ST_DISABLE,
				     SPHW_PCIE_AT_DISABLE, SPHW_PCIE_PH_DISABLE,
				     SPHW_PCIE_SNOOP, SPHW_PCIE_TPH_DISABLE);
}

static int init_aeqs_msix_attr(struct sphw_hwdev *hwdev)
{
	struct sphw_aeqs *aeqs = hwdev->aeqs;
	struct interrupt_info info = {0};
	struct sphw_eq *eq = NULL;
	int q_id;
	int err;

	info.lli_set = 0;
	info.interrupt_coalesc_set = 1;
	info.pending_limt = SPHW_DEAULT_EQ_MSIX_PENDING_LIMIT;
	info.coalesc_timer_cfg = SPHW_DEAULT_EQ_MSIX_COALESC_TIMER_CFG;
	info.resend_timer_cfg = SPHW_DEAULT_EQ_MSIX_RESEND_TIMER_CFG;

	for (q_id = aeqs->num_aeqs - 1; q_id >= 0; q_id--) {
		eq = &aeqs->aeq[q_id];
		info.msix_index = eq->eq_irq.msix_entry_idx;
		err = sphw_set_interrupt_cfg_direct(hwdev, &info, SPHW_CHANNEL_COMM);
		if (err) {
			sdk_err(hwdev->dev_hdl, "Set msix attr for aeq %d failed\n",
				q_id);
			return -EFAULT;
		}
	}

	return 0;
}

static int init_ceqs_msix_attr(struct sphw_hwdev *hwdev)
{
	struct sphw_ceqs *ceqs = hwdev->ceqs;
	struct interrupt_info info = {0};
	struct sphw_eq *eq = NULL;
	u16 q_id;
	int err;

	info.lli_set = 0;
	info.interrupt_coalesc_set = 1;
	info.pending_limt = SPHW_DEAULT_EQ_MSIX_PENDING_LIMIT;
	info.coalesc_timer_cfg = SPHW_DEAULT_EQ_MSIX_COALESC_TIMER_CFG;
	info.resend_timer_cfg = SPHW_DEAULT_EQ_MSIX_RESEND_TIMER_CFG;

	for (q_id = 0; q_id < ceqs->num_ceqs; q_id++) {
		eq = &ceqs->ceq[q_id];
		info.msix_index = eq->eq_irq.msix_entry_idx;
		err = sphw_set_interrupt_cfg(hwdev, info, SPHW_CHANNEL_COMM);
		if (err) {
			sdk_err(hwdev->dev_hdl, "Set msix attr for ceq %u failed\n",
				q_id);
			return -EFAULT;
		}
	}

	return 0;
}

static int sphw_comm_clp_to_mgmt_init(struct sphw_hwdev *hwdev)
{
	int err;

	if (sphw_func_type(hwdev) == TYPE_VF)
		return 0;

	err = sphw_clp_pf_to_mgmt_init(hwdev);
	if (err)
		return err;

	return 0;
}

static void sphw_comm_clp_to_mgmt_free(struct sphw_hwdev *hwdev)
{
	if (sphw_func_type(hwdev) == TYPE_VF)
		return;

	sphw_clp_pf_to_mgmt_free(hwdev);
}

static int sphw_comm_aeqs_init(struct sphw_hwdev *hwdev)
{
	struct irq_info aeq_irqs[SPHW_MAX_AEQS] = {{0} };
	u16 num_aeqs, resp_num_irq = 0, i;
	int err;

	num_aeqs = SPHW_HWIF_NUM_AEQS(hwdev->hwif);
	if (num_aeqs > SPHW_MAX_AEQS) {
		sdk_warn(hwdev->dev_hdl, "Adjust aeq num to %d\n",
			 SPHW_MAX_AEQS);
		num_aeqs = SPHW_MAX_AEQS;
	}
	err = sphw_alloc_irqs(hwdev, SERVICE_T_INTF, num_aeqs, aeq_irqs, &resp_num_irq);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc aeq irqs, num_aeqs: %u\n",
			num_aeqs);
		return err;
	}

	if (resp_num_irq < num_aeqs) {
		sdk_warn(hwdev->dev_hdl, "Adjust aeq num to %u\n",
			 resp_num_irq);
		num_aeqs = resp_num_irq;
	}

	err = sphw_aeqs_init(hwdev, num_aeqs, aeq_irqs);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init aeqs\n");
		goto aeqs_init_err;
	}

	return 0;

aeqs_init_err:
	for (i = 0; i < num_aeqs; i++)
		sphw_free_irq(hwdev, SERVICE_T_INTF, aeq_irqs[i].irq_id);

	return err;
}

static void sphw_comm_aeqs_free(struct sphw_hwdev *hwdev)
{
	struct irq_info aeq_irqs[SPHW_MAX_AEQS] = {{0} };
	u16 num_irqs, i;

	sphw_get_aeq_irqs(hwdev, aeq_irqs, &num_irqs);

	sphw_aeqs_free(hwdev);

	for (i = 0; i < num_irqs; i++)
		sphw_free_irq(hwdev, SERVICE_T_INTF, aeq_irqs[i].irq_id);
}

static int sphw_comm_ceqs_init(struct sphw_hwdev *hwdev)
{
	struct irq_info ceq_irqs[SPHW_MAX_CEQS] = {{0} };
	u16 num_ceqs, resp_num_irq = 0, i;
	int err;

	num_ceqs = SPHW_HWIF_NUM_CEQS(hwdev->hwif);
	if (num_ceqs > SPHW_MAX_CEQS) {
		sdk_warn(hwdev->dev_hdl, "Adjust ceq num to %d\n",
			 SPHW_MAX_CEQS);
		num_ceqs = SPHW_MAX_CEQS;
	}

	err = sphw_alloc_irqs(hwdev, SERVICE_T_INTF, num_ceqs, ceq_irqs, &resp_num_irq);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc ceq irqs, num_ceqs: %u\n",
			num_ceqs);
		return err;
	}

	if (resp_num_irq < num_ceqs) {
		sdk_warn(hwdev->dev_hdl, "Adjust ceq num to %u\n",
			 resp_num_irq);
		num_ceqs = resp_num_irq;
	}

	err = sphw_ceqs_init(hwdev, num_ceqs, ceq_irqs);
	if (err) {
		sdk_err(hwdev->dev_hdl,
			"Failed to init ceqs, err:%d\n", err);
		goto ceqs_init_err;
	}

	return 0;

ceqs_init_err:
	for (i = 0; i < num_ceqs; i++)
		sphw_free_irq(hwdev, SERVICE_T_INTF, ceq_irqs[i].irq_id);

	return err;
}

static void sphw_comm_ceqs_free(struct sphw_hwdev *hwdev)
{
	struct irq_info ceq_irqs[SPHW_MAX_CEQS] = {{0} };
	u16 num_irqs;
	int i;

	sphw_get_ceq_irqs(hwdev, ceq_irqs, &num_irqs);

	sphw_ceqs_free(hwdev);

	for (i = 0; i < num_irqs; i++)
		sphw_free_irq(hwdev, SERVICE_T_INTF, ceq_irqs[i].irq_id);
}

static int sphw_comm_func_to_func_init(struct sphw_hwdev *hwdev)
{
	int err;

	err = sphw_func_to_func_init(hwdev);
	if (err)
		return err;

	sphw_aeq_register_hw_cb(hwdev, SPHW_MBX_FROM_FUNC, sphw_mbox_func_aeqe_handler);
	sphw_aeq_register_hw_cb(hwdev, SPHW_MSG_FROM_MGMT_CPU, sphw_mgmt_msg_aeqe_handler);

	if (!SPHW_IS_VF(hwdev))
		sphw_register_pf_mbox_cb(hwdev, SPHW_MOD_COMM, hwdev->func_to_func,
					 pf_handle_vf_comm_mbox);
	else
		sphw_register_vf_mbox_cb(hwdev, SPHW_MOD_COMM, hwdev->func_to_func,
					 vf_handle_pf_comm_mbox);

	return 0;
}

static void sphw_comm_func_to_func_free(struct sphw_hwdev *hwdev)
{
	sphw_aeq_unregister_hw_cb(hwdev, SPHW_MBX_FROM_FUNC);

	if (!SPHW_IS_VF(hwdev)) {
		sphw_unregister_pf_mbox_cb(hwdev, SPHW_MOD_COMM);
	} else {
		sphw_unregister_vf_mbox_cb(hwdev, SPHW_MOD_COMM);

		sphw_aeq_unregister_hw_cb(hwdev, SPHW_MSG_FROM_MGMT_CPU);
	}

	sphw_func_to_func_free(hwdev);
}

static int sphw_comm_pf_to_mgmt_init(struct sphw_hwdev *hwdev)
{
	int err;

	/* VF do not support api chain */
	if (sphw_func_type(hwdev) == TYPE_VF ||
	    !COMM_SUPPORT_API_CHAIN(hwdev))
		return 0;

	err = sphw_pf_to_mgmt_init(hwdev);
	if (err)
		return err;

	sphw_register_mgmt_msg_cb(hwdev, SPHW_MOD_COMM, hwdev->pf_to_mgmt,
				  pf_handle_mgmt_comm_event);

	return 0;
}

static void sphw_comm_pf_to_mgmt_free(struct sphw_hwdev *hwdev)
{
	/* VF do not support api chain */
	if (sphw_func_type(hwdev) == TYPE_VF ||
	    !COMM_SUPPORT_API_CHAIN(hwdev))
		return;

	sphw_unregister_mgmt_msg_cb(hwdev, SPHW_MOD_COMM);

	sphw_aeq_unregister_hw_cb(hwdev, SPHW_MSG_FROM_MGMT_CPU);

	sphw_pf_to_mgmt_free(hwdev);
}

static int sphw_comm_cmdqs_init(struct sphw_hwdev *hwdev)
{
	int err;

	err = sphw_cmdqs_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init cmd queues\n");
		return err;
	}

	sphw_ceq_register_cb(hwdev, SPHW_CMDQ, sphw_cmdq_ceq_handler);

	err = sphw_set_cmdq_depth(hwdev, SPHW_CMDQ_DEPTH);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to set cmdq depth\n");
		goto set_cmdq_depth_err;
	}

	return 0;

set_cmdq_depth_err:
	sphw_cmdqs_free(hwdev);

	return err;
}

static void sphw_comm_cmdqs_free(struct sphw_hwdev *hwdev)
{
	sphw_ceq_unregister_cb(hwdev, SPHW_CMDQ);
	sphw_cmdqs_free(hwdev);
}

static void sphw_sync_mgmt_func_state(struct sphw_hwdev *hwdev)
{
	sphw_set_pf_status(hwdev->hwif, SPHW_PF_STATUS_ACTIVE_FLAG);
}

static void sphw_unsync_mgmt_func_state(struct sphw_hwdev *hwdev)
{
	sphw_set_pf_status(hwdev->hwif, SPHW_PF_STATUS_INIT);
}

static int init_basic_attributes(struct sphw_hwdev *hwdev)
{
	int err;

	err = sphw_get_board_info(hwdev, &hwdev->board_info, SPHW_CHANNEL_COMM);
	if (err)
		return err;

	err = sphw_get_comm_features(hwdev, hwdev->features, COMM_MAX_FEATURE_QWORD);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Get comm features failed\n");
		return err;
	}

	sdk_info(hwdev->dev_hdl, "Comm features: 0x%llx\n", hwdev->features[0]);

	err = sphw_get_global_attr(hwdev, &hwdev->glb_attr);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to get global attribute\n");
		return err;
	}

	sdk_info(hwdev->dev_hdl, "global attribute: max_host: 0x%x, max_pf: 0x%x, vf_id_start: 0x%x, mgmt cpu node id: 0x%x\n",
		 hwdev->glb_attr.max_host_num, hwdev->glb_attr.max_pf_num,
		 hwdev->glb_attr.vf_id_start,
		 hwdev->glb_attr.mgmt_host_node_id);

	sphw_init_profile_adapter(hwdev);

	return 0;
}

static int init_basic_mgmt_channel(struct sphw_hwdev *hwdev)
{
	int err;

	err = sphw_comm_aeqs_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init async event queues\n");
		return err;
	}

	err = sphw_comm_func_to_func_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init mailbox\n");
		goto func_to_func_init_err;
	}

	err = init_aeqs_msix_attr(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init aeqs msix attr\n");
		goto aeqs_msix_attr_init_err;
	}

	return 0;

aeqs_msix_attr_init_err:
	sphw_comm_func_to_func_free(hwdev);

func_to_func_init_err:
	sphw_comm_aeqs_free(hwdev);

	return err;
}

static void free_base_mgmt_channel(struct sphw_hwdev *hwdev)
{
	sphw_comm_func_to_func_free(hwdev);
	sphw_comm_aeqs_free(hwdev);
}

static int init_pf_mgmt_channel(struct sphw_hwdev *hwdev)
{
	int err;

	err = sphw_comm_clp_to_mgmt_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init clp\n");
		return err;
	}

	err = sphw_comm_pf_to_mgmt_init(hwdev);
	if (err) {
		sphw_comm_clp_to_mgmt_free(hwdev);
		sdk_err(hwdev->dev_hdl, "Failed to init pf to mgmt\n");
		return err;
	}

	return 0;
}

static void free_pf_mgmt_channel(struct sphw_hwdev *hwdev)
{
	sphw_comm_clp_to_mgmt_free(hwdev);
	sphw_comm_pf_to_mgmt_free(hwdev);
}

static int init_mgmt_channel_post(struct sphw_hwdev *hwdev)
{
	int err;

	/* mbox host channel resources will be freed in
	 * sphw_func_to_func_free
	 */
	err = sphw_mbox_init_host_msg_channel(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init mbox host channel\n");
		return err;
	}

	err = init_pf_mgmt_channel(hwdev);
	if (err)
		return err;

	return 0;
}

static void free_mgmt_msg_channel_post(struct sphw_hwdev *hwdev)
{
	free_pf_mgmt_channel(hwdev);
}

static int init_cmdqs_channel(struct sphw_hwdev *hwdev)
{
	int err;

	err = dma_attr_table_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init dma attr table\n");
		goto dma_attr_init_err;
	}

	err = sphw_comm_ceqs_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init completion event queues\n");
		goto ceqs_init_err;
	}

	err = init_ceqs_msix_attr(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init ceqs msix attr\n");
		goto init_ceq_msix_err;
	}

	/* set default wq page_size */
	if (wq_page_order > SPHW_MAX_WQ_PAGE_SIZE_ORDER) {
		sdk_info(hwdev->dev_hdl, "wq_page_order exceed limit[0, %d], reset to %d\n",
			 SPHW_MAX_WQ_PAGE_SIZE_ORDER,
			 SPHW_MAX_WQ_PAGE_SIZE_ORDER);
		wq_page_order = SPHW_MAX_WQ_PAGE_SIZE_ORDER;
	}
	hwdev->wq_page_size = SPHW_HW_WQ_PAGE_SIZE * (1U << wq_page_order);
	sdk_info(hwdev->dev_hdl, "WQ page size: 0x%x\n", hwdev->wq_page_size);
	err = sphw_set_wq_page_size(hwdev, sphw_global_func_id(hwdev), hwdev->wq_page_size,
				    SPHW_CHANNEL_COMM);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to set wq page size\n");
		goto init_wq_pg_size_err;
	}

	err = sphw_comm_cmdqs_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init cmd queues\n");
		goto cmdq_init_err;
	}

	return 0;

cmdq_init_err:
	if (SPHW_FUNC_TYPE(hwdev) != TYPE_VF)
		sphw_set_wq_page_size(hwdev, sphw_global_func_id(hwdev), SPHW_HW_WQ_PAGE_SIZE,
				      SPHW_CHANNEL_COMM);
init_wq_pg_size_err:
init_ceq_msix_err:
	sphw_comm_ceqs_free(hwdev);

ceqs_init_err:
dma_attr_init_err:

	return err;
}

int sphw_init_comm_ch(struct sphw_hwdev *hwdev)
{
	int err;

	err = init_basic_mgmt_channel(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init mgmt channel\n");
		return err;
	}

	err = sphw_func_reset(hwdev, sphw_global_func_id(hwdev), SPHW_COMM_RES, SPHW_CHANNEL_COMM);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to reset function\n");
		goto func_reset_err;
	}

	err = init_basic_attributes(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init basic attributes\n");
		goto init_basic_attr_err;
	}

	err = init_mgmt_channel_post(hwdev);
	if (err)
		goto init_mgmt_channel_post_err;

	err = init_cmdqs_channel(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init cmdq channel\n");
		goto init_cmdqs_channel_err;
	}

	sphw_sync_mgmt_func_state(hwdev);

	if (SPHW_F_CHANNEL_LOCK_EN(hwdev)) {
		sphw_mbox_enable_channel_lock(hwdev, true);
		sphw_cmdq_enable_channel_lock(hwdev, true);
	}

	return 0;

init_cmdqs_channel_err:
	free_mgmt_msg_channel_post(hwdev);
init_mgmt_channel_post_err:
init_basic_attr_err:
func_reset_err:
	free_base_mgmt_channel(hwdev);

	return err;
}

void sphw_uninit_comm_ch(struct sphw_hwdev *hwdev)
{
	sphw_unsync_mgmt_func_state(hwdev);

	sphw_comm_cmdqs_free(hwdev);

	if (SPHW_FUNC_TYPE(hwdev) != TYPE_VF)
		sphw_set_wq_page_size(hwdev, sphw_global_func_id(hwdev), SPHW_HW_WQ_PAGE_SIZE,
				      SPHW_CHANNEL_COMM);

	sphw_comm_ceqs_free(hwdev);

	sphw_deinit_profile_adapter(hwdev);

	free_mgmt_msg_channel_post(hwdev);

	free_base_mgmt_channel(hwdev);
}

int sphw_init_hwdev(struct sphw_init_para *para)
{
	struct sphw_hwdev *hwdev;
	int err;

	hwdev = kzalloc(sizeof(*hwdev), GFP_KERNEL);
	if (!hwdev)
		return -ENOMEM;

	*para->hwdev = hwdev;
	hwdev->adapter_hdl = para->adapter_hdl;
	hwdev->pcidev_hdl = para->pcidev_hdl;
	hwdev->dev_hdl = para->dev_hdl;
	hwdev->chip_node = para->chip_node;
	hwdev->poll = para->poll;

	hwdev->chip_fault_stats = vzalloc(SPHW_CHIP_FAULT_SIZE);
	if (!hwdev->chip_fault_stats)
		goto alloc_chip_fault_stats_err;

	err = sphw_init_hwif(hwdev, para->cfg_reg_base, para->intr_reg_base,
			     para->mgmt_reg_base, para->db_base_phy,
			     para->db_base, para->db_dwqe_len);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init hwif\n");
		goto init_hwif_err;
	}

	sphw_set_chip_present(hwdev);

	if (disable_cfg_comm)
		return 0;

	hwdev->workq = alloc_workqueue(SPHW_HWDEV_WQ_NAME, WQ_MEM_RECLAIM,
				       SPHW_WQ_MAX_REQ);
	if (!hwdev->workq) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc hardware workq\n");
		goto alloc_workq_err;
	}

	sphw_init_heartbeat_detect(hwdev);

	err = init_cfg_mgmt(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init config mgmt\n");
		goto init_cfg_mgmt_err;
	}

	err = sphw_init_comm_ch(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init communication channel\n");
		goto init_comm_ch_err;
	}

	err = init_capability(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init capability\n");
		goto init_cap_err;
	}

	err = sphw_set_comm_features(hwdev, hwdev->features, COMM_MAX_FEATURE_QWORD);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to set comm features\n");
		goto set_feature_err;
	}

	return 0;

set_feature_err:
	free_capability(hwdev);

init_cap_err:
	sphw_uninit_comm_ch(hwdev);

init_comm_ch_err:
	free_cfg_mgmt(hwdev);

init_cfg_mgmt_err:
	sphw_destroy_heartbeat_detect(hwdev);
	destroy_workqueue(hwdev->workq);

alloc_workq_err:
	sphw_free_hwif(hwdev);

init_hwif_err:
	vfree(hwdev->chip_fault_stats);

alloc_chip_fault_stats_err:
	kfree(hwdev);
	*para->hwdev = NULL;

	return -EFAULT;
}

void sphw_free_hwdev(void *hwdev)
{
	struct sphw_hwdev *dev = hwdev;

	sphw_func_rx_tx_flush(hwdev, SPHW_CHANNEL_COMM);

	free_capability(dev);

	sphw_uninit_comm_ch(dev);

	free_cfg_mgmt(dev);
	sphw_destroy_heartbeat_detect(hwdev);
	destroy_workqueue(dev->workq);
	sphw_free_hwif(dev);
	vfree(dev->chip_fault_stats);

	kfree(dev);
}

void *sphw_get_pcidev_hdl(void *hwdev)
{
	struct sphw_hwdev *dev = (struct sphw_hwdev *)hwdev;

	if (!hwdev)
		return NULL;

	return dev->pcidev_hdl;
}

int sphw_register_service_adapter(void *hwdev, void *service_adapter, enum sphw_service_type type)
{
	struct sphw_hwdev *dev = hwdev;

	if (!hwdev || !service_adapter || type >= SERVICE_T_MAX)
		return -EINVAL;

	if (dev->service_adapter[type])
		return -EINVAL;

	dev->service_adapter[type] = service_adapter;

	return 0;
}

void sphw_unregister_service_adapter(void *hwdev, enum sphw_service_type type)
{
	struct sphw_hwdev *dev = hwdev;

	if (!hwdev || type >= SERVICE_T_MAX)
		return;

	dev->service_adapter[type] = NULL;
}

void *sphw_get_service_adapter(void *hwdev, enum sphw_service_type type)
{
	struct sphw_hwdev *dev = hwdev;

	if (!hwdev || type >= SERVICE_T_MAX)
		return NULL;

	return dev->service_adapter[type];
}

int sphw_dbg_get_hw_stats(const void *hwdev, u8 *hw_stats, u16 *out_size)
{
	if (*out_size != sizeof(struct sphw_hw_stats)) {
		pr_err("Unexpect out buf size from user :%u, expect: %lu\n",
		       *out_size, sizeof(struct sphw_hw_stats));
		return -EFAULT;
	}

	memcpy(hw_stats, &((struct sphw_hwdev *)hwdev)->hw_stats,
	       sizeof(struct sphw_hw_stats));
	return 0;
}

u16 sphw_dbg_clear_hw_stats(void *hwdev)
{
	memset((void *)&((struct sphw_hwdev *)hwdev)->hw_stats, 0,
	       sizeof(struct sphw_hw_stats));
	memset((void *)((struct sphw_hwdev *)hwdev)->chip_fault_stats, 0,
	       SPHW_CHIP_FAULT_SIZE);
	return sizeof(struct sphw_hw_stats);
}

void sphw_get_chip_fault_stats(const void *hwdev, u8 *chip_fault_stats, u32 offset)
{
	u32 copy_len = offset + MAX_DRV_BUF_SIZE - SPHW_CHIP_FAULT_SIZE;

	if (offset + MAX_DRV_BUF_SIZE <= SPHW_CHIP_FAULT_SIZE)
		memcpy(chip_fault_stats,
		       ((struct sphw_hwdev *)hwdev)->chip_fault_stats
		       + offset, MAX_DRV_BUF_SIZE);
	else
		memcpy(chip_fault_stats,
		       ((struct sphw_hwdev *)hwdev)->chip_fault_stats
		       + offset, copy_len);
}

void sphw_event_register(void *dev, void *pri_handle, sphw_event_handler callback)
{
	struct sphw_hwdev *hwdev = dev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for register event\n");
		return;
	}

	hwdev->event_callback = callback;
	hwdev->event_pri_handle = pri_handle;
}

void sphw_event_unregister(void *dev)
{
	struct sphw_hwdev *hwdev = dev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for register event\n");
		return;
	}

	hwdev->event_callback = NULL;
	hwdev->event_pri_handle = NULL;
}

void sphw_event_callback(void *hwdev, struct sphw_event_info *event)
{
	struct sphw_hwdev *dev = hwdev;

	if (!hwdev) {
		pr_err("Hwdev pointer is NULL for event callback\n");
		return;
	}

	if (!dev->event_callback) {
		sdk_info(dev->dev_hdl, "Event callback function not register\n");
		return;
	}

	dev->event_callback(dev->event_pri_handle, event);
}

void sphw_set_pcie_order_cfg(void *handle)
{
}

void sphw_disable_mgmt_msg_report(void *hwdev)
{
	struct sphw_hwdev *hw_dev = (struct sphw_hwdev *)hwdev;

	sphw_set_pf_status(hw_dev->hwif, SPHW_PF_STATUS_INIT);
}

void sphw_record_pcie_error(void *hwdev)
{
	struct sphw_hwdev *dev = (struct sphw_hwdev *)hwdev;

	if (!hwdev)
		return;

	atomic_inc(&dev->hw_stats.fault_event_stats.pcie_fault_stats);
}

int sphw_get_card_present_state(void *hwdev, bool *card_present_state)
{
	struct sphw_hwdev *dev = hwdev;
	u32 addr, attr1;

	if (!hwdev || !card_present_state)
		return -EINVAL;

	addr = SPHW_CSR_FUNC_ATTR1_ADDR;
	attr1 = sphw_hwif_read_reg(dev->hwif, addr);
	if (attr1 == SPHW_PCIE_LINK_DOWN) {
		sdk_warn(dev->dev_hdl, "Card is not present\n");
		*card_present_state = (bool)0;
	} else {
		*card_present_state = (bool)1;
	}

	return 0;
}

void sphw_link_event_stats(void *dev, u8 link)
{
	struct sphw_hwdev *hwdev = dev;

	if (link)
		atomic_inc(&hwdev->hw_stats.link_event_stats.link_up_stats);
	else
		atomic_inc(&hwdev->hw_stats.link_event_stats.link_down_stats);
}

u8 sphw_max_pf_num(void *hwdev)
{
	if (!hwdev)
		return 0;

	return SPHW_MAX_PF_NUM((struct sphw_hwdev *)hwdev);
}

void sphw_fault_event_report(void *hwdev, u16 src, u16 level)
{
	if (!hwdev)
		return;

	sdk_info(((struct sphw_hwdev *)hwdev)->dev_hdl, "Fault event report, src: %u, level: %u\n",
		 src, level);

	sphw_fault_post_process(hwdev, src, level);
}

void sphw_heartbeat_lost_handler(struct work_struct *work)
{
	struct sphw_event_info event_info = { 0 };
	struct sphw_hwdev *hwdev = container_of(work, struct sphw_hwdev,
						  heartbeat_lost_work);
	u16 src, level;

	atomic_inc(&hwdev->hw_stats.heart_lost_stats);

	if (hwdev->event_callback) {
		event_info.type =
			hwdev->pcie_link_down ? SPHW_EVENT_PCIE_LINK_DOWN :
			SPHW_EVENT_HEART_LOST;
		hwdev->event_callback(hwdev->event_pri_handle, &event_info);
	}

	if (hwdev->pcie_link_down) {
		src = SPHW_FAULT_SRC_PCIE_LINK_DOWN;
		level = FAULT_LEVEL_HOST;
		sdk_err(hwdev->dev_hdl, "Detect pcie is link down\n");
	} else {
		src = SPHW_FAULT_SRC_HOST_HEARTBEAT_LOST;
		level = FAULT_LEVEL_FATAL;
		sdk_err(hwdev->dev_hdl, "Heart lost report received, func_id: %d\n",
			sphw_global_func_id(hwdev));
	}

	sphw_fault_post_process(hwdev, src, level);
}

#define DETECT_PCIE_LINK_DOWN_RETRY		2
#define SPHW_HEARTBEAT_START_EXPIRE		5000
#define SPHW_HEARTBEAT_PERIOD			1000

static bool sphw_is_hw_abnormal(struct sphw_hwdev *hwdev)
{
	u32 status;

	if (!sphw_get_chip_present_flag(hwdev))
		return false;

	status = sphw_get_heartbeat_status(hwdev);
	if (status == SPHW_PCIE_LINK_DOWN) {
		sdk_warn(hwdev->dev_hdl, "Detect BAR register read failed\n");
		hwdev->rd_bar_err_cnt++;
		if (hwdev->rd_bar_err_cnt >= DETECT_PCIE_LINK_DOWN_RETRY) {
			sphw_set_chip_absent(hwdev);
			sphw_force_complete_all(hwdev);
			hwdev->pcie_link_down = true;
			return true;
		}

		return false;
	}

	if (status) {
		hwdev->heartbeat_lost = true;
		return true;
	}

	hwdev->rd_bar_err_cnt = 0;

	return false;
}

static void sphw_heartbeat_timer_handler(struct timer_list *t)
{
	struct sphw_hwdev *hwdev = from_timer(hwdev, t, heartbeat_timer);

	if (sphw_is_hw_abnormal(hwdev))
		queue_work(hwdev->workq, &hwdev->heartbeat_lost_work);
	else
		mod_timer(&hwdev->heartbeat_timer,
			  jiffies + msecs_to_jiffies(SPHW_HEARTBEAT_PERIOD));
}

static void sphw_init_heartbeat_detect(struct sphw_hwdev *hwdev)
{
	timer_setup(&hwdev->heartbeat_timer, sphw_heartbeat_timer_handler, 0);

	hwdev->heartbeat_timer.expires =
		jiffies + msecs_to_jiffies(SPHW_HEARTBEAT_START_EXPIRE);

	add_timer(&hwdev->heartbeat_timer);

	INIT_WORK(&hwdev->heartbeat_lost_work, sphw_heartbeat_lost_handler);
}

static void sphw_destroy_heartbeat_detect(struct sphw_hwdev *hwdev)
{
	del_timer_sync(&hwdev->heartbeat_timer);
}
