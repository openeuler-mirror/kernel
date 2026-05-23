/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hwdev.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/semaphore.h>
#include <linux/interrupt.h>
#include <linux/vmalloc.h>

#include "ossl_knl.h"
#include "hinic5_mt.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_common.h"
#include "hinic5_csr_inner.h"
#include "hinic5_hwif_inner.h"
#include "hinic5_typedef_inner.h"
#include "hinic5_eqs.h"
#include "hinic5_api_cmd.h"
#include "hinic5_mgmt.h"
#include "hinic5_mbox.h"
#include "hinic5_cmdq.h"
#include "hinic5_hw_cfg.h"
#include "hinic5_hw_comm.h"
#include "hinic5_hinic5_cqm.h"
#include "sdk_pub_cmd.h"
#if !defined(__WIN__)
#include "hinic5_cqm_fast_msg.h"
#include "hinic5_devlink.h"
#endif
#include "mpu_inband_cmd.h"
#if defined(__UEFI__) && !defined(__HIFC__)
#include "mpu_board_defs.h"
#endif
#include "hinic5_prof_adap.h"
#include "hinic5_chip_info.h"
#if !defined(__UEFI__) && !defined(__VMWARE__) && !defined(__WIN__)
#include "hinic5_id_tbl.h"
#include "hinic5_bus.h"
#include "hinic5_lld.h"
#include "hinic5_dev_mgmt.h"
#include "hinic5_micro_log.h"
#include "hinic5_non_ptp.h"
#endif
#include "hinic5_hwdev.h"

static unsigned int wq_page_order = HINIC5_MAX_WQ_PAGE_SIZE_ORDER;
module_param(wq_page_order, uint, 0444);
MODULE_PARM_DESC(wq_page_order, "Set wq page size order, wq page size is 4K * " \
		 "(2 ^ wq_page_order) - default is 8");

static ulong perf_en_bitmap;
module_param(perf_en_bitmap, ulong, 0644);
MODULE_PARM_DESC(perf_en_bitmap,
		 "Set perf enable bitmap: 0-disable, 1-enable (bit(0)-cmdq, " \
		 "bit(1)-mailbox) - default is 0");

#define HINIC5_DMA_ATTR_INDIR_IDX_SHIFT				0
#define UNKNOWN_LEN   7

#define HINIC5_DMA_ATTR_INDIR_IDX_MASK				0x3FF

#define HINIC5_DMA_ATTR_INDIR_IDX_SET(val, member)			\
		(((u32)(val) & HINIC5_DMA_ATTR_INDIR_##member##_MASK) << \
			HINIC5_DMA_ATTR_INDIR_##member##_SHIFT)

#define HINIC5_DMA_ATTR_INDIR_IDX_CLEAR(val, member)		\
		((val) & (~(HINIC5_DMA_ATTR_INDIR_##member##_MASK	\
			<< HINIC5_DMA_ATTR_INDIR_##member##_SHIFT)))

#define HINIC5_DMA_ATTR_ENTRY_ST_SHIFT				0
#define HINIC5_DMA_ATTR_ENTRY_AT_SHIFT				8
#define HINIC5_DMA_ATTR_ENTRY_PH_SHIFT				10
#define HINIC5_DMA_ATTR_ENTRY_NO_SNOOPING_SHIFT			12
#define HINIC5_DMA_ATTR_ENTRY_TPH_EN_SHIFT			13

#define HINIC5_DMA_ATTR_ENTRY_ST_MASK				0xFF
#define HINIC5_DMA_ATTR_ENTRY_AT_MASK				0x3
#define HINIC5_DMA_ATTR_ENTRY_PH_MASK				0x3
#define HINIC5_DMA_ATTR_ENTRY_NO_SNOOPING_MASK			0x1
#define HINIC5_DMA_ATTR_ENTRY_TPH_EN_MASK			0x1

#define HINIC5_DMA_ATTR_ENTRY_SET(val, member)			\
		(((u32)(val) & HINIC5_DMA_ATTR_ENTRY_##member##_MASK) << \
			HINIC5_DMA_ATTR_ENTRY_##member##_SHIFT)

#define HINIC5_DMA_ATTR_ENTRY_CLEAR(val, member)		\
		((val) & (~(HINIC5_DMA_ATTR_ENTRY_##member##_MASK	\
			<< HINIC5_DMA_ATTR_ENTRY_##member##_SHIFT)))

#define HINIC5_PCIE_ST_DISABLE			0
#define HINIC5_PCIE_AT_DISABLE			0
#define HINIC5_PCIE_PH_DISABLE			0

#define PCIE_MSIX_ATTR_ENTRY			0

#define HINIC5_DEAULT_EQ_MSIX_PENDING_LIMIT	0
#define HINIC5_DEAULT_EQ_MSIX_COALESC_TIMER_CFG	0xFF
#define HINIC5_DEAULT_EQ_MSIX_RESEND_TIMER_CFG	7

#define HINIC5_HWDEV_WQ_NAME			"hinic5_hardware"
#define HINIC5_WQ_MAX_REQ			10

#define SLAVE_HOST_STATUS_CLEAR(host_id, val)	((val) & (~(1U << (host_id))))
#define SLAVE_HOST_STATUS_SET(host_id, enable)	(((u8)(enable) & 1U) << (host_id))
#define SLAVE_HOST_STATUS_GET(host_id, val)	(((val) & (1U << (host_id))) != 0)

#define HINIC5_COMM_RES \
		((BIT(RES_TYPE_COMM)) | (BIT(RES_TYPE_COMM_CMD_CH)) | \
				(BIT(RES_TYPE_FLUSH_BIT)) | (BIT(RES_TYPE_MQM)) | \
				(BIT(RES_TYPE_SMF)) | (BIT(RES_TYPE_PF_BW_CFG)))

void hinic5_set_slave_host_enable(void *hwdev, u8 host_id, bool enable)
{
	u32 reg_val;
	struct hinic5_hwdev *dev = (struct hinic5_hwdev *)hwdev;

	if (HINIC5_FUNC_TYPE(dev) != TYPE_PPF)
		return;

	reg_val = hinic5_hwif_read_reg(dev->hwif, HINIC5_MULT_HOST_SLAVE_STATUS_ADDR);

	reg_val = SLAVE_HOST_STATUS_CLEAR(host_id, reg_val);
	reg_val |= SLAVE_HOST_STATUS_SET(host_id, enable);
	hinic5_hwif_write_reg(dev->hwif, HINIC5_MULT_HOST_SLAVE_STATUS_ADDR, reg_val);

	sdk_info(dev->dev_hdl, "Set slave host %u status %d, reg value: 0x%x\n",
		 host_id, enable, reg_val);
}

int hinic5_get_slave_host_enable(void *hwdev, u8 host_id, u8 *slave_en)
{
	struct hinic5_hwdev *dev = hwdev;

	u32 reg_val;

	if (!hwdev || !slave_en)
		return -EINVAL;

	if (HINIC5_FUNC_TYPE(dev) != TYPE_PPF) {
		sdk_warn(dev->dev_hdl, "hwdev should be ppf\n");
		return -EINVAL;
	}

	reg_val = hinic5_hwif_read_reg(dev->hwif, HINIC5_MULT_HOST_SLAVE_STATUS_ADDR);
	*slave_en = SLAVE_HOST_STATUS_GET(host_id, reg_val);

	return 0;
}
EXPORT_SYMBOL(hinic5_get_slave_host_enable);

int hinic5_get_slave_bitmap(void *hwdev, u8 *slave_host_bitmap)
{
	struct hinic5_hwdev *dev = hwdev;
	struct service_cap *cap = NULL;

	if (!dev || !dev->cfg_mgmt)
		return -EINVAL;
	cap = &dev->cfg_mgmt->svc_cap;
	if (HINIC5_FUNC_TYPE(dev) != TYPE_PPF) {
		sdk_warn(dev->dev_hdl, "hwdev should be ppf\n");
		return -EINVAL;
	}

	*slave_host_bitmap = cap->host_valid_bitmap & (~(1U << cap->master_host_id));

	return 0;
}
EXPORT_SYMBOL(hinic5_get_slave_bitmap);

static void hinic5_init_host_mode_pre(struct hinic5_hwdev *hwdev)
{
	struct service_cap *cap = &hwdev->cfg_mgmt->svc_cap;
	u8 host_id = hwdev->hwif->attr.pci_intf_idx;

	switch (cap->srv_multi_host_mode) {
	case HINIC5_SDI_MODE_BM:
		if (host_id == cap->master_host_id)
			hwdev->func_mode = FUNC_MOD_MULTI_BM_MASTER;
		else
			hwdev->func_mode = FUNC_MOD_MULTI_BM_SLAVE;
		break;
	case HINIC5_SDI_MODE_VM:
		if (host_id == cap->master_host_id)
			hwdev->func_mode = FUNC_MOD_MULTI_VM_MASTER;
		else
			hwdev->func_mode = FUNC_MOD_MULTI_VM_SLAVE;
		break;
	default:
		hwdev->func_mode = FUNC_MOD_NORMAL_HOST;
		break;
	}
	sdk_info(hwdev->dev_hdl, "host mode init, host_mode:%d, func_mode:%d\n",
		 cap->srv_multi_host_mode, hwdev->func_mode);
}

STATIC int hinic5_multi_host_enable(struct hinic5_hwdev *hwdev, bool enable)
{
	if (!IS_SLAVE_HOST(hwdev) || !HINIC5_IS_PPF(hwdev))
		return 0;

	hinic5_set_slave_host_enable(hwdev, hinic5_pcie_itf_id(hwdev), enable);

	return 0;
}

static void hinic5_init_heartbeat_detect(struct hinic5_hwdev *hwdev);
static void hinic5_destroy_heartbeat_detect(struct hinic5_hwdev *hwdev);

typedef void (*mgmt_event_cb)(void *handle, void *buf_in, u16 in_size,
			      void *buf_out, u16 *out_size);

struct mgmt_event_handle {
	u16 cmd;
	mgmt_event_cb proc;
};

static int pf_handle_vf_comm_mbox(void *pri_handle,
				  u16 vf_id, u16 cmd, void *buf_in,
				  u16 in_size, void *buf_out, u16 *out_size)
{
	struct hinic5_hwdev *hwdev = pri_handle;

	if (!hwdev)
		return -EINVAL;

	sdk_warn(hwdev->dev_hdl, "Unsupported vf mbox event %u to process\n",
		 cmd);

	return 0;
}

static int vf_handle_pf_comm_mbox(void *pri_handle,
				  u16 cmd, void *buf_in,
				  u16 in_size, void *buf_out, u16 *out_size)
{
	struct hinic5_hwdev *hwdev = pri_handle;

	if (!hwdev)
		return -EINVAL;

	sdk_warn(hwdev->dev_hdl, "Unsupported pf mbox event %u to process\n",
		 cmd);
	return 0;
}

static void chip_fault_show(struct hinic5_hwdev *hwdev,
			    struct hinic5_fault_event *event)
{
	char fault_level[FAULT_LEVEL_MAX][FAULT_SHOW_STR_LEN + 1] = {
		"fatal", "reset", "host", "flr", "general", "suggestion"};
	char level_str[FAULT_SHOW_STR_LEN + 1];
	u8 level;

	memset(level_str, 0, FAULT_SHOW_STR_LEN + 1);
	level = event->event.chip.err_level;
	if (level < FAULT_LEVEL_MAX)
		strscpy(level_str, fault_level[level], sizeof(level_str));
	else
		strscpy(level_str, "Unknown", sizeof(level_str));

	if (level == FAULT_LEVEL_SERIOUS_FLR)
		dev_err(hwdev->dev_hdl, "err_level: %u [%s], flr func_id: %u\n",
			level, level_str, event->event.chip.func_id);

	dev_err(hwdev->dev_hdl,
		"Module_id: 0x%x, err_type: 0x%x, err_level: %u[%s], err_csr_addr: 0x%08x, err_csr_value: 0x%08x\n",
		event->event.chip.node_id,
		event->event.chip.err_type, level, level_str,
		event->event.chip.err_csr_addr,
		event->event.chip.err_csr_value);
}

static void fault_report_show(struct hinic5_hwdev *hwdev,
			      struct hinic5_fault_event *event)
{
	char fault_type[FAULT_TYPE_MAX][FAULT_SHOW_STR_LEN + 1] = {
		"chip", "ucode", "mem rd timeout", "mem wr timeout",
		"reg rd timeout", "reg wr timeout", "phy fault", "tsensor fault"
	};
	char type_str[FAULT_SHOW_STR_LEN + 1] = {0};
	struct fault_event_stats *fault = NULL;

	sdk_err(hwdev->dev_hdl, "Fault event report received, func_id: %u\n",
		hinic5_global_func_id(hwdev));

	fault = &hwdev->hw_stats.fault_event_stats;

	if (event->type < FAULT_TYPE_MAX) {
		strscpy(type_str, fault_type[event->type], sizeof(type_str));
		atomic_inc(&fault->fault_type_stat[event->type]);
	} else {
		strscpy(type_str, "Unknown", sizeof(type_str));
	}

	sdk_err(hwdev->dev_hdl, "Fault type: %u [%s]\n", event->type, type_str);
	/* 0, 1, 2 and 3 word Represents array event->event.val index */
	sdk_err(hwdev->dev_hdl,
		"Fault val[0]: 0x%08x, val[1]: 0x%08x, val[2]: 0x%08x, val[3]: 0x%08x\n",
		event->event.val[0x0], event->event.val[0x1],
		event->event.val[0x2], event->event.val[0x3]);

	hinic5_show_chip_err_info(hwdev);

	switch (event->type) {
	case FAULT_TYPE_CHIP:
		chip_fault_show(hwdev, event);
		break;
	case FAULT_TYPE_UCODE:
		sdk_err(hwdev->dev_hdl, "Cause_id: %u, core_id: %u, c_id: %u, epc: 0x%08x\n",
			event->event.ucode.cause_id, event->event.ucode.core_id,
			event->event.ucode.c_id, event->event.ucode.epc);
		break;
	case FAULT_TYPE_MEM_RD_TIMEOUT:
	case FAULT_TYPE_MEM_WR_TIMEOUT:
		sdk_err(hwdev->dev_hdl,
			"Err_csr_ctrl: 0x%08x, err_csr_data: 0x%08x, ctrl_tab: 0x%08x, mem_index: 0x%08x\n",
			event->event.mem_timeout.err_csr_ctrl,
			event->event.mem_timeout.err_csr_data,
			event->event.mem_timeout.ctrl_tab, event->event.mem_timeout.mem_index);
		break;
	case FAULT_TYPE_REG_RD_TIMEOUT:
	case FAULT_TYPE_REG_WR_TIMEOUT:
		sdk_err(hwdev->dev_hdl, "Err_csr: 0x%08x\n", event->event.reg_timeout.err_csr);
		break;
	case FAULT_TYPE_PHY_FAULT:
		sdk_err(hwdev->dev_hdl,
			"Op_type: %u, port_id: %u, dev_ad: %u, csr_addr: 0x%08x, op_data: 0x%08x\n",
			event->event.phy_fault.op_type,
			event->event.phy_fault.port_id, event->event.phy_fault.dev_ad,
			event->event.phy_fault.csr_addr, event->event.phy_fault.op_data);
		break;
	default:
		break;
	}
}

static void fault_event_handler(void *dev, void *buf_in, u16 in_size,
				void *buf_out, u16 *out_size)
{
	struct hinic5_cmd_fault_event *fault_event = NULL;
	struct hinic5_fault_event *fault = NULL;
	struct hinic5_event_info event_info;
	struct hinic5_hwdev *hwdev = dev;
	struct card_node *chip_info = hwdev->chip_node;
	u8 fault_src = HINIC5_FAULT_SRC_TYPE_MAX;
	u8 fault_level;

	if (in_size != sizeof(*fault_event)) {
		sdk_err(hwdev->dev_hdl, "Invalid fault event report, length: %u, should be %lu\n",
			in_size, sizeof(*fault_event));
		return;
	}

	fault_event = buf_in;
	fault_report_show(hwdev, &fault_event->event);

	if (fault_event->event.type == FAULT_TYPE_CHIP)
		fault_level = fault_event->event.event.chip.err_level;
	else
		fault_level = FAULT_LEVEL_FATAL;

	if (fault_event->event.type == FAULT_TYPE_CHIP &&
	    fault_level <= (u8)FAULT_LEVEL_SERIOUS_RESET) {
		chip_info->exception_flag = true;
		sdk_err(hwdev->dev_hdl, "Set card error due to chip fault, lvl %u\n",
			fault_level);
	}

	if (hwdev->event_callback) {
		event_info.service = EVENT_SRV_COMM;
		event_info.type = EVENT_COMM_FAULT;
		fault = (void *)event_info.event_data;
		memcpy(fault, &fault_event->event,
		       sizeof(struct hinic5_fault_event));
		fault->fault_level = fault_level;
		hwdev->event_callback(hwdev->event_pri_handle, &event_info);
	}

	if (fault_event->event.type <= FAULT_TYPE_REG_WR_TIMEOUT)
		fault_src = fault_event->event.type;
	else if (fault_event->event.type == FAULT_TYPE_PHY_FAULT)
		fault_src = HINIC5_FAULT_SRC_HW_PHY_FAULT;

	hisdk5_fault_post_process(hwdev, fault_src, fault_level);
}

static void ffm_event_record(struct hinic5_hwdev *dev, struct dbgtool_k_glb_info *dbgtool_info,
			     struct ffm_intr_info *intr)
{
	struct rtc_time rctm;
	struct timeval txc;
	u32 ffm_idx;
	u32 last_err_csr_addr;
	u32 last_err_csr_value;

	ffm_idx = dbgtool_info->ffm->ffm_num;
	last_err_csr_addr = dbgtool_info->ffm->last_err_csr_addr;
	last_err_csr_value = dbgtool_info->ffm->last_err_csr_value;
	if (ffm_idx < FFM_RECORD_NUM_MAX) {
		if (intr->err_csr_addr == last_err_csr_addr &&
		    intr->err_csr_value == last_err_csr_value) {
			dbgtool_info->ffm->ffm[ffm_idx - 1].times++;
			sdk_err(dev->dev_hdl, "Receive intr same, ffm_idx: %u\n", ffm_idx - 1);
			return;
		}
		sdk_err(dev->dev_hdl, "Receive intr, ffm_idx: %u\n", ffm_idx);

		dbgtool_info->ffm->ffm[ffm_idx].intr_info.node_id = intr->node_id;
		dbgtool_info->ffm->ffm[ffm_idx].intr_info.err_level = intr->err_level;
		dbgtool_info->ffm->ffm[ffm_idx].intr_info.err_type = intr->err_type;
		dbgtool_info->ffm->ffm[ffm_idx].intr_info.err_csr_addr = intr->err_csr_addr;
		dbgtool_info->ffm->ffm[ffm_idx].intr_info.err_csr_value = intr->err_csr_value;
		dbgtool_info->ffm->last_err_csr_addr = intr->err_csr_addr;
		dbgtool_info->ffm->last_err_csr_value = intr->err_csr_value;
		dbgtool_info->ffm->ffm[ffm_idx].times = 1;

		/* Obtain the current UTC time */
		 do_gettimeofday(&txc);

		/* Calculate the time in date value to tm, i.e. GMT + 8, mutiplied by 60 * 60 */
		 rtc_time_to_tm(txc.tv_sec + 60 * 60 * 8, &rctm);

		/* tm_year starts from 1900; 0->1900, 1->1901, and so on */
		dbgtool_info->ffm->ffm[ffm_idx].year = (u16)(rctm.tm_year + 1900);
		/* tm_mon starts from 0, 0 indicates January, and so on */
		dbgtool_info->ffm->ffm[ffm_idx].mon = (u8)rctm.tm_mon + 1;
		dbgtool_info->ffm->ffm[ffm_idx].mday = (u8)rctm.tm_mday;
		dbgtool_info->ffm->ffm[ffm_idx].hour = (u8)rctm.tm_hour;
		dbgtool_info->ffm->ffm[ffm_idx].min = (u8)rctm.tm_min;
		dbgtool_info->ffm->ffm[ffm_idx].sec = (u8)rctm.tm_sec;

		dbgtool_info->ffm->ffm_num++;
	}
}

static void ffm_event_msg_handler(void *hwdev, void *buf_in, u16 in_size,
				  void *buf_out, u16 *out_size)
{
#if !defined(__VMWARE__) && !defined(__WIN__)
	struct dbgtool_k_glb_info *dbgtool_info = NULL;
	struct hinic5_hwdev *dev = hwdev;
	struct card_node *card_info = NULL;
	struct ffm_intr_info *intr = NULL;
	spinlock_t *lock = NULL;

	if (in_size != sizeof(*intr)) {
		sdk_err(dev->dev_hdl, "Invalid fault event report, length: %u, should be %ld.\n",
			in_size, sizeof(*intr));
		return;
	}

	intr = buf_in;

	sdk_err(dev->dev_hdl, "node_id: 0x%x, err_type: 0x%x, err_level: %u, err_csr_addr: 0x%08x, err_csr_value: 0x%08x\n",
		intr->node_id, intr->err_type, intr->err_level,
		intr->err_csr_addr, intr->err_csr_value);

	hinic5_show_chip_err_info(hwdev);

	card_info = dev->chip_node;
	dbgtool_info = card_info->dbgtool_info;

	*out_size = sizeof(*intr);

	if (!dbgtool_info)
		return;

	if (!dbgtool_info->ffm)
		return;

	lock = &card_info->dbgtool_info_lock;
	spin_lock(lock);
	ffm_event_record(dev, dbgtool_info, intr);
	spin_unlock(lock);
#endif
}

#define X_CSR_INDEX 30

static void sw_watchdog_timeout_info_show(struct hinic5_hwdev *hwdev,
					  void *buf_in, u16 in_size,
					  void *buf_out, u16 *out_size)
{
	struct comm_info_sw_watchdog *watchdog_info = buf_in;
	u32 stack_len, i, j, tmp;
	u32 *dump_addr = NULL;
	u64 *reg = NULL;

	if (in_size != sizeof(*watchdog_info)) {
		sdk_err(hwdev->dev_hdl, "Invalid mgmt watchdog report, length: %u, should be %ld\n",
			in_size, sizeof(*watchdog_info));
		return;
	}

	sdk_err(hwdev->dev_hdl, "Mgmt deadloop time: 0x%x 0x%x, task id: 0x%x, sp: 0x%llx\n",
		watchdog_info->curr_time_h, watchdog_info->curr_time_l,
		watchdog_info->task_id, watchdog_info->sp);
	sdk_err(hwdev->dev_hdl,
		"Stack current used: 0x%x, peak used: 0x%x, overflow flag: 0x%x, top: 0x%llx, bottom: 0x%llx\n",
		watchdog_info->curr_used, watchdog_info->peak_used,
		watchdog_info->is_overflow, watchdog_info->stack_top, watchdog_info->stack_bottom);

	sdk_err(hwdev->dev_hdl,
		"Mgmt pc: 0x%llx, elr: 0x%llx, spsr: 0x%llx, far: 0x%llx, esr: 0x%llx, xzr: 0x%llx\n",
		watchdog_info->pc, watchdog_info->reg_info.arm_reg.elr,
		watchdog_info->reg_info.arm_reg.spsr, watchdog_info->reg_info.arm_reg.far,
		watchdog_info->reg_info.arm_reg.esr, watchdog_info->reg_info.arm_reg.xzr);

	sdk_err(hwdev->dev_hdl, "Mgmt register info\n");
	reg = &watchdog_info->reg_info.arm_reg.x30;
	for (i = 0; i <= X_CSR_INDEX; i++)
		sdk_err(hwdev->dev_hdl, "x%02u:0x%llx\n",
			X_CSR_INDEX - i, reg[i]);

	if (watchdog_info->stack_actlen <= DATA_LEN_1K) {
		stack_len = watchdog_info->stack_actlen;
	} else {
		sdk_err(hwdev->dev_hdl, "Oops stack length: 0x%x is wrong\n",
			watchdog_info->stack_actlen);
		stack_len = DATA_LEN_1K;
	}

	sdk_err(hwdev->dev_hdl, "Mgmt dump stack, 16 bytes per line(start from sp)\n");
	for (i = 0; i < (stack_len / DUMP_16B_PER_LINE); i++) {
		dump_addr = (u32 *)(watchdog_info->stack_data + (u32)(i * DUMP_16B_PER_LINE));
		sdk_err(hwdev->dev_hdl, "0x%08x 0x%08x 0x%08x 0x%08x\n",
			*dump_addr, *(dump_addr + 0x1), *(dump_addr + 0x2), *(dump_addr + 0x3));
	}

	tmp = (stack_len % DUMP_16B_PER_LINE) / DUMP_4_VAR_PER_LINE;
	for (j = 0; j < tmp; j++) {
		dump_addr = (u32 *)(watchdog_info->stack_data +
				    (u32)(i * DUMP_16B_PER_LINE + j * DUMP_4_VAR_PER_LINE));
		sdk_err(hwdev->dev_hdl, "0x%08x ", *dump_addr);
	}

	*out_size = sizeof(*watchdog_info);
	watchdog_info = buf_out;
	watchdog_info->head.status = 0;
}

static void mgmt_watchdog_timeout_event_handler(void *hwdev, void *buf_in, u16 in_size,
						void *buf_out, u16 *out_size)
{
	struct hinic5_event_info event_info = { 0 };
	struct hinic5_hwdev *dev = hwdev;

	sw_watchdog_timeout_info_show(dev, buf_in, in_size, buf_out, out_size);

	if (dev->event_callback) {
		event_info.type = EVENT_COMM_MGMT_WATCHDOG;
		dev->event_callback(dev->event_pri_handle, &event_info);
	}
}

static void show_exc_info(struct hinic5_hwdev *hwdev, const EXC_INFO_S *exc_info)
{
	u32 i;

	/* key information */
	sdk_err(hwdev->dev_hdl, "==================== Exception Info Begin ====================\n");
	sdk_err(hwdev->dev_hdl, "Exception CpuTick       : 0x%08x 0x%08x\n",
		exc_info->cpu_tick.cnt_hi, exc_info->cpu_tick.cnt_lo);
	sdk_err(hwdev->dev_hdl, "Exception Cause         : %u\n", exc_info->exc_cause);
	sdk_err(hwdev->dev_hdl, "Os Version              : %s\n", exc_info->os_ver);
	sdk_err(hwdev->dev_hdl, "App Version             : %s\n", exc_info->app_ver);
	sdk_err(hwdev->dev_hdl, "CPU Type                : 0x%08x\n", exc_info->cpu_type);
	sdk_err(hwdev->dev_hdl, "CPU ID                  : 0x%08x\n", exc_info->cpu_id);
	sdk_err(hwdev->dev_hdl, "Thread Type             : 0x%08x\n", exc_info->thread_type);
	sdk_err(hwdev->dev_hdl, "Thread ID               : 0x%08x\n", exc_info->thread_id);
	sdk_err(hwdev->dev_hdl, "Byte Order              : 0x%08x\n", exc_info->byte_order);
	sdk_err(hwdev->dev_hdl, "Nest Count              : 0x%08x\n", exc_info->nest_cnt);
	sdk_err(hwdev->dev_hdl, "Fatal Error Num         : 0x%08x\n", exc_info->fatal_errno);
	sdk_err(hwdev->dev_hdl, "Current SP              : 0x%016llx\n", exc_info->uw_sp);
	sdk_err(hwdev->dev_hdl, "Stack Bottom            : 0x%016llx\n", exc_info->stack_bottom);

	/* register field */
	sdk_err(hwdev->dev_hdl, "Register contents when exception occur.\n");
	sdk_err(hwdev->dev_hdl, "%-14s: 0x%016llx \t %-14s: 0x%016llx\n", "TTBR0",
		exc_info->reg_info.ttbr0, "TTBR1", exc_info->reg_info.ttbr1);
	sdk_err(hwdev->dev_hdl, "%-14s: 0x%016llx \t %-14s: 0x%016llx\n", "TCR",
		exc_info->reg_info.tcr, "MAIR", exc_info->reg_info.mair);
	sdk_err(hwdev->dev_hdl, "%-14s: 0x%016llx \t %-14s: 0x%016llx\n", "SCTLR",
		exc_info->reg_info.sctlr, "VBAR", exc_info->reg_info.vbar);
	sdk_err(hwdev->dev_hdl, "%-14s: 0x%016llx \t %-14s: 0x%016llx\n", "CURRENTE1",
		exc_info->reg_info.current_el, "SP", exc_info->reg_info.sp);
	sdk_err(hwdev->dev_hdl, "%-14s: 0x%016llx \t %-14s: 0x%016llx\n", "ELR",
		exc_info->reg_info.elr, "SPSR", exc_info->reg_info.spsr);
	sdk_err(hwdev->dev_hdl, "%-14s: 0x%016llx \t %-14s: 0x%016llx\n", "FAR",
		exc_info->reg_info.far_r, "ESR", exc_info->reg_info.esr);
	sdk_err(hwdev->dev_hdl, "%-14s: 0x%016llx\n", "XZR", exc_info->reg_info.xzr);

	for (i = 0; i < XREGS_NUM - 1; i += 0x2)
		sdk_err(hwdev->dev_hdl, "XREGS[%02u]%-5s: 0x%016llx \t XREGS[%02u]%-5s: 0x%016llx",
			i, " ", exc_info->reg_info.xregs[i],
			(u32)(i + 0x1U), " ", exc_info->reg_info.xregs[(u32)(i + 0x1U)]);

	sdk_err(hwdev->dev_hdl, "XREGS[%02u]%-5s: 0x%016llx \t ", XREGS_NUM - 1, " ",
		exc_info->reg_info.xregs[XREGS_NUM - 1]);
}

#define FOUR_REG_LEN 16

static void mgmt_lastword_report_event_handler(void *hwdev, void *buf_in, u16 in_size,
					       void *buf_out, u16 *out_size)
{
	comm_info_up_lastword_s *lastword_info = buf_in;
	EXC_INFO_S *exc_info = NULL;
	struct hinic5_hwdev *dev = hwdev;
	u32 *curr_reg = NULL;
	u32 reg_i, cnt, stack_len;

	if (in_size != sizeof(*lastword_info)) {
		sdk_err(dev->dev_hdl, "Invalid mgmt lastword, length: %u, should be %lu\n",
			in_size, sizeof(*lastword_info));
		return;
	}
	exc_info = &lastword_info->stack_info;
	stack_len = lastword_info->stack_actlen;

	if (stack_len > MPU_LASTWORD_SIZE) {
		sdk_err(dev->dev_hdl, "Invalid mgmt lastword, length: stack_len: %u, should less than %u\n",
			stack_len, MPU_LASTWORD_SIZE);
		return;
	}

	show_exc_info(dev, exc_info);

	/* call stack dump */
	sdk_err(dev->dev_hdl, "Dump stack when exceptioin occurs, 16Bytes per line.\n");

	cnt = stack_len / FOUR_REG_LEN;
	for (reg_i = 0; reg_i < cnt; reg_i++) {
		curr_reg = (u32 *)(lastword_info->stack_data + ((u64)(u32)(reg_i * FOUR_REG_LEN)));
		sdk_err(dev->dev_hdl, "0x%08x 0x%08x 0x%08x 0x%08x\n",
			*curr_reg, *(curr_reg + 0x1), *(curr_reg + 0x2), *(curr_reg + 0x3));
	}

	sdk_err(dev->dev_hdl, "==================== Exception Info End ====================\n");
}

#if !defined(__UEFI__) && !defined(__WIN__) && !defined(__VMWARE__)
static int hisdk5_attach_vf_vroce(struct hinic5_lld_dev *lld_dev, u16 func_id)
{
	int err = 0;
	struct hinic5_adev *src_adev = NULL;
	struct hinic5_adev *dst_adev = NULL;

	if (!lld_dev)
		return -EINVAL;

	src_adev = to_hinic5_adev(lld_dev);
	dst_adev = hinic5_get_vf_adev_by_pf((void *)src_adev, func_id);
	if (!dst_adev)
		return -EINVAL;

	err = hinic5_attach_service(&dst_adev->lld_dev, SERVICE_T_ROCE);
	return err;
}

static void hisdk5_detach_vf_vroce(struct hinic5_lld_dev *lld_dev, u16 func_id)
{
	struct hinic5_adev *src_adev = NULL;
	struct hinic5_adev *dst_adev = NULL;

	if (!lld_dev)
		return;

	src_adev = to_hinic5_adev(lld_dev);
	dst_adev = hinic5_get_vf_adev_by_pf((void *)src_adev, func_id);
	if (!dst_adev)
		return;

	hinic5_detach_service(&dst_adev->lld_dev, SERVICE_T_VROCE);
}

static int hisdk5_attach_vf_ub(struct hinic5_lld_dev *lld_dev, u16 func_id)
{
	int err = 0;
	struct hinic5_adev *src_adev = NULL;
	struct hinic5_adev *dst_adev = NULL;

	if (!lld_dev)
		return -EINVAL;

	src_adev = to_hinic5_adev(lld_dev);
	dst_adev = hinic5_get_vf_adev_by_pf((void *)src_adev, func_id);
	if (!dst_adev)
		return -EINVAL;

	err = hinic5_attach_service(&dst_adev->lld_dev, SERVICE_T_UB);
	return err;
}

static void hisdk5_detach_vf_ub(struct hinic5_lld_dev *lld_dev, u16 func_id)
{
	struct hinic5_adev *src_adev = NULL;
	struct hinic5_adev *dst_adev = NULL;

	if (!lld_dev)
		return;

	src_adev = to_hinic5_adev(lld_dev);
	dst_adev = hinic5_get_vf_adev_by_pf((void *)src_adev, func_id);
	if (!dst_adev)
		return;

	hinic5_detach_service(&dst_adev->lld_dev, SERVICE_T_UB);
}

static int hisdk5_attach_vf_nic(struct hinic5_lld_dev *lld_dev, u16 func_id)
{
	int err = 0;
	struct hinic5_adev *src_adev = NULL;
	struct hinic5_adev *dst_adev = NULL;

	if (!lld_dev)
		return -EINVAL;

	src_adev = to_hinic5_adev(lld_dev);

	dst_adev = hinic5_get_vf_adev_by_pf((void *)src_adev, func_id);
	if (!dst_adev)
		return -EINVAL;

	err = hinic5_set_func_en(dst_adev, true, func_id);
	return err;
}

static void hisdk5_detach_vf_nic(struct hinic5_lld_dev *lld_dev, u16 func_id)
{
	struct hinic5_adev *src_adev = NULL;
	struct hinic5_adev *dst_adev = NULL;

	if (!lld_dev)
		return;

	src_adev = to_hinic5_adev(lld_dev);
	dst_adev = hinic5_get_vf_adev_by_pf((void *)src_adev, func_id);
	if (!dst_adev)
		return;

	(void)hinic5_set_func_en(dst_adev, false, func_id);
}

static void hisdk5_attach_plug_service(struct hinic5_lld_dev *lld_dev, u8 srv_type,
				       struct hinic5_hwdev *dev, u16 func_id)
{
	int err = 0;

	if (func_id < CMD_MAX_MAX_PF_NUM) {
		switch (srv_type) {
		case COMM_PLUG_SRV_NIC:
			err = hinic5_attach_service(lld_dev, SERVICE_T_NIC);
			break;
		case COMM_PLUG_SRV_VROCE:
			err = hinic5_attach_service(lld_dev, SERVICE_T_ROCE);
			break;
		case COMM_PLUG_SRV_UB:
			err = hinic5_attach_service(lld_dev, SERVICE_T_UB);
			break;
		default:
			sdk_err(dev->dev_hdl, "plug attach pf service type error.\n");
		}
	} else {
		switch (srv_type) {
		case COMM_PLUG_SRV_NIC:
			err = hisdk5_attach_vf_nic(lld_dev, func_id);
			break;
		case COMM_PLUG_SRV_VROCE:
			err = hisdk5_attach_vf_vroce(lld_dev, func_id);
			break;
		case COMM_PLUG_SRV_UB:
			err = hisdk5_attach_vf_ub(lld_dev, func_id);
			break;
		default:
			sdk_err(dev->dev_hdl, "plug attach vf service type error.\n");
		}
	}

	if (err != 0)
		sdk_err(dev->dev_hdl, "plug attach service failed.\n");
}

static void hisdk5_detach_plug_service(struct hinic5_lld_dev *lld_dev, u8 srv_type,
									   struct hinic5_hwdev *dev, u16 func_id)
{
	if (func_id < CMD_MAX_MAX_PF_NUM) {
		switch (srv_type) {
		case COMM_PLUG_SRV_NIC:
			hinic5_detach_service(lld_dev, SERVICE_T_NIC);
			break;
		case COMM_PLUG_SRV_VROCE:
			hinic5_detach_service(lld_dev, SERVICE_T_VROCE);
			break;
		case COMM_PLUG_SRV_UB:
			hinic5_detach_service(lld_dev, SERVICE_T_UB);
			break;
		default:
			sdk_err(dev->dev_hdl, "plug attach pf service type error.\n");
		}
	} else {
		switch (srv_type) {
		case COMM_PLUG_SRV_NIC:
			hisdk5_detach_vf_nic(lld_dev, func_id);
			break;
		case COMM_PLUG_SRV_VROCE:
			hisdk5_detach_vf_vroce(lld_dev, func_id);
			break;
		case COMM_PLUG_SRV_UB:
			hisdk5_detach_vf_ub(lld_dev, func_id);
			break;
		default:
			sdk_err(dev->dev_hdl, "plug detach vf service type error.\n");
		}
	}
}

static void hisdk5_plug_service_pre_handler(u8 srv_type, struct comm_cmd_plug_srv *plug_srv,
					    struct hinic5_hwdev *dev)
{
	if (srv_type == COMM_PLUG_SRV_NIC) {
		dev->cfg_mgmt->svc_cap.nic_cap.max_sqs = plug_srv->nic_cap.max_sqs;
		dev->cfg_mgmt->svc_cap.nic_cap.max_rqs = plug_srv->nic_cap.max_rqs;
	}
}

static void mgmt_plug_report_event_handler(void *hwdev, void *buf_in, u16 in_size,
					   void *buf_out, u16 *out_size)
{
	struct comm_cmd_plug_srv *plug_srv = buf_in;
	struct hinic5_hwdev *dev = hwdev;
	struct hinic5_adev *adev = dev->adapter_hdl;
	struct hinic5_lld_dev *lld_dev = &adev->lld_dev;
	u16 func_id;
	u8 srv_type;
	u8 attach_en;

	if (in_size != sizeof(*plug_srv)) {
		sdk_err(dev->dev_hdl, "Invalid plug event report, length: %u, should be %ld.\n",
			in_size, sizeof(*plug_srv));
		return;
	}

	if (!IS_BMGW_SLAVE_HOST(dev)) {
		sdk_warn(dev->dev_hdl, "Discard plug event from unexpected function (mode %u).\n",
			 dev->func_mode);
		return;
	}

	srv_type = plug_srv->srv_type;
	attach_en = plug_srv->attach_en;
	func_id = plug_srv->func_id;
	hisdk5_plug_service_pre_handler(srv_type, plug_srv, dev);

	if (attach_en != 0)
		hisdk5_attach_plug_service(lld_dev, srv_type, dev, func_id);
	else
		hisdk5_detach_plug_service(lld_dev, srv_type, dev, func_id);
}
#endif

static void mgmt_reset_event_handler(void *dev, void *buf_in, u16 in_size,
				     void *buf_out, u16 *out_size)
{
	struct hinic5_hwdev *hwdev = dev;

	sdk_err(hwdev->dev_hdl, "Event COMM_MGMT_CMD_MGMT_RESET from MPU\n");
}

const struct mgmt_event_handle hinic5_mgmt_event_proc[] = {
	{
		.cmd	= COMM_MGMT_CMD_FAULT_REPORT,
		.proc	= fault_event_handler,
	},

	{
		.cmd	= COMM_MGMT_CMD_FFM_SET,
		.proc	= ffm_event_msg_handler,
	},

	{
		.cmd	= COMM_MGMT_CMD_WATCHDOG_INFO,
		.proc	= mgmt_watchdog_timeout_event_handler,
	},

	{
		.cmd	= COMM_MGMT_CMD_LASTWORD_GET,
		.proc	= mgmt_lastword_report_event_handler,
	},

	{
		.cmd    = COMM_MGMT_CMD_MGMT_RESET,
		.proc   = mgmt_reset_event_handler,
	},

#if !defined(__UEFI__) && !defined(__WIN__) && !defined(__VMWARE__)
	{
		.cmd	= COMM_MGMT_CMD_SET_FUNC_PLUG_SRV,
		.proc	= mgmt_plug_report_event_handler,
	},
#endif
};

static void pf_handle_mgmt_comm_event(void *handle, u16 cmd,
				      void *buf_in, u16 in_size, void *buf_out,
				      u16 *out_size)
{
	struct hinic5_hwdev *hwdev = handle;
	u32 i, event_num = (u32)ARRAY_LEN(hinic5_mgmt_event_proc);

	if (!hwdev)
		return;

	for (i = 0; i < event_num; i++) {
		if (cmd == hinic5_mgmt_event_proc[i].cmd) {
			if (hinic5_mgmt_event_proc[i].proc)
				hinic5_mgmt_event_proc[i].proc(handle, buf_in, in_size,
							buf_out, out_size);
			else
				sdk_warn(hwdev->dev_hdl,
					 "Mgmt event proc is not registered, cmd %u\n", cmd);
			return;
		}
	}

	sdk_warn(hwdev->dev_hdl, "Unsupported mgmt cpu event %u to process\n",
		 cmd);
	*out_size = sizeof(struct mgmt_msg_head);
	((struct mgmt_msg_head *)buf_out)->status = HINIC5_MGMT_CMD_UNSUPPORTED;
}

static inline void hinic5_set_chip_present(struct hinic5_hwdev *hwdev)
{
	hwdev->chip_present_flag = HINIC5_CHIP_PRESENT;
}

static inline void hinic5_set_chip_absent(struct hinic5_hwdev *hwdev)
{
	hwdev->chip_present_flag = HINIC5_CHIP_ABSENT;
}

bool hinic5_check_htn_device_id(void *hwdev)
{
#if !defined(__UEFI__) && !defined(__WIN__) && !defined(__VMWARE__)
	struct hinic5_hwdev *dev = hwdev;
	struct hinic5_adev *adev = dev->adapter_hdl;

	if ((hinic5_adev_get_device_id(adev) != HINIC5_UDEV_DEVICE_ID_1872_PF &&
	     hinic5_adev_get_device_id(adev) != HINIC5_UDEV_DEVICE_ID_1872_VF) ||
	    adev->lld_dev.dev_type != HINIC5_DEVICE_T_UB) {
		return false;
	}
#endif

	return true;
}

int hinic5_get_chip_present_flag(const void *hwdev)
{
	struct hinic5_hwdev *dev = (struct hinic5_hwdev *)hwdev;

	if (unlikely(!hwdev))
		return HINIC5_CHIP_ABSENT;

	if (unlikely(!get_handshake_state(dev)))
		return HINIC5_CHIP_ABSENT;

	if (likely(hinic5_is_chip_present(dev)))
		return HINIC5_CHIP_PRESENT;
	return HINIC5_CHIP_ABSENT;
}
EXPORT_SYMBOL(hinic5_get_chip_present_flag);

void hinic5_force_complete_all(void *dev)
{
	struct hinic5_recv_msg *recv_resp_msg = NULL;
	struct hinic5_hwdev *hwdev = dev;
	struct hinic5_mbox *func_to_func = NULL;

	if (!dev || !hwdev->pf_to_mgmt)
		return;

	spin_lock_bh(&hwdev->channel_lock);
	if (test_bit(HINIC5_HWDEV_MGMT_INITED, &hwdev->func_state)) {
		recv_resp_msg = &hwdev->pf_to_mgmt->recv_resp_msg_from_mgmt;
		spin_lock_bh(&hwdev->pf_to_mgmt->sync_event_lock);
		if (hwdev->pf_to_mgmt->event_flag == SEND_EVENT_START) {
			complete(&recv_resp_msg->recv_done);
			hwdev->pf_to_mgmt->event_flag = SEND_EVENT_TIMEOUT;
		}
		spin_unlock_bh(&hwdev->pf_to_mgmt->sync_event_lock);
	}

	if (test_bit(HINIC5_HWDEV_MBOX_INITED, &hwdev->func_state)) {
		func_to_func = hwdev->func_to_func;
		spin_lock(&func_to_func->mbox_lock);
		if (func_to_func->event_flag == EVENT_START)
			func_to_func->event_flag = EVENT_TIMEOUT;
		spin_unlock(&func_to_func->mbox_lock);
	}

	if (test_bit(HINIC5_HWDEV_CMDQ_INITED, &hwdev->func_state))
		hinic5_cmdq_flush_sync_cmd(hwdev);

	spin_unlock_bh(&hwdev->channel_lock);
}
EXPORT_SYMBOL(hinic5_force_complete_all);

void hinic5_detect_hw_present(void *hwdev)
{
	struct hinic5_hwdev *dev = (struct hinic5_hwdev *)hwdev;

	if (!hinic5_get_card_present_state(dev)) {
		sdk_err(dev->dev_hdl, "Detect card absent.\n");
		hinic5_set_chip_absent(hwdev);
		hinic5_force_complete_all(hwdev);
	}
}

/**
 * dma_attr_table_init - initialize the default dma attributes
 * @hwdev: the pointer to hw device
 **/
static int dma_attr_table_init(struct hinic5_hwdev *hwdev)
{
	u32 addr, val, dst_attr;

	/* Use indirect access should set entry_idx first */
	addr = HINIC5_CSR_DMA_ATTR_INDIR_IDX_ADDR;
	val = hinic5_hwif_read_reg(hwdev->hwif, addr);
	val = HINIC5_DMA_ATTR_INDIR_IDX_CLEAR(val, IDX);

	val |= HINIC5_DMA_ATTR_INDIR_IDX_SET(PCIE_MSIX_ATTR_ENTRY, IDX);

	hinic5_hwif_write_reg(hwdev->hwif, addr, val);

	wmb(); /* write index before config */

	addr = HINIC5_CSR_DMA_ATTR_TBL_ADDR;
	val = hinic5_hwif_read_reg(hwdev->hwif, addr);

	dst_attr = HINIC5_DMA_ATTR_ENTRY_SET(HINIC5_PCIE_ST_DISABLE, ST)	|
		HINIC5_DMA_ATTR_ENTRY_SET(HINIC5_PCIE_AT_DISABLE, AT)		|
		HINIC5_DMA_ATTR_ENTRY_SET(HINIC5_PCIE_PH_DISABLE, PH)		|
		HINIC5_DMA_ATTR_ENTRY_SET(HINIC5_PCIE_SNOOP, NO_SNOOPING)	|
		HINIC5_DMA_ATTR_ENTRY_SET(HINIC5_PCIE_TPH_DISABLE, TPH_EN);

	if (val == dst_attr)
		return 0;

	return hinic5_set_dma_attr_tbl(hwdev, PCIE_MSIX_ATTR_ENTRY, HINIC5_PCIE_ST_DISABLE,
				       HINIC5_PCIE_AT_DISABLE, HINIC5_PCIE_PH_DISABLE,
				       HINIC5_PCIE_SNOOP, HINIC5_PCIE_TPH_DISABLE);
}

static int init_aeqs_msix_attr(struct hinic5_hwdev *hwdev)
{
	struct hinic5_aeqs *aeqs = hwdev->aeqs;
	struct interrupt_info info = {0};
	struct hinic5_eq *eq = NULL;
	int q_id;
	int err;

	info.lli_set = 0;
	info.interrupt_coalesc_set = 1;
	info.pending_limt = HINIC5_DEAULT_EQ_MSIX_PENDING_LIMIT;
	info.coalesc_timer_cfg = HINIC5_DEAULT_EQ_MSIX_COALESC_TIMER_CFG;
	info.resend_timer_cfg = HINIC5_DEAULT_EQ_MSIX_RESEND_TIMER_CFG;

	for (q_id = aeqs->num_aeqs - 1; q_id >= 0; q_id--) {
		eq = &aeqs->aeq[q_id];
		info.msix_index = eq->eq_irq.msix_entry_idx;
		err = hinic5_set_interrupt_cfg_direct(hwdev, &info,
						      HINIC5_CHANNEL_COMM);
		if (err != 0) {
			sdk_err(hwdev->dev_hdl, "Set msix attr for aeq %d failed\n",
				q_id);
			return -EFAULT;
		}
	}

	return 0;
}

static int init_ceqs_msix_attr(struct hinic5_hwdev *hwdev)
{
#ifdef __UEFI__
	return 0;
#endif
	struct hinic5_ceqs *ceqs = hwdev->ceqs;
	struct interrupt_info info = {0};
	struct hinic5_eq *eq = NULL;
	u16 q_id;
	int err;

	if (!ceqs)
		return 0;

	info.lli_set = 0;
	info.interrupt_coalesc_set = 1;
	info.pending_limt = HINIC5_DEAULT_EQ_MSIX_PENDING_LIMIT;
	info.coalesc_timer_cfg = HINIC5_DEAULT_EQ_MSIX_COALESC_TIMER_CFG;
	info.resend_timer_cfg = HINIC5_DEAULT_EQ_MSIX_RESEND_TIMER_CFG;

	for (q_id = 0; q_id < ceqs->num_ceqs; q_id++) {
		eq = &ceqs->ceq[q_id];
		info.msix_index = eq->eq_irq.msix_entry_idx;
		err = hinic5_set_interrupt_cfg(hwdev, info,
					       HINIC5_CHANNEL_COMM);
		if (err != 0) {
			sdk_err(hwdev->dev_hdl, "Set msix attr for ceq %u failed\n",
				q_id);
			return -EFAULT;
		}
	}

	return 0;
}

static int hinic5_comm_clp_to_mgmt_init(struct hinic5_hwdev *hwdev)
{
	int err;

	if (hinic5_func_type(hwdev) == TYPE_VF || !COMM_SUPPORT_CLP(hwdev))
		return 0;

	err = hinic5_clp_pf_to_mgmt_init(hwdev);
	if (err != 0)
		return err;

	return 0;
}

static void hinic5_comm_clp_to_mgmt_free(struct hinic5_hwdev *hwdev)
{
	if (hinic5_func_type(hwdev) == TYPE_VF || !COMM_SUPPORT_CLP(hwdev))
		return;

	hinic5_clp_pf_to_mgmt_free(hwdev);
}

static int hinic5_comm_aeqs_init(struct hinic5_hwdev *hwdev)
{
	struct irq_info aeq_irqs[HINIC5_MAX_AEQS] = { { 0 } };
	u16 num_aeqs, resp_num_irq = 0, i;
	int err;

	num_aeqs = HINIC5_HWIF_NUM_AEQS(hwdev->hwif);
	if (num_aeqs > HINIC5_MAX_AEQS) {
		sdk_warn(hwdev->dev_hdl, "Adjust aeq num to %d\n",
			 HINIC5_MAX_AEQS);
		num_aeqs = HINIC5_MAX_AEQS;
	}
	err = hinic5_alloc_irqs(hwdev, SERVICE_T_INTF, num_aeqs, aeq_irqs,
				&resp_num_irq);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc aeq irqs, num_aeqs: %u\n",
			num_aeqs);
		return err;
	}

	if (resp_num_irq < num_aeqs) {
		sdk_warn(hwdev->dev_hdl, "Adjust aeq num to %u\n",
			 resp_num_irq);
		num_aeqs = resp_num_irq;
	}

	err = hinic5_aeqs_init(hwdev, num_aeqs, aeq_irqs);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init aeqs\n");
		goto aeqs_init_err;
	}

	return 0;

aeqs_init_err:
	for (i = 0; i < num_aeqs; i++)
		hinic5_free_irq(hwdev, SERVICE_T_INTF, aeq_irqs[i].irq_id);

	return err;
}

static void hinic5_comm_aeqs_free(struct hinic5_hwdev *hwdev)
{
	struct irq_info aeq_irqs[HINIC5_MAX_AEQS] = {{0} };
	struct irq_info *aeq_irq = &aeq_irqs[0];
	u16 num_irqs, i;

	hinic5_get_aeq_irqs(hwdev, aeq_irq, &num_irqs);

	hinic5_aeqs_free(hwdev);

	for (i = 0; i < num_irqs; i++)
		hinic5_free_irq(hwdev, SERVICE_T_INTF, aeq_irqs[i].irq_id);
}

static int hinic5_comm_ceqs_init(struct hinic5_hwdev *hwdev)
{
#ifdef __UEFI__
	return 0;
#endif
	struct irq_info ceq_irqs[HINIC5_MAX_CEQS] = { { 0 } };
	u16 num_ceqs, resp_num_irq = 0, i;
	int err;

	num_ceqs = HINIC5_HWIF_NUM_CEQS(hwdev->hwif);
	if (num_ceqs == 0)
		return 0;

	if (num_ceqs > HINIC5_MAX_CEQS) {
		sdk_warn(hwdev->dev_hdl, "Adjust ceq num to %d\n",
			 HINIC5_MAX_CEQS);
		num_ceqs = HINIC5_MAX_CEQS;
	}

	err = hinic5_alloc_irqs(hwdev, SERVICE_T_INTF, num_ceqs, ceq_irqs,
				&resp_num_irq);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc ceq irqs, num_ceqs: %u\n",
			num_ceqs);
		return err;
	}

	if (resp_num_irq < num_ceqs) {
		sdk_warn(hwdev->dev_hdl, "Adjust ceq num to %u\n",
			 resp_num_irq);
		num_ceqs = resp_num_irq;
	}

	err = hinic5_ceqs_init(hwdev, num_ceqs, ceq_irqs);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl,
			"Failed to init ceqs, err:%d\n", err);
		goto ceqs_init_err;
	}

	return 0;

ceqs_init_err:
	for (i = 0; i < num_ceqs; i++)
		hinic5_free_irq(hwdev, SERVICE_T_INTF, ceq_irqs[i].irq_id);

	return err;
}

static void hinic5_comm_ceqs_free(struct hinic5_hwdev *hwdev)
{
#ifdef __UEFI__
	return;
#endif
	struct irq_info ceq_irqs[HINIC5_MAX_CEQS] = { { 0 } };
	struct irq_info *ceq_irq = &ceq_irqs[0];
	u16 num_irqs;
	int i;

	if (!hwdev->ceqs)
		return;

	hinic5_get_ceq_irqs(hwdev, ceq_irq, &num_irqs);

	hinic5_ceqs_free(hwdev);

	for (i = 0; i < num_irqs; i++)
		hinic5_free_irq(hwdev, SERVICE_T_INTF, ceq_irqs[i].irq_id);
}

/**
 * @brief Initialize communication between functions
 *
 * @param[in] hwdev device pointer
 *
 * @details
 *     Note that mpu is a special function
 *     Communication is implemented through mailbox
 *     1) Initialize mailbox related registers and resources
 *     2) Register callback for receiving mailbox data
 *
 * @return:
 *     @retval 0 success
 *     @retval non-zero failure
 */
static int hinic5_comm_func_to_func_init(struct hinic5_hwdev *hwdev)
{
	int err;

	err = hinic5_func_to_func_init(hwdev);
	if (err != 0)
		return err;

	hinic5_aeq_register_hw_cb(hwdev, hwdev, HINIC5_MBX_FROM_FUNC,
				  hinic5_mbox_func_aeqe_handler);
	hinic5_aeq_register_hw_cb(hwdev, hwdev, HINIC5_MSG_FROM_MGMT_CPU,
				  hinic5_mgmt_msg_aeqe_handler);

	if (!HINIC5_IS_VF(hwdev))
		hinic5_register_pf_mbox_cb(hwdev, HINIC5_MOD_COMM,
					   hwdev,
					   pf_handle_vf_comm_mbox);
	else
		hinic5_register_vf_mbox_cb(hwdev, HINIC5_MOD_COMM,
					   hwdev,
					   vf_handle_pf_comm_mbox);

	set_bit(HINIC5_HWDEV_MBOX_INITED, &hwdev->func_state);

	return 0;
}

static void hinic5_comm_func_to_func_free(struct hinic5_hwdev *hwdev)
{
	spin_lock_bh(&hwdev->channel_lock);
	clear_bit(HINIC5_HWDEV_MBOX_INITED, &hwdev->func_state);
	spin_unlock_bh(&hwdev->channel_lock);

	hinic5_aeq_unregister_hw_cb(hwdev, HINIC5_MBX_FROM_FUNC);
	hinic5_aeq_unregister_hw_cb(hwdev, HINIC5_MSG_FROM_MGMT_CPU);

	if (!HINIC5_IS_VF(hwdev))
		hinic5_unregister_pf_mbox_cb(hwdev, HINIC5_MOD_COMM);
	else
		hinic5_unregister_vf_mbox_cb(hwdev, HINIC5_MOD_COMM);

	hinic5_func_to_func_free(hwdev);
}

static int hinic5_comm_pf_to_mgmt_init(struct hinic5_hwdev *hwdev)
{
	int err;

	err = hinic5_pf_to_mgmt_init(hwdev);
	if (err != 0)
		return err;

	hinic5_register_mgmt_msg_cb(hwdev, HINIC5_MOD_COMM, hwdev,
				    pf_handle_mgmt_comm_event);

	set_bit(HINIC5_HWDEV_MGMT_INITED, &hwdev->func_state);

	return 0;
}

static void hinic5_comm_pf_to_mgmt_free(struct hinic5_hwdev *hwdev)
{
	spin_lock_bh(&hwdev->channel_lock);
	clear_bit(HINIC5_HWDEV_MGMT_INITED, &hwdev->func_state);
	spin_unlock_bh(&hwdev->channel_lock);

	hinic5_unregister_mgmt_msg_cb(hwdev, HINIC5_MOD_COMM);

	hinic5_pf_to_mgmt_free(hwdev);
}

static int hinic5_comm_cmdqs_init(struct hinic5_hwdev *hwdev)
{
	int err;

	err = hinic5_cmdqs_init(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init cmd queues\n");
		return err;
	}

	hinic5_ceq_register_cb(hwdev, hwdev, HINIC5_CMDQ, hinic5_cmdq_ceq_handler);

	err = hinic5_set_cmdq_depth(hwdev, HINIC5_CMDQ_DEPTH);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to set cmdq depth\n");
		goto set_cmdq_depth_err;
	}

	set_bit(HINIC5_HWDEV_CMDQ_INITED, &hwdev->func_state);

	return 0;

set_cmdq_depth_err:
	hinic5_cmdqs_free(hwdev);

	return err;
}

static void hinic5_comm_cmdqs_free(struct hinic5_hwdev *hwdev)
{
	spin_lock_bh(&hwdev->channel_lock);
	clear_bit(HINIC5_HWDEV_CMDQ_INITED, &hwdev->func_state);
	spin_unlock_bh(&hwdev->channel_lock);

	hinic5_ceq_unregister_cb(hwdev, HINIC5_CMDQ);
	hinic5_cmdqs_free(hwdev);
}

static void hinic5_sync_mgmt_func_state(struct hinic5_hwdev *hwdev)
{
#if defined(__UEFI__) && !defined(__HIFC__)
		hinic5_set_pf_status(hwdev->hwif, HINIC5_PF_STATUS_INIT);
#else
		hinic5_set_pf_status(hwdev->hwif, HINIC5_PF_STATUS_ACTIVE_FLAG);
#endif
}

static void hinic5_unsync_mgmt_func_state(struct hinic5_hwdev *hwdev)
{
	hinic5_set_pf_status(hwdev->hwif, HINIC5_PF_STATUS_INIT);
}

static int init_basic_attributes(struct hinic5_hwdev *hwdev)
{
	u64 drv_features[COMM_MAX_FEATURE_QWORD] = {HINIC5_DRV_FEATURE_QW0, 0, 0, 0};
	int err, i;

#if !defined(__UEFI__)
	if (hinic5_func_type(hwdev) == TYPE_PPF)
		drv_features[0] |= COMM_F_CHANNEL_DETECT;
#endif

	err = hinic5_get_board_info(hwdev, &hwdev->board_info,
				    HINIC5_CHANNEL_COMM);
	if (err != 0)
		return err;

	err = hinic5_get_comm_features(hwdev, hwdev->features,
				       COMM_MAX_FEATURE_QWORD);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Get comm features failed\n");
		return err;
	}

	sdk_info(hwdev->dev_hdl, "Comm hw features: 0x%llx, drv features: 0x%llx\n",
		 hwdev->features[0], drv_features[0]);

	for (i = 0; i < COMM_MAX_FEATURE_QWORD; i++)
		hwdev->features[i] &= drv_features[i];

	err = hinic5_get_global_attr(hwdev, &hwdev->glb_attr);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to get global attribute\n");
		return err;
	}

	sdk_info(hwdev->dev_hdl,
		 "global attribute: max_host: 0x%x, max_pf: 0x%x, vf_id_start: 0x%x, mgmt node id: 0x%x, cmdq_num: 0x%x\n",
		 hwdev->glb_attr.max_host_num, hwdev->glb_attr.max_pf_num,
		 hwdev->glb_attr.vf_id_start,
		 hwdev->glb_attr.mgmt_host_node_id,
		 hwdev->glb_attr.cmdq_num);

	return 0;
}

static int init_basic_mgmt_channel(struct hinic5_hwdev *hwdev)
{
	int err;

	err = hinic5_comm_aeqs_init(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init async event queues\n");
		return err;
	}

	err = hinic5_comm_func_to_func_init(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init mailbox\n");
		goto func_to_func_init_err;
	}

	err = init_aeqs_msix_attr(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init aeqs msix attr\n");
		goto aeqs_msix_attr_init_err;
	}
#if !defined(__UEFI__) && !defined(__WIN__) && !defined(__VMWARE__)
	err = hinic5_cqm_init_fast_msg(hwdev);
	if (err != 0)
		sdk_err(hwdev->dev_hdl, "Failed to init fast msg\n");
#endif
	return 0;

aeqs_msix_attr_init_err:
	hinic5_comm_func_to_func_free(hwdev);

func_to_func_init_err:
	hinic5_comm_aeqs_free(hwdev);

	return err;
}

static void free_base_mgmt_channel(struct hinic5_hwdev *hwdev)
{
	hinic5_comm_func_to_func_free(hwdev);
	hinic5_comm_aeqs_free(hwdev);
}

static int init_pf_mgmt_channel(struct hinic5_hwdev *hwdev)
{
	int err;

	err = hinic5_comm_clp_to_mgmt_init(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init clp\n");
		return err;
	}

	err = hinic5_comm_pf_to_mgmt_init(hwdev);
	if (err != 0) {
		hinic5_comm_clp_to_mgmt_free(hwdev);
		sdk_err(hwdev->dev_hdl, "Failed to init pf to mgmt\n");
		return err;
	}

	return 0;
}

static void free_pf_mgmt_channel(struct hinic5_hwdev *hwdev)
{
	hinic5_comm_clp_to_mgmt_free(hwdev);
	hinic5_comm_pf_to_mgmt_free(hwdev);
}

static int init_mgmt_channel_post(struct hinic5_hwdev *hwdev)
{
	int err;

	/* mbox host channel resources will be freed in
	 * hinic5_func_to_func_free
	 */
	if (HINIC5_IS_PPF(hwdev)) {
		err = hinic5_mbox_init_host_msg_channel(hwdev);
		if (err != 0) {
			sdk_err(hwdev->dev_hdl, "Failed to init mbox host channel\n");
			return err;
		}
	}

	err = init_pf_mgmt_channel(hwdev);
	if (err != 0)
		return err;

	return 0;
}

static void free_mgmt_msg_channel_post(struct hinic5_hwdev *hwdev)
{
	free_pf_mgmt_channel(hwdev);
}

static int init_cmdqs_channel(struct hinic5_hwdev *hwdev)
{
	int err;

	err = dma_attr_table_init(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init dma attr table\n");
		goto dma_attr_init_err;
	}

	err = hinic5_comm_ceqs_init(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init completion event queues\n");
		goto ceqs_init_err;
	}

	err = init_ceqs_msix_attr(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init ceqs msix attr\n");
		goto init_ceq_msix_err;
	}

	/* set default wq page_size */
	if (wq_page_order > HINIC5_MAX_WQ_PAGE_SIZE_ORDER) {
		sdk_info(hwdev->dev_hdl, "wq_page_order exceed limit[0, %d], reset to %d\n",
			 HINIC5_MAX_WQ_PAGE_SIZE_ORDER,
			 HINIC5_MAX_WQ_PAGE_SIZE_ORDER);
		wq_page_order = HINIC5_MAX_WQ_PAGE_SIZE_ORDER;
	}
	hwdev->wq_page_size = HINIC5_HW_WQ_PAGE_SIZE * (1U << wq_page_order);
	sdk_info(hwdev->dev_hdl, "WQ page size: 0x%x\n", hwdev->wq_page_size);
	err = hinic5_set_wq_page_size(hwdev, hinic5_global_func_id(hwdev),
				      hwdev->wq_page_size, HINIC5_CHANNEL_COMM);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to set wq page size\n");
		goto init_wq_pg_size_err;
	}

	err = hinic5_comm_cmdqs_init(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init cmd queues\n");
		goto cmdq_init_err;
	}

	return 0;

cmdq_init_err:
	hinic5_set_wq_page_size(hwdev, hinic5_global_func_id(hwdev),
				HINIC5_HW_WQ_PAGE_SIZE,
				HINIC5_CHANNEL_COMM);
init_wq_pg_size_err:
init_ceq_msix_err:
	hinic5_comm_ceqs_free(hwdev);

ceqs_init_err:
dma_attr_init_err:

	return err;
}

static void hinic5_free_cmdqs_channel(struct hinic5_hwdev *hwdev)
{
	hinic5_comm_cmdqs_free(hwdev);

	hinic5_set_wq_page_size(hwdev, hinic5_global_func_id(hwdev),
				HINIC5_HW_WQ_PAGE_SIZE, HINIC5_CHANNEL_COMM);

	hinic5_comm_ceqs_free(hwdev);
}

static int hinic5_init_comm_ch(struct hinic5_hwdev *hwdev)
{
	int err;

	err = init_basic_mgmt_channel(hwdev);
	if (err != 0)
		return err;

	err = hinic5_func_reset(hwdev, hinic5_global_func_id(hwdev),
				HINIC5_COMM_RES, HINIC5_CHANNEL_COMM);
	if (err != 0)
		goto func_reset_err;

	err = init_basic_attributes(hwdev);
	if (err != 0)
		goto init_basic_attr_err;

	err = init_mgmt_channel_post(hwdev);
	if (err != 0)
		goto init_mgmt_channel_post_err;

	err = init_cmdqs_channel(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init cmdq channel\n");
		goto init_cmdqs_channel_err;
	}

	err = hinic5_set_func_svc_used_state(hwdev, SVC_T_COMM, 1, HINIC5_CHANNEL_COMM);
	if (err != 0)
		goto set_used_state_err;

	hinic5_sync_mgmt_func_state(hwdev);

	if (HISDK5_F_CHANNEL_LOCK_EN(hwdev)) {
		hinic5_mbox_enable_channel_lock(hwdev, true);
		hinic5_cmdq_enable_channel_lock(hwdev, true);
	}
	err = hinic5_init_stateless_aeqs(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl,
			"Failed to init stateless aeqs\n");
		goto init_stateless_aeqs_err;
	}

	err = hinic5_aeq_register_swe_cb(hwdev, hwdev, HINIC5_STATELESS_EVENT,
					 (hinic5_aeq_swe_cb)hinic5_nic_sw_aeqe_handler);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl,
			"Failed to register sw aeqe handler\n");
		goto register_ucode_aeqe_err;
	}

	return 0;

register_ucode_aeqe_err:
	hinic5_stateless_aeqs_free(hwdev);
init_stateless_aeqs_err:
	hinic5_unsync_mgmt_func_state(hwdev);
	hinic5_set_func_svc_used_state(hwdev, SVC_T_COMM, 0, HINIC5_CHANNEL_COMM);
set_used_state_err:
	hinic5_free_cmdqs_channel(hwdev);
init_cmdqs_channel_err:
	free_mgmt_msg_channel_post(hwdev);
init_mgmt_channel_post_err:
init_basic_attr_err:
func_reset_err:
	free_base_mgmt_channel(hwdev);

	return err;
}

static void hinic5_uninit_comm_ch(struct hinic5_hwdev *hwdev)
{
	hinic5_aeq_unregister_swe_cb(hwdev, HINIC5_STATELESS_EVENT);

	hinic5_stateless_aeqs_free(hwdev);

	hinic5_unsync_mgmt_func_state(hwdev);

	hinic5_set_func_svc_used_state(hwdev, SVC_T_COMM, 0, HINIC5_CHANNEL_COMM);

	hinic5_free_cmdqs_channel(hwdev);

	free_mgmt_msg_channel_post(hwdev);
#if !defined(__UEFI__) && !defined(__WIN__) && !defined(__VMWARE__)
	hinic5_cqm_deinit_fast_msg(hwdev);
#endif
	free_base_mgmt_channel(hwdev);
}

#if !defined(__UEFI__) && !defined(__VMWARE__) && !defined(__WIN__)
static void hinic5_auto_sync_time_work(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct hinic5_hwdev *hwdev = container_of(delay, struct hinic5_hwdev, sync_time_task);
	int err;

	err = hinic5_sync_time(hwdev, hinic5_ossl_get_real_time());
	if (err != 0)
		sdk_err(hwdev->dev_hdl, "Synchronize UTC time to firmware failed, errno:%d.\n",
			err);

	queue_delayed_work(hwdev->workq, &hwdev->sync_time_task,
			   msecs_to_jiffies(HINIC5_SYNFW_TIME_PERIOD));
}

static void hinic5_auto_channel_detect_work(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct hinic5_hwdev *hwdev = container_of(delay, struct hinic5_hwdev, channel_detect_task);

	if (!hinic5_is_chip_present(hwdev)) {
		sdk_warn(hwdev->dev_hdl, "Detect card absent, stop channel detect.\n");
		return;
	}

	(void)hinic5_comm_channel_detect(hwdev);

	/* reschedule self */
	if (!hinic5_channel_detect_should_stop(hwdev))
		queue_delayed_work(hwdev->workq, &hwdev->channel_detect_task,
				   msecs_to_jiffies(HINIC5_CHANNEL_DETECT_PERIOD));
}

void hinic5_kernel_sync_time_work(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct hinic5_hwdev *hwdev = container_of(delay, struct hinic5_hwdev,
						  sync_kernel_time_task);
	int err;

	struct card_node *chip_node = (struct card_node *)(hwdev->chip_node);

	if (!chip_node || !chip_node->non_ptp_info ||
	    (chip_node->non_ptp_info->non_ptp_time_diff_enable == 0)) {
		return;
	}

	err = hinic5_sync_kernel_time(hwdev);
	if (err != 0)
		sdk_err(hwdev->dev_hdl, "Synchronize kernel time failed, errno:%d.\n", err);

	queue_delayed_work(hwdev->workq, &hwdev->sync_kernel_time_task,
			   msecs_to_jiffies(HINIC5_NON_PTP_SYNC_FW_TIME_PERIOD));
}

static int hinic5_init_ppf_work(struct hinic5_hwdev *hwdev)
{
	int err;

	if (hinic5_func_type(hwdev) != TYPE_PPF)
		return 0;

	INIT_DELAYED_WORK(&hwdev->sync_time_task, hinic5_auto_sync_time_work);
	queue_delayed_work(hwdev->workq, &hwdev->sync_time_task,
			   msecs_to_jiffies(HINIC5_SYNFW_TIME_PERIOD));

	if (COMM_SUPPORT_CHANNEL_DETECT(hwdev) != 0) {
		INIT_DELAYED_WORK(&hwdev->channel_detect_task,
				  hinic5_auto_channel_detect_work);
		queue_delayed_work(hwdev->workq, &hwdev->channel_detect_task,
				   msecs_to_jiffies(HINIC5_CHANNEL_DETECT_PERIOD));
	}

	if (COMM_SUPPORT_NON_PTP_SYNC(hwdev) != 0) {
		err = hinic5_non_ptp_cdev_init(hwdev);
		if (err != 0) {
			sdk_err(hwdev->dev_hdl, "Failed to init non_ptp char dev\n");
			goto init_non_ptp_err;
		}
		/* Register delayed task, initialized as disable */
		INIT_DELAYED_WORK(&hwdev->sync_kernel_time_task, hinic5_kernel_sync_time_work);
		hinic5_set_non_ptp_time_diff_en(hwdev, false);
	}

	if (!COMM_SUPPORT_HTN_CMD(hwdev)) {
		err = hinic5_comm_micro_log_init(hwdev);
		if (err != 0)
			sdk_warn(hwdev->dev_hdl, "Failed to init micro log\n");
	}

	return 0;

init_non_ptp_err:
	if (COMM_SUPPORT_CHANNEL_DETECT(hwdev) != 0) {
		hwdev->features[0] &= ~(COMM_F_CHANNEL_DETECT);
		cancel_delayed_work_sync(&hwdev->channel_detect_task);
	}

	cancel_delayed_work_sync(&hwdev->sync_time_task);

	return err;
}

static void hinic5_free_ppf_work(struct hinic5_hwdev *hwdev)
{
	if (hinic5_func_type(hwdev) != TYPE_PPF)
		return;

	if (!COMM_SUPPORT_HTN_CMD(hwdev))
		hinic5_micro_log_uninit(hwdev);

	if (COMM_SUPPORT_NON_PTP_SYNC(hwdev) != 0) {
		hwdev->features[0] &= ~(COMM_F_NON_PTP_SYNC);
		cancel_delayed_work_sync(&hwdev->sync_kernel_time_task);
		hinic5_non_ptp_cdev_deinit(hwdev);
	}

	if (COMM_SUPPORT_CHANNEL_DETECT(hwdev)) {
		hwdev->features[0] &= ~(COMM_F_CHANNEL_DETECT);
		cancel_delayed_work_sync(&hwdev->channel_detect_task);
	}

	cancel_delayed_work_sync(&hwdev->sync_time_task);
}

#else
static int hinic5_init_ppf_work(struct hinic5_hwdev *hwdev)
{
	return 0;
}

static void hinic5_free_ppf_work(struct hinic5_hwdev *hwdev)
{
}
#endif

/*
 * CMDQ timeout should be greater than SMEG1 runaway timeout(SMEG1_RUNAWAY_CFG)
 */
#define HINIC5_ASIC_CMDQ_TIMEOUT 10000
#define HINIC5_FPGA_CMDQ_TIMEOUT 50000
#define HINIC5_EMU_CMDQ_TIMEOUT 500000
#define HINIC5_EDA_CMDQ_TIMEOUT 10000

#define HINIC5_ASIC_MBOX_TIMEOUT 40000
#define HINIC5_FPGA_MBOX_TIMEOUT 40000
#define HINIC5_EMU_MBOX_TIMEOUT 400000
#define HINIC5_EDA_MBOX_TIMEOUT 40000

#define HINIC5_ASIC_MBOX_POLL_TIMEOUT 8000
#define HINIC5_FPGA_MBOX_POLL_TIMEOUT 8000
#define HINIC5_EMU_MBOX_POLL_TIMEOUT 80000
#define HINIC5_EDA_MBOX_POLL_TIMEOUT 8000

static const struct hinic5_sdk_timeout_info g_sdk_timeout_info[] = {
	{
		.hw_type = HINIC5_HW_TYPE_FPGA,
		.hw_type_desc = "FPGA",
		.mbox_poll_timeout = HINIC5_FPGA_MBOX_POLL_TIMEOUT,
		.mbox_timeout = HINIC5_FPGA_MBOX_TIMEOUT,
		.cmdq_timeout = HINIC5_FPGA_CMDQ_TIMEOUT,
	},
	{
		.hw_type = HINIC5_HW_TYPE_ASIC,
		.hw_type_desc = "ASIC",
		.mbox_poll_timeout = HINIC5_ASIC_MBOX_POLL_TIMEOUT,
		.mbox_timeout = HINIC5_ASIC_MBOX_TIMEOUT,
		.cmdq_timeout = HINIC5_ASIC_CMDQ_TIMEOUT,
	},
	{
		.hw_type = HINIC5_HW_TYPE_EMU,
		.hw_type_desc = "EMU",
		.mbox_poll_timeout = HINIC5_EMU_MBOX_POLL_TIMEOUT,
		.mbox_timeout = HINIC5_EMU_MBOX_TIMEOUT,
		.cmdq_timeout = HINIC5_EMU_CMDQ_TIMEOUT,
	},
	{
		.hw_type = HINIC5_HW_TYPE_EDA,
		.hw_type_desc = "EDA",
		.mbox_poll_timeout = HINIC5_EDA_MBOX_POLL_TIMEOUT,
		.mbox_timeout = HINIC5_EDA_MBOX_TIMEOUT,
		.cmdq_timeout = HINIC5_EDA_CMDQ_TIMEOUT,
	},
};

STATIC void hinic5_hwdev_init_timeout(struct hinic5_hwdev *hwdev, u8 hw_type)
{
	u8 temp_hw_type = hw_type;

	if (temp_hw_type > HINIC5_HW_TYPE_EDA) {
		sdk_warn(hwdev->dev_hdl, "No available timeout info for type(%d), use default type(%d)\n",
			 temp_hw_type, HINIC5_HW_TYPE_FPGA);
		temp_hw_type = HINIC5_HW_TYPE_FPGA;
	}

	hwdev->timeout_info = &g_sdk_timeout_info[temp_hw_type];
}

static int init_hwdev(struct hinic5_init_para *para)
{
	struct hinic5_hwdev *hwdev = NULL;

	hwdev = kzalloc(sizeof(*hwdev), GFP_KERNEL);
	if (!hwdev)
		return -ENOMEM;

	*para->hwdev = hwdev;
	hwdev->adapter_hdl = para->adapter_hdl;
#ifdef __UEFI__
	hwdev->busdev_hdl = para->busdev_hdl;
#endif
	hwdev->dev_hdl = para->dev_hdl;
	hwdev->chip_node = para->chip_node;
	hwdev->poll = para->poll;
	atomic_set(&hwdev->check_ob_flush_bypass_ref_cnt, 0);
	hwdev->probe_fault_level = para->probe_fault_level;
	hwdev->func_state = 0;

	hwdev->chip_fault_stats = vzalloc(HINIC5_CHIP_FAULT_SIZE);
	if (!hwdev->chip_fault_stats)
		goto alloc_chip_fault_stats_err;

	hwdev->stateful_ref_cnt = 0;
	memset(hwdev->features, 0, sizeof(hwdev->features));

	hinic5_hwdev_init_timeout(hwdev, HINIC5_HW_TYPE_ASIC);

	spin_lock_init(&hwdev->channel_lock);
	mutex_init(&hwdev->stateful_mutex);

	return 0;

alloc_chip_fault_stats_err:
	kfree(hwdev);
	*para->hwdev = NULL;
	return  -EFAULT;
}

static void deinit_hwdev(struct hinic5_hwdev *hwdev)
{
	mutex_deinit(&hwdev->stateful_mutex);
	spin_lock_deinit(&hwdev->channel_lock);
	vfree(hwdev->chip_fault_stats);
	hwdev->chip_fault_stats = NULL;
	kfree(hwdev);
}

static inline void hinic5_init_max_aeq_busy_cnt(struct hinic5_hwdev *hwdev)
{
	hwdev->max_aeq_busy_cnt = hwdev->timeout_info->mbox_timeout / MSEC_PER_SEC;
}

#define HINIC5_HEARTBEAT_PERIOD			1000
#define DETECT_PCIE_LINK_DOWN_RETRY		2

int hinic5_init_hwdev(struct hinic5_init_para *para)
{
	struct hinic5_hwdev *hwdev = NULL;
	u8 hw_type;
	int err;

	err = init_hwdev(para);
	if (err != 0)
		return err;

	hwdev = *para->hwdev;

	err = hinic5_init_hwif(hwdev, para->fers2_reg_base, para->cfg_reg_base, para->intr_reg_base,
			       para->mgmt_reg_base, para->db_base_phy, para->db_base,
			       para->db_dwqe_len);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init hwif\n");
		goto init_hwif_err;
	}

	hw_type = hinic5_get_hw_type(hwdev);
	hinic5_hwdev_init_timeout(hwdev, hw_type);
	hinic5_init_max_aeq_busy_cnt(hwdev);

	hinic5_set_chip_present(hwdev);

	err = hisdk5_init_profile_adapter(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init profile adapter\n");
		goto init_prof_adapter_err;
	}

	hwdev->workq = alloc_workqueue(HINIC5_HWDEV_WQ_NAME, WQ_MEM_RECLAIM, HINIC5_WQ_MAX_REQ);
	if (!hwdev->workq) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc hardware workq\n");
		goto alloc_workq_err;
	}

	(void)hinic5_set_heartbeat_period_and_linkdown_cnt((void *)hwdev, HINIC5_HEARTBEAT_PERIOD,
							   DETECT_PCIE_LINK_DOWN_RETRY);
	hinic5_init_heartbeat_detect(hwdev);

	err = hinic5_init_cfg_mgmt(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init config mgmt\n");
		goto hinic5_init_cfg_mgmt_err;
	}

	err = hinic5_init_comm_ch(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init communication channel\n");
		goto init_comm_ch_err;
	}

#ifdef HAVE_DEVLINK_FLASH_UPDATE_PARAMS
	err = hinic5_init_devlink(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init devlink\n");
		goto init_devlink_err;
	}
#endif

	err = hinic5_init_capability(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init capability\n");
		goto init_cap_err;
	}

	hinic5_init_host_mode_pre(hwdev);

	err = hinic5_multi_host_enable(hwdev, true);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init function mode\n");
		goto init_multi_host_fail;
	}

	err = hinic5_init_ppf_work(hwdev);
	if (err != 0)
		goto init_ppf_work_fail;

	err = hinic5_set_comm_features(hwdev, hwdev->features, COMM_MAX_FEATURE_QWORD);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to set comm features\n");
		goto set_feature_err;
	}

	return 0;

set_feature_err:
	hinic5_free_ppf_work(hwdev);

init_ppf_work_fail:
	hinic5_multi_host_enable(hwdev, false);

init_multi_host_fail:
	hinic5_free_capability(hwdev);

init_cap_err:
#ifdef HAVE_DEVLINK_FLASH_UPDATE_PARAMS
	hinic5_uninit_devlink(hwdev);

init_devlink_err:
#endif
	hinic5_uninit_comm_ch(hwdev);

init_comm_ch_err:
	hinic5_free_cfg_mgmt(hwdev);

hinic5_init_cfg_mgmt_err:
	hinic5_destroy_heartbeat_detect(hwdev);
	destroy_workqueue(hwdev->workq);

alloc_workq_err:
	hisdk5_deinit_profile_adapter(hwdev);

init_prof_adapter_err:
	hinic5_free_hwif(hwdev);

init_hwif_err:
	deinit_hwdev(hwdev);
	*para->hwdev = NULL;

	return -EFAULT;
}

void hinic5_free_hwdev(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;
	u64 drv_features[COMM_MAX_FEATURE_QWORD];

	memset(drv_features, 0, sizeof(drv_features));
	hinic5_set_comm_features(hwdev, drv_features, COMM_MAX_FEATURE_QWORD);

	hinic5_free_ppf_work(dev);

	hinic5_multi_host_enable(dev, false);

	hinic5_func_rx_tx_flush(hwdev, HINIC5_CHANNEL_COMM, true, 0);

	hinic5_free_capability(dev);

#ifdef HAVE_DEVLINK_FLASH_UPDATE_PARAMS
	hinic5_uninit_devlink(dev);
#endif

	hinic5_uninit_comm_ch(dev);

	hinic5_free_cfg_mgmt(dev);
	hinic5_destroy_heartbeat_detect(hwdev);
	destroy_workqueue(dev->workq);

	hisdk5_deinit_profile_adapter(hwdev);
	hinic5_free_hwif(dev);

	deinit_hwdev(dev);
}

int hinic5_register_service_adapter(void *hwdev, void *service_adapter,
				    enum hinic5_service_type type)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev || !service_adapter || type >= SERVICE_T_MAX)
		return -EINVAL;

	if (dev->service_adapter[type])
		return -EINVAL;

	dev->service_adapter[type] = service_adapter;

	return 0;
}
EXPORT_SYMBOL(hinic5_register_service_adapter);

void hinic5_unregister_service_adapter(void *hwdev,
				       enum hinic5_service_type type)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev || type >= SERVICE_T_MAX)
		return;

	dev->service_adapter[type] = NULL;
}
EXPORT_SYMBOL(hinic5_unregister_service_adapter);

void *hinic5_get_service_adapter(void *hwdev, enum hinic5_service_type type)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev || type < SERVICE_T_NIC || type >= SERVICE_T_MAX)
		return NULL;

	return dev->service_adapter[type];
}
EXPORT_SYMBOL(hinic5_get_service_adapter);

int hinic5_dbg_get_hw_stats(const void *hwdev, u8 *hw_stats, const u32 *out_size)
{
	struct hinic5_hw_stats *tmp_hw_stats = (struct hinic5_hw_stats *)hw_stats;
	struct card_node *chip_node = NULL;

	if (!hwdev)
		return -EINVAL;

	if (*out_size != sizeof(struct hinic5_hw_stats) || !hw_stats) {
		pr_err("Unexpect out buf size from user :%u, expect: %lu\n",
		       *out_size, sizeof(struct hinic5_hw_stats));
		return -EFAULT;
	}

	memcpy(hw_stats, &((struct hinic5_hwdev *)hwdev)->hw_stats,
	       sizeof(struct hinic5_hw_stats));

	chip_node = ((struct hinic5_hwdev *)hwdev)->chip_node;

	atomic_set(&tmp_hw_stats->nic_ucode_event_stats[HINIC5_CHANNEL_BUSY],
		   atomic_read(&chip_node->channel_busy_cnt));

	return 0;
}

static int check_cmdq_args(struct hinic5_hwdev *hwdev, u16 cmdq_id)
{
	struct hinic5_cmdqs *cmdqs = hwdev->cmdqs;

	if (unlikely(!cmdqs))
		return -EAGAIN; /* cmdqs not ready */

	if (unlikely(cmdq_id >= cmdqs->cmdq_num))
		return -E2BIG;

	return 0;
}

int hinic5_dump_cmdq_wq(struct hinic5_hwdev *hwdev, u16 cmdq_id, struct hinic5_wq *wq)
{
	int err;

	if (unlikely(!hwdev || !wq))
		return -EINVAL;

	err = check_cmdq_args(hwdev, cmdq_id);
	if (unlikely(err != 0))
		return err;

	memcpy(wq, &hwdev->cmdqs->cmdq[cmdq_id].wq, sizeof(struct hinic5_wq));

	return 0;
}

int hinic5_dump_cmdq_wqebb(struct hinic5_hwdev *hwdev, u16 cmdq_id, u16 wqe_idx,
			   struct sdk_cmdq_wqe_desc *wqe_desc)
{
	struct hinic5_wq *wq = NULL;
	u16 wqebb_size, wqe_idx_masked;
	void *wqebb = NULL;
	int err;

	if (unlikely(!hwdev || !wqe_desc))
		return -EINVAL;

	err = check_cmdq_args(hwdev, cmdq_id);
	if (unlikely(err != 0))
		return err;

	wq = &hwdev->cmdqs->cmdq[cmdq_id].wq;
	wqebb_size = wq->wqebb_size;
	if (unlikely(wqebb_size > sizeof(wqe_desc->data)))
		dev_warn_once(hwdev->dev_hdl, "WARN: out wqebb size too small\n");

	wqe_idx_masked = WQ_MASK_IDX(wq, wqe_idx);
	wqebb = hinic5_wq_wqebb_addr(wq, wqe_idx_masked);

	memset((void *)wqe_desc->data, 0, sizeof(wqe_desc->data));
	memcpy((void *)wqe_desc->data, wqebb, wqebb_size);

	wqe_desc->wqebb_size = wqebb_size;
	return 0;
}

u16 hinic5_dbg_clear_hw_stats(void *hwdev)
{
	struct card_node *chip_node = NULL;
	struct hinic5_hwdev *dev = hwdev;

	memset((void *)&dev->hw_stats, 0, sizeof(struct hinic5_hw_stats));
	memset((void *)dev->chip_fault_stats, 0, HINIC5_CHIP_FAULT_SIZE);

	chip_node = dev->chip_node;
	if (COMM_SUPPORT_CHANNEL_DETECT(dev) && (atomic_read(&chip_node->channel_busy_cnt) != 0)) {
		atomic_set(&chip_node->channel_busy_cnt, 0);
		dev->aeq_busy_cnt = 0;
#if !defined(__UEFI__) && !defined(__VMWARE__) && !defined(__WIN__)
		queue_delayed_work(dev->workq, &dev->channel_detect_task,
				   msecs_to_jiffies(HINIC5_CHANNEL_DETECT_PERIOD));
#endif
	}

	return sizeof(struct hinic5_hw_stats);
}

void hinic5_get_chip_fault_stats(const void *hwdev, u8 *chip_fault_stats,
				 u32 offset)
{
	u32 chip_fault_len;

	if (offset >= HINIC5_CHIP_FAULT_SIZE) {
		pr_err("Invalid chip offset value: %u\n", offset);
		return;
	}

	if (offset + MAX_DRV_BUF_SIZE <= HINIC5_CHIP_FAULT_SIZE)
		chip_fault_len = MAX_DRV_BUF_SIZE;
	else
		chip_fault_len = HINIC5_CHIP_FAULT_SIZE - offset;
	memcpy(chip_fault_stats,
	       ((struct hinic5_hwdev *)hwdev)->chip_fault_stats + offset, chip_fault_len);
}

int hinic5_event_register(void *dev, void *pri_handle, hinic5_event_handler callback)
{
	struct hinic5_hwdev *hwdev = dev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for register event\n");
		return -EINVAL;
	}

	if (hwdev->event_callback) {
		pr_err("event_callback is already registered\n");
		return -EPERM;
	}

	hwdev->event_callback = callback;
	hwdev->event_pri_handle = pri_handle;
	return 0;
}

void hinic5_event_unregister(void *dev)
{
	struct hinic5_hwdev *hwdev = dev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for register event\n");
		return;
	}

	hwdev->event_callback = NULL;
	hwdev->event_pri_handle = NULL;
}

void hinic5_event_callback(void *hwdev, struct hinic5_event_info *event)
{
	struct hinic5_hwdev *dev = hwdev;

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
EXPORT_SYMBOL(hinic5_event_callback);

void hinic5_set_pcie_order_cfg(void *handle)
{
}

void hinic5_disable_mgmt_msg_report(void *hwdev)
{
	struct hinic5_hwdev *hw_dev = (struct hinic5_hwdev *)hwdev;

	hinic5_set_pf_status(hw_dev->hwif, HINIC5_PF_STATUS_INIT);
}

void hinic5_record_pcie_error(void *hwdev)
{
	struct hinic5_hwdev *dev = (struct hinic5_hwdev *)hwdev;

	if (!hwdev)
		return;

	atomic_inc(&dev->hw_stats.fault_event_stats.pcie_fault_stats);
}

#if !defined(__VMWARE__)
bool hinic5_need_init_stateful_default(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;
	u16 chip_svc_type = (u16)dev->cfg_mgmt->svc_cap.svc_type;

#if defined(__UEFI__) && !defined(__HIFC__) && !defined(VIRTIO_2X100G_NORMAL)
	if (dev->board_info.board_type == BOARD_TYPE_CAL_2X100G_NIC_120MPPS ||
	    dev->board_info.board_type == BOARD_TYPE_CAL_4X25G_NIC_120MPPS)
		return false;
#endif

	if (lowpower_mode != 0)
		return true;

	/* Current virtio net have to init hinic5_cqm in PPF. */
	if ((hinic5_func_type(hwdev) == TYPE_PPF) &&
	    ((chip_svc_type & CFG_SERVICE_MASK_VIRTIO) != 0)) {
		sdk_info(dev->dev_hdl, "sdk init ppf resource, chip_svc_type: 0x%x\n",
			 chip_svc_type);
		return true;
	}

	/* vroce have to init hinic5_cqm */
	if (IS_MASTER_HOST(dev) && (hinic5_func_type(hwdev) != TYPE_PPF) &&
	    (((chip_svc_type & CFG_SERVICE_MASK_VROCE) != 0)))
		return true;

	/* Other service type will init hinic5_cqm when uld call. */
	return false;
}

static bool hinic5_ext_db_en(struct hinic5_hwdev *dev)
{
	u32 stateful_en = IS_FT_TYPE(dev) | IS_RDMA_TYPE(dev);

	return (((stateful_en != 0) || IS_RDMA_ENABLE(dev) ||
		IS_FT_ENABLE(dev)) && HINIC5_IS_PPF(dev));
}

static inline void stateful_uninit(struct hinic5_hwdev *hwdev)
{
	hinic5_cqm_uninit(hwdev);

	if (hinic5_ext_db_en(hwdev))
		hinic5_ppf_ext_db_deinit(hwdev);
}

int hinic5_stateful_init(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;
	int err;
	bool ext_db_en;

	if (!dev)
		return -EINVAL;

	if (!hinic5_get_stateful_enable(dev))
		return 0;

	mutex_lock(&dev->stateful_mutex);
	if (dev->stateful_ref_cnt != 0) {
		dev->stateful_ref_cnt++;
		mutex_unlock(&dev->stateful_mutex);
		return 0;
	}

	dev->stateful_ref_cnt++;
	ext_db_en = hinic5_ext_db_en(dev);
	if (ext_db_en) {
		err = hinic5_ppf_ext_db_init(dev);
		if (err != 0)
			goto out;
	}

	err = hinic5_cqm_init(dev);
	if (err != 0) {
		sdk_err(dev->dev_hdl, "Failed to init hinic5_cqm, err: %d\n", err);
		goto init_hinic5_cqm_err;
	}

	mutex_unlock(&dev->stateful_mutex);
	sdk_info(dev->dev_hdl, "Initialize stateful resource success\n");

	return 0;

init_hinic5_cqm_err:
	if (ext_db_en)
		hinic5_ppf_ext_db_deinit(dev);

out:
	dev->stateful_ref_cnt--;
	mutex_unlock(&dev->stateful_mutex);

	return err;
}
EXPORT_SYMBOL(hinic5_stateful_init);

void hinic5_stateful_deinit(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev || !hinic5_get_stateful_enable(dev))
		return;

	mutex_lock(&dev->stateful_mutex);
	if (dev->stateful_ref_cnt == 0 || ((--dev->stateful_ref_cnt) != 0)) {
		mutex_unlock(&dev->stateful_mutex);
		return;
	}

	stateful_uninit(hwdev);
	mutex_unlock(&dev->stateful_mutex);

	sdk_info(dev->dev_hdl, "Clear stateful resource success\n");
}
EXPORT_SYMBOL(hinic5_stateful_deinit);

void hinic5_free_stateful(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev || !hinic5_get_stateful_enable(dev) || dev->stateful_ref_cnt == 0)
		return;

	if (!hinic5_need_init_stateful_default(hwdev) || dev->stateful_ref_cnt > 1)
		sdk_info(dev->dev_hdl, "Current stateful resource ref is incorrect, ref_cnt:%u\n",
			 dev->stateful_ref_cnt);

	stateful_uninit(hwdev);

	sdk_info(dev->dev_hdl, "Clear stateful resource success\n");
}
#endif /* __VMWARE__ */

int hinic5_hinic5_get_card_present_state(void *hwdev, bool *card_present_state)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev || !card_present_state)
		return -EINVAL;

	*card_present_state = hinic5_get_card_present_state(dev);

	return 0;
}
EXPORT_SYMBOL(hinic5_hinic5_get_card_present_state);

void hinic5_link_event_stats(void *dev, u8 link)
{
	struct hinic5_hwdev *hwdev = dev;

	if (!hwdev) {
		pr_err("hwdev is null\n");
		return;
	}

	if (link != 0)
		atomic_inc(&hwdev->hw_stats.link_event_stats.link_up_stats);
	else
		atomic_inc(&hwdev->hw_stats.link_event_stats.link_down_stats);
}
EXPORT_SYMBOL(hinic5_link_event_stats);

int hinic5_get_link_down_cnt(void *dev, int *link_down_cnt)
{
	struct hinic5_hwdev *hwdev = dev;

	if (!hwdev || !link_down_cnt)
		return -EINVAL;

	*link_down_cnt = hwdev->hw_stats.link_event_stats.link_down_stats.counter;

	return 0;
}
EXPORT_SYMBOL(hinic5_get_link_down_cnt);

u8 hinic5_max_pf_num(void *hwdev)
{
	if (!hwdev)
		return 0;

	return HINIC5_MAX_PF_NUM((struct hinic5_hwdev *)hwdev);
}
EXPORT_SYMBOL(hinic5_max_pf_num);

void hinic5_fault_event_report(void *hwdev, u16 src, u16 level)
{
	if (!hwdev)
		return;

	sdk_info(((struct hinic5_hwdev *)hwdev)->dev_hdl, "Fault event report, src: %u, level: %u\n",
		 src, level);

	hisdk5_fault_post_process(hwdev, src, level);
}
EXPORT_SYMBOL(hinic5_fault_event_report);

void hinic5_probe_success(void *hwdev)
{
	if (!hwdev)
		return;

	hisdk5_probe_success(hwdev);
}

static void hinic5_update_channel_status(struct hinic5_hwdev *hwdev)
{
	struct card_node *chip_node = hwdev->chip_node;

	if (!chip_node)
		return;

	if ((hinic5_func_type(hwdev) != TYPE_PPF) || !COMM_SUPPORT_CHANNEL_DETECT(hwdev) ||
	    hinic5_channel_detect_should_stop(hwdev))
		return;

	if (test_bit(HINIC5_HWDEV_MBOX_INITED, &hwdev->func_state) == 0)
		return;

	if (hwdev->last_recv_aeq_cnt != hwdev->cur_recv_aeq_cnt) {
		hwdev->aeq_busy_cnt = 0;
		hwdev->last_recv_aeq_cnt = hwdev->cur_recv_aeq_cnt;
		/* Intentionally keep channel_busy_cnt */
		return;
	}

	hwdev->aeq_busy_cnt++;
	if (hwdev->aeq_busy_cnt > hwdev->max_aeq_busy_cnt) {
		atomic_inc(&chip_node->channel_busy_cnt);
		hwdev->aeq_busy_cnt = 0;
		sdk_err(hwdev->dev_hdl, "Detect channel busy\n");
	}
}

static void hinic5_heartbeat_lost_handler(struct work_struct *work)
{
	struct hinic5_event_info event_info = { 0 };
	struct hinic5_hwdev *hwdev = container_of(work, struct hinic5_hwdev,
						  heartbeat_lost_work);
	u16 src, level;

	atomic_inc(&hwdev->hw_stats.heart_lost_stats);

	if (hwdev->event_callback) {
		event_info.service = EVENT_SRV_COMM;
		event_info.type =
			(atomic_read(&hwdev->bus_link_down) != 0) ? EVENT_COMM_PCIE_LINK_DOWN :
			EVENT_COMM_HEART_LOST;
		hwdev->event_callback(hwdev->event_pri_handle, &event_info);
	}

	if (atomic_read(&hwdev->bus_link_down) != 0) {
		src = HINIC5_FAULT_SRC_PCIE_LINK_DOWN;
		level = FAULT_LEVEL_HOST;
		sdk_err(hwdev->dev_hdl, "Detect bus is link down\n");
	} else {
		src = HINIC5_FAULT_SRC_HOST_HEARTBEAT_LOST;
		level = FAULT_LEVEL_FATAL;
		sdk_err(hwdev->dev_hdl, "Heart lost report received, func_id: %u\n",
			hinic5_global_func_id(hwdev));
	}

	hinic5_show_chip_err_info(hwdev);

	hisdk5_fault_post_process(hwdev, src, level);
}

#define HINIC5_HEARTBEAT_START_EXPIRE		5000

/* Check if the current function is in available state */
bool hinic5_is_function_active(struct hinic5_hwdev *hwdev)
{
	return (atomic_read(&hwdev->bus_link_down) == 0 &&
		atomic_read(&hwdev->heartbeat_lost) == 0);
}

static bool hinic5_is_hw_abnormal(struct hinic5_hwdev *hwdev)
{
	struct card_node *chip_info = hwdev->chip_node;
	u32 status;

	if (hinic5_get_chip_present_flag(hwdev) == 0)
		return false;

	status = hinic5_get_heartbeat_status(hwdev);
	if (status == HINIC5_BUS_LINK_DOWN) {
		sdk_warn(hwdev->dev_hdl, "Detect BAR register read failed\n");
		hwdev->rd_bar_err_cnt++;
		if (hwdev->rd_bar_err_cnt >= hwdev->linkdown_threshold) {
			sdk_err(hwdev->dev_hdl, "Set card absent due to bus link down\n");
			hinic5_set_chip_absent(hwdev);
			hinic5_force_complete_all(hwdev);
			atomic_set(&hwdev->bus_link_down, true);
			return true;
		}

		return false;
	}

	if (status != 0) {
		atomic_set(&hwdev->heartbeat_lost, true);
		chip_info->exception_flag = true;
		sdk_err(hwdev->dev_hdl, "Set card error due to heartbeat lost\n");
		return true;
	}

	hwdev->rd_bar_err_cnt = 0;

	return false;
}

int hinic5_set_heartbeat_period_and_linkdown_cnt(void *hwdev, u32 heartbeat_period,
						 u32 linkdown_threshold)
{
	struct hinic5_hwdev *dev = (struct hinic5_hwdev *)hwdev;

	if (!hwdev) {
		pr_err("Hwdev is NULL\n");
		return -EINVAL;
	}

	if (heartbeat_period == 0 && linkdown_threshold == 0) {
		sdk_err(dev->dev_hdl, "heartbeat_period and linkdown_threshold is 0\n");
		return -EINVAL;
	}

	if (heartbeat_period != 0) {
		dev->heartbeat_period = heartbeat_period;
		sdk_info(dev->dev_hdl, "heartbeat_period modify to %d\n", dev->heartbeat_period);
	}

	if (linkdown_threshold != 0) {
		dev->linkdown_threshold = linkdown_threshold;
		sdk_info(dev->dev_hdl, "linkdown_threshold modify to %d\n",
			 dev->linkdown_threshold);
	}

	return 0;
}
EXPORT_SYMBOL(hinic5_set_heartbeat_period_and_linkdown_cnt);

#ifdef HAVE_TIMER_SETUP
static void hinic5_heartbeat_timer_handler(struct timer_list *t)
#else
static void hinic5_heartbeat_timer_handler(ulong data)
#endif
{
#ifdef HAVE_TIMER_SETUP
	struct hinic5_hwdev *hwdev = from_timer(hwdev, t, heartbeat_timer);
#else
	struct hinic5_hwdev *hwdev = (struct hinic5_hwdev *)data;
#endif

	if (hinic5_is_hw_abnormal(hwdev)) {
		hinic5_stop_timer(&hwdev->heartbeat_timer);
		queue_work(hwdev->workq, &hwdev->heartbeat_lost_work);
	} else {
		mod_timer(&hwdev->heartbeat_timer,
			  jiffies + msecs_to_jiffies(hwdev->heartbeat_period));
	}

	hinic5_update_channel_status(hwdev);
}

static void hinic5_init_heartbeat_detect(struct hinic5_hwdev *hwdev)
{
#ifdef HAVE_TIMER_SETUP
	timer_setup(&hwdev->heartbeat_timer, hinic5_heartbeat_timer_handler, 0);
#else
	initialize_timer(hwdev->adapter_hdl, &hwdev->heartbeat_timer);
	hwdev->heartbeat_timer.data = (u64)hwdev;
	hwdev->heartbeat_timer.function = hinic5_heartbeat_timer_handler;
#endif

	hwdev->heartbeat_timer.expires =
		jiffies + msecs_to_jiffies(HINIC5_HEARTBEAT_START_EXPIRE);

	INIT_WORK(&hwdev->heartbeat_lost_work, hinic5_heartbeat_lost_handler);

	hinic5_add_to_timer(&hwdev->heartbeat_timer, hwdev->heartbeat_period);
}

static void hinic5_destroy_heartbeat_detect(struct hinic5_hwdev *hwdev)
{
	destroy_work(&hwdev->heartbeat_lost_work);
	hinic5_stop_timer(&hwdev->heartbeat_timer);
	hinic5_delete_timer(&hwdev->heartbeat_timer);
}

void hinic5_set_api_stop(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return;

	sdk_info(dev->dev_hdl, "Set card absent\n");
	hinic5_set_chip_absent(dev);
	hinic5_force_complete_all(dev);
	sdk_info(dev->dev_hdl, "All messages interacting with the chip will stop\n");
}

bool hinic5_get_perf_en(enum hinic5_perf_bitmap perf_bit)
{
	return test_bit(perf_bit, (void *)&perf_en_bitmap);
}
