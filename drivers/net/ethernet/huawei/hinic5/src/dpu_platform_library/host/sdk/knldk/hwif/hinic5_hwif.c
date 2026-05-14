/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hwif.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/types.h>
#include <linux/delay.h>
#include <linux/module.h>

#include "ossl_knl.h"
#include "hinic5_csr_inner.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_common.h"
#include "hinic5_hwdev.h"
#include "hinic5_hwif_inner.h"

#define WAIT_HWIF_READY_TIMEOUT				30000
#define MAX_TS_UP_EN_RETRY_CNT				100

#define HINIC5_WAIT_DOORBELL_AND_OUTBOUND_TIMEOUT	180000

#define MAX_MSIX_ENTRY 2048

#define DB_IDX(db, db_base)	\
	((u32)(((ulong)(db) - (ulong)(db_base)) /	\
	       HINIC5_DB_PAGE_SIZE))

#define HINIC5_AF0_FUNC_GLOBAL_IDX_SHIFT	0
#define HINIC5_AF0_P2P_IDX_SHIFT		12
#define HINIC5_AF0_PCI_INTF_IDX_SHIFT		17
#define HINIC5_AF0_VF_IN_PF_SHIFT		20
#define HINIC5_AF0_FUNC_TYPE_SHIFT		28

#define HINIC5_AF0_FUNC_GLOBAL_IDX_MASK		0xFFF
#define HINIC5_AF0_P2P_IDX_MASK			0x1F
#define HINIC5_AF0_PCI_INTF_IDX_MASK		0x7
#define HINIC5_AF0_VF_IN_PF_MASK		0xFF
#define HINIC5_AF0_FUNC_TYPE_MASK		0x1

#define HINIC5_AF0_GET(val, member)				\
	(((val) >> HINIC5_AF0_##member##_SHIFT) & HINIC5_AF0_##member##_MASK)

#define HINIC5_AF1_PPF_IDX_SHIFT		0
#define HINIC5_AF1_AEQS_PER_FUNC_SHIFT		8
#define HINIC5_AF1_MGMT_INIT_STATUS_SHIFT	30
#define HINIC5_AF1_PF_INIT_STATUS_SHIFT		31

#define HINIC5_AF1_PPF_IDX_MASK			0x3F
#define HINIC5_AF1_AEQS_PER_FUNC_MASK		0x3
#define HINIC5_AF1_MGMT_INIT_STATUS_MASK	0x1
#define HINIC5_AF1_PF_INIT_STATUS_MASK		0x1

#define HINIC5_AF1_GET(val, member)				\
	(((val) >> HINIC5_AF1_##member##_SHIFT) & HINIC5_AF1_##member##_MASK)

#define HINIC5_AF2_CEQS_PER_FUNC_SHIFT		0
#define HINIC5_AF2_DMA_ATTR_PER_FUNC_SHIFT	9
#define HINIC5_AF2_IRQS_PER_FUNC_SHIFT		16

#define HINIC5_AF2_CEQS_PER_FUNC_MASK		0x1FF
#define HINIC5_AF2_DMA_ATTR_PER_FUNC_MASK	0x7
#define HINIC5_AF2_IRQS_PER_FUNC_MASK		0x7FF

#define HINIC5_AF2_GET(val, member)				\
	(((val) >> HINIC5_AF2_##member##_SHIFT) & HINIC5_AF2_##member##_MASK)

#define HINIC5_AF3_GLOBAL_VF_ID_OF_NXT_PF_SHIFT	0
#define HINIC5_AF3_GLOBAL_VF_ID_OF_PF_SHIFT	16

#define HINIC5_AF3_GLOBAL_VF_ID_OF_NXT_PF_MASK	0xFFF
#define HINIC5_AF3_GLOBAL_VF_ID_OF_PF_MASK	0xFFF

#define HINIC5_AF3_GET(val, member)				\
	(((val) >> HINIC5_AF3_##member##_SHIFT) & HINIC5_AF3_##member##_MASK)

#define HINIC5_AF4_DOORBELL_CTRL_SHIFT		0
#define HINIC5_AF4_DOORBELL_CTRL_MASK		0x1

#define HINIC5_AF4_GET(val, member)				\
	(((val) >> HINIC5_AF4_##member##_SHIFT) & HINIC5_AF4_##member##_MASK)

#define HINIC5_AF4_SET(val, member)				\
	(((val) & HINIC5_AF4_##member##_MASK) << HINIC5_AF4_##member##_SHIFT)

#define HINIC5_AF4_CLEAR(val, member)				\
	((val) & (~(HINIC5_AF4_##member##_MASK << HINIC5_AF4_##member##_SHIFT)))

#define HINIC5_AF5_OUTBOUND_CTRL_SHIFT		0
#define HINIC5_AF5_OUTBOUND_CTRL_MASK		0x1

#define HINIC5_AF5_GET(val, member)				\
	(((val) >> HINIC5_AF5_##member##_SHIFT) & HINIC5_AF5_##member##_MASK)

#define HINIC5_AF5_SET(val, member)				\
	(((val) & HINIC5_AF5_##member##_MASK) << HINIC5_AF5_##member##_SHIFT)

#define HINIC5_AF5_CLEAR(val, member)				\
	((val) & (~(HINIC5_AF5_##member##_MASK << HINIC5_AF5_##member##_SHIFT)))

#define HINIC5_AF6_PF_STATUS_SHIFT		0
#define HINIC5_AF6_PF_STATUS_MASK		0xFFFF

#define HINIC5_AF6_FUNC_MAX_SQ_SHIFT	23
#define HINIC5_AF6_FUNC_MAX_SQ_MASK		0x1FF

#define HINIC5_AF6_MSIX_FLEX_EN_SHIFT	22
#define HINIC5_AF6_MSIX_FLEX_EN_MASK	0x1

#define HINIC5_AF6_HW_TYPE_SHIFT	17
#define HINIC5_AF6_HW_TYPE_MASK		0x3

#define HINIC5_TASK1_MBOX_TIMEOUT_SHIFT		0
#define HINIC5_TASK1_MBOX_TIMEOUT_MASK		0x1

#define HINIC5_AF6_SET(val, member)				\
	((((u32)(val)) & HINIC5_AF6_##member##_MASK) <<		\
	 HINIC5_AF6_##member##_SHIFT)

#define HINIC5_AF6_GET(val, member)				\
	(((u32)(val) >> HINIC5_AF6_##member##_SHIFT) & HINIC5_AF6_##member##_MASK)

#define HINIC5_AF6_CLEAR(val, member)				\
	((u32)(val) & (~(HINIC5_AF6_##member##_MASK <<		\
	 HINIC5_AF6_##member##_SHIFT)))

#define HINIC5_TASK1_SET(val, member)				\
	((((u32)(val)) & HINIC5_TASK1_##member##_MASK) <<		\
	 HINIC5_TASK1_##member##_SHIFT)

#define HINIC5_TASK1_CLEAR(val, member)				\
	((u32)(val) & (~(HINIC5_TASK1_##member##_MASK <<		\
	 HINIC5_TASK1_##member##_SHIFT)))

#define HINIC5_PPF_ELECT_PORT_IDX_SHIFT		0

#define HINIC5_PPF_ELECT_PORT_IDX_MASK		0x3F

#define HINIC5_PPF_ELECT_PORT_GET(val, member)			\
	(((val) >> HINIC5_PPF_ELECT_PORT_##member##_SHIFT) &	\
	 HINIC5_PPF_ELECT_PORT_##member##_MASK)

#define HINIC5_PPF_ELECTION_IDX_SHIFT		0

#define HINIC5_PPF_ELECTION_IDX_MASK		0x3F

#define HINIC5_PPF_ELECTION_SET(val, member)			\
	(((val) & HINIC5_PPF_ELECTION_##member##_MASK) <<	\
	 HINIC5_PPF_ELECTION_##member##_SHIFT)

#define HINIC5_PPF_ELECTION_GET(val, member)			\
	(((val) >> HINIC5_PPF_ELECTION_##member##_SHIFT) &	\
	 HINIC5_PPF_ELECTION_##member##_MASK)

#define HINIC5_PPF_ELECTION_CLEAR(val, member)			\
	((val) & (~(HINIC5_PPF_ELECTION_##member##_MASK <<	\
		  HINIC5_PPF_ELECTION_##member##_SHIFT)))

#define HINIC5_MPF_ELECTION_IDX_SHIFT		0

#define HINIC5_MPF_ELECTION_IDX_MASK		0x1F

#define HINIC5_MPF_ELECTION_SET(val, member)			\
	(((val) & HINIC5_MPF_ELECTION_##member##_MASK) <<	\
	 HINIC5_MPF_ELECTION_##member##_SHIFT)

#define HINIC5_MPF_ELECTION_GET(val, member)			\
	(((val) >> HINIC5_MPF_ELECTION_##member##_SHIFT) &	\
	 HINIC5_MPF_ELECTION_##member##_MASK)

#define HINIC5_MPF_ELECTION_CLEAR(val, member)			\
	((val) & (~(HINIC5_MPF_ELECTION_##member##_MASK <<	\
	 HINIC5_MPF_ELECTION_##member##_SHIFT)))

#define HINIC5_GET_REG_FLAG(reg)	((reg) & (~(HINIC5_REGS_FLAG_MASK)))

#define HINIC5_GET_REG_ADDR(reg)	((reg) & (HINIC5_REGS_FLAG_MASK))

#define HINIC5_MPU_BOOT_CAUSE_MAX_NUM			3

#define SPU_HOST_ID_BASE				4
#define SPU_HOST_NUM					2
#define SPU_HOST_ID_MAX					(SPU_HOST_ID_BASE + SPU_HOST_NUM - 1)

enum {
	UBC_SW_HANDSHAKE_VALID,
	UBC_SW_HANDSHAKE_NO_VALID,
};

u32 hinic5_hwif_read_reg(struct hinic5_hwif *hwif, u32 reg)
{
#ifndef __UEFI__
	if (HINIC5_GET_REG_FLAG(reg) == HINIC5_MGMT_REGS_FLAG)
		return be32_to_cpu(readl(hwif->mgmt_regs_base +
					 HINIC5_GET_REG_ADDR((u64)reg)));
	else
		return be32_to_cpu(readl(hwif->cfg_regs_base +
					 HINIC5_GET_REG_ADDR((u64)reg)));
#else
	UINT8 bar_idx;

	if (HINIC5_GET_REG_FLAG(reg) == HINIC5_MGMT_REGS_FLAG)
		bar_idx = HINIC5_MGMT_BAR;
	else
		bar_idx = HINIC5_CFG_BAR;

	return be32_to_cpu(readl_uefi(hwif->bus_dev, HINIC5_GET_REG_ADDR(reg),
				      bar_idx));
#endif
}

void hinic5_hwif_write_reg(struct hinic5_hwif *hwif, u32 reg, u32 val)
{
#ifndef __UEFI__
	if (HINIC5_GET_REG_FLAG(reg) == HINIC5_MGMT_REGS_FLAG)
		writel(cpu_to_be32(val),
		       hwif->mgmt_regs_base + HINIC5_GET_REG_ADDR((u64)reg));
	else
		writel(cpu_to_be32(val),
		       hwif->cfg_regs_base + HINIC5_GET_REG_ADDR((u64)reg));
#else
	UINT8 bar_idx;

	if (HINIC5_GET_REG_FLAG(reg) == HINIC5_MGMT_REGS_FLAG)
		bar_idx = HINIC5_MGMT_BAR;
	else
		bar_idx = HINIC5_CFG_BAR;

	writel_uefi(hwif->bus_dev, HINIC5_GET_REG_ADDR(reg), bar_idx,
		    be32_to_cpu(val));
#endif
}

bool hinic5_get_card_present_state(struct hinic5_hwdev *hwdev)
{
	u32 attr1;

	if (!get_handshake_state(hwdev))
		return false;

	attr1 = hinic5_hwif_read_reg(hwdev->hwif, HINIC5_CSR_FUNC_ATTR1_ADDR);
	if (attr1 == HINIC5_BUS_LINK_DOWN) {
		sdk_warn(hwdev->dev_hdl, "Card is not present\n");
		return false;
	}

	return true;
}

u8 hinic5_get_hw_type(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (unlikely(!dev || !dev->hwif))
		return HINIC5_HW_TYPE_INVALID;

	return dev->hwif->attr.hw_type;
}
EXPORT_SYMBOL(hinic5_get_hw_type);

/**
 * get_handshake_state - for UBC ELR, only 72 use
 * @hwdev: the pointer to hw device
 * Return: 0 - normal, 1 - in ELR
 **/
bool get_handshake_state(struct hinic5_hwdev *hwdev)
{
#ifndef __UEFI__
	u32 sw_handshake_chk;

	if (!hinic5_check_htn_device_id(hwdev))
		return true;

	sw_handshake_chk = readl(hwdev->hwif->fers2_reg_base +
				 HINIC5_GET_REG_ADDR \
				 ((u64)HINIC5_CSR_INTC_BAR_SW_HANDSHAKE_0_CSR0_REG));
	if (sw_handshake_chk == UBC_SW_HANDSHAKE_NO_VALID)
		return false;
#endif

	return true;
}

u32 hinic5_get_heartbeat_status(void *hwdev)
{
	u32 attr1;
	struct hinic5_hwif *hwif = NULL;

	if (!hwdev)
		return HINIC5_BUS_LINK_DOWN;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return HINIC5_BUS_LINK_DOWN;

	attr1 = hinic5_hwif_read_reg(hwif, HINIC5_CSR_FUNC_ATTR1_ADDR);
	if (attr1 == HINIC5_BUS_LINK_DOWN)
		return attr1;

	return (HINIC5_AF1_GET(attr1, MGMT_INIT_STATUS) == 0);
}
EXPORT_SYMBOL(hinic5_get_heartbeat_status);

#define MIGRATE_HOST_STATUS_CLEAR(host_id, val)	((val) & (~(1U << (host_id))))
#define MIGRATE_HOST_STATUS_SET(host_id, enable)	(((u8)(enable) & 1U) << (host_id))
#define MIGRATE_HOST_STATUS_GET(host_id, val)	(((val) & (1U << (host_id))) != 0)

static inline int hinic5_hwdev_check(struct hinic5_hwdev *dev)
{
	if (!dev || !dev->hwif)
		return -EINVAL;
	if (HINIC5_FUNC_TYPE(dev) != TYPE_PPF) {
		sdk_warn(dev->dev_hdl, "hwdev should be ppf\n");
		return -EINVAL;
	}
	return 0;
}

int hinic5_set_host_migrate_enable(void *hwdev, u8 host_id, bool enable)
{
	struct hinic5_hwdev *dev = hwdev;

	u32 reg_val;
	int ret = hinic5_hwdev_check(dev);

	if (ret != 0)
		return ret;

	reg_val = hinic5_hwif_read_reg(dev->hwif, HINIC5_MULT_MIGRATE_HOST_STATUS_ADDR);
	reg_val = MIGRATE_HOST_STATUS_CLEAR(host_id, reg_val);
	reg_val |= MIGRATE_HOST_STATUS_SET(host_id, enable);

	hinic5_hwif_write_reg(dev->hwif, HINIC5_MULT_MIGRATE_HOST_STATUS_ADDR, reg_val);

	sdk_info(dev->dev_hdl, "Set migrate host %u status %d, reg value: 0x%x\n",
		 host_id, enable, reg_val);

	return 0;
}
EXPORT_SYMBOL(hinic5_set_host_migrate_enable);

int hinic5_get_host_migrate_enable(void *hwdev, u8 host_id, u8 *migrate_en)
{
	struct hinic5_hwdev *dev = hwdev;

	u32 reg_val;
	int ret = hinic5_hwdev_check(dev);

	if (ret != 0)
		return ret;

	reg_val = hinic5_hwif_read_reg(dev->hwif, HINIC5_MULT_MIGRATE_HOST_STATUS_ADDR);
	*migrate_en = MIGRATE_HOST_STATUS_GET(host_id, reg_val);

	return 0;
}
EXPORT_SYMBOL(hinic5_get_host_migrate_enable);

static enum hinic5_wait_return check_hwif_ready_handler(void *priv_data)
{
	u32 status;

	status = hinic5_get_heartbeat_status(priv_data);
	if (status == HINIC5_BUS_LINK_DOWN)
		return WAIT_PROCESS_ERR;
	else if (status == 0)
		return WAIT_PROCESS_CPL;

	return WAIT_PROCESS_WAITING;
}

static int wait_hwif_ready(struct hinic5_hwdev *hwdev)
{
	int ret;

	ret = hinic5_wait_for_timeout(hwdev, check_hwif_ready_handler,
				      WAIT_HWIF_READY_TIMEOUT, USEC_PER_MSEC);
	if (ret == -ETIMEDOUT) {
		hwdev->probe_fault_level = FAULT_LEVEL_FATAL;
		sdk_err(hwdev->dev_hdl, "Wait for hwif timeout\n");
	}

	return ret;
}

/**
 * set_hwif_attr - set the attributes as members in hwif
 * @hwif: the hardware interface of a pci function device
 * @attr0: the first attribute that was read from the hw
 * @attr1: the second attribute that was read from the hw
 * @attr2: the third attribute that was read from the hw
 * @attr3: the fourth attribute that was read from the hw
 **/
static void set_hwif_attr(struct hinic5_hwif *hwif, u32 attr0, u32 attr1,
			  u32 attr2, u32 attr3, u32 attr6)
{
	struct hinic5_hwdev *hwdev = hwif->hwdev;

	hwif->attr.func_global_idx = HINIC5_AF0_GET(attr0, FUNC_GLOBAL_IDX);
	hwif->attr.port_to_port_idx = HINIC5_AF0_GET(attr0, P2P_IDX);
	hwif->attr.pci_intf_idx = HINIC5_AF0_GET(attr0, PCI_INTF_IDX);
	hwif->attr.vf_in_pf = HINIC5_AF0_GET(attr0, VF_IN_PF);
	hwif->attr.func_type = HINIC5_AF0_GET(attr0, FUNC_TYPE);

	hwif->attr.ppf_idx = HINIC5_AF1_GET(attr1, PPF_IDX);
	hwif->attr.num_aeqs = BIT(HINIC5_AF1_GET(attr1, AEQS_PER_FUNC));
	hwif->attr.num_ceqs = (u8)HINIC5_AF2_GET(attr2, CEQS_PER_FUNC);
	hwif->attr.num_irqs = HINIC5_AF2_GET(attr2, IRQS_PER_FUNC);
	if (hwif->attr.num_irqs > MAX_MSIX_ENTRY)
		hwif->attr.num_irqs = MAX_MSIX_ENTRY;

	hwif->attr.num_dma_attr = BIT(HINIC5_AF2_GET(attr2, DMA_ATTR_PER_FUNC));

	hwif->attr.global_vf_id_of_pf = HINIC5_AF3_GET(attr3,
						       GLOBAL_VF_ID_OF_PF);

	hwif->attr.num_sq = HINIC5_AF6_GET(attr6, FUNC_MAX_SQ);
	hwif->attr.msix_flex_en = HINIC5_AF6_GET(attr6, MSIX_FLEX_EN);
	hwif->attr.hw_type = HINIC5_AF6_GET(attr6, HW_TYPE);

	sdk_info(hwdev->dev_hdl,
		 "func_global_idx: 0x%x, port_to_port_idx: 0x%x, pci_intf_idx: 0x%x\n",
		 hwif->attr.func_global_idx, hwif->attr.port_to_port_idx,
		 hwif->attr.pci_intf_idx);

	sdk_info(hwdev->dev_hdl,
		 "vf_in_pf: 0x%x, func_type: %d msix_flex_en %u\n",
		 hwif->attr.vf_in_pf, hwif->attr.func_type,
		 hwif->attr.msix_flex_en);

	sdk_info(hwdev->dev_hdl,
		 "ppf_idx: 0x%x, num_aeqs: 0x%x, num_ceqs: 0x%x, num_irqs: 0x%x\n",
		 hwif->attr.ppf_idx, hwif->attr.num_aeqs,
		 hwif->attr.num_ceqs, hwif->attr.num_irqs);

	sdk_info(hwdev->dev_hdl,
		 "num_sq: 0x%x, num_dma_attr: 0x%x, global_vf_id_of_pf: %u, hw_type: %u\n",
		 hwif->attr.num_sq, hwif->attr.num_dma_attr,
		 hwif->attr.global_vf_id_of_pf, hwif->attr.hw_type);
}

/**
 * get_hwif_attr - read and set the attributes as members in hwif
 * @hwif: the hardware interface of a pci function device
 **/
static int get_hwif_attr(struct hinic5_hwif *hwif)
{
	struct hinic5_hwdev *hwdev = hwif->hwdev;
	u32 addr, attr0, attr1, attr2, attr3, attr6;

	addr   = HINIC5_CSR_FUNC_ATTR0_ADDR;
	attr0  = hinic5_hwif_read_reg(hwif, addr);
	if (attr0 == HINIC5_BUS_LINK_DOWN)
		return -EFAULT;

	addr   = HINIC5_CSR_FUNC_ATTR1_ADDR;
	attr1  = hinic5_hwif_read_reg(hwif, addr);
	if (attr1 == HINIC5_BUS_LINK_DOWN)
		return -EFAULT;

	addr   = HINIC5_CSR_FUNC_ATTR2_ADDR;
	attr2  = hinic5_hwif_read_reg(hwif, addr);
	if (attr2 == HINIC5_BUS_LINK_DOWN)
		return -EFAULT;

	addr   = HINIC5_CSR_FUNC_ATTR3_ADDR;
	attr3  = hinic5_hwif_read_reg(hwif, addr);
	if (attr3 == HINIC5_BUS_LINK_DOWN)
		return -EFAULT;

	addr   = HINIC5_CSR_FUNC_ATTR6_ADDR;
	attr6  = hinic5_hwif_read_reg(hwif, addr);
	if (attr6 == HINIC5_BUS_LINK_DOWN)
		return -EFAULT;

	sdk_info(hwdev->dev_hdl,
		 "attr0: 0x%08x, attr1: 0x%08x, attr2: 0x%08x, attr3: 0x%08x, attr6: 0x%08x\n",
		 attr0, attr1, attr2, attr3, attr6);
	set_hwif_attr(hwif, attr0, attr1, attr2, attr3, attr6);

	return 0;
}

void hinic5_set_pf_status(struct hinic5_hwif *hwif,
			  enum hinic5_pf_status status)
{
	u32 attr6 = hinic5_hwif_read_reg(hwif, HINIC5_CSR_FUNC_ATTR6_ADDR);

	attr6 = HINIC5_AF6_CLEAR(attr6, PF_STATUS);
	attr6 |= HINIC5_AF6_SET(status, PF_STATUS);

	hinic5_hwif_write_reg(hwif, HINIC5_CSR_FUNC_ATTR6_ADDR, attr6);
}

enum hinic5_pf_status hinic5_get_pf_status(struct hinic5_hwif *hwif)
{
	u32 attr6 = hinic5_hwif_read_reg(hwif, HINIC5_CSR_FUNC_ATTR6_ADDR);

	return HINIC5_AF6_GET(attr6, PF_STATUS);
}

static inline enum doorbell_flush_state hinic5_get_doorbell_ctrl_status(struct hinic5_hwif *hwif)
{
	u32 attr4 = hinic5_hwif_read_reg(hwif, HINIC5_CSR_FUNC_ATTR4_ADDR);

	return HINIC5_AF4_GET(attr4, DOORBELL_CTRL);
}

static inline enum outbound_flush_state hinic5_get_outbound_ctrl_status(struct hinic5_hwif *hwif)
{
	u32 attr5 = hinic5_hwif_read_reg(hwif, HINIC5_CSR_FUNC_ATTR5_ADDR);

	return HINIC5_AF5_GET(attr5, OUTBOUND_CTRL);
}

void hinic5_enable_doorbell(struct hinic5_hwif *hwif)
{
	u32 addr, attr4;

	addr = HINIC5_CSR_FUNC_ATTR4_ADDR;
	attr4 = hinic5_hwif_read_reg(hwif, addr);

	attr4 = HINIC5_AF4_CLEAR(attr4, DOORBELL_CTRL);
	attr4 |= HINIC5_AF4_SET(DOORBELL_FLUSH_DISABLED, DOORBELL_CTRL);

	hinic5_hwif_write_reg(hwif, addr, attr4);
}

void hinic5_disable_doorbell(struct hinic5_hwif *hwif)
{
	u32 addr, attr4;

	addr = HINIC5_CSR_FUNC_ATTR4_ADDR;
	attr4 = hinic5_hwif_read_reg(hwif, addr);

	attr4 = HINIC5_AF4_CLEAR(attr4, DOORBELL_CTRL);
	attr4 |= HINIC5_AF4_SET(DOORBELL_FLUSH_ENABLED, DOORBELL_CTRL);

	hinic5_hwif_write_reg(hwif, addr, attr4);
}

/**
 * set_ppf - try to set hwif as ppf and set the type of hwif in this case
 * @hwif: the hardware interface of a pci function device
 **/
static void set_ppf(struct hinic5_hwif *hwif)
{
	struct hinic5_func_attr *attr = &hwif->attr;
	u32 addr, val, ppf_election;

	/* Read Modify Write */
	addr  = HINIC5_CSR_PPF_ELECTION_ADDR;

	val = hinic5_hwif_read_reg(hwif, addr);
	val = HINIC5_PPF_ELECTION_CLEAR(val, IDX);

	ppf_election =  HINIC5_PPF_ELECTION_SET(attr->func_global_idx, IDX);
	val |= ppf_election;

	hinic5_hwif_write_reg(hwif, addr, val);

	/* Check PPF */
	val = hinic5_hwif_read_reg(hwif, addr);

	attr->ppf_idx = HINIC5_PPF_ELECTION_GET(val, IDX);
	if (attr->ppf_idx == attr->func_global_idx)
		attr->func_type = TYPE_PPF;
}

/**
 * get_mpf - get the mpf index into the hwif
 * @hwif: the hardware interface of a pci function device
 **/
static void get_mpf(struct hinic5_hwif *hwif)
{
	struct hinic5_func_attr *attr = &hwif->attr;
	u32 mpf_election, addr;

	addr = HINIC5_CSR_GLOBAL_MPF_ELECTION_ADDR;

	mpf_election = hinic5_hwif_read_reg(hwif, addr);
	attr->mpf_idx = HINIC5_MPF_ELECTION_GET(mpf_election, IDX);
}

/**
 * set_mpf - try to set hwif as mpf and set the mpf idx in hwif
 * @hwif: the hardware interface of a pci function device
 **/
static void set_mpf(struct hinic5_hwif *hwif)
{
	struct hinic5_func_attr *attr = &hwif->attr;
	u32 addr, val, mpf_election;

	/* Read Modify Write */
	addr  = HINIC5_CSR_GLOBAL_MPF_ELECTION_ADDR;

	val = hinic5_hwif_read_reg(hwif, addr);

	val = HINIC5_MPF_ELECTION_CLEAR(val, IDX);
	mpf_election = HINIC5_MPF_ELECTION_SET(attr->func_global_idx, IDX);

	val |= mpf_election;
	hinic5_hwif_write_reg(hwif, addr, val);
}

static int init_hwif(struct hinic5_hwdev *hwdev, void *fers2_reg_base,
		     void *cfg_reg_base, void *intr_reg_base,
		     void *mgmt_regs_base)
{
	struct hinic5_hwif *hwif = NULL;

	hwif = kzalloc(sizeof(*hwif), GFP_KERNEL);
	if (!hwif)
		return -ENOMEM;

	hwdev->hwif = hwif;
#ifdef __UEFI__
	hwif->bus_dev = hwdev->busdev_hdl;
#endif
	hwif->hwdev = hwdev;

	hwif->fers2_reg_base = fers2_reg_base;
	/* if function is VF, mgmt_regs_base will be NULL */
	hwif->cfg_regs_base = mgmt_regs_base ? cfg_reg_base :
		(u8 *)((uintptr_t)cfg_reg_base + HINIC5_VF_CFG_REG_OFFSET);

	hwif->intr_regs_base = intr_reg_base;
	hwif->mgmt_regs_base = mgmt_regs_base;

	hwif->attr.func_type = TYPE_UNKNOWN;

	return 0;
}

static int init_db_area_idx(struct hinic5_hwif *hwif, u64 db_base_phy, u8 *db_base,
			    u64 db_dwqe_len)
{
	struct hinic5_free_db_area *free_db_area = &hwif->free_db_area;
	u32 db_max_areas;

	hwif->db_base_phy = db_base_phy;
	hwif->db_base = db_base;
	hwif->db_dwqe_len = db_dwqe_len;

	db_max_areas = (db_dwqe_len > HINIC5_DB_DWQE_SIZE) ?
		      HINIC5_DB_MAX_AREAS :
		      (u32)(db_dwqe_len / HINIC5_DB_PAGE_SIZE);
	free_db_area->db_bitmap_array = bitmap_zalloc(db_max_areas, GFP_KERNEL);
	if (!free_db_area->db_bitmap_array) {
		pr_err("Failed to allocate db area.\n");
		return -ENOMEM;
	}
	free_db_area->db_max_areas = db_max_areas;
	spin_lock_init(&free_db_area->idx_lock);
	return 0;
}

static void free_db_area(struct hinic5_free_db_area *free_db_area)
{
	spin_lock_deinit(&free_db_area->idx_lock);
	kfree(free_db_area->db_bitmap_array);
}

static int get_db_idx(struct hinic5_hwif *hwif, u32 *idx)
{
	struct hinic5_free_db_area *free_db_area = &hwif->free_db_area;
	u32 pg_idx;

	spin_lock(&free_db_area->idx_lock);
	pg_idx = (u32)find_first_zero_bit(free_db_area->db_bitmap_array,
					  free_db_area->db_max_areas);
	if (pg_idx == free_db_area->db_max_areas) {
		spin_unlock(&free_db_area->idx_lock);
		return -ENOMEM;
	}
	set_bit(pg_idx, free_db_area->db_bitmap_array);
	spin_unlock(&free_db_area->idx_lock);

	*idx = pg_idx;

	return 0;
}

static void free_db_idx(struct hinic5_hwif *hwif, u32 idx)
{
	struct hinic5_free_db_area *free_db_area = &hwif->free_db_area;

	if (idx >= free_db_area->db_max_areas)
		return;

	spin_lock(&free_db_area->idx_lock);
	clear_bit((int)idx, free_db_area->db_bitmap_array);

	spin_unlock(&free_db_area->idx_lock);
}

void hinic5_free_db_addr(void *hwdev, const void __iomem *db_base,
			 void __iomem *dwqe_base)
{
	struct hinic5_hwif *hwif = NULL;
	u32 idx;

	if (!hwdev || !db_base)
		return;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return;
	idx = DB_IDX((uintptr_t)db_base, (uintptr_t)hwif->db_base);

	free_db_idx(hwif, idx);
}
EXPORT_SYMBOL(hinic5_free_db_addr);

int hinic5_alloc_db_addr(void *hwdev, void __iomem **db_base,
			 void __iomem **dwqe_base)
{
	struct hinic5_hwif *hwif = NULL;
	u32 idx = 0;
#ifdef __HIFC__
#define HIFC3_DB_ADDR_RSVD 12
#define HIFC3_DB_MASK 128
	u64 db_base_phy_fc;

	if (!hwdev || !db_base)
		return -EINVAL;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;

	db_base_phy_fc = hwif->db_base_phy >> HIFC3_DB_ADDR_RSVD;

	if (db_base_phy_fc & (HIFC3_DB_MASK - 1))
		idx = HIFC3_DB_MASK - (db_base_phy_fc && (HIFC3_DB_MASK - 1));
#else
	int err;

	if (!hwdev || !db_base)
		return -EINVAL;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return -EINVAL;

	err = get_db_idx(hwif, &idx);
	if (err != 0)
		return -EFAULT;
#endif

	*db_base = hwif->db_base + idx * HINIC5_DB_PAGE_SIZE;

	if (dwqe_base)
		*dwqe_base = (u8 *)*db_base + HINIC5_DWQE_OFFSET;

	return 0;
}
EXPORT_SYMBOL(hinic5_alloc_db_addr);

void hinic5_free_db_phy_addr(void *hwdev, u64 db_base, u64 dwqe_base)
{
	struct hinic5_hwif *hwif = NULL;
	u32 idx;

	if (!hwdev)
		return;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return;
	idx = DB_IDX(db_base, hwif->db_base_phy);

	free_db_idx(hwif, idx);
}
EXPORT_SYMBOL(hinic5_free_db_phy_addr);

int hinic5_alloc_db_phy_addr(void *hwdev, u64 *db_base, u64 *dwqe_base)
{
	struct hinic5_hwif *hwif = NULL;
	u32 idx;
	int err;

	if (!hwdev || !db_base || !dwqe_base)
		return -EINVAL;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return -EINVAL;

	err = get_db_idx(hwif, &idx);
	if (err != 0)
		return -EFAULT;

	*db_base = hwif->db_base_phy + idx * HINIC5_DB_PAGE_SIZE;
	*dwqe_base = *db_base + HINIC5_DWQE_OFFSET;

	return 0;
}
EXPORT_SYMBOL(hinic5_alloc_db_phy_addr);

void hinic5_set_msix_auto_mask_state(void *hwdev, u16 msix_idx,
				     enum hinic5_msix_auto_mask flag)
{
	struct hinic5_hwif *hwif = NULL;
	u32 mask_bits;
	u32 addr;

	if (!hwdev)
		return;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return;

	if (flag != 0)
		mask_bits = HINIC5_MSI_CLR_INDIR_SET(1, AUTO_MSK_SET);
	else
		mask_bits = HINIC5_MSI_CLR_INDIR_SET(1, AUTO_MSK_CLR);

	mask_bits = mask_bits |
		    HINIC5_MSI_CLR_INDIR_SET(msix_idx, SIMPLE_INDIR_IDX);

	addr = HINIC5_CSR_FUNC_MSI_CLR_WR_ADDR;
	hinic5_hwif_write_reg(hwif, addr, mask_bits);
}
EXPORT_SYMBOL(hinic5_set_msix_auto_mask_state);

void hinic5_set_msix_state(void *hwdev, u16 msix_idx,
			   enum hinic5_msix_state flag)
{
	struct hinic5_hwif *hwif = NULL;
	u32 mask_bits;
	u32 addr;
	u8 int_msk = 1;

	if (!hwdev)
		return;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return;

	if (flag != 0)
		mask_bits = HINIC5_MSI_CLR_INDIR_SET(int_msk, INT_MSK_SET);
	else
		mask_bits = HINIC5_MSI_CLR_INDIR_SET(int_msk, INT_MSK_CLR);
	mask_bits = mask_bits |
		    HINIC5_MSI_CLR_INDIR_SET(msix_idx, SIMPLE_INDIR_IDX);

	addr = HINIC5_CSR_FUNC_MSI_CLR_WR_ADDR;
	hinic5_hwif_write_reg(hwif, addr, mask_bits);
}
EXPORT_SYMBOL(hinic5_set_msix_state);

static void disable_all_msix(struct hinic5_hwdev *hwdev)
{
	u16 num_irqs = hwdev->hwif->attr.num_irqs;
	u16 i;

	for (i = 0; i < num_irqs; i++)
		hinic5_set_msix_state(hwdev, i, HINIC5_MSIX_DISABLE);
}

static enum hinic5_wait_return check_db_outbound_enable_handler(void *priv_data)
{
	struct hinic5_hwif *hwif = priv_data;
	enum doorbell_flush_state db_ctrl;
	enum outbound_flush_state outbound_ctrl;

	db_ctrl = hinic5_get_doorbell_ctrl_status(hwif);
	outbound_ctrl = hinic5_get_outbound_ctrl_status(hwif);
	if (outbound_ctrl == OUTBOUND_FLUSH_DISABLED && db_ctrl == DOORBELL_FLUSH_DISABLED)
		return WAIT_PROCESS_CPL;
	return WAIT_PROCESS_WAITING;
}

enum hinic5_wait_return check_outbound_enable_handler(struct hinic5_hwdev *hwdev)
{
	enum outbound_flush_state outbound_ctrl;
	/* bypass counter is non-zero, indicates a flow that may cause
	 * outbound_ctrl_status to be non-zero is being executed, cmdq and mbox do not check
	 */
	if (atomic_read(&hwdev->check_ob_flush_bypass_ref_cnt) > 0)
		return WAIT_PROCESS_CPL;

	outbound_ctrl = hinic5_get_outbound_ctrl_status(hwdev->hwif);
	if (outbound_ctrl == OUTBOUND_FLUSH_DISABLED)
		return WAIT_PROCESS_CPL;
	return WAIT_PROCESS_WAITING;
}

static int wait_until_doorbell_and_outbound_enabled(struct hinic5_hwif *hwif)
{
	return hinic5_wait_for_timeout(hwif, check_db_outbound_enable_handler,
		HINIC5_WAIT_DOORBELL_AND_OUTBOUND_TIMEOUT, USEC_PER_MSEC);
}

static void select_ppf_mpf(struct hinic5_hwdev *hwdev)
{
	struct hinic5_hwif *hwif = hwdev->hwif;

	if (!HINIC5_IS_VF(hwdev)) {
		set_ppf(hwif);

		if (HINIC5_IS_PPF(hwdev))
			set_mpf(hwif);

		get_mpf(hwif);
	}
}

/**
 * hinic5_init_hwif - initialize the hw interface
 * @hwif: the hardware interface of a pci/ubus function device
 * Return: 0 - success, negative - failure
 **/
int hinic5_init_hwif(struct hinic5_hwdev *hwdev, void *fers2_reg_base, void *cfg_reg_base,
		     void *intr_reg_base, void *mgmt_regs_base, u64 db_base_phy,
		     void *db_base, u64 db_dwqe_len)
{
	struct hinic5_hwif *hwif = NULL;
	u32 attr1, attr4, attr5;
	int err;

	err = init_hwif(hwdev, fers2_reg_base, cfg_reg_base, intr_reg_base, mgmt_regs_base);
	if (err != 0)
		return err;

	hwif = hwdev->hwif;

	err = init_db_area_idx(hwif, db_base_phy, db_base, db_dwqe_len);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init db area.\n");
		goto init_db_area_err;
	}

	err = wait_hwif_ready(hwdev);
	if (err != 0) {
		attr1 = hinic5_hwif_read_reg(hwif, HINIC5_CSR_FUNC_ATTR1_ADDR);
		sdk_err(hwdev->dev_hdl, "Chip status is not ready, attr1:0x%x\n", attr1);
		goto hwif_ready_err;
	}

	err = get_hwif_attr(hwif);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Get hwif attr failed\n");
		goto hwif_ready_err;
	}

	err = wait_until_doorbell_and_outbound_enabled(hwif);
	if (err != 0) {
		attr4 = hinic5_hwif_read_reg(hwif, HINIC5_CSR_FUNC_ATTR4_ADDR);
		attr5 = hinic5_hwif_read_reg(hwif, HINIC5_CSR_FUNC_ATTR5_ADDR);
		sdk_err(hwdev->dev_hdl, "Hw doorbell/outbound is disabled, attr4 0x%x attr5 0x%x\n",
			attr4, attr5);
		goto hwif_ready_err;
	}

	select_ppf_mpf(hwdev);

	disable_all_msix(hwdev);
	/* disable mgmt cpu report any event */
	hinic5_set_pf_status(hwdev->hwif, HINIC5_PF_STATUS_INIT);

	sdk_info(hwdev->dev_hdl, "global_func_idx: %u, func_type: %d, host_id: %u, ppf: %u, mpf: %u\n",
		 hwif->attr.func_global_idx, hwif->attr.func_type, hwif->attr.pci_intf_idx,
		 hwif->attr.ppf_idx, hwif->attr.mpf_idx);

	return 0;

hwif_ready_err:
	hinic5_show_chip_err_info(hwdev);
	free_db_area(&hwif->free_db_area);
init_db_area_err:
	kfree(hwif);

	return err;
}

/**
 * hinic5_free_hwif - free the hw interface
 * @hwif: the hardware interface of a pci/ubus function device
 **/
void hinic5_free_hwif(struct hinic5_hwdev *hwdev)
{
	free_db_area(&hwdev->hwif->free_db_area);
	kfree(hwdev->hwif);
}

u16 hinic5_global_func_id(void *hwdev)
{
	struct hinic5_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return 0;

	return hwif->attr.func_global_idx;
}
EXPORT_SYMBOL(hinic5_global_func_id);

u16 hinic5_intr_num(void *hwdev)
{
	struct hinic5_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return 0;

	return hwif->attr.num_irqs;
}
EXPORT_SYMBOL(hinic5_intr_num);

u8 hinic5_pf_id_of_vf(void *hwdev)
{
	struct hinic5_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return 0;

	return hwif->attr.port_to_port_idx;
}
EXPORT_SYMBOL(hinic5_pf_id_of_vf);

u8 hinic5_pcie_itf_id(void *hwdev)
{
	struct hinic5_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return 0;

	return hwif->attr.pci_intf_idx;
}
EXPORT_SYMBOL(hinic5_pcie_itf_id);

bool hinic5_in_spu(void *hwdev)
{
	const u8 host_id = hinic5_pcie_itf_id(hwdev);

	return SPU_HOST_ID_BASE <= host_id && host_id <= SPU_HOST_ID_MAX;
}
EXPORT_SYMBOL(hinic5_in_spu);

u8 hinic5_vf_in_pf(void *hwdev)
{
	struct hinic5_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return 0;

	return hwif->attr.vf_in_pf;
}
EXPORT_SYMBOL(hinic5_vf_in_pf);

enum func_type hinic5_func_type(void *hwdev)
{
	struct hinic5_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return 0;

	return hwif->attr.func_type;
}
EXPORT_SYMBOL(hinic5_func_type);

u8 hinic5_ceq_num(void *hwdev)
{
	struct hinic5_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return 0;

	return hwif->attr.num_ceqs;
}
EXPORT_SYMBOL(hinic5_ceq_num);

u16 hinic5_glb_pf_vf_offset(void *hwdev)
{
	struct hinic5_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return 0;

	return hwif->attr.global_vf_id_of_pf;
}
EXPORT_SYMBOL(hinic5_glb_pf_vf_offset);

u8 hinic5_ppf_idx(void *hwdev)
{
	struct hinic5_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;
	if (!hwif)
		return 0;

	return hwif->attr.ppf_idx;
}
EXPORT_SYMBOL(hinic5_ppf_idx);

#if !defined(__UEFI__) && !defined(__VMWARE__) && !defined(__WIN__)
int hinic5_ts_up_en(void *hwdev, u32 flags)
{
	u32 retry_cnt;
	struct hinic5_hwdev *dev = (struct hinic5_hwdev *)hwdev;

	if (!dev || HINIC5_IS_VF(dev))
		return -EINVAL;

	hinic5_hwif_write_reg(dev->hwif, HINIC5_PTP_REG(UP_EN), flags);
	for (retry_cnt = 0; retry_cnt < MAX_TS_UP_EN_RETRY_CNT; retry_cnt++) {
		if ((hinic5_hwif_read_reg(dev->hwif, HINIC5_PTP_REG(UP_EN)) & flags) == 0)
			return 0;

		udelay(1);
	}
	return -EINVAL;
}
EXPORT_SYMBOL(hinic5_ts_up_en);

void hinic5_read_ts_data(void *hwdev, struct timespec64 *ts)
{
	u32 hi, lo;
	struct hinic5_hwdev *dev = (struct hinic5_hwdev *)hwdev;

	if (!dev || HINIC5_IS_VF(dev) || !ts)
		return;

	ts->tv_nsec = hinic5_hwif_read_reg(dev->hwif, HINIC5_PTP_REG(RD_DATA2));
	lo = hinic5_hwif_read_reg(dev->hwif, HINIC5_PTP_REG(RD_DATA1));
	hi = hinic5_hwif_read_reg(dev->hwif, HINIC5_PTP_REG(RD_DATA0));
	ts->tv_sec = (time64_t)MAKE_64BITS(hi, lo);
}
EXPORT_SYMBOL(hinic5_read_ts_data);

void hinic5_write_ts_data(void *hwdev, const struct timespec64 *ts)
{
	u32 retry_cnt;
	u64 second;
	struct hinic5_hwdev *dev = (struct hinic5_hwdev *)hwdev;

	if (!dev || !dev->hwif || HINIC5_IS_VF(dev) || !ts)
		return;

	second = (u64)ts->tv_sec;
	hinic5_hwif_write_reg(dev->hwif, HINIC5_PTP_REG(WR_DATA2), (u32)ts->tv_nsec);
	hinic5_hwif_write_reg(dev->hwif, HINIC5_PTP_REG(WR_DATA1), second & 0xFFFFFFFF);
	hinic5_hwif_write_reg(dev->hwif, HINIC5_PTP_REG(WR_DATA0), upper_32_bits(second));
	hinic5_hwif_write_reg(dev->hwif, HINIC5_PTP_REG(UP_EN), 1);
	for (retry_cnt = 0; retry_cnt < MAX_TS_UP_EN_RETRY_CNT; retry_cnt++) {
		if (hinic5_hwif_read_reg(dev->hwif, HINIC5_PTP_REG(UP_EN)) == 0)
			break;

		udelay(1);
	}
}
EXPORT_SYMBOL(hinic5_write_ts_data);

#define PTP_INC_CFG_UP_EN_FLAG	BIT(2)
#define PTP_DELTA_UP_EN_FLAG	BIT(3)
void hinic5_set_ptp_inc(void *hwdev, u32 inc_val)
{
	u32 retry_cnt;
	struct hinic5_hwdev *dev = (struct hinic5_hwdev *)hwdev;

	if (!dev || !dev->hwif || HINIC5_IS_VF(dev))
		return;

	hinic5_hwif_write_reg(dev->hwif, HINIC5_PTP_REG(INC_CFG), inc_val);
	hinic5_hwif_write_reg(dev->hwif, HINIC5_PTP_REG(UP_EN), PTP_INC_CFG_UP_EN_FLAG);
	for (retry_cnt = 0; retry_cnt < MAX_TS_UP_EN_RETRY_CNT; retry_cnt++) {
		if (hinic5_hwif_read_reg(dev->hwif, HINIC5_PTP_REG(UP_EN)) == 0)
			break;

		udelay(1);
	}
}
EXPORT_SYMBOL(hinic5_set_ptp_inc);

#define PTP_NS_DELTA_OP_ADD	BIT(31)
void hinic5_ptp_ts_update(void *hwdev, s32 delta_ns)
{
	u32 retry_cnt;
	u32 update_cfg_val;
	struct hinic5_hwdev *dev = (struct hinic5_hwdev *)hwdev;

	if (!dev || !dev->hwif || HINIC5_IS_VF(dev))
		return;

	if (delta_ns < 0) {
		update_cfg_val = (u32)(-delta_ns);
	} else {
		update_cfg_val = (u32)delta_ns;
		update_cfg_val |= PTP_NS_DELTA_OP_ADD;
	}

	hinic5_hwif_write_reg(dev->hwif, HINIC5_PTP_REG(UPDT_CFG), update_cfg_val);
	hinic5_hwif_write_reg(dev->hwif, HINIC5_PTP_REG(UP_EN), PTP_DELTA_UP_EN_FLAG);
	for (retry_cnt = 0; retry_cnt < MAX_TS_UP_EN_RETRY_CNT; retry_cnt++) {
		if (hinic5_hwif_read_reg(dev->hwif, HINIC5_PTP_REG(UP_EN)) == 0)
			break;

		udelay(1);
	}
}
EXPORT_SYMBOL(hinic5_ptp_ts_update);

#define HINIC5_N_PTP_HIGH_SHIFT 61
#define HINIC5_N_PTP_MID_SHIFT 29
#define HINIC5_N_PTP_HIGH_MASK 7
#define HINIC5_N_PTP_LOW_MASK 0x1FFFFFFF
int hinic5_read_n_ptp_ts_data(struct hinic5_hwdev *hwdev, u64 *time_ns)
{
	u32 hi, mid, lo;

	if (!hwdev || HINIC5_IS_VF(hwdev) || !time_ns)
		return -EINVAL;

	/* 80 bit non-ptp TimeStamp */
	/* | [79 : 64]  | [63 : 32] | [31 : 29] | [28 : 0] |
	 * | hi         | mid       |  rsv      | lo       |
	 */
	lo = hinic5_hwif_read_reg(hwdev->hwif, HINIC5_N_PTP_REG(RD_DATA2));
	mid = hinic5_hwif_read_reg(hwdev->hwif, HINIC5_N_PTP_REG(RD_DATA1));
	hi = hinic5_hwif_read_reg(hwdev->hwif, HINIC5_N_PTP_REG(RD_DATA0));

	/* 64 bit nsec_lo */
	/* | [63 : 61] | [60 : 29] | [28 : 0] |
	 * | hi[2 : 0] | mid	   | lo	      |
	 */
	*time_ns = (((u64)(lo & HINIC5_N_PTP_LOW_MASK)) | (((u64)mid) << HINIC5_N_PTP_MID_SHIFT) |
		   (((u64)(hi & HINIC5_N_PTP_HIGH_MASK)) << HINIC5_N_PTP_HIGH_SHIFT));
	return 0;
}

static inline int hinic5_hwif_wait_n_ptp_up_en(struct hinic5_hwif *hwif, u32 flags)
{
	u32 retry_cnt;

	for (retry_cnt = 0; retry_cnt < MAX_TS_UP_EN_RETRY_CNT; retry_cnt++) {
		if ((hinic5_hwif_read_reg(hwif, HINIC5_N_PTP_REG(UP_EN)) & flags) == 0)
			return 0;
		udelay(1);
	}
	return -EBUSY;
}

int hinic5_n_ptp_ts_up_en(struct hinic5_hwdev *hwdev, u32 flags)
{
	if (!hwdev || HINIC5_IS_VF(hwdev))
		return -EINVAL;

	hinic5_hwif_write_reg(hwdev->hwif, HINIC5_N_PTP_REG(UP_EN), flags);
	return hinic5_hwif_wait_n_ptp_up_en(hwdev->hwif, flags);
}
#endif

u8 hinic5_host_ppf_idx(struct hinic5_hwdev *hwdev, u8 host_id)
{
	u32 ppf_elect_port_addr;
	u32 val;

	if (!hwdev || !hwdev->hwif)
		return 0;

	ppf_elect_port_addr = HINIC5_CSR_FUNC_PPF_ELECT(host_id);
	val = hinic5_hwif_read_reg(hwdev->hwif, ppf_elect_port_addr);

	return HINIC5_PPF_ELECT_PORT_GET(val, IDX);
}

u32 hinic5_hinic5_get_self_test_result(void *hwdev)
{
	struct hinic5_hwif *hwif = ((struct hinic5_hwdev *)hwdev)->hwif;

	return hinic5_hwif_read_reg(hwif, HINIC5_MGMT_HEALTH_STATUS_ADDR);
}

void hinic5_show_chip_err_info(struct hinic5_hwdev *hwdev)
{
	const enum func_type func_type = hinic5_func_type(hwdev);
	struct hinic5_hwif *hwif = hwdev->hwif;
	u32 value;

	if (func_type != TYPE_PPF && func_type != TYPE_PF)
		return;

	value = hinic5_hwif_read_reg(hwif, HINIC5_CHIP_BASE_INFO_ADDR);
	sdk_warn(hwdev->dev_hdl, "Chip base info: 0x%08x\n", value);

	value = hinic5_hwif_read_reg(hwif, HINIC5_MGMT_HEALTH_STATUS_ADDR);
	sdk_warn(hwdev->dev_hdl, "Mgmt CPU health status: 0x%08x\n", value);

	value = hinic5_hwif_read_reg(hwif, HINIC5_CHIP_ERR_STATUS0_ADDR);
	sdk_warn(hwdev->dev_hdl, "Chip fatal error status0: 0x%08x\n", value);
	value = hinic5_hwif_read_reg(hwif, HINIC5_CHIP_ERR_STATUS1_ADDR);
	sdk_warn(hwdev->dev_hdl, "Chip fatal error status1: 0x%08x\n", value);

	value = hinic5_hwif_read_reg(hwif, HINIC5_ERR_INFO0_ADDR);
	sdk_warn(hwdev->dev_hdl, "Chip exception info0: 0x%08x\n", value);
	value = hinic5_hwif_read_reg(hwif, HINIC5_ERR_INFO1_ADDR);
	sdk_warn(hwdev->dev_hdl, "Chip exception info1: 0x%08x\n", value);
	value = hinic5_hwif_read_reg(hwif, HINIC5_ERR_INFO2_ADDR);
	sdk_warn(hwdev->dev_hdl, "Chip exception info2: 0x%08x\n", value);
}
