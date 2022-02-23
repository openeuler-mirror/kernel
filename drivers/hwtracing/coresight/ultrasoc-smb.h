/* SPDX-License-Identifier: MIT */
/*
 * Siemens System Memory Buffer driver.
 * Copyright(c) 2021, HiSilicon Limited.
 */

#ifndef _ULTRASOC_SMB_H
#define _ULTRASOC_SMB_H

#include <linux/coresight.h>
#include <linux/list.h>
#include <linux/miscdevice.h>

#include "coresight-etm-perf.h"
#include "coresight-priv.h"

/* Offset of SMB logical buffer registers */
#define SMB_CFG_REG			0X0
#define SMB_GLOBAL_EN			0X4
#define SMB_GLOBAL_INT			0X8
#define SMB_LB_CFG_LO			0X40
#define SMB_LB_CFG_HI			0X44
#define SMB_LB_INT_CTRL			0X48
#define SMB_LB_INT_STS			0X4C
#define SMB_LB_LIMIT			0X58
#define SMB_LB_RD_ADDR			0X5C
#define SMB_LB_WR_ADDR			0X60
#define SMB_LB_PURGE			0X64

/* Set SMB_CFG_REG register */
#define SMB_IDLE_PRD(period)		(((period - 216) & 0xf) << 12)
#define SMB_MEM_WR(credit, rate)	(((credit) << 16) | ((rate) << 18))
#define SMB_MEM_RD(credit, rate)	(((credit) << 22) | ((rate) << 24))
#define SMB_BURST_LEN(len)		((len - 1) << 4)
#define SMB_GLOBAL_CFG			(SMB_IDLE_PRD(231) | SMB_MEM_WR(0x3, 0x0) |   \
					 SMB_MEM_RD(0x3, 0x6) | SMB_BURST_LEN(16))

/* Set SMB_GLOBAL_INT register */
#define SMB_INT_EN			BIT(0)
#define SMB_INT_TYPE_PULSE		BIT(1)
#define SMB_INT_POLARITY_HIGH		BIT(2)
#define SMB_GLB_INT_CFG			(SMB_INT_EN | SMB_INT_TYPE_PULSE | SMB_INT_POLARITY_HIGH)

/* Set SMB_LB_CFG_LO register */
#define SMB_BUF_EN			BIT(0)
#define SMB_BUF_SINGLE_END		BIT(1)
#define SMB_BUF_INIT			BIT(8)
#define SMB_BUF_CONTINUOUS		BIT(11)
#define SMB_FLOW_MASK			GENMASK(19, 16)
#define SMB_BUF_CFG_STREAMING		(SMB_BUF_INIT | SMB_BUF_CONTINUOUS | SMB_FLOW_MASK)
#define SMB_BASE_LOW_MASK		GENMASK(31, 0)

/* Set SMB_LB_CFG_HI register */
#define SMB_MSG_FILTER(lower, upper)	((lower & 0xff) | ((upper & 0xff) << 8))
#define SMB_BUF_INT_EN			BIT(0)
#define SMB_BUF_NOTE_MASK		GENMASK(11, 8)
#define SMB_BUF_INT_CFG			(SMB_BUF_INT_EN | SMB_BUF_NOTE_MASK)

/**
 * struct smb_data_buffer - Details of the buffer used by SMB
 * @buf_base	: Memory mapped base address of SMB.
 * @start_addr	: SMB buffer start Physical address.
 * @buf_size	: Size of the buffer.
 * @data_size	: Size of Trace data copy to userspace.
 * @rd_offset	: Offset of the read pointer in the buffer.
 */
struct smb_data_buffer {
	void __iomem *buf_base;
	u32 start_addr;
	unsigned long buf_size;
	unsigned long data_size;
	unsigned long rd_offset;
};

/**
 * struct smb_drv_data - specifics associated to an SMB component
 * @base:	Memory mapped base address for SMB component.
 * @csdev:	Component vitals needed by the framework.
 * @sdb:	Data buffer for SMB.
 * @miscdev:	Specifics to handle "/dev/xyz.smb" entry.
 * @spinlock:	Only one at a time pls.
 * @reading:	Synchronise user space access to SMB buffer.
 * @pid:	Process ID of the process being monitored by the session
 *		that is using this component.
 * @mode:	how this SMB is being used, perf mode or sysfs mode.
 */
struct smb_drv_data {
	void __iomem *base;
	struct coresight_device	*csdev;
	struct smb_data_buffer sdb;
	struct miscdevice miscdev;
	spinlock_t spinlock;
	local_t reading;
	pid_t pid;
	u32 mode;
};

#define smb_reg(name, offset)  coresight_simple_reg32(struct smb_drv_data, name, offset)

#endif
