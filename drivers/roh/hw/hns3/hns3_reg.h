/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2020-2022 Hisilicon Limited.
#ifndef __HNS3_ROH_REG_H__
#define __HNS3_ROH_REG_H__

/* CMDq Reg */
#define HNS3_ROH_CMDQ_BASE 0x26000
#define HNS3_ROH_TX_CMDQ_BASEADDR_L_REG (HNS3_ROH_CMDQ_BASE + 0x0)
#define HNS3_ROH_TX_CMDQ_BASEADDR_H_REG (HNS3_ROH_CMDQ_BASE + 0x4)
#define HNS3_ROH_TX_CMDQ_DEPTH_REG (HNS3_ROH_CMDQ_BASE + 0x8)
#define HNS3_ROH_TX_CMDQ_TAIL_REG (HNS3_ROH_CMDQ_BASE + 0x10)
#define HNS3_ROH_TX_CMDQ_HEAD_REG (HNS3_ROH_CMDQ_BASE + 0x14)

#define HNS3_ROH_RX_CMDQ_BASEADDR_L_REG (HNS3_ROH_CMDQ_BASE + 0x18)
#define HNS3_ROH_RX_CMDQ_BASEADDR_H_REG (HNS3_ROH_CMDQ_BASE + 0x1c)
#define HNS3_ROH_RX_CMDQ_DEPTH_REG (HNS3_ROH_CMDQ_BASE + 0x20)
#define HNS3_ROH_RX_CMDQ_TAIL_REG (HNS3_ROH_CMDQ_BASE + 0x24)
#define HNS3_ROH_RX_CMDQ_HEAD_REG (HNS3_ROH_CMDQ_BASE + 0x28)

/* Vector0 interrupt CMDQ event source register(RW) */
#define HNS3_ROH_VECTOR0_CMDQ_SRC_REG (HNS3_ROH_CMDQ_BASE + 0x110)
#define HNS3_ROH_VECTOR0_RX_CMDQ_INT_B 1

#define HNS3_ROH_VECTOR0_INT_CTRL_REG 0x20404

#define hns3_roh_write(dev, reg, val) writel((val), (dev)->reg_base + (reg))
#define hns3_roh_read(dev, reg) readl((dev)->reg_base + (reg))
#define hns3_roh_raw_write(value, addr) \
	__raw_writel((__force u32)cpu_to_le32(value), (addr))

#endif /* __HNS3_ROH_REG_H__ */
