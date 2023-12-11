/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __YS_K2_HW_H__
#define __YS_K2_HW_H__

#include <linux/types.h>

#define YSK2_MAX_FRAGS 8
#define YSK2_MAX_MTU 9600

/* ring parameters */
#define YSK2_MAX_RINGS 63
#define YSK2_RING_PTR_MASK 0xffff
#define YSK2_EQ_ENTR_NUM 1024U
#define YSK2_TXQ_ENTR_NUM 1024U
#define YSK2_TXCPL_ENTR_NUM 1024U
#define YSK2_RXQ_ENTR_NUM 1024U
#define YSK2_RXCPL_ENTR_NUM 1024U

#define YSK2_REG_BASE 0x7000000
/* common register */
#define YSK2_FUNC_QREADY (YSK2_REG_BASE + 0x100)
#define YSK2_FUNC_QSTART (YSK2_REG_BASE + 0x104)
#define YSK2_FUNC_QSTOP (YSK2_REG_BASE + 0x108)
#define YSK2_FUNC_ID (YSK2_REG_BASE + 0x120)
#define YSK2_FID_PF GENMASK(7, 0)
#define YSK2_FID_VF GENMASK(31, 16)

/* queue registers */
#define YSK2_CHN_REG_BASE(i) (YSK2_REG_BASE + 0x100000 + (i) * 0x1000)
#define YSK2_CHN_EQ_BASE(i) (YSK2_CHN_REG_BASE(i) + 0x00)
#define YSK2_CHN_TXQ_BASE(i) (YSK2_CHN_REG_BASE(i) + 0x20)
#define YSK2_CHN_TXCQ_BASE(i) (YSK2_CHN_REG_BASE(i) + 0x40)
#define YSK2_CHN_RXQ_BASE(i) (YSK2_CHN_REG_BASE(i) + 0x60)
#define YSK2_CHN_RXCQ_BASE(i) (YSK2_CHN_REG_BASE(i) + 0x80)
#define YSK2_CHN_CONTROL(i) (YSK2_CHN_REG_BASE(i) + 0xa0)
#define YSK2_CHN_ENABLE GENMASK(1, 0)

#define YSK2_QUEUE_BASE_ADDR_LOW 0x00
#define YSK2_QUEUE_BASE_ADDR_HIGH 0x04
#define YSK2_QUEUE_ACTIVE_LOG_SIZE 0x08
#define YSK2_QUEUE_ACTIVE_MASK BIT(31)
#define YSK2_QUEUE_LOG_BLOCK_SIZE_MASK GENMASK(15, 8)
#define YSK2_QUEUE_LOG_QUEUE_SIZE_MASK GENMASK(7, 0)
#define YSK2_QUEUE_TARGET_QUEUE_INDEX 0x0C
#define YSK2_QUEUE_ARM_IRQ_MASK GENMASK(31, 30)
#define YSK2_QUEUE_HEAD_PTR 0x10
#define YSK2_QUEUE_TAIL_PTR 0x18

/* Device queue/vf config registers, pf only */
#define YSK2_CFG_REG_BASE (YSK2_REG_BASE + 0x800000)
#define YSK2_CFG_HWVF_ID(pf_id, vf_base, vf_id) (0x10 + (vf_base) + (vf_id))
#define YSK2_CFG_QREADY(f) (YSK2_CFG_REG_BASE + (f) * 0x10 + 0x00)
#define YSK2_CFG_QSTART(f) (YSK2_CFG_REG_BASE + (f) * 0x10 + 0x04)
#define YSK2_CFG_QSTOP(f) (YSK2_CFG_REG_BASE + (f) * 0x10 + 0x08)
#define YSK2_CFG_VF_START(pf) (YSK2_CFG_REG_BASE + (pf) * 0x10 + 0x10004)
#define YSK2_CFG_VF_STOP(pf) (YSK2_CFG_REG_BASE + (pf) * 0x10 + 0x10008)

/* misc */
#define YSK2_CFG_TX_SCH_ENABLE (YSK2_REG_BASE + 0x81028)
#define YSK2_CFG_IRQ_BASE(hw_vfid) (YSK2_REG_BASE + 0xd10000 + (hw_vfid) * 4)

/* ring entry structure */
#define YSK2_DESC_SIZE 16U
#define YSK2_CPL_SIZE 32U
#define YSK2_EVENT_SIZE 32U
struct ysk2_desc {
	__le32 rsv;
	__le32 len;
	__le64 addr;
};

struct ysk2_cpl {
	__le16 queue; /* source rx/tx queue id */
	__le16 index; /* desc index of src_q */
	__le16 len;
	__le16 rsv1;
	__le32 rsv2[6];
};

struct ysk2_event {
	__le16 type;
	__le16 source; /* source completion queue id */
	__le32 rsv[7];
};

enum ysk2_event_type {
	YSK2_EVENT_TYPE_TX_CPL = 0x0000,
	YSK2_EVENT_TYPE_RX_CPL = 0x0001,
};

#endif /* YS_K2_HW_H */
