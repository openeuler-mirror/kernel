// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/mutex.h>
#include <linux/dinghai/dh_cmd.h>
#include "msg_chan_lock.h"
#include "msg_chan_priv.h"
/**
 * [src/dst]
 * src/dst: TO_RISC, TO_PFVF, TO_MPF
 * MPF:       1         1       1
 * PF:        0         0       1
 * VF:        0         0       1
 */

/*/PF0-7 DIRECT_CHNA/(PF0)VF0-VF32/(PF1)VF0-VF32/...*/
struct mutex lock_array[LOCK_ARR_LENGTH] = { 0 };

u8 lock_type_tbl[BAR_MSG_SRC_NUM][BAR_MSG_DST_NUM] = {
	{ LOCK_TYPE_HARD, LOCK_TYPE_HARD, LOCK_TYPE_HARD },
	{ LOCK_TYPE_HARD, LOCK_TYPE_SOFT, LOCK_TYPE_HARD },
	{ LOCK_TYPE_HARD, LOCK_TYPE_HARD, LOCK_TYPE_HARD }
};

/**
 * @src_pcieid: pcie_id
 */
u16 pcieid_to_lockid(u16 src_pcieid, u8 dst)
{
	u16 lock_id = 0;
	u16 pf_idx = 0;
	u16 vf_idx = 0;
	u16 ep_idx = 0;

	pf_idx = (src_pcieid & PCIEID_PF_IDX_MASK) >> PCIEID_PF_IDX_OFFSET;
	vf_idx = (src_pcieid & PCIEID_VF_IDX_MASK);
	ep_idx = (src_pcieid & PCIEID_EP_IDX_MASK) >> PCIEID_EP_IDX_OFFSET;
	switch (dst) {
	case MSG_CHAN_END_RISC: {
		if (src_pcieid & PCIEID_IS_PF_MASK) {
			lock_id = MULTIPLY_BY_8(ep_idx) + pf_idx;
		} else {
			lock_id = MULTIPLY_BY_256(ep_idx) + MULTIPLY_BY_32(pf_idx) + vf_idx +
				  MULTIPLY_BY_32(1);
		}
		break;
	}
	case MSG_CHAN_END_VF: {
		lock_id = MULTIPLY_BY_8(ep_idx) + pf_idx + MULTIPLY_BY_32(1 + VF_NUM_PER_PF);
		break;
	}
	case MSG_CHAN_END_PF: {
		lock_id = MULTIPLY_BY_8(ep_idx) + pf_idx + MULTIPLY_BY_32(2 + VF_NUM_PER_PF);
		break;
	}
	default: {
		lock_id = 0;
		break;
	}
	}

	if (lock_id >= LOCK_ARR_LENGTH)
		lock_id = 0;

	return lock_id;
}

/**
 * @src_pcieid: pcie_id
 */
u16 pcie_id_to_hard_lock(u16 src_pcieid, u8 dst)
{
	u16 lock_id = 0;
	u16 pf_idx = 0;
	u16 vf_idx = 0;
	u16 ep_idx = 0;

	pf_idx = (src_pcieid & PCIEID_PF_IDX_MASK) >> PCIEID_PF_IDX_OFFSET;
	vf_idx = (src_pcieid & PCIEID_VF_IDX_MASK);
	ep_idx = (src_pcieid & PCIEID_EP_IDX_MASK) >> PCIEID_EP_IDX_OFFSET;

	switch (dst) {
	/* msg to risc*/
	case MSG_CHAN_END_RISC: {
		lock_id = MULTIPLY_BY_8(ep_idx) + pf_idx;
		break;
	}
	/* msg to pf/vf*/
	case MSG_CHAN_END_VF:
	case MSG_CHAN_END_PF:

	{
		lock_id = MULTIPLY_BY_8(ep_idx) + pf_idx + MULTIPLY_BY_8(1 + MAX_EP_NUM);
		break;
	}
	/* default*/
	default: {
		lock_id = 0;
		break;
	}
	}

	if (lock_id >= MAX_HARD_SPINLOCK_NUM)
		lock_id = 0;

	return lock_id;
}

static u8 spinklock_read(void __iomem *virt_lock_addr, u32 lock_id)
{
	return readb((void __iomem *)(virt_lock_addr + lock_id));
}

static void spinlock_write(void __iomem *virt_lock_addr, u32 lock_id, u8 data)
{
	writeb(data, (void __iomem *)(virt_lock_addr + lock_id));
}

static void label_write(void __iomem *label_lock_addr, u32 lock_id, u16 value)
{
	writew(value, (void __iomem *)(label_lock_addr + lock_id * 2));
}

static u16 label_read(void __iomem *label_lock_addr, u32 lock_id)
{
	return readw(label_lock_addr + lock_id * 2);
}

s32 zxdh_spinlock_lock(u32 virt_lock_id, u64 lock_virt_addr, u64 label_addr, u16 masterid)
{
	u8 spl_val = 0;
	u32 lock_rd_cnt = 0;

	do {
		spl_val = spinklock_read((void __iomem *)(uintptr_t)lock_virt_addr, virt_lock_id);
		if (spl_val == 0) {
			label_write((void __iomem *)(uintptr_t)label_addr, virt_lock_id, masterid);
			break;
		}
		lock_rd_cnt++;
		msleep(BAR_CHAN_HARD_LOCK_POLLING_SPAN_MS);
	} while (lock_rd_cnt < MAX_HARD_SPINLOCK_ASK_TIMES);

	if (lock_rd_cnt >= MAX_HARD_SPINLOCK_ASK_TIMES) {
		BAR_LOG_ERR("spl val: 0x%x lock_id:%u, masterID: 0x%x.\n", spl_val, virt_lock_id,
			    label_read((void __iomem *)(uintptr_t)label_addr, virt_lock_id));
		return BAR_MSG_ERR_LOCK_FAILED;
	}

	return 0;
}

s32 zxdh_spinlock_unlock(u32 virt_lock_id, u64 lock_virt_addr, u64 label_addr)
{
	label_write((void __iomem *)(uintptr_t)label_addr, virt_lock_id, 0);
	spinlock_write((void __iomem *)(uintptr_t)lock_virt_addr, virt_lock_id, 0);
	return 0;
}

void bar_soft_lock(u16 src_pcieid, u8 dst)
{
	u16 lockid = 0;

	lockid = pcieid_to_lockid(src_pcieid, dst);
	mutex_lock(&lock_array[lockid]);
}

void bar_soft_unlock(u16 src_pcieid, u8 dst)
{
	u16 lockid = 0;

	lockid = pcieid_to_lockid(src_pcieid, dst);
	mutex_unlock(&lock_array[lockid]);
}

int bar_hard_lock(u16 src_pcieid, u8 dst, u64 chan_virt_addr)
{
	int ret = 0;
	u16 lockid = 0;

	lockid = pcie_id_to_hard_lock(src_pcieid, dst);
	if (dst == MSG_CHAN_END_RISC) {
		ret = zxdh_spinlock_lock(lockid, chan_virt_addr + CHAN_RISC_SPINLOCK_OFFSET,
					 chan_virt_addr + CHAN_RISC_LABEL_OFFSET,
					 src_pcieid | LOCK_MASTER_ID_MASK);
	} else {
		ret = zxdh_spinlock_lock(lockid, chan_virt_addr + CHAN_PFVF_SPINLOCK_OFFSET,
					 chan_virt_addr + CHAN_PFVF_LABEL_OFFSET,
					 src_pcieid | LOCK_MASTER_ID_MASK);
	}
	return ret;
}

void bar_hard_unlock(u16 src_pcieid, u8 dst, u64 chan_virt_addr)
{
	u16 lockid = 0;

	lockid = pcie_id_to_hard_lock(src_pcieid, dst);
	if (dst == MSG_CHAN_END_RISC) {
		zxdh_spinlock_unlock(lockid, chan_virt_addr + CHAN_RISC_SPINLOCK_OFFSET,
				     chan_virt_addr + CHAN_RISC_LABEL_OFFSET);
	} else {
		zxdh_spinlock_unlock(lockid, chan_virt_addr + CHAN_PFVF_SPINLOCK_OFFSET,
				     chan_virt_addr + CHAN_PFVF_LABEL_OFFSET);
	}
}

void bar_init_lock_arr(void)
{
	int idx = 0;

	for (idx = 0; idx < ARR_LEN(lock_array); idx++)
		mutex_init(&lock_array[idx]);
}

int bar_chan_lock(u8 src, u8 dst, u16 src_pcieid, u64 virt_addr)
{
	int ret = 0;
	u16 idx = 0;
	u8 src_index = 0;
	u8 dst_index = 0;

	src_index = bar_msg_row_index_trans(src);
	dst_index = bar_msg_col_index_trans(dst);
	if (src_index == BAR_MSG_SRC_ERR || dst_index == BAR_MSG_DST_ERR) {
		BAR_LOG_ERR("lock ERR: chan doesn't exist.\n");
		return BAR_MSG_ERR_TYPE;
	}
	idx = lock_type_tbl[src_index][dst_index];
	if (idx == LOCK_TYPE_SOFT)
		bar_soft_lock(src_pcieid, dst);
	else
		ret = bar_hard_lock(src_pcieid, dst, virt_addr);

	return ret;
}

int bar_chan_unlock(u8 src, u8 dst, u16 src_pcieid, u64 virt_addr)
{
	u16 idx = 0;
	u8 src_index = 0;
	u8 dst_index = 0;

	src_index = bar_msg_row_index_trans(src);
	dst_index = bar_msg_col_index_trans(dst);
	if (src_index == BAR_MSG_SRC_ERR || dst_index == BAR_MSG_DST_ERR) {
		BAR_LOG_ERR("unlock ERR: chan doesn't exist.\n");
		return BAR_MSG_ERR_TYPE;
	}
	idx = lock_type_tbl[src_index][dst_index];
	if (idx == LOCK_TYPE_SOFT)
		bar_soft_unlock(src_pcieid, dst);
	else
		bar_hard_unlock(src_pcieid, dst, virt_addr);

	return BAR_MSG_OK;
}

int bar_chan_pf_init_spinlock(u16 pcie_id, u64 bar_base_addr)
{
	int lock_id = 0;

	lock_id = pcie_id_to_hard_lock(pcie_id, MSG_CHAN_END_RISC);
	zxdh_spinlock_unlock(lock_id, bar_base_addr + BAR0_SPINLOCK_OFFSET,
			     bar_base_addr + HW_LABEL_OFFSET);
	lock_id = pcie_id_to_hard_lock(pcie_id, MSG_CHAN_END_VF);
	zxdh_spinlock_unlock(lock_id, bar_base_addr + BAR0_SPINLOCK_OFFSET,
			     bar_base_addr + HW_LABEL_OFFSET);
	return 0;
}
EXPORT_SYMBOL(bar_chan_pf_init_spinlock);
