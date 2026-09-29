// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include "mce_base.h"
#include "mce.h"
#include "mce_mbx.h"
/* Mailbox ctrl register
 * [31:16]: mask for [15:0], only masked bit will be update
 * [15:0] : value

 * ie:
 * only set bit3 to 1 (4-15,0-2 bit value will be ignored by chip), write ctrl
 * reg ((1 << (16 + 3)) | 1)
 */

/* ==== flags === */
#define MBX_CTRL_REQ_IRQ_MSK BIT(0) /* WO */
#define MBX_CTRL_FW_HOLD_PF_SHM_MSK BIT(2) /* PFU:RO, CFU:WR */
#define MBX_CTRL_FW_HOLD_PF_SHM BIT(2) /* PFU:RO, CFU:WR */
#define MBX_CTRL_FW_HOLD_VF_SHM_MSK BIT(3) /* CFU:RW, VFU:RO */
#define MBX_CTRL_FW_HOLD_VF_SHM BIT(3) /* CFU:RW, VFU:RO */
#define MBX_CTRL_IRQ_MSK BIT(4)

/* === PF2FW MBX FLAGS == */
#define MBX_CTRL_PF2FW_REQ_STAT_SHIFT (5)
#define MBX_CTRL_PF2FW_REQ_STAT_MSK (0b11 << MBX_CTRL_PF2FW_REQ_STAT_SHIFT)
#define MBX_CTRL_PF2FW_STAT_VALID_SHIFT 7
#define MBX_CTRL_PF2FW_STAT_VALID_MSK BIT(MBX_CTRL_PF2FW_STAT_VALID_SHIFT)
#define MBX_CTRL_PF2FW_STAT_VALID MBX_CTRL_PF2FW_STAT_VALID_MSK
#define MBX_CTRL_PF2FW_LINK_STAT_SHIFT (8)
#define MBX_CTRL_PF2FW_LINK_STAT_MSK BIT(MBX_CTRL_PF2FW_LINK_STAT_SHIFT)
#define MBX_CTRL_FW2PF_LINK_CHANG_NOTIFY_EN_SHIFT 10
#define MBX_CTRL_FW2PF_LINK_CHANG_NOTIFY_MSK \
	BIT(MBX_CTRL_FW2PF_LINK_CHANG_NOTIFY_EN_SHIFT)
#define MBX_CTRL_FW2PF_SFP_PLUG_NOTIFY_EN_SHIFT 11
#define MBX_CTRL_FW2PF_SFP_PLUG_NOTIFY_MSK \
	BIT(MBX_CTRL_FW2PF_SFP_PLUG_NOTIFY_EN_SHIFT)
#define MBX_CTRL_PF2FW_EVENT_ID_SHIFT (12)
#define MBX_CTRL_PF2FW_EVENT_ID_MASK (0b1111 << MBX_CTRL_PF2FW_EVENT_ID_SHIFT)
#define MBX_CTRL_GET_PF2FW_EVENT_ID(v) \
	(((v) & MBX_CTRL_PF2FW_EVENT_ID_MASK) >> MBX_CTRL_PF2FW_EVENT_ID_SHIFT)
#define MBX_CTRL_GET_PF2FW_REQ_STAT(v) \
	(((v) & MBX_CTRL_PF2FW_REQ_STAT_MSK) >> MBX_CTRL_PF2FW_REQ_STAT_SHIFT)

/* === FW2PF MBX CTRL == */
#define MBX_CTRL_FW2PF_REQ_STAT_SHIFT (5)
#define MBX_CTRL_FW2PF_REQ_STAT_MSK (0b11 << MBX_CTRL_FW2PF_REQ_STAT_SHIFT)
#define MBX_CTRL_FW2PF_STAT_VALID_MSK BIT(7)
#define MBX_CTRL_FW2PF_STAT_VALID BIT(7)
#define MBX_CTRL_FW2PF_FW_LINKUP_MSK BIT(8)
#define MBX_CTRL_FW2PF_FW_NIC_RESET_DONE_MSK BIT(9)
#define MBX_CTRL_FW2PF_NR_PF_MSK BIT(10)
#define MBX_CTRL_FW2PF_EVENT_ID_SHIFT (12)
#define MBX_CTRL_FW2PF_EVENT_ID_MASK (0b1111 << MBX_CTRL_FW2PF_EVENT_ID_SHIFT)
#define MBX_CTRL_GET_FW2PF_EVENT_ID(v) \
	(((v) & MBX_CTRL_FW2PF_EVENT_ID_MASK) >> MBX_CTRL_FW2PF_EVENT_ID_SHIFT)
#define MBX_CTRL_GET_FW2PF_REQ_STAT(v) \
	(((v) & MBX_CTRL_FW2PF_REQ_STAT_MSK) >> MBX_CTRL_FW2PF_REQ_STAT_SHIFT)

#define MBX_IRQ_EN (0 << 4)
#define MBX_IRQ_DISABLE BIT(4)

/* ==== PF2VF MBX FLAGS == */
#define MBX_CTRL_PF2VF_REQ_STAT_SHIFT (5)
#define MBX_CTRL_PF2VF_REQ_STAT_MSK (0b11 << MBX_CTRL_PF2VF_REQ_STAT_SHIFT)
#define MBX_CTRL_PF2VF_STAT_VALID_SHIFT 7
#define MBX_CTRL_PF2VF_STAT_VALID_MSK BIT(MBX_CTRL_PF2VF_STAT_VALID_SHIFT)
#define MBX_CTRL_PF2VF_STAT_VALID MBX_CTRL_PF2VF_STAT_VALID_MSK
#define MBX_CTRL_PF2VF_LINK_STAT_SHIFT 8
#define MBX_CTRL_PF2VF_LINK_STAT_MSK BIT(MBX_CTRL_PF2VF_LINK_STAT_SHIFT)
#define MBX_CTRL_PF2VF_SPEED_SHIFT 9
#define MBX_CTRL_PF2VF_PF_SPEED_MSK GENMASK(11, MBX_CTRL_PF2VF_SPEED_SHIFT)
#define MBX_CTRL_PF2VF_EVENT_ID_SHIFT (12)
#define MBX_CTRL_PF2VF_EVENT_ID_MASK (0b1111 << MBX_CTRL_PF2VF_EVENT_ID_SHIFT)
#define MBX_CTRL_GET_PF2VF_EVENT_ID(v) \
	(((v) & MBX_CTRL_PF2VF_EVENT_ID_MASK) >> MBX_CTRL_PF2VF_EVENT_ID_SHIFT)
#define MBX_CTRL_GET_PF2VF_REQ_STAT(v) \
	(((v) & MBX_CTRL_PF2VF_REQ_STAT_MSK) >> MBX_CTRL_PF2VF_REQ_STAT_SHIFT)

/* === VF2PF MBX CTRL == */
#define MBX_CTRL_VF2PF_REQ_ST_CLR_SHIFT 5
#define MBX_CTRL_VF2PF_REQ_ST_CLR_MSK BIT(MBX_CTRL_VF2PF_REQ_ST_CLR_SHIFT)
#define MBX_CTRL_VF2PF_REQ_STAT_SHIFT (6)
#define MBX_CTRL_VF2PF_REQ_STAT_MSK (0b11 << MBX_CTRL_VF2PF_REQ_STAT_SHIFT)
#define MBX_CTRL_VF2PF_STAT_VALID_MSK BIT(8)
#define MBX_CTRL_VF2PF_STAT_VALID MBX_CTRL_VF2PF_STAT_VALID_MSK
#define MBX_CTRL_VF2PF_RESET_DONE_SHIFT (9)
#define MBX_CTRL_VF2PF_RESET_DONE_MSK BIT(MBX_CTRL_VF2PF_RESET_DONE_SHIFT)
#define MBX_CTRL_VF2PF_MBX_INIT_DONE_SHIFT 10
#define MBX_CTRL_VF2PF_MBX_INIT_DONE_MSK BIT(MBX_CTRL_VF2PF_MBX_INIT_DONE_SHIFT)
#define MBX_CTRL_VF2PF_EVENT_ID_SHIFT (13)
#define MBX_CTRL_VF2PF_EVENT_ID_MASK (0b111 << MBX_CTRL_VF2PF_EVENT_ID_SHIFT)
#define MBX_CTRL_GET_VF2PF_EVENT_ID(v) \
	(((v) & MBX_CTRL_VF2PF_EVENT_ID_MASK) >> MBX_CTRL_VF2PF_EVENT_ID_SHIFT)
#define MBX_CTRL_GET_VF2PF_REQ_STAT(v) \
	(((v) & MBX_CTRL_VF2PF_REQ_STAT_MSK) >> MBX_CTRL_VF2PF_REQ_STAT_SHIFT)

#define MBX_SEND_REQ_WITH_IRQ BIT(0)

#define mbx_rd32(reg) raw_rd32((reg))
#define mbx_wr32(reg, val) raw_wr32((val), (reg))
#define mbx_wr32_masked(reg, mask16, val16) \
	raw_wr32((val16) | ((mask16) << 16), (reg))

void mce_mbx_clear_peer_req_irq_with_stat(struct mce_mbx_info *mbx,
					  enum MBX_REQ_STAT stat)
{
	u32 mask;
	u32 val;

	if (mbx->is_vf_mbx) {
		mask = MBX_CTRL_VF2PF_REQ_STAT_MSK | MBX_CTRL_REQ_IRQ_MSK;
		val = (stat << MBX_CTRL_VF2PF_REQ_STAT_SHIFT) | 0;
	} else {
		mask = MBX_CTRL_FW2PF_REQ_STAT_MSK | MBX_CTRL_REQ_IRQ_MSK;
		val = (stat << MBX_CTRL_FW2PF_REQ_STAT_SHIFT) | 0;
	}
	mbx_wr32_masked(mbx->peer2pf_ctrl, mask, val);
}

void mce_mbx_clear_peer_req_irq_with_no_stat_change(struct mce_mbx_info *mbx)
{
	mbx_wr32_masked(mbx->peer2pf_ctrl, MBX_CTRL_REQ_IRQ_MSK, 0);
}

static inline int mce_mbx_get_req_shm_lock(struct mce_mbx_info *mbx,
					   int timeout_us)
{
	while (1) {
		mbx_wr32_masked(mbx->pf2peer_shm_lock,
				mbx->pf2peer_shm_lock_msk,
				mbx->pf2peer_shm_lock_msk);
		/* Ensure the lock request is visible before checking ownership. */
		mb();
		if (mbx_rd32(mbx->pf2peer_shm_lock) &
		    mbx->pf2peer_shm_lock_msk) {
			return 0;
		}

		if (timeout_us > 0) {
			udelay(1);
			timeout_us--;
		} else {
			break;
		}
	}

	return -ETIMEDOUT;
}

static void mce_mbx_put_req_shm_lock(struct mce_mbx_info *mbx)
{
	mbx_wr32_masked(mbx->pf2peer_shm_lock, mbx->pf2peer_shm_lock_msk, 0);
}

static int mce_mbx_get_peer_shm_lock(struct mce_mbx_info *mbx, int timeout_us)
{
	while (1) {
		mbx_wr32_masked(mbx->peer2pf_shm_lock,
				mbx->peer2pf_shm_lock_msk,
				mbx->peer2pf_shm_lock_msk);
		/* Ensure the lock request is visible before checking ownership. */
		mb();
		if (mbx_rd32(mbx->peer2pf_shm_lock) &
		    mbx->peer2pf_shm_lock_msk) {
			return 0;
		}

		if (timeout_us > 0) {
			udelay(1);
			timeout_us--;
		} else {
			break;
		}
	}

	return -ETIMEDOUT;
}

static inline void mce_mbx_put_peer_shm_lock(struct mce_mbx_info *mbx)
{
	mbx_wr32_masked(mbx->peer2pf_shm_lock, mbx->peer2pf_shm_lock_msk, 0);
}

int mce_mbx_init_configure(struct mce_mbx_info *mbx)
{
	int i;

	mbx_wr32_masked(mbx->pf2peer_ctrl, 0xffff, 0);
	/* disable vf/fw mbx irq to pf */
	if (mbx->irq_enabled) {
		mbx_wr32_masked(mbx->peer2pf_ctrl, MBX_CTRL_IRQ_MSK,
				MBX_IRQ_EN);
	} else {
		mbx_wr32_masked(mbx->peer2pf_ctrl, MBX_CTRL_IRQ_MSK,
				MBX_IRQ_DISABLE);
	}

	/* clear req-shm to 0 */
	for (i = 0; i < mbx->req_shm_size / 4; i++)
		mbx_wr32(mbx->pf2peer_shm + i * 4, 0);

	/* release pf to vf/fw shm lock (if have) */
	mbx_wr32_masked(mbx->pf2peer_shm_lock, mbx->pf2peer_shm_lock_msk, 0);
	mbx_wr32(mbx->pf2peer_shm, 0);

	/* release vf/fw to pf shm lock (if have) */
	mbx_wr32_masked(mbx->peer2pf_shm_lock, mbx->peer2pf_shm_lock_msk, 0);

	return 0;
}

void mce_mbx_reset(struct mce_hw *hw)
{
	int i;

	mce_mbx_init_configure(&hw->fw_mbx);

	for (i = 0; i < hw->num_vfs; i++)
		mce_mbx_init_configure(&hw->vf_mbx[i]);
}

int mce_mbx_vector_set(struct mce_mbx_info *mbx, int nr_vector, bool enable)
{
	mbx_logd(LOG_MISC_IRQ, "%s: %s vector:%d enable:%d\n", __func__,
		 mbx->name, nr_vector, enable);
	if (enable) {
		mbx_wr32(mbx->mbx_vec_base, nr_vector);
		mbx_wr32_masked(mbx->peer2pf_ctrl, MBX_CTRL_IRQ_MSK,
				MBX_IRQ_EN);
		mbx->irq_enabled = true;
	} else {
		mbx_wr32_masked(mbx->peer2pf_ctrl, MBX_CTRL_IRQ_MSK,
				MBX_IRQ_DISABLE);
		mbx->irq_enabled = false;
	}

	mce_mbx_set_pf_stat_reg(mbx->hw);
	return 0;
}

int mce_mbx_send_event(struct mce_mbx_info *mbx, int event_id, int timeout_us)
{
	int need_lock = (timeout_us > 0) ? 1 : 0;
	int ret = 0;
	u32 mask;
	u32 val;

#define __MCE_MBX_EVENT_DELAY_STEP_US 10
	timeout_us = round_up(timeout_us, __MCE_MBX_EVENT_DELAY_STEP_US);
	if (need_lock)
		mutex_lock(&mbx->req_lock);

	if (mbx->is_vf_mbx) {
		mask = MBX_CTRL_PF2VF_EVENT_ID_MASK |
		       MBX_CTRL_PF2VF_REQ_STAT_MSK | MBX_CTRL_REQ_IRQ_MSK;
		val = (event_id << MBX_CTRL_PF2VF_EVENT_ID_SHIFT) |
		      (EVENT_REQ << MBX_CTRL_PF2VF_REQ_STAT_SHIFT) |
		      MBX_SEND_REQ_WITH_IRQ;
	} else {
		mask = MBX_CTRL_PF2FW_EVENT_ID_MASK |
		       MBX_CTRL_PF2FW_REQ_STAT_MSK | MBX_CTRL_REQ_IRQ_MSK;
		val = (event_id << MBX_CTRL_PF2FW_EVENT_ID_SHIFT) |
		      (EVENT_REQ << MBX_CTRL_PF2FW_REQ_STAT_SHIFT) |
		      MBX_SEND_REQ_WITH_IRQ;
	}
	mbx_wr32_masked(mbx->pf2peer_ctrl, mask, val);

	mbx->stats.tx_event_cnt++;

	if (timeout_us == 0) {
		ret = 0;
		goto quit;
	}

	/* wait ack */
	ret = -ETIMEDOUT;
	while (timeout_us > 0) {
		u32 v = mbx_rd32(mbx->pf2peer_ctrl);
		int stat;

		if (mbx->is_vf_mbx)
			stat = MBX_CTRL_GET_PF2VF_REQ_STAT(v);
		else
			stat = MBX_CTRL_GET_PF2FW_REQ_STAT(v);
		if (stat != EVENT_REQ) {
			if (stat == RESP_OR_ACK)
				ret = 0;
			else
				ret = -EIO;
			break;
		}
		if (!mce_context_can_sleep())
			udelay(__MCE_MBX_EVENT_DELAY_STEP_US);
		else
			usleep_range(__MCE_MBX_EVENT_DELAY_STEP_US,
				     __MCE_MBX_EVENT_DELAY_STEP_US);
		timeout_us -= __MCE_MBX_EVENT_DELAY_STEP_US;
	}

	if (ret != 0)
		mbx->stats.tx_event_err_cnt++;

quit:
	if (need_lock)
		mutex_unlock(&mbx->req_lock);

	return ret;
}

int mce_mbx_send_resp_isr(struct mce_mbx_info *mbx, struct mbx_resp *resp)
{
	enum MBX_REQ_STAT stat = RESP_OR_ACK;
	int i, total_sz, ret = 0;

	if (!mbx || !resp || !in_interrupt()) {
		dev_err(mbx->hw->dev,
			"%s:%s should be called in interrupt ctx. opcode:%d arg_cnt:%d\n",
			__func__, mbx->name, resp->cmd.opcode,
			resp->cmd.arg_cnts);
		stat = HAS_ERR;
		ret = -EINVAL;
		goto quit;
	}

	/* no lock needed, as can only be called from irq handler */
	if (!resp->cmd.flag_no_resp) {
		total_sz = resp->cmd.arg_cnts * 4 +
			   offsetof(struct mbx_resp, data);
		if (total_sz > mbx->peer_shm_size) {
			dev_err(mbx->hw->dev,
				"%s:%s opcode:%d  total_sz:%d > max size:%d\n",
				__func__, mbx->name, resp->cmd.opcode, total_sz,
				mbx->peer_shm_size);
			stat = HAS_ERR;
			ret = -EINVAL;
			goto quit;
		}

		if (logd_if(LOG_MBX_IN_REQ)) {
			mbx_logd(LOG_MBX_IN_REQ, "== %s shm:0x%x==\n", mbx->name,
				 (int)mbx_info_reg_bar_off(mbx, mbx->peer2pf_shm));
			print_hex_dump(KERN_CONT,
				       "req-in-resp: ", DUMP_PREFIX_OFFSET, 16,
				       1, (char *)resp, total_sz, false);
		}

		if (mce_mbx_get_peer_shm_lock(mbx, 200) < 0) { /* 200us */
			dev_err(mbx->hw->dev,
				"%s:%s get resp shm lock timeout.opcode:%d\n",
				__func__, mbx->name, resp->cmd.opcode);
			mbx->stats.rx_resp_shm_lock_timeout++;
			stat = HAS_ERR;
			ret = -ETIMEDOUT;
			goto quit;
		}

		for (i = 0; i < total_sz / 4; i++)
			mbx_wr32(mbx->peer2pf_shm + i * 4, ((int *)resp)[i]);
		/* Ensure response data is visible before releasing the shared-memory lock. */
		mb();
		mce_mbx_put_peer_shm_lock(mbx);
	}
quit:
	mce_mbx_clear_peer_req_irq_with_stat(mbx, stat);

	return ret;
}

static int mce_mbx_read_incoming_req_isr(struct mce_mbx_info *mbx,
					 struct mbx_req *req)
{
	unsigned int *req_arr = (unsigned int *)req;
	unsigned long flags;
	int total_sz, i;

	if (!req || !mbx)
		return -EINVAL;

	if (mce_mbx_get_peer_shm_lock(mbx, 200) < 0) { /* 200us */
		dev_err(mbx->hw->dev, "%s:%s get req shm lock timeout\n",
			__func__, mbx->name);
		mbx->stats.rx_req_shm_lock_timeout++;
		return -ETIMEDOUT;
	}

	req_arr[0] = mbx_rd32(mbx->peer2pf_shm);
	/* Ensure the request header read completes before accessing its fields. */
	rmb();
	if (req->cmd.arg_cnts > (sizeof(req->data) / 4) ||
	    req->cmd.arg_cnts > (mbx->peer_shm_size / 4)) {
		dev_err(mbx->hw->dev,
			"%s:%s opcode req hdr arg_cnts:%d, cmd:0x%x error!\n",
			__func__, mbx->name, req->cmd.arg_cnts, req->cmd.v);
		mce_mbx_put_peer_shm_lock(mbx);
		return -EIO;
	}

	total_sz = offsetof(struct mbx_req, data) + req->cmd.arg_cnts * 4;

	/* disable irq && schedule */
	spin_lock_irqsave(&mbx->peer_shm_lock, flags);
	for (i = 0; i < total_sz / 4; i++)
		req_arr[i] = mbx_rd32(mbx->peer2pf_shm + i * 4);
	/* Ensure all request data reads complete before clearing the opcode. */
	rmb();
	/* set to 0 */
	mbx_wr32(mbx->peer2pf_shm + 0, 0);
	/* Ensure the opcode clear is visible before releasing the lock. */
	mb();
	mce_mbx_put_peer_shm_lock(mbx);
	spin_unlock_irqrestore(&mbx->peer_shm_lock, flags);

	if (logd_if(LOG_MBX_IN_REQ)) {
		mbx_logd(LOG_MBX_IN_REQ, "== %s ==\n", mbx->name);
		print_hex_dump(KERN_CONT, "req-in: ", DUMP_PREFIX_OFFSET, 16, 1,
			       req, total_sz, false);
	}

	return total_sz;
}

int mce_mbx_clean_all_incoming_req(struct mce_hw *hw,
				   mbx_event_req_cb *event_cb,
				    mbx_req_with_data_cb *req_cb)
{
	volatile unsigned int vf_req_status[4] = {};
	unsigned int i, v, stat, mbx_cnt = 0;
	struct mce_mbx_info *mbx;

	if (!event_cb || !hw || !req_cb)
		return -EINVAL;

	if (hw->num_vfs > 0) {
		for (i = 0; i < ARRAY_SIZE(vf_req_status); i++) {
			vf_req_status[i] =
				mbx_rd32(hw->fw_mbx.vf2pf_irq_stat + i * 4);
		}
	}

	/* PF2FW mailbox first */
	hw->irq_valid_mbxs[mbx_cnt++] = &hw->fw_mbx;
	hw_logd(LOG_MBX_IN_REQ, "vf_req_st:%08x %08x %08x %08x\n",
		vf_req_status[0], vf_req_status[1], vf_req_status[2],
		vf_req_status[3]);

	/* + PF2VF mailbox(if have req) */
	for (i = 0; i < hw->num_vfs; i++) {
		if (test_bit(i, (const volatile unsigned long *)
					vf_req_status)) { /* check if vf has req */
			hw->irq_valid_mbxs[mbx_cnt++] = &hw->vf_mbx[i];
			/* clear st irq */
			mbx_wr32_masked(hw->vf_mbx[i].peer2pf_ctrl,
					MBX_CTRL_VF2PF_REQ_ST_CLR_MSK,
					MBX_CTRL_VF2PF_REQ_ST_CLR_MSK);
			/* Ensure the status-clear write completes before restoring the mask. */
			mb();
			mbx_wr32_masked(hw->vf_mbx[i].peer2pf_ctrl,
					MBX_CTRL_VF2PF_REQ_ST_CLR_MSK, 0);
		}
	}

	for (i = 0; i < mbx_cnt; i++) {
		mbx = hw->irq_valid_mbxs[i];

		v = mbx_rd32(mbx->peer2pf_ctrl);
		if (mbx->is_vf_mbx)
			stat = MBX_CTRL_GET_VF2PF_REQ_STAT(v);
		else
			stat = MBX_CTRL_GET_FW2PF_REQ_STAT(v);

		if (stat == EVENT_REQ) {
			int event_id;

			if (mbx->is_vf_mbx)
				event_id = MBX_CTRL_GET_VF2PF_EVENT_ID(v);
			else
				event_id = MBX_CTRL_GET_FW2PF_EVENT_ID(v);
			mce_mbx_clear_peer_req_irq_with_stat(mbx, RESP_OR_ACK);
			hw_logd(LOG_MBX_IN_REQ, "%s: get event:%d\n", mbx->name,
				event_id);
			event_cb(mbx, event_id);
		} else if (stat == REQ_WITH_DATA) {
			struct mbx_req req = {};

			int total_size =
				mce_mbx_read_incoming_req_isr(mbx, &req);
			if (total_size < 0) {
				mce_mbx_clear_peer_req_irq_with_stat(mbx,
								     HAS_ERR);
			} else {
				req_cb(mbx, &req);
			}
		}
	}
	return 0;
}

int mce_mbx_req_read_resp_out(struct mce_mbx_info *mbx, struct mbx_resp *resp)
{
	unsigned int *resp_arr = (unsigned int *)resp;
	unsigned long flags;
	int total_sz, i;

	if (!resp)
		return -EINVAL;

	resp_arr[0] = mbx_rd32(mbx->pf2peer_shm);
	/* Ensure the response header read completes before accessing its fields. */
	rmb();
	if (resp->cmd.arg_cnts > (sizeof(resp->data) / 4) ||
	    resp->cmd.arg_cnts > (mbx->req_shm_size / 4)) {
		dev_err(mbx->hw->dev,
			"%s: opcode resp hdr arg_cnts:%d, 0x%x error!\n",
			__func__, resp->cmd.arg_cnts, resp->cmd.v);
		return -EIO;
	}

	total_sz = offsetof(struct mbx_resp, data) + resp->cmd.arg_cnts * 4;

	if (mce_mbx_get_req_shm_lock(mbx, 1000) < 0) { /* 1ms */
		dev_err(mbx->hw->dev, "%s: get req shm lock timeout\n",
			__func__);
		mbx->stats.tx_shm_lock_timeout++;
		return -ETIMEDOUT;
	}
	/* disable irq && schedule after get mbx share memory hw-lock */
	spin_lock_irqsave(&mbx->req_shm_lock, flags);
	for (i = 1; i < total_sz / 4; i++)
		resp_arr[i] = mbx_rd32(mbx->pf2peer_shm + i * 4);
	/* Ensure all response data reads complete before clearing the opcode. */
	rmb();
	mbx_wr32(mbx->pf2peer_shm + 0, 0); /* clear opcode */
	mb();
	mce_mbx_put_req_shm_lock(mbx);
	spin_unlock_irqrestore(&mbx->req_shm_lock, flags);

	if (logd_if(LOG_MBX_REQ_OUT)) {
		mbx_logd(LOG_MBX_REQ_OUT, "== %s ==\n", mbx->name);
		print_hex_dump(KERN_CONT, "req-resp: ", DUMP_PREFIX_OFFSET, 16,
			       1, resp_arr, total_sz, false);
	}

	return total_sz;
}

int mce_mbx_send_req(struct mce_mbx_info *mbx, int opcode, int *data,
		     int data_bytes, struct mbx_resp *resp, int timeout_us)
{
	int i, total_sz = data_bytes + offsetof(struct mbx_req, data);
	struct mbx_req req = {};
	int ret = 0, err = 0;
	unsigned long flags;
	u32 mask;
	u32 val;

	if (total_sz > mbx->req_shm_size) {
		dev_err(mbx->hw->dev,
			"%s:%s opcode:0x%x data_bytes:%d > max_size:%d\n",
			__func__, mbx->name, opcode, data_bytes,
			mbx->req_shm_size);
		return -EINVAL;
	}
	req.cmd.opcode = opcode;
	req.cmd.arg_cnts = round_up(data_bytes, 4) / 4;
	req.cmd.flag_pf2peer_req = 1;
	memcpy(req.data, data, data_bytes);

	if (!resp)
		req.cmd.flag_no_resp = 1;

	if (logd_if(LOG_MBX_REQ_OUT)) {
		mbx_logd(LOG_MBX_REQ_OUT, "== %s opcode:%d ==\n", mbx->name,
			 opcode);
		print_hex_dump(KERN_CONT, "req: ", DUMP_PREFIX_OFFSET, 16, 1,
			       &req, total_sz, false);
	}

	/* send req */
	mutex_lock(&mbx->req_lock);

	if (mce_mbx_get_req_shm_lock(mbx, 1000) < 0) { /* 1ms */
		dev_err(mbx->hw->dev,
			"%s:%s opcode:0x%x get req shm lock timeout\n",
			__func__, mbx->name, opcode);
		ret = -ETIMEDOUT;
		mbx->stats.tx_shm_lock_timeout++;
		goto quit;
	}
	/* disable irq && schedule after get mbx share memory hw-lock */
	spin_lock_irqsave(&mbx->req_shm_lock, flags);
	for (i = 0; i < total_sz / 4; i++)
		mbx_wr32(mbx->pf2peer_shm + i * 4, ((int *)&req)[i]);
	mce_mbx_put_req_shm_lock(mbx);
	spin_unlock_irqrestore(&mbx->req_shm_lock, flags);

	/* Ensure request data is visible before notifying the peer. */
	mb();
	/* send req with irq to peer */
	if (mbx->is_vf_mbx) {
		mask = MBX_CTRL_PF2VF_REQ_STAT_MSK | MBX_CTRL_REQ_IRQ_MSK;
		val = (REQ_WITH_DATA << MBX_CTRL_PF2VF_REQ_STAT_SHIFT) |
		      MBX_SEND_REQ_WITH_IRQ;
	} else {
		mask = MBX_CTRL_PF2FW_REQ_STAT_MSK | MBX_CTRL_REQ_IRQ_MSK;
		val = (REQ_WITH_DATA << MBX_CTRL_PF2FW_REQ_STAT_SHIFT) |
		      MBX_SEND_REQ_WITH_IRQ;
	}
	mbx_wr32_masked(mbx->pf2peer_ctrl, mask, val);
	mbx->stats.tx_req_cnt++;

	/* Ensure the request notification reaches the peer before polling. */
	mb();

	if (timeout_us == 0) {
		ret = 0;
		goto quit;
	}

	ret = -ETIMEDOUT;
	/* wait response or ack */
	while (timeout_us > 0) {
		u32 v = mbx_rd32(mbx->pf2peer_ctrl);
		int stat;

		if (mbx->is_vf_mbx)
			stat = MBX_CTRL_GET_PF2VF_REQ_STAT(v);
		else
			stat = MBX_CTRL_GET_PF2FW_REQ_STAT(v);
		if (stat != REQ_WITH_DATA) {
			ret = 0;
			if (stat == RESP_OR_ACK) {
				if (resp) {
					err = mce_mbx_req_read_resp_out(mbx,
									resp);
					if (err > 0 &&
					    resp->cmd.opcode != opcode) {
						dev_err(mbx->hw->dev,
							"%s:%s resp->opcode:0x%x != opencode:%d\n",
							__func__, mbx->name,
							resp->cmd.opcode,
							opcode);
						ret = -EIO;
					}
					if (resp->cmd.err_code != 0) {
						ret = resp->cmd.err_code;
						dev_err(mbx->hw->dev,
							"%s:%s resp->err_code: 0x%x\n",
							__func__, mbx->name,
							ret);
					}
				}
			} else {
				ret = -EIO;
				dev_err(mbx->hw->dev,
					"%s:%s stat:%d != RESP_OR_ACK v:0x%x\n",
					__func__, mbx->name, stat, v);
			}
			break;
		}

		if (!mce_context_can_sleep())
			udelay(10);
		else
			usleep_range(10, 10);
		timeout_us -= 10;
	}

quit:
	mutex_unlock(&mbx->req_lock);

	return ret;
}

void mce_mbx_set_pf_stat_vf(struct mce_mbx_info *vf_mbx)
{
	int pf_speed = speed_zip_to_bit3(vf_mbx->hw->port_info->link_speed);
	int stat_valid = MBX_CTRL_PF2VF_STAT_VALID;
	struct mce_pf *pf = vf_mbx->hw->back;
	bool pf_netdev_is_linkup = false;
	int mask, val;

	/* driver removing, status is invalid */
	if (test_bit(MCE_REMOVED, pf->state))
		stat_valid = 0;

	pf_netdev_is_linkup = is_eth_carrier_ok(vf_mbx->hw);

	mask = MBX_CTRL_PF2VF_STAT_VALID_MSK | MBX_CTRL_PF2VF_LINK_STAT_MSK |
	       MBX_CTRL_PF2VF_PF_SPEED_MSK;
	val = stat_valid |
	      (pf_netdev_is_linkup << MBX_CTRL_PF2VF_LINK_STAT_SHIFT) |
	      (pf_speed << MBX_CTRL_PF2VF_SPEED_SHIFT);

	mbx_wr32_masked(vf_mbx->pf2peer_ctrl, mask, val);
}

void mce_mbx_set_pf_stat_fw(struct mce_mbx_info *fw_mbx)
{
	int stat_valid = MBX_CTRL_PF2FW_STAT_VALID; /* default valid */
	struct mce_pf *pf = fw_mbx->hw->back;
	bool pf_netdev_is_linkup = false;
	int mask, val;

	/* driver removing, status is invalid */
	if (test_bit(MCE_REMOVED, pf->state))
		stat_valid = 0;

	pf_netdev_is_linkup = is_eth_carrier_ok(fw_mbx->hw);

	/* update pf2hw status */
	mask = MBX_CTRL_PF2FW_STAT_VALID_MSK | MBX_CTRL_PF2FW_LINK_STAT_MSK |
	       MBX_CTRL_FW2PF_LINK_CHANG_NOTIFY_MSK |
	       MBX_CTRL_FW2PF_SFP_PLUG_NOTIFY_MSK;
	val = stat_valid |
	      (pf_netdev_is_linkup << MBX_CTRL_PF2FW_LINK_STAT_SHIFT) |
	      (fw_mbx->fw2pf_link_change_notify_en
	       << MBX_CTRL_FW2PF_LINK_CHANG_NOTIFY_EN_SHIFT) |
	      (fw_mbx->fw2pf_sfp_pluginout_notify_en
	       << MBX_CTRL_FW2PF_SFP_PLUG_NOTIFY_EN_SHIFT);
	mbx_wr32_masked(fw_mbx->pf2peer_ctrl, mask, val);
}

/* Update PF write status register. */
int mce_mbx_set_pf_stat_reg(struct mce_hw *hw)
{
	int vf;

	/* update pf2fw status */
	mce_mbx_set_pf_stat_fw(&hw->fw_mbx);

	/*  update pf2vf status */
	for (vf = 0; vf < hw->num_vfs; vf++)
		mce_mbx_set_pf_stat_vf(&hw->vf_mbx[vf]);
	return 0;
}

void mce_mbx_clear_fw_nic_reset_done_flag(struct mce_mbx_info *fw_mbx)
{
	mbx_wr32_masked(fw_mbx->peer2pf_ctrl,
			MBX_CTRL_FW2PF_FW_NIC_RESET_DONE_MSK, 0);
}

void mce_mbx_send_nic_reset_event_to_fw(struct mce_hw *hw)
{
	struct mce_mbx_info *fw_mbx = &hw->fw_mbx;

	mce_mbx_clear_fw_nic_reset_done_flag(fw_mbx);
	mce_mbx_send_event(fw_mbx, EVT_NIC_RESET, 200);
}

int mce_mbx_get_fw_stat(struct mce_mbx_info *fw_mbx, enum MBX_FW_STAT stat)
{
	int v = mbx_rd32(fw_mbx->peer2pf_ctrl);

	if (!(v & MBX_CTRL_FW2PF_STAT_VALID_MSK)) {
		dev_err(fw_mbx->hw->dev,
			"%s:%s FW2PF_STAT not valid: 0x%x[7]\n", __func__,
			fw_mbx->name, v);
		return -EIO;
	}

	switch (stat) {
	case FW_LINK_STAT:
		return !!(v & MBX_CTRL_FW2PF_FW_LINKUP_MSK);
	case FW_NIC_RESET_DONE_STAT:
		return !!(v & MBX_CTRL_FW2PF_FW_NIC_RESET_DONE_MSK);
	case FW_NR_PF:
		return !!(v & MBX_CTRL_FW2PF_NR_PF_MSK);
	}
	return -EINVAL;
}

int mce_mbx_get_vf_stat(struct mce_mbx_info *vf_mbx, enum MBX_VF_STAT stat)
{
	int v = mbx_rd32(vf_mbx->peer2pf_ctrl);

	if (!(v & MBX_CTRL_VF2PF_STAT_VALID_MSK))
		return -EIO;

	switch (stat) {
	case VF_RESET_DONE:
		return !!(v & MBX_CTRL_VF2PF_RESET_DONE_MSK);
	case VF_MBX_IRQ_INIT_DONE:
		return !!(v & MBX_CTRL_VF2PF_MBX_INIT_DONE_MSK);
	}
	return -EINVAL;
}

void mce_mbx_clear_vf_reset_done_stat(struct mce_mbx_info *vf_mbx)
{
	mbx_wr32_masked(vf_mbx->peer2pf_ctrl, MBX_CTRL_VF2PF_RESET_DONE_MSK, 0);
}

void mce_mbx_link_state_change_notify_en(struct mce_hw *hw, int enable)
{
	hw->fw_mbx.fw2pf_link_change_notify_en = !!enable;
	mce_mbx_set_pf_stat_fw(&hw->fw_mbx);
}

void mce_mbx_sfp_plug_notify_en(struct mce_hw *hw, int enable)
{
	hw->fw_mbx.fw2pf_sfp_pluginout_notify_en = !!enable;
	mce_mbx_set_pf_stat_fw(&hw->fw_mbx);
}

void mce_mbx_drv_send_uninstall_notify_fw(struct mce_hw *hw)
{
	mce_mbx_send_event(&hw->fw_mbx, EVT_DRV_REMOVE, 1000);
}
