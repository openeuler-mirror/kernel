// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */

#include "mcevf.h"
#include "mcevf_mbx.h"

//==== flags ===
#define MBX_CTRL_REQ_IRQ_MSK	    BIT(0)  // WO
#define MBX_CTRL_FW_HOLD_PF_SHM_MSK BIT(2)  // PFU:RO, CFU:WR
#define MBX_CTRL_FW_HOLD_PF_SHM	    BIT(2)  // PFU:RO, CFU:WR
#define MBX_CTRL_FW_HOLD_VF_SHM_MSK BIT(3)  // CFU:RW, VFU:RO
#define MBX_CTRL_FW_HOLD_VF_SHM	    BIT(3)  // CFU:RW, VFU:RO
#define MBX_CTRL_IRQ_MSK	    BIT(4)

#define MBX_IRQ_EN	(0 << 4)
#define MBX_IRQ_DISABLE BIT(4)

//==== PF2VF MBX FLAGS ==
#define MBX_CTRL_PF2VF_REQ_STAT_SHIFT  (5)
#define MBX_CTRL_PF2VF_REQ_STAT_MSK    (0b11 << MBX_CTRL_PF2VF_REQ_STAT_SHIFT)
#define MBX_CTRL_PF2VF_STAT_VALID_MSK  BIT(7)
#define MBX_CTRL_PF2VF_STAT_VALID      MBX_CTRL_STAT_VF_VALID_MSK
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

//=== VF2PF MBX CTRL ==
#define MBX_CTRL_VF2PF_REQ_ST_CLR_SHIFT	   5
#define MBX_CTRL_VF2PF_REQ_ST_CLR_MSK	   BIT(MBX_CTRL_VF2PF_REQ_ST_CLR_SHIFT)
#define MBX_CTRL_VF2PF_REQ_STAT_SHIFT	   (6)
#define MBX_CTRL_VF2PF_REQ_STAT_MSK	   (0b11 << MBX_CTRL_VF2PF_REQ_STAT_SHIFT)
#define MBX_CTRL_VF2PF_STAT_VALID_MSK	   BIT(8)
#define MBX_CTRL_VF2PF_STAT_VALID	   MBX_CTRL_VF2PF_STAT_VALID_MSK
#define MBX_CTRL_VF2PF_RESET_DONE_SHIFT	   (9)
#define MBX_CTRL_VF2PF_RESET_DONE_MSK	   BIT(MBX_CTRL_VF2PF_RESET_DONE_SHIFT)
#define MBX_CTRL_VF2PF_MBX_INIT_DONE_SHIFT 10
#define MBX_CTRL_VF2PF_MBX_INIT_DONE_MSK   BIT(MBX_CTRL_VF2PF_MBX_INIT_DONE_SHIFT)
#define MBX_CTRL_VF2PF_EVENT_ID_SHIFT	   (13)
#define MBX_CTRL_VF2PF_EVENT_ID_MASK	   (0b111 << MBX_CTRL_VF2PF_EVENT_ID_SHIFT)

#define MBX_CTRL_GET_VF2PF_REQ_STAT(v) \
	(((v) & MBX_CTRL_VF2PF_REQ_STAT_MSK) >> MBX_CTRL_VF2PF_REQ_STAT_SHIFT)

#define MBX_SEND_REQ_WITH_IRQ BIT(0)

#define mbx_rd32(reg)			    readl((reg))
#define mbx_wr32(reg, val)		    writel((val), (reg))
#define mbx_wr32_masked(reg, mask16, val16) writel((val16) | ((mask16) << 16), (reg))

void mcevf_mbx_clear_peer_req_irq_with_stat(struct mcevf_mbx_info *mbx,
					    enum MBX_REQ_STAT stat)
{
	u32 mask;
	u32 val;

	mask = MBX_CTRL_PF2VF_REQ_STAT_MSK | MBX_CTRL_REQ_IRQ_MSK;
	val = (stat << MBX_CTRL_PF2VF_REQ_STAT_SHIFT) | 0;
	mbx_wr32_masked(mbx->peer2vf_ctrl, mask, val);
}

static void __maybe_unused
mcevf_mbx_clear_peer_req_irq_with_no_stat_change(struct mcevf_mbx_info *mbx)
{
	mbx_wr32_masked(mbx->peer2vf_ctrl, MBX_CTRL_REQ_IRQ_MSK, 0);
}

static inline int mcevf_mbx_get_req_shm_lock(struct mcevf_mbx_info *mbx,
					     int timeout_us)
{
	while (1) {
		mbx_wr32_masked(mbx->vf2peer_shm_lock,
				mbx->vf2peer_shm_lock_msk,
				mbx->vf2peer_shm_lock_msk);
		/* Ensure the lock request reaches the peer before reading it back. */
		mb();
		if (mbx_rd32(mbx->vf2peer_shm_lock) & mbx->vf2peer_shm_lock_msk)
			return 0;

		if (timeout_us > 0) {
			udelay(1);
			timeout_us--;
		} else {
			break;
		}
	}

	return -ETIMEDOUT;
}

static void mcevf_mbx_put_req_shm_lock(struct mcevf_mbx_info *mbx)
{
	mbx_wr32_masked(mbx->vf2peer_shm_lock, mbx->vf2peer_shm_lock_msk, 0);
}

static int mcevf_mbx_get_peer_shm_lock(struct mcevf_mbx_info *mbx,
				       int timeout_us)
{
	while (1) {
		mbx_wr32_masked(mbx->peer2vf_shm_lock,
				mbx->peer2vf_shm_lock_msk,
				mbx->peer2vf_shm_lock_msk);
		/* Ensure the lock request reaches the peer before reading it back. */
		mb();
		if (mbx_rd32(mbx->peer2vf_shm_lock) & mbx->peer2vf_shm_lock_msk)
			return 0;

		if (timeout_us > 0) {
			udelay(1);
			timeout_us--;
		} else {
			break;
		}
	}

	return -ETIMEDOUT;
}

static inline void mcevf_mbx_put_peer_shm_lock(struct mcevf_mbx_info *mbx)
{
	mbx_wr32_masked(mbx->peer2vf_shm_lock, mbx->peer2vf_shm_lock_msk, 0);
}

int mcevf_mbx_init_configure(struct mcevf_mbx_info *mbx)
{
	int i;

	mbx_wr32_masked(mbx->vf2peer_ctrl, 0xffff, 0);
	/* if mbx irq unregisterred, disable pf/fw mbx irq to vf */
	if (!mbx->irq_enabled) {
		mbx_wr32_masked(mbx->peer2vf_ctrl, MBX_CTRL_IRQ_MSK,
				MBX_IRQ_DISABLE);
	} else {
		mbx_wr32_masked(mbx->peer2vf_ctrl, MBX_CTRL_IRQ_MSK,
				MBX_IRQ_EN);
	}

	/* clear req-shm to 0*/
	for (i = 0; i < mbx->req_shm_size / 4; i++)
		mbx_wr32(mbx->vf2peer_shm + i * 4, 0);

	/* release vf to pf/fw shm lock (if have) */
	mbx_wr32_masked(mbx->vf2peer_shm_lock, mbx->vf2peer_shm_lock_msk, 0);
	mbx_wr32(mbx->vf2peer_shm, 0);

	/* release pf/fw to vf shm lock (if have) */
	mbx_wr32_masked(mbx->peer2vf_shm_lock, mbx->peer2vf_shm_lock_msk, 0);

	return 0;
}

void mcevf_mbx_reset(struct mcevf_hw *hw)
{
	mcevf_mbx_init_configure(&hw->pf_mbx);
}

void mcevf_mbx_set_vf_stat(struct mcevf_mbx_info *pf_mbx)
{
	struct mcevf_pf *vf = pf_mbx->hw->back;
	int stat_valid = MBX_CTRL_VF2PF_STAT_VALID;
	u32 mask;
	u32 val;

	if (test_bit(MCEVF_SHUTTING_DOWN, vf->state))
		stat_valid = 0; /*  driver removing, status is invalid */

	mask = MBX_CTRL_VF2PF_STAT_VALID_MSK |
	       MBX_CTRL_VF2PF_MBX_INIT_DONE_MSK | MBX_CTRL_VF2PF_RESET_DONE_MSK;
	val = stat_valid |
	      (pf_mbx->irq_enabled << MBX_CTRL_VF2PF_MBX_INIT_DONE_SHIFT) |
	      (pf_mbx->hw->reset_done << MBX_CTRL_VF2PF_RESET_DONE_SHIFT);
	mbx_wr32_masked(pf_mbx->vf2peer_ctrl, mask, val);
}

int mcevf_mbx_vector_set(struct mcevf_mbx_info *mbx, int nr_vector, bool enable)
{
	mbx_logd(LOG_MISC_IRQ, "%s: %s vector:%d enable:%d\n", __func__,
		 mbx->name, nr_vector, enable);

	if (enable) {
		mbx_wr32(mbx->mbx_vec_base, nr_vector);
		mbx_wr32_masked(mbx->peer2vf_ctrl, MBX_CTRL_IRQ_MSK, MBX_IRQ_EN);
		mbx->irq_enabled = true;
	} else {
		mbx_wr32_masked(mbx->peer2vf_ctrl, MBX_CTRL_IRQ_MSK, MBX_IRQ_DISABLE);
		mbx->irq_enabled = false;
	}

	mcevf_mbx_set_vf_stat(mbx);
	return 0;
}

int mcevf_mbx_send_event(struct mcevf_mbx_info *mbx, int event_id,
			 int timeout_us)
{
	int ret = 0;
	u32 mask;
	u32 val;

	mask = MBX_CTRL_VF2PF_EVENT_ID_MASK | MBX_CTRL_VF2PF_REQ_STAT_MSK |
	       MBX_CTRL_REQ_IRQ_MSK;
	val = (event_id << MBX_CTRL_VF2PF_EVENT_ID_SHIFT) |
	      (EVENT_REQ << MBX_CTRL_VF2PF_REQ_STAT_SHIFT) |
	      MBX_SEND_REQ_WITH_IRQ;
	mbx_wr32_masked(mbx->vf2peer_ctrl, mask, val);
	mbx->stats.tx_event_cnt++;

	/* wait ack */
	ret = -ETIMEDOUT;
	while (timeout_us > 0) {
		int stat;
		u32 v = mbx_rd32(mbx->vf2peer_ctrl);

		stat = MBX_CTRL_GET_VF2PF_REQ_STAT(v);
		if (stat != EVENT_REQ) {
			if (stat == RESP_OR_ACK)
				ret = 0;
			else
				ret = -EIO;
			break;
		}

		if (in_interrupt() || irqs_disabled())
			udelay(10);
		else
			usleep_range(10, 10);
		timeout_us -= 10;
	}

	if (ret != 0)
		mbx->stats.tx_event_err_cnt++;

	return ret;
}

int mcevf_mbx_send_resp_isr(struct mcevf_mbx_info *mbx, struct mbx_resp *resp)
{
	int i, total_sz, ret = 0;
	enum MBX_REQ_STAT stat = RESP_OR_ACK;

	if (!mbx || !resp || !in_interrupt()) {
		dev_err(mbx->hw->dev,
			"%s:%s should be called in interrupt ctx. opcode:%d arg_cnt:%d\n",
			__func__,
			mbx->name,
			resp->cmd.opcode,
			resp->cmd.arg_cnts);
		stat = HAS_ERR;
		ret = -EINVAL;
		goto quit;
	}

	// no lock needed, as can only be called from irq handler
	if (resp->cmd.flag_no_resp != 0) {
		total_sz = resp->cmd.arg_cnts * 4 + offsetof(struct mbx_resp, data);
		if (total_sz > mbx->peer_shm_size) {
			dev_err(mbx->hw->dev,
				"%s:%s opcode:%d  total_sz:%d > max size:%d\n",
				__func__,
				mbx->name,
				resp->cmd.opcode,
				total_sz,
				mbx->peer_shm_size);
			stat = HAS_ERR;
			ret = -EINVAL;
			goto quit;
		}

		if (BIT(LOG_MBX_IN_REQ) & mcevf_loglevel) {
			dev_dbg(mbx->hw->dev, "== %s ==\n", mbx->name);
			print_hex_dump(KERN_CONT,
				       "req-in-resp: ", DUMP_PREFIX_OFFSET, 16,
				       1, (char *)resp, total_sz, false);
		}

		if (mcevf_mbx_get_peer_shm_lock(mbx, 200) < 0) {  // 200us
			dev_err(mbx->hw->dev,
				"%s:%s get resp shm lock timeout.opcode:%d\n",
				__func__,
				mbx->name,
				resp->cmd.opcode);
			mbx->stats.rx_resp_shm_lock_timeout++;
			stat = HAS_ERR;
			ret = -ETIMEDOUT;
			goto quit;
		}

		for (i = 0; i < total_sz / 4; i++)
			mbx_wr32(mbx->peer2vf_shm + i * 4, ((int *)resp)[i]);
		/* Publish the complete response before releasing the shared lock. */
		mb();
		mcevf_mbx_put_peer_shm_lock(mbx);
	}

quit:
	mcevf_mbx_clear_peer_req_irq_with_stat(mbx, stat);

	return ret;
}

static int mcevf_mbx_read_incoming_req_isr(struct mcevf_mbx_info *mbx,
					   struct mbx_req *req)
{
	unsigned long flags;
	int total_sz, i;
	unsigned int *req_arr = (unsigned int *)req;

	if (!req || !mbx)
		return -EINVAL;

	if (mcevf_mbx_get_peer_shm_lock(mbx, 200) < 0) {  // 200us
		dev_err(mbx->hw->dev, "%s:%s get req shm lock timeout\n", __func__, mbx->name);
		mbx->stats.rx_req_shm_lock_timeout++;
		return -ETIMEDOUT;
	}

	req_arr[0] = mbx_rd32(mbx->peer2vf_shm);
	/* Order the header read before validating its payload length. */
	rmb();
	if (req->cmd.arg_cnts > (sizeof(req->data) / 4) ||
	    req->cmd.arg_cnts > (mbx->peer_shm_size / 4)) {
		dev_err(mbx->hw->dev,
			"%s:%s opcode req hdr arg_cnts:%d, cmd:0x%x error!\n",
			__func__,
			mbx->name,
			req->cmd.arg_cnts,
			req->cmd.v);
		mcevf_mbx_put_peer_shm_lock(mbx);
		return -EIO;
	}

	total_sz = offsetof(struct mbx_req, data) + req->cmd.arg_cnts * 4;

	/* disable irq && schedule */
	spin_lock_irqsave(&mbx->peer_shm_lock, flags);
	for (i = 0; i < total_sz / 4; i++)
		req_arr[i] = mbx_rd32(mbx->peer2vf_shm + i * 4);
	/* Finish reading the request before clearing its shared-memory header. */
	rmb();
	/* set to 0 */
	mbx_wr32(mbx->peer2vf_shm + 0, 0);
	/* Publish the cleared header before dropping the shared lock. */
	mb();
	mcevf_mbx_put_peer_shm_lock(mbx);
	spin_unlock_irqrestore(&mbx->peer_shm_lock, flags);

	if (BIT(LOG_MBX_IN_REQ) & mcevf_loglevel) {
		dev_dbg(mbx->hw->dev, "== %s ==\n", mbx->name);
		print_hex_dump(KERN_CONT, "req-in: ", DUMP_PREFIX_OFFSET, 16,
			       1, req, total_sz, false);
	}

	return total_sz;
}

int mcevf_mbx_clean_all_incoming_req(struct mcevf_hw *hw,
				     mbx_event_req_cb *event_cb,
				     mbx_req_with_data_cb *req_cb)
{
	unsigned int v, stat;
	struct mcevf_mbx_info *mbx = &hw->pf_mbx;
	struct mcevf_pf *pf = hw->back;

	if (!event_cb || !hw || !req_cb)
		return -EINVAL;

	v = mbx_rd32(mbx->peer2vf_ctrl);
	stat = MBX_CTRL_GET_PF2VF_REQ_STAT(v);

	if (stat == EVENT_REQ) {
		int event_id = MBX_CTRL_GET_PF2VF_EVENT_ID(v);

		mcevf_mbx_clear_peer_req_irq_with_stat(mbx, RESP_OR_ACK);
		hw_logd(LOG_MBX_IN_REQ, "%s: get event:%d\n", mbx->name,
			event_id);
		event_cb(mbx, event_id);
	} else if (stat == REQ_WITH_DATA) {
		struct mbx_req req = {};

		int total_size = mcevf_mbx_read_incoming_req_isr(mbx, &req);

		if (total_size < 0)
			mcevf_mbx_clear_peer_req_irq_with_stat(mbx, HAS_ERR);
		else
			req_cb(mbx, &req);
	}

	if (stat == EVENT_REQ || stat == REQ_WITH_DATA)
		mcevf_service_task_schedule(pf);
	return 0;
}

static int mcevf_mbx_req_read_resp_out(struct mcevf_mbx_info *mbx,
				       struct mbx_resp *resp)
{
	unsigned long flags;
	int total_sz, i;
	unsigned int *resp_arr = (unsigned int *)resp;

	if (!resp)
		return -EINVAL;

	resp_arr[0] = mbx_rd32(mbx->vf2peer_shm);
	/* Order the response header read before validating its payload length. */
	rmb();
	if (resp->cmd.arg_cnts > (sizeof(resp->data) / 4) ||
	    resp->cmd.arg_cnts > (mbx->req_shm_size / 4)) {
		dev_err(mbx->hw->dev,
			"%s: opcode resp hdr arg_cnts:%d, 0x%x error!\n",
			__func__,
			resp->cmd.arg_cnts,
			resp->cmd.v);
		return -EIO;
	}

	total_sz = offsetof(struct mbx_resp, data) + resp->cmd.arg_cnts * 4;

	if (mcevf_mbx_get_req_shm_lock(mbx, 1000) < 0) {  // 1ms
		dev_err(mbx->hw->dev, "%s: get req shm lock timeout\n", __func__);
		mbx->stats.tx_shm_lock_timeout++;
		return -ETIMEDOUT;
	}
	/* disable irq && schedule after get mbx share memory hw-lock */
	spin_lock_irqsave(&mbx->req_shm_lock, flags);
	for (i = 1; i < total_sz / 4; i++)
		resp_arr[i] = mbx_rd32(mbx->vf2peer_shm + i * 4);
	/* Finish reading the response before clearing its shared-memory header. */
	rmb();
	mbx_wr32(mbx->vf2peer_shm + 0, 0);  // clear opcode
	/* Publish the cleared header before releasing the shared lock. */
	mb();
	mcevf_mbx_put_req_shm_lock(mbx);
	spin_unlock_irqrestore(&mbx->req_shm_lock, flags);

	if (BIT(LOG_MBX_REQ_OUT) & mcevf_loglevel) {
		dev_dbg(mbx->hw->dev, "== %s ==\n", mbx->name);
		print_hex_dump(KERN_CONT, "req-resp: ", DUMP_PREFIX_OFFSET, 16,
			       1, resp_arr, total_sz, false);
	}

	return total_sz;
}

int mcevf_mbx_send_req(struct mcevf_mbx_info *mbx, int opcode, int *data,
		       int data_bytes, struct mbx_resp *resp, int timeout_us)
{
	struct mbx_req req = {};
	int i, total_sz = data_bytes + offsetof(struct mbx_req, data);
	int ret = 0, err = 0;
	unsigned long flags;

	if (total_sz > mbx->req_shm_size) {
		dev_err(mbx->hw->dev,
			"%s:%s opcode:0x%x data_bytes:%d > max_size:%d\n",
			__func__,
			mbx->name,
			opcode,
			data_bytes,
			mbx->req_shm_size);
		return -EINVAL;
	}
	req.cmd.opcode = opcode;
	req.cmd.arg_cnts = round_up(data_bytes, 4) / 4;
	req.cmd.flag_peer2pf_req = 1;
	memcpy(req.data, data, data_bytes);

	if (!resp)
		req.cmd.flag_no_resp = 1;

	if (BIT(LOG_MBX_REQ_OUT) & mcevf_loglevel) {
		dev_dbg(mbx->hw->dev, "== %s ==\n", mbx->name);
		print_hex_dump(KERN_CONT, "req: ", DUMP_PREFIX_OFFSET, 16,
			       1, &req, total_sz, false);
	}

	// send req
	mutex_lock(&mbx->req_lock);

	if (mcevf_mbx_get_req_shm_lock(mbx, 1000) < 0) {  // 1ms
		dev_err(mbx->hw->dev,
			"%s:%s opcode:0x%x get req shm lock timeout\n",
			__func__,
			mbx->name,
			opcode);
		ret = -ETIMEDOUT;
		mbx->stats.tx_shm_lock_timeout++;
		goto quit;
	}
	// disable irq && schedule after get mbx share memory hw-lock
	spin_lock_irqsave(&mbx->req_shm_lock, flags);
	for (i = 0; i < total_sz / 4; i++)
		mbx_wr32(mbx->vf2peer_shm + i * 4, ((int *)&req)[i]);
	mcevf_mbx_put_req_shm_lock(mbx);
	spin_unlock_irqrestore(&mbx->req_shm_lock, flags);

	/* Ensure the request data is visible before raising the peer IRQ. */
	mb();
	// send req with irq to peer
	mbx_wr32_masked(mbx->vf2peer_ctrl,
			MBX_CTRL_VF2PF_REQ_STAT_MSK | MBX_CTRL_REQ_IRQ_MSK,
			(REQ_WITH_DATA << MBX_CTRL_VF2PF_REQ_STAT_SHIFT) | MBX_SEND_REQ_WITH_IRQ);
	mbx->stats.tx_req_cnt++;

	/* Order the doorbell write before polling its completion state. */
	mb();

	ret = -ETIMEDOUT;
	// wait response or ack
	while (timeout_us > 0) {
		u32 v = mbx_rd32(mbx->vf2peer_ctrl);
		int stat;

		stat = MBX_CTRL_GET_VF2PF_REQ_STAT(v);
		if (stat != REQ_WITH_DATA) {
			ret = 0;
			if (stat == RESP_OR_ACK) {
				if (resp) {
					err = mcevf_mbx_req_read_resp_out(mbx, resp);
					if (err > 0 &&
					    resp->cmd.opcode != opcode) {
						ret = -EIO;
					}
				}
			} else {
				ret = -EIO;
			}
			break;
		}
		if (in_interrupt() || irqs_disabled())
			udelay(10);
		else
			usleep_range(10, 10);
		timeout_us -= 10;
	}
quit:
	mutex_unlock(&mbx->req_lock);

	return ret;
}

int mcevf_mbx_get_pf_stat(struct mcevf_mbx_info *pf_mbx, enum MBX_PF_STAT stat)
{
	int v = mbx_rd32(pf_mbx->peer2vf_ctrl);

	if (!(v & MBX_CTRL_PF2VF_STAT_VALID_MSK))
		return -EIO;

	switch (stat) {
	case PF_SPEED:
		return speed_unzip((v & MBX_CTRL_PF2VF_PF_SPEED_MSK) >>
				   MBX_CTRL_PF2VF_SPEED_SHIFT);
	case PF_LINKUP:
		return !!(v & MBX_CTRL_PF2VF_LINK_STAT_MSK);
	}
	return -EINVAL;
}
