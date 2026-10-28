// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/random.h>
#include <linux/types.h>

#include "nse.h"
#include "nse_type.h"
#include "nse_fwmng.h"
#include "nse_hw_reg.h"

/* cmd = 0x41 */
u32 fwmng_cmd_id_high_reset =
		MAKE_FWMNG_CMD_CODE(NSE_FWMNG_CMD_CATEGORY_RESET, NSE_FWMNG_CMD_HIGH_RESET);

/* cmd = 0x42 */
u32 fwmng_evt_id_aqm_err =
		MAKE_FWMNG_CMD_CODE(NSE_FWMNG_CMD_CATEGORY_RESET, NSE_FWMNG_CMD_AQM_ERROR);

#define FWMNG_DEFAULT_WAIT_TICK_US				50
/*  below are base values, would be scaled by *= nse_timeout_scale in
 * __fwmng_send_req_read_rsp_unlocked()
 */
/* 50 us x 200 = 10 000 us = 10 ms */
unsigned int fwmng_wait_very_short_timeout	= 200;
/* 50 us x 1000 = 50 000 us = 50 ms */
unsigned int fwmng_wait_short_timeout		= 1000;
/* 50 us x 40000 = 2 000 000 us = 2 s */
unsigned int fwmng_wait_mid_timeout			= 40000;
/* 50 us x 400000 = 20 000 000 us = 20 s */
unsigned int fwmng_wait_long_timeout		= 400000;

void fwmng_clear_rsp(struct nse_hw *hw, bool fwmng_locked, unsigned int clear_rsp_op)
{
	u32 rsp;

	if (!fwmng_locked)
		mutex_lock(&hw->fwmng_lock);

	if (clear_rsp_op == NSE_FWMNG_CLEAR_RSP_VALID_ONLY) {
		rsp = rd32(hw, NSE_REG_RSP);
		rsp &= ~(NSE_REG_RSP_VLD_M);

		/* clear NSE_REG_RSP_VLD_M, but keep reset of data */
		wr32(hw, NSE_REG_RSP, rsp);
	} else if (clear_rsp_op == NSE_FWMNG_CLEAR_RSP_ONLY) {
		/* clear register: RSP, but keep reset of RSP_BUF[0 - 3] */
		wr32(hw, NSE_REG_RSP, 0);
	} else if (clear_rsp_op == NSE_FWMNG_CLEAR_RSP_ALL) {
		wr32(hw, NSE_REG_RSP, 0);

		wr32(hw, NSE_REG_RSP_BUF(0), 0);
		wr32(hw, NSE_REG_RSP_BUF(1), 0);
		wr32(hw, NSE_REG_RSP_BUF(2), 0);
		wr32(hw, NSE_REG_RSP_BUF(3), 0);
	}

	nse_flush(hw);

	if (!fwmng_locked)
		mutex_unlock(&hw->fwmng_lock);
}

void fwmng_read_clear_rsp(struct nse_hw *hw,
					struct nse_fwmng_cmd_rsp_generic *cmd_rsp,
					bool fwmng_locked,
					unsigned int clear_rsp_op)
{
	if (!fwmng_locked)
		mutex_lock(&hw->fwmng_lock);

	cmd_rsp->rsp = rd32(hw, NSE_REG_RSP);
	cmd_rsp->rsp_buf[0] = rd32(hw, NSE_REG_RSP_BUF(0));
	cmd_rsp->rsp_buf[1] = rd32(hw, NSE_REG_RSP_BUF(1));
	cmd_rsp->rsp_buf[2] = rd32(hw, NSE_REG_RSP_BUF(2));
	cmd_rsp->rsp_buf[3] = rd32(hw, NSE_REG_RSP_BUF(3));

	/* Make sure the response registers above are read before the
	 * response is cleared.
	 */
	wmb();

	/* if at this moment, a rsp is coming, then there is nothing we can do */
	if (clear_rsp_op)
		fwmng_clear_rsp(hw, true, clear_rsp_op);

	nse_flush(hw);

	if (!fwmng_locked)
		mutex_unlock(&hw->fwmng_lock);
}

int __fwmng_send_req_read_rsp_unlocked(struct nse_hw *hw,
						struct nse_fwmng_cmd_req_generic *cmd_req,
						struct nse_fwmng_cmd_rsp_generic *cmd_rsp,
						unsigned int flags,
						unsigned int wait_tick_us,
						unsigned int wait_times,
						unsigned int *detail_status)
{
	struct device *dev = nse_hw_to_dev(hw);
	u32 reg;
	u32 req_id, rsp_id;
	unsigned int wait = 0;
	int ret = 0;

	if (!wait_tick_us)
		wait_tick_us = FWMNG_DEFAULT_WAIT_TICK_US;

	if (!wait_times)
		wait_times = fwmng_wait_short_timeout;

	wait_times *= nse_timeout_scale;

	*detail_status = NSE_FWMNG_STATUS_OK;

	/* check if existing old uncleared rsp or event uncleared.
	 */
	if (!(flags & NSE_FWMNG_FLAG_CHECK_OLD_RSP))
		goto no_check_old_rsp;

	reg = rd32(hw, NSE_REG_RSP);

	if (reg & NSE_REG_RSP_VLD_M) {
		cmd_rsp->rsp = reg;
		cmd_rsp->rsp_buf[0] = rd32(hw, NSE_REG_RSP_BUF(0));
		cmd_rsp->rsp_buf[1] = rd32(hw, NSE_REG_RSP_BUF(1));
		cmd_rsp->rsp_buf[2] = rd32(hw, NSE_REG_RSP_BUF(2));
		cmd_rsp->rsp_buf[3] = rd32(hw, NSE_REG_RSP_BUF(3));

		*detail_status = NSE_FWMNG_STATUS_EXIST_OLD_RSP;
		ret = -EIO;

		nse_debug(hw, NSE_DBG_FW, "[%s, %d] exist old data in rsp (rsp=%X, rsp_buf[4]=[%x, %x, %x, %x])\n",
					__func__, __LINE__,
					cmd_rsp->rsp, cmd_rsp->rsp_buf[0], cmd_rsp->rsp_buf[1],
						cmd_rsp->rsp_buf[2], cmd_rsp->rsp_buf[3]);

		goto out;
	}

no_check_old_rsp:

	/* send request
	 */

	nse_debug(hw, NSE_DBG_FW, "[%s, %d] send cmd-req to FW (cmd=%X, cmd_buf[4]=[%x, %x, %x, %x])\n",
				__func__, __LINE__,
				cmd_req->cmd, cmd_req->cmd_buf[0], cmd_req->cmd_buf[1],
					cmd_req->cmd_buf[2], cmd_req->cmd_buf[3]);

	/* clear cmd, and resp first */
	wr32(hw, NSE_REG_CMD, 0);
	wr32(hw, NSE_REG_RSP, 0);

	/* write cmd request */
	wr32(hw, NSE_REG_CMD_BUF(0), cmd_req->cmd_buf[0]);
	wr32(hw, NSE_REG_CMD_BUF(1), cmd_req->cmd_buf[1]);
	wr32(hw, NSE_REG_CMD_BUF(2), cmd_req->cmd_buf[2]);
	wr32(hw, NSE_REG_CMD_BUF(3), cmd_req->cmd_buf[3]);

	/* Make sure the command buffer above is written before the VLD
	 * bit triggers the FW interrupt.
	 */
	wmb();

	/* VLD 0->1 posedge trigger FW interrupt */
	wr32(hw, NSE_REG_CMD, (cmd_req->cmd | NSE_REG_CMD_VLD_M));

	/* Order the flush below after the command VLD write above. */
	wmb();
	nse_flush(hw);

	if (!(flags & NSE_FWMNG_FLAG_WAIT_REQ))
		goto no_wait_req;

	/* wait for MNG to receive cmd request */
	wait = 0;
	do {
		reg = rd32(hw, NSE_REG_CMD);

		if (!(reg & NSE_REG_CMD_VLD_M))
			break;

		udelay(wait_tick_us);

		wait++;
	} while (wait < wait_times);

	if (wait >= wait_times) {
		dev_err(dev, "FAIL: [%s] timeout wait for MNG to receive cmd request\n",
			__func__);

		*detail_status = NSE_FWMNG_STATUS_REQ_TIMEOUT;
		ret = -EBUSY;

		goto out;
	}

no_wait_req:

	/* read response from FW
	 */

	if (!(flags & NSE_FWMNG_FLAG_WAIT_RSP))	/* ret = 0 */
		goto out;

	/* wait for MNG to writeback cmd response */
	wait = 0;
	do {
		reg = rd32(hw, NSE_REG_RSP);

		if (reg & NSE_REG_RSP_VLD_M)
			break;

		udelay(wait_tick_us);

		wait++;
	} while (wait < wait_times);

	if (wait >= wait_times) {
		dev_err(dev, "FAIL: [%s] timeout wait for MNG to write-back cmd response\n",
			__func__);

		*detail_status = NSE_FWMNG_STATUS_RSP_TIMEOUT;
		ret = -EBUSY;

		goto out;
	}

	/* read cmd response and clear */
	cmd_rsp->rsp = reg;
	cmd_rsp->rsp_buf[0] = rd32(hw, NSE_REG_RSP_BUF(0));
	cmd_rsp->rsp_buf[1] = rd32(hw, NSE_REG_RSP_BUF(1));
	cmd_rsp->rsp_buf[2] = rd32(hw, NSE_REG_RSP_BUF(2));
	cmd_rsp->rsp_buf[3] = rd32(hw, NSE_REG_RSP_BUF(3));

	/* Make sure the response buffer above is read before the
	 * response is cleared.
	 */
	wmb();
	nse_flush(hw);

	wr32(hw, NSE_REG_RSP, 0);	/* clear NSE_REG_RSP_VLD_M */

	nse_debug(hw, NSE_DBG_FW, "[%s, %d] receive cmd-rsp to FW (rsp=%X, rsp_buf[4]=[%x, %x, %x, %x])\n",
				__func__, __LINE__,
				cmd_rsp->rsp, cmd_rsp->rsp_buf[0], cmd_rsp->rsp_buf[1],
					cmd_rsp->rsp_buf[2], cmd_rsp->rsp_buf[3]);

	if (!(flags & NSE_FWMNG_FLAG_CHECK_RSP_MATCH))	/* ret = 0 */
		goto out;

	/* check if cmd response is really for cmd request */
	if (!(cmd_rsp->rsp & NSE_FWMNG_CMD_RESPONSE_FLAG)) {
		dev_err(dev, "FAIL: [%s] MNG writeback a NON-cmd-resp: 0x%X\n",
			__func__, cmd_rsp->rsp);

		*detail_status = NSE_FWMNG_STATUS_RSP_NOT_MATCH_REQ;
		ret = -EIO;

		goto out;
	}

	req_id = NSE_FWMNG_CMD_REQ_RSP_GET_ID(cmd_req->cmd);
	rsp_id = NSE_FWMNG_CMD_REQ_RSP_GET_ID(cmd_rsp->rsp);

	if (rsp_id != req_id) {
		dev_err(dev, "FAIL: [%s] MNG writeback a cmd-resp (0x%X) NOT for us (0x%X)\n",
			__func__, rsp_id, req_id);

		*detail_status = NSE_FWMNG_STATUS_RSP_NOT_MATCH_REQ;
		ret = -EIO;

		goto out;
	}

	ret = 0;

out:
	return ret;
}

int __fwmng_send_req_read_rsp(struct nse_hw *hw,
						struct nse_fwmng_cmd_req_generic *cmd_req,
						struct nse_fwmng_cmd_rsp_generic *cmd_rsp,
						unsigned int flags,
						unsigned int wait_tick_us,
						unsigned int wait_times,
						unsigned int *detail_status)
{
	int ret;

	mutex_lock(&hw->fwmng_lock);

	ret = __fwmng_send_req_read_rsp_unlocked(hw, cmd_req, cmd_rsp,
						 flags, wait_tick_us, wait_times, detail_status);

	mutex_unlock(&hw->fwmng_lock);

	return ret;
}

int fwmng_cmd_send_req_read_rsp(struct nse_hw *hw,
						struct nse_fwmng_cmd_req_generic *cmd_req,
						struct nse_fwmng_cmd_rsp_generic *cmd_rsp,
						unsigned int wait_timeout)
{
	unsigned int detail_status = 0;
	int ret = 0;
	unsigned int flags = (NSE_FWMNG_FLAG_WAIT_REQ | NSE_FWMNG_FLAG_WAIT_RSP |
			      NSE_FWMNG_FLAG_CHECK_RSP_MATCH);

	/* wait_rsp = true, check_rsp_match=true, */
	ret = __fwmng_send_req_read_rsp(hw, cmd_req, cmd_rsp, flags,
								FWMNG_DEFAULT_WAIT_TICK_US,
									wait_timeout,
								&detail_status);
	if (ret) {
		dev_err(nse_hw_to_dev(hw), "FAIL: __fwmng_send_req_read_rsp(), ret=%d, detail_status=%d\n",
								ret, detail_status);
	}

	return ret;
}

int fwmng_high_reset_send_request_only(struct nse_hw *hw,
				       enum nse_reset_req reset_req, bool fwmng_locked)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_fwmng_cmd_req_generic cmd_req;
	struct nse_fwmng_cmd_rsp_generic cmd_rsp;
	u32 rsp_id;
	unsigned int flags;
	unsigned int detail_status = 0;
	int ret = 0;

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_req=%d\n", __func__, reset_req);

	if (!fwmng_locked)
		mutex_lock(&hw->fwmng_lock);

	if (reset_req != NSE_RESET_HIGH_RESET_CORER) {
		dev_err(dev, "[%s] BAD: request wrong reset_type (%d)\n", __func__, reset_req);
		ret = -EINVAL;
		goto out;
	}

	fwmng_read_clear_rsp(hw, &cmd_rsp, true, 0);

	rsp_id = NSE_FWMNG_CMD_REQ_RSP_GET_ID(cmd_rsp.rsp);
	if (rsp_id == fwmng_cmd_id_high_reset) {
		dev_info(dev, "[%s, %d] detect high_reset (type=0x%X, reset_status=0x%X), before I request\n",
						__func__, __LINE__,
						cmd_rsp.rsp_buf[0], cmd_rsp.rsp_buf[2]);
		goto out;
	}

	memset(&cmd_req, 0, sizeof(cmd_req));
	memset(&cmd_rsp, 0, sizeof(cmd_rsp));

	cmd_req.cmd = fwmng_cmd_id_high_reset;
	cmd_req.cmd_buf[0] = 0x0;	/* core-reset */

retry:
	/* flags: CHECK_OLD_RSP = 1, WAIT_REQ = 1, WAIT_RSP = 0, CHECK_RSP_MATCH = 0 */

	flags = (NSE_FWMNG_FLAG_CHECK_OLD_RSP | NSE_FWMNG_FLAG_WAIT_REQ);

	ret = __fwmng_send_req_read_rsp_unlocked(hw, &cmd_req, &cmd_rsp, flags,
					FWMNG_DEFAULT_WAIT_TICK_US, fwmng_wait_short_timeout,
					&detail_status);
	if (!ret) {
		dev_info(dev, "[%s, %d] I send high_reset req, accepted by FW\n",
						__func__, __LINE__);
		goto out;
	} else {
		if (detail_status == NSE_FWMNG_STATUS_REQ_TIMEOUT) {
			dev_info(dev, "[%s, %d] I send high_reset req, but not accepted by FW in time, maybe FW is already in high_reset\n",
							__func__, __LINE__);
			ret = 0;
			goto out;
		} else if (detail_status == NSE_FWMNG_STATUS_EXIST_OLD_RSP) {
			rsp_id = NSE_FWMNG_CMD_REQ_RSP_GET_ID(cmd_rsp.rsp);
			if (rsp_id == fwmng_cmd_id_high_reset) {
				dev_info(dev, "[%s, %d] detect OLD_RSP high_reset (type=0x%X, reset_status=0x%X)\n",
								__func__, __LINE__,
								cmd_rsp.rsp_buf[0],
									cmd_rsp.rsp_buf[2]);
				ret = 0;
				goto out;
			} else {
				/* clear rsp and retry */
				fwmng_clear_rsp(hw, true, NSE_FWMNG_CLEAR_RSP_VALID_ONLY);
				goto retry;
			}
		} else {
			dev_info(dev, "[%s, %d] some impossible cornercase ? ret=%d, detail_status=%d\n",
							__func__, __LINE__, ret, detail_status);
			goto out;
		}
	}

out:
	if (!fwmng_locked)
		mutex_unlock(&hw->fwmng_lock);

	return ret;
}

