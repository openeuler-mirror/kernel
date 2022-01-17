// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/completion.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/delay.h>

#include "sphw_crm.h"
#include "sphw_hw.h"
#include "sphw_hwdev.h"
#include "sphw_eqs.h"
#include "sphw_common.h"
#include "sphw_wq.h"
#include "sphw_hw_comm.h"
#include "sphw_cmdq.h"

#define	SPHW_CMDQ_BUF_SIZE				2048U
#define SPHW_CMDQ_BUF_HW_RSVD				8
#define SPHW_CMDQ_MAX_DATA_SIZE			\
			(SPHW_CMDQ_BUF_SIZE - SPHW_CMDQ_BUF_HW_RSVD)

#define CMDQ_CMD_TIMEOUT				300000 /* millisecond */

#define UPPER_8_BITS(data)				(((data) >> 8) & 0xFF)
#define LOWER_8_BITS(data)				((data) & 0xFF)

#define CMDQ_DB_INFO_HI_PROD_IDX_SHIFT			0
#define CMDQ_DB_INFO_HI_PROD_IDX_MASK			0xFFU
#define CMDQ_DB_INFO_SET(val, member)			\
			((((u32)(val)) & CMDQ_DB_INFO_##member##_MASK) << \
			 CMDQ_DB_INFO_##member##_SHIFT)

#define CMDQ_DB_HEAD_QUEUE_TYPE_SHIFT			23
#define CMDQ_DB_HEAD_CMDQ_TYPE_SHIFT			24
#define CMDQ_DB_HEAD_SRC_TYPE_SHIFT			27
#define CMDQ_DB_HEAD_QUEUE_TYPE_MASK			0x1U
#define CMDQ_DB_HEAD_CMDQ_TYPE_MASK			0x7U
#define CMDQ_DB_HEAD_SRC_TYPE_MASK			0x1FU
#define CMDQ_DB_HEAD_SET(val, member)			\
			((((u32)(val)) & CMDQ_DB_HEAD_##member##_MASK) << \
			 CMDQ_DB_HEAD_##member##_SHIFT)

#define CMDQ_CTRL_PI_SHIFT				0
#define CMDQ_CTRL_CMD_SHIFT				16
#define CMDQ_CTRL_MOD_SHIFT				24
#define CMDQ_CTRL_ACK_TYPE_SHIFT			29
#define CMDQ_CTRL_HW_BUSY_BIT_SHIFT			31

#define CMDQ_CTRL_PI_MASK				0xFFFFU
#define CMDQ_CTRL_CMD_MASK				0xFFU
#define CMDQ_CTRL_MOD_MASK				0x1FU
#define CMDQ_CTRL_ACK_TYPE_MASK				0x3U
#define CMDQ_CTRL_HW_BUSY_BIT_MASK			0x1U

#define CMDQ_CTRL_SET(val, member)			\
			((((u32)(val)) & CMDQ_CTRL_##member##_MASK) << \
			 CMDQ_CTRL_##member##_SHIFT)

#define CMDQ_CTRL_GET(val, member)			\
			(((val) >> CMDQ_CTRL_##member##_SHIFT) & \
			 CMDQ_CTRL_##member##_MASK)

#define CMDQ_WQE_HEADER_BUFDESC_LEN_SHIFT		0
#define CMDQ_WQE_HEADER_COMPLETE_FMT_SHIFT		15
#define CMDQ_WQE_HEADER_DATA_FMT_SHIFT			22
#define CMDQ_WQE_HEADER_COMPLETE_REQ_SHIFT		23
#define CMDQ_WQE_HEADER_COMPLETE_SECT_LEN_SHIFT		27
#define CMDQ_WQE_HEADER_CTRL_LEN_SHIFT			29
#define CMDQ_WQE_HEADER_HW_BUSY_BIT_SHIFT		31

#define CMDQ_WQE_HEADER_BUFDESC_LEN_MASK		0xFFU
#define CMDQ_WQE_HEADER_COMPLETE_FMT_MASK		0x1U
#define CMDQ_WQE_HEADER_DATA_FMT_MASK			0x1U
#define CMDQ_WQE_HEADER_COMPLETE_REQ_MASK		0x1U
#define CMDQ_WQE_HEADER_COMPLETE_SECT_LEN_MASK		0x3U
#define CMDQ_WQE_HEADER_CTRL_LEN_MASK			0x3U
#define CMDQ_WQE_HEADER_HW_BUSY_BIT_MASK		0x1U

#define CMDQ_WQE_HEADER_SET(val, member)		\
			((((u32)(val)) & CMDQ_WQE_HEADER_##member##_MASK) << \
			 CMDQ_WQE_HEADER_##member##_SHIFT)

#define CMDQ_WQE_HEADER_GET(val, member)		\
			(((val) >> CMDQ_WQE_HEADER_##member##_SHIFT) & \
			 CMDQ_WQE_HEADER_##member##_MASK)

#define CMDQ_CTXT_CURR_WQE_PAGE_PFN_SHIFT		0
#define CMDQ_CTXT_EQ_ID_SHIFT				53
#define CMDQ_CTXT_CEQ_ARM_SHIFT				61
#define CMDQ_CTXT_CEQ_EN_SHIFT				62
#define CMDQ_CTXT_HW_BUSY_BIT_SHIFT			63

#define CMDQ_CTXT_CURR_WQE_PAGE_PFN_MASK		0xFFFFFFFFFFFFF
#define CMDQ_CTXT_EQ_ID_MASK				0xFF
#define CMDQ_CTXT_CEQ_ARM_MASK				0x1
#define CMDQ_CTXT_CEQ_EN_MASK				0x1
#define CMDQ_CTXT_HW_BUSY_BIT_MASK			0x1

#define CMDQ_CTXT_PAGE_INFO_SET(val, member)		\
			(((u64)(val) & CMDQ_CTXT_##member##_MASK) << \
			 CMDQ_CTXT_##member##_SHIFT)

#define CMDQ_CTXT_PAGE_INFO_GET(val, member)		\
			(((u64)(val) >> CMDQ_CTXT_##member##_SHIFT) & \
			 CMDQ_CTXT_##member##_MASK)

#define CMDQ_CTXT_WQ_BLOCK_PFN_SHIFT			0
#define CMDQ_CTXT_CI_SHIFT				52

#define CMDQ_CTXT_WQ_BLOCK_PFN_MASK			0xFFFFFFFFFFFFF
#define CMDQ_CTXT_CI_MASK				0xFFF

#define CMDQ_CTXT_BLOCK_INFO_SET(val, member)		\
			(((u64)(val) & CMDQ_CTXT_##member##_MASK) << \
			 CMDQ_CTXT_##member##_SHIFT)

#define CMDQ_CTXT_BLOCK_INFO_GET(val, member)		\
			(((u64)(val) >> CMDQ_CTXT_##member##_SHIFT) & \
			 CMDQ_CTXT_##member##_MASK)

#define SAVED_DATA_ARM_SHIFT				31

#define SAVED_DATA_ARM_MASK				0x1U

#define SAVED_DATA_SET(val, member)			\
			(((val) & SAVED_DATA_##member##_MASK) << \
			 SAVED_DATA_##member##_SHIFT)

#define SAVED_DATA_CLEAR(val, member)			\
			((val) & (~(SAVED_DATA_##member##_MASK << \
				    SAVED_DATA_##member##_SHIFT)))

#define WQE_ERRCODE_VAL_SHIFT				0

#define WQE_ERRCODE_VAL_MASK				0x7FFFFFFF

#define WQE_ERRCODE_GET(val, member)	\
			(((val) >> WQE_ERRCODE_##member##_SHIFT) & \
			 WQE_ERRCODE_##member##_MASK)

#define CEQE_CMDQ_TYPE_SHIFT				0

#define CEQE_CMDQ_TYPE_MASK				0x7

#define CEQE_CMDQ_GET(val, member)	\
			(((val) >> CEQE_CMDQ_##member##_SHIFT) & \
			 CEQE_CMDQ_##member##_MASK)

#define WQE_COMPLETED(ctrl_info)	CMDQ_CTRL_GET(ctrl_info, HW_BUSY_BIT)

#define WQE_HEADER(wqe)			((struct sphw_cmdq_header *)(wqe))

#define CMDQ_DB_PI_OFF(pi)		(((u16)LOWER_8_BITS(pi)) << 3)

#define CMDQ_DB_ADDR(db_base, pi)	\
			(((u8 *)(db_base)) + CMDQ_DB_PI_OFF(pi))

#define CMDQ_PFN_SHIFT			12
#define CMDQ_PFN(addr)			((addr) >> CMDQ_PFN_SHIFT)

#define FIRST_DATA_TO_WRITE_LAST	sizeof(u64)

#define WQE_LCMD_SIZE			64
#define WQE_SCMD_SIZE			64

#define COMPLETE_LEN			3

#define CMDQ_WQEBB_SIZE			64
#define CMDQ_WQE_SIZE			64

#define cmdq_to_cmdqs(cmdq)	container_of((cmdq) - (cmdq)->cmdq_type, \
					     struct sphw_cmdqs, cmdq[0])

#define CMDQ_SEND_CMPT_CODE		10
#define CMDQ_COMPLETE_CMPT_CODE		11
#define CMDQ_FORCE_STOP_CMPT_CODE	12

enum cmdq_scmd_type {
	CMDQ_SET_ARM_CMD = 2,
};

enum cmdq_wqe_type {
	WQE_LCMD_TYPE,
	WQE_SCMD_TYPE,
};

enum ctrl_sect_len {
	CTRL_SECT_LEN = 1,
	CTRL_DIRECT_SECT_LEN = 2,
};

enum bufdesc_len {
	BUFDESC_LCMD_LEN = 2,
	BUFDESC_SCMD_LEN = 3,
};

enum data_format {
	DATA_SGE,
	DATA_DIRECT,
};

enum completion_format {
	COMPLETE_DIRECT,
	COMPLETE_SGE,
};

enum completion_request {
	CEQ_SET = 1,
};

enum cmdq_cmd_type {
	SYNC_CMD_DIRECT_RESP,
	SYNC_CMD_SGE_RESP,
	ASYNC_CMD,
};

#define NUM_WQEBBS_FOR_CMDQ_WQE		1

bool sphw_cmdq_idle(struct sphw_cmdq *cmdq)
{
	return sphw_wq_is_empty(&cmdq->wq);
}

static void *cmdq_read_wqe(struct sphw_wq *wq, u16 *ci)
{
	if (sphw_wq_is_empty(wq))
		return NULL;

	return sphw_wq_read_one_wqebb(wq, ci);
}

static void *cmdq_get_wqe(struct sphw_wq *wq, u16 *pi)
{
	if (!sphw_wq_free_wqebbs(wq))
		return NULL;

	return sphw_wq_get_one_wqebb(wq, pi);
}

struct sphw_cmd_buf *sphw_alloc_cmd_buf(void *hwdev)
{
	struct sphw_cmdqs *cmdqs = NULL;
	struct sphw_cmd_buf *cmd_buf = NULL;
	void *dev = NULL;

	if (!hwdev) {
		pr_err("Failed to alloc cmd buf, Invalid hwdev\n");
		return NULL;
	}

	cmdqs = ((struct sphw_hwdev *)hwdev)->cmdqs;
	dev = ((struct sphw_hwdev *)hwdev)->dev_hdl;

	cmd_buf = kzalloc(sizeof(*cmd_buf), GFP_ATOMIC);
	if (!cmd_buf) {
		sdk_err(dev, "Failed to allocate cmd buf\n");
		return NULL;
	}

	cmd_buf->buf = pci_pool_alloc(cmdqs->cmd_buf_pool, GFP_ATOMIC,
				      &cmd_buf->dma_addr);
	if (!cmd_buf->buf) {
		sdk_err(dev, "Failed to allocate cmdq cmd buf from the pool\n");
		goto alloc_pci_buf_err;
	}

	atomic_set(&cmd_buf->ref_cnt, 1);

	return cmd_buf;

alloc_pci_buf_err:
	kfree(cmd_buf);
	return NULL;
}

void sphw_free_cmd_buf(void *hwdev, struct sphw_cmd_buf *cmd_buf)
{
	struct sphw_cmdqs *cmdqs = NULL;

	if (!hwdev || !cmd_buf) {
		pr_err("Failed to free cmd buf: hwdev: %p, cmd_buf: %p\n",
		       hwdev, cmd_buf);
		return;
	}

	if (!atomic_dec_and_test(&cmd_buf->ref_cnt))
		return;

	cmdqs = ((struct sphw_hwdev *)hwdev)->cmdqs;

	pci_pool_free(cmdqs->cmd_buf_pool, cmd_buf->buf, cmd_buf->dma_addr);
	kfree(cmd_buf);
}

static void cmdq_set_completion(struct sphw_cmdq_completion *complete,
				struct sphw_cmd_buf *buf_out)
{
	struct sphw_sge_resp *sge_resp = &complete->sge_resp;

	sphw_set_sge(&sge_resp->sge, buf_out->dma_addr, SPHW_CMDQ_BUF_SIZE);
}

static void cmdq_set_lcmd_bufdesc(struct sphw_cmdq_wqe_lcmd *wqe,
				  struct sphw_cmd_buf *buf_in)
{
	sphw_set_sge(&wqe->buf_desc.sge, buf_in->dma_addr, buf_in->size);
}

static void cmdq_set_inline_wqe_data(struct sphw_cmdq_inline_wqe *wqe,
				     const void *buf_in, u32 in_size)
{
	struct sphw_cmdq_wqe_scmd *wqe_scmd = &wqe->wqe_scmd;

	wqe_scmd->buf_desc.buf_len = in_size;
	memcpy(wqe_scmd->buf_desc.data, buf_in, in_size);
}

static void cmdq_fill_db(struct sphw_cmdq_db *db,
			 enum sphw_cmdq_type cmdq_type, u16 prod_idx)
{
	db->db_info = CMDQ_DB_INFO_SET(UPPER_8_BITS(prod_idx), HI_PROD_IDX);

	db->db_head = CMDQ_DB_HEAD_SET(SPHW_DB_CMDQ_TYPE, QUEUE_TYPE) |
			CMDQ_DB_HEAD_SET(cmdq_type, CMDQ_TYPE)		|
			CMDQ_DB_HEAD_SET(SPHW_DB_SRC_CMDQ_TYPE, SRC_TYPE);
}

static void cmdq_set_db(struct sphw_cmdq *cmdq,
			enum sphw_cmdq_type cmdq_type, u16 prod_idx)
{
	struct sphw_cmdq_db db = {0};

	cmdq_fill_db(&db, cmdq_type, prod_idx);

	wmb();	/* write all before the doorbell */
	writeq(*((u64 *)&db), CMDQ_DB_ADDR(cmdq->db_base, prod_idx));
}

static void cmdq_wqe_fill(void *dst, const void *src)
{
	memcpy((u8 *)dst + FIRST_DATA_TO_WRITE_LAST,
	       (u8 *)src + FIRST_DATA_TO_WRITE_LAST,
	       CMDQ_WQE_SIZE - FIRST_DATA_TO_WRITE_LAST);

	wmb();	/* The first 8 bytes should be written last */

	*(u64 *)dst = *(u64 *)src;
}

static void cmdq_prepare_wqe_ctrl(struct sphw_cmdq_wqe *wqe, int wrapped,
				  u8 mod, u8 cmd, u16 prod_idx,
				  enum completion_format complete_format,
				  enum data_format data_format,
				  enum bufdesc_len buf_len)
{
	struct sphw_ctrl *ctrl = NULL;
	enum ctrl_sect_len ctrl_len;
	struct sphw_cmdq_wqe_lcmd *wqe_lcmd = NULL;
	struct sphw_cmdq_wqe_scmd *wqe_scmd = NULL;
	u32 saved_data = WQE_HEADER(wqe)->saved_data;

	if (data_format == DATA_SGE) {
		wqe_lcmd = &wqe->wqe_lcmd;

		wqe_lcmd->status.status_info = 0;
		ctrl = &wqe_lcmd->ctrl;
		ctrl_len = CTRL_SECT_LEN;
	} else {
		wqe_scmd = &wqe->inline_wqe.wqe_scmd;

		wqe_scmd->status.status_info = 0;
		ctrl = &wqe_scmd->ctrl;
		ctrl_len = CTRL_DIRECT_SECT_LEN;
	}

	ctrl->ctrl_info = CMDQ_CTRL_SET(prod_idx, PI)		|
			CMDQ_CTRL_SET(cmd, CMD)			|
			CMDQ_CTRL_SET(mod, MOD);

	WQE_HEADER(wqe)->header_info =
		CMDQ_WQE_HEADER_SET(buf_len, BUFDESC_LEN)	|
		CMDQ_WQE_HEADER_SET(complete_format, COMPLETE_FMT) |
		CMDQ_WQE_HEADER_SET(data_format, DATA_FMT)	|
		CMDQ_WQE_HEADER_SET(CEQ_SET, COMPLETE_REQ)	|
		CMDQ_WQE_HEADER_SET(COMPLETE_LEN, COMPLETE_SECT_LEN) |
		CMDQ_WQE_HEADER_SET(ctrl_len, CTRL_LEN)		|
		CMDQ_WQE_HEADER_SET((u32)wrapped, HW_BUSY_BIT);

	if (cmd == CMDQ_SET_ARM_CMD && mod == SPHW_MOD_COMM) {
		saved_data &= SAVED_DATA_CLEAR(saved_data, ARM);
		WQE_HEADER(wqe)->saved_data = saved_data	|
						SAVED_DATA_SET(1, ARM);
	} else {
		saved_data &= SAVED_DATA_CLEAR(saved_data, ARM);
		WQE_HEADER(wqe)->saved_data = saved_data;
	}
}

static void cmdq_set_lcmd_wqe(struct sphw_cmdq_wqe *wqe,
			      enum cmdq_cmd_type cmd_type,
			      struct sphw_cmd_buf *buf_in,
			      struct sphw_cmd_buf *buf_out, int wrapped,
			      u8 mod, u8 cmd, u16 prod_idx)
{
	struct sphw_cmdq_wqe_lcmd *wqe_lcmd = &wqe->wqe_lcmd;
	enum completion_format complete_format = COMPLETE_DIRECT;

	switch (cmd_type) {
	case SYNC_CMD_DIRECT_RESP:
		wqe_lcmd->completion.direct_resp = 0;
		break;
	case SYNC_CMD_SGE_RESP:
		if (buf_out) {
			complete_format = COMPLETE_SGE;
			cmdq_set_completion(&wqe_lcmd->completion,
					    buf_out);
		}
		break;
	case ASYNC_CMD:
		wqe_lcmd->completion.direct_resp = 0;
		wqe_lcmd->buf_desc.saved_async_buf = (u64)(buf_in);
		break;
	}

	cmdq_prepare_wqe_ctrl(wqe, wrapped, mod, cmd, prod_idx, complete_format,
			      DATA_SGE, BUFDESC_LCMD_LEN);

	cmdq_set_lcmd_bufdesc(wqe_lcmd, buf_in);
}

static void cmdq_set_inline_wqe(struct sphw_cmdq_wqe *wqe,
				enum cmdq_cmd_type cmd_type,
				const void *buf_in, u16 in_size,
				struct sphw_cmd_buf *buf_out, int wrapped,
				u8 mod, u8 cmd, u16 prod_idx)
{
	struct sphw_cmdq_wqe_scmd *wqe_scmd = &wqe->inline_wqe.wqe_scmd;
	enum completion_format complete_format = COMPLETE_DIRECT;

	switch (cmd_type) {
	case SYNC_CMD_SGE_RESP:
		complete_format = COMPLETE_SGE;
		cmdq_set_completion(&wqe_scmd->completion, buf_out);
		break;
	case SYNC_CMD_DIRECT_RESP:
		complete_format = COMPLETE_DIRECT;
		wqe_scmd->completion.direct_resp = 0;
		break;
	default:
		break;
	}

	cmdq_prepare_wqe_ctrl(wqe, wrapped, mod, cmd, prod_idx,
			      complete_format, DATA_DIRECT, BUFDESC_SCMD_LEN);

	cmdq_set_inline_wqe_data(&wqe->inline_wqe, buf_in, in_size);
}

static void cmdq_update_cmd_status(struct sphw_cmdq *cmdq, u16 prod_idx,
				   struct sphw_cmdq_wqe *wqe)
{
	struct sphw_cmdq_cmd_info *cmd_info;
	struct sphw_cmdq_wqe_lcmd *wqe_lcmd;
	u32 status_info;

	wqe_lcmd = &wqe->wqe_lcmd;
	cmd_info = &cmdq->cmd_infos[prod_idx];

	if (cmd_info->errcode) {
		status_info = wqe_lcmd->status.status_info;
		*cmd_info->errcode = WQE_ERRCODE_GET(status_info, VAL);
	}

	if (cmd_info->direct_resp)
		*cmd_info->direct_resp = wqe_lcmd->completion.direct_resp;
}

static int sphw_cmdq_sync_timeout_check(struct sphw_cmdq *cmdq, struct sphw_cmdq_wqe *wqe, u16 pi)
{
	struct sphw_cmdq_wqe_lcmd *wqe_lcmd;
	u32 ctrl_info;

	wqe_lcmd = &wqe->wqe_lcmd;
	ctrl_info = wqe_lcmd->ctrl.ctrl_info;
	if (!WQE_COMPLETED(ctrl_info)) {
		sdk_info(cmdq->hwdev->dev_hdl, "Cmdq sync command check busy bit not set\n");
		return -EFAULT;
	}

	cmdq_update_cmd_status(cmdq, pi, wqe);

	sdk_info(cmdq->hwdev->dev_hdl, "Cmdq sync command check succeed\n");
	return 0;
}

static void clear_cmd_info(struct sphw_cmdq_cmd_info *cmd_info,
			   struct sphw_cmdq_cmd_info *saved_cmd_info)
{
	if (cmd_info->errcode == saved_cmd_info->errcode)
		cmd_info->errcode = NULL;

	if (cmd_info->done == saved_cmd_info->done)
		cmd_info->done = NULL;

	if (cmd_info->direct_resp == saved_cmd_info->direct_resp)
		cmd_info->direct_resp = NULL;
}

static int cmdq_ceq_handler_status(struct sphw_cmdq *cmdq,
				   struct sphw_cmdq_cmd_info *cmd_info,
				   struct sphw_cmdq_cmd_info *saved_cmd_info,
				   u64 curr_msg_id, u16 curr_prod_idx,
				   struct sphw_cmdq_wqe *curr_wqe,
				   u32 timeout)
{
	ulong timeo;
	int err;

	timeo = msecs_to_jiffies(timeout);
	if (wait_for_completion_timeout(saved_cmd_info->done, timeo))
		return 0;

	spin_lock_bh(&cmdq->cmdq_lock);

	if (cmd_info->cmpt_code == saved_cmd_info->cmpt_code)
		cmd_info->cmpt_code = NULL;

	if (*saved_cmd_info->cmpt_code == CMDQ_COMPLETE_CMPT_CODE) {
		sdk_info(cmdq->hwdev->dev_hdl, "Cmdq direct sync command has been completed\n");
		spin_unlock_bh(&cmdq->cmdq_lock);
		return 0;
	}

	if (curr_msg_id == cmd_info->cmdq_msg_id) {
		err = sphw_cmdq_sync_timeout_check(cmdq, curr_wqe, curr_prod_idx);
		if (err)
			cmd_info->cmd_type = SPHW_CMD_TYPE_TIMEOUT;
		else
			cmd_info->cmd_type = SPHW_CMD_TYPE_FAKE_TIMEOUT;
	} else {
		err = -ETIMEDOUT;
		sdk_err(cmdq->hwdev->dev_hdl, "Cmdq sync command current msg id dismatch with cmd_info msg id\n");
	}

	clear_cmd_info(cmd_info, saved_cmd_info);

	spin_unlock_bh(&cmdq->cmdq_lock);

	if (!err)
		return 0;

	sphw_dump_ceq_info(cmdq->hwdev);

	return -ETIMEDOUT;
}

static int wait_cmdq_sync_cmd_completion(struct sphw_cmdq *cmdq,
					 struct sphw_cmdq_cmd_info *cmd_info,
					 struct sphw_cmdq_cmd_info *saved_cmd_info,
					 u64 curr_msg_id, u16 curr_prod_idx,
					 struct sphw_cmdq_wqe *curr_wqe, u32 timeout)
{
	return cmdq_ceq_handler_status(cmdq, cmd_info, saved_cmd_info,
				       curr_msg_id, curr_prod_idx,
				       curr_wqe, timeout);
}

static int cmdq_msg_lock(struct sphw_cmdq *cmdq, u16 channel)
{
	struct sphw_cmdqs *cmdqs = cmdq_to_cmdqs(cmdq);

	/* Keep wrapped and doorbell index correct. bh - for tasklet(ceq) */
	spin_lock_bh(&cmdq->cmdq_lock);

	if (cmdqs->lock_channel_en && test_bit(channel, &cmdqs->channel_stop)) {
		spin_unlock_bh(&cmdq->cmdq_lock);
		return -EAGAIN;
	}

	return 0;
}

static void cmdq_msg_unlock(struct sphw_cmdq *cmdq)
{
	spin_unlock_bh(&cmdq->cmdq_lock);
}

static void cmdq_clear_cmd_buf(struct sphw_cmdq_cmd_info *cmd_info,
			       struct sphw_hwdev *hwdev)
{
	if (cmd_info->buf_in)
		sphw_free_cmd_buf(hwdev, cmd_info->buf_in);

	if (cmd_info->buf_out)
		sphw_free_cmd_buf(hwdev, cmd_info->buf_out);

	cmd_info->buf_in = NULL;
	cmd_info->buf_out = NULL;
}

static void cmdq_set_cmd_buf(struct sphw_cmdq_cmd_info *cmd_info,
			     struct sphw_hwdev *hwdev,
			     struct sphw_cmd_buf *buf_in,
			     struct sphw_cmd_buf *buf_out)
{
	cmd_info->buf_in = buf_in;
	cmd_info->buf_out = buf_out;

	if (buf_in)
		atomic_inc(&buf_in->ref_cnt);

	if (buf_out)
		atomic_inc(&buf_out->ref_cnt);
}

static int cmdq_sync_cmd_direct_resp(struct sphw_cmdq *cmdq, u8 mod,
				     u8 cmd, struct sphw_cmd_buf *buf_in,
				     u64 *out_param, u32 timeout, u16 channel)
{
	struct sphw_wq *wq = &cmdq->wq;
	struct sphw_cmdq_wqe *curr_wqe = NULL, wqe;
	struct sphw_cmdq_cmd_info *cmd_info = NULL, saved_cmd_info;
	struct completion done;
	u16 curr_prod_idx, next_prod_idx;
	int wrapped, errcode = 0;
	int cmpt_code = CMDQ_SEND_CMPT_CODE;
	u64 curr_msg_id;
	int err;

	err = cmdq_msg_lock(cmdq, channel);
	if (err)
		return err;

	curr_wqe = cmdq_get_wqe(wq, &curr_prod_idx);
	if (!curr_wqe) {
		cmdq_msg_unlock(cmdq);
		return -EBUSY;
	}

	memset(&wqe, 0, sizeof(wqe));

	wrapped = cmdq->wrapped;

	next_prod_idx = curr_prod_idx + NUM_WQEBBS_FOR_CMDQ_WQE;
	if (next_prod_idx >= wq->q_depth) {
		cmdq->wrapped = !cmdq->wrapped;
		next_prod_idx -= (u16)wq->q_depth;
	}

	cmd_info = &cmdq->cmd_infos[curr_prod_idx];

	init_completion(&done);

	cmd_info->cmd_type = SPHW_CMD_TYPE_DIRECT_RESP;
	cmd_info->done = &done;
	cmd_info->errcode = &errcode;
	cmd_info->direct_resp = out_param;
	cmd_info->cmpt_code = &cmpt_code;
	cmd_info->channel = channel;
	cmdq_set_cmd_buf(cmd_info, cmdq->hwdev, buf_in, NULL);

	memcpy(&saved_cmd_info, cmd_info, sizeof(*cmd_info));

	cmdq_set_lcmd_wqe(&wqe, SYNC_CMD_DIRECT_RESP, buf_in, NULL,
			  wrapped, mod, cmd, curr_prod_idx);

	/* CMDQ WQE is not shadow, therefore wqe will be written to wq */
	cmdq_wqe_fill(curr_wqe, &wqe);

	(cmd_info->cmdq_msg_id)++;
	curr_msg_id = cmd_info->cmdq_msg_id;

	cmdq_set_db(cmdq, SPHW_CMDQ_SYNC, next_prod_idx);

	cmdq_msg_unlock(cmdq);

	timeout = timeout ? timeout : CMDQ_CMD_TIMEOUT;
	err = wait_cmdq_sync_cmd_completion(cmdq, cmd_info, &saved_cmd_info,
					    curr_msg_id, curr_prod_idx,
					    curr_wqe, timeout);
	if (err) {
		sdk_err(cmdq->hwdev->dev_hdl, "Cmdq sync command(mod: %u, cmd: %u) timeout, prod idx: 0x%x\n",
			mod, cmd, curr_prod_idx);
		err = -ETIMEDOUT;
	}

	if (cmpt_code == CMDQ_FORCE_STOP_CMPT_CODE) {
		sdk_info(cmdq->hwdev->dev_hdl, "Force stop cmdq cmd, mod: %u, cmd: %u\n",
			 mod, cmd);
		err = -EAGAIN;
	}

	smp_rmb();	/* read error code after completion */

	return err ? err : errcode;
}

static int cmdq_sync_cmd_detail_resp(struct sphw_cmdq *cmdq, u8 mod, u8 cmd,
				     struct sphw_cmd_buf *buf_in,
				     struct sphw_cmd_buf *buf_out,
				     u64 *out_param, u32 timeout, u16 channel)
{
	struct sphw_wq *wq = &cmdq->wq;
	struct sphw_cmdq_wqe *curr_wqe = NULL, wqe;
	struct sphw_cmdq_cmd_info *cmd_info = NULL, saved_cmd_info;
	struct completion done;
	u16 curr_prod_idx, next_prod_idx;
	int wrapped, errcode = 0;
	int cmpt_code = CMDQ_SEND_CMPT_CODE;
	u64 curr_msg_id;
	int err;

	err = cmdq_msg_lock(cmdq, channel);
	if (err)
		return err;

	curr_wqe = cmdq_get_wqe(wq, &curr_prod_idx);
	if (!curr_wqe) {
		cmdq_msg_unlock(cmdq);
		return -EBUSY;
	}

	memset(&wqe, 0, sizeof(wqe));

	wrapped = cmdq->wrapped;

	next_prod_idx = curr_prod_idx + NUM_WQEBBS_FOR_CMDQ_WQE;
	if (next_prod_idx >= wq->q_depth) {
		cmdq->wrapped = !cmdq->wrapped;
		next_prod_idx -= (u16)wq->q_depth;
	}

	cmd_info = &cmdq->cmd_infos[curr_prod_idx];

	init_completion(&done);

	cmd_info->cmd_type = SPHW_CMD_TYPE_SGE_RESP;
	cmd_info->done = &done;
	cmd_info->errcode = &errcode;
	cmd_info->direct_resp = out_param;
	cmd_info->cmpt_code = &cmpt_code;
	cmd_info->channel = channel;
	cmdq_set_cmd_buf(cmd_info, cmdq->hwdev, buf_in, buf_out);

	memcpy(&saved_cmd_info, cmd_info, sizeof(*cmd_info));

	cmdq_set_lcmd_wqe(&wqe, SYNC_CMD_SGE_RESP, buf_in, buf_out,
			  wrapped, mod, cmd, curr_prod_idx);

	cmdq_wqe_fill(curr_wqe, &wqe);

	(cmd_info->cmdq_msg_id)++;
	curr_msg_id = cmd_info->cmdq_msg_id;

	cmdq_set_db(cmdq, cmdq->cmdq_type, next_prod_idx);

	cmdq_msg_unlock(cmdq);

	timeout = timeout ? timeout : CMDQ_CMD_TIMEOUT;
	err = wait_cmdq_sync_cmd_completion(cmdq, cmd_info, &saved_cmd_info,
					    curr_msg_id, curr_prod_idx,
					    curr_wqe, timeout);
	if (err) {
		sdk_err(cmdq->hwdev->dev_hdl, "Cmdq sync command(mod: %u, cmd: %u) timeout, prod idx: 0x%x\n",
			mod, cmd, curr_prod_idx);
		err = -ETIMEDOUT;
	}

	if (cmpt_code == CMDQ_FORCE_STOP_CMPT_CODE) {
		sdk_info(cmdq->hwdev->dev_hdl, "Force stop cmdq cmd, mod: %u, cmd: %u\n",
			 mod, cmd);
		err = -EAGAIN;
	}

	smp_rmb();	/* read error code after completion */

	return err ? err : errcode;
}

static int cmdq_async_cmd(struct sphw_cmdq *cmdq, u8 mod, u8 cmd,
			  struct sphw_cmd_buf *buf_in, u16 channel)
{
	struct sphw_cmdq_cmd_info *cmd_info = NULL;
	struct sphw_wq *wq = &cmdq->wq;
	u16 curr_prod_idx, next_prod_idx;
	struct sphw_cmdq_wqe *curr_wqe = NULL, wqe;
	int wrapped, err;

	err = cmdq_msg_lock(cmdq, channel);
	if (err)
		return err;

	curr_wqe = cmdq_get_wqe(wq, &curr_prod_idx);
	if (!curr_wqe) {
		cmdq_msg_unlock(cmdq);
		return -EBUSY;
	}

	memset(&wqe, 0, sizeof(wqe));

	wrapped = cmdq->wrapped;
	next_prod_idx = curr_prod_idx + NUM_WQEBBS_FOR_CMDQ_WQE;
	if (next_prod_idx >= wq->q_depth) {
		cmdq->wrapped = !cmdq->wrapped;
		next_prod_idx -= (u16)wq->q_depth;
	}

	cmdq_set_lcmd_wqe(&wqe, ASYNC_CMD, buf_in, NULL, wrapped,
			  mod, cmd, curr_prod_idx);

	cmdq_wqe_fill(curr_wqe, &wqe);

	cmd_info = &cmdq->cmd_infos[curr_prod_idx];
	cmd_info->cmd_type = SPHW_CMD_TYPE_ASYNC;
	cmd_info->channel = channel;
	/* The caller will not free the cmd_buf of the asynchronous command,
	 * so there is no need to increase the reference count here
	 */
	cmd_info->buf_in = buf_in;

	/* LB mode 1 compatible, cmdq 0 also for async, which is sync_no_wait */
	cmdq_set_db(cmdq, SPHW_CMDQ_SYNC, next_prod_idx);

	cmdq_msg_unlock(cmdq);

	return 0;
}

int cmdq_set_arm_bit(struct sphw_cmdq *cmdq, const void *buf_in,
		     u16 in_size)
{
	struct sphw_wq *wq = &cmdq->wq;
	struct sphw_cmdq_wqe *curr_wqe = NULL, wqe;
	u16 curr_prod_idx, next_prod_idx;
	int wrapped;

	/* Keep wrapped and doorbell index correct. bh - for tasklet(ceq) */
	spin_lock_bh(&cmdq->cmdq_lock);

	curr_wqe = cmdq_get_wqe(wq, &curr_prod_idx);
	if (!curr_wqe) {
		spin_unlock_bh(&cmdq->cmdq_lock);
		return -EBUSY;
	}

	memset(&wqe, 0, sizeof(wqe));

	wrapped = cmdq->wrapped;

	next_prod_idx = curr_prod_idx + NUM_WQEBBS_FOR_CMDQ_WQE;
	if (next_prod_idx >= wq->q_depth) {
		cmdq->wrapped = !cmdq->wrapped;
		next_prod_idx -= (u16)wq->q_depth;
	}

	cmdq_set_inline_wqe(&wqe, SYNC_CMD_DIRECT_RESP, buf_in, in_size, NULL,
			    wrapped, SPHW_MOD_COMM, CMDQ_SET_ARM_CMD,
			    curr_prod_idx);

	/* cmdq wqe is not shadow, therefore wqe will be written to wq */
	cmdq_wqe_fill(curr_wqe, &wqe);

	cmdq->cmd_infos[curr_prod_idx].cmd_type = SPHW_CMD_TYPE_SET_ARM;

	cmdq_set_db(cmdq, cmdq->cmdq_type, next_prod_idx);

	spin_unlock_bh(&cmdq->cmdq_lock);

	return 0;
}

static int cmdq_params_valid(void *hwdev, struct sphw_cmd_buf *buf_in)
{
	if (!buf_in || !hwdev) {
		pr_err("Invalid CMDQ buffer addr: %p or hwdev: %p\n",
		       buf_in, hwdev);
		return -EINVAL;
	}

	if (!buf_in->size || buf_in->size > SPHW_CMDQ_MAX_DATA_SIZE) {
		pr_err("Invalid CMDQ buffer size: 0x%x\n", buf_in->size);
		return -EINVAL;
	}

	return 0;
}

#define WAIT_CMDQ_ENABLE_TIMEOUT	300
static int wait_cmdqs_enable(struct sphw_cmdqs *cmdqs)
{
	unsigned long end;

	end = jiffies + msecs_to_jiffies(WAIT_CMDQ_ENABLE_TIMEOUT);
	do {
		if (cmdqs->status & SPHW_CMDQ_ENABLE)
			return 0;
	} while (time_before(jiffies, end) && cmdqs->hwdev->chip_present_flag &&
		 !cmdqs->disable_flag);

	cmdqs->disable_flag = 1;

	return -EBUSY;
}

int sphw_cmdq_direct_resp(void *hwdev, u8 mod, u8 cmd, struct sphw_cmd_buf *buf_in,
			  u64 *out_param, u32 timeout, u16 channel)
{
	struct sphw_cmdqs *cmdqs = NULL;
	int err = cmdq_params_valid(hwdev, buf_in);

	if (err) {
		pr_err("Invalid CMDQ parameters\n");
		return err;
	}

	/* to do :  support send cmdq only when cmdq init*/
	if (!(((struct sphw_hwdev *)hwdev)->chip_present_flag))
		return -EPERM;

	cmdqs = ((struct sphw_hwdev *)hwdev)->cmdqs;
	err = wait_cmdqs_enable(cmdqs);
	if (err) {
		sdk_err(cmdqs->hwdev->dev_hdl, "Cmdq is disable\n");
		return err;
	}

	err = cmdq_sync_cmd_direct_resp(&cmdqs->cmdq[SPHW_CMDQ_SYNC],
					mod, cmd, buf_in, out_param,
					timeout, channel);

	if (!(((struct sphw_hwdev *)hwdev)->chip_present_flag))
		return -ETIMEDOUT;
	else
		return err;
}

int sphw_cmdq_detail_resp(void *hwdev, u8 mod, u8 cmd, struct sphw_cmd_buf *buf_in,
			  struct sphw_cmd_buf *buf_out, u64 *out_param, u32 timeout, u16 channel)
{
	struct sphw_cmdqs *cmdqs = NULL;
	int err = cmdq_params_valid(hwdev, buf_in);

	if (err)
		return err;

	cmdqs = ((struct sphw_hwdev *)hwdev)->cmdqs;

	if (!(((struct sphw_hwdev *)hwdev)->chip_present_flag)) /*to do*/
		return -EPERM;

	err = wait_cmdqs_enable(cmdqs);
	if (err) {
		sdk_err(cmdqs->hwdev->dev_hdl, "Cmdq is disable\n");
		return err;
	}

	err = cmdq_sync_cmd_detail_resp(&cmdqs->cmdq[SPHW_CMDQ_SYNC],
					mod, cmd, buf_in, buf_out, out_param,
					timeout, channel);
	if (!(((struct sphw_hwdev *)hwdev)->chip_present_flag))
		return -ETIMEDOUT;
	else
		return err;
}

int sphw_cos_id_detail_resp(void *hwdev, u8 mod, u8 cmd, u8 cos_id, struct sphw_cmd_buf *buf_in,
			    struct sphw_cmd_buf *buf_out, u64 *out_param, u32 timeout, u16 channel)
{
	struct sphw_cmdqs *cmdqs = NULL;
	int err = cmdq_params_valid(hwdev, buf_in);

	if (err)
		return err;

	cmdqs = ((struct sphw_hwdev *)hwdev)->cmdqs;

	if (!(((struct sphw_hwdev *)hwdev)->chip_present_flag)) /*to do*/
		return -EPERM;

	err = wait_cmdqs_enable(cmdqs);
	if (err) {
		sdk_err(cmdqs->hwdev->dev_hdl, "Cmdq is disable\n");
		return err;
	}

	if (cos_id >= SPHW_MAX_CMDQ_TYPES) {
		sdk_err(cmdqs->hwdev->dev_hdl, "Cmdq id is invalid\n");
		return -EINVAL;
	}

	err = cmdq_sync_cmd_detail_resp(&cmdqs->cmdq[cos_id], mod, cmd,
					buf_in, buf_out, out_param,
					timeout, channel);
	if (!(((struct sphw_hwdev *)hwdev)->chip_present_flag))
		return -ETIMEDOUT;
	else
		return err;
}

int sphw_cmdq_async(void *hwdev, u8 mod, u8 cmd, struct sphw_cmd_buf *buf_in, u16 channel)
{
	struct sphw_cmdqs *cmdqs = NULL;
	int err = cmdq_params_valid(hwdev, buf_in);

	if (err)
		return err;

	cmdqs = ((struct sphw_hwdev *)hwdev)->cmdqs;

	if (!(((struct sphw_hwdev *)hwdev)->chip_present_flag)) /*to do*/
		return -EPERM;

	err = wait_cmdqs_enable(cmdqs);
	if (err) {
		sdk_err(cmdqs->hwdev->dev_hdl, "Cmdq is disable\n");
		return err;
	}
	/* LB mode 1 compatible, cmdq 0 also for async, which is sync_no_wait*/
	return cmdq_async_cmd(&cmdqs->cmdq[SPHW_CMDQ_SYNC], mod,
			      cmd, buf_in, channel);
}

int sphw_set_arm_bit(void *hwdev, enum sphw_set_arm_type q_type, u16 q_id)
{
	struct sphw_cmdqs *cmdqs = NULL;
	struct sphw_cmdq *cmdq = NULL;
	struct sphw_cmdq_arm_bit arm_bit;
	enum sphw_cmdq_type cmdq_type = SPHW_CMDQ_SYNC;
	u16 in_size;
	int err;

	if (!hwdev)
		return -EINVAL;

	if (!(((struct sphw_hwdev *)hwdev)->chip_present_flag))/* to do*/
		return -EPERM;

	cmdqs = ((struct sphw_hwdev *)hwdev)->cmdqs;

	if (!(cmdqs->status & SPHW_CMDQ_ENABLE))
		return -EBUSY;

	if (q_type == SPHW_SET_ARM_CMDQ) {
		if (q_id >= SPHW_MAX_CMDQ_TYPES)
			return -EFAULT;

		cmdq_type = q_id;
	}
	/* sq is using interrupt now, so we only need to set arm bit for cmdq,
	 * remove comment below if need to set sq arm bit
	 * else
	 *	cmdq_type = SPHW_CMDQ_SYNC;
	 */

	cmdq = &cmdqs->cmdq[cmdq_type];

	arm_bit.q_type = q_type;
	arm_bit.q_id   = q_id;
	in_size = sizeof(arm_bit);

	err = cmdq_set_arm_bit(cmdq, &arm_bit, in_size);
	if (err) {
		sdk_err(cmdqs->hwdev->dev_hdl,
			"Failed to set arm for q_type: %d, qid %d\n",
			q_type, q_id);
		return err;
	}

	return 0;
}

static void clear_wqe_complete_bit(struct sphw_cmdq *cmdq,
				   struct sphw_cmdq_wqe *wqe, u16 ci)
{
	struct sphw_ctrl *ctrl = NULL;
	u32 header_info = WQE_HEADER(wqe)->header_info;
	enum data_format df = CMDQ_WQE_HEADER_GET(header_info, DATA_FMT);

	if (df == DATA_SGE)
		ctrl = &wqe->wqe_lcmd.ctrl;
	else
		ctrl = &wqe->inline_wqe.wqe_scmd.ctrl;

	/* clear HW busy bit */
	ctrl->ctrl_info = 0;
	cmdq->cmd_infos[ci].cmd_type = SPHW_CMD_TYPE_NONE;

	wmb();	/* verify wqe is clear */

	sphw_wq_put_wqebbs(&cmdq->wq, NUM_WQEBBS_FOR_CMDQ_WQE);
}

static void cmdq_sync_cmd_handler(struct sphw_cmdq *cmdq,
				  struct sphw_cmdq_wqe *wqe, u16 ci)
{
	spin_lock(&cmdq->cmdq_lock);

	cmdq_update_cmd_status(cmdq, ci, wqe);

	if (cmdq->cmd_infos[ci].cmpt_code) {
		*cmdq->cmd_infos[ci].cmpt_code = CMDQ_COMPLETE_CMPT_CODE;
		cmdq->cmd_infos[ci].cmpt_code = NULL;
	}

	/* make sure cmpt_code operation before done operation */
	smp_rmb();

	if (cmdq->cmd_infos[ci].done) {
		complete(cmdq->cmd_infos[ci].done);
		cmdq->cmd_infos[ci].done = NULL;
	}

	spin_unlock(&cmdq->cmdq_lock);

	cmdq_clear_cmd_buf(&cmdq->cmd_infos[ci], cmdq->hwdev);
	clear_wqe_complete_bit(cmdq, wqe, ci);
}

static void cmdq_async_cmd_handler(struct sphw_hwdev *hwdev,
				   struct sphw_cmdq *cmdq,
				   struct sphw_cmdq_wqe *wqe, u16 ci)
{
	cmdq_clear_cmd_buf(&cmdq->cmd_infos[ci], hwdev);
	clear_wqe_complete_bit(cmdq, wqe, ci);
}

static int cmdq_arm_ceq_handler(struct sphw_cmdq *cmdq,
				struct sphw_cmdq_wqe *wqe, u16 ci)
{
	struct sphw_ctrl *ctrl = &wqe->inline_wqe.wqe_scmd.ctrl;
	u32 ctrl_info = ctrl->ctrl_info;

	if (!WQE_COMPLETED(ctrl_info))
		return -EBUSY;

	clear_wqe_complete_bit(cmdq, wqe, ci);

	return 0;
}

#define SPHW_CMDQ_WQE_HEAD_LEN		32
static void sphw_dump_cmdq_wqe_head(struct sphw_hwdev *hwdev, struct sphw_cmdq_wqe *wqe)
{
	u32 i;
	u32 *data = (u32 *)wqe;

	for (i = 0; i < (SPHW_CMDQ_WQE_HEAD_LEN / sizeof(u32)); i += 4) {
		sdk_info(hwdev->dev_hdl, "wqe data: 0x%08x, 0x%08x, 0x%08x, 0x%08x\n",
			 *(data + i), *(data + i + 1), *(data + i + 2),
			 *(data + i + 3));
	}
}

void sphw_cmdq_ceq_handler(void *handle, u32 ceqe_data)
{
	struct sphw_cmdqs *cmdqs = ((struct sphw_hwdev *)handle)->cmdqs;
	enum sphw_cmdq_type cmdq_type = CEQE_CMDQ_GET(ceqe_data, TYPE);
	struct sphw_cmdq *cmdq = &cmdqs->cmdq[cmdq_type];
	struct sphw_hwdev *hwdev = cmdqs->hwdev;
	struct sphw_cmdq_wqe *wqe = NULL;
	struct sphw_cmdq_wqe_lcmd *wqe_lcmd = NULL;
	struct sphw_cmdq_cmd_info *cmd_info = NULL;
	u32 ctrl_info;
	u16 ci;

	while ((wqe = cmdq_read_wqe(&cmdq->wq, &ci)) != NULL) {
		cmd_info = &cmdq->cmd_infos[ci];

		switch (cmd_info->cmd_type) {
		case SPHW_CMD_TYPE_NONE:
			return;
		case SPHW_CMD_TYPE_TIMEOUT:
			sdk_warn(hwdev->dev_hdl, "Cmdq timeout, q_id: %u, ci: %u\n",
				 cmdq_type, ci);
			sphw_dump_cmdq_wqe_head(hwdev, wqe);
			fallthrough;
		case SPHW_CMD_TYPE_FAKE_TIMEOUT:
			cmdq_clear_cmd_buf(cmd_info, hwdev);
			clear_wqe_complete_bit(cmdq, wqe, ci);
			break;
		case SPHW_CMD_TYPE_SET_ARM:
			if (cmdq_arm_ceq_handler(cmdq, wqe, ci))
				return;

			break;
		default:
			/* only arm bit is using scmd wqe, the wqe is lcmd */
			wqe_lcmd = &wqe->wqe_lcmd;
			ctrl_info = wqe_lcmd->ctrl.ctrl_info;

			if (!WQE_COMPLETED(ctrl_info))
				return;

			/* For FORCE_STOP cmd_type, we also need to wait for
			 * the firmware processing to complete to prevent the
			 * firmware from accessing the released cmd_buf
			 */
			if (cmd_info->cmd_type == SPHW_CMD_TYPE_FORCE_STOP) {
				cmdq_clear_cmd_buf(cmd_info, hwdev);
				clear_wqe_complete_bit(cmdq, wqe, ci);
			} else if (cmd_info->cmd_type == SPHW_CMD_TYPE_ASYNC) {
				cmdq_async_cmd_handler(hwdev, cmdq, wqe, ci);
			} else {
				cmdq_sync_cmd_handler(cmdq, wqe, ci);
			}

			break;
		}
	}
}

static void cmdq_init_queue_ctxt(struct sphw_cmdqs *cmdqs,
				 struct sphw_cmdq *cmdq,
				 struct cmdq_ctxt_info *ctxt_info)
{
	struct sphw_wq *wq = &cmdq->wq;
	u64 cmdq_first_block_paddr, pfn;
	u16 start_ci = (u16)wq->cons_idx;

	pfn = CMDQ_PFN(sphw_wq_get_first_wqe_page_addr(wq));

	ctxt_info->curr_wqe_page_pfn =
		CMDQ_CTXT_PAGE_INFO_SET(1, HW_BUSY_BIT) |
		CMDQ_CTXT_PAGE_INFO_SET(1, CEQ_EN)	|
		CMDQ_CTXT_PAGE_INFO_SET(1, CEQ_ARM)	|
		CMDQ_CTXT_PAGE_INFO_SET(SPHW_CEQ_ID_CMDQ, EQ_ID) |
		CMDQ_CTXT_PAGE_INFO_SET(pfn, CURR_WQE_PAGE_PFN);

	if (!WQ_IS_0_LEVEL_CLA(wq)) {
		cmdq_first_block_paddr = cmdqs->wq_block_paddr;
		pfn = CMDQ_PFN(cmdq_first_block_paddr);
	}

	ctxt_info->wq_block_pfn = CMDQ_CTXT_BLOCK_INFO_SET(start_ci, CI) |
				CMDQ_CTXT_BLOCK_INFO_SET(pfn, WQ_BLOCK_PFN);
}

static int init_cmdq(struct sphw_cmdq *cmdq, struct sphw_hwdev *hwdev,
		     enum sphw_cmdq_type q_type)
{
	void __iomem *db_base;
	int err;

	cmdq->cmdq_type = q_type;
	cmdq->wrapped = 1;
	cmdq->hwdev = hwdev;

	spin_lock_init(&cmdq->cmdq_lock);

	cmdq->cmd_infos = kcalloc(cmdq->wq.q_depth, sizeof(*cmdq->cmd_infos),
				  GFP_KERNEL);
	if (!cmdq->cmd_infos) {
		sdk_err(hwdev->dev_hdl, "Failed to allocate cmdq infos\n");
		err = -ENOMEM;
		goto cmd_infos_err;
	}

	err = sphw_alloc_db_addr(hwdev, &db_base, NULL);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to allocate doorbell address\n");
		goto alloc_db_err;
	}

	cmdq->db_base = (u8 *)db_base;
	return 0;

alloc_db_err:
	kfree(cmdq->cmd_infos);

cmd_infos_err:

	return err;
}

static void free_cmdq(struct sphw_hwdev *hwdev, struct sphw_cmdq *cmdq)
{
	sphw_free_db_addr(hwdev, cmdq->db_base, NULL);
	kfree(cmdq->cmd_infos);
}

static int sphw_set_cmdq_ctxts(struct sphw_hwdev *hwdev)
{
	struct sphw_cmdqs *cmdqs = hwdev->cmdqs;
	enum sphw_cmdq_type cmdq_type;
	int err;

	cmdq_type = SPHW_CMDQ_SYNC;
	for (; cmdq_type < SPHW_MAX_CMDQ_TYPES; cmdq_type++) {
		err = sphw_set_cmdq_ctxt(hwdev, (u8)cmdq_type, &cmdqs->cmdq[cmdq_type].cmdq_ctxt);
		if (err)
			return err;
	}

	cmdqs->status |= SPHW_CMDQ_ENABLE;
	cmdqs->disable_flag = 0;

	return 0;
}

static void cmdq_flush_sync_cmd(struct sphw_cmdq_cmd_info *cmd_info)
{
	if (cmd_info->cmd_type != SPHW_CMD_TYPE_DIRECT_RESP &&
	    cmd_info->cmd_type != SPHW_CMD_TYPE_SGE_RESP)
		return;

	cmd_info->cmd_type = SPHW_CMD_TYPE_FORCE_STOP;

	if (cmd_info->cmpt_code &&
	    *cmd_info->cmpt_code == CMDQ_SEND_CMPT_CODE)
		*cmd_info->cmpt_code = CMDQ_FORCE_STOP_CMPT_CODE;

	if (cmd_info->done) {
		complete(cmd_info->done);
		cmd_info->done = NULL;
		cmd_info->cmpt_code = NULL;
		cmd_info->direct_resp = NULL;
		cmd_info->errcode = NULL;
	}
}

void sphw_cmdq_flush_cmd(struct sphw_hwdev *hwdev, struct sphw_cmdq *cmdq)
{
	struct sphw_cmdq_cmd_info *cmd_info = NULL;
	u16 ci = 0;

	spin_lock_bh(&cmdq->cmdq_lock);

	while (cmdq_read_wqe(&cmdq->wq, &ci)) {
		sphw_wq_put_wqebbs(&cmdq->wq, NUM_WQEBBS_FOR_CMDQ_WQE);
		cmd_info = &cmdq->cmd_infos[ci];

		if (cmd_info->cmd_type == SPHW_CMD_TYPE_DIRECT_RESP ||
		    cmd_info->cmd_type == SPHW_CMD_TYPE_SGE_RESP)
			cmdq_flush_sync_cmd(cmd_info);
	}

	spin_unlock_bh(&cmdq->cmdq_lock);
}

void sphw_cmdq_flush_channel_sync_cmd(struct sphw_hwdev *hwdev, u16 channel)
{
	struct sphw_cmdq_cmd_info *cmd_info = NULL;
	struct sphw_cmdq *cmdq = NULL;
	struct sphw_wq *wq = NULL;
	u16 wqe_cnt, ci, i;

	if (channel >= SPHW_CHANNEL_MAX)
		return;

	cmdq = &hwdev->cmdqs->cmdq[SPHW_CMDQ_SYNC];

	spin_lock_bh(&cmdq->cmdq_lock);

	wq = &cmdq->wq;
	ci = wq->cons_idx;
	wqe_cnt = (u16)WQ_MASK_IDX(wq, wq->prod_idx +
				   wq->q_depth - wq->cons_idx);
	for (i = 0; i < wqe_cnt; i++) {
		cmd_info = &cmdq->cmd_infos[WQ_MASK_IDX(wq, ci + i)];

		if (cmd_info->channel == channel)
			cmdq_flush_sync_cmd(cmd_info);
	}

	spin_unlock_bh(&cmdq->cmdq_lock);
}

static void cmdq_reset_all_cmd_buff(struct sphw_cmdq *cmdq)
{
	u16 i;

	for (i = 0; i < cmdq->wq.q_depth; i++)
		cmdq_clear_cmd_buf(&cmdq->cmd_infos[i], cmdq->hwdev);
}

int sphw_cmdq_set_channel_status(struct sphw_hwdev *hwdev, u16 channel, bool enable)
{
	if (channel >= SPHW_CHANNEL_MAX)
		return -EINVAL;

	if (enable) {
		clear_bit(channel, &hwdev->cmdqs->channel_stop);
	} else {
		set_bit(channel, &hwdev->cmdqs->channel_stop);
		sphw_cmdq_flush_channel_sync_cmd(hwdev, channel);
	}

	sdk_info(hwdev->dev_hdl, "%s cmdq channel 0x%x\n",
		 enable ? "Enable" : "Disable", channel);

	return 0;
}

void sphw_cmdq_enable_channel_lock(struct sphw_hwdev *hwdev, bool enable)
{
	hwdev->cmdqs->lock_channel_en = enable;

	sdk_info(hwdev->dev_hdl, "%s cmdq channel lock\n",
		 enable ? "Enable" : "Disable");
}

int sphw_reinit_cmdq_ctxts(struct sphw_hwdev *hwdev)
{
	struct sphw_cmdqs *cmdqs = hwdev->cmdqs;
	enum sphw_cmdq_type cmdq_type;

	cmdq_type = SPHW_CMDQ_SYNC;
	for (; cmdq_type < SPHW_MAX_CMDQ_TYPES; cmdq_type++) {
		sphw_cmdq_flush_cmd(hwdev, &cmdqs->cmdq[cmdq_type]);
		cmdq_reset_all_cmd_buff(&cmdqs->cmdq[cmdq_type]);
		cmdqs->cmdq[cmdq_type].wrapped = 1;
		sphw_wq_reset(&cmdqs->cmdq[cmdq_type].wq);
	}

	return sphw_set_cmdq_ctxts(hwdev);
}

static int create_cmdq_wq(struct sphw_cmdqs *cmdqs)
{
	enum sphw_cmdq_type type, cmdq_type;
	int err;

	cmdq_type = SPHW_CMDQ_SYNC;
	for (; cmdq_type < SPHW_MAX_CMDQ_TYPES; cmdq_type++) {
		err = sphw_wq_create(cmdqs->hwdev, &cmdqs->cmdq[cmdq_type].wq, SPHW_CMDQ_DEPTH,
				     CMDQ_WQEBB_SIZE);
		if (err) {
			sdk_err(cmdqs->hwdev->dev_hdl, "Failed to create cmdq wq\n");
			goto destroy_wq;
		}
	}

	/* 1-level CLA must put all cmdq's wq page addr in one wq block */
	if (!WQ_IS_0_LEVEL_CLA(&cmdqs->cmdq[SPHW_CMDQ_SYNC].wq)) {
		/* cmdq wq's CLA table is up to 512B */
#define CMDQ_WQ_CLA_SIZE	512
		if (cmdqs->cmdq[SPHW_CMDQ_SYNC].wq.num_wq_pages >
		    CMDQ_WQ_CLA_SIZE / sizeof(u64)) {
			sdk_err(cmdqs->hwdev->dev_hdl, "Cmdq wq page exceed limit: %lu\n",
				CMDQ_WQ_CLA_SIZE / sizeof(u64));
			goto destroy_wq;
		}

		cmdqs->wq_block_vaddr =
			dma_alloc_coherent(cmdqs->hwdev->dev_hdl, PAGE_SIZE,
					   &cmdqs->wq_block_paddr, GFP_KERNEL);
		if (!cmdqs->wq_block_vaddr) {
			sdk_err(cmdqs->hwdev->dev_hdl, "Failed to alloc cmdq wq block\n");
			goto destroy_wq;
		}

		type = SPHW_CMDQ_SYNC;
		for (; type < SPHW_MAX_CMDQ_TYPES; type++)
			memcpy((u8 *)cmdqs->wq_block_vaddr +
			       CMDQ_WQ_CLA_SIZE * type,
			       cmdqs->cmdq[type].wq.wq_block_vaddr,
			       cmdqs->cmdq[type].wq.num_wq_pages * sizeof(u64));
	}

	return 0;

destroy_wq:
	type = SPHW_CMDQ_SYNC;
	for (; type < cmdq_type; type++)
		sphw_wq_destroy(&cmdqs->cmdq[type].wq);

	return err;
}

static void destroy_cmdq_wq(struct sphw_cmdqs *cmdqs)
{
	enum sphw_cmdq_type cmdq_type;

	if (cmdqs->wq_block_vaddr)
		dma_free_coherent(cmdqs->hwdev->dev_hdl, PAGE_SIZE,
				  cmdqs->wq_block_vaddr, cmdqs->wq_block_paddr);

	cmdq_type = SPHW_CMDQ_SYNC;
	for (; cmdq_type < SPHW_MAX_CMDQ_TYPES; cmdq_type++)
		sphw_wq_destroy(&cmdqs->cmdq[cmdq_type].wq);
}

int sphw_cmdqs_init(struct sphw_hwdev *hwdev)
{
	struct sphw_cmdqs *cmdqs = NULL;
	enum sphw_cmdq_type type, cmdq_type;
	int err;

	cmdqs = kzalloc(sizeof(*cmdqs), GFP_KERNEL);
	if (!cmdqs)
		return -ENOMEM;

	hwdev->cmdqs = cmdqs;
	cmdqs->hwdev = hwdev;

	cmdqs->cmd_buf_pool = dma_pool_create("sphw_cmdq", hwdev->dev_hdl,
					      SPHW_CMDQ_BUF_SIZE,
					      SPHW_CMDQ_BUF_SIZE, 0ULL);
	if (!cmdqs->cmd_buf_pool) {
		sdk_err(hwdev->dev_hdl, "Failed to create cmdq buffer pool\n");
		err = -ENOMEM;
		goto pool_create_err;
	}

	err = create_cmdq_wq(cmdqs);
	if (err)
		goto create_wq_err;

	cmdq_type = SPHW_CMDQ_SYNC;
	for (; cmdq_type < SPHW_MAX_CMDQ_TYPES; cmdq_type++) {
		err = init_cmdq(&cmdqs->cmdq[cmdq_type], hwdev, cmdq_type);
		if (err) {
			sdk_err(hwdev->dev_hdl, "Failed to initialize cmdq type :%d\n",
				cmdq_type);
			goto init_cmdq_err;
		}

		cmdq_init_queue_ctxt(cmdqs, &cmdqs->cmdq[cmdq_type],
				     &cmdqs->cmdq[cmdq_type].cmdq_ctxt);
	}

	err = sphw_set_cmdq_ctxts(hwdev);
	if (err)
		goto init_cmdq_err;

	return 0;

init_cmdq_err:
	type = SPHW_CMDQ_SYNC;
	for (; type < cmdq_type; type++)
		free_cmdq(hwdev, &cmdqs->cmdq[type]);

	destroy_cmdq_wq(cmdqs);

create_wq_err:
	dma_pool_destroy(cmdqs->cmd_buf_pool);

pool_create_err:
	kfree(cmdqs);

	return err;
}

void sphw_cmdqs_free(struct sphw_hwdev *hwdev)
{
	struct sphw_cmdqs *cmdqs = hwdev->cmdqs;
	enum sphw_cmdq_type cmdq_type = SPHW_CMDQ_SYNC;

	cmdqs->status &= ~SPHW_CMDQ_ENABLE;

	for (; cmdq_type < SPHW_MAX_CMDQ_TYPES; cmdq_type++) {
		sphw_cmdq_flush_cmd(hwdev, &cmdqs->cmdq[cmdq_type]);
		cmdq_reset_all_cmd_buff(&cmdqs->cmdq[cmdq_type]);
		free_cmdq(cmdqs->hwdev, &cmdqs->cmdq[cmdq_type]);
	}

	destroy_cmdq_wq(cmdqs);

	dma_pool_destroy(cmdqs->cmd_buf_pool);

	kfree(cmdqs);
}
