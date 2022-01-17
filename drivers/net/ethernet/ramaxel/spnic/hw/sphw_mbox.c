// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include "sphw_hw.h"
#include "sphw_hwdev.h"
#include "sphw_csr.h"
#include "sphw_hwif.h"
#include "sphw_eqs.h"
#include "sphw_prof_adap.h"
#include "sphw_mbox.h"
#include "sphw_common.h"

#define SPHW_MBOX_INT_DST_AEQN_SHIFT		10
#define SPHW_MBOX_INT_SRC_RESP_AEQN_SHIFT	12
#define SPHW_MBOX_INT_STAT_DMA_SHIFT		14
/* The size of data to be send (unit of 4 bytes) */
#define SPHW_MBOX_INT_TX_SIZE_SHIFT		20
/* SO_RO(strong order, relax order)  */
#define SPHW_MBOX_INT_STAT_DMA_SO_RO_SHIFT	25
#define SPHW_MBOX_INT_WB_EN_SHIFT		28

#define SPHW_MBOX_INT_DST_AEQN_MASK		0x3
#define SPHW_MBOX_INT_SRC_RESP_AEQN_MASK	0x3
#define SPHW_MBOX_INT_STAT_DMA_MASK		0x3F
#define SPHW_MBOX_INT_TX_SIZE_MASK		0x1F
#define SPHW_MBOX_INT_STAT_DMA_SO_RO_MASK	0x3
#define SPHW_MBOX_INT_WB_EN_MASK		0x1

#define SPHW_MBOX_INT_SET(val, field)	\
			(((val) & SPHW_MBOX_INT_##field##_MASK) << \
			 SPHW_MBOX_INT_##field##_SHIFT)

enum sphw_mbox_tx_status {
	TX_NOT_DONE = 1,
};

#define SPHW_MBOX_CTRL_TRIGGER_AEQE_SHIFT	0
/* specifies the issue request for the message data.
 * 0 - Tx request is done;
 * 1 - Tx request is in process.
 */
#define SPHW_MBOX_CTRL_TX_STATUS_SHIFT		1
#define SPHW_MBOX_CTRL_DST_FUNC_SHIFT		16

#define SPHW_MBOX_CTRL_TRIGGER_AEQE_MASK	0x1
#define SPHW_MBOX_CTRL_TX_STATUS_MASK		0x1
#define SPHW_MBOX_CTRL_DST_FUNC_MASK		0x1FFF

#define SPHW_MBOX_CTRL_SET(val, field)	\
			(((val) & SPHW_MBOX_CTRL_##field##_MASK) << \
			 SPHW_MBOX_CTRL_##field##_SHIFT)

#define MBOX_SEGLEN_MASK	SPHW_MSG_HEADER_SET(SPHW_MSG_HEADER_SEG_LEN_MASK, SEG_LEN)

#define MBOX_MSG_POLLING_TIMEOUT		300000
#define SPHW_MBOX_COMP_TIME			300000U

#define MBOX_MAX_BUF_SZ				2048U
#define MBOX_HEADER_SZ				8
#define SPHW_MBOX_DATA_SIZE		(MBOX_MAX_BUF_SZ - MBOX_HEADER_SZ)

/* MBOX size is 64B, 8B for mbox_header, 8B reserved */
#define MBOX_SEG_LEN				48
#define MBOX_SEG_LEN_ALIGN			4
#define MBOX_WB_STATUS_LEN			16UL

#define SEQ_ID_START_VAL			0
#define SEQ_ID_MAX_VAL				42
#define MBOX_LAST_SEG_MAX_LEN			(MBOX_MAX_BUF_SZ - \
						 SEQ_ID_MAX_VAL * MBOX_SEG_LEN)

/* mbox write back status is 16B, only first 4B is used */
#define MBOX_WB_STATUS_ERRCODE_MASK		0xFFFF
#define MBOX_WB_STATUS_MASK			0xFF
#define MBOX_WB_ERROR_CODE_MASK			0xFF00
#define MBOX_WB_STATUS_FINISHED_SUCCESS		0xFF
#define MBOX_WB_STATUS_FINISHED_WITH_ERR	0xFE
#define MBOX_WB_STATUS_NOT_FINISHED		0x00

#define MBOX_STATUS_FINISHED(wb)	\
	(((wb) & MBOX_WB_STATUS_MASK) != MBOX_WB_STATUS_NOT_FINISHED)
#define MBOX_STATUS_SUCCESS(wb)		\
	(((wb) & MBOX_WB_STATUS_MASK) == MBOX_WB_STATUS_FINISHED_SUCCESS)
#define MBOX_STATUS_ERRCODE(wb)		\
	((wb) & MBOX_WB_ERROR_CODE_MASK)

#define DST_AEQ_IDX_DEFAULT_VAL			0
#define SRC_AEQ_IDX_DEFAULT_VAL			0
#define NO_DMA_ATTRIBUTE_VAL			0

#define MBOX_MSG_NO_DATA_LEN			1

#define MBOX_BODY_FROM_HDR(header)	((u8 *)(header) + MBOX_HEADER_SZ)
#define MBOX_AREA(hwif)			\
	((hwif)->cfg_regs_base + SPHW_FUNC_CSR_MAILBOX_DATA_OFF)

#define MBOX_DMA_MSG_QUEUE_DEPTH		32

#define MBOX_MQ_CI_OFFSET		(SPHW_CFG_REGS_FLAG + SPHW_FUNC_CSR_MAILBOX_DATA_OFF + \
					 MBOX_HEADER_SZ + MBOX_SEG_LEN)

#define MBOX_MQ_SYNC_CI_SHIFT			0
#define MBOX_MQ_ASYNC_CI_SHIFT			8

#define MBOX_MQ_SYNC_CI_MASK			0xFF
#define MBOX_MQ_ASYNC_CI_MASK			0xFF

#define MBOX_MQ_CI_SET(val, field)	\
		(((val) & MBOX_MQ_##field##_CI_MASK) << MBOX_MQ_##field##_CI_SHIFT)
#define MBOX_MQ_CI_GET(val, field)	\
		(((val) >> MBOX_MQ_##field##_CI_SHIFT) & MBOX_MQ_##field##_CI_MASK)
#define MBOX_MQ_CI_CLEAR(val, field)		\
		((val) & (~(MBOX_MQ_##field##_CI_MASK << MBOX_MQ_##field##_CI_SHIFT)))

#define IS_PF_OR_PPF_SRC(hwdev, src_func_idx)	\
	((src_func_idx) < SPHW_MAX_PF_NUM(hwdev))

#define MBOX_RESPONSE_ERROR			0x1
#define MBOX_MSG_ID_MASK			0xF
#define MBOX_MSG_ID(func_to_func)		((func_to_func)->send_msg_id)
#define MBOX_MSG_ID_INC(func_to_func)	\
			(MBOX_MSG_ID(func_to_func) = \
			 (MBOX_MSG_ID(func_to_func) + 1) & MBOX_MSG_ID_MASK)

/* max message counter wait to process for one function */
#define SPHW_MAX_MSG_CNT_TO_PROCESS		10

#define MBOX_MSG_CHANNEL_STOP(func_to_func)				\
	((((func_to_func)->lock_channel_en) &&				\
	    test_bit((func_to_func)->cur_msg_channel,			\
		     &(func_to_func)->channel_stop)) ? true : false)

enum mbox_ordering_type {
	STRONG_ORDER,
};

enum mbox_write_back_type {
	WRITE_BACK = 1,
};

enum mbox_aeq_trig_type {
	NOT_TRIGGER,
	TRIGGER,
};

static int send_mbox_msg(struct sphw_mbox *func_to_func, u8 mod, u16 cmd,
			 void *msg, u16 msg_len, u16 dst_func,
			 enum sphw_msg_direction_type direction,
			 enum sphw_msg_ack_type ack_type,
			 struct mbox_msg_info *msg_info);

struct sphw_msg_desc *get_mbox_msg_desc(struct sphw_mbox *func_to_func,
					u64 dir, u64 src_func_id);

/**
 * sphw_register_ppf_mbox_cb - register mbox callback for ppf
 * @hwdev:	the pointer to hw device
 * @mod:	specific mod that the callback will handle
 * @pri_handle	specific mod's private data that will be used in callback
 * @callback:	callback function
 * Return:	0 - success, negative - failure
 */
int sphw_register_ppf_mbox_cb(void *hwdev, u8 mod, void *pri_handle, sphw_ppf_mbox_cb callback)
{
	struct sphw_mbox *func_to_func = NULL;

	if (mod >= SPHW_MOD_MAX || !hwdev)
		return -EFAULT;

	func_to_func = ((struct sphw_hwdev *)hwdev)->func_to_func;

	func_to_func->ppf_mbox_cb[mod] = callback;
	func_to_func->ppf_mbox_data[mod] = pri_handle;

	set_bit(SPHW_PPF_MBOX_CB_REG, &func_to_func->ppf_mbox_cb_state[mod]);

	return 0;
}

/**
 * sphw_register_pf_mbox_cb - register mbox callback for pf
 * @hwdev:	the pointer to hw device
 * @mod:	specific mod that the callback will handle
 * @pri_handle	specific mod's private data that will be used in callback
 * @callback:	callback function
 * Return:	0 - success, negative - failure
 */
int sphw_register_pf_mbox_cb(void *hwdev, u8 mod, void *pri_handle, sphw_pf_mbox_cb callback)
{
	struct sphw_mbox *func_to_func = NULL;

	if (mod >= SPHW_MOD_MAX || !hwdev)
		return -EFAULT;

	func_to_func = ((struct sphw_hwdev *)hwdev)->func_to_func;

	func_to_func->pf_mbox_cb[mod] = callback;
	func_to_func->pf_mbox_data[mod] = pri_handle;

	set_bit(SPHW_PF_MBOX_CB_REG, &func_to_func->pf_mbox_cb_state[mod]);

	return 0;
}

/**
 * sphw_register_vf_mbox_cb - register mbox callback for vf
 * @hwdev:	the pointer to hw device
 * @mod:	specific mod that the callback will handle
 * @pri_handle	specific mod's private data that will be used in callback
 * @callback:	callback function
 * Return:	0 - success, negative - failure
 */
int sphw_register_vf_mbox_cb(void *hwdev, u8 mod, void *pri_handle, sphw_vf_mbox_cb callback)
{
	struct sphw_mbox *func_to_func = NULL;

	if (mod >= SPHW_MOD_MAX || !hwdev)
		return -EFAULT;

	func_to_func = ((struct sphw_hwdev *)hwdev)->func_to_func;

	func_to_func->vf_mbox_cb[mod] = callback;
	func_to_func->vf_mbox_data[mod] = pri_handle;

	set_bit(SPHW_VF_MBOX_CB_REG, &func_to_func->vf_mbox_cb_state[mod]);

	return 0;
}

/**
 * sphw_register_ppf_to_pf_mbox_cb - register mbox callback for pf from ppf
 * @hwdev:	the pointer to hw device
 * @mod:	specific mod that the callback will handle
 * @pri_handle	specific mod's private data that will be used in callback
 * @callback:	callback function
 * Return:	0 - success, negative - failure
 */
int sphw_register_ppf_to_pf_mbox_cb(void *hwdev, u8 mod, void *pri_handle,
				    sphw_pf_recv_from_ppf_mbox_cb callback)
{
	struct sphw_mbox *func_to_func = NULL;

	if (mod >= SPHW_MOD_MAX || !hwdev)
		return -EFAULT;

	func_to_func = ((struct sphw_hwdev *)hwdev)->func_to_func;

	func_to_func->pf_recv_ppf_mbox_cb[mod] = callback;
	func_to_func->pf_recv_ppf_mbox_data[mod] = pri_handle;

	set_bit(SPHW_PPF_TO_PF_MBOX_CB_REG,
		&func_to_func->ppf_to_pf_mbox_cb_state[mod]);

	return 0;
}

/**
 * sphw_unregister_ppf_mbox_cb - unregister the mbox callback for ppf
 * @hwdev:	the pointer to hw device
 * @mod:	specific mod that the callback will handle
 * Return:
 */
void sphw_unregister_ppf_mbox_cb(void *hwdev, u8 mod)
{
	struct sphw_mbox *func_to_func = NULL;

	if (mod >= SPHW_MOD_MAX || !hwdev)
		return;

	func_to_func = ((struct sphw_hwdev *)hwdev)->func_to_func;

	clear_bit(SPHW_PPF_MBOX_CB_REG,
		  &func_to_func->ppf_mbox_cb_state[mod]);

	while (test_bit(SPHW_PPF_MBOX_CB_RUNNING,
			&func_to_func->ppf_mbox_cb_state[mod]))
		usleep_range(900, 1000);

	func_to_func->ppf_mbox_data[mod] = NULL;
	func_to_func->ppf_mbox_cb[mod] = NULL;
}

/**
 * sphw_unregister_ppf_mbox_cb - unregister the mbox callback for pf
 * @hwdev:	the pointer to hw device
 * @mod:	specific mod that the callback will handle
 * Return:
 */
void sphw_unregister_pf_mbox_cb(void *hwdev, u8 mod)
{
	struct sphw_mbox *func_to_func = NULL;

	if (mod >= SPHW_MOD_MAX || !hwdev)
		return;

	func_to_func = ((struct sphw_hwdev *)hwdev)->func_to_func;

	clear_bit(SPHW_PF_MBOX_CB_REG, &func_to_func->pf_mbox_cb_state[mod]);

	while (test_bit(SPHW_PF_MBOX_CB_RUNNING,
			&func_to_func->pf_mbox_cb_state[mod]))
		usleep_range(900, 1000);

	func_to_func->pf_mbox_data[mod] = NULL;
	func_to_func->pf_mbox_cb[mod] = NULL;
}

/**
 * sphw_unregister_vf_mbox_cb - unregister the mbox callback for vf
 * @hwdev:	the pointer to hw device
 * @mod:	specific mod that the callback will handle
 * Return:
 */
void sphw_unregister_vf_mbox_cb(void *hwdev, u8 mod)
{
	struct sphw_mbox *func_to_func = NULL;

	if (mod >= SPHW_MOD_MAX || !hwdev)
		return;

	func_to_func = ((struct sphw_hwdev *)hwdev)->func_to_func;

	clear_bit(SPHW_VF_MBOX_CB_REG, &func_to_func->vf_mbox_cb_state[mod]);

	while (test_bit(SPHW_VF_MBOX_CB_RUNNING,
			&func_to_func->vf_mbox_cb_state[mod]))
		usleep_range(900, 1000);

	func_to_func->vf_mbox_data[mod] = NULL;
	func_to_func->vf_mbox_cb[mod] = NULL;
}

/**
 * sphw_unregister_ppf_mbox_cb - unregister the mbox callback for pf from ppf
 * @hwdev:	the pointer to hw device
 * @mod:	specific mod that the callback will handle
 * Return:
 */
void sphw_unregister_ppf_to_pf_mbox_cb(void *hwdev, u8 mod)
{
	struct sphw_mbox *func_to_func = NULL;

	if (mod >= SPHW_MOD_MAX || !hwdev)
		return;

	func_to_func = ((struct sphw_hwdev *)hwdev)->func_to_func;

	clear_bit(SPHW_PPF_TO_PF_MBOX_CB_REG,
		  &func_to_func->ppf_to_pf_mbox_cb_state[mod]);

	while (test_bit(SPHW_PPF_TO_PF_MBOX_CB_RUNNIG,
			&func_to_func->ppf_to_pf_mbox_cb_state[mod]))
		usleep_range(900, 1000);

	func_to_func->pf_recv_ppf_mbox_data[mod] = NULL;
	func_to_func->pf_recv_ppf_mbox_cb[mod] = NULL;
}

static int recv_vf_mbox_handler(struct sphw_mbox *func_to_func,
				struct sphw_recv_mbox *recv_mbox,
				void *buf_out, u16 *out_size)
{
	sphw_vf_mbox_cb cb;
	int ret;

	if (recv_mbox->mod >= SPHW_MOD_MAX) {
		sdk_warn(func_to_func->hwdev->dev_hdl, "Receive illegal mbox message, mod = %hhu\n",
			 recv_mbox->mod);
		return -EINVAL;
	}

	set_bit(SPHW_VF_MBOX_CB_RUNNING, &func_to_func->vf_mbox_cb_state[recv_mbox->mod]);

	cb = func_to_func->vf_mbox_cb[recv_mbox->mod];
	if (cb && test_bit(SPHW_VF_MBOX_CB_REG,
			   &func_to_func->vf_mbox_cb_state[recv_mbox->mod])) {
		ret = cb(func_to_func->hwdev,
			 func_to_func->vf_mbox_data[recv_mbox->mod],
			 recv_mbox->cmd, recv_mbox->msg,
			 recv_mbox->msg_len, buf_out, out_size);
	} else {
		sdk_warn(func_to_func->hwdev->dev_hdl, "VF mbox cb is not registered\n");
		ret = -EINVAL;
	}

	clear_bit(SPHW_VF_MBOX_CB_RUNNING,
		  &func_to_func->vf_mbox_cb_state[recv_mbox->mod]);

	return ret;
}

static int recv_pf_from_ppf_handler(struct sphw_mbox *func_to_func,
				    struct sphw_recv_mbox *recv_mbox,
				    void *buf_out, u16 *out_size)
{
	sphw_pf_recv_from_ppf_mbox_cb	cb;
	enum sphw_mod_type mod = recv_mbox->mod;
	int ret;

	if (mod >= SPHW_MOD_MAX) {
		sdk_warn(func_to_func->hwdev->dev_hdl, "Receive illegal mbox message, mod = %d\n",
			 mod);
		return -EINVAL;
	}

	set_bit(SPHW_PPF_TO_PF_MBOX_CB_RUNNIG,
		&func_to_func->ppf_to_pf_mbox_cb_state[mod]);

	cb = func_to_func->pf_recv_ppf_mbox_cb[mod];
	if (cb && test_bit(SPHW_PPF_TO_PF_MBOX_CB_REG,
			   &func_to_func->ppf_to_pf_mbox_cb_state[mod])) {
		ret = cb(func_to_func->hwdev,
			 func_to_func->pf_recv_ppf_mbox_data[mod],
			 recv_mbox->cmd, recv_mbox->msg, recv_mbox->msg_len,
			 buf_out, out_size);
	} else {
		sdk_warn(func_to_func->hwdev->dev_hdl, "PF receive ppf mailbox callback is not registered\n");
		ret = -EINVAL;
	}

	clear_bit(SPHW_PPF_TO_PF_MBOX_CB_RUNNIG,
		  &func_to_func->ppf_to_pf_mbox_cb_state[mod]);

	return ret;
}

static int recv_ppf_mbox_handler(struct sphw_mbox *func_to_func,
				 struct sphw_recv_mbox *recv_mbox,
				 u8 pf_id, void *buf_out, u16 *out_size)
{
	sphw_ppf_mbox_cb cb;
	u16 vf_id = 0;
	int ret;

	if (recv_mbox->mod >= SPHW_MOD_MAX) {
		sdk_warn(func_to_func->hwdev->dev_hdl, "Receive illegal mbox message, mod = %hhu\n",
			 recv_mbox->mod);
		return -EINVAL;
	}

	set_bit(SPHW_PPF_MBOX_CB_RUNNING,
		&func_to_func->ppf_mbox_cb_state[recv_mbox->mod]);

	cb = func_to_func->ppf_mbox_cb[recv_mbox->mod];
	if (cb && test_bit(SPHW_PPF_MBOX_CB_REG,
			   &func_to_func->ppf_mbox_cb_state[recv_mbox->mod])) {
		ret = cb(func_to_func->hwdev,
			 func_to_func->ppf_mbox_data[recv_mbox->mod],
			 pf_id, vf_id, recv_mbox->cmd, recv_mbox->msg,
			 recv_mbox->msg_len, buf_out, out_size);
	} else {
		sdk_warn(func_to_func->hwdev->dev_hdl, "PPF mbox cb is not registered, mod = %hhu\n",
			 recv_mbox->mod);
		ret = -EINVAL;
	}

	clear_bit(SPHW_PPF_MBOX_CB_RUNNING,
		  &func_to_func->ppf_mbox_cb_state[recv_mbox->mod]);

	return ret;
}

static int recv_pf_from_vf_mbox_handler(struct sphw_mbox *func_to_func,
					struct sphw_recv_mbox *recv_mbox,
					u16 src_func_idx, void *buf_out,
					u16 *out_size)
{
	sphw_pf_mbox_cb cb;
	u16 vf_id = 0;
	int ret;

	if (recv_mbox->mod >= SPHW_MOD_MAX) {
		sdk_warn(func_to_func->hwdev->dev_hdl, "Receive illegal mbox message, mod = %hhu\n",
			 recv_mbox->mod);
		return -EINVAL;
	}

	set_bit(SPHW_PF_MBOX_CB_RUNNING,
		&func_to_func->pf_mbox_cb_state[recv_mbox->mod]);

	cb = func_to_func->pf_mbox_cb[recv_mbox->mod];
	if (cb && test_bit(SPHW_PF_MBOX_CB_REG,
			   &func_to_func->pf_mbox_cb_state[recv_mbox->mod])) {
		vf_id = src_func_idx -
			sphw_glb_pf_vf_offset(func_to_func->hwdev);
		ret = cb(func_to_func->hwdev,
			 func_to_func->pf_mbox_data[recv_mbox->mod],
			 vf_id, recv_mbox->cmd, recv_mbox->msg,
			 recv_mbox->msg_len, buf_out, out_size);
	} else {
		sdk_warn(func_to_func->hwdev->dev_hdl, "PF mbox mod(0x%x) cb is not registered\n",
			 recv_mbox->mod);
		ret = -EINVAL;
	}

	clear_bit(SPHW_PF_MBOX_CB_RUNNING,
		  &func_to_func->pf_mbox_cb_state[recv_mbox->mod]);

	return ret;
}

static void response_for_recv_func_mbox(struct sphw_mbox *func_to_func,
					struct sphw_recv_mbox *recv_mbox,
					int err, u16 out_size, u16 src_func_idx)
{
	struct mbox_msg_info msg_info = {0};

	msg_info.msg_id = recv_mbox->msg_id;
	if (err)
		msg_info.status = SPHW_MBOX_PF_SEND_ERR;

	/* if not data need to response, set out_size to 1 */
	if (!out_size || err)
		out_size = MBOX_MSG_NO_DATA_LEN;

	send_mbox_msg(func_to_func, recv_mbox->mod, recv_mbox->cmd,
		      recv_mbox->resp_buff, out_size, src_func_idx,
		      SPHW_MSG_RESPONSE, SPHW_MSG_NO_ACK, &msg_info);
}

static void recv_func_mbox_handler(struct sphw_mbox *func_to_func,
				   struct sphw_recv_mbox *recv_mbox)
{
	struct sphw_hwdev *dev = func_to_func->hwdev;
	void *buf_out = recv_mbox->resp_buff;
	u16 src_func_idx = recv_mbox->src_func_idx;
	u16 out_size = MBOX_MAX_BUF_SZ;
	int err = 0;

	if (SPHW_IS_VF(dev)) {
		err = recv_vf_mbox_handler(func_to_func, recv_mbox, buf_out,
					   &out_size);
	} else { /* pf/ppf process */
		if (IS_PF_OR_PPF_SRC(dev, src_func_idx)) {
			if (SPHW_IS_PPF(dev)) {
				err = recv_ppf_mbox_handler(func_to_func,
							    recv_mbox,
							    (u8)src_func_idx,
							    buf_out, &out_size);
				if (err)
					goto out;
			} else {
				err = recv_pf_from_ppf_handler(func_to_func,
							       recv_mbox,
							       buf_out,
							       &out_size);
				if (err)
					goto out;
			}
		/* The source is neither PF nor PPF, so it is from VF */
		} else {
			err = recv_pf_from_vf_mbox_handler(func_to_func,
							   recv_mbox,
							   src_func_idx,
							   buf_out, &out_size);
		}
	}

out:
	if (recv_mbox->ack_type == SPHW_MSG_ACK)
		response_for_recv_func_mbox(func_to_func, recv_mbox, err,
					    out_size, src_func_idx);
}

static struct sphw_recv_mbox *alloc_recv_mbox(void)
{
	struct sphw_recv_mbox *recv_msg = NULL;

	recv_msg = kzalloc(sizeof(*recv_msg), GFP_KERNEL);
	if (!recv_msg)
		return NULL;

	recv_msg->msg = kzalloc(MBOX_MAX_BUF_SZ, GFP_KERNEL);
	if (!recv_msg->msg)
		goto alloc_msg_err;

	recv_msg->resp_buff = kzalloc(MBOX_MAX_BUF_SZ, GFP_KERNEL);
	if (!recv_msg->resp_buff)
		goto alloc_resp_bff_err;

	return recv_msg;

alloc_resp_bff_err:
	kfree(recv_msg->msg);

alloc_msg_err:
	kfree(recv_msg);

	return NULL;
}

static void free_recv_mbox(struct sphw_recv_mbox *recv_msg)
{
	kfree(recv_msg->resp_buff);
	kfree(recv_msg->msg);
	kfree(recv_msg);
}

static void recv_func_mbox_work_handler(struct work_struct *work)
{
	struct sphw_mbox_work *mbox_work =
			container_of(work, struct sphw_mbox_work, work);

	recv_func_mbox_handler(mbox_work->func_to_func, mbox_work->recv_mbox);

	atomic_dec(&mbox_work->msg_ch->recv_msg_cnt);

	free_recv_mbox(mbox_work->recv_mbox);
	kfree(mbox_work);
}

static void resp_mbox_handler(struct sphw_mbox *func_to_func,
			      struct sphw_msg_desc *msg_desc)
{
	spin_lock(&func_to_func->mbox_lock);
	if (msg_desc->msg_info.msg_id == func_to_func->send_msg_id &&
	    func_to_func->event_flag == EVENT_START)
		func_to_func->event_flag = EVENT_SUCCESS;
	else
		sdk_err(func_to_func->hwdev->dev_hdl,
			"Mbox response timeout, current send msg id(0x%x), recv msg id(0x%x), status(0x%x)\n",
			func_to_func->send_msg_id, msg_desc->msg_info.msg_id,
			msg_desc->msg_info.status);
	spin_unlock(&func_to_func->mbox_lock);
}

static void recv_mbox_msg_handler(struct sphw_mbox *func_to_func,
				  struct sphw_msg_desc *msg_desc,
				  u64 mbox_header)
{
	struct sphw_hwdev *hwdev = func_to_func->hwdev;
	struct sphw_recv_mbox *recv_msg = NULL;
	struct sphw_mbox_work *mbox_work = NULL;
	struct sphw_msg_channel *msg_ch =
		container_of(msg_desc, struct sphw_msg_channel, recv_msg);
	u16 src_func_idx = SPHW_MSG_HEADER_GET(mbox_header, SRC_GLB_FUNC_IDX);

	if (atomic_read(&msg_ch->recv_msg_cnt) >
	    SPHW_MAX_MSG_CNT_TO_PROCESS) {
		sdk_warn(hwdev->dev_hdl, "This function(%u) have %d message wait to process, can't add to work queue\n",
			 src_func_idx, atomic_read(&msg_ch->recv_msg_cnt));
		return;
	}

	recv_msg = alloc_recv_mbox();
	if (!recv_msg) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc receive mbox message buffer\n");
		return;
	}
	recv_msg->msg_len = msg_desc->msg_len;
	memcpy(recv_msg->msg, msg_desc->msg, recv_msg->msg_len);
	recv_msg->msg_id = msg_desc->msg_info.msg_id;
	recv_msg->mod = SPHW_MSG_HEADER_GET(mbox_header, MODULE);
	recv_msg->cmd = SPHW_MSG_HEADER_GET(mbox_header, CMD);
	recv_msg->ack_type = SPHW_MSG_HEADER_GET(mbox_header, NO_ACK);
	recv_msg->src_func_idx = src_func_idx;

	mbox_work = kzalloc(sizeof(*mbox_work), GFP_KERNEL);
	if (!mbox_work) {
		sdk_err(hwdev->dev_hdl, "Allocate mbox work memory failed.\n");
		free_recv_mbox(recv_msg);
		return;
	}

	atomic_inc(&msg_ch->recv_msg_cnt);

	mbox_work->func_to_func = func_to_func;
	mbox_work->recv_mbox = recv_msg;
	mbox_work->msg_ch = msg_ch;

	INIT_WORK(&mbox_work->work, recv_func_mbox_work_handler);
	queue_work_on(sphw_get_work_cpu_affinity(hwdev, WORK_TYPE_MBOX),
		      func_to_func->workq, &mbox_work->work);
}

static bool check_mbox_segment(struct sphw_mbox *func_to_func,
			       struct sphw_msg_desc *msg_desc,
			       u64 mbox_header)
{
	u8 seq_id, seg_len, msg_id, mod;
	u16 src_func_idx, cmd;

	seq_id = SPHW_MSG_HEADER_GET(mbox_header, SEQID);
	seg_len = SPHW_MSG_HEADER_GET(mbox_header, SEG_LEN);
	msg_id = SPHW_MSG_HEADER_GET(mbox_header, MSG_ID);
	mod = SPHW_MSG_HEADER_GET(mbox_header, MODULE);
	cmd = SPHW_MSG_HEADER_GET(mbox_header, CMD);
	src_func_idx = SPHW_MSG_HEADER_GET(mbox_header, SRC_GLB_FUNC_IDX);

	if (seq_id > SEQ_ID_MAX_VAL || seg_len > MBOX_SEG_LEN ||
	    (seq_id == SEQ_ID_MAX_VAL && seg_len > MBOX_LAST_SEG_MAX_LEN))
		goto seg_err;

	if (seq_id == 0) {
		msg_desc->seq_id = seq_id;
		msg_desc->msg_info.msg_id = msg_id;
		msg_desc->mod = mod;
		msg_desc->cmd = cmd;
	} else {
		if (seq_id != msg_desc->seq_id + 1 ||
		    msg_id != msg_desc->msg_info.msg_id ||
		    mod != msg_desc->mod || cmd != msg_desc->cmd)
			goto seg_err;

		msg_desc->seq_id = seq_id;
	}

	return true;

seg_err:
	sdk_err(func_to_func->hwdev->dev_hdl,
		"Mailbox segment check failed, src func id: 0x%x, front seg info: seq id: 0x%x, msg id: 0x%x, mod: 0x%x, cmd: 0x%x\n",
		src_func_idx, msg_desc->seq_id, msg_desc->msg_info.msg_id,
		msg_desc->mod, msg_desc->cmd);
	sdk_err(func_to_func->hwdev->dev_hdl,
		"Current seg info: seg len: 0x%x, seq id: 0x%x, msg id: 0x%x, mod: 0x%x, cmd: 0x%x\n",
		seg_len, seq_id, msg_id, mod, cmd);

	return false;
}

static void recv_mbox_handler(struct sphw_mbox *func_to_func,
			      void *header, struct sphw_msg_desc *msg_desc)
{
	u64 mbox_header = *((u64 *)header);
	void *mbox_body = MBOX_BODY_FROM_HDR(header);
	u8 seq_id, seg_len;
	int pos;

	if (!check_mbox_segment(func_to_func, msg_desc, mbox_header)) {
		msg_desc->seq_id = SEQ_ID_MAX_VAL;
		return;
	}

	seq_id = SPHW_MSG_HEADER_GET(mbox_header, SEQID);
	seg_len = SPHW_MSG_HEADER_GET(mbox_header, SEG_LEN);

	pos = seq_id * MBOX_SEG_LEN;
	memcpy((u8 *)msg_desc->msg + pos, mbox_body, seg_len);

	if (!SPHW_MSG_HEADER_GET(mbox_header, LAST))
		return;

	msg_desc->msg_len = SPHW_MSG_HEADER_GET(mbox_header, MSG_LEN);
	msg_desc->msg_info.status = SPHW_MSG_HEADER_GET(mbox_header, STATUS);

	if (SPHW_MSG_HEADER_GET(mbox_header, DIRECTION) ==
	    SPHW_MSG_RESPONSE) {
		resp_mbox_handler(func_to_func, msg_desc);
		return;
	}

	recv_mbox_msg_handler(func_to_func, msg_desc, mbox_header);
}

void sphw_mbox_func_aeqe_handler(void *handle, u8 *header, u8 size)
{
	struct sphw_mbox *func_to_func = NULL;
	struct sphw_msg_desc *msg_desc = NULL;
	u64 mbox_header = *((u64 *)header);
	u64 src, dir;

	func_to_func = ((struct sphw_hwdev *)handle)->func_to_func;

	dir = SPHW_MSG_HEADER_GET(mbox_header, DIRECTION);
	src = SPHW_MSG_HEADER_GET(mbox_header, SRC_GLB_FUNC_IDX);

	msg_desc = get_mbox_msg_desc(func_to_func, dir, src);
	if (!msg_desc) {
		sdk_err(func_to_func->hwdev->dev_hdl,
			"Mailbox source function id: %u is invalid for current function\n",
			(u32)src);
		return;
	}

	recv_mbox_handler(func_to_func, (u64 *)header, msg_desc);
}

static int init_mbox_dma_queue(struct sphw_hwdev *hwdev, struct mbox_dma_queue *mq)
{
	u32 size;

	mq->depth = MBOX_DMA_MSG_QUEUE_DEPTH;
	mq->prod_idx = 0;
	mq->cons_idx = 0;

	size = mq->depth * MBOX_MAX_BUF_SZ;
	mq->dma_buff_vaddr = dma_alloc_coherent(hwdev->dev_hdl, size, &mq->dma_buff_paddr,
						GFP_KERNEL);
	if (!mq->dma_buff_vaddr) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc dma_buffer\n");
		return -ENOMEM;
	}

	return 0;
}

static void deinit_mbox_dma_queue(struct sphw_hwdev *hwdev, struct mbox_dma_queue *mq)
{
	dma_free_coherent(hwdev->dev_hdl, mq->depth * MBOX_MAX_BUF_SZ,
			  mq->dma_buff_vaddr, mq->dma_buff_paddr);
}

static int sphw_init_mbox_dma_queue(struct sphw_mbox *func_to_func)
{
	u32 val;
	int err;

	err = init_mbox_dma_queue(func_to_func->hwdev, &func_to_func->sync_msg_queue);
	if (err)
		return err;

	err = init_mbox_dma_queue(func_to_func->hwdev, &func_to_func->async_msg_queue);
	if (err) {
		deinit_mbox_dma_queue(func_to_func->hwdev, &func_to_func->sync_msg_queue);
		return err;
	}

	val = sphw_hwif_read_reg(func_to_func->hwdev->hwif, MBOX_MQ_CI_OFFSET);
	val = MBOX_MQ_CI_CLEAR(val, SYNC);
	val = MBOX_MQ_CI_CLEAR(val, ASYNC);
	sphw_hwif_write_reg(func_to_func->hwdev->hwif, MBOX_MQ_CI_OFFSET, val);

	return 0;
}

static void sphw_deinit_mbox_dma_queue(struct sphw_mbox *func_to_func)
{
	deinit_mbox_dma_queue(func_to_func->hwdev, &func_to_func->sync_msg_queue);
	deinit_mbox_dma_queue(func_to_func->hwdev, &func_to_func->async_msg_queue);
}

#define MBOX_DMA_MSG_INIT_XOR_VAL	0x5a5a5a5a
static u32 mbox_dma_msg_xor(u32 *data, u16 msg_len)
{
	u32 xor = MBOX_DMA_MSG_INIT_XOR_VAL;
	u16 dw_len = msg_len / sizeof(u32);
	u16 i;

	for (i = 0; i < dw_len; i++)
		xor ^= data[i];

	return xor;
}

#define MQ_ID_MASK(mq, idx)	((idx) & ((mq)->depth - 1))
#define IS_MSG_QUEUE_FULL(mq)	(MQ_ID_MASK(mq, (mq)->prod_idx + 1) == \
				 MQ_ID_MASK(mq, (mq)->cons_idx))

static int mbox_prepare_dma_entry(struct sphw_mbox *func_to_func, struct mbox_dma_queue *mq,
				  struct mbox_dma_msg *dma_msg, void *msg, u16 msg_len)
{
	u64 dma_addr, offset;

	if (IS_MSG_QUEUE_FULL(mq)) {
		sdk_err(func_to_func->hwdev->dev_hdl, "Mbox sync message queue is busy, pi: %u, ci: %u\n",
			mq->prod_idx, MQ_ID_MASK(mq, mq->cons_idx));
		return -EBUSY;
	}

	/* copy data to DMA buffer */
	offset = mq->prod_idx * MBOX_MAX_BUF_SZ;
	memcpy((u8 *)mq->dma_buff_vaddr + offset, msg, msg_len);
	dma_addr = mq->dma_buff_paddr + offset;
	dma_msg->dma_addr_high = upper_32_bits(dma_addr);
	dma_msg->dma_addr_low = lower_32_bits(dma_addr);
	dma_msg->msg_len = msg_len;
	dma_msg->xor = mbox_dma_msg_xor(msg, msg_len);

	mq->prod_idx++;
	mq->prod_idx = MQ_ID_MASK(mq, mq->prod_idx);

	return 0;
}

static int mbox_prepare_dma_msg(struct sphw_mbox *func_to_func, enum sphw_msg_ack_type ack_type,
				struct mbox_dma_msg *dma_msg, void *msg, u16 msg_len)
{
	struct mbox_dma_queue *mq = NULL;
	u32 val;

	val = sphw_hwif_read_reg(func_to_func->hwdev->hwif, MBOX_MQ_CI_OFFSET);
	if (ack_type == SPHW_MSG_ACK) {
		mq = &func_to_func->sync_msg_queue;
		mq->cons_idx = MBOX_MQ_CI_GET(val, SYNC);
	} else {
		mq = &func_to_func->async_msg_queue;
		mq->cons_idx = MBOX_MQ_CI_GET(val, ASYNC);
	}

	return mbox_prepare_dma_entry(func_to_func, mq, dma_msg, msg, msg_len);
}

static void clear_mbox_status(struct sphw_send_mbox *mbox)
{
	*mbox->wb_status = 0;

	/* clear mailbox write back status */
	wmb();
}

static void mbox_copy_header(struct sphw_hwdev *hwdev,
			     struct sphw_send_mbox *mbox, u64 *header)
{
	u32 *data = (u32 *)header;
	u32 i, idx_max = MBOX_HEADER_SZ / sizeof(u32);

	for (i = 0; i < idx_max; i++)
		__raw_writel(cpu_to_be32(*(data + i)), mbox->data + i * sizeof(u32));
}

static void mbox_copy_send_data(struct sphw_hwdev *hwdev, struct sphw_send_mbox *mbox, void *seg,
				u16 seg_len)
{
	u32 *data = seg;
	u32 data_len, chk_sz = sizeof(u32);
	u32 i, idx_max;

	data_len = seg_len;
	idx_max = ALIGN(data_len, chk_sz) / chk_sz;

	for (i = 0; i < idx_max; i++)
		__raw_writel(cpu_to_be32(*(data + i)),
			     mbox->data + MBOX_HEADER_SZ + i * sizeof(u32));
}

static void write_mbox_msg_attr(struct sphw_mbox *func_to_func,
				u16 dst_func, u16 dst_aeqn, u16 seg_len)
{
	u32 mbox_int, mbox_ctrl;

	/* for VF to PF's message, dest func id will self-learning by HW */
	if (SPHW_IS_VF(func_to_func->hwdev) &&
	    dst_func != SPHW_MGMT_SRC_ID)
		dst_func = 0;	/* the destination is the VF's PF */

	mbox_int = SPHW_MBOX_INT_SET(dst_aeqn, DST_AEQN) |
		   SPHW_MBOX_INT_SET(0, SRC_RESP_AEQN) |
		   SPHW_MBOX_INT_SET(NO_DMA_ATTRIBUTE_VAL, STAT_DMA) |
		   SPHW_MBOX_INT_SET(ALIGN(seg_len + MBOX_HEADER_SZ,
					   MBOX_SEG_LEN_ALIGN) >> 2, TX_SIZE) |
		   SPHW_MBOX_INT_SET(STRONG_ORDER, STAT_DMA_SO_RO) |
		   SPHW_MBOX_INT_SET(WRITE_BACK, WB_EN);

	sphw_hwif_write_reg(func_to_func->hwdev->hwif, SPHW_FUNC_CSR_MAILBOX_INT_OFFSET_OFF,
			    mbox_int);

	wmb();	/* writing the mbox int attributes */
	mbox_ctrl = SPHW_MBOX_CTRL_SET(TX_NOT_DONE, TX_STATUS);

	mbox_ctrl |= SPHW_MBOX_CTRL_SET(NOT_TRIGGER, TRIGGER_AEQE);

	mbox_ctrl |= SPHW_MBOX_CTRL_SET(dst_func, DST_FUNC);

	sphw_hwif_write_reg(func_to_func->hwdev->hwif,
			    SPHW_FUNC_CSR_MAILBOX_CONTROL_OFF, mbox_ctrl);
}

void dump_mbox_reg(struct sphw_hwdev *hwdev)
{
	u32 val;

	val = sphw_hwif_read_reg(hwdev->hwif, SPHW_FUNC_CSR_MAILBOX_CONTROL_OFF);
	sdk_err(hwdev->dev_hdl, "Mailbox control reg: 0x%x\n", val);
	val = sphw_hwif_read_reg(hwdev->hwif, SPHW_FUNC_CSR_MAILBOX_INT_OFFSET_OFF);
	sdk_err(hwdev->dev_hdl, "Mailbox interrupt offset: 0x%x\n", val);
}

static u16 get_mbox_status(struct sphw_send_mbox *mbox)
{
	/* write back is 16B, but only use first 4B */
	u64 wb_val = be64_to_cpu(*mbox->wb_status);

	rmb(); /* verify reading before check */

	return (u16)(wb_val & MBOX_WB_STATUS_ERRCODE_MASK);
}

enum sphw_wait_return check_mbox_wb_status(void *priv_data)
{
	struct sphw_mbox *func_to_func = priv_data;
	u16 wb_status;

	if (MBOX_MSG_CHANNEL_STOP(func_to_func))
		return WAIT_PROCESS_ERR;

	wb_status = get_mbox_status(&func_to_func->send_mbox);

	return MBOX_STATUS_FINISHED(wb_status) ?
		WAIT_PROCESS_CPL : WAIT_PROCESS_WAITING;
}

static int send_mbox_seg(struct sphw_mbox *func_to_func, u64 header,
			 u16 dst_func, void *seg, u16 seg_len, void *msg_info)
{
	struct sphw_send_mbox *send_mbox = &func_to_func->send_mbox;
	struct sphw_hwdev *hwdev = func_to_func->hwdev;
	u8 num_aeqs = hwdev->hwif->attr.num_aeqs;
	u16 dst_aeqn, wb_status = 0, errcode;
	u16 seq_dir = SPHW_MSG_HEADER_GET(header, DIRECTION);
	int err;

	/* mbox to mgmt cpu, hardware don't care dst aeq id*/
	if (num_aeqs > SPHW_MBOX_RSP_MSG_AEQ)
		dst_aeqn = (seq_dir == SPHW_MSG_DIRECT_SEND) ?
			   SPHW_ASYNC_MSG_AEQ : SPHW_MBOX_RSP_MSG_AEQ;
	else
		dst_aeqn = 0;

	clear_mbox_status(send_mbox);

	mbox_copy_header(hwdev, send_mbox, &header);

	mbox_copy_send_data(hwdev, send_mbox, seg, seg_len);

	write_mbox_msg_attr(func_to_func, dst_func, dst_aeqn, seg_len);

	wmb();	/* writing the mbox msg attributes */

	err = sphw_wait_for_timeout(func_to_func, check_mbox_wb_status,
				    MBOX_MSG_POLLING_TIMEOUT, USEC_PER_MSEC);
	wb_status = get_mbox_status(send_mbox);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Send mailbox segment timeout, wb status: 0x%x\n",
			wb_status);
		dump_mbox_reg(hwdev);
		return -ETIMEDOUT;
	}

	if (!MBOX_STATUS_SUCCESS(wb_status)) {
		sdk_err(hwdev->dev_hdl, "Send mailbox segment to function %u error, wb status: 0x%x\n",
			dst_func, wb_status);
		errcode = MBOX_STATUS_ERRCODE(wb_status);
		return errcode ? errcode : -EFAULT;
	}

	return 0;
}

static int send_mbox_msg(struct sphw_mbox *func_to_func, u8 mod, u16 cmd,
			 void *msg, u16 msg_len, u16 dst_func,
			 enum sphw_msg_direction_type direction,
			 enum sphw_msg_ack_type ack_type,
			 struct mbox_msg_info *msg_info)
{
	struct sphw_hwdev *hwdev = func_to_func->hwdev;
	struct mbox_dma_msg dma_msg = {0};
	enum sphw_data_type data_type = SPHW_DATA_INLINE;
	int err = 0;
	u32 seq_id = 0;
	u16 seg_len = MBOX_SEG_LEN;
	u16 rsp_aeq_id, left;
	u8 *msg_seg = NULL;
	u64 header = 0;

	if (hwdev->poll || hwdev->hwif->attr.num_aeqs >= 2)
		rsp_aeq_id = SPHW_MBOX_RSP_MSG_AEQ;
	else
		rsp_aeq_id = 0;

	mutex_lock(&func_to_func->msg_send_lock);

	if (IS_DMA_MBX_MSG(dst_func)) {
		err = mbox_prepare_dma_msg(func_to_func, ack_type, &dma_msg, msg, msg_len);
		if (err)
			goto send_err;

		msg = &dma_msg;
		msg_len = sizeof(dma_msg);
		data_type = SPHW_DATA_DMA;
	}

	msg_seg = (u8 *)msg;
	left = msg_len;

	header = SPHW_MSG_HEADER_SET(msg_len, MSG_LEN) |
		 SPHW_MSG_HEADER_SET(mod, MODULE) |
		 SPHW_MSG_HEADER_SET(seg_len, SEG_LEN) |
		 SPHW_MSG_HEADER_SET(ack_type, NO_ACK) |
		 SPHW_MSG_HEADER_SET(data_type, DATA_TYPE) |
		 SPHW_MSG_HEADER_SET(SEQ_ID_START_VAL, SEQID) |
		 SPHW_MSG_HEADER_SET(NOT_LAST_SEGMENT, LAST) |
		 SPHW_MSG_HEADER_SET(direction, DIRECTION) |
		 SPHW_MSG_HEADER_SET(cmd, CMD) |
		 /* The vf's offset to it's associated pf */
		 SPHW_MSG_HEADER_SET(msg_info->msg_id, MSG_ID) |
		 SPHW_MSG_HEADER_SET(rsp_aeq_id, AEQ_ID) |
		 SPHW_MSG_HEADER_SET(SPHW_MSG_FROM_MBOX, SOURCE) |
		 SPHW_MSG_HEADER_SET(!!msg_info->status, STATUS) |
		 SPHW_MSG_HEADER_SET(sphw_global_func_id(hwdev), SRC_GLB_FUNC_IDX);

	while (!(SPHW_MSG_HEADER_GET(header, LAST))) {
		if (left <= MBOX_SEG_LEN) {
			header &= ~MBOX_SEGLEN_MASK;
			header |= SPHW_MSG_HEADER_SET(left, SEG_LEN);
			header |= SPHW_MSG_HEADER_SET(LAST_SEGMENT, LAST);

			seg_len = left;
		}

		err = send_mbox_seg(func_to_func, header, dst_func, msg_seg,
				    seg_len, msg_info);
		if (err) {
			sdk_err(hwdev->dev_hdl, "Failed to send mbox seg, seq_id=0x%llx\n",
				SPHW_MSG_HEADER_GET(header, SEQID));
			goto send_err;
		}

		left -= MBOX_SEG_LEN;
		msg_seg += MBOX_SEG_LEN;

		seq_id++;
		header &= ~(SPHW_MSG_HEADER_SET(SPHW_MSG_HEADER_SEQID_MASK, SEQID));
		header |= SPHW_MSG_HEADER_SET(seq_id, SEQID);
	}

send_err:
	mutex_unlock(&func_to_func->msg_send_lock);

	return err;
}

static void set_mbox_to_func_event(struct sphw_mbox *func_to_func,
				   enum mbox_event_state event_flag)
{
	spin_lock(&func_to_func->mbox_lock);
	func_to_func->event_flag = event_flag;
	spin_unlock(&func_to_func->mbox_lock);
}

static enum sphw_wait_return check_mbox_msg_finish(void *priv_data)
{
	struct sphw_mbox *func_to_func = priv_data;

	if (MBOX_MSG_CHANNEL_STOP(func_to_func))
		return WAIT_PROCESS_ERR;

	return (func_to_func->event_flag == EVENT_SUCCESS) ?
		WAIT_PROCESS_CPL : WAIT_PROCESS_WAITING;
}

static int wait_mbox_msg_completion(struct sphw_mbox *func_to_func,
				    u32 timeout)
{
	int err;

	timeout = timeout ? timeout : SPHW_MBOX_COMP_TIME;
	err = sphw_wait_for_timeout(func_to_func, check_mbox_msg_finish,
				    timeout, USEC_PER_MSEC);
	if (err) {
		set_mbox_to_func_event(func_to_func, EVENT_TIMEOUT);
		return -ETIMEDOUT;
	}

	set_mbox_to_func_event(func_to_func, EVENT_END);

	return 0;
}

#define TRY_MBOX_LOCK_SLEPP	1000
static int send_mbox_msg_lock(struct sphw_mbox *func_to_func, u16 channel)
{
	if (!func_to_func->lock_channel_en) {
		mutex_lock(&func_to_func->mbox_send_lock);
		return 0;
	}

	while (!test_bit(channel, &func_to_func->channel_stop)) {
		if (mutex_trylock(&func_to_func->mbox_send_lock))
			return 0;

		usleep_range(TRY_MBOX_LOCK_SLEPP - 1, TRY_MBOX_LOCK_SLEPP);
	}

	return -EAGAIN;
}

static void send_mbox_msg_unlock(struct sphw_mbox *func_to_func)
{
	mutex_unlock(&func_to_func->mbox_send_lock);
}

int sphw_mbox_to_func(struct sphw_mbox *func_to_func, u8 mod, u16 cmd, u16 dst_func, void *buf_in,
		      u16 in_size, void *buf_out, u16 *out_size, u32 timeout, u16 channel)
{
	/* use mbox_resp to hole data which responsed from other function */
	struct sphw_msg_desc *msg_desc = NULL;
	struct mbox_msg_info msg_info = {0};
	int err;

	if (!func_to_func->hwdev->chip_present_flag)
		return -EPERM;

	/* expect response message */
	msg_desc = get_mbox_msg_desc(func_to_func, SPHW_MSG_RESPONSE,
				     dst_func);
	if (!msg_desc)
		return -EFAULT;

	err = send_mbox_msg_lock(func_to_func, channel);
	if (err)
		return err;

	func_to_func->cur_msg_channel = channel;
	msg_info.msg_id = MBOX_MSG_ID_INC(func_to_func);

	set_mbox_to_func_event(func_to_func, EVENT_START);

	err = send_mbox_msg(func_to_func, mod, cmd, buf_in, in_size, dst_func,
			    SPHW_MSG_DIRECT_SEND, SPHW_MSG_ACK, &msg_info);
	if (err) {
		sdk_err(func_to_func->hwdev->dev_hdl, "Send mailbox mod %u, cmd %u failed, msg_id: %u, err: %d\n",
			mod, cmd, msg_info.msg_id, err);
		set_mbox_to_func_event(func_to_func, EVENT_FAIL);
		goto send_err;
	}

	if (wait_mbox_msg_completion(func_to_func, timeout)) {
		sdk_err(func_to_func->hwdev->dev_hdl,
			"Send mbox msg timeout, msg_id: %u\n", msg_info.msg_id);
		sphw_dump_aeq_info(func_to_func->hwdev);
		err = -ETIMEDOUT;
		goto send_err;
	}

	if (mod != msg_desc->mod || cmd != msg_desc->cmd) {
		sdk_err(func_to_func->hwdev->dev_hdl,
			"Invalid response mbox message, mod: 0x%x, cmd: 0x%x, expect mod: 0x%x, cmd: 0x%x\n",
			msg_desc->mod, msg_desc->cmd, mod, cmd);
		err = -EFAULT;
		goto send_err;
	}

	if (msg_desc->msg_info.status) {
		err = msg_desc->msg_info.status;
		goto send_err;
	}

	if (buf_out && out_size) {
		if (*out_size < msg_desc->msg_len) {
			sdk_err(func_to_func->hwdev->dev_hdl,
				"Invalid response mbox message length: %u for mod %d cmd %u, should less than: %u\n",
				msg_desc->msg_len, mod, cmd, *out_size);
			err = -EFAULT;
			goto send_err;
		}

		if (msg_desc->msg_len)
			memcpy(buf_out, msg_desc->msg, msg_desc->msg_len);

		*out_size = msg_desc->msg_len;
	}

send_err:
	send_mbox_msg_unlock(func_to_func);

	return err;
}

static int mbox_func_params_valid(struct sphw_mbox *func_to_func,
				  void *buf_in, u16 in_size, u16 channel)
{
	if (!buf_in || !in_size)
		return -EINVAL;

	if (in_size > SPHW_MBOX_DATA_SIZE) {
		sdk_err(func_to_func->hwdev->dev_hdl,
			"Mbox msg len %u exceed limit: [1, %u]\n",
			in_size, SPHW_MBOX_DATA_SIZE);
		return -EINVAL;
	}

	if (channel >= SPHW_CHANNEL_MAX) {
		sdk_err(func_to_func->hwdev->dev_hdl,
			"Invalid channel id: 0x%x\n", channel);
		return -EINVAL;
	}

	return 0;
}

int sphw_mbox_to_func_no_ack(struct sphw_hwdev *hwdev, u16 func_idx, u8 mod, u16 cmd,
			     void *buf_in, u16 in_size, u16 channel)
{
	struct mbox_msg_info msg_info = {0};
	int err = mbox_func_params_valid(hwdev->func_to_func, buf_in, in_size,
					 channel);

	if (err)
		return err;

	err = send_mbox_msg_lock(hwdev->func_to_func, channel);
	if (err)
		return err;

	err = send_mbox_msg(hwdev->func_to_func, mod, cmd, buf_in, in_size,
			    func_idx, SPHW_MSG_DIRECT_SEND,
			    SPHW_MSG_NO_ACK, &msg_info);
	if (err)
		sdk_err(hwdev->dev_hdl, "Send mailbox no ack failed\n");

	send_mbox_msg_unlock(hwdev->func_to_func);

	return err;
}

int sphw_send_mbox_to_mgmt(struct sphw_hwdev *hwdev, u8 mod, u16 cmd, void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size, u32 timeout, u16 channel)
{
	struct sphw_mbox *func_to_func = hwdev->func_to_func;
	int err = mbox_func_params_valid(func_to_func, buf_in, in_size, channel);

	if (err)
		return err;

	return sphw_mbox_to_func(func_to_func, mod, cmd, SPHW_MGMT_SRC_ID,
				 buf_in, in_size, buf_out, out_size, timeout, channel);
}

void sphw_response_mbox_to_mgmt(struct sphw_hwdev *hwdev, u8 mod, u16 cmd,
				void *buf_in, u16 in_size, u16 msg_id)
{
	struct mbox_msg_info msg_info;

	msg_info.msg_id = (u8)msg_id;
	msg_info.status = 0;

	send_mbox_msg(hwdev->func_to_func, mod, cmd, buf_in, in_size,
		      SPHW_MGMT_SRC_ID, SPHW_MSG_RESPONSE,
		      SPHW_MSG_NO_ACK, &msg_info);
}

int sphw_send_mbox_to_mgmt_no_ack(struct sphw_hwdev *hwdev, u8 mod, u16 cmd,
				  void *buf_in, u16 in_size, u16 channel)
{
	struct sphw_mbox *func_to_func = hwdev->func_to_func;
	int err = mbox_func_params_valid(func_to_func, buf_in, in_size,
					 channel);

	if (err)
		return err;

	return sphw_mbox_to_func_no_ack(hwdev, SPHW_MGMT_SRC_ID, mod, cmd,
					buf_in, in_size, channel);
}

int sphw_mbox_ppf_to_host(void *hwdev, u8 mod, u16 cmd, u8 host_id,
			  void *buf_in, u16 in_size, void *buf_out,
			  u16 *out_size, u32 timeout, u16 channel)
{
	struct sphw_hwdev *dev = hwdev;
	u16 dst_ppf_func;
	int err;

	if (!hwdev)
		return -EINVAL;

	if (!(dev->chip_present_flag))
		return -EPERM;

	err = mbox_func_params_valid(dev->func_to_func, buf_in, in_size,
				     channel);
	if (err)
		return err;

	if (!SPHW_IS_PPF(dev)) {
		sdk_err(dev->dev_hdl, "Params error, only ppf support send mbox to ppf. func_type: %d\n",
			sphw_func_type(dev));
		return -EINVAL;
	}

	if (host_id >= SPHW_MAX_HOST_NUM(dev) ||
	    host_id == SPHW_PCI_INTF_IDX(dev->hwif)) {
		sdk_err(dev->dev_hdl, "Params error, host id: %u\n", host_id);
		return -EINVAL;
	}

	dst_ppf_func = sphw_host_ppf_idx(dev, host_id);
	if (dst_ppf_func >= SPHW_MAX_PF_NUM(dev)) {
		sdk_err(dev->dev_hdl, "Dest host(%u) have not elect ppf(0x%x).\n",
			host_id, dst_ppf_func);
		return -EINVAL;
	}

	return sphw_mbox_to_func(dev->func_to_func, mod, cmd, dst_ppf_func, buf_in, in_size,
				 buf_out, out_size, timeout, channel);
}

int sphw_mbox_to_pf(void *hwdev, u8 mod, u16 cmd, void *buf_in, u16 in_size, void *buf_out,
		    u16 *out_size, u32 timeout, u16 channel)
{
	struct sphw_hwdev *dev = hwdev;
	int err;

	if (!hwdev)
		return -EINVAL;

	if (!(dev->chip_present_flag))
		return -EPERM;

	err = mbox_func_params_valid(dev->func_to_func, buf_in, in_size,
				     channel);
	if (err)
		return err;

	if (!SPHW_IS_VF(dev)) {
		sdk_err(dev->dev_hdl, "Params error, func_type: %d\n",
			sphw_func_type(dev));
		return -EINVAL;
	}

	return sphw_mbox_to_func(dev->func_to_func, mod, cmd, sphw_pf_id_of_vf(dev), buf_in,
				 in_size, buf_out, out_size, timeout, channel);
}

int sphw_mbox_to_vf(void *hwdev, u16 vf_id, u8 mod, u16 cmd, void *buf_in, u16 in_size,
		    void *buf_out, u16 *out_size, u32 timeout, u16 channel)
{
	struct sphw_mbox *func_to_func = NULL;
	int err = 0;
	u16 dst_func_idx;

	if (!hwdev)
		return -EINVAL;

	func_to_func = ((struct sphw_hwdev *)hwdev)->func_to_func;
	err = mbox_func_params_valid(func_to_func, buf_in, in_size, channel);
	if (err)
		return err;

	if (SPHW_IS_VF((struct sphw_hwdev *)hwdev)) {
		sdk_err(((struct sphw_hwdev *)hwdev)->dev_hdl, "Params error, func_type: %d\n",
			sphw_func_type(hwdev));
		return -EINVAL;
	}

	if (!vf_id) {
		sdk_err(((struct sphw_hwdev *)hwdev)->dev_hdl,
			"VF id(%u) error!\n", vf_id);
		return -EINVAL;
	}

	/* vf_offset_to_pf + vf_id is the vf's global function id of vf in
	 * this pf
	 */
	dst_func_idx = sphw_glb_pf_vf_offset(hwdev) + vf_id;

	return sphw_mbox_to_func(func_to_func, mod, cmd, dst_func_idx, buf_in,
				 in_size, buf_out, out_size, timeout, channel);
}

void sphw_mbox_enable_channel_lock(struct sphw_hwdev *hwdev, bool enable)
{
	hwdev->func_to_func->lock_channel_en = enable;

	sdk_info(hwdev->dev_hdl, "%s mbox channel lock\n",
		 enable ? "Enable" : "Disable");
}

static int alloc_mbox_msg_channel(struct sphw_msg_channel *msg_ch)
{
	msg_ch->resp_msg.msg = kzalloc(MBOX_MAX_BUF_SZ, GFP_KERNEL);
	if (!msg_ch->resp_msg.msg)
		return -ENOMEM;

	msg_ch->recv_msg.msg = kzalloc(MBOX_MAX_BUF_SZ, GFP_KERNEL);
	if (!msg_ch->recv_msg.msg) {
		kfree(msg_ch->resp_msg.msg);
		return -ENOMEM;
	}

	msg_ch->resp_msg.seq_id = SEQ_ID_MAX_VAL;
	msg_ch->recv_msg.seq_id = SEQ_ID_MAX_VAL;
	atomic_set(&msg_ch->recv_msg_cnt, 0);

	return 0;
}

static void free_mbox_msg_channel(struct sphw_msg_channel *msg_ch)
{
	kfree(msg_ch->recv_msg.msg);
	kfree(msg_ch->resp_msg.msg);
}

static int init_mgmt_msg_channel(struct sphw_mbox *func_to_func)
{
	int err;

	err = alloc_mbox_msg_channel(&func_to_func->mgmt_msg);
	if (err) {
		sdk_err(func_to_func->hwdev->dev_hdl, "Failed to alloc mgmt message channel\n");
		return err;
	}

	err = sphw_init_mbox_dma_queue(func_to_func);
	if (err) {
		sdk_err(func_to_func->hwdev->dev_hdl, "Failed to init mbox dma queue\n");
		free_mbox_msg_channel(&func_to_func->mgmt_msg);
	}

	return err;
}

static void deinit_mgmt_msg_channel(struct sphw_mbox *func_to_func)
{
	sphw_deinit_mbox_dma_queue(func_to_func);
	free_mbox_msg_channel(&func_to_func->mgmt_msg);
}

int sphw_mbox_init_host_msg_channel(struct sphw_hwdev *hwdev)
{
	struct sphw_mbox *func_to_func = hwdev->func_to_func;
	u8 host_num = SPHW_MAX_HOST_NUM(hwdev);
	int i, host_id, err;

	if (host_num == 0)
		return 0;

	func_to_func->host_msg = kcalloc(host_num,
					 sizeof(*func_to_func->host_msg),
					 GFP_KERNEL);
	if (!func_to_func->host_msg) {
		sdk_err(func_to_func->hwdev->dev_hdl, "Failed to alloc host message array\n");
		return -ENOMEM;
	}

	for (host_id = 0; host_id < host_num; host_id++) {
		err = alloc_mbox_msg_channel(&func_to_func->host_msg[host_id]);
		if (err) {
			sdk_err(func_to_func->hwdev->dev_hdl,
				"Failed to alloc host %d message channel\n",
				host_id);
			goto alloc_msg_ch_err;
		}
	}

	func_to_func->support_h2h_msg = true;

	return 0;

alloc_msg_ch_err:
	for (i = 0; i < host_id; i++)
		free_mbox_msg_channel(&func_to_func->host_msg[i]);

	kfree(func_to_func->host_msg);
	func_to_func->host_msg = NULL;

	return -ENOMEM;
}

static void deinit_host_msg_channel(struct sphw_mbox *func_to_func)
{
	int i;

	if (!func_to_func->host_msg)
		return;

	for (i = 0; i < SPHW_MAX_HOST_NUM(func_to_func->hwdev); i++)
		free_mbox_msg_channel(&func_to_func->host_msg[i]);

	kfree(func_to_func->host_msg);
	func_to_func->host_msg = NULL;
}

int sphw_init_func_mbox_msg_channel(void *hwdev, u16 num_func)
{
	struct sphw_hwdev *dev = hwdev;
	struct sphw_mbox *func_to_func = NULL;
	u16 func_id, i;
	int err;

	if (!hwdev || !num_func || num_func > SPHW_MAX_FUNCTIONS)
		return -EINVAL;

	func_to_func = dev->func_to_func;
	if (func_to_func->func_msg)
		return (func_to_func->num_func_msg == num_func) ? 0 : -EFAULT;

	func_to_func->func_msg =
		kcalloc(num_func, sizeof(*func_to_func->func_msg), GFP_KERNEL);
	if (!func_to_func->func_msg) {
		sdk_err(func_to_func->hwdev->dev_hdl, "Failed to alloc func message array\n");
		return -ENOMEM;
	}

	for (func_id = 0; func_id < num_func; func_id++) {
		err = alloc_mbox_msg_channel(&func_to_func->func_msg[func_id]);
		if (err) {
			sdk_err(func_to_func->hwdev->dev_hdl,
				"Failed to alloc func %hu message channel\n",
				func_id);
			goto alloc_msg_ch_err;
		}
	}

	func_to_func->num_func_msg = num_func;

	return 0;

alloc_msg_ch_err:
	for (i = 0; i < func_id; i++)
		free_mbox_msg_channel(&func_to_func->func_msg[i]);

	kfree(func_to_func->func_msg);
	func_to_func->func_msg = NULL;

	return -ENOMEM;
}

void sphw_deinit_func_mbox_msg_channel(struct sphw_hwdev *hwdev)
{
	struct sphw_mbox *func_to_func = hwdev->func_to_func;
	u16 i;

	if (!func_to_func->func_msg)
		return;

	for (i = 0; i < func_to_func->num_func_msg; i++)
		free_mbox_msg_channel(&func_to_func->func_msg[i]);

	kfree(func_to_func->func_msg);
	func_to_func->func_msg = NULL;
}

struct sphw_msg_desc *get_mbox_msg_desc(struct sphw_mbox *func_to_func, u64 dir, u64 src_func_id)
{
	struct sphw_hwdev *hwdev = func_to_func->hwdev;
	struct sphw_msg_channel *msg_ch = NULL;
	u16 id;

	if (src_func_id == SPHW_MGMT_SRC_ID) {
		msg_ch = &func_to_func->mgmt_msg;
	} else if (SPHW_IS_VF(hwdev)) {
		/* message from pf */
		msg_ch = func_to_func->func_msg;
		if (src_func_id != sphw_pf_id_of_vf(hwdev) || !msg_ch)
			return NULL;
	} else if (src_func_id > sphw_glb_pf_vf_offset(hwdev)) {
		/* message from vf */
		id = (u16)(src_func_id - 1U) - sphw_glb_pf_vf_offset(hwdev);
		if (id >= func_to_func->num_func_msg)
			return NULL;

		msg_ch = &func_to_func->func_msg[id];
	} else {
		/* message from other host's ppf */
		if (!func_to_func->support_h2h_msg)
			return NULL;

		for (id = 0; id < SPHW_MAX_HOST_NUM(hwdev); id++) {
			if (src_func_id == sphw_host_ppf_idx(hwdev, (u8)id))
				break;
		}

		if (id == SPHW_MAX_HOST_NUM(hwdev) || !func_to_func->host_msg)
			return NULL;

		msg_ch = &func_to_func->host_msg[id];
	}

	return (dir == SPHW_MSG_DIRECT_SEND) ?
		&msg_ch->recv_msg : &msg_ch->resp_msg;
}

static void prepare_send_mbox(struct sphw_mbox *func_to_func)
{
	struct sphw_send_mbox *send_mbox = &func_to_func->send_mbox;

	send_mbox->data = MBOX_AREA(func_to_func->hwdev->hwif);
}

static int alloc_mbox_wb_status(struct sphw_mbox *func_to_func)
{
	struct sphw_send_mbox *send_mbox = &func_to_func->send_mbox;
	struct sphw_hwdev *hwdev = func_to_func->hwdev;
	u32 addr_h, addr_l;

	send_mbox->wb_vaddr = dma_alloc_coherent(hwdev->dev_hdl, MBOX_WB_STATUS_LEN,
						 &send_mbox->wb_paddr, GFP_KERNEL);
	if (!send_mbox->wb_vaddr)
		return -ENOMEM;

	send_mbox->wb_status = send_mbox->wb_vaddr;

	addr_h = upper_32_bits(send_mbox->wb_paddr);
	addr_l = lower_32_bits(send_mbox->wb_paddr);

	sphw_hwif_write_reg(hwdev->hwif, SPHW_FUNC_CSR_MAILBOX_RESULT_H_OFF, addr_h);
	sphw_hwif_write_reg(hwdev->hwif, SPHW_FUNC_CSR_MAILBOX_RESULT_L_OFF, addr_l);

	return 0;
}

static void free_mbox_wb_status(struct sphw_mbox *func_to_func)
{
	struct sphw_send_mbox *send_mbox = &func_to_func->send_mbox;
	struct sphw_hwdev *hwdev = func_to_func->hwdev;

	sphw_hwif_write_reg(hwdev->hwif, SPHW_FUNC_CSR_MAILBOX_RESULT_H_OFF, 0);
	sphw_hwif_write_reg(hwdev->hwif, SPHW_FUNC_CSR_MAILBOX_RESULT_L_OFF, 0);

	dma_free_coherent(hwdev->dev_hdl, MBOX_WB_STATUS_LEN,
			  send_mbox->wb_vaddr, send_mbox->wb_paddr);
}

int sphw_func_to_func_init(struct sphw_hwdev *hwdev)
{
	struct sphw_mbox *func_to_func;
	int err;

	func_to_func = kzalloc(sizeof(*func_to_func), GFP_KERNEL);
	if (!func_to_func)
		return -ENOMEM;

	hwdev->func_to_func = func_to_func;
	func_to_func->hwdev = hwdev;
	mutex_init(&func_to_func->mbox_send_lock);
	mutex_init(&func_to_func->msg_send_lock);
	spin_lock_init(&func_to_func->mbox_lock);
	func_to_func->workq =
		create_singlethread_workqueue(SPHW_MBOX_WQ_NAME);
	if (!func_to_func->workq) {
		sdk_err(hwdev->dev_hdl, "Failed to initialize MBOX workqueue\n");
		err = -ENOMEM;
		goto create_mbox_workq_err;
	}

	err = init_mgmt_msg_channel(func_to_func);
	if (err)
		goto init_mgmt_msg_ch_err;

	if (SPHW_IS_VF(hwdev)) {
		/* VF to PF mbox message channel */
		err = sphw_init_func_mbox_msg_channel(hwdev, 1);
		if (err)
			goto init_func_msg_ch_err;
	}

	err = alloc_mbox_wb_status(func_to_func);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc mbox write back status\n");
		goto alloc_wb_status_err;
	}

	prepare_send_mbox(func_to_func);

	return 0;

alloc_wb_status_err:
	if (SPHW_IS_VF(hwdev))
		sphw_deinit_func_mbox_msg_channel(hwdev);

init_func_msg_ch_err:
	deinit_mgmt_msg_channel(func_to_func);

init_mgmt_msg_ch_err:
	destroy_workqueue(func_to_func->workq);

create_mbox_workq_err:
	kfree(func_to_func);

	return err;
}

void sphw_func_to_func_free(struct sphw_hwdev *hwdev)
{
	struct sphw_mbox *func_to_func = hwdev->func_to_func;

	/* destroy workqueue before free related mbox resources in case of
	 * illegal resource access
	 */
	destroy_workqueue(func_to_func->workq);

	free_mbox_wb_status(func_to_func);
	if (SPHW_IS_PPF(hwdev))
		deinit_host_msg_channel(func_to_func);
	sphw_deinit_func_mbox_msg_channel(hwdev);
	deinit_mgmt_msg_channel(func_to_func);

	kfree(func_to_func);
}
