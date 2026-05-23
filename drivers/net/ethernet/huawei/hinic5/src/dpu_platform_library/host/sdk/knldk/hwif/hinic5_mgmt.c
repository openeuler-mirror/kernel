/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_mgmt.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/semaphore.h>

#include "ossl_knl.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_common.h"
#include "mpu_inband_cmd.h"
#include "hinic5_hwdev.h"
#include "hinic5_bus.h"
#include "hinic5_eqs.h"
#include "hinic5_mbox.h"
#include "hinic5_api_cmd.h"
#include "hinic5_prof_adap.h"
#include "hinic5_csr_inner.h"
#include "hinic5_mgmt.h"

#define HINIC5_MSG_TO_MGMT_MAX_LEN	2016

#define HINIC5_API_CHAIN_AEQ_ID		2
#define MAX_PF_MGMT_BUF_SIZE		2048UL
#define SEGMENT_LEN			48
#define ASYNC_MSG_FLAG			0x8
#define MGMT_MSG_MAX_SEQ_ID	(ALIGN(HINIC5_MSG_TO_MGMT_MAX_LEN, \
				       SEGMENT_LEN) / SEGMENT_LEN)

#define MGMT_MSG_LAST_SEG_MAX_LEN	(MAX_PF_MGMT_BUF_SIZE - \
					 SEGMENT_LEN * MGMT_MSG_MAX_SEQ_ID)

#define BUF_OUT_DEFAULT_SIZE		1

#define MGMT_MSG_SIZE_MIN		20
#define MGMT_MSG_SIZE_STEP		16
#define	MGMT_MSG_RSVD_FOR_DEV		8

#define SYNC_MSG_ID_MASK		0x7
#define ASYNC_MSG_ID_MASK		0x7

#define SYNC_FLAG			0
#define ASYNC_FLAG			1

#define MSG_NO_RESP			0xFFFF

#ifdef PLATFORM_MODE_FPGA
#define MGMT_MSG_TIMEOUT		200000
#else
#define MGMT_MSG_TIMEOUT		20000
#endif

#define SYNC_MSG_ID(pf_to_mgmt)	((pf_to_mgmt)->sync_msg_id)

#define SYNC_MSG_ID_INC(pf_to_mgmt)	(SYNC_MSG_ID(pf_to_mgmt) = \
			(SYNC_MSG_ID(pf_to_mgmt) + 1) & SYNC_MSG_ID_MASK)
#define ASYNC_MSG_ID(pf_to_mgmt)	((pf_to_mgmt)->async_msg_id)

#define ASYNC_MSG_ID_INC(pf_to_mgmt)	(ASYNC_MSG_ID(pf_to_mgmt) = \
			((ASYNC_MSG_ID(pf_to_mgmt) + 1) & ASYNC_MSG_ID_MASK) \
			 | ASYNC_MSG_FLAG)

static void pf_to_mgmt_send_event_set(struct hinic5_msg_pf_to_mgmt *pf_to_mgmt,
				      int event_flag)
{
	spin_lock(&pf_to_mgmt->sync_event_lock);
	pf_to_mgmt->event_flag = event_flag;
	spin_unlock(&pf_to_mgmt->sync_event_lock);
}

/**
 * hinic5_register_mgmt_msg_cb - register sync msg handler for a module
 * @hwdev: the pointer to hw device
 * @mod: module in the chip that this handler will handle its sync messages
 * @pri_handle: specific mod's private data that will be used in callback
 * @callback: the handler for a sync message that will handle messages
 **/
int hinic5_register_mgmt_msg_cb(void *hwdev, u8 mod, void *pri_handle,
				hinic5_mgmt_msg_cb callback)
{
	struct hinic5_msg_pf_to_mgmt *pf_to_mgmt = NULL;

	if (mod >= HINIC5_MOD_HW_MAX || !hwdev)
		return -EFAULT;

	pf_to_mgmt = ((struct hinic5_hwdev *)hwdev)->pf_to_mgmt;
	if (!pf_to_mgmt)
		return -EINVAL;

	pf_to_mgmt->recv_mgmt_msg_cb[mod] = callback;
	pf_to_mgmt->recv_mgmt_msg_data[mod] = pri_handle;

	set_bit(HINIC5_MGMT_MSG_CB_REG, &pf_to_mgmt->mgmt_msg_cb_state[mod]);

	return 0;
}
EXPORT_SYMBOL(hinic5_register_mgmt_msg_cb);

/**
 * hinic5_unregister_mgmt_msg_cb - unregister sync msg handler for a module
 * @hwdev: the pointer to hw device
 * @mod: module in the chip that this handler will handle its sync messages
 **/
void hinic5_unregister_mgmt_msg_cb(void *hwdev, u8 mod)
{
	struct hinic5_msg_pf_to_mgmt *pf_to_mgmt = NULL;

	if (!hwdev || mod >= HINIC5_MOD_HW_MAX)
		return;

	pf_to_mgmt = ((struct hinic5_hwdev *)hwdev)->pf_to_mgmt;
	if (!pf_to_mgmt)
		return;

	clear_bit(HINIC5_MGMT_MSG_CB_REG, &pf_to_mgmt->mgmt_msg_cb_state[mod]);

	while (test_bit(HINIC5_MGMT_MSG_CB_RUNNING,
			&pf_to_mgmt->mgmt_msg_cb_state[mod]))
		usleep_range(900, 1000); /* sleep 900 us ~ 1000 us */

	pf_to_mgmt->recv_mgmt_msg_cb[mod] = NULL;
	pf_to_mgmt->recv_mgmt_msg_data[mod] = NULL;
}
EXPORT_SYMBOL(hinic5_unregister_mgmt_msg_cb);

/**
 * mgmt_msg_len - calculate the total message length
 * @msg_data_len: the length of the message data
 * Return: the total message length
 **/
static u16 mgmt_msg_len(u16 msg_data_len)
{
	/* u64 - the size of the header */
	u16 msg_size;

	msg_size = (u16)(MGMT_MSG_RSVD_FOR_DEV + sizeof(u64) + msg_data_len);

	if (msg_size > MGMT_MSG_SIZE_MIN)
		msg_size = MGMT_MSG_SIZE_MIN +
				ALIGN((msg_size - MGMT_MSG_SIZE_MIN),
				      MGMT_MSG_SIZE_STEP);
	else
		msg_size = MGMT_MSG_SIZE_MIN;

	return msg_size;
}

/**
 * prepare_header - prepare the header of the message
 * @pf_to_mgmt: PF to MGMT channel
 * @header: pointer of the header to prepare
 * @msg_len: the length of the message
 * @mod: module in the chip that will get the message
 * @direction: the direction of the original message
 * @msg_id: message id
 **/
static void prepare_header(struct hinic5_msg_pf_to_mgmt *pf_to_mgmt,
			   u64 *header, u16 msg_len, u8 mod,
			   enum hinic5_msg_ack_type ack_type,
			   enum hinic5_mgmt_cmd cmd, u32 msg_id)
{
	struct hinic5_hwif *hwif = pf_to_mgmt->hwdev->hwif;

	mbox_msg_header_set_last(header, msg_len, mod, msg_len, pf_to_mgmt->hwdev);

	*header |= HINIC5_MSG_HEADER_SET(ack_type, NO_ACK) |
		HINIC5_MSG_HEADER_SET(HINIC5_DATA_INLINE, DATA_TYPE) |
		HINIC5_MSG_HEADER_SET(0, SEQID) |
		HINIC5_MSG_HEADER_SET(HINIC5_API_CHAIN_AEQ_ID, AEQ_ID) |
		HINIC5_MSG_HEADER_SET(LAST_SEGMENT, LAST) |
		HINIC5_MSG_HEADER_SET(HINIC5_MSG_DIRECT_SEND, DIRECTION) |
		HINIC5_MSG_HEADER_SET(cmd, CMD) |
		HINIC5_MSG_HEADER_SET(HINIC5_MSG_FROM_MGMT, SOURCE) |
		HINIC5_MSG_HEADER_SET(hwif->attr.func_global_idx,
				      SRC_GLB_FUNC_IDX) |
		HINIC5_MSG_HEADER_SET(msg_id, MSG_ID);
}

static void clp_prepare_header(struct hinic5_hwdev *hwdev, u64 *header,
			       u16 msg_len, u8 mod,
			       enum hinic5_mgmt_cmd cmd)
{
	struct hinic5_hwif *hwif = hwdev->hwif;

	mbox_msg_header_set_last(header, msg_len, mod, msg_len, hwdev);
	*header |= HINIC5_MSG_HEADER_SET(0, NO_ACK) |
		HINIC5_MSG_HEADER_SET(HINIC5_DATA_INLINE, DATA_TYPE) |
		HINIC5_MSG_HEADER_SET(0, SEQID) |
		HINIC5_MSG_HEADER_SET(HINIC5_API_CHAIN_AEQ_ID, AEQ_ID) |
		HINIC5_MSG_HEADER_SET(LAST_SEGMENT, LAST) |
		HINIC5_MSG_HEADER_SET(0, DIRECTION) |
		HINIC5_MSG_HEADER_SET(cmd, CMD) |
		HINIC5_MSG_HEADER_SET(hwif->attr.func_global_idx,
				      SRC_GLB_FUNC_IDX) |
		HINIC5_MSG_HEADER_SET(0, MSG_ID);
}

/**
 * prepare_mgmt_cmd - prepare the mgmt command
 * @mgmt_cmd: pointer to the command to prepare
 * @header: pointer of the header to prepare
 * @msg: the data of the message
 * @msg_len: the length of the message
 **/
static int prepare_mgmt_cmd(u8 *mgmt_cmd, u64 *header, const void *msg,
			    int msg_len)
{
	u8 *mgmt_cmd_new = mgmt_cmd;

	memset(mgmt_cmd_new, 0, MGMT_MSG_RSVD_FOR_DEV);

	mgmt_cmd_new += MGMT_MSG_RSVD_FOR_DEV;
	memcpy(mgmt_cmd_new, header, sizeof(*header));

	mgmt_cmd_new += sizeof(*header);
	memcpy(mgmt_cmd_new, msg, (size_t)(u32)msg_len);

	return 0;
}

/**
 * send_msg_to_mgmt_sync - send async message
 * @pf_to_mgmt: PF to MGMT channel
 * @mod: module in the chip that will get the message
 * @cmd: command of the message
 * @msg: the msg data
 * @msg_len: the msg data length
 * @direction: the direction of the original message
 * @resp_msg_id: msg id to response for
 * Return: 0 - success, negative - failure
 **/
static int send_msg_to_mgmt_sync(struct hinic5_msg_pf_to_mgmt *pf_to_mgmt,
				 u8 mod, u16 cmd, const void *msg, u16 msg_len)
{
	void *mgmt_cmd = pf_to_mgmt->sync_msg_buf;
	struct hinic5_api_cmd_chain *chain = NULL;
	u8 node_id = HINIC5_MGMT_CPU_NODE_ID(pf_to_mgmt->hwdev);
	u64 header = 0;
	u16 cmd_size = mgmt_msg_len(msg_len);
	int ret;

	if (hinic5_get_chip_present_flag(pf_to_mgmt->hwdev) == 0)
		return -EFAULT;

	if (cmd_size > HINIC5_MSG_TO_MGMT_MAX_LEN)
		return -EFAULT;

	prepare_header(pf_to_mgmt, &header, msg_len, mod, HINIC5_MSG_ACK,
		       cmd, SYNC_MSG_ID_INC(pf_to_mgmt));
	chain = pf_to_mgmt->cmd_chain[HINIC5_API_CMD_WRITE_TO_MGMT_CPU];

	pf_to_mgmt_send_event_set(pf_to_mgmt, SEND_EVENT_START);

	ret = prepare_mgmt_cmd((u8 *)mgmt_cmd, &header, msg, msg_len);
	if (ret != 0)
		return ret;

	return hinic5_api_cmd_write(chain, node_id, mgmt_cmd, cmd_size);
}

/**
 * send_msg_to_mgmt_async - send async message
 * @pf_to_mgmt: PF to MGMT channel
 * @mod: module in the chip that will get the message
 * @cmd: command of the message
 * @msg: the data of the message
 * @msg_len: the length of the message
 * @direction: the direction of the original message
 * Return: 0 - success, negative - failure
 **/
static int send_msg_to_mgmt_async(struct hinic5_msg_pf_to_mgmt *pf_to_mgmt,
				  u8 mod, u16 cmd, const void *msg, u16 msg_len)
{
	void *mgmt_cmd = pf_to_mgmt->async_msg_buf;
	struct hinic5_api_cmd_chain *chain = NULL;
	u8 node_id = HINIC5_MGMT_CPU_NODE_ID(pf_to_mgmt->hwdev);
	u64 header = 0;
	u16 cmd_size = mgmt_msg_len(msg_len);
	int ret;

	if (hinic5_get_chip_present_flag(pf_to_mgmt->hwdev) == 0)
		return -EFAULT;

	if (cmd_size > HINIC5_MSG_TO_MGMT_MAX_LEN)
		return -EFAULT;

	prepare_header(pf_to_mgmt, &header, msg_len, mod, HINIC5_MSG_NO_ACK,
		       cmd, ASYNC_MSG_ID(pf_to_mgmt));

	ret = prepare_mgmt_cmd((u8 *)mgmt_cmd, &header, msg, msg_len);
	if (ret != 0)
		return ret;

	chain = pf_to_mgmt->cmd_chain[HINIC5_API_CMD_WRITE_ASYNC_TO_MGMT_CPU];

	return hinic5_api_cmd_write(chain, node_id, mgmt_cmd, cmd_size);
}

static inline int msg_to_mgmt_pre(u8 mod, void *buf_in, u16 in_size)
{
	struct hinic5_msg_head *msg_head = NULL;

	/* set aeq fix num to 3, need to ensure response aeq id < 3 */
	if (mod == HINIC5_MOD_COMM || mod == HINIC5_MOD_L2NIC) {
		if (in_size < sizeof(struct hinic5_msg_head))
			return -EINVAL;

		msg_head = buf_in;

		if (msg_head->resp_aeq_num >= HINIC5_MAX_AEQS)
			msg_head->resp_aeq_num = 0;
	}

	return 0;
}

static int msg_to_mgmt_wait_completion(void *hwdev, u32 timeout)
{
	struct hinic5_msg_pf_to_mgmt *pf_to_mgmt = NULL;
	void *dev = ((struct hinic5_hwdev *)hwdev)->dev_hdl;
	struct hinic5_recv_msg *recv_msg = NULL;
	ulong timeo;
	ulong ret;

	pf_to_mgmt = ((struct hinic5_hwdev *)hwdev)->pf_to_mgmt;
	recv_msg = &pf_to_mgmt->recv_resp_msg_from_mgmt;

	timeo = msecs_to_jiffies((timeout != 0) ? timeout : MGMT_MSG_TIMEOUT);

	ret = wait_for_completion_timeout(&recv_msg->recv_done, timeo);
	if (ret == 0) {
		sdk_err(dev, "Mgmt response sync cmd timeout, sync_msg_id: %u\n",
			pf_to_mgmt->sync_msg_id);
		hinic5_dump_aeq_info((struct hinic5_hwdev *)hwdev);
		pf_to_mgmt_send_event_set(pf_to_mgmt, SEND_EVENT_TIMEOUT);
		return -ETIMEDOUT;
	}

	spin_lock(&pf_to_mgmt->sync_event_lock);
	if (pf_to_mgmt->event_flag == SEND_EVENT_TIMEOUT) {
		spin_unlock(&pf_to_mgmt->sync_event_lock);
		return -ETIMEDOUT;
	}
	spin_unlock(&pf_to_mgmt->sync_event_lock);

	pf_to_mgmt_send_event_set(pf_to_mgmt, SEND_EVENT_END);

	if (!hinic5_is_chip_present(hwdev))
		return -ETIMEDOUT;

	return 0;
}

int hinic5_pf_to_mgmt_sync(void *hwdev, u8 mod, u16 cmd, void *buf_in,
			   u16 in_size, void *buf_out, u16 *out_size, u32 timeout)
{
	struct hinic5_msg_pf_to_mgmt *pf_to_mgmt = NULL;
	void *dev = ((struct hinic5_hwdev *)hwdev)->dev_hdl;
	struct hinic5_recv_msg *recv_msg = NULL;
	struct completion *recv_done = NULL;
	int err;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	if (!buf_in || in_size == 0)
		return -EINVAL;

	err = msg_to_mgmt_pre(mod, buf_in, in_size);
	if (err != 0)
		return -EINVAL;

	pf_to_mgmt = ((struct hinic5_hwdev *)hwdev)->pf_to_mgmt;

	/* Lock the sync_msg_buf */
	down(&pf_to_mgmt->sync_msg_lock);
	recv_msg = &pf_to_mgmt->recv_resp_msg_from_mgmt;
	recv_done = &recv_msg->recv_done;

	init_completion(recv_done);

	err = send_msg_to_mgmt_sync(pf_to_mgmt, mod, cmd, buf_in, in_size);
	if (err != 0) {
		sdk_err(dev, "Failed to send sync msg to mgmt, sync_msg_id: %u\n",
			pf_to_mgmt->sync_msg_id);
		pf_to_mgmt_send_event_set(pf_to_mgmt, SEND_EVENT_FAIL);
		goto unlock_sync_msg;
	}

	err = msg_to_mgmt_wait_completion(hwdev, timeout);
	if (err != 0)
		goto unlock_sync_msg;

	if (buf_out && out_size) {
		if (*out_size < recv_msg->msg_len) {
			sdk_err(dev, "Invalid response message length: %u for mod %u cmd %u from mgmt, should less than: %u\n",
				recv_msg->msg_len, mod, cmd, *out_size);
			err = -EFAULT;
			goto unlock_sync_msg;
		}

		if (recv_msg->msg_len != 0)
			memcpy(buf_out, recv_msg->msg, recv_msg->msg_len);

		*out_size = recv_msg->msg_len;
	}

unlock_sync_msg:
	destroy_completion(recv_done);
	up(&pf_to_mgmt->sync_msg_lock);
	return err;
}

int hinic5_pf_to_mgmt_async(void *hwdev, u8 mod, u16 cmd, const void *buf_in,
			    u16 in_size)
{
	struct hinic5_msg_pf_to_mgmt *pf_to_mgmt = NULL;
	void *dev = ((struct hinic5_hwdev *)hwdev)->dev_hdl;
	int err;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	pf_to_mgmt = ((struct hinic5_hwdev *)hwdev)->pf_to_mgmt;

	/* Lock the async_msg_buf */
	spin_lock_bh(&pf_to_mgmt->async_msg_lock);
	ASYNC_MSG_ID_INC(pf_to_mgmt);

	err = send_msg_to_mgmt_async(pf_to_mgmt, mod, cmd, buf_in, in_size);
	spin_unlock_bh(&pf_to_mgmt->async_msg_lock);

	if (err != 0) {
		sdk_err(dev, "Failed to send async mgmt msg\n");
		return err;
	}

	return 0;
}

int hinic5_pf_msg_to_mgmt_sync(void *hwdev, u8 mod, u16 cmd, void *buf_in,
			       u16 in_size, void *buf_out, u16 *out_size,
			       u32 timeout)
{
	if (!hwdev)
		return -EINVAL;

	if (hinic5_get_chip_present_flag(hwdev) == 0)
		return -EPERM;

	if (in_size > HINIC5_MSG_TO_MGMT_MAX_LEN)
		return -EINVAL;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	return hinic5_pf_to_mgmt_sync(hwdev, mod, cmd, buf_in, in_size,
				      buf_out, out_size, timeout);
}

int hinic5_msg_to_mgmt_sync(void *hwdev, u8 mod, u16 cmd, void *buf_in,
			    u16 in_size, void *buf_out, u16 *out_size,
			    u32 timeout, u16 channel)
{
	if (!hwdev)
		return -EINVAL;

	if (hinic5_get_chip_present_flag(hwdev) == 0)
		return -EPERM;

	return hinic5_send_mbox_to_mgmt(hwdev, mod, cmd, buf_in, in_size,
					buf_out, out_size, timeout, channel);
}
EXPORT_SYMBOL(hinic5_msg_to_mgmt_sync);

int hinic5_msg_to_mgmt_no_ack(void *hwdev, u8 mod, u16 cmd, void *buf_in,
			      u16 in_size, u16 channel)
{
	if (!hwdev)
		return -EINVAL;

	if (hinic5_get_chip_present_flag(hwdev) == 0)
		return -EPERM;

	return hinic5_send_mbox_to_mgmt_no_ack(hwdev, mod, cmd, buf_in,
					       in_size, channel);
}
EXPORT_SYMBOL(hinic5_msg_to_mgmt_no_ack);

int hinic5_msg_to_mgmt_async(void *hwdev, u8 mod, u16 cmd, const void *buf_in,
			     u16 in_size, u16 channel)
{
	return hinic5_msg_to_mgmt_api_chain_async(hwdev, mod, cmd, buf_in,
						  in_size);
}
EXPORT_SYMBOL(hinic5_msg_to_mgmt_async);

int hinic5_msg_to_mgmt_api_chain_sync(void *hwdev, u8 mod, u16 cmd,
				      void *buf_in, u16 in_size, void *buf_out,
				      u16 *out_size, u32 timeout)
{
	if (!hwdev)
		return -EINVAL;

	if (hinic5_get_chip_present_flag(hwdev) == 0)
		return -EPERM;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev)) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"PF don't support api chain\n");
		return -EPERM;
	}

	return hinic5_pf_msg_to_mgmt_sync(hwdev, mod, cmd, buf_in, in_size,
					  buf_out, out_size, timeout);
}

int hinic5_msg_to_mgmt_api_chain_async(void *hwdev, u8 mod, u16 cmd,
				       const void *buf_in, u16 in_size)
{
	int err;

	if (!hwdev)
		return -EINVAL;

	if (hinic5_func_type(hwdev) == TYPE_VF) {
		err = -EFAULT;
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"VF don't support async cmd\n");
	} else if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev)) {
		err = -EPERM;
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"PF don't support api chain\n");
	} else {
		err = hinic5_pf_to_mgmt_async(hwdev, mod, cmd, buf_in, in_size);
	}

	return err;
}
EXPORT_SYMBOL(hinic5_msg_to_mgmt_api_chain_async);

bool hinic5_is_multi_bm(void *hwdev)
{
	struct hinic5_hwdev *hw_dev = hwdev;

	if (!hwdev)
		return false;

	return ((IS_BMGW_SLAVE_HOST(hw_dev)) || (IS_BMGW_MASTER_HOST(hw_dev))) ? true : false;
}
EXPORT_SYMBOL(hinic5_is_multi_bm);

bool hinic5_is_slave_host(void *hwdev)
{
	struct hinic5_hwdev *hw_dev = hwdev;

	if (!hwdev) {
		pr_err("hwdev is null\n");
		return false;
	}

	return ((IS_BMGW_SLAVE_HOST(hw_dev)) || (IS_VM_SLAVE_HOST(hw_dev))) ? true : false;
}
EXPORT_SYMBOL(hinic5_is_slave_host);

bool hinic5_is_master_host(void *hwdev)
{
	struct hinic5_hwdev *hw_dev = hwdev;

	if (!hwdev) {
		pr_err("hwdev is null\n");
		return false;
	}

	return ((IS_BMGW_MASTER_HOST(hw_dev)) || (IS_VM_MASTER_HOST(hw_dev))) ? true : false;
}
EXPORT_SYMBOL(hinic5_is_master_host);

static void send_mgmt_ack(struct hinic5_msg_pf_to_mgmt *pf_to_mgmt,
			  u8 mod, u16 cmd, void *buf_in, u16 in_size,
			  u16 msg_id)
{
	u16 buf_size;

	if (in_size == 0)
		buf_size = BUF_OUT_DEFAULT_SIZE;
	else
		buf_size = in_size;

	hinic5_response_mbox_to_mgmt(pf_to_mgmt->hwdev, mod, cmd, buf_in,
				     buf_size, msg_id);
}

static void mgmt_recv_msg_handler(struct hinic5_msg_pf_to_mgmt *pf_to_mgmt,
				  u8 mod, u16 cmd, void *buf_in, u16 in_size,
				  u16 msg_id, bool need_resp)
{
	void *dev = pf_to_mgmt->hwdev->dev_hdl;
	void *buf_out = pf_to_mgmt->mgmt_ack_buf;
	enum hinic5_mod_type tmp_mod = mod;
	u16 out_size = 0;

	memset(buf_out, 0, MAX_PF_MGMT_BUF_SIZE);

	if (mod >= HINIC5_MOD_HW_MAX) {
		sdk_warn(dev, "Receive illegal message from mgmt cpu, mod = %u\n",
			 mod);
		goto unsupported;
	}

	set_bit(HINIC5_MGMT_MSG_CB_RUNNING,
		&pf_to_mgmt->mgmt_msg_cb_state[tmp_mod]);

	if (!pf_to_mgmt->recv_mgmt_msg_cb[mod] ||
	    !test_bit(HINIC5_MGMT_MSG_CB_REG,
	    &pf_to_mgmt->mgmt_msg_cb_state[tmp_mod])) {
		sdk_warn(dev, "Receive mgmt callback is null, mod = %u, cmd=%u\n", mod, cmd);
		clear_bit(HINIC5_MGMT_MSG_CB_RUNNING,
			  &pf_to_mgmt->mgmt_msg_cb_state[tmp_mod]);
		goto unsupported;
	}

	pf_to_mgmt->recv_mgmt_msg_cb[tmp_mod](pf_to_mgmt->recv_mgmt_msg_data[tmp_mod],
					cmd, buf_in, in_size,
					buf_out, &out_size);

	clear_bit(HINIC5_MGMT_MSG_CB_RUNNING,
		  &pf_to_mgmt->mgmt_msg_cb_state[tmp_mod]);

	goto resp;

unsupported:
	out_size = sizeof(struct mgmt_msg_head);
	((struct mgmt_msg_head *)buf_out)->status = HINIC5_MGMT_CMD_UNSUPPORTED;

resp:
	if (need_resp)
		send_mgmt_ack(pf_to_mgmt, mod, cmd, buf_out, out_size, msg_id);
}

/**
 * mgmt_resp_msg_handler - handler for response message from mgmt cpu
 * @pf_to_mgmt: PF to MGMT channel
 * @recv_msg: received message details
 **/
static void mgmt_resp_msg_handler(struct hinic5_msg_pf_to_mgmt *pf_to_mgmt,
				  struct hinic5_recv_msg *recv_msg)
{
	void *dev = pf_to_mgmt->hwdev->dev_hdl;

	/* delete async msg */
	if ((recv_msg->msg_id & ASYNC_MSG_FLAG) != 0)
		return;

	spin_lock(&pf_to_mgmt->sync_event_lock);
	if (recv_msg->msg_id == pf_to_mgmt->sync_msg_id &&
	    pf_to_mgmt->event_flag == SEND_EVENT_START) {
		pf_to_mgmt->event_flag = SEND_EVENT_SUCCESS;
		complete(&recv_msg->recv_done);
	} else if (recv_msg->msg_id != pf_to_mgmt->sync_msg_id) {
		sdk_err(dev, "Send msg id(0x%x) recv msg id(0x%x) dismatch, event state=%d\n",
			pf_to_mgmt->sync_msg_id, recv_msg->msg_id,
			pf_to_mgmt->event_flag);
	} else {
		sdk_err(dev, "Wait timeout, send msg id(0x%x) recv msg id(0x%x), event state=%d!\n",
			pf_to_mgmt->sync_msg_id, recv_msg->msg_id,
			pf_to_mgmt->event_flag);
	}
	spin_unlock(&pf_to_mgmt->sync_event_lock);
}

static void recv_mgmt_msg_work_handler(struct work_struct *work)
{
	struct hinic5_mgmt_msg_handle_work *mgmt_work =
		container_of(work, struct hinic5_mgmt_msg_handle_work, work);

	mgmt_recv_msg_handler(mgmt_work->pf_to_mgmt, mgmt_work->mod,
			      mgmt_work->cmd, mgmt_work->msg,
			      mgmt_work->msg_len, mgmt_work->msg_id,
			      (mgmt_work->async_mgmt_to_pf == 0));

	destroy_work(&mgmt_work->work);

	kfree(mgmt_work->msg);
	kfree(mgmt_work);
}

static bool check_mgmt_head_info(struct hinic5_recv_msg *recv_msg,
				 u8 seq_id, u8 seg_len, u16 msg_id)
{
	if (seq_id > MGMT_MSG_MAX_SEQ_ID || seg_len > SEGMENT_LEN ||
	    (seq_id == MGMT_MSG_MAX_SEQ_ID && seg_len > MGMT_MSG_LAST_SEG_MAX_LEN))
		return false;

	if (seq_id == 0) {
		recv_msg->seq_id = seq_id;
		recv_msg->msg_id = msg_id;
	} else {
		if (seq_id != recv_msg->seq_id + 1 || msg_id != recv_msg->msg_id)
			return false;

		recv_msg->seq_id = seq_id;
	}

	return true;
}

static void init_mgmt_msg_work(struct hinic5_msg_pf_to_mgmt *pf_to_mgmt,
			       struct hinic5_recv_msg *recv_msg)
{
	struct hinic5_mgmt_msg_handle_work *mgmt_work = NULL;
	struct hinic5_hwdev *hwdev = pf_to_mgmt->hwdev;

	mgmt_work = kzalloc(sizeof(*mgmt_work), GFP_KERNEL);
	if (!mgmt_work)
		return;

	if (recv_msg->msg_len != 0) {
		mgmt_work->msg = kzalloc(recv_msg->msg_len, GFP_KERNEL);
		if (!mgmt_work->msg)
			goto msg_alloc_err;
	}

	mgmt_work->pf_to_mgmt = pf_to_mgmt;
	mgmt_work->msg_len = recv_msg->msg_len;
	memcpy(mgmt_work->msg, recv_msg->msg, recv_msg->msg_len);

	mgmt_work->msg_id = recv_msg->msg_id;
	mgmt_work->mod = recv_msg->mod;
	mgmt_work->cmd = recv_msg->cmd;
	mgmt_work->async_mgmt_to_pf = recv_msg->async_mgmt_to_pf;

	INIT_WORK(&mgmt_work->work, recv_mgmt_msg_work_handler);
	queue_work_on(hisdk5_get_work_cpu_affinity(hwdev, WORK_TYPE_MGMT_MSG),
		      pf_to_mgmt->workq, &mgmt_work->work);
	return;

msg_alloc_err:
	kfree(mgmt_work);
}

/**
 * recv_mgmt_msg_handler - handler a message from mgmt cpu
 * @pf_to_mgmt: PF to MGMT channel
 * @header: the header of the message
 * @recv_msg: received message details
 **/
static void recv_mgmt_msg_handler(struct hinic5_msg_pf_to_mgmt *pf_to_mgmt,
				  u8 *header, struct hinic5_recv_msg *recv_msg)
{
	struct hinic5_hwdev *hwdev = pf_to_mgmt->hwdev;
	u64 mbox_header = *((u64 *)header);
	void *msg_body = (void *)((uintptr_t)header + sizeof(mbox_header));
	u8 seq_id, seq_len, version;
	u16 msg_id;
	u32 offset;
	u64 dir;

	version = hinic5_mbox_get_version(hwdev, &mbox_header);
	/* Don't need to get anything from hw when cmd is async */
	dir = HINIC5_MSG_HEADER_GET(mbox_header, DIRECTION);
	if (dir == HINIC5_MSG_RESPONSE &&
	    ((HINIC5_MSG_HEADER_GET(mbox_header, MSG_ID) & ASYNC_MSG_FLAG) != 0))
		return;

	seq_len = hinic5_mbox_get_seg_len(version, &mbox_header);
	seq_id  = HINIC5_MSG_HEADER_GET(mbox_header, SEQID);
	msg_id = HINIC5_MSG_HEADER_GET(mbox_header, MSG_ID);
	if (!check_mgmt_head_info(recv_msg, seq_id, seq_len, msg_id)) {
		sdk_err(hwdev->dev_hdl, "Mgmt msg sequence id and segment length check failed\n");
		sdk_err(hwdev->dev_hdl,
			"Front seq_id: 0x%x,current seq_id: 0x%x, seg len: 0x%x, front msg_id: %u, cur: %u\n",
			recv_msg->seq_id, seq_id, seq_len, recv_msg->msg_id, msg_id);
		/* set seq_id to invalid seq_id */
		recv_msg->seq_id = MGMT_MSG_MAX_SEQ_ID;
		return;
	}

	offset  = seq_id * SEGMENT_LEN;
	memcpy((u8 *)recv_msg->msg + offset, msg_body, seq_len);

	if (HINIC5_MSG_HEADER_GET(mbox_header, LAST) == 0)
		return;

	recv_msg->cmd = HINIC5_MSG_HEADER_GET(mbox_header, CMD);
	recv_msg->mod = hinic5_mbox_get_mod_id(version, &mbox_header);
	recv_msg->async_mgmt_to_pf = HINIC5_MSG_HEADER_GET(mbox_header,
							   NO_ACK);
	recv_msg->msg_len = hinic5_mbox_get_msg_len(version, &mbox_header);
	recv_msg->msg_id = msg_id;
	recv_msg->seq_id = MGMT_MSG_MAX_SEQ_ID;

	if (HINIC5_MSG_HEADER_GET(mbox_header, DIRECTION) ==
	    HINIC5_MSG_RESPONSE) {
		mgmt_resp_msg_handler(pf_to_mgmt, recv_msg);
		return;
	}

	init_mgmt_msg_work(pf_to_mgmt, recv_msg);
}

/**
 * hinic5_mgmt_msg_aeqe_handler - handler for a mgmt message event
 * @handle: PF to MGMT channel
 * @header: the header of the message
 * @size: unused
 **/
void hinic5_mgmt_msg_aeqe_handler(void *hwdev, u8 *header, u8 size)
{
	struct hinic5_hwdev *dev = (struct hinic5_hwdev *)hwdev;
	struct hinic5_msg_pf_to_mgmt *pf_to_mgmt = NULL;
	struct hinic5_recv_msg *recv_msg = NULL;
	bool is_send_dir = false;

	if ((HINIC5_MSG_HEADER_GET(*(u64 *)header, SOURCE) ==
	     HINIC5_MSG_FROM_MBOX)) {
		hinic5_mbox_func_aeqe_handler(hwdev, header, size);
		return;
	}

	pf_to_mgmt = dev->pf_to_mgmt;
	if (!pf_to_mgmt)
		return;

	is_send_dir = (HINIC5_MSG_HEADER_GET(*(u64 *)header, DIRECTION) ==
		       HINIC5_MSG_DIRECT_SEND) ? true : false;

	recv_msg = is_send_dir ? &pf_to_mgmt->recv_msg_from_mgmt :
		   &pf_to_mgmt->recv_resp_msg_from_mgmt;

	recv_mgmt_msg_handler(pf_to_mgmt, header, recv_msg);
}

/**
 * alloc_recv_msg - allocate received message memory
 * @recv_msg: pointer that will hold the allocated data
 * Return: 0 - success, negative - failure
 **/
static int alloc_recv_msg(struct hinic5_recv_msg *recv_msg)
{
	recv_msg->seq_id = MGMT_MSG_MAX_SEQ_ID;

	recv_msg->msg = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!recv_msg->msg)
		return -ENOMEM;

	return 0;
}

/**
 * free_recv_msg - free received message memory
 * @recv_msg: pointer that holds the allocated data
 **/
static void free_recv_msg(struct hinic5_recv_msg *recv_msg)
{
	kfree(recv_msg->msg);
}

/**
 * alloc_msg_buf - allocate all the message buffers of PF to MGMT channel
 * @pf_to_mgmt: PF to MGMT channel
 * Return: 0 - success, negative - failure
 **/
static int alloc_msg_buf(struct hinic5_msg_pf_to_mgmt *pf_to_mgmt)
{
	int err;
	void *dev = pf_to_mgmt->hwdev->dev_hdl;

	err = alloc_recv_msg(&pf_to_mgmt->recv_msg_from_mgmt);
	if (err != 0) {
		sdk_err(dev, "Failed to allocate recv msg\n");
		return err;
	}

	err = alloc_recv_msg(&pf_to_mgmt->recv_resp_msg_from_mgmt);
	if (err != 0) {
		sdk_err(dev, "Failed to allocate resp recv msg\n");
		goto alloc_msg_for_resp_err;
	}

	pf_to_mgmt->async_msg_buf = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!pf_to_mgmt->async_msg_buf) {
		err = -ENOMEM;
		goto async_msg_buf_err;
	}

	pf_to_mgmt->sync_msg_buf = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!pf_to_mgmt->sync_msg_buf) {
		err = -ENOMEM;
		goto sync_msg_buf_err;
	}

	pf_to_mgmt->mgmt_ack_buf = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!pf_to_mgmt->mgmt_ack_buf) {
		err = -ENOMEM;
		goto ack_msg_buf_err;
	}

	return 0;

ack_msg_buf_err:
	kfree(pf_to_mgmt->sync_msg_buf);

sync_msg_buf_err:
	kfree(pf_to_mgmt->async_msg_buf);

async_msg_buf_err:
	free_recv_msg(&pf_to_mgmt->recv_resp_msg_from_mgmt);

alloc_msg_for_resp_err:
	free_recv_msg(&pf_to_mgmt->recv_msg_from_mgmt);
	return err;
}

/**
 * free_msg_buf - free all the message buffers of PF to MGMT channel
 * @pf_to_mgmt: PF to MGMT channel
 * Return: 0 - success, negative - failure
 **/
static void free_msg_buf(struct hinic5_msg_pf_to_mgmt *pf_to_mgmt)
{
	kfree(pf_to_mgmt->mgmt_ack_buf);
	kfree(pf_to_mgmt->sync_msg_buf);
	kfree(pf_to_mgmt->async_msg_buf);

	free_recv_msg(&pf_to_mgmt->recv_resp_msg_from_mgmt);
	free_recv_msg(&pf_to_mgmt->recv_msg_from_mgmt);
}

/**
 * hinic_pf_to_mgmt_init - initialize PF to MGMT channel
 * @hwdev: the pointer to hw device
 * Return: 0 - success, negative - failure
 **/
int hinic5_pf_to_mgmt_init(struct hinic5_hwdev *hwdev)
{
	struct hinic5_msg_pf_to_mgmt *pf_to_mgmt = NULL;
	void *dev = hwdev->dev_hdl;
	int err;

	pf_to_mgmt = kzalloc(sizeof(*pf_to_mgmt), GFP_KERNEL);
	if (!pf_to_mgmt)
		return -ENOMEM;

	hwdev->pf_to_mgmt = pf_to_mgmt;
	pf_to_mgmt->hwdev = hwdev;
	spin_lock_init(&pf_to_mgmt->async_msg_lock);
	spin_lock_init(&pf_to_mgmt->sync_event_lock);
	sema_init(&pf_to_mgmt->sync_msg_lock, 1);
	pf_to_mgmt->workq = create_singlethread_workqueue(HINIC5_MGMT_WQ_NAME);
	if (!pf_to_mgmt->workq) {
		sdk_err(dev, "Failed to initialize MGMT workqueue\n");
		err = -ENOMEM;
		goto create_mgmt_workq_err;
	}

	err = alloc_msg_buf(pf_to_mgmt);
	if (err != 0) {
		sdk_err(dev, "Failed to allocate msg buffers\n");
		goto alloc_msg_buf_err;
	}

	err = hinic5_api_cmd_init(hwdev, pf_to_mgmt->cmd_chain);
	if (err != 0) {
		sdk_err(dev, "Failed to init the api cmd chains\n");
		goto api_cmd_init_err;
	}

	return 0;

api_cmd_init_err:
	free_msg_buf(pf_to_mgmt);

alloc_msg_buf_err:
	destroy_workqueue(pf_to_mgmt->workq);

create_mgmt_workq_err:
	spin_lock_deinit(&pf_to_mgmt->sync_event_lock);
	spin_lock_deinit(&pf_to_mgmt->async_msg_lock);
	sema_deinit(&pf_to_mgmt->sync_msg_lock);
	kfree(pf_to_mgmt);

	return err;
}

/**
 * hinic_pf_to_mgmt_free - free PF to MGMT channel
 * @hwdev: the pointer to hw device
 **/
void hinic5_pf_to_mgmt_free(struct hinic5_hwdev *hwdev)
{
	struct hinic5_msg_pf_to_mgmt *pf_to_mgmt = hwdev->pf_to_mgmt;

	/* destroy workqueue before free related pf_to_mgmt resources in case of
	 * illegal resource access
	 */
	destroy_workqueue(pf_to_mgmt->workq);
	hinic5_api_cmd_free(hwdev, pf_to_mgmt->cmd_chain);

	free_msg_buf(pf_to_mgmt);
	spin_lock_deinit(&pf_to_mgmt->sync_event_lock);
	spin_lock_deinit(&pf_to_mgmt->async_msg_lock);
	sema_deinit(&pf_to_mgmt->sync_msg_lock);
	kfree(pf_to_mgmt);
}

void hinic5_flush_mgmt_workq(void *hwdev)
{
	struct hinic5_hwdev *dev = (struct hinic5_hwdev *)hwdev;

	flush_workqueue(dev->aeqs->workq);

	if (hinic5_func_type(dev) != TYPE_VF)
		flush_workqueue(dev->pf_to_mgmt->workq);
}

int hinic5_api_cmd_read_ack(void *hwdev, u8 dest, const void *cmd,
			    u16 size, void *ack, u16 ack_size)
{
	struct hinic5_msg_pf_to_mgmt *pf_to_mgmt = NULL;
	struct hinic5_api_cmd_chain *chain = NULL;

	if (!hwdev || !cmd || (ack_size != 0 && !ack) || size > MAX_PF_MGMT_BUF_SIZE)
		return -EINVAL;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	pf_to_mgmt = ((struct hinic5_hwdev *)hwdev)->pf_to_mgmt;
	if (!pf_to_mgmt)
		return -EINVAL;

	chain = pf_to_mgmt->cmd_chain[HINIC5_API_CMD_POLL_READ];

	if (!hinic5_is_chip_present(hwdev))
		return -EPERM;

	return hinic5_api_cmd_read(chain, dest, cmd, size, ack, ack_size);
}

/**
 * api cmd write or read bypass default use poll, if want to use aeq interrupt,
 * please set wb_trigger_aeqe to 1
 **/
int hinic5_api_cmd_write_nack(void *hwdev, u8 dest, const void *cmd, u16 size)
{
	struct hinic5_msg_pf_to_mgmt *pf_to_mgmt = NULL;
	struct hinic5_api_cmd_chain *chain = NULL;

	if (!hwdev || size == 0 || !cmd || size > MAX_PF_MGMT_BUF_SIZE)
		return -EINVAL;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	pf_to_mgmt = ((struct hinic5_hwdev *)hwdev)->pf_to_mgmt;
	chain = pf_to_mgmt->cmd_chain[HINIC5_API_CMD_POLL_WRITE];

	if (!hinic5_is_chip_present(hwdev))
		return -EPERM;

	return hinic5_api_cmd_write(chain, dest, cmd, size);
}

static int get_clp_reg(void *hwdev, enum clp_data_type data_type,
		       enum clp_reg_type reg_type, u32 *reg_addr)
{
	switch (reg_type) {
	case HINIC5_CLP_BA_HOST:
		*reg_addr = (data_type == HINIC5_CLP_REQ_HOST) ?
			     HINIC5_CLP_REG(REQBASE) :
			     HINIC5_CLP_REG(RSPBASE);
		break;

	case HINIC5_CLP_SIZE_HOST:
		*reg_addr = HINIC5_CLP_REG(SIZE);
		break;

	case HINIC5_CLP_LEN_HOST:
		*reg_addr = (data_type == HINIC5_CLP_REQ_HOST) ?
			     HINIC5_CLP_REG(REQ) : HINIC5_CLP_REG(RSP);
		break;

	case HINIC5_CLP_START_REQ_HOST:
		*reg_addr = HINIC5_CLP_REG(REQ);
		break;

	case HINIC5_CLP_READY_RSP_HOST:
		*reg_addr = HINIC5_CLP_REG(RSP);
		break;

	default:
		*reg_addr = 0;
		break;
	}
	if (*reg_addr == 0)
		return -EINVAL;

	return 0;
}

static inline int clp_param_valid(struct hinic5_hwdev *hwdev,
				  enum clp_data_type data_type,
				  enum clp_reg_type reg_type)
{
	if (data_type == HINIC5_CLP_REQ_HOST &&
	    reg_type == HINIC5_CLP_READY_RSP_HOST)
		return -EINVAL;

	if (data_type == HINIC5_CLP_RSP_HOST &&
	    reg_type == HINIC5_CLP_START_REQ_HOST)
		return -EINVAL;

	return 0;
}

static u32 get_clp_reg_value(struct hinic5_hwdev *hwdev,
			     enum clp_data_type data_type,
			     enum clp_reg_type reg_type, u32 reg_addr)
{
	u32 value;

	value = hinic5_hwif_read_reg(hwdev->hwif, reg_addr);

	switch (reg_type) {
	case HINIC5_CLP_BA_HOST:
		value = ((value >> HINIC5_CLP_OFFSET(BASE)) &
			HINIC5_CLP_MASK(BASE));
		break;

	case HINIC5_CLP_SIZE_HOST:
		if (data_type == HINIC5_CLP_REQ_HOST)
			value = ((value >> HINIC5_CLP_OFFSET(REQ_SIZE)) &
				HINIC5_CLP_MASK(SIZE));
		else
			value = ((value >> HINIC5_CLP_OFFSET(RSP_SIZE)) &
				HINIC5_CLP_MASK(SIZE));
		break;

	case HINIC5_CLP_LEN_HOST:
		value = ((value >> HINIC5_CLP_OFFSET(LEN)) &
			HINIC5_CLP_MASK(LEN));
		break;

	case HINIC5_CLP_START_REQ_HOST:
		value = ((value >> HINIC5_CLP_OFFSET(START)) &
			HINIC5_CLP_MASK(START));
		break;

	case HINIC5_CLP_READY_RSP_HOST:
		value = ((value >> HINIC5_CLP_OFFSET(READY)) &
			HINIC5_CLP_MASK(READY));
		break;

	default:
		break;
	}

	return value;
}

static int hinic5_read_clp_reg(struct hinic5_hwdev *hwdev,
			       enum clp_data_type data_type,
			       enum clp_reg_type reg_type, u32 *read_value)
{
	u32 reg_addr;
	int err;

	err = clp_param_valid(hwdev, data_type, reg_type);
	if (err != 0)
		return err;

	err = get_clp_reg(hwdev, data_type, reg_type, &reg_addr);
	if (err != 0)
		return err;

	*read_value = get_clp_reg_value(hwdev, data_type, reg_type, reg_addr);

	return 0;
}

static int check_data_type(enum clp_data_type data_type,
			   enum clp_reg_type reg_type)
{
	if (data_type == HINIC5_CLP_REQ_HOST &&
	    reg_type == HINIC5_CLP_READY_RSP_HOST)
		return -EINVAL;
	if (data_type == HINIC5_CLP_RSP_HOST &&
	    reg_type == HINIC5_CLP_START_REQ_HOST)
		return -EINVAL;

	return 0;
}

static int check_reg_value(enum clp_reg_type reg_type, u32 value)
{
	if (reg_type == HINIC5_CLP_BA_HOST &&
	    value > HINIC5_CLP_SRAM_BASE_REG_MAX)
		return -EINVAL;

	if (reg_type == HINIC5_CLP_SIZE_HOST &&
	    value > HINIC5_CLP_SRAM_SIZE_REG_MAX)
		return -EINVAL;

	if (reg_type == HINIC5_CLP_LEN_HOST &&
	    value > HINIC5_CLP_LEN_REG_MAX)
		return -EINVAL;

	if ((reg_type == HINIC5_CLP_START_REQ_HOST ||
	     reg_type == HINIC5_CLP_READY_RSP_HOST) &&
	    value > HINIC5_CLP_START_OR_READY_REG_MAX)
		return -EINVAL;

	return 0;
}

static int hinic5_check_clp_init_status(struct hinic5_hwdev *hwdev)
{
	int err;
	u32 reg_value = 0;

	err = hinic5_read_clp_reg(hwdev, HINIC5_CLP_REQ_HOST,
				  HINIC5_CLP_BA_HOST, &reg_value);
	if (err != 0 || reg_value == 0) {
		sdk_err(hwdev->dev_hdl, "Wrong req ba value: 0x%x\n",
			reg_value);
		return -EINVAL;
	}

	err = hinic5_read_clp_reg(hwdev, HINIC5_CLP_RSP_HOST,
				  HINIC5_CLP_BA_HOST, &reg_value);
	if (err != 0 || reg_value == 0) {
		sdk_err(hwdev->dev_hdl, "Wrong rsp ba value: 0x%x\n",
			reg_value);
		return -EINVAL;
	}

	err = hinic5_read_clp_reg(hwdev, HINIC5_CLP_REQ_HOST,
				  HINIC5_CLP_SIZE_HOST, &reg_value);
	if (err != 0 || reg_value == 0) {
		sdk_err(hwdev->dev_hdl, "Wrong req size\n");
		return -EINVAL;
	}

	err = hinic5_read_clp_reg(hwdev, HINIC5_CLP_RSP_HOST,
				  HINIC5_CLP_SIZE_HOST, &reg_value);
	if (err != 0 || reg_value == 0) {
		sdk_err(hwdev->dev_hdl, "Wrong rsp size\n");
		return -EINVAL;
	}

	return 0;
}

static void hinic5_write_clp_reg(struct hinic5_hwdev *hwdev,
				 enum clp_data_type data_type,
				 enum clp_reg_type reg_type, u32 value)
{
	u32 reg_addr, reg_value;

	if (check_data_type(data_type, reg_type) != 0)
		return;

	if (check_reg_value(reg_type, value) != 0)
		return;

	if (get_clp_reg(hwdev, data_type, reg_type, &reg_addr) != 0)
		return;

	reg_value = hinic5_hwif_read_reg(hwdev->hwif, reg_addr);

	switch (reg_type) {
	case HINIC5_CLP_LEN_HOST:
		reg_value = reg_value &
			    (~(HINIC5_CLP_MASK(LEN) << HINIC5_CLP_OFFSET(LEN)));
		reg_value = reg_value | (value << HINIC5_CLP_OFFSET(LEN));
		break;

	case HINIC5_CLP_START_REQ_HOST:
		reg_value = reg_value &
			    (~(HINIC5_CLP_MASK(START) <<
			      HINIC5_CLP_OFFSET(START)));
		reg_value = reg_value | (value << HINIC5_CLP_OFFSET(START));
		break;

	case HINIC5_CLP_READY_RSP_HOST:
		reg_value = reg_value &
			    (~(HINIC5_CLP_MASK(READY) <<
			    HINIC5_CLP_OFFSET(READY)));
		reg_value = reg_value | (value << HINIC5_CLP_OFFSET(READY));
		break;

	default:
		return;
	}

	hinic5_hwif_write_reg(hwdev->hwif, reg_addr, reg_value);
}

static int hinic5_read_clp_data(struct hinic5_hwdev *hwdev,
				void *buf_out, u16 *out_size)
{
	int err;
	u32 reg = HINIC5_CLP_DATA(RSP);
	u32 ready, delay_cnt;
	u32 *ptr = (u32 *)buf_out;
	u32 temp_out_size = 0;

	err = hinic5_read_clp_reg(hwdev, HINIC5_CLP_RSP_HOST,
				  HINIC5_CLP_READY_RSP_HOST, &ready);
	if (err != 0)
		return err;

	delay_cnt = 0;
	while (ready == 0) {
		usleep_range(9000, 10000); /* sleep 9000 us ~ 10000 us */
		delay_cnt++;
		err = hinic5_read_clp_reg(hwdev, HINIC5_CLP_RSP_HOST,
					  HINIC5_CLP_READY_RSP_HOST, &ready);
		if (err != 0 || delay_cnt > HINIC5_CLP_DELAY_CNT_MAX) {
			sdk_err(hwdev->dev_hdl, "Timeout with delay_cnt: %u\n",
				delay_cnt);
			return -EINVAL;
		}
	}

	err = hinic5_read_clp_reg(hwdev, HINIC5_CLP_RSP_HOST,
				  HINIC5_CLP_LEN_HOST, &temp_out_size);
	if (err != 0)
		return err;

	if (temp_out_size > HINIC5_CLP_SRAM_SIZE_REG_MAX || temp_out_size == 0) {
		sdk_err(hwdev->dev_hdl, "Invalid temp_out_size: %u\n",
			temp_out_size);
		return -EINVAL;
	}

	*out_size = (u16)temp_out_size;
	for (; temp_out_size > 0; temp_out_size--) {
		*ptr = hinic5_hwif_read_reg(hwdev->hwif, reg);
		ptr++;
		/* read 4 bytes every time */
		reg = reg + 4;
	}

	hinic5_write_clp_reg(hwdev, HINIC5_CLP_RSP_HOST,
			     HINIC5_CLP_READY_RSP_HOST, (u32)0x0);
	hinic5_write_clp_reg(hwdev, HINIC5_CLP_RSP_HOST, HINIC5_CLP_LEN_HOST,
			     (u32)0x0);

	return 0;
}

static int hinic5_write_clp_data(struct hinic5_hwdev *hwdev,
				 void *buf_in, u16 in_size)
{
	int err;
	u32 reg = HINIC5_CLP_DATA(REQ);
	u32 start = 1;
	u32 delay_cnt = 0;
	u32 *ptr = (u32 *)buf_in;
	u16 size_in = in_size;

	err = hinic5_read_clp_reg(hwdev, HINIC5_CLP_REQ_HOST,
				  HINIC5_CLP_START_REQ_HOST, &start);
	if (err != 0)
		return err;

	while (start == 1) {
		usleep_range(9000, 10000); /* sleep 9000 us ~ 10000 us */
		delay_cnt++;
		err = hinic5_read_clp_reg(hwdev, HINIC5_CLP_REQ_HOST,
					  HINIC5_CLP_START_REQ_HOST, &start);
		if (err != 0 || delay_cnt > HINIC5_CLP_DELAY_CNT_MAX)
			return -EINVAL;
	}

	hinic5_write_clp_reg(hwdev, HINIC5_CLP_REQ_HOST,
			     HINIC5_CLP_LEN_HOST, size_in);
	hinic5_write_clp_reg(hwdev, HINIC5_CLP_REQ_HOST,
			     HINIC5_CLP_START_REQ_HOST, (u32)0x1);

	for (; size_in > 0; size_in--) {
		hinic5_hwif_write_reg(hwdev->hwif, reg, *ptr);
		ptr++;
		reg = reg + sizeof(u32);
	}

	return 0;
}

static void hinic5_clear_clp_data(struct hinic5_hwdev *hwdev,
				  enum clp_data_type data_type)
{
	u32 reg = (data_type == HINIC5_CLP_REQ_HOST) ?
		   HINIC5_CLP_DATA(REQ) : HINIC5_CLP_DATA(RSP);
	u32 count = HINIC5_CLP_INPUT_BUF_LEN_HOST / HINIC5_CLP_DATA_UNIT_HOST;

	for (; count > 0; count--) {
		hinic5_hwif_write_reg(hwdev->hwif, reg, 0x0);
		reg = reg + sizeof(u32);
	}
}

static int clp_to_mgmt_response(void *hwdev, void *buf_out, const u16 *out_size)
{
	struct hinic5_hwdev *dev = hwdev;
	u8 *clp_msg_buf = NULL;
	u64 header;
	u16 real_size = 0;
	int ret;

	clp_msg_buf = ((struct hinic5_hwdev *)hwdev)->clp_pf_to_mgmt->clp_msg_buf;

	memset(clp_msg_buf, 0x0, HINIC5_CLP_INPUT_BUF_LEN_HOST);
	ret = hinic5_read_clp_data(hwdev, clp_msg_buf, &real_size);
	hinic5_clear_clp_data(dev, HINIC5_CLP_RSP_HOST);
	if (ret != 0) {
		sdk_err(dev->dev_hdl, "Read clp response failed\n");
		return -EINVAL;
	}

	real_size = (u16)((real_size * HINIC5_CLP_DATA_UNIT_HOST) & 0xffff);
	if (real_size <= sizeof(header) || real_size > HINIC5_CLP_INPUT_BUF_LEN_HOST) {
		sdk_err(dev->dev_hdl, "Invalid response size: %u", real_size);
		return -EINVAL;
	}
	real_size = real_size - sizeof(header);
	if (real_size != *out_size) {
		sdk_err(dev->dev_hdl, "Invalid real_size:%u, out_size: %u\n", real_size, *out_size);
		return -EINVAL;
	}

	memcpy(buf_out, (clp_msg_buf + sizeof(header)), real_size);
	return 0;
}

int hinic5_pf_clp_to_mgmt(void *hwdev, u8 mod, u16 cmd, const void *buf_in,
			  u16 in_size, void *buf_out, const u16 *out_size)
{
	struct hinic5_clp_pf_to_mgmt *clp_pf_to_mgmt = NULL;
	struct hinic5_hwdev *dev = hwdev;
	u8 *clp_msg_buf = NULL;
	u64 header = 0;
	u16 real_size;
	int err;

	if (!COMM_SUPPORT_CLP(dev))
		return -EPERM;

	clp_pf_to_mgmt = ((struct hinic5_hwdev *)hwdev)->clp_pf_to_mgmt;
	if (!clp_pf_to_mgmt)
		return -EPERM;

	clp_msg_buf = clp_pf_to_mgmt->clp_msg_buf;

	/* 4 bytes alignment */
	real_size = in_size + (u16)sizeof(header) +
		(((in_size % HINIC5_CLP_DATA_UNIT_HOST) != 0) ? HINIC5_CLP_DATA_UNIT_HOST : 0);
	real_size = real_size / HINIC5_CLP_DATA_UNIT_HOST;

	if (real_size > (HINIC5_CLP_INPUT_BUF_LEN_HOST / HINIC5_CLP_DATA_UNIT_HOST)) {
		sdk_err(dev->dev_hdl, "Invalid real_size: %u\n", real_size);
		return -EINVAL;
	}
	down(&clp_pf_to_mgmt->clp_msg_lock);

	err = hinic5_check_clp_init_status(dev);
	if (err != 0) {
		sdk_err(dev->dev_hdl, "Check clp init status failed\n");
		goto unlock_clp_msg;
	}

	hinic5_clear_clp_data(dev, HINIC5_CLP_RSP_HOST);
	hinic5_write_clp_reg(dev, HINIC5_CLP_RSP_HOST, HINIC5_CLP_READY_RSP_HOST, 0x0);

	/* Send request */
	memset(clp_msg_buf, 0x0, HINIC5_CLP_INPUT_BUF_LEN_HOST);
	clp_prepare_header(dev, &header, in_size, mod, cmd);

	memcpy(clp_msg_buf, &header, sizeof(header));

	clp_msg_buf += sizeof(header);
	memcpy(clp_msg_buf, buf_in, in_size);

	hinic5_clear_clp_data(dev, HINIC5_CLP_REQ_HOST);
	if (hinic5_write_clp_data(hwdev, clp_pf_to_mgmt->clp_msg_buf, real_size) != 0) {
		sdk_err(dev->dev_hdl, "Send clp request failed\n");
		err = -EINVAL;
		goto unlock_clp_msg;
	}

	/* Get response */
	err = clp_to_mgmt_response(hwdev, buf_out, out_size);

unlock_clp_msg:
	up(&clp_pf_to_mgmt->clp_msg_lock);
	return err;
}

int hinic5_clp_to_mgmt(void *hwdev, u8 mod, u16 cmd, const void *buf_in,
		       u16 in_size, void *buf_out, u16 *out_size)

{
	struct hinic5_hwdev *dev = hwdev;
	int err;

	if (!dev)
		return -EINVAL;

	if (!hinic5_is_chip_present(hwdev))
		return -EPERM;

	if (hinic5_func_type(hwdev) == TYPE_VF)
		return -EINVAL;

	if (!COMM_SUPPORT_CLP(dev))
		return -EPERM;

	err = hinic5_pf_clp_to_mgmt(dev, mod, cmd, buf_in, in_size, buf_out,
				    out_size);

	return err;
}

int hinic5_clp_pf_to_mgmt_init(struct hinic5_hwdev *hwdev)
{
	struct hinic5_clp_pf_to_mgmt *clp_pf_to_mgmt = NULL;

	if (!COMM_SUPPORT_CLP(hwdev))
		return 0;

	clp_pf_to_mgmt = kzalloc(sizeof(*clp_pf_to_mgmt), GFP_KERNEL);
	if (!clp_pf_to_mgmt)
		return -ENOMEM;

	clp_pf_to_mgmt->clp_msg_buf = kzalloc(HINIC5_CLP_INPUT_BUF_LEN_HOST,
					      GFP_KERNEL);
	if (!clp_pf_to_mgmt->clp_msg_buf) {
		kfree(clp_pf_to_mgmt);
		return -ENOMEM;
	}
	sema_init(&clp_pf_to_mgmt->clp_msg_lock, 1);

	hwdev->clp_pf_to_mgmt = clp_pf_to_mgmt;

	return 0;
}

void hinic5_clp_pf_to_mgmt_free(struct hinic5_hwdev *hwdev)
{
	struct hinic5_clp_pf_to_mgmt *clp_pf_to_mgmt = hwdev->clp_pf_to_mgmt;

	if (!COMM_SUPPORT_CLP(hwdev))
		return;

	sema_deinit(&clp_pf_to_mgmt->clp_msg_lock);
	kfree(clp_pf_to_mgmt->clp_msg_buf);
	kfree(clp_pf_to_mgmt);
}
