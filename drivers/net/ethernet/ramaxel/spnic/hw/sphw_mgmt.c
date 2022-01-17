// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/semaphore.h>
#include <linux/delay.h>

#include "sphw_crm.h"
#include "sphw_hw.h"
#include "sphw_common.h"
#include "sphw_comm_cmd.h"
#include "sphw_hwdev.h"
#include "sphw_eqs.h"
#include "sphw_mbox.h"
#include "sphw_api_cmd.h"
#include "sphw_prof_adap.h"
#include "sphw_mgmt.h"
#include "sphw_csr.h"

#define SPHW_MSG_TO_MGMT_MAX_LEN	2016

#define SPHW_API_CHAIN_AEQ_ID		2
#define MAX_PF_MGMT_BUF_SIZE		2048UL
#define SEGMENT_LEN			48
#define ASYNC_MSG_FLAG			0x8
#define MGMT_MSG_MAX_SEQ_ID	(ALIGN(SPHW_MSG_TO_MGMT_MAX_LEN, \
				       SEGMENT_LEN) / SEGMENT_LEN)

#define BUF_OUT_DEFAULT_SIZE		1

#define MGMT_MSG_SIZE_MIN		20
#define MGMT_MSG_SIZE_STEP		16
#define	MGMT_MSG_RSVD_FOR_DEV		8

#define SYNC_MSG_ID_MASK		0x7
#define ASYNC_MSG_ID_MASK		0x7

#define SYNC_FLAG			0
#define ASYNC_FLAG			1

#define MSG_NO_RESP			0xFFFF

#define MGMT_MSG_TIMEOUT		300000	/* millisecond */

#define SYNC_MSG_ID(pf_to_mgmt)	((pf_to_mgmt)->sync_msg_id)

#define SYNC_MSG_ID_INC(pf_to_mgmt)	(SYNC_MSG_ID(pf_to_mgmt) = \
			(SYNC_MSG_ID(pf_to_mgmt) + 1) & SYNC_MSG_ID_MASK)
#define ASYNC_MSG_ID(pf_to_mgmt)	((pf_to_mgmt)->async_msg_id)

#define ASYNC_MSG_ID_INC(pf_to_mgmt)	(ASYNC_MSG_ID(pf_to_mgmt) = \
			((ASYNC_MSG_ID(pf_to_mgmt) + 1) & ASYNC_MSG_ID_MASK) | ASYNC_MSG_FLAG)

static void pf_to_mgmt_send_event_set(struct sphw_msg_pf_to_mgmt *pf_to_mgmt,
				      int event_flag)
{
	spin_lock(&pf_to_mgmt->sync_event_lock);
	pf_to_mgmt->event_flag = event_flag;
	spin_unlock(&pf_to_mgmt->sync_event_lock);
}

/**
 * sphw_register_mgmt_msg_cb - register sync msg handler for a module
 * @hwdev: the pointer to hw device
 * @mod: module in the chip that this handler will handle its sync messages
 * @pri_handle: specific mod's private data that will be used in callback
 * @callback: the handler for a sync message that will handle messages
 **/
int sphw_register_mgmt_msg_cb(void *hwdev, u8 mod, void *pri_handle, sphw_mgmt_msg_cb callback)
{
	struct sphw_msg_pf_to_mgmt *pf_to_mgmt = NULL;

	if (mod >= SPHW_MOD_HW_MAX || !hwdev)
		return -EFAULT;

	pf_to_mgmt = ((struct sphw_hwdev *)hwdev)->pf_to_mgmt;
	if (!pf_to_mgmt)
		return -EINVAL;

	pf_to_mgmt->recv_mgmt_msg_cb[mod] = callback;
	pf_to_mgmt->recv_mgmt_msg_data[mod] = pri_handle;

	set_bit(SPHW_MGMT_MSG_CB_REG, &pf_to_mgmt->mgmt_msg_cb_state[mod]);

	return 0;
}

/**
 * sphw_unregister_mgmt_msg_cb - unregister sync msg handler for a module
 * @hwdev: the pointer to hw device
 * @mod: module in the chip that this handler will handle its sync messages
 **/
void sphw_unregister_mgmt_msg_cb(void *hwdev, u8 mod)
{
	struct sphw_msg_pf_to_mgmt *pf_to_mgmt = NULL;

	if (!hwdev || mod >= SPHW_MOD_HW_MAX)
		return;

	pf_to_mgmt = ((struct sphw_hwdev *)hwdev)->pf_to_mgmt;
	if (!pf_to_mgmt)
		return;

	clear_bit(SPHW_MGMT_MSG_CB_REG, &pf_to_mgmt->mgmt_msg_cb_state[mod]);

	while (test_bit(SPHW_MGMT_MSG_CB_RUNNING, &pf_to_mgmt->mgmt_msg_cb_state[mod]))
		usleep_range(900, 1000);

	pf_to_mgmt->recv_mgmt_msg_cb[mod] = NULL;
	pf_to_mgmt->recv_mgmt_msg_data[mod] = NULL;
}

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
static void prepare_header(struct sphw_msg_pf_to_mgmt *pf_to_mgmt,
			   u64 *header, u16 msg_len, u8 mod,
			   enum sphw_msg_ack_type ack_type,
			   enum sphw_msg_direction_type direction,
			   enum sphw_mgmt_cmd cmd, u32 msg_id)
{
	struct sphw_hwif *hwif = pf_to_mgmt->hwdev->hwif;

	*header = SPHW_MSG_HEADER_SET(msg_len, MSG_LEN) |
		SPHW_MSG_HEADER_SET(mod, MODULE) |
		SPHW_MSG_HEADER_SET(msg_len, SEG_LEN) |
		SPHW_MSG_HEADER_SET(ack_type, NO_ACK) |
		SPHW_MSG_HEADER_SET(SPHW_DATA_INLINE, DATA_TYPE) |
		SPHW_MSG_HEADER_SET(0, SEQID) |
		SPHW_MSG_HEADER_SET(SPHW_API_CHAIN_AEQ_ID, AEQ_ID) |
		SPHW_MSG_HEADER_SET(LAST_SEGMENT, LAST) |
		SPHW_MSG_HEADER_SET(direction, DIRECTION) |
		SPHW_MSG_HEADER_SET(cmd, CMD) |
		SPHW_MSG_HEADER_SET(SPHW_MSG_FROM_MGMT, SOURCE) |
		SPHW_MSG_HEADER_SET(hwif->attr.func_global_idx, SRC_GLB_FUNC_IDX) |
		SPHW_MSG_HEADER_SET(msg_id, MSG_ID);
}

/**
 * prepare_mgmt_cmd - prepare the mgmt command
 * @mgmt_cmd: pointer to the command to prepare
 * @header: pointer of the header to prepare
 * @msg: the data of the message
 * @msg_len: the length of the message
 **/
static void prepare_mgmt_cmd(u8 *mgmt_cmd, u64 *header, const void *msg,
			     int msg_len)
{
	memset(mgmt_cmd, 0, MGMT_MSG_RSVD_FOR_DEV);

	mgmt_cmd += MGMT_MSG_RSVD_FOR_DEV;
	memcpy(mgmt_cmd, header, sizeof(*header));

	mgmt_cmd += sizeof(*header);
	memcpy(mgmt_cmd, msg, msg_len);
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
static int send_msg_to_mgmt_sync(struct sphw_msg_pf_to_mgmt *pf_to_mgmt,
				 u8 mod, u16 cmd, const void *msg, u16 msg_len,
				 enum sphw_msg_ack_type ack_type,
				 enum sphw_msg_direction_type direction,
				 u16 resp_msg_id)
{
	void *mgmt_cmd = pf_to_mgmt->sync_msg_buf;
	struct sphw_api_cmd_chain *chain = NULL;
	u8 node_id = SPHW_MGMT_CPU_NODE_ID(pf_to_mgmt->hwdev);
	u64 header;
	u16 cmd_size = mgmt_msg_len(msg_len);

	if (!sphw_get_chip_present_flag(pf_to_mgmt->hwdev))
		return -EFAULT;

	if (direction == SPHW_MSG_RESPONSE)
		prepare_header(pf_to_mgmt, &header, msg_len, mod, ack_type,
			       direction, cmd, resp_msg_id);
	else
		prepare_header(pf_to_mgmt, &header, msg_len, mod, ack_type,
			       direction, cmd, SYNC_MSG_ID_INC(pf_to_mgmt));
	chain = pf_to_mgmt->cmd_chain[SPHW_API_CMD_WRITE_TO_MGMT_CPU];

	if (ack_type == SPHW_MSG_ACK)
		pf_to_mgmt_send_event_set(pf_to_mgmt, SEND_EVENT_START);

	prepare_mgmt_cmd((u8 *)mgmt_cmd, &header, msg, msg_len);

	return sphw_api_cmd_write(chain, node_id, mgmt_cmd, cmd_size);
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
static int send_msg_to_mgmt_async(struct sphw_msg_pf_to_mgmt *pf_to_mgmt,
				  u8 mod, u16 cmd, const void *msg, u16 msg_len,
				  enum sphw_msg_direction_type direction)
{
	void *mgmt_cmd = pf_to_mgmt->async_msg_buf;
	struct sphw_api_cmd_chain *chain = NULL;
	u8 node_id = SPHW_MGMT_CPU_NODE_ID(pf_to_mgmt->hwdev);
	u64 header;
	u16 cmd_size = mgmt_msg_len(msg_len);

	if (!sphw_get_chip_present_flag(pf_to_mgmt->hwdev))
		return -EFAULT;

	prepare_header(pf_to_mgmt, &header, msg_len, mod, SPHW_MSG_NO_ACK,
		       direction, cmd, ASYNC_MSG_ID(pf_to_mgmt));

	prepare_mgmt_cmd((u8 *)mgmt_cmd, &header, msg, msg_len);

	chain = pf_to_mgmt->cmd_chain[SPHW_API_CMD_WRITE_ASYNC_TO_MGMT_CPU];

	return sphw_api_cmd_write(chain, node_id, mgmt_cmd, cmd_size);
}

static inline void msg_to_mgmt_pre(u8 mod, void *buf_in)
{
	struct sphw_msg_head *msg_head = NULL;

	/* set aeq fix num to 3, need to ensure response aeq id < 3*/
	if (mod == SPHW_MOD_COMM || mod == SPHW_MOD_L2NIC) {
		msg_head = buf_in;

		if (msg_head->resp_aeq_num >= SPHW_MAX_AEQS)
			msg_head->resp_aeq_num = 0;
	}
}

int sphw_pf_to_mgmt_sync(void *hwdev, u8 mod, u16 cmd, void *buf_in,
			 u16 in_size, void *buf_out, u16 *out_size, u32 timeout)
{
	struct sphw_msg_pf_to_mgmt *pf_to_mgmt = NULL;
	void *dev = ((struct sphw_hwdev *)hwdev)->dev_hdl;
	struct sphw_recv_msg *recv_msg = NULL;
	struct completion *recv_done = NULL;
	ulong timeo;
	int err;
	ulong ret;

	msg_to_mgmt_pre(mod, buf_in);

	pf_to_mgmt = ((struct sphw_hwdev *)hwdev)->pf_to_mgmt;

	/* Lock the sync_msg_buf */
	down(&pf_to_mgmt->sync_msg_lock);
	recv_msg = &pf_to_mgmt->recv_resp_msg_from_mgmt;
	recv_done = &recv_msg->recv_done;

	init_completion(recv_done);

	err = send_msg_to_mgmt_sync(pf_to_mgmt, mod, cmd, buf_in, in_size,
				    SPHW_MSG_ACK, SPHW_MSG_DIRECT_SEND,
				    MSG_NO_RESP);
	if (err) {
		sdk_err(dev, "Failed to send sync msg to mgmt, sync_msg_id: %u\n",
			pf_to_mgmt->sync_msg_id);
		pf_to_mgmt_send_event_set(pf_to_mgmt, SEND_EVENT_FAIL);
		goto unlock_sync_msg;
	}

	timeo = msecs_to_jiffies(timeout ? timeout : MGMT_MSG_TIMEOUT);

	ret = wait_for_completion_timeout(recv_done, timeo);
	if (!ret) {
		sdk_err(dev, "Mgmt response sync cmd timeout, sync_msg_id: %u\n",
			pf_to_mgmt->sync_msg_id);
		sphw_dump_aeq_info((struct sphw_hwdev *)hwdev);
		err = -ETIMEDOUT;
		pf_to_mgmt_send_event_set(pf_to_mgmt, SEND_EVENT_TIMEOUT);
		goto unlock_sync_msg;
	}
	pf_to_mgmt_send_event_set(pf_to_mgmt, SEND_EVENT_END);

	if (!(((struct sphw_hwdev *)hwdev)->chip_present_flag)) {
		up(&pf_to_mgmt->sync_msg_lock);
		return -ETIMEDOUT;
	}

	if (buf_out && out_size) {
		if (*out_size < recv_msg->msg_len) {
			sdk_err(dev, "Invalid response message length: %u for mod %d cmd %u from mgmt, should less than: %u\n",
				recv_msg->msg_len, mod, cmd, *out_size);
			err = -EFAULT;
			goto unlock_sync_msg;
		}

		if (recv_msg->msg_len)
			memcpy(buf_out, recv_msg->msg, recv_msg->msg_len);

		*out_size = recv_msg->msg_len;
	}

unlock_sync_msg:
	up(&pf_to_mgmt->sync_msg_lock);

	return err;
}

int sphw_pf_to_mgmt_async(void *hwdev, u8 mod, u16 cmd, const void *buf_in, u16 in_size)
{
	struct sphw_msg_pf_to_mgmt *pf_to_mgmt;
	void *dev = ((struct sphw_hwdev *)hwdev)->dev_hdl;
	int err;

	pf_to_mgmt = ((struct sphw_hwdev *)hwdev)->pf_to_mgmt;

	/* Lock the async_msg_buf */
	spin_lock_bh(&pf_to_mgmt->async_msg_lock);
	ASYNC_MSG_ID_INC(pf_to_mgmt);

	err = send_msg_to_mgmt_async(pf_to_mgmt, mod, cmd, buf_in, in_size,
				     SPHW_MSG_DIRECT_SEND);
	spin_unlock_bh(&pf_to_mgmt->async_msg_lock);

	if (err) {
		sdk_err(dev, "Failed to send async mgmt msg\n");
		return err;
	}

	return 0;
}

int sphw_pf_msg_to_mgmt_sync(void *hwdev, u8 mod, u16 cmd, void *buf_in,
			     u16 in_size, void *buf_out, u16 *out_size, u32 timeout)
{
	if (!hwdev)
		return -EINVAL;

	if (!sphw_get_chip_present_flag(hwdev))
		return -EPERM;

	if (in_size > SPHW_MSG_TO_MGMT_MAX_LEN)
		return -EINVAL;

	return sphw_pf_to_mgmt_sync(hwdev, mod, cmd, buf_in, in_size, buf_out, out_size, timeout);
}

int sphw_msg_to_mgmt_sync(void *hwdev, u8 mod, u16 cmd, void *buf_in, u16 in_size, void *buf_out,
			  u16 *out_size, u32 timeout, u16 channel)
{
	if (!hwdev)
		return -EINVAL;

	if (!sphw_get_chip_present_flag(hwdev))
		return -EPERM;

	return sphw_send_mbox_to_mgmt(hwdev, mod, cmd, buf_in, in_size,
					buf_out, out_size, timeout, channel);
}

int sphw_msg_to_mgmt_no_ack(void *hwdev, u8 mod, u16 cmd, void *buf_in, u16 in_size, u16 channel)
{
	if (!hwdev)
		return -EINVAL;

	if (!sphw_get_chip_present_flag(hwdev))
		return -EPERM;

	return sphw_send_mbox_to_mgmt_no_ack(hwdev, mod, cmd, buf_in, in_size, channel);
}

int sphw_msg_to_mgmt_async(void *hwdev, u8 mod, u16 cmd, void *buf_in, u16 in_size, u16 channel)
{
	return sphw_msg_to_mgmt_api_chain_async(hwdev, mod, cmd, buf_in, in_size);
}

int sphw_msg_to_mgmt_api_chain_sync(void *hwdev, u8 mod, u16 cmd, void *buf_in, u16 in_size,
				    void *buf_out, u16 *out_size, u32 timeout)
{
	if (!hwdev)
		return -EINVAL;

	if (!sphw_get_chip_present_flag(hwdev))
		return -EPERM;

	return sphw_pf_msg_to_mgmt_sync(hwdev, mod, cmd, buf_in, in_size,
					buf_out, out_size, timeout);
}

int sphw_msg_to_mgmt_api_chain_async(void *hwdev, u8 mod, u16 cmd, const void *buf_in, u16 in_size)
{
	int err;

	if (!hwdev)
		return -EINVAL;

	if (sphw_func_type(hwdev) == TYPE_VF) {
		err = -EFAULT;
		sdk_err(((struct sphw_hwdev *)hwdev)->dev_hdl,
			"VF don't support async cmd\n");
	} else {
		err = sphw_pf_to_mgmt_async(hwdev, mod, cmd, buf_in, in_size);
	}

	return err;
}

static void send_mgmt_ack(struct sphw_msg_pf_to_mgmt *pf_to_mgmt,
			  u8 mod, u16 cmd, void *buf_in, u16 in_size,
			  u16 msg_id)
{
	u16 buf_size;

	if (!in_size)
		buf_size = BUF_OUT_DEFAULT_SIZE;
	else
		buf_size = in_size;

	sphw_response_mbox_to_mgmt(pf_to_mgmt->hwdev, mod, cmd, buf_in, buf_size, msg_id);
}

static void mgmt_recv_msg_handler(struct sphw_msg_pf_to_mgmt *pf_to_mgmt,
				  u8 mod, u16 cmd, void *buf_in, u16 in_size,
				  u16 msg_id, int need_resp)
{
	void *dev = pf_to_mgmt->hwdev->dev_hdl;
	void *buf_out = pf_to_mgmt->mgmt_ack_buf;
	enum sphw_mod_type tmp_mod = mod;
	bool ack_first = false;
	u16 out_size = 0;

	memset(buf_out, 0, MAX_PF_MGMT_BUF_SIZE);

	if (mod >= SPHW_MOD_HW_MAX) {
		sdk_warn(dev, "Receive illegal message from mgmt cpu, mod = %d\n",
			 mod);
		goto resp;
	}

	set_bit(SPHW_MGMT_MSG_CB_RUNNING, &pf_to_mgmt->mgmt_msg_cb_state[tmp_mod]);

	if (!pf_to_mgmt->recv_mgmt_msg_cb[mod] ||
	    !test_bit(SPHW_MGMT_MSG_CB_REG,
	    &pf_to_mgmt->mgmt_msg_cb_state[tmp_mod])) {
		sdk_warn(dev, "Receive mgmt callback is null, mod = %d\n",
			 mod);
		clear_bit(SPHW_MGMT_MSG_CB_RUNNING, &pf_to_mgmt->mgmt_msg_cb_state[tmp_mod]);
		goto resp;
	}

	pf_to_mgmt->recv_mgmt_msg_cb[tmp_mod](pf_to_mgmt->hwdev,
					      pf_to_mgmt->recv_mgmt_msg_data[tmp_mod],
					      cmd, buf_in, in_size, buf_out, &out_size);

	clear_bit(SPHW_MGMT_MSG_CB_RUNNING, &pf_to_mgmt->mgmt_msg_cb_state[tmp_mod]);

resp:
	if (!ack_first && need_resp)
		send_mgmt_ack(pf_to_mgmt, mod, cmd, buf_out, out_size, msg_id);
}

/**
 * mgmt_resp_msg_handler - handler for response message from mgmt cpu
 * @pf_to_mgmt: PF to MGMT channel
 * @recv_msg: received message details
 **/
static void mgmt_resp_msg_handler(struct sphw_msg_pf_to_mgmt *pf_to_mgmt,
				  struct sphw_recv_msg *recv_msg)
{
	void *dev = pf_to_mgmt->hwdev->dev_hdl;

	/* delete async msg */
	if (recv_msg->msg_id & ASYNC_MSG_FLAG)
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
	struct sphw_mgmt_msg_handle_work *mgmt_work =
		container_of(work, struct sphw_mgmt_msg_handle_work, work);

	mgmt_recv_msg_handler(mgmt_work->pf_to_mgmt, mgmt_work->mod,
			      mgmt_work->cmd, mgmt_work->msg,
			      mgmt_work->msg_len, mgmt_work->msg_id,
			      !mgmt_work->async_mgmt_to_pf);

	kfree(mgmt_work->msg);
	kfree(mgmt_work);
}

static bool check_mgmt_seq_id_and_seg_len(struct sphw_recv_msg *recv_msg,
					  u8 seq_id, u8 seg_len)
{
	if (seq_id > MGMT_MSG_MAX_SEQ_ID || seg_len > SEGMENT_LEN)
		return false;

	if (seq_id == 0) {
		recv_msg->seq_id = seq_id;
	} else {
		if (seq_id != recv_msg->seq_id + 1)
			return false;

		recv_msg->seq_id = seq_id;
	}

	return true;
}

/**
 * recv_mgmt_msg_handler - handler a message from mgmt cpu
 * @pf_to_mgmt: PF to MGMT channel
 * @header: the header of the message
 * @recv_msg: received message details
 **/
static void recv_mgmt_msg_handler(struct sphw_msg_pf_to_mgmt *pf_to_mgmt,
				  u8 *header, struct sphw_recv_msg *recv_msg)
{
	struct sphw_hwdev *hwdev = pf_to_mgmt->hwdev;
	struct sphw_mgmt_msg_handle_work *mgmt_work = NULL;
	u64 mbox_header = *((u64 *)header);
	void *msg_body = header + sizeof(mbox_header);
	u8 seq_id, seq_len;
	u32 offset;
	u64 dir;

	/* Don't need to get anything from hw when cmd is async */
	dir = SPHW_MSG_HEADER_GET(mbox_header, DIRECTION);
	if (dir == SPHW_MSG_RESPONSE && SPHW_MSG_HEADER_GET(mbox_header, MSG_ID) & ASYNC_MSG_FLAG)
		return;

	seq_len = SPHW_MSG_HEADER_GET(mbox_header, SEG_LEN);
	seq_id  = SPHW_MSG_HEADER_GET(mbox_header, SEQID);

	if (!check_mgmt_seq_id_and_seg_len(recv_msg, seq_id, seq_len)) {
		sdk_err(hwdev->dev_hdl,
			"Mgmt msg sequence id and segment length check fail, front seq_id: 0x%x,current seq_id: 0x%x, seg len: 0x%x\n",
			recv_msg->seq_id, seq_id, seq_len);
		/* set seq_id to invalid seq_id */
		recv_msg->seq_id = MGMT_MSG_MAX_SEQ_ID;
		return;
	}

	offset  = seq_id * SEGMENT_LEN;
	memcpy((u8 *)recv_msg->msg + offset, msg_body, seq_len);

	if (!SPHW_MSG_HEADER_GET(mbox_header, LAST))
		return;

	recv_msg->cmd = SPHW_MSG_HEADER_GET(mbox_header, CMD);
	recv_msg->mod = SPHW_MSG_HEADER_GET(mbox_header, MODULE);
	recv_msg->async_mgmt_to_pf = SPHW_MSG_HEADER_GET(mbox_header, NO_ACK);
	recv_msg->msg_len = SPHW_MSG_HEADER_GET(mbox_header, MSG_LEN);
	recv_msg->msg_id = SPHW_MSG_HEADER_GET(mbox_header, MSG_ID);
	recv_msg->seq_id = MGMT_MSG_MAX_SEQ_ID;

	if (SPHW_MSG_HEADER_GET(mbox_header, DIRECTION) == SPHW_MSG_RESPONSE) {
		mgmt_resp_msg_handler(pf_to_mgmt, recv_msg);
		return;
	}

	mgmt_work = kzalloc(sizeof(*mgmt_work), GFP_KERNEL);
	if (!mgmt_work) {
		sdk_err(hwdev->dev_hdl, "Allocate mgmt work memory failed\n");
		return;
	}

	if (recv_msg->msg_len) {
		mgmt_work->msg = kzalloc(recv_msg->msg_len, GFP_KERNEL);
		if (!mgmt_work->msg) {
			sdk_err(hwdev->dev_hdl, "Allocate mgmt msg memory failed\n");
			kfree(mgmt_work);
			return;
		}
	}

	mgmt_work->pf_to_mgmt = pf_to_mgmt;
	mgmt_work->msg_len = recv_msg->msg_len;
	memcpy(mgmt_work->msg, recv_msg->msg, recv_msg->msg_len);
	mgmt_work->msg_id = recv_msg->msg_id;
	mgmt_work->mod = recv_msg->mod;
	mgmt_work->cmd = recv_msg->cmd;
	mgmt_work->async_mgmt_to_pf = recv_msg->async_mgmt_to_pf;

	INIT_WORK(&mgmt_work->work, recv_mgmt_msg_work_handler);
	queue_work_on(sphw_get_work_cpu_affinity(hwdev, WORK_TYPE_MGMT_MSG),
		      pf_to_mgmt->workq, &mgmt_work->work);
}

/**
 * sphw_mgmt_msg_aeqe_handler - handler for a mgmt message event
 * @handle: PF to MGMT channel
 * @header: the header of the message
 * @size: unused
 **/
void sphw_mgmt_msg_aeqe_handler(void *hwdev, u8 *header, u8 size)
{
	struct sphw_hwdev *dev = (struct sphw_hwdev *)hwdev;
	struct sphw_msg_pf_to_mgmt *pf_to_mgmt = NULL;
	struct sphw_recv_msg *recv_msg = NULL;
	bool is_send_dir = false;

	if ((SPHW_MSG_HEADER_GET(*(u64 *)header, SOURCE) ==
	     SPHW_MSG_FROM_MBOX)) {
		sphw_mbox_func_aeqe_handler(hwdev, header, size);
		return;
	}

	pf_to_mgmt = dev->pf_to_mgmt;
	if (!pf_to_mgmt)
		return;

	is_send_dir = (SPHW_MSG_HEADER_GET(*(u64 *)header, DIRECTION) ==
		       SPHW_MSG_DIRECT_SEND) ? true : false;

	recv_msg = is_send_dir ? &pf_to_mgmt->recv_msg_from_mgmt :
		   &pf_to_mgmt->recv_resp_msg_from_mgmt;

	recv_mgmt_msg_handler(pf_to_mgmt, header, recv_msg);
}

/**
 * alloc_recv_msg - allocate received message memory
 * @recv_msg: pointer that will hold the allocated data
 * Return: 0 - success, negative - failure
 **/
static int alloc_recv_msg(struct sphw_recv_msg *recv_msg)
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
static void free_recv_msg(struct sphw_recv_msg *recv_msg)
{
	kfree(recv_msg->msg);
}

/**
 * alloc_msg_buf - allocate all the message buffers of PF to MGMT channel
 * @pf_to_mgmt: PF to MGMT channel
 * Return: 0 - success, negative - failure
 **/
static int alloc_msg_buf(struct sphw_msg_pf_to_mgmt *pf_to_mgmt)
{
	int err;
	void *dev = pf_to_mgmt->hwdev->dev_hdl;

	err = alloc_recv_msg(&pf_to_mgmt->recv_msg_from_mgmt);
	if (err) {
		sdk_err(dev, "Failed to allocate recv msg\n");
		return err;
	}

	err = alloc_recv_msg(&pf_to_mgmt->recv_resp_msg_from_mgmt);
	if (err) {
		sdk_err(dev, "Failed to allocate resp recv msg\n");
		goto alloc_msg_for_resp_err;
	}

	pf_to_mgmt->async_msg_buf = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!pf_to_mgmt->async_msg_buf)	{
		err = -ENOMEM;
		goto async_msg_buf_err;
	}

	pf_to_mgmt->sync_msg_buf = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!pf_to_mgmt->sync_msg_buf)	{
		err = -ENOMEM;
		goto sync_msg_buf_err;
	}

	pf_to_mgmt->mgmt_ack_buf = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!pf_to_mgmt->mgmt_ack_buf)	{
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
static void free_msg_buf(struct sphw_msg_pf_to_mgmt *pf_to_mgmt)
{
	kfree(pf_to_mgmt->mgmt_ack_buf);
	kfree(pf_to_mgmt->sync_msg_buf);
	kfree(pf_to_mgmt->async_msg_buf);

	free_recv_msg(&pf_to_mgmt->recv_resp_msg_from_mgmt);
	free_recv_msg(&pf_to_mgmt->recv_msg_from_mgmt);
}

/**
 * sphw_pf_to_mgmt_init - initialize PF to MGMT channel
 * @hwdev: the pointer to hw device
 * Return: 0 - success, negative - failure
 **/
int sphw_pf_to_mgmt_init(struct sphw_hwdev *hwdev)
{
	struct sphw_msg_pf_to_mgmt *pf_to_mgmt;
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
	pf_to_mgmt->workq = create_singlethread_workqueue(SPHW_MGMT_WQ_NAME);
	if (!pf_to_mgmt->workq) {
		sdk_err(dev, "Failed to initialize MGMT workqueue\n");
		err = -ENOMEM;
		goto create_mgmt_workq_err;
	}

	err = alloc_msg_buf(pf_to_mgmt);
	if (err) {
		sdk_err(dev, "Failed to allocate msg buffers\n");
		goto alloc_msg_buf_err;
	}

	err = sphw_api_cmd_init(hwdev, pf_to_mgmt->cmd_chain);
	if (err) {
		sdk_err(dev, "Failed to init the api cmd chains\n");
		goto api_cmd_init_err;
	}

	return 0;

api_cmd_init_err:
	free_msg_buf(pf_to_mgmt);

alloc_msg_buf_err:
	destroy_workqueue(pf_to_mgmt->workq);

create_mgmt_workq_err:
	kfree(pf_to_mgmt);

	return err;
}

/**
 * sphw_pf_to_mgmt_free - free PF to MGMT channel
 * @hwdev: the pointer to hw device
 **/
void sphw_pf_to_mgmt_free(struct sphw_hwdev *hwdev)
{
	struct sphw_msg_pf_to_mgmt *pf_to_mgmt = hwdev->pf_to_mgmt;

	/* destroy workqueue before free related pf_to_mgmt resources in case of
	 * illegal resource access
	 */
	destroy_workqueue(pf_to_mgmt->workq);
	sphw_api_cmd_free(pf_to_mgmt->cmd_chain);

	free_msg_buf(pf_to_mgmt);
	kfree(pf_to_mgmt);
}

void sphw_flush_mgmt_workq(void *hwdev)
{
	struct sphw_hwdev *dev = (struct sphw_hwdev *)hwdev;

	flush_workqueue(dev->aeqs->workq);

	if (sphw_func_type(dev) != TYPE_VF)
		flush_workqueue(dev->pf_to_mgmt->workq);
}

int sphw_api_cmd_read_ack(void *hwdev, u8 dest, const void *cmd, u16 size, void *ack, u16 ack_size)
{
	struct sphw_msg_pf_to_mgmt *pf_to_mgmt = NULL;
	struct sphw_api_cmd_chain *chain = NULL;

	if (!hwdev || !cmd || (ack_size && !ack))
		return -EINVAL;

	pf_to_mgmt = ((struct sphw_hwdev *)hwdev)->pf_to_mgmt;
	chain = pf_to_mgmt->cmd_chain[SPHW_API_CMD_POLL_READ];

	if (!(((struct sphw_hwdev *)hwdev)->chip_present_flag))
		return -EPERM;

	return sphw_api_cmd_read(chain, dest, cmd, size, ack, ack_size);
}

/**
 * api cmd write or read bypass default use poll, if want to use aeq interrupt,
 * please set wb_trigger_aeqe to 1
 **/
int sphw_api_cmd_write_nack(void *hwdev, u8 dest, const void *cmd, u16 size)
{
	struct sphw_msg_pf_to_mgmt *pf_to_mgmt = NULL;
	struct sphw_api_cmd_chain *chain = NULL;

	if (!hwdev || !size || !cmd)
		return -EINVAL;

	pf_to_mgmt = ((struct sphw_hwdev *)hwdev)->pf_to_mgmt;
	chain = pf_to_mgmt->cmd_chain[SPHW_API_CMD_POLL_WRITE];

	if (!(((struct sphw_hwdev *)hwdev)->chip_present_flag))
		return -EPERM;

	return sphw_api_cmd_write(chain, dest, cmd, size);
}
