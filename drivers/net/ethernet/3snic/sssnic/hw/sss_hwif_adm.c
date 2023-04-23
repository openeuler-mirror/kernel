// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 3snic Technologies Co., Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [BASE]" fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/completion.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/semaphore.h>
#include <linux/jiffies.h>
#include <linux/delay.h>

#include "sss_kernel.h"
#include "sss_hw.h"
#include "sss_common.h"
#include "sss_hwdev.h"
#include "sss_csr.h"
#include "sss_hwif_api.h"
#include "sss_hwif_adm_common.h"
#include "sss_hwif_aeq.h"

#define SSS_ADM_MSG_ELEM_DESC_SIZE				8
#define SSS_ADM_MSG_ELEM_DATA_ADDR_SIZE			8

#define SSS_ADM_MSG_ELEM_ALIGNMENT				8

#define SSS_ADM_MSG_STATE_TIMEOUT				10000

#define SSS_WRITE_ADM_MSG_PRIV_DATA(id)			(((u8)(id)) << 16)

#define SSS_MASK_ID(adm_msg, id)			\
		((id) & ((adm_msg)->elem_num - 1))

#define SSS_SIZE_TO_4B(size)				\
		(ALIGN((u32)(size), 4U) >> 2)
#define SSS_SIZE_TO_8B(size)				\
		(ALIGN((u32)(size), 8U) >> 3)

/* adm_msg_elem structure */
#define SSS_ADM_MSG_ELEM_CTRL_ELEM_LEN_SHIFT			0
#define SSS_ADM_MSG_ELEM_CTRL_RD_DMA_ATTR_OFF_SHIFT		16
#define SSS_ADM_MSG_ELEM_CTRL_WR_DMA_ATTR_OFF_SHIFT		24
#define SSS_ADM_MSG_ELEM_CTRL_XOR_CHKSUM_SHIFT			56

#define SSS_ADM_MSG_ELEM_CTRL_ELEM_LEN_MASK				0x3FU
#define SSS_ADM_MSG_ELEM_CTRL_RD_DMA_ATTR_OFF_MASK		0x3FU
#define SSS_ADM_MSG_ELEM_CTRL_WR_DMA_ATTR_OFF_MASK		0x3FU
#define SSS_ADM_MSG_ELEM_CTRL_XOR_CHKSUM_MASK			0xFFU

#define SSS_ADM_MSG_ELEM_CTRL_SET(val, member)		\
		((((u64)(val)) & SSS_ADM_MSG_ELEM_CTRL_##member##_MASK) << \
			SSS_ADM_MSG_ELEM_CTRL_##member##_SHIFT)

/* adm_msg_elem.desc structure */
#define SSS_ADM_MSG_DESC_SGL_TYPE_SHIFT				0
#define SSS_ADM_MSG_DESC_RD_WR_SHIFT				1
#define SSS_ADM_MSG_DESC_MGMT_BYPASS_SHIFT			2
#define SSS_ADM_MSG_DESC_REPLY_AEQE_EN_SHIFT		3
#define SSS_ADM_MSG_DESC_MSG_VALID_SHIFT			4
#define SSS_ADM_MSG_DESC_MSG_CHANNEL_SHIFT			6
#define SSS_ADM_MSG_DESC_PRIV_DATA_SHIFT			8
#define SSS_ADM_MSG_DESC_DEST_SHIFT					32
#define SSS_ADM_MSG_DESC_SIZE_SHIFT					40
#define SSS_ADM_MSG_DESC_XOR_CHKSUM_SHIFT			56

#define SSS_ADM_MSG_DESC_SGL_TYPE_MASK				0x1U
#define SSS_ADM_MSG_DESC_RD_WR_MASK					0x1U
#define SSS_ADM_MSG_DESC_MGMT_BYPASS_MASK			0x1U
#define SSS_ADM_MSG_DESC_REPLY_AEQE_EN_MASK			0x1U
#define SSS_ADM_MSG_DESC_MSG_VALID_MASK				0x3U
#define SSS_ADM_MSG_DESC_MSG_CHANNEL_MASK			0x3U
#define SSS_ADM_MSG_DESC_PRIV_DATA_MASK				0xFFFFFFU
#define SSS_ADM_MSG_DESC_DEST_MASK					0x1FU
#define SSS_ADM_MSG_DESC_SIZE_MASK					0x7FFU
#define SSS_ADM_MSG_DESC_XOR_CHKSUM_MASK				0xFFU

#define SSS_ADM_MSG_DESC_SET(val, member)			\
		((((u64)(val)) & SSS_ADM_MSG_DESC_##member##_MASK) << \
			SSS_ADM_MSG_DESC_##member##_SHIFT)

/* adm_msg_state header */
#define SSS_ADM_MSG_STATE_HEAD_VALID_SHIFT		0
#define SSS_ADM_MSG_STATE_HEAD_MSG_ID_SHIFT		16

#define SSS_ADM_MSG_STATE_HEAD_VALID_MASK			0xFFU
#define SSS_ADM_MSG_STATE_HEAD_MSG_ID_MASK		0xFFU

#define SSS_ADM_MSG_STATE_HEAD_GET(val, member)		\
			(((val) >> SSS_ADM_MSG_STATE_HEAD_##member##_SHIFT) & \
				SSS_ADM_MSG_STATE_HEAD_##member##_MASK)

enum sss_adm_msg_data_format {
	SSS_SGL_TYPE	= 1,
};

enum sss_adm_msg_opt {
	SSS_ADM_MSG_WRITE = 0,
	SSS_ADM_MSG_READ = 1,
};

enum sss_adm_msg_bypass {
	SSS_NO_BYPASS = 0,
	SSS_BYPASS = 1,
};

enum sss_adm_msg_reply_aeq {
	SSS_NO_TRIGGER = 0,
	SSS_TRIGGER = 1,
};

enum sss_adm_msg_chn_code {
	SSS_ADM_MSG_CHANNEL_0 = 0,
};

enum sss_adm_msg_chn_rsvd {
	SSS_VALID_MSG_CHANNEL = 0,
	SSS_INVALID_MSG_CHANNEL = 1,
};

#define SSS_ADM_MSG_DESC_LEN	7

struct sss_msg_head {
	u8	state;
	u8	version;
	u8	reply_aeq_num;
	u8	rsvd0[5];
};

#define SSS_ADM_MSG_AEQ_ID					2

#define SSS_MGMT_MSG_SIZE_MIN					20
#define SSS_MGMT_MSG_SIZE_STEP					16
#define	SSS_MGMT_MSG_RSVD_FOR_DEV				8

#define SSS_MSG_TO_MGMT_LEN_MAX					2016

#define SSS_SYNC_MSG_ID_MASK					0x7
#define SSS_SYNC_MSG_ID(pf_to_mgmt)				((pf_to_mgmt)->sync_msg_id)
#define SSS_INCREASE_SYNC_MSG_ID(pf_to_mgmt)	\
	((pf_to_mgmt)->sync_msg_id = \
		((pf_to_mgmt)->sync_msg_id + 1) & SSS_SYNC_MSG_ID_MASK)

#define SSS_MGMT_MSG_TIMEOUT					20000 /* millisecond */

#define SSS_MSG_CB_USLEEP_MIN				900
#define SSS_MSG_CB_USLEEP_MAX				1000

#define SSS_ENCAPSULATE_ADM_MSG_HEAD(func_id, msg_len, mod, cmd, msg_id) \
	(SSS_SET_MSG_HEADER(msg_len, MSG_LEN) | \
		SSS_SET_MSG_HEADER(mod, MODULE) | \
		SSS_SET_MSG_HEADER(msg_len, SEG_LEN) | \
		SSS_SET_MSG_HEADER(SSS_MSG_ACK, NO_ACK) | \
		SSS_SET_MSG_HEADER(SSS_INLINE_DATA, DATA_TYPE) | \
		SSS_SET_MSG_HEADER(0, SEQID) | \
		SSS_SET_MSG_HEADER(SSS_ADM_MSG_AEQ_ID, AEQ_ID) | \
		SSS_SET_MSG_HEADER(SSS_LAST_SEG, LAST) | \
		SSS_SET_MSG_HEADER(SSS_DIRECT_SEND_MSG, DIRECTION) | \
		SSS_SET_MSG_HEADER(cmd, CMD) | \
		SSS_SET_MSG_HEADER(SSS_MSG_SRC_MGMT, SOURCE) | \
		SSS_SET_MSG_HEADER(func_id, SRC_GLB_FUNC_ID) | \
		SSS_SET_MSG_HEADER(msg_id, MSG_ID))

static u8 sss_xor_chksum_set(void *data)
{
	int id;
	u8 checksum = 0;
	u8 *val = data;

	for (id = 0; id < SSS_ADM_MSG_DESC_LEN; id++)
		checksum ^= val[id];

	return checksum;
}

static void sss_chip_set_pi(struct sss_adm_msg *adm_msg)
{
	enum sss_adm_msg_type msg_type = adm_msg->msg_type;
	struct sss_hwif *hwif = SSS_TO_HWDEV(adm_msg)->hwif;
	u32 hw_pi_addr = SSS_CSR_ADM_MSG_PI_ADDR(msg_type);

	sss_chip_write_reg(hwif, hw_pi_addr, adm_msg->pi);
}

static u32 sss_chip_get_ci(struct sss_adm_msg *adm_msg)
{
	u32 addr;
	u32 val;

	addr = SSS_CSR_ADM_MSG_STATE_0_ADDR(adm_msg->msg_type);
	val = sss_chip_read_reg(SSS_TO_HWDEV(adm_msg)->hwif, addr);

	return SSS_GET_ADM_MSG_STATE(val, CI);
}

static void sss_dump_adm_msg_reg(struct sss_adm_msg *adm_msg)
{
	void *dev = SSS_TO_HWDEV(adm_msg)->dev_hdl;
	u32 addr;
	u32 val;
	u16 pci_cmd = 0;

	addr = SSS_CSR_ADM_MSG_STATE_0_ADDR(adm_msg->msg_type);
	val  = sss_chip_read_reg(SSS_TO_HWDEV(adm_msg)->hwif, addr);

	sdk_err(dev, "Msg type: 0x%x, cpld error: 0x%x, check error: 0x%x,  current fsm: 0x%x\n",
		adm_msg->msg_type, SSS_GET_ADM_MSG_STATE(val, CPLD_ERR),
		SSS_GET_ADM_MSG_STATE(val, CHKSUM_ERR),
		SSS_GET_ADM_MSG_STATE(val, FSM));

	sdk_err(dev, "Adm msg hw current ci: 0x%x\n",
		SSS_GET_ADM_MSG_STATE(val, CI));

	addr = SSS_CSR_ADM_MSG_PI_ADDR(adm_msg->msg_type);
	val = sss_chip_read_reg(SSS_TO_HWDEV(adm_msg)->hwif, addr);
	sdk_err(dev, "Adm msg hw current pi: 0x%x\n", val);
	pci_read_config_word(SSS_TO_HWDEV(adm_msg)->pcidev_hdl, PCI_COMMAND, &pci_cmd);
	sdk_err(dev, "PCI command reg: 0x%x\n", pci_cmd);
}

static int sss_adm_msg_busy(struct sss_adm_msg *adm_msg)
{
	adm_msg->ci = sss_chip_get_ci(adm_msg);
	if (adm_msg->ci == SSS_MASK_ID(adm_msg, adm_msg->pi + 1)) {
		sdk_err(SSS_TO_HWDEV(adm_msg)->dev_hdl, "Adm cmd is busy, ci = %u, pi = %u\n",
			adm_msg->ci, adm_msg->pi);
		sss_dump_adm_msg_reg(adm_msg);
		return -EBUSY;
	}

	return 0;
}

static void sss_prepare_elem_ctrl(u64 *elem_ctrl)
{
	u64 control;
	u8 chksum;
	u16 elem_len = ALIGN(SSS_ADM_MSG_ELEM_DESC_SIZE +
			     SSS_ADM_MSG_ELEM_DATA_ADDR_SIZE, SSS_ADM_MSG_ELEM_ALIGNMENT);

	control = SSS_ADM_MSG_ELEM_CTRL_SET(SSS_SIZE_TO_8B(elem_len), ELEM_LEN) |
		  SSS_ADM_MSG_ELEM_CTRL_SET(0ULL, RD_DMA_ATTR_OFF) |
		  SSS_ADM_MSG_ELEM_CTRL_SET(0ULL, WR_DMA_ATTR_OFF);

	chksum = sss_xor_chksum_set(&control);

	control |= SSS_ADM_MSG_ELEM_CTRL_SET(chksum, XOR_CHKSUM);

	/* The data in the HW should be in Big Endian Format */
	*elem_ctrl = cpu_to_be64(control);
}

static void sss_prepare_elem_desc(struct sss_adm_msg *adm_msg,
				  u8 node_id, u16 cmd_size)
{
	u32 priv;
	struct sss_adm_msg_elem *elem = adm_msg->now_node;

	priv = SSS_WRITE_ADM_MSG_PRIV_DATA(adm_msg->msg_type);
	elem->desc = SSS_ADM_MSG_DESC_SET(SSS_SGL_TYPE, SGL_TYPE) |
		     SSS_ADM_MSG_DESC_SET(SSS_ADM_MSG_WRITE, RD_WR) |
		     SSS_ADM_MSG_DESC_SET(SSS_NO_BYPASS, MGMT_BYPASS) |
		     SSS_ADM_MSG_DESC_SET(SSS_TRIGGER, REPLY_AEQE_EN) |
		     SSS_ADM_MSG_DESC_SET(priv, PRIV_DATA);

	elem->desc |= SSS_ADM_MSG_DESC_SET(SSS_ADM_MSG_CHANNEL_0, MSG_CHANNEL) |
		      SSS_ADM_MSG_DESC_SET(SSS_VALID_MSG_CHANNEL, MSG_VALID);

	elem->desc |= SSS_ADM_MSG_DESC_SET(node_id, DEST) |
		      SSS_ADM_MSG_DESC_SET(SSS_SIZE_TO_4B(cmd_size), SIZE);

	elem->desc |= SSS_ADM_MSG_DESC_SET(sss_xor_chksum_set(&elem->desc), XOR_CHKSUM);

	/* The data in the HW should be in Big Endian Format */
	elem->desc = cpu_to_be64(elem->desc);
}

static void sss_prepare_elem_ctx(struct sss_adm_msg *adm_msg,
				 const void *cmd, u16 cmd_size)
{
	struct sss_adm_msg_elem_ctx *elem_ctx = &adm_msg->elem_ctx[adm_msg->pi];

	memcpy(elem_ctx->adm_msg_vaddr, cmd, cmd_size);
}

static void sss_prepare_elem(struct sss_adm_msg *adm_msg, u8 node_id,
			     const void *cmd, u16 cmd_size)
{
	struct sss_adm_msg_elem *now_node = adm_msg->now_node;

	sss_prepare_elem_ctrl(&now_node->control);
	sss_prepare_elem_desc(adm_msg, node_id, cmd_size);
	sss_prepare_elem_ctx(adm_msg, cmd, cmd_size);
}

static inline void sss_adm_msg_increase_pi(struct sss_adm_msg *adm_msg)
{
	adm_msg->pi = SSS_MASK_ID(adm_msg, adm_msg->pi + 1);
}

static void sss_issue_adm_msg(struct sss_adm_msg *adm_msg)
{
	sss_chip_set_pi(adm_msg);
}

static void sss_update_adm_msg_state(struct sss_adm_msg *adm_msg)
{
	struct sss_adm_msg_state *wb_state;
	enum sss_adm_msg_type msg_type;
	u64 status_header;
	u32 desc_buf;

	wb_state = adm_msg->wb_state;

	desc_buf = be32_to_cpu(wb_state->desc_buf);
	if (SSS_GET_ADM_MSG_STATE(desc_buf, CHKSUM_ERR))
		return;

	status_header = be64_to_cpu(wb_state->head);
	msg_type = SSS_ADM_MSG_STATE_HEAD_GET(status_header, MSG_ID);
	if (msg_type >= SSS_ADM_MSG_MAX)
		return;

	if (msg_type != adm_msg->msg_type)
		return;

	adm_msg->ci = SSS_GET_ADM_MSG_STATE(desc_buf, CI);
}

static enum sss_process_ret sss_wait_for_state_poll_handler(void *priv_data)
{
	struct sss_adm_msg *adm_msg = priv_data;

	if (!SSS_TO_HWDEV(adm_msg)->chip_present_flag)
		return SSS_PROCESS_ERR;

	sss_update_adm_msg_state(adm_msg);
	/* SYNC ADM MSG cmd should start after prev cmd finished */
	if (adm_msg->ci == adm_msg->pi)
		return SSS_PROCESS_OK;

	return SSS_PROCESS_DOING;
}

static int sss_wait_for_state_poll(struct sss_adm_msg *adm_msg)
{
	return sss_check_handler_timeout(adm_msg, sss_wait_for_state_poll_handler,
					 SSS_ADM_MSG_STATE_TIMEOUT, 100); /* wait 100 us once */
}

static int sss_wait_for_adm_msg_completion(struct sss_adm_msg *adm_msg,
					   struct sss_adm_msg_elem_ctx *ctx)
{
	int ret = 0;

	ret = sss_wait_for_state_poll(adm_msg);
	if (ret != 0) {
		sdk_err(SSS_TO_HWDEV(adm_msg)->dev_hdl, "Adm msg poll state timeout\n");
		sss_dump_adm_msg_reg(adm_msg);
	}

	return ret;
}

static inline void sss_update_adm_msg_ctx(struct sss_adm_msg *adm_msg)
{
	struct sss_adm_msg_elem_ctx *ctx = &adm_msg->elem_ctx[adm_msg->pi];

	ctx->state = 1;
	ctx->store_pi = adm_msg->pi;
	if (ctx->reply_fmt) {
		ctx->reply_fmt->head = 0;

		/* make sure "header" was cleared */
		wmb();
	}
}

static void sss_adm_msg_lock(struct sss_adm_msg *adm_msg)
{
	down(&adm_msg->sem);
}

static void sss_adm_msg_unlock(struct sss_adm_msg *adm_msg)
{
	up(&adm_msg->sem);
}

static int sss_send_adm_cmd(struct sss_adm_msg *adm_msg, u8 node_id,
			    const void *cmd, u16 cmd_size)
{
	struct sss_adm_msg_elem_ctx *ctx = NULL;

	if (adm_msg->msg_type != SSS_ADM_MSG_WRITE_TO_MGMT_MODULE) {
		sdk_err(SSS_TO_HWDEV(adm_msg)->dev_hdl,
			"Unsupport adm cmd type: %d\n", adm_msg->msg_type);
		return -EINVAL;
	}

	sss_adm_msg_lock(adm_msg);

	ctx = &adm_msg->elem_ctx[adm_msg->pi];

	if (sss_adm_msg_busy(adm_msg)) {
		sss_adm_msg_unlock(adm_msg);
		return -EBUSY;
	}

	sss_update_adm_msg_ctx(adm_msg);

	sss_prepare_elem(adm_msg, node_id, cmd, cmd_size);

	sss_adm_msg_increase_pi(adm_msg);

	wmb(); /* make sure issue correctly the command */

	sss_issue_adm_msg(adm_msg);

	adm_msg->now_node = adm_msg->elem_ctx[adm_msg->pi].elem_vaddr;

	sss_adm_msg_unlock(adm_msg);

	return sss_wait_for_adm_msg_completion(adm_msg, ctx);
}

static void sss_set_adm_event_flag(struct sss_msg_pf_to_mgmt *pf_to_mgmt,
				   int event_flag)
{
	spin_lock(&pf_to_mgmt->sync_event_lock);
	pf_to_mgmt->event_state = event_flag;
	spin_unlock(&pf_to_mgmt->sync_event_lock);
}

static u16 sss_align_adm_msg_len(u16 msg_data_len)
{
	/* u64 - the size of the header */
	u16 msg_size;

	msg_size = (u16)(SSS_MGMT_MSG_RSVD_FOR_DEV + sizeof(u64) + msg_data_len);

	if (msg_size > SSS_MGMT_MSG_SIZE_MIN)
		msg_size = SSS_MGMT_MSG_SIZE_MIN +
			   ALIGN((msg_size - SSS_MGMT_MSG_SIZE_MIN), SSS_MGMT_MSG_SIZE_STEP);
	else
		msg_size = SSS_MGMT_MSG_SIZE_MIN;

	return msg_size;
}

static void sss_encapsulate_adm_msg(u8 *adm_msg, u64 *header,
				    const void *body, int body_len)
{
	u8 *adm_msg_new = adm_msg;

	memset(adm_msg_new, 0, SSS_MGMT_MSG_RSVD_FOR_DEV);

	adm_msg_new += SSS_MGMT_MSG_RSVD_FOR_DEV;
	memcpy(adm_msg_new, header, sizeof(*header));

	adm_msg_new += sizeof(*header);
	memcpy(adm_msg_new, body, (size_t)(u32)body_len);
}

static int sss_send_adm_msg(struct sss_msg_pf_to_mgmt *pf_to_mgmt,
			    u8 mod, u16 cmd, const void *msg_body, u16 msg_body_len)
{
	struct sss_hwif *hwif = SSS_TO_HWDEV(pf_to_mgmt)->hwif;
	void *adm_msg = pf_to_mgmt->sync_buf;
	u16 adm_msg_len = sss_align_adm_msg_len(msg_body_len);
	u32 func_id = SSS_GET_HWIF_GLOBAL_ID(hwif);
	u8 node_id = SSS_MGMT_CPU_NODE_ID(SSS_TO_HWDEV(pf_to_mgmt));
	u64 header;

	if (sss_get_dev_present_flag(pf_to_mgmt->hwdev) == 0)
		return -EFAULT;

	if (adm_msg_len > SSS_MSG_TO_MGMT_LEN_MAX)
		return -EFAULT;

	sss_set_adm_event_flag(pf_to_mgmt, SSS_ADM_EVENT_START);
	SSS_INCREASE_SYNC_MSG_ID(pf_to_mgmt);

	header = SSS_ENCAPSULATE_ADM_MSG_HEAD(func_id, msg_body_len, mod,
					      cmd, SSS_SYNC_MSG_ID(pf_to_mgmt));
	sss_encapsulate_adm_msg((u8 *)adm_msg, &header, msg_body, msg_body_len);

	return sss_send_adm_cmd(&pf_to_mgmt->adm_msg, node_id, adm_msg, adm_msg_len);
}

static inline void sss_check_msg_body(u8 mod, void *buf_in)
{
	struct sss_msg_head *msg_head = NULL;

	/* set aeq fix num to 3, need to ensure response aeq id < 3 */
	if (mod == SSS_MOD_TYPE_COMM || mod == SSS_MOD_TYPE_L2NIC) {
		msg_head = buf_in;

		if (msg_head->reply_aeq_num >= SSS_MAX_AEQ)
			msg_head->reply_aeq_num = 0;
	}
}

int sss_sync_send_adm_msg(void *hwdev, u8 mod, u16 cmd, void *buf_in,
			  u16 in_size, void *buf_out, u16 *out_size, u32 timeout)
{
	struct sss_msg_pf_to_mgmt *pf_to_mgmt = NULL;
	void *dev = ((struct sss_hwdev *)hwdev)->dev_hdl;
	struct sss_recv_msg *recv_msg = NULL;
	struct completion *recv_done = NULL;
	ulong timeo;
	int err;
	ulong ret;

	if (!SSS_SUPPORT_ADM_MSG((struct sss_hwdev *)hwdev))
		return -EPERM;

	sss_check_msg_body(mod, buf_in);

	pf_to_mgmt = ((struct sss_hwdev *)hwdev)->pf_to_mgmt;

	/* Lock the sync_buf */
	down(&pf_to_mgmt->sync_lock);
	recv_msg = &pf_to_mgmt->recv_resp_msg;
	recv_done = &recv_msg->done;

	init_completion(recv_done);

	err = sss_send_adm_msg(pf_to_mgmt, mod, cmd, buf_in, in_size);
	if (err != 0) {
		sdk_err(dev, "Fail to send adm msg to mgmt, sync_msg_id: %u\n",
			pf_to_mgmt->sync_msg_id);
		sss_set_adm_event_flag(pf_to_mgmt, SSS_ADM_EVENT_FAIL);
		goto unlock_sync_msg;
	}

	timeo = msecs_to_jiffies(timeout ? timeout : SSS_MGMT_MSG_TIMEOUT);

	ret = wait_for_completion_timeout(recv_done, timeo);
	if (ret == 0) {
		sdk_err(dev, "Mgmt response sync cmd timeout, sync_msg_id: %u\n",
			pf_to_mgmt->sync_msg_id);
		sss_dump_aeq_info((struct sss_hwdev *)hwdev);
		err = -ETIMEDOUT;
		sss_set_adm_event_flag(pf_to_mgmt, SSS_ADM_EVENT_TIMEOUT);
		goto unlock_sync_msg;
	}

	spin_lock(&pf_to_mgmt->sync_event_lock);
	if (pf_to_mgmt->event_state == SSS_ADM_EVENT_TIMEOUT) {
		spin_unlock(&pf_to_mgmt->sync_event_lock);
		err = -ETIMEDOUT;
		goto unlock_sync_msg;
	}
	spin_unlock(&pf_to_mgmt->sync_event_lock);

	sss_set_adm_event_flag(pf_to_mgmt, SSS_ADM_EVENT_END);

	if (!(((struct sss_hwdev *)hwdev)->chip_present_flag)) {
		destroy_completion(recv_done);
		up(&pf_to_mgmt->sync_lock);
		return -ETIMEDOUT;
	}

	if (buf_out && out_size) {
		if (*out_size < recv_msg->buf_len) {
			sdk_err(dev,
				"Invalid resp msg len: %u out of range: %u, mod %d, cmd %u\n",
				recv_msg->buf_len, *out_size, mod, cmd);
			err = -EFAULT;
			goto unlock_sync_msg;
		}

		if (recv_msg->buf_len)
			memcpy(buf_out, recv_msg->buf, recv_msg->buf_len);

		*out_size = recv_msg->buf_len;
	}

unlock_sync_msg:
	destroy_completion(recv_done);
	up(&pf_to_mgmt->sync_lock);

	return err;
}

int sss_register_mgmt_msg_handler(void *hwdev, u8 mod_type, void *data,
				  sss_mgmt_msg_handler_t handler)
{
	struct sss_msg_pf_to_mgmt *mgmt_msg = NULL;

	if (!hwdev || mod_type >= SSS_MOD_TYPE_HW_MAX)
		return -EFAULT;

	mgmt_msg = ((struct sss_hwdev *)hwdev)->pf_to_mgmt;
	if (!mgmt_msg)
		return -EINVAL;

	mgmt_msg->recv_data[mod_type] = data;
	mgmt_msg->recv_handler[mod_type] = handler;

	set_bit(SSS_CALLBACK_REG, &mgmt_msg->recv_handler_state[mod_type]);

	return 0;
}
EXPORT_SYMBOL(sss_register_mgmt_msg_handler);

void sss_unregister_mgmt_msg_handler(void *hwdev, u8 mod_type)
{
	struct sss_msg_pf_to_mgmt *mgmt_msg = NULL;

	if (!hwdev || mod_type >= SSS_MOD_TYPE_HW_MAX)
		return;

	mgmt_msg = ((struct sss_hwdev *)hwdev)->pf_to_mgmt;
	if (!mgmt_msg)
		return;

	clear_bit(SSS_CALLBACK_REG, &mgmt_msg->recv_handler_state[mod_type]);

	while (test_bit(SSS_CALLBACK_RUNNING, &mgmt_msg->recv_handler_state[mod_type]))
		usleep_range(SSS_MSG_CB_USLEEP_MIN, SSS_MSG_CB_USLEEP_MAX);

	mgmt_msg->recv_data[mod_type] = NULL;
	mgmt_msg->recv_handler[mod_type] = NULL;
}
EXPORT_SYMBOL(sss_unregister_mgmt_msg_handler);
