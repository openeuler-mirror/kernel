// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
#include <linux/bitmap.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/slab.h>

#include "nse_msgbox.h"
#include "nse_lib.h"
#include "nse_vf_mbx.h"

static unsigned int nse_msgbox_verbose;	/* for debug log */

static unsigned int nse_msgbox_tx_clear_first = 1;

static unsigned int nse_msgbox_frag_timeout_tick = 100;		/* 100 us = 0.1 ms */
static unsigned int nse_msgbox_tx_frag_timeout = 2000;		/* 0.1 ms * 2000 = 200 ms */
static unsigned int nse_msgbox_rx_frag_timeout = 200;		/* 0.1 ms * 100 = 20 ms */

void p2v_send_one_frag(struct nse_hw *hw, u16 vsi_rel_id, u32 *cur_frag,
		       u32 frag_seq, u32 frag_flag, u32 msg_type)
{
	u32 ctl;
	u32 i;

	ctl = NSE_REG_P2V_UPCTL_VLD_M |
			(frag_flag << NSE_MSGBOX_MSG_FRAG_FLAG_S) |
			(msg_type << MSG_MSGBOX_MSG_TYPE_S) |
			(frag_seq << NSE_MSGBOX_MSG_FRAG_SEQ_S);

	for (i = 0; i < 4; i++)
		wr32(hw, NSE_REG_P2V_UPBUF(vsi_rel_id, i), cur_frag[i]);

	/* Make sure the fragment buffer above is written before the
	 * control register makes it visible.
	 */
	wmb();

	wr32(hw, NSE_REG_P2V_UPCTL(vsi_rel_id), ctl);

	nse_flush(hw);

	/* sleep a while for VSI to RX. */
	usleep_range(nse_msgbox_frag_timeout_tick, (nse_msgbox_frag_timeout_tick << 1));
}

enum nse_status nse_msgbox_p2v_send_msg(struct nse_pf *pf, u16 vsi_rel_id, char *msg,
					unsigned int msg_len, u32 msg_type)
{
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	u32 *cur_frag = NULL;
	u32 frag_seq, frag_cnt;
	u32 frag_flag;
	unsigned int frag_send_timeout;
	unsigned int frag_send_timeout_limit = (nse_msgbox_tx_frag_timeout * nse_timeout_scale);
	u32 reg;
	enum nse_status ret = 0;

	if (vsi_rel_id >= pf->vsi_space_size ||
		!msg ||
		msg_len > NSE_MSGBOX_MSG_MAX_LEN)
		return NSE_ERR_PARAM;

	frag_cnt = DIV_ROUND_UP(msg_len, NSE_MSGBOX_MSG_FRAG_LEN);

	if (nse_msgbox_verbose) {
		dev_info(dev, "PF msgbox P2V_TX: send a msg to VSI(rel_id=%d), frag_cnt=%d, msg_len(in bytes)=%d\n",
					vsi_rel_id, frag_cnt, msg_len);
		dev_info(dev, "msg content:\n");

		cur_frag = (u32 *)msg;

		for (frag_seq = 0; frag_seq < frag_cnt; frag_seq++) {
			dev_info(dev, "\t %08X %08X %08X %08X\n",
						cur_frag[0], cur_frag[1], cur_frag[2], cur_frag[3]);

			cur_frag += 4;
		}
	}

	mutex_lock(&pf->msgbox_cb.p2v_mutex[vsi_rel_id]);

	if (nse_msgbox_tx_clear_first)
		wr32(hw, NSE_REG_P2V_UPCTL(vsi_rel_id), 0);

	for (frag_seq = 0; frag_seq < frag_cnt; frag_seq++) {
		cur_frag = (u32 *)(msg + (frag_seq * NSE_MSGBOX_MSG_FRAG_LEN));

		for (frag_send_timeout =
		     0; frag_send_timeout < frag_send_timeout_limit; frag_send_timeout++) {
			reg = rd32(hw, NSE_REG_P2V_UPCTL(vsi_rel_id));

			if (nse_is_regval_reset_magic(reg) || nse_is_reset_in_progress(pf->state)) {
				nse_debug(hw, NSE_DBG_SYS, "[%s, %d] reset detected\n",
					  __func__, __LINE__);
				ret = NSE_ERR_NOT_READY;
				goto out;
			}

			if (reg & NSE_REG_P2V_UPCTL_VLD_M) {
				pf->msgbox_cb.stats.p2v_tx_send_wait_cnt++;
				usleep_range(nse_msgbox_frag_timeout_tick,
					     (nse_msgbox_frag_timeout_tick << 1));
			} else {
				break;
			}
		}

		if (frag_send_timeout >= frag_send_timeout_limit) {
			ret = NSE_ERR_BUSY;
			pf->msgbox_cb.stats.p2v_tx_send_timeout_cnt++;

			if (nse_msgbox_verbose) {
				dev_info(dev, "[%s, %d] p2v_tx_send_timeout, frag_seq=%d, in frag_cnt=%d",
						__func__, __LINE__,
						frag_seq, frag_cnt);
			}

			goto out;
		}

		if (frag_seq == (frag_cnt - 1))
			frag_flag = NSE_MSGBOX_MSG_FRAG_FLAG_LAST;
		else
			frag_flag = NSE_MSGBOX_MSG_FRAG_FLAG_MORE;

		p2v_send_one_frag(hw, vsi_rel_id, cur_frag, frag_seq, frag_flag, msg_type);
	}

	ret = NSE_SUCCESS;

out:
	mutex_unlock(&pf->msgbox_cb.p2v_mutex[vsi_rel_id]);

	return ret;
}

/* msgbox version of nse_aq_send_msg_to_vf() */
#ifdef CONFIG_PCI_IOV
enum nse_status
nse_msgbox_p2v_send_msg_to_vf(struct nse_hw *hw, u16 vf_vsi_abs_id, u32 v_opcode, u32 v_retval,
		      u8 *msg, u16 msglen)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	void *cbuf = NULL;
	size_t cbuf_len = sizeof(struct nse_aqc_mbx_cmd_buff_hdr) + msglen;
	struct nse_aqc_mbx_cmd_buff_hdr *hdr = NULL;
	enum nse_status status;
	u32 msg_type;

	if (hw->high_reset_ongoing)
		return NSE_SUCCESS;

	if (vf_vsi_abs_id >= NSE_AQ_MAILBOX_ID_VSI_MAX)
		return NSE_ERR_DOES_NOT_EXIST;

	cbuf = devm_kzalloc(nse_hw_to_dev(hw), cbuf_len, GFP_KERNEL);
	if (!cbuf)
		return NSE_ERR_NO_MEMORY;

	/* set hdr */
	hdr = (struct nse_aqc_mbx_cmd_buff_hdr *)cbuf;
	hdr->cookie_high = cpu_to_le32(v_opcode);
	hdr->cookie_low = cpu_to_le32(v_retval);

	if (msglen)
		memcpy(cbuf + sizeof(struct nse_aqc_mbx_cmd_buff_hdr), msg, msglen);

	if (v_opcode == VIRTCHNL_OP_EVENT)
		msg_type = MSG_MSGBOX_MSG_TYPE_EVENT;
	else
		msg_type = MSG_MSGBOX_MSG_TYPE_RESPONSE;

	status = nse_msgbox_p2v_send_msg(pf, (vf_vsi_abs_id - pf->vsi_space_start),
									cbuf, cbuf_len, msg_type);

	devm_kfree(nse_hw_to_dev(hw), cbuf);

	return status;
}
#endif /* CONFIG_PCI_IOV */

void v2p_dump_msg(struct nse_pf *pf, struct nse_rq_event_info *event)
{
	struct device *dev = nse_pf_to_dev(pf);
	u16 vsi_rel_id = le16_to_cpu(event->desc.mailbox_id) - pf->vsi_space_start;
	u32 *cur_frag = (u32 *)event->msg_buf;
	u32 frag_cnt = DIV_ROUND_UP(event->msg_len, NSE_MSGBOX_MSG_FRAG_LEN);
	u32 i;

	dev_info(dev, "PF MSGBOX_V2P_RX: receive msg from VSI(rel_id=%d), content:\n", vsi_rel_id);

	for (i = 0; i < frag_cnt; i++) {
		dev_info(dev, "\t %08X %08X %08X %08X\n",
					cur_frag[0], cur_frag[1], cur_frag[2], cur_frag[3]);

		cur_frag += 4;
	}
}

static void v2p_rx_flush_previous(struct nse_msgbox_rx_msg_buf *rx_msg_buf)
{
	/* no need: memset(msg_buf->rx_msg_buf, 0) */

	rx_msg_buf->rx_msg_len = 0;

	bitmap_clear(rx_msg_buf->rx_frag_bitmap, 0, NSE_MSGBOX_MSG_FRAG_MAX_CNT);
}

static void v2p_rx_handle_msg(struct nse_pf *pf, u16 vsi_rel_id, struct nse_rq_event_info *event)
{
	struct nse_msgbox_rx_msg_buf *rx_msg_buf = &pf->msgbox_cb.v2p_rx_msg_buf[vsi_rel_id];

	event->src = NSE_RQ_EVENT_INFO_SRC_MSGBOX;

	event->desc.mailbox_id = cpu_to_le16(vsi_rel_id + pf->vsi_space_start);

	event->msg_len = min_t(u16, event->buf_len, rx_msg_buf->rx_msg_len);

	memcpy(event->msg_buf, rx_msg_buf->msg_buf, event->msg_len);

	v2p_rx_flush_previous(rx_msg_buf);	//already copy into event, OK to flush for now.

	if (nse_msgbox_verbose)
		v2p_dump_msg(pf, event);

	nse_vc_process_vf_msg(pf, event);
}

int v2p_rx_one_frag(struct nse_pf *pf, u16 vsi_rel_id, u32 v2p_dnctl)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_msgbox_rx_msg_buf *rx_msg_buf = &pf->msgbox_cb.v2p_rx_msg_buf[vsi_rel_id];
	u32 *cur_frag_buf = NULL;
	u32 frag_seq, frag_flag;
	int i;
	int ret = 0;

	frag_seq = (v2p_dnctl & NSE_MSGBOX_MSG_FRAG_SEQ_M) >> NSE_MSGBOX_MSG_FRAG_SEQ_S;
	frag_flag = (v2p_dnctl & NSE_MSGBOX_MSG_FRAG_FLAG_M) >> NSE_MSGBOX_MSG_FRAG_FLAG_S;

	if (nse_msgbox_verbose) {
		dev_info(dev, "[%s, %d] rx one frag from vsi(rel_id=%d), v2p_dnctl=%X (frag_seq=%d, frag_flag=%d)\n",
					__func__, __LINE__, vsi_rel_id,
						v2p_dnctl, frag_seq, frag_flag);
	}

	/* receive frag #0, flush any previous, start a new session. */
	if (!frag_seq)
		v2p_rx_flush_previous(rx_msg_buf);

	/* already rx this frag_seq? */
	if (test_and_set_bit(frag_seq, rx_msg_buf->rx_frag_bitmap)) {
		pf->msgbox_cb.stats.v2p_rx_bad_dup_frag++;

		if (nse_msgbox_verbose)
			dev_info(dev, "BAD: v2p_rx_bad_dup_frag from vsi_rel_id(%d)\n", vsi_rel_id);

		goto bad_case;
	}

	/* if any previous missing? --- don't allow out of order */
	if (!bitmap_full(rx_msg_buf->rx_frag_bitmap, (frag_seq + 1))) {
		pf->msgbox_cb.stats.v2p_rx_bad_miss_frag++;

		if (nse_msgbox_verbose)
			dev_info(dev, "BAD: v2p_rx_bad_miss_frag from vsi_rel_id(%d)\n",
				 vsi_rel_id);

		goto bad_case;
	}

	/* save frag data from _buf[4] */
	cur_frag_buf = (u32 *)(rx_msg_buf->msg_buf + (frag_seq * NSE_MSGBOX_MSG_FRAG_LEN));

	for (i = 0; i < 4; i++)
		cur_frag_buf[i] = rd32(hw, NSE_REG_V2P_DNBUF(vsi_rel_id, i));

	/* receive last frag of a msg */
	if (frag_flag == NSE_MSGBOX_MSG_FRAG_FLAG_LAST)
		rx_msg_buf->rx_msg_len = (frag_seq + 1) * NSE_MSGBOX_MSG_FRAG_LEN;

	/* Make sure the fragment buffer above is read before the VLD bit
	 * is cleared.
	 */
	wmb();

	/* Clear VLD, let VSI to send the next */
	wr32(hw, NSE_REG_V2P_DNCTL(vsi_rel_id), 0);

	nse_flush(hw);

	/* receive last and all frag of a msg, then do actual handling */
	if (frag_flag == NSE_MSGBOX_MSG_FRAG_FLAG_LAST)
		ret = 1;

	return ret;

bad_case:
	/* Clear VLD, let VSI to send the next */
	wr32(hw, NSE_REG_V2P_DNCTL(vsi_rel_id), 0);

	nse_flush(hw);

	v2p_rx_flush_previous(rx_msg_buf);

	ret = 2;

	return ret;
}

void v2p_rx_frags(struct nse_pf *pf, u16 vsi_rel_id, struct nse_rq_event_info *event)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_msgbox_rx_msg_buf *rx_msg_buf = &pf->msgbox_cb.v2p_rx_msg_buf[vsi_rel_id];
	u32 v2p_dnctl;
	unsigned int rx_next_frag_timeout;
	unsigned int rx_next_frag_timeout_limit = (nse_msgbox_rx_frag_timeout * nse_timeout_scale);
	int one_frag_ret;

	mutex_lock(&pf->msgbox_cb.v2p_mutex[vsi_rel_id]);

	v2p_dnctl = rd32(hw, NSE_REG_V2P_DNCTL(vsi_rel_id));

	if (!(v2p_dnctl & NSE_REG_V2P_DNCTL_VLD_M))
		goto out;

	if (nse_is_regval_reset_magic(v2p_dnctl) || nse_is_reset_in_progress(pf->state)) {
		nse_debug(hw, NSE_DBG_SYS, "[%s, %d] reset detected\n", __func__, __LINE__);
		goto out;
	}

	do {
		one_frag_ret = v2p_rx_one_frag(pf, vsi_rel_id, v2p_dnctl);

		/*  if one_frag_ret == 0, then non-last frag, more frags probably comes in short
		 * time.
		 *
		 *  if one_frag_ret == 1, then last frag of a msg, no more msg frags to come in
		 * short time
		 * so we handle this msg and then break.
		 */
		if (one_frag_ret == 0) {
			for (rx_next_frag_timeout =
		0; rx_next_frag_timeout < rx_next_frag_timeout_limit; rx_next_frag_timeout++) {
				usleep_range(nse_msgbox_frag_timeout_tick,
					     (nse_msgbox_frag_timeout_tick << 1));

				v2p_dnctl = rd32(hw, NSE_REG_V2P_DNCTL(vsi_rel_id));

				/*  next frag arrives, break this for wait loop, and continue
				 * external loop for v2p_rx_one_frag() to receive next frag
				 */
				if (v2p_dnctl & NSE_REG_V2P_DNCTL_VLD_M)
					break;

				if (nse_is_regval_reset_magic(v2p_dnctl) ||
				    nse_is_reset_in_progress(pf->state)) {
					nse_debug(hw, NSE_DBG_SYS, "[%s, %d] reset detected\n",
						  __func__, __LINE__);

					v2p_rx_flush_previous(rx_msg_buf);

					goto out;
				}
			}

			if (rx_next_frag_timeout >= rx_next_frag_timeout_limit) {
				if (nse_msgbox_verbose)
					nse_debug(hw, NSE_DBG_SYS, "[%s, %d] rx_next_frag timeout, vsi_rel_id=%d\n",
						  __func__, __LINE__, vsi_rel_id);
				goto out;
			}

		} else if (one_frag_ret == 1) {
			v2p_rx_handle_msg(pf, vsi_rel_id, event);

		} else {
			if (nse_msgbox_verbose)
				dev_info(nse_pf_to_dev(pf),
					 "BAD case in v2p_rx_one_frag(vsi_rel_id=%d)\n",
					vsi_rel_id);
		}

	} while (one_frag_ret == 0);

out:
	mutex_unlock(&pf->msgbox_cb.v2p_mutex[vsi_rel_id]);
}

void nse_msgbox_clean_v2p_subtask(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	u16 vsi_rel_id;
	struct nse_rq_event_info event;
	u32 bm_reg_cnt = ((u32)pf->vsi_space_size + 31) / 32;
	u32 bm_regval;
	u32 i, j;

	if (!nse_is_hw_static_fea_set(&pf->hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_VIRTIO))
		return;

	/* allocate once, use it in this whole thread... */
	memset(&event, 0, sizeof(event));
	event.buf_len = NSE_MSGBOX_MSG_MAX_LEN;
	event.msg_buf = kzalloc(event.buf_len, GFP_KERNEL);
	if (!event.msg_buf)
		return;

	for (i = 0; i < bm_reg_cnt; i++) {
		bm_regval = rd32(hw, NSE_REG_DNCTL_STATUS(i));

		if (!bm_regval)
			continue;

		/* tip: VSI-0 (rel ID) PF-main-VSI never use msgbox */
		if (nse_is_regval_reset_magic(bm_regval))
			break;

		for (j = 0; j < 32; j++) {
			if (bm_regval & BIT(j)) {
				vsi_rel_id = (32 * i) + j;

				if (vsi_rel_id >= pf->vsi_space_size)
					goto out;

				v2p_rx_frags(pf, vsi_rel_id, &event);
			}
		}
	}

out:
	kfree(event.msg_buf);
}

void nse_msgbox_dis_interrupt(struct nse_hw *hw)
{
	if (!nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_VIRTIO))
		return;

	/* VLD = 0 */
	wr32(hw, NSE_REG_V2P_DNINT, 0);

	nse_flush(hw);
}

void nse_msgbox_ena_interrupt(struct nse_hw *hw, u32 reg_idx)
{
	u32 val;

	if (!nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_VIRTIO))
		return;

	/* bind and enable V2P as irq-source */
	val = NSE_REG_V2P_DNINT_VLD_M |
			(reg_idx << NSE_REG_V2P_DNINT_MSIX_IDX_S);

	wr32(hw, NSE_REG_V2P_DNINT, val);

	nse_flush(hw);
}

static ssize_t dbgfs_msgbox_params_rfunc(struct file *filp,
				 char __user *to, size_t count, loff_t *ppos)
{
	char *buf = NULL;
	int desc = 0;
	int ret;

	buf = kzalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	desc += sprintf(buf + desc, "verbose: %d\n",
		nse_msgbox_verbose);

	desc += sprintf(buf + desc, "tx_clear_first: %d\n",
		nse_msgbox_tx_clear_first);

	desc += sprintf(buf + desc, "frag_timeout_tick: %d\n",
		nse_msgbox_frag_timeout_tick);

	desc += sprintf(buf + desc, "tx_frag_timeout: %d\n",
		nse_msgbox_tx_frag_timeout);

	desc += sprintf(buf + desc, "rx_frag_timeout: %d\n",
		nse_msgbox_rx_frag_timeout);

	ret = simple_read_from_buffer(to, count, ppos, buf, desc);

	kfree(buf);

	return ret;
}

static ssize_t
dbgfs_msgbox_params_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int new_val;

	if (*ppos != 0)
		return 0;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc < 2)
		goto bad_usage;

	if (kstrtouint(argv[1], 10, &new_val))
		goto bad_usage;

	if (!new_val)
		goto bad_usage;

	if (!strcmp(argv[0], "verbose"))
		nse_msgbox_verbose = new_val;
	else if (!strcmp(argv[0], "tx_clear_first"))
		nse_msgbox_tx_clear_first = new_val;
	else if (!strcmp(argv[0], "frag_timeout_tick"))
		nse_msgbox_frag_timeout_tick = new_val;
	else if (!strcmp(argv[0], "tx_frag_timeout"))
		nse_msgbox_tx_frag_timeout = new_val;
	else if (!strcmp(argv[0], "rx_frag_timeout"))
		nse_msgbox_rx_frag_timeout = new_val;
	else
		goto bad_usage;

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations dbgfs_msgbox_params_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read = dbgfs_msgbox_params_rfunc,
	.write = dbgfs_msgbox_params_wfunc,
	.llseek = default_llseek,
};

static ssize_t dbgfs_msgbox_stats_rfunc(struct file *filp,
				 char __user *to, size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	char *buf = NULL;
	int desc = 0;
	int ret;

	buf = kzalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	desc += sprintf(buf + desc, "v2p_rx_bad_dup_frag: %ld\n",
		pf->msgbox_cb.stats.v2p_rx_bad_dup_frag);

	desc += sprintf(buf + desc, "v2p_rx_bad_miss_frag: %ld\n",
		pf->msgbox_cb.stats.v2p_rx_bad_miss_frag);

	desc += sprintf(buf + desc, "p2v_tx_send_wait_cnt: %ld\n",
		pf->msgbox_cb.stats.p2v_tx_send_wait_cnt);

	desc += sprintf(buf + desc, "p2v_tx_send_timeout_cnt: %ld\n",
		pf->msgbox_cb.stats.p2v_tx_send_timeout_cnt);

	ret = simple_read_from_buffer(to, count, ppos, buf, desc);

	kfree(buf);

	return ret;
}

static ssize_t
dbgfs_msgbox_stats_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc != 1)
		goto bad_usage;

	memset(&pf->msgbox_cb.stats, 0, sizeof(pf->msgbox_cb.stats));

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations dbgfs_msgbox_stats_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read = dbgfs_msgbox_stats_rfunc,
	.write = dbgfs_msgbox_stats_wfunc,
	.llseek = default_llseek,
};

static ssize_t
dbgfs_msgbox_p2v_send_msg_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u16 vsi_rel_id;
	unsigned int msg_len;
	char *msg = NULL;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc < 2)
		goto bad_usage;

	if (kstrtou16(argv[0], 10, &vsi_rel_id))
		goto bad_usage;

	if (vsi_rel_id >= pf->vsi_space_size)
		goto bad_usage;

	if (kstrtouint(argv[1], 10, &msg_len))
		goto bad_usage;

	if (msg_len > NSE_MSGBOX_MSG_MAX_LEN)
		goto bad_usage;

	msg = kmalloc(msg_len, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto command_write_done;
	}

	get_random_bytes(msg, msg_len);

	ret = nse_msgbox_p2v_send_msg(pf, vsi_rel_id, msg, msg_len, MSG_MSGBOX_MSG_TYPE_EVENT);

	if (ret)
		dev_err(dev, "FAIL: p2v_send_msg(vsi_rel_id=%d, msg_len=%d)\n",
			vsi_rel_id, msg_len);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	kfree(msg);

	return ret;

bad_usage:
	dev_info(dev, "echo 'vsi_rel_id msg_len' for p2v_send_msg\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations dbgfs_msgbox_p2v_send_msg_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = dbgfs_msgbox_p2v_send_msg_wfunc,
	.llseek = default_llseek,
};

void nse_msgbox_debugfs_init(struct nse_pf *pf)
{
	if (!nse_is_hw_static_fea_set(&pf->hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_VIRTIO))
		return;

	if (pf->pf_dbgfs_dir) {
		(void)debugfs_create_file("msgbox_params", 0600, pf->pf_dbgfs_dir,
					  pf, &dbgfs_msgbox_params_fops);
		(void)debugfs_create_file("msgbox_stats", 0600, pf->pf_dbgfs_dir,
					  pf, &dbgfs_msgbox_stats_fops);
		(void)debugfs_create_file("msgbox_p2v_send_msg", 0600, pf->pf_dbgfs_dir,
					  pf, &dbgfs_msgbox_p2v_send_msg_fops);
	}
}

int nse_msgbox_init(struct nse_pf *pf)
{
	int i = 0;
	struct nse_msgbox_rx_msg_buf *rx_msg_buf = NULL;

	/* no need to use msgbox */
	if (!nse_is_hw_static_fea_set(&pf->hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_VIRTIO))
		return 0;

	/* don't use pf->vsi_space_size, because it may not set at early init time */
	for (i = 0; i < NSE_MAX_VSI; i++) {
		mutex_init(&pf->msgbox_cb.p2v_mutex[i]);
		mutex_init(&pf->msgbox_cb.v2p_mutex[i]);

		rx_msg_buf = &pf->msgbox_cb.v2p_rx_msg_buf[i];

		rx_msg_buf->msg_buf = kzalloc(NSE_MSGBOX_MSG_MAX_LEN, GFP_KERNEL);
		if (!rx_msg_buf->msg_buf)
			return -ENOMEM;
	}

	return 0;
}

void nse_msgbox_exit(struct nse_pf *pf)
{
	int i = 0;
	struct nse_msgbox_rx_msg_buf *rx_msg_buf = NULL;

	if (!nse_is_hw_static_fea_set(&pf->hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_VIRTIO))
		return;

	for (i = 0; i < NSE_MAX_VSI; i++) {
		mutex_destroy(&pf->msgbox_cb.p2v_mutex[i]);
		mutex_destroy(&pf->msgbox_cb.v2p_mutex[i]);

		rx_msg_buf = &pf->msgbox_cb.v2p_rx_msg_buf[i];

		kfree(rx_msg_buf->msg_buf);

		rx_msg_buf->msg_buf = NULL;
	}
}

/* clear all VLD of registers */
void nse_msgbox_reset(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	int i = 0;

	if (!nse_is_hw_static_fea_set(&pf->hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_VIRTIO))
		return;

	for (i = 0; i < pf->vsi_space_size; i++) {
		mutex_lock(&pf->msgbox_cb.p2v_mutex[i]);
		wr32(hw, NSE_REG_P2V_UPCTL(i), 0);
		mutex_unlock(&pf->msgbox_cb.p2v_mutex[i]);

		mutex_lock(&pf->msgbox_cb.v2p_mutex[i]);
		wr32(hw, NSE_REG_V2P_DNCTL(i), 0);
		v2p_rx_flush_previous(&pf->msgbox_cb.v2p_rx_msg_buf[i]);
		mutex_unlock(&pf->msgbox_cb.v2p_mutex[i]);
	}

	memset(&pf->msgbox_cb.stats, 0, sizeof(pf->msgbox_cb.stats));
}

