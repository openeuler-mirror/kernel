// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nsevf.h"

#include <linux/bitmap.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/slab.h>

#include "nsevf_msgbox.h"
#include "nsevf_adminq.h"
#include "virtchnl.h"

static unsigned int nse_msgbox_verbose; /* for debug */

static unsigned int nse_msgbox_tx_clear_first = 1;

static unsigned int nse_msgbox_frag_timeout_tick = 100; /* 100 us = 0.1 ms */
static unsigned int nse_msgbox_tx_frag_timeout =
	2000; /* 0.1 ms * 2000 = 200 ms */
static unsigned int nse_msgbox_rx_frag_timeout = 200; /* 0.1 ms * 100 = 20 ms */

static void v2p_send_one_frag(struct nsevf_hw *hw, u32 *cur_frag, u32 frag_seq,
			      u32 frag_flag)
{
	u32 ctl;
	u32 i;

	ctl = NSEVF_REG_V2P_DNCTL_VLD_M |
	      (frag_flag << NSE_MSGBOX_MSG_FRAG_FLAG_S) |
	      (frag_seq << NSE_MSGBOX_MSG_FRAG_SEQ_S);

	for (i = 0; i < 4; i++)
		wr32(hw, NSEVF_REG_V2P_DNBUF(i), cur_frag[i]);

	/* Publish fragment data before notifying the peer. */
	mb();

	wr32(hw, NSEVF_REG_V2P_DNCTL, ctl);

	nsevf_flush(hw);

	usleep_range(nse_msgbox_frag_timeout_tick,
		     (nse_msgbox_frag_timeout_tick
		      << 1)); /* sleep a while for VSI to RX. */
}

enum nsevf_status nsevf_msgbox_v2p_send_msg(struct nsevf_adapter *adapter,
					    char *msg, unsigned int msg_len)
{
	struct nsevf_hw *hw = &adapter->hw;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	u32 *cur_frag = NULL;
	u32 frag_seq, frag_cnt;
	u32 frag_flag;
	unsigned int frag_send_timeout;
	unsigned int frag_send_timeout_limit =
		(nse_msgbox_tx_frag_timeout * nse_timeout_scale);
	u32 reg;
	enum nsevf_status ret = 0;

	if (!msg || msg_len > NSE_MSGBOX_MSG_MAX_LEN)
		return NSEVF_ERR_PARAM;

	frag_cnt = DIV_ROUND_UP(msg_len, NSE_MSGBOX_MSG_FRAG_LEN);

	if (nse_msgbox_verbose) {
		dev_info(dev,
			 "VF msgbox V2P_TX: send a msg to PF, frag_cnt=%d, msg_len(in bytes)=%d\n",
			frag_cnt, msg_len);
		dev_info(dev, "msg content:\n");

		cur_frag = (u32 *)msg;

		for (frag_seq = 0; frag_seq < frag_cnt; frag_seq++) {
			dev_info(dev, "\t %08X %08X %08X %08X\n", cur_frag[0],
				 cur_frag[1], cur_frag[2], cur_frag[3]);

			cur_frag += 4;
		}
	}

	mutex_lock(&adapter->msgbox_cb.v2p_mutex);

	if (nse_msgbox_tx_clear_first)
		wr32(hw, NSEVF_REG_V2P_DNCTL, 0);

	for (frag_seq = 0; frag_seq < frag_cnt; frag_seq++) {
		cur_frag = (u32 *)(msg + (frag_seq * NSE_MSGBOX_MSG_FRAG_LEN));

		for (frag_send_timeout = 0;
		     frag_send_timeout < frag_send_timeout_limit;
		     frag_send_timeout++) {
			reg = rd32(hw, NSEVF_REG_V2P_DNCTL);

			if (reg & NSEVF_REG_V2P_DNCTL_VLD_M) {
				adapter->msgbox_cb.stats.v2p_tx_send_wait_cnt++;
				usleep_range(nse_msgbox_frag_timeout_tick,
					     (nse_msgbox_frag_timeout_tick
					      << 1));
			} else {
				break;
			}
		}

		if (frag_send_timeout >= frag_send_timeout_limit) {
			ret = NSEVF_ERR_TIMEOUT;
			adapter->msgbox_cb.stats.v2p_tx_send_timeout_cnt++;
			goto out;
		}

		if (frag_seq == (frag_cnt - 1))
			frag_flag = NSE_MSGBOX_MSG_FRAG_FLAG_LAST;
		else
			frag_flag = NSE_MSGBOX_MSG_FRAG_FLAG_MORE;

		v2p_send_one_frag(hw, cur_frag, frag_seq, frag_flag);
	}

	ret = NSEVF_SUCCESS;

out:
	mutex_unlock(&adapter->msgbox_cb.v2p_mutex);

	return ret;
}

/* msgbox version of nsevf_aq_send_msg_to_pf() */
enum nsevf_status
nse_msgbox_v2p_send_msg_to_pf(struct nsevf_hw *hw, enum virtchnl_ops v_opcode,
			      enum virtchnl_status_code v_retval, u8 *msg,
			      u16 msglen)
{
	struct nsevf_adapter *adapter = (struct nsevf_adapter *)hw->back;
	void *cbuf = NULL;
	size_t cbuf_len = sizeof(struct nse_aqc_mbx_cmd_buff_hdr) + msglen;
	struct nse_aqc_mbx_cmd_buff_hdr *hdr = NULL;
	enum nsevf_status status;

	cbuf = devm_kzalloc(nsevf_hw_to_dev(hw), cbuf_len, GFP_KERNEL);
	if (!cbuf)
		return NSEVF_ERR_NO_MEMORY;

	/* set hdr */
	hdr = (struct nse_aqc_mbx_cmd_buff_hdr *)cbuf;
	hdr->cookie_high = cpu_to_le32(v_opcode);
	hdr->cookie_low = cpu_to_le32(v_retval);

	if (msglen)
		memcpy(cbuf + sizeof(struct nse_aqc_mbx_cmd_buff_hdr), msg,
		       msglen);

	status = nsevf_msgbox_v2p_send_msg(adapter, cbuf, cbuf_len);

	devm_kfree(nsevf_hw_to_dev(hw), cbuf);

	return status;
}

static void p2v_rx_flush_previous(struct nsevf_msgbox_rx_msg_buf *rx_msg_buf)
{
	/* no need: memset(msg_buf->rx_msg_buf, 0) */

	rx_msg_buf->rx_msg_len = 0;

	bitmap_clear(rx_msg_buf->rx_frag_bitmap, 0,
		     NSE_MSGBOX_MSG_FRAG_MAX_CNT);
}

static int p2v_rx_one_frag(struct nsevf_adapter *adapter, u32 p2v_upctl)
{
	struct device *dev = nsevf_adapter_to_dev(adapter);
	struct nsevf_hw *hw = &adapter->hw;
	struct nsevf_msgbox_rx_msg_buf *rx_msg_buf =
		&adapter->msgbox_cb.p2v_rx_msg_buf;
	u32 *cur_frag_buf = NULL;
	u32 frag_seq, frag_flag, msg_type;
	int i;
	int ret = 0;

	frag_seq = (p2v_upctl & NSE_MSGBOX_MSG_FRAG_SEQ_M) >>
		   NSE_MSGBOX_MSG_FRAG_SEQ_S;
	frag_flag = (p2v_upctl & NSE_MSGBOX_MSG_FRAG_FLAG_M) >>
		    NSE_MSGBOX_MSG_FRAG_FLAG_S;
	msg_type = (p2v_upctl & MSG_MSGBOX_MSG_TYPE_M) >> MSG_MSGBOX_MSG_TYPE_S;

	if (nse_msgbox_verbose)
		dev_info(dev,
			 "[%s, %d] rx one frag from PF, p2v_upctl=%X (frag_seq=%d, frag_flag=%d)\n",
			__func__, __LINE__, p2v_upctl, frag_seq, frag_flag);

	/* receive frag #0, flush any previous, start a new session. */
	if (!frag_seq)
		p2v_rx_flush_previous(rx_msg_buf);

	/* already rx this frag_seq? */
	if (test_and_set_bit(frag_seq, rx_msg_buf->rx_frag_bitmap)) {
		adapter->msgbox_cb.stats.p2v_rx_bad_dup_frag++;

		if (nse_msgbox_verbose)
			dev_info(dev, "BAD: p2v_rx_bad_dup_frag\n");

		goto bad_case;
	}

	/* if any previous missing? --- don't allow out of order */
	if (!bitmap_full(rx_msg_buf->rx_frag_bitmap, (frag_seq + 1))) {
		adapter->msgbox_cb.stats.p2v_rx_bad_miss_frag++;

		if (nse_msgbox_verbose)
			dev_info(dev, "BAD: p2v_rx_bad_miss_frag\n");

		goto bad_case;
	}

	rx_msg_buf->msg_type = msg_type;

	/* save frag data from _buf[4] */
	cur_frag_buf = (u32 *)(rx_msg_buf->msg_buf +
			       frag_seq * NSE_MSGBOX_MSG_FRAG_LEN);

	for (i = 0; i < 4; i++)
		cur_frag_buf[i] = rd32(hw, NSEVF_REG_P2V_UPBUF(i));

	/* receive last frag of a msg */
	if (frag_flag == NSE_MSGBOX_MSG_FRAG_FLAG_LAST)
		rx_msg_buf->rx_msg_len =
			(frag_seq + 1) * NSE_MSGBOX_MSG_FRAG_LEN;

	/* Consume fragment data before releasing the mailbox slot. */
	mb();

	/* Clear VLD, let VSI to send the next */
	wr32(hw, NSEVF_REG_P2V_UPCTL, 0);

	/* receive last and all frag of a msg, then do actual handling */
	if (frag_flag == NSE_MSGBOX_MSG_FRAG_FLAG_LAST)
		ret = 1;

	return ret;

bad_case:
	/* Clear VLD, let VSI to send the next */
	wr32(hw, NSEVF_REG_P2V_UPCTL, 0);

	p2v_rx_flush_previous(rx_msg_buf);

	ret = 2;

	return ret;
}

static void msgbox_p2v_dump_msg(struct nsevf_adapter *adapter, u8 *msg,
				u16 msglen)
{
	struct device *dev = nsevf_adapter_to_dev(adapter);
	u32 *cur_frag = (u32 *)msg;
	u32 frag_cnt = DIV_ROUND_UP(msglen, NSE_MSGBOX_MSG_FRAG_LEN);
	u32 i;

	dev_info(dev, "VF msgbox P2V_RX: receive msg from PF, content:\n");

	for (i = 0; i < frag_cnt; i++) {
		dev_info(dev, "\t %08X %08X %08X %08X\n", cur_frag[0],
			 cur_frag[1], cur_frag[2], cur_frag[3]);

		cur_frag += 4;
	}
}

static enum nsevf_status p2v_rx_frags(struct nsevf_adapter *adapter,
				      struct nsevf_arq_event_info *e)
{
	struct nsevf_hw *hw = &adapter->hw;
	struct nsevf_msgbox_rx_msg_buf *rx_msg_buf =
		&adapter->msgbox_cb.p2v_rx_msg_buf;
	u32 p2v_upctl;
	int one_frag_ret;
	unsigned int rx_next_frag_timeout;
	unsigned int rx_next_frag_timeout_limit =
		(nse_msgbox_rx_frag_timeout * nse_timeout_scale);
	enum nsevf_status ret = NSEVF_ERR_ADMIN_QUEUE_NO_WORK;

	mutex_lock(&adapter->msgbox_cb.p2v_mutex);

	p2v_upctl = rd32(hw, NSEVF_REG_P2V_UPCTL);

	if (!(p2v_upctl & NSEVF_REG_P2V_UPCTL_VLD_M))
		goto out;

	if (nsevf_is_regval_reset_magic(p2v_upctl) ||
	    adapter->state == __NSEVF_RESETTING) {
		nsevf_debug(hw, NSEVF_DBG_SYS, "[%s, %d] reset detected\n",
			    __func__, __LINE__);
		goto out;
	}

	do {
		one_frag_ret = p2v_rx_one_frag(adapter, p2v_upctl);

		/* A zero return means more fragments may arrive shortly.
		 *
		 * A return of one identifies the final fragment.
		 * so we handle this msg and then break.
		 */
		if (one_frag_ret == 0) {
			for (rx_next_frag_timeout = 0;
			     rx_next_frag_timeout < rx_next_frag_timeout_limit;
			     rx_next_frag_timeout++) {
				usleep_range(nse_msgbox_frag_timeout_tick,
					     (nse_msgbox_frag_timeout_tick
					      << 1));

				p2v_upctl = rd32(hw, NSEVF_REG_P2V_UPCTL);

				/* Let the outer loop receive the next fragment. */
				if (p2v_upctl & NSEVF_REG_P2V_UPCTL_VLD_M)
					break;

				if (nsevf_is_regval_reset_magic(p2v_upctl) ||
				    adapter->state == __NSEVF_RESETTING) {
					nsevf_debug(hw, NSEVF_DBG_SYS,
						    "[%s, %d] reset detected\n",
						    __func__, __LINE__);

					p2v_rx_flush_previous(rx_msg_buf);

					goto out;
				}
			}

			if (rx_next_frag_timeout >=
			    rx_next_frag_timeout_limit) {
				if (nse_msgbox_verbose)
					nsevf_debug(hw, NSEVF_DBG_SYS,
						    "[%s, %d] rx_next_frag timeout\n",
						__func__, __LINE__);
				goto out;
			}

			/* The next fragment is already valid (p2v_upctl
			 * was re-read above), go back and receive it.
			 */
			continue;
		}

		if (one_frag_ret == 1) {
			e->msg_len = min_t(u16, e->buf_len,
					   adapter->msgbox_cb.p2v_rx_msg_buf.rx_msg_len);
			memcpy(e->msg_buf,
			       adapter->msgbox_cb.p2v_rx_msg_buf.msg_buf,
			       e->msg_len);

			e->msg_type =
				adapter->msgbox_cb.p2v_rx_msg_buf.msg_type;

			if (nse_msgbox_verbose)
				msgbox_p2v_dump_msg(adapter, e->msg_buf,
						    e->msg_len);

			ret = NSEVF_SUCCESS;

			break;
		}

		if (nse_msgbox_verbose)
			dev_info(nsevf_adapter_to_dev(adapter),
				 "BAD case in p2v_rx_one_frag\n");

		ret = NSEVF_ERR_INVALID_FRAG_COUNT;
		break;

	} while (one_frag_ret == 0);

out:
	mutex_unlock(&adapter->msgbox_cb.p2v_mutex);

	return ret;
}

/* msgbox version of nsevf_clean_arq_element() */
/* this is gonna be inserted into nsevf_adminq_task(), to rx from P2V msgbox */
enum nsevf_status nsevf_msgbox_p2v_clean_rx(struct nsevf_hw *hw,
					    struct nsevf_arq_event_info *e,
					    u16 __always_unused *pending)
{
	struct nsevf_adapter *adapter = (struct nsevf_adapter *)hw->back;

	return p2v_rx_frags(adapter, e);
}

/* msgbox version of nsevf_poll_virtchnl_msg() */
int nsevf_msgbox_p2v_poll_virtchnl_msg(struct nsevf_hw *hw,
				       struct nsevf_arq_event_info *event,
				       enum virtchnl_ops op_to_poll)
{
	struct nsevf_adapter *adapter = (struct nsevf_adapter *)hw->back;
	struct nse_aqc_mbx_cmd_buff_hdr *v_hdr = NULL;
	enum virtchnl_ops received_op;
	enum nsevf_status status;
	u32 v_retval;

	while (1) {
		event->vch_msg_content = NULL;
		event->vch_msg_len = 0;

		/* When the AQ is empty, nsevf_clean_arq_element will return
		 * NSEVF_ERR_AQ_NO_WORK and this loop will terminate. Callers
		 * which want to wait until a new message is received should
		 * check for -EALREADY and repeat polling attempts.
		 */
		status = p2v_rx_frags(adapter, event);
		if (status)
			return nsevf_status_to_errno(status);

		if (event->msg_len < sizeof(struct nse_aqc_mbx_cmd_buff_hdr))
			continue; /* invalid vch-msg, ignore it, and check the next one */

		event->vch_msg_content =
			event->msg_buf +
			sizeof(struct nse_aqc_mbx_cmd_buff_hdr);
		event->vch_msg_len = event->msg_len -
				     sizeof(struct nse_aqc_mbx_cmd_buff_hdr);

		v_hdr = (struct nse_aqc_mbx_cmd_buff_hdr *)event->msg_buf;

		received_op =
			(enum virtchnl_ops)le32_to_cpu(v_hdr->cookie_high);
		if (op_to_poll == received_op)
			break;
	}

	v_retval = le32_to_cpu(v_hdr->cookie_low);
	return virtchnl_status_to_errno((enum virtchnl_status_code)v_retval);
}

static ssize_t dbgfs_msgbox_params_rfunc(struct file *filp, char __user *to,
					 size_t count, loff_t *ppos)
{
	char *buf = NULL;
	int desc = 0;
	int ret;

	buf = kzalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	desc += sprintf(buf + desc, "verbose: %d\n", nse_msgbox_verbose);

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

static ssize_t dbgfs_msgbox_params_wfunc(struct file *filp,
					 const char __user *buf, size_t count,
					 loff_t *ppos)
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
	.open = simple_open,
	.read = dbgfs_msgbox_params_rfunc,
	.write = dbgfs_msgbox_params_wfunc,
	.llseek = default_llseek,
};

static ssize_t dbgfs_msgbox_stats_rfunc(struct file *filp, char __user *to,
					size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	char *buf = NULL;
	int desc = 0;
	int ret;

	buf = kzalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	desc += sprintf(buf + desc, "p2v_rx_bad_dup_frag: %ld\n",
			adapter->msgbox_cb.stats.p2v_rx_bad_dup_frag);

	desc += sprintf(buf + desc, "p2v_rx_bad_miss_frag: %ld\n",
			adapter->msgbox_cb.stats.p2v_rx_bad_miss_frag);

	desc += sprintf(buf + desc, "v2p_tx_send_wait_cnt: %ld\n",
			adapter->msgbox_cb.stats.v2p_tx_send_wait_cnt);

	desc += sprintf(buf + desc, "v2p_tx_send_timeout_cnt: %ld\n",
			adapter->msgbox_cb.stats.v2p_tx_send_timeout_cnt);

	ret = simple_read_from_buffer(to, count, ppos, buf, desc);

	kfree(buf);

	return ret;
}

static ssize_t dbgfs_msgbox_stats_wfunc(struct file *filp,
					const char __user *buf, size_t count,
					loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
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

	memset(&adapter->msgbox_cb.stats, 0, sizeof(adapter->msgbox_cb.stats));

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
	.open = simple_open,
	.read = dbgfs_msgbox_stats_rfunc,
	.write = dbgfs_msgbox_stats_wfunc,
	.llseek = default_llseek,
};

static ssize_t dbgfs_msgbox_v2p_send_msg_wfunc(struct file *filp,
					       const char __user *buf,
					       size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
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

	if (argc < 1)
		goto bad_usage;

	if (kstrtouint(argv[0], 10, &msg_len))
		goto bad_usage;

	if (msg_len > NSE_MSGBOX_MSG_MAX_LEN)
		goto bad_usage;

	msg = kmalloc(msg_len, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto command_write_done;
	}

	get_random_bytes(msg, msg_len);

	ret = nsevf_msgbox_v2p_send_msg(adapter, msg, msg_len);

	if (ret)
		dev_err(dev, "FAIL: v2p_send_msg(msg_len=%d)\n", msg_len);

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
	dev_info(dev, "echo 'msg_len' for v2p_send_msg\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations dbgfs_msgbox_v2p_send_msg_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = dbgfs_msgbox_v2p_send_msg_wfunc,
	.llseek = default_llseek,
};

void nsevf_msgbox_debugfs_init(struct nsevf_adapter *adapter)
{
	if (adapter->vf_dbgfs_dir) {
		(void)debugfs_create_file("msgbox_params", 0600,
					  adapter->vf_dbgfs_dir, adapter,
					  &dbgfs_msgbox_params_fops);
		(void)debugfs_create_file("msgbox_stats", 0600,
					  adapter->vf_dbgfs_dir, adapter,
					  &dbgfs_msgbox_stats_fops);
		(void)debugfs_create_file("msgbox_v2p_send_msg", 0600,
					  adapter->vf_dbgfs_dir, adapter,
					  &dbgfs_msgbox_v2p_send_msg_fops);
	}
}

int nsevf_msgbox_init(struct nsevf_adapter *adapter)
{
	mutex_init(&adapter->msgbox_cb.p2v_mutex);
	mutex_init(&adapter->msgbox_cb.v2p_mutex);

	adapter->msgbox_cb.p2v_rx_msg_buf.msg_buf =
		kzalloc(NSE_MSGBOX_MSG_MAX_LEN, GFP_KERNEL);
	if (!adapter->msgbox_cb.p2v_rx_msg_buf.msg_buf)
		return -ENOMEM;

	return 0;
}

void nsevf_msgbox_exit(struct nsevf_adapter *adapter)
{
	kfree(adapter->msgbox_cb.p2v_rx_msg_buf.msg_buf);

	adapter->msgbox_cb.p2v_rx_msg_buf.msg_buf = NULL;

	mutex_destroy(&adapter->msgbox_cb.p2v_mutex);
	mutex_destroy(&adapter->msgbox_cb.v2p_mutex);
}

enum nsevf_status nsevf_msgbox_init_mailboxq(struct nsevf_hw *hw)
{
	enum nsevf_status ret_code = 0;
	u32 reg = 0;

	wr32(hw, hw->mailboxq.arq.bal,
	     NSEVF_REG_VMBX_ARQBAL_MAGIC_VF_MSGBOX_INIT);

	/* Check one register to verify that config was applied */
	reg = rd32(hw, hw->mailboxq.arq.bal);
	if (reg != NSEVF_REG_VMBX_ARQBAL_MAGIC_VF_MSGBOX_INIT)
		ret_code = NSEVF_ERR_ADMIN_QUEUE_ERROR;

	return ret_code;
}
