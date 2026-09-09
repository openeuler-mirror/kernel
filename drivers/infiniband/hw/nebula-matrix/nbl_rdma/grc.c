// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include "grc.h"
#include "uds_client.h"

static void grc_dwork_check_result(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct nbl_grc_work_ent *ent =
		container_of(dwork, struct nbl_grc_work_ent, dwork);
	int ret;
	u8 *cmd_out;

	ret = nbl_uds_get_resp_from_grc(ent->grc, ent->out, ent->out_size);
	if (ret) {
		nbl_pr_err("get resp from grc uds err=%d", ret);
		ent->ret = -EAGAIN;
		complete(&ent->done);
		return;
	}

	cmd_out = (u8 *)ent->out;
	ent->ret = cmd_out[0];
	if (ent->ret)
		nbl_pr_err("grc recv cmd out with error=%d", ent->ret);

	complete(&ent->done);
}

static void grc_work_handler(struct work_struct *work)
{
	struct nbl_grc_work_ent *ent =
		container_of(work, struct nbl_grc_work_ent, work);
	struct nbl_grc *grc = ent->grc;
	int ret;

	/* work handler is being called */
	complete(&ent->handling);

	ret = nbl_uds_send_msg_to_grc(grc, ent->in, ent->in_size);
	if (ret) {
		nbl_pr_err("send req to grc uds err=%d", ret);
		ent->ret = -EAGAIN;
		complete(&ent->done);
		return;
	}

	INIT_DELAYED_WORK(&ent->dwork, grc_dwork_check_result);
	queue_delayed_work(grc->wq, &ent->dwork, msecs_to_jiffies(NBL_GRC_TIMEOUT_MSEC));
}

static int wait_func(struct nbl_grc_work_ent *ent)
{
	unsigned long timeout = msecs_to_jiffies(NBL_GRC_WQ_TIMEOUT_MSEC);

	/* wq work handler is not being called, when timeout cancel and return err */
	if (!wait_for_completion_timeout(&ent->handling, timeout) &&
	    cancel_work_sync(&ent->work)) {
		ent->ret = -ECANCELED;
		goto out_err;
	}

	wait_for_completion(&ent->done);

out_err:
	return ent->ret;
}

static int nbl_grc_invoke(struct nbl_pci_f *rf, void *in, int in_size,
			  void *out, int out_size)
{
	struct nbl_grc *grc = &rf->grc;
	struct nbl_grc_work_ent *ent;
	int err = 0;
	u8 *msg_in;

	ent = kzalloc(sizeof(*ent), GFP_KERNEL);
	if (!ent)
		return -ENOMEM;

	ent->grc = grc;
	ent->in = in;
	ent->in_size = in_size;
	ent->out = out;
	ent->out_size = out_size;

	nbl_pr_dbg("send grc cmd. seq_num:%d\n", grc->seq_num);
	msg_in = (u8 *)ent->in;
	msg_in[0] = grc->seq_num++; /* use first byte as seq num */

	init_completion(&ent->handling);
	init_completion(&ent->done);

	INIT_WORK(&ent->work, grc_work_handler);

	if (!queue_work(grc->wq, &ent->work)) {
		nbl_pr_err("grc failed to queue work\n");
		err = -ENOMEM;
		goto out_free;
	}

	err = wait_func(ent);
	if (err != 0)
		nbl_pr_err("grc wait func err\n");

out_free:
	kfree(ent);

	return err;
}

int nbl_grc_exec(struct nbl_pci_f *rf, void *in, int in_size, void *out,
		int out_size)
{
	struct nbl_grc *grc = &rf->grc;
	int err;

	mutex_lock(&grc->grc_mlock);
	err = nbl_grc_invoke(rf, in, in_size, out, out_size);
	mutex_unlock(&grc->grc_mlock);

	return err;
}

int nbl_grc_write_reg(struct nbl_pci_f *rf, u32 offset, u32 var)
{
	uint8_t in[NBL_GRC_INPUT_SIZE];
	uint8_t out[NBL_GRC_OUTPUT_SIZE];
	int data_len = 0;
	int ret;
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_WRITE_REG;
	head->payload_len = sizeof(offset) + sizeof(var);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &offset, sizeof(offset));
	data_len += sizeof(offset);

	memcpy(in + data_len, &var, sizeof(var));
	data_len += sizeof(var);

	ret = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret != 0)
		nbl_pr_err("write reg err=%d offset:%d, var:%d\n", ret, offset, var);

	return ret;
}

int nbl_grc_read_reg(struct nbl_pci_f *rf, u32 offset, u32 *var)
{
	uint8_t in[NBL_GRC_INPUT_SIZE];
	uint8_t out[NBL_GRC_OUTPUT_SIZE];
	uint8_t resp_rst;
	int data_len = 0;
	int ret;
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_READ_REG;
	head->payload_len = sizeof(offset) + sizeof(*var);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &offset, sizeof(offset));
	data_len += sizeof(offset);

	memcpy(in + data_len, var, sizeof(*var));
	data_len += sizeof(var);

	ret = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret != 0)
		nbl_pr_err("read reg err=%d offset:%#x, var:%#x\n", ret, offset, *var);

	/* get operation result */
	memcpy(&resp_rst, out, sizeof(resp_rst));
	if (resp_rst) {
		nbl_pr_err("read reg err=%d offset:%#x, var:%#x\n", ret, offset, *var);
		return -ENODATA;
	}

	memcpy(var, out + 1 + sizeof(offset), sizeof(*var));
	nbl_pr_dbg("read reg OK. offset:%#x var:%#x\n", offset, *var);

	return ret;
}

int nbl_grc_init(struct nbl_pci_f *rf)
{
	struct nbl_grc *grc = &rf->grc;
	int err;

	memset(grc, 0, sizeof(*grc));

	mutex_init(&grc->grc_mlock);

	snprintf(grc->wq_name, sizeof(grc->wq_name), "nbl_grc");
	grc->wq = create_singlethread_workqueue(grc->wq_name);
	if (!grc->wq) {
		nbl_pr_err("failed to create grc workqueue\n");
		err = -ENOMEM;
		goto err_back;
	}

	err = nbl_uds_client_init(grc);
	if (err) {
		nbl_pr_err("failed to init grc unix domain socket\n");
		err = -ENOMEM;
		goto err_free_wq;
	}

	return 0;

err_free_wq:
	destroy_workqueue(grc->wq);
err_back:
	return err;
}

void nbl_grc_exit(struct nbl_pci_f *rf)
{
	destroy_workqueue(rf->grc.wq);
	nbl_uds_client_exit(&rf->grc);
}
