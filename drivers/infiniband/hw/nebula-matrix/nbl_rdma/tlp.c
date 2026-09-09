// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 * Author: lewis.liu <lewis.liu@nebula-matrix.com>
 */
#include "main.h"
#include "tlp.h"

static void tlp_dwork_get_result(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct nbl_tlp_work_ent *ent =
		container_of(dwork, struct nbl_tlp_work_ent, dwork);
	struct nbl_pci_f *rf = container_of(ent->tlp, struct nbl_pci_f, tlp);
	u8 resp_data_len;
	u8 *msg_out = (u8 *)ent->out;
	u8 *msg;
	u8 copy_len = 0;
	u32 val;
	struct tlp_read_msg_header *head;
	u8 i;
	struct grc_cache_msg_header *req_head = (struct grc_cache_msg_header *)ent->in;

	val = readl(rf->hw.hw_addr + RDMA_TLP_WRITE_OFFSET + RDMA_TLP_READ_OFFSET_MIN);
	head = (struct tlp_read_msg_header *)&val;
	resp_data_len = head->msg_len;

	msg = (u8 *)&val;
	nbl_pr_dbg("first rd tlp ret=%u,msg_len=%u,op_code=%u,msg_id=0x%x",
		msg[0], resp_data_len, req_head->op_code, req_head->rsv);
	msg_out[0] = msg[0];
	ent->ret = msg[0];
	if (resp_data_len <= TLP_RD_REG_LEN - sizeof(struct tlp_read_msg_header)) {
		memcpy(msg_out + 1, msg + sizeof(struct tlp_read_msg_header), resp_data_len);
		complete(&ent->done);
		nbl_pr_dbg("no slice tlp cmd exec success,ret=%u,msg_id=0x%x",
			ent->ret, req_head->rsv);
		return;
	}

	copy_len += (TLP_RD_REG_LEN - sizeof(struct tlp_read_msg_header));
	memcpy(msg_out + 1, msg + sizeof(struct tlp_read_msg_header), copy_len);
	for (i = TLP_RD_REG_LEN; i < 64; i += TLP_RD_REG_LEN) {
		val = readl(rf->hw.hw_addr + RDMA_TLP_WRITE_OFFSET + RDMA_TLP_READ_OFFSET_MIN + i);
		nbl_pr_dbg("more rd offset=0x%x,val=0x%08x,msg_id=0x%x",
			i + RDMA_TLP_READ_OFFSET_MIN, val, req_head->rsv);
		memcpy(msg_out + 1 + copy_len, &val, sizeof(val));
		copy_len += sizeof(val);
		if (copy_len >= resp_data_len)
			break;
	}

	nbl_pr_dbg("tlp slices cmd exec success,ret=%u,msg_id=0x%x", ent->ret, req_head->rsv);
	complete(&ent->done);
}

static void tlp_work_handler(struct work_struct *work)
{
	struct nbl_tlp_work_ent *ent = container_of(work, struct nbl_tlp_work_ent, work);
	struct nbl_tlp *tlp = ent->tlp;
	struct nbl_pci_f *rf = container_of(tlp, struct nbl_pci_f, tlp);
	u8 *msg = (u8 *)ent->in;
	int i;

	if (ent->in == NULL || ent->in_size <= 0 || ent->in_size > 64)
		return;

	nbl_pr_dbg("ent->in_size=%d,msg_id=0x%x", ent->in_size, msg[0]);
	for (i = 0; i < ent->in_size; i += 8)
		writeq(*(u64 *)(msg + i), rf->hw.hw_addr + RDMA_TLP_WRITE_OFFSET + i);

	INIT_DELAYED_WORK(&ent->dwork, tlp_dwork_get_result);
	queue_delayed_work(tlp->wq, &ent->dwork, msecs_to_jiffies(rf->tlp_timeout));
}

static int tlp_wait_func(struct nbl_tlp_work_ent *ent)
{
	nbl_pr_dbg("wait msg to complete,msg_id=0x%x", *(u8 *)ent->in);
	wait_for_completion(&ent->done);

	return ent->ret;
}

static int nbl_tlp_invoke(struct nbl_pci_f *rf, void *in, int in_size, void *out, int out_size)
{
	struct nbl_tlp *tlp = &rf->tlp;
	struct nbl_tlp_work_ent *ent;
	int err = 0;
	u8 *msg_in;

	ent = kzalloc(sizeof(*ent), GFP_KERNEL);
	if (!ent)
		return -ENOMEM;

	ent->tlp = tlp;
	ent->in = in;
	ent->in_size = in_size;
	ent->out = out;
	ent->out_size = out_size;

	msg_in = (u8 *)ent->in;
	msg_in[0] = tlp->seq_num++; /* use first byte as seq num */

	init_completion(&ent->done);

	INIT_WORK(&ent->work, tlp_work_handler);

	if (!queue_work(tlp->wq, &ent->work)) {
		nbl_pr_err("tlp failed to queue work,msg_id=0x%x", msg_in[0]);
		err = -ENOMEM;
		goto out_free;
	}

	err = tlp_wait_func(ent);
	if (err != 0)
		nbl_pr_err("tlp wait func err,msg_id=0x%x", msg_in[0]);

out_free:
	kfree(ent);

	return err;
}

int nbl_tlp_exec(struct nbl_pci_f *rf, void *in, int in_size, void *out,
		int out_size)
{
	struct nbl_tlp *tlp = &rf->tlp;
	int err;

	mutex_lock(&tlp->tlp_mlock);
	err = nbl_tlp_invoke(rf, in, in_size, out, out_size);
	mutex_unlock(&tlp->tlp_mlock);

	return err;
}

int nbl_tlp_init(struct nbl_pci_f *rf)
{
	struct nbl_tlp *tlp = &rf->tlp;

	if (host_id != HOST_ID_TYPE_HOST)
		return 0;

	mutex_init(&tlp->tlp_mlock);
	snprintf(tlp->wq_name, sizeof(tlp->wq_name), "nbl_tlp");
	tlp->wq = create_singlethread_workqueue(tlp->wq_name);
	if (!tlp->wq) {
		nbl_pr_err("failed to create tlp workqueue");
		return -ENOMEM;
	}

	return 0;
}

void nbl_tlp_exit(struct nbl_pci_f *rf)
{
	if (host_id != HOST_ID_TYPE_HOST)
		return;

	destroy_workqueue(rf->tlp.wq);
}
