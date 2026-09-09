// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 * Author: lewis.liu <lewis.liu@nebula-matrix.com>
 */
#include "main.h"
#include "mailbox.h"
#include "grc.h"
#include "cqp.h"

static void mbx_work_handler(struct work_struct *work)
{
	struct nbl_mbx_work_ent *ent = container_of(work, struct nbl_mbx_work_ent, work);
	u8 *msg = (u8 *)ent->in;
	int ret_val;
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)ent->rf->cdev;

	if (ent->in == NULL || ent->in_size <= 0 || ent->in_size > 64)
		return;

	nbl_pr_dbg("ent->in_size=%d,msg_id=0x%x", ent->in_size, msg[0]);

	ret_val = cdev_info->send(cdev_info->pdev, msg, (u8)ent->in_size,
		ent->out, (u16)ent->out_size);
	if (ret_val)
		nbl_pr_err("send msg to af_grc err=%d", ret_val);

	memcpy(&ent->ret, ent->out, sizeof(char));
	complete(&ent->done);
}

static int mbx_wait_func(struct nbl_mbx_work_ent *ent)
{
	nbl_pr_dbg("wait msg to complete,msg_id=0x%x", *(u8 *)ent->in);
	wait_for_completion(&ent->done);

	return ent->ret;
}

static int nbl_mbx_invoke(struct nbl_pci_f *rf, void *in, int in_size, void *out, int out_size)
{
	struct nbl_mbx *mbx = &rf->mbx;
	struct nbl_mbx_work_ent *ent;
	int err = 0;
	u8 *msg_in;

	ent = kzalloc(sizeof(*ent), GFP_KERNEL);
	if (!ent)
		return -ENOMEM;

	ent->mbx = mbx;
	ent->in = in;
	ent->in_size = in_size;
	ent->out = out;
	ent->out_size = out_size;
	ent->rf = rf;

	msg_in = (u8 *)ent->in;
	msg_in[0] = mbx->seq_num++; /* use first byte as seq num */

	init_completion(&ent->done);

	INIT_WORK(&ent->work, mbx_work_handler);

	if (!queue_work(mbx->wq, &ent->work)) {
		nbl_pr_err("mbx failed to queue work,msg_id=0x%x", msg_in[0]);
		err = -ENOMEM;
		goto out_free;
	}

	err = mbx_wait_func(ent);

out_free:
	kfree(ent);

	return err;
}

int nbl_mbx_exec(struct nbl_pci_f *rf, void *in, int in_size, void *out, int out_size)
{
	struct nbl_mbx *mbx = &rf->mbx;
	int err;

	mutex_lock(&mbx->mbx_mlock);
	err = nbl_mbx_invoke(rf, in, in_size, out, out_size);
	mutex_unlock(&mbx->mbx_mlock);

	return err;
}

int nbl_mbx_roce_init(struct nbl_pci_f *rf)
{
	struct nbl_mbx *mbx = &rf->mbx;

	mutex_init(&mbx->mbx_mlock);
	snprintf(mbx->wq_name, sizeof(mbx->wq_name), "nbl_mbx");
	mbx->wq = create_singlethread_workqueue(mbx->wq_name);
	if (!mbx->wq) {
		nbl_pr_err("failed to create mbx workqueue");
		return -ENOMEM;
	}

	return 0;
}

void nbl_mbx_roce_exit(struct nbl_pci_f *rf)
{
	if (rf->mbx.wq)
		destroy_workqueue(rf->mbx.wq);
}
