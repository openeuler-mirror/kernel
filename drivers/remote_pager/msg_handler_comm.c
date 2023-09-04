// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generalized Memory Management.
 *
 * Copyright (C) 2023- Huawei, Inc.
 * Author: Chushu Ni
 * Co-Author: Chunsheng Luo
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/workqueue.h>

#include "msg_handler.h"
#include "svm_proc_mng.h"

static struct workqueue_struct *remote_pager_wq;

struct msg_handler_st rpg_kmsg_cbftns[GMEM_MSG_MAX_ID] = {
#if IS_ENABLED(CONFIG_REMOTE_PAGER_SLAVE)
	/* HOST TO REMOTE */
	[GMEM_TASK_PAIRING_REQUEST] = {
		gmem_handle_task_pairing
	},
	[GMEM_ALLOC_VMA_REQUEST] = {
		gmem_handle_alloc_vma_fixed
	},
	[GMEM_FREE_VMA_REQUEST] = {
		gmem_handle_free_vma
	},
	[GMEM_ALLOC_PAGE_REQUEST] = {
		gmem_handle_alloc_page
	},
	[GMEM_FREE_PAGE_REQUEST] = {
		gmem_handle_free_page
	},
	[GMEM_HMADVISE_REQUEST] = {
		gmem_handle_hmadvise
	},
	[GMEM_HMEMCPY_REQUEST] = {
		gmem_handle_hmemcpy
	},
#endif

#if IS_ENABLED(CONFIG_REMOTE_PAGER_MASTER)
	/* REMOTE TO HOST */
	[GMEM_PAGE_FAULT_REQUEST] = {
		gmem_handle_dev_fault
	},
	[GMEM_EVICT_PAGE_REQUEST] = {
		gmem_handle_evict_page
	},
#endif

	/* BOTH */
	[GMEM_COMMON_RESPONSE] = {
		gmem_handle_comm_msg_rsp
	},
};

int gmem_handle_comm_msg_rsp(struct rpg_kmsg_message *msg)
{
	struct comm_msg_rsp *rsp = (struct comm_msg_rsp *)msg;
	struct wait_station *my_ws = wait_station(rsp->peer_ws);

	my_ws->private = rsp;
	/* must first set my_ws */
	smp_rmb();
	complete(&my_ws->pendings);

	return 0;
}

int gmem_send_comm_msg_reply(unsigned int from_nid, unsigned int to_nid,
							 unsigned int peer_ws, int reply)
{
	struct comm_msg_rsp rsp;
	int ret = reply;

	rsp.ret = reply;
	rsp.peer_ws = peer_ws;
	ret = msg_send_nid(GMEM_COMMON_RESPONSE, from_nid,
					   to_nid, &rsp, sizeof(struct comm_msg_rsp));

	return ret;
}

int gmem_add_to_svm_proc(int my_nid, int my_pid, int peer_nid, int peer_pid)
{
	struct svm_proc *peer_proc;

	peer_proc = alloc_svm_proc(my_nid, my_pid, peer_nid, peer_pid);
	if (!peer_proc)
		return -1;

	return 0;
}

void process_remote_pager_work(struct work_struct *work)
{
	struct rpg_kmsg_work *w = container_of(work, struct rpg_kmsg_work, work);
	struct rpg_kmsg_message *msg = w->msg;
	rpg_kmsg_cbftn ftn;

	ftn = rpg_kmsg_cbftns[msg->header.type].fnt;
	if (ftn != NULL)
		ftn(msg);
	else
		pr_err("No callback registered for %d\n", msg->header.type);
	kfree(w);
}

int handle_remote_pager_work(void *msg)
{
	struct rpg_kmsg_work *w = kmalloc(sizeof(*w), GFP_ATOMIC);

	w->msg = msg;

	INIT_WORK(&w->work, process_remote_pager_work);
	/* should firstly initialize w */
	smp_wmb();
	queue_work(remote_pager_wq, &w->work);

	return 0;
}

int msg_handle_init(void)
{
	unsigned int flags = __WQ_LEGACY | WQ_UNBOUND | WQ_HIGHPRI | WQ_CPU_INTENSIVE;

	remote_pager_wq = alloc_workqueue("remote_wq",  flags, 0);
	if (!remote_pager_wq) {
		pr_err("%s alloc workqueue failed %lx\n", __func__, (unsigned long)remote_pager_wq);
		return -1;
	}

	pr_err("%s alloc workqueue%lx\n", __func__, (unsigned long)remote_pager_wq);
#ifndef WITH_GMEM
		msg_open(0);
#endif
	return 0;
}
