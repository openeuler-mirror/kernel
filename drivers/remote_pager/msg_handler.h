/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Generalized Memory Management.
 *
 * Copyright (c) 2023- Huawei, Inc.
 * Author: Liming Huang
 * Co-Author: Jun Chen
 *
 */
#ifndef _REMOTE_PAGER_MSG_HANDLER_H_
#define _REMOTE_PAGER_MSG_HANDLER_H_

#include <linux/sched/task.h>
#include <linux/kthread.h>

#ifdef WITH_GMEM
#include <linux/gmem.h>
#endif

#include "wait_station.h"
#include "msg_chan/msg_layer/msg_layer.h"

#define PXD_JUDGE(pxd) (((pxd) == NULL) || (pxd##_none(*(pxd##_t *)(pxd)) != 0) || \
	(pxd##_bad(*(pxd##_t *)(pxd)) != 0))
#define PMD_JUDGE(pmd) (((pmd) == NULL) || (pmd_none(*(pmd_t *)(pmd)) != 0) || \
	(pmd_bad(*(pmd_t *)(pmd)) != 0))

#define GMEM_COPY_PAGE 1

/* Function pointer to callback function */
typedef int (*rpg_kmsg_cbftn)(struct rpg_kmsg_message *);

enum rpg_kmsg_type {
	/* TASK CMD */
	GMEM_TASK_PAIRING_REQUEST,
	GMEM_TASK_EXIT_ORIGIN,
	GMEM_TASK_EXIT_REMOTE,

	/* VMA CMD */
	GMEM_ALLOC_VMA_REQUEST,
	GMEM_FREE_VMA_REQUEST,

	/* PAGE CMD */
	GMEM_ALLOC_PAGE_REQUEST,
	GMEM_FREE_PAGE_REQUEST,
	GMEM_PAGE_FAULT_REQUEST,
	GMEM_EVICT_PAGE_REQUEST,

	/* ADVISE CMD */
	GMEM_HMADVISE_REQUEST,
	GMEM_HMEMCPY_REQUEST,

	GMEM_COMMON_RESPONSE,
	GMEM_MSG_MAX_ID,
};

enum msg_location {
	MSG_ON_ORIGIN,
	MSG_ON_REMOTE,
};

struct rpg_kmsg_work {
	struct work_struct work;
	void *msg;
};

struct msg_handler_st {
	rpg_kmsg_cbftn fnt;
};

struct comm_msg_rsp {
	struct rpg_kmsg_hdr header;
	int peer_ws;
	int ret;
};

struct gm_pair_msg_rq {
	struct rpg_kmsg_hdr header;
	unsigned int my_ws;
	unsigned int my_pid;
	unsigned int peer_nid;
	unsigned int peer_pid;
};

struct gm_pager_msg_rq {
	struct rpg_kmsg_hdr header;
	unsigned int my_ws;
	unsigned int peer_pid;
	unsigned long va;
	unsigned long dma_addr;
	unsigned long size;
	unsigned long prot;
	unsigned long flags;
	int behavior;
};

struct gm_evict_page_msg_rq {
	struct rpg_kmsg_hdr header;
	unsigned int peer_pid;
	unsigned int ws;
	unsigned long va;
	unsigned long size;
};


int gmem_register_pair_remote_task(int origin_nid, int origin_pid, int remote_nid, int remote_pid);

#ifdef WITH_GMEM
gm_dev_t *gmem_id_to_device(unsigned int id);
#endif


/* msg handler */
int gmem_handle_task_pairing(struct rpg_kmsg_message *msg);
int gmem_handle_comm_msg_rsp(struct rpg_kmsg_message *msg);
int gmem_handle_alloc_vma_fixed(struct rpg_kmsg_message *msg);
int gmem_handle_free_vma(struct rpg_kmsg_message *msg);

int gmem_handle_alloc_page(struct rpg_kmsg_message *msg);
int gmem_handle_free_page(struct rpg_kmsg_message *msg);
int gmem_handle_hmadvise(struct rpg_kmsg_message *msg);
int gmem_handle_hmemcpy(struct rpg_kmsg_message *msg);
int gmem_handle_dev_fault(struct rpg_kmsg_message *msg);
int gmem_handle_evict_page(struct rpg_kmsg_message *msg);

int gmem_add_to_svm_proc(int my_nid, int my_pid, int peer_nid, int peer_pid);
int gmem_send_comm_msg_reply(unsigned int from_nid, unsigned int to_nid,
							 unsigned int peer_ws, int ret);

int handle_remote_pager_work(void *msg);
int msg_handle_init(void);

#endif
