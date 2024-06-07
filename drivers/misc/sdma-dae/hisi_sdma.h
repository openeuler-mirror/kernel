/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __HISI_SDMA_H__
#define __HISI_SDMA_H__

#include <asm-generic/ioctl.h>
#include <linux/errno.h>
#include <linux/types.h>

#define HISI_SDMA_DEVICE_NAME			"sdma"
#define HISI_SDMA_MAX_DEVS			4
#define HISI_SDMA_MAX_NODES			16

#define HISI_SDMA_MMAP_SQE			0
#define HISI_SDMA_MMAP_CQE			1
#define HISI_SDMA_MMAP_IO			2
#define HISI_SDMA_MMAP_SHMEM			3
#define HISI_SDMA_FSM_TIMEOUT			100

#define HISI_SDMA_CHANNEL_IOMEM_SIZE		0x1000
#define HISI_SDMA_SQ_ENTRY_SIZE			64UL
#define HISI_SDMA_CQ_ENTRY_SIZE			16UL
#define HISI_SDMA_SQ_LENGTH			(1U << 16)
#define HISI_SDMA_CQ_LENGTH			(1U << 16)

#define HISI_STARS_CHN_NUM			32
#define HISI_SDMA_DEFAULT_CHANNEL_NUM		(192 - HISI_STARS_CHN_NUM)
#define HISI_SDMA_SQ_SIZE			(HISI_SDMA_SQ_ENTRY_SIZE * HISI_SDMA_SQ_LENGTH)
#define HISI_SDMA_CQ_SIZE			(HISI_SDMA_CQ_ENTRY_SIZE * HISI_SDMA_CQ_LENGTH)
#define HISI_SDMA_REG_SIZE			4096
#define HISI_SDMA_CH_OFFSET			(HISI_STARS_CHN_NUM * HISI_SDMA_REG_SIZE)
#define HISI_SDMA_DEVICE_NAME_MAX		20
#define HISI_SDMA_MAX_ALLOC_SIZE		0x400000

struct chn_ioe_info {
	u32 ch_err_status;
	u32 ch_cqe_sqeid;
	u32 ch_cqe_status;
};

struct hisi_sdma_queue_info {
	u32    sq_head;
	u32    sq_tail;
	u32    cq_head;
	u32    cq_tail;
	u32    cq_vld;
	int    lock;
	u32    lock_pid;
	int    err_cnt;
	int    cqe_err[HISI_SDMA_SQ_LENGTH];
	u32    round_cnt[HISI_SDMA_SQ_LENGTH];
	struct chn_ioe_info ioe;
};

typedef int (*sdma_ioctl_funcs)(struct file *file, unsigned long arg);
struct hisi_sdma_ioctl_func_list {
	unsigned int cmd;
	sdma_ioctl_funcs ioctl_func;
};

#define IOCTL_SDMA_GET_PROCESS_ID	_IOR('s', 1, u32)
#define IOCTL_SDMA_GET_STREAMID		_IOR('s', 2, u32)

#endif
