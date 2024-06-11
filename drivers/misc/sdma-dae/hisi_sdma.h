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
#define HISI_SDMA_BYPASS_GROUP_MEMBER		32
#define HISI_SDMA_DEVICE_NAME_MAX		20
#define HISI_SDMA_READ_REG			1
#define HISI_SDMA_WRITE_REG			2
#define HISI_SDMA_MAX_ALLOC_SIZE		0x400000

#define HISI_SDMA_CLR_NORMAL_SQE_CNT		1
#define HISI_SDMA_CLR_ERR_SQE_CNT		2

#define HISI_SDMA_HBM_CACHE_PRELOAD_MODE	0x6

struct chn_ioe_info {
	u32 ch_err_status;
	u32 ch_cqe_sqeid;
	u32 ch_cqe_status;
};

struct hisi_sdma_chn_num {
	u32 total_chn_num;
	u32 share_chn_num;
};

struct hisi_sdma_umem_info {
	uintptr_t vma;
	u32 size;
	u64 cookie;
};

struct hisi_sdma_sq_entry {
	__le32 opcode          : 8;
	__le32 sssv            : 1;
	__le32 dssv            : 1;
	__le32 sns             : 1;
	__le32 dns             : 1;
	__le32 sro             : 1;
	__le32 dro             : 1;
	__le32 stride          : 2;
	__le32 ie              : 1;
	__le32 comp_en         : 1;
	__le32 reserved0       : 14;

	__le32 sqe_id          : 16;
	__le32 mpam_partid     : 8;
	__le32 mpamns          : 1;
	__le32 pmg             : 2;
	__le32 qos             : 4;
	__le32 reserved1       : 1;

	__le32 src_streamid    : 16;
	__le32 src_substreamid : 16;
	__le32 dst_streamid    : 16;
	__le32 dst_substreamid : 16;

	__le32 src_addr_l      : 32;
	__le32 src_addr_h      : 32;
	__le32 dst_addr_l      : 32;
	__le32 dst_addr_h      : 32;

	__le32 length_move     : 32;

	__le32 src_stride_len  : 32;
	__le32 dst_stride_len  : 32;
	__le32 stride_num      : 32;
	__le32 reserved2       : 32;
	__le32 reserved3       : 32;
	__le32 reserved4       : 32;
	__le32 reserved5       : 32;
};

struct hisi_sdma_cq_entry {
	__le32 reserved1;
	__le32 reserved2;
	__le32 sqhd      : 16;
	__le32 sqe_id    : 16;
	__le32 opcode    : 16;
	__le32 vld       : 1;
	__le32 status    : 15;
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

struct hisi_sdma_mpamcfg {
	u16    partid : 8;
	u16    pmg    : 2;
	u16    qos    : 4;
	u16    mpamid_replace_en : 1;
	u16    rsv5   : 1;
};

struct hisi_sdma_share_chn {
	u16    chn_idx;
	bool   init_flag;
};

struct hisi_sdma_reg_info {
	int chn;
	int type;
	u32 reg_value;
};

struct hisi_sdma_pid_info {
	int num;
	uintptr_t pid_list_addr;
};

typedef void (*sdma_task_callback)(int task_status, void *task_data);

struct hisi_sdma_sqe_task {
	u64 src_addr;
	u64 dst_addr;
	u32 src_process_id;
	u32 dst_process_id;
	u32 src_stride_len;
	u32 dst_stride_len;
	u32 stride_num;
	u32 length;
	u8 opcode;
	u8 mpam_partid;
	u8 pmg : 2;
	u8 resvd1 : 6;
	u8 qos : 4;
	u8 resvd2 : 4;
	sdma_task_callback task_cb;
	void *task_data;
	struct sdma_sqe_task *next_sqe;
};

struct hisi_sdma_task_info {
	int chn;
	u32 req_cnt;
	u32 task_cnt;
	uintptr_t task_addr;
};

typedef int (*sdma_ioctl_funcs)(struct file *file, unsigned long arg);
struct hisi_sdma_ioctl_func_list {
	unsigned int cmd;
	sdma_ioctl_funcs ioctl_func;
};

#define IOCTL_SDMA_GET_PROCESS_ID	_IOR('s', 1, u32)
#define IOCTL_SDMA_GET_CHN		_IOR('s', 2, int)
#define IOCTL_SDMA_PUT_CHN		_IOW('s', 3, int)
#define IOCTL_SDMA_GET_STREAMID		_IOR('s', 4, u32)
#define IOCTL_SDMA_PIN_UMEM		_IOWR('s', 5, struct hisi_sdma_umem_info)
#define IOCTL_SDMA_UNPIN_UMEM		_IOW('s', 6, u64)
#define IOCTL_GET_SDMA_NUM		_IOR('s', 7, int)
#define IOCTL_GET_NEAR_SDMAID		_IOR('s', 8, int)
#define IOCTL_GET_SDMA_CHN_NUM		_IOR('s', 9, struct hisi_sdma_chn_num)
#define IOCTL_SDMA_MPAMID_CFG		_IOW('s', 10, struct hisi_sdma_mpamcfg)
#define IOCTL_SDMA_CHN_USED_REFCOUNT	_IOW('s', 11, struct hisi_sdma_share_chn)
#define IOCTL_SDMA_ADD_AUTH_HT		_IOW('s', 12, struct hisi_sdma_pid_info)
#define IOCTL_SDMA_SEND_TASK		_IOWR('s', 13, struct hisi_sdma_task_info)
#define IOCTL_SDMA_SQ_HEAD_REG		_IOWR('s', 14, struct hisi_sdma_reg_info)
#define IOCTL_SDMA_SQ_TAIL_REG		_IOWR('s', 15, struct hisi_sdma_reg_info)
#define IOCTL_SDMA_CQ_HEAD_REG		_IOWR('s', 16, struct hisi_sdma_reg_info)
#define IOCTL_SDMA_CQ_TAIL_REG		_IOWR('s', 17, struct hisi_sdma_reg_info)
#define IOCTL_SDMA_DFX_REG		_IOWR('s', 18, struct hisi_sdma_reg_info)
#define IOCTL_SDMA_SQE_CNT_REG		_IOW('s', 19, struct hisi_sdma_reg_info)

#endif
