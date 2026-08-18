/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef __HISI_MSG_H__
#define __HISI_MSG_H__

#include <linux/spinlock.h>
#include <linux/device.h>
#include <ub/ubus/ubus.h>

#include "../../msg.h"

extern int msg_wait;

/* Hardware register context */
#define HI_MSGQ_SIZE	0x120
#define SQ_ADDR_L	0x0
#define SQ_ADDR_H	0x4
#define SQ_PI		0x8
#define SQ_CI		0xc
#define SQ_DEPTH	0x10
#define SQ_STATUS	0x14
#define SQ_INT_MSK	0x18
#define RQ_ADDR_L	0x40
#define RQ_ADDR_H	0x44
#define RQ_PI		0x48
#define RQ_CI		0x4c
#define RQ_DEPTH	0x50
#define RQ_ENTRY_SIZE	0x54
#define RQ_STATUS	0x58
#define CQ_ADDR_L	0x70
#define CQ_ADDR_H	0x74
#define CQ_PI		0x78
#define CQ_CI		0x7c
#define CQ_DEPTH	0x80
#define CQ_STATUS	0x84
#define CQ_INT_MASK	0x88
#define CQ_INT_STATUS	0x8c
#define CQ_INT_RO	0x90
#define MSGQ_RST	0xB0
#define MSGQ_INT_SEL	0xC0

#define HI_MSG_RQE_SIZE		0x800 /* 2K */
#define HI_MSG_SQE_PLD_SIZE	0x800 /* 2K */
#define HI_SQ_CFG_DEPTH		0x400
#define HI_RQ_CFG_DEPTH		0x400
#define HI_CQ_CFG_DEPTH		0x400
#define HI_MSG_SQE_SIZE		16
#define HI_MSG_CQE_SIZE		16

#define HI_UBUS_LOWEST_VER	0U
#define HI_UBUS_HIGHEST_VER	2U
#define HI_VER_EXCH_REQ_SIZE	4
#define HI_VER_EXCH_RSP_SIZE	4

extern u16 hi_firmware_lowest_ver;
extern u16 hi_firmware_highest_ver;

enum hi_firmware_ver {
	FIRMWARE_VER_DEFAULT = 0,
	FIRMWARE_VER_VPORT_DISABLE_NOTIFY = 2,
};

static inline bool hi_vport_disable_notify_enabled(void)
{
	return hi_firmware_highest_ver >= FIRMWARE_VER_VPORT_DISABLE_NOTIFY;
}

enum hi_cqe_status {
	CQE_SUCCESS = 0,
	CQE_FAIL = 1,
	CQE_OP_UNSUPP_ASCEND = 38,
	CQE_OP_UNSUPP_KUNPENG = 39
};

enum hi_task_type {
	PROTOCOL_MSG = 0,
	PROTOCOL_ENUM = 1,
	HISI_PRIVATE = 2,
	TASK_TYPE_NUM
};

enum hi_msgq_private_opcode {
	EU_TABLE_CFG_CMD = 2,
	GET_UBMEM_EVENT_CMD = 4,
	VER_EXCH_CMD = 255
};

enum hi_msgq_user {
	MSGQ_USER_BUS_DRV = 0,
	MSGQ_USER_NUMS
};

enum hi_msgq_idx {
	MSG_SQ = 0,
	MSG_RQ = 1,
	MSG_CQ = 2,
	MSGQ_NUM
};

struct hi_msg_sqe {
	/* DW0 */
	u32 task_type : 2;
	u32 rsvd0 : 2;
	u32 local : 1;
	u32 dev_type : 2;
	u32 icrc : 1;
	union {
		struct {
			u8 type : 1;
			u8 msg_code : 3;
			u8 sub_msg_code : 4;
		};
		u8 opcode;
	};
	u32 p_len : 12;
	u32 rsvd1 : 4;
	/* DW1 */
	u32 msn : 16;
	u32 rsvd3 : 16;
	/* DW2 */
	u32 p_addr;
	/* DW3 */
	u32 rsvd2;
};

struct hi_msg_cqe {
	/* DW0 */
	u32 task_type : 2;
	u32 rsvd0 : 6;
	union {
		struct {
			u8 type : 1;
			u8 msg_code : 3;
			u8 sub_msg_code : 4;
		};
		u8 opcode;
	};
	u32 p_len : 12;
	u32 rsvd1 : 4;
	/* DW1 */
	u32 msn : 16;
	u32 rsvd5 : 16;
	/* DW2 */
	u32 rq_pi : 10;
	u32 rsvd2 : 6;
	u32 status : 8;
	u32 rsvd3 : 8;
	/* DW3 */
	u32 rsvd4;
};

struct hi_msg_queue {
	union {
		struct hi_msg_sqe *sqe;
		void *rqe;
		struct hi_msg_cqe *cqe;
		void *entry;
	};

	dma_addr_t dma_addr;

	u16 ci;
	u16 pi;
	u16 depth;
	u16 entry_size;
	size_t total_size;

	spinlock_t lock;
};

#define HI_MSG_INT_NAME_LEN 32
struct hi_msg_core {
	struct device *dev; /* ubc->dev */
	phys_addr_t q_addr; /* MSGQ ctx's phy addr & size */
	size_t q_size;
	void __iomem *reg_base; /* MSGQ context virtual address */

	u32 virq; /* if virq == 0, then use poll mode, else int mode */
	u32 intx;
	void (*irq_handler)(struct hi_msg_core *hmc);
	void (*isr_handler)(struct hi_msg_core *hmc);
	char queue_name[HI_MSG_INT_NAME_LEN];
	atomic_t cq_int_mask;
	int user;
	struct hi_msg_queue queue[MSGQ_NUM];
};

struct hi_ver_exch_rsp {
	u32 firmware_highest_ver : 16;
	u32 firmware_lowest_ver : 16;
};

struct hi_ver_exch_req {
	u32 ubus_highest_ver : 16;
	u32 ubus_lowest_ver : 16;
};

struct hi_ver_exch_pld {
	union {
		struct hi_ver_exch_req req;
		struct hi_ver_exch_rsp rsp;
	};
};

#define q_used_cnt(q) (((q)->pi + (q)->depth - (q)->ci) % (q)->depth)
#define q_ptr_idx(q, p, i) (((q)->p + (i)) % (q)->depth)
#define cq_entry(hmc, idx) (&((hmc)->queue[MSG_CQ].cqe[idx]))
#define rq_entry(hmc, idx) \
	((hmc)->queue[MSG_RQ].rqe + (HI_MSG_RQE_SIZE * (idx)))

static inline bool hi_ver_exch_unsupp_msg(struct hi_msg_cqe *cqe)
{
	return cqe->task_type == HISI_PRIVATE && cqe->opcode == VER_EXCH_CMD &&
	       (cqe->status == CQE_OP_UNSUPP_ASCEND ||
		cqe->status == CQE_OP_UNSUPP_KUNPENG);
}

int hi_msg_cq_poll(struct hi_msg_core *hmc, int task_type, u16 msn);
void hi_msg_rq_update(struct hi_msg_core *hmc, int cq_idx);
void hi_msg_sqe_init(struct hi_msg_sqe *sqe, int msn, struct msg_info *info,
		     int task_type, u8 code);
void hi_msg_set_pkt_msn(struct msg_info *info, int task_type, u16 msn,
			u8 msgq_id);
int hi_message_cqe_check(struct device *dev, struct hi_msg_sqe *sqe,
			 struct hi_msg_cqe *cqe, u16 rsp_pkt_size);
void hi_msg_rqe_get(struct hi_msg_core *hmc, void *buf, struct hi_msg_cqe *cqe);
u32 hi_msg_reg_read(struct hi_msg_core *hmc, u16 offset);
void hi_msg_reg_write(struct hi_msg_core *hmc, u16 offset, u32 val);
int hi_msg_core_init(struct hi_msg_core *hmc, int user);
void hi_msg_core_uninit(struct hi_msg_core *hmc);
int hi_msg_device_probe(struct ub_bus_controller *ubc);
void hi_msg_device_remove(struct ub_bus_controller *ubc);
int hi_message_sync_request(struct message_device *mdev,
			    struct msg_info *info, u8 opcode);
int hi_message_sync_request_sched(struct message_device *mdev,
				  struct msg_info *info, u8 opcode);
int hi_message_private(struct message_device *mdev, struct msg_info *info,
		       u8 opcode);
void hi_msg_debugfs_init(struct hi_msg_core *hmc);
void hi_msg_debugfs_uninit(struct hi_msg_core *hmc);
void ub_msg_dump_sq(struct hi_msg_sqe *sqe, void *sq_pld);
void ub_msg_dump_cq(struct hi_msg_cqe *cqe, void *rqe);

#endif /* __HISI_MSG_H__ */
