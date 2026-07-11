/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _ZXDH_MSG_CHAN_PRIV_H_
#define _ZXDH_MSG_CHAN_PRIV_H_
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/pci.h>
#include <linux/dinghai/dh_cmd.h>
#include <linux/dinghai/zxdh_compat.h>
#include <linux/dinghai/log.h>

#define BAR_KFREE_PTR(ptr)  \
	{                   \
		kfree(ptr); \
		ptr = NULL; \
	}

#define BAR_LOG_ERR(fmt, arg...) DH_LOG_ERR(MODULE_CMD, fmt, ##arg)
#define BAR_LOG_INFO(fmt, arg...) DH_LOG_INFO(MODULE_CMD, fmt, ##arg)
#define BAR_LOG_DEBUG(fmt, arg...) DH_LOG_DEBUG(MODULE_CMD, fmt, ##arg)
#define BAR_LOG_WARN(fmt, arg...) DH_LOG_WARNING(MODULE_CMD, fmt, ##arg)

#define HOST_OR_ZX 0

#define MAX_MSG_BUFF_NUM 0xffff

#define BAR_ALIGN_WORD_MASK 0xffffffc
#define BAR_MSG_ADDR_CHAN_INTERVAL (1024 * 2)

#define BAR_CHAN_MSG_SYNC 0
#define BAR_CHAN_MSG_ASYNC 1
#define BAR_CHAN_MSG_NO_EMEC 0
#define BAR_CHAN_MSG_EMEC 1
#define BAR_CHAN_MSG_NO_ACK 0
#define BAR_CHAN_MSG_ACK 1

#define BAR_MSG_PLAYLOAD_OFFSET (sizeof(struct bar_msg_header))
#define BAR_MSG_LEN_OFFSET 2
#define BAR_MSG_VALID_OFFSET 0

#define BAR_MSG_VALID_MASK 1

#define REPS_HEADER_VALID_OFFSET 0
#define REPS_HEADER_LEN_OFFSET 1
#define REPS_HEADER_PAYLOAD_OFFSET 4

#define REPS_HEADER_REPLYED 0xff

#define BAR_MSG_CHAN_USABLE 0
#define BAR_MSG_CHAN_USED 1

#define BAR_MSG_POLLING_SPAN_US 100
#define BAR_MSG_TIMEOUT_TH 30000

#define BAR_DRIVER_TOTAL_NUM (BAR_MPF_NUM + BAR_PF_NUM + BAR_VF_NUM)

#define BAR_INDEX_TO_RISC 0
#define BAR_MPF_NUM 1

#define BAR_MSGID_FREE_THRESHOLD (jiffies + msecs_to_jiffies(2000))

#define BAR_MSG_OFFSET (0x2000)
#define MPF_VENDOR_ID (0x16c3)
#define MPF_DEVICE_ID (0x8045)

enum {
	TYPE_SEND_NP = 0x0,
	TYPE_SEND_DRS = 0x01,
	TYPE_SEND_DTP = 0x10,
	TYPE_END,
};

#define SCENE_TEST

#ifdef SCENE_HOST_IN_DPU
#define BAR_PF_NUM 31
#define BAR_VF_NUM 1024
#define BAR_INDEX_PF_TO_VF 1
#define BAR_INDEX_MPF_TO_MPF 1
#define BAR_INDEX_MPF_TO_PFVF 0xff
#define BAR_INDEX_PFVF_TO_MPF 0xff
#endif

#ifdef SCENE_ZF_IN_DPU
#define BAR_PF_NUM 7
#define BAR_VF_NUM 128
#define BAR_INDEX_PF_TO_VF 0xff
#define BAR_INDEX_MPF_TO_MPF 1
#define BAR_INDEX_MPF_TO_PFVF 0xff
#define BAR_INDEX_PFVF_TO_MPF 0xff
#endif

#ifdef SCENE_NIC_WITH_DDR
#define BAR_PF_NUM 31
#define BAR_VF_NUM 1024
#define BAR_INDEX_PF_TO_VF 1
#define BAR_INDEX_MPF_TO_MPF 0xff
#define BAR_INDEX_MPF_TO_PFVF 0xff
#define BAR_INDEX_PFVF_TO_MPF 0xff
#endif

#ifdef SCENE_NIC_NO_DDR
#define BAR_PF_NUM 31
#define BAR_VF_NUM 1024
#define BAR_INDEX_PF_TO_VF 1
#define BAR_INDEX_MPF_TO_MPF 0xff
#define BAR_INDEX_MPF_TO_PFVF 1
#define BAR_INDEX_PFVF_TO_MPF 2
#endif

#ifdef SCENE_STD_NIC
#define BAR_PF_NUM 7
#define BAR_VF_NUM 256
#define BAR_INDEX_PF_TO_VF 1
#define BAR_INDEX_MPF_TO_MPF 0xff
#define BAR_INDEX_MPF_TO_PFVF 1
#define BAR_INDEX_PFVF_TO_MPF 2
#endif

#ifdef SCENE_TEST
#define BAR_PF_NUM 7
#define BAR_VF_NUM 256
#define BAR_INDEX_PF_TO_VF 0
#define BAR_INDEX_MPF_TO_MPF 0xff
#define BAR_INDEX_MPF_TO_PFVF 0
#define BAR_INDEX_PFVF_TO_MPF 0
#endif

#define BAR_SUBCHAN_INDEX_SEND 0
#define BAR_SUBCHAN_INDEX_RECV 1

#define BAR_MSG_SRC_NUM 3
#define BAR_MSG_SRC_MPF 0
#define BAR_MSG_SRC_PF 1
#define BAR_MSG_SRC_VF 2
#define BAR_MSG_SRC_ERR 0xff

#define BAR_MSG_DST_NUM 3
#define BAR_MSG_DST_RISC 0
#define BAR_MSG_DST_MPF 2
#define BAR_MSG_DST_PFVF 1
#define BAR_MSG_DST_ERR 0xff

#define REPS_INFO_FLAG_USABLE 0
#define REPS_INFO_FLAG_USED 1

#define BAR_MSG_PAYLOAD_MAX_LEN (BAR_MSG_ADDR_CHAN_INTERVAL - sizeof(struct bar_msg_header))

#define BAR_MSG_POL_MASK (0x10)
#define BAR_MSG_POL_OFFSET (4)

enum {
	CHECK_STATE_OK = 0,
	CHECK_STATE_EVENT_EXCEED = 1,
	CHECK_STATE_EVENT_NOT_EXIST = 2,
	CHECK_STATE_EVENT_ERR_RET = 4,
	CHECK_STATE_EVENT_ERR_REPS_LEN = 5,
};

struct zxdh_pcie_bar_msg_internal {
	u32 id; /**< the msg id that passing through */
	u64 virt_addr; /**< pcie bar mapping virtual addr */
};

struct bar_msg_header {
	u8 valid : 1;
	u8 sync : 1;
	u8 emec : 1;
	u8 ack : 1;
	u8 poll : 1;
	u8 usr : 1;
	u8 check;
	u16 event_id;
	u16 len;
	u16 msg_id;
	u16 src_pcieid;
	u16 dst_pcieid;
};

struct msgid_reps_info {
	void *reps_buffer;
	u16 id; /* msg_id*/
	u16 buffer_len;
	u16 flag;
	struct timer_list id_timer;
};

struct msix_msg {
	u16 pcie_id;
	u16 vector_risc;
	u16 vector_pfvf;
	u16 vector_mpf;
} __packed;

struct offset_get_msg {
	u16 pcie_id;
	u16 type;
};

struct bar_offset_reps {
	u16 check;
	u16 rsv;
	u32 offset;
	u32 length;
} __packed;

struct bar_recv_msg {
	u8 replied;
	u16 reps_len;
	u8 rsv1;
	union {
		struct bar_offset_reps offset_reps;
		u8 data[BAR_MSG_PAYLOAD_MAX_LEN - 4];
	};
} __packed;

struct msgid_ring {
	u16 msg_id;
	spinlock_t lock;
	struct msgid_reps_info reps_info_tbl[MAX_MSG_BUFF_NUM];
};

struct async_msg_entity {
	struct task_struct *async_proc;
	struct mutex async_qlock;
	struct bar_async_node *noemq_head;
	struct bar_async_node *noemq_tail;
	struct bar_async_node *emq_head;
	struct bar_async_node *emq_tail;
};

struct bar_async_node {
	u32 msg_id;
	void *payload_addr;
	u64 payload_len;
	u64 subchan_addr;
	u32 event_id;
	u16 src_pcieid;
	u16 dst_pcieid;
	u16 emec;
	u16 ack;
	u8 src;
	u8 dst;
	struct bar_async_node *next;
};

struct vqm_qid_reset_msg {
	u32 qid;
} __packed;
struct OVS_TO_VQM_MSG {
	u16 vqm_vfid;
	u16 opcode; /* get:0, set:1 */
#define VQM_QUEUE_RSET (14)
	u16 cmd;
	union {
		u8 value[8];
		struct vqm_qid_reset_msg q_reset_msg;
	} __packed;
} __packed;

struct VQM_RSP_OVS_DATA {
	u32 reps_hdr;
#define VQM_REPS_SUCCESS (0xaa)
	u32 check_result;
	union {
		u8 rsv[40];
	} __packed;
} __packed;

#define VCQ_NOTIFY_EVENT_ID (36)

u8 bar_msg_col_index_trans(u8 dst);
u8 bar_msg_row_index_trans(u8 src);

#endif /* _ZXDH_MSG_CHAN_PRIV_H_  */
