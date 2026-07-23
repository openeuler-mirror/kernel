/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_PRIV_QUEUE_H__
#define __ZXDH_PRIV_QUEUE_H__
#include <linux/list.h>
#include <linux/dinghai/driver.h>
#include <linux/dinghai/dh_cmd.h>
#include <linux/netdevice.h>
#include <linux/scatterlist.h>
#include <linux/spinlock.h>
#include "queue.h"
#include "../en_aux.h"
#include "../../dinghai/en_np/table/include/dpp_tbl_api.h"

#define MSGQ_TEST 1

#define MSGQ_RET_OK 0
#define MSGQ_RET_ERR (-1)
#define MSGQ_RET_ERR_NULL_PTR (-2)
#define MSGQ_RET_ERR_INVALID_PARA (-3)
#define MSGQ_RET_ERR_CHANNEL_NOT_READY (-5)
#define MSGQ_RET_ERR_CHAN_BUSY (-6)
#define MSGQ_RET_ERR_VQ_BROKEN (-7)
#define MSGQ_RET_ERR_CALLBACK_OUT_OF_TIME (-8)
#define MSGQ_RET_ERR_CALLBACK_FAIL (-9)
#define MSGQ_RET_ERR_REPS_LEN_NOT_ENOUGH (-10)
#define MSGQ_RET_ERR_RX_INVALID_NUM_BUF (-11)

struct reps_info {
	u32 len;
	u8 *addr;
};

struct msgq_pkt_info {
	u32 timeout_us;
	u16 event_id;
	bool is_async;
	bool no_reps;
	u8 msg_priority;
	u8 rsv;
	u32 len;
	u8 *addr;
} __packed;

/* msg_chan_pkt Definitions */
#define MAX_PACKET_LEN (MSGQ_MAX_ADDR_LEN - PRIV_HEADER_LEN)
#define MSGQ_MAX_ADDR_LEN 14000
#define NO_REPS_SEQUENCE_NUM 0x8000

#define TIMER_DELAY_US 100
#define MSGQ_MAX_MSG_BUFF_NUM 1024
#define BUFF_LEN 4096

#define PRIV_HEADER_LEN sizeof(struct priv_queues_net_hdr)
#define DEFAULT_PI_TYPE 0x00 /*NP*/
#define CONTROL_MSG_TYPE 0x1f
#define NEED_REPS_MSG 0x00
#define ACK_MSG 0x01
#define NO_REPS_MSG 0x02

#define RISCV_COMMON_VFID (1192)
#define RISCV_COMMON_QID (4092)

enum msgq_err_code {
	ERR_CODE_INVALID_EVENTID = 1,
	ERR_CODE_EVENT_UNREGIST,
	ERR_CODE_INVALID_ACK,
	ERR_CODE_EVENT_FAIL,
	ERR_CODE_INVALID_REPS_LEN,
	ERR_CODE_PEER_BROKEN,
};

struct pi_header {
	u8 pi_type;
	u8 pkt_type;
	u16 event_id;
	u16 vfid_dst;
	u16 qid_dst;
	u16 vfid_src;
	u16 qid_src;
	u16 sequence_num;
	u8 msg_priority;
	u8 msg_type;
	u8 err_code;
	u8 rsv[3];
};

struct msgq_pi_info {
	u16 event_id;
	u16 vfid_dst;
	u16 qid_dst;
	u16 vfid_src;
	u16 qid_src;
	u16 sequence_num;
} __packed;

struct priv_queues_net_hdr {
	u8 tx_port;
	u8 pd_len;
	u8 num_buffers;
	u8 rsv;
	struct pi_header pi_hdr;
};

struct msg_buff {
	bool using;
	bool valid;
	bool need_free;
	u32 timeout_cnt;
	u8 **data;
	u32 *data_len;
} __packed;

#define MSGQ_PRINT_HDR 1
#define MSGQ_PRINT_128B 2
#define MSGQ_PRINT_ALL 3
#define MSGQ_PRINT_STA 4

struct msgq_dev {
	bool msgq_enable;
	bool timer_in_use;
	bool loopback;
	u8 print_flag;
	u16 sequence_num;
	u16 free_cnt;
	u16 msgq_vfid;
	u16 msgq_rqid;
	struct send_queue *sq_priv;
	struct receive_queue *rq_priv;
	struct mutex *mlock;
	spinlock_t sn_lock;
	spinlock_t tx_lock;
	struct msg_buff msg_buff_ring[MSGQ_MAX_MSG_BUFF_NUM];
	struct timer_list poll_timer;
} __packed;

#define CHECK_CHANNEL_USABLE(msgq, ret)                         \
	do {                                                    \
		if (!(msgq)->msgq_enable) {                     \
			LOG_ERR("msgq unable\n");               \
			(ret) = MSGQ_RET_ERR_CHANNEL_NOT_READY; \
		}                                               \
	} while (0)

#define ZXDH_FREE_PTR(ptr)            \
	do {                          \
		if ((ptr) != NULL) {  \
			kfree(ptr);   \
			(ptr) = NULL; \
		}                     \
	} while (0)

#define SEQUENCE_NUM_ADD(id)                   \
	do {                                   \
		(id)++;                        \
		(id) %= MSGQ_MAX_MSG_BUFF_NUM; \
	} while (0)

s32 zxdh_msgq_init(struct zxdh_en_device *en_dev);
void zxdh_msgq_exit(struct zxdh_en_device *en_dev);
s32 print_data(u8 *data, u32 len);
s32 zxdh_msgq_send_cmd(struct msgq_dev *msgq_dev, struct msgq_pkt_info *pkt_info,
		       struct reps_info *reps);
int zxdh_msgq_poll(struct napi_struct *napi, int budget);
s32 msgq_privq_init(struct msgq_dev *msgq_dev, struct net_device *netdev);
void msgq_privq_uninit(struct msgq_dev *msgq_dev);

#endif /* __ZXDH_PRIV_QUEUE_H__  */
