/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ub_mad private header
 * Author: Chen Yutao
 * Create: 2025-01-13
 * Note:
 * History: 2025-01-13: Create file
 */

#ifndef UB_MAD_PRIV_H
#define UB_MAD_PRIV_H

#include <linux/bitmap.h>
#include "ub_mad.h"

/* well-known jetty (wk jetty) parameters */
#define UBMAD_WK_JETTY_NUM 2 /* well-known jetty 0 and 1 only used in ubcm */
#define UBMAD_WK_JETTY_ID_0 1U
#define UBMAD_WK_JETTY_ID_1 2U

// jetty
#define UBMAD_JFS_DEPTH 512U
#define UBMAD_JFR_DEPTH 1024U
#define UBMAD_JFS_MAX_SGE_NUM 1
#define UBMAD_JFR_MAX_SGE_NUM 1
#define UBMAD_JETTY_ERR_TIMEOUT 17

// seg
#define UBMAD_SEND_SGE_NUM (UBMAD_JFS_DEPTH * 2)
#define UBMAD_RECV_SGE_NUM (UBMAD_JFR_DEPTH * 2)

// tjetty
#define UBMAD_MAX_TJETTY_NUM 10240

/* datapath */
#define UBMAD_MSG_VERSION_0 0 /* current version */

// reliable communication
#define UBMAD_MSN_HLIST_SIZE 1024
#define UBMAD_MAX_SEID_NUM 1024

#define UBMAD_RETRANSMIT_MS 500
#define UBMAD_RETRANSMIT_PERIOD msecs_to_jiffies(UBMAD_RETRANSMIT_MS)

#define UBMAD_MAX_RETRY_CNT 4
#define UBMAD_RX_BITMAP_SIZE 1024

#define UBMAD_TX_THREDSHOLD (UBMAD_JFS_DEPTH - 8)

#define UBMAD_INI_RTBUFFER_SIZE 1024
#define UBMAD_TGT_RTBUFFER_SIZE 256
#define UBMAD_TGT_RTBUFFER_MASK 255
#define UBMAD_RTBUFFER_PKTSIZE 256
#define UBMAD_TGT_HASH_SIZE 1024

/* common */
struct ubmad_bitmap {
	unsigned long *bits;
	uint32_t size;
	uint64_t right_end; /* Only for RX side */
	spinlock_t lock;
};

struct ubmad_msn_mgr {
	atomic64_t msn_gen; // msn generator, increased with each post_send

	// msn_hlist holds msn that posted but not ack yet. key: msn, val: msn_node
	struct hlist_head msn_hlist[UBMAD_MSN_HLIST_SIZE]; // ubmad_msn_node
	spinlock_t msn_hlist_lock;
};

/* jetty */
struct ubmad_jetty_resource {
	/* jetty */
	uint32_t jetty_id;
	struct ubcore_jfc *jfc_s; // send
	struct ubcore_jfc *jfc_r; // recv
	struct ubcore_jfr *jfr;
	struct ubcore_jetty *jetty; /* well-known jetty */
	atomic_t tx_in_queue;

	/* seg */
	// each post uses one sge in the seg
	// send
	struct ubcore_target_seg *send_seg;
	struct ubmad_bitmap *send_seg_bitmap;
	// recv
	struct ubcore_target_seg *recv_seg;
	struct ubmad_bitmap *recv_seg_bitmap;

	/* tjetty */
	// key: ubcore_eid dst_eid, val: ubmad_tjetty tjetty
	struct hlist_head tjetty_hlist[UBMAD_MAX_TJETTY_NUM];
	spinlock_t tjetty_hlist_lock;
};

struct ubmad_ini_rtbuffer {
	struct hlist_node node;
	uint64_t msn;
	uint32_t payload_len;
	uint8_t data[UBMAD_RTBUFFER_PKTSIZE];
};

struct ubmad_tgt_rtbuffer {
	uint64_t msn;
	uint32_t payload_len;
	uint8_t data[UBMAD_RTBUFFER_PKTSIZE];
};

struct ubmad_tgt_hash_node {
	struct hlist_node node;
	uint64_t msn;
	uint64_t idx;
};

struct ubmad_tjetty {
	struct ubcore_tjetty *tjetty;
	struct kref kref;
	struct hlist_node node; // ubmad_device_priv.tjetty_hlist

	/* reliable communication */
	struct ubmad_msn_mgr msn_mgr; // for retransmit, only for initiator
	spinlock_t ini_rt_spinlock;
	struct hlist_head ini_rt_hlist[UBMAD_INI_RTBUFFER_SIZE];

	spinlock_t tgt_hash_lock;
	atomic64_t tgt_idx_gen;
	struct hlist_head tgt_hash_hlist[UBMAD_TGT_HASH_SIZE];
	struct ubmad_tgt_rtbuffer tgt_rt_buffer[UBMAD_TGT_RTBUFFER_SIZE];

	struct ubmad_jetty_resource *rsrc;
};

/* device */
// device contains resources used inside ubmad, including jetty, seg and etc.
struct ubmad_device_priv {
	struct ubcore_device *device;
	struct kref kref;
	struct list_head node; // g_ubmad_device_list
	struct ubcore_event_handler handler;

	/** resources **/
	bool valid; // following resources inited or not
	struct ubmad_jetty_resource
		jetty_rsrc[UBMAD_WK_JETTY_NUM]; // well-known jetty resource
	/** end of resources **/

	/* reliable communication */
	struct workqueue_struct
		 *rt_wq; // retransmit work queue, only for initiator
	struct ubcore_eid_info eid_info;
	bool has_create_jetty_rsrc;
	struct workqueue_struct *conn_wq;
};

/* agent */
// agent contains resources used between ubmad and ubcm.
struct ubmad_agent_priv {
	struct ubmad_agent agent;
	struct kref kref;
	struct list_head node; // g_ubmad_agent_list
	struct workqueue_struct *jfce_wq_s; // ubmad_jfce_work for Tx
	struct workqueue_struct *jfce_wq_r; // ubmad_jfce_work for Rx
};

/** datapath **/
/* msg */
/*
 * 1. considering 8B alignment, layout is not logical.
 * 2. msg is stored in sge rather than alloc.
 */
struct ubmad_msg {
	uint8_t version;
	uint8_t msg_type; // ubmad_msg_type
	uint16_t payload_len;
	uint32_t reserved; // reserved for 8B aligned

	uint64_t msn; // Message sequence number

	uint8_t payload[];
};

/* poll */
/*
 * msg not processed right after poll jfc in ubmad_jfce_handler(), but tranformed to ubmad_jfce_work
 * and left for workqueue.
 */
enum ubmad_jfce_work_type {
	UBMAD_SEND_WORK,
	UBMAD_RECV_WORK
};

struct ubmad_jfce_work {
	struct work_struct work; // ubmad_agent_priv.jfce_wq
	enum ubmad_jfce_work_type type;

	struct ubcore_jfc *jfc;
	struct ubmad_agent_priv *agent_priv;
};

struct ubmad_jetty_work {
	struct work_struct work;
	struct ubmad_device_priv *dev_priv;
	struct ubmad_jetty_resource *rsrc;
	union ubcore_eid dst_primary_eid;
	struct ubmad_send_buf *send_buf;
};

/** reliable communication **/
/* for initiator (data sender, ack recver) */
// add msn_node to msn_hlist when post and remove when recv ack
struct ubmad_msn_node {
	struct hlist_node node; // ubmad_msn_mgr.msn_hlist
	uint64_t msn;
};

/* try to find msn_node in msn_hlist when timeout. If find, repost and re-add work,
 * else indicating already ack, free work.
 */
struct ubmad_rt_work {
	struct delayed_work delay_work; // ubmad_device_priv.rt_wq

	uint64_t msn;
	uint32_t rt_cnt; /* Retry count, no larger than UBMAD_MAX_RETRY_CNT */
	struct ubmad_msn_mgr *msn_mgr;
	struct ubmad_jetty_resource *rsrc;
	union ubcore_eid dst;
	struct workqueue_struct *rt_wq;
};

/* common */
struct ubmad_bitmap *ubmad_create_bitmap(uint32_t bitmap_size);
void ubmad_destroy_bitmap(struct ubmad_bitmap *bitmap);
uint32_t ubmad_bitmap_get_id(struct ubmad_bitmap *bitmap);
int ubmad_bitmap_put_id(struct ubmad_bitmap *bitmap, uint32_t id);
bool ubmad_bitmap_test_id(struct ubmad_bitmap *bitmap, uint32_t id);
int ubmad_bitmap_set_id(struct ubmad_bitmap *bitmap, uint32_t id);

/* jetty */
struct ubmad_tjetty *ubmad_get_tjetty(union ubcore_eid *dst_eid,
				      struct ubmad_jetty_resource *rsrc);
void ubmad_put_tjetty(struct ubmad_tjetty *tjetty);

struct ubmad_tjetty *ubmad_import_jetty(struct ubcore_device *device,
					struct ubmad_jetty_resource *rsrc,
					union ubcore_eid *dst_eid);

struct ubmad_jetty_resource *
ubmad_get_jetty_rsrc_by_jfc_s(struct ubmad_device_priv *dev_priv,
			      struct ubcore_jfc *jfc_s);
struct ubmad_jetty_resource *
ubmad_get_jetty_rsrc_by_jfc_r(struct ubmad_device_priv *dev_priv,
			      struct ubcore_jfc *jfc_r);

void ubmad_remove_tjetty(union ubcore_eid *seid,
			 struct ubmad_jetty_resource *rsrc);

/* device */
struct ubmad_device_priv *ubmad_get_device_priv(struct ubcore_device *device);
void ubmad_put_device_priv(struct ubmad_device_priv *dev_priv);

/* agent */
struct ubmad_agent_priv *ubmad_get_agent_priv(struct ubcore_device *device);
void ubmad_put_agent_priv(struct ubmad_agent_priv *agent_priv);

/** datapath **/
/* reliable communication */
void ubmad_init_msn_mgr(struct ubmad_msn_mgr *msn_mgr);
void ubmad_uninit_msn_mgr(struct ubmad_msn_mgr *msn_mgr);

/* post */
void ubmad_post_send_close_req(struct ubmad_jetty_resource *rsrc,
			       struct ubcore_tjetty *tjetty);

int ubmad_post_recv(struct ubmad_jetty_resource *rsrc);

/* poll */
void ubmad_jfce_handler_s(struct ubcore_jfc *jfc);
void ubmad_jfce_handler_r(struct ubcore_jfc *jfc);

#endif /* UB_MAD_PRIV_H */
