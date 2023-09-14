/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: Types definition provided by ubcore to client and ubep device
 * Author: Qian Guoxin, Ouyang Changchun
 * Create: 2021-8-3
 * Note:
 * History: 2021-8-3: Create file
 * History: 2021-11-23: Add segment and jetty management
 */

#ifndef UBCORE_TYPES_H
#define UBCORE_TYPES_H

#include <linux/list.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <urma/ubcore_opcode.h>

#define UBCORE_MAX_DEV_NAME 64
#define UBCORE_MAX_DRIVER_NAME 64
#define UBCORE_HASH_TABLE_SIZE 64
#define UBCORE_NET_ADDR_BYTES (16)
#define UBCORE_MAC_BYTES 6
#define UBCORE_MAX_ATTR_GROUP 3
#define UBCORE_EID_SIZE (16)
#define UBCORE_EID_STR_LEN (39)
#define EID_FMT                                                                                    \
	"%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x"
#define EID_UNPACK(...) __VA_ARGS__
#define EID_RAW_ARGS(eid) EID_UNPACK(eid[0], eid[1], eid[2], eid[3], eid[4], eid[5], eid[6],	\
	eid[7], eid[8], eid[9], eid[10], eid[11], eid[12], eid[13], eid[14], eid[15])
#define EID_ARGS(eid) EID_RAW_ARGS((eid).raw)

enum ubcore_transport_type {
	UBCORE_TRANSPORT_INVALID = -1,
	UBCORE_TRANSPORT_UB,
	UBCORE_TRANSPORT_IB,
	UBCORE_TRANSPORT_IP,
	UBCORE_TRANSPORT_MAX
};

#define UBCORE_ACCESS_LOCAL_WRITE (0x1 << 0)
#define UBCORE_ACCESS_REMOTE_READ (0x1 << 1)
#define UBCORE_ACCESS_REMOTE_WRITE (0x1 << 2)
#define UBCORE_ACCESS_REMOTE_ATOMIC (0x1 << 3)
#define UBCORE_ACCESS_REMOTE_INVALIDATE (0x1 << 4)

union ubcore_eid {
	uint8_t raw[UBCORE_EID_SIZE];
	struct {
		uint64_t resv;
		uint32_t prefix;
		uint32_t addr;
	} in4;
	struct {
		uint64_t subnet_prefix;
		uint64_t interface_id;
	} in6;
};

struct ubcore_jetty_id {
	union ubcore_eid eid;
	uint32_t uasid;
	uint32_t id;
};

struct ubcore_ubva {
	union ubcore_eid eid;
	uint32_t uasid;
	uint64_t va;
} __packed;

struct ubcore_ht_param {
	uint32_t size;
	uint32_t node_offset; /* offset of hlist node in the hash table object */
	uint32_t key_offset;
	uint32_t key_size;
	int (*cmp_f)(void *obj, const void *key);
	void (*free_f)(void *obj);
};

struct ubcore_hash_table {
	struct ubcore_ht_param p;
	struct hlist_head *head;
	spinlock_t lock;
	struct kref kref;
};

union ubcore_jfc_flag {
	struct {
		uint32_t lock_free : 1;
		uint32_t jfc_inline : 1;
		uint32_t reserved : 30;
	} bs;
	uint32_t value;
};

union ubcore_jfs_flag {
	struct {
		/* 0: IDC_MODE.
		 * 1: DC_MODE.
		 * 2: LS_MODE
		 */
		uint32_t mode : 2;
		uint32_t lock_free : 1;
		uint32_t reserved : 29;
	} bs;
	uint32_t value;
};

union ubcore_jfr_flag {
	struct {
		uint32_t key_policy : 3;	/* 0: UBCORE_KEY_NONE
						 * 1: UBCORE_KEY_PLAIN_TEXT
						 * 2: UBCORE_KEY_SIGNED
						 * 3: UBCORE_KEY_ALL_ENCRYPTED
						 * 4: UBCORE_KEY_RESERVED
						 */
		uint32_t tag_matching : 1;
		uint32_t lock_free : 1;
		uint32_t reserved : 27;
	} bs;
	uint32_t value;
};

enum ubcore_jfc_attr_mask {
	UBCORE_JFC_MODERATE_COUNT = 0x1,
	UBCORE_JFC_MODERATE_PERIOD = 0x1 << 1
};

struct ubcore_jfc_attr {
	uint32_t mask; /* mask value refer to enum ubcore_jfc_attr_mask */
	uint16_t moderate_count;
	uint16_t moderate_period; /* in micro seconds */
};

enum ubcore_jfc_state {
	UBCORE_JFC_STATE_INVALID = 0,
	UBCORE_JFC_STATE_VALID,
	UBCORE_JFC_STATE_ERROR
};

enum ubcore_jetty_state {
	UBCORE_JETTY_STATE_RESET = 0,
	UBCORE_JETTY_STATE_READY,
	UBCORE_JETTY_STATE_SUSPENDED,
	UBCORE_JETTY_STATE_ERROR
};

struct ubcore_jfs_attr {
	uint32_t mask; /* mask value refer to ubcore_jfs_attr_mask_t */
	enum ubcore_jetty_state state;
};

enum ubcore_jfr_attr_mask { UBCORE_JFR_RX_THRESHOLD = 0x1 };

struct ubcore_jfr_attr {
	uint32_t mask; /* mask value refer to enum ubcore_jfr_attr_mask */
	uint32_t rx_threshold;
};

enum ubcore_jetty_attr_mask { UBCORE_JETTY_RX_THRESHOLD = 0x1 };

struct ubcore_jetty_attr {
	uint32_t mask; /* mask value refer to enum ubcore_jetty_attr_mask */
	uint32_t rx_threshold;
	enum ubcore_jetty_state state;
};

union ubcore_import_seg_flag {
	struct {
		uint32_t cacheable : 1;
		uint32_t access : 6;
		uint32_t mapping : 1;
		uint32_t reserved : 24;
	} bs;
	uint32_t value;
};

union ubcore_reg_seg_flag {
	struct {
		uint32_t key_policy : 3;
		uint32_t cacheable : 1;
		uint32_t dsva : 1;
		uint32_t access : 6;
		uint32_t non_pin : 1;
		uint32_t user_iova : 1;
		uint32_t reserved : 19;
	} bs;
	uint32_t value;
};

struct ubcore_udrv_priv {
	uint64_t in_addr;
	uint32_t in_len;
	uint64_t out_addr;
	uint32_t out_len;
};

struct ubcore_ucontext {
	struct ubcore_device *ub_dev;
	uint32_t uasid;
	void *jfae; /* jfae uobj */
	atomic_t use_cnt;
};

struct ubcore_udata {
	struct ubcore_ucontext *uctx;
	struct ubcore_udrv_priv *udrv_data;
};

struct ubcore_jfc;
typedef void (*ubcore_comp_callback_t)(struct ubcore_jfc *jfc);

enum ubcore_event_type {
	UBCORE_EVENT_JFC_ERR,
	UBCORE_EVENT_JFS_FATAL,
	UBCORE_EVENT_JFS_ACCESS_ERR,
	UBCORE_EVENT_JFR_FATAL,
	UBCORE_EVENT_JFR_ACCESS_ERR,
	UBCORE_EVENT_JETTY_FATAL,
	UBCORE_EVENT_JETTY_ACCESS_ERR,
	UBCORE_EVENT_PORT_ACTIVE,
	UBCORE_EVENT_PORT_ERR,
	UBCORE_EVENT_DEV_FATAL,
	UBCORE_EVENT_ID_CHANGE,
	UBCORE_EVENT_TP_ERR
};

struct ubcore_event {
	struct ubcore_device *ub_dev;
	union {
		struct ubcore_jfc *jfc;
		struct ubcore_jfs *jfs;
		struct ubcore_jfr *jfr;
		struct ubcore_jetty *jetty;
		struct ubcore_tp *tp;
		uint32_t port_id;
	} element;
	enum ubcore_event_type event_type;
};

typedef void (*ubcore_event_callback_t)(struct ubcore_event *event, struct ubcore_ucontext *ctx);

struct ubcore_event_handler {
	void (*event_callback)(struct ubcore_event *event, struct ubcore_event_handler *handler);
	struct list_head node;
};

struct ubcore_jfc_cfg {
	uint32_t depth;
	union ubcore_jfc_flag flag;
	void *jfc_context;
	uint32_t eq_id;
};

struct ubcore_jfc {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	struct ubcore_jfc_cfg jfc_cfg;
	uint32_t id; /* allocated by driver */
	ubcore_comp_callback_t jfce_handler;
	ubcore_event_callback_t jfae_handler;
	uint64_t urma_jfc; /* user space jfc pointer */
	struct hlist_node hnode;
	atomic_t use_cnt;
};

/* transport mode */
enum ubcore_transport_mode {
	UBCORE_TP_RM = 0x1, /* Reliable message */
	UBCORE_TP_RC = 0x1 << 1, /* Reliable connection */
	UBCORE_TP_UM = 0x1 << 2 /* Unreliable message */
};

struct ubcore_jfs_cfg {
	uint32_t depth;
	union ubcore_jfs_flag flag;
	uint8_t priority;
	uint8_t max_sge;
	uint8_t max_rsge;
	uint32_t max_inline_data;
	uint8_t retry_cnt;
	uint8_t rnr_retry;
	uint8_t err_timeout;
	void *jfs_context;
	struct ubcore_jfc *jfc;
	enum ubcore_transport_mode trans_mode;
};

struct ubcore_jfs {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	struct ubcore_jfs_cfg jfs_cfg;
	uint32_t id; /* allocted by driver */
	ubcore_event_callback_t jfae_handler;
	uint64_t urma_jfs; /* user space jfs pointer */
	struct hlist_node hnode;
	atomic_t use_cnt;
	struct ubcore_hash_table *tptable; /* Only for devices not natively supporting RM mode */
};

struct ubcore_key {
	uint32_t key;
};

struct ubcore_jfr_cfg {
	uint32_t id; /* user may assign id */
	uint32_t depth;
	union ubcore_jfr_flag flag;
	uint8_t max_sge;
	uint8_t min_rnr_timer;
	enum ubcore_transport_mode trans_mode;
	struct ubcore_jfc *jfc;
	struct ubcore_key ukey;
	void *jfr_context;
};

struct ubcore_jfr {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	struct ubcore_jfr_cfg jfr_cfg;
	uint32_t id; /* allocted by driver */
	ubcore_event_callback_t jfae_handler;
	uint64_t urma_jfr; /* user space jfr pointer */
	struct hlist_node hnode;
	atomic_t use_cnt;
	struct ubcore_hash_table *tptable; /* Only for devices not natively supporting RM mode */
};

union ubcore_jetty_flag {
	struct {
		uint32_t share_jfr : 1; /* 0: URMA_NO_SHARE_JFR.
					 * 1: URMA_SHARE_JFR.
					 */
		uint32_t reserved : 31;
	} bs;
	uint32_t value;
};

struct ubcore_jetty_cfg {
	uint32_t id; /* user may assign id */
	uint32_t jfs_depth;
	uint32_t jfr_depth;
	union ubcore_jetty_flag flag;
	struct ubcore_jfc *send_jfc;
	struct ubcore_jfc *recv_jfc;
	struct ubcore_jfr *jfr; /* shared jfr */
	uint8_t max_send_sge;
	uint8_t max_send_rsge;
	uint8_t max_recv_sge;
	uint32_t max_inline_data;
	uint8_t priority;
	uint8_t retry_cnt;
	uint8_t rnr_retry;
	uint8_t err_timeout;
	uint8_t min_rnr_timer;
	enum ubcore_transport_mode trans_mode;
	struct ubcore_key ukey;
	void *jetty_context;
};

struct ubcore_tjetty_cfg {
	struct ubcore_jetty_id id; /* jfr, jetty or jetty group id to be imported */
	enum ubcore_transport_mode trans_mode;
	struct ubcore_key ukey; /* jfr, jetty or jetty group ukey value to be imported */
};

enum ubcore_target_type { UBCORE_JFR = 0, UBCORE_JETTY, UBCORE_JFR_GROUP, UBCORE_JETTY_GROUP };

struct ubcore_tjetty {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	enum ubcore_target_type type;
	struct ubcore_tjetty_cfg cfg;
	struct ubcore_tp *tp; /* for UB transport device  */
	atomic_t use_cnt;
	struct mutex lock;
};

struct ubcore_jetty {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	struct ubcore_jetty_cfg jetty_cfg;
	uint32_t id; /* allocted by driver */
	struct ubcore_tjetty *remote_jetty; // bind to remote jetty
	ubcore_event_callback_t jfae_handler;
	uint64_t urma_jetty; /* user space jetty pointer */
	struct hlist_node hnode;
	atomic_t use_cnt;
	struct ubcore_hash_table *tptable; /* Only for devices not natively supporting RM mode */
};

struct ubcore_key_id {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	uint32_t key_id;
	atomic_t use_cnt;
};

struct ubcore_seg_cfg {
	uint64_t va;
	uint64_t len;
	struct ubcore_key_id *keyid;
	struct ubcore_key ukey;
	union ubcore_reg_seg_flag flag;
	uint64_t iova;
};

union ubcore_seg_attr {
	struct {
		uint32_t key_policy : 3;
		uint32_t cacheable : 1;
		uint32_t dsva : 1;
		uint32_t access : 6;
		uint32_t non_pin : 1;
		uint32_t user_iova : 1;
		uint32_t reserved : 19;
	} bs;
	uint32_t value;
};

struct ubcore_seg {
	struct ubcore_ubva ubva;
	uint64_t len;
	union ubcore_seg_attr attr;
	uint32_t key_id;
};

struct ubcore_target_seg_cfg {
	struct ubcore_seg seg;
	union ubcore_import_seg_flag flag;
	uint64_t mva; /* optional */
	struct ubcore_key ukey;
};

struct ubcore_target_seg {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	struct ubcore_seg seg;
	uint64_t mva;
	struct ubcore_key_id *keyid;
	atomic_t use_cnt;
};

enum ubcore_mtu {
	UBCORE_MTU_256 = 1,
	UBCORE_MTU_512,
	UBCORE_MTU_1024,
	UBCORE_MTU_2048,
	UBCORE_MTU_4096,
	UBCORE_MTU_8192
};

struct ubcore_device_attr {
	union ubcore_eid eid; // RW
	uint32_t max_eid_cnt;
};

union ubcore_device_cfg_mask {
	struct {
		uint32_t port_ets : 1;
		uint32_t port_fec : 1;
	} bs;
	uint32_t value;
};

struct ubcore_congestion_control {
	uint32_t data;
};

struct ubcore_port_ets {
	uint32_t data;
};

struct ubcore_port_fec {
	uint32_t data;
};

struct ubcore_device_cfg {
	union ubcore_device_cfg_mask mask;
	struct ubcore_port_fec fec;
	struct ubcore_port_ets ets;
};

struct ubcore_net_addr {
	union {
		uint8_t raw[UBCORE_NET_ADDR_BYTES];
		struct {
			uint64_t resv1;
			uint32_t resv2;
			uint32_t addr;
		} in4;
		struct {
			uint64_t subnet_prefix;
			uint64_t interface_id;
		} in6;
	} net_addr;
	uint64_t vlan; /* available for UBOE */
	uint8_t mac[UBCORE_MAC_BYTES]; /* available for UBOE */
};

union ubcore_tp_cfg_flag {
	struct {
		uint32_t target : 1; /* 0: initiator, 1: target */
		uint32_t oor_en : 1; /* out of order receive, 0: disable 1: enable */
		uint32_t sr_en : 1; /* selective retransmission, 0: disable 1: enable */
		uint32_t cc_en : 1; /* congestion control algorithm, 0: disable 1: enable */
		uint32_t spray_en : 1; /* spray with src udp port, 0: disable 1: enable */
		uint32_t reserved : 27;
	} bs;
	uint32_t value;
};

union ubcore_tp_mod_flag {
	struct {
		uint32_t oor_en : 1; /* out of order receive, 0: disable 1: enable */
		uint32_t sr_en : 1; /* selective retransmission, 0: disable 1: enable */
		uint32_t cc_en : 1; /* congestion control algorithm, 0: disable 1: enable */
		uint32_t cc_alg : 4; /* The value is enum ubcore_tp_cc_alg */
		uint32_t spray_en : 1; /* spray with src udp port, 0: disable 1: enable */
		uint32_t reserved : 24;
	} bs;
	uint32_t value;
};

/* The first bits must be consistent with union ubcore_tp_cfg_flag */
union ubcore_tp_flag {
	struct {
		uint32_t target : 1; /* 0: initiator, 1: target */
		uint32_t oor_en : 1; /* out of order receive, 0: disable 1: enable */
		uint32_t sr_en : 1; /* selective retransmission, 0: disable 1: enable */
		uint32_t cc_en : 1; /* congestion control algorithm, 0: disable 1: enable */
		uint32_t cc_alg : 4; /* The value is enum ubcore_tp_cc_alg */
		uint32_t spray_en : 1; /* spray with src udp port, 0: disable 1: enable */
		uint32_t reserved : 23;
	} bs;
	uint32_t value;
};

enum ubcore_tp_state {
	UBCORE_TP_STATE_RESET = 0,
	UBCORE_TP_STATE_RTR,
	UBCORE_TP_STATE_RTS,
	UBCORE_TP_STATE_ERROR
};

enum ubcore_ta_type {
	UBCORE_TA_NONE = 0,
	UBCORE_TA_JFS_TJFR,
	UBCORE_TA_JETTY_TJETTY,
	UBCORE_TA_VIRT /* virtualization */
};

struct ubcore_ta {
	enum ubcore_ta_type type;
	union {
		struct ubcore_jfs *jfs;
		struct ubcore_jfr *jfr;
		struct ubcore_jetty *jetty;
	};
	struct ubcore_jetty_id tjetty_id; /* peer jetty id */
};

struct ubcore_tp_cfg {
	struct ubcore_ta *ta; /* NULL for UB device */
	union ubcore_tp_cfg_flag flag; /* indicate initiator or target, etc */
	struct ubcore_net_addr local_net_addr;
	struct ubcore_net_addr peer_net_addr;
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	enum ubcore_transport_mode trans_mode;
	uint32_t rx_psn;
	enum ubcore_mtu mtu;
	uint16_t data_udp_start; /* src udp port start, for multipath data */
	uint16_t ack_udp_start; /* src udp port start, for multipath ack */
	uint8_t udp_range; /* src udp port range, for both multipath data and ack */
	uint8_t retry_num;
	uint8_t ack_timeout;
	uint8_t tc; /* traffic class */
};

struct ubcore_tp_ext {
	uint64_t addr;
	uint32_t len;
};

union ubcore_tp_attr_mask {
	struct {
		uint32_t flag : 1;
		uint32_t peer_tpn : 1;
		uint32_t state : 1;
		uint32_t tx_psn : 1;
		uint32_t rx_psn : 1; /* modify both rx psn and tx psn when restore tp */
		uint32_t mtu : 1;
		uint32_t cc_pattern_idx : 1;
		uint32_t peer_ext : 1;
		uint32_t reserved : 24;
	} bs;
	uint32_t value;
};

struct ubcore_tp_attr {
	union ubcore_tp_mod_flag flag;
	uint32_t peer_tpn;
	enum ubcore_tp_state state;
	uint32_t tx_psn;
	uint32_t rx_psn; /* modify both rx psn and tx psn when restore tp */
	enum ubcore_mtu mtu;
	uint8_t cc_pattern_idx;
	struct ubcore_tp_ext peer_ext;
};

struct ubcore_tp {
	uint32_t tpn; /* driver assgined in creating tp */
	uint32_t peer_tpn;
	struct ubcore_device *ub_dev;
	union ubcore_tp_flag flag; /* indicate initiator or target, etc */
	struct ubcore_net_addr local_net_addr;
	struct ubcore_net_addr peer_net_addr;
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	enum ubcore_transport_mode trans_mode;
	enum ubcore_tp_state state;
	uint32_t rx_psn;
	uint32_t tx_psn;
	enum ubcore_mtu mtu;
	uint16_t data_udp_start; /* src udp port start, for multipath data */
	uint16_t ack_udp_start; /* src udp port start, for multipath ack */
	uint8_t udp_range; /* src udp port range, for both multipath data and ack */
	uint8_t retry_num;
	uint8_t ack_timeout;
	uint8_t tc; /* traffic class */
	uint8_t cc_pattern_idx;
	struct ubcore_tp_ext tp_ext; /* driver fill in creating tp */
	struct ubcore_tp_ext peer_ext; /* ubcore fill before modifying tp */
	atomic_t use_cnt;
	void *priv; /* ubcore private data for tp management */
};

union ubcore_jfs_wr_flag {
	struct {
		uint32_t place_order : 2;	/* 0: There is no order with other WR.
						 * 1: relax order.
						 * 2: strong order.
						 * 3: reserve.
						 */
		uint32_t comp_order : 1;	/* 0: There is no completion order with other WR
						 * 1: Completion order with previous WR.
						 */

		uint32_t fence : 1;		/* 0: There is no fence.
						 * 1: Fence with previous read and atomic WR
						 */
		uint32_t solicited_enable : 1;	/* 0: not solicited.
						 * 1: solicited. It will trigger an event
						 * on remote side
						 */
		uint32_t complete_enable : 1;	/* 0: Do not notify local process
						 * after the task is complete.
						 * 1: Notify local process
						 * after the task is completed.
						 */
		uint32_t inline_flag : 1;	/* 0: No inline.
						 * 1: Inline data.
						 */
		uint32_t reserved : 25;
	} bs;
	uint32_t value;
};

struct ubcore_sge {
	uint64_t addr;
	uint32_t len;
	struct ubcore_target_seg *tseg;
};

struct ubcore_sg {
	struct ubcore_sge *sge;
	uint32_t num_sge;
};

struct ubcore_rw_wr {
	struct ubcore_sg src;
	struct ubcore_sg dst;
	struct ubcore_tjetty *tjetty; /* For write imm */
	uint64_t notify_data; /* notify data or immeditate data in host byte order */
};

struct ubcore_send_wr {
	struct ubcore_sg src;
	struct ubcore_tjetty *tjetty;
	uint8_t target_hint; /* hint of jetty in a target jetty group */
	uint64_t imm_data; /* immeditate data in host byte order */
	struct ubcore_target_seg *tseg; /* Used only when send with invalidate */
};

struct ubcore_cas_wr {
	struct ubcore_sge *dst; /* len must be less or equal to 8 Bytes */
	struct ubcore_sge *src; /* Local address for destination original value written back */
	uint64_t cmp_data; /* Value compared with destination value */
	uint64_t swap_data;	/* If destination value is the same as cmp_data,
				 * destination value will be change to swap_data
				 */
};

struct ubcore_cas_mask_wr {
	struct ubcore_cas_wr cas;
	uint64_t cmp_msk;
	uint64_t swap_msk;
};

struct ubcore_faa_wr {
	struct ubcore_sge *dst; /* len in the sge is the length of faa at remote side */
	struct ubcore_sge *src; /* Local address for destination original value written back */
	uint64_t operand; /* Addend */
};

struct ubcore_faa_mask_wr {
	struct ubcore_faa_wr faa;
	uint64_t msk;
};

struct ubcore_jfs_wr {
	enum ubcore_opcode opcode;
	union ubcore_jfs_wr_flag flag;
	uintptr_t user_ctx;
	union {
		struct ubcore_rw_wr rw;
		struct ubcore_send_wr send;
		struct ubcore_cas_wr cas;
		struct ubcore_cas_mask_wr cas_mask;
		struct ubcore_faa_wr faa;
		struct ubcore_faa_mask_wr faa_mask;
	};
	struct ubcore_jfs_wr *next;
};

struct ubcore_jfr_wr {
	struct ubcore_sg src;
	uintptr_t user_ctx;
	struct ubcore_jfr_wr *next;
};

union ubcore_cr_flag {
	struct {
		uint8_t inline_flag : 1; /* Indicate CR contains inline data or not */
		uint8_t s_r : 1; /* Indicate CR stands for sending or receiving */
		uint8_t jetty : 1;	/* Indicate local_id or remote_id
					 * in the CR stands for jetty or JFS/JFR
					 */
	} bs;
	uint8_t value;
};

struct ubcore_cr {
	enum ubcore_cr_status status;
	uintptr_t user_ctx;
	enum ubcore_cr_opcode opcode;
	union ubcore_cr_flag flag;
	uint32_t completion_len; /* The number of bytes transferred */
	uint32_t local_id; /* Local jetty ID, or JFS ID, or JFR ID, depending on flag */
	struct ubcore_jetty_id remote_id;	/* Valid only for receiving CR.
						 * The remote jetty where received msg comes from,
						 * may be jetty ID or JFS ID, depending on flag
						 */
	uint64_t imm_data; /* Valid only for received CR */
	uint32_t tpn;
	uintptr_t user_data; /* Use as pointer to local jetty struct */
};

enum ubcore_stats_key_type {
	UBCORE_STATS_KEY_TP = 1,
	UBCORE_STATS_KEY_TPG = 2,
	UBCORE_STATS_KEY_JFS = 3,
	UBCORE_STATS_KEY_JFR = 4,
	UBCORE_STATS_KEY_JETTY = 5,
	UBCORE_STATS_KEY_JETTY_GROUP = 6
};

struct ubcore_stats_key {
	uint8_t type; /* stats type, refer to enum ubcore_stats_key_type */
	uint32_t key; /* key can be tpn/tpgn/jetty_id/token_id/ctx_id/etc */
};

struct ubcore_stats_com_val {
	uint64_t tx_pkt;
	uint64_t rx_pkt;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint64_t tx_pkt_err;
	uint64_t rx_pkt_err;
};

struct ubcore_stats_val {
	uint64_t addr; /* this addr is alloc and free by ubcore,
			* refer to struct ubcore_stats_com_val
			*/

	uint32_t len;	/* [in/out] real length filled when success
			 * to query and buffer length enough;
			 * expected length filled and return failure when buffer length not enough
			 */
};

struct ubcore_device;
struct ubcore_ops {
	struct module *owner; /* kernel driver module */
	char driver_name[UBCORE_MAX_DRIVER_NAME]; /* user space driver name */
	uint32_t abi_version; /* abi version of kernel driver */
	/**
	 * set function entity id for ub device. must be called before alloc context
	 * @param[in] dev: the ub device handle;
	 * @param[in] eid: function entity id (eid) to set;
	 * @return: 0 on success, other value on error
	 */
	int (*set_eid)(struct ubcore_device *dev, union ubcore_eid eid);
	/**
	 * query device attributes
	 * @param[in] dev: the ub device handle;
	 * @param[out] attr: attributes for the driver to fill in
	 * @return: 0 on success, other value on error
	 */
	int (*query_device_attr)(struct ubcore_device *dev, struct ubcore_device_attr *attr);
	/**
	 * config device
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: device configuration
	 * @return: 0 on success, other value on error
	 */
	int (*config_device)(struct ubcore_device *dev, const struct ubcore_device_cfg *cfg);
	/**
	 * set ub network address
	 * @param[in] dev: the ub device handle;
	 * @param[in] net_addr: net_addr to set
	 * @return: 0 on success, other value on error
	 */
	int (*set_net_addr)(struct ubcore_device *dev, const struct ubcore_net_addr *net_addr);
	/**
	 * unset ub network address
	 * @param[in] dev: the ub device handle;
	 * @param[in] net_addr: net_addr to unset
	 * @return: 0 on success, other value on error
	 */
	int (*unset_net_addr)(struct ubcore_device *dev, const struct ubcore_net_addr *net_addr);
	/**
	 * allocate a context from ubep for a user process
	 * @param[in] dev: the ub device handle;
	 * @param[in] uasid: uasid for the context to be allocated
	 * @param[in] udrv_data: user space driver data
	 * @return: pointer to user context on success, null or error,
	 */
	struct ubcore_ucontext *(*alloc_ucontext)(struct ubcore_device *dev, uint32_t uasid,
						  struct ubcore_udrv_priv *udrv_data);
	/**
	 * free a context to ubep
	 * @param[in] uctx: the user context created before;
	 * @return: 0 on success, other value on error
	 */
	int (*free_ucontext)(struct ubcore_ucontext *uctx);
	/**
	 * mmap doorbell or jetty buffer, etc
	 * @param[in] uctx: the user context created before;
	 * @param[in] vma: linux vma including vm_start, vm_pgoff, etc;
	 * @return: 0 on success, other value on error
	 */
	int (*mmap)(struct ubcore_ucontext *ctx, struct vm_area_struct *vma);

	/* segment part */
	/** alloc key id to ubep
	 * @param[in] dev: the ub device handle;
	 * @param[in] udata: ucontext and user space driver data
	 * @return: key id pointer on success, NULL on error
	 */
	struct ubcore_key_id *(*alloc_key_id)(struct ubcore_device *dev,
					      struct ubcore_udata *udata);

	/** free key id from ubep
	 * @param[in] key_id: the key id alloced before;
	 * @return: 0 on success, other value on error
	 */
	int (*free_key_id)(struct ubcore_key_id *key_id);

	/** register segment to ubep
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: segment attributes and configurations
	 * @param[in] udata: ucontext and user space driver data
	 * @return: target segment pointer on success, NULL on error
	 */
	struct ubcore_target_seg *(*register_seg)(struct ubcore_device *dev,
						  const struct ubcore_seg_cfg *cfg,
						  struct ubcore_udata *udata);

	/** unregister segment from ubep
	 * @param[in] tseg: the segment registered before;
	 * @return: 0 on success, other value on error
	 */
	int (*unregister_seg)(struct ubcore_target_seg *tseg);

	/** import a remote segment to ubep
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: segment attributes and import configurations
	 * @param[in] udata: ucontext and user space driver data
	 * @return: target segment handle on success, NULL on error
	 */
	struct ubcore_target_seg *(*import_seg)(struct ubcore_device *dev,
						const struct ubcore_target_seg_cfg *cfg,
						struct ubcore_udata *udata);

	/** unimport seg from ubep
	 * @param[in] tseg: the segment imported before;
	 * @return: 0 on success, other value on error
	 */
	int (*unimport_seg)(struct ubcore_target_seg *tseg);

	/* jetty part */
	/**
	 * create jfc with ubep.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: jfc attributes and configurations
	 * @param[in] udata: ucontext and user space driver data
	 * @return: jfc pointer on success, NULL on error
	 */
	struct ubcore_jfc *(*create_jfc)(struct ubcore_device *dev,
					 const struct ubcore_jfc_cfg *cfg,
					 struct ubcore_udata *udata);

	/**
	 * modify jfc from ubep.
	 * @param[in] jfc: the jfc created before;
	 * @param[in] attr: ubcore jfc attr;
	 * @param[in] udata: ucontext and user space driver data
	 * @return: 0 on success, other value on error
	 */
	int (*modify_jfc)(struct ubcore_jfc *jfc, const struct ubcore_jfc_attr *attr,
			  struct ubcore_udata *udata);

	/**
	 * destroy jfc from ubep.
	 * @param[in] jfc: the jfc created before;
	 * @return: 0 on success, other value on error
	 */
	int (*destroy_jfc)(struct ubcore_jfc *jfc);

	/**
	 * rearm jfc.
	 * @param[in] jfc: the jfc created before;
	 * @param[in] solicited_only: rearm notify by message marked with solicited flag
	 * @return: 0 on success, other value on error
	 */
	int (*rearm_jfc)(struct ubcore_jfc *jfc, bool solicited_only);

	/**
	 * create jfs with ubep.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: jfs attributes and configurations
	 * @param[in] udata: ucontext and user space driver data
	 * @return: jfs pointer on success, NULL on error
	 */
	struct ubcore_jfs *(*create_jfs)(struct ubcore_device *dev,
					 const struct ubcore_jfs_cfg *cfg,
					 struct ubcore_udata *udata);
	/**
	 * modify jfs from ubep.
	 * @param[in] jfs: the jfs created before;
	 * @param[in] attr: ubcore jfs attr;
	 * @param[in] udata: ucontext and user space driver data
	 * @return: 0 on success, other value on error
	 */
	int (*modify_jfs)(struct ubcore_jfs *jfs, const struct ubcore_jfs_attr *attr,
			  struct ubcore_udata *udata);
	/**
	 * query jfs from ubep.
	 * @param[in] jfs: the jfs created before;
	 * @param[out] cfg: jfs configurations;
	 * @param[out] attr: ubcore jfs attributes;
	 * @return: 0 on success, other value on error
	 */
	int (*query_jfs)(struct ubcore_jfs *jfs, struct ubcore_jfs_cfg *cfg,
			 struct ubcore_jfs_attr *attr);
	/**
	 * destroy jfs from ubep.
	 * @param[in] jfs: the jfs created before;
	 * @return: 0 on success, other value on error
	 */
	int (*destroy_jfs)(struct ubcore_jfs *jfs);
	/**
	 * flush jfs from ubep.
	 * @param[in] jfs: the jfs created before;
	 * @param[in] cr_cnt: the maximum number of CRs expected to be returned;
	 * @param[out] cr: the addr of returned CRs;
	 * @return: the number of completion record returned,
	 * 0 means no completion record returned, -1 on error
	 */
	int (*flush_jfs)(struct ubcore_jfs *jfs, int cr_cnt, struct ubcore_cr *cr);

	/**
	 * create jfr with ubep.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: jfr attributes and configurations
	 * @param[in] udata: ucontext and user space driver data
	 * @return: jfr pointer on success, NULL on error
	 */
	struct ubcore_jfr *(*create_jfr)(struct ubcore_device *dev,
					 const struct ubcore_jfr_cfg *cfg,
					 struct ubcore_udata *udata);
	/**
	 * modify jfr from ubep.
	 * @param[in] jfr: the jfr created before;
	 * @param[in] attr: ubcore jfr attr;
	 * @param[in] udata: ucontext and user space driver data
	 * @return: 0 on success, other value on error
	 */
	int (*modify_jfr)(struct ubcore_jfr *jfr, const struct ubcore_jfr_attr *attr,
			  struct ubcore_udata *udata);
	/**
	 * query jfr from ubep.
	 * @param[in] jfr: the jfr created before;
	 * @param[out] cfg: jfr configurations;
	 * @param[out] attr: ubcore jfr attributes;
	 * @return: 0 on success, other value on error
	 */
	int (*query_jfr)(struct ubcore_jfr *jfr, struct ubcore_jfr_cfg *cfg,
			 struct ubcore_jfr_attr *attr);
	/**
	 * destroy jfr from ubep.
	 * @param[in] jfr: the jfr created before;
	 * @return: 0 on success, other value on error
	 */
	int (*destroy_jfr)(struct ubcore_jfr *jfr);

	/**
	 * import jfr to ubep.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: remote jfr attributes and import configurations
	 * @param[in] udata: ucontext and user space driver data
	 * @return: target jfr pointer on success, NULL on error
	 */
	struct ubcore_tjetty *(*import_jfr)(struct ubcore_device *dev,
					    const struct ubcore_tjetty_cfg *cfg,
					    struct ubcore_udata *udata);
	/**
	 * unimport jfr from ubep.
	 * @param[in] tjfr: the target jfr imported before;
	 * @return: 0 on success, other value on error
	 */
	int (*unimport_jfr)(struct ubcore_tjetty *tjfr);

	/**
	 * create jetty with ubep.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: jetty attributes and configurations
	 * @param[in] udata: ucontext and user space driver data
	 * @return: jetty pointer on success, NULL on error
	 */
	struct ubcore_jetty *(*create_jetty)(struct ubcore_device *dev,
					     const struct ubcore_jetty_cfg *cfg,
					     struct ubcore_udata *udata);
	/**
	 * modify jetty from ubep.
	 * @param[in] jetty: the jetty created before;
	 * @param[in] attr: ubcore jetty attr;
	 * @param[in] udata: ucontext and user space driver data
	 * @return: 0 on success, other value on error
	 */
	int (*modify_jetty)(struct ubcore_jetty *jetty, const struct ubcore_jetty_attr *attr,
			    struct ubcore_udata *udata);
	/**
	 * query jetty from ubep.
	 * @param[in] jetty: the jetty created before;
	 * @param[out] cfg: jetty configurations;
	 * @param[out] attr: ubcore jetty attributes;
	 * @return: 0 on success, other value on error
	 */
	int (*query_jetty)(struct ubcore_jetty *jetty, struct ubcore_jetty_cfg *cfg,
			   struct ubcore_jetty_attr *attr);
	/**
	 * destroy jetty from ubep.
	 * @param[in] jetty: the jetty created before;
	 * @return: 0 on success, other value on error
	 */
	int (*destroy_jetty)(struct ubcore_jetty *jetty);

	/**
	 * flush jetty from ubep.
	 * @param[in] jetty: the jetty created before;
	 * @param[in] cr_cnt: the maximum number of CRs expected to be returned;
	 * @param[out] cr: the addr of returned CRs;
	 * @return: the number of completion record returned,
	 * 0 means no completion record returned, -1 on error
	 */
	int (*flush_jetty)(struct ubcore_jetty *jetty, int cr_cnt, struct ubcore_cr *cr);

	/**
	 * import jetty to ubep.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: remote jetty attributes and import configurations
	 * @param[in] udata: ucontext and user space driver data
	 * @return: target jetty pointer on success, NULL on error
	 */
	struct ubcore_tjetty *(*import_jetty)(struct ubcore_device *dev,
					      const struct ubcore_tjetty_cfg *cfg,
					      struct ubcore_udata *udata);
	/**
	 * unimport jetty from ubep.
	 * @param[in] tjetty: the target jetty imported before;
	 * @return: 0 on success, other value on error
	 */
	int (*unimport_jetty)(struct ubcore_tjetty *tjetty);

	/** data path ops */
	/**
	 * post jfs wr.
	 * @param[in] jfs: the jfs created before;
	 * @param[in] wr: the wr to be posted;
	 * @param[out] bad_wr: the first failed wr;
	 * @return: 0 on success, other value on error
	 */
	int (*post_jfs_wr)(struct ubcore_jfs *jfs, const struct ubcore_jfs_wr *wr,
			   struct ubcore_jfs_wr **bad_wr);
	/**
	 * post jfr wr.
	 * @param[in] jfr: the jfr created before;
	 * @param[in] wr: the wr to be posted;
	 * @param[out] bad_wr: the first failed wr;
	 * @return: 0 on success, other value on error
	 */
	int (*post_jfr_wr)(struct ubcore_jfr *jfr, const struct ubcore_jfr_wr *wr,
			   struct ubcore_jfr_wr **bad_wr);
	/**
	 * post jetty send wr.
	 * @param[in] jetty: the jetty created before;
	 * @param[in] wr: the wr to be posted;
	 * @param[out] bad_wr: the first failed wr;
	 * @return: 0 on success, other value on error
	 */
	int (*post_jetty_send_wr)(struct ubcore_jetty *jetty, const struct ubcore_jfs_wr *wr,
				  struct ubcore_jfs_wr **bad_wr);
	/**
	 * post jetty receive wr.
	 * @param[in] jetty: the jetty created before;
	 * @param[in] wr: the wr to be posted;
	 * @param[out] bad_wr: the first failed wr;
	 * @return: 0 on success, other value on error
	 */
	int (*post_jetty_recv_wr)(struct ubcore_jetty *jetty, const struct ubcore_jfr_wr *wr,
				  struct ubcore_jfr_wr **bad_wr);
	/**
	 * poll jfc.
	 * @param[in] jfc: the jfc created before;
	 * @param[in] cr_cnt: the maximum number of CRs expected to be polled;
	 * @return: 0 on success, other value on error
	 */
	int (*poll_jfc)(struct ubcore_jfc *jfc, int cr_cnt, struct ubcore_cr *cr);
	/**
	 * query_stats. success to query and buffer length is enough
	 * @param[in] dev: the ub device handle;
	 * @param[in] key: type and key value of the ub device to query;
	 * @param[in/out] val: address and buffer length of query results
	 * @return: 0 on success, other value on error
	 */
	int (*query_stats)(const struct ubcore_device *dev, struct ubcore_stats_key *key,
			   struct ubcore_stats_val *val);
};

struct ubcore_device {
	struct list_head list_node; /* add to device list */

	/* driver fills start */
	char dev_name[UBCORE_MAX_DEV_NAME];

	struct device *dma_dev;
	struct device dev;
	struct net_device *netdev;
	struct ubcore_ops *ops;
	enum ubcore_transport_type transport_type;
	int num_comp_vectors; /* Number of completion interrupt vectors for the device */
	struct ubcore_device_attr attr;
	struct attribute_group *group[UBCORE_MAX_ATTR_GROUP]; /* driver may fill group [1] */
	/* driver fills end */

	struct ubcore_device_cfg cfg;

	/* port management */
	struct kobject *ports_parent; /* kobject parent of the ports in the port list */
	struct list_head port_list;

	/* For ubcore client */
	spinlock_t client_ctx_lock;
	struct list_head client_ctx_list;
	struct list_head event_handler_list;
	spinlock_t event_handler_lock;

	/* protect from unregister device */
	atomic_t use_cnt;
	struct completion comp;
};

struct ubcore_port {
	struct kobject kobj; /* add to port list */
	struct ubcore_device *ub_dev;
	uint32_t port_no;
	struct ubcore_net_addr net_addr;
};

struct ubcore_client {
	struct list_head list_node;
	char *client_name;
	int (*add)(struct ubcore_device *dev);
	void (*remove)(struct ubcore_device *dev, void *client_ctx);
};

struct ubcore_client_ctx {
	struct list_head list_node;
	void *data; // Each ubep device create some data on the client, such as uburma_device.
	struct ubcore_client *client;
};

union ubcore_umem_flag {
	struct {
		uint32_t non_pin : 1;	/* 0: pinned to physical memory.
					 * 1: non pin.
					 */
		uint32_t writable : 1;	/* 0: read-only.
					 * 1: writable.
					 */
		uint32_t reserved : 30;
	} bs;
	uint32_t value;
};

struct ubcore_umem {
	struct ubcore_device *ub_dev;
	struct mm_struct *owning_mm;
	uint64_t length;
	uint64_t va;
	union ubcore_umem_flag flag;
	struct sg_table sg_head;
	uint32_t nmap;
};

#endif
