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

#include <net/net_namespace.h>
#include <linux/list.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/scatterlist.h>
#include <linux/libfdt_env.h>
#include <linux/mm.h>
#include <linux/netdevice.h>
#include <linux/uuid.h>

#ifdef CONFIG_CGROUP_RDMA
#include <linux/cgroup_rdma.h>
#endif

#include <urma/ubcore_opcode.h>

#define UBCORE_GET_VERSION(a, b) (((a) << 16) + ((b) > 65535 ? 65535 : (b)))
#define UBCORE_API_VERSION ((0 << 16) + 9)        // Current Version: 0.9

#define UBCORE_MAX_JETTY_IN_JETTY_GRP 32U // 1650: 32
#define UBCORE_MAX_PORT_CNT 16
#define UBCORE_MAX_FE_CNT 1024
#define UBCORE_MAX_DEV_NAME 64
#define UBCORE_MAX_DRIVER_NAME 64
#define UBCORE_HASH_TABLE_SIZE 10240
#define UBCORE_NET_ADDR_BYTES (16)
#define UBCORE_MAC_BYTES 6
#define UBCORE_MAX_ATTR_GROUP 3
#define UBCORE_EID_SIZE (16)
#define UBCORE_EID_STR_LEN (39)
#define UBCORE_DEVID_SIZE (16)
#define UBCORE_GUID_SIZE (16)
#define UBCORE_MAX_MSG 4096
#define UBCORE_MAX_EID_CNT 1024
#define UBCORE_MAX_VTP_CNT_PER_TPF (128 * 1024) // Temporarily specify the upper limit
#define UBCORE_EID_GROUP_NAME_LEN 10
#define UBCORE_MAX_MIG_ENTRY_CNT 64

#define EID_FMT                           \
	"%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x"
#define EID_UNPACK(...) __VA_ARGS__
#define EID_RAW_ARGS(eid) EID_UNPACK(eid[0], eid[1], eid[2], eid[3], eid[4], eid[5], eid[6],	\
	eid[7], eid[8], eid[9], eid[10], eid[11], eid[12], eid[13], eid[14], eid[15])
#define EID_ARGS(eid) EID_RAW_ARGS((eid).raw)

#define UBCORE_OWN_FE_IDX (0xffff)
#define UBCORE_JETTY_GRP_MAX_NAME 64
#define UBCORE_MAX_TP_CNT_IN_GRP 32
/* support 8 priorities and 8 algorithms */
/* same as URMA_CC_IDX_TABLE_SIZE */
#define UBCORE_CC_IDX_TABLE_SIZE 64
#define UBCORE_SIP_TABLE_SIZE (1024) /* 1823: 16; 1650: 1024; 1636: N/A */
#define UBCORE_MAX_SIP UBCORE_SIP_TABLE_SIZE
#define UBCORE_CHECK_RETURN_ERR_PTR(ptr, err) \
	((ptr) == NULL ? ERR_PTR(-(err)) : (ptr))

#define UBCORE_MAX_DSCP_NUM (64)

enum ubcore_transport_type {
	UBCORE_TRANSPORT_INVALID = -1,
	UBCORE_TRANSPORT_UB      = 0,
	UBCORE_TRANSPORT_IB      = 1,
	UBCORE_TRANSPORT_IP      = 2,
	UBCORE_TRANSPORT_HNS_UB  = 5,
	UBCORE_TRANSPORT_MAX
};

enum ubcore_resource_type {
	UBCORE_RESOURCE_HCA_HANDLE = 0,
	UBCORE_RESOURCE_HCA_OBJECT,
	UBCORE_RESOURCE_HCA_MAX
};

enum ubcore_ldev_attr_group {
	UBCORE_ATTR_GROUP_DEV_DEFAULT = 0,
	UBCORE_ATTR_GROUP_EIDS = 1,
	UBCORE_ATTR_GROUP_NULL = 2,
	UBCORE_ATTR_GROUP_MAX = 3
};

#define UBCORE_ACCESS_LOCAL_WRITE   0x1
#define UBCORE_ACCESS_REMOTE_READ   (0x1 << 1)
#define UBCORE_ACCESS_REMOTE_WRITE  (0x1 << 2)
#define UBCORE_ACCESS_REMOTE_ATOMIC (0x1 << 3)
#define UBCORE_ACCESS_REMOTE_INVALIDATE (0x1 << 4)

#define UBCORE_SEG_TOKEN_ID_INVALID UINT_MAX

struct ubcore_cg_device {
#ifdef CONFIG_CGROUP_RDMA
	struct rdmacg_device dev;
#endif
};

struct ubcore_cg_object {
#ifdef CONFIG_CGROUP_RDMA
	struct rdma_cgroup *cg;
#endif
};

union ubcore_eid {
	uint8_t raw[UBCORE_EID_SIZE];
	struct {
		uint64_t reserved;
		uint32_t prefix;
		uint32_t addr;
	} in4;
	struct {
		uint64_t subnet_prefix;
		uint64_t interface_id;
	} in6;
};

struct ubcore_eid_info {
	union ubcore_eid eid;
	uint32_t eid_index; /* 0~MAX_EID_CNT -1 */
};

struct ubcore_ueid_cfg {
	union ubcore_eid eid;
	uint32_t upi;
	uint32_t eid_index;
	uuid_t uuid;
};

struct ubcore_devid {
	uint8_t raw[UBCORE_DEVID_SIZE];
};

struct ubcore_jetty_id {
	union ubcore_eid eid;
	uint32_t id;
};

struct ubcore_ubva {
	union ubcore_eid eid;
	uint64_t va;
} __packed;

struct ubcore_ht_param {
	uint32_t size;
	uint32_t node_offset; /* offset of hlist node in the hash table object */
	uint32_t key_offset;
	uint32_t key_size;
	int (*cmp_f)(void *obj, const void *key);
	void (*free_f)(void *obj);
	void (*get_f)(void *obj);
};

struct ubcore_hash_table {
	struct ubcore_ht_param p;
	struct hlist_head *head;
	/* Prevent the same jetty
	 * from being bound by different tjetty
	 */
	struct ubcore_jetty_id rc_tjetty_id;
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

#define UBCORE_SUB_TRANS_MODE_TA_DST_ORDERING_ENABLE (0x1)
#define UBCORE_SUB_TRANS_MODE_USER_TP (0x2)

union ubcore_jfs_flag {
	struct {
		uint32_t lock_free      : 1;
		uint32_t error_suspend  : 1;
		uint32_t outorder_comp  : 1;
		/* (0x1): UBCORE_SUB_TRANS_MODE_TA_DST_ORDERING_ENABLE */
		uint32_t sub_trans_mode : 8;
		uint32_t reserved       : 21;
	} bs;
	uint32_t value;
};

union ubcore_jfr_flag {
	struct {
		/* 0: UBCORE_TOKEN_NONE
		 * 1: UBCORE_TOKEN_PLAIN_TEXT
		 * 2: UBCORE_TOKEN_SIGNED
		 * 3: UBCORE_TOKEN_ALL_ENCRYPTED
		 * 4: UBCORE_TOKEN_RESERVED
		 */
		uint32_t token_policy   : 3;
		uint32_t tag_matching   : 1;
		uint32_t lock_free      : 1;
		/* (0x1): UBCORE_SUB_TRANS_MODE_TA_DST_ORDERING_ENABLE */
		uint32_t sub_trans_mode : 8;
		uint32_t reserved       : 19;
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

enum ubcore_jfr_state {
	UBCORE_JFR_STATE_RESET = 0,
	UBCORE_JFR_STATE_READY,
	UBCORE_JFR_STATE_ERROR
};

enum ubcore_jfs_attr_mask {
	UBCORE_JFS_STATE = 0x1
};

struct ubcore_jfs_attr {
	uint32_t mask;             /* mask value refer to ubcore_jfs_attr_mask_t */
	enum ubcore_jetty_state state;
};

enum ubcore_jfr_attr_mask {
	UBCORE_JFR_RX_THRESHOLD = 0x1,
	UBCORE_JFR_STATE = 0x1 << 1
};

struct ubcore_jfr_attr {
	uint32_t mask; /* mask value refer to enum ubcore_jfr_attr_mask */
	uint32_t rx_threshold;
	enum ubcore_jfr_state state;
};

enum ubcore_jetty_attr_mask {
	UBCORE_JETTY_RX_THRESHOLD = 0x1,
	UBCORE_JETTY_STATE = 0x1 << 1
};

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
		uint32_t token_policy   : 3;
		uint32_t cacheable      : 1;
		uint32_t dsva           : 1;
		uint32_t access         : 6;
		uint32_t non_pin        : 1;
		uint32_t user_iova      : 1;
		uint32_t token_id_valid : 1;
		uint32_t pa             : 1;
		uint32_t reserved       : 17;
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
	union ubcore_eid eid;
	uint32_t eid_index;
	void *jfae; /* jfae uobj */
	struct ubcore_cg_object cg_obj;
	atomic_t use_cnt;
};

struct ubcore_udata {
	struct ubcore_ucontext *uctx;
	struct ubcore_udrv_priv *udrv_data;
};

struct ubcore_token {
	uint32_t token;
};

enum ubcore_event_type {
	UBCORE_EVENT_JFC_ERR,
	UBCORE_EVENT_JFS_ERR,
	UBCORE_EVENT_JFR_ERR,
	UBCORE_EVENT_JFR_LIMIT_REACHED,
	UBCORE_EVENT_JETTY_ERR,
	UBCORE_EVENT_JETTY_LIMIT_REACHED,
	UBCORE_EVENT_JETTY_GRP_ERR,
	UBCORE_EVENT_PORT_ACTIVE,
	UBCORE_EVENT_PORT_DOWN,
	UBCORE_EVENT_DEV_FATAL,
	UBCORE_EVENT_EID_CHANGE,
	UBCORE_EVENT_TP_ERR,
	UBCORE_EVENT_TP_SUSPEND,
	UBCORE_EVENT_TP_FLUSH_DONE,
	UBCORE_EVENT_ELR_ERR,
	UBCORE_EVENT_ELR_DONE,
	UBCORE_EVENT_MIGRATE_VTP_SWITCH,
	UBCORE_EVENT_MIGRATE_VTP_ROLLBACK
};

/* transport mode */
enum ubcore_transport_mode {
	UBCORE_TP_RM = 0x1, /* Reliable message */
	UBCORE_TP_RC = 0x1 << 1, /* Reliable connection */
	UBCORE_TP_UM = 0x1 << 2 /* Unreliable message */
};

enum ubcore_jetty_grp_policy {
	UBCORE_JETTY_GRP_POLICY_RR = 0,
	UBCORE_JETTY_GRP_POLICY_HASH_HINT = 1
};

enum ubcore_target_type {
	UBCORE_JFR = 0,
	UBCORE_JETTY,
	UBCORE_JETTY_GROUP
};

union ubcore_token_id_flag {
	struct {
		uint32_t pa             : 1;
		uint32_t reserved       : 31;
	} bs;
	uint32_t value;
};

struct ubcore_token_id {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	uint32_t token_id;    // driver fill
	union ubcore_token_id_flag flag;
	atomic_t use_cnt;
};

struct ubcore_seg_cfg {
	uint64_t va;
	uint64_t len;
	uint32_t eid_index;
	struct ubcore_token_id *token_id;
	struct ubcore_token token_value;
	union ubcore_reg_seg_flag flag;
	uint64_t user_ctx;
	uint64_t iova;
};

union ubcore_seg_attr {
	struct {
		uint32_t token_policy     : 3;
		uint32_t cacheable      : 1;
		uint32_t dsva           : 1;
		uint32_t access         : 6;
		uint32_t non_pin        : 1;
		uint32_t user_iova      : 1;
		uint32_t user_token_id  : 1;
		uint32_t pa             : 1;
		uint32_t reserved       : 17;
	} bs;
	uint32_t value;
};

struct ubcore_seg {
	struct ubcore_ubva ubva;
	uint64_t len;
	union ubcore_seg_attr attr;
	uint32_t token_id;
};

struct ubcore_target_seg_cfg {
	struct ubcore_seg seg;
	union ubcore_import_seg_flag flag;
	uint64_t mva; /* optional */
	struct ubcore_token token_value;
};

struct ubcore_target_seg {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	struct ubcore_seg seg;
	uint64_t mva;
	struct ubcore_token_id *token_id;
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

enum ubcore_tp_cc_alg {
	UBCORE_TP_CC_NONE = 0,
	UBCORE_TP_CC_DCQCN,
	UBCORE_TP_CC_DCQCN_AND_NETWORK_CC,
	UBCORE_TP_CC_LDCP,
	UBCORE_TP_CC_LDCP_AND_CAQM,
	UBCORE_TP_CC_LDCP_AND_OPEN_CC,
	UBCORE_TP_CC_HC3,
	UBCORE_TP_CC_DIP,
	UBCORE_TP_CC_NUM
};

enum ubcore_congestion_ctrl_alg {
	UBCORE_CC_NONE = 0x1 << UBCORE_TP_CC_NONE,
	UBCORE_CC_DCQCN = 0x1 << UBCORE_TP_CC_DCQCN,
	UBCORE_CC_DCQCN_AND_NETWORK_CC = 0x1 << UBCORE_TP_CC_DCQCN_AND_NETWORK_CC,
	UBCORE_CC_LDCP = 0x1 << UBCORE_TP_CC_LDCP,
	UBCORE_CC_LDCP_AND_CAQM = 0x1 << UBCORE_TP_CC_LDCP_AND_CAQM,
	UBCORE_CC_LDCP_AND_OPEN_CC = 0x1 << UBCORE_TP_CC_LDCP_AND_OPEN_CC,
	UBCORE_CC_HC3 = 0x1 << UBCORE_TP_CC_HC3,
	UBCORE_CC_DIP = 0x1 << UBCORE_TP_CC_DIP
};

enum ubcore_speed {
	UBCORE_SP_10M = 0,
	UBCORE_SP_100M,
	UBCORE_SP_1G,
	UBCORE_SP_2_5G,
	UBCORE_SP_5G,
	UBCORE_SP_10G,
	UBCORE_SP_14G,
	UBCORE_SP_25G,
	UBCORE_SP_40G,
	UBCORE_SP_50G,
	UBCORE_SP_100G,
	UBCORE_SP_200G,
	UBCORE_SP_400G,
	UBCORE_SP_800G
};

enum ubcore_link_width {
	UBCORE_LINK_X1 = 0x1,
	UBCORE_LINK_X2 = 0x1 << 1,
	UBCORE_LINK_X4 = 0x1 << 2,
	UBCORE_LINK_X8 = 0x1 << 3,
	UBCORE_LINK_X16 = 0x1 << 4,
	UBCORE_LINK_X32 = 0x1 << 5
};

enum ubcore_port_state {
	UBCORE_PORT_NOP = 0,
	UBCORE_PORT_DOWN,
	UBCORE_PORT_INIT,
	UBCORE_PORT_ARMED,
	UBCORE_PORT_ACTIVE,
	UBCORE_PORT_ACTIVE_DEFER
};

union ubcore_device_feat {
	struct {
		uint32_t oor : 1;
		uint32_t jfc_per_wr : 1;
		uint32_t stride_op : 1;
		uint32_t load_store_op : 1;
		uint32_t non_pin : 1;
		uint32_t pmem : 1;
		uint32_t jfc_inline : 1;
		uint32_t spray_en : 1;
		uint32_t selective_retrans : 1;
		uint32_t live_migrate : 1;
		uint32_t dca : 1;
		uint32_t jetty_grp : 1;
		uint32_t err_suspend : 1;
		uint32_t outorder_comp : 1;
		uint32_t mn : 1;
		uint32_t clan : 1;
		uint32_t reserved : 16;
	} bs;
	uint32_t value;
};

union ubcore_atomic_feat {
	struct {
		uint32_t cas               :   1;
		uint32_t swap              :   1;
		uint32_t fetch_and_add     :   1;
		uint32_t fetch_and_sub     :   1;
		uint32_t fetch_and_and     :   1;
		uint32_t fetch_and_or      :   1;
		uint32_t fetch_and_xor     :   1;
		uint32_t reserved          :   25;
	} bs;
	uint32_t value;
};

struct ubcore_port_status {
	enum ubcore_port_state state; /* PORT_DOWN, PORT_INIT, PORT_ACTIVE */
	enum ubcore_speed active_speed; /* bandwidth */
	enum ubcore_link_width active_width; /* link width: X1, X2, X4 */
	enum ubcore_mtu active_mtu;
};

struct ubcore_device_status {
	struct ubcore_port_status port_status[UBCORE_MAX_PORT_CNT];
};

struct ubcore_port_attr {
	enum ubcore_mtu max_mtu; /* MTU_256, MTU_512, MTU_1024 */
};

enum ubcore_pattern {
	UBCORE_PATTERN_1 = 0,
	UBCORE_PATTERN_3
};

enum ubcore_sub_trans_mode_cap {
	UBCORE_RC_TP_DST_ORDERING = 0x1,      /* rc mode with tp dst ordering */
	UBCORE_RC_TA_DST_ORDERING = 0x1 << 1, /* rc mode with ta dst ordering  */
	UBCORE_RC_USER_TP		  = 0x1 << 2, /* rc mode with user connection  */
};

struct ubcore_device_cap {
	union ubcore_device_feat feature;
	uint32_t max_jfc;
	uint32_t max_jfs;
	uint32_t max_jfr;
	uint32_t max_jetty;
	uint32_t max_tp_cnt;
	uint32_t max_tpg_cnt;
	/* max_vtp_cnt_per_fe * max_fe_cnt Equal to the number of VTPs on the entire card */
	uint32_t max_vtp_cnt_per_fe;
	uint32_t max_jetty_grp;
	uint32_t max_jetty_in_jetty_grp;
	uint32_t max_rc;              /* max rc queues */
	uint32_t max_jfc_depth;
	uint32_t max_jfs_depth;
	uint32_t max_jfr_depth;
	uint32_t max_rc_depth;            /* max depth of each rc queue */
	uint32_t max_jfs_inline_size;
	uint32_t max_jfs_sge;
	uint32_t max_jfs_rsge;
	uint32_t max_jfr_sge;
	uint64_t max_msg_size;
	/* max read command outstanding count in the function entity */
	uint64_t max_rc_outstd_cnt;
	uint32_t max_sip_cnt_per_fe;
	uint32_t max_dip_cnt_per_fe;
	uint32_t max_seid_cnt_per_fe;
	uint16_t trans_mode;          /* one or more from ubcore_transport_mode_t */
	uint16_t sub_trans_mode_cap;  /* one or more from ubcore_sub_trans_mode_cap */
	uint16_t congestion_ctrl_alg; /* one or more mode from ubcore_congestion_ctrl_alg_t */
	uint16_t ceq_cnt;     /* completion vector count */
	uint32_t max_tp_in_tpg;
	uint32_t max_utp_cnt;
	uint32_t max_oor_cnt;         /* max OOR window size by packet */
	uint32_t mn;
	uint32_t min_slice;           /* 32K (1823), 64K (1650) */
	uint32_t max_slice;           /* 256K (1823), 64K (1650) */
	uint32_t max_atomic_size;     /* in terms of bytes, e.g. 8 or 64 */
	union ubcore_atomic_feat atomic_feat;
	uint32_t max_eid_cnt;
	uint32_t max_upi_cnt;
	uint32_t max_netaddr_cnt;
	uint16_t max_fe_cnt;          /* PF: greater than or equal to 0; FE: must be 0 */
	uint64_t page_size_cap;
};

struct ubcore_guid {
	uint8_t raw[UBCORE_GUID_SIZE];
};

struct ubcore_device_attr {
	struct ubcore_guid guid;
	uint16_t fe_idx;
	struct ubcore_device_cap dev_cap;
	struct ubcore_port_attr port_attr[UBCORE_MAX_PORT_CNT];
	uint8_t port_cnt;
	bool virtualization; /* In VM or not, must set by driver when register device */
	bool tp_maintainer;                /* device used to maintain TP resource */
	enum ubcore_pattern pattern;
};

union ubcore_device_cfg_mask {
	struct {
		uint32_t rc_cnt         : 1;
		uint32_t rc_depth       : 1;
		uint32_t slice          : 1;
		uint32_t pattern        : 1;
		uint32_t virtualization : 1;
		uint32_t suspend_period : 1;
		uint32_t suspend_cnt	: 1;
		uint32_t min_jetty_cnt  : 1;
		uint32_t max_jetty_cnt  : 1;
		uint32_t min_jfr_cnt    : 1;
		uint32_t max_jfr_cnt    : 1;
		uint32_t reserved       : 21;
	} bs;
	uint32_t value;
};

struct ubcore_congestion_control {
	uint32_t data;
};

struct ubcore_rc_cfg {
	uint32_t rc_cnt;                /* rc queue count */
	uint32_t depth;
};

struct ubcore_device_cfg {
	uint16_t fe_idx;                  /* vf id or pf id. e.g: bdf id */
	union ubcore_device_cfg_mask mask;
	struct ubcore_rc_cfg rc_cfg;
	uint32_t slice;                 /* TA slice size byte */
	uint8_t pattern;                /* 0: pattern1; 1: pattern3 */
	bool virtualization;
	uint32_t suspend_period;        /* us */
	uint32_t suspend_cnt;           /* TP resend cnt */
	uint32_t min_jetty_cnt;
	uint32_t max_jetty_cnt;
	uint32_t min_jfr_cnt;
	uint32_t max_jfr_cnt;
};

/* struct [struct ubcore_user_ctl_in] should be consistent with [urma_user_ctl_in_t] */
struct ubcore_user_ctl_in {
	uint64_t addr;
	uint32_t len;
	uint32_t opcode;
};

/* struct [struct ubcore_user_ctl_out] should be consistent with [urma_user_ctl_out_t] */
struct ubcore_user_ctl_out {
	uint64_t addr;
	uint32_t len;
	uint32_t reserved;
};

struct ubcore_user_ctl {
	struct ubcore_ucontext *uctx;
	struct ubcore_user_ctl_in in;
	struct ubcore_user_ctl_out out;
	struct ubcore_udrv_priv udrv_data;
};

enum ubcore_net_addr_type {
	UBCORE_NET_ADDR_TYPE_IPV4 = 0,
	UBCORE_NET_ADDR_TYPE_IPV6
};

union ubcore_net_addr_union {
	uint8_t raw[UBCORE_NET_ADDR_BYTES];
	struct {
		uint64_t reserved1;
		uint32_t reserved2;
		uint32_t addr;
	} in4;
	struct {
		uint64_t subnet_prefix;
		uint64_t interface_id;
	} in6;
};

struct ubcore_net_addr {
	enum ubcore_net_addr_type type;
	union ubcore_net_addr_union net_addr;
	uint64_t vlan; /* available for UBOE */
	uint8_t mac[UBCORE_MAC_BYTES]; /* available for UBOE */
	uint32_t prefix_len;
};

union ubcore_tp_cfg_flag {
	struct {
		uint32_t target : 1;          /* 0: initiator, 1: target */
		uint32_t loopback : 1;
		uint32_t ack_resp : 1;
		uint32_t dca_enable : 1;
		/* for the bonding case, the hardware selects the port
		 * ignoring the port of the tp context and
		 * selects the port based on the hash value
		 * along with the information in the bonding group table.
		 */
		uint32_t bonding : 1;
		uint32_t reserved : 27;
	} bs;
	uint32_t value;
};

union ubcore_tp_mod_flag {
	struct {
		uint32_t oor_en      : 1; /* out of order receive, 0: disable 1: enable */
		uint32_t sr_en       : 1; /* selective retransmission, 0: disable 1: enable */
		uint32_t cc_en       : 1; /* congestion control algorithm, 0: disable 1: enable */
		uint32_t cc_alg      : 4; /* The value is ubcore_tp_cc_alg_t */
		uint32_t spray_en    : 1; /* spray with src udp port, 0: disable 1: enable */
		uint32_t clan        : 1; /* clan domain, 0: disable 1: enable */
		uint32_t reserved    : 23;
	} bs;
	uint32_t value;
};

/* The first bits must be consistent with union ubcore_tp_cfg_flag */
union ubcore_tp_flag {
	struct {
		uint32_t target : 1;   /* 0: initiator, 1: target */
		uint32_t oor_en : 1;   /* out of order receive, 0: disable 1: enable */
		uint32_t sr_en : 1;    /* selective retransmission, 0: disable 1: enable */
		uint32_t cc_en : 1;    /* congestion control algorithm, 0: disable 1: enable */
		uint32_t cc_alg : 4;   /* The value is ubcore_tp_cc_alg_t */
		uint32_t spray_en : 1; /* spray with src udp port, 0: disable 1: enable */
		uint32_t loopback : 1;
		uint32_t ack_resp : 1;
		uint32_t dca_enable : 1;     /* dynamic connection, 0: disable 1: enable */
		uint32_t bonding : 1;
		uint32_t clan : 1;
		uint32_t reserved : 18;
	} bs;
	uint32_t value;
};

enum ubcore_tp_state {
	UBCORE_TP_STATE_RESET = 0,
	UBCORE_TP_STATE_RTR,
	UBCORE_TP_STATE_RTS,
	UBCORE_TP_STATE_SUSPENDED,
	UBCORE_TP_STATE_ERR
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

struct ubcore_tpg;
struct ubcore_tp_cfg {
	union ubcore_tp_cfg_flag flag; /* flag of initial tp */
	/* transaction layer attributes */
	union {
		union ubcore_eid local_eid;
		struct ubcore_jetty_id local_jetty;
	};
	uint16_t fe_idx; /* rc mode only */
	union {
		union ubcore_eid peer_eid;
		struct ubcore_jetty_id peer_jetty;
	};
	/* transport layer attributes */
	enum ubcore_transport_mode trans_mode;
	uint8_t retry_num;
	uint8_t retry_factor;      /* for calculate the time slot to retry */
	uint8_t ack_timeout;
	uint8_t dscp;
	uint32_t oor_cnt;          /* OOR window size: by packet */
	struct ubcore_tpg *tpg;         /* NULL if no tpg, eg.UM mode */
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
		uint32_t oos_cnt : 1;
		uint32_t local_net_addr_idx : 1;
		uint32_t peer_net_addr : 1;
		uint32_t data_udp_start : 1;
		uint32_t ack_udp_start : 1;
		uint32_t udp_range : 1;
		uint32_t hop_limit : 1;
		uint32_t flow_label : 1;
		uint32_t port_id : 1;
		uint32_t mn : 1;
		uint32_t peer_trans_type : 1; /* user tp only */
		uint32_t reserved : 13;
	} bs;
	uint32_t value;
};

struct ubcore_tp_attr {
	union ubcore_tp_mod_flag flag;
	uint32_t peer_tpn;
	enum ubcore_tp_state state;
	uint32_t tx_psn;
	uint32_t rx_psn;
	enum ubcore_mtu mtu;
	uint8_t cc_pattern_idx;
	struct ubcore_tp_ext peer_ext;
	uint32_t oos_cnt; /* out of standing packet cnt */
	uint32_t local_net_addr_idx;
	struct ubcore_net_addr peer_net_addr;
	uint16_t data_udp_start;
	uint16_t ack_udp_start;
	uint8_t udp_range;
	uint8_t hop_limit;
	uint32_t flow_label;
	uint8_t port_id;
	uint8_t mn;       /* 0~15, a packet contains only one msg if mn is set as 0 */
	enum ubcore_transport_type peer_trans_type; /* Only for user tp connection */
};

struct ubcore_tp {
	uint32_t tpn;            /* driver assgined in creating tp */
	uint32_t peer_tpn;
	struct ubcore_device *ub_dev;
	union ubcore_tp_flag flag;   /* indicate initiator or target, etc */
	uint32_t local_net_addr_idx;
	struct ubcore_net_addr peer_net_addr;
	/* only for RC START */
	union {
		union ubcore_eid local_eid;
		struct ubcore_jetty_id local_jetty;
	};
	union {
		union ubcore_eid peer_eid;
		struct ubcore_jetty_id peer_jetty;
	};
	/* only for RC END */
	enum ubcore_transport_mode trans_mode;
	enum ubcore_tp_state state;
	uint32_t rx_psn;
	uint32_t tx_psn;
	enum ubcore_mtu mtu;
	uint16_t data_udp_start;  /* src udp port start, for multipath data */
	uint16_t ack_udp_start;   /* src udp port start, for multipath ack */
	uint8_t udp_range;        /* src udp port range, for both multipath data and ack */
	uint8_t port_id;          /* optional, physical port, only for non-bonding */
	uint8_t retry_num;
	uint8_t retry_factor;
	uint8_t ack_timeout;
	uint8_t dscp;
	uint8_t cc_pattern_idx;
	uint8_t hop_limit;
	struct ubcore_tpg *tpg;        /* NULL if no tpg, eg. UM mode */
	uint32_t oor_cnt;         /* out of order window size for recv: packet cnt */
	uint32_t oos_cnt;		  /* out of order window size for send: packet cnt */
	struct ubcore_tp_ext tp_ext;   /* driver fill in creating tp */
	struct ubcore_tp_ext peer_ext; /* ubcore fill before modifying tp */
	atomic_t use_cnt;
	struct hlist_node hnode;  /* driver inaccessible */
	struct kref ref_cnt;
	struct completion comp;
	void *priv;               /* ubcore private data for tp management */
};

struct ubcore_tpg_cfg {
	/* transaction layer attributes */
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;

	/* tranport layer attributes */
	enum ubcore_transport_mode trans_mode;
	uint8_t dscp;
	enum ubcore_tp_cc_alg cc_alg;
	uint8_t cc_pattern_idx;
	uint32_t tp_cnt;
};

struct ubcore_tpg_ext {
	uint64_t addr;
	uint32_t len;
};

struct ubcore_tpg {
	uint32_t tpgn;
	struct ubcore_device *ub_dev;
	struct ubcore_tpg_cfg tpg_cfg;             /* filled by ubcore when creating tp */
	struct ubcore_tpg_ext tpg_ext;             /* filled by ubn driver when creating tp */
	struct ubcore_tpg_ext peer_ext;            /* filled by ubcore before modifying tp */
	struct ubcore_tp *tp_list[UBCORE_MAX_TP_CNT_IN_GRP]; // UBCORE_MAX_TP_CNT_IN_GRP=32
	struct hlist_node hnode;                   /* driver inaccessible */
	struct kref ref_cnt;
	struct mutex mutex;
};

struct ubcore_cc_entry {
	enum ubcore_tp_cc_alg alg;
	uint8_t cc_pattern_idx;
	uint8_t cc_priority;
} __packed;

union ubcore_utp_cfg_flag {
	struct {
		uint32_t loopback :  1;
		uint32_t spray_en :  1;
		uint32_t clan     :  1;
		uint32_t reserved : 29;
	} bs;
	uint32_t value;
};

struct ubcore_utp_cfg {
	/* transaction layer attributes */
	union ubcore_utp_cfg_flag flag;
	uint16_t udp_start;     // src udp port start
	uint8_t udp_range;     // src udp port range
	uint32_t local_net_addr_idx;
	struct ubcore_net_addr peer_net_addr;
	uint32_t flow_label;
	uint8_t dscp;
	uint8_t hop_limit;
	uint32_t port_id;
	enum ubcore_mtu mtu;
};

struct ubcore_utp {
	uint32_t utpn; /* driver fills */
	struct ubcore_device *ub_dev;
	struct ubcore_utp_cfg utp_cfg;     /* filled by ubcore when createing utp. */
	struct hlist_node hnode;
	struct kref ref_cnt;
};

struct ubcore_ctp_cfg {
	struct ubcore_net_addr peer_net_addr;
	uint32_t cna_len;
};

struct ubcore_ctp {
	uint32_t ctpn; /* driver fills */
	struct ubcore_device *ub_dev;
	struct ubcore_ctp_cfg ctp_cfg;     /* filled by ubcore when createing cp. */
	atomic_t use_cnt;
	struct hlist_node hnode;
	struct kref ref_cnt;
	struct completion comp;
};

enum ubcore_vtp_state {
	UBCORE_VTPS_RESET = 0,
	UBCORE_VTPS_READY = 1
};

struct ubcore_vtpn {
	uint32_t vtpn; /* driver fills */
	struct ubcore_device *ub_dev;
	/* ubcore private, inaccessible to driver */
	enum ubcore_transport_mode trans_mode;
	/* vtpn key start */
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint32_t local_jetty;
	uint32_t peer_jetty;
	/* vtpn key end */
	uint32_t eid_index;
	struct mutex state_lock;
	enum ubcore_vtp_state state; /* protect by state_lock */
	struct hlist_node hnode;
	atomic_t use_cnt;
	struct kref ref_cnt;
	struct completion comp;
};

union ubcore_vtp_cfg_flag {
	struct {
		uint32_t clan_tp : 1;
		uint32_t migrate : 1;
		uint32_t reserve : 30;
	} bs;
	uint32_t value;
};

struct ubcore_vtp_cfg {
	uint16_t fe_idx;        // vfid or pfid
	uint32_t vtpn;
	uint32_t local_jetty;
	/* key start */
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint32_t peer_jetty;
	/* key end */
	union ubcore_vtp_cfg_flag flag;
	enum ubcore_transport_mode trans_mode;
	union {
		struct ubcore_tpg *tpg;
		struct ubcore_tp *tp;
		struct ubcore_utp *utp; // idx of dip
		struct ubcore_ctp *ctp; /* valid when clan is true */
	};
};

struct ubcore_vtp {
	struct ubcore_device *ub_dev;
	struct ubcore_vtp_cfg cfg; /* driver fills */
	struct hlist_node hnode; /* driver inaccessible */
	uint32_t role; /* current side is initiator, target or duplex */
	uint32_t eid_idx;
	uint32_t upi;
	bool share_mode;
	struct kref ref_cnt;
};

struct ubcore_vtp_attr {
	union {
		struct ubcore_tpg *tpg;
		struct ubcore_tp *tp;
		struct ubcore_utp *utp; // idx of dip
		struct ubcore_ctp *ctp; /* clan domain */
	} tp;
};

union ubcore_vtp_attr_mask {
	struct {
		uint32_t tp : 1;
		uint32_t reserved : 31;
	} bs;
	uint32_t value;
};

enum ubcore_msg_opcode {
	/* Processed by UVS. */
	UBCORE_MSG_CREATE_VTP = 0,
	UBCORE_MSG_DESTROY_VTP,
	UBCORE_MSG_ALLOC_EID,
	UBCORE_MSG_DEALLOC_EID,
	UBCORE_MSG_CONFIG_DEVICE,
	/* Live migration, processed by UVS */
	UBCORE_MSG_STOP_PROC_VTP_MSG = 0x10,
	UBCORE_MSG_QUERY_VTP_MIG_STATUS,
	UBCORE_MSG_FLOW_STOPPED,
	UBCORE_MSG_MIG_ROLLBACK,
	UBCORE_MSG_MIG_VM_START,
	/* Processed by backend ubcore. */
	UBCORE_MSG_NEGO_VER,
	UBCORE_MSG_UPDATE_NET_ADDR,
	UBCORE_MSP_UPDATE_EID
};

struct ubcore_req {
	uint32_t msg_id;
	enum ubcore_msg_opcode opcode;
	uint32_t len;
	uint8_t data[0];
};

struct ubcore_req_host {
	uint16_t src_fe_idx;
	struct ubcore_req req;
};

struct ubcore_resp {
	uint32_t msg_id;
	enum ubcore_msg_opcode opcode;
	uint32_t len;
	uint8_t data[0];
};

struct ubcore_resp_host {
	uint16_t dst_fe_idx;
	struct ubcore_resp resp;
};

struct ubcore_event {
	struct ubcore_device *ub_dev;
	union {
		struct ubcore_jfc *jfc;
		struct ubcore_jfs *jfs;
		struct ubcore_jfr *jfr;
		struct ubcore_jetty *jetty;
		struct ubcore_jetty_group *jetty_grp;
		struct ubcore_tp *tp;
		struct ubcore_vtp *vtp;
		uint32_t port_id;
		uint32_t eid_idx;
	} element;
	enum ubcore_event_type event_type;
};

typedef void (*ubcore_event_callback_t)(struct ubcore_event *event, struct ubcore_ucontext *ctx);

struct ubcore_event_handler {
	void (*event_callback)(struct ubcore_event *event, struct ubcore_event_handler *handler);
	struct list_head node;
};

typedef void (*ubcore_comp_callback_t)(struct ubcore_jfc *jfc);

struct ubcore_jfc_cfg {
	uint32_t depth;
	union ubcore_jfc_flag flag;
	uint32_t ceqn;
	void *jfc_context;
};

struct ubcore_jfc {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	struct ubcore_jfc_cfg jfc_cfg;
	uint32_t id;    /* allocated by driver */
	ubcore_comp_callback_t jfce_handler;
	ubcore_event_callback_t jfae_handler;
	uint64_t urma_jfc; /* user space jfc pointer */
	struct hlist_node hnode;
	atomic_t use_cnt;
};

struct ubcore_jfs_cfg {
	uint32_t depth;
	union ubcore_jfs_flag flag;
	enum ubcore_transport_mode trans_mode;
	uint32_t eid_index;
	uint8_t priority;
	uint8_t max_sge;
	uint8_t max_rsge;
	uint32_t max_inline_data;
	uint8_t rnr_retry;
	uint8_t err_timeout;
	void *jfs_context;
	struct ubcore_jfc *jfc;
};

struct ubcore_jfs {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	struct ubcore_jfs_cfg jfs_cfg;
	struct ubcore_jetty_id jfs_id;  /* driver fill jfs_id->id */
	ubcore_event_callback_t jfae_handler;
	uint64_t urma_jfs; /* user space jfs pointer */
	struct hlist_node hnode;
	atomic_t use_cnt;
	struct kref ref_cnt;
	struct completion comp;
	struct ubcore_hash_table *tptable; /* Only for devices not natively supporting RM mode */
};

struct ubcore_jfr_cfg {
	uint32_t id; /* user may assign id */
	uint32_t depth;
	union ubcore_jfr_flag flag;
	enum ubcore_transport_mode trans_mode;
	uint32_t eid_index;
	uint8_t max_sge;
	uint8_t min_rnr_timer;
	struct ubcore_token token_value;
	struct ubcore_jfc *jfc;
	void *jfr_context;
};

struct ubcore_jfr {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	struct ubcore_jfr_cfg jfr_cfg;
	struct ubcore_jetty_id jfr_id;  /* driver fill jfr_id->id */
	ubcore_event_callback_t jfae_handler;
	uint64_t urma_jfr; /* user space jfr pointer */
	struct hlist_node hnode;
	atomic_t use_cnt;
	struct kref ref_cnt;
	struct completion comp;
	struct ubcore_hash_table *tptable; /* Only for devices not natively supporting RM mode */
};

union ubcore_jetty_flag {
	struct {
		uint32_t share_jfr      : 1;  /* 0: URMA_NO_SHARE_JFR. 1: URMA_SHARE_JFR. */
		uint32_t lock_free      : 1;
		uint32_t error_suspend  : 1;
		uint32_t outorder_comp  : 1;
		/* (0x1): UBCORE_SUB_TRANS_MODE_TA_DST_ORDERING_ENABLE */
		uint32_t sub_trans_mode : 8;
		/* (0x1): shared tp; (0x0): non_shared tp.
		 * When rc mode is not ta dst ordering, this flag can only be set to 0.
		 */
		uint32_t rc_share_tp    : 1;
		uint32_t reserved       : 19;
	} bs;
	uint32_t value;
};

struct ubcore_jetty_cfg {
	uint32_t id; /* user may assign id */
	union ubcore_jetty_flag flag;
	enum ubcore_transport_mode trans_mode;
	uint32_t eid_index;
	uint32_t jfs_depth;
	uint8_t priority;
	uint8_t max_send_sge;
	uint8_t max_send_rsge;
	uint32_t max_inline_data;
	uint8_t rnr_retry;
	uint8_t err_timeout;
	uint32_t jfr_depth; /* deprecated */
	uint8_t min_rnr_timer; /* deprecated */
	uint8_t max_recv_sge; /* deprecated */
	struct ubcore_token token_value; /* deprecated */
	struct ubcore_jfc *send_jfc;
	struct ubcore_jfc *recv_jfc; /* must set */
	struct ubcore_jfr *jfr; /* must set, shared jfr */
	struct ubcore_jetty_group *jetty_grp; /* [Optional] user specified jetty group */
	void *jetty_context;
};

union ubcore_import_jetty_flag {
	struct {
		uint32_t token_policy	: 3;
		/* (0x1): UBCORE_SUB_TRANS_MODE_TA_DST_ORDERING_ENABLE */
		uint32_t sub_trans_mode : 8;
		uint32_t rc_share_tp    : 1;
		uint32_t reserved       : 20;
	} bs;
	uint32_t value;
};

struct ubcore_tjetty_cfg {
	struct ubcore_jetty_id id; /* jfr, jetty or jetty group id to be imported */
	union ubcore_import_jetty_flag flag;
	enum ubcore_transport_mode trans_mode;
	uint32_t eid_index;
	enum ubcore_target_type type;
	enum ubcore_jetty_grp_policy policy;
	struct ubcore_token token_value; /* jfr, jetty or jetty group token_value to be imported */
};

struct ubcore_tjetty {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	struct ubcore_tjetty_cfg cfg;
	struct ubcore_tp *tp;
	struct ubcore_vtpn *vtpn;
	atomic_t use_cnt;
	struct mutex lock;
};

struct ubcore_jetty {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	struct ubcore_jetty_cfg jetty_cfg;
	struct ubcore_jetty_id jetty_id; /* driver fill jetty_id->id */
	struct ubcore_tjetty *remote_jetty; // bind to remote jetty
	ubcore_event_callback_t jfae_handler;
	uint64_t urma_jetty; /* user space jetty pointer */
	struct hlist_node hnode;
	atomic_t use_cnt;
	struct kref ref_cnt;
	struct completion comp;
	struct ubcore_hash_table *tptable; /* Only for devices not natively supporting RM mode */
};

union ubcore_jetty_grp_flag {
	struct {
		uint32_t token_policy	: 3;
		uint32_t reserved	: 29;
	} bs;
	uint32_t value;
};

struct ubcore_jetty_grp_cfg {
	char name[UBCORE_JETTY_GRP_MAX_NAME];
	uint32_t eid_index;
	union ubcore_jetty_grp_flag flag;
	struct ubcore_token token_value;
	uint32_t id;
	enum ubcore_jetty_grp_policy policy;
	uint64_t user_ctx;
};

struct ubcore_jetty_group {
	struct ubcore_device *ub_dev;
	struct ubcore_ucontext *uctx;
	struct ubcore_jetty_grp_cfg jetty_grp_cfg;
	struct ubcore_jetty_id jetty_grp_id; /* driver fill jetty_grp_id->id */
	uint32_t jetty_cnt;        /* current jetty cnt in the jetty group */
	struct ubcore_jetty **jetty;
	ubcore_event_callback_t jfae_handler;
	uint64_t urma_jetty_grp; /* user space jetty_grp pointer */
	struct mutex lock;           /* Protect jetty array */
};

enum ubcore_res_key_type {
	UBCORE_RES_KEY_VTP = 1,       // key id: VTPN
	UBCORE_RES_KEY_TP,            // key id: TPN
	UBCORE_RES_KEY_TPG,           // key id: TPGN
	UBCORE_RES_KEY_UTP,           // key id: UTP ID
	UBCORE_RES_KEY_JFS,           // key id: JFS ID
	UBCORE_RES_KEY_JFR,           // key id: JFR ID
	UBCORE_RES_KEY_JETTY,         // key id: JETTY ID
	UBCORE_RES_KEY_JETTY_GROUP,   // key id: JETTY GROUP ID
	UBCORE_RES_KEY_JFC,           // key id: JFC ID
	UBCORE_RES_KEY_RC,            // key id: RC ID
	UBCORE_RES_KEY_SEG,           // key id: TOKEN ID
	UBCORE_RES_KEY_DEV_TA,        // key id: EID
	UBCORE_RES_KEY_DEV_TP         // key id: EID
};

struct ubcore_res_upi_val {
	uint32_t upi;
};

struct ubcore_res_vtp_val {
	uint16_t fe_idx;
	uint32_t vtpn;
	union ubcore_eid local_eid;
	uint32_t local_jetty;
	union ubcore_eid peer_eid;
	uint32_t peer_jetty;
	union ubcore_vtp_cfg_flag flag;
	enum ubcore_transport_mode trans_mode;
	union {
		uint32_t tpgn;
		uint32_t tpn;
		uint32_t utpn;
		uint32_t ctpn;
	};
};

struct ubcore_res_tp_val {
	uint32_t tpn;
	uint32_t tx_psn;
	uint32_t rx_psn;
	uint8_t dscp;
	uint8_t oor_en;
	uint8_t selective_retrans_en;
	uint8_t state;
	uint16_t data_udp_start;
	uint16_t ack_udp_start;
	uint8_t udp_range;
	uint32_t spray_en;
};

struct ubcore_res_tpg_val {
	uint32_t tp_cnt;
	uint8_t dscp;
	uint32_t *tp_list;
};

struct ubcore_res_utp_val {
	uint32_t utpn;
	uint16_t data_udp_start;
	uint8_t udp_range;
	union ubcore_utp_cfg_flag flag;
};

struct ubcore_res_jfs_val {
	uint32_t jfs_id;
	uint8_t state;
	uint32_t depth;
	uint8_t priority;
	uint32_t jfc_id;
};

struct ubcore_res_jfr_val {
	uint32_t jfr_id;
	uint8_t state;
	uint32_t depth;
	uint32_t jfc_id;
};

struct ubcore_res_jetty_val {
	uint32_t jetty_id;
	uint32_t send_jfc_id;
	uint32_t recv_jfc_id;
	uint32_t jfr_id;
	uint32_t jfs_depth;
	uint8_t state;
	uint8_t priority;
};

struct ubcore_res_jetty_group_val {
	uint32_t jetty_cnt;
	uint32_t *jetty_list;
};

struct ubcore_res_jfc_val {
	uint32_t jfc_id;
	uint8_t state;
	uint32_t depth;
};

struct ubcore_res_rc_val {
	uint32_t type;          // type of rc; read, ta-ack/ta-nak or atomic etc.
	uint32_t rc_id;
	uint16_t depth;
	uint8_t state;
};

struct ubcore_seg_info {
	struct ubcore_ubva ubva;
	uint64_t len;
	uint32_t token_id;
};

struct ubcore_res_seg_val {
	uint32_t seg_cnt;
	struct ubcore_seg_info *seg_list;
};

struct ubcore_res_list_val {
	uint32_t cnt;
	uint32_t *list;
};

struct ubcore_res_dev_ta_val {
	uint32_t seg_cnt;
	uint32_t jfs_cnt;
	uint32_t jfr_cnt;
	uint32_t jfc_cnt;
	uint32_t jetty_cnt;
	uint32_t jetty_group_cnt;
	uint32_t rc_cnt;
};

struct ubcore_res_dev_tp_val {
	uint32_t vtp_cnt;
	uint32_t tp_cnt;
	uint32_t tpg_cnt;
	uint32_t utp_cnt;
};

struct ubcore_res_key {
	uint8_t type;      /* refer to ubcore_res_key_type_t */
	uint32_t key;      /* as UPI, key is fe_idx */
	uint32_t key_ext;  /* only for vtp */
	uint32_t key_cnt;  /* only for rc */
};

struct ubcore_res_val {
	uint64_t addr; /* allocated and free by ubcore */
	/* in&out. As a input parameter,
	 * it indicates the length allocated by the ubcore
	 * As a output parameter, it indicates the actual data length.
	 */
	uint32_t len;
};

union ubcore_jfs_wr_flag {
	struct {
		/* 0: There is no order with other WR.
		 * 1: relax order.
		 * 2: strong order.
		 * 3: reserve.
		 */
		uint32_t place_order : 2;
		/* 0: There is no completion order with other WR
		 * 1: Completion order with previous WR.
		 */
		uint32_t comp_order : 1;
		/* 0: There is no fence.
		 * 1: Fence with previous read and atomic WR
		 */
		uint32_t fence : 1;
		/* 0: not solicited.
		 * 1: solicited. It will trigger an event
		 * on remote side
		 */
		uint32_t solicited_enable : 1;
		/* 0: Do not notify local process
		 * after the task is complete.
		 * 1: Notify local process
		 * after the task is completed.
		 */
		uint32_t complete_enable : 1;
		/* 0: No inline.
		 * 1: Inline data.
		 */
		uint32_t inline_flag : 1;
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
	uint8_t target_hint; /* hint of jetty in a target jetty group */
	uint64_t notify_data;	 /* notify data or immeditate data in host byte order */
};

struct ubcore_send_wr {
	struct ubcore_sg src;
	uint8_t target_hint; /* hint of jetty in a target jetty group */
	uint64_t imm_data;	 /* immeditate data in host byte order */
	struct ubcore_target_seg *tseg; /* Used only when send with invalidate */
};

struct ubcore_cas_wr {
	struct ubcore_sge *dst;  /* len is the data length of CAS operation */
	struct ubcore_sge *src;  /* Local address for destination original value written back */
	union {
		uint64_t cmp_data;  /* When the len <= 8B, it indicates the CMP value. */
		uint64_t cmp_addr;  /* When the len > 8B, it indicates the data address. */
	};
	union {
		/* If destination value is the same as cmp_data,
		 * destination value will be change to swap_data.
		 */
		uint64_t swap_data;
		uint64_t swap_addr;
	};
};

struct ubcore_faa_wr {
	struct ubcore_sge *dst; /* len in the sge is the length of faa at remote side */
	struct ubcore_sge *src; /* Local address for destination original value written back */
	union {
		uint64_t operand;  /* Addend */
		uint64_t operand_addr;
	};
};

struct ubcore_jfs_wr {
	enum ubcore_opcode opcode;
	union ubcore_jfs_wr_flag flag;
	uint64_t user_ctx;
	struct ubcore_tjetty *tjetty;
	union {
		struct ubcore_rw_wr rw;
		struct ubcore_send_wr send;
		struct ubcore_cas_wr cas;
		struct ubcore_faa_wr faa;
	};
	struct ubcore_jfs_wr *next;
};

struct ubcore_jfr_wr {
	struct ubcore_sg src;
	uint64_t user_ctx;
	struct ubcore_jfr_wr *next;
};

union ubcore_cr_flag {
	struct {
		uint8_t s_r            : 1;  /* Indicate CR stands for sending or receiving */
		uint8_t jetty          : 1;  /* Indicate id in the CR stands for jetty or JFS/JFR */
		uint8_t suspend_done   : 1;
		uint8_t flush_err_done : 1;
		uint8_t reserved       : 4;
	} bs;
	uint8_t value;
};

struct ubcore_cr_token {
	uint32_t token_id;
	struct ubcore_token token_value;
};

struct ubcore_cr {
	enum ubcore_cr_status status;
	uint64_t user_ctx;
	enum ubcore_cr_opcode opcode;
	union ubcore_cr_flag flag;
	uint32_t completion_len; /* The number of bytes transferred */
	uint32_t local_id; /* Local jetty ID, or JFS ID, or JFR ID, depending on flag */
	/* Valid only for receiving CR. The remote jetty where received msg
	 * comes from, may be jetty ID or JFS ID, depending on flag.
	 */
	struct ubcore_jetty_id remote_id;
	union {
		uint64_t imm_data; /* Valid only for received CR */
		struct ubcore_cr_token invalid_token;
	};
	uint32_t tpn;
	uintptr_t user_data; /* Use as pointer to local jetty struct */
};

enum ubcore_stats_key_type {
	UBCORE_STATS_KEY_VTP = 1,
	UBCORE_STATS_KEY_TP = 2,
	UBCORE_STATS_KEY_TPG = 3,
	UBCORE_STATS_KEY_JFS = 4,
	UBCORE_STATS_KEY_JFR = 5,
	UBCORE_STATS_KEY_JETTY = 6,
	UBCORE_STATS_KEY_JETTY_GROUP = 7,
	UBCORE_STATS_KEY_URMA_DEV = 8,
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
	/* this addr is alloc and free by ubcore,
	 * refer to struct ubcore_stats_com_val
	 */
	uint64_t addr;
	/* [in/out] real length filled when success
	 * to query and buffer length enough;
	 * expected length filled and return failure when buffer length not enough
	 */
	uint32_t len;
};

union ubcore_utp_mod_flag {
	struct {
		uint32_t spray_en : 1; // Whether to enable end-side port number hashing,
								// 0 : disabled, 1 : enabled
		uint32_t reserved : 31;
	} bs;
	uint32_t value;
};

struct ubcore_utp_attr {
	union ubcore_utp_mod_flag flag;
	uint16_t data_udp_start;
	uint8_t udp_range;
};

union ubcore_utp_attr_mask {
	struct {
		uint32_t flag : 1;
		uint32_t udp_port : 1;
		uint32_t udp_range : 1;
		uint32_t reserved : 29;
	} bs;
	uint32_t value;
};

/* live migration struct */
enum ubcore_mig_state {
	UBCORE_MIG_STATE_START,
	UBCORE_MIG_STATE_ROLLBACK,
	UBCORE_MIG_STATE_FINISH
};

enum ubcore_mig_resp_status {
	UBCORE_MIG_MSG_PROC_SUCCESS,
	UBCORE_MIG_MSG_PROC_FAILURE,
	UBCORE_VTP_MIG_COMPLETE,
	UBCORE_VTP_MIG_UNCOMPLETE
};

struct ubcore_fe_stats {
	uint64_t tx_pkt;
	uint64_t rx_pkt;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint64_t tx_pkt_err;
	uint64_t rx_pkt_err;
	uint64_t tx_timeout_cnt;
	uint64_t rx_ce_pkt;
};

struct ubcore_ops {
	struct module *owner; /* kernel driver module */
	char driver_name[UBCORE_MAX_DRIVER_NAME]; /* user space driver name */
	uint32_t abi_version; /* abi version of kernel driver */

	/**
	 * add a function entity id (eid) to ub device (for uvs)
	 * @param[in] dev: the ubcore_device handle;
	 * @param[in] fe_idx: fe_idx;
	 * @param[in] cfg: eid and the upi of fe to which the eid belongs can be specified;
	 * @return: the index of eid/upi, less than 0 indicating error
	 */
	int (*add_ueid)(struct ubcore_device *dev, uint16_t fe_idx, struct ubcore_ueid_cfg *cfg);

	/**
	 * delete a function entity id (eid) to ub device (for uvs)
	 * @param[in] dev: the ubcore_device handle;
	 * @param[in] fe_idx: fe_idx;
	 * @param[in] cfg: eid and the upi of fe to which the eid belongs can be specified;
	 * @return: 0 on success, other value on error
	 */
	int (*delete_ueid)(struct ubcore_device *dev, uint16_t fe_idx, struct ubcore_ueid_cfg *cfg);

	/**
	 * query device attributes
	 * @param[in] dev: the ub device handle;
	 * @param[out] attr: attributes for the driver to fill in
	 * @return: 0 on success, other value on error
	 */
	int (*query_device_attr)(struct ubcore_device *dev, struct ubcore_device_attr *attr);

	/**
	 * query device status
	 * @param[in] dev: the ub device handle;
	 * @param[out] status: status for the driver to fill in
	 * @return: 0 on success, other value on error
	 */
	int (*query_device_status)(struct ubcore_device *dev, struct ubcore_device_status *status);

	/**
	 * query resource
	 * @param[in] dev: the ub device handle;
	 * @param[in] key: resource type and key;
	 * @param[in/out] val: addr and len of value
	 * @return: 0 on success, other value on error
	 */
	int (*query_res)(struct ubcore_device *dev, struct ubcore_res_key *key,
		struct ubcore_res_val *val);

	/**
	 * config device
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: device configuration
	 * @return: 0 on success, other value on error
	 */
	int (*config_device)(struct ubcore_device *dev, struct ubcore_device_cfg *cfg);

	/**
	 * set ub network address
	 * @param[in] dev: the ub device handle;
	 * @param[in] net_addr: net_addr to set
	 * @param[in] index: index by sip table
	 * @return: 0 on success, other value on error
	 */
	int (*add_net_addr)(struct ubcore_device *dev, struct ubcore_net_addr *net_addr,
		uint32_t index);

	/**
	 * unset ub network address
	 * @param[in] dev: the ub device handle;
	 * @param[in] idx: net_addr idx by sip table entry
	 * @return: 0 on success, other value on error
	 */
	int (*delete_net_addr)(struct ubcore_device *dev, uint32_t idx);

	/**
	 * allocate a context from ubep for a user process
	 * @param[in] dev: the ub device handle;
	 * @param[in] eid: function entity id (eid) index to set;
	 * @param[in] udrv_data: user space driver data
	 * @return: pointer to user context on success, null or error,
	 */
	struct ubcore_ucontext *(*alloc_ucontext)(struct ubcore_device *dev,
		uint32_t eid_index, struct ubcore_udrv_priv *udrv_data);

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
	/** alloc token id to ubep
	 * @param[in] dev: the ub device handle;
	 * @param[in] flag: token_id_flag;
	 * @param[in] udata: ucontext and user space driver data
	 * @return: token id pointer on success, NULL on error
	 */
	struct ubcore_token_id *(*alloc_token_id)(struct ubcore_device *dev,
		union ubcore_token_id_flag flag, struct ubcore_udata *udata);

	/** free key id from ubep
	 * @param[in] token_id: the token id alloced before;
	 * @return: 0 on success, other value on error
	 */
	int (*free_token_id)(struct ubcore_token_id *token_id);

	/** register segment to ubep
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: segment attributes and configurations
	 * @param[in] udata: ucontext and user space driver data
	 * @return: target segment pointer on success, NULL on error
	 */
	struct ubcore_target_seg *(*register_seg)(struct ubcore_device *dev,
		struct ubcore_seg_cfg *cfg,
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
						struct ubcore_target_seg_cfg *cfg,
						struct ubcore_udata *udata);

	/** unimport seg from ubep
	 * @param[in] tseg: the segment imported before;
	 * @return: 0 on success, other value on error
	 */
	int (*unimport_seg)(struct ubcore_target_seg *tseg);

	/** add port for bound device
	 * @param[in] dev: the ub device handle;
	 * @param[in] port_cnt: port count
	 * @param[in] port_list: port list
	 * @return: target segment handle on success, NULL on error
	 */
	int (*add_port)(struct ubcore_device *dev, uint32_t port_cnt, uint32_t *port_list);

	/* jetty part */
	/**
	 * create jfc with ubep.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: jfc attributes and configurations
	 * @param[in] udata: ucontext and user space driver data
	 * @return: jfc pointer on success, NULL on error
	 */
	struct ubcore_jfc *(*create_jfc)(struct ubcore_device *dev,
					 struct ubcore_jfc_cfg *cfg,
					 struct ubcore_udata *udata);

	/**
	 * modify jfc from ubep.
	 * @param[in] jfc: the jfc created before;
	 * @param[in] attr: ubcore jfc attr;
	 * @param[in] udata: ucontext and user space driver data
	 * @return: 0 on success, other value on error
	 */
	int (*modify_jfc)(struct ubcore_jfc *jfc, struct ubcore_jfc_attr *attr,
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
					 struct ubcore_jfs_cfg *cfg,
					 struct ubcore_udata *udata);
	/**
	 * modify jfs from ubep.
	 * @param[in] jfs: the jfs created before;
	 * @param[in] attr: ubcore jfs attr;
	 * @param[in] udata: ucontext and user space driver data
	 * @return: 0 on success, other value on error
	 */
	int (*modify_jfs)(struct ubcore_jfs *jfs, struct ubcore_jfs_attr *attr,
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
	 * flush jfs from ubep.
	 * @param[in] jfs: the jfs created before;
	 * @param[in] cr_cnt: the maximum number of CRs expected to be returned;
	 * @param[out] cr: the addr of returned CRs;
	 * @return: the number of CR returned, 0 means no completion record returned, -1 on error
	 */
	int (*flush_jfs)(struct ubcore_jfs *jfs, int cr_cnt, struct ubcore_cr *cr);
	/**
	 * destroy jfs from ubep.
	 * @param[in] jfs: the jfs created before;
	 * @return: 0 on success, other value on error
	 */
	int (*destroy_jfs)(struct ubcore_jfs *jfs);

	/**
	 * create jfr with ubep.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: jfr attributes and configurations
	 * @param[in] udata: ucontext and user space driver data
	 * @return: jfr pointer on success, NULL on error
	 */
	struct ubcore_jfr *(*create_jfr)(struct ubcore_device *dev,
					 struct ubcore_jfr_cfg *cfg,
					 struct ubcore_udata *udata);
	/**
	 * modify jfr from ubep.
	 * @param[in] jfr: the jfr created before;
	 * @param[in] attr: ubcore jfr attr;
	 * @param[in] udata: ucontext and user space driver data
	 * @return: 0 on success, other value on error
	 */
	int (*modify_jfr)(struct ubcore_jfr *jfr, struct ubcore_jfr_attr *attr,
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
						struct ubcore_tjetty_cfg *cfg,
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
						 struct ubcore_jetty_cfg *cfg,
						 struct ubcore_udata *udata);
	/**
	 * modify jetty from ubep.
	 * @param[in] jetty: the jetty created before;
	 * @param[in] attr: ubcore jetty attr;
	 * @param[in] udata: ucontext and user space driver data
	 * @return: 0 on success, other value on error
	 */
	int (*modify_jetty)(struct ubcore_jetty *jetty, struct ubcore_jetty_attr *attr,
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
	 * flush jetty from ubep.
	 * @param[in] jetty: the jetty created before;
	 * @param[in] cr_cnt: the maximum number of CRs expected to be returned;
	 * @param[out] cr: the addr of returned CRs;
	 * @return: the number of CR returned, 0 means no completion record returned, -1 on error
	 */
	int (*flush_jetty)(struct ubcore_jetty *jetty, int cr_cnt, struct ubcore_cr *cr);
	/**
	 * destroy jetty from ubep.
	 * @param[in] jetty: the jetty created before;
	 * @return: 0 on success, other value on error
	 */
	int (*destroy_jetty)(struct ubcore_jetty *jetty);

	/**
	 * import jetty to ubep.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: remote jetty attributes and import configurations
	 * @param[in] udata: ucontext and user space driver data
	 * @return: target jetty pointer on success, NULL on error
	 */
	struct ubcore_tjetty *(*import_jetty)(struct ubcore_device *dev,
						  struct ubcore_tjetty_cfg *cfg,
						  struct ubcore_udata *udata);
	/**
	 * unimport jetty from ubep.
	 * @param[in] tjetty: the target jetty imported before;
	 * @return: 0 on success, other value on error
	 */
	int (*unimport_jetty)(struct ubcore_tjetty *tjetty);
	/**
	 * bind jetty from ubep.
	 * @param[in] jetty: the jetty created before;
	 * @param[in] tjetty: the target jetty imported before;
	 * @param[in] udata: ucontext and user space driver data
	 * @return: 0 on success, other value on error
	 */
	int (*bind_jetty)(struct ubcore_jetty *jetty, struct ubcore_tjetty *tjetty,
		struct ubcore_udata *udata);
	/**
	 * unbind jetty from ubep.
	 * @param[in] jetty: the jetty binded before;
	 * @return: 0 on success, other value on error
	 */
	int (*unbind_jetty)(struct ubcore_jetty *jetty);

	/**
	 * create jetty group to ubep.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: pointer of the jetty group config;
	 * @param[in] udata: ucontext and user space driver data
	 * @return: jetty group pointer on success, NULL on error
	 */
	struct ubcore_jetty_group *(*create_jetty_grp)(struct ubcore_device *dev,
		struct ubcore_jetty_grp_cfg *cfg, struct ubcore_udata *udata);
	/**
	 * destroy jetty group to ubep.
	 * @param[in] jetty_grp: the jetty group created before;
	 * @return: 0 on success, other value on error
	 */
	int (*delete_jetty_grp)(struct ubcore_jetty_group *jetty_grp);

	/**
	 * create tpg.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: tpg init attributes
	 * @param[in] udata: ucontext and user space driver data
	 * @return: tp pointer on success, NULL on error
	 */
	struct ubcore_tpg *(*create_tpg)(struct ubcore_device *dev,
		struct ubcore_tpg_cfg *cfg, struct ubcore_udata *udata);
	/**
	 * destroy tpg.
	 * @param[in] tp: tp pointer created before
	 * @return: 0 on success, other value on error
	 */
	int (*destroy_tpg)(struct ubcore_tpg *tpg);

	/**
	 * create tp.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: tp init attributes
	 * @param[in] udata: ucontext and user space driver data
	 * @return: tp pointer on success, NULL on error
	 */
	struct ubcore_tp *(*create_tp)(struct ubcore_device *dev,
		struct ubcore_tp_cfg *cfg, struct ubcore_udata *udata);
	/**
	 * modify tp.
	 * @param[in] tp: tp pointer created before
	 * @param[in] attr: tp attributes
	 * @param[in] mask: attr mask indicating the attributes to be modified
	 * @return: 0 on success, other value on error
	 */
	int (*modify_tp)(struct ubcore_tp *tp, struct ubcore_tp_attr *attr,
		union ubcore_tp_attr_mask mask);
	/**
	 * modify user tp.
	 * @param[in] dev: the ub device handle
	 * @param[in] tpn: tp number of the tp created before
	 * @param[in] cfg: user configuration of the tp
	 * @param[in] attr: tp attributes
	 * @param[in] mask: attr mask indicating the attributes to be modified
	 * @return: 0 on success, other value on error
	 */
	int (*modify_user_tp)(struct ubcore_device *dev, uint32_t tpn, struct ubcore_tp_cfg *cfg,
		struct ubcore_tp_attr *attr, union ubcore_tp_attr_mask mask);
	/**
	 * destroy tp.
	 * @param[in] tp: tp pointer created before
	 * @return: 0 on success, other value on error
	 */
	int (*destroy_tp)(struct ubcore_tp *tp);

	/**
	 * create multi tp.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cnt: the number of tp, must be less than or equal to 32;
	 * @param[in] cfg: array of tp init attributes
	 * @param[in] udata: array of ucontext and user space driver data
	 * @param[out] tp: pointer array of tp
	 * @return: created tp cnt, 0 on error
	 */
	int (*create_multi_tp)(struct ubcore_device *dev, uint32_t cnt, struct ubcore_tp_cfg *cfg,
		struct ubcore_udata *udata, struct ubcore_tp **tp);
	/**
	 * modify multi tp.
	 * @param[in] cnt: the number of tp;
	 * @param[in] tp: pointer array of tp created before
	 * @param[in] attr: array of tp attributes
	 * @param[in] mask: array of attr mask indicating the attributes to be modified
	 * @param[in] fail_tp: pointer of tp failed to modify
	 * @return: modified successfully tp cnt, 0 on error
	 */
	int (*modify_multi_tp)(uint32_t cnt, struct ubcore_tp **tp, struct ubcore_tp_attr *attr,
		union ubcore_tp_attr_mask *mask, struct ubcore_tp **fail_tp);
	/**
	 * destroy multi tp.
	 * @param[in] cnt: the number of tp;
	 * @param[in] tp: pointer array of tp created before
	 * @return: destroyed tp cnt, 0 on error
	 */
	int (*destroy_multi_tp)(uint32_t cnt, struct ubcore_tp **tp);

	/**
	 * allocate vtp.
	 * @param[in] dev: the ub device handle;
	 * @return: vtpn pointer on success, NULL on error
	 */
	struct ubcore_vtpn *(*alloc_vtpn)(struct ubcore_device *dev);

	/**
	 * free vtpn.
	 * @param[in] vtpn: vtpn pointer allocated before
	 * @return: 0 on success, other value on error
	 */
	int (*free_vtpn)(struct ubcore_vtpn *vtpn);

	/**
	 * create vtp.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: vtp init attributes
	 * @param[in] udata: ucontext and user space driver data
	 * @return: vtp pointer on success, NULL on error
	 */
	struct ubcore_vtp *(*create_vtp)(struct ubcore_device *dev,
		struct ubcore_vtp_cfg *cfg, struct ubcore_udata *udata);
	/**
	 * destroy vtp.
	 * @param[in] vtp: vtp pointer created before
	 * @return: 0 on success, other value on error
	 */
	int (*destroy_vtp)(struct ubcore_vtp *vtp);

	/**
	 * create utp.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: utp init attributes
	 * @param[in] udata: ucontext and user space driver data
	 * @return: utp pointer on success, NULL on error
	 */
	struct ubcore_utp *(*create_utp)(struct ubcore_device *dev,
		struct ubcore_utp_cfg *cfg, struct ubcore_udata *udata);
	/**
	 * destroy utp.
	 * @param[in] utp: utp pointer created before
	 * @return: 0 on success, other value on error
	 */
	int (*destroy_utp)(struct ubcore_utp *utp);

	/**
	 * create ctp.
	 * @param[in] dev: the ub device handle;
	 * @param[in] cfg: ctp init attributes
	 * @param[in] udata: ucontext and user space driver data
	 * @return: ctp pointer on success, NULL on error
	 */
	struct ubcore_ctp *(*create_ctp)(struct ubcore_device *dev,
		struct ubcore_ctp_cfg *cfg, struct ubcore_udata *udata);
	/**
	 * destroy ctp.
	 * @param[in] ctp: ctp pointer created before
	 * @return: 0 on success, other value on error
	 */
	int (*destroy_ctp)(struct ubcore_ctp *ctp);

	/**
	 * VF send msg to TPF device.
	 * @param[in] dev: VF or PF device;
	 * @param[in] msg: msg to send;
	 * @return: 0 on success, other value on error
	 */
	int (*send_req)(struct ubcore_device *dev,  struct ubcore_req *msg);

	/**
	 * TPF send msg to vf device.
	 * @param[in] dev: TPF device;
	 * @param[in] msg: msg to send;
	 * @return: 0 on success, other value on error
	 */
	int (*send_resp)(struct ubcore_device *dev,  struct ubcore_resp_host *msg);

	/**
	 * query cc table to get cc pattern idx
	 * @param[in] dev: the ub device handle;
	 * @param[in] cc_entry_cnt: cc entry cnt;
	 * @return: return NULL on fail, otherwise, return cc entry array
	 */
	struct ubcore_cc_entry *(*query_cc)(struct ubcore_device *dev, uint32_t *cc_entry_cnt);

	/**
	 * bond slave net device
	 * @param[in] bond: bond netdev;
	 * @param[in] slave: slave netdev;
	 * @param[in] upper_info: change upper event info;
	 * @return: 0 on success, other value on error
	 */
	int (*bond_add)(struct net_device *bond, struct net_device *slave,
		struct netdev_lag_upper_info *upper_info);

	/**
	 * unbond slave net device
	 * @param[in] bond: bond netdev;
	 * @param[in] slave: slave netdev;
	 * @return: 0 on success, other value on error
	 */
	int (*bond_remove)(struct net_device *bond, struct net_device *slave);

	/**
	 * update slave net device
	 * @param[in] bond: bond netdev;
	 * @param[in] slave: slave netdev;
	 * @param[in] lower_info: change lower state event info;
	 * @return: 0 on success, other value on error
	 */
	int (*slave_update)(struct net_device *bond, struct net_device *slave,
		struct netdev_lag_lower_state_info *lower_info);

	/**
	 * operation of user ioctl cmd.
	 * @param[in] dev: the ub device handle;
	 * @param[in] user_ctl: kdrv user control command pointer;
	 * Return: 0 on success, other value on error
	 */
	int (*user_ctl)(struct ubcore_device *dev, struct ubcore_user_ctl *user_ctl);

	/** data path ops */
	/**
	 * post jfs wr.
	 * @param[in] jfs: the jfs created before;
	 * @param[in] wr: the wr to be posted;
	 * @param[out] bad_wr: the first failed wr;
	 * @return: 0 on success, other value on error
	 */
	int (*post_jfs_wr)(struct ubcore_jfs *jfs, struct ubcore_jfs_wr *wr,
			   struct ubcore_jfs_wr **bad_wr);
	/**
	 * post jfr wr.
	 * @param[in] jfr: the jfr created before;
	 * @param[in] wr: the wr to be posted;
	 * @param[out] bad_wr: the first failed wr;
	 * @return: 0 on success, other value on error
	 */
	int (*post_jfr_wr)(struct ubcore_jfr *jfr, struct ubcore_jfr_wr *wr,
			   struct ubcore_jfr_wr **bad_wr);
	/**
	 * post jetty send wr.
	 * @param[in] jetty: the jetty created before;
	 * @param[in] wr: the wr to be posted;
	 * @param[out] bad_wr: the first failed wr;
	 * @return: 0 on success, other value on error
	 */
	int (*post_jetty_send_wr)(struct ubcore_jetty *jetty, struct ubcore_jfs_wr *wr,
				  struct ubcore_jfs_wr **bad_wr);
	/**
	 * post jetty receive wr.
	 * @param[in] jetty: the jetty created before;
	 * @param[in] wr: the wr to be posted;
	 * @param[out] bad_wr: the first failed wr;
	 * @return: 0 on success, other value on error
	 */
	int (*post_jetty_recv_wr)(struct ubcore_jetty *jetty, struct ubcore_jfr_wr *wr,
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
	int (*query_stats)(struct ubcore_device *dev, struct ubcore_stats_key *key,
		struct ubcore_stats_val *val);
	/**
	 * config function migrate state.
	 * @param[in] dev: the ub device handle;
	 * @param[in] fe_idx: fe id;
	 * @param[in] cnt: config count;
	 * @param[in] cfg: eid and the upi of fe to which the eid belongs can be specified;
	 * @param[in] state: config state (start, rollback and finish)
	 * @return: config success count, -1 on error
	 */
	int (*config_function_migrate_state)(
		struct ubcore_device *dev, uint16_t fe_idx, uint32_t cnt,
		struct ubcore_ueid_cfg *cfg, enum ubcore_mig_state state);
	/**
	 * modify vtp.
	 * @param[in] vtp: vtp pointer to be modified;
	 * @param[in] attr: vtp attr, tp that we want to change;
	 * @param[in] mask: attr mask;
	 * @return: 0 on success, other value on error
	 */
	int (*modify_vtp)(struct ubcore_vtp *vtp, struct ubcore_vtp_attr *attr,
		union ubcore_vtp_attr_mask *mask);
	/**
	 * query fe index.
	 * @param[in] dev: the ub device handle;
	 * @param[in] devid: vf devid to query
	 * @param[out] fe_idx: fe id;
	 * @return: 0 on success, other value on error
	 */
	int (*query_fe_idx)(struct ubcore_device *dev, struct ubcore_devid *devid,
		uint16_t *fe_idx);
	/**
	 * config dscp-vl mapping
	 * @param[in] dev:the ub dev handle;
	 * @param[in] dscp: the dscp value array
	 * @param[in] vl: the vl value array
	 * @param[in] num: array num
	 * @return: 0 on success, other value on error
	 */
	int (*config_dscp_vl)(struct ubcore_device *dev, uint8_t *dscp, uint8_t *vl,
		uint8_t num);
    /**
     * query fe stats, for migration currently.
     * @param[in] dev: the ub device handle;
     * @param[in] cnt: array count;
     * @param[in] fe_idx: fe id array;
     * @param[out] stats: fe counters
     * @return: 0 on success, other value on error
     */
	int (*query_fe_stats)(struct ubcore_device *dev, uint32_t cnt, uint16_t *fe_idx,
		struct ubcore_fe_stats *stats);

	/**
	 * query dscp-vl mapping
	 * @param[in] dev:the ub dev handle;
	 * @param[in] dscp: the dscp value array
	 * @param[in] num: array num
	 * @param[out] vl: the vl value array
	 * @return: 0 on success, other value on error
	 */
	int (*query_dscp_vl)(struct ubcore_device *dev, uint8_t *dscp, uint8_t num, uint8_t *vl);
};

struct ubcore_bitmap {
	unsigned long *bits;
	uint32_t size;
	spinlock_t lock;
};

enum ubcore_hash_table_type {
	UBCORE_HT_JFS = 0, /* jfs hash table */
	UBCORE_HT_JFR, /* jfr hash table */
	UBCORE_HT_JFC, /* jfc hash table */
	UBCORE_HT_JETTY, /* jetty hash table */
	UBCORE_HT_TP,    /* tp table */
	UBCORE_HT_TPG,   /* tpg table */
	UBCORE_HT_RM_VTP,   /* rm vtp table */
	UBCORE_HT_RC_VTP,   /* rc vtp table */
	UBCORE_HT_UM_VTP,   /* um vtp table */
	UBCORE_HT_RM_VTPN,   /* rm vtpn table */
	UBCORE_HT_RC_VTPN,   /* rc vtpn table */
	UBCORE_HT_UM_VTPN,   /* um vtpn table */
	UBCORE_HT_UTP,   /* utp table */
	UBCORE_HT_CTP,   /* ctp table */
	UBCORE_HT_NUM
};

struct ubcore_eid_entry {
	union ubcore_eid eid;
	uint32_t eid_index;
	struct net *net;
	bool valid;
};

struct ubcore_eid_table {
	uint32_t eid_cnt;
	struct ubcore_eid_entry *eid_entries;
	spinlock_t lock;
};

struct ubcore_sip_table {
	struct mutex lock;
	uint32_t max_sip_cnt;
	struct ubcore_sip_info *entry;
	DECLARE_BITMAP(index_bitmap, UBCORE_MAX_SIP);
};

struct ubcore_port_kobj {
	struct kobject kobj;
	struct ubcore_device *dev;
	uint8_t port_id;
};

struct ubcore_eid_attr {
	char name[UBCORE_EID_GROUP_NAME_LEN];
	uint32_t eid_idx;
	struct device_attribute attr;
};

struct ubcore_logic_device {
	struct device *dev;
	struct ubcore_port_kobj port[UBCORE_MAX_PORT_CNT];
	struct list_head node; /* add to ldev list */
	possible_net_t net;
	struct ubcore_device *ub_dev;
	const struct attribute_group *dev_group[UBCORE_ATTR_GROUP_MAX];
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
	struct ubcore_device_attr attr;
	struct attribute_group *group[UBCORE_MAX_ATTR_GROUP]; /* driver may fill group [1] */
	/* driver fills end */

	struct ubcore_device_cfg cfg;

	/* port management */
	struct list_head port_list;

	/* For ubcore client */
	struct rw_semaphore client_ctx_rwsem;
	struct list_head client_ctx_list;
	struct list_head event_handler_list;
	struct rw_semaphore event_handler_rwsem;
	struct ubcore_hash_table ht[UBCORE_HT_NUM]; /* to be replaced with uobj */

	/* protect from unregister device */
	atomic_t use_cnt;
	struct completion comp;
	bool dynamic_eid; /* Assign eid dynamically with netdev notifier */
	struct ubcore_eid_table eid_table;
	struct ubcore_cg_device cg_device;
	struct ubcore_sip_table sip_table;

	/* logic device list and mutex */
	struct ubcore_logic_device ldev;
	struct mutex ldev_mutex;
	struct list_head ldev_list;
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
		uint32_t non_pin : 1; /* 0: pinned to physical memory. 1: non pin. */
		uint32_t writable : 1; /* 0: read-only. 1: writable. */
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

enum ubcore_net_addr_op {
	UBCORE_ADD_NET_ADDR = 0,
	UBCORE_DEL_NET_ADDR = 1,
	UBCORE_UPDATE_NET_ADDR = 2
};

struct ubcore_sip_info {
	char dev_name[UBCORE_MAX_DEV_NAME];
	struct ubcore_net_addr addr;
	uint8_t port_cnt;
	uint8_t port_id[UBCORE_MAX_PORT_CNT];
	uint32_t mtu;
	char netdev_name[UBCORE_MAX_DEV_NAME]; /* for change mtu */
	bool is_active;
};

union ubcore_global_cfg_mask {
	struct {
		uint32_t mtu            : 1;
		uint32_t slice          : 1;
		uint32_t suspend_period : 1;
		uint32_t suspend_cnt    : 1;
		uint32_t reserved       : 28;
	} bs;
	uint32_t value;
};

struct ubcore_global_cfg {
	union ubcore_global_cfg_mask mask;
	enum ubcore_mtu mtu;
	uint32_t slice;
	uint32_t suspend_period;
	uint32_t suspend_cnt;
};

#endif
