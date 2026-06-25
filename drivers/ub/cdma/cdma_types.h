/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#ifndef __CDMA_TYPES_H__
#define __CDMA_TYPES_H__

#include <linux/list.h>
#include <linux/idr.h>
#include <linux/spinlock.h>
#include "cdma.h"

struct cdma_jfae;

enum cdma_event_type {
	CDMA_EVENT_JFC_ERR,
	CDMA_EVENT_JFS_ERR,
	CDMA_EVENT_DEV_INVALID
};

enum cdma_remove_reason {
	/* Context deletion. This call should delete the actual object itself */
	CDMA_REMOVE_CLOSE,
	/* Driver is being hot-unplugged. This call should delete the actual object itself */
	CDMA_REMOVE_DRIVER_REMOVE,
};

struct cdma_ucontext {
	struct cdma_dev *dev;
	u32 eid;
	u32 eid_index;
};

struct cdma_udrv_priv {
	u64 in_addr;
	u32 in_len;
	u64 out_addr;
	u32 out_len;
};

union cdma_jfs_flag {
	struct {
		u32 error_suspend : 1;
		u32 outorder_comp : 1;
		u32 reserved : 30;
	} bs;
	u32 value;
};

struct cdma_jfs_cfg {
	u32 depth;
	union cdma_jfs_flag flag;
	u32 eid_index;
	u8 priority;
	u8 max_sge;
	u8 max_rsge;
	u8 rnr_retry;
	u8 err_timeout;
	u32 jfc_id;
	u32 sqe_pos;
	u32 rmt_eid;
	u32 tpn;
	u32 pld_pos;
	u32 pld_token_id;
	u32 queue_id;
	u32 trans_mode;
};

struct cdma_tp_cfg {
	u32 scna;
	u32 dcna;
	u32 seid;
	u32 deid;
};

struct cdma_base_tp {
	struct cdma_ucontext *uctx;
	struct cdma_tp_cfg cfg;
	u32 tpn;
	u32 tp_id;
};

struct cdma_udata {
	struct cdma_context *uctx;
	struct cdma_jfae *jfae;
	struct cdma_udrv_priv *udrv_data;
};

struct cdma_event {
	struct cdma_dev *dev;
	union {
		struct cdma_base_jfc *jfc;
		struct cdma_base_jfs *jfs;
		u32 eid_idx;
	} element;
	enum cdma_event_type event_type;
};

typedef void (*cdma_event_callback_t)(struct cdma_event *event,
				      struct cdma_jfae *jfae);

struct cdma_base_jfs {
	struct cdma_dev *dev;
	struct cdma_context *ctx;
	struct cdma_jfae *jfae;
	struct cdma_jfs_cfg cfg;
	cdma_event_callback_t jfae_handler;
	u32 id;
	atomic_t use_cnt;
	struct cdma_jfs_event jfs_event;
};

struct cdma_jfc_cfg {
	u32 depth;
	u32 ceqn;
	u32 queue_id;
};

struct cdma_base_jfc;

typedef void (*cdma_comp_callback_t)(struct cdma_base_jfc *jfc);

struct cdma_base_jfc {
	struct cdma_dev *dev;
	struct cdma_context *ctx;
	struct cdma_jfae *jfae;
	struct cdma_jfc_cfg jfc_cfg;
	u32 id;
	cdma_comp_callback_t jfce_handler;
	cdma_event_callback_t jfae_handler;
	struct hlist_node hnode;
	atomic_t use_cnt;
	struct cdma_jfc_event jfc_event;
};

enum cdma_wr_opcode {
	CDMA_WR_OPC_WRITE = 0x00,
	CDMA_WR_OPC_WRITE_NOTIFY = 0x02,
	CDMA_WR_OPC_READ = 0x10,
	CDMA_WR_OPC_CAS = 0x20,
	CDMA_WR_OPC_FADD = 0x22,
	CDMA_WR_OPC_LAST
};

struct cdma_mn {
	struct mmu_notifier mn;
	struct mm_struct *mm;
};

struct cdma_file {
	struct cdma_dev *cdev;
	struct list_head list;
	struct mutex ctx_mutex;
	struct cdma_context *uctx;
	struct cdma_jfae *jfae;
	struct idr idr;
	spinlock_t idr_lock;
	struct mutex umap_mutex;
	struct list_head umaps_list;
	struct page *fault_page;
	struct cdma_mn mn_notifier;
	struct kref ref;
};

struct cdma_umap_priv {
	struct vm_area_struct *vma;
	struct list_head node;
};

#endif /* __CDMA_TYPES_H__ */
