/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#ifndef __CDMA_H__
#define __CDMA_H__

#include <linux/auxiliary_bus.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <ub/ubus/ubus.h>
#include <ub/ubase/ubase_comm_eq.h>
#include "cdma_debugfs.h"
#include <ub/cdma/cdma_api.h>

extern u32 jfc_arm_mode;
extern bool cqe_mode;
extern struct list_head cdma_client_list;
extern struct rw_semaphore cdma_clients_rwsem;
extern struct rw_semaphore cdma_device_rwsem;
extern struct mutex cdma_reset_mutex;

#define CDMA_HW_PAGE_SHIFT	12
#define CDMA_HW_PAGE_SIZE	(1 << CDMA_HW_PAGE_SHIFT)

#define CDMA_DEFAULT_CQE_SIZE	128
#define CDMA_RESET_WAIT_TIME	3000
#define CDMA_MAX_SL_NUM		16

#define CDMA_UPI_MASK		0x7FFF

#define CDMA_CLIENT_NAME 64

enum cdma_cqe_size {
	CDMA_64_CQE_SIZE,
	CDMA_128_CQE_SIZE,
};

enum cdma_dev_status {
	CDMA_STATUS_NORMAL,
	CDMA_STATUS_SUSPENDED,
	CDMA_STATUS_INVALID
};

enum cdma_client_op {
	CDMA_CLIENT_OP_STOP,
	CDMA_CLIENT_OP_REMOVE,
	CDMA_CLIENT_OP_ADD,
};

enum {
	CDMA_CAP_FEATURE_AR		= BIT(0),
	CDMA_CAP_FEATURE_JFC_INLINE	= BIT(4),
	CDMA_CAP_FEATURE_DIRECT_WQE	= BIT(11),
	CDMA_CAP_FEATURE_CONG_CTRL	= BIT(16),
};

struct cdma_resource {
	u32 max_cnt;
	u32 start_idx;
	u32 depth;
};

struct cdma_oor_caps {
	bool oor_en;
	bool reorder_queue_en;
	u8 reorder_cap;
	u8 reorder_queue_shift;
	u8 at_times;
	u16 on_flight_size;
};

struct cdma_cap_table {
	u32 max_cnt;
	u32 size;
};

struct cdma_caps {
	struct cdma_resource jfs;
	struct cdma_resource jfce;
	struct cdma_resource jfc;
	struct cdma_resource queue;
	u32 jfs_sge;
	u32 jfr_sge;
	u32 jfs_rsge;
	u32 jfs_inline_sz;
	u32 comp_vector_cnt;
	u32 eid_num;
	u16 ue_cnt;
	u8 ue_id;
	u32 rc_outstd_cnt;
	u32 utp_cnt;
	u32 trans_mode;
	u32 ta_version;
	u32 tp_version;
	u32 max_msg_len;
	u32 feature;
	u32 public_jetty_cnt;
	u32 rsvd_jetty_cnt;
	u16 cons_ctrl_alg;
	u16 rc_queue_num;
	u16 rc_queue_depth;
	u8 rc_entry_size;
	u8 packet_pattern_mode;
	u8 ack_queue_num;
	u8 port_num;
	u8 cqe_size;
	u8 cc_priority_cnt;
	bool virtualization;
	struct cdma_oor_caps oor_caps;
	struct cdma_cap_table src_addr;
	struct cdma_cap_table seid;
};

struct cdma_idr {
	struct idr idr;
	u32 min;
	u32 max;
	u32 next;
};

struct cdma_table {
	spinlock_t lock;
	struct cdma_idr idr_pool;
};

struct cdma_chardev {
	struct device *dev;

#define CDMA_NAME_LEN 16
	char name[CDMA_NAME_LEN];
	struct cdev cdev;
	int dev_num;
	dev_t devno;
};

union cdma_umem_flag {
	struct {
		u32 non_pin : 1;  /* 0: pinned to physical memory. 1: non pin. */
		u32 writable : 1; /* 0: read-only. 1: writable. */
		u32 reserved : 30;
	} bs;
	u32 value;
};

struct cdma_umem {
	struct mm_struct *owning_mm;
	union cdma_umem_flag flag;
	struct sg_table sg_head;
	struct cdma_dev *dev;
	struct sg_append_table sgt_append;

	u64 length;
	u32 nmap;
	u64 va;
	u32 tid;
	int sva_mode;
};

struct cdma_buf {
	dma_addr_t addr; /* pass to hw */
	union {
		void  *kva; /* used for kernel mode */
		struct iova_slot *slot;
		void *kva_or_slot;
	};
	void *va_aligned;
	struct cdma_umem *umem;
	u32 entry_mask;
	u32 entry_shift;
	u32 entry_size;
	u32 entry_cnt;
	u32 cnt_per_page_shift;
	struct xarray id_table_xa;
	struct mutex id_table_mutex;
};

struct cdma_dev {
	struct dma_device base;
	struct device *dev;
	struct auxiliary_device *adev;
	struct cdma_chardev chardev;
	struct cdma_caps caps;
	struct cdma_dbgfs cdbgfs;

	u32 eid;
	u32 upi;
	u32 tid;
	int sva_mode;
	u32 iopf_feature;
	u32 hw_ver;
	u32 status;
	u8 sl_num;
	u8 sl[CDMA_MAX_SL_NUM];

	void __iomem *db_kva_base;
	resource_size_t db_pa_base;
	struct iommu_sva *ksva;
	/* ctx manager */
	struct list_head ctx_list;
	struct idr ctx_idr;
	spinlock_t ctx_lock;
	struct mutex eu_mutex;
	struct mutex db_mutex;
	struct list_head db_page;

	struct cdma_table queue_table;
	struct cdma_table ctp_table;
	struct cdma_table jfs_table;
	struct cdma_table jfc_table;
	struct cdma_table jfce_table;
	struct cdma_table seg_table;
	struct ubase_event_nb *ae_event_addr[UBASE_EVENT_TYPE_MAX];
	struct mutex file_mutex;
	struct list_head file_list;
	struct page *arm_db_page;
	atomic_t cmdcnt;
	atomic_t kcmdcnt;
	struct completion cmddone;
	struct completion kcmddone;
};

struct cdma_jfs_event {
	struct list_head async_event_list;
	u32 async_events_reported;
};

struct cdma_jfc_event {
	struct cdma_jfce *jfce;
	struct list_head comp_event_list;
	struct list_head async_event_list;
	u32 comp_events_reported;
	u32 async_events_reported;
};

static inline struct cdma_dev *get_cdma_dev(struct auxiliary_device *adev)
{
	return (struct cdma_dev *)dev_get_drvdata(&adev->dev);
}

#endif /* __CDMA_H__ */
