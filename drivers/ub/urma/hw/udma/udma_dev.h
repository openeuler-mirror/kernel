/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_DEV_H__
#define __UDMA_DEV_H__

#include <ub/urma/ubcore_api.h>
#include <ub/ubase/ubase_comm_dev.h>
#include <ub/ubase/ubase_comm_eq.h>
#include "udma_def.h"
#include <uapi/ub/urma/udma/udma_abi.h>
#include <ub/urma/udma/udma_ctl.h>

extern bool dev_name_style;
extern bool dfx_switch;
extern bool cqe_mode;
extern uint32_t batch_flush_query_freq;
extern uint32_t batch_flush_query_timeout;
extern uint32_t jfr_sleep_time;
extern uint32_t jfc_arm_mode;
extern bool dump_aux_info;
extern bool hugepage_enable;

#define UBCORE_MAX_DEV_NAME 64

#define WQE_BB_SIZE_SHIFT 6

#define UDMA_CTX_NUM 2

#define UDMA_BITS_PER_INT 32

#define MAX_JETTY_IN_JETTY_GRP 32

#define UDMA_USER_DATA_H_OFFSET 32U

#define MAX_WQEBB_IN_SQE 4

#define JETTY_DSQE_OFFSET 0x1000

#define UDMA_HW_PAGE_SHIFT 12
#define UDMA_HW_PAGE_SIZE (1 << UDMA_HW_PAGE_SHIFT)
#define UDMA_HUGEPAGE_SHIFT 21
#define UDMA_HUGEPAGE_SIZE (1 << UDMA_HUGEPAGE_SHIFT)

#define UDMA_DEV_UE_NUM 47

#define SEID_TABLE_SIZE 1024

#define UDMA_MAX_SL_NUM 16
#define UDMA_DEFAULT_SL_NUM 0

#define UDMA_RCV_SEND_MAX_DIFF 512U

#define UDMA_CQE_SIZE 64

#define UDMA_MAX_GRANT_SIZE 0xFFFFFFFFF000

#define UDMA_FAULT_MODULE_ID	(2)
#define UDMA_FAULT_EVENT_PROBE	(0)
#define UDMA_FAULT_EVENT_REMOVE	(1)

#define UDMA_FAULT_EVENT_ID_PROBE	(UDMA_FAULT_MODULE_ID << 24 | \
					UDMA_FAULT_EVENT_PROBE)
#define UDMA_FAULT_EVENT_ID_REMOVE	(UDMA_FAULT_MODULE_ID << 24 | \
					UDMA_FAULT_EVENT_REMOVE)

enum udma_status {
	UDMA_NORMAL,
	UDMA_SUSPEND,
};

struct udma_ida {
	struct ida	ida;
	uint32_t	min; /* Lowest ID to allocate. */
	uint32_t	max; /* Highest ID to allocate. */
	uint32_t	next; /* Next ID to allocate. */
	spinlock_t	lock;
};

struct udma_group_bitmap {
	uint32_t min;
	uint32_t max;
	uint32_t grp_next;
	uint32_t n_bits;
	uint32_t *bit;
	uint32_t bitmap_cnt;
	spinlock_t lock;
};

struct udma_group_table {
	struct xarray xa;
	struct udma_group_bitmap bitmap_table;
};

struct udma_table {
	struct xarray xa;
	struct udma_ida ida_table;
};

struct udma_mailbox_cmd {
	struct dma_pool *pool;
	struct semaphore poll_sem;
	struct rw_semaphore udma_mb_rwsem;
};

struct udma_ex_jfc_addr {
	uint64_t cq_addr;
	uint32_t cq_len;
};

struct udma_dev {
	struct ubase_adev_com comdev;
	struct ubcore_device ub_dev;
	struct device *dev;
	struct udma_caps caps;
	uint16_t adev_id;
	uint32_t chip_id;
	uint32_t die_id;
	uint32_t port_id;
	uint32_t port_logic_id;
	bool is_ue;
	char dev_name[UBCORE_MAX_DEV_NAME];
	struct udma_mailbox_cmd mb_cmd;
	struct udma_table jfr_table;
	struct udma_group_table jetty_table;
	struct udma_table jfc_table;
	struct udma_table jetty_grp_table;
	struct udma_ida rsvd_jetty_ida_table;
	struct xarray crq_nb_table;
	struct xarray npu_nb_table;
	struct mutex npu_nb_mutex;
	struct xarray ctrlq_tpid_table;
	struct xarray tpn_ue_idx_table;
	struct ubase_event_nb *ae_event_addr[UBASE_EVENT_TYPE_MAX];
	resource_size_t db_base;
	void __iomem *k_db_base;
	struct workqueue_struct *act_workq;
	struct workqueue_struct *ae_workq;
	struct xarray ksva_table;
	struct mutex ksva_mutex;
	struct xarray eid_table;
	struct mutex eid_mutex;
	struct xarray eid_guid_table;
	struct mutex eid_guid_mutex;
	uint32_t tid;
	struct iommu_sva *ksva;
	struct list_head db_list[UDMA_DB_TYPE_NUM];
	struct mutex db_mutex;
	struct udma_dfx_info *dfx_info;
	uint32_t status;
	uint32_t ue_num;
	struct udma_ex_jfc_addr cq_addr_array[UDMA_JFC_TYPE_NUM];
	uint32_t ue_id;
	struct page *db_page;
	u8 udma_tp_sl_num;
	u8 udma_ctp_sl_num;
	u8 unic_sl_num;
	u8 udma_total_sl_num;
	u8 udma_tp_resp_vl_off;
	u8 udma_tp_sl[UDMA_MAX_SL_NUM];
	u8 udma_ctp_sl[UDMA_MAX_SL_NUM];
	u8 unic_sl[UDMA_MAX_SL_NUM];
	u8 udma_sl[UDMA_MAX_SL_NUM];
	struct ubcore_sl_info priority_info[UDMA_MAX_SL_NUM];
	int disable_ue_rx_count;
	struct mutex disable_ue_rx_mutex;
	struct mutex hugepage_lock;
	struct list_head hugepage_list;
	atomic_t hugepage_seq;
	struct udma_tp_cmdq_info *wait_cmdq_info;
	struct udma_sq_reserved_info sq_reserved_info;
};

#define UDMA_ERR_MSG_LEN	128
struct udma_func_map {
	char err_msg[UDMA_ERR_MSG_LEN];
	int (*init_func)(struct udma_dev *udma_dev);
	void (*uninit_func)(struct udma_dev *udma_dev);
};

static inline struct udma_dev *get_udma_dev(struct auxiliary_device *adev)
{
	return (struct udma_dev *)dev_get_drvdata(&adev->dev);
}

static inline struct udma_dev *to_udma_dev(struct ubcore_device *ub_device)
{
	return container_of(ub_device, struct udma_dev, ub_dev);
}

static inline void udma_id_free(struct udma_ida *ida_table, int idx)
{
	ida_free(&ida_table->ida, idx);
}

int udma_id_alloc_auto_grow(struct udma_dev *udma_dev, struct udma_ida *ida_table,
			    uint32_t *idx);
int udma_id_alloc(struct udma_dev *udma_dev, struct udma_ida *ida_table,
		  uint32_t *idx);
int udma_adv_id_alloc(struct udma_dev *udma_dev, struct udma_group_bitmap *bitmap_table,
			uint32_t *start_idx, bool is_grp, uint32_t next);
void udma_adv_id_free(struct udma_group_bitmap *bitmap_table, uint32_t start_idx,
		      bool is_grp);
int udma_specify_adv_id(struct udma_dev *udma_dev, struct udma_group_bitmap *bitmap_table,
			uint32_t user_id);
void udma_destroy_tables(struct udma_dev *udma_dev);
int udma_init_tables(struct udma_dev *udma_dev);
int udma_probe(struct auxiliary_device *adev, const struct auxiliary_device_id *id);
void udma_remove(struct auxiliary_device *adev);
void udma_reset_init(struct auxiliary_device *adev);
void udma_reset_uninit(struct auxiliary_device *adev);
void udma_reset_down(struct auxiliary_device *adev);

#endif /* __UDMA_DEV_H__ */
