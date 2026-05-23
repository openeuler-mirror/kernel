/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_bat_cla.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_CQM_BAT_CLA_H
#define HINIC5_CQM_BAT_CLA_H

#include <linux/types.h>
#include <linux/mutex.h>

#include "hinic5_hw_cfg.h"
#include "hinic5_hinic5_cqm.h"
#include "hinic5_cqm_bitmap_table.h"
#include "hinic5_cqm_object.h"

/* When the connection check is enabled, the maximum number of connections
 * supported by the chip is 1M - 63, which cannot reach 1M
 */
#define HINIC5_CQM_BAT_MAX_CONN_NUM       (0x100000 - 63)
#define HINIC5_CQM_BAT_MAX_CACHE_CONN_NUM (0x100000 - 63)

#ifndef MAX_ORDER
#ifdef MAX_PAGE_ORDER
#define MAX_ORDER MAX_PAGE_ORDER
#endif
#endif

#define CLA_TABLE_PAGE_ORDER       0
#define HINIC5_CQM_4K_PAGE_ORDER          0
#define HINIC5_CQM_4K_PAGE_SIZE           4096

#define HINIC5_CQM_8K_PAGE_ORDER          1

#define HINIC5_CQM_BAT_ENTRY_MAX          16
#define HINIC5_CQM_BAT_ENTRY_SIZE         16
#define HINIC5_CQM_BAT_STORE_API_SIZE     16
#define HINIC5_CQM_BAT_MAX                (HINIC5_CQM_BAT_ENTRY_MAX * HINIC5_CQM_BAT_ENTRY_SIZE)

#define HINIC5_CQM_BAT_SIZE_FT_RDMA_PF    240
#define HINIC5_CQM_BAT_SIZE_FT_RDMA_VF    160
#define HINIC5_CQM_BAT_SIZE_FT_PF         192
#define HINIC5_CQM_BAT_SIZE_FT_VF         112
#define HINIC5_CQM_BAT_SIZE_RDMA_PF       160
#define HINIC5_CQM_BAT_SIZE_RDMA_VF       80

#define HINIC5_CQM_BAT_INDEX0             0
#define HINIC5_CQM_BAT_INDEX1             1
#define HINIC5_CQM_BAT_INDEX2             2
#define HINIC5_CQM_BAT_INDEX3             3
#define HINIC5_CQM_BAT_INDEX4             4
#define HINIC5_CQM_BAT_INDEX5             5
#define HINIC5_CQM_BAT_INDEX6             6
#define HINIC5_CQM_BAT_INDEX7             7
#define HINIC5_CQM_BAT_INDEX8             8
#define HINIC5_CQM_BAT_INDEX9             9
#define HINIC5_CQM_BAT_INDEX10            10
#define HINIC5_CQM_BAT_INDEX11            11
#define HINIC5_CQM_BAT_INDEX12            12
#define HINIC5_CQM_BAT_INDEX13            13
#define HINIC5_CQM_BAT_INDEX14            14
#define HINIC5_CQM_BAT_INDEX15            15

enum hinic5_cqm_bat_entry_type {
	HINIC5_CQM_BAT_ENTRY_T_CFG = 0,
	HINIC5_CQM_BAT_ENTRY_T_HASH = 1,
	HINIC5_CQM_BAT_ENTRY_T_QPC = 2,
	HINIC5_CQM_BAT_ENTRY_T_SCQC = 3,
	HINIC5_CQM_BAT_ENTRY_T_SRQC = 4,
	HINIC5_CQM_BAT_ENTRY_T_MPT = 5,
	HINIC5_CQM_BAT_ENTRY_T_GID = 6,
	HINIC5_CQM_BAT_ENTRY_T_LUN = 7,
	HINIC5_CQM_BAT_ENTRY_T_TASKMAP = 8,
	HINIC5_CQM_BAT_ENTRY_T_L3I = 9,
	HINIC5_CQM_BAT_ENTRY_T_CHILDC = 10,
	HINIC5_CQM_BAT_ENTRY_T_TIMER = 11,
	HINIC5_CQM_BAT_ENTRY_T_XID2CID = 12,
	HINIC5_CQM_BAT_ENTRY_T_REORDER = 13,
	HINIC5_CQM_BAT_ENTRY_T_INVALID = 14,
	HINIC5_CQM_BAT_ENTRY_T_MAX = 15,
};

/* CLA update mode */
#define HINIC5_CQM_CLA_RECORD_NEW_GPA                0
#define HINIC5_CQM_CLA_DEL_GPA_WITHOUT_CACHE_INVALID 1
#define HINIC5_CQM_CLA_DEL_GPA_WITH_CACHE_INVALID    2

#define HINIC5_CQM_CLA_LVL_0                         0
#define HINIC5_CQM_CLA_LVL_1                         1
#define HINIC5_CQM_CLA_LVL_2                         2
#define HINIC5_CQM_CLA_LVL_UNSUPPORT                 3

#define HINIC5_CQM_MAX_INDEX_BIT_DEFAULT             19

#define HINIC5_CQM_CHIP_CACHELINE                    256
#define HINIC5_CQM_CHIP_TIMER_CACHELINE              512
#define HINIC5_CQM_OBJECT_256                        256
#define HINIC5_CQM_OBJECT_512                        512
#define HINIC5_CQM_OBJECT_1024                       1024
#define HINIC5_CQM_CHIP_GPA_MASK                     0x1ffffffffffffff
#define HINIC5_CQM_CHIP_GPA_HIMASK                   0x1ffffff
#define HINIC5_CQM_CHIP_GPA_LOMASK                   0xffffffff
#define HINIC5_CQM_CHIP_GPA_HSHIFT                   32

/* Aligns with 64 buckets and shifts rightward by 6 bits */
#define HINIC5_CQM_HASH_NUMBER_UNIT                  6

/* mem_size should be none-zero and be 2^n */
#define HINIC5_CQM_IS_SECURE_MEMSIZE_VALID(mem_size)  \
	(((mem_size) != 0) && (((mem_size) & ((mem_size) - 1)) == 0))

struct hinic5_cqm_mem_addr {
	void *va;
	dma_addr_t pa;
};

struct hinic5_cqm_secure_mem_info {
	struct hinic5_cqm_mem_addr addr;
	u32 len;
};

struct tag_hinic5_cqm_cla_table {
	u32 type;
	u32 obj_size;
	u32 obj_num;
	u32 max_buffer_size;

	u32 cla_lvl;
	u32 trunk_order; /* Preferred page order for CLA buffer.
			  * Set this before calling hinic5_cqm_cla_xyz(). This value
			  * will be overriden by hinic5_cqm_cla_xyz() when
			  * hugepage_hint is enabled.
			  */
	bool hugepage_hint; /* Hint for hugepage alloc to improve TLB locality */

	/* Dynamic allocation */
	bool alloc_static; /* Whether the buffer is statically allocated */
	struct mutex lock; /* Lock for cla buffer allocation and free */

	u32 max_index_bit;
	u32 cacheline_x; /* x value calculated based on cacheline, used by the chip */
	u32 cacheline_y; /* y value calculated based on cacheline, used by the chip */
	u32 cacheline_z; /* z value calculated based on cacheline, used by the chip */
	u32 x; /* x value calculated based on obj_size, used by software */
	u32 y; /* y value calculated based on obj_size, used by software */
	u32 z; /* z value calculated based on obj_size, used by software */
	struct tag_hinic5_cqm_buf cla_x_buf;
	struct tag_hinic5_cqm_buf cla_y_buf;
	struct tag_hinic5_cqm_buf cla_z_buf;

	struct tag_hinic5_cqm_bitmap bitmap;

	struct tag_hinic5_cqm_object_table obj_table; /* Mapping table between
						* indexes and objects
						*/
	struct hinic5_cqm_mem_addr secure_mem; /* Secure memory with consecutive physical addresses */

	char name[HINIC5_VRAM_NAME_APPLY_LEN];
};

struct tag_hinic5_cqm_bat_entry_cfg {
	u32 cur_conn_num_h_4 : 4;
	u32 rsv1 : 4;
	u32 max_conn_num : 20;
	u32 rsv2 : 4;

	u32 max_conn_cache : 10;
	u32 rsv3 : 6;
	u32 cur_conn_num_l_16 : 16;

	u32 bloom_filter_addr : 16;
	u32 cur_conn_cache : 10;
	u32 rsv4 : 6;

	u32 bucket_num : 16;
	u32 bloom_filter_len : 16;
};

#define HINIC5_CQM_BAT_NO_BYPASS_CACHE 0
#define HINIC5_CQM_BAT_BYPASS_CACHE    1

#define HINIC5_CQM_BAT_ENTRY_SIZE_256  0
#define HINIC5_CQM_BAT_ENTRY_SIZE_512  1
#define HINIC5_CQM_BAT_ENTRY_SIZE_1024 2

struct tag_hinic5_cqm_bat_entry_standerd {
	u32 entry_size : 2;     /* 0: 256B, 1: 512B, 2: 1024B, others reserved */
	u32 rsv1 : 6;
	u32 max_number : 22;    /* Maximum indexable number. Some types of CLA can only use 20 bits. */
	u32 rsv2 : 2;

	u32 cla_gpa_h : 32;

	u32 cla_gpa_l : 32;

	u32 rsv3 : 8;
	u32 z : 5;              /* SM uses memory index [Z: 0]   to access physical memory. */
	u32 y : 5;              /* SM uses memory index [Y: Z+1] to access 2nd CLA. */
	u32 x : 5;              /* SM uses memory index [X: Y+1] to access 1st CLA. */
	u32 rsv24 : 1;
	u32 bypass : 1;         /* 0: not bypass, 1: bypass */
	u32 cla_level : 2;      /* 0: 0 level CLA, 1: 1 level CLA, 2: 2 levels CLA, others reserved */
	u32 rsv5 : 5;
};

struct tag_hinic5_cqm_bat_entry_vf2pf {
	u32 cla_gpa_h : 25;
	u32 pf_id : 5;
	u32 fake_vf_en : 1;
	u32 acs_spu_en : 1;
};

#define HINIC5_CQM_BAT_ENTRY_TASKMAP_NUM 4
struct tag_hinic5_cqm_bat_entry_taskmap_addr {
	u32 gpa_h;
	u32 gpa_l;
};

struct tag_hinic5_cqm_bat_entry_taskmap {
	struct tag_hinic5_cqm_bat_entry_taskmap_addr addr[HINIC5_CQM_BAT_ENTRY_TASKMAP_NUM];
};

struct tag_hinic5_cqm_bat_table {
	u32 bat_entry_type[HINIC5_CQM_BAT_ENTRY_MAX];
	u8 bat[HINIC5_CQM_BAT_ENTRY_MAX * HINIC5_CQM_BAT_ENTRY_SIZE];
	struct tag_hinic5_cqm_cla_table entry[HINIC5_CQM_BAT_ENTRY_MAX];
	/* Secure memory with consecutive physical addresses */
	struct hinic5_cqm_secure_mem_info func_secure_mem;
	/* In LB mode 1/2, the following entries need to be configured in all
	 * enabled SMFs, and the GPAs must be different and independent.
	 */
	struct tag_hinic5_cqm_cla_table timer_entry[CHIP_SMF_NUM_MAX];
	struct tag_hinic5_cqm_cla_table hash_entry[CHIP_SMF_NUM_MAX];
	struct tag_hinic5_cqm_cla_table xid2cid_entry[CHIP_SMF_NUM_MAX];
	u32 bat_size;
};

struct tag_hinic5_cqm_bat_update_param {
	u32 smf_id;
	u32 func_id;
	u32 bat_offset;
	u32 update_size;
};

s32 hinic5_cqm_bat_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle);
void hinic5_cqm_bat_uninit(struct tag_hinic5_cqm_handle *hinic5_cqm_handle);

s32 hinic5_cqm_cla_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle);
void hinic5_cqm_cla_uninit(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, u32 entry_numb);

u8 *hinic5_cqm_cla_get(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_cla_table *cla_table,
		u32 index, u32 count, dma_addr_t *pa);
void hinic5_cqm_cla_put(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_cla_table *cla_table,
		 u32 index, u32 count);

struct tag_hinic5_cqm_cla_table *hinic5_cqm_cla_table_get(struct tag_hinic5_cqm_bat_table *bat_table,
					    u32 entry_type);
u32 hinic5_cqm_funcid2smfid(const struct tag_hinic5_cqm_handle *hinic5_cqm_handle);

#endif /* HINIC5_CQM_BAT_CLA_H */
