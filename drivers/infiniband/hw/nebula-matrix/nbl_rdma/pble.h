/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_PBLE_H
#define NBL_PBLE_H

#include "main.h"

#define NBL_PBLE_VLD_FLAG 0x800
#define MAX_PBLE_CNT_PER_SD_SHIFT 18
#define PBLE_SIZE_SHIFT 3 /* the pble size, 8Byte */
#define NBL_INVALID_IDX 0xffffffff
#define BYTE_SIZE_SHIFT 3
#define PBLE_CNT_ALIGN_SIZE 2
#define NBL_PBLE_MAX_ORDER 10
#define NBL_SINGLE_CHUNK_PD_CNT 1

enum nbl_pble_level {
	PBLE_LEVEL_0 = 0,
	PBLE_LEVEL_1 = 1,
};

struct nbl_chunk {
	struct list_head list;
	dma_addr_t base_addr;
	void *va;
	void *bitmap_buf;

	u32 sizeof_bitmap;
	u32 pd_idx;
	u64 base_idx;
	int is_used;
	bool initial_chunk;

	struct nbl_sc_dev *sc_dev;
};

struct nbl_pble_chunkinfo {
	struct nbl_chunk *pchunk;
	u64 bit_idx;
	u64 bits_used;
};

struct nbl_pble_info {
	u64 *addr;
	u32 idx;
	u32 cnt;
	u32 pble_cnt_per_chunk;
	int order;
	int allocated_chunk_num; /* used for multi chunk rsrc release */
	bool is_single;
	struct nbl_pble_chunkinfo first_chunk;
	struct nbl_pble_chunkinfo last_chunk;
};

struct nbl_pble_alloc {
	u32 total_cnt;
	u32 needed_cnt; /* upcast the value of total_cnt to an even number */
	struct nbl_pble_info pble_info;
};

struct nbl_pble_prm {
	struct list_head clist;
	spinlock_t prm_lock; /* protect clist access */
	u32 pble_cnt_per_chunk;
};

struct nbl_hmc_pble_rsrc {
	struct nbl_pble_prm pinfo[NBL_PBLE_MAX_ORDER]; /* pble prm info by orders */
	struct mutex pble_mutex_lock;
	struct nbl_sc_dev *sc_dev;
	u64 base_idx;
	u64 stats_alloc_ok;
	u64 stats_alloc_failed;

	u64 total_pble_cnt;
	u64 allocated_pble_cnt;
	u64 free_pble_cnt;

	/* the info about pble pd */
	u64 max_index;
	u64 free_pd_cnt; /* the remaining available number of pble pd */
	u64 pd_bmap_size; /* the size of pd bitmap */
	unsigned long *pd_bmap; /* Pointer to pd resource bitmap */
};

void nbl_free_pble(struct nbl_hmc_pble_rsrc *pble_rsrc,
		   struct nbl_pble_alloc *palloc);
int nbl_get_pble(struct nbl_pci_f *rf, struct nbl_pble_alloc *palloc, u32 pble_cnt);
int nbl_hmc_init_pble(struct nbl_pci_f *rf);
void nbl_hmc_deinit_pble(struct nbl_pci_f *rf);
int nbl_fill_pble_value(struct nbl_pble_alloc *palloc, u32 tpcnt, u64 addr);

#endif /* NBL_PBLE_H */
