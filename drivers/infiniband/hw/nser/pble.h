/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2018 - 2025 Beijing WangXun Technology Co., Ltd. */
#ifndef NSER_PBLE_H
#define NSER_PBLE_H

#define PBLE_SHIFT		6
#define PBLE_PER_PAGE		512
#define HMC_PAGED_BP_SHIFT	12
#define PBLE_512_SHIFT		9
#define PBLE_INVALID_IDX	0xffffffff

enum nser_pble_level {
	PBLE_LEVEL_0 = 0,
	PBLE_LEVEL_1 = 1,
	PBLE_LEVEL_2 = 2,
};

enum nser_alloc_type {
	PBLE_NO_ALLOC	  = 0,
	PBLE_SD_CONTIGOUS = 1,
	PBLE_SD_PAGED	  = 2,
	PBLE_ON_CHIP      = 3,
};

struct nser_chunk;

struct nser_pble_chunkinfo {
	struct nser_chunk *pchunk;
	u64 bit_idx;
	u64 bits_used;
};

struct nser_pble_info {
	u64 *addr;
	u32 idx;
	u32 cnt;
	struct nser_pble_chunkinfo chunkinfo;
};

struct nser_pble_level2 {
	struct nser_pble_info root;
	struct nser_pble_info *leaf;
	struct nser_virt_mem leafmem;
	u32 leaf_cnt;
};

struct nser_pble_alloc {
	u32 total_cnt;
	enum nser_pble_level level;
	union {
		struct nser_pble_info level1;
		struct nser_pble_level2 level2;
	};
};

struct sd_pd_idx {
	u32 sd_idx;
	u32 pd_idx;
	u32 rel_pd_idx;
};

struct nser_add_page_info {
	struct nser_chunk *chunk;
	struct nser_hmc_sd_entry *sd_entry;
	struct nser_hmc_info *hmc_info;
	struct sd_pd_idx idx;
	u32 pages;
};

struct nser_chunk {
	struct list_head list;
	struct nser_dma_info dmainfo;
	void *bitmapbuf;

	u32 sizeofbitmap;
	u64 size;
	void *vaddr;
	u64 fpm_addr;
	u32 pg_cnt;
	enum nser_alloc_type type;
	struct nser_sc_dev *dev;
	struct nser_virt_mem bitmapmem;
	struct nser_virt_mem chunkmem;
};

struct nser_pble_prm {
	struct list_head clist;
	spinlock_t prm_lock; /* protect prm bitmap */
	u64 total_pble_alloc;
	u64 free_pble_cnt;
	u8 pble_shift;
};

struct nser_hmc_pble_rsrc {
	u32 unallocated_pble;
	struct mutex pble_mutex_lock; /* protect PBLE resource */
	struct nser_sc_dev *dev;
	u64 fpm_base_addr;
	u64 next_fpm_addr;
	struct nser_pble_prm pinfo;
	u64 allocdpbles;
	u64 freedpbles;
	u32 stats_direct_sds;
	u32 stats_paged_sds;
	u64 stats_alloc_ok;
	u64 stats_alloc_fail;
	u64 stats_alloc_freed;
	u64 stats_lvl1;
	u64 stats_lvl2;
};

void nser_destroy_pble_prm(struct nser_hmc_pble_rsrc *pble_rsrc);
int nser_hmc_init_pble(struct nser_sc_dev *dev,
			struct nser_hmc_pble_rsrc *pble_rsrc);
void nser_free_pble(struct nser_hmc_pble_rsrc *pble_rsrc,
		     struct nser_pble_alloc *palloc);
int nser_get_pble(struct nser_hmc_pble_rsrc *pble_rsrc,
		   struct nser_pble_alloc *palloc, u32 pble_cnt,
		   u8 lvl);
int nser_prm_add_pble_mem(struct nser_pble_prm *pprm,
			   struct nser_chunk *pchunk);
int nser_prm_get_pbles(struct nser_pble_prm *pprm,
			struct nser_pble_chunkinfo *chunkinfo, u64 mem_size,
			u64 **vaddr, u64 *fpm_addr);
void nser_prm_return_pbles(struct nser_pble_prm *pprm,
			    struct nser_pble_chunkinfo *chunkinfo);
void nser_pble_acquire_lock(struct nser_hmc_pble_rsrc *pble_rsrc,
			     unsigned long *flags);
void nser_pble_release_lock(struct nser_hmc_pble_rsrc *pble_rsrc,
			     unsigned long *flags);
void nser_pble_free_paged_mem(struct nser_chunk *chunk);
int nser_pble_get_paged_mem(struct nser_chunk *chunk, u32 pg_cnt);
void nser_prm_rem_bitmapmem(struct nser_hw *hw, struct nser_chunk *chunk);
int nser_hw_manage_vf_pble_bp(struct nser_sc_dev *dev,
			       struct nser_manage_vf_pble_info *info);
#endif /* NSER_PBLE_H */
