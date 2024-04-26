/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef HMM_EM_H
#define HMM_EM_H

#include <linux/pci.h>
#include <linux/mutex.h>
#include "hmm_umem.h"

#define HMM_EM_CHUNK_SIZE (1 << 21)
#define HMM_EM_PAGE_SIZE PAGE_SIZE // (4096UL)

#define HMM_EM_ROUNDUP_POW_OF_TWO roundup_pow_of_two

struct hmm_em_buf {
	u32 length;
	void *buf;
	dma_addr_t dma_addr;
	struct hmm_em_buf *next_buf;
};

struct hmm_em_chunk {
	u32 buf_num;
	u32 refcount;
	struct hmm_em_buf em_buf_list;
};

struct hmm_em_table {
	u32 chunk_num;
	u32 obj_num;
	u32 obj_size;
	int min_order;
	struct mutex mutex;
	struct hmm_em_chunk **em_chunk;
};


void *hmm_em_table_find(struct hmm_em_table *em_table, u32 obj, dma_addr_t *dma_handle);
void hmm_em_table_put_range(struct pci_dev *pdev, struct hmm_em_table *em_table,
	u32 start, u32 end);
int hmm_em_table_get_range(struct pci_dev *pdev, struct hmm_em_table *em_table, u32 start, u32 end);
int hmm_em_init_table(struct pci_dev *pdev, struct hmm_em_table *em_table,
	u32 obj_size, u32 nobj, u32 reserved_bot, int min_order);
void hmm_em_cleanup_table(struct pci_dev *pdev, struct hmm_em_table *em_table);

#endif
