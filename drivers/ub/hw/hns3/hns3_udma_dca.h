/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
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
 */

#ifndef _UDMA_DCA_H
#define _UDMA_DCA_H

#include "hns3_udma_abi.h"
#include "hns3_udma_tp.h"
#include "hns3_udma_hem.h"

#define DCA_MEM_FLAGS_ALLOCED BIT(0)
#define DCA_MEM_FLAGS_REGISTERED BIT(1)

#define DCA_MEM_AGEING_MSES 1000 /* DCA mem ageing interval time */
#define UDMA_DCA_INVALID_BUF_ID 0U
#define DCA_MEM_STOP_ITERATE (-1)
#define DCA_MEM_NEXT_ITERATE (-2)

#define DCAN_TO_SYNC_BIT(n) ((n) * UDMA_DCA_BITS_PER_STATUS)
#define DCAN_TO_STAT_BIT(n) DCAN_TO_SYNC_BIT(n)

#define UDMA_DCA_OWN_MASK GENMASK(21, 0)

/*
 * buffer id(29b) = tag(7b) + owner(22b)
 * [28:22] tag  : indicate the QP config update times.
 * [21: 0] owner: indicate the QP to which the page belongs.
 */
#define UDMA_DCA_ID_MASK GENMASK(28, 0)
#define UDMA_DCA_TAG_MASK GENMASK(28, 22)
#define UDMA_DCA_OWN_MASK GENMASK(21, 0)

#define UDMA_DCA_BUF_ID_TO_QPN(buf_id) ((buf_id) & UDMA_DCA_OWN_MASK)
#define UDMA_DCA_TO_BUF_ID(qpn, tag) (((qpn) & UDMA_DCA_OWN_MASK) | \
				      (((tag) << 22) & UDMA_DCA_TAG_MASK))

/* DCA page state (32 bit) */
struct dca_page_state {
	uint32_t buf_id		: 29; /* If zero, means page can be used by any buffer. */
	uint32_t lock		: 1; /* @buf_id locked this page to prepare access. */
	uint32_t active		: 1; /* @buf_id is accessing this page. */
	uint32_t head		: 1; /* This page is the head in a continuous address range. */
};

struct dca_mem {
	uint32_t		flags; /* dca mem usages status */
	struct list_head	list; /* link to mem list in dca context */
	spinlock_t		lock; /* protect the @flags and @list */
	uint32_t		page_count; /* page count in this mem obj */
	uint64_t		key; /* register by caller */
	uint32_t		size; /* bytes in this mem object */
	struct dca_page_state	*states; /* record each page's state */
	void			*pages; /* memory handle for getting dma address */
};

struct dca_page_free_buf_attr {
	uint32_t buf_id;
	uint32_t max_pages;
	uint32_t free_pages;
	uint32_t clean_mems;
};

struct dca_page_assign_attr {
	uint32_t buf_id;
	uint32_t unit;
	uint32_t total;
	uint32_t max;
};

struct dca_page_clear_attr {
	uint32_t buf_id;
	uint32_t max_pages;
	uint32_t clear_pages;
};

struct dca_get_alloced_pages_attr {
	uint32_t buf_id;
	dma_addr_t *pages;
	uint32_t total;
	uint32_t max;
};

struct dca_page_active_attr {
	uint32_t buf_id;
	uint32_t max_pages;
	uint32_t alloc_pages;
	uint32_t dirty_mems;
};

struct dca_page_query_active_attr {
	uint32_t buf_id;
	uint32_t curr_index;
	uint32_t start_index;
	uint32_t page_index;
	uint32_t page_count;
	uint64_t mem_key;
};

typedef int (*udma_dca_enum_callback)(struct dca_page_state *states,
				      uint32_t count, void *param);

struct dca_mem_enum_attr {
	void *param;
	udma_dca_enum_callback enum_fn;
};

static inline bool dca_page_is_attached(struct dca_page_state *state,
					uint32_t buf_id)
{
	/* only the own bit needs to be matched. */
	return (UDMA_DCA_OWN_MASK & buf_id) ==
	       (UDMA_DCA_OWN_MASK & state->buf_id);
}

static inline bool dca_mem_is_available(struct dca_mem *mem)
{
	return mem->flags == (DCA_MEM_FLAGS_ALLOCED | DCA_MEM_FLAGS_REGISTERED);
}

static inline void set_dca_page_to_free(struct dca_page_state *state)
{
	state->buf_id = UDMA_DCA_INVALID_BUF_ID;
	state->active = 0;
	state->lock = 0;
}

static inline bool dca_page_is_free(struct dca_page_state *state)
{
	return state->buf_id == UDMA_DCA_INVALID_BUF_ID;
}

static inline bool dca_page_is_active(struct dca_page_state *state,
				      uint32_t buf_id)
{
	/* all buf id bits must be matched */
	return (UDMA_DCA_ID_MASK & buf_id) == state->buf_id &&
		!state->lock && state->active;
}

static inline bool dca_page_is_inactive(struct dca_page_state *state)
{
	return !state->lock && !state->active;
}

static inline void lock_dca_page_to_attach(struct dca_page_state *state,
					   uint32_t buf_id)
{
	state->buf_id = UDMA_DCA_ID_MASK & buf_id;
	state->active = 0;
	state->lock = 1;
}

static inline bool dca_page_is_allocated(struct dca_page_state *state,
					 uint32_t buf_id)
{
	return dca_page_is_attached(state, buf_id) && state->lock;
}

static inline void unlock_dca_page_to_active(struct dca_page_state *state,
					     uint32_t buf_id)
{
	state->buf_id = UDMA_DCA_ID_MASK & buf_id;
	state->active = 1;
	state->lock = 0;
}

void udma_enable_dca(struct udma_dev *dev, struct udma_qp *qp);
void udma_disable_dca(struct udma_dev *dev, struct udma_qp *qp);

void udma_modify_dca(struct udma_dev *dev, struct udma_qp *qp);

int udma_register_dca_mem(struct udma_dev *dev, struct udma_ucontext *context,
			  struct udma_dca_reg_attr *attr);
int udma_unregister_dca_mem(struct udma_dev *dev,
			    struct udma_ucontext *context,
			    struct udma_dca_dereg_attr *attr, bool from_user);

void udma_shrink_dca_mem(struct udma_dev *dev, struct udma_ucontext *context,
			 struct udma_dca_shrink_attr *attr,
			 struct udma_dca_shrink_resp *resp);

int udma_query_dca_mem(struct udma_dev *dev, struct udma_dca_query_attr *attr,
		       struct udma_dca_query_resp *resp);

int udma_dca_attach(struct udma_dev *dev, struct udma_dca_attach_attr *attr,
		    struct udma_dca_attach_resp *resp);
void udma_dca_disattach(struct udma_dev *dev, struct udma_dca_attach_attr *attr);
void udma_dca_detach(struct udma_dev *dev, struct udma_dca_detach_attr *attr);

int udma_register_udca(struct udma_dev *udma_dev,
		       struct udma_ucontext *context, struct ubcore_udrv_priv *udrv_data);

void udma_unregister_udca(struct udma_dev *udma_dev,
			  struct udma_ucontext *context);

void udma_enum_dca_pool(struct udma_dca_ctx *dca_ctx, void *param,
			udma_dca_enum_callback cb);
#endif /* _UDMA_DCA_H */
