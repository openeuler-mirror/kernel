// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2022 Hisilicon Limited. All rights reserved.
 */

#include <rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>
#include <rdma/uverbs_types.h>
#include <rdma/uverbs_ioctl.h>
#include <rdma/uverbs_std_types.h>
#include <rdma/ib_umem.h>
#include "hns_roce_device.h"
#include "hns_roce_dca.h"

#define UVERBS_MODULE_NAME hns_ib
#include <rdma/uverbs_named_ioctl.h>

/* DCA mem ageing interval time */
#define DCA_MEM_AGEING_MSES 1000

/* DCA memory */
struct dca_mem {
#define DCA_MEM_FLAGS_ALLOCED BIT(0)
#define DCA_MEM_FLAGS_REGISTERED BIT(1)
	u32 flags;
	struct list_head list; /* link to mem list in dca context */
	spinlock_t lock; /* protect the @flags and @list */
	int page_count; /* page count in this mem obj */
	u64 key; /* register by caller */
	u32 size; /* bytes in this mem object */
	struct hns_dca_page_state *states; /* record each page's state */
	void *pages; /* memory handle for getting dma address */
};

struct dca_mem_attr {
	u64 key;
	u64 addr;
	u32 size;
};

static inline void set_dca_page_to_free(struct hns_dca_page_state *state)
{
	state->buf_id = HNS_DCA_INVALID_BUF_ID;
	state->active = 0;
	state->lock = 0;
}

static inline void set_dca_page_to_inactive(struct hns_dca_page_state *state)
{
	state->active = 0;
	state->lock = 0;
}

static inline void lock_dca_page_to_attach(struct hns_dca_page_state *state,
					   u32 buf_id)
{
	state->buf_id = HNS_DCA_ID_MASK & buf_id;
	state->active = 0;
	state->lock = 1;
}

static inline void unlock_dca_page_to_active(struct hns_dca_page_state *state,
					     u32 buf_id)
{
	state->buf_id = HNS_DCA_ID_MASK & buf_id;
	state->active = 1;
	state->lock = 0;
}

static inline bool dca_page_is_free(struct hns_dca_page_state *state)
{
	return state->buf_id == HNS_DCA_INVALID_BUF_ID;
}

static inline bool dca_page_is_attached(struct hns_dca_page_state *state,
					u32 buf_id)
{
	/* only the own bit needs to be matched. */
	return (HNS_DCA_OWN_MASK & buf_id) ==
			(HNS_DCA_OWN_MASK & state->buf_id);
}

static inline bool dca_page_is_allocated(struct hns_dca_page_state *state,
					 u32 buf_id)
{
	return dca_page_is_attached(state, buf_id) && state->lock;
}

static inline bool dca_page_is_inactive(struct hns_dca_page_state *state)
{
	return !state->lock && !state->active;
}

static inline bool dca_mem_is_available(struct dca_mem *mem)
{
	return mem->flags == (DCA_MEM_FLAGS_ALLOCED | DCA_MEM_FLAGS_REGISTERED);
}

static void *alloc_dca_pages(struct hns_roce_dev *hr_dev, struct dca_mem *mem,
			     struct dca_mem_attr *attr)
{
	struct ib_device *ibdev = &hr_dev->ib_dev;
	struct ib_umem *umem;

	umem = ib_umem_get(ibdev, attr->addr, attr->size, 0);
	if (IS_ERR(umem)) {
		ibdev_err(ibdev, "failed to get uDCA pages, ret = %ld.\n",
			  PTR_ERR(umem));
		return NULL;
	}

	mem->page_count = ib_umem_num_dma_blocks(umem, HNS_HW_PAGE_SIZE);

	return umem;
}

static void init_dca_umem_states(struct hns_dca_page_state *states, int count,
				 struct ib_umem *umem)
{
	struct ib_block_iter biter;
	dma_addr_t cur_addr;
	dma_addr_t pre_addr;
	int i = 0;

	pre_addr = 0;
	rdma_for_each_block(umem->sgt_append.sgt.sgl, &biter,
			    umem->sgt_append.sgt.nents, HNS_HW_PAGE_SIZE) {
		cur_addr = rdma_block_iter_dma_address(&biter);
		if (i < count) {
			if (cur_addr - pre_addr != HNS_HW_PAGE_SIZE)
				states[i].head = 1;
		}

		pre_addr = cur_addr;
		i++;
	}
}

static struct hns_dca_page_state *alloc_dca_states(void *pages, int count)
{
	struct hns_dca_page_state *states;

	states = kcalloc(count, sizeof(*states), GFP_KERNEL);
	if (!states)
		return NULL;

	init_dca_umem_states(states, count, pages);

	return states;
}

#define DCA_MEM_STOP_ITERATE -1
#define DCA_MEM_NEXT_ITERATE -2
static void travel_dca_pages(struct hns_roce_dca_ctx *ctx, void *param,
			     int (*cb)(struct dca_mem *, int, void *))
{
	struct dca_mem *mem, *tmp;
	unsigned long flags;
	bool avail;
	int ret;
	int i;

	spin_lock_irqsave(&ctx->pool_lock, flags);
	list_for_each_entry_safe(mem, tmp, &ctx->pool, list) {
		spin_unlock_irqrestore(&ctx->pool_lock, flags);

		spin_lock(&mem->lock);
		avail = dca_mem_is_available(mem);
		ret = 0;
		for (i = 0; avail && i < mem->page_count; i++) {
			ret = cb(mem, i, param);
			if (ret == DCA_MEM_STOP_ITERATE ||
			    ret == DCA_MEM_NEXT_ITERATE)
				break;
		}
		spin_unlock(&mem->lock);
		spin_lock_irqsave(&ctx->pool_lock, flags);

		if (ret == DCA_MEM_STOP_ITERATE)
			goto done;
	}

done:
	spin_unlock_irqrestore(&ctx->pool_lock, flags);
}

/* user DCA is managed by ucontext */
static inline struct hns_roce_dca_ctx *
to_hr_dca_ctx(struct hns_roce_ucontext *uctx)
{
	return &uctx->dca_ctx;
}

static void unregister_dca_mem(struct hns_roce_ucontext *uctx,
			       struct dca_mem *mem)
{
	struct hns_roce_dca_ctx *ctx = to_hr_dca_ctx(uctx);
	unsigned long flags;
	void *states, *pages;

	spin_lock_irqsave(&ctx->pool_lock, flags);

	spin_lock(&mem->lock);
	mem->flags &= ~DCA_MEM_FLAGS_REGISTERED;
	mem->page_count = 0;
	pages = mem->pages;
	mem->pages = NULL;
	states = mem->states;
	mem->states = NULL;
	spin_unlock(&mem->lock);

	ctx->free_mems--;
	ctx->free_size -= mem->size;

	ctx->total_size -= mem->size;
	spin_unlock_irqrestore(&ctx->pool_lock, flags);

	kfree(states);
	ib_umem_release(pages);
}

static int register_dca_mem(struct hns_roce_dev *hr_dev,
			    struct hns_roce_ucontext *uctx,
			    struct dca_mem *mem, struct dca_mem_attr *attr)
{
	struct hns_roce_dca_ctx *ctx = to_hr_dca_ctx(uctx);
	void *states, *pages;
	unsigned long flags;

	pages = alloc_dca_pages(hr_dev, mem, attr);
	if (!pages)
		return -ENOMEM;

	states = alloc_dca_states(pages, mem->page_count);
	if (!states) {
		ib_umem_release(pages);
		return -ENOMEM;
	}

	spin_lock_irqsave(&ctx->pool_lock, flags);

	spin_lock(&mem->lock);
	mem->pages = pages;
	mem->states = states;
	mem->key = attr->key;
	mem->size = attr->size;
	mem->flags |= DCA_MEM_FLAGS_REGISTERED;
	spin_unlock(&mem->lock);

	ctx->free_mems++;
	ctx->free_size += attr->size;
	ctx->total_size += attr->size;
	spin_unlock_irqrestore(&ctx->pool_lock, flags);

	return 0;
}

struct dca_mem_shrink_attr {
	u64 shrink_key;
	u32 shrink_mems;
};

static int shrink_dca_page_proc(struct dca_mem *mem, int index, void *param)
{
	struct dca_mem_shrink_attr *attr = param;
	struct hns_dca_page_state *state;
	int i, free_pages;

	free_pages = 0;
	for (i = 0; i < mem->page_count; i++) {
		state = &mem->states[i];
		if (dca_page_is_free(state))
			free_pages++;
	}

	/* No pages are in use */
	if (free_pages == mem->page_count) {
		/* unregister first empty DCA mem */
		if (!attr->shrink_mems) {
			mem->flags &= ~DCA_MEM_FLAGS_REGISTERED;
			attr->shrink_key = mem->key;
		}

		attr->shrink_mems++;
	}

	if (attr->shrink_mems > 1)
		return DCA_MEM_STOP_ITERATE;
	else
		return DCA_MEM_NEXT_ITERATE;
}

static void shrink_dca_mem(struct hns_roce_dev *hr_dev,
			  struct hns_roce_ucontext *uctx, u64 reserved_size,
			  struct hns_dca_shrink_resp *resp)
{
	struct hns_roce_dca_ctx *ctx = to_hr_dca_ctx(uctx);
	struct dca_mem_shrink_attr attr = {};
	unsigned long flags;
	bool need_shink;

	spin_lock_irqsave(&ctx->pool_lock, flags);
	need_shink = ctx->free_mems > 0 && ctx->free_size > reserved_size;
	spin_unlock_irqrestore(&ctx->pool_lock, flags);
	if (!need_shink)
		return;

	travel_dca_pages(ctx, &attr, shrink_dca_page_proc);
	resp->free_mems = attr.shrink_mems;
	resp->free_key = attr.shrink_key;
}

static void init_dca_context(struct hns_roce_dca_ctx *ctx)
{
	INIT_LIST_HEAD(&ctx->pool);
	spin_lock_init(&ctx->pool_lock);
	ctx->total_size = 0;
}

static void cleanup_dca_context(struct hns_roce_dev *hr_dev,
				struct hns_roce_dca_ctx *ctx)
{
	struct dca_mem *mem, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&ctx->pool_lock, flags);
	list_for_each_entry_safe(mem, tmp, &ctx->pool, list) {
		list_del(&mem->list);
		mem->flags = 0;
		spin_unlock_irqrestore(&ctx->pool_lock, flags);

		kfree(mem->states);
		ib_umem_release(mem->pages);
		kfree(mem);

		spin_lock_irqsave(&ctx->pool_lock, flags);
	}
	ctx->total_size = 0;
	spin_unlock_irqrestore(&ctx->pool_lock, flags);
}

void hns_roce_register_udca(struct hns_roce_dev *hr_dev,
			    struct hns_roce_ucontext *uctx)
{
	if (!(uctx->config & HNS_ROCE_UCTX_CONFIG_DCA))
		return;

	init_dca_context(&uctx->dca_ctx);
}

void hns_roce_unregister_udca(struct hns_roce_dev *hr_dev,
			      struct hns_roce_ucontext *uctx)
{
	if (!(uctx->config & HNS_ROCE_UCTX_CONFIG_DCA))
		return;

	cleanup_dca_context(hr_dev, &uctx->dca_ctx);
}

static struct dca_mem *alloc_dca_mem(struct hns_roce_dca_ctx *ctx)
{
	struct dca_mem *mem, *tmp, *found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&ctx->pool_lock, flags);
	list_for_each_entry_safe(mem, tmp, &ctx->pool, list) {
		spin_lock(&mem->lock);
		if (!mem->flags) {
			found = mem;
			mem->flags |= DCA_MEM_FLAGS_ALLOCED;
			spin_unlock(&mem->lock);
			break;
		}
		spin_unlock(&mem->lock);
	}
	spin_unlock_irqrestore(&ctx->pool_lock, flags);

	if (found)
		return found;

	mem = kzalloc(sizeof(*mem), GFP_NOWAIT);
	if (!mem)
		return NULL;

	spin_lock_init(&mem->lock);
	INIT_LIST_HEAD(&mem->list);

	mem->flags |= DCA_MEM_FLAGS_ALLOCED;

	spin_lock_irqsave(&ctx->pool_lock, flags);
	list_add(&mem->list, &ctx->pool);
	spin_unlock_irqrestore(&ctx->pool_lock, flags);

	return mem;
}

static void free_dca_mem(struct dca_mem *mem)
{
	/* We cannot hold the whole pool's lock during the DCA is working
	 * until cleanup the context in cleanup_dca_context(), so we just
	 * set the DCA mem state as free when destroying DCA mem object.
	 */
	spin_lock(&mem->lock);
	mem->flags = 0;
	spin_unlock(&mem->lock);
}

static inline struct hns_roce_dca_ctx *hr_qp_to_dca_ctx(struct hns_roce_qp *qp)
{
	return to_hr_dca_ctx(to_hr_ucontext(qp->ibqp.pd->uobject->context));
}

struct dca_page_clear_attr {
	u32 buf_id;
	u32 max_pages;
	u32 clear_pages;
};

static int clear_dca_pages_proc(struct dca_mem *mem, int index, void *param)
{
	struct hns_dca_page_state *state = &mem->states[index];
	struct dca_page_clear_attr *attr = param;

	if (dca_page_is_attached(state, attr->buf_id)) {
		set_dca_page_to_free(state);
		attr->clear_pages++;
	}

	if (attr->clear_pages >= attr->max_pages)
		return DCA_MEM_STOP_ITERATE;
	else
		return 0;
}

static void clear_dca_pages(struct hns_roce_dca_ctx *ctx, u32 buf_id, u32 count)
{
	struct dca_page_clear_attr attr = {};

	attr.buf_id = buf_id;
	attr.max_pages = count;
	travel_dca_pages(ctx, &attr, clear_dca_pages_proc);
}

struct dca_page_assign_attr {
	u32 buf_id;
	int unit;
	int total;
	int max;
};

static bool dca_page_is_allocable(struct hns_dca_page_state *state, bool head)
{
	bool is_free = dca_page_is_free(state) || dca_page_is_inactive(state);

	return head ? is_free : is_free && !state->head;
}

static int assign_dca_pages_proc(struct dca_mem *mem, int index, void *param)
{
	struct dca_page_assign_attr *attr = param;
	struct hns_dca_page_state *state;
	int checked_pages = 0;
	int start_index = 0;
	int free_pages = 0;
	int i;

	/* Check the continuous pages count is not smaller than unit count */
	for (i = index; free_pages < attr->unit && i < mem->page_count; i++) {
		checked_pages++;
		state = &mem->states[i];
		if (dca_page_is_allocable(state, free_pages == 0)) {
			if (free_pages == 0)
				start_index = i;

			free_pages++;
		} else {
			free_pages = 0;
		}
	}

	if (free_pages < attr->unit)
		return DCA_MEM_NEXT_ITERATE;

	for (i = 0; i < free_pages; i++) {
		state = &mem->states[start_index + i];
		lock_dca_page_to_attach(state, attr->buf_id);
		attr->total++;
	}

	if (attr->total >= attr->max)
		return DCA_MEM_STOP_ITERATE;

	return checked_pages;
}

static u32 assign_dca_pages(struct hns_roce_dca_ctx *ctx, u32 buf_id, u32 count,
			    u32 unit)
{
	struct dca_page_assign_attr attr = {};

	attr.buf_id = buf_id;
	attr.unit = unit;
	attr.max = count;
	travel_dca_pages(ctx, &attr, assign_dca_pages_proc);
	return attr.total;
}

struct dca_page_active_attr {
	u32 buf_id;
	u32 max_pages;
	u32 alloc_pages;
	u32 dirty_mems;
};

static int active_dca_pages_proc(struct dca_mem *mem, int index, void *param)
{
	struct dca_page_active_attr *attr = param;
	struct hns_dca_page_state *state;
	bool changed = false;
	bool stop = false;
	int i, free_pages;

	free_pages = 0;
	for (i = 0; !stop && i < mem->page_count; i++) {
		state = &mem->states[i];
		if (dca_page_is_free(state)) {
			free_pages++;
		} else if (dca_page_is_allocated(state, attr->buf_id)) {
			free_pages++;
			/* Change matched pages state */
			unlock_dca_page_to_active(state, attr->buf_id);
			changed = true;
			attr->alloc_pages++;
			if (attr->alloc_pages == attr->max_pages)
				stop = true;
		}
	}

	for (; changed && i < mem->page_count; i++)
		if (dca_page_is_free(state))
			free_pages++;

	/* Clean mem changed to dirty */
	if (changed && free_pages == mem->page_count)
		attr->dirty_mems++;

	return stop ? DCA_MEM_STOP_ITERATE : DCA_MEM_NEXT_ITERATE;
}

static u32 active_dca_pages(struct hns_roce_dca_ctx *ctx, u32 buf_id, u32 count)
{
	struct dca_page_active_attr attr = {};
	unsigned long flags;

	attr.buf_id = buf_id;
	attr.max_pages = count;
	travel_dca_pages(ctx, &attr, active_dca_pages_proc);

	/* Update free size */
	spin_lock_irqsave(&ctx->pool_lock, flags);
	ctx->free_mems -= attr.dirty_mems;
	ctx->free_size -= attr.alloc_pages << HNS_HW_PAGE_SHIFT;
	spin_unlock_irqrestore(&ctx->pool_lock, flags);

	return attr.alloc_pages;
}

struct dca_get_alloced_pages_attr {
	u32 buf_id;
	dma_addr_t *pages;
	u32 total;
	u32 max;
};

static int get_alloced_umem_proc(struct dca_mem *mem, int index, void *param)

{
	struct dca_get_alloced_pages_attr *attr = param;
	struct hns_dca_page_state *states = mem->states;
	struct ib_umem *umem = mem->pages;
	struct ib_block_iter biter;
	u32 i = 0;

	rdma_for_each_block(umem->sgt_append.sgt.sgl, &biter,
			    umem->sgt_append.sgt.nents, HNS_HW_PAGE_SIZE) {
		if (dca_page_is_allocated(&states[i], attr->buf_id)) {
			attr->pages[attr->total++] =
					rdma_block_iter_dma_address(&biter);
			if (attr->total >= attr->max)
				return DCA_MEM_STOP_ITERATE;
		}
		i++;
	}

	return DCA_MEM_NEXT_ITERATE;
}

static int apply_dca_cfg(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp,
			 struct hns_dca_attach_attr *attach_attr)
{
	struct hns_roce_dca_attr attr;

	if (hr_dev->hw->set_dca_buf) {
		attr.sq_offset = attach_attr->sq_offset;
		attr.sge_offset = attach_attr->sge_offset;
		attr.rq_offset = attach_attr->rq_offset;
		return hr_dev->hw->set_dca_buf(hr_dev, hr_qp, &attr);
	}

	return 0;
}

static int setup_dca_buf_to_hw(struct hns_roce_dca_ctx *ctx,
			       struct hns_roce_qp *hr_qp, u32 buf_id,
			       struct hns_dca_attach_attr *attach_attr)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(hr_qp->ibqp.device);
	struct dca_get_alloced_pages_attr attr = {};
	struct ib_device *ibdev = &hr_dev->ib_dev;
	u32 count = hr_qp->dca_cfg.npages;
	dma_addr_t *pages;
	int ret;

	/* Alloc a tmp array to store buffer's dma address */
	pages = kvcalloc(count, sizeof(dma_addr_t), GFP_NOWAIT);
	if (!pages)
		return -ENOMEM;

	attr.buf_id = buf_id;
	attr.pages = pages;
	attr.max = count;

	travel_dca_pages(ctx, &attr, get_alloced_umem_proc);
	if (attr.total != count) {
		ibdev_err(ibdev, "failed to get DCA page %u != %u.\n",
			  attr.total, count);
		ret = -ENOMEM;
		goto done;
	}

	/* Update MTT for ROCEE addressing */
	ret = hns_roce_mtr_map(hr_dev, &hr_qp->mtr, pages, count);
	if (ret) {
		ibdev_err(ibdev, "failed to map DCA pages, ret = %d.\n", ret);
		goto done;
	}

	/* Apply the changes for WQE address */
	ret = apply_dca_cfg(hr_dev, hr_qp, attach_attr);
	if (ret)
		ibdev_err(ibdev, "failed to apply DCA cfg, ret = %d.\n", ret);

done:
	/* Drop tmp array */
	kvfree(pages);
	return ret;
}

static u32 alloc_buf_from_dca_mem(struct hns_roce_qp *hr_qp,
				  struct hns_roce_dca_ctx *ctx)
{
	u32 buf_pages, unit_pages, alloc_pages;
	u32 buf_id;

	buf_pages = hr_qp->dca_cfg.npages;
	/* Gen new buf id */
	buf_id = HNS_DCA_TO_BUF_ID(hr_qp->qpn, hr_qp->dca_cfg.attach_count);

	/* Assign pages from free pages */
	unit_pages = hr_qp->mtr.hem_cfg.is_direct ? buf_pages : 1;
	alloc_pages = assign_dca_pages(ctx, buf_id, buf_pages, unit_pages);
	if (buf_pages != alloc_pages) {
		if (alloc_pages > 0)
			clear_dca_pages(ctx, buf_id, alloc_pages);
		return HNS_DCA_INVALID_BUF_ID;
	}

	return buf_id;
}

static int active_alloced_buf(struct hns_roce_qp *hr_qp,
			      struct hns_roce_dca_ctx *ctx,
			      struct hns_dca_attach_attr *attr, u32 buf_id)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(hr_qp->ibqp.device);
	struct ib_device *ibdev = &hr_dev->ib_dev;
	u32 active_pages, alloc_pages;
	int ret;

	ret = setup_dca_buf_to_hw(ctx, hr_qp, buf_id, attr);
	if (ret) {
		ibdev_err(ibdev, "failed to setup DCA buf, ret = %d.\n", ret);
		goto active_fail;
	}

	alloc_pages = hr_qp->dca_cfg.npages;
	active_pages = active_dca_pages(ctx, buf_id, alloc_pages);
	if (active_pages != alloc_pages) {
		ibdev_err(ibdev, "failed to active DCA pages, %u != %u.\n",
			  active_pages, alloc_pages);
		ret = -ENOBUFS;
		goto active_fail;
	}

	return 0;

active_fail:
	clear_dca_pages(ctx, buf_id, alloc_pages);
	return ret;
}

static int attach_dca_mem(struct hns_roce_dev *hr_dev,
			  struct hns_roce_qp *hr_qp,
			  struct hns_dca_attach_attr *attr,
			  struct hns_dca_attach_resp *resp)
{
	struct hns_roce_dca_ctx *ctx = hr_qp_to_dca_ctx(hr_qp);
	struct hns_roce_dca_cfg *cfg = &hr_qp->dca_cfg;
	u32 buf_id;
	int ret;

	/* Stop DCA mem ageing worker */
	cancel_delayed_work(&cfg->dwork);
	resp->alloc_flags = 0;

	spin_lock(&cfg->lock);
	buf_id = cfg->buf_id;
	/* Already attached */
	if (buf_id != HNS_DCA_INVALID_BUF_ID) {
		resp->alloc_pages = cfg->npages;
		spin_unlock(&cfg->lock);
		return 0;
	}

	/* Start to new attach */
	resp->alloc_pages = 0;
	buf_id = alloc_buf_from_dca_mem(hr_qp, ctx);
	if (buf_id == HNS_DCA_INVALID_BUF_ID) {
		spin_unlock(&cfg->lock);
		/* No report fail, need try again after the pool increased */
		return 0;
	}

	ret = active_alloced_buf(hr_qp, ctx, attr, buf_id);
	if (ret) {
		spin_unlock(&cfg->lock);
		ibdev_err(&hr_dev->ib_dev,
			  "failed to active DCA buf for QP-%lu, ret = %d.\n",
			  hr_qp->qpn, ret);
		return ret;
	}

	/* Attach ok */
	cfg->buf_id = buf_id;
	cfg->attach_count++;
	spin_unlock(&cfg->lock);

	resp->alloc_flags |= HNS_IB_ATTACH_FLAGS_NEW_BUFFER;
	resp->alloc_pages = cfg->npages;

	return 0;
}

struct dca_page_free_buf_attr {
	u32 buf_id;
	u32 max_pages;
	u32 free_pages;
	u32 clean_mems;
};

static int free_buffer_pages_proc(struct dca_mem *mem, int index, void *param)
{
	struct dca_page_free_buf_attr *attr = param;
	struct hns_dca_page_state *state;
	bool changed = false;
	bool stop = false;
	int i, free_pages;

	free_pages = 0;
	for (i = 0; !stop && i < mem->page_count; i++) {
		state = &mem->states[i];
		/* Change matched pages state */
		if (dca_page_is_attached(state, attr->buf_id)) {
			set_dca_page_to_free(state);
			changed = true;
			attr->free_pages++;
			if (attr->free_pages == attr->max_pages)
				stop = true;
		}

		if (dca_page_is_free(state))
			free_pages++;
	}

	for (; changed && i < mem->page_count; i++)
		if (dca_page_is_free(state))
			free_pages++;

	if (changed && free_pages == mem->page_count)
		attr->clean_mems++;

	return stop ? DCA_MEM_STOP_ITERATE : DCA_MEM_NEXT_ITERATE;
}

static void free_buf_from_dca_mem(struct hns_roce_dca_ctx *ctx,
				  struct hns_roce_dca_cfg *cfg)
{
	struct dca_page_free_buf_attr attr = {};
	unsigned long flags;
	u32 buf_id;

	spin_lock(&cfg->lock);
	buf_id = cfg->buf_id;
	cfg->buf_id = HNS_DCA_INVALID_BUF_ID;
	spin_unlock(&cfg->lock);
	if (buf_id == HNS_DCA_INVALID_BUF_ID)
		return;

	attr.buf_id = buf_id;
	attr.max_pages = cfg->npages;
	travel_dca_pages(ctx, &attr, free_buffer_pages_proc);

	/* Update free size */
	spin_lock_irqsave(&ctx->pool_lock, flags);
	ctx->free_mems += attr.clean_mems;
	ctx->free_size += attr.free_pages << HNS_HW_PAGE_SHIFT;
	spin_unlock_irqrestore(&ctx->pool_lock, flags);
}

static void kick_dca_mem(struct hns_roce_dev *hr_dev,
			 struct hns_roce_dca_cfg *cfg,
			 struct hns_roce_ucontext *uctx)
{
	struct hns_roce_dca_ctx *ctx = to_hr_dca_ctx(uctx);

	/* Stop ageing worker and free DCA buffer from pool */
	cancel_delayed_work_sync(&cfg->dwork);
	free_buf_from_dca_mem(ctx, cfg);
}

static void dca_mem_ageing_work(struct work_struct *work)
{
	struct hns_roce_qp *hr_qp = container_of(work, struct hns_roce_qp,
						 dca_cfg.dwork.work);
	struct hns_roce_dev *hr_dev = to_hr_dev(hr_qp->ibqp.device);
	struct hns_roce_dca_ctx *ctx = hr_qp_to_dca_ctx(hr_qp);
	bool hw_is_inactive;

	hw_is_inactive = hr_dev->hw->chk_dca_buf_inactive &&
			 hr_dev->hw->chk_dca_buf_inactive(hr_dev, hr_qp);
	if (hw_is_inactive)
		free_buf_from_dca_mem(ctx, &hr_qp->dca_cfg);
}

void hns_roce_dca_kick(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp)
{
	struct hns_roce_ucontext *uctx;

	if (hr_qp->ibqp.uobject && hr_qp->ibqp.pd->uobject) {
		uctx = to_hr_ucontext(hr_qp->ibqp.pd->uobject->context);
		kick_dca_mem(hr_dev, &hr_qp->dca_cfg, uctx);
	}
}

static void detach_dca_mem(struct hns_roce_dev *hr_dev,
			   struct hns_roce_qp *hr_qp,
			   struct hns_dca_detach_attr *attr)
{
	struct hns_roce_dca_cfg *cfg = &hr_qp->dca_cfg;

	/* Start an ageing worker to free buffer */
	cancel_delayed_work(&cfg->dwork);
	spin_lock(&cfg->lock);
	cfg->sq_idx = attr->sq_idx;
	queue_delayed_work(hr_dev->irq_workq, &cfg->dwork,
			   msecs_to_jiffies(DCA_MEM_AGEING_MSES));
	spin_unlock(&cfg->lock);
}

void hns_roce_enable_dca(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp)
{
	struct hns_roce_dca_cfg *cfg = &hr_qp->dca_cfg;

	spin_lock_init(&cfg->lock);
	INIT_DELAYED_WORK(&cfg->dwork, dca_mem_ageing_work);
	cfg->buf_id = HNS_DCA_INVALID_BUF_ID;
	cfg->npages = hr_qp->buff_size >> HNS_HW_PAGE_SHIFT;
}

void hns_roce_disable_dca(struct hns_roce_dev *hr_dev,
			  struct hns_roce_qp *hr_qp, struct ib_udata *udata)
{
	struct hns_roce_ucontext *uctx = rdma_udata_to_drv_context(udata,
					 struct hns_roce_ucontext, ibucontext);
	struct hns_roce_dca_cfg *cfg = &hr_qp->dca_cfg;

	kick_dca_mem(hr_dev, cfg, uctx);
	cfg->buf_id = HNS_DCA_INVALID_BUF_ID;
}

static inline struct hns_roce_ucontext *
uverbs_attr_to_hr_uctx(struct uverbs_attr_bundle *attrs)
{
	return rdma_udata_to_drv_context(&attrs->driver_udata,
					 struct hns_roce_ucontext, ibucontext);
}

static int UVERBS_HANDLER(HNS_IB_METHOD_DCA_MEM_REG)(
	struct uverbs_attr_bundle *attrs)
{
	struct hns_roce_ucontext *uctx = uverbs_attr_to_hr_uctx(attrs);
	struct hns_roce_dev *hr_dev = to_hr_dev(uctx->ibucontext.device);
	struct ib_uobject *uobj =
		uverbs_attr_get_uobject(attrs, HNS_IB_ATTR_DCA_MEM_REG_HANDLE);
	struct dca_mem_attr init_attr = {};
	struct dca_mem *mem;
	int ret;

	ret = uverbs_copy_from(&init_attr.addr, attrs,
			       HNS_IB_ATTR_DCA_MEM_REG_ADDR);
	if (!ret)
		ret = uverbs_copy_from(&init_attr.size, attrs,
				       HNS_IB_ATTR_DCA_MEM_REG_LEN);
	if (!ret)
		ret = uverbs_copy_from(&init_attr.key, attrs,
				       HNS_IB_ATTR_DCA_MEM_REG_KEY);
	if (ret)
		return ret;

	if (!init_attr.size)
		return -EINVAL;

	init_attr.size = hr_hw_page_align(init_attr.size);

	mem = alloc_dca_mem(to_hr_dca_ctx(uctx));
	if (!mem)
		return -ENOMEM;

	ret = register_dca_mem(hr_dev, uctx, mem, &init_attr);
	if (ret) {
		free_dca_mem(mem);
		return ret;
	}

	uobj->object = mem;

	return 0;
}

static int dca_cleanup(struct ib_uobject *uobject, enum rdma_remove_reason why,
		       struct uverbs_attr_bundle *attrs)
{
	struct hns_roce_ucontext *uctx = uverbs_attr_to_hr_uctx(attrs);
	struct dca_mem *mem;

	/* One DCA MEM maybe shared by many QPs, so the DCA mem uobject must
	 * be destroyed before all QP uobjects, and we will destroy the DCA
	 * uobjects when cleanup DCA context by calling hns_roce_cleanup_dca().
	 */
	if (why == RDMA_REMOVE_CLOSE || why == RDMA_REMOVE_DRIVER_REMOVE)
		return 0;

	mem = uobject->object;
	unregister_dca_mem(uctx, mem);
	free_dca_mem(mem);

	return 0;
}

DECLARE_UVERBS_NAMED_METHOD(
	HNS_IB_METHOD_DCA_MEM_REG,
	UVERBS_ATTR_IDR(HNS_IB_ATTR_DCA_MEM_REG_HANDLE, HNS_IB_OBJECT_DCA_MEM,
			UVERBS_ACCESS_NEW, UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(HNS_IB_ATTR_DCA_MEM_REG_LEN, UVERBS_ATTR_TYPE(u32),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(HNS_IB_ATTR_DCA_MEM_REG_ADDR, UVERBS_ATTR_TYPE(u64),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(HNS_IB_ATTR_DCA_MEM_REG_KEY, UVERBS_ATTR_TYPE(u64),
			   UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD_DESTROY(
	HNS_IB_METHOD_DCA_MEM_DEREG,
	UVERBS_ATTR_IDR(HNS_IB_ATTR_DCA_MEM_DEREG_HANDLE, HNS_IB_OBJECT_DCA_MEM,
			UVERBS_ACCESS_DESTROY, UA_MANDATORY));

static int UVERBS_HANDLER(HNS_IB_METHOD_DCA_MEM_SHRINK)(
	struct uverbs_attr_bundle *attrs)
{
	struct hns_roce_ucontext *uctx = uverbs_attr_to_hr_uctx(attrs);
	struct hns_dca_shrink_resp resp = {};
	u64 reserved_size = 0;
	int ret;

	ret = uverbs_copy_from(&reserved_size, attrs,
			       HNS_IB_ATTR_DCA_MEM_SHRINK_RESERVED_SIZE);
	if (ret)
		return ret;

	shrink_dca_mem(to_hr_dev(uctx->ibucontext.device), uctx,
		       reserved_size, &resp);

	ret = uverbs_copy_to(attrs, HNS_IB_ATTR_DCA_MEM_SHRINK_OUT_FREE_KEY,
			     &resp.free_key, sizeof(resp.free_key));
	if (!ret)
		ret = uverbs_copy_to(attrs,
				     HNS_IB_ATTR_DCA_MEM_SHRINK_OUT_FREE_MEMS,
				     &resp.free_mems, sizeof(resp.free_mems));
	if (ret)
		return ret;

	return 0;
}

DECLARE_UVERBS_NAMED_METHOD(
	HNS_IB_METHOD_DCA_MEM_SHRINK,
	UVERBS_ATTR_IDR(HNS_IB_ATTR_DCA_MEM_SHRINK_HANDLE,
			HNS_IB_OBJECT_DCA_MEM, UVERBS_ACCESS_WRITE,
			UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(HNS_IB_ATTR_DCA_MEM_SHRINK_RESERVED_SIZE,
			   UVERBS_ATTR_TYPE(u64), UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HNS_IB_ATTR_DCA_MEM_SHRINK_OUT_FREE_KEY,
			    UVERBS_ATTR_TYPE(u64), UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HNS_IB_ATTR_DCA_MEM_SHRINK_OUT_FREE_MEMS,
			    UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

static inline struct hns_roce_qp *
uverbs_attr_to_hr_qp(struct uverbs_attr_bundle *attrs)
{
	struct ib_uobject *uobj =
		uverbs_attr_get_uobject(attrs, 1U << UVERBS_ID_NS_SHIFT);

	if (uobj_get_object_id(uobj) == UVERBS_OBJECT_QP)
		return to_hr_qp(uobj->object);

	return NULL;
}

static int UVERBS_HANDLER(HNS_IB_METHOD_DCA_MEM_ATTACH)(
	struct uverbs_attr_bundle *attrs)
{
	struct hns_roce_qp *hr_qp = uverbs_attr_to_hr_qp(attrs);
	struct hns_dca_attach_attr attr = {};
	struct hns_dca_attach_resp resp = {};
	int ret;

	if (!hr_qp)
		return -EINVAL;

	ret = uverbs_copy_from(&attr.sq_offset, attrs,
			     HNS_IB_ATTR_DCA_MEM_ATTACH_SQ_OFFSET);
	if (!ret)
		ret = uverbs_copy_from(&attr.sge_offset, attrs,
				       HNS_IB_ATTR_DCA_MEM_ATTACH_SGE_OFFSET);
	if (!ret)
		ret = uverbs_copy_from(&attr.rq_offset, attrs,
				       HNS_IB_ATTR_DCA_MEM_ATTACH_RQ_OFFSET);
	if (ret)
		return ret;

	ret = attach_dca_mem(to_hr_dev(hr_qp->ibqp.device), hr_qp, &attr,
			     &resp);
	if (ret)
		return ret;

	ret = uverbs_copy_to(attrs, HNS_IB_ATTR_DCA_MEM_ATTACH_OUT_ALLOC_FLAGS,
			     &resp.alloc_flags, sizeof(resp.alloc_flags));
	if (!ret)
		ret = uverbs_copy_to(attrs,
				     HNS_IB_ATTR_DCA_MEM_ATTACH_OUT_ALLOC_PAGES,
				     &resp.alloc_pages,
				     sizeof(resp.alloc_pages));

	return ret;
}

DECLARE_UVERBS_NAMED_METHOD(
	HNS_IB_METHOD_DCA_MEM_ATTACH,
	UVERBS_ATTR_IDR(HNS_IB_ATTR_DCA_MEM_ATTACH_HANDLE, UVERBS_OBJECT_QP,
			UVERBS_ACCESS_WRITE, UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(HNS_IB_ATTR_DCA_MEM_ATTACH_SQ_OFFSET,
			   UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(HNS_IB_ATTR_DCA_MEM_ATTACH_SGE_OFFSET,
			   UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(HNS_IB_ATTR_DCA_MEM_ATTACH_RQ_OFFSET,
			   UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HNS_IB_ATTR_DCA_MEM_ATTACH_OUT_ALLOC_FLAGS,
			    UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HNS_IB_ATTR_DCA_MEM_ATTACH_OUT_ALLOC_PAGES,
			    UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

static int UVERBS_HANDLER(HNS_IB_METHOD_DCA_MEM_DETACH)(
	struct uverbs_attr_bundle *attrs)
{
	struct hns_roce_qp *hr_qp = uverbs_attr_to_hr_qp(attrs);
	struct hns_dca_detach_attr attr = {};
	int ret;

	if (!hr_qp)
		return -EINVAL;

	ret = uverbs_copy_from(&attr.sq_idx, attrs,
			       HNS_IB_ATTR_DCA_MEM_DETACH_SQ_INDEX);
	if (ret)
		return ret;

	detach_dca_mem(to_hr_dev(hr_qp->ibqp.device), hr_qp, &attr);

	return 0;
}

DECLARE_UVERBS_NAMED_METHOD(
	HNS_IB_METHOD_DCA_MEM_DETACH,
	UVERBS_ATTR_IDR(HNS_IB_ATTR_DCA_MEM_DETACH_HANDLE, UVERBS_OBJECT_QP,
			UVERBS_ACCESS_WRITE, UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(HNS_IB_ATTR_DCA_MEM_DETACH_SQ_INDEX,
			   UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_OBJECT(HNS_IB_OBJECT_DCA_MEM,
			    UVERBS_TYPE_ALLOC_IDR(dca_cleanup),
			    &UVERBS_METHOD(HNS_IB_METHOD_DCA_MEM_REG),
			    &UVERBS_METHOD(HNS_IB_METHOD_DCA_MEM_DEREG),
			    &UVERBS_METHOD(HNS_IB_METHOD_DCA_MEM_SHRINK),
			    &UVERBS_METHOD(HNS_IB_METHOD_DCA_MEM_ATTACH),
			    &UVERBS_METHOD(HNS_IB_METHOD_DCA_MEM_DETACH));

static bool dca_is_supported(struct ib_device *device)
{
	struct hns_roce_dev *dev = to_hr_dev(device);

	return dev->caps.flags & HNS_ROCE_CAP_FLAG_DCA_MODE;
}

const struct uapi_definition hns_roce_dca_uapi_defs[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(
		HNS_IB_OBJECT_DCA_MEM,
		UAPI_DEF_IS_OBJ_SUPPORTED(dca_is_supported)),
	{}
};
