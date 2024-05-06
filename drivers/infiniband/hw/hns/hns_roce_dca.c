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

static inline bool dca_page_is_active(struct hns_dca_page_state *state,
				      u32 buf_id)
{
	/* all buf id bits must be matched */
	return (HNS_DCA_ID_MASK & buf_id) == state->buf_id &&
		!state->lock && state->active;
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

static void free_dca_pages(struct hns_roce_dev *hr_dev, bool is_user,
			   void *pages)
{
	if (is_user)
		ib_umem_release(pages);
	else
		hns_roce_buf_free(hr_dev, pages);
}

static void *alloc_dca_pages(struct hns_roce_dev *hr_dev, bool is_user,
			     struct dca_mem *mem, struct dca_mem_attr *attr)
{
	struct ib_device *ibdev = &hr_dev->ib_dev;
	struct hns_roce_buf *kmem;

	if (is_user) {
		struct ib_umem *umem;

		umem = ib_umem_get(ibdev, attr->addr, attr->size, 0);
		if (IS_ERR(umem)) {
			ibdev_err(ibdev, "failed to get uDCA pages, ret = %ld.\n",
				  PTR_ERR(umem));
			return NULL;
		}

		mem->page_count = ib_umem_num_dma_blocks(umem,
							 HNS_HW_PAGE_SIZE);
		return umem;
	}

	kmem = hns_roce_buf_alloc(hr_dev, attr->size, HNS_HW_PAGE_SHIFT,
				  HNS_ROCE_BUF_NOSLEEP | HNS_ROCE_BUF_NOFAIL);
	if (IS_ERR(kmem)) {
		ibdev_err(ibdev, "failed to alloc kDCA pages, ret = %ld.\n",
			  PTR_ERR(kmem));
		return NULL;
	}

	mem->page_count = kmem->npages;
	/* Overwrite the attr->size by actually alloced size */
	attr->size = kmem->ntrunks << kmem->trunk_shift;
	return kmem;

}

static void init_dca_kmem_states(struct hns_dca_page_state *states, int count,
				 struct hns_roce_buf *kmem)
{
	dma_addr_t cur_addr;
	dma_addr_t pre_addr;
	int i;

	pre_addr = 0;
	for (i = 0; i < kmem->npages && i < count; i++) {
		cur_addr = hns_roce_buf_page(kmem, i);
		if (cur_addr - pre_addr != HNS_HW_PAGE_SIZE)
			states[i].head = 1;

		pre_addr = cur_addr;
	}
}

static void init_dca_umem_states(struct hns_dca_page_state *states, int count,
				 struct ib_umem *umem)
{
	struct ib_block_iter biter;
	dma_addr_t cur_addr;
	dma_addr_t pre_addr;
	int i = 0;

	pre_addr = 0;
	rdma_umem_for_each_dma_block(umem, &biter, HNS_HW_PAGE_SIZE) {
		cur_addr = rdma_block_iter_dma_address(&biter);
		if (i < count) {
			if (cur_addr - pre_addr != HNS_HW_PAGE_SIZE)
				states[i].head = 1;
		}

		pre_addr = cur_addr;
		i++;
	}
}

static struct hns_dca_page_state *alloc_dca_states(struct hns_roce_dev *hr_dev,
						   void *pages, int count,
						   bool is_user)
{
	struct hns_dca_page_state *states;

	states = kcalloc(count, sizeof(*states), GFP_KERNEL);
	if (!states)
		return NULL;

	if (is_user)
		init_dca_umem_states(states, count, pages);
	else
		init_dca_kmem_states(states, count, pages);

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

struct dca_get_alloced_pages_attr {
	u32 buf_id;
	dma_addr_t *pages;
	u32 total;
	u32 max;
};

static int get_alloced_kmem_proc(struct dca_mem *mem, int index, void *param)

{
	struct dca_get_alloced_pages_attr *attr = param;
	struct hns_dca_page_state *states = mem->states;
	struct hns_roce_buf *kmem = mem->pages;
	u32 i;

	for (i = 0; i < kmem->npages; i++) {
		if (dca_page_is_allocated(&states[i], attr->buf_id)) {
			attr->pages[attr->total++] = hns_roce_buf_page(kmem, i);
			if (attr->total >= attr->max)
				return DCA_MEM_STOP_ITERATE;
		}
	}

	return DCA_MEM_NEXT_ITERATE;
}

static int get_alloced_umem_proc(struct dca_mem *mem, int index, void *param)

{
	struct dca_get_alloced_pages_attr *attr = param;
	struct hns_dca_page_state *states = mem->states;
	struct ib_umem *umem = mem->pages;
	struct ib_block_iter biter;
	u32 i = 0;

	rdma_umem_for_each_dma_block(umem, &biter, HNS_HW_PAGE_SIZE) {
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

/* user DCA is managed by ucontext, kernel DCA is managed by device */
static inline struct hns_roce_dca_ctx *
to_hr_dca_ctx(struct hns_roce_dev *hr_dev, struct hns_roce_ucontext *uctx)
{
	return uctx ? &uctx->dca_ctx : &hr_dev->dca_ctx;
}

static inline struct hns_roce_dca_ctx *
hr_qp_to_dca_ctx(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp)
{
	struct hns_roce_ucontext *uctx = NULL;

	if (hr_qp->ibqp.pd->uobject)
		uctx = to_hr_ucontext(hr_qp->ibqp.pd->uobject->context);

	return to_hr_dca_ctx(hr_dev, uctx);
}

static int config_dca_qpc(struct hns_roce_dev *hr_dev,
			  struct hns_roce_qp *hr_qp, dma_addr_t *pages,
			  int page_count)
{
	struct ib_device *ibdev = &hr_dev->ib_dev;
	struct hns_roce_mtr *mtr = &hr_qp->mtr;
	int ret;

	ret = hns_roce_mtr_map(hr_dev, mtr, pages, page_count);
	if (ret) {
		ibdev_err(ibdev, "failed to map DCA pages, ret = %d.\n", ret);
		return ret;
	}

	if (hr_dev->hw->set_dca_buf) {
		ret = hr_dev->hw->set_dca_buf(hr_dev, hr_qp);
		if (ret) {
			ibdev_err(ibdev, "failed to set DCA to HW, ret = %d.\n",
				  ret);
			return ret;
		}
	}

	return 0;
}

static int setup_dca_buf_to_hw(struct hns_roce_dev *hr_dev,
			       struct hns_roce_qp *hr_qp,
			       struct hns_roce_dca_ctx *ctx, u32 buf_id,
			       u32 count)
{
	struct dca_get_alloced_pages_attr attr = {};
	dma_addr_t *pages;
	int ret;

	/* alloc a tmp array to store buffer's dma address */
	pages = kcalloc(count, sizeof(dma_addr_t), GFP_ATOMIC);
	if (!pages)
		return -ENOMEM;

	attr.buf_id = buf_id;
	attr.pages = pages;
	attr.max = count;

	if (hr_qp->ibqp.uobject)
		travel_dca_pages(ctx, &attr, get_alloced_umem_proc);
	else
		travel_dca_pages(ctx, &attr, get_alloced_kmem_proc);

	if (attr.total != count) {
		ibdev_err(&hr_dev->ib_dev, "failed to get DCA page %u != %u.\n",
			  attr.total, count);
		ret = -ENOMEM;
		goto err_get_pages;
	}

	ret = config_dca_qpc(hr_dev, hr_qp, pages, count);
err_get_pages:
	/* drop tmp array */
	kfree(pages);

	return ret;
}

static void unregister_dca_mem(struct hns_roce_dev *hr_dev,
			       struct hns_roce_ucontext *uctx,
			       struct dca_mem *mem)
{
	struct hns_roce_dca_ctx *ctx = to_hr_dca_ctx(hr_dev, uctx);
	bool is_user = !!uctx;
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
	free_dca_pages(hr_dev, is_user, pages);
}

static int register_dca_mem(struct hns_roce_dev *hr_dev,
			    struct hns_roce_ucontext *uctx,
			    struct dca_mem *mem, struct dca_mem_attr *attr)
{
	struct hns_roce_dca_ctx *ctx = to_hr_dca_ctx(hr_dev, uctx);
	bool is_user = !!uctx;
	void *states, *pages;
	unsigned long flags;

	pages = alloc_dca_pages(hr_dev, is_user, mem, attr);
	if (!pages)
		return -ENOMEM;

	states = alloc_dca_states(hr_dev, pages, mem->page_count, is_user);
	if (!states) {
		free_dca_pages(hr_dev, is_user, pages);
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

struct dca_page_query_active_attr {
	u32 buf_id;
	u32 curr_index;
	u32 start_index;
	u32 page_index;
	u32 page_count;
	u64 mem_key;
};

static int sync_dca_buf_offset(struct hns_roce_dev *hr_dev,
			       struct hns_roce_qp *hr_qp,
			       struct hns_dca_attach_attr *attr)
{
	struct ib_device *ibdev = &hr_dev->ib_dev;

	if (hr_qp->sq.wqe_cnt > 0) {
		if (attr->sq_offset >= hr_qp->sge.offset) {
			ibdev_err(ibdev, "failed to check SQ offset = %u\n",
				  attr->sq_offset);
			return -EINVAL;
		}
		hr_qp->sq.wqe_offset = hr_qp->sq.offset + attr->sq_offset;
	}

	if (hr_qp->sge.sge_cnt > 0) {
		if (attr->sge_offset >= hr_qp->rq.offset) {
			ibdev_err(ibdev, "failed to check exSGE offset = %u\n",
				  attr->sge_offset);
			return -EINVAL;
		}
		hr_qp->sge.wqe_offset = hr_qp->sge.offset + attr->sge_offset;
	}

	if (hr_qp->rq.wqe_cnt > 0) {
		if (attr->rq_offset >= hr_qp->buff_size) {
			ibdev_err(ibdev, "failed to check RQ offset = %u\n",
				  attr->rq_offset);
			return -EINVAL;
		}
		hr_qp->rq.wqe_offset = hr_qp->rq.offset + attr->rq_offset;
	}

	return 0;
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

	alloc_pages = hr_qp->dca_cfg.npages;
	ret = sync_dca_buf_offset(hr_dev, hr_qp, attr);
	if (ret) {
		ibdev_err(ibdev, "failed to sync DCA offset, ret = %d\n", ret);
		goto active_fail;
	}

	ret = setup_dca_buf_to_hw(hr_dev, hr_qp, ctx, buf_id, alloc_pages);
	if (ret) {
		ibdev_err(ibdev, "failed to setup DCA buf, ret = %d.\n", ret);
		goto active_fail;
	}

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

#define DCAN_TO_SYNC_BIT(n) ((n) * HNS_DCA_BITS_PER_STATUS)
#define DCAN_TO_STAT_BIT(n) DCAN_TO_SYNC_BIT(n)
static bool start_free_dca_buf(struct hns_roce_dca_ctx *ctx, u32 dcan)
{
	unsigned long *st = ctx->sync_status;

	if (st && dcan < ctx->max_qps)
		return !test_and_set_bit_lock(DCAN_TO_SYNC_BIT(dcan), st);

	return true;
}

static void stop_free_dca_buf(struct hns_roce_dca_ctx *ctx, u32 dcan)
{
	unsigned long *st = ctx->sync_status;

	if (st && dcan < ctx->max_qps)
		clear_bit_unlock(DCAN_TO_SYNC_BIT(dcan), st);
}

static void update_dca_buf_status(struct hns_roce_dca_ctx *ctx, u32 dcan,
				  bool en)
{
	unsigned long *st = ctx->buf_status;

	if (st && dcan < ctx->max_qps) {
		if (en)
			set_bit(DCAN_TO_STAT_BIT(dcan), st);
		else
			clear_bit(DCAN_TO_STAT_BIT(dcan), st);

		/* sync status with user-space rdma */
		smp_mb__after_atomic();
	}
}

static void restart_aging_dca_mem(struct hns_roce_dev *hr_dev,
				  struct hns_roce_dca_ctx *ctx)
{
	spin_lock(&ctx->aging_lock);
	ctx->exit_aging = false;
	if (!list_empty(&ctx->aging_new_list))
		queue_delayed_work(hr_dev->irq_workq, &ctx->aging_dwork,
				   msecs_to_jiffies(DCA_MEM_AGEING_MSES));

	spin_unlock(&ctx->aging_lock);
}

static void stop_aging_dca_mem(struct hns_roce_dca_ctx *ctx,
			       struct hns_roce_dca_cfg *cfg, bool stop_worker)
{
	spin_lock(&ctx->aging_lock);
	if (stop_worker) {
		ctx->exit_aging = true;
		cancel_delayed_work(&ctx->aging_dwork);
	}

	spin_lock(&cfg->lock);

	if (!list_empty(&cfg->aging_node))
		list_del_init(&cfg->aging_node);

	spin_unlock(&cfg->lock);
	spin_unlock(&ctx->aging_lock);
}

static int attach_dca_mem(struct hns_roce_dev *hr_dev,
			  struct hns_roce_qp *hr_qp,
			  struct hns_dca_attach_attr *attr,
			  struct hns_dca_attach_resp *resp)
{
	struct hns_roce_dca_ctx *ctx = hr_qp_to_dca_ctx(hr_dev, hr_qp);
	struct hns_roce_dca_cfg *cfg = &hr_qp->dca_cfg;
	u32 buf_id;
	int ret;

	if (hr_qp->en_flags & HNS_ROCE_QP_CAP_DYNAMIC_CTX_DETACH)
		stop_aging_dca_mem(ctx, cfg, false);
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

	resp->alloc_flags |= HNS_DCA_ATTACH_FLAGS_NEW_BUFFER;
	resp->alloc_pages = cfg->npages;
	update_dca_buf_status(ctx, cfg->dcan, true);

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
		if (dca_page_is_free(&mem->states[i]))
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

	update_dca_buf_status(ctx, cfg->dcan, false);
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

void hns_roce_dca_detach(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp,
			 struct hns_dca_detach_attr *attr)
{
	struct hns_roce_dca_ctx *ctx = hr_qp_to_dca_ctx(hr_dev, hr_qp);
	struct hns_roce_dca_cfg *cfg = &hr_qp->dca_cfg;

	stop_aging_dca_mem(ctx, cfg, true);

	spin_lock(&ctx->aging_lock);
	spin_lock(&cfg->lock);
	cfg->sq_idx = attr->sq_idx;
	list_add_tail(&cfg->aging_node, &ctx->aging_new_list);
	spin_unlock(&cfg->lock);
	spin_unlock(&ctx->aging_lock);

	restart_aging_dca_mem(hr_dev, ctx);
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

	/* No any page be used */
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

struct hns_dca_shrink_resp {
	u64 free_key;
	u32 free_mems;
};

static void shrink_dca_mem(struct hns_roce_dev *hr_dev,
			  struct hns_roce_ucontext *uctx, u64 reserved_size,
			  struct hns_dca_shrink_resp *resp)
{
	struct hns_roce_dca_ctx *ctx = to_hr_dca_ctx(hr_dev, uctx);
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

static void process_aging_dca_mem(struct hns_roce_dev *hr_dev,
				  struct hns_roce_dca_ctx *ctx)
{
	struct hns_roce_dca_cfg *cfg, *tmp_cfg;
	struct hns_roce_qp *hr_qp;

	spin_lock(&ctx->aging_lock);
	list_for_each_entry_safe(cfg, tmp_cfg, &ctx->aging_new_list, aging_node)
		list_move(&cfg->aging_node, &ctx->aging_proc_list);

	while (!ctx->exit_aging && !list_empty(&ctx->aging_proc_list)) {
		cfg = list_first_entry(&ctx->aging_proc_list,
				       struct hns_roce_dca_cfg, aging_node);
		list_del_init_careful(&cfg->aging_node);
		hr_qp = container_of(cfg, struct hns_roce_qp, dca_cfg);
		spin_unlock(&ctx->aging_lock);

		if (start_free_dca_buf(ctx, cfg->dcan)) {
			if (hr_dev->hw->chk_dca_buf_inactive(hr_dev, hr_qp))
				free_buf_from_dca_mem(ctx, cfg);

			stop_free_dca_buf(ctx, cfg->dcan);
		}

		spin_lock(&ctx->aging_lock);

		spin_lock(&cfg->lock);

		if (cfg->buf_id != HNS_DCA_INVALID_BUF_ID)
			list_move(&cfg->aging_node, &ctx->aging_new_list);

		spin_unlock(&cfg->lock);
	}
	spin_unlock(&ctx->aging_lock);
}

static void udca_mem_aging_work(struct work_struct *work)
{
	struct hns_roce_dca_ctx *ctx = container_of(work,
			struct hns_roce_dca_ctx, aging_dwork.work);
	struct hns_roce_ucontext *uctx = container_of(ctx,
					 struct hns_roce_ucontext, dca_ctx);
	struct hns_roce_dev *hr_dev = to_hr_dev(uctx->ibucontext.device);

	cancel_delayed_work(&ctx->aging_dwork);
	process_aging_dca_mem(hr_dev, ctx);
	if (!ctx->exit_aging)
		restart_aging_dca_mem(hr_dev, ctx);
}

static void remove_unused_dca_mem(struct hns_roce_dev *hr_dev);

static void kdca_mem_aging_work(struct work_struct *work)
{
	struct hns_roce_dca_ctx *ctx = container_of(work,
			struct hns_roce_dca_ctx, aging_dwork.work);
	struct hns_roce_dev *hr_dev = container_of(ctx, struct hns_roce_dev,
						   dca_ctx);

	cancel_delayed_work(&ctx->aging_dwork);
	process_aging_dca_mem(hr_dev, ctx);
	remove_unused_dca_mem(hr_dev);
	if (!ctx->exit_aging)
		restart_aging_dca_mem(hr_dev, ctx);
}

static void init_dca_context(struct hns_roce_dca_ctx *ctx, bool is_user)
{
	INIT_LIST_HEAD(&ctx->pool);
	spin_lock_init(&ctx->pool_lock);
	ctx->total_size = 0;

	ida_init(&ctx->ida);
	INIT_LIST_HEAD(&ctx->aging_new_list);
	INIT_LIST_HEAD(&ctx->aging_proc_list);
	spin_lock_init(&ctx->aging_lock);
	ctx->exit_aging = false;
	if (is_user)
		INIT_DELAYED_WORK(&ctx->aging_dwork, udca_mem_aging_work);
	else
		INIT_DELAYED_WORK(&ctx->aging_dwork, kdca_mem_aging_work);
}

static void cleanup_dca_context(struct hns_roce_dev *hr_dev,
				struct hns_roce_dca_ctx *ctx)
{
	struct dca_mem *mem, *tmp;
	unsigned long flags;
	bool is_user;

	cancel_delayed_work_sync(&ctx->aging_dwork);

	is_user = (ctx != &hr_dev->dca_ctx);
	spin_lock_irqsave(&ctx->pool_lock, flags);
	list_for_each_entry_safe(mem, tmp, &ctx->pool, list) {
		list_del(&mem->list);
		spin_lock(&mem->lock);
		mem->flags = 0;
		spin_unlock(&mem->lock);
		spin_unlock_irqrestore(&ctx->pool_lock, flags);

		kfree(mem->states);
		free_dca_pages(hr_dev, is_user, mem->pages);
		kfree(mem);

		spin_lock_irqsave(&ctx->pool_lock, flags);
	}
	ctx->total_size = 0;
	spin_unlock_irqrestore(&ctx->pool_lock, flags);
}

#define DCA_MAX_MEM_SIZE	~0UL

static uint dca_unit_size;
static ulong dca_min_size = DCA_MAX_MEM_SIZE;
static ulong dca_max_size = DCA_MAX_MEM_SIZE;

static void load_kdca_param(struct hns_roce_dca_ctx *ctx)
{
	unsigned int unit_size;

	unit_size = ALIGN(dca_unit_size, PAGE_SIZE);
	ctx->unit_size = unit_size;
	if (!unit_size)
		return;

	if (dca_max_size == DCA_MAX_MEM_SIZE || dca_max_size == 0)
		ctx->max_size = DCA_MAX_MEM_SIZE;
	else
		ctx->max_size = roundup(dca_max_size, unit_size);

	if (dca_min_size == DCA_MAX_MEM_SIZE)
		ctx->min_size = ctx->max_size;
	else
		ctx->min_size = roundup(dca_min_size, unit_size);
}

void hns_roce_init_dca(struct hns_roce_dev *hr_dev)
{
	load_kdca_param(&hr_dev->dca_ctx);
	init_dca_context(&hr_dev->dca_ctx, false);
}

void hns_roce_cleanup_dca(struct hns_roce_dev *hr_dev)
{
	cleanup_dca_context(hr_dev, &hr_dev->dca_ctx);
}

static void init_udca_status(struct hns_roce_ucontext *uctx, int udca_max_qps,
			     unsigned int dev_max_qps)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(uctx->ibucontext.device);
	const unsigned int bits_per_qp = 2 * HNS_DCA_BITS_PER_STATUS;
	struct hns_roce_dca_ctx *ctx = to_hr_dca_ctx(hr_dev, uctx);
	struct ib_ucontext *ib_uctx = &uctx->ibucontext;
	void *kaddr;
	size_t size;

	size = BITS_TO_BYTES(udca_max_qps * bits_per_qp);
	ctx->status_npage = DIV_ROUND_UP(size, PAGE_SIZE);

	size = ctx->status_npage * PAGE_SIZE;
	ctx->max_qps = min_t(unsigned int, dev_max_qps,
			     size * BITS_PER_BYTE / bits_per_qp);

	kaddr = alloc_pages_exact(size, GFP_KERNEL | __GFP_ZERO);
	if (!kaddr)
		return;

	ctx->dca_mmap_entry = hns_roce_user_mmap_entry_insert(ib_uctx,
				(u64)kaddr, size, HNS_ROCE_MMAP_TYPE_DCA);
	if (!ctx->dca_mmap_entry) {
		free_pages_exact(kaddr, size);
		return;
	}

	ctx->buf_status = (unsigned long *)kaddr;
	ctx->sync_status = (unsigned long *)(kaddr + size / 2);
}

void hns_roce_register_udca(struct hns_roce_dev *hr_dev, int max_qps,
			    struct hns_roce_ucontext *uctx)
{
	struct hns_roce_dca_ctx *ctx = to_hr_dca_ctx(hr_dev, uctx);

	if (!(uctx->config & HNS_ROCE_UCTX_CONFIG_DCA))
		return;

	init_dca_context(ctx, true);
	if (max_qps > 0)
		init_udca_status(uctx, max_qps, hr_dev->caps.num_qps);
}

void hns_roce_unregister_udca(struct hns_roce_dev *hr_dev,
			      struct hns_roce_ucontext *uctx)
{
	struct hns_roce_dca_ctx *ctx = to_hr_dca_ctx(hr_dev, uctx);

	if (!(uctx->config & HNS_ROCE_UCTX_CONFIG_DCA))
		return;

	cleanup_dca_context(hr_dev, ctx);

	if (ctx->buf_status) {
		free_pages_exact(ctx->buf_status,
				 ctx->status_npage * PAGE_SIZE);
		ctx->buf_status = NULL;
	}

	ida_destroy(&ctx->ida);
}

static struct dca_mem *key_to_dca_mem(struct list_head *head, u64 key)
{
	struct dca_mem *mem;

	list_for_each_entry(mem, head, list)
		if (mem->key == key)
			return mem;

	return NULL;
}

static bool add_dca_mem_enabled(struct hns_roce_dca_ctx *ctx, u32 alloc_size)
{
	unsigned long flags;
	bool enable;

	spin_lock_irqsave(&ctx->pool_lock, flags);

	/* Pool size no limit */
	if (ctx->max_size == DCA_MAX_MEM_SIZE)
		enable = true;
	else /* Pool size not exceed max size */
		enable = (ctx->total_size + alloc_size) < ctx->max_size;

	spin_unlock_irqrestore(&ctx->pool_lock, flags);

	return enable;
}

static bool shrink_dca_mem_enabled(struct hns_roce_dca_ctx *ctx)
{
	unsigned long flags;
	bool enable;

	spin_lock_irqsave(&ctx->pool_lock, flags);
	enable = ctx->total_size > 0 && ctx->min_size < ctx->max_size;
	spin_unlock_irqrestore(&ctx->pool_lock, flags);

	return enable;
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

	mem = kzalloc(sizeof(*mem), GFP_ATOMIC);
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
	/* When iterate all DCA mems in travel_dca_pages(), we will NOT hold the
	 * pool's lock and just set the DCA mem as free state during the DCA is
	 * working until cleanup the DCA context in hns_roce_cleanup_dca().
	 */
	spin_lock(&mem->lock);
	mem->flags = 0;
	spin_unlock(&mem->lock);
}

static int add_dca_mem(struct hns_roce_dev *hr_dev, u32 new_size)
{
	struct hns_roce_dca_ctx *ctx = to_hr_dca_ctx(hr_dev, NULL);
	struct dca_mem_attr attr = {};
	struct dca_mem *mem = NULL;
	int ret;

	if (!add_dca_mem_enabled(ctx, new_size))
		return -ENOMEM;

	/* Add new DCA mem */
	mem = alloc_dca_mem(ctx);
	if (!mem)
		return -ENOMEM;

	attr.key = (u64)mem;
	attr.size = roundup(new_size, ctx->unit_size);
	ret = register_dca_mem(hr_dev, NULL, mem, &attr);
	if (ret) {
		free_dca_mem(mem);
		ibdev_err(&hr_dev->ib_dev,
			  "failed to register DCA mem, ret = %d.\n", ret);
	}

	return ret;
}

struct dca_page_get_active_buf_attr {
	u32 buf_id;
	void **buf_list;
	u32 total;
	u32 max;
};

static int get_active_kbuf_proc(struct dca_mem *mem, int index, void *param)
{
	struct dca_page_get_active_buf_attr *attr = param;
	struct hns_dca_page_state *states = mem->states;
	struct hns_roce_buf *kmem = mem->pages;
	void *buf;
	u32 i;

	for (i = 0; i < kmem->npages; i++) {
		if (!dca_page_is_active(&states[i], attr->buf_id))
			continue;

		buf = hns_roce_buf_offset(kmem, i << HNS_HW_PAGE_SHIFT);
		attr->buf_list[attr->total++] = buf;
		if (attr->total >= attr->max)
			return DCA_MEM_STOP_ITERATE;
	}

	return DCA_MEM_NEXT_ITERATE;
}

static int setup_dca_buf_list(struct hns_roce_dca_ctx *ctx,
			      struct hns_roce_dca_cfg *cfg)
{
	struct dca_page_get_active_buf_attr attr = {};

	attr.buf_id = cfg->buf_id;
	attr.buf_list = cfg->buf_list;
	attr.max = cfg->npages;
	travel_dca_pages(ctx, &attr, get_active_kbuf_proc);

	return attr.total == attr.max ? 0 : -ENOMEM;
}

#define DCA_EXPAND_MEM_TRY_TIMES	3
int hns_roce_dca_attach(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp,
			struct hns_dca_attach_attr *attr)
{
	struct hns_roce_dca_cfg *cfg = &hr_qp->dca_cfg;
	struct hns_dca_attach_resp resp = {};
	bool is_new_buf = true;
	int try_times = 0;
	int ret;

	do {
		resp.alloc_flags = 0;
		ret = attach_dca_mem(hr_dev, hr_qp, attr, &resp);
		if (ret)
			break;

		if (resp.alloc_pages >= cfg->npages) {
			is_new_buf = !!(resp.alloc_flags &
					HNS_DCA_ATTACH_FLAGS_NEW_BUFFER);
			break;
		}

		ret = add_dca_mem(hr_dev, hr_qp->buff_size);
		if (ret)
			break;
	} while (try_times++ < DCA_EXPAND_MEM_TRY_TIMES);

	if (ret || resp.alloc_pages < cfg->npages) {
		ibdev_err(&hr_dev->ib_dev,
			  "failed to attach buf %u != %u, try %d, ret = %d.\n",
			   cfg->npages, resp.alloc_pages, try_times, ret);
		return -ENOMEM;
	}

	/* DCA config not changed */
	if (!is_new_buf && cfg->buf_list[0])
		return 0;

	return setup_dca_buf_list(hr_qp_to_dca_ctx(hr_dev, hr_qp), cfg);
}

static void remove_unused_dca_mem(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_dca_ctx *ctx = to_hr_dca_ctx(hr_dev, NULL);
	struct hns_dca_shrink_resp resp = {};
	struct dca_mem *mem;
	unsigned long flags;

	while (shrink_dca_mem_enabled(ctx)) {
		resp.free_mems = 0;
		shrink_dca_mem(hr_dev, NULL, ctx->min_size, &resp);
		if (resp.free_mems < 1)
			break;
		spin_lock_irqsave(&ctx->pool_lock, flags);
		mem = key_to_dca_mem(&ctx->pool, resp.free_key);
		spin_unlock_irqrestore(&ctx->pool_lock, flags);
		if (!mem)
			break;

		unregister_dca_mem(hr_dev, NULL, mem);
		free_dca_mem(mem);
		/* No more free memory */
		if (resp.free_mems <= 1)
			break;
	}
}

static void kick_dca_buf(struct hns_roce_dev *hr_dev,
			 struct hns_roce_dca_cfg *cfg,
			 struct hns_roce_dca_ctx *ctx)
{
	stop_aging_dca_mem(ctx, cfg, true);
	free_buf_from_dca_mem(ctx, cfg);
	restart_aging_dca_mem(hr_dev, ctx);

	/* Shrink kenrel DCA mem */
	if (ctx == &hr_dev->dca_ctx)
		remove_unused_dca_mem(hr_dev);
}

static u32 alloc_dca_num(struct hns_roce_dca_ctx *ctx)
{
	int ret;

	ret = ida_alloc_max(&ctx->ida, ctx->max_qps - 1, GFP_KERNEL);
	if (ret < 0)
		return HNS_DCA_INVALID_DCA_NUM;

	stop_free_dca_buf(ctx, ret);
	update_dca_buf_status(ctx, ret, false);
	return ret;
}

static void free_dca_num(u32 dcan, struct hns_roce_dca_ctx *ctx)
{
	if (dcan == HNS_DCA_INVALID_DCA_NUM)
		return;

	ida_free(&ctx->ida, dcan);
}

static int setup_kdca(struct hns_roce_dca_cfg *cfg)
{
	if (!cfg->npages)
		return -EINVAL;

	cfg->buf_list = kcalloc(cfg->npages, sizeof(void *), GFP_KERNEL);
	if (!cfg->buf_list)
		return -ENOMEM;

	return 0;
}

static void teardown_kdca(struct hns_roce_dca_cfg *cfg)
{
	kfree(cfg->buf_list);
	cfg->buf_list = NULL;
}

int hns_roce_enable_dca(struct hns_roce_qp *hr_qp, struct ib_udata *udata)
{
	struct hns_roce_dca_cfg *cfg = &hr_qp->dca_cfg;

	spin_lock_init(&cfg->lock);
	INIT_LIST_HEAD(&cfg->aging_node);
	cfg->buf_id = HNS_DCA_INVALID_BUF_ID;
	cfg->npages = hr_qp->buff_size >> HNS_HW_PAGE_SHIFT;
	cfg->dcan = HNS_DCA_INVALID_DCA_NUM;
	/* Cannot support dynamic detach when rq is not empty */
	if (!hr_qp->rq.wqe_cnt)
		hr_qp->en_flags |= HNS_ROCE_QP_CAP_DYNAMIC_CTX_DETACH;

	if (!udata)
		return setup_kdca(cfg);

	return 0;
}

void hns_roce_disable_dca(struct hns_roce_dev *hr_dev,
			  struct hns_roce_qp *hr_qp, struct ib_udata *udata)
{
	struct hns_roce_ucontext *uctx = rdma_udata_to_drv_context(udata,
					 struct hns_roce_ucontext, ibucontext);
	struct hns_roce_dca_ctx *ctx = to_hr_dca_ctx(hr_dev, uctx);
	struct hns_roce_dca_cfg *cfg = &hr_qp->dca_cfg;

	kick_dca_buf(hr_dev, cfg, ctx);
	free_dca_num(cfg->dcan, ctx);
	cfg->dcan = HNS_DCA_INVALID_DCA_NUM;

	if (!udata)
		teardown_kdca(&hr_qp->dca_cfg);
}

void hns_roce_modify_dca(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp,
			 struct ib_udata *udata)
{
	struct hns_roce_ucontext *uctx = rdma_udata_to_drv_context(udata,
					 struct hns_roce_ucontext, ibucontext);
	struct hns_roce_dca_ctx *ctx = to_hr_dca_ctx(hr_dev, uctx);
	struct hns_roce_dca_cfg *cfg = &hr_qp->dca_cfg;

	if (hr_qp->state == IB_QPS_RESET || hr_qp->state == IB_QPS_ERR) {
		kick_dca_buf(hr_dev, cfg, ctx);
		free_dca_num(cfg->dcan, ctx);
		cfg->dcan = HNS_DCA_INVALID_DCA_NUM;
	} else if (hr_qp->state == IB_QPS_RTR) {
		free_dca_num(cfg->dcan, ctx);
		cfg->dcan = alloc_dca_num(ctx);
	}
}

static inline struct hns_roce_ucontext *
uverbs_attr_to_hr_uctx(struct uverbs_attr_bundle *attrs)
{
	return rdma_udata_to_drv_context(&attrs->driver_udata,
					 struct hns_roce_ucontext, ibucontext);
}

#if IS_ENABLED(CONFIG_INFINIBAND_USER_ACCESS)
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

	mem = alloc_dca_mem(to_hr_dca_ctx(hr_dev, uctx));
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
	unregister_dca_mem(to_hr_dev(uctx->ibucontext.device), uctx, mem);
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
uverbs_attr_to_hr_qp(struct uverbs_attr_bundle *attrs, u16 idx)
{
	struct ib_uobject *uobj = uverbs_attr_get_uobject(attrs, idx);

	if (IS_ERR(uobj))
		return ERR_CAST(uobj);

	return to_hr_qp(uobj->object);
}

static int UVERBS_HANDLER(HNS_IB_METHOD_DCA_MEM_ATTACH)(
	struct uverbs_attr_bundle *attrs)
{
	struct hns_roce_qp *hr_qp = uverbs_attr_to_hr_qp(attrs,
					HNS_IB_ATTR_DCA_MEM_ATTACH_HANDLE);
	struct hns_dca_attach_attr attr = {};
	struct hns_dca_attach_resp resp = {};
	int ret;

	if (IS_ERR(hr_qp))
		return PTR_ERR(hr_qp);

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
	struct hns_roce_qp *hr_qp = uverbs_attr_to_hr_qp(attrs,
					HNS_IB_ATTR_DCA_MEM_DETACH_HANDLE);
	struct hns_dca_detach_attr attr = {};
	int ret;

	if (IS_ERR(hr_qp))
		return PTR_ERR(hr_qp);

	ret = uverbs_copy_from(&attr.sq_idx, attrs,
			       HNS_IB_ATTR_DCA_MEM_DETACH_SQ_INDEX);
	if (ret)
		return ret;

	hns_roce_dca_detach(to_hr_dev(hr_qp->ibqp.device), hr_qp, &attr);

	return 0;
}

DECLARE_UVERBS_NAMED_METHOD(
	HNS_IB_METHOD_DCA_MEM_DETACH,
	UVERBS_ATTR_IDR(HNS_IB_ATTR_DCA_MEM_DETACH_HANDLE, UVERBS_OBJECT_QP,
			UVERBS_ACCESS_WRITE, UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(HNS_IB_ATTR_DCA_MEM_DETACH_SQ_INDEX,
			   UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

static int query_dca_active_pages_proc(struct dca_mem *mem, int index,
				       void *param)
{
	struct hns_dca_page_state *state = &mem->states[index];
	struct dca_page_query_active_attr *attr = param;

	if (!dca_page_is_active(state, attr->buf_id))
		return 0;

	if (attr->curr_index < attr->start_index) {
		attr->curr_index++;
		return 0;
	} else if (attr->curr_index > attr->start_index) {
		return DCA_MEM_STOP_ITERATE;
	}

	/* Search first page in DCA mem */
	attr->page_index = index;
	attr->mem_key = mem->key;
	/* Search active pages in continuous addresses */
	while (index < mem->page_count) {
		state = &mem->states[index];
		if (!dca_page_is_active(state, attr->buf_id))
			break;

		index++;
		attr->page_count++;
	}

	return DCA_MEM_STOP_ITERATE;
}

static int UVERBS_HANDLER(HNS_IB_METHOD_DCA_MEM_QUERY)(
	struct uverbs_attr_bundle *attrs)
{
	struct hns_roce_qp *hr_qp = uverbs_attr_to_hr_qp(attrs,
					HNS_IB_ATTR_DCA_MEM_QUERY_HANDLE);
	struct dca_page_query_active_attr active_attr = {};
	struct hns_roce_dca_ctx *ctx = NULL;
	struct hns_roce_dev *hr_dev = NULL;
	u32 page_idx, page_ofs;
	int ret;

	if (IS_ERR(hr_qp))
		return PTR_ERR(hr_qp);

	hr_dev = to_hr_dev(hr_qp->ibqp.device);
	ctx = hr_qp_to_dca_ctx(hr_dev, hr_qp);
	if (!ctx)
		return -ENOENT;

	ret = uverbs_copy_from(&page_idx, attrs,
			       HNS_IB_ATTR_DCA_MEM_QUERY_PAGE_INDEX);
	if (ret)
		return ret;

	active_attr.buf_id = hr_qp->dca_cfg.buf_id;
	active_attr.start_index = page_idx;
	travel_dca_pages(ctx, &active_attr, query_dca_active_pages_proc);
	page_ofs = active_attr.page_index << HNS_HW_PAGE_SHIFT;

	if (!active_attr.page_count)
		return -ENOMEM;

	ret = uverbs_copy_to(attrs, HNS_IB_ATTR_DCA_MEM_QUERY_OUT_KEY,
			     &active_attr.mem_key, sizeof(active_attr.mem_key));
	if (!ret)
		ret = uverbs_copy_to(attrs,
				     HNS_IB_ATTR_DCA_MEM_QUERY_OUT_OFFSET,
				     &page_ofs, sizeof(page_ofs));
	if (!ret)
		ret = uverbs_copy_to(attrs,
				     HNS_IB_ATTR_DCA_MEM_QUERY_OUT_PAGE_COUNT,
				     &active_attr.page_count,
				     sizeof(active_attr.page_count));

	return ret;
}

DECLARE_UVERBS_NAMED_METHOD(
	HNS_IB_METHOD_DCA_MEM_QUERY,
	UVERBS_ATTR_IDR(HNS_IB_ATTR_DCA_MEM_QUERY_HANDLE, UVERBS_OBJECT_QP,
			UVERBS_ACCESS_READ, UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(HNS_IB_ATTR_DCA_MEM_QUERY_PAGE_INDEX,
			   UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HNS_IB_ATTR_DCA_MEM_QUERY_OUT_KEY,
			    UVERBS_ATTR_TYPE(u64), UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HNS_IB_ATTR_DCA_MEM_QUERY_OUT_OFFSET,
			    UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HNS_IB_ATTR_DCA_MEM_QUERY_OUT_PAGE_COUNT,
			    UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_OBJECT(HNS_IB_OBJECT_DCA_MEM,
			    UVERBS_TYPE_ALLOC_IDR(dca_cleanup),
			    &UVERBS_METHOD(HNS_IB_METHOD_DCA_MEM_REG),
			    &UVERBS_METHOD(HNS_IB_METHOD_DCA_MEM_DEREG),
			    &UVERBS_METHOD(HNS_IB_METHOD_DCA_MEM_SHRINK),
			    &UVERBS_METHOD(HNS_IB_METHOD_DCA_MEM_ATTACH),
			    &UVERBS_METHOD(HNS_IB_METHOD_DCA_MEM_DETACH),
			    &UVERBS_METHOD(HNS_IB_METHOD_DCA_MEM_QUERY));

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

#else

const struct uapi_definition hns_roce_dca_uapi_defs[] = {
};

#endif

/* enum DCA pool */
struct dca_mem_enum_attr {
	void *param;
	hns_dca_enum_callback enum_fn;
};

static int enum_dca_pool_proc(struct dca_mem *mem, int index, void *param)
{
	struct dca_mem_enum_attr *attr = param;
	int ret;

	ret = attr->enum_fn(mem->states, mem->page_count, attr->param);

	return ret ? DCA_MEM_STOP_ITERATE : DCA_MEM_NEXT_ITERATE;
}

void hns_roce_enum_dca_pool(struct hns_roce_dca_ctx *dca_ctx, void *param,
			    hns_dca_enum_callback cb)
{
	struct dca_mem_enum_attr attr;

	attr.enum_fn = cb;
	attr.param = param;
	travel_dca_pages(dca_ctx, &attr, enum_dca_pool_proc);
}

module_param(dca_unit_size, uint, 0444);
module_param(dca_max_size, ulong, 0444);
module_param(dca_min_size, ulong, 0444);
