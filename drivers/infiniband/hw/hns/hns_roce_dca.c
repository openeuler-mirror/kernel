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

DECLARE_UVERBS_NAMED_OBJECT(HNS_IB_OBJECT_DCA_MEM,
			    UVERBS_TYPE_ALLOC_IDR(dca_cleanup),
			    &UVERBS_METHOD(HNS_IB_METHOD_DCA_MEM_REG),
			    &UVERBS_METHOD(HNS_IB_METHOD_DCA_MEM_DEREG));

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
