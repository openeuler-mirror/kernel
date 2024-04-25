// SPDX-License-Identifier: GPL-2.0
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

#include <linux/slab.h>
#include "urma/ubcore_api.h"
#include "hns3_udma_cmd.h"
#include "hns3_udma_debugfs.h"
#include "hns3_udma_dca.h"

static void travel_dca_pages(struct udma_dca_ctx *ctx, void *param,
			     int (*cb)(struct dca_mem *, uint32_t, void *))
{
	struct dca_mem *mem;
	unsigned long flags;
	uint32_t i;
	bool avail;
	int ret;

	spin_lock_irqsave(&ctx->pool_lock, flags);
	list_for_each_entry(mem, &ctx->pool, list) {
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

void udma_enable_dca(struct udma_dev *dev, struct udma_qp *qp)
{
	struct udma_dca_cfg *cfg = &qp->dca_cfg;

	spin_lock_init(&cfg->lock);
	INIT_LIST_HEAD(&cfg->aging_node);
	cfg->buf_id = UDMA_DCA_INVALID_BUF_ID;
	cfg->npages = qp->buff_size >> UDMA_HW_PAGE_SHIFT;
	cfg->dcan = HNS3_UDMA_DCA_INVALID_DCA_NUM;
}

static void stop_aging_dca_mem(struct udma_dca_ctx *ctx,
			       struct udma_dca_cfg *cfg, bool stop_worker)
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

static void update_dca_buf_status(struct udma_dca_ctx *ctx, uint32_t dcan,
				  bool en)
{
	uintptr_t *st = ctx->buf_status;

	if (st && dcan < ctx->max_qps) {
		if (en)
			set_bit(DCAN_TO_STAT_BIT(dcan), st);
		else
			clear_bit(DCAN_TO_STAT_BIT(dcan), st);
		/* barrier */
		smp_mb__after_atomic();
	}
}

static int free_buffer_pages_proc(struct dca_mem *mem, uint32_t index,
				  void *param)
{
	struct dca_page_free_buf_attr *attr = param;
	struct dca_page_state *state;
	uint32_t free_pages = 0;
	bool changed = false;
	bool stop = false;
	uint32_t i = 0;

	for (; !stop && i < mem->page_count; i++) {
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

	for (; changed && i < mem->page_count; i++) {
		state = &mem->states[i];
		if (dca_page_is_free(state))
			free_pages++;
	}

	if (changed && free_pages == mem->page_count)
		attr->clean_mems++;

	return stop ? DCA_MEM_STOP_ITERATE : DCA_MEM_NEXT_ITERATE;
}

static void free_buf_from_dca_mem(struct udma_dca_ctx *ctx,
				  struct udma_dca_cfg *cfg)
{
	struct dca_page_free_buf_attr attr = {};
	unsigned long flags;
	uint32_t buf_id;

	update_dca_buf_status(ctx, cfg->dcan, false);
	spin_lock(&cfg->lock);
	buf_id = cfg->buf_id;
	cfg->buf_id = UDMA_DCA_INVALID_BUF_ID;
	spin_unlock(&cfg->lock);
	if (buf_id == UDMA_DCA_INVALID_BUF_ID)
		return;

	attr.buf_id = buf_id;
	attr.max_pages = cfg->npages;
	travel_dca_pages(ctx, &attr, free_buffer_pages_proc);

	/* Update free size */
	spin_lock_irqsave(&ctx->pool_lock, flags);
	ctx->free_mems += attr.clean_mems;
	ctx->free_size += attr.free_pages << UDMA_HW_PAGE_SHIFT;
	spin_unlock_irqrestore(&ctx->pool_lock, flags);
}

static void restart_aging_dca_mem(struct udma_dev *dev,
				  struct udma_dca_ctx *ctx)
{
	spin_lock(&ctx->aging_lock);
	ctx->exit_aging = false;
	if (!list_empty(&ctx->aging_new_list))
		queue_delayed_work(dev->irq_workq, &ctx->aging_dwork,
				   msecs_to_jiffies(DCA_MEM_AGEING_MSES));

	spin_unlock(&ctx->aging_lock);
}

static void kick_dca_buf(struct udma_dev *dev, struct udma_dca_cfg *cfg,
			 struct udma_dca_ctx *ctx)
{
	stop_aging_dca_mem(ctx, cfg, true);
	free_buf_from_dca_mem(ctx, cfg);
	restart_aging_dca_mem(dev, ctx);
}

static void free_dca_num(struct udma_dca_cfg *cfg, struct udma_dca_ctx *ctx)
{
	if (cfg->dcan == HNS3_UDMA_DCA_INVALID_DCA_NUM)
		return;

	ida_free(&ctx->ida, cfg->dcan);
	cfg->dcan = HNS3_UDMA_DCA_INVALID_DCA_NUM;
}

void udma_disable_dca(struct udma_dev *dev, struct udma_qp *qp)
{
	struct udma_dca_cfg *cfg = &qp->dca_cfg;
	struct udma_dca_ctx *ctx = qp->dca_ctx;

	kick_dca_buf(dev, cfg, ctx);
	free_dca_num(cfg, ctx);
}

static struct dca_mem *alloc_dca_mem(struct udma_dev *dev,
				     struct udma_dca_ctx *ctx)
{
	struct dca_mem *mem, *found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&ctx->pool_lock, flags);
	list_for_each_entry(mem, &ctx->pool, list) {
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
	 * working until cleanup the DCA context in cleanup_dca_context().
	 */
	spin_lock(&mem->lock);
	mem->flags = 0;
	spin_unlock(&mem->lock);
}

static void *alloc_dca_pages(struct udma_dev *dev, struct dca_mem *mem,
			     struct udma_dca_reg_attr *attr)
{
	struct ubcore_device *ub_dev = &dev->ub_dev;
	union ubcore_umem_flag flag = {};
	struct ubcore_umem *umem;

	flag.bs.non_pin = 0;
	flag.bs.writable = 1;
	umem = ubcore_umem_get(ub_dev, attr->addr, attr->size, flag);
	if (IS_ERR_OR_NULL(umem)) {
		dev_err(dev->dev, "failed to get uDCA pages, ret = %ld.\n",
			PTR_ERR(umem));
		return NULL;
	}

	mem->page_count = umem_cal_npages(umem->va, umem->length);

	return umem;
}

static void init_dca_umem_states(struct udma_dev *dev, struct ubcore_umem *umem,
				 struct dca_page_state *states, uint32_t count)
{
	uint32_t npage_per_sg, k, i, total = 0;
	dma_addr_t cur_addr, pre_addr = 0;
	struct scatterlist *sg;

	for_each_sg(umem->sg_head.sgl, sg, umem->sg_head.nents, k) {
		npage_per_sg = sg_dma_len(sg) >> UDMA_HW_PAGE_SHIFT;
		for (i = 0; i < npage_per_sg; ++i) {
			cur_addr = sg_dma_address(sg) + (i << UDMA_HW_PAGE_SHIFT);
			if (cur_addr - pre_addr != UDMA_PAGE_SIZE)
				states[total].head = 1;

			if (count <= ++total)
				return;

			pre_addr = cur_addr;
		}
	}
}

static struct dca_page_state *alloc_dca_states(struct udma_dev *dev,
					       void *pages, uint32_t count)
{
	struct dca_page_state *states;

	states = kcalloc(count, sizeof(*states), GFP_KERNEL);
	if (!states)
		return NULL;

	init_dca_umem_states(dev, pages, states, count);

	return states;
}

static void stop_free_dca_buf(struct udma_dca_ctx *ctx, uint32_t dcan)
{
	uintptr_t *st = ctx->sync_status;

	if (st && dcan < ctx->max_qps)
		clear_bit_unlock(DCAN_TO_SYNC_BIT(dcan), st);
}

static uint32_t alloc_dca_num(struct udma_dca_ctx *ctx)
{
	int ret;

	ret = ida_alloc_range(&ctx->ida, 0, ctx->max_qps - 1, GFP_KERNEL);
	if (ret < 0)
		return HNS3_UDMA_DCA_INVALID_DCA_NUM;

	stop_free_dca_buf(ctx, ret);
	update_dca_buf_status(ctx, ret, false);

	return ret;
}

void udma_modify_dca(struct udma_dev *dev, struct udma_qp *qp)
{
	struct udma_dca_cfg *cfg = &qp->dca_cfg;
	struct udma_dca_ctx *ctx = qp->dca_ctx;

	if (qp->state == QPS_RESET || qp->state == QPS_ERR) {
		kick_dca_buf(dev, cfg, ctx);
		free_dca_num(cfg, ctx);
	} else if (qp->state == QPS_RTS) {
		free_dca_num(cfg, ctx);
		cfg->dcan = alloc_dca_num(ctx);
	}
}

int udma_register_dca_mem(struct udma_dev *dev, struct udma_ucontext *context,
			  struct udma_dca_reg_attr *attr)
{
	struct udma_dca_ctx *ctx = &context->dca_ctx;
	struct dca_mem *mem;
	unsigned long flags;
	void *states;
	void *pages;

	mem = alloc_dca_mem(dev, ctx);
	if (!mem) {
		dev_err(dev->dev, "failed to alloc dca mem.\n");
		return -ENOMEM;
	}

	pages = alloc_dca_pages(dev, mem, attr);
	if (!pages) {
		dev_err(dev->dev, "failed to alloc dca pages.\n");
		goto err_alloc_dca_pages;
	}

	states = alloc_dca_states(dev, pages, mem->page_count);
	if (!states) {
		dev_err(dev->dev, "failed to alloc dca states.\n");
		goto err_alloc_dca_states;
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
err_alloc_dca_states:
	ubcore_umem_release(pages);
err_alloc_dca_pages:
	free_dca_mem(mem);

	return -ENOMEM;
}

static void unregister_dca_mem(struct udma_dev *dev, struct udma_dca_ctx *ctx,
			       struct dca_mem *mem)
{
	void *states, *pages;
	unsigned long flags;

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
	ubcore_umem_release(pages);
}

static uint32_t get_udca_max_qps(struct udma_dev *udma_dev,
				 struct hns3_udma_create_ctx_ucmd *ucmd)
{
	uint32_t qp_num = 0;

	if (ucmd->comp & UDMA_CONTEXT_MASK_DCA_PRIME_QPS) {
		qp_num = ucmd->dca_max_qps;
		if (!qp_num)
			qp_num = udma_dev->caps.num_qps;
	}

	return qp_num;
}

static bool start_free_dca_buf(struct udma_dca_ctx *ctx, uint32_t dcan)
{
	uintptr_t *st = ctx->sync_status;

	if (st && dcan < ctx->max_qps)
		return !test_and_set_bit_lock(dcan, st);

	return true;
}

static int udma_query_qpc(struct udma_dev *udma_dev, uint32_t qpn,
			  void *context)
{
	struct udma_cmd_mailbox *mailbox;
	struct udma_cmq_desc desc;
	struct udma_mbox *mb;
	int ret;

	mailbox = udma_alloc_cmd_mailbox(udma_dev);
	if (IS_ERR(mailbox)) {
		dev_err(udma_dev->dev, "alloc mailbox failed\n");
		ret = PTR_ERR(mailbox);
		goto alloc_mailbox_fail;
	}

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_POST_MB, false);
	mb = (struct udma_mbox *)desc.data;
	mbox_desc_init(mb, 0, mailbox->dma, qpn, UDMA_CMD_QUERY_QPC);

	ret = udma_cmd_mbox(udma_dev, &desc, UDMA_CMD_TIMEOUT_MSECS, 0);
	if (ret) {
		dev_err(udma_dev->dev, "QUERY id(0x%x) cmd(0x%x) error(%d).\n",
			qpn, UDMA_CMD_QUERY_QPC, ret);
		goto err_mailbox;
	}
	memcpy(context, mailbox->buf, sizeof(struct udma_qp_context));

err_mailbox:
	udma_free_cmd_mailbox(udma_dev, mailbox);
alloc_mailbox_fail:
	return ret;
}

static bool udma_chk_dca_buf_inactive(struct udma_dev *udma_dev,
				      struct udma_qp *qp)
{
	struct udma_dca_cfg *cfg = &qp->dca_cfg;
	struct udma_qp_context context = {};
	uint32_t tmp, sq_idx;
	int state;
	int ret;

	ret = udma_query_qpc(udma_dev, qp->qpn, &context);
	if (ret) {
		dev_info(udma_dev->dev, "Failed to query QPC, ret = %d.\n",
			 ret);
		return false;
	}

	state = udma_reg_read(&context, QPC_QP_ST);
	if (state == QP_ST_ERR || state == QP_ST_RST)
		return true;

	if (qp->sq.wqe_cnt > 0) {
		tmp = udma_reg_read(&context, QPC_RETRY_MSG_MSN);
		sq_idx = tmp & (qp->sq.wqe_cnt - 1);
		/* If SQ-PI equals to retry_msg_msn in QPC, the QP is
		 * inactive.
		 */
		if (sq_idx != cfg->sq_idx)
			return false;
	}

	return true;
}

static void process_aging_dca_mem(struct udma_dev *udma_dev,
				  struct udma_dca_ctx *ctx)
{
	struct udma_dca_cfg *cfg, *cfg_tmp;
	struct udma_qp *qp;

	spin_lock(&ctx->aging_lock);
	list_for_each_entry_safe(cfg, cfg_tmp, &ctx->aging_new_list, aging_node)
		list_move(&cfg->aging_node, &ctx->aging_proc_list);

	while (!ctx->exit_aging && !list_empty(&ctx->aging_proc_list)) {
		cfg = list_first_entry(&ctx->aging_proc_list,
				       struct udma_dca_cfg, aging_node);
		list_del_init_careful(&cfg->aging_node);
		qp = container_of(cfg, struct udma_qp, dca_cfg);
		spin_unlock(&ctx->aging_lock);

		if (start_free_dca_buf(ctx, cfg->dcan)) {
			if (udma_chk_dca_buf_inactive(udma_dev, qp))
				free_buf_from_dca_mem(ctx, cfg);

			stop_free_dca_buf(ctx, cfg->dcan);
		}

		spin_lock(&ctx->aging_lock);

		spin_lock(&cfg->lock);

		if (cfg->buf_id != UDMA_DCA_INVALID_BUF_ID)
			list_move(&cfg->aging_node, &ctx->aging_new_list);

		spin_unlock(&cfg->lock);
	}
	spin_unlock(&ctx->aging_lock);
}

static void udca_mem_aging_work(struct work_struct *work)
{
	struct udma_dca_ctx *ctx = container_of(work, struct udma_dca_ctx,
						aging_dwork.work);
	struct udma_ucontext *ucontext = container_of(ctx, struct udma_ucontext,
						      dca_ctx);
	struct udma_dev *udma_dev = to_udma_dev(ucontext->uctx.ub_dev);

	cancel_delayed_work(&ctx->aging_dwork);
	process_aging_dca_mem(udma_dev, ctx);
	if (!ctx->exit_aging)
		restart_aging_dca_mem(udma_dev, ctx);
}

static void init_dca_context(struct udma_dca_ctx *dca_ctx)
{
	INIT_LIST_HEAD(&dca_ctx->pool);
	spin_lock_init(&dca_ctx->pool_lock);
	dca_ctx->total_size = 0;

	ida_init(&dca_ctx->ida);
	INIT_LIST_HEAD(&dca_ctx->aging_new_list);
	INIT_LIST_HEAD(&dca_ctx->aging_proc_list);
	spin_lock_init(&dca_ctx->aging_lock);
	dca_ctx->exit_aging = false;

	INIT_DELAYED_WORK(&dca_ctx->aging_dwork, udca_mem_aging_work);
}

static void init_udca_status(struct udma_ucontext *uctx, int udca_max_qps,
			     uint32_t dev_max_qps)
{
	const uint32_t bits_per_qp = 2 * UDMA_DCA_BITS_PER_STATUS;
	struct udma_dca_ctx *dca_ctx = &uctx->dca_ctx;
	void *kaddr;
	size_t size;

	size = BITS_TO_BYTES(udca_max_qps * bits_per_qp);
	dca_ctx->status_npage = DIV_ROUND_UP(size, PAGE_SIZE);

	size = dca_ctx->status_npage * PAGE_SIZE;
	dca_ctx->max_qps = min_t(uint32_t, dev_max_qps,
				 size * BITS_PER_BYTE / bits_per_qp);

	kaddr = alloc_pages_exact(size, GFP_KERNEL | __GFP_ZERO);
	if (!kaddr)
		return;

	dca_ctx->buf_status = (uintptr_t *)kaddr;
	dca_ctx->sync_status = (uintptr_t *)(kaddr + size / DCA_BITS_HALF);
}

int udma_register_udca(struct udma_dev *udma_dev,
		       struct udma_ucontext *context, struct ubcore_udrv_priv *udrv_data)
{
	struct udma_dca_ctx *dca_ctx = &context->dca_ctx;
	struct hns3_udma_create_ctx_ucmd ucmd = {};
	int max_qps;
	int ret;

	ret = copy_from_user(&ucmd, (void *)udrv_data->in_addr,
			     min(udrv_data->in_len, (uint32_t)sizeof(ucmd)));
	if (ret) {
		dev_err(udma_dev->dev, "Failed to copy udata, ret = %d.\n",
			ret);
		return -EFAULT;
	}

	if (!(udma_dev->caps.flags & UDMA_CAP_FLAG_DCA_MODE) ||
	    ucmd.dca_unit_size == 0)
		return 0;

	dca_ctx->unit_size = ucmd.dca_unit_size;
	max_qps = get_udca_max_qps(udma_dev, &ucmd);
	init_dca_context(dca_ctx);
	if (max_qps > 0)
		init_udca_status(context, max_qps, udma_dev->caps.num_qps);

	return 0;
}

static void cleanup_dca_context(struct udma_dca_ctx *ctx)
{
	struct dca_mem *mem, *tmp;
	unsigned long flags;

	spin_lock(&ctx->aging_lock);
	cancel_delayed_work_sync(&ctx->aging_dwork);
	spin_unlock(&ctx->aging_lock);

	spin_lock_irqsave(&ctx->pool_lock, flags);
	list_for_each_entry_safe(mem, tmp, &ctx->pool, list) {
		list_del(&mem->list);
		spin_lock(&mem->lock);
		mem->flags = 0;
		spin_unlock(&mem->lock);
		spin_unlock_irqrestore(&ctx->pool_lock, flags);

		kfree(mem->states);
		ubcore_umem_release(mem->pages);
		kfree(mem);

		spin_lock_irqsave(&ctx->pool_lock, flags);
	}
	ctx->total_size = 0;
	spin_unlock_irqrestore(&ctx->pool_lock, flags);
}

void udma_unregister_udca(struct udma_dev *udma_dev,
			    struct udma_ucontext *context)
{
	struct udma_dca_ctx *dca_ctx = &context->dca_ctx;

	if (dca_ctx->unit_size == 0)
		return;
	udma_unregister_uctx_debugfs(context);

	cleanup_dca_context(dca_ctx);
	if (dca_ctx->buf_status) {
		free_pages_exact(dca_ctx->buf_status,
				 dca_ctx->status_npage * PAGE_SIZE);
		dca_ctx->buf_status = NULL;
	}

	ida_destroy(&dca_ctx->ida);
}

static int dereg_dca_page_proc(struct dca_mem *mem, uint32_t index,
			       void *param)
{
	struct udma_dca_dereg_attr *attr = param;

	if (mem->key == attr->free_key) {
		attr->mem = mem;
		return DCA_MEM_STOP_ITERATE;
	} else {
		return DCA_MEM_NEXT_ITERATE;
	}
}

int udma_unregister_dca_mem(struct udma_dev *dev,
			    struct udma_ucontext *context,
			    struct udma_dca_dereg_attr *attr, bool from_user)
{
	if (from_user) {
		travel_dca_pages(&context->dca_ctx, attr,
				 dereg_dca_page_proc);
		if (attr->mem == NULL) {
			dev_err(dev->dev, "failed to dereg DCA mems.\n");
			return -EINVAL;
		}
	}

	unregister_dca_mem(dev, &context->dca_ctx, attr->mem);
	free_dca_mem(attr->mem);

	return 0;
}

static int shrink_dca_page_proc(struct dca_mem *mem, uint32_t index,
				void *param)
{
	struct udma_dca_shrink_resp *resp = param;
	struct dca_page_state *state;
	int i, free_pages;

	free_pages = 0;
	for (i = 0; i < mem->page_count; i++) {
		state = &mem->states[i];
		if (dca_page_is_free(state))
			free_pages++;
	}

	/* No any page be used */
	if (free_pages == mem->page_count) {
		/* shrink first empty DCA mem */
		if (!resp->free_mems) {
			resp->mem = mem;
			resp->free_key = mem->key;
		}
		resp->free_mems++;
	}

	if (resp->free_mems > 1)
		return DCA_MEM_STOP_ITERATE;
	else
		return DCA_MEM_NEXT_ITERATE;
}

void udma_shrink_dca_mem(struct udma_dev *dev, struct udma_ucontext *context,
			 struct udma_dca_shrink_attr *attr,
			 struct udma_dca_shrink_resp *resp)
{
	struct udma_dca_ctx *ctx = &context->dca_ctx;
	unsigned long flags;
	bool need_shink;

	spin_lock_irqsave(&ctx->pool_lock, flags);
	need_shink = ctx->free_mems > 0 && ctx->free_size > attr->reserved_size;
	spin_unlock_irqrestore(&ctx->pool_lock, flags);
	if (!need_shink)
		return;

	travel_dca_pages(ctx, resp, shrink_dca_page_proc);
}

static int query_dca_active_pages_proc(struct dca_mem *mem, uint32_t index,
				       void *param)
{
	struct dca_page_state *state = &mem->states[index];
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

int udma_query_dca_mem(struct udma_dev *dev, struct udma_dca_query_attr *attr,
		       struct udma_dca_query_resp *resp)
{
	struct dca_page_query_active_attr a_attr = {};
	struct udma_dca_ctx *ctx;
	struct udma_dca_cfg *cfg;
	struct udma_qp *qp;

	qp = get_qp(dev, attr->qpn);
	if (qp == NULL) {
		dev_err(dev->dev, "failed to find qp, qpn = 0x%llx\n", attr->qpn);
		return -EINVAL;
	}
	cfg = &qp->dca_cfg;
	ctx = qp->dca_ctx;

	a_attr.buf_id = qp->dca_cfg.buf_id;
	a_attr.start_index = attr->page_idx;
	travel_dca_pages(ctx, &a_attr, query_dca_active_pages_proc);

	resp->mem_key = a_attr.mem_key;
	resp->mem_ofs = a_attr.page_index << UDMA_HW_PAGE_SHIFT;
	resp->page_count = a_attr.page_count;

	return a_attr.page_count ? 0 : -ENOMEM;
}

static bool dca_page_is_allocable(struct dca_page_state *state, bool head)
{
	bool is_free = dca_page_is_free(state) || dca_page_is_inactive(state);

	return head ? is_free : is_free && !state->head;
}

static int assign_dca_pages_proc(struct dca_mem *mem, uint32_t index,
				 void *param)
{
	struct dca_page_assign_attr *attr = param;
	struct dca_page_state *state;
	uint32_t checked_pages = 0;
	uint32_t start_index = 0;
	uint32_t free_pages = 0;
	uint32_t i = index;

	/* Check the continuous pages count is not smaller than unit count */
	for (; free_pages < attr->unit && i < mem->page_count; i++) {
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

static uint32_t assign_dca_pages(struct udma_dca_ctx *ctx, uint32_t buf_id,
				 uint32_t count, uint32_t unit)
{
	struct dca_page_assign_attr attr = {};

	attr.buf_id = buf_id;
	attr.unit = unit;
	attr.max = count;
	travel_dca_pages(ctx, &attr, assign_dca_pages_proc);

	return attr.total;
}

static int clear_dca_pages_proc(struct dca_mem *mem, uint32_t index,
				void *param)
{
	struct dca_page_state *state = &mem->states[index];
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

static void clear_dca_pages(struct udma_dca_ctx *ctx, uint32_t buf_id,
			    uint32_t count)
{
	struct dca_page_clear_attr attr = {};

	attr.buf_id = buf_id;
	attr.max_pages = count;
	travel_dca_pages(ctx, &attr, clear_dca_pages_proc);
}

static uint32_t alloc_buf_from_dca_mem(struct udma_qp *qp,
				       struct udma_dca_ctx *ctx)
{
	uint32_t alloc_pages;
	uint32_t unit_pages;
	uint32_t buf_pages;
	uint32_t buf_id;

	buf_pages = qp->dca_cfg.npages;
	/* Gen new buf id */
	buf_id = UDMA_DCA_TO_BUF_ID(qp->qpn, qp->dca_cfg.attach_count);

	/* Assign pages from free pages */
	unit_pages = qp->mtr.hem_cfg.is_direct ? buf_pages : 1;
	alloc_pages = assign_dca_pages(ctx, buf_id, buf_pages, unit_pages);
	if (buf_pages != alloc_pages) {
		if (alloc_pages > 0)
			clear_dca_pages(ctx, buf_id, alloc_pages);
		return UDMA_DCA_INVALID_BUF_ID;
	}

	return buf_id;
}

static int sync_dca_buf_offset(struct udma_dev *dev, struct udma_qp *qp,
			       struct udma_dca_attach_attr *attr)
{
	if (qp->sq.wqe_cnt > 0) {
		if (attr->sq_offset >= qp->sge.offset) {
			dev_err(dev->dev, "failed to check SQ offset = %u\n",
				attr->sq_offset);
			return -EINVAL;
		}
		qp->sq.wqe_offset = qp->sq.offset + attr->sq_offset;
	}

	if (qp->sge.sge_cnt > 0)
		qp->sge.wqe_offset = qp->sge.offset + attr->sge_offset;

	return 0;
}

static int get_alloced_umem_proc(struct dca_mem *mem, uint32_t index,
				 void *param)
{
	struct dca_get_alloced_pages_attr *attr = param;
	struct dca_page_state *states = mem->states;
	struct ubcore_umem *umem = mem->pages;
	uint32_t npage_per_sg, k, i;
	struct scatterlist *sg;

	for_each_sg(umem->sg_head.sgl, sg, umem->sg_head.nents, k) {
		npage_per_sg = sg_dma_len(sg) >> UDMA_HW_PAGE_SHIFT;
		for (i = 0; i < npage_per_sg; ++i) {
			if (dca_page_is_allocated(&states[i], attr->buf_id)) {
				attr->pages[attr->total++] = sg_dma_address(sg) +
							     (i << UDMA_HW_PAGE_SHIFT);
			}
			if (attr->total >= attr->max)
				return DCA_MEM_STOP_ITERATE;
		}
	}

	return DCA_MEM_NEXT_ITERATE;
}

static int config_dca_qpc(struct udma_dev *dev, struct udma_qp *qp,
			  dma_addr_t *pages, uint32_t page_count)
{
	int ret;

	ret = udma_mtr_map(dev, &qp->mtr, pages, page_count);
	if (ret) {
		dev_err(dev->dev, "failed to map DCA pages, ret = %d.\n", ret);
		return ret;
	}

	ret = udma_set_dca_buf(dev, qp);
	if (ret) {
		dev_err(dev->dev, "failed to set DCA to HW, ret = %d.\n", ret);
		return ret;
	}

	return 0;
}

static int setup_dca_buf_to_hw(struct udma_dev *dev, struct udma_qp *qp,
			       struct udma_dca_ctx *ctx, uint32_t buf_id,
			       uint32_t count)
{
	struct dca_get_alloced_pages_attr attr = {};
	dma_addr_t *pages;
	int ret;

	/* alloc a tmp array to store buffer's dma address */
	pages = kvcalloc(count, sizeof(dma_addr_t), GFP_ATOMIC);
	if (!pages)
		return -ENOMEM;

	attr.buf_id = buf_id;
	attr.pages = pages;
	attr.max = count;

	travel_dca_pages(ctx, &attr, get_alloced_umem_proc);

	if (attr.total != count) {
		dev_err(dev->dev, "failed to get DCA page %u != %u.\n",
			attr.total, count);
		ret = -ENOMEM;
		goto err_get_pages;
	}

	ret = config_dca_qpc(dev, qp, pages, count);
err_get_pages:
	/* drop tmp array */
	kvfree(pages);

	return ret;
}

static int active_dca_pages_proc(struct dca_mem *mem, uint32_t index,
				 void *param)
{
	struct dca_page_active_attr *attr = param;
	struct dca_page_state *state;
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

static uint32_t active_dca_pages(struct udma_dca_ctx *ctx, uint32_t buf_id,
				 uint32_t count)
{
	struct dca_page_active_attr attr = {};
	unsigned long flags;

	attr.buf_id = buf_id;
	attr.max_pages = count;
	travel_dca_pages(ctx, &attr, active_dca_pages_proc);

	/* Update free size */
	spin_lock_irqsave(&ctx->pool_lock, flags);
	ctx->free_mems -= attr.dirty_mems;
	ctx->free_size -= attr.alloc_pages << UDMA_HW_PAGE_SHIFT;
	spin_unlock_irqrestore(&ctx->pool_lock, flags);

	return attr.alloc_pages;
}

static int active_alloced_buf(struct udma_dev *dev, struct udma_dca_ctx *ctx,
			      struct udma_qp *qp, uint32_t buf_id,
			      struct udma_dca_attach_attr *attr)
{
	uint32_t active_pages;
	uint32_t alloc_pages;
	int ret;

	alloc_pages = qp->dca_cfg.npages;
	ret = sync_dca_buf_offset(dev, qp, attr);
	if (ret) {
		dev_err(dev->dev, "failed to sync DCA offset, ret = %d\n", ret);
		goto active_fail;
	}

	ret = setup_dca_buf_to_hw(dev, qp, ctx, buf_id, alloc_pages);
	if (ret) {
		dev_err(dev->dev, "failed to setup DCA buf, ret = %d.\n", ret);
		goto active_fail;
	}

	active_pages = active_dca_pages(ctx, buf_id, alloc_pages);
	if (active_pages != alloc_pages) {
		dev_err(dev->dev, "failed to active DCA pages, %u != %u.\n",
			active_pages, alloc_pages);
		ret = -ENOBUFS;
		goto active_fail;
	}

	return 0;
active_fail:
	clear_dca_pages(ctx, buf_id, alloc_pages);
	return ret;
}

int udma_dca_attach(struct udma_dev *dev, struct udma_dca_attach_attr *attr,
		    struct udma_dca_attach_resp *resp)
{
	struct udma_dca_ctx *ctx;
	struct udma_dca_cfg *cfg;
	struct udma_qp *qp;
	uint32_t buf_id;
	int ret;

	qp = get_qp(dev, attr->qpn);
	if (qp == NULL) {
		dev_err(dev->dev, "failed to find attach qp, qpn = 0x%llx\n",
			attr->qpn);
		return -EINVAL;
	}
	cfg = &qp->dca_cfg;
	ctx = qp->dca_ctx;

	stop_aging_dca_mem(ctx, cfg, false);
	resp->alloc_flags = 0;

	spin_lock(&cfg->lock);
	buf_id = cfg->buf_id;
	/* Already attached */
	if (buf_id != UDMA_DCA_INVALID_BUF_ID) {
		resp->alloc_pages = cfg->npages;
		spin_unlock(&cfg->lock);
		return 0;
	}

	/* Start to new attach */
	resp->alloc_pages = 0;
	buf_id = alloc_buf_from_dca_mem(qp, ctx);
	if (buf_id == UDMA_DCA_INVALID_BUF_ID) {
		spin_unlock(&cfg->lock);
		/* No report fail, need try again after the pool increased */
		return 0;
	}

	ret = active_alloced_buf(dev, ctx, qp, buf_id, attr);
	if (ret) {
		spin_unlock(&cfg->lock);
		dev_err(dev->dev,
			"failed to active DCA buf for QP-%llu, ret = %d.\n",
			qp->qpn, ret);
		return ret;
	}

	/* Attach ok */
	cfg->buf_id = buf_id;
	cfg->attach_count++;
	spin_unlock(&cfg->lock);

	resp->alloc_flags |= HNS3_UDMA_DCA_ATTACH_FLAGS_NEW_BUFFER;
	resp->alloc_pages = cfg->npages;
	resp->dcan = cfg->dcan;
	update_dca_buf_status(ctx, cfg->dcan, true);

	return 0;
}

void udma_dca_disattach(struct udma_dev *dev, struct udma_dca_attach_attr *attr)
{
	struct udma_dca_ctx *ctx;
	struct udma_dca_cfg *cfg;
	struct udma_qp *qp;

	qp = get_qp(dev, attr->qpn);
	if (qp == NULL) {
		dev_err(dev->dev, "failed to find disattach qp, qpn = 0x%llx\n",
			attr->qpn);
		return;
	}
	cfg = &qp->dca_cfg;
	ctx = qp->dca_ctx;

	clear_dca_pages(ctx, cfg->buf_id, qp->dca_cfg.npages);

	cfg->buf_id = UDMA_DCA_INVALID_BUF_ID;

	update_dca_buf_status(ctx, cfg->dcan, false);
}

void udma_dca_detach(struct udma_dev *dev, struct udma_dca_detach_attr *attr)
{
	struct udma_dca_ctx *ctx;
	struct udma_dca_cfg *cfg;
	struct udma_qp *qp;

	qp = get_qp(dev, attr->qpn);
	if (qp == NULL) {
		dev_err(dev->dev, "failed to find detach qp, qpn = 0x%llx\n",
			attr->qpn);
		return;
	}
	cfg = &qp->dca_cfg;
	ctx = qp->dca_ctx;

	stop_aging_dca_mem(ctx, cfg, true);

	spin_lock(&ctx->aging_lock);
	spin_lock(&cfg->lock);
	cfg->sq_idx = attr->sq_idx;
	list_add_tail(&cfg->aging_node, &ctx->aging_new_list);
	spin_unlock(&cfg->lock);
	spin_unlock(&ctx->aging_lock);

	restart_aging_dca_mem(dev, ctx);
}

static int enum_dca_pool_proc(struct dca_mem *mem, uint32_t index, void *param)
{
	struct dca_mem_enum_attr *attr = param;
	int ret;

	ret = attr->enum_fn((struct dca_page_state *)(mem->states),
			    mem->page_count, attr->param);

	return ret ? DCA_MEM_STOP_ITERATE : DCA_MEM_NEXT_ITERATE;
}

void udma_enum_dca_pool(struct udma_dca_ctx *dca_ctx, void *param,
			udma_dca_enum_callback cb)
{
	struct dca_mem_enum_attr attr;

	attr.enum_fn = cb;
	attr.param = param;
	travel_dca_pages(dca_ctx, &attr, enum_dca_pool_proc);
}
