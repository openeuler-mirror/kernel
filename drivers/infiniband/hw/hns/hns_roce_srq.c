/*
 * Copyright (c) 2018 Hisilicon Limited.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "roce_k_compat.h"
#include <linux/pci.h>
#include <rdma/ib_umem.h>
#include <rdma/hns-abi.h>
#include "hns_roce_device.h"
#include "hns_roce_cmd.h"
#include "hns_roce_hem.h"

void hns_roce_srq_event(struct hns_roce_dev *hr_dev, u32 srqn, int event_type)
{
	struct hns_roce_srq_table *srq_table = &hr_dev->srq_table;
	struct hns_roce_srq *srq;

	rcu_read_lock();
	srq = radix_tree_lookup(&srq_table->tree,
				srqn & (hr_dev->caps.num_srqs - 1));
	rcu_read_unlock();
	if (srq) {
		refcount_inc(&srq->refcount);
	} else {
		dev_warn(hr_dev->dev, "Async event for bogus SRQ 0x%08x\n",
			 srqn);
		return;
	}

	srq->event(srq, event_type);

	if (refcount_dec_and_test(&srq->refcount))
		complete(&srq->free);
}
EXPORT_SYMBOL_GPL(hns_roce_srq_event);

static void hns_roce_ib_srq_event(struct hns_roce_srq *srq,
				  enum hns_roce_event event_type)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(srq->ibsrq.device);
	struct ib_srq *ibsrq = &srq->ibsrq;
	struct ib_event event;

	if (ibsrq->event_handler) {
		event.device      = ibsrq->device;
		event.element.srq = ibsrq;
		switch (event_type) {
		case HNS_ROCE_EVENT_TYPE_SRQ_LIMIT_REACH:
			event.event = IB_EVENT_SRQ_LIMIT_REACHED;
			break;
		case HNS_ROCE_EVENT_TYPE_SRQ_CATAS_ERROR:
			event.event = IB_EVENT_SRQ_ERR;
			break;
		default:
			dev_err(hr_dev->dev,
			   "hns_roce:Unexpected event type 0x%x on SRQ 0x%06lx\n",
			   event_type, srq->srqn);
			return;
		}

		ibsrq->event_handler(&event, ibsrq->srq_context);
	}
}

static int hns_roce_hw_create_srq(struct hns_roce_dev *dev,
				  struct hns_roce_cmd_mailbox *mailbox,
				  unsigned long srq_num)
{
	return hns_roce_cmd_mbox(dev, mailbox->dma, 0, srq_num, 0,
				 HNS_ROCE_CMD_CREATE_SRQ,
				 HNS_ROCE_CMD_TIMEOUT_MSECS);
}

static int hns_roce_hw_destroy_srq(struct hns_roce_dev *dev,
				   struct hns_roce_cmd_mailbox *mailbox,
				   unsigned long srq_num)
{
	return hns_roce_cmd_mbox(dev, 0, mailbox ? mailbox->dma : 0, srq_num,
				 mailbox ? 0 : 1, HNS_ROCE_CMD_DESTROY_SRQ,
				 HNS_ROCE_CMD_TIMEOUT_MSECS);
}

static int hns_roce_srq_alloc(struct hns_roce_dev *hr_dev, u32 pdn, u32 cqn,
			      u16 xrcd, struct hns_roce_mtt *hr_mtt,
			      u64 db_rec_addr, struct hns_roce_srq *srq)
{
	struct hns_roce_srq_table *srq_table = &hr_dev->srq_table;
	struct hns_roce_cmd_mailbox *mailbox;
	dma_addr_t dma_handle_wqe;
	dma_addr_t dma_handle_idx;
	u64 *mtts_wqe;
	u64 *mtts_idx;
	int ret;

	/* Get the physical address of srq buf */
	mtts_wqe = hns_roce_table_find(hr_dev,
				       &hr_dev->mr_table.mtt_srqwqe_table,
				       srq->mtt.first_seg,
				       &dma_handle_wqe);
	if (!mtts_wqe) {
		dev_err(hr_dev->dev, "Failed to find mtt for srq buf.\n");
		return -EINVAL;
	}

	/* Get physical address of idx que buf */
	mtts_idx = hns_roce_table_find(hr_dev, &hr_dev->mr_table.mtt_idx_table,
				       srq->idx_que.mtt.first_seg,
				       &dma_handle_idx);
	if (!mtts_idx) {
		dev_err(hr_dev->dev,
			"Failed to find mtt for srq idx queue buf.\n");
		return -EINVAL;
	}

	ret = hns_roce_bitmap_alloc(&srq_table->bitmap, &srq->srqn);
	if (ret == -1) {
		dev_err(hr_dev->dev,
			"Failed to alloc a bit from srq bitmap.\n");
		return -ENOMEM;
	}

	ret = hns_roce_table_get(hr_dev, &srq_table->table, srq->srqn);
	if (ret) {
		dev_err(hr_dev->dev, "Get table failed(%d) for SRQ(0x%lx) alloc.\n",
			ret, srq->srqn);
		goto err_out;
	}

	spin_lock_irq(&srq_table->lock);
	ret = radix_tree_insert(&srq_table->tree, srq->srqn, srq);
	spin_unlock_irq(&srq_table->lock);
	if (ret)
		goto err_put;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox)) {
		ret = PTR_ERR(mailbox);
		goto err_radix;
	}

	hr_dev->hw->write_srqc(hr_dev, srq, pdn, xrcd, cqn, mailbox->buf,
			       mtts_wqe, mtts_idx, dma_handle_wqe,
			       dma_handle_idx);

	ret = hns_roce_hw_create_srq(hr_dev, mailbox, srq->srqn);
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);
	if (ret) {
		dev_err(hr_dev->dev, "CREATE_SRQ(0x%lx) failed(%d).\n",
			srq->srqn, ret);
		goto err_radix;
	}

	refcount_set(&srq->refcount, 1);
	init_completion(&srq->free);
	return ret;

err_radix:
	spin_lock_irq(&srq_table->lock);
	radix_tree_delete(&srq_table->tree, srq->srqn);
	spin_unlock_irq(&srq_table->lock);

err_put:
	hns_roce_table_put(hr_dev, &srq_table->table, srq->srqn);

err_out:
	hns_roce_bitmap_free(&srq_table->bitmap, srq->srqn, BITMAP_NO_RR);
	return ret;
}

static void hns_roce_srq_free(struct hns_roce_dev *hr_dev,
			      struct hns_roce_srq *srq)
{
	struct hns_roce_srq_table *srq_table = &hr_dev->srq_table;
	int ret;

	ret = hns_roce_hw_destroy_srq(hr_dev, NULL, srq->srqn);
	if (ret)
		dev_err(hr_dev->dev, "DESTROY_SRQ failed (%d) for SRQN 0x%06lx.\n",
			ret, srq->srqn);

	spin_lock_irq(&srq_table->lock);
	radix_tree_delete(&srq_table->tree, srq->srqn);
	spin_unlock_irq(&srq_table->lock);

	if (refcount_dec_and_test(&srq->refcount))
		complete(&srq->free);
	wait_for_completion(&srq->free);

	hns_roce_table_put(hr_dev, &srq_table->table, srq->srqn);
	hns_roce_bitmap_free(&srq_table->bitmap, srq->srqn, BITMAP_NO_RR);
}

static int create_user_srq(struct ib_pd *pd, struct hns_roce_srq *srq,
			   struct ib_udata *udata, int srq_buf_size)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(pd->device);
	struct hns_roce_ib_create_srq  ucmd;
	struct hns_roce_buf *buf;
	int ret;

	if (ib_copy_from_udata(&ucmd, udata, sizeof(ucmd)))
		return -EFAULT;

	srq->umem = ib_umem_get(pd->uobject->context, ucmd.buf_addr,
				srq_buf_size, 0, 0);
	if (IS_ERR(srq->umem))
		return PTR_ERR(srq->umem);

	if (hr_dev->caps.srqwqe_buf_pg_sz) {
		buf = srq->buf;
		buf->npages = (ib_umem_page_count(srq->umem) +
		       (1 << hr_dev->caps.srqwqe_buf_pg_sz) - 1) /
		      (1 << hr_dev->caps.srqwqe_buf_pg_sz);
		buf->page_shift = PAGE_SHIFT + hr_dev->caps.srqwqe_buf_pg_sz;
		ret = hns_roce_mtt_init(hr_dev, buf->npages, buf->page_shift,
				&srq->mtt);
	} else
		ret = hns_roce_mtt_init(hr_dev, ib_umem_page_count(srq->umem),
					srq->umem->page_shift, &srq->mtt);
	if (ret) {
		dev_err(hr_dev->dev, "Mtt init error(%d) when create srq.\n",
			ret);
		goto err_user_buf;
	}

	ret = hns_roce_ib_umem_write_mtt(hr_dev, &srq->mtt, srq->umem);
	if (ret)
		goto err_user_srq_mtt;

	/* config index queue BA */
	srq->idx_que.umem = ib_umem_get(pd->uobject->context, ucmd.que_addr,
					srq->idx_que.buf_size, 0, 0);
	if (IS_ERR(srq->idx_que.umem)) {
		dev_err(hr_dev->dev, "umem get error for idx que\n");
		goto err_user_srq_mtt;
	}

	if (hr_dev->caps.idx_buf_pg_sz) {
		buf = srq->idx_que.idx_buf;
		buf->npages = DIV_ROUND_UP(ib_umem_page_count(srq->idx_que.umem),
				   1 << hr_dev->caps.idx_buf_pg_sz);
		buf->page_shift = PAGE_SHIFT + hr_dev->caps.idx_buf_pg_sz;
		ret = hns_roce_mtt_init(hr_dev, buf->npages, buf->page_shift,
				&srq->idx_que.mtt);
	} else {
		ret = hns_roce_mtt_init(hr_dev,
					ib_umem_page_count(srq->idx_que.umem),
					srq->idx_que.umem->page_shift,
					&srq->idx_que.mtt);
	}

	if (ret) {
		dev_err(hr_dev->dev, "User mtt init error for idx que\n");
		goto err_user_idx_mtt;
	}

	ret = hns_roce_ib_umem_write_mtt(hr_dev, &srq->idx_que.mtt,
					 srq->idx_que.umem);
	if (ret) {
		dev_err(hr_dev->dev,
			"Write mtt error(%d) for idx que\n", ret);
		goto err_user_idx_buf;
	}

	return 0;

err_user_idx_buf:
	hns_roce_mtt_cleanup(hr_dev, &srq->idx_que.mtt);

err_user_idx_mtt:
	ib_umem_release(srq->idx_que.umem);

err_user_srq_mtt:
	hns_roce_mtt_cleanup(hr_dev, &srq->mtt);

err_user_buf:
	ib_umem_release(srq->umem);

	return ret;
}

static int hns_roce_create_idx_que(struct ib_pd *pd, struct hns_roce_srq *srq,
				   u32 page_shift)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(pd->device);
	struct hns_roce_idx_que *idx_que = &srq->idx_que;
	struct hns_roce_buf *kbuf;
	u32 bitmap_num;
	int i;

	idx_que->entry_sz = HNS_ROCE_IDX_QUE_ENTRY_SZ;
	bitmap_num = HNS_ROCE_ALIGN_UP(srq->max, BITS_PER_LONG_LONG);

	idx_que->bitmap = kcalloc(1, bitmap_num / BITS_PER_BYTE, GFP_KERNEL);
	if (!idx_que->bitmap)
		return -ENOMEM;

	bitmap_num = bitmap_num / BITS_PER_LONG_LONG;

	idx_que->buf_size = srq->max * idx_que->entry_sz;

	kbuf = hns_roce_buf_alloc(hr_dev, idx_que->buf_size, page_shift, 0);
	if (IS_ERR(kbuf)) {
		kfree(idx_que->bitmap);
		return -ENOMEM;
	}

	idx_que->idx_buf = kbuf;
	for (i = 0; i < bitmap_num; i++)
		idx_que->bitmap[i] = ~(0UL);

	idx_que->head = 0;
	idx_que->tail = 0;

	return 0;
}

static int create_kernel_srq(struct ib_pd *pd, struct hns_roce_srq *srq,
			     int srq_buf_size)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(pd->device);
	u32 page_shift = PAGE_SHIFT + hr_dev->caps.srqwqe_buf_pg_sz;
	struct hns_roce_buf *kbuf;
	int ret;

	kbuf = hns_roce_buf_alloc(hr_dev, srq_buf_size, page_shift, 0);
	if (IS_ERR(kbuf))
		return -ENOMEM;

	srq->buf = kbuf;
	srq->wqe_ctr = 0;

	ret = hns_roce_mtt_init(hr_dev, kbuf->npages, kbuf->page_shift,
				&srq->mtt);
	if (ret) {
		dev_err(hr_dev->dev, "Mtt init error(%d) when create srq.\n",
			ret);
		goto err_kernel_buf;
	}

	ret = hns_roce_buf_write_mtt(hr_dev, &srq->mtt, srq->buf);
	if (ret)
		goto err_kernel_srq_mtt;

	page_shift = PAGE_SHIFT + hr_dev->caps.idx_buf_pg_sz;
	ret = hns_roce_create_idx_que(pd, srq, page_shift);
	if (ret) {
		dev_err(hr_dev->dev, "Create idx queue fail(%d)!\n", ret);
		goto err_kernel_srq_mtt;
	}

	/* Init mtt table for idx_que */
	ret = hns_roce_mtt_init(hr_dev, srq->idx_que.idx_buf->npages,
				srq->idx_que.idx_buf->page_shift,
				&srq->idx_que.mtt);
	if (ret) {
		dev_err(hr_dev->dev, "Kernel mtt init error(%d) for idx que.\n",
			ret);
		goto err_kernel_create_idx;
	}
	/* Write buffer address into the mtt table */
	ret = hns_roce_buf_write_mtt(hr_dev, &srq->idx_que.mtt,
				     srq->idx_que.idx_buf);
	if (ret) {
		dev_err(hr_dev->dev, "Write mtt error(%d) for idx que.\n", ret);
		goto err_kernel_idx_buf;
	}
	srq->wrid = kcalloc(srq->max, sizeof(u64), GFP_KERNEL);
	if (!srq->wrid) {
		ret = -ENOMEM;
		goto err_kernel_idx_buf;
	}

	return 0;

err_kernel_idx_buf:
	hns_roce_mtt_cleanup(hr_dev, &srq->idx_que.mtt);

err_kernel_create_idx:
	hns_roce_buf_free(hr_dev, srq->idx_que.idx_buf);
	kfree(srq->idx_que.bitmap);

err_kernel_srq_mtt:
	hns_roce_mtt_cleanup(hr_dev, &srq->mtt);

err_kernel_buf:
	hns_roce_buf_free(hr_dev, srq->buf);

	return ret;
}

static void destroy_user_srq(struct hns_roce_dev *hr_dev,
			     struct hns_roce_srq *srq)
{
	hns_roce_mtt_cleanup(hr_dev, &srq->idx_que.mtt);
	ib_umem_release(srq->idx_que.umem);
	hns_roce_mtt_cleanup(hr_dev, &srq->mtt);
	ib_umem_release(srq->umem);
}

static void destroy_kernel_srq(struct hns_roce_dev *hr_dev,
			       struct hns_roce_srq *srq, int srq_buf_size)
{
	kfree(srq->wrid);
	hns_roce_mtt_cleanup(hr_dev, &srq->idx_que.mtt);
	hns_roce_buf_free(hr_dev, srq->idx_que.idx_buf);
	kfree(srq->idx_que.bitmap);
	hns_roce_mtt_cleanup(hr_dev, &srq->mtt);
	hns_roce_buf_free(hr_dev, srq->buf);
}

static u32 proc_srq_sge(struct hns_roce_dev *dev, struct hns_roce_srq *hr_srq,
	bool user)
{
	u32 max_sge = dev->caps.max_srq_sges;

	if (dev->pci_dev->revision > PCI_REVISION_ID_HIP08_B)
		return max_sge;
	/* Reserve SGEs only for HIP08 in kernel; The userspace driver will
	 * calculate number of max_sge with reserved SGEs when allocating wqe
	 * buf, so there is no need to do this again in kernel. But the number
	 * may exceed the capacity of SGEs recorded in the firmware, so the
	 * kernel driver should just adapt the value accordingly.
	 */
	if (user)
		max_sge = roundup_pow_of_two(max_sge + 1);
	else
		hr_srq->rsv_sge = 1;

	return max_sge;
}


struct ib_srq *hns_roce_create_srq(struct ib_pd *pd,
				   struct ib_srq_init_attr *srq_init_attr,
				   struct ib_udata *udata)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(pd->device);
	struct hns_roce_srq *srq;
	int srq_desc_size;
	int srq_buf_size;
	u32 max_sge;
	int ret;
	u32 cqn;

	srq = kzalloc(sizeof(*srq), GFP_KERNEL);
	if (!srq)
		return ERR_PTR(-ENOMEM);

	max_sge = proc_srq_sge(hr_dev, srq, !!udata);

	if (srq_init_attr->attr.max_wr >= hr_dev->caps.max_srq_wrs ||
	    srq_init_attr->attr.max_sge > max_sge)
		return ERR_PTR(-EINVAL);

	mutex_init(&srq->mutex);
	spin_lock_init(&srq->lock);

	srq->max = roundup_pow_of_two(srq_init_attr->attr.max_wr + 1);
	srq->max_gs =
		roundup_pow_of_two(srq_init_attr->attr.max_sge + srq->rsv_sge);

	srq_desc_size = max(HNS_ROCE_SGE_SIZE, HNS_ROCE_SGE_SIZE * srq->max_gs);
	srq_desc_size = roundup_pow_of_two(srq_desc_size);

	srq->wqe_shift = ilog2(srq_desc_size);

	srq_buf_size = srq->max * srq_desc_size;

	srq->idx_que.entry_sz = HNS_ROCE_IDX_QUE_ENTRY_SZ;
	srq->idx_que.buf_size = srq->max * srq->idx_que.entry_sz;
	srq->mtt.mtt_type = MTT_TYPE_SRQWQE;
	srq->idx_que.mtt.mtt_type = MTT_TYPE_IDX;

	if (pd->uobject) {
		ret = create_user_srq(pd, srq, udata, srq_buf_size);
		if (ret) {
			dev_err(hr_dev->dev, "Create user srq fail\n");
			goto err_srq;
		}
	} else {
		ret = create_kernel_srq(pd, srq, srq_buf_size);
		if (ret) {
			dev_err(hr_dev->dev, "Create kernel srq fail\n");
			goto err_srq;
		}
	}

	cqn = ib_srq_has_cq(srq_init_attr->srq_type) ?
	      to_hr_cq(srq_init_attr->ext.cq)->cqn : 0;

	srq->db_reg_l = hr_dev->reg_base + SRQ_DB_REG;

	ret = hns_roce_srq_alloc(hr_dev, to_hr_pd(pd)->pdn, cqn, 0, &srq->mtt,
				 0, srq);
	if (ret) {
		dev_err(hr_dev->dev,
			"Alloc srq failed(%d), cqn is 0x%x, pdn is 0x%lx.\n",
			ret, cqn, to_hr_pd(pd)->pdn);
		goto err_wrid;
	}

	srq->event = hns_roce_ib_srq_event;
	srq->ibsrq.ext.xrc.srq_num = srq->srqn;
	srq_init_attr->attr.max_wr = srq->max;
	srq_init_attr->attr.max_sge = srq->max_gs - srq->rsv_sge;
	srq_init_attr->attr.srq_limit = 0;

	if (pd->uobject) {
		if (ib_copy_to_udata(udata, &srq->srqn, sizeof(__u32))) {
			ret = -EFAULT;
			goto err_srqc_alloc;
		}
	}

	return &srq->ibsrq;

err_srqc_alloc:
	hns_roce_srq_free(hr_dev, srq);

err_wrid:
	if (pd->uobject)
		destroy_user_srq(hr_dev, srq);
	else
		destroy_kernel_srq(hr_dev, srq, srq_buf_size);

err_srq:
	kfree(srq);
	return ERR_PTR(ret);
}

int hns_roce_destroy_srq(struct ib_srq *ibsrq)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ibsrq->device);
	struct hns_roce_srq *srq = to_hr_srq(ibsrq);

	hns_roce_srq_free(hr_dev, srq);
	hns_roce_mtt_cleanup(hr_dev, &srq->mtt);

	if (ibsrq->uobject) {
		hns_roce_mtt_cleanup(hr_dev, &srq->idx_que.mtt);
		ib_umem_release(srq->idx_que.umem);
		ib_umem_release(srq->umem);
	} else {
		kfree(srq->wrid);
		hns_roce_buf_free(hr_dev, srq->buf);
	}

	kfree(srq);

	return 0;
}

int hns_roce_init_srq_table(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_srq_table *srq_table = &hr_dev->srq_table;

	spin_lock_init(&srq_table->lock);
	INIT_RADIX_TREE(&srq_table->tree, GFP_ATOMIC);

	return hns_roce_bitmap_init(&srq_table->bitmap, hr_dev->caps.num_srqs,
				    hr_dev->caps.num_srqs - 1,
				    hr_dev->caps.reserved_srqs, 0);
}

void hns_roce_cleanup_srq_table(struct hns_roce_dev *hr_dev)
{
	hns_roce_bitmap_cleanup(&hr_dev->srq_table.bitmap);
}
