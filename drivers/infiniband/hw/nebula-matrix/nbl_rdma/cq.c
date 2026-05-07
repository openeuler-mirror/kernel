// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/bitfield.h>
#include <rdma/nbl-abi.h>
#include "main.h"
#include "alloc.h"
#include "cq.h"
#include "qp.h"
#include "verbs.h"
#include "cqp.h"
#include "defs.h"
#include "mem.h"
#include "user.h"
#include "defs.h"
#include "debug.h"
#include "ceq.h"

/**
 * nbl_uk_clean_soft_wc - destroy cq soft_wc in cq
 * @nblcq: rdma cq ptr
 */
static void nbl_cq_destroy_soft_wc(struct nbl_cq *nblcq)
{
	struct nbl_ib_wc *soft_wc, *next;

	list_for_each_entry_safe(soft_wc, next, &nblcq->pre_list, list) {
		list_del(&soft_wc->list);
		kfree(soft_wc);
	}

	list_for_each_entry_safe(soft_wc, next, &nblcq->wc_list, list) {
		list_del(&soft_wc->list);
		kfree(soft_wc);
	}
}

/**
 * nbl_cqp_cq_create_cmd - Create/Destroy CQ.
 * @dev: pointer to device info
 * @sc_cq: pointer to aeq structure
 * Return: return 0 if the cqp cmd exec success, otherwise return error.
 */
static int nbl_cqp_cq_create_cmd(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq)
{
	int ret;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;
	u32 cq_size = sc_cq->cq_uk.cq_size;
	u32 cq_id = sc_cq->cq_uk.cq_id;
	u32 ceq_id = sc_cq->ceq_id;
	bool pa_continuous = sc_cq->pa_continuous;
	u32 shadow_read_th = sc_cq->shadow_read_threshold;
	u64 cq_base_pa = sc_cq->cq_pa;
	u64 cq_1st_page_pa = 0;
	u64 cq_2nd_page_pa = 0;
	u64 *base_addr = NULL;
	u64 cqc_begin_pa = sc_cq->cqc_begin_pa;
	int cqe_cnt = ilog2(cq_size); /* here cq_size is 2^X */
	u32 cq_pg_num = sc_cq->cq_pg_num;

	if (pa_continuous) {
		cq_1st_page_pa = cq_base_pa;
		if (cq_pg_num > 1)
			cq_2nd_page_pa =
				cq_base_pa + (1 << NBL_ADAPTER_PAGE_SHIFT);
	} else {
		base_addr = (u64 *)sc_cq->cq_uk.cq_base;
		if (base_addr) {
			/* as base_addr point to hw read pd area,
			 * this area is big end, so here we covert it first
			 */
			cq_1st_page_pa = be64_to_cpu(base_addr[0]);
			if (cq_pg_num > 1)
				cq_2nd_page_pa = be64_to_cpu(base_addr[1]);
		} else {
			nbl_ib_err(&rf->sc_dev, "[CQ] create cq base addr NULL err\n");
			return NBL_ERR_ALLOCMEM_FAILED;
		}
	}

	nbl_ib_dbg(&rf->sc_dev,
		"[CQ] (cqn %u) CQP parameter: 1st_addr: 0x%llx, 2nd_addr:0x%llx\n",
		cq_id, cq_1st_page_pa, cq_2nd_page_pa);
	nbl_ib_dbg(&rf->sc_dev,
		"[CQ] (continus %d)cq_base_pa:0x%llx, sc cq 0x%llx,cqc pa 0x%llx\n",
		pa_continuous, cq_base_pa, (u64)((uintptr_t)sc_cq), cqc_begin_pa);

	in = kzalloc(in_size, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	set_64bit_val(
		in, 0,
		FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_CREATE_CQ) |
		FIELD_PREP(NBL_CQPSQ_CQ_STAT, NBL_CQ_STAT_VALID) |
		FIELD_PREP(NBL_CQPSQ_CQ_CQSIZE, cqe_cnt) |
		FIELD_PREP(NBL_CQPSQ_CQ_CQID, cq_id) |
		FIELD_PREP(NBL_CQPSQ_CQ_CEQID, ceq_id) |
		FIELD_PREP(NBL_CQPSQ_CQ_PS, pa_continuous ?
			NBL_CQP_PM_0_CONTINUS : NBL_CQP_PM_1_UNCONTINUS) |
		FIELD_PREP(NBL_CQPSQ_CQ_SHADOWTH, shadow_read_th));
	set_64bit_val(in, 16, (u64)((uintptr_t)sc_cq));
	set_64bit_val(in, 24, FIELD_PREP(NBL_CQPSQ_CQ_BASEADDR,
		cq_base_pa >> NBL_ADAPTER_PAGE_SHIFT));
	set_64bit_val(in, 32, FIELD_PREP(NBL_CQPSQ_CQ_CUR_ADDR,
		cq_1st_page_pa >> NBL_ADAPTER_PAGE_SHIFT));
	set_64bit_val(in, 40, FIELD_PREP(NBL_CQPSQ_CQ_NXT_ADDR,
		cq_2nd_page_pa >> NBL_ADAPTER_PAGE_SHIFT));
	set_64bit_val(in, 48, FIELD_PREP(NBL_CQPSQ_CQ_CQC_BASE_ADDR,
		cqc_begin_pa >> NBL_CQ_CQC_BASE_ADDR_SHIFT));

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);

	kfree(in);

	return ret;
}

/**
 * nbl_uk_cq_init - initialize shared cq (user and kernel)
 * @cq: hw cq
 * @info: hw cq initialization info
 */
static int nbl_uk_cq_init(struct nbl_cq_uk *cq,
	struct nbl_sc_cq *sc_cq, struct nbl_cq_uk_init_info *info)
{
	cq->cq_base = info->cq_base;
	cq->cq_id = info->cq_id;
	cq->cq_size = info->cq_size;
	cq->shadow_area = info->shadow_area;
	cq->cqc_base_va = info->cqc_base_va;
	cq->cqc_base_pa = info->cqc_base_pa;
	NBL_RING_INIT(cq->cq_ring, cq->cq_size);
	cq->polarity = 1;
	cq->bak_sc_cq = sc_cq;

	return 0;
}

/**
 * nbl_sc_cq_init - initialize completion q
 * @cq: cq struct
 * @info: cq initialization info
 */
static enum nbl_status_code nbl_sc_cq_init(struct nbl_sc_cq *cq,
				    struct nbl_cq_init_info *info)
{
	int ret_code;

	cq->cq_pa = info->cq_base_pa;
	cq->dev = info->dev;
	cq->ceq_id = info->ceq_id;

	ret_code = nbl_uk_cq_init(&cq->cq_uk, cq, &info->cq_uk_init_info);
	if (ret_code)
		return ret_code;

	cq->cqc_begin_pa = info->cqc_begin_pa;
	cq->shadow_area_pa = info->shadow_area_pa;
	cq->shadow_read_threshold = info->shadow_read_threshold;

	cq->pa_continuous = info->pa_continuous;
	cq->cq_pg_num = info->cq_pg_num;

	return 0;
}

/**
 * destroy_cq_user - free up buf resources for cq user-mode
 * @dev: RDMA source control device
 * @cq: RDMA CQ pointer
 */
static void destroy_cq_user(struct nbl_sc_dev *dev, struct nbl_cq *cq)
{
	if (!cq->pa_continuous) {
		dma_free_coherent(dev->hw->device, NBL_ADAPTER_PAGE_SIZE,
				  cq->kmem.va, cq->kmem.pa);
		nbl_ib_dbg(dev, "destroy cq user, 0-level page freed ok.\n");
	}

	ib_umem_release(cq->buf.umem);
	cq->kmem.va = NULL;
	nbl_ib_dbg(dev, "destroy cq user success, umem released.\n");
}

/**
 * destroy_cq_kernel - free up buf resources for cq kernel-mode
 * @dev: RDMA source control device
 * @cq: RDMA CQ pointer
 */
static void destroy_cq_kernel(struct nbl_sc_dev *dev, struct nbl_cq *cq)
{
	struct nbl_frag_buf *cq_buf = &cq->buf.frag_buf;

	if (cq->pa_continuous)
		dma_free_coherent(dev->hw->device, cq->kmem.size, cq->kmem.va,
				  cq->kmem.pa);
	else
		nbl_frag_buf_free(dev->hw->device, cq->kmem.va, cq->kmem.pa,
				  cq_buf);

	cq->kmem.va = NULL;
}

/**
 * nbl_cq_free_rsrc - free up resources for cq
 * @rf: RDMA PCI function
 * @nblcq: cq ptr
 */
static void nbl_cq_free_rsrc(struct nbl_pci_f *rf, struct nbl_cq *nblcq)
{
	struct nbl_sc_cq *cq = &nblcq->sc_cq;

	nbl_free_rsrc(&rf->rsrc_lock, rf->allocated_cqs, cq->cq_uk.cq_id);
	nbl_ib_dbg(&rf->sc_dev, "cq rsrc freed.\n");
}

/**
 * nbl_create_cq_user - create cq by userspace cmd
 */
static int nbl_create_cq_user(struct nbl_device *dev, struct ib_udata *udata,
			      struct nbl_cq *cq, struct ib_ucontext *uctx)
{
	struct nbl_create_cq_req ucmd = {};
	struct nbl_sc_dev *sc_dev = &dev->rf->sc_dev;
	size_t ucmdlen;
	u32 pg_num;
	bool is_contiguous = false;
	int status;
	u32 copy_num;
	u32 pas_size;
	int err;
	u64 cq_buf_size;

	ucmdlen = min(udata->inlen, sizeof(ucmd));
	if (ib_copy_from_udata(&ucmd, udata, ucmdlen))
		return -EFAULT;
	cq_buf_size = ucmd.cq_buf_size;

	nbl_ib_dbg(sc_dev, "[CQ_CREATE]create cq user, cqe_size:%d, buffer size :%ld, cq_buf_size:%lld, user_cq_buf:0x%llx\n",
		cq->ibcq.cqe, cq->ibcq.cqe * sizeof(struct nbl_cqe),
		cq_buf_size, ucmd.user_cq_buf);

	cq->buf.umem = ib_umem_get(&dev->ibdev, ucmd.user_cq_buf, cq_buf_size,
				   IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(cq->buf.umem)) {
		err = PTR_ERR(cq->buf.umem);
		return err;
	}

	nbl_get_umem_info(cq->buf.umem, &pg_num, &is_contiguous);

	cq->cq_pg_num = pg_num;

	nbl_ib_dbg(sc_dev, "[CQ_CREATE]create cq with pg_num:%d, contiguous: %s", pg_num,
		is_contiguous ? "true" : "false");

	if (is_contiguous) {
		cq->kmem.pa = nbl_get_first_sg_dma_addr(cq->buf.umem);

		cq->pa_continuous = true;
		cq->kmem.va = NULL;

		nbl_ib_dbg(sc_dev, "[CQ_CREATE]CQ buffer, pa: 0x%llx\n", cq->kmem.pa);
	} else {
		cq->pa_continuous = false;
		pas_size =
			NBL_ADAPTER_PAGE_SIZE; /* just support one page by now*/
		cq->kmem.va = nbl_dma_alloc_coherent(sc_dev->hw->device,
						     NBL_ADAPTER_PAGE_SIZE,
						     &cq->kmem.pa, GFP_KERNEL);
		if (!cq->kmem.va) {
			status = NBL_ERR_ALLOCMEM_FAILED;
			nbl_ib_err(sc_dev, "[CQ_CREATE] CQ kmem va NULL\n");
			goto err_umem;
		}

		status = nbl_copy_user_pgaddrs(cq->buf.umem, cq->kmem.va,
					       pas_size, pg_num, &copy_num);
		if (status) {
			dma_free_coherent(sc_dev->hw->device,
					  NBL_ADAPTER_PAGE_SIZE, cq->kmem.va,
					  cq->kmem.pa);
			goto err_umem;
		}
	}

	return 0;

err_umem:
	ib_umem_release(cq->buf.umem);
	return status;
}

/**
 * nbl_cqp_cq_destroy_cmd - send cq destroy cqp
 * @rf: RDMA PCI function
 * @cq: hardware control cq
 */
static int nbl_cqp_cq_destroy_cmd(struct nbl_pci_f *rf, struct nbl_sc_cq *cq)
{
	int ret;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;
	u32 cq_id = cq->cq_uk.cq_id;

	in = kzalloc(in_size, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	set_64bit_val(in, 0,
		      FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_DESTROY_CQ) |
			      FIELD_PREP(NBL_CQPSQ_CQ_STAT, NBL_CQ_STAT_INVALID) |
			      FIELD_PREP(NBL_CQPSQ_CQ_CQID, cq_id));

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);

	kfree(in);

	return ret;
}

/**
 * nbl_sc_cleanup_ceqes - clear the valid ceqes ctx matching the cq
 * @cq: cq for which the ceqes need to be cleaned up
 * @ceq: ceq ptr
 *
 * The function is called after the cq is destroyed to cleanup
 * its pending ceqe entries. It is expected caller serializes this
 * function with process_ceq() in interrupt context.
 */
static void nbl_sc_cleanup_ceqes(struct nbl_sc_cq *cq, struct nbl_ceq *ceq)
{
	struct nbl_sc_dev *dev = cq->dev;
	struct nbl_sc_ceq *sc_ceq;
	u32 cq_idx;
	u8 ceq_polarity;
	__be64 *ceqe;
	u8 polarity;
	u64 temp;
	u32 next;
	u32 i;

	sc_ceq = &ceq->sc_ceq;
	ceq_polarity = sc_ceq->polarity;

	next = NBL_RING_GET_NEXT_TAIL(sc_ceq->ceq_ring, 0);

	for (i = 1; i <= NBL_RING_SIZE(sc_ceq->ceq_ring); i++) {
		ceqe = nbl_get_wqe(sc_ceq->ceqe_base, &(ceq->buf),
			sizeof(struct nbl_ceqe), next, sc_ceq->pa_continuous);
		if (!ceqe) {
			nbl_ib_err(dev, "get ceqe fail\n");
			return;
		}

		get_64bit_val(ceqe, 0, &temp);
		polarity = (u8)FIELD_GET(NBL_CEQE_VALID, temp);
		if (polarity != ceq_polarity)
			return;

		cq_idx = FIELD_GET(NBL_CEQE_CQN, temp);
		/* for same contex, then clear cqn of ceqe to invalid this ceqe */
		if (cq->cq_uk.cq_id == cq_idx)
			set_64bit_val(ceqe, 0,
				      FIELD_PREP(NBL_CEQE_VALID, polarity) |
					  FIELD_PREP(NBL_CEQE_CQN, 0xffffff));

		next = NBL_RING_GET_NEXT_TAIL(sc_ceq->ceq_ring, i);
		if (!next)
			ceq_polarity ^= 1;
	}
}

static void nbl_cq_suspend_ceq(struct nbl_pci_f *rf, struct nbl_cq *nblcq)
{
	unsigned long flags;

	spin_lock_irqsave(&rf->cqtable_lock, flags);
	nblcq->ceq_suspend = true;
	spin_unlock_irqrestore(&rf->cqtable_lock, flags);
}

static void nbl_cq_cancel_poll_work(struct ib_cq *cq)
{
	if (cq->poll_ctx == IB_POLL_WORKQUEUE ||
	    cq->poll_ctx == IB_POLL_UNBOUND_WORKQUEUE)
		cancel_work_sync(&cq->work);
}

/**
 * nbl_ib_destroy_cq - destroy cq
 * @ib_cq: cq pointer
 * @udata: user data
 */
int nbl_ib_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata)
{
	struct nbl_device *nbldev = to_nbl_dev(ib_cq->device);
	struct nbl_cq *nblcq = to_nblcq(ib_cq);
	struct nbl_sc_cq *cq = &nblcq->sc_cq;
	struct nbl_sc_dev *dev = cq->dev;
	unsigned long flags;
	struct nbl_ceq *nblceq;
	struct nbl_sc_ceq *ceq;

	nbl_ib_dbg(dev, "destroy cq(%u) start, with ceq_id: %d\n", cq->cq_uk.cq_id, cq->ceq_id);

	ceq = dev->ceq[cq->ceq_id];
	nblceq = container_of(ceq, struct nbl_ceq, sc_ceq);

	nbl_cq_suspend_ceq(nbldev->rf, nblcq);
	spin_lock_irqsave(&nblcq->lock, flags);
	nbl_cq_destroy_soft_wc(nblcq);
	spin_unlock_irqrestore(&nblcq->lock, flags);

	nbl_cq_rem_ref(ib_cq);
	wait_for_completion(&nblcq->free_cq);
	nbl_cq_cancel_poll_work(ib_cq);
	nbl_cqp_cq_destroy_cmd(nbldev->rf, cq);
	if (udata)
		destroy_cq_user(dev, nblcq);
	else
		destroy_cq_kernel(dev, nblcq);

	set_64bit_val((__be64 *)nblcq->kmem_shadow.va, 8, 0); /* clean shadow area pi/ci part */

	spin_lock_irqsave(&nblceq->ce_lock, flags);
	nbl_sc_cleanup_ceqes(cq, nblceq);
	spin_unlock_irqrestore(&nblceq->ce_lock, flags);

	nbl_cq_free_rsrc(nbldev->rf, nblcq);

	nbl_ib_dbg(dev, "[CQ_DESTROY] destroy cq success.\n");
	return 0;
}

static int nbl_create_cq_kernel(struct nbl_sc_dev *dev, struct nbl_cq *nblcq,
			 int rsize, struct nbl_frag_buf *nblcq_buf)
{
	int status;

	nblcq->kmem.size = round_up(rsize, NBL_ADAPTER_PAGE_SIZE);
	nblcq->kmem.va = nbl_dma_alloc_coherent(
		dev->hw->device, nblcq->kmem.size, &nblcq->kmem.pa, GFP_KERNEL);
	nblcq_buf->size = nblcq->kmem.size;
	nblcq_buf->npages =
		DIV_ROUND_UP(nblcq_buf->size, NBL_ADAPTER_PAGE_SIZE);
	if (nblcq->kmem.va)
		nblcq->pa_continuous = true;
	else {
		nblcq->pa_continuous = false;
		status = nbl_frag_buf_alloc(dev->hw->device, &nblcq->kmem.va,
					    &nblcq->kmem.pa, nblcq_buf);
		if (status)
			return status;
	}

	nblcq->cq_pg_num = nblcq_buf->npages;

	return 0;
}

/**
 * nbl_cq_user_shadow_init - prepare uresp for user space and add mmap list
 * @cq: source control cq
 * @rf: RDMA PCI function
 * @uctx: user context
 * @uresp: response struct for user space
 *
 * this function handle uresp structure value init, then check and add
 * shadow_base_addr to mmap hash list
 */
static int nbl_cq_user_shadow_init(struct nbl_sc_cq *cq, struct nbl_pci_f *rf,
				     struct nbl_ucontext *uctx,
				     struct nbl_ib_create_cq_resp *uresp)
{
	struct nbl_hmc_obj_sd_info *cq_sd_info = rf->cq_sd_info;
	struct nbl_cq_uk *cq_uk = &cq->cq_uk;
	struct shadow_node *cqc_shadow = NULL;
	u32 map_size;

	uresp->shadow_base_addr = cq_uk->cqc_base_pa & PAGE_MASK;
	uresp->sys_page_offset = cq_uk->cqc_base_pa & (PAGE_SIZE - 1);
	uresp->cqc_size = NBL_CQ_CTX_SIZE;
	uresp->shadow_offset = NBL_CQ_SHADOW_OFFST;
	uresp->shadow_size = NBL_CQ_SHADOW_SIZE;
	uresp->page_size = cq_sd_info->page_sz;

	map_size = uresp->page_size <= PAGE_SIZE ? PAGE_SIZE : uresp->page_size;
	nbl_pr_dbg("cq cqc_base_pa=0x%llx,shadow_base_addr=0x%llx,sys_page_offset=0x%llx\n",
		   cq_uk->cqc_base_pa, uresp->shadow_base_addr, uresp->sys_page_offset);
	cqc_shadow = nbl_find_shadow_mmap(uctx, uresp->shadow_base_addr, map_size);
	if (!cqc_shadow)
		return nbl_add_shadow_mmap(uctx, cq_uk->cqc_base_va,
					   uresp->shadow_base_addr, map_size);

	return 0;
}

static int nbl_create_cq_kernel_shadow(struct nbl_cq *cq,
				       struct nbl_hmc_obj_sd_info *cq_sd_info,
				       struct nbl_cq_init_info *info)
{
	u32 num_one_page; /* how many cqc in one page */
	u32 page_index; /* page index that cqc located */
	u32 cqc_index; /* cqc index in a page */
	struct nbl_hmc_obj_sd_addr *sd;

	num_one_page = cq_sd_info->page_sz / NBL_CQ_CTX_SIZE; /* 4K/64=64*/
	page_index = cq->cq_num / num_one_page;
	if (page_index >= cq_sd_info->cnt)
		return NBL_ERR_CFG;

	sd = &cq_sd_info->sd_addr[page_index];
	/* get cqc index */
	cqc_index = cq->cq_num % num_one_page;
	info->cq_uk_init_info.cqc_base_va = sd->va;
	info->cq_uk_init_info.cqc_base_pa = sd->dma_addr;
	info->cq_uk_init_info.shadow_area =
		sd->va + (cqc_index * NBL_CQ_CTX_SIZE) + NBL_CQ_SHADOW_OFFST;

	info->cqc_begin_pa = sd->dma_addr + (cqc_index * NBL_CQ_CTX_SIZE);
	info->shadow_area_pa =
		sd->dma_addr + (cqc_index * NBL_CQ_CTX_SIZE) + NBL_CQ_SHADOW_OFFST;

	cq->kmem_shadow.va = info->cq_uk_init_info.shadow_area;
	cq->kmem_shadow.pa = info->shadow_area_pa;

	nbl_ib_dbg(cq->sc_cq.dev, "[CQ create] shadow area get shadow base va:%p, area va: %p, pa %lld\n",
		info->cq_uk_init_info.cqc_base_va,
		info->cq_uk_init_info.shadow_area,
		info->shadow_area_pa);
	return 0;
}

/**
 * nbl_ib_create_cq - create cq
 * @ibcq: CQ allocated
 * @attr: attributes for cq
 * @udata: user data
 */

int nbl_ib_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr,
		     struct ib_udata *udata)
{
	struct nbl_ib_create_cq_resp resp = {};
	struct nbl_device *nbldev;
	struct nbl_pci_f *rf;
	struct nbl_cq *nblcq;
	u32 cq_num = 0;
	struct nbl_sc_cq *cq;
	struct nbl_sc_dev *dev;
	struct nbl_cq_init_info info = {};
	enum nbl_status_code status;
	struct nbl_cq_uk_init_info *ukinfo = &info.cq_uk_init_info;
	int err_code;
	int entries = attr->cqe;
	struct nbl_frag_buf *nblcq_buf;
	int err;
	int rsize;
	struct nbl_ucontext *uctx;

	nbldev = to_nbl_dev(ibcq->device);
	nblcq = to_nblcq(ibcq);
	uctx = rdma_udata_to_drv_context(udata, struct nbl_ucontext, ibucontext);

	rf = nbldev->rf;
	dev = &rf->sc_dev;
	nblcq_buf = &nblcq->buf.frag_buf;

	nbl_ib_dbg(dev, "[CQ] Create cq with: entries: %d, comp_vector: %d, uctx 0x%p\n",
		entries, attr->comp_vector, uctx);

	if (attr->comp_vector < rf->ceqs_count)
		info.ceq_id = attr->comp_vector;
	else {
		nbl_ib_err(dev, "CEQ id %d error, device ceq counts:%d\n",
			   attr->comp_vector, rf->ceqs_count);
		err_code = -ENOENT;
		goto cq_exit;
	}

	err_code = nbl_alloc_rsrc(&rf->rsrc_lock, rf->allocated_cqs, rf->max_cq, &cq_num,
				  &rf->next_cq);
	if (err_code) {
		nbl_ib_err(dev, "CQ id request error, device cq max:%d\n", rf->max_cq);
		goto cq_exit;
	}

	nbl_ib_dbg(dev, "[CQ] nbl_alloc_rsrc success, alloced cq_num :%u\n", cq_num);

	nblcq->cq_num = cq_num;
	cq = &nblcq->sc_cq;
	cq->bak_nbl_cq = nblcq;
	nblcq->ceq_suspend = false;
	refcount_set(&nblcq->refcnt, 1);
	spin_lock_init(&nblcq->lock);
	atomic_set(&nblcq->armed, 0);
	info.dev = dev;
	ukinfo->cq_size = max(entries, NBL_MIN_CQ_SIZE);
	ukinfo->cq_id = cq_num;

	nbl_ib_dbg(dev, "[CQ] create cq with cq_size :%u, cq_id:%u",
		ukinfo->cq_size, ukinfo->cq_id);

	if (udata) {
		nblcq->ibcq.cqe = ukinfo->cq_size - 1;
		nblcq->user_mode = true;
		err = nbl_create_cq_user(nbldev, udata, nblcq, &uctx->ibucontext);
		if (err) {
			nbl_ib_err(dev, "create user mode cq err(%d)\n", err);
			err_code = -ENOMEM;
			goto cq_free_rsrc;
		}
	} else {
		/* Kmode allocations */
		entries += 1; /* one more for full situation */
		if (entries < NBL_MIN_CQ_SIZE)
			entries = NBL_MIN_CQ_SIZE;
		ukinfo->cq_size = roundup_pow_of_two(entries);
		if (ukinfo->cq_size > rf->max_cqe) {
			nbl_ib_err(dev, "create kernel mode cq with cqe num err(request %u, max %u)\n",
				entries, rf->max_cqe);
			err_code = -EINVAL;
			goto cq_free_rsrc;
		}
		nblcq->ibcq.cqe = ukinfo->cq_size - 1;

		rsize = ukinfo->cq_size * sizeof(struct nbl_cqe);
		status = nbl_create_cq_kernel(dev, nblcq, rsize, nblcq_buf);
		if (status) {
			nbl_ib_err(dev, "create kernel mode cq failed(%d).\n", status);
			err_code = -ENOMEM;
			goto cq_free_rsrc;
		}
	}

	/* shadow used by kernel*/
	status = nbl_create_cq_kernel_shadow(nblcq, rf->cq_sd_info, &info);
	if (status) {
		nbl_ib_err(dev, "create cq kernel shadow error(%d)\n", status);
		err_code = -EFAULT;
		goto cq_free_buf;
	}

	ukinfo->cq_base = nblcq->kmem.va;
	info.cq_base_pa = nblcq->kmem.pa;
	if (ukinfo->cq_size <= NBL_CQ_SHADOW_TH_BOUNDARY)
		info.shadow_read_threshold = NBL_CQ_SHADOW_TH_LOW;
	else
		info.shadow_read_threshold = ukinfo->cq_size / NBL_CQ_SHADOW_TH_GAP;
	info.pa_continuous = nblcq->pa_continuous;
	info.cq_pg_num = nblcq->cq_pg_num;

	if (nbl_sc_cq_init(cq, &info)) {
		nbl_ib_err(dev, "nbl_sc_cq_init failed.\n");
		err_code = -EPROTO;
		goto cq_free_buf;
	}

	/* collect shadow infos for userspace*/
	if (udata) {
		status = nbl_cq_user_shadow_init(cq, rf, uctx, &resp);
		if (status) {
			nbl_ib_err(dev, "user mode cq shadow init err(%d)\n", status);
			err_code = -EFAULT;
			goto cq_free_buf;
		}
	}

	status = nbl_cqp_cq_create_cmd(rf, cq);
	if (status) {
		nbl_ib_err(dev, "[CQ_CREATE] Create CQ CQP execute failed(%d).\n", status);
		err_code = -ENOMEM;
		goto cq_free_buf;
	}

	INIT_LIST_HEAD(&nblcq->wc_list);
	INIT_LIST_HEAD(&nblcq->pre_list);
	nblcq->pre_num = 0;

	if (udata) {
		resp.cq_id = info.cq_uk_init_info.cq_id;
		resp.cq_size = info.cq_uk_init_info.cq_size;
		if (ib_copy_to_udata(udata, &resp,
				     min(sizeof(resp), udata->outlen))) {
			nbl_ib_err(dev, "ib_copy_to_udata failed.\n");
			err_code = -EPROTO;
			goto cq_destroy;
		}
	}

	rf->cq_table[cq_num] = nblcq;
	init_completion(&nblcq->free_cq);

	nbl_ib_dbg(dev, "[CQ Create]shadow infos: shadow_base_addr:0x%llx, cqc_size:%d,shadow_offset:%d, shadow_size:%d, page_size:%d",
		resp.shadow_base_addr, resp.cqc_size, resp.shadow_offset,
		resp.shadow_size, resp.page_size);
	nbl_ib_dbg(dev, "[CQ Create]Create CQ SUCCESS with resp cq_id:%u, cq_size:%u\n",
		resp.cq_id, resp.cq_size);

	return 0;

cq_destroy:
	nbl_cqp_cq_destroy_cmd(rf, cq);
cq_free_buf:
	if (udata)
		destroy_cq_user(dev, nblcq);
	else
		destroy_cq_kernel(dev, nblcq);
cq_free_rsrc:
	nbl_cq_free_rsrc(rf, nblcq);
cq_exit:
	return err_code;
}

/**
 * get_sqinfo_jump_nop - check current sq ci wqe(jump nop) and get info, then move sq ci
 * @ukqp: uk qp
 * @info: information structure to hold info
 */
static int get_sqinfo_jump_nop(struct nbl_uk_qp *ukqp, struct nbl_cq_poll_info *info)
{
	u8 op_type;
	u32 tail;
	struct nbl_wqe_ctrl_seg *ctrl;
	struct nbl_qp *qp = ukqp->back_qp;

	do {
		tail = ukqp->sq_ring.tail;
		ctrl = nbl_get_wqe(ukqp->sq_base, &(qp->sc_qp.sqbuf.frag_buf),
					sizeof(struct nbl_qp_block), tail, !qp->sc_qp.sq_pm);
		if (!ctrl)
			return -EFAULT;

		op_type = ctrl->opcode;
		NBL_RING_SET_TAIL(ukqp->sq_ring,
				  tail + ukqp->sq_wrtrk_array[tail].quanta);
		if (op_type != NBL_OPCODE_NOP) {
			info->op_type = op_type;
			info->wr_id = ukqp->sq_wrtrk_array[tail].wrid;
			info->bytes_xfered = ukqp->sq_wrtrk_array[tail].wr_len;

			break;
		}
	} while (1);

	return 0;
}

static int nbl_poll_soft_wc(struct nbl_cq *nblcq, struct nbl_cq_poll_info *info)
{
	struct nbl_ib_wc *soft_wc;

	soft_wc = list_first_entry_or_null(&nblcq->wc_list,
				struct nbl_ib_wc, list);
	if (unlikely(soft_wc)) {
		memcpy(info, &soft_wc->info, sizeof(struct nbl_cq_poll_info));
		list_del(&soft_wc->list);
		kfree(soft_wc);
		nbl_pr_dbg("qp 0x%x swcqe, merr 0x%x, err 0x%x, wrid 0x%llx\n",
			info->qpn, info->major_err, info->error, info->wr_id);
		return NBL_SUCCESS;
	}
	return NBL_ERR_Q_EMPTY;
}

static bool nbl_is_tx_errcqe(u16 errcode)
{
	if (NBL_ERR_IS_TXP_ERRCQE(errcode))
		return true;
	if (NBL_ERR_IS_TXMR_ERRCQE(errcode))
		return true;

	return false;
}

/**
 * nbl_uk_cq_poll_cmpl - get cq completion info
 * @cq: hw cq
 * @info: cq poll information returned
 */
static enum nbl_status_code nbl_uk_cq_poll_cmpl(struct nbl_cq_uk *cq,
					struct nbl_uk_qp **cur_ukqp,
					struct nbl_cq_poll_info *info)
{
	enum nbl_status_code ret_code = NBL_SUCCESS;
	__be64 *cqe;
	struct nbl_qp *nblqp;
	struct nbl_uk_qp *qp;
	struct nbl_ring *pring = NULL;
	u64 comp_ctx, qword0, qword2, qword3, qword4;
	u8 polarity;
	u8 cq_ci_phase;
	u32 wqe_idx, q_type;
	u32 qp_num;
	int cqe_idx;
	struct nbl_sc_cq *sc_cq = cq->bak_sc_cq;
	struct nbl_cq *nblcq = sc_cq->bak_nbl_cq;
	struct nbl_device *nbldev = to_nbl_dev(nblcq->ibcq.device);
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_frag_buf *nblcq_buf = &nblcq->buf.frag_buf;
	bool move_cq_head = true;
	bool repoll_cq = false;

repoll:
	cqe_idx = NBL_RING_CURRENT_HEAD(cq->cq_ring);
	cqe = nbl_get_wqe(cq->cq_base, nblcq_buf,
			sizeof(struct nbl_cqe), cqe_idx, nblcq->pa_continuous);
	if (!cqe)
		return NBL_ERR_Q_EMPTY;

	get_64bit_val(cqe, 0, &qword0);
	polarity = (u8)FIELD_GET(NBL_CQ_VALID, qword0);
	if (polarity != cq->polarity)
		return NBL_ERR_Q_EMPTY;

	/* Ensure CQE contents are read after valid bit is checked */
	dma_rmb();

	get_64bit_val(cqe, 24, &qword3);
	info->error = (bool)FIELD_GET(NBL_CQ_ERROR, qword0);
	if (info->error) {
		info->major_err = FIELD_GET(NBL_CQ_MAJOR_ERROR, qword3);
		if (info->major_err == NBL_ERR_SQ_FLUSH_COMPLETE ||
			info->major_err == NBL_ERR_RQ_FLUSH_COMPLETE)
			info->comp_status = NBL_COMPL_STATUS_FLUSHED;
		else {
			info->comp_status = NBL_COMPL_STATUS_UNKNOWN;
			print_hex_dump_debug("Error CQE ", 0, 16, 1,
				(u64 *)cqe, 64, false);
			pr_debug("\n\n");
		}
	} else
		info->comp_status = NBL_COMPL_STATUS_SUCCESS;

	info->imm_valid = (bool)FIELD_GET(NBL_CQ_IMMVALID, qword0);
	if (info->imm_valid)
		info->imm_data = (u32)FIELD_GET(NBL_CQ_IMMDATA, qword3);

	info->ud_smac_valid = (bool)FIELD_GET(NBL_CQ_UDVALID, qword0);
	info->ud_vlan_valid = (bool)FIELD_GET(NBL_CQ_UDVLANVALID, qword0);

	get_64bit_val(cqe, 32, &qword4);
	if (info->ud_vlan_valid)
		info->ud_vlan = (u16)FIELD_GET(NBL_CQ_UDVLAN, qword4);
	info->ud_smac[5] = qword4 & 0xFF;
	info->ud_smac[4] = (qword4 >> 8) & 0xFF;
	info->ud_smac[3] = (qword4 >> 16) & 0xFF;
	info->ud_smac[2] = (qword4 >> 24) & 0xFF;
	info->ud_smac[1] = (qword4 >> 32) & 0xFF;
	info->ud_smac[0] = (qword4 >> 40) & 0xFF;

	q_type = (u8)FIELD_GET(NBL_CQ_SQ, qword0);
	info->ipv4 = (bool)FIELD_GET(NBL_CQ_IPV4, qword0);

	get_64bit_val(cqe, 16, &qword2);
	info->qpn = (u32)FIELD_GET(NBL_CQ_QPN, qword2);
	info->ud_src_qpn = (u32)FIELD_GET(NBL_CQ_UDSRCQPN, qword2);

	info->solicited_event = (bool)FIELD_GET(NBL_CQ_SOEVENT, qword0);

	get_64bit_val(cqe, 8, &comp_ctx);
	if (comp_ctx & NBL_CQ_CTX_INVALID) {
		ret_code = NBL_ERR_Q_DESTROYED;
		goto exit;
	}
	qp_num = (u32)FIELD_GET(NBL_CQ_CTX_QPN, comp_ctx);
	if (!*cur_ukqp || (qp_num != (*cur_ukqp)->qpn)) {
		nblqp = rf->qp_table[qp_num];
		if (!nblqp)
			*cur_ukqp = NULL;
		else
			*cur_ukqp = &nblqp->sc_qp.uk_qp;
	}
	qp = *cur_ukqp;
	if (!qp || qp->destroy_pending) {
		ret_code = NBL_ERR_Q_DESTROYED;
		goto exit;
	}

	wqe_idx = (u32)FIELD_GET(NBL_CQ_WQEIDX, qword3);
	info->qp_handle = (nbl_qp_handle)(unsigned long)qp;
	if (q_type == NBL_CQE_QTYPE_RQ) {
		/* if qp queue is empty, there must be somethins wrong,
		 * No need to do next work, just move cq ci
		 */
		if (!NBL_RING_MORE_WORK(qp->rq_ring)) {
			if (info->comp_status == NBL_COMPL_STATUS_FLUSHED) {
				/*
				 * maybe all wqe cqe is polled, then flush cqe come,
				 * here we set figures for sw cqe list use.
				 */
				qp->rq_flush_seen = true;
				qp->rq_flush_complete = true;
			}
			ret_code = NBL_ERR_Q_EMPTY;
			goto exit;
		}

		if (info->comp_status == NBL_COMPL_STATUS_FLUSHED)
			wqe_idx = qp->rq_ring.tail;

		info->wr_id = qp->rq_wrid_array[wqe_idx];
		info->bytes_xfered = (u32)FIELD_GET(NBL_CQ_PAYLDLEN, qword0);

		if (info->imm_valid)
			info->op_type = NBL_OPCODE_RECV_IMM;
		else
			info->op_type = NBL_OPCODE_RECV;

		if (qword0 & NBL_CQ_MKEY_VALID) {
			info->mkey_valid = true;
			info->invalidated_mkey =
				(u32)FIELD_GET(NBL_CQ_INVMKEY, qword3);
		} else {
			info->mkey_valid = false;
		}

		/* move rq ci */
		NBL_RING_SET_TAIL(qp->rq_ring, wqe_idx + qp->rq_wqe_size_multiplier);

		if (info->comp_status == NBL_COMPL_STATUS_FLUSHED) {
			qp->rq_flush_seen = true;
			if (!NBL_RING_MORE_WORK(qp->rq_ring))
				qp->rq_flush_complete = true;
			else
				move_cq_head = false;
		}
		pring = &qp->rq_ring;
	} else { /*q_type is NBL_CQE_QTYPE_SQ*/
		/* if qp queue is empty, there must be somethins wrong,
		 * No need to do next work, just move cq ci
		 */
		if (!NBL_RING_MORE_WORK(qp->sq_ring)) {
			if (info->comp_status == NBL_COMPL_STATUS_FLUSHED) {
				/*
				 * maybe all wqe cqe is polled, then flush cqe come,
				 * here we set figures for sw cqe list use.
				 */
				qp->sq_flush_seen = true;
				qp->sq_flush_complete = true;
			}
			ret_code = NBL_ERR_Q_EMPTY;
			goto exit;
		}

		if (info->comp_status != NBL_COMPL_STATUS_FLUSHED) {
			if (nbl_is_tx_errcqe(info->major_err)) {
				NBL_RING_SET_TAIL(qp->sq_ring, wqe_idx);
				if (get_sqinfo_jump_nop(qp, info) != 0) {
					/* Something Fatal, No need do next work, just move cq ci */
					ret_code = NBL_ERR_Q_EMPTY;
					goto exit;
				}
			} else {
				info->wr_id = qp->sq_wrtrk_array[wqe_idx].wrid;
				if (!info->comp_status)
					info->bytes_xfered =
						qp->sq_wrtrk_array[wqe_idx].wr_len;
				info->op_type = (u8)FIELD_GET(NBL_CQ_OP, qword0);

				if (qp->sq_wrtrk_array[wqe_idx].driver_ce) {
					qp->sq_wrtrk_array[wqe_idx].driver_ce = 0;
					nbl_pr_dbg("qp:%d poll driver cqe:%d\n", qp->qpn, wqe_idx);
					repoll_cq = true;
				}

				/* move sq ci */
				NBL_RING_SET_TAIL(
					qp->sq_ring,
					wqe_idx + qp->sq_wrtrk_array[wqe_idx].quanta);
			}
		} else {
			/*flush sq. Return the wr_id, from which wqes be flushed by hw.*/
			if (get_sqinfo_jump_nop(qp, info) != 0) {
				/* Something Fatal, No need do next work, just move cq ci */
				ret_code = NBL_ERR_Q_EMPTY;
				goto exit;
			}

			qp->sq_flush_seen = true;
			if (!NBL_RING_MORE_WORK(qp->sq_ring))
				qp->sq_flush_complete = true;
			else
				move_cq_head = false;
		}

		pring = &qp->sq_ring;
	}

	ret_code = 0;
exit:
	/*
	 * if flushed by hw
	 * (1) hw will generate only one cqe
	 * (2) after sw polled the only cqe, rewrite the wr_id by sq/rq tail element
	 * (3) when poll the next cqe, use the same cqe, only wr_id is different
	 */
	if (!ret_code && info->comp_status == NBL_COMPL_STATUS_FLUSHED) {
		if (pring && NBL_RING_MORE_WORK(*pring))
			move_cq_head = false;
	}

	if (move_cq_head) {
		NBL_RING_MOVE_HEAD_NOCHECK(cq->cq_ring);
		if (!NBL_RING_CURRENT_HEAD(cq->cq_ring))
			cq->polarity ^= 1;

		/* update shadow area cq ci */
		cq_ci_phase = (cq->polarity ^ 1); /* ci phase and polarity is reverse  */
		set_32bit_val((__be32 *)cq->shadow_area, 12,
			FIELD_PREP(NBL_CQ_SHADOWAREA_CI_PHASE, cq_ci_phase) |
			FIELD_PREP(NBL_CQ_SHADOWAREA_CI, NBL_RING_CURRENT_HEAD(cq->cq_ring)));
	} else {
		/* rewrite the cqe_wqeidx by sq/rq tail, which will be used by next poll*/
		qword3 &= ~NBL_CQ_WQEIDX;
		qword3 |= FIELD_PREP(NBL_CQ_WQEIDX, pring->tail);
		set_64bit_val(cqe, 24, qword3);
	}

	if (repoll_cq) {
		repoll_cq = false;
		goto repoll;
	}

	return ret_code;
}

static void nbl_hw_err_to_ib_wc_status(u16 hw_error_code, struct ib_wc *wc)
{
	switch (hw_error_code) {
	case NBL_ERR_RX_PKT_REQ_PKT_LEN_ERR:
	case NBL_ERR_RX_UD_RQE_ERR:
		wc->status = IB_WC_LOC_LEN_ERR;
		break;
	case NBL_ERR_RX_PKT_READ_RESP_PKT_LEN_OVERFLOW:
	case NBL_ERR_RX_PKT_READ_RESP_PKT_LEN_ILLEGAL:
	case NBL_ERR_RX_PKT_READ_RESP_PKT_LEN_TOOLONG:
	case NBL_ERR_RX_PKT_READ_RESP_OPCODE_OUT_ORDER:
	case NBL_ERR_RX_RESP_RECV_NOT_PSN_SEQ_ERR_NAK:
	case NBL_ERR_NAK_NOT_PSN_ERR4:
		wc->status = IB_WC_BAD_RESP_ERR;
		break;
	case NBL_ERR_RNR_RETRY:
		wc->status = IB_WC_RNR_RETRY_EXC_ERR;
		break;
	case NBL_ERR_NAK_NOT_PSN_ERR2:
	case NBL_ERR_RX_MR_INDEX_ILLEGAL:
	case NBL_ERR_RX_MR_KEY_ILLEGAL:
	case NBL_ERR_RX_PD_MISS_MATCH:
	case NBL_ERR_RX_REMOTE_INV_PERMISSION_CHK_ERR:
		wc->status = IB_WC_REM_ACCESS_ERR;
		break;
	case NBL_ERR_NAK_NOT_PSN_ERR3:
		wc->status = IB_WC_REM_OP_ERR;
		break;
	case NBL_ERR_SQ_FLUSH_COMPLETE:
	case NBL_ERR_RQ_FLUSH_COMPLETE:
		wc->status = IB_WC_WR_FLUSH_ERR;
		break;
	case NBL_ERR_SQ_INVALID_OPCODE:
		wc->status = IB_WC_LOC_QP_OP_ERR;
		break;
	case NBL_ERR_SQ_PSN_ERR_RETRY:
	case NBL_ERR_SQ_RTO_RETRY:
		wc->status = IB_WC_RETRY_EXC_ERR;
		break;
	case NBL_ERR_RX_MR_INVALID:
	case NBL_ERR_RX_ACCESS_RIGHT_CHECK_ERR:
	case NBL_ERR_RX_BOUNDARY_CHECK_ERR:
	case NBL_ERR_TXMR_INDEX_ERR:
	case NBL_ERR_TX_MR_INVALID:
	case NBL_ERR_TX_MR_KEY_ILLEGAL:
	case NBL_ERR_TX_PD_MISS_MATCH:
	case NBL_ERR_TX_ACCESS_RIGHT_CHECK_ERR:
	case NBL_ERR_TX_BOUNDARY_CHECK_ERR:
		wc->status = IB_WC_LOC_PROT_ERR;
		break;
	case NBL_ERR_NAK_NOT_PSN_ERR1:
		wc->status = IB_WC_REM_INV_REQ_ERR;
		break;
	default:
		wc->status = IB_WC_GENERAL_ERR;
		break;
	}
}

/**
 * nbl_process_cqe - process cqe info
 * @entry: processed cqe
 * @cq_poll_info: cqe info
 */
static void nbl_process_cqe(struct ib_wc *entry,
			    struct nbl_cq_poll_info *cq_poll_info)
{
	struct nbl_qp *qp;
	struct nbl_uk_qp *ukqp;
	u16 vlan;

	ukqp = (struct nbl_uk_qp *)cq_poll_info->qp_handle;
	qp = ukqp->back_qp;

	entry->wc_flags = 0;
	entry->pkey_index = 0;
	entry->wr_id = cq_poll_info->wr_id;
	entry->qp = &qp->ibqp;

	if (cq_poll_info->error) {
		nbl_hw_err_to_ib_wc_status(cq_poll_info->major_err, entry);
		entry->vendor_err = cq_poll_info->major_err;

		if (cq_poll_info->major_err == NBL_ERR_SQ_FLUSH_COMPLETE &&
			qp->first_4a == false) {
			nbl_pr_dbg("qp 0x%x first 4a com\n", ukqp->qpn);
			qp->first_4a = true;
		}
		if (cq_poll_info->major_err == NBL_ERR_RQ_FLUSH_COMPLETE &&
			qp->first_4b == false) {
			nbl_pr_dbg("qp 0x%x first 4b com\n", ukqp->qpn);
			qp->first_4b = true;
		}
	} else {
		entry->status = IB_WC_SUCCESS;

		if (cq_poll_info->imm_valid) {
			entry->ex.imm_data = htonl(cq_poll_info->imm_data);
			entry->wc_flags |= IB_WC_WITH_IMM;
		}

		ether_addr_copy(entry->smac, cq_poll_info->ud_smac);
		if (cq_poll_info->ud_smac_valid)
			entry->wc_flags |= IB_WC_WITH_SMAC;

		if (cq_poll_info->ud_vlan_valid) {
			vlan = cq_poll_info->ud_vlan & VLAN_VID_MASK;

			entry->sl = cq_poll_info->ud_vlan >> VLAN_PRIO_SHIFT;
			if (vlan) {
				entry->vlan_id = vlan;
				entry->wc_flags |= IB_WC_WITH_VLAN;
			}
		} else
			entry->sl = 0;
	}

	switch (cq_poll_info->op_type) {
	case NBL_OPCODE_SEND:
	case NBL_OPCODE_SEND_WITH_IMM:
	case NBL_OPCODE_SEND_WITH_INV:
		entry->opcode = IB_WC_SEND;
		break;
	case NBL_OPCODE_READ:
		entry->opcode = IB_WC_RDMA_READ;
		break;
	case NBL_OPCODE_WRITE:
	case NBL_OPCODE_WRITE_WITH_IMM:
		entry->opcode = IB_WC_RDMA_WRITE;
		break;
	case NBL_OPCODE_ATOMIC_CMP_AND_SWP:
		entry->opcode = IB_WC_COMP_SWAP;
		break;
	case NBL_OPCODE_ATOMIC_FETCH_AND_ADD:
		entry->opcode = IB_WC_FETCH_ADD;
		break;
	case NBL_OPCODE_BIND_MW:
		entry->opcode = IB_WC_BIND_MW;
		break;
	case NBL_OPCODE_LOCAL_INV:
		entry->opcode = IB_WC_LOCAL_INV;
		break;
	case NBL_OPCODE_FAST_MR:
		entry->opcode = IB_WC_REG_MR;
		break;
	case NBL_OPCODE_RECV:
		entry->opcode = IB_WC_RECV;
		if (ukqp->qp_type == IB_QPT_RC && cq_poll_info->mkey_valid) {
			entry->ex.invalidate_rkey = cq_poll_info->invalidated_mkey;
			entry->wc_flags |= IB_WC_WITH_INVALIDATE;
		}
		break;
	case NBL_OPCODE_RECV_IMM:
		entry->opcode = IB_WC_RECV;
		entry->wc_flags |= IB_WC_WITH_IMM;
		if (ukqp->qp_type == IB_QPT_RC && cq_poll_info->mkey_valid) {
			entry->ex.invalidate_rkey = cq_poll_info->invalidated_mkey;
			entry->wc_flags |= IB_WC_WITH_INVALIDATE;
		}
		break;
	default:
		nbl_ib_err(qp->sc_qp.dev, "Invalid opcode = %d in CQE\n",
			   cq_poll_info->op_type);
		entry->status = IB_WC_GENERAL_ERR;
		return;
	}

	if (ukqp->qp_type == IB_QPT_UD || ukqp->qp_type == IB_QPT_GSI) {
		entry->src_qp = cq_poll_info->ud_src_qpn;
		entry->slid = 0;
		entry->network_hdr_type = cq_poll_info->ipv4 ?
							RDMA_NETWORK_IPV4 : RDMA_NETWORK_IPV6;
		entry->wc_flags |= (IB_WC_GRH | IB_WC_WITH_NETWORK_HDR_TYPE);
	} else {
		entry->src_qp = cq_poll_info->qpn;
	}
	entry->byte_len = cq_poll_info->bytes_xfered;
}

/**
 * nbl_poll_one - poll one entry of the CQ
 * @ukcq: ukcq to poll
 * @cur_cqe: current CQE info to be filled in
 * @entry: ibv_wc object to be filled for non-extended CQ or NULL for extended CQ
 *
 * Returns the internal rdma device error code or 0 on success
 */
static inline int nbl_poll_one(struct nbl_cq_uk *ukcq,
			       struct nbl_uk_qp **cur_ukqp,
				   struct nbl_cq_poll_info *cur_cqe,
			       struct ib_wc *entry)
{
	int ret = nbl_uk_cq_poll_cmpl(ukcq, cur_ukqp, cur_cqe);

	if (ret)
		return ret;

	nbl_process_cqe(entry, cur_cqe);

	return 0;
}

/**
 * __nbl_poll_cq - poll cq for completion (kernel apps)
 * @nblcq: cq to poll
 * @num_entries: number of entries to poll
 * @entry: wr of a completed entry
 */
static int __nbl_poll_cq(struct nbl_cq *nblcq, int num_entries,
			 struct ib_wc *entry)
{
	int npolled = 0;
	enum nbl_status_code ret;
	struct nbl_cq_uk *ukcq;
	struct nbl_cq_poll_info *cur_cqe;
	struct nbl_uk_qp *cur_ukqp = NULL;

	ukcq = &nblcq->sc_cq.cq_uk;
	cur_cqe = &nblcq->cur_cqe;

	/* check the current CQ for new cqes */
	while (npolled < num_entries) {
		ret = nbl_poll_one(ukcq, &cur_ukqp, cur_cqe, entry + npolled);
		if (ret == NBL_ERR_Q_EMPTY) {
			ret = nbl_poll_soft_wc(nblcq, cur_cqe);
			if (!ret)
				nbl_process_cqe(entry + npolled, cur_cqe);
		}
		if (!ret) {
			++npolled;
			continue;
		}

		if (ret == NBL_ERR_Q_EMPTY)
			break;

		/* QP using the CQ is destroyed. Skip reporting this CQE */
		if (ret == NBL_ERR_Q_DESTROYED)
			continue;

		goto error;
	}

	return npolled;
error:
	nbl_ib_err(nblcq->sc_cq.dev, "%s: ERROR polling CQ, err: %d\n",
		   __func__, ret);
	return -EINVAL;
}

/**
 * nbl_ib_poll_cq - poll cq for completion
 * @ibcq: cq to poll
 * @num_entries: number of entries to poll
 * @entry: wr of a completed entry
 */
int nbl_ib_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *entry)
{
	struct nbl_cq *nblcq;
	unsigned long flags;
	int ret;

	nblcq = to_nblcq(ibcq);

	spin_lock_irqsave(&nblcq->lock, flags);
	ret = __nbl_poll_cq(nblcq, num_entries, entry);
	spin_unlock_irqrestore(&nblcq->lock, flags);

	return ret;
}

static bool nbl_cq_empty(struct nbl_cq *nblcq)
{
	struct nbl_cq_uk *cq = &nblcq->sc_cq.cq_uk;
	struct nbl_frag_buf *nblcq_buf = &nblcq->buf.frag_buf;
	int cqe_idx;
	__be64 *cqe;
	u64 qword0;
	u8 polarity;

	cqe_idx = NBL_RING_CURRENT_HEAD(cq->cq_ring);
	cqe = nbl_get_wqe(cq->cq_base, nblcq_buf,
			sizeof(struct nbl_cqe), cqe_idx, nblcq->pa_continuous);
	if (!cqe)
		return true;

	get_64bit_val(cqe, 0, &qword0);
	polarity = (u8)FIELD_GET(NBL_CQ_VALID, qword0);

	return polarity != cq->polarity;
}

static void nbl_cq_get_ci_from_shadow(struct nbl_cq_uk *cq, u32 *ci, u8 *ci_phase)
{
	u64 shadow_val;

	get_64bit_val(cq->shadow_area, 8, &shadow_val);
	*ci = (u32)FIELD_GET(NBL_CQ_SHADOWAREA_CI, shadow_val);
	*ci_phase = (u8)FIELD_GET(NBL_CQ_SHADOWAREA_CI_PHASE, shadow_val);

	nbl_pr_dbg("get ci from shadow: ci %u, phase %u\n", *ci, *ci_phase);
}

/**
 * nbl_cq_request_notification - cq notification request (arm cqp)
 * @rf: RDMA PCI function
 * @cq: hw cq
 * @cq_notify: notification type
 */
static void nbl_cq_request_notification(struct nbl_pci_f *rf, struct nbl_cq *nblcq,
		      enum nbl_cmpl_notify cq_notify)
{
	u8 cq_ci_phase;
	u32 cq_ci;
	u64 value_arm;
	u32 cq_id;
	struct nbl_cq_uk *ukcq = &nblcq->sc_cq.cq_uk;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;

	/* update used, arm cnt */
	atomic_inc(&rf->armc.used);
	rf->armc.arm_cnt++;

	if (rf->sc_dev.has_high_temp_alarm)
		return;

	cq_id = ukcq->cq_id;
	if (nblcq->user_mode) {
		/* user mode ci is user mode, so we can only get ci from shadow */
		nbl_cq_get_ci_from_shadow(ukcq, &cq_ci, &cq_ci_phase);
	} else {
		cq_ci_phase = ukcq->polarity;
		cq_ci = NBL_RING_CURRENT_HEAD(ukcq->cq_ring);
	}

	value_arm = (FIELD_PREP(NBL_REG_ARM_CQ_REG1_ARM_NEXT_SE,
					(cq_notify == NBL_CQ_COMPL_SOLICITED ? 0 : 1)) |
					FIELD_PREP(NBL_REG_ARM_CQ_REG1_ARM_CQN, cq_id) |
					FIELD_PREP(NBL_REG_ARM_CQ_REG0_ARM_CQ_CI_PHASE,
						cq_ci_phase) |
					FIELD_PREP(NBL_REG_ARM_CQ_REG0_ARM_CQ_CI, cq_ci));
	write64_reg(value_arm, sc_dev->hw_regs[NBL_ARM_CQ]);
}

static inline u32 nbl_get_arm_fifo_cnt(struct nbl_pci_f *rf)
{
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	u32 arm0_val;
	u32 fifo_cnt;

	read32_reg(&arm0_val, sc_dev->hw_regs[NBL_ARM_CQ]);
	fifo_cnt = (u32)FIELD_GET(NBL_REG_ARM_CQ_REG0_FIFO_CNT, arm0_val);
	if (fifo_cnt > 0) {
		rf->armc.fifo_nz++;
		if (fifo_cnt > NBL_CQ_ARM_FIFO_QUARTER)
			rf->armc.fifo_quarter++;
	}
	rf->armc.fifo_rdcnt++;

	return fifo_cnt;
}

static bool nbl_cq_arm_is_ready(struct nbl_pci_f *rf)
{
	u32 fcnt;
	int arm_used;

	arm_used = atomic_read(&rf->armc.used);
	if (rf->armc.arm_cnt > NBL_ARM_RD_FIFO_PERIOD ||
		arm_used >= rf->armc.free || rf->armc.limit_reached) {
		fcnt = nbl_get_arm_fifo_cnt(rf);
		if (fcnt >= NBL_CQ_ARM_FIFO_THRESHOLD) {
			/* once limit reach, next time we need check fifo again,
			 * so here use limit reached to record thie event.
			 */
			rf->armc.limit_reached = true;
			return false;
		}

		/* reset free, used, arm cnt, limit reach */
		rf->armc.free = NBL_ARM_FREE_LIMIT(fcnt);
		atomic_set(&rf->armc.used, 0);
		rf->armc.arm_cnt = 0;
		rf->armc.limit_reached = false;
	}

	nbl_pr_dbg("arm used val 0x%x, arm free 0x%x\n", arm_used, rf->armc.free);

	return true;
}

int nbl_arm_control_init(struct nbl_pci_f *rf)
{
	u32 fcnt;

	rf->armc.fifo_rdcnt = 0;
	rf->armc.fifo_nz = 0;
	rf->armc.fifo_quarter = 0;

	fcnt = nbl_get_arm_fifo_cnt(rf);
	if (fcnt >= NBL_CQ_ARM_FIFO_THRESHOLD)
		return -EIO;

	rf->armc.free = NBL_ARM_FREE_LIMIT(fcnt);
	atomic_set(&rf->armc.used, 0);
	rf->armc.arm_cnt = 0;
	rf->armc.limit_reached = false;

	return 0;
}

/**
 * nbl_ib_req_notify_cq - arm cq kernel application
 * @ibcq: ib cq to arm
 * @notify_flags: notification flags
 */
int nbl_ib_req_notify_cq(struct ib_cq *ibcq,
			 enum ib_cq_notify_flags notify_flags)
{
	struct nbl_cq *nblcq;
	struct nbl_cq_uk *ukcq;
	unsigned long flags;
	unsigned long flags_cq;
	bool do_arm = false;
	enum nbl_cmpl_notify cq_notify = NBL_CQ_COMPL_EVENT;
	struct nbl_device *nbldev = to_nbl_dev(ibcq->device);
	struct nbl_pci_f *rf = nbldev->rf;
	int ret = 0;

	nblcq = to_nblcq(ibcq);
	ukcq = &nblcq->sc_cq.cq_uk;

	spin_lock_irqsave(&rf->cq_arm_lock, flags);

	if (!nbl_cq_arm_is_ready(rf)) /* hw arm busy */
		ret = EAGAIN;
	else {
		if (nblcq->user_mode) {
			/* user mode, we already lock cq in user mode code,
			 * so here is no need to lock again.
			 */
			if (notify_flags == IB_CQ_SOLICITED)
				cq_notify = NBL_CQ_COMPL_SOLICITED;
			nbl_cq_request_notification(rf, nblcq, cq_notify);
		} else {
			spin_lock_irqsave(&nblcq->lock, flags_cq);
			if (notify_flags == IB_CQ_SOLICITED)
				cq_notify = NBL_CQ_COMPL_SOLICITED;
			else {
				if (nblcq->last_notify == NBL_CQ_COMPL_SOLICITED)
					do_arm = true;
			}
			if (!atomic_cmpxchg(&nblcq->armed, 0, 1) || do_arm) {
				nblcq->last_notify = cq_notify;
				nbl_cq_request_notification(rf, nblcq, cq_notify);
			}

			/* report missed events figure means if not empty,
			 * we should return > 0 for caller to do next work.
			 */
			if ((notify_flags & IB_CQ_REPORT_MISSED_EVENTS) &&
				(!nbl_cq_empty(nblcq) || !list_empty(&nblcq->wc_list)))
				ret = EPERM;

			spin_unlock_irqrestore(&nblcq->lock, flags_cq);
		}
	}

	spin_unlock_irqrestore(&rf->cq_arm_lock, flags);

	return ret;
}

/**
 * nbl_cqp_cq_cqc_ref_sub - SUB cqc reference.
 * @rf: RDMA PCI function
 * @sc_cq: source control cq
 * Return: return 0 if the cqp cmd exec success, otherwise return error.
 */
static int nbl_cqp_cq_cqc_ref_sub(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq)
{
	int ret;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;
	u32 cq_id = sc_cq->cq_uk.cq_id;

	in = kzalloc(in_size, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	set_64bit_val(in, 0,
		      FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_MODIFY_CQ) |
			      FIELD_PREP(NBL_CQPSQ_CQ_STAT, NBL_CQ_STAT_VALID) |
			      FIELD_PREP(NBL_CQPSQ_CQ_QP_REF,
					 NBL_CQ_CQC_REF_SUB) |
			      FIELD_PREP(NBL_CQPSQ_CQ_CQID, cq_id));

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);

	kfree(in);

	return ret;
}

/**
 * nbl_cqp_cq_cqc_ref_add - ADD cqc reference.
 * @rf: RDMA PCI function
 * @sc_cq: source control cq
 * Return: return 0 if the cqp cmd exec success, otherwise return error.
 */
static int nbl_cqp_cq_cqc_ref_add(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq)
{
	int ret;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;
	u32 cq_id = sc_cq->cq_uk.cq_id;

	in = kzalloc(in_size, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	set_64bit_val(in, 0,
		      FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_MODIFY_CQ) |
			      FIELD_PREP(NBL_CQPSQ_CQ_STAT, NBL_CQ_STAT_VALID) |
			      FIELD_PREP(NBL_CQPSQ_CQ_QP_REF,
					 NBL_CQ_CQC_REF_ADD) |
			      FIELD_PREP(NBL_CQPSQ_CQ_CQID, cq_id));

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);

	kfree(in);

	return ret;
}

/**
 * nbl_add_cqc_ref - add reference of cqc by cqp cmd
 * @cq: rdma cq
 */
int nbl_add_cqc_ref(struct nbl_cq *cq)
{
	struct ib_device *ibdev = cq->ibcq.device;
	struct nbl_device *nbldev = to_nbl_dev(ibdev);
	struct nbl_pci_f *rf = nbldev->rf;
	int ret = 0;

	ret = nbl_cqp_cq_cqc_ref_add(rf, &cq->sc_cq);

	return ret;
}

int nbl_dec_cqc_ref(struct nbl_cq *cq)
{
	struct ib_device *ibdev = cq->ibcq.device;
	struct nbl_device *nbldev = to_nbl_dev(ibdev);
	struct nbl_pci_f *rf = nbldev->rf;
	int ret = 0;

	ret = nbl_cqp_cq_cqc_ref_sub(rf, &cq->sc_cq);

	return ret;
}

void nbl_cq_rem_ref(struct ib_cq *ibcq)
{
	struct nbl_cq *nblcq = to_nblcq(ibcq);
	struct nbl_pci_f *rf =
		container_of(nblcq->sc_cq.dev, struct nbl_pci_f, sc_dev);
	unsigned long flags;

	spin_lock_irqsave(&rf->cqtable_lock, flags);
	if (!refcount_dec_and_test(&nblcq->refcnt)) {
		spin_unlock_irqrestore(&rf->cqtable_lock, flags);
		return;
	}

	rf->cq_table[nblcq->cq_num] = NULL;
	spin_unlock_irqrestore(&rf->cqtable_lock, flags);
	complete(&nblcq->free_cq);
}

/**
 * nbl_uk_clean_soft_wc - clean cq soft_wc in cq
 * @nblcq: rdma cq ptr
 * @qpn: qp num we clean
 */
static void nbl_uk_clean_soft_wc(struct nbl_cq *nblcq, u32 qpn)
{
	struct nbl_ib_wc *soft_wc, *next;

	list_for_each_entry_safe(soft_wc, next, &nblcq->pre_list, list) {
		if (qpn == soft_wc->ukqp->qpn) {
			list_del(&soft_wc->list);
			kfree(soft_wc);
		}
	}

	list_for_each_entry_safe(soft_wc, next, &nblcq->wc_list, list) {
		if (qpn == soft_wc->ukqp->qpn) {
			list_del(&soft_wc->list);
			kfree(soft_wc);
		}
	}
}

/**
 * nbl_uk_clean_cqes - clean cq entries in cq
 * @nblcq: rdma cq ptr
 * @qpn: qp num we clean
 */
static void nbl_uk_clean_cqes(struct nbl_cq *nblcq, u32 qpn)
{
	struct nbl_cq_uk *cq = &nblcq->sc_cq.cq_uk;
	struct nbl_frag_buf *nblcq_buf = &nblcq->buf.frag_buf;
	__be64 *cqe;
	u64 qword0, comp_ctx;
	u32 cq_head;
	u32 qpn_in_cqe;
	u8 polarity, temp;

	cq_head = cq->cq_ring.head;
	temp = cq->polarity;

	do {
		cqe = nbl_get_wqe(cq->cq_base, nblcq_buf,
			sizeof(struct nbl_cqe), cq_head, nblcq->pa_continuous);
		if (!cqe) {
			nbl_pr_err("get cqe failed when clean cq\n");
			return;
		}
		get_64bit_val(cqe, 0, &qword0);
		polarity = (u8)FIELD_GET(NBL_CQ_VALID, qword0);

		if (polarity != temp)
			break;

		get_64bit_val(cqe, 8, &comp_ctx);
		if (!(comp_ctx & NBL_CQ_CTX_INVALID)) {
			qpn_in_cqe = (u32)FIELD_GET(NBL_CQ_CTX_QPN, comp_ctx);
			if (qpn_in_cqe == qpn) {
				comp_ctx |= NBL_CQ_CTX_INVALID;
				set_64bit_val(cqe, 8, comp_ctx);
			}
		}

		cq_head = (cq_head + 1) % cq->cq_ring.size;
		if (!cq_head)
			temp ^= 1;
	} while (true);
}

void nbl_clean_cqes(struct nbl_cq *nblcq, u32 qpn)
{
	unsigned long flags;

	spin_lock_irqsave(&nblcq->lock, flags);
	nbl_uk_clean_cqes(nblcq, qpn);
	nbl_uk_clean_soft_wc(nblcq, qpn);
	spin_unlock_irqrestore(&nblcq->lock, flags);
}

int nbl_dump_hmc_cqc(struct nbl_pci_f *rf, u32 dump_mask)
{
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_hmc_obj_sd_info *cq_sd_info = rf->cq_sd_info;
	u32 num_one_page; /* how many cqc in one page */
	u32 page_index; /* page index that cqc located */
	u32 cqc_index; /* cqc index in a page */
	struct nbl_hmc_obj_sd_addr *sd;
	u32 cq_num;

	cq_num = dump_mask & NBL_CQN_MASK;

	num_one_page = cq_sd_info->page_sz / NBL_CQ_CTX_SIZE; /* 4K/64=64*/
	page_index = cq_num / num_one_page;
	if (page_index >= cq_sd_info->cnt)
		return NBL_ERR_CFG;

	sd = &cq_sd_info->sd_addr[page_index];
	cqc_index = cq_num % num_one_page;

	nbl_ib_err(sc_dev, "[cqc] dump cqn(%u) cqc(sd va %p, 0x%llx, offset 0x%x)",
		cq_num, sd->va, (u64)((uintptr_t)sd->va), (cqc_index * NBL_CQ_CTX_SIZE));
	nbl_dump_hex(rf, (sd->va + (cqc_index * NBL_CQ_CTX_SIZE)), NBL_CQ_CTX_SIZE);

	return 0;
}

int nbl_dbg_create_cq(struct nbl_pci_f *rf, u32 cqn_input)
{
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	u32 cqn;
	int ret;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;

	cqn = cqn_input & NBL_CQN_MASK;
	if (cqn >= rf->max_cq) {
		nbl_ib_err(sc_dev, "[dbg cq] create with wrong cqn(%u), max qpn is(%u)\n",
			cqn, rf->max_cq);
		return -EFAULT;
	}

	in = kzalloc(in_size, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	set_64bit_val(
		in, 0,
		FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_CREATE_CQ) |
		FIELD_PREP(NBL_CQPSQ_CQ_STAT, NBL_CQ_STAT_VALID) |
		FIELD_PREP(NBL_CQPSQ_CQ_CQSIZE, 8) |
		FIELD_PREP(NBL_CQPSQ_CQ_CQID, cqn) |
		FIELD_PREP(NBL_CQPSQ_CQ_CEQID, 0) |
		FIELD_PREP(NBL_CQPSQ_CQ_PS, NBL_CQP_PM_0_CONTINUS) |
		FIELD_PREP(NBL_CQPSQ_CQ_SHADOWTH, 64));
	set_64bit_val(in, 16, cqn);
	set_64bit_val(in, 24, FIELD_PREP(NBL_CQPSQ_CQ_BASEADDR, cqn));
	set_64bit_val(in, 32, FIELD_PREP(NBL_CQPSQ_CQ_CUR_ADDR, cqn));
	set_64bit_val(in, 40, FIELD_PREP(NBL_CQPSQ_CQ_NXT_ADDR, cqn));
	set_64bit_val(in, 48, FIELD_PREP(NBL_CQPSQ_CQ_CQC_BASE_ADDR, cqn));

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);
	if (ret)
		nbl_ib_err(sc_dev, "[dbg cq] create cq(%u) cmd err\n", cqn);

	kfree(in);

	return ret;
}

int nbl_dbg_destroy_cq(struct nbl_pci_f *rf, u32 cqn_input)
{
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	int ret;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;
	u32 cqn;

	cqn = cqn_input & NBL_CQN_MASK;
	if (cqn >= rf->max_cq) {
		nbl_ib_err(sc_dev, "[dbg cq] destroy with wrong cqn(%u), max qpn is(%u)\n",
			cqn, rf->max_cq);
		return -EFAULT;
	}

	in = kzalloc(in_size, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	set_64bit_val(in, 0,
		FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_DESTROY_CQ) |
		FIELD_PREP(NBL_CQPSQ_CQ_STAT, NBL_CQ_STAT_INVALID) |
		FIELD_PREP(NBL_CQPSQ_CQ_CQID, cqn));

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);

	kfree(in);

	return ret;
}

void nbl_generate_wc(struct nbl_cq *nblcq, struct nbl_ib_wc *soft_wc)
{
	unsigned long flags;

	spin_lock_irqsave(&nblcq->lock, flags);
	list_add_tail(&soft_wc->list, &nblcq->pre_list);
	nblcq->pre_num++;
	spin_unlock_irqrestore(&nblcq->lock, flags);
}

static inline void nbl_soft_wc_ce_handler(struct nbl_cq *nblcq)
{
	if (!nblcq->ibcq.comp_handler)
		return;

	if (atomic_cmpxchg(&nblcq->armed, 1, 0))
		nblcq->ibcq.comp_handler(&nblcq->ibcq, nblcq->ibcq.cq_context);
}

static int nbl_cq_sw_wc_update(struct nbl_qp *nblqp, bool is_sq)
{
	struct nbl_pci_f *rf = nblqp->nbldev->rf;
	struct nbl_uk_qp *ukqp = &nblqp->sc_qp.uk_qp;
	struct nbl_ib_wc *soft_wc, *next;
	struct nbl_cq *nblcq;
	unsigned long flags;
	bool updated = false;
	int ret = 0;

	nblcq = (is_sq ? nblqp->scq : nblqp->rcq);
	spin_lock_irqsave(&nblcq->lock, flags);

	if (nblcq->pre_num == 0) {
		ret = SWWC_N_NTF_N_TIMER;
		goto unlock;
	}

	if ((is_sq && ukqp->sq_flush_complete) ||
		((!is_sq) && ukqp->rq_flush_complete) ||
		rf->sc_dev.has_high_temp_alarm) {
		list_for_each_entry_safe(soft_wc, next, &nblcq->pre_list, list) {
			if (soft_wc->is_sq == is_sq && soft_wc->ukqp == ukqp) {
				list_del(&soft_wc->list);
				list_add_tail(&soft_wc->list, &nblcq->wc_list);
				updated = true;
				nblcq->pre_num--;
			}
		}
		if (updated)
			ret = SWWC_Y_NTF_N_TIMER;
		else
			ret = SWWC_N_NTF_N_TIMER;
	} else
		ret = SWWC_N_NTF_Y_TIMER;

unlock:
	spin_unlock_irqrestore(&nblcq->lock, flags);

	return ret;
}

void nbl_sched_qp_flush_work(struct nbl_qp *qp)
{
	struct nbl_pci_f *rf = qp->nbldev->rf;
	unsigned long flags;

	if (qp->sc_qp.uk_qp.destroy_pending)
		return;

	spin_lock_irqsave(&rf->qptable_lock, flags);
	if (!rf->qp_table[qp->sc_qp.uk_qp.qpn]) {
		spin_unlock_irqrestore(&rf->qptable_lock, flags);
		nbl_ib_err(&rf->sc_dev, "sched qp flush qpn %u is already freed\n",
			   qp->sc_qp.uk_qp.qpn);
		return;
	}
	nbl_qp_add_ref(qp);
	spin_unlock_irqrestore(&rf->qptable_lock, flags);

	if (mod_delayed_work(rf->flush_wq, &qp->dwork_flush,
			msecs_to_jiffies(NBL_QP_FLUSH_COMPLETE_CHK_DELAY_MS)))
		nbl_qp_rem_ref(&qp->ibqp);
}

static void nbl_generate_flush_completions(struct nbl_qp *nblqp)
{
	int sq_chk;
	int rq_chk;

	sq_chk = nbl_cq_sw_wc_update(nblqp, true);
	rq_chk = nbl_cq_sw_wc_update(nblqp, false);

	if (sq_chk == SWWC_Y_NTF_N_TIMER || rq_chk == SWWC_Y_NTF_N_TIMER) {
		if (nblqp->scq == nblqp->rcq)
			nbl_soft_wc_ce_handler(nblqp->scq);
		else {
			if (sq_chk == SWWC_Y_NTF_N_TIMER)
				nbl_soft_wc_ce_handler(nblqp->scq);
			if (rq_chk == SWWC_Y_NTF_N_TIMER)
				nbl_soft_wc_ce_handler(nblqp->rcq);
		}
	}

	if (sq_chk == SWWC_N_NTF_Y_TIMER || rq_chk == SWWC_N_NTF_Y_TIMER)
		nbl_sched_qp_flush_work(nblqp);
}

void nbl_flush_dworker(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct nbl_qp *nblqp = container_of(dwork, struct nbl_qp, dwork_flush);

	nbl_generate_flush_completions(nblqp);

	/* for add ref in nbl_sched_qp_flush_work */
	nbl_qp_rem_ref(&nblqp->ibqp);
}
