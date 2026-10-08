// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/bitfield.h>
#include <rdma/nbl-v2-abi.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
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
#include "srq.h"
#include "dump_fields.h"
#include "device.h"

static u32 nbl_cq_shadow_rd_thd_calc(u32 cq_size)
{
	u32 thd;

	if (cq_size <= NBL_CQ_SHADOW_TH_BOUNDARY)
		thd = NBL_CQ_SHADOW_TH_LOW;
	else
		thd = cq_size / NBL_CQ_SHADOW_TH_GAP;

	return thd;
}

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

static void nbl_cq_clean_resize_list(struct nbl_cq *nblcq)
{
	struct nbl_device *nbldev = to_nbl_dev(nblcq->ibcq.device);
	struct nbl_pci_f *rf = nbldev->rf;
	struct list_head *tmp_node, *list_node;
	struct nbl_cq_buf *cq_buf;

	list_for_each_safe(list_node, tmp_node, &nblcq->resize_list) {
		cq_buf = container_of(list_node, struct nbl_cq_buf, list);
		list_del(&cq_buf->list);
		queue_work(rf->cleanup_wq, &cq_buf->work);
	}
}

static void nbl_cq_clean_uresize_list(struct nbl_cq *nblcq, u32 clr_num)
{
	struct nbl_device *nbldev = to_nbl_dev(nblcq->ibcq.device);
	struct list_head *tmp_node, *list_node;
	struct nbl_user_rsize *ursize;
	u32 clr_cnt = 0;

	list_for_each_safe(list_node, tmp_node, &nblcq->u_resize_list) {
		ursize = container_of(list_node, struct nbl_user_rsize, list);
		nbl_user_buf_release(nbldev, &ursize->bdes);
		list_del(&ursize->list);
		kfree(ursize);
		clr_cnt++;
		if (clr_cnt == clr_num)
			return;
	}
}

int nbl_cqp_cq_resize_cmd(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq,
				struct nbl_modify_cq_info *info)
{
	struct nbl_cq_uk *ukcq = &sc_cq->cq_uk;
	__be64 *in;
	u64 page_1st_pa = 0;
	u64 page_2nd_pa = 0;
	u64 *base_addr = NULL;
	int ret;

	if (info->bdes.pa_continuous) {
		page_1st_pa = info->cq_base_pa;
		if (info->bdes.cq_pg_num > 1)
			page_2nd_pa =
				info->cq_base_pa + (1 << NBL_ADAPTER_PAGE_SHIFT);
	} else {
		base_addr = (u64 *)info->cq_base;
		if (base_addr) {
			/* as base_addr point to hw read pd area,
			 * this area is big end, so here we covert it first
			 */
			page_1st_pa = be64_to_cpu(base_addr[0]);
			if (info->bdes.cq_pg_num > 1)
				page_2nd_pa = be64_to_cpu(base_addr[1]);
		} else {
			nbl_ib_err(&rf->sc_dev, "[CQ] create cq base addr NULL err\n");
			return NBL_ERR_ALLOCMEM_FAILED;
		}
	}

	nbl_ib_dbg(&rf->sc_dev,
		"[CQ] (cqn %u) CQP parameter: 1st_addr: 0x%llx, 2nd_addr:0x%llx\n",
		ukcq->cq_id, page_1st_pa, page_2nd_pa);
	nbl_ib_dbg(&rf->sc_dev,
		"[CQ] (continus %d)cq_base_pa:0x%llx, sc cq 0x%llx\n",
		info->bdes.pa_continuous, info->cq_base_pa, (u64)((uintptr_t)sc_cq));

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_RESIZE_CQ);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_STAT, NBL_CQ_STAT_VALID);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_CQSIZE, ilog2(info->cq_size));
	nbl_64bit_write(in, NBL_CQP_V2_CQ_CQID, ukcq->cq_id);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_CEQID, sc_cq->ceq_id);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_PM, info->bdes.pa_continuous ?
		NBL_CQP_PM_0_CONTINUS : NBL_CQP_PM_1_UNCONTINUS);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_CONTEXT, (u64)((uintptr_t)sc_cq));
	nbl_64bit_write(in, NBL_CQP_V2_CQ_BASEADDR, (info->cq_base_pa >> NBL_ADAPTER_PAGE_SHIFT));
	nbl_64bit_write(in, NBL_CQP_V2_CQ_CUR_ADDR, page_1st_pa >> NBL_ADAPTER_PAGE_SHIFT);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_NXT_ADDR, page_2nd_pa >> NBL_ADAPTER_PAGE_SHIFT);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_SHADOW_ADDR,
		(sc_cq->shadow_area_pa >> NBL_CQP_CQ_SHDW_SHIFT));
	nbl_64bit_write(in, NBL_CQP_V2_CQ_SHADOWTH, info->shadow_rd_thd);

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);

	kfree(in);

	return ret;
}

int nbl_cqp_v2_cq_create_cmd(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq)
{
	__be64 *in;
	struct nbl_cq_uk *ukcq = &sc_cq->cq_uk;
	struct nbl_cq *nblcq = sc_cq->bak_nbl_cq;
	u64 page_1st_pa = 0;
	u64 page_2nd_pa = 0;
	u64 *base_addr = NULL;
	int ret;

	if (ukcq->bdes.pa_continuous) {
		page_1st_pa = ukcq->cq_base_pa;
		if (ukcq->bdes.cq_pg_num > 1)
			page_2nd_pa =
				ukcq->cq_base_pa + (1 << NBL_ADAPTER_PAGE_SHIFT);
	} else {
		base_addr = (u64 *)ukcq->cq_base;
		if (base_addr) {
			/* as base_addr point to hw read pd area,
			 * this area is big end, so here we covert it first
			 */
			page_1st_pa = be64_to_cpu(base_addr[0]);
			if (ukcq->bdes.cq_pg_num > 1)
				page_2nd_pa = be64_to_cpu(base_addr[1]);
		} else {
			nbl_ib_err(&rf->sc_dev, "[CQ] create cq base addr NULL err\n");
			return -EFAULT;
		}
	}

	nbl_ib_dbg(&rf->sc_dev,
		"[CQ] (cqn %u) CQP parameter: 1st_addr: 0x%llx, 2nd_addr:0x%llx\n",
		ukcq->cq_id, page_1st_pa, page_2nd_pa);
	nbl_ib_dbg(&rf->sc_dev,
		"[CQ] (continus %d)cq_base_pa:0x%llx, sc cq 0x%llx\n",
		ukcq->bdes.pa_continuous, ukcq->cq_base_pa, (u64)((uintptr_t)sc_cq));

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_CREATE_CQ);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_STAT, NBL_CQ_STAT_VALID);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_CQSIZE, (ilog2(ukcq->cq_size)));
	if (sc_cq->cq_cc)
		nbl_64bit_write(in, NBL_CQP_V2_CQ_CC, 1);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_CQID, ukcq->cq_id);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_CEQID, sc_cq->ceq_id);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_PM, ukcq->bdes.pa_continuous ?
		NBL_CQP_PM_0_CONTINUS : NBL_CQP_PM_1_UNCONTINUS);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_CONTEXT, (u64)((uintptr_t)sc_cq));
	nbl_64bit_write(in, NBL_CQP_V2_CQ_BASEADDR,
		(ukcq->cq_base_pa >> NBL_ADAPTER_PAGE_SHIFT));
	nbl_64bit_write(in, NBL_CQP_V2_CQ_CUR_ADDR,
		page_1st_pa >> NBL_ADAPTER_PAGE_SHIFT);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_NXT_ADDR,
		page_2nd_pa >> NBL_ADAPTER_PAGE_SHIFT);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_SHADOW_ADDR,
		(sc_cq->shadow_area_pa >> NBL_CQP_CQ_SHDW_SHIFT));
	nbl_64bit_write(in, NBL_CQP_V2_CQ_SHADOWTH, ukcq->shadow_rd_thd);
	if (!nblcq->user_mode && rf->sc_dev.cem_enable) {
		nbl_64bit_write(in, NBL_CQP_V2_CQ_CE_MDN, 1);
		nbl_64bit_write(in, NBL_CQP_V2_CQ_PERIOD, NBL_START_CQ_PERIOD);
		nbl_64bit_write(in, NBL_CQP_V2_CQ_MAXCNT, NBL_START_CQ_MAXCNT);
	}

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (ret)
		nbl_ib_err(&rf->sc_dev, "[CQ_CREATE] Create CQ CQP execute failed(%d)\n", ret);

	kfree(in);

	return ret;
}

/**
 * nbl_uk_cq_init - initialize shared cq (user and kernel)
 * @ukcq: struct uk cq
 * @sc_cq: struct sc cq
 */
static void nbl_uk_cq_init(struct nbl_cq_uk *ukcq, struct nbl_sc_cq *sc_cq)
{
	ukcq->cq_base = ukcq->bdes.kmem.va;
	ukcq->cq_base_pa = ukcq->bdes.kmem.pa;
	ukcq->shadow_rd_thd = nbl_cq_shadow_rd_thd_calc(ukcq->cq_size);

	NBL_RING_INIT(ukcq->cq_ring, ukcq->cq_size);
	ukcq->polarity = 1;
	ukcq->bak_sc_cq = sc_cq;
}

/**
 * nbl_sc_cq_init - initialize completion q
 * @cq: cq struct
 * @info: cq initialization info
 */
void nbl_sc_cq_init(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq)
{
	sc_cq->dev = &rf->sc_dev;
	nbl_uk_cq_init(&sc_cq->cq_uk, sc_cq);
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


/* nbl_uresize_handle - copy ucmd and unpin user free resize buf */
static int nbl_uresize_handle(struct nbl_device *dev, struct nbl_cq *nblcq,
		struct ib_udata *udata, struct nbl_resize_cq_req *ucmd)
{
	struct nbl_sc_dev *sc_dev = &dev->rf->sc_dev;
	size_t ucmdlen;

	ucmdlen = min(udata->inlen, sizeof(*ucmd));
	if (ib_copy_from_udata(ucmd, udata, ucmdlen))
		return -EFAULT;

	/* unpin pre resize mem first */
	if (ucmd->rsz_free_num > 0)
		nbl_cq_clean_uresize_list(nblcq, ucmd->rsz_free_num);

	nbl_ib_dbg(sc_dev, "resize cq user, size:%d, buf:0x%llx, free num %u\n",
		ucmd->cq_buf_size, ucmd->user_cq_buffer, ucmd->rsz_free_num);

	return 0;
}

/**
 * nbl_create_cq_user - create cq by userspace cmd
 */
static int nbl_create_cq_user(struct ib_ucontext *ibctx,
	struct nbl_device *dev, struct ib_udata *udata,
	struct nbl_buf_desc *bd)
{
	struct nbl_create_cq_req ucmd = {};
	struct nbl_sc_dev *sc_dev = &dev->rf->sc_dev;
	size_t ucmdlen;

	ucmdlen = min(udata->inlen, sizeof(ucmd));
	if (ib_copy_from_udata(&ucmd, udata, ucmdlen)) {
		nbl_ib_err(sc_dev, "create user cq copy data err\n");
		return -EFAULT;
	}

	nbl_ib_dbg(sc_dev, "create cq user, buf size:%d, user buf:0x%llx\n",
		ucmd.cq_buf_size, ucmd.user_cq_buf);

	return nbl_user_buf_get(ibctx, dev, ucmd.user_cq_buf, ucmd.cq_buf_size, bd, udata);
}

int nbl_cqp_v2_cq_destroy_cmd(struct nbl_pci_f *rf, struct nbl_sc_cq *cq)
{
	int ret;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;
	u32 cq_id = cq->cq_uk.cq_id;

	in = kzalloc(in_size, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_DESTROY_CQ);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_STAT, NBL_CQ_STAT_INVALID);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_CQID, cq_id);

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);

	kfree(in);

	return ret;
}


/**
 * nbl_ib_destroy_cq - destroy cq
 * @ib_cq: cq pointer
 * @udata: user data
 */
int nbl_ib_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata)
{
	struct nbl_device *nbldev = to_nbl_dev(ib_cq->device);
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_res_table *cq_table = &rf->cq_table;
	struct nbl_cq *nblcq = to_nbl_cq(ib_cq);
	struct nbl_sc_cq *cq = &nblcq->sc_cq;
	struct nbl_cq_uk *ukcq = &cq->cq_uk;
	struct nbl_sc_dev *dev = cq->dev;
	struct nbl_cq *tmp;
	unsigned long flags;
	struct nbl_ceq *nblceq;
	struct nbl_sc_ceq *ceq;

	nbl_ib_dbg(dev, "destroy cq(%u) start, with ceq_id: %d\n", cq->cq_uk.cq_id, cq->ceq_id);

	spin_lock(&cq_table->lock);
	tmp = radix_tree_delete(&cq_table->tree, nblcq->cq_num);
	spin_unlock(&cq_table->lock);
	if (!tmp || tmp != nblcq)
		nbl_ib_err(dev, "cq table del err for cq %u\n", nblcq->cq_num);

	spin_lock_irqsave(&nblcq->lock, flags);
	if (!list_empty(&nblcq->wc_list))
		nbl_cq_destroy_soft_wc(nblcq);
	if (!list_empty(&nblcq->resize_list))
		nbl_cq_clean_resize_list(nblcq);
	spin_unlock_irqrestore(&nblcq->lock, flags);

	rf->cqp_ops->cqp_destroy_cq(rf, cq);

	ceq = dev->ceq[cq->ceq_id];
	nblceq = container_of(ceq, struct nbl_ceq, sc_ceq);
	/* waiting interrupt process procedure carried out */
	synchronize_irq(nblceq->irq);

	nbl_cq_put(nblcq);
	wait_for_completion(&nblcq->free_cq);

	if (nblcq->user_mode) {
		nbl_user_buf_release(nbldev, &ukcq->bdes);
		if (!list_empty(&nblcq->u_resize_list))
			nbl_cq_clean_uresize_list(nblcq, 0);
	} else
		nbl_kernel_buf_free(dev->hw, &ukcq->bdes);

	set_64bit_val(ukcq->shadow_area, 0, 0); /* clean shadow area pi/ci part */

	nbl_cq_free_rsrc(rf, nblcq);

	nbl_ib_dbg(dev, "[CQ_DESTROY] destroy cq success.\n");
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
static int nbl_cq_user_shadow_init(struct nbl_pci_f *rf, struct nbl_sc_cq *cq,
						struct nbl_ucontext *uctx,
						struct nbl_ib_create_cq_resp *uresp)
{
	struct nbl_hmc_obj_sd_info *cq_sd_info = rf->cq_sd_info;
	struct nbl_cq_uk *cq_uk = &cq->cq_uk;
	struct shadow_node *cqc_shadow = NULL;
	u32 map_size;

	uresp->shadow_base_addr = cq_uk->cqc_base_pa;
	uresp->cqc_size = NBL_CQ_CTX_SIZE;
	/* shadow offset from a page 4K OR 2M, for user mode easy calc */
	uresp->shadow_offset = cq_uk->shdw_page_offset;
	uresp->shadow_size = NBL_CQ_SHADOW_SIZE;
	uresp->page_size = cq_sd_info->page_sz;

	map_size = uresp->page_size <= PAGE_SIZE ? PAGE_SIZE : uresp->page_size;
	cqc_shadow = nbl_find_shadow_mmap(uctx, uresp->shadow_base_addr, map_size);
	if (!cqc_shadow)
		return nbl_add_shadow_mmap(uctx, cq_uk->cqc_base_va,
					   uresp->shadow_base_addr, map_size);

	return 0;
}

static int nbl_create_cq_ddr_kernel_shadow(struct nbl_cq *cq,
			struct nbl_hmc_obj_sd_info *cq_sd_info)
{
	struct nbl_sc_cq *sccq = &cq->sc_cq;
	struct nbl_cq_uk *ukcq = &cq->sc_cq.cq_uk;
	u32 num_one_page; /* how many cqc in one page */
	u32 page_index; /* page index that cqc located */
	u32 cqc_index; /* cqc index in a page */
	struct nbl_hmc_obj_sd_addr *sd;

	num_one_page = cq_sd_info->page_sz / NBL_CQ_SHADOW_SIZE; /* 4K/8=512 */
	page_index = cq->cq_num / num_one_page;
	if (page_index >= cq_sd_info->cnt) {
		nbl_ib_err(cq->sc_cq.dev, "cq shadow page index %u err, max cnt %u\n",
			page_index, cq_sd_info->cnt);
		return -EINVAL;
	}

	sd = &cq_sd_info->sd_addr[page_index];
	/* get cqc index */
	cqc_index = cq->cq_num % num_one_page;
	ukcq->cqc_base_va = sd->va;
	ukcq->shdw_page_offset =
		(cqc_index * NBL_CQ_SHADOW_SIZE);
	ukcq->shadow_area =
		(sd->va + (cqc_index * NBL_CQ_SHADOW_SIZE));

	/* DDR mode: info->cqc_begin_pa we can not calc */
	sccq->shadow_area_pa =
		sd->dma_addr + (cqc_index * NBL_CQ_SHADOW_SIZE);

	nbl_ib_dbg(cq->sc_cq.dev, "[CQ create] DDR mode, page base va:%p, shdw va: %p, shdw pa %lld\n",
		ukcq->cqc_base_va,
		ukcq->shadow_area,
		sccq->shadow_area_pa);
	return 0;
}

int nbl_create_cq_kernel_shadow(struct nbl_pci_f *rf,
			struct nbl_cq *cq, struct nbl_hmc_obj_sd_info *cq_sd_info)
{
	struct nbl_sc_cq *sccq = &cq->sc_cq;
	struct nbl_cq_uk *ukcq = &cq->sc_cq.cq_uk;
	u32 num_one_page; /* how many cqc in one page */
	u32 page_index; /* page index that cqc located */
	u32 cqc_index; /* cqc index in a page */
	struct nbl_hmc_obj_sd_addr *sd;

	if (rf->sc_dev.ddr_mode_en)
		return nbl_create_cq_ddr_kernel_shadow(cq, cq_sd_info);

	num_one_page = cq_sd_info->page_sz / NBL_CQ_CTX_SIZE; /* 4K/64=64*/
	page_index = cq->cq_num / num_one_page;
	if (page_index >= cq_sd_info->cnt) {
		nbl_ib_err(cq->sc_cq.dev, "cq shadow page index %u err, max cnt %u\n",
			page_index, cq_sd_info->cnt);
		return -EINVAL;
	}

	sd = &cq_sd_info->sd_addr[page_index];
	/* get cqc index */
	cqc_index = cq->cq_num % num_one_page;
	ukcq->cqc_base_va = sd->va;
	ukcq->cqc_base_pa = sd->dma_addr;
	ukcq->shdw_page_offset =
		(cqc_index * NBL_CQ_CTX_SIZE) + NBL_CQ_SHADOW_OFFST;
	ukcq->shadow_area =
		sd->va + (cqc_index * NBL_CQ_CTX_SIZE) + NBL_CQ_SHADOW_OFFST;

	sccq->cqc_begin_pa = sd->dma_addr + (cqc_index * NBL_CQ_CTX_SIZE);
	sccq->shadow_area_pa =
		sd->dma_addr + (cqc_index * NBL_CQ_CTX_SIZE) + NBL_CQ_SHADOW_OFFST;

	nbl_ib_dbg(cq->sc_cq.dev, "[CQ create] none DDR mode, page base va:%p, shdw va: %p, shdw pa %lld\n",
		ukcq->cqc_base_va,
		ukcq->shadow_area,
		sccq->shadow_area_pa);
	return 0;
}

static int nbl_cq_init(struct nbl_pci_f *rf,
				struct nbl_cq *nblcq,
				const struct ib_cq_init_attr *attr)
{
	struct nbl_sc_cq *cq = &nblcq->sc_cq;
	u32 cq_num = 0;
	int ret;

	if (attr->comp_vector < rf->ceqs_count)
		cq->ceq_id = attr->comp_vector;
	else {
		nbl_ib_err(&rf->sc_dev, "CEQ id %d error, device ceq counts:%d\n",
			   attr->comp_vector, rf->ceqs_count);
		return -ENOENT;
	}

	ret = nbl_alloc_rsrc(&rf->rsrc_lock, rf->allocated_cqs, rf->max_cq, &cq_num,
				  &rf->next_cq);
	if (ret) {
		nbl_ib_err(&rf->sc_dev, "CQ id request error, device cq max:%d\n", rf->max_cq);
		return ret;
	}

	nblcq->cq_num = cq_num;
	cq->cq_uk.cq_id = cq_num;

	cq->bak_nbl_cq = nblcq;
	refcount_set(&nblcq->refcnt, 1);
	spin_lock_init(&nblcq->lock);
	atomic_set(&nblcq->armed, 0);
	cq->cq_cc = false; /* cq cc for ibgda only */

	return 0;
}

static int nbl_kernel_cq_calc(struct nbl_pci_f *rf, struct nbl_cq_uk *ukcq,
		int entries)
{
	if (entries < rf->sc_dev.hw_attrs.uk_attrs.min_hw_cq_size)
		entries = rf->sc_dev.hw_attrs.uk_attrs.min_hw_cq_size;
	ukcq->cq_size = roundup_pow_of_two(entries);
	if (ukcq->cq_size > rf->max_cqe) {
		nbl_ib_err(&rf->sc_dev,
			"create kernel mode cq with cqe num err(request %d, max %u)\n",
			entries, rf->max_cqe);
		return -EINVAL;
	}

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
	struct nbl_sc_dev *dev;
	struct nbl_res_table *cq_table;
	struct nbl_cq *nblcq;
	struct nbl_sc_cq *sccq;
	struct nbl_cq_uk *ukcq;
	struct nbl_ucontext *uctx;
	int entries = attr->cqe;
	enum nbl_status_code status;
	int err_code;
	int load_rsvd;

	nbldev = to_nbl_dev(ibcq->device);
	nblcq = to_nbl_cq(ibcq);
	uctx = rdma_udata_to_drv_context(udata, struct nbl_ucontext, ibucontext);
	rf = nbldev->rf;
	dev = &rf->sc_dev;
	cq_table = &rf->cq_table;
	sccq = &nblcq->sc_cq;
	ukcq = &sccq->cq_uk;
	load_rsvd = NBL_CQ_LOAD_RSVD_V2;

	err_code = nbl_cq_init(rf, nblcq, attr);
	if (err_code)
		goto cq_free_cqmem_ondemand;

	if (udata) {
		nblcq->user_mode = true;
		ukcq->cq_size = max_t(int, entries, dev->hw_attrs.uk_attrs.min_hw_cq_size);
		nblcq->ibcq.cqe = ukcq->cq_size - 1;
		nblcq->uctx = uctx;
		err_code = nbl_create_cq_user(&uctx->ibucontext, nbldev, udata, &ukcq->bdes);
		if (err_code)
			goto cq_free_rsrc;
	} else {
		err_code = nbl_kernel_cq_calc(rf, ukcq, entries + load_rsvd);
		if (err_code)
			goto cq_free_rsrc;

		nblcq->ibcq.cqe = ukcq->cq_size - load_rsvd;
		status = nbl_kernel_buf_alloc(dev->hw,
			(ukcq->cq_size * sizeof(struct nbl_cqe)), &ukcq->bdes);
		if (status) {
			nbl_ib_err(dev, "create kernel cq buf alloc err(%d).\n", status);
			err_code = -ENOMEM;
			goto cq_free_rsrc;
		}
	}

	/* shadow kernel init */
	err_code = nbl_create_cq_kernel_shadow(rf, nblcq, rf->cq_sd_info);
	if (err_code)
		goto cq_free_buf;

	nbl_sc_cq_init(rf, sccq);

	/* collect shadow infos for userspace*/
	if (udata) {
		err_code = nbl_cq_user_shadow_init(rf, sccq, uctx, &resp);
		if (err_code) {
			nbl_ib_err(dev, "user mode cq shadow init err(%d)\n", err_code);
			goto cq_free_buf;
		}
	}

	err_code = rf->cqp_ops->cqp_create_cq(rf, sccq);
	if (err_code)
		goto cq_free_buf;

	INIT_LIST_HEAD(&nblcq->wc_list);
	INIT_LIST_HEAD(&nblcq->pre_list);
	nblcq->pre_num = 0;
	INIT_LIST_HEAD(&nblcq->resize_list);
	INIT_LIST_HEAD(&nblcq->u_resize_list);
	nblcq->sw_sel_cnt = 0;
	nblcq->arm_seq_num = 0;

	if (udata) {
		resp.cq_id = ukcq->cq_id;
		resp.cq_size = ukcq->cq_size;
		err_code = ib_copy_to_udata(udata, &resp,
						min(sizeof(resp), udata->outlen));
		if (err_code) {
			nbl_ib_err(dev, "ib_copy_to_udata failed.\n");
			goto cq_destroy;
		}
	}

	spin_lock(&cq_table->lock);
	err_code = radix_tree_insert(&cq_table->tree, nblcq->cq_num, nblcq);
	spin_unlock(&cq_table->lock);
	if (err_code)
		goto cq_destroy;

	init_completion(&nblcq->free_cq);

	return 0;

cq_destroy:
	rf->cqp_ops->cqp_destroy_cq(rf, sccq);
cq_free_buf:
	if (udata)
		nbl_user_buf_release(nbldev, &ukcq->bdes);
	else
		nbl_kernel_buf_free(dev->hw, &ukcq->bdes);
cq_free_rsrc:
	nbl_cq_free_rsrc(rf, nblcq);
cq_free_cqmem_ondemand:
	return err_code;
}

/**
 * get_sqinfo_nml_wqe - V2R1/DF200 get sq ci info, then move sq ci
 * @ukqp: uk qp
 * @info: information structure to hold info
 */
static int get_sqinfo_nml_wqe(struct nbl_uk_qp *ukqp, struct nbl_cq_poll_info *info)
{
	u32 tail;
	struct nbl_wqe_ctrl_seg *ctrl;
	struct nbl_qp *qp = ukqp->back_qp;

	tail = ukqp->sq_ring.tail;
	ctrl = nbl_get_wqe(ukqp->sq_base, &(qp->sc_qp.sqbuf.frag_buf),
				sizeof(struct nbl_qp_block), tail, !qp->sc_qp.sq_pm);
	if (!ctrl)
		return -EFAULT;

	NBL_RING_SET_TAIL(ukqp->sq_ring,
				tail + ukqp->sq_wrtrk_array[tail].quanta);
	info->op_type = ctrl->opcode;
	info->wqe_idx_wrid_use = tail; /* dbg only */
	info->wr_id = ukqp->sq_wrtrk_array[tail].wrid;
	info->ib_op = ukqp->sq_wrtrk_array[tail].ib_op;
	info->bytes_xfered = ukqp->sq_wrtrk_array[tail].wr_len;

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

static int nbl_parse_cqe_for_req(struct nbl_pci_f *rf,
				 struct nbl_cq_uk *cq, struct nbl_uk_qp *qp,
				 struct nbl_cq_poll_info *info)
{
	__be64 *cqe = info->cqe;

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
		return NBL_ERR_Q_EMPTY;
	}

	if (info->comp_status != NBL_COMPL_STATUS_FLUSHED) {
		info->wqe_idx_wrid_use = info->wqe_idx; /* dbg only */
		info->wr_id = qp->sq_wrtrk_array[info->wqe_idx].wrid;
		if (!info->comp_status)
			info->bytes_xfered =
				qp->sq_wrtrk_array[info->wqe_idx].wr_len;
		info->op_type = (u8)nbl_64bit_read(cqe, NBL_CQ_OP);
		info->ib_op = qp->sq_wrtrk_array[info->wqe_idx].ib_op;

		/* move sq ci */
		NBL_RING_SET_TAIL(
			qp->sq_ring,
			info->wqe_idx + qp->sq_wrtrk_array[info->wqe_idx].quanta);

		/* for driver ce, only success we need repoll, so here add strong
		 * judgement: succ and driver ce.
		 */
		if (info->comp_status == NBL_COMPL_STATUS_SUCCESS &&
			qp->sq_wrtrk_array[info->wqe_idx].driver_ce) {
			nbl_pr_dbg("qp:%d poll driver cqe:%d\n", qp->qpn, info->wqe_idx);
			return NBL_ERR_Q_DRIVER_CE; /* finally repoll */
		}
	} else {
		/* during flush sq, check sq wqe one by one and move sq ci
		 * V2R1 DF200 there is no nop sq wqe, so here add judgement.
		 */
		if (get_sqinfo_nml_wqe(qp, info))
			return NBL_ERR_Q_EMPTY;

		qp->sq_flush_seen = true;
		if (!NBL_RING_MORE_WORK(qp->sq_ring))
			qp->sq_flush_complete = true;
		else
			info->move_cq_head = false;
	}

	info->pring = &qp->sq_ring;

	return 0;
}

static void nbl_parse_cqe_resp_common(struct nbl_cq_poll_info *info)
{
	__be64 *cqe = info->cqe;

	info->bytes_xfered = (u32)nbl_64bit_read(cqe, NBL_CQ_PAYLDLEN);

	if (info->imm_valid)
		info->op_type = NBL_OPCODE_RECV_IMM;
	else
		info->op_type = NBL_OPCODE_RECV;

	info->mkey_valid = (bool)nbl_64bit_read(cqe, NBL_CQ_MKEY_VALID);
	if (info->mkey_valid)
		info->invalidated_mkey = (u32)nbl_64bit_read(cqe, NBL_CQ_INVMKEY);
}

static int nbl_parse_cqe_for_srq(struct nbl_qp *nblqp, struct nbl_cq_poll_info *info)
{
	__be64 *cqe = info->cqe;
	struct nbl_device *nbldev = nblqp->nbldev;
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_srq *srq = NULL;
	u32 wr_idx;

	info->srqn = (u32)nbl_64bit_read(cqe, NBL_CQ_SRQN);
	info->srq_subid = (u8)nbl_64bit_read(cqe, NBL_CQ_SRQ_SUBID);

	if (nblqp->ibqp.xrcd)
		srq = rf->srq_table[info->srqn];
	else
		srq = to_nbl_srq(nblqp->ibqp.srq);
	if (srq) {
		wr_idx = ((info->srq_subid << srq->max_wr_shift) |
			(info->wqe_idx / srq->wqe_quanta));
		info->wr_id = srq->wrid[wr_idx];
		nbl_ib_free_srq_wqe(srq, info->srq_subid, info->wqe_idx);
	} else
		return NBL_ERR_Q_SRQNULL; /* jump this cqe and repoll */

	return 0;
}

static int nbl_parse_cqe_for_resp(struct nbl_pci_f *rf,
				  struct nbl_cq_uk *cq, struct nbl_uk_qp *qp,
				  struct nbl_cq_poll_info *info)
{
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
		return NBL_ERR_Q_EMPTY;
	}

	if (info->comp_status == NBL_COMPL_STATUS_FLUSHED)
		info->wqe_idx = qp->rq_ring.tail;

	info->wqe_idx_wrid_use = info->wqe_idx; /* dbg only */
	info->wr_id = qp->rq_wrid_array[info->wqe_idx];

	/* move rq ci */
	NBL_RING_SET_TAIL(qp->rq_ring, info->wqe_idx + qp->rqe_mult);

	if (info->comp_status == NBL_COMPL_STATUS_FLUSHED) {
		qp->rq_flush_seen = true;
		if (!NBL_RING_MORE_WORK(qp->rq_ring))
			qp->rq_flush_complete = true;
		else
			info->move_cq_head = false;
	}
	info->pring = &qp->rq_ring;

	return 0;
}

static void nbl_parse_cqe_common(struct nbl_uk_qp *qp,
				 struct nbl_cq_poll_info *info)
{
	__be64 *cqe = info->cqe;
	__u64 smac;

	info->ud_src_qpn = (u32)nbl_64bit_read(cqe, NBL_CQ_UDSRCQPN);
	info->imm_valid = (bool)nbl_64bit_read(cqe, NBL_CQ_IMMVALID);
	if (info->imm_valid)
		info->imm_data = (u32)nbl_64bit_read(cqe, NBL_CQ_IMMDATA);
	info->ud_smac_valid = (bool)nbl_64bit_read(cqe, NBL_CQ_UDVALID);
	info->ud_vlan_valid = (bool)nbl_64bit_read(cqe, NBL_CQ_UDVLANVALID);
	if (info->ud_vlan_valid)
		info->ud_vlan = (u16)nbl_64bit_read(cqe, NBL_CQ_UDVLAN);
	if (info->ud_smac_valid) {
		smac = (__u64)nbl_64bit_read(cqe, NBL_CQ_UDSMAC);
		info->ud_smac[5] = smac & 0xFF;
		info->ud_smac[4] = (smac >> 8) & 0xFF;
		info->ud_smac[3] = (smac >> 16) & 0xFF;
		info->ud_smac[2] = (smac >> 24) & 0xFF;
		info->ud_smac[1] = (smac >> 32) & 0xFF;
		info->ud_smac[0] = (smac >> 40) & 0xFF;
	}
	info->ipv4 = (bool)nbl_64bit_read(cqe, NBL_CQ_IPV4);
	info->solicited_event = (bool)nbl_64bit_read(cqe, NBL_CQ_SOEVENT);
	info->qp_handle = (nbl_qp_handle)(unsigned long)qp;
	info->wqe_idx = (u32)nbl_64bit_read(cqe, NBL_CQ_WQEIDX);
}

static int nbl_parse_cqe_detail(struct nbl_pci_f *rf,
				struct nbl_cq_uk *cq,
				struct nbl_uk_qp *qp,
				struct nbl_cq_poll_info *info)
{
	__be64 *cqe = info->cqe;
	struct nbl_qp *nblqp = qp->back_qp;
	u8 q_type;
	int ret = 0;

	nbl_parse_cqe_common(qp, info);

	q_type = (u8)nbl_64bit_read(cqe, NBL_CQ_SQ);
	if (q_type == NBL_CQE_QTYPE_RQ) {
		nbl_parse_cqe_resp_common(info);
		if (nblqp->ibqp.srq || nblqp->ibqp.xrcd)
			ret = nbl_parse_cqe_for_srq(nblqp, info);
		else
			ret = nbl_parse_cqe_for_resp(rf, cq, qp, info);
	} else {
		ret = nbl_parse_cqe_for_req(rf, cq, qp, info);
	}
	info->q_type = q_type;

	return ret;
}

static void nbl_parse_cqe_errcode(struct nbl_pci_f *rf,
	struct nbl_cq_poll_info *info)
{
	__be64 *cqe = info->cqe;

	info->error = (bool)nbl_64bit_read(cqe, NBL_CQ_ERROR);

	if (info->error) {
		info->major_err = nbl_64bit_read(cqe, NBL_CQ_MAJOR_ERROR);

		if (info->major_err == NBL_ERR_SQ_FLUSH_COMPLETE ||
			info->major_err == NBL_ERR_RQ_FLUSH_COMPLETE)
			info->comp_status = NBL_COMPL_STATUS_FLUSHED;
		else
			info->comp_status = NBL_COMPL_STATUS_UNKNOWN;

		if (info->major_err == NBL_ERR_V2_CQRESIZE_FIGURE)
			info->comp_status = NBL_COMPL_STATUS_RESIZE;
	} else
		info->comp_status = NBL_COMPL_STATUS_SUCCESS;
}

static void nbl_cq_ci_handle(struct nbl_cq *nblcq,
		struct nbl_cq_uk *cq, struct nbl_cq_poll_info *info)
{
	u8 cq_ci_phase;

	if (info->move_cq_head) {
		NBL_RING_MOVE_HEAD_NOCHECK(cq->cq_ring);
		if (!NBL_RING_CURRENT_HEAD(cq->cq_ring))
			cq->polarity ^= 1;

		/* update shadow area cq ci */
		cq_ci_phase = (cq->polarity ^ 1); /* ci phase and polarity is reverse  */
		set_32bit_val((__be32 *)cq->shadow_area, 4,
			FIELD_PREP(NBL_CQ_SHADOWAREA_SCNT, nblcq->sw_sel_cnt) |
			FIELD_PREP(NBL_CQ_SHADOWAREA_CI_PHASE, cq_ci_phase) |
			FIELD_PREP(NBL_CQ_SHADOWAREA_CI, NBL_RING_CURRENT_HEAD(cq->cq_ring)));
	} else {
		/* rewrite the cqe_wqeidx by sq/rq tail, which will be used by next poll*/
		nbl_64bit_write(info->cqe, NBL_CQ_WQEIDX, info->pring->tail);
	}
}

/**
 * nbl_check_cqe_mark_invalid
 * @rf: rf struct
 * @info: cq poll information returned
 * Return: return true for cqe is marked invalid
 */
static inline bool nbl_check_cqe_mark_invalid(struct nbl_pci_f *rf,
	struct nbl_cq_poll_info *info)
{
	return ((bool)nbl_64bit_read(info->cqe, NBL_CQ_V2_MARK_INVALID));
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
	struct nbl_qp *nblqp;
	struct nbl_uk_qp *qp;
	struct nbl_sc_cq *sc_cq = cq->bak_sc_cq;
	struct nbl_cq *nblcq = sc_cq->bak_nbl_cq;
	struct nbl_device *nbldev = to_nbl_dev(nblcq->ibcq.device);
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_frag_buf *nblcq_buf = &cq->bdes.buf.frag_buf;
	__be64 *cqe;
	u8 polarity;
	int cqe_idx;

	cqe_idx = NBL_RING_CURRENT_HEAD(cq->cq_ring);
	cqe = nbl_get_wqe(cq->cq_base, nblcq_buf,
			sizeof(struct nbl_cqe), cqe_idx, cq->bdes.pa_continuous);
	if (!cqe)
		return NBL_ERR_Q_EMPTY;

	polarity = (u8)nbl_64bit_read(cqe, NBL_CQ_VALID);
	if (polarity != cq->polarity)
		return NBL_ERR_Q_EMPTY;

	/* Ensure CQE contents are read after valid bit is checked */
	dma_rmb();

	/* info is cycle use, init first */
	info->pring = NULL;
	info->move_cq_head = true;
	info->cqe = cqe;

	nbl_parse_cqe_errcode(rf, info);
	if (info->comp_status == NBL_COMPL_STATUS_RESIZE) {
		ret_code = NBL_ERR_Q_RESIZE;
		goto exit;
	}

	if (nbl_check_cqe_mark_invalid(rf, info)) {
		ret_code = NBL_ERR_Q_DESTROYED; /* finally repoll */
		goto exit;
	}

	info->qpn = (u32)nbl_64bit_read(cqe, NBL_CQ_QPN);
	if (!*cur_ukqp || (info->qpn != (*cur_ukqp)->qpn)) {
		nblqp = rf->qp_table[info->qpn];
		if (!nblqp)
			*cur_ukqp = NULL;
		else
			*cur_ukqp = &nblqp->sc_qp.uk_qp;
	}
	qp = *cur_ukqp;
	if (!qp || qp->destroy_pending) {
		ret_code = NBL_ERR_Q_DESTROYED; /* finally repoll */
		goto exit;
	}

	ret_code = nbl_parse_cqe_detail(rf, cq, qp, info);

exit:
	if (!ret_code && info->comp_status == NBL_COMPL_STATUS_FLUSHED) {
		/* These code is meaning less, as move cq head has
		 * already set false when cqe detail handle.
		 * todo: del these code when srq is clear.
		 */
		if (info->pring && NBL_RING_MORE_WORK(*(info->pring)))
			info->move_cq_head = false;
	}

	nbl_cq_ci_handle(nblcq, cq, info);

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
	case NBL_ERR_REM_INV_STAT_ERR:
	case NBL_ERR_REM_INV_PD_ERR:
	case NBL_ERR_REM_INV_KEY_ERR:
		wc->status = IB_WC_REM_INV_REQ_ERR;
		break;
	default:
		wc->status = IB_WC_GENERAL_ERR;
		break;
	}
}

static void nbl_fill_sqerr_wc_opcode(struct nbl_qp *qp, struct ib_wc *entry,
			    struct nbl_cq_poll_info *info)
{
	switch (info->ib_op) {
	case IB_WR_RDMA_WRITE:
	case IB_WR_RDMA_WRITE_WITH_IMM:
		entry->opcode = IB_WC_RDMA_WRITE;
		break;
	case IB_WR_SEND:
	case IB_WR_SEND_WITH_IMM:
	case IB_WR_SEND_WITH_INV:
		entry->opcode = IB_WC_SEND;
		break;
	case IB_WR_RDMA_READ:
		entry->opcode = IB_WC_RDMA_READ;
		break;
	case IB_WR_ATOMIC_CMP_AND_SWP:
		entry->opcode = IB_WC_COMP_SWAP;
		break;
	case IB_WR_ATOMIC_FETCH_AND_ADD:
		entry->opcode = IB_WC_FETCH_ADD;
		break;
	case IB_WR_BIND_MW:
		entry->opcode = IB_WC_BIND_MW;
		break;
	case IB_WR_LOCAL_INV:
		entry->opcode = IB_WC_LOCAL_INV;
		break;
	case IB_WR_REG_MR:
		entry->opcode = IB_WC_REG_MR;
		break;
	default:
		nbl_ib_err(qp->sc_qp.sc_dev,
			"SQ ERR with Invalid opcode = %d in CQE and %d in ib op\n",
			info->op_type, info->ib_op);
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

	if (unlikely(cq_poll_info->error &&
		cq_poll_info->q_type == NBL_CQE_QTYPE_SQ))
		nbl_fill_sqerr_wc_opcode(qp, entry, cq_poll_info);
	else {
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
			if ((ukqp->qp_type == IB_QPT_RC ||
				ukqp->qp_type == NBL_IB_QPT_SRP) &&
				cq_poll_info->mkey_valid) {
				entry->ex.invalidate_rkey = cq_poll_info->invalidated_mkey;
				entry->wc_flags |= IB_WC_WITH_INVALIDATE;
			}
			break;
		case NBL_OPCODE_RECV_IMM:
			entry->opcode = IB_WC_RECV;
			entry->wc_flags |= IB_WC_WITH_IMM;
			if ((ukqp->qp_type == IB_QPT_RC ||
				ukqp->qp_type == NBL_IB_QPT_SRP) &&
				cq_poll_info->mkey_valid) {
				entry->ex.invalidate_rkey = cq_poll_info->invalidated_mkey;
				entry->wc_flags |= IB_WC_WITH_INVALIDATE;
			}
			break;
		default:
			nbl_ib_err(qp->sc_qp.sc_dev, "Invalid opcode = %d in CQE\n",
				cq_poll_info->op_type);
			entry->status = IB_WC_GENERAL_ERR;
			return;
		}
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

static void nbl_uk_cq_inc_resized_cnt(struct nbl_cq *nblcq)
{
	struct nbl_cq_uk *ukcq = &nblcq->sc_cq.cq_uk;

	nblcq->sw_sel_cnt++;
	if (nblcq->sw_sel_cnt > NBL_CQ_SW_SEL_CNT_MAX)
		nblcq->sw_sel_cnt = 0;

	set_32bit_val((__be32 *)ukcq->shadow_area, 4,
		FIELD_PREP(NBL_CQ_SHADOWAREA_SCNT, nblcq->sw_sel_cnt));
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
	struct nbl_device *nbldev = to_nbl_dev(nblcq->ibcq.device);
	struct nbl_pci_f *rf = nbldev->rf;
	struct list_head *tmp_node, *list_node;
	struct nbl_cq_buf *cq_buf;
	int npolled = 0;
	enum nbl_status_code ret;
	struct nbl_cq_uk *ukcq;
	struct nbl_cq_poll_info *cur_cqe;
	struct nbl_uk_qp *cur_ukqp = NULL;

	ukcq = &nblcq->sc_cq.cq_uk;
	cur_cqe = &nblcq->cur_cqe;

	/* drain resize cq buffer first */
	list_for_each_safe(list_node, tmp_node, &nblcq->resize_list) {
		cq_buf = container_of(list_node, struct nbl_cq_buf, list);
		while (npolled < num_entries) {
			ret = nbl_poll_one(&cq_buf->cq_uk, &cur_ukqp, cur_cqe, entry + npolled);
			if (!ret) {
				++npolled;
				continue;
			}
			/* QP using the CQ is destroyed, OR
			 * QP wqe is driver ce, OR
			 * SRQ got SRQ NULL,
			 * Skip reporting this CQE.
			 */
			if (ret == NBL_ERR_Q_DESTROYED ||
				ret == NBL_ERR_Q_DRIVER_CE ||
				ret == NBL_ERR_Q_SRQNULL)
				continue;
			/* when we meet special cqe, means we could clear this old buf */
			if (ret == NBL_ERR_Q_RESIZE) {
				list_del(&cq_buf->list);
				queue_work(rf->cleanup_wq, &cq_buf->work);
				nbl_uk_cq_inc_resized_cnt(nblcq);
				break;
			}
			/* special cqe come first, other case there must be something wrong */
			goto error;
		}
	}

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

		/* QP using the CQ is destroyed, OR
		 * QP wqe is driver ce, OR
		 * SRQ got SRQ NULL,
		 * Skip reporting this CQE.
		 */
		if (ret == NBL_ERR_Q_DESTROYED ||
			ret == NBL_ERR_Q_DRIVER_CE ||
			ret == NBL_ERR_Q_SRQNULL)
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

	nblcq = to_nbl_cq(ibcq);

	spin_lock_irqsave(&nblcq->lock, flags);
	ret = __nbl_poll_cq(nblcq, num_entries, entry);
	spin_unlock_irqrestore(&nblcq->lock, flags);

	return ret;
}

static bool nbl_cq_empty(struct nbl_cq *nblcq)
{
	struct nbl_cq_uk *cq = &nblcq->sc_cq.cq_uk;
	struct nbl_frag_buf *nblcq_buf = &cq->bdes.buf.frag_buf;
	int cqe_idx;
	__be64 *cqe;
	u8 polarity;

	if (!list_empty(&nblcq->resize_list))
		return true;

	cqe_idx = NBL_RING_CURRENT_HEAD(cq->cq_ring);
	cqe = nbl_get_wqe(cq->cq_base, nblcq_buf,
			sizeof(struct nbl_cqe), cqe_idx, cq->bdes.pa_continuous);
	if (!cqe)
		return true;

	polarity = (u8)nbl_64bit_read(cqe, NBL_CQ_VALID);

	return polarity != cq->polarity;
}

static void nbl_cq_get_ci_from_shadow(struct nbl_cq_uk *cq, u32 *ci, u8 *ci_phase)
{
	u64 shadow_val;

	get_64bit_val(cq->shadow_area, 0, &shadow_val);
	*ci = (u32)FIELD_GET(NBL_CQ_SHADOWAREA_CI, shadow_val);
	*ci_phase = (u8)FIELD_GET(NBL_CQ_SHADOWAREA_CI_PHASE, shadow_val);

	nbl_pr_dbg("get ci from shadow: ci %u, phase %u\n", *ci, *ci_phase);
}

/**
 * nbl_cq_v1_request_notification - cq notification request (only V1R1 use)
 * @rf: RDMA PCI function
 * @cq: hw cq
 * @cq_notify: notification type
 */
static void nbl_cq_v1_request_notification(struct nbl_pci_f *rf, struct nbl_cq *nblcq,
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
			FIELD_PREP(NBL_REG_ARM_CQ_REG0_ARM_CQ_CI_PHASE, cq_ci_phase) |
			FIELD_PREP(NBL_REG_ARM_CQ_REG0_ARM_CQ_CI, cq_ci));
	write64_reg(value_arm, sc_dev->hw_regs[NBL_ARM_CQ]);
}

/**
 * nbl_cq_v2_request_notification - cq notification request (arm cq)
 * @rf: RDMA PCI function
 * @cq: hw cq
 * @cq_notify: notification type
 */
static void nbl_cq_v2_request_notification(struct nbl_pci_f *rf, struct nbl_cq *nblcq,
		      enum nbl_cmpl_notify cq_notify)
{
	u8 cq_ci_phase;
	u32 cq_ci;
	u64 value_arm;
	u32 cq_id;
	struct nbl_cq_uk *ukcq = &nblcq->sc_cq.cq_uk;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;

	cq_id = ukcq->cq_id;
	cq_ci_phase = (ukcq->polarity ^ 1);
	cq_ci = NBL_RING_CURRENT_HEAD(ukcq->cq_ring);

	value_arm = (FIELD_PREP(NBL_REG_ARM_CQ_V2_REG1_ARM_CQN, cq_id) |
			FIELD_PREP(NBL_REG_ARM_CQ_V2_REG1_SW_SEL_CNT, nblcq->sw_sel_cnt) |
			FIELD_PREP(NBL_REG_ARM_CQ_V2_REG1_ARM_NEXT,
			(cq_notify == NBL_CQ_COMPL_SOLICITED ? 0 : 1)) |
			FIELD_PREP(NBL_REG_ARM_CQ_V2_REG0_ARM_CQ_CI_PHASE, cq_ci_phase) |
			FIELD_PREP(NBL_REG_ARM_CQ_V2_REG0_ARM_CQ_CI, cq_ci));
	if (rf->sc_dev.cem_enable)
		value_arm |= FIELD_PREP(NBL_REG_ARM_CQ_V2_SEQ_NUM, nblcq->arm_seq_num);
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

/**
 * nbl_ib_v1_req_notify_cq - arm cq kernel application, V1R1 Only
 * @ibcq: ib cq to arm
 * @notify_flags: notification flags
 */
int nbl_ib_v1_req_notify_cq(struct ib_cq *ibcq,
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

	nblcq = to_nbl_cq(ibcq);
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
			nbl_cq_v1_request_notification(rf, nblcq, cq_notify);
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
				nbl_cq_v1_request_notification(rf, nblcq, cq_notify);
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
 * nbl_ib_v2_req_notify_cq - arm cq kernel application gen2
 * @ibcq: ib cq to arm
 * @notify_flags: notification flags
 */
int nbl_ib_v2_req_notify_cq(struct ib_cq *ibcq,
			 enum ib_cq_notify_flags notify_flags)
{
	struct nbl_cq *nblcq;
	unsigned long flags_cq;
	bool do_arm = false;
	bool need_rdb = false;
	enum nbl_cmpl_notify cq_notify = NBL_CQ_COMPL_EVENT;
	struct nbl_device *nbldev = to_nbl_dev(ibcq->device);
	struct nbl_pci_f *rf = nbldev->rf;
	int ret = 0;

	nblcq = to_nbl_cq(ibcq);

	spin_lock_irqsave(&nblcq->lock, flags_cq);
	if (notify_flags == IB_CQ_SOLICITED)
		cq_notify = NBL_CQ_COMPL_SOLICITED;
	else {
		if (nblcq->last_notify == NBL_CQ_COMPL_SOLICITED)
			do_arm = true;
	}
	if (!atomic_cmpxchg(&nblcq->armed, 0, 1) || do_arm) {
		nblcq->last_notify = cq_notify;
		need_rdb = true;
		if (rf->sc_dev.cem_enable)
			nblcq->arm_seq_num++;
	}
	if ((notify_flags & IB_CQ_REPORT_MISSED_EVENTS) &&
		!list_empty(&nblcq->wc_list))
		ret = EPERM;
	spin_unlock_irqrestore(&nblcq->lock, flags_cq);

	if (need_rdb)
		nbl_cq_v2_request_notification(rf, nblcq, cq_notify);

	return ret;
}

static int nbl_cqp_modify_cq_moderation(struct nbl_pci_f *rf,
	struct nbl_cq *nblcq, u16 cq_count, u16 cq_period)
{
	__be64 cmd_in[NBL_CMD_INPUT_SIZE / sizeof(u64)] = {0};
	int ret;

	nbl_64bit_write(cmd_in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_CE_MOD_CQ);
	nbl_64bit_write(cmd_in, NBL_CQP_V2_CQ_CQID, nblcq->cq_num);
	nbl_64bit_write(cmd_in, NBL_CQP_V2_CQ_CE_MDN, 1);
	nbl_64bit_write(cmd_in, NBL_CQP_V2_CQ_PERIOD, cq_period);
	nbl_64bit_write(cmd_in, NBL_CQP_V2_CQ_MAXCNT, cq_count);

	ret = nbl_cmd_exec(rf, cmd_in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (ret)
		nbl_ib_err(&rf->sc_dev, "[CQ MOD] ce mod cq execute failed(%d)\n", ret);

	return ret;
}

const struct nbl_cq_ops nbl_common_cq_ops = {
	.cq_moderation_supported = false,
};

const struct nbl_cq_ops nbl_rnic400_cq_ops = {
	.set_cq_moderation = nbl_cqp_modify_cq_moderation,
	.cq_moderation_supported = true,
};

int nbl_ib_modify_cq(struct ib_cq *cq, u16 cq_count, u16 cq_period)
{
	struct nbl_device *nbldev = to_nbl_dev(cq->device);
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_cq *nblcq = to_nbl_cq(cq);
	int err;

	if (!rf->product->cq_ops->cq_moderation_supported)
		return -EOPNOTSUPP;

	if (cq_period > NBL_MAX_CQ_PERIOD || cq_count > NBL_MAX_CQ_COUNT)
		return -EINVAL;

	err = rf->product->cq_ops->set_cq_moderation(rf, nblcq, cq_count,
						      cq_period);
	if (err)
		nbl_ib_err(&rf->sc_dev, "ce modify cq 0x%x failed\n", nblcq->cq_num);

	return err;
}

int nbl_cqp_v2_cq_cqc_ref_sub(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq)
{
	int ret;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;
	u32 cq_id = sc_cq->cq_uk.cq_id;

	in = kzalloc(in_size, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_MODIFY_CQ);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_STAT, NBL_CQ_STAT_VALID);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_QP_REF, NBL_CQ_CQC_REF_SUB);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_CQID, cq_id);

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);

	kfree(in);

	return ret;
}

int nbl_cqp_v2_cq_cqc_ref_add(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq)
{
	int ret;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;
	u32 cq_id = sc_cq->cq_uk.cq_id;

	in = kzalloc(in_size, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_MODIFY_CQ);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_STAT, NBL_CQ_STAT_VALID);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_QP_REF, NBL_CQ_CQC_REF_ADD);
	nbl_64bit_write(in, NBL_CQP_V2_CQ_CQID, cq_id);

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

	ret = rf->cqp_ops->cqp_cq_ref_add(rf, &cq->sc_cq);

	return ret;
}

int nbl_dec_cqc_ref(struct nbl_cq *cq)
{
	struct ib_device *ibdev = cq->ibcq.device;
	struct nbl_device *nbldev = to_nbl_dev(ibdev);
	struct nbl_pci_f *rf = nbldev->rf;
	int ret = 0;

	ret = rf->cqp_ops->cqp_cq_ref_sub(rf, &cq->sc_cq);

	return ret;
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
static void nbl_uk_clean_cqes(struct nbl_sc_dev *sc_dev,
	struct nbl_cq *nblcq, u32 qpn)
{
	struct nbl_cq_uk *cq = &nblcq->sc_cq.cq_uk;
	struct nbl_frag_buf *nblcq_buf = &cq->bdes.buf.frag_buf;
	u8 invalid_fig;
	__be64 *cqe;
	u32 cq_head;
	u32 qpn_in_cqe;
	u8 polarity, temp;

	cq_head = cq->cq_ring.head;
	temp = cq->polarity;

	do {
		cqe = nbl_get_wqe(cq->cq_base, nblcq_buf,
			sizeof(struct nbl_cqe), cq_head, cq->bdes.pa_continuous);
		if (!cqe) {
			nbl_pr_err("get cqe failed when clean cq\n");
			return;
		}

		polarity = (u8)nbl_64bit_read(cqe, NBL_CQ_VALID);
		if (polarity != temp)
			break;

		/* Ensure CQE contents are read after valid bit is checked */
		dma_rmb();

		/* V2R1 and DF200 we use a special bit provided by
		 * HW, and HW alwasy write this bit to 0, just write
		 * this bit to 1 to mark a cqe invalid.
		 */
		invalid_fig = (u8)nbl_64bit_read(cqe, NBL_CQ_V2_MARK_INVALID);
		if (invalid_fig != NBL_CQ_V2_MARK_INVALID_VAL) {
			qpn_in_cqe = (u32)nbl_64bit_read(cqe, NBL_CQ_QPN);
			if (qpn_in_cqe == qpn)
				nbl_64bit_write(cqe, NBL_CQ_V2_MARK_INVALID,
					NBL_CQ_V2_MARK_INVALID_VAL);
		}

		cq_head = (cq_head + 1) % cq->cq_ring.size;
		if (!cq_head)
			temp ^= 1;
	} while (true);
}

void nbl_clean_cqes(struct nbl_sc_dev *sc_dev, struct nbl_cq *nblcq, u32 qpn)
{
	unsigned long flags;

	spin_lock_irqsave(&nblcq->lock, flags);
	nbl_uk_clean_cqes(sc_dev, nblcq, qpn);
	nbl_uk_clean_soft_wc(nblcq, qpn);
	spin_unlock_irqrestore(&nblcq->lock, flags);
}

int nbl_dump_hmc_cqc(struct nbl_device *nbl_dev, u32 dump_mask)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_hmc_obj_sd_info *cq_sd_info = rf->cq_sd_info;
	u32 num_one_page; /* how many cqc in one page */
	u32 page_index; /* page index that cqc located */
	u32 cqc_index; /* cqc index in a page */
	struct nbl_hmc_obj_sd_addr *sd;
	u32 cq_num;
	struct nbl_func_file *func_file = &nbl_dev->func_dump_info->dump_func_file;

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

	write_to_file_buffer(func_file,
		"[cqc] dump cqn(%u) cqc(sd va %p, 0x%llx, offset 0x%x)",
		cq_num, sd->va, (u64)((uintptr_t)sd->va), (cqc_index * NBL_CQ_CTX_SIZE));
	nbl_dump_fields(rf, func_file,
	(sd->va + (cqc_index * NBL_CQ_CTX_SIZE)), NBL_DBG_DUMP_CQC);
	return 0;
}

int nbl_dbg_v2_create_cq(struct nbl_pci_f *rf, u32 cqn_input)
{
	/* TODO, depends need */
	return 0;
}

int nbl_dbg_v2_destroy_cq(struct nbl_pci_f *rf, u32 cqn_input)
{
	/* TODO, depends */
	return 0;
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
		((!is_sq) && ukqp->rq_flush_complete)) {
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

static void nbl_free_cqbuf(struct work_struct *work)
{
	struct nbl_cq_buf *cq_buf = container_of(work, struct nbl_cq_buf, work);

	nbl_kernel_buf_free(cq_buf->hw, &cq_buf->cq_uk.bdes);
	kfree(cq_buf);
}

static void nbl_uk_cq_resize(struct nbl_cq_uk *cq, struct nbl_modify_cq_info *info)
{
	memcpy(&cq->bdes, &info->bdes, sizeof(cq->bdes));
	cq->cq_base = info->cq_base;
	cq->cq_size = info->cq_size;
	cq->shadow_rd_thd = info->shadow_rd_thd;
	NBL_RING_INIT(cq->cq_ring, cq->cq_size);
	cq->polarity = 1;
}

static void nbl_sc_cq_resize(struct nbl_sc_cq *sc_cq, struct nbl_modify_cq_info *info)
{
	nbl_uk_cq_resize(&sc_cq->cq_uk, info);
}

int nbl_ib_resize_cq(struct ib_cq *ibcq, int entries, struct ib_udata *udata)
{
	struct nbl_cq *nblcq = to_nbl_cq(ibcq);
	struct nbl_cq_uk *ukcq = &nblcq->sc_cq.cq_uk;
	struct nbl_device *nbldev = to_nbl_dev(ibcq->device);
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_resize_cq_req ucmd = {};
	struct nbl_modify_cq_info info = {};
	struct nbl_cq_buf *cq_buf = NULL;
	struct nbl_user_rsize *ursize = NULL;
	struct nbl_ucontext *uctx;
	unsigned long flags;
	int rsize;
	int ret;

	if (udata) {
		ret = nbl_uresize_handle(nbldev, nblcq, udata, &ucmd);
		if (ret)
			return ret;
	}

	if (!nblcq->user_mode) {
		entries++;
		if (entries < sc_dev->hw_attrs.uk_attrs.min_hw_cq_size)
			entries = sc_dev->hw_attrs.uk_attrs.min_hw_cq_size;
		info.cq_size = roundup_pow_of_two(entries);
	} else
		info.cq_size = entries;

	if (info.cq_size == ukcq->cq_size)
		return 0;

	if (udata) {
		ursize = kzalloc(sizeof(*ursize), GFP_KERNEL);
		if (!ursize)
			return -ENOMEM;
		uctx = nblcq->uctx;
		ret = nbl_user_buf_get(&uctx->ibucontext, nbldev,
				ucmd.user_cq_buffer, ucmd.cq_buf_size, &info.bdes, udata);
		if (ret)
			goto error;
		memcpy(&ursize->bdes, &ukcq->bdes, sizeof(ursize->bdes));
		list_add_tail(&ursize->list, &nblcq->u_resize_list);
	} else {
		cq_buf = kzalloc(sizeof(*cq_buf), GFP_KERNEL);
		if (!cq_buf)
			return -ENOMEM;

		rsize = info.cq_size * sizeof(struct nbl_cqe);
		ret = nbl_kernel_buf_alloc(sc_dev->hw, rsize, &info.bdes);
		if (ret)
			goto error;
	}
	info.cq_base_pa = info.bdes.kmem.pa;
	info.cq_base = info.bdes.kmem.va;
	info.shadow_rd_thd = nbl_cq_shadow_rd_thd_calc(info.cq_size);

	ret = rf->cqp_ops->cqp_cq_resize(rf, &nblcq->sc_cq, &info);
	if (ret)
		goto buf_free;

	spin_lock_irqsave(&nblcq->lock, flags);
	if (cq_buf) {
		cq_buf->hw = sc_dev->hw;
		memcpy(&cq_buf->cq_uk, ukcq, sizeof(cq_buf->cq_uk));
		INIT_WORK(&cq_buf->work, nbl_free_cqbuf);
		list_add_tail(&cq_buf->list, &nblcq->resize_list);
	}
	nbl_sc_cq_resize(&nblcq->sc_cq, &info);
	ibcq->cqe = info.cq_size - 1;
	spin_unlock_irqrestore(&nblcq->lock, flags);

	return 0;

buf_free:
	if (udata)
		nbl_user_buf_release(nbldev, &info.bdes);
	else
		nbl_kernel_buf_free(sc_dev->hw, &info.bdes);
error:
	if (!udata)
		kfree(cq_buf);
	else
		kfree(ursize);

	return ret;
}
