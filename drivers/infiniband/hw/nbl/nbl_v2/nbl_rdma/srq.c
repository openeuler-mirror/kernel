// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/bitfield.h>
#include <rdma/nbl-v2-abi.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_verbs.h>
#include "main.h"
#include "srq.h"
#include "mem.h"
#include "cqp.h"
#include "pd.h"

static int nbl_get_ddr_srqc_shdw_addr(u32 srq_num,
				struct nbl_hmc_obj_sd_info *srq_sd_info,
				struct nbl_ctx_hmc_base_info *hmc_info)
{
	u32 num_one_page; /* how many srqc in one page */
	u32 page_index; /* page index that qpc located */
	u32 srq_index;
	struct nbl_hmc_obj_sd_addr *sd;

	/* 4K/16 = 256 */
	num_one_page = srq_sd_info->page_sz / NBL_HMC_SRQ_SHADOW_SZ;

	/* get page index, for srqn=513 we got 2 */
	page_index = srq_num / num_one_page;
	if (page_index >= srq_sd_info->cnt) {
		nbl_pr_err("invalid page_index, the page_index is %u.\n",
			   page_index);
		return -EFAULT;
	}
	srq_index = srq_num % num_one_page;

	sd = &srq_sd_info->sd_addr[page_index];

	hmc_info->va = sd->va;
	hmc_info->pa = sd->dma_addr;
	hmc_info->ctx_size = NBL_HMC_SRQC_SZ;
	hmc_info->shadow_offset = (srq_index * NBL_HMC_SRQ_SHADOW_SZ);
	hmc_info->shadow_size = NBL_HMC_SRQ_SHADOW_SZ;
	hmc_info->page_size = srq_sd_info->page_sz;

	return 0;
}

static int nbl_get_srqc_base_addr(struct nbl_pci_f *rf, u32 srq_num,
				 struct nbl_hmc_obj_sd_info *srq_sd_info,
				 struct nbl_ctx_hmc_base_info *hmc_info)
{
	u32 num_one_page; /* how many srqc in one page */
	u32 page_index; /* page index that srqc located */
	u32 srqc_index;
	struct nbl_hmc_obj_sd_addr *sd;

	if (rf->sc_dev.ddr_mode_en)
		return nbl_get_ddr_srqc_shdw_addr(srq_num, srq_sd_info, hmc_info);

	/* for 4K, here we got 4096/64=64 */
	num_one_page = srq_sd_info->page_sz / NBL_HMC_SRQC_SZ;

	/* get page index, for srqn=65 we got 1 */
	page_index = srq_num / num_one_page;
	if (page_index >= srq_sd_info->cnt) {
		nbl_pr_err("invalid page_index, the page_index is %u.\n",
			   page_index);
		return -EFAULT;
	}
	srqc_index = srq_num % num_one_page;

	sd = &srq_sd_info->sd_addr[page_index];

	hmc_info->va = sd->va;
	hmc_info->pa = sd->dma_addr;
	hmc_info->ctx_size = NBL_HMC_SRQC_SZ;
	hmc_info->shadow_offset = (srqc_index * NBL_HMC_SRQC_SZ) + NBL_SRQ_SHADOW_OFFST;
	hmc_info->shadow_size = NBL_HMC_SRQ_SHADOW_SZ;
	hmc_info->page_size = srq_sd_info->page_sz;

	return 0;
}

static int nbl_user_srq_shadow(struct nbl_pci_f *rf, struct nbl_srq *srq,
			       struct ib_udata *udata,
			       struct nbl_ib_create_srq_resp *uresp)
{
	struct nbl_ucontext *uctx;
	struct nbl_hmc_obj_sd_info *srq_sd_info = rf->srq_sd_info;
	struct nbl_ctx_hmc_base_info hmc_info;
	int ret;
	struct shadow_node *srqc_shadow = NULL;
	u32 map_size;

	uctx = rdma_udata_to_drv_context(udata, struct nbl_ucontext,

					 ibucontext);

	ret = nbl_get_srqc_base_addr(rf, srq->srqn, srq_sd_info, &hmc_info);
	if (ret) {
		nbl_pr_err("get nbl srqc base addr failed.\n");
		return ret;
	}

	uresp->shadow_base_addr = hmc_info.pa;
	uresp->srqc_size = hmc_info.ctx_size;
	uresp->shadow_offset = hmc_info.shadow_offset;
	uresp->shadow_size = hmc_info.shadow_size;
	uresp->page_size = hmc_info.page_size;

	srq->shdw.va = hmc_info.va + hmc_info.shadow_offset;
	srq->shdw.pa = hmc_info.pa + hmc_info.shadow_offset;
	srq->shdw.size = hmc_info.shadow_size;

	map_size = uresp->page_size <= PAGE_SIZE ? PAGE_SIZE : uresp->page_size;
	srqc_shadow = nbl_find_shadow_mmap(uctx, uresp->shadow_base_addr, map_size);
	if (!srqc_shadow) {
		nbl_pr_dbg(
			"not find valid shadow node, and start to add new shadow node.\n");
		return nbl_add_shadow_mmap(uctx, hmc_info.va, uresp->shadow_base_addr,
					   map_size);
	}

	return 0;
}

static int nbl_kernel_srq_shadow(struct nbl_pci_f *rf, struct nbl_srq *srq)
{
	struct nbl_hmc_obj_sd_info *srq_sd_info = rf->srq_sd_info;
	struct nbl_ctx_hmc_base_info hmc_info;
	int ret;

	ret = nbl_get_srqc_base_addr(rf, srq->srqn, srq_sd_info, &hmc_info);
	if (ret) {
		nbl_pr_err("get nbl srqc base addr failed.\n");
		return ret;
	}
	srq->shdw.va = hmc_info.va + hmc_info.shadow_offset;
	srq->shdw.pa = hmc_info.pa + hmc_info.shadow_offset;
	srq->shdw.size = hmc_info.shadow_size;

	return 0;
}

void free_subq_item(struct nbl_sc_dev *sc_dev, struct nbl_srq *srq, struct nbl_srq_subq *subq)
{
	if (subq) {
		/* user mode srq only page_mode 1 has allocated dma mem
		 * kernel mode srq both page_mode allocated dma
		 */
		if ((srq->user_mode && subq->page_mode && subq->mem.va) ||
			(!srq->user_mode && subq->mem.va))
			dma_free_coherent(sc_dev->hw->device, subq->mem.size,
						subq->mem.va, subq->mem.pa);
		if (!IS_ERR(subq->subq_buf.umem))
			nbl_ib_umem_release(subq->subq_buf.umem, subq->subq_buf.nbl_peer);
		if (subq->subq_buf.frag_buf.frags)
			nbl_frag_buf_free(sc_dev->hw, subq->mem.va, subq->mem.pa,
				  &subq->subq_buf.frag_buf);
		kfree(subq);
	}
}

void free_subq(struct nbl_sc_dev *sc_dev, struct nbl_srq *srq, struct nbl_srq_subq **subq_arr)
{
	int j;

	for (j = 0; j < SRQ_SUBQ_NUM; j++)
		free_subq_item(sc_dev, srq, subq_arr[j]);

	kfree(subq_arr);
}

int nbl_create_subq_user(struct nbl_srq *srq, struct nbl_device *dev,
			u64 *buf_base, u32 buf_size, struct ib_udata *udata,
			u8 sorted_indices[], u64 sorted_ba[], u32 *page_0_num)
{
	struct nbl_sc_dev *sc_dev = &dev->rf->sc_dev;
	struct nbl_srq_subq **subq_arr;
	struct nbl_srq_subq *subq;
	int err;
	u32 pg_num, copy_num;
	bool is_contiguous;
	int head = 0, tail = SRQ_SUBQ_NUM - 1;
	int i;

	/* alloc buffer to subq_arr */
	subq_arr = kcalloc(SRQ_SUBQ_NUM, sizeof(struct nbl_srq_subq *), GFP_KERNEL);
	if (!subq_arr)
		return -ENOMEM;

	*page_0_num = 0;
	/* alloc buffer to each subq, and set attrs */
	for (i = 0; i < SRQ_SUBQ_NUM; i++) {
		subq = kcalloc(1, sizeof(struct nbl_srq_subq), GFP_KERNEL);
		if (!subq) {
			err = -ENOMEM;
			goto err_free_subq_arr_item;
		}
		/* buf_base from user is sorted by subq_id,
		 * so buf_base[i] represents subq i
		 */
		subq->subq_id = i;
		subq->nxt_wqe_phase = 1;

		subq->subq_buf.nbl_peer = false;
		/* maybe gpu mem */
#ifdef CONFIG_INFINIBAND_PEER_MEMORY
		subq->subq_buf.umem =
			ib_umem_get_peer(&dev->ibdev, buf_base[i], buf_size,
				IB_ACCESS_LOCAL_WRITE, 0);
#else
		subq->subq_buf.umem =
			ib_umem_get(&dev->ibdev, buf_base[i], buf_size,
				    IB_ACCESS_LOCAL_WRITE);
#endif
		if (IS_ERR(subq->subq_buf.umem)) {
			nbl_ib_err(sc_dev, "pin and dma map addr failed.\n");
			err = PTR_ERR(subq->subq_buf.umem);
			goto err_free_cur_subq;
		}

		nbl_get_umem_info(subq->subq_buf.umem, &pg_num, &is_contiguous, false);

		/* page_mode 0 or 1
		 * page mode 0 add to arr head, page mode 1 add to arr tail
		 */
		if (is_contiguous) {
			subq->page_mode = NBL_LEVEL0_PAGE_MODE;
			subq->mem.va = (void *)(uintptr_t)buf_base[i];
			subq->mem.pa = nbl_get_first_sg_dma_addr(subq->subq_buf.umem);
			subq_arr[head++] = subq;
			(*page_0_num)++;
		} else {
			subq->page_mode = NBL_LEVEL1_PAGE_MODE;
			subq->mem.size = NBL_ADAPTER_PAGE_SIZE;
			subq->mem.va = nbl_dma_alloc_coherent(sc_dev->hw,
					    subq->mem.size, &subq->mem.pa,
					    GFP_KERNEL);
			if (!subq->mem.va) {
				nbl_ib_err(sc_dev, "subq page 1 dma alloc coherent failed.\n");
				err = NBL_ERR_ALLOCMEM_FAILED;
				goto err_free_cur_subq;
			}
			err = nbl_copy_user_pgaddrs(subq->subq_buf.umem, subq->mem.va,
							subq->mem.size, pg_num, &copy_num);
			if (err) {
				nbl_ib_err(sc_dev, "copy nbl user pgaddrs failed.\n");
				goto err_free_cur_subq;
			}
			subq_arr[tail--] = subq;
		}
	}

	/* fill sorted_indices, page_0_num and revalue subq_id, sw_srq_pi_phase */
	for (i = 0; i < SRQ_SUBQ_NUM; i++) {
		sorted_indices[i] = subq_arr[i]->subq_id;
		subq_arr[i]->subq_id = i;
		subq_arr[i]->sw_srq_pi_phase = (i % 2 == 0) ? false : true;
		sorted_ba[i] = subq_arr[i]->mem.pa;
		nbl_ib_dbg(sc_dev, "[SRQ subq user create] subq_id: %d, page_mode: %d, ba: %llx",
			subq_arr[i]->subq_id, subq_arr[i]->page_mode, sorted_ba[i]);
	}
	srq->subq_arr = subq_arr;
	return 0;

err_free_cur_subq:
	free_subq_item(sc_dev, srq, subq);
err_free_subq_arr_item:
	free_subq(sc_dev, srq, subq_arr);
	return err;
}

int nbl_create_subq_kernel(struct nbl_srq *srq, struct nbl_device *dev, u32 buf_size, u16 max_wqe)
{
	struct nbl_sc_dev *sc_dev = &dev->rf->sc_dev;
	struct nbl_srq_subq **subq_arr;
	struct nbl_srq_subq *subq;
	struct nbl_dma_mem *mem;
	struct nbl_ib_subq_buf *subq_buf;
	int i, err = 0;
	int head = 0, tail = SRQ_SUBQ_NUM - 1;

	/* alloc buffer to subq_arr */
	subq_arr = kcalloc(SRQ_SUBQ_NUM, sizeof(struct nbl_srq_subq *), GFP_KERNEL);
	if (!subq_arr)
		return -ENOMEM;

	for (i = 0; i < SRQ_SUBQ_NUM; i++) {
		/* alloc buffer to subq struct */
		subq = kcalloc(1, sizeof(struct nbl_srq_subq), GFP_KERNEL);
		if (!subq) {
			err = -ENOMEM;
			goto err_free_subq_arr_item;
		}
		mem = &subq->mem;
		subq_buf = &subq->subq_buf;
		subq_buf->umem = NULL;
		mem->size = buf_size;
		/* alloc buf to subq */
		mem->va = dma_alloc_coherent(dev->rf->sc_dev.hw->device, mem->size,
				    &mem->pa, GFP_KERNEL);
		subq_buf->frag_buf.size = mem->size;
		if (mem->va) {
			memset(mem->va, 0, mem->size);
			subq->page_mode = NBL_LEVEL0_PAGE_MODE;
			subq_buf->frag_buf.npages = 1;
			subq_arr[head++] = subq;
		} else {
			subq->page_mode = NBL_LEVEL1_PAGE_MODE;
			subq_buf->frag_buf.npages = DIV_ROUND_UP(mem->size, NBL_ADAPTER_PAGE_SIZE);
			/* alloc buf for page mode 1 */
			err = nbl_frag_buf_alloc(dev->rf->sc_dev.hw, &mem->va,
					   &mem->pa, &subq_buf->frag_buf);
			if (err)
				goto err_free_cur_subq;

			subq_arr[tail--] = subq;
		}
	}

	/* fill subq_id, nxt_wqe_phase, sw_srq_pi_pahse and other attrs */
	for (i = 0; i < SRQ_SUBQ_NUM; i++) {
		subq_arr[i]->subq_id = i;
		subq_arr[i]->nxt_wqe_phase = 1;
		subq_arr[i]->sw_srq_pi_phase = (i % 2 == 0) ? false : true;
		subq_arr[i]->buf_size = buf_size;
		subq_arr[i]->buf_quanta = buf_size / NBL_WQE_QUANTA_SIZE;
		subq_arr[i]->pi = 0;
		subq_arr[i]->ci = 0;
		subq_arr[i]->has_pi = (i == 0) ? true : false;
		subq_arr[i]->has_ci = (i == 0) ? true : false;
		subq_arr[i]->finish_wqe_count = 0;
		subq_arr[i]->max_wqe = max_wqe;
		subq_arr[i]->prevq = (i == 0) ? NULL : subq_arr[i - 1];
		subq_arr[i]->nextq = (i == SRQ_SUBQ_NUM - 1) ? NULL : subq_arr[i + 1];
		nbl_ib_dbg(sc_dev, "[SRQ subq kernel create] subq_id: %d, buf_size: %d, page_mode: %d, ba: %llx",
			subq_arr[i]->subq_id, subq_arr[i]->buf_size,
			subq_arr[i]->page_mode, (u64)subq_arr[i]->mem.pa);
	}
	srq->subq_arr = subq_arr;
	return 0;

err_free_cur_subq:
	free_subq_item(sc_dev, srq, subq);
err_free_subq_arr_item:
	free_subq(sc_dev, srq, subq_arr);
	return err;
}

static void nbl_set_srq_ext_param(struct nbl_srq *srq, struct ib_srq_init_attr *init_attr)
{
	srq->cqn = ib_srq_has_cq(init_attr->srq_type) ?
			to_nbl_cq(init_attr->ext.cq)->cq_num : 0;
	srq->xrcdn = (init_attr->srq_type == IB_SRQT_XRC) ?
			to_nbl_xrcd(init_attr->ext.xrc.xrcd)->xrcdn : SRQ_XRCDN_INV_VAL;
}

void nbl_srq_add_ref(struct nbl_srq *srq)
{
	refcount_inc(&srq->refcnt);
}

void nbl_srq_rem_ref(struct ib_srq *ibsrq)
{
	struct nbl_srq *srq = to_nbl_srq(ibsrq);
	struct nbl_device *nbldev = srq->nbldev;
	struct nbl_pci_f *rf = nbldev->rf;
	u32 srq_num;
	unsigned long flags;

	spin_lock_irqsave(&rf->srqtable_lock, flags);
	if (!refcount_dec_and_test(&srq->refcnt)) {
		nbl_ib_dbg(&rf->sc_dev, "refcnt is not zero.\n");
		spin_unlock_irqrestore(&rf->srqtable_lock, flags);
		return;
	}

	srq_num = srq->srqn;
	rf->srq_table[srq_num] = NULL;
	spin_unlock_irqrestore(&rf->srqtable_lock, flags);
	complete(&srq->free_srq);
}

static int nbl_check_srq_init_attr(struct nbl_sc_dev *dev,
							struct nbl_uk_attrs *uk_attrs,
							struct ib_srq_init_attr *init_attr)
{
	/* check attr */
	if (init_attr->attr.max_wr > uk_attrs->max_hw_srq_wr) {
		nbl_ib_err(dev, "srq init_attr max_wr %d, max_hw_srq_wr %d\n",
				init_attr->attr.max_wr, uk_attrs->max_hw_srq_wr);
		return -EINVAL;
	}

	if (init_attr->attr.max_sge > uk_attrs->max_hw_wq_sges) {
		nbl_ib_err(dev, "srq init_attr max_sge %d, max_hw_wq_sges %d\n",
				init_attr->attr.max_sge, uk_attrs->max_hw_wq_sges);
		return -EINVAL;
	}

	return 0;
}

static int cal_srq_attrs(struct ib_srq_init_attr *init_attr,
					struct nbl_sc_dev *dev, struct nbl_pci_f *rf,
					u32 *size, u32 *buf_size, u32 *srqn)
{
	int err;
	int max_wr;

	*size = RQ_CTRL_SEG_BYTES + max_t(u32, init_attr->attr.max_sge, MIN_WR_SGE)
		* RQ_DATA_SEG_BYTES;
	*size = roundup_pow_of_two(*size);
	if (*size > SRQ_BIGGEST_WQE_SIZE) {
		nbl_ib_err(dev, "srqe size %d, SRQ_BIGGEST_WQE_SIZE %d\n",
				*size, SRQ_BIGGEST_WQE_SIZE);
		return -EINVAL;
	}

	/* cal bufsize and align up by 4K, at least 16K */
	*buf_size = MAX_SRQ_SUBQ_SIZE;
	max_wr = (*buf_size)/(*size);
	if (init_attr->attr.max_wr > max_wr) {
		nbl_ib_err(dev,
		"create srq wr > max wr. max_sge: %d, max_wr: %d, cal_wqe_size: %d, cal_wqe_num: %d\n",
		init_attr->attr.max_sge, init_attr->attr.max_wr,
		*size, max_wr);
		return -EINVAL;
	}

	nbl_ib_dbg(dev, "[SRQ attrs] srqe size %d, buf_size %d", *size, *buf_size);

	/* alloc srqn */
	err = nbl_alloc_rsrc(&rf->rsrc_lock, rf->allocated_srq,
				       rf->max_srq, srqn, &rf->next_srq);
	if (err) {
		nbl_ib_err(dev, "alloc srqn failed.\n");
		return err;
	}

	return 0;
}

static int set_srq_common_attrs(struct nbl_device *nbldev,
							struct nbl_srq *srq,
							u32 srqn, u32 size, u32 buf_size,
							u32 subq_buf_quanta, u8 user_mode)
{
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_sc_dev *dev = &rf->sc_dev;

	srq->nbldev = nbldev;
	srq->hw_srq_ci_rth = SRQ_HW_SRQ_CI_RTH;
	srq->srq_db0 = dev->hw_regs[NBL_SRQ_DB0];
	srq->srq_db1 = dev->hw_regs[NBL_SRQ_DB1];
	srq->srqn = srqn;
	srq->db0_count = 0;
	srq->nxt_queue_num = 0;
	srq->wqe_ts = size / NBL_WQE_QUANTA_SIZE;
	srq->subq_buf_quanta = subq_buf_quanta;
	srq->user_mode = user_mode;
	srq->max_wr = buf_size / size;
	srq->max_sge = (size - RQ_CTRL_SEG_BYTES) / RQ_DATA_SEG_BYTES;
	srq->max_wr_shift = ilog2(srq->max_wr);
	srq->wqe_quanta = size / NBL_WQE_QUANTA_SIZE;
	srq->wrid = kvmalloc_array(SRQ_SUBQ_NUM << srq->max_wr_shift, sizeof(u64), GFP_KERNEL);

	nbl_ib_dbg(dev, "[SRQ attrs] srqn %d, wqe_ts %d, subq_buf_quanta %d, max_wr %d,  max_sge %d, max_wr_shift %d, wqe_quanta %d",
		srq->srqn, srq->wqe_ts,
		srq->subq_buf_quanta, srq->max_wr, srq->max_sge, srq->max_wr_shift,
		srq->wqe_quanta);
	if (!srq->wrid) {
		nbl_ib_err(dev, "alloc wrid array failed.\n");
		return -ENOMEM;
	}

	return 0;
}

static int fill_create_srq_resp(struct nbl_ib_create_srq_resp *resp,
						struct nbl_sc_dev *dev,
						struct nbl_srq *srq,
						u32 page_0_num, u8 sorted_indices[],
						u64 sorted_ba[], struct ib_udata *udata)
{
	int err;

	resp->srqn = srq->srqn;
	resp->seq_num = srq->seq_num;
	resp->page_0_num = page_0_num;
	memcpy(resp->sorted_indices, sorted_indices, sizeof(resp->sorted_indices));
	memcpy(resp->sorted_ba, sorted_ba, sizeof(resp->sorted_ba));
	err = ib_copy_to_udata(udata, resp, min(sizeof(*resp), udata->outlen));
	if (err) {
		nbl_ib_err(dev, "srq create user resp failed.\n");
		return err;
	}
	return 0;
}

static int nbl_srq_create_user_subq_and_set_shadow(
						struct nbl_device *nbldev,
						struct nbl_create_srq_req *req,
						struct nbl_ib_create_srq_resp *resp,
						struct ib_udata *udata, struct nbl_srq *srq,
						u32 *subq_buf_quanta, u8 *user_mode,
						u8 sorted_indices[], u64 sorted_ba[],
						u32 *page_0_num)
{
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_sc_dev *dev = &rf->sc_dev;
	int err;

	nbl_ib_dbg(dev, "enter user create SRQ.\n");
	err = ib_copy_from_udata(req, udata,
					min(sizeof(*req), udata->inlen));
	if (err) {
		nbl_ib_err(dev,
				"copy data from udata to req failed.\n");
		return err;
	}

	*subq_buf_quanta = req->buf_size / NBL_WQE_QUANTA_SIZE;
	*user_mode = 1;

	err = nbl_create_subq_user(srq, nbldev, req->buf_base,
						req->buf_size, udata, sorted_indices,
						sorted_ba, page_0_num);
	if (err) {
		nbl_ib_err(dev, "alloc subq failed.\n");
		return err;
	}
	/* shadow */
	nbl_user_srq_shadow(rf, srq, udata, resp);
	return 0;
}

static void nbl_init_srq_shadow(struct nbl_srq *srq)
{
	set_64bit_val((__be64 *)srq->shdw.va, 0,
		FIELD_PREP(NBL_SRQ_SHDW_SW_SEQ_NUM, srq->seq_num));
}

static int nbl_srq_create_kernel_subq_and_set_shadow(
				struct nbl_device *nbldev,
				struct nbl_srq *srq, u32 *subq_buf_quanta,
				u8 *user_mode, u32 *buf_size, u32 *size)
{
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_sc_dev *dev = &rf->sc_dev;
	int err;

	nbl_ib_dbg(dev, "enter kernel create SRQ.\n");

	*subq_buf_quanta = *buf_size / NBL_WQE_QUANTA_SIZE;
	*user_mode = 0;

	err = nbl_create_subq_kernel(srq, nbldev, *buf_size, *buf_size / *size);
	if (err) {
		nbl_ib_err(dev, "alloc subq failed.\n");
		return err;
	}

	srq->cur_subq = srq->subq_arr[0];
	srq->tail_subq = srq->subq_arr[SRQ_SUBQ_NUM - 1];
	/* shadow */
	nbl_kernel_srq_shadow(rf, srq);
	return 0;
}

int nbl_ib_create_srq(struct ib_srq *ib_srq, struct ib_srq_init_attr *init_attr,
		      struct ib_udata *udata)
{
	struct nbl_create_srq_req req;
	struct nbl_ib_create_srq_resp resp = {};
	struct ib_pd *ibpd = ib_srq->pd;
	struct nbl_pd *nblpd = to_nbl_pd(ibpd);
	struct nbl_device *nbldev = to_nbl_dev(ibpd->device);
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_sc_dev *dev = &rf->sc_dev;
	struct nbl_uk_attrs *uk_attrs = &dev->hw_attrs.uk_attrs;
	struct nbl_srq *srq;
	int err;
	u8 user_mode;
	/* give user to resort subq */
	u8 sorted_indices[SRQ_SUBQ_NUM];
	u64 sorted_ba[SRQ_SUBQ_NUM];
	u32 srqn = 0, page_0_num, size, buf_size, subq_buf_quanta;

	srq = to_nbl_srq(ib_srq);

	nbl_ib_dbg(&rf->sc_dev, "get into srq create\n");

	err = nbl_check_srq_init_attr(dev, uk_attrs, init_attr);
	if (err)
		goto err_out;

	/* init lock */
	mutex_init(&srq->mutex);
	spin_lock_init(&srq->lock);

	nbl_set_srq_ext_param(srq, init_attr);
	err = cal_srq_attrs(init_attr, dev, rf, &size, &buf_size, &srqn);
	if (err)
		goto err_out;

	/*set srqn*/
	srq->srqn = srqn;
	if (rf->srq_seq_table[srqn] != NBL_SRQ_MAX_SEQ)
		rf->srq_seq_table[srqn] += 1;
	else
		rf->srq_seq_table[srqn] = 1;
	srq->seq_num = rf->srq_seq_table[srqn];

	/* create subq */
	if (udata) {
		err = nbl_srq_create_user_subq_and_set_shadow(nbldev,
					&req, &resp, udata, srq, &subq_buf_quanta,
					&user_mode, sorted_indices, sorted_ba, &page_0_num);
		if (err)
			goto err_free_rsrc;
	} else {
		/* kernel create srq */
		err = nbl_srq_create_kernel_subq_and_set_shadow(nbldev, srq,
					&subq_buf_quanta, &user_mode, &buf_size, &size);
		if (err)
			goto err_free_rsrc;
	}

	err = set_srq_common_attrs(nbldev, srq, srqn, size,
					buf_size, subq_buf_quanta, user_mode);
	if (err)
		goto err_free_subq;

	/* init shadow */
	nbl_init_srq_shadow(srq);

	err = nbl_cqp_create_srq_cmd(rf, nblpd, srq);
	if (err) {
		nbl_ib_err(dev, "cqp create srq cmd failed.\n");
		goto err_free_wrid;
	}

	/* fill resp */
	if (udata) {
		err = fill_create_srq_resp(&resp, dev, srq, page_0_num,
							sorted_indices, sorted_ba, udata);
		if (err)
			goto err_free_wrid;
	}

	rf->srq_table[srqn] = srq;
	refcount_set(&srq->refcnt, 1);
	init_completion(&srq->free_srq);

	return 0;

err_free_wrid:
	kvfree(srq->wrid);
err_free_subq:
	free_subq(dev, srq, srq->subq_arr);
err_free_rsrc:
	nbl_free_rsrc(&rf->rsrc_lock, rf->allocated_srq, srqn);
err_out:
	return err;
}

int nbl_ib_destroy_srq(struct ib_srq *srq, struct ib_udata *udata)
{
	struct ib_pd *ibpd = srq->pd;
	struct nbl_device *nbldev = to_nbl_dev(ibpd->device);
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_srq *nblsrq = to_nbl_srq(srq);
	int ret = 0;

	if (!rf->srq_table[nblsrq->srqn]) {
		nbl_ib_err(&rf->sc_dev, "SRQ was destroyed, but enter destroy again!");
		return 0;
	}

	nbl_srq_rem_ref(srq);
	wait_for_completion(&nblsrq->free_srq);

	ret = nbl_cqp_destroy_srq_cmd(rf, nblsrq);
	if (ret)
		return ret;

	kvfree(nblsrq->wrid);
	free_subq(sc_dev, nblsrq, nblsrq->subq_arr);
	nbl_free_rsrc(&rf->rsrc_lock, rf->allocated_srq, nblsrq->srqn);
	return 0;
}

int nbl_ib_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
				enum ib_srq_attr_mask attr_mask, struct ib_udata *udata)
{
	struct ib_pd *ibpd = ibsrq->pd;
	struct nbl_device *nbldev = to_nbl_dev(ibpd->device);
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_srq *srq = to_nbl_srq(ibsrq);
	int ret = 0;

	if (attr_mask & IB_SRQ_MAX_WR)
		return -EINVAL;

	if (attr_mask & IB_SRQ_LIMIT) {
		if (attr->srq_limit >= srq->max_wr)
			return -EINVAL;

		mutex_lock(&srq->mutex);
		ret = nbl_cqp_modify_srq_cmd(rf, srq, attr->srq_limit);
		mutex_unlock(&srq->mutex);
	}

	return ret;
}

int nbl_ib_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *srq_attr)
{
	struct ib_pd *ibpd = ibsrq->pd;
	struct nbl_device *nbldev = to_nbl_dev(ibpd->device);
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_srq *srq = to_nbl_srq(ibsrq);
	int ret;
	__be64 *srqc;
	u64 temp;

	srqc = kzalloc(NBL_CMD_OUTPUT_SIZE, GFP_KERNEL);

	if (!srqc)
		return NBL_ERR_ALLOCMEM_FAILED;


	ret = nbl_cqp_query_srq_cmd(rf, srq, srqc);
	if (ret)
		goto out;

	get_64bit_val(srqc, 0x18, &temp);
	srq_attr->srq_limit = FIELD_GET(SRQC_LIMIT_RTH, temp);
	srq_attr->max_wr = srq->max_wr;
	srq_attr->max_sge = srq->max_sge;

out:
	kfree(srqc);
	return ret;
}

static void rechain_subq(struct nbl_srq *srq, struct nbl_srq_subq *subq)
{
	struct nbl_srq_subq *temp;
	/* break the chain */
	if (subq->prevq != NULL)
		subq->prevq->nextq = subq->nextq;
	if (subq->nextq != NULL)
		subq->nextq->prevq = subq->prevq;
	subq->prevq = NULL;
	subq->nextq = NULL;

	/* rechain */
	if (subq->page_mode == NBL_LEVEL0_PAGE_MODE) {
		/* insert after cur_subq  */
		subq->nextq = srq->cur_subq->nextq;
		subq->prevq = srq->cur_subq;
		if (srq->cur_subq->nextq != NULL)
			srq->cur_subq->nextq->prevq = subq;

		srq->cur_subq->nextq = subq;
		temp = subq;
		while (temp) {
			temp->sw_srq_pi_phase = !temp->prevq->sw_srq_pi_phase;
			temp = temp->nextq;
		}
	} else {
		/* attach to the tail */
		srq->tail_subq->nextq = subq;
		subq->prevq = srq->tail_subq;
		srq->tail_subq = subq;
		subq->sw_srq_pi_phase = !subq->prevq->sw_srq_pi_phase;
	}
	subq->has_ci = 0;
	subq->has_pi = 0;
	subq->ci = 0;
	subq->pi = 0;
	subq->finish_wqe_count = 0;
}

void nbl_ib_free_srq_wqe(struct nbl_srq *srq, u8 subq_id, u32 wqe_index)
{
	u32 current_consuming_idx = wqe_index;
	struct nbl_srq_subq *subq = srq->subq_arr[subq_id];

	/* always called with interrupts disabled. */
	spin_lock(&srq->lock);

	/* consider out-of-order completion, ci only advances
	 * when it is less then the current consuming wqe index
	 */
	if ((subq->has_ci && current_consuming_idx >= subq->ci) ||
	    (subq->prevq && subq->prevq->has_ci)) {
		/* the consuming wqe is the last wqe of subq */
		if (current_consuming_idx + srq->wqe_quanta >
		    subq->buf_quanta - 1) {
			subq->has_ci = 0;
			subq->ci = 0;
			subq->nextq->has_ci = 1;
			subq->nextq->ci = 0;
		} else {
			/* the consuming wqe at the next q */
			if (subq->prevq && subq->prevq->has_ci) {
				subq->prevq->has_ci = 0;
				subq->prevq->ci = 0;
				subq->has_ci = 1;
			}
			subq->ci = current_consuming_idx + srq->wqe_quanta;
		}
	}

	/* check all wqe are consumed */
	if (++(subq->finish_wqe_count) == subq->max_wqe)
		rechain_subq(srq, subq);

	spin_unlock(&srq->lock);
}

int nbl_cqp_create_srq_cmd(struct nbl_pci_f *rf, struct nbl_pd *nblpd, struct nbl_srq *srq)
{
	int ret = 0;
	__be64 *in;
	__u64 *temp_addr;
	__u64 pd_entry;

	nbl_ib_dbg(&rf->sc_dev, "[SRQ create] create srq %d cmd", srq->srqn);

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);

	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_CREATE_SRQ);
	nbl_64bit_write(in, SRQ_CQP_CQN, srq->cqn);
	nbl_64bit_write(in, SRQ_CQP_SRQN, srq->srqn);
	nbl_64bit_write(in, SRQ_CQP_SRQ_CUR_ID, srq->subq_arr[0]->subq_id);
	nbl_64bit_write(in, SRQ_CQP_CUR_SRQE_VLD, srq->subq_arr[0]->nxt_wqe_phase);
	nbl_64bit_write(in, SRQ_CQP_LIMIT_ARM, 0);
	nbl_64bit_write(in, SRQ_CQP_LIMIT_RTH, 0);
	nbl_64bit_write(in, SRQ_CQP_SRQWQE_SIZE, srq->wqe_ts);
	nbl_64bit_write(in, SRQ_CQP_SRQ_PI_RTH, 1);
	nbl_64bit_write(in, SRQ_CQP_SRQ_PM, srq->subq_arr[0]->page_mode);
	nbl_64bit_write(in, SRQ_CQP_SRQ_SIZE, ilog2(srq->subq_buf_quanta));
	nbl_64bit_write(in, SRQ_CQP_STATE, 1);
	nbl_64bit_write(in, SRQ_CQP_HW_SRQ_CI_RTH, 1);
	nbl_64bit_write(in, SRQ_CQP_SRQC_BA, srq->shdw.pa >> SRQ_CQP_SRQC_BA_SHIFT);
	nbl_64bit_write(in, SRQ_CQP_SW_SEQ_NUM, srq->seq_num);
	nbl_64bit_write(in, SRQ_CQP_XR_DOMAIN, srq->xrcdn);
	nbl_64bit_write(in, SRQ_CQP_PD, nblpd->sc_pd.pd_id);
	nbl_64bit_write(in, SRQ_CQP_SRQ_CUR_BA, srq->subq_arr[0]->mem.pa >> SRQ_CQP_PDPA_SHIFT);
	if (srq->subq_arr[0]->page_mode == NBL_LEVEL0_PAGE_MODE) {
		nbl_64bit_write(in, SRQ_CQP_SRQ_CUR_PDPA_VLD, 0);
		nbl_64bit_write(in, SRQ_CQP_SRQ_CUR_PDPA, 0);
		nbl_64bit_write(in, SRQ_CQP_SRQ_NXT_PDPA_VLD, 0);
		nbl_64bit_write(in, SRQ_CQP_SRQ_NXT_PDPA, 0);
	} else {
		temp_addr = (__u64 *)srq->subq_arr[0]->mem.va;
		pd_entry = be64_to_cpu(temp_addr[0]);
		nbl_64bit_write(in, SRQ_CQP_SRQ_CUR_PDPA_VLD, 1);
		nbl_64bit_write(in, SRQ_CQP_SRQ_CUR_PDPA, pd_entry >> SRQ_CQP_PDPA_SHIFT);

		pd_entry = be64_to_cpu(temp_addr[1]);
		nbl_64bit_write(in, SRQ_CQP_SRQ_NXT_PDPA_VLD, 1);
		nbl_64bit_write(in, SRQ_CQP_SRQ_NXT_PDPA, pd_entry >> SRQ_CQP_PDPA_SHIFT);
	}

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);

	kfree(in);
	return ret;
}

int nbl_cqp_destroy_srq_cmd(struct nbl_pci_f *rf, struct nbl_srq *srq)
{
	int ret = 0;
	__be64 *in;

	nbl_ib_dbg(&rf->sc_dev, "[SRQ destroy] destroy srq %d cmd", srq->srqn);

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);

	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_DESTROY_SRQ);
	nbl_64bit_write(in, SRQ_CQP_SRQN, srq->srqn);

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);

	kfree(in);

	return ret;
}

int nbl_cqp_modify_srq_cmd(struct nbl_pci_f *rf, struct nbl_srq *srq, u32 srq_limit)
{
	int ret = 0;
	__be64 *in;

	nbl_ib_dbg(&rf->sc_dev, "[SRQ modify] modify srq %d cmd", srq->srqn);

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);

	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_MODIFY_SRQ);
	nbl_64bit_write(in, SRQ_CQP_SRQN, srq->srqn);
	nbl_64bit_write(in, SRQ_CQP_LIMIT_ARM, 1);
	nbl_64bit_write(in, SRQ_CQP_LIMIT_RTH, srq_limit);

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);

	kfree(in);
	return ret;
}

int nbl_cqp_query_srq_cmd(struct nbl_pci_f *rf, struct nbl_srq *srq, __be64 *out)
{
	int ret = 0;
	__be64 *in;

	nbl_ib_dbg(&rf->sc_dev, "[SRQ query] query srq %d cmd", srq->srqn);

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);

	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_QUERY_SRQ);
	nbl_64bit_write(in, SRQ_CQP_SRQN, srq->srqn);

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, out, NBL_CMD_OUTPUT_SIZE);

	kfree(in);
	return ret;
}
int nbl_ib_alloc_xrcd(struct ib_xrcd *ib_xrcd, struct ib_udata *udata)
{
	struct nbl_device *nbl_dev;
	struct nbl_pci_f *rf;
	struct nbl_xrcd *xrcd;
	u32 next_idx = 0;
	int state;

	xrcd = to_nbl_xrcd(ib_xrcd);
	nbl_dev = to_nbl_dev(ib_xrcd->device);
	rf = nbl_dev->rf;

	state = nbl_alloc_rsrc(&rf->rsrc_lock, rf->allocated_xrcd,
				       rf->max_xrcd, &xrcd->xrcdn, &next_idx);
	if (state) {
		nbl_ib_err(&rf->sc_dev, "alloc xrc domain rsrc failed.\n");
		return state;
	}

	return 0;
}

int nbl_ib_dealloc_xrcd(struct ib_xrcd *ib_xrcd, struct ib_udata *udata)
{
	struct nbl_device *nbl_dev = to_nbl_dev(ib_xrcd->device);
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_xrcd *xrcd = to_nbl_xrcd(ib_xrcd);

	nbl_free_rsrc(&rf->rsrc_lock, rf->allocated_xrcd, xrcd->xrcdn);

	return 0;
}

int nbl_dump_hmc_srqc(struct nbl_device *nbl_dev, u32 dump_mask)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_ctx_hmc_base_info hmc_info;
	u32 num_one_page; /* how many srqc in one page */
	u32 offset;
	u32 srqn;
	int ret;

	srqn = dump_mask;
	if (srqn >= rf->max_srq) {
		nbl_ib_err(sc_dev, "[srqc] dump srqc with wrong srqn(%u)\n", srqn);
		return -EFAULT;
	}

	ret = nbl_get_srqc_base_addr(rf, srqn, rf->srq_sd_info, &hmc_info);
	if (ret) {
		nbl_ib_err(sc_dev, "[srqc] get nbl srqc base addr failed.\n");
		return -EFAULT;
	}

	num_one_page = (hmc_info.page_size / hmc_info.ctx_size);
	offset = ((srqn % num_one_page) * hmc_info.ctx_size);

	nbl_ib_err(sc_dev,
		   "[srqc] dump srqn(%u) srqc(sd va %p, 0x%llx, offset 0x%x)", srqn,
		   hmc_info.va, (u64)((uintptr_t)hmc_info.va), offset);
	nbl_dump_hex(rf, (hmc_info.va + offset), hmc_info.ctx_size);
	return 0;
}

void nbl_debug_query_cache_srqc(struct nbl_pci_f *rf, int srqn)
{
	int err, ix = 0;
	struct nbl_dma_mem srqc_mem;
	__be64 *in;
	u8 *buf;

	srqc_mem.size = NBL_SRQC_SIZE;
	srqc_mem.va = nbl_dma_alloc_coherent(rf->sc_dev.hw, srqc_mem.size,
					    &srqc_mem.pa, GFP_KERNEL);
	if (!srqc_mem.va) {
		dev_err(rf->sc_dev.hw->device, "query srqc dma alloc err");
		return;
	}
	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in) {
		dma_free_coherent(rf->sc_dev.hw->device, srqc_mem.size,
				  srqc_mem.va, srqc_mem.pa);
		return;
	}

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_QUERY_SRQ);
	nbl_64bit_write(in, SRQ_CQP_SRQN, srqn);
	nbl_64bit_write(in, SRQ_CQP_SRQC_UPLOAD_ADDR, srqc_mem.pa);

	err = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err)
		goto out;

	buf = srqc_mem.va;
	while (ix < NBL_SRQC_SIZE) {
		dev_err(rf->sc_dev.hw->device,
			"srqn[%d][%d-%d]%02x-%02x-%02x-%02x %02x-%02x-%02x-%02x %02x-%02x-%02x-%02x %02x-%02x-%02x-%02x\n",
			srqn, ix, ix + 15, buf[ix], buf[ix + 1], buf[ix + 2],
			buf[ix + 3], buf[ix + 4], buf[ix + 5], buf[ix + 6],
			buf[ix + 7], buf[ix + 8], buf[ix + 9], buf[ix + 10],
			buf[ix + 11], buf[ix + 12], buf[ix + 13], buf[ix + 14],
			buf[ix + 15]);
		ix += 16;
	}

out:
	kfree(in);
	dma_free_coherent(rf->sc_dev.hw->device, srqc_mem.size, srqc_mem.va,
			  srqc_mem.pa);
}
