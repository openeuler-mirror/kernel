// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/slab.h>
#include <linux/vmalloc.h>
#ifndef __PC_LINT__
#include <linux/kernel.h>
#endif

#include "roce.h"
#include "roce_compat.h"
#include "roce_cq.h"
#include "roce_cqm_cmd.h"
#include "roce_user.h"
#include "roce_xrc.h"
#include "roce_pd.h"
#include "roce_srq.h"
#include "roce_verbs_attr.h"
#include "roce_verbs_format.h"

#include "roce_srq_extension.h"
#include "roce_main_extension.h"
#include "hinic3_hmm.h"
#include "roce_pub_cmd.h"

/*
 ****************************************************************************
 Prototype	: roce3_srq_sw2hw
 Description  : roce3_srq_sw2hw
 Input		: struct roce3_device *rdev
				struct roce3_srq *rsrq
				u32 pdn
				u32 cqn
				u16 xrcdn
				int page_shift
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

  1.Date		 : 2015/7/27
	Modification : modify function
****************************************************************************
*/
static void roce3_srq_sw2hw_set(struct tag_roce_verbs_srq_attr *srq_attr, struct roce3_srq *rsrq,
	u32 pdn, u32 cqn, u16 xrcdn, int page_shift)
{
	srq_attr->dw0.bs.size = (u32)(ROCE_ILOG2((unsigned int)rsrq->max_depth));
	srq_attr->dw0.bs.page_size = (u32)page_shift;
	srq_attr->dw0.bs.wqebb_size = (u32)rsrq->wqe_shift - SRQ_WQEBB_SIZE_CAL_SECTTOR;
	srq_attr->dw0.bs.mtt_page_size = (rsrq->mtt.mtt_page_shift - PAGE_SHIFT_4K);
	srq_attr->dw0.bs.xrcd = xrcdn;

	srq_attr->dw1.bs.dma_attr_idx = 0;
	srq_attr->dw1.bs.so_ro = 1;
	srq_attr->dw1.bs.state = ROCE_SRQ_STATE_VALID;

	srq_attr->dw3.bs.container = rsrq->container_flag;
	srq_attr->dw3.bs.lth_pre_en = (rsrq->container_flag == 0); // rdma engine prefetch
	srq_attr->dw3.bs.pcnt_on_chip = 0;
	srq_attr->dw3.bs.rkey_en = 1;
	srq_attr->dw3.bs.pd = pdn;

	srq_attr->srqn = cpu_to_be32(rsrq->srqn);
	srq_attr->xrc_cqn = cpu_to_be32(cqn);

	if (rsrq->container_flag == 0) { // normal srq
		srq_attr->dw1.bs.ep = 0;
		srq_attr->dw1.bs.cos = 0;

		srq_attr->dw2.value = 0;
		// rdma engine wqe prefetch max num
		srq_attr->dw2.bs.wqe_prefetch_max_num = RDMA_PREFETCH_WQE_MAX;
		// srq_attr->dw2.bs.wqe_prefetch_min_num = 0;
		// srq_attr->dw2.bs.wqe_cache_thd_sel = 0;
		srq_attr->dw2.bs.wqecnt_lth = 0xe;
		// srq_attr->dw2.bs.wqecnt_ctrl_en = 0;
		// srq_attr->dw2.bs.wqecnt_rctl = 0;
		srq_attr->dw2.bs.mtt_prefetch_maxlen = 0; // rdma engine mtt prefetch max len
		// srq_attr->dw2.bs.next_wqe_idx = 0;

		srq_attr->dw3.bs.lth_pre_en = 1; // rdma engine prefetch
		srq_attr->dw3.bs.lth_gap = 0;
	} else {
		srq_attr->cont.dw2.bs.head_idx = 0;
		srq_attr->cont.dw2.bs.warn_th = 0; // Do NOT init warn_th until user arm srq
		srq_attr->cont.dw2.bs.cont_size =
			(MAX_SUPPORT_CONTAINER_MODE - rsrq->container_mode) & 0x3;
		srq_attr->cont.dw2.value = cpu_to_be32(srq_attr->cont.dw2.value);
		srq_attr->record_gpa_at_hop_num = cpu_to_be64((rsrq->mtt.mtt_layers & 0x3));
	}

	srq_attr->dw0.value = cpu_to_be32(srq_attr->dw0.value);
	srq_attr->dw1.value = cpu_to_be32(srq_attr->dw1.value);
	srq_attr->dw2.value = cpu_to_be32(srq_attr->dw2.value);
	srq_attr->dw3.value = cpu_to_be32(srq_attr->dw3.value);

	srq_attr->l0mtt_gpa = rsrq->mtt.mtt_paddr;

	srq_attr->l0mtt_gpa = cpu_to_be64(srq_attr->l0mtt_gpa);

	srq_attr->record_gpa_at_hop_num = cpu_to_be64(rsrq->db.dma | (rsrq->mtt.mtt_layers & 0x3));
}

static int roce3_srq_sw2hw(struct roce3_device *rdev, struct roce3_srq *rsrq,
	u32 pdn, u32 cqn, u16 xrcdn, int page_shift)
{
	int ret = 0;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_roce_verbs_srq_attr *srq_attr = NULL;
	struct tag_roce_uni_cmd_creat_srq *srq_sw2hw_inbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_uni_cmd_creat_srq), NULL, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	srq_sw2hw_inbuf = (struct tag_roce_uni_cmd_creat_srq *)cqm_cmd_inbuf->buf;
	srq_sw2hw_inbuf->com.index = cpu_to_be32((u32)rsrq->srqn);
	srq_sw2hw_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_SRQ_BITMASK); //lint !e778
	srq_attr = &srq_sw2hw_inbuf->srq_attr;

	roce3_srq_sw2hw_set(srq_attr, rsrq, pdn, cqn, xrcdn, page_shift);

	ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_SW2HW_SRQ,
		cqm_cmd_inbuf, NULL, NULL, ROCE_CMD_TIME_CLASS_A, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to send SW2HW_SRQ command, ret(%d), func_id(%d)\n",
			__func__, ret, rdev->glb_func_id);

		if (roce3_hca_is_present(rdev) != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE] %s: HCA is present(SW2HW_SRQ), srqn(0x%x), func_id(%u)\n",
				__func__, rsrq->srqn, rdev->glb_func_id);

			/* update dev status after cmdq timeout or exception, notify PCIe reset */
			if ((ret == -ETIMEDOUT) || (ret == -EPERM))
				rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;
		}

		ret = -1;
	}

	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);

	return ret;
}

static int roce3_create_srq_check(const struct ib_pd *ibpd,
	const struct ib_srq_init_attr *init_attr)
{
	struct roce3_device *rdev = to_roce3_dev(ibpd->device);

	if ((init_attr->attr.max_wr > (u32)rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_srq_wqes) ||
		(init_attr->attr.max_sge >
		(u32)rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_srq_sge)) {
		pr_err("[ROCE, ERR] %s: Invalid input parms\n", __func__);
		return -EINVAL;
	}

	return 0;
}

static int roce3_create_srq_write_mtt_and_db(struct roce3_device *rdev, struct roce3_srq *rsrq,
	struct roce3_create_srq_cmd *ucmd, struct roce3_pd *pd)
{
	int ret = 0;

	ret = roce3_umem_write_mtt(rdev, &rsrq->mtt, rsrq->umem);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to write mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	ret = roce3_db_map_user(to_roce3_ucontext(pd->ibpd.uobject->context),
		ucmd->db_addr, &rsrq->db);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to map db to user space, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	return ret;
}

static int roce3_create_srq_get_umem(struct roce3_create_srq_cmd *ucmd,
	struct ib_udata *udata, struct roce3_srq *rsrq,
	struct roce3_device *rdev, struct roce3_pd *pd)
{
	int ret = 0;

	if (ib_copy_from_udata(ucmd, udata, sizeof(*ucmd)) != 0) {
		ret = -EFAULT;
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to copy from user space, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	rsrq->umem = ib_umem_get(&rdev->ib_dev, ucmd->buf_addr, (size_t)rsrq->buf_sz, 0);
	if (IS_ERR(rsrq->umem)) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to get ib_umem, func_id(%d) rsrq->buf_sz:%u\n",
			__func__, rdev->glb_func_id, rsrq->buf_sz);
		ret = (int)PTR_ERR(rsrq->umem);
		return ret;
	}

	return ret;
}

static int roce3_create_user_srq_update(struct roce3_device *rdev, struct roce3_srq *rsrq,
	struct roce3_pd *pd, struct ib_srq_init_attr *init_attr,
	struct ib_udata *udata, int page_shift)
{
	u32 cqn = 0;
	u16 xrcdn = 0;
	struct roce_srq_context *srqc = NULL;
	int ret = 0;

#if defined(OFED_MLNX_5_8) || defined(OFED_VER_4_19)
	cqn = (u32)((init_attr->srq_type == IB_SRQT_XRC) ?
		to_roce3_cq(init_attr->ext.cq)->cqn : 0); /*lint !e40*/
#endif
	xrcdn = (init_attr->srq_type == IB_SRQT_XRC) ?
		(u16)(to_roce3_xrcd(init_attr->ext.xrc.xrcd)->xrcdn) :
		(u16)rdev->rdma_cap.reserved_xrcds;
	roce3_create_user_srq_update_ext(&cqn, rsrq->srqn);

	srqc = (struct roce_srq_context *)((void *)rsrq->cqm_srq->q_ctx_vaddr);
	srqc->dw2.bs.state = ROCE_SRQ_STATE_MEM_INIT;
	srqc->dw2.value = cpu_to_be32(srqc->dw2.value);

	/* set SRQC */
	ret = roce3_srq_sw2hw(rdev, rsrq, pd->pdn, cqn, xrcdn, (page_shift - PAGE_SHIFT_4K));
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to handle srq_sw2hw, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_unmap;
	}

	rsrq->ibsrq.ext.xrc.srq_num = (u32)rsrq->srqn;

	if (ib_copy_to_udata(udata, &rsrq->srqn, sizeof(u32)) != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to copy data to user space, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		ret = -EFAULT;
		goto err_unmap;
	}

	return 0;

err_unmap:
	roce3_db_unmap_user(to_roce3_ucontext(pd->ibpd.uobject->context), &rsrq->db);
	return ret;
}

u32 roce3_srq_max_avail_wr_set(struct roce3_srq *rsrq)
{
	u32 link_wqe_count = 0;

	if (rsrq->container_flag != 0) {
		link_wqe_count = (u32)rsrq->max_depth / rsrq->container_size;
		return ((u32)rsrq->max_depth - link_wqe_count) - (rsrq->container_size - 1);
	} else {
		return (u32)rsrq->max_depth - 1;
	}
}

/*
 ****************************************************************************
 Prototype	: roce3_create_user_srq
 Description  : roce3_create_user_srq
 Input		: struct roce3_device *rdev
				struct roce3_srq *rsrq
				struct roce3_pd *pd
				struct ib_srq_init_attr *init_attr
				struct ib_udata *udata
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static int roce3_create_user_srq(struct roce3_device *rdev, struct roce3_srq *rsrq,
	struct roce3_pd *pd, struct ib_srq_init_attr *init_attr, struct ib_udata *udata, u32 index)
{
	int ret = 0;
	u32 npages = 0;
	int page_shift = 0;
	struct roce3_create_srq_cmd ucmd = { 0 };

	/* dispatch SRQN and SRQC */
	rsrq->cqm_srq =
		cqm_object_rdma_queue_create(rdev->hwdev, SERVICE_T_ROCE,
		CQM_OBJECT_RDMA_SRQ, 0, rsrq, false, index);
	if (rsrq->cqm_srq == NULL) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to create rdma queue by cqm_object, func_id(%d) index(%d)\n",
			__func__, rdev->glb_func_id, index);
		return (-ENOMEM);
	}

	rsrq->srqn = rsrq->cqm_srq->index;

	ret = roce3_create_srq_get_umem(&ucmd, udata, rsrq, rdev, pd);
	if (ret != 0)
		goto err_free_cqm_srq;

	npages = (u32)ib_umem_num_pages(rsrq->umem);
	page_shift = PAGE_SHIFT;


	rsrq->mtt.mtt_type = MTT_CMTT_TYPE;
	ret = hmm_rdma_mtt_alloc(rdev->hwdev, npages, (u32)page_shift, &rsrq->mtt, SERVICE_T_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc rdma_mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_release_umem;
	}

	ret = roce3_create_srq_write_mtt_and_db(rdev, rsrq, &ucmd, pd);
	if (ret != 0)
		goto err_free_mtt;

	ret = roce3_create_user_srq_update(rdev, rsrq, pd, init_attr, udata, page_shift);
	if (ret != 0)
		goto err_free_mtt;

	init_attr->attr.max_wr = roce3_srq_max_avail_wr_set(rsrq);

	return 0;

err_free_mtt:
	hmm_rdma_mtt_free(rdev->hwdev, &rsrq->mtt, SERVICE_T_ROCE);

err_release_umem:
	ib_umem_release(rsrq->umem);

err_free_cqm_srq:
	hiudk_cqm_object_delete(rdev->hwdev, &rsrq->cqm_srq->object);

	return ret;
}

static void roce3_get_cqn_xrcdn(u32 *cqn, u16 *xrcdn,
	struct ib_srq_init_attr *init_attr, struct roce3_device *rdev)
{
#if defined(OFED_MLNX_5_8) || defined(OFED_VER_4_19)
	*cqn = (u32)((init_attr->srq_type == IB_SRQT_XRC) ?
		to_roce3_cq(init_attr->ext.cq)->cqn : 0); /*lint !e40*/
#endif
	*xrcdn = (init_attr->srq_type == IB_SRQT_XRC) ?
		(u16)(to_roce3_xrcd(init_attr->ext.xrc.xrcd)->xrcdn) :
		(u16)rdev->rdma_cap.reserved_xrcds;
}

static int roce3_create_kernel_srq_update(struct roce3_device *rdev,
	struct roce3_srq *rsrq, struct roce3_pd *pd,
	struct ib_srq_init_attr *init_attr, int page_shift)
{
	u32 cqn = 0;
	u16 xrcdn = 0;
	struct roce_srq_context *srqc = NULL;
	int ret;

	ret = roce3_buf_write_mtt(rdev, &rsrq->mtt, rsrq->buf);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to write mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_free_mtt;
	}

	rsrq->wrid = kmalloc((size_t)((u32)rsrq->max_depth * sizeof(u64)),
		GFP_KERNEL);
	if (rsrq->wrid == NULL) {
		rsrq->wrid = vzalloc((size_t)((u32)rsrq->max_depth * sizeof(u64)));
		if (rsrq->wrid == NULL) {
			ret = -ENOMEM;
			goto err_free_mtt;
		}
	}

	roce3_get_cqn_xrcdn(&cqn, &xrcdn, init_attr, rdev);

	srqc = (struct roce_srq_context *)((void *)rsrq->cqm_srq->q_ctx_vaddr);
	srqc->dw2.bs.state = ROCE_SRQ_STATE_MEM_INIT;
	srqc->dw2.value = cpu_to_be32(srqc->dw2.value);

	ret = roce3_srq_sw2hw(rdev, rsrq, pd->pdn, cqn, xrcdn, (page_shift - PAGE_SHIFT_4K));
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to handle srq sw2hw, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_free_wrid;
	}

	return 0;

err_free_wrid:
	kvfree(rsrq->wrid);
	rsrq->wrid = NULL;

err_free_mtt:
	hmm_rdma_mtt_free(rdev->hwdev, &rsrq->mtt, SERVICE_T_ROCE);

	return ret;
}

/*
 ****************************************************************************
 Prototype	: roce3_create_kernel_srq
 Description  : roce3_create_kernel_srq
 Input		: struct roce3_device *rdev
				struct roce3_srq *rsrq
				struct roce3_pd *pd
				struct ib_srq_init_attr *init_attr
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static int roce3_create_kernel_srq(struct roce3_device *rdev, struct roce3_srq *rsrq,
	struct roce3_pd *pd, struct ib_srq_init_attr *init_attr, u32 index)
{
	int i = 0;
	int ret = 0;
	int page_shift = 0;
	struct roce3_wqe_srq_next_seg *next = NULL;
	struct roce3_wqe_srq_data_seg *scatter = NULL;

	/* alloc queue Buf/ Soft DB/SRQN/SRQC */
	rsrq->cqm_srq = cqm_object_rdma_queue_create(rdev->hwdev, SERVICE_T_ROCE,
		CQM_OBJECT_RDMA_SRQ, (u32)rsrq->buf_sz, rsrq, true, index);
	if (rsrq->cqm_srq == NULL) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to create rdma queue by cqm_object, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -ENOMEM;
	}

	rsrq->srqn = rsrq->cqm_srq->index;
	rsrq->buf = &rsrq->cqm_srq->q_room_buf_1;

	/* set Soft DB */
	rsrq->db.db_record = (__be32 *)(void *)(&rsrq->cqm_srq->q_header_vaddr->doorbell_record);
	rsrq->db.dma = rsrq->cqm_srq->q_header_paddr;
	*rsrq->db.db_record = 0;

	rsrq->head = 0;
	rsrq->tail = rsrq->max_depth - 1;
	rsrq->wqe_ctr = 0;

	for (i = 0; i < rsrq->max_depth; ++i) {
		next = (struct roce3_wqe_srq_next_seg *)roce3_srq_get_wqe(rsrq, i);
		next->next_wqe_index = cpu_to_be16((u16)((u32)(i + 1) &
			(u32)(rsrq->max_depth - 1)));

		scatter = (struct roce3_wqe_srq_data_seg *)(next + 1);
		scatter->dw2.length = 0;

		/* first SGE = last SGE */
		scatter->dw3.lkey = LAST_SGE_NO_PRESENT;
		scatter->dw3.lkey = cpu_to_be32(scatter->dw3.lkey);
	}

	page_shift = ROCE_ILOG2(rsrq->buf->buf_size);
	rsrq->mtt.mtt_type = MTT_CMTT_TYPE;
	ret = hmm_rdma_mtt_alloc(rdev->hwdev, rsrq->buf->buf_number, (u32)page_shift,
		&rsrq->mtt, SERVICE_T_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc rdma rdma_mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_free_cqm_srq;
	}

	ret = roce3_create_kernel_srq_update(rdev, rsrq, pd, init_attr, page_shift);
	if (ret != 0)
		goto err_free_cqm_srq;

	rsrq->ibsrq.ext.xrc.srq_num = (u32)rsrq->srqn;
	init_attr->attr.max_wr = (u32)rsrq->max_depth - 1;
	return 0;

err_free_cqm_srq:
	hiudk_cqm_object_delete(rdev->hwdev, &rsrq->cqm_srq->object);

	return ret;
}

u8 roce3_get_container_sz(u32 container_mode)
{
	switch (container_mode) {
	case ROCE_SRQ_MODE_0:
		return ROCE_SRQ_CONT_NUM_MODE0;
	case ROCE_SRQ_MODE_1:
		return ROCE_SRQ_CONT_NUM_MODE1;
	case ROCE_SRQ_MODE_2:
		return ROCE_SRQ_CONT_NUM_MODE2;
	case ROCE_SRQ_MODE_3:
		return ROCE_SRQ_CONT_NUM_MODE3;
	default:
		return ROCE_SRQ_CONT_NUM_MODE3;
	}
}

static void roce3_set_srq_depth(struct ib_srq_init_attr *init_attr, struct roce3_srq *rsrq)
{
	u32 link_wqe_count = 0;
	u32 remain_wqe_count = 0;

	/*
	 * +---+---+---+---+---+---+---+---+
	 * |wqe|wqe|wqe|wqe|wqe|wqe|wqe|nil|
	 * +---+---+---+---+---+---+---+---+
	 * ^
	 * |
	 * full condition:head==tail==nil
	 */
	if (rsrq->container_flag != 0) {
		link_wqe_count = init_attr->attr.max_wr / (rsrq->container_size - 1u);
		remain_wqe_count = init_attr->attr.max_wr % (rsrq->container_size - 1u);
		link_wqe_count += ((remain_wqe_count == 0) ?
			0 : (rsrq->container_size - remain_wqe_count));
		rsrq->max_depth = (int)(init_attr->attr.max_wr + link_wqe_count +
			rsrq->container_size);
	} else {
		rsrq->max_depth = (int)(init_attr->attr.max_wr + 1);
	}
	rsrq->max_depth = (int)((ROCE_ROUNDUP_POW_OF_TWO(
		(u32)rsrq->max_depth)) & 0xffffffff); //lint !e587
}

static void roce3_rsrq_init(struct ib_srq_init_attr *init_attr,
	struct roce3_srq *rsrq, struct roce3_device *rdev)
{
	int buf_size = 0;
	int desc_size = 0;

	roce3_srq_container_init(init_attr, rsrq, rdev);

	mutex_init(&rsrq->mutex);
	/*lint -e708*/
	spin_lock_init(&rsrq->lock);
	/*lint +e708*/

	roce3_set_srq_depth(init_attr, rsrq);

	rsrq->max_gs = (init_attr->attr.max_sge <= ROCE_SRQ_MIN_SGE) ?
		ROCE_SRQ_MIN_SGE :
		((init_attr->attr.max_sge <= ROCE_SRQ_MID_SGE) ?
		ROCE_SRQ_MID_SGE : ROCE_SRQ_MAX_SGE);
	init_attr->attr.max_sge = (u32)rsrq->max_gs;

	/* 0 <= max_gs <= 3, desc_size = 64
	 * 4 <= max_gs <= 7, desc_size = 128
	 */
	desc_size = (int)sizeof(struct roce3_wqe_srq_next_seg) +
		rsrq->max_gs * (int)sizeof(struct roce3_wqe_srq_data_seg);
	desc_size = (int)(ROCE_ROUNDUP_POW_OF_TWO((u32)desc_size)); //lint !e587
	desc_size = ROCE_MAX(ROCE_WQE_BB_SIZE_MIN, desc_size);	  // align with min bb_size
	rsrq->wqe_shift = ROCE_ILOG2((unsigned int)desc_size);
	buf_size = rsrq->max_depth * desc_size;

	/* WQEBB align 1 PAGE */
	if (buf_size < (int)PAGE_SIZE)
		rsrq->max_depth = (int)((u64)PAGE_SIZE >> (unsigned int)rsrq->wqe_shift);

	/* align with PAGE SIZE */
	buf_size = (int)ROCE_ALIGN((u32)buf_size, PAGE_SIZE);
	rsrq->buf_sz = buf_size;
}

int roce3_create_srq_common(struct roce3_device *rdev, struct roce3_srq *rsrq, struct roce3_pd *pd,
	struct ib_srq_init_attr *init_attr, struct ib_udata *udata, u32 index)
{
	int ret;

	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	ret = roce3_create_srq_check(&pd->ibpd, init_attr);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to check srq info\n", __func__);
		return ret;
	}

	roce3_rsrq_init(init_attr, rsrq, rdev);
	if (rsrq->ibsrq.uobject) {
		ret = roce3_create_user_srq(rdev, rsrq, pd, init_attr, udata, index);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to create user srq, func_id(%u), index(%u)\n",
				__func__, rdev->glb_func_id, index);
		}
	} else {
		ret = roce3_create_kernel_srq(rdev, rsrq, pd, init_attr, index);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to create kernel srq, func_id(%u)\n",
				__func__, rdev->glb_func_id);
		}
	}

	return ret;
}

int roce3_create_srq(struct ib_srq *ibsrq, struct ib_srq_init_attr *init_attr,
	struct ib_udata *udata)
{
	struct roce3_pd *pd = to_roce3_pd(ibsrq->pd);
	struct roce3_device *rdev = to_roce3_dev(ibsrq->device);
	struct roce3_srq *rsrq = to_roce3_srq(ibsrq);

	return roce3_create_srq_common(rdev, rsrq, pd, init_attr, udata, ROCE_SRQN_INVLD);
}
