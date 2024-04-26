// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "roce.h"
#include "roce_compat.h"
#include "roce_user.h"
#include "roce_xrc.h"
#include "roce_srq.h"
#include "roce_cq.h"
#include "roce_cqm_cmd.h"
#include "hinic3_hmm.h"
#include "roce_main_extension.h"
#include "roce_pub_cmd.h"

u8 roce3_calculate_cont_th(u32 srq_limit)
{
	u8 cont_th = 0;
	u32 srq_limit_tmp = srq_limit;

	srq_limit_tmp >>= 1;
	while (srq_limit_tmp != 0) {
		srq_limit_tmp >>= 1;
		++cont_th;
	}

	return cont_th;
}

static u8 roce3_cal_srq_container_num(u32 avail_wr, struct roce3_srq *srq)
{
	u32 container_num = 0;
	u32 srqe_num = 0;

	/* cal container_num by avail_wr from user */
	srqe_num = srq->container_size - 1;

	/* explain the formula: round up by srqe_num */
	container_num = (avail_wr + srqe_num - 1) / srqe_num;
	return roce3_calculate_cont_th(container_num);
}

/*
 ****************************************************************************
 Prototype	: roce3_srq_arm
 Description  : roce3_srq_arm
 Input		: struct roce3_device *rdev
				struct roce3_srq *srq
				u32 srq_limit
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static int roce3_srq_arm(struct roce3_device *rdev, struct roce3_srq *srq, u32 srq_limit)
{
	int ret = 0;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_roce_cmd_srq_arm *srq_arm_inbuf = NULL;
	u8 warth = 0;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_cmd_srq_arm), NULL, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	srq_arm_inbuf = (struct tag_roce_cmd_srq_arm *)cqm_cmd_inbuf->buf;
	srq_arm_inbuf->com.index = cpu_to_be32((u32)(srq->srqn));
	srq_arm_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_SRQ_BITMASK); //lint !e778
	if (srq->container_flag != 0) {
		srq_arm_inbuf->bs.cont_en = srq->container_flag;
		srq_arm_inbuf->bs.th_up_en = 1; // Valid for setting up container warn_threshold
		warth = roce3_cal_srq_container_num(srq_limit, srq);
		srq_arm_inbuf->bs.warth = warth & ROCE_SRQ_CONTAINER_WARTH_MASK;
		srq_arm_inbuf->limitwater = cpu_to_be32(srq_arm_inbuf->limitwater);
	} else {
		srq_arm_inbuf->bs.lwm = srq_limit;
		srq_arm_inbuf->limitwater = cpu_to_be32(srq_arm_inbuf->limitwater);
	}

	ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_ARM_SRQ,
		cqm_cmd_inbuf, NULL, NULL, ROCE_CMD_TIME_CLASS_A, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s:send ARM_SRQ command Failed, ret(%d), func_id(%d), warth(%d)\n",
			__func__, ret, rdev->glb_func_id, warth);

		if (roce3_hca_is_present(rdev) != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE] %s: HCA is present(ARM_SRQ), srqn(0x%x), func_id(%u)\n",
				__func__, srq->srqn, rdev->glb_func_id);

			if ((ret == -ETIMEDOUT) || (ret == -EPERM))
				rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;
		}
		ret = -1;
	}

	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);

	return ret;
}

/*
 ****************************************************************************
 Prototype	: roce3_modify_srq
 Description  : roce3_modify_srq
 Input		: struct ib_srq *ibsrq
				struct ib_srq_attr *attr
				enum ib_srq_attr_mask attr_mask
				struct ib_udata *udata
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
int roce3_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
	enum ib_srq_attr_mask attr_mask, struct ib_udata *udata)
{
	int ret = 0;
	struct roce3_device *rdev = NULL;
	struct roce3_srq *srq = NULL;
	struct roce3_modify_srq_cmd ucmd = { 0 };
	u32 max_avail_wr = 0;

	if ((ibsrq == NULL) || (attr == NULL)) {
		pr_err("[ROCE, ERR] %s: Ibsrq or attr is null\n", __func__);
		return (-EINVAL);
	}

	if (((unsigned int)attr_mask & IB_SRQ_MAX_WR) != 0) {
		pr_err("[ROCE, ERR] %s: Not support resizing SRQs\n", __func__);
		return (-EINVAL);
	}

	rdev = to_roce3_dev(ibsrq->device);
	srq = to_roce3_srq(ibsrq);

	if ((udata != NULL) && (ib_copy_from_udata(&ucmd, udata, sizeof(ucmd)) != 0)) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: SRQN:(%d), Failed to copy from user space, func_id(%d)\n",
			__func__, srq->srqn, rdev->glb_func_id);
		return (-EFAULT);
	}

	if (((unsigned int)attr_mask & IB_SRQ_LIMIT) != 0) {
		/* calculate max_wr */
		max_avail_wr = roce3_srq_max_avail_wr_set(srq);
		if (attr->srq_limit > max_avail_wr) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: srq_limit > max_wr, func_id(%d), max_avail_wr(%d)\n",
				__func__, rdev->glb_func_id, max_avail_wr);
			return (-EINVAL);
		}

		mutex_lock(&srq->mutex);
		ret = roce3_srq_arm(rdev, srq, attr->srq_limit);
		mutex_unlock(&srq->mutex);

		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to handle srq arm, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return ret;
		}
	}

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_srq_query
 Description  : roce3_srq_query
 Input		: struct roce3_device *rdev
				struct roce3_srq *srq
				u32 *srq_limit
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static int roce3_srq_query(struct roce3_device *rdev, struct roce3_srq *srq, u32 *srq_limit)
{
	int ret = 0;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_cqm_cmd_buf *cqm_cmd_outbuf = NULL;
	struct tag_roce_cmd_srq_query *srq_query_inbuf = NULL;
	struct roce3_srq_query_outbuf *srq_query_outbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_cmd_srq_query), &cqm_cmd_outbuf,
		(u16)sizeof(struct roce3_srq_query_outbuf));
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	srq_query_inbuf = (struct tag_roce_cmd_srq_query *)cqm_cmd_inbuf->buf;
	srq_query_outbuf = (struct roce3_srq_query_outbuf *)cqm_cmd_outbuf->buf;
	srq_query_inbuf->com.index = cpu_to_be32((u32)srq->srqn);
	srq_query_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_SRQ_BITMASK); //lint !e778

	ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_QUERY_SRQ,
		cqm_cmd_inbuf, cqm_cmd_outbuf, NULL,
		ROCE_CMD_TIME_CLASS_A, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to send QUERY_SRQ command, ret(%d), func_id(%d)\n",
			__func__, ret, rdev->glb_func_id);

		if (roce3_hca_is_present(rdev) != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE] %s: HCA is present(QUERY_SRQ), srqn(0x%x), func_id(%u)\n",
				__func__, srq->srqn, rdev->glb_func_id);

			if ((ret == -ETIMEDOUT) || (ret == -EPERM))
				rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;
		}

		ret = -1;
		goto err_cmd;
	}

	srq_query_outbuf->srqc.dw3.value = be32_to_cpu(srq_query_outbuf->srqc.dw3.value);
	*srq_limit = srq_query_outbuf->srqc.dw3.bs.lth;

	if (srq->container_flag != 0) {
		/* parse srqc to get warn_th */
		u32 warn_th = srq_query_outbuf->srqc.dw2.bs_c.warn_th;
		*srq_limit = (warn_th == 0) ? 0 :
			((u32)((srq->container_size - 1) * (1U << warn_th)));
	}

err_cmd:
	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);

	return ret;
}

/*
 ****************************************************************************
 Prototype	: roce3_query_srq
 Description  : roce3_query_srq
 Input		: struct ib_srq *ibsrq
				struct ib_srq_attr *srq_attr
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
int roce3_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *srq_attr)
{
	int ret = 0;
	u32 limit_water = 0;
	struct roce3_device *rdev = NULL;
	struct roce3_srq *rsrq = NULL;

	if ((ibsrq == NULL) || (srq_attr == NULL)) {
		pr_err("[ROCE, ERR] %s: Ibsrq or srq_attr is null\n", __func__);
		return -EINVAL;
	}

	rdev = to_roce3_dev(ibsrq->device);
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s): HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	rsrq = to_roce3_srq(ibsrq);

	ret = roce3_srq_query(rdev, rsrq, &limit_water);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
		"[ROCE, ERR] %s: Failed to query srq, func_id(%d)\n",
		__func__, rdev->glb_func_id);
		return ret;
	}

	srq_attr->srq_limit = limit_water;
	srq_attr->max_wr = roce3_srq_max_avail_wr_set(rsrq);
	srq_attr->max_sge = (u32)rsrq->max_gs;

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_srq_hw2sw
 Description  : roce3_srq_hw2sw
 Input		: struct roce3_device *rdev
				struct roce3_srq *srq
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static int roce3_srq_hw2sw(struct roce3_device *rdev, struct roce3_srq *srq)
{
	int ret = 0;
	struct rdma_service_cap *rdma_cap = NULL;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_roce_cmd_srq_hw2sw *srq_hw2sw_inbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_cmd_srq_hw2sw), NULL, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	srq_hw2sw_inbuf = (struct tag_roce_cmd_srq_hw2sw *)cqm_cmd_inbuf->buf;
	rdma_cap = &rdev->rdma_cap;
	srq_hw2sw_inbuf->com.index = cpu_to_be32((u32)srq->srqn);
	srq_hw2sw_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_SRQ_BITMASK); //lint !e778
	srq_hw2sw_inbuf->srq_buf_len = cpu_to_be32((u32)srq->buf_sz);

	srq_hw2sw_inbuf->mtt_info.mtt_flags = 0;
	srq_hw2sw_inbuf->mtt_info.mtt_num = 0;
	srq_hw2sw_inbuf->mtt_info.mtt_cache_line_start =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.cmtt_cl_start);
	srq_hw2sw_inbuf->mtt_info.mtt_cache_line_end =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.cmtt_cl_end);
	srq_hw2sw_inbuf->mtt_info.mtt_cache_line_size =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.cmtt_cl_sz);

	srq_hw2sw_inbuf->wqe_cache_line_start =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.wqe_cl_start);
	srq_hw2sw_inbuf->wqe_cache_line_end =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.wqe_cl_end);
	srq_hw2sw_inbuf->wqe_cache_line_size =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.wqe_cl_sz);

	ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_HW2SW_SRQ,
		cqm_cmd_inbuf, NULL, NULL, ROCE_CMD_TIME_CLASS_A, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to send HW2SW_SRQ command, func_id(%d)\n",
			__func__, rdev->glb_func_id);

		if (roce3_hca_is_present(rdev) == 0) {
			ret = 0;
		} else {
			dev_err(rdev->hwdev_hdl,
				"[ROCE] %s: HCA is present(HW2SW_SRQ), srqn(0x%x), func_id(%u)\n",
				__func__, srq->srqn, rdev->glb_func_id);

			if ((ret == -ETIMEDOUT) || (ret == -EPERM))
				rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;

			ret = -1;
		}
	}

	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);

	return ret;
}

static void roce3_free_srq(struct ib_srq *ibsrq, struct roce3_device *rdev,
	struct roce3_srq *srq, struct ib_udata *udata)
{
	hmm_rdma_mtt_free(rdev->hwdev, &srq->mtt, SERVICE_T_ROCE);

	if (ibsrq->uobject) {
		struct roce3_ucontext *ucontext = rdma_udata_to_drv_context(
			udata, struct roce3_ucontext, ibucontext);
		roce3_db_unmap_user(ucontext, &srq->db);
		ib_umem_release(srq->umem);
	} else {
		kfree(srq->wrid);
	}

	hiudk_cqm_object_delete(rdev->hwdev, &srq->cqm_srq->object);
}

int roce3_destroy_srq(struct ib_srq *ibsrq, struct ib_udata *udata)
{
	int ret = 0;
	int times = 0;
	int read_back_flag = 0;
	struct roce3_device *rdev = NULL;
	struct roce3_srq *srq = NULL;
	struct roce_srq_context *srqc = NULL;
	struct roce_srq_context check_srqc;

	if (ibsrq == NULL) {
		pr_err("[ROCE, ERR] %s: Ibsrq is null\n", __func__);
		return -EINVAL;
	}

	rdev = to_roce3_dev(ibsrq->device);
	srq = to_roce3_srq(ibsrq);
	times = rdev->try_times;

	ret = roce3_srq_hw2sw(rdev, srq);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to handle srq hw2sw, func_id(%u), ret:%d\n",
			__func__, rdev->glb_func_id, ret);
		return ret;
	}

	srqc = (struct roce_srq_context *)((void *)srq->cqm_srq->q_ctx_vaddr);
	while ((times--) != 0) {
		if (roce3_hca_is_present(rdev) == 0)
			goto err_roce_srq_free;
		check_srqc.dw2.value = be32_to_cpu(srqc->dw2.value);
		if (check_srqc.dw2.bs.state == ROCE_SRQ_STATE_CHECK_VALUE) {
			read_back_flag = 1;
			break;
		}

		ROCE_UDELAY(US_PERF_DELAY);
	}

	if (read_back_flag == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to read srq state back after try %d times, func_id(%u), Srqn(0x%x), state_dw(0x%x)\n",
			__func__, rdev->try_times, rdev->glb_func_id, srq->srqn, srqc->dw2.value);
		return -1;
	}

err_roce_srq_free:
	roce3_free_srq(ibsrq, rdev, srq, udata);

	return 0;
}

static int roce3_check_sge_length(const struct ib_recv_wr *wr, struct roce3_device *rdev,
	const struct ib_recv_wr **bad_wr, struct roce3_wqe_srq_data_seg *scat)
{
	int i = 0;
	int ret = 0;
	u32 data_len = 0;

	for (i = 0; i < wr->num_sge; ++i) {
		if (ROCE_UNLIKELY(wr->sg_list[i].length >
			rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_msg_sz - 1)) {
			ret = -EINVAL;
			*bad_wr = wr;
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Sge data length is over range, sg_list(%d), length(0x%x), max_msg_sz(0x%x), func_id(%d)\n",
				__func__, i, wr->sg_list[i].length,
				rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_msg_sz,
				rdev->glb_func_id);

			scat[0].dw2.length = 0;
			scat[0].dw3.lkey = LAST_SGE_NO_PRESENT;
			scat[0].dw3.lkey = cpu_to_be32(scat[0].dw3.lkey);
			return ret;
		}

		data_len += wr->sg_list[i].length;
		if (ROCE_UNLIKELY(data_len > rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_msg_sz)) {
			ret = -EINVAL;
			*bad_wr = wr;
			scat[0].dw2.length = 0;
			scat[0].dw3.lkey = LAST_SGE_NO_PRESENT;
			scat[0].dw3.lkey = cpu_to_be32(scat[0].dw3.lkey);

			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Data length is over range, data_len(0x%x), max_msg_sz(0x%x), func_id(%d)\n",
				__func__, data_len,
				rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_msg_sz,
				rdev->glb_func_id);
			return ret;
		}

		scat[i].dw2.length = cpu_to_be32(wr->sg_list[i].length);
		scat[i].dw3.lkey = cpu_to_be32((u32)(wr->sg_list[i].lkey &
			NORMAL_FMT_AND_NEXT_SGE_PRESENT));
		scat[i].addr = cpu_to_be64(wr->sg_list[i].addr);
	}

	if (ROCE_UNLIKELY(i == 0)) {
		scat[0].dw3.lkey = LAST_SGE_NO_PRESENT;
		scat[0].dw3.lkey = cpu_to_be32(scat[0].dw3.lkey);
		scat[0].dw2.length = 0;
	} else {
		scat[i - 1].dw3.lkey =
			cpu_to_be32((u32)((wr->sg_list[i - 1].lkey | LAST_SGE_NO_PRESENT) &
						NORMAL_FMT_AND_LAST_SGE_NO_PRESENT));
	}

	return ret;
}

int roce3_post_srq_recv(struct ib_srq *ibsrq, const struct ib_recv_wr *wr,
					    const struct ib_recv_wr **bad_wr)
{
	int ret = 0;
	int nreq = 0;
	unsigned long flags = 0;
	struct roce3_srq *srq = to_roce3_srq(ibsrq);
	struct roce3_device *rdev = NULL;
	struct roce3_wqe_srq_next_seg *next = NULL;
	struct roce3_wqe_srq_data_seg *scat = NULL;
	const struct ib_recv_wr *wr_tmp = wr;

	rdev = to_roce3_dev(ibsrq->device);
	if (roce3_hca_is_present(rdev) == 0)
		return -EPERM;

	spin_lock_irqsave(&srq->lock, flags);

	for (nreq = 0; wr_tmp; ++nreq, wr_tmp = wr_tmp->next) {
		if (ROCE_UNLIKELY((wr_tmp->num_sge > srq->max_gs) || (srq->head == srq->tail))) {
			ret = (wr_tmp->num_sge > srq->max_gs) ? (-EINVAL) : (-ENOMEM);
			*bad_wr = wr_tmp;
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Num_sge(%d) > max_gs(%d) or srq is empty(head(%d) == tail(%d)), func_id(%d)\n",
				__func__, wr_tmp->num_sge, srq->max_gs,
				rdev->glb_func_id, srq->head, srq->tail);
			break;
		}

		next = (struct roce3_wqe_srq_next_seg *)roce3_srq_get_wqe(srq, srq->head);
		scat = (struct roce3_wqe_srq_data_seg *)(next + 1);

		ret = roce3_check_sge_length(wr_tmp, rdev, bad_wr, scat);
		if (ret != 0)
			goto sge_len_err;

		next->pcnt = (u16)cpu_to_be16(srq->wqe_ctr + (u16)nreq);
		srq->wrid[srq->head] = wr_tmp->wr_id;
		srq->head = be16_to_cpu(next->next_wqe_index);
	}

sge_len_err:
	if (ROCE_UNLIKELY(nreq != 0)) {
		srq->wqe_ctr += (u16)nreq;

		/*
		 * Make sure that descriptors are written before
		 * doorbell record.
		 */
		wmb();

		*srq->db.db_record = cpu_to_be32(srq->wqe_ctr);
	}

	spin_unlock_irqrestore(&srq->lock, flags);

	return ret;
}
