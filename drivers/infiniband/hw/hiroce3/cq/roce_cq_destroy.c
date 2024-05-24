// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/slab.h>

#include "hinic3_hw.h"

#include "roce.h"
#include "roce_srq.h"
#include "roce_qp.h"
#include "roce_mix.h"
#include "roce_xrc.h"
#include "roce_cq.h"
#include "roce_cqm_cmd.h"
#include "roce_pub_cmd.h"
#include "hinic3_hmm.h"
#include "roce_main_extension.h"

static int roce3_check_cqc_data_state(struct roce3_device *rdev, const struct roce3_cq *cq,
	struct roce_cq_context *cqc_data, u32 check_state)
{
	int read_back_flag = 0;
	int times = rdev->try_times;
	struct roce_cq_context check_cqc_data;

	while ((times--) != 0) {
		if (roce3_hca_is_present(rdev) == 0)
			return 0;

		check_cqc_data.dw2.value = be32_to_cpu(cqc_data->dw2.value);
		if (check_cqc_data.dw2.bs.state == check_state) {
			read_back_flag = 1;
			break;
		}
		ROCE_UDELAY(US_PERF_DELAY);
	}

	if (read_back_flag == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to read back after try %d times, CQ state(0x%x), func_id(%u)\n",
			__func__, rdev->try_times, cqc_data->dw2.value, (u32)rdev->glb_func_id);
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Cqn(0x%x), timer_dw(0x%x), func_id(%u)\n",
			__func__, cq->cqn, cqc_data->dw2.value, (u32)rdev->glb_func_id);
		return -1;
	}

	return 0;
}

static int roce3_cq_hw2sw(struct roce3_device *rdev, struct roce3_cq *cq)
{
	int ret;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct roce_cq_context *cqc_data = NULL;
	struct tag_roce_cmd_cq_hw2sw *cq_hw2sw_inbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_cmd_cq_hw2sw), NULL, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	cq_hw2sw_inbuf = (struct tag_roce_cmd_cq_hw2sw *)cqm_cmd_inbuf->buf;
	cq_hw2sw_inbuf->com.index = cpu_to_be32((u32)cq->cqn);
	cq_hw2sw_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_CQ_BITMASK); //lint !e778

	cqc_data = (struct roce_cq_context *)((void *)cq->cqm_cq->q_ctx_vaddr);
	ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_HW2SW_CQ,
		cqm_cmd_inbuf, NULL, NULL, ROCE_CMD_TIME_CLASS_A, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to send HW2SW_CQ command, func_id(%u), cqn(0x%x), (ret:%d)\n",
			__func__, (u32)rdev->glb_func_id, cq->cqn, ret);

		if (roce3_hca_is_present(rdev) != 0) {
			dev_err(rdev->hwdev_hdl, "[ROCE] %s: HCA is present(HW2SW_CQ), cqn(0x%x), func_id(%u)\n",
				__func__, cq->cqn, rdev->glb_func_id);

			/*
			 * When CMDq times out or CMDq cannot work, update
			 * the device status and notify the PCIe module to reset
			 * the device through OFED
			 */
			if ((ret == -ETIMEDOUT) || (ret == -EPERM))
				rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;
		}

		/* CMDq may return a positive number, so its return value cannot be used directly */
		roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);
		return -1;
	}

	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);
	return roce3_check_cqc_data_state(rdev, cq, cqc_data, ROCE_CQ_TIME_OUT_CHECK_VALUE);
}

static int roce3_cq_cache_out(struct roce3_device *rdev, struct roce3_cq *cq)
{
	int ret = 0;
	struct rdma_service_cap *rdma_cap = NULL;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_roce_cmd_cq_cache_invalidate *cq_cache_invld_inbuf = NULL;

	/* Send the cache out command */
	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_cmd_cq_cache_invalidate), NULL, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	dev_dbg(rdev->hwdev_hdl, "[ROCE, INFO] %s:  func_id(%d) cqn(%d)\n",
		__func__, rdev->glb_func_id, cq->cqn);
	rdma_cap = &rdev->rdma_cap;
	cq_cache_invld_inbuf = (struct tag_roce_cmd_cq_cache_invalidate *)cqm_cmd_inbuf->buf;
	cq_cache_invld_inbuf->com.index = cpu_to_be32((u32)cq->cqn);
	cq_cache_invld_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_CQ_BITMASK); //lint !e778
	cq_cache_invld_inbuf->mtt_info.mtt_flags = 0;
	cq_cache_invld_inbuf->mtt_info.mtt_num = 0;
	cq_cache_invld_inbuf->mtt_info.mtt_cache_line_start =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.cmtt_cl_start);
	cq_cache_invld_inbuf->mtt_info.mtt_cache_line_end =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.cmtt_cl_end);
	cq_cache_invld_inbuf->mtt_info.mtt_cache_line_size =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.cmtt_cl_sz);

	ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_MISC_CQ_CACHE_INVLD,
		cqm_cmd_inbuf, NULL, NULL, ROCE_CMD_TIME_CLASS_A, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to send CQ_CACHE_INVLD command, ret(%d), func_id(%d)\n",
			__func__, ret, rdev->glb_func_id);

		if (roce3_hca_is_present(rdev) != 0) {
			dev_err(rdev->hwdev_hdl, "[ROCE] %s: HCA is present(CQ_CACHE_INVLD), cqn(0x%x), func_id(%u)\n",
				__func__, cq->cqn, rdev->glb_func_id);

			roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);

			/*
			 * When CMDq times out or CMDq cannot work, update
			 * the device status and notify the PCIe module to reset
			 * the device through OFED
			 */
			if ((ret == -ETIMEDOUT) || (ret == -EPERM))
				rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;

			return -1;
		}
	}

	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);

	return 0;
}

static void destroy_cq_user(struct roce3_cq *cq, struct ib_udata *udata)
{
	struct roce3_ucontext *context = rdma_udata_to_drv_context(
		udata, struct roce3_ucontext, ibucontext);

	roce3_db_unmap_user(context, &cq->db);
	ib_umem_release(cq->umem);
}

int roce3_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata)
{
	int ret = 0;
	struct roce3_device *rdev = NULL;
	struct roce3_cq *cq = NULL;
	struct roce_cq_context *cqc_data = NULL;

	if (ibcq == NULL) {
		pr_err("[ROCE, ERR] %s: Ibcq is null\n", __func__);
		return -EINVAL;
	}

	rdev = to_roce3_dev(ibcq->device);
	cq = to_roce3_cq(ibcq);

	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: HCA not present(return ok), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		goto err_roce_cq_free;
	}

	/* Modify CQC to be owned by the software */
	ret = roce3_cq_hw2sw(rdev, cq);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to modify CQC, ret(%d), func_id(%u), cqn(0x%x)\n",
			__func__, ret, rdev->glb_func_id, cq->cqn);
		return ret;
	}

	/* Send the cache out command */
	ret = roce3_cq_cache_out(rdev, cq);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to modify cqc, ret(%d), func_id(%u)\n",
			__func__, ret, rdev->glb_func_id);
		return ret;
	}

	cqc_data = (struct roce_cq_context *)((void *)cq->cqm_cq->q_ctx_vaddr);
	ret = roce3_check_cqc_data_state(rdev, cq, cqc_data, ROCE_CQ_STATE_CHECK_VALUE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: check cqc data state fail, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

err_roce_cq_free:
	/* Release the MTT corresponding to cq_buf */
	hmm_rdma_mtt_free(rdev->hwdev, &cq->buf.mtt, SERVICE_T_ROCE);

	/*
	 * Call the CQM interface to release CQN and CQC.
	 * Since there is no cq_buf and software DB in user mode,
	 * it does not need to be released; since kernel mode
	 * has both, it needs to be released
	 */
	hiudk_cqm_object_delete(rdev->hwdev, &cq->cqm_cq->object);

	/*
	 * If it is user mode, you also need to cancel
	 * the mapping of the corresponding software DB
	 */
	if (ibcq->uobject)
		destroy_cq_user(cq, udata);

	return 0;
}
