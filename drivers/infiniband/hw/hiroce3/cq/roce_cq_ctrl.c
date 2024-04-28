// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include "roce_cq.h"
#include "roce_cqm_cmd.h"
#include "roce_pub_cmd.h"
#include "roce_main_extension.h"

/*
 ****************************************************************************
 Prototype	: roce3_cq_modify
 Description  : Send the command of cq_modify
 Input		: struct roce3_device *rdev
				struct roce3_cq *cq
				u32 cnt
				u32 period
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static int roce3_cq_modify(struct roce3_device *rdev, struct roce3_cq *cq, u32 cnt, u32 period)
{
	int ret = 0;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_roce_cmd_modify_cq *cq_modify_inbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_cmd_modify_cq), NULL, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	cq_modify_inbuf = (struct tag_roce_cmd_modify_cq *)cqm_cmd_inbuf->buf;
	cq_modify_inbuf->com.index = cpu_to_be32(cq->cqn);
	cq_modify_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_CQ_BITMASK); //lint !e778
	cq_modify_inbuf->max_cnt = cpu_to_be32(cnt);
	cq_modify_inbuf->timeout = cpu_to_be32(period);

	ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_MODIFY_CQ, cqm_cmd_inbuf,
		NULL, NULL, ROCE_CMD_TIME_CLASS_A, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to send MODIFY_CQ, cqn(0x%x), ret(%d), func_id(%u)\n",
			__func__, cq->cqn, ret, rdev->glb_func_id);

		if (roce3_hca_is_present(rdev) != 0) {
			dev_err(rdev->hwdev_hdl, "[ROCE] %s: HCA is present(MODIFY_CQ), cqn(0x%x), func_id(%u)\n",
				__func__, cq->cqn, rdev->glb_func_id);

			/*
			 * CMDq times out or CMDq does not work, update the device status,
			 * notify the PCIe module to reset the device through OFED
			 */
			if ((ret == -ETIMEDOUT) || (ret == -EPERM))
				rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;
		}

		roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);

		/* CMDq may return a positive number, so its return value cannot be used directly */
		return -1;
	}

	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);
	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_modify_cq
 Description  : OFED_3_12
 Input		: struct ib_cq *ibcq
				u16 cq_count
				u16 cq_period
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
int roce3_modify_cq(struct ib_cq *ibcq, u16 cq_count, u16 cq_period)
{
	int ret = 0;
	struct roce3_cq *cq = NULL;
	struct roce3_device *rdev = NULL;

	if (ibcq == NULL) {
		pr_err("[ROCE, ERR] %s: Ibcq is null\n", __func__);
		return -EINVAL;
	}

	cq = to_roce3_cq(ibcq);
	rdev = to_roce3_dev(ibcq->device);

	ret = roce3_cq_modify(rdev, cq, cq_count, cq_period);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to modify cq, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_cq_alloc_resize_buf
 Description  : Kernel mode applies for resize_buf, and its corresponding MTT
				When there is an error in execution, this function
				ensures that all intermediate resources are released;
				when the execution is successful, this function
				can confirm that all resources are acquired.
 Input		: struct roce3_device *rdev
				struct roce3_cq *rcq
				int entries
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static int roce3_cq_alloc_resize_buf(struct roce3_device *rdev, struct roce3_cq *rcq, int entries)
{
	int ret = 0;
	int page_shift = 0;

	if (rcq->resize_buf) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Resize buffer is busy, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EBUSY;
	}

	/* Apply for resize_buf and assign it */
	rcq->resize_buf = kmalloc(sizeof(*rcq->resize_buf), GFP_ATOMIC);
	if (rcq->resize_buf == NULL)
		return -ENOMEM;

	rcq->resize_buf->buf.entry_size = rcq->buf.entry_size;
	rcq->resize_buf->buf.buf_size = entries * rcq->buf.entry_size;
	ret = hiudk_cqm_object_resize_alloc_new(rdev->hwdev, &rcq->cqm_cq->object,
		(u32)rcq->resize_buf->buf.buf_size);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to resize cq buffer, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_resize_buf_alloc;
	}

	/* If the application is successful, record the buffer information of the new buffer */
	rcq->resize_buf->cqe = entries - 1;
	rcq->resize_buf->buf.buf = &rcq->cqm_cq->q_room_buf_2;

	/* Initialize new buf to unused state */
	roce3_cq_buf_init(&rcq->resize_buf->buf);

	page_shift = (int)ROCE_ILOG2(rcq->resize_buf->buf.buf->buf_size);

	/* Apply MTT for resize_buf */
	rcq->buf.mtt.mtt_type = MTT_CMTT_TYPE;
	ret = hmm_rdma_mtt_alloc(rdev->hwdev, rcq->resize_buf->buf.buf->buf_number,
		(u32)page_shift, &rcq->resize_buf->buf.mtt, SERVICE_T_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to alloc rdma mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_mtt_alloc;
	}

	/* configurate MTT, write PA of resize_buf to MTT */
	ret = roce3_buf_write_mtt(rdev, &rcq->resize_buf->buf.mtt, rcq->resize_buf->buf.buf);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to write rdma mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_mtt_write;
	}

	return 0;

err_mtt_write:
	hmm_rdma_mtt_free(rdev->hwdev, &rcq->buf.mtt, SERVICE_T_ROCE);

err_mtt_alloc:
	/* free resize_buf */
	hiudk_cqm_object_resize_free_new(rdev->hwdev, &rcq->cqm_cq->object);

err_resize_buf_alloc:
	kfree(rcq->resize_buf);
	rcq->resize_buf = NULL;

	return ret;
}

/*
 ****************************************************************************
 Prototype	: roce3_cq_free_resize_buf
 Description  : Kernel Mode releases resize_buf and its corresponding MTT
 Input		: struct roce3_device *rdev
				struct roce3_cq *rcq
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static void roce3_cq_free_resize_buf(struct roce3_device *rdev, struct roce3_cq *rcq)
{
	/* Release the MTT of resize_buf first */
	hmm_rdma_mtt_free(rdev->hwdev, &rcq->buf.mtt, SERVICE_T_ROCE);

	/* free resize_buf */
	hiudk_cqm_object_resize_free_new(rdev->hwdev, &rcq->cqm_cq->object);

	/* free the resize_buf pointer itself */
	kfree(rcq->resize_buf);
	rcq->resize_buf = NULL;
}

/*
 ****************************************************************************
 Prototype	: roce3_cq_alloc_resize_umem
 Description  : User mode applies for umem of
				resize_buf,and MTT corresponding to user mode buf
 Input		: struct roce3_device *rdev
				struct roce3_cq *rcq
				int entries
				struct ib_udata *udata
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static int roce3_cq_alloc_resize_umem(struct roce3_device *rdev, struct roce3_cq *rcq, int entries,
	struct ib_udata *udata)
{
	int ret = 0;
	struct roce3_resize_cq_cmd ucmd = { 0 };

	/*
	 * If a resize is being executed, it is not allowed
	 * to execute another resize at the same time
	 */
	if (rcq->resize_umem) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Resize_umem is busy, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EBUSY;
	}

	if (ib_copy_from_udata(&ucmd, udata, sizeof(ucmd)) != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to copy from user space, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EFAULT;
	}

	rcq->resize_buf = kmalloc(sizeof(*rcq->resize_buf), GFP_ATOMIC);
	if (rcq->resize_buf == NULL)
		return -ENOMEM;

	ret = roce3_cq_get_umem(rdev, udata, &rcq->resize_buf->buf,
		&rcq->resize_umem, ucmd.buf_addr, entries);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to get umem, func_id(%d)\n",
			__func__, rdev->glb_func_id);

		kfree(rcq->resize_buf);
		rcq->resize_buf = NULL;

		return ret;
	}

	rcq->resize_buf->buf.entry_size = rcq->buf.entry_size;
	rcq->resize_buf->buf.buf_size = entries * rcq->buf.entry_size;
	rcq->resize_buf->cqe = entries - 1;

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_cq_free_resize_umem
 Description  : User mode applies for umem of resize_buf, and MTT corresponding to user mode buf
 Input		: struct roce3_device *rdev
				struct roce3_cq *rcq
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static void roce3_cq_free_resize_umem(struct roce3_device *rdev, struct roce3_cq *rcq)
{
	/* Free MTT and umem of resize_buf */
	roce3_cq_put_umem(rdev, &rcq->resize_buf->buf, &rcq->resize_umem);
	rcq->resize_umem = NULL;

	/* free resize_buf itself */
	kfree(rcq->resize_buf);
	rcq->resize_buf = NULL;
}

/*
 ****************************************************************************
 Prototype	: roce3_cq_get_outstanding_cqes
 Description  : roce3_cq_get_outstanding_cqes
 Input		: struct roce3_cq *cq
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static int roce3_cq_get_outstanding_cqes(struct roce3_cq *cq)
{
	u32 i = 0;

	i = cq->cons_index;
	while (roce3_get_sw_cqe(cq, i))
		++i;

	return (int)(i - cq->cons_index);
}

static int roce3_cq_get_next_cqe(struct roce_cqe **cqe, struct roce3_cq *cq,
	unsigned int *i, u32 *times, const struct roce_cqe *start_cqe)
{
	int ret = 0;

	do {
		*cqe = (struct roce_cqe *)roce3_get_sw_cqe(cq, ++(*i));
		if (*cqe == NULL) {
			ROCE_MDELAY(MS_DELAY);
			--(*times);
		}
	} while ((*cqe == NULL) && (*times != 0));

	if ((*cqe == start_cqe) || (*cqe == NULL)) {
		pr_err("[ROCE, ERR] %s: Failed to get resize CQE, CQN(0x%x)\n", __func__, cq->cqn);
		return -ENOMEM;
	}

	return ret;
}

/*
 ****************************************************************************
 Prototype	: roce3_cq_resize_copy_cqes
 Description  : roce3_cq_resize_copy_cqes
 Input		: struct roce3_cq *cq
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static int roce3_cq_resize_copy_cqes(struct roce3_cq *cq)
{
	struct roce_cqe *cqe = NULL;
	struct roce_cqe *new_cqe = NULL;
	struct roce_cqe *start_cqe = NULL;
	u32 times;
	unsigned int i = 0;
	int ret = 0;

	i = cq->cons_index;

	times = ROCE_CQ_RESIZE_POLL_TIMES;
	do {
		cqe = (struct roce_cqe *)roce3_get_sw_cqe(cq, i);
		if (cqe == NULL) {
			ROCE_MDELAY(MS_DELAY);
			--times;
		}
	} while ((cqe == NULL) && (times != 0));

	if (cqe == NULL) {
		pr_err("[ROCE, ERR] %s: Failed to get resize CQE, CQN(0x%x)\n", __func__, cq->cqn);
		return -ENOMEM;
	}

	start_cqe = cqe;

	/*
	 *	r_cqe:resize_cqe
	 *						 CI
	 *				+--------+-----+-----+-----+----------+
	 *	old_buf:	|		| CQE | CQE |R_CQE|		  |
	 *				+--------+-----+-----+-----+----------+
	 *							 |	 |
	 *							 |	 |
	 *				+--------+-----+-----+-----+----------+
	 *	new_buf:	|		| CQE | CQE |	 |		  |
	 *				+--------+-----+-----+-----+----------+
	 */
	/* Convert the fields needed by CQE to little endian */
	cqe->dw0.value = roce3_convert_cpu32(cqe->dw0.value);
	cqe->dw1.value = roce3_convert_cpu32(cqe->dw1.value);
	while (cqe->dw1.bs.op_type != ROCE_OPCODE_RESIZE_CQE) {
		/*
		 * The resized PI can be inherited, and the index of
		 * the original CQE remains unchanged in resize_buf
		 */
		new_cqe =
			(struct roce_cqe *)roce3_get_cqe_from_buf(&cq->resize_buf->buf,
			(i & ((unsigned int)cq->resize_buf->cqe)));

		memcpy((void *)new_cqe, (void *)cqe, sizeof(struct roce_cqe));

		/* If the CQE has been wrapped in resize_buf,
		 * the corresponding Owner bit needs to be modified
		 * to be owned by the software.
		 * The rule is: when the owner bit is owned by CQE software,
		 * the O bit is opposite to the high bit of ci;
		 * when the owner bit is owned by hardware,
		 * the O bit is the same as the high bit of CI.
		 */
		new_cqe->dw0.bs.owner =
			((i & ((unsigned int)cq->resize_buf->cqe + 1)) != 0) ? 1 : 0;

		/* After processing, turn the DW0/DW1 of CQE back to big endian */
		cqe->dw0.value = roce3_convert_be32(cqe->dw0.value);
		cqe->dw1.value = roce3_convert_be32(cqe->dw1.value);

		/* Convert DW0/DW1 of the CQE in the new queue back to big endian */
		new_cqe->dw0.value = roce3_convert_be32(new_cqe->dw0.value);
		new_cqe->dw1.value = roce3_convert_be32(new_cqe->dw1.value);

		/* Get the next CQE */
		ret = roce3_cq_get_next_cqe(&cqe, cq, &i, &times, start_cqe);
		if (ret != 0)
			return ret;

		/* Convert DW0/DW1 of CQE to little endian */
		cqe->dw0.value = roce3_convert_cpu32(cqe->dw0.value);
		cqe->dw1.value = roce3_convert_cpu32(cqe->dw1.value);
	}

	return 0;
}

static void roce3_cq_fill_resize_inbuf(struct roce3_device *rdev, struct roce3_cq *rcq,
	int page_shift, struct tag_cqm_cmd_buf *cqm_cmd_inbuf)
{
	struct rdma_service_cap *rdma_cap = NULL;
	u32 cq_size = 0;
	u32 mtt_layer = 0;
	u64 mtt_paddr = 0;
	u32 mtt_page_size = 0;
	struct tag_roce_cmd_resize_cq *cq_resize_inbuf = NULL;

	rdma_cap = &rdev->rdma_cap;
	cq_size = (u32)rcq->resize_buf->cqe + 1;
	cq_size = (u32)ROCE_ILOG2(cq_size);
	mtt_layer = rcq->resize_buf->buf.mtt.mtt_layers;
	mtt_paddr = rcq->resize_buf->buf.mtt.mtt_paddr;
	mtt_page_size = rcq->resize_buf->buf.mtt.mtt_page_shift - PAGE_SHIFT_4K;

	cq_resize_inbuf = (struct tag_roce_cmd_resize_cq *)cqm_cmd_inbuf->buf;
	cq_resize_inbuf->com.index = cpu_to_be32(rcq->cqn);
	cq_resize_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_CQ_BITMASK); //lint !e778
	cq_resize_inbuf->page_size = cpu_to_be32((u32)page_shift);
	cq_resize_inbuf->log_cq_size = cpu_to_be32(cq_size);
	cq_resize_inbuf->mtt_layer_num = cpu_to_be32(mtt_layer);
	cq_resize_inbuf->mtt_base_addr = mtt_paddr;
	cq_resize_inbuf->mtt_base_addr = cpu_to_be64(cq_resize_inbuf->mtt_base_addr);
	cq_resize_inbuf->mtt_page_size = cpu_to_be32(mtt_page_size);

	cq_resize_inbuf->mtt_info.mtt_flags = 0;
	cq_resize_inbuf->mtt_info.mtt_num = 0;
	cq_resize_inbuf->mtt_info.mtt_cache_line_start =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.cmtt_cl_start);
	cq_resize_inbuf->mtt_info.mtt_cache_line_end =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.cmtt_cl_end);
	cq_resize_inbuf->mtt_info.mtt_cache_line_size =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.cmtt_cl_sz);
}

/*
 ****************************************************************************
 Prototype	: roce3_cq_resize
 Description  : roce3_cq_resize
 Input		: struct roce3_device *rdev
				struct roce3_cq *rcq
				int page_shift
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static int roce3_cq_resize(struct roce3_device *rdev, struct roce3_cq *rcq, int page_shift)
{
	int ret = 0;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_cmd_resize_cq), NULL, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	roce3_cq_fill_resize_inbuf(rdev, rcq, page_shift, cqm_cmd_inbuf);

	ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_RESIZE_CQ, cqm_cmd_inbuf,
		NULL, NULL, ROCE_CMD_TIME_CLASS_A, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to send RESIZE_CQ command, ret(%d), func_id(%d)\n",
			__func__, ret, rdev->glb_func_id);

		if (roce3_hca_is_present(rdev) != 0) {
			dev_err(rdev->hwdev_hdl, "[ROCE] %s: HCA is present(RESIZE_CQ), cqn(0x%x), func_id(%u)\n",
				__func__, rcq->cqn, rdev->glb_func_id);

			/*
			 * When CMDq times out or CMDq cannot work, update the
			 * device status and notify the PCIe module to reset
			 * the device through OFED
			 */
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
 Prototype	: roce3_user_cq_resize
 Description  : roce3_user_cq_resize
 Input		: struct roce3_device *rdev
				struct roce3_cq *rcq
				int entries
				struct ib_udata *udata
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static int roce3_user_cq_resize(struct roce3_device *rdev, struct roce3_cq *rcq,
	int entries, struct ib_udata *udata)
{
	int page_shift = 0;
	int ret = 0;

	/* Cannot exceed max size after power-of-2 alignment */
	if (entries > ((int)rdev->rdma_cap.max_cqes + 1)) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Over range after align, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	ret = roce3_cq_alloc_resize_umem(rdev, rcq, entries, udata);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to alloc resize_umem, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	/*
	 * Send the cq_resize command to configure CQC.
	 * After the configuration is successful, the new CQE is written to
	 * resize_buf, and the old buffer may still retain the old CQE.
	 */
	ret = roce3_cq_resize(rdev, rcq, page_shift);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to resize cq, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		roce3_cq_free_resize_umem(rdev, rcq);
		return ret;
	}

	rcq->ibcq.cqe = rcq->resize_buf->cqe;

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_resize_user_cq
 Description  : roce3_resize_user_cq
 Input		: struct roce3_device *rdev
				struct roce3_cq *rcq
				int entries
				struct ib_udata *udata
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static int roce3_resize_user_cq(struct roce3_device *rdev, struct roce3_cq *rcq,
	int entries, struct ib_udata *udata)
{
	int ret = 0;
	struct roce3_resize_cq_cmd ucmd = { 0 };
	int cqe_entries = entries;

	if (ib_copy_from_udata(&ucmd, udata, sizeof(ucmd)) != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to copy from user space, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EFAULT;
	}

	if (ucmd.stage == 1)
		goto release_flow;

	mutex_lock(&rcq->resize_mutex);

	cqe_entries++;
	cqe_entries = (int)(ROCE_ROUNDUP_POW_OF_TWO((u32)cqe_entries) & 0xffffffff); /*lint !e587*/
	// Minimum queue depth needs to be aligned by page
	if ((u32)(cqe_entries * (int)rdev->rdma_cap.cqe_size) < PAGE_SIZE)
		cqe_entries = (int)(PAGE_SIZE >> (unsigned int)ROCE_ILOG2(rdev->rdma_cap.cqe_size));

	/*
	 * The new depth of CQ cannot be the same as the old
	 * depth. A special CQE space is reserved when CQ is created,
	 * so the value of ibcq->cqe is 1 smaller than the actual value
	 */
	if (cqe_entries == (rcq->ibcq.cqe + 1)) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: No need to resize cq, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		ret = 0;
		goto out;
	}

	ret = roce3_user_cq_resize(rdev, rcq, cqe_entries, udata);
	if (ret != 0)
		goto out;

	mutex_unlock(&rcq->resize_mutex);

	return 0;

release_flow:
	/* free old MTT */
	hmm_rdma_mtt_free(rdev->hwdev, &rcq->buf.mtt, SERVICE_T_ROCE);

	rcq->buf = rcq->resize_buf->buf;
	ib_umem_release(rcq->umem);
	rcq->umem = rcq->resize_umem;

	kfree(rcq->resize_buf);
	rcq->resize_buf = NULL;
	rcq->resize_umem = NULL;

out:
	mutex_unlock(&rcq->resize_mutex);

	return ret;
}

/*
 ****************************************************************************
 Prototype	: roce3_kernel_cq_resize
 Description  : roce3_kernel_cq_resize
 Input		: struct roce3_device *rdev
				struct roce3_cq *rcq
				int entries
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static int roce3_kernel_cq_resize(struct roce3_device *rdev, struct roce3_cq *rcq, int entries)
{
	int outst_cqe = 0;
	int page_shift = 0;
	int ret = 0;

	/* Cannot exceed max size after power-of-2 alignment */
	if (entries > ((int)rdev->rdma_cap.max_cqes + 1)) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Over range after align, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	/* The number of resized CQEs cannot be smaller than the number of outstanding CQEs */
	outst_cqe = roce3_cq_get_outstanding_cqes(rcq);
	if (entries < (outst_cqe + 1)) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Can't resize, because smaller than the number of outstanding CQES, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	ret = roce3_cq_alloc_resize_buf(rdev, rcq, entries);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to alloc resize buffer, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	/*lint -e834*/
	page_shift = ROCE_ILOG2(rcq->cqm_cq->q_room_buf_2.buf_size) - PAGE_SHIFT_4K;
	/*lint +e834*/

	/*
	 * Send the cq_resize command to configure CQC. After
	 * the configuration is successful, the new CQE is written to
	 * resize_buf, and the old buffer may still retain the old CQE.
	 */
	ret = roce3_cq_resize(rdev, rcq, page_shift);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to resize cq, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		roce3_cq_free_resize_buf(rdev, rcq);
		return ret;
	}

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_resize_kernel_cq
 Description  : roce3_resize_kernel_cq
 Input		: struct roce3_device *rdev
				struct roce3_cq *rcq
				int entries
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static int roce3_resize_kernel_cq(struct roce3_device *rdev, struct roce3_cq *rcq, int entries)
{
	int ret = 0;
	int tmp_cqe = 0;
	int cqe_entries = entries;

	mutex_lock(&rcq->resize_mutex);

	cqe_entries++;
	cqe_entries = (int)(ROCE_ROUNDUP_POW_OF_TWO((u32)cqe_entries) & 0xffffffff); /*lint !e587*/
	/* Minimum queue depth needs to be aligned by page */
	if ((u32)(cqe_entries * (int)rdev->rdma_cap.cqe_size) < PAGE_SIZE)
		cqe_entries = (PAGE_SIZE >> (unsigned int)ROCE_ILOG2(rdev->rdma_cap.cqe_size));

	/*
	 * The new depth of CQ cannot be the same as the
	 * old depth. A special CQE space is reserved when CQ is created,
	 * so the value of ibcq->cqe is 1 smaller than the actual value
	 */
	if (cqe_entries == (rcq->ibcq.cqe + 1)) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: No need to resize cq, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		mutex_unlock(&rcq->resize_mutex);
		return 0;
	}

	ret = roce3_kernel_cq_resize(rdev, rcq, cqe_entries);
	if (ret != 0)
		goto out;

	/* free old MTT */
	hmm_rdma_mtt_free(rdev->hwdev, &rcq->buf.mtt, SERVICE_T_ROCE);

	/*
	 * When copying CQE from the old buffer to resize_buf,
	 * the user may be polling cqe from the old buf, so
	 * it needs to be locked.If CQE of the old buffer has
	 * been polled in the polling process, polling process will
	 * free old buffer and switch to new buffer.
	 */
	spin_lock_irq(&rcq->lock);

	/* If the new buf has been switched to, nothing needs to be done */
	if (rcq->resize_buf) {
		ret = roce3_cq_resize_copy_cqes(rcq);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl, "[ROCE] %s: Have not polled resize cqe(fuc:%d, cqn:%u, ret:%d)\n",
				__func__, rdev->glb_func_id, rcq->cqn, ret);
			spin_unlock_irq(&rcq->lock);
			mutex_unlock(&rcq->resize_mutex);
			return ret;
		}
		tmp_cqe = rcq->ibcq.cqe;
		rcq->buf = rcq->resize_buf->buf;
		rcq->ibcq.cqe = rcq->resize_buf->cqe;

		kfree(rcq->resize_buf);
		rcq->resize_buf = NULL;
	}

	spin_unlock_irq(&rcq->lock);

	/*
	 * Non-0 means that the above resize_buf non-empty
	 * branch has been entered, the old buffer needs to be released
	 */
	if (tmp_cqe != 0)
		hiudk_cqm_object_resize_free_old(rdev->hwdev, &rcq->cqm_cq->object);

out:
	mutex_unlock(&rcq->resize_mutex);

	return ret;
}

static int roce3_resize_cq_check(struct ib_cq *ibcq, int entries, const struct ib_udata *udata)
{
	struct roce3_device *rdev = NULL;

	if (ibcq == NULL) {
		pr_err("[ROCE, ERR] %s: Ibcq is null\n", __func__);
		return -EINVAL;
	}

	if ((ibcq->uobject != NULL) && (udata == NULL)) {
		pr_err("[ROCE, ERR] %s: Udata is null, but uobject is not null\n", __func__);
		return -EINVAL;
	}

	rdev = to_roce3_dev(ibcq->device);
	if ((entries < 1) || (entries > (int)rdev->rdma_cap.max_cqes)) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: resize CQEs invalid. entries(%d), func_id(%d)\n",
			__func__, entries, rdev->glb_func_id);
		return -EINVAL;
	}

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_resize_cq
 Description  : roce3_resize_cq
 Input		: struct ib_cq *ibcq
				int entries
				struct ib_udata *udata
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
int roce3_resize_cq(struct ib_cq *ibcq, int entries, struct ib_udata *udata)
{
	int ret = 0;
	struct roce3_cq *rcq = NULL;
	struct roce3_device *rdev = NULL;

	ret = roce3_resize_cq_check(ibcq, entries, udata);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: failed to check resize_cq\n", __func__);
		return ret;
	}

	rcq = to_roce3_cq(ibcq);
	rdev = to_roce3_dev(ibcq->device);
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -1;
	}

	if (ibcq->uobject) {
		ret = roce3_resize_user_cq(rdev, rcq, entries, udata);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to resize user cq, func_id(%u) ret(%d)\n",
				__func__, (u32)rdev->glb_func_id, ret);
			return ret;
		}
	} else {
		ret = roce3_resize_kernel_cq(rdev, rcq, entries);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to resize kernel cq, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return ret;
		}
	}

	return 0;
}

void roce3_lock_cqs(struct roce3_cq *roce3_send_cq, struct roce3_cq *roce3_recv_cq)
	__acquires(&roce3_send_cq->lock) __acquires(&roce3_recv_cq->lock)
{
	if (roce3_send_cq == roce3_recv_cq) {
		spin_lock_irq(&roce3_send_cq->lock);
		__acquire(&roce3_recv_cq->lock);
	} else if (roce3_send_cq->cqn < roce3_recv_cq->cqn) {
		spin_lock_irq(&roce3_send_cq->lock);
		spin_lock_nested(&roce3_recv_cq->lock, SINGLE_DEPTH_NESTING);
	} else {
		spin_lock_irq(&roce3_recv_cq->lock);
		spin_lock_nested(&roce3_send_cq->lock, SINGLE_DEPTH_NESTING);
	}
}

void roce3_unlock_cqs(struct roce3_cq *roce3_send_cq, struct roce3_cq *roce3_recv_cq)
	__releases(&roce3_send_cq->lock) __releases(&roce3_recv_cq->lock)
{
	if (roce3_send_cq == roce3_recv_cq) {
		__release(&roce3_recv_cq->lock);
		spin_unlock_irq(&roce3_send_cq->lock);
	} else if (roce3_send_cq->cqn < roce3_recv_cq->cqn) {
		spin_unlock(&roce3_recv_cq->lock);
		spin_unlock_irq(&roce3_send_cq->lock);
	} else {
		spin_unlock(&roce3_send_cq->lock);
		spin_unlock_irq(&roce3_recv_cq->lock);
	}
}
