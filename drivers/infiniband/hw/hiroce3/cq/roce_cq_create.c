// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include "roce_cq.h"
#include "roce_pub_cmd.h"
#include "roce_cqm_cmd.h"
#include "roce_main_extension.h"

/*
 ****************************************************************************
 Prototype	: roce_cq_attr_assign
 Description  : Assign value to CQC
 Input		: struct roce_cq_attr *cq_attr
				struct roce3_cq *rcq
				int eqn
				int page_shift
 Output	   : None

  1.Date		 : 2019/10/13
	Modification : Created function

****************************************************************************
*/
static void roce_cq_attr_assign(struct roce_verbs_cq_attr *cq_attr, struct roce3_cq *rcq,
	int eqn, int page_shift)
{
	/* Assign value to CQ */
	/* dw0 */
	cq_attr->dw0.bs.size = (u32)ROCE_ILOG2((unsigned int)(rcq->ibcq.cqe + 1));
	cq_attr->dw0.bs.page_size = (u32)page_shift;
	/* entry_size=(2^cq_cqe_size)*16B. */
	cq_attr->dw0.bs.cqe_size =
		(u32)ROCE_ILOG2((unsigned int)(rcq->buf.entry_size / 16));
	cq_attr->dw0.bs.mtt_page_size = rcq->buf.mtt.mtt_page_shift - PAGE_SHIFT_4K;
	cq_attr->dw0.bs.tss_timer_num = 7; /* 7 : The maximum number of timers supported by cq */
	cq_attr->dw0.bs.arm_timer_en = 0;
	cq_attr->dw0.bs.timer_mode = 0;
	cq_attr->dw0.bs.cnt_adjust_en = 1;
	cq_attr->dw0.bs.cnt_clear_en = 1;
	cq_attr->dw0.bs.ci_on_chip = 0;
	cq_attr->dw0.value = cpu_to_be32(cq_attr->dw0.value);

	/* dw1 */
	cq_attr->dw1.bs.dma_attr_idx = 0;
	cq_attr->dw1.bs.so_ro = 0;
	cq_attr->dw1.bs.state = ROCE_CQ_STATE_VALID;
	cq_attr->dw1.value = cpu_to_be32(cq_attr->dw1.value);

	/* dw2 */
	cq_attr->dw2.bs.idle_max_count = 0;
	cq_attr->dw2.bs.cqecnt_lth = 6; /* update ci threshold: 2^6=64 */
	cq_attr->dw2.bs.cqecnt_rctl_en = 0;
	cq_attr->dw2.bs.ceqe_en = 1;
	cq_attr->dw2.bs.arm_ceqe_en = 1;
	cq_attr->dw2.bs.ceqn = (u8)eqn;
	cq_attr->dw2.value = cpu_to_be32(cq_attr->dw2.value);

	/* dw3 */
	/* The timeout mechanism is disabled by default when CQ is created */
	cq_attr->dw3.bs.timeout = 0;
	/* The overtime mechanism is disabled by default when CQ is created */
	cq_attr->dw3.bs.max_cnt = 0;
	cq_attr->dw3.value = cpu_to_be32(cq_attr->dw3.value);

	/* dw4 - dw5 */
	cq_attr->cqc_l0mtt_gpa = rcq->buf.mtt.mtt_paddr;
	cq_attr->cqc_l0mtt_gpa = cpu_to_be64(cq_attr->cqc_l0mtt_gpa);

	/* dw6 - dw7 */
	cq_attr->ci_record_gpa_at_hop_num =
		cpu_to_be64((rcq->db.dma & (~0x3uLL)) | rcq->buf.mtt.mtt_layers);
}

static int roce3_cq_fill_create_inbuf(struct roce3_device *rdev, struct roce3_cq *rcq,
	int vector, int page_shift, struct tag_cqm_cmd_buf *cqm_cmd_inbuf)
{
	int eqn = 0;
	struct roce_verbs_cq_attr *cq_attr = NULL;
	struct tag_roce_uni_cmd_creat_cq *cq_sw2hw_inbuf = NULL;

	cq_sw2hw_inbuf = (struct tag_roce_uni_cmd_creat_cq *)cqm_cmd_inbuf->buf;
	cq_sw2hw_inbuf->com.index = cpu_to_be32(rcq->cqn);
	cq_sw2hw_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_CQ_BITMASK); //lint !e778
	cq_attr = &cq_sw2hw_inbuf->cq_attr;

	/* Get the EQN of the CEQ based on the Vector index */
	eqn = hinic3_vector_to_eqn(rdev->hwdev, SERVICE_T_ROCE, vector);
	if (eqn < 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to get eqn from hinic vector, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	roce_cq_attr_assign(cq_attr, rcq, eqn, page_shift);

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_cq_sw2hw
 Description  : Send the cqc configuration command
 Input		: struct roce3_device *rdev
				struct roce3_cq *rcq
				int vector
				int page_shift
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static int roce3_cq_sw2hw(struct roce3_device *rdev, struct roce3_cq *rcq,
	int vector, int page_shift)
{
	int ret = 0;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_uni_cmd_creat_cq), NULL, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	ret = roce3_cq_fill_create_inbuf(rdev, rcq, vector, page_shift, cqm_cmd_inbuf);
	if (ret != 0) {
		roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);
		return ret;
	}

	ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_SW2HW_CQ, cqm_cmd_inbuf,
		NULL, NULL, ROCE_CMD_TIME_CLASS_A, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to send SW2HW_CQ command, ret(%d), func_id(%d)\n",
			__func__, ret, rdev->glb_func_id);

		if (roce3_hca_is_present(rdev) != 0) {
			dev_err(rdev->hwdev_hdl, "[ROCE] %s: HCA is present(SW2HW_CQ), CQN(0x%x), func_id(%u)\n",
				__func__, rcq->cqn, rdev->glb_func_id);

			/*
			 * CMDq times out or CMDq does not work, update the
			 * device status, notify the PCIe module to reset
			 * the device through OFED
			 */
			if ((ret == -ETIMEDOUT) || (ret == -EPERM))
				rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;
		}
		ret = -1;
		goto err_send_cmd;
	}

	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);

	rcq->cons_index = 0;
	rcq->arm_sn = 1;
	rcq->arm_flag = 0;
	rcq->vector = (u32)vector;

	return 0;

err_send_cmd:
	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);

	return ret;
}

/*
 ****************************************************************************
 Prototype	: roce3_create_cq_check
 Description  : roce3_create_cq_check
 Input		: struct ib_device *ibdev
				int entries
				int vector
				struct ib_ucontext *ibcontext
				struct ib_udata *udata
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static int roce3_create_cq_check(struct ib_device *ibdev, int entries, int vector,
	const struct ib_ucontext *ibcontext, const struct ib_udata *udata)
{
	struct roce3_device *rdev = NULL;

	if (ibdev == NULL) {
		pr_err("[ROCE, ERR] %s: Ibdev is null\n", __func__);
		return -EINVAL;
	}

	if ((ibcontext != NULL) && (udata == NULL)) {
		pr_err("[ROCE, ERR] %s: Udata is null ptr, but ibcontext is not null ptr\n",
			__func__);
		return -EINVAL;
	}

	rdev = to_roce3_dev(ibdev);
	if ((entries < 1) || (entries > (int)rdev->rdma_cap.max_cqes)) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Cqe number invalid, entries(%d), func_id(%d)\n",
			__func__, entries, rdev->glb_func_id);
		return -EINVAL;
	}

	if (vector > (int)rdev->rdma_cap.num_comp_vectors) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Vector over range, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	return 0;
}

static int roce3_check_cq_create_flags(u32 flags)
{
	/*
	 * It returns non-zero value for unsupported CQ
	 * create flags, otherwise it returns zero.
	 */
	return (int)(flags & ~(IB_UVERBS_CQ_FLAGS_IGNORE_OVERRUN |
		IB_UVERBS_CQ_FLAGS_TIMESTAMP_COMPLETION)); /*lint !e40*/
}

static int roce3_cq_cqc_cfg(struct roce3_device *rdev, struct roce3_cq *rcq, int vector,
	struct ib_udata *udata)
{
	int ret = 0;
	int page_shift = 0;

	/* configurate CQC */
	ret = roce3_cq_sw2hw(rdev, rcq, vector, page_shift);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to handle cq sw2hw, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	/* User mode requires outgoing CQN */
	if (ib_copy_to_udata(udata, &rcq->cqn, sizeof(u32)) != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to copy data to user space, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		ret = -EFAULT;
		return ret;
	}

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_create_user_cq
 Description  : roce3_create_user_cq
 Input		: struct roce3_device *rdev
				struct roce3_cq *rcq
				int entries
				int vector
				struct ib_ucontext *ibcontext
				struct ib_udata *udata
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static int roce3_create_user_cq(struct roce3_device *rdev, struct roce3_cq *rcq, int entries,
	int vector, struct ib_ucontext *ibcontext, struct ib_udata *udata, u32 index)
{
	int ret = 0;
	struct roce3_create_cq_cmd ucmd = { 0 };

	rcq->cqm_cq = cqm_object_rdma_queue_create(rdev->hwdev, SERVICE_T_ROCE,
		CQM_OBJECT_RDMA_SCQ, 0, rcq, false, index);
	if (rcq->cqm_cq == NULL) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to create rdma queue from cqm object, func_id(%d), index(%d)\n",
			__func__, rdev->glb_func_id, index);
		return -ENOMEM;
	}

	/* record CQN */
	rcq->cqn = rcq->cqm_cq->index;

	if (ib_copy_from_udata(&ucmd, udata, sizeof(ucmd)) != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to copy from user space, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		ret = -EFAULT;
		goto err_free_cqm_cq;
	}

	/*
	 * Entries has been decreased by one when it was input by
	 * User Mode, and it is the expected value exactly
	 * after increased by one by Kernel Mode
	 */
#if defined(OFED_MLNX_5_8)
	ret = roce3_cq_get_umem(rdev, udata, &rcq->buf, &rcq->umem, ucmd.buf_addr, entries);
#else
	ret = roce3_cq_get_umem(rdev, ibcontext, &rcq->buf, &rcq->umem, ucmd.buf_addr, entries);
#endif
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to get umem, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_free_cqm_cq;
	}

	ret = roce3_db_map_user(to_roce3_ucontext(ibcontext),
		(unsigned long)ucmd.db_addr, &rcq->db);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to map kernel_mem to user_mem, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_free_mtt;
	}

	ret = roce3_cq_cqc_cfg(rdev, rcq, vector, udata);
	if (ret != 0)
		goto err_unmap_db;

	return 0;

err_unmap_db:
	roce3_db_unmap_user(to_roce3_ucontext(ibcontext), &rcq->db);

err_free_mtt:
	roce3_cq_put_umem(rdev, &rcq->buf, &rcq->umem);
	rcq->umem = NULL;

err_free_cqm_cq:
	hiudk_cqm_object_delete(rdev->hwdev, &rcq->cqm_cq->object);

	return ret;
}

static void roce3_fill_rcq_info(struct roce3_cq *rcq)
{
	rcq->cqn = rcq->cqm_cq->index;
	rcq->buf.buf = &rcq->cqm_cq->q_room_buf_1;

	/* Initialize buf to unused */
	roce3_cq_buf_init(&rcq->buf);

	/* Software DB assignment */
	rcq->set_ci_db = (__be32 *)(void *)(&rcq->cqm_cq->q_header_vaddr->doorbell_record);
	*rcq->set_ci_db = 0;
	rcq->db.db_record = (__be32 *)(void *)(&rcq->cqm_cq->q_header_vaddr->doorbell_record);
	rcq->db.dma = rcq->cqm_cq->q_header_paddr;
}

/*
 ****************************************************************************
 Prototype	: roce3_create_kernel_cq
 Description  : roce3_create_kernel_cq
 Input		: struct roce3_device *rdev
				struct roce3_cq *rcq
				int entries
				int vector
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static int roce3_create_kernel_cq(struct roce3_device *rdev, struct roce3_cq *rcq,
	int entries, int vector, u32 index)
{
	int ret = 0;
	int page_shift = 0;

	rcq->buf.buf_size = entries * (int)rdev->rdma_cap.cqe_size;
	rcq->cqm_cq = cqm_object_rdma_queue_create(rdev->hwdev, SERVICE_T_ROCE,
		CQM_OBJECT_RDMA_SCQ, (u32)rcq->buf.buf_size, rcq, true, index);
	if (rcq->cqm_cq == NULL) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to create rdma_queue from cqm_object, func_id(%d), index(%d)\n",
			__func__, rdev->glb_func_id, index);
		return (-ENOMEM);
	}

	/* Buffer is obtained from room1 when the queue is just created */
	if (rcq->cqm_cq->current_q_room != CQM_RDMA_Q_ROOM_1) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Not use CQM_RDMA_Q_ROOM_1, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		ret = -EINVAL;
		goto err_free_cqm_cq;
	}

	roce3_fill_rcq_info(rcq);

	page_shift = ROCE_ILOG2(rcq->cqm_cq->q_room_buf_1.buf_size);

	/* allocate MTT */
	rcq->buf.mtt.mtt_type = MTT_CMTT_TYPE;
	ret = hmm_rdma_mtt_alloc(rdev->hwdev, rcq->buf.buf->buf_number, (u32)page_shift,
		&rcq->buf.mtt, SERVICE_T_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to alloc rdma mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_free_cqm_cq;
	}

	/* Write the PA of the CQ Buffer to the MTT */
	ret = roce3_buf_write_mtt(rdev, &rcq->buf.mtt, rcq->buf.buf);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to write rdma mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_free_mtt;
	}

	/*lint -e834*/
	page_shift = ROCE_ILOG2(rcq->cqm_cq->q_room_buf_1.buf_size) - PAGE_SHIFT_4K;
	/*lint +e834*/

	/* configurate CQC */
	ret = roce3_cq_sw2hw(rdev, rcq, vector, page_shift);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to configure CQC, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_free_mtt;
	}

	return 0;

err_free_mtt:
	hmm_rdma_mtt_free(rdev->hwdev, &rcq->buf.mtt, SERVICE_T_ROCE);

err_free_cqm_cq:
	hiudk_cqm_object_delete(rdev->hwdev, &rcq->cqm_cq->object);

	return ret;
}

/*
 ****************************************************************************
 Prototype	: roce3_do_create_cq
 Description  : OFED_3_12
 Input		: struct ib_device *ibdev
				struct ib_ucontext *ibcontext
				struct ib_ucontext *ibcontext
				struct ib_udata *udata
				struct roce3_cq *rcq
				u32 index
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function
  2.Date		 : 2015/8/10
	Modification : modify function
  3.Date		 : 2017/11/10
	Modification : modify function

****************************************************************************
*/
static int roce3_do_create_cq(struct ib_device *ibdev, const struct ib_cq_init_attr *attr,
	struct ib_ucontext *ibcontext, struct ib_udata *udata, struct roce3_cq *rcq, u32 index)
{
	struct roce3_device *rdev = NULL;
	int ret = 0;
	int vector = attr->comp_vector;
	int entries = (int)attr->cqe;

	/* The CQE queue should reserve a special CQE for resize cq */
	entries++;
	entries = (int)(ROCE_ROUNDUP_POW_OF_TWO((u32)entries) & 0xffffffff); /*lint !e587*/

	rdev = to_roce3_dev(ibdev);
	/* Chip Constraints: Minimum queue depth needs to be page-aligned */
	if ((u32)((u32)entries * rdev->rdma_cap.cqe_size) < PAGE_SIZE)
		entries = (PAGE_SIZE >> (u32)ROCE_ILOG2(rdev->rdma_cap.cqe_size));

	/* Check if max spec is exceeded */
	if (entries > ((int)rdev->rdma_cap.max_cqes + 1)) {
		ret = (-EINVAL);
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Over range after align, entries(%d), max_cqes(%d), func_id(%d)\n",
			__func__, entries, rdev->rdma_cap.max_cqes + 1, rdev->glb_func_id);
		return ret;
	}

	rcq->ibcq.cqe = entries - 1;
	mutex_init(&rcq->resize_mutex);
	/*lint -e708*/
	spin_lock_init(&rcq->lock);
	/*lint +e708*/
	rcq->resize_buf = NULL;
	rcq->resize_umem = NULL;
	rcq->buf.entry_size = (int)rdev->rdma_cap.cqe_size;

	INIT_LIST_HEAD(&rcq->send_qp_list);
	INIT_LIST_HEAD(&rcq->recv_qp_list);
	if (ibcontext) {
		ret = roce3_create_user_cq(rdev, rcq, entries, vector, ibcontext, udata, index);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to create user_cq, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return ret;
		}
	} else {
		ret = roce3_create_kernel_cq(rdev, rcq, entries, vector, index);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to create kernel_cq, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return ret;
		}
	}

	rcq->reset_flow_comp = roce_reset_flow_comp;

	return 0;
}

#if defined(OFED_MLNX_5_8)
int roce3_create_cq_common(struct ib_device *ibdev, const struct ib_cq_init_attr *attr,
	struct ib_udata *udata, struct roce3_cq *rcq, u32 index)
{
	int ret;
	struct roce3_device *rdev = to_roce3_dev(ibdev);
	struct roce3_ucontext *context = rdma_udata_to_drv_context(
		udata, struct roce3_ucontext, ibucontext);
	int vector = attr->comp_vector;
	int entries = (int)attr->cqe;

	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	if (roce3_check_cq_create_flags(attr->flags) != 0) {
		pr_err("[ROCE, ERR] %s: Not support the cq_create flag(%x)\n",
			__func__, attr->flags);
		return -EOPNOTSUPP;
	}

	ret = roce3_create_cq_check(ibdev, entries, vector, &context->ibucontext, udata);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to check cq information\n", __func__);
		return ret;
	}

	return roce3_do_create_cq(ibdev, attr, &context->ibucontext, udata, rcq, index);
}

int roce3_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr, struct ib_udata *udata)
{
	struct roce3_cq *rcq = to_roce3_cq(ibcq);

	return roce3_create_cq_common(ibcq->device, attr, udata, rcq, ROCE_CQN_INVLD);
}
#else
struct ib_cq *roce3_create_cq_common(struct ib_device *ibdev, const struct ib_cq_init_attr *attr,
	struct ib_ucontext *ibcontext, struct ib_udata *udata, u32 index)
{
	int ret = 0;
	struct roce3_cq *rcq = NULL;
	int vector = attr->comp_vector;
	int entries = (int)attr->cqe;
	struct roce3_device *rdev = to_roce3_dev(ibdev);

	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return ERR_PTR((long)-EPERM);
	}

	if (roce3_check_cq_create_flags(attr->flags) != 0) {
		pr_err("[ROCE, ERR] %s: Not support the cq_create flag(%x)\n",
			__func__, attr->flags);
		return ERR_PTR((long)(-EOPNOTSUPP));
	}

	ret = roce3_create_cq_check(ibdev, entries, vector, ibcontext, udata);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to check cq information\n", __func__);
		goto err_out;
	}

	rcq = kzalloc(sizeof(*rcq), GFP_KERNEL);
	if (rcq == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = roce3_do_create_cq(ibdev, attr, ibcontext, udata, rcq, index);
	if (ret != 0)
		goto err_free_cq;

	return &rcq->ibcq;

err_free_cq:
	kfree(rcq);

err_out:
	return (struct ib_cq *)ERR_PTR((long)ret);
}

/*
 ****************************************************************************
 Prototype	: roce3_create_cq
 Description  : OFED_3_12
 Input		: struct ib_device *ibdev
				struct ib_cq_init_attr *attr(flags for exp)
				struct ib_ucontext *ibcontext
				struct ib_udata *udata
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function
  2.Date		 : 2015/8/10
	Modification : modify function
  3.Date		 : 2017/11/10
	Modification : modify function
  4.Date		 : 2021/1/7
	Modification : modified function

****************************************************************************
*/
struct ib_cq *roce3_create_cq(struct ib_device *ibdev, const struct ib_cq_init_attr *attr,
	struct ib_ucontext *ibcontext, struct ib_udata *udata)
{
	return roce3_create_cq_common(ibdev, attr, ibcontext, udata, ROCE_CQN_INVLD);
}
#endif

