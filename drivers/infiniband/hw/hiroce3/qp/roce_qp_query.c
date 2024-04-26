// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>

#include <rdma/ib_verbs.h>

#include "roce_compat.h"

#include "hinic3_crm.h"

#include "roce.h"
#include "roce_mix.h"
#include "roce_mr.h"
#include "roce_xrc.h"
#include "roce_srq.h"
#include "roce_cq.h"
#include "roce_cqm_cmd.h"
#include "roce_qp.h"
#include "roce_pub_cmd.h"
#include "roce_main_extension.h"
#ifdef __ROCE_DFX__
#include "roce_dfx.h"
#endif

static enum ib_mig_state to_ib_mig_state(int roce3_mig_state)
{
	switch (roce3_mig_state) {
	case ROCE_QP_PM_ARMED:
		return IB_MIG_ARMED;

	case ROCE_QP_PM_REARM:
		return IB_MIG_REARM;

	case ROCE_QP_PM_MIGRATED:
		return IB_MIG_MIGRATED;

	default:
		return (enum ib_mig_state)(-1);
	}
}

static int to_ib_qp_access_flags(const struct roce_qp_context *context)
{
	unsigned int ib_flags = 0;
	u32 tmp = 0;

	/* RRE */
	if (context->chip_seg.qpcc.dw5.bs.qp_rre != 0) {
		tmp = ib_flags | IB_ACCESS_REMOTE_READ;
		ib_flags = tmp;
	}

	/* RWE */
	if (context->chip_seg.qpcc.dw5.bs.qp_rwe != 0) {
		tmp = ib_flags | IB_ACCESS_REMOTE_WRITE;
		ib_flags = tmp;
	}

	/* RAE */
	if (context->chip_seg.qpcc.dw5.bs.qp_rae != 0) {
		tmp = ib_flags | IB_ACCESS_REMOTE_ATOMIC;
		ib_flags = tmp;
	}

	return (int)ib_flags;
}

/*
 ****************************************************************************
 Prototype	: to_ib_ah_attr
 Description  : to_ib_ah_attr
 Input		: struct roce3_device *rdev
				struct ib_ah_attr *ah_attr(struct rdma_ah_attr *ah_attr)
				struct roce_qp_context *context
 Output	   : None
 Return Value :
 Calls		:
 Called By	:

  History		:
  1.Date		 : 2015/5/26
	Author	   :
	Modification : Created function

****************************************************************************
*/
static void to_ib_ah_attr(struct roce3_device *rdev,
	struct rdma_ah_attr *ah_attr, struct roce_qp_context *context)
{
	struct drv_path_info *path_seg = &context->sw_seg.path_seg;

	memset(ah_attr, 0, sizeof(*ah_attr));

	ah_attr->port_num = context->sw_seg.ucode_seg.common.dw0.bs.port;

	ah_attr->sl = 0x7 - path_seg->dw7.bs.sl;

	ah_attr->static_rate = 0;

	ah_attr->ah_flags = IB_AH_GRH;

	ah_attr->grh.sgid_index = path_seg->dw7.bs.sgid_index;
	ah_attr->grh.hop_limit = path_seg->dw7.bs.hoplmt;
	ah_attr->grh.traffic_class = path_seg->dw6.bs.tclass;
	ah_attr->grh.flow_label = path_seg->dw6.bs.flow_label;

	memcpy((void *)ah_attr->grh.dgid.raw, (void *)path_seg->dgid,
		sizeof(ah_attr->grh.dgid.raw));
}

/*
 ****************************************************************************
 Prototype	: roce3_qp_query
 Description  : roce3_qp_query
 Input		: struct roce3_device *rdev
				struct roce3_qp *qp
				struct roce_qp_context *context
 Output	   : None

  1.Date		 : 2015/5/26
	Modification : Created function

****************************************************************************
*/
int roce3_qp_query(struct roce3_device *rdev, u32 qpn, u32 *context, int qpc_size)
{
	int ret;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_cqm_cmd_buf *cqm_cmd_outbuf = NULL;
	struct tag_roce_cmd_qp_query *qp_query_inbuf = NULL;
	struct roce3_qp_query_outbuf *qp_query_outbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_cmd_qp_query), &cqm_cmd_outbuf,
		(u16)sizeof(struct roce3_qp_query_outbuf));
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	qp_query_inbuf = (struct tag_roce_cmd_qp_query *)cqm_cmd_inbuf->buf;
	qp_query_outbuf = (struct roce3_qp_query_outbuf *)cqm_cmd_outbuf->buf;
	qp_query_inbuf->com.index = cpu_to_be32(qpn);
	qp_query_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_QP_BITMASK); //lint !e778
	ret = roce3_send_qp_lb_cmd(qpn, rdev, ROCE_CMD_QUERY_QP,
		cqm_cmd_inbuf, cqm_cmd_outbuf, ROCE_CMD_TIME_CLASS_B);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to send QUERY_QP command, func_id(%d)\n",
			__func__, rdev->glb_func_id);

		if (roce3_hca_is_present(rdev) != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE] %s: HCA is present(QUERY_QP), qpn(0x%x), func_id(%u)\n",
				__func__, qpn, rdev->glb_func_id);

			if ((ret == -ETIMEDOUT) || (ret == -EPERM))
				rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;
		}

		ret = -1;
		goto free_cqm_buf;
	}

	memcpy((void *)context, (void *)&qp_query_outbuf->qpc, (size_t)qpc_size);
	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);
	return 0;

free_cqm_buf:
	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);

	return ret;
}

/*
 ****************************************************************************
 Prototype	: qpc_seg_to_le32
 Input		: struct roce_qp_context *le_ctx
				struct roce_qp_context *be_ctx
				struct roce3_qp *rqp
 Output	   : None

  1.Date		 : 2015/8/15
	Modification : Created function

****************************************************************************
*/
void qpc_seg_to_le32(struct roce_qp_context *be_ctx, struct roce_qp_context *le_ctx, u32 srq_vld)
{
	/* DRV Seg */
	memcpy((void *)le_ctx->sw_seg.path_seg.dgid,
		(void *)be_ctx->sw_seg.path_seg.dgid, sizeof(be_ctx->sw_seg.path_seg.dgid));

	/* CHIP Seg */
	le_ctx->chip_seg.qpcc.sq_rq_l0mtt_gpa = be64_to_cpu(be_ctx->chip_seg.qpcc.sq_rq_l0mtt_gpa);

	le_ctx->chip_seg.qpcc.sq_rq_pi_record_gpa_at_hop_num =
		cpu_to_be64(be_ctx->chip_seg.qpcc.sq_rq_pi_record_gpa_at_hop_num);

	le_ctx->chip_seg.rcc.rc_curt_sge_va = be64_to_cpu(be_ctx->chip_seg.rcc.rc_curt_sge_va);

	le_ctx->chip_seg.sqc.sq_curt_sge_va = be64_to_cpu(be_ctx->chip_seg.sqc.sq_curt_sge_va);

	le_ctx->chip_seg.sqac.sqa_curt_sge_va = be64_to_cpu(be_ctx->chip_seg.sqac.sqa_curt_sge_va);

	if (srq_vld != 0) {
		le_ctx->chip_seg.srqc.srq_curt_sge_va =
			be64_to_cpu(be_ctx->chip_seg.srqc.srq_curt_sge_va);
	} else {
		le_ctx->chip_seg.rqc.rq_curt_sge_va =
			be64_to_cpu(be_ctx->chip_seg.rqc.rq_curt_sge_va);
	}

	le_ctx->chip_seg.rrwc.rrw_curt_sge_va = be64_to_cpu(be_ctx->chip_seg.rrwc.rrw_curt_sge_va);

	le_ctx->chip_seg.rrwc.rrw_curt_sge_va = be64_to_cpu(be_ctx->chip_seg.rrwc.rrw_curt_sge_va);
}

void roce3_be32_2_le32(void *context, u32 *le_ctx, u32 ctx_size)
{
	u32 *ctx = NULL, *ctx1 = NULL;
	u32 i = 0;

	ctx = le_ctx;
	ctx1 = (u32 *)context;

	for (i = 0; i < ctx_size; ++i, ++ctx1, ++ctx)
		*ctx = be32_to_cpu(*ctx1);
}

static void roce3_get_ah_attr(const struct roce3_qp *rqp, struct ib_qp_attr *qp_attr,
	struct roce3_device *rdev, struct roce_qp_context *context)
{
	if ((rqp->qp_type == IB_QPT_RC) || (rqp->qp_type == IB_QPT_UC))
		to_ib_ah_attr(rdev, &qp_attr->ah_attr, context);
}

static void roce3_query_set_common_attr(struct ib_qp_attr *qp_attr,
	const struct ib_qp *ibqp, struct roce3_qp *rqp, struct ib_qp_init_attr *qp_init_attr)
{
	qp_attr->cur_qp_state = qp_attr->qp_state;
	qp_attr->cap.max_recv_wr = (u32)rqp->rq.wqebb_cnt;
	qp_attr->cap.max_recv_sge = (u32)rqp->rq.max_sge;

	if (!ibqp->uobject) {
		qp_attr->cap.max_send_wr = (u32)rqp->sq.max_post;
		qp_attr->cap.max_send_sge = (u32)rqp->sq.max_sge;
	} else {
		qp_attr->cap.max_send_wr = 0;
		qp_attr->cap.max_send_sge = 0;
	}

	qp_attr->cap.max_inline_data = rqp->max_inline_data;

	qp_init_attr->cap = qp_attr->cap;

	qp_init_attr->create_flags = (enum ib_qp_create_flags)0;

	qp_init_attr->sq_sig_type = (rqp->sq_signal_bits == 1) ?
		IB_SIGNAL_ALL_WR : IB_SIGNAL_REQ_WR;
}

static void roce3_query_set_attr(struct ib_qp_attr *qp_attr, u8 tmp_qp_state, struct roce3_qp *rqp,
	struct roce_qp_context context, struct roce3_device *rdev)
{
	qp_attr->qp_state = (enum ib_qp_state)rqp->qp_state;
	qp_attr->path_mtu = (enum ib_mtu)context.sw_seg.drv_seg.dw2.bs.pmtu;
	qp_attr->path_mig_state = (enum ib_mig_state)to_ib_mig_state(ROCE_QP_PM_MIGRATED);
	qp_attr->qkey = context.sw_seg.ucode_seg.common.dw2.qkey;
	qp_attr->rq_psn = context.sw_seg.ucode_seg.rq_ctx.dw20.bs.next_rcv_psn;
	qp_attr->sq_psn = context.sw_seg.ucode_seg.sq_ctx.dw8.bs.next_send_psn;
	qp_attr->dest_qp_num = context.sw_seg.drv_seg.dw0.bs.dest_qp;
	qp_attr->qp_access_flags = to_ib_qp_access_flags(&context);

	roce3_get_ah_attr(rqp, qp_attr, rdev, &context);

	qp_attr->pkey_index = 0;

	if (qp_attr->qp_state == IB_QPS_INIT)
		qp_attr->port_num = rqp->port;
	else
		qp_attr->port_num = context.sw_seg.ucode_seg.common.dw0.bs.port;

	/* qp_attr->en_sqd_async_notify is only applicable in modify qp */

	/* SQ Draining FLAG */
	qp_attr->sq_draining = (tmp_qp_state == ROCE_QP_STATE_SQ_DRAINING);

	qp_attr->max_rd_atomic = (1 << context.sw_seg.drv_seg.dw3.bs.sra_max);
	qp_attr->max_dest_rd_atomic = (1 << context.sw_seg.drv_seg.dw3.bs.rra_max);

	qp_attr->min_rnr_timer = context.sw_seg.drv_seg.dw2.bs.min_rnr_nak;
	qp_attr->timeout = context.sw_seg.drv_seg.dw2.bs.ack_to;
	qp_attr->retry_cnt = context.sw_seg.drv_seg.dw2.bs.to_retry_limit;
	qp_attr->rnr_retry = context.sw_seg.drv_seg.dw2.bs.rnr_retry_limit;
}

static int roce3_query_qp_struct_clean(struct ib_qp_attr *qp_attr,
	struct ib_qp_init_attr *qp_init_attr, struct roce_qp_context *be_ctx,
	struct roce_qp_context *context)
{
	memset(qp_attr, 0, sizeof(struct ib_qp_attr));
	memset(qp_init_attr, 0, sizeof(struct ib_qp_init_attr));
	memset(be_ctx, 0, sizeof(struct roce_qp_context));
	memset(context, 0, sizeof(struct roce_qp_context));

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_query_qp
 Description  : roce3_query_qp
 Input		: struct ib_qp *ibqp
				struct ib_qp_attr *qp_attr
				int qp_attr_mask
				struct ib_qp_init_attr *qp_init_attr
 Output	   : None

  1.Date		 : 2015/4/29
	Modification : Created function

****************************************************************************
*/
int roce3_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
	struct ib_qp_init_attr *qp_init_attr)
{
	int ret = 0;
	struct roce3_qp *rqp = NULL;
	struct roce3_device *rdev = NULL;
	struct roce_qp_context be_ctx;  /* BE context structure */
	struct roce_qp_context context; /* LE context structure */
	u32 srq_vld;
	u8 tmp_qp_state = 0;

	ret = roce3_query_qp_struct_clean(qp_attr, qp_init_attr, &be_ctx, &context);
	if (ret != 0)
		return ret;

	rqp = to_roce3_qp(ibqp);
	rdev = to_roce3_dev(ibqp->device);
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	mutex_lock(&rqp->mutex);

	if (rqp->qp_state == IB_QPS_RESET) {
		qp_attr->qp_state = IB_QPS_RESET;
		goto done;
	}

	ret = roce3_qp_query(rdev, rqp->qpn, (u32 *)(void *)(&be_ctx), sizeof(be_ctx));
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to query qp, ret(%d), func_id(%d)\n",
			__func__, ret, rdev->glb_func_id);
		mutex_unlock(&rqp->mutex);
		return ret;
	}

	srq_vld = (!(rqp->ibqp.srq)) ? ROCE_QP_NO_SRQ : ROCE_QP_HAS_SRQ;
	roce3_be32_2_le32(&be_ctx, (u32 *)(void *)&context,
		sizeof(struct roce_qp_context) / sizeof(u32));

	qpc_seg_to_le32(&be_ctx, &context, srq_vld);

	rqp->qp_state = context.sw_seg.drv_seg.dw0.bs.state; /* state:4bits */

	tmp_qp_state = rqp->qp_state;
	if (rqp->qp_state == ROCE_QP_STATE_SQ_DRAINING)
		rqp->qp_state = IB_QPS_SQD;

	roce3_query_set_attr(qp_attr, tmp_qp_state, rqp, context, rdev);

done:
	roce3_query_set_common_attr(qp_attr, ibqp, rqp, qp_init_attr);

	mutex_unlock(&rqp->mutex);

	return 0;
}
