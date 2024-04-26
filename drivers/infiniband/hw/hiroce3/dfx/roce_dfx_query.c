// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#ifdef __ROCE_DFX__

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/kthread.h>

#include <rdma/ib_verbs.h>
#include "roce_compat.h"
#include "roce.h"
#include "roce_dfx.h"
#include "roce_srq.h"
#include "roce_qp.h"
#include "roce_cq.h"
#include "hinic3_hw.h"
#include "roce_cmd.h"
#include "roce_pub_cmd.h"
#include "roce_cqm_cmd.h"

int roce3_dfx_cmd_query_qp(struct roce3_device *rdev, u32 qpn, struct roce_qp_context *qp_ctx)
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
		roce3_dfx_print("Failed to alloc cqm_cmd_inoutbuf, ret=%d", ret);
		return ret;
	}

	qp_query_inbuf = (struct tag_roce_cmd_qp_query *)cqm_cmd_inbuf->buf;
	qp_query_inbuf->com.dw0.bs.cmd_bitmask = cpu_to_be16(VERBS_CMD_TYPE_QP_BITMASK);
	qp_query_inbuf->com.index = cpu_to_be32(qpn);

	if ((rdev->cfg_info.lb_en != 0) && (rdev->cfg_info.lb_mode == ROCE_LB_MODE_1)) {
		u8 cos = qpn & 0x3;

		roce3_dfx_print("%s: lb_mode1 func_id(%d) qpn:%u cos:%u\n",
				__func__, rdev->glb_func_id, qpn, cos);
		ret = cqm_lb_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_QUERY_QP,
			cos, cqm_cmd_inbuf, cqm_cmd_outbuf,
			NULL, ROCE_CMD_TIME_CLASS_B, HINIC3_CHANNEL_ROCE);
	} else {
		roce3_dfx_print("%s: Not lb_mode1 func_id(%d) qpn:%u\n",
				__func__, rdev->glb_func_id, qpn);
		ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_QUERY_QP,
			cqm_cmd_inbuf, cqm_cmd_outbuf, NULL,
			ROCE_CMD_TIME_CLASS_B, HINIC3_CHANNEL_ROCE);
	}

	if (ret != 0) {
		roce3_dfx_print("Failed to send cmd QUERY_QP");
		ret = -1;
		goto out;
	}

	qp_query_outbuf = (struct roce3_qp_query_outbuf *)cqm_cmd_outbuf->buf;
	memcpy(qp_ctx, &qp_query_outbuf->qpc, sizeof(struct roce_qp_context));
out:
	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);
	return ret;
}

static int roce3_dfx_get_dev_algo(const struct roce3_dfx_query_inbuf *inbuf,
	struct roce3_device *rdev, union roce3_dfx_query_outbuf *outbuf)
{
	u32 cc_algo;
	struct roce3_ecn_ctx ecn_ctx;
	u32 *algo_type = &outbuf->algo_type;

	if (rdev == NULL) {
		pr_err("[ROCE, ERR] %s: Failed to get roce device.\n", __func__);
		return -EINVAL;
	}
	ecn_ctx = rdev->ecn_ctx;
	cc_algo = ecn_ctx.cc_algo;
	*algo_type = cc_algo;

	return 0;
}

static int roce3_dfx_get_qp_count(const struct roce3_dfx_query_inbuf *inbuf,
	struct roce3_device *rdev, union roce3_dfx_query_outbuf *outbuf)
{
	struct roce3_dfx_qp_count *qp_count = &outbuf->qp_count;

	qp_count->qp_alloced = rdev->qp_cnt.alloc_qp_cnt;
	qp_count->qp_deleted = rdev->qp_cnt.del_qp_cnt;
	qp_count->qp_alive = rdev->qp_cnt.alloc_qp_cnt - rdev->qp_cnt.del_qp_cnt;

	return 0;
}

/*
 * QPC is statically allocated, so it is not necessary to judge
 * whether it exists when querying the cache content
 */
static int roce3_dfx_query_cache_qpc(const struct roce3_dfx_query_inbuf *inbuf,
	struct roce3_device *rdev, union roce3_dfx_query_outbuf *outbuf)
{
	int ret;
	u32 qpn = inbuf->qpn;
	struct roce_qp_context *qp_ctx = &outbuf->qp_ctx;

	memset(qp_ctx, 0, sizeof(struct roce_qp_context));
	ret = roce3_dfx_cmd_query_qp(rdev, qpn, qp_ctx);
	if (ret != 0) {
		roce3_dfx_print("Failed to query QPC from cache!");
		roce3_dfx_print("******************From Cache: qpn(%#x) ********************", qpn);
		roce3_dfx_print(">>>>>>>>>>>>>>>> QUERY QPC FROM CACHE FAILED <<<<<<<<<<<<<<<<<");
		roce3_dfx_print("******************From Cache: qpn(%#x) ********************", qpn);

		return ret;
	}

	return 0;
}

static int roce3_dfx_query_host_qpc(const struct roce3_dfx_query_inbuf *inbuf,
	struct roce3_device *rdev, union roce3_dfx_query_outbuf *outbuf)
{
	struct tag_cqm_object *cqm_obj_qp = NULL;
	struct roce3_qp *rqp = NULL;
	u32 qpn = inbuf->qpn;
	struct roce_qp_context *qp_ctx = &outbuf->qp_ctx;

	cqm_obj_qp = cqm_object_get(rdev->hwdev, CQM_OBJECT_SERVICE_CTX, qpn, false);
	if (cqm_obj_qp == NULL) {
		roce3_dfx_print("Failed to get cqm_obj_qp.");
		roce3_dfx_print("******************From Host: qpn(%#x) ********************", qpn);
		roce3_dfx_print(">>>>>>>>>>> QUERY QPC FROM HOST FAILED, NOT EXIST <<<<<<<<<<<");
		roce3_dfx_print("******************From Host: qpn(%#x) ********************", qpn);

		return -EINVAL;
	}

	rqp = cqmobj_to_roce_qp(cqm_obj_qp);
	hiudk_cqm_object_put(rdev->hwdev, cqm_obj_qp);

	memcpy(qp_ctx, rqp->qpc_info->vaddr, sizeof(struct roce_qp_context));

	return 0;
}

int roce3_dfx_cmd_query_cq(struct roce3_device *rdev, u32 cqn, struct roce_cq_context *cq_ctx)
{
	int ret;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_cqm_cmd_buf *cqm_cmd_outbuf = NULL;
	struct tag_roce_cmd_roce_cq_query *cq_query_inbuf = NULL;
	struct roce3_cq_query_outbuf *cq_query_outbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_cmd_roce_cq_query), &cqm_cmd_outbuf,
		(u16)sizeof(struct roce3_cq_query_outbuf));
	if (ret != 0) {
		roce3_dfx_print("Failed to alloc cqm_cmd_inoutbuf, ret=%d", ret);
		return ret;
	}

	cq_query_inbuf = (struct tag_roce_cmd_roce_cq_query *)cqm_cmd_inbuf->buf;
	cq_query_inbuf->com.index = cpu_to_be32(cqn);
	cq_query_inbuf->com.dw0.bs.cmd_bitmask = cpu_to_be16(VERBS_CMD_TYPE_CQ_BITMASK);

	ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_QUERY_CQ, cqm_cmd_inbuf,
		cqm_cmd_outbuf, NULL, ROCE_CMD_TIME_CLASS_B, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		roce3_dfx_print("Failed to send cmd QUERY_CQ, ret=%d", ret);
		ret = -1;
		goto out;
	}

	cq_query_outbuf = (struct roce3_cq_query_outbuf *)cqm_cmd_outbuf->buf;
	memcpy(cq_ctx, &cq_query_outbuf->cqc, sizeof(struct roce_cq_context));
out:
	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);

	return ret;
}

/*
 * CQC is dynamic allocation. When querying cache content,
 * you need to determine whether it exists or not.
 */
static int roce3_dfx_query_cache_cqc(const struct roce3_dfx_query_inbuf *inbuf,
	struct roce3_device *rdev, union roce3_dfx_query_outbuf *outbuf)
{
	int ret;
	struct tag_cqm_object *cqm_obj_cq = NULL;
	u32 cqn = inbuf->cqn;
	struct roce_cq_context *cq_ctx = &outbuf->cq_ctx;

	cqm_obj_cq = cqm_object_get(rdev->hwdev, CQM_OBJECT_RDMA_SCQ, cqn, false);
	if (cqm_obj_cq == NULL) {
		roce3_dfx_print("Failed to get cqm_obj_cq.");
		roce3_dfx_print("******************From Cache: cqn(%#x) ********************", cqn);
		roce3_dfx_print(">>>>>>>>>>> QUERY CQC FROM CACHE FAILED, NOT EXIST <<<<<<<<<<<");
		roce3_dfx_print("******************From Cache: cqn(%#x) ********************", cqn);

		return -EINVAL;
	}

	hiudk_cqm_object_put(rdev->hwdev, cqm_obj_cq);

	memset(cq_ctx, 0, sizeof(struct roce_cq_context));
	ret = roce3_dfx_cmd_query_cq(rdev, cqn, cq_ctx);
	if (ret != 0) {
		roce3_dfx_print("Failed to query cq from cache!");
		roce3_dfx_print("******************From Cache: cqn(%#x) ********************", cqn);
		roce3_dfx_print(">>>>>>>>>>>>>>>> QUERY CQC FROM CACHE FAILED <<<<<<<<<<<<<<<<<");
		roce3_dfx_print("******************From Cache: cqn(%#x) ********************", cqn);

		return -EINVAL;
	}

	return 0;
}

static int roce3_dfx_query_host_cqc(const struct roce3_dfx_query_inbuf *inbuf,
	struct roce3_device *rdev, union roce3_dfx_query_outbuf *outbuf)
{
	struct tag_cqm_object *cqm_obj_cq = NULL;
	struct roce3_cq *rcq = NULL;
	u32 cqn = inbuf->cqn;
	struct roce_cq_context *cq_ctx = &outbuf->cq_ctx;

	cqm_obj_cq = cqm_object_get(rdev->hwdev, CQM_OBJECT_RDMA_SCQ, cqn, false);
	if (cqm_obj_cq == NULL) {
		roce3_dfx_print("Failed to get cqm_obj_cq.");
		roce3_dfx_print("******************From Host: cqn(%#x) ********************", cqn);
		roce3_dfx_print(">>>>>>>>>>> QUERY CQC FROM HOST FAILED, NOT EXIST <<<<<<<<<<<");
		roce3_dfx_print("******************From Host: cqn(%#x) ********************", cqn);

		return -EINVAL;
	}

	rcq = cqmobj_to_roce3_cq(cqm_obj_cq);
	hiudk_cqm_object_put(rdev->hwdev, cqm_obj_cq);

	memcpy(cq_ctx, rcq->cqm_cq->q_ctx_vaddr, sizeof(struct roce_cq_context));

	return 0;
}

int roce3_dfx_cmd_query_srq(struct roce3_device *rdev, u32 srqn, struct roce_srq_context *srq_ctx)
{
	int ret;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_cqm_cmd_buf *cqm_cmd_outbuf = NULL;
	struct tag_roce_cmd_srq_query *srq_query_inbuf = NULL;
	struct roce3_srq_query_outbuf *srq_query_outbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_cmd_srq_query), &cqm_cmd_outbuf,
		(u16)sizeof(struct roce3_srq_query_outbuf));
	if (ret != 0) {
		roce3_dfx_print("Failed to alloc cqm_cmd_inoutbuf, ret=%d", ret);
		return ret;
	}

	srq_query_inbuf = (struct tag_roce_cmd_srq_query *)cqm_cmd_inbuf->buf;
	srq_query_inbuf->com.index = cpu_to_be32(srqn);
	srq_query_inbuf->com.dw0.bs.cmd_bitmask = cpu_to_be16(VERBS_CMD_TYPE_SRQ_BITMASK);

	ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_QUERY_SRQ,
		cqm_cmd_inbuf, cqm_cmd_outbuf, NULL, ROCE_CMD_TIME_CLASS_B, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		roce3_dfx_print("Failed to send cmd QUERY_SRQ, ret=%d", ret);
		ret = -1;
		goto out;
	}

	srq_query_outbuf = (struct roce3_srq_query_outbuf *)cqm_cmd_outbuf->buf;
	memcpy(srq_ctx, srq_query_outbuf,
		sizeof(struct roce3_srq_query_outbuf));
out:
	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);

	return ret;
}

/*
 * SRQC is dynamic allocation. When querying the cache content,
 * you need to determine whether it exists or not.
 */
static int roce3_dfx_query_cache_srqc(const struct roce3_dfx_query_inbuf *inbuf,
	struct roce3_device *rdev, union roce3_dfx_query_outbuf *outbuf)
{
	int ret;
	struct tag_cqm_object *cqm_obj_srq = NULL;
	u32 srqn = inbuf->srqn;
	struct roce_srq_context *srq_ctx = &outbuf->srq_ctx;

	cqm_obj_srq = cqm_object_get(rdev->hwdev, CQM_OBJECT_RDMA_SRQ, srqn, false);
	if (cqm_obj_srq == NULL) {
		roce3_dfx_print("Failed to get cqm_obj_srq");
		roce3_dfx_print("******************From Cache: srqn(%#x) ********************",
			srqn);
		roce3_dfx_print(">>>>>>>>>>> QUERY CQC FROM CACHE FAILED, NOT EXIST <<<<<<<<<<<");
		roce3_dfx_print("******************From Cache: srqn(%#x) ********************",
			srqn);

		return -EINVAL;
	}

	hiudk_cqm_object_put(rdev->hwdev, cqm_obj_srq);

	memset(srq_ctx, 0, sizeof(struct roce_srq_context));
	ret = roce3_dfx_cmd_query_srq(rdev, srqn, srq_ctx);
	if (ret != 0) {
		roce3_dfx_print("Failed to query srq from cache");
		roce3_dfx_print("******************From Cache: srqn(%#x) ********************",
			srqn);
		roce3_dfx_print(">>>>>>>>>>>>>>>> QUERY SRQC FROM CACHE FAILED <<<<<<<<<<<<<<<<<");
		roce3_dfx_print("******************From Cache: srqn(%#x) ********************",
			srqn);

		return -EINVAL;
	}

	return 0;
}

static int roce3_dfx_query_host_srqc(const struct roce3_dfx_query_inbuf *inbuf,
	struct roce3_device *rdev, union roce3_dfx_query_outbuf *outbuf)
{
	struct tag_cqm_object *cqm_obj_srq = NULL;
	struct roce3_srq *rsrq = NULL;
	u32 srqn = inbuf->srqn;
	struct roce_srq_context *srq_ctx = &outbuf->srq_ctx;

	cqm_obj_srq = cqm_object_get(rdev->hwdev, CQM_OBJECT_RDMA_SRQ, srqn, false);
	if (cqm_obj_srq == NULL) {
		roce3_dfx_print("Failed to get cqm_obj_srq.");
		roce3_dfx_print("******************From Host: srqn(%#x) ********************",
			srqn);
		roce3_dfx_print(">>>>>>>>>>> QUERY SRQC FROM HOST FAILED, NOT EXIST <<<<<<<<<<<");
		roce3_dfx_print("******************From Host: srqn(%#x) ********************",
			srqn);

		return -EINVAL;
	}

	rsrq = cqmobj_to_roce3_srq(cqm_obj_srq);
	hiudk_cqm_object_put(rdev->hwdev, cqm_obj_srq);

	memcpy(srq_ctx, rsrq->cqm_srq->q_ctx_vaddr, sizeof(struct roce_srq_context));

	return 0;
}

static int roce3_dfx_cmd_query_mpt(struct roce3_device *rdev, u32 key,
	struct roce_mpt_context *mpt_entry)
{
	int ret;
	u32 mpt_index;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_cqm_cmd_buf *cqm_cmd_outbuf = NULL;
	struct tag_roce_cmd_mpt_query *mpt_query_inbuf = NULL;
	struct roce3_mpt_query_outbuf *mpt_query_outbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_cmd_mpt_query), &cqm_cmd_outbuf,
		(u16)sizeof(struct roce3_mpt_query_outbuf));
	if (ret != 0) {
		roce3_dfx_print("Failed to alloc cqm_cmd_inoutbuf, ret=%d", ret);
		return ret;
	}

	mpt_query_inbuf = (struct tag_roce_cmd_mpt_query *)cqm_cmd_inbuf->buf;
	mpt_index = (key >> MR_KEY_2_INDEX_SHIFT) & 0xFFFFFF;
	mpt_query_inbuf->com.index = cpu_to_be32(mpt_index);
	mpt_query_inbuf->com.dw0.bs.cmd_bitmask = cpu_to_be16(VERBS_CMD_TYPE_MR_BITMASK);

	ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_QUERY_MPT,
		cqm_cmd_inbuf, cqm_cmd_outbuf, NULL, ROCE_CMD_TIME_CLASS_B, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		roce3_dfx_print("Failed to send cmd QUERY_MPT");
		ret = -1;
		goto out;
	}

	mpt_query_outbuf = (struct roce3_mpt_query_outbuf *)cqm_cmd_outbuf->buf;
	memcpy(mpt_entry, &mpt_query_outbuf->mpt_entry,
		sizeof(struct roce_mpt_context));
out:
	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);
	return ret;
}

static int roce3_dfx_cmd_query_gid(struct roce3_device *rdev, u32 port, u32 gid_index,
	struct rdma_gid_entry *gid_entry)
{
	int ret;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_cqm_cmd_buf *cqm_cmd_outbuf = NULL;
	struct tag_roce_qurey_gid *gid_query_inbuf = NULL;
	struct rdma_gid_query_outbuf *gid_query_outbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_qurey_gid), &cqm_cmd_outbuf,
		(u16)sizeof(struct rdma_gid_query_outbuf));
	if (ret != 0) {
		roce3_dfx_print("Failed to alloc cqm_cmd_inoutbuf, ret=%d", ret);
		return ret;
	}

	gid_query_inbuf = (struct tag_roce_qurey_gid *)cqm_cmd_inbuf->buf;
	gid_query_inbuf->port = cpu_to_be32(port);
	gid_query_inbuf->com.index = cpu_to_be32(gid_index);
	gid_query_inbuf->com.dw0.bs.cmd_bitmask = cpu_to_be16(VERBS_CMD_TYPE_GID_BITMASK);
	ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, ROCE_CMD_QUERY_GID, cqm_cmd_inbuf,
		cqm_cmd_outbuf, NULL, ROCE_CMD_TIME_CLASS_B, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		roce3_dfx_print("Failed to send cmd QUERY_GID");
		ret = -1;
		goto out;
	}

	gid_query_outbuf = (struct rdma_gid_query_outbuf *)cqm_cmd_outbuf->buf;
	memcpy(gid_entry, &gid_query_outbuf->gid_entry, sizeof(struct rdma_gid_entry));
out:
	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);

	return ret;
}

/*
 * MPT is statically allocated, so it is not necessary to
 * judge whether it exists when querying the cache content
 */
static int roce3_dfx_query_cache_mpt(const struct roce3_dfx_query_inbuf *inbuf,
	struct roce3_device *rdev, union roce3_dfx_query_outbuf *outbuf)
{
	int ret;
	u32 mpt_key = inbuf->mpt_key;
	struct roce_mpt_context *mpt_entry = &outbuf->mpt;

	memset(mpt_entry, 0, sizeof(struct roce_mpt_context));
	ret = roce3_dfx_cmd_query_mpt(rdev, mpt_key, mpt_entry);
	if (ret != 0) {
		roce3_dfx_print("Failed to query mpt from cache!");
		roce3_dfx_print("******************From Cache: mpt_key(%#x) ********************",
			mpt_key);
		roce3_dfx_print(">>>>>>>>>>>>>>>> QUERY MPT FROM CACHE FAILED <<<<<<<<<<<<<<<<<");
		roce3_dfx_print("******************From Cache: mpt_key(%#x) ********************",
			mpt_key);

		return ret;
	}

	return 0;
}

static int roce3_dfx_query_host_mpt(const struct roce3_dfx_query_inbuf *inbuf,
	struct roce3_device *rdev, union roce3_dfx_query_outbuf *outbuf)
{
	u32 mpt_index = 0;
	struct tag_cqm_object *cqm_obj_mpt = NULL;
	struct tag_cqm_qpc_mpt *cqm_mpt = NULL;
	struct rdma_mpt *rmpt = NULL;
	u32 mpt_key = inbuf->mpt_key;
	struct roce_mpt_context *mpt_entry = &outbuf->mpt;

	mpt_index = (mpt_key >> MR_KEY_2_INDEX_SHIFT) & 0xFFFFFF;
	cqm_obj_mpt = cqm_object_get(rdev->hwdev, CQM_OBJECT_MPT, mpt_index, false);
	if (cqm_obj_mpt == NULL) {
		roce3_dfx_print("Failed to get cqm_obj_mpt.");
		roce3_dfx_print("******************From Host: mpt_key(%#x) ********************",
			mpt_key);
		roce3_dfx_print(">>>>>>>>>>> QUERY MPT FROM HOST FAILED, NOT EXIST <<<<<<<<<<<");
		roce3_dfx_print("******************From Host: mpt_key(%#x) ********************",
			mpt_key);

		return -EINVAL;
	}

	cqm_mpt = container_of(cqm_obj_mpt, struct tag_cqm_qpc_mpt, object);
	rmpt = (struct rdma_mpt *)cqm_mpt->priv;
	hiudk_cqm_object_put(rdev->hwdev, cqm_obj_mpt);

	memcpy(mpt_entry, rmpt->vaddr, sizeof(struct roce_mpt_context));

	return 0;
}

static int roce3_dfx_query_cache_gid(const struct roce3_dfx_query_inbuf *inbuf,
	struct roce3_device *rdev, union roce3_dfx_query_outbuf *outbuf)
{
	int ret;
	u32 gid_index = inbuf->gid_index;
	struct rdma_gid_entry *gid_entry = &outbuf->gid_entry;

	memset(gid_entry, 0, sizeof(struct rdma_gid_entry));
	ret = roce3_dfx_cmd_query_gid(rdev, 0, gid_index, gid_entry);
	if (ret != 0) {
		roce3_dfx_print("***************port(1), gid_index(%d) *****************",
			gid_index);
		roce3_dfx_print("Failed to query gid from cache!");
		roce3_dfx_print("***************port(1), gid_index(%d) *****************",
			gid_index);

		return -EINVAL;
	}

	return 0;
}

static void roce3_dfx_query_pi_ci_b32_to_cpu(struct roce_qp_context *qp_ctx)
{
	qp_ctx->chip_seg.sqc.dw0.value = be32_to_cpu(qp_ctx->chip_seg.sqc.dw0.value);
	qp_ctx->chip_seg.sqc.dw2.value = be32_to_cpu(qp_ctx->chip_seg.sqc.dw2.value);
	qp_ctx->chip_seg.sqc.dw3.value = be32_to_cpu(qp_ctx->chip_seg.sqc.dw3.value);
	qp_ctx->chip_seg.sqc.dw7.value = be32_to_cpu(qp_ctx->chip_seg.sqc.dw7.value);
	qp_ctx->chip_seg.sqc.dw14.value = be32_to_cpu(qp_ctx->chip_seg.sqc.dw14.value);
	qp_ctx->chip_seg.rqc.dw0.value = be32_to_cpu(qp_ctx->chip_seg.rqc.dw0.value);
	qp_ctx->chip_seg.rqc.dw3.value = be32_to_cpu(qp_ctx->chip_seg.rqc.dw3.value);
	qp_ctx->chip_seg.rqc.dw7.value = be32_to_cpu(qp_ctx->chip_seg.rqc.dw7.value);
	qp_ctx->chip_seg.rqc.dw14.value = be32_to_cpu(qp_ctx->chip_seg.rqc.dw14.value);
	qp_ctx->chip_seg.sqac.dw3.value = be32_to_cpu(qp_ctx->chip_seg.sqac.dw3.value);
	qp_ctx->chip_seg.sqac.dw7.value = be32_to_cpu(qp_ctx->chip_seg.sqac.dw7.value);
	qp_ctx->chip_seg.rcc.dw5.value = be32_to_cpu(qp_ctx->chip_seg.rcc.dw5.value);
	qp_ctx->chip_seg.rcc.dw6.value = be32_to_cpu(qp_ctx->chip_seg.rcc.dw6.value);
	qp_ctx->chip_seg.rcc.dw7.value = be32_to_cpu(qp_ctx->chip_seg.rcc.dw7.value);
	qp_ctx->chip_seg.qpcc.dw4.value = be32_to_cpu(qp_ctx->chip_seg.qpcc.dw4.value);
}

static void roce3_dfx_query_pi_ci_set(struct roce_qp_context qp_ctx, struct roce3_dfx_pi_ci *pi_ci)
{
	pi_ci->qpc_sq_pi_on_chip = qp_ctx.chip_seg.sqc.dw0.bs.sq_pi_on_chip;
	pi_ci->qpc_sq_pi = qp_ctx.chip_seg.sqc.dw2.bs.sq_pi;
	pi_ci->qpc_sq_load_pi = qp_ctx.chip_seg.sqc.dw3.bs.sq_load_pi;
	pi_ci->qpc_rq_pi_on_chip = qp_ctx.chip_seg.rqc.dw0.bs.rq_pi_on_chip;
	pi_ci->qpc_rq_load_pi = qp_ctx.chip_seg.rqc.dw3.bs.rq_load_pi;
	pi_ci->qpc_rq_pi = qp_ctx.chip_seg.rqc.dw7.bs.rq_pi;
	pi_ci->qpc_rc_pi = qp_ctx.chip_seg.rcc.dw5.bs.rc_pi;
	pi_ci->qpc_sq_ci = qp_ctx.chip_seg.sqc.dw3.bs.sq_ci;
	pi_ci->qpc_sq_wqe_prefetch_ci = qp_ctx.chip_seg.sqc.dw7.bs.sq_wqe_prefetch_ci;
	pi_ci->qpc_sq_mtt_prefetch_wqe_ci = qp_ctx.chip_seg.sqc.dw14.bs.sq_mtt_prefetch_wqe_ci;
	pi_ci->qpc_sqa_ci = qp_ctx.chip_seg.sqac.dw3.bs.sqa_ci;
	pi_ci->qpc_sqa_wqe_prefetch_ci = qp_ctx.chip_seg.sqac.dw7.bs.sqa_wqe_prefetch_ci;
	pi_ci->qpc_rq_ci = qp_ctx.chip_seg.rqc.dw3.bs.rq_ci;
	pi_ci->qpc_rq_wqe_prefetch_ci = qp_ctx.chip_seg.rqc.dw7.bs.rq_wqe_prefetch_ci;
	pi_ci->qpc_rq_mtt_prefetch_wqe_ci = qp_ctx.chip_seg.rqc.dw14.bs.rq_mtt_prefetch_wqe_ci;
	pi_ci->qpc_rq_base_ci = qp_ctx.chip_seg.qpcc.dw4.bs.rq_base_ci;
	pi_ci->qpc_rc_ci = qp_ctx.chip_seg.rcc.dw6.bs.rc_ci;
	pi_ci->qpc_rc_prefetch_ci = qp_ctx.chip_seg.rcc.dw7.bs.rc_prefetch_ci;
}

static int roce3_dfx_query_pi_ci(const struct roce3_dfx_query_inbuf *inbuf,
	struct roce3_device *rdev, union roce3_dfx_query_outbuf *outbuf)
{
	int ret;
	struct roce_qp_context qp_ctx;
	struct roce_cq_context cq_ctx;
	u32 qpn = inbuf->query_pi_ci.qpn;
	u32 cqn = inbuf->query_pi_ci.cqn;
	struct roce3_dfx_pi_ci *pi_ci = &outbuf->pi_ci;

	memset(pi_ci, 0, sizeof(struct roce3_dfx_pi_ci));

	memset(&qp_ctx, 0, sizeof(qp_ctx));
	ret = roce3_dfx_cmd_query_qp(rdev, qpn, &qp_ctx);
	if (ret != 0)
		return ret;

	roce3_dfx_query_pi_ci_b32_to_cpu(&qp_ctx);
	roce3_dfx_query_pi_ci_set(qp_ctx, pi_ci);

	memset(&cq_ctx, 0, sizeof(cq_ctx));
	ret = roce3_dfx_cmd_query_cq(rdev, cqn, &cq_ctx);
	if (ret != 0)
		return ret;

	cq_ctx.dw0.value = be32_to_cpu(cq_ctx.dw0.value);
	cq_ctx.dw1.value = be32_to_cpu(cq_ctx.dw1.value);
	cq_ctx.dw2.value = be32_to_cpu(cq_ctx.dw2.value);
	cq_ctx.dw3.value = be32_to_cpu(cq_ctx.dw3.value);
	cq_ctx.dw9.value = be32_to_cpu(cq_ctx.dw9.value);
	cq_ctx.ci_record_gpa_at_hop_num = be32_to_cpu(cq_ctx.ci_record_gpa_at_hop_num);

	pi_ci->cq_ci_on_chip = cq_ctx.dw0.bs.ci_on_chip;
	pi_ci->cq_ci = cq_ctx.dw1.bs.ci;
	pi_ci->cq_load_ci = cq_ctx.dw3.bs.load_ci;
	pi_ci->cq_ci_record_gpa_at_hop_num = cq_ctx.ci_record_gpa_at_hop_num;
	pi_ci->cq_last_solicited_pi = cq_ctx.dw0.bs.last_solicited_pi;
	pi_ci->cq_pi = cq_ctx.dw2.bs.pi;
	pi_ci->cq_last_notified_pi = cq_ctx.dw9.bs.last_notified_pi;

	return 0;
}

typedef int (*roce3_adm_dfx_query_t)(const struct roce3_dfx_query_inbuf *inbuf,
	struct roce3_device *rdev, union roce3_dfx_query_outbuf *outbuf);

static roce3_adm_dfx_query_t roce3_adm_dfx_query_funcs[COMMON_CMD_VM_COMPAT_TEST] = {
	[ROCE_CMD_GET_QPC_FROM_CACHE] = roce3_dfx_query_cache_qpc,
	[ROCE_CMD_GET_QPC_FROM_HOST] = roce3_dfx_query_host_qpc,
	[ROCE_CMD_GET_CQC_FROM_CACHE] = roce3_dfx_query_cache_cqc,
	[ROCE_CMD_GET_CQC_FROM_HOST] = roce3_dfx_query_host_cqc,
	[ROCE_CMD_GET_SRQC_FROM_CACHE] = roce3_dfx_query_cache_srqc,
	[ROCE_CMD_GET_SRQC_FROM_HOST] = roce3_dfx_query_host_srqc,
	[ROCE_CMD_GET_MPT_FROM_CACHE] = roce3_dfx_query_cache_mpt,
	[ROCE_CMD_GET_MPT_FROM_HOST] = roce3_dfx_query_host_mpt,
	[ROCE_CMD_GET_GID_FROM_CACHE] = roce3_dfx_query_cache_gid,
	[ROCE_CMD_GET_QPC_CQC_PI_CI] = roce3_dfx_query_pi_ci,
	[ROCE_CMD_GET_QP_COUNT] = roce3_dfx_get_qp_count,
	[ROCE_CMD_GET_DEV_ALGO] = roce3_dfx_get_dev_algo,
};

int roce3_adm_dfx_query(struct roce3_device *rdev, const void *buf_in, u32 in_size,
	void *buf_out, u32 *out_size)
{
	const struct roce3_dfx_query_inbuf *inbuf = (struct roce3_dfx_query_inbuf *)buf_in;
	union roce3_dfx_query_outbuf *outbuf = (union roce3_dfx_query_outbuf *)buf_out;
	roce3_adm_dfx_query_t roce3_adm_dfx_query_func;

	memset(buf_out, 0, sizeof(union roce3_dfx_query_outbuf));
	*out_size = (u32)sizeof(union roce3_dfx_query_outbuf);

	if (inbuf->cmd_type >= COMMON_CMD_VM_COMPAT_TEST) {
		roce3_dfx_print("Not support this type(%d)", inbuf->cmd_type);
		return -EINVAL;
	}

	roce3_adm_dfx_query_func = roce3_adm_dfx_query_funcs[inbuf->cmd_type];
	if (roce3_adm_dfx_query_func == NULL) {
		roce3_dfx_print("Not support this type(%d)", inbuf->cmd_type);
		return -EINVAL;
	}

	return roce3_adm_dfx_query_func(inbuf, rdev, outbuf);
}

#endif
