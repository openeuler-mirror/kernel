// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <rdma/ib_verbs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>

#include "roce_compat.h"
#include "hinic3_srv_nic.h"

#include "roce.h"
#include "roce_mix.h"
#include "roce_mr.h"
#include "roce_user.h"
#include "roce_xrc.h"
#include "roce_pd.h"
#include "roce_srq.h"
#include "roce_cq.h"
#include "roce_cqm_cmd.h"
#include "roce_qp.h"
#include "roce_qp_exp.h"
#include "roce_qp_extension.h"
#include "roce_main_extension.h"
#include "roce_pub_cmd.h"
#include "roce_verbs_attr.h"
#include "roce_verbs_ext_attr.h"
#include "rdma_context_format.h"

#ifdef ROCE_VBS_EN
#include "roce_vbs_qp.h"
#endif

#ifdef ROCE_ANTI_ATTACK
#include "roce_anti_attack.h"
#include "roce_cmd.h"
#endif

#ifdef __ROCE_DFX__
#include "roce_dfx.h"
#endif

#ifdef ROCE_BONDING_EN
#include "roce_bond.h"
#endif

#define ROCE_MTT_GPA_VALID 0x1
#define ROCE_WQE_PREFETCH_MAXNUM 4
#define ROCE_SQ_WQEBB_SIZE_SHIFT 4
#define ROCE_SQ_WQEBB_SIZE_MASK 0x7
#define ROCE_SQ_PD_MASK 0x3ffff
#define ROCE_SQ_PAGE_SIZE_MASK 0xf
#define ROCE_SQ_WQECNT_LTH 4
#define ROCE_SQ_PREFETCH_MINNUM 2
#define ROCE_SQ_PREFETCH_MAXNUM 4
#define ROCE_SQ_SIZE_MASK 0x1f
#define ROCE_SQ_CQN_MASK 0xfffff
#define ROCE_RQ_WQECNT_LTH 0xe
#define ROCE_RQ_MTT_PREFETCH_MAXLEN0 3
#define ROCE_RQ_MTT_PREFETCH_MAXWQE 7
#define ROCE_RQ_WQE_PREFETCH_MAXNUM 7
#define ROCE_SRQ_INIT_STATE 0xf
#define ROCE_MAX_PI_ON_CHIP_QPN 1024

enum {
	ROCE_IPSUTX_CHANNEL_5 = 0x0,  /* 00 */
	ROCE_IPSUTX_CHANNEL_10 = 0x1, /* 01 */
	ROCE_IPSUTX_CHANNEL_15 = 0x2, /* 10 */
	ROCE_IPSUTX_CHANNEL_20 = 0x3, /* 01 */
};

enum {
	BIT_LENGTH_IB_MTU_256 = 8,
	BIT_LENGTH_IB_MTU_512,
	BIT_LENGTH_IB_MTU_1024,
	BIT_LENGTH_IB_MTU_2048,
	BIT_LENGTH_IB_MTU_4096
};

enum {
	CACHE_INVLAID_ALLOC,
	CACHE_INVLAID_CMDQ,
	CACHE_INVLAID_RDMARC_CHECK,
	CACHE_INVLAID_QP_CHECK,
	MODIFY_2RST_CMDQ,
	CMDQ_SDKCALL_BUTT
};

#define ROCE_CMDQ_TIMEOUT 1000
#define ROCE_CMDQ_TIMEOUT_10MS 10


#ifdef ROCE_COMPUTE
static int g_sq_cqn_lb;
module_param(g_sq_cqn_lb, int, 0444); //lint !e806
MODULE_PARM_DESC(g_sq_cqn_lb, "default: 0");

static int g_rq_cqn_lb;
module_param(g_rq_cqn_lb, int, 0444); //lint !e806
MODULE_PARM_DESC(g_rq_cqn_lb, "default: 0");
#else
static int g_sq_cqn_lb = 1;
module_param(g_sq_cqn_lb, int, 0444); //lint !e806
MODULE_PARM_DESC(g_sq_cqn_lb, "default: 1");

static int g_rq_cqn_lb = 1;
module_param(g_rq_cqn_lb, int, 0444); //lint !e806
MODULE_PARM_DESC(g_rq_cqn_lb, "default: 1");
#endif

static void roce3_timeout_check(struct roce3_device *rdev, const struct timespec64 *tv_start,
	int func_id, int times)
{
	uint64_t cost;
	struct timespec64 delta;
	struct timespec64 tv_end = { 0 };

	ktime_get_ts64(&tv_end);
	delta = timespec64_sub(tv_end, *tv_start);
	cost = delta.tv_sec * USEC_PER_SEC + delta.tv_nsec / NSEC_PER_USEC;

	if (cost >= ROCE_CMDQ_TIMEOUT) {
		dev_warn_ratelimited(rdev->hwdev_hdl,
			"[ROCE, WARN] %s:destroy qp exec too long, func_id(%d), cost(%llu), times:%d\n",
			__func__, func_id, cost, times);
	}
}

#ifdef ROCE_SIGN_EN
enum mtt_check_type_e {
	MTT_CHECK_TYPE_0 = 0,
	MTT_CHECK_TYPE_1
};

#define ROCE_QP_QPCC_SIGN_WIDTH 5
#define ROCE_QP_QPCC_SIGN_SPLITNUM 4
#define ROCE_QP_QPCC_SIGN_CHECKBITS (ROCE_QP_QPCC_SIGN_WIDTH * ROCE_QP_QPCC_SIGN_SPLITNUM)

#define ROCE_QP_SUB_SIGN_WIDTH 3
#define ROCE_QP_SUB_SIGN_SPLITNUM 5
#define ROCE_QP_SUB_SIGN_CHECKBITS (ROCE_QP_SUB_SIGN_WIDTH * ROCE_QP_SUB_SIGN_SPLITNUM)

#define ROCE_QP_GPA_SIGN_WIDTH 3
#define ROCE_QP_GPA_SIGN_SPLITNUM 11
#define ROCE_QP_GPA_SIGN_CHECKBITS (ROCE_QP_GPA_SIGN_WIDTH * ROCE_QP_GPA_SIGN_SPLITNUM)

#define ROCE_SQ_WQE_SIGN_WIDTH 8
#define ROCE_SQ_WQE_SIGN_SPLITNUM 9
#define ROCE_SQ_WQE_SIGN_CHECKBITS_1 32
#define ROCE_SQ_WQE_SIGN_CHECKBITS_2 20
#define ROCE_SQ_WQE_SIGN_CHECKBITS_12 (ROCE_SQ_WQE_SIGN_CHECKBITS_2 + ROCE_SQ_WQE_SIGN_CHECKBITS_1)
#define ROCE_SQ_WQE_SIGN_CHECKBITS_3 20
#define ROCE_SQ_WQE_SIGN_CHECKBITS_123 \
	(ROCE_SQ_WQE_SIGN_CHECKBITS_3 + ROCE_SQ_WQE_SIGN_CHECKBITS_12)
#define ROCE_SQ_WQE_SIGN_CHECKBITS (ROCE_SQ_WQE_SIGN_WIDTH * ROCE_SQ_WQE_SIGN_SPLITNUM)

#define ROCE_MTT_SIGN_WIDTH 11
#define ROCE_MTT_SIGN_SPLITNUM 5
#define ROCE_MTT_SIGN_CHECKBITS_1 22
#define ROCE_MTT_SIGN_CHECKBITS_2 33
#define ROCE_MTT_SIGN_CHECKBITS_12 (ROCE_MTT_SIGN_CHECKBITS_1 + ROCE_MTT_SIGN_CHECKBITS_2)
#define ROCE_MTT_SIGN_CHECKBITS (ROCE_MTT_SIGN_WIDTH * ROCE_MTT_SIGN_SPLITNUM)

#define ROCE_MTT_BLOCK_SIGN_WIDTH 5
#define ROCE_MTT_BLOCK_SIGN_SPLITNUM 11

/*
 ****************************************************************************
 Prototype	: roce3_calculate_sign_bit
 Description  : roce3_calculate_signature
 Input		: u32 *check_bit
				u32 sign_width
				u32 sign_split
				u32 *sign_bit
 Output	   : None

  1.Date		 : 2017/4/1
	Modification : Created function

****************************************************************************
*/
static void roce3_calculate_sign_bit(u32 *check_bit, u32 sign_width, u32 sign_split, u32 *sign_bit)
{
	u32 i = 0;
	u32 j = 0;

	for (i = 0; i < sign_width; i++) {
		sign_bit[i] = 0;
		for (j = 0; j < sign_split; j++)
			sign_bit[i] = sign_bit[i] ^ check_bit[i + sign_width * j];

		sign_bit[i] = (~sign_bit[i]) & 0x1;
	}
}

/*
 ****************************************************************************
 Prototype	: roce3_calculate_signature
 Description  : roce3_calculate_signature
 Input		: u32 *sign_bit
				u32 sign_width
 Output	   : None

  1.Date		 : 2017/4/1
	Modification : Created function

****************************************************************************
*/
static u32 roce3_calculate_signature(u32 *sign_bit, u32 sign_width)
{
	u32 i = 0;
	u32 signature = 0;

	for (i = 0; i < sign_width; i++)
		signature |= sign_bit[i] << i;

	return (signature & ((1U << sign_width) - 1));
}

/*
 ****************************************************************************
 Prototype	: roce3_gen_sq_rq_gpa_sign
 Description  : Signature	   3bit
				CheckedBits = sq_rq_l0mtt_gpa[32:00]
 Input		: u64 sq_rq_l0mtt_gpa
 Output	   : None

  1.Date		 : 2017/4/1
	Modification : Created function

****************************************************************************
*/
static u32 roce3_gen_sq_rq_gpa_sign(u64 sq_rq_l0mtt_gpa)
{
	u32 i;
	u32 signature = 0;
	u32 sign_bit[ROCE_QP_GPA_SIGN_WIDTH] = {0};
	u32 check_bit[ROCE_QP_GPA_SIGN_CHECKBITS] = {0};

	for (i = 0; i < ROCE_QP_GPA_SIGN_CHECKBITS; i++) {
		if ((sq_rq_l0mtt_gpa >> ROCE_QP_GPA_SIG_LEN) & (1ULL << i))
			check_bit[i] = 1;
	}

	roce3_calculate_sign_bit(check_bit, ROCE_QP_GPA_SIGN_WIDTH,
		ROCE_QP_GPA_SIGN_SPLITNUM, sign_bit);

	signature = roce3_calculate_signature(sign_bit, ROCE_QP_GPA_SIGN_WIDTH);

	return signature;
}

/*
 ****************************************************************************
 Prototype	: roce3_gen_qp_qpcc_sign
 Description  : Signature	   5bit
				CheckedBits = QPn[19:0]
 Input		: u32 qpn
 Output	   : None

  1.Date		 : 2017/4/1
	Modification : Created function

****************************************************************************
*/
static u32 roce3_gen_qp_qpcc_sign(u32 qpn)
{
	u32 i;
	u32 signature = 0;
	u32 sign_bit[ROCE_QP_QPCC_SIGN_WIDTH] = {0};
	u32 check_bit[ROCE_QP_QPCC_SIGN_CHECKBITS] = {0};

	for (i = 0; i < ROCE_QP_QPCC_SIGN_CHECKBITS; i++) {
		if (qpn & (1U << i))
			check_bit[i] = 1;
	}

	roce3_calculate_sign_bit(check_bit, ROCE_QP_QPCC_SIGN_WIDTH,
		ROCE_QP_QPCC_SIGN_SPLITNUM, sign_bit);

	signature = roce3_calculate_signature(sign_bit, ROCE_QP_QPCC_SIGN_WIDTH);

	return signature;
}

/*
 ****************************************************************************
 Prototype	: roce3_gen_qp_rcc_sign
 Description  : Signature	   3bit
				CheckedBits = QPn[14:0]
 Input		: u32 qpn
 Output	   : None

  1.Date		 : 2017/4/1
	Modification : Created function

****************************************************************************
*/
static u32 roce3_gen_qp_rcc_sign(u32 qpn)
{
	u32 i;
	u32 signature = 0;
	u32 sign_bit[ROCE_QP_SUB_SIGN_WIDTH] = {0};
	u32 check_bit[ROCE_QP_SUB_SIGN_CHECKBITS] = {0};

	for (i = 0; i < ROCE_QP_SUB_SIGN_CHECKBITS; i++) {
		if (qpn & (1U << i))
			check_bit[i] = 1;
	}

	roce3_calculate_sign_bit(check_bit, ROCE_QP_SUB_SIGN_WIDTH,
		ROCE_QP_SUB_SIGN_SPLITNUM, sign_bit);

	signature = roce3_calculate_signature(sign_bit, ROCE_QP_SUB_SIGN_WIDTH);

	return signature;
}

/*
 ****************************************************************************
 Prototype	: roce3_gen_qp_sqc_sign
 Description  : Signature	   3bit
				CheckedBits = QPn[14:0]
 Input		: u32 qpn
 Output	   : None

  1.Date		 : 2017/4/1
	Modification : Created function

****************************************************************************
*/
static u32 roce3_gen_qp_sqc_sign(u32 qpn)
{
	u32 i;
	u32 signature = 0;
	u32 sign_bit[ROCE_QP_SUB_SIGN_WIDTH] = {0};
	u32 check_bit[ROCE_QP_SUB_SIGN_CHECKBITS] = {0};

	for (i = 0; i < ROCE_QP_SUB_SIGN_CHECKBITS; i++) {
		if (qpn & (1U << i))
			check_bit[i] = 1;
	}

	roce3_calculate_sign_bit(check_bit, ROCE_QP_SUB_SIGN_WIDTH,
		ROCE_QP_SUB_SIGN_SPLITNUM, sign_bit);

	signature = roce3_calculate_signature(sign_bit, ROCE_QP_SUB_SIGN_WIDTH);

	return signature;
}

/*
 ****************************************************************************
 Prototype	: roce3_gen_qp_sqac_sign
 Description  : Signature	   3bit
				CheckedBits = QPn[14:0]
 Input		: u32 qpn
 Output	   : None

  1.Date		 : 2017/4/1
	Modification : Created function

****************************************************************************
*/
static u32 roce3_gen_qp_sqac_sign(u32 qpn)
{
	u32 i;
	u32 signature = 0;
	u32 sign_bit[ROCE_QP_SUB_SIGN_WIDTH] = {0};
	u32 check_bit[ROCE_QP_SUB_SIGN_CHECKBITS] = {0};

	for (i = 0; i < ROCE_QP_SUB_SIGN_CHECKBITS; i++) {
		if (qpn & (1U << i))
			check_bit[i] = 1;
	}

	roce3_calculate_sign_bit(check_bit, ROCE_QP_SUB_SIGN_WIDTH,
		ROCE_QP_SUB_SIGN_SPLITNUM, sign_bit);

	signature = roce3_calculate_signature(sign_bit, ROCE_QP_SUB_SIGN_WIDTH);

	return signature;
}

/*
 ****************************************************************************
 Prototype	: roce3_gen_qp_rqc_sign
 Description  : Signature	   3bit
				CheckedBits = QPn[14:0]
 Input		: u32 qpn
 Output	   : None

  1.Date		 : 2017/4/1
	Modification : Created function

****************************************************************************
*/
static u32 roce3_gen_qp_rqc_sign(u32 qpn)
{
	u32 i;
	u32 signature = 0;
	u32 sign_bit[ROCE_QP_SUB_SIGN_WIDTH] = {0};
	u32 check_bit[ROCE_QP_SUB_SIGN_CHECKBITS] = {0};

	for (i = 0; i < ROCE_QP_SUB_SIGN_CHECKBITS; i++) {
		if (qpn & (1U << i))
			check_bit[i] = 1;
	}

	roce3_calculate_sign_bit(check_bit, ROCE_QP_SUB_SIGN_WIDTH,
		ROCE_QP_SUB_SIGN_SPLITNUM, sign_bit);

	signature = roce3_calculate_signature(sign_bit, ROCE_QP_SUB_SIGN_WIDTH);

	return signature;
}

/*
 ****************************************************************************
 Prototype	: roce3_gen_qp_rrwc_sign
 Description  : Signature	   3bit
				CheckedBits = QPn[14:0]
 Input		: u32 qpn
 Output	   : None

  1.Date		 : 2017/4/1
	Modification : Created function

****************************************************************************
*/
static u32 roce3_gen_qp_rrwc_sign(u32 qpn)
{
	u32 i;
	u32 signature = 0;
	u32 sign_bit[ROCE_QP_SUB_SIGN_WIDTH] = {0};
	u32 check_bit[ROCE_QP_SUB_SIGN_CHECKBITS] = {0};

	for (i = 0; i < ROCE_QP_SUB_SIGN_CHECKBITS; i++) {
		if (qpn & (1U << i))
			check_bit[i] = 1;
	}

	roce3_calculate_sign_bit(check_bit, ROCE_QP_SUB_SIGN_WIDTH,
		ROCE_QP_SUB_SIGN_SPLITNUM, sign_bit);

	signature = roce3_calculate_signature(sign_bit, ROCE_QP_SUB_SIGN_WIDTH);

	return signature;
}

/*
 ****************************************************************************
 Prototype	: roce3_gen_sq_wqe_sign
 Description  : Signature	   8bit
				CheckedBits = {QPn[19:0], WQECI[19:0], WQE.Header[31:0]}
 Input		: u32 qpn
				u32 wqe_ci
				u32 wqe_header
 Output	   : None

  1.Date		 : 2017/4/1
	Modification : Created function

****************************************************************************
*/
static u32 roce3_gen_sq_wqe_sign(u32 qpn, u32 wqe_ci, u32 wqe_header)
{
	u32 i;
	u32 signature = 0;
	u32 sign_bit[ROCE_SQ_WQE_SIGN_WIDTH] = {0};
	u32 check_bit[ROCE_SQ_WQE_SIGN_CHECKBITS] = {0};

	for (i = 0; i < ROCE_SQ_WQE_SIGN_CHECKBITS_1; i++) {
		if (wqe_header & (1U << i))
			check_bit[i] = 1;
	}

	for (i = ROCE_SQ_WQE_SIGN_CHECKBITS_1; i < ROCE_SQ_WQE_SIGN_CHECKBITS_12; i++) {
		if (wqe_ci & (1U << (i - ROCE_SQ_WQE_SIGN_CHECKBITS_1)))
			check_bit[i] = 1;
	}

	for (i = ROCE_SQ_WQE_SIGN_CHECKBITS_12; i < ROCE_SQ_WQE_SIGN_CHECKBITS_123; i++) {
		if (qpn & (1U << (i - ROCE_SQ_WQE_SIGN_CHECKBITS_12)))
			check_bit[i] = 1;
	}

	roce3_calculate_sign_bit(check_bit, ROCE_SQ_WQE_SIGN_WIDTH,
		ROCE_SQ_WQE_SIGN_SPLITNUM, sign_bit);

	signature = roce3_calculate_signature(sign_bit, ROCE_SQ_WQE_SIGN_WIDTH);

	return signature;
}
#endif

static void roce3_qp_set_path(const struct roce3_device *rdev, struct rdma_ah_attr *ah_attr,
	struct tag_roce_verbs_qpc_attr_path *path_info)
{
	u8 *dmac = ah_attr->roce.dmac;

	path_info->dw7.bs.hoplmt = (u8)ah_attr->grh.hop_limit;
	path_info->dw6.bs.tclass = (u8)(ah_attr->grh.traffic_class | 0x2);
	path_info->dw6.bs.flow_label = ah_attr->grh.flow_label & 0xfffff; /* flow_label: 20bit */
	path_info->dw7.bs.sgid_index = ah_attr->grh.sgid_index & 0x7f;	/* sgid_index: 7bit */

	path_info->dw7.bs.base_sgid_n = (path_info->dw7.bs.sgid_index != ROCE_BASE_GID_IDX);

	memcpy((void *)path_info->dgid, (void *)ah_attr->grh.dgid.raw,
		sizeof(path_info->dgid));

	memcpy((void *)&path_info->dmac_l32, (void *)&dmac[ROCE_RAH_DMAC_L32_START],
		sizeof(path_info->dmac_l32));
	path_info->dmac_l32 = cpu_to_be32(path_info->dmac_l32);
	// shift dmac[0] left by 8 bits
	path_info->dw0.bs.dmac_h16 = (dmac[0] << ROCE_RAH_DMAC_H16_SHIFT) | dmac[1];
	path_info->dw7.bs.sl = (ah_attr->sl & 0x7); /* sl: 3bit */
}

struct roce3_pd *roce3_get_pd(struct roce3_qp *rqp)
{
	if (rqp->qp_type == IB_QPT_XRC_TGT)
		return to_roce3_pd(to_roce3_xrcd(rqp->ibqp.xrcd)->pd);
	else
		return to_roce3_pd(rqp->ibqp.pd);
}

void roce3_get_cqs(struct roce3_qp *rqp, struct roce3_cq **send_cq, struct roce3_cq **recv_cq)
{
	switch (rqp->qp_type) {
	case IB_QPT_XRC_TGT:
		*send_cq = to_roce3_cq(to_roce3_xrcd(rqp->ibqp.xrcd)->cq);
		*recv_cq = *send_cq;
		break;

	case IB_QPT_XRC_INI:
		*send_cq = to_roce3_cq(rqp->ibqp.send_cq);
		*recv_cq = *send_cq;
		break;

	default:
		*send_cq = to_roce3_cq(rqp->ibqp.send_cq);
		*recv_cq = to_roce3_cq(rqp->ibqp.recv_cq);
		break;
	}
}

/*
 ****************************************************************************
 Prototype	: roce3_set_access_flags
 Description  : roce3_set_access_flags
 Input		: struct roce3_qp *rqp
				struct tag_roce_verbs_qp_attr *qp_attr
				struct ib_qp_attr *attr
				int attr_mask
 Output	   : None

  1.Date		 : 2015/5/26
	Modification : Created function
  2.Date		 : 2016/2/26
	Modification : Created function

****************************************************************************
*/
static void roce3_set_access_flags(struct roce3_qp *rqp, struct tag_roce_verbs_qp_attr *qp_attr,
	struct ib_qp_attr *attr, int attr_mask)
{
	u16 dest_rd_atomic = 0;
	u32 access_flags = 0;

	if ((((u32)attr_mask) & IB_QP_MAX_DEST_RD_ATOMIC) != 0)
		dest_rd_atomic = attr->max_dest_rd_atomic;
	else
		dest_rd_atomic = rqp->rsp_depth;

	if ((((u32)attr_mask) & IB_QP_ACCESS_FLAGS) != 0)
		access_flags = (u32)attr->qp_access_flags;
	else
		access_flags = rqp->atomic_rd_en;

	if (dest_rd_atomic == 0)
		access_flags &= IB_ACCESS_REMOTE_WRITE;

	if ((access_flags & IB_ACCESS_REMOTE_READ) != 0)
		qp_attr->com_info.dw0.bs.rre = 1; /* rc_rre: 1bits */

	if ((access_flags & IB_ACCESS_REMOTE_ATOMIC) != 0)
		qp_attr->com_info.dw0.bs.rae = 1; /* rc_rae: 1bits */

	if ((access_flags & IB_ACCESS_REMOTE_WRITE) != 0)
		qp_attr->com_info.dw0.bs.rwe = 1; /* rrw_rwe: 1bits */
}

int roce3_sqp_check(const struct roce3_qp *qp)
{
	if (((qp->qp_type == IB_QPT_GSI) && (qp->qpn == ROCE_QP_SMI_QP_NUM)) ||
		(qp->qpn == ROCE_QP_GSI_QP_NUM))
		return 1;

	return 0;
}

/*
 ****************************************************************************
 Prototype	: store_sqp_attrs
 Description  : save the special
 Input		: struct roce3_sqp *sqp
				const struct ib_qp_attr *attr
				int attr_mask
 Output	   : None

  1.Date		 : 2015/7/24
	Modification : Created function

****************************************************************************
*/
static void store_sqp_attrs(struct roce3_sqp *sqp, const struct ib_qp_attr *attr, int attr_mask)
{
	if (((u32)attr_mask & IB_QP_PKEY_INDEX) != 0)
		sqp->pkey_index = attr->pkey_index;

	if ((((u32)attr_mask) & IB_QP_QKEY) != 0)
		sqp->qkey = attr->qkey;

	if ((((u32)attr_mask) & IB_QP_SQ_PSN) != 0)
		sqp->send_psn = attr->sq_psn;
}

/*
 ****************************************************************************
 Prototype	: qpc_seg_to_be
 Input		: struct roce_qp_context *be_ctx
				struct roce_qp_context *le_ctx
				struct roce3_qp *rqp
 Output	   : None

  1.Date		 : 2015/7/29
	Modification : Created function

****************************************************************************
*/
static void qpc_seg_to_be(struct tag_roce_verbs_qp_attr *be_ctx,
	struct tag_roce_verbs_qp_attr *le_ctx, struct roce3_qp *rqp)
{
	/* DRV Seg */
	memcpy((void *)be_ctx->path_info.dgid, (void *)le_ctx->path_info.dgid,
		sizeof(le_ctx->path_info.dgid));

	/* CHIP Seg */
	be_ctx->chip_seg.dw0.sq_rq_l0mtt_gpa = cpu_to_be64(le_ctx->chip_seg.dw0.sq_rq_l0mtt_gpa);

	be_ctx->chip_seg.dw2.sq_rq_pi_record_gpa_at_hop_num =
		cpu_to_be64(le_ctx->chip_seg.dw2.sq_rq_pi_record_gpa_at_hop_num);
}

/*
 ****************************************************************************
 Prototype	: roce3_qpc_to_be
 Description  : translate big endian
 Input		: struct tag_roce_verbs_qp_attr *qp_attr
				struct roce3_qp *rqp
				u32 *be_ctx
 Output	   : None

  1.Date		 : 2015/7/29
	Modification : Created function

****************************************************************************
*/
void roce3_qpc_to_be(struct tag_roce_verbs_qp_attr *qp_attr, struct roce3_qp *rqp, u32 *be_ctx)
{
	u32 *ctx = NULL;
	u32 *ctx1 = NULL;
	u32 i = 0;
	u32 ctx_size = 0;

	ctx = be_ctx;
	ctx1 = (u32 *)qp_attr;
	ctx_size = sizeof(struct tag_roce_verbs_qp_attr) / sizeof(u32);

	for (i = 0; i < ctx_size; ++i, ++ctx1, ++ctx)
		*ctx = cpu_to_be32(*ctx1);

	qpc_seg_to_be((struct tag_roce_verbs_qp_attr *)((void *)be_ctx), qp_attr, rqp);
}

/*
 ****************************************************************************
 Prototype	: roce3_alloc_opt_rdmarc
 Description  : alloc rdmarc when modify qp
 Input		: struct roce3_qp *rqp
				struct ib_qp_attr *attr
				int attr_mask
 Output	   : None

  1.Date		 : 2016/01/30
	Modification : Created function

****************************************************************************
*/
static int roce3_alloc_opt_rdmarc(struct roce3_qp *rqp,
	const struct ib_qp_attr *attr, int attr_mask)
{
	int ret = 0;
	struct roce3_device *rdev = NULL;
	u32 response_depth = 0;

	rdev = to_roce3_dev(rqp->ibqp.device);
	/*lint -e587*/
	response_depth = (attr->max_dest_rd_atomic == 0) ?
		1 : (u32)ROCE_ROUNDUP_POW_OF_TWO((u32)attr->max_dest_rd_atomic);
	/*lint +e587*/
	if (rqp->rsp_depth != response_depth) {
		if (rqp->rsp_depth > 0)
			roce3_rdma_rdmarc_free(rdev->hwdev, &rqp->rdmarc);

		ret = roce3_rdma_rdmarc_alloc(rdev->hwdev, response_depth, &rqp->rdmarc);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to alloc rdma rdmarc, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return ret;
		}

		rqp->rsp_depth = (u16)response_depth;
	}

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_free_opt_rdmarc
 Description  : free rdmarc when modify qp failed or destroy qp
 Input		: struct roce3_qp *rqp
 Output	   : None

  1.Date		 : 2016/01/30
	Modification : Created function

****************************************************************************
*/
void roce3_free_opt_rdmarc(struct roce3_qp *rqp)
{
	struct roce3_device *rdev = NULL;

	rdev = to_roce3_dev(rqp->ibqp.device);

	if (rqp->rsp_depth > 0)
		roce3_rdma_rdmarc_free(rdev->hwdev, &rqp->rdmarc);

	rqp->rsp_depth = 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_set_opt_rdmarc
 Description  : set opt rdmarc field
 Input		: struct roce3_device *rdev
				struct roce3_qp *rqp
				struct tag_roce_verbs_qp_attr *qp_attr
 Output	   : None

  1.Date		 : 2017/04/27
	Modification : Created function

****************************************************************************
*/
static void roce3_set_opt_rdmarc(struct roce3_device *rdev, struct roce3_qp *rqp,
	struct tag_roce_verbs_qp_attr *qp_attr)
{
	qp_attr->chip_seg.dw10.bs.rc_page_gpa_h =
		(rqp->rdmarc.dma_addr >> 40) & 0xffffff; /* high:24bit, 64-24= 40 */
	qp_attr->chip_seg.rc_page_gpa_l = (u32)(rqp->rdmarc.dma_addr >> 8);	// bit[39:8]
	qp_attr->chip_seg.dw4.bs.rc_size = rqp->rdmarc.order;
	qp_attr->com_info.dw1.bs.rra_max = ((u8)fls(rqp->rsp_depth - 1)) & 0x7; /* rra_max:3bit */
	qp_attr->chip_seg.dw4.bs.rc_max_size = rqp->rdmarc.ext_order - 3;
}

static void roce3_set_opt_mtu(struct tag_roce_verbs_qp_attr *qp_attr, const struct ib_qp_attr *attr)
{
	u32 pmtu = (u32)attr->path_mtu & 0x7;

	qp_attr->com_info.dw3.bs.pmtu = pmtu; /* 1,2,3,4,5 */
	qp_attr->com_info.dw5.bs.mtu_code =
		ROCE_QPC_PMTU_TRANSLATE(pmtu); /* 0,1,3,7,15 */
	if (qp_attr->com_info.dw3.bs.pmtu == IB_MTU_1024)
		qp_attr->com_info.dw3.bs.base_mtu_n = 0;
	else
		qp_attr->com_info.dw3.bs.base_mtu_n = 1;
}

/*
 ****************************************************************************
 Prototype	: roce3_set_opt_sra
 Description  : set opt sra
 Input		:  struct tag_roce_verbs_qp_attr *qp_attr
				struct ib_qp_attr *attr
 Output	   : None

  1.Date		 : 2017/04/27
	Modification : Created function

****************************************************************************
*/
static void roce3_set_opt_sra(struct tag_roce_verbs_qp_attr *qp_attr, struct ib_qp_attr *attr)
{
	u8 initiator_depth;

	/*lint -e587*/
	initiator_depth = (attr->max_rd_atomic == 0) ? 1 :
		(u8)ROCE_ROUNDUP_POW_OF_TWO((u32)attr->max_rd_atomic);
	/*lint +e587*/
	qp_attr->com_info.dw1.bs.sra_max =
		((u32)ROCE_FLS(initiator_depth - 1)) & 0x7; /* sra_max:3bit */
}

u8 roce3_get_db_cos_from_vlan_pri(struct roce3_device *rdev, u8 vlan_pri)
{
	u8 db_cos;
	int ret;

	ret = hinic3_get_cos_by_pri(rdev->hwdev, vlan_pri, &db_cos);
	if (ret != 0) {
		pr_info("%s, ret:%d vlan_pri:%u\n", __func__, ret, vlan_pri);
		db_cos = 0;
	}

	return db_cos;
}

static void roce3_set_opt_attr_av(struct roce3_qp *rqp, struct roce3_device *rdev,
	struct ib_qp_attr *attr, struct tag_roce_verbs_qp_attr *qp_attr, u32 *optpar)
{
	u8 cos;
	struct roce3_get_cos_inbuf inbuf = { 0 };

	roce3_qp_set_path(rdev, &attr->ah_attr, &qp_attr->path_info);
	qp_attr->com_info.dw3.bs.ext_mtu = rqp->ext_mtu & 0x1;
	qp_attr->com_info.dw3.bs.ext_md = rqp->ext_mtu_mode & 0x1;
	qp_attr->com_info.dw2.bs.vroce_en = (u32)rdev->is_vroce;
	*optpar |= ROCE_QP_OPTPAR_PRIMARY_ADDR_PATH;

	inbuf.sl = attr->ah_attr.sl;
	inbuf.sgid_index = attr->ah_attr.grh.sgid_index;
	inbuf.port_num = attr->ah_attr.port_num;
	inbuf.traffic_class = attr->ah_attr.grh.traffic_class;
	(void)roce3_get_dcb_cfg_cos(rdev, &inbuf, &cos);
	if (rdev->is_vroce)
		cos = rqp->sl;

	qp_attr->com_info.dw5.bs.cos = cos & 0x7;

	rqp->db_sgid_index = attr->ah_attr.grh.sgid_index & 0x7f;
}

static void roce3_set_opt_field_attr(struct roce3_qp *rqp, const struct ib_qp_attr *attr,
	int attr_mask, struct tag_roce_verbs_qp_attr *qp_attr, u32 *optpar)
{
	/* RTR2RTS/SQD2SQD RETRY_CNT */
	if ((((u32)attr_mask) & IB_QP_RETRY_CNT) != 0) {
		qp_attr->com_info.dw1.bs.to_retry_limit =
			attr->retry_cnt & 0x7; /* to_retry_limit:3 */
		*optpar |= ROCE_QP_OPTPAR_RETRY_COUNT;
	}

	/* RTR2RTS/SQD2SQD RNR_RETRY */
	if ((((u32)attr_mask) & IB_QP_RNR_RETRY) != 0) {
		qp_attr->com_info.dw1.bs.rnr_retry_limit =
			attr->rnr_retry & 0x7; /* rnr_retry_limit:3bits */
		*optpar |= ROCE_QP_OPTPAR_RNR_RETRY;
	}

	/* INIT2RTR/SQD2SQD/RTR2RTS/RTS2RTS MIN_RNR_TIMER */
	if ((((u32)attr_mask) & IB_QP_MIN_RNR_TIMER) != 0) {
		qp_attr->com_info.dw2.bs.min_rnr_nak =
			attr->min_rnr_timer & 0x1f; /* min_rnr_nak:5bits */
		*optpar |= ROCE_QP_OPTPAR_RNR_TIMEOUT;
	}

	if ((((u32)attr_mask) & IB_QP_SQ_PSN) != 0) {
		qp_attr->com_info.dw8.bs.next_send_psn =
			attr->sq_psn & 0xffffff; /* next_rcv_psn:24bit */
	}

	if ((((u32)attr_mask) & IB_QP_RQ_PSN) != 0) {
		qp_attr->com_info.dw9.bs.next_rcv_psn =
			attr->rq_psn & 0xffffff; /* next_rcv_psn:24bit */
	}

	if ((((u32)attr_mask) & IB_QP_DEST_QPN) != 0) {
		qp_attr->com_info.dw0.bs.dest_qp =
			attr->dest_qp_num & 0xffffff; /* dest_qp:24bit */
	}

#ifdef ROCE_VBS_EN
	if ((((u32)attr_mask) & ROCE_QP_VBS_FLAG) != 0) { /*  IBV_QP_VBS_OSD_FLAG */
		roce3_vbs_set_attr(rqp, qp_attr, attr_mask);
	}
#endif
}

static s32 roce3_set_db_path_mtu(const struct ib_qp_attr *attr,
	struct roce3_qp *rqp, struct roce3_device *rdev)
{
	switch (attr->path_mtu) {
	case IB_MTU_256:
	case IB_MTU_512:
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s:Only support mtu larger than 1K.func_id(%d) mtu:%u\n",
			__func__, rdev->glb_func_id, attr->path_mtu);
		return -EINVAL;
	case IB_MTU_1024:
		rqp->db_path_mtu = BIT_LENGTH_IB_MTU_1024;
		break;
	case IB_MTU_2048:
		rqp->db_path_mtu = BIT_LENGTH_IB_MTU_2048;
		break;
	case IB_MTU_4096:
		rqp->db_path_mtu = BIT_LENGTH_IB_MTU_4096;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int roce3_set_opt_field(struct roce3_qp *rqp, struct ib_qp_attr *attr, int attr_mask,
	struct tag_roce_verbs_qp_attr *qp_attr, u32 *optpar)
{
	struct roce3_device *rdev = to_roce3_dev(rqp->ibqp.device);
	int ret = 0;

	if ((((u32)attr_mask) & IB_QP_QKEY) != 0) {
		qp_attr->com_info.q_key = attr->qkey;
		*optpar |= ROCE_QP_OPTPAR_Q_KEY;
	}

	if ((((u32)attr_mask) & IB_QP_AV) != 0) {
		if (rdev->is_vroce) {
			if (rqp->qp_type == (u32)IB_QPT_RC) {
				attr->ah_attr.sl = rdev->group_rc_cos;
				rqp->sl = rdev->group_rc_cos;
			} else if (rqp->qp_type == (u32)IB_QPT_UD) {
				attr->ah_attr.sl = rdev->group_ud_cos;
				rqp->sl = rdev->group_ud_cos;
			} else {
				attr->ah_attr.sl = rdev->group_xrc_cos;
				rqp->sl = rdev->group_xrc_cos;
			}
		}
		roce3_set_opt_attr_av(rqp, rdev, attr, qp_attr, optpar);
	}

	if ((((u32)attr_mask) & IB_QP_PORT) != 0) {
		qp_attr->com_info.dw5.bs.port = attr->port_num & 0x7; /* port: 3bits */
		*optpar |= ROCE_QP_OPTPAR_SCHED_QUEUE;
	}

	if ((((u32)attr_mask) & IB_QP_MAX_DEST_RD_ATOMIC) != 0) {
		roce3_set_opt_rdmarc(rdev, rqp, qp_attr);
		*optpar |= ROCE_QP_OPTPAR_RRA_MAX;
	}

	/* RTR2RTS/SQD2SQD SRA_MAX */
	if ((((u32)attr_mask) & IB_QP_MAX_QP_RD_ATOMIC) != 0) {
		roce3_set_opt_sra(qp_attr, attr);
		*optpar |= ROCE_QP_OPTPAR_SRA_MAX;
	}

	/* RWE/RRE/RAE,RST2INIT */
	if ((((u32)attr_mask) & (IB_QP_ACCESS_FLAGS | IB_QP_MAX_DEST_RD_ATOMIC)) != 0) {
		roce3_set_access_flags(rqp, qp_attr, attr, attr_mask);
		*optpar |= ROCE_QP_OPTPAR_RWE | ROCE_QP_OPTPAR_RRE | ROCE_QP_OPTPAR_RAE;
	}

	/* RTR2RTS/SQD2SQD ACK TIMEOUT */
	if ((((u32)attr_mask) & IB_QP_TIMEOUT) != 0) {
		qp_attr->com_info.dw2.bs.ack_to = attr->timeout & 0x1f; /* ack_to:5bits */
		*optpar |= ROCE_QP_OPTPAR_ACK_TIMEOUT;
	}

	if ((((u32)attr_mask) & IB_QP_PATH_MTU) != 0) {
		ret = roce3_set_db_path_mtu(attr, rqp, rdev);
		if (ret != 0)
			return ret;

		roce3_set_opt_mtu(qp_attr, attr);
	}

	roce3_set_opt_field_attr(rqp, attr, attr_mask, qp_attr, optpar);
	return ret;
}

static void roce3_set_qp_srq_attr(struct roce3_qp *rqp, struct tag_roce_verbs_qp_attr *qp_attr,
	struct roce3_pd *pd, const struct roce3_cq *recv_cq)
{
	struct roce3_srq *rsrq = to_roce3_srq(rqp->ibqp.srq);
	struct roce_srq_context temp;

	if (rsrq->container_flag != 0) {
		struct roce_srq_context *srqc = (struct roce_srq_context *)
			((void *)rsrq->cqm_srq->q_ctx_vaddr);

		temp.dw0.value = be32_to_cpu(srqc->dw0.value);
		qp_attr->chip_seg.dw12.bs.srq_pd = temp.dw0.bs.pdn & 0x3ffff; /* srq_pd:18bits */
		qp_attr->chip_seg.dw12.bs.srq_wqebb_size = temp.dw0.bs.wqebb_size;
		qp_attr->chip_seg.dw12.bs.srq_page_size = temp.dw0.bs.page_size;
		qp_attr->chip_seg.dw12.bs.srq_size = temp.dw0.bs.size;

		temp.dw1.value = be32_to_cpu(srqc->dw1.value);
		qp_attr->com_info.dw5.bs.so_ro = temp.dw1.bs_c.so_ro;
		qp_attr->com_info.dw5.bs.dma_attr_idx = temp.dw1.bs_c.dma_attr_idx;

		qp_attr->chip_seg.dw9.bs.container_sz =
			MAX_SUPPORT_CONTAINER_MODE - rsrq->container_mode;
		qp_attr->chip_seg.dw9.bs.container_en = 1;

		qp_attr->com_info.dw3.bs.srq_container = 1;

		if (rsrq->rqe_cnt_th > 0) {
			qp_attr->chip_seg.dw9.bs.srq_warth_flag = 1;
			qp_attr->chip_seg.dw8.bs.srq_rqecnt_th =
				rsrq->rqe_cnt_th & 0xf; /* srq_rqecnt_th:4bits */
		}

		qp_attr->chip_seg.dw7.bs.srqn = rsrq->srqn & 0x3ffff; /* srqn:18bits */
	} else {
		qp_attr->chip_seg.dw7.bs.srqn = rsrq->srqn & 0x3ffff; /* srqn:18bits */
	}

	qp_attr->com_info.dw2.bs.srq_en = 1;
	qp_attr->chip_seg.dw12.bs.srq_rkey_en = 1;
	qp_attr->com_info.dw0.bs.rkey_en = 1;
	qp_attr->chip_seg.dw13.bs.srq_cqn = recv_cq->cqn & 0xfffff; /* rq_cqn:20bits */
	qp_attr->chip_seg.dw9.bs.srq_mtt_prefetch_maxlen1 = 1;
}

static void roce3_set_qp_rst2init_attr(struct roce3_qp *rqp,
	struct tag_roce_verbs_qp_attr *qp_attr, struct roce3_pd *pd, struct roce3_cq *recv_cq)
{
	qp_attr->chip_seg.dw4.bs.rq_base_ci =
		(u32)(ROCE_ILOG2(rqp->rq.offset >> rqp->rq.wqe_shift));
	qp_attr->chip_seg.dw19.bs.qp_pd = pd->pdn & 0x3ffff; /* pd:18bits */
	qp_attr->com_info.dw3.bs.dsgl_en = rqp->double_sgl_mode & 0x1;

	if (rqp->ibqp.srq) {
		roce3_set_qp_srq_attr(rqp, qp_attr, pd, recv_cq);
	} else {
		qp_attr->chip_seg.dw15.bs.rq_size = (rqp->rq.wqebb_cnt > 0) ?
			(((u32)ROCE_ILOG2(rqp->rq.wqebb_cnt)) & 0x1f) : 0;
		qp_attr->chip_seg.dw15.bs.rq_page_size =
			((u32)((u32)rqp->buf.page_shift - PAGE_SHIFT_4K)) & ROCE_SQ_PAGE_SIZE_MASK;
		qp_attr->chip_seg.dw15.bs.rq_pd = pd->pdn & 0x3ffff; /* pd:18bits */
		qp_attr->chip_seg.dw8.bs.rq_wqebb_size =
			(u32)(rqp->rq.wqe_shift - BYTES_TO_16B_SHIFT) & 0x7;
		qp_attr->com_info.dw7.bs.rq_cqn = recv_cq->cqn & 0xfffff; /* rq_cqn:20bits */
		qp_attr->com_info.dw7.bs.rq_cqn_lb = g_rq_cqn_lb;
		qp_attr->chip_seg.dw15.bs.rq_rkey_en = 1;

		qp_attr->chip_seg.dw8.bs.rq_pi_on_chip = 0;
		qp_attr->chip_seg.dw7.bs.rq_wqecnt_lth = ROCE_RQ_WQECNT_LTH;
		qp_attr->chip_seg.dw7.bs.rq_wqecnt_rctl_en = 0;
		qp_attr->chip_seg.dw7.bs.rq_wqe_cache_thd_sel = 0;
		qp_attr->chip_seg.dw7.bs.rq_wqecnt_rctl = 0;
		qp_attr->chip_seg.dw9.bs.rq_mtt_prefetch_maxlen0 = ROCE_RQ_MTT_PREFETCH_MAXLEN0;
		qp_attr->chip_seg.dw9.bs.rq_mtt_prefetch_maxlen1 = 0;
		qp_attr->chip_seg.dw9.bs.rq_mtt_prefetch_maxwqe = ROCE_RQ_MTT_PREFETCH_MAXWQE;
		qp_attr->chip_seg.dw7.bs.rq_wqe_prefetch_minnum = 0;
		qp_attr->chip_seg.dw7.bs.rq_wqe_prefetch_maxnum = ROCE_RQ_WQE_PREFETCH_MAXNUM;
	}
}

static void roce3_qp_rst2init_set_qpcc(struct tag_roce_verbs_qp_attr *qp_attr,
	const struct roce3_qp *rqp, const struct roce3_device *rdev)
{
	qp_attr->chip_seg.dw0.sq_rq_l0mtt_gpa = rqp->mtt.mtt_paddr;
	qp_attr->chip_seg.dw2.sq_rq_pi_record_gpa_at_hop_num =
		rqp->db.dma & (~0x3ULL);	/* bits:63-2 */
	qp_attr->chip_seg.dw2.sq_rq_pi_record_gpa_at_hop_num |=
		rqp->mtt.mtt_layers & 0x3; /* bits:1-0 */
	if (rqp->qp_type == IB_QPT_XRC_TGT) {
		qp_attr->chip_seg.dw2.sq_rq_pi_record_gpa_at_hop_num =
			rqp->qpc_info->paddr & (~0x3ULL); /* bits:63-2 */
	}

	qp_attr->chip_seg.dw4.bs.sq_rq_mtt_page_size = rqp->mtt.mtt_page_shift - PAGE_SHIFT_4K;
	/* rc_entry_size:2bits */
	qp_attr->chip_seg.dw10.bs.rc_entry_size =
		((u32)ROCE_ILOG2(rdev->rdma_cap.dev_rdma_cap.roce_own_cap.rdmarc_entry_sz >>
		BYTES_TO_16B_SHIFT) & 0x3);
	qp_attr->chip_seg.dw14.bs.qp_rkey_en = 1;
	qp_attr->chip_seg.dw10.bs.rc_entry_prefetch_maxnum = 0;
}

static void roce3_qp_rst2init_set_sqc_sqac(struct tag_roce_verbs_qp_attr *qp_attr,
	const struct roce3_qp *rqp, const struct roce3_pd *pd, const struct roce3_cq *send_cq)
{
#ifdef ROCE_COMPUTE
	u8 sq_pi_on_chip = (u8)((rqp->qpn <= ROCE_MAX_PI_ON_CHIP_QPN) &&
		(rqp->qp_type != IB_QPT_UD));

	qp_attr->chip_seg.dw5.bs.sq_pi_on_chip = sq_pi_on_chip;
#else
	qp_attr->chip_seg.dw5.bs.sq_pi_on_chip = 0;
#endif
	qp_attr->chip_seg.dw16.bs.sq_wqebb_size =
		((u32)(rqp->sq.wqe_shift - ROCE_SQ_WQEBB_SIZE_SHIFT)) & ROCE_SQ_WQEBB_SIZE_MASK;
	qp_attr->chip_seg.dw16.bs.sq_pd = ((u32)pd->pdn) & 0x3ffff; /* pd:18bits */
	qp_attr->chip_seg.dw16.bs.sq_page_size =
		((u32)(rqp->buf.page_shift - PAGE_SHIFT_4K)) & ROCE_SQ_PAGE_SIZE_MASK;
	qp_attr->chip_seg.dw5.bs.sq_inline_en = rqp->max_inline_data > 0 ? 1 : 0;

	qp_attr->chip_seg.dw16.bs.sq_rkey_en = 1;

	qp_attr->chip_seg.dw5.bs.sq_wqecnt_lth = ROCE_SQ_WQECNT_LTH;
	qp_attr->chip_seg.dw5.bs.sq_wqecnt_rctl_en = 0;
	qp_attr->chip_seg.dw5.bs.sq_wqecnt_rctl = 0;
	qp_attr->chip_seg.dw5.bs.sq_wqe_prefetch_minnum = ROCE_SQ_PREFETCH_MINNUM;
	qp_attr->chip_seg.dw5.bs.sq_wqe_prefetch_maxnum = ROCE_SQ_PREFETCH_MAXNUM;
	qp_attr->chip_seg.dw5.bs.sq_wqe_cache_thd_sel = 0;
	qp_attr->chip_seg.dw6.bs.sq_wqe_prefetch_mode = 0;
	qp_attr->chip_seg.dw6.bs.sq_mtt_prefetch_maxlen = 0;

	if (rqp->sq.wqebb_cnt != 0) {
		qp_attr->chip_seg.dw5.bs.sq_size =
			(u32)(ROCE_ILOG2((u32)rqp->sq.wqebb_cnt)) & ROCE_SQ_SIZE_MASK;
	}

	qp_attr->com_info.dw7.bs.sq_cqn_lb = g_sq_cqn_lb;
	qp_attr->chip_seg.dw17.bs.sqa_cqn = send_cq->cqn & ROCE_SQ_CQN_MASK;

	qp_attr->chip_seg.dw5.bs.sqa_wqe_prefetch_minnum = ROCE_SQ_PREFETCH_MINNUM;
	qp_attr->chip_seg.dw5.bs.sqa_wqe_prefetch_maxnum = ROCE_WQE_PREFETCH_MAXNUM;
	qp_attr->chip_seg.dw6.bs.sqa_mtt_prefetch_maxlen = 0;
	qp_attr->chip_seg.dw5.bs.sqa_wqe_cache_thd_sel = 0;
}

static void roce3_qp_rst2init_set_drv(struct tag_roce_verbs_qp_attr *qp_attr,
	struct roce3_qp *rqp, struct roce3_device *rdev)
{
	u16 host_oqid = 0;
	u8 host_id = 0;

	host_id = hinic3_host_id(rdev->hwdev);
	if (host_id == ROCE_SPU_HOST_ID) {
		host_id = ROCE_SPU_OQID_HOST_ID;
		host_oqid = (u16)ROCE_GET_SPU_HOST_OQID(host_id, rdev->glb_func_id, rqp->qpn);
	} else {
		host_oqid = (u16)ROCE_GET_HOST_OQID(host_id, rqp->qpn);
	}

	qp_attr->com_info.dw0.bs.service_type =
		(u32)to_roce3_qp_type((enum ib_qp_type)rqp->qp_type) & 0x7;
	if (rdev->is_vroce) {
		if (qp_attr->com_info.dw0.bs.service_type == ROCE_QP_ST_RC) {
			qp_attr->path_info.dw7.bs.sl = rdev->group_rc_cos;
			rqp->sl = rdev->group_rc_cos;
		} else if (qp_attr->com_info.dw0.bs.service_type == ROCE_QP_ST_UD) {
			qp_attr->path_info.dw7.bs.sl = rdev->group_ud_cos;
			rqp->sl = rdev->group_ud_cos;
		} else {
			qp_attr->path_info.dw7.bs.sl = rdev->group_xrc_cos;
			rqp->sl = rdev->group_xrc_cos;
		}
	}
	qp_attr->com_info.dw3.bs.dif_en = (u32)rqp->signature_en;
	qp_attr->com_info.dw2.bs.vroce_en = (u32)rdev->is_vroce;

	if (!rqp->ibqp.uobject)
		qp_attr->com_info.dw0.bs.fre = 1;

	qp_attr->com_info.dw3.bs.xrc_vld = (u32)(rqp->qp_type == IB_QPT_XRC_INI);
	qp_attr->com_info.dw1.bs.local_qp = rqp->qpn & 0xffffff; /* local_qp:24bits */
	qp_attr->com_info.dw5.bs.ep = rdev->hw_info.ep_id;
	if (rdev->is_vroce)
		qp_attr->com_info.dw2.bs.host_oqid = (host_oqid & 0xfffc) | ROCE_IPSUTX_CHANNEL_15;
	else
		qp_attr->com_info.dw2.bs.host_oqid = host_oqid & 0xffff; /* host_oqid:16bits */

	qp_attr->chip_seg.dw4.bs.dsgl = rqp->double_sgl_mode & 0x1;
	qp_attr->path_info.dw7.bs.udp_src_port = (qp_attr->com_info.dw1.bs.local_qp & 0xff);
}

static void roce3_qp_rst2init_set_common(struct tag_roce_verbs_qp_attr *qp_attr,
	const struct roce3_pd *pd)
{
	qp_attr->com_info.dw12.bs.ccf_app_id = ROCE_CC_DISABLE; // STUB
	qp_attr->chip_seg.dw18.bs.ud_pd = pd->pdn & 0x3ffff;	/* pd:18bits */
}

static void roce3_qp_rst2init_set_dcqcn(struct tag_roce_verbs_qp_attr *qp_attr)
{
/* ecn ver
 * b300 nic do not support the func
 * context->sw_seg.ucode_seg.common.dw1.bs.ecn_ver = rdev->ecn_ctx.ecn_ver & 0xf;
 */
}

static void roce3_qp_rst2init_set_fake_vf(const struct roce3_device *rdev,
	const struct roce3_pd *pd, struct tag_roce_verbs_qp_attr *qp_attr)
{
	u32 fake_vf_id = 0;
	struct roce3_ucontext *roce3_uctx = NULL;
	u32 db_offset;

	fake_vf_id = ((u32)rdev->glb_func_id) << rdev->cfg_info.pf_start_bit;
	if (rdev->cfg_info.pf_end_bit < ROCE_VLD_PF_NUM_10)
		fake_vf_id |= 0x1C00; /* 12 11 10 bit 1 */
	else if (rdev->cfg_info.pf_end_bit < ROCE_VLD_PF_NUM_11)
		fake_vf_id |= 0x1800; /* 12 11  bit 1 */
	else if (rdev->cfg_info.pf_end_bit < ROCE_VLD_PF_NUM_12)
		fake_vf_id |= 0x1000; /* 12   bit 1 */

	if (pd->ibpd.uobject) {
		roce3_uctx = to_roce3_ucontext(pd->ibpd.uobject->context);
		db_offset = (u32)((roce3_uctx->db_dma_addr >> (12UL + rdev->cfg_info.page_bit)) &
			((1UL << rdev->cfg_info.pf_start_bit) - 1));
		qp_attr->com_info.dw11.bs.vf_id = fake_vf_id | db_offset;
		pr_info("[ROCE] func_id:%u The fake_id:%u ,start:%u end:%u  page_bit:%u roce3_uctx->db_dma_addr:%llu\n",
			rdev->glb_func_id, qp_attr->com_info.dw11.bs.vf_id,
			rdev->cfg_info.pf_start_bit, rdev->cfg_info.pf_end_bit,
			rdev->cfg_info.page_bit, roce3_uctx->db_dma_addr);
		qp_attr->com_info.dw11.bs.fake = 1;
	} else {
		pr_info("[ROCE] kernel not support fake_vf currently. func:%u\n",
			rdev->glb_func_id);
	}
}

static void roce3_qp_rst2init_set_xrc_attr(const struct roce3_qp *rqp,
	const struct ib_qp_attr *attr, struct tag_roce_verbs_qp_attr *qp_attr,
	const struct roce3_device *rdev, const struct roce3_cq *recv_cq)
{
	qp_attr->com_info.dw2.bs.xrc_srq_en = 1;

	if ((((u32)attr->qp_access_flags & XRC_CONTAINER_FLAG) != 0) ||
		(rdev->cfg_info.srq_container_en != 0)) {
		qp_attr->chip_seg.dw9.bs.container_en = 1;
		qp_attr->com_info.dw3.bs.srq_container = 1;
		qp_attr->chip_seg.dw8.bs.xrcd = rqp->xrcdn & 0xffff; /* xrcd:16bits */
		qp_attr->com_info.dw2.bs.srq_en = 1;
		qp_attr->chip_seg.dw8.bs.srq_rqecnt_th = 1;
		qp_attr->com_info.dw3.bs.xrc_vld = 1;
		qp_attr->chip_seg.dw13.bs.srq_state = ROCE_SRQ_INIT_STATE;
	} else {
		qp_attr->chip_seg.dw12.bs.srq_rkey_en = 1;
		qp_attr->com_info.dw2.bs.srq_en = 1;
		qp_attr->chip_seg.dw8.bs.xrcd = rqp->xrcdn & 0xffff; /* xrcd:16bits */
		qp_attr->chip_seg.dw9.bs.srq_mtt_prefetch_maxlen1 = 1;
		qp_attr->com_info.dw3.bs.xrc_vld = 1;
		qp_attr->chip_seg.dw14.bs.srq_xrcd = rqp->xrcdn & 0xffff; /* xrcd:16bits */
	}
	if (recv_cq != NULL)
		qp_attr->chip_seg.dw13.bs.srq_cqn = recv_cq->cqn & 0xfffff; /* rq_cqn:20bits */
}

/*
 ****************************************************************************
 Prototype	: roce3_qp_rst2init
 Description  : parameter set when QP is from RESET to INIT
 Input		: struct roce3_qp *rqp
				const struct ib_qp_attr *attr
				struct tag_roce_verbs_qp_attr *qp_attr
 Output	   : None

  1.Date		 : 2015/8/6
	Modification : Created function

****************************************************************************
*/
void roce3_qp_rst2init(struct roce3_qp *rqp, const struct ib_qp_attr *attr,
	struct tag_roce_verbs_qp_attr *qp_attr)
{
	struct roce3_pd *pd = NULL;
	struct roce3_cq *send_cq = NULL;
	struct roce3_cq *recv_cq = NULL;
	struct roce3_device *rdev = NULL;

	rdev = to_roce3_dev(rqp->ibqp.device);
	pd = roce3_get_pd(rqp);
	roce3_get_cqs(rqp, &send_cq, &recv_cq);

	/* CHIP_SEG: QPCC */
	roce3_qp_rst2init_set_qpcc(qp_attr, rqp, rdev);

	/* CHIP_SEG: SQC & SQAC */
	roce3_qp_rst2init_set_sqc_sqac(qp_attr, rqp, pd, send_cq);

	/* RRWC */
	qp_attr->chip_seg.dw4.bs.rrw_mtt_prefetch_maxlen = 0;

	/* RCC */
	qp_attr->chip_seg.dw10.bs.rc_mtt_prefetch_maxlen = ROCE_QP_MAX_PFETCH_MTT_LAYER;

	/* TIMER_SEG */
	qp_attr->com_info.dw3.bs.tss_timer_num = ROCE_QP_MAX_TIMER_NUM;

	/* DRV_SEG */
	roce3_qp_rst2init_set_drv(qp_attr, rqp, rdev);

	/* UCODE COM_SEG */
	roce3_qp_rst2init_set_common(qp_attr, pd);

	/* EXT DCQCN SEG */
	roce3_qp_rst2init_set_dcqcn(qp_attr);

	if (rdev->cfg_info.fake_en != 0)
		roce3_qp_rst2init_set_fake_vf(rdev, pd, qp_attr);

	if (rqp->qp_type == IB_QPT_XRC_TGT)
		roce3_qp_rst2init_set_xrc_attr(rqp, attr, qp_attr, rdev, recv_cq);
	else
		roce3_set_qp_rst2init_attr(rqp, qp_attr, pd, recv_cq);

#ifdef ROCE_BONDING_EN
	roce3_bond_rr_set_flow(rdev, rqp, qp_attr);
#endif
}

/*
 ****************************************************************************
 Prototype	: roce3_qp_init2rtr
 Description  : init2rtr attributes modify
 Input		: struct roce3_qp *rqp
				const struct ib_qp_attr *attr
				struct tag_roce_verbs_qp_attr *qp_attr
 Output	   : None

  1.Date		 : 2015/8/1
	Modification : Created function

****************************************************************************
*/
static void roce3_qp_init2rtr(struct roce3_qp *rqp, const struct ib_qp_attr *attr,
	struct tag_roce_verbs_qp_attr *qp_attr)
{
	if (rqp->ibqp.srq || (rqp->qp_type == IB_QPT_XRC_TGT) ||
		(rqp->qp_type == IB_QPT_XRC_INI) || (rqp->qp_type == IB_QPT_UD) ||
		(rqp->qp_type == IB_QPT_UC) || (rqp->qp_type == IB_QPT_GSI)) {
		qp_attr->com_info.dw3.bs.invalid_credit = 1;
	}

	if ((rqp->qp_type == IB_QPT_GSI) || (rqp->qp_type == IB_QPT_UD)) {
		qp_attr->com_info.dw3.bs.pmtu = IB_MTU_4096 & 0x7; /* for UD, mtu = 4096 */
		qp_attr->com_info.dw5.bs.mtu_code = ROCE_MTU_CODE_4K;
	}

	qp_attr->com_info.dw2.bs.ack_to = 0xf; /* ack_to:5bits */
	qp_attr->com_info.dw0.bs.service_type =
		(u32)to_roce3_qp_type((enum ib_qp_type)rqp->qp_type) & 0x7; /* service_type: 3bit */
}

/*
 ****************************************************************************
 Prototype	: roce3_qp_rtr2rts
 Description  : roce3_qp_rtr2rts
 Input		: struct roce3_qp *rqp
				const struct ib_qp_attr *attr
				struct tag_roce_verbs_qp_attr *qp_attr
 Output	   : None

  1.Date		 : 2015/8/2
	Modification : Created function

****************************************************************************
*/
static void roce3_qp_rtr2rts(struct roce3_qp *rqp, const struct ib_qp_attr *attr,
	struct tag_roce_verbs_qp_attr *qp_attr)
{
}

static void roce3_qp_2err(struct roce3_qp *rqp, const struct ib_qp_attr *attr,
	struct tag_roce_verbs_qp_attr *qp_attr)
{
}

/*
 ****************************************************************************
 Prototype	: roce3_set_abs_field
 Description  : set abs field to qpc
 Input		: struct roce3_qp *rqp
				struct ib_qp_attr *attr
				struct tag_roce_verbs_qp_attr *qp_attr
				enum ib_qp_state cur_state
				enum ib_qp_state new_state
 Output	   : None

  1.Date		 : 2016/01/30
	Modification : Created function

****************************************************************************
*/
static void roce3_set_abs_field(struct roce3_qp *rqp, struct ib_qp_attr *attr, int attr_mask,
	struct tag_roce_verbs_qp_attr *qp_attr)
{
	enum ib_qp_state cur_state, new_state;

	cur_state = (enum ib_qp_state)(((((u32)attr_mask) & IB_QP_CUR_STATE) != 0) ?
		attr->cur_qp_state : rqp->qp_state);
	new_state = ((((u32)attr_mask) & IB_QP_STATE) != 0) ? attr->qp_state : cur_state;
	if ((cur_state == IB_QPS_RESET) && (new_state == IB_QPS_INIT))
		roce3_qp_rst2init(rqp, attr, qp_attr);

	if ((cur_state == IB_QPS_INIT) && (new_state == IB_QPS_RTR))
		roce3_qp_init2rtr(rqp, attr, qp_attr);

	if ((cur_state == IB_QPS_RTR) && (new_state == IB_QPS_RTS))
		roce3_qp_rtr2rts(rqp, attr, qp_attr);

	if (new_state == IB_QPS_ERR)
		roce3_qp_2err(rqp, attr, qp_attr);
}

/*
 ****************************************************************************
 Prototype	: roce3_record_opt_field
 Description  : set opt field to roce3_qp after send cmd modify_qp
 Input		: struct roce3_qp *rqp
				struct ib_qp_attr *attr
				int attr_mask
 Output	   : None

  1.Date		 : 2016/01/30
	Modification : Created function

****************************************************************************
*/
static void roce3_record_opt_field(struct roce3_qp *rqp, struct ib_qp_attr *attr, int attr_mask)
{
	enum ib_qp_state cur_state, new_state;

	cur_state = (enum ib_qp_state)(((((u32)attr_mask) & IB_QP_CUR_STATE) != 0) ?
		attr->cur_qp_state : rqp->qp_state);
	new_state = ((((u32)attr_mask) & IB_QP_STATE) != 0) ? attr->qp_state : cur_state;
	rqp->qp_state = new_state;

	if ((((u32)attr_mask) & IB_QP_AV) != 0)
		rqp->sl = attr->ah_attr.sl & 0x7;

	if ((((u32)attr_mask) & IB_QP_ACCESS_FLAGS) != 0)
		rqp->atomic_rd_en = (u8)attr->qp_access_flags;

	if ((((u32)attr_mask) & IB_QP_PORT) != 0)
		rqp->port = attr->port_num;

	if (roce3_sqp_check(rqp) != 0)
		store_sqp_attrs(to_roce3_sqp(rqp), attr, attr_mask);
}

/*
 ****************************************************************************
 Prototype	: roce3_qp_modify_2rst_cmd
 Description  : cache out qpc mtt
 Input		: struct roce3_device *rdev
				struct roce3_qp *rqp
 Output	   : None

  1.Date		 : 2016/6/17
	Modification : Created function

  2.Date		 : 2017/04/26
	Modification : Modify function

****************************************************************************
*/
int roce3_qp_modify_2rst_cmd(struct roce3_device *rdev, u32 qpn)
{
	int ret = 0;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_roce_uni_cmd_qp_modify2rst *qp_moidfy2rst_inbuf = NULL;
	struct timespec64 tv_start;

	ktime_get_ts64(&tv_start);
	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_uni_cmd_qp_modify2rst), NULL, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	qp_moidfy2rst_inbuf = (struct tag_roce_uni_cmd_qp_modify2rst *)cqm_cmd_inbuf->buf;
	qp_moidfy2rst_inbuf->com.index = cpu_to_be32(qpn);
	if (!roce3_is_roceaa(rdev->cfg_info.scence_id)) {
		qp_moidfy2rst_inbuf->com.dw0.bs.cmd_bitmask =
			cpu_to_be16(VERBS_CMD_TYPE_QP_BITMASK); //lint !e778
	} else {
		qp_moidfy2rst_inbuf->com.dw0.bs.cmd_bitmask =
			cpu_to_be16(VERBS_CMD_TYPE_NOFAA_BITMASK); //lint !e778
	}

	ret = roce3_send_qp_lb_cmd(qpn, rdev, ROCE_CMD_2RST_QP,
		cqm_cmd_inbuf, NULL, ROCE_CMD_TIME_CLASS_A);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to send 2RST_QP command, qpn(0x%x), func_id(%d), ret(0x%x)\n",
			__func__, qpn, rdev->glb_func_id, ret);

		if (roce3_hca_is_present(rdev) != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE] %s: HCA is present(2RST_QP), qpn(0x%x), func_id(%u)\n",
				__func__, qpn, rdev->glb_func_id);

			roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);

			if ((ret == -ETIMEDOUT) || (ret == -EPERM))
				rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;

			return -1;
		}
	}
	roce3_timeout_check(rdev, &tv_start, MODIFY_2RST_CMDQ, 0);
	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);
	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_qp_check_rdmarc
 Description  : roce3_qp_check_rdmarc
 Input		: struct roce3_device *rdev
				struct roce3_qp *rqp
 Output	   : None

  1.Date		 : 2017/04/26
	Modification : Create function

****************************************************************************
*/
static int roce3_qp_check_rdmarc(struct roce3_device *rdev, struct roce3_qp *rqp, int *cost)
{
	int times = 0;
	u32 rc_num = 0;
	u32 rc_check_index = 0;
	void *rdmarc_vaddr = NULL;
	dma_addr_t rdmarc_paddr = 0;

	rc_num = (u32)(((u32)1 << rqp->rdmarc.order) / RDMARC_NUM_PER_CACHELINE);
	rdmarc_vaddr = rqp->rdmarc.vaddr;
	rdmarc_paddr = rqp->rdmarc.dma_addr;

	times = rdev->try_times;
	do {
		if (roce3_hca_is_present(rdev) == 0)
			return 0;

		if ((*((u32 *)rdmarc_vaddr) == ROCE_RDMARC_DESTROY_CHECK_VALUE) &&
			(cpu_to_be32(*((u32 *)rdmarc_vaddr + 1)) == rqp->qpn) &&
			(cpu_to_be64(*((u64 *)rdmarc_vaddr + 1)) ==
			((u64)rdmarc_paddr + ((u64)ROCE_CACHE_LINE_SIZE * (u64)rc_check_index)))) {
			rdmarc_vaddr = (void *)((u8 *)rdmarc_vaddr + ROCE_CACHE_LINE_SIZE);
			rc_check_index++;
			if (rc_num == rc_check_index)
				break;
		} else {
			ROCE_UDELAY(US_PERF_DELAY);
			times--;
		}
	} while (times != 0);

	if (rc_num != rc_check_index) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to read rdmarc field back after try %d times, func_id(%d) rc_check_index:%u rc_num:%u\n",
			__func__, ((rdev->try_times - times) + 1),
			rdev->glb_func_id, rc_check_index, rc_num);
		*cost = (rdev->try_times - times) + 1;
		return -1;
	}
	*cost = (rdev->try_times - times) + 1;
	return 0;
}

static int roce3_qp_check_state(struct roce3_device *rdev,
	const struct roce3_qp *rqp, const u32 *wb_va, int *cost)
{
	int times = 0;
	int read_back_flag = 0;

	times = rdev->try_times;
	while ((times--) != 0) {
		if (roce3_hca_is_present(rdev) == 0)
			return 0;

		if (*(u32 *)wb_va == ROCE_QP_DESTROY_CHECK_VALUE) {
			read_back_flag = 1;
			break;
		}
		ROCE_UDELAY(US_PERF_DELAY);
	}

	if (read_back_flag == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to read QP field back after try %d times,qpn(0x%x), wb_data(0x%x), func_id(%d)\n",
			__func__, ((rdev->try_times - times) + 1), rqp->qpn,
			*(u32 *)wb_va, rdev->glb_func_id);
		*cost = (rdev->try_times - times) + 1;
		return -1;
	}
	*cost = (rdev->try_times - times) + 1;
	return 0;
}

static void roce3_qp_fill_cacheout_inbuf(struct roce3_device *rdev,
	struct roce3_qp *rqp, dma_addr_t wb_dma, struct tag_cqm_cmd_buf *cqm_cmd_inbuf)
{
	struct tag_roce_uni_cmd_qp_cache_invalid *qp_cacheout_inbuf = NULL;
	struct rdma_service_cap *rdma_cap = NULL;
	u16 host_oqid = 0;
	u8 host_id = 0;

	host_id = hinic3_host_id(rdev->hwdev);
	if (host_id == ROCE_SPU_HOST_ID) {
		host_id = ROCE_SPU_OQID_HOST_ID;
		host_oqid = (u16)ROCE_GET_SPU_HOST_OQID(host_id, rdev->glb_func_id, rqp->qpn);
	} else {
		host_oqid = (u16)ROCE_GET_HOST_OQID(host_id, rqp->qpn);
	}

	qp_cacheout_inbuf = (struct tag_roce_uni_cmd_qp_cache_invalid *)(cqm_cmd_inbuf)->buf;
	rdma_cap = &rdev->rdma_cap;

	if (!roce3_is_roceaa(rdev->cfg_info.scence_id)) {
		qp_cacheout_inbuf->com.dw0.bs.cmd_bitmask =
			cpu_to_be16(VERBS_CMD_TYPE_QP_BITMASK); //lint !e778
	} else {
		qp_cacheout_inbuf->com.dw0.bs.cmd_bitmask =
			cpu_to_be16(VERBS_CMD_TYPE_NOFAA_BITMASK); //lint !e778
	}

	qp_cacheout_inbuf->com.index = cpu_to_be32(rqp->qpn);
	qp_cacheout_inbuf->qp_cache.sq_buf_len =
		cpu_to_be32(ALIGN(((u32)rqp->sq.wqebb_cnt) << ((u32)rqp->sq.wqe_shift), PAGE_SIZE));
	qp_cacheout_inbuf->qp_cache.rq_buf_len =
		cpu_to_be32(ALIGN(((u32)rqp->rq.wqebb_cnt) << ((u32)rqp->sq.wqe_shift), PAGE_SIZE));
	qp_cacheout_inbuf->qp_cache.cmtt_cache.mtt_flags = 0;
	qp_cacheout_inbuf->qp_cache.cmtt_cache.mtt_num = 0;
	qp_cacheout_inbuf->qp_cache.cmtt_cache.mtt_cache_line_start =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.cmtt_cl_start);
	qp_cacheout_inbuf->qp_cache.cmtt_cache.mtt_cache_line_end =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.cmtt_cl_end);
	qp_cacheout_inbuf->qp_cache.cmtt_cache.mtt_cache_line_size =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.cmtt_cl_sz);
	qp_cacheout_inbuf->qp_cache.wb_gpa = cpu_to_be64(wb_dma);
	qp_cacheout_inbuf->qp_cache.dw9.bs.host_oqid = cpu_to_be16(host_oqid);
	qp_cacheout_inbuf->qp_cache.wqe_cache.wqe_flags = 0;
	qp_cacheout_inbuf->qp_cache.wqe_cache.wqe_num = 0;
	qp_cacheout_inbuf->qp_cache.wqe_cache.wqe_cache_line_start =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.wqe_cl_start);
	qp_cacheout_inbuf->qp_cache.wqe_cache.wqe_cache_line_end =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.wqe_cl_end);
	qp_cacheout_inbuf->qp_cache.wqe_cache.wqe_cache_line_size =
		cpu_to_be32(rdma_cap->dev_rdma_cap.roce_own_cap.wqe_cl_sz);
}

static int roce3_qp_send_cache_out_cmd(struct roce3_device *rdev,
	struct roce3_qp *rqp, void *wb_va, dma_addr_t wb_dma, int *cost)
{
	unsigned long end;
	int times = 0;
	int ret;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_uni_cmd_qp_cache_invalid), NULL, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	roce3_qp_fill_cacheout_inbuf(rdev, rqp, wb_dma, cqm_cmd_inbuf);

	end = jiffies + (ROCE_CMDQ_TIMEOUT_10MS * HZ);
	while (time_before(jiffies, end)) {
		times++;
		ret = roce3_send_qp_lb_cmd(rqp->qpn, rdev, ROCE_CMD_MISC_CACHE_INVLD,
			cqm_cmd_inbuf, NULL, ROCE_CMD_TIME_CLASS_C);
		if (ret <= 0) { /* return success or exception happened */
			break;
		}

		/*lint -e160 -e522*/
		cond_resched();
		/*lint +e160 +e522*/
	};

	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed MISC_CACHE_INVLD command after try %d times, ret(%d), func_id(%d) qpn(%d)\n",
			__func__, times, ret, rdev->glb_func_id, rqp->qpn);
		/* Card not present need to return OK */
		if (roce3_hca_is_present(rdev) == 0) {
			dev_err(rdev->hwdev_hdl, "[ROCE] %s: HCA not present(return ok), QPN(0x%x), ret(%d), func_id(%d)\n",
				__func__, rqp->qpn, ret, rdev->glb_func_id);
			goto out;
		}

		if ((ret == (-ETIMEDOUT)) || (ret == (-EPERM))) {
			dev_err(rdev->hwdev_hdl, "[ROCE] %s: CMDq timeout, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;
		}
		roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);
		*cost = times;
		return (-EINVAL);
	}

out:
	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);
	*cost = (rdev->try_times - times) + 1;
	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_qp_cache_out_cmd
 Description  : cache out qpc mtt
 Input		: struct roce3_device *rdev
				struct roce3_qp *rqp
 Output	   : None

  1.Date		 : 2016/9/24
	Modification : Created function

  2.Date		 : 2017/04/26
	Modification : Modify function

****************************************************************************
*/
int roce3_qp_cache_out_cmd(struct roce3_device *rdev, struct roce3_qp *rqp)
{
	int ret = 0;
	int cost = 0;
	void *wb_va = NULL;
	dma_addr_t wb_dma = 0;
	struct timespec64 tv_start;

	ktime_get_ts64(&tv_start);
	wb_va = dma_alloc_coherent(&rdev->pdev->dev, (size_t)4UL, &wb_dma, GFP_KERNEL);
	if (wb_va == NULL) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc wb_va, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -ENOMEM;
	}
	roce3_timeout_check(rdev, &tv_start, CACHE_INVLAID_ALLOC, cost);

	ret = roce3_qp_send_cache_out_cmd(rdev, rqp, wb_va, wb_dma, &cost);
	if (ret != 0)
		goto err;

	roce3_timeout_check(rdev, &tv_start, CACHE_INVLAID_CMDQ, cost);
	if (rqp->rsp_depth > 0) {
		ret = roce3_qp_check_rdmarc(rdev, rqp, &cost);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to check qp rdmarc, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			goto err;
		}
		roce3_timeout_check(rdev, &tv_start, CACHE_INVLAID_RDMARC_CHECK, cost);
	}
	ret = roce3_qp_check_state(rdev, rqp, (u32 *)wb_va, &cost);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to check qp state, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err;
	}
	roce3_timeout_check(rdev, &tv_start, CACHE_INVLAID_QP_CHECK, cost);

err:
	dma_free_coherent(&rdev->pdev->dev, sizeof(u32), wb_va, wb_dma);

	return ret;
}

static u8 roce3_get_qp_cmdq_cmd(struct roce3_device *rdev, struct roce3_qp *rqp,
	struct ib_qp_attr *attr, int attr_mask)
{
	static u16 op[ROCE_QP_STATE_NUM][ROCE_QP_STATE_NUM];
	enum ib_qp_state cur_state, new_state;

	cur_state = (enum ib_qp_state)(((((u32)attr_mask) & IB_QP_CUR_STATE) != 0) ?
		attr->cur_qp_state : rqp->qp_state);
	new_state = ((((u32)attr_mask) & IB_QP_STATE) != 0) ? attr->qp_state : cur_state;
	if ((cur_state > IB_QPS_ERR) || (new_state > IB_QPS_ERR)) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: QP state modify invalid, cur_state(%d), new_state(%d), func_id(%d)\n",
			__func__, cur_state, new_state, rdev->glb_func_id);
		return 0;
	}
	op[IB_QPS_RESET][IB_QPS_ERR] = ROCE_CMD_2ERR_QP;
	op[IB_QPS_RESET][IB_QPS_INIT] = ROCE_CMD_RST2INIT_QP;

	op[IB_QPS_INIT][IB_QPS_ERR] = ROCE_CMD_2ERR_QP;
	op[IB_QPS_INIT][IB_QPS_INIT] = ROCE_CMD_INIT2INIT_QP;
	op[IB_QPS_INIT][IB_QPS_RTR] = ROCE_CMD_INIT2RTR_QP;

	op[IB_QPS_RTR][IB_QPS_ERR] = ROCE_CMD_2ERR_QP;
	op[IB_QPS_RTR][IB_QPS_RTS] = ROCE_CMD_RTR2RTS_QP;

	op[IB_QPS_RTS][IB_QPS_ERR] = ROCE_CMD_2ERR_QP;
	op[IB_QPS_RTS][IB_QPS_RTS] = ROCE_CMD_RTS2RTS_QP;
	op[IB_QPS_RTS][IB_QPS_SQD] = ROCE_CMD_RTS2SQD_QP;

	op[IB_QPS_SQD][IB_QPS_ERR] = ROCE_CMD_2ERR_QP;
	op[IB_QPS_SQD][IB_QPS_RTS] = ROCE_CMD_SQD2RTS_QP;
	op[IB_QPS_SQD][IB_QPS_SQD] = ROCE_CMD_SQD2SQD_QP;

	op[IB_QPS_SQE][IB_QPS_ERR] = ROCE_CMD_2ERR_QP;
	op[IB_QPS_SQE][IB_QPS_RTS] = ROCE_CMD_SQERR2RTS_QP;

	op[IB_QPS_ERR][IB_QPS_ERR] = ROCE_CMD_2ERR_QP;

	return (u8)op[cur_state][new_state];
}

static int roce3_qp_rts2sqd_cmd(struct roce3_device *rdev, struct roce3_qp *rqp,
	const struct ib_qp_attr *attr, int attr_mask)
{
	int ret = 0;
	int sqd_event = 0;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_roce_uni_cmd_qp_modify_rts2sqd *qp_rts2sqd_inbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_uni_cmd_qp_modify_rts2sqd), NULL, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	sqd_event = ((((u32)attr_mask) & IB_QP_EN_SQD_ASYNC_NOTIFY) != 0) &&
		(attr->en_sqd_async_notify != 0);
	qp_rts2sqd_inbuf = (struct tag_roce_uni_cmd_qp_modify_rts2sqd *)cqm_cmd_inbuf->buf;
	qp_rts2sqd_inbuf->com.index = cpu_to_be32(rqp->qpn);
	qp_rts2sqd_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_QP_BITMASK); //lint !e778
	qp_rts2sqd_inbuf->sqd_event_en = cpu_to_be32((u32)(sqd_event != 0));

	ret = roce3_send_qp_lb_cmd(rqp->qpn, rdev, ROCE_CMD_RTS2SQD_QP,
		cqm_cmd_inbuf, NULL, ROCE_CMD_TIME_CLASS_A);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to send RTS2SQD_QP cmd, func_id(%d), ret(0x%x)\n",
			__func__, rdev->glb_func_id, ret);
		roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);
		return -1;
	}

	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);
	return 0;
}

static void roce3_qp_fill_modify_inbuf(struct tag_cqm_cmd_buf *cqm_cmd_inbuf, struct roce3_qp *rqp,
	struct tag_roce_verbs_qp_attr *qp_attr, u32 optpar)
{
	struct tag_roce_uni_cmd_modify_qpc *qp_modify_inbuf = NULL;

	qp_modify_inbuf = (struct tag_roce_uni_cmd_modify_qpc *)cqm_cmd_inbuf->buf;
	roce3_qpc_to_be(qp_attr, rqp, (u32 *)&qp_modify_inbuf->qp_attr);

	qp_modify_inbuf->com.index = cpu_to_be32(rqp->qpn);
	qp_modify_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_QP_BITMASK); //lint !e778
	qp_modify_inbuf->com.opt = cpu_to_be32(optpar);

#ifdef ROCE_VBS_EN
	if (rqp->vbs_qp_ptr) { // vbs_en, transmit record addr to ucode
		roce3_vbs_transmit_sqpc_ci_record_addr(rqp, cqm_cmd_inbuf->buf);
	}
#endif

}

static int roce3_qp_handle_err(struct roce3_device *rdev, const struct roce3_qp *rqp, int ret)
{
	dev_err(rdev->hwdev_hdl,
		"[ROCE, ERR] %s: Failed to send MODIFY_QP command, func_id(%d), ret(%d)\n",
		__func__, rdev->glb_func_id, ret);

	if (roce3_hca_is_present(rdev) != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA is present(MODIFY_QP), qpn(0x%x), func_id(%u)\n",
			__func__, rqp->qpn, rdev->glb_func_id);

		if ((ret == (-ETIMEDOUT)) || (ret == (-EPERM)))
			rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;

		return -1;
	}

	return 0;
}

static int roce3_qp_modify_cmd(struct roce3_device *rdev, struct roce3_qp *rqp, u8 cmd,
	struct tag_roce_verbs_qp_attr *qp_attr, u32 optpar)
{
	int ret = 0;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_cqm_cmd_buf *cqm_cmd_outbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_uni_cmd_modify_qpc),
		&cqm_cmd_outbuf, ROCE_QP_MODIFY_CMD_OUT_BUF_SIZE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return (-ENOMEM);
	}

	if (!roce3_is_roceaa(rdev->cfg_info.scence_id))
		roce3_qp_fill_modify_inbuf(cqm_cmd_inbuf, rqp, qp_attr, optpar);
	else
		roce3_qp_modify_cmd_ext(cqm_cmd_inbuf, rqp, qp_attr, optpar);

	ret = roce3_send_qp_lb_cmd(rqp->qpn, rdev, cmd, cqm_cmd_inbuf,
		cqm_cmd_outbuf, ROCE_CMD_TIME_CLASS_A);
	if (ret != 0)
		ret = roce3_qp_handle_err(rdev, rqp, ret);

	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);
	return ret;
}

void roce3_cq_clean(struct roce3_cq *cq, u32 qpn, struct roce3_srq *srq)
{
	spin_lock_irq(&cq->lock);
	roce3_cq_clean_process(cq, qpn, srq);
	spin_unlock_irq(&cq->lock);
}

static int roce3_qp_clean_kernel_res(struct roce3_qp *rqp)
{
	struct roce3_cq *send_cq = NULL;
	struct roce3_cq *recv_cq = NULL;

	roce3_get_cqs(rqp, &send_cq, &recv_cq);

	roce3_cq_clean(recv_cq, rqp->qpn, rqp->ibqp.srq ? to_roce3_srq(rqp->ibqp.srq) : NULL);
	if (send_cq != recv_cq)
		roce3_cq_clean(send_cq, rqp->qpn, NULL);

	rqp->rq.head = 0;
	rqp->rq.tail = 0;

	rqp->sq.head = 0;
	rqp->sq.tail = 0;

	rqp->sq_next_wqe = 0;

	*(rqp->db.db_record) = 0;

	if (rqp->qp_type != IB_QPT_XRC_TGT) {
		if (rqp->has_rq && rqp->qp_buf_info->q_header_vaddr)
			memset(rqp->qp_buf_info->q_header_vaddr, 0, sizeof(u64));
	}

	return 0;
}

static int roce3_qp_modify_2rst(struct roce3_device *rdev, struct roce3_qp *rqp)
{
	int ret = 0;

	ret = roce3_qp_modify_2rst_cmd(rdev, rqp->qpn);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to modify QP(0x%06x) to RESET, func_id(%d)\n",
			__func__, rqp->qpn, rdev->glb_func_id);
		return ret;
	}

	ret = roce3_qp_cache_out_cmd(rdev, rqp);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: QP(0x%06x) cache invalid failed, func_id(%d)\n",
			__func__, rqp->qpn, rdev->glb_func_id);
		return ret;
	}

	rqp->qp_state = IB_QPS_RESET;

	if (rqp->ibqp.uobject == NULL) {
		ret = roce3_qp_clean_kernel_res(rqp);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Clean kernel QP(0x%06x)  failed, func_id(%d)\n",
				__func__, rqp->qpn, rdev->glb_func_id);
			return ret;
		}
	}

	return 0;
}

static int roce3_qp_modify(struct roce3_device *rdev, struct roce3_qp *rqp,
	struct ib_qp_attr *attr, int attr_mask)
{
	int ret = 0;
	u32 optpar = 0;
	struct tag_roce_verbs_qp_attr qp_attr;
	u8 cmd = 0;

	memset(&qp_attr, 0, sizeof(qp_attr));

	if ((((u32)attr_mask) & IB_QP_MAX_DEST_RD_ATOMIC) != 0) {
		ret = roce3_alloc_opt_rdmarc(rqp, attr, attr_mask);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to alloc rdmarc, func(%d)\n",
				__func__, rdev->glb_func_id);
			return ret;
		}
	}

	ret = roce3_set_opt_field(rqp, attr, attr_mask, &qp_attr, &optpar);
	if (ret != 0)
		goto err_out;

	roce3_set_abs_field(rqp, attr, attr_mask, &qp_attr);

	cmd = roce3_get_qp_cmdq_cmd(rdev, rqp, attr, attr_mask);
	if (cmd == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Invalid cmd, func_id(%d), qpn(%d), cmd(%d)\n",
			__func__, rdev->glb_func_id, rqp->qpn, cmd);
		ret = (-EINVAL);
		goto err_out;
	}
	if (cmd == ROCE_CMD_RTS2SQD_QP)
		ret = roce3_qp_rts2sqd_cmd(rdev, rqp, attr, attr_mask);
	else
		ret = roce3_qp_modify_cmd(rdev, rqp, cmd, &qp_attr, optpar);

	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to send modify cmd(%d), func(%d), qpn(%d), ret(%d)\n",
			__func__, cmd, rdev->glb_func_id, rqp->qpn, ret);
		goto err_out;
	}

	roce3_record_opt_field(rqp, attr, attr_mask);
	return 0;

err_out:
	if ((((u32)attr_mask) & IB_QP_MAX_DEST_RD_ATOMIC) != 0)
		roce3_free_opt_rdmarc(rqp);

	return ret;
}

static int roce3_qp_get_path(struct roce3_device *rdev, struct roce3_qp *rqp,
	struct rdma_ah_attr *ah_attr)
{
	return 0;
}

static int roce3_qp_modify_check_rd_and_mtu(const struct roce3_qp *rqp,
	const struct ib_qp_attr *attr, int attr_mask, const struct rdma_service_cap *rdma_cap)
{
	enum ib_qp_state cur_state =
		(enum ib_qp_state)(((((u32)attr_mask) & IB_QP_CUR_STATE) != 0) ?
		attr->cur_qp_state : rqp->qp_state);
	enum ib_qp_state new_state =
		(enum ib_qp_state)(((((u32)attr_mask) & IB_QP_STATE) != 0) ?
		attr->qp_state : cur_state);

	if (((((u32)attr_mask) & IB_QP_MAX_QP_RD_ATOMIC) != 0) &&
		(attr->max_rd_atomic > rdma_cap->dev_rdma_cap.roce_own_cap.max_qp_init_rdma)) {
		pr_err(
			"[ROCE, ERR] %s: Qpn(0x%x), max_rd_atomic (%d) too large. Transition %d to %d. qp_type(%d)\n",
			__func__, rqp->ibqp.qp_num, attr->max_rd_atomic, cur_state,
			new_state, rqp->ibqp.qp_type);
		return -EINVAL;
	}

	if (((((u32)attr_mask) & IB_QP_MAX_DEST_RD_ATOMIC) != 0) &&
		(attr->max_dest_rd_atomic > rdma_cap->dev_rdma_cap.roce_own_cap.max_qp_dest_rdma)) {
		pr_err("[ROCE, ERR] %s: Qpn(0x%x), max_dest_rd_atomic (%d) too large. Transition %d to %d. qp_type(%d)\n",
			__func__, rqp->ibqp.qp_num, attr->max_dest_rd_atomic,
			cur_state, new_state, rqp->ibqp.qp_type);
		return -EINVAL;
	}

	if (((((u32)attr_mask) & IB_QP_PATH_MTU) != 0) &&
		((attr->path_mtu < IB_MTU_256) || (attr->path_mtu > IB_MTU_4096))) {
		pr_err("[ROCE, ERR] %s: Input path MTU(%u) is invalid\n", __func__, attr->path_mtu);
		return -EINVAL;
	}

	return 0;
}

static int roce3_qp_modify_check(struct roce3_qp *rqp, struct ib_qp_attr *attr, int attr_mask,
	struct rdma_service_cap *rdma_cap)
{
	int ret;
	enum ib_qp_state cur_state, new_state;

	cur_state = (enum ib_qp_state)(((((u32)attr_mask) & IB_QP_CUR_STATE) != 0) ?
		attr->cur_qp_state : rqp->qp_state);
	new_state = (enum ib_qp_state)(((((u32)attr_mask) & IB_QP_STATE) != 0) ?
		attr->qp_state : cur_state);

	if (!roce3_check_qp_modify_ok(cur_state, new_state, (enum ib_qp_type)(rqp->ibqp.qp_type),
		(enum ib_qp_attr_mask)attr_mask, IB_LINK_LAYER_ETHERNET)) {
		pr_err(
			"[ROCE, ERR] %s: Qpn(0x%x), invalid attribute mask specified for transition %d to %d, qp_type(%d), attr_mask(0x%x)\n",
			__func__, rqp->ibqp.qp_num, cur_state, new_state,
			rqp->ibqp.qp_type, attr_mask);
		return (-EINVAL);
	}

	if (((((u32)attr_mask) & IB_QP_PORT) != 0) && (attr->port_num != ROCE_DEFAULT_PORT_NUM)) {
		pr_err("[ROCE, ERR] %s: Qpn(0x%x), invalid port number(%d) specified for transition %d to %d. qp_type(%d)\n",
			__func__, rqp->ibqp.qp_num, attr->port_num, cur_state,
			new_state, rqp->ibqp.qp_type);
		return (-EINVAL);
	}

	if ((((u32)attr_mask) & IB_QP_PKEY_INDEX) != 0) {
		if (attr->pkey_index > 0) {
			pr_err(
				"[ROCE, ERR] %s: Qpn(0x%x), invalid pkey index (%d) specified for transition %d to %d. qp_type(%d)\n",
				__func__, rqp->ibqp.qp_num, attr->pkey_index, cur_state,
				new_state, rqp->ibqp.qp_type);
			return (-EINVAL);
		}
	}

	ret = roce3_qp_modify_check_rd_and_mtu(rqp, attr, attr_mask, rdma_cap);

	return ret;
}

#define ROCE3_QP_HANDLE 0
#define ROCE3_QP_CONTINUE 1
static int roce3_modify_qp_pre(struct ib_qp *ibqp, struct ib_qp_attr *attr,
	int attr_mask, struct ib_udata *udata)
{
	int ret;
	struct roce3_qp *rqp = NULL;
	struct roce3_device *rdev = NULL;
	enum ib_qp_state cur_state, new_state;

	rqp = to_roce3_qp(ibqp);
	rdev = to_roce3_dev(ibqp->device);
	cur_state = (enum ib_qp_state)(((((u32)attr_mask) & IB_QP_CUR_STATE) != 0) ?
		attr->cur_qp_state : rqp->qp_state);
	new_state = ((((u32)attr_mask) & IB_QP_STATE) != 0) ? attr->qp_state : cur_state;

	ret = roce3_qp_modify_check(rqp, attr, attr_mask, &rdev->rdma_cap);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed qp modify check, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	if (new_state == IB_QPS_RESET) {
		if (cur_state != new_state) {
			ret = roce3_qp_modify_2rst(rdev, rqp);
			if (ret != 0) {
				dev_err(rdev->hwdev_hdl,
					"[ROCE, ERR] %s: Failed to modify 2rst, func_id(%d)\n",
					__func__, rdev->glb_func_id);
			}
		}
		return ROCE3_QP_HANDLE;
	}

	ret = roce3_qp_modify_pre_extend(rqp, attr, attr_mask, udata);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to modify extend qp, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	return ROCE3_QP_CONTINUE;
}

int roce3_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
	int attr_mask, struct ib_udata *udata)
{
	int ret = 0;
	struct roce3_qp *rqp = NULL;
	struct roce3_device *rdev = NULL;

	rqp = to_roce3_qp(ibqp);
	rdev = to_roce3_dev(ibqp->device);

	mutex_lock(&rqp->mutex);

	ret = roce3_modify_qp_pre(ibqp, attr, attr_mask, udata);
	if ((ret == ROCE3_QP_HANDLE) || (ret < 0))
		goto out;

	if ((((u32)attr_mask) & IB_QP_AV) != 0) {
		ret = roce3_qp_get_path(rdev, rqp, &attr->ah_attr);
		if (ret != 0)
			goto out;
	}

	ret = roce3_qp_modify(rdev, rqp, attr, attr_mask);
	if (ret != 0)
		goto out;

out:
	mutex_unlock(&rqp->mutex);
	return ret;
}

int roce3_send_qp_lb_cmd(u32 qpn, struct roce3_device *rdev, u8 cmd,
	struct tag_cqm_cmd_buf *buf_in, struct tag_cqm_cmd_buf *buf_out, u32 timeout)
{
	int ret = 0;
	struct timespec64 tv_start;

	ktime_get_ts64(&tv_start);
	if ((rdev->cfg_info.lb_en != 0) && (rdev->cfg_info.lb_mode == ROCE_LB_MODE_1)) {
		u8 cos = qpn & 0x3;

		ret = cqm_lb_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, cmd, cos,
			buf_in, buf_out, NULL, timeout, HINIC3_CHANNEL_ROCE);
	} else {
		ret = cqm_send_cmd_box(rdev->hwdev, HINIC3_MOD_ROCE, cmd, buf_in,
			buf_out, NULL, timeout, HINIC3_CHANNEL_ROCE);
	}

	roce3_timeout_check(rdev, &tv_start, CMDQ_SDKCALL_BUTT, 0);
	return ret;
}
