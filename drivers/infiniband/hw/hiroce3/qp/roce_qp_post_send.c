// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <rdma/ib_verbs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>

#include "roce_compat.h"

#include "roce.h"
#include "roce_mix.h"
#include "roce_mr.h"
#include "roce_user.h"
#include "roce_xrc.h"
#include "roce_srq.h"
#include "roce_cq.h"
#include "roce_qp.h"
#include "roce_post.h"
#include "roce_dif_format.h"
#include "roce_main_extension.h"

#ifdef __ROCE_DFX__
#include "roce_dfx.h"
#endif

#define GOTO_LOCAL 1

#define GOTO_OUT 2

#define ROCE_NEED_JUMP 1

#define BYTE_MASK 255

#define ROCE_CTRL_SEG_SL 2
/*
 ****************************************************************************
 Prototype	: roce3_get_send_wqe
 Description  : roce3_get_send_wqe
 Input		: struct roce3_qp *rqp
				u32 n
 Output	   : None

  1.Date		 : 2015/5/26
	Modification : Created function

****************************************************************************
*/
static void *roce3_get_send_wqe(struct roce3_qp *rqp, u32 n)
{
	u32 wqebb_index = (n & (((u32)rqp->sq.wqebb_cnt) - 1));
	u32 wqebb_pos = wqebb_index << rqp->sq.wqe_shift;

	return roce3_get_wqe(rqp, rqp->sq.offset + wqebb_pos);
}

/*
 ****************************************************************************
 Prototype	: roce3_wq_overflow
 Description  : roce3_wq_overflow
 Input		: struct roce3_wq *wq
				int wr_num
				struct ib_cq *ibcq
 Output	   : None

  1.Date		 : 2015/5/26
	Modification : Created function

****************************************************************************
*/
int roce3_wq_overflow(struct roce3_wq *wq, u32 wr_num, struct ib_cq *ibcq)
{
	unsigned int cur = 0;
	struct roce3_cq *cq = NULL;

	cur = wq->head - wq->tail;
	if (ROCE_LIKELY((cur + wr_num) < (unsigned int)wq->max_post))
		return 0;

	cq = to_roce3_cq(ibcq);
	spin_lock(&cq->lock);
	cur = wq->head - wq->tail;
	spin_unlock(&cq->lock);

	return ((cur + (unsigned int)wr_num) >= (unsigned int)wq->max_post);
}

/*
 ****************************************************************************
 Prototype	: roce3_ib_opcode
 Description  :
 Input		:
 Output	   : None
 Return Value :
 Calls		:
 Called By	:

  History		:
  1.Date		 : 2015/7/30
	Author	   :
	Modification : Created function

****************************************************************************
*/
static const u32 roce3_ib_opcode[] = {
	ROCE_WQE_OPCODE_RDMA_WRITE, /* [IB_WR_RDMA_WRITE] : 0 */
	ROCE_WQE_OPCODE_RDMA_WRITE_IMM, /* [IB_WR_RDMA_WRITE_WITH_IMM] : 1 */
	ROCE_WQE_OPCODE_SEND, /* [IB_WR_SEND] : 2 */
	ROCE_WQE_OPCODE_SEND_IMM, /* [IB_WR_SEND_WITH_IMM] : 3 */
	ROCE_WQE_OPCODE_RDMA_READ, /* [IB_WR_RDMA_READ] : 4 */
	ROCE_WQE_OPCODE_ATOMIC_CMP_SWP, /* [IB_WR_ATOMIC_CMP_AND_SWP] : 5 */
	ROCE_WQE_OPCODE_ATOMIC_FETCH_ADD, /* [IB_WR_ATOMIC_FETCH_AND_ADD] : 6 */
	0, /* [IB_WR_LSO] : 7 NO SUPPORT */
	ROCE_WQE_OPCODE_SEND_INVAL, /* [IB_WR_SEND_WITH_INV] : 8 */
	0, /* [IB_WR_RDMA_READ_WITH_INV] : 9 */
	ROCE_WQE_OPCODE_LOCAL_INVAL, /* [IB_WR_LOCAL_INV] : 10 */
	ROCE_WQE_OPCODE_FRMR, /* [IB_WR_REG_MR] : 11 */
	ROCE_WQE_OPCODE_MASKED_ATOMIC_CMP_SWP, /* [IBV_EXP_WR_EXT_MASKED_ATOMIC_CMP_AND_SWP] : 12 */
	/* [IBV_EXP_WR_EXT_MASKED_ATOMIC_FETCH_AND_ADD] : 13 */
	ROCE_WQE_OPCODE_MASKED_ATOMIC_FETCH_ADD,
	ROCE_WQE_OPCODE_REG_SIG_MR, /* [IB_WR_REG_SIG_MR] : 14 */

	/* 15-64 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0,

	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, /* IBV_EXP_WR_SEND_ENABLE 96 */
	0, /* IBV_EXP_WR_RECV_ENABLE 97 */
	0, /* IBV_EXP_WR_CQE_WAIT 98 */

	/* ex */
	ROCE_WQE_OPCODE_FRMR, /* [IB_WR_FAST_REG_MR] : 11 */
};

/*
 ****************************************************************************
 Prototype	: roce3_set_send_seg
 Description  : roce3_set_send_seg
 Input		: struct roce3_wqe_snd_tsk_seg *snd_tsk_seg
				struct ib_send_wr *wr
 Output	   : None

  1.Date		 : 2017/5/26
	Modification : Created function

****************************************************************************
*/
static void roce3_set_send_seg(struct roce3_wqe_send_tsk_seg *snd_tsk_seg,
	const struct ib_send_wr *wr)
{
	if (wr->opcode == IB_WR_SEND_WITH_IMM)
		snd_tsk_seg->immdata_invkey = wr->ex.imm_data;

	if (wr->opcode == IB_WR_SEND_WITH_INV)
		snd_tsk_seg->immdata_invkey = cpu_to_be32(wr->ex.invalidate_rkey);
}

/*
 ****************************************************************************
 Prototype	: roce3_set_atomic_seg
 Description  : roce3_set_atomic_seg
 Input		: struct roce3_wqe_atomic_tsk_seg *atomic_tsk_seg
				struct ib_send_wr *wr
 Output	   : None

  1.Date		 : 2015/5/26
	Modification : Created function

****************************************************************************
*/

static void roce3_set_atomic_seg(struct roce3_wqe_atomic_tsk_seg *atomic_tsk_seg,
	const struct ib_send_wr *wr)
{
	const struct ib_atomic_wr *atomic = ROCE_ATOMIC_WR(wr);

	atomic_tsk_seg->key = cpu_to_be32(atomic->rkey);
	atomic_tsk_seg->va = cpu_to_be64(atomic->remote_addr);

	if (wr->opcode == IB_WR_ATOMIC_CMP_AND_SWP) {
		atomic_tsk_seg->swap_add_data = cpu_to_be64(atomic->swap);
		atomic_tsk_seg->cmp_data = cpu_to_be64(atomic->compare_add);
	} else if (wr->opcode == IB_WR_ATOMIC_FETCH_AND_ADD) {
		atomic_tsk_seg->swap_add_data = cpu_to_be64(atomic->compare_add);
		atomic_tsk_seg->cmp_data = 0;
	} else {
		/* IB_WR_MASKED_ATOMIC_FETCH_AND_ADD */
		atomic_tsk_seg->swap_add_data = cpu_to_be64(atomic->compare_add);
		atomic_tsk_seg->cmp_data = cpu_to_be64(atomic->compare_add_mask);
	}
}

/*
 ****************************************************************************
 Prototype	: roce3_set_masked_atomic_seg
 Description  : roce3_set_masked_atomic_seg
 Input		: struct roce3_wqe_mask_atomic_tsk_seg *mask_atomic_tsk_seg
				struct ib_send_wr *wr
 Output	   : None

  1.Date		 : 2015/5/26
	Modification : Created function

****************************************************************************
*/
static void roce3_set_masked_atomic_seg(struct roce3_wqe_mask_atomic_tsk_seg *mask_atomic_tsk_seg,
	const struct ib_send_wr *wr)
{
	const struct ib_atomic_wr *atomic = ROCE_ATOMIC_WR(wr);

	mask_atomic_tsk_seg->rkey = cpu_to_be32(atomic->rkey);
	mask_atomic_tsk_seg->va = cpu_to_be64(atomic->remote_addr);

	mask_atomic_tsk_seg->swap_add_data = cpu_to_be64(atomic->swap);
	mask_atomic_tsk_seg->swap_msk = cpu_to_be64(atomic->swap_mask);
	mask_atomic_tsk_seg->cmp_data = cpu_to_be64(atomic->compare_add);
	mask_atomic_tsk_seg->cmp_msk = cpu_to_be64(atomic->compare_add_mask);
}

/*
 ****************************************************************************
 Prototype	: roce3_set_rdma_seg
 Description  : roce3_set_rdma_seg
 Input		: struct roce3_wqe_rdma_tsk_seg *rdma_tsk_seg
				struct ib_send_wr *wr
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
static __always_inline void roce3_set_rdma_seg(struct roce3_wqe_rdma_tsk_seg *rdma_tsk_seg,
	const struct ib_send_wr *wr)
{
	const struct ib_rdma_wr *rdma = ROCE_RDMA_WR(wr);

	rdma_tsk_seg->va = cpu_to_be64(rdma->remote_addr);
	rdma_tsk_seg->rkey = cpu_to_be32(rdma->rkey);

	if (wr->opcode == IB_WR_RDMA_WRITE_WITH_IMM)
		rdma_tsk_seg->imm_data = wr->ex.imm_data;
}

/*
 ****************************************************************************
 Prototype	: roce3_set_local_inv_seg
 Description  : roce3_set_local_inv_seg
 Input		: struct roce3_wqe_local_inv_tsk_seg *inv_tsk_seg
				struct ib_send_wr *wr
 Output	   : None

  1.Date		 : 2015/5/26
	Modification : Created function

****************************************************************************
*/
static void roce3_set_local_inv_seg(struct roce3_wqe_local_inv_tsk_seg *inv_tsk_seg,
	const struct ib_send_wr *wr)
{
	inv_tsk_seg->inv_key = cpu_to_be32(wr->ex.invalidate_rkey);
}

/*
 ****************************************************************************
 Prototype	: roce3_set_ud_seg_cycle1
 Description  : set ud type task segment before cycled
 Input		: struct roce3_wqe_ud_tsk_seg_cycle1 *ud_tsk_seg_cycle1
				struct ib_send_wr *wr
 Output	   : None

  1.Date		 : 2015/8/8
	Modification : Created function

****************************************************************************
*/
static void roce3_set_ud_seg_cycle1(struct roce3_wqe_ud_tsk_seg_cycle1 *ud_tsk_seg_cycle1,
	const struct ib_send_wr *wr)
{
	const struct ib_ud_wr *ud = ROCE_UD_WR(wr);
	struct roce3_ah *rah = to_roce3_ah(ud->ah);

	if (wr->opcode == IB_WR_SEND_WITH_IMM)
		ud_tsk_seg_cycle1->immdata_invkey = wr->ex.imm_data;

	ud_tsk_seg_cycle1->dw2.value = rah->priv_ah.dw0.value;
	ud_tsk_seg_cycle1->dw3.value = rah->priv_ah.dw1.value;
	ud_tsk_seg_cycle1->dw4.value = rah->priv_ah.dw2.value;
	memcpy((void *)ud_tsk_seg_cycle1->dgid, (void *)rah->priv_ah.dgid, ROCE_GID_LEN);
	ud_tsk_seg_cycle1->dw9.value = cpu_to_be32(ud->remote_qpn);
	ud_tsk_seg_cycle1->qkey = cpu_to_be32(ud->remote_qkey);
}

/*
 ****************************************************************************
 Prototype	: roce3_set_ud_seg_cycle2
 Description  : set ud type task segment after cycled
 Input		: struct roce3_wqe_ud_tsk_seg_cycle2 *ud_tsk_seg_cycle2
				struct ib_send_wr *wr
 Output	   : None

  1.Date		 : 2015/5/26
	Modification : Created function

****************************************************************************
*/
static void roce3_set_ud_seg_cycle2(struct roce3_wqe_ud_tsk_seg_cycle2 *ud_tsk_seg_cycle2,
	const struct ib_send_wr *wr)
{
	const struct ib_ud_wr *ud = ROCE_UD_WR(wr);
	struct roce3_ah *rah = to_roce3_ah(ud->ah);

	ud_tsk_seg_cycle2->dw0.value = rah->priv_ah.dw7.value;
	ud_tsk_seg_cycle2->dmac_l32 = rah->priv_ah.dmac_l32;
}

/*
 ****************************************************************************
 Prototype	: roce3_set_ud_seg
 Description  : roce3_set_ud_seg
 Input		: struct roce3_wqe_ud_tsk_seg *ud_tsk_seg
				struct ib_send_wr *wr
 Output	   : None

  1.Date		 : 2015/5/26
	Modification : Created function

****************************************************************************
*/
static void roce3_set_ud_seg(struct roce3_wqe_ud_tsk_seg *ud_tsk_seg, const struct ib_send_wr *wr)
{
	const struct ib_ud_wr *ud = ROCE_UD_WR(wr);
	struct roce3_ah *rah = to_roce3_ah(ud->ah);

	if (wr->opcode == IB_WR_SEND_WITH_IMM)
		ud_tsk_seg->immdata_invkey = wr->ex.imm_data;

	ud_tsk_seg->dw3.value = rah->priv_ah.dw0.value;
	ud_tsk_seg->dw4.value = rah->priv_ah.dw1.value;
	ud_tsk_seg->dw5.value = rah->priv_ah.dw2.value;
	memcpy((void *)ud_tsk_seg->dgid, (void *)rah->priv_ah.dgid,
		sizeof(ud_tsk_seg->dgid));
	ud_tsk_seg->dw10.value = cpu_to_be32(ud->remote_qpn);
	ud_tsk_seg->qkey = cpu_to_be32(ud->remote_qkey);
	ud_tsk_seg->dw12.value = rah->priv_ah.dw7.value;
	ud_tsk_seg->dmac_l32 = rah->priv_ah.dmac_l32;
}

/*
 ****************************************************************************
 Prototype	: roce3_set_data_seg
 Description  : roce3_set_data_seg
 Input		: struct roce3_wqe_data_seg *dseg
				struct ib_sge *sge
 Output	   : None

  1.Date		 : 2015/5/26
	Modification : Created function

****************************************************************************
*/
void roce3_set_data_seg(struct roce3_wqe_data_seg *dseg, struct ib_sge *sge)
{
	dseg->addr = cpu_to_be64(sge->addr);

	dseg->dw2.bs.len = sge->length & 0x7fffffff;
	dseg->dw2.bs.rsvd = 0;

	dseg->dw2.value = cpu_to_be32(dseg->dw2.value);

	dseg->key = cpu_to_be32(sge->lkey);
}

static void roce3_set_dwqe_db(struct roce3_qp *qp, struct roce3_wqe_ctrl_seg *ctrl_seg,
	unsigned int index)
{
	struct roce3_device *rdev = to_roce3_dev(qp->ibqp.device);

	ctrl_seg->dw2.bs.qpn = qp->qpn & 0xfffff;
	ctrl_seg->dw2.bs.ctx_size = 1; /* 512B */
	ctrl_seg->dw2.bs.cp_flag = 0;
	ctrl_seg->dw2.bs.cos = roce3_get_db_cos_from_vlan_pri(rdev, qp->sl & 0x7);
	ctrl_seg->dw2.bs.type = ROCE_SQ_DB_TYPE;

	ctrl_seg->dw3.bs.pi = index & 0xffff;
	ctrl_seg->dw3.bs.sub_type = 0;

	ctrl_seg->dw3.bs.mtu_shift = qp->db_path_mtu;
	ctrl_seg->dw3.bs.sgid_index = qp->db_sgid_index;
	if (qp->qp_type == IB_QPT_RC) {
		// ctrl_seg->dw3.bs.rc_flag = 1;
	} else if (qp->qp_type == IB_QPT_UD) {
		// ctrl_seg->dw3.bs.ud_vld = 1;
		ctrl_seg->dw3.bs.mtu_shift = 3;
	} else if (qp->qp_type == IB_QPT_XRC_INI || qp->qp_type == IB_QPT_XRC_TGT) {
		ctrl_seg->dw3.bs.xrc_vld = 1;
		// ctrl_seg->dw3.bs.rc_flag = 1;
	}
	// ctrl_seg->dw3.bs.local_trans = 0;

	ctrl_seg->dw1.value = cpu_to_be32(ctrl_seg->dw1.value);
	ctrl_seg->dw2.value = cpu_to_be32(ctrl_seg->dw2.value);
	ctrl_seg->dw3.value = cpu_to_be32(ctrl_seg->dw3.value);
}

static void roce3_set_sq_db(struct roce3_qp *qp, struct roce_sq_db_seg *db, unsigned int index)
{
	struct roce3_device *rdev = to_roce3_dev(qp->ibqp.device);

	db->dw0.bs.qpn = qp->qpn & 0xfffff;
	db->dw0.bs.ctx_size = 1; /* 512B */
	db->dw0.bs.cp_flag = 0;
	db->dw0.bs.cos = roce3_get_db_cos_from_vlan_pri(rdev, qp->sl & 0x7);
	db->dw0.bs.type = ROCE_SQ_DB_TYPE;

	db->dw1.bs.pi = ((index & 0xffff) >> 8) & 0xff; /* 8bits */
	db->dw1.bs.sub_type = 0;
	db->dw1.bs.mtu_shift = qp->db_path_mtu;
	db->dw1.bs.sgid_index = qp->db_sgid_index;
	if (qp->qp_type != IB_QPT_RC) {
		if (qp->qp_type == IB_QPT_UD || qp->qp_type == IB_QPT_GSI)
			db->dw1.bs.mtu_shift = ROCE_UD_MTU_SHIFT;
		else if (qp->qp_type == IB_QPT_XRC_INI || qp->qp_type == IB_QPT_XRC_TGT)
			db->dw1.bs.xrc_vld = 1;
	}

	db->dw0.value = roce3_convert_be32(db->dw0.value);
	db->dw1.value = roce3_convert_be32(db->dw1.value);
}

static void roce3_set_inline_data(void *start_addr, struct ib_sge *sge)
{
	memcpy(start_addr, (void *)(uintptr_t)sge->addr, sge->length);
}

static void roce3_set_inline_data_cycle1(void *start_addr, struct ib_sge *sge, u32 size)
{
	memcpy(start_addr, (void *)(uintptr_t)sge->addr, size);
}

static void roce3_set_inline_data_cycle2(void *start_addr, struct ib_sge *sge, u32 size)
{
	memcpy(start_addr, (void *)((u8 *)(void *)(uintptr_t)sge->addr + size), size);
}

/*
 ****************************************************************************
 Prototype	: roce3_dwqe_copy
 Description  : roce3_dwqe_copy
 Input		: unsigned long *dst
				unsigned long *src
				unsigned int bytecnt
 Output	   : None

  1.Date		 : 2015/5/26
	Modification : Created function

****************************************************************************
*/
/*
 * Avoid using memcpy() to copy to DWQE Page, since memcpy()
 * implementations may use move-string-buffer assembler instructions,
 * which do not guarantee order of copying.
 * Assume that the DWQE page header address is VA, the WQE size is size, and the WQE address is wqe
	size=64,  iowrite64_copy(va + 256, wqe, size)
	size=128, iowrite64_copy(va + 256*2, wqe, size)
	size=192, iowrite64_copy(va + 256*3, wqe, size)
	The current chip supports this function, but the software wqe_size is aligned by
	the power of 2. Therefore, this function is not used and can be ignored.
	size=256, __iowrite64_copy(va, wqe, size)

	formula:
	__iowrite64_copy(va + ((size & 255) << 2), wqe, size)
 */
static void roce3_dwqe_copy(unsigned long *dst, unsigned long *src, unsigned int bytecnt)
{
	unsigned long *src_tmp = src;
	unsigned int bytecnt_tmp = bytecnt;
	unsigned long *dst_tmp = (unsigned long *)(
		(u64)dst + ((bytecnt_tmp & BYTE_MASK) << 2)); // 2 is addr offset

	while ((int)bytecnt_tmp > 0) {
		wmb();	/* Sequential write memory barrier */
		*dst_tmp++ = *src_tmp++;
		bytecnt_tmp -= (unsigned int)sizeof(u64);
	}
}

/*
 ****************************************************************************
 Prototype	: roce3_set_gsi_seg
 Input		: struct roce3_sqp *sqp
				struct ib_send_wr *wr
				void *wqe
 Output	   : None

  1.Date		 : 2015/8/27
	Modification : Created function

****************************************************************************
*/
static void roce3_set_gsi_seg(struct roce3_sqp *sqp, const struct ib_send_wr *wr, void *wqe)
{
	struct roce3_wqe_ud_tsk_seg *ud_tsk_seg = (struct roce3_wqe_ud_tsk_seg *)wqe;
	struct ib_ud_wr *ud_wr = (struct ib_ud_wr *)(void *)wr;
	struct roce3_ah *rah = to_roce3_ah(ud_wr->ah);

	if (wr->opcode == IB_WR_SEND_WITH_IMM) {
		ud_tsk_seg->immdata_invkey = wr->ex.imm_data;
		ud_tsk_seg->dw2.bs.last_ext_len = ROCE_IMM_EXT_LEN;
		ud_tsk_seg->dw2.value = cpu_to_be32(ud_tsk_seg->dw2.value);
	}

	ud_tsk_seg->common.bs.c = 1;
	ud_tsk_seg->dw3.value = rah->priv_ah.dw0.value;
	ud_tsk_seg->dw4.value = rah->priv_ah.dw1.value;
	ud_tsk_seg->dw5.value = rah->priv_ah.dw2.value;
	memcpy((void *)ud_tsk_seg->dgid, (void *)rah->priv_ah.dgid,
		sizeof(ud_tsk_seg->dgid));
	ud_tsk_seg->dw10.value = cpu_to_be32(ud_wr->remote_qpn);
	ud_tsk_seg->qkey = cpu_to_be32(((ud_wr->remote_qkey & 0x80000000) != 0) ?
		sqp->qkey : ud_wr->remote_qkey);
	ud_tsk_seg->dw12.value = rah->priv_ah.dw7.value;
	ud_tsk_seg->dmac_l32 = rah->priv_ah.dmac_l32;
}

/*
 ****************************************************************************
 Prototype	: write_invalid_wqe
 Description  : set the next wqe invalidate
 Input		: struct roce3_qp *qp
				u32 index
 Output	   : None

  1.Date		 : 2015/9/8
	Modification : Created function

****************************************************************************
*/
static void write_invalid_wqe(struct roce3_qp *qp, u32 index)
{
	u32 invalid_wqe_dw0 = 0;
	struct roce3_wqe_ctrl_seg *ctrl_seg = NULL;

	ctrl_seg = (struct roce3_wqe_ctrl_seg *)roce3_get_send_wqe(qp, index);
	invalid_wqe_dw0 = ((index & (u32)qp->sq.wqebb_cnt) == 0) ? 0xff000000 : 0x7f000000;
	ctrl_seg->dw0.value = cpu_to_be32(invalid_wqe_dw0);
}

/*
 ****************************************************************************
 Prototype	: roce3_validate_wr
 Description  : roce3_validate_wr
 Input		: struct roce3_qp *rqp
				struct ib_send_wr *wr
				int wr_num
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static int roce3_validate_wr(struct roce3_qp *rqp, const struct ib_send_wr *wr, u32 wr_num)
{
#define IB_WR_REG_SIG_MR IB_WR_REG_MR_INTEGRITY
	if (roce3_wq_overflow(&rqp->sq, wr_num, rqp->ibqp.send_cq) != 0) {
		pr_err("[ROCE] %s: SQ is full\n", __func__);
		return -ENOMEM;
	}

	if (ROCE_UNLIKELY(((u32)wr->num_sge) > rqp->sq.max_sge)) {
		pr_err("[ROCE, ERR] %s: Sge num is invalid, wr->num_sge(%d), rqp->sq.max_sge(%d)\n",
			__func__, wr->num_sge, rqp->sq.max_sge);
		return -EINVAL;
	}

	if (ROCE_UNLIKELY((wr->opcode == IB_WR_LSO) || (wr->opcode > IB_WR_REG_SIG_MR))) {
		pr_err("[ROCE, ERR] %s: wr->opcode(%d)\n", __func__, wr->opcode);
		return -EINVAL;
	}

	return 0;
}

static void roce3_set_rc_wqe_for_optype_send(const struct ib_send_wr *wr,
	struct roce3_post_send_normal_param *param)
{
	param->ctrl_seg_tmp.dw0.bs.tsl = ROCE_SEND_LOCAL_WQE_TSL;
	param->ctrl_seg_tmp.dw1.bs.cl = 1;
	roce3_set_send_seg((struct roce3_wqe_send_tsk_seg *)param->wqe, wr);
	param->data_len_addr = &((struct roce3_wqe_send_tsk_seg *)param->wqe)->data_len;
	param->wqe = ((u8 *)param->wqe + sizeof(struct roce3_wqe_send_tsk_seg));
	param->wqe_size += (u32)sizeof(struct roce3_wqe_send_tsk_seg);
}

static void roce3_set_rc_wqe_for_optype_atomic(const struct ib_send_wr *wr,
	struct roce3_post_send_normal_param *param)
{
	param->ctrl_seg_tmp.dw0.bs.tsl = ROCE_RDMA_WQE_TSL;
	param->ctrl_seg_tmp.dw1.bs.cl = 1;
	roce3_set_atomic_seg((struct roce3_wqe_atomic_tsk_seg *)param->wqe, wr);
	param->wqe = ((u8 *)param->wqe + sizeof(struct roce3_wqe_atomic_tsk_seg));
	param->wqe_size += (u32)sizeof(struct roce3_wqe_atomic_tsk_seg);
}

static void roce3_set_rc_wqe_for_optype_cmp_and_swap(const struct ib_send_wr *wr,
	struct roce3_post_send_normal_param *param)
{
	param->ctrl_seg_tmp.dw0.bs.tsl = ROCE_ATOMIC_CWP_WQE_TSL;
	param->ctrl_seg_tmp.dw1.bs.cl = 1;
	roce3_set_masked_atomic_seg((struct roce3_wqe_mask_atomic_tsk_seg *)param->wqe, wr);
	param->wqe = ((u8 *)param->wqe + sizeof(struct roce3_wqe_mask_atomic_tsk_seg));
	param->wqe_size += (u32)sizeof(struct roce3_wqe_atomic_tsk_seg);
}

static void roce3_set_rc_wqe_for_optype_write(const struct ib_send_wr *wr,
	struct roce3_post_send_normal_param *param)
{
	param->ctrl_seg_tmp.dw0.bs.tsl = ROCE_RDMA_WQE_TSL;
	param->ctrl_seg_tmp.dw1.bs.cl = 1;
	roce3_set_rdma_seg((struct roce3_wqe_rdma_tsk_seg *)param->wqe, wr);
	param->data_len_addr = &((struct roce3_wqe_rdma_tsk_seg *)param->wqe)->data_len;
	param->wqe = ((u8 *)param->wqe + sizeof(struct roce3_wqe_rdma_tsk_seg));
	param->wqe_size += (u32)(sizeof(struct roce3_wqe_rdma_tsk_seg));
}

static void roce3_set_rc_wqe_for_optype_local(const struct ib_send_wr *wr,
	struct roce3_post_send_normal_param *param)
{
	param->ctrl_seg_tmp.dw0.bs.tsl = ROCE_SEND_LOCAL_WQE_TSL;
	param->ctrl_seg_tmp.dw1.bs.cl = 1;
	param->tsk_com_seg->bs.so = 1;
	roce3_set_local_inv_seg((struct roce3_wqe_local_inv_tsk_seg *)param->wqe, wr);
	param->wqe_size += (u32)sizeof(struct roce3_wqe_local_inv_tsk_seg);
	param->inline_flag = 0;
	param->ctrl_seg_tmp.dw0.bs.df = 0;
}

static void roce3_set_wqe_last_len(u8 *wqe)
{
	struct roce3_wqe_send_tsk_seg *snd_task = (struct roce3_wqe_send_tsk_seg *)(void *)wqe;

	snd_task->dw3.value = 0;
	snd_task->dw3.bs.last_ext_len = ROCE_IMM_EXT_LEN;
	snd_task->dw3.value = cpu_to_be32(snd_task->dw3.value);
}

static inline u32 roce3_log2(u32 x)
{
	u32 shift;

	for (shift = 0; (1U << shift) < x; ++shift)
		;

	return shift;
}

static int set_frmr_wqe_section(const struct ib_send_wr *wr,
	struct roce3_post_send_normal_param *param)
{
	u64 iova;
	u32 fbo;
	u32 page_num;
	struct ib_reg_wr *frmr_reg_wr = NULL;
	struct roce3_mr *roce3_kernel_frmr = NULL;
	struct roce3_wqe_frmr_tsk_seg *frmr_wqe_task = NULL;

	frmr_reg_wr = (struct ib_reg_wr *)reg_wr(wr); //lint !e605

	roce3_kernel_frmr = to_roce3_mr(frmr_reg_wr->mr);
	page_num = (u32)((frmr_reg_wr->mr->length +
		frmr_reg_wr->mr->page_size - 1) / frmr_reg_wr->mr->page_size);
	if (page_num > ROCE_FRMR_MAX_PAGES)
		return -EINVAL;

	/* base section set */
	param->wqe_size += sizeof(struct roce3_wqe_frmr_tsk_seg);

	frmr_wqe_task = (struct roce3_wqe_frmr_tsk_seg *)((void *)param->tsk_com_seg);

	param->dseg = (struct roce3_wqe_data_seg *)
		(((u8 *)param->tsk_com_seg) + sizeof(struct roce3_wqe_frmr_tsk_seg));

	param->ctrl_seg_tmp.dw0.bs.tsl =
		sizeof(struct roce3_wqe_frmr_tsk_seg) / ROCE_TASK_SEG_ALIGN;
	/* fill wqe ctrl head section:cl bit */
	param->ctrl_seg_tmp.dw1.bs.cl = 1; //lint !e572  !e778 !e845

	/* local invalidate associated section set */
	param->tsk_com_seg->bs.so = 1;

	iova = (u64)(void *)(frmr_reg_wr->mr->iova);
	fbo = (u32)(iova & (FRMR_PAGE_SIZE - 1));
	frmr_wqe_task->dw2.bs.fbo = fbo & 0x3FFFFF;
	frmr_wqe_task->dw2.value = cpu_to_be32(frmr_wqe_task->dw2.value);

	frmr_wqe_task->dw5.va = ((u32)frmr_reg_wr->access & IB_ZERO_BASED) ? 0 : cpu_to_be64(iova);

	/* 填写访问权限 */
	frmr_wqe_task->dw3.bs.zbva = (u32)(!!((u32)frmr_reg_wr->access & IB_ZERO_BASED));
	/* 绑定操作使能 */
	frmr_wqe_task->dw3.bs.be = (u32)(!!((u32)frmr_reg_wr->access & IB_ACCESS_MW_BIND));
	/* 本地读使能 */
	frmr_wqe_task->dw3.bs.lre = 1;
	/* 本地写使能 */
	frmr_wqe_task->dw3.bs.lwe = (u32)(!!((u32)frmr_reg_wr->access & IB_ACCESS_LOCAL_WRITE));
	/* 远端读使能 */
	frmr_wqe_task->dw3.bs.rre = (u32)(!!((u32)frmr_reg_wr->access & IB_ACCESS_REMOTE_READ));
	/* 远端写使能 */
	frmr_wqe_task->dw3.bs.rwe = (u32)(!!((u32)frmr_reg_wr->access & IB_ACCESS_REMOTE_WRITE));
	 /* 远端Atomic使能 */
	frmr_wqe_task->dw3.bs.rae = (u32)(!!((u32)frmr_reg_wr->access & IB_ACCESS_REMOTE_ATOMIC));
	frmr_wqe_task->dw3.bs.block = 1;
	frmr_wqe_task->dw3.bs.rsvd = 0;
	frmr_wqe_task->dw3.bs.pa_num = page_num;
	/* MR内存页大小。equals to (2^page_size)*4KB */
	frmr_wqe_task->dw3.bs.page_size = roce3_log2(frmr_reg_wr->mr->page_size) - PAGE_4K_SHIFT;
	frmr_wqe_task->dw3.value = cpu_to_be32(frmr_wqe_task->dw3.value);

	frmr_wqe_task->m_key = cpu_to_be32(frmr_reg_wr->key);
	frmr_wqe_task->dw7.len = cpu_to_be64(frmr_reg_wr->mr->length);
	frmr_wqe_task->dw9.pbl_addr = cpu_to_be64(roce3_kernel_frmr->page_map);
	/* set inline and direct wqe handle section */
	frmr_wqe_task->rsvd[0] = 0;
	frmr_wqe_task->rsvd[1] = 0;

	param->inline_flag = 0;

	return 0;
}


static int roce3_post_send_rc(struct roce3_post_send_normal_param *param, struct roce3_device *rdev,
	const struct ib_send_wr *wr)
{
	int ret = 0;

	switch (wr->opcode) {
	case IB_WR_SEND_WITH_IMM:
	case IB_WR_SEND_WITH_INV:
		roce3_set_wqe_last_len(param->wqe);
		roce3_set_rc_wqe_for_optype_send(wr, param);
		break;
	case IB_WR_SEND:
		roce3_set_rc_wqe_for_optype_send(wr, param);
		break;

	case IB_WR_ATOMIC_CMP_AND_SWP:
	case IB_WR_ATOMIC_FETCH_AND_ADD:
	case IB_WR_MASKED_ATOMIC_FETCH_AND_ADD:
		roce3_set_rc_wqe_for_optype_atomic(wr, param);
		break;

	case IB_WR_MASKED_ATOMIC_CMP_AND_SWP:
		roce3_set_rc_wqe_for_optype_cmp_and_swap(wr, param);
		break;

	case IB_WR_RDMA_WRITE_WITH_IMM:
		roce3_set_wqe_last_len(param->wqe);
		roce3_set_rc_wqe_for_optype_write(wr, param);
		break;

	case IB_WR_RDMA_READ:
	case IB_WR_RDMA_WRITE:
		roce3_set_rc_wqe_for_optype_write(wr, param);
		break;

	case IB_WR_LOCAL_INV:
		roce3_set_rc_wqe_for_optype_local(wr, param);
		ret = ROCE_NEED_JUMP;
		break;

	case IB_WR_REG_MR:
		set_frmr_wqe_section(wr, param);
		ret = ROCE_NEED_JUMP;
		break;

	default:
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Invalid opcode, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		break;
	}

	return ret;
}

static int roce3_post_send_uc(struct roce3_post_send_normal_param *param, struct roce3_device *rdev,
	const struct ib_send_wr *wr)
{
	switch (wr->opcode) {
	case IB_WR_SEND_WITH_IMM:
	case IB_WR_SEND:
		if (wr->opcode == IB_WR_SEND_WITH_IMM)
			roce3_set_wqe_last_len(param->wqe);

		param->ctrl_seg_tmp.dw0.bs.tsl = ROCE_SEND_LOCAL_WQE_TSL;
		param->ctrl_seg_tmp.dw1.bs.cl = 1;
		roce3_set_send_seg((struct roce3_wqe_send_tsk_seg *)param->wqe, wr);
		param->data_len_addr = &((struct roce3_wqe_send_tsk_seg *)param->wqe)->data_len;
		param->wqe = ((u8 *)param->wqe + sizeof(struct roce3_wqe_send_tsk_seg));
		param->wqe_size += (u32)sizeof(struct roce3_wqe_send_tsk_seg);
		break;

	case IB_WR_RDMA_WRITE_WITH_IMM:
	case IB_WR_RDMA_WRITE:
		if (wr->opcode == IB_WR_RDMA_WRITE_WITH_IMM)
			roce3_set_wqe_last_len(param->wqe);

		param->ctrl_seg_tmp.dw0.bs.tsl = ROCE_RDMA_WQE_TSL;
		param->ctrl_seg_tmp.dw1.bs.cl = 1;
		roce3_set_rdma_seg((struct roce3_wqe_rdma_tsk_seg *)param->wqe, wr);
		param->data_len_addr = &((struct roce3_wqe_rdma_tsk_seg *)param->wqe)->data_len;
		param->wqe = ((u8 *)param->wqe + sizeof(struct roce3_wqe_rdma_tsk_seg));
		param->wqe_size += (u32)sizeof(struct roce3_wqe_rdma_tsk_seg);
		break;

	case IB_WR_LOCAL_INV:
		param->ctrl_seg_tmp.dw0.bs.tsl = ROCE_SEND_LOCAL_WQE_TSL;
		param->ctrl_seg_tmp.dw1.bs.cl = 1;
		param->tsk_com_seg->bs.so = 1;
		roce3_set_local_inv_seg((struct roce3_wqe_local_inv_tsk_seg *)param->wqe, wr);
		param->wqe_size += (u32)sizeof(struct roce3_wqe_local_inv_tsk_seg);
		return ROCE_NEED_JUMP;

	default:
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Invalid opcode, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		break;
	}

	return 0;
}

static int roce3_post_send_ud(struct roce3_post_send_normal_param *param, struct roce3_device *rdev,
	struct roce3_qp *rqp, const struct ib_send_wr *wr, const struct ib_send_wr **bad_wr)
{
	struct roce3_wqe_ud_tsk_seg *tsk_sg = (struct roce3_wqe_ud_tsk_seg *)param->wqe;

	if (ROCE_UNLIKELY((wr->opcode != IB_WR_SEND) && (wr->opcode != IB_WR_SEND_WITH_IMM))) {
		// ret = -EINVAL;
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Wr->opcode(%d), func_id(%d)\n",
			__func__, wr->opcode, rdev->glb_func_id);
		*bad_wr = wr;
		return ROCE_NEED_JUMP;
	}

	if (wr->opcode == IB_WR_SEND_WITH_IMM) {
		tsk_sg->dw2.bs.last_ext_len = ROCE_IMM_EXT_LEN;
		tsk_sg->dw2.value = cpu_to_be32(tsk_sg->dw2.value);
	}

	param->ctrl_seg_tmp.dw0.bs.tsl = ROCE_UD_WQE_COM_TSL;
	param->ctrl_seg_tmp.dw1.bs.cl = 1;
	param->data_len_addr = &((struct roce3_wqe_ud_tsk_seg *)param->wqe)->data_len;

	if (param->sq_rmd_size > (1UL << (unsigned int)rqp->sq.wqe_shift)) {
		roce3_set_ud_seg((struct roce3_wqe_ud_tsk_seg *)(param->wqe), wr);
		param->wqe = ((u8 *)param->wqe + sizeof(struct roce3_wqe_ud_tsk_seg));
		param->wqe_size += (u32)sizeof(struct roce3_wqe_ud_tsk_seg);
	} else {
		roce3_set_ud_seg_cycle1((struct roce3_wqe_ud_tsk_seg_cycle1 *)param->wqe, wr);
		param->wqe = rqp->sq_head_addr;
		param->wqe_size += (u32)sizeof(struct roce3_wqe_ud_tsk_seg_cycle1);
		roce3_set_ud_seg_cycle2((struct roce3_wqe_ud_tsk_seg_cycle2 *)param->wqe, wr);
		param->wqe = ((u8 *)param->wqe + sizeof(struct roce3_wqe_ud_tsk_seg_cycle2));
		param->wqe_size += (u32)sizeof(struct roce3_wqe_ud_tsk_seg_cycle2);
	}

	return 0;
}

static void roce3_post_send_set_normal_data_seg(const struct ib_send_wr *wr,
	struct roce3_wqe_data_seg **dseg, struct roce3_qp *rqp)
{
	if (wr->num_sge != 0) {
		if ((u8 *)(*dseg) == rqp->sq_head_addr) {
			*dseg = (struct roce3_wqe_data_seg *)(
				(void *)(rqp->sq_tail_addr - sizeof(struct roce3_wqe_data_seg)));
		} else {
			(*dseg)--;
		}
		(*dseg)->key = (u32)wr->sg_list[wr->num_sge - 1].lkey | ROCE_WQE_NEXT_SGE_INVALID;
		(*dseg)->key = cpu_to_be32((*dseg)->key);
	}
}

static int roce3_post_send_set_normal_sge(struct roce3_post_send_normal_param *param,
	struct roce3_device *rdev, struct roce3_qp *rqp,
	const struct ib_send_wr *wr, const struct ib_send_wr **bad_wr)
{
	int i;

	param->data_len = 0;
	param->dseg = (struct roce3_wqe_data_seg *)param->wqe;
	param->wqe_size += (u32)(wr->num_sge * (int)sizeof(struct roce3_wqe_data_seg));
	for (i = 0; i < wr->num_sge; ++i) {
		if (param->sq_rmd_size < sizeof(struct roce3_wqe_data_seg))
			param->dseg = (struct roce3_wqe_data_seg *)((void *)rqp->sq_head_addr);

		if (ROCE_UNLIKELY(wr->sg_list[i].length >
			(rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_msg_sz))) {
			*bad_wr = wr;
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Sge_data length is over range, sg_list(%d), length(0x%x), max_msg_sz(0x%x), func_id(%d)\n",
				__func__, i, wr->sg_list[i].length,
				rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_msg_sz,
				rdev->glb_func_id);
			return ROCE_NEED_JUMP;
		}

		param->data_len += wr->sg_list[i].length;
		if (ROCE_UNLIKELY(param->data_len >
			rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_msg_sz)) {
			*bad_wr = wr;
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Data len is over range, data_len(%d), max_msg_sz(%d), func_id(%d)\n",
				__func__, param->data_len,
				rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_msg_sz,
				rdev->glb_func_id);
			return ROCE_NEED_JUMP;
		}
		roce3_set_data_seg(param->dseg, wr->sg_list + i);

		(param->dseg)++;
		param->sq_rmd_size = (u32)(rqp->sq_tail_addr - (u8 *)param->dseg);
	}

	return 0;
}

static void roce3_copy_inline_data(struct roce3_post_send_normal_param *param,
	const struct ib_send_wr *wr, struct roce3_qp *rqp, int i)
{
	if (param->sq_rmd_size >= wr->sg_list[i].length) {
		roce3_set_inline_data(param->wqe, wr->sg_list + i);
		param->wqe = ((u8 *)param->wqe + wr->sg_list[i].length);
		if ((u8 *)param->wqe == rqp->sq_tail_addr)
			param->wqe = rqp->sq_head_addr;
	} else {
		roce3_set_inline_data_cycle1(param->wqe, wr->sg_list + i, param->sq_rmd_size);
		param->wqe = rqp->sq_head_addr;

		roce3_set_inline_data_cycle2(param->wqe, wr->sg_list + i,
			wr->sg_list[i].length - param->sq_rmd_size);
		param->wqe = ((u8 *)param->wqe + wr->sg_list[i].length - param->sq_rmd_size);

		param->cycle = 1;
	}
}

static int roce3_post_send_set_data_seg(struct roce3_post_send_normal_param *param,
	struct roce3_device *rdev, struct roce3_qp *rqp,
	const struct ib_send_wr *wr, const struct ib_send_wr **bad_wr)
{
	int i;
	int ret;

	if ((((unsigned int)wr->send_flags & (unsigned int)IB_SEND_INLINE) != 0) &&
		(wr->num_sge != 0) && (param->inline_flag != 0)) {
		param->data_len = 0;

		for (i = 0; i < wr->num_sge; ++i) {
			param->wqe_size += wr->sg_list[i].length;
			param->data_len += wr->sg_list[i].length;
			if (param->data_len > rqp->max_inline_data) {
				*bad_wr = wr;
				dev_err(rdev->hwdev_hdl,
					"[ROCE, ERR] %s: Data len is too big, data_len(%d), max_inline_data(%d), func_id(%d)\n",
					__func__, param->data_len,
					rqp->max_inline_data, rdev->glb_func_id);
				return ROCE_NEED_JUMP;
			}

			if ((u8 *)param->wqe == rqp->sq_head_addr)
				param->cycle = 1;

			roce3_copy_inline_data(param, wr, rqp, i);

			param->sq_rmd_size = (u32)(rqp->sq_tail_addr - (u8 *)param->wqe);
		}
		param->ctrl_seg_tmp.dw0.bs.bdsl =
			(ALIGN((u32)(param->data_len), ROCE_TASK_SEG_ALIGN) /
			ROCE_TASK_SEG_ALIGN) & 0x7ff;
		param->ctrl_seg_tmp.dw0.bs.df = 1;
		param->inline_flag = 1;
	} else {
		ret = roce3_post_send_set_normal_sge(param, rdev, rqp, wr, bad_wr);
		if (ret != 0)
			return ret;

		roce3_post_send_set_normal_data_seg(wr, &param->dseg, rqp);

		param->ctrl_seg_tmp.dw0.bs.bdsl =
			(u32)((wr->num_sge * (int)sizeof(struct roce3_wqe_data_seg)) /
			ROCE_TASK_SEG_ALIGN) & 0x7ff;
		param->ctrl_seg_tmp.dw0.bs.df = 0;
	}

	return 0;
}

static int roce3_post_send_ring_db(struct roce3_post_send_normal_param *param,
	struct roce3_device *rdev, struct roce3_qp *rqp)
{
	int ret = 0;

	if ((rdev->kernel_dwqe_map != NULL) && (param->wr_num == 1) && (param->inline_flag != 0) &&
		(param->wqe_size > (u32)sizeof(struct roce3_wqe_ctrl_seg)) &&
		((int)param->wqe_size <= rqp->max_dwqe_size) &&
		(param->cycle == 0)) {
		wmb();	/* Ring db memory barrier */

		param->ctrl_seg->dw1.value = be32_to_cpu(param->ctrl_seg->dw1.value);
		param->ctrl_seg->dw1.bs.mask_pi =
			(u32)((param->index & ((unsigned int)rqp->sq.wqebb_cnt - 1)) & 0xfffff);

		roce3_set_dwqe_db(rqp, param->ctrl_seg, param->index);

		param->wqe_size = ALIGN((u32)param->wqe_size, ROCE_SQ_WQEBB_SIZE);

		*(rqp->db.db_record) = cpu_to_be32(param->index);

		wmb();	/* Ring db memory barrier */

		++rqp->sq.head;
		roce3_dwqe_copy((unsigned long *)rdev->kernel_dwqe_map,
			(unsigned long *)param->ctrl_seg, (u32)param->wqe_size);
		wc_wmb();	/* Ring db memory barrier */
	} else if (param->wr_num != 0) {
		rqp->sq.head += param->wr_num;

		wmb();	/* Ring db memory barrier */

		memset(&(param->sq_db.sq_db_val), 0, sizeof(u64));
		roce3_set_sq_db(rqp, &(param->sq_db.sq_db_seg), param->index);

		*(rqp->db.db_record) = cpu_to_be32(param->index & 0xffff);

		wmb();	/* Ring db memory barrier */
		ret = cqm_ring_hardware_db(rdev->hwdev, SERVICE_T_ROCE,
			param->index & 0xff, param->sq_db.sq_db_val);
		wmb();	/* Ring db memory barrier */
	}

	return ret;
}

static void roce3_fill_task_data_len(u32 *data_len_addr, u32 data_len)
{
	if (data_len_addr)
		*data_len_addr = cpu_to_be32(data_len);
}

static int roce3_construct_wqe(struct roce3_post_send_normal_param *param,
	struct roce3_device *rdev, struct roce3_qp *rqp,
	const struct ib_send_wr *wr, const struct ib_send_wr **bad_wr)
{
	int need_goto = 0;

	switch (rqp->qp_type) {
	case IB_QPT_RC:
		need_goto = roce3_post_send_rc(param, rdev, wr);
		if (need_goto == ROCE_NEED_JUMP)
			return GOTO_LOCAL;
		break;

	case IB_QPT_UC:
		need_goto = roce3_post_send_uc(param, rdev, wr);
		if (need_goto == ROCE_NEED_JUMP)
			return GOTO_LOCAL;
		break;

	case IB_QPT_UD:
		need_goto = roce3_post_send_ud(param, rdev, rqp, wr, bad_wr);
		if (need_goto == ROCE_NEED_JUMP) {
			// ret = -EINVAL;
			return GOTO_OUT;
		}
		break;

	case IB_QPT_GSI:
		param->ctrl_seg_tmp.dw0.bs.tsl = ROCE_UD_WQE_COM_TSL;
		param->ctrl_seg_tmp.dw1.bs.cl = 1;

		roce3_set_gsi_seg(to_roce3_sqp(rqp), wr, param->wqe);

		param->data_len_addr = &((struct roce3_wqe_ud_tsk_seg *)param->wqe)->data_len;
		param->wqe = ((u8 *)param->wqe + sizeof(struct roce3_wqe_ud_tsk_seg));
		param->wqe_size += (u32)sizeof(struct roce3_wqe_ud_tsk_seg);
		break;

	default:
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Unknown qp type, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		break;
	}

	return 0;
}

static void roce3_init_ctrl_seg(struct roce3_post_send_normal_param *param,
	const struct ib_send_wr *wr, const struct roce3_qp *rqp)
{
	param->ctrl_seg_tmp.dw0.bs.owner = ((param->index & (u32)rqp->sq.wqebb_cnt) != 0) ? 1 : 0;
	param->ctrl_seg_tmp.dw0.bs.drvsl = 0;
	param->ctrl_seg_tmp.dw0.bs.wf = 0;
	param->ctrl_seg_tmp.dw0.bs.cf = 0;
	param->ctrl_seg_tmp.dw0.bs.va = 1;
	param->ctrl_seg_tmp.dw0.bs.df = 0; /* va:1bits, 0-sge,1-inline */
	param->ctrl_seg_tmp.dw0.bs.cr =
		(u32)(!(((((u32)wr->send_flags) & IB_SEND_SIGNALED) | rqp->sq_signal_bits) == 0));
	param->ctrl_seg_tmp.dw0.bs.difsl = 0;
	param->ctrl_seg_tmp.dw0.bs.csl = 0;
	param->ctrl_seg_tmp.dw0.bs.ctrlsl = ROCE_CTRL_SEG_SL;
	param->ctrl_seg_tmp.dw0.bs.bdsl = 0;
}

static void roce3_init_task_com_seg(union roce3_wqe_tsk_com_seg **tsk_com_seg, u8 *wqe,
	const struct ib_send_wr *wr, const struct roce3_qp *rqp)
{
	*tsk_com_seg = (union roce3_wqe_tsk_com_seg *)(void *)wqe;

	(*tsk_com_seg)->bs.c =
		(u32)(!((((unsigned int)wr->send_flags &
		(unsigned int)IB_SEND_SIGNALED) | rqp->sq_signal_bits) == 0));
	(*tsk_com_seg)->bs.se =
		(u32)(!(((unsigned int)wr->send_flags & (unsigned int)IB_SEND_SOLICITED) == 0));
	(*tsk_com_seg)->bs.f = (u32)(!(((unsigned int)wr->send_flags &
		(unsigned int)IB_SEND_FENCE) == 0));
	(*tsk_com_seg)->bs.op_type = roce3_ib_opcode[wr->opcode] & 0x1f;
	if (wr->opcode == IB_WR_REG_MR)
		(*tsk_com_seg)->bs.op_type = ROCE_WQE_OPCODE_FRMR;
}

static void roce3_post_send_local_operation(struct roce3_post_send_normal_param *param,
	struct roce3_qp *rqp, struct roce3_device *rdev)
{
	param->opcode = param->tsk_com_seg->bs.op_type;
	param->tsk_com_seg->value = cpu_to_be32(param->tsk_com_seg->value);
	param->ctrl_seg->dw1.value = cpu_to_be32(param->ctrl_seg_tmp.dw1.value);
	param->index += (u32)DIV_ROUND_UP(param->wqe_size, 1U << (u32)rqp->sq.wqe_shift);

	write_invalid_wqe(rqp, param->index);

	/*
	 * Make sure descriptor is fully written before
	 * setting ownership bit (because HW can start
	 * executing as soon as we do).
	 */
	wmb();

	param->ctrl_seg->dw0.value = cpu_to_be32(param->ctrl_seg_tmp.dw0.value);
}
/*
 ****************************************************************************
 Prototype	: roce3_post_send_normal
 Description  : roce3_post_send_normal
 Input		: struct roce3_device *rdev
				struct roce3_qp *rqp
				struct ib_send_wr *wr
				struct ib_send_wr **bad_wr
 Output	   : None

  1.Date		 : 2015/4/29
	Modification : Created function

  2.Date		 : 2015/8/8
	Modification : Modify function

****************************************************************************
*/
static int roce3_post_send_normal(struct roce3_device *rdev, struct roce3_qp *rqp,
	const struct ib_send_wr *wr, const struct ib_send_wr **bad_wr)
{
	int need_goto = 0;
	int ret = 0;
	struct roce3_post_send_normal_param param = { 0 };
	const struct ib_send_wr *wr_tmp = wr;

	spin_lock_irqsave(&rqp->sq.lock, param.flags);

	param.index = rqp->sq_next_wqe;

	for (param.wr_num = 0; wr_tmp != NULL; ++(param.wr_num), wr_tmp = wr_tmp->next) {
		ret = roce3_validate_wr(rqp, wr_tmp, param.wr_num);
		if (ret != 0) {
			*bad_wr = wr_tmp;
			pr_err("[ROCE, ERR] %s: Failed to validate wr, func(%d) qpn(%u)\n",
				__func__, rdev->glb_func_id, rqp->qpn);
			goto out;
		}

		param.wqe = (u8 *)roce3_get_send_wqe(rqp, param.index);
		param.ctrl_seg = (struct roce3_wqe_ctrl_seg *)param.wqe;

		param.sq_rmd_size = (u32)(rqp->sq_tail_addr - (u8 *)param.wqe);

		rqp->sq.wrid[(rqp->sq.head + param.wr_num) &
			(u32)(rqp->sq.wqebb_cnt - 1)] = wr_tmp->wr_id;

		roce3_init_ctrl_seg(&param, wr_tmp, rqp);

		param.wqe = ((u8 *)param.wqe + sizeof(*(param.ctrl_seg)));
		param.wqe_size = (u32)sizeof(*param.ctrl_seg);
		roce3_init_task_com_seg(&param.tsk_com_seg, param.wqe, wr_tmp, rqp);

		ret = roce3_construct_wqe(&param, rdev, rqp, wr_tmp, bad_wr);
		if (ret == GOTO_LOCAL) {
			ret = 0;
			goto local;
		} else if (ret == GOTO_OUT) {
			ret = -EINVAL;
			goto out;
		}

		param.sq_rmd_size = (u32)(rqp->sq_tail_addr - (u8 *)param.wqe);

		need_goto = roce3_post_send_set_data_seg(&param, rdev, rqp, wr_tmp, bad_wr);
		if (need_goto == ROCE_NEED_JUMP) {
			ret = -EINVAL;
			goto out;
		}

		roce3_fill_task_data_len(param.data_len_addr, param.data_len);

local:
		roce3_post_send_local_operation(&param, rqp, rdev);
	}

out:

	ret = roce3_post_send_ring_db(&param, rdev, rqp);

	if (ROCE_LIKELY(param.wr_num != 0))
		rqp->sq_next_wqe = param.index;

	spin_unlock_irqrestore(&rqp->sq.lock, param.flags);

	return ret;
}

static int roce3_post_send_check_qp_type(const struct roce3_qp *rqp)
{
	if (ROCE_UNLIKELY(rqp->qp_type == IB_QPT_XRC_TGT)) {
		pr_err("[ROCE, ERR] %s: Can't post WQE when TGT XRC QP\n", __func__);
		return -EINVAL;
	}

	if (ROCE_UNLIKELY(rqp->qp_type == IB_QPT_XRC_INI)) {
		pr_err("[ROCE, ERR] %s: not support xrc in kernel space\n", __func__);
		return -EINVAL;
	}

	if (ROCE_UNLIKELY((rqp->qp_state == IB_QPS_RESET) || (rqp->qp_state == IB_QPS_INIT) ||
		(rqp->qp_state == IB_QPS_RTR))) {
		pr_err("[ROCE, ERR] %s: Can't post WQE when QP is RST/INIT/RTR state\n", __func__);
		return -EINVAL;
	}

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_post_send
 Description  : roce3_post_send
 Input		: struct ib_qp *ibqp
				struct ib_send_wr *wr
				const struct ib_send_wr **bad_wr
 Output	   : None
****************************************************************************
*/
int roce3_post_send_standard(struct ib_qp *ibqp, const struct ib_send_wr *wr,
	const struct ib_send_wr **bad_wr)
{
	int ret = 0;
	struct roce3_qp *rqp = to_roce3_qp(ibqp);
	struct roce3_device *rdev = to_roce3_dev(ibqp->device);

	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	ret = roce3_post_send_check_qp_type(rqp);
	if (ret != 0) {
		*bad_wr = wr;
		pr_err("[ROCE, ERR] %s: Failed to check qp.ret(%d)\n", __func__, ret);
		return ret;
	}

	ret = roce3_post_send_normal(rdev, rqp, wr, bad_wr);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to post send normal wr, ret(%d)\n", __func__, ret);
		return ret;
	}

	return 0;
}
