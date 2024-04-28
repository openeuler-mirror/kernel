// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/slab.h>

#include "hinic3_hw.h"

#include "roce.h"
#include "roce_srq.h"
#include "roce_qp.h"
#include "roce_mix.h"
#include "roce_xrc.h"
#include "roce_user.h"
#include "roce_cq.h"
#include "roce_pub_cmd.h"
#include "hinic3_hmm.h"

/*
 ****************************************************************************
 Prototype	: roce3_cq_async_event
 Description  : roce3_cq_async_event
 Input		: struct roce3_device *rdev
				struct roce3_cq *cq
				int type
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
void roce3_cq_async_event(struct roce3_device *rdev, struct roce3_cq *cq, int type)
{
	struct ib_cq *ibcq = &cq->ibcq;
	struct ib_event event;

	memset(&event, 0, sizeof(event));
	if (type != ROCE_EVENT_TYPE_CQ_ERROR) {
		dev_warn_ratelimited(rdev->hwdev_hdl,
			"[ROCE] %s: Unexpected event type(0x%x) on CQ(%06x), func_id(%d)\n",
			__func__, type, cq->cqn, rdev->glb_func_id);
		return;
	}

	if (ibcq->event_handler) {
		event.device = ibcq->device;
		event.event = IB_EVENT_CQ_ERR;
		event.element.cq = ibcq;
		ibcq->event_handler(&event, ibcq->cq_context);
	}
}

/*
 ****************************************************************************
 Prototype	: roce3_cq_buf_init
 Description  : roce3_cq_buf_init
 Input		: struct roce3_cq_buf *buf
 Output	   : None

  1.Date		 : 2015/11/9
	Modification : Created function

****************************************************************************
*/
void roce3_cq_buf_init(struct roce3_cq_buf *buf)
{
	/* optype was initialized into ROCE_OPCODE_CQE_UNUSED(0x1f) */
	memset(buf->buf->direct.va, ROCE_CQE_INVALID_VALUE,
		(unsigned long)((unsigned int)buf->buf_size));
}

/*
 ****************************************************************************
 Prototype	: roce3_cq_put_umem
 Description  : Release umem and corresponding mtt, corresponding to put
 Input		: struct roce3_device *rdev
				struct roce3_cq_buf *buf
				struct ib_umem **umem
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
void roce3_cq_put_umem(struct roce3_device *rdev, struct roce3_cq_buf *buf, struct ib_umem **umem)
{
	/* free MTT of Buffer */
	hmm_rdma_mtt_free(rdev->hwdev, &buf->mtt, SERVICE_T_ROCE);

	/* release umem */
	ib_umem_release(*umem);
}

static void *roce3_cq_buf_offset(struct tag_cqm_buf *buf, unsigned int offset)
{
	return (void *)((char *)buf->direct.va + offset);
}

void *roce3_get_cqe_from_buf(struct roce3_cq_buf *buf, unsigned int n)
{
	return roce3_cq_buf_offset(buf->buf, (n * buf->entry_size));
}

void *roce3_get_cqe(struct roce3_cq *cq, unsigned int n)
{
	return roce3_get_cqe_from_buf(&cq->buf, n);
}

/*
 ****************************************************************************
 Prototype	: roce3_get_sw_cqe
 Description  : roce3_get_sw_cqe
 Input		: struct roce3_cq *cq
				unsigned int n
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
void *roce3_get_sw_cqe(struct roce3_cq *cq, unsigned int n)
{
	struct roce_cqe *cqe = (struct roce_cqe *)roce3_get_cqe(
		cq, (n & ((unsigned int)cq->ibcq.cqe)));
	struct roce_cqe tmp_cqe;
	unsigned int tmp_val;

	tmp_cqe.dw0.value = roce3_convert_cpu32(cqe->dw0.value);
	tmp_cqe.dw1.value = roce3_convert_cpu32(cqe->dw1.value);

	/*
	 * Add judgment condition: the optype of CQE cannot be UNUSED,
	 * UNUSED means that it has been initialized in resize cq
	 */
	tmp_val = ((n & ((unsigned int)cq->ibcq.cqe + 1)) == 0) ? 1 : 0;
	if ((ROCE_LIKELY(tmp_cqe.dw1.bs.op_type != ROCE_OPCODE_CQE_UNUSED)) &&
	    ((tmp_cqe.dw0.bs.owner ^ tmp_val) != 0))
		return cqe;

	return NULL;
}

int roce3_cq_get_umem(struct roce3_device *rdev, struct ib_udata *udata, struct roce3_cq_buf *buf,
	struct ib_umem **umem, u64 buf_addr, int cqe)
{
	int ret = 0;
	u32 npages = 0;
	int page_shift = 0;
	int cqe_size = (int)rdev->rdma_cap.cqe_size;

	*umem = ib_umem_get(&rdev->ib_dev, buf_addr,
		(unsigned long)(cqe * cqe_size), IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(*umem)) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to get ib_umem, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return (int)PTR_ERR(*umem);
	}

	npages = (u32)ib_umem_num_pages(*umem);
	page_shift = PAGE_SHIFT;

	buf->mtt.mtt_type = MTT_CMTT_TYPE;
	ret = hmm_rdma_mtt_alloc(rdev->hwdev, npages, (u32)page_shift, &buf->mtt, SERVICE_T_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to alloc rdma_mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_buf;
	}

	ret = roce3_umem_write_mtt(rdev, &buf->mtt, *umem);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to write mtt for umem, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_mtt;
	}

	return 0;

err_mtt:
	hmm_rdma_mtt_free(rdev->hwdev, &buf->mtt, SERVICE_T_ROCE);

err_buf:
	ib_umem_release(*umem);

	return ret;
}

void roce_reset_flow_comp(struct roce3_cq *rcq)
{
	struct ib_cq *ibcq = &rcq->ibcq;

	ibcq->comp_handler(ibcq, ibcq->cq_context);
}
