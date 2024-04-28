// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "roce.h"
#include "roce_compat.h"
#include "roce_xrc.h"
#include "roce_srq.h"
#include "roce_cq.h"
#include "roce_pub_cmd.h"

u8 roce3_srq_mode_chip_adapt(u8 cfg_mode)
{
	switch (cfg_mode) {
	case ROCE_CHIP_SRQ_MODE_1:
		return ROCE_SRQ_MODE_3;
	case ROCE_CHIP_SRQ_MODE_2:
		return ROCE_SRQ_MODE_2;
	case ROCE_CHIP_SRQ_MODE_3:
		return ROCE_SRQ_MODE_1;
	case ROCE_CHIP_SRQ_MODE_4:
		return ROCE_SRQ_MODE_0;
	default:
		return ROCE_SRQ_MODE_3;
	}
}

static void *roce3_srq_buf_offset(struct tag_cqm_buf *buf, int offset)
{
	return (void *)((char *)buf->direct.va + offset);
}

void *roce3_srq_get_wqe(struct roce3_srq *srq, int n)
{
	return roce3_srq_buf_offset(srq->buf, (int)((u32)n << (unsigned int)srq->wqe_shift));
}

void roce3_srq_async_event(struct roce3_device *rdev, struct roce3_srq *srq, int type)
{
	struct ib_srq *ibsrq = &srq->ibsrq;
	struct ib_event event;

	memset(&event, 0, sizeof(event));
	if (ibsrq->event_handler) {
		event.device = ibsrq->device;
		event.element.srq = ibsrq;
		switch (type) {
		case ROCE_EVENT_TYPE_SRQ_LIMIT:
			event.event = IB_EVENT_SRQ_LIMIT_REACHED;
			break;

		case ROCE_EVENT_TYPE_SRQ_CATAS_ERROR:
			event.event = IB_EVENT_SRQ_ERR;
			break;

		default:
			dev_warn_ratelimited(rdev->hwdev_hdl,
				"[ROCE] %s: unexpected event type(%d) on SRQ(%06x), func_id(%d)\n",
				__func__, type, srq->srqn, rdev->glb_func_id);
			return;
		}

		ibsrq->event_handler(&event, ibsrq->srq_context);
	}
}

/*
 ****************************************************************************
 Prototype	: roce3_free_srq_wqe
 Description  : roce3_free_srq_wqe
 Input		: struct roce3_srq *srq
				int wqe_index
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
void roce3_free_srq_wqe(struct roce3_srq *srq, int wqe_index)
{
	struct roce3_wqe_srq_next_seg *next = NULL;

	spin_lock(&srq->lock);

	next = (struct roce3_wqe_srq_next_seg *)roce3_srq_get_wqe(srq, srq->tail);
	next->next_wqe_index = (u16)wqe_index;
	srq->tail = wqe_index;

	spin_unlock(&srq->lock);
}
