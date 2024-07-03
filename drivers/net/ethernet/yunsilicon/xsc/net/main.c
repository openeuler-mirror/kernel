// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/in.h>
#include <linux/interrupt.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/overflow.h>

#include "common/xsc_hsi.h"
#include "common/xsc_core.h"
#include "common/xsc_ioctl.h"
#include "common/xsc_cmd.h"
#include "common/qp.h"
#include "common/xsc_lag.h"
#include "common/xsc_pp.h"

#include "xsc_eth.h"
#include "xsc_eth_txrx.h"
#include "xsc_eth_ethtool.h"
#include "xsc_eth_common.h"
#include "xsc_eth_stats.h"
#include "xsc_accel.h"
#include "xsc_eth_ctrl.h"
#include "../pci/eswitch.h"

#include "common/xsc_fs.h"
#include "common/vport.h"
#include "common/qp.h"

MODULE_LICENSE("GPL");

static void xsc_eth_close_channel(struct xsc_channel *c, bool free_rq);
static void xsc_eth_remove(struct xsc_core_device *xdev, void *context);

static int xsc_eth_open(struct net_device *netdev);
static int xsc_eth_close(struct net_device *netdev);
static void xsc_netdev_set_tcs(struct xsc_adapter *priv, u16 nch, u8 ntc);

#ifdef NEED_CREATE_RX_THREAD
extern uint32_t xsc_eth_rx_thread_create(struct xsc_adapter *adapter);
#endif

static inline void xsc_set_feature(netdev_features_t *features,
				   netdev_features_t feature,
				   bool enable)
{
	if (enable)
		*features |= feature;
	else
		*features &= ~feature;
}

typedef int (*xsc_feature_handler)(struct net_device *netdev, bool enable);

static int xsc_eth_modify_qp_status(struct xsc_core_device *xdev,
				    u32 qpn, u16 status);

static void xsc_eth_build_queue_param(struct xsc_adapter *adapter,
				      struct xsc_queue_attr *attr, u8 type)
{
	struct xsc_core_device *xdev = adapter->xdev;

	if (adapter->nic_param.sq_size == 0)
		adapter->nic_param.sq_size = BIT(xdev->caps.log_max_qp_depth);
	if (adapter->nic_param.rq_size == 0)
		adapter->nic_param.rq_size = BIT(xdev->caps.log_max_qp_depth);

	if (type == XSC_QUEUE_TYPE_EQ) {
		attr->q_type = XSC_QUEUE_TYPE_EQ;
		attr->ele_num = XSC_EQ_ELE_NUM;
		attr->ele_size = XSC_EQ_ELE_SZ;
		attr->ele_log_size = order_base_2(XSC_EQ_ELE_SZ);
		attr->q_log_size = order_base_2(XSC_EQ_ELE_NUM);
	} else if (type == XSC_QUEUE_TYPE_RQCQ) {
		attr->q_type = XSC_QUEUE_TYPE_RQCQ;
		attr->ele_num = adapter->nic_param.rq_size;
		attr->ele_size = XSC_RQCQ_ELE_SZ;
		attr->ele_log_size = order_base_2(XSC_RQCQ_ELE_SZ);
		attr->q_log_size = order_base_2(attr->ele_num);
	} else if (type == XSC_QUEUE_TYPE_SQCQ) {
		attr->q_type = XSC_QUEUE_TYPE_SQCQ;
		attr->ele_num = adapter->nic_param.sq_size;
		attr->ele_size = XSC_SQCQ_ELE_SZ;
		attr->ele_log_size = order_base_2(XSC_SQCQ_ELE_SZ);
		attr->q_log_size = order_base_2(attr->ele_num);
	} else if (type == XSC_QUEUE_TYPE_RQ) {
		attr->q_type = XSC_QUEUE_TYPE_RQ;
		attr->ele_num = adapter->nic_param.rq_size;
		attr->ele_size = xdev->caps.recv_ds_num * XSC_RECV_WQE_DS;
		attr->ele_log_size = order_base_2(attr->ele_size);
		attr->q_log_size = order_base_2(attr->ele_num);
	} else if (type == XSC_QUEUE_TYPE_SQ) {
		attr->q_type = XSC_QUEUE_TYPE_SQ;
		attr->ele_num = adapter->nic_param.sq_size;
		attr->ele_size = xdev->caps.send_ds_num * XSC_SEND_WQE_DS;
		attr->ele_log_size = order_base_2(attr->ele_size);
		attr->q_log_size = order_base_2(attr->ele_num);
	}
}

static void xsc_eth_init_frags_partition(struct xsc_rq *rq)
{
	struct xsc_wqe_frag_info next_frag = {};
	struct xsc_wqe_frag_info *prev;
	int i;

	next_frag.di = &rq->wqe.di[0];
	next_frag.offset = 0;
	prev = NULL;

	for (i = 0; i < xsc_wq_cyc_get_size(&rq->wqe.wq); i++) {
		struct xsc_rq_frag_info *frag_info = &rq->wqe.info.arr[0];
		struct xsc_wqe_frag_info *frag =
			&rq->wqe.frags[i << rq->wqe.info.log_num_frags];
		int f;

		for (f = 0; f < rq->wqe.info.num_frags; f++, frag++) {
			if (next_frag.offset + frag_info[f].frag_stride >
				XSC_RX_FRAG_SZ) {
				next_frag.di++;
				next_frag.offset = 0;
				if (prev)
					prev->last_in_page = 1;
			}
			*frag = next_frag;

			/* prepare next */
			next_frag.offset += frag_info[f].frag_stride;
			prev = frag;
		}
	}

	if (prev)
		prev->last_in_page = 1;
}

static int xsc_eth_init_di_list(struct xsc_rq *rq, int wq_sz, int cpu)
{
	int len = wq_sz << rq->wqe.info.log_num_frags;

	rq->wqe.di = kvzalloc_node(array_size(len, sizeof(*rq->wqe.di)),
				   GFP_KERNEL, cpu_to_node(cpu));
	if (!rq->wqe.di)
		return -ENOMEM;

	xsc_eth_init_frags_partition(rq);

	return 0;
}

static void xsc_eth_free_di_list(struct xsc_rq *rq)
{
	kvfree(rq->wqe.di);
}

int xsc_rx_alloc_page_cache(struct xsc_rq *rq, int node, u8 log_init_sz)
{
	struct xsc_page_cache *cache = &rq->page_cache;

	cache->sz = 1 << log_init_sz;
	cache->page_cache = kvzalloc_node(cache->sz * sizeof(*cache->page_cache),
					  GFP_KERNEL, node);
	if (!cache->page_cache)
		return -ENOMEM;

	return 0;
}

void xsc_rx_free_page_cache(struct xsc_rq *rq)
{
	struct xsc_page_cache *cache = &rq->page_cache;
	u32 i;

	for (i = cache->head; i != cache->tail; i = (i + 1) & (cache->sz - 1)) {
		struct xsc_dma_info *dma_info = &cache->page_cache[i];

		xsc_page_release_dynamic(rq, dma_info, false);
	}
	kvfree(cache->page_cache);
}

int xsc_eth_reset(struct xsc_core_device *dev)
{
	return 0;
}

void xsc_eth_cq_error_event(struct xsc_core_cq *xcq, enum xsc_event event)
{
	struct xsc_cq *xsc_cq = container_of(xcq, struct xsc_cq, xcq);
	struct xsc_core_device *xdev = xsc_cq->xdev;

	if (event != XSC_EVENT_TYPE_CQ_ERROR) {
		xsc_core_err(xdev, "Unexpected event type %d on CQ %06x\n",
			     event, xcq->cqn);
		return;
	}

	xsc_core_err(xdev, "Eth catch CQ ERROR：%x, cqn: %d\n", event, xcq->cqn);
}

void xsc_eth_completion_event(struct xsc_core_cq *xcq)
{
	struct xsc_cq *cq = container_of(xcq, struct xsc_cq, xcq);
	struct xsc_core_device *xdev = cq->xdev;
	struct xsc_rq *rq = NULL;

	if (unlikely(!cq->channel)) {
		xsc_core_warn(xdev, "cq%d->channel is null\n", xcq->cqn);
		return;
	}

	rq = &cq->channel->qp.rq[0];

	set_bit(XSC_CHANNEL_NAPI_SCHED, &cq->channel->flags);
	cq->channel->stats->events++;
	cq->channel->stats->poll = 0;
	if (cq->rx)
		cq->channel->rx_int = 1;
	else
		cq->channel->rx_int = 0;

	if (!test_bit(XSC_ETH_RQ_STATE_ENABLED, &rq->state))
		xsc_core_warn(xdev, "ch%d_cq%d, napi_flag=0x%lx\n",
			      cq->channel->chl_idx, xcq->cqn, cq->napi->state);

	napi_schedule(cq->napi);
}

static inline int xsc_cmd_destroy_cq(struct xsc_core_device *dev, struct xsc_core_cq *xcq)
{
	struct xsc_destroy_cq_mbox_in in;
	struct xsc_destroy_cq_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_CQ);
	in.cqn = cpu_to_be32(xcq->cqn);
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(dev, "failed to destroy cq, err=%d out.status=%u\n",
			     err, out.hdr.status);
		return -ENOEXEC;
	}

	xcq->cqn = 0;
	return 0;
}

int xsc_eth_create_cq(struct xsc_core_device *xdev, struct xsc_core_cq *xcq,
		      struct xsc_create_cq_mbox_in *in, int insize)
{
	int err, ret = -1;
	struct xsc_cq_table *table = &xdev->dev_res->cq_table;
	struct xsc_create_cq_mbox_out out;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_CQ);
	ret = xsc_cmd_exec(xdev, in, insize, &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev, "failed to create cq, err=%d out.status=%u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	xcq->cqn = be32_to_cpu(out.cqn) & 0xffffff;
	xcq->cons_index = 0;
	xcq->arm_sn = 0;
	atomic_set(&xcq->refcount, 1);
	init_completion(&xcq->free);

	spin_lock_irq(&table->lock);
	ret = radix_tree_insert(&table->tree, xcq->cqn, xcq);
	spin_unlock_irq(&table->lock);
	if (ret)
		goto err_insert_cq;
	return 0;

err_insert_cq:
	err = xsc_cmd_destroy_cq(xdev, xcq);
	if (err)
		xsc_core_warn(xdev, "failed to destroy cqn=%d, err=%d\n", xcq->cqn, err);
	return ret;
}

int xsc_eth_destroy_cq(struct xsc_core_device *xdev, struct xsc_cq *cq)
{
	struct xsc_cq_table *table = &xdev->dev_res->cq_table;
	struct xsc_core_cq *tmp;
	int err;

	spin_lock_irq(&table->lock);
	tmp = radix_tree_delete(&table->tree, cq->xcq.cqn);
	spin_unlock_irq(&table->lock);
	if (!tmp) {
		err = -ENOENT;
		goto err_delete_cq;
	}

	if (tmp != &cq->xcq) {
		err = -EINVAL;
		goto err_delete_cq;
	}

	err = xsc_cmd_destroy_cq(xdev, &cq->xcq);
	if (err)
		goto err_destroy_cq;

	if (atomic_dec_and_test(&cq->xcq.refcount))
		complete(&cq->xcq.free);
	wait_for_completion(&cq->xcq.free);
	return 0;

err_destroy_cq:
	xsc_core_warn(xdev, "failed to destroy cqn=%d, err=%d\n",
		      cq->xcq.cqn, err);
	return err;
err_delete_cq:
	xsc_core_warn(xdev, "cqn=%d not found in tree, err=%d\n",
		      cq->xcq.cqn, err);
	return err;
}

void xsc_eth_free_cq(struct xsc_cq *cq)
{
	xsc_eth_wq_destroy(&cq->wq_ctrl);
}

int xsc_eth_create_rss_qp_rqs(struct xsc_core_device *xdev,
			      struct xsc_create_multiqp_mbox_in *in,
			      int insize,
			      int *prqn_base)
{
	int ret;
	struct xsc_create_multiqp_mbox_out out;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_MULTI_QP);
	ret = xsc_cmd_exec(xdev, in, insize, &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev,
			     "failed to create rss rq, qp_num=%d, type=%d, err=%d out.status=%u\n",
			     in->qp_num, in->qp_type, ret, out.hdr.status);
		return -ENOEXEC;
	}

	*prqn_base = be32_to_cpu(out.qpn_base) & 0xffffff;
	return 0;
}

void xsc_eth_qp_event(struct xsc_core_qp *qp, int type)
{
	struct xsc_rq *rq;
	struct xsc_sq *sq;
	struct xsc_core_device *xdev;

	if (qp->eth_queue_type == XSC_RES_RQ) {
		rq = container_of(qp, struct xsc_rq, cqp);
		xdev = rq->cq.xdev;
	} else if (qp->eth_queue_type == XSC_RES_SQ) {
		sq = container_of(qp, struct xsc_sq, cqp);
		xdev = sq->cq.xdev;
	} else {
		pr_err("%s:Unknown eth qp type %d\n", __func__, type);
		return;
	}

	switch (type) {
	case XSC_EVENT_TYPE_WQ_CATAS_ERROR:
	case XSC_EVENT_TYPE_WQ_INVAL_REQ_ERROR:
	case XSC_EVENT_TYPE_WQ_ACCESS_ERROR:
		xsc_core_err(xdev, "%s:Async event %x on QP %d\n", __func__, type, qp->qpn);
		break;
	default:
		xsc_core_err(xdev, "%s: Unexpected event type %d on QP %d\n",
			     __func__, type, qp->qpn);
		return;
	}
}

int xsc_eth_create_qp_rq(struct xsc_core_device *xdev, struct xsc_rq *prq,
			 struct xsc_create_qp_mbox_in *in, int insize)
{
	int ret = -1;
	struct xsc_create_qp_mbox_out out;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_QP);
	ret = xsc_cmd_exec(xdev, in, insize, &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev, "failed to create rq, err=%d out.status=%u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	prq->rqn = be32_to_cpu(out.qpn) & 0xffffff;
	prq->cqp.event = xsc_eth_qp_event;
	prq->cqp.eth_queue_type = XSC_RES_RQ;

	ret = create_resource_common(xdev, &prq->cqp);
	if (ret) {
		xsc_core_err(xdev, "%s:error qp:%d errno:%d\n", __func__, prq->rqn, ret);
		return ret;
	}

	return 0;
}

int xsc_eth_destroy_qp_rq(struct xsc_core_device *xdev, struct xsc_rq *prq)
{
	struct xsc_destroy_qp_mbox_in in;
	struct xsc_destroy_qp_mbox_out out;
	int err;

	err = xsc_eth_modify_qp_status(xdev, prq->rqn, XSC_CMD_OP_2RST_QP);
	if (err) {
		xsc_core_warn(xdev, "failed to set rq%d status=rst, err=%d\n", prq->rqn, err);
		return err;
	}

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_QP);
	in.qpn = cpu_to_be32(prq->rqn);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "failed to destroy rq%d, err=%d out.status=%u\n",
			     prq->rqn, err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

static void xsc_eth_free_rx_wqe(struct xsc_rq *rq)
{
	u16 wqe_ix;
	struct xsc_wq_cyc *wq = &rq->wqe.wq;

	while (!xsc_wq_cyc_is_empty(wq)) {
		wqe_ix = xsc_wq_cyc_get_tail(wq);
		rq->dealloc_wqe(rq, wqe_ix);
		xsc_wq_cyc_pop(wq);
	}
}

static void xsc_free_qp_rq(struct xsc_rq *rq)
{
	if (rq->page_cache.page_cache)
		xsc_rx_free_page_cache(rq);

	kvfree(rq->wqe.frags);
	kvfree(rq->wqe.di);

#ifdef HAVE_PAGE_POOL_HEADER
	if (rq->page_pool)
		page_pool_destroy(rq->page_pool);
#endif

	xsc_eth_wq_destroy(&rq->wq_ctrl);
}

int xsc_eth_create_qp_sq(struct xsc_core_device *xdev, struct xsc_sq *psq,
			 struct xsc_create_qp_mbox_in *in, int insize)
{
	struct xsc_create_qp_mbox_out out;
	int ret;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_QP);
	ret = xsc_cmd_exec(xdev, in, insize, &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev, "failed to create sq, err=%d out.status=%u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	psq->sqn = be32_to_cpu(out.qpn) & 0xffffff;

	return 0;
}

int xsc_eth_modify_qp_sq(struct xsc_core_device *xdev, struct xsc_modify_raw_qp_mbox_in *in)
{
	struct xsc_modify_raw_qp_mbox_out out;
	int ret;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_RAW_QP);

	ret = xsc_cmd_exec(xdev, in, sizeof(struct xsc_modify_raw_qp_mbox_in),
			   &out, sizeof(struct xsc_modify_raw_qp_mbox_out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev, "failed to modify sq, err=%d out.status=%u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

int xsc_eth_destroy_qp_sq(struct xsc_core_device *xdev, struct xsc_sq *psq)
{
	struct xsc_destroy_qp_mbox_in in;
	struct xsc_destroy_qp_mbox_out out;
	int err;

	err = xsc_eth_modify_qp_status(xdev, psq->sqn, XSC_CMD_OP_2RST_QP);
	if (err) {
		xsc_core_warn(xdev, "failed to set sq%d status=rst, err=%d\n", psq->sqn, err);
		return err;
	}

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_QP);
	in.qpn = cpu_to_be32(psq->sqn);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "failed to destroy sq%d, err=%d out.status=%u\n",
			     psq->sqn, err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

static void xsc_free_qp_sq_db(struct xsc_sq *sq)
{
	kvfree(sq->db.wqe_info);
	kvfree(sq->db.dma_fifo);
}

static void xsc_free_qp_sq(struct xsc_sq *sq)
{
	xsc_free_qp_sq_db(sq);
	xsc_eth_wq_destroy(&sq->wq_ctrl);
}

static int xsc_eth_alloc_qp_sq_db(struct xsc_sq *sq, int numa)
{
	int wq_sz = xsc_wq_cyc_get_size(&sq->wq);
	struct xsc_core_device *xdev = sq->cq.xdev;
	int df_sz = wq_sz * xdev->caps.send_ds_num;

	sq->db.dma_fifo = kvzalloc_node(array_size(df_sz, sizeof(*sq->db.dma_fifo)),
					GFP_KERNEL, numa);
	sq->db.wqe_info = kvzalloc_node(array_size(wq_sz, sizeof(*sq->db.wqe_info)),
					GFP_KERNEL, numa);

	if (!sq->db.dma_fifo || !sq->db.wqe_info) {
		xsc_free_qp_sq_db(sq);
		return -ENOMEM;
	}

	sq->dma_fifo_mask = df_sz - 1;

	return 0;
}

static int xsc_eth_alloc_cq(struct xsc_channel *c, struct xsc_cq *pcq,
			    struct xsc_cq_param *pcq_param)
{
	int ret;
	struct xsc_core_device *xdev = c->adapter->xdev;
	struct xsc_core_cq *core_cq = &pcq->xcq;
	u32 i;
	u8 q_log_size = pcq_param->cq_attr.q_log_size;
	u8 ele_log_size = pcq_param->cq_attr.ele_log_size;

	pcq_param->wq.db_numa_node = cpu_to_node(c->cpu);
	pcq_param->wq.buf_numa_node = cpu_to_node(c->cpu);

	ret = xsc_eth_cqwq_create(xdev, &pcq_param->wq,
				  q_log_size, ele_log_size, &pcq->wq,
				  &pcq->wq_ctrl);
	if (ret)
		return ret;

	core_cq->cqe_sz = pcq_param->cq_attr.ele_num;
	core_cq->comp = xsc_eth_completion_event;
	core_cq->event = xsc_eth_cq_error_event;
	core_cq->vector = c->chl_idx;

	for (i = 0; i < xsc_cqwq_get_size(&pcq->wq); i++) {
		struct xsc_cqe *cqe = xsc_cqwq_get_wqe(&pcq->wq, i);

		cqe->owner = 1;
	}
	pcq->xdev = xdev;

	return ret;
}

#ifdef NEED_CREATE_RX_THREAD
static int xsc_eth_set_cq(struct xsc_channel *c,
			  struct xsc_cq *pcq,
			  struct xsc_cq_param *pcq_param)
{
	int ret = XSCALE_RET_SUCCESS;
	struct xsc_create_cq_mbox_in *in;
	int inlen;
	int hw_npages;

	hw_npages = DIV_ROUND_UP(pcq->wq_ctrl.buf.size, PAGE_SIZE_4K);
	/*mbox size + pas size*/
	inlen = sizeof(struct xsc_create_cq_mbox_in) +
		sizeof(__be64) * hw_npages;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	/*construct param of in struct*/
	in->ctx.log_cq_sz = pcq_param->cq_attr.q_log_size;
	in->ctx.pa_num = cpu_to_be16(hw_npages);
	in->ctx.glb_func_id = cpu_to_be16(c->adapter->xdev->glb_func_id);

	xsc_fill_page_frag_array(&pcq->wq_ctrl.buf,
				 &in->pas[0], hw_npages);

	ret = xsc_eth_create_cq(c->adapter->xdev, &pcq->xcq, in, inlen);

	kfree(in);
	xsc_core_info(c->adapter->xdev, "create cqn%d, func_id=%d, ret=%d\n",
		      pcq->xcq.cqn, c->adapter->xdev->glb_func_id, ret);
	return ret;
}
#else
static int xsc_eth_set_cq(struct xsc_channel *c,
			  struct xsc_cq *pcq,
			  struct xsc_cq_param *pcq_param)
{
	int ret = XSCALE_RET_SUCCESS;
	struct xsc_core_device *xdev = c->adapter->xdev;
	struct xsc_create_cq_mbox_in *in;
	int inlen;
	int eqn, irqn;
	int hw_npages;

	hw_npages = DIV_ROUND_UP(pcq->wq_ctrl.buf.size, PAGE_SIZE_4K);
	/*mbox size + pas size*/
	inlen = sizeof(struct xsc_create_cq_mbox_in) +
		sizeof(__be64) * hw_npages;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	/*construct param of in struct*/
	ret = xsc_vector2eqn(xdev, c->chl_idx, &eqn, &irqn);
	if (ret)
		goto err;

	in->ctx.eqn = eqn;
	in->ctx.eqn = cpu_to_be16(in->ctx.eqn);
	in->ctx.log_cq_sz = pcq_param->cq_attr.q_log_size;
	in->ctx.pa_num = cpu_to_be16(hw_npages);
	in->ctx.glb_func_id = cpu_to_be16(xdev->glb_func_id);

	xsc_fill_page_frag_array(&pcq->wq_ctrl.buf, &in->pas[0], hw_npages);

	ret = xsc_eth_create_cq(c->adapter->xdev, &pcq->xcq, in, inlen);

err:
	kvfree(in);
	xsc_core_info(c->adapter->xdev, "create ch%d cqn%d, eqn=%d, func_id=%d, ret=%d\n",
		      c->chl_idx, pcq->xcq.cqn, eqn, xdev->glb_func_id, ret);
	return ret;
}
#endif

static int xsc_eth_open_cq(struct xsc_channel *c,
			   struct xsc_cq *pcq,
			   struct xsc_cq_param *pcq_param)
{
	int ret = XSCALE_RET_SUCCESS;

	ret = xsc_eth_alloc_cq(c, pcq, pcq_param);
	if (ret)
		return ret;

	ret = xsc_eth_set_cq(c, pcq, pcq_param);
	if (ret)
		goto err_set_cq;

	xsc_cq_notify_hw_rearm(pcq);

	pcq->napi = &c->napi;
	pcq->channel = c;
	pcq->rx = (pcq_param->cq_attr.q_type == XSC_QUEUE_TYPE_RQCQ) ? 1 : 0;

	return 0;

err_set_cq:
	xsc_eth_free_cq(pcq);
	return ret;
}

static int xsc_eth_close_cq(struct xsc_channel *c, struct xsc_cq *pcq)
{
	int ret;
	struct xsc_core_device *xdev = c->adapter->xdev;

	ret = xsc_eth_destroy_cq(xdev, pcq);
	if (ret) {
		xsc_core_warn(xdev, "failed to close ch%d cq%d, ret=%d\n",
			      c->chl_idx, pcq->xcq.cqn, ret);
		return ret;
	}

	xsc_eth_free_cq(pcq);

	return 0;
}

static int xsc_eth_modify_qp_status(struct xsc_core_device *xdev,
				    u32 qpn, u16 status)
{
	struct xsc_modify_qp_mbox_in in;
	struct xsc_modify_qp_mbox_out out;

	return xsc_modify_qp(xdev, &in, &out, qpn, status);
}

int xsc_eth_set_hw_mtu(struct xsc_core_device *dev, u16 mtu, u16 rx_buf_sz)
{
	struct xsc_set_mtu_mbox_in in;
	struct xsc_set_mtu_mbox_out out;
	int ret;

	memset(&in, 0, sizeof(struct xsc_set_mtu_mbox_in));
	memset(&out, 0, sizeof(struct xsc_set_mtu_mbox_out));

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_SET_MTU);
	in.mtu = cpu_to_be16(mtu);
	in.rx_buf_sz_min = cpu_to_be16(rx_buf_sz);
	in.mac_port = dev->mac_port;

	ret = xsc_cmd_exec(dev, &in, sizeof(struct xsc_set_mtu_mbox_in), &out,
			   sizeof(struct xsc_set_mtu_mbox_out));
	if (ret || out.hdr.status) {
		xsc_core_err(dev, "failed to set hw_mtu=%u rx_buf_sz=%u, err=%d, status=%d\n",
			     mtu, rx_buf_sz, ret, out.hdr.status);
		ret = -ENOEXEC;
	}

	return ret;
}

int xsc_eth_get_mac(struct xsc_core_device *dev, char *mac)
{
	struct xsc_query_eth_mac_mbox_out *out;
	struct xsc_query_eth_mac_mbox_in in;
	int err;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_ETH_MAC);
	in.hdr.opmod  = cpu_to_be16(0x1);

	err = xsc_cmd_exec(dev, &in, sizeof(in), out, sizeof(*out));
	if (err || out->hdr.status) {
		xsc_core_warn(dev, "get mac failed! err=%d, out.status=%u\n", err, out->hdr.status);
		err = -ENOEXEC;
		goto exit;
	}

	memcpy(mac, out->mac, 6);
	xsc_core_dbg(dev, "get mac %02x:%02x:%02x:%02x:%02x:%02x\n",
		     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

exit:
	kfree(out);

	return err;
}

int xsc_eth_modify_qps_channel(struct xsc_adapter *adapter, struct xsc_channel *c)
{
	int ret = 0;
	int i;

	for (i = 0; i < c->qp.rq_num; i++) {
		c->qp.rq[i].post_wqes(&c->qp.rq[i]);
		ret = xsc_eth_modify_qp_status(adapter->xdev, c->qp.rq[i].rqn,
					       XSC_CMD_OP_RTR2RTS_QP);
		if (ret)
			return ret;
	}

	for (i = 0; i < c->qp.sq_num; i++) {
		ret = xsc_eth_modify_qp_status(adapter->xdev, c->qp.sq[i].sqn,
					       XSC_CMD_OP_RTR2RTS_QP);
		if (ret)
			return ret;
	}
	return 0;
}

int xsc_eth_modify_qps(struct xsc_adapter *adapter,
		       struct xsc_eth_channels *chls)
{
	int ret;
	int i;

	for (i = 0; i < chls->num_chl; i++) {
		struct xsc_channel *c = &chls->c[i];

		ret = xsc_eth_modify_qps_channel(adapter, c);
		if (ret)
			return ret;
	}

	return 0;
}

u32 xsc_rx_get_linear_frag_sz(u32 mtu)
{
	u32 byte_count = XSC_SW2HW_FRAG_SIZE(mtu);

	return XSC_SKB_FRAG_SZ(byte_count);
}

bool xsc_rx_is_linear_skb(u32 mtu)
{
	u32 linear_frag_sz = xsc_rx_get_linear_frag_sz(mtu);

	return linear_frag_sz <= PAGE_SIZE;
}

static int xsc_eth_alloc_rq(struct xsc_channel *c,
			    struct xsc_rq *prq,
			    struct xsc_rq_param *prq_param)
{
	struct xsc_adapter *adapter = c->adapter;
	u8 q_log_size = prq_param->rq_attr.q_log_size;
#ifdef HAVE_PAGE_POOL_HEADER
	struct page_pool_params pagepool_params = { 0 };
	u32 pool_size = 1 << q_log_size;
#endif
	u8 ele_log_size = prq_param->rq_attr.ele_log_size;
	struct xsc_stats *stats = c->adapter->stats;
	struct xsc_channel_stats *channel_stats =
					&stats->channel_stats[c->chl_idx];
	int cache_init_sz = 0;
	int wq_sz;
	int i, f;
	int ret = 0;

	prq->stats = &channel_stats->rq;
	prq_param->wq.db_numa_node = cpu_to_node(c->cpu);

	ret = xsc_eth_wq_cyc_create(c->adapter->xdev, &prq_param->wq,
				    q_log_size, ele_log_size, &prq->wqe.wq,
				    &prq->wq_ctrl);
	if (ret)
		return ret;

	wq_sz = xsc_wq_cyc_get_size(&prq->wqe.wq);

	prq->wqe.info = prq_param->frags_info;
	prq->wqe.frags = kvzalloc_node(array_size((wq_sz << prq->wqe.info.log_num_frags),
						  sizeof(*prq->wqe.frags)),
				       GFP_KERNEL,
				       cpu_to_node(c->cpu));
	if (!prq->wqe.frags) {
		ret = -ENOMEM;
		goto err_alloc_frags;
	}

	ret = xsc_eth_init_di_list(prq, wq_sz, c->cpu);
	if (ret)
		goto err_init_di;

	prq->buff.map_dir = DMA_FROM_DEVICE;
#ifdef XSC_PAGE_CACHE
	cache_init_sz = wq_sz << prq->wqe.info.log_num_frags;
	ret = xsc_rx_alloc_page_cache(prq, cpu_to_node(c->cpu), ilog2(cache_init_sz));
	if (ret)
		goto err_create_pool;
#endif

#ifdef HAVE_PAGE_POOL_HEADER
	/* Create a page_pool and register it with rxq */
	pool_size =  wq_sz << prq->wqe.info.log_num_frags;
	pagepool_params.order		= XSC_RX_FRAG_SZ_ORDER;
	pagepool_params.flags		= 0; /* No-internal DMA mapping in page_pool */
	pagepool_params.pool_size	= pool_size;
	pagepool_params.nid		= cpu_to_node(c->cpu);
	pagepool_params.dev		= c->adapter->dev;
	pagepool_params.dma_dir	= prq->buff.map_dir;

	prq->page_pool = page_pool_create(&pagepool_params);
	if (IS_ERR(prq->page_pool)) {
		ret = PTR_ERR(prq->page_pool);
		prq->page_pool = NULL;
		goto err_create_pool;
	}

	if (c->chl_idx == 0)
		xsc_core_dbg(adapter->xdev,
			     "page pool: size=%d, cpu=%d, pool_numa=%d, cache_size=%d, mtu=%d, wqe_numa=%d\n",
			     pool_size, c->cpu, pagepool_params.nid,
			     cache_init_sz, adapter->nic_param.mtu,
			     prq_param->wq.buf_numa_node);
#endif

	for (i = 0; i < wq_sz; i++) {
		struct xsc_eth_rx_wqe_cyc *wqe =
			xsc_wq_cyc_get_wqe(&prq->wqe.wq, i);

		for (f = 0; f < prq->wqe.info.num_frags; f++) {
			u32 frag_size = prq->wqe.info.arr[f].frag_size;

			wqe->data[f].seg_len = cpu_to_le32(frag_size);
			wqe->data[f].mkey = cpu_to_le32(XSC_INVALID_LKEY);
		}

		for (; f < prq->wqe.info.frags_max_num; f++) {
			wqe->data[f].seg_len = 0;
			wqe->data[f].mkey = cpu_to_le32(XSC_INVALID_LKEY);
			wqe->data[f].va = 0;
		}
	}

	prq->post_wqes = xsc_eth_post_rx_wqes;
	prq->handle_rx_cqe = xsc_eth_handle_rx_cqe;
	prq->dealloc_wqe = xsc_eth_dealloc_rx_wqe;
	prq->wqe.skb_from_cqe = xsc_rx_is_linear_skb(adapter->nic_param.mtu) ?
					xsc_skb_from_cqe_linear :
					xsc_skb_from_cqe_nonlinear;
	prq->ix = c->chl_idx;
	prq->frags_sz = adapter->nic_param.rq_frags_size;

	return 0;

err_create_pool:
	xsc_eth_free_di_list(prq);
err_init_di:
	kvfree(prq->wqe.frags);
err_alloc_frags:
	xsc_eth_wq_destroy(&prq->wq_ctrl);
	return ret;
}

#ifdef XSC_RSS_SUPPORT
static int xsc_eth_open_rss_qp_rqs(struct xsc_adapter *adapter,
				   struct xsc_rq_param *prq_param,
				   struct xsc_eth_channels *chls,
				   unsigned int num_chl)
{
	int ret = 0, err = 0;
	struct xsc_create_multiqp_mbox_in *in;
	struct xsc_create_qp_request *req;
	u8 q_log_size = prq_param->rq_attr.q_log_size;
	int paslen = 0;
	struct xsc_rq *prq;
	struct xsc_channel *c;
	int rqn_base;
	int inlen;
	int entry_len;
	int i, j, n;
	int hw_npages;

	for (i = 0; i < num_chl; i++) {
		c = &chls->c[i];

		for (j = 0; j < c->qp.rq_num; j++) {
			prq = &c->qp.rq[j];
			ret = xsc_eth_alloc_rq(c, prq, prq_param);
			if (ret)
				goto err_alloc_rqs;

			hw_npages = DIV_ROUND_UP(prq->wq_ctrl.buf.size, PAGE_SIZE_4K);
			/*support different npages number smoothly*/
			entry_len = sizeof(struct xsc_create_qp_request) +
				sizeof(__be64) * hw_npages;

			paslen += entry_len;
		}
	}

	inlen = sizeof(struct xsc_create_multiqp_mbox_in) + paslen;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in) {
		ret = -ENOMEM;
		goto err_create_rss_rqs;
	}

	in->qp_num = cpu_to_be16(num_chl);
	in->qp_type = XSC_QUEUE_TYPE_RAW;
	in->req_len = cpu_to_be32(inlen);

	req = (struct xsc_create_qp_request *)&in->data[0];
	n = 0;
	for (i = 0; i < num_chl; i++) {
		c = &chls->c[i];
		for (j = 0; j < c->qp.rq_num; j++) {
			prq = &c->qp.rq[j];

			hw_npages = DIV_ROUND_UP(prq->wq_ctrl.buf.size, PAGE_SIZE_4K);
			/* no use for eth */
			req->input_qpn = cpu_to_be16(0);
			req->qp_type = XSC_QUEUE_TYPE_RAW;
			req->log_rq_sz = ilog2(adapter->xdev->caps.recv_ds_num) +
						q_log_size;
			req->pa_num = cpu_to_be16(hw_npages);
			req->cqn_recv = cpu_to_be16(prq->cq.xcq.cqn);
			req->cqn_send = req->cqn_recv;
			req->glb_funcid = cpu_to_be16(adapter->xdev->glb_func_id);

			xsc_fill_page_frag_array(&prq->wq_ctrl.buf, &req->pas[0], hw_npages);
			n++;
			req = (struct xsc_create_qp_request *)(&in->data[0] + entry_len * n);
		}
	}

	ret = xsc_eth_create_rss_qp_rqs(adapter->xdev, in, inlen, &rqn_base);
	kvfree(in);
	if (ret)
		goto err_create_rss_rqs;

	n = 0;
	for (i = 0; i < num_chl; i++) {
		c = &chls->c[i];
		for (j = 0; j < c->qp.rq_num; j++) {
			prq = &c->qp.rq[j];
			prq->rqn = rqn_base + n;
			prq->cqp.qpn = prq->rqn;
			prq->cqp.event = xsc_eth_qp_event;
			prq->cqp.eth_queue_type = XSC_RES_RQ;
			ret = create_resource_common(adapter->xdev, &prq->cqp);
			if (ret) {
				err = ret;
				xsc_core_err(adapter->xdev,
					     "create resource common error qp:%d errno:%d\n",
					     prq->rqn, ret);
				continue;
			}
			n++;
		}
	}
	if (err)
		return err;

	adapter->channels.rqn_base = rqn_base;
	xsc_core_info(adapter->xdev, "rqn_base=%d, rq_num=%d\n", rqn_base, num_chl);
	return 0;

err_create_rss_rqs:
	i = num_chl;
err_alloc_rqs:
	for (--i; i >= 0; i--) {
		c = &chls->c[i];
		for (j = 0; j < c->qp.rq_num; j++) {
			prq = &c->qp.rq[j];
			xsc_free_qp_rq(prq);
		}
	}
	return ret;
}

#else
static int xsc_eth_open_qp_rq(struct xsc_channel *c,
			      struct xsc_rq *prq,
			      struct xsc_rq_param *prq_param,
			      u32 rq_idx)
{
	struct xsc_adapter *adapter = c->adapter;
	struct xsc_core_device *xdev  = adapter->xdev;
	u8 q_log_size = prq_param->rq_attr.q_log_size;
	struct xsc_create_qp_mbox_in *in;
	int hw_npages;
	int inlen;
	int ret = 0;

	ret = xsc_eth_alloc_rq(c, prq, prq_param);
	if (ret)
		goto out;

	hw_npages = DIV_ROUND_UP(prq->wq_ctrl.buf.size, PAGE_SIZE_4K);
	inlen = sizeof(struct xsc_create_qp_mbox_in) +
		sizeof(__be64) * hw_npages;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in) {
		ret = -ENOMEM;
		goto err_alloc_rq;
	}

	in->req.input_qpn = cpu_to_be16(XSC_QPN_RQN_STUB); /*no use for eth*/
	in->req.qp_type = XSC_QUEUE_TYPE_RAW;
	in->req.log_rq_sz = ilog2(xdev->caps.recv_ds_num) + q_log_size;
	in->req.pa_num = cpu_to_be16(hw_npages);
	in->req.cqn_recv = cpu_to_be16(prq->cq.xcq.cqn);
	in->req.cqn_send = in->req.cqn_recv;
	in->req.glb_funcid = cpu_to_be16(xdev->glb_func_id);

	xsc_fill_page_frag_array(&prq->wq_ctrl.buf, &in->req.pas[0], hw_npages);

	ret = xsc_eth_create_qp_rq(xdev, prq, in, inlen);
	if (ret)
		goto err_create_rq;

	prq->cqp.qpn = prq->rqn;
	prq->cqp.event = xsc_eth_qp_event;
	prq->cqp.eth_queue_type = XSC_RES_RQ;

	ret = create_resource_common(xdev, &prq->cqp);
	if (ret) {
		xsc_core_err(xdev, "failed to init rqn%d, err=%d\n",
			     prq->rqn, ret);
		goto err_destroy_rq;
	}

	xsc_core_info(c->adapter->xdev, "rqn=%d ch_num=%d\n",
		      prq->rqn, c->chl_idx);

	kvfree(in);

	return 0;

err_destroy_rq:
	xsc_eth_destroy_qp_rq(xdev, prq);
err_create_rq:
	kvfree(in);
err_alloc_rq:
	xsc_free_qp_rq(prq);
out:
	return ret;
}
#endif

static int xsc_eth_close_qp_rq(struct xsc_channel *c, struct xsc_rq *prq)
{
	int ret;
	struct xsc_core_device *xdev = c->adapter->xdev;

	destroy_resource_common(xdev, &prq->cqp);

	ret = xsc_eth_destroy_qp_rq(xdev, prq);
	if (ret)
		return ret;

	xsc_eth_free_rx_wqe(prq);
	xsc_free_qp_rq(prq);

	return 0;
}

static int xsc_eth_open_qp_sq(struct xsc_channel *c,
			      struct xsc_sq *psq,
			      struct xsc_sq_param *psq_param,
			      u32 sq_idx)
{
	struct xsc_adapter *adapter = c->adapter;
	struct xsc_core_device *xdev  = adapter->xdev;
	u8 q_log_size = psq_param->sq_attr.q_log_size;
	u8 ele_log_size = psq_param->sq_attr.ele_log_size;
	struct xsc_stats *stats = adapter->stats;
	struct xsc_channel_stats *channel_stats =
					&stats->channel_stats[c->chl_idx];
	struct xsc_create_qp_mbox_in *in;
	struct xsc_modify_raw_qp_mbox_in *modify_in;
	int hw_npages;
	int inlen;
	int ret;

	psq->stats = &channel_stats->sq[sq_idx];
	psq_param->wq.db_numa_node = cpu_to_node(c->cpu);

	ret = xsc_eth_wq_cyc_create(xdev, &psq_param->wq,
				    q_log_size, ele_log_size, &psq->wq,
				    &psq->wq_ctrl);
	if (ret)
		return ret;

	hw_npages = DIV_ROUND_UP(psq->wq_ctrl.buf.size, PAGE_SIZE_4K);
	inlen = sizeof(struct xsc_create_qp_mbox_in) +
		sizeof(__be64) * hw_npages;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in) {
		ret = -ENOMEM;
		goto err_sq_wq_destroy;
	}
	in->req.input_qpn = cpu_to_be16(XSC_QPN_SQN_STUB); /*no use for eth*/
	in->req.qp_type = XSC_QUEUE_TYPE_RAW_TSO; /*default sq is tso qp*/
	in->req.log_sq_sz = ilog2(xdev->caps.send_ds_num) + q_log_size;
	in->req.pa_num = cpu_to_be16(hw_npages);
	in->req.cqn_send = cpu_to_be16(psq->cq.xcq.cqn);
	in->req.cqn_recv = in->req.cqn_send;
	in->req.glb_funcid = cpu_to_be16(xdev->glb_func_id);

	xsc_fill_page_frag_array(&psq->wq_ctrl.buf,
				 &in->req.pas[0], hw_npages);

	ret = xsc_eth_create_qp_sq(xdev, psq, in, inlen);
	if (ret)
		goto err_sq_in_destroy;

	psq->cqp.qpn = psq->sqn;
	psq->cqp.event = xsc_eth_qp_event;
	psq->cqp.eth_queue_type = XSC_RES_SQ;

	ret = create_resource_common(xdev, &psq->cqp);
	if (ret) {
		xsc_core_err(xdev, "%s:error qp:%d errno:%d\n",
			     __func__, psq->sqn, ret);
		goto err_sq_destroy;
	}

	psq->channel = c;
	psq->ch_ix = c->chl_idx;
	psq->txq_ix = psq->ch_ix + sq_idx * adapter->channels.num_chl;

	/*need to querify from hardware*/
	psq->hw_mtu = XSC_ETH_HW_MTU_SEND;
	psq->stop_room = 1;

	ret = xsc_eth_alloc_qp_sq_db(psq, psq_param->wq.db_numa_node);
	if (ret)
		goto err_sq_common_destroy;

	inlen = sizeof(struct xsc_modify_raw_qp_mbox_in);
	modify_in = kvzalloc(inlen, GFP_KERNEL);
	if (!modify_in) {
		ret = -ENOMEM;
		goto err_sq_common_destroy;
	}

	modify_in->req.qp_out_port = xdev->pf_id;
	modify_in->pcie_no = xdev->pcie_no;
	modify_in->req.qpn = cpu_to_be16((u16)(psq->sqn));
	modify_in->req.func_id = cpu_to_be16(xdev->glb_func_id);
	modify_in->req.dma_direct = DMA_DIR_TO_MAC;
	modify_in->req.prio = sq_idx;
	ret = xsc_eth_modify_qp_sq(xdev, modify_in);
	if (ret)
		goto err_sq_modify_in_destroy;

	kvfree(modify_in);
	kvfree(in);

	xsc_core_info(c->adapter->xdev, "open sq ok, ch%d_sq%d_qpn=%d, db_numa=%d, buf_numa=%d\n",
		      c->chl_idx, sq_idx, psq->sqn,
		      psq_param->wq.db_numa_node, psq_param->wq.buf_numa_node);

	return 0;

err_sq_modify_in_destroy:
	kvfree(modify_in);

err_sq_common_destroy:
	destroy_resource_common(xdev, &psq->cqp);

err_sq_destroy:
	xsc_eth_destroy_qp_sq(xdev, psq);

err_sq_in_destroy:
	kvfree(in);

err_sq_wq_destroy:
	xsc_eth_wq_destroy(&psq->wq_ctrl);
	return ret;
}

static int xsc_eth_close_qp_sq(struct xsc_channel *c, struct xsc_sq *psq)
{
	struct xsc_core_device *xdev = c->adapter->xdev;
	int ret;

	destroy_resource_common(xdev, &psq->cqp);

	ret = xsc_eth_destroy_qp_sq(xdev, psq);
	if (ret)
		return ret;

	xsc_free_tx_wqe(c->adapter->dev, psq);
	xsc_free_qp_sq(psq);

	return 0;
}

int xsc_eth_open_channel(struct xsc_adapter *adapter,
			 int idx,
			 struct xsc_channel *c,
			 struct xsc_channel_param *chl_param)
{
	int ret = 0;
	struct net_device *netdev = adapter->netdev;
	struct xsc_stats *stats = adapter->stats;
	struct xsc_core_device *xdev = adapter->xdev;
	int i, j, eqn, irqn;
	const struct cpumask *aff;

	c->adapter = adapter;
	c->netdev = adapter->netdev;
	c->chl_idx = idx;
	c->num_tc = adapter->nic_param.num_tc;
	c->stats = &stats->channel_stats[idx].ch;

	/*1rq per channel, and may have multi sqs per channel*/
	c->qp.rq_num = 1;
	c->qp.sq_num = c->num_tc;

	if (xdev->caps.msix_enable) {
		ret = xsc_vector2eqn(xdev, c->chl_idx, &eqn, &irqn);
		if (ret)
			goto err;
		aff = irq_get_affinity_mask(irqn);
		c->aff_mask = aff;
		c->cpu = cpumask_first(aff);
	}

	if (c->qp.sq_num > XSC_MAX_NUM_TC || c->qp.rq_num > XSC_MAX_NUM_TC) {
		ret = -EINVAL;
		goto err;
	}

	for (i = 0; i < c->qp.rq_num; i++) {
		ret = xsc_eth_open_cq(c, &c->qp.rq[i].cq, &chl_param->rqcq_param);
		if (ret) {
			j = i - 1;
			goto err_open_rq_cq;
		}
	}

	for (i = 0; i < c->qp.sq_num; i++) {
		ret = xsc_eth_open_cq(c, &c->qp.sq[i].cq, &chl_param->sqcq_param);
		if (ret) {
			j = i - 1;
			goto err_open_sq_cq;
		}
	}

#ifndef XSC_RSS_SUPPORT
	for (i = 0; i < c->qp.rq_num; i++) {
		ret = xsc_eth_open_qp_rq(c, &c->qp.rq[i], &chl_param->rq_param, i);
		if (ret) {
			j = i - 1;
			goto err_open_rq;
		}
	}
#endif

	for (i = 0; i < c->qp.sq_num; i++) {
		ret = xsc_eth_open_qp_sq(c, &c->qp.sq[i], &chl_param->sq_param, i);
		if (ret) {
			j = i - 1;
			goto err_open_sq;
		}
	}

	netif_napi_add(netdev, &c->napi, xsc_eth_napi_poll);

	xsc_core_dbg(adapter->xdev, "open channel%d ok\n", idx);
	return 0;

err_open_sq:
	for (; j >= 0; j--)
		xsc_eth_close_qp_sq(c, &c->qp.sq[j]);
	j = (c->qp.rq_num - 1);
#ifndef XSC_RSS_SUPPORT
err_open_rq:
	for (; j >= 0; j--)
		xsc_eth_close_qp_rq(c, &c->qp.rq[j]);
	j = (c->qp.sq_num - 1);
#endif
err_open_sq_cq:
	for (; j >= 0; j--)
		xsc_eth_close_cq(c, &c->qp.sq[j].cq);
	j = (c->qp.rq_num - 1);
err_open_rq_cq:
	for (; j >= 0; j--)
		xsc_eth_close_cq(c, &c->qp.rq[j].cq);
err:
	xsc_core_warn(adapter->xdev,
		      "failed to open channel: ch%d, sq_num=%d, rq_num=%d, err=%d\n",
		      idx, c->qp.sq_num, c->qp.rq_num, ret);
	return ret;
}

static u32 xsc_get_rq_frag_info(struct xsc_rq_frags_info *frags_info, u32 mtu)
{
	u32 byte_count = XSC_SW2HW_FRAG_SIZE(mtu);
	int frag_stride;
	int i = 0;

	if (xsc_rx_is_linear_skb(mtu)) {
		frag_stride = xsc_rx_get_linear_frag_sz(mtu);
		frag_stride = roundup_pow_of_two(frag_stride);

		frags_info->arr[0].frag_size = byte_count;
		frags_info->arr[0].frag_stride = frag_stride;
		frags_info->num_frags = 1;
		frags_info->wqe_bulk = PAGE_SIZE / frag_stride;
		frags_info->wqe_bulk_min = frags_info->wqe_bulk;
		goto out;
	}

	if (byte_count <= DEFAULT_FRAG_SIZE) {
		frags_info->arr[0].frag_size = DEFAULT_FRAG_SIZE;
		frags_info->arr[0].frag_stride = DEFAULT_FRAG_SIZE;
		frags_info->num_frags = 1;
	} else if (byte_count <= PAGE_SIZE_4K) {
		frags_info->arr[0].frag_size = PAGE_SIZE_4K;
		frags_info->arr[0].frag_stride = PAGE_SIZE_4K;
		frags_info->num_frags = 1;
	} else if (byte_count <= (PAGE_SIZE_4K + DEFAULT_FRAG_SIZE)) {
		if (PAGE_SIZE < 2 * PAGE_SIZE_4K) {
			frags_info->arr[0].frag_size = DEFAULT_FRAG_SIZE;
			frags_info->arr[0].frag_stride = DEFAULT_FRAG_SIZE;
			frags_info->arr[1].frag_size = DEFAULT_FRAG_SIZE;
			frags_info->arr[1].frag_stride = DEFAULT_FRAG_SIZE;
			frags_info->arr[2].frag_size = DEFAULT_FRAG_SIZE;
			frags_info->arr[2].frag_stride = DEFAULT_FRAG_SIZE;
			frags_info->num_frags = 3;
		} else {
			frags_info->arr[0].frag_size = 2 * PAGE_SIZE_4K;
			frags_info->arr[0].frag_stride = 2 * PAGE_SIZE_4K;
			frags_info->num_frags = 1;
		}
	} else if (byte_count <= 2 * PAGE_SIZE_4K) {
		if (PAGE_SIZE < 2 * PAGE_SIZE_4K) {
			frags_info->arr[0].frag_size = PAGE_SIZE_4K;
			frags_info->arr[0].frag_stride = PAGE_SIZE_4K;
			frags_info->arr[1].frag_size = PAGE_SIZE_4K;
			frags_info->arr[1].frag_stride = PAGE_SIZE_4K;
			frags_info->num_frags = 2;
		} else {
			frags_info->arr[0].frag_size = 2 * PAGE_SIZE_4K;
			frags_info->arr[0].frag_stride = 2 * PAGE_SIZE_4K;
			frags_info->num_frags = 1;
		}
	} else {
		if (PAGE_SIZE < 4 * PAGE_SIZE_4K) {
			frags_info->num_frags = roundup(byte_count, PAGE_SIZE_4K) / PAGE_SIZE_4K;
			for (i = 0; i < frags_info->num_frags; i++) {
				frags_info->arr[i].frag_size = PAGE_SIZE_4K;
				frags_info->arr[i].frag_stride = PAGE_SIZE_4K;
			}
		} else {
			frags_info->arr[0].frag_size = 4 * PAGE_SIZE_4K;
			frags_info->arr[0].frag_stride = 4 * PAGE_SIZE_4K;
			frags_info->num_frags = 1;
		}
	}

	if (PAGE_SIZE <= PAGE_SIZE_4K) {
		frags_info->wqe_bulk_min = 4;
		frags_info->wqe_bulk = max_t(u8, frags_info->wqe_bulk_min, 8);
	} else {
		frags_info->wqe_bulk =
			PAGE_SIZE / (frags_info->num_frags * frags_info->arr[0].frag_size);
		frags_info->wqe_bulk_min = frags_info->wqe_bulk;
	}

out:
	frags_info->log_num_frags = order_base_2(frags_info->num_frags);

	return frags_info->num_frags * frags_info->arr[0].frag_size;
}

static void xsc_build_rq_frags_info(struct xsc_queue_attr *attr,
				    struct xsc_rq_frags_info *frags_info,
				    struct xsc_eth_params *params)
{
	params->rq_frags_size = xsc_get_rq_frag_info(frags_info, params->mtu);
	frags_info->frags_max_num = attr->ele_size / XSC_RECV_WQE_DS;
}

static void xsc_eth_build_channel_param(struct xsc_adapter *adapter,
					struct xsc_channel_param *chl_param)
{
	xsc_eth_build_queue_param(adapter, &chl_param->rqcq_param.cq_attr,
				  XSC_QUEUE_TYPE_RQCQ);
	chl_param->rqcq_param.wq.buf_numa_node = dev_to_node(adapter->dev);

	xsc_eth_build_queue_param(adapter, &chl_param->sqcq_param.cq_attr,
				  XSC_QUEUE_TYPE_SQCQ);
	chl_param->sqcq_param.wq.buf_numa_node = dev_to_node(adapter->dev);

	xsc_eth_build_queue_param(adapter, &chl_param->sq_param.sq_attr,
				  XSC_QUEUE_TYPE_SQ);
	chl_param->sq_param.wq.buf_numa_node = dev_to_node(adapter->dev);

	xsc_eth_build_queue_param(adapter, &chl_param->rq_param.rq_attr,
				  XSC_QUEUE_TYPE_RQ);
	chl_param->rq_param.wq.buf_numa_node = dev_to_node(adapter->dev);

	xsc_build_rq_frags_info(&chl_param->rq_param.rq_attr,
				&chl_param->rq_param.frags_info,
				&adapter->nic_param);
}

int xsc_eth_open_channels(struct xsc_adapter *adapter)
{
	int ret = 0;
	int i;
	struct xsc_channel_param *chl_param;
	struct xsc_eth_channels *chls = &adapter->channels;
	struct xsc_core_device *xdev = adapter->xdev;
	bool free_rq = false;

	chls->num_chl = adapter->nic_param.num_channels;
	chls->c = kcalloc_node(chls->num_chl, sizeof(struct xsc_channel),
			       GFP_KERNEL, xdev->priv.numa_node);
	if (!chls->c) {
		ret = -ENOMEM;
		goto err;
	}

	chl_param = kvzalloc(sizeof(*chl_param), GFP_KERNEL);
	if (!chl_param) {
		ret = -ENOMEM;
		goto err_free_ch;
	}

	xsc_eth_build_channel_param(adapter, chl_param);

	for (i = 0; i < chls->num_chl; i++) {
		ret = xsc_eth_open_channel(adapter, i, &chls->c[i], chl_param);
		if (ret)
			goto err_open_channel;
#ifndef XSC_RSS_SUPPORT
		free_rq = true;
#endif
	}

#ifdef XSC_RSS_SUPPORT
	ret = xsc_eth_open_rss_qp_rqs(adapter, &chl_param->rq_param, chls, chls->num_chl);
	if (ret)
		goto err_open_channel;
	free_rq = true;
#endif

	for (i = 0; i < chls->num_chl; i++)
		napi_enable(&chls->c[i].napi);

	/* flush cache to memory before interrupt and napi_poll running */
	smp_wmb();

	ret = xsc_eth_modify_qps(adapter, chls);
	if (ret)
		goto err_modify_qps;

	kvfree(chl_param);
	xsc_core_info(adapter->xdev, "open %d channels ok\n", chls->num_chl);
	return 0;

err_modify_qps:
	i = chls->num_chl;
err_open_channel:
	for (--i; i >= 0; i--)
		xsc_eth_close_channel(&chls->c[i], free_rq);

	kvfree(chl_param);
err_free_ch:
	kfree(chls->c);
err:
	chls->num_chl = 0;
	xsc_core_warn(adapter->xdev, "failed to open %d channels, err=%d\n",
		      chls->num_chl, ret);
	return ret;
}

static void xsc_eth_activate_txqsq(struct xsc_channel *c)
{
	int tc = c->num_tc;
	struct xsc_sq *psq;

	for (tc = 0; tc < c->num_tc; tc++) {
		psq = &c->qp.sq[tc];
		psq->txq = netdev_get_tx_queue(psq->channel->netdev, psq->txq_ix);
		set_bit(XSC_ETH_SQ_STATE_ENABLED, &psq->state);
		netdev_tx_reset_queue(psq->txq);
		netif_tx_start_queue(psq->txq);
	}
}

static void xsc_eth_deactivate_txqsq(struct xsc_channel *c)
{
	int tc = c->num_tc;
	struct xsc_sq *psq;

	for (tc = 0; tc < c->num_tc; tc++) {
		psq = &c->qp.sq[tc];
		clear_bit(XSC_ETH_SQ_STATE_ENABLED, &psq->state);
	}
}

static void xsc_activate_rq(struct xsc_channel *c)
{
	int i;

	for (i = 0; i < c->qp.rq_num; i++)
		set_bit(XSC_ETH_RQ_STATE_ENABLED, &c->qp.rq[i].state);
}

static void xsc_deactivate_rq(struct xsc_channel *c)
{
	int i;

	for (i = 0; i < c->qp.rq_num; i++)
		clear_bit(XSC_ETH_RQ_STATE_ENABLED, &c->qp.rq[i].state);
}

void xsc_eth_activate_channel(struct xsc_channel *c)
{
	xsc_eth_activate_txqsq(c);
	xsc_activate_rq(c);
}

void xsc_eth_deactivate_channel(struct xsc_channel *c)
{
	xsc_deactivate_rq(c);
	xsc_eth_deactivate_txqsq(c);
}

static void xsc_eth_activate_channels(struct xsc_eth_channels *chs)
{
	int i;

	for (i = 0; i < chs->num_chl; i++)
		xsc_eth_activate_channel(&chs->c[i]);
}

static void xsc_eth_deactivate_channels(struct xsc_eth_channels *chs)
{
	int i;

	for (i = 0; i < chs->num_chl; i++)
		xsc_eth_deactivate_channel(&chs->c[i]);

	/* Sync with all NAPIs to wait until they stop using queues. */
	synchronize_net();

	for (i = 0; i < chs->num_chl; i++)
		/* last doorbell out */
		napi_disable(&chs->c[i].napi);
}

static void xsc_eth_build_tx2sq_maps(struct xsc_adapter *adapter)
{
	struct xsc_channel *c;
	struct xsc_sq *psq;
	int i, tc;

	for (i = 0; i < adapter->channels.num_chl; i++) {
		c = &adapter->channels.c[i];
		for (tc = 0; tc < c->num_tc; tc++) {
			psq = &c->qp.sq[tc];
			adapter->txq2sq[psq->txq_ix] = psq;
			adapter->channel_tc2realtxq[i][tc] =
					i + tc * adapter->channels.num_chl;
		}
	}
}

void xsc_eth_activate_priv_channels(struct xsc_adapter *adapter)
{
	int num_txqs;
	struct net_device *netdev = adapter->netdev;

	num_txqs = adapter->channels.num_chl * adapter->nic_param.num_tc;
	xsc_netdev_set_tcs(adapter, adapter->channels.num_chl, adapter->nic_param.num_tc);
	netif_set_real_num_tx_queues(netdev, num_txqs);
	netif_set_real_num_rx_queues(netdev, adapter->channels.num_chl);

	xsc_eth_build_tx2sq_maps(adapter);
	xsc_eth_activate_channels(&adapter->channels);
	netif_tx_start_all_queues(adapter->netdev);
}

void xsc_eth_deactivate_priv_channels(struct xsc_adapter *adapter)
{
	netif_tx_disable(adapter->netdev);
	xsc_eth_deactivate_channels(&adapter->channels);
}

static int xsc_eth_sw_init(struct xsc_adapter *adapter)
{
	int ret;

	ret = xsc_eth_open_channels(adapter);
	if (ret)
		return ret;

	xsc_eth_activate_priv_channels(adapter);

	return 0;
}

static void xsc_eth_close_channel(struct xsc_channel *c, bool free_rq)
{
	int i;

	for (i = 0; i < c->qp.rq_num; i++) {
		if (free_rq)
			xsc_eth_close_qp_rq(c, &c->qp.rq[i]);
		xsc_eth_close_cq(c, &c->qp.rq[i].cq);
		memset(&c->qp.rq[i], 0, sizeof(struct xsc_rq));
	}

	for (i = 0; i < c->qp.sq_num; i++) {
		xsc_eth_close_qp_sq(c, &c->qp.sq[i]);
		xsc_eth_close_cq(c, &c->qp.sq[i].cq);
	}

	netif_napi_del(&c->napi);
}

static void xsc_eth_close_channels(struct xsc_adapter *adapter)
{
	int i;
	struct xsc_channel *c = NULL;

	for (i = 0; i < adapter->channels.num_chl; i++) {
		c = &adapter->channels.c[i];
		xsc_core_dbg(adapter->xdev, "start to close channel%d\n", c->chl_idx);

		xsc_eth_close_channel(c, true);
	}

	kfree(adapter->channels.c);
	adapter->channels.num_chl = 0;
}

static void xsc_eth_sw_deinit(struct xsc_adapter *adapter)
{
	xsc_eth_deactivate_priv_channels(adapter);

	return xsc_eth_close_channels(adapter);
}

static void xsc_eth_set_port_status(struct xsc_core_device *xdev,
				    enum xsc_port_status status)
{
}

int xsc_eth_set_led_status(int id, struct xsc_adapter *adapter)
{
	int err;

	struct xsc_event_set_led_status_mbox_in in;
	struct xsc_event_set_led_status_mbox_out out;

	/*query linkstatus cmd*/
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_SET_LED_STATUS);
	in.port_id = id;

	err = xsc_cmd_exec(adapter->xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.status) {
		xsc_core_err(adapter->xdev, "failed to set led to %d, err=%d, status=%d\n",
			     id, err, out.status);
		return -1;
	}

	return 0;
}

bool xsc_eth_get_link_status(struct xsc_adapter *adapter)
{
	struct xsc_event_query_linkstatus_mbox_in in;
	struct xsc_event_query_linkstatus_mbox_out out;
	int err;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_PHYPORT_STATE);

	err = xsc_cmd_exec(adapter->xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(adapter->xdev, "failed to get link status, err=%d, status=%d\n",
			     err, out.hdr.status);
		return false;
	}

	xsc_core_dbg(adapter->xdev, "link_status=%d\n", out.ctx.linkstatus);

	return out.ctx.linkstatus ? true : false;
}

int xsc_eth_get_link_info(struct xsc_adapter *adapter,
			  struct xsc_event_linkinfo *plinkinfo)
{
	struct xsc_event_query_linkinfo_mbox_in in;
	struct xsc_event_query_linkinfo_mbox_out out;
	int i, err;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_LINK_INFO);

	err = xsc_cmd_exec(adapter->xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(adapter->xdev, "failed to get link info, err=%d, status=%d\n",
			     err, out.hdr.status);
		return -ENOEXEC;
	}

	memcpy(plinkinfo, &out.ctx, sizeof(*plinkinfo));

	plinkinfo->linkspeed = be32_to_cpu(plinkinfo->linkspeed);
	plinkinfo->supported = be64_to_cpu(plinkinfo->supported);
	plinkinfo->advertising = be64_to_cpu(plinkinfo->advertising);
	for (i = 0; i < ARRAY_SIZE(plinkinfo->supported_speed); i++) {
		plinkinfo->supported_speed[i] = be64_to_cpu(plinkinfo->supported_speed[i]);
		plinkinfo->advertising_speed[i] = be64_to_cpu(plinkinfo->advertising_speed[i]);
	}

	return 0;
}

int xsc_eth_set_link_info(struct xsc_adapter *adapter,
			  struct xsc_event_linkinfo *plinkinfo)
{
	struct xsc_event_modify_linkinfo_mbox_in in;
	struct xsc_event_modify_linkinfo_mbox_out out;
	int err = 0;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_LINK_INFO);
	memcpy(&in.ctx, plinkinfo, sizeof(*plinkinfo));

	err = xsc_cmd_exec(adapter->xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(adapter->xdev, "failed to set link info, err=%d, status=%d\n",
			     err, out.hdr.status);
		return -ENOEXEC;
	}

	return err;
}

int xsc_get_link_speed(struct xsc_core_device *dev)
{
	struct xsc_adapter *adapter = netdev_priv(dev->netdev);
	struct xsc_event_linkinfo linkinfo;

	if (xsc_eth_get_link_info(adapter, &linkinfo)) {
		xsc_core_err(adapter->xdev, "fail to get linkspeed, return 25G\n");
		return MODULE_SPEED_25G;
	}

	return linkinfo.linkspeed;
}
EXPORT_SYMBOL(xsc_get_link_speed);

#if defined(MSIX_SUPPORT)
int xsc_eth_change_link_status(struct xsc_adapter *adapter)
{
	bool link_up;

	link_up = xsc_eth_get_link_status(adapter);

	if (link_up && !netif_carrier_ok(adapter->netdev)) {
		netdev_info(adapter->netdev, "Link up\n");
		netif_carrier_on(adapter->netdev);
	} else if (!link_up && netif_carrier_ok(adapter->netdev)) {
		netdev_info(adapter->netdev, "Link down\n");
		netif_carrier_off(adapter->netdev);
	}

	return 0;
}

static void xsc_eth_event_work(struct work_struct *work)
{
	int err;
	struct xsc_event_query_type_mbox_in in;
	struct xsc_event_query_type_mbox_out out;
	struct xsc_adapter *adapter = container_of(work, struct xsc_adapter, event_work);

	if (adapter->status != XSCALE_ETH_DRIVER_OK)
		return;

	/*query cmd_type cmd*/
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_EVENT_TYPE);

	err = xsc_cmd_exec(adapter->xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(adapter->xdev, "failed to query event type, err=%d, stats=%d\n",
			     err, out.hdr.status);
		goto failed;
	}

	switch (out.ctx.resp_cmd_type) {
	case XSC_CMD_EVENT_RESP_CHANGE_LINK:
		err = xsc_eth_change_link_status(adapter);
		if (err) {
			xsc_core_err(adapter->xdev, "failed to change linkstatus, err=%d\n", err);
			goto failed;
		}

		xsc_core_dbg(adapter->xdev, "event cmdtype=%04x\n", out.ctx.resp_cmd_type);
		break;
	default:
		xsc_core_info(adapter->xdev, "unknown event cmdtype=%04x\n",
			      out.ctx.resp_cmd_type);
		break;
	}

failed:
	return;
}

void xsc_eth_event_handler(void *arg)
{
	struct xsc_adapter *adapter = (struct xsc_adapter *)arg;

	queue_work(adapter->workq, &adapter->event_work);
}
#endif

int xsc_eth_enable_nic_hca(struct xsc_adapter *adapter)
{
	struct xsc_core_device *xdev = adapter->xdev;
	struct net_device *netdev = adapter->netdev;
	struct xsc_cmd_enable_nic_hca_mbox_in in = {};
	struct xsc_cmd_enable_nic_hca_mbox_out out = {};
	u16 caps = 0;
	u16 caps_mask = 0;
	int err;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ENABLE_NIC_HCA);

#ifdef XSC_RSS_SUPPORT
	in.rss.rss_en = 1;
	in.rss.rqn_base = cpu_to_be16(adapter->channels.rqn_base -
				xdev->caps.raweth_rss_qp_id_base);
	in.rss.rqn_num = cpu_to_be16(adapter->channels.num_chl);
	in.rss.hash_tmpl = cpu_to_be32(adapter->rss_params.rss_hash_tmpl);
	in.rss.hfunc = hash_func_type(adapter->rss_params.hfunc);
#else
	in.rss.rss_en = 0;
	if (adapter->channels.c)
		in.rss.rqn_base = cpu_to_be16(adapter->channels.c[0].qp.rq[0].rqn -
			xdev->caps.raweth_rss_qp_id_base);
#endif
	caps_mask |= BIT(XSC_TBM_CAP_RSS);

	if (netdev->features & NETIF_F_RXCSUM)
		caps |= BIT(XSC_TBM_CAP_HASH_PPH);
	caps_mask |= BIT(XSC_TBM_CAP_HASH_PPH);

	if (xsc_get_pp_bypass_res(adapter->xdev, false))
		caps |= BIT(XSC_TBM_CAP_PP_BYPASS);
	caps_mask |= BIT(XSC_TBM_CAP_PP_BYPASS);

	if (xsc_get_pct_drop_config(xdev) && !(netdev->flags & IFF_SLAVE))
		caps |= BIT(XSC_TBM_CAP_PCT_DROP_CONFIG);
	caps_mask |= BIT(XSC_TBM_CAP_PCT_DROP_CONFIG);

	memcpy(in.nic.mac_addr, netdev->dev_addr, ETH_ALEN);

	in.nic.caps = cpu_to_be16(caps);
	in.nic.caps_mask = cpu_to_be16(caps_mask);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "failed!! err=%d, status=%d\n", err, out.hdr.status);
		return -ENOEXEC;
	}

	xsc_core_info(xdev, "caps=0x%x, caps_mask=0x%x\n", caps, caps_mask);

	return 0;
}

int xsc_eth_disable_nic_hca(struct xsc_adapter *adapter)
{
	struct xsc_core_device *xdev = adapter->xdev;
	struct net_device *netdev = adapter->netdev;
	struct xsc_cmd_disable_nic_hca_mbox_in in = {};
	struct xsc_cmd_disable_nic_hca_mbox_out out = {};
	int err;
	u16 caps = 0;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DISABLE_NIC_HCA);

	if (xsc_get_pp_bypass_res(adapter->xdev, false))
		caps |= BIT(XSC_TBM_CAP_PP_BYPASS);

	if (xsc_get_pct_drop_config(xdev) && !(netdev->priv_flags & IFF_BONDING))
		caps |= BIT(XSC_TBM_CAP_PCT_DROP_CONFIG);

	in.nic.caps = cpu_to_be16(caps);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "failed!! err=%d, status=%d\n", err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

void xsc_eth_rss_params_change(struct xsc_adapter *adapter, u32 change, void *modify)
{
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_rss_params *rss = &adapter->rss_params;
	struct xsc_eth_params *params = &adapter->nic_param;
	struct xsc_cmd_modify_nic_hca_mbox_in *in =
		(struct xsc_cmd_modify_nic_hca_mbox_in *)modify;
	u32 hash_field = 0;
	int key_len;
	u8 rss_caps_mask = 0;

	if (change & BIT(XSC_RSS_RXQ_DROP)) {
		in->rss.rqn_base = cpu_to_be16(adapter->channels.rqn_base -
				xdev->caps.raweth_rss_qp_id_base);
		in->rss.rqn_num = 0;
		rss_caps_mask |= BIT(XSC_RSS_RXQ_DROP);
		goto rss_caps;
	}

	if (change & BIT(XSC_RSS_RXQ_UPDATE)) {
		in->rss.rqn_base = cpu_to_be16(adapter->channels.rqn_base -
				xdev->caps.raweth_rss_qp_id_base);
		in->rss.rqn_num = cpu_to_be16(params->num_channels);
		rss_caps_mask |= BIT(XSC_RSS_RXQ_UPDATE);
	}

	if (change & BIT(XSC_RSS_HASH_KEY_UPDATE)) {
		key_len = min(sizeof(in->rss.hash_key), sizeof(rss->toeplitz_hash_key));
		memcpy(&in->rss.hash_key, rss->toeplitz_hash_key, key_len);
		rss_caps_mask |= BIT(XSC_RSS_HASH_KEY_UPDATE);
	}

	if (change & BIT(XSC_RSS_HASH_TEMP_UPDATE)) {
		hash_field = rss->rx_hash_fields[XSC_TT_IPV4_TCP] |
				rss->rx_hash_fields[XSC_TT_IPV6_TCP];
		in->rss.hash_tmpl = cpu_to_be32(hash_field);
		rss_caps_mask |= BIT(XSC_RSS_HASH_TEMP_UPDATE);
	}

	if (change & BIT(XSC_RSS_HASH_FUNC_UPDATE)) {
		in->rss.hfunc = hash_func_type(rss->hfunc);
		rss_caps_mask |= BIT(XSC_RSS_HASH_FUNC_UPDATE);
	}

rss_caps:
	if (rss_caps_mask) {
		in->rss.caps_mask = rss_caps_mask;
		in->rss.rss_en = 1;
		in->nic.caps_mask = cpu_to_be16(BIT(XSC_TBM_CAP_RSS));
		in->nic.caps = in->nic.caps_mask;
	}
}

int xsc_eth_modify_nic_hca(struct xsc_adapter *adapter, u32 flags)
{
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_cmd_modify_nic_hca_mbox_in in = {};
	struct xsc_cmd_modify_nic_hca_mbox_out out = {};
	int err = 0;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_NIC_HCA);

	xsc_eth_rss_params_change(adapter, flags, &in);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "failed!! err=%d, status=%u\n", err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

#ifdef MSIX_SUPPORT
static void xsc_set_default_xps_cpumasks(struct xsc_adapter *priv,
					 struct xsc_eth_params *params)
{
	struct xsc_core_device *xdev = priv->xdev;
	int num_comp_vectors, irq;

	num_comp_vectors = priv->nic_param.comp_vectors;
	cpumask_clear(xdev->xps_cpumask);

	for (irq = 0; irq < num_comp_vectors; irq++) {
		mask_cpu_by_node(xdev->priv.numa_node, xdev->xps_cpumask);
		netif_set_xps_queue(priv->netdev, xdev->xps_cpumask, irq);
	}
}
#endif

int xsc_eth_open(struct net_device *netdev)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	int ret = XSCALE_RET_SUCCESS;

	mutex_lock(&adapter->state_lock);
	if (adapter->status == XSCALE_ETH_DRIVER_OK) {
		xsc_core_warn(adapter->xdev, "unnormal ndo_open when status=%d\n",
			      adapter->status);
		goto ret;
	}

	spin_lock_init(&adapter->lock);

	ret = xsc_eth_sw_init(adapter);
	if (ret)
		goto ret;

	ret = xsc_eth_reset(adapter->xdev);
	if (ret)
		goto sw_deinit;

	ret = xsc_eth_enable_nic_hca(adapter);
	if (ret)
		goto sw_deinit;

#ifdef NEED_CREATE_RX_THREAD
	ret = xsc_eth_rx_thread_create(adapter);
	if (ret) {
		xsc_core_warn(adapter->xdev, "xsc_eth_rx_thread_create failed, err=%d\n", ret);
		goto sw_deinit;
	}
#endif

#if defined(MSIX_SUPPORT)
	if (xsc_core_is_pf(adapter->xdev)) {
		/*INIT_WORK*/
		INIT_WORK(&adapter->event_work, xsc_eth_event_work);
		adapter->xdev->event_handler = xsc_eth_event_handler;

		if (xsc_eth_get_link_status(adapter))	{
			netdev_info(netdev, "Link up\n");
			netif_carrier_on(adapter->netdev);
		} else {
			netdev_info(netdev, "Link down\n");
		}
	} else {
		netif_carrier_on(netdev);
	}
#else
	netif_carrier_on(netdev);
#endif

	adapter->status = XSCALE_ETH_DRIVER_OK;

#ifdef MSIX_SUPPORT
	xsc_set_default_xps_cpumasks(adapter, &adapter->nic_param);
#endif

	goto ret;

sw_deinit:
	xsc_eth_sw_deinit(adapter);

ret:
	mutex_unlock(&adapter->state_lock);
	xsc_core_info(adapter->xdev, "open %s %s, ret=%d\n",
		      netdev->name, ret ? "failed" : "ok", ret);
	if (ret)
		return XSCALE_RET_ERROR;
	else
		return XSCALE_RET_SUCCESS;
}

int xsc_eth_close(struct net_device *netdev)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	int ret = 0;

	mutex_lock(&adapter->state_lock);

	if (!netif_device_present(netdev)) {
		ret = -ENODEV;
		goto ret;
	}

	if (adapter->status != XSCALE_ETH_DRIVER_OK)
		goto ret;

	adapter->status = XSCALE_ETH_DRIVER_CLOSE;

#ifdef NEED_CREATE_RX_THREAD
	if (adapter->task)
		kthread_stop(adapter->task);
#endif

	xsc_eth_set_port_status(adapter->xdev, XSC_PORT_DOWN);
	netif_carrier_off(adapter->netdev);

	xsc_eth_sw_deinit(adapter);

	ret = xsc_eth_disable_nic_hca(adapter);
	if (ret)
		xsc_core_warn(adapter->xdev, "failed to disable nic hca, err=%d\n", ret);

ret:
	mutex_unlock(&adapter->state_lock);
	xsc_core_info(adapter->xdev, "close device %s %s, ret=%d\n",
		      adapter->netdev->name, ret ? "failed" : "ok", ret);

	return ret;
}

static int xsc_eth_set_mac(struct net_device *netdev, void *addr)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	struct sockaddr *saddr = addr;
	struct xsc_core_device *xdev = adapter->xdev;
	int ret;
	u16 vport = xsc_core_is_pf(xdev) ? 0 : (xdev->vf_id + 1);

	if (!is_valid_ether_addr(saddr->sa_data))
		return -EADDRNOTAVAIL;

	ret = xsc_modify_nic_vport_mac_address(xdev, vport, saddr->sa_data, false);
	if (ret)
		xsc_core_err(adapter->xdev, "%s: xsc set mac addr failed\n", __func__);

	netif_addr_lock_bh(netdev);
	eth_hw_addr_set(netdev, saddr->sa_data);
	netif_addr_unlock_bh(netdev);

	return 0;
}

static void xsc_netdev_set_tcs(struct xsc_adapter *priv, u16 nch, u8 ntc)
{
	int tc;

	netdev_reset_tc(priv->netdev);

	if (ntc == 1)
		return;

	netdev_set_num_tc(priv->netdev, ntc);

	/* Map netdev TCs to offset 0
	 * We have our own UP to TXQ mapping for QoS
	 */
	for (tc = 0; tc < ntc; tc++)
		netdev_set_tc_queue(priv->netdev, tc, nch, 0);
}

static int xsc_update_netdev_queues(struct xsc_adapter *priv)
{
	struct net_device *netdev = priv->netdev;
	int num_txqs, num_rxqs, nch, ntc;
	int old_num_txqs, old_ntc;
	int err;
#ifndef HAVE_NET_SYNCHRONIZE_IN_SET_REAL_NUM_TX_QUEUES
	bool disabling;
#endif

	old_num_txqs = netdev->real_num_tx_queues;
	old_ntc = netdev->num_tc ? : 1;

	nch = priv->nic_param.num_channels;
	ntc = priv->nic_param.num_tc;
	num_txqs = nch * ntc;
	num_rxqs = nch;// * priv->profile->rq_groups;

#ifndef HAVE_NET_SYNCHRONIZE_IN_SET_REAL_NUM_TX_QUEUES
	disabling = num_txqs < netdev->real_num_tx_queues;
#endif

	xsc_netdev_set_tcs(priv, nch, ntc);

	err = netif_set_real_num_tx_queues(netdev, num_txqs);
	if (err) {
		netdev_warn(netdev,
			    "netif_set_real_num_tx_queues failed, txqs=%d->%d, tc=%d->%d, err=%d\n",
			    old_num_txqs, num_txqs, old_ntc, ntc, err);
		goto err_tcs;
	}

	err = netif_set_real_num_rx_queues(netdev, num_rxqs);
	if (err) {
		netdev_warn(netdev, "netif_set_real_num_rx_queues failed, rxqs=%d, err=%d\n",
			    num_rxqs, err);
		goto err_txqs;
	}

#ifndef HAVE_NET_SYNCHRONIZE_IN_SET_REAL_NUM_TX_QUEUES
	if (disabling)
		synchronize_net();
#endif

	return 0;

err_txqs:
	/* netif_set_real_num_rx_queues could fail only when nch increased. Only
	 * one of nch and ntc is changed in this function. That means, the call
	 * to netif_set_real_num_tx_queues below should not fail, because it
	 * decreases the number of TX queues.
	 */
	WARN_ON_ONCE(netif_set_real_num_tx_queues(netdev, old_num_txqs));

err_tcs:
	xsc_netdev_set_tcs(priv, old_num_txqs / old_ntc, old_ntc);
	return err;
}

void xsc_build_default_indir_rqt(u32 *indirection_rqt, int len,
				 int num_channels)
{
	int i;

	for (i = 0; i < len; i++)
		indirection_rqt[i] = i % num_channels;
}

int xsc_eth_num_channels_changed(struct xsc_adapter *priv)
{
	struct net_device *netdev = priv->netdev;
	u16 count = priv->nic_param.num_channels;
	int err;

	err = xsc_update_netdev_queues(priv);
	if (err)
		goto err;

	if (!netif_is_rxfh_configured(priv->netdev))
		xsc_build_default_indir_rqt(priv->rss_params.indirection_rqt,
					    XSC_INDIR_RQT_SIZE, count);

	return 0;

err:
	netdev_err(netdev, "%s: failed to change rss rxq number %d, err=%d\n",
		   __func__, count, err);
	return err;
}

int xsc_safe_switch_channels(struct xsc_adapter *adapter,
			     xsc_eth_fp_preactivate preactivate,
			     xsc_eth_fp_postactivate postactivate)
{
	struct net_device *netdev = adapter->netdev;
	int carrier_ok;
	int ret = 0;

	adapter->status = XSCALE_ETH_DRIVER_CLOSE;

	carrier_ok = netif_carrier_ok(netdev);
	netif_carrier_off(netdev);
#ifdef NEED_CREATE_RX_THREAD
	if (adapter->task)
		kthread_stop(adapter->task);
#endif
	ret = xsc_eth_modify_nic_hca(adapter, BIT(XSC_RSS_RXQ_DROP));
	if (ret)
		goto close_channels;

	xsc_eth_deactivate_priv_channels(adapter);
	xsc_eth_close_channels(adapter);

	if (preactivate) {
		ret = preactivate(adapter);
		if (ret)
			goto out;
	}

	ret = xsc_eth_open_channels(adapter);
	if (ret)
		goto close_channels;

	if (postactivate) {
		ret = postactivate(adapter);
		if (ret)
			goto close_channels;
	}

	xsc_eth_activate_priv_channels(adapter);
	ret = xsc_eth_modify_nic_hca(adapter, BIT(XSC_RSS_RXQ_UPDATE));
	if (ret)
		goto close_channels;

#ifdef NEED_CREATE_RX_THREAD
	ret = xsc_eth_rx_thread_create(adapter);
	if (ret)
		goto close_channels;
#endif

	adapter->status = XSCALE_ETH_DRIVER_OK;

	goto out;

close_channels:
	xsc_eth_deactivate_priv_channels(adapter);
	xsc_eth_close_channels(adapter);

out:
	if (carrier_ok)
		netif_carrier_on(netdev);
	xsc_core_dbg(adapter->xdev, "channels=%d, mtu=%d, err=%d\n",
		     adapter->nic_param.num_channels,
		     adapter->nic_param.mtu, ret);
	return ret;
}

int xsc_eth_nic_mtu_changed(struct xsc_adapter *priv)
{
	u32 new_mtu = priv->nic_param.mtu;
	int ret;

	ret = xsc_eth_set_hw_mtu(priv->xdev, XSC_SW2HW_MTU(new_mtu),
				 XSC_SW2HW_RX_PKT_LEN(new_mtu));

	return ret;
}

static int xsc_eth_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	int old_mtu = netdev->mtu;
	int ret = 0;
	int max_buf_len = 0;

#ifdef HAVE_NETDEV_OPS_EXTEND
	if (new_mtu > netdev->extended->max_mtu || new_mtu < netdev->extended->min_mtu) {
		netdev_err(netdev, "%s: Bad MTU (%d), valid range is: [%d..%d]\n",
			   __func__, new_mtu, netdev->extended->min_mtu, netdev->extended->max_mtu);
		return -EINVAL;
	}
#else
	if (new_mtu > netdev->max_mtu || new_mtu < netdev->min_mtu) {
		netdev_err(netdev, "%s: Bad MTU (%d), valid range is: [%d..%d]\n",
			   __func__, new_mtu, netdev->min_mtu, netdev->max_mtu);
		return -EINVAL;
	}
#endif

	if (!xsc_rx_is_linear_skb(new_mtu)) {
		max_buf_len = adapter->xdev->caps.recv_ds_num * PAGE_SIZE;
		if (new_mtu > max_buf_len) {
			netdev_err(netdev, "Bad MTU (%d), max buf len is %d\n",
				   new_mtu, max_buf_len);
			return -EINVAL;
		}
	}
	mutex_lock(&adapter->state_lock);
	adapter->nic_param.mtu = new_mtu;
	if (adapter->status != XSCALE_ETH_DRIVER_OK) {
		ret = xsc_eth_nic_mtu_changed(adapter);
		if (ret)
			adapter->nic_param.mtu = old_mtu;
		else
			netdev->mtu = adapter->nic_param.mtu;
		goto out;
	}

	ret = xsc_safe_switch_channels(adapter, xsc_eth_nic_mtu_changed, NULL);
	if (ret)
		goto out;

	netdev->mtu = adapter->nic_param.mtu;

out:
	mutex_unlock(&adapter->state_lock);
	xsc_core_info(adapter->xdev, "mtu change from %d to %d, new_mtu=%d, err=%d\n",
		      old_mtu, netdev->mtu, new_mtu, ret);
	return ret;
}

static void xsc_get_stats(struct net_device *netdev, struct rtnl_link_stats64 *stats)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);

	xsc_fold_sw_stats64(adapter, stats);
}

int xsc_set_vf_mac(struct net_device *netdev, int vf, u8 *mac)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	struct xsc_core_sriov *sriov = &adapter->xdev->priv.sriov;
	struct xsc_core_device *xdev = adapter->xdev;
	int ret;

	if (vf >= sriov->num_vfs)
		return -EINVAL;

	ret = xsc_eswitch_set_vport_mac(xdev->priv.eswitch, vf + 1, mac);
	if (ret)
		xsc_core_err(xdev, "xsc set mac addr failed\n");

	return ret;
}

int xsc_get_vf_config(struct net_device *dev,
		      int vf, struct ifla_vf_info *ivi)
{
	struct xsc_adapter *adapter = netdev_priv(dev);
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_eswitch *esw = xdev->priv.eswitch;
	int err;

	if (!netif_device_present(dev))
		return -EOPNOTSUPP;

	err = xsc_eswitch_get_vport_config(esw, vf + 1, ivi);

	return err;
}

int set_feature_rxcsum(struct net_device *netdev, bool enable)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_cmd_modify_nic_hca_mbox_in in = {};
	struct xsc_cmd_modify_nic_hca_mbox_out out = {};
	int err;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_NIC_HCA);
	in.nic.caps_mask = cpu_to_be16(BIT(XSC_TBM_CAP_HASH_PPH));
	in.nic.caps = cpu_to_be16(enable << XSC_TBM_CAP_HASH_PPH);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		netdev_err(netdev, "failed to change rxcsum=%d, err=%d, status=%d\n",
			   enable, err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

static int xsc_handle_feature(struct net_device *netdev,
			      netdev_features_t *features,
			      netdev_features_t wanted_features,
			      netdev_features_t feature,
			      xsc_feature_handler feature_handler)
{
	netdev_features_t changes = wanted_features ^ netdev->features;
	bool enable = !!(wanted_features & feature);
	int err;

	if (!(changes & feature))
		return 0;

	err = feature_handler(netdev, enable);
	if (err) {
		netdev_err(netdev, "%s feature %pNF failed, err %d\n",
			   enable ? "Enable" : "Disable", &feature, err);
		return err;
	}

	xsc_set_feature(features, feature, enable);

	return 0;
}

int xsc_eth_set_features(struct net_device *netdev, netdev_features_t features)
{
	netdev_features_t oper_features = netdev->features;
	int err = 0;

#define XSC_HANDLE_FEATURE(feature, handler) \
	xsc_handle_feature(netdev, &oper_features, features, feature, handler)

	err |= XSC_HANDLE_FEATURE(NETIF_F_RXCSUM, set_feature_rxcsum);
	if (err) {
		netdev->features = oper_features;
		return -EINVAL;
	}

	return 0;
}

#ifdef HAVE_NETDEVICE_OPS_SELECT_QUEUE_FALLBACK
#ifdef HAVE_NETDEV_OPS_EXTEND
u16 xsc_select_queue(struct net_device *dev, struct sk_buff *skb,
		     void *accel_priv,
		     select_queue_fallback_t fallback)
#else
u16 xsc_select_queue(struct net_device *dev, struct sk_buff *skb,
		     struct net_device *sb_dev,
		     select_queue_fallback_t fallback)
#endif
{
#ifdef HAVE_NETDEV_OPS_EXTEND
	int txq_ix = fallback(dev, skb);
#else
	int txq_ix = fallback(dev, skb, NULL);
#endif
	u16 num_channels;
	int up = 0;
	struct xsc_adapter *adapter = netdev_priv(dev);

	if (!adapter) {
		pr_err("%s adapter is null\n", __func__);
		return txq_ix;
	}

	if (!netdev_get_num_tc(dev))
		return txq_ix;

	if (skb_vlan_tag_present(skb)) {
		up = skb->vlan_tci >> VLAN_PRIO_SHIFT;
		if (adapter->nic_param.num_tc > 1)
			up = up % (adapter->nic_param.num_tc - 1) + 1;
		else
			up = 0;
	}

	/* channel_ix can be larger than num_channels since
	 * dev->num_real_tx_queues = num_channels * num_tc
	 */
	num_channels = adapter->channels.num_chl;
	if (txq_ix >= num_channels)
		txq_ix = adapter->txq2sq[txq_ix]->ch_ix;

	return adapter->channel_tc2realtxq[txq_ix][up];
}
#else
u16 xsc_select_queue(struct net_device *dev, struct sk_buff *skb,
		     struct net_device *sb_dev)
{
	int txq_ix, up = 0;
	u16 num_channels;
	struct xsc_adapter *adapter = netdev_priv(dev);

	if (!adapter) {
		pr_err("%s adapter is null\n", __func__);
		return txq_ix;
	}

	txq_ix = netdev_pick_tx(dev, skb, NULL);
	if (!netdev_get_num_tc(dev))
		return txq_ix;

	if (skb_vlan_tag_present(skb)) {
		up = skb_vlan_tag_get_prio(skb);
		if (adapter->nic_param.num_tc > 1)
			up = up % (adapter->nic_param.num_tc - 1) + 1;
		else
			up = 0;
	}

	/* channel_ix can be larger than num_channels since
	 * dev->num_real_tx_queues = num_channels * num_tc
	 */
	num_channels = adapter->channels.num_chl;
	if (txq_ix >= num_channels)
		txq_ix = adapter->txq2sq[txq_ix]->ch_ix;

	return adapter->channel_tc2realtxq[txq_ix][up];
}
#endif

static int xsc_get_phys_port_name(struct net_device *dev,
				  char *buf, size_t len)
{
	struct xsc_adapter *adapter = netdev_priv(dev);
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_core_device *pf_xdev;
	struct net_device *pf_netdev;
	struct pci_dev *pdev = xdev->pdev;
	int ret = len;

	if (!pdev)
		return -EOPNOTSUPP;
	if (!xsc_core_is_pf(xdev)) {
		if (!pdev->physfn)
			return -EOPNOTSUPP;
		pf_xdev = pci_get_drvdata(pdev->physfn);
		if (!pf_xdev || !pf_xdev->netdev)
			return -EOPNOTSUPP;
		pf_netdev = (struct net_device *)pf_xdev->netdev;
		ret = snprintf(buf, len, "%s_%d",
			       pf_netdev->name, xdev->vf_id);
	} else {
		return -EOPNOTSUPP;
	}
	if (ret >= len)
		return -EOPNOTSUPP;

	return 0;
}

static const struct net_device_ops xsc_netdev_ops = {
	.ndo_open		= xsc_eth_open,
	.ndo_stop		= xsc_eth_close,
	.ndo_start_xmit		= xsc_eth_xmit_start,

	.ndo_set_rx_mode	= NULL,
	.ndo_validate_addr	= NULL,
	.ndo_set_mac_address	= xsc_eth_set_mac,
#ifdef HAVE_NETDEV_OPS_EXTEND
	.extended.ndo_change_mtu = xsc_eth_change_mtu,
#else
	.ndo_change_mtu = xsc_eth_change_mtu,
#endif

	.ndo_tx_timeout		= NULL,
#ifdef HAVE_NETDEV_OPS_EXTEND
	.extended.ndo_set_tx_maxrate	= NULL,
#else
	.ndo_set_tx_maxrate		= NULL,
#endif
	.ndo_vlan_rx_add_vid	= xsc_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= xsc_vlan_rx_kill_vid,
	.ndo_do_ioctl		= NULL,
	.ndo_set_vf_mac		= xsc_set_vf_mac,
#ifdef HAVE_NETDEV_OPS_EXTEND
	.extended.ndo_set_vf_vlan	= NULL,
#else
	.ndo_set_vf_vlan		= NULL,
#endif
	.ndo_set_vf_rate	= NULL,
	.ndo_set_vf_spoofchk	= NULL,
	.ndo_set_vf_rss_query_en = NULL,
#ifdef HAVE_NETDEV_OPS_EXTEND
	.extended.ndo_set_vf_trust = NULL,
#else
	.ndo_set_vf_trust	= NULL,
#endif
#ifdef NETLINK_MIN_DUMP_ALLOC_U32
	.ndo_get_vf_config	= xsc_get_vf_config,
#endif
	.ndo_get_stats64	= xsc_get_stats,
#ifdef HAVE_NETDEV_OPS_EXTEND
	.extended.ndo_setup_tc_rh	= NULL,
#else
	.ndo_setup_tc			= NULL,
#endif
	.ndo_set_features = xsc_eth_set_features,
	.ndo_fix_features = NULL,
	.ndo_fdb_add		= NULL,
	.ndo_bridge_setlink	= NULL,
	.ndo_bridge_getlink	= NULL,
#ifdef HAVE_NETDEV_OPS_EXTEND
	.extended.ndo_dfwd_add_station	= NULL,
	.extended.ndo_dfwd_del_station	= NULL,
	.extended.ndo_bpf	= NULL,
	.extended.ndo_xdp_xmit	= NULL,
	.extended.ndo_get_phys_port_name  = xsc_get_phys_port_name,
#else
	.ndo_dfwd_add_station	= NULL,
	.ndo_dfwd_del_station	= NULL,
	.ndo_bpf                = NULL,
	.ndo_xdp_xmit           = NULL,
	.ndo_get_phys_port_name  = xsc_get_phys_port_name,
#endif

#ifdef HAVE_NETDEVICE_OPS_UDP_TUNNEL
#ifdef HAVE_NETDEV_OPS_EXTEND
	.extended.ndo_udp_tunnel_add = NULL,
	.extended.ndo_udp_tunnel_del = NULL,
#else
	.ndo_udp_tunnel_add	= NULL,
	.ndo_udp_tunnel_del	= NULL,
#endif
#endif
	.ndo_features_check	= NULL,
	.ndo_select_queue	= xsc_select_queue,
};

static int xsc_eth_check_required_cap(struct xsc_core_device *xdev)
{
	int err = -1;

	/*get cap from hw*/

	err = 0;
	return err;
}

static int xsc_get_max_num_channels(struct xsc_core_device *xdev)
{
#ifdef NEED_CREATE_RX_THREAD
	return 8;
#else
	return min_t(int, xdev->dev_res->eq_table.num_comp_vectors,
			XSC_ETH_MAX_NUM_CHANNELS);
#endif
}

static int xsc_eth_netdev_init(struct xsc_adapter *adapter)
{
	unsigned int node, tc, nch;

	tc = adapter->nic_param.num_tc;
	nch = adapter->nic_param.max_num_ch;
	node = dev_to_node(adapter->dev);
	adapter->txq2sq = kcalloc_node(nch * tc,
				       sizeof(*adapter->txq2sq), GFP_KERNEL, node);
	if (!adapter->txq2sq)
		goto err_out;

	mutex_init(&adapter->state_lock);

	/*INIT_WORK*/
	adapter->workq = create_singlethread_workqueue("xsc_eth");
	if (!adapter->workq)
		goto err_free_priv;

	netif_carrier_off(adapter->netdev);

	return 0;

err_free_priv:
	kfree(adapter->txq2sq);
err_out:
	return -ENOMEM;
}

static const struct xsc_tirc_config tirc_default_config[XSC_NUM_INDIR_TIRS] = {
	[XSC_TT_IPV4] = {
				.l3_prot_type = XSC_L3_PROT_TYPE_IPV4,
				.l4_prot_type = 0,
				.rx_hash_fields = XSC_HASH_IP,
	},
	[XSC_TT_IPV4_TCP] = {
				.l3_prot_type = XSC_L3_PROT_TYPE_IPV4,
				.l4_prot_type = XSC_L4_PROT_TYPE_TCP,
				.rx_hash_fields = XSC_HASH_IP_PORTS,
	},
	[XSC_TT_IPV4_UDP] = {
				.l3_prot_type = XSC_L3_PROT_TYPE_IPV4,
				.l4_prot_type = XSC_L4_PROT_TYPE_UDP,
				.rx_hash_fields = XSC_HASH_IP_PORTS,
	},
	[XSC_TT_IPV6] = {
				.l3_prot_type = XSC_L3_PROT_TYPE_IPV6,
				.l4_prot_type = 0,
				.rx_hash_fields = XSC_HASH_IP6,
	},
	[XSC_TT_IPV6_TCP] = {
				.l3_prot_type = XSC_L3_PROT_TYPE_IPV6,
				.l4_prot_type = XSC_L4_PROT_TYPE_TCP,
				.rx_hash_fields = XSC_HASH_IP6_PORTS,
	},
	[XSC_TT_IPV6_UDP] = {
				.l3_prot_type = XSC_L3_PROT_TYPE_IPV6,
				.l4_prot_type = XSC_L4_PROT_TYPE_UDP,
				.rx_hash_fields = XSC_HASH_IP6_PORTS,
	},
};

struct xsc_tirc_config xsc_tirc_get_default_config(enum xsc_traffic_types tt)
{
	return tirc_default_config[tt];
}

void xsc_build_rss_params(struct xsc_rss_params *rss_params, u16 num_channels)
{
	enum xsc_traffic_types tt;

	rss_params->hfunc = ETH_RSS_HASH_TOP;
	netdev_rss_key_fill(rss_params->toeplitz_hash_key,
			    sizeof(rss_params->toeplitz_hash_key));

	xsc_build_default_indir_rqt(rss_params->indirection_rqt,
				    XSC_INDIR_RQT_SIZE, num_channels);

	for (tt = 0; tt < XSC_NUM_INDIR_TIRS; tt++) {
		rss_params->rx_hash_fields[tt] =
			tirc_default_config[tt].rx_hash_fields;
	}
	rss_params->rss_hash_tmpl = XSC_HASH_IP_PORTS | XSC_HASH_IP6_PORTS;
}

void xsc_eth_build_nic_params(struct xsc_adapter *adapter, u32 ch_num, u32 tc_num)
{
	struct xsc_core_device *xdev = adapter->xdev;

	adapter->nic_param.mtu = SW_DEFAULT_MTU;
	adapter->nic_param.num_tc = tc_num;

	adapter->nic_param.comp_vectors = xdev->dev_res->eq_table.num_comp_vectors;
	adapter->nic_param.max_num_ch = ch_num;
	adapter->nic_param.num_channels = ch_num;

	adapter->nic_param.rq_max_size = BIT(xdev->caps.log_max_qp_depth);
	adapter->nic_param.sq_max_size = BIT(xdev->caps.log_max_qp_depth);

	xsc_build_rss_params(&adapter->rss_params, adapter->nic_param.num_channels);
	xsc_core_info(xdev, "mtu=%d, num_ch=%d(max=%d), num_tc=%d\n",
		      adapter->nic_param.mtu,
		      adapter->nic_param.num_channels,
		      adapter->nic_param.max_num_ch,
		      adapter->nic_param.num_tc);
}

void xsc_eth_build_nic_netdev(struct xsc_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct xsc_core_device *xdev = adapter->xdev;

	/* Set up network device as normal. */
	netdev->priv_flags |= IFF_UNICAST_FLT | IFF_LIVE_ADDR_CHANGE;
	netdev->netdev_ops = &xsc_netdev_ops;

#ifdef CONFIG_XSC_CORE_EN_DCB
	netdev->dcbnl_ops = &xsc_dcbnl_ops;
#endif
	eth_set_ethtool_ops(netdev);

#ifdef HAVE_NETDEV_OPS_EXTEND
	netdev->extended->min_mtu = SW_MIN_MTU;
	netdev->extended->max_mtu = SW_MAX_MTU;
#else
	netdev->min_mtu = SW_MIN_MTU;
	netdev->max_mtu = SW_MAX_MTU;
#endif
	/*mtu - macheaderlen - ipheaderlen should be aligned in 8B*/
	netdev->mtu = SW_DEFAULT_MTU;

	netdev->vlan_features |= NETIF_F_SG;
	netdev->vlan_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;//NETIF_F_HW_CSUM;
	netdev->vlan_features |= NETIF_F_GRO;
	netdev->vlan_features |= NETIF_F_TSO;//NETIF_F_TSO_ECN
	netdev->vlan_features |= NETIF_F_TSO6;
	netdev->vlan_features |= NETIF_F_RXCSUM;
	netdev->vlan_features |= NETIF_F_RXHASH;
	netdev->vlan_features |= NETIF_F_GSO_PARTIAL;

	netdev->hw_features = netdev->vlan_features;
	netdev->hw_features |= NETIF_F_HW_VLAN_CTAG_FILTER;

	if (xsc_vxlan_allowed(xdev) || xsc_geneve_tx_allowed(xdev) ||
	    xsc_any_tunnel_proto_supported(xdev)) {
		netdev->hw_enc_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
		netdev->hw_enc_features |= NETIF_F_TSO; //NETIF_F_TSO_ECN
		netdev->hw_enc_features |= NETIF_F_TSO6;
		netdev->hw_enc_features |= NETIF_F_GSO_PARTIAL;
	}

	netdev->features |= netdev->hw_features;
	netdev->features |= NETIF_F_HIGHDMA;
}

static int xsc_eth_nic_init(struct xsc_adapter *adapter,
			    void *rep_priv, u32 ch_num, u32 tc_num)
{
	int err = -1;

	xsc_eth_build_nic_params(adapter, ch_num, tc_num);

	err = xsc_eth_netdev_init(adapter);
	if (err)
		return err;

	adapter->workq = create_singlethread_workqueue("xsc_eth");
	if (!adapter->workq)
		return err;

	xsc_eth_build_nic_netdev(adapter);

	return 0;
}

static void xsc_eth_nic_cleanup(struct xsc_adapter *adapter)
{
	destroy_workqueue(adapter->workq);
	kfree(adapter->txq2sq);
}

/* create xdev resource,pd/domain/mkey */
int xsc_eth_create_xdev_resources(struct xsc_core_device *xdev)
{
	return 0;
}

static int xsc_eth_init_nic_tx(struct xsc_adapter *adapter)
{
	/*create tis table*/
#ifdef CONFIG_XSC_CORE_EN_DCB
	xsc_dcbnl_initialize(adapter);
#endif

	return 0;
}

static int xsc_eth_cleanup_nic_tx(struct xsc_adapter *adapter)
{
	return 0;
}

/* init tx: create hw resource, set register according to spec */
int xsc_eth_init_nic_rx(struct xsc_adapter *adapter)
{
	/* create rqt and tir table
	 * tir table:base on traffic type like ip4_tcp/ipv6_tcp/
	 * each rqt table for a traffic type
	 */

	return 0;
}

static int xsc_eth_cleanup_nic_rx(struct xsc_adapter *adapter)
{
	return 0;
}

static void xsc_eth_l2_addr_init(struct xsc_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	char mac[6] = {0};
	int ret = 0;

	ret = xsc_eth_get_mac(adapter->xdev, mac);
	if (ret) {
		xsc_core_warn(adapter->xdev, "get mac failed %d, generate random mac...", ret);
		eth_random_addr(mac);
	}
	dev_addr_mod(netdev, 0, mac, 6);

	if (!is_valid_ether_addr(netdev->perm_addr))
		memcpy(netdev->perm_addr, netdev->dev_addr, netdev->addr_len);
}

static int xsc_eth_nic_enable(struct xsc_adapter *adapter)
{
	struct xsc_core_device *xdev = adapter->xdev;

	xsc_lag_add(xdev, adapter->netdev);

	xsc_eth_l2_addr_init(adapter);

	xsc_eth_set_hw_mtu(xdev, XSC_SW2HW_MTU(adapter->nic_param.mtu),
			   XSC_SW2HW_RX_PKT_LEN(adapter->nic_param.mtu));

#ifdef CONFIG_XSC_CORE_EN_DCB
	xsc_dcbnl_init_app(adapter);
#endif

	xsc_eth_set_port_status(xdev, XSC_PORT_UP);

	rtnl_lock();
	netif_device_attach(adapter->netdev);
	rtnl_unlock();

	return 0;
}

static void xsc_eth_nic_disable(struct xsc_adapter *adapter)
{
	rtnl_lock();
	if (netif_running(adapter->netdev))
		xsc_eth_close(adapter->netdev);
	netif_device_detach(adapter->netdev);
	rtnl_unlock();

	xsc_lag_remove(adapter->xdev);
}

/* call init tx/rx, enable function about nic init */
static int xsc_attach_netdev(struct xsc_adapter *adapter)
{
	int err = -1;

	err = xsc_eth_init_nic_tx(adapter);
	if (err)
		return err;

	err = xsc_eth_init_nic_rx(adapter);
	if (err)
		return err;

	err = xsc_eth_nic_enable(adapter);
	if (err)
		return err;

	xsc_core_info(adapter->xdev, "%s ok\n", __func__);
	return 0;
}

static void xsc_detach_netdev(struct xsc_adapter *adapter)
{
	xsc_eth_nic_disable(adapter);

	flush_workqueue(adapter->workq);

	xsc_eth_cleanup_nic_rx(adapter);
	xsc_eth_cleanup_nic_tx(adapter);
	adapter->status = XSCALE_ETH_DRIVER_DETACH;
}

static int xsc_eth_attach(struct xsc_core_device *xdev, struct xsc_adapter *adapter)
{
	int err = -1;

	if (netif_device_present(adapter->netdev))
		return 0;

	err = xsc_eth_create_xdev_resources(xdev);
	if (err)
		return err;

	err = xsc_attach_netdev(adapter);
	if (err)
		return err;

	xsc_core_info(adapter->xdev, "%s ok\n", __func__);
	return 0;
}

static void xsc_eth_detach(struct xsc_core_device *xdev, struct xsc_adapter *adapter)
{
	if (!netif_device_present(adapter->netdev))
		return;

	xsc_detach_netdev(adapter);
}

static void *xsc_eth_add(struct xsc_core_device *xdev)
{
	int err = -1;
	int num_chl, num_tc;
	struct net_device *netdev;
	struct xsc_adapter *adapter = NULL;
	void *rep_priv = NULL;

	err = xsc_eth_check_required_cap(xdev);
	if (err)
		return NULL;

	num_chl = xsc_get_max_num_channels(xdev);
	num_tc = xdev->caps.max_tc;

	/* Allocate ourselves a network device with room for our info */
	netdev = alloc_etherdev_mqs(sizeof(struct xsc_adapter),
				    num_chl * num_tc, num_chl);
	if (unlikely(!netdev)) {
		xsc_core_warn(xdev, "alloc_etherdev_mqs failed, txq=%d, rxq=%d\n",
			      (num_chl * num_tc), num_chl);
		return NULL;
	}

	/* Set up our device-specific information */
	netdev->dev.parent = &xdev->pdev->dev;
	adapter = netdev_priv(netdev);
	adapter->netdev = netdev;
	adapter->pdev = xdev->pdev;
	adapter->dev = &adapter->pdev->dev;
	adapter->xdev = (void *)xdev;
	xdev->eth_priv = adapter;

	err = xsc_eth_nic_init(adapter, rep_priv, num_chl, num_tc);
	if (err) {
		xsc_core_warn(xdev, "xsc_nic_init failed, num_ch=%d, num_tc=%d, err=%d\n",
			      num_chl, num_tc, err);
		goto err_free_netdev;
	}

	err = xsc_eth_attach(xdev, adapter);
	if (err) {
		xsc_core_warn(xdev, "xsc_eth_attach failed, err=%d\n", err);
		goto err_cleanup_netdev;
	}

	adapter->stats = kvzalloc(sizeof(*adapter->stats), GFP_KERNEL);
	if (unlikely(!adapter->stats))
		goto err_detach;

	err = register_netdev(netdev);
	if (err) {
		xsc_core_warn(xdev, "register_netdev failed, err=%d\n", err);
		goto err_reg_netdev;
	}

	err = xsc_eth_sysfs_create(netdev, xdev);
	if (err)
		goto err_sysfs_create;

	xdev->netdev = (void *)netdev;
	adapter->status = XSCALE_ETH_DRIVER_INIT;

	return adapter;

err_sysfs_create:
	unregister_netdev(adapter->netdev);
err_reg_netdev:
	kfree(adapter->stats);
err_detach:
	xsc_eth_detach(xdev, adapter);
err_cleanup_netdev:
	xsc_eth_nic_cleanup(adapter);
err_free_netdev:
	free_netdev(netdev);

	return NULL;
}

static void xsc_eth_remove(struct xsc_core_device *xdev, void *context)
{
	struct xsc_adapter *adapter = NULL;

	if (!xdev)
		return;

	adapter = xdev->eth_priv;
	if (!adapter) {
		xsc_core_warn(xdev, "failed! adapter is null\n");
		return;
	}

	xsc_core_info(adapter->xdev, "remove netdev %s entry\n", adapter->netdev->name);

	xsc_eth_sysfs_remove(adapter->netdev, xdev);

	unregister_netdev(adapter->netdev);

	kfree(adapter->stats);

	xsc_eth_detach(xdev, adapter);
	xsc_eth_nic_cleanup(adapter);

	free_netdev(adapter->netdev);

	xdev->netdev = NULL;
	xdev->eth_priv = NULL;
}

static struct xsc_interface xsc_interface = {
	.add       = xsc_eth_add,
	.remove    = xsc_eth_remove,
	.event     = NULL,
	.protocol  = XSC_INTERFACE_PROTOCOL_ETH,
};

static __init int xsc_net_driver_init(void)
{
	int ret;

	pr_info("add ethernet driver\n");
	ret = xsc_register_interface(&xsc_interface);
	if (ret != 0) {
		pr_err("failed to register interface\n");
		goto out;
	}

	ret = xsc_eth_ctrl_init();
	if (ret != 0) {
		pr_err("failed to register port control node\n");
		xsc_unregister_interface(&xsc_interface);
		goto out;
	}

	return 0;
out:
	return -1;
}

static __exit void xsc_net_driver_exit(void)
{
	pr_info("remove ethernet driver\n");
	xsc_eth_ctrl_fini();
	xsc_unregister_interface(&xsc_interface);
}

module_init(xsc_net_driver_init);
module_exit(xsc_net_driver_exit);
