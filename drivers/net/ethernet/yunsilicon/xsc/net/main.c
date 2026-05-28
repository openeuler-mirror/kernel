// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/in.h>
#include <linux/interrupt.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/overflow.h>
#include <net/dsfield.h>

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
#include "xsc_accel.h"
#include "xsc_eth_ctrl.h"
#include "../pci/eswitch.h"

#include "common/xsc_fs.h"
#include "common/vport.h"
#include "xsc_eth_dim.h"
#include "xsc_hw_comm.h"
#include "rep/xsc_eth_rep.h"
#include "common/tc_flow.h"
#include "common/tc_priv.h"


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Yunsilicon network adapters ethernet driver");
MODULE_VERSION(DRIVER_VERSION);

bool mc_filter = 1;
module_param(mc_filter, bool, 0644);
MODULE_PARM_DESC(mc_filter, "1=enable multicast filter, 0=disable");

#define MAX_VF_NUM_MINIDUMP	1024

static void xsc_eth_close_channel(struct xsc_channel *c, bool free_rq);
static void xsc_eth_remove(struct xsc_core_device *xdev, void *context);

static void xsc_netdev_set_tcs(struct xsc_adapter *priv, u16 nch, u8 ntc);

#ifdef NEED_CREATE_RX_THREAD
extern uint32_t xsc_eth_rx_thread_create(struct xsc_adapter *adapter);
#endif

const struct xsc_profile xsc_nic_profile;

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

static void xsc_eth_build_queue_param(struct xsc_adapter *adapter,
				      struct xsc_queue_attr *attr, u8 type)
{
	struct xsc_core_device *xdev = adapter->xdev;
	u32 xsc_rqcq_ele_num;
	u32 xsc_sqcq_ele_num;

	if (type == XSC_QUEUE_TYPE_EQ) {
		attr->q_type = XSC_QUEUE_TYPE_EQ;
		attr->ele_num = xdev->caps.max_eqes;
		attr->ele_size = XSC_EQ_ELE_SZ;
		attr->ele_log_size = order_base_2(XSC_EQ_ELE_SZ);
		attr->q_log_size = order_base_2(attr->ele_num);
	} else if (type == XSC_QUEUE_TYPE_RQCQ) {
		attr->q_type = XSC_QUEUE_TYPE_RQCQ;
		xsc_rqcq_ele_num = 1 <<
			xsc_get_raw_rqcq_logsz(xdev, order_base_2(adapter->nic_param.rq_size));
		attr->ele_num = min_t(int, xsc_rqcq_ele_num, xdev->caps.max_cqes);
		attr->ele_size = is_support_cqe64(xdev) ? XSC_RQCQ_ELE_SZ64 : XSC_RQCQ_ELE_SZ;
		attr->ele_log_size = order_base_2(attr->ele_size);
		attr->q_log_size = order_base_2(attr->ele_num);
	} else if (type == XSC_QUEUE_TYPE_SQCQ) {
		attr->q_type = XSC_QUEUE_TYPE_SQCQ;
		xsc_sqcq_ele_num = 1 <<
			xsc_get_raw_sqcq_logsz(xdev, order_base_2(adapter->nic_param.sq_size));
		attr->ele_num = min_t(int, xsc_sqcq_ele_num, xdev->caps.max_cqes);
		attr->ele_size = is_support_cqe64(xdev) ? XSC_SQCQ_ELE_SZ64 : XSC_SQCQ_ELE_SZ;
		attr->ele_log_size = order_base_2(attr->ele_size);
		attr->q_log_size = order_base_2(attr->ele_num);
	} else if (type == XSC_QUEUE_TYPE_RQ) {
		attr->q_type = XSC_QUEUE_TYPE_RQ;
		attr->ele_num = adapter->nic_param.rq_size;
		attr->ele_size = xsc_get_recv_ds_num(adapter->xdev) * XSC_RECV_WQE_DS;
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

		if (rq->wqe.info.num_frags == 1 &&
		    frag_info->frag_stride >= XSC_RX_FRAG_SZ) {
			*frag = next_frag;
			frag->last_in_page = 1;
			next_frag.di++;
			continue;
		}

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

static int xsc_rx_alloc_page_cache(struct xsc_rq *rq, int node, u8 log_init_sz)
{
	struct xsc_page_cache *cache = &rq->page_cache;

	cache->sz = 1 << log_init_sz;
	cache->page_cache = kvzalloc_node(cache->sz * sizeof(*cache->page_cache),
					  GFP_KERNEL, node);
	if (!cache->page_cache)
		return -ENOMEM;

	return 0;
}

static void xsc_rx_free_page_cache(struct xsc_rq *rq)
{
	struct xsc_page_cache *cache = &rq->page_cache;
	u32 i;

	for (i = cache->head; i != cache->tail; i = (i + 1) & (cache->sz - 1)) {
		struct xsc_dma_info *dma_info = &cache->page_cache[i];

		xsc_page_release_dynamic(rq, dma_info, false);
	}
	kvfree(cache->page_cache);
}

static int xsc_eth_nic_reset(struct xsc_adapter *adapter)
{
	if (xsc_is_vf_rep(adapter->netdev))
		return xsc_eth_rep_enable_nic_hca(adapter);
	else
		return xsc_eth_enable_nic_hca(adapter);
}

static void xsc_eth_cq_error_event(struct xsc_core_cq *xcq, enum xsc_event event)
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

static void xsc_eth_completion_event(struct xsc_core_cq *xcq)
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
	cq->channel->stats->poll = 0;
	cq->channel->stats->poll_tx = 0;

	if (!test_bit(XSC_ETH_RQ_STATE_ENABLED, &rq->state))
		xsc_core_info(xdev, "ch%d_cq%d, napi_flag=0x%lx\n",
			      cq->channel->chl_idx, xcq->cqn, cq->napi->state);

	napi_schedule(cq->napi);
	cq->event_ctr++;
	cq->channel->stats->events++;
}

static int xsc_eth_destroy_cq(struct xsc_core_device *xdev, struct xsc_cq *cq)
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

static void xsc_eth_free_cq(struct xsc_cq *cq)
{
	xsc_eth_wq_destroy(&cq->wq_ctrl);
}

static void xsc_eth_qp_event(struct xsc_core_qp *qp, int type)
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

	if (rq->page_pool)
		page_pool_destroy(rq->page_pool);

	xsc_eth_wq_destroy(&rq->wq_ctrl);

	if (test_bit(XSC_ETH_RQ_STATE_AM, &rq->state)) {
		hrtimer_cancel(&rq->cq.cq_reduce.timer);
		clear_bit(XSC_ETH_RQ_STATE_AM, &rq->state);
	}
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
	struct xsc_create_cq_ex_mbox_in *in;
	int inlen;
	int hw_npages;

	hw_npages = DIV_ROUND_UP(pcq->wq_ctrl.buf.size, PAGE_SIZE_4K);
	/*mbox size + pas size*/
	inlen = sizeof(struct xsc_create_cq_ex_mbox_in) +
		sizeof(__be64) * hw_npages;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	/*construct param of in struct*/
	in->ctx_ex.ctx.log_cq_sz = pcq_param->cq_attr.q_log_size;
	in->ctx_ex.ctx.pa_num = cpu_to_be16(hw_npages);
	in->ctx_ex.ctx.glb_func_id = cpu_to_be16(c->adapter->xdev->glb_func_id);
	in->ctx.page_shift = PAGE_SHIFT;

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
	struct xsc_create_cq_ex_mbox_in *in;
	int inlen;
	int eqn, irqn;
	int hw_npages;

	hw_npages = DIV_ROUND_UP(pcq->wq_ctrl.buf.size, PAGE_SIZE_4K);
	/*mbox size + pas size*/
	inlen = sizeof(struct xsc_create_cq_ex_mbox_in) +
		sizeof(__be64) * hw_npages;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	/*construct param of in struct*/
	ret = xsc_vector2eqn(xdev, c->chl_idx, &eqn, &irqn);
	if (ret)
		goto err;

	in->ctx_ex.ctx.eqn = eqn;
	in->ctx_ex.ctx.eqn = cpu_to_be16(in->ctx_ex.ctx.eqn);
	in->ctx_ex.ctx.log_cq_sz = pcq_param->cq_attr.q_log_size;
	in->ctx_ex.ctx.pa_num = cpu_to_be16(hw_npages);
	in->ctx_ex.ctx.glb_func_id = cpu_to_be16(xdev->glb_func_id);
	in->ctx_ex.page_shift = PAGE_SHIFT;

	xsc_fill_page_frag_array(&pcq->wq_ctrl.buf, &in->pas[0], hw_npages);

	ret = xsc_eth_create_cq(c->adapter->xdev, &pcq->xcq, in, inlen);
	if (ret == 0) {
		pcq->xcq.irqn = irqn;
		pcq->xcq.eq = xsc_eq_get(xdev, pcq->xcq.vector);
	}

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
	int ret;

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

static int xsc_eth_set_hw_mtu(struct xsc_adapter *adapter, u16 mtu, u16 rx_buf_sz)
{
	struct xsc_set_mtu_mbox_in in;
	struct xsc_set_mtu_mbox_out out;
	int ret;
	struct xsc_core_device *dev = adapter->xdev;

	if (xsc_is_vf_rep(adapter->netdev))
		return 0;

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

static  int xsc_eth_get_mac(struct xsc_core_device *dev, char *mac)
{
	struct xsc_query_eth_mac_mbox_out *out;
	struct xsc_query_eth_mac_mbox_in in;
	int err;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_ETH_MAC);

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

static int xsc_eth_modify_qps_channel(struct xsc_adapter *adapter, struct xsc_channel *c)
{
	int ret = 0;
	int i;

	for (i = 0; i < c->qp.rq_num; i++) {
		c->qp.rq[i].post_wqes(&c->qp.rq[i], true);
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

static int xsc_eth_modify_qps(struct xsc_adapter *adapter,
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

static u32 xsc_rx_get_linear_frag_sz(u32 mtu)
{
	u32 byte_count = XSC_SW2HW_FRAG_SIZE(mtu);

	return XSC_SKB_FRAG_SZ(byte_count);
}

static bool xsc_rx_is_linear_skb(u32 mtu)
{
	u32 linear_frag_sz = xsc_rx_get_linear_frag_sz(mtu);

	return linear_frag_sz <= PAGE_SIZE;
}

static bool is_mtu_valid(struct net_device *netdev, int mtu)
{
	if (mtu > netdev->max_mtu || mtu < netdev->min_mtu) {
		netdev_err(netdev, "%s: Bad MTU (%d), valid range is: [%d..%d]\n",
			   __func__, mtu, netdev->min_mtu, netdev->max_mtu);
		return false;
	}

	return true;
}

static int xsc_eth_get_mtu(struct xsc_adapter *adapter, u16 *pmtu)
{
	struct xsc_query_mtu_mbox_out *out;
	struct xsc_query_mtu_mbox_in in;
	int err;
	struct xsc_core_device *dev = adapter->xdev;

	if (xsc_is_vf_rep(adapter->netdev))
		return -EOPNOTSUPP;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_MTU);

	err = xsc_cmd_exec(dev, &in, sizeof(in), out, sizeof(*out));
	if (err || out->hdr.status) {
		if (out->hdr.status == XSC_CMD_STATUS_NOT_SUPPORTED)
			xsc_core_info(dev, "not support get mtu\n");
		else
			xsc_core_warn(dev, "get mtu failed! err=%d, out.status=%u\n",
				      err, out->hdr.status);
		err = -ENOEXEC;
		goto exit;
	}

	if (!is_mtu_valid(adapter->netdev, be16_to_cpu(out->mtu))) {
		err = -EINVAL;
		goto exit;
	}

	*pmtu = be16_to_cpu(out->mtu);
	xsc_core_dbg(dev, "get mtu %u\n", *pmtu);

exit:
	kfree(out);

	return err;
}

static int xsc_eth_alloc_rq(struct xsc_channel *c,
			    struct xsc_rq *prq,
			    struct xsc_rq_param *prq_param)
{
	struct xsc_adapter *adapter = c->adapter;
	u8 q_log_size = prq_param->rq_attr.q_log_size;
	struct page_pool_params pagepool_params = { 0 };
	u32 pool_size = 1 << q_log_size;
	u8 ele_log_size = prq_param->rq_attr.ele_log_size;
	struct xsc_stats *stats = c->adapter->stats;
	struct xsc_channel_stats *channel_stats =
					&stats->channel_stats[c->chl_idx];
	int cache_init_sz = 0;
	int wq_sz;
	int i, f;
	int ret = 0;
	const struct xsc_profile *profile = adapter->profile;

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
	prq->buff.page_order = prq_param->frags_info.page_order;
#ifdef XSC_PAGE_CACHE
	cache_init_sz = wq_sz << prq->wqe.info.log_num_frags;
	cache_init_sz <<= 2;
	ret = xsc_rx_alloc_page_cache(prq, cpu_to_node(c->cpu), ilog2(cache_init_sz));
	if (ret)
		goto err_create_pool;
#endif

	/* Create a page_pool and register it with rxq */
	pool_size =  wq_sz << prq->wqe.info.log_num_frags;
	pagepool_params.order		= prq->buff.page_order;
	pagepool_params.flags		= 0;
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
		xsc_core_info(adapter->xdev,
			      "page pool: order=%d, size=%d, cpu=%d, pool_numa=%d, cache_size=%d, mtu=%d, wqe_numa=%d\n",
			      pagepool_params.order, pool_size, c->cpu,
			      pagepool_params.nid, cache_init_sz,
			      adapter->nic_param.mtu,
			      prq_param->wq.buf_numa_node);

	for (i = 0; i < wq_sz; i++) {
		struct xsc_eth_rx_wqe_cyc *wqe =
			xsc_wq_cyc_get_wqe(&prq->wqe.wq, i);

		for (f = 0; f < prq->wqe.info.num_frags; f++) {
			u32 frag_size = prq->wqe.info.arr[f].frag_size;

			xsc_set_data_seg(adapter->xdev, &wqe->data[f], 0,
					 cpu_to_le32(XSC_INVALID_LKEY), cpu_to_le32(frag_size));
		}

		for (; f < prq->wqe.info.frags_max_num; f++)
			xsc_set_data_seg(adapter->xdev, &wqe->data[f], 0,
					 cpu_to_le32(XSC_INVALID_LKEY), 0);
	}

	prq->post_wqes = xsc_eth_post_rx_wqes;
	prq->handle_rx_cqe = profile->rx_handlers->handle_rx_cqe;
	prq->dealloc_wqe = xsc_eth_dealloc_rx_wqe;
	prq->wqe.skb_from_cqe = xsc_rx_is_linear_skb(adapter->nic_param.mtu) ?
					xsc_skb_from_cqe_linear :
					xsc_skb_from_cqe_nonlinear;
	prq->ix = c->chl_idx;
	prq->frags_sz = adapter->nic_param.rq_frags_size;

	if (adapter->nic_param.rx_dim_enabled) {
		INIT_WORK(&prq->dim_obj.dim.work, xsc_rx_dim_work);
		prq->dim_obj.dim.mode =
			adapter->nic_param.rx_cq_moderation.cq_period_mode;
		hrtimer_init(&prq->cq.cq_reduce.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		prq->cq.cq_reduce.timer.function = xsc_dim_reduce_timer_fn;
		set_bit(XSC_ETH_RQ_STATE_AM, &prq->state);
	}

	return 0;

err_create_pool:
	xsc_eth_free_di_list(prq);
err_init_di:
	kvfree(prq->wqe.frags);
err_alloc_frags:
	xsc_eth_wq_destroy(&prq->wq_ctrl);
	return ret;
}

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
	struct xsc_rq *prq = NULL;
	struct xsc_channel *c;
	int rqn_base;
	int inlen;
	int entry_len = 0;
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
			req->log_rq_sz = ilog2(xsc_get_recv_ds_num(adapter->xdev)) +
					q_log_size;
			req->pa_num = cpu_to_be16(hw_npages);
			req->cqn_recv = cpu_to_be16(prq->cq.xcq.cqn);
			req->cqn_send = req->cqn_recv;
			req->glb_funcid = cpu_to_be16(adapter->xdev->glb_func_id);
			req->page_shift = PAGE_SHIFT;

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
	xsc_core_info(adapter->xdev, "rqn_base=%d, rq_num=%d, state=0x%lx\n",
		      rqn_base, num_chl, prq->state);
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
	in->req.page_shift = PAGE_SHIFT;

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

	if (adapter->nic_param.tx_dim_enabled) {
		INIT_WORK(&psq->dim_obj.dim.work, xsc_tx_dim_work);
		psq->dim_obj.dim.mode = adapter->nic_param.tx_cq_moderation.cq_period_mode;
		hrtimer_init(&psq->cq.cq_reduce.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		psq->cq.cq_reduce.timer.function = xsc_dim_reduce_timer_fn;
		set_bit(XSC_ETH_SQ_STATE_AM, &psq->state);
	}

	xsc_core_info(c->adapter->xdev,
		      "open sq ok, ch%d_sq%d_qpn=%d, state=0x%lx, db_numa=%d, buf_numa=%d\n",
		      c->chl_idx, sq_idx, psq->sqn, psq->state,
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

	if (test_bit(XSC_ETH_SQ_STATE_AM, &psq->state)) {
		hrtimer_cancel(&psq->cq.cq_reduce.timer);
		clear_bit(XSC_ETH_SQ_STATE_AM, &psq->state);
	}

	return 0;
}

static int xsc_eth_open_channel(struct xsc_adapter *adapter,
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

	if (byte_count <= PAGE_SIZE_4K) {
		frags_info->arr[0].frag_size = PAGE_SIZE_4K;
		frags_info->arr[0].frag_stride = PAGE_SIZE_4K;
		frags_info->num_frags = 1;
	} else if (byte_count <= 2 * PAGE_SIZE_4K) {
		if (PAGE_SIZE < 2 * PAGE_SIZE_4K && frags_info->frags_max_num >= 2) {
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
		frags_info->num_frags = roundup(byte_count, PAGE_SIZE_4K) / PAGE_SIZE_4K;
		if (PAGE_SIZE < 4 * PAGE_SIZE_4K &&
		    frags_info->frags_max_num >= frags_info->num_frags) {
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
	} else if (PAGE_SIZE <= 2 * PAGE_SIZE_4K) {
		frags_info->wqe_bulk = 2;
		frags_info->wqe_bulk_min = frags_info->wqe_bulk;
	} else {
		frags_info->wqe_bulk =
			PAGE_SIZE / (frags_info->num_frags * frags_info->arr[0].frag_size);
		frags_info->wqe_bulk_min = frags_info->wqe_bulk;
	}

	if (frags_info->arr[0].frag_size > PAGE_SIZE)
		frags_info->page_order =
			order_base_2(frags_info->arr[0].frag_size / PAGE_SIZE);

out:
	frags_info->log_num_frags = order_base_2(frags_info->num_frags);

	return frags_info->num_frags * frags_info->arr[0].frag_size;
}

static void xsc_build_rq_frags_info(struct xsc_queue_attr *attr,
				    struct xsc_rq_frags_info *frags_info,
				    struct xsc_eth_params *params)
{
	frags_info->frags_max_num = attr->ele_size / XSC_RECV_WQE_DS;
	frags_info->page_order = 0;
	params->rq_frags_size = xsc_get_rq_frag_info(frags_info, params->mtu);
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

static int xsc_eth_open_channels(struct xsc_adapter *adapter)
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
	}

	ret = xsc_eth_open_rss_qp_rqs(adapter, &chl_param->rq_param, chls, chls->num_chl);
	if (ret)
		goto err_open_channel;
	free_rq = true;

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

static void xsc_eth_activate_channel(struct xsc_channel *c)
{
	xsc_eth_activate_txqsq(c);
	xsc_activate_rq(c);
}

static void xsc_eth_deactivate_channel(struct xsc_channel *c)
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

static void xsc_set_default_xps_cpumasks(struct xsc_adapter *adapter)
{
	struct xsc_core_device *xdev = adapter->xdev;
	int num_comp_vectors, irq;

	num_comp_vectors = adapter->nic_param.comp_vectors;
	cpumask_clear(xdev->xps_cpumask);

	for (irq = 0; irq < num_comp_vectors; irq++) {
		mask_cpu_by_node(xdev->priv.numa_node, xdev->xps_cpumask);
		netif_set_xps_queue(adapter->netdev, xdev->xps_cpumask, irq);
	}
}

static void xsc_init_netdev_queues(struct xsc_adapter *adapter)
{
	int num_txqs;
	struct net_device *netdev = adapter->netdev;

	num_txqs = adapter->channels.num_chl * adapter->nic_param.num_tc;
	xsc_netdev_set_tcs(adapter, adapter->channels.num_chl, adapter->nic_param.num_tc);
	netif_set_real_num_tx_queues(netdev, num_txqs);
	netif_set_real_num_rx_queues(netdev, adapter->channels.num_chl);

	xsc_set_default_xps_cpumasks(adapter);
}

static void xsc_eth_activate_priv_channels(struct xsc_adapter *adapter)
{
	xsc_eth_build_tx2sq_maps(adapter);
	xsc_eth_activate_channels(&adapter->channels);
	netif_tx_start_all_queues(adapter->netdev);
}

static void xsc_eth_deactivate_priv_channels(struct xsc_adapter *adapter)
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

	xsc_init_netdev_queues(adapter);
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
	if (!xsc_is_vf_rep(adapter->netdev))
		xsc_eth_modify_nic_hca(adapter, BIT(XSC_RSS_RXQ_DROP));
	else
		xsc_eth_rep_modify_nic_hca(adapter, BIT(XSC_RSS_RXQ_DROP));

	xsc_eth_deactivate_priv_channels(adapter);

	return xsc_eth_close_channels(adapter);
}

int xsc_eth_set_led_status(int id, struct xsc_adapter *adapter)
{
	int err;

	struct xsc_event_set_led_status_mbox_in in;
	struct xsc_event_set_led_status_mbox_out out;

	/*query linkstatus cmd*/
	memset(&in, 0, sizeof(in));
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
	bool link_up;
	struct xsc_core_device *xdev = adapter->xdev;
	u16 vport = xsc_core_is_pf(xdev) ? 0 : (xdev->vf_id + 1);

	link_up = xsc_query_vport_state(xdev, XSC_CMD_OP_QUERY_VPORT_STATE, vport);

	xsc_core_dbg(adapter->xdev, "link_status=%d\n", link_up);

	return link_up ? true : false;
}

bool xsc_eth_get_port_present(struct xsc_adapter *adapter)
{
	bool port_present;
	struct xsc_core_device *xdev = adapter->xdev;
	u16 vport = xsc_core_is_pf(xdev) ? 0 : (xdev->vf_id + 1);

	port_present = xsc_query_port_present(xdev, XSC_CMD_OP_QUERY_VPORT_STATE, vport);

	xsc_core_dbg(adapter->xdev, "port_present=%d\n", port_present);

	return port_present ? true : false;
}

int xsc_eth_get_link_info(struct xsc_adapter *adapter,
			  struct xsc_event_linkinfo *plinkinfo)
{
	struct xsc_event_query_linkinfo_mbox_in in;
	struct xsc_event_query_linkinfo_mbox_out out;
	int i, err;

	memset(&in, 0, sizeof(in));
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

	memset(&in, 0, sizeof(in));
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

static int xsc_eth_change_link_status(struct xsc_adapter *adapter)
{
	bool link_up;

	link_up = xsc_eth_get_link_status(adapter);

	if (link_up && !netif_carrier_ok(adapter->netdev)) {
		netdev_info(adapter->netdev, "Link up\n");
		netif_carrier_on(adapter->netdev);
	} else if (!link_up) {
		netdev_info(adapter->netdev, "Link down\n");
		if (netif_carrier_ok(adapter->netdev))
			netif_carrier_off(adapter->netdev);
	}

	return 0;
}

static int xsc_eth_change_port_present_status(struct xsc_adapter *adapter)
{
	bool port_present;

	port_present = xsc_eth_get_port_present(adapter);

	if (port_present)
		netdev_info(adapter->netdev, "Port module inserted\n");
	else
		netdev_info(adapter->netdev, "Port module removed\n");

	return 0;
}

int xsc_eth_enable_nic_hca(struct xsc_adapter *adapter)
{
	struct xsc_core_device *xdev = adapter->xdev;
	struct net_device *netdev = adapter->netdev;
	struct xsc_cmd_enable_nic_hca_mbox_in in = {};
	struct xsc_cmd_enable_nic_hca_mbox_out out = {};
	u16 caps = 0;
	u16 caps_mask = 0;
	int err;

	if (xsc_get_user_mode(xdev))
		return 0;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ENABLE_NIC_HCA);

	in.rss.rss_en = 1;
	in.rss.rqn_base = cpu_to_be16(adapter->channels.rqn_base -
				xdev->caps.raweth_rss_qp_id_base);
	in.rss.rqn_num = cpu_to_be16(adapter->channels.num_chl);
	in.rss.hash_tmpl = cpu_to_be32(adapter->rss_params.rss_hash_tmpl);
	in.rss.hfunc = hash_func_type(adapter->rss_params.hfunc);
	caps_mask |= BIT(XSC_TBM_CAP_RSS);

	if ((netdev->features & NETIF_F_RXCSUM) ||
	    XSC_GET_PFLAG(&adapter->nic_param, XSC_PFLAG_RX_TC_SKB_EXT))
		caps |= BIT(XSC_TBM_CAP_HASH_PPH);
	caps_mask |= BIT(XSC_TBM_CAP_HASH_PPH);

	if (adapter->nic_param.vlan_strip_enabled)
		caps |= BIT(XSC_TBM_CAP_VLAN_STRIP) | BIT(XSC_TBM_CAP_HASH_PPH);
	caps_mask |= BIT(XSC_TBM_CAP_VLAN_STRIP);

	if (xsc_get_pp_bypass_res(adapter->xdev, false))
		caps |= BIT(XSC_TBM_CAP_PP_BYPASS);
	caps_mask |= BIT(XSC_TBM_CAP_PP_BYPASS);

	if (xsc_get_pf_isolate_config(xdev, BOND_ENSLAVE)) {
		caps |= BIT(XSC_TBM_CAP_PF_ISOLATE_CONFIG);
		caps_mask |= BIT(XSC_TBM_CAP_PF_ISOLATE_CONFIG);
	}

	if (xsc_get_mac_drop_config(xdev, BOND_ENSLAVE)) {
		caps |= BIT(XSC_TBM_CAP_MAC_DROP_CONFIG);
		caps_mask |= BIT(XSC_TBM_CAP_MAC_DROP_CONFIG);
	}

	memcpy(in.nic.mac_addr, netdev->dev_addr, ETH_ALEN);

	in.nic.caps = cpu_to_be16(caps);
	in.nic.caps_mask = cpu_to_be16(caps_mask);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "failed, err=%d, status=%d\n", err, out.hdr.status);
		return -ENOEXEC;
	}

	xsc_core_info(xdev, "caps=0x%x, caps_mask=0x%x\n", caps, caps_mask);

	return 0;
}

static int xsc_eth_disable_nic_hca(struct xsc_adapter *adapter)
{
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_cmd_disable_nic_hca_mbox_in in = {};
	struct xsc_cmd_disable_nic_hca_mbox_out out = {};
	int err;
	u16 caps = 0;

	if (xsc_get_user_mode(xdev))
		return 0;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DISABLE_NIC_HCA);

	if (xsc_get_pp_bypass_res(xdev, false))
		caps |= BIT(XSC_TBM_CAP_PP_BYPASS);

	if (xsc_get_pf_isolate_config(xdev, BOND_RELEASE))
		caps |= BIT(XSC_TBM_CAP_PF_ISOLATE_CONFIG);

	if (xsc_get_mac_drop_config(xdev, BOND_RELEASE))
		caps |= BIT(XSC_TBM_CAP_MAC_DROP_CONFIG);

	in.nic.caps = cpu_to_be16(caps);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "failed, err=%d, status=%d\n", err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

static void xsc_eth_rss_params_change(struct xsc_adapter *adapter, u32 change, void *modify)
{
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_rss_params *rss = &adapter->rss_params;
	struct xsc_eth_params *params = &adapter->nic_param;
	struct xsc_cmd_modify_nic_hca_mbox_in *in =
		(struct xsc_cmd_modify_nic_hca_mbox_in *)modify;
	u32 hash_field = 0;
	int key_len;
	u8 rss_caps_mask = 0;

	if (xsc_get_user_mode(xdev))
		return;

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

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_NIC_HCA);

	xsc_eth_rss_params_change(adapter, flags, &in);
	if (in.rss.caps_mask) {
		err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
		if (err || out.hdr.status) {
			xsc_core_err(xdev, "failed, err=%d, status=%u\n",
				     err, out.hdr.status);
			return -ENOEXEC;
		}
	}

	return 0;
}

int xsc_eth_query_pkt_dst_info(struct xsc_adapter *adapter, u8 mac_bitmap,
			       u16 pkt_bitmap, u16 *dst_info)
{
	struct xsc_cmd_query_pkt_dst_info_mbox_in in;
	struct xsc_cmd_query_pkt_dst_info_mbox_out out;
	int i, ret = 0;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_PKT_DST_INFO);
	in.mac_bitmap = mac_bitmap;
	in.pkt_bitmap = cpu_to_be16(pkt_bitmap);

	ret = xsc_cmd_exec(adapter->xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status) {
		if (out.hdr.status == XSC_CMD_STATUS_NOT_SUPPORTED)
			return -EOPNOTSUPP;
		xsc_core_err(adapter->xdev,
			     "failed to query pkt dst info, pkt=0x%x, mac=0x%x,err=%d\n",
			     pkt_bitmap, mac_bitmap, out.hdr.status);
		return -ENOEXEC;
	}

	for (i = 0; i < XSC_USER_MODE_FWD_PKT_NUM; i++)
		dst_info[i] = be16_to_cpu(out.dst_info[i]);

	return ret;
}

int xsc_eth_modify_pkt_dst_info(struct xsc_adapter *adapter, u8 mac_bitmap,
				u16 pkt_bitmap, u16 dst_info)
{
	struct xsc_cmd_modify_pkt_dst_info_mbox_in in;
	struct xsc_cmd_modify_pkt_dst_info_mbox_out out;
	int ret = 0;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_PKT_DST_INFO);
	in.mac_bitmap = mac_bitmap;
	in.pkt_bitmap = cpu_to_be16(pkt_bitmap);
	in.dst_info = cpu_to_be16(dst_info);

	ret = xsc_cmd_exec(adapter->xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status) {
		if (out.hdr.status == XSC_CMD_STATUS_NOT_SUPPORTED)
			return -EOPNOTSUPP;
		xsc_core_err(adapter->xdev,
			     "failed to modify pkt dst info, pkt=0x%x, mac=0x%x, dst_info=%d, err=%d\n",
			     pkt_bitmap, mac_bitmap, dst_info, out.hdr.status);
		ret = -ENOEXEC;
	}

	return ret;
}

static int xsc_set_port_admin_status(struct xsc_adapter *adapter,
				     enum xsc_port_status status)
{
	struct xsc_event_set_port_admin_status_mbox_in in;
	struct xsc_event_set_port_admin_status_mbox_out out;
	int ret = 0;

	if (!xsc_core_is_pf(adapter->xdev))
		return 0;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_SET_PORT_ADMIN_STATUS);
	in.admin_status = cpu_to_be16(status);
	in.force = XSC_GET_PFLAG(&adapter->nic_param, XSC_PFLAG_LINK_DOWN_ON_CLOSE);
	in.hdr.ver = cpu_to_be16(CMD_SET_PORT_ADMIN_STATUS_V1);

	ret = xsc_cmd_exec(adapter->xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status) {
		if (out.hdr.status == XSC_CMD_STATUS_NOT_SUPPORTED)
			return -EOPNOTSUPP;
		xsc_core_err(adapter->xdev, "failed to set port admin status(%d), err=%d, status=%d\n",
			     status, ret, out.hdr.status);
		return -ENOEXEC;
	}

	return ret;
}

static void xsc_link_event_handler(void *arg)
{
	struct xsc_core_device *dev = arg;
	struct xsc_adapter *adapter = dev->eth_priv;
	int err = 0;

	if (!adapter)
		return;

	if (adapter->status != XSCALE_ETH_DRIVER_OK &&
	    adapter->status != XSCALE_ETH_DRIVER_CLOSE)
		return;

	err = xsc_eth_change_link_status(adapter);
	if (err)
		xsc_core_err(adapter->xdev, "failed to change linkstatus, err=%d\n", err);
}

static void xsc_port_present_event_handler(void *arg)
{
	struct xsc_core_device *dev = arg;
	struct xsc_adapter *adapter = dev->eth_priv;
	int err = 0;

	if (!adapter)
		return;

	if (adapter->status != XSCALE_ETH_DRIVER_OK &&
	    adapter->status != XSCALE_ETH_DRIVER_CLOSE)
		return;

	err = xsc_eth_change_port_present_status(adapter);
	if (err)
		xsc_core_err(adapter->xdev, "failed to change port_present, err=%d\n", err);
}

int xsc_eth_open_locked(struct net_device *netdev)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	struct xsc_core_device *xdev = adapter->xdev;
	int ret = 0;

	xsc_core_info(adapter->xdev, "open %s\n", netdev->name);

	if (adapter->status == XSCALE_ETH_DRIVER_OK) {
		xsc_core_warn(adapter->xdev, "unnormal ndo_open when status=%d\n",
			      adapter->status);
		goto ret;
	}

	spin_lock_init(&adapter->lock);

	ret = xsc_eth_sw_init(adapter);
	if (ret)
		goto ret;

	ret = xsc_eth_nic_reset(adapter);
	if (ret)
		goto sw_deinit;

#ifdef NEED_CREATE_RX_THREAD
	ret = xsc_eth_rx_thread_create(adapter);
	if (ret) {
		xsc_core_warn(xdev, "xsc_eth_rx_thread_create failed, err=%d\n", ret);
		goto sw_deinit;
	}
#endif

	if (!xsc_is_vf_rep(adapter->netdev)) {
		if (xsc_eth_get_port_present(adapter))
			netdev_info(netdev, "Port module inserted\n");
		if (xsc_eth_get_link_status(adapter))	{
			netdev_info(netdev, "Link up\n");
			netif_carrier_on(adapter->netdev);
		}
	}

	adapter->status = XSCALE_ETH_DRIVER_OK;

	goto ret;

sw_deinit:
	xsc_eth_sw_deinit(adapter);
ret:
	xsc_core_info(xdev, "open %s %s, ret=%d\n",
		      netdev->name, ret ? "failed" : "ok", ret);
	return ret;
}

int xsc_eth_open(struct net_device *netdev)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	int ret = 0;

	mutex_lock(&adapter->state_lock);
	ret = xsc_eth_open_locked(netdev);
	if (!ret)
		xsc_set_port_admin_status(adapter, XSC_PORT_UP);

	mutex_unlock(&adapter->state_lock);

	return ret;
}

int xsc_eth_close_locked(struct net_device *netdev)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	int ret = 0;

	if (adapter->status != XSCALE_ETH_DRIVER_OK)
		goto ret;

	adapter->status = XSCALE_ETH_DRIVER_CLOSE;

#ifdef NEED_CREATE_RX_THREAD
	if (adapter->task)
		kthread_stop(adapter->task);
#endif

	netif_carrier_off(adapter->netdev);

	xsc_eth_sw_deinit(adapter);

	if (xsc_is_vf_rep(adapter->netdev))
		ret = xsc_eth_rep_disable_nic_hca(adapter);
	else
		ret = xsc_eth_disable_nic_hca(adapter);
	if (ret)
		xsc_core_warn(adapter->xdev, "failed to disable nic hca, err=%d\n", ret);

ret:
	xsc_core_info(adapter->xdev, "close device %s %s, ret=%d\n",
		      adapter->netdev->name, ret ? "failed" : "ok", ret);

	return ret;
}

int xsc_eth_close(struct net_device *netdev)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	int ret = 0;

	if (!netif_device_present(netdev))
		return -ENODEV;

	mutex_lock(&adapter->state_lock);
	ret = xsc_eth_close_locked(netdev);
	if (ret)
		goto out;

	xsc_set_port_admin_status(adapter, XSC_PORT_DOWN);

out:
	mutex_unlock(&adapter->state_lock);

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

	for (tc = 0; tc < ntc; tc++)
		netdev_set_tc_queue(priv->netdev, tc, nch, tc * nch);
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

static void xsc_build_default_indir_rqt(u32 *indirection_rqt, int len,
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

	xsc_set_default_xps_cpumasks(priv);
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
	if (!xsc_is_vf_rep(adapter->netdev))
		ret = xsc_eth_modify_nic_hca(adapter, BIT(XSC_RSS_RXQ_DROP));
	else
		ret = xsc_eth_rep_modify_nic_hca(adapter, BIT(XSC_RSS_RXQ_DROP));
	if (ret)
		goto out;

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
	if (!xsc_is_vf_rep(adapter->netdev))
		ret = xsc_eth_modify_nic_hca(adapter, BIT(XSC_RSS_RXQ_UPDATE));
	else
		ret = xsc_eth_rep_modify_nic_hca(adapter, BIT(XSC_RSS_RXQ_UPDATE));
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
	xsc_core_info(adapter->xdev, "name=%s, channels=%d, mtu=%d, err=%d\n",
		      netdev->name, adapter->nic_param.num_channels,
		      adapter->nic_param.mtu, ret);
	return ret;
}

static int xsc_eth_nic_mtu_changed(struct xsc_adapter *priv)
{
	u32 new_mtu = priv->nic_param.mtu;
	int ret;

	ret = xsc_eth_set_hw_mtu(priv, XSC_SW2HW_MTU(new_mtu),
				 XSC_SW2HW_RX_PKT_LEN(new_mtu));

	return ret;
}

int xsc_eth_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	int old_mtu = netdev->mtu;
	int ret = 0;

	if (!is_mtu_valid(netdev, new_mtu))
		return -EINVAL;

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

static void xsc_set_rx_mode(struct net_device *dev)
{
	struct xsc_adapter *priv = netdev_priv(dev);

	queue_work(priv->workq, &priv->set_rx_mode_work);
}

static int xsc_set_vf_mac(struct net_device *netdev, int vf, u8 *mac)
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

static int xsc_set_vf_trust(struct net_device *dev, int vf, bool setting)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct xsc_core_device *xdev = priv->xdev;

	return xsc_eswitch_set_vport_trust(xdev->priv.eswitch, vf + 1, setting);
}

static int xsc_set_vf_spoofchk(struct net_device *dev, int vf, bool setting)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct xsc_core_device *xdev = priv->xdev;

	return xsc_eswitch_set_vport_spoofchk(xdev->priv.eswitch, vf + 1, setting);
}

static int xsc_set_vf_vlan(struct net_device *dev, int vf, u16 vlan, u8 qos,
			   __be16 vlan_proto)
{
	struct xsc_adapter *adapter = netdev_priv(dev);
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_vport *evport = xsc_eswitch_get_vport(xdev->priv.eswitch, vf + 1);
	int err;

	if (vlan_proto != htons(ETH_P_8021Q) && vlan_proto != htons(ETH_P_8021AD))
		return -EPROTONOSUPPORT;

	err = xsc_eswitch_set_vport_vlan(xdev->priv.eswitch, vf + 1,
					 vlan, qos, vlan_proto);
	if (err) {
		xsc_core_err(xdev, "fail to set vf %d vlan %u qos %u err=%d\n",
			     vf, vlan, qos, err);
		return err;
	}

	if (evport) {
		evport->vlan_id = vlan;
		evport->vlan_qos = qos;
		evport->vlan_proto = vlan_proto;
	}

	return 0;
}

static int xsc_get_vf_config(struct net_device *dev,
			     int vf, struct ifla_vf_info *ivi)
{
	struct xsc_adapter *adapter = netdev_priv(dev);
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_eswitch *esw = xdev->priv.eswitch;
	struct xsc_core_sriov *sriov = &xdev->priv.sriov;
	int err;

	if (!netif_device_present(dev) || sriov->num_vfs > MAX_VF_NUM_MINIDUMP)
		return -EOPNOTSUPP;

	err = xsc_eswitch_get_vport_config(esw, vf + 1, ivi);

	return err;
}

static int xsc_set_vf_link_state(struct net_device *dev, int vf,
				 int link_state)
{
	struct xsc_adapter *adapter = netdev_priv(dev);
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_eswitch *esw = xdev->priv.eswitch;

	if (xsc_is_uplink_rep(adapter))
		return -EOPNOTSUPP;

	return xsc_eswitch_set_vport_state(esw, vf + 1, link_state);
}

static int xsc_change_rx_caps(struct xsc_adapter *adapter, u32 caps, bool enable)
{
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_cmd_modify_nic_hca_mbox_in in = {};
	struct xsc_cmd_modify_nic_hca_mbox_out out = {};
	bool pph_change = false;
	bool change = false;
	int err;

	if (caps & BIT(XSC_TBM_CAP_HASH_PPH)) {
		spin_lock(&adapter->lock);
		if (enable) {
			if (++adapter->nic_param.pph_usr_cnt == 1)
				pph_change = true;
		} else {
			if (--adapter->nic_param.pph_usr_cnt == 0)
				pph_change = true;
		}

		change |= pph_change;
		spin_unlock(&adapter->lock);
	}

	if (caps & BIT(XSC_TBM_CAP_VLAN_STRIP))
		change |= true;

	if (!change)
		goto out;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_NIC_HCA);

	if (caps & BIT(XSC_TBM_CAP_HASH_PPH)) {
		in.nic.caps_mask = cpu_to_be16(BIT(XSC_TBM_CAP_HASH_PPH));
		in.nic.caps = cpu_to_be16(enable << XSC_TBM_CAP_HASH_PPH);
	}

	if (caps & BIT(XSC_TBM_CAP_VLAN_STRIP)) {
		in.nic.caps_mask = cpu_to_be16(BIT(XSC_TBM_CAP_VLAN_STRIP));
		in.nic.caps = cpu_to_be16(enable << XSC_TBM_CAP_VLAN_STRIP);
	}

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		if (pph_change) {
			spin_lock(&adapter->lock);
			if (enable)
				adapter->nic_param.pph_usr_cnt--;
			else
				adapter->nic_param.pph_usr_cnt++;
			spin_unlock(&adapter->lock);
		}

		xsc_core_err(xdev, "failed to change rx_caps=0x%x, enable=%d, err=%d\n",
			     caps, enable, out.hdr.status);
	}

out:
	return out.hdr.status;
}

static int set_feature_rxcsum(struct net_device *netdev, bool enable)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	u32 caps = BIT(XSC_TBM_CAP_HASH_PPH);

	return xsc_change_rx_caps(adapter, caps, enable);
}

static int set_feature_rx_vlan_strip(struct net_device *netdev, bool enable)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	u32 caps = BIT(XSC_TBM_CAP_HASH_PPH) | BIT(XSC_TBM_CAP_VLAN_STRIP);
	int err = 0;

	err = xsc_change_rx_caps(adapter, caps, enable);
	if (err == EBUSY) {
		netdev_err(netdev,
			   "Failed to set dev %s vlan strip because vlan vst mode exist.\n",
			   netdev->name);
		netdev_err(netdev,
			   "<ip link set $pf vf $id vlan 0> to disable vlan vst mode and try again\n");
	}

	return err;
}

static int set_feature_hw_tc(struct net_device *netdev, bool enable)
{
	return 0;
}

static int set_feature_gso_udp_tunnel(struct net_device *netdev, bool enable)
{
	return 0;
}

static int set_feature_gso_udp_tunnel_csum(struct net_device *netdev, bool enable)
{
	return 0;
}

int set_feature_rx_tc_skb_ext(struct net_device *netdev, bool enable)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);
	u32 caps = BIT(XSC_TBM_CAP_HASH_PPH);

	return xsc_change_rx_caps(adapter, caps, enable);
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

static int xsc_set_features(struct net_device *netdev, netdev_features_t features)
{
	netdev_features_t oper_features = netdev->features;
	int err = 0;

#define XSC_HANDLE_FEATURE(feature, handler) \
	xsc_handle_feature(netdev, &oper_features, features, feature, handler)

	err |= XSC_HANDLE_FEATURE(NETIF_F_RXCSUM, set_feature_rxcsum);
	err |= XSC_HANDLE_FEATURE(NETIF_F_HW_VLAN_CTAG_RX, set_feature_rx_vlan_strip);
	err |= XSC_HANDLE_FEATURE(NETIF_F_HW_TC, set_feature_hw_tc);
	err |= XSC_HANDLE_FEATURE(NETIF_F_GSO_UDP_TUNNEL, set_feature_gso_udp_tunnel);
	err |= XSC_HANDLE_FEATURE(NETIF_F_GSO_UDP_TUNNEL_CSUM, set_feature_gso_udp_tunnel_csum);
	if (err) {
		netdev->features = oper_features;
		return -EINVAL;
	}

	return 0;
}

static netdev_features_t xsc_fix_features(struct net_device *netdev,
					  netdev_features_t features)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);

	if ((features & NETIF_F_HW_VLAN_CTAG_RX) &&
	    !xsc_support_hw_feature(adapter->xdev, XSC_HW_RX_VLAN_STRIP))
		features &= ~NETIF_F_HW_VLAN_CTAG_RX;

	if ((features & NETIF_F_TSO) &&
	    xsc_support_hw_feature(adapter->xdev, XSC_HW_OFFLOAD_UNSUPPORT))
		features &= ~NETIF_F_TSO;

	if ((features & NETIF_F_TSO6) &&
	    xsc_support_hw_feature(adapter->xdev, XSC_HW_OFFLOAD_UNSUPPORT))
		features &= ~NETIF_F_TSO6;

	if ((features & NETIF_F_GSO_UDP_TUNNEL_CSUM) &&
	    !XSC_GET_PFLAG(&adapter->nic_param, XSC_PFLAG_TUNNEL_GSO)) {
		features &= ~(NETIF_F_GSO_UDP_TUNNEL | NETIF_F_GSO_UDP_TUNNEL_CSUM);
		netdev->wanted_features &= ~(NETIF_F_GSO_UDP_TUNNEL | NETIF_F_GSO_UDP_TUNNEL_CSUM);
	}

	return features;
}

#ifdef CONFIG_XSC_CORE_EN_DCB
static int xsc_get_dscp_up(struct xsc_adapter *adapter, struct sk_buff *skb)
{
	int dscp = 0;

	if (skb->protocol == htons(ETH_P_IP))
		dscp = ipv4_get_dsfield(ip_hdr(skb)) >> 2;
	else if (skb->protocol == htons(ETH_P_IPV6))
		dscp = ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;

	return adapter->dcbx_dp.dscp2prio[dscp];
}
#endif

static int xsc_get_up(struct xsc_adapter *adapter, struct sk_buff *skb)
{
	int up = 0;

#ifdef CONFIG_XSC_CORE_EN_DCB
	if (READ_ONCE(adapter->dcbx_dp.trust_state) == XSC_QPTS_TRUST_DSCP)
		return xsc_get_dscp_up(adapter, skb);
#endif

	if (skb_vlan_tag_present(skb)) {
		up = skb->vlan_tci >> VLAN_PRIO_SHIFT;
		if (adapter->nic_param.num_tc > 1) {
			if (is_dpu_soc_pf(adapter->xdev->pdev->device))
				up = up % (adapter->nic_param.num_tc - 1) + 1;
			else
				up = up % adapter->nic_param.num_tc;
		} else {
			up = 0;
		}
	}

	return up;
}

static u16 xsc_select_queue(struct net_device *dev, struct sk_buff *skb,
			    struct net_device *sb_dev)
{
	int txq_ix = 0;
	int up = 0;
	u16 num_channels;
	struct xsc_adapter *adapter = netdev_priv(dev);

	if (!adapter) {
		pr_err("%s adapter is null\n", __func__);
		return txq_ix;
	}

	txq_ix = netdev_pick_tx(dev, skb, NULL);
	if (!netdev_get_num_tc(dev))
		return txq_ix;

	up = xsc_get_up(adapter, skb);

	/* channel_ix can be larger than num_channels since
	 * dev->num_real_tx_queues = num_channels * num_tc
	 */
	num_channels = adapter->channels.num_chl;
	if (txq_ix >= num_channels)
		txq_ix = adapter->txq2sq[txq_ix]->ch_ix;

	return adapter->channel_tc2realtxq[txq_ix][up];
}

struct xsc_core_device *xsc_get_pf_xdev(struct xsc_core_device *xdev)
{
	struct pci_dev *pdev = xdev->pdev;
	struct xsc_core_device *pf_xdev;

	if (!pdev->physfn)
		return NULL;

	pf_xdev = pci_get_drvdata(pdev->physfn);
	if (!pf_xdev)
		return NULL;

	return pf_xdev;
}

static inline int xsc_get_port_index(struct xsc_core_device *xdev)
{
	if (xdev->pf_num_per_pcie == 1 && xsc_core_is_ocp(xdev))
		return xdev->pcie_no == 0 ? 1 : 0;
	else if (xsc_core_is_ms400(xdev))
		return xdev->pcie_no;
	else
		return xdev->pf_id;
}

int xsc_get_phys_port_name(struct net_device *dev, char *buf, size_t len)
{
	struct xsc_adapter *adapter = netdev_priv(dev);
	struct xsc_core_device *xdev = adapter->xdev;
	struct pci_dev *pdev = xdev->pdev;
	struct xsc_core_device *pf_xdev;
	struct net_device *pf_netdev;
	struct xsc_eswitch_rep *rep;
	int ret = len;

	if (!pdev)
		return -EOPNOTSUPP;

	if (xsc_core_is_vf(xdev)) {
		pf_xdev = xsc_get_pf_xdev(xdev);
		if (!pf_xdev || !pf_xdev->netdev)
			return -EOPNOTSUPP;

		pf_netdev = pf_xdev->netdev;
		if (xsc_core_is_ms400(pf_xdev))
			ret = snprintf(buf, len, "p%d", xsc_get_port_index(xdev));
		else
			return -EOPNOTSUPP;
	} else if (xsc_is_vf_rep(dev)) {
		rep = xsc_get_vf_rep(adapter);
		if (!rep)
			return -EOPNOTSUPP;

		ret = snprintf(buf, len, "pf%dvf%d",
			       xsc_get_port_index(xdev), (rep->vport - 1));
	} else if (xsc_core_is_pf(xdev) && xsc_core_is_multihost(xdev)) {
		ret = snprintf(buf, len, "p%d", xsc_get_port_index(xdev));
	} else {
		return -EOPNOTSUPP;
	}

	if (ret >= len)
		return -EOPNOTSUPP;

	return 0;
}

static int xsc_set_vf_rate(struct net_device *dev, int vf, int min_tx_rate, int max_tx_rate)
{
	struct xsc_adapter *adapter = netdev_priv(dev);
	struct xsc_core_sriov *sriov = &adapter->xdev->priv.sriov;
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_eswitch *esw = xdev->priv.eswitch;
	u16 vport;
	int err = 0;
	u32 rate = 0;

	if (vf >= sriov->num_vfs)
		return -EINVAL;

	if (min_tx_rate > 0)
		return -EOPNOTSUPP;

	vport = vf + 1;
	xsc_core_dbg(xdev, "set vf rate %d Mbps\n", max_tx_rate);

	rate = (u32)max_tx_rate;
	err = xsc_eswitch_set_vport_rate(esw, vport, rate, 0);
	if (err) {
		xsc_core_err(xdev, "set_vf_rate failed, err=%d\n", err);
		return -EINVAL;
	}

	return 0;
}

static void xsc_tx_timeout(struct net_device *dev, unsigned int txqueue)
{
	netdev_err(dev, "TX timeout detected\n");
}

static LIST_HEAD(xsc_block_cb_list);

static int xsc_setup_tc(struct net_device *dev, enum tc_setup_type type, void *type_data)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct flow_block_offload *f;
	bool tc_unbind = false;

	if (type == TC_SETUP_BLOCK &&
	    ((struct flow_block_offload *)type_data)->command == FLOW_BLOCK_UNBIND)
		tc_unbind = true;

	if (!netif_device_present(dev) && !tc_unbind)
		return -ENODEV;

	switch (type) {
	case TC_SETUP_BLOCK:
		f = type_data;
		f->unlocked_driver_cb = true;
		return flow_block_cb_setup_simple(type_data,
						  &xsc_block_cb_list,
						  xsc_setup_tc_block_cb,
						  priv, priv, true);
		break;

	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

int xsc_get_port_parent_id(struct net_device *dev, struct netdev_phys_item_id *ppid)
{
	struct xsc_adapter *adapter = netdev_priv(dev);
	struct xsc_core_device *xdev = adapter->xdev;
	u64 parent_id;

	if (xsc_core_is_vf(xdev))
		return -EOPNOTSUPP;

	parent_id = xsc_query_nic_system_image_guid(adapter->xdev);
	ppid->id_len = sizeof(parent_id);
	memcpy(ppid->id, &parent_id, sizeof(parent_id));

	return 0;
}

const struct net_device_ops xsc_netdev_ops = {
	.ndo_open		= xsc_eth_open,
	.ndo_stop		= xsc_eth_close,
	.ndo_start_xmit		= xsc_eth_xmit_start,

	.ndo_set_rx_mode	= xsc_set_rx_mode,
	.ndo_validate_addr	= NULL,
	.ndo_set_mac_address	= xsc_eth_set_mac,
	.ndo_change_mtu = xsc_eth_change_mtu,

	.ndo_tx_timeout		= xsc_tx_timeout,
	.ndo_set_tx_maxrate		= NULL,
	.ndo_vlan_rx_add_vid	= xsc_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= xsc_vlan_rx_kill_vid,
	.ndo_do_ioctl		= NULL,
	.ndo_set_vf_mac		= xsc_set_vf_mac,
	.ndo_set_vf_vlan		= xsc_set_vf_vlan,
	.ndo_set_vf_rate	= xsc_set_vf_rate,
	.ndo_set_vf_spoofchk	= xsc_set_vf_spoofchk,
	.ndo_set_vf_rss_query_en = NULL,
	.ndo_set_vf_trust	= xsc_set_vf_trust,
	.ndo_get_vf_config	= xsc_get_vf_config,
	.ndo_set_vf_link_state = xsc_set_vf_link_state,
	.ndo_get_stats64	= xsc_get_stats,

	.ndo_setup_tc			= xsc_setup_tc,
	.ndo_set_features = xsc_set_features,
	.ndo_fix_features = xsc_fix_features,
	.ndo_fdb_add		= NULL,
	.ndo_bridge_setlink	= NULL,
	.ndo_bridge_getlink	= NULL,
	.ndo_dfwd_add_station	= NULL,
	.ndo_dfwd_del_station	= NULL,
	.ndo_get_phys_port_name  = xsc_get_phys_port_name,

	.ndo_features_check	= NULL,
	.ndo_select_queue	= xsc_select_queue,

		.ndo_get_port_parent_id  = xsc_get_port_parent_id,
};

int xsc_max_nch_limit(struct xsc_core_device *xdev)
{
	return XSC_ETH_MAX_NUM_CHANNELS;
}

static int xsc_get_max_num_channels(struct xsc_core_device *xdev,
				    const struct xsc_profile *profile)
{
#ifdef NEED_CREATE_RX_THREAD
	return 8;
#else
	return min_t(int, xdev->dev_res->eq_table.num_comp_vectors,
		     profile->max_nch_limit(xdev));
#endif
}

static inline void _xsc_get_ifname(struct net_device *netdev, u8 *ifname, int len)
{
	memcpy(ifname, netdev->name, len);
}

static void xsc_get_ifname(void *dev, u8 *ifname, int len)
{
	struct xsc_adapter *adapter =
		(struct xsc_adapter *)((struct xsc_core_device *)dev)->eth_priv;
	struct net_device *netdev = adapter->netdev;

	_xsc_get_ifname(netdev, ifname, len);
}

static void _xsc_get_ip_addr(struct net_device *netdev, u32 *ip_addr)
{
	struct in_device *in_dev;
	struct in_ifaddr *ifa;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(netdev);
	if (!in_dev) {
		*ip_addr = 0;
		goto out;
	}

	ifa = in_dev->ifa_list;
	if (!ifa) {
		*ip_addr = 0;
		goto out;
	}

	*ip_addr = ntohl(ifa->ifa_address);

out:
	rcu_read_unlock();
}

static void xsc_get_ip_addr(void *dev, u32 *ip_addr)
{
	struct xsc_adapter *adapter =
		(struct xsc_adapter *)((struct xsc_core_device *)dev)->eth_priv;
	struct net_device *netdev = adapter->netdev;

	_xsc_get_ip_addr(netdev, ip_addr);
}

static void xsc_get_mac(void *dev, u8 *mac)
{
	struct xsc_adapter *adapter =
		(struct xsc_adapter *)((struct xsc_core_device *)dev)->eth_priv;
	struct net_device *netdev = adapter->netdev;

	ether_addr_copy(mac, netdev->dev_addr);
}

int xsc_eth_priv_init(struct xsc_adapter *adapter,
		      const struct xsc_profile *profile,
		      struct net_device *netdev,
		      struct xsc_core_device *xdev)
{
	unsigned int node;
	int ret = 0;

	/* Set up our device-specific information */
	netdev->dev.parent = &xdev->pdev->dev;
	adapter = netdev_priv(netdev);
	adapter->netdev = netdev;
	adapter->pdev = xdev->pdev;
	adapter->dev = &adapter->pdev->dev;
	adapter->xdev = (void *)xdev;

	node = dev_to_node(adapter->dev);
	adapter->txq2sq = kcalloc_node(netdev->num_tx_queues,
				       sizeof(*adapter->txq2sq), GFP_KERNEL, node);
	if (!adapter->txq2sq) {
		xsc_core_err(xdev, "failed to alloc mem for txq2sq");
		goto err_out;
	}

	mutex_init(&adapter->state_lock);

	INIT_WORK(&adapter->set_rx_mode_work, xsc_set_rx_mode_work);

	adapter->workq = create_singlethread_workqueue("xsc_eth");
	if (!adapter->workq) {
		xsc_core_err(xdev, "failed to create workqueue");
		goto err_free_priv;
	}

	adapter->stats = kvzalloc(sizeof(*adapter->stats), GFP_KERNEL);
	if (unlikely(!adapter->stats)) {
		xsc_core_err(xdev, "failed to alloc mem for stats");
		goto err_destroy_workqueue;
	}

	if (!xsc_is_vf_rep_profile(profile)) {
		ret = xsc_mc_filter_setup(adapter);
		if (ret) {
			xsc_core_err(xdev, "failed to setup mc filter, err=%d", ret);
			goto err_destroy_stats;
		}
	}

	return 0;

err_destroy_stats:
	kfree(adapter->stats);
err_destroy_workqueue:
	destroy_workqueue(adapter->workq);
	adapter->workq = NULL;
err_free_priv:
	kfree(adapter->txq2sq);
err_out:
	return -ENOMEM;
}

void xsc_eth_priv_cleanup(struct xsc_adapter *adapter)
{
	kfree(adapter->txq2sq);
	adapter->txq2sq = NULL;

	kfree(adapter->stats);
	adapter->stats = NULL;

	destroy_workqueue(adapter->workq);
	if (!xsc_is_vf_rep(adapter->netdev))
		xsc_mc_filter_cleanup(adapter);

	xsc_eth_l2_fs_cleanup(adapter);

	memset(adapter, 0, sizeof(*adapter));
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

static void xsc_build_rss_params(struct xsc_rss_params *rss_params, u16 num_channels)
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

static void xsc_eth_build_nic_params(struct xsc_adapter *adapter)
{
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_eth_params *params = &adapter->nic_param;
	const struct xsc_profile *profile = adapter->profile;
	u32 num_chl = xsc_get_max_num_channels(xdev, profile);
	int caps_max_tc = xdev->caps.max_tc;
	int num_tc = min(caps_max_tc, profile->max_tc);

	params->mtu = adapter->netdev->mtu;
	params->num_tc = num_tc;
	params->comp_vectors = num_chl;
	params->max_num_ch = num_chl;
	params->num_channels = num_chl;
	params->bql_thresh = XSC_BQL_THRESHOLD;

	params->sq_size = min(BIT(XSC_DEF_LOG_SQ_SZ), BIT(xdev->caps.log_max_qp_depth));
	params->rq_size = min(BIT(XSC_DEF_LOG_RQ_SZ), BIT(xdev->caps.log_max_qp_depth));
	params->rq_max_size = min(BIT(XSC_MAX_LOG_SQ_SZ), BIT(xdev->caps.log_max_qp_depth));
	params->sq_max_size = min(BIT(XSC_MAX_LOG_RQ_SZ), BIT(xdev->caps.log_max_qp_depth));
	xsc_build_rss_params(&adapter->rss_params, adapter->nic_param.num_channels);

	params->rx_dim_enabled = 1;
	params->tx_dim_enabled = 1;
	xsc_set_rx_cq_mode_params(params, XSC_CQ_PERIOD_MODE_START_FROM_EQE);
	xsc_set_tx_cq_mode_params(params, XSC_CQ_PERIOD_MODE_START_FROM_EQE);

	spin_lock(&adapter->lock);
	if (adapter->netdev->features & NETIF_F_RXCSUM)
		params->pph_usr_cnt = 1;

	if (adapter->netdev->features & NETIF_F_HW_VLAN_CTAG_RX) {
		params->vlan_strip_enabled = 1;
		params->pph_usr_cnt++;
	}

	if (xsc_is_vf_rep(adapter->netdev)) {
		XSC_SET_PFLAG(&adapter->nic_param, XSC_PFLAG_RX_TC_SKB_EXT, true);
		params->pph_usr_cnt++;
	}

	spin_unlock(&adapter->lock);

	xsc_core_info(xdev, "mtu=%d, num_ch=%d(max=%d), num_tc=%d\n",
		      params->mtu, params->num_channels,
		      params->max_num_ch, params->num_tc);
}

int xsc_eth_nic_init(struct net_device *netdev)
{
	struct xsc_adapter *adapter = netdev_priv(netdev);

	xsc_eth_build_nic_params(adapter);

	return 0;
}

void xsc_eth_mtu_set(struct net_device *netdev)
{
	netdev->min_mtu = SW_MIN_MTU;
	netdev->max_mtu = SW_MAX_MTU;
	/*mtu - macheaderlen - ipheaderlen should be aligned in 8B*/
	netdev->mtu = SW_DEFAULT_MTU;
}

static void xsc_eth_build_nic_netdev(struct xsc_adapter *adapter)
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

	xsc_eth_mtu_set(netdev);

	netdev->vlan_features |= NETIF_F_SG |
				NETIF_F_GRO |
				NETIF_F_GSO_PARTIAL;

	if (!xsc_support_hw_feature(xdev, XSC_HW_OFFLOAD_UNSUPPORT)) {
		netdev->vlan_features |= NETIF_F_IP_CSUM |
			NETIF_F_IPV6_CSUM |
			NETIF_F_RXCSUM |
			NETIF_F_RXHASH |
			NETIF_F_TSO |
			NETIF_F_TSO6;
	} else {
		if (xsc_support_hw_feature(xdev, XSC_HW_OFFLOAD_RSS_SUPPORT))
			netdev->vlan_features |= NETIF_F_RXHASH;
	}

	netdev->hw_features = netdev->vlan_features;

	if (!xsc_support_hw_feature(xdev, XSC_HW_OFFLOAD_UNSUPPORT))
		netdev->hw_features |= NETIF_F_HW_VLAN_CTAG_FILTER;

	netdev->features |= netdev->hw_features;

	if (!xsc_support_hw_feature(xdev, XSC_HW_OFFLOAD_UNSUPPORT) &&
	    (xsc_vxlan_allowed(xdev) || xsc_geneve_tx_allowed(xdev) ||
	     xsc_any_tunnel_proto_supported(xdev)) &&
	    XSC_GET_PFLAG(&adapter->nic_param, XSC_PFLAG_TUNNEL_GSO)) {
		netdev->hw_enc_features |= NETIF_F_IP_CSUM |
			NETIF_F_IPV6_CSUM |
			NETIF_F_TSO |
			NETIF_F_TSO6 |
			NETIF_F_GSO_PARTIAL |
			NETIF_F_GSO_UDP_TUNNEL |
			NETIF_F_GSO_UDP_TUNNEL_CSUM;

		netdev->hw_features |= NETIF_F_GSO_UDP_TUNNEL | NETIF_F_GSO_UDP_TUNNEL_CSUM;
	}

	netdev->features |= NETIF_F_HIGHDMA;

	netdev->hw_features |= NETIF_F_HW_TC;

	if (xsc_support_hw_feature(xdev, XSC_HW_RX_VLAN_STRIP)) {
		netdev->hw_features |= NETIF_F_HW_VLAN_CTAG_RX;
		netdev->hw_enc_features |= NETIF_F_HW_VLAN_CTAG_RX;
	}

	if (xsc_support_hw_feature(xdev, XSC_HW_ARP_FILTER_SUPPORT))
		XSC_SET_PFLAG(&adapter->nic_param, XSC_PFLAG_ARP_FILTER, true);
}

static void xsc_eth_nic_cleanup(struct xsc_adapter *adapter)
{
}

static int xsc_eth_init_nic_tx(struct xsc_adapter *adapter)
{
#ifdef CONFIG_XSC_CORE_EN_DCB
	xsc_dcbnl_initialize(adapter);
#endif

	return 0;
}

static void xsc_eth_cleanup_nic_tx(struct xsc_adapter *adapter)
{
}

static int xsc_eth_init_nic_rx(struct xsc_adapter *adapter)
{
	return 0;
}

static void xsc_eth_cleanup_nic_rx(struct xsc_adapter *adapter)
{
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
	eth_hw_addr_set(netdev, mac);

	if (!is_valid_ether_addr(netdev->perm_addr))
		memcpy(netdev->perm_addr, netdev->dev_addr, netdev->addr_len);
}

int xsc_bql_threshold_set(struct xsc_adapter *adapter)
{
	if (adapter->nic_param.bql_thresh) {
		u8 thresh = roundup_pow_of_two(adapter->nic_param.bql_thresh);

		adapter->xdev->bql_thresh = thresh - 1;
		adapter->nic_param.bql_thresh = thresh;
	} else {
		adapter->xdev->bql_thresh = 0;
	}

	xsc_core_dbg(adapter->xdev, "bql_thresh: 0x%x\n", adapter->xdev->bql_thresh);

	return 0;
}

static void xsc_eth_nic_enable(struct xsc_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	u16 cfg_mtu;
	int ret;

	xsc_eth_l2_addr_init(adapter);

	ret = xsc_eth_get_mtu(adapter, &cfg_mtu);
	if (ret == 0) {
		adapter->nic_param.mtu = cfg_mtu;
		adapter->netdev->mtu = cfg_mtu;
	}

	xsc_eth_set_hw_mtu(adapter, XSC_SW2HW_MTU(adapter->nic_param.mtu),
			   XSC_SW2HW_RX_PKT_LEN(adapter->nic_param.mtu));

	xsc_bql_threshold_set(adapter);

	rtnl_lock();
	if (netif_running(netdev))
		xsc_eth_open(netdev);
	netif_device_attach(netdev);
	rtnl_unlock();
}

static void xsc_eth_nic_disable(struct xsc_adapter *adapter)
{
	rtnl_lock();
	if (netif_running(adapter->netdev))
		xsc_eth_close(adapter->netdev);
	netif_device_detach(adapter->netdev);
	rtnl_unlock();
}

extern const struct xsc_rx_handlers xsc_rx_handlers_nic;

const struct xsc_profile xsc_nic_profile = {
	.init		   = xsc_eth_nic_init,
	.cleanup	   = xsc_eth_nic_cleanup,
	.init_rx	   = xsc_eth_init_nic_rx,
	.cleanup_rx	   = xsc_eth_cleanup_nic_rx,
	.init_tx	   = xsc_eth_init_nic_tx,
	.cleanup_tx	   = xsc_eth_cleanup_nic_tx,
	.enable		   = xsc_eth_nic_enable,
	.disable	   = xsc_eth_nic_disable,
	.rx_handlers	   = &xsc_rx_handlers_nic,
	.max_nch_limit	   = xsc_max_nch_limit,
	.max_tc		   = XSC_MAX_NUM_TC,
};

/* call init tx/rx, enable function about nic init */
int xsc_attach_netdev(struct xsc_adapter *adapter)
{
	int err = -1;
	const struct xsc_profile *profile = adapter->profile;

	err = profile->init_tx(adapter);
	if (err)
		goto out;

	err = profile->init_rx(adapter);
	if (err)
		goto out;

	if (profile->enable)
		profile->enable(adapter);

out:
	xsc_core_info(adapter->xdev, "%s, ret=%d\n", __func__, err);
	return err;
}

void xsc_detach_netdev(struct xsc_adapter *adapter)
{
	const struct xsc_profile *profile = adapter->profile;

	if (!profile) {
		xsc_core_err(adapter->xdev, "profile is null");
		return;
	}

	if (profile->disable)
		profile->disable(adapter);

	flush_workqueue(adapter->workq);

	profile->cleanup_rx(adapter);
	profile->cleanup_tx(adapter);

	netdev_reset_tc(adapter->netdev);

	adapter->status = XSCALE_ETH_DRIVER_DETACH;
}

static int xsc_eth_attach(struct xsc_core_device *xdev, struct xsc_adapter *adapter)
{
	int err = -1;

	if (netif_device_present(adapter->netdev))
		return 0;

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

static get_ibdev_name_func_t _xsc_get_mdev_ibdev_name;
void xsc_register_get_mdev_ibdev_name_func(get_ibdev_name_func_t fn)
{
	_xsc_get_mdev_ibdev_name = fn;
}
EXPORT_SYMBOL(xsc_register_get_mdev_ibdev_name_func);

void xsc_unregister_get_mdev_ibdev_name_func(void)
{
	_xsc_get_mdev_ibdev_name = NULL;
}
EXPORT_SYMBOL(xsc_unregister_get_mdev_ibdev_name_func);

static int xsc_get_mdev_info(void *data)
{
	struct xsc_devinfo *devinfo = data;
	struct net *net;
	struct net_device *ndev;
	struct pci_dev *pdev;
	int count = 0;

	rcu_read_lock();
	down_read(&net_rwsem);
	for_each_net(net) {
		for_each_netdev(net, ndev) {
			if (!ndev->dev.parent)
				continue;
			pdev = to_pci_dev(ndev->dev.parent);
			if (pdev->vendor != PCI_VENDOR_ID_MELLANOX)
				continue;

			devinfo->domain = cpu_to_be32(pci_domain_nr(pdev->bus));
			devinfo->bus = cpu_to_be32(pdev->bus->number);
			devinfo->devfn = cpu_to_be32(pdev->devfn);
			_xsc_get_ifname(ndev, devinfo->ifname, MAX_IFNAME_LEN);
			_xsc_get_ip_addr(ndev, &devinfo->ip_addr);
			devinfo->ip_addr = cpu_to_be32(devinfo->ip_addr);
			ether_addr_copy(devinfo->mac, ndev->dev_addr);
			devinfo->vendor_id = cpu_to_be32(PCI_VENDOR_ID_MELLANOX);
			if (_xsc_get_mdev_ibdev_name)
				_xsc_get_mdev_ibdev_name(ndev, devinfo->ibdev_name, MAX_IFNAME_LEN);
			devinfo++;
			count++;
		}
	}
	up_read(&net_rwsem);
	rcu_read_unlock();

	return count;
}

static void xsc_create_netlink_socket(struct xsc_core_device *xdev)
{
	int ret;
	struct socket *sock;
	struct file *file;

	ret = sock_create_kern(&init_net, AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE, &sock);
	if (ret) {
		xsc_core_err(xdev, "failed to create kernel netlink socket, err = %d\n", ret);
		return;
	}

	file = sock_alloc_file(sock, O_RDWR, 0);
	if (!file) {
		xsc_core_err(xdev, "failed to alloc file for netlink socket\n");
		sock_release(sock);
		return;
	}
	xdev->sock = sock;
}

static void xsc_bind_netlink_socket(struct xsc_core_device *xdev)
{
	struct sockaddr_nl addr;
	int ret;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	ret = kernel_bind(xdev->sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret)
		xsc_core_err(xdev, "failed to bind kernel netlink socket, err = %d\n", ret);
}

void xsc_destroy_netdev(struct xsc_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	xsc_eth_priv_cleanup(adapter);
	free_netdev(netdev);
}

struct net_device *
xsc_create_netdev(struct xsc_core_device *xdev, const struct xsc_profile *profile)
{
	struct net_device *netdev;
	int num_chl, num_tc;
	int err = 0;
	unsigned int txqs, rxqs;
	int caps_max_tc;

	num_chl = xsc_get_max_num_channels(xdev, profile);
	caps_max_tc = xdev->caps.max_tc;
	num_tc = min(caps_max_tc, profile->max_tc);
	txqs = num_chl * num_tc;
	rxqs = num_chl;

	/* Allocate ourselves a network device with room for our info */
	netdev = alloc_etherdev_mqs(sizeof(struct xsc_adapter), txqs, rxqs);
	if (unlikely(!netdev)) {
		xsc_core_warn(xdev, "alloc_etherdev_mqs failed, txq=%d, rxq=%d\n",
			      (num_chl * num_tc), num_chl);
		return NULL;
	}

	err = xsc_eth_priv_init(netdev_priv(netdev), profile, netdev, xdev);
	if (err) {
		xsc_core_warn(xdev, "xsc_eth_nic_init failed, num_ch=%d, num_tc=%d, err=%d\n",
			      num_chl, num_tc, err);
		goto err_free_netdev;
	}

	netif_carrier_off(netdev);

	return netdev;

err_free_netdev:
	free_netdev(netdev);

	return NULL;
}

static void *xsc_eth_add(struct xsc_core_device *xdev)
{
	int err = -1;
	struct net_device *netdev;
	struct xsc_adapter *adapter = NULL;
	const struct xsc_profile *profile = &xsc_nic_profile;

	netdev = xsc_create_netdev(xdev, profile);
	if (!netdev) {
		xsc_core_err(xdev, "xsc_create_netdev failed\n");
		err = -ENOMEM;
		goto err_create;
	}

	adapter = netdev_priv(netdev);
	adapter->profile = profile;
	adapter->ppriv = NULL;

	xdev->eth_priv = adapter;
	rcu_assign_pointer(xdev->get_ifname, xsc_get_ifname);
	rcu_assign_pointer(xdev->get_ip_addr, xsc_get_ip_addr);
	rcu_assign_pointer(xdev->get_mac, xsc_get_mac);
	rcu_assign_pointer(xdev->link_event_handler, xsc_link_event_handler);
	rcu_assign_pointer(xdev->port_present_event_handler, xsc_port_present_event_handler);

	xsc_eth_build_nic_netdev(adapter);

	err = profile->init(netdev);
	if (err) {
		xsc_core_err(xdev, "xsc_nic_profile init failed, %d\n", err);
		goto err_free_netdev;
	}

	err = xsc_eth_attach(xdev, adapter);
	if (err) {
		xsc_core_warn(xdev, "xsc_eth_attach failed, err=%d\n", err);
		goto err_cleanup_netdev;
	}

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
	if (is_dpu_host_pf(xdev->pdev->device)) {
		xsc_create_netlink_socket(xdev);
		xsc_bind_netlink_socket(xdev);
		xdev->handle_netlink_cmd = xsc_handle_netlink_cmd;
	}

	if (XSC_ESWITCH_MANAGER(xdev)) {
		xsc_rep_register_vport_reps(xdev);
		xsc_uplink_netdev_set(xdev, netdev);
	}

	if (xsc_core_is_pf(xdev))
		xsc_lag_add_netdev(netdev);

#ifdef CONFIG_XSC_CORE_EN_DCB
	xsc_dcbnl_init_app(adapter);
#endif

	return adapter;

err_sysfs_create:
	unregister_netdev(adapter->netdev);
err_reg_netdev:
	xsc_eth_detach(xdev, adapter);
err_cleanup_netdev:
	profile->cleanup(adapter);
err_free_netdev:
	xsc_destroy_netdev(adapter);
err_create:
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

	if (xsc_core_is_pf(xdev))
		xsc_lag_remove_netdev(adapter->netdev);

	if (XSC_ESWITCH_MANAGER(xdev)) {
		xsc_rep_unregister_vport_reps(xdev);
		xsc_uplink_netdev_set(xdev, NULL);
	}

#ifdef CONFIG_XSC_CORE_EN_DCB
		xsc_dcbnl_delete_app(adapter);
#endif

	if (is_dpu_host_pf(xdev->pdev->device)) {
		sock_release(xdev->sock);
		xdev->handle_netlink_cmd = NULL;
	}

	rcu_assign_pointer(xdev->get_ifname, NULL);
	rcu_assign_pointer(xdev->get_ip_addr, NULL);
	rcu_assign_pointer(xdev->get_mac, NULL);
	synchronize_rcu();
	rcu_assign_pointer(xdev->link_event_handler, NULL);
	rcu_assign_pointer(xdev->port_present_event_handler, NULL);
	flush_workqueue(xdev->event_wq);
	synchronize_srcu(&xdev->srcu);

	xsc_core_info(adapter->xdev, "remove netdev %s entry\n", adapter->netdev->name);

	xsc_eth_sysfs_remove(adapter->netdev, xdev);

	unregister_netdev(adapter->netdev);

	xsc_eth_detach(xdev, adapter);
	xsc_eth_nic_cleanup(adapter);
	xsc_destroy_netdev(adapter);

	xdev->netdev = NULL;
	xdev->eth_priv = NULL;
}

static struct xsc_interface xsc_interface = {
	.add       = xsc_eth_add,
	.remove    = xsc_eth_remove,
	.event     = NULL,
	.protocol  = XSC_INTERFACE_PROTOCOL_ETH,
};

void xsc_remove_eth_driver(void)
{
	pr_info("remove ethernet driver\n");
	xsc_eth_ctrl_fini();
	xsc_unregister_interface(&xsc_interface);
}

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

	xsc_register_get_mdev_info_func(xsc_get_mdev_info);
	return 0;
out:
	return -1;
}

static __exit void xsc_net_driver_exit(void)
{
	xsc_unregister_get_mdev_info_func();
	xsc_remove_eth_driver();
}

module_init(xsc_net_driver_init);
module_exit(xsc_net_driver_exit);
