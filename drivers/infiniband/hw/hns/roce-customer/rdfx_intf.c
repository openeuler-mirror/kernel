// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.
#ifdef CONFIG_INFINIBAND_HNS_DFX
#include "roce_k_compat.h"
#include "hns_roce_device.h"
#include "hns_roce_common.h"
#include "hns_roce_cmd.h"
#include "hnae3.h"
#include "hns_roce_hw_v2.h"
#include "rdfx_common.h"

unsigned int hr_fc_print;
module_param(hr_fc_print, uint, 0644);
MODULE_PARM_DESC(hr_fc_print, "enable function call print");

struct rdfx_qp_info *rdfx_find_rdfx_qp(struct rdfx_info *rdfx,
					      unsigned long qpn);
static struct rdfx_ceq_info *rdfx_find_rdfx_ceq(struct rdfx_info *rdfx,
						int ceqn);
struct rdfx_cq_info *rdfx_find_rdfx_cq(struct rdfx_info *rdfx,
					     unsigned long cqn);

static void rdfx_v2_free_cqe_dma_buf(struct rdfx_cq_info *rdfx_cq)
{
	struct hns_roce_dev *hr_dev = (struct hns_roce_dev *)rdfx_cq->priv;
	u32 size = (rdfx_cq->cq_depth) * hr_dev->caps.cq_entry_sz;

	hns_roce_buf_free(hr_dev, size, (struct hns_roce_buf *)rdfx_cq->buf);
}

static void rdfx_v2_free_wqe_dma_buf(struct rdfx_qp_info *rdfx_qp)
{
	struct hns_roce_dev *hr_dev = (struct hns_roce_dev *)rdfx_qp->priv;
	u32 size = rdfx_qp->buf_size;

	hns_roce_buf_free(hr_dev, size, (struct hns_roce_buf *)rdfx_qp->buf);
}

void qp_release(struct kref *ref)
{
	struct rdfx_qp_info *rdfx_qp =
		container_of(ref, struct rdfx_qp_info, cnt);
	rdfx_v2_free_wqe_dma_buf(rdfx_qp);
	kfree(rdfx_qp->buf);
	kfree(rdfx_qp);
}
EXPORT_SYMBOL_GPL(qp_release);

void cq_release(struct kref *ref)
{
	struct rdfx_cq_info *rdfx_cq =
		container_of(ref, struct rdfx_cq_info, cnt);
	rdfx_v2_free_cqe_dma_buf(rdfx_cq);
	kfree(rdfx_cq->buf);
	kfree(rdfx_cq);
}
EXPORT_SYMBOL_GPL(cq_release);

static void ceq_release(struct kref *ref)
{
	struct rdfx_ceq_info *rdfx_ceq =
		container_of(ref, struct rdfx_ceq_info, cnt);

	kfree(rdfx_ceq);
}

static void pd_release(struct kref *ref)
{
	struct rdfx_pd_info *rdfx_pd =
		container_of(ref, struct rdfx_pd_info, cnt);

	kfree(rdfx_pd);
}

static void mr_release(struct kref *ref)
{
	struct rdfx_mr_info *rdfx_mr =
		container_of(ref, struct rdfx_mr_info, cnt);

	kfree(rdfx_mr);
}

int alloc_rdfx_info(struct hns_roce_dev *hr_dev)
{
	struct rdfx_info *rdfx;

	rdfx = kzalloc(sizeof(*rdfx), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(rdfx))
		return -ENOMEM;

	hr_dev->dfx_priv = rdfx;
	rdfx->priv = hr_dev;

	INIT_LIST_HEAD(&rdfx->pd.list);
	INIT_LIST_HEAD(&rdfx->qp.list);
	INIT_LIST_HEAD(&rdfx->cq.list);
	INIT_LIST_HEAD(&rdfx->mr.list);
	INIT_LIST_HEAD(&rdfx->eq.ceq_list);
	INIT_LIST_HEAD(&rdfx->eq.aeq_list);

	spin_lock_init(&rdfx->pd.pd_lock);
	spin_lock_init(&rdfx->qp.qp_lock);
	spin_lock_init(&rdfx->cq.cq_lock);
	spin_lock_init(&rdfx->mr.mr_lock);
	spin_lock_init(&rdfx->eq.eq_lock);

	return 0;
}

void rdfx_set_dev_name(struct hns_roce_dev *hr_dev)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;

	if (!hr_dev->is_reset) {
		strlcpy(rdfx->dev.dev_name, hr_dev->ib_dev.name,
			IB_DEVICE_NAME_MAX);
		dev_info(hr_dev->dev, "config dfx dev name - %s\n",
			 rdfx->dev.dev_name);
	}
}

/*unregister struct rdfx_info*/
static void rdfx_clean_list(struct rdfx_info *rdfx)
{
	struct rdfx_qp_info *rdfx_qp;
	struct rdfx_cq_info *rdfx_cq;
	struct rdfx_mr_info *rdfx_mr;
	struct rdfx_pd_info *rdfx_pd;
	struct rdfx_ceq_info *rdfx_ceq;
	struct list_head *pos;
	struct list_head *q;

	if (!list_empty(&rdfx->qp.list)) {
		list_for_each_safe(pos, q, &rdfx->qp.list) {
			rdfx_qp = list_entry(pos, struct rdfx_qp_info, list);
			list_del(pos);
			kref_put(&(rdfx_qp->cnt), qp_release);
		}
	}

	if (!list_empty(&rdfx->cq.list)) {
		list_for_each_safe(pos, q, &rdfx->cq.list) {
			rdfx_cq = list_entry(pos, struct rdfx_cq_info, list);
			list_del(pos);
			kref_put(&(rdfx_cq->cnt), cq_release);
		}
	}

	if (!list_empty(&rdfx->mr.list)) {
		list_for_each_safe(pos, q, &rdfx->mr.list) {
			rdfx_mr = list_entry(pos, struct rdfx_mr_info, list);
			list_del(pos);
			kref_put(&(rdfx_mr->cnt), mr_release);
		}
	}

	if (!list_empty(&rdfx->pd.list)) {
		list_for_each_safe(pos, q, &rdfx->pd.list) {
			rdfx_pd = list_entry(pos, struct rdfx_pd_info, list);
			list_del(pos);
			kref_put(&(rdfx_pd->cnt), pd_release);
		}
	}
	if (!list_empty(&rdfx->eq.ceq_list)) {
		list_for_each_safe(pos, q, &rdfx->eq.ceq_list) {
			rdfx_ceq = list_entry(pos, struct rdfx_ceq_info, list);
			list_del(pos);
			kref_put(&(rdfx_ceq->cnt), ceq_release);
		}
	}
}

void free_rdfx_info(struct hns_roce_dev *hr_dev)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;

	if (!rdfx)
		return;
	rdfx_clean_list(rdfx);
	kfree(rdfx);
	hr_dev->dfx_priv = NULL;
}

const char *rdfx_func_name[RDFX_FUNC_MAX] = {
	"modify_dev",
	"query_dev",
	"query_port",
	"modify_port",
	"get_link_lyr",
	"get_netdev",
	"query_gid",
	"add_gid",
	"del_gid",
	"query_pkey",
	"alloc_uctx",
	"dealloc_uctx",
	"hr_mmap",
	"alloc_pd",
	"dealloc_pd",
	"create_ah",
	"query_ah",
	"destroy_ah",
	"create_qp",
	"modify_qp",
	"query_qp",
	"destroy_qp",
	"post_send",
	"post_recv",
	"create_cq",
	"modify_cq",
	"destroy_cq",
	"notify_cq",
	"poll_cq",
	"resize_cq",
	"get_dma_mr",
	"reg_user_mr",
	"rereg_mr",
	"dereg_mr",
	"port_immutbl",
	"reg_umm_mr",
	"dereg_umm_mr",
};
EXPORT_SYMBOL(rdfx_func_name);

void rdfx_func_cnt(struct hns_roce_dev *hr_dev, int func)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;

	atomic_inc(&rdfx->dev.fc[func]);

	if (hr_fc_print && rdfx_func_name[func])
		pr_info("%s has been called %d times!",
			rdfx_func_name[func], atomic_read(&rdfx->dev.fc[func]));
}
EXPORT_SYMBOL_GPL(rdfx_func_cnt);

inline void rdfx_inc_dealloc_qp_cnt(struct hns_roce_dev *hr_dev)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;

	atomic_inc(&rdfx->qp.dealloc_qp_cnt);
}
EXPORT_SYMBOL_GPL(rdfx_inc_dealloc_qp_cnt);

struct rdfx_cq_info *rdfx_get_rdfx_cq(struct hns_roce_dev *hr_dev,
				      unsigned long cqn);

void rdfx_inc_arm_cq_cnt(struct hns_roce_dev *hr_dev, struct hns_roce_cq *hr_cq,
			 enum ib_cq_notify_flags flags)
{
	struct rdfx_cq_info *rdfx_cq;

	rdfx_cq = rdfx_get_rdfx_cq(hr_dev, hr_cq->cqn);
	if (!rdfx_cq) {
		dev_err(hr_dev->dev, "get cq 0x%lx failed while inc arm cq cnt\n",
			hr_cq->cqn);
		return;
	}

	if ((flags & IB_CQ_SOLICITED_MASK) == IB_CQ_SOLICITED)
		atomic_inc(&(rdfx_cq->arm_cnt[0]));
	else
		atomic_inc(&(rdfx_cq->arm_cnt[1]));

	kref_put(&(rdfx_cq->cnt), cq_release);
}
EXPORT_SYMBOL_GPL(rdfx_inc_arm_cq_cnt);

inline void rdfx_inc_dereg_mr_cnt(struct hns_roce_dev *hr_dev)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;

	atomic_inc(&rdfx->mr.dealloc_mr_cnt);
}

inline void rdfx_inc_dealloc_cq_cnt(struct hns_roce_dev *hr_dev)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;

	atomic_inc(&rdfx->cq.dealloc_cq_cnt);
}

void rdfx_inc_sq_db_cnt(struct hns_roce_dev *hr_dev, u32 qpn)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_qp_info *rdfx_qp;

	spin_lock(&(rdfx->qp.qp_lock));

	rdfx_qp = rdfx_find_rdfx_qp(rdfx, qpn);
	if (!rdfx_qp) {
		dev_err(hr_dev->dev, "find qp 0x%x failed while inc sq db cnt!\n",
			qpn);
		spin_unlock(&(rdfx->qp.qp_lock));
		return;
	}
	atomic_inc(&rdfx_qp->sq.db_cnt);

	spin_unlock(&(rdfx->qp.qp_lock));
}
EXPORT_SYMBOL_GPL(rdfx_inc_sq_db_cnt);

void rdfx_inc_rq_db_cnt(struct hns_roce_dev *hr_dev, u32 qpn)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_qp_info *rdfx_qp;

	spin_lock(&(rdfx->qp.qp_lock));

	rdfx_qp = rdfx_find_rdfx_qp(rdfx, qpn);
	if (!rdfx_qp) {
		dev_err(hr_dev->dev, "find qp 0x%x failed while inc rq db cnt!\n",
			qpn);
		spin_unlock(&(rdfx->qp.qp_lock));
		return;
	}
	atomic_inc(&rdfx_qp->rq.db_cnt);

	spin_unlock(&(rdfx->qp.qp_lock));
}
EXPORT_SYMBOL_GPL(rdfx_inc_rq_db_cnt);

void rdfx_inc_ceqe_cnt(struct hns_roce_dev *hr_dev, int ceqn)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_ceq_info *rdfx_ceq;
	unsigned long flags;

	spin_lock_irqsave(&rdfx->eq.eq_lock, flags);

	rdfx_ceq = rdfx_find_rdfx_ceq(rdfx, ceqn);
	if (!rdfx_ceq) {
		dev_err(hr_dev->dev, "find ceq 0x%x failed while inc ceqe cnt!\n",
			ceqn);
		spin_unlock_irqrestore(&rdfx->eq.eq_lock, flags);
		return;
	}
	atomic_inc(&rdfx_ceq->ceqe_cnt);

	spin_unlock_irqrestore(&rdfx->eq.eq_lock, flags);
}
EXPORT_SYMBOL_GPL(rdfx_inc_ceqe_cnt);

/* This function should be called while get rdfx->qp.qp_lock */
struct rdfx_qp_info *rdfx_find_rdfx_qp(struct rdfx_info *rdfx,
					      unsigned long qpn)
{
	struct rdfx_qp_info *rdfx_qp;
	struct list_head *pos;
	struct list_head *q;
	u32 is_existed = 0;

	list_for_each_safe(pos, q, &(rdfx->qp.list)) {
		rdfx_qp = list_entry(pos, struct rdfx_qp_info, list);
		if (qpn == rdfx_qp->qpn) {
			is_existed = 1;
			break;
		}
	}

	if (!is_existed)
		return NULL;

	return rdfx_qp;
}

struct rdfx_qp_info *rdfx_get_rdfx_qp(struct hns_roce_dev *hr_dev,
				      unsigned long qpn)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_qp_info *rdfx_qp;

	spin_lock(&(rdfx->qp.qp_lock));

	rdfx_qp = rdfx_find_rdfx_qp(rdfx, qpn);
	if (!rdfx_qp) {
		dev_err(hr_dev->dev,
			"find qp 0x%lx failed while get rdfx qp!\n", qpn);
		spin_unlock(&(rdfx->qp.qp_lock));
		return NULL;
	}

	kref_get(&(rdfx_qp->cnt));

	spin_unlock(&(rdfx->qp.qp_lock));

	return rdfx_qp;
}
EXPORT_SYMBOL_GPL(rdfx_get_rdfx_qp);

void rdfx_put_rdfx_qp(struct hns_roce_dev *hr_dev, unsigned long qpn)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_qp_info *rdfx_qp;
	unsigned long flags;

	spin_lock_irqsave(&rdfx->qp.qp_lock, flags);

	rdfx_qp = rdfx_find_rdfx_qp(rdfx, qpn);
	if (!rdfx_qp) {
		dev_err(hr_dev->dev, "find qp 0x%lx failed while put rdfx qp!\n",
			qpn);
		spin_unlock_irqrestore(&rdfx->qp.qp_lock, flags);
		return;
	}

	spin_unlock_irqrestore(&rdfx->qp.qp_lock, flags);

	kref_put(&(rdfx_qp->cnt), qp_release);
}
EXPORT_SYMBOL_GPL(rdfx_put_rdfx_qp);

#ifndef CONFIG_INFINIBAND_HNS_DFX_ENHANCE
void rdfx_release_rdfx_qp(struct hns_roce_dev *hr_dev, unsigned long qpn)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_qp_info *rdfx_qp;
	unsigned long flags;

	spin_lock_irqsave(&rdfx->qp.qp_lock, flags);

	rdfx_qp = rdfx_find_rdfx_qp(rdfx, qpn);
	if (!rdfx_qp) {
		dev_err(hr_dev->dev, "find qp 0x%lx failed while release rdfx qp!\n",
			qpn);
		spin_unlock_irqrestore(&rdfx->qp.qp_lock, flags);
		return;
	}
	list_del(&(rdfx_qp->list));

	spin_unlock_irqrestore(&rdfx->qp.qp_lock, flags);

	kref_put(&(rdfx_qp->cnt), qp_release);
}
EXPORT_SYMBOL_GPL(rdfx_release_rdfx_qp);
#endif

/* This function should be called while get rdfx->cq.cq_lock */
struct rdfx_cq_info *rdfx_find_rdfx_cq(struct rdfx_info *rdfx,
					     unsigned long cqn)
{
	struct rdfx_cq_info *rdfx_cq;
	struct list_head *pos;
	struct list_head *q;
	u32 is_existed = 0;

	list_for_each_safe(pos, q, &(rdfx->cq.list)) {
		rdfx_cq = list_entry(pos, struct rdfx_cq_info, list);
		if (cqn == rdfx_cq->cqn) {
			is_existed = 1;
			break;
		}
	}

	if (!is_existed)
		return NULL;

	return rdfx_cq;
}

struct rdfx_cq_info *rdfx_get_rdfx_cq(struct hns_roce_dev *hr_dev,
				      unsigned long cqn)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_cq_info *rdfx_cq;

	spin_lock(&rdfx->cq.cq_lock);

	rdfx_cq = rdfx_find_rdfx_cq(rdfx, cqn);
	if (!rdfx_cq) {
		dev_err(hr_dev->dev, "find cqn %lu failed while get rdfx cq!\n",
			cqn);
		spin_unlock(&rdfx->cq.cq_lock);
		return NULL;
	}
	kref_get(&(rdfx_cq->cnt));

	spin_unlock(&rdfx->cq.cq_lock);

	return rdfx_cq;
}
EXPORT_SYMBOL_GPL(rdfx_get_rdfx_cq);

void rdfx_put_rdfx_cq(struct hns_roce_dev *hr_dev, unsigned long cqn)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_cq_info *rdfx_cq;
	unsigned long flags;

	spin_lock_irqsave(&rdfx->cq.cq_lock, flags);

	rdfx_cq = rdfx_find_rdfx_cq(rdfx, cqn);
	if (!rdfx_cq) {
		dev_err(hr_dev->dev, "find cq %lu failed while get rdfx cq!\n",
			cqn);
		spin_unlock_irqrestore(&rdfx->cq.cq_lock, flags);
		return;
	}

	spin_unlock_irqrestore(&rdfx->cq.cq_lock, flags);

	kref_put(&(rdfx_cq->cnt), cq_release);
}
EXPORT_SYMBOL_GPL(rdfx_put_rdfx_cq);

void rdfx_release_rdfx_cq(struct hns_roce_dev *hr_dev, unsigned long cqn)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_cq_info *rdfx_cq;
	unsigned long flags;

	spin_lock_irqsave(&rdfx->cq.cq_lock, flags);

	rdfx_cq = rdfx_find_rdfx_cq(rdfx, cqn);
	if (!rdfx_cq) {
		dev_err(hr_dev->dev, "find cqn %lu failed while get rdfx cq!\n",
			cqn);
		spin_unlock_irqrestore(&rdfx->cq.cq_lock, flags);
		return;
	}

	list_del(&(rdfx_cq->list));

	spin_unlock_irqrestore(&rdfx->cq.cq_lock, flags);

	kref_put(&(rdfx_cq->cnt), cq_release);
}

/* This function should be called while get rdfx->cq.cq_lock */
static struct rdfx_ceq_info *rdfx_find_rdfx_ceq(struct rdfx_info *rdfx,
						int ceqn)
{
	struct rdfx_ceq_info *rdfx_ceq;
	struct list_head *pos;
	struct list_head *q;
	u32 is_existed = 0;

	list_for_each_safe(pos, q, &(rdfx->eq.ceq_list)) {
		rdfx_ceq = list_entry(pos, struct rdfx_ceq_info, list);
		if (ceqn == rdfx_ceq->ceqn) {
			is_existed = 1;
			break;
		}
	}

	if (!is_existed)
		return NULL;

	return rdfx_ceq;
}

struct rdfx_ceq_info *rdfx_get_rdfx_ceq(struct hns_roce_dev *hr_dev,
					unsigned long ceqn)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_ceq_info *rdfx_ceq;

	spin_lock(&rdfx->eq.eq_lock);

	rdfx_ceq = rdfx_find_rdfx_ceq(rdfx, ceqn);
	if (!rdfx_ceq) {
		dev_err(hr_dev->dev, "find ceqn %lu failed while get rdfx ceq!\n",
			ceqn);
		spin_unlock(&rdfx->eq.eq_lock);
		return NULL;
	}
	kref_get(&(rdfx_ceq->cnt));

	spin_unlock(&rdfx->eq.eq_lock);

	return rdfx_ceq;
}
EXPORT_SYMBOL_GPL(rdfx_get_rdfx_ceq);

void rdfx_put_rdfx_ceq(struct hns_roce_dev *hr_dev, unsigned long ceqn)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_ceq_info *rdfx_ceq;
	unsigned long flags;

	spin_lock_irqsave(&rdfx->eq.eq_lock, flags);

	rdfx_ceq = rdfx_find_rdfx_ceq(rdfx, ceqn);
	if (!rdfx_ceq) {
		dev_err(hr_dev->dev, "find ceq %lu failed while get rdfx ceq!\n",
			ceqn);
		spin_unlock_irqrestore(&rdfx->eq.eq_lock, flags);
		return;
	}

	spin_unlock_irqrestore(&rdfx->eq.eq_lock, flags);

	kref_put(&(rdfx_ceq->cnt), ceq_release);
}
EXPORT_SYMBOL_GPL(rdfx_put_rdfx_ceq);

void rdfx_release_rdfx_ceq(struct hns_roce_dev *hr_dev, unsigned long ceqn)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_ceq_info *rdfx_ceq;
	unsigned long flags;

	spin_lock_irqsave(&rdfx->eq.eq_lock, flags);

	rdfx_ceq = rdfx_find_rdfx_ceq(rdfx, ceqn);
	if (!rdfx_ceq) {
		dev_err(hr_dev->dev, "find ceq %lu failed while release rdfx ceq!\n",
			ceqn);
		spin_unlock_irqrestore(&rdfx->eq.eq_lock, flags);
		return;
	}
	list_del(&(rdfx_ceq->list));

	spin_unlock_irqrestore(&rdfx->eq.eq_lock, flags);

	kref_put(&(rdfx_ceq->cnt), ceq_release);
}
EXPORT_SYMBOL_GPL(rdfx_release_rdfx_ceq);

void rdfx_alloc_rdfx_ceq(struct hns_roce_dev *hr_dev, unsigned long ceqn,
			 unsigned int eq_cmd)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_ceq_info *rdfx_ceq;
	unsigned long flags;

	if (eq_cmd == HNS_ROCE_CMD_CREATE_CEQC) {
		rdfx_ceq = kzalloc(sizeof(struct rdfx_ceq_info), GFP_KERNEL);
		if (ZERO_OR_NULL_PTR(rdfx_ceq))
			return;

		rdfx_ceq->ceqn = ceqn;
		kref_init(&(rdfx_ceq->cnt));

		spin_lock_irqsave(&rdfx->eq.eq_lock, flags);
		list_add_tail(&rdfx_ceq->list, &rdfx->eq.ceq_list);
		spin_unlock_irqrestore(&rdfx->eq.eq_lock, flags);
	}
}
EXPORT_SYMBOL_GPL(rdfx_alloc_rdfx_ceq);

void rdfx_alloc_cq_buf(struct hns_roce_dev *hr_dev, struct hns_roce_cq *hr_cq)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct hns_roce_buf *dfx_cq_buf;
	struct rdfx_cq_info *rdfx_cq;
	unsigned long flags;
	u32 page_shift;
	int cq_entries;
	int ret;

	cq_entries = hr_cq->cq_depth;

	dfx_cq_buf = kzalloc(sizeof(struct hns_roce_buf), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(dfx_cq_buf))
		return;

	page_shift = PAGE_SHIFT + hr_dev->caps.cqe_buf_pg_sz;

	ret = hns_roce_buf_alloc(hr_dev, cq_entries * hr_dev->caps.cq_entry_sz,
				 (1 << page_shift) * 2, dfx_cq_buf, page_shift);
	if (ret) {
		dev_err(hr_dev->dev, "hns_roce_dfx_buf_alloc error!\n");
		goto err_dfx_buf;
	}

#ifdef CONFIG_INFINIBAND_HNS_DFX_ENHANCE
	rdfx_put_rdfx_cq(hr_dev, hr_cq->cqn);
#endif

	rdfx_cq = kzalloc(sizeof(*rdfx_cq), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(rdfx_cq))
		goto err_buf;

	rdfx_cq->buf = dfx_cq_buf;
	rdfx_cq->cq_depth = cq_entries;
	rdfx_cq->cqn = hr_cq->cqn;
	rdfx_cq->cq = &hr_cq->ib_cq;
	rdfx_cq->priv = hr_dev;

	atomic_inc(&rdfx->cq.alloc_cq_cnt);
	if (hr_cq->cqn > rdfx->cq.top_cq_index.counter)
		atomic_set(&rdfx->cq.top_cq_index, (int)hr_cq->cqn);
	kref_init(&(rdfx_cq->cnt));

	spin_lock_irqsave(&rdfx->cq.cq_lock, flags);
	list_add_tail(&rdfx_cq->list, &rdfx->cq.list);
	spin_unlock_irqrestore(&rdfx->cq.cq_lock, flags);

	return;

err_buf:
	hns_roce_buf_free(hr_dev, cq_entries * hr_dev->caps.cq_entry_sz,
		dfx_cq_buf);
err_dfx_buf:
	kfree(dfx_cq_buf);
}

void rdfx_free_cq_buff(struct hns_roce_dev *hr_dev, struct hns_roce_cq *hr_cq)
{
#ifndef CONFIG_INFINIBAND_HNS_DFX_ENHANCE
	rdfx_release_rdfx_cq(hr_dev, hr_cq->cqn);
#endif
}

void rdfx_alloc_qp_buf(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct hns_roce_buf *dfx_qp_buf;
	struct rdfx_qp_info *rdfx_qp;
	u32 page_shift = 0;
	unsigned long flags;

	dfx_qp_buf = kzalloc(sizeof(struct hns_roce_buf), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(dfx_qp_buf))
		return;

	page_shift = PAGE_SHIFT + hr_dev->caps.mtt_buf_pg_sz;

	if (hns_roce_buf_alloc(hr_dev, hr_qp->buff_size, (1 << page_shift) * 2,
		dfx_qp_buf, page_shift)) {
		kfree(dfx_qp_buf);
		dev_err(hr_dev->dev, "alloc dfx qp 0x%lx buff failed!\n",
			hr_qp->qpn);
		return;
	}

	rdfx_qp = kzalloc(sizeof(*rdfx_qp), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(rdfx_qp)) {
		hns_roce_buf_free(hr_dev, hr_qp->buff_size, dfx_qp_buf);
		kfree(dfx_qp_buf);
		return;
	}

	rdfx_qp->buf = dfx_qp_buf;
	rdfx_qp->priv = hr_dev;
	rdfx_qp->buf_size = hr_qp->buff_size;
	rdfx_qp->sq.sq_depth = hr_qp->sq.wqe_cnt;
	rdfx_qp->rq.rq_depth = hr_qp->rq.wqe_cnt;
	rdfx_qp->sq.offset = hr_qp->sq.offset;
	rdfx_qp->rq.offset = hr_qp->rq.offset;
	rdfx_qp->sq.sq_wqe_size = hr_qp->sq.wqe_shift;
	rdfx_qp->rq.rq_wqe_size = hr_qp->rq.wqe_shift;
	rdfx_qp->qp = &hr_qp->ibqp;
	rdfx_qp->qpn = hr_qp->ibqp.qp_num;

	kref_init(&(rdfx_qp->cnt));
	atomic_inc(&rdfx->qp.alloc_qp_cnt);
	if (hr_qp->ibqp.qp_num > rdfx->qp.top_qp_index.counter)
		atomic_set(&rdfx->qp.top_qp_index, (int)hr_qp->ibqp.qp_num);

	spin_lock_irqsave(&rdfx->qp.qp_lock, flags);
	list_add_tail(&rdfx_qp->list, &rdfx->qp.list);
	spin_unlock_irqrestore(&rdfx->qp.qp_lock, flags);
}

void rdfx_set_qp_attr(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp,
		      const struct ib_qp_attr *attr, int attr_mask,
		      enum ib_qp_state new_state)
{
	struct rdfx_qp_info *rdfx_qp;

	if (attr_mask & IB_QP_ACCESS_FLAGS) {
		rdfx_qp = rdfx_get_rdfx_qp(hr_dev, hr_qp->qpn);
		if (!rdfx_qp) {
			dev_err(hr_dev->dev, "get rdfx qp 0x%lx failed while set qp!\n",
				hr_qp->qpn);
			return;
		}

		rdfx_qp->attr.read_en =
			attr->qp_access_flags & IB_ACCESS_REMOTE_READ;
		rdfx_qp->attr.write_en =
			attr->qp_access_flags & IB_ACCESS_REMOTE_WRITE;
		rdfx_qp->attr.atomic_en =
		attr->qp_access_flags & IB_ACCESS_REMOTE_ATOMIC;
		atomic_set(&rdfx_qp->attr.state, (int)new_state);
		rdfx_qp->attr.max_ird = attr->max_rd_atomic;
		rdfx_qp->attr.max_ord = attr->max_dest_rd_atomic;
		rdfx_qp->attr.max_sge[0] = attr->cap.max_send_sge;
		rdfx_qp->attr.max_sge[1] = attr->cap.max_recv_sge;
		rdfx_qp->attr.pd_id = to_hr_pd(hr_qp->ibqp.pd)->pdn;

		kref_put(&(rdfx_qp->cnt), qp_release);
	}
}
EXPORT_SYMBOL_GPL(rdfx_set_qp_attr);

void rdfx_alloc_rdfx_mr(struct hns_roce_dev *hr_dev, struct hns_roce_mr *mr)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_mr_info *rdfx_mr;
	unsigned long flags;

	rdfx_mr = kzalloc(sizeof(*rdfx_mr), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(rdfx_mr))
		return;

	rdfx_mr->pd = mr->pd;
	rdfx_mr->mr = &mr->ibmr;
	kref_init(&(rdfx_mr->cnt));
	atomic_inc(&rdfx->mr.alloc_mr_cnt);

	spin_lock_irqsave(&rdfx->mr.mr_lock, flags);
	list_add_tail(&rdfx_mr->list, &rdfx->mr.list);
	spin_unlock_irqrestore(&rdfx->mr.mr_lock, flags);
}

/* This function should be called while get rdfx->mr.mr_lock */
static struct rdfx_mr_info *rdfx_find_rdfx_mr(struct rdfx_info *rdfx,
					      unsigned long key)
{
	struct rdfx_mr_info *rdfx_mr;
	struct list_head *pos;
	struct list_head *q;
	u32 is_existed = 0;

	list_for_each_safe(pos, q, &(rdfx->mr.list)) {
		rdfx_mr = list_entry(pos, struct rdfx_mr_info, list);
		if (key == rdfx_mr->mr->lkey) {
			is_existed = 1;
			break;
		}
	}

	if (!is_existed)
		return NULL;

	return rdfx_mr;
}

void rdfx_release_rdfx_mr(struct hns_roce_dev *hr_dev, unsigned long key)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_mr_info *rdfx_mr;
	unsigned long flags;

	spin_lock_irqsave(&rdfx->mr.mr_lock, flags);

	rdfx_mr = rdfx_find_rdfx_mr(rdfx, key);
	if (!rdfx_mr) {
		dev_err(hr_dev->dev, "find mr 0x%lx failed while release rdfx mr!\n",
			key);
		spin_unlock_irqrestore(&rdfx->mr.mr_lock, flags);
		return;
	}
	list_del(&(rdfx_mr->list));

	spin_unlock_irqrestore(&rdfx->mr.mr_lock, flags);

	kref_put(&(rdfx_mr->cnt), mr_release);
}

void rdfx_alloc_rdfx_pd(struct hns_roce_dev *hr_dev, struct hns_roce_pd *pd)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_pd_info *rdfx_pd;
	unsigned long flags;

	rdfx_pd = kzalloc(sizeof(struct rdfx_pd_info), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(rdfx_pd))
		return;

	rdfx_pd->pdn = pd->pdn;
	rdfx_pd->pd = &pd->ibpd;
	kref_init(&(rdfx_pd->cnt));
	atomic_inc(&rdfx->pd.alloc_pd_cnt);

	if (pd->pdn > rdfx->pd.top_pd_index.counter)
		atomic_set(&rdfx->pd.top_pd_index, (int)pd->pdn);

	spin_lock_irqsave(&rdfx->pd.pd_lock, flags);
	list_add_tail(&rdfx_pd->list, &rdfx->pd.list);
	spin_unlock_irqrestore(&rdfx->pd.pd_lock, flags);
}

static struct rdfx_pd_info *rdfx_find_rdfx_pd(struct hns_roce_dev *hr_dev,
					      unsigned long pdn)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_pd_info *rdfx_pd;
	struct list_head *pos;
	struct list_head *q;
	u32 is_existed = 0;

	list_for_each_safe(pos, q, &(rdfx->pd.list)) {
		rdfx_pd = list_entry(pos, struct rdfx_pd_info, list);
		if (pdn == rdfx_pd->pdn) {
			is_existed = 1;
			break;
		}
	}

	if (!is_existed)
		return NULL;

	return rdfx_pd;
}

void rdfx_release_rdfx_pd(struct hns_roce_dev *hr_dev, unsigned long pdn)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_pd_info *rdfx_pd;
	unsigned long flags;

	spin_lock_irqsave(&rdfx->pd.pd_lock, flags);

	rdfx_pd = rdfx_find_rdfx_pd(hr_dev, pdn);
	if (!rdfx_pd) {
		dev_err(hr_dev->dev, "find pd 0x%lx failed while release rdfx pd!\n",
			pdn);
		spin_unlock_irqrestore(&rdfx->pd.pd_lock, flags);
		return;
	}
	list_del(&(rdfx_pd->list));

	spin_unlock_irqrestore(&rdfx->pd.pd_lock, flags);

	kref_put(&(rdfx_pd->cnt), pd_release);
}

void rdfx_set_rdfx_cq_ci(struct hns_roce_dev *hr_dev,
			 struct hns_roce_cq *hr_cq)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_cq_info *rdfx_cq;

	spin_lock(&rdfx->cq.cq_lock);

	rdfx_cq = rdfx_find_rdfx_cq(rdfx, hr_cq->cqn);
	if (!rdfx_cq) {
		dev_err(hr_dev->dev, "find cq 0x%lx failed while set cq ci\n",
			hr_cq->cqn);
		spin_unlock(&rdfx->cq.cq_lock);
		return;
	}

	atomic_set(&rdfx_cq->ci, (int)(hr_cq->cons_index & 0xffffff));

	spin_unlock(&rdfx->cq.cq_lock);
}
EXPORT_SYMBOL_GPL(rdfx_set_rdfx_cq_ci);
#endif
