/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __RDFX_COMMON__
#define __RDFX_COMMON__

#include <rdma/ib_verbs.h>
#include "hns_roce_device.h"
#include "hns_roce_common.h"
#include "hnae3.h"
#include "hns_roce_hw_v2.h"

#define WQE_TYPE_MAX	(IB_WR_REG_SIG_MR + 1)
#define CQ_ST_MAX	(IB_WC_GENERAL_ERR + 1)
#define RCQE_TYPE_MAX	(RECV_SEND_WITH_INV + 1)
#define RDFX_FUNC_MAX	(37)

extern const char *rdfx_func_name[RDFX_FUNC_MAX];
struct rdfx_info;

/**************** kobject attribute ****************/
struct rdfx_hw_sys_attr {
	struct attribute attr;
	int (*pub_show)(struct rdfx_info *rdfx);
	int (*pub_store)(const char *buf, struct rdfx_info *rdfx);
};

#define rdfx_hw_file_attr_def(file_name, func_show, func_store) \
static struct rdfx_hw_sys_attr g_sysfs_roce_##file_name##_attr = {\
	{\
		.name = #file_name,\
		.mode = 0644,\
	},\
	.pub_show  = func_show,\
	.pub_store = func_store,\
}

#define HW_ATTRS_LIST_MEMBER(file_name)(&g_sysfs_roce_##file_name##_attr.attr)

enum {
	RECV_RDMA_WITH_IMM,
	RECV_SEND,
	RECV_SEND_WITH_IMM,
	RECV_SEND_WITH_INV,
};

#define MAX_CHAR_NUM_DEV_NAME	(12)
struct rdfx_dev_info {
	atomic_t fc[RDFX_FUNC_MAX];
	char dev_name[MAX_CHAR_NUM_DEV_NAME];
};

struct rdfx_pd_info {
	struct ib_pd		*pd;
	unsigned long		pdn;
	struct list_head	list;
	void			*priv;
	struct kref		cnt;
};

struct rdfx_pd_top_info {
	atomic_t		alloc_pd_cnt;
	atomic_t		dealloc_pd_cnt;
	atomic_t		top_pd_index;
	struct list_head	list;
	spinlock_t		pd_lock;
};

struct rdfx_sq_info {
	atomic_t		sq_wqe_cnt[WQE_TYPE_MAX];
	u32			sq_wqe_size;
	u32			sq_sge_size;
	u32			offset;
	u32			sq_depth;
	atomic_t		sig_wqe_cnt;
	atomic_t		db_cnt;
	atomic_t		inline_cnt;
	atomic_t		head;
	atomic_t		tail;
	atomic_t		last_comp;
	u64			head_addr;
	u64			tail_addr;
};

struct rdfx_rq_info {
	atomic_t		rq_wqe_cnt;
	u32			rq_wqe_size;
	u32			offset;
	u32			rq_depth;
	atomic_t		db_cnt;
	atomic_t		inline_cnt;
	atomic_t		head;
	atomic_t		tail;
	u64			head_addr;
	u64			tail_addr;
};

struct rdfx_qp_attr {
	atomic_t		state;
	u32			read_en;
	u32			write_en;
	u32			fast_reg_en;
	u32			atomic_en;
	u8			max_ord;
	u8			max_ird;
	u32			pd_id;
	u32			err_code;
	u32			max_sge[2];
};

struct rdfx_qp_info {
	struct ib_qp		*qp;
	unsigned long		qpn;
	struct rdfx_sq_info	sq;
	struct rdfx_rq_info	rq;
	struct rdfx_qp_attr	attr;
	struct list_head	list;
	void			*priv;
	void			*buf;
	u32			buf_size;
	struct kref		cnt;
};

struct rdfx_qp_top_info {
	atomic_t		alloc_qp_cnt;
	atomic_t		dealloc_qp_cnt;
	atomic_t		top_qp_index;
	atomic_t		dwqe_cnt;
	struct list_head	list;
	spinlock_t		qp_lock;
};

struct rdfx_cq_info {
	struct ib_cq		*cq;
	unsigned long		cqn;
	atomic_t		scqe_cnt[WQE_TYPE_MAX];
	atomic_t		rcqe_cnt[RCQE_TYPE_MAX];
	atomic_t		arm_cnt[2];
	atomic_t		st_cnt[CQ_ST_MAX];
	atomic_t		ci;
	u32			cqe_size;
	u32			cq_depth;
	struct list_head	list;
	void			*priv;
	void			*buf;
	struct kref		cnt;
};

struct rdfx_cq_top_info {
	atomic_t		alloc_cq_cnt;
	atomic_t		dealloc_cq_cnt;
	atomic_t		top_cq_index;
	struct list_head	list;
	spinlock_t		cq_lock;
};

struct rdfx_mr_info {
	struct ib_mr		*mr;
	u32			pd;
	struct list_head	list;
	struct kref		cnt;
};

struct rdfx_mr_top_info {
	atomic_t		alloc_mr_cnt;
	atomic_t		dealloc_mr_cnt;
	atomic_t		top_mr_index;
	struct list_head	list;
	spinlock_t		mr_lock;
};

struct rdfx_ceq_info {
	struct list_head	list;
	unsigned long		ceqn;
	atomic_t		ceqe_cnt;
	void			*priv;
	struct kref		cnt;
};

struct rdfx_aeq_info {
	struct list_head	list;
	atomic_t		aeqe_cnt;
	void			*priv;
	struct kref		cnt;
};

struct rdfx_eq_top_info {
	struct list_head	ceq_list;
	struct list_head	aeq_list;
	spinlock_t		eq_lock;
};

struct rdfx_ops {
	int (*add_sysfs)(struct rdfx_info *info);
	void (*del_sysfs)(struct rdfx_info *info);
	void (*print_sq_wqe)(void *wqe);
	void (*print_rq_wqe)(void *wqe);
	void *(*get_dfx)(struct ib_device *ib_dev);
};

struct rdfx_info {
	struct rdfx_dev_info	dev;
	struct rdfx_pd_top_info	pd;
	struct rdfx_qp_top_info	qp;
	struct rdfx_cq_top_info	cq;
	struct rdfx_mr_top_info	mr;
	struct rdfx_eq_top_info	eq;
	struct rdfx_ops		*ops;

	struct device		*drv_dev;
	struct kobject		kobj;

	void			*priv;
};

struct rdfx_dev_id {
	char			name[20];
	struct rdfx_ops		*ops;
};

struct rdfx_top_info {
	struct ib_device	*dev;
	struct rdfx_info	*rdfx;
};

void qp_release(struct kref *ref);
void cq_release(struct kref *ref);

#endif
