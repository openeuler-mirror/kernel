// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <asm/cacheflush.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <rdma/ib_verbs.h>

#include "rdfx_common.h"
#include "rdfx_main.h"

static struct kobject rdfx_common_kobj;

static ssize_t rdfx_common_show(struct kobject *kobj, struct attribute *attr,
				char *buf);
static ssize_t rdfx_common_store(struct kobject *kobj, struct attribute *attr,
				 const char *buf, size_t count);

static int show_pd_detail(struct rdfx_pd_info *rdfx_pd)
{
	pr_info("***************** PD INFO *****************\n");

	return 0;
}

static int rdfx_pd_store(const char *p_buf)
{
	struct rdfx_pd_info *rdfx_pd;
	char *buf = (char *)p_buf;
	struct rdfx_info *rdfx;
	long long convert_val;
	char dev_name[DEF_OPT_STR_LEN];
	char str[DEF_OPT_STR_LEN];
	u32 pdn = 0;

	parg_getopt(buf, "d:", dev_name);
	rdfx = rdfx_find_rdfx_info(dev_name);
	if (!rdfx) {
		pr_err("pd: can't find device of %s\n", dev_name);
		return -EINVAL;
	}

	parg_getopt(buf, "v:", str);
	if (kstrtoll(str, 0, &convert_val)) {
		pr_info("convert str failed\n");
		return -EINVAL;
	}
	pdn = (u32)convert_val;

	pr_info("***************** PD(0x%x) INFO *****************\n",
		pdn);
	pr_info("alloc_pd_cnt	  : 0x%x\n",
		atomic_read(&(rdfx->pd.alloc_pd_cnt)));
	pr_info("dealloc_pd_cnt  : 0x%x\n",
		atomic_read(&(rdfx->pd.dealloc_pd_cnt)));
	pr_info("top_pd_index	  : 0x%x\n",
		atomic_read(&(rdfx->pd.top_pd_index)));

	list_for_each_entry(rdfx_pd, &(rdfx->pd.list), list) {
		if (pdn == rdfx_pd->pdn)
			return show_pd_detail(rdfx_pd);
	}

	pr_err("pd index(0x%x) is invalid\n", pdn);
	return -EINVAL;
}

static int show_qp_detail(struct rdfx_qp_info *rdfx_qp)
{
	pr_info("***************** SQ INFO *****************\n");
	pr_info("sq_wqe_cnt:\n");

	pr_info("IB_WR_RDMA_WRITE		IB_WR_RDMA_WRITE_WITH_IMM\n");
	pr_info("	0x%x				0x%x\n",
		atomic_read(&rdfx_qp->sq.sq_wqe_cnt[IB_WR_RDMA_WRITE]),
		atomic_read(
		  &rdfx_qp->sq.sq_wqe_cnt[IB_WR_RDMA_WRITE_WITH_IMM]));

	pr_info("IB_WR_SEND			IB_WR_RDMA_READ\n");
	pr_info("	0x%x				0x%x\n",
		atomic_read(&rdfx_qp->sq.sq_wqe_cnt[IB_WR_SEND]),
		atomic_read(&rdfx_qp->sq.sq_wqe_cnt[IB_WR_RDMA_READ]));

	pr_info("IB_WR_SEND_WITH_INV		IB_WR_SEND_WITH_IMM\n");
	pr_info("	0x%x				0x%x\n",
		atomic_read(&rdfx_qp->sq.sq_wqe_cnt[IB_WR_SEND_WITH_INV]),
		atomic_read(&rdfx_qp->sq.sq_wqe_cnt[IB_WR_SEND_WITH_IMM]));

	pr_info("IB_WR_ATOMIC_FETCH_AND_ADD	IB_WR_ATOMIC_CMP_AND_SWP\n");
	pr_info("	0x%x				0x%x\n",
		atomic_read(
		  &rdfx_qp->sq.sq_wqe_cnt[IB_WR_ATOMIC_FETCH_AND_ADD]),
		atomic_read(&rdfx_qp->sq.sq_wqe_cnt[IB_WR_ATOMIC_CMP_AND_SWP]));

	pr_info("IB_WR_MASKED_ATOMIC_FETCH_AND_ADD  IB_WR_MASKED_ATOMIC_CMP_AND_SWP\n");
	pr_info("	0x%x				0x%x\n",
		atomic_read(
		&rdfx_qp->sq.sq_wqe_cnt[IB_WR_MASKED_ATOMIC_FETCH_AND_ADD]),
		atomic_read(
		&rdfx_qp->sq.sq_wqe_cnt[IB_WR_MASKED_ATOMIC_CMP_AND_SWP]));

	pr_info("IB_WR_REG_MR			IB_WR_LOCAL_INV\n");
	pr_info("	0x%x				0x%x\n",
		atomic_read(&rdfx_qp->sq.sq_wqe_cnt[IB_WR_REG_MR]),
		atomic_read(&rdfx_qp->sq.sq_wqe_cnt[IB_WR_LOCAL_INV]));

	pr_info("IB_WR_RDMA_READ_WITH_INV	IB_WR_LSO\n");
	pr_info("	0x%x				0x%x\n",
		atomic_read(&rdfx_qp->sq.sq_wqe_cnt[IB_WR_RDMA_READ_WITH_INV]),
		atomic_read(&rdfx_qp->sq.sq_wqe_cnt[IB_WR_LSO]));


	pr_info("\n");
	pr_info("sig_wqe_cnt      bd_cnt       inline_cnt\n");
	pr_info("   0x%x           0x%x          0x%x\n",
		atomic_read(&rdfx_qp->sq.sig_wqe_cnt),
		atomic_read(&rdfx_qp->sq.db_cnt),
		atomic_read(&rdfx_qp->sq.inline_cnt));
	pr_info("\n");
	pr_info("***************** RQ INFO *****************\n");
	pr_info("rq_wqe_cnt       bd_cnt        inline_cnt\n");
	pr_info("   0x%x	    0x%x	   0x%x\n",
		    atomic_read(&rdfx_qp->rq.rq_wqe_cnt),
		    atomic_read(&rdfx_qp->rq.db_cnt),
		    atomic_read(&rdfx_qp->rq.inline_cnt));
	pr_info("\n");
	pr_info("***************** QP ATTR *****************\n");
	pr_info("state        : 0x%x\n",
		atomic_read(&rdfx_qp->attr.state));
	pr_info("read_en      : 0x%x\n", rdfx_qp->attr.read_en);
	pr_info("write_en     : 0x%x\n", rdfx_qp->attr.write_en);
	pr_info("fast_reg_en  : 0x%x\n", rdfx_qp->attr.fast_reg_en);
	pr_info("atomic_en    : 0x%x\n", rdfx_qp->attr.atomic_en);
	pr_info("max_ord      : 0x%x\n", rdfx_qp->attr.max_ord);
	pr_info("max_ird      : 0x%x\n", rdfx_qp->attr.max_ird);
	pr_info("pd_id        : 0x%x\n", rdfx_qp->attr.pd_id);
	pr_info("err_rode     : 0x%x\n", rdfx_qp->attr.err_code);
	pr_info("max_send_sge : 0x%x\n", rdfx_qp->attr.max_sge[0]);
	pr_info("max_recv_sge : 0x%x\n", rdfx_qp->attr.max_sge[1]);

	return 0;
}

static void show_valid_qpn(struct list_head *head)
{
	struct rdfx_qp_info *rdfx_qp;
	int line_len = 0;

	pr_info("current valid qpn:\n");
	list_for_each_entry(rdfx_qp, head, list) {
		if (rdfx_qp->qp != NULL) {
			pr_info("0x%lx      ", rdfx_qp->qpn);
			line_len++;
			if (line_len == 10) {
				pr_info("\n");
				line_len = 0;
			}

		}
	}
	pr_info("\n");
}

static int show_wqe(struct rdfx_qp_info *rdfx_qp, u32 sq_or_rq, int wqe_index)
{
	u32 *wqe;

	if (sq_or_rq == 1) {
		wqe_index = wqe_index & (rdfx_qp->sq.sq_depth - 1);
		wqe = rdfx_buf_offset(rdfx_qp->buf, rdfx_qp->sq.offset +
			(wqe_index << rdfx_qp->sq.sq_wqe_size));
	} else if (sq_or_rq == 2) {
		wqe_index = wqe_index & (rdfx_qp->sq.sq_depth - 1);
		wqe = rdfx_buf_offset(rdfx_qp->buf, rdfx_qp->rq.offset +
			(wqe_index << rdfx_qp->rq.rq_wqe_size));
	}
	if (wqe)
		pr_info("%08x %08x %08x %08x %08x %08x %08x %08x\n",
			*wqe, *(wqe + 1), *(wqe + 2), *(wqe + 3),
			*(wqe + 4), *(wqe + 5),	*(wqe + 6), *(wqe + 7));
	else
		pr_info("wqe buf was not alloced\n");

	return 0;
}

static int show_cqe(struct rdfx_cq_info *rdfx_cq, int cqe_index)
{
	u32 *cqe;

	rdfx_cq->cqe_size = CQE_SIZE;
	cqe_index = cqe_index & (rdfx_cq->cq_depth - 1);
	cqe = rdfx_buf_offset(rdfx_cq->buf, (cqe_index * rdfx_cq->cqe_size));
	if (cqe)
		pr_info("%08x %08x %08x %08x %08x %08x %08x %08x\n",
			*cqe, *(cqe + 1), *(cqe + 2), *(cqe + 3),
			*(cqe + 4), *(cqe + 5),	*(cqe + 6), *(cqe + 7));
	else
		pr_info("cqe buf was not alloced\n");

	return 0;
}

static inline int rdfx_convert_str(char *str, u32 *val)
{
	long long convert_val;

	if (kstrtoll(str, 0, &convert_val)) {
		pr_info("convert str failed\n");
		return -EINVAL;
	}
	*val = (u32)convert_val;

	return 0;
}

static inline int rdfx_show_qp_wqe(char *sq_rq, void *buf, u32 qpn,
				   struct rdfx_info *rdfx)
{
	struct rdfx_qp_info *rdfx_qp;
	char str[DEF_OPT_STR_LEN] = {0};
	u32 sq_or_rq = 0;
	u32 wqe_index = 0;

	if (!memcmp(sq_rq, "sq", strlen("sq"))) {
		sq_or_rq = 1;
		parg_getopt(buf, "i:", str);
		if (rdfx_convert_str(str, &wqe_index))
			return -EINVAL;

		pr_info("show sq(0x%x) wqe(0x%x) info:\n", qpn, wqe_index);
	}

	if (!memcmp(sq_rq, "rq", strlen("rq"))) {
		sq_or_rq = 2;
		parg_getopt(buf, "i:", str);
		if (rdfx_convert_str(str, &wqe_index))
			return -EINVAL;

		pr_info("show rq(0x%x) wqe(0x%x) info:\n", qpn, wqe_index);
	}

	if (sq_or_rq) {
		list_for_each_entry(rdfx_qp, &(rdfx->qp.list), list) {
			if (qpn == rdfx_qp->qpn)
				return show_wqe(rdfx_qp, sq_or_rq, wqe_index);
		}
		pr_err("QPN %u is not in dfx list!\n", qpn);
	}

	return -EINVAL;
}

static int rdfx_qp_store(const char *p_buf)
{
	struct rdfx_qp_info *rdfx_qp;
	struct rdfx_info *rdfx;
	char *buf = (char *)p_buf;
	char dev_name[DEF_OPT_STR_LEN] = {0};
	char str[DEF_OPT_STR_LEN] = {0};
	char sq_rq[DEF_OPT_STR_LEN] = {0};
	u32 qpn;

	parg_getopt(buf, "d:", dev_name);
	rdfx = rdfx_find_rdfx_info(dev_name);
	if (!rdfx) {
		pr_err("cann't find dev of %s\n", dev_name);
		return -EINVAL;
	}

	if (!parg_getopt(buf, "a", NULL)) {
		show_valid_qpn(&(rdfx->qp.list));
		return 0;
	}

	parg_getopt(buf, "v:", str);
	if (rdfx_convert_str(str, &qpn))
		return -EINVAL;

	if (!parg_getopt(buf, "s:", sq_rq))
		return rdfx_show_qp_wqe(sq_rq, buf, qpn, rdfx);

	pr_info("***************** QP(0x%x) INFO *****************\n", qpn);
	pr_info("alloc_qp_cnt    : 0x%x\n",
		atomic_read(&rdfx->qp.alloc_qp_cnt));
	pr_info("dealloc_qp_cnt  : 0x%x\n",
		atomic_read(&rdfx->qp.dealloc_qp_cnt));
	pr_info("top_qp_index    : 0x%x\n",
		atomic_read(&rdfx->qp.top_qp_index));

	list_for_each_entry(rdfx_qp, &(rdfx->qp.list), list) {
		if (qpn == rdfx_qp->qpn)
			return show_qp_detail(rdfx_qp);
	}
	pr_err("qp index(0x%x) is invalid\n", qpn);

	return -EINVAL;
}

static int show_cq_detail(struct rdfx_cq_info *rdfx_cq)
{

	pr_info("***************** CQ INFO *****************\n");
	pr_info("scqe_cnt:\n");
	pr_info("RDMA_READ             RDMA_WRITE\n");
	pr_info("  0x%x                   0x%x\n",
		atomic_read(&rdfx_cq->scqe_cnt[IB_WR_RDMA_READ]),
		atomic_read(&rdfx_cq->scqe_cnt[IB_WR_RDMA_WRITE]));
	pr_info("RDMA_WRITE_WITH_IMM	 SEND\n");
	pr_info("  0x%x                   0x%x\n",
		atomic_read(&rdfx_cq->scqe_cnt[IB_WR_RDMA_WRITE_WITH_IMM]),
		atomic_read(&rdfx_cq->scqe_cnt[IB_WR_SEND]));
	pr_info("SEND_WITH_INV          SEND_WITH_IMM\n");
	pr_info("  0x%x                   0x%x\n",
		atomic_read(&rdfx_cq->scqe_cnt[IB_WR_SEND_WITH_INV]),
		atomic_read(&rdfx_cq->scqe_cnt[IB_WR_SEND_WITH_IMM]));
	pr_info("LOCAL_INV              ATOMIC_CMP_AND_SWP\n");
	pr_info("  0x%x                   0x%x\n",
		atomic_read(&rdfx_cq->scqe_cnt[IB_WR_LOCAL_INV]),
		atomic_read(&rdfx_cq->scqe_cnt[IB_WR_ATOMIC_CMP_AND_SWP]));
	pr_info("ATOMIC_FETCH_AND_ADD   MASKED_ATOMIC_CMP_AND_SWP\n");
	pr_info("  0x%x                   0x%x\n",
		atomic_read(&rdfx_cq->scqe_cnt[IB_WR_ATOMIC_FETCH_AND_ADD]),
		atomic_read(
		&rdfx_cq->scqe_cnt[IB_WR_MASKED_ATOMIC_CMP_AND_SWP]));
	pr_info("MASKED_ATOMIC_FETCH_AND_ADD   : 0x%x\n",
		atomic_read(
		&rdfx_cq->scqe_cnt[IB_WR_MASKED_ATOMIC_FETCH_AND_ADD]));
	pr_info("\n");

	pr_info("st_cnt:\n");
	pr_info("IB_WC_LOC_LEN_ERR      IB_WC_LOC_QP_OP_ERR\n");
	pr_info("  0x%x                   0x%x\n",
		atomic_read(&rdfx_cq->st_cnt[IB_WC_LOC_LEN_ERR]),
		atomic_read(&rdfx_cq->st_cnt[IB_WC_LOC_QP_OP_ERR]));
	pr_info("IB_WC_LOC_PROT_ERR	 IB_WC_WR_FLUSH_ERR\n");
	pr_info("  0x%x                   0x%x\n",
		atomic_read(&rdfx_cq->st_cnt[IB_WC_LOC_PROT_ERR]),
		atomic_read(&rdfx_cq->st_cnt[IB_WC_WR_FLUSH_ERR]));
	pr_info("IB_WC_MW_BIND_ERR      IB_WC_BAD_RESP_ERR\n");
	pr_info("  0x%x                   0x%x\n",
		atomic_read(&rdfx_cq->st_cnt[IB_WC_MW_BIND_ERR]),
		atomic_read(&rdfx_cq->st_cnt[IB_WC_BAD_RESP_ERR]));
	pr_info("IB_WC_LOC_ACCESS_ERR   IB_WC_REM_INV_REQ_ERR\n");
	pr_info("  0x%x                   0x%x\n",
		atomic_read(&rdfx_cq->st_cnt[IB_WC_LOC_ACCESS_ERR]),
		atomic_read(&rdfx_cq->st_cnt[IB_WC_REM_INV_REQ_ERR]));
	pr_info("IB_WC_REM_ACCESS_ERR   IB_WC_REM_OP_ERR\n");
	pr_info("  0x%x                   0x%x\n",
		atomic_read(&rdfx_cq->st_cnt[IB_WC_REM_ACCESS_ERR]),
		atomic_read(&rdfx_cq->st_cnt[IB_WC_REM_OP_ERR]));
	pr_info("IB_WC_RETRY_EXC_ERR    IB_WC_RNR_RETRY_EXC_ERR\n");
	pr_info("  0x%x                   0x%x\n",
		atomic_read(&rdfx_cq->st_cnt[IB_WC_RETRY_EXC_ERR]),
		atomic_read(&rdfx_cq->st_cnt[IB_WC_RNR_RETRY_EXC_ERR]));
	pr_info("IB_WC_REM_ABORT_ERR    IB_WC_GENERAL_ERR\n");
	pr_info("  0x%x                   0x%x\n",
		atomic_read(&rdfx_cq->st_cnt[IB_WC_REM_ABORT_ERR]),
		atomic_read(&rdfx_cq->st_cnt[IB_WC_GENERAL_ERR]));
	pr_info("IB_WC_SUCCESS          : 0x%x\n",
		atomic_read(&rdfx_cq->st_cnt[IB_WC_SUCCESS]));
	pr_info("\n");
	pr_info("arm_cnt:\n");
	pr_info("IB_CQ_SOLICITED      : 0x%x\n",
		atomic_read(&rdfx_cq->rcqe_cnt[0]));
	pr_info("IB_CQ_NEXT_COMP      : 0x%x\n",
		atomic_read(&rdfx_cq->rcqe_cnt[1]));
	pr_info("CQ_CI      : 0x%x\n", atomic_read(&rdfx_cq->ci));

	return 0;
}

static void show_valid_cqn(struct list_head *head)
{
	struct rdfx_cq_info *rdfx_cq;
	int line_len = 0;

	pr_info("current valid cqn:\n");
	list_for_each_entry(rdfx_cq, head, list) {
		pr_info("0x%lx      ", rdfx_cq->cqn);
		line_len++;
		if (line_len == 10) {
			pr_info("\n");
			line_len = 0;
		}
	}
	pr_info("\n");
}

static inline int rdfx_show_cq_detail(u32 cqn, struct rdfx_info *rdfx)
{
	struct rdfx_cq_info *rdfx_cq = NULL;

	pr_info("***************** CQ(0x%x) INFO *****************\n", cqn);
	pr_info("alloc_cq_cnt    : 0x%x\n",
		atomic_read(&rdfx->cq.alloc_cq_cnt));
	pr_info("dealloc_cq_cnt  : 0x%x\n",
		atomic_read(&rdfx->cq.dealloc_cq_cnt));
	pr_info("top_cq_index    : 0x%x\n",
		atomic_read(&rdfx->cq.top_cq_index));

	list_for_each_entry(rdfx_cq, &rdfx->cq.list, list) {
		if (cqn == rdfx_cq->cqn)
			return show_cq_detail(rdfx_cq);
	}

	pr_info("cq index(0x%x) is invalid\n", cqn);
	return -EINVAL;
}

static int rdfx_cq_store(const char *p_buf)
{
	struct rdfx_cq_info *rdfx_cq = NULL;
	struct rdfx_info *rdfx;
	char *buf = (char *)p_buf;
	char dev_name[DEF_OPT_STR_LEN];
	char str[DEF_OPT_STR_LEN];
	u32 cqe_index = 0;
	u32 cqn = 0;

	parg_getopt(buf, "d:", dev_name);
	rdfx = rdfx_find_rdfx_info(dev_name);
	if (!rdfx) {
		pr_err("cq: can't find device of %s\n", dev_name);
		return -EINVAL;
	}

	if (!parg_getopt(buf, "a", NULL)) {
		show_valid_cqn(&(rdfx->cq.list));
		return 0;
	}

	parg_getopt(buf, "v:", str);
	if (rdfx_convert_str(str, &cqn))
		return -EINVAL;

	if (!parg_getopt(buf, "i:", str)) {
		if (rdfx_convert_str(str, &cqe_index))
			return -EINVAL;
		pr_info("show cq(0x%x) cqe(0x%x) info:\n", cqn, cqe_index);
		list_for_each_entry(rdfx_cq, &rdfx->cq.list, list) {
			if (cqn == rdfx_cq->cqn)
				return show_cqe(rdfx_cq, cqe_index);
		}
		pr_err("CQN %u is not in dfx list!\n", cqn);
		return -EINVAL;
	}

	return rdfx_show_cq_detail(cqn, rdfx);
}

static int show_mr_detail(struct rdfx_mr_info *rdfx_mr)
{

	pr_info("***************** MR INFO *****************\n");

	return 0;
}

static int rdfx_mr_store(const char *p_buf)
{
	struct rdfx_mr_info *rdfx_mr;
	char *buf = (char *)p_buf;
	struct rdfx_info *rdfx;
	long long convert_val;
	char dev_name[DEF_OPT_STR_LEN];
	char str[DEF_OPT_STR_LEN];
	u32 key;

	parg_getopt(buf, "d:", dev_name);
	rdfx = rdfx_find_rdfx_info(dev_name);
	if (!rdfx) {
		pr_err("mr: can't find device of %s\n", dev_name);
		return -EINVAL;
	}

	parg_getopt(buf, "v:", str);
	if (kstrtoll(str, 0, &convert_val)) {
		pr_info("convert str failed\n");
		return -EINVAL;
	}
	key = (u32)convert_val;

	pr_info("**************** MR(0x%x) INFO ****************\n", key);
	pr_info("alloc_mr_cnt    : 0x%x\n",
		atomic_read(&rdfx->mr.alloc_mr_cnt));
	pr_info("dealloc_mr_cnt  : 0x%x\n",
		atomic_read(&rdfx->mr.dealloc_mr_cnt));
	pr_info("top_mr_index    : 0x%x\n",
		atomic_read(&rdfx->mr.top_mr_index));

	list_for_each_entry(rdfx_mr, &rdfx->mr.list, list) {
		if (key == rdfx_mr->mr->lkey)
			return show_mr_detail(rdfx_mr);
	}

	pr_info("mr index(0x%x) is invalid.\n", key);

	return -EINVAL;
}

static int show_ceq_detail(struct rdfx_ceq_info *rdfx_ceq)
{
	pr_info("\n");
	pr_info("***************** CEQ INFO *****************\n");
	pr_info("*ceqn: %lu\n", rdfx_ceq->ceqn);
	pr_info("*ceqe_cnt: %d\n", rdfx_ceq->ceqe_cnt.counter);

	return 0;
}

static int rdfx_eq_store(const char *p_buf)
{
	struct rdfx_ceq_info *rdfx_ceq;
	long long convert_val;
	char *buf = (char *)p_buf;
	struct rdfx_info *rdfx;
	char dev_name[DEF_OPT_STR_LEN];
	char str[DEF_OPT_STR_LEN];
	u32 ceqn;

	parg_getopt(buf, "d:", dev_name);
	rdfx = rdfx_find_rdfx_info(dev_name);
	if (!rdfx) {
		pr_err("eq: can't find device of %s\n", dev_name);
		return -EINVAL;
	}

	parg_getopt(buf, "v:", str);
	if (kstrtoll(str, 0, &convert_val)) {
		pr_info("convert str failed\n");
		return -EINVAL;
	}
	ceqn = (u32)convert_val;

	list_for_each_entry(rdfx_ceq, &rdfx->eq.ceq_list, list) {
		if (ceqn == rdfx_ceq->ceqn)
			return show_ceq_detail(rdfx_ceq);
	}

	pr_info("ceq index(0x%x) is invalid.\n", ceqn);

	return -EINVAL;
}

static int roce_dev_store(const char *p_buf)
{
	char *buf = (char *)p_buf;
	struct rdfx_info *rdfx;
	char dev_name[DEF_OPT_STR_LEN];
	int i;

	parg_getopt(buf, "d:", dev_name);
	rdfx = rdfx_find_rdfx_info(dev_name);
	if (!rdfx) {
		pr_err("cann't find dev of %s\n", dev_name);
		return -EINVAL;
	}

	pr_info("***************** DEV INFO ******************\n");
	for (i = 0; i < RDFX_FUNC_MAX; i++)
		pr_info("intf_cnt[%s]:			0x%x\n",
			rdfx_func_name[i], atomic_read(&rdfx->dev.fc[i]));

	return 0;
}

/**************** kobject attribute ****************/
struct rdfx_common_sys_attr {
	struct attribute attr;
	int (*pub_show)(void);
	int (*pub_store)(const char *buf);
};

#define rdfx_common_file_attr_def(file_name, func_show, func_store) \
	static struct rdfx_common_sys_attr g_rdfx_common_##file_name##_attr = {\
		{\
			.name = #file_name,\
			.mode = 0640,\
		},\
		.pub_show  = func_show,\
		.pub_store = func_store,\
	}

rdfx_common_file_attr_def(pd, NULL, rdfx_pd_store);
rdfx_common_file_attr_def(qp, NULL, rdfx_qp_store);
rdfx_common_file_attr_def(cq, NULL, rdfx_cq_store);
rdfx_common_file_attr_def(mr, NULL, rdfx_mr_store);
rdfx_common_file_attr_def(eq, NULL, rdfx_eq_store);
rdfx_common_file_attr_def(dev, NULL, roce_dev_store);

#define COMM_ATTRS_LIST_MEMBER(file_name)   \
	(&g_rdfx_common_##file_name##_attr.attr)
static struct attribute *rdfx_common_attrs_list[] = {
	COMM_ATTRS_LIST_MEMBER(pd),
	COMM_ATTRS_LIST_MEMBER(qp),
	COMM_ATTRS_LIST_MEMBER(cq),
	COMM_ATTRS_LIST_MEMBER(mr),
	COMM_ATTRS_LIST_MEMBER(eq),
	COMM_ATTRS_LIST_MEMBER(dev),
	NULL
};

static const struct sysfs_ops rdfx_common_file_ops = {
	.show  = rdfx_common_show,
	.store = rdfx_common_store,
};

static struct kobj_type rdfx_common_kobj_ktype = {
	.release        = NULL,
	.sysfs_ops      = &rdfx_common_file_ops,
	.default_attrs  = rdfx_common_attrs_list,
};

static ssize_t rdfx_common_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct rdfx_common_sys_attr *p_roce_sys_attr =
		container_of(attr, struct rdfx_common_sys_attr, attr);
	int ret = 0;

	memset(buf, 0, SYSFS_PAGE_SIZE);
	if (p_roce_sys_attr->pub_show) {
		ret = p_roce_sys_attr->pub_show();
		if (ret)
			return ret;
		else
			return strlen(buf);
	}

	return -EPERM;
}

static ssize_t rdfx_common_store(struct kobject *kobj, struct attribute *attr,
				 const char *buf, size_t count)
{
	struct rdfx_common_sys_attr *p_roce_sys_attr =
		container_of(attr, struct rdfx_common_sys_attr, attr);
	int ret = 0;

	if (p_roce_sys_attr->pub_store) {
		ret = p_roce_sys_attr->pub_store((char *)buf);
		return ret ? ret : count;
	}

	return -EPERM;
}

int rdfx_add_common_sysfs(struct device *p_dev)
{
	int ret = 0;

	ret = kobject_init_and_add(&rdfx_common_kobj,
				   &rdfx_common_kobj_ktype,
				   &(p_dev->kobj), "common");
	if (ret) {
		pr_info("kobject_init_and_add failed!\r\n");
		return ret;
	}

	return ret;
}

void rdfx_del_common_sysfs(void)
{
	kobject_del(&rdfx_common_kobj);
}

