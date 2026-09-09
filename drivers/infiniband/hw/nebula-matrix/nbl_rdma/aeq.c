// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/kernel.h>
#include <linux/bitfield.h>

#include "aeq.h"
#include "alloc.h"
#include "defs.h"
#include "cqp.h"
#include "qp.h"
#include "cq.h"
#include "hw.h"
#include "ceq.h"
#include "debug.h"

static void nbl_aeq_stat_inc(struct nbl_aeq *aeq, u16 ae_id)
{
	if (ae_id >= NBL_ERR_MAX_AEID)
		return;
	aeq->ae_stat[ae_id]++;
}

static void nbl_aeq_stat_dump(struct nbl_aeq *aeq)
{
	u16 i;

	pr_info("ae_id    count\n");
	for (i = 0; i < NBL_ERR_MAX_AEID; i++) {
		if (aeq->ae_stat[i])
			pr_info("%#x        %d\n", i, aeq->ae_stat[i]);
	}
}

void nbl_dump_aeqe(struct nbl_pci_f *rf, int index)
{
	__be64 *aeqe;
	struct nbl_aeq *aeq = &rf->aeq;
	struct nbl_sc_aeq *sc_aeq = &aeq->sc_aeq;
	struct nbl_aeqe_info info;
	u64 temp, compl_ctx;
	u8 polarity;

	aeqe = nbl_get_wqe(sc_aeq->aeqe_base, &(aeq->buf), sizeof(struct nbl_sc_aeqe),
		index, sc_aeq->pa_continuous);
	if (!aeqe) {
		nbl_pr_err("get aeqe[%d] is null\n", index);
		return;
	}

	get_64bit_val(aeqe, 8, &compl_ctx);
	get_64bit_val(aeqe, 0, &temp);
	polarity = (u8)FIELD_GET(NBL_AEQE_VALID, temp);
	if (sc_aeq->polarity != polarity) {
		nbl_pr_err("aeqe[%d] hw polarity %d, aeq->polarity:%d!!!\n",
			index, polarity, sc_aeq->polarity);
	}

	info.qp_cq_ceq_id = (u32)FIELD_GET(NBL_AEQE_QP_CQ_CEQ_ID, temp);
	info.wqe_idx = (u32)FIELD_GET(NBL_AEQE_WQE_CMD_IDX, temp);
	info.cmd_idx = (info.wqe_idx & 0x1F);
	info.ae_id = (u16)FIELD_GET(NBL_AEQE_AECODE, temp);

	switch (info.ae_id) {
	case NBL_ERR_CQ_OVERFLOW:
	case NBL_ERR_CQ_LOAD_DIFF:
		info.ae_src = NBL_AE_SOURCE_CQ;
		break;
	case NBL_ERR_AEQ_OVERFLOW:
	case NBL_ERR_AEQ_LOAD_PAGE:
		info.ae_src = NBL_AE_SOURCE_AEQ;
		break;
	case NBL_ERR_CEQ_OVERFLOW:
	case NBL_ERR_CEQ_LOAD_PAGE:
		info.ae_src = NBL_AE_SOURCE_CEQ;
		break;
	case NBL_ERR_CQP_EXEC_RESP:
	case NBL_ERR_CQP_FATAL:
		info.ae_src = NBL_AE_SOURCE_CQP;
		break;
	default:
		info.ae_src = NBL_AE_SOURCE_QP;
		break;
	}

	nbl_pr_info(
		"dump aeqe[%d] qp_cq_ceq_id:%d wqe_idx:%d cmd_idx:%d ae_id:0x%x ae_src:%d\n",
		index, info.qp_cq_ceq_id, info.wqe_idx, info.cmd_idx,
		info.ae_id, info.ae_src);
	nbl_dump_hex(rf, (u8 *)aeqe, 16);
}

static void nbl_dump_aeqc(__be64 *query_out)
{
	struct nbl_aeqc_t aeqc;
	int i;
	u16 msix_num;

	for (i = 0; i < sizeof(struct nbl_aeqc_t)/sizeof(u64); i++)
		get_64bit_val(query_out, (i * 8 + 32), ((u64 *)(&aeqc)) + i);

	pr_info("state:%d aeq_pm:%d aeq_size(log):%d aeq_pi_phase:%d aeq_pi:%d aeq_ci_phase:%d aeq_ci:%d\n",
		aeqc.state, aeqc.aeq_pm, aeqc.aeq_size, aeqc.aeq_pi_phase,
		aeqc.aeq_pi, aeqc.aeq_ci_phase, aeqc.aeq_ci);
	msix_num = (aeqc.msix_num_h11 << 5) + aeqc.msix_num_l5;
	pr_info("msix_num:%d aeq_pd_start_ba:0x%llx\n",
		msix_num, (u64)aeqc.aeq_pd_start_ba);
	pr_info("aeq_cur_pdpa_vld:%d aeq_cur_pdpa:0x%llx\n",
		aeqc.aeq_cur_pdpa_vld, (u64)aeqc.aeq_cur_pdpa);
	pr_info("aeq_nxt_pdpa_vld:%d aeq_nxt_pdpa:0x%llx\n",
		aeqc.aeq_nxt_pdpa_vld, (u64)aeqc.aeq_nxt_pdpa);
}

int nbl_query_aeq(struct nbl_pci_f *rf)
{
	__be64 *in;
	__be64 *out;
	u8 *ptr;
	int err_code;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;
	out = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!out) {
		kfree(in);
		return NBL_ERR_ALLOCMEM_FAILED;
	}

	set_64bit_val(in, 0,
			FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_QUERY_AEQ));

	nbl_pr_info("QUERY AEQ INFO(cqp in) :\n");
	ptr = (u8 *)in;
	nbl_dump_hex(rf, ptr, NBL_CMD_INPUT_SIZE);

	err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, out, NBL_CMD_OUTPUT_SIZE);
	if (err_code)
		nbl_pr_err("query aeq cqp cmd failed err_code :%d\n", err_code);

	nbl_pr_info("AEQC INFO(cqp out) :\n");
	ptr = (u8 *)out;
	nbl_dump_hex(rf, ptr, NBL_CMD_OUTPUT_SIZE);
	nbl_dump_aeqc(out);
	nbl_aeq_stat_dump(&rf->aeq);

	kfree(in);
	kfree(out);
	return 0;
}
/**
 * nbl_sc_aeq_init - initialize aeq
 * @aeq: aeq structure ptr
 * @info: aeq initialization info
 */
static int nbl_sc_aeq_init(struct nbl_sc_aeq *aeq,
			   struct nbl_aeq_init_info *info)
{
	if (info->elem_cnt < info->dev->hw_attrs.min_hw_aeqe_count ||
	    info->elem_cnt > info->dev->hw_attrs.max_hw_aeqe_count)
		return -EINVAL;

	aeq->size = sizeof(*aeq);
	aeq->polarity = 1;
	aeq->aeqe_base = (struct nbl_sc_aeqe *)info->aeqe_base;
	aeq->dev = info->dev;
	aeq->elem_cnt = info->elem_cnt;
	aeq->aeq_pg_num = info->aeq_pg_num;
	aeq->aeq_elem_pa = info->aeq_elem_pa;
	NBL_RING_INIT(aeq->aeq_ring, aeq->elem_cnt);
	aeq->pa_continuous = info->pa_continuous;
	aeq->msix_idx = info->msix_idx;
	info->dev->aeq = aeq;

	return 0;
}

/**
 * nbl_cqp_aeq_destroy_cmd - Destroy AEQ.
 * @dev: pointer to device info
 * @sc_aeq: pointer to aeq structure
 * Return 0, if the cqp cmd exec success, otherwise return error.
 */
static int nbl_cqp_aeq_destroy_cmd(struct nbl_pci_f *rf, struct nbl_sc_aeq *sc_aeq)
{
	int ret = 0;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;

	in = kzalloc(in_size, GFP_ATOMIC);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	set_64bit_val(in, 0,
		      FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_DESTROY_AEQ) |
			      FIELD_PREP(NBL_CQP_AEQ_STATE, NBL_AEQ_STAT_VALID));

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);

	kfree(in);

	return ret;
}

/**
 * nbl_cqp_aeq_create_cmd - Create AEQ.
 * @dev: pointer to device info
 * @sc_aeq: pointer to aeq structure
 * Return 0, if the cqp cmd exec success, otherwise return error.
 */
static int nbl_cqp_aeq_create_cmd(struct nbl_pci_f *rf, struct nbl_sc_aeq *sc_aeq)
{
	int ret;
	__be64 *in;
	u8 *ptr;

	u32 elem_cnt = sc_aeq->elem_cnt;
	int cqp_aeq_size = ilog2(elem_cnt);
	u64 aeq_base_pa = sc_aeq->aeq_elem_pa;
	u64 *base_addr = (u64 *)sc_aeq->aeqe_base; /* va */
	u64 aeq_1st_page_pa;
	u64 aeq_2nd_page_pa;

	if (sc_aeq->pa_continuous) {
		aeq_1st_page_pa = aeq_base_pa;
		aeq_2nd_page_pa = aeq_base_pa + (1 << NBL_ADAPTER_PAGE_SHIFT);
	} else {
		aeq_1st_page_pa = be64_to_cpu(base_addr[0]);
		aeq_2nd_page_pa = be64_to_cpu(base_addr[1]);
	}

	nbl_ib_dbg(&rf->sc_dev, "[AEQ CREATE] CQP parameter: pa_continuous:%d, aeqe_cnt :%d,cqp_aeq_sz:%d, msix_idx:%d, aeq_base_va:%p aeq_base_pa:%llx, 1st_pa:0x%llx, 2nd_pa:0x%llx\n",
		sc_aeq->pa_continuous, elem_cnt, cqp_aeq_size, sc_aeq->msix_idx,
		sc_aeq->aeqe_base, aeq_base_pa, aeq_1st_page_pa, aeq_2nd_page_pa);

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_ATOMIC);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	set_64bit_val(in, 0,
		FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_CREATE_AEQ) |
		FIELD_PREP(NBL_CQP_AEQ_STATE, NBL_CEQ_STAT_VALID) |
		FIELD_PREP(NBL_CQP_AEQ_PM, sc_aeq->pa_continuous ?
			NBL_CQP_PM_0_CONTINUS : NBL_CQP_PM_1_UNCONTINUS) |
		FIELD_PREP(NBL_CQP_AEQ_SIZE, cqp_aeq_size) |
		FIELD_PREP(NBL_CQP_AEQ_MSIX_INDEX_H11, sc_aeq->msix_idx >> 5));

	set_64bit_val(in, 8,  FIELD_PREP(NBL_CQP_AEQ_MSIX_INDEX_L5, sc_aeq->msix_idx & 0x1F) |
		FIELD_PREP(NBL_CQP_AEQ_BASE_ADDR, (aeq_base_pa >> NBL_CEQ_CQP_ADDR_SHIFT)));
	set_64bit_val(in, 16, FIELD_PREP(NBL_CQP_AEQ_FIR_PAGE_ADDR,
		(aeq_1st_page_pa >> NBL_CEQ_CQP_ADDR_SHIFT)));
	set_64bit_val(in, 24, FIELD_PREP(NBL_CQP_AEQ_SEC_PAGE_ADDR,
		(aeq_2nd_page_pa >> NBL_CEQ_CQP_ADDR_SHIFT)));

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);

	ptr = (u8 *)in;

	kfree(in);

	return ret;
}

/**
 * nbl_create_aeq - create async event queue
 * @rf: RDMA PCI function
 *
 * Return 0, if the aeq and the resources associated with it
 * are successfully created, otherwise return error
 */
int nbl_create_aeq(struct nbl_pci_f *rf)
{
	int status;
	struct nbl_sc_dev *dev = &rf->sc_dev;
	struct nbl_aeq_init_info info = {};
	struct nbl_aeq *aeq = &rf->aeq;
	struct nbl_frag_buf *aeq_buf = &aeq->buf;
	u32 aeqe_count;
	u32 aeq_size;

	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;

	aeqe_count = min((hmc_info->hmc_obj[NBL_HMC_QP].cnt +
			  hmc_info->hmc_obj[NBL_HMC_CQ].cnt),
			 dev->hw_attrs.max_hw_aeqe_count);

	aeqe_count = roundup_pow_of_two(aeqe_count);
	if (aeqe_count > dev->hw_attrs.max_hw_aeqe_count) {

		nbl_pr_err("aeqe_count:%d is invalid, max:%d\n", aeqe_count,
			   dev->hw_attrs.max_hw_aeqe_count);
		return NBL_ERR_SPEC_ERROR;
	}

	if (aeqe_count < dev->hw_attrs.min_hw_aeqe_count) {
		nbl_pr_notice("aeqe_count=%u is too small, use default value=%u\n", aeqe_count,
			      dev->hw_attrs.min_hw_aeqe_count);
		aeqe_count = dev->hw_attrs.min_hw_aeqe_count;
	}

	aeq_size = ALIGN(sizeof(struct nbl_sc_aeqe) * aeqe_count,
			 NBL_AEQ_ALIGNMENT);
	aeq->kmem.size = aeq_size;

	aeq->kmem.va = nbl_dma_alloc_coherent(dev->hw->device, aeq->kmem.size,
					      &aeq->kmem.pa, GFP_KERNEL);

	if (aeq->kmem.va) {
		aeq->pa_continuous = true;
		aeq_buf->npages = NBL_CEQ_2M_PAGE_NUM;
		nbl_ib_dbg(&rf->sc_dev, "alloced aeq continuous pa, va:%llx\n", (u64)aeq->kmem.va);
	} else {
		aeq->pa_continuous = false;
		aeq_buf->size = aeq->kmem.size;
		aeq_buf->npages =
			DIV_ROUND_UP(aeq_buf->size, NBL_ADAPTER_PAGE_SIZE);

		status = nbl_frag_buf_alloc(dev->hw->device, &aeq->kmem.va,
				&aeq->kmem.pa, aeq_buf);
		if (status)
			return status;
	}

	info.aeqe_base = aeq->kmem.va;
	info.aeq_elem_pa = aeq->kmem.pa;
	info.elem_cnt = aeqe_count;
	info.dev = dev;
	info.msix_idx = rf->nbl_msixtbl->idx;
	info.pa_continuous = aeq->pa_continuous;
	info.aeq_pg_num = aeq_buf->npages;
	status = nbl_sc_aeq_init(&aeq->sc_aeq, &info);
	if (status)
		goto err;

	status = nbl_cqp_aeq_create_cmd(rf, &aeq->sc_aeq);
	if (status)
		goto err;

	return 0;

err:
	if (aeq->pa_continuous)
		dma_free_coherent(dev->hw->device, aeq->kmem.size, aeq->kmem.va,
				  aeq->kmem.pa);
	else
		nbl_frag_buf_free(dev->hw->device, aeq->kmem.va, aeq->kmem.pa,
				  aeq_buf);

	aeq->kmem.va = NULL;
	return status;
}

/**
 * nbl_sc_get_next_aeqe - get next aeq entry
 * @aeq: aeq structure ptr
 * @info: aeqe info to be returned
 */
static enum nbl_status_code nbl_sc_get_next_aeqe(struct nbl_aeq *aeq,
					  struct nbl_aeqe_info *info)
{
	u64 temp;
	__be64 *aeqe;
	u8 polarity;
	int wqe_idx;
	struct nbl_sc_aeq *sc_aeq = &aeq->sc_aeq;

	wqe_idx = sc_aeq->aeq_ring.tail;
	aeqe = nbl_get_wqe(sc_aeq->aeqe_base, &(aeq->buf), sizeof(struct nbl_sc_aeqe),
		wqe_idx, sc_aeq->pa_continuous);
	if (!aeqe) {
		nbl_pr_err("get NULL aeqe\n");
		return NBL_ERR_Q_EMPTY;
	}

	get_64bit_val(aeqe, 0, &temp);
	polarity = (u8)FIELD_GET(NBL_AEQE_VALID, temp);
	if (sc_aeq->polarity != polarity) {
		nbl_pr_dbg("polarity %d, aeq->polarity:%d\n", polarity,
			   sc_aeq->polarity);
		return NBL_ERR_Q_EMPTY;
	}

	info->qp_cq_ceq_id = (u32)FIELD_GET(NBL_AEQE_QP_CQ_CEQ_ID, temp);
	info->wqe_idx = (u32)FIELD_GET(NBL_AEQE_WQE_CMD_IDX, temp);
	info->cmd_idx = (info->wqe_idx & 0x1F);
	info->ae_id = (u16)FIELD_GET(NBL_AEQE_AECODE, temp);

	switch (info->ae_id) {
	case NBL_ERR_CQ_OVERFLOW:
	case NBL_ERR_CQ_LOAD_DIFF:
	case NBL_ERR_ARM_CQ_OVERFLOW:
		info->ae_src = NBL_AE_SOURCE_CQ;
		break;
	case NBL_ERR_AEQ_OVERFLOW:
	case NBL_ERR_AEQ_LOAD_PAGE:
		info->ae_src = NBL_AE_SOURCE_AEQ;
		break;
	case NBL_ERR_CEQ_OVERFLOW:
	case NBL_ERR_CEQ_LOAD_PAGE:
		info->ae_src = NBL_AE_SOURCE_CEQ;
		break;
	case NBL_ERR_CQP_EXEC_RESP:
	case NBL_ERR_CQP_FATAL:
		info->ae_src = NBL_AE_SOURCE_CQP;
		break;
	default:
		info->ae_src = NBL_AE_SOURCE_QP;
		break;
	}
	NBL_RING_MOVE_TAIL(sc_aeq->aeq_ring);
	if (!NBL_RING_CURRENT_TAIL(sc_aeq->aeq_ring))
		sc_aeq->polarity ^= 1;

	return NBL_SUCCESS;
}

static void nbl_aeq_process_cqp_ae_err(struct nbl_aeqe_info *info,
				struct nbl_pci_f *rf)
{
	switch (info->ae_id) {
	case NBL_ERR_CQP_EXEC_RESP:
		nbl_cmd_comp_notifier(rf, info->cmd_idx);
		nbl_pr_dbg("CQP exec comp! ae_id:%#x, cmd_idx:%d\n", info->ae_id, info->cmd_idx);
		break;
	case NBL_ERR_CQP_FATAL:
		nbl_pr_err("CQP fatal! ae_id:%#x, cmd_idx:%d\n", info->ae_id, info->cmd_idx);
		break;
	default:
		break;
	}
}

static void nbl_aeq_process_aeq_ae_err(struct nbl_aeqe_info *info,
				struct nbl_aeq *nblaeq)
{
	switch (info->ae_id) {
	case NBL_ERR_AEQ_LOAD_PAGE:
	case NBL_ERR_AEQ_OVERFLOW:
		nbl_ib_err_ratelimited(nblaeq->sc_aeq.dev, "AE_SOURCE is AEQ, ae_id:%#x\n",
			info->ae_id);
		/*TODO*/
		break;

	default:
		break;
	}
}

static void nbl_aeq_process_ceq_ae_err(struct nbl_aeqe_info *info,
				struct nbl_ceq *nblceq)
{
	switch (info->ae_id) {
	case NBL_ERR_CEQ_LOAD_PAGE:
	case NBL_ERR_CEQ_OVERFLOW:
		nbl_ib_err_ratelimited(nblceq->sc_ceq.dev, "AE_SOURCE is CEQ, ae_id:%#x\n",
			info->ae_id);
		/*TODO*/
		break;

	default:
		break;
	}
}

static void nbl_aeq_process_cq_ae_err(struct nbl_aeqe_info *info, struct nbl_cq *nblcq)
{
	struct ib_event ib_event;

	switch (info->ae_id) {
	case NBL_ERR_CQ_OVERFLOW:
		if (nblcq->ibcq.event_handler) {
			ib_event.device = nblcq->ibcq.device;
			ib_event.event = IB_EVENT_CQ_ERR;
			ib_event.element.cq = &nblcq->ibcq;
			nblcq->ibcq.event_handler(&ib_event,
						  nblcq->ibcq.cq_context);
		}
		nbl_ib_err_ratelimited(nblcq->sc_cq.dev, "CQ OVERFLOW! ae_id:%#x, cqn:%d\n",
			info->ae_id, info->qp_cq_ceq_id);
		break;
	case NBL_ERR_CQ_LOAD_DIFF:
		/*TODO*/
		nbl_ib_err_ratelimited(nblcq->sc_cq.dev, "CQ LOAD DIFF ERR! ae_id:%#x, cqn:%d\n",
			info->ae_id, info->qp_cq_ceq_id);
		break;
	case NBL_ERR_ARM_CQ_OVERFLOW:
		nbl_ib_err_ratelimited(nblcq->sc_cq.dev, "ARM_CQ_OVERFLOW ERR! ae_id:%#x, cqn:%d\n",
			info->ae_id, info->qp_cq_ceq_id);
		break;
	default:
		nbl_ib_err_ratelimited(nblcq->sc_cq.dev, "CQ unkonwn ERR! ae_id:%#x, cqn:%d\n",
			info->ae_id, info->qp_cq_ceq_id);
		break;
	}
}

static void nbl_aeq_process_qp_ae_err(struct nbl_aeqe_info *info, struct nbl_qp *nblqp)
{
	struct ib_event ib_event;

	switch (info->ae_id) {
	case NBL_ERR_SQ_FLUSH_COMPLETE:
	case NBL_ERR_RQ_FLUSH_COMPLETE:
		nbl_pr_dbg("Hw %s[%d] flush done.\n",
		    info->ae_id == NBL_ERR_SQ_FLUSH_COMPLETE ? "SQ" : "RQ",
			info->qp_cq_ceq_id);
		/* until sq and rq flush completed, release the flush_qp */
		if (refcount_dec_and_test(&nblqp->flush_cnt)) {
			complete(&nblqp->flush_qp);
			nbl_pr_dbg("Hw qp flush done, send signal to qp[%d].\n",
			    info->qp_cq_ceq_id);
		}
		break;
	case NBL_ERR_SQ_DRAINED:
		nbl_pr_dbg("Hw sq[%d] drained done.\n",
			    info->qp_cq_ceq_id);
		if (nblqp->ibqp.event_handler) {
			ib_event.event = IB_EVENT_SQ_DRAINED;
			ib_event.device = nblqp->ibqp.device;
			ib_event.element.qp = &nblqp->ibqp;
			nblqp->ibqp.event_handler(&ib_event,
						  nblqp->ibqp.qp_context);
		}
		break;

	default: /* QP errors*/
		/* all types of QP AE error would cause flush-qp */
		nbl_ib_err_ratelimited(nblqp->sc_qp.dev, "qp err! ae_id:0x%x, qp_num:%d wqe_idx:%d\n",
			info->ae_id, info->qp_cq_ceq_id, info->wqe_idx);
		nbl_flush_work(nblqp);
		break;
	}
}

static void nbl_debug_query_cache_qpc(struct work_struct *work)
{
	int err_code;
	struct nbl_dma_mem qpc_mem;
	__be64 *in;
	struct query_qpc_work *qwork =
		container_of(work, struct query_qpc_work, work);
	struct nbl_pci_f *rf = qwork->rf;
	__u32 qpn = qwork->qpn;

	kfree(qwork);
	qpc_mem.size = NBL_QP_CTX_SIZE;
	qpc_mem.va = nbl_dma_alloc_coherent(rf->sc_dev.hw->device, qpc_mem.size,
					    &qpc_mem.pa, GFP_KERNEL);
	if (!qpc_mem.va)
		return;
	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in) {
		dma_free_coherent(rf->sc_dev.hw->device, qpc_mem.size,
				  qpc_mem.va, qpc_mem.pa);
		return;
	}
	set_64bit_val(in, 0,
		      FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_QUERY_QP) |
			      FIELD_PREP(NBL_CQP_QP_NUM, qpn));
	set_64bit_val(in, 8, FIELD_PREP(NBL_CQP_QP_CTX_ADDR, qpc_mem.pa));
	err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code)
		goto out;
	nbl_dump_hex(rf, qpc_mem.va, NBL_QP_CTX_SIZE);
out:
	kfree(in);
	dma_free_coherent(rf->sc_dev.hw->device, qpc_mem.size, qpc_mem.va,
			  qpc_mem.pa);
}

static void nbl_query_qpc_work(struct nbl_pci_f *rf, u32 qpn)
{
	struct query_qpc_work *qwork;

	qwork = kzalloc(sizeof(*qwork), GFP_ATOMIC);
	if (!qwork)
		return;

	qwork->qpn = qpn;
	qwork->rf = rf;
	INIT_WORK(&qwork->work, nbl_debug_query_cache_qpc);
	queue_work(rf->query_qpc_wq, &qwork->work);
}

static void nbl_debug_query_cache_cqc(struct work_struct *work)
{
	int err_code;
	struct nbl_dma_mem cqc_mem;
	__be64 *in;
	struct query_cqc_work *qwork =
		container_of(work, struct query_cqc_work, work);
	struct nbl_pci_f *rf = qwork->rf;
	__u32 cqn = qwork->cqn;
	struct nbl_cq *cq = rf->cq_table[cqn];

	kfree(qwork);
	cqc_mem.size = NBL_CQ_CTX_SIZE;
	cqc_mem.va = nbl_dma_alloc_coherent(rf->sc_dev.hw->device, cqc_mem.size,
					    &cqc_mem.pa, GFP_KERNEL);
	if (!cqc_mem.va)
		return;
	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in) {
		dma_free_coherent(rf->sc_dev.hw->device, cqc_mem.size,
				  cqc_mem.va, cqc_mem.pa);
		return;
	}
	set_64bit_val(in, 0,
		      FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_QUERY_CQ) |
			      FIELD_PREP(NBL_CQPSQ_CQ_CQID, cqn));
	set_64bit_val(in, 8, FIELD_PREP(NBL_CQPSQ_CQ_UPLOAD_ADDRESS, cqc_mem.pa));
	err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code)
		goto out;
	nbl_dump_hex(rf, cqc_mem.va, NBL_CQ_CTX_SIZE);

	nbl_ib_warn(&rf->sc_dev, "===hmc cqc info as follow:===");
	nbl_dump_hex(rf, cq->kmem_shadow.va - NBL_CQ_SHADOW_OFFST, NBL_CQ_CTX_SIZE);

out:
	kfree(in);
	dma_free_coherent(rf->sc_dev.hw->device, cqc_mem.size, cqc_mem.va,
			  cqc_mem.pa);
}

static void nbl_query_cqc_work(struct nbl_pci_f *rf, u32 cqn)
{
	struct query_cqc_work *qwork;

	qwork = kzalloc(sizeof(*qwork), GFP_ATOMIC);
	if (!qwork)
		return;

	qwork->cqn = cqn;
	qwork->rf = rf;
	INIT_WORK(&qwork->work, nbl_debug_query_cache_cqc);
	queue_work(rf->query_qpc_wq, &qwork->work);
}

static int nbl_process_ae_id(struct nbl_pci_f *rf, struct nbl_aeqe_info *info)
{
	struct nbl_sc_dev *dev = &rf->sc_dev;
	struct nbl_cq *nblcq = NULL;
	struct nbl_qp *nblqp = NULL;
	struct nbl_ceq *nblceq = NULL;
	struct nbl_aeq *nblaeq = NULL;

	unsigned long flags;
	int ret = 0;

	nbl_ib_dbg(dev, "ae_src:%d, err_code:0x%x\n", info->ae_src, info->ae_id);
	switch (info->ae_src) {
	case NBL_AE_SOURCE_QP:
		spin_lock_irqsave(&rf->qptable_lock, flags);
		nblqp = rf->qp_table[info->qp_cq_ceq_id];
		if (!nblqp) {
			spin_unlock_irqrestore(&rf->qptable_lock, flags);
			nbl_ib_err_ratelimited(dev, "AE event process qp, nblqp (id:%d) get null.\n",
				info->qp_cq_ceq_id);
			return NBL_ERR_GET_QP_NULL;
		}
		nbl_qp_add_ref(nblqp);
		spin_unlock_irqrestore(&rf->qptable_lock, flags);

		spin_lock_irqsave(&nblqp->lock, flags);
		nblqp->last_aeq = info->ae_id;
		spin_unlock_irqrestore(&nblqp->lock, flags);

		if (unlikely(info->ae_id == rf->sc_dev.debug_errcdoe))
			nbl_query_qpc_work(rf, info->qp_cq_ceq_id);
		nbl_aeq_process_qp_ae_err(info, nblqp);
		nbl_qp_rem_ref(&nblqp->ibqp);
		break;
	case NBL_AE_SOURCE_CQ:
		if (info->qp_cq_ceq_id >= rf->max_cq) {
			nbl_ib_err_ratelimited(
				dev,
				"AE event process cq, cqn:%d is not available.\n",
				info->qp_cq_ceq_id);
			return NBL_ERR_GET_CQ_NULL;
		}
		nblcq = rf->cq_table[info->qp_cq_ceq_id];
		if (!nblcq) {
			nbl_ib_err_ratelimited(dev, "AE event process cq, nblcq (id:%d) get null.\n",
				info->qp_cq_ceq_id);
			return NBL_ERR_GET_CQ_NULL;
		}

		if (unlikely(info->ae_id == rf->sc_dev.debug_errcdoe))
			nbl_query_cqc_work(rf, info->qp_cq_ceq_id);

		nbl_aeq_process_cq_ae_err(info, nblcq);
		break;
	case NBL_AE_SOURCE_CEQ:
		nblceq = &rf->ceqlist[info->qp_cq_ceq_id];
		if (!nblceq) {
			nbl_ib_err_ratelimited(dev, "AE event process ceq, nblceq (id:%d) get null.\n",
				info->qp_cq_ceq_id);
			return NBL_ERR_GET_CEQ_NULL;
		}
		nbl_aeq_process_ceq_ae_err(info, nblceq);
		break;
	case NBL_AE_SOURCE_AEQ:
		nblaeq = &rf->aeq;
		if (!nblaeq) {
			nbl_ib_err_ratelimited(dev, "AE event process aeq, nblaeq get null.\n");
			return NBL_ERR_GET_CEQ_NULL;
		}
		nbl_aeq_process_aeq_ae_err(info, nblaeq);
		break;
	case NBL_AE_SOURCE_CQP:
		nbl_aeq_process_cqp_ae_err(info, rf);
		break;
	default:
		nbl_ib_err_ratelimited(dev, "err ae_src:%d\n", info->ae_src);
		ret = NBL_ERR_AEINFO_ERR;
		break;
	}
	nbl_aeq_stat_inc(&rf->aeq, info->ae_id);
	return ret;
}
/**
 * nbl_process_aeq - handle aeq events
 * @rf: RDMA PCI function
 */
static void nbl_process_aeq(struct nbl_pci_f *rf)
{
	struct nbl_sc_dev *dev = &rf->sc_dev;
	struct nbl_aeq *aeq = &rf->aeq;
	struct nbl_sc_aeq *sc_aeq = &aeq->sc_aeq;
	struct nbl_aeqe_info aeinfo;
	struct nbl_aeqe_info *info = &aeinfo;
	u32 aeqcnt = 0;
	int ret;

	if (!sc_aeq->size)
		return;

	do {
		memset(info, 0, sizeof(*info));
		ret = nbl_sc_get_next_aeqe(aeq, info);
		if (ret)
			break;

		aeqcnt++;
		ret = nbl_process_ae_id(rf, info);
		if (ret)
			nbl_ib_err(dev, "nb_process_ae_id fail,ret:%d\n", ret);

	} while (1);

	if (aeqcnt)
		nbl_sc_update_aeq_ci(dev, sc_aeq);
}

/**
 * nbl_dpc - tasklet for aeq
 * @t: tasklet_struct ptr
 */
static void nbl_dpc(struct tasklet_struct *t)
{
	struct nbl_pci_f *rf = from_tasklet(rf, t, dpc_tasklet);

	nbl_process_aeq(rf);
}

/**
 * nbl_irq_handler - interrupt handler for aeq
 * @irq: Interrupt request number
 * @data: RDMA PCI function
 */
static irqreturn_t nbl_irq_handler(int irq, void *data)
{
	struct nbl_pci_f *rf = data;

	tasklet_schedule(&rf->dpc_tasklet);

	return IRQ_HANDLED;
}

/**
 * nbl_cfg_aeq_vector - set up the msix vector for aeq
 * @rf: RDMA PCI function
 *
 * Allocate interrupt resources and enable irq handle
 * Return 0 if success, otherwise return error
 */
int nbl_cfg_aeq_vector(struct nbl_pci_f *rf)
{
	u32 ret;
	struct nbl_sc_dev *dev = &rf->sc_dev;
	struct nbl_msix_vector *msix_vec = rf->nbl_msixtbl;

	tasklet_setup(&rf->dpc_tasklet, nbl_dpc);
	ret = request_irq(msix_vec->irq, nbl_irq_handler, 0, "nbl_aeq", rf);
	if (ret) {
		nbl_ib_err(dev, "ERR: aeq irq config fail\n");
		return NBL_ERR_CFG;
	}

	cpumask_clear(&msix_vec->mask);
	cpumask_set_cpu(msix_vec->cpu_affinity, &msix_vec->mask);
	irq_set_affinity_hint(msix_vec->irq, &msix_vec->mask);

	dev->irq_ops->nbl_en_irq(rf, msix_vec->idx);

	return 0;
}

/**
 * nbl_destroy_aeq - destroy aeq
 * @rf: RDMA PCI function
 *
 * Issue a destroy aeq request and
 * free the resources associated with the aeq
 * The function is called during driver unload
 */
void nbl_destroy_aeq(struct nbl_pci_f *rf)
{
	struct nbl_sc_dev *dev = &rf->sc_dev;
	struct nbl_aeq *aeq = &rf->aeq;
	struct nbl_frag_buf *aeq_buf = &aeq->buf;
	int status = -EBUSY;

	if (rf->dpc_tasklet.func)
		tasklet_kill(&rf->dpc_tasklet);

	nbl_destroy_irq(rf, rf->nbl_msixtbl, rf);

	aeq->sc_aeq.size = 0;
	status = nbl_cqp_aeq_destroy_cmd(rf, &aeq->sc_aeq);
	if (status)
		nbl_ib_err(dev, "ERR: Destroy AEQ failed %d\n", status);

	if (aeq->pa_continuous)
		dma_free_coherent(dev->hw->device, aeq->kmem.size, aeq->kmem.va,
				  aeq->kmem.pa);
	else
		nbl_frag_buf_free(dev->hw->device, aeq->kmem.va, aeq->kmem.pa,
				  aeq_buf);

	aeq->kmem.va = NULL;
}

/**
 * nbl_setup_aeq - set up the device aeq
 * @rf: RDMA PCI function
 *
 * Create the aeq and configure its msix interrupt vector
 * Return 0 if successful, otherwise return error
 */
int nbl_setup_aeq(struct nbl_pci_f *rf)
{
	int status;

	status = nbl_create_aeq(rf);
	if (status)
		return status;

	status = nbl_cfg_aeq_vector(rf);
	if (status) {
		nbl_destroy_aeq(rf);
		return status;
	}
	return 0;
}
