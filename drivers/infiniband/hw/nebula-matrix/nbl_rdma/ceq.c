// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/bitfield.h>
#include <linux/log2.h>
#include "main.h"
#include "cqp.h"
#include "defs.h"
#include "alloc.h"
#include "hw.h"
#include "ceq.h"
#include "debug.h"
#include "mem.h"
#include "cq.h"

void nbl_dump_ceqe(struct nbl_pci_f *rf, int ceq_id, int index)
{
	__be64 *ceqe;
	struct nbl_ceq *ceq = &rf->ceqlist[ceq_id];
	struct nbl_sc_ceq *sc_ceq = &ceq->sc_ceq;
	u64 temp, cq_ctx;
	u32 cqn;
	u8 polarity;

	ceqe = nbl_get_wqe(sc_ceq->ceqe_base, &(ceq->buf), sizeof(struct nbl_ceqe),
		index, sc_ceq->pa_continuous);
	if (!ceqe) {
		nbl_pr_err("get ceqe[%d] is null\n", index);
		return;
	}

	get_64bit_val(ceqe, 8, &cq_ctx);
	get_64bit_val(ceqe, 0, &temp);
	polarity = (u8)FIELD_GET(NBL_CEQE_VALID, temp);
	if (sc_ceq->polarity != polarity) {
		nbl_pr_err("ceqe%d[%d] hw polarity %d, ceq->polarity:%d!!!\n",
			ceq_id, index, polarity, sc_ceq->polarity);
	}
	cqn = FIELD_GET(NBL_CEQE_CQN, temp);

	nbl_pr_info("dump ceqe%d[%d] cqn:%d cq_ctx:0x%llx\n", ceq_id, index, cqn, cq_ctx);
	nbl_dump_hex(rf, (u8 *)ceqe, 16);
}

static void nbl_dump_ceqc(__be64 *query_out)
{
	struct nbl_ceqc_t ceqc;
	int i;
	u16 msix_num;

	for (i = 0; i < sizeof(struct nbl_ceqc_t)/sizeof(u64); i++)
		get_64bit_val(query_out, (i * 8 + 32), ((u64 *)(&ceqc)) + i);

	pr_info("state:%d ceq_pm:%d ceq_size(log):%d ceq_pi_phase:%d ceq_pi:%d ceq_ci_phase:%d ceq_ci:%d\n",
		ceqc.state, ceqc.ceq_pm, ceqc.ceq_size, ceqc.ceq_pi_phase,
		ceqc.ceq_pi, ceqc.ceq_ci_phase, ceqc.ceq_ci);
	msix_num = (ceqc.msix_num_h11 << 5) + ceqc.msix_num_l5;
	pr_info("msix_num:%d ceq_pd_start_ba:0x%llx\n",
		msix_num, (u64)ceqc.ceq_pd_start_ba);
	pr_info("ceq_cur_pdpa_vld:%d ceq_cur_pdpa:0x%llx\n",
		ceqc.ceq_cur_pdpa_vld, (u64)ceqc.ceq_cur_pdpa);
	pr_info("ceq_nxt_pdpa_vld:%d ceq_nxt_pdpa:0x%llx\n",
		ceqc.ceq_nxt_pdpa_vld, (u64)ceqc.ceq_nxt_pdpa);
}

int nbl_query_ceq(struct nbl_pci_f *rf)
{
	__be64 *in;
	__be64 *out;
	u8 *ptr;
	int err_code;
	int i;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;
	out = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!out) {
		kfree(in);
		return NBL_ERR_ALLOCMEM_FAILED;
	}

	for (i = 0; i < NBL_CEQ_MAX_COUNT; i++) {
		set_64bit_val(in, 0,
				FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_QUERY_CEQ) |
				FIELD_PREP(NBL_CQP_CEQ_ID, i));

		nbl_pr_info("QUERY CEQ-%d INFO :\n", i);
		ptr = (u8 *)in;
		nbl_dump_hex(rf, ptr, NBL_CMD_INPUT_SIZE);

		err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, out, NBL_CMD_OUTPUT_SIZE);
		if (err_code)
			nbl_pr_err("query ceq cqp cmd failed err_code :%d\n", err_code);

		nbl_pr_info("CEQC-%d INFO :\n", i);
		ptr = (u8 *)out;
		nbl_dump_hex(rf, ptr, NBL_CMD_OUTPUT_SIZE);
		nbl_dump_ceqc(out);
	}
	kfree(in);
	kfree(out);
	return 0;
}

/**
 * nbl_destroy_irq - destroy device interrupts
 * @rf: RDMA PCI function
 * @msix_vec: msix vector to disable irq
 * @dev_id: parameter to pass to free_irq (used during irq setup)
 * The function is called when destroying aeq/ceq
 */
void nbl_destroy_irq(struct nbl_pci_f *rf, struct nbl_msix_vector *msix_vec,
		     void *dev_id)
{
	struct nbl_sc_dev *dev = &rf->sc_dev;

	dev->irq_ops->nbl_dis_irq(rf, msix_vec->idx);
	irq_set_affinity_hint(msix_vec->irq, NULL);
	free_irq(msix_vec->irq, dev_id);
}

/**
 * nbl_cqp_ceq_create_cmd - Create CEQ.
 * @dev: pointer to device info
 * @sc_ceq: pointer to ceq structure
 * Return 0, if the cqp cmd exec success, otherwise return error.
 */
static int nbl_cqp_ceq_create_cmd(struct nbl_pci_f *rf, struct nbl_sc_ceq *sc_ceq)
{
	int ret;
	__be64 *in;
	u32 elem_cnt = sc_ceq->elem_cnt;
	u32 cqp_ceq_size = ilog2(elem_cnt);

	u64 ceq_base_pa = sc_ceq->ceq_elem_pa; /* pa */
	u64 *base_addr = (u64 *)sc_ceq->ceqe_base; /* va */
	u64 ceq_1st_page_pa;
	u64 ceq_2nd_page_pa;

	if (sc_ceq->pa_continuous) {
		ceq_1st_page_pa = ceq_base_pa;
		ceq_2nd_page_pa = ceq_base_pa + (1 << NBL_ADAPTER_PAGE_SHIFT);
	} else {
		ceq_1st_page_pa = be64_to_cpu(base_addr[0]);
		ceq_2nd_page_pa = be64_to_cpu(base_addr[1]);
	}

	nbl_ib_dbg(&rf->sc_dev, "[CEQ CREATE] CQP parameter: ceq_id:%d, pa_continuous:%d, ceqe_cnt :%d,ceq_sz:%d, msix_idx:%d, ceq_base_va:%p ceq_base_pa:%llx, 1st_pa:0x%llx, 2nd_pa:0x%llx\n",
		sc_ceq->ceq_id, sc_ceq->pa_continuous, elem_cnt, cqp_ceq_size,
		sc_ceq->msix_idx, sc_ceq->ceqe_base, ceq_base_pa, ceq_1st_page_pa, ceq_2nd_page_pa);

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_ATOMIC);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	set_64bit_val(in, 0,
		FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_CREATE_CEQ) |
		FIELD_PREP(NBL_CQP_CEQ_STATE, NBL_CEQ_STAT_VALID) |
		FIELD_PREP(NBL_CQP_CEQ_PM, sc_ceq->pa_continuous ?
			NBL_CQP_PM_0_CONTINUS : NBL_CQP_PM_1_UNCONTINUS) |
		FIELD_PREP(NBL_CQP_CEQ_SIZE, cqp_ceq_size) |
		FIELD_PREP(NBL_CQP_CEQ_MSIX_INDEX_H11, sc_ceq->msix_idx >> 5) |
		FIELD_PREP(NBL_CQP_CEQ_ID, sc_ceq->ceq_id));

	set_64bit_val(in, 8,
		FIELD_PREP(NBL_CQP_CEQ_MSIX_INDEX_L5, sc_ceq->msix_idx & 0x1F) |
		FIELD_PREP(NBL_CQP_BASE_ADDR, (ceq_base_pa >> NBL_CEQ_CQP_ADDR_SHIFT)));
	set_64bit_val(in, 16, FIELD_PREP(NBL_CQP_CEQ_FIR_PAGE_ADDR,
		(ceq_1st_page_pa >> NBL_CEQ_CQP_ADDR_SHIFT)));
	set_64bit_val(in, 24, FIELD_PREP(NBL_CQP_CEQ_SEC_PAGE_ADDR,
		(ceq_2nd_page_pa >> NBL_CEQ_CQP_ADDR_SHIFT)));

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	kfree(in);

	return ret;
}

/**
 * nbl_cqp_ceq_destroy_cmd - Destroy CEQ.
 * @dev: pointer to device info
 * @sc_ceq: pointer to ceq structure
 * Return 0, if the cqp cmd exec success, otherwise return error.
 */
static int nbl_cqp_ceq_destroy_cmd(struct nbl_pci_f *rf, struct nbl_sc_ceq *sc_ceq)
{
	int ret;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;
	u32 ceq_id = sc_ceq->ceq_id;

	in = kzalloc(in_size, GFP_ATOMIC);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	set_64bit_val(in, 0,
		      FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_DESTROY_CEQ) |
		FIELD_PREP(NBL_CQP_CEQ_STATE, NBL_CEQ_STAT_INVALID) |
			      FIELD_PREP(NBL_CQP_CEQ_ID, ceq_id));

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);

	kfree(in);

	return ret;
}

/**
 * nbl_destroy_ceq - destroy ceq
 * @rf: RDMA PCI function
 * @ceq: ceq to be destroyed
 * 1.Issue a destroy ceq request by cqp
 * 2.free the resources associated with the ceq
 */
static void nbl_destroy_ceq(struct nbl_pci_f *rf,
			    struct nbl_msix_vector *msix_vec,
			    struct nbl_ceq *ceq)
{
	struct nbl_sc_dev *dev = &rf->sc_dev;
	struct nbl_frag_buf *ceq_buf = &ceq->buf;
	int status;

	nbl_destroy_irq(rf, msix_vec, ceq);

	status = nbl_cqp_ceq_destroy_cmd(rf, &ceq->sc_ceq);
	if (status)
		nbl_ib_err(dev, "ERR: CEQ destroy command failed %d\n", status);

	if (ceq->pa_continuous)
		dma_free_coherent(dev->hw->device, ceq->kmem.size, ceq->kmem.va,
				  ceq->kmem.pa);
	else
		nbl_frag_buf_free(dev->hw->device, ceq->kmem.va, ceq->kmem.pa,
				  ceq_buf);

	ceq->kmem.va = NULL;
}

static void nbl_ceq_rem_ref(struct nbl_ceq *ceq)
{
	unsigned long flags;

	spin_lock_irqsave(&ceq->ce_reslock, flags);
	if (!refcount_dec_and_test(&ceq->refcnt)) {
		spin_unlock_irqrestore(&ceq->ce_reslock, flags);
	} else {
		ceq->ceq_valid = 0;
		spin_unlock_irqrestore(&ceq->ce_reslock, flags);
		complete(&ceq->ceq_comp);
	}
}

/**
 * nbl_del_ceqs - destroy all ceqs
 * @rf: RDMA PCI function
 * for each ceq, disable the ceq interrupt, and
 * destroy the ceq by cqp, and
 * free the resources associated with the ceq
 */
void nbl_del_ceqs(struct nbl_pci_f *rf)
{
	if (rf->ceqs_count > 0) {
		u32 i;
		struct nbl_msix_vector *msix_vec;
		struct nbl_ceq *ceq = &rf->ceqlist[0];

		for (i = 0; i < rf->ceqs_count; i++, ceq++) {
			msix_vec = &rf->nbl_msixtbl[NBL_MSIX_ID_CEQ_BASE + i];

			nbl_ceq_rem_ref(ceq);
			wait_for_completion(&ceq->ceq_comp);

			if (ceq->dpc_tasklet.func)
				tasklet_kill(&ceq->dpc_tasklet);
			nbl_destroy_ceq(rf, msix_vec, ceq);
		}
	}

	kfree(rf->ceqlist); /* kfree NULL is safe */
	rf->ceqlist = NULL;
	rf->ceqs_count = 0;
	rf->sc_dev.ceq_valid = false;
}

/**
 * nbl_sc_ceq_init - initialize ceq
 * @ceq: ceq sc structure
 * @info: ceq initialization info
 */
static enum nbl_status_code nbl_sc_ceq_init(struct nbl_sc_ceq *ceq,
				     struct nbl_ceq_init_info *info)
{
	if (info->ceq_id > NBL_MAX_CEQID)
		return -EINVAL;

	ceq->ceqe_base = (struct nbl_ceqe *)info->ceqe_base;
	ceq->ceq_id = info->ceq_id;
	ceq->msix_idx = info->msix_idx;
	ceq->dev = info->dev;
	ceq->elem_cnt = info->elem_cnt;
	ceq->ceq_pg_num = info->ceq_pg_num;
	ceq->ceq_elem_pa = info->ceqe_pa;
	ceq->pa_continuous = info->pa_continuous;
	ceq->polarity = 1;
	NBL_RING_INIT(ceq->ceq_ring, ceq->elem_cnt);
	ceq->dev->ceq[info->ceq_id] = ceq;
	nbl_pr_dbg("%s, %d, elem_cnt %d, dev_min_ceq_size %d, dev_max_ceq_size:%d, ceq_id:%d, max ceq_id:%d, msix_idx: %d, pg_num:%d\n",
		__func__, __LINE__, info->elem_cnt,
		info->dev->hw_attrs.min_hw_ceqe_count,
		info->dev->hw_attrs.max_hw_ceqe_count, info->ceq_id,
		NBL_MAX_CEQID, ceq->msix_idx, info->ceq_pg_num);
	return 0;
}

/**
 * nbl_create_ceq - create completion event queue
 * @rf: RDMA PCI function
 * @ceq: pointer to the ceq resources to be created
 * @ceq_id: the id number of the ceq
 * Return 0, if the ceq and the resources associated with it
 * are successfully created, otherwise return error
 */
static enum nbl_status_code nbl_create_ceq(struct nbl_pci_f *rf,
					   struct nbl_ceq *ceq, u32 ceq_id)
{
	enum nbl_status_code status;
	struct nbl_ceq_init_info info = {};
	struct nbl_sc_dev *dev = &rf->sc_dev;
	struct nbl_frag_buf *ceq_buf = &ceq->buf;
	u32 ceqe_count;
	u32 ceq_size;

	ceq->rf = rf;
	ceqe_count = min(rf->sc_dev.hmc_info->hmc_obj[NBL_HMC_CQ].cnt,
		       dev->hw_attrs.max_hw_ceqe_count);
	ceqe_count = roundup_pow_of_two(ceqe_count);
	if (ceqe_count > dev->hw_attrs.max_hw_ceqe_count) {

		nbl_pr_err("ceqe_count:%d is invalid, max:%d\n", ceqe_count,
			   dev->hw_attrs.max_hw_ceqe_count);

		return NBL_ERR_SPEC_ERROR;
	}

	if (ceqe_count < dev->hw_attrs.min_hw_ceqe_count) {
		nbl_pr_notice("ceqe_count=%u, is too small, use default value=%u\n", ceqe_count,
			      dev->hw_attrs.min_hw_ceqe_count);
		ceqe_count = dev->hw_attrs.min_hw_ceqe_count;
	}

	ceq_size = ALIGN(sizeof(struct nbl_ceqe) * ceqe_count, NBL_CEQ_ALIGNMENT);
	ceq->kmem.size = ceq_size;
	ceq->kmem.va = nbl_dma_alloc_coherent(dev->hw->device, ceq->kmem.size,
					      &ceq->kmem.pa, GFP_KERNEL);
	if (ceq->kmem.va) {
		ceq->pa_continuous = true;
		ceq_buf->npages = NBL_CEQ_2M_PAGE_NUM;
		nbl_ib_dbg(&rf->sc_dev, "alloced ceq continuous pa, va:%llx\n", (u64)ceq->kmem.va);

	} else {
		ceq->pa_continuous = false;
		ceq_buf->size = ceq->kmem.size;
		ceq_buf->npages = DIV_ROUND_UP(ceq_buf->size, NBL_ADAPTER_PAGE_SIZE);
		status = nbl_frag_buf_alloc(dev->hw->device, &ceq->kmem.va,
			&ceq->kmem.pa, ceq_buf);
		if (status)
			return status;
	}

	info.ceq_id = ceq_id;
	info.msix_idx = ceq->msix_idx;
	info.ceqe_base = ceq->kmem.va;
	info.ceqe_pa = ceq->kmem.pa;
	info.elem_cnt = ceqe_count;
	info.ceq_pg_num = ceq_buf->npages;
	info.pa_continuous = ceq->pa_continuous;
	ceq->sc_ceq.ceq_id = ceq_id;
	info.dev = dev;
	status = nbl_sc_ceq_init(&ceq->sc_ceq, &info);
	if (status) {
		nbl_ib_err(&rf->sc_dev, "[CEQ CREATE] nbl_sc_ceq_init failed:%d\n", status);
		goto err;
	}

	status = nbl_cqp_ceq_create_cmd(rf, &ceq->sc_ceq);
	if (status) {
		nbl_ib_err(&rf->sc_dev, "[CEQ CREATE] nbl_cqp_ceq_create_cmd failed:%d\n", status);
		goto err;
	}

	return NBL_SUCCESS;
err:
	if (ceq->pa_continuous)
		dma_free_coherent(dev->hw->device, ceq->kmem.size,
			ceq->kmem.va, ceq->kmem.pa);
	else
		nbl_frag_buf_free(dev->hw->device, ceq->kmem.va,
			ceq->kmem.pa, ceq_buf);

	ceq->kmem.va = NULL;
	return status;
}

static inline void nbl_move_ceq_tail(struct nbl_sc_ceq *sc_ceq)
{
	NBL_RING_MOVE_TAIL(sc_ceq->ceq_ring);
	if (!NBL_RING_CURRENT_TAIL(sc_ceq->ceq_ring))
		sc_ceq->polarity ^= 1;
}
/**
 * nbl_sc_process_ceq - process ceq
 * @dev: sc device struct
 * @ceq: ceq sc structure
 * @ceqcnt: sw process ceqe count
 * It is expected caller serializes this function with cleanup_ceqes()
 * because these functions manipulate the same ceq
 */
static void *nbl_sc_process_ceq(struct nbl_pci_f *rf, struct nbl_ceq *ceq, u32 *ceqcnt)
{
	u64 temp;
	__be64 *ceqe;
	struct nbl_sc_cq *sc_cq;
	struct nbl_sc_ceq *sc_ceq;
	struct nbl_cq *nblcq;
	unsigned long flags;
	u8 polarity;
	u32 cq_idx;
	u32 wqe_idx;

	sc_ceq = &ceq->sc_ceq;
	do {
		cq_idx = 0;
		wqe_idx = sc_ceq->ceq_ring.tail;
		ceqe = nbl_get_wqe(sc_ceq->ceqe_base, &(ceq->buf),
			sizeof(struct nbl_ceqe), wqe_idx, sc_ceq->pa_continuous);
		if (!ceqe) {
			nbl_ib_dbg(&rf->sc_dev, "get ceqe fail\n");
			return NULL;
		}
		get_64bit_val(ceqe, 0, &temp);
		polarity = (u8)FIELD_GET(NBL_CEQE_VALID, temp);
		if (polarity != sc_ceq->polarity)
			return NULL;

		(*ceqcnt)++;
		cq_idx = FIELD_GET(NBL_CEQE_CQN, temp);
		if (cq_idx >= rf->max_cq) {
			cq_idx = NBL_INVALID_CQ_IDX;
			nbl_move_ceq_tail(sc_ceq);
			continue;
		}

		spin_lock_irqsave(&rf->cqtable_lock, flags);
		nblcq = rf->cq_table[cq_idx];
		if (!nblcq) {
			cq_idx = NBL_INVALID_CQ_IDX;
			nbl_move_ceq_tail(sc_ceq);
			spin_unlock_irqrestore(&rf->cqtable_lock, flags);
			continue;
		}
		refcount_inc(&nblcq->refcnt);
		spin_unlock_irqrestore(&rf->cqtable_lock, flags);
		sc_cq = &nblcq->sc_cq;
		nbl_ib_dbg(&rf->sc_dev, "sc_cq :0x%lx, cqn :%u refcnt:%d\n",
			   (unsigned long)sc_cq, cq_idx,
			   refcount_read(&nblcq->refcnt));

		nbl_move_ceq_tail(sc_ceq);
	} while (cq_idx == NBL_INVALID_CQ_IDX);

	nbl_ib_dbg(&rf->sc_dev, "[CEQ%d] consumed ceqcnt :%u\n", sc_ceq->ceq_id,
		   *ceqcnt);

	return sc_cq;
}

/**
 * nbl_ce_handler - handle cq completions
 * @nblcq: cq receiving event
 */
static void nbl_ce_handler(struct nbl_pci_f *rf, struct nbl_sc_cq *nblcq)
{
	struct nbl_cq *cq = nblcq->bak_nbl_cq;

	if (!cq->user_mode)
		atomic_set(&cq->armed, 0);
	if (cq->ibcq.comp_handler && !cq->ceq_suspend)
		cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
	nbl_cq_rem_ref(&cq->ibcq);
}

/**
 * nbl_process_ceq - handle ceq for completions
 * @rf: RDMA PCI function
 * @ceq: ceq having cq for completion
 */
static void nbl_process_ceq(struct nbl_pci_f *rf, struct nbl_ceq *ceq)
{
	struct nbl_sc_dev *dev = &rf->sc_dev;
	struct nbl_sc_ceq *sc_ceq;
	struct nbl_sc_cq *cq;
	unsigned long flags;
	u32 ceqcnt = 0;

	sc_ceq = &ceq->sc_ceq;
	spin_lock_irqsave(&ceq->ce_reslock, flags);
	if (ceq->ceq_valid == 0) {
		spin_unlock_irqrestore(&ceq->ce_reslock, flags);
		nbl_ib_err(dev, "ceq is disable\n");
		return;
	}
	refcount_inc(&ceq->refcnt);
	spin_unlock_irqrestore(&ceq->ce_reslock, flags);

	spin_lock_irqsave(&ceq->ce_lock, flags);
	do {
		cq = nbl_sc_process_ceq(rf, ceq, &ceqcnt);
		if (!cq)
			goto exit;

		/* update arm used */
		atomic_dec(&rf->armc.used);

		nbl_ce_handler(rf, cq);
	} while (1);
exit:
	if (ceqcnt)
		nbl_sc_update_ceq_ci(dev, sc_ceq);
	spin_unlock_irqrestore(&ceq->ce_lock, flags);
	nbl_ceq_rem_ref(ceq);
}

/**
 * nbl_ceq_dpc - dpc handler for CEQ
 * @t: tasklet_struct ptr
 */
static void nbl_ceq_dpc(struct tasklet_struct *t)
{
	struct nbl_ceq *nblceq = from_tasklet(nblceq, t, dpc_tasklet);
	struct nbl_pci_f *rf = nblceq->rf;

	nbl_process_ceq(rf, nblceq);
}

/**
 * nbl_ceq_handler - interrupt handler for ceq
 * @irq: interrupt request number
 * @data: ceq pointer
 */
static irqreturn_t nbl_ceq_handler(int irq, void *data)
{
	struct nbl_ceq *nblceq = data;

	if (nblceq->irq != irq)
		nbl_ib_err(&nblceq->rf->sc_dev,
			   "expected irq = %d received irq = %d\n", nblceq->irq,
			   irq);

	tasklet_schedule(&nblceq->dpc_tasklet);

	return IRQ_HANDLED;
}

/**
 * nbl_cfg_ceq_vector - set up the msix interrupt vector for
 * ceq
 * @rf: RDMA PCI function
 * @ceq: ceq associated with the vector
 * @ceq_id: the id number of the ceq
 * @msix_vec: interrupt vector information
 *
 * Allocate interrupt resources and enable irq handling
 * Return 0 if successful, otherwise return error
 */
static enum nbl_status_code nbl_cfg_ceq_vector(struct nbl_pci_f *rf,
					       struct nbl_ceq *nblceq,
					       u32 ceq_id,
					       struct nbl_msix_vector *msix_vec)
{
	int status;

	snprintf(nblceq->name, NBL_MAX_IRQ_NAME, "nbl_ceq-%d", ceq_id);
	tasklet_setup(&nblceq->dpc_tasklet, nbl_ceq_dpc);

	status = request_irq(msix_vec->irq, nbl_ceq_handler, 0, nblceq->name, nblceq);
	if (status) {
		nbl_ib_err(&rf->sc_dev, "request_irq for ceq fail:%d\n",
			status);
		return NBL_ERR_CFG;
	}

	cpumask_clear(&msix_vec->mask);
	cpumask_set_cpu(msix_vec->cpu_affinity, &msix_vec->mask);
	irq_set_affinity_hint(msix_vec->irq, &msix_vec->mask);

	msix_vec->ceq_id = ceq_id;
	rf->sc_dev.irq_ops->nbl_en_irq(rf, msix_vec->idx);

	return NBL_SUCCESS;
}

/**
 * get_ceq_num - get the number of ceqs
 */
static u32 get_ceq_num(struct nbl_pci_f *rf)
{
	return NBL_CEQ_MAX_COUNT;
}

/**
 * nbl_setup_ceqs - manage the device ceq's and their interrupt resources
 * @rf: RDMA PCI function
 * Allocate a list for all device completion event queues
 * Create the ceq's and configure their msix interrupt vectors
 * Return 0, if ceqs are successfully set up, otherwise return error
 */
enum nbl_status_code nbl_setup_ceqs(struct nbl_pci_f *rf)
{
	u32 num_ceqs;
	u32 ceq_id;
	struct nbl_ceq *ceq;
	struct nbl_msix_vector *msix_vec;
	enum nbl_status_code status;

	num_ceqs = get_ceq_num(rf);
	if (num_ceqs < NBL_CEQ_MIN_COUNT) {
		nbl_ib_err(&rf->sc_dev,
			   "CEQ counts %d should be greater than %d.", num_ceqs,
			   NBL_CEQ_MIN_COUNT);
		return NBL_ERR_SPEC_ERROR;
	}

	rf->ceqlist = kcalloc(num_ceqs, sizeof(*rf->ceqlist), GFP_KERNEL);
	if (!rf->ceqlist)
		return NBL_ERR_NO_MEMORY;

	for (ceq_id = 0; ceq_id < num_ceqs; ceq_id++) {
		msix_vec = &rf->nbl_msixtbl[NBL_MSIX_ID_CEQ_BASE + ceq_id];
		ceq = &rf->ceqlist[ceq_id];
		spin_lock_init(&ceq->ce_lock);
		spin_lock_init(&ceq->ce_reslock);
		init_completion(&ceq->ceq_comp);
		refcount_set(&ceq->refcnt, 1);
		ceq->ceq_valid = 1;
		ceq->irq = msix_vec->irq;
		ceq->msix_idx = msix_vec->idx;
		ceq->ceq_id = ceq_id;

		status = nbl_create_ceq(rf, ceq, ceq_id);
		if (status)
			goto del_ceqs;

		status = nbl_cfg_ceq_vector(rf, ceq, ceq_id, msix_vec);
		if (status) {
			nbl_destroy_ceq(rf, msix_vec, ceq);
			goto del_ceqs;
		}

		rf->ceqs_count++;
	}

	nbl_ib_dbg(&rf->sc_dev, "rf->ceqs_count : %d\n", rf->ceqs_count);
	rf->sc_dev.ceq_valid = true;
	return 0;

del_ceqs:
	nbl_del_ceqs(rf);

	return status;
}
